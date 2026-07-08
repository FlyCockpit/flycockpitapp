//! Attention subsystem — a small, reliable policy layer for events that
//! want the user back in the TUI (implementation note).
//!
//! The classification + debounce logic is a **pure function**
//! ([`decide`]) over an [`AttentionEvent`], the user's [`AttentionConfig`],
//! a recent-interaction flag, and a monotonic clock. It returns an
//! [`AttentionDecision`] describing what the caller should surface (toast
//! text/kind, terminal bell, desktop notification). Side effects — showing
//! the toast, ringing the bell, posting a desktop notification — live in the
//! TUI `App`, never here, so the decision logic is fully testable without a
//! terminal.
//!
//! Payloads are terse and secret-safe by construction: every variant maps to
//! a fixed generic string. No command output, file contents, env values, or
//! prompt text ever enters a notification.

use std::time::{Duration, Instant};

/// The narrow attention-event vocabulary. The TUI's event handler
//  classifies the relevant daemon events into exactly these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttentionEvent {
    /// An agent/user question is waiting (action required).
    Question,
    /// A permission/approval decision is waiting (action required).
    Approval,
    /// The foreground agent finished a turn. `long_running` is set when the
    /// turn ran long enough to be worth a notification on its own.
    TurnDone { long_running: bool },
    /// The foreground turn failed (inference error).
    TurnError,
    /// An async job (loop / timer / background) completed.
    ScheduleDone,
}

/// Toast intent for an attention notification. Mirrors the App's private
/// toast palette without depending on it, so this module stays pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    Info,
    Success,
    Error,
}

impl AttentionEvent {
    /// Events that require the user to *act* (answer, approve, resolve).
    /// These are the only events eligible for the optional terminal bell.
    pub fn is_action_required(self) -> bool {
        matches!(self, AttentionEvent::Question | AttentionEvent::Approval)
    }

    /// The terse, secret-safe toast text. Fixed generic strings only.
    pub fn toast_text(self) -> &'static str {
        match self {
            AttentionEvent::Question => "Question waiting",
            AttentionEvent::Approval => "Approval needed",
            AttentionEvent::TurnDone { .. } => "Agent finished",
            AttentionEvent::TurnError => "Agent turn failed",
            AttentionEvent::ScheduleDone => "Background job finished",
        }
    }

    /// Toast color intent.
    pub fn notice_kind(self) -> NoticeKind {
        match self {
            AttentionEvent::Question | AttentionEvent::Approval => NoticeKind::Info,
            AttentionEvent::TurnDone { .. } | AttentionEvent::ScheduleDone => NoticeKind::Success,
            AttentionEvent::TurnError => NoticeKind::Error,
        }
    }

    /// Coarse identity used for debounce. Distinct events never collapse;
    /// repeats of the *same* kind within the debounce window do. `TurnDone`
    /// collapses across its `long_running` flag (a burst is a burst).
    fn debounce_key(self) -> u8 {
        match self {
            AttentionEvent::Question => 0,
            AttentionEvent::Approval => 1,
            AttentionEvent::TurnDone { .. } => 2,
            AttentionEvent::TurnError => 3,
            AttentionEvent::ScheduleDone => 4,
        }
    }
}

/// User-tunable attention settings (persisted under `tui.attention`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttentionConfig {
    /// In-TUI toast/status notifications. Default on.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Terminal bell for action-required events. Default off.
    #[serde(default)]
    pub bell: bool,
    /// Desktop notification (best-effort, non-fatal). Default off.
    #[serde(default)]
    pub desktop: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AttentionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bell: false,
            desktop: false,
        }
    }
}

/// What the caller should surface for one attention event. Empty fields mean
/// "do nothing" — the caller never has to re-derive policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttentionDecision {
    /// `Some((text, kind))` to show an in-TUI toast.
    pub toast: Option<(&'static str, NoticeKind)>,
    /// Ring the terminal bell once.
    pub bell: bool,
    /// Post a desktop notification (best-effort).
    pub desktop: bool,
}

impl AttentionDecision {
    /// True when this decision asks for no user-visible effect at all.
    pub fn is_noop(&self) -> bool {
        self.toast.is_none() && !self.bell && !self.desktop
    }
}

/// How long an identical event is suppressed for bell/desktop after the last
/// time it fired one. A burst of tool errors or plan updates inside this
/// window rings/pops at most once.
pub const DEBOUNCE_WINDOW: Duration = Duration::from_secs(5);

/// Mutable debounce bookkeeping. One per running TUI.
#[derive(Debug, Default, Clone)]
pub struct AttentionState {
    /// (debounce key, when its last bell/desktop fired).
    last_fired: Option<(u8, Instant)>,
}

impl AttentionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `event` is currently debounced for *escalation* (bell/desktop):
    /// the same key fired one within [`DEBOUNCE_WINDOW`]. The in-TUI toast is
    /// never debounced — it is the subtle channel.
    fn escalation_debounced(&self, event: AttentionEvent, now: Instant) -> bool {
        match self.last_fired {
            Some((key, at)) => {
                key == event.debounce_key() && now.duration_since(at) < DEBOUNCE_WINDOW
            }
            None => false,
        }
    }

    fn record_fired(&mut self, event: AttentionEvent, now: Instant) {
        self.last_fired = Some((event.debounce_key(), now));
    }
}

/// The pure attention decision. Given the event, the user's config, whether
/// the user has interacted recently (conservative focus proxy), the clock,
/// and the debounce state, decide what to surface — and update the debounce
/// state for any escalation it fires.
///
/// Policy:
/// - With `attention.enabled` off, nothing is surfaced at all.
/// - The in-TUI toast always shows for an enabled subsystem (the subtle,
///   never-spammy channel — it self-expires and a fresh one replaces it).
/// - The terminal bell (when `attention.bell` on) fires only for
///   action-required events, debounced per-kind.
/// - Desktop notifications (when `attention.desktop` on) fire for
///   action-required events and for a long-running `turn_done`, debounced
///   per-kind. A plain (fast) `turn_done` while the user is actively at the
///   keyboard stays toast-only — no desktop pop for a turn they watched
///   finish.
pub fn decide(
    event: AttentionEvent,
    config: &AttentionConfig,
    recently_interacted: bool,
    now: Instant,
    state: &mut AttentionState,
) -> AttentionDecision {
    if !config.enabled {
        return AttentionDecision::default();
    }

    let toast = Some((event.toast_text(), event.notice_kind()));

    // Which events warrant escalation (bell/desktop) at all. Action-required
    // events always do; a turn completion only when it ran long or the user
    // has stepped away. A fast turn the user watched finish stays subtle.
    let wants_escalation = match event {
        e if e.is_action_required() => true,
        AttentionEvent::TurnDone { long_running } => long_running || !recently_interacted,
        _ => false,
    };

    if !wants_escalation {
        return AttentionDecision {
            toast,
            bell: false,
            desktop: false,
        };
    }

    if state.escalation_debounced(event, now) {
        // Same kind fired recently — keep it subtle (toast only).
        return AttentionDecision {
            toast,
            bell: false,
            desktop: false,
        };
    }

    // Bell only for action-required events; desktop for any escalating event.
    let bell = config.bell && event.is_action_required();
    let desktop = config.desktop;

    if bell || desktop {
        state.record_fired(event, now);
    }

    AttentionDecision {
        toast,
        bell,
        desktop,
    }
}

/// Strip control characters (ESC, BEL, and every other C0/C1 control and
/// DEL) from notification text so an odd or hostile summary cannot inject a
/// string terminator / control byte and break out of the OSC string it is
/// embedded in. Printable text passes through unchanged.
fn sanitize_notification_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Build the terminal notification escape sequences for a desktop-style
/// notification, as a single string carrying two best-effort OSC commands
/// back-to-back (each terminated by ST = `ESC \`):
///
/// - **OSC 777** (`ESC ] 777 ; notify ; <title> ; <body> ST`) — the
///   kitty / WezTerm / foot notification protocol.
/// - **OSC 9** (`ESC ] 9 ; <title>: <body> ST`) — the iTerm2 / Ghostty
///   growl-style notification (single message field, so title and body are
///   joined).
///
/// Terminals that understand either turn it into a native notification;
/// everything else silently ignores an unknown OSC, and both travel fine over
/// SSH. The sequences contain no cursor movement or visible glyphs, so
/// emitting them mid-frame under ratatui is safe. `title` and `body` are run
/// through [`sanitize_notification_text`] first so their content cannot alter
/// the framing. Pure (no I/O) so it can be unit-tested.
pub(crate) fn desktop_notification_escapes(title: &str, body: &str) -> String {
    let title = sanitize_notification_text(title);
    let body = sanitize_notification_text(body);
    format!("\x1b]777;notify;{title};{body}\x1b\\\x1b]9;{title}: {body}\x1b\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, bell: bool, desktop: bool) -> AttentionConfig {
        AttentionConfig {
            enabled,
            bell,
            desktop,
        }
    }

    #[test]
    fn defaults_match_spec() {
        let d = AttentionConfig::default();
        assert!(d.enabled);
        assert!(!d.bell);
        assert!(!d.desktop);
    }

    #[test]
    fn disabled_subsystem_surfaces_nothing() {
        let mut st = AttentionState::new();
        let d = decide(
            AttentionEvent::Approval,
            &cfg(false, true, true),
            false,
            Instant::now(),
            &mut st,
        );
        assert!(d.is_noop());
    }

    #[test]
    fn approval_toast_and_bell_fire_once() {
        let mut st = AttentionState::new();
        let now = Instant::now();
        let d = decide(
            AttentionEvent::Approval,
            &cfg(true, true, false),
            true,
            now,
            &mut st,
        );
        assert_eq!(d.toast, Some(("Approval needed", NoticeKind::Info)));
        assert!(d.bell);
        assert!(!d.desktop);
    }

    #[test]
    fn bell_off_means_no_bell() {
        let mut st = AttentionState::new();
        let d = decide(
            AttentionEvent::Question,
            &cfg(true, false, false),
            true,
            Instant::now(),
            &mut st,
        );
        assert!(d.toast.is_some());
        assert!(!d.bell);
    }

    #[test]
    fn bell_only_for_action_required() {
        let mut st = AttentionState::new();
        // turn_error is not action-required → no bell even with bell on.
        let d = decide(
            AttentionEvent::TurnError,
            &cfg(true, true, false),
            false,
            Instant::now(),
            &mut st,
        );
        assert!(d.toast.is_some());
        assert!(!d.bell);
    }

    #[test]
    fn identical_burst_is_debounced_for_escalation() {
        let mut st = AttentionState::new();
        let t0 = Instant::now();
        let first = decide(
            AttentionEvent::Approval,
            &cfg(true, true, true),
            true,
            t0,
            &mut st,
        );
        assert!(first.bell && first.desktop);

        // Same kind, immediately after — toast still shows, but no bell/desktop.
        let second = decide(
            AttentionEvent::Approval,
            &cfg(true, true, true),
            true,
            t0 + Duration::from_millis(200),
            &mut st,
        );
        assert!(second.toast.is_some());
        assert!(!second.bell);
        assert!(!second.desktop);

        // After the window elapses, escalation fires again.
        let third = decide(
            AttentionEvent::Approval,
            &cfg(true, true, true),
            true,
            t0 + DEBOUNCE_WINDOW + Duration::from_millis(1),
            &mut st,
        );
        assert!(third.bell && third.desktop);
    }

    #[test]
    fn distinct_events_do_not_debounce_each_other() {
        let mut st = AttentionState::new();
        let t0 = Instant::now();
        let a = decide(
            AttentionEvent::Approval,
            &cfg(true, true, true),
            true,
            t0,
            &mut st,
        );
        assert!(a.bell);
        // A different kind right after is not suppressed by the approval.
        let q = decide(
            AttentionEvent::Question,
            &cfg(true, true, true),
            true,
            t0 + Duration::from_millis(10),
            &mut st,
        );
        assert!(q.bell);
    }

    #[test]
    fn fast_turn_done_while_interacting_stays_subtle() {
        let mut st = AttentionState::new();
        let d = decide(
            AttentionEvent::TurnDone {
                long_running: false,
            },
            &cfg(true, true, true),
            true, // user is right here
            Instant::now(),
            &mut st,
        );
        assert!(d.toast.is_some());
        assert!(!d.bell); // never for turn_done anyway
        assert!(!d.desktop); // subtle — they watched it finish
    }

    #[test]
    fn long_running_turn_done_escalates_to_desktop() {
        let mut st = AttentionState::new();
        let d = decide(
            AttentionEvent::TurnDone { long_running: true },
            &cfg(true, false, true),
            true,
            Instant::now(),
            &mut st,
        );
        assert!(d.toast.is_some());
        assert!(!d.bell);
        assert!(d.desktop);
    }

    #[test]
    fn turn_done_escalates_when_user_away_even_if_short() {
        let mut st = AttentionState::new();
        let d = decide(
            AttentionEvent::TurnDone {
                long_running: false,
            },
            &cfg(true, false, true),
            false, // stepped away
            Instant::now(),
            &mut st,
        );
        assert!(d.desktop);
    }

    #[test]
    fn desktop_escapes_frame_both_osc_sequences() {
        let s = desktop_notification_escapes("Cockpit", "Question waiting");
        // OSC 777 for kitty/WezTerm/foot, terminated by ST (ESC \).
        assert!(s.starts_with("\x1b]777;notify;Cockpit;Question waiting\x1b\\"));
        // Followed immediately by OSC 9 for iTerm2/Ghostty, also ST-terminated.
        assert!(s.ends_with("\x1b]9;Cockpit: Question waiting\x1b\\"));
        assert_eq!(
            s,
            "\x1b]777;notify;Cockpit;Question waiting\x1b\\\x1b]9;Cockpit: Question waiting\x1b\\"
        );
    }

    #[test]
    fn desktop_escapes_strip_control_characters() {
        // An embedded ESC / BEL / ST would otherwise break out of the OSC
        // string; every control byte must be dropped.
        let s = desktop_notification_escapes("Cock\x07pit", "evil\x1bbody\x07here\nline");
        // The only ESC bytes left are our own framing (start ESC ] and ST ESC \).
        assert_eq!(s.matches('\x1b').count(), 4);
        assert!(!s.contains('\x07'));
        assert!(!s.contains('\n'));
        assert!(s.contains("Cockpit"));
        assert!(s.contains("evilbodyhereline"));
    }

    #[test]
    fn sanitize_keeps_printable_and_unicode() {
        assert_eq!(sanitize_notification_text("héllo · ok"), "héllo · ok");
        assert_eq!(sanitize_notification_text("a\x00b\x1bc"), "abc");
    }
}
