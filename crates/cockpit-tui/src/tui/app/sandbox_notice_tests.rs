use super::{
    App, MAX_SANDBOX_NOTICE_ROWS, sandbox_down_notice_text, sandbox_notice_render_text,
    sandbox_notice_wrapped_rows,
};
use cockpit_core::engine::TurnEvent;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

const FIX_COMMAND: &str = "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0";
const REMEDY: &str = "unprivileged user namespaces are restricted by AppArmor (Ubuntu 23.10+); \
     `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` re-enables confinement";

/// §6.5 raise + clear, end-to-end on the client state. A
/// `SandboxUnavailable` event raises the persistent notice (a non-zero
/// below-input row count — it is NOT a 3 s toast, so it survives across
/// frames); a later `SandboxState { enabled: false }` (what `/sandbox off`
/// triggers) clears it. Crucially, neither writes anything to `history` —
/// the notice never enters the transcript and so never the LLM context.
#[test]
fn unavailable_raises_persistent_notice_and_sandbox_off_clears_it() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let history_len_before = app.history.len();

    // No notice initially.
    assert!(app.sandbox_down_notice.is_none());
    assert_eq!(app.sandbox_notice_lines(), 0);

    // Sandbox-unavailable → persistent notice raised.
    app.apply_event(TurnEvent::SandboxUnavailable {
        remedy: REMEDY.to_string(),
        fix_command: Some(FIX_COMMAND.to_string()),
    });
    assert_eq!(
        app.sandbox_down_notice
            .as_ref()
            .map(|notice| notice.remedy.as_str()),
        Some(REMEDY)
    );
    assert_eq!(
        app.sandbox_down_notice
            .as_ref()
            .and_then(|notice| notice.fix_command.as_deref()),
        Some(FIX_COMMAND)
    );
    assert!(app.sandbox_notice_lines() > 0, "persistent row reserved");
    let text = app.sandbox_down_notice_text().unwrap();
    assert!(text.contains("/sandbox off"));
    assert!(text.contains("sudo sysctl"));
    // Purely client-side: nothing was pushed into the transcript.
    assert_eq!(app.history.len(), history_len_before);

    // A repeated unavailable event just refreshes the same notice (the
    // daemon de-dupes the broadcast; the client stays idempotent).
    app.apply_event(TurnEvent::SandboxUnavailable {
        remedy: REMEDY.to_string(),
        fix_command: Some(FIX_COMMAND.to_string()),
    });
    assert_eq!(
        app.sandbox_down_notice
            .as_ref()
            .map(|notice| notice.remedy.as_str()),
        Some(REMEDY)
    );
    assert_eq!(
        app.sandbox_down_notice
            .as_ref()
            .and_then(|notice| notice.fix_command.as_deref()),
        Some(FIX_COMMAND)
    );
    assert_eq!(app.history.len(), history_len_before);

    // `/sandbox off` -> `SandboxState { mode: Off }` clears it.
    app.apply_event(TurnEvent::SandboxState {
        mode: cockpit_core::tools::sandbox_mode::SandboxMode::Off,
        container_network_enabled: false,
        container_availability: cockpit_core::container::availability_snapshot(),
    });
    assert!(app.sandbox_down_notice.is_none());
    assert_eq!(app.sandbox_notice_lines(), 0);

    // Re-enabling does not resurrect a stale notice on its own.
    app.apply_event(TurnEvent::SandboxState {
        mode: cockpit_core::tools::sandbox_mode::SandboxMode::Sandbox,
        container_network_enabled: false,
        container_availability: cockpit_core::container::availability_snapshot(),
    });
    assert!(app.sandbox_down_notice.is_none());
}

/// The waiting-for-lock chrome state (`readlock-wait-and-lock-expiry.md`):
/// a `WaitingForLock { waiting: true }` event sets the transient state with
/// the path + holder, the `waiting: false` clear removes it, and neither
/// touches the transcript (purely client-side chrome).
#[test]
fn waiting_for_lock_event_sets_and_clears_chrome_state() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let history_len_before = app.history.len();
    assert!(app.waiting_for_lock.is_none());

    // Wait starts → state set with path + holder.
    app.apply_event(TurnEvent::WaitingForLock {
        path: "/repo/src/lib.rs".to_string(),
        holder_agent: "builder".to_string(),
        waiting: true,
    });
    assert_eq!(
        app.waiting_for_lock
            .as_ref()
            .map(|(p, h)| (p.as_str(), h.as_str())),
        Some(("/repo/src/lib.rs", "builder"))
    );
    // The chrome renders the path basename + holder.
    let spans = crate::tui::chrome::waiting_for_lock_spans(app.waiting_for_lock.as_ref());
    let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
    assert!(
        text.contains("lib.rs") && text.contains("builder"),
        "{text}"
    );
    // Purely client-side: nothing entered the transcript.
    assert_eq!(app.history.len(), history_len_before);

    // Wait ends (acquired/cancelled) → state cleared.
    app.apply_event(TurnEvent::WaitingForLock {
        path: "/repo/src/lib.rs".to_string(),
        holder_agent: String::new(),
        waiting: false,
    });
    assert!(app.waiting_for_lock.is_none());
    assert!(crate::tui::chrome::waiting_for_lock_spans(app.waiting_for_lock.as_ref()).is_empty());
    assert_eq!(app.history.len(), history_len_before);
}

/// §6.5: the persistent user-facing notice carries the deterministic
/// `/sandbox off` instruction AND the diagnosed `sudo sysctl …=0` host
/// command (when the remedy provides one) — so the user can act
/// regardless of what the model does.
#[test]
fn notice_text_names_sandbox_off_and_diagnosed_sysctl() {
    let remedy = "unprivileged user namespaces are restricted by AppArmor (Ubuntu 23.10+); \
         `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` re-enables confinement";
    let text = sandbox_down_notice_text(remedy, Some(FIX_COMMAND), false);
    assert!(text.contains("/sandbox off"));
    assert!(text.contains("sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"));
    // The original diagnosed reason is preserved verbatim inside it.
    assert!(text.contains(remedy));
}

/// A generic (non-diagnosed) remedy still surfaces the deterministic
/// `/sandbox off` action — the actionable instruction is always present.
#[test]
fn notice_text_always_has_sandbox_off_even_without_sysctl() {
    let text =
        sandbox_down_notice_text("bwrap: setting up uid map: Permission denied", None, false);
    assert!(text.contains("/sandbox off"));
    assert!(!text.contains("sudo sysctl"));
}

fn ratatui_notice_rows(text: &str, width: u16) -> u16 {
    let width = width.max(1);
    let height = 20;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| {
            let para = Paragraph::new(Line::from(vec![Span::styled(
                sandbox_notice_render_text(text),
                Style::default(),
            )]))
            .wrap(Wrap { trim: true });
            frame.render_widget(para, Rect::new(0, 0, width, height));
        })
        .unwrap();
    let buffer = terminal.backend().buffer();
    let rows = (0..height)
        .filter(|&y| {
            (0..width).any(|x| {
                buffer[(x, y)]
                    .symbol()
                    .chars()
                    .any(|ch| !ch.is_whitespace())
            })
        })
        .count()
        .max(1);
    (rows as u16).min(MAX_SANDBOX_NOTICE_ROWS)
}

#[test]
fn notice_height_matches_ratatui_wrap_for_representative_widths() {
    let text = sandbox_down_notice_text(REMEDY, Some(FIX_COMMAND), false);
    for width in [20, 32, 48, 80] {
        assert_eq!(
            sandbox_notice_wrapped_rows(&text, width),
            ratatui_notice_rows(&text, width),
            "width {width}"
        );
    }
}

#[test]
fn notice_height_keeps_long_sysctl_remedy_within_existing_cap() {
    let text = sandbox_down_notice_text(REMEDY, Some(FIX_COMMAND), false);
    let rows = sandbox_notice_wrapped_rows(&text, 48);
    assert_eq!(rows, ratatui_notice_rows(&text, 48));
    assert_eq!(rows, MAX_SANDBOX_NOTICE_ROWS);
}

#[test]
fn notice_height_matches_ratatui_wrap_for_unicode_display_width() {
    let text = sandbox_down_notice_text(
        "原因: 名前空間を作成できません。`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`",
        Some(FIX_COMMAND),
        false,
    );
    for width in [16, 24, 40] {
        assert_eq!(
            sandbox_notice_wrapped_rows(&text, width),
            ratatui_notice_rows(&text, width),
            "width {width}"
        );
    }
}
