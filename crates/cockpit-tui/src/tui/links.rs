use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRegion {
    pub rect: Rect,
    pub url: String,
    pub label: String,
}

#[derive(Debug, Default)]
pub struct LinkRegistry {
    regions: Vec<LinkRegion>,
    hovered: Option<usize>,
    hovered_url: Option<String>,
    generation: u64,
}

impl LinkRegistry {
    pub fn begin_frame(&mut self) {
        self.regions.clear();
        self.hovered = None;
    }

    pub fn invalidate_pointer_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn register(&mut self, rect: Rect, url: impl Into<String>, label: impl Into<String>) {
        if rect.width > 0 && rect.height == 1 {
            let url = url.into();
            let index = self.regions.len();
            if self.hovered_url.as_deref() == Some(url.as_str()) {
                self.hovered = Some(index);
            }
            self.regions.push(LinkRegion {
                rect,
                url,
                label: label.into(),
            });
        }
    }

    pub fn at(&self, col: u16, row: u16) -> Option<&LinkRegion> {
        self.regions.iter().find(|link| {
            col >= link.rect.x
                && col < link.rect.x.saturating_add(link.rect.width)
                && row == link.rect.y
        })
    }

    pub fn update_hover(&mut self, col: u16, row: u16) -> bool {
        let next = self.regions.iter().position(|link| {
            col >= link.rect.x
                && col < link.rect.x.saturating_add(link.rect.width)
                && row == link.rect.y
        });
        let changed = next != self.hovered;
        self.hovered = next;
        self.hovered_url = next.map(|index| self.regions[index].url.clone());
        changed
    }

    pub fn clear_hover(&mut self) {
        self.hovered = None;
        self.hovered_url = None;
    }

    pub fn hovered(&self) -> Option<&LinkRegion> {
        self.hovered.and_then(|index| self.regions.get(index))
    }

    pub fn hovered_url(&self) -> Option<&str> {
        self.hovered_url.as_deref()
    }

    pub fn regions(&self) -> &[LinkRegion] {
        &self.regions
    }
}

const LINK_RELEASE_WINDOW: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
struct PendingLinkPress {
    url: String,
    column: u16,
    row: u16,
    registry_generation: u64,
    #[allow(dead_code)]
    pressed_at: Instant,
}

/// A scheduled activation waiting for the multi-click window to expire.
/// The host calls [`LinkPointerGesture::check_activation`] after the
/// deadline to see if the token is still current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingActivation {
    pub url: String,
    pub token: u64,
    pub deadline: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkGestureOutcome {
    Consumed,
    /// Link activation scheduled — the host should start a timer and call
    /// [`LinkPointerGesture::check_activation`] after the deadline. A
    /// second click, movement, view change, or cancellation tombstones the
    /// token before the timer fires.
    ScheduleActivation(PendingActivation),
    /// Link activation is now current — the host should open/copy the URL.
    Activate(String),
    /// A second click on the same semantic link canceled the pending
    /// activation and the release is now a double-click. The host should
    /// select the URL/word.
    SelectUrl(String),
    Unhandled,
}

/// Generation-scoped press/release reducer for registered links. Activation
/// is deliberately delayed through the 500 ms multi-click window so a second
/// click on the same semantic link can cancel it and become explicit URL
/// double-click selection. A new press, capture transition, render
/// generation, movement, or unrelated button tombstones the pending
/// activation token so any queued timer is inert.
#[derive(Debug, Default)]
pub struct LinkPointerGesture {
    pending: Option<PendingLinkPress>,
    /// Pending activation after a matching release, awaiting the
    /// multi-click window to expire.
    pending_activation: Option<PendingActivation>,
    /// The semantic link URL of the first click in the current sequence.
    sequence_url: Option<String>,
    /// The timestamp of the first click in the current sequence.
    sequence_started: Option<Instant>,
    /// Click count in the current multi-click sequence.
    click_count: u32,
    next_token: u64,
}

impl LinkPointerGesture {
    pub fn handle(
        &mut self,
        kind: crossterm::event::MouseEventKind,
        column: u16,
        row: u16,
        hit_url: Option<&str>,
        registry_generation: u64,
        now: Instant,
    ) -> LinkGestureOutcome {
        use crossterm::event::{MouseButton, MouseEventKind};
        match kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let Some(url) = hit_url else {
                    self.cancel();
                    return LinkGestureOutcome::Unhandled;
                };
                // A second press on the same semantic link within the
                // window tombstones the pending activation. The release
                // will then be a double-click.
                self.tombstone_activation();

                // Determine multi-click sequence.
                let same_target = self.sequence_url.as_deref() == Some(url);
                let expired = self.sequence_started.is_some_and(|started| {
                    now.saturating_duration_since(started) > LINK_RELEASE_WINDOW
                });
                if !same_target || expired {
                    self.click_count = 0;
                    self.sequence_url = Some(url.to_string());
                    self.sequence_started = Some(now);
                }
                self.click_count = self.click_count.saturating_add(1);

                self.pending = Some(PendingLinkPress {
                    url: url.to_string(),
                    column,
                    row,
                    registry_generation,
                    pressed_at: now,
                });
                LinkGestureOutcome::Consumed
            }
            MouseEventKind::Up(MouseButton::Left) => {
                let Some(pending) = self.pending.take() else {
                    return LinkGestureOutcome::Unhandled;
                };
                let matches = pending.column == column
                    && pending.row == row
                    && pending.registry_generation == registry_generation
                    && hit_url == Some(pending.url.as_str());

                if !matches {
                    return LinkGestureOutcome::Consumed;
                }

                // Double-click on the same semantic link → cancel
                // activation and select the URL.
                if self.click_count >= 2 {
                    self.tombstone_activation();
                    self.click_count = 0;
                    self.sequence_url = None;
                    self.sequence_started = None;
                    return LinkGestureOutcome::SelectUrl(pending.url);
                }

                // Single click release → schedule delayed activation.
                let token = self.fresh_token();
                let deadline = now + LINK_RELEASE_WINDOW;
                let pa = PendingActivation {
                    url: pending.url.clone(),
                    token,
                    deadline,
                };
                self.pending_activation = Some(pa.clone());
                LinkGestureOutcome::ScheduleActivation(pa)
            }
            MouseEventKind::Down(_) | MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                self.cancel();
                LinkGestureOutcome::Unhandled
            }
            _ => LinkGestureOutcome::Unhandled,
        }
    }

    /// Check whether the pending activation token is still current and
    /// the deadline has passed. Called by the host after the timer fires.
    /// Returns `Activate(url)` if current, `Consumed` otherwise.
    pub fn check_activation(&mut self, token: u64, now: Instant) -> LinkGestureOutcome {
        if let Some(pa) = &self.pending_activation
            && pa.token == token
            && now >= pa.deadline
        {
            let url = pa.url.clone();
            self.pending_activation = None;
            self.click_count = 0;
            self.sequence_url = None;
            self.sequence_started = None;
            return LinkGestureOutcome::Activate(url);
        }
        LinkGestureOutcome::Consumed
    }

    /// The URL of the pending activation, if any.
    pub fn pending_activation_url(&self) -> Option<&str> {
        self.pending_activation.as_ref().map(|pa| pa.url.as_str())
    }

    fn fresh_token(&mut self) -> u64 {
        let t = self.next_token;
        self.next_token = self.next_token.wrapping_add(1).max(1);
        t
    }

    fn tombstone_activation(&mut self) {
        self.pending_activation = None;
    }

    pub fn cancel(&mut self) {
        self.pending = None;
        self.tombstone_activation();
        self.click_count = 0;
        self.sequence_url = None;
        self.sequence_started = None;
    }
}

pub fn base_link_style() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::UNDERLINED)
}

pub fn hovered_link_style() -> Style {
    base_link_style().add_modifier(Modifier::BOLD)
}

pub fn link_style(hovered: bool) -> Style {
    if hovered {
        hovered_link_style()
    } else {
        base_link_style()
    }
}

pub fn clipped_label(label: &str, width: u16) -> String {
    let width = usize::from(width);
    if width == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(label) <= width {
        return label.to_string();
    }
    if width == 1 {
        return "…".into();
    }
    let mut out = String::new();
    let mut used = 0;
    for ch in label.chars() {
        let ch_width = ch.width().unwrap_or(0);
        if used + ch_width > width - 1 {
            break;
        }
        out.push(ch);
        used += ch_width;
    }
    out.push('…');
    out
}

fn safe_url(url: &str) -> bool {
    !url.is_empty() && !url.chars().any(char::is_control)
}

pub fn osc8_bytes(registry: &LinkRegistry, enabled: bool, is_tty: bool) -> Vec<u8> {
    if !enabled || !is_tty {
        return Vec::new();
    }
    let links = registry
        .regions()
        .iter()
        .filter(|link| safe_url(&link.url))
        .collect::<Vec<_>>();
    if links.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"\x1b7");
    out.extend_from_slice(b"\x1b[?25l");
    for link in links {
        let sequence = format!(
            "\x1b[{};{}H\x1b]8;;{}\x1b\\\x1b[36;4m{}\x1b[0m\x1b]8;;\x1b\\",
            link.rect.y + 1,
            link.rect.x + 1,
            link.url,
            link.label
        );
        out.extend_from_slice(sequence.as_bytes());
    }
    out.extend_from_slice(b"\x1b[?25h");
    out.extend_from_slice(b"\x1b8");
    out
}

pub fn emit_osc8(registry: &LinkRegistry, enabled: bool) -> io::Result<()> {
    let stdout = io::stdout();
    let bytes = osc8_bytes(registry, enabled, stdout.is_terminal());
    if bytes.is_empty() {
        return Ok(());
    }
    let mut lock = stdout.lock();
    lock.write_all(&bytes)?;
    lock.flush()
}

pub fn open_browser(url: &str) -> anyhow::Result<()> {
    cockpit_core::browser::open(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipping_is_single_line_and_uses_ellipsis() {
        assert_eq!(clipped_label("abcdefgh", 5), "abcd…");
        assert_eq!(clipped_label("abcdefgh", 1), "…");
    }

    #[test]
    fn registry_rebuild_and_hit_test() {
        let mut links = LinkRegistry::default();
        links.register(Rect::new(2, 3, 4, 1), "https://x.test", "link");
        assert_eq!(links.regions().len(), 1);
        assert!(links.at(2, 3).is_some());
        assert!(links.at(6, 3).is_none());
        links.begin_frame();
        assert!(links.regions().is_empty());
    }

    #[test]
    fn hover_getter_and_styles_reflect_hovered_region() {
        let mut links = LinkRegistry::default();
        links.register(Rect::new(2, 3, 4, 1), "https://x.test", "link");
        assert!(links.hovered().is_none());
        assert!(links.update_hover(2, 3));
        assert_eq!(
            links.hovered().map(|link| link.url.as_str()),
            Some("https://x.test")
        );
        assert!(
            hovered_link_style()
                .add_modifier
                .contains(Modifier::UNDERLINED)
        );
        assert!(hovered_link_style().add_modifier.contains(Modifier::BOLD));
        assert!(!base_link_style().add_modifier.contains(Modifier::BOLD));
        assert!(links.update_hover(7, 3));
        assert!(links.hovered().is_none());
    }

    #[test]
    fn osc8_is_gated_rejects_control_characters_and_preserves_label() {
        let mut links = LinkRegistry::default();
        links.register(Rect::new(1, 2, 4, 1), "https://x.test", "painted");
        links.register(Rect::new(1, 3, 4, 1), "https://bad\n.test", "bad");
        assert!(osc8_bytes(&links, false, true).is_empty());
        assert!(osc8_bytes(&links, true, false).is_empty());
        let rendered = String::from_utf8(osc8_bytes(&links, true, true)).unwrap();
        assert!(rendered.contains("\x1b7\x1b[?25l"));
        assert!(rendered.contains("\x1b[36;4mpainted\x1b[0m"));
        assert!(rendered.contains("\x1b[?25h\x1b8"));
        assert!(!rendered.contains("bad"));
    }

    #[test]
    fn osc8_short_circuits_without_safe_links_and_ignores_hover() {
        let empty = LinkRegistry::default();
        assert!(osc8_bytes(&empty, true, true).is_empty());

        let mut links = LinkRegistry::default();
        links.register(Rect::new(1, 2, 4, 1), "https://bad\n.test", "bad");
        assert!(osc8_bytes(&links, true, true).is_empty());

        let mut links = LinkRegistry::default();
        links.register(Rect::new(1, 2, 4, 1), "https://x.test", "link");
        let before = osc8_bytes(&links, true, true);
        assert!(links.update_hover(1, 2));
        let after = osc8_bytes(&links, true, true);
        assert_eq!(before, after);
    }

    #[test]
    fn pointer_gesture_schedules_activation_then_fires_after_window() {
        use crossterm::event::{MouseButton, MouseEventKind};
        let now = Instant::now();
        let mut gesture = LinkPointerGesture::default();

        // Press on a link — consumed, no activation.
        assert_eq!(
            gesture.handle(
                MouseEventKind::Down(MouseButton::Left),
                4,
                7,
                Some("https://x.test"),
                9,
                now,
            ),
            LinkGestureOutcome::Consumed
        );

        // Release on the same link — schedules activation (does not
        // activate synchronously).
        let outcome = gesture.handle(
            MouseEventKind::Up(MouseButton::Left),
            4,
            7,
            Some("https://x.test"),
            9,
            now + Duration::from_millis(10),
        );
        let pa = match outcome {
            LinkGestureOutcome::ScheduleActivation(pa) => pa,
            other => panic!("expected ScheduleActivation, got {other:?}"),
        };
        assert_eq!(pa.url, "https://x.test");
        assert_eq!(
            pa.deadline,
            now + Duration::from_millis(10) + LINK_RELEASE_WINDOW
        );

        // Before the deadline — check_activation is inert.
        assert_eq!(
            gesture.check_activation(pa.token, now + Duration::from_millis(100)),
            LinkGestureOutcome::Consumed,
        );

        // At/after the deadline — activates.
        assert_eq!(
            gesture.check_activation(pa.token, pa.deadline),
            LinkGestureOutcome::Activate("https://x.test".into())
        );

        // A second check with the same token is inert (already consumed).
        assert_eq!(
            gesture.check_activation(pa.token, pa.deadline + Duration::from_secs(1)),
            LinkGestureOutcome::Consumed,
        );
    }

    #[test]
    fn pointer_gesture_second_click_cancels_activation_and_selects_url() {
        use crossterm::event::{MouseButton, MouseEventKind};
        let now = Instant::now();
        let mut gesture = LinkPointerGesture::default();

        // First press + release → schedule activation.
        assert_eq!(
            gesture.handle(
                MouseEventKind::Down(MouseButton::Left),
                4,
                7,
                Some("https://x.test"),
                9,
                now,
            ),
            LinkGestureOutcome::Consumed
        );
        let outcome = gesture.handle(
            MouseEventKind::Up(MouseButton::Left),
            4,
            7,
            Some("https://x.test"),
            9,
            now + Duration::from_millis(10),
        );
        let pa = match outcome {
            LinkGestureOutcome::ScheduleActivation(pa) => pa,
            other => panic!("expected ScheduleActivation, got {other:?}"),
        };

        // Second press on the same link within the window — tombstones
        // the activation. The press is consumed.
        assert_eq!(
            gesture.handle(
                MouseEventKind::Down(MouseButton::Left),
                4,
                7,
                Some("https://x.test"),
                9,
                now + Duration::from_millis(200),
            ),
            LinkGestureOutcome::Consumed
        );

        // Second release — double-click selects the URL.
        assert_eq!(
            gesture.handle(
                MouseEventKind::Up(MouseButton::Left),
                4,
                7,
                Some("https://x.test"),
                9,
                now + Duration::from_millis(210),
            ),
            LinkGestureOutcome::SelectUrl("https://x.test".into())
        );

        // The stale timer is inert.
        assert_eq!(
            gesture.check_activation(pa.token, pa.deadline + Duration::from_secs(1)),
            LinkGestureOutcome::Consumed,
        );
    }

    #[test]
    fn pointer_gesture_render_generation_invalidates_press() {
        use crossterm::event::{MouseButton, MouseEventKind};
        let now = Instant::now();
        let mut gesture = LinkPointerGesture::default();

        // Press with generation 9.
        assert_eq!(
            gesture.handle(
                MouseEventKind::Down(MouseButton::Left),
                4,
                7,
                Some("https://x.test"),
                9,
                now,
            ),
            LinkGestureOutcome::Consumed
        );
        // Release with generation 10 — mismatch, consumed (no activation).
        assert_eq!(
            gesture.handle(
                MouseEventKind::Up(MouseButton::Left),
                4,
                7,
                Some("https://x.test"),
                10,
                now + Duration::from_millis(1),
            ),
            LinkGestureOutcome::Consumed,
            "render generation invalidates the press"
        );

        // Press again with generation 10, then cancel, then release —
        // unhandled (no pending press).
        let _ = gesture.handle(
            MouseEventKind::Down(MouseButton::Left),
            4,
            7,
            Some("https://x.test"),
            10,
            now,
        );
        gesture.cancel();
        assert_eq!(
            gesture.handle(
                MouseEventKind::Up(MouseButton::Left),
                4,
                7,
                Some("https://x.test"),
                10,
                now,
            ),
            LinkGestureOutcome::Unhandled
        );
    }
}
