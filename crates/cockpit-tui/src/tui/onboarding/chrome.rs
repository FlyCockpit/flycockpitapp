//! Shared form chrome: the top-left "back" button that walks the onboarding
//! wizard backwards, and a right-aligned **action bar** of clickable buttons
//! (Continue / Save / Retry / …) so every step can be driven with the mouse
//! alone, not just the keyboard.

use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::theme::{BRASS, DISABLED, FOG, HOVER_BG, INK};

const BACK_LABEL: &str = " ‹ Back ";

/// Draw the back button in the top-left of `area` and return the rect it
/// occupies so the caller can hit-test clicks against it. When the wizard is
/// on its first step there is nowhere to go back to, so pass `visible = false`
/// and the returned rect is empty (matches nothing).
///
/// `enabled = false` still paints `‹ Back` (in [`DISABLED`]) so the control
/// stays visible on stages the daemon rejects (`Welcome`, `Provider`), but
/// returns [`Rect::default()`] so clicks are structurally ignored — the same
/// idiom as a disabled [`Button`].
pub(super) fn render_back_button(
    frame: &mut Frame,
    area: Rect,
    visible: bool,
    enabled: bool,
    hovered: bool,
) -> Rect {
    if !visible || area.width == 0 || area.height == 0 {
        return Rect::default();
    }
    let width = BACK_LABEL.chars().count() as u16;
    let rect = Rect {
        x: area.x,
        y: area.y,
        width: width.min(area.width),
        height: 1,
    };
    let style = if !enabled {
        Style::new().fg(DISABLED)
    } else if hovered {
        Style::new()
            .fg(BRASS)
            .bg(HOVER_BG)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(BRASS)
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(BACK_LABEL, style))),
        rect,
    );
    if enabled { rect } else { Rect::default() }
}

/// Whether `pos` falls on a rect (empty rects never match). Used for the back
/// button and every action-bar button.
pub(super) fn hit(rect: Rect, pos: Position) -> bool {
    rect.width > 0 && rect.height > 0 && rect.contains(pos)
}

/// One clickable button in an [`render_action_bar`].
pub(super) struct Button<'a> {
    pub label: &'a str,
    /// Disabled buttons render dimmed and never match a click.
    pub enabled: bool,
    /// The primary (default) action is brass and bold; others are muted.
    pub primary: bool,
}

impl<'a> Button<'a> {
    pub(super) fn primary(label: &'a str) -> Self {
        Self {
            label,
            enabled: true,
            primary: true,
        }
    }

    pub(super) fn secondary(label: &'a str) -> Self {
        Self {
            label,
            enabled: true,
            primary: false,
        }
    }

    #[allow(dead_code)] // variable button sets in #428–#433.
    pub(super) fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Cells the action bar occupies, including 1-cell gaps. Used to clip the
/// left-aligned help string so the two never paint over each other.
pub(super) fn action_bar_width(buttons: &[Button<'_>]) -> u16 {
    if buttons.is_empty() {
        return 0;
    }
    let labels: u16 = buttons
        .iter()
        .map(|button| button.label.chars().count() as u16 + 4)
        .sum();
    labels + (buttons.len() as u16).saturating_sub(1)
}

/// Render `buttons` right-aligned on the single-line `area` (typically the help
/// row, sharing it with the left-aligned key hints). Returns each button's rect
/// in order for hit-testing; disabled buttons get an empty rect so their clicks
/// are ignored. `hover` highlights the button currently under the pointer.
pub(super) fn render_action_bar(
    frame: &mut Frame,
    area: Rect,
    buttons: &[Button<'_>],
    hover: Option<usize>,
) -> Vec<Rect> {
    let mut rects = vec![Rect::default(); buttons.len()];
    if area.width == 0 || area.height == 0 || buttons.is_empty() {
        return rects;
    }
    let gap: u16 = 1;
    // "[ " + label + " ]" = label + 4 cells.
    let widths: Vec<u16> = buttons
        .iter()
        .map(|b| b.label.chars().count() as u16 + 4)
        .collect();
    let total: u16 = widths.iter().sum::<u16>() + gap * (buttons.len().saturating_sub(1) as u16);
    let mut x = if total >= area.width {
        area.x
    } else {
        area.right() - total
    };
    for (index, button) in buttons.iter().enumerate() {
        if x >= area.right() {
            break;
        }
        let width = widths[index].min(area.right() - x);
        let rect = Rect {
            x,
            y: area.y,
            width,
            height: 1,
        };
        let hovered = hover == Some(index) && button.enabled;
        let style = if !button.enabled {
            Style::new().fg(DISABLED)
        } else if hovered {
            Style::new()
                .fg(if button.primary { BRASS } else { INK })
                .bg(HOVER_BG)
                .add_modifier(Modifier::BOLD)
        } else if button.primary {
            Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(FOG)
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("[ {} ]", button.label),
                style,
            ))),
            rect,
        );
        if button.enabled {
            rects[index] = rect;
        }
        x += widths[index] + gap;
    }
    rects
}

/// Index of the button whose rect contains `pos`, if any.
pub(super) fn button_at(rects: &[Rect], pos: Position) -> Option<usize> {
    rects.iter().position(|rect| hit(*rect, pos))
}

/// A stateful wrapper around [`render_action_bar`] that remembers the button
/// rects and the hovered button between frames, so a screen only needs a
/// single field. Render it each frame, feed pointer moves to [`Self::track`],
/// and map left-clicks with [`Self::clicked`].
#[derive(Default)]
pub(super) struct ActionBar {
    rects: Vec<Rect>,
    hover: Option<usize>,
}

impl ActionBar {
    /// Draw the buttons right-aligned on `area` (usually the help row).
    pub(super) fn render(&mut self, frame: &mut Frame, area: Rect, buttons: &[Button<'_>]) {
        self.rects = render_action_bar(frame, area, buttons, self.hover);
    }

    /// Update the hovered button from a pointer position (call on move/drag).
    pub(super) fn track(&mut self, pos: Position) {
        self.hover = button_at(&self.rects, pos);
    }

    /// The button index under `pos`, if any (call on a left-click).
    pub(super) fn clicked(&self, pos: Position) -> Option<usize> {
        button_at(&self.rects, pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render(buttons: &[Button<'_>], hover: Option<usize>) -> (Vec<Rect>, String) {
        let backend = TestBackend::new(40, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut rects = Vec::new();
        terminal
            .draw(|frame| {
                rects = render_action_bar(frame, frame.area(), buttons, hover);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let text: String = buf.content().iter().map(|c| c.symbol()).collect();
        (rects, text)
    }

    fn render_back(visible: bool, enabled: bool, hovered: bool) -> (Rect, String) {
        let backend = TestBackend::new(20, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut rect = Rect::default();
        terminal
            .draw(|frame| {
                rect = render_back_button(frame, frame.area(), visible, enabled, hovered);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let text: String = buf.content().iter().map(|c| c.symbol()).collect();
        (rect, text)
    }

    #[test]
    fn buttons_render_and_hit_test() {
        let buttons = [Button::secondary("Add"), Button::primary("Done")];
        let (rects, text) = render(&buttons, None);
        assert!(text.contains("[ Add ]"));
        assert!(text.contains("[ Done ]"));
        // Both buttons are enabled, so both have a real rect.
        assert!(rects.iter().all(|r| r.width > 0));
        // A click inside the "Done" rect maps back to index 1.
        let done = rects[1];
        assert_eq!(button_at(&rects, Position::new(done.x, done.y)), Some(1));
    }

    #[test]
    fn disabled_buttons_are_unclickable() {
        let buttons = [Button::primary("Next").enabled(false)];
        let (rects, _) = render(&buttons, None);
        assert_eq!(rects[0], Rect::default());
        assert_eq!(button_at(&rects, Position::ORIGIN), None);
    }

    #[test]
    fn disabled_back_button_paints_but_is_unclickable() {
        let (rect, text) = render_back(true, false, false);
        assert!(text.contains("‹ Back"), "{text}");
        assert_eq!(rect, Rect::default());
        assert!(!hit(rect, Position::ORIGIN));
    }

    #[test]
    fn hidden_back_button_paints_nothing() {
        let (rect, text) = render_back(false, true, false);
        assert_eq!(rect, Rect::default());
        assert!(!text.contains("‹ Back"), "{text}");
    }
}
