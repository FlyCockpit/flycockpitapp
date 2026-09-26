//! Shared form chrome: the top-left "back" button that walks the onboarding
//! wizard backwards, and a right-aligned **action bar** of clickable buttons
//! (Continue / Save / Retry / …) so every step can be driven with the mouse
//! alone, not just the keyboard.

use ratatui::Frame;
use ratatui::layout::{Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::tui::chrome::chip_style;
pub(super) use crate::tui::chrome::{ActionBar, ActionButton as Button, action_bar_width};
#[cfg(test)]
use crate::tui::chrome::{action_button_at as button_at, render_action_bar};
use crate::tui::theme::{BRASS, DISABLED};

const BACK_LABEL: &str = " ‹ Back ";

/// Where the back button sits in `area` (its top-left corner), whether or
/// not it is painted this frame. Callers derive hover from this rect and the
/// pointer before painting.
pub(super) fn back_button_rect(area: Rect) -> Rect {
    if area.width == 0 || area.height == 0 {
        return Rect::default();
    }
    Rect {
        x: area.x,
        y: area.y,
        width: (BACK_LABEL.chars().count() as u16).min(area.width),
        height: 1,
    }
}

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
    let rect = back_button_rect(area);
    let style = if !enabled {
        Style::new().fg(DISABLED)
    } else {
        chip_style(Style::new().fg(BRASS), hovered)
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
    fn disabled_buttons_paint_but_action_bar_rejects_clicks() {
        let buttons = [Button::primary("Next").enabled(false)];
        let (rects, text) = render(&buttons, None);
        let rect = rects[0];
        assert!(text.contains("[ Next ]"), "{text}");
        assert!(rect.width > 0 && rect.height > 0);
        // Raw geometry remains visible to settings' pointer registry; the
        // stateful ActionBar is the interaction boundary and rejects it.
        assert_eq!(button_at(&rects, Position::new(rect.x, rect.y)), Some(0));

        let backend = TestBackend::new(40, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut action_bar = ActionBar::default();
        terminal
            .draw(|frame| action_bar.render(frame, frame.area(), &buttons, None))
            .unwrap();
        assert_eq!(action_bar.clicked(Position::new(rect.x, rect.y)), None);
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
