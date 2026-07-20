//! Right-click context menu for the chat area.
//!
//! Triggered by `MouseEventKind::Down(MouseButton::Right)` in the chat
//! area when `tui.mouse_capture` is on. Offers per-message copy
//! actions in three formats: rich text (HTML), markdown source, and
//! markdown rendered to plain text.
//!
//! The "Copy as rich text" option is omitted over SSH — `arboard`
//! can't reach the local clipboard through an SSH pipe, so there's
//! no useful path for multi-format clipboard data in that case. The
//! markdown and plain-text variants go through OSC52 (plus `arboard`
//! locally as a parallel backend) and work over SSH so long as the
//! terminal honors OSC52.
//!
//! Layout follows the same visual language as the queue / input box:
//! rounded borders, white outline, yellow highlight on the focused
//! row. Plays nicely with the dialog/modal stack — the menu
//! intercepts every key and mouse event while open.
//!
//! See `plan.md` T8 for the broader feature plan.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use unicode_width::UnicodeWidthStr;

/// Actions the user can pick from the context menu. Resolved by the
/// App in [`crate::tui::app::App::execute_context_menu_action`]. All
/// three operate on the agent message under (or most recently
/// before) the right-click point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// The shared `CopyAs` prefix is the meaningful "copy as <format>" family
// name, not incidental repetition — renaming would obscure intent.
#[allow(clippy::enum_variant_names)]
pub enum ContextMenuAction {
    /// Open the changed file under a diff row in `$EDITOR`. Only offered
    /// when the right-click resolved to a diff row and `$EDITOR` is set.
    OpenInEditor,
    /// Copy the agent message under the right-click as rich text
    /// (HTML to clipboard, plain alt). Only offered when not on SSH
    /// — `arboard` can't reach the local clipboard over SSH.
    CopyAsRichText,
    /// Copy the agent message's raw markdown source verbatim. Lands
    /// on the clipboard as plain text — paste into Slack / GitHub /
    /// anywhere that re-renders markdown.
    CopyAsMarkdown,
    /// Copy the agent message rendered to plain text (formatting
    /// markers stripped, list items prefixed with `- `, paragraphs
    /// separated by blank lines). Best for pasting into an editor
    /// or plain-text email.
    CopyAsPlainText,
}

impl ContextMenuAction {
    fn label(self) -> &'static str {
        match self {
            Self::OpenInEditor => "Open in $EDITOR",
            Self::CopyAsRichText => "Copy as rich text",
            Self::CopyAsMarkdown => "Copy as markdown",
            Self::CopyAsPlainText => "Copy as plain text",
        }
    }
}

fn label_display_width(label: &str) -> usize {
    UnicodeWidthStr::width(label)
}

/// Active right-click context menu state.
#[derive(Debug, Clone)]
pub struct ContextMenu {
    /// Absolute terminal position the menu's top-left corner would
    /// prefer. The render function clamps this so the menu fits on
    /// screen.
    pub preferred_origin: (u16, u16),
    /// Which row of the chat area (chat-relative) the user
    /// right-clicked on. Each copy action uses this to find the
    /// agent message under the click.
    pub clicked_chat_row: usize,
    /// Item the keyboard focus is on.
    pub cursor: usize,
    /// Item list — composed at menu-open time based on whether
    /// rich-text copy is available (i.e., not on SSH). Fixed for
    /// the lifetime of this menu open.
    pub items: Vec<ContextMenuAction>,
}

impl ContextMenu {
    /// Build the items list for the current session. Includes rich
    /// text only when the local OS clipboard is reachable (i.e.,
    /// `!is_ssh`). Markdown + plain text always available.
    pub fn build_items(is_ssh: bool, diff_editor: bool) -> Vec<ContextMenuAction> {
        let mut items = Vec::with_capacity(4);
        if diff_editor {
            items.push(ContextMenuAction::OpenInEditor);
        }
        if !is_ssh {
            items.push(ContextMenuAction::CopyAsRichText);
        }
        items.push(ContextMenuAction::CopyAsMarkdown);
        items.push(ContextMenuAction::CopyAsPlainText);
        items
    }

    /// Move the keyboard focus by `delta` (±1), wrapping at both ends —
    /// Up on the first item lands on the last, Down on the last lands on
    /// the first. Consistent with every other selectable list in the TUI.
    pub fn move_cursor(&mut self, delta: i32) {
        let len = self.items.len();
        if len == 0 {
            return;
        }
        self.cursor = match delta.cmp(&0) {
            std::cmp::Ordering::Less => crate::tui::nav::wrap_prev(self.cursor, len),
            std::cmp::Ordering::Greater => crate::tui::nav::wrap_next(self.cursor, len),
            std::cmp::Ordering::Equal => self.cursor,
        };
    }

    pub fn focused_action(&self) -> Option<ContextMenuAction> {
        self.items.get(self.cursor).copied()
    }

    /// Hit-test a mouse click against the rendered menu. Returns the
    /// action under `(col, row)` if any.
    pub fn hit_test(&self, col: u16, row: u16, full_area: Rect) -> Option<ContextMenuAction> {
        let menu_rect = self.placement(full_area);
        if col < menu_rect.x || col >= menu_rect.x + menu_rect.width {
            return None;
        }
        if row <= menu_rect.y || row >= menu_rect.y + menu_rect.height.saturating_sub(1) {
            return None;
        }
        // First and last row are borders; items occupy the inner rows.
        let item_row = row.saturating_sub(menu_rect.y + 1) as usize;
        self.items.get(item_row).copied()
    }

    /// Compute the on-screen rect for the menu, clamping so it always
    /// fits inside `full_area`. Width is fixed; height = items + 2 for
    /// borders.
    pub fn placement(&self, full_area: Rect) -> Rect {
        let width = self.render_width();
        let height = self.items.len() as u16 + 2;
        let mut x = self.preferred_origin.0;
        let mut y = self.preferred_origin.1;
        if x + width > full_area.x + full_area.width {
            x = (full_area.x + full_area.width).saturating_sub(width);
        }
        if x < full_area.x {
            x = full_area.x;
        }
        if y + height > full_area.y + full_area.height {
            // Flip above the click if there's no room below.
            y = y.saturating_sub(height);
        }
        if y < full_area.y {
            y = full_area.y;
        }
        Rect::new(x, y, width, height)
    }

    fn render_width(&self) -> u16 {
        // Widest label + 4 (left pad + right pad + 2 border cells).
        let widest = self
            .items
            .iter()
            .map(|a| label_display_width(a.label()))
            .max()
            .unwrap_or(0) as u16;
        widest + 4
    }
}

/// Render the context menu over the given full area (typically the
/// frame's whole rect).
pub fn render_context_menu(frame: &mut Frame, full_area: Rect, menu: &ContextMenu) {
    let rect = menu.placement(full_area);
    // Wipe whatever was rendered underneath so the menu reads cleanly.
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::White));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let mut lines: Vec<Line<'static>> = Vec::new();
    for (i, action) in menu.items.iter().enumerate() {
        let focused = i == menu.cursor;
        let marker = if focused { "▸ " } else { "  " };
        let style = if focused {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(action.label().to_string(), style),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn menu(items: Vec<ContextMenuAction>) -> ContextMenu {
        ContextMenu {
            preferred_origin: (0, 0),
            clicked_chat_row: 0,
            cursor: 0,
            items,
        }
    }

    #[test]
    fn move_cursor_wraps_at_both_ends() {
        let mut m = menu(vec![
            ContextMenuAction::CopyAsRichText,
            ContextMenuAction::CopyAsMarkdown,
            ContextMenuAction::CopyAsPlainText,
        ]);
        // Up from the first item wraps to the last.
        m.move_cursor(-1);
        assert_eq!(m.cursor, 2);
        // Down from the last item wraps to the first.
        m.move_cursor(1);
        assert_eq!(m.cursor, 0);
    }

    #[test]
    fn move_cursor_single_item_stays_put() {
        let mut m = menu(vec![ContextMenuAction::CopyAsMarkdown]);
        m.move_cursor(1);
        assert_eq!(m.cursor, 0);
        m.move_cursor(-1);
        assert_eq!(m.cursor, 0);
    }

    #[test]
    fn move_cursor_empty_is_noop() {
        let mut m = menu(Vec::new());
        m.move_cursor(1);
        assert_eq!(m.cursor, 0);
        m.move_cursor(-1);
        assert_eq!(m.cursor, 0);
    }

    #[test]
    fn build_items_adds_editor_action_first_for_diff_rows() {
        let items = ContextMenu::build_items(false, true);
        assert_eq!(items.first(), Some(&ContextMenuAction::OpenInEditor));
        assert!(items.contains(&ContextMenuAction::CopyAsMarkdown));
    }

    #[test]
    fn build_items_omits_editor_action_for_non_diff_rows() {
        let items = ContextMenu::build_items(false, false);
        assert!(!items.contains(&ContextMenuAction::OpenInEditor));
    }

    #[test]
    fn render_width_ascii_unchanged() {
        let m = menu(ContextMenu::build_items(false, true));

        assert_eq!(m.render_width(), 22);
        let widest = m
            .items
            .iter()
            .map(|action| label_display_width(action.label()))
            .max()
            .unwrap();
        assert_eq!(m.render_width(), widest as u16 + 4);
    }

    #[test]
    fn render_width_counts_display_columns_for_wide_glyph() {
        let label = "Copy 好";

        assert_eq!(label.chars().count(), 6);
        assert_eq!(label_display_width(label), 7);
    }

    #[test]
    fn placement_and_hit_test_agree_on_width() {
        let mut m = menu(ContextMenu::build_items(false, true));
        m.preferred_origin = (10, 5);
        let full_area = Rect::new(0, 0, 80, 24);
        let rect = m.placement(full_area);

        assert_eq!(rect.width, m.render_width());
        assert_eq!(
            m.hit_test(rect.x + rect.width - 1, rect.y + 1, full_area),
            Some(ContextMenuAction::OpenInEditor)
        );
        assert_eq!(m.hit_test(rect.x + rect.width, rect.y + 1, full_area), None);
    }

    #[test]
    fn hit_test_ignores_menu_borders() {
        let mut m = menu(ContextMenu::build_items(false, true));
        m.preferred_origin = (10, 5);
        let full_area = Rect::new(0, 0, 80, 24);
        let rect = m.placement(full_area);

        assert_eq!(m.hit_test(rect.x + 1, rect.y, full_area), None);
        assert_eq!(
            m.hit_test(rect.x + 1, rect.y + rect.height - 1, full_area),
            None
        );
        assert_eq!(
            m.hit_test(rect.x + 1, rect.y + 1, full_area),
            Some(ContextMenuAction::OpenInEditor)
        );
    }
}
