use super::slash::SLASH_COMMANDS;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::tui::theme::{ACCENT_BLUE_INDEX, MUTED_COLOR_INDEX};

const TITLE: &str = " Help ";
const MIN_WIDTH: u16 = 30;
const MIN_HEIGHT: u16 = 8;

#[derive(Default)]
pub(in crate::tui) struct HelpOverlay {
    scroll: u16,
    last_content_rows: u16,
    last_visible_rows: u16,
}

impl HelpOverlay {
    pub(super) fn open() -> Self {
        Self::default()
    }

    pub(super) fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => true,
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll_up();
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll_down();
                false
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(self.page_size());
                false
            }
            KeyCode::PageDown => {
                self.scroll = self
                    .scroll
                    .saturating_add(self.page_size())
                    .min(self.max_scroll());
                false
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.scroll = 0;
                false
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.scroll = self.max_scroll();
                false
            }
            _ => false,
        }
    }

    pub(super) fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    pub(super) fn scroll_down(&mut self) {
        self.scroll = self.scroll.saturating_add(1).min(self.max_scroll());
    }

    pub(super) fn render(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        let rect = centered_rect(area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(TITLE)
            .border_style(Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX)));
        let inner = block.inner(rect);
        let lines = help_lines();
        self.last_content_rows = lines.len() as u16;
        self.last_visible_rows = inner.height;
        self.scroll = self.scroll.min(self.max_scroll());

        frame.render_widget(Clear, rect);
        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((self.scroll, 0));
        frame.render_widget(paragraph, rect);
    }

    fn page_size(&self) -> u16 {
        self.last_visible_rows.max(1)
    }

    fn max_scroll(&self) -> u16 {
        self.last_content_rows
            .saturating_sub(self.last_visible_rows)
    }

    #[cfg(test)]
    pub(super) fn snapshot_text() -> String {
        help_lines()
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content.into_owned())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[cfg(test)]
    pub(super) fn scroll_for_test(&self) -> u16 {
        self.scroll
    }
}

fn centered_rect(area: Rect) -> Rect {
    let width = area.width.saturating_sub(2).clamp(MIN_WIDTH, 78);
    let height = area.height.saturating_sub(2).clamp(MIN_HEIGHT, 22);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}

fn help_lines() -> Vec<Line<'static>> {
    let heading = Style::default().add_modifier(Modifier::BOLD);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let command = Style::default()
        .fg(Color::Indexed(ACCENT_BLUE_INDEX))
        .add_modifier(Modifier::BOLD);

    let mut lines = vec![
        Line::from(Span::styled("Getting started", heading)),
        Line::from(vec![
            Span::raw("Type a message, then press "),
            Span::styled("Enter", command),
            Span::raw(" to send it."),
        ]),
        Line::from(vec![
            Span::styled("/", command),
            Span::raw(" opens the command menu; "),
            Span::styled("Ctrl+K", command),
            Span::raw(" opens keybindings."),
        ]),
        Line::from(vec![
            Span::styled("/setup", command),
            Span::raw(" opens provider and workspace setup wizards."),
        ]),
        Line::from(Span::styled(
            "Esc closes overlays and dialogs. Ctrl+C interrupts the running agent.",
            muted,
        )),
        Line::default(),
        Line::from(Span::styled("Slash commands", heading)),
    ];

    for slash in SLASH_COMMANDS {
        lines.push(Line::from(vec![
            Span::styled(format!("/{:<18}", slash.name), command),
            Span::raw(slash.description),
        ]));
    }

    lines.extend([
        Line::default(),
        Line::from(Span::styled("More help", heading)),
        Line::from("Run `cockpit doctor` outside the TUI for environment diagnostics."),
        Line::from("Use `/settings` for model, provider, UI, and permission settings."),
        Line::from(Span::styled(
            "Scroll with ↑/↓, j/k, PageUp/PageDown. Press Esc or q to close.",
            muted,
        )),
    ]);
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    #[test]
    fn help_overlay_lists_all_slash_commands() {
        let snapshot = HelpOverlay::snapshot_text();
        for slash in SLASH_COMMANDS {
            assert!(
                snapshot.contains(&format!("/{}", slash.name)),
                "missing /{} in help overlay:\n{snapshot}",
                slash.name
            );
            assert!(
                snapshot.contains(slash.description),
                "missing /{} description in help overlay:\n{snapshot}",
                slash.name
            );
        }
    }

    #[test]
    fn help_overlay_getting_started_names_command_entrypoints() {
        let snapshot = HelpOverlay::snapshot_text();

        assert!(
            snapshot.contains("/ opens the command menu"),
            "missing slash hint:\n{snapshot}"
        );
        assert!(
            snapshot.contains("Ctrl+K"),
            "missing Ctrl+K hint:\n{snapshot}"
        );
        assert!(
            snapshot.contains("/setup opens provider and workspace setup wizards"),
            "missing /setup hint:\n{snapshot}"
        );
    }

    #[test]
    fn help_overlay_small_terminal_scrolls() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let mut overlay = HelpOverlay::open();

        terminal
            .draw(|frame| overlay.render(frame, Rect::new(0, 0, 80, 24)))
            .expect("help renders in an 80x24 terminal");
        overlay.handle_key(press(KeyCode::PageDown));

        assert!(
            overlay.scroll_for_test() > 0,
            "help overlay should scroll after PageDown"
        );
    }
}
