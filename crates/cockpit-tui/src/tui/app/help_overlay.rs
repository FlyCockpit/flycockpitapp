use super::slash::SLASH_COMMANDS;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use unicode_width::UnicodeWidthStr;

use crate::tui::message_block::{slice_spans_at_width, wrap_lines_to_width};
use crate::tui::theme::{ACCENT_BLUE_INDEX, MUTED_COLOR_INDEX};

const TITLE: &str = " Help ";
const MIN_WIDTH: u16 = 30;
const MIN_HEIGHT: u16 = 8;
const NAME_GUTTER: usize = 2;
const MAX_NAME_COLUMN: usize = 24;
const MIN_DESCRIPTION_COLUMN: usize = 20;
const NARROW_CONTINUATION_INDENT: usize = 2;

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
        let lines = help_lines(inner.width);
        self.last_content_rows = lines.len() as u16;
        self.last_visible_rows = inner.height;
        self.scroll = self.scroll.min(self.max_scroll());

        frame.render_widget(Clear, rect);
        let paragraph = Paragraph::new(lines).block(block).scroll((self.scroll, 0));
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
    pub(super) fn snapshot_text(width: u16) -> String {
        help_lines(width)
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
    let width = area.width.saturating_sub(2).max(MIN_WIDTH).min(area.width);
    let height = area
        .height
        .saturating_sub(2)
        .max(MIN_HEIGHT)
        .min(area.height);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width, height)
}

fn help_lines(inner_width: u16) -> Vec<Line<'static>> {
    let heading = Style::default().add_modifier(Modifier::BOLD);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let command = Style::default()
        .fg(Color::Indexed(ACCENT_BLUE_INDEX))
        .add_modifier(Modifier::BOLD);

    let width = usize::from(inner_width).max(1);
    let mut lines = Vec::new();
    push_wrapped(
        &mut lines,
        Line::from(Span::styled("Getting started", heading)),
        width,
    );
    push_wrapped(
        &mut lines,
        Line::from(vec![
            Span::raw("Type a message, then press "),
            Span::styled("Enter", command),
            Span::raw(" to send it."),
        ]),
        width,
    );
    push_wrapped(
        &mut lines,
        Line::from(vec![
            Span::styled("/", command),
            Span::raw(" opens the command menu; "),
            Span::styled("Ctrl+K", command),
            Span::raw(" opens keybindings."),
        ]),
        width,
    );
    push_wrapped(
        &mut lines,
        Line::from(vec![
            Span::styled("/setup", command),
            Span::raw(" opens provider and workspace setup wizards."),
        ]),
        width,
    );
    push_wrapped(
        &mut lines,
        Line::from(Span::styled(
            "Esc closes overlays and dialogs. Ctrl+C interrupts the running agent.",
            muted,
        )),
        width,
    );
    lines.push(Line::default());
    push_wrapped(
        &mut lines,
        Line::from(Span::styled("Slash commands", heading)),
        width,
    );

    lines.extend(command_lines(
        SLASH_COMMANDS
            .iter()
            .map(|slash| (slash.name, slash.description)),
        width,
        command,
    ));

    lines.push(Line::default());
    push_wrapped(
        &mut lines,
        Line::from(Span::styled("More help", heading)),
        width,
    );
    push_wrapped(
        &mut lines,
        Line::from("Run `cockpit doctor` outside the TUI for environment diagnostics."),
        width,
    );
    push_wrapped(
        &mut lines,
        Line::from("Use `/settings` for model, provider, UI, and permission settings."),
        width,
    );
    push_wrapped(
        &mut lines,
        Line::from(Span::styled(
            "Scroll with ↑/↓, j/k, PageUp/PageDown. Press Esc or q to close.",
            muted,
        )),
        width,
    );
    lines
}

fn push_wrapped(lines: &mut Vec<Line<'static>>, line: Line<'static>, width: usize) {
    let (wrapped, _) = wrap_lines_to_width(vec![line], width);
    lines.extend(wrapped);
}

fn command_lines<'a>(
    commands: impl IntoIterator<Item = (&'a str, &'a str)>,
    inner_width: usize,
    command_style: Style,
) -> Vec<Line<'static>> {
    let entries: Vec<(&str, &str)> = commands.into_iter().collect();
    let name_column = name_column_width(entries.iter().map(|(name, _)| *name));
    let narrow = inner_width <= name_column.saturating_add(MIN_DESCRIPTION_COLUMN);
    let mut lines = Vec::new();
    for (name, description) in entries {
        if narrow {
            lines.extend(narrow_command_lines(
                name,
                description,
                inner_width,
                command_style,
            ));
        } else {
            lines.extend(wide_command_lines(
                name,
                description,
                inner_width,
                name_column,
                command_style,
            ));
        }
    }
    lines
}

fn name_column_width<'a>(names: impl IntoIterator<Item = &'a str>) -> usize {
    names
        .into_iter()
        .map(|name| format!("/{name}").width())
        .max()
        .unwrap_or(1)
        .saturating_add(NAME_GUTTER)
        .min(MAX_NAME_COLUMN)
}

fn wide_command_lines(
    name: &str,
    description: &str,
    inner_width: usize,
    name_column: usize,
    command_style: Style,
) -> Vec<Line<'static>> {
    let description_width = inner_width.saturating_sub(name_column).max(1);
    let name_spans =
        command_name_spans(name, command_style, name_column.saturating_sub(NAME_GUTTER));
    let name_width = first_prefix_width(&name_spans);
    let padding = name_column.saturating_sub(name_width);
    wrap_prefixed_description(
        [name_spans, vec![Span::raw(" ".repeat(padding))]].concat(),
        name_column,
        description,
        description_width,
    )
}

fn narrow_command_lines(
    name: &str,
    description: &str,
    inner_width: usize,
    command_style: Style,
) -> Vec<Line<'static>> {
    let name_budget = inner_width.saturating_sub(NAME_GUTTER + 1).max(1);
    let mut prefix = command_name_spans(name, command_style, name_budget);
    prefix.push(Span::raw(" ".repeat(NAME_GUTTER)));
    let first_description_width = inner_width
        .saturating_sub(first_prefix_width(&prefix))
        .max(1);
    wrap_prefixed_description(
        prefix,
        NARROW_CONTINUATION_INDENT,
        description,
        first_description_width,
    )
}

fn command_name_spans(name: &str, command_style: Style, max_width: usize) -> Vec<Span<'static>> {
    let (head, _) = slice_spans_at_width(
        vec![Span::styled(format!("/{name}"), command_style)],
        max_width,
    );
    head
}

fn wrap_prefixed_description(
    first_prefix: Vec<Span<'static>>,
    continuation_indent: usize,
    description: &str,
    first_description_width: usize,
) -> Vec<Line<'static>> {
    let mut remaining = vec![Span::raw(description.to_string())];
    let mut first = true;
    let mut out = Vec::new();
    loop {
        let budget = if first {
            first_description_width.max(1)
        } else {
            first_description_width
                .saturating_add(first_prefix_width(&first_prefix))
                .saturating_sub(continuation_indent)
                .max(1)
        };
        let (mut row_description, tail) = slice_spans_at_width(remaining, budget);
        let mut row = if first {
            first_prefix.clone()
        } else {
            vec![Span::raw(" ".repeat(continuation_indent))]
        };
        row.append(&mut row_description);
        out.push(Line::from(row));
        first = false;
        match tail {
            Some(tail) => remaining = tail,
            None => break,
        }
    }
    out
}

fn first_prefix_width(prefix: &[Span<'static>]) -> usize {
    prefix
        .iter()
        .map(|span| span.content.as_ref().width())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    fn line_text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>()
    }

    fn leading_spaces(s: &str) -> usize {
        s.chars().take_while(|ch| *ch == ' ').count()
    }

    fn normalize_ws(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn bordered_inner_width(area: Rect) -> usize {
        let overlay = centered_rect(area);
        usize::from(overlay.width.saturating_sub(2))
    }

    #[test]
    fn help_overlay_fills_body_minus_margin() {
        assert_eq!(
            centered_rect(Rect::new(5, 3, 120, 40)),
            Rect::new(6, 4, 118, 38)
        );
        assert_eq!(
            centered_rect(Rect::new(0, 0, 33, 11)),
            Rect::new(1, 1, 31, 9)
        );
        assert_eq!(
            centered_rect(Rect::new(0, 0, 31, 9)),
            Rect::new(0, 0, 30, 8)
        );
    }

    #[test]
    fn help_overlay_description_wraps_within_column() {
        let description = "This description is intentionally long enough to wrap inside the description column when the overlay is wide, and every continuation row must keep the command column clear instead of falling back to the left edge.";
        let inner_width = bordered_inner_width(Rect::new(0, 0, 120, 40));
        assert_eq!(inner_width, 116);

        let lines = command_lines([("short", description)], inner_width, Style::default());
        assert!(lines.len() > 1, "description should wrap: {lines:?}");

        let desc_col = name_column_width(["short"]);
        let first = line_text(&lines[0]);
        assert_eq!(
            first.find("This"),
            Some(desc_col),
            "first description row should start at the description column: {first:?}"
        );
        for line in lines.iter().skip(1).map(line_text) {
            assert_eq!(
                leading_spaces(&line),
                desc_col,
                "continuation row should keep the name column empty: {line:?}"
            );
        }
    }

    #[test]
    fn help_overlay_name_column_fits_longest_command() {
        let command_style = Style::default()
            .fg(Color::Indexed(ACCENT_BLUE_INDEX))
            .add_modifier(Modifier::BOLD);
        let lines = command_lines(
            SLASH_COMMANDS
                .iter()
                .map(|slash| (slash.name, slash.description)),
            116,
            command_style,
        );
        let rendered: Vec<String> = lines.iter().map(line_text).collect();
        let longest = SLASH_COMMANDS
            .iter()
            .max_by_key(|slash| format!("/{}", slash.name).width())
            .expect("slash commands are non-empty");
        assert!(
            rendered
                .iter()
                .any(|line| line.starts_with(&format!("/{}", longest.name))),
            "longest command name should render unclipped: /{}",
            longest.name
        );

        let agent = SLASH_COMMANDS
            .iter()
            .find(|slash| slash.name == "agent")
            .expect("/agent command");
        let long = SLASH_COMMANDS
            .iter()
            .find(|slash| slash.name == longest.name)
            .expect("longest command");
        let agent_line = rendered
            .iter()
            .find(|line| line.starts_with("/agent"))
            .expect("/agent row");
        let long_line = rendered
            .iter()
            .find(|line| line.starts_with(&format!("/{}", long.name)))
            .expect("longest command row");

        assert_eq!(
            agent_line.find(agent.description),
            long_line.find(long.description),
            "description columns should align for short and long command names"
        );
    }

    #[test]
    fn help_overlay_caps_absurd_command_name_column() {
        let name = "absurdly-long-command-name-that-should-not-starve-descriptions";
        let description = "Description remains in a usable column.";
        let lines = command_lines([(name, description)], 64, Style::default());
        let rendered = line_text(&lines[0]);

        assert_eq!(name_column_width([name]), MAX_NAME_COLUMN);
        assert!(
            rendered.width() <= 64,
            "first row should fit the requested width: {rendered:?}"
        );
        assert_eq!(
            rendered.find("Description"),
            Some(MAX_NAME_COLUMN),
            "description should start at the capped column: {rendered:?}"
        );
    }

    #[test]
    fn help_overlay_narrow_terminal_degrades_gracefully() {
        let description = "Narrow overlays still wrap descriptions without creating a one-character sliver column.";
        let lines = command_lines([("model-comparison", description)], 30, Style::default());
        assert!(lines.len() > 1, "narrow description should wrap");

        let first = line_text(&lines[0]);
        assert!(
            first.starts_with("/model-comparison  "),
            "first row should keep the command and a small gutter: {first:?}"
        );
        for line in lines.iter().skip(1).map(line_text) {
            assert_eq!(
                leading_spaces(&line),
                NARROW_CONTINUATION_INDENT,
                "narrow continuation should use a small hanging indent, not the full name column: {line:?}"
            );
        }
    }

    #[test]
    fn help_overlay_lists_all_slash_commands() {
        let snapshot = HelpOverlay::snapshot_text(76);
        let normalized = normalize_ws(&snapshot);
        for slash in SLASH_COMMANDS {
            assert!(
                snapshot.contains(&format!("/{}", slash.name)),
                "missing /{} in help overlay:\n{snapshot}",
                slash.name
            );
            assert!(
                normalized.contains(&normalize_ws(slash.description)),
                "missing /{} description in help overlay:\n{snapshot}",
                slash.name
            );
        }
    }

    #[test]
    fn help_overlay_getting_started_names_command_entrypoints() {
        let snapshot = HelpOverlay::snapshot_text(76);

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
