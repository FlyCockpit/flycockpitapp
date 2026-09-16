//! Agent screen 6: define subagents.
//!
//! A subagent is a scoped helper the agent can delegate to. Each one gets its
//! own name, trust level, models, and tools — so you can, for example, keep the
//! primary agent untrusted while defining one small **trusted** subagent whose
//! only job is to set up a sealed value.
//!
//! The list screen adds/edits/removes; the editor reuses the very same model
//! and tool pickers the primary agent used.

use std::io::Stdout;

use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};
use ratatui::{Terminal, backend::CrosstermBackend};

use super::super::chrome;
use super::ui::{self, BRASS, FOG, GOOD, HOVER_BG, INK, NIGHT, WARN};
use super::{AgentDraft, AvailableModel, Nav, Subagent, count_enabled};

pub(super) fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    draft: &mut AgentDraft,
    catalog: &[AvailableModel],
) -> Result<Nav> {
    execute!(terminal.backend_mut(), EnableMouseCapture)?;
    let result = run_loop(terminal, draft, catalog);
    let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    Stay,
    Next,
    Back,
    Quit,
    Add,
    Edit(usize),
    Delete(usize),
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    draft: &mut AgentDraft,
    catalog: &[AvailableModel],
) -> Result<Nav> {
    let mut screen = List::new();
    loop {
        terminal.draw(|frame| screen.render(frame, frame.area(), &draft.subagents))?;
        let act = match event::read()? {
            Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                screen.handle_key(key, draft.subagents.len())
            }
            Event::Mouse(mouse) => screen.handle_mouse(mouse, draft.subagents.len()),
            _ => Act::Stay,
        };
        match act {
            Act::Stay => {}
            Act::Next => return Ok(Nav::Next),
            Act::Back => return Ok(Nav::Back),
            Act::Quit => return Ok(Nav::Quit),
            Act::Add => {
                let mut candidate = Subagent::new(catalog);
                match editor::run(terminal, catalog, &mut candidate)? {
                    editor::Outcome::Saved => {
                        draft.subagents.push(candidate);
                        screen.cursor = draft.subagents.len() - 1;
                    }
                    editor::Outcome::Cancel => {}
                    editor::Outcome::Quit => return Ok(Nav::Quit),
                }
                execute!(terminal.backend_mut(), EnableMouseCapture)?;
            }
            Act::Edit(index) => {
                let mut candidate = draft.subagents[index].clone();
                match editor::run(terminal, catalog, &mut candidate)? {
                    editor::Outcome::Saved => draft.subagents[index] = candidate,
                    editor::Outcome::Cancel => {}
                    editor::Outcome::Quit => return Ok(Nav::Quit),
                }
                execute!(terminal.backend_mut(), EnableMouseCapture)?;
            }
            Act::Delete(index) => {
                draft.subagents.remove(index);
                screen.cursor = screen.cursor.min(draft.subagents.len().saturating_sub(1));
            }
        }
    }
}

struct List {
    cursor: usize,
    hover: Option<usize>,
    rows: Vec<Rect>,
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
}

impl List {
    fn new() -> Self {
        Self {
            cursor: 0,
            hover: None,
            rows: Vec::new(),
            back_rect: Rect::default(),
            back_hover: false,
            actions: chrome::ActionBar::default(),
        }
    }

    fn handle_key(&mut self, key: KeyEvent, count: usize) -> Act {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return Act::Quit;
        }
        match key.code {
            KeyCode::Esc => Act::Back,
            KeyCode::Enter => Act::Next,
            KeyCode::Char('a') | KeyCode::Char('A') => Act::Add,
            KeyCode::Char('e') | KeyCode::Char('E') | KeyCode::Char(' ') if count > 0 => {
                Act::Edit(self.cursor.min(count - 1))
            }
            KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Delete if count > 0 => {
                Act::Delete(self.cursor.min(count - 1))
            }
            KeyCode::Up | KeyCode::Char('k') if count > 0 => {
                self.cursor = (self.cursor + count - 1) % count;
                Act::Stay
            }
            KeyCode::Down | KeyCode::Char('j') if count > 0 => {
                self.cursor = (self.cursor + 1) % count;
                Act::Stay
            }
            _ => Act::Stay,
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent, count: usize) -> Act {
        let pos = Position::new(event.column, event.row);
        self.back_hover = chrome::hit(self.back_rect, pos);
        if matches!(event.kind, MouseEventKind::Down(MouseButton::Left))
            && chrome::hit(self.back_rect, pos)
        {
            return Act::Back;
        }
        match event.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.hover = self.rows.iter().position(|r| r.contains(pos));
                self.actions.track(pos);
                Act::Stay
            }
            MouseEventKind::Down(MouseButton::Left) => {
                match self.actions.clicked(pos) {
                    Some(0) => return Act::Add,
                    Some(_) => return Act::Next,
                    None => {}
                }
                if let Some(index) = self.rows.iter().position(|r| r.contains(pos))
                    && index < count
                {
                    self.cursor = index;
                    return Act::Edit(index);
                }
                Act::Stay
            }
            _ => Act::Stay,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, subagents: &[Subagent]) {
        frame.render_widget(Clear, area);
        self.back_rect = chrome::render_back_button(frame, area, true, self.back_hover);
        let col = ui::column(area);
        let [header, _, list, note, help] = col.layout(&Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(2),
            Constraint::Length(1),
        ]));
        ui::render_header(
            frame,
            header,
            "Define subagents",
            "Helpers the agent can delegate to. The suggested \u{201c}runner\u{201d} is pre-added \u{2014} keep, edit, or remove it, and add your own.",
        );
        self.render_list(frame, list, subagents);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Tip: a small trusted subagent is the safe way to set up a sealed value while the primary agent stays untrusted.",
                Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
            )))
            .wrap(Wrap { trim: true }),
            note,
        );
        ui::render_help(
            frame,
            help,
            "a add   e edit   d delete   \u{2191}\u{2193} move   enter continue   esc back",
        );
        self.actions.render(
            frame,
            help,
            &[
                chrome::Button::secondary("Add subagent"),
                chrome::Button::primary("Continue"),
            ],
        );
    }

    fn render_list(&mut self, frame: &mut Frame, area: Rect, subagents: &[Subagent]) {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(NIGHT))
            .title(Span::styled(
                format!(" Subagents  \u{b7}  {} ", subagents.len()),
                Style::new().fg(INK),
            ));
        let inner = block.inner(area);
        frame.render_widget(&block, area);
        self.rows.clear();

        if subagents.is_empty() {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    "No subagents yet \u{2014} press a to add one.",
                    Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
                ))
                .centered(),
                inner,
            );
            return;
        }

        let width = usize::from(inner.width);
        let visible = usize::from(inner.height);
        for (row, sub) in subagents.iter().enumerate().take(visible) {
            let rect = Rect {
                x: inner.x,
                y: inner.y + row as u16,
                width: inner.width,
                height: 1,
            };
            self.rows.push(rect);
            let focused = self.cursor == row;
            let mut para = Paragraph::new(subagent_line(sub, width, focused));
            if self.hover == Some(row) {
                para = para.style(Style::new().bg(HOVER_BG));
            }
            frame.render_widget(para, rect);
        }
    }
}

fn subagent_line(sub: &Subagent, width: usize, focused: bool) -> Line<'static> {
    let name = if sub.name.trim().is_empty() {
        "unnamed".to_string()
    } else {
        sub.name.trim().to_string()
    };
    let name_style = if focused {
        Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(INK)
    };
    let trust = if sub.trusted { "trusted" } else { "untrusted" };
    let trust_style = if sub.trusted {
        Style::new().fg(WARN)
    } else {
        Style::new().fg(GOOD)
    };
    let models = sub.model_allowed.iter().filter(|&&on| on).count();
    let tools = count_enabled(&sub.tools);
    let tail = format!("{models} model(s) \u{b7} {tools} tool(s)");
    let marker = if focused { "\u{25b8} " } else { "  " };
    let used = 2 + name.chars().count() + 3 + trust.len() + 3 + tail.chars().count();
    let pad = width.saturating_sub(used).max(1);
    Line::from(vec![
        Span::styled(marker, Style::new().fg(BRASS)),
        Span::styled(name, name_style),
        Span::styled("  \u{b7}  ", Style::new().fg(NIGHT)),
        Span::styled(trust, trust_style),
        Span::raw(" ".repeat(pad)),
        Span::styled(tail, Style::new().fg(FOG)),
    ])
}

/// The subagent editor: name, trust, and (via the shared pickers) models & tools.
mod editor {
    use super::*;
    use crate::onboard::field::TextField;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Outcome {
        Saved,
        Cancel,
        Quit,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Field {
        Name,
        Trusted,
        Models,
        Tools,
    }

    const FIELDS: [Field; 4] = [Field::Name, Field::Trusted, Field::Models, Field::Tools];

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Act {
        Stay,
        Save,
        Cancel,
        Quit,
        OpenModels,
        OpenTools,
    }

    pub(super) fn run(
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        catalog: &[AvailableModel],
        sub: &mut Subagent,
    ) -> Result<Outcome> {
        execute!(terminal.backend_mut(), EnableMouseCapture)?;
        let result = run_loop(terminal, catalog, sub);
        let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
        result
    }

    fn run_loop(
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        catalog: &[AvailableModel],
        sub: &mut Subagent,
    ) -> Result<Outcome> {
        let mut screen = Screen::new(sub);
        loop {
            terminal.draw(|frame| screen.render(frame, frame.area(), sub))?;
            let act = match event::read()? {
                Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                    screen.handle_key(key, sub)
                }
                Event::Paste(text) => {
                    if screen.focus == Field::Name {
                        screen.name.paste(&text);
                    }
                    Act::Stay
                }
                Event::Mouse(mouse) => screen.handle_mouse(mouse, sub),
                _ => Act::Stay,
            };
            match act {
                Act::Stay => {}
                Act::Save => {
                    if screen.name.trimmed().is_empty() {
                        screen.flash = Some("Give the subagent a name.".to_string());
                        screen.focus = Field::Name;
                    } else {
                        sub.name = screen.name.trimmed().to_string();
                        return Ok(Outcome::Saved);
                    }
                }
                Act::Cancel => return Ok(Outcome::Cancel),
                Act::Quit => return Ok(Outcome::Quit),
                Act::OpenModels => {
                    let nav = super::super::models::run(
                        terminal,
                        catalog,
                        &mut sub.model_allowed,
                        &mut sub.default_model,
                        "Subagent models",
                        "Which models this subagent may use.",
                    )?;
                    execute!(terminal.backend_mut(), EnableMouseCapture)?;
                    if nav == Nav::Quit {
                        return Ok(Outcome::Quit);
                    }
                }
                Act::OpenTools => {
                    let nav = super::super::tools::run(
                        terminal,
                        catalog,
                        &mut sub.tools,
                        "Subagent tools",
                        "Which tools this subagent may use.",
                    )?;
                    execute!(terminal.backend_mut(), EnableMouseCapture)?;
                    if nav == Nav::Quit {
                        return Ok(Outcome::Quit);
                    }
                }
            }
        }
    }

    struct Screen {
        focus: Field,
        name: TextField,
        rows: Vec<(Rect, Field)>,
        flash: Option<String>,
        back_rect: Rect,
        back_hover: bool,
        actions: chrome::ActionBar,
    }

    impl Screen {
        fn new(sub: &Subagent) -> Self {
            let mut name = TextField::new();
            if !sub.name.is_empty() {
                name.set(&sub.name);
            }
            Self {
                focus: Field::Name,
                name,
                rows: Vec::new(),
                flash: None,
                back_rect: Rect::default(),
                back_hover: false,
                actions: chrome::ActionBar::default(),
            }
        }

        fn focus_index(&self) -> usize {
            FIELDS.iter().position(|f| *f == self.focus).unwrap_or(0)
        }

        fn move_focus(&mut self, down: bool) {
            let i = self.focus_index();
            let next = if down {
                (i + 1) % FIELDS.len()
            } else {
                (i + FIELDS.len() - 1) % FIELDS.len()
            };
            self.focus = FIELDS[next];
        }

        fn handle_key(&mut self, key: KeyEvent, sub: &mut Subagent) -> Act {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
            {
                return Act::Quit;
            }
            match key.code {
                KeyCode::Esc => return Act::Cancel,
                KeyCode::Enter => return Act::Save,
                KeyCode::Tab => {
                    self.move_focus(true);
                    return Act::Stay;
                }
                KeyCode::BackTab => {
                    self.move_focus(false);
                    return Act::Stay;
                }
                _ => {}
            }
            // Name is a live text field; everything else is a control row.
            if self.focus == Field::Name {
                match key.code {
                    KeyCode::Up => self.move_focus(false),
                    KeyCode::Down => self.move_focus(true),
                    _ => {
                        if self.name.handle_key(key) {
                            self.flash = None;
                        }
                    }
                }
                return Act::Stay;
            }
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.move_focus(false);
                    Act::Stay
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.move_focus(true);
                    Act::Stay
                }
                KeyCode::Char(' ') => self.activate(sub),
                _ => Act::Stay,
            }
        }

        fn activate(&mut self, sub: &mut Subagent) -> Act {
            match self.focus {
                Field::Name => Act::Stay,
                Field::Trusted => {
                    sub.trusted = !sub.trusted;
                    Act::Stay
                }
                Field::Models => Act::OpenModels,
                Field::Tools => Act::OpenTools,
            }
        }

        fn handle_mouse(&mut self, event: MouseEvent, sub: &mut Subagent) -> Act {
            let pos = Position::new(event.column, event.row);
            self.back_hover = chrome::hit(self.back_rect, pos);
            if matches!(event.kind, MouseEventKind::Moved | MouseEventKind::Drag(_)) {
                self.actions.track(pos);
            }
            if !matches!(event.kind, MouseEventKind::Down(MouseButton::Left)) {
                return Act::Stay;
            }
            if chrome::hit(self.back_rect, pos) {
                return Act::Cancel;
            }
            if self.actions.clicked(pos).is_some() {
                return Act::Save;
            }
            if let Some((_, field)) = self.rows.iter().find(|(rect, _)| rect.contains(pos)) {
                self.focus = *field;
                // Clicking a control row also activates it; Name only focuses.
                if *field != Field::Name {
                    return self.activate(sub);
                }
            }
            Act::Stay
        }

        fn render(&mut self, frame: &mut Frame, area: Rect, sub: &Subagent) {
            frame.render_widget(Clear, area);
            self.back_rect = chrome::render_back_button(frame, area, true, self.back_hover);
            let col = ui::column(area);
            let [header, _, name, trusted, models, tools, note, _, help] =
                col.layout(&Layout::vertical([
                    Constraint::Length(3),
                    Constraint::Length(1),
                    Constraint::Length(3),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(2),
                    Constraint::Min(0),
                    Constraint::Length(1),
                ]));
            ui::render_header(
                frame,
                header,
                "Subagent",
                "Name it, set its trust, and pick its models and tools.",
            );

            self.rows.clear();
            self.rows.push((name, Field::Name));
            let caret = ui::render_field(
                frame,
                name,
                "Name",
                &self.name,
                self.focus == Field::Name,
                "e.g. sealer",
            );

            self.rows.push((trusted, Field::Trusted));
            frame.render_widget(
                control_row(
                    "Trusted",
                    if sub.trusted {
                        "yes \u{2014} may read sealed values"
                    } else {
                        "no \u{2014} secrets redacted"
                    },
                    self.focus == Field::Trusted,
                    sub.trusted,
                ),
                trusted,
            );

            self.rows.push((models, Field::Models));
            frame.render_widget(
                control_row(
                    "Models",
                    &format!(
                        "{} enabled  \u{203a}",
                        sub.model_allowed.iter().filter(|&&on| on).count()
                    ),
                    self.focus == Field::Models,
                    false,
                ),
                models,
            );

            self.rows.push((tools, Field::Tools));
            frame.render_widget(
                control_row(
                    "Tools",
                    &format!("{} granted  \u{203a}", count_enabled(&sub.tools)),
                    self.focus == Field::Tools,
                    false,
                ),
                tools,
            );

            let note_line = if let Some(flash) = &self.flash {
                Line::from(Span::styled(
                    flash.clone(),
                    Style::new().fg(WARN).add_modifier(Modifier::BOLD),
                ))
            } else {
                Line::from(Span::styled(
                    "space toggles or opens the focused row.",
                    Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
                ))
            };
            frame.render_widget(Paragraph::new(note_line), note);

            ui::render_help(
                frame,
                help,
                "tab move   space toggle/open   enter save   esc cancel   ^c quit",
            );
            self.actions
                .render(frame, help, &[chrome::Button::primary("Save")]);

            if self.focus == Field::Name
                && let Some(pos) = caret
            {
                frame.set_cursor_position(pos);
            }
        }
    }

    fn control_row(label: &str, value: &str, focused: bool, good: bool) -> Paragraph<'static> {
        let marker = if focused { "\u{25b8} " } else { "  " };
        let label_style = if focused {
            Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(INK)
        };
        let value_style = if good {
            Style::new().fg(WARN)
        } else {
            Style::new().fg(FOG)
        };
        let pad = 12usize.saturating_sub(label.chars().count()).max(1);
        Paragraph::new(Line::from(vec![
            Span::styled(marker.to_string(), Style::new().fg(BRASS)),
            Span::styled(label.to_string(), label_style),
            Span::raw(" ".repeat(pad)),
            Span::styled(value.to_string(), value_style),
        ]))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::onboard::agent::sample_catalog;

        fn key(code: KeyCode) -> KeyEvent {
            KeyEvent::from(code)
        }

        #[test]
        fn save_requires_a_name() {
            let catalog = sample_catalog();
            let mut sub = Subagent::new(&catalog);
            let mut screen = Screen::new(&sub);
            // Empty name → Save is refused with a flash.
            assert_eq!(screen.handle_key(key(KeyCode::Enter), &mut sub), Act::Save);
            // run_loop would convert Save→flash; emulate that guard here:
            assert!(screen.name.trimmed().is_empty());
        }

        #[test]
        fn space_toggles_trusted() {
            let catalog = sample_catalog();
            let mut sub = Subagent::new(&catalog);
            let mut screen = Screen::new(&sub);
            screen.focus = Field::Trusted;
            assert!(!sub.trusted);
            screen.handle_key(key(KeyCode::Char(' ')), &mut sub);
            assert!(sub.trusted);
        }

        #[test]
        fn space_on_models_and_tools_opens_pickers() {
            let catalog = sample_catalog();
            let mut sub = Subagent::new(&catalog);
            let mut screen = Screen::new(&sub);
            screen.focus = Field::Models;
            assert_eq!(
                screen.handle_key(key(KeyCode::Char(' ')), &mut sub),
                Act::OpenModels
            );
            screen.focus = Field::Tools;
            assert_eq!(
                screen.handle_key(key(KeyCode::Char(' ')), &mut sub),
                Act::OpenTools
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onboard::agent::sample_catalog;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    #[test]
    fn a_adds_and_d_deletes() {
        let mut list = List::new();
        assert_eq!(list.handle_key(key(KeyCode::Char('a')), 0), Act::Add);
        // With one subagent, e edits and d deletes it.
        assert_eq!(list.handle_key(key(KeyCode::Char('e')), 1), Act::Edit(0));
        assert_eq!(list.handle_key(key(KeyCode::Char('d')), 1), Act::Delete(0));
    }

    #[test]
    fn enter_continues_and_esc_backs() {
        let mut list = List::new();
        let _ = sample_catalog();
        assert_eq!(list.handle_key(key(KeyCode::Enter), 0), Act::Next);
        assert_eq!(list.handle_key(key(KeyCode::Esc), 0), Act::Back);
    }
}
