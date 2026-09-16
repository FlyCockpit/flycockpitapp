//! Agent screen 4: the orthogonal optimizations.
//!
//! A compact settings list. `space` acts on the focused row (toggles a switch,
//! cycles steering, or opens self-verify); the arrow keys nudge numbers; Enter
//! moves on. Each row explains itself in the detail pane so the trade-offs are
//! legible without leaving the screen.
//!
//! Self-verify is rich enough to warrant its own screen ([`super::selfverify`]),
//! reached from the last row.

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
use ratatui::widgets::{Clear, Paragraph, Wrap};
use ratatui::{Terminal, backend::CrosstermBackend};

use super::super::chrome;
use super::ui::{self, BRASS, FOG, GOOD, INK};
use super::{AgentDraft, AvailableModel, Nav};

const RECURSION_MAX: u8 = 6;
const SKEPTICS_MAX: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Row {
    AutoPrune,
    Interactive,
    Recursion,
    Steering,
    Skeptics,
    SelfVerify,
}

const ROWS: [Row; 6] = [
    Row::AutoPrune,
    Row::Interactive,
    Row::Recursion,
    Row::Steering,
    Row::Skeptics,
    Row::SelfVerify,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    Stay,
    Next,
    Back,
    Quit,
    OpenSelfVerify,
}

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

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    draft: &mut AgentDraft,
    catalog: &[AvailableModel],
) -> Result<Nav> {
    let mut screen = Screen::new();
    loop {
        terminal.draw(|frame| screen.render(frame, frame.area(), draft))?;
        let act = match event::read()? {
            Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                screen.handle_key(key, draft)
            }
            Event::Mouse(mouse) => screen.handle_mouse(mouse, draft),
            _ => Act::Stay,
        };
        match act {
            Act::Stay => {}
            Act::Next => return Ok(Nav::Next),
            Act::Back => return Ok(Nav::Back),
            Act::Quit => return Ok(Nav::Quit),
            Act::OpenSelfVerify => {
                let nav = super::selfverify::run(terminal, catalog, &mut draft.self_verify)?;
                // The nested screen dropped mouse capture on exit; take it back.
                execute!(terminal.backend_mut(), EnableMouseCapture)?;
                if nav == Nav::Quit {
                    return Ok(Nav::Quit);
                }
            }
        }
    }
}

struct Screen {
    cursor: usize,
    hover: Option<usize>,
    rows: Vec<Rect>,
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
}

impl Screen {
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

    /// `\u{2190}`/`\u{2192}` nudge the numeric rows by `delta`. Switches, steering,
    /// and self-verify are `space`-only (see [`Self::activate`]); nudging them
    /// with an arrow would let `\u{2190}` and `\u{2192}` both flip the same toggle,
    /// so those rows ignore the arrows entirely.
    fn adjust(&self, draft: &mut AgentDraft, delta: i8) {
        match ROWS[self.cursor] {
            Row::AutoPrune | Row::Interactive | Row::Steering | Row::SelfVerify => {}
            Row::Recursion => {
                draft.max_recursion = (draft.max_recursion as i16 + delta as i16)
                    .clamp(0, RECURSION_MAX as i16) as u8;
            }
            Row::Skeptics => {
                draft.goal_skeptics =
                    (draft.goal_skeptics as i16 + delta as i16).clamp(0, SKEPTICS_MAX as i16) as u8;
            }
        }
    }

    /// `space` on the focused row: toggle a switch, cycle steering, bump a
    /// number, or open self-verify.
    fn activate(&self, draft: &mut AgentDraft) -> Act {
        match ROWS[self.cursor] {
            Row::AutoPrune => {
                draft.autoprune = !draft.autoprune;
                Act::Stay
            }
            Row::Interactive => {
                draft.interactive_subagents = !draft.interactive_subagents;
                Act::Stay
            }
            Row::Steering => {
                draft.steering = draft.steering.toggled();
                Act::Stay
            }
            Row::Recursion => {
                draft.max_recursion = if draft.max_recursion >= RECURSION_MAX {
                    0
                } else {
                    draft.max_recursion + 1
                };
                Act::Stay
            }
            Row::Skeptics => {
                draft.goal_skeptics = if draft.goal_skeptics >= SKEPTICS_MAX {
                    0
                } else {
                    draft.goal_skeptics + 1
                };
                Act::Stay
            }
            Row::SelfVerify => Act::OpenSelfVerify,
        }
    }

    fn handle_key(&mut self, key: KeyEvent, draft: &mut AgentDraft) -> Act {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return Act::Quit;
        }
        match key.code {
            KeyCode::Esc => Act::Back,
            KeyCode::Enter => Act::Next,
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.cursor = (self.cursor + ROWS.len() - 1) % ROWS.len();
                Act::Stay
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.cursor = (self.cursor + 1) % ROWS.len();
                Act::Stay
            }
            KeyCode::Left | KeyCode::Char('-') | KeyCode::Char('h') => {
                self.adjust(draft, -1);
                Act::Stay
            }
            KeyCode::Right | KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Char('l') => {
                self.adjust(draft, 1);
                Act::Stay
            }
            KeyCode::Char(' ') => self.activate(draft),
            _ => Act::Stay,
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent, draft: &mut AgentDraft) -> Act {
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
                if self.actions.clicked(pos).is_some() {
                    return Act::Next;
                }
                if let Some(index) = self.rows.iter().position(|r| r.contains(pos)) {
                    self.cursor = index;
                    return self.activate(draft);
                }
                Act::Stay
            }
            _ => Act::Stay,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, draft: &AgentDraft) {
        frame.render_widget(Clear, area);
        self.back_rect = chrome::render_back_button(frame, area, true, self.back_hover);
        let col = ui::column(area);
        let [header, _, list, _, detail, help] = col.layout(&Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(ROWS.len() as u16),
            Constraint::Length(1),
            Constraint::Min(2),
            Constraint::Length(1),
        ]));
        ui::render_header(
            frame,
            header,
            "Tune the agent",
            "These are all independent \u{2014} the defaults are a sane starting point.",
        );
        self.render_rows(frame, list, draft);
        self.render_detail(frame, detail, draft);
        ui::render_help(
            frame,
            help,
            "\u{2191}\u{2193} move   space toggle/open   \u{2190}\u{2192} adjust   enter continue   esc back",
        );
        self.actions
            .render(frame, help, &[chrome::Button::primary("Continue")]);
    }

    fn render_rows(&mut self, frame: &mut Frame, area: Rect, draft: &AgentDraft) {
        self.rows.clear();
        let rects = Layout::vertical([Constraint::Length(1); 6]).split(area);
        for (index, (&row, &rect)) in ROWS.iter().zip(rects.iter()).enumerate() {
            self.rows.push(rect);
            let focused = self.cursor == index;
            let line = row_line(row, draft, focused);
            frame.render_widget(Paragraph::new(line), rect);
        }
    }

    fn render_detail(&self, frame: &mut Frame, area: Rect, draft: &AgentDraft) {
        let text = match ROWS[self.cursor] {
            Row::AutoPrune => {
                "Auto-prune losslessly drops duplicated context (old file reads, repeated tool output) before it forces a summary. Off by default for frontier models, whose caches it can disturb."
                    .to_string()
            }
            Row::Interactive => {
                "An interactive subagent temporarily becomes the main chat: it takes the foreground, then hands control back. It does not count against the recursion depth below."
                    .to_string()
            }
            Row::Recursion => format!(
                "How many levels of (non-interactive) subagents may spawn subagents of their own. {} means only the agent delegates.",
                if draft.max_recursion == 0 { "0" } else { "Higher" }
            ),
            Row::Steering => {
                "Terse tool and MCP descriptions save tokens and keep the cache stable; verbose spells every tool out, which can help a smaller model."
                    .to_string()
            }
            Row::Skeptics => {
                "Before a goal is allowed to complete, this many refute-framed skeptics independently try to poke holes in it. 0 turns the gate off."
                    .to_string()
            }
            Row::SelfVerify => {
                "Re-check risky actions before they land. Press space to configure it per surface (writes/edits, commands, Monty)."
                    .to_string()
            }
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(text, Style::new().fg(FOG))))
                .wrap(Wrap { trim: true }),
            area,
        );
    }
}

fn row_line(row: Row, draft: &AgentDraft, focused: bool) -> Line<'static> {
    let (label, value) = match row {
        Row::AutoPrune => ("Auto-prune", switch(draft.autoprune)),
        Row::Interactive => ("Interactive subagents", switch(draft.interactive_subagents)),
        Row::Recursion => (
            "Max subagent recursion",
            stepper(draft.max_recursion, focused),
        ),
        Row::Steering => ("Tool steering", cycle(draft.steering.label(), focused)),
        Row::Skeptics => (
            "Goal-completion skeptics",
            if draft.goal_skeptics == 0 {
                cycle("off", focused)
            } else {
                stepper(draft.goal_skeptics, focused)
            },
        ),
        Row::SelfVerify => (
            "Self-verify",
            format!("{}  \u{203a}", self_verify_summary(draft)),
        ),
    };
    let marker = if focused { "\u{25b8} " } else { "  " };
    let label_style = if focused {
        Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(INK)
    };
    let value_style = match row {
        Row::AutoPrune if draft.autoprune => Style::new().fg(GOOD),
        Row::Interactive if draft.interactive_subagents => Style::new().fg(GOOD),
        _ => Style::new().fg(FOG),
    };
    // Pad the label column so the values line up.
    let pad = 26usize.saturating_sub(label.chars().count()).max(1);
    Line::from(vec![
        Span::styled(marker, Style::new().fg(BRASS)),
        Span::styled(label, label_style),
        Span::raw(" ".repeat(pad)),
        Span::styled(value, value_style),
    ])
}

fn switch(on: bool) -> String {
    if on {
        "[ on ]".to_string()
    } else {
        "[ off ]".to_string()
    }
}

fn stepper(value: u8, focused: bool) -> String {
    if focused {
        format!("\u{25c2} {value} \u{25b8}")
    } else {
        format!("  {value}")
    }
}

fn cycle(value: &str, focused: bool) -> String {
    if focused {
        format!("\u{25c2} {value} \u{25b8}")
    } else {
        format!("  {value}")
    }
}

fn self_verify_summary(draft: &AgentDraft) -> String {
    let on = draft.self_verify.iter().filter(|s| !s.is_off()).count();
    match on {
        0 => "off on all surfaces".to_string(),
        3 => "on for all surfaces".to_string(),
        n => format!("on for {n} of 3 surfaces"),
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
    fn space_toggles_switches_and_arrows_step_numbers() {
        let catalog = sample_catalog();
        let mut draft = AgentDraft::new(&catalog);
        let mut screen = Screen::new();
        // Row 0 is auto-prune (off) — space turns it on.
        assert!(!draft.autoprune);
        screen.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert!(draft.autoprune);
        // Move to recursion and step it.
        screen.cursor = 2;
        let before = draft.max_recursion;
        screen.handle_key(key(KeyCode::Right), &mut draft);
        assert_eq!(draft.max_recursion, before + 1);
        screen.handle_key(key(KeyCode::Left), &mut draft);
        assert_eq!(draft.max_recursion, before);
    }

    #[test]
    fn arrows_do_not_flip_switches() {
        let catalog = sample_catalog();
        let mut draft = AgentDraft::new(&catalog);
        let mut screen = Screen::new();
        // Row 0 is auto-prune. Arrows are for numeric rows only, so neither
        // direction may toggle a switch (or \u{2190} would undo nothing that \u{2192} did).
        screen.cursor = 0;
        let before = draft.autoprune;
        screen.handle_key(key(KeyCode::Right), &mut draft);
        assert_eq!(draft.autoprune, before);
        screen.handle_key(key(KeyCode::Left), &mut draft);
        assert_eq!(draft.autoprune, before);
        // Steering is likewise space-only.
        screen.cursor = ROWS.iter().position(|r| *r == Row::Steering).unwrap();
        let steering = draft.steering;
        screen.handle_key(key(KeyCode::Right), &mut draft);
        screen.handle_key(key(KeyCode::Left), &mut draft);
        assert_eq!(draft.steering, steering);
    }

    #[test]
    fn recursion_clamps_and_wraps_on_space() {
        let catalog = sample_catalog();
        let mut draft = AgentDraft::new(&catalog);
        let mut screen = Screen::new();
        screen.cursor = 2;
        draft.max_recursion = RECURSION_MAX;
        // Arrow up clamps at max.
        screen.handle_key(key(KeyCode::Right), &mut draft);
        assert_eq!(draft.max_recursion, RECURSION_MAX);
        // Space wraps back to 0.
        screen.handle_key(key(KeyCode::Char(' ')), &mut draft);
        assert_eq!(draft.max_recursion, 0);
    }

    #[test]
    fn self_verify_row_requests_the_nested_screen() {
        let catalog = sample_catalog();
        let mut draft = AgentDraft::new(&catalog);
        let mut screen = Screen::new();
        screen.cursor = ROWS.iter().position(|r| *r == Row::SelfVerify).unwrap();
        assert_eq!(
            screen.handle_key(key(KeyCode::Char(' ')), &mut draft),
            Act::OpenSelfVerify
        );
    }

    #[test]
    fn summary_counts_active_surfaces() {
        let catalog = sample_catalog();
        let mut draft = AgentDraft::new(&catalog);
        // Default: writes on, others off => 1 of 3.
        assert_eq!(self_verify_summary(&draft), "on for 1 of 3 surfaces");
        for surface in &mut draft.self_verify {
            surface.same_copies = 0;
            surface.copies.iter_mut().for_each(|c| *c = 0);
        }
        assert_eq!(self_verify_summary(&draft), "off on all surfaces");
    }
}
