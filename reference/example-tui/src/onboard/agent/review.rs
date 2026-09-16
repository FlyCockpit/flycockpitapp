//! Agent screen 7: read the whole draft back and create it.
//!
//! Everything here is derived from the draft, so this screen is read-only apart
//! from scrolling. Enter creates the agent (ending the wizard); Esc steps back
//! to keep editing.

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
use ratatui::widgets::{Block, BorderType, Clear, Paragraph};
use ratatui::{Terminal, backend::CrosstermBackend};

use super::super::chrome;
use super::ui::{self, BRASS, FOG, GOOD, INK, NIGHT, WARN};
use super::{AgentDraft, AvailableModel, Nav};

pub(super) fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    draft: &AgentDraft,
    catalog: &[AvailableModel],
) -> Result<Nav> {
    execute!(terminal.backend_mut(), EnableMouseCapture)?;
    let result = run_loop(terminal, draft, catalog);
    let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    draft: &AgentDraft,
    catalog: &[AvailableModel],
) -> Result<Nav> {
    let lines = detail_lines(draft, catalog);
    let mut screen = Screen::new(lines);
    loop {
        terminal.draw(|frame| screen.render(frame, frame.area()))?;
        match event::read()? {
            Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                if let Some(nav) = screen.handle_key(key) {
                    return Ok(nav);
                }
            }
            Event::Mouse(mouse) => {
                if let Some(nav) = screen.handle_mouse(mouse) {
                    return Ok(nav);
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

struct Screen {
    lines: Vec<Line<'static>>,
    nav: ui::ListNav,
    list_area: Rect,
    scrollbar_area: Option<Rect>,
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
}

impl Screen {
    fn new(lines: Vec<Line<'static>>) -> Self {
        Self {
            lines,
            nav: ui::ListNav::new(),
            list_area: Rect::default(),
            scrollbar_area: None,
            back_rect: Rect::default(),
            back_hover: false,
            actions: chrome::ActionBar::default(),
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Option<Nav> {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return Some(Nav::Quit);
        }
        let n = self.lines.len();
        match key.code {
            KeyCode::Esc => Some(Nav::Back),
            KeyCode::Enter => Some(Nav::Next),
            KeyCode::Up | KeyCode::Char('k') => {
                self.nav.scroll_by(-1, n);
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.nav.scroll_by(1, n);
                None
            }
            KeyCode::PageUp => {
                self.nav.scroll_by(-(self.nav.view_h as isize), n);
                None
            }
            KeyCode::PageDown => {
                self.nav.scroll_by(self.nav.view_h as isize, n);
                None
            }
            _ => None,
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent) -> Option<Nav> {
        let pos = Position::new(event.column, event.row);
        self.back_hover = chrome::hit(self.back_rect, pos);
        if matches!(event.kind, MouseEventKind::Down(MouseButton::Left))
            && chrome::hit(self.back_rect, pos)
        {
            return Some(Nav::Back);
        }
        let n = self.lines.len();
        let over =
            self.list_area.contains(pos) || self.scrollbar_area.is_some_and(|a| a.contains(pos));
        match event.kind {
            MouseEventKind::ScrollDown if over => {
                self.nav.scroll_by(1, n);
                None
            }
            MouseEventKind::ScrollUp if over => {
                self.nav.scroll_by(-1, n);
                None
            }
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.actions.track(pos);
                None
            }
            MouseEventKind::Down(MouseButton::Left) => self.actions.clicked(pos).map(|_| Nav::Next),
            _ => None,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Clear, area);
        self.back_rect = chrome::render_back_button(frame, area, true, self.back_hover);
        let col = ui::column(area);
        let [header, _, body, help] = col.layout(&Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ]));
        ui::render_header(
            frame,
            header,
            "Ready to create",
            "Here's the whole agent. Enter creates it; step back to change anything.",
        );

        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(GOOD))
            .title(Span::styled(" Summary ", Style::new().fg(GOOD)));
        let inner = block.inner(body);
        frame.render_widget(&block, body);
        self.nav.set_view_h(usize::from(inner.height));
        let total = self.lines.len();

        let overflow = total > usize::from(inner.height);
        let (rows_area, bar_area) = if overflow && inner.width >= 2 {
            let [rows, bar] = inner.layout(&Layout::horizontal([
                Constraint::Min(0),
                Constraint::Length(1),
            ]));
            (rows, Some(bar))
        } else {
            (inner, None)
        };
        self.list_area = rows_area;
        self.scrollbar_area = bar_area;
        let offset = self.nav.offset.min(total.saturating_sub(1));
        let shown: Vec<Line> = self
            .lines
            .iter()
            .skip(offset)
            .take(usize::from(rows_area.height))
            .cloned()
            .collect();
        frame.render_widget(Paragraph::new(shown), rows_area);
        if let Some(bar_area) = bar_area {
            ui::render_scrollbar(
                frame,
                bar_area,
                total,
                usize::from(rows_area.height),
                offset,
            );
        }

        ui::render_help(
            frame,
            help,
            "\u{2191}\u{2193} scroll   enter create   esc back   ^c quit",
        );
        self.actions
            .render(frame, help, &[chrome::Button::primary("Create agent")]);
    }
}

fn kv(key: &str, value: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key}: "), Style::new().fg(FOG)),
        Span::styled(value, Style::new().fg(INK)),
    ])
}

fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        title.to_string(),
        Style::new().fg(BRASS).add_modifier(Modifier::BOLD),
    ))
}

fn detail_lines(draft: &AgentDraft, catalog: &[AvailableModel]) -> Vec<Line<'static>> {
    let name = if draft.name.trim().is_empty() {
        "pilot".to_string()
    } else {
        draft.name.trim().to_string()
    };
    let default_label = draft
        .default_model
        .and_then(|i| catalog.get(i))
        .map(|m| m.label().to_string())
        .unwrap_or_else(|| "none".to_string());

    let mut lines = vec![
        kv("Name", name),
        kv(
            "Trust",
            if draft.trusted {
                "trusted (sees raw secrets & sealed values)".to_string()
            } else {
                "untrusted (secrets & sealed values redacted)".to_string()
            },
        ),
        Line::raw(""),
        section("Models"),
        kv(
            "Enabled",
            format!(
                "{} of {}",
                draft.model_allowed.iter().filter(|&&on| on).count(),
                catalog.len()
            ),
        ),
        kv("Default", default_label),
        Line::raw(""),
        section("Optimizations"),
        kv("Auto-prune", on_off(draft.autoprune)),
        kv("Interactive subagents", on_off(draft.interactive_subagents)),
        kv(
            "Max subagent recursion",
            format!(
                "{} (interactive subagents don't count)",
                draft.max_recursion
            ),
        ),
        kv("Tool steering", draft.steering.label().to_string()),
        kv(
            "Goal-completion skeptics",
            if draft.goal_skeptics == 0 {
                "off".to_string()
            } else {
                draft.goal_skeptics.to_string()
            },
        ),
        Line::raw(""),
        section("Self-verify"),
    ];
    for (name, surface) in super::SURFACES.iter().zip(&draft.self_verify) {
        lines.push(kv(name, surface.describe()));
    }
    lines.push(Line::raw(""));
    lines.push(section("Tools"));
    for (tool, state) in super::TOOLS.iter().zip(&draft.tools) {
        let grant = if matches!(tool.tier, super::Tier::Required) {
            super::ToolGrant::Enabled
        } else {
            state.grant
        };
        let mark = match grant {
            super::ToolGrant::Enabled => "\u{2713}",
            super::ToolGrant::Discoverable => "\u{25d0}",
            super::ToolGrant::Disabled => "\u{00b7}",
        };
        let color = match grant {
            super::ToolGrant::Enabled => GOOD,
            super::ToolGrant::Discoverable => WARN,
            super::ToolGrant::Disabled => NIGHT,
        };
        let model = state
            .model
            .and_then(|m| catalog.get(m))
            .map(|m| format!("  (model: {})", m.label()))
            .unwrap_or_default();
        lines.push(Line::from(vec![
            Span::styled(format!("{mark} "), Style::new().fg(color)),
            Span::styled(
                tool.display.to_string(),
                Style::new().fg(if matches!(grant, super::ToolGrant::Disabled) {
                    FOG
                } else {
                    INK
                }),
            ),
            Span::styled(model, Style::new().fg(FOG)),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(section("Subagents"));
    if draft.subagents.is_empty() {
        lines.push(Line::from(Span::styled(
            "none",
            Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
        )));
    } else {
        for sub in &draft.subagents {
            let sub_name = if sub.name.trim().is_empty() {
                "unnamed".to_string()
            } else {
                sub.name.trim().to_string()
            };
            lines.push(kv(
                &sub_name,
                format!(
                    "{} \u{b7} {} model(s) \u{b7} {} tool(s)",
                    if sub.trusted { "trusted" } else { "untrusted" },
                    sub.model_allowed.iter().filter(|&&on| on).count(),
                    super::count_enabled(&sub.tools),
                ),
            ));
        }
    }
    lines
}

fn on_off(on: bool) -> String {
    if on {
        "on".to_string()
    } else {
        "off".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onboard::agent::sample_catalog;

    #[test]
    fn detail_lines_cover_every_section() {
        let catalog = sample_catalog();
        let draft = AgentDraft::new(&catalog);
        let lines = detail_lines(&draft, &catalog);
        let text: String = lines
            .iter()
            .flat_map(|line| line.spans.iter().map(|s| s.content.to_string()))
            .collect::<Vec<_>>()
            .join(" ");
        for needle in [
            "Trust",
            "Models",
            "Optimizations",
            "Self-verify",
            "Tools",
            "Subagents",
        ] {
            assert!(text.contains(needle), "missing {needle} in: {text}");
        }
    }
}
