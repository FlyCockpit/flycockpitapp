//! `/skills` pane — a read-only listing of every discovered skill.
//!
//! Lists each skill's name, one-line description, and source path so the
//! user can tell which scan-dir / which copy won when names collide. The
//! pane is purely informational: there's no selecting, invoking, or
//! editing — Esc (or `q`) dismisses it.
//!
//! The list comes from the attached session's `GetInventoryBundle` RPC.
//! Pre-attach inventory is explicitly unavailable (no local discovery).
//! Mirrors [`crate::tui::stats_pane`]'s shape (`handle_key` / `render`);
//! `App` opens it over the chat body and routes input/render the same way.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState,
};

use crate::tui::pane::Pane;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_proto::SkillSummary;

pub struct SkillsPane {
    generation: u64,
    state: SkillsPaneState,
    /// Durable row viewport. This read-only pane has no selected item, so
    /// only `ListState`'s offset is user-owned.
    list: ListState,
    /// Rendered body height at the last draw — drives scroll clamping.
    last_body_height: usize,
    /// Total rendered body rows at the last draw — drives scroll clamp.
    last_content_rows: usize,
}

#[derive(Debug, Clone)]
enum SkillsPaneState {
    Loading,
    Ready {
        skills: Vec<SkillSummary>,
        source: SkillsPaneSource,
    },
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillsPaneSource {
    Session,
    Local,
}

#[derive(Debug, Clone)]
pub struct SkillsPaneFetchResult {
    pub generation: u64,
    pub source: SkillsPaneSource,
    pub skills: Result<Vec<SkillSummary>, String>,
    /// Full bundle when the fetch came from GetInventoryBundle (for inventory state).
    pub bundle: Option<cockpit_proto::Response>,
}

impl SkillsPane {
    pub fn loading(generation: u64) -> Self {
        Self::new(generation, SkillsPaneState::Loading)
    }

    pub fn ready(
        generation: u64,
        source: SkillsPaneSource,
        skills: Result<Vec<SkillSummary>, String>,
    ) -> Self {
        let state = match skills {
            Ok(skills) => SkillsPaneState::Ready { skills, source },
            Err(error) => SkillsPaneState::Error(error),
        };
        Self::new(generation, state)
    }

    fn new(generation: u64, state: SkillsPaneState) -> Self {
        Self {
            generation,
            state,
            list: ListState::default(),
            last_body_height: 0,
            last_content_rows: 0,
        }
    }

    pub fn apply_fetch_result(&mut self, result: SkillsPaneFetchResult) -> bool {
        if result.generation != self.generation {
            return false;
        }
        self.state = match result.skills {
            Ok(skills) => SkillsPaneState::Ready {
                skills,
                source: result.source,
            },
            Err(error) => SkillsPaneState::Error(error),
        };
        *self.list.offset_mut() = 0;
        true
    }

    /// Handle a key. Returns `true` when the pane should close. The
    /// overlay is read-only, so only scroll + dismiss keys are live.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            KeyCode::Up | KeyCode::Char('k') => {
                *self.list.offset_mut() = self.list.offset().saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
                *self.list.offset_mut() = (self.list.offset() + 1).min(max_scroll);
            }
            KeyCode::PageUp => {
                *self.list.offset_mut() = self
                    .list
                    .offset()
                    .saturating_sub(self.last_body_height.max(1));
            }
            KeyCode::PageDown => {
                let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
                *self.list.offset_mut() =
                    (self.list.offset() + self.last_body_height.max(1)).min(max_scroll);
            }
            KeyCode::Char('g') => *self.list.offset_mut() = 0,
            KeyCode::Char('G') => {
                *self.list.offset_mut() =
                    self.last_content_rows.saturating_sub(self.last_body_height);
            }
            _ => {}
        }
        false
    }

    /// Scroll the body up by one row (mouse wheel).
    pub fn scroll_up(&mut self) {
        *self.list.offset_mut() = self.list.offset().saturating_sub(1);
    }

    /// Scroll the body down by one row (mouse wheel), clamped so the last
    /// row can't scroll above the body floor.
    pub fn scroll_down(&mut self) {
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        *self.list.offset_mut() = (self.list.offset() + 1).min(max_scroll);
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Line::from(" /skills "));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        // Body above, single help line at the bottom.
        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let body = layout[0];
        let help_area = layout[1];

        let lines = self.body_lines();
        self.last_content_rows = lines.len();
        self.last_body_height = body.height as usize;
        // Clamp scroll to the valid range now that we know the heights.
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        *self.list.offset_mut() = self.list.offset().min(max_scroll);

        let overflow = self.last_content_rows > self.last_body_height;
        let (list_area, scrollbar_area) = if overflow && body.width >= 2 {
            let cols = Layout::horizontal([Constraint::Min(0), Constraint::Length(1)]).split(body);
            (cols[0], Some(cols[1]))
        } else {
            (body, None)
        };
        let items = lines.into_iter().map(ListItem::new).collect::<Vec<_>>();
        frame.render_stateful_widget(List::new(items), list_area, &mut self.list);
        if let Some(scrollbar_area) = scrollbar_area {
            let mut scrollbar = ScrollbarState::new(self.last_content_rows)
                .position(self.list.offset())
                .viewport_content_length(list_area.height as usize);
            frame.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(None)
                    .end_symbol(None),
                scrollbar_area,
                &mut scrollbar,
            );
        }

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "q quit  ↑/↓ scroll  g/G top/bottom".to_string(),
                muted,
            ))),
            help_area,
        );
    }

    /// Assemble every body row as owned [`Line`]s. Pure aside from
    /// reading `self`, so the empty-state / listing logic is unit-testable
    /// without an `App`/terminal.
    fn body_lines(&self) -> Vec<Line<'static>> {
        match &self.state {
            SkillsPaneState::Loading => vec![Line::from(Span::styled(
                "Loading skills...".to_string(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ))],
            SkillsPaneState::Error(e) => vec![Line::from(Span::styled(
                format!("skills unavailable: {e}"),
                Style::default().fg(Color::Red),
            ))],
            SkillsPaneState::Ready { skills, source } => ready_lines(skills, *source),
        }
    }

    #[cfg(test)]
    pub(crate) fn body_text_for_test(&self) -> String {
        self.body_lines()
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[cfg(test)]
    pub(crate) fn generation_for_test(&self) -> u64 {
        self.generation
    }
}

impl Pane for SkillsPane {
    type Outcome = bool;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        SkillsPane::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        SkillsPane::render(self, frame, area);
    }
}

fn ready_lines(skills: &[SkillSummary], source: SkillsPaneSource) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if source == SkillsPaneSource::Local {
        lines.push(Line::from(Span::styled(
            "local view - session-specific activation unavailable".to_string(),
            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
        )));
        lines.push(Line::default());
    }
    if skills.is_empty() {
        lines.push(Line::from(Span::styled(
            "No skills found in the configured scan directories.".to_string(),
            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
        )));
    } else {
        lines.extend(skill_lines(skills));
    }
    lines
}

/// Render the non-empty skill list: a name + source header line per skill
/// (source muted), then the indented description underneath, with a blank
/// separator between entries.
fn skill_lines(skills: &[SkillSummary]) -> Vec<Line<'static>> {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let mut out: Vec<Line<'static>> = Vec::new();
    for (i, s) in skills.iter().enumerate() {
        if i > 0 {
            out.push(Line::default());
        }
        out.push(Line::from(vec![
            Span::styled(
                s.name.clone(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(s.source.clone(), muted),
        ]));
        out.push(Line::from(Span::styled(
            format!("  {}", s.description),
            Style::default().fg(Color::White),
        )));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn pane_with(skills: Result<Vec<SkillSummary>, String>) -> SkillsPane {
        SkillsPane::ready(1, SkillsPaneSource::Session, skills)
    }

    fn summary(name: &str, desc: &str, source: &str) -> SkillSummary {
        SkillSummary {
            name: name.into(),
            description: desc.into(),
            source: source.into(),
            user_invocable: true,
        }
    }

    fn rendered_buffer(pane: &mut SkillsPane, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, width, height)))
            .expect("draw skills");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn lists_name_description_and_source() {
        let pane = pane_with(Ok(vec![
            summary("greet", "say hi", "/home/u/.agents/skills/greet/SKILL.md"),
            summary("build", "compile it", "/proj/.agents/skills/build/SKILL.md"),
        ]));
        let text = pane.body_text_for_test();
        assert!(text.contains("greet"));
        assert!(text.contains("say hi"));
        assert!(text.contains("/home/u/.agents/skills/greet/SKILL.md"));
        assert!(text.contains("build"));
        assert!(text.contains("compile it"));
        assert!(text.contains("/proj/.agents/skills/build/SKILL.md"));
    }

    #[test]
    fn empty_shows_empty_state_not_blank() {
        let pane = pane_with(Ok(Vec::new()));
        let text = pane.body_text_for_test();
        assert_eq!(text, "No skills found in the configured scan directories.");
    }

    #[test]
    fn fetch_error_renders_inline() {
        let pane = pane_with(Err("daemon not running".to_string()));
        let text = pane.body_text_for_test();
        assert!(text.contains("skills unavailable"));
        assert!(text.contains("daemon not running"));
    }

    #[test]
    fn esc_and_q_close_the_pane() {
        let mut pane = pane_with(Ok(Vec::new()));
        assert!(pane.handle_key(press(KeyCode::Esc)));
        let mut pane = pane_with(Ok(Vec::new()));
        assert!(pane.handle_key(press(KeyCode::Char('q'))));
    }

    #[test]
    fn scroll_clamps_to_content() {
        // One skill → two content rows; with a tall body the scroll floor
        // pins at zero and Down can't move past it.
        let mut pane = pane_with(Ok(vec![summary("a", "d", "/s")]));
        pane.last_content_rows = 2;
        pane.last_body_height = 100;
        pane.handle_key(press(KeyCode::Down));
        assert_eq!(pane.list.offset(), 0, "can't scroll past the content floor");

        // A short body: Down advances, capped at content - height.
        pane.last_content_rows = 10;
        pane.last_body_height = 4;
        *pane.list.offset_mut() = 0;
        for _ in 0..20 {
            pane.handle_key(press(KeyCode::Down));
        }
        assert_eq!(
            pane.list.offset(),
            6,
            "scroll caps at content_rows - body_height"
        );
        pane.handle_key(press(KeyCode::Char('g')));
        assert_eq!(pane.list.offset(), 0, "g jumps to top");
        pane.handle_key(press(KeyCode::Char('G')));
        assert_eq!(pane.list.offset(), 6, "G jumps to bottom");
    }

    #[test]
    fn local_source_renders_detached_subtitle() {
        let pane = SkillsPane::ready(
            1,
            SkillsPaneSource::Local,
            Ok(vec![summary("a", "d", "/s")]),
        );

        let text = pane.body_text_for_test();

        assert!(text.contains("local view - session-specific activation unavailable"));
        assert!(text.contains("a"));
    }

    #[test]
    fn skills_pane_stale_result_dropped() {
        let mut pane = SkillsPane::ready(
            2,
            SkillsPaneSource::Local,
            Ok(vec![summary("new", "d", "/s")]),
        );

        let applied = pane.apply_fetch_result(SkillsPaneFetchResult {
            generation: 1,
            source: SkillsPaneSource::Session,
            skills: Ok(vec![summary("stale", "d", "/s")]),
            bundle: None,
        });

        assert!(!applied);
        assert!(pane.body_text_for_test().contains("new"));
        assert!(!pane.body_text_for_test().contains("stale"));
    }

    #[test]
    fn test_backend_covers_loading_error_empty_unicode_resize_and_scrollbar() {
        let mut loading = SkillsPane::loading(1);
        assert!(rendered_buffer(&mut loading, 40, 6).contains("Loading skills"));

        let mut error = pane_with(Err("離線 — daemon unavailable".to_string()));
        let error_text = rendered_buffer(&mut error, 48, 6);
        assert!(error_text.contains("skills unavailable"));
        assert!(error_text.contains("離線"));

        let mut empty = pane_with(Ok(Vec::new()));
        assert!(rendered_buffer(&mut empty, 64, 6).contains("No skills found"));

        let skills = (0..18)
            .map(|index| {
                summary(
                    &format!("技能-{index}"),
                    "A deliberately long Unicode description — café 🚀 — clipped safely",
                    &format!("/project/技能/{index}/SKILL.md"),
                )
            })
            .collect();
        let mut pane = pane_with(Ok(skills));
        let narrow = rendered_buffer(&mut pane, 32, 7);
        assert!(narrow.contains("技能-0"));
        assert!(pane.last_content_rows > pane.last_body_height);

        for _ in 0..100 {
            pane.scroll_down();
        }
        let bottom = pane.list.offset();
        assert_eq!(
            bottom,
            pane.last_content_rows.saturating_sub(pane.last_body_height)
        );
        let scrolled = rendered_buffer(&mut pane, 32, 7);
        assert_ne!(narrow, scrolled);
        assert!(scrolled.contains("技能-17"));
        assert!(!scrolled.contains("技能-0 "));

        let wide = rendered_buffer(&mut pane, 90, 12);
        assert_eq!(
            pane.list.offset(),
            bottom.min(pane.last_content_rows.saturating_sub(pane.last_body_height))
        );
        assert!(wide.contains("q quit"));
    }

    #[test]
    fn scrollbar_has_a_reserved_column_and_does_not_overwrite_content_edge() {
        let edge_name = format!("{}Z", "a".repeat(36));
        let skills = std::iter::once(summary(&edge_name, "first", "/s"))
            .chain((1..20).map(|index| summary(&format!("skill-{index}"), "desc", "/s")))
            .collect();
        let mut pane = pane_with(Ok(skills));
        let mut terminal = Terminal::new(TestBackend::new(40, 7)).expect("terminal");
        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, 40, 7)))
            .expect("draw skills");
        let buffer = terminal.backend().buffer();
        assert_eq!(buffer[(37, 1)].symbol(), "Z");
        assert_ne!(buffer[(38, 1)].symbol(), "Z");
        assert!(
            (1..5).any(|row| !buffer[(38, row)].symbol().trim().is_empty()),
            "reserved rightmost body column contains the scrollbar"
        );
    }
}
