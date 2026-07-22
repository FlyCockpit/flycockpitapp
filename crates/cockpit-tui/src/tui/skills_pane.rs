//! `/skills` pane — a read-only listing of every discovered skill.
//!
//! Lists each skill's name, one-line description, and source path so the
//! user can tell which scan-dir / which copy won when names collide. The
//! pane is purely informational: there's no selecting, invoking, or
//! editing — Esc (or `q`) dismisses it.
//!
//! The list comes from the attached session's `ListSkills` RPC when an
//! agent runner is present, with local discovery as the detached fallback.
//! Mirrors [`crate::tui::stats_pane`]'s shape (`handle_key` / `render`);
//! `App` opens it over the chat body and routes input/render the same way.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::tui::pane::Pane;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_config::extended::SkillsConfig;
use cockpit_core::daemon::proto::SkillSummary;

pub struct SkillsPane {
    generation: u64,
    state: SkillsPaneState,
    /// Vertical scroll offset (in rendered body rows).
    scroll: usize,
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
            scroll: 0,
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
        self.scroll = 0;
        true
    }

    /// Handle a key. Returns `true` when the pane should close. The
    /// overlay is read-only, so only scroll + dismiss keys are live.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
                self.scroll = (self.scroll + 1).min(max_scroll);
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(self.last_body_height.max(1));
            }
            KeyCode::PageDown => {
                let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
                self.scroll = (self.scroll + self.last_body_height.max(1)).min(max_scroll);
            }
            KeyCode::Char('g') => self.scroll = 0,
            KeyCode::Char('G') => {
                self.scroll = self.last_content_rows.saturating_sub(self.last_body_height);
            }
            _ => {}
        }
        false
    }

    /// Scroll the body up by one row (mouse wheel).
    pub fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    /// Scroll the body down by one row (mouse wheel), clamped so the last
    /// row can't scroll above the body floor.
    pub fn scroll_down(&mut self) {
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        self.scroll = (self.scroll + 1).min(max_scroll);
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
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }

        frame.render_widget(Paragraph::new(lines).scroll((self.scroll as u16, 0)), body);

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

pub(crate) fn local_skill_summaries(
    cwd: &std::path::Path,
    skills_config: &SkillsConfig,
    agent_name: &str,
) -> Result<Vec<SkillSummary>, String> {
    cockpit_core::skills::discover_for_agent(cwd, skills_config, agent_name)
        .map(|skills| {
            skills
                .into_iter()
                .map(|s| SkillSummary {
                    name: s.frontmatter.name,
                    description: s.frontmatter.description,
                    source: s.source.display().to_string(),
                    user_invocable: s.frontmatter.user_invocable,
                })
                .collect()
        })
        .map_err(|error| error.to_string())
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
        assert_eq!(pane.scroll, 0, "can't scroll past the content floor");

        // A short body: Down advances, capped at content - height.
        pane.last_content_rows = 10;
        pane.last_body_height = 4;
        pane.scroll = 0;
        for _ in 0..20 {
            pane.handle_key(press(KeyCode::Down));
        }
        assert_eq!(pane.scroll, 6, "scroll caps at content_rows - body_height");
        pane.handle_key(press(KeyCode::Char('g')));
        assert_eq!(pane.scroll, 0, "g jumps to top");
        pane.handle_key(press(KeyCode::Char('G')));
        assert_eq!(pane.scroll, 6, "G jumps to bottom");
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
        });

        assert!(!applied);
        assert!(pane.body_text_for_test().contains("new"));
        assert!(!pane.body_text_for_test().contains("stale"));
    }
}
