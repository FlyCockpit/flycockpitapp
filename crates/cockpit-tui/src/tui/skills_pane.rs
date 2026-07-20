//! `/skills` pane — a read-only listing of every discovered skill.
//!
//! Lists each skill's name, one-line description, and source path so the
//! user can tell which scan-dir / which copy won when names collide. The
//! pane is purely informational: there's no selecting, invoking, or
//! editing — Esc (or `q`) dismisses it.
//!
//! The list comes from the daemon's `ListSkills` RPC (the same discovery
//! the `skill` tool and auto-select path use), not from re-running
//! discovery in the TUI. Mirrors [`crate::tui::stats_pane`]'s shape
//! (`open` / `handle_key` / `render`); `App` opens it over the chat body
//! and routes input/render the same way.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::tui::agent_runner;
use crate::tui::pane::Pane;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_core::daemon::proto::{Request, Response, SkillSummary};

pub struct SkillsPane {
    /// Discovered skills, or an error string if the fetch failed. Loaded
    /// once at open — the set is static for the life of the overlay.
    skills: Result<Vec<SkillSummary>, String>,
    /// Vertical scroll offset (in rendered body rows).
    scroll: usize,
    /// Rendered body height at the last draw — drives scroll clamping.
    last_body_height: usize,
    /// Total rendered body rows at the last draw — drives scroll clamp.
    last_content_rows: usize,
}

impl SkillsPane {
    /// Open the pane for `cwd`, fetching the skill list via the
    /// `ListSkills` RPC. A daemon/RPC failure is non-fatal — the pane
    /// renders the error inline rather than refusing to open, so
    /// `/skills` always shows something.
    pub fn open(cwd: &std::path::Path) -> Self {
        let skills = fetch_skills(cwd);
        Self {
            skills,
            scroll: 0,
            last_body_height: 0,
            last_content_rows: 0,
        }
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
        match &self.skills {
            Err(e) => vec![Line::from(Span::styled(
                format!("skills unavailable: {e}"),
                Style::default().fg(Color::Red),
            ))],
            Ok(skills) if skills.is_empty() => vec![Line::from(Span::styled(
                "No skills found in the configured scan directories.".to_string(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ))],
            Ok(skills) => skill_lines(skills),
        }
    }
}

/// Fetch the skill list from the daemon for `cwd`. Returns the error as a
/// string so the pane can render it inline rather than panicking.
impl Pane for SkillsPane {
    type Outcome = bool;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        SkillsPane::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        SkillsPane::render(self, frame, area);
    }
}

fn fetch_skills(cwd: &std::path::Path) -> Result<Vec<SkillSummary>, String> {
    let req = Request::ListSkills {
        project_root: cwd.to_string_lossy().into_owned(),
    };
    match agent_runner::daemon_request_blocking(req)? {
        Response::Skills { skills } => Ok(skills),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
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
        SkillsPane {
            skills,
            scroll: 0,
            last_body_height: 100,
            last_content_rows: 0,
        }
    }

    fn summary(name: &str, desc: &str, source: &str) -> SkillSummary {
        SkillSummary {
            name: name.into(),
            description: desc.into(),
            source: source.into(),
        }
    }

    fn render_text(pane: &SkillsPane) -> String {
        pane.body_lines()
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

    #[test]
    fn lists_name_description_and_source() {
        let pane = pane_with(Ok(vec![
            summary("greet", "say hi", "/home/u/.agents/skills/greet/SKILL.md"),
            summary("build", "compile it", "/proj/.agents/skills/build/SKILL.md"),
        ]));
        let text = render_text(&pane);
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
        let text = render_text(&pane);
        assert_eq!(text, "No skills found in the configured scan directories.");
    }

    #[test]
    fn fetch_error_renders_inline() {
        let pane = pane_with(Err("daemon not running".to_string()));
        let text = render_text(&pane);
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
}
