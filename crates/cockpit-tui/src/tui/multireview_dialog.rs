use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_config::extended::persist_review_default_participants;
use unicode_width::UnicodeWidthStr;

pub const DIALOG_HEIGHT: u16 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParticipantKind {
    Model,
    Harness,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn dialog() -> MultireviewDialog {
        MultireviewDialog {
            cwd: PathBuf::from("/tmp"),
            step: Step::Sources,
            source_cursor: 0,
            participant_cursor: 0,
            sources: vec![SourceRow {
                label: "Uncommitted changes",
                selected: false,
                pr: None,
            }],
            participants: vec![Participant {
                label: "openrouter/reviewer".into(),
                kind: ParticipantKind::Model,
                selected: false,
                sticky: false,
            }],
            prompt: TextField::default(),
            error: None,
            done: None,
        }
    }

    #[test]
    fn sources_require_at_least_one_selection() {
        let mut d = dialog();
        assert!(!d.handle_key(key(KeyCode::Enter)));
        assert_eq!(d.step, Step::Sources);
        assert_eq!(
            d.error.as_deref(),
            Some("select at least one change source")
        );
    }

    #[test]
    fn participant_space_and_a_toggle_selection_and_persistence() {
        let mut d = dialog();
        d.step = Step::Participants;
        assert!(!d.participants[0].selected);
        d.handle_key(key(KeyCode::Char(' ')));
        assert!(d.participants[0].selected);
        assert!(!d.participants[0].sticky);
        d.handle_key(key(KeyCode::Char('a')));
        assert!(d.participants[0].selected);
        assert!(d.participants[0].sticky);
    }

    #[test]
    fn paste_into_pr_source_field_selects_pr_and_truncates_to_first_line() {
        let mut d = dialog();
        d.sources.push(SourceRow {
            label: "PR",
            selected: false,
            pr: None,
        });
        d.source_cursor = 1;

        d.paste("123\nignored");

        assert!(d.sources[1].selected);
        assert_eq!(d.sources[1].pr.as_deref(), Some("123"));
    }

    #[test]
    fn paste_into_prompt_uses_text_field_cursor_behavior() {
        let mut d = dialog();
        d.step = Step::Prompt;
        d.handle_key(key(KeyCode::Char('a')));
        d.handle_key(key(KeyCode::Char('c')));
        d.handle_key(key(KeyCode::Left));

        d.paste("b\nignored");

        assert_eq!(d.prompt.text(), "abc");
        assert_eq!(d.prompt.cursor(), 2);
        assert!(d.done.is_none());
    }

    #[test]
    fn prompt_lines_render_text_without_fake_caret() {
        let mut d = dialog();
        d.prompt.set("alpha".to_string());
        d.prompt.handle_key(key(KeyCode::Home));
        d.prompt.handle_key(key(KeyCode::Right));
        d.prompt.handle_key(key(KeyCode::Right));

        let rendered = d
            .prompt_lines()
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("focus: alpha"), "{rendered}");
    }

    #[test]
    fn paste_on_non_text_multireview_controls_is_ignored() {
        let mut d = dialog();
        d.paste("does not toggle");
        assert!(!d.sources[0].selected);
        assert_eq!(d.sources[0].pr, None);

        d.step = Step::Participants;
        d.paste("does not select");
        assert!(!d.participants[0].selected);
        assert_eq!(d.prompt.text(), "");
    }

    #[test]
    fn participant_lines_window_around_cursor() {
        let mut d = dialog();
        d.participants = (0..20)
            .map(|i| Participant {
                label: format!("reviewer-{i}"),
                kind: ParticipantKind::Model,
                selected: false,
                sticky: false,
            })
            .collect();
        d.participant_cursor = 19;

        let rendered = d
            .participant_lines()
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!rendered.contains("reviewer-0"), "{rendered}");
        assert!(rendered.contains("> [ ] reviewer-19"), "{rendered}");
    }
}

#[derive(Debug, Clone)]
struct Participant {
    label: String,
    kind: ParticipantKind,
    selected: bool,
    sticky: bool,
}

#[derive(Debug, Clone)]
pub struct MultireviewKickoff {
    pub prompt: String,
}

pub struct MultireviewDialog {
    cwd: PathBuf,
    step: Step,
    source_cursor: usize,
    participant_cursor: usize,
    sources: Vec<SourceRow>,
    participants: Vec<Participant>,
    prompt: TextField,
    error: Option<String>,
    done: Option<MultireviewKickoff>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Sources,
    Participants,
    Prompt,
}

#[derive(Debug, Clone)]
struct SourceRow {
    label: &'static str,
    selected: bool,
    pr: Option<String>,
}

impl MultireviewDialog {
    pub fn open(
        cwd: &Path,
        counts: &std::collections::HashMap<String, u64>,
    ) -> Result<Self, String> {
        let cfg = cockpit_config::extended::load_for_cwd(cwd);
        let defaults: BTreeSet<String> = cfg.review.default_participants.iter().cloned().collect();
        let mut participants = Vec::new();
        for model in crate::tui::model_picker::ordered_model_choices(cwd, counts)? {
            let label = model.label;
            let sticky = defaults.contains(&label);
            participants.push(Participant {
                label,
                kind: ParticipantKind::Model,
                selected: sticky,
                sticky,
            });
        }
        let harnesses = cockpit_config::extended::resolve_harnesses(cwd);
        let mut names: Vec<String> = harnesses.keys().cloned().collect();
        names.sort();
        for name in names {
            let label = format!("harness:{name}");
            let sticky = defaults.contains(&label);
            participants.push(Participant {
                label,
                kind: ParticipantKind::Harness,
                selected: sticky,
                sticky,
            });
        }
        Ok(Self {
            cwd: cwd.to_path_buf(),
            step: Step::Sources,
            source_cursor: 0,
            participant_cursor: 0,
            sources: vec![
                SourceRow {
                    label: "Uncommitted changes",
                    selected: false,
                    pr: None,
                },
                SourceRow {
                    label: "Unstaged changes",
                    selected: false,
                    pr: None,
                },
                SourceRow {
                    label: "Unpushed changes",
                    selected: false,
                    pr: None,
                },
                SourceRow {
                    label: "PR",
                    selected: false,
                    pr: None,
                },
            ],
            participants,
            prompt: TextField::default(),
            error: None,
            done: None,
        })
    }

    pub fn take_done(&mut self) -> Option<MultireviewKickoff> {
        self.done.take()
    }

    pub fn paste(&mut self, text: &str) {
        match self.step {
            Step::Sources if self.sources[self.source_cursor].label == "PR" => {
                let first_line = match text.find('\n') {
                    Some(nl) => &text[..nl],
                    None => text,
                };
                if first_line.is_empty() {
                    return;
                }
                let row = &mut self.sources[self.source_cursor];
                let pr = row.pr.get_or_insert_with(String::new);
                pr.push_str(first_line);
                row.selected = true;
            }
            Step::Prompt => self.prompt.paste(text),
            Step::Sources | Step::Participants => {}
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        self.error = None;
        if matches!(key.code, KeyCode::Esc) {
            return true;
        }
        match self.step {
            Step::Sources => self.handle_sources(key),
            Step::Participants => self.handle_participants(key),
            Step::Prompt => self.handle_prompt(key),
        }
        false
    }

    fn handle_sources(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up => self.source_cursor = self.source_cursor.saturating_sub(1),
            KeyCode::Down => {
                self.source_cursor = (self.source_cursor + 1).min(self.sources.len() - 1);
            }
            KeyCode::Char(' ') => {
                let row = &mut self.sources[self.source_cursor];
                row.selected = !row.selected;
            }
            KeyCode::Char(c) if self.sources[self.source_cursor].label == "PR" => {
                let row = &mut self.sources[self.source_cursor];
                let pr = row.pr.get_or_insert_with(String::new);
                pr.push(c);
                row.selected = true;
            }
            KeyCode::Backspace if self.sources[self.source_cursor].label == "PR" => {
                if let Some(pr) = self.sources[self.source_cursor].pr.as_mut() {
                    pr.pop();
                }
            }
            KeyCode::Enter | KeyCode::Tab => {
                if self.sources.iter().any(|s| s.selected) {
                    self.step = Step::Participants;
                } else {
                    self.error = Some("select at least one change source".into());
                }
            }
            _ => {}
        }
    }

    fn handle_participants(&mut self, key: KeyEvent) {
        if self.participants.is_empty() {
            if matches!(key.code, KeyCode::Enter | KeyCode::Tab) {
                self.error = Some("no configured models or harnesses found".into());
            }
            return;
        }
        match key.code {
            KeyCode::Up => self.participant_cursor = self.participant_cursor.saturating_sub(1),
            KeyCode::Down => {
                self.participant_cursor =
                    (self.participant_cursor + 1).min(self.participants.len() - 1);
            }
            KeyCode::Char(' ') => {
                let row = &mut self.participants[self.participant_cursor];
                row.selected = !row.selected;
                if !row.selected {
                    row.sticky = false;
                }
            }
            KeyCode::Char('a') => {
                let row = &mut self.participants[self.participant_cursor];
                row.selected = true;
                row.sticky = !row.sticky;
            }
            KeyCode::Enter | KeyCode::Tab => {
                if self.participants.iter().any(|p| p.selected) {
                    let sticky: Vec<String> = self
                        .participants
                        .iter()
                        .filter(|p| p.sticky)
                        .map(|p| p.label.clone())
                        .collect();
                    if let Err(e) = persist_review_default_participants(&self.cwd, sticky) {
                        self.error = Some(format!("could not persist defaults: {e:#}"));
                    } else {
                        self.step = Step::Prompt;
                    }
                } else {
                    self.error = Some("select at least one reviewer".into());
                }
            }
            _ => {}
        }
    }

    fn handle_prompt(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Tab => match self.build_kickoff() {
                Ok(kickoff) => self.done = Some(kickoff),
                Err(e) => self.error = Some(e),
            },
            _ => {
                self.prompt.handle_key(key);
            }
        }
    }

    fn build_kickoff(&self) -> Result<MultireviewKickoff, String> {
        let mut commands = Vec::new();
        let mut skipped = Vec::new();
        for row in self.sources.iter().filter(|s| s.selected) {
            let result = match row.label {
                "Uncommitted changes" => cockpit_core::git::review_source_uncommitted(&self.cwd),
                "Unstaged changes" => cockpit_core::git::review_source_unstaged(&self.cwd),
                "Unpushed changes" => cockpit_core::git::review_source_unpushed(&self.cwd),
                "PR" => {
                    let pr = row.pr.as_deref().unwrap_or("").trim();
                    if pr.is_empty() {
                        Err(anyhow::anyhow!(
                            "PR source selected but no PR number or URL was entered"
                        ))
                    } else {
                        cockpit_core::git::review_source_pr(&self.cwd, pr)
                    }
                }
                _ => continue,
            };
            match result {
                Ok(src) if src.diff.trim().is_empty() => {
                    skipped.push(format!("- {}: no changes", src.label));
                }
                Ok(src) => commands.push(format!("- {}: `{}`", src.label, src.command)),
                Err(e) => skipped.push(format!("- {}: {e:#}", row.label)),
            }
        }
        if commands.is_empty() {
            return Err("all selected sources were empty or skipped".into());
        }
        let models: Vec<String> = self
            .participants
            .iter()
            .filter(|p| p.selected && p.kind == ParticipantKind::Model)
            .map(|p| p.label.clone())
            .collect();
        let harnesses: Vec<String> = self
            .participants
            .iter()
            .filter(|p| p.selected && p.kind == ParticipantKind::Harness)
            .map(|p| p.label.trim_start_matches("harness:").to_string())
            .collect();
        let guide = self.prompt.text().trim();
        let guide = if guide.is_empty() {
            "Perform a comprehensive code review of correctness, regressions, missing tests, concurrency, security, and maintainability."
        } else {
            guide
        };
        let skipped_text = if skipped.is_empty() {
            "(none)".to_string()
        } else {
            skipped.join("\n")
        };
        Ok(MultireviewKickoff {
            prompt: format!(
                "Begin `/multireview` now. First action: spawn the selected cockpit model reviewers as read-only `scout` workers, then run harness reviewers in isolated review-only mode.\n\nChange-source commands every worker must run:\n{}\n\nSkipped or empty sources:\n{}\n\nCockpit model reviewers:\n{}\n\nHarness reviewers:\n{}\n\nGuiding prompt:\n{}\n\nHard constraints: review only, make zero modifications, never change git state, use tiebreaker `scout` workers for conflicts, and return one consolidated file:line-anchored report.",
                commands.join("\n"),
                skipped_text,
                if models.is_empty() {
                    "(none)".into()
                } else {
                    models.join("\n")
                },
                if harnesses.is_empty() {
                    "(none)".into()
                } else {
                    harnesses.join("\n")
                },
                guide
            ),
        })
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default().borders(Borders::ALL).title("/multireview");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(inner);
        let lines = match self.step {
            Step::Sources => self.source_lines(),
            Step::Participants => self.participant_lines(),
            Step::Prompt => self.prompt_lines(),
        };
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), chunks[0]);
        if matches!(self.step, Step::Prompt) && chunks[0].height > 1 && chunks[0].width > 0 {
            let (before, _) = self.prompt.split_at_cursor();
            let col = "focus: ".width() + before.width();
            let col = col.min(chunks[0].width.saturating_sub(1) as usize) as u16;
            frame.set_cursor_position(Position::new(chunks[0].x + col, chunks[0].y + 1));
        }
        let help = self.error.as_deref().unwrap_or(match self.step {
            Step::Sources => "Space toggles, type PR number on PR row, Enter continues",
            Step::Participants => "Space selects once, a selects and persists, Enter continues",
            Step::Prompt => "Enter starts review, Esc cancels",
        });
        frame.render_widget(Paragraph::new(help), chunks[1]);
    }

    fn source_lines(&self) -> Vec<Line<'_>> {
        let mut lines = vec![Line::from("Change sources")];
        for (i, row) in self.sources.iter().enumerate() {
            let mark = if row.selected { "[x]" } else { "[ ]" };
            let cursor = if i == self.source_cursor { "> " } else { "  " };
            let extra = row
                .pr
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| format!(" {s}"))
                .unwrap_or_default();
            lines.push(Line::from(format!("{cursor}{mark} {}{extra}", row.label)));
        }
        lines
    }

    fn participant_lines(&self) -> Vec<Line<'_>> {
        let mut lines = vec![Line::from("Participants")];
        let visible_rows = 14usize;
        let start = if self.participant_cursor >= visible_rows {
            self.participant_cursor + 1 - visible_rows
        } else {
            0
        };
        for (i, row) in self
            .participants
            .iter()
            .enumerate()
            .skip(start)
            .take(visible_rows)
        {
            let mark = if row.sticky {
                "[a]"
            } else if row.selected {
                "[x]"
            } else {
                "[ ]"
            };
            let cursor = if i == self.participant_cursor {
                "> "
            } else {
                "  "
            };
            lines.push(Line::from(format!("{cursor}{mark} {}", row.label)));
        }
        lines
    }

    fn prompt_lines(&self) -> Vec<Line<'_>> {
        let (before, after) = self.prompt.split_at_cursor();
        vec![
            Line::from("Guiding prompt"),
            Line::from(vec![
                Span::styled(
                    "focus: ",
                    Style::default().fg(ratatui::style::Color::Indexed(MUTED_COLOR_INDEX)),
                ),
                Span::raw(before.to_string()),
                Span::raw(after.to_string()),
            ]),
        ]
    }
}
