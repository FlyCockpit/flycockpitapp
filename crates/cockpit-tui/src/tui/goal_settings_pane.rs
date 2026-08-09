use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cockpit_core::agents::{AgentDef, GoalSettingsOverride};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{List, ListItem, ListState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GoalSettingsSaveTarget {
    Session,
    Agent,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GoalSettingsOutcome {
    Close,
    Apply {
        override_json: Option<String>,
        persist_session: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GoalSettingsField {
    Enabled,
    SkepticCount,
    SkepticModel,
    MaxRounds,
}

const FIELDS: &[GoalSettingsField] = &[
    GoalSettingsField::Enabled,
    GoalSettingsField::SkepticCount,
    GoalSettingsField::SkepticModel,
    GoalSettingsField::MaxRounds,
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct GoalSettingsDraft {
    enabled: Option<bool>,
    skeptic_count: Option<usize>,
    skeptic_model: Option<String>,
    max_rounds: Option<u32>,
}

impl GoalSettingsDraft {
    fn from_override(override_: &GoalSettingsOverride) -> Self {
        Self {
            enabled: override_.enabled,
            skeptic_count: override_.skeptic_count,
            skeptic_model: override_.skeptic_model.clone(),
            max_rounds: override_.max_rounds,
        }
    }

    fn to_override(&self) -> GoalSettingsOverride {
        GoalSettingsOverride {
            enabled: self.enabled,
            skeptic_count: self.skeptic_count,
            skeptic_model: self
                .skeptic_model
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            max_rounds: self.max_rounds,
        }
    }

    fn clear(&mut self, field: GoalSettingsField) {
        match field {
            GoalSettingsField::Enabled => self.enabled = None,
            GoalSettingsField::SkepticCount => self.skeptic_count = None,
            GoalSettingsField::SkepticModel => self.skeptic_model = None,
            GoalSettingsField::MaxRounds => self.max_rounds = None,
        }
    }
}

pub(crate) struct GoalSettingsPane {
    agent_name: String,
    cwd: PathBuf,
    root_foreground: bool,
    def: AgentDef,
    draft: GoalSettingsDraft,
    cursor: usize,
    status: Option<String>,
    confirm: Option<GoalSettingsSaveTarget>,
}

impl GoalSettingsPane {
    pub(crate) fn open(cwd: &Path, agent_name: &str, root_foreground: bool) -> Result<Self> {
        let def = cockpit_core::agents::resolve(cwd, agent_name)?
            .ok_or_else(|| anyhow::anyhow!("agent `{agent_name}` could not be resolved"))?;
        let draft = GoalSettingsDraft::from_override(&def.goal_verification);
        let status = (!root_foreground).then(|| {
            "Apply is disabled while an interactive subagent holds the foreground.".to_string()
        });
        Ok(Self {
            agent_name: agent_name.to_string(),
            cwd: cwd.to_path_buf(),
            root_foreground,
            def,
            draft,
            cursor: 0,
            status,
            confirm: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn agent_name(&self) -> &str {
        &self.agent_name
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<GoalSettingsOutcome> {
        if self.confirm.is_some() {
            return self.handle_confirm_key(key);
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Some(GoalSettingsOutcome::Close),
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_prev();
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_next();
                None
            }
            KeyCode::Char(' ') | KeyCode::Char('t') => {
                self.cycle_selected();
                None
            }
            KeyCode::Char('+') | KeyCode::Char('=') => {
                self.bump_selected(1);
                None
            }
            KeyCode::Char('-') => {
                self.bump_selected(-1);
                None
            }
            KeyCode::Char('i') => {
                self.draft.clear(self.selected_field());
                self.status = None;
                None
            }
            KeyCode::Backspace => {
                if self.selected_field() == GoalSettingsField::SkepticModel
                    && let Some(model) = &mut self.draft.skeptic_model
                {
                    model.pop();
                    if model.trim().is_empty() {
                        self.draft.skeptic_model = None;
                    }
                    self.status = None;
                }
                None
            }
            KeyCode::Char('s') => {
                self.start_confirm(GoalSettingsSaveTarget::Session);
                None
            }
            KeyCode::Char('a') => {
                self.start_confirm(GoalSettingsSaveTarget::Agent);
                None
            }
            KeyCode::Char(ch)
                if self.selected_field() == GoalSettingsField::SkepticModel
                    && !key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                let model = self.draft.skeptic_model.get_or_insert_with(String::new);
                model.push(ch);
                self.status = None;
                None
            }
            _ => None,
        }
    }

    fn handle_confirm_key(&mut self, key: KeyEvent) -> Option<GoalSettingsOutcome> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') => {
                self.confirm = None;
                self.status = Some("save cancelled".to_string());
                None
            }
            KeyCode::Enter | KeyCode::Char('y') => Some(self.confirmed_save()),
            _ => None,
        }
    }

    fn move_prev(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    fn move_next(&mut self) {
        self.cursor = (self.cursor + 1).min(FIELDS.len().saturating_sub(1));
    }

    fn selected_field(&self) -> GoalSettingsField {
        FIELDS[self.cursor]
    }

    fn cycle_selected(&mut self) {
        match self.selected_field() {
            GoalSettingsField::Enabled => {
                self.draft.enabled = match self.draft.enabled {
                    None => Some(true),
                    Some(true) => Some(false),
                    Some(false) => None,
                };
            }
            GoalSettingsField::SkepticCount => {
                self.draft.skeptic_count = Some(self.draft.skeptic_count.unwrap_or(1));
            }
            GoalSettingsField::SkepticModel => {}
            GoalSettingsField::MaxRounds => {
                self.draft.max_rounds = Some(self.draft.max_rounds.unwrap_or(1));
            }
        }
        self.status = None;
    }

    fn bump_selected(&mut self, delta: i32) {
        match self.selected_field() {
            GoalSettingsField::SkepticCount => {
                self.draft.skeptic_count =
                    Some(adjust_positive_usize(self.draft.skeptic_count, delta));
            }
            GoalSettingsField::MaxRounds => {
                self.draft.max_rounds = Some(adjust_positive_u32(self.draft.max_rounds, delta));
            }
            _ => {}
        }
        self.status = None;
    }

    fn start_confirm(&mut self, target: GoalSettingsSaveTarget) {
        self.confirm = Some(target);
        let target_label = match target {
            GoalSettingsSaveTarget::Session => "this session",
            GoalSettingsSaveTarget::Agent => "this agent",
        };
        self.status = Some(format!(
            "confirm save for {target_label}: enter/y apply, esc cancel"
        ));
    }

    fn confirmed_save(&mut self) -> GoalSettingsOutcome {
        if !self.root_foreground {
            self.confirm = None;
            self.status = Some(
                "Goal settings changes were refused because an interactive subagent holds the foreground."
                    .to_string(),
            );
            return GoalSettingsOutcome::Close;
        }
        let target = self
            .confirm
            .take()
            .unwrap_or(GoalSettingsSaveTarget::Session);
        match self.build_save(target) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.status = Some(error.to_string());
                GoalSettingsOutcome::Close
            }
        }
    }

    fn build_save(&mut self, target: GoalSettingsSaveTarget) -> Result<GoalSettingsOutcome> {
        let override_ = self.draft.to_override();
        override_.validate()?;
        let override_json = if override_.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&override_)?)
        };
        if target == GoalSettingsSaveTarget::Agent {
            let mut def = self.def.clone();
            def.goal_verification = override_;
            cockpit_core::agents::validate_invariants(&def)?;
            self.write_agent_def(&def)?;
            self.def = def;
        }
        Ok(GoalSettingsOutcome::Apply {
            override_json,
            persist_session: target == GoalSettingsSaveTarget::Session,
        })
    }

    fn write_agent_def(&self, def: &AgentDef) -> Result<()> {
        let path = agent_edit_path(&self.cwd, &self.agent_name)?;
        let markdown = def.to_markdown()?;
        std::fs::write(&path, markdown).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub(crate) fn render(&mut self, frame: &mut Frame, area: Rect) {
        let items = self
            .lines()
            .into_iter()
            .map(ListItem::new)
            .collect::<Vec<_>>();
        let mut state = ListState::default();
        state.select(Some(self.cursor + 3));
        frame.render_stateful_widget(List::new(items).scroll_padding(1), area, &mut state);
    }

    #[cfg(test)]
    fn field_labels(&self) -> Vec<&'static str> {
        FIELDS.iter().map(|field| field.label()).collect()
    }

    #[cfg(test)]
    fn status_text(&self) -> Option<&str> {
        self.status.as_deref()
    }

    fn lines(&self) -> Vec<Line<'static>> {
        let mut lines = vec![
            Line::from(format!("Goal settings - {}", self.agent_name)),
            Line::from("s save session | a save agent | i inherit | +/- adjust | q close"),
            Line::from(""),
        ];
        for field in FIELDS {
            lines.push(Line::from(format!(
                "{:<16} {}",
                field.label(),
                self.value_label(*field)
            )));
        }
        if let Some(status) = &self.status {
            lines.push(Line::from(""));
            lines.push(Line::from(status.clone()));
        }
        lines
    }

    fn value_label(&self, field: GoalSettingsField) -> String {
        match field {
            GoalSettingsField::Enabled => match self.draft.enabled {
                None => "inherit".to_string(),
                Some(true) => "force on".to_string(),
                Some(false) => "force off".to_string(),
            },
            GoalSettingsField::SkepticCount => self
                .draft
                .skeptic_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "inherit".to_string()),
            GoalSettingsField::SkepticModel => self
                .draft
                .skeptic_model
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("inherit")
                .to_string(),
            GoalSettingsField::MaxRounds => self
                .draft
                .max_rounds
                .map(|value| value.to_string())
                .unwrap_or_else(|| "inherit".to_string()),
        }
    }
}

impl GoalSettingsField {
    fn label(self) -> &'static str {
        match self {
            GoalSettingsField::Enabled => "enabled",
            GoalSettingsField::SkepticCount => "skeptic count",
            GoalSettingsField::SkepticModel => "skeptic model",
            GoalSettingsField::MaxRounds => "max rounds",
        }
    }
}

fn adjust_positive_usize(current: Option<usize>, delta: i32) -> usize {
    adjust_positive(current.unwrap_or(1) as i64, delta) as usize
}

fn adjust_positive_u32(current: Option<u32>, delta: i32) -> u32 {
    adjust_positive(i64::from(current.unwrap_or(1)), delta) as u32
}

fn adjust_positive(current: i64, delta: i32) -> i64 {
    (current + i64::from(delta)).max(1)
}

fn agent_edit_path(cwd: &Path, name: &str) -> Result<PathBuf> {
    if cockpit_core::agents::is_builtin_agent(name) {
        let config_dir = cwd.join(".cockpit");
        let (path, _newly) = cockpit_core::agents::eject_builtin(cwd, &config_dir, name)?;
        Ok(path)
    } else {
        cockpit_core::agents::find_override(cwd, name)
            .ok_or_else(|| anyhow::anyhow!("custom agent `{name}` has no on-disk file"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn focus_field(pane: &mut GoalSettingsPane, field: GoalSettingsField) {
        pane.cursor = FIELDS
            .iter()
            .position(|candidate| *candidate == field)
            .unwrap();
    }

    #[test]
    fn goal_settings_dialog_fields_and_inherit() {
        let tmp = tempfile::tempdir().unwrap();
        let pane = GoalSettingsPane::open(tmp.path(), "Build", true).unwrap();

        assert_eq!(
            pane.field_labels(),
            vec!["enabled", "skeptic count", "skeptic model", "max rounds"]
        );
        assert!(pane.draft.to_override().is_empty());
    }

    #[test]
    fn goal_settings_agent_save_writes_disk_and_ejects_pristine_builtin() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pane = GoalSettingsPane::open(tmp.path(), "Build", true).unwrap();
        focus_field(&mut pane, GoalSettingsField::Enabled);
        pane.handle_key(KeyEvent::from(KeyCode::Char('t')));
        pane.start_confirm(GoalSettingsSaveTarget::Agent);

        let outcome = pane.confirmed_save();

        assert!(matches!(
            outcome,
            GoalSettingsOutcome::Apply {
                persist_session: false,
                ..
            }
        ));
        let path = tmp.path().join(".cockpit").join("agents").join("Build.md");
        assert!(path.exists(), "agent save must eject pristine built-in");
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("goalVerification:"));
        assert!(text.contains("enabled: true"));
    }

    #[test]
    fn goal_settings_requires_confirm_before_save() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pane = GoalSettingsPane::open(tmp.path(), "Build", true).unwrap();

        assert_eq!(
            pane.handle_key(KeyEvent::from(KeyCode::Char('s'))),
            None,
            "first save key only starts confirmation"
        );
        assert!(pane.confirm.is_some());
        assert!(matches!(
            pane.handle_key(KeyEvent::from(KeyCode::Enter)),
            Some(GoalSettingsOutcome::Apply { .. })
        ));
    }

    #[test]
    fn goal_settings_dialog_shows_no_cache_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pane = GoalSettingsPane::open(tmp.path(), "Build", true).unwrap();
        pane.start_confirm(GoalSettingsSaveTarget::Session);

        let status = pane.status_text().unwrap();
        assert!(!status.contains("cache"));
        assert!(!status.contains("prompt"));
    }
}
