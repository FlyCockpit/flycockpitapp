use std::path::{Path, PathBuf};

use anyhow::Result;
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
    SkepticCount,
    SkepticModel,
    MaxRounds,
}

const FIELDS: &[GoalSettingsField] = &[
    GoalSettingsField::SkepticCount,
    GoalSettingsField::SkepticModel,
    GoalSettingsField::MaxRounds,
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct GoalSettingsDraft {
    cold_skeptic_count: Option<usize>,
    cold_skeptic_model: Option<String>,
    max_verification_attempts: Option<u32>,
}

impl GoalSettingsDraft {
    fn from_json(raw: Option<&str>) -> Result<Self> {
        let value = raw
            .map(serde_json::from_str::<serde_json::Value>)
            .transpose()?
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        Ok(Self {
            cold_skeptic_count: value
                .get("coldSkepticCount")
                .and_then(serde_json::Value::as_u64)
                .map(|value| value as usize),
            cold_skeptic_model: value
                .get("coldSkepticModel")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            max_verification_attempts: value
                .get("maxVerificationAttempts")
                .and_then(serde_json::Value::as_u64)
                .map(|value| value as u32),
        })
    }

    fn to_json(&self) -> Result<Option<String>> {
        if self
            .cold_skeptic_count
            .is_some_and(|value| !(1..=5).contains(&value))
        {
            anyhow::bail!("skeptic count must be between 1 and 5");
        }
        if self.max_verification_attempts == Some(0) {
            anyhow::bail!("max rounds must be at least 1");
        }
        let mut object = serde_json::Map::new();
        if let Some(value) = self.cold_skeptic_count {
            object.insert("coldSkepticCount".into(), value.into());
        }
        if let Some(value) = self
            .cold_skeptic_model
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let valid = value
                .split_once('/')
                .is_some_and(|(provider, model)| !provider.is_empty() && !model.is_empty());
            if !valid {
                anyhow::bail!("skeptic model must use provider/model form");
            }
            object.insert("coldSkepticModel".into(), value.into());
        }
        if let Some(value) = self.max_verification_attempts {
            object.insert("maxVerificationAttempts".into(), value.into());
        }
        if object.is_empty() {
            Ok(None)
        } else {
            Ok(Some(serde_json::to_string(&object)?))
        }
    }

    fn clear(&mut self, field: GoalSettingsField) {
        match field {
            GoalSettingsField::SkepticCount => self.cold_skeptic_count = None,
            GoalSettingsField::SkepticModel => self.cold_skeptic_model = None,
            GoalSettingsField::MaxRounds => self.max_verification_attempts = None,
        }
    }
}

pub(crate) struct GoalSettingsPane {
    agent_name: String,
    cwd: PathBuf,
    root_foreground: bool,
    revision: String,
    supports_agent_save: bool,
    draft: GoalSettingsDraft,
    cursor: usize,
    status: Option<String>,
    confirm: Option<GoalSettingsSaveTarget>,
}

impl GoalSettingsPane {
    pub(crate) fn open(cwd: &Path, agent_name: &str, root_foreground: bool) -> Result<Self> {
        let response = crate::tui::agent_runner::daemon_request_blocking(
            cockpit_core::daemon::proto::Request::GetAgentEditSnapshot {
                project_root: cwd.to_string_lossy().into_owned(),
                name: agent_name.to_string(),
            },
        )
        .map_err(anyhow::Error::msg)?;
        let cockpit_core::daemon::proto::Response::AgentEditSnapshot(snapshot) = response else {
            anyhow::bail!("daemon returned an unexpected agent snapshot");
        };
        let draft = GoalSettingsDraft::from_json(snapshot.goal_supervision_json.as_deref())?;
        let status = (!root_foreground).then(|| {
            "Apply is disabled while an interactive subagent holds the foreground.".to_string()
        });
        Ok(Self {
            agent_name: agent_name.to_string(),
            cwd: cwd.to_path_buf(),
            root_foreground,
            revision: snapshot.revision,
            supports_agent_save: snapshot.supports_goal_supervision,
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
                    && let Some(model) = &mut self.draft.cold_skeptic_model
                {
                    model.pop();
                    if model.trim().is_empty() {
                        self.draft.cold_skeptic_model = None;
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
                let model = self
                    .draft
                    .cold_skeptic_model
                    .get_or_insert_with(String::new);
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
            GoalSettingsField::SkepticCount => {
                self.draft.cold_skeptic_count = Some(self.draft.cold_skeptic_count.unwrap_or(1));
            }
            GoalSettingsField::SkepticModel => {}
            GoalSettingsField::MaxRounds => {
                self.draft.max_verification_attempts =
                    Some(self.draft.max_verification_attempts.unwrap_or(1));
            }
        }
        self.status = None;
    }

    fn bump_selected(&mut self, delta: i32) {
        match self.selected_field() {
            GoalSettingsField::SkepticCount => {
                self.draft.cold_skeptic_count =
                    Some(adjust_positive_usize(self.draft.cold_skeptic_count, delta));
            }
            GoalSettingsField::MaxRounds => {
                self.draft.max_verification_attempts = Some(adjust_positive_u32(
                    self.draft.max_verification_attempts,
                    delta,
                ));
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
        let override_json = self.draft.to_json()?;
        if target == GoalSettingsSaveTarget::Agent {
            // vNext documents deliberately reject `goalSupervision` as a
            // retired legacy field.  Do not report a successful agent save
            // when canonical vNext serialization would omit the override.
            if !self.supports_agent_save {
                anyhow::bail!(
                    "agent-scoped goal settings are unavailable for vNext agents; save them for this session instead"
                );
            }
            let response = crate::tui::agent_runner::daemon_request_blocking(
                cockpit_core::daemon::proto::Request::MutateAgent {
                    project_root: self.cwd.to_string_lossy().into_owned(),
                    mutation: cockpit_core::daemon::proto::AgentMutation::SaveGoalSupervision {
                        name: self.agent_name.clone(),
                        goal_supervision_json: override_json.clone(),
                    },
                    expected_revision: Some(self.revision.clone()),
                },
            )
            .map_err(anyhow::Error::msg)?;
            let cockpit_core::daemon::proto::Response::AgentMutated(result) = response else {
                anyhow::bail!("daemon returned an unexpected goal-settings response");
            };
            if let Some(snapshot) = result.snapshot {
                self.revision = snapshot.revision;
            }
        }
        Ok(GoalSettingsOutcome::Apply {
            override_json,
            persist_session: target == GoalSettingsSaveTarget::Session,
        })
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
            GoalSettingsField::SkepticCount => self
                .draft
                .cold_skeptic_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "inherit".to_string()),
            GoalSettingsField::SkepticModel => self
                .draft
                .cold_skeptic_model
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("inherit")
                .to_string(),
            GoalSettingsField::MaxRounds => self
                .draft
                .max_verification_attempts
                .map(|value| value.to_string())
                .unwrap_or_else(|| "inherit".to_string()),
        }
    }
}

impl GoalSettingsField {
    fn label(self) -> &'static str {
        match self {
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
            vec!["skeptic count", "skeptic model", "max rounds"]
        );
        assert!(pane.draft.to_json().unwrap().is_none());
    }

    #[test]
    fn goal_settings_agent_save_refuses_vnext_builtin_without_ejecting() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pane = GoalSettingsPane::open(tmp.path(), "Build", true).unwrap();
        focus_field(&mut pane, GoalSettingsField::SkepticCount);
        pane.handle_key(KeyEvent::from(KeyCode::Char('t')));
        pane.start_confirm(GoalSettingsSaveTarget::Agent);

        let outcome = pane.confirmed_save();

        assert_eq!(outcome, GoalSettingsOutcome::Close);
        assert!(
            pane.status_text()
                .is_some_and(|status| status.contains("unavailable for vNext agents")),
            "vNext agent save must explain why it was refused: {:?}",
            pane.status_text()
        );
        let path = tmp.path().join(".cockpit").join("agents").join("Build.md");
        assert!(
            !path.exists(),
            "refused vNext agent save must not eject a pristine built-in"
        );
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
