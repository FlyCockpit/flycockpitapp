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
    /// A daemon-owned mutation has been queued. The pane remains open and
    /// will emit `Apply` only after the correlated receipt is validated.
    Pending,
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
    original: serde_json::Map<String, serde_json::Value>,
}

impl Default for GoalSettingsDraft {
    fn default() -> Self {
        Self {
            cold_skeptic_count: None,
            cold_skeptic_model: None,
            max_verification_attempts: None,
            original: serde_json::Map::new(),
        }
    }
}

impl GoalSettingsDraft {
    fn from_json(raw: Option<&str>) -> Result<Self> {
        let value = raw
            .map(serde_json::from_str::<serde_json::Value>)
            .transpose()?
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        let object = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("goal supervision snapshot must be an object"))?;
        let checked_u64 = |key: &str| -> Result<Option<u64>> {
            object
                .get(key)
                .map(|value| {
                    value.as_u64().ok_or_else(|| {
                        anyhow::anyhow!("goal supervision `{key}` must be an unsigned integer")
                    })
                })
                .transpose()
        };
        let cold_skeptic_count = checked_u64("coldSkepticCount")?
            .map(usize::try_from)
            .transpose()
            .map_err(|_| anyhow::anyhow!("coldSkepticCount is outside this platform's range"))?;
        if cold_skeptic_count.is_some_and(|value| !(1..=5).contains(&value)) {
            anyhow::bail!("coldSkepticCount must be between 1 and 5");
        }
        let max_verification_attempts = checked_u64("maxVerificationAttempts")?
            .map(u32::try_from)
            .transpose()
            .map_err(|_| anyhow::anyhow!("maxVerificationAttempts is outside the u32 range"))?;
        if max_verification_attempts == Some(0) {
            anyhow::bail!("maxVerificationAttempts must be at least 1");
        }
        let cold_skeptic_model = object
            .get("coldSkepticModel")
            .map(|value| {
                let model = value.as_str().ok_or_else(|| {
                    anyhow::anyhow!("goal supervision `coldSkepticModel` must be a string")
                })?;
                validate_model_reference(model)?;
                Ok::<_, anyhow::Error>(model.to_string())
            })
            .transpose()?;
        for key in ["plannerModel", "evaluatorModel", "gatekeeperModel"] {
            if let Some(value) = object.get(key) {
                let model = value
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("goal supervision `{key}` must be a string"))?;
                validate_model_reference(model)?;
            }
        }
        if let Some(value) = object.get("defaultTokenBudget") {
            if value.as_i64().is_none_or(|value| value <= 0) {
                anyhow::bail!(
                    "goal supervision `defaultTokenBudget` must be a positive signed integer"
                );
            }
        }
        Ok(Self {
            cold_skeptic_count,
            cold_skeptic_model,
            max_verification_attempts,
            original: object.clone(),
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
        let mut object = self.original.clone();
        if let Some(value) = self.cold_skeptic_count {
            object.insert("coldSkepticCount".into(), value.into());
        } else {
            object.remove("coldSkepticCount");
        }
        if let Some(value) = self
            .cold_skeptic_model
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            validate_model_reference(value)?;
            object.insert("coldSkepticModel".into(), value.into());
        } else {
            object.remove("coldSkepticModel");
        }
        if let Some(value) = self.max_verification_attempts {
            object.insert("maxVerificationAttempts".into(), value.into());
        } else {
            object.remove("maxVerificationAttempts");
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

fn validate_model_reference(value: &str) -> Result<()> {
    let valid = value.split_once('/').is_some_and(|(provider, model)| {
        !provider.is_empty()
            && !model.is_empty()
            && !provider.chars().any(char::is_whitespace)
            && !model.chars().any(char::is_whitespace)
    });
    if !valid {
        anyhow::bail!("model references must use non-empty provider/model form");
    }
    Ok(())
}

pub(crate) struct GoalSettingsPane {
    agent_name: String,
    cwd: PathBuf,
    root_foreground: bool,
    revision: Option<String>,
    supports_agent_save: bool,
    draft: GoalSettingsDraft,
    cursor: usize,
    status: Option<String>,
    confirm: Option<GoalSettingsSaveTarget>,
    pending_effect: Option<GoalSettingsEffect>,
    in_flight: Option<GoalSettingsPending>,
}

#[derive(Debug)]
pub(crate) struct GoalSettingsEffect {
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) agent_name: String,
    pub(crate) project_root: String,
    pub(crate) expected_revision: Option<String>,
    pub(crate) request: cockpit_core::daemon::proto::Request,
}

#[derive(Debug)]
enum GoalSettingsPending {
    Load {
        operation_id: uuid::Uuid,
        agent_name: String,
        project_root: String,
    },
    SaveAgent {
        operation_id: uuid::Uuid,
        agent_name: String,
        project_root: String,
        expected_revision: String,
        mutation: cockpit_core::daemon::proto::AgentMutation,
        patch: cockpit_core::daemon::proto::GoalSupervisionPatch,
        prior_goal_json: Option<String>,
        override_json: Option<String>,
    },
}

#[derive(Debug)]
pub(crate) struct GoalSettingsCompletion {
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) agent_name: String,
    pub(crate) project_root: String,
    pub(crate) expected_revision: Option<String>,
    pub(crate) response: Result<cockpit_core::daemon::proto::Response, String>,
}

impl GoalSettingsPane {
    pub(crate) fn open(cwd: &Path, agent_name: &str, root_foreground: bool) -> Result<Self> {
        let operation_id = uuid::Uuid::new_v4();
        let project_root = cwd.to_string_lossy().into_owned();
        let request = cockpit_core::daemon::proto::Request::GetAgentEditSnapshot {
            project_root: project_root.clone(),
            name: agent_name.to_string(),
        };
        let status = (!root_foreground)
            .then(|| {
                "Apply is disabled while an interactive subagent holds the foreground.".to_string()
            })
            .or_else(|| Some("loading daemon-owned goal settings…".to_string()));
        Ok(Self {
            agent_name: agent_name.to_string(),
            cwd: cwd.to_path_buf(),
            root_foreground,
            revision: None,
            supports_agent_save: false,
            draft: GoalSettingsDraft::default(),
            cursor: 0,
            status,
            confirm: None,
            pending_effect: Some(GoalSettingsEffect {
                operation_id,
                agent_name: agent_name.to_string(),
                project_root: project_root.clone(),
                expected_revision: None,
                request,
            }),
            in_flight: Some(GoalSettingsPending::Load {
                operation_id,
                agent_name: agent_name.to_string(),
                project_root,
            }),
        })
    }

    pub(crate) fn take_effect(&mut self) -> Option<GoalSettingsEffect> {
        self.pending_effect.take()
    }

    /// Apply a host-delivered daemon result only when it belongs to the exact
    /// operation and authority snapshot still owned by this pane. Duplicate,
    /// late, and out-of-order completions are presentation no-ops.
    pub(crate) fn apply_completion(
        &mut self,
        completion: GoalSettingsCompletion,
    ) -> Option<GoalSettingsOutcome> {
        let Some(pending) = self.in_flight.take() else {
            return None;
        };
        let pending_id = match &pending {
            GoalSettingsPending::Load { operation_id, .. }
            | GoalSettingsPending::SaveAgent { operation_id, .. } => *operation_id,
        };
        let (pending_agent, pending_root, pending_revision) = match &pending {
            GoalSettingsPending::Load {
                agent_name,
                project_root,
                ..
            } => (agent_name.as_str(), project_root.as_str(), None),
            GoalSettingsPending::SaveAgent {
                agent_name,
                project_root,
                expected_revision,
                ..
            } => (
                agent_name.as_str(),
                project_root.as_str(),
                Some(expected_revision.as_str()),
            ),
        };
        if completion.operation_id != pending_id
            || completion.agent_name != pending_agent
            || completion.project_root != pending_root
            || completion.expected_revision.as_deref() != pending_revision
        {
            self.in_flight = Some(pending);
            return None;
        }
        match pending {
            GoalSettingsPending::Load {
                agent_name,
                project_root,
                ..
            } => {
                if self.agent_name != agent_name
                    || self.cwd.to_string_lossy().as_ref() != project_root
                {
                    return None;
                }
                let loaded = completion.response.and_then(|response| {
                    let cockpit_core::daemon::proto::Response::AgentEditSnapshot(snapshot) =
                        response
                    else {
                        return Err("daemon returned an unexpected agent snapshot".to_string());
                    };
                    super::settings::agents_page::validate_agent_snapshot(
                        &snapshot,
                        &self.cwd,
                        &self.agent_name,
                        None,
                    )?;
                    let draft =
                        GoalSettingsDraft::from_json(snapshot.goal_supervision_json.as_deref())
                            .map_err(|error| error.to_string())?;
                    Ok((snapshot, draft))
                });
                match loaded {
                    Ok((snapshot, draft)) => {
                        self.revision = Some(snapshot.revision);
                        self.supports_agent_save = snapshot.supports_goal_supervision;
                        self.draft = draft;
                        self.status = (!self.root_foreground).then(|| {
                            "Apply is disabled while an interactive subagent holds the foreground."
                                .to_string()
                        });
                    }
                    Err(error) => self.status = Some(format!("load failed: {error}")),
                }
                None
            }
            GoalSettingsPending::SaveAgent {
                agent_name,
                project_root,
                expected_revision,
                mutation,
                patch,
                prior_goal_json,
                override_json,
                ..
            } => {
                if self.agent_name != agent_name
                    || self.cwd.to_string_lossy().as_ref() != project_root
                    || self.revision.as_deref() != Some(expected_revision.as_str())
                {
                    return None;
                }
                let saved = completion.response.and_then(|response| {
                    let cockpit_core::daemon::proto::Response::AgentMutated(result) = response
                    else {
                        return Err("daemon returned an unexpected goal-settings response".into());
                    };
                    super::settings::agents_page::validate_agent_mutation_result(
                        &result,
                        &self.cwd,
                        &mutation,
                        Some(&expected_revision),
                        None,
                    )?;
                    let snapshot = result
                        .snapshot
                        .ok_or_else(|| "daemon omitted the goal-settings snapshot".to_string())?;
                    cockpit_proto::validate_goal_supervision_projection(
                        prior_goal_json.as_deref(),
                        &patch,
                        snapshot.goal_supervision_json.as_deref(),
                    )?;
                    let original = snapshot
                        .goal_supervision_json
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()
                        .map_err(|error| error.to_string())?
                        .unwrap_or_default();
                    Ok((snapshot.revision, original))
                });
                match saved {
                    Ok((revision, original)) => {
                        self.revision = Some(revision);
                        self.draft.original = original;
                        self.status = Some("agent goal settings committed".to_string());
                        Some(GoalSettingsOutcome::Apply {
                            override_json,
                            persist_session: false,
                        })
                    }
                    Err(error) => {
                        self.status = Some(format!("save failed: {error}"));
                        None
                    }
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn agent_name(&self) -> &str {
        &self.agent_name
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<GoalSettingsOutcome> {
        if self.in_flight.is_some() {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                return Some(GoalSettingsOutcome::Close);
            }
            self.status = Some("goal settings operation is still pending".to_string());
            return None;
        }
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
            KeyCode::Enter | KeyCode::Char('y') => self.confirmed_save(),
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

    fn confirmed_save(&mut self) -> Option<GoalSettingsOutcome> {
        if !self.root_foreground {
            self.confirm = None;
            self.status = Some(
                "Goal settings changes were refused because an interactive subagent holds the foreground."
                    .to_string(),
            );
            return None;
        }
        let target = self
            .confirm
            .take()
            .unwrap_or(GoalSettingsSaveTarget::Session);
        match self.build_save(target) {
            Ok(outcome) => Some(outcome),
            Err(error) => {
                self.status = Some(error.to_string());
                // Keep the pane and draft open so a conflict can be
                // reconciled or retried instead of discarding user input.
                None
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
            let prior_goal_json = if self.draft.original.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&self.draft.original)?)
            };
            let goal_patch = cockpit_core::daemon::proto::GoalSupervisionPatch {
                cold_skeptic_count: Some(self.draft.cold_skeptic_count),
                cold_skeptic_model: Some(
                    self.draft
                        .cold_skeptic_model
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string),
                ),
                max_verification_attempts: Some(self.draft.max_verification_attempts),
            };
            let mutation = cockpit_core::daemon::proto::AgentMutation::SaveGoalSupervision {
                name: self.agent_name.clone(),
                patch: goal_patch.clone(),
            };
            let expected_revision = self.revision.clone().ok_or_else(|| {
                anyhow::anyhow!("goal settings have no daemon-owned revision; reload first")
            })?;
            let operation_id = uuid::Uuid::new_v4();
            let project_root = self.cwd.to_string_lossy().into_owned();
            self.pending_effect = Some(GoalSettingsEffect {
                operation_id,
                agent_name: self.agent_name.clone(),
                project_root: project_root.clone(),
                expected_revision: Some(expected_revision.clone()),
                request: cockpit_core::daemon::proto::Request::MutateAgent {
                    project_root: project_root.clone(),
                    mutation: mutation.clone(),
                    expected_revision: Some(expected_revision.clone()),
                },
            });
            self.in_flight = Some(GoalSettingsPending::SaveAgent {
                operation_id,
                agent_name: self.agent_name.clone(),
                project_root,
                expected_revision,
                mutation,
                patch: goal_patch,
                prior_goal_json,
                override_json,
            });
            self.status = Some("saving agent goal settings…".to_string());
            return Ok(GoalSettingsOutcome::Pending);
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
    fn loaded_pane(cwd: &Path, supports_agent_save: bool) -> GoalSettingsPane {
        let mut pane = GoalSettingsPane::open(cwd, "Build", true).unwrap();
        pane.pending_effect = None;
        pane.in_flight = None;
        pane.revision = Some("test-revision".to_string());
        pane.supports_agent_save = supports_agent_save;
        pane.status = None;
        pane
    }

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
        let mut pane = loaded_pane(tmp.path(), false);
        focus_field(&mut pane, GoalSettingsField::SkepticCount);
        pane.handle_key(KeyEvent::from(KeyCode::Char('t')));
        pane.start_confirm(GoalSettingsSaveTarget::Agent);

        let outcome = pane.confirmed_save();

        assert_eq!(outcome, None);
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
        let mut pane = loaded_pane(tmp.path(), false);

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
        let mut pane = loaded_pane(tmp.path(), false);
        pane.start_confirm(GoalSettingsSaveTarget::Session);

        let status = pane.status_text().unwrap();
        assert!(!status.contains("cache"));
        assert!(!status.contains("prompt"));
    }

    #[test]
    fn goal_settings_load_is_a_correlated_effect_and_stale_completion_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pane = GoalSettingsPane::open(tmp.path(), "Build", true).unwrap();
        let effect = pane.take_effect().expect("load effect");
        assert_eq!(effect.agent_name, "Build");
        assert_eq!(effect.project_root, tmp.path().to_string_lossy());
        assert!(effect.expected_revision.is_none());

        let stale = GoalSettingsCompletion {
            operation_id: uuid::Uuid::new_v4(),
            agent_name: effect.agent_name,
            project_root: effect.project_root,
            expected_revision: None,
            response: Err("must not be applied".to_string()),
        };
        assert!(pane.apply_completion(stale).is_none());
        assert!(
            pane.in_flight.is_some(),
            "stale result must not settle load"
        );
    }

    #[test]
    fn agent_save_stages_once_and_keeps_exact_revision_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pane = loaded_pane(tmp.path(), true);
        pane.start_confirm(GoalSettingsSaveTarget::Agent);
        assert_eq!(pane.confirmed_save(), Some(GoalSettingsOutcome::Pending));
        let effect = pane.take_effect().expect("save effect");
        assert_eq!(effect.expected_revision.as_deref(), Some("test-revision"));
        assert!(
            pane.take_effect().is_none(),
            "duplicate submission was staged"
        );
        assert_eq!(
            pane.handle_key(KeyEvent::from(KeyCode::Enter)),
            None,
            "pending operation must keep the reducer responsive without resubmitting"
        );
    }
}
