use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::tui::tool_surface_picker::{
    ToolSurfaceDraft, ToolSurfaceEditOutcome, ToolSurfacePicker, ToolSurfaceRender,
    tool_surface_lines,
};
use anyhow::Result;
use cockpit_core::agents::{AgentDef, ToolSurfaceSelection, ToolTier};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{List, ListItem};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolsSaveTarget {
    Session,
    Agent,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ToolsOutcome {
    Close,
    Pending,
    Apply {
        override_json: String,
        persist_session: bool,
        cache_break: bool,
        monty_nudge: Option<String>,
    },
}

pub(crate) struct ToolsPane {
    agent_name: String,
    cwd: PathBuf,
    root_foreground: bool,
    original: ToolSurfaceSelection,
    def: Option<AgentDef>,
    revision: Option<String>,
    editable: bool,
    draft: ToolSurfaceDraft,
    picker: ToolSurfacePicker,
    status: Option<String>,
    row_errors: BTreeMap<String, String>,
    confirm: Option<ToolsSaveTarget>,
    nudge_monty: bool,
    pending_effect: Option<ToolsEffect>,
    in_flight: Option<ToolsPending>,
}

#[derive(Debug)]
pub(crate) struct ToolsEffect {
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) agent_name: String,
    pub(crate) project_root: String,
    pub(crate) expected_revision: Option<String>,
    pub(crate) request: cockpit_proto::Request,
}

#[derive(Debug)]
enum ToolsPending {
    Load {
        operation_id: uuid::Uuid,
        agent_name: String,
        project_root: String,
    },
    SaveAgent {
        operation_id: uuid::Uuid,
        client_operation_id: String,
        mutation_intent_hash: String,
        agent_name: String,
        project_root: String,
        expected_revision: String,
        mutation: cockpit_proto::AgentMutation,
        def: AgentDef,
        selection: ToolSurfaceSelection,
        override_json: String,
        cache_break: bool,
        monty_nudge: Option<String>,
        querying: bool,
    },
}

enum ToolsMutationResolution {
    Committed {
        revision: String,
        warning: Option<String>,
    },
    Pending,
    Rejected(String),
    Invalid(String),
}

#[derive(Debug)]
pub(crate) struct ToolsCompletion {
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) agent_name: String,
    pub(crate) project_root: String,
    pub(crate) expected_revision: Option<String>,
    pub(crate) response: Result<cockpit_proto::Response, String>,
}

impl ToolsPane {
    /// A save owns durable agent authority until its exact receipt is known.
    /// The initial snapshot load is deliberately excluded: it is read-only.
    pub(crate) fn has_unsettled_local_authority(&self) -> bool {
        matches!(self.in_flight, Some(ToolsPending::SaveAgent { .. }))
    }

    pub(crate) fn open(cwd: &Path, agent_name: &str, root_foreground: bool) -> Result<Self> {
        let operation_id = uuid::Uuid::new_v4();
        let project_root = cwd.to_string_lossy().into_owned();
        let request = cockpit_proto::Request::GetAgentEditSnapshot {
            project_root: project_root.clone(),
            name: agent_name.to_string(),
        };
        let draft = ToolSurfaceDraft::empty();
        let original = draft.selection().clone();
        let status = (!root_foreground)
            .then(|| {
                "Apply is disabled while an interactive subagent holds the foreground.".to_string()
            })
            .or_else(|| Some("loading daemon-owned tool settings…".to_string()));
        Ok(Self {
            agent_name: agent_name.to_string(),
            cwd: cwd.to_path_buf(),
            root_foreground,
            original,
            def: None,
            revision: None,
            editable: false,
            draft,
            picker: ToolSurfacePicker::default(),
            status,
            row_errors: BTreeMap::new(),
            confirm: None,
            nudge_monty: true,
            pending_effect: Some(ToolsEffect {
                operation_id,
                agent_name: agent_name.to_string(),
                project_root: project_root.clone(),
                expected_revision: None,
                request,
            }),
            in_flight: Some(ToolsPending::Load {
                operation_id,
                agent_name: agent_name.to_string(),
                project_root,
            }),
        })
    }

    pub(crate) fn take_effect(&mut self) -> Option<ToolsEffect> {
        self.pending_effect.take()
    }

    #[allow(clippy::too_many_arguments)]
    fn requeue_settlement(
        &mut self,
        operation_id: uuid::Uuid,
        client_operation_id: String,
        mutation_intent_hash: String,
        agent_name: String,
        project_root: String,
        expected_revision: String,
        mutation: cockpit_proto::AgentMutation,
        def: AgentDef,
        selection: ToolSurfaceSelection,
        override_json: String,
        cache_break: bool,
        monty_nudge: Option<String>,
        schedule_query: bool,
        message: String,
    ) {
        let operation_id = if schedule_query {
            uuid::Uuid::new_v4()
        } else {
            operation_id
        };
        if schedule_query {
            self.pending_effect = Some(ToolsEffect {
                operation_id,
                agent_name: agent_name.clone(),
                project_root: project_root.clone(),
                expected_revision: Some(expected_revision.clone()),
                request: cockpit_proto::Request::GetLocalOperationSettlement {
                    client_operation_id: client_operation_id.clone(),
                },
            });
        }
        self.in_flight = Some(ToolsPending::SaveAgent {
            operation_id,
            client_operation_id,
            mutation_intent_hash,
            agent_name,
            project_root,
            expected_revision,
            mutation,
            def,
            selection,
            override_json,
            cache_break,
            monty_nudge,
            querying: true,
        });
        self.status = Some(format!("{message}; press Enter to query again"));
    }

    fn retry_settlement(&mut self) {
        let Some(ToolsPending::SaveAgent {
            client_operation_id,
            mutation_intent_hash,
            agent_name,
            project_root,
            expected_revision,
            mutation,
            def,
            selection,
            override_json,
            cache_break,
            monty_nudge,
            querying: _,
            ..
        }) = self.in_flight.take()
        else {
            return;
        };
        let operation_id = uuid::Uuid::new_v4();
        self.pending_effect = Some(ToolsEffect {
            operation_id,
            agent_name: agent_name.clone(),
            project_root: project_root.clone(),
            expected_revision: Some(expected_revision.clone()),
            request: cockpit_proto::Request::MutateAgent {
                client_operation_id: client_operation_id.clone(),
                mutation_intent_hash: mutation_intent_hash.clone(),
                project_root: project_root.clone(),
                mutation: mutation.clone(),
                expected_revision: Some(expected_revision.clone()),
            },
        });
        self.in_flight = Some(ToolsPending::SaveAgent {
            operation_id,
            client_operation_id,
            mutation_intent_hash,
            agent_name,
            project_root,
            expected_revision,
            mutation,
            def,
            selection,
            override_json,
            cache_break,
            monty_nudge,
            querying: false,
        });
        self.status = Some("retrying the exact durable agent-save mutation".into());
    }

    pub(crate) fn apply_completion(&mut self, completion: ToolsCompletion) -> Option<ToolsOutcome> {
        let Some(pending) = self.in_flight.take() else {
            return None;
        };
        let (operation_id, agent_name, project_root, expected_revision) = match &pending {
            ToolsPending::Load {
                operation_id,
                agent_name,
                project_root,
            } => (
                *operation_id,
                agent_name.as_str(),
                project_root.as_str(),
                None,
            ),
            ToolsPending::SaveAgent {
                operation_id,
                agent_name,
                project_root,
                expected_revision,
                ..
            } => (
                *operation_id,
                agent_name.as_str(),
                project_root.as_str(),
                Some(expected_revision.as_str()),
            ),
        };
        if completion.operation_id != operation_id
            || completion.agent_name != agent_name
            || completion.project_root != project_root
            || completion.expected_revision.as_deref() != expected_revision
        {
            self.in_flight = Some(pending);
            self.status = Some(
                "ignored an unbound tool-settings completion; press Enter to query the exact operation"
                    .into(),
            );
            return None;
        }
        match pending {
            ToolsPending::Load {
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
                    let cockpit_proto::Response::AgentEditSnapshot(snapshot) = response else {
                        return Err("daemon returned an unexpected agent snapshot".to_string());
                    };
                    crate::tui::settings::agents_page::validate_agent_snapshot(
                        &snapshot,
                        &self.cwd,
                        &self.agent_name,
                        None,
                    )?;
                    if snapshot.markdown.len() > cockpit_proto::MAX_AGENT_MARKDOWN_BYTES {
                        return Err("daemon returned an oversized agent snapshot".to_string());
                    }
                    let def = cockpit_core::agents::parse_agent(
                        &snapshot.markdown,
                        &self.agent_name,
                        PathBuf::from("<daemon-agent-snapshot>"),
                    )
                    .map_err(|error| error.to_string())?;
                    Ok((snapshot, def))
                });
                match loaded {
                    Ok((snapshot, def)) => {
                        let draft = ToolSurfaceDraft::from_def(&def);
                        self.original = draft.selection().clone();
                        self.draft = draft;
                        self.def = Some(def);
                        self.revision = Some(snapshot.revision);
                        self.editable = snapshot.editable;
                        self.status = (!self.root_foreground).then(|| {
                            "Apply is disabled while an interactive subagent holds the foreground.".to_string()
                        });
                    }
                    Err(error) => self.status = Some(format!("load failed: {error}")),
                }
                None
            }
            ToolsPending::SaveAgent {
                operation_id,
                client_operation_id,
                mutation_intent_hash,
                agent_name,
                project_root,
                expected_revision,
                mutation,
                def,
                selection,
                override_json,
                cache_break,
                monty_nudge,
                querying: _,
                ..
            } => {
                if self.agent_name != agent_name
                    || self.cwd.to_string_lossy().as_ref() != project_root
                    || self.revision.as_deref() != Some(expected_revision.as_str())
                {
                    return None;
                }
                let response = match completion.response {
                    Ok(response) => response,
                    Err(error) => {
                        self.requeue_settlement(
                            operation_id,
                            client_operation_id,
                            mutation_intent_hash,
                            agent_name,
                            project_root,
                            expected_revision,
                            mutation,
                            def,
                            selection,
                            override_json,
                            cache_break,
                            monty_nudge,
                            true,
                            format!("agent-save outcome is unknown ({error})"),
                        );
                        return None;
                    }
                };
                let saved = match crate::tui::settings::agents_page::bind_agent_mutation_settlement(
                    response,
                    &client_operation_id,
                    &mutation_intent_hash,
                ) {
                    Ok(crate::tui::settings::agents_page::AgentMutationSettlement::Committed(
                        result,
                    )) => (|| {
                        crate::tui::settings::agents_page::validate_agent_mutation_result(
                            &result,
                            &client_operation_id,
                            &mutation_intent_hash,
                            &self.cwd,
                            &mutation,
                            Some(&expected_revision),
                            None,
                        )?;
                        if let cockpit_proto::AgentMutationOutcome::CommittedRefreshNeeded {
                            warning,
                        } = result.outcome
                        {
                            return Ok(ToolsMutationResolution::Committed {
                                revision: result.result_revision,
                                warning: Some(warning),
                            });
                        }
                        let snapshot = result
                            .snapshot
                            .ok_or_else(|| "daemon omitted the saved snapshot".to_string())?;
                        Ok(ToolsMutationResolution::Committed {
                            revision: snapshot.revision,
                            warning: None,
                        })
                    })()
                    .unwrap_or_else(ToolsMutationResolution::Invalid),
                    Ok(crate::tui::settings::agents_page::AgentMutationSettlement::Pending) => {
                        ToolsMutationResolution::Pending
                    }
                    Ok(crate::tui::settings::agents_page::AgentMutationSettlement::Rejected(
                        error,
                    )) => ToolsMutationResolution::Rejected(error),
                    Err(error) => ToolsMutationResolution::Invalid(error),
                };
                match saved {
                    ToolsMutationResolution::Committed { revision, warning } => {
                        self.revision = Some(revision);
                        self.def = Some(def);
                        self.original = selection;
                        self.status = Some(match warning {
                            Some(warning) => format!(
                                "agent tool settings committed but refresh is required: {warning}"
                            ),
                            None => "agent tool settings committed".to_string(),
                        });
                        Some(ToolsOutcome::Apply {
                            override_json,
                            persist_session: false,
                            cache_break,
                            monty_nudge,
                        })
                    }
                    ToolsMutationResolution::Pending => {
                        self.requeue_settlement(
                            operation_id,
                            client_operation_id,
                            mutation_intent_hash,
                            agent_name,
                            project_root,
                            expected_revision,
                            mutation,
                            def,
                            selection,
                            override_json,
                            cache_break,
                            monty_nudge,
                            false,
                            "agent-save mutation is still pending".into(),
                        );
                        None
                    }
                    ToolsMutationResolution::Rejected(error) => {
                        self.status = Some(format!("save was durably rejected: {error}"));
                        None
                    }
                    ToolsMutationResolution::Invalid(error) => {
                        self.requeue_settlement(
                            operation_id,
                            client_operation_id,
                            mutation_intent_hash,
                            agent_name,
                            project_root,
                            expected_revision,
                            mutation,
                            def,
                            selection,
                            override_json,
                            cache_break,
                            monty_nudge,
                            false,
                            format!("agent-save receipt was malformed or unbound ({error})"),
                        );
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

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<ToolsOutcome> {
        if self.in_flight.is_some() {
            if key.code == KeyCode::Enter && self.pending_effect.is_none() {
                self.retry_settlement();
            } else {
                self.status = Some(
                    "tool settings operation is still pending; this pane cannot close yet"
                        .to_string(),
                );
            }
            return None;
        }
        if self.confirm.is_some() {
            return self.handle_confirm_key(key);
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => Some(ToolsOutcome::Close),
            KeyCode::Up | KeyCode::Char('k') => {
                self.picker.move_prev();
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.picker.move_next();
                None
            }
            KeyCode::Char(' ') => {
                match self.draft.toggle_selected_tool(&self.picker, true) {
                    ToolSurfaceEditOutcome::BlockedSafetyUngrant(tool) => {
                        self.status =
                            Some(format!("`{tool}` is required and cannot be ungranted here"));
                    }
                    ToolSurfaceEditOutcome::Ungranted(tool)
                    | ToolSurfaceEditOutcome::Granted(tool)
                    | ToolSurfaceEditOutcome::TierChanged { tool, .. } => {
                        self.row_errors.remove(&tool);
                        self.status = None;
                    }
                    ToolSurfaceEditOutcome::NoSelection => {}
                }
                None
            }
            KeyCode::Char('t') => {
                if let ToolSurfaceEditOutcome::TierChanged { tool, .. } =
                    self.draft.cycle_selected_tier(&self.picker)
                {
                    self.row_errors.remove(&tool);
                    self.status = None;
                }
                None
            }
            KeyCode::Char('s') => {
                self.start_confirm(ToolsSaveTarget::Session);
                None
            }
            KeyCode::Char('a') => {
                self.start_confirm(ToolsSaveTarget::Agent);
                None
            }
            _ => None,
        }
    }

    fn handle_confirm_key(&mut self, key: KeyEvent) -> Option<ToolsOutcome> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') => {
                self.confirm = None;
                self.status = Some("save cancelled".to_string());
                None
            }
            KeyCode::Char('m') => {
                if self.monty_delta() {
                    self.nudge_monty = !self.nudge_monty;
                    self.start_confirm(self.confirm.unwrap_or(ToolsSaveTarget::Session));
                }
                None
            }
            KeyCode::Enter | KeyCode::Char('y') => self.confirmed_save(),
            _ => None,
        }
    }

    fn start_confirm(&mut self, target: ToolsSaveTarget) {
        self.confirm = Some(target);
        let target_label = match target {
            ToolsSaveTarget::Session => "this session",
            ToolsSaveTarget::Agent => "this agent",
        };
        let mut parts = vec![format!(
            "confirm save for {target_label}: enter/y apply, esc cancel"
        )];
        if self.cache_break_delta() {
            parts.push("changes enabled tools and will break prompt cache".to_string());
        }
        if self.monty_delta() {
            let toggle = if self.nudge_monty { "on" } else { "off" };
            parts.push(format!("monty nudge {toggle}; press m to toggle"));
        }
        self.status = Some(parts.join(" | "));
    }

    fn confirmed_save(&mut self) -> Option<ToolsOutcome> {
        if !self.root_foreground {
            self.confirm = None;
            self.status = Some(
                "Tool surface changes were refused because an interactive subagent holds the foreground."
                    .to_string(),
            );
            return None;
        }
        let target = self.confirm.take().unwrap_or(ToolsSaveTarget::Session);
        match self.build_save(target) {
            Ok(outcome) => Some(outcome),
            Err(error) => {
                let message = error.to_string();
                if let Some(tool) = backticked_tool(&message) {
                    self.row_errors.insert(tool, message.clone());
                }
                self.status = Some(message);
                None
            }
        }
    }

    fn build_save(&mut self, target: ToolsSaveTarget) -> Result<ToolsOutcome> {
        // vNext definitions deliberately reject legacy `tools` and
        // `toolTiers` authority. Refuse before ejecting so the UI cannot
        // report a successful agent save whose canonical markdown omits the
        // selected surface.
        if target == ToolsSaveTarget::Agent
            && self.def.as_ref().is_some_and(|def| def.vnext.is_some())
        {
            anyhow::bail!(
                "agent-scoped tool settings are unavailable for vNext agents; save them for this session instead"
            );
        }
        let mut def = self
            .def
            .clone()
            .ok_or_else(|| anyhow::anyhow!("agent tool settings are not loaded"))?;
        self.draft.write_to_def(&mut def);
        cockpit_core::agents::validate_invariants(&def)?;
        let selection = self.draft.selection().clone();
        let override_json = serde_json::to_string(&selection)?;
        if target == ToolsSaveTarget::Agent {
            self.queue_agent_save(def, selection, override_json)?;
            return Ok(ToolsOutcome::Pending);
        }
        Ok(ToolsOutcome::Apply {
            override_json,
            persist_session: target == ToolsSaveTarget::Session,
            cache_break: self.cache_break_delta(),
            monty_nudge: self.monty_nudge_text(),
        })
    }

    fn queue_agent_save(
        &mut self,
        def: AgentDef,
        selection: ToolSurfaceSelection,
        override_json: String,
    ) -> Result<()> {
        if !self.editable {
            anyhow::bail!("this daemon-owned agent definition is not editable");
        }
        let markdown = def.to_markdown()?;
        let prior_revision = self
            .revision
            .clone()
            .ok_or_else(|| anyhow::anyhow!("agent revision is unavailable"))?;
        let mutation = cockpit_proto::AgentMutation::SaveDefinition {
            name: self.agent_name.clone(),
            markdown,
        };
        let operation_id = uuid::Uuid::new_v4();
        let project_root = self.cwd.to_string_lossy().into_owned();
        let client_operation_id = uuid::Uuid::new_v4().to_string();
        let mutation_intent_hash = cockpit_proto::agent_mutation_intent_hash(
            &project_root,
            &mutation,
            Some(&prior_revision),
        );
        let cache_break = self.cache_break_delta();
        let monty_nudge = self.monty_nudge_text();
        self.pending_effect = Some(ToolsEffect {
            operation_id,
            agent_name: self.agent_name.clone(),
            project_root: project_root.clone(),
            expected_revision: Some(prior_revision.clone()),
            request: cockpit_proto::Request::MutateAgent {
                client_operation_id: client_operation_id.clone(),
                mutation_intent_hash: mutation_intent_hash.clone(),
                project_root: project_root.clone(),
                mutation: mutation.clone(),
                expected_revision: Some(prior_revision.clone()),
            },
        });
        self.in_flight = Some(ToolsPending::SaveAgent {
            operation_id,
            client_operation_id,
            mutation_intent_hash,
            agent_name: self.agent_name.clone(),
            project_root,
            expected_revision: prior_revision,
            mutation,
            def,
            selection,
            override_json,
            cache_break,
            monty_nudge,
            querying: false,
        });
        self.status = Some("saving daemon-owned agent tool settings…".to_string());
        Ok(())
    }

    pub(crate) fn render(&mut self, frame: &mut Frame, area: Rect) {
        let (lines, selected_line, _) = tool_surface_lines(
            &self.picker,
            &self.draft,
            ToolSurfaceRender {
                title: &self.agent_name,
                subtitle: "current agent tools",
                status: self.status.as_deref(),
                row_errors: &self.row_errors,
                block_safety_ungrant: true,
            },
        );
        let items = lines.into_iter().map(ListItem::new).collect::<Vec<_>>();
        let mut state = ratatui::widgets::ListState::default();
        state.select(selected_line);
        frame.render_stateful_widget(List::new(items).scroll_padding(1), area, &mut state);
    }

    fn cache_break_delta(&self) -> bool {
        let after = self.draft.selection();
        all_surface_tools(&self.original, after)
            .into_iter()
            .any(|tool| wire_enabled(&self.original, &tool) != wire_enabled(after, &tool))
    }

    fn monty_delta(&self) -> bool {
        let after = self.draft.selection();
        all_surface_tools(&self.original, after)
            .into_iter()
            .any(|tool| monty_only(&self.original, &tool) != monty_only(after, &tool))
    }

    fn monty_nudge_text(&self) -> Option<String> {
        if !self.nudge_monty || !self.monty_delta() || self.cache_break_delta() {
            return None;
        }
        let after = self.draft.selection();
        let mut enabled = Vec::new();
        let mut disabled = Vec::new();
        for tool in all_surface_tools(&self.original, after) {
            match (monty_only(&self.original, &tool), monty_only(after, &tool)) {
                (false, true) => enabled.push(tool),
                (true, false) => disabled.push(tool),
                _ => {}
            }
        }
        let mut parts = Vec::new();
        if !enabled.is_empty() {
            parts.push(format!("monty tools enabled: {}", enabled.join(", ")));
        }
        if !disabled.is_empty() {
            parts.push(format!("monty tools disabled: {}", disabled.join(", ")));
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

fn all_surface_tools(before: &ToolSurfaceSelection, after: &ToolSurfaceSelection) -> Vec<String> {
    let mut tools = before.tools.clone();
    tools.extend(after.tools.iter().cloned());
    tools.extend(before.tool_tiers.keys().cloned());
    tools.extend(after.tool_tiers.keys().cloned());
    tools.sort();
    tools.dedup();
    tools
}

fn surface_tier(surface: &ToolSurfaceSelection, tool: &str) -> Option<ToolTier> {
    surface.tools.iter().any(|name| name == tool).then(|| {
        surface
            .tool_tiers
            .get(tool)
            .copied()
            .unwrap_or(ToolTier::Enabled)
    })
}

fn wire_enabled(surface: &ToolSurfaceSelection, tool: &str) -> bool {
    surface_tier(surface, tool) == Some(ToolTier::Enabled)
}

fn monty_only(surface: &ToolSurfaceSelection, tool: &str) -> bool {
    surface_tier(surface, tool) == Some(ToolTier::Discoverable)
}

fn backticked_tool(message: &str) -> Option<String> {
    let known: std::collections::BTreeSet<&str> = cockpit_core::agents::known_tool_names()
        .iter()
        .copied()
        .collect();
    let mut rest = message;
    while let Some(start) = rest.find('`') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('`') else {
            break;
        };
        let candidate = &after[..end];
        if known.contains(candidate) {
            return Some(candidate.to_string());
        }
        rest = &after[end + 1..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pane_with_tools(tools: &[&str], tiers: &[(&str, ToolTier)]) -> ToolsPane {
        let tmp = tempfile::tempdir().unwrap();
        let def = AgentDef {
            name: "Build".to_string(),
            description: "d".to_string(),
            mode: cockpit_core::agents::AgentMode::Primary,
            model: None,
            temperature: None,
            tools: Some(tools.iter().map(|tool| (*tool).to_string()).collect()),
            tool_tiers: tiers
                .iter()
                .map(|(tool, tier)| ((*tool).to_string(), *tier))
                .collect(),
            tool_descriptions: BTreeMap::new(),
            scan_tool_results: None,
            goal_supervision: cockpit_core::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            mcp_bindings: Vec::new(),
            private_subagents: std::collections::BTreeMap::new(),
            source: tmp.path().join("Build.md"),
        };
        let draft = ToolSurfaceDraft::from_def(&def);
        ToolsPane {
            agent_name: "Build".to_string(),
            cwd: tmp.keep(),
            root_foreground: true,
            original: draft.selection().clone(),
            def: Some(def),
            revision: Some("test-revision".into()),
            editable: true,
            draft,
            picker: ToolSurfacePicker::default(),
            status: None,
            row_errors: BTreeMap::new(),
            confirm: None,
            nudge_monty: true,
            pending_effect: None,
            in_flight: None,
        }
    }

    fn focus_tool(pane: &mut ToolsPane, name: &str) {
        let idx = cockpit_core::agents::tool_surface_catalog()
            .iter()
            .position(|item| item.name == name)
            .unwrap();
        pane.picker.set_cursor(idx);
    }

    #[test]
    fn tools_overlay_cycles_tier_within_legal_tiers() {
        let mut pane = pane_with_tools(&["code", "mcp"], &[]);
        focus_tool(&mut pane, "code");

        pane.handle_key(KeyEvent::from(KeyCode::Char('t')));
        assert_eq!(pane.draft.tier("code"), ToolTier::Discoverable);
        pane.handle_key(KeyEvent::from(KeyCode::Char('t')));
        assert_eq!(pane.draft.tier("code"), ToolTier::Disabled);
        pane.handle_key(KeyEvent::from(KeyCode::Char('t')));
        assert_eq!(pane.draft.tier("code"), ToolTier::Enabled);
    }

    #[test]
    fn tools_warns_on_builtin_transition() {
        let mut pane = pane_with_tools(&["read"], &[]);
        pane.draft.set_granted("read", false);
        assert!(pane.cache_break_delta());
        pane.start_confirm(ToolsSaveTarget::Session);
        assert!(
            pane.status
                .as_deref()
                .is_some_and(|status| status.contains("will break prompt cache"))
        );
    }

    #[test]
    fn tools_no_warn_on_discoverable_disabled_transition() {
        let mut pane = pane_with_tools(&["code"], &[("code", ToolTier::Discoverable)]);
        pane.draft
            .selection_mut()
            .tool_tiers
            .insert("code".to_string(), ToolTier::Disabled);
        assert!(!pane.cache_break_delta());
        assert!(pane.monty_delta());
        pane.start_confirm(ToolsSaveTarget::Session);
        assert!(
            pane.status
                .as_deref()
                .is_some_and(|status| !status.contains("will break prompt cache"))
        );
    }

    #[test]
    fn tools_treat_direct_native_media_as_schema_affecting() {
        let mut pane = pane_with_tools(&["inspect_audio"], &[]);
        focus_tool(&mut pane, "inspect_audio");

        pane.handle_key(KeyEvent::from(KeyCode::Char('t')));

        assert_eq!(pane.draft.tier("inspect_audio"), ToolTier::Disabled);
        assert!(pane.cache_break_delta());
        assert_eq!(
            cockpit_core::agents::legal_tool_tiers("inspect_audio"),
            &[ToolTier::Enabled, ToolTier::Disabled]
        );
    }

    #[test]
    fn tools_no_nudge_offer_for_wire_tier_only_delta() {
        let mut pane = pane_with_tools(&["read"], &[]);
        pane.draft
            .selection_mut()
            .tool_tiers
            .insert("read".to_string(), ToolTier::Discoverable);
        assert_eq!(pane.monty_nudge_text(), None);
    }

    #[test]
    fn tools_requires_confirm_before_apply() {
        let mut pane = pane_with_tools(&["read"], &[]);
        assert_eq!(
            pane.handle_key(KeyEvent::from(KeyCode::Char('s'))),
            None,
            "first save key only starts confirmation"
        );
        assert!(pane.confirm.is_some());
        assert!(matches!(
            pane.handle_key(KeyEvent::from(KeyCode::Enter)),
            Some(ToolsOutcome::Apply { .. })
        ));
    }

    #[test]
    fn tools_session_save_persists_and_does_not_eject() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pane = pane_with_tools(&["read"], &[]);
        focus_tool(&mut pane, "skill");
        pane.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        pane.start_confirm(ToolsSaveTarget::Session);

        let outcome = pane.confirmed_save();

        assert!(matches!(
            outcome,
            Some(ToolsOutcome::Apply {
                persist_session: true,
                ..
            })
        ));
        assert!(
            !tmp.path()
                .join(".cockpit")
                .join("agents")
                .join("Build.md")
                .exists(),
            "session save must not eject built-in agent to disk"
        );
    }

    #[test]
    fn tools_agent_save_refuses_vnext_builtin_without_ejecting() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pane = pane_with_tools(&["read"], &[]);
        pane.def.as_mut().unwrap().vnext = Some(cockpit_core::agents::VnextAgentDef {
            schema_version: cockpit_core::agents::SCHEMA_VERSION,
            agent_id: "local:test".to_string(),
            execution_kind: cockpit_core::agents::ExecutionKind::Coding,
            model_slots: BTreeMap::new(),
            delegation: cockpit_core::agents::DelegationPolicy::default(),
            questions: None,
            verification: None,
            allowed_knowledge_bases: None,
        });
        focus_tool(&mut pane, "skill");
        pane.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        pane.start_confirm(ToolsSaveTarget::Agent);

        let outcome = pane.confirmed_save();

        assert_eq!(outcome, None);
        let status = pane.status.as_deref();
        assert!(
            status.is_some_and(|message| message.contains("unavailable for vNext agents")),
            "vNext agent save must explain why it was refused: {:?}",
            status
        );
        let path = tmp.path().join(".cockpit").join("agents").join("Build.md");
        assert!(
            !path.exists(),
            "refused vNext agent save must not eject a pristine built-in"
        );
    }

    #[test]
    fn tools_overlay_forbids_disabling_safety_set() {
        let pane = pane_with_tools(&["question"], &[]);
        assert_eq!(
            cockpit_core::agents::legal_tool_tiers("question"),
            &[ToolTier::Enabled]
        );
        assert!(pane.draft.granted("question"));
    }

    #[test]
    fn tools_overlay_blocks_ungrant_of_safety_set() {
        let mut pane = pane_with_tools(&["question"], &[]);
        let question = cockpit_core::agents::tool_surface_catalog()
            .iter()
            .position(|item| item.name == "question")
            .unwrap();
        for _ in 0..question {
            pane.picker.move_next();
        }
        pane.handle_key(KeyEvent::from(KeyCode::Char(' ')));
        assert!(pane.draft.granted("question"));
        assert!(pane.status.unwrap().contains("cannot be ungranted"));
    }

    #[test]
    fn tools_monty_change_nudge_opt_out() {
        let mut pane = pane_with_tools(&["code"], &[("code", ToolTier::Discoverable)]);
        pane.draft.set_granted("code", false);
        pane.start_confirm(ToolsSaveTarget::Session);
        pane.handle_key(KeyEvent::from(KeyCode::Char('m')));
        assert_eq!(pane.monty_nudge_text(), None);
    }
}
