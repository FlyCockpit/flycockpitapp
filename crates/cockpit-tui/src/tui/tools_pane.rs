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
    def: AgentDef,
    revision: String,
    editable: bool,
    draft: ToolSurfaceDraft,
    picker: ToolSurfacePicker,
    status: Option<String>,
    row_errors: BTreeMap<String, String>,
    confirm: Option<ToolsSaveTarget>,
    nudge_monty: bool,
}

impl ToolsPane {
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
        let def = cockpit_core::agents::parse_agent(
            &snapshot.markdown,
            agent_name,
            PathBuf::from("<daemon-agent-snapshot>"),
        )?;
        let draft = ToolSurfaceDraft::from_def(&def);
        let original = draft.selection().clone();
        let status = (!root_foreground).then(|| {
            "Apply is disabled while an interactive subagent holds the foreground.".to_string()
        });
        Ok(Self {
            agent_name: agent_name.to_string(),
            cwd: cwd.to_path_buf(),
            root_foreground,
            original,
            def,
            revision: snapshot.revision,
            editable: snapshot.editable,
            draft,
            picker: ToolSurfacePicker::default(),
            status,
            row_errors: BTreeMap::new(),
            confirm: None,
            nudge_monty: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn agent_name(&self) -> &str {
        &self.agent_name
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<ToolsOutcome> {
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
        if target == ToolsSaveTarget::Agent && self.def.vnext.is_some() {
            anyhow::bail!(
                "agent-scoped tool settings are unavailable for vNext agents; save them for this session instead"
            );
        }
        let mut def = self.def.clone();
        self.draft.write_to_def(&mut def);
        cockpit_core::agents::validate_invariants(&def)?;
        let selection = self.draft.selection().clone();
        let override_json = serde_json::to_string(&selection)?;
        if target == ToolsSaveTarget::Agent {
            self.write_agent_def(&def)?;
            self.def = def;
            self.original = selection.clone();
        }
        Ok(ToolsOutcome::Apply {
            override_json,
            persist_session: target == ToolsSaveTarget::Session,
            cache_break: self.cache_break_delta(),
            monty_nudge: self.monty_nudge_text(),
        })
    }

    fn write_agent_def(&mut self, def: &AgentDef) -> Result<()> {
        let markdown = def.to_markdown()?;
        let mut revision = self.revision.clone();
        if !self.editable {
            let response = crate::tui::agent_runner::daemon_request_blocking(
                cockpit_core::daemon::proto::Request::MutateAgent {
                    project_root: self.cwd.to_string_lossy().into_owned(),
                    mutation: cockpit_core::daemon::proto::AgentMutation::EjectBuiltin {
                        name: self.agent_name.clone(),
                    },
                    expected_revision: Some(revision),
                },
            )
            .map_err(anyhow::Error::msg)?;
            let cockpit_core::daemon::proto::Response::AgentMutated(result) = response else {
                anyhow::bail!("daemon returned an unexpected eject response");
            };
            revision = result
                .snapshot
                .ok_or_else(|| anyhow::anyhow!("daemon omitted the ejected snapshot"))?
                .revision;
        }
        let response = crate::tui::agent_runner::daemon_request_blocking(
            cockpit_core::daemon::proto::Request::MutateAgent {
                project_root: self.cwd.to_string_lossy().into_owned(),
                mutation: cockpit_core::daemon::proto::AgentMutation::SaveDefinition {
                    name: self.agent_name.clone(),
                    markdown,
                },
                expected_revision: Some(revision),
            },
        )
        .map_err(anyhow::Error::msg)?;
        let cockpit_core::daemon::proto::Response::AgentMutated(result) = response else {
            anyhow::bail!("daemon returned an unexpected agent-save response");
        };
        let snapshot = result
            .snapshot
            .ok_or_else(|| anyhow::anyhow!("daemon omitted the saved snapshot"))?;
        self.revision = snapshot.revision;
        self.editable = snapshot.editable;
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
            fork_eligible: false,
            vnext: None,
            prompt: "body".to_string(),
            prompt_variants: std::collections::HashMap::new(),
            source: tmp.path().join("Build.md"),
        };
        let draft = ToolSurfaceDraft::from_def(&def);
        ToolsPane {
            agent_name: "Build".to_string(),
            cwd: tmp.keep(),
            root_foreground: true,
            original: draft.selection().clone(),
            def,
            revision: "test-revision".into(),
            editable: true,
            draft,
            picker: ToolSurfacePicker::default(),
            status: None,
            row_errors: BTreeMap::new(),
            confirm: None,
            nudge_monty: true,
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
        let mut pane = ToolsPane::open(tmp.path(), "Build", true).unwrap();
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
        let mut pane = ToolsPane::open(tmp.path(), "Build", true).unwrap();
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
