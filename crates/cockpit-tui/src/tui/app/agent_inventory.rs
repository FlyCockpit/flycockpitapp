use super::*;
use cockpit_core::daemon::proto::{AgentSummary, ModelSummary, SkillSummary};
use uuid::Uuid;

impl App {
    pub(super) fn sync_active_agent(&mut self) {
        let (name, path) = {
            let Some(Ok(runner)) = self.agent_runner.as_ref() else {
                return;
            };
            (
                cockpit_core::sync::lock_or_recover(&runner.active_agent).clone(),
                cockpit_core::sync::lock_or_recover(&runner.active_agent_path).clone(),
            )
        };
        let mut changed = false;
        if name != self.launch.agent_name {
            self.launch.agent_name = name;
            changed = true;
        }
        if !path.is_empty() && path != self.agent_path {
            self.agent_path = path;
        }
        if changed {
            self.request_inventory_refresh(true);
            self.refresh_skill_commands();
        }
    }

    /// Skills from the last complete daemon inventory snapshot. Empty when
    /// inventory is unavailable (pre-attach) — never a local filesystem walk.
    pub(super) fn visible_skill_summaries(&self) -> Vec<SkillSummary> {
        self.inventory
            .snapshot
            .as_ref()
            .map(|snap| snap.skills.clone())
            .unwrap_or_default()
    }

    pub(super) fn inventory_agents(&self) -> Vec<AgentSummary> {
        self.inventory
            .snapshot
            .as_ref()
            .map(|snap| snap.agents.clone())
            .unwrap_or_default()
    }

    pub(super) fn inventory_agent_names(&self) -> Vec<String> {
        self.inventory_agents()
            .into_iter()
            .map(|agent| agent.name)
            .collect()
    }

    pub(super) fn inventory_models(&self) -> Vec<ModelSummary> {
        self.inventory
            .snapshot
            .as_ref()
            .map(|snap| snap.models.clone())
            .unwrap_or_default()
    }

    /// Rebuild slash skill entries from the last complete inventory snapshot.
    pub(super) fn refresh_skill_commands(&mut self) {
        self.skill_commands = bare_skill_commands_from(self.visible_skill_summaries());
    }

    /// Schedule an async GetInventoryBundle refresh (coalesced via InventoryState).
    pub(super) fn request_inventory_refresh(&mut self, allow_equal_generations: bool) {
        let selected = self.launch.agent_name.clone();
        let Some(_ticket) = self
            .inventory
            .start_refresh(selected.clone(), allow_equal_generations)
        else {
            return;
        };
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            return;
        };
        let attached = runner.attached_request_binding();
        let cwd = self.launch.cwd.clone();
        let agent_name = selected;
        const INVENTORY_REFRESH_ACTION: &str = "inventory.bundle";
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc(INVENTORY_REFRESH_ACTION),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new(INVENTORY_REFRESH_ACTION),
            ),
            async move {
                let response = attached
                    .request(cockpit_core::daemon::proto::Request::GetInventoryBundle {
                        project_root: cwd.to_string_lossy().into_owned(),
                        session_id: attached.session_id(),
                        selected_agent: agent_name,
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(crate::tui::async_action::AsyncActionPayload::InventoryBundle(response))
            },
        );
    }

    /// Seed inventory identity after attach succeeds.
    pub(super) fn bootstrap_inventory_after_attach(
        &mut self,
        client_instance_id: Uuid,
        connection_epoch: u64,
        session_id: Uuid,
        session_generation: u64,
    ) {
        self.inventory.begin_attach(
            client_instance_id,
            connection_epoch,
            session_id,
            self.launch.agent_name.clone(),
            session_generation,
        );
        self.request_inventory_refresh(true);
    }

    /// Apply a completed GetInventoryBundle response into inventory state.
    /// Late results without a matching in-flight ticket are inert.
    pub(super) fn apply_inventory_bundle_response(
        &mut self,
        response: cockpit_core::daemon::proto::Response,
    ) -> bool {
        let cockpit_core::daemon::proto::Response::InventoryBundle {
            selected_agent,
            agents,
            models,
            skills,
            session_generation,
            config_generation,
            inventory_generation,
        } = response
        else {
            return false;
        };
        let Some(ticket) = self.inventory.in_flight.clone() else {
            return false;
        };
        let snap = inventory::InventorySnapshot {
            selected_agent,
            agents,
            models,
            skills,
            session_generation,
            config_generation,
            inventory_generation,
        };
        let applied = self.inventory.apply_success(&ticket, snap);
        if applied {
            self.refresh_skill_commands();
        } else if self.inventory.take_dirty_replacement() {
            self.request_inventory_refresh(false);
        }
        applied
    }

    /// Apply inventory/config invalidation from a daemon event.
    pub(super) fn on_inventory_invalidation(
        &mut self,
        config_generation: Option<u64>,
        inventory_generation: Option<u64>,
    ) {
        self.inventory
            .on_invalidation(config_generation, inventory_generation);
        if self.inventory.take_dirty_replacement() {
            self.request_inventory_refresh(false);
        }
    }

    pub(super) fn push_agent_path_child(&mut self, parent: &str, child: &str) {
        if let Some(parent_idx) = self.agent_path.iter().position(|name| name == parent) {
            self.agent_path.truncate(parent_idx + 1);
        } else {
            self.agent_path.clear();
            self.agent_path.push(self.launch.agent_name.clone());
        }
        self.agent_path.push(child.to_string());
        self.launch.agent_name = child.to_string();
        self.refresh_skill_commands();
    }

    pub(super) fn pop_agent_path_for_report(&mut self, agent: &str) {
        if let Some(agent_idx) = self.agent_path.iter().position(|name| name == agent) {
            self.agent_path.truncate(agent_idx);
        } else {
            self.agent_path.pop();
        }
        if self.agent_path.is_empty() {
            self.agent_path.push(self.launch.agent_name.clone());
        }
        if let Some(current) = self.agent_path.last() {
            self.launch.agent_name = current.clone();
            self.refresh_skill_commands();
        }
    }
}
