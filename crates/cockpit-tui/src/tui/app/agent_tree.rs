//! App-side wiring for the agent-tree overlay: open, fetch the tree + attention
//! snapshot, apply it, resolve a selected child's decision, and re-fetch on
//! `AgentTreeChanged` (or manual refresh).

use super::*;

use cockpit_proto::{AgentDecisionAnswer, AgentInterruptResponse};
use uuid::Uuid;

/// Combined tree + attention fetch. `Replace` policy coalesces bursts of
/// `AgentTreeChanged` invalidations into a single in-flight snapshot request.
const AGENT_TREE_SNAPSHOT_ACTION: &str = "agent_tree.snapshot";
/// Page size for the read-only tree/attention pages this surface renders.
const AGENT_TREE_PAGE_LIMIT: u16 = 256;

impl App {
    /// Open the agent-tree overlay and schedule its first snapshot fetch.
    pub(super) fn open_agent_tree(&mut self) {
        self.overlay =
            Overlay::AgentTree(crate::tui::agent_tree_pane::AgentTreePane::loading(true));
        self.request_agent_tree_refresh();
    }

    /// Fetch the agent tree and its attention list in one coalesced action.
    pub(super) fn request_agent_tree_refresh(&mut self) {
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            if let Overlay::AgentTree(pane) = &mut self.overlay {
                pane.set_error("The agent tree is only available once attached to a session.");
            }
            return;
        };
        let attached = runner.attached_request_binding();
        let session_id = attached.session_id();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc(AGENT_TREE_SNAPSHOT_ACTION),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new(AGENT_TREE_SNAPSHOT_ACTION),
            ),
            async move {
                let tree = attached
                    .request(cockpit_proto::Request::ReadAgentTree {
                        session_id,
                        root_agent_instance_id: None,
                        after: None,
                        limit: AGENT_TREE_PAGE_LIMIT,
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                let attention = attached
                    .request(cockpit_proto::Request::ReadAgentAttention {
                        session_id,
                        after: None,
                        limit: AGENT_TREE_PAGE_LIMIT,
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(
                    crate::tui::async_action::AsyncActionPayload::AgentTreeSnapshot {
                        tree: Box::new(tree),
                        attention: Box::new(attention),
                    },
                )
            },
        );
    }

    /// Apply a completed tree + attention snapshot into the open overlay.
    pub(super) fn apply_agent_tree_snapshot(
        &mut self,
        tree: cockpit_proto::Response,
        attention: cockpit_proto::Response,
    ) {
        let (
            cockpit_proto::Response::AgentTreePage { nodes, .. },
            cockpit_proto::Response::AgentAttentionPage { entries, .. },
        ) = (tree, attention)
        else {
            return;
        };
        if let Overlay::AgentTree(pane) = &mut self.overlay {
            pane.apply(nodes, entries);
        }
    }

    pub(super) fn apply_agent_tree_error(&mut self, error: String) {
        if let Overlay::AgentTree(pane) = &mut self.overlay {
            pane.set_error(format!("The agent tree could not be loaded: {error}"));
        }
    }

    /// Submit a resolve/steer for the selected child's pending decision. The
    /// daemon owns the transaction; the TUI only names the decision, attributed
    /// to `agent_instance_id`. The initial resolve is a Cancel; richer answer
    /// contracts (option/free-text) are a follow-on.
    pub(super) fn resolve_agent_decision(
        &mut self,
        decision_request_id: Uuid,
        _agent_instance_id: Uuid,
    ) {
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            return;
        };
        let attached = runner.attached_request_binding();
        let session_id = attached.session_id();
        const RESOLVE_ACTION: &str = "agent_tree.resolve";
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc(RESOLVE_ACTION),
            crate::tui::async_action::AsyncActionPolicy::AllowConcurrent,
            async move {
                let _ = attached
                    .request(cockpit_proto::Request::ResolveAgentDecision {
                        session_id,
                        decision_request_id,
                        answer: AgentDecisionAnswer::InterruptResponse {
                            response: AgentInterruptResponse::Cancel,
                        },
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                // The daemon emits `AgentTreeChanged`; re-read the snapshot.
                Ok(crate::tui::async_action::AsyncActionPayload::AgentTreeResolved)
            },
        );
    }

    /// Fetch the focused node's daemon-resolved effective settings and open the
    /// per-node override controls inside the agent-tree overlay (modes AC5/6/7).
    pub(super) fn request_agent_effective_settings(&mut self, agent_instance_id: Uuid) {
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            if let Overlay::AgentTree(pane) = &mut self.overlay {
                pane.set_override_error(
                    "Per-node settings are only available once attached to a session.",
                );
            }
            return;
        };
        let attached = runner.attached_request_binding();
        let session_id = attached.session_id();
        const EFFECTIVE_SETTINGS_ACTION: &str = "agent_tree.effective_settings";
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc(EFFECTIVE_SETTINGS_ACTION),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new(EFFECTIVE_SETTINGS_ACTION),
            ),
            async move {
                let response = attached
                    .request(cockpit_proto::Request::GetAgentEffectiveSettings {
                        session_id,
                        agent_instance_id,
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(crate::tui::async_action::AsyncActionPayload::AgentEffectiveSettings(response))
            },
        );

        // Fetch the model choices for the same node in parallel: they populate
        // the override view's Model section (modes AC5/AC6). Sourced from the
        // daemon-owned session-setup snapshot; the daemon re-validates
        // hard-compatibility on apply.
        let model_attached = runner.attached_request_binding();
        let model_session_id = model_attached.session_id();
        const MODEL_CHOICES_ACTION: &str = "agent_tree.override_model_choices";
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc(MODEL_CHOICES_ACTION),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new(MODEL_CHOICES_ACTION),
            ),
            async move {
                let response = model_attached
                    .request(cockpit_proto::Request::GetSessionSetupSnapshot {
                        session_id: model_session_id,
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(crate::tui::async_action::AsyncActionPayload::SessionSetupSnapshot(response))
            },
        );
    }

    pub(super) fn apply_agent_effective_settings(&mut self, response: cockpit_proto::Response) {
        let cockpit_proto::Response::AgentEffectiveSettings { snapshot } = response else {
            return;
        };
        if let Overlay::AgentTree(pane) = &mut self.overlay {
            pane.apply_effective_settings(snapshot);
        }
    }

    pub(super) fn apply_agent_effective_settings_error(&mut self, error: String) {
        if let Overlay::AgentTree(pane) = &mut self.overlay {
            pane.set_override_error(format!("Per-node settings could not be loaded: {error}"));
        }
    }

    /// Apply fetched model choices into the open override view's Model section.
    /// Supplementary to the effective settings, so a fetch failure is silently
    /// tolerated (the Model section simply stays empty).
    pub(super) fn apply_agent_override_model_choices(&mut self, response: cockpit_proto::Response) {
        let cockpit_proto::Response::SessionSetupSnapshot { snapshot } = response else {
            return;
        };
        if let Overlay::AgentTree(pane) = &mut self.overlay {
            pane.apply_model_choices(snapshot);
        }
    }

    /// Submit one typed, non-escalating override for `agent_instance_id` against
    /// the effective-settings revision. The daemon owns the CAS; on any outcome
    /// we re-fetch so the controls reflect the current revision and pending
    /// state (or the daemon's rejection reason).
    pub(super) fn submit_agent_session_override(
        &mut self,
        agent_instance_id: Uuid,
        expected_override_revision: u64,
        field: cockpit_proto::AgentSessionOverrideFieldV1,
    ) {
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            return;
        };
        let attached = runner.attached_request_binding();
        let session_id = attached.session_id();
        const APPLY_OVERRIDE_ACTION: &str = "agent_tree.apply_override";
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc(APPLY_OVERRIDE_ACTION),
            crate::tui::async_action::AsyncActionPolicy::AllowConcurrent,
            async move {
                let response = attached
                    .request(cockpit_proto::Request::ApplyAgentSessionOverride {
                        session_id,
                        agent_instance_id,
                        expected_override_revision,
                        field,
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(
                    crate::tui::async_action::AsyncActionPayload::AgentSessionOverrideOutcome(
                        response,
                    ),
                )
            },
        );
    }

    /// Handle an override outcome: surface any rejection, then re-fetch the
    /// node's effective settings so the controls show the new revision.
    pub(super) fn apply_agent_session_override_outcome(
        &mut self,
        response: cockpit_proto::Response,
    ) {
        let cockpit_proto::Response::AgentSessionOverrideOutcome {
            agent_instance_id,
            status,
            ..
        } = response
        else {
            return;
        };
        if !status.is_applied()
            && let Overlay::AgentTree(pane) = &mut self.overlay
        {
            pane.set_override_error(override_status_message(status));
        }
        self.request_agent_effective_settings(agent_instance_id);
    }

    pub(super) fn set_agent_override_error(&mut self, error: String) {
        if let Overlay::AgentTree(pane) = &mut self.overlay {
            pane.set_override_error(format!("The override could not be applied: {error}"));
        }
    }
}

fn override_status_message(status: cockpit_proto::AgentSessionOverrideStatusV1) -> String {
    use cockpit_proto::AgentSessionOverrideStatusV1 as Status;
    match status {
        Status::Applied => "Override applied.".to_string(),
        Status::StaleRevision => {
            "The controls were out of date; refreshed to the current settings.".to_string()
        }
        Status::RejectedNotFound => "That agent is no longer in the session.".to_string(),
        Status::RejectedTerminal => {
            "That agent has finished; its settings are read-only.".to_string()
        }
        Status::RejectedEscalation => {
            "That change would raise authority and was refused.".to_string()
        }
        Status::RejectedIncompatible => "That change is not available for this agent.".to_string(),
    }
}
