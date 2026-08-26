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
                Ok(crate::tui::async_action::AsyncActionPayload::AgentTreeSnapshot {
                    tree: Box::new(tree),
                    attention: Box::new(attention),
                })
            },
        );
    }

    /// Apply a completed tree + attention snapshot into the open overlay.
    pub(super) fn apply_agent_tree_snapshot(
        &mut self,
        tree: cockpit_proto::Response,
        attention: cockpit_proto::Response,
    ) {
        let (cockpit_proto::Response::AgentTreePage { nodes, .. },
             cockpit_proto::Response::AgentAttentionPage { entries, .. }) = (tree, attention)
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
}
