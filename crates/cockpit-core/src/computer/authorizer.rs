//! Production [`ComputerAuthorizer`] backed by the real [`Approver`].
//!
//! The coordinator authorizes every canonical computer action through the
//! [`ComputerAuthorizer`] seam. Hermetic tests inject
//! [`FakeComputerAuthorizer`](crate::computer::coordinator::FakeComputerAuthorizer);
//! production injects [`ApproverComputerAuthorizer`], which is the only path
//! that constructs the exhaustive [`AuthorizationRequest::ComputerAction`]
//! central-authorization variant and routes it to [`Approver::authorize`].
//!
//! Fail-closed contract: any decision other than an explicit `Allow`, and any
//! authorization error, results in the action **not** being dispatched. A user
//! `Deny` (or a headless noninteractive deny) maps to a sticky per-delegation
//! [`ComputerAuthorizationDecision::Deny`]; a transient authorization error
//! surfaces as [`ComputerError`] so the coordinator journals a fail-closed
//! failure without executing input.

use std::sync::Arc;

use async_trait::async_trait;

use crate::approval::{Approver, AuthorizationRequest, Decision, NONINTERACTIVE_RUN_DENIAL};
use crate::computer::ComputerError;
use crate::computer::coordinator::{
    ComputerActionAuthorization, ComputerApprovalTier, ComputerAuthorizationDecision,
    ComputerAuthorizer,
};

/// Production computer authorizer: constructs the central
/// [`AuthorizationRequest::ComputerAction`] variant and delegates to the real
/// [`Approver`].
pub struct ApproverComputerAuthorizer {
    approver: Arc<Approver>,
}

impl ApproverComputerAuthorizer {
    /// Wrap a shared [`Approver`] as a computer authorizer.
    pub fn new(approver: Arc<Approver>) -> Self {
        Self { approver }
    }
}

/// The stable wire string for a computer approval tier passed to the central
/// authorizer. Only `"yolo"` auto-allows on the computer path; `"ask"` prompts
/// (and survives global session YOLO — see `approve_computer_action_inner`).
fn tier_str(tier: ComputerApprovalTier) -> &'static str {
    match tier {
        ComputerApprovalTier::Ask => "ask",
        ComputerApprovalTier::Yolo => "yolo",
    }
}

/// Map a central-authorizer [`Decision`] onto a computer authorization
/// decision. Every non-`Allow` verdict fails closed as a `Deny` carrying a
/// safe, bounded reason.
fn map_decision(decision: Decision) -> ComputerAuthorizationDecision {
    match decision {
        Decision::Allow { .. } => ComputerAuthorizationDecision::Allow,
        Decision::Deny => ComputerAuthorizationDecision::Deny {
            reason: "computer action denied by user".to_string(),
        },
        Decision::NoninteractiveDeny => ComputerAuthorizationDecision::Deny {
            reason: NONINTERACTIVE_RUN_DENIAL.to_string(),
        },
        Decision::StandingReject { .. } => ComputerAuthorizationDecision::Deny {
            reason: "computer action denied by a saved decision".to_string(),
        },
    }
}

#[async_trait]
impl ComputerAuthorizer for ApproverComputerAuthorizer {
    async fn authorize(
        &self,
        request: &ComputerActionAuthorization,
    ) -> Result<ComputerAuthorizationDecision, ComputerError> {
        let central = AuthorizationRequest::ComputerAction {
            session_id: &request.session_id,
            delegation_id: &request.delegation_id.0,
            action_id: &request.action_id,
            tier: tier_str(request.tier),
            action_label: &request.action_label,
            backend_kind: request.backend_kind.diagnostic_label(),
            focus_generation: request.focus_generation,
            observation_generation: request.observation_generation,
            has_host_lease: request.host_lease.is_some(),
            provider_call_id: &request.provider_call_id,
            batch_index: request.batch_index,
            geometry_generation: request.geometry_generation,
            action_class: request.action_class.label(),
            action_payload_digest: &request.action_payload_digest,
            lease_binding_digest: request.lease_binding_digest.as_deref(),
            target_evidence_binding_digest: &request.target_evidence_binding_digest,
        };
        match self.approver.authorize(central).await {
            Ok(decision) => Ok(map_decision(decision)),
            // A transient authorization failure (e.g. persistence error) must
            // fail closed without leaking internals: the coordinator journals a
            // failed, non-dispatched outcome and the next action re-enters the
            // authorize path.
            Err(_err) => Err(ComputerError::Refused(
                "computer action authorization unavailable".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::approval::store::GrantStore;
    use crate::computer::coordinator::{ActionRiskClass, DelegationId};
    use crate::computer::target::BackendKind;
    use crate::daemon::session_worker::SessionConfigHandle;
    use crate::engine::interrupt::InterruptHub;

    fn build_approver(cwd: &std::path::Path) -> (Arc<Approver>, crate::db::Db, uuid::Uuid) {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = crate::session::Session::create_for_test(
            db.clone(),
            cwd.to_path_buf(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let sid = session.id;
        let store = GrantStore::new(
            db.clone(),
            sid,
            cwd.to_path_buf(),
            SessionConfigHandle::from_disk_for_tests(cwd),
        );
        let hub = Arc::new(InterruptHub::detached());
        let approver = Approver::new(store, db.clone(), sid, "builder", hub);
        (Arc::new(approver), db, sid)
    }

    fn authorization(tier: ComputerApprovalTier) -> ComputerActionAuthorization {
        ComputerActionAuthorization {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            action_id: "call-1".to_string(),
            tier,
            host_lease: None,
            focus_generation: 1,
            observation_generation: 1,
            action_label: "openai_call:1".to_string(),
            backend_kind: BackendKind::VirtualDisplay,
            provider_call_id: "call-1".to_string(),
            batch_index: 0,
            geometry_generation: 1,
            action_class: ActionRiskClass::Unknown,
            action_payload_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            lease_binding_digest: None,
            target_evidence_binding_digest:
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        }
    }

    #[test]
    fn computer_live_approver_adapter_maps_decisions() {
        assert_eq!(
            map_decision(Decision::Allow {
                scope: crate::approval::store::Scope::Once
            }),
            ComputerAuthorizationDecision::Allow
        );
        assert!(matches!(
            map_decision(Decision::Deny),
            ComputerAuthorizationDecision::Deny { .. }
        ));
        assert!(matches!(
            map_decision(Decision::NoninteractiveDeny),
            ComputerAuthorizationDecision::Deny { .. }
        ));
        assert!(matches!(
            map_decision(Decision::StandingReject {
                scope: crate::approval::store::Scope::Session
            }),
            ComputerAuthorizationDecision::Deny { .. }
        ));
    }

    /// The adapter builds the central request and, for the computer `yolo`
    /// tier, the real Approver auto-allows with **zero** human requests: no
    /// interrupt is opened.
    #[tokio::test]
    async fn computer_live_approver_adapter_yolo_zero_requests() {
        let tmp = tempfile::tempdir().unwrap();
        let (approver, db, sid) = build_approver(tmp.path());
        let adapter = ApproverComputerAuthorizer::new(approver);

        let decision = adapter
            .authorize(&authorization(ComputerApprovalTier::Yolo))
            .await
            .unwrap();
        assert_eq!(decision, ComputerAuthorizationDecision::Allow);

        // Yolo raises no human request.
        let open = db.list_open_interrupts(sid).await.unwrap();
        assert!(open.is_empty(), "yolo computer tier must open no interrupt");
    }
}
