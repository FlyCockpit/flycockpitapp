//! Static production-wiring ratchets for agent-tree lifecycle work.
//!
//! These intentionally inspect the composition sources rather than duplicating
//! lifecycle unit tests: a future refactor must keep the real task, question,
//! approval, restart, deadline, resolver, and late-steer paths connected to
//! the durable implementation.

#[test]
fn production_paths_keep_agent_tree_authoritative() {
    let worker = include_str!("../src/daemon/session_worker/run.rs");
    let interrupt = include_str!("../src/engine/interrupt.rs");
    let question = include_str!("../src/tools/question.rs");
    let approval = include_str!("../src/approval/prompt.rs");
    let driver = include_str!("../src/engine/driver/mod.rs");
    let noninteractive = include_str!("../src/engine/driver/noninteractive.rs");
    let runtime = include_str!("../src/agent_tree.rs");
    let dispatch = include_str!("../src/daemon/server/dispatch.rs");
    let persistence = include_str!("../../cockpit-db/src/db/agent_tree_decisions.rs");
    let attention_persistence = include_str!("../../cockpit-db/src/db/needs_attention.rs");
    let migration = include_str!("../../cockpit-db/src/db/migrations/0001_initial.sql");
    let protocol = include_str!("../../../packages/cockpit-protocol/src/index.ts");
    let requests =
        include_str!("../../../packages/cockpit-protocol/fixtures/daemon-wire/requests.json");
    let responses =
        include_str!("../../../packages/cockpit-protocol/fixtures/daemon-wire/responses.json");
    let events =
        include_str!("../../../packages/cockpit-protocol/fixtures/daemon-wire/events.json");

    for required in [
        "AgentTreeRuntime::new",
        "with_resolver_delivery",
        "WorkerAgentTreeResolverDelivery",
        "AgentTreeResolverCompletion",
        "AgentTreeDecision",
        "accept_resolver_result",
        "abandon_resolver_delivery",
        "deliver_terminal_agent_tree_interrupt",
        "deliver_live_agent_tree_late_user_steers",
        "deliver_next_pending_late_user_steer",
        "try_send_pending_late_user_steer",
        "schedule_accepted_late_steer_recovery_control",
        "root_parked_interrupt_id_from_snapshot",
        "ReapStaleHostCapabilityRefreshes",
        "completed_unpublished_host_capability_refresh_operations",
        "drain_completed_host_capability_refresh_outbox_while_serialized",
        "reap_stale_host_capability_refresh_operations_globally",
        "InterruptResponse",
        "reconcile_pending_requests",
        "WorkerAgentTreeDeadlines",
        "ExpireAgentTreeDeadlines",
        "relay_agent_tree_events",
        "attention_transition",
        "decision_request_for_interrupt",
        "resolve_user_answer",
        "ReplayParkedInterrupt",
        "spawn_parked_interrupt_replay",
        "complete_executing_interrupt",
        "host_approval_response_allows",
        "consume_host_approval_final_operation",
        "with_persisted_operation_id",
        "mark_host_approval_final_operation_submission_unknown",
        "consume_agent_resume_claims_atomically",
        "try_send",
        "DeliverLateUserDecisionSteer",
        "pending_late_user_steer_acks",
        "finish_late_steer_deliveries",
        "run_invocation_id",
        "release_agent_resume_claim",
        "release_late_user_decision_steer_claim",
        "WorkerAgentTreeResolverRegistry",
        "parent_endpoint",
        "exact_owner_executor_is_live",
        "recovery left a decision owner unattached",
        "ResolveAgentTreeDecision",
        "AgentTreeNoninteractiveEndpointAttached",
        "task_delegation_recovery_descriptor",
        "ReattachInteractiveTaskChild",
        "ReattachNoninteractiveTaskChild",
        "ReattachNoninteractiveTaskBatch",
        "attach_noninteractive_endpoint",
        "attached_recovered_agents",
        "recursive_noninteractive_recovery_descriptor",
        "RecoveredNoninteractiveResolverEndpoint",
        "complete_late_user_decision_steer_execution",
        "AgentTreeExecutorRequest",
        "exact parked continuation executor is not attached",
        "AuthorizeHostCapabilitiesRefresh",
        "HostEffect(",
        "WorkerAgentTreeResolverEndpoint::HostOperation",
        "handle_terminal_host_capability_refresh_interrupt",
        "host-operation continuation must be acknowledged by its typed durable operation",
    ] {
        assert!(worker.contains(required), "worker lost {required}");
    }
    for required in [
        "request_decision_for_interrupt",
        "user_question_interrupt",
        "interrupt_response_contract",
        "session_root_agent",
        "InterruptHub",
        "raise_interrupt_questions_with_payload",
        "durable_agent_id",
        "reserve_host_approval_final_operation",
        "consume_host_approval_final_operation",
        "operation_kind",
        "input_digest",
        "with_persisted_operation_id",
        "recheck_host_approval_effect_boundary",
        "cancel_unbound_host_approval_final_operation",
        "mark_interrupt_interrupted",
    ] {
        assert!(
            interrupt.contains(required),
            "interrupt bridge lost {required}"
        );
    }
    // The real waiter has to exist before the durable request becomes eligible
    // for automatic delivery; otherwise an immediate resolver result can win
    // the tree CAS before QuestionTool has a continuation to wake.
    let durable_question_bridge = interrupt
        .split("pub(crate) async fn raise_and_wait_with_agent_tree")
        .nth(1)
        .expect("durable QuestionTool bridge must exist");
    assert!(
        durable_question_bridge
            .find("let pending = interrupts.register(interrupt_id)")
            .expect("durable QuestionTool bridge must register its waiter")
            < durable_question_bridge
                .find(".request_decision_for_interrupt")
                .expect("durable QuestionTool bridge must bind its decision"),
        "QuestionTool waiter must be registered before automatic lifecycle delivery is possible"
    );
    let resolve_interrupt = worker
        .split("SessionWork::ResolveInterrupt {")
        .nth(1)
        .expect("worker must own the ResolveInterrupt composition boundary");
    let winning_tree_settlement = resolve_interrupt
        .split("if tree_settlement_won {")
        .nth(1)
        .expect("tree-linked interrupt winner must have a dedicated delivery branch");
    assert!(
        winning_tree_settlement
            .find("deliver_terminal_agent_tree_interrupt(")
            .expect("winning tree settlement must deliver its original continuation")
            < winning_tree_settlement
                .find("if row.as_ref().is_some_and")
                .expect("legacy parked/resolve branch must remain after the tree-winner branch"),
        "a tree-won QuestionTool or host-approval settlement must wake/replay through the shared terminal delivery boundary before legacy resolve_interrupt can reject its already-projected row"
    );
    assert!(question.contains("raise_and_wait_with_agent_tree"));
    assert!(approval.contains("raise_and_wait_with_agent_tree"));
    assert!(approval.contains("HostApproval"));
    assert!(approval.contains("HostApprovalOperation::new"));
    for required in [
        "publish_task_delegation_children_and_agents",
        "terminalize_agent_tree_executor",
        "with_agent_instance_id",
        "settle_task_delegation_child_and_agent",
        "persist_active_interactive_task_snapshot",
        "restore_root_late_user_steer_continuation",
        "AgentTreeExecutorEndpointAttached",
        "recovered_child_has_parked_continuation",
        "synthetic empty submission",
    ] {
        assert!(
            driver.contains(required),
            "interactive task path lost {required}"
        );
    }
    for required in [
        "publish_task_delegation_children_and_agents",
        "task_delegation_child_agent",
        "claim_late_user_decision_steers",
        "ack_late_user_decision_steer_delivery",
        "release_late_user_decision_steer_claim",
        "render_noninteractive_agent_tree_late_steers",
        "NoninteractiveAgentTreeEndpointRegistration",
        "reattach_noninteractive_task_child",
        "launch_recovered_noninteractive_task",
        "reattach_noninteractive_task_batch",
        "execute_recovered_batch_noninteractive_task",
        "endpoint_ready",
        "RecoveredNoninteractiveEndpointCollector",
        "waiting_recursive_recovery_snapshot",
        "recursive_batch_execution_order_labels",
        "recursive_recovery_execution_order",
        "validate_recovered_batch_dependency_descriptor",
        "batch_execution_order",
        "batch_dependencies",
        "replay_parked_interrupt_in_noninteractive_executor",
        "loading durable parked continuation for noninteractive recovery",
        "pre-interrupt prompt",
        "complete_recursive_noninteractive_children_and_checkpoint_parent",
        "recover_pending_recursive_continuation",
        "persist_task_delegation_snapshot",
        "settle_task_tree_child",
        "settle_task_delegation_child_and_agent",
        "settle_recursive_noninteractive_child_outcome",
        "drain_task_delegation_steers",
    ] {
        assert!(
            noninteractive.contains(required),
            "background task path lost {required}"
        );
    }
    for required in [
        "begin_delivery",
        "abandon_auto_resolution",
        "record_late_user_decision_steer",
        "reconcile_pending_requests",
        "resolve_host_approval",
        "decision_owner_is_live",
        "resolve_user_answer",
        "expire_deadline",
        "TerminalDeadlineSettlement",
        "request_decision_for_interrupt",
    ] {
        assert!(runtime.contains(required), "runtime lost {required}");
    }
    assert!(
        dispatch.contains("refresh_host_capabilities_request")
            && dispatch.contains("AuthorizeHostCapabilitiesRefresh")
            && dispatch.contains("require_attached(state)")
            && dispatch.contains("host capability refresh was declined by its durable decision"),
        "the real low-risk host effect must wait for an attached durable AgentTree continuation"
    );
    for required in [
        "set_agent_auto_answer_from_resolved_profile",
        "release_agent_resume_claim",
        "release_late_user_decision_steer_claim",
        "task_delegation_binding_for_agent",
        "task_delegation_is_noninteractive_for_agent",
        "task_delegation_recovery_descriptor",
        "persist_task_delegation_snapshot",
        "create_recursive_noninteractive_executors_and_checkpoint_parent",
        "complete_recursive_noninteractive_children_and_checkpoint_parent",
        "recursive_noninteractive_recovery_descriptor",
        "recursive_noninteractive_executors",
        "recursive_noninteractive_outcomes",
        "settle_task_delegation_child_and_agent",
        "settle_recursive_noninteractive_child_outcome",
        "agent_host_approval_operations",
        "agent_host_approval_effect_handoffs",
        "existing final interrupt",
        "reserve_host_approval_final_operation",
        "consume_host_approval_final_operation",
        "complete_host_approval_final_operation",
        "claim_host_approval_effect_handoff",
        "claimed_host_approval_effect_handoff_matches_candidate",
        "reject_unclaimed_host_approval_final_operation",
        "host_approval_operation_has_exact_interrupt",
        "validate_host_approval_response_against_offered_interrupt",
        "submission_unknown",
        "host approval final operation was not reserved",
        "root_agent_continuations",
        "persist_session_root_agent_continuation",
        "completed_unpublished_host_capability_refresh_operations",
        "mark_host_capability_refresh_published",
        "reap_stale_host_capability_refresh_operations",
        "reap_stale_host_capability_refresh_operations_globally",
    ] {
        assert!(
            persistence.contains(required),
            "persistence lost {required}"
        );
    }
    for required in [
        "park_interrupt",
        "complete_executing_interrupt",
        "interrupt_question_occurrence",
        "decision_attention_mutation_guards",
        "attention_transition",
    ] {
        assert!(
            attention_persistence.contains(required),
            "QuestionTool continuation persistence lost {required}"
        );
    }
    for required in [
        "needs_attention_decision_owned_update",
        "OLD.state = 'open'",
        "NEW.state = 'parked'",
        "agent_host_approval_operation_matches_decision",
        "agent_host_approval_operation_must_start_unbound",
        "agent_host_approval_effect_handoff_matches_operation",
        "agent_host_approval_operation_state_is_forward_only",
        "ready' AND NEW.state IN ('dispatching', 'rejected')",
        "approved' AND NEW.state IN ('dispatching', 'rejected', 'cancelled')",
        "recursive_noninteractive_outcomes",
        "must exist before its decision",
        "root_agent_continuations",
        "host_capability_refresh_operation_publication_is_forward_only",
    ] {
        assert!(
            migration.contains(required),
            "0001 lifecycle enforcement lost {required}"
        );
    }

    // The cross-language daemon contract cannot silently lose the lifecycle
    // surface or accept Rust-rejected nil IDs while the Rust fixtures evolve.
    for required in [
        "nonNilUuidSchema",
        "read_agent_tree",
        "read_agent_attention",
        "resolve_agent_decision",
        "agent_tree_changed",
    ] {
        assert!(protocol.contains(required), "protocol lost {required}");
    }
    for (fixture, required) in [
        (requests, "read_agent_tree"),
        (requests, "read_agent_attention"),
        (requests, "resolve_agent_decision"),
        (responses, "agent_tree_page"),
        (responses, "agent_attention_page"),
        (responses, "agent_decision_steered"),
        (events, "agent_tree_changed"),
    ] {
        assert!(fixture.contains(required), "wire fixture lost {required}");
        assert!(
            !fixture.contains("00000000-0000-0000-0000-000000000000"),
            "agent-tree wire fixture must not normalize a nil UUID"
        );
    }
}

/// A recovered executor becomes addressable before the worker consumes its
/// durable claim.  This source-level crash-window ratchet keeps that ordering
/// explicit across root, foreground, single/batch detached, and recursive
/// reconstruction, while the driver unit test exercises the gate itself.
#[test]
fn recovered_executors_publish_then_claim_then_activate_or_abort() {
    let worker = include_str!("../src/daemon/session_worker/run.rs");
    let driver = include_str!("../src/engine/driver/mod.rs");
    let noninteractive = include_str!("../src/engine/driver/noninteractive.rs");

    for required in [
        "pub struct RecoveryActivationGate",
        "set_root_recovery_activation",
        "recovery_activation: Some(recovery.activation_gate)",
        "recovered executor activation was aborted",
    ] {
        assert!(
            driver.contains(required),
            "driver lost recovery gate: {required}"
        );
    }
    for required in [
        "activation_gate: RecoveryActivationGate",
        "Some(recovery.activation_gate)",
        "activation_gate.clone()",
        "gate.wait().await",
        "recover_pending_recursive_continuation",
    ] {
        assert!(
            noninteractive.contains(required),
            "noninteractive recovery lost activation gate: {required}"
        );
    }
    for required in [
        "let root_activation_gate",
        "root_activation_gate.as_ref()",
        "ReattachInteractiveTaskChild",
        "ReattachNoninteractiveTaskChild",
        "ReattachNoninteractiveTaskBatch",
        "activation_gate.abort()",
        "activation_gate.release()",
        "consume_agent_resume_claims_atomically",
    ] {
        assert!(
            worker.contains(required),
            "worker lost recovery gate: {required}"
        );
    }

    let root = worker
        .split("let root_activation_gate")
        .nth(1)
        .expect("root recovery activation must be installed");
    assert!(
        root.find(".consume_agent_resume_claim(")
            .expect("root claim consumption")
            < root
                .find("gate.release()")
                .expect("root activation release"),
        "root must consume its exact claim before activation"
    );

    // Every recovered detached path passes the same barrier into the executor
    // before the all-or-nothing claim transaction, and releases it only after
    // that transaction.  This is the important ordering if the process dies
    // between endpoint publication and claim acknowledgement.
    for branch in [
        worker
            .split("if batch_job")
            .nth(1)
            .expect("batch recovery branch"),
        worker
            .split("ReattachNoninteractiveTaskChild")
            .nth(1)
            .expect("single noninteractive recovery branch"),
        worker
            .split("ReattachInteractiveTaskChild")
            .nth(1)
            .expect("interactive recovery branch"),
    ] {
        let consume = branch
            .find("consume_agent_resume_claim")
            .expect("recovered branch consumes an exact claim");
        let release = branch
            .find("activation_gate.release()")
            .expect("recovered branch releases after claim");
        assert!(
            consume < release,
            "recovered branch activates before its claim"
        );
    }
    let publication = noninteractive
        .split("NoninteractiveAgentTreeEndpointRegistration")
        .nth(1)
        .expect("noninteractive endpoint registration");
    assert!(
        publication
            .find("collector.register")
            .expect("recursive descendants publish endpoints")
            < publication
                .find("gate.wait().await")
                .expect("recovered executor waits for activation"),
        "recursive endpoints must publish before the shared claim/activation barrier"
    );
}

/// `SetAgent` crosses both the remote-operation ledger and the live driver.
/// Keep those authorities ordered so a rejected/replayed remote request cannot
/// mutate the worker, and a post-profile installed-root rebuild failure cannot
/// leave a stale driver serving a committed root while returning an error.
#[test]
fn set_agent_admits_durably_then_applies_or_closes_for_recovery() {
    let dispatch = include_str!("../src/daemon/server/dispatch.rs");
    let worker = include_str!("../src/daemon/session_worker/run.rs");

    let set_agent = dispatch
        .split("Request::SetAgent { name } => {")
        .nth(1)
        .expect("SetAgent dispatch branch exists")
        .split("Request::SetToolSurfaceOverride")
        .next()
        .expect("SetAgent dispatch branch is bounded");
    let durable_admission = set_agent
        .find("execute_idempotent_adapter_remote_operation")
        .expect("remote SetAgent has durable adapter admission");
    let replay_lookup = set_agent
        .find("lookup_committed_remote_operation")
        .expect("remote SetAgent resolves its committed receipt before mutable validation");
    let fresh_remote_validation = set_agent
        .rfind("validate_set_agent(ctx, att, &name)?")
        .expect("fresh remote SetAgent validates current availability");
    let replay_return = set_agent
        .find("TransactionalRemoteOperationOutcome::Replay(bytes) => return")
        .expect("remote SetAgent replay returns directly");
    let worker_dispatch = set_agent
        .find(".send_work(SessionWork::SetAgent")
        .expect("SetAgent reaches the attached worker");
    assert!(
        durable_admission < worker_dispatch,
        "remote desired state and receipt must commit before worker mutation"
    );
    assert!(
        replay_lookup < fresh_remote_validation && fresh_remote_validation < durable_admission,
        "exact remote replay/conflict must resolve before mutable ownability, which applies only to a fresh operation"
    );
    assert!(
        replay_return < worker_dispatch,
        "an exact replay must return without worker reexecution"
    );
    for required in [
        "set_remote_session_agent_conn",
        "TransactionalRemoteMutation",
        "durable_selection_committed",
        "remote_response.as_ref()",
    ] {
        assert!(
            set_agent.contains(required),
            "SetAgent durable adapter path lost {required}"
        );
    }

    let installed_apply = worker
        .split("Ok(Some(prepared)) => {")
        .nth(1)
        .expect("installed SetAgent apply branch exists")
        .split("Ok(None) => {")
        .next()
        .expect("installed SetAgent apply branch is bounded");
    for required in [
        "SwapPreparedPrimary",
        "respond_to.send(Ok(()))",
        "pause_for_resume: true",
        "prepared installed root could not be applied live",
    ] {
        assert!(
            installed_apply.contains(required),
            "installed SetAgent recovery path lost {required}"
        );
    }
    assert!(
        !installed_apply.contains("respond_to.send(Err("),
        "a committed installed selection must not return a contradictory error"
    );

    let preparation_error = worker
        .split("Err(error) => {")
        .filter(|branch| branch.contains("durable_selection_committed || committed_profile"))
        .next()
        .expect("SetAgent preparation error checks durable authority");
    for required in [
        "agent_profile_snapshot(session.id)",
        "durable_selection_committed || committed_profile",
        "respond_to.send(Ok(()))",
        "pause_for_resume: true",
    ] {
        assert!(
            preparation_error.contains(required),
            "SetAgent preparation recovery lost {required}"
        );
    }

    let startup_prepare = worker
        .split("pub(crate) async fn prepare_fresh_installed_root_snapshot")
        .nth(1)
        .expect("installed-root startup preparation exists")
        .split("async fn prepare_installed_root_snapshot_named")
        .next()
        .expect("installed-root startup preparation is bounded");
    for required in [
        "agent_profile_snapshot(session.id)",
        "pending_remote_agent_selection",
        "return Ok(None)",
    ] {
        assert!(
            startup_prepare.contains(required),
            "snapshotless remote SetAgent recovery lost {required}"
        );
    }
    assert!(
        startup_prepare.contains("snapshotless_remote_reconciliation_required"),
        "snapshotless recovery must bind the remote marker to the selected root"
    );
}

#[test]
fn private_child_binding_receipts_are_scoped_to_reviewed_parent_generation() {
    let worker = include_str!("../src/daemon/session_worker/run.rs");
    let key = worker
        .split("let idempotency_key = format!(")
        .nth(1)
        .expect("package-child binding key exists")
        .split("slot_bindings.push")
        .next()
        .expect("package-child binding key is bounded");
    for generation in [
        "parent.installation_revision",
        "parent_observation.observation_revision",
        "parent.source_digest",
    ] {
        assert!(
            key.contains(generation),
            "package-child binding receipt lost parent-generation component {generation}"
        );
    }
}
