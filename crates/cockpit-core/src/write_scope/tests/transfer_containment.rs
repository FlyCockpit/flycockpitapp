//! AC7 — `spawn_transfer_uses_proven_backend_and_containment`.
//!
//! Capability + execution-wide permit + containment are acquired before any
//! native spawn or runtime-container create/exec. The direct backend is
//! Unsupported before ParentExcluded. Nothing restores authority before the
//! exact child containment is ProvenEmpty, publication is resolved, and the
//! permit is released. Unwind ordering is exact on every failure point.

use crate::write_scope::backend::ExecutionMode;
use crate::write_scope::fake::{BarrierCall, FakeEmptyBehavior};
use crate::write_scope::types::WriteScopeError;

use super::Harness;

#[tokio::test]
async fn acquisition_order_is_permit_then_capability_then_containment_then_user_code() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    let calls = h.containment.calls();
    // Containment is created, then user code is released — never the reverse.
    assert!(matches!(calls[0], BarrierCall::Create { .. }), "{calls:?}");
    assert!(
        matches!(calls[1], BarrierCall::ReleaseUserCode { .. }),
        "{calls:?}"
    );

    // The execution-wide permit exists and is held.
    let permit =
        h.db.get_write_scope_permit(handle.execution_permit_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(permit.kind, "execution");
    assert_eq!(permit.state, "held");

    // It is recorded on the transfer row alongside the containment.
    let transfer =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        transfer.execution_permit_id,
        Some(handle.execution_permit_id)
    );
    assert_eq!(
        transfer.containment_id,
        Some(handle.containment.containment_id)
    );
}

#[tokio::test]
async fn every_runtime_mode_takes_the_same_barrier_with_a_proven_backend() {
    for mode in ExecutionMode::ALL {
        let (h, _backend) = Harness::proven().await;
        let parent = h.open_root("parent").await;
        let mut request = h.request(parent.lease_id(), "a");
        request.mode = *mode;

        let handle = h
            .coordinator
            .begin_transfer(request)
            .await
            .unwrap_or_else(|e| panic!("{} should transfer: {e}", mode.as_str()));

        assert_eq!(h.containment.created_count(), 1, "{}", mode.as_str());
        assert!(
            !h.containment.user_code_never_released(),
            "{} should have released user code",
            mode.as_str()
        );
        assert!(handle.child_token.is_valid());
    }
}

#[tokio::test]
async fn containment_create_failure_unwinds_before_exclusion_and_user_code() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    h.containment.fail_create_with("cgroup unavailable");

    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap_err();
    assert!(err.is_unsupported(), "got {err}");

    // No user code, no child lease, and the parent is back to Active.
    assert!(h.containment.user_code_never_released());
    assert!(
        h.db.list_child_write_scope_leases(parent.lease_id())
            .await
            .unwrap()
            .is_empty()
    );
    let row =
        h.db.get_write_scope_lease(parent.lease_id())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.state, "active");

    // The reserved execution permit was released as part of the unwind.
    assert!(
        h.db.list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .is_empty(),
        "a failed acquisition must not leak a held permit"
    );

    // A failed acquisition retires its own transfer rather than leaving an open
    // row behind: nothing was ever handed over, so there is nothing for recovery
    // to reconcile later.
    let open =
        h.db.list_open_write_scope_transfers(Some(h.session_id))
            .await
            .unwrap();
    assert!(
        open.is_empty(),
        "no open transfer may be left behind: {open:?}"
    );
    let all =
        h.db.list_write_scope_transfers_for_parent(parent.lease_id())
            .await
            .unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].phase, "committed");
    assert_eq!(all[0].recovery_phase.as_deref(), Some("reconciled"));
    assert!(all[0].child_lease_id.is_none());
}

#[tokio::test]
async fn membership_proof_failure_terminates_containment_and_unwinds() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    h.containment
        .fail_release_with("could not prove runtime ownership");

    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap_err();
    assert!(err.is_unsupported(), "got {err}");

    // Containment was created, then terminated — exact unwind ordering.
    let calls = h.containment.calls();
    assert!(matches!(calls[0], BarrierCall::Create { .. }), "{calls:?}");
    assert!(
        matches!(calls[1], BarrierCall::Terminate { .. }),
        "a created containment must be torn down on failure: {calls:?}"
    );
    assert!(h.containment.user_code_never_released());
    assert_eq!(h.containment.terminated_count(), 1);

    // No child, no held permit, parent restored.
    assert!(
        h.db.list_child_write_scope_leases(parent.lease_id())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        h.db.list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn authority_is_not_restored_until_the_exact_containment_is_proven_empty() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();
    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();

    // Immediate-child exit is not enough: descendants may still be alive.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::ProvenPopulated);
    let err = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::ContainmentNotProvenEmpty { .. }),
        "got {err}"
    );
    let row =
        h.db.get_write_scope_lease(parent.lease_id())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.state, "delegated", "parent must stay excluded");

    // A lost kill/wait/remove acknowledgement is also not enough.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::Uncertain {
            reason: "remove acknowledgement lost".into(),
        });
    assert!(
        h.coordinator
            .complete_return(handle.transfer_id)
            .await
            .is_err()
    );
    // The execution permit is still held throughout.
    assert!(
        !h.db
            .list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .is_empty()
    );

    // Only ProvenEmpty releases the barrier.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::ProvenEmpty);
    let restored = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap();
    assert!(restored.is_valid());
    assert!(
        h.db.list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .is_empty(),
        "the execution permit is released only after ProvenEmpty"
    );
}

#[tokio::test]
async fn the_execution_permit_outlives_the_immediate_child_exit() {
    // The permit must be held across background/double-forked descendants and
    // later container execs, not released when the first process exits.
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    // Immediate child exits -> ChildTerminal. The permit stays held.
    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();
    let permit =
        h.db.get_write_scope_permit(handle.execution_permit_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        permit.state, "held",
        "an execution permit must survive the immediate child's exit"
    );

    // Descendants still alive -> still held.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::ProvenPopulated);
    let _ = h.coordinator.complete_return(handle.transfer_id).await;
    let permit =
        h.db.get_write_scope_permit(handle.execution_permit_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(permit.state, "held");
}

#[tokio::test]
async fn a_second_transfer_waits_while_a_sibling_execution_permit_overlaps() {
    // Delegation starts no child while a parent execution-wide permit overlaps
    // the requested subtree.
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    // The first child's execution permit is widened to reach `a`'s ancestor,
    // so it overlaps a later request for a sibling under that ancestor.
    let mut first = h.request(parent.lease_id(), "a/inner");
    first.reachable_ancestor = Some(h.root().join("a"));
    let handle = h.coordinator.begin_transfer(first).await.unwrap();

    // The execution permit belongs to the parent lease and covers `a`.
    let permit =
        h.db.get_write_scope_permit(handle.execution_permit_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(permit.lease_id, parent.lease_id());
    assert_eq!(
        permit.influence_root,
        h.root().join("a").display().to_string()
    );

    // A transfer of another subtree under `a` must not activate.
    std::fs::create_dir_all(h.root().join("a/other")).unwrap();
    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a/other"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::PermitsNotDrained { .. }),
        "got {err}"
    );

    // No second child was created.
    assert_eq!(
        h.db.list_child_write_scope_leases(parent.lease_id())
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn cancellation_converges_through_the_same_phases() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    // Cancellation is just an early ChildTerminal; the return barrier is
    // identical to the happy path.
    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();
    assert!(!handle.child_token.is_valid());

    let restored = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap();
    assert!(restored.is_valid());
    let transfer =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(transfer.phase, "committed");
}

/// Regression guard for the ordering the spec makes central: the
/// overlapping-permit barrier drains BEFORE containment exists and before any
/// user code runs. Creating containment first would run user code inside a
/// scope whose authority is still contested.
#[tokio::test]
async fn the_drain_barrier_precedes_containment_and_user_code() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    let in_flight = h
        .coordinator
        .acquire_mutation_permit(
            &parent,
            &h.root().join("a/inner/busy.txt"),
            crate::write_scope::MutationKind::WriteContent,
        )
        .await
        .unwrap();

    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::PermitsNotDrained { .. }),
        "got {err}"
    );

    // The decisive assertions: containment was never created, so user code
    // never had anywhere to run.
    assert_eq!(
        h.containment.created_count(),
        0,
        "containment must not be created before the barrier drains"
    );
    assert!(h.containment.user_code_never_released());
    assert_eq!(h.containment.terminated_count(), 0);

    h.coordinator
        .release_mutation_permit(in_flight)
        .await
        .unwrap();
}

/// A sibling transfer that widened its reachable ancestor records its execution
/// permit under a different lease. A per-lease drain query would miss it.
#[tokio::test]
async fn a_widened_sibling_execution_permit_blocks_across_leases() {
    let (h, _backend) = Harness::proven().await;
    let root = h.open_root("root").await;

    // Child A owns /a and its handover permit is widened to the workspace root.
    let mut first = h.request(root.lease_id(), "a");
    first.reachable_ancestor = Some(h.root().to_path_buf());
    let a = h.coordinator.begin_transfer(first).await.unwrap();

    // A nested transfer under A must still work: A's own handover permit covers
    // A's scope, and blocking on it would make nesting impossible.
    assert!(
        h.coordinator
            .begin_transfer(h.request(a.child_token.lease_id(), "a/inner"))
            .await
            .is_ok(),
        "nested delegation must not block on its own handover permit"
    );

    // But a sibling under the root IS blocked by A's widened influence.
    let err = h
        .coordinator
        .begin_transfer(h.request(root.lease_id(), "b"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::PermitsNotDrained { .. }),
        "a widened sibling permit must block across leases, got {err}"
    );
}

/// The parent may not reclaim a scope while a grandchild still owns part of it.
#[tokio::test]
async fn a_live_descendant_blocks_parent_restoration() {
    let (h, _backend) = Harness::proven().await;
    let root = h.open_root("root").await;

    let outer = h
        .coordinator
        .begin_transfer(h.request(root.lease_id(), "a"))
        .await
        .unwrap();
    let inner = h
        .coordinator
        .begin_transfer(h.request(outer.child_token.lease_id(), "a/inner"))
        .await
        .unwrap();

    h.coordinator
        .child_terminal(outer.transfer_id)
        .await
        .unwrap();

    // The grandchild still owns /a/inner, so /a must not go back to the root.
    let err = h
        .coordinator
        .complete_return(outer.transfer_id)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            WriteScopeError::DescendantStillDelegated { count: 1, .. }
        ),
        "got {err}"
    );
    let row =
        h.db.get_write_scope_lease(root.lease_id())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.state, "delegated");

    // Once the grandchild returns, the outer return succeeds.
    h.coordinator
        .child_terminal(inner.transfer_id)
        .await
        .unwrap();
    h.coordinator
        .complete_return(inner.transfer_id)
        .await
        .unwrap();
    assert!(
        h.coordinator
            .complete_return(outer.transfer_id)
            .await
            .is_ok()
    );
}

/// The containment generation is its own counter. An oracle answering for a
/// different generation is not evidence about this child.
#[tokio::test]
async fn a_containment_generation_mismatch_is_not_evidence() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    let transfer =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap();
    let recorded = transfer
        .containment_generation
        .expect("containment generation is persisted");
    assert_eq!(recorded, handle.containment.generation);

    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();

    // The oracle answers ProvenEmpty, but for a different generation.
    h.containment.set_empty_behavior(
        crate::write_scope::fake::FakeEmptyBehavior::ProvenEmptyAtGeneration(recorded + 41),
    );
    let err = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::ContainmentGenerationMismatch { .. }),
        "got {err}"
    );

    // Correct generation completes the return.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::ProvenEmpty);
    assert!(
        h.coordinator
            .complete_return(handle.transfer_id)
            .await
            .is_ok()
    );
}
