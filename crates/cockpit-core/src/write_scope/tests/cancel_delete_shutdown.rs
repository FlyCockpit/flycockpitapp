//! AC10 — `spawn_cancel_delete_shutdown_barriers`.
//!
//! Nested bottom-up cancellation, session Deleting, daemon shutdown, kill
//! failure, Uncertain recovery, retained permit/lease/transfer rows, and no
//! authority restoration / deletion / clean status before ProvenEmpty and
//! permit release.

use crate::write_scope::fake::FakeEmptyBehavior;
use crate::write_scope::types::WriteScopeError;

use super::Harness;

#[tokio::test]
async fn nested_cancellation_unwinds_bottom_up() {
    let (h, _backend) = Harness::proven().await;
    let root = h.open_root("root").await;

    // root -> a -> a/inner
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

    // The outer child cannot return while its own child still holds authority:
    // the inner transfer must be committed first.
    h.coordinator
        .child_terminal(outer.transfer_id)
        .await
        .unwrap();

    // Bottom-up: finish the inner one first.
    h.coordinator
        .child_terminal(inner.transfer_id)
        .await
        .unwrap();
    h.coordinator
        .complete_return(inner.transfer_id)
        .await
        .unwrap();

    // Now the outer return succeeds.
    let restored = h
        .coordinator
        .complete_return(outer.transfer_id)
        .await
        .unwrap();
    assert!(restored.is_valid());

    // Everything drained.
    assert!(
        h.db.list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn session_deleting_blocks_new_transfers_and_retains_state() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    let blockers = h
        .coordinator
        .begin_session_deletion(h.session_id)
        .await
        .unwrap();
    assert!(
        !blockers.is_empty(),
        "live leases and held permits must block deletion"
    );

    // New transfers are refused while Deleting.
    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "b"))
        .await
        .unwrap_err();
    assert!(matches!(err, WriteScopeError::SessionDeleting), "got {err}");

    // Session/authority state is retained, not torn down.
    assert!(
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        h.db.get_write_scope_permit(handle.execution_permit_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        !h.db
            .list_live_write_scope_leases(Some(h.session_id))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn deletion_blockers_clear_only_after_proven_empty_and_permit_release() {
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

    // Kill fails / acknowledgement lost -> Uncertain. Blockers remain.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::Uncertain {
            reason: "kill failed".into(),
        });
    assert!(
        h.coordinator
            .complete_return(handle.transfer_id)
            .await
            .is_err()
    );
    let blockers = h.coordinator.deletion_blockers(h.session_id).await.unwrap();
    assert!(
        blockers.contains(&handle.execution_permit_id),
        "the held execution permit must still block deletion"
    );

    // ProvenEmpty -> the return completes and the permit is released.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::ProvenEmpty);
    h.coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap();
    let blockers = h.coordinator.deletion_blockers(h.session_id).await.unwrap();
    assert!(
        !blockers.contains(&handle.execution_permit_id),
        "the permit no longer blocks once released"
    );
    assert!(
        h.db.list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn shutdown_closes_intake_and_cannot_report_clean_while_anything_is_held() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    h.coordinator.begin_shutdown().await.unwrap();

    // Intake is closed.
    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "b"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::ShutdownIntakeClosed),
        "got {err}"
    );

    // Not clean: a live lease and a held permit remain.
    assert!(
        h.coordinator.assert_shutdown_clean().await.is_err(),
        "shutdown must not report clean while authority is outstanding"
    );

    // Drain properly.
    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();
    h.coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap();

    // Now clean: the delegated child returned and every permit drained. The
    // session's own root lease remains live and must NOT block — it is baseline
    // authority, not outstanding delegated authority.
    assert!(
        h.coordinator.assert_shutdown_clean().await.is_ok(),
        "a session root lease must not keep shutdown from reporting clean"
    );
    assert!(
        h.db.list_held_write_scope_permits(None)
            .await
            .unwrap()
            .is_empty(),
        "all permits drained"
    );
    assert!(
        !h.db
            .list_live_write_scope_leases(None)
            .await
            .unwrap()
            .is_empty(),
        "the root lease is still live — that is exactly what must not block"
    );
}

/// A session whose only write-scope state is its own root lease must remain
/// deletable, and shutdown must still report clean.
///
/// Regression guard: the session worker opens a root lease for every session, so
/// treating any live lease as a blocker would make every session permanently
/// undeletable and force-abort every daemon shutdown.
#[tokio::test]
async fn a_bare_session_root_lease_blocks_neither_deletion_nor_shutdown() {
    let (h, _backend) = Harness::proven().await;
    let root = h
        .coordinator
        .ensure_session_root_lease(h.session_id, "session-root", h.root_scope())
        .await
        .unwrap();

    // The root really is live.
    let live =
        h.db.list_live_write_scope_leases(Some(h.session_id))
            .await
            .unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].lease_id, root);
    assert!(live[0].parent_lease_id.is_none());

    assert!(
        h.coordinator
            .deletion_blockers(h.session_id)
            .await
            .unwrap()
            .is_empty(),
        "a bare root lease must not block deletion"
    );
    assert!(
        h.coordinator
            .begin_session_deletion(h.session_id)
            .await
            .unwrap()
            .is_empty(),
        "deletion must be admitted"
    );
    assert!(
        h.coordinator.assert_shutdown_clean().await.is_ok(),
        "a bare root lease must not make shutdown unclean"
    );
}

/// But a *delegated* child lease does block both, because someone else still
/// owns a subtree.
#[tokio::test]
async fn a_delegated_child_lease_blocks_deletion_and_shutdown() {
    let (h, _backend) = Harness::proven().await;
    let root = h
        .coordinator
        .ensure_session_root_lease(h.session_id, "session-root", h.root_scope())
        .await
        .unwrap();
    let handle = h
        .coordinator
        .begin_transfer(h.request(root, "a"))
        .await
        .unwrap();

    let blockers = h.coordinator.deletion_blockers(h.session_id).await.unwrap();
    assert!(
        blockers.contains(&handle.child_token.lease_id()),
        "the delegated child lease must block deletion: {blockers:?}"
    );
    assert!(
        blockers.contains(&handle.execution_permit_id),
        "the held execution permit must block deletion: {blockers:?}"
    );
    assert!(h.coordinator.assert_shutdown_clean().await.is_err());

    // After the child returns, only the root remains and both clear.
    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();
    h.coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap();
    assert!(
        h.coordinator
            .deletion_blockers(h.session_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(h.coordinator.assert_shutdown_clean().await.is_ok());
}

#[tokio::test]
async fn an_uncertain_containment_never_restores_parent_authority() {
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

    h.containment
        .set_empty_behavior(FakeEmptyBehavior::Uncertain {
            reason: "remove acknowledgement lost".into(),
        });

    for _ in 0..3 {
        let err = h
            .coordinator
            .complete_return(handle.transfer_id)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            WriteScopeError::ContainmentNotProvenEmpty { .. }
        ));
    }

    // The parent is still Delegated and still denied inside the sub-scope.
    let row =
        h.db.get_write_scope_lease(parent.lease_id())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.state, "delegated");
    let authority = h
        .coordinator
        .effective_authority(parent.lease_id())
        .await
        .unwrap();
    assert!(!authority.allows_path(&h.root().join("a/x.txt")));

    // Rows are retained for recovery.
    let transfer =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(transfer.phase, "child_terminal");
    let permit =
        h.db.get_write_scope_permit(handle.execution_permit_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(permit.state, "held");
}
