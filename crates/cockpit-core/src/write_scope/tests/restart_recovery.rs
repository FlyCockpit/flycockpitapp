//! AC9 — `spawn_restart_recovery`.
//!
//! Crash after every phase; child never started / live / terminal / unknown;
//! containment and lease generation match and mismatch; repeated recovery;
//! generation monotonicity; and no dual owner.

use crate::write_scope::coordinator::RecoveryOutcome;
use crate::write_scope::fake::FakeEmptyBehavior;
use crate::write_scope::types::TransferPhase;

use super::Harness;

/// Drive a transfer up to (and including) `phase`, then stop — simulating a
/// crash immediately after that phase was durably recorded.
async fn crash_after(h: &Harness, phase: TransferPhase) -> (uuid::Uuid, uuid::Uuid) {
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    if phase == TransferPhase::Prepared {
        // Simulate process death immediately after the durable Prepared step:
        // write exactly what `begin_transfer` writes, then stop. Driving
        // `begin_transfer` with a failing containment would NOT reproduce this,
        // because the coordinator now unwinds eagerly — which is the behaviour
        // `containment_create_failure_unwinds_before_exclusion_and_user_code`
        // covers.
        let parent =
            h.db.get_write_scope_lease(parent_lease_id)
                .await
                .unwrap()
                .unwrap();
        let scope = h.scope("a");
        let (_, transfer) =
            h.db.prepare_write_scope_transfer(
                crate::db::write_scope_leases::CasWriteScopeLease {
                    lease_id: parent.lease_id,
                    expected_state: parent.state.clone(),
                    expected_generation: parent.generation,
                    expected_version: parent.version,
                    new_state: "transferring".into(),
                    new_generation: parent.generation + 1,
                    now_wall_ms: 1,
                    released: false,
                },
                crate::db::write_scope_leases::WriteScopeTransferRow {
                    transfer_id: uuid::Uuid::new_v4(),
                    session_id: h.session_id,
                    parent_lease_id: parent.lease_id,
                    child_lease_id: None,
                    sub_scope_path: scope.path().display().to_string(),
                    phase: "prepared".into(),
                    prepare_parent_generation: parent.generation,
                    parent_generation: parent.generation + 1,
                    child_generation: None,
                    restored_parent_generation: None,
                    backend_kind: "fake_mediated_cow".into(),
                    capability: "proven".into(),
                    unsupported_reason: None,
                    containment_id: None,
                    containment_generation: None,
                    publication_identity: None,
                    execution_permit_id: None,
                    recovery_phase: Some("pending".into()),
                    version: 1,
                    created_at_wall_ms: 1,
                    updated_at_wall_ms: 1,
                },
            )
            .await
            .unwrap()
            .expect("prepare succeeds");
        return (parent_lease_id, transfer.transfer_id);
    }

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent_lease_id, "a"))
        .await
        .expect("transfer begins");

    match phase {
        TransferPhase::ChildActivated => {}
        TransferPhase::ChildTerminal => {
            h.coordinator
                .child_terminal(handle.transfer_id)
                .await
                .unwrap();
        }
        _ => {}
    }
    (parent_lease_id, handle.transfer_id)
}

#[tokio::test]
async fn crash_after_prepared_leaves_nothing_to_resume() {
    let (h, _backend) = Harness::proven().await;
    let (_parent, transfer_id) = crash_after(&h, TransferPhase::Prepared).await;

    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert_eq!(
        outcomes,
        vec![RecoveryOutcome::ReturnAdvanced { transfer_id }],
        "a crash before exclusion hands nothing over"
    );
}

#[tokio::test]
async fn crash_with_a_live_child_resumes_child_ownership() {
    let (h, _backend) = Harness::proven().await;
    let (_parent, transfer_id) = crash_after(&h, TransferPhase::ChildActivated).await;

    // Proven populated containment == the child is alive and still owns it.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::ProvenPopulated);
    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert!(
        matches!(
            outcomes.as_slice(),
            [RecoveryOutcome::ChildResumedOwnership { transfer_id: t, .. }] if *t == transfer_id
        ),
        "got {outcomes:?}"
    );
}

#[tokio::test]
async fn crash_with_a_terminal_child_advances_the_return_only_when_proven_empty() {
    let (h, _backend) = Harness::proven().await;
    let (_parent, transfer_id) = crash_after(&h, TransferPhase::ChildTerminal).await;

    // Not proven empty -> retained, authority stays with the child.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::Uncertain {
            reason: "kill acknowledgement lost".into(),
        });
    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert!(
        matches!(
            outcomes.as_slice(),
            [RecoveryOutcome::RetainedNotProvenEmpty { transfer_id: t, .. }] if *t == transfer_id
        ),
        "got {outcomes:?}"
    );

    // Proven empty -> the return may advance.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::ProvenEmpty);
    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert_eq!(
        outcomes,
        vec![RecoveryOutcome::ReturnAdvanced { transfer_id }]
    );
}

#[tokio::test]
async fn unknown_containment_state_stays_denied() {
    let (h, _backend) = Harness::proven().await;
    let (_parent, transfer_id) = crash_after(&h, TransferPhase::ChildActivated).await;

    // The platform cannot say anything about this generation.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::Unsupported {
            reason: "no oracle for this generation".into(),
        });
    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert!(
        matches!(
            outcomes.as_slice(),
            [RecoveryOutcome::Denied { transfer_id: t, .. }] if *t == transfer_id
        ),
        "an unknown containment must stay denied, got {outcomes:?}"
    );
}

#[tokio::test]
async fn a_child_activated_row_without_a_child_lease_is_denied() {
    // Durable mismatch: the phase claims a child exists but no lease does.
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    // Corrupt the durable row the way a torn write would.
    let transfer =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert!(transfer.child_lease_id.is_some());

    // A row in child_activated with no containment is equally unmatched.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::Unsupported {
            reason: "generation mismatch".into(),
        });
    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert!(
        outcomes
            .iter()
            .all(|o| matches!(o, RecoveryOutcome::Denied { .. })),
        "mismatch must remain denied, got {outcomes:?}"
    );
}

#[tokio::test]
async fn recovery_is_repeatable_and_never_creates_a_second_owner() {
    let (h, _backend) = Harness::proven().await;
    let (parent_lease_id, _transfer_id) = crash_after(&h, TransferPhase::ChildActivated).await;

    h.containment
        .set_empty_behavior(FakeEmptyBehavior::ProvenPopulated);

    let first = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    let second = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    let third = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert_eq!(first, second);
    assert_eq!(second, third, "repeated recovery must be idempotent");

    // Still exactly one child lease — no dual owner.
    let children =
        h.db.list_child_write_scope_leases(parent_lease_id)
            .await
            .unwrap();
    assert_eq!(children.len(), 1, "recovery must never mint a second owner");

    // And the parent is still excluded from the delegated subtree.
    let authority = h
        .coordinator
        .effective_authority(parent_lease_id)
        .await
        .unwrap();
    assert!(!authority.allows_path(&h.root().join("a/file.txt")));
}

#[tokio::test]
async fn generations_stay_monotonic_across_a_recovery_cycle() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent_lease_id, "a"))
        .await
        .unwrap();
    let after_transfer =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();

    h.containment
        .set_empty_behavior(FakeEmptyBehavior::ProvenPopulated);
    h.coordinator.recover(Some(h.session_id)).await.unwrap();

    let after_recovery =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();
    assert!(
        after_recovery.generation >= after_transfer.generation,
        "recovery must never rewind a generation"
    );

    // Finish the transfer normally; the generation still only moves forward.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::ProvenEmpty);
    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();
    let restored = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap();
    assert!(restored.generation() > after_recovery.generation);
}

#[tokio::test]
async fn a_committed_transfer_is_not_reprocessed() {
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
    h.coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap();

    // Committed rows are not open, so recovery finds nothing to do.
    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert!(
        outcomes.is_empty(),
        "a committed transfer must not be reprocessed, got {outcomes:?}"
    );
}

// ---------------------------------------------------------------------------
// Recovery must change durable state, not merely report an enum.
//
// The suite previously asserted only the returned `RecoveryOutcome`, which a
// no-op implementation satisfies trivially. These assert the durable effects.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovering_a_prepared_crash_actually_returns_authority_to_the_parent() {
    let (h, _backend) = Harness::proven().await;
    let (parent_lease_id, transfer_id) = crash_after(&h, TransferPhase::Prepared).await;

    // Before recovery the parent is stranded mid-transfer.
    let before =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        before.state, "transferring",
        "precondition: the crash left the parent mid-transfer"
    );

    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert_eq!(
        outcomes,
        vec![RecoveryOutcome::ReturnAdvanced { transfer_id }]
    );

    // Durable effects, not just the enum:
    let after =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(after.state, "active", "recovery must restore the parent");
    assert!(
        after.generation > before.generation,
        "restoration moves the generation forward"
    );

    let transfer =
        h.db.get_write_scope_transfer(transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        transfer.phase, "committed",
        "an abandoned transfer must be retired, not left to be rediscovered"
    );
    assert_eq!(transfer.recovery_phase.as_deref(), Some("reconciled"));

    // Nothing is left held.
    assert!(
        h.db.list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .is_empty()
    );

    // And the parent can immediately delegate again.
    assert!(
        h.coordinator
            .begin_transfer(h.request(parent_lease_id, "a"))
            .await
            .is_ok(),
        "a recovered parent must be usable again"
    );
}

#[tokio::test]
async fn recovering_an_empty_activated_child_completes_the_whole_return() {
    let (h, backend) = Harness::proven().await;
    let (parent_lease_id, transfer_id) = crash_after(&h, TransferPhase::ChildActivated).await;

    let transfer_before =
        h.db.get_write_scope_transfer(transfer_id)
            .await
            .unwrap()
            .unwrap();
    let child_lease_id = transfer_before.child_lease_id.unwrap();
    let permit_id = transfer_before.execution_permit_id.unwrap();
    let publishes_before = backend.publish_count();

    // The child's containment is provably empty: the return must be driven all
    // the way through, exactly as the live path would.
    h.containment
        .set_empty_behavior(FakeEmptyBehavior::ProvenEmpty);
    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert_eq!(
        outcomes,
        vec![RecoveryOutcome::ReturnAdvanced { transfer_id }]
    );

    // Publication actually happened.
    assert_eq!(
        backend.publish_count(),
        publishes_before + 1,
        "recovery must resolve the broker publication"
    );

    // The execution permit was released.
    let permit =
        h.db.get_write_scope_permit(permit_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(permit.state, "released");

    // The child lease was released and the parent restored.
    let child =
        h.db.get_write_scope_lease(child_lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(child.state, "released");
    let parent =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(parent.state, "active");

    // The transfer is committed, and the parent's authority is whole again.
    let transfer =
        h.db.get_write_scope_transfer(transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(transfer.phase, "committed");
    let authority = h
        .coordinator
        .effective_authority(parent_lease_id)
        .await
        .unwrap();
    assert!(
        authority.allows_path(&h.root().join("a/file.txt")),
        "the reclaimed sub-scope must be writable by the parent again"
    );
}

#[tokio::test]
async fn recovery_never_restores_authority_while_containment_is_uncertain() {
    let (h, backend) = Harness::proven().await;
    let (parent_lease_id, transfer_id) = crash_after(&h, TransferPhase::ChildActivated).await;
    let publishes_before = backend.publish_count();

    h.containment
        .set_empty_behavior(FakeEmptyBehavior::Uncertain {
            reason: "kill acknowledgement lost".into(),
        });
    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert!(
        matches!(
            outcomes.as_slice(),
            [RecoveryOutcome::RetainedNotProvenEmpty { .. }]
        ),
        "got {outcomes:?}"
    );

    // No publication, no restoration, permit still held.
    assert_eq!(backend.publish_count(), publishes_before);
    let parent =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(parent.state, "delegated");
    assert!(
        !h.db
            .list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .is_empty()
    );
    let transfer =
        h.db.get_write_scope_transfer(transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert_ne!(transfer.phase, "committed");
}

// ---------------------------------------------------------------------------
// AC9 phase-boundary coverage: ParentExcluded and ParentRestored.
//
// The `crash_after` helper cannot reach these two, because the live coordinator
// never pauses there — ParentExcluded and ChildActivated are adjacent within one
// `serial`-held critical section, and ParentRestored is followed immediately by
// Committed. A crash between them is nonetheless reachable in production (the
// process can die between two durable writes), so these build the durable crash
// image directly and then call the real `recover`.
// ---------------------------------------------------------------------------

/// Build a durable image of "crashed at ParentExcluded": the parent is excluded
/// and a containment plus execution permit exist, but no child lease was ever
/// created.
async fn crash_at_parent_excluded(
    h: &Harness,
    empty_behavior: FakeEmptyBehavior,
) -> (uuid::Uuid, uuid::Uuid, uuid::Uuid) {
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();
    let scope = h.scope("a");

    let parent_row =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();

    // Prepared, atomically, exactly as `begin_transfer` does.
    let (_, transfer) =
        h.db.prepare_write_scope_transfer(
            crate::db::write_scope_leases::CasWriteScopeLease {
                lease_id: parent_lease_id,
                expected_state: parent_row.state.clone(),
                expected_generation: parent_row.generation,
                expected_version: parent_row.version,
                new_state: "transferring".into(),
                new_generation: parent_row.generation + 1,
                now_wall_ms: 1,
                released: false,
            },
            crate::db::write_scope_leases::WriteScopeTransferRow {
                transfer_id: uuid::Uuid::new_v4(),
                session_id: h.session_id,
                parent_lease_id,
                child_lease_id: None,
                sub_scope_path: scope.path().display().to_string(),
                phase: "prepared".into(),
                prepare_parent_generation: parent_row.generation,
                parent_generation: parent_row.generation + 1,
                child_generation: None,
                restored_parent_generation: None,
                backend_kind: "fake_mediated_cow".into(),
                capability: "proven".into(),
                unsupported_reason: None,
                containment_id: None,
                containment_generation: None,
                publication_identity: None,
                execution_permit_id: None,
                recovery_phase: Some("pending".into()),
                version: 1,
                created_at_wall_ms: 1,
                updated_at_wall_ms: 1,
            },
        )
        .await
        .unwrap()
        .unwrap();

    // The execution-wide permit reserved during acquisition.
    let permit =
        h.db.insert_write_scope_permit(crate::db::write_scope_leases::WriteScopePermitRow {
            permit_id: uuid::Uuid::new_v4(),
            session_id: h.session_id,
            lease_id: parent_lease_id,
            generation: parent_row.generation + 1,
            kind: "execution".into(),
            influence_kind: "rename".into(),
            influence_root: scope.path().display().to_string(),
            target_path: scope.path().display().to_string(),
            state: "held".into(),
            containment_id: None,
            acquired_at_wall_ms: 1,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();

    // ParentExcluded, carrying the containment and its own generation.
    let containment_id = uuid::Uuid::new_v4();
    h.db.cas_write_scope_transfer_phase(crate::db::write_scope_leases::CasWriteScopeTransfer {
        transfer_id: transfer.transfer_id,
        expected_phase: "prepared".into(),
        expected_version: transfer.version,
        new_phase: "parent_excluded".into(),
        now_wall_ms: 2,
        child_lease_id: None,
        parent_generation: None,
        child_generation: None,
        restored_parent_generation: None,
        containment_id: Some(containment_id),
        containment_generation: Some(7),
        publication_identity: Some(Some("1000".into())),
        execution_permit_id: Some(permit.permit_id),
        recovery_phase: None,
    })
    .await
    .unwrap()
    .unwrap();

    h.containment.set_empty_behavior(empty_behavior);
    (parent_lease_id, transfer.transfer_id, permit.permit_id)
}

#[tokio::test]
async fn crash_at_parent_excluded_reclaims_authority_once_containment_is_empty() {
    let (h, _backend) = Harness::proven().await;
    let (parent_lease_id, transfer_id, permit_id) =
        crash_at_parent_excluded(&h, FakeEmptyBehavior::ProvenEmptyAtGeneration(7)).await;

    // Precondition: the parent is stranded and the permit is held.
    let before =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(before.state, "transferring");
    assert_eq!(
        h.db.get_write_scope_permit(permit_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "held"
    );

    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert_eq!(
        outcomes,
        vec![RecoveryOutcome::ReturnAdvanced { transfer_id }]
    );

    // Durable effects: permit released, transfer retired, parent restored.
    assert_eq!(
        h.db.get_write_scope_permit(permit_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "released"
    );
    let transfer =
        h.db.get_write_scope_transfer(transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(transfer.phase, "committed");
    assert_eq!(transfer.recovery_phase.as_deref(), Some("reconciled"));
    assert!(transfer.child_lease_id.is_none(), "no child ever existed");

    let after =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(after.state, "active");
    assert!(after.generation > before.generation);

    // The reclaimed sub-scope is writable by the parent again.
    let authority = h
        .coordinator
        .effective_authority(parent_lease_id)
        .await
        .unwrap();
    assert!(authority.allows_path(&h.root().join("a/file.txt")));
}

#[tokio::test]
async fn crash_at_parent_excluded_retains_everything_while_containment_is_uncertain() {
    let (h, _backend) = Harness::proven().await;
    let (parent_lease_id, transfer_id, permit_id) = crash_at_parent_excluded(
        &h,
        FakeEmptyBehavior::Uncertain {
            reason: "kill acknowledgement lost".into(),
        },
    )
    .await;

    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert!(
        matches!(
            outcomes.as_slice(),
            [RecoveryOutcome::RetainedNotProvenEmpty { transfer_id: t, .. }] if *t == transfer_id
        ),
        "got {outcomes:?}"
    );

    // Nothing released, nothing restored — user code may still be running.
    assert_eq!(
        h.db.get_write_scope_permit(permit_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "held"
    );
    assert_eq!(
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "transferring"
    );
    let transfer =
        h.db.get_write_scope_transfer(transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert_ne!(transfer.phase, "committed");

    // The parent is still denied inside the delegated sub-scope.
    let authority = h
        .coordinator
        .effective_authority(parent_lease_id)
        .await
        .unwrap();
    assert!(!authority.allows_path(&h.root().join("a/file.txt")));
}

#[tokio::test]
async fn crash_at_parent_excluded_with_a_foreign_containment_generation_is_denied() {
    // The oracle answers ProvenEmpty, but for a generation that is not this
    // transfer's. That is not evidence about this child.
    let (h, _backend) = Harness::proven().await;
    let (parent_lease_id, transfer_id, permit_id) =
        crash_at_parent_excluded(&h, FakeEmptyBehavior::ProvenEmptyAtGeneration(99)).await;

    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert!(
        matches!(
            outcomes.as_slice(),
            [RecoveryOutcome::Denied { transfer_id: t, .. }] if *t == transfer_id
        ),
        "a foreign containment generation must be denied, got {outcomes:?}"
    );

    // Denied means nothing moves.
    assert_eq!(
        h.db.get_write_scope_permit(permit_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "held"
    );
    assert_eq!(
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "transferring"
    );
}

#[tokio::test]
async fn crash_at_parent_restored_only_needs_the_committed_marker() {
    // Authority was already handed back; the process died before writing
    // Committed. Recovery must finish the marker and change nothing else.
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

    // Drive the live return, then rewind ONLY the committed marker by
    // reconstructing the parent_restored image.
    h.coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap();
    let committed =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(committed.phase, "committed");

    // A second recovery pass must treat it as already committed, not reprocess.
    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert!(
        outcomes.is_empty(),
        "a committed transfer is not open and must not be reprocessed: {outcomes:?}"
    );

    // Parent authority is intact and whole.
    let parent_row =
        h.db.get_write_scope_lease(parent.lease_id())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(parent_row.state, "active");
    let authority = h
        .coordinator
        .effective_authority(parent.lease_id())
        .await
        .unwrap();
    assert!(authority.allows_path(&h.root().join("a/file.txt")));
}

/// Insert a durable containment row for `transfer_id` under the *derived*
/// operation id, simulating a crash that landed between
/// `ContainmentBarrier::create` and the ownership attach: the containment (and
/// the user code inside it) exists, but nothing on the transfer row points at
/// it.
async fn containment_created_but_never_attached(
    h: &Harness,
    transfer_id: uuid::Uuid,
    state: &str,
) -> uuid::Uuid {
    let containment_id = uuid::Uuid::new_v4();
    h.db.insert_execution_containment(crate::db::execution_containments::ExecutionContainmentRow {
        containment_id,
        session_id: h.session_id,
        // HARD-CODED on purpose: calling `write_scope_containment_operation_id`
        // here would couple the test to the implementation, so a derivation
        // changed on both sides would still pass. Pin the documented contract
        // instead — `write-scope-{transfer_id}`.
        operation_id: format!("write-scope-{transfer_id}"),
        generation: 1,
        platform_kind: "fake".into(),
        state: state.into(),
        guarantee: "proven".into(),
        platform_locator_json: "{}".into(),
        runtime_context_digest: None,
        unsupported_reason: None,
        created_at_wall_ms: 1,
        updated_at_wall_ms: 1,
        emptied_at_wall_ms: None,
    })
    .await
    .expect("containment row inserts");
    containment_id
}

#[tokio::test]
async fn crash_between_containment_create_and_ownership_attach_does_not_reclaim_the_scope() {
    let (h, _backend) = Harness::proven().await;
    let (parent_lease_id, transfer_id) = crash_after(&h, TransferPhase::Prepared).await;

    // The transfer row carries no containment ticket — the attach never ran.
    let transfer =
        h.db.get_write_scope_transfer(transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert!(
        transfer.containment_id.is_none(),
        "precondition: the crash landed before the ownership attach"
    );

    // ...but a live containment exists, findable only via the derived
    // operation id. Recovery must NOT hand the parent back a scope whose child
    // may still be writing to it.
    containment_created_but_never_attached(&h, transfer_id, "active").await;

    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert!(
        matches!(
            outcomes.as_slice(),
            [RecoveryOutcome::RetainedNotProvenEmpty { transfer_id: t, .. }] if *t == transfer_id
        ),
        "an orphaned live containment must retain the transfer, got {outcomes:?}"
    );

    // The parent must still be `transferring`: authority was not restored.
    let parent_row =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        parent_row.state, "transferring",
        "parent authority must not be restored while a child may be running"
    );
}

#[tokio::test]
async fn crash_before_the_attach_still_reclaims_when_the_containment_is_proven_empty() {
    let (h, _backend) = Harness::proven().await;
    let (parent_lease_id, transfer_id) = crash_after(&h, TransferPhase::Prepared).await;

    // Same orphaned containment, but the platform already proved it empty.
    // The retention above must be caused by liveness, not merely by the row
    // existing — otherwise the fix would strand every crashed transfer forever.
    containment_created_but_never_attached(&h, transfer_id, "empty").await;

    let outcomes = h.coordinator.recover(Some(h.session_id)).await.unwrap();
    assert_eq!(
        outcomes,
        vec![RecoveryOutcome::ReturnAdvanced { transfer_id }],
        "a proven-empty orphan must not strand the parent"
    );

    let parent_row =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(parent_row.state, "active");
}

/// The production seam: drive the REAL `ProcessContainmentBarrier` through a
/// real transfer and assert on the row it actually PERSISTED.
///
/// Only the *platform* is faked here — `FakeProvenAdapter` stands in for the
/// OS and reports `Proven`, which the real barrier's release path requires.
/// Everything the linkage depends on (the witness, the derivation, `create`,
/// the durable insert) is production code.
///
/// This closes a gap the other tests cannot. The orphan tests above pin
/// recovery's *lookup* to the documented `write-scope-{transfer_id}` format,
/// and the source inventory pins `create` to the derivation helper — but if
/// `OwnershipReserved::containment_operation_id` itself stopped calling that
/// helper, every one of them would still pass while the link silently broke.
/// This test compares the persisted `execution_containments` row against the
/// format spelled out literally below, sharing no helper with the code under
/// test on either side.
#[tokio::test]
async fn production_barrier_persists_the_transfer_derived_operation_id() {
    use std::sync::Arc;

    let workspace = tempfile::tempdir().expect("workspace tempdir");
    std::fs::create_dir_all(workspace.path().join("a")).unwrap();

    let db = crate::db::Db::open_in_memory().expect("in-memory db");
    let session_id = db
        .create_session(
            "proj",
            &workspace.path().display().to_string(),
            "orchestrator-build",
        )
        .await
        .expect("session")
        .session_id;

    let adapter = Arc::new(crate::process_containment::FakeProvenAdapter::new(
        crate::process_containment::PlatformKind::Fake,
    ));
    let actor = crate::process_containment::ProcessContainmentActor::start(db.clone(), adapter);
    let barrier = Arc::new(crate::write_scope::ProcessContainmentBarrier::new(
        actor.handle(),
    ));

    let coordinator = crate::write_scope::WriteScopeCoordinator::new(
        db.clone(),
        Arc::new(crate::write_scope::fake::FakeMediatedCowBackend::new()),
        barrier,
        Arc::new(crate::write_scope::RecordingEventSink::new()),
        super::test_clock(),
    );

    let root = crate::write_scope::CanonicalScope::from_canonical(
        cockpit_host::path_containment::effective_path(workspace.path())
            .expect("canonical workspace"),
    );
    let parent = coordinator
        .open_root_lease(session_id, "parent", root)
        .await
        .expect("root lease opens");
    let sub_scope = crate::write_scope::CanonicalScope::resolve_under(workspace.path(), "a")
        .expect("sub-scope resolves");

    let result = coordinator
        .begin_transfer(crate::write_scope::TransferRequest {
            parent_lease_id: parent.lease_id(),
            session_id,
            sub_scope,
            child_owner_id: "child-a".into(),
            task_id: Some("task-a".into()),
            mode: crate::write_scope::ExecutionMode::Native,
            launch: crate::write_scope::ExecutionLaunch::Native {
                program: "/bin/true".into(),
                args: Vec::new(),
                cwd: workspace.path().to_path_buf(),
            },
            reachable_ancestor: None,
        })
        .await;

    // Deliberately not `.expect(...)`. The claim under test is about what
    // `create` persisted, which happens before the rest of the transfer; if a
    // later step fails, the error surfaces in the assertions below rather than
    // masking the linkage check.
    let transfer_id = match &result {
        Ok(handle) => handle.transfer_id,
        Err(_) => {
            let transfers = db
                .list_open_write_scope_transfers(Some(session_id))
                .await
                .expect("transfer rows");
            assert_eq!(
                transfers.len(),
                1,
                "expected exactly one transfer row; begin_transfer returned {result:?}"
            );
            transfers[0].transfer_id
        }
    };

    let rows = db
        .list_execution_containments_for_session(session_id)
        .await
        .expect("containment rows");
    assert_eq!(
        rows.len(),
        1,
        "production `create` must have persisted exactly one containment row; \
         begin_transfer returned {result:?}"
    );
    assert_eq!(
        rows[0].operation_id,
        format!("write-scope-{transfer_id}"),
        "production `create` must persist the transfer-derived operation id. If this \
         drifts, a crash between `create` and the ownership attach leaves recovery unable \
         to find the live containment, and parent authority is restored to a scope a \
         child is still writing to."
    );
}
