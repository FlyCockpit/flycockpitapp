//! AC2 — `spawn_lease_schema_and_state_machine`.
//!
//! Every state and phase, the exact parent/child generation increments, token
//! replacement and invalidation, monotonic non-reuse, and legal/illegal CAS
//! transitions.

use crate::db::write_scope_leases::{
    CasWriteScopeLease, LEASE_STATES, TRANSFER_PHASES, transfer_phase_ordinal,
};
use crate::write_scope::types::{LeaseState, TransferPhase};

use super::Harness;

#[test]
fn every_declared_state_and_phase_round_trips_through_storage_labels() {
    // The Rust enum and the SQL CHECK constraint must agree exactly, or a
    // legal transition would be rejected at write time.
    let rust_states: Vec<&str> = [
        LeaseState::Active,
        LeaseState::Transferring,
        LeaseState::Delegated,
        LeaseState::Returning,
        LeaseState::Released,
    ]
    .iter()
    .map(|s| s.as_str())
    .collect();
    assert_eq!(rust_states, LEASE_STATES);
    for state in LEASE_STATES {
        assert!(LeaseState::parse(state).is_some(), "{state}");
    }

    let rust_phases: Vec<&str> = TransferPhase::ALL.iter().map(|p| p.as_str()).collect();
    assert_eq!(rust_phases, TRANSFER_PHASES);
    for (i, phase) in TRANSFER_PHASES.iter().enumerate() {
        assert_eq!(transfer_phase_ordinal(phase), Some(i));
        assert_eq!(
            TransferPhase::parse(phase).map(TransferPhase::ordinal),
            Some(i)
        );
    }
}

#[test]
fn legal_and_illegal_transitions_are_exhaustively_specified() {
    use LeaseState::*;
    let all = [Active, Transferring, Delegated, Returning, Released];
    let legal = [
        (Active, Transferring),
        (Active, Released),
        (Transferring, Delegated),
        (Transferring, Active),
        // A parent that already delegated one sub-scope may delegate another
        // disjoint one; it still holds authority elsewhere.
        (Delegated, Transferring),
        (Delegated, Returning),
        (Delegated, Released),
        (Returning, Active),
        // Returning while other children remain delegated.
        (Returning, Delegated),
        (Returning, Released),
    ];
    for from in all {
        for to in all {
            let expected = legal.contains(&(from, to));
            assert_eq!(
                from.can_transition_to(to),
                expected,
                "{from:?} -> {to:?} should be {}",
                if expected { "legal" } else { "illegal" }
            );
        }
    }
    // Released is a sink: nothing leaves it.
    for to in all {
        assert!(!Released.can_transition_to(to), "Released -> {to:?}");
    }
}

#[tokio::test]
async fn transfer_walks_exact_generation_increments_and_replaces_tokens() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    // Parent starts at g = 1.
    assert_eq!(parent.generation(), 1);
    assert!(parent.is_valid());

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent_lease_id, "a"))
        .await
        .expect("proven backend permits the transfer");

    // Prepared CASed Active(1) -> Transferring(2); ParentExcluded issued the
    // replacement parent token at g+1 = 2.
    assert_eq!(handle.parent_token.generation(), 2);
    // ChildActivated created the child at g+2 = 3.
    assert_eq!(handle.child_token.generation(), 3);

    // The original g=1 parent token was invalidated by the generation bump.
    assert!(
        !parent.is_valid(),
        "the pre-transfer parent token must be invalidated"
    );
    assert!(handle.parent_token.is_valid());
    assert!(handle.child_token.is_valid());

    // ChildTerminal invalidates the child token before return begins.
    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();
    assert!(
        !handle.child_token.is_valid(),
        "child token must be dead before return begins"
    );

    // ParentRestored increments the parent again and issues a fresh
    // full-authority token.
    let restored = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .expect("return completes");
    assert!(
        restored.generation() > handle.parent_token.generation(),
        "restored generation {} must exceed excluded generation {}",
        restored.generation(),
        handle.parent_token.generation()
    );
    assert!(restored.is_valid());
    // Every older parent token is now invalid.
    assert!(!handle.parent_token.is_valid());
}

#[tokio::test]
async fn generations_never_decrement_or_get_reused_across_repeated_transfers() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    let mut seen_parent_generations = vec![parent.generation()];

    for relative in ["a", "b", "shared"] {
        let handle = h
            .coordinator
            .begin_transfer(h.request(parent_lease_id, relative))
            .await
            .unwrap_or_else(|e| panic!("transfer of {relative} should succeed: {e}"));
        seen_parent_generations.push(handle.parent_token.generation());
        h.coordinator
            .child_terminal(handle.transfer_id)
            .await
            .unwrap();
        let restored = h
            .coordinator
            .complete_return(handle.transfer_id)
            .await
            .unwrap();
        seen_parent_generations.push(restored.generation());
    }

    // Strictly increasing: never decrements, never reused.
    for pair in seen_parent_generations.windows(2) {
        assert!(
            pair[1] > pair[0],
            "generation sequence must strictly increase, got {seen_parent_generations:?}"
        );
    }
    let mut sorted = seen_parent_generations.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        seen_parent_generations.len(),
        "no generation may be reused: {seen_parent_generations:?}"
    );
}

#[tokio::test]
async fn an_unwound_transfer_still_moves_the_generation_forward() {
    // Rollback must never reuse a generation, so the unwind CASes forward.
    let h = Harness::direct().await;
    let parent = h.open_root("parent").await;
    let before =
        h.db.get_write_scope_lease(parent.lease_id())
            .await
            .unwrap()
            .unwrap();

    // Direct backend refuses, so nothing is ever prepared and the generation
    // is untouched.
    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap_err();
    assert!(err.is_unsupported());

    let after =
        h.db.get_write_scope_lease(parent.lease_id())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        after.generation, before.generation,
        "a fail-fast refusal must not churn the parent generation"
    );
    assert_eq!(after.state, "active");

    // Now force the unwind *after* Prepared by failing containment creation.
    let (h2, _backend) = Harness::proven().await;
    let parent2 = h2.open_root("parent").await;
    h2.containment.fail_create_with("no containment available");
    let before2 = h2
        .db
        .get_write_scope_lease(parent2.lease_id())
        .await
        .unwrap()
        .unwrap();
    let err = h2
        .coordinator
        .begin_transfer(h2.request(parent2.lease_id(), "a"))
        .await
        .unwrap_err();
    assert!(err.is_unsupported(), "{err}");
    let after2 = h2
        .db
        .get_write_scope_lease(parent2.lease_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after2.state, "active", "parent authority is restored");
    assert!(
        after2.generation > before2.generation,
        "unwind moves the generation forward ({} -> {})",
        before2.generation,
        after2.generation
    );
}

#[tokio::test]
async fn stale_cas_expectations_lose_without_mutating_authority() {
    let h = Harness::direct().await;
    let token = h.open_root("owner").await;
    let row =
        h.db.get_write_scope_lease(token.lease_id())
            .await
            .unwrap()
            .unwrap();

    // Correct expectation wins.
    let won =
        h.db.cas_write_scope_lease(CasWriteScopeLease {
            lease_id: row.lease_id,
            expected_state: "active".into(),
            expected_generation: row.generation,
            expected_version: row.version,
            new_state: "transferring".into(),
            new_generation: row.generation + 1,
            now_wall_ms: 1,
            released: false,
        })
        .await
        .unwrap();
    assert!(won.is_some());

    // Replaying the same (now stale) expectation loses and changes nothing.
    let after_win =
        h.db.get_write_scope_lease(row.lease_id)
            .await
            .unwrap()
            .unwrap();
    let lost =
        h.db.cas_write_scope_lease(CasWriteScopeLease {
            lease_id: row.lease_id,
            expected_state: "active".into(),
            expected_generation: row.generation,
            expected_version: row.version,
            new_state: "transferring".into(),
            new_generation: row.generation + 1,
            now_wall_ms: 2,
            released: false,
        })
        .await
        .unwrap();
    assert!(lost.is_none());
    let after_loss =
        h.db.get_write_scope_lease(row.lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(after_win, after_loss, "a losing CAS must be a no-op");
}

#[tokio::test]
async fn illegal_phase_advances_are_refused_by_the_coordinator() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    // Skipping ChildTerminal and going straight to return must fail: the child
    // token would still be live while the parent reclaims authority.
    let err = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            crate::write_scope::WriteScopeError::IllegalPhaseAdvance { .. }
        ),
        "expected an illegal phase advance, got {err}"
    );
}

// ---------------------------------------------------------------------------
// Session root lease — the authority every delegation descends from, opened by
// the session worker at startup and drained by deletion/shutdown.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_session_root_lease_is_found_and_opened_idempotently() {
    let (h, _backend) = Harness::proven().await;

    // No root yet.
    assert!(
        h.coordinator
            .session_root_lease(h.session_id)
            .await
            .unwrap()
            .is_none()
    );

    let first = h
        .coordinator
        .ensure_session_root_lease(h.session_id, "session-root", h.root_scope())
        .await
        .unwrap();

    // Idempotent: a worker restart must reuse the root, never mint a second.
    let second = h
        .coordinator
        .ensure_session_root_lease(h.session_id, "session-root", h.root_scope())
        .await
        .unwrap();
    assert_eq!(first, second, "a second root lease must never be created");

    let roots =
        h.db.list_write_scope_leases_for_session(h.session_id)
            .await
            .unwrap()
            .into_iter()
            .filter(|l| l.parent_lease_id.is_none())
            .count();
    assert_eq!(roots, 1);

    assert_eq!(
        h.coordinator
            .session_root_lease(h.session_id)
            .await
            .unwrap(),
        Some(first)
    );

    // A delegation descends from it, and the child is not mistaken for a root.
    let handle = h
        .coordinator
        .begin_transfer(h.request(first, "a"))
        .await
        .unwrap();
    assert_eq!(
        h.coordinator
            .session_root_lease(h.session_id)
            .await
            .unwrap(),
        Some(first),
        "the child lease must not be reported as the session root"
    );
    assert_ne!(handle.child_token.lease_id(), first);
}

#[tokio::test]
async fn a_released_root_is_not_reported_as_the_session_root() {
    let (h, _backend) = Harness::proven().await;
    let root = h
        .coordinator
        .ensure_session_root_lease(h.session_id, "session-root", h.root_scope())
        .await
        .unwrap();

    let row = h.db.get_write_scope_lease(root).await.unwrap().unwrap();
    h.db.cas_write_scope_lease(crate::db::write_scope_leases::CasWriteScopeLease {
        lease_id: root,
        expected_state: row.state.clone(),
        expected_generation: row.generation,
        expected_version: row.version,
        new_state: "released".into(),
        new_generation: row.generation + 1,
        now_wall_ms: 9_000,
        released: true,
    })
    .await
    .unwrap()
    .unwrap();

    assert!(
        h.coordinator
            .session_root_lease(h.session_id)
            .await
            .unwrap()
            .is_none(),
        "a released root holds no authority and must not be delegated from"
    );
}
