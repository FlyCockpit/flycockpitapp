//! AC8 — `spawn_concurrent_transfer_cas`.
//!
//! Same-parent disjoint and overlapping contenders, stale versions, effective
//! exclusion recomputation, one linearized winner per overlap, and zero
//! records/tokens/events for losers.

use std::sync::Arc;

use crate::db::write_scope_leases::CasWriteScopeLease;
use crate::write_scope::events::WriteScopeEvent;
use crate::write_scope::types::WriteScopeError;

use super::Harness;

#[tokio::test]
async fn disjoint_contenders_all_win() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    // Three disjoint subtrees can be delegated concurrently: disjoint authority
    // is exactly what this system is for.
    let mut children = Vec::new();
    for relative in ["a", "b", "shared"] {
        let handle = h
            .coordinator
            .begin_transfer(h.request(parent_lease_id, relative))
            .await
            .unwrap_or_else(|e| panic!("{relative}: {e}"));
        children.push(handle);
    }
    assert_eq!(children.len(), 3);

    let leases =
        h.db.list_child_write_scope_leases(parent_lease_id)
            .await
            .unwrap();
    assert_eq!(leases.len(), 3);

    // Pairwise disjoint scopes.
    for i in 0..children.len() {
        for j in (i + 1)..children.len() {
            assert!(
                children[i]
                    .child_token
                    .scope()
                    .is_disjoint_from(children[j].child_token.scope()),
                "children must hold pairwise disjoint authority"
            );
        }
    }
}

#[tokio::test]
async fn overlapping_contenders_produce_exactly_one_winner() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    // `a`, `a/inner`, and `a` again all overlap. Only one may win.
    let contenders = ["a", "a/inner", "a"];
    let mut winners = 0;
    let mut losers = 0;
    for relative in contenders {
        match h
            .coordinator
            .begin_transfer(h.request(parent_lease_id, relative))
            .await
        {
            Ok(_) => winners += 1,
            Err(WriteScopeError::IntersectsDelegatedExclusion { .. }) => losers += 1,
            Err(other) => panic!("unexpected error for {relative}: {other}"),
        }
    }
    assert_eq!(winners, 1, "exactly one contender may win an overlap");
    assert_eq!(losers, 2);

    // Exactly one child lease exists.
    assert_eq!(
        h.db.list_child_write_scope_leases(parent_lease_id)
            .await
            .unwrap()
            .len(),
        1
    );
    // Exactly one activation event.
    assert_eq!(
        h.events
            .events()
            .iter()
            .filter(|e| matches!(e, WriteScopeEvent::ChildActivated { .. }))
            .count(),
        1
    );
}

#[tokio::test]
async fn losers_create_no_record_token_or_event() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    h.coordinator
        .begin_transfer(h.request(parent_lease_id, "a"))
        .await
        .unwrap();

    let leases_before =
        h.db.list_child_write_scope_leases(parent_lease_id)
            .await
            .unwrap()
            .len();
    let transfers_before =
        h.db.list_write_scope_transfers_for_parent(parent_lease_id)
            .await
            .unwrap()
            .len();
    let events_before = h.events.count();
    let permits_before =
        h.db.list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .len();

    // Five losing attempts.
    for _ in 0..5 {
        let err = h
            .coordinator
            .begin_transfer(h.request(parent_lease_id, "a/inner"))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            WriteScopeError::IntersectsDelegatedExclusion { .. }
        ));
    }

    assert_eq!(
        h.db.list_child_write_scope_leases(parent_lease_id)
            .await
            .unwrap()
            .len(),
        leases_before,
        "a loser must create no child lease"
    );
    assert_eq!(
        h.db.list_write_scope_transfers_for_parent(parent_lease_id)
            .await
            .unwrap()
            .len(),
        transfers_before,
        "a loser must create no transfer row"
    );
    assert_eq!(
        h.events.count(),
        events_before,
        "a loser must emit no event"
    );
    assert_eq!(
        h.db.list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .len(),
        permits_before,
        "a loser must leave no permit behind"
    );
}

#[tokio::test]
async fn each_contender_recomputes_against_the_latest_exclusions() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    // Before any delegation, `a/inner` is admissible.
    let authority = h
        .coordinator
        .effective_authority(parent_lease_id)
        .await
        .unwrap();
    assert!(authority.admits_subscope(&h.scope("a/inner")).is_ok());

    // Delegate `a`. The very next contender must see the new exclusion.
    h.coordinator
        .begin_transfer(h.request(parent_lease_id, "a"))
        .await
        .unwrap();
    let authority = h
        .coordinator
        .effective_authority(parent_lease_id)
        .await
        .unwrap();
    assert!(
        authority.admits_subscope(&h.scope("a/inner")).is_err(),
        "a contender must recompute against the latest effective exclusions"
    );

    // After the return, it becomes admissible again.
    let transfers =
        h.db.list_write_scope_transfers_for_parent(parent_lease_id)
            .await
            .unwrap();
    let transfer_id = transfers[0].transfer_id;
    h.coordinator.child_terminal(transfer_id).await.unwrap();
    h.coordinator.complete_return(transfer_id).await.unwrap();

    let authority = h
        .coordinator
        .effective_authority(parent_lease_id)
        .await
        .unwrap();
    assert!(authority.admits_subscope(&h.scope("a/inner")).is_ok());
}

#[tokio::test]
async fn a_stale_version_loses_even_with_the_right_state_and_generation() {
    let h = Harness::direct().await;
    let token = h.open_root("owner").await;
    let original =
        h.db.get_write_scope_lease(token.lease_id())
            .await
            .unwrap()
            .unwrap();

    // Someone else advances the version without changing state semantics.
    h.db.cas_write_scope_lease(CasWriteScopeLease {
        lease_id: original.lease_id,
        expected_state: "active".into(),
        expected_generation: original.generation,
        expected_version: original.version,
        new_state: "transferring".into(),
        new_generation: original.generation + 1,
        now_wall_ms: 10,
        released: false,
    })
    .await
    .unwrap()
    .unwrap();
    h.db.cas_write_scope_lease(CasWriteScopeLease {
        lease_id: original.lease_id,
        expected_state: "transferring".into(),
        expected_generation: original.generation + 1,
        expected_version: original.version + 1,
        new_state: "active".into(),
        new_generation: original.generation + 2,
        now_wall_ms: 11,
        released: false,
    })
    .await
    .unwrap()
    .unwrap();

    let current =
        h.db.get_write_scope_lease(original.lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(current.state, "active");

    // A contender with the right state and generation but a stale version loses.
    let lost =
        h.db.cas_write_scope_lease(CasWriteScopeLease {
            lease_id: original.lease_id,
            expected_state: "active".into(),
            expected_generation: current.generation,
            expected_version: original.version,
            new_state: "transferring".into(),
            new_generation: current.generation + 1,
            now_wall_ms: 12,
            released: false,
        })
        .await
        .unwrap();
    assert!(lost.is_none(), "a stale version must lose");
    assert_eq!(
        h.db.get_write_scope_lease(original.lease_id)
            .await
            .unwrap()
            .unwrap(),
        current,
        "the losing CAS changed nothing"
    );
}

#[tokio::test]
async fn concurrent_overlapping_transfers_linearize_to_one_winner() {
    // Drive the contenders through the real async coordinator concurrently.
    let (h, _backend) = Harness::proven().await;
    let h = Arc::new(h);
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    let mut tasks = Vec::new();
    for relative in ["a", "a/inner", "a", "a/inner"] {
        let h = h.clone();
        let request = h.request(parent_lease_id, relative);
        tasks.push(tokio::spawn(async move {
            h.coordinator.begin_transfer(request).await.is_ok()
        }));
    }

    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(
        winners, 1,
        "overlapping contenders must linearize to exactly one winner"
    );
    assert_eq!(
        h.db.list_child_write_scope_leases(parent_lease_id)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn concurrent_disjoint_transfers_all_succeed_without_interference() {
    let (h, _backend) = Harness::proven().await;
    let h = Arc::new(h);
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    let mut tasks = Vec::new();
    for relative in ["a", "b", "shared", "ab"] {
        let h = h.clone();
        let request = h.request(parent_lease_id, relative);
        tasks.push(tokio::spawn(async move {
            h.coordinator.begin_transfer(request).await.is_ok()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 4, "disjoint contenders must not block each other");

    let leases =
        h.db.list_child_write_scope_leases(parent_lease_id)
            .await
            .unwrap();
    assert_eq!(leases.len(), 4);
}
