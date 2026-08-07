//! AC4 — `spawn_parent_exclusion_and_restore`.
//!
//! Outside writes are allowed under the replacement token, inside writes are
//! denied, and the activation/return barriers land at exactly the right phases.

use crate::write_scope::permits::MutationKind;
use crate::write_scope::types::{TransferPhase, WriteScopeError};

use super::Harness;

#[tokio::test]
async fn parent_writes_outside_the_subscope_under_the_replacement_token() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    // The replacement token (generation g+1) still writes everywhere else.
    let permit = h
        .coordinator
        .acquire_mutation_permit(
            &handle.parent_token,
            &h.root().join("b/out.txt"),
            MutationKind::WriteContent,
        )
        .await
        .expect("outside the delegated sub-scope is allowed");
    assert_eq!(permit.effective_target(), h.root().join("b/out.txt"));
    h.coordinator.release_mutation_permit(permit).await.unwrap();
}

#[tokio::test]
async fn parent_is_denied_inside_the_delegated_subscope() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    for target in ["a/file.txt", "a/inner/deep.txt", "a"] {
        let err = h
            .coordinator
            .acquire_mutation_permit(
                &handle.parent_token,
                &h.root().join(target),
                MutationKind::WriteContent,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, WriteScopeError::DeniedInsideDelegatedSubscope { .. }),
            "`{target}` must be denied to the parent, got {err}"
        );
    }
}

#[tokio::test]
async fn the_superseded_parent_token_cannot_write_anywhere() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    // The pre-transfer token is from generation g; it is invalid even for a
    // path that is still perfectly inside the parent's effective authority.
    let err = h
        .coordinator
        .acquire_mutation_permit(
            &parent,
            &h.root().join("b/x.txt"),
            MutationKind::WriteContent,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::StaleGeneration { .. }),
        "got {err}"
    );
    let _ = handle;
}

#[tokio::test]
async fn the_child_writes_inside_its_scope_and_nowhere_else() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    let permit = h
        .coordinator
        .acquire_mutation_permit(
            &handle.child_token,
            &h.root().join("a/inner/result.txt"),
            MutationKind::WriteContent,
        )
        .await
        .expect("child writes inside its own scope");
    h.coordinator.release_mutation_permit(permit).await.unwrap();

    // Outside its scope, even though the path is inside the workspace.
    let err = h
        .coordinator
        .acquire_mutation_permit(
            &handle.child_token,
            &h.root().join("b/steal.txt"),
            MutationKind::WriteContent,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::OutsideScope { .. }),
        "got {err}"
    );
}

#[tokio::test]
async fn denial_begins_at_parent_excluded_and_lifts_at_parent_restored() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    // Before any transfer the parent may write inside `a`.
    let permit = h
        .coordinator
        .acquire_mutation_permit(
            &parent,
            &h.root().join("a/pre.txt"),
            MutationKind::WriteContent,
        )
        .await
        .expect("pre-transfer write inside `a` is allowed");
    h.coordinator.release_mutation_permit(permit).await.unwrap();

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent_lease_id, "a"))
        .await
        .unwrap();

    // The exclusion is live exactly while the phase says it should be.
    let row =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap();
    let phase = TransferPhase::parse(&row.phase).unwrap();
    assert!(phase.parent_denied_in_subscope());
    assert!(
        h.coordinator
            .acquire_mutation_permit(
                &handle.parent_token,
                &h.root().join("a/mid.txt"),
                MutationKind::WriteContent
            )
            .await
            .is_err()
    );

    // Return, then the denial lifts under the fresh full-authority token.
    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();
    let restored = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap();

    let row =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.phase, TransferPhase::Committed.as_str());
    assert!(
        !TransferPhase::parse(&row.phase)
            .unwrap()
            .parent_denied_in_subscope()
    );

    let permit = h
        .coordinator
        .acquire_mutation_permit(
            &restored,
            &h.root().join("a/post.txt"),
            MutationKind::WriteContent,
        )
        .await
        .expect("parent regains its full authority after restoration");
    h.coordinator.release_mutation_permit(permit).await.unwrap();
}

#[tokio::test]
async fn no_activation_while_an_overlapping_parent_permit_is_in_flight() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    // The parent holds an in-flight mutation permit inside the subtree it is
    // about to delegate. This is an in-flight permit, not a grandfathered
    // write: the transfer must wait for it rather than proceed.
    let in_flight = h
        .coordinator
        .acquire_mutation_permit(
            &parent,
            &h.root().join("a/inner/busy.txt"),
            MutationKind::WriteContent,
        )
        .await
        .unwrap();

    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::PermitsNotDrained { count: 1 }),
        "got {err}"
    );

    // No child lease was created.
    assert!(
        h.db.list_child_write_scope_leases(parent.lease_id())
            .await
            .unwrap()
            .is_empty()
    );

    // Once it drains, the transfer proceeds.
    h.coordinator
        .release_mutation_permit(in_flight)
        .await
        .unwrap();
    let fresh =
        h.db.get_write_scope_lease(parent.lease_id())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(fresh.state, "active", "the parent unwound cleanly");
    assert!(
        h.coordinator
            .begin_transfer(h.request(parent.lease_id(), "a"))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn an_ancestor_rename_permit_blocks_a_transfer_of_its_descendant() {
    // Target-path-only overlap would miss this: the parent's permit names
    // `a`, the transfer names `a/inner`.
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    let rename = h
        .coordinator
        .acquire_mutation_permit(&parent, &h.root().join("a"), MutationKind::Rename)
        .await
        .unwrap();

    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a/inner"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::PermitsNotDrained { .. }),
        "an in-flight ancestor rename must block delegation of a descendant: got {err}"
    );

    h.coordinator.release_mutation_permit(rename).await.unwrap();
}
