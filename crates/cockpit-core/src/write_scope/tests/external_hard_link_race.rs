//! AC6 — `spawn_external_hard_link_race`.
//!
//! An adversarial same-user fixture creates and removes hard links and renames
//! ancestors before, during, and after preflight. The direct backend always
//! fails Unsupported before the transfer; the injected MediatedCow backend
//! either publishes a fresh unaliased inode through the broker or returns
//! Conflict — never mutating an aliased backing inode, leaking another owner's
//! content, starting a child without capability, or restoring authority after
//! an uncertain publish.

use crate::write_scope::backend::{HardLinkPreflight, InodeIdentity, ScopedWriteBackend};
use crate::write_scope::fake::{ExternalRaceFixture, PublishBehavior};
use crate::write_scope::permits::MutationKind;
use crate::write_scope::types::WriteScopeError;

use super::Harness;

/// Seed a file and return the fixture rooted at the workspace.
fn seeded_fixture(h: &Harness) -> ExternalRaceFixture {
    std::fs::write(h.root().join("a/secret.txt"), b"owned by a").unwrap();
    ExternalRaceFixture::new(h.root().to_path_buf())
}

#[tokio::test]
async fn direct_backend_refuses_before_transfer_no_matter_when_links_appear() {
    let h = Harness::direct().await;
    let fixture = seeded_fixture(&h);
    let parent = h.open_root("parent").await;

    // Before preflight.
    #[cfg(unix)]
    assert!(
        fixture
            .create_hard_link("a/secret.txt", "b/alias-before")
            .unwrap()
    );

    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap_err();
    assert!(err.is_unsupported(), "got {err}");

    // After the refusal, more links appear. The answer never changes.
    #[cfg(unix)]
    {
        assert!(
            fixture
                .create_hard_link("a/secret.txt", "b/alias-after")
                .unwrap()
        );
        fixture.remove("b/alias-before").unwrap();
    }
    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap_err();
    assert!(err.is_unsupported(), "got {err}");

    // Never a child, never user code.
    assert!(
        h.db.list_child_write_scope_leases(parent.lease_id())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(h.containment.user_code_never_released());
    assert_eq!(h.containment.created_count(), 0);
}

#[tokio::test]
async fn an_nlink_preflight_is_defeated_by_a_link_created_immediately_after() {
    // This is the concrete demonstration that a preflight is not evidence.
    let h = Harness::direct().await;
    let fixture = seeded_fixture(&h);

    #[cfg(unix)]
    {
        // Preflight observes a pristine, unaliased file.
        let nlink = fixture.nlink("a/secret.txt").unwrap();
        assert_eq!(nlink, 1, "preflight sees no aliases");
        let preflight = HardLinkPreflight {
            nlink,
            observed_at_wall_ms: 0,
        };
        // Even so, it establishes nothing...
        assert!(!preflight.establishes_strict_delegation());

        // ...and an unrelated same-user process immediately proves why.
        assert!(fixture.create_hard_link("a/secret.txt", "b/alias").unwrap());
        assert_eq!(
            fixture.nlink("a/secret.txt").unwrap(),
            2,
            "the observation was stale the instant it was taken"
        );

        // The alias reaches the same bytes from outside the scope.
        let via_alias = std::fs::read(h.root().join("b/alias")).unwrap();
        assert_eq!(via_alias, b"owned by a");
    }
}

#[tokio::test]
async fn an_ancestor_swapped_for_a_symlink_mid_permit_fails_closed_before_the_syscall() {
    // The permit's overlap set stops another *Cockpit* mutation from moving
    // this path. An unrelated same-user host process is outside that guarantee,
    // so the pre-syscall revalidation is what must catch it.
    #[cfg(unix)]
    {
        let h = Harness::direct().await;
        let fixture = seeded_fixture(&h);
        let parent = h.open_root("parent").await;

        let target = h.root().join("a/inner/out.txt");
        let permit = h
            .coordinator
            .acquire_mutation_permit(&parent, &target, MutationKind::WriteContent)
            .await
            .unwrap();
        assert_eq!(permit.effective_target(), target);

        // While the permit is held, revalidation still agrees.
        h.coordinator
            .revalidate_mutation_permit(&parent, &permit)
            .await
            .expect("an untouched path revalidates");

        // An unrelated host process replaces the ancestor with a symlink to a
        // different subtree. `a/inner/out.txt` now means `b/out.txt`.
        fixture.replace_with_symlink("a/inner", "b").unwrap();

        let err = h
            .coordinator
            .revalidate_mutation_permit(&parent, &permit)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WriteScopeError::EffectivePathChanged { .. }),
            "a redirected ancestor must fail closed before the syscall, got {err}"
        );

        h.coordinator.release_mutation_permit(permit).await.unwrap();
    }
}

#[tokio::test]
async fn a_stale_token_cannot_revalidate_a_permit_after_an_authority_change() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    let target = h.root().join("b/out.txt");
    let permit = h
        .coordinator
        .acquire_mutation_permit(&parent, &target, MutationKind::WriteContent)
        .await
        .unwrap();

    // An authority change happens while the permit is in flight.
    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    // The permit's token is from the superseded generation, so revalidation —
    // the check immediately before the syscall — refuses.
    let err = h
        .coordinator
        .revalidate_mutation_permit(&parent, &permit)
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::StaleGeneration { .. }),
        "got {err}"
    );

    // The replacement token still revalidates the same path, since `b` was
    // never delegated.
    h.coordinator
        .revalidate_mutation_permit(&handle.parent_token, &permit)
        .await
        .expect("the replacement token still owns `b`");
}

#[tokio::test]
async fn ancestor_replaced_by_symlink_is_refused_rather_than_followed() {
    #[cfg(unix)]
    {
        let h = Harness::direct().await;
        let fixture = seeded_fixture(&h);
        let parent = h.open_root("parent").await;

        // Replace `a/inner` with a symlink to `b` — a namespace mutation that
        // redirects every path beneath it.
        fixture.replace_with_symlink("a/inner", "b").unwrap();

        // The effective path of `a/inner/x.txt` is now under `b`. It is still
        // inside the workspace, so it resolves — but it must resolve to where
        // it actually lands, not where it was named.
        let effective =
            crate::path_containment::effective_path(&h.root().join("a/inner/x.txt")).unwrap();
        let b_real = crate::path_containment::effective_path(&h.root().join("b")).unwrap();
        assert!(
            effective.starts_with(&b_real),
            "the symlink must be resolved, not trusted: {}",
            effective.display()
        );

        // A child scoped to `a` therefore cannot use the symlink to write into
        // `b`: its permit is judged by the effective path.
        let handle_scope = h.scope("a");
        assert!(!handle_scope.contains_path(&effective));
        let _ = parent;
    }
}

#[tokio::test]
async fn proven_backend_publishes_a_fresh_unaliased_inode_through_the_broker() {
    let (h, backend) = Harness::proven().await;
    let _fixture = seeded_fixture(&h);
    let parent = h.open_root("parent").await;

    // Record the identity the backend reports for this scope, so the assertion
    // below compares against a real minted value rather than an arbitrary
    // number the fixture never produces.
    let scope = h.scope("a");
    let backing = backend
        .target_identity(&scope)
        .expect("proven backend tracks identity");

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();
    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();
    let restored = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .expect("a clean publish restores authority");

    assert_eq!(backend.publish_count(), 1);
    let published = backend.published_inodes();
    assert_eq!(published.len(), 1);
    assert_ne!(
        published[0], backing,
        "publication must mint a fresh inode, not reuse the backing one"
    );
    assert!(
        backend.never_mutated_an_aliased_backing_inode(),
        "publication must be replace-only onto a fresh inode"
    );
    assert!(backend.mutated_backing_inodes().is_empty());
    assert!(restored.is_valid());
}

/// Negative control for `never_mutated_an_aliased_backing_inode`.
///
/// The guard must read real publication data, not be true by construction. Here
/// the backend genuinely writes through the aliased backing inode, and the
/// guard has to notice. Without this, the assertion in the test above could
/// pass on a backend that never published at all.
#[test]
fn the_aliased_backing_guard_reads_real_publication_data() {
    use crate::write_scope::CanonicalScope;
    use crate::write_scope::backend::PublishRequest;
    use crate::write_scope::fake::FakeMediatedCowBackend;

    let backend = FakeMediatedCowBackend::new();
    let scope = CanonicalScope::from_canonical("/ws/a");
    let backing = backend.target_identity(&scope).unwrap();
    backend.mark_backing_aliased(backing);

    // A correct copy-on-write publish never touches the backing inode.
    backend.publish(PublishRequest {
        scope: scope.clone(),
        expected_target_identity: None,
    });
    assert!(backend.never_mutated_an_aliased_backing_inode());
    assert!(backend.mutated_backing_inodes().is_empty());

    // A backend that writes through it must be caught.
    backend.set_behavior(PublishBehavior::MutateBackingInPlace);
    backend.publish(PublishRequest {
        scope,
        expected_target_identity: None,
    });
    assert!(
        !backend.never_mutated_an_aliased_backing_inode(),
        "the guard must detect an in-place mutation of an aliased backing inode"
    );
    assert_eq!(backend.mutated_backing_inodes(), vec![backing]);
}

/// An externally hard-linked publication target is a Conflict: the backend sees
/// the alias on the identity it recorded and refuses to publish onto it.
#[tokio::test]
async fn an_externally_aliased_target_is_refused_at_publish() {
    let (h, backend) = Harness::proven().await;
    let _fixture = seeded_fixture(&h);
    let parent = h.open_root("parent").await;

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    // An unrelated same-user process hard-links the publication target.
    let backing = backend.target_identity(&h.scope("a")).unwrap();
    backend.mark_backing_aliased(backing);

    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();
    let err = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::PublicationConflict { .. }),
        "got {err}"
    );
    assert!(backend.published_inodes().is_empty());
    assert!(backend.never_mutated_an_aliased_backing_inode());

    // Authority is not restored after an uncertain publish.
    let row =
        h.db.get_write_scope_lease(parent.lease_id())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.state, "delegated");
}

/// The identity recorded when the child started must still hold at publish. If
/// the target or an ancestor was replaced meanwhile, the publish is a Conflict
/// and authority is never restored.
#[tokio::test]
async fn a_replaced_publication_target_is_a_conflict_not_a_publish() {
    let (h, backend) = Harness::proven().await;
    let _fixture = seeded_fixture(&h);
    let parent = h.open_root("parent").await;

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    // The recorded identity was captured at ParentExcluded.
    let transfer =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap();
    let recorded = transfer
        .publication_identity
        .clone()
        .expect("identity recorded at child start");

    // An external race replaces the target: the backend now reports a different
    // identity for the same scope.
    backend.set_identity(&h.scope("a"), InodeIdentity(999_999));

    h.coordinator
        .child_terminal(handle.transfer_id)
        .await
        .unwrap();
    let err = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::PublicationConflict { .. }),
        "a changed target identity must be a Conflict, got {err}"
    );
    assert_ne!(recorded, "999999");

    // Authority stays with the child.
    let row =
        h.db.get_write_scope_lease(parent.lease_id())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.state, "delegated");
}

#[tokio::test]
async fn a_publish_conflict_never_restores_authority() {
    let (h, backend) = Harness::proven().await;
    let _fixture = seeded_fixture(&h);
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

    // An external same-user hard link / namespace race is detected at publish.
    backend.set_behavior(PublishBehavior::Conflict {
        reason: "external hard link detected on the publication target".into(),
    });

    let err = h
        .coordinator
        .complete_return(handle.transfer_id)
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::PublicationConflict { .. }),
        "got {err}"
    );

    // Nothing was published, and the parent did NOT get its authority back.
    assert!(backend.published_inodes().is_empty());
    assert!(backend.never_mutated_an_aliased_backing_inode());
    let parent_row =
        h.db.get_write_scope_lease(parent.lease_id())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        parent_row.state, "delegated",
        "authority must not be restored after an uncertain publish"
    );

    // The transfer row is retained for recovery, not committed.
    let transfer =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(transfer.phase, "child_terminal");

    // The execution-wide permit is still held: the barrier never drained.
    assert!(
        !h.db
            .list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .is_empty(),
        "the execution permit must not be released on a conflicted publish"
    );
}

#[tokio::test]
async fn a_child_never_starts_without_capability_even_under_race_pressure() {
    let h = Harness::direct().await;
    let fixture = seeded_fixture(&h);
    let parent = h.open_root("parent").await;

    // Hammer the tree with the adversarial operations at every point around the
    // attempted transfer. None of them can turn Unsupported into a child.
    for round in 0..5 {
        #[cfg(unix)]
        {
            let alias = format!("b/alias-{round}");
            let _ = fixture.create_hard_link("a/secret.txt", &alias);
            let _ = fixture.remove(&alias);
        }
        let err = h
            .coordinator
            .begin_transfer(h.request(parent.lease_id(), "a"))
            .await
            .unwrap_err();
        assert!(err.is_unsupported(), "round {round}: {err}");
    }

    assert!(
        h.db.list_child_write_scope_leases(parent.lease_id())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(h.containment.user_code_never_released());
    assert!(h.events.events().iter().all(|e| !e.implies_child_exists()));
}
