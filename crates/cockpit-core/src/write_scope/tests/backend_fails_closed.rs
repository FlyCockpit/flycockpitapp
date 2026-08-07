//! AC5 — `spawn_scoped_backend_fails_closed`.
//!
//! The direct workspace, descriptor walk + nlink preflight, shell filter, and
//! the native/zerobox/Docker/Podman paths never advertise Proven hard-link
//! isolation. Writable strict delegation returns `ScopedWritesUnsupported`
//! before ParentExcluded, before any child record/token/event, and before any
//! user code. An injected future-capable backend must attest every clause.

use crate::write_scope::backend::{
    DescriptorWalk, DirectWorkspaceBackend, ExecutionMode, HardLinkPreflight,
    ProvenScopedWriteAttestation, PublishOutcome, PublishRequest, ScopedWriteBackend,
    ShellSyntaxFilter,
};
use crate::write_scope::events::WriteScopeEvent;
use crate::write_scope::fake::FakeMediatedCowBackend;

use super::Harness;

#[test]
fn no_direct_path_advertises_proven_hard_link_isolation() {
    let backend = DirectWorkspaceBackend;
    let scope = crate::write_scope::CanonicalScope::from_canonical("/ws/a");

    // Every execution mode, one at a time, so none can be quietly special-cased.
    for mode in ExecutionMode::ALL {
        let cap = backend.capability_for(&scope, *mode);
        assert!(
            !cap.is_proven(),
            "{} must not advertise Proven isolation",
            mode.as_str()
        );
    }

    // The defense-in-depth mechanisms cannot upgrade that answer.
    let preflight = HardLinkPreflight {
        nlink: 1,
        observed_at_wall_ms: 0,
    };
    assert!(!preflight.establishes_strict_delegation());
    assert!(!preflight.capability().is_proven());
    assert!(!DescriptorWalk.establishes_strict_delegation());
    assert!(!DescriptorWalk.capability().is_proven());
    assert!(!ShellSyntaxFilter.establishes_strict_delegation());
    assert!(!ShellSyntaxFilter.capability().is_proven());

    // Even an nlink of exactly 1 — the strongest reading a preflight can get —
    // is not evidence, because the observation is stale immediately.
    for nlink in [1, 2, 17] {
        let p = HardLinkPreflight {
            nlink,
            observed_at_wall_ms: 0,
        };
        assert!(!p.establishes_strict_delegation(), "nlink={nlink}");
    }
}

#[tokio::test]
async fn writable_delegation_on_the_direct_backend_is_unsupported_for_every_mode() {
    for mode in ExecutionMode::ALL {
        let h = Harness::direct().await;
        let parent = h.open_root("parent").await;
        let mut request = h.request(parent.lease_id(), "a");
        request.mode = *mode;

        let err = h.coordinator.begin_transfer(request).await.unwrap_err();
        assert!(
            err.is_unsupported(),
            "{} must return ScopedWritesUnsupported, got {err}",
            mode.as_str()
        );
        assert!(
            err.to_string().contains("hard link"),
            "the refusal should name the hard-link reason: {err}"
        );
    }
}

#[tokio::test]
async fn refusal_happens_before_exclusion_child_records_events_and_user_code() {
    let h = Harness::direct().await;
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    let before =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();
    let events_before = h.events.count();

    let err = h
        .coordinator
        .begin_transfer(h.request(parent_lease_id, "a"))
        .await
        .unwrap_err();
    assert!(err.is_unsupported());

    // No authority change at all.
    let after =
        h.db.get_write_scope_lease(parent_lease_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(after.state, "active");
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.version, before.version);

    // No transfer row, no child lease.
    assert!(
        h.db.list_open_write_scope_transfers(Some(h.session_id))
            .await
            .unwrap()
            .is_empty(),
        "no transfer row may exist"
    );
    assert!(
        h.db.list_child_write_scope_leases(parent_lease_id)
            .await
            .unwrap()
            .is_empty(),
        "no child lease may exist"
    );

    // No permits were left behind.
    assert!(
        h.db.list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .is_empty()
    );

    // No events at all.
    assert_eq!(h.events.count(), events_before, "no event may be emitted");

    // No containment was created and no user code was ever released.
    assert_eq!(h.containment.created_count(), 0);
    assert!(h.containment.user_code_never_released());
}

#[tokio::test]
async fn the_parent_keeps_working_after_a_refusal() {
    // A refusal is not a poison pill: non-delegated behavior is unchanged.
    let h = Harness::direct().await;
    let parent = h.open_root("parent").await;

    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap_err();
    assert!(err.is_unsupported());

    // The original token is still valid and still writes everywhere.
    assert!(parent.is_valid());
    for target in ["a/file.txt", "b/file.txt", "shared/file.txt"] {
        let permit = h
            .coordinator
            .acquire_mutation_permit(
                &parent,
                &h.root().join(target),
                crate::write_scope::MutationKind::WriteContent,
            )
            .await
            .unwrap_or_else(|e| panic!("`{target}` should still be writable: {e}"));
        h.coordinator.release_mutation_permit(permit).await.unwrap();
    }
}

#[tokio::test]
async fn an_injected_future_capable_backend_must_attest_every_clause() {
    // Complete attestation -> the transfer proceeds.
    let (h, backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    assert!(
        h.coordinator
            .begin_transfer(h.request(parent.lease_id(), "a"))
            .await
            .is_ok()
    );
    assert!(
        backend
            .capability_for(&h.scope("a"), ExecutionMode::Native)
            .is_proven()
    );

    // Drop any single clause and delegation fails closed again.
    for drop_clause in [
        "private_inode_view",
        "backing_tree_unreachable",
        "other_uppers_unreachable",
        "cross_owner_hard_link_denied",
        "broker_only_replace_publication",
        "crash_cleanup",
    ] {
        let mut attestation = ProvenScopedWriteAttestation::complete();
        match drop_clause {
            "private_inode_view" => attestation.private_inode_view = false,
            "backing_tree_unreachable" => attestation.backing_tree_unreachable = false,
            "other_uppers_unreachable" => attestation.other_uppers_unreachable = false,
            "cross_owner_hard_link_denied" => attestation.cross_owner_hard_link_denied = false,
            "broker_only_replace_publication" => {
                attestation.broker_only_replace_publication = false
            }
            "crash_cleanup" => attestation.crash_cleanup = false,
            _ => unreachable!(),
        }
        let weakened =
            std::sync::Arc::new(FakeMediatedCowBackend::new().with_attestation(attestation));
        let h = Harness::with_backend(weakened).await;
        let parent = h.open_root("parent").await;
        let err = h
            .coordinator
            .begin_transfer(h.request(parent.lease_id(), "a"))
            .await
            .unwrap_err();
        assert!(
            err.is_unsupported(),
            "dropping `{drop_clause}` must make the backend Unsupported, got {err}"
        );
        assert!(h.containment.user_code_never_released());
    }
}

#[tokio::test]
async fn the_proven_path_emits_exclusion_and_activation_in_order() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    h.coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    let events = h.events.events();
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| match e {
            WriteScopeEvent::LeaseOpened { .. } => "lease_opened",
            WriteScopeEvent::TransferPrepared { .. } => "prepared",
            WriteScopeEvent::ParentExcluded { .. } => "parent_excluded",
            WriteScopeEvent::ChildActivated { .. } => "child_activated",
            WriteScopeEvent::ChildTerminal { .. } => "child_terminal",
            WriteScopeEvent::ParentRestored { .. } => "parent_restored",
            WriteScopeEvent::TransferCommitted { .. } => "committed",
            WriteScopeEvent::TransferUnwound { .. } => "unwound",
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            "lease_opened",
            "prepared",
            "parent_excluded",
            "child_activated"
        ]
    );
}

#[test]
fn the_direct_backend_cannot_publish() {
    let outcome = DirectWorkspaceBackend.publish(PublishRequest {
        scope: crate::write_scope::CanonicalScope::from_canonical("/ws/a"),
        expected_target_identity: None,
    });
    assert!(matches!(outcome, PublishOutcome::Unsupported { .. }));
}

/// A backend that attests the complete clause set but does not track inode
/// identity cannot prove replace-only publication. It must fail closed BEFORE
/// user code is released, not silently publish without a comparison.
#[tokio::test]
async fn a_proven_backend_without_identity_tracking_fails_closed_before_user_code() {
    let backend = std::sync::Arc::new(FakeMediatedCowBackend::new().without_identity_tracking());
    let h = Harness::with_backend(backend.clone()).await;
    let parent = h.open_root("parent").await;

    // It really does claim Proven — the refusal must come from the missing
    // identity, not from a weakened attestation.
    assert!(
        backend
            .capability_for(&h.scope("a"), ExecutionMode::Native)
            .is_proven()
    );

    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap_err();
    assert!(err.is_unsupported(), "got {err}");
    assert!(
        err.to_string().contains("stable inode identity"),
        "the refusal must name the missing identity: {err}"
    );

    // The decisive part: no user code, no child, no authority change.
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
    assert!(
        h.db.list_held_write_scope_permits(Some(h.session_id))
            .await
            .unwrap()
            .is_empty(),
        "the reserved permit must be released on the fail-closed path"
    );
}

/// The identity must be sampled before user code is released. If it were
/// sampled afterwards, an external replacement during that window would become
/// the accepted baseline and the publish-time comparison would confirm the
/// attacker's inode instead of rejecting it.
#[tokio::test]
async fn the_publication_identity_is_sampled_before_user_code_runs() {
    let (h, backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    let recorded =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap()
            .publication_identity
            .expect("identity recorded");

    // Whatever the backend reported at acquisition is what was persisted.
    let sampled = backend
        .target_identity(&h.scope("a"))
        .expect("proven backend tracks identity");
    assert_eq!(recorded, sampled.0.to_string());

    // An external replacement AFTER user code started must not be adopted as
    // the baseline — the recorded value still points at the pre-release inode.
    backend.set_identity(&h.scope("a"), crate::write_scope::InodeIdentity(424_242));
    let still =
        h.db.get_write_scope_transfer(handle.transfer_id)
            .await
            .unwrap()
            .unwrap()
            .publication_identity
            .unwrap();
    assert_eq!(still, recorded, "the baseline must not drift after release");

    // And the return refuses, because the target changed under the child.
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
        matches!(
            err,
            crate::write_scope::WriteScopeError::PublicationConflict { .. }
        ),
        "got {err}"
    );
}
