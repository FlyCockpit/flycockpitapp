//! AC11 — the durable invariant.
//!
//! Effective authorities are pairwise disjoint after subtracting delegated
//! exclusions, and no Active/Delegated owner, execution-wide permit,
//! namespace-influencing mutation, descendant, hard-link alias, external
//! publication race, or in-flight operation can write or redirect another
//! owner's scope.
//!
//! In the absence of a Proven backend the invariant is satisfied by *refusing
//! the transfer* — which is the only reason it holds on the direct workspace
//! today.

use crate::write_scope::permits::{MutationKind, PermitFootprint};
use crate::write_scope::scope::{CanonicalScope, EffectiveAuthority};
use crate::write_scope::types::WriteScopeError;

use super::Harness;

/// Collect every live owner's effective authority.
async fn live_authorities(h: &Harness) -> Vec<(uuid::Uuid, EffectiveAuthority)> {
    let leases =
        h.db.list_live_write_scope_leases(Some(h.session_id))
            .await
            .unwrap();
    let mut out = Vec::new();
    for lease in leases {
        let authority = h
            .coordinator
            .effective_authority(lease.lease_id)
            .await
            .unwrap();
        out.push((lease.lease_id, authority));
    }
    out
}

/// Assert no path is writable by two different owners.
fn assert_pairwise_disjoint(
    authorities: &[(uuid::Uuid, EffectiveAuthority)],
    probes: &[&std::path::Path],
) {
    for probe in probes {
        let owners: Vec<uuid::Uuid> = authorities
            .iter()
            .filter(|(_, a)| a.allows_path(probe))
            .map(|(id, _)| *id)
            .collect();
        assert!(
            owners.len() <= 1,
            "`{}` is writable by {} owners: {owners:?}",
            probe.display(),
            owners.len()
        );
    }
}

#[tokio::test]
async fn effective_authorities_are_pairwise_disjoint_across_a_nested_tree() {
    let (h, _backend) = Harness::proven().await;
    let root = h.open_root("root").await;

    // root -> a, root -> b, a -> a/inner
    let a = h
        .coordinator
        .begin_transfer(h.request(root.lease_id(), "a"))
        .await
        .unwrap();
    let _b = h
        .coordinator
        .begin_transfer(h.request(root.lease_id(), "b"))
        .await
        .unwrap();
    let _inner = h
        .coordinator
        .begin_transfer(h.request(a.child_token.lease_id(), "a/inner"))
        .await
        .unwrap();

    let authorities = live_authorities(&h).await;
    assert_eq!(authorities.len(), 4, "root + a + b + a/inner");

    let probes = [
        h.root().join("a/file.txt"),
        h.root().join("a/inner/file.txt"),
        h.root().join("b/file.txt"),
        h.root().join("shared/file.txt"),
        h.root().join("ab/file.txt"),
        h.root().to_path_buf(),
    ];
    let probe_refs: Vec<&std::path::Path> = probes.iter().map(|p| p.as_path()).collect();
    assert_pairwise_disjoint(&authorities, &probe_refs);

    // And every probe inside the workspace has exactly one owner or none.
    let inner_owners: Vec<_> = authorities
        .iter()
        .filter(|(_, auth)| auth.allows_path(&h.root().join("a/inner/x")))
        .collect();
    assert_eq!(
        inner_owners.len(),
        1,
        "the deepest delegate is the sole owner of its scope"
    );
}

#[tokio::test]
async fn no_owner_can_write_or_redirect_another_owners_scope() {
    let (h, _backend) = Harness::proven().await;
    let root = h.open_root("root").await;

    let a = h
        .coordinator
        .begin_transfer(h.request(root.lease_id(), "a"))
        .await
        .unwrap();
    let b = h
        .coordinator
        .begin_transfer(h.request(root.lease_id(), "b"))
        .await
        .unwrap();

    // Sibling cannot write into the other's scope.
    for (token, foreign) in [
        (&a.child_token, "b/steal.txt"),
        (&b.child_token, "a/steal.txt"),
    ] {
        let err = h
            .coordinator
            .acquire_mutation_permit(token, &h.root().join(foreign), MutationKind::WriteContent)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WriteScopeError::OutsideScope { .. }),
            "sibling must not write `{foreign}`: got {err}"
        );
    }

    // The parent (still holding the root lease) cannot write into either.
    for foreign in ["a/x.txt", "b/x.txt"] {
        let err = h
            .coordinator
            .acquire_mutation_permit(
                &b.parent_token,
                &h.root().join(foreign),
                MutationKind::WriteContent,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, WriteScopeError::DeniedInsideDelegatedSubscope { .. }),
            "parent must not write `{foreign}`: got {err}"
        );
    }

    // Namespace redirection is refused too: a sibling cannot rename or symlink
    // its way into the other's scope.
    for kind in [
        MutationKind::Rename,
        MutationKind::Symlink,
        MutationKind::Remove,
        MutationKind::Replace,
        MutationKind::Link,
    ] {
        let err = h
            .coordinator
            .acquire_mutation_permit(&a.child_token, &h.root().join("b"), kind)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WriteScopeError::OutsideScope { .. }),
            "{kind:?} into a sibling scope must be refused: got {err}"
        );
    }
}

#[test]
fn overlap_is_computed_from_namespace_influence_not_the_target_path() {
    // The invariant depends on this: if overlap were target-path-only, an
    // ancestor rename would silently pass a barrier it should block.
    let ancestor_rename = PermitFootprint::for_mutation("/ws/a", MutationKind::Rename);
    let descendant_write =
        PermitFootprint::for_mutation("/ws/a/inner/deep.txt", MutationKind::WriteContent);
    assert!(ancestor_rename.overlaps(&descendant_write));
    assert!(ancestor_rename.overlaps_scope(std::path::Path::new("/ws/a/inner")));

    // An execution permit reaches every ancestor it can redirect.
    let execution = PermitFootprint::for_execution("/ws/a/inner", "/ws/a");
    assert!(execution.overlaps_scope(std::path::Path::new("/ws/a/sibling")));

    // Still bounded — the invariant is disjointness, not universal blocking.
    assert!(!execution.overlaps_scope(std::path::Path::new("/ws/b")));
    assert!(!ancestor_rename.overlaps_scope(std::path::Path::new("/ws/ab")));
}

#[tokio::test]
async fn on_the_direct_backend_the_invariant_holds_by_refusing_the_transfer() {
    let h = Harness::direct().await;
    let root = h.open_root("root").await;

    // Every attempt to create a second writable owner is refused.
    for relative in ["a", "b", "a/inner", "shared"] {
        let err = h
            .coordinator
            .begin_transfer(h.request(root.lease_id(), relative))
            .await
            .unwrap_err();
        assert!(err.is_unsupported(), "{relative}: {err}");
    }

    // So there is exactly one owner, and disjointness is trivially satisfied.
    let authorities = live_authorities(&h).await;
    assert_eq!(
        authorities.len(),
        1,
        "no second writable owner may ever exist on the direct backend"
    );

    let probes = [
        h.root().join("a/file.txt"),
        h.root().join("b/file.txt"),
        h.root().join("a/inner/file.txt"),
    ];
    let probe_refs: Vec<&std::path::Path> = probes.iter().map(|p| p.as_path()).collect();
    assert_pairwise_disjoint(&authorities, &probe_refs);
}

#[test]
fn subtracting_exclusions_yields_disjoint_authorities_for_arbitrary_shapes() {
    let base = CanonicalScope::from_canonical("/ws");
    let parent = EffectiveAuthority::new(
        base.clone(),
        vec![
            CanonicalScope::from_canonical("/ws/a"),
            CanonicalScope::from_canonical("/ws/b"),
        ],
    );
    let child_a = EffectiveAuthority::new(CanonicalScope::from_canonical("/ws/a"), vec![]);
    let child_b = EffectiveAuthority::new(CanonicalScope::from_canonical("/ws/b"), vec![]);

    for probe in [
        "/ws/a/x",
        "/ws/b/x",
        "/ws/c/x",
        "/ws/ab/x",
        "/ws",
        "/elsewhere/x",
    ] {
        let path = std::path::Path::new(probe);
        let owners = [
            parent.allows_path(path),
            child_a.allows_path(path),
            child_b.allows_path(path),
        ]
        .iter()
        .filter(|allowed| **allowed)
        .count();
        assert!(owners <= 1, "`{probe}` has {owners} owners");
    }

    // Coverage is preserved: a path outside every exclusion still has an owner.
    assert!(parent.allows_path(std::path::Path::new("/ws/c/x")));
    assert!(child_a.allows_path(std::path::Path::new("/ws/a/x")));
}

#[tokio::test]
async fn an_in_flight_operation_cannot_straddle_a_transfer_boundary() {
    let (h, _backend) = Harness::proven().await;
    let root = h.open_root("root").await;

    // An in-flight parent mutation inside the subtree blocks the transfer...
    let in_flight = h
        .coordinator
        .acquire_mutation_permit(
            &root,
            &h.root().join("a/inflight.txt"),
            MutationKind::WriteContent,
        )
        .await
        .unwrap();
    assert!(
        h.coordinator
            .begin_transfer(h.request(root.lease_id(), "a"))
            .await
            .is_err()
    );

    // ...and once the transfer does happen, the old permit's owner has no
    // authority left there, so it cannot be re-acquired.
    h.coordinator
        .release_mutation_permit(in_flight)
        .await
        .unwrap();
    let fresh_root =
        h.db.get_write_scope_lease(root.lease_id())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(fresh_root.state, "active");

    let handle = h
        .coordinator
        .begin_transfer(h.request(root.lease_id(), "a"))
        .await
        .unwrap();
    let err = h
        .coordinator
        .acquire_mutation_permit(
            &handle.parent_token,
            &h.root().join("a/inflight.txt"),
            MutationKind::WriteContent,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        WriteScopeError::DeniedInsideDelegatedSubscope { .. }
    ));
}
