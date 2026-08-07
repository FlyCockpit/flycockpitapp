//! AC3 — `spawn_recursive_strict_subscope`.
//!
//! Sibling, ancestor, overlap, symlink, and textual-prefix escapes are all
//! rejected, as is any scope intersecting an effective delegated exclusion.

use crate::write_scope::scope::CanonicalScope;
use crate::write_scope::types::WriteScopeError;

use super::Harness;

#[tokio::test]
async fn sibling_ancestor_and_prefix_escapes_are_rejected() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    // Delegate `a`, then use `a`'s own lease as the parent for the escapes.
    let handle = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();
    let child_lease_id = handle.child_token.lease_id();

    // Ancestor of the child's scope.
    let mut req = h.request(child_lease_id, ".");
    req.sub_scope = h.root_scope();
    assert!(matches!(
        h.coordinator.begin_transfer(req).await.unwrap_err(),
        WriteScopeError::NotStrictSubscope { .. }
    ));

    // Sibling of the child's scope.
    let mut req = h.request(child_lease_id, "b");
    req.sub_scope = h.scope("b");
    assert!(matches!(
        h.coordinator.begin_transfer(req).await.unwrap_err(),
        WriteScopeError::NotStrictSubscope { .. }
    ));

    // Textual-prefix sibling: `ab` is not under `a`.
    let mut req = h.request(child_lease_id, "ab");
    req.sub_scope = h.scope("ab");
    assert!(
        matches!(
            h.coordinator.begin_transfer(req).await.unwrap_err(),
            WriteScopeError::NotStrictSubscope { .. }
        ),
        "`ab` must not count as a sub-scope of `a`"
    );

    // Equal to the child's own scope is not *strict*.
    let mut req = h.request(child_lease_id, "a");
    req.sub_scope = h.scope("a");
    assert!(matches!(
        h.coordinator.begin_transfer(req).await.unwrap_err(),
        WriteScopeError::NotStrictSubscope { .. }
    ));

    // A genuine strict sub-scope is admitted.
    let mut req = h.request(child_lease_id, "a/inner");
    req.sub_scope = h.scope("a/inner");
    assert!(h.coordinator.begin_transfer(req).await.is_ok());
}

#[tokio::test]
async fn a_scope_intersecting_a_delegated_exclusion_is_rejected() {
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;

    // Give `a` away.
    let _first = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap();

    // The same scope again: already delegated.
    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::IntersectsDelegatedExclusion { .. }),
        "got {err}"
    );

    // A descendant of the delegated scope: the parent no longer holds it.
    let err = h
        .coordinator
        .begin_transfer(h.request(parent.lease_id(), "a/inner"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, WriteScopeError::IntersectsDelegatedExclusion { .. }),
        "got {err}"
    );

    // A disjoint sibling is still fine — effective authority is base minus
    // exclusions, not "nothing left".
    assert!(
        h.coordinator
            .begin_transfer(h.request(parent.lease_id(), "b"))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn validation_uses_effective_authority_not_the_base_scope() {
    // Regression guard for the forbidden shortcut: checking a candidate only
    // against the parent's original scope would admit `a/inner` here.
    let (h, _backend) = Harness::proven().await;
    let parent = h.open_root("parent").await;
    let parent_lease_id = parent.lease_id();

    h.coordinator
        .begin_transfer(h.request(parent_lease_id, "a"))
        .await
        .unwrap();

    let authority = h
        .coordinator
        .effective_authority(parent_lease_id)
        .await
        .unwrap();

    // The base still contains `a/inner`...
    assert!(authority.base().contains_path(&h.root().join("a/inner")));
    // ...but the effective authority does not.
    assert!(!authority.allows_path(&h.root().join("a/inner")));
    assert!(authority.allows_path(&h.root().join("b/file.txt")));
}

#[test]
fn symlink_escape_out_of_the_workspace_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(root.join("a")).unwrap();
    std::fs::create_dir_all(outside.join("secret")).unwrap();

    #[cfg(unix)]
    {
        // A symlink inside the scope pointing out of the workspace.
        std::os::unix::fs::symlink(&outside, root.join("a/escape")).unwrap();

        let err = CanonicalScope::resolve_under(&root, "a/escape").unwrap_err();
        assert!(
            matches!(err, WriteScopeError::ScopeEscapesWorkspace { .. }),
            "got {err}"
        );

        // And through it.
        assert!(CanonicalScope::resolve_under(&root, "a/escape/secret").is_err());

        // A scope legitimately inside still resolves.
        assert!(CanonicalScope::resolve_under(&root, "a").is_ok());
    }
}

#[test]
fn parent_traversal_cannot_climb_out_of_the_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ws");
    std::fs::create_dir_all(root.join("a/inner")).unwrap();
    std::fs::create_dir_all(tmp.path().join("outside")).unwrap();

    for attempt in [
        "..",
        "../outside",
        "a/../../outside",
        "a/inner/../../../outside",
    ] {
        assert!(
            CanonicalScope::resolve_under(&root, attempt).is_err(),
            "`{attempt}` must not resolve to an authority"
        );
    }

    // Traversal that stays inside is fine.
    let inside = CanonicalScope::resolve_under(&root, "a/inner/..").unwrap();
    assert_eq!(
        inside.path(),
        CanonicalScope::resolve_under(&root, "a").unwrap().path()
    );
}

#[tokio::test]
async fn a_symlinked_sub_scope_is_judged_by_where_it_lands() {
    #[cfg(unix)]
    {
        let (h, _backend) = Harness::proven().await;
        let parent = h.open_root("parent").await;

        // `b/link` points at `a`, which is a real sibling subtree.
        std::os::unix::fs::symlink(h.root().join("a"), h.root().join("b/link")).unwrap();

        // Delegate the real `a` first.
        h.coordinator
            .begin_transfer(h.request(parent.lease_id(), "a"))
            .await
            .unwrap();

        // Now requesting `b/link` must resolve to `a` and collide with the
        // exclusion — not sneak through as a fresh path under `b`.
        let err = h
            .coordinator
            .begin_transfer(h.request(parent.lease_id(), "b/link"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, WriteScopeError::IntersectsDelegatedExclusion { .. }),
            "a symlink must not launder an already-delegated scope: got {err}"
        );
    }
}
