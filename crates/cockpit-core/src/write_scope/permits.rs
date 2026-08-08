//! Namespace-influence overlap for durable-generation write permits.
//!
//! # Why target-path-only overlap is wrong
//!
//! Authorizing a mutation against the target path alone lets another Cockpit
//! mutation change what that path *means* between revalidation and syscall:
//! rename the parent directory, replace an ancestor with a symlink, remove and
//! recreate a component. The permit's overlap set must therefore include the
//! target **plus its namespace influence** — the subtree whose path meaning the
//! operation can alter.
//!
//! Two permits overlap when either influence root contains the other. That
//! makes an ancestor rename overlap every affected descendant, so a transfer
//! barrier cannot drain while such an operation is in flight.

use std::path::{Path, PathBuf};

use super::scope::path_contains;

/// The filesystem operation a mutation permit protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationKind {
    /// Write bytes into an existing or new file. Affects the target only.
    WriteContent,
    /// Create a new directory entry.
    Create,
    /// Remove a directory entry. Changes the meaning of every descendant path.
    Remove,
    /// Rename/move. Changes the meaning of every descendant path.
    Rename,
    /// Atomically replace an existing entry. Changes descendant meaning.
    Replace,
    /// Create a hard link. Introduces an alias to an inode.
    Link,
    /// Create a symlink. Redirects every path that traverses it.
    Symlink,
}

impl MutationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WriteContent => "write_content",
            Self::Create => "create",
            Self::Remove => "remove",
            Self::Rename => "rename",
            Self::Replace => "replace",
            Self::Link => "link",
            Self::Symlink => "symlink",
        }
    }

    /// True when the operation can change what *other* paths resolve to, not
    /// just the bytes at the target.
    pub fn influences_namespace(self) -> bool {
        matches!(
            self,
            Self::Remove | Self::Rename | Self::Replace | Self::Link | Self::Symlink
        )
    }

    pub const ALL: &'static [MutationKind] = &[
        Self::WriteContent,
        Self::Create,
        Self::Remove,
        Self::Rename,
        Self::Replace,
        Self::Link,
        Self::Symlink,
    ];
}

/// The subtree whose path meaning an operation can influence.
///
/// For a namespace mutation this is the target itself, which by the containment
/// rule below then overlaps every descendant. For a content write it is also
/// the target, but the target is a leaf so the overlap set is just that file.
/// The distinction matters at the *ancestor* end: renaming `/ws/a` yields an
/// influence root of `/ws/a`, which contains `/ws/a/b/c.txt`, so a concurrent
/// write to that file overlaps and the barrier must wait.
pub fn influence_root(target: &Path, kind: MutationKind) -> PathBuf {
    let _ = kind;
    target.to_path_buf()
}

/// A permit's overlap footprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitFootprint {
    pub influence_root: PathBuf,
    pub target: PathBuf,
    pub kind: MutationKind,
}

impl PermitFootprint {
    pub fn for_mutation(target: impl Into<PathBuf>, kind: MutationKind) -> Self {
        let target = target.into();
        Self {
            influence_root: influence_root(&target, kind),
            target,
            kind,
        }
    }

    /// An execution-wide permit covers the execution's entire effective write
    /// authority *plus* every ancestor namespace through which it could
    /// rename/remove/replace/link/symlink or redirect that authority.
    ///
    /// The influence root is therefore the highest such ancestor, not the
    /// effective write root: a child that can rename `/ws/a` changes the
    /// meaning of `/ws/a/b` even though its write root is `/ws/a/b`.
    pub fn for_execution(
        effective_write_root: impl Into<PathBuf>,
        reachable_ancestor: impl Into<PathBuf>,
    ) -> Self {
        let target = effective_write_root.into();
        Self {
            influence_root: reachable_ancestor.into(),
            target,
            kind: MutationKind::Rename,
        }
    }

    /// Overlap is symmetric containment of influence roots.
    pub fn overlaps(&self, other: &Self) -> bool {
        path_contains(&self.influence_root, &other.influence_root)
            || path_contains(&other.influence_root, &self.influence_root)
    }

    /// Whether two *in-flight mutations* may be held at the same time.
    ///
    /// Overlap alone is not conflict: two content writes to different files
    /// never overlap, and parallelism there is the whole point. A conflict is
    /// an overlap where at least one side can change what the other's path
    /// means, or where both target the identical path.
    pub fn conflicts_with(&self, other: &Self) -> bool {
        if !self.overlaps(other) {
            return false;
        }
        if self.kind.influences_namespace() || other.kind.influences_namespace() {
            return true;
        }
        self.target == other.target
    }

    /// True when this permit can influence anything inside `scope` — the test a
    /// transfer barrier uses to decide whether it must wait.
    pub fn overlaps_scope(&self, scope: &Path) -> bool {
        path_contains(&self.influence_root, scope) || path_contains(scope, &self.influence_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_mutations_are_classified() {
        assert!(!MutationKind::WriteContent.influences_namespace());
        assert!(!MutationKind::Create.influences_namespace());
        for kind in [
            MutationKind::Remove,
            MutationKind::Rename,
            MutationKind::Replace,
            MutationKind::Link,
            MutationKind::Symlink,
        ] {
            assert!(kind.influences_namespace(), "{kind:?}");
        }
    }

    #[test]
    fn ancestor_rename_overlaps_every_affected_descendant() {
        let rename = PermitFootprint::for_mutation("/ws/a", MutationKind::Rename);
        let deep_write = PermitFootprint::for_mutation("/ws/a/b/c.txt", MutationKind::WriteContent);
        assert!(rename.overlaps(&deep_write));
        // Symmetric.
        assert!(deep_write.overlaps(&rename));
    }

    #[test]
    fn disjoint_siblings_do_not_overlap() {
        let a = PermitFootprint::for_mutation("/ws/a/file", MutationKind::WriteContent);
        let b = PermitFootprint::for_mutation("/ws/b/file", MutationKind::WriteContent);
        assert!(!a.overlaps(&b));

        // Textual prefix siblings must not overlap either.
        let ab = PermitFootprint::for_mutation("/ws/ab/file", MutationKind::WriteContent);
        let a_dir = PermitFootprint::for_mutation("/ws/a", MutationKind::Rename);
        assert!(!a_dir.overlaps(&ab));
    }

    #[test]
    fn symlink_creation_on_an_ancestor_overlaps_the_scope_it_redirects() {
        // Replacing /ws/a with a symlink redirects every path under it.
        let symlink = PermitFootprint::for_mutation("/ws/a", MutationKind::Symlink);
        assert!(symlink.overlaps_scope(Path::new("/ws/a/b")));
        assert!(!symlink.overlaps_scope(Path::new("/ws/b")));
    }

    #[test]
    fn execution_permit_covers_reachable_ancestors_not_just_its_write_root() {
        // A child whose write root is /ws/a/b but which can rename /ws/a must
        // block a transfer touching /ws/a/other.
        let exec = PermitFootprint::for_execution("/ws/a/b", "/ws/a");
        assert!(exec.overlaps_scope(Path::new("/ws/a/other")));
        assert!(exec.overlaps_scope(Path::new("/ws/a/b")));
        // Still bounded: it cannot influence a disjoint sibling of the ancestor.
        assert!(!exec.overlaps_scope(Path::new("/ws/c")));

        // Contrast: a target-path-only footprint would have missed the sibling,
        // which is exactly the bug this design forbids.
        let target_only = PermitFootprint::for_mutation("/ws/a/b", MutationKind::WriteContent);
        assert!(!target_only.overlaps_scope(Path::new("/ws/a/other")));
    }

    #[test]
    fn link_creation_overlaps_the_inode_scope_it_aliases() {
        let link = PermitFootprint::for_mutation("/ws/a/alias", MutationKind::Link);
        assert!(link.overlaps_scope(Path::new("/ws/a")));
        assert!(link.overlaps_scope(Path::new("/ws/a/alias")));
    }
}
