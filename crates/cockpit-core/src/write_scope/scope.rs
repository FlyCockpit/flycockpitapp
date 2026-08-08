//! Canonical write scopes, strict sub-scope containment, and effective
//! authority.
//!
//! Every path here is *syscall-effective*: resolved through
//! [`crate::path_containment::effective_path`] so a symlink cannot name one
//! path and mean another. A scope that cannot be resolved fails closed.

use std::path::{Path, PathBuf};

use super::types::WriteScopeError;

/// A canonical absolute directory subtree that a lease grants write authority
/// over.
///
/// Construction always goes through symlink-aware resolution, so two
/// `CanonicalScope`s can be compared with plain path containment without
/// re-resolving. A not-yet-created leaf is allowed as long as its nearest
/// existing ancestor resolves inside the workspace — write scope may target a
/// directory the child will create.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalScope(PathBuf);

impl CanonicalScope {
    /// Resolve a workspace-relative request into a canonical scope under
    /// `workspace_root`.
    ///
    /// Fails closed on absolute paths that land outside the workspace, on
    /// unresolved `..` traversal, and on symlinks whose target escapes. The
    /// request is a *scope*, not an output suggestion: an empty request is an
    /// error rather than a default.
    pub fn resolve_under(workspace_root: &Path, requested: &str) -> Result<Self, WriteScopeError> {
        let trimmed = requested.trim();
        if trimmed.is_empty() {
            return Err(WriteScopeError::InvalidScope {
                requested: requested.to_string(),
                reason: "write scope is required and must not be empty".into(),
            });
        }
        let root =
            Self::canonicalize(workspace_root).ok_or_else(|| WriteScopeError::InvalidScope {
                requested: requested.to_string(),
                reason: format!(
                    "workspace root `{}` does not resolve",
                    workspace_root.display()
                ),
            })?;
        let candidate = Path::new(trimmed);
        let joined = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            root.join(candidate)
        };
        let resolved =
            Self::canonicalize(&joined).ok_or_else(|| WriteScopeError::InvalidScope {
                requested: requested.to_string(),
                reason: "scope path does not resolve (symlink escape or `..` traversal)".into(),
            })?;
        if !path_contains(&root, &resolved) {
            return Err(WriteScopeError::ScopeEscapesWorkspace {
                requested: requested.to_string(),
                resolved: resolved.display().to_string(),
                workspace_root: root.display().to_string(),
            });
        }
        Ok(Self(resolved))
    }

    /// Build a scope from a path that is already known to be canonical (durable
    /// row rehydration). Recovery re-resolves before trusting it for authority.
    pub fn from_canonical(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// Re-resolve this scope against the live filesystem. Startup recovery and
    /// every permit revalidation use this: if the path's meaning changed (an
    /// ancestor was renamed or replaced by a symlink) the result differs and the
    /// caller must fail closed.
    pub fn reresolve(&self) -> Option<Self> {
        Self::canonicalize(&self.0).map(Self)
    }

    fn canonicalize(path: &Path) -> Option<PathBuf> {
        crate::path_containment::effective_path(path).ok()
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn display(&self) -> std::path::Display<'_> {
        self.0.display()
    }

    /// True when `candidate` is this scope or lives under it, compared by whole
    /// path components so `/ws/a` never contains `/ws/ab`.
    pub fn contains_path(&self, candidate: &Path) -> bool {
        path_contains(&self.0, candidate)
    }

    /// True when `other` is equal to or under this scope.
    pub fn contains_scope(&self, other: &Self) -> bool {
        path_contains(&self.0, &other.0)
    }

    /// True when `other` is *strictly* under this scope — under it and not
    /// equal to it. A delegated descendant must be strict: handing a child the
    /// parent's entire scope is not a sub-scope transfer.
    pub fn is_strict_subscope_of(&self, other: &Self) -> bool {
        self.0 != other.0 && path_contains(&other.0, &self.0)
    }

    /// True when neither scope contains the other. Sibling scopes are disjoint;
    /// ancestor/descendant pairs are not.
    pub fn is_disjoint_from(&self, other: &Self) -> bool {
        !self.contains_scope(other) && !other.contains_scope(self)
    }
}

/// Component-wise containment. `Path::starts_with` already compares whole
/// components, which is what makes the `/ws/a` vs `/ws/ab` prefix escape fail.
pub fn path_contains(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}

/// A lease's *effective* write authority: its base scope minus every
/// currently-delegated descendant exclusion.
///
/// Validating a new child against the base scope alone is forbidden — that is
/// exactly how two children end up with overlapping authority over the same
/// subtree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveAuthority {
    base: CanonicalScope,
    exclusions: Vec<CanonicalScope>,
}

impl EffectiveAuthority {
    pub fn new(base: CanonicalScope, mut exclusions: Vec<CanonicalScope>) -> Self {
        exclusions.sort();
        exclusions.dedup();
        Self { base, exclusions }
    }

    pub fn base(&self) -> &CanonicalScope {
        &self.base
    }

    pub fn exclusions(&self) -> &[CanonicalScope] {
        &self.exclusions
    }

    /// True when a concrete path may be written under this authority: inside
    /// the base scope and inside none of the delegated exclusions.
    pub fn allows_path(&self, path: &Path) -> bool {
        if !self.base.contains_path(path) {
            return false;
        }
        !self
            .exclusions
            .iter()
            .any(|excluded| excluded.contains_path(path))
    }

    /// Whether `candidate` may be delegated away from this authority.
    ///
    /// It must be a *strict* sub-scope of the base and must not intersect any
    /// existing exclusion in either direction: a candidate that contains an
    /// exclusion would re-delegate authority this owner no longer holds, and a
    /// candidate inside an exclusion was already given away.
    pub fn admits_subscope(&self, candidate: &CanonicalScope) -> Result<(), WriteScopeError> {
        if !candidate.is_strict_subscope_of(&self.base) {
            return Err(WriteScopeError::NotStrictSubscope {
                candidate: candidate.display().to_string(),
                base: self.base.display().to_string(),
            });
        }
        for excluded in &self.exclusions {
            if !candidate.is_disjoint_from(excluded) {
                return Err(WriteScopeError::IntersectsDelegatedExclusion {
                    candidate: candidate.display().to_string(),
                    exclusion: excluded.display().to_string(),
                });
            }
        }
        Ok(())
    }

    /// Add a delegated exclusion (ParentExcluded).
    pub fn with_exclusion(&self, scope: CanonicalScope) -> Self {
        let mut exclusions = self.exclusions.clone();
        exclusions.push(scope);
        Self::new(self.base.clone(), exclusions)
    }

    /// Drop a delegated exclusion (ParentRestored).
    pub fn without_exclusion(&self, scope: &CanonicalScope) -> Self {
        let exclusions = self
            .exclusions
            .iter()
            .filter(|e| *e != scope)
            .cloned()
            .collect();
        Self::new(self.base.clone(), exclusions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(p: &str) -> CanonicalScope {
        CanonicalScope::from_canonical(p)
    }

    #[test]
    fn component_wise_containment_rejects_prefix_siblings() {
        let a = scope("/ws/a");
        assert!(a.contains_path(Path::new("/ws/a/inner.txt")));
        assert!(a.contains_path(Path::new("/ws/a")));
        // `/ws/ab` shares a textual prefix but is a different directory.
        assert!(!a.contains_path(Path::new("/ws/ab/inner.txt")));
        assert!(!a.contains_path(Path::new("/ws/ab")));
    }

    #[test]
    fn strict_subscope_excludes_equality_and_ancestors() {
        let base = scope("/ws/a");
        assert!(scope("/ws/a/b").is_strict_subscope_of(&base));
        // Equal is not strict.
        assert!(!scope("/ws/a").is_strict_subscope_of(&base));
        // Ancestor is not a sub-scope.
        assert!(!scope("/ws").is_strict_subscope_of(&base));
        // Sibling is not a sub-scope.
        assert!(!scope("/ws/b").is_strict_subscope_of(&base));
    }

    #[test]
    fn effective_authority_subtracts_delegated_exclusions() {
        let auth = EffectiveAuthority::new(scope("/ws"), vec![scope("/ws/a")]);
        assert!(auth.allows_path(Path::new("/ws/b/file.txt")));
        // Inside a delegated exclusion the parent is denied.
        assert!(!auth.allows_path(Path::new("/ws/a/file.txt")));
        assert!(!auth.allows_path(Path::new("/ws/a")));
        // Outside the base entirely.
        assert!(!auth.allows_path(Path::new("/other/file.txt")));
    }

    #[test]
    fn admits_subscope_rejects_every_escape_shape() {
        let auth = EffectiveAuthority::new(scope("/ws"), vec![scope("/ws/a")]);

        assert!(auth.admits_subscope(&scope("/ws/b")).is_ok());

        // Equal to base — not strict.
        assert!(matches!(
            auth.admits_subscope(&scope("/ws")),
            Err(WriteScopeError::NotStrictSubscope { .. })
        ));
        // Ancestor of base.
        assert!(matches!(
            auth.admits_subscope(&scope("/")),
            Err(WriteScopeError::NotStrictSubscope { .. })
        ));
        // Sibling of base.
        assert!(matches!(
            auth.admits_subscope(&scope("/elsewhere")),
            Err(WriteScopeError::NotStrictSubscope { .. })
        ));
        // Textual-prefix sibling of base.
        assert!(matches!(
            auth.admits_subscope(&scope("/wsx")),
            Err(WriteScopeError::NotStrictSubscope { .. })
        ));
        // Already delegated away.
        assert!(matches!(
            auth.admits_subscope(&scope("/ws/a")),
            Err(WriteScopeError::IntersectsDelegatedExclusion { .. })
        ));
        // Inside something already delegated away.
        assert!(matches!(
            auth.admits_subscope(&scope("/ws/a/deeper")),
            Err(WriteScopeError::IntersectsDelegatedExclusion { .. })
        ));
    }

    #[test]
    fn candidate_containing_an_exclusion_is_refused() {
        // The parent delegated /ws/a/b away; it may not now delegate /ws/a,
        // which would hand out authority it no longer holds.
        let auth = EffectiveAuthority::new(scope("/ws"), vec![scope("/ws/a/b")]);
        assert!(matches!(
            auth.admits_subscope(&scope("/ws/a")),
            Err(WriteScopeError::IntersectsDelegatedExclusion { .. })
        ));
    }

    #[test]
    fn resolve_under_rejects_traversal_and_symlink_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        // Plain relative scope resolves.
        let ok = CanonicalScope::resolve_under(&root, "a").unwrap();
        assert!(ok.contains_path(&root.join("a/new-file.txt")));

        // A not-yet-created leaf is allowed (write scope may target a leaf the
        // child will create).
        assert!(CanonicalScope::resolve_under(&root, "a/not-yet").is_ok());

        // Empty is an error, never a default.
        assert!(matches!(
            CanonicalScope::resolve_under(&root, "   "),
            Err(WriteScopeError::InvalidScope { .. })
        ));

        // `..` traversal out of the workspace.
        assert!(CanonicalScope::resolve_under(&root, "../outside").is_err());

        // Absolute path outside the workspace.
        assert!(matches!(
            CanonicalScope::resolve_under(&root, outside.to_str().unwrap()),
            Err(WriteScopeError::ScopeEscapesWorkspace { .. })
        ));

        #[cfg(unix)]
        {
            // A symlink inside the workspace pointing out of it must resolve to
            // its target and then fail containment.
            std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
            assert!(matches!(
                CanonicalScope::resolve_under(&root, "escape"),
                Err(WriteScopeError::ScopeEscapesWorkspace { .. })
            ));
            // Through the symlink too.
            assert!(CanonicalScope::resolve_under(&root, "escape/deeper").is_err());
        }
    }
}
