//! Deny-closed mapping from a canonical local project root to the 16-byte
//! control-plane project id used by attempt-grant permission ceilings.
//!
//! Local project ids in this daemon are 12-hex truncated hashes of canonical
//! roots (`crate::session`), which are *not* the grant's 16-byte control-plane
//! project ids. A verified attempt grant's ceiling is keyed by the
//! control-plane id, so the authorization path cannot derive the id from a
//! root hash — it must resolve it through an injected mapping owned by the
//! attachment/operation-ledger state.
//!
//! This module lands the trait, a deterministic test double, and the
//! authorization-side consumption. Production wiring of the resolver against
//! attachment/operation-ledger state is owned by the transport-wiring prompts;
//! see `attempt-grant-verification-and-principal-derivation` scope notes.
//!
//! The mapping is **deny-closed**: an unmapped root resolves to `None`, which
//! the authorization path treats as a hard authorization failure — never a
//! best-effort root hash.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Maps a canonical local project root to the control-plane project id a
/// verified attempt-grant ceiling is keyed by. Injected on `DaemonContext` so
/// the authorization path never derives an id from a root hash.
pub trait RemoteProjectResolver: Send + Sync {
    /// Resolve a canonical local project root to its 16-byte control-plane
    /// project id, or `None` when the root is not mapped (deny-closed).
    fn resolve_project_id(&self, canonical_root: &Path) -> Option<[u8; 16]>;
}

/// A deterministic in-memory resolver used by tests and, until the
/// transport-wiring prompts land, as an empty deny-all default. Maps exact
/// canonical root strings to fixed 16-byte project ids.
#[derive(Debug, Clone, Default)]
pub struct StaticRemoteProjectResolver {
    by_root: BTreeMap<PathBuf, [u8; 16]>,
}

impl StaticRemoteProjectResolver {
    /// An empty resolver that maps nothing (deny-all).
    pub fn new() -> Self {
        Self {
            by_root: BTreeMap::new(),
        }
    }

    /// Register a canonical root → project id mapping.
    pub fn with_mapping(
        mut self,
        canonical_root: impl Into<PathBuf>,
        project_id: [u8; 16],
    ) -> Self {
        self.by_root.insert(canonical_root.into(), project_id);
        self
    }
}

impl RemoteProjectResolver for StaticRemoteProjectResolver {
    fn resolve_project_id(&self, canonical_root: &Path) -> Option<[u8; 16]> {
        self.by_root.get(canonical_root).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_resolver_maps_known_roots_and_denies_unknown() {
        let pid = [7u8; 16];
        let resolver = StaticRemoteProjectResolver::new().with_mapping("/workspace/app", pid);
        assert_eq!(
            resolver.resolve_project_id(Path::new("/workspace/app")),
            Some(pid)
        );
        // Deny-closed: an unmapped root resolves to None, never a best-effort id.
        assert_eq!(
            resolver.resolve_project_id(Path::new("/workspace/other")),
            None
        );
        // The empty resolver denies every root.
        assert_eq!(
            StaticRemoteProjectResolver::new().resolve_project_id(Path::new("/workspace/app")),
            None
        );
    }
}
