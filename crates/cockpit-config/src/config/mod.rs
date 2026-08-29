//! Configuration loaders for `cockpit`.
//!
//! cockpit reads its own config files in its own locations — see
//! `project guidance` "Design rules" and the [[config_layering]] plan. It does
//! **not** parse `opencode.json` or any `.opencode/` directory.
//!
//! Layout (GOALS §2a):
//!
//! - One `config.json` per discovered `.cockpit/` directory — see
//!   `dirs::discover_config_dirs` for the walk order. It holds layer-wide
//!   provider metadata (`active_model`, `on_unlisted_models_fetch`) and the
//!   cockpit-only superset described in `the design notes` §4 as top-level keys (typed
//!   by `extended.rs` via `ExtendedConfig`/`ExtendedConfigDoc`). Provider
//!   bodies live beside it under `providers/<provider-id>.json` and are typed
//!   by `providers.rs` via `ConfigDoc`.
//! - The retired `extended-config.json` is read by no code path; a stray
//!   one in a discovered layer triggers a single one-time warning (see
//!   `dirs::warn_if_stray_extended_config`) and is otherwise ignored.

macro_rules! default_const {
    ($name:ident, $ty:ty, $val:expr) => {
        fn $name() -> $ty {
            $val
        }
    };
}

pub mod dirs;
pub mod effective_default;
pub mod extended;
mod files;
pub mod image_generation;
pub mod image_sidecar;
pub mod image_spend;
pub mod media_budget;
pub(crate) mod merge;
pub mod model_defaults;
pub mod model_policy;
pub mod provider;
pub mod providers;
pub mod resolve;
pub mod sandbox_mode;
pub mod trust;

/// Maximum bytes accepted from one capability-bound workspace configuration
/// leaf.  Every daemon-owned workspace reader, including hook configuration,
/// uses this one policy limit so an attacker cannot turn a configuration
/// refresh into an unbounded allocation.
pub const MAX_WORKSPACE_CONFIG_FILE_BYTES: usize = 2 * 1024 * 1024;

/// Immutable bytes captured from one attach-time configuration layer through
/// a retained directory handle. A layer can be trusted global, project, or an
/// explicit override. This is deliberately a data object, rather than a
/// filesystem capability: parsing/projection can therefore stay in this lower
/// crate while the daemon retains ownership of the directory handle that
/// authorized acquisition. In particular, a global layer never grants
/// workspace filesystem authority.
///
/// `provider_files` is ordered by its validated provider id.  The bytes are
/// bounded regular files read without following a path component; callers must
/// discard the entire capture on an acquisition error instead of combining a
/// partial layer with a later retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceConfigLayerSnapshot {
    pub config_json: Option<Vec<u8>>,
    pub provider_files: Vec<(String, Vec<u8>)>,
    /// Opaque digest of the exact effective-default journal/backup pair read
    /// for this selected leaf. The raw backup can contain configuration
    /// secrets, so it never leaves acquisition; its digest still participates
    /// in the authoritative configuration revision.
    pub effective_default_artifact_digest: Option<String>,
    pub digest: String,
}

/// Ordered attach-time configuration layers, from least to most specific.
/// The aggregate digest is framed over the per-layer digests and is the only
/// revision token a daemon worker publishes for the capability-backed config
/// contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceConfigLayerSnapshotChain {
    pub layers: Vec<WorkspaceConfigLayerSnapshot>,
    /// This snapshot is a complete retained effective chain, so the ambient
    /// loader must not rediscover normal layers beside it. An explicit
    /// `COCKPIT_CONFIG` is the one-layer case; normal worker snapshots retain
    /// every attach-time source to keep global/project provenance and reload
    /// on the same authority chain.
    pub exclusive: bool,
    pub digest: String,
}

pub fn workspace_config_layer_snapshot_chain(
    layers: Vec<WorkspaceConfigLayerSnapshot>,
) -> WorkspaceConfigLayerSnapshotChain {
    workspace_config_layer_snapshot_chain_with_exclusive(layers, false)
}

pub fn workspace_config_layer_snapshot_chain_with_exclusive(
    layers: Vec<WorkspaceConfigLayerSnapshot>,
    exclusive: bool,
) -> WorkspaceConfigLayerSnapshotChain {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"cockpit-workspace-config-layer-chain-v1");
    hasher.update([u8::from(exclusive)]);
    hasher.update((layers.len() as u64).to_be_bytes());
    for layer in &layers {
        hasher.update((layer.digest.len() as u64).to_be_bytes());
        hasher.update(layer.digest.as_bytes());
    }
    WorkspaceConfigLayerSnapshotChain {
        layers,
        exclusive,
        digest: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    }
}

/// An intentionally empty retained layer used when a daemon has kept an
/// attach-time capability for a source that current workspace policy no
/// longer permits projecting.  Keeping the slot (rather than compacting the
/// chain) makes retained provider-source indices stable while ensuring no
/// config, provider, or transaction-artifact bytes from the denied source
/// enter the resolved view.
pub fn empty_workspace_config_layer_snapshot() -> WorkspaceConfigLayerSnapshot {
    files::empty_workspace_config_layer_snapshot()
}

/// Capture the project-local `.cockpit` configuration layer relative to an
/// already-open workspace directory.  No pathname below that directory is
/// reopened, so replacing the workspace pathname after attachment cannot
/// redirect the returned bytes.
pub fn snapshot_workspace_config_layer_from_retained_directory(
    directory: &std::fs::File,
) -> anyhow::Result<WorkspaceConfigLayerSnapshot> {
    files::snapshot_workspace_config_layer_from_retained_directory(directory)
}

/// Capture one config file and its sibling provider directory relative to an
/// already-held *config-directory* handle. The leaf must be a single normal
/// path component; this supports a trusted explicit `COCKPIT_CONFIG` without
/// reopening its mutable absolute path.
pub fn snapshot_workspace_config_layer_from_retained_config_directory(
    directory: &std::fs::File,
    config_leaf: &std::ffi::OsStr,
    canonical_config_path: &std::path::Path,
    journal_leaf: Option<&std::ffi::OsStr>,
    backup_leaf: Option<&std::ffi::OsStr>,
) -> anyhow::Result<WorkspaceConfigLayerSnapshot> {
    files::snapshot_workspace_config_layer_from_retained_config_directory(
        directory,
        config_leaf,
        canonical_config_path,
        journal_leaf,
        backup_leaf,
    )
}

/// Derive a new retained-layer snapshot with replacement `config.json` bytes
/// while preserving its acquired provider inventory and artifact digest. This
/// is a pure operation; it never reopens the source directory.
pub fn workspace_config_layer_snapshot_with_config_json(
    snapshot: &WorkspaceConfigLayerSnapshot,
    config_json: Option<Vec<u8>>,
) -> WorkspaceConfigLayerSnapshot {
    files::workspace_config_layer_snapshot_with_config_json(snapshot, config_json)
}

/// A held cross-process config mutation lock.
///
/// The lock itself is crate-internal; this handle exists so higher layers can
/// prove contended-lock behavior (a `/model` deadline must expire *before* the
/// durable commit boundary and mutate nothing) without reaching into the
/// private file module.
///
/// `!Send` by construction, inherited from the inner guard: the lock's
/// re-entrancy depth is thread-local, so a guard that crossed threads would
/// corrupt it in both directions.
pub struct HeldConfigMutationLock(#[allow(dead_code)] files::ConfigMutationLock);

/// Acquire and hold the shared config mutation lock until the returned handle
/// is dropped.
pub fn hold_config_mutation_lock(
    target: &std::path::Path,
) -> anyhow::Result<HeldConfigMutationLock> {
    files::ConfigMutationLock::acquire(target).map(HeldConfigMutationLock)
}

/// Try to acquire the shared config mutation lock until `deadline`.
///
/// This is intended for pre-socket recovery, where waiting forever on a lock
/// left behind by another process would prevent clients from reaching the
/// daemon's diagnostic and settlement APIs. `Ok(None)` means the lock remained
/// busy through the deadline; callers must retain their durable pending work.
pub fn try_hold_config_mutation_lock_until(
    target: &std::path::Path,
    deadline: std::time::Instant,
) -> anyhow::Result<Option<HeldConfigMutationLock>> {
    files::ConfigMutationLock::acquire_until(target, deadline)
        .map(|guard| guard.map(HeldConfigMutationLock))
}

/// Commit already-rendered configuration bytes with the same audited atomic
/// writer used by typed config documents. Higher layers must hold
/// [`hold_config_mutation_lock`] while checking/reloading their target.
pub fn write_config_bytes_atomic(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    files::atomic_write(path, bytes)
}

/// Durably remove one configuration file without following a final symlink.
/// Callers must hold [`hold_config_mutation_lock`] while resolving and
/// removing the target.
pub fn remove_config_file_atomic(path: &std::path::Path) -> anyhow::Result<()> {
    files::remove_file_nofollow(path)
}

/// Durably commit directory-entry changes without following a symlink at the
/// directory itself. Multi-file daemon journals use this after each rename or
/// unlink so their persisted phase never gets ahead of filesystem metadata.
pub fn sync_directory_nofollow(path: &std::path::Path) -> anyhow::Result<()> {
    files::fsync_dir(path)
}

/// Reuse the audited component-relative/no-follow private-file primitive for
/// short-lived terminal ingress. Callers must still enforce their own root,
/// filename, media, and lifecycle policy.
pub fn write_terminal_ingress_private_file(
    path: &std::path::Path,
    bytes: &[u8],
) -> anyhow::Result<TerminalIngressFileIdentity> {
    files::prepare_atomic_write(path, bytes)?.commit_noreplace()?;
    let (_, _, identity) = files::read_file_nofollow_with_identity(path, false, true)?
        .ok_or_else(|| anyhow::anyhow!("published terminal ingress file disappeared"))?;
    Ok(identity)
}

/// Create/open every terminal-ingress directory component without following
/// symlinks or reparse points and enforce the platform private-directory mode.
pub fn ensure_terminal_ingress_private_dir(path: &std::path::Path) -> anyhow::Result<()> {
    files::ensure_parent_dir_private(&path.join("ingress-leaf"))
}

/// Read a terminal-ingress file through the same retained-parent no-follow
/// implementation used by config journals.
pub fn read_terminal_ingress_file_nofollow(
    path: &std::path::Path,
) -> anyhow::Result<Option<Vec<u8>>> {
    files::read_file_nofollow(path)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalIngressFileIdentity {
    pub volume: u64,
    pub file: u64,
    pub links: u32,
}

#[derive(Debug)]
pub struct VerifiedTerminalIngressFile {
    file: std::fs::File,
    pub bytes: Vec<u8>,
    pub identity: TerminalIngressFileIdentity,
}

impl Drop for VerifiedTerminalIngressFile {
    fn drop(&mut self) {
        // The held exact object is scrubbed even if a same-user process renamed
        // it after verification. Do not perform a later pathname unlink: POSIX
        // has no conditional unlink-by-identity primitive, so check-then-unlink
        // could delete a same-user replacement. Generation teardown owns the
        // remaining private namespace; this handle cleanup targets only the
        // proven object.
        let _ = self.file.set_len(0);
    }
}

pub fn read_terminal_ingress_file_verified(
    path: &std::path::Path,
) -> anyhow::Result<Option<(Vec<u8>, TerminalIngressFileIdentity)>> {
    Ok(files::read_file_nofollow_with_identity(path, false, true)?
        .map(|(_, bytes, identity)| (bytes, identity)))
}

/// Read an authority-bearing configuration file without following a planted
/// path component. Missing files are reported as `None`.
pub fn read_config_file_nofollow(path: &std::path::Path) -> anyhow::Result<Option<Vec<u8>>> {
    files::read_file_nofollow(path)
}

/// Read a configuration target through the audited retained-parent,
/// component-relative no-follow primitive and return its stable filesystem
/// identity. Daemon capabilities use this to reject same-content pathname
/// substitution between snapshot and commit.
pub fn read_config_file_nofollow_with_identity(
    path: &std::path::Path,
) -> anyhow::Result<Option<(Vec<u8>, TerminalIngressFileIdentity)>> {
    Ok(files::read_file_nofollow_with_identity(path, false, false)?
        .map(|(_, bytes, identity)| (bytes, identity)))
}

/// Retain an existing directory without following any path component.
pub fn open_config_directory_nofollow(path: &std::path::Path) -> anyhow::Result<std::fs::File> {
    files::open_directory_handle_nofollow(path)
}

/// Read one bounded regular-file leaf relative to a retained directory.
/// Path replacement after the directory was opened cannot redirect this read.
pub fn read_config_leaf_from_retained_directory(
    directory: &std::fs::File,
    leaf: &std::ffi::OsStr,
    max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    files::read_leaf_from_directory_handle(directory, leaf, max_bytes)
}

/// Snapshot every visible Markdown document below an existing directory using
/// component-relative, no-follow handles. Symlinks/reparse points and identity
/// ambiguity fail the entire snapshot; callers never mix trusted and untrusted
/// descendants.
pub fn snapshot_markdown_tree_nofollow(
    root: &std::path::Path,
    max_files: usize,
    max_entries: usize,
    max_depth: usize,
    max_file_bytes: usize,
    max_total_bytes: usize,
) -> anyhow::Result<Vec<(std::path::PathBuf, String)>> {
    files::snapshot_markdown_tree_nofollow(
        root,
        max_files,
        max_entries,
        max_depth,
        max_file_bytes,
        max_total_bytes,
    )
}

pub fn hold_terminal_ingress_file_verified(
    path: &std::path::Path,
) -> anyhow::Result<Option<VerifiedTerminalIngressFile>> {
    Ok(
        files::read_file_nofollow_with_identity(path, true, true)?.map(
            |(file, bytes, identity)| VerifiedTerminalIngressFile {
                file,
                bytes,
                identity,
            },
        ),
    )
}

/// Remove the exact no-follow terminal-ingress entry through the audited
/// retained-parent platform primitive.
pub fn remove_terminal_ingress_file_nofollow(path: &std::path::Path) -> anyhow::Result<()> {
    files::remove_file_nofollow(path)
}

/// Move an authority-bearing regular file between two retained, no-follow
/// parent directory handles. Both parent identities and the source entry are
/// checked immediately before the move. The required cross-process mutation
/// guard serializes cooperating Flycockpit writers; it is not a reentrant lock
/// and does not exclude a malicious same-UID process. Unix therefore performs
/// a post-operation identity proof and reports an explicitly recoverable
/// two-name/namespace state if a noncooperating substitution is detected.
/// Windows moves the already-open source handle relative to a retained
/// destination handle. Callers cannot accidentally perform a bare pathname
/// check/rename sequence, but must retain their durable journal until this
/// function returns success.
pub fn rename_config_file_nofollow(
    _mutation_lock: &HeldConfigMutationLock,
    source: &std::path::Path,
    destination: &std::path::Path,
) -> anyhow::Result<()> {
    files::rename_file_nofollow(source, destination)
}

/// Compare two regular no-follow entries by stable filesystem identity.
/// Used only to reconcile the recoverable two-name state of a link/unlink
/// no-replace fallback.
pub fn same_config_file_identity_nofollow(
    left: &std::path::Path,
    right: &std::path::Path,
) -> anyhow::Result<bool> {
    files::same_file_identity_nofollow(left, right)
}

#[cfg(all(test, unix))]
mod terminal_ingress_cleanup_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn held_cleanup_scrubs_exact_inode_without_deleting_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let published = temp.path().join("published.png");
        let renamed = temp.path().join("renamed.png");
        std::fs::write(&published, b"verified-image").unwrap();
        std::fs::set_permissions(&published, std::fs::Permissions::from_mode(0o600)).unwrap();

        let held = hold_terminal_ingress_file_verified(&published)
            .unwrap()
            .unwrap();
        std::fs::rename(&published, &renamed).unwrap();
        std::fs::write(&published, b"replacement-must-survive").unwrap();
        std::fs::set_permissions(&published, std::fs::Permissions::from_mode(0o600)).unwrap();

        drop(held);

        assert_eq!(
            std::fs::read(&published).unwrap(),
            b"replacement-must-survive"
        );
        assert!(std::fs::read(&renamed).unwrap().is_empty());
    }
}
