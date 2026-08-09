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
pub mod media_budget;
pub(crate) mod merge;
pub mod model_defaults;
pub mod model_policy;
pub mod provider;
pub mod providers;
pub mod resolve;
pub mod sandbox_mode;
pub mod trust;

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

/// Reuse the audited component-relative/no-follow private-file primitive for
/// short-lived terminal ingress. Callers must still enforce their own root,
/// filename, media, and lifecycle policy.
pub fn write_terminal_ingress_private_file(
    path: &std::path::Path,
    bytes: &[u8],
) -> anyhow::Result<TerminalIngressFileIdentity> {
    files::prepare_atomic_write(path, bytes)?.commit_noreplace()?;
    let (_, _, identity) = files::read_file_nofollow_with_identity(path)?
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
    path: std::path::PathBuf,
    pub bytes: Vec<u8>,
    pub identity: TerminalIngressFileIdentity,
    cleanup_armed: bool,
}

impl Drop for VerifiedTerminalIngressFile {
    fn drop(&mut self) {
        if !self.cleanup_armed {
            return;
        }
        // The held exact object is scrubbed even if a same-user process renamed
        // it after verification. Removal of the published name remains
        // identity-gated and never follows a replacement.
        let _ = self.file.set_len(0);
        if let Ok(Some((_, _, current))) = files::read_file_nofollow_with_identity(&self.path)
            && current == self.identity
        {
            let _ = files::remove_file_nofollow(&self.path);
        }
    }
}

pub fn read_terminal_ingress_file_verified(
    path: &std::path::Path,
) -> anyhow::Result<Option<(Vec<u8>, TerminalIngressFileIdentity)>> {
    Ok(
        files::read_file_nofollow_with_identity(path)?
            .map(|(_, bytes, identity)| (bytes, identity)),
    )
}

pub fn hold_terminal_ingress_file_verified(
    path: &std::path::Path,
) -> anyhow::Result<Option<VerifiedTerminalIngressFile>> {
    Ok(
        files::read_file_nofollow_with_identity(path)?.map(|(file, bytes, identity)| {
            VerifiedTerminalIngressFile {
                file,
                path: path.to_path_buf(),
                bytes,
                identity,
                cleanup_armed: true,
            }
        }),
    )
}

/// Remove the exact no-follow terminal-ingress entry through the audited
/// retained-parent platform primitive.
pub fn remove_terminal_ingress_file_nofollow(path: &std::path::Path) -> anyhow::Result<()> {
    files::remove_file_nofollow(path)
}
