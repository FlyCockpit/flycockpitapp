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
