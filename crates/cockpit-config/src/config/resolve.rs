//! Well-known cockpit paths.
//!
//! Centralized so all callers (daemon, db, debug commands, init)
//! agree on where files live. Directory discovery for layered
//! `.cockpit/` configs lives in [`crate::config::dirs`]; this module
//! is only for the fixed system-level paths.
//!
//! ## Test-build home isolation
//!
//! Production [`cockpit_config_dir`] semantics are unchanged: platform defaults
//! via `dirs::config_dir()` / XDG env vars, with no redirect.
//!
//! Public resolvers (all choke points for Cockpit-owned user roots):
//!
//! - [`cockpit_config_dir`]
//! - [`cockpit_data_dir`]
//! - [`cockpit_state_dir`]
//! - [`cockpit_cache_dir`]
//! - [`cockpit_runtime_dir`] (`Option` — `None` when `XDG_RUNTIME_DIR` is unset)
//!
//! In test builds (`cfg(any(test, feature = "test-support"))`), those five pass
//! through [`cockpit_test_support::home_isolation`] (`CockpitHomeKind` includes
//! `Cache`, `Runtime` (`$XDG_RUNTIME_DIR/cockpit`), and `RuntimeRoot`
//! (`$XDG_RUNTIME_DIR` for `cockpit-host` private runtime materialization):
//!
//! 1. Explicit env overrides installed by [`cockpit_test_support::TestEnvGuard`]
//!    (XDG/HOME pointing away from the real developer profile) win unchanged.
//! 2. [`cockpit_test_support::home_isolation::COCKPIT_TEST_ALLOW_REAL_HOME_ENV`]=`1`
//!    opts into the real path (manual smokes only).
//! 3. Otherwise redirect to a lazy per-process isolated home mirroring
//!    `TestEnvGuard::set_isolated_home` (`{root}/home/.config/cockpit`,
//!    `{root}/data/cockpit`, `{root}/state/cockpit`, `{root}/cache/cockpit`,
//!    `{root}/runtime/cockpit`, and `{root}/runtime` for `RuntimeRoot`).
//!
//! **Platform notes (greenfield):** `XDG_CACHE_HOME` is honored on every
//! platform when set. On Windows the state dir canonical path is
//! `%LOCALAPPDATA%\cockpit\state` (not under `%APPDATA%`).
//!
//! Under `cargo nextest` each test is its own process, so the isolated root is
//! per test. Under `cargo test` one binary shares it across threads; creation is
//! thread-safe via `OnceLock`.
//!
//! **Perimeter:** the redirect is compiled into every workspace test binary that
//! links `cockpit-config` with `cfg(test)` (this crate's own unit tests) or with
//! the `test-support` feature enabled from `[dev-dependencies]` (`cockpit-core`,
//! `cockpit-tui`, `apps/cli`, `cockpit-proto`, `apps/tenant-authority`, …).
//! Production dependents never enable `test-support`.

use std::path::PathBuf;

use anyhow::{Context, Result};

#[cfg(any(test, feature = "test-support"))]
use cockpit_test_support::home_isolation::{CockpitHomeKind, finalize_test_cockpit_path};

pub(crate) fn cockpit_config_dir_unchecked() -> Result<PathBuf> {
    let base = dirs::config_dir().context("could not locate user config dir")?;
    Ok(base.join("cockpit"))
}

pub(crate) fn cockpit_data_dir_unchecked() -> Result<PathBuf> {
    if let Ok(s) = std::env::var("XDG_DATA_HOME")
        && !s.trim().is_empty()
    {
        return Ok(PathBuf::from(s).join("cockpit"));
    }
    let base = dirs::data_dir().context("could not locate user data dir")?;
    Ok(base.join("cockpit"))
}

pub(crate) fn cockpit_state_dir_unchecked() -> Result<PathBuf> {
    if let Ok(s) = std::env::var("XDG_STATE_HOME")
        && !s.trim().is_empty()
    {
        return Ok(PathBuf::from(s).join("cockpit"));
    }
    #[cfg(unix)]
    {
        let home = dirs::home_dir().context("could not locate home dir")?;
        Ok(home.join(".local/state/cockpit"))
    }
    #[cfg(not(unix))]
    {
        let base = dirs::data_local_dir().context("could not locate local data dir")?;
        Ok(base.join("cockpit").join("state"))
    }
}

pub(crate) fn cockpit_cache_dir_unchecked() -> Result<PathBuf> {
    if let Ok(s) = std::env::var("XDG_CACHE_HOME")
        && !s.trim().is_empty()
    {
        return Ok(PathBuf::from(s).join("cockpit"));
    }
    let base = dirs::cache_dir().context("could not locate user cache dir")?;
    Ok(base.join("cockpit"))
}

pub(crate) fn cockpit_runtime_dir_unchecked() -> Option<PathBuf> {
    if let Ok(s) = std::env::var("XDG_RUNTIME_DIR")
        && !s.trim().is_empty()
    {
        return Some(PathBuf::from(s).join("cockpit"));
    }
    None
}

/// Platform-default global configuration directory.
///
/// This is `~/.config/cockpit` on Linux (respecting `XDG_CONFIG_HOME`) and
/// the platform configuration location elsewhere. It is intentionally
/// separate from workspace `.cockpit/` directories: workspace trust controls
/// only those project-local layers, never this user-owned global directory.
pub fn cockpit_config_dir() -> Result<PathBuf> {
    let path = cockpit_config_dir_unchecked()?;
    #[cfg(any(test, feature = "test-support"))]
    let path = finalize_test_cockpit_path(path, CockpitHomeKind::Config);
    Ok(path)
}

/// `~/.local/share/cockpit/` on Unix (`$XDG_DATA_HOME/cockpit` if set),
/// `%APPDATA%\cockpit` on Windows. Holds the session SQLite database
/// and any other durable user data the daemon writes between runs.
pub fn cockpit_data_dir() -> Result<PathBuf> {
    let path = cockpit_data_dir_unchecked()?;
    #[cfg(any(test, feature = "test-support"))]
    let path = finalize_test_cockpit_path(path, CockpitHomeKind::Data);
    Ok(path)
}

/// `~/.local/state/cockpit/` on Unix (`$XDG_STATE_HOME/cockpit` if
/// set), `%LOCALAPPDATA%\cockpit\state` on Windows. Holds the daemon
/// pid file, lock-state mirror snapshots, and rotating logs
/// (implementation notes §5).
/// State-dir resolver, used by the daemon state paths (implementation
/// notes §5) and by the TUI's private clipboard recovery artifact
/// directory (`crates/cockpit-tui/src/clipboard/recovery`).
pub fn cockpit_state_dir() -> Result<PathBuf> {
    let path = cockpit_state_dir_unchecked()?;
    #[cfg(any(test, feature = "test-support"))]
    let path = finalize_test_cockpit_path(path, CockpitHomeKind::State);
    Ok(path)
}

/// `$XDG_CACHE_HOME/cockpit` when set, otherwise the platform cache directory
/// with a `cockpit` suffix (for example `~/.cache/cockpit` on Linux).
pub fn cockpit_cache_dir() -> Result<PathBuf> {
    let path = cockpit_cache_dir_unchecked()?;
    #[cfg(any(test, feature = "test-support"))]
    let path = finalize_test_cockpit_path(path, CockpitHomeKind::Cache);
    Ok(path)
}

/// `$XDG_RUNTIME_DIR/cockpit` when `XDG_RUNTIME_DIR` is set and non-blank;
/// `None` when the runtime directory is unavailable.
pub fn cockpit_runtime_dir() -> Result<Option<PathBuf>> {
    let path = cockpit_runtime_dir_unchecked();
    #[cfg(any(test, feature = "test-support"))]
    let path = path.map(|path| finalize_test_cockpit_path(path, CockpitHomeKind::Runtime));
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn data_dir_respects_xdg() {
        let env = crate::test_env::lock();
        env.set_var("XDG_DATA_HOME", "/tmp/xdg-data-test");
        let p = cockpit_data_dir().unwrap();
        assert_eq!(p, PathBuf::from("/tmp/xdg-data-test/cockpit"));
    }

    #[test]
    fn config_dir_respects_platform_config_home() {
        let env = crate::test_env::lock();
        env.set_var("XDG_CONFIG_HOME", "/tmp/xdg-config-test");
        let path = cockpit_config_dir().unwrap();
        assert_eq!(path, PathBuf::from("/tmp/xdg-config-test/cockpit"));
    }

    #[test]
    fn state_dir_respects_xdg() {
        let env = crate::test_env::lock();
        env.set_var("XDG_STATE_HOME", "/tmp/xdg-state-test");
        let p = cockpit_state_dir().unwrap();
        assert_eq!(p, PathBuf::from("/tmp/xdg-state-test/cockpit"));
    }

    #[test]
    fn cache_dir_respects_xdg() {
        let env = crate::test_env::lock();
        env.set_var("XDG_CACHE_HOME", "/tmp/xdg-cache-test");
        let p = cockpit_cache_dir().unwrap();
        assert_eq!(p, PathBuf::from("/tmp/xdg-cache-test/cockpit"));
    }

    #[test]
    fn runtime_dir_respects_xdg() {
        let env = crate::test_env::lock();
        env.set_var("XDG_RUNTIME_DIR", "/tmp/xdg-runtime-test");
        let p = cockpit_runtime_dir().unwrap();
        assert_eq!(p, Some(PathBuf::from("/tmp/xdg-runtime-test/cockpit")));
    }

    #[test]
    fn runtime_dir_is_none_when_unset() {
        let env = crate::test_env::lock();
        env.remove_var("XDG_RUNTIME_DIR");
        let p = cockpit_runtime_dir().unwrap();
        assert_eq!(p, None);
    }

    #[test]
    fn config_dir_redirects_without_explicit_override() {
        use cockpit_test_support::home_isolation;

        let path = cockpit_config_dir().expect("resolve global config dir");
        home_isolation::assert_not_real_developer_cockpit_path(&path);
        assert!(
            path.ends_with(std::path::Path::new(".config").join("cockpit")),
            "redirected config dir should mirror the platform layout: {}",
            path.display()
        );
    }

    #[test]
    fn cache_dir_redirects_without_explicit_override() {
        use cockpit_test_support::home_isolation;

        let path = cockpit_cache_dir().expect("resolve global cache dir");
        home_isolation::assert_not_real_developer_cockpit_path(&path);
        assert!(
            path.ends_with(std::path::Path::new("cache").join("cockpit")),
            "redirected cache dir should mirror the platform layout: {}",
            path.display()
        );
    }

    #[test]
    fn runtime_dir_redirects_without_explicit_override() {
        use cockpit_test_support::home_isolation;

        home_isolation::ensure_real_developer_roots_captured();
        let env = crate::test_env::lock();
        let forced_runtime = home_isolation::real_developer_runtime_root_for_redirect_test();
        env.set_var("XDG_RUNTIME_DIR", forced_runtime.as_os_str());

        let path = cockpit_runtime_dir()
            .expect("resolve runtime dir")
            .expect("runtime dir should be set when XDG_RUNTIME_DIR is set");
        home_isolation::assert_not_real_developer_cockpit_path(&path);
        assert!(
            path.ends_with(std::path::Path::new("runtime").join("cockpit")),
            "redirected runtime dir should mirror the platform layout: {}",
            path.display()
        );
    }

    #[test]
    fn runtime_root_redirects_without_explicit_override() {
        use cockpit_test_support::home_isolation;

        home_isolation::ensure_real_developer_roots_captured();
        let env = crate::test_env::lock();
        let forced_runtime = home_isolation::real_developer_runtime_root_for_redirect_test();
        env.set_var("XDG_RUNTIME_DIR", forced_runtime.as_os_str());

        let path = cockpit_host::private_fs::private_runtime_root()
            .expect("private runtime root when XDG_RUNTIME_DIR is set");
        home_isolation::assert_not_real_developer_cockpit_path(&path);
        assert!(
            path.ends_with("runtime"),
            "redirected private runtime root should be the isolated runtime parent: {}",
            path.display()
        );
    }
}
