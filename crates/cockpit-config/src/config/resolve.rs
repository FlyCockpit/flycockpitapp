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
//! In test builds (`cfg(any(test, feature = "test-support"))`), the three public
//! resolvers below pass through [`cockpit_test_support::home_isolation`]:
//!
//! 1. Explicit env overrides installed by [`cockpit_test_support::TestEnvGuard`]
//!    (XDG/HOME pointing away from the real developer profile) win unchanged.
//! 2. [`cockpit_test_support::home_isolation::COCKPIT_TEST_ALLOW_REAL_HOME_ENV`]=`1`
//!    opts into the real path (manual smokes only).
//! 3. Otherwise redirect to a lazy per-process isolated home mirroring
//!    `TestEnvGuard::set_isolated_home` (`{root}/home/.config/cockpit`,
//!    `{root}/data/cockpit`, `{root}/state/cockpit`).
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

/// An installation root (config, data, state, or cache) did not resolve to a
/// fully absolute path. Such a path would be interpreted against the process
/// working directory (or, on Windows, the current drive), letting the launch
/// location choose the user-global layer, so resolution fails instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonAbsoluteInstallationRoot {
    /// The environment variable or platform lookup the path came from.
    pub source: &'static str,
    pub path: PathBuf,
}

impl std::fmt::Display for NonAbsoluteInstallationRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} resolved to `{}`, which is not an absolute path; set it to an absolute directory",
            self.source,
            self.path.display()
        )
    }
}

impl std::error::Error for NonAbsoluteInstallationRoot {}

fn require_absolute(source: &'static str, path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(NonAbsoluteInstallationRoot { source, path }.into())
    }
}

/// An explicit XDG base-directory override, honored on every platform so the
/// config, data, and state roots follow one rule. Per the XDG spec a purely
/// relative value is ignored. A value that carries a root but is not absolute
/// (Windows `\config` or `C:config`) would resolve against the current drive
/// or its working directory, so it is an error rather than a silent fallback.
fn xdg_base_override(variable: &'static str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(variable) else {
        return Ok(None);
    };
    if value.to_string_lossy().trim().is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return Ok(Some(path));
    }
    let anchored = path.components().any(|component| {
        matches!(
            component,
            std::path::Component::Prefix(_) | std::path::Component::RootDir
        )
    });
    if anchored {
        return Err(NonAbsoluteInstallationRoot {
            source: variable,
            path,
        }
        .into());
    }
    Ok(None)
}

pub(crate) fn cockpit_config_dir_unchecked() -> Result<PathBuf> {
    // `dirs::config_dir()` already honors XDG_CONFIG_HOME on Linux but not on
    // Windows (FOLDERID_RoamingAppData) or macOS (Application Support); the
    // data and state roots below honor their XDG overrides everywhere, so the
    // config root does too.
    if let Some(base) = xdg_base_override("XDG_CONFIG_HOME")? {
        return Ok(base.join("cockpit"));
    }
    let base = dirs::config_dir().context("could not locate user config dir")?;
    Ok(require_absolute("the platform config directory", base)?.join("cockpit"))
}

pub(crate) fn cockpit_data_dir_unchecked() -> Result<PathBuf> {
    if let Some(base) = xdg_base_override("XDG_DATA_HOME")? {
        return Ok(base.join("cockpit"));
    }
    let base = dirs::data_dir().context("could not locate user data dir")?;
    Ok(require_absolute("the platform data directory", base)?.join("cockpit"))
}

pub(crate) fn cockpit_state_dir_unchecked() -> Result<PathBuf> {
    if let Some(base) = xdg_base_override("XDG_STATE_HOME")? {
        return Ok(base.join("cockpit"));
    }
    #[cfg(unix)]
    {
        let home = dirs::home_dir().context("could not locate home dir")?;
        Ok(require_absolute("HOME", home)?.join(".local/state/cockpit"))
    }
    #[cfg(not(unix))]
    {
        let base = dirs::data_local_dir().context("could not locate local data dir")?;
        Ok(require_absolute("the platform local data directory", base)?
            .join("cockpit")
            .join("state"))
    }
}

/// Cockpit's cache directory: `$XDG_CACHE_HOME/cockpit` when a rooted
/// `XDG_CACHE_HOME` is set (on every platform, like the config, data, and
/// state roots), otherwise the platform cache location (`~/.cache/cockpit`
/// on Linux, `~/Library/Caches/cockpit` on macOS, `%LOCALAPPDATA%\cockpit`
/// on Windows). Holds the CLI log and disposable caches; nothing here is
/// authoritative state.
pub fn cockpit_cache_dir() -> Result<PathBuf> {
    if let Some(base) = xdg_base_override("XDG_CACHE_HOME")? {
        return Ok(base.join("cockpit"));
    }
    let base = dirs::cache_dir().context("could not locate user cache dir")?;
    Ok(require_absolute("the platform cache directory", base)?.join("cockpit"))
}

/// Platform-default global configuration directory.
///
/// A rooted `XDG_CONFIG_HOME` wins on every platform (as `XDG_DATA_HOME` and
/// `XDG_STATE_HOME` do for the data and state roots). Otherwise this is
/// `~/.config/cockpit` on Linux and the platform configuration location
/// elsewhere (`%APPDATA%\cockpit` on Windows). It is intentionally
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn data_dir_respects_xdg() {
        let env = crate::test_env::lock();
        // A fully absolute base on every platform (`/tmp/..` is rooted but
        // drive-relative on Windows, which installation roots reject).
        let base = std::env::temp_dir().join("xdg-data-test");
        env.set_var("XDG_DATA_HOME", &base);
        let p = cockpit_data_dir().unwrap();
        assert_eq!(p, base.join("cockpit"));
    }

    #[test]
    fn config_dir_respects_platform_config_home() {
        let env = crate::test_env::lock();
        // A fully absolute base on every platform (`/tmp/..` is rooted but
        // drive-relative on Windows, which installation roots reject).
        let base = std::env::temp_dir().join("xdg-config-test");
        env.set_var("XDG_CONFIG_HOME", &base);
        let path = cockpit_config_dir().unwrap();
        assert_eq!(path, base.join("cockpit"));
    }

    #[test]
    fn cache_dir_respects_xdg_cache_home_on_every_platform() {
        let env = crate::test_env::lock();
        // A fully absolute base on every platform (`/tmp/..` is rooted but
        // drive-relative on Windows, which installation roots reject).
        let base = std::env::temp_dir().join("xdg-cache-test");
        env.set_var("XDG_CACHE_HOME", &base);
        let path = cockpit_cache_dir().unwrap();
        assert_eq!(path, base.join("cockpit"));
    }

    #[test]
    fn cache_dir_ignores_a_relative_xdg_cache_home() {
        let env = crate::test_env::lock();
        env.set_var("XDG_CACHE_HOME", "relative-cache");
        let path = cockpit_cache_dir().unwrap();
        assert!(
            path.has_root(),
            "relative XDG_CACHE_HOME must be ignored: {}",
            path.display()
        );
    }

    #[test]
    fn state_dir_respects_xdg() {
        let env = crate::test_env::lock();
        // A fully absolute base on every platform (`/tmp/..` is rooted but
        // drive-relative on Windows, which installation roots reject).
        let base = std::env::temp_dir().join("xdg-state-test");
        env.set_var("XDG_STATE_HOME", &base);
        let p = cockpit_state_dir().unwrap();
        assert_eq!(p, base.join("cockpit"));
    }

    #[test]
    fn require_absolute_rejects_relative_roots() {
        let error = require_absolute("HOME", PathBuf::from("relative-home")).unwrap_err();
        assert_eq!(
            error.downcast_ref::<NonAbsoluteInstallationRoot>(),
            Some(&NonAbsoluteInstallationRoot {
                source: "HOME",
                path: PathBuf::from("relative-home"),
            })
        );
        let absolute = std::env::temp_dir();
        assert_eq!(
            require_absolute("HOME", absolute.clone()).unwrap(),
            absolute
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installation_roots_reject_a_relative_home() {
        let env = crate::test_env::lock();
        env.remove_var("XDG_CONFIG_HOME");
        env.remove_var("XDG_STATE_HOME");
        env.set_var("HOME", "relative-home");
        // On Linux the platform fallback derives from $HOME unvalidated, so
        // the guard below is what keeps the global layer off the cwd.
        assert_eq!(dirs::home_dir(), Some(PathBuf::from("relative-home")));
        for error in [
            cockpit_config_dir_unchecked().unwrap_err(),
            cockpit_state_dir_unchecked().unwrap_err(),
        ] {
            assert!(
                error
                    .downcast_ref::<NonAbsoluteInstallationRoot>()
                    .is_some(),
                "{error:#}"
            );
        }
    }

    #[test]
    fn rooted_but_not_absolute_xdg_override_is_an_error() {
        let env = crate::test_env::lock();
        #[cfg(windows)]
        for value in [r"\config", r"C:config"] {
            env.set_var("XDG_CONFIG_HOME", value);
            let error = cockpit_config_dir_unchecked().unwrap_err();
            assert!(
                error
                    .downcast_ref::<NonAbsoluteInstallationRoot>()
                    .is_some()
            );
        }
        // A purely relative value is ignored per the XDG spec, never joined
        // onto the working directory: the platform default applies.
        let home = std::env::temp_dir().join("xdg-relative-home");
        env.set_var("HOME", &home);
        env.set_var("XDG_CONFIG_HOME", "relative-config");
        let path = cockpit_config_dir_unchecked().expect("platform default applies");
        assert!(path.is_absolute(), "{}", path.display());
        assert!(!path.starts_with("relative-config"), "{}", path.display());
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
}
