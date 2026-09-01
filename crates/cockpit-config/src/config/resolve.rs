//! Well-known cockpit paths.
//!
//! Centralized so all callers (daemon, db, debug commands, init)
//! agree on where files live. Directory discovery for layered
//! `.cockpit/` configs lives in [`crate::config::dirs`]; this module
//! is only for the fixed system-level paths.

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Platform-default global configuration directory.
///
/// This is `~/.config/cockpit` on Linux (respecting `XDG_CONFIG_HOME`) and
/// the platform configuration location elsewhere. It is intentionally
/// separate from workspace `.cockpit/` directories: workspace trust controls
/// only those project-local layers, never this user-owned global directory.
pub fn cockpit_config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("could not locate user config dir")?;
    Ok(base.join("cockpit"))
}

/// `~/.local/share/cockpit/` on Unix (`$XDG_DATA_HOME/cockpit` if set),
/// `%APPDATA%\cockpit` on Windows. Holds the session SQLite database
/// and any other durable user data the daemon writes between runs.
pub fn cockpit_data_dir() -> Result<PathBuf> {
    if let Ok(s) = std::env::var("XDG_DATA_HOME")
        && !s.trim().is_empty()
    {
        return Ok(PathBuf::from(s).join("cockpit"));
    }
    let base = dirs::data_dir().context("could not locate user data dir")?;
    Ok(base.join("cockpit"))
}

/// `~/.local/state/cockpit/` on Unix (`$XDG_STATE_HOME/cockpit` if
/// set), `%LOCALAPPDATA%\cockpit\state` on Windows. Holds the daemon
/// pid file, lock-state mirror snapshots, and rotating logs
/// (implementation notes §5).
/// State-dir resolver, used by the daemon state paths (implementation
/// notes §5) and by the TUI's private clipboard recovery artifact
/// directory (`crates/cockpit-tui/src/clipboard/recovery`).
pub fn cockpit_state_dir() -> Result<PathBuf> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
