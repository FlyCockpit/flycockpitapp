//! One module per top-level subcommand. Each module exposes a single
//! `pub async fn run(...)` that takes the relevant clap args struct.

use std::fmt;

pub const USAGE_EXIT_CODE: u8 = 64;
pub const REMOVED_COMMAND_EXIT_CODE: u8 = 2;

/// Canonical workspace key for the cross-workspace history-recall consent
/// stored under the daemon's `workspace_history_scopes` ledger (issue #299).
///
/// `config history-scope` and `trust history-scope` read and write the same
/// privacy setting, so both commands must send the identical `project_root`
/// wire key: the resolved workspace trust root for the opened path. The
/// daemon re-resolves whatever key it receives, but resolving it here as
/// well makes the shared key explicit and identical by construction
/// instead of an accident of daemon-side re-resolution.
pub(crate) fn history_scope_project_root(
    path: Option<std::path::PathBuf>,
) -> anyhow::Result<String> {
    let opened = match path {
        Some(path) => path,
        None => std::env::current_dir()?,
    };
    let trust_root = crate::config::trust::resolve_trust_root(&opened)?;
    Ok(trust_root.root.display().to_string())
}

#[cfg(test)]
mod history_scope_tests {
    use super::*;

    #[test]
    fn history_scope_key_is_shared_by_config_and_trust_commands() {
        // Both commands derive the key through `history_scope_project_root`,
        // so one path's setting can never become invisible to the other. The
        // key must be the workspace trust root regardless of which directory
        // inside the workspace the command was invoked from.
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let output = std::process::Command::new("git")
            .current_dir(&repo)
            .args(["init"])
            .output()
            .expect("run git init");
        assert!(
            output.status.success(),
            "git init failed in {}",
            repo.display()
        );
        let subdir = repo.join("crates").join("inner");
        std::fs::create_dir_all(&subdir).unwrap();

        let from_root = history_scope_project_root(Some(repo.clone())).unwrap();
        let from_subdir = history_scope_project_root(Some(subdir)).unwrap();
        assert_eq!(from_root, from_subdir);
        assert!(std::path::Path::new(&from_root).is_dir());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandUsageError {
    message: String,
}

impl CommandUsageError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CommandUsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CommandUsageError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedCommandError {
    message: String,
}

impl RemovedCommandError {
    pub fn new(command: &'static str) -> Self {
        let account_command = match command {
            "login" => "cockpit account login",
            "logout" => "cockpit account logout",
            "whoami" => "cockpit account whoami",
            _ => "cockpit account login",
        };
        Self {
            message: format!(
                "`cockpit {command}` was split: use `{account_command}` for FlyCockpit account access or `cockpit provider add` for model provider API keys/OAuth"
            ),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RemovedCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RemovedCommandError {}

pub mod acp;
pub mod agent;
pub mod ask;
pub mod assistant;
pub mod bash_hints;
pub mod config;
#[cfg(feature = "remote")]
pub mod connect;
pub mod daemon;
pub mod debug;
pub mod doctor;
pub mod dream;
pub mod export;
pub mod fetch_models;
#[cfg(feature = "remote")]
pub mod flycockpit;
pub mod import;
pub mod init;
pub mod invocation;
pub mod jq;
pub mod kcl;
pub mod knowledge;
pub mod learn;
pub mod mcp;
pub mod models;
pub mod packages;
pub mod providers;
pub mod run;
pub mod schedule;
pub mod session;
pub mod setup;
pub mod skill;
pub mod stats;
#[cfg(feature = "remote")]
pub mod sync;
pub mod trust;
pub mod tui;
