//! One module per top-level subcommand. Each module exposes a single
//! `pub async fn run(...)` that takes the relevant clap args struct.

use std::fmt;

pub const USAGE_EXIT_CODE: u8 = 64;
pub const REMOVED_COMMAND_EXIT_CODE: u8 = 2;

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
                "`cockpit {command}` was split: use `{account_command}` for Flycockpit account access or `cockpit provider add` for model provider API keys/OAuth"
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

pub mod agent;
pub mod ask;
pub mod assistant;
pub mod bash_hints;
pub mod config;
pub mod connect;
pub mod daemon;
pub mod debug;
pub mod doctor;
pub mod export;
pub mod fetch_models;
pub mod flycockpit;
pub mod import;
pub mod init;
pub mod kcl;
pub mod learn;
pub mod mcp;
pub mod meta;
pub mod models;
pub mod packages;
pub mod pr;
pub mod providers;
pub mod run;
pub mod schedule;
pub mod session;
pub mod setup;
pub mod stats;
pub mod sync;
pub mod trust;
pub mod tui;
