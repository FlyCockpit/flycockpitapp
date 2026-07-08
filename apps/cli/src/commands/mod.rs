//! One module per top-level subcommand. Each module exposes a single
//! `pub async fn run(...)` that takes the relevant clap args struct.

use std::fmt;

pub const USAGE_EXIT_CODE: u8 = 64;

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

pub mod agent;
pub mod ask;
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
pub mod mcp;
pub mod meta;
pub mod models;
pub mod packages;
pub mod pr;
pub mod providers;
pub mod run;
pub mod session;
pub mod stats;
pub mod sync;
pub mod trust;
pub mod tui;
