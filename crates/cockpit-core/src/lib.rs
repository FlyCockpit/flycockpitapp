//! UI-free application layer for Cockpit.
//!
//! This crate owns the reusable session, daemon, engine, tools, auth,
//! provider, redaction, and workspace logic used by Cockpit front ends.
//! It must stay below consumers such as `cockpit-cli`: do not add direct or
//! transitive dependencies on ratatui, crossterm, PTY widgets, terminal UI
//! renderers, or the binary crate. UI and terminal implementations depend on
//! this crate and plug in through explicit boundary traits.
//!
//! Crate direction is one-way:
//! `cockpit-cli -> cockpit-core -> cockpit-config/cockpit-db/cockpit-proto`;
//! the lower crates do not depend on `cockpit-core` or `cockpit-cli`.

pub mod agents;
pub mod approval;
pub mod assistants;
pub mod auth;
pub mod auto_title;
pub mod banner;
pub mod browser;
pub use cockpit_config as config;
pub mod computer;
pub mod container;
pub mod credentials;
pub mod daemon;
pub use cockpit_db as db;
pub mod diagnostics;
pub mod embeddings;
pub mod engine;
pub mod env_snapshot;
pub mod envref;
pub mod git;
pub mod gitignore;
pub mod harness;
pub mod init;
pub mod intel;
pub mod knowledge;
pub mod locks;
pub mod mcp;
pub mod model_system_prompt;
pub mod packages;
pub mod private_fs;
pub mod process;
pub mod providers;
pub mod redact;
pub mod secret_ref;
pub mod session;
pub mod skills;
pub mod startup;
pub mod sync;
pub mod sysinfo;
#[cfg(any(test, feature = "test-support"))]
pub mod test_env;
pub mod text;
pub mod tokens;
pub mod tools;
pub mod user_agent;
pub mod welcome;
pub mod wizard;

pub use cockpit_proto as proto_crate;
