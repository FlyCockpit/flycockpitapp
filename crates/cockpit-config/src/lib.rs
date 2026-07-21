//! Configuration loading, layering, provider catalogs, and workspace trust
//! policy for Cockpit.
//!
//! This crate owns config file discovery and typed config data. It may depend
//! on `cockpit-db` for persisted trust decisions, but it must not depend on
//! CLI commands, daemon workers, engine execution, tools, redaction, or TUI
//! rendering code.

pub use cockpit_db as db;

#[cfg(test)]
mod test_env;

pub mod config;

pub use config::*;
