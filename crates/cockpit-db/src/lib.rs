//! SQLite persistence for Cockpit sessions and durable daemon state.
//!
//! This crate owns schema migrations, typed row structures, persisted session
//! state machines, and small DB-side wire payloads. It must remain independent
//! of CLI, daemon, TUI, engine, config, approval, and redaction logic.

pub mod db;

pub use db::*;
