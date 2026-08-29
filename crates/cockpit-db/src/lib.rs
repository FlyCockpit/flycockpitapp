//! SQLite persistence for Cockpit sessions and durable daemon state.
//!
//! This crate owns schema migrations, typed row structures, persisted session
//! state machines, and small DB-side wire payloads. It must remain independent
//! of CLI, daemon, TUI, engine, config, approval, and redaction logic.

pub mod db;

/// Local v0.1 image-sidecar grant authority. Named so callers do not have to
/// reach through `db::image_sidecar` for the ledger row types.
pub use db::image_sidecar::{ImageSidecarGrantCreate, ImageSidecarGrantRow, ImageSidecarSnapshot};
/// Private durable replay authority for one provider-emitted tool-call turn.
/// These rows are never session-exported; crash recovery is the only consumer.
pub use db::turn_scheduler_continuations::{
    TurnSchedulerContinuationInput, TurnSchedulerContinuationRow,
};
pub use db::*;
