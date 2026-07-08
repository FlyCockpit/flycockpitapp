//! External-harness invocation (implementation note,
//! GOALS §6).
//!
//! cockpit can delegate a unit of work to **another** coding harness
//! (claude, codex, opencode, grok, …) run in its non-interactive/programmatic
//! mode, treating it as an external leaf subagent. This module owns the
//! mechanism: arg-template expansion + prompt delivery
//! ([`prepare`]), the spawn + concurrent-drain + timeout loop
//! ([`spawn`]), preflight PATH/auth checks ([`preflight`]), lenient JSON
//! metadata parsing ([`parse`]), and the synchronous end-to-end driver
//! ([`run`]). The list/invoke tools (`crate::tools::harness`) sit on top.
//!
//! The proven shape is adapted from `ralph-rs/src/harness.rs`; cockpit
//! owns its own config (`crate::config::extended::HarnessConfig`) and
//! conventions (redaction chokepoint, subagent-report caps, error style).

pub mod env;
pub mod models;
pub mod parse;
pub mod preflight;
pub mod prepare;
pub mod run;
pub mod spawn;

// Convenience re-exports of the entry points the tools/engine call by short
// path; everything else is reachable via its submodule
// (`crate::harness::run::RunContext`, etc.).
pub use models::probe_models;
pub use preflight::{PreflightError, preflight_with_env};
