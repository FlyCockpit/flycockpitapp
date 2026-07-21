//! Single integration-test binary for the CLI's process-boundary coverage.
//!
//! Each module was previously its own `tests/*.rs` binary; they are merged
//! here (explicit `[[test]]` target `e2e` in Cargo.toml) so an incremental
//! `cargo test` links one full-dependency-graph test binary instead of seven.

mod support;

mod binary_smoke;
#[cfg(unix)]
mod daemon_lifecycle;
#[cfg(unix)]
mod daemon_lifecycle_replay;
#[cfg(unix)]
mod daemon_state_freshness;
mod mangen;
#[cfg(unix)]
mod multi_client_queue;
#[cfg(unix)]
mod run_noninteractive;
