//! Dependency-minimal host operating-system primitives for Cockpit.
//!
//! This crate owns reusable filesystem/path, child-process, and named-pipe
//! identity/connect behavior. It has no knowledge of daemon protocol,
//! application state, configuration, or the SQLite ledger, so the CLI host,
//! `cockpit-core`, and `cockpit-client` can depend on it without creating an
//! authority inversion.

pub mod bounded;
pub mod daemon_lifecycle;
pub mod goal_scratch;
pub mod jitter;
pub mod named_pipe;
pub mod path_containment;
#[cfg(any(unix, windows))]
pub mod peer_cred;
pub mod private_fs;
pub mod process;
pub mod sysinfo;
pub mod text;
