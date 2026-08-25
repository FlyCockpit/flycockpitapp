//! Dependency-minimal host operating-system primitives for Cockpit.
//!
//! This crate owns reusable filesystem/path and child-process behavior. It has
//! no knowledge of daemon protocol, application state, configuration, or the
//! SQLite ledger, so both the CLI host and `cockpit-core` can depend on it
//! without creating an authority inversion.

pub mod goal_scratch;
pub mod path_containment;
pub mod private_fs;
pub mod process;
