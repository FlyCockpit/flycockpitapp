//! Ratatui terminal interface for the `cockpit` binary.
//!
//! This crate owns terminal rendering, input handling, panes, overlays, and
//! local clipboard helpers — everything that exists because the front end is a
//! terminal. Product logic stays in `cockpit-core`, configuration in
//! `cockpit-config`, and persistence in `cockpit-db`: if a behavior would be
//! just as true of a web or native front end, it does not belong here. This
//! crate is the mirror image of the `cockpit-core` charter, which forbids
//! ratatui, crossterm, PTY widgets, and terminal renderers below this layer.
//!
//! This crate is a leaf. Only the `cockpit-cli` binary depends on it, through
//! the single sanctioned edge in `commands/tui.rs`; no other crate may, and
//! nothing here may be depended upon by `cockpit-core` or lower.
//!
//! Crate direction is one-way:
//! `cockpit-cli -> cockpit-tui -> cockpit-core -> cockpit-config/cockpit-db/cockpit-proto`;
//! the lower crates do not depend on `cockpit-tui` or `cockpit-cli`. A
//! discovered inversion is fixed by moving the symbol to its correct crate,
//! never by a shim or a circular dev-dependency.

pub mod banner;
pub mod clipboard;
pub mod tui;
