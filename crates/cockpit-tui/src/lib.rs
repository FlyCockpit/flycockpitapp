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
//! `cockpit-cli -> cockpit-tui -> cockpit-core -> cockpit-client -> cockpit-proto -> cockpit-config -> cockpit-db`.
//! The TUI also depends directly on `cockpit-client` for authority-free daemon
//! transport and on the lower host/protocol/config crates named in `AGENTS.md`;
//! none of those lower crates depends on `cockpit-tui` or `cockpit-cli`. A
//! discovered inversion is fixed by moving the symbol to its correct crate,
//! never by a shim or a circular dev-dependency.
//!
//! Durable authority belongs to the daemon. The TUI may keep drafts and may
//! write only explicitly inventoried host-presentation artifacts: clipboard
//! recovery files, user-selected export destinations, and isolated external-
//! editor staging files. Agent/config discovery, validation, revisions and
//! commits cross typed daemon RPCs; a staging pathname is never an authority
//! capability. `tui_db_boundary` audits every production filesystem mutation
//! as an exact source-line exception so adding authority cannot hide behind a
//! whole-file allowlist.

pub mod banner;
pub mod clipboard;
#[cfg(feature = "test-support")]
pub mod test_support;
pub mod tui;
