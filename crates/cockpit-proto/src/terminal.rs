//! Transport-neutral terminal constants shared by the host parser and
//! TUI emission path.
//!
//! Parsing policy, clipboard data, and host lifecycle stay out of this
//! crate. The sole size contract for OSC 52 sequences lives here so
//! `apps/cli` and `crates/cockpit-tui` cannot drift.

/// Maximum total byte length of one OSC 52 candidate sequence, counting
/// every introducer form, selector/separators, payload, and terminator.
///
/// This is the only public OSC 52 size constant in the workspace. Host
/// filtering and TUI emission both import it; neither crate may declare
/// a local alias, literal cap, or competing decoded-payload limit.
pub const OSC52_MAX_SEQUENCE_BYTES: usize = 102_400;
