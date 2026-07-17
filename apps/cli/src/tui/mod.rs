//! ratatui TUI app.
//!
//! Modeled on codex (see `kcl ask codex`). Key components:
//!   - `app`           top-level state machine + event loop
//!   - `composer`      bottom input area; vim mode default-on (GOALS §1b)
//!   - `chrome`        status line — always shows cwd + git branch (GOALS §1a)
//!   - `chat`          scrollback of user/assistant turns
//!   - `slash`         leader-less slash menu
//!   - `theme`         color palette, opencode-compatible
//!
//! Implementation guidance: codex's `bottom_pane/textarea.rs` has a
//! battle-tested vim state machine — port the structure rather than
//! reinventing it.

pub mod agent_runner;
pub mod app;
pub mod async_action;
pub mod attention;
pub mod auth_failure;
pub mod banner_box;
pub mod chat;
pub mod chrome;
pub mod composer;
pub mod context_menu;
pub mod context_pane;
pub mod daemon_prompt;
pub mod dialog;
pub mod diff;
pub mod diff_pane;
pub mod dir_suggest;
pub mod file_tag;
pub mod geometry;
pub mod history;
pub mod input_source;
pub mod keys_overlay;
pub mod links;
pub mod markdown;
pub mod math_render;
pub mod model_picker;
pub mod multireview_dialog;
pub mod nav;
pub mod notes_pane;
pub mod pane;
pub mod pane_shared;
pub mod paste;
pub mod permissions_pane;
pub mod pins_overlay;
pub mod pty;
pub mod quick_dialog;
pub(crate) mod read_highlight;
pub mod resources_pane;
pub mod sessions_pane;
pub mod settings;
pub mod skills_pane;
pub mod slash;
pub mod stats_pane;
pub mod textfield;
pub mod theme;
pub mod usage_pane;
pub mod vim_editor;
