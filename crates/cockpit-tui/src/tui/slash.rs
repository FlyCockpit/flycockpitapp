//! Slash-command menu.
//!
//! The set is the union of:
//!   - Built-ins (see `the CLI design notes` §5 "Built-in slash
//!     commands" for the design inspiration; cockpit ships its own subset).
//!   - User-defined commands from `~/.config/cockpit/commands/*.md`
//!     and any `.cockpit/commands/*.md` on the discovered config path.
//!
//! cockpit-specific commands:
//!   - `/settings` — opt into vim editing (insert editing is the default).
//!   - `/quit` — exit through the same work guard as `/exit`.
//!   - `/redact` — show what would be substituted in the next outbound prompt.
//!   - `/mcp` — print the mcp2cli pointer and exit.
//!
//! Omitted from opencode's set: `/share`, `/statusline`, `/terminaltitle`
//! (see `the CLI design notes`).
