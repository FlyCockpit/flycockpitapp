//! Model Context Protocol support (GOALS §18).
//!
//! MCP tools stay out of context; the model reaches them by writing Python
//! in the locked-down [`sandbox`] Monty VM via the `mcp` tool
//! ([`crate::tools::mcp_tool`]), using `mcp.search`/`mcp.describe`/
//! `mcp.invoke`.
//!
//! Layered config ([`config`]), a source-tagged effective [`resolver`],
//! three transports ([`transport`]), four auth kinds ([`auth`]), a
//! SHA256+TTL catalog [`cache`], and the [`catalog`] operations
//! (search / describe / invoke) make up the host side.

pub mod auth;
pub mod builtin;
pub mod cache;
pub mod catalog;
pub mod child_failure;
pub mod client;
pub mod config;
pub mod device;
// The forwarded catalog is an internal daemon capability.  Keeping its module
// crate-private prevents another workspace consumer from routing editor input
// around the catalog/approval funnel.
pub(crate) mod forwarded;
pub mod invoke_prep;
pub mod protocol;
pub mod resolver;
pub mod sandbox;
mod suggest;
pub mod transport;
