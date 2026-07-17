//! Concrete tool implementations.
//!
//! Every tool implements [`crate::engine::tool::Tool`] with
//! `Args = serde_json::Value` so the §12 repair layer can run between
//! rig's JSON-deserialized args and the typed dispatcher.
//!
//! Layout:
//!
//! - [`bash`] — process spawn, output capping, env scrub.
//! - [`read`] — snapshot read (no lock). Used by `Build`
//!   for shallow inspection and by `builder` for non-mutating context
//!   reads.
//! - [`readlock`] — acquire-and-read (plan §4.1).
//! - [`writeunlock`] — write-and-release.
//! - [`unlock`] — release without write.
//! - [`editunlock`] — cascade-based search/replace (plan §13b).
//! - [`task`] — structural; the engine intercepts this name.
//! - [`todo`] / [`todo_read`] — durable task-backed todo state.

pub mod bash;
pub mod command_resource_profiles;
pub mod custom;
pub mod custom_templates;
pub mod data_syntax;
pub mod defer;
pub mod delegation_payload_retrieve;
pub mod docs;
pub mod editunlock;
pub mod escalate;
pub mod glob;
pub mod goal;
pub mod grep;
pub mod handoff;
pub mod harness;
pub mod intel;
pub mod lsp;
pub mod mcp_tool;
pub mod plan_doc;
pub mod question;
pub mod read;
pub mod readlock;
pub mod return_tool;
pub mod sandbox;
pub mod sandbox_mode;
pub mod schedule;
pub mod seed;
pub mod session_read;
pub mod session_search;
pub mod shell_compress;
pub mod shell_sandbox;
pub mod skill;
pub mod skill_manage;
pub mod spawn;
pub mod task;
pub mod task_repair;
pub mod text_search;
pub mod todo;
pub mod todo_read;
pub mod tool_result_retrieve;
pub mod unlock;
pub mod web;
pub mod writeunlock;

pub mod common;
