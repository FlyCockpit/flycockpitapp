//! Concrete tool implementations.
//!
//! Every tool implements [`crate::engine::tool::Tool`] with
//! `Args = serde_json::Value` so the §12 repair layer can run between
//! rig's JSON-deserialized args and the typed dispatcher.
//!
//! Layout:
//!
//! - [`bash`] — process spawn, output capping, env scrub.
//! - [`read`] — snapshot read used for inspection and pre-write freshness.
//! - [`write`] — write-and-release.
//! - [`unlock`] — release without write.
//! - [`edit`] — cascade-based search/replace (plan §13b).
//! - [`task`] — structural; the engine intercepts this name.
//! - [`todo`] — durable task-backed todo state.

pub mod ask_image;
pub mod audio_video;
pub mod bash;
pub mod command_resource_profiles;
pub mod custom;
pub mod data_syntax;
pub mod defer;
pub mod delegation_payload_retrieve;
pub mod docs;
pub mod edit;
pub mod escalate;
pub mod glob;
pub mod grep;
pub mod harness;
pub mod intel;
pub mod jq_shim;
mod lock_wait;
pub mod lsp;
pub mod mcp_tool;
pub mod plan_doc;
pub mod question;
pub mod read;
pub mod read_image;
pub mod return_tool;
pub mod sandbox;
pub mod sandbox_mode;
pub mod schedule;
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
pub mod transcribe_audio;
pub mod unlock;
pub mod use_sealed_value;
pub mod web;
pub mod write;

pub mod artifact_read;
pub mod artifact_search;
pub mod common;
