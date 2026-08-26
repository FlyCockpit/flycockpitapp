#![recursion_limit = "256"]

//! UI-free application layer for Cockpit.
//!
//! This crate owns the reusable session, daemon, engine, tools, auth,
//! provider, redaction, and workspace logic used by Cockpit front ends.
//! It must stay below consumers such as `cockpit-cli`: do not add direct or
//! transitive dependencies on ratatui, crossterm, PTY widgets, terminal UI
//! renderers, or the binary crate. UI and terminal implementations depend on
//! this crate and plug in through explicit boundary traits.
//!
//! Crate direction is one-way:
//! `cockpit-cli -> cockpit-core -> cockpit-client/cockpit-proto/cockpit-config/cockpit-db`;
//! the lower crates do not depend on `cockpit-core` or `cockpit-cli`.

pub mod agents;
pub mod approval;
pub mod assistants;
pub mod audio_transcription;
pub mod auth;
pub mod auto_title;
pub mod banner;
pub mod browser;
pub mod capabilities;
pub use cockpit_config as config;
pub mod computer;
pub mod container;
pub mod credentials;
pub mod daemon;
pub mod diagnostics;
pub mod embeddings;
pub mod engine;
pub mod env_snapshot;
pub mod envref;
pub mod external_journal;
pub mod external_runtime;
pub mod generated_svg;
pub mod git;
pub mod gitignore;
pub mod harness;
pub mod host_capabilities;
pub mod image_generation;
pub mod image_generation_agent_tools;
pub mod image_generation_artifact_routes;
pub mod image_generation_comfyui;
pub mod image_generation_control_plane;
pub mod image_generation_job;
pub mod image_generation_runtime;
pub mod image_sidecar;
pub mod init;
pub mod intel;
pub mod jitter;
pub mod knowledge;
pub mod leak_report;
pub mod leaks;
pub mod locks;
pub mod mcp;
mod media_https;
pub mod media_reservation;
mod media_storage;
pub mod model_system_prompt;
pub mod openai_images_adapter;
pub mod packages;
pub mod policy;
pub mod process_containment;
#[cfg(test)]
mod production_path_ratchet;
pub mod providers;
pub mod redact;
#[cfg(feature = "remote")]
pub mod remote_daemon_identity_custody;
#[cfg(feature = "remote")]
pub mod remote_webrtc_endpoint;
pub mod sealed;
pub mod secret_command;
pub(crate) mod secret_ownership;
pub mod secret_paths;
pub mod secret_ref;
pub mod secure_key;
pub mod session;
pub mod skills;
pub mod startup;
pub mod sync;
pub mod sysinfo;
pub mod tags;
// This surface is compiled for core's own tests and for dependents that
// explicitly opt into the dev-only `test-support` feature. It intentionally
// exposes only test instrumentation, never a production database API.
#[cfg(any(test, feature = "test-support"))]
pub mod test_env;
pub mod text;
pub mod tls_crypto_provider;
pub mod tokens;
pub mod tools;
pub mod typed_media_result;
pub mod user_agent;
pub mod welcome;
pub mod wizard;
pub mod write_scope;

// The storage crate is an implementation detail of the core layer.  Keeping
// this alias crate-visible prevents upper layers from bypassing daemon-owned
// RPCs to open the ledger directly.
pub(crate) use cockpit_db as db;
pub use cockpit_proto as proto_crate;
