//! Per-provider authentication flows that store tokens in
//! [`crate::credentials::CredentialStore`].
//!
//! GitHub Copilot was migrated off the reverse-engineered device-flow +
//! `/copilot_internal/v2/token` swap and now uses GitHub's documented
//! token sources (`COPILOT_GITHUB_TOKEN` / `GH_TOKEN` / `GITHUB_TOKEN` /
//! `GITHUB_COPILOT_API_TOKEN`) plus the documented `COPILOT_API_URL`
//! base-URL override; see [`crate::providers::models_fetch::
//! resolve_provider_request`]. Other providers use static API keys plus
//! `$VAR` references in their header values, so they don't need a flow.

pub mod codex_oauth;
pub(crate) mod command;
pub mod copilot_setup;
#[cfg(feature = "remote")]
pub mod flycockpit;
pub(crate) mod refresh_guard;
pub mod subscription_ack;
pub mod xai_oauth;

/// Reserved provider-credential key for the Flycockpit account credential.
///
/// Defined here rather than in the `remote`-gated `flycockpit` module so the
/// semantic reservation check in `validate_request_semantics` applies even
/// when the `remote` feature is off (the public v0.1 CLI). `flycockpit::
/// CREDENTIAL_KEY` re-exports this value for the remote-enabled paths.
pub(crate) const FLYCOCKPIT_CREDENTIAL_KEY: &str = "flycockpit";
