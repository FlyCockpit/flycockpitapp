//! Server-private authority for direct-native media tools.
//!
//! This module owns the single server-private authority used by direct-native
//! media tools to resolve session attachments and admit local/retained-HTTPS
//! sources. It persists an authenticated binding across queue recovery,
//! revalidates it on every use, fails closed for folded mixed-principal turns,
//! and never exposes source authority to MCP, Monty, models, or public tool
//! context construction.
//!
//! # Layout
//!
//! - [`receipt`] — `ToolMediaSubjectReceiptV1` canonical encoding and digest.
//! - [`locator`] — `LocatorV1` local/remote encoding and digests.
//! - [`seal`] — XChaCha20-Poly1305/HKDF-SHA-256 sealed-locator scheme.
//! - [`revalidator`] — `ToolMediaSubjectRevalidator` live revalidation.
//! - [`session_authority`] — `SessionMediaAuthority` private direct-native
//!   authority for attachment/local/HTTPS admission.
//! - [`availability`] — `MediaToolAvailability` data-free tool-presence
//!   snapshot created before `ToolCtx`.
//! - [`recovery`] — queue recovery/materialization, folded-root subject
//!   derivation, spawn-context enforcement, and epoch increment on
//!   control-state changes.
//!
//! ```compile_fail
//! use cockpit_core::tool_media_authority::SessionMediaAuthority;
//!
//! // `new` is crate-private: an external crate cannot mint a source-admitting
//! // authority from a fabricated subject or policy objects.
//! let _ = SessionMediaAuthority::new;
//! ```
//!
pub mod availability;
pub mod locator;
pub mod receipt;
pub mod recovery;
pub mod revalidator;
pub(crate) mod runtime;
pub mod seal;
pub mod session_authority;

// Re-export the primary public types for ergonomic access from within core.
pub use availability::MediaToolAvailability;
pub use receipt::ToolMediaSubjectReceiptV1;
pub use recovery::{
    ControlStateChange, RecoveredBinding, RecoveryError, SpawnContext,
    apply_control_state_change_conn, context_eligible_for_authority, derive_folded_root_subject,
    media_availability_for_context, receipt_from_binding_row, recover_session_bindings,
    recover_session_bindings_with_failures,
};
pub use revalidator::{RevalidatorError, ToolMediaSubjectRevalidator};
pub use seal::{SealError, SealedLocator, UnsealedLocator};
pub use session_authority::{AdmissionDenial, AdmittedHandle, SessionMediaAuthority};

/// The secure-key namespace used by tool-media-subject-binding sealed locators.
pub const TOOL_MEDIA_SUBJECT_BINDING_NAMESPACE: &str = "tool_media_subject_binding";

/// Consumer kind for secure-key refs owned by tool-media-subject bindings.
pub const TOOL_MEDIA_SUBJECT_BINDING_CONSUMER_KIND: &str = "tool_media_subject_binding";

/// Derive the opaque project digest bound into every receipt from the durable
/// session project identifier. The UUID namespace avoids treating an arbitrary
/// project string as a UUID while keeping the receipt fixed-width.
pub(crate) fn project_digest_for_project_id(project_id: &str) -> [u8; 32] {
    let project_uuid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, project_id.as_bytes());
    locator::LocatorV1::project_digest(project_uuid.as_bytes())
}

/// Build the secure-key reference id for a binding.
///
/// Format: `tool-media-subject-binding/<session>/<client-submission>/<key-version>`
pub fn binding_key_reference_id(
    session_id: &str,
    client_submission_hex: &str,
    key_version: i64,
) -> String {
    format!("tool-media-subject-binding/{session_id}/{client_submission_hex}/{key_version}")
}

/// Build the secure-key consumer id for a binding.
///
/// Format: `<session>/<client-submission>`
pub fn binding_consumer_id(session_id: &str, client_submission_hex: &str) -> String {
    format!("{session_id}/{client_submission_hex}")
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod secure_key_consumer_test_helpers;
