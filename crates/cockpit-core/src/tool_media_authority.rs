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

pub mod receipt;
pub mod locator;
pub mod seal;
pub mod revalidator;
pub mod session_authority;
pub mod availability;

// Re-export the primary public types for ergonomic access from within core.
pub use availability::MediaToolAvailability;
pub use receipt::ToolMediaSubjectReceiptV1;
pub use revalidator::{RevalidatorError, ToolMediaSubjectRevalidator};
pub use seal::{SealedLocator, SealError, UnsealedLocator};
pub use session_authority::{AdmittedHandle, AdmissionDenial, SessionMediaAuthority};

/// The secure-key namespace used by tool-media-subject-binding sealed locators.
pub const TOOL_MEDIA_SUBJECT_BINDING_NAMESPACE: &str = "tool_media_subject_binding";

/// Consumer kind for secure-key refs owned by tool-media-subject bindings.
pub const TOOL_MEDIA_SUBJECT_BINDING_CONSUMER_KIND: &str = "tool_media_subject_binding";

/// Build the secure-key reference id for a binding.
///
/// Format: `tool-media-subject-binding/<session>/<client-submission>/<key-version>`
pub fn binding_key_reference_id(
    session_id: &str,
    client_submission_hex: &str,
    key_version: i64,
) -> String {
    format!(
        "tool-media-subject-binding/{session_id}/{client_submission_hex}/{key_version}"
    )
}

/// Build the secure-key consumer id for a binding.
///
/// Format: `<session>/<client-submission>`
pub fn binding_consumer_id(session_id: &str, client_submission_hex: &str) -> String {
    format!("{session_id}/{client_submission_hex}")
}
