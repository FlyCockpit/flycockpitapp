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
//!
//! # Remaining wiring (TODO for follow-up)
//!
//! The following pieces are scaffolded but not yet wired into the full
//! daemon flow in this rough draft:
//!
//! - **Queue recovery/materialization** loads the binding for every accepted
//!   `UserSubmission` via `Db::load_tool_media_subject_bindings_for_session`.
//! - **Folded root** gets a subject only if all contributors have
//!   byte-identical canonical receipts and each live revalidation succeeds;
//!   otherwise it remains folded with no authority.
//! - **Scheduled/background/headless roots** and children without inherited
//!   valid root authority get none.
//! - **Secure-key ref lifecycle** in `accept_message_with_attachments`:
//!   reserve → activate after reachable binding insert in the same
//!   transaction (the binding insert is wired; the ref lifecycle needs the
//!   secure-key actor integration).
//! - **Epoch increment** on control-state changes (device revocation,
//!   authority status transition, local membership/read-path change) in the
//!   authoritative write transaction.

pub mod availability;
pub mod locator;
pub mod receipt;
pub mod revalidator;
pub mod seal;
pub mod session_authority;

// Re-export the primary public types for ergonomic access from within core.
pub use availability::MediaToolAvailability;
pub use receipt::ToolMediaSubjectReceiptV1;
pub use revalidator::{RevalidatorError, ToolMediaSubjectRevalidator};
pub use seal::{SealError, SealedLocator, UnsealedLocator};
pub use session_authority::{AdmissionDenial, AdmittedHandle, SessionMediaAuthority};

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
