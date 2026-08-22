//! Shared image-generation provider transport vocabulary.
//!
//! One crate-local outcome/error pair classifies every provider Image API
//! submission so the four adapter kinds (OpenAI, OpenRouter, ComfyUI, Gemini)
//! map failures onto the same billing-safe boundary rather than each inventing
//! a divergent transport enum. The central distinction the dispatch layer needs
//! is whether a request byte was accepted by the provider:
//!
//! * A **pre-handoff** failure ([`ProviderTransportError::Connect`],
//!   [`ProviderTransportError::Tls`]) proves no byte was accepted, so the slot
//!   may safely resubmit under a fresh idempotency identity without risking a
//!   duplicate paid submission.
//! * A **post-handoff ambiguous** failure ([`ProviderTransportError::Timeout`],
//!   [`ProviderTransportError::AmbiguousAcceptance`]) means the provider may or
//!   may not have processed a paid request; the outcome must be reconciled, not
//!   blindly retried.
//! * A **definitive non-acceptance** ([`ProviderTransportError::Status`]) is a
//!   provider response that rejected the request without a paid submission.
//!
//! The vocabulary carries no credential material and no raw reference bytes; a
//! bounded response body is retained only for a [`ProviderTransportError::Status`]
//! so the adapter can encode redacted evidence.

/// A successful provider submission: the observed HTTP status and the bounded
/// response body. Body bytes are enforced against the per-adapter limit while
/// they are read, never after buffering an unbounded response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTransportOutcome {
    /// HTTP status observed at handoff completion (a 2xx success).
    pub status: u16,
    /// Bounded response body bytes.
    pub body: Vec<u8>,
}

/// Transport failure classification driving billing-safe submission semantics.
///
/// Variants are ordered from "certainly no paid submission" to "definitely a
/// provider response". A production transport must never widen a post-handoff
/// ambiguity into a safe pre-handoff class: only [`Self::Connect`] / [`Self::Tls`]
/// may be reported when it is certain no request byte was accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderTransportError {
    /// The socket could not be established (DNS, connect, connect-timeout, or a
    /// forbidden destination) before any request byte was accepted. Safe to
    /// resubmit with a fresh idempotency identity.
    Connect,
    /// The TLS handshake failed before any request byte was accepted. Safe to
    /// resubmit.
    Tls,
    /// The header or body deadline elapsed after the request was written. The
    /// provider may have processed a paid request; the outcome is ambiguous.
    Timeout,
    /// The connection was reset after the request was written. Ambiguous.
    AmbiguousAcceptance,
    /// The provider returned a definitive non-2xx status (redirect, client
    /// error, or server error the transport classifies as a non-acceptance).
    /// The body is bounded and carries no credential material.
    Status { status: u16, body: Vec<u8> },
    /// The response body exceeded the per-adapter limit while being read.
    BodyLimit,
    /// The response bytes were malformed or could not be read to completion for
    /// a reason other than a deadline.
    Malformed,
}
