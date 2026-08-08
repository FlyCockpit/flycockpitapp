//! The typed raw-literal custody predicate.
//!
//! `ModelTrust` is the **sole** custody gate for releasing a raw sealed or
//! environment literal:
//!
//! * `Trusted` — a self-hosted / log-safe provider. Raw literals may reach it.
//! * `Untrusted` — a cloud provider that may retain logs. It receives IDs,
//!   safe descriptions, and reference mechanisms only, forever.
//!
//! The invariant is one-directional: a raw sensitive value must never reach an
//! untrusted model. Nothing widens that — not a mode, not a tool, not a grant.
//!
//! `LlmMode` is an independent harness-steering posture. It selects context
//! variants and defensive tool-definition prose. It never decides whether an
//! already-selected provider sees a raw literal, whether a provider is
//! eligible for a sensitive request, or any sealed authorization outcome.
//! This module is where that orthogonality is made structural: the resolver
//! below takes both axes and reads only one of them.

use crate::config::extended::LlmMode;
use crate::config::providers::ModelTrust;

/// Whether a caller may receive a raw literal at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedLiteralCustody {
    /// Trusted custody: the ordinary raw-custody contract applies. Note this
    /// is a statement about *inference egress*, not about tool APIs — no
    /// literal-returning sealed tool exists for any caller.
    RawLiteralPermitted,
    /// Untrusted custody: sealed values are usable by reference only.
    ReferenceOnly,
}

impl SealedLiteralCustody {
    /// The one-directional invariant, phrased positively.
    pub fn permits_raw_literal(self) -> bool {
        matches!(self, Self::RawLiteralPermitted)
    }

    /// Whether the caller is restricted to reference-only use.
    pub fn is_reference_only(self) -> bool {
        matches!(self, Self::ReferenceOnly)
    }
}

/// Both posture axes of a caller, presented together on purpose.
///
/// Carrying `mode` here is what makes the orthogonality claim testable: the
/// predicate is handed the mode and demonstrably ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedCustodyRequest {
    pub trust: ModelTrust,
    pub mode: LlmMode,
}

impl SealedCustodyRequest {
    pub fn new(trust: ModelTrust, mode: LlmMode) -> Self {
        Self { trust, mode }
    }

    /// Resolve custody for this caller.
    pub fn custody(self) -> SealedLiteralCustody {
        sealed_literal_custody(self)
    }
}

/// The custody predicate.
///
/// Deliberately a single `match` on `trust`. `request.mode` is never read; any
/// future edit that reads it is both an orthogonality regression and a
/// custody-gate regression, and is caught by
/// `trust_and_mode_are_orthogonal_for_sealed_values`.
pub fn sealed_literal_custody(request: SealedCustodyRequest) -> SealedLiteralCustody {
    match request.trust {
        ModelTrust::Trusted => SealedLiteralCustody::RawLiteralPermitted,
        ModelTrust::Untrusted => SealedLiteralCustody::ReferenceOnly,
    }
}

/// Custody from trust alone, for call sites that have no mode in hand.
///
/// Identical by construction to [`sealed_literal_custody`] — trust is the
/// whole input either way.
pub fn sealed_literal_custody_for_trust(trust: ModelTrust) -> SealedLiteralCustody {
    sealed_literal_custody(SealedCustodyRequest {
        trust,
        // Any mode resolves identically; `Defensive` is `LlmMode::default()`.
        mode: LlmMode::default(),
    })
}

/// Every `LlmMode`, for exhaustive orthogonality proofs.
pub const ALL_LLM_MODES: [LlmMode; 3] = [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier];

/// Every `ModelTrust`, for exhaustive custody proofs.
pub const ALL_MODEL_TRUSTS: [ModelTrust; 2] = [ModelTrust::Trusted, ModelTrust::Untrusted];
