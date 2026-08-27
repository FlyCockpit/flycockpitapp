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
//! untrusted model. Nothing widens that — not a steering posture, not a tool,
//! not a grant.
//!
//! Steering posture is an independent harness-steering axis that selects
//! context variants and verbose tool-definition prose. It
//! never decides whether an already-selected provider sees a raw literal,
//! whether a provider is eligible for a sensitive request, or any sealed
//! authorization outcome. This module is where that orthogonality is made
//! structural: the resolver below reads only `trust`.

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

/// The custody request: the caller's trust axis.
///
/// Carrying only `trust` makes the orthogonality claim structural: the
/// predicate is handed the trust axis and resolves custody from it alone.
/// Steering posture is not part of custody (issue #75).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedCustodyRequest {
    pub trust: ModelTrust,
}

impl SealedCustodyRequest {
    pub fn new(trust: ModelTrust) -> Self {
        Self { trust }
    }

    /// Resolve custody for this caller.
    pub fn custody(self) -> SealedLiteralCustody {
        sealed_literal_custody(self)
    }
}

/// The custody predicate.
///
/// Deliberately a single `match` on `trust`. There is no steering axis to
/// read; any future edit that introduces one is both an orthogonality
/// regression and a custody-gate regression, and is caught by
/// `trust_alone_decides_sealed_value_custody`.
pub fn sealed_literal_custody(request: SealedCustodyRequest) -> SealedLiteralCustody {
    match request.trust {
        ModelTrust::Trusted => SealedLiteralCustody::RawLiteralPermitted,
        ModelTrust::Untrusted => SealedLiteralCustody::ReferenceOnly,
    }
}

/// Custody from trust alone, for call sites that have no steering in hand.
///
/// Identical by construction to [`sealed_literal_custody`] — trust is the
/// whole input either way.
pub fn sealed_literal_custody_for_trust(trust: ModelTrust) -> SealedLiteralCustody {
    sealed_literal_custody(SealedCustodyRequest { trust })
}

/// Every `ModelTrust`, for exhaustive custody proofs.
pub const ALL_MODEL_TRUSTS: [ModelTrust; 2] = [ModelTrust::Trusted, ModelTrust::Untrusted];
