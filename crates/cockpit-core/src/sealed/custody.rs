//! The sealed-value custody predicate.
//!
//! No model receives a sealed literal. Trust governs capture/write authority
//! and reference reach elsewhere; it never changes sealed-value read custody.
//!
//! Steering posture is an independent harness-steering axis that selects
//! context variants and verbose tool-definition prose. It
//! never decides whether an already-selected provider sees a raw literal,
//! whether a provider is eligible for a sensitive request, or any sealed
//! authorization outcome. This module is where that orthogonality is made
//! structural: the resolver below reads only `trust`.

use crate::config::providers::ModelTrust;

/// Every model uses sealed values by reference only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedLiteralCustody {
    ReferenceOnly,
}

impl SealedLiteralCustody {
    /// The one-directional invariant, phrased positively.
    pub fn permits_raw_literal(self) -> bool {
        false
    }

    /// Whether the caller is restricted to reference-only use.
    pub fn is_reference_only(self) -> bool {
        true
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

/// The custody predicate. Trust is deliberately ignored: `use_sealed_value`
/// plus grants is the only model-facing sealed-use surface.
pub fn sealed_literal_custody(request: SealedCustodyRequest) -> SealedLiteralCustody {
    let _ = request;
    SealedLiteralCustody::ReferenceOnly
}

/// Custody from trust alone, for call sites that have no steering in hand.
///
/// Identical by construction to [`sealed_literal_custody`].
pub fn sealed_literal_custody_for_trust(trust: ModelTrust) -> SealedLiteralCustody {
    sealed_literal_custody(SealedCustodyRequest { trust })
}

/// Every `ModelTrust`, for exhaustive custody proofs.
pub const ALL_MODEL_TRUSTS: [ModelTrust; 2] = [ModelTrust::Trusted, ModelTrust::Untrusted];
