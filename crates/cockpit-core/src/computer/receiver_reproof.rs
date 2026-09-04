//! Window-level terminal receiver re-proof (issue #374, stage 1).
//!
//! Evidence-based re-authentication before typed-line commits on an unproven
//! receiver (Enter-class keys or embedded line feeds in typed text). Re-proof
//! is evidence (target snapshot through the authenticated
//! window fence), never an action. A window-level pass alone is never
//! sufficient for unattended commit: the coordinator still routes the Enter
//! through Ask (even on Yolo) so a human confirms tab/pane residual.

use std::sync::Arc;

use tracing::info;

use super::audit::{AuditErrorCode, ComputerAuditChain, ReceiverReproofAuditAppend};
use super::target::{OpaqueWindowId, TargetIdentityEvidence};
use super::{ComputerAction, ComputerError, TypedInputLineModel};

/// Receiver window identity journaled at coordinator open, at Ask-gate identity
/// adoption, or after a prior successful evidence re-proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JournaledReceiverProof {
    pub window: OpaqueWindowId,
    pub focus_generation: u64,
}

impl JournaledReceiverProof {
    pub(crate) fn from_open(window: Option<OpaqueWindowId>, focus_generation: u64) -> Option<Self> {
        window.map(|window| Self {
            window,
            focus_generation,
        })
    }
}

/// Outcome of one receiver re-proof attempt (telemetry + audit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiverReproofOutcome {
    Proven,
    Refused,
}

/// Specific operator-facing re-proof failure. Sticky: repeated failures never
/// escalate to a bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceiverReproofFailure {
    EvidenceUnavailable,
    JournaledProofUnset,
    AuditJournalUnavailable,
    WindowMismatch,
    GenerationMismatch,
    FocusElsewhere,
    KeyboardIdentityDirty,
    LineClearFailed,
}

impl ReceiverReproofFailure {
    pub fn refusal_message(self) -> &'static str {
        match self {
            Self::EvidenceUnavailable => RECEIVER_REPROOF_EVIDENCE_UNAVAILABLE_REFUSAL,
            Self::JournaledProofUnset => RECEIVER_REPROOF_JOURNALED_PROOF_UNSET_REFUSAL,
            Self::AuditJournalUnavailable => RECEIVER_REPROOF_AUDIT_JOURNAL_UNAVAILABLE_REFUSAL,
            Self::WindowMismatch => RECEIVER_REPROOF_WINDOW_MISMATCH_REFUSAL,
            Self::GenerationMismatch => RECEIVER_REPROOF_GENERATION_MISMATCH_REFUSAL,
            Self::FocusElsewhere => RECEIVER_REPROOF_FOCUS_ELSEWHERE_REFUSAL,
            Self::KeyboardIdentityDirty => RECEIVER_REPROOF_KEYBOARD_DIRTY_REFUSAL,
            Self::LineClearFailed => RECEIVER_REPROOF_LINE_CLEAR_FAILED_REFUSAL,
        }
    }

    pub(crate) fn audit_error_code(self) -> AuditErrorCode {
        match self {
            Self::EvidenceUnavailable | Self::JournaledProofUnset => {
                AuditErrorCode::VerificationUnavailable
            }
            Self::AuditJournalUnavailable => AuditErrorCode::StorageFailure,
            Self::WindowMismatch | Self::GenerationMismatch | Self::FocusElsewhere => {
                AuditErrorCode::VerificationMismatch
            }
            Self::KeyboardIdentityDirty | Self::LineClearFailed => AuditErrorCode::PolicyDenied,
        }
    }
}

pub(crate) const RECEIVER_REPROOF_EVIDENCE_UNAVAILABLE_REFUSAL: &str = "computer use cannot press Enter: receiver re-proof could not capture live window evidence; \
     the receiving object stays unproven";

pub(crate) const RECEIVER_REPROOF_JOURNALED_PROOF_UNSET_REFUSAL: &str = "computer use cannot press Enter: receiver re-proof has no journaled window identity from \
     coordinator open or prior proof; the receiving object stays unproven";

pub(crate) const RECEIVER_REPROOF_AUDIT_JOURNAL_UNAVAILABLE_REFUSAL: &str = "computer use cannot press Enter: receiver re-proof could not journal the evidence \
     receipt on the computer audit chain; the receiving object stays unproven";

pub(crate) const RECEIVER_REPROOF_WINDOW_MISMATCH_REFUSAL: &str = "computer use cannot press Enter: receiver re-proof found a different authenticated window \
     than the one journaled at proof time; the receiving object stays unproven";

pub(crate) const RECEIVER_REPROOF_GENERATION_MISMATCH_REFUSAL: &str = "computer use cannot press Enter: receiver re-proof found a mismatched window generation \
     token; the receiving object stays unproven";

pub(crate) const RECEIVER_REPROOF_FOCUS_ELSEWHERE_REFUSAL: &str = "computer use cannot press Enter: receiver re-proof found keyboard focus on a different \
     window than the journaled receiver; the receiving object stays unproven";

pub(crate) const RECEIVER_REPROOF_KEYBOARD_DIRTY_REFUSAL: &str = "computer use cannot press Enter: identity-changing keyboard input was delivered since the \
     last receiver proof; the receiving object stays unproven";

pub(crate) const RECEIVER_REPROOF_LINE_CLEAR_FAILED_REFUSAL: &str = "computer use cannot press Enter: receiver re-proof could not deliver a line clear to the \
     journaled receiver; the receiving object stays unproven";

/// True when simulating `actions` on `model` would refuse a typed-line commit
/// because the receiver is unproven.
pub(crate) fn batch_would_refuse_unproven_receiver_enter(
    model: &TypedInputLineModel,
    actions: &[ComputerAction],
) -> bool {
    if !model.is_receiver_unproven() {
        return false;
    }
    let mut simulated = model.clone();
    for action in actions {
        match simulated.absorb_action(action) {
            Err(ComputerError::Refused(_)) if action.commits_typed_line() => return true,
            Err(_) => return false,
            Ok(()) => {}
        }
    }
    false
}

/// Compare live evidence against the journaled receiver proof from coordinator
/// open, Ask-gate identity adoption, or the prior successful re-proof.
pub(crate) fn evidence_matches_journaled_proof(
    evidence: &TargetIdentityEvidence,
    journaled: &JournaledReceiverProof,
) -> Result<(), ReceiverReproofFailure> {
    let Some(live_window) = evidence.focused_window_id_value() else {
        return Err(ReceiverReproofFailure::FocusElsewhere);
    };
    if live_window != journaled.window {
        if evidence.focus_generation != journaled.focus_generation {
            return Err(ReceiverReproofFailure::GenerationMismatch);
        }
        return Err(ReceiverReproofFailure::WindowMismatch);
    }
    if evidence.focus_generation != journaled.focus_generation {
        return Err(ReceiverReproofFailure::GenerationMismatch);
    }
    Ok(())
}

pub(crate) fn emit_receiver_reproof_telemetry(
    session_id: &str,
    delegation_id: &str,
    call_id: &str,
    outcome: ReceiverReproofOutcome,
    reason: &str,
) {
    info!(
        event = "receiver_reproof",
        outcome = ?outcome,
        reason,
        session_id,
        delegation_id,
        call_id,
    );
}

pub(crate) async fn journal_receiver_reproof_attempt(
    chain: Option<&Arc<ComputerAuditChain>>,
    append: ReceiverReproofAuditAppend,
) -> Result<(), ReceiverReproofFailure> {
    let Some(chain) = chain else {
        tracing::warn!("receiver re-proof audit chain is not installed; evidence receipt refused");
        return Err(ReceiverReproofFailure::AuditJournalUnavailable);
    };
    if !chain.is_available() {
        tracing::warn!("receiver re-proof audit chain is unavailable; evidence receipt refused");
        return Err(ReceiverReproofFailure::AuditJournalUnavailable);
    }
    chain
        .append_receiver_reproof(append)
        .await
        .map_err(|error| {
            tracing::warn!(?error, "receiver re-proof audit append failed");
            ReceiverReproofFailure::AuditJournalUnavailable
        })
}

pub(crate) fn line_clear_action() -> ComputerAction {
    use super::{CanonicalKeyChord, KeyCode};
    ComputerAction::KeyChord {
        chord: CanonicalKeyChord::new(vec![
            KeyCode::parse("CONTROL").expect("CONTROL"),
            KeyCode::parse("C").expect("C"),
        ])
        .expect("ctrl+c"),
    }
}

pub(crate) fn reproof_operation_id(call_id: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("receiver-reproof:{call_id}").as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}
