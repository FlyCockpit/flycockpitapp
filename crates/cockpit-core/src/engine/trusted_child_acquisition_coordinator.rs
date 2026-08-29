//! Trusted-child sealed-value acquisition coordinator (leak-report AC6,
//! sub-increment 2c-3b).
//!
//! ## What this module owns
//!
//! The single host function that performs ONE trusted-child credential
//! acquisition end to end and returns ONLY a closed
//! [`AcquisitionOutcome`](crate::engine::trusted_child_acquisition::AcquisitionOutcome).
//! It ties together the three already-landed pieces without reimplementing any
//! of them:
//!
//! - **2c-1** [`resolve_trusted_child_model`] — selects a trusted child and
//!   mints a `TrustedCustodyGrant` ONLY when the resolved model is host-`Local`
//!   (Remote / PrivateRemote / missing location fail closed, no grant).
//! - **2c-2** [`TrustedChildCaptureRegistry`] — mints ONE exact single-use
//!   capture authority ([`TrustedChildCaptureRegistry::begin_capture`]) and
//!   performs the verify-before-parse in-process transfer
//!   ([`TrustedChildCaptureRegistry::verify_and_capture`]).
//! - **2c-3a** [`RequiresUser::parse`] — the fail-closed validator that is the
//!   ONLY way to build a human-surfacing `RequiresUser` prompt.
//!
//! ## The discard seam (why the child's raw output cannot leak)
//!
//! The child runs as a **non-persisting utility completion**
//! ([`Model::text_completion_with_system_for`]), NOT through the turn runner.
//! A utility completion issues exactly one provider request and returns the
//! assistant text as an owned `String`: it never records a session event, never
//! appends to any durable transcript / inference log, never streams a
//! `TurnEvent`, and runs no tool loop. So the child's raw output exists ONLY in
//! the [`Zeroizing`] buffer this function owns and drops. The ONLY thing
//! extracted from it is the structured acquisition claim (a small JSON object),
//! from which ONLY whitelisted fields are read: `requires_user.{reason,prompt}`
//! (each re-validated by 2c-3a) or the `captured_secret` literal (moved — not
//! copied — straight into a zeroizing [`SealedCaptureValue`] and handed to
//! 2c-2). Any other content — a rambling preamble, a smuggled token in an
//! unrecognized field, reasoning, non-JSON text — is ignored and dropped with
//! the zeroizing buffer. This function emits no `tracing` record carrying
//! child-derived content.
//!
//! Using the turn runner here would be unsound: it durably records the child's
//! assistant text + reasoning to the session event log BEFORE this function
//! could classify, redacted only by a table that does not yet contain the
//! just-captured secret. The utility-completion path has no such sink.
//!
//! ## Fail-closed ordering
//!
//! 1. **Eligibility.** Only [`ApprovalMode::Auto`] / [`ApprovalMode::Yolo`]
//!    callers dispatch. Manual (and any ineligible posture) returns `Failed`
//!    WITHOUT minting a capture record, selecting a model, or dispatching.
//!    Eligibility is identical across every harness posture.
//! 2. **Mint the pending record** (2c-2) before any model identity is selected.
//!    A refusal (one already in flight for the session) fails closed.
//! 3. **Select** the trusted child (2c-1). An `Err` (non-Local / ineligible)
//!    cancels the pending record and returns `Failed` WITHOUT dispatching.
//! 4. **Dispatch** exactly one non-persisting utility completion.
//! 5. **Classify** the structured claim into the closed outcome.
//! 6. **Lifecycle.** Retain the pending record on `RequiresUser` (the human is
//!    prompted by RETURNING the outcome); `cancel` it on `Failed`;
//!    `verify_and_capture` consumes it single-use on `Sealed`.
//!
//! ## Live wiring is deferred (callable-and-dormant, like 2c-1/2c-2/2c-3a)
//!
//! The task-delegation loop ([`crate::engine::schedule::swarm::run_swarm_loop`])
//! injects a child's text into the PARENT via `budget_result` — it has no
//! existing "this parent turn needs a sealed value, delegate to a trusted child"
//! trigger, and the live computer-use caller (`computer/coordinator.rs`) is not
//! a model-turn dispatch host and is coupled to unlanded work. So this module is
//! built as a callable host unit, exercised end to end through a
//! `ScriptedProvider`, and the thin live trigger is a follow-up. The module is
//! `#[allow(dead_code)]`-gated at its `mod` declaration until that live caller
//! lands, mirroring how 2c-1/2c-2/2c-3a stayed dormant until consumed.

use std::sync::Arc;

use serde_json::Value;
use zeroize::Zeroizing;

use crate::config::extended::ApprovalMode;
use crate::config::extended::ExtendedConfig;
use crate::config::providers::ProvidersConfig;
use crate::credentials::CredentialStore;
use crate::engine::model::{Model, UtilityCallSite};
use crate::engine::model_roles::resolve_trusted_child_model;
use crate::engine::trusted_child_acquisition::{AcquisitionOutcome, RequiresUser};
use crate::redact::RedactionTable;
use crate::session::Session;
use crate::session::trusted_child_capture::{
    SealedCaptureValue, TrustedChildCaptureAuthority, TrustedChildCaptureOutcome,
    TrustedChildCaptureRegistry,
};

/// The host-authored system contract for the acquisition child. It constrains
/// the reply to exactly one of the two whitelisted claim shapes; anything else
/// the child emits is ignored and dropped by the classifier.
const ACQUISITION_SYSTEM: &str = "You are a host-local trusted acquisition child. Acquire the \
     requested credential and reply with exactly one JSON object: either \
     {\"captured_secret\":\"<literal>\"} or \
     {\"requires_user\":{\"reason\":\"<reason>\",\"prompt\":\"<one-line question>\"}}. \
     Output only that JSON object, with no preamble, explanation, or code fences.";

/// One trusted-child acquisition request. Bundles the selection inputs (2c-1)
/// and the capture-binding inputs (2c-2) so the coordinator's entry point stays
/// a single call. Carries no secret.
pub struct AcquisitionRequest<'a> {
    /// The caller's approval posture. Only [`ApprovalMode::Auto`] /
    /// [`ApprovalMode::Yolo`] dispatch; everything else fails closed with no
    /// side effects.
    pub caller_mode: ApprovalMode,

    // ---- 2c-1 selection inputs ----
    /// The role/category scanned for a trusted child (empty ⇒ `Any`).
    pub category: &'a str,
    /// The delegating agent name (drives required capabilities).
    pub agent_name: &'a str,
    pub extended: &'a ExtendedConfig,
    pub providers: &'a ProvidersConfig,
    pub session_model: &'a Arc<Model>,
    pub store: Option<CredentialStore>,

    // ---- 2c-2 capture-binding inputs (host-derived, never child-supplied) ----
    pub record_id: &'a str,
    pub value_id: &'a str,
    pub reason: &'a str,
    pub origin: &'a str,
    pub generation: i64,
    pub version: i64,
    pub source_tool_call_id: &'a str,
    /// The single pinned clock for the whole acquisition (mint AND verify use
    /// it, so the operation is atomic w.r.t. the clock — guidance L17).
    pub now_ms: i64,

    /// The host-authored brief handed to the trusted child as its user turn.
    pub child_brief: String,
}

/// Perform ONE trusted-child sealed-value acquisition and return ONLY the closed
/// [`AcquisitionOutcome`]. See the module docs for the full fail-closed ordering
/// and the discard seam.
///
/// `redaction` is the session's live redaction table: 2c-2 unions the captured
/// literal into it on `Sealed`.
pub async fn run_trusted_child_acquisition(
    request: AcquisitionRequest<'_>,
    registry: &TrustedChildCaptureRegistry,
    session: Arc<Session>,
    redaction: Arc<RedactionTable>,
) -> AcquisitionOutcome {
    // 1. Eligibility gate. Manual / ineligible postures perform ZERO side
    //    effects: no capture record is minted, no model is selected, no request
    //    is dispatched (guidance L18 — resolve/validate before any lifecycle
    //    effect; here we refuse before the very first one).
    if !matches!(request.caller_mode, ApprovalMode::Auto | ApprovalMode::Yolo) {
        return AcquisitionOutcome::Failed;
    }

    // 2. Mint the single pending record (2c-2) BEFORE any model identity is
    //    selected — the child is chosen without a model-selected provider
    //    identity in hand. A refusal (one already in flight for the session)
    //    fails closed. The pending record carries no capability by itself: the
    //    authority it mints is inert until an exact verify, so this benign
    //    lifecycle registration may precede selection (L18).
    let session_id = session.id.to_string();
    let authority = match registry.begin_capture(
        &session,
        request.record_id,
        request.value_id,
        request.reason,
        request.origin,
        request.generation,
        request.version,
        request.source_tool_call_id,
        request.now_ms,
    ) {
        Ok(authority) => authority,
        Err(_already_in_flight) => return AcquisitionOutcome::Failed,
    };

    // 3. Select the trusted child (2c-1). A non-Local / ineligible resolution
    //    fails closed HERE, before any dispatch: cancel the pending record we
    //    just minted (so no authority orphans) and return `Failed`.
    let (child_model, _grant) = match resolve_trusted_child_model(
        request.category,
        request.agent_name,
        request.extended,
        request.providers,
        request.session_model,
        request.store,
    ) {
        Ok(selected) => selected,
        Err(_non_local_or_ineligible) => {
            registry.cancel(&session_id);
            return AcquisitionOutcome::Failed;
        }
    };

    // 4. Dispatch exactly ONE non-persisting utility completion. Unlike the turn
    //    runner, `text_completion_with_system_for` records no session event,
    //    streams no `TurnEvent`, keeps no durable transcript, and runs no tool
    //    loop — the child's raw output lives ONLY in the `Zeroizing` buffer
    //    below. The system contract + brief are host-authored (no secret); the
    //    utility path scrubs both through the outbound redaction chokepoint
    //    before any provider work. A dispatch error fails closed: cancel the
    //    pending record and return `Failed`, dropping the error without logging
    //    any child-derived content.
    let raw_claim: Zeroizing<String> = match child_model
        .text_completion_with_system_for(
            UtilityCallSite::TrustedChildAcquisition,
            ACQUISITION_SYSTEM,
            &request.child_brief,
        )
        .await
    {
        Ok(text) => Zeroizing::new(text),
        Err(_dispatch_failed) => {
            registry.cancel(&session_id);
            return AcquisitionOutcome::Failed;
        }
    };

    // 5 + 6. Classify the claim into the closed outcome and run the matching
    //    lifecycle transition.
    classify_and_capture(
        &raw_claim,
        &authority,
        registry,
        &session,
        &redaction,
        &session_id,
        request.now_ms,
    )
    .await
}

/// Classify the child's structured claim and perform the matching capture /
/// lifecycle transition. Reads ONLY whitelisted fields; everything else in the
/// claim is ignored (the discard guarantee for the structured channel).
#[allow(clippy::too_many_arguments)]
async fn classify_and_capture(
    raw_claim: &str,
    authority: &TrustedChildCaptureAuthority,
    registry: &TrustedChildCaptureRegistry,
    session: &Session,
    redaction: &RedactionTable,
    session_id: &str,
    now_ms: i64,
) -> AcquisitionOutcome {
    // A non-JSON / non-object claim is unclassifiable ⇒ fail closed. The parsed
    // `Value` is confined to this scope and dropped before return; the
    // authoritative copy of the raw text stays in the caller's `Zeroizing`
    // buffer.
    let Ok(Value::Object(mut claim)) = serde_json::from_str::<Value>(raw_claim) else {
        registry.cancel(session_id);
        return AcquisitionOutcome::Failed;
    };

    // MOVE (not clone) any captured-secret literal out of the parsed map into a
    // zeroizing frame UP FRONT, so it is zeroized on drop on EVERY branch —
    // including when a `requires_user` claim is also present and wins
    // classification below (the secret is then dropped, zeroized, unused). After
    // this, the parsed `Value` retains no owned copy of the secret.
    let captured_secret: Option<Zeroizing<String>> = match claim.remove("captured_secret") {
        Some(Value::String(secret)) => Some(Zeroizing::new(secret)),
        _ => None,
    };

    // A RequiresUser claim wins classification when present. Read ONLY the two
    // whitelisted fields and route them through the 2c-3a fail-closed validator;
    // an invalid reason/prompt collapses to `Failed` and the pending record is
    // deleted. On a valid `RequiresUser`, the pending record is RETAINED (the
    // human answers next) — the human is surfaced by RETURNING the outcome. Any
    // `captured_secret` taken above drops here, zeroized and unused.
    if let Some(Value::Object(requires)) = claim.get("requires_user") {
        let reason = requires.get("reason").and_then(Value::as_str).unwrap_or("");
        let prompt = requires.get("prompt").and_then(Value::as_str).unwrap_or("");
        return match RequiresUser::parse(reason, prompt) {
            outcome @ AcquisitionOutcome::RequiresUser(_) => outcome,
            _invalid => {
                registry.cancel(session_id);
                AcquisitionOutcome::Failed
            }
        };
    }

    // A captured-secret claim: move the literal out of the zeroizing frame into
    // a zeroizing `SealedCaptureValue`, so the only remaining plaintext copies
    // are the caller's `Zeroizing` raw buffer and the sealed value. Present the
    // EXACT host-minted authority (the child never supplies or influences it). On
    // `Captured` the record is consumed single-use and the value is sealed
    // in-process; on `Denied` (any fail-closed reason in 2c-2, including a value
    // the sealed-value validator rejects) nothing is stored — fail closed and
    // free the slot.
    if let Some(mut secret) = captured_secret {
        let value = SealedCaptureValue::new(std::mem::take(&mut *secret));
        return match registry
            .verify_and_capture(session, redaction, &authority.to_ingress(), value, now_ms)
            .await
        {
            TrustedChildCaptureOutcome::Captured { .. } => AcquisitionOutcome::Sealed,
            TrustedChildCaptureOutcome::Denied => {
                registry.cancel(session_id);
                AcquisitionOutcome::Failed
            }
        };
    }

    // Anything else (an unrecognized claim shape, an empty object) ⇒ fail closed.
    registry.cancel(session_id);
    AcquisitionOutcome::Failed
}

#[cfg(test)]
mod tests;
