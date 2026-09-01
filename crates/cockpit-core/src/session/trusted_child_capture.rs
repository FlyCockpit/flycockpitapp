//! Trusted-child sealed-value capture authority (leak-report AC7/AC8,
//! sub-increment 2c-2).
//!
//! ## What this module owns
//!
//! The host-side **authority + pending-record** infrastructure for an exact,
//! single-use trusted-child sealed-value capture. It mirrors
//! [`crate::leak_report::ReportLeakAuthority`]'s shape — mint, then a
//! verify-before-parse entry point that fails closed BEFORE the secret is
//! parsed, stored, or redaction-installed, and consumes the authority
//! single-use.
//!
//! The flow this supports (the coordinator that drives it is a **separate**
//! follow-up, sub-increment 2c-3, and is intentionally NOT built here):
//!
//! 1. The host calls [`TrustedChildCaptureRegistry::begin_capture`] to allocate
//!    ONE pending [`PendingCapture`] record for a session and mint ONE exact
//!    [`TrustedChildCaptureAuthority`] bound to
//!    `(record_id, project, session, generation, version, source_tool_call_id)`.
//!    At most one acquisition may be in flight per session (the rate limit).
//! 2. A trusted child runs and produces a candidate literal.
//! 3. The host presents the claimed authority (as the closed
//!    [`ProtectedSensitiveIngress::TrustedChildCapture`] variant) plus the raw
//!    candidate value to [`TrustedChildCaptureRegistry::verify_and_capture`].
//!    Replay, expiry, cancel, wrong project/session/generation/value/version,
//!    and a non-trusted-child authority ALL fail closed **before** the value is
//!    parsed, stored, or installed into the live redaction table. Only an exact
//!    match on every bound field of a live pending record proceeds to the
//!    in-process transfer.
//!
//! ## Fail-closed / non-oracular
//!
//! Every rejection returns the SAME [`TrustedChildCaptureOutcome::Denied`]: the
//! parent cannot distinguish a missing record, a wrong binding, a replay, an
//! expiry, a cancel, or a non-trusted authority (AC7's indistinguishability).
//! The distinguishable rate-limit refusal is surfaced only to the host at
//! `begin_capture` time (a [`BeginCaptureError`]), never to the parent/child.
//!
//! ## Transfer is in-process only (AC8)
//!
//! On an exact match the captured literal is written through
//! [`Session::set_sealed_value`] — the in-process host write that unions the
//! live redaction table, journals protected history, and stores the vault item
//! atomically. The value never routes through any generic MCP/Tool/event/
//! transcript path (that broader sweep is sub-increment 2c-4), and the Monty
//! `set_sealed_value` tool stays retired.

use std::collections::HashMap;
use std::sync::Mutex;

use zeroize::Zeroizing;

use super::Session;
use crate::leak_report::ProtectedSensitiveIngress;
use crate::redact::RedactionTable;

/// How long a minted acquisition stays live before it fails closed on expiry.
/// A trusted-child round-trip is short; an authority older than this is stale
/// and can never be honored.
pub const TRUSTED_CHILD_CAPTURE_TTL_MS: i64 = 5 * 60 * 1000;

/// One exact authority minted for a single trusted-child capture. Mirrors
/// [`crate::leak_report::ReportLeakAuthority`]: it binds the host-derived
/// identity and is single-use — a replayed, expired, cancelled, or mismatched
/// claim fails before secret parse, storage, or redaction install.
///
/// The authority carries only the SIX bound fields. The sealed-slot name
/// (`value_id`), reason, and origin the value is ultimately written under stay
/// host-held in the [`PendingCapture`] record and are never exposed to the
/// child, so the child cannot choose the destination slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedChildCaptureAuthority {
    record_id: String,
    project: String,
    session: String,
    generation: i64,
    version: i64,
    source_tool_call_id: String,
}

impl TrustedChildCaptureAuthority {
    /// The bound record id.
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    /// The bound project.
    pub fn project(&self) -> &str {
        &self.project
    }

    /// The bound session.
    pub fn session(&self) -> &str {
        &self.session
    }

    /// The bound session generation.
    pub fn generation(&self) -> i64 {
        self.generation
    }

    /// The bound sealed-value version.
    pub fn version(&self) -> i64 {
        self.version
    }

    /// The bound originating tool-call id.
    pub fn source_tool_call_id(&self) -> &str {
        &self.source_tool_call_id
    }

    /// Render the authority as the closed ingress variant the host presents
    /// back to [`TrustedChildCaptureRegistry::verify_and_capture`]. This is the
    /// only sanctioned way to build the claim, so the presented tuple always
    /// matches what was minted unless a field is deliberately tampered with.
    pub fn to_ingress(&self) -> ProtectedSensitiveIngress {
        ProtectedSensitiveIngress::TrustedChildCapture {
            record_id: self.record_id.clone(),
            project: self.project.clone(),
            session: self.session.clone(),
            generation: self.generation,
            version: self.version,
            source_tool_call_id: self.source_tool_call_id.clone(),
        }
    }
}

/// The raw candidate literal a trusted child produced, held in a
/// [`Zeroizing`] frame so it is wiped on drop. It is **not** validated or
/// parsed at construction — the value is opaque until an exact authority match
/// hands it to [`Session::set_sealed_value`]. The type deliberately does not
/// derive `Clone`/`Display` and its `Debug` is redacting, mirroring
/// [`crate::leak_report::ReportLeakRequest`], so a stray copy or `{:?}` cannot
/// defeat the containment guarantees.
pub struct SealedCaptureValue {
    literal: Zeroizing<String>,
}

impl SealedCaptureValue {
    /// Wrap a candidate literal. No validation happens here; the value is
    /// consumed into a zeroizing frame and parsed only on the success path.
    pub fn new(literal: String) -> Self {
        Self {
            literal: Zeroizing::new(literal),
        }
    }

    fn as_str(&self) -> &str {
        self.literal.as_str()
    }
}

impl std::fmt::Debug for SealedCaptureValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedCaptureValue")
            .field(
                "literal",
                &format_args!("[REDACTED; {}]", self.literal.len()),
            )
            .finish()
    }
}

/// The closed outcome of a verify-and-capture. The parent ever observes only
/// the discriminant: [`Self::Captured`] or [`Self::Denied`]. Every fail-closed
/// reason collapses to the single `Denied` variant so the result is
/// non-oracular (AC7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedChildCaptureOutcome {
    /// The value matched an exact live authority and was written in-process via
    /// [`Session::set_sealed_value`]; the live redaction table now scrubs it and
    /// the pending record is consumed.
    Captured { record_id: String },
    /// The capture was refused. Indistinguishable across missing record, wrong
    /// binding, replay, expiry, cancel, and non-trusted authority. No value was
    /// parsed, stored, or redaction-installed.
    Denied,
}

/// The distinguishable-to-host reason a `begin_capture` was refused. This is
/// surfaced only at mint time to the host coordinator, never to the
/// parent/child, so it is not an oracle over any secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginCaptureError {
    /// An acquisition is already in flight for this session (the one-per-session
    /// rate limit). The host must await or cancel it before starting another.
    AlreadyInFlight,
}

impl std::fmt::Display for BeginCaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInFlight => {
                f.write_str("a trusted-child capture is already in flight for this session")
            }
        }
    }
}

impl std::error::Error for BeginCaptureError {}

/// One pending Session sealed record. Holds the SIX bound fields plus the
/// host-held destination metadata (`value_id`/`reason`/`origin`) the value is
/// written under, and the expiry deadline. Carries no secret.
#[derive(Debug, Clone)]
struct PendingCapture {
    record_id: String,
    project: String,
    session: String,
    generation: i64,
    version: i64,
    source_tool_call_id: String,
    value_id: String,
    reason: String,
    expires_at_ms: i64,
}

/// Host-owned registry of in-flight trusted-child capture pending records,
/// keyed by session id. At most one pending record exists per session (the
/// rate limit). In-process only: an interrupted acquisition simply fails closed
/// — a captured secret is never resumed from a half-live durable record.
#[derive(Default)]
pub struct TrustedChildCaptureRegistry {
    pending: Mutex<HashMap<String, PendingCapture>>,
}

impl TrustedChildCaptureRegistry {
    /// A fresh, empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate ONE pending Session sealed record and mint ONE exact authority.
    ///
    /// The project and session are **host-derived** from the live [`Session`]
    /// (never caller-supplied strings), mirroring how
    /// [`crate::leak_report::ReportLeakAuthority`] derives its provenance. The
    /// destination slot (`value_id`), reason, and origin are host-chosen and
    /// stay in the pending record, out of the minted authority.
    ///
    /// Fails closed with [`BeginCaptureError::AlreadyInFlight`] if a
    /// non-expired acquisition is already in flight for this session, so at most
    /// one capture runs per session at a time.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_capture(
        &self,
        session: &Session,
        record_id: &str,
        value_id: &str,
        reason: &str,
        _origin: &str,
        generation: i64,
        version: i64,
        source_tool_call_id: &str,
        now_ms: i64,
    ) -> Result<TrustedChildCaptureAuthority, BeginCaptureError> {
        let session_key = session.id.to_string();
        let project = session.project_id.clone();
        let mut pending = self.pending.lock().unwrap();
        // A live (non-expired) record occupies the single in-flight slot. An
        // expired record is stale and reapable, so it does not block a fresh
        // acquisition.
        if let Some(existing) = pending.get(&session_key)
            && now_ms <= existing.expires_at_ms
        {
            return Err(BeginCaptureError::AlreadyInFlight);
        }
        let record = PendingCapture {
            record_id: record_id.to_owned(),
            project: project.clone(),
            session: session_key.clone(),
            generation,
            version,
            source_tool_call_id: source_tool_call_id.to_owned(),
            value_id: value_id.to_owned(),
            reason: reason.to_owned(),
            expires_at_ms: now_ms + TRUSTED_CHILD_CAPTURE_TTL_MS,
        };
        pending.insert(session_key.clone(), record);
        Ok(TrustedChildCaptureAuthority {
            record_id: record_id.to_owned(),
            project,
            session: session_key,
            generation,
            version,
            source_tool_call_id: source_tool_call_id.to_owned(),
        })
    }

    /// Cancel any in-flight acquisition for a session, freeing the slot. A
    /// subsequent verify for a cancelled record fails closed (indistinguishably
    /// from a missing record).
    pub fn cancel(&self, session_id: &str) {
        self.pending.lock().unwrap().remove(session_id);
    }

    /// Whether a live (non-expired) acquisition is in flight for a session.
    /// Host-only bookkeeping; carries no secret.
    pub fn has_in_flight(&self, session_id: &str, now_ms: i64) -> bool {
        self.pending
            .lock()
            .unwrap()
            .get(session_id)
            .is_some_and(|record| now_ms <= record.expires_at_ms)
    }

    /// Verify a claimed authority against the live pending record and, on an
    /// exact match, capture the value in-process.
    ///
    /// **Order (fail-closed before any side effect, guidance L18):** every
    /// binding, lifecycle, and authority check runs in a synchronous critical
    /// section BEFORE the value is parsed, validated, stored, or installed into
    /// the redaction table. Only an exact match on ALL six bound fields of a
    /// live, non-expired pending record — presented as the
    /// [`ProtectedSensitiveIngress::TrustedChildCapture`] variant — removes the
    /// record (single-use) and proceeds to the in-process transfer. Any other
    /// case leaves storage untouched and returns
    /// [`TrustedChildCaptureOutcome::Denied`].
    pub async fn verify_and_capture(
        &self,
        session: &Session,
        redaction: &RedactionTable,
        claimed: &ProtectedSensitiveIngress,
        value: SealedCaptureValue,
        now_ms: i64,
    ) -> TrustedChildCaptureOutcome {
        // The synchronous decision: hold the lock across every check and the
        // single-use removal so a concurrent replay cannot double-spend, then
        // drop it before the async transfer (a std Mutex guard must not cross an
        // await). The value is NOT touched here — it is parsed only after an
        // exact match, inside `set_sealed_value`.
        let proceed = {
            let mut pending = self.pending.lock().unwrap();
            match self.decide(&mut pending, session, claimed, now_ms) {
                Some(p) => p,
                None => return TrustedChildCaptureOutcome::Denied,
            }
        };

        // Exact match: perform the in-process host write. `set_sealed_value`
        // validates the literal, unions the live redaction table, journals
        // protected history, and writes the vault item in ONE atomic
        // transaction. It is the ONLY consumer of the literal — no generic
        // MCP/Tool/event/transcript path sees it. A write failure fails closed
        // (the record is already consumed; the host must begin a new capture).
        match session
            .create_agent_acquired_sealed_value(
                redaction,
                &proceed.record_id,
                &proceed.record_id,
                &proceed.value_id,
                &proceed.reason,
                value.as_str(),
                &proceed.source_tool_call_id,
                now_ms,
            )
            .await
        {
            Ok(_) => TrustedChildCaptureOutcome::Captured {
                record_id: proceed.record_id,
            },
            Err(_) => TrustedChildCaptureOutcome::Denied,
        }
    }

    /// The synchronous verify decision. Returns `Some(Proceed)` and removes the
    /// pending record (single-use) ONLY on an exact match of a live record;
    /// otherwise returns `None` and leaves storage untouched. Split out so the
    /// whole decision is atomic under one lock and no value is parsed here.
    fn decide(
        &self,
        pending: &mut HashMap<String, PendingCapture>,
        session: &Session,
        claimed: &ProtectedSensitiveIngress,
        now_ms: i64,
    ) -> Option<Proceed> {
        // 1. Non-trusted-child authority: any other closed ingress variant is
        //    refused before we even look up a record.
        let ProtectedSensitiveIngress::TrustedChildCapture {
            record_id,
            project,
            session: claim_session,
            generation,
            version,
            source_tool_call_id,
        } = claimed
        else {
            return None;
        };

        // 2. The claim must name the session it is being verified against, and a
        //    live pending record must exist for it. A wrong session (or a
        //    replayed/consumed one, which was already removed) finds no record.
        let session_key = session.id.to_string();
        if *claim_session != session_key {
            return None;
        }
        let record = pending.get(&session_key)?;

        // 3. Exact match on EVERY remaining bound field. Any mismatch leaves the
        //    legitimate record intact (a griefer cannot burn it with a wrong
        //    guess) and fails closed.
        let bindings_match = record.record_id == *record_id
            && record.project == *project
            && record.session == *claim_session
            && record.generation == *generation
            && record.version == *version
            && record.source_tool_call_id == *source_tool_call_id;
        if !bindings_match {
            return None;
        }

        // 4. Expiry: a stale authority is dead. Reap it and fail closed.
        if now_ms > record.expires_at_ms {
            pending.remove(&session_key);
            return None;
        }

        // 5. Exact live match: consume the record single-use and proceed. A
        //    replay now finds no record (step 2) and is denied.
        let record = pending.remove(&session_key)?;
        Some(Proceed {
            record_id: record.record_id,
            value_id: record.value_id,
            reason: record.reason,
            source_tool_call_id: record.source_tool_call_id,
        })
    }
}

/// The host-held destination metadata extracted on an exact match, carried out
/// of the critical section into the async transfer. Carries no secret.
struct Proceed {
    record_id: String,
    value_id: String,
    reason: String,
    source_tool_call_id: String,
}

#[cfg(test)]
mod tests;
