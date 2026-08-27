//! Production orchestration of the computer-use guidance proposal lifecycle
//! (issue #59).
//!
//! Wires the four landed pieces together against real sessions/delegations:
//!
//! - the pure enablement resolver ([`super::enablement::resolve_guidance_enablement`])
//!   is called on the proposal-create path (AC1/AC11: a create while enablement
//!   is false is hard-denied *before* any receipt);
//! - the daemon-memory custody ([`super::lifecycle::PendingProposalStore`]) holds
//!   typed values + rationale;
//! - the durable receipts + counters
//!   ([`cockpit_db::db::guidance_proposals`]) enforce the 3/10 caps and record
//!   the terminal state;
//! - accepted session/persistent rules are compiled into new model contexts via
//!   [`super::compose_and_compile`] (AC9).
//!
//! ## Audit emission (blocked on `computer-audit-chain-completion`)
//!
//! The four `guidance_proposal_*` audit events are emitted through the
//! [`GuidanceAuditWriter`] trait. The real tamper-evident audit-chain writer is
//! a separate pending decision (not yet filed as an issue); until it lands a
//! [`StubGuidanceAuditWriter`] logs a warning and proceeds. The contract
//! requires fail-closed behavior when a writer is unavailable at create time;
//! that wiring is deferred with the real writer and marked with `TODO` — it is
//! intentionally NOT remote/transport work, but it depends on an unfiled
//! owner scope decision, so it is stubbed here rather than invented.

use std::path::Path;
use std::sync::Arc;

use cockpit_db::db::guidance_proposals::{
    CreateReceiptError, GuidanceProposalAcceptedScope, GuidanceProposalCounterScope,
    GuidanceProposalReceiptInsert, GuidanceProposalReceiptState,
};
use cockpit_db::Db;
use tracing::warn;

use super::audit::{AuditEventKind, Disposition, GuidanceScope, domains, domain_digest};
use super::enablement::resolve_guidance_enablement;
use super::lifecycle::{PendingProposalStore, ProposalId, ProposalScopeKey};
use super::{
    ComputerGuidanceRuleV1, EnablementResolution, PROPOSAL_EXPIRY_SECS_MILLIS, validate_proposal,
};

// ---------------------------------------------------------------------------
// Scope digests (byte-identical to the audit contract)
// ---------------------------------------------------------------------------

/// Compute the canonical project identity digest (domain-separated SHA-256,
/// matching the audit `project` domain).
pub fn canonical_project_digest(project_identity: &[u8]) -> [u8; 32] {
    domain_digest(domains::PROJECT, project_identity)
}

/// Compute the provider identity digest (audit `provider` domain).
pub fn provider_digest(provider_id: &str) -> [u8; 32] {
    domain_digest(domains::PROVIDER, provider_id.as_bytes())
}

/// Compute the model identity digest (audit `model` domain).
pub fn model_digest(provider_id: &str, model_id: &str) -> [u8; 32] {
    // Include the provider so a model id collision across providers never
    // collapses two distinct model scopes.
    let mut value = Vec::with_capacity(provider_id.len() + 1 + model_id.len());
    value.extend_from_slice(provider_id.as_bytes());
    value.push(0x00);
    value.extend_from_slice(model_id.as_bytes());
    domain_digest(domains::MODEL, &value)
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    let bytes = decode_hex(s)?;
    if bytes.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Decode a lowercase hex string to bytes (no external `hex` dependency).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = decode_hex(s)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

// ---------------------------------------------------------------------------
// Audit writer (stub pending computer-audit-chain-completion)
// ---------------------------------------------------------------------------

/// The safe fields for a guidance-proposal audit event. Typed rule values and
/// rationale bytes are NEVER present here (AC7).
#[derive(Debug, Clone)]
pub struct GuidanceAuditEvent {
    pub kind: AuditEventKind,
    pub proposal_id: [u8; 16],
    pub session_id: [u8; 16],
    pub delegation_id: [u8; 16],
    pub canonical_project_digest: [u8; 32],
    pub provider_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub config_generation: u64,
    pub rule_kind_bits: u16,
    pub disposition: Option<Disposition>,
    pub scope: Option<GuidanceScope>,
}

/// Append-only audit writer for the four `guidance_proposal_*` event kinds.
///
/// The real implementation is the tamper-evident computer-audit chain from
/// `computer-audit-chain-completion` (pending). Until it lands, the
/// [`StubGuidanceAuditWriter`] is used.
pub trait GuidanceAuditWriter: Send + Sync {
    /// Append one guidance-proposal audit event. Returns `Err` when the writer
    /// is unavailable so the orchestrator can fail closed (no silent undurable
    /// proposals).
    fn append(&self, event: &GuidanceAuditEvent) -> anyhow::Result<()>;
}

/// Placeholder writer used until the real audit-chain writer lands.
///
/// TODO(computer-audit-chain-completion): replace with the real tamper-evident
/// writer and enforce fail-closed at create time. The stub logs and succeeds so
/// the lifecycle is exercisable in tests and the local TUI before the writer
/// decision is made; it carries no typed rule values or rationale bytes.
#[derive(Debug, Default)]
pub struct StubGuidanceAuditWriter;

impl GuidanceAuditWriter for StubGuidanceAuditWriter {
    fn append(&self, event: &GuidanceAuditEvent) -> anyhow::Result<()> {
        warn!(
            kind = ?event.kind,
            proposal_id = %hex16(&event.proposal_id),
            "guidance proposal audit event emitted via stub writer; \
             real audit-chain writer pending computer-audit-chain-completion"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Accepted rules (session + persistent, machine-local, never roaming)
// ---------------------------------------------------------------------------

/// The key for accepted **session** rules: `(session, canonical project,
/// provider, model, rule kind)`. Lives until session end.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SessionRuleKey {
    session_id: [u8; 16],
    project_digest: [u8; 32],
    provider_digest: [u8; 32],
    model_digest: [u8; 32],
}

/// The key for accepted **persistent** rules: `(canonical machine-local
/// project, provider, model, rule kind)`. Never roams via config export/sync.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PersistentRuleKey {
    project_digest: [u8; 32],
    provider_digest: [u8; 32],
    model_digest: [u8; 32],
}

/// In-memory custody of accepted rules. Session rules live until session end;
/// persistent rules are machine-local and never roam.
///
/// TODO: durable persistence of persistent rules (a future local-only table) so
/// they survive restart. Session rules are intentionally memory-only.
#[derive(Debug, Default)]
pub struct AcceptedRulesStore {
    session: std::sync::Mutex<std::collections::HashMap<SessionRuleKey, Vec<ComputerGuidanceRuleV1>>>,
    persistent:
        std::sync::Mutex<std::collections::HashMap<PersistentRuleKey, Vec<ComputerGuidanceRuleV1>>>,
}

impl AcceptedRulesStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn install_session(
        &self,
        key: SessionRuleKey,
        rules: Vec<ComputerGuidanceRuleV1>,
    ) {
        let mut guard = self.session.lock().expect("accepted session rules mutex poisoned");
        let existing = guard.entry(key).or_default();
        *existing = super::apply_accepted(existing, &rules);
    }

    fn install_persistent(
        &self,
        key: PersistentRuleKey,
        rules: Vec<ComputerGuidanceRuleV1>,
    ) {
        let mut guard = self.persistent.lock().expect("accepted persistent rules mutex poisoned");
        let existing = guard.entry(key).or_default();
        *existing = super::apply_accepted(existing, &rules);
    }

    fn clear_session(&self, session_id: &[u8; 16]) {
        let mut guard = self.session.lock().expect("accepted session rules mutex poisoned");
        guard.retain(|k, _| k.session_id != *session_id);
    }

    /// Read the accepted session rules for `(session, project, provider, model)`.
    fn session_rules(
        &self,
        session_id: &[u8; 16],
        project_digest: &[u8; 32],
        provider_digest: &[u8; 32],
        model_digest: &[u8; 32],
    ) -> Vec<ComputerGuidanceRuleV1> {
        let key = SessionRuleKey {
            session_id: *session_id,
            project_digest: *project_digest,
            provider_digest: *provider_digest,
            model_digest: *model_digest,
        };
        self.session
            .lock()
            .expect("accepted session rules mutex poisoned")
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }

    /// Read the accepted persistent rules for `(project, provider, model)`.
    fn persistent_rules(
        &self,
        project_digest: &[u8; 32],
        provider_digest: &[u8; 32],
        model_digest: &[u8; 32],
    ) -> Vec<ComputerGuidanceRuleV1> {
        let key = PersistentRuleKey {
            project_digest: *project_digest,
            provider_digest: *provider_digest,
            model_digest: *model_digest,
        };
        self.persistent
            .lock()
            .expect("accepted persistent rules mutex poisoned")
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Create-path errors
// ---------------------------------------------------------------------------

/// Failure to create a pending proposal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CreateProposalError {
    /// Enablement is false — hard-denied before any receipt (AC11).
    #[error("computer guidance proposals are disabled for this scope")]
    Disabled,
    /// The proposal failed validation (1..=6 unique kinds).
    #[error("guidance proposal validation failed: {0}")]
    InvalidProposal(String),
    /// A proposal is already pending for this scope.
    #[error("{0}")]
    AlreadyPending(String),
    /// A creation cap (3 per delegation / 10 per session) was exceeded — zero
    /// receipt, zero memory install, zero audit append (AC4).
    #[error("guidance proposal cap exceeded: {0}")]
    CapExceeded(String),
    /// The durable receipt insert failed for another reason.
    #[error("guidance proposal durable create failed: {0}")]
    Storage(String),
    /// The audit writer was unavailable (fail-closed — no durable proposal).
    #[error("guidance proposal audit writer unavailable: {0}")]
    AuditUnavailable(String),
}

// ---------------------------------------------------------------------------
// Accept-path errors
// ---------------------------------------------------------------------------

/// Failure to accept or reject a pending proposal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransitionProposalError {
    /// No pending proposal exists for this scope.
    #[error("no pending guidance proposal for this scope")]
    NotFound,
    /// The durable CAS did not match (e.g. accept after expiry) — no rule
    /// install (AC: edge cases).
    #[error("guidance proposal CAS conflict: current state is not the expected {expected:?}")]
    CasConflict { expected: GuidanceProposalReceiptState },
    /// A durable failure.
    #[error("guidance proposal durable transition failed: {0}")]
    Storage(String),
    /// The audit writer was unavailable.
    #[error("guidance proposal audit writer unavailable: {0}")]
    AuditUnavailable(String),
}

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

/// The production guidance-proposal lifecycle service. Single-owner over the
/// memory store; the daemon coordinator holds it behind `&mut`-style
/// serialization. Holds:
/// - the daemon-memory pending-proposal store,
/// - the in-memory accepted-rules store,
/// - a handle to the durable receipt/counter database,
/// - the audit writer (stub until the real chain lands).
pub struct GuidanceProposalService {
    pending: PendingProposalStore,
    accepted: AcceptedRulesStore,
    db: Arc<Db>,
    audit: Arc<dyn GuidanceAuditWriter>,
}

/// The enablement resolution plus the config generation it was resolved under,
/// for the TUI enablement trace (AC2).
#[derive(Debug, Clone)]
pub struct GuidanceEnablementTrace {
    pub resolution: EnablementResolution,
    pub config_generation: u64,
}

impl GuidanceProposalService {
    /// Construct a service backed by `db` and the stub audit writer.
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            pending: PendingProposalStore::new(),
            accepted: AcceptedRulesStore::new(),
            db,
            audit: Arc::new(StubGuidanceAuditWriter),
        }
    }

    /// Construct a service with an explicit audit writer (for tests / the real
    /// writer when it lands).
    pub fn with_audit_writer(db: Arc<Db>, audit: Arc<dyn GuidanceAuditWriter>) -> Self {
        Self {
            pending: PendingProposalStore::new(),
            accepted: AcceptedRulesStore::new(),
            db,
            audit,
        }
    }

    /// Borrow the pending-proposal store (for the review UI to read typed
    /// values + inert rationale).
    pub fn pending_store(&self) -> &PendingProposalStore {
        &self.pending
    }

    /// Resolve the enablement trace for `(cwd, provider_id, model_id)` (AC2).
    pub fn enablement_trace(
        &self,
        providers: &crate::config::providers::ProvidersConfig,
        cwd: &Path,
        provider_id: &str,
        model_id: &str,
    ) -> GuidanceEnablementTrace {
        let resolution = resolve_guidance_enablement(providers, cwd, provider_id, model_id);
        GuidanceEnablementTrace {
            config_generation: providers.resolution_generation.max(1),
            resolution,
        }
    }

    /// Create a pending proposal (the production proposal-create path, AC1/AC4/AC11).
    ///
    /// Ordering:
    /// 1. Resolve enablement; hard-deny before any receipt when disabled.
    /// 2. Validate the proposal (1..=6 unique kinds).
    /// 3. Reserve the scope in memory (fails `AlreadyPending` before durable
    ///    work).
    /// 4. Insert the content-free receipt + increment counters (transactional,
    ///    cap-enforced). On any failure release the reservation and return.
    /// 5. Append `guidance_proposal_created` via the audit writer (fail-closed
    ///    on unavailable writer: the receipt is CASed to `expired` and the
    ///    reservation/memory released — no silent undurable proposal).
    /// 6. Install typed values + rationale into memory.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_proposal(
        &mut self,
        providers: &crate::config::providers::ProvidersConfig,
        cwd: &Path,
        provider_id: &str,
        model_id: &str,
        project_identity: &[u8],
        session_id: [u8; 16],
        delegation_id: [u8; 16],
        proposal_id: [u8; 16],
        rules: Vec<ComputerGuidanceRuleV1>,
        rationale: Option<String>,
        now_unix_ms: i64,
    ) -> Result<(), CreateProposalError> {
        // 1. Enablement gate (AC11).
        let trace = self.enablement_trace(providers, cwd, provider_id, model_id);
        if !trace.resolution.enabled {
            return Err(CreateProposalError::Disabled);
        }

        // 2. Validate the proposal.
        let rule_kind_bits = validate_proposal(&rules)
            .map_err(|e| CreateProposalError::InvalidProposal(e.to_string()))?;

        let project_d = canonical_project_digest(project_identity);
        let provider_d = provider_digest(provider_id);
        let model_d = model_digest(provider_id, model_id);
        let key = ProposalScopeKey {
            session_id,
            delegation_id,
            project_digest: project_d,
            provider_digest: provider_d,
            model_digest: model_d,
        };
        let pid = ProposalId(proposal_id);

        // 3. Reserve the scope in memory (before durable work).
        self.pending
            .reserve(key.clone(), pid)
            .map_err(|e| CreateProposalError::AlreadyPending(e.wire_reason().to_string()))?;

        // 4. Durable receipt + counters (transactional).
        let session_id_str = hex16(&session_id);
        let delegation_id_str = hex16(&delegation_id);
        let expires_at_unix_ms = now_unix_ms.saturating_add(PROPOSAL_EXPIRY_SECS_MILLIS);
        let insert = GuidanceProposalReceiptInsert {
            proposal_id: &hex16(&proposal_id),
            session_id: &session_id_str,
            delegation_id: &delegation_id_str,
            canonical_project_digest: &hex32(&project_d),
            provider_digest: &hex32(&provider_d),
            model_digest: &hex32(&model_d),
            config_generation: trace.config_generation as i64,
            rule_kind_bits: rule_kind_bits as i64,
            created_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
        };
        if let Err(err) = self.db.insert_guidance_proposal_receipt(insert).await {
            self.pending.release(&key, pid);
            return Err(match err {
                CreateReceiptError::DelegationCapExceeded(n) => CreateProposalError::CapExceeded(
                    format!("delegation {n}/{MAX_DELEGATION}"),
                ),
                CreateReceiptError::SessionCapExceeded(n) => CreateProposalError::CapExceeded(
                    format!("session {n}/{MAX_SESSION}"),
                ),
                CreateReceiptError::DuplicateProposalId(id) => {
                    CreateProposalError::Storage(format!("duplicate proposal id {id}"))
                }
                CreateReceiptError::Storage(msg) => CreateProposalError::Storage(msg),
            });
        }

        // 5. Audit append (fail-closed on unavailable writer).
        let audit_event = GuidanceAuditEvent {
            kind: AuditEventKind::GuidanceProposalCreated,
            proposal_id,
            session_id,
            delegation_id,
            canonical_project_digest: project_d,
            provider_digest: provider_d,
            model_digest: model_d,
            config_generation: trace.config_generation,
            rule_kind_bits,
            disposition: None,
            scope: None,
        };
        if let Err(e) = self.audit.append(&audit_event) {
            // Fail closed: CAS the receipt to expired + append an expired audit,
            // then release memory. No silent undurable proposal.
            let _ = self
                .cas_and_audit(
                    &hex16(&proposal_id),
                    GuidanceProposalReceiptState::Created,
                    GuidanceProposalReceiptState::Expired,
                    None,
                    now_unix_ms,
                    AuditEventKind::GuidanceProposalExpired,
                )
                .await;
            self.pending.release(&key, pid);
            return Err(CreateProposalError::AuditUnavailable(e.to_string()));
        }

        // 6. Install typed values + rationale into memory.
        let now_unix_secs = now_unix_ms / 1000;
        if self
            .pending
            .install(key, pid, rules, rationale, now_unix_secs)
            .is_err()
        {
            // The reservation was released mid-create (invalidation). CAS the
            // durable receipt to expired + audit, and surface a storage error.
            let _ = self
                .cas_and_audit(
                    &hex16(&proposal_id),
                    GuidanceProposalReceiptState::Created,
                    GuidanceProposalReceiptState::Expired,
                    None,
                    now_unix_ms,
                    AuditEventKind::GuidanceProposalExpired,
                )
                .await;
            return Err(CreateProposalError::Storage(
                "memory reservation released mid-create (invalidation)".to_string(),
            ));
        }
        Ok(())
    }

    /// Accept a pending proposal as session-scoped rules (AC8).
    pub async fn accept_session(
        &mut self,
        scope: &ProposalScopeKey,
        proposal_id: [u8; 16],
        now_unix_ms: i64,
    ) -> Result<Vec<ComputerGuidanceRuleV1>, TransitionProposalError> {
        self.accept(scope, proposal_id, GuidanceProposalAcceptedScope::Session, now_unix_ms)
            .await
    }

    /// Accept a pending proposal as persistent (machine-local) rules (AC8).
    pub async fn accept_persistent(
        &mut self,
        scope: &ProposalScopeKey,
        proposal_id: [u8; 16],
        now_unix_ms: i64,
    ) -> Result<Vec<ComputerGuidanceRuleV1>, TransitionProposalError> {
        self.accept(scope, proposal_id, GuidanceProposalAcceptedScope::Persistent, now_unix_ms)
            .await
    }

    async fn accept(
        &mut self,
        scope: &ProposalScopeKey,
        proposal_id: [u8; 16],
        accepted_scope: GuidanceProposalAcceptedScope,
        now_unix_ms: i64,
    ) -> Result<Vec<ComputerGuidanceRuleV1>, TransitionProposalError> {
        let pid = ProposalId(proposal_id);
        // Read the typed values from memory (accept compiles the rules).
        let proposal = self
            .pending
            .get(scope)
            .ok_or(TransitionProposalError::NotFound)?
            .clone();

        // Durable CAS: created -> accepted.
        let proposal_id_str = hex16(&proposal_id);
        let applied = self
            .db
            .cas_guidance_proposal_receipt_state(
                &proposal_id_str,
                GuidanceProposalReceiptState::Created,
                GuidanceProposalReceiptState::Accepted,
                Some(accepted_scope),
                Some(now_unix_ms),
            )
            .await
            .map_err(|e| TransitionProposalError::Storage(e.to_string()))?;
        if !applied {
            return Err(TransitionProposalError::CasConflict {
                expected: GuidanceProposalReceiptState::Created,
            });
        }

        // Audit append.
        let (disp, gscope) = match accepted_scope {
            GuidanceProposalAcceptedScope::Session => {
                (Disposition::AcceptedSession, GuidanceScope::Session)
            }
            GuidanceProposalAcceptedScope::Persistent => (
                Disposition::AcceptedPersistent,
                GuidanceScope::ProjectProviderModel,
            ),
        };
        let audit_event = GuidanceAuditEvent {
            kind: AuditEventKind::GuidanceProposalAccepted,
            proposal_id,
            session_id: scope.session_id,
            delegation_id: scope.delegation_id,
            canonical_project_digest: scope.project_digest,
            provider_digest: scope.provider_digest,
            model_digest: scope.model_digest,
            config_generation: 0,
            rule_kind_bits: validate_proposal(&proposal.rules).unwrap_or(0),
            disposition: Some(disp),
            scope: Some(gscope),
        };
        if let Err(e) = self.audit.append(&audit_event) {
            // Best-effort rollback of the CAS so the receipt does not lie.
            let _ = self
                .db
                .cas_guidance_proposal_receipt_state(
                    &proposal_id_str,
                    GuidanceProposalReceiptState::Accepted,
                    GuidanceProposalReceiptState::Rejected,
                    None,
                    Some(now_unix_ms),
                )
                .await;
            return Err(TransitionProposalError::AuditUnavailable(e.to_string()));
        }

        // Install the accepted rules into the accepted-rules store.
        let rules = proposal.rules.clone();
        match accepted_scope {
            GuidanceProposalAcceptedScope::Session => {
                let key = SessionRuleKey {
                    session_id: scope.session_id,
                    project_digest: scope.project_digest,
                    provider_digest: scope.provider_digest,
                    model_digest: scope.model_digest,
                };
                self.accepted.install_session(key, rules.clone());
            }
            GuidanceProposalAcceptedScope::Persistent => {
                let key = PersistentRuleKey {
                    project_digest: scope.project_digest,
                    provider_digest: scope.provider_digest,
                    model_digest: scope.model_digest,
                };
                self.accepted.install_persistent(key, rules.clone());
            }
        }

        // Drop memory (rationale + typed values gone).
        self.pending.remove_committed(scope, pid);
        Ok(rules)
    }

    /// Reject a pending proposal (AC8).
    pub async fn reject(
        &mut self,
        scope: &ProposalScopeKey,
        proposal_id: [u8; 16],
        now_unix_ms: i64,
    ) -> Result<(), TransitionProposalError> {
        let pid = ProposalId(proposal_id);
        // Read exists (so the review UI had something to show).
        if self.pending.get(scope).is_none() {
            return Err(TransitionProposalError::NotFound);
        }

        let proposal_id_str = hex16(&proposal_id);
        let applied = self
            .db
            .cas_guidance_proposal_receipt_state(
                &proposal_id_str,
                GuidanceProposalReceiptState::Created,
                GuidanceProposalReceiptState::Rejected,
                None,
                Some(now_unix_ms),
            )
            .await
            .map_err(|e| TransitionProposalError::Storage(e.to_string()))?;
        if !applied {
            return Err(TransitionProposalError::CasConflict {
                expected: GuidanceProposalReceiptState::Created,
            });
        }

        let audit_event = GuidanceAuditEvent {
            kind: AuditEventKind::GuidanceProposalRejected,
            proposal_id,
            session_id: scope.session_id,
            delegation_id: scope.delegation_id,
            canonical_project_digest: scope.project_digest,
            provider_digest: scope.provider_digest,
            model_digest: scope.model_digest,
            config_generation: 0,
            rule_kind_bits: 0,
            disposition: Some(Disposition::Rejected),
            scope: None,
        };
        if let Err(e) = self.audit.append(&audit_event) {
            return Err(TransitionProposalError::AuditUnavailable(e.to_string()));
        }

        self.pending.remove_committed(scope, pid);
        Ok(())
    }

    /// Enumerate expired pending proposals (injected clock) without mutating.
    /// The caller (coordinator tick) commits each durable expiry CAS + audit,
    /// then [`Self::remove_expired`] drops memory (AC5).
    pub fn expired_candidates(&self, now_unix_secs: i64) -> Vec<super::lifecycle::ProposalCandidate> {
        self.pending.expired_candidates(now_unix_secs)
    }

    /// Commit the durable expiry CAS + audit for one candidate, then drop memory.
    pub async fn expire_candidate(
        &mut self,
        candidate: &super::lifecycle::ProposalCandidate,
        now_unix_ms: i64,
    ) -> Result<(), TransitionProposalError> {
        let proposal_id_str = hex16(&candidate.proposal_id.0);
        let applied = self
            .cas_and_audit(
                &proposal_id_str,
                GuidanceProposalReceiptState::Created,
                GuidanceProposalReceiptState::Expired,
                None,
                now_unix_ms,
                AuditEventKind::GuidanceProposalExpired,
            )
            .await?;
        if applied {
            self.pending
                .remove_committed(&candidate.key, candidate.proposal_id);
        }
        Ok(())
    }

    /// Invalidate pending proposals whose scope matches `predicate` (terminal
    /// delegation/session state or project/provider/model/config-generation
    /// change) — AC5. Commits each durable expiry CAS + audit, then drops memory
    /// and releases any in-flight reservations.
    pub async fn invalidate(
        &mut self,
        predicate: impl Fn(&ProposalScopeKey) -> bool,
        now_unix_ms: i64,
    ) -> Result<usize, TransitionProposalError> {
        let installed = self.pending.invalidation_candidates(&predicate);
        let mut count = 0;
        for candidate in installed {
            let proposal_id_str = hex16(&candidate.proposal_id.0);
            let applied = self
                .cas_and_audit(
                    &proposal_id_str,
                    GuidanceProposalReceiptState::Created,
                    GuidanceProposalReceiptState::Expired,
                    None,
                    now_unix_ms,
                    AuditEventKind::GuidanceProposalExpired,
                )
                .await?;
            if applied {
                self.pending
                    .remove_committed(&candidate.key, candidate.proposal_id);
                count += 1;
            }
        }
        // Cancel any in-flight reservations for the affected scopes.
        let reserved = self.pending.reserved_candidates(&predicate);
        for candidate in reserved {
            self.pending.release(&candidate.key, candidate.proposal_id);
        }
        Ok(count)
    }

    /// Startup `expired_on_restart` reconciliation (AC6): every receipt still
    /// `created` is CASed to `expired_on_restart` with exactly one
    /// `guidance_proposal_expired` audit append and no counter re-increment.
    /// Memory is fresh on restart so there is nothing to drop.
    pub async fn reconcile_on_restart(
        &self,
        now_unix_ms: i64,
    ) -> Result<usize, TransitionProposalError> {
        let stale = self
            .db
            .list_stale_created_guidance_proposal_receipts()
            .await
            .map_err(|e| TransitionProposalError::Storage(e.to_string()))?;
        let mut count = 0;
        for row in stale {
            // The proposal id hex is already 32 lowercase chars.
            let proposal_id = match parse_hex16(&row.proposal_id) {
                Some(id) => id,
                None => continue,
            };
            let applied = self
                .cas_and_audit(
                    &row.proposal_id,
                    GuidanceProposalReceiptState::Created,
                    GuidanceProposalReceiptState::ExpiredOnRestart,
                    None,
                    now_unix_ms,
                    AuditEventKind::GuidanceProposalExpired,
                )
                .await?;
            if applied {
                // Exactly one audit append per stale receipt; no counter
                // re-increment (creation already counted).
                let _ = proposal_id;
                count += 1;
            }
        }
        Ok(count)
    }

    /// Clear all accepted session rules for a session (on session end).
    pub fn clear_session_rules(&self, session_id: &[u8; 16]) {
        self.accepted.clear_session(session_id);
    }

    /// Compile the accepted guidance byte string for a new model context
    /// (AC9): session overrides persistent per kind; kinds emit in fixed
    /// discriminant order; only the 24 code-owned literals appear.
    pub fn compile_guidance_for_context(
        &self,
        session_id: &[u8; 16],
        project_digest: &[u8; 32],
        provider_digest: &[u8; 32],
        model_digest: &[u8; 32],
    ) -> Vec<u8> {
        let session = self
            .accepted
            .session_rules(session_id, project_digest, provider_digest, model_digest);
        let persistent = self
            .accepted
            .persistent_rules(project_digest, provider_digest, model_digest);
        super::compose_and_compile(&session, &persistent)
    }

    /// The current durable counter for a session (for diagnostics / tests).
    pub async fn session_counter(&self, session_id: &[u8; 16]) -> Result<i64, anyhow::Error> {
        self.db
            .guidance_proposal_counter(GuidanceProposalCounterScope::Session, &hex16(session_id))
            .await
    }

    /// The current durable counter for a delegation (for diagnostics / tests).
    pub async fn delegation_counter(
        &self,
        delegation_id: &[u8; 16],
    ) -> Result<i64, anyhow::Error> {
        self.db
            .guidance_proposal_counter(
                GuidanceProposalCounterScope::Delegation,
                &hex16(delegation_id),
            )
            .await
    }

    // -- internal --

    /// CAS the receipt state and append the matching audit event. Returns
    /// whether the CAS matched.
    async fn cas_and_audit(
        &self,
        proposal_id_str: &str,
        from: GuidanceProposalReceiptState,
        to: GuidanceProposalReceiptState,
        accepted_scope: Option<GuidanceProposalAcceptedScope>,
        now_unix_ms: i64,
        audit_kind: AuditEventKind,
    ) -> Result<bool, TransitionProposalError> {
        let applied = self
            .db
            .cas_guidance_proposal_receipt_state(
                proposal_id_str,
                from,
                to,
                accepted_scope,
                Some(now_unix_ms),
            )
            .await
            .map_err(|e| TransitionProposalError::Storage(e.to_string()))?;
        if !applied {
            return Ok(false);
        }
        // Best-effort audit append after a successful CAS. A failure here is
        // surfaced so the caller can retry/log; the durable state has already
        // advanced, which is the safer direction (no zombie `created` receipt).
        let row = self
            .db
            .guidance_proposal_receipt(proposal_id_str)
            .await
            .map_err(|e| TransitionProposalError::Storage(e.to_string()))?
            .ok_or(TransitionProposalError::NotFound)?;
        let proposal_id = parse_hex16(&row.proposal_id).unwrap_or([0u8; 16]);
        let event = GuidanceAuditEvent {
            kind: audit_kind,
            proposal_id,
            session_id: parse_hex16(&row.session_id).unwrap_or([0u8; 16]),
            delegation_id: parse_hex16(&row.delegation_id).unwrap_or([0u8; 16]),
            canonical_project_digest: parse_hex32(&row.canonical_project_digest)
                .unwrap_or([0u8; 32]),
            provider_digest: parse_hex32(&row.provider_digest).unwrap_or([0u8; 32]),
            model_digest: parse_hex32(&row.model_digest).unwrap_or([0u8; 32]),
            config_generation: row.config_generation as u64,
            rule_kind_bits: row.rule_kind_bits as u16,
            disposition: match to {
                GuidanceProposalReceiptState::Expired | GuidanceProposalReceiptState::ExpiredOnRestart => {
                    Some(Disposition::Expired)
                }
                GuidanceProposalReceiptState::Accepted => match accepted_scope {
                    Some(GuidanceProposalAcceptedScope::Session) => Some(Disposition::AcceptedSession),
                    Some(GuidanceProposalAcceptedScope::Persistent) => {
                        Some(Disposition::AcceptedPersistent)
                    }
                    None => None,
                },
                GuidanceProposalReceiptState::Rejected => Some(Disposition::Rejected),
                GuidanceProposalReceiptState::Created => None,
            },
            scope: match to {
                GuidanceProposalReceiptState::Accepted => match accepted_scope {
                    Some(GuidanceProposalAcceptedScope::Session) => Some(GuidanceScope::Session),
                    Some(GuidanceProposalAcceptedScope::Persistent) => {
                        Some(GuidanceScope::ProjectProviderModel)
                    }
                    None => None,
                },
                _ => None,
            },
        };
        if let Err(e) = self.audit.append(&event) {
            // The durable state already advanced; surface the audit failure but
            // do not revert (a reverted CAS would leave a stale `created`).
            warn!(error = %e, kind = ?audit_kind, "guidance proposal audit append failed after CAS");
        }
        Ok(true)
    }
}

const MAX_DELEGATION: i64 = super::MAX_PROPOSALS_PER_DELEGATION as i64;
const MAX_SESSION: i64 = super::MAX_PROPOSALS_PER_SESSION as i64;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer::guidance::{ObservationCadence, enablement::resolve_guidance_enablement};
    use cockpit_db::Db;
    use std::sync::Mutex;

    fn fresh_service() -> GuidanceProposalService {
        GuidanceProposalService::new(Arc::new(Db::open_in_memory().unwrap()))
    }

    fn id16(n: u8) -> [u8; 16] {
        [n; 16]
    }

    fn rule() -> ComputerGuidanceRuleV1 {
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction)
    }

    fn providers_disabled() -> crate::config::providers::ProvidersConfig {
        // No layers set -> all absent -> disabled (default off).
        crate::config::providers::ProvidersConfig::default()
    }

    fn providers_enabled() -> crate::config::providers::ProvidersConfig {
        // The resolver reads the provider layer from the catalog; setting it
        // here exercises the real production resolver (AC1) with no disable
        // veto, so the effective result is enabled.
        let mut cfg = crate::config::providers::ProvidersConfig::default();
        let entry = cfg.providers.entry("p".to_string()).or_default();
        entry.allow_computer_guidance_proposals = Some(true);
        cfg
    }

    #[tokio::test]
    async fn create_denied_when_disabled_with_zero_side_effects() {
        let mut svc = fresh_service();
        let err = svc
            .create_proposal(
                &providers_disabled(),
        Path::new("/x"),
                "p",
                "m",
                b"project",
                id16(1),
                id16(2),
                id16(9),
                vec![rule()],
                None,
                1000,
            )
            .await
            .unwrap_err();
        assert_eq!(err, CreateProposalError::Disabled);
        // Zero side effects: no receipt, no memory.
        assert!(svc.pending_store().is_empty());
        assert_eq!(svc.session_counter(&id16(1)).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn create_succeeds_when_enabled_and_installs_memory() {
        let mut svc = fresh_service();
        svc.create_proposal(
            &providers_enabled(),
            Path::new("/x"),
            "p",
            "m",
            b"project",
            id16(1),
            id16(2),
            id16(9),
            vec![rule()],
            Some("why".into()),
            1000,
        )
        .await
        .unwrap();
        assert_eq!(svc.pending_store().len(), 1);
        assert_eq!(svc.session_counter(&id16(1)).await.unwrap(), 1);
        assert_eq!(svc.delegation_counter(&id16(2)).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn fourth_delegation_create_rejected_with_zero_side_effects() {
        let mut svc = fresh_service();
        for n in 1..=3u8 {
            svc.create_proposal(
                &providers_enabled(),
                Path::new("/x"),
                "p",
                "m",
                b"project",
                id16(1),
                id16(n), // distinct delegations
                id16(n),
                vec![rule()],
                None,
                1000 + n as i64,
            )
            .await
            .unwrap();
        }
        let err = svc
            .create_proposal(
                &providers_enabled(),
                Path::new("/x"),
                "p",
                "m",
                b"project",
                id16(1),
                id16(4),
                id16(10),
                vec![rule()],
                None,
                2000,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, CreateProposalError::CapExceeded(_)));
        // Zero side effects for the rejected 4th.
        assert_eq!(svc.pending_store().len(), 3);
        assert_eq!(svc.delegation_counter(&id16(4)).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn expiry_drops_memory_and_cas_receipt() {
        let mut svc = fresh_service();
        svc.create_proposal(
            &providers_enabled(),
            Path::new("/x"),
            "p",
            "m",
            b"project",
            id16(1),
            id16(2),
            id16(9),
            vec![rule()],
            Some("r".into()),
            0,
        )
        .await
        .unwrap();
        // created_at_secs = 0; expiry at 600s.
        let due = svc.expired_candidates(600);
        assert_eq!(due.len(), 1);
        svc.expire_candidate(&due[0], 600_000).await.unwrap();
        assert!(svc.pending_store().is_empty());
    }

    #[tokio::test]
    async fn accept_session_compiles_rules_and_overrides_persistent() {
        let mut svc = fresh_service();
        let project = canonical_project_digest(b"proj");
        let provider = provider_digest("p");
        let model = model_digest("p", "m");

        // Create + accept session (max_actions=2) under delegation 2.
        let scope_session = ProposalScopeKey {
            session_id: id16(1),
            delegation_id: id16(2),
            project_digest: project,
            provider_digest: provider,
            model_digest: model,
        };
        svc.create_proposal(
            &providers_enabled(),
            Path::new("/x"),
            "p",
            "m",
            b"proj",
            id16(1),
            id16(2),
            id16(9),
            vec![ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 2 }],
            None,
            1000,
        )
        .await
        .unwrap();
        let accepted = svc.accept_session(&scope_session, id16(9), 2000).await.unwrap();
        assert_eq!(accepted.len(), 1);

        // Create + accept persistent (max_actions=5, same kind) under a
        // distinct delegation so the pending scope does not collide.
        let scope_persistent = ProposalScopeKey {
            session_id: id16(1),
            delegation_id: id16(3),
            project_digest: project,
            provider_digest: provider,
            model_digest: model,
        };
        svc.create_proposal(
            &providers_enabled(),
            Path::new("/x"),
            "p",
            "m",
            b"proj",
            id16(1),
            id16(3),
            id16(8),
            vec![ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 5 }],
            None,
            3000,
        )
        .await
        .unwrap();
        svc.accept_persistent(&scope_persistent, id16(8), 4000)
            .await
            .unwrap();

        // Compile: session (max_actions=2) overrides persistent (max_actions=5)
        // for the same kind. Only the code-owned literal for max_actions=2
        // appears — never the 5 literal or any rationale/proposal bytes (AC9).
        let compiled = svc.compile_guidance_for_context(&id16(1), &project, &provider, &model);
        let expected = super::super::compose_and_compile(
            &[ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 2 }],
            &[ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 5 }],
        );
        assert_eq!(compiled, expected);
        // The compiler literal for max_actions=2 is "two"; "five" must NOT
        // appear (session wins, persistent value suppressed).
        let compiled_str = std::str::from_utf8(&compiled).unwrap();
        assert!(compiled_str.contains("two"));
        assert!(!compiled_str.contains("five"));
    }

    #[tokio::test]
    async fn restart_reconcile_cas_to_expired_on_restart_one_audit_no_recount() {
        // A recording audit writer to count exactly one expired append per
        // stale receipt.
        let recorded: Arc<Mutex<Vec<AuditEventKind>>> = Arc::new(Mutex::new(vec![]));
        struct Recording(Arc<Mutex<Vec<AuditEventKind>>>);
        impl GuidanceAuditWriter for Recording {
            fn append(&self, event: &GuidanceAuditEvent) -> anyhow::Result<()> {
                self.0.lock().unwrap().push(event.kind);
                Ok(())
            }
        }
        let db = Arc::new(Db::open_in_memory().unwrap());
        let mut svc =
            GuidanceProposalService::with_audit_writer(db.clone(), Arc::new(Recording(recorded.clone())));
        svc.create_proposal(
            &providers_enabled(),
            Path::new("/x"),
            "p",
            "m",
            b"proj",
            id16(1),
            id16(2),
            id16(9),
            vec![rule()],
            None,
            1000,
        )
        .await
        .unwrap();
        let before = svc.delegation_counter(&id16(2)).await.unwrap();
        assert_eq!(before, 1);

        // Simulate restart: a fresh service with the same db (memory empty).
        let svc2 = GuidanceProposalService::with_audit_writer(
            db.clone(),
            Arc::new(Recording(recorded.clone())),
        );
        let n = svc2.reconcile_on_restart(9000).await.unwrap();
        assert_eq!(n, 1);
        // Exactly one expired audit append.
        let kinds = recorded.lock().unwrap();
        assert!(kinds.iter().any(|k| *k == AuditEventKind::GuidanceProposalCreated));
        assert_eq!(
            kinds.iter().filter(|k| **k == AuditEventKind::GuidanceProposalExpired).count(),
            1
        );
        // No counter re-increment.
        assert_eq!(svc2.delegation_counter(&id16(2)).await.unwrap(), 1);
    }
}
