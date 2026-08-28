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
//! Until the tamper-evident chain is installed, production uses
//! [`StubGuidanceAuditWriter`] and proposal creation fails closed.

use std::sync::Arc;

use super::audit::{AuditEventKind, Disposition, GuidanceScope, domain_digest, domains};
use super::enablement::resolve_guidance_enablement_pinned;
use super::lifecycle::{PendingProposalStore, ProposalId, ProposalScopeKey};
use super::{
    ComputerGuidanceRuleV1, EnablementResolution, PROPOSAL_EXPIRY_SECS_MILLIS, normalize_rationale,
    validate_proposal,
};
use cockpit_db::Db;
use cockpit_db::db::guidance_proposals::{
    CreateReceiptError, GuidanceProposalAcceptedScope, GuidanceProposalCounterScope,
    GuidanceProposalReceiptInsert, GuidanceProposalReceiptState,
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
    /// Whether the writer can currently accept an append. Lifecycle methods
    /// check this before changing durable state; `append` remains authoritative
    /// because availability can change between the two calls.
    fn is_available(&self) -> bool {
        true
    }

    /// Whether this adapter can deliver into the final audit chain now. A
    /// durable-outbox-only adapter remains available for safe commits but
    /// leaves rows pending.
    fn delivers_immediately(&self) -> bool {
        true
    }

    /// Append one guidance-proposal audit event. Returns `Err` when the writer
    /// is unavailable so the orchestrator can fail closed (no silent undurable
    /// proposals).
    fn append(&self, event: &GuidanceAuditEvent) -> anyhow::Result<()>;
}

/// Fail-closed writer used until the real audit-chain writer lands.
///
/// TODO(computer-audit-chain-completion): replace with the real tamper-evident
/// writer. No lifecycle mutation may be presented as audited while the writer
/// is unavailable.
#[derive(Debug, Default)]
pub struct StubGuidanceAuditWriter;

impl GuidanceAuditWriter for StubGuidanceAuditWriter {
    fn is_available(&self) -> bool {
        false
    }

    fn append(&self, event: &GuidanceAuditEvent) -> anyhow::Result<()> {
        anyhow::bail!(
            "computer guidance audit writer unavailable for {:?} proposal {}",
            event.kind,
            hex16(&event.proposal_id)
        )
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
    session:
        std::sync::Mutex<std::collections::HashMap<SessionRuleKey, Vec<ComputerGuidanceRuleV1>>>,
    persistent:
        std::sync::Mutex<std::collections::HashMap<PersistentRuleKey, Vec<ComputerGuidanceRuleV1>>>,
}

impl AcceptedRulesStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn install_session(&self, key: SessionRuleKey, rules: Vec<ComputerGuidanceRuleV1>) {
        let mut guard = self
            .session
            .lock()
            .expect("accepted session rules mutex poisoned");
        let existing = guard.entry(key).or_default();
        *existing = super::apply_accepted(existing, &rules);
    }

    fn install_persistent(&self, key: PersistentRuleKey, rules: Vec<ComputerGuidanceRuleV1>) {
        let mut guard = self
            .persistent
            .lock()
            .expect("accepted persistent rules mutex poisoned");
        let existing = guard.entry(key).or_default();
        *existing = super::apply_accepted(existing, &rules);
    }

    fn clear_session(&self, session_id: &[u8; 16]) {
        let mut guard = self
            .session
            .lock()
            .expect("accepted session rules mutex poisoned");
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

impl CreateProposalError {
    /// Content-safe lifecycle reason returned to the proposing model.
    pub fn wire_reason(&self) -> &'static str {
        match self {
            Self::Disabled => "proposal_disabled",
            Self::InvalidProposal(_) => "proposal_invalid",
            Self::AlreadyPending(_) => "proposal_already_pending",
            Self::CapExceeded(_) => "proposal_cap_exceeded",
            Self::Storage(_) => "proposal_storage_unavailable",
            Self::AuditUnavailable(_) => "proposal_audit_unavailable",
        }
    }
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
    /// The review arrived at or after the proposal deadline. The service
    /// expires it durably instead of applying the requested transition.
    #[error("guidance proposal has expired")]
    Expired,
    /// The durable CAS did not match (e.g. accept after expiry) — no rule
    /// install (AC: edge cases).
    #[error("guidance proposal CAS conflict: current state is not the expected {expected:?}")]
    CasConflict {
        expected: GuidanceProposalReceiptState,
    },
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
    accepted: Arc<AcceptedRulesStore>,
    db: Arc<Db>,
    audit: Arc<dyn GuidanceAuditWriter>,
}

#[derive(Clone)]
pub struct GuidanceCompiler {
    accepted: Arc<AcceptedRulesStore>,
    session_id: [u8; 16],
    canonical_project_digest: [u8; 32],
}

impl GuidanceCompiler {
    pub fn compile(&self, _cwd: &std::path::Path, provider_id: &str, model_id: &str) -> Vec<u8> {
        let provider = provider_digest(provider_id);
        let model = model_digest(provider_id, model_id);
        let session = self.accepted.session_rules(
            &self.session_id,
            &self.canonical_project_digest,
            &provider,
            &model,
        );
        let persistent =
            self.accepted
                .persistent_rules(&self.canonical_project_digest, &provider, &model);
        super::compose_and_compile(&session, &persistent)
    }
}

/// The enablement resolution plus the config generation it was resolved under,
/// for the TUI enablement trace (AC2).
#[derive(Debug, Clone)]
pub struct GuidanceEnablementTrace {
    pub resolution: EnablementResolution,
    pub config_generation: u64,
}

/// Trusted, generation-pinned create authority resolved once at the daemon
/// worker boundary. Lifecycle code never reopens config files or resolves a
/// second generation beneath that boundary.
#[derive(Debug, Clone)]
pub struct GuidanceCreateSnapshot {
    pub enablement: GuidanceEnablementTrace,
    pub project_digest: [u8; 32],
    pub provider_digest: [u8; 32],
    pub model_digest: [u8; 32],
}

impl GuidanceProposalService {
    pub fn pending_proposals(
        &self,
        include_scope: impl Fn(&ProposalScopeKey) -> bool,
        persistent_acceptance_allowed: impl Fn(&ProposalScopeKey) -> bool,
    ) -> Vec<cockpit_proto::PendingGuidanceProposal> {
        self.pending
            .proposals()
            .filter(|(scope, _)| include_scope(scope))
            .map(|(scope, proposal)| cockpit_proto::PendingGuidanceProposal {
                proposal_id: uuid::Uuid::from_bytes(proposal.proposal_id.0),
                rules: proposal
                    .rules
                    .iter()
                    .map(ComputerGuidanceRuleV1::encode)
                    .collect(),
                rationale: proposal.rationale.clone(),
                expires_at_unix_ms: proposal.expires_at,
                persistent_acceptance_allowed: persistent_acceptance_allowed(scope),
            })
            .collect()
    }

    pub fn proposal_scope_by_id(&self, proposal_id: [u8; 16]) -> Option<ProposalScopeKey> {
        self.pending
            .proposals()
            .find(|(_, proposal)| proposal.proposal_id.0 == proposal_id)
            .map(|(scope, _)| scope.clone())
    }

    pub async fn proposal_config_generation(
        &self,
        proposal_id: [u8; 16],
    ) -> Result<Option<u64>, TransitionProposalError> {
        let receipt = self
            .db
            .guidance_proposal_receipt(&hex16(&proposal_id))
            .await
            .map_err(|error| TransitionProposalError::Storage(error.to_string()))?;
        receipt
            .map(|receipt| {
                u64::try_from(receipt.config_generation)
                    .map_err(|error| TransitionProposalError::Storage(error.to_string()))
            })
            .transpose()
    }

    pub async fn review_by_id(
        &mut self,
        proposal_id: [u8; 16],
        decision: cockpit_proto::GuidanceProposalDecision,
        now_unix_ms: i64,
    ) -> Result<Vec<ComputerGuidanceRuleV1>, TransitionProposalError> {
        let scope = self
            .pending
            .proposals()
            .find(|(_, proposal)| proposal.proposal_id.0 == proposal_id)
            .map(|(scope, _)| scope.clone())
            .ok_or(TransitionProposalError::NotFound)?;
        match decision {
            cockpit_proto::GuidanceProposalDecision::Reject => {
                self.reject(&scope, proposal_id, now_unix_ms).await?;
                Ok(Vec::new())
            }
            cockpit_proto::GuidanceProposalDecision::AcceptSession => {
                self.accept_session(&scope, proposal_id, now_unix_ms).await
            }
            cockpit_proto::GuidanceProposalDecision::AcceptPersistent => {
                self.accept_persistent(&scope, proposal_id, now_unix_ms)
                    .await
            }
        }
    }
    /// Construct a service backed by `db` and the stub audit writer.
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            pending: PendingProposalStore::new(),
            accepted: Arc::new(AcceptedRulesStore::new()),
            db,
            audit: Arc::new(StubGuidanceAuditWriter),
        }
    }

    /// Construct a service with an explicit audit writer (for tests / the real
    /// writer when it lands).
    pub fn with_audit_writer(db: Arc<Db>, audit: Arc<dyn GuidanceAuditWriter>) -> Self {
        Self {
            pending: PendingProposalStore::new(),
            accepted: Arc::new(AcceptedRulesStore::new()),
            db,
            audit,
        }
    }

    pub fn compiler(
        &self,
        session_id: [u8; 16],
        canonical_project_digest: [u8; 32],
    ) -> GuidanceCompiler {
        GuidanceCompiler {
            accepted: self.accepted.clone(),
            session_id,
            canonical_project_digest,
        }
    }

    /// Reload machine-local persistent rules during daemon boot. Session rules
    /// intentionally have no durable representation.
    pub async fn reload_persistent_rules(&self) -> anyhow::Result<usize> {
        let rows = self.db.load_persistent_guidance_rules().await?;
        let mut loaded = 0;
        for (project, provider, model, encoded) in rows {
            let project_digest = parse_hex32(&project)
                .ok_or_else(|| anyhow::anyhow!("invalid stored guidance project digest"))?;
            let provider_digest = parse_hex32(&provider)
                .ok_or_else(|| anyhow::anyhow!("invalid stored guidance provider digest"))?;
            let model_digest = parse_hex32(&model)
                .ok_or_else(|| anyhow::anyhow!("invalid stored guidance model digest"))?;
            let rule = ComputerGuidanceRuleV1::decode(&encoded)?;
            self.accepted.install_persistent(
                PersistentRuleKey {
                    project_digest,
                    provider_digest,
                    model_digest,
                },
                vec![rule],
            );
            loaded += 1;
        }
        Ok(loaded)
    }

    /// Retry every audit event left in the durable outbox by an append error
    /// or daemon crash. Delivery marking is idempotent; the audit writer must
    /// use the proposal/state identity for append deduplication.
    pub async fn flush_audit_outbox(&self, now_unix_ms: i64) -> anyhow::Result<usize> {
        if !self.audit.delivers_immediately() {
            return Ok(0);
        }
        let pending = self.db.pending_guidance_proposal_audits().await?;
        let mut delivered = 0;
        for item in pending {
            let row = &item.receipt;
            let accepted_scope = item.event_accepted_scope;
            let kind = match item.event_state {
                GuidanceProposalReceiptState::Created => AuditEventKind::GuidanceProposalCreated,
                GuidanceProposalReceiptState::Accepted => AuditEventKind::GuidanceProposalAccepted,
                GuidanceProposalReceiptState::Rejected => AuditEventKind::GuidanceProposalRejected,
                GuidanceProposalReceiptState::Expired
                | GuidanceProposalReceiptState::ExpiredOnRestart => {
                    AuditEventKind::GuidanceProposalExpired
                }
            };
            let event = GuidanceAuditEvent {
                kind,
                proposal_id: parse_hex16(&row.proposal_id)
                    .ok_or_else(|| anyhow::anyhow!("invalid receipt proposal id"))?,
                session_id: parse_hex16(&row.session_id)
                    .ok_or_else(|| anyhow::anyhow!("invalid receipt session id"))?,
                delegation_id: parse_hex16(&row.delegation_id)
                    .ok_or_else(|| anyhow::anyhow!("invalid receipt delegation id"))?,
                canonical_project_digest: parse_hex32(&row.canonical_project_digest)
                    .ok_or_else(|| anyhow::anyhow!("invalid receipt project digest"))?,
                provider_digest: parse_hex32(&row.provider_digest)
                    .ok_or_else(|| anyhow::anyhow!("invalid receipt provider digest"))?,
                model_digest: parse_hex32(&row.model_digest)
                    .ok_or_else(|| anyhow::anyhow!("invalid receipt model digest"))?,
                config_generation: u64::try_from(row.config_generation)?,
                rule_kind_bits: u16::try_from(row.rule_kind_bits)?,
                disposition: match item.event_state {
                    GuidanceProposalReceiptState::Accepted => match accepted_scope {
                        Some(GuidanceProposalAcceptedScope::Session) => {
                            Some(Disposition::AcceptedSession)
                        }
                        Some(GuidanceProposalAcceptedScope::Persistent) => {
                            Some(Disposition::AcceptedPersistent)
                        }
                        None => anyhow::bail!("accepted guidance audit lacks scope"),
                    },
                    GuidanceProposalReceiptState::Rejected => Some(Disposition::Rejected),
                    GuidanceProposalReceiptState::Expired
                    | GuidanceProposalReceiptState::ExpiredOnRestart => Some(Disposition::Expired),
                    GuidanceProposalReceiptState::Created => None,
                },
                scope: match accepted_scope {
                    Some(GuidanceProposalAcceptedScope::Session) => Some(GuidanceScope::Session),
                    Some(GuidanceProposalAcceptedScope::Persistent) => {
                        Some(GuidanceScope::ProjectProviderModel)
                    }
                    None => None,
                },
            };
            self.audit.append(&event)?;
            self.db
                .mark_guidance_proposal_audit_delivered(
                    &row.proposal_id,
                    item.event_state,
                    now_unix_ms,
                )
                .await?;
            delivered += 1;
        }
        Ok(delivered)
    }

    /// Borrow the pending-proposal store (for the review UI to read typed
    /// values + inert rationale).
    pub fn pending_store(&self) -> &PendingProposalStore {
        &self.pending
    }

    pub fn resolve_create_snapshot(
        &self,
        providers: &crate::config::providers::ProvidersConfig,
        global: Option<bool>,
        project: Option<bool>,
        config_generation: u64,
        provider_id: &str,
        model_id: &str,
        project_identity: &[u8],
    ) -> GuidanceCreateSnapshot {
        GuidanceCreateSnapshot {
            enablement: GuidanceEnablementTrace {
                resolution: resolve_guidance_enablement_pinned(
                    providers,
                    global,
                    project,
                    provider_id,
                    model_id,
                ),
                config_generation,
            },
            project_digest: canonical_project_digest(project_identity),
            provider_digest: provider_digest(provider_id),
            model_digest: model_digest(provider_id, model_id),
        }
    }

    /// Create a pending proposal (the production proposal-create path, AC1/AC4/AC11).
    ///
    /// The create path resolves the layered config itself, before any receipt,
    /// and stamps that resolution's generation onto the durable receipt.
    ///
    /// Ordering:
    /// 1. Enablement gate: hard-deny before any receipt when disabled (AC11).
    /// 2. Validate the proposal (1..=6 unique kinds).
    /// 3. Reserve the scope in memory (fails `AlreadyPending` before durable
    ///    work).
    /// 4. Insert the content-free receipt + increment counters (transactional,
    ///    cap-enforced). On any failure release the reservation and return.
    /// 5. Append `guidance_proposal_created` via the audit writer (fail-closed
    ///    on append failure: atomically delete the new receipt, its outbox row,
    ///    and both counter increments; then release the memory reservation).
    /// 6. Install typed values + rationale into memory.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_proposal(
        &mut self,
        snapshot: GuidanceCreateSnapshot,
        session_id: [u8; 16],
        delegation_id: [u8; 16],
        proposal_id: [u8; 16],
        rules: Vec<ComputerGuidanceRuleV1>,
        rationale: Option<String>,
        now_unix_ms: i64,
    ) -> Result<(), CreateProposalError> {
        // 1. Enablement gate (AC11).
        if !snapshot.enablement.resolution.enabled {
            return Err(CreateProposalError::Disabled);
        }

        // 2. Validate the proposal.
        let rule_kind_bits = validate_proposal(&rules)
            .map_err(|e| CreateProposalError::InvalidProposal(e.to_string()))?;
        let rationale = match rationale {
            Some(value) => normalize_rationale(&value)
                .map_err(|e| CreateProposalError::InvalidProposal(e.to_string()))?,
            None => None,
        };

        let project_d = snapshot.project_digest;
        let provider_d = snapshot.provider_digest;
        let model_d = snapshot.model_digest;
        let key = ProposalScopeKey {
            session_id,
            delegation_id,
            project_digest: project_d,
            provider_digest: provider_d,
            model_digest: model_d,
        };
        let pid = ProposalId(proposal_id);

        if !self.audit.is_available() {
            return Err(CreateProposalError::AuditUnavailable(
                "computer guidance audit writer is not installed".to_string(),
            ));
        }

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
            config_generation: snapshot.enablement.config_generation as i64,
            rule_kind_bits: rule_kind_bits as i64,
            created_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
        };
        if let Err(err) = self.db.insert_guidance_proposal_receipt(insert).await {
            self.pending.release(&key, pid);
            return Err(match err {
                CreateReceiptError::DelegationCapExceeded(n) => {
                    CreateProposalError::CapExceeded(format!("delegation {n}/{MAX_DELEGATION}"))
                }
                CreateReceiptError::SessionCapExceeded(n) => {
                    CreateProposalError::CapExceeded(format!("session {n}/{MAX_SESSION}"))
                }
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
            config_generation: snapshot.enablement.config_generation,
            rule_kind_bits,
            disposition: None,
            scope: None,
        };
        if self.audit.delivers_immediately() {
            if let Err(audit_error) = self.audit.append(&audit_event) {
                let proposal_id = hex16(&proposal_id);
                let rollback = self
                    .db
                    .rollback_created_guidance_proposal_receipt(&proposal_id)
                    .await;
                self.pending.release(&key, pid);
                return match rollback {
                    Ok(true) => Err(CreateProposalError::AuditUnavailable(
                        audit_error.to_string(),
                    )),
                    Ok(false) => Err(CreateProposalError::Storage(format!(
                        "guidance audit append failed and created receipt could not be rolled back: {audit_error}"
                    ))),
                    Err(rollback_error) => Err(CreateProposalError::Storage(format!(
                        "guidance audit append failed and rollback failed: {audit_error}; {rollback_error}"
                    ))),
                };
            }
            if let Err(error) = self
                .db
                .mark_guidance_proposal_audit_delivered(
                    &hex16(&proposal_id),
                    GuidanceProposalReceiptState::Created,
                    now_unix_ms,
                )
                .await
            {
                tracing::warn!(%error, "guidance created audit delivery mark remains retryable");
            }
        }

        // 6. Install typed values + rationale into memory.
        if self
            .pending
            .install(key, pid, rules, rationale, now_unix_ms)
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
        self.accept(
            scope,
            proposal_id,
            GuidanceProposalAcceptedScope::Session,
            now_unix_ms,
        )
        .await
    }

    /// Accept a pending proposal as persistent (machine-local) rules (AC8).
    pub async fn accept_persistent(
        &mut self,
        scope: &ProposalScopeKey,
        proposal_id: [u8; 16],
        now_unix_ms: i64,
    ) -> Result<Vec<ComputerGuidanceRuleV1>, TransitionProposalError> {
        self.accept(
            scope,
            proposal_id,
            GuidanceProposalAcceptedScope::Persistent,
            now_unix_ms,
        )
        .await
    }

    async fn accept(
        &mut self,
        scope: &ProposalScopeKey,
        proposal_id: [u8; 16],
        accepted_scope: GuidanceProposalAcceptedScope,
        now_unix_ms: i64,
    ) -> Result<Vec<ComputerGuidanceRuleV1>, TransitionProposalError> {
        if !self.audit.is_available() {
            return Err(TransitionProposalError::AuditUnavailable(
                "computer guidance audit writer is not installed".to_string(),
            ));
        }
        let pid = ProposalId(proposal_id);
        // Read the typed values from memory (accept compiles the rules).
        let proposal = self
            .pending
            .get(scope)
            .ok_or(TransitionProposalError::NotFound)?
            .clone();
        if proposal.proposal_id != pid {
            return Err(TransitionProposalError::NotFound);
        }
        if proposal.is_expired_at(now_unix_ms) {
            self.expire_candidate(
                &super::lifecycle::ProposalCandidate {
                    key: scope.clone(),
                    proposal_id: pid,
                },
                now_unix_ms,
            )
            .await?;
            return Err(TransitionProposalError::Expired);
        }

        // Durable CAS: created -> accepted.
        let proposal_id_str = hex16(&proposal_id);
        let applied = if accepted_scope == GuidanceProposalAcceptedScope::Persistent {
            self.db
                .accept_persistent_guidance_proposal(
                    &proposal_id_str,
                    &hex32(&scope.project_digest),
                    &hex32(&scope.provider_digest),
                    &hex32(&scope.model_digest),
                    proposal
                        .rules
                        .iter()
                        .map(ComputerGuidanceRuleV1::encode)
                        .collect(),
                    now_unix_ms,
                )
                .await
                .map_err(|e| TransitionProposalError::Storage(e.to_string()))?
        } else {
            self.db
                .cas_guidance_proposal_receipt_state(
                    &proposal_id_str,
                    GuidanceProposalReceiptState::Created,
                    GuidanceProposalReceiptState::Accepted,
                    Some(accepted_scope),
                    Some(now_unix_ms),
                )
                .await
                .map_err(|e| TransitionProposalError::Storage(e.to_string()))?
        };
        if !applied {
            return Err(TransitionProposalError::CasConflict {
                expected: GuidanceProposalReceiptState::Created,
            });
        }

        // Build terminal audit metadata from the creation receipt, preserving
        // the generation and rule-kind bitset stamped at proposal creation.
        let receipt = self
            .db
            .guidance_proposal_receipt(&proposal_id_str)
            .await
            .map_err(|e| TransitionProposalError::Storage(e.to_string()))?
            .ok_or(TransitionProposalError::NotFound)?;

        let rules = proposal.rules.clone();
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
            config_generation: receipt.config_generation as u64,
            rule_kind_bits: receipt.rule_kind_bits as u16,
            disposition: Some(disp),
            scope: Some(gscope),
        };
        let audit_error = if !self.audit.delivers_immediately() {
            None
        } else {
            match self.audit.append(&audit_event) {
                Ok(()) => {
                    if let Err(error) = self
                        .db
                        .mark_guidance_proposal_audit_delivered(
                            &proposal_id_str,
                            GuidanceProposalReceiptState::Accepted,
                            now_unix_ms,
                        )
                        .await
                    {
                        tracing::warn!(%error, "guidance accepted audit delivery mark remains retryable");
                    }
                    None
                }
                Err(error) => Some(error.to_string()),
            }
        };

        // Install the accepted rules into the accepted-rules store.
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
        if let Some(error) = audit_error {
            tracing::warn!(%error, proposal_id = %proposal_id_str, "accepted guidance audit delivery deferred to durable outbox");
        }
        Ok(rules)
    }

    /// Reject a pending proposal (AC8).
    pub async fn reject(
        &mut self,
        scope: &ProposalScopeKey,
        proposal_id: [u8; 16],
        now_unix_ms: i64,
    ) -> Result<(), TransitionProposalError> {
        if !self.audit.is_available() {
            return Err(TransitionProposalError::AuditUnavailable(
                "computer guidance audit writer is not installed".to_string(),
            ));
        }
        let pid = ProposalId(proposal_id);
        // Bind the caller's proposal capability to the exact pending scope.
        let proposal = self
            .pending
            .get(scope)
            .ok_or(TransitionProposalError::NotFound)?
            .clone();
        if proposal.proposal_id != pid {
            return Err(TransitionProposalError::NotFound);
        }
        if proposal.is_expired_at(now_unix_ms) {
            self.expire_candidate(
                &super::lifecycle::ProposalCandidate {
                    key: scope.clone(),
                    proposal_id: pid,
                },
                now_unix_ms,
            )
            .await?;
            return Err(TransitionProposalError::Expired);
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

        let receipt = self
            .db
            .guidance_proposal_receipt(&proposal_id_str)
            .await
            .map_err(|e| TransitionProposalError::Storage(e.to_string()))?
            .ok_or(TransitionProposalError::NotFound)?;
        let audit_event = GuidanceAuditEvent {
            kind: AuditEventKind::GuidanceProposalRejected,
            proposal_id,
            session_id: scope.session_id,
            delegation_id: scope.delegation_id,
            canonical_project_digest: scope.project_digest,
            provider_digest: scope.provider_digest,
            model_digest: scope.model_digest,
            config_generation: receipt.config_generation as u64,
            rule_kind_bits: receipt.rule_kind_bits as u16,
            disposition: Some(Disposition::Rejected),
            scope: None,
        };
        let audit_error = if !self.audit.delivers_immediately() {
            None
        } else {
            match self.audit.append(&audit_event) {
                Ok(()) => {
                    if let Err(error) = self
                        .db
                        .mark_guidance_proposal_audit_delivered(
                            &proposal_id_str,
                            GuidanceProposalReceiptState::Rejected,
                            now_unix_ms,
                        )
                        .await
                    {
                        tracing::warn!(%error, "guidance rejected audit delivery mark remains retryable");
                    }
                    None
                }
                Err(error) => Some(error.to_string()),
            }
        };

        self.pending.remove_committed(scope, pid);
        if let Some(error) = audit_error {
            tracing::warn!(%error, proposal_id = %proposal_id_str, "rejected guidance audit delivery deferred to durable outbox");
        }
        Ok(())
    }

    /// Enumerate expired pending proposals (injected clock) without mutating.
    /// The caller (coordinator tick) commits each durable expiry CAS + audit,
    /// then [`Self::remove_expired`] drops memory (AC5).
    pub fn expired_candidates(&self, now_unix_ms: i64) -> Vec<super::lifecycle::ProposalCandidate> {
        self.pending.expired_candidates(now_unix_ms)
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
        let session =
            self.accepted
                .session_rules(session_id, project_digest, provider_digest, model_digest);
        let persistent =
            self.accepted
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
    pub async fn delegation_counter(&self, delegation_id: &[u8; 16]) -> Result<i64, anyhow::Error> {
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
        if !self.audit.is_available() {
            return Err(TransitionProposalError::AuditUnavailable(
                "computer guidance audit writer is not installed".to_string(),
            ));
        }
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
                GuidanceProposalReceiptState::Expired
                | GuidanceProposalReceiptState::ExpiredOnRestart => Some(Disposition::Expired),
                GuidanceProposalReceiptState::Accepted => match accepted_scope {
                    Some(GuidanceProposalAcceptedScope::Session) => {
                        Some(Disposition::AcceptedSession)
                    }
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
        if self.audit.delivers_immediately() && self.audit.append(&event).is_ok() {
            if let Err(error) = self
                .db
                .mark_guidance_proposal_audit_delivered(proposal_id_str, to, now_unix_ms)
                .await
            {
                tracing::warn!(%error, "guidance terminal audit delivery mark remains retryable");
            }
        }
        // An append failure is recoverable from the durable outbox and must
        // not retain typed/rationale memory after the terminal CAS.
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

    struct RecordingAuditWriter;

    impl GuidanceAuditWriter for RecordingAuditWriter {
        fn append(&self, _event: &GuidanceAuditEvent) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct FailingAuditWriter;

    impl GuidanceAuditWriter for FailingAuditWriter {
        fn append(&self, _event: &GuidanceAuditEvent) -> anyhow::Result<()> {
            anyhow::bail!("audit transport failed")
        }
    }

    fn fresh_service() -> GuidanceProposalService {
        GuidanceProposalService::with_audit_writer(
            Arc::new(Db::open_in_memory().unwrap()),
            Arc::new(RecordingAuditWriter),
        )
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

    fn snapshot(
        svc: &GuidanceProposalService,
        providers: &crate::config::providers::ProvidersConfig,
        model: &str,
        project: &[u8],
    ) -> GuidanceCreateSnapshot {
        svc.resolve_create_snapshot(providers, None, None, 1, "p", model, project)
    }

    #[tokio::test]
    async fn create_denied_when_disabled_with_zero_side_effects() {
        let mut svc = fresh_service();
        let create = snapshot(&svc, &providers_disabled(), "m", b"project");
        let err = svc
            .create_proposal(create, id16(1), id16(2), id16(9), vec![rule()], None, 1000)
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
        let create = snapshot(&svc, &providers_enabled(), "m", b"project");
        svc.create_proposal(
            create,
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
    async fn create_rolls_back_receipt_counters_outbox_and_reservation_when_audit_append_fails() {
        let db = Arc::new(Db::open_in_memory().unwrap());
        let mut svc =
            GuidanceProposalService::with_audit_writer(db.clone(), Arc::new(FailingAuditWriter));
        let err = svc
            .create_proposal(
                snapshot(&svc, &providers_enabled(), "m", b"project"),
                id16(1),
                id16(2),
                id16(9),
                vec![rule()],
                None,
                1000,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, CreateProposalError::AuditUnavailable(_)));
        assert!(svc.pending_store().is_empty());
        assert_eq!(svc.session_counter(&id16(1)).await.unwrap(), 0);
        assert_eq!(svc.delegation_counter(&id16(2)).await.unwrap(), 0);
        assert!(
            db.guidance_proposal_receipt(&hex16(&id16(9)))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.pending_guidance_proposal_audits()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn fourth_delegation_create_rejected_with_zero_side_effects() {
        let mut svc = fresh_service();
        for n in 1..=3u8 {
            let model = format!("m{n}");
            let create = snapshot(&svc, &providers_enabled(), &model, b"project");
            svc.create_proposal(
                create,
                id16(1),
                id16(2),
                id16(n),
                vec![rule()],
                None,
                1000 + n as i64,
            )
            .await
            .unwrap();
        }
        let create = snapshot(&svc, &providers_enabled(), "m", b"project");
        let err = svc
            .create_proposal(create, id16(1), id16(2), id16(10), vec![rule()], None, 2000)
            .await
            .unwrap_err();
        assert!(matches!(err, CreateProposalError::CapExceeded(_)));
        // Zero side effects for the rejected 4th.
        assert_eq!(svc.pending_store().len(), 3);
        assert_eq!(svc.delegation_counter(&id16(2)).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn expiry_drops_memory_and_cas_receipt() {
        let mut svc = fresh_service();
        let create = snapshot(&svc, &providers_enabled(), "m", b"project");
        svc.create_proposal(
            create,
            id16(1),
            id16(2),
            id16(9),
            vec![rule()],
            Some("r".into()),
            0,
        )
        .await
        .unwrap();
        // Creation and deadline are both Unix milliseconds.
        let due = svc.expired_candidates(600_000);
        assert_eq!(due.len(), 1);
        svc.expire_candidate(&due[0], 600_000).await.unwrap();
        assert!(svc.pending_store().is_empty());
    }

    #[tokio::test]
    async fn millisecond_creation_time_does_not_expire_on_immediate_accept() {
        let mut svc = fresh_service();
        let create = snapshot(&svc, &providers_enabled(), "m", b"project");
        let scope = ProposalScopeKey {
            session_id: id16(1),
            delegation_id: id16(2),
            project_digest: create.project_digest,
            provider_digest: create.provider_digest,
            model_digest: create.model_digest,
        };
        svc.create_proposal(
            create,
            id16(1),
            id16(2),
            id16(9),
            vec![rule()],
            None,
            1_700_000_000_000,
        )
        .await
        .unwrap();

        svc.accept_session(&scope, id16(9), 1_700_000_000_001)
            .await
            .unwrap();
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
        let create = snapshot(&svc, &providers_enabled(), "m", b"proj");
        svc.create_proposal(
            create,
            id16(1),
            id16(2),
            id16(9),
            vec![ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 2 }],
            None,
            1000,
        )
        .await
        .unwrap();
        let accepted = svc
            .accept_session(&scope_session, id16(9), 2000)
            .await
            .unwrap();
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
        let create = snapshot(&svc, &providers_enabled(), "m", b"proj");
        svc.create_proposal(
            create,
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

    #[test]
    fn compiler_keeps_the_session_project_scope_when_child_cwd_changes() {
        let svc = fresh_service();
        let session_id = id16(1);
        let project = canonical_project_digest(b"session-project");
        let provider = provider_digest("p");
        let model = model_digest("p", "m");
        svc.accepted.install_session(
            SessionRuleKey {
                session_id,
                project_digest: project,
                provider_digest: provider,
                model_digest: model,
            },
            vec![rule()],
        );

        let compiled = svc.compiler(session_id, project).compile(
            std::path::Path::new("session-project/child"),
            "p",
            "m",
        );
        assert!(!compiled.is_empty());
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
        let mut svc = GuidanceProposalService::with_audit_writer(
            db.clone(),
            Arc::new(Recording(recorded.clone())),
        );
        let create = snapshot(&svc, &providers_enabled(), "m", b"proj");
        svc.create_proposal(create, id16(1), id16(2), id16(9), vec![rule()], None, 1000)
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
        assert!(
            kinds
                .iter()
                .any(|k| *k == AuditEventKind::GuidanceProposalCreated)
        );
        assert_eq!(
            kinds
                .iter()
                .filter(|k| **k == AuditEventKind::GuidanceProposalExpired)
                .count(),
            1
        );
        // No counter re-increment.
        assert_eq!(svc2.delegation_counter(&id16(2)).await.unwrap(), 1);
    }
}
