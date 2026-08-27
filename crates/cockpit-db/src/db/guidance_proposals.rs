//! Durable guidance-proposal receipts and creation counters (issue #59).
//!
//! The durable half of the user-reviewed typed computer-use guidance proposal
//! lifecycle: content-free receipts + per-session/per-delegation creation
//! counters. Typed rule values and the optional rationale live **only** in
//! daemon memory ([`cockpit_core::computer::guidance::lifecycle`]); this
//! module never persists them.
//!
//! # Create path (one transaction)
//!
//! [`Db::insert_guidance_proposal_receipt`] atomically: reads the session and
//! delegation counters, rejects if either cap would be exceeded, inserts the
//! content-free receipt in state `created`, and increments both counters. A
//! duplicate `proposal_id` is an idempotent-safe error (the caller releases
//! its memory reservation). Accepted/rejected/expired receipts remain
//! counted — creation consumed quota, so counters are monotonic and never
//! decremented.
//!
//! # Transitions
//!
//! [`Db::cas_guidance_proposal_receipt_state`] is an id-conditional
//! compare-and-swap: it advances `state` only when the current row matches
//! `from_state`, setting `accepted_scope` (session | persistent) only on a
//! transition to `accepted`. A CAS that does not match (e.g. accept after
//! expiry) returns `Ok(false)` — the caller treats that as a stable conflict
//! and performs no memory drop or rule install.
//!
//! # Startup reconciliation
//!
//! [`Db::list_stale_created_guidance_proposal_receipts`] enumerates every
//! receipt still `created` after a daemon restart. Their memory-only values
//! are unrecoverable, so the orchestrator CASes each to `expired_on_restart`
//! and appends exactly one `guidance_proposal_expired` audit event — without
//! re-incrementing counters (creation already counted).

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};

use crate::db::Db;

// ---------------------------------------------------------------------------
// Caps (mirror cockpit_core::computer::guidance constants)
// ---------------------------------------------------------------------------

/// The maximum number of proposals per delegation.
pub const MAX_PROPOSALS_PER_DELEGATION: i64 = 3;

/// The maximum number of proposals per session.
pub const MAX_PROPOSALS_PER_SESSION: i64 = 10;

// ---------------------------------------------------------------------------
// Receipt state
// ---------------------------------------------------------------------------

/// The terminal/lifecycle state of a guidance-proposal receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuidanceProposalReceiptState {
    Created,
    Accepted,
    Rejected,
    Expired,
    ExpiredOnRestart,
}

impl GuidanceProposalReceiptState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::ExpiredOnRestart => "expired_on_restart",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "created" => Some(Self::Created),
            "accepted" => Some(Self::Accepted),
            "rejected" => Some(Self::Rejected),
            "expired" => Some(Self::Expired),
            "expired_on_restart" => Some(Self::ExpiredOnRestart),
            _ => None,
        }
    }
}

/// The accepted scope recorded on an `accepted` receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuidanceProposalAcceptedScope {
    Session,
    Persistent,
}

impl GuidanceProposalAcceptedScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Persistent => "persistent",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "session" => Some(Self::Session),
            "persistent" => Some(Self::Persistent),
            _ => None,
        }
    }
}

/// The scope kind for a creation counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuidanceProposalCounterScope {
    Session,
    Delegation,
}

impl GuidanceProposalCounterScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Delegation => "delegation",
        }
    }
}

// ---------------------------------------------------------------------------
// Receipt row
// ---------------------------------------------------------------------------

/// A content-free guidance-proposal receipt row. Holds IDs, three opaque
/// scope digests (64-char lowercase hex), the config generation, the
/// rule-kind bitmask, timestamps, and the terminal state — never typed rule
/// values or rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuidanceProposalReceiptRow {
    pub proposal_id: String,
    pub session_id: String,
    pub delegation_id: String,
    pub canonical_project_digest: String,
    pub provider_digest: String,
    pub model_digest: String,
    pub config_generation: i64,
    pub rule_kind_bits: i64,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub state: GuidanceProposalReceiptState,
    pub accepted_scope: Option<GuidanceProposalAcceptedScope>,
    pub transitioned_at_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingGuidanceAuditRow {
    pub receipt: GuidanceProposalReceiptRow,
    pub event_state: GuidanceProposalReceiptState,
    pub event_accepted_scope: Option<GuidanceProposalAcceptedScope>,
    pub transitioned_at_unix_ms: i64,
}

fn parse_receipt_row(row: &rusqlite::Row<'_>) -> Result<GuidanceProposalReceiptRow> {
    let state_str: String = row.get("state")?;
    let state = GuidanceProposalReceiptState::from_str(&state_str)
        .context("guidance_proposal_receipts row has unknown state")?;
    let accepted_scope_str: Option<String> = row.get("accepted_scope")?;
    let accepted_scope = accepted_scope_str
        .as_deref()
        .map(GuidanceProposalAcceptedScope::from_str)
        .transpose()
        .context("guidance_proposal_receipts row has unknown accepted_scope")?;
    Ok(GuidanceProposalReceiptRow {
        proposal_id: row.get("proposal_id")?,
        session_id: row.get("session_id")?,
        delegation_id: row.get("delegation_id")?,
        canonical_project_digest: row.get("canonical_project_digest")?,
        provider_digest: row.get("provider_digest")?,
        model_digest: row.get("model_digest")?,
        config_generation: row.get("config_generation")?,
        rule_kind_bits: row.get("rule_kind_bits")?,
        created_at_unix_ms: row.get("created_at_unix_ms")?,
        expires_at_unix_ms: row.get("expires_at_unix_ms")?,
        state,
        accepted_scope,
        transitioned_at_unix_ms: row.get("transitioned_at_unix_ms")?,
    })
}

// ---------------------------------------------------------------------------
// Create-path errors
// ---------------------------------------------------------------------------

/// Errors from the transactional receipt-insert + counter-increment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CreateReceiptError {
    /// The delegation cap (3) would be exceeded.
    #[error("guidance proposal delegation cap exceeded: {0}/{MAX_PROPOSALS_PER_DELEGATION}")]
    DelegationCapExceeded(i64),
    /// The session cap (10) would be exceeded.
    #[error("guidance proposal session cap exceeded: {0}/{MAX_PROPOSALS_PER_SESSION}")]
    SessionCapExceeded(i64),
    /// A receipt with this proposal_id already exists (idempotent-safe).
    #[error("guidance proposal receipt already exists: {0}")]
    DuplicateProposalId(String),
    /// A storage or caller-contract failure (validation or DB error).
    #[error("guidance proposal create storage failure: {0}")]
    Storage(String),
}

/// Arguments for a content-free receipt insert.
#[derive(Debug, Clone)]
pub struct GuidanceProposalReceiptInsert<'a> {
    pub proposal_id: &'a str,
    pub session_id: &'a str,
    pub delegation_id: &'a str,
    pub canonical_project_digest: &'a str,
    pub provider_digest: &'a str,
    pub model_digest: &'a str,
    pub config_generation: i64,
    pub rule_kind_bits: i64,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Debug, Clone)]
struct OwnedGuidanceProposalReceiptInsert {
    proposal_id: String,
    session_id: String,
    delegation_id: String,
    canonical_project_digest: String,
    provider_digest: String,
    model_digest: String,
    config_generation: i64,
    rule_kind_bits: i64,
    created_at_unix_ms: i64,
    expires_at_unix_ms: i64,
}

fn validate_hex64(s: &str, field: &str) -> Result<()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || s != s.to_ascii_lowercase()
    {
        anyhow::bail!("guidance proposal {field} must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_hex16(s: &str, field: &str) -> Result<()> {
    if s.len() != 32
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || s != s.to_ascii_lowercase()
    {
        anyhow::bail!("guidance proposal {field} must be 32 lowercase hexadecimal characters");
    }
    Ok(())
}

impl Db {
    /// Atomically accept a proposal persistently, upsert every closed encoded
    /// rule, and enqueue the accepted audit event. No accepted receipt can be
    /// committed without its machine-local rules.
    pub async fn accept_persistent_guidance_proposal(
        &self,
        proposal_id: &str,
        project_digest: &str,
        provider_digest: &str,
        model_digest: &str,
        encoded_rules: Vec<[u8; 3]>,
        transitioned_at_unix_ms: i64,
    ) -> Result<bool> {
        validate_hex64(project_digest, "canonical_project_digest")?;
        validate_hex64(provider_digest, "provider_digest")?;
        validate_hex64(model_digest, "model_digest")?;
        let proposal_id = proposal_id.to_string();
        let project_digest = project_digest.to_string();
        let provider_digest = provider_digest.to_string();
        let model_digest = model_digest.to_string();
        self.transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE guidance_proposal_receipts
                 SET state = 'accepted', accepted_scope = 'persistent', transitioned_at_unix_ms = ?1
                 WHERE proposal_id = ?2 AND state = 'created'",
                params![transitioned_at_unix_ms, proposal_id],
            )?;
            if changed == 0 {
                return Ok(false);
            }
            for encoded in encoded_rules {
                conn.execute(
                    "INSERT INTO accepted_persistent_guidance_rules
                         (canonical_project_digest, provider_digest, model_digest, rule_kind, encoded_rule, updated_at_unix_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(canonical_project_digest, provider_digest, model_digest, rule_kind)
                     DO UPDATE SET encoded_rule = excluded.encoded_rule, updated_at_unix_ms = excluded.updated_at_unix_ms",
                    params![project_digest, provider_digest, model_digest, i64::from(encoded[1]), encoded.to_vec(), transitioned_at_unix_ms],
                )?;
            }
            conn.execute(
                "INSERT INTO guidance_proposal_audit_outbox
                     (proposal_id, terminal_state, accepted_scope, transitioned_at_unix_ms)
                 VALUES (?1, 'accepted', 'persistent', ?2)
                 ON CONFLICT(proposal_id, terminal_state) DO NOTHING",
                params![proposal_id, transitioned_at_unix_ms],
            )?;
            Ok(true)
        }).await
    }

    /// Atomically insert a content-free `created` receipt and increment the
    /// session + delegation creation counters, enforcing the 3/10 caps.
    /// On any failure (cap exceeded or duplicate id) the transaction rolls
    /// back: zero receipt, zero counter increment, zero audit append (the
    /// caller performs audit append only after this commits).
    pub async fn insert_guidance_proposal_receipt(
        &self,
        insert: GuidanceProposalReceiptInsert<'_>,
    ) -> Result<(), CreateReceiptError> {
        // Validate opaque identifiers before crossing into the writer thread.
        validate_hex16(insert.proposal_id, "proposal_id")
            .map_err(|e| CreateReceiptError::Storage(e.to_string()))?;
        // The session/delegation ids are opaque strings here; the CHECK
        // constraints enforce their length bounds.
        validate_hex64(insert.canonical_project_digest, "canonical_project_digest")
            .map_err(|e| CreateReceiptError::Storage(e.to_string()))?;
        validate_hex64(insert.provider_digest, "provider_digest")
            .map_err(|e| CreateReceiptError::Storage(e.to_string()))?;
        validate_hex64(insert.model_digest, "model_digest")
            .map_err(|e| CreateReceiptError::Storage(e.to_string()))?;
        if !(1..=63).contains(&insert.rule_kind_bits) {
            return Err(CreateReceiptError::Storage(format!(
                "rule_kind_bits must be 1..=63, got {}",
                insert.rule_kind_bits
            )));
        }
        if insert.expires_at_unix_ms < insert.created_at_unix_ms {
            return Err(CreateReceiptError::Storage(
                "expires_at_unix_ms must be >= created_at_unix_ms".to_string(),
            ));
        }

        let insert = OwnedGuidanceProposalReceiptInsert {
            proposal_id: insert.proposal_id.to_string(),
            session_id: insert.session_id.to_string(),
            delegation_id: insert.delegation_id.to_string(),
            canonical_project_digest: insert.canonical_project_digest.to_string(),
            provider_digest: insert.provider_digest.to_string(),
            model_digest: insert.model_digest.to_string(),
            config_generation: insert.config_generation,
            rule_kind_bits: insert.rule_kind_bits,
            created_at_unix_ms: insert.created_at_unix_ms,
            expires_at_unix_ms: insert.expires_at_unix_ms,
        };
        self.transaction(move |conn| {
            // Duplicate proposal_id — idempotent-safe conflict.
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM guidance_proposal_receipts WHERE proposal_id = ?1)",
                    [&insert.proposal_id],
                    |row| row.get(0),
                )
                .context("checking existing guidance proposal receipt")?;
            if exists {
                return Err(CreateReceiptError::DuplicateProposalId(
                    insert.proposal_id.clone(),
                )
                .into());
            }

            // Read current counters (0 when absent).
            let delegation_count: i64 = conn
                .query_row(
                    "SELECT count FROM guidance_proposal_counters
                     WHERE scope_kind = 'delegation' AND scope_id = ?1",
                    [&insert.delegation_id],
                    |row| row.get(0),
                )
                .optional()
                .context("reading delegation counter")?
                .unwrap_or(0);
            if delegation_count >= MAX_PROPOSALS_PER_DELEGATION {
                return Err(CreateReceiptError::DelegationCapExceeded(delegation_count).into());
            }
            let session_count: i64 = conn
                .query_row(
                    "SELECT count FROM guidance_proposal_counters
                     WHERE scope_kind = 'session' AND scope_id = ?1",
                    [&insert.session_id],
                    |row| row.get(0),
                )
                .optional()
                .context("reading session counter")?
                .unwrap_or(0);
            if session_count >= MAX_PROPOSALS_PER_SESSION {
                return Err(CreateReceiptError::SessionCapExceeded(session_count).into());
            }

            // Insert the content-free receipt.
            conn.execute(
                "INSERT INTO guidance_proposal_receipts
                     (proposal_id, session_id, delegation_id,
                      canonical_project_digest, provider_digest, model_digest,
                      config_generation, rule_kind_bits,
                      created_at_unix_ms, expires_at_unix_ms, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'created')",
                params![
                    insert.proposal_id,
                    insert.session_id,
                    insert.delegation_id,
                    insert.canonical_project_digest,
                    insert.provider_digest,
                    insert.model_digest,
                    insert.config_generation,
                    insert.rule_kind_bits,
                    insert.created_at_unix_ms,
                    insert.expires_at_unix_ms,
                ],
            )
            .context("inserting guidance proposal receipt")?;

            // Increment both counters (upsert).
            conn.execute(
                "INSERT INTO guidance_proposal_counters (scope_kind, scope_id, count)
                 VALUES ('delegation', ?1, 1)
                 ON CONFLICT(scope_kind, scope_id) DO UPDATE SET count = count + 1",
                [&insert.delegation_id],
            )
            .context("incrementing delegation counter")?;
            conn.execute(
                "INSERT INTO guidance_proposal_counters (scope_kind, scope_id, count)
                 VALUES ('session', ?1, 1)
                 ON CONFLICT(scope_kind, scope_id) DO UPDATE SET count = count + 1",
                [&insert.session_id],
            )
            .context("incrementing session counter")?;
            conn.execute(
                "INSERT INTO guidance_proposal_audit_outbox
                     (proposal_id, terminal_state, accepted_scope, transitioned_at_unix_ms)
                 VALUES (?1, 'created', NULL, ?2)",
                params![insert.proposal_id, insert.created_at_unix_ms],
            )
            .context("enqueueing guidance proposal created audit event")?;
            Ok(())
        })
        .await
        .map_err(|e| match e.downcast::<CreateReceiptError>() {
            Ok(typed) => typed,
            Err(other) => CreateReceiptError::Storage(other.to_string()),
        })
    }

    /// Roll back a just-created receipt when the mandatory audit append fails.
    /// The delete and both counter decrements are one transaction and only
    /// apply while the receipt is still `created`.
    pub async fn rollback_created_guidance_proposal_receipt(
        &self,
        proposal_id: &str,
    ) -> Result<bool> {
        let proposal_id = proposal_id.to_string();
        self.transaction(move |conn| {
            let scopes = conn
                .query_row(
                    "SELECT session_id, delegation_id
                     FROM guidance_proposal_receipts
                     WHERE proposal_id = ?1 AND state = 'created'",
                    [&proposal_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .context("reading guidance proposal scopes for rollback")?;
            let Some((session_id, delegation_id)) = scopes else {
                return Ok(false);
            };
            conn.execute(
                "DELETE FROM guidance_proposal_receipts
                 WHERE proposal_id = ?1 AND state = 'created'",
                [&proposal_id],
            )
            .context("rolling back unaudited guidance proposal receipt")?;
            conn.execute(
                "UPDATE guidance_proposal_counters SET count = count - 1
                 WHERE scope_kind = 'session' AND scope_id = ?1 AND count > 0",
                [&session_id],
            )
            .context("rolling back guidance session counter")?;
            conn.execute(
                "UPDATE guidance_proposal_counters SET count = count - 1
                 WHERE scope_kind = 'delegation' AND scope_id = ?1 AND count > 0",
                [&delegation_id],
            )
            .context("rolling back guidance delegation counter")?;
            Ok(true)
        })
        .await
    }

    /// Compare-and-swap a receipt's state. Returns `Ok(true)` when the
    /// transition matched `from_state` and was applied, `Ok(false)` when the
    /// current state did not match (stable conflict — e.g. accept after
    /// expiry). `accepted_scope` is set only on a transition to `accepted`
    /// and must be `None` otherwise. `transitioned_at_unix_ms` stamps the
    /// transition time (defaults to now when `None`).
    pub async fn cas_guidance_proposal_receipt_state(
        &self,
        proposal_id: &str,
        from_state: GuidanceProposalReceiptState,
        to_state: GuidanceProposalReceiptState,
        accepted_scope: Option<GuidanceProposalAcceptedScope>,
        transitioned_at_unix_ms: Option<i64>,
    ) -> Result<bool> {
        // Invariant: accepted_scope is non-None only on a transition to
        // accepted.
        if to_state == GuidanceProposalReceiptState::Accepted && accepted_scope.is_none() {
            anyhow::bail!("accepted_scope must be set when transitioning to accepted");
        }
        if to_state != GuidanceProposalReceiptState::Accepted && accepted_scope.is_some() {
            anyhow::bail!("accepted_scope must be None unless transitioning to accepted");
        }

        let proposal_id = proposal_id.to_string();
        let to_state_str = to_state.as_str().to_string();
        let from_state_str = from_state.as_str().to_string();
        let accepted_scope_str = accepted_scope.map(|s| s.as_str().to_string());
        let transitioned_at =
            transitioned_at_unix_ms.unwrap_or_else(|| Utc::now().timestamp_millis());
        self.transaction(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE guidance_proposal_receipts
                 SET state = ?1,
                     accepted_scope = ?2,
                     transitioned_at_unix_ms = ?3
                 WHERE proposal_id = ?4 AND state = ?5",
                    params![
                        to_state_str,
                        accepted_scope_str,
                        transitioned_at,
                        proposal_id,
                        from_state_str,
                    ],
                )
                .context("CAS guidance proposal receipt state")?;
            if changed == 1 && to_state_str != "created" {
                conn.execute(
                    "INSERT INTO guidance_proposal_audit_outbox
                         (proposal_id, terminal_state, accepted_scope, transitioned_at_unix_ms)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(proposal_id, terminal_state) DO NOTHING",
                    params![
                        proposal_id,
                        to_state_str,
                        accepted_scope_str,
                        transitioned_at
                    ],
                )
                .context("enqueueing guidance proposal audit event")?;
            }
            Ok(changed == 1)
        })
        .await
    }

    /// Mark the durable terminal audit event delivered after the append
    /// succeeds.  A crash before this call leaves a retryable outbox row.
    pub async fn mark_guidance_proposal_audit_delivered(
        &self,
        proposal_id: &str,
        terminal_state: GuidanceProposalReceiptState,
        delivered_at_unix_ms: i64,
    ) -> Result<()> {
        let proposal_id = proposal_id.to_string();
        let terminal_state = terminal_state.as_str().to_string();
        self.write(move |conn| {
            let changed = conn.execute(
                "UPDATE guidance_proposal_audit_outbox
                 SET delivered_at_unix_ms = COALESCE(delivered_at_unix_ms, ?1)
                 WHERE proposal_id = ?2 AND terminal_state = ?3",
                params![delivered_at_unix_ms, proposal_id, terminal_state],
            )?;
            anyhow::ensure!(changed == 1, "guidance proposal audit outbox row missing");
            Ok(())
        })
        .await
    }

    /// Undelivered audit events in stable creation/transition order. Joining
    /// the receipt supplies the original safe metadata required to reconstruct
    /// the event after a crash.
    pub async fn pending_guidance_proposal_audits(&self) -> Result<Vec<PendingGuidanceAuditRow>> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT r.proposal_id, r.session_id, r.delegation_id,
                        r.canonical_project_digest, r.provider_digest, r.model_digest,
                        r.config_generation, r.rule_kind_bits, r.created_at_unix_ms,
                        r.expires_at_unix_ms, r.state, r.accepted_scope,
                        r.transitioned_at_unix_ms,
                        o.terminal_state AS outbox_state,
                        o.accepted_scope AS outbox_accepted_scope,
                        o.transitioned_at_unix_ms AS outbox_transitioned_at
                 FROM guidance_proposal_audit_outbox o
                 JOIN guidance_proposal_receipts r USING (proposal_id)
                 WHERE o.delivered_at_unix_ms IS NULL
                 ORDER BY o.transitioned_at_unix_ms, o.proposal_id",
            )?;
            let rows = stmt
                .query_and_then([], |row| {
                    let receipt = parse_receipt_row(row)?;
                    let state: String = row.get("outbox_state")?;
                    let event_state = GuidanceProposalReceiptState::from_str(&state)
                        .context("guidance audit outbox has unknown state")?;
                    let scope: Option<String> = row.get("outbox_accepted_scope")?;
                    let event_accepted_scope = scope
                        .as_deref()
                        .map(GuidanceProposalAcceptedScope::from_str)
                        .transpose()
                        .context("guidance audit outbox has unknown accepted scope")?;
                    Ok(PendingGuidanceAuditRow {
                        receipt,
                        event_state,
                        event_accepted_scope,
                        transitioned_at_unix_ms: row.get("outbox_transitioned_at")?,
                    })
                })?
                .collect::<Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Persist one accepted persistent rule. The caller supplies the closed
    /// three-byte encoding; this table is local-only and is never exported.
    pub async fn upsert_persistent_guidance_rule(
        &self,
        project_digest: &str,
        provider_digest: &str,
        model_digest: &str,
        encoded_rule: [u8; 3],
        updated_at_unix_ms: i64,
    ) -> Result<()> {
        validate_hex64(project_digest, "canonical_project_digest")?;
        validate_hex64(provider_digest, "provider_digest")?;
        validate_hex64(model_digest, "model_digest")?;
        let project_digest = project_digest.to_string();
        let provider_digest = provider_digest.to_string();
        let model_digest = model_digest.to_string();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO accepted_persistent_guidance_rules
                     (canonical_project_digest, provider_digest, model_digest, rule_kind, encoded_rule, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(canonical_project_digest, provider_digest, model_digest, rule_kind)
                 DO UPDATE SET encoded_rule = excluded.encoded_rule, updated_at_unix_ms = excluded.updated_at_unix_ms",
                params![project_digest, provider_digest, model_digest, i64::from(encoded_rule[1]), encoded_rule.to_vec(), updated_at_unix_ms],
            )?;
            Ok(())
        }).await
    }

    pub async fn load_persistent_guidance_rules(
        &self,
    ) -> Result<Vec<(String, String, String, [u8; 3])>> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT canonical_project_digest, provider_digest, model_digest, encoded_rule
                 FROM accepted_persistent_guidance_rules ORDER BY canonical_project_digest, provider_digest, model_digest, rule_kind"
            )?;
            let rows = stmt.query_map([], |row| {
                let bytes: Vec<u8> = row.get(3)?;
                let encoded: [u8; 3] = bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, encoded))
            })?.collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        }).await
    }

    /// Read a single receipt row by `proposal_id`, or `None` if absent.
    pub async fn guidance_proposal_receipt(
        &self,
        proposal_id: &str,
    ) -> Result<Option<GuidanceProposalReceiptRow>> {
        let proposal_id = proposal_id.to_string();
        self.read(move |conn| {
            let row = conn
                .query_row(
                    "SELECT proposal_id, session_id, delegation_id,
                            canonical_project_digest, provider_digest, model_digest,
                            config_generation, rule_kind_bits,
                            created_at_unix_ms, expires_at_unix_ms,
                            state, accepted_scope, transitioned_at_unix_ms
                     FROM guidance_proposal_receipts
                     WHERE proposal_id = ?1",
                    [&proposal_id],
                    parse_receipt_row,
                )
                .optional()
                .context("reading guidance proposal receipt")?;
            Ok(row)
        })
        .await
    }

    /// Enumerate every receipt still in state `created` (startup
    /// reconciliation). Their memory-only values are unrecoverable; the
    /// orchestrator CASes each to `expired_on_restart` and appends exactly
    /// one `guidance_proposal_expired` audit event without re-incrementing
    /// counters.
    pub async fn list_stale_created_guidance_proposal_receipts(
        &self,
    ) -> Result<Vec<GuidanceProposalReceiptRow>> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT proposal_id, session_id, delegation_id,
                        canonical_project_digest, provider_digest, model_digest,
                        config_generation, rule_kind_bits,
                        created_at_unix_ms, expires_at_unix_ms,
                        state, accepted_scope, transitioned_at_unix_ms
                 FROM guidance_proposal_receipts
                 WHERE state = 'created'
                 ORDER BY created_at_unix_ms ASC",
            )?;
            let rows = stmt
                .query_and_then([], parse_receipt_row)?
                .collect::<Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// Read the creation counter for `(scope_kind, scope_id)`, or 0 when
    /// absent. Counters are monotonic and never decremented.
    pub async fn guidance_proposal_counter(
        &self,
        scope: GuidanceProposalCounterScope,
        scope_id: &str,
    ) -> Result<i64> {
        let scope_kind = scope.as_str().to_string();
        let scope_id = scope_id.to_string();
        self.read(move |conn| {
            let count: Option<i64> = conn
                .query_row(
                    "SELECT count FROM guidance_proposal_counters
                     WHERE scope_kind = ?1 AND scope_id = ?2",
                    params![scope_kind, scope_id],
                    |row| row.get(0),
                )
                .optional()
                .context("reading guidance proposal counter")?;
            Ok(count.unwrap_or(0))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn hex16(n: u8) -> String {
        format!("{n:016x}{n:016x}")
    }
    fn hex32(n: u8) -> String {
        format!("{n:032x}{n:032x}")
    }

    fn insert<'a>(
        proposal: &'a str,
        session: &'a str,
        delegation: &'a str,
    ) -> GuidanceProposalReceiptInsert<'a> {
        GuidanceProposalReceiptInsert {
            proposal_id: proposal,
            session_id: session,
            delegation_id: delegation,
            canonical_project_digest: &hex32(1),
            provider_digest: &hex32(2),
            model_digest: &hex32(3),
            config_generation: 7,
            rule_kind_bits: 0b000001,
            created_at_unix_ms: 1000,
            expires_at_unix_ms: 1000 + 600_000,
        }
    }

    #[tokio::test]
    async fn receipt_insert_increments_counters_and_reads_back() {
        let db = Db::open_in_memory().unwrap();
        db.insert_guidance_proposal_receipt(insert(&hex16(1), "s1", "d1"))
            .await
            .unwrap();
        let row = db
            .guidance_proposal_receipt(&hex16(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, GuidanceProposalReceiptState::Created);
        assert!(row.accepted_scope.is_none());
        assert_eq!(
            db.guidance_proposal_counter(GuidanceProposalCounterScope::Session, "s1")
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            db.guidance_proposal_counter(GuidanceProposalCounterScope::Delegation, "d1")
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn receipt_insert_rejects_fourth_delegation_create_with_zero_side_effects() {
        let db = Db::open_in_memory().unwrap();
        for n in 1..=3u8 {
            db.insert_guidance_proposal_receipt(insert(&hex16(n), "s1", "d1"))
                .await
                .unwrap();
        }
        // 4th delegation create is rejected.
        let err = db
            .insert_guidance_proposal_receipt(insert(&hex16(4), "s1", "d1"))
            .await
            .unwrap_err();
        assert_eq!(err, CreateReceiptError::DelegationCapExceeded(3));
        // Zero side effects: no 4th receipt, counter unchanged.
        assert!(
            db.guidance_proposal_receipt(&hex16(4))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db.guidance_proposal_counter(GuidanceProposalCounterScope::Delegation, "d1")
                .await
                .unwrap(),
            3
        );
    }

    #[tokio::test]
    async fn receipt_insert_rejects_eleventh_session_create() {
        let db = Db::open_in_memory().unwrap();
        for n in 1..=10u8 {
            db.insert_guidance_proposal_receipt(insert(&hex16(n), "s1", &format!("d{n}")))
                .await
                .unwrap();
        }
        let err = db
            .insert_guidance_proposal_receipt(insert(&hex16(11), "s1", "d11"))
            .await
            .unwrap_err();
        assert_eq!(err, CreateReceiptError::SessionCapExceeded(10));
        assert_eq!(
            db.guidance_proposal_counter(GuidanceProposalCounterScope::Session, "s1")
                .await
                .unwrap(),
            10
        );
    }

    #[tokio::test]
    async fn cas_transitions_state_and_sets_accepted_scope_only_on_accept() {
        let db = Db::open_in_memory().unwrap();
        db.insert_guidance_proposal_receipt(insert(&hex16(1), "s1", "d1"))
            .await
            .unwrap();

        // created -> accepted (session).
        assert!(
            db.cas_guidance_proposal_receipt_state(
                &hex16(1),
                GuidanceProposalReceiptState::Created,
                GuidanceProposalReceiptState::Accepted,
                Some(GuidanceProposalAcceptedScope::Session),
                Some(2000),
            )
            .await
            .unwrap()
        );
        let row = db
            .guidance_proposal_receipt(&hex16(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, GuidanceProposalReceiptState::Accepted);
        assert_eq!(
            row.accepted_scope,
            Some(GuidanceProposalAcceptedScope::Session)
        );

        // A second CAS from `created` fails (state is now accepted).
        assert!(
            !db.cas_guidance_proposal_receipt_state(
                &hex16(1),
                GuidanceProposalReceiptState::Created,
                GuidanceProposalReceiptState::Rejected,
                None,
                None,
            )
            .await
            .unwrap()
        );
        // State unchanged.
        let row = db
            .guidance_proposal_receipt(&hex16(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, GuidanceProposalReceiptState::Accepted);
    }

    #[tokio::test]
    async fn accept_after_expiry_is_a_stable_conflict() {
        let db = Db::open_in_memory().unwrap();
        db.insert_guidance_proposal_receipt(insert(&hex16(1), "s1", "d1"))
            .await
            .unwrap();
        // Expire first.
        assert!(
            db.cas_guidance_proposal_receipt_state(
                &hex16(1),
                GuidanceProposalReceiptState::Created,
                GuidanceProposalReceiptState::Expired,
                None,
                Some(3000),
            )
            .await
            .unwrap()
        );
        // Accept after expiry: CAS from `created` fails — no rule install.
        assert!(
            !db.cas_guidance_proposal_receipt_state(
                &hex16(1),
                GuidanceProposalReceiptState::Created,
                GuidanceProposalReceiptState::Accepted,
                Some(GuidanceProposalAcceptedScope::Persistent),
                None,
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn list_stale_created_enumerates_only_created_receipts() {
        let db = Db::open_in_memory().unwrap();
        db.insert_guidance_proposal_receipt(insert(&hex16(1), "s1", "d1"))
            .await
            .unwrap();
        db.insert_guidance_proposal_receipt(insert(&hex16(2), "s1", "d2"))
            .await
            .unwrap();
        // Expire the first; the second remains created.
        db.cas_guidance_proposal_receipt_state(
            &hex16(1),
            GuidanceProposalReceiptState::Created,
            GuidanceProposalReceiptState::Expired,
            None,
            Some(2000),
        )
        .await
        .unwrap();
        let stale = db
            .list_stale_created_guidance_proposal_receipts()
            .await
            .unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].proposal_id, hex16(2));
    }

    #[tokio::test]
    async fn restart_reconcile_cas_to_expired_on_restart_without_counter_increment() {
        let db = Db::open_in_memory().unwrap();
        db.insert_guidance_proposal_receipt(insert(&hex16(1), "s1", "d1"))
            .await
            .unwrap();
        let before = db
            .guidance_proposal_counter(GuidanceProposalCounterScope::Delegation, "d1")
            .await
            .unwrap();
        assert_eq!(before, 1);

        // Reconcile: CAS created -> expired_on_restart.
        assert!(
            db.cas_guidance_proposal_receipt_state(
                &hex16(1),
                GuidanceProposalReceiptState::Created,
                GuidanceProposalReceiptState::ExpiredOnRestart,
                None,
                Some(9000),
            )
            .await
            .unwrap()
        );
        // Counter NOT re-incremented.
        let after = db
            .guidance_proposal_counter(GuidanceProposalCounterScope::Delegation, "d1")
            .await
            .unwrap();
        assert_eq!(after, 1);
        let row = db
            .guidance_proposal_receipt(&hex16(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, GuidanceProposalReceiptState::ExpiredOnRestart);
    }

    #[tokio::test]
    async fn duplicate_proposal_id_is_rejected_without_counter_increment() {
        let db = Db::open_in_memory().unwrap();
        db.insert_guidance_proposal_receipt(insert(&hex16(1), "s1", "d1"))
            .await
            .unwrap();
        let err = db
            .insert_guidance_proposal_receipt(insert(&hex16(1), "s1", "d1"))
            .await
            .unwrap_err();
        assert!(matches!(err, CreateReceiptError::DuplicateProposalId(_)));
        assert_eq!(
            db.guidance_proposal_counter(GuidanceProposalCounterScope::Delegation, "d1")
                .await
                .unwrap(),
            1
        );
    }
}
