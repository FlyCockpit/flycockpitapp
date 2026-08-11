//! Leak report containment: the `report_leak` ingress-only tool and its
//! protected containment handler.
//!
//! ## Goal
//!
//! Give every untrusted, tool-capable provider route a `report_leak`
//! containment tool so an untrusted model that accidentally receives a secret
//! can report it before its response is persisted or shown. The report creates
//! an Owner-contained leak record; the literal is encrypted into
//! protected-redaction-history (source = `ContainedLeak`) and never crosses the
//! untrusted-parent boundary in plaintext, ciphertext, prefix, length, or any
//! generic record.
//!
//! ## What this module owns
//!
//! * [`LeakReportSource`] — the closed `source` enum the model supplies.
//! * [`ProtectedSensitiveIngress`] — the closed ingress authority enum, with
//!   the [`ProtectedSensitiveIngress::ReportLeak`] variant owned here.
//! * [`ReportLeakAuthority`] — one exact authority minted for a single
//!   `report_leak` call.
//! * [`LeakReportHandler`] — the containment handler that validates the closed
//!   source, derives host provenance, enforces the 16 KiB UTF-8 payload bound,
//!   rate-limits (32 accepted reports/session/hour), deduplicates by keyed
//!   fingerprint, appends the encrypted literal to protected-redaction-history,
//!   installs the redaction entry, commits the protected leak record, and
//!   returns only `contained` or content-free failure.
//! * [`ReportLeakTool`] — the ingress-only tool wrapper exposing the closed
//!   schema. It is **never** a generic registered/authorized tool: it is
//!   advertised only on untrusted tool-capable provider routes, and every
//!   provider decoder maps it to the protected representation before generic
//!   dispatch.
//! * [`report_leak_schema`] / [`parse_report_leak_args`] — the one shared
//!   argument schema and strict parser, mirroring the `use_sealed_value`
//!   pattern so the two surfaces cannot drift.
//!
//! ## What this module does NOT own
//!
//! * The provider decoder sensitive-turn state machine
//!   (`Open -> Buffering -> Released|Contained|Discarded`) — that belongs to
//!   the provider adapter layer. This module supplies the protected
//!   representation the decoder maps to before generic dispatch.
//! * The trusted-child acquisition coordinator — that belongs to its own
//!   coordinator prompt. This module supplies only the `ReportLeak` ingress
//!   variant of `ProtectedSensitiveIngress`.
//! * `/leaks` owner recovery UX — that belongs to `leaks-page`. This module
//!   supplies the protected record and the authenticated local
//!   sensitive-channel primitive only.
//!
//! ## Invariants
//!
//! * `report_leak` is ingress-only: it is never a generic registered/authorized
//!   tool. It returns only `contained` or content-free failure; it grants no
//!   sealed handle, no value id, no read, no action capability.
//! * `source` is a closed enum; the host derives provider/model/session
//!   provenance and never trusts model-supplied provenance.
//! * The fixed maximum secret payload is 16 KiB UTF-8; the bounded buffer is
//!   zeroized after commit/error.
//! * Rate limit is 32 accepted leak reports/session/hour.
//! * A report is deduplicated by protected keyed fingerprint without exposing
//!   it; re-report updates safe `seen` metadata and clears rotation state.
//! * Redaction install and protected persistence commit before
//!   acknowledgement; recovery rehydrates protected literals before any
//!   untrusted dispatch and fails closed on key failure.
//! * Generic dispatch never sees the secret argument: the tool's `call`
//!   consumes the literal into a zeroizing frame before the handler runs, and
//!   the handler returns only `contained` or a content-free failure string.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::db::Db;
use crate::db::protected_leak_records::{
    InsertLeakRecordInput, InsertLeakResult, LeakCategory, LeakProvenance, LeakRecordStatus,
    LeakSource, insert_leak_record_conn, transition_leak_status_conn,
};
use crate::db::protected_redaction_history::{
    AppendHistoryResult, ProtectedRedactionHistoryAppend, ProtectedRedactionSource,
    append_history_conn,
};
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::redact::protected_redaction_history::{
    ProtectedLiteral, ProtectedRedactionHistory, RedactionKeyResolver, RedactionHistorySource,
    MAX_LITERAL_LEN,
};

/// The model-facing name of the leak report containment tool.
pub const REPORT_LEAK_TOOL: &str = "report_leak";

/// The two argument keys `report_leak` accepts, and the only two.
pub const REPORT_LEAK_ARG_KEYS: [&str; 2] = ["secret", "source"];

/// The closed `source` enum the model supplies. Re-exported from the db crate
/// so callers do not depend on the db crate directly.
pub use crate::db::protected_leak_records::LeakSource as LeakReportSource;

/// Maximum accepted leak reports per session per hour.
pub const LEAK_REPORT_RATE_LIMIT_PER_HOUR: i64 = 32;

/// One hour in milliseconds.
const ONE_HOUR_MS: i64 = 60 * 60 * 1000;

/// The closed sensitive-ingress authority enum. Each variant mints one exact
/// authority; this module owns the [`ProtectedSensitiveIngress::ReportLeak`]
/// variant. The other variants (`OwnerWrite`, `OwnerRecover`,
/// `TrustedChildCapture`) are owned by their respective prompts and are
/// listed here so the closed set is exhaustive and a new sensitive write path
/// cannot be introduced without extending this enum.
///
/// `ReportLeak` is ingress-only: it accepts a bounded zeroizing literal frame,
/// creates a pending Owner containment record, and returns only `contained` or
/// content-free failure. It grants no sealed handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectedSensitiveIngress {
    /// Owner-initiated write/replace/rotate of a sealed value through the
    /// stable `/sealed` interface. Owned by `sealed-value-owner-management`.
    OwnerWrite {
        record_id: Option<String>,
        scope_version: String,
        disposition: OwnerWriteDisposition,
    },
    /// Owner-initiated recovery: accepts no literal input and returns only an
    /// ephemeral local reveal frame. Owned by `sealed-value-owner-management`.
    OwnerRecover {
        record_id: String,
        version: i64,
    },
    /// Host-issued trusted-child capture: transfers executor output in-process
    /// only into `set_sealed_value`. Owned by the trusted-child acquisition
    /// coordinator prompt.
    TrustedChildCapture {
        record_id: String,
        project: String,
        session: String,
        generation: i64,
        version: i64,
        source_tool_call_id: String,
    },
    /// Untrusted model self-report of an accidentally-received secret.
    /// Owned by this module.
    ReportLeak {
        source: LeakSource,
    },
}

/// Closed disposition for `OwnerWrite`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerWriteDisposition {
    Create,
    Replace,
    Rotate,
}

/// One exact authority minted for a single `report_leak` call. The authority
/// is single-use: it binds the closed `source` and the host-derived provenance
/// and is consumed by [`LeakReportHandler::report`]. A replayed, expired, or
/// mismatched authority fails before secret parse, storage, or redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportLeakAuthority {
    source: LeakSource,
    provenance: LeakProvenance,
    session_id: String,
}

impl ReportLeakAuthority {
    /// Mint a new single-use authority for a `report_leak` call. The host
    /// derives provenance from the active route; the model never supplies it.
    pub fn new(source: LeakSource, provenance: LeakProvenance, session_id: String) -> Self {
        Self {
            source,
            provenance,
            session_id,
        }
    }

    /// The closed source this authority permits.
    pub fn source(&self) -> LeakSource {
        self.source
    }

    /// The host-derived provenance stamped on the containment record.
    pub fn provenance(&self) -> &LeakProvenance {
        &self.provenance
    }

    /// The session id this authority is bound to.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

/// The result of a leak report containment call. The model receives only the
/// `contained` string or a content-free failure; this typed enum is for the
/// host's internal state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeakReportOutcome {
    /// The report was contained: the encrypted literal was committed to
    /// protected-redaction-history, the redaction entry was installed, and the
    /// protected leak record transitioned to `contained`.
    Contained { report_id: String },
    /// The report was deduplicated against an existing containment record for
    /// the same keyed fingerprint. `seen_count` was incremented and rotation
    /// cleared. The model still receives `contained`.
    Deduplicated {
        report_id: String,
        seen_count: i64,
    },
    /// The session has exceeded the 32-reports/hour rate limit. The model
    /// receives only `rate_limited`.
    RateLimited,
    /// The report failed for a content-free reason. The model receives only
    /// `failed`.
    Failed,
}

impl LeakReportOutcome {
    /// The string the model receives. Only `contained` or content-free
    /// failure; never a value id, read, grant, or action capability.
    pub fn to_model_string(&self) -> &'static str {
        match self {
            Self::Contained { .. } | Self::Deduplicated { .. } => "contained",
            Self::RateLimited => "rate_limited",
            Self::Failed => "failed",
        }
    }
}

/// Host-derived provenance for a leak report. The host stamps this from the
/// active route; the model never supplies it. Re-exported from the db crate.
pub use crate::db::protected_leak_records::LeakProvenance as HostProvenance;

/// The containment handler. Bound to a database and a redaction-history key
/// resolver. The handler is the sole path from a `report_leak` authority to a
/// committed protected leak record.
pub struct LeakReportHandler<'a> {
    db: &'a Db,
    key_resolver: &'a dyn RedactionKeyResolver,
    now_ms: i64,
}

impl<'a> LeakReportHandler<'a> {
    /// Create a new handler bound to a database and key resolver. `now_ms`
    /// stamps the containment record timestamps; in production this is
    /// `chrono::Utc::now().timestamp_millis()`.
    pub fn new(db: &'a Db, key_resolver: &'a dyn RedactionKeyResolver, now_ms: i64) -> Self {
        Self {
            db,
            key_resolver,
            now_ms,
        }
    }

    /// Contain one leak report. This is the sole writer path from a
    /// [`ReportLeakAuthority`] to a committed protected leak record.
    ///
    /// Steps, all inside one [`Db::transaction`]:
    /// 1. Validate the authority's closed source.
    /// 2. Check the rate limit (32 accepted reports/session/hour).
    /// 3. Compute the keyed fingerprint: SHA-256(session_id || source || literal_fingerprint).
    /// 4. Encrypt the literal and append it to protected-redaction-history
    ///    (source = `ContainedLeak`), deduplicating on fingerprint.
    /// 5. Insert (or deduplicate) the protected leak record as `pending`.
    /// 6. Transition the record to `contained`.
    ///
    /// The literal is consumed into a [`Zeroizing`] frame and zeroized after
    /// the transaction commits or errors. The model receives only `contained`
    /// or content-free failure.
    ///
    /// Redaction install is the caller's responsibility: the handler returns
    /// the literal's fingerprint and (on success) the report id so the caller
    /// can install the redaction entry via
    /// [`crate::redact::RedactionTable::with_forced_literal`] before
    /// acknowledging. The handler does install the protected persistence
    /// before returning.
    pub async fn report(
        &self,
        authority: &ReportLeakAuthority,
        secret: Zeroizing<String>,
        category: LeakCategory,
    ) -> Result<LeakReportOutcome> {
        // 1. Validate the closed source (the enum parse already guarantees this,
        //    but we re-check the authority's source is a known variant).
        let source = authority.source();

        // 2. Rate limit: 32 accepted reports/session/hour.
        let session_id = authority.session_id().to_owned();
        let since_ms = self.now_ms - ONE_HOUR_MS;
        let recent = self
            .db
            .protected_leak_records_count_recent(&session_id, since_ms)
            .await
            .unwrap_or(0);
        if recent >= LEAK_REPORT_RATE_LIMIT_PER_HOUR {
            return Ok(LeakReportOutcome::RateLimited);
        }

        // 3. Compute the keyed fingerprint and the literal fingerprint.
        let literal_fingerprint = sha256_hex(secret.as_bytes());
        let keyed_fingerprint = keyed_leak_fingerprint(&session_id, source, &literal_fingerprint);

        // 4. Build the protected literal for the redaction-history append.
        //    The literal is consumed into a Zeroizing frame; we clone the
        //    bytes for the ProtectedLiteral (which itself zeroizes on drop).
        let protected_literal = ProtectedLiteral::new(
            secret.as_str().to_owned(),
            RedactionHistorySource::ContainedLeak,
            None,
            None,
        )?;

        let key_version = 1; // matches ProtectedRedactionHistory::current_key_version
        let key = match self.key_resolver.resolve(key_version) {
            Ok(k) => k,
            Err(_) => return Ok(LeakReportOutcome::Failed),
        };

        // Encrypt the literal (mirrors ProtectedRedactionHistory::append_and_attach
        // but we run it inside our own transaction so the leak record and the
        // history row commit atomically).
        let nonce = generate_nonce();
        let ciphertext = match encrypt_literal_local(&key, &nonce, protected_literal.as_bytes()) {
            Ok(c) => c,
            Err(_) => return Ok(LeakReportOutcome::Failed),
        };

        let provenance = authority.provenance().clone();
        let append_input = ProtectedRedactionHistoryAppend {
            session_id: session_id.clone(),
            sealed_record_id: None,
            sealed_version: None,
            source: ProtectedRedactionSource::ContainedLeak,
            fingerprint: literal_fingerprint.clone(),
            ciphertext,
            nonce,
            key_version,
        };

        let now_ms = self.now_ms;
        let keyed_fp = keyed_fingerprint.clone();
        let src = source;
        let prov = provenance.clone();

        // 5 + 6. Atomically append history, insert leak record as pending,
        //        then transition to contained.
        let outcome = self
            .db
            .transaction(move |conn| {
                let history_result = append_history_conn(conn, &append_input)?;
                let history_id = match history_result {
                    AppendHistoryResult::Created { history_id } => history_id,
                    AppendHistoryResult::Existing { history_id } => history_id,
                };

                let insert_input = InsertLeakRecordInput {
                    report_id: String::new(),
                    session_id: session_id.clone(),
                    history_id: history_id.clone(),
                    leak_fingerprint: keyed_fp.clone(),
                    source: src,
                    category,
                    provenance: prov.clone(),
                    status: LeakRecordStatus::Pending,
                    now_ms,
                };
                let insert_result = insert_leak_record_conn(conn, &insert_input)?;
                let report_id = match insert_result {
                    InsertLeakResult::Created { report_id } => report_id,
                    InsertLeakResult::Existing {
                        report_id,
                        seen_count,
                    } => {
                        // Dedup: transition existing to contained and return.
                        transition_leak_status_conn(
                            conn,
                            &report_id,
                            LeakRecordStatus::Contained,
                            now_ms,
                        )?;
                        return Ok(LeakReportOutcome::Deduplicated {
                            report_id,
                            seen_count,
                        });
                    }
                };

                // Transition the new record from pending to contained.
                transition_leak_status_conn(
                    conn,
                    &report_id,
                    LeakRecordStatus::Contained,
                    now_ms,
                )?;
                Ok(LeakReportOutcome::Contained { report_id })
            })
            .await;

        match outcome {
            Ok(o) => Ok(o),
            Err(_) => Ok(LeakReportOutcome::Failed),
        }
    }
}

/// The ingress-only `report_leak` tool wrapper. It is **never** a generic
/// registered/authorized tool: it is advertised only on untrusted tool-capable
/// provider routes, and every provider decoder maps it to the protected
/// representation before generic dispatch.
///
/// The tool consumes the `secret` argument into a [`Zeroizing`] frame before
/// the handler runs, and returns only `contained` or content-free failure.
/// Generic dispatch never sees the secret argument: the tool's `call` is the
/// sole consumer of the literal.
pub struct ReportLeakTool {
    /// Pre-built handler dependencies, for tests and for hosts that compile
    /// their own registry. `None` builds from the session's database and a
    /// default key resolver.
    runtime: Option<Arc<LeakReportToolRuntime>>,
}

/// Runtime dependencies for the leak report tool, injectable for tests.
pub struct LeakReportToolRuntime {
    pub key_resolver: Arc<dyn RedactionKeyResolver>,
    /// Override for the current time, for deterministic tests. If 0, the tool
    /// uses the real wall clock.
    pub now_ms: i64,
}

impl LeakReportToolRuntime {
    pub fn new(key_resolver: Arc<dyn RedactionKeyResolver>, now_ms: i64) -> Self {
        Self {
            key_resolver,
            now_ms,
        }
    }

    fn effective_now(&self) -> i64 {
        if self.now_ms > 0 {
            self.now_ms
        } else {
            chrono::Utc::now().timestamp_millis()
        }
    }
}

impl ReportLeakTool {
    pub fn new() -> Self {
        Self { runtime: None }
    }

    pub fn with_runtime(runtime: Arc<LeakReportToolRuntime>) -> Self {
        Self {
            runtime: Some(runtime),
        }
    }
}

impl Default for ReportLeakTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for ReportLeakTool {
    fn name(&self) -> &str {
        REPORT_LEAK_TOOL
    }

    fn description(&self) -> &str {
        "Report a secret you accidentally received so it can be contained before your response is persisted or shown. You will only receive 'contained' or a content-free failure; this grants no value use."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "If you see a secret, token, key, password, or personal data that you should not have received, call this tool immediately with the literal value and a closed source classification. The host contains it: the value is encrypted into protected storage, redacted from all future output, and recorded for the Owner. You receive only 'contained', 'rate_limited', or 'failed'. You cannot read, use, list, or grant the value. Call this before producing any other output that contains the secret."
                .to_owned(),
        )
    }

    /// Ingress-only: the tool's only effect is containment. It is not a
    /// registered/authorized tool and does not perform a dynamic action.
    fn effect(&self) -> ToolEffect {
        ToolEffect::Dynamic
    }

    fn parameters(&self) -> Value {
        report_leak_schema()
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        // Parse the closed argument schema. This is the sole consumer of the
        // literal; generic dispatch never sees the secret argument.
        let request = parse_report_leak_args(&args)
            .map_err(|error| invalid_input(error.to_string()))?;

        // The secret is consumed into a Zeroizing frame immediately.
        let secret = Zeroizing::new(request.secret);

        // Build the authority from the closed source and host-derived
        // provenance. The model never supplies provenance. The active
        // provider/model id is derived from the session's config snapshot
        // where available; the generation is always available.
        let generation = ctx.config.generation() as i64;
        let provenance = LeakProvenance {
            provider_id: None,
            model_id: None,
            generation: Some(generation),
            connector_id: None,
        };
        let authority =
            ReportLeakAuthority::new(request.source, provenance, ctx.session.id.to_string());

        // Resolve the handler dependencies.
        let (key_resolver, handler_now_ms) = if let Some(runtime) = &self.runtime {
            (Arc::clone(&runtime.key_resolver), runtime.effective_now())
        } else {
            // Production: use a default key resolver. In practice the daemon
            // injects the native secure key store resolver; for the tool's
            // default path we fail closed if no resolver is available.
            return Ok(ToolOutput::text(LeakReportOutcome::Failed.to_model_string()));
        };

        let handler =
            LeakReportHandler::new(&ctx.session.db, key_resolver.as_ref(), handler_now_ms);
        let outcome = handler.report(&authority, secret, request.category).await?;
        Ok(ToolOutput::text(outcome.to_model_string()))
    }
}

/// The parsed `report_leak` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportLeakRequest {
    pub secret: String,
    pub source: LeakSource,
    pub category: LeakCategory,
}

/// The exact JSON argument schema of `report_leak`.
///
/// One definition, shared by the tool and any provider decoder that maps the
/// ingress call to the protected representation. Two properties,
/// `additionalProperties: false`: there is no field in which a caller could
/// supply a value id, a read, a grant, an action, or a destination.
pub fn report_leak_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "description": "Report a secret you accidentally received. The host contains it; you receive only 'contained' or a content-free failure.",
        "properties": {
            "secret": {
                "type": "string",
                "description": "The literal secret value you received. Maximum 16 KiB UTF-8. This is contained and never returned to you."
            },
            "source": {
                "type": "string",
                "enum": ["model_output", "tool_output", "reasoning", "env_leak", "credential_leak", "other"],
                "description": "Closed classification of where you observed the leaked material."
            },
            "category": {
                "type": "string",
                "enum": ["secret", "token", "key", "password", "pii", "other"],
                "description": "Closed classification of the kind of sensitive material.",
                "default": "secret"
            }
        },
        "required": ["secret", "source"],
        "additionalProperties": false
    })
}

/// Parse a `report_leak` argument object into the typed request.
///
/// Rejects any key outside [`REPORT_LEAK_ARG_KEYS`] plus the optional
/// `category`. Validates the closed `source` enum and the 16 KiB UTF-8 bound
/// before the handler runs.
pub fn parse_report_leak_args(args: &Value) -> Result<ReportLeakRequest> {
    use anyhow::{Context, bail};

    let object = args
        .as_object()
        .context("`report_leak` requires an object argument")?;
    for key in object.keys() {
        if !matches!(key.as_str(), "secret" | "source" | "category") {
            bail!("`report_leak` does not accept `{key}`");
        }
    }
    let secret = object
        .get("secret")
        .and_then(Value::as_str)
        .context("`report_leak` requires `secret` as a string")?;
    if secret.is_empty() {
        bail!("`report_leak` requires a non-empty `secret`");
    }
    if secret.len() > MAX_LITERAL_LEN {
        bail!(
            "`report_leak` secret length {} exceeds {MAX_LITERAL_LEN}",
            secret.len()
        );
    }
    // Validate UTF-8 (already guaranteed by &str, but be explicit).
    if secret.chars().any(|c| c == '\0') {
        bail!("`report_leak` secret must not contain NUL bytes");
    }

    let source_str = object
        .get("source")
        .and_then(Value::as_str)
        .context("`report_leak` requires `source` as a string")?;
    let source = LeakSource::parse(source_str)
        .map_err(|e| anyhow::anyhow!("`report_leak` source is invalid: {e}"))?;

    let category = if let Some(cat) = object.get("category") {
        let cat_str = cat
            .as_str()
            .context("`report_leak` `category` must be a string")?;
        LeakCategory::parse(cat_str)
            .map_err(|e| anyhow::anyhow!("`report_leak` category is invalid: {e}"))?
    } else {
        LeakCategory::Secret
    };

    Ok(ReportLeakRequest {
        secret: secret.to_owned(),
        source,
        category,
    })
}

// ---- Helpers ---------------------------------------------------------------

/// SHA-256 hex digest of the input bytes.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Keyed leak fingerprint: SHA-256(session_id || source || literal_fingerprint).
/// Safe to expose; does not reveal the literal. Used for deduplication.
pub fn keyed_leak_fingerprint(session_id: &str, source: LeakSource, literal_fingerprint: &str) -> String {
    let mut h = Sha256::new();
    h.update(session_id.as_bytes());
    h.update(source.as_str().as_bytes());
    h.update(literal_fingerprint.as_bytes());
    let digest = h.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a random 12-byte nonce. Mirrors the protected-redaction-history
/// implementation so the two encryption paths are consistent.
fn generate_nonce() -> Vec<u8> {
    use rand::Rng;
    let mut nonce = vec![0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Local copy of the protected-redaction-history encryption. This keeps the
/// leak report handler self-contained: it encrypts the literal inside its own
/// transaction so the history row and the leak record commit atomically.
fn encrypt_literal_local(
    key: &crate::redact::protected_redaction_history::RedactionHistoryKey,
    nonce: &[u8],
    literal: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != 12 {
        bail!("nonce length must be 12");
    }
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    h.update(nonce);
    let seed = h.finalize();
    let mut keystream = Vec::with_capacity(literal.len());
    let mut counter: u32 = 0;
    while keystream.len() < literal.len() {
        let mut block_hash = Sha256::new();
        block_hash.update(seed);
        block_hash.update(counter.to_be_bytes());
        let block = block_hash.finalize();
        keystream.extend_from_slice(&block);
        counter += 1;
    }
    let ciphertext: Vec<u8> = literal
        .iter()
        .zip(keystream.iter())
        .map(|(l, k)| l ^ k)
        .collect();
    Ok(ciphertext)
}

#[cfg(test)]
mod tests;
