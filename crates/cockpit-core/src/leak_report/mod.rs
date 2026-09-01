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
//! * [`report_leak_schema`] / [`parse_report_leak_args`] — the one shared
//!   argument schema and strict parser, mirroring the `use_sealed_value`
//!   pattern so the two surfaces cannot drift. `report_leak` is **never** a
//!   generic registered/authorized [`crate::engine::tool::Tool`]: no type in
//!   this module implements `Tool`. The schema is advertised only on untrusted
//!   tool-capable provider routes; the provider decoder maps a decoded call to
//!   the protected representation via [`decode_and_contain_report_leak`] before
//!   any generic tool dispatch, so `Tool::call` never receives a `Value`
//!   carrying the plaintext secret.
//! * [`decode_and_contain_report_leak`] — the sole host ingress entry point.
//!   A provider decoder calls it with the raw decoded argument `Value`; it
//!   consumes the literal into a [`Zeroizing`] frame, mints the single-use
//!   [`ReportLeakAuthority`], drives [`LeakReportHandler::report`], and returns
//!   only the closed [`LeakReportOutcome`] (whose model string is `contained`,
//!   `rate_limited`, or `failed`).
//!
//! ## What this module does NOT own
//!
//! * The provider decoder sensitive-turn state machine
//!   (`Open -> Buffering -> Released|Contained|Discarded`) — that lives in
//!   [`crate::engine::agent::sensitive_turn`], which drives this module's
//!   [`decode_and_contain_report_leak`] ingress at the dispatch chokepoint. This
//!   module supplies the protected representation the barrier maps to before
//!   generic dispatch.
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
//! * Protected persistence (the AEAD history row + the leak record) commits
//!   transactionally before the outcome is returned; recovery rehydrates
//!   protected literals through the shared sole writer and fails closed on key
//!   failure. Installing the forced-literal redaction into the *live* session
//!   redaction table before acknowledgement is the responsibility of the
//!   provider Contained transition that calls this module — the sensitive-turn
//!   barrier [`crate::engine::agent::sensitive_turn`], which installs the forced
//!   literal via [`crate::engine::interrupt::InterruptHub::install_contained_leak_literal`]
//!   before the turn is acked.
//! * Generic dispatch never sees the secret argument: the decoder consumes the
//!   raw `Value` into a zeroizing frame inside [`decode_and_contain_report_leak`]
//!   before the handler runs, and the handler returns only `contained` or a
//!   content-free failure string. No type here implements
//!   [`crate::engine::tool::Tool`], so `report_leak` cannot reach the generic
//!   authorized-tool roster.

use anyhow::Result;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::db::Db;
use crate::db::protected_leak_records::{
    InsertLeakRecordInput, InsertLeakResult, LeakCategory, LeakProvenance, LeakRecordStatus,
    LeakSource, insert_leak_record_conn, transition_leak_status_conn,
};
use crate::engine::message::ToolDefinition;
use crate::redact::MIN_REDACTION_ENTRY_LENGTH;
use crate::redact::protected_redaction_history::{
    MAX_LITERAL_LEN, ProtectedLiteral, ProtectedRedactionHistory, RedactionHistorySource,
    RedactionKeyResolver, append_and_attach_conn,
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
    OwnerRecover { record_id: String, version: i64 },
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
    ReportLeak { source: LeakSource },
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
    Deduplicated { report_id: String, seen_count: i64 },
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
    /// Not all steps run inside the transaction. The async
    /// `prepare_append` — key-store resolve, subkey derivation, keyed-MAC
    /// fingerprint, pad, and AEAD encryption — runs BEFORE the transaction (it
    /// cannot touch the connection), as do source validation, the rate-limit
    /// check, and the keyed leak fingerprint. Only the connection-scoped
    /// dedup/insert/attach is inside one [`Db::transaction`], so the history
    /// row and the leak record commit together or not at all.
    ///
    /// Before the transaction:
    /// 1. Validate the authority's closed source.
    /// 2. Check the rate limit (32 accepted reports/session/hour).
    /// 3. `prepare_append`: resolve key material, derive subkeys, compute the
    ///    keyed-MAC literal fingerprint, pad, and AEAD-encrypt the literal
    ///    (source = `ContainedLeak`). Fails closed on any key-store/crypto error.
    /// 4. Derive the record's keyed leak fingerprint from the prepared literal's
    ///    keyed MAC (SHA-256(session_id || source || literal_fingerprint)).
    ///
    /// Inside the transaction:
    /// 5. Append the prepared (already-encrypted) row to
    ///    protected-redaction-history, deduplicating on fingerprint.
    /// 6. Insert (or deduplicate) the protected leak record as `pending`, then
    ///    transition it to `contained`.
    ///
    /// The literal is consumed into a [`Zeroizing`] frame and zeroized after
    /// the transaction commits or errors. The model receives only `contained`
    /// or content-free failure.
    ///
    /// This handler commits the *protected persistence* (the AEAD history row
    /// and the leak record) atomically. It does **not** install the
    /// forced-literal redaction into the live session redaction table: that
    /// happens in the provider Contained transition (the sensitive-turn barrier
    /// [`crate::engine::agent::sensitive_turn`], via
    /// [`crate::redact::RedactionTable::with_forced_literal`]) before the turn
    /// is acknowledged, so a contained secret cannot re-emit next turn.
    pub async fn report(
        &self,
        authority: &ReportLeakAuthority,
        secret: Zeroizing<String>,
        category: LeakCategory,
    ) -> Result<LeakReportOutcome> {
        // 1. Validate the closed source (the enum parse already guarantees this,
        //    but we re-check the authority's source is a known variant).
        let source = authority.source();

        // 2. Rate limit: 32 accepted reports/session/hour. This is a
        //    secret-leak containment boundary, so the count query FAILS CLOSED:
        //    a DB error is NOT treated as "zero recent reports" (which would let
        //    an attacker exceed the limit by inducing errors). On a count error
        //    we return `Failed` with no protected record, never `unwrap_or(0)`.
        let session_id = authority.session_id().to_owned();
        let since_ms = self.now_ms - ONE_HOUR_MS;
        let recent = match self
            .db
            .protected_leak_records_count_recent(&session_id, since_ms)
            .await
        {
            Ok(count) => count,
            Err(_) => return Ok(LeakReportOutcome::Failed),
        };
        if recent >= LEAK_REPORT_RATE_LIMIT_PER_HOUR {
            return Ok(LeakReportOutcome::RateLimited);
        }

        // 3. Prepare the protected append off the DB thread: load key material
        //    from the secure key store, derive subkeys, compute the keyed MAC
        //    fingerprint, pad, and AEAD-encrypt. This is the shared sole-writer
        //    crypto path — no local cipher. The literal is consumed and zeroized.
        let protected_literal = match ProtectedLiteral::from_zeroizing(
            secret,
            RedactionHistorySource::ContainedLeak,
            None,
            None,
        ) {
            Ok(l) => l,
            Err(_) => return Ok(LeakReportOutcome::Failed),
        };
        let history = ProtectedRedactionHistory::new(self.db, self.key_resolver);
        let prepared = match history.prepare_append(&session_id, protected_literal).await {
            Ok(p) => p,
            // Fail closed on any key-store / encryption failure (decision 12).
            Err(_) => return Ok(LeakReportOutcome::Failed),
        };

        // 4. The leak record's dedup fingerprint is keyed: it is derived from
        //    the prepared literal's key-store keyed MAC (`prepared.fingerprint()`),
        //    never an unkeyed SHA-256 of the literal, so the dedup index is not an
        //    offline guessing oracle. See `keyed_leak_fingerprint`.
        let keyed_fingerprint = keyed_leak_fingerprint(&session_id, source, prepared.fingerprint());

        let provenance = authority.provenance().clone();
        let now_ms = self.now_ms;
        let keyed_fp = keyed_fingerprint.clone();
        let src = source;
        let prov = provenance.clone();
        let sess = session_id.clone();

        // 5 + 6. Atomically append the encrypted history row via the shared
        //        connection-scoped sole writer, insert the leak record as
        //        pending, then transition to contained — all in one transaction
        //        so the leak record and history row commit together.
        let outcome = self
            .db
            .transaction(move |conn| {
                // The leak record references the history row by history_id; no
                // artifact refs are attached here.
                let history_id = append_and_attach_conn(conn, &prepared, &[])?;

                let insert_input = InsertLeakRecordInput {
                    report_id: String::new(),
                    session_id: sess.clone(),
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
                transition_leak_status_conn(conn, &report_id, LeakRecordStatus::Contained, now_ms)?;
                Ok(LeakReportOutcome::Contained { report_id })
            })
            .await;

        match outcome {
            Ok(o) => Ok(o),
            Err(_) => Ok(LeakReportOutcome::Failed),
        }
    }
}

/// The sole host ingress entry point for a decoded `report_leak` tool call.
///
/// `report_leak` is **never** a generic registered/authorized
/// [`crate::engine::tool::Tool`]: there is deliberately no type in this module
/// that implements `Tool`, so the closed argument object — which carries the
/// plaintext `secret` — can never reach the generic authorized-tool roster,
/// generic tool-call records, transcripts, events, or exports.
///
/// A provider sensitive-turn decoder, on classifying a buffered tool call as
/// `report_leak`, calls this function with the raw decoded argument `Value`
/// **before** any generic tool dispatch, history persistence, stream delivery,
/// audit, or export. The function:
///
/// 1. Parses the closed schema, consuming the literal directly into a
///    [`Zeroizing`] frame ([`ReportLeakRequest::secret`]); malformed args
///    yield a content-free `Failed` with **no** protected record (the turn is
///    Discarded).
/// 2. Mints the single-use [`ReportLeakAuthority`] from the closed `source` and
///    the **host-derived** provenance the decoder supplies (the model never
///    supplies provenance).
/// 3. Drives [`LeakReportHandler::report`], which fails closed on rate-limit
///    count errors and on key-store/crypto failure.
///
/// It returns only the closed [`LeakReportOutcome`]; the model ever sees only
/// its `to_model_string()` (`contained` / `rate_limited` / `failed`). Installing
/// the forced-literal redaction into the live session before acknowledgement is
/// the caller's Contained-transition responsibility (see [`LeakReportHandler`]).
pub async fn decode_and_contain_report_leak(
    db: &Db,
    key_resolver: &dyn RedactionKeyResolver,
    now_ms: i64,
    provenance: LeakProvenance,
    session_id: &str,
    args: &Value,
) -> LeakReportOutcome {
    // Parse consumes the raw `Value` into a zeroizing frame. Generic dispatch
    // never sees the secret argument: this is the only consumer of the literal.
    let request = match parse_report_leak_args(args) {
        Ok(r) => r,
        // Malformed sensitive call → Discarded: no protected record, content-free
        // failure to the model if a response is required.
        Err(_) => return LeakReportOutcome::Failed,
    };
    let authority = ReportLeakAuthority::new(request.source, provenance, session_id.to_owned());
    let handler = LeakReportHandler::new(db, key_resolver, now_ms);
    match handler
        .report(&authority, request.secret, request.category)
        .await
    {
        Ok(outcome) => outcome,
        // Any unexpected error fails closed to a content-free failure.
        Err(_) => LeakReportOutcome::Failed,
    }
}

/// The parsed `report_leak` request.
///
/// The plaintext literal is held in a [`Zeroizing`] frame so it is wiped on
/// drop, and the type deliberately does **not** derive `Clone`, `Display`, or a
/// literal-printing `Debug` — see the manual [`std::fmt::Debug`] impl — so a
/// stray copy or `{:?}` cannot defeat the containment guarantees.
#[derive(PartialEq, Eq)]
pub struct ReportLeakRequest {
    pub secret: Zeroizing<String>,
    pub source: LeakSource,
    pub category: LeakCategory,
}

impl std::fmt::Debug for ReportLeakRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `secret` is raw model-supplied plaintext; never print it. Mirror
        // `ProtectedLiteral`'s redacting Debug (`[REDACTED; len]`) so a stray
        // `{:?}` cannot defeat the zeroizing/containment guarantees (K8).
        f.debug_struct("ReportLeakRequest")
            .field("secret", &format_args!("[REDACTED; {}]", self.secret.len()))
            .field("source", &self.source)
            .field("category", &self.category)
            .finish()
    }
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
                "description": "The literal secret value you received. Between 4 bytes and 16 KiB UTF-8. This is contained and never returned to you."
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

/// The tool-level description advertised alongside [`report_leak_schema`] on an
/// eligible route. Names the containment contract so an untrusted model that
/// received a secret has a legal, non-oracular way to report it.
pub const REPORT_LEAK_TOOL_DESCRIPTION: &str = "Report a secret you accidentally received (in a tool result, the environment, \
     or your own output) so the host can contain it. Report the exact literal \
     form you received, including base64, hexadecimal, URL-encoded, and other \
     encoded, transformed, or derived forms; do not decode or normalize it. You \
     receive only 'contained' or a content-free failure; the secret is never \
     returned to you and never reaches the conversation, logs, or any record.";

/// The wire [`ToolDefinition`] for `report_leak`, advertised on eligible routes.
///
/// This is a **schema-only** advertisement: appending it to a route's wire tool
/// definitions lets an untrusted model emit a legal `report_leak` call, but
/// `report_leak` is **never** a generic registered [`crate::engine::tool::Tool`]
/// — no type implements `Tool` for it, and the sensitive-turn barrier
/// ([`crate::engine::agent::sensitive_turn::partition_sensitive_calls`])
/// intercepts any such call before generic dispatch. The name matches
/// [`REPORT_LEAK_TOOL`] so the barrier's closed
/// [`crate::engine::agent::sensitive_turn::SENSITIVE_INGRESS_TOOL_NAMES`] set
/// routes it to containment.
pub fn report_leak_tool_definition() -> ToolDefinition {
    ToolDefinition {
        name: REPORT_LEAK_TOOL.to_string(),
        description: REPORT_LEAK_TOOL_DESCRIPTION.to_string(),
        parameters: report_leak_schema(),
    }
}

/// The single eligibility funnel for the `report_leak` sensitive-turn barrier
/// (AC3, AC1's route gate).
///
/// A route advertises `report_leak` (and, correspondingly, engages the buffered
/// delivery sink so its pre-classification deltas are withheld) **iff** it is a
/// **supported, untrusted, tool-capable** completion route:
///
/// * **untrusted** (`!model_is_trusted`) — a trusted route is in the owner's own
///   custody; it neither advertises nor decodes `report_leak`, so its streaming
///   is never withheld;
/// * **tool-capable** (`!tools.is_empty()`) — a tool-disabled route offers no
///   tools at all, so `report_leak` cannot be advertised or called on it; and
/// * **supported** — every provider Cockpit dispatches (`OpenAi` / `ChatGpt` /
///   `Anthropic`) supports tool calls, so "supported" reduces to tool-capable
///   here; an unsupported/tool-disabled route has an empty `tools`.
///
/// This one predicate drives BOTH the schema-advertising append (AC3) and the
/// buffered-delivery engagement (AC1), so the two cannot drift: a route that is
/// gated for withholding is exactly a route that advertises `report_leak`, and
/// vice versa.
pub fn route_advertises_report_leak(model_is_trusted: bool, tools: &[ToolDefinition]) -> bool {
    !model_is_trusted && !tools.is_empty()
}

/// Parse a `report_leak` argument object into the typed request.
///
/// Rejects any key outside [`REPORT_LEAK_ARG_KEYS`] plus the optional
/// `category`. Validates the closed `source` enum and live-redaction-safe
/// 4-byte through 16 KiB UTF-8 bounds before the handler runs. This admission
/// check precedes protected persistence, so `contained` can only be produced
/// for a literal the live redaction table is able to install.
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
    if secret.len() < MIN_REDACTION_ENTRY_LENGTH {
        bail!(
            "`report_leak` secret length {} is below the live-redaction minimum {MIN_REDACTION_ENTRY_LENGTH}",
            secret.len()
        );
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
        // Consume the literal into a zeroizing frame immediately; no plain
        // `String` copy of the secret outlives this expression.
        secret: Zeroizing::new(secret.to_owned()),
        source,
        category,
    })
}

// ---- Helpers ---------------------------------------------------------------

/// The per-record dedup index for a contained leak.
///
/// SHA-256(session_id || source || literal_fingerprint), where
/// `literal_fingerprint` is the **key-store keyed MAC** of the literal produced
/// by the shared protected-redaction-history writer
/// ([`crate::redact::protected_redaction_history::PreparedAppend::fingerprint`]),
/// never an unkeyed SHA-256 of the plaintext. Because the sole variable input
/// derived from the secret is already a keyed MAC, this index is **not** an
/// offline guessing oracle: without the key store an attacker cannot compute the
/// literal fingerprint for a guessed secret, so they cannot compute this index.
/// The value is safe to store and does not reveal the literal.
pub fn keyed_leak_fingerprint(
    session_id: &str,
    source: LeakSource,
    literal_fingerprint: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(session_id.as_bytes());
    h.update(source.as_str().as_bytes());
    h.update(literal_fingerprint.as_bytes());
    let digest = h.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
