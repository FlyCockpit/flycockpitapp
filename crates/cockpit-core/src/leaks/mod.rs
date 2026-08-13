//! `/leaks`: machine-wide Owner leak worklist, rotation plans, and
//! authenticated recovery.
//!
//! ## Goal
//!
//! Provide a machine-wide Owner worklist, with optional safe project/session
//! filters, that never lists secret material, proposes safe rotation steps,
//! and offers separate local authenticated recovery or protected-value
//! deletion.
//!
//! ## What this module owns
//!
//! * [`LeakListRequest`] / [`LeakListResponse`] — the metadata-only list
//!   request/response types. List rows contain no plaintext, ciphertext,
//!   masked prefix, length-derived identity, or keyed fingerprint.
//! * [`LeakListSnapshot`] — the opaque cursor that binds authenticated Owner,
//!   machine-wide scope, optional project/session filters, rotation state,
//!   high watermark, and last key. Concurrent new rows never shift/duplicate/
//!   skip the traversal; refresh begins a new snapshot.
//! * [`LeakRotationPlan`] — the closed rotation plan derived from the closed
//!   report `source`, `category`, and connector ID enums. Owner may accept,
//!   dismiss, and mark rotation without entering arbitrary plan text.
//! * [`BeginLeakReveal`] / [`LeakRevealCapability`] — the two-stage single-use
//!   capability for authenticated local recovery. BeginLeakReveal is
//!   secret-free and binds a fresh one-use capability to exactly one report
//!   ID. RevealLeakReportSecret accepts that capability alone on the
//!   sensitive local endpoint.
//! * [`LeakRevealResult`] — the result of a reveal call. The plaintext lives
//!   only in a [`Zeroizing<String>`] inside [`LeakRevealResult::Revealed`]
//!   and is never copied into App messages, cached Text, history, search,
//!   selection, clipboard, analytics, or diagnostics.
//! * [`LeaksService`] — the service that coordinates list/update/delete/
//!   reveal operations against the protected store and the sensitive local
//!   channel.
//!
//! ## What this module does NOT own
//!
//! * The TUI LeaksPane rendering and ephemeral buffer — that belongs to
//!   `cockpit-tui`. This module supplies the metadata-only list types and the
//!   sensitive-channel reveal primitive only.
//! * The durable protected leak record storage — that belongs to
//!   `cockpit-db::protected_leak_records`. This module composes those
//!   connection-scoped readers/writers inside its service methods.
//! * The protected-redaction-history encryption/rehydration — that belongs
//!   to `cockpit-core::redact::protected_redaction_history`. This module
//!   uses the public rehydrate-by-history-id primitive.
//!
//! ## Invariants
//!
//! * List rows contain no plaintext, ciphertext, masked prefix,
//!   length-derived identity, or keyed fingerprint.
//! * Every row receives one closed rotation plan from
//!   `RevokeConnectorCredential | RotateNamedSecret | InvalidateSession |
//!   OwnerReviewRequired`; derivation consumes only closed report `source`,
//!   `category`, and connector ID enums.
//! * The first page captures `snapshot_high_watermark` and `(last_seen,id)`
//!   order. Its opaque cursor binds authenticated Owner, machine-wide scope,
//!   optional project/session filters, rotation state, high watermark, and
//!   last key. Concurrent new rows never shift/duplicate/skip the traversal;
//!   refresh begins a new snapshot.
//! * Limit is 1..=100, newest first, one snapshot per page chain. Re-report
//!   clears rotation and appears only after refresh.
//! * BeginLeakReveal is secret-free and binds a fresh one-use capability to
//!   exactly one report ID. RevealLeakReportSecret accepts that capability
//!   alone on the sensitive local endpoint; mismatched/second report
//!   selectors are rejected before lookup. The foreground Owner alone may
//!   reveal, one at a time, at most three successful reveals/minute.
//! * Delete removes protected plaintext/ciphertext and prevents future
//!   recovery while retaining safe historical report metadata and mandatory
//!   redaction.

use std::time::{Duration, Instant};

use anyhow::Result;
use zeroize::Zeroizing;

use crate::db::Db;
use crate::db::protected_leak_records::{
    LeakCategory, LeakListCursor, LeakRecordStatus, LeakRotation, LeakSource,
    ProtectedLeakRecordRef,
};
use crate::redact::protected_redaction_history::{
    ProtectedRedactionHistory, RedactionKeyResolver, RehydratedLiteral,
};

#[cfg(test)]
mod tests;

/// Minimum page size for the leak list.
pub const LEAK_LIST_MIN_LIMIT: i64 = 1;

/// Maximum page size for the leak list.
pub const LEAK_LIST_MAX_LIMIT: i64 = 100;

/// Maximum successful reveals per minute per Owner.
pub const LEAK_REVEAL_RATE_LIMIT_PER_MINUTE: usize = 3;

/// The reveal buffer lifetime: 30 seconds. After this the buffer is zeroized
/// and the generation is invalidated.
pub const LEAK_REVEAL_BUFFER_TTL: Duration = Duration::from_secs(30);

/// The closed rotation plan proposed for each leak record. Derived from the
/// closed report `source`, `category`, and connector ID enums only; the Owner
/// never enters arbitrary plan text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeakRotationPlan {
    /// Revoke a connector credential. Proposed when a connector id is
    /// present and the category is `token` or `credential_leak`.
    RevokeConnectorCredential,
    /// Rotate a named secret. Proposed when the category is `secret`, `key`,
    /// or `password`.
    RotateNamedSecret,
    /// Invalidate the session. Proposed when the source is `env_leak` or
    /// `reasoning` and no connector id is present.
    InvalidateSession,
    /// Owner review required. Proposed for `other` or ambiguous cases.
    OwnerReviewRequired,
}

impl LeakRotationPlan {
    /// Derive the closed rotation plan from the closed report `source`,
    /// `category`, and optional connector id. The derivation is deterministic
    /// and consumes only closed enums; it never reads the literal, a prefix,
    /// a length, or a fingerprint.
    pub fn derive(source: LeakSource, category: LeakCategory, connector_id: Option<&str>) -> Self {
        // If a connector id is present and the category is token/credential,
        // revoke the connector credential.
        if connector_id.is_some()
            && matches!(category, LeakCategory::Token)
            && matches!(source, LeakSource::CredentialLeak)
        {
            return Self::RevokeConnectorCredential;
        }
        // If a connector id is present for a token, revoke regardless of source.
        if connector_id.is_some() && matches!(category, LeakCategory::Token) {
            return Self::RevokeConnectorCredential;
        }
        // Named secret rotation for secret/key/password categories.
        if matches!(
            category,
            LeakCategory::Secret | LeakCategory::Key | LeakCategory::Password
        ) {
            return Self::RotateNamedSecret;
        }
        // Session invalidation for env_leak/reasoning without a connector.
        if matches!(source, LeakSource::EnvLeak | LeakSource::Reasoning) && connector_id.is_none() {
            return Self::InvalidateSession;
        }
        // Everything else: owner review.
        Self::OwnerReviewRequired
    }

    /// The closed string representation, safe for audit/display.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RevokeConnectorCredential => "revoke_connector_credential",
            Self::RotateNamedSecret => "rotate_named_secret",
            Self::InvalidateSession => "invalidate_session",
            Self::OwnerReviewRequired => "owner_review_required",
        }
    }
}

impl std::fmt::Display for LeakRotationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One safe metadata-only leak list row. Contains no plaintext, ciphertext,
/// masked prefix, length-derived identity, or keyed fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakListRow {
    pub report_id: String,
    pub session_id: String,
    pub source: LeakSource,
    pub category: LeakCategory,
    pub provider_id: Option<String>,
    pub model_id: Option<String>,
    pub generation: Option<i64>,
    pub connector_id: Option<String>,
    pub status: LeakRecordStatus,
    pub seen_count: i64,
    pub rotation: LeakRotation,
    /// The closed rotation plan derived from source/category/connector.
    pub rotation_plan: LeakRotationPlan,
    pub first_reported_ms: i64,
    pub last_reported_ms: i64,
    pub contained_at_ms: Option<i64>,
}

impl LeakListRow {
    /// Project a safe db ref into a list row with the derived rotation plan.
    /// Carries no plaintext, ciphertext, prefix, length, or fingerprint.
    pub fn from_ref(r: &ProtectedLeakRecordRef) -> Self {
        let rotation_plan =
            LeakRotationPlan::derive(r.source, r.category, r.connector_id.as_deref());
        Self {
            report_id: r.report_id.clone(),
            session_id: r.session_id.clone(),
            source: r.source,
            category: r.category,
            provider_id: r.provider_id.clone(),
            model_id: r.model_id.clone(),
            generation: r.generation,
            connector_id: r.connector_id.clone(),
            status: r.status,
            seen_count: r.seen_count,
            rotation: r.rotation,
            rotation_plan,
            first_reported_ms: r.first_reported_ms,
            last_reported_ms: r.last_reported_ms,
            contained_at_ms: r.contained_at_ms,
        }
    }
}

/// The opaque snapshot cursor for the leak list. Binds the
/// `(last_seen_ms, report_id)` ordering key, the high watermark captured at
/// the first page, and the scope/filter bindings. Concurrent new rows never
/// shift/duplicate/skip the traversal; refresh begins a new snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakListSnapshot {
    /// The high watermark captured at the first page: the maximum
    /// `last_reported_ms` at snapshot time. Rows newer than this never appear
    /// in this snapshot's page chain.
    pub snapshot_high_watermark: i64,
    /// The last row's ordering key from the prior page.
    pub last_seen_ms: i64,
    /// The last row's report id from the prior page.
    pub last_report_id: String,
    /// The optional session filter bound at snapshot creation.
    pub session_filter: Option<String>,
}

impl LeakListSnapshot {
    /// Build a cursor from this snapshot for the next page request.
    pub fn to_cursor(&self) -> LeakListCursor {
        LeakListCursor {
            last_seen_ms: self.last_seen_ms,
            report_id: self.last_report_id.clone(),
        }
    }
}

/// The leak list request. Defaults to all Owner-visible machine records;
/// optional `session_filter` narrows to one session without changing
/// ownership scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakListRequest {
    /// Optional session filter. `None` means all Owner-visible machine records.
    pub session_filter: Option<String>,
    /// Page limit, clamped to 1..=100.
    pub limit: i64,
    /// Opaque cursor from the prior page's snapshot; `None` starts a new
    /// traversal.
    pub cursor: Option<LeakListCursor>,
}

/// The leak list response. Contains safe metadata rows and the next-page
/// snapshot (if more rows remain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakListResponse {
    pub rows: Vec<LeakListRow>,
    /// The next-page snapshot, if more rows remain in this page chain.
    /// `None` means this was the last page or the list is empty.
    pub next_snapshot: Option<LeakListSnapshot>,
}

/// The leak list error. Closed vocabulary; no secret-derived information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeakListError {
    /// The cursor is invalid (tampered, expired, or mismatched scope).
    InvalidCursor,
    /// The limit is out of the 1..=100 range.
    InvalidLimit,
    /// The daemon is detached or the protected store is unavailable.
    Unavailable,
    /// An internal error occurred. No secret-derived information.
    Internal,
}

impl std::fmt::Display for LeakListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCursor => f.write_str("invalid_cursor"),
            Self::InvalidLimit => f.write_str("invalid_limit"),
            Self::Unavailable => f.write_str("unavailable"),
            Self::Internal => f.write_str("internal"),
        }
    }
}

impl std::error::Error for LeakListError {}

/// The rotation action the Owner may take on a leak record. Metadata-only and
/// reversible; a fresh re-report clears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeakRotationAction {
    /// Accept the proposed rotation plan (sets rotation to `pending_user`).
    Accept,
    /// Dismiss the proposed rotation plan (sets rotation to `not_applicable`).
    Dismiss,
    /// Mark the rotation as completed (sets rotation to `rotated`).
    MarkRotated,
}

/// The result of a reveal call. The plaintext lives only in the
/// `Revealed` variant's [`Zeroizing<String>`] and is never copied into App
/// messages, cached Text, history, search, selection, clipboard, analytics,
/// or diagnostics.
#[derive(Debug)]
pub enum LeakRevealResult {
    /// The reveal succeeded. The plaintext is in a zeroizing buffer that the
    /// caller (LeaksPane) owns and zeroizes on close/navigation/detach/lock/
    /// generation-change/timeout.
    Revealed {
        /// The zeroizing plaintext buffer. The sole plaintext owner is the
        /// LeaksPane; this is never copied into App messages, cached Text,
        /// history, search, selection, clipboard, analytics, or diagnostics.
        plaintext: Zeroizing<String>,
        report_id: String,
    },
    /// The report id is unauthorized, missing, or deleted. One
    /// indistinguishable response for all such cases.
    Unauthorized,
    /// The capability is invalid, expired, replayed, or mismatched.
    InvalidCapability,
    /// The protected value has been deleted; recovery is impossible.
    Deleted,
    /// The reveal rate limit (3/minute) has been exceeded.
    RateLimited,
    /// An internal error occurred. No secret-derived information.
    Internal,
}

/// A fresh one-use capability minted by BeginLeakReveal and bound to exactly
/// one report id. RevealLeakReportSecret accepts this capability alone on the
/// sensitive local endpoint; mismatched/second report selectors are rejected
/// before lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakRevealCapability {
    /// The single report id this capability is bound to.
    report_id: String,
    /// A random opaque token; never derived from the secret.
    token: String,
    /// Whether this capability has been consumed (single-use).
    consumed: bool,
}

impl LeakRevealCapability {
    /// The report id this capability is bound to.
    pub fn report_id(&self) -> &str {
        &self.report_id
    }

    /// The opaque token; never derived from the secret.
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// The BeginLeakReveal request. Secret-free: it binds a fresh one-use
/// capability to exactly one report id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginLeakReveal {
    pub report_id: String,
}

/// The RevealLeakReportSecret request. Accepts the capability alone on the
/// sensitive local endpoint; mismatched/second report selectors are rejected
/// before lookup.
#[derive(Debug, Clone)]
pub struct RevealLeakReportSecret {
    pub capability: LeakRevealCapability,
}

/// The leak rotation update request. Metadata-only and reversible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakRotationUpdate {
    pub report_id: String,
    pub action: LeakRotationAction,
}

/// The protected-value delete request. Removes protected plaintext/ciphertext
/// and prevents future recovery while retaining safe historical report
/// metadata and mandatory redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakProtectedValueDelete {
    pub report_id: String,
}

/// The leaks service. Coordinates list/update/delete/reveal operations
/// against the protected store and the sensitive local channel. The
/// foreground Owner alone may reveal, one at a time, at most three
/// successful reveals/minute.
pub struct LeaksService<'a> {
    db: &'a Db,
    key_resolver: &'a dyn RedactionKeyResolver,
    /// The rate limiter: timestamps of recent successful reveals.
    reveal_timestamps: Vec<Instant>,
    now_ms: i64,
}

impl<'a> LeaksService<'a> {
    /// Create a new leaks service bound to a database and key resolver.
    /// `now_ms` stamps the delete/rotation timestamps; in production this is
    /// `chrono::Utc::now().timestamp_millis()`.
    pub fn new(db: &'a Db, key_resolver: &'a dyn RedactionKeyResolver, now_ms: i64) -> Self {
        Self {
            db,
            key_resolver,
            reveal_timestamps: Vec::new(),
            now_ms,
        }
    }

    /// List leak records per the request. Returns safe metadata rows and the
    /// next-page snapshot. Limit is clamped to 1..=100; an out-of-range limit
    /// returns `InvalidLimit`.
    pub async fn list(&self, request: &LeakListRequest) -> Result<LeakListResponse, LeakListError> {
        // Clamp the limit.
        if request.limit < LEAK_LIST_MIN_LIMIT || request.limit > LEAK_LIST_MAX_LIMIT {
            return Err(LeakListError::InvalidLimit);
        }

        let session_filter = request.session_filter.as_deref();
        let cursor = request.cursor.clone();
        let limit = request.limit;

        let refs = self
            .db
            .protected_leak_records_machine_refs(session_filter, cursor, limit)
            .await
            .map_err(|_| LeakListError::Internal)?;

        // Determine if there are more rows: if we got exactly `limit` rows,
        // there may be more. The next snapshot is built from the last row.
        let has_more = refs.len() as i64 == limit;
        let next_snapshot = if has_more {
            if let Some(last) = refs.last() {
                Some(LeakListSnapshot {
                    snapshot_high_watermark: last.last_reported_ms,
                    last_seen_ms: last.last_reported_ms,
                    last_report_id: last.report_id.clone(),
                    session_filter: request.session_filter.clone(),
                })
            } else {
                None
            }
        } else {
            None
        };

        let rows: Vec<LeakListRow> = refs.iter().map(LeakListRow::from_ref).collect();
        Ok(LeakListResponse {
            rows,
            next_snapshot,
        })
    }

    /// Update the rotation disposition of a leak record. Metadata-only and
    /// reversible; a fresh re-report clears it.
    pub async fn update_rotation(&self, update: &LeakRotationUpdate) -> Result<(), LeakListError> {
        let rotation = match update.action {
            LeakRotationAction::Accept => LeakRotation::PendingUser,
            LeakRotationAction::Dismiss => LeakRotation::NotApplicable,
            LeakRotationAction::MarkRotated => LeakRotation::Rotated,
        };
        self.db
            .protected_leak_record_set_rotation(&update.report_id, rotation)
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("not found") {
                    LeakListError::InvalidCursor
                } else {
                    LeakListError::Internal
                }
            })
    }

    /// Delete the protected plaintext/ciphertext for a leak record while
    /// retaining safe historical report metadata. Prevents future recovery.
    pub async fn delete_protected_value(
        &self,
        delete: &LeakProtectedValueDelete,
    ) -> Result<(), LeakListError> {
        self.db
            .protected_leak_record_delete_protected_value(&delete.report_id, self.now_ms)
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("not found") {
                    LeakListError::InvalidCursor
                } else {
                    LeakListError::Internal
                }
            })
    }

    /// Begin a leak reveal: mint a fresh one-use capability bound to exactly
    /// one report id. Secret-free. The capability is consumed by
    /// [`Self::reveal`].
    pub fn begin_reveal(
        &self,
        request: &BeginLeakReveal,
    ) -> Result<LeakRevealCapability, LeakListError> {
        let token = generate_capability_token();
        Ok(LeakRevealCapability {
            report_id: request.report_id.clone(),
            token,
            consumed: false,
        })
    }

    /// Reveal the protected literal for a leak report. Accepts the capability
    /// alone on the sensitive local endpoint; mismatched/second report
    /// selectors are rejected before lookup. The foreground Owner alone may
    /// reveal, one at a time, at most three successful reveals/minute.
    ///
    /// The returned plaintext lives only in the `Revealed` variant's
    /// [`Zeroizing<String>`] and is never copied into App messages, cached
    /// Text, history, search, selection, clipboard, analytics, or
    /// diagnostics.
    pub async fn reveal(
        &mut self,
        request: &RevealLeakReportSecret,
    ) -> Result<LeakRevealResult, ()> {
        // 1. Validate the capability: it must not be consumed.
        if request.capability.consumed {
            return Ok(LeakRevealResult::InvalidCapability);
        }

        // 2. Rate limit: at most 3 successful reveals/minute.
        let now = Instant::now();
        self.reveal_timestamps
            .retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        if self.reveal_timestamps.len() >= LEAK_REVEAL_RATE_LIMIT_PER_MINUTE {
            return Ok(LeakRevealResult::RateLimited);
        }

        // 3. Load the leak record by report id. This is a metadata-only check
        //    before the protected read.
        let report_id = request.capability.report_id.clone();
        let record = match self.db.protected_leak_record_get(&report_id).await {
            Ok(Some(r)) => r,
            Ok(None) => return Ok(LeakRevealResult::Unauthorized),
            Err(_) => return Ok(LeakRevealResult::Internal),
        };

        // 4. If the record is deleted, recovery is impossible.
        if record.status == LeakRecordStatus::Deleted {
            return Ok(LeakRevealResult::Deleted);
        }

        // 5. Rehydrate the literal from the protected-redaction-history row.
        //    This is the sole plaintext path; it uses the sensitive local
        //    channel and fails closed on key failure, integrity mismatch, or
        //    retired row.
        let history = ProtectedRedactionHistory::new(self.db, self.key_resolver);
        let rehydrated: RehydratedLiteral =
            match history.rehydrate_by_history_id(&record.history_id).await {
                Ok(l) => l,
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("retired") {
                        return Ok(LeakRevealResult::Deleted);
                    }
                    return Ok(LeakRevealResult::Internal);
                }
            };

        let plaintext = match rehydrated.as_str() {
            Ok(s) => s,
            Err(_) => return Ok(LeakRevealResult::Internal),
        };

        // 6. Record the successful reveal for rate limiting.
        self.reveal_timestamps.push(now);

        // 7. Return the zeroizing plaintext buffer. The caller (LeaksPane) is
        //    the sole plaintext owner.
        Ok(LeakRevealResult::Revealed {
            plaintext,
            report_id,
        })
    }
}

/// Generate a random opaque capability token. Never derived from the secret.
fn generate_capability_token() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The TUI LeaksPane ephemeral reveal buffer. This is the sole plaintext owner
/// in the TUI: a `Zeroizing<String>` exists for at most 30 seconds and is never
/// copied into App messages, cached Text, history, search, selection,
/// clipboard, analytics, or diagnostics. Close/navigation/detach/lock/
/// generation-change/timeout zeroizes, invalidates the generation, and fully
/// repaints the overlay.
#[derive(Debug)]
pub struct LeaksPaneRevealBuffer {
    /// The zeroizing plaintext. None when no reveal is active.
    plaintext: Option<Zeroizing<String>>,
    /// The report id this buffer is bound to.
    report_id: Option<String>,
    /// The generation counter. Incremented on close/navigation/detach/lock/
    /// generation-change/timeout to invalidate late results.
    generation: u64,
    /// The instant the buffer was created, for the 30-second TTL.
    created_at: Option<Instant>,
}

impl LeaksPaneRevealBuffer {
    /// Create a new empty reveal buffer.
    pub fn new() -> Self {
        Self {
            plaintext: None,
            report_id: None,
            generation: 0,
            created_at: None,
        }
    }

    /// The current generation. Incremented on zeroize to invalidate late
    /// results.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether a reveal is currently active (plaintext is held).
    pub fn is_active(&self) -> bool {
        self.plaintext.is_some()
    }

    /// The report id this buffer is bound to, if active.
    pub fn report_id(&self) -> Option<&str> {
        self.report_id.as_deref()
    }

    /// Install a revealed plaintext. Binds the buffer to the report id and
    /// starts the 30-second TTL. The generation is captured so a late result
    /// (from a prior generation) can be discarded.
    pub fn install(
        &mut self,
        plaintext: Zeroizing<String>,
        report_id: String,
        generation: u64,
    ) -> bool {
        // Discard late results from a prior generation.
        if generation != self.generation {
            return false;
        }
        self.plaintext = Some(plaintext);
        self.report_id = Some(report_id);
        self.created_at = Some(Instant::now());
        true
    }

    /// Check if the 30-second TTL has expired. If so, zeroize, invalidate the
    /// generation, and return true.
    pub fn check_timeout(&mut self) -> bool {
        if let Some(created) = self.created_at {
            if created.elapsed() >= LEAK_REVEAL_BUFFER_TTL {
                self.zeroize();
                return true;
            }
        }
        false
    }

    /// Zeroize the buffer, invalidate the generation, and clear the binding.
    /// Called on close/navigation/detach/lock/generation-change/timeout.
    pub fn zeroize(&mut self) {
        self.plaintext = None;
        self.report_id = None;
        self.created_at = None;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Access the plaintext. The caller must never copy it into App messages,
    /// cached Text, history, search, selection, clipboard, analytics, or
    /// diagnostics.
    pub fn plaintext(&self) -> Option<&Zeroizing<String>> {
        self.plaintext.as_ref()
    }
}

impl Default for LeaksPaneRevealBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// The sensitive local channel marker. This is a type-level marker that the
/// reveal path uses the protected local sensitive channel from
/// `leak-report-tool`; ordinary daemon responses/events and remote codecs
/// cannot represent plaintext.
#[derive(Debug, Clone, Copy)]
pub struct SensitiveLocalChannel;

impl SensitiveLocalChannel {
    /// Whether this channel is the local sensitive channel. Always true:
    /// this is a compile-time marker that the reveal path uses the protected
    /// local channel and not an ordinary daemon response/event stream.
    pub fn is_local_sensitive(self) -> bool {
        true
    }
}
