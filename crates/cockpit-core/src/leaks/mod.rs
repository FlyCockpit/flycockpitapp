//! `/leaks`: machine-wide Owner leak worklist, rotation plans, and
//! authenticated recovery — the single production implementation the daemon
//! dispatch delegates to.
//!
//! ## What this module owns
//!
//! * List paging over the protected leak store: a per-daemon-boot MAC'd cursor
//!   ([`encode_leak_cursor`] / [`decode_leak_cursor`]) bound to owner + filters
//!   + rotation state + snapshot high watermark + last key; a first-page
//!   watermark snapshot; `project_root`/`session`/`rotation` filters; and a
//!   correct `has_more` via a `limit + 1` fetch ([`list_leak_reports`]).
//! * The closed rotation plan derivation ([`LeakRotationPlan`]).
//! * Rotation update and true protected-value delete wrappers
//!   ([`update_rotation`], [`delete_protected_value`]).
//! * The reveal capability slot + successful-reveal rate window
//!   ([`LeakRevealState`]) that lives inside the daemon context. Minting a new
//!   capability **replaces** (invalidates) any outstanding one, so exactly one
//!   is in flight by construction; the raw 32-byte token is stored here (never
//!   the hex string) and consumed once.
//!
//! ## Reveal channel (honest)
//!
//! The revealed plaintext never rides an ordinary daemon response/event or any
//! remote codec — after this landing the ordinary protocol cannot even express
//! a reveal. Plaintext is produced only by the consumption core in
//! [`crate::daemon::leak_reveal`], reached over exactly two production paths:
//!
//! * **in-process** ([`crate::daemon::leak_reveal::reveal_leak_secret_in_process`]) —
//!   when the TUI hosts the daemon, and the **only** path on Windows (no
//!   external socket transport exists there);
//! * **Unix peer-authenticated reveal socket** ([`crate::daemon::leak_reveal_socket`]) —
//!   a dedicated 0600 socket, path a pure function of the control socket, that
//!   accepts only after the same same-uid peer check the control socket uses.
//!
//! The plaintext buffer with its 30-second TTL lives in the TUI `LeaksPane`,
//! the sole plaintext owner; this module never holds the revealed literal.

use base64::Engine;
use hmac::{Hmac, KeyInit as _, Mac};
use rand::Rng;
use sha2::Sha256;

use crate::db::Db;
use crate::db::protected_leak_records::{
    LeakCategory, LeakListCursor, LeakListFilters, LeakRecordStatus, LeakRotation, LeakSource,
    ProtectedLeakRecordRef,
};

#[cfg(test)]
mod tests;

type HmacSha256 = Hmac<Sha256>;

/// Minimum page size for the leak list.
pub const LEAK_LIST_MIN_LIMIT: i64 = 1;

/// Maximum page size for the leak list.
pub const LEAK_LIST_MAX_LIMIT: i64 = 100;

/// Maximum successful reveals per rolling minute (machine-wide/owner-scoped).
pub const LEAK_REVEAL_RATE_LIMIT_PER_MINUTE: usize = 3;

/// Reveal capability TTL: 60 seconds.
pub const LEAK_REVEAL_CAPABILITY_TTL_MS: i64 = 60_000;

/// The rolling rate-limit window: 60 seconds.
pub const LEAK_REVEAL_RATE_WINDOW_MS: i64 = 60_000;

/// Hard cap on a revealed secret's UTF-8 byte length on the sensitive channel.
pub const LEAK_REVEAL_MAX_PLAINTEXT_BYTES: usize = 65_536;

/// The closed rotation plan proposed for each leak record. Derived from the
/// closed report `source`, `category`, and connector ID enums only; the Owner
/// never enters arbitrary plan text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeakRotationPlan {
    /// Revoke a connector credential.
    RevokeConnectorCredential,
    /// Rotate a named secret.
    RotateNamedSecret,
    /// Invalidate the session.
    InvalidateSession,
    /// Owner review required.
    OwnerReviewRequired,
}

impl LeakRotationPlan {
    /// Derive the closed rotation plan from the closed report `source`,
    /// `category`, and optional connector id. Consumes only closed enums; never
    /// reads the literal, a prefix, a length, or a fingerprint.
    pub fn derive(source: LeakSource, category: LeakCategory, connector_id: Option<&str>) -> Self {
        if connector_id.is_some()
            && matches!(category, LeakCategory::Token)
            && matches!(source, LeakSource::CredentialLeak)
        {
            return Self::RevokeConnectorCredential;
        }
        if connector_id.is_some() && matches!(category, LeakCategory::Token) {
            return Self::RevokeConnectorCredential;
        }
        if matches!(
            category,
            LeakCategory::Secret | LeakCategory::Key | LeakCategory::Password
        ) {
            return Self::RotateNamedSecret;
        }
        if matches!(source, LeakSource::EnvLeak | LeakSource::Reasoning) && connector_id.is_none() {
            return Self::InvalidateSession;
        }
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

/// The rotation action the Owner may take on a leak record. Metadata-only and
/// reversible; a fresh re-report clears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeakRotationAction {
    Accept,
    Dismiss,
    MarkRotated,
}

/// The leak list error. Closed vocabulary; no secret-derived information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeakListError {
    /// The cursor is invalid (tampered, wrong boot key, or filter mismatch).
    InvalidCursor,
    /// The limit is out of the 1..=100 range.
    InvalidLimit,
    /// The report id was not found (indistinguishable-unauthorized at dispatch).
    NotFound,
    /// An internal error occurred. No secret-derived information.
    Internal,
}

impl std::fmt::Display for LeakListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCursor => f.write_str("invalid_cursor"),
            Self::InvalidLimit => f.write_str("invalid_limit"),
            Self::NotFound => f.write_str("not_found"),
            Self::Internal => f.write_str("internal"),
        }
    }
}

impl std::error::Error for LeakListError {}

// ---------------------------------------------------------------------------
// Reveal capability slot + rate window (lives inside the daemon context)
// ---------------------------------------------------------------------------

/// A minted, single-use, one-in-flight reveal capability at rest. Stores the
/// **raw 32 token bytes only** (never the hex string), the bound report id, and
/// the absolute expiry. Consumed by the reveal core under the state lock.
pub struct PendingCapability {
    token: [u8; 32],
    report_id: String,
    expires_at_ms: i64,
}

impl PendingCapability {
    /// The raw 32-byte token for constant-time comparison after hex-decode.
    pub fn token(&self) -> &[u8; 32] {
        &self.token
    }
    /// The single report id this capability is bound to.
    pub fn report_id(&self) -> &str {
        &self.report_id
    }
    /// Absolute expiry (unix ms).
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}

impl std::fmt::Debug for PendingCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the raw token bytes.
        f.debug_struct("PendingCapability")
            .field("token", &"[REDACTED; 32 bytes]")
            .field("report_id", &self.report_id)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// The outcome of beginning a reveal under the state lock.
#[derive(Debug)]
pub enum RevealStart {
    /// The rolling rate limit is exhausted; the pending capability is **not**
    /// consumed (it still expires on its own clock).
    RateLimited,
    /// No capability was pending (or a later mint replaced it); indistinguishable
    /// unauthorized.
    NoCapability,
    /// The pending capability was consumed (taken from the slot). It is gone even
    /// if the subsequent verification/read fails (fail-closed).
    Consumed(PendingCapability),
}

/// The daemon-held reveal state: one pending-capability slot plus the recent
/// reveal timestamp window. Both live behind one mutex in the daemon context;
/// time is injected (no `Instant::now`/`Utc::now` inside this logic).
///
/// The rate limit counts confirmed successes **plus in-flight reservations**:
/// `begin_reveal` reserves a slot atomically under the lock (before the caller
/// releases it to do the DB rehydrate across `.await`s), so concurrent reveals
/// cannot all pass a `< 3` check while their successes are still pending. Every
/// non-success path must [`Self::release_reservation`]; a success path
/// [`Self::confirm_success`], which records the success at the CONFIRM time and
/// removes the reservation.
///
/// An in-flight reservation is **never aged out purely by time** — it stays
/// counted until it is confirmed or released, and only confirmed successes age
/// by their own confirm time (RL2). If a reservation aged out on its own, a set
/// of stalled reveals could vacate their slots at the window boundary, let a
/// fresh batch through, and then complete — exceeding 3 successes in a rolling
/// minute. The reservation count is bounded by the limit (a 4th cannot reserve),
/// and a daemon restart resets all state, so a dropped/cancelled reveal that
/// never finalizes can at worst shrink the budget (fail-closed), never grow it.
#[derive(Debug, Default)]
pub struct LeakRevealState {
    pending: Option<PendingCapability>,
    /// Unix-ms timestamps of recent confirmed successful reveals (rolling 60s).
    successes: Vec<i64>,
    /// Reservation keys of reveals reserved-but-not-yet-confirmed. Not aged.
    in_flight: Vec<i64>,
}

impl LeakRevealState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a new capability, **replacing** (thereby invalidating) any
    /// outstanding one — one-in-flight by construction.
    pub fn mint(&mut self, token: [u8; 32], report_id: String, expires_at_ms: i64) {
        self.pending = Some(PendingCapability {
            token,
            report_id,
            expires_at_ms,
        });
    }

    fn prune(&mut self, now_ms: i64) {
        // Only confirmed successes age out (by their own confirm time). In-flight
        // reservations are NEVER aged by time — a stalled reveal stays counted
        // until it confirms or releases, so slow reveals can't let extra ones
        // slip through the rolling window (RL2).
        self.successes
            .retain(|t| now_ms.saturating_sub(*t) < LEAK_REVEAL_RATE_WINDOW_MS);
    }

    /// Begin a reveal under the lock: enforce the rate limit against confirmed
    /// **and** in-flight reveals, then take the pending capability and RESERVE
    /// an in-flight slot in the same critical section. A rate-limit rejection
    /// neither reserves nor consumes.
    pub fn begin_reveal(&mut self, now_ms: i64) -> RevealStart {
        self.prune(now_ms);
        if self.successes.len() + self.in_flight.len() >= LEAK_REVEAL_RATE_LIMIT_PER_MINUTE {
            return RevealStart::RateLimited;
        }
        match self.pending.take() {
            Some(cap) => {
                self.in_flight.push(now_ms);
                RevealStart::Consumed(cap)
            }
            None => RevealStart::NoCapability,
        }
    }

    /// Convert an in-flight reservation into a confirmed success (on the
    /// happy path). `reserve_ms` is the `now_ms` passed to `begin_reveal`.
    pub fn confirm_success(&mut self, reserve_ms: i64, now_ms: i64) {
        remove_one(&mut self.in_flight, reserve_ms);
        self.successes.push(now_ms);
    }

    /// Release an in-flight reservation without recording a success (every
    /// non-success path: decode/mismatch/expiry/DB error/rehydrate failure).
    pub fn release_reservation(&mut self, reserve_ms: i64) {
        remove_one(&mut self.in_flight, reserve_ms);
    }

    /// Record a confirmed success directly (test seam for the rate window).
    #[cfg(test)]
    pub fn record_success(&mut self, now_ms: i64) {
        self.prune(now_ms);
        self.successes.push(now_ms);
    }

    #[cfg(test)]
    pub fn pending_is_some(&self) -> bool {
        self.pending.is_some()
    }
}

/// Remove the first element equal to `val` (count-preserving reservation
/// bookkeeping; concurrent reservations may share a timestamp).
fn remove_one(v: &mut Vec<i64>, val: i64) {
    if let Some(pos) = v.iter().position(|&t| t == val) {
        v.swap_remove(pos);
    }
}

/// Generate a fresh 32-byte reveal token (raw bytes) and its lowercase-hex
/// wire encoding (64 hex chars). Only the raw bytes are stored at rest.
pub fn mint_reveal_token() -> ([u8; 32], String) {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let hex = hex_lower_32(&bytes);
    (bytes, hex)
}

/// A per-daemon-boot random 32-byte cursor-MAC key. Rotated on restart, so
/// stale cursors fail closed into a fresh snapshot.
pub fn random_cursor_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    key
}

/// Lowercase-hex encode 32 bytes into a 64-char string.
fn hex_lower_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode exactly 64 lowercase/uppercase hex chars into 32 raw bytes. Returns
/// `None` on any non-hex byte or wrong length (treated as unauthorized after
/// structural failure by the caller).
pub fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Constant-time equality of two fixed-length 32-byte tokens. Fixed-length,
/// branch-free comparison — no early return on the first differing byte.
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    // black_box the accumulator so the compiler cannot fold the comparison into
    // an early-out.
    std::hint::black_box(diff) == 0
}

// ---------------------------------------------------------------------------
// List cursor: base64url(payload || HMAC-SHA256(key, payload))
// ---------------------------------------------------------------------------

/// The versioned, canonically-encoded cursor payload. Binds owner tag, all
/// filters, rotation state, the snapshot high watermark, and the last ordering
/// key. Its MAC is verified constant-time on decode and its filters checked for
/// equality with the incoming request's filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakCursorPayload {
    pub session_filter: Option<String>,
    pub project_root: Option<String>,
    pub rotation: Option<LeakRotation>,
    pub snapshot_high_watermark: i64,
    pub last_seen_ms: i64,
    pub last_report_id: String,
}

const LEAK_CURSOR_VERSION: u8 = 1;
const LEAK_CURSOR_OWNER_TAG: u8 = 1;

fn rotation_wire(r: LeakRotation) -> u8 {
    match r {
        LeakRotation::None => 1,
        LeakRotation::PendingUser => 2,
        LeakRotation::Rotated => 3,
        LeakRotation::NotApplicable => 4,
    }
}

fn rotation_from_wire(v: u8) -> Option<LeakRotation> {
    match v {
        1 => Some(LeakRotation::None),
        2 => Some(LeakRotation::PendingUser),
        3 => Some(LeakRotation::Rotated),
        4 => Some(LeakRotation::NotApplicable),
        _ => None,
    }
}

fn push_opt_str(buf: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(s) => {
            buf.push(1);
            buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        None => buf.push(0),
    }
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn encode_cursor_payload_bytes(p: &LeakCursorPayload) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(LEAK_CURSOR_VERSION);
    buf.push(LEAK_CURSOR_OWNER_TAG);
    push_opt_str(&mut buf, p.session_filter.as_deref());
    push_opt_str(&mut buf, p.project_root.as_deref());
    match p.rotation {
        Some(r) => {
            buf.push(1);
            buf.push(rotation_wire(r));
        }
        None => buf.push(0),
    }
    buf.extend_from_slice(&p.snapshot_high_watermark.to_be_bytes());
    buf.extend_from_slice(&p.last_seen_ms.to_be_bytes());
    push_str(&mut buf, &p.last_report_id);
    buf
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn i64(&mut self) -> Option<i64> {
        let end = self.pos.checked_add(8)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(i64::from_be_bytes(slice.try_into().ok()?))
    }
    fn str(&mut self) -> Option<String> {
        let end = self.pos.checked_add(4)?;
        let len_slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        let len = u32::from_be_bytes(len_slice.try_into().ok()?) as usize;
        let s_end = self.pos.checked_add(len)?;
        let s_slice = self.buf.get(self.pos..s_end)?;
        self.pos = s_end;
        String::from_utf8(s_slice.to_vec()).ok()
    }
    fn opt_str(&mut self) -> Option<Option<String>> {
        match self.u8()? {
            0 => Some(None),
            1 => Some(Some(self.str()?)),
            _ => None,
        }
    }
    fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn decode_cursor_payload_bytes(buf: &[u8]) -> Option<LeakCursorPayload> {
    let mut r = Reader { buf, pos: 0 };
    if r.u8()? != LEAK_CURSOR_VERSION {
        return None;
    }
    if r.u8()? != LEAK_CURSOR_OWNER_TAG {
        return None;
    }
    let session_filter = r.opt_str()?;
    let project_root = r.opt_str()?;
    let rotation = match r.u8()? {
        0 => None,
        1 => Some(rotation_from_wire(r.u8()?)?),
        _ => return None,
    };
    let snapshot_high_watermark = r.i64()?;
    let last_seen_ms = r.i64()?;
    let last_report_id = r.str()?;
    if !r.at_end() {
        return None;
    }
    Some(LeakCursorPayload {
        session_filter,
        project_root,
        rotation,
        snapshot_high_watermark,
        last_seen_ms,
        last_report_id,
    })
}

/// Encode a cursor payload as `base64url(payload || HMAC-SHA256(key, payload))`.
pub fn encode_leak_cursor(key: &[u8; 32], p: &LeakCursorPayload) -> String {
    let payload = encode_cursor_payload_bytes(p);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&payload);
    let tag = mac.finalize().into_bytes();
    let mut framed = payload;
    framed.extend_from_slice(tag.as_slice());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&framed)
}

/// Decode + constant-time MAC-verify a cursor, then require its bound filters to
/// equal `filters`. Any failure (bad base64, short frame, wrong version/owner,
/// MAC mismatch, filter mismatch, legacy JSON cursor, wrong boot key) →
/// [`LeakListError::InvalidCursor`].
pub fn decode_leak_cursor(
    key: &[u8; 32],
    cursor: &str,
    filters: &LeakListFilters,
) -> Result<LeakCursorPayload, LeakListError> {
    let framed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.as_bytes())
        .map_err(|_| LeakListError::InvalidCursor)?;
    if framed.len() < 32 {
        return Err(LeakListError::InvalidCursor);
    }
    let (payload, tag) = framed.split_at(framed.len() - 32);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload);
    // Constant-time verification of the 32-byte tag.
    mac.verify_slice(tag)
        .map_err(|_| LeakListError::InvalidCursor)?;
    let parsed = decode_cursor_payload_bytes(payload).ok_or(LeakListError::InvalidCursor)?;
    if parsed.session_filter != filters.session_filter
        || parsed.project_root != filters.project_root
        || parsed.rotation != filters.rotation
    {
        return Err(LeakListError::InvalidCursor);
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// List / rotation / delete (the single dispatch-backing implementation)
// ---------------------------------------------------------------------------

/// One page of the machine-wide Owner leak list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakListPage {
    pub refs: Vec<ProtectedLeakRecordRef>,
    /// The opaque MAC'd cursor for the next page; `None` on the last page.
    pub next_cursor: Option<String>,
    /// True iff a further page exists (a `limit + 1` row was fetched).
    pub has_more: bool,
}

/// List one page of leak reports. The first page (no cursor) captures the
/// snapshot high watermark and binds it into the returned cursor; every page is
/// constrained to `last_reported_ms <= watermark`, so concurrent inserts and
/// re-reports never shift/duplicate/skip the traversal. `has_more` is computed
/// by fetching `limit + 1` rows and truncating.
pub async fn list_leak_reports(
    db: &Db,
    cursor_key: &[u8; 32],
    filters: LeakListFilters,
    limit: i64,
    cursor: Option<&str>,
) -> Result<LeakListPage, LeakListError> {
    if !(LEAK_LIST_MIN_LIMIT..=LEAK_LIST_MAX_LIMIT).contains(&limit) {
        return Err(LeakListError::InvalidLimit);
    }

    let (watermark, position) = match cursor {
        Some(cursor) => {
            let payload = decode_leak_cursor(cursor_key, cursor, &filters)?;
            (
                payload.snapshot_high_watermark,
                Some(LeakListCursor {
                    last_seen_ms: payload.last_seen_ms,
                    report_id: payload.last_report_id,
                }),
            )
        }
        None => {
            let watermark = db
                .protected_leak_records_watermark(filters.clone())
                .await
                .map_err(|_| LeakListError::Internal)?;
            (watermark, None)
        }
    };

    let mut refs = db
        .protected_leak_records_machine_page(filters.clone(), watermark, position, limit + 1)
        .await
        .map_err(|_| LeakListError::Internal)?;

    let has_more = refs.len() as i64 > limit;
    if has_more {
        refs.truncate(limit as usize);
    }

    let next_cursor = if has_more {
        refs.last().map(|last| {
            encode_leak_cursor(
                cursor_key,
                &LeakCursorPayload {
                    session_filter: filters.session_filter.clone(),
                    project_root: filters.project_root.clone(),
                    rotation: filters.rotation,
                    snapshot_high_watermark: watermark,
                    last_seen_ms: last.last_reported_ms,
                    last_report_id: last.report_id.clone(),
                },
            )
        })
    } else {
        None
    };

    Ok(LeakListPage {
        refs,
        next_cursor,
        has_more,
    })
}

/// Update the rotation disposition of a leak record. Metadata-only and
/// reversible; a fresh re-report clears it. A missing record maps to
/// [`LeakListError::NotFound`] (indistinguishable-unauthorized at dispatch).
pub async fn update_rotation(
    db: &Db,
    report_id: &str,
    action: LeakRotationAction,
) -> Result<(), LeakListError> {
    let rotation = match action {
        LeakRotationAction::Accept => LeakRotation::PendingUser,
        LeakRotationAction::Dismiss => LeakRotation::NotApplicable,
        LeakRotationAction::MarkRotated => LeakRotation::Rotated,
    };
    db.protected_leak_record_set_rotation(report_id, rotation)
        .await
        .map_err(|e| classify_not_found(&e))
}

/// Delete the protected plaintext/ciphertext for a leak record while retaining
/// safe historical report metadata. Destroys the ciphertext/nonce/tag in one
/// transaction regardless of artifact references (see
/// [`crate::db::protected_leak_records::delete_protected_value_conn`]). A
/// missing record maps to [`LeakListError::NotFound`]. No error path carries a
/// reference count.
pub async fn delete_protected_value(
    db: &Db,
    report_id: &str,
    now_ms: i64,
) -> Result<(), LeakListError> {
    db.protected_leak_record_delete_protected_value(report_id, now_ms)
        .await
        .map_err(|e| classify_not_found(&e))
}

fn classify_not_found(e: &anyhow::Error) -> LeakListError {
    if e.to_string().contains("not found") {
        LeakListError::NotFound
    } else {
        LeakListError::Internal
    }
}
