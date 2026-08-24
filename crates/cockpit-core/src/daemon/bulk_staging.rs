//! Daemon-side staging for bulk transfers.
//!
//! Application messages carry a [`RemoteBulkTransferRef`] instead of inline
//! bytes. The bytes themselves live here until the peer pulls them (export) or
//! until the daemon consumes them (import).
//!
//! This is deliberately small and in-memory: it is the staging area a bulk
//! carrier fills and drains, not the carrier itself. Every entry is bounded by
//! its transfer's declared length, the whole store is bounded, and a completed
//! transfer's digest is verified before anything reads it.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::time::Instant;

use cockpit_proto::bulk_transfer::{
    MAX_TRANSFER_BYTES, BulkMimeClass as RemoteBulkMimeClass,
    BulkTransferRef as RemoteBulkTransferRef,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

/// Total bytes the staging area may hold across all transfers.
pub const MAX_STAGED_BYTES: u64 = 512 * 1024 * 1024;

/// Most transfers the staging area may hold at once.
///
/// [`MAX_STAGED_BYTES`] alone does not bound *metadata*: a zero-length transfer
/// charges zero bytes, so a peer could otherwise insert unbounded completed
/// entries by replaying distinct valid empty transfers. Entry count is the
/// bound that closes that, and it is checked before any insertion.
pub const MAX_STAGED_TRANSFERS: usize = 256;

/// Bytes of raw payload carried per staged chunk. Chosen so the base64 body
/// stays within [`cockpit_proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES`] and the
/// encoded frame inside one bulk-lane logical payload.
pub const STAGED_CHUNK_BYTES: usize = 3 * (cockpit_proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES / 4);

const _: () = assert!(STAGED_CHUNK_BYTES <= cockpit_proto::bulk_transfer::MAX_BULK_CHUNK_PAYLOAD_BYTES);

/// How long a staged transfer may sit untouched before it is reclaimed.
///
/// Staging holds a *reservation*, so an import that declares a large length and
/// then goes away — a disconnect, a crash, or a deliberate squat — would
/// otherwise hold that reservation until the daemon restarts.
///
/// Expiry runs from two places, and it needs both: opportunistically on every
/// staging operation (free, covers a busy daemon), and from [`spawn_reaper`]
/// (covers an *idle* daemon, where no second operation is ever coming). The
/// opportunistic sweep alone would leave an abandoned 512 MiB reservation held
/// forever on a quiet daemon.
///
/// This value is **advertised to the peer** on every accepted chunk
/// (`BulkTransferChunkAccepted.idle_timeout_ms`). That is what makes expiry a
/// contract rather than a surprise: a backpressured or stalled peer knows the
/// deadline it is held to, and every write renews it.
pub const STAGED_TRANSFER_TTL_MS: u64 = 5 * 60 * 1000;

/// How often the daemon's reaper sweeps staging.
pub const STAGED_TRANSFER_REAP_INTERVAL_MS: u64 = 30 * 1000;

#[derive(Debug, thiserror::Error)]
pub enum BulkStagingError {
    #[error("unknown bulk transfer")]
    UnknownTransfer,
    #[error("bulk transfer chunk index is not contiguous")]
    ChunkIndexGap,
    #[error("bulk transfer replay does not match the accepted chunk")]
    ChunkReplayMismatch,
    #[error("bulk transfer exceeds its declared length")]
    LengthOverrun,
    #[error("bulk transfer digest mismatch")]
    DigestMismatch,
    #[error("bulk transfer is not yet complete")]
    Incomplete,
    #[error("bulk staging capacity exceeded")]
    CapacityExceeded,
    #[error("bulk transfer chunk is too large")]
    ChunkTooLarge,
    #[error("bulk transfer exceeds its class limit")]
    ClassLimit,
    #[error("bulk transfer is not of the required kind")]
    WrongKind,
    #[error("bulk transfer id is already staged")]
    DuplicateTransfer,
    /// The transfer belongs to a different attached session or authenticated
    /// actor. Callers which expose opaque user-message transfers intentionally
    /// map this to the same safe response as an unavailable transfer.
    #[error("bulk transfer is unavailable")]
    OwnerMismatch,
}

/// Stable daemon-side owner for an opaque user-message transfer.
///
/// The wire reference is deliberately only a bearer *locator*, never an
/// authorization credential. Every opaque user-message transfer is therefore
/// bound to its attached session and a digest of the daemon-authenticated
/// principal/actor identity before bytes may be written or consumed. The
/// digest keeps raw principal and attachment values out of this process-global
/// in-memory store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkTransferOwner {
    binding: [u8; 32],
}

impl BulkTransferOwner {
    /// Build a transfer owner from daemon-authenticated identity material.
    ///
    /// `identity_material` must be stable for every chunk and the eventual
    /// consume request. In particular, it is the authenticated actor binding
    /// (logical attachment/device/generation), not the per-request operation
    /// UUID: upload chunks and their `SendUserMessageBulk` consumer are
    /// independently replayable protocol operations.
    pub fn for_attached_identity(session_id: Uuid, identity_material: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"flycockpit-bulk-user-transfer-owner-v1\0");
        hasher.update(session_id.as_bytes());
        hasher.update(identity_material);
        Self {
            binding: hasher.finalize().into(),
        }
    }
}

#[derive(Debug)]
struct StagedTransfer {
    total_length: u64,
    sha256: [u8; 32],
    mime_class: RemoteBulkMimeClass,
    bytes: Vec<u8>,
    /// Exclusive byte end for every accepted chunk. Chunks need not always be
    /// max-sized, so this is the only authoritative way to compare a retried
    /// chunk byte-for-byte without accidentally accepting a matching prefix.
    chunk_ends: Vec<usize>,
    next_chunk_index: u32,
    complete: bool,
    /// Monotonic milliseconds at the last operation that touched this transfer.
    touched_ms: u64,
    /// `Some` only for opaque user-message transfers. Generic archive/export
    /// staging intentionally has no attached-session owner because those
    /// transfer classes have separate authorization/consumption boundaries.
    owner: Option<BulkTransferOwner>,
}

/// Storage identity for a staged transfer. Opaque ingress deliberately carries
/// the owner binding in the key rather than treating the globally visible
/// transfer id as authority: another attached session or principal may never
/// occupy, overwrite, or consume the owner's staging slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StagedTransferKey {
    transfer_id: [u8; 16],
    owner_binding: Option<[u8; 32]>,
}

impl StagedTransferKey {
    fn new(transfer_id: [u8; 16], owner: Option<&BulkTransferOwner>) -> Self {
        Self {
            transfer_id,
            owner_binding: owner.map(|owner| owner.binding),
        }
    }
}

#[derive(Debug, Default)]
struct Store {
    transfers: HashMap<StagedTransferKey, StagedTransfer>,
    staged_bytes: u64,
}

impl Store {
    /// Reclaim every transfer untouched for longer than the TTL.
    ///
    /// Both the reservation and the buffered bytes go back, so an abandoned
    /// transfer cannot wedge the store shut.
    fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.transfers.len();
        let mut freed = 0u64;
        self.transfers.retain(|_, transfer| {
            let stale = now_ms.saturating_sub(transfer.touched_ms) >= STAGED_TRANSFER_TTL_MS;
            if stale {
                freed += transfer.total_length;
            }
            !stale
        });
        self.staged_bytes = self.staged_bytes.saturating_sub(freed);
        before - self.transfers.len()
    }

    /// Remove one transfer and release its reservation.
    fn remove(&mut self, key: &StagedTransferKey) -> Option<StagedTransfer> {
        let removed = self.transfers.remove(key)?;
        self.staged_bytes = self.staged_bytes.saturating_sub(removed.total_length);
        Some(removed)
    }
}

fn store() -> &'static Mutex<Store> {
    static STORE: OnceLock<Mutex<Store>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(Store::default()))
}

/// Monotonic milliseconds since the first staging call in this process.
///
/// Deliberately `tokio::time::Instant`: it falls back to the system clock
/// outside a runtime, but honours a paused test clock inside one, so the TTL
/// and the reaper are provable by advancing time rather than sleeping.
pub fn now_ms() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Sweep abandoned reservations on a schedule.
///
/// Staging also sweeps opportunistically inside every staging call, which is
/// free and covers a busy daemon. It is not sufficient on its own: on an idle
/// daemon no second operation is ever coming, so an abandoned reservation would
/// be held until restart. This is the half that covers that case.
pub fn spawn_reaper(shutdown: crate::daemon::shutdown::ShutdownSignal) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_millis(STAGED_TRANSFER_REAP_INTERVAL_MS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if shutdown.is_draining() {
                return;
            }
            let reclaimed = expire(now_ms());
            if reclaimed > 0 {
                // Count only: never a transfer id, length, or content.
                tracing::info!(count = reclaimed, "reclaimed abandoned bulk transfers");
            }
        }
    });
}

/// Reclaim expired transfers. Exposed so the TTL is provable without sleeping.
pub fn expire(now_ms: u64) -> usize {
    let mut guard = store().lock().expect("bulk staging poisoned");
    guard.expire(now_ms)
}

/// Bytes currently reserved across every staged transfer.
pub fn staged_bytes() -> u64 {
    store().lock().expect("bulk staging poisoned").staged_bytes
}

/// Transfers currently staged. Bounded by [`MAX_STAGED_TRANSFERS`].
pub fn staged_transfers() -> usize {
    store()
        .lock()
        .expect("bulk staging poisoned")
        .transfers
        .len()
}

fn digest_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// Number of chunks a transfer of `total_length` bytes occupies.
pub fn chunk_count(total_length: u64) -> u32 {
    if total_length == 0 {
        return 1;
    }
    total_length.div_ceil(STAGED_CHUNK_BYTES as u64) as u32
}

/// Stage daemon-produced non-opaque bytes (export/archive) and return their
/// reference.
///
/// Opaque user-message bytes must use [`stage_owned`]. An opaque transfer id
/// is a locator, not a bearer credential, so the low-level store must not
/// retain an ownerless opaque entry that another attached client could later
/// consume by guessing its id.
pub fn stage(
    bytes: &[u8],
    mime_class: RemoteBulkMimeClass,
    transfer_id_bytes: [u8; 16],
) -> Result<RemoteBulkTransferRef, BulkStagingError> {
    stage_with_owner(bytes, mime_class, transfer_id_bytes, None)
}

/// Stage a complete opaque user-message body under its exact attached
/// session/authenticated-actor owner.
pub fn stage_owned(
    bytes: &[u8],
    owner: &BulkTransferOwner,
    transfer_id_bytes: [u8; 16],
) -> Result<RemoteBulkTransferRef, BulkStagingError> {
    stage_with_owner(
        bytes,
        RemoteBulkMimeClass::Opaque,
        transfer_id_bytes,
        Some(owner),
    )
}

fn stage_with_owner(
    bytes: &[u8],
    mime_class: RemoteBulkMimeClass,
    transfer_id_bytes: [u8; 16],
    owner: Option<&BulkTransferOwner>,
) -> Result<RemoteBulkTransferRef, BulkStagingError> {
    match (mime_class, owner) {
        (RemoteBulkMimeClass::Opaque, None) => return Err(BulkStagingError::OwnerMismatch),
        (RemoteBulkMimeClass::Opaque, Some(_)) | (_, None) => {}
        (_, Some(_)) => return Err(BulkStagingError::WrongKind),
    }
    let total_length = bytes.len() as u64;
    if total_length > mime_class.max_total_length() || total_length > MAX_TRANSFER_BYTES {
        return Err(BulkStagingError::ClassLimit);
    }
    let sha256 = digest_of(bytes);
    let now = now_ms();
    let mut guard = store().lock().expect("bulk staging poisoned");
    guard.expire(now);
    let key = StagedTransferKey::new(transfer_id_bytes, owner);
    // A staged id is immutable identity *within this owner namespace*: refuse
    // to overwrite a live transfer. Silently replacing it would let a
    // redacted-export id be restaged as a raw `Export` (or vice versa) under a
    // reader that already verified its kind.
    if guard.transfers.contains_key(&key) {
        return Err(BulkStagingError::DuplicateTransfer);
    }
    if guard.transfers.len() >= MAX_STAGED_TRANSFERS {
        return Err(BulkStagingError::CapacityExceeded);
    }
    if guard.staged_bytes + total_length > MAX_STAGED_BYTES {
        return Err(BulkStagingError::CapacityExceeded);
    }
    guard.staged_bytes += total_length;
    guard.transfers.insert(
        key,
        StagedTransfer {
            total_length,
            sha256,
            mime_class,
            bytes: bytes.to_vec(),
            chunk_ends: (0..chunk_count(total_length))
                .map(|index| ((index as usize + 1) * STAGED_CHUNK_BYTES).min(bytes.len()))
                .collect(),
            next_chunk_index: chunk_count(total_length),
            complete: true,
            touched_ms: now,
            owner: owner.cloned(),
        },
    );
    drop(guard);

    let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(transfer_id_bytes)
    .map_err(|_| BulkStagingError::UnknownTransfer)?;
    RemoteBulkTransferRef::new(transfer_id, total_length, sha256, mime_class)
        .map_err(|_| BulkStagingError::ClassLimit)
}

/// Result of accepting one pushed chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkAccepted {
    pub next_chunk_index: u32,
    pub received_bytes: u64,
    pub complete: bool,
}

/// Accept one chunk pushed by the peer (import).
pub fn write_chunk(
    reference: &RemoteBulkTransferRef,
    chunk_index: u32,
    chunk: &[u8],
) -> Result<ChunkAccepted, BulkStagingError> {
    write_chunk_with_owner(reference, None, chunk_index, chunk)
}

/// Accept an opaque user-message chunk under its attached-session/actor owner.
pub fn write_chunk_owned(
    reference: &RemoteBulkTransferRef,
    owner: &BulkTransferOwner,
    chunk_index: u32,
    chunk: &[u8],
) -> Result<ChunkAccepted, BulkStagingError> {
    write_chunk_with_owner(reference, Some(owner), chunk_index, chunk)
}

fn write_chunk_with_owner(
    reference: &RemoteBulkTransferRef,
    owner: Option<&BulkTransferOwner>,
    chunk_index: u32,
    chunk: &[u8],
) -> Result<ChunkAccepted, BulkStagingError> {
    match (reference.mime_class, owner) {
        (RemoteBulkMimeClass::Opaque, None) => return Err(BulkStagingError::OwnerMismatch),
        (RemoteBulkMimeClass::Opaque, Some(_)) | (_, None) => {}
        (_, Some(_)) => return Err(BulkStagingError::WrongKind),
    }
    if chunk.len() > STAGED_CHUNK_BYTES {
        return Err(BulkStagingError::ChunkTooLarge);
    }
    let total_length = reference.total_length_value();
    if total_length > reference.mime_class.max_total_length() {
        return Err(BulkStagingError::ClassLimit);
    }
    let key = StagedTransferKey::new(*reference.transfer_id.as_bytes(), owner);
    let now = now_ms();
    let mut guard = store().lock().expect("bulk staging poisoned");
    guard.expire(now);

    if !guard.transfers.contains_key(&key) {
        if chunk_index != 0 {
            return Err(BulkStagingError::ChunkIndexGap);
        }
        if guard.transfers.len() >= MAX_STAGED_TRANSFERS {
            return Err(BulkStagingError::CapacityExceeded);
        }
        if guard.staged_bytes + total_length > MAX_STAGED_BYTES {
            return Err(BulkStagingError::CapacityExceeded);
        }
        guard.staged_bytes += total_length;
        guard.transfers.insert(
            key.clone(),
            StagedTransfer {
                total_length,
                sha256: reference.sha256,
                mime_class: reference.mime_class,
                // Deliberately *not* `with_capacity(total_length)`: the length
                // is a peer's claim, not a delivery. Storage grows with bytes
                // that actually arrive, so declaring 512 MiB and sending one
                // empty chunk costs a reservation, never 512 MiB of memory.
                bytes: Vec::new(),
                chunk_ends: Vec::new(),
                next_chunk_index: 0,
                complete: false,
                touched_ms: now,
                owner: owner.cloned(),
            },
        );
    }

    let entry = guard.transfers.get_mut(&key).expect("present");
    // The opaque transfer reference is its immutable identity.  Do this before
    // accepting a replay so a peer cannot borrow an existing id while changing
    // its declared length, digest, or MIME class.
    if entry.owner.as_ref() != owner {
        return Err(BulkStagingError::OwnerMismatch);
    }
    if entry.total_length != total_length
        || entry.sha256 != reference.sha256
        || entry.mime_class != reference.mime_class
    {
        return Err(BulkStagingError::DuplicateTransfer);
    }

    if chunk_index < entry.next_chunk_index {
        // A response may be lost after the daemon committed a chunk.  Retrying
        // that exact chunk is an idempotent adapter operation: acknowledge the
        // already accepted state without appending or reopening the transfer.
        let replay_index =
            usize::try_from(chunk_index).map_err(|_| BulkStagingError::ChunkIndexGap)?;
        let end = *entry
            .chunk_ends
            .get(replay_index)
            .ok_or(BulkStagingError::ChunkIndexGap)?;
        let start = replay_index
            .checked_sub(1)
            .and_then(|index| entry.chunk_ends.get(index).copied())
            .unwrap_or(0);
        if entry.bytes.get(start..end) != Some(chunk) {
            return Err(BulkStagingError::ChunkReplayMismatch);
        }
        entry.touched_ms = now;
        return Ok(ChunkAccepted {
            next_chunk_index: entry.next_chunk_index,
            received_bytes: entry.bytes.len() as u64,
            complete: entry.complete,
        });
    }
    if entry.complete {
        // A completed transfer is terminal; only an exact replay above may
        // observe it again. A new late chunk cannot reopen it.
        return Err(BulkStagingError::ChunkIndexGap);
    }
    if chunk_index != entry.next_chunk_index {
        return Err(BulkStagingError::ChunkIndexGap);
    }
    if entry.bytes.len() as u64 + chunk.len() as u64 > entry.total_length {
        return Err(BulkStagingError::LengthOverrun);
    }
    entry.touched_ms = now;
    entry.bytes.extend_from_slice(chunk);
    entry.chunk_ends.push(entry.bytes.len());
    entry.next_chunk_index += 1;

    if entry.bytes.len() as u64 == entry.total_length {
        if digest_of(&entry.bytes) != entry.sha256 {
            guard.remove(&key).expect("present");
            return Err(BulkStagingError::DigestMismatch);
        }
        entry.complete = true;
    }
    Ok(ChunkAccepted {
        next_chunk_index: entry.next_chunk_index,
        received_bytes: entry.bytes.len() as u64,
        complete: entry.complete,
    })
}

/// Read one chunk of a staged transfer (export pull). Returns the chunk and
/// whether it is the last one.
///
/// Serving the last chunk is the terminal event for an export: the transfer is
/// removed and its reservation released on the way out. Without that, every
/// completed download would stay charged against the store for the life of the
/// daemon and later exports would fail with `CapacityExceeded`.
pub fn read_chunk(
    transfer_id_bytes: [u8; 16],
    chunk_index: u32,
) -> Result<(Vec<u8>, bool), BulkStagingError> {
    let now = now_ms();
    let mut guard = store().lock().expect("bulk staging poisoned");
    guard.expire(now);
    let key = StagedTransferKey::new(transfer_id_bytes, None);
    let entry = guard
        .transfers
        .get_mut(&key)
        .ok_or(BulkStagingError::UnknownTransfer)?;
    // The unowned key can resolve only daemon-produced export/archive entries.
    // Opaque user-message bodies live under an owner-bound key and are thus
    // invisible to this unscoped reader even when a caller knows their id.
    if entry.mime_class == RemoteBulkMimeClass::Opaque {
        return Err(BulkStagingError::OwnerMismatch);
    }
    if !entry.complete {
        return Err(BulkStagingError::Incomplete);
    }
    let total_chunks = chunk_count(entry.total_length);
    if chunk_index >= total_chunks {
        return Err(BulkStagingError::ChunkIndexGap);
    }
    entry.touched_ms = now;
    let start = chunk_index as usize * STAGED_CHUNK_BYTES;
    let end = (start + STAGED_CHUNK_BYTES).min(entry.bytes.len());
    let chunk = entry.bytes[start..end].to_vec();
    let last = chunk_index + 1 == total_chunks;
    if last {
        guard.remove(&key);
    }
    Ok((chunk, last))
}

/// Serve one chunk of a staged transfer, but ONLY when its staged MIME class is
/// exactly `expected`. This is the type-bound read primitive: the redacted-export
/// remoted reader admits a transfer solely because it was staged as
/// [`RemoteBulkMimeClass::RedactedExport`], never merely "not raw". A transfer of
/// any other kind (a raw `Export`, an `Archive`, an image, …) is rejected with
/// [`BulkStagingError::WrongKind`] and NO bytes are returned or removed.
///
/// The kind check, chunk extraction, and terminal removal all happen under ONE
/// lock acquisition: dropping the lock between the kind check and the read would
/// let a concurrent restage swap the id to a raw `Export` between the two, so the
/// redacted reader could return raw bytes for an id it just verified as redacted.
/// Holding the lock across the whole operation closes that window; combined with
/// [`stage`] refusing to overwrite a live id, a staged redacted-export id can
/// never serve raw bytes.
pub fn read_chunk_of_kind(
    transfer_id_bytes: [u8; 16],
    chunk_index: u32,
    expected: RemoteBulkMimeClass,
) -> Result<(Vec<u8>, bool), BulkStagingError> {
    let now = now_ms();
    let mut guard = store().lock().expect("bulk staging poisoned");
    guard.expire(now);
    let key = StagedTransferKey::new(transfer_id_bytes, None);
    let entry = guard
        .transfers
        .get_mut(&key)
        .ok_or(BulkStagingError::UnknownTransfer)?;
    // Defensive invariant for any corrupt legacy entry. Normal opaque bodies
    // live under an owner-bound key and cannot reach this unscoped reader.
    if entry.mime_class == RemoteBulkMimeClass::Opaque {
        return Err(BulkStagingError::OwnerMismatch);
    }
    // Kind gate first: a non-`expected` transfer is refused before any byte is
    // read, and the entry is left untouched (never removed).
    if entry.mime_class != expected {
        return Err(BulkStagingError::WrongKind);
    }
    if !entry.complete {
        return Err(BulkStagingError::Incomplete);
    }
    let total_chunks = chunk_count(entry.total_length);
    if chunk_index >= total_chunks {
        return Err(BulkStagingError::ChunkIndexGap);
    }
    entry.touched_ms = now;
    let start = chunk_index as usize * STAGED_CHUNK_BYTES;
    let end = (start + STAGED_CHUNK_BYTES).min(entry.bytes.len());
    let chunk = entry.bytes[start..end].to_vec();
    let last = chunk_index + 1 == total_chunks;
    if last {
        guard.remove(&key);
    }
    Ok((chunk, last))
}

/// Take several completed transfers as one all-or-nothing staging operation.
///
/// A message may contain two independently bounded text fields. Consuming its
/// source before discovering that its display-form transfer is absent would
/// turn a recoverable retry into an unavailable submission. Validate every
/// reference under one lock before removing any of them so a missing,
/// incomplete, or mismatched sibling leaves the entire message retryable.
pub fn take_all(references: &[&RemoteBulkTransferRef]) -> Result<Vec<Vec<u8>>, BulkStagingError> {
    take_all_with_owner(references, None)
}

/// Take opaque user-message transfer bodies only for their exact attached
/// session and authenticated actor. Validation of every reference, including
/// owner equality, happens before any entry is removed, so a cross-owner
/// sibling cannot consume an otherwise valid multi-reference submission.
pub fn take_all_owned(
    references: &[&RemoteBulkTransferRef],
    owner: &BulkTransferOwner,
) -> Result<Vec<Vec<u8>>, BulkStagingError> {
    take_all_with_owner(references, Some(owner))
}

fn take_all_with_owner(
    references: &[&RemoteBulkTransferRef],
    owner: Option<&BulkTransferOwner>,
) -> Result<Vec<Vec<u8>>, BulkStagingError> {
    let now = now_ms();
    let mut guard = store().lock().expect("bulk staging poisoned");
    guard.expire(now);
    let mut keys = Vec::with_capacity(references.len());
    for reference in references {
        match (reference.mime_class, owner) {
            (RemoteBulkMimeClass::Opaque, None) => {
                return Err(BulkStagingError::OwnerMismatch);
            }
            (RemoteBulkMimeClass::Opaque, Some(_)) | (_, None) => {}
            (_, Some(_)) => return Err(BulkStagingError::WrongKind),
        }
        let key = StagedTransferKey::new(*reference.transfer_id.as_bytes(), owner);
        if keys.contains(&key) {
            return Err(BulkStagingError::DuplicateTransfer);
        }
        let entry = guard
            .transfers
            .get(&key)
            .ok_or(BulkStagingError::UnknownTransfer)?;
        if entry.owner.as_ref() != owner {
            return Err(BulkStagingError::OwnerMismatch);
        }
        if !entry.complete {
            return Err(BulkStagingError::Incomplete);
        }
        if entry.total_length != reference.total_length_value() {
            return Err(BulkStagingError::LengthOverrun);
        }
        if entry.sha256 != reference.sha256 || digest_of(&entry.bytes) != reference.sha256 {
            return Err(BulkStagingError::DigestMismatch);
        }
        // The class is part of the transfer's identity: a reference may not
        // be re-labelled to borrow a larger class limit.
        if entry.mime_class != reference.mime_class {
            return Err(BulkStagingError::ClassLimit);
        }
        keys.push(key);
    }
    Ok(keys
        .iter()
        .map(|key| guard.remove(key).expect("validated live transfer").bytes)
        .collect())
}

/// Take a completed transfer's bytes, verifying length and digest first.
pub fn take(reference: &RemoteBulkTransferRef) -> Result<Vec<u8>, BulkStagingError> {
    let mut bodies = take_all(&[reference])?;
    Ok(bodies.pop().expect("one requested transfer"))
}

/// Take one owned opaque user-message transfer.
pub fn take_owned(
    reference: &RemoteBulkTransferRef,
    owner: &BulkTransferOwner,
) -> Result<Vec<u8>, BulkStagingError> {
    let mut bodies = take_all_owned(&[reference], owner)?;
    Ok(bodies.pop().expect("one requested transfer"))
}

/// Drop a staged transfer without reading it (cancellation / cleanup).
pub fn discard(transfer_id_bytes: [u8; 16]) {
    let mut guard = store().lock().expect("bulk staging poisoned");
    guard.remove(&StagedTransferKey::new(transfer_id_bytes, None));
}

/// Drop one owned opaque transfer without exposing an unscoped deletion path.
pub fn discard_owned(transfer_id_bytes: [u8; 16], owner: &BulkTransferOwner) {
    let mut guard = store().lock().expect("bulk staging poisoned");
    guard.remove(&StagedTransferKey::new(transfer_id_bytes, Some(owner)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = seed.wrapping_add(i as u8).wrapping_add(1);
        }
        bytes
    }

    fn opaque_reference(payload: &[u8], seed: u8) -> RemoteBulkTransferRef {
        let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(id(seed))
        .expect("nonzero transfer id");
        RemoteBulkTransferRef::new(
            transfer_id,
            payload.len() as u64,
            digest_of(payload),
            RemoteBulkMimeClass::Opaque,
        )
        .expect("opaque transfer reference")
    }

    #[test]
    fn owned_opaque_transfer_rejects_cross_session_and_principal_without_consuming() {
        let payload = b"owned opaque source";
        let reference = opaque_reference(payload, 201);
        let owner = BulkTransferOwner::for_attached_identity(Uuid::from_u128(1), b"owner-a");
        let other_session =
            BulkTransferOwner::for_attached_identity(Uuid::from_u128(2), b"owner-a");
        let other_principal =
            BulkTransferOwner::for_attached_identity(Uuid::from_u128(1), b"owner-b");

        write_chunk_owned(&reference, &owner, 0, payload).expect("owner stages source");
        assert!(matches!(
            take_owned(&reference, &other_session),
            Err(BulkStagingError::UnknownTransfer)
        ));
        assert!(matches!(
            take_owned(&reference, &other_principal),
            Err(BulkStagingError::UnknownTransfer)
        ));
        assert_eq!(
            take_owned(&reference, &owner).expect("the original owner retains the transfer"),
            payload,
            "cross-owner attempts must not consume the source"
        );
    }

    #[test]
    fn owned_opaque_multi_ref_rejection_is_atomic_and_owner_replays_are_exact() {
        let source = opaque_reference(b"source", 211);
        let display = opaque_reference(b"display", 212);
        let owner_a = BulkTransferOwner::for_attached_identity(Uuid::from_u128(3), b"actor-a");
        let owner_b = BulkTransferOwner::for_attached_identity(Uuid::from_u128(3), b"actor-b");

        let source_first =
            write_chunk_owned(&source, &owner_a, 0, b"source").expect("source is staged");
        assert_eq!(
            write_chunk_owned(&source, &owner_a, 0, b"source")
                .expect("exact owner replay is idempotent"),
            source_first
        );
        write_chunk_owned(&display, &owner_b, 0, b"display").expect("display is staged");

        assert!(matches!(
            take_all_owned(&[&source, &display], &owner_a),
            Err(BulkStagingError::UnknownTransfer)
        ));
        assert_eq!(
            take_owned(&source, &owner_a).expect("cross-owner sibling leaves source live"),
            b"source"
        );
        assert_eq!(
            take_owned(&display, &owner_b).expect("other owner keeps its sibling"),
            b"display"
        );
    }

    #[test]
    fn opaque_transfers_cannot_enter_or_leave_staging_without_an_owner() {
        let payload = b"opaque owner proof";
        let reference = opaque_reference(payload, 213);
        let owner = BulkTransferOwner::for_attached_identity(Uuid::from_u128(4), b"actor-a");

        assert!(matches!(
            stage(payload, RemoteBulkMimeClass::Opaque, id(213)),
            Err(BulkStagingError::OwnerMismatch)
        ));
        assert!(matches!(
            write_chunk(&reference, 0, payload),
            Err(BulkStagingError::OwnerMismatch)
        ));

        write_chunk_owned(&reference, &owner, 0, payload).expect("owner stages opaque body");
        assert!(matches!(
            take(&reference),
            Err(BulkStagingError::OwnerMismatch)
        ));
        assert!(matches!(
            read_chunk(*reference.transfer_id.as_bytes(), 0),
            Err(BulkStagingError::UnknownTransfer)
        ));
        assert_eq!(
            take_owned(&reference, &owner).expect("owner consumes opaque body"),
            payload
        );
    }

    #[test]
    fn opaque_transfer_ids_are_namespaced_by_attached_owner() {
        let payload = b"same opaque reference under isolated owners";
        let reference = opaque_reference(payload, 214);
        let owner_a = BulkTransferOwner::for_attached_identity(Uuid::from_u128(5), b"actor-a");
        let owner_b = BulkTransferOwner::for_attached_identity(Uuid::from_u128(6), b"actor-b");

        write_chunk_owned(&reference, &owner_a, 0, payload).expect("first owner stages body");
        write_chunk_owned(&reference, &owner_b, 0, payload)
            .expect("same locator cannot globally squat another owner");
        assert_eq!(take_owned(&reference, &owner_a).unwrap(), payload);
        assert_eq!(take_owned(&reference, &owner_b).unwrap(), payload);
    }

    #[test]
    fn bulk_staging_round_trips_an_export_pull() {
        let payload: Vec<u8> = (0..(STAGED_CHUNK_BYTES * 2 + 17))
            .map(|i| (i % 251) as u8)
            .collect();
        let reference = stage(&payload, RemoteBulkMimeClass::Export, id(1)).unwrap();
        assert_eq!(reference.total_length_value(), payload.len() as u64);

        let before = staged_bytes();
        let total = chunk_count(payload.len() as u64);
        assert_eq!(total, 3);
        let mut pulled = Vec::new();
        for index in 0..total {
            let (chunk, last) = read_chunk(id(1), index).unwrap();
            assert!(chunk.len() <= STAGED_CHUNK_BYTES);
            assert_eq!(last, index + 1 == total);
            pulled.extend_from_slice(&chunk);
        }
        assert_eq!(pulled, payload);
        // The final pull is terminal: the transfer is gone and its reservation
        // released, so repeated exports cannot exhaust the store.
        assert_eq!(
            staged_bytes(),
            before - payload.len() as u64,
            "a completed pull must release its reservation"
        );
        assert!(matches!(
            read_chunk(id(1), 0),
            Err(BulkStagingError::UnknownTransfer)
        ));
        assert!(matches!(
            take(&reference),
            Err(BulkStagingError::UnknownTransfer)
        ));
    }

    #[test]
    fn bulk_staging_take_all_keeps_sibling_references_retryable() {
        let owner = BulkTransferOwner::for_attached_identity(Uuid::from_u128(5), b"actor-a");
        let source = stage_owned(b"source", &owner, id(110)).unwrap();
        let missing = stage_owned(b"display", &owner, id(111)).unwrap();
        discard_owned(id(111), &owner);

        assert!(matches!(
            take_all_owned(&[&source, &missing], &owner),
            Err(BulkStagingError::UnknownTransfer)
        ));
        assert_eq!(
            take_owned(&source, &owner).unwrap(),
            b"source",
            "a missing display sibling must not consume the source"
        );

        let source = stage_owned(b"source", &owner, id(112)).unwrap();
        let display = stage_owned(b"display", &owner, id(113)).unwrap();
        assert_eq!(
            take_all_owned(&[&source, &display], &owner).unwrap(),
            vec![b"source".to_vec(), b"display".to_vec()],
            "all references are returned in request order only after every one validates"
        );
        assert!(matches!(
            take_owned(&source, &owner),
            Err(BulkStagingError::UnknownTransfer)
        ));
    }

    /// A staged redacted-export id can never be swapped for raw bytes under the
    /// redacted reader: restaging the same id (to raw `Export`) is refused, and
    /// the kind-checked read stays atomic so no raw bytes ever ride the reader.
    #[test]
    fn redacted_reader_never_serves_raw_bytes_after_restage_attempt() {
        let redacted = b"redacted export payload".to_vec();
        let raw = b"RAW SECRET payload sk-XXXX".to_vec();
        let key = id(70);
        stage(&redacted, RemoteBulkMimeClass::RedactedExport, key).unwrap();

        // Restaging the same id to raw is rejected, not silently applied.
        assert!(matches!(
            stage(&raw, RemoteBulkMimeClass::Export, key),
            Err(BulkStagingError::DuplicateTransfer)
        ));

        // The redacted reader still serves the ORIGINAL redacted bytes.
        let (chunk, last) =
            read_chunk_of_kind(key, 0, RemoteBulkMimeClass::RedactedExport).unwrap();
        assert!(last);
        assert_eq!(chunk, redacted);
        assert_ne!(chunk, raw);

        // A raw-kinded read of a redacted id is refused (and vice versa).
        let other = id(71);
        stage(&raw, RemoteBulkMimeClass::Export, other).unwrap();
        assert!(matches!(
            read_chunk_of_kind(other, 0, RemoteBulkMimeClass::RedactedExport),
            Err(BulkStagingError::WrongKind)
        ));
        // Untouched: the raw transfer is still readable by the generic reader.
        let (raw_chunk, _) = read_chunk(other, 0).unwrap();
        assert_eq!(raw_chunk, raw);
    }

    /// Repeated full exports must not accumulate. Before the terminal release,
    /// each completed download stayed charged and the store wedged shut.
    #[test]
    fn bulk_staging_completed_exports_do_not_accumulate() {
        let payload = vec![3u8; STAGED_CHUNK_BYTES + 1];
        let baseline = staged_bytes();
        for round in 0..4u8 {
            let key = id(40 + round);
            stage(&payload, RemoteBulkMimeClass::Export, key).unwrap();
            assert!(staged_bytes() > baseline);
            let total = chunk_count(payload.len() as u64);
            for index in 0..total {
                read_chunk(key, index).unwrap();
            }
            assert_eq!(
                staged_bytes(),
                baseline,
                "round {round} must leave the store exactly as it found it"
            );
        }
    }

    /// A declared length is a claim, not a delivery: it reserves capacity but
    /// must never drive an allocation of that size.
    #[test]
    fn bulk_staging_does_not_allocate_from_a_declared_length() {
        let declared = 256 * 1024 * 1024u64;
        let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(id(60))
        .unwrap();
        let reference = RemoteBulkTransferRef::new(
            transfer_id,
            declared,
            digest_of(&[0u8; 0]),
            RemoteBulkMimeClass::Archive,
        )
        .unwrap();

        // One empty chunk against a 256 MiB claim.
        write_chunk(&reference, 0, &[]).unwrap();
        let guard = store().lock().expect("bulk staging poisoned");
        let entry = guard
            .transfers
            .get(&StagedTransferKey::new(id(60), None))
            .expect("staged");
        assert_eq!(entry.bytes.len(), 0);
        assert_eq!(
            entry.bytes.capacity(),
            0,
            "storage must grow with delivered bytes, never with the claim"
        );
        // The reservation is still charged: that is the actual bound.
        assert!(entry.total_length == declared);
        drop(guard);
        discard(id(60));
    }

    /// An abandoned transfer's reservation is reclaimed at the TTL.
    #[test]
    fn bulk_staging_expires_abandoned_transfers() {
        let payload = vec![9u8; 4096];
        let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(id(70))
        .unwrap();
        let reference = RemoteBulkTransferRef::new(
            transfer_id,
            payload.len() as u64 * 4,
            digest_of(&payload),
            RemoteBulkMimeClass::Archive,
        )
        .unwrap();
        let baseline = staged_bytes();
        // Push one chunk, then walk away.
        write_chunk(&reference, 0, &payload).unwrap();
        assert!(staged_bytes() > baseline);

        let started = now_ms();
        assert_eq!(expire(started), 0, "nothing is stale yet");
        assert!(staged_bytes() > baseline);
        assert_eq!(
            expire(started + STAGED_TRANSFER_TTL_MS),
            1,
            "the abandoned transfer must be reclaimed at the TTL"
        );
        assert_eq!(
            staged_bytes(),
            baseline,
            "expiry must release the reservation"
        );
        assert!(matches!(
            take(&reference),
            Err(BulkStagingError::UnknownTransfer)
        ));
    }

    /// The reaper reclaims an abandoned transfer on a daemon that never
    /// performs another staging operation.
    ///
    /// This is the case the opportunistic in-call sweep cannot reach: it fires
    /// only as a side effect of a *later* staging call, and on an idle daemon
    /// none is coming. The test therefore performs exactly one staging call and
    /// then only advances the clock — if the sweep were not scheduled, the
    /// reservation would still be held.
    #[tokio::test(start_paused = true)]
    async fn bulk_staging_reaper_reclaims_on_an_idle_daemon() {
        let payload = vec![3u8; 2048];
        let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(id(90))
        .unwrap();
        let reference = RemoteBulkTransferRef::new(
            transfer_id,
            payload.len() as u64 * 8,
            digest_of(&payload),
            RemoteBulkMimeClass::Archive,
        )
        .unwrap();
        let baseline = staged_bytes();

        // The one and only staging operation in this test.
        write_chunk(&reference, 0, &payload).unwrap();
        assert!(staged_bytes() > baseline, "the reservation is charged");

        let shutdown = crate::daemon::shutdown::ShutdownSignal::new();
        spawn_reaper(shutdown.clone());

        // Nothing touches staging from here on; only time passes.
        tokio::time::advance(Duration::from_millis(
            STAGED_TRANSFER_TTL_MS + STAGED_TRANSFER_REAP_INTERVAL_MS * 2,
        ))
        .await;
        tokio::task::yield_now().await;

        assert_eq!(
            staged_bytes(),
            baseline,
            "an idle daemon must still reclaim an abandoned reservation"
        );
        assert!(matches!(
            take(&reference),
            Err(BulkStagingError::UnknownTransfer)
        ));
    }

    /// A live transfer that is still being fed must never be swept.
    #[tokio::test(start_paused = true)]
    async fn bulk_staging_reaper_does_not_drop_a_live_transfer() {
        let chunk = vec![5u8; 1024];
        let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(id(95))
        .unwrap();
        let total = chunk.len() as u64 * 3;
        let mut whole = Vec::new();
        for _ in 0..3 {
            whole.extend_from_slice(&chunk);
        }
        let reference = RemoteBulkTransferRef::new(
            transfer_id,
            total,
            digest_of(&whole),
            RemoteBulkMimeClass::Archive,
        )
        .unwrap();

        let shutdown = crate::daemon::shutdown::ShutdownSignal::new();
        spawn_reaper(shutdown.clone());

        // Feed a chunk, wait most of the TTL, feed again: each write renews
        // `touched_ms`, so the transfer stays alive across more than one TTL.
        for index in 0..3u32 {
            write_chunk(&reference, index, &chunk).unwrap();
            tokio::time::advance(Duration::from_millis(STAGED_TRANSFER_TTL_MS - 1_000)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(
            take(&reference).unwrap(),
            whole,
            "a transfer being actively fed must survive the reaper"
        );
    }

    /// A transfer that goes quiet for a long — but sub-deadline — interval must
    /// survive and be able to continue.
    ///
    /// The earlier live-transfer test only fed the transfer every `TTL - 1s`,
    /// so it could not distinguish "renewed constantly" from "survives a real
    /// stall". A backpressured peer is idle for a genuine interval and then
    /// resumes; that must work.
    #[tokio::test(start_paused = true)]
    async fn bulk_staging_survives_a_sub_deadline_stall() {
        let chunk = vec![7u8; 512];
        let mut whole = Vec::new();
        for _ in 0..2 {
            whole.extend_from_slice(&chunk);
        }
        let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(id(120))
        .unwrap();
        let reference = RemoteBulkTransferRef::new(
            transfer_id,
            whole.len() as u64,
            digest_of(&whole),
            RemoteBulkMimeClass::Archive,
        )
        .unwrap();

        let shutdown = crate::daemon::shutdown::ShutdownSignal::new();
        spawn_reaper(shutdown.clone());

        write_chunk(&reference, 0, &chunk).unwrap();
        // Stall for almost the whole advertised deadline, with no traffic at
        // all — exactly the backpressure case.
        tokio::time::advance(Duration::from_millis(STAGED_TRANSFER_TTL_MS - 1)).await;
        tokio::task::yield_now().await;

        let resumed = write_chunk(&reference, 1, &chunk)
            .expect("a stall shorter than the advertised deadline must not lose the transfer");
        assert!(resumed.complete);
        assert_eq!(take(&reference).unwrap(), whole);
    }

    /// Zero-length transfers charge no bytes, so only an entry cap bounds them.
    #[test]
    fn bulk_staging_bounds_zero_length_transfer_entries() {
        /// Drains everything this test staged, even if an assertion unwinds.
        ///
        /// The store is process-global, so a test that fills it to the entry
        /// cap and walks away would deny staging to anything that runs later
        /// in the same process.
        struct DrainOnDrop {
            owner: BulkTransferOwner,
            ids: Vec<[u8; 16]>,
        }
        impl Drop for DrainOnDrop {
            fn drop(&mut self) {
                for id in &self.ids {
                    discard_owned(*id, &self.owner);
                }
            }
        }

        let empty_digest = digest_of(&[]);
        let baseline = staged_bytes();
        let owner = BulkTransferOwner::for_attached_identity(Uuid::from_u128(6), b"actor-a");
        let mut staged = DrainOnDrop {
            owner: owner.clone(),
            ids: Vec::new(),
        };
        let mut refused = None;

        // Sustained distinct zero-length transfers from one peer.
        for nth in 0..(MAX_STAGED_TRANSFERS * 2) {
            let mut raw = [0u8; 16];
            raw[0] = 0xC0;
            raw[1..9].copy_from_slice(&(nth as u64).to_be_bytes());
            let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(raw)
            .unwrap();
            let reference = RemoteBulkTransferRef::new(
                transfer_id,
                0,
                empty_digest,
                RemoteBulkMimeClass::Opaque,
            )
            .unwrap();
            match write_chunk_owned(&reference, &owner, 0, &[]) {
                Ok(_) => staged.ids.push(raw),
                Err(error) => {
                    refused = Some(error);
                    break;
                }
            }
        }

        let accepted = staged.ids.len();
        assert!(
            matches!(refused, Some(BulkStagingError::CapacityExceeded)),
            "sustained zero-length transfers must hit a hard entry cap"
        );
        assert!(accepted <= MAX_STAGED_TRANSFERS);
        // They charged no bytes at all, which is exactly why the byte budget
        // could never have stopped them.
        assert_eq!(staged_bytes(), baseline);

        // Draining restores capacity for anything that runs after this.
        drop(staged);
        assert!(
            staged_transfers() < MAX_STAGED_TRANSFERS,
            "the test must not leave the global store full"
        );
    }

    #[test]
    fn bulk_staging_import_push_verifies_digest_and_order() {
        let payload: Vec<u8> = (0..(STAGED_CHUNK_BYTES + 5))
            .map(|i| (i % 97) as u8)
            .collect();
        let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(id(2))
        .unwrap();
        let reference = RemoteBulkTransferRef::new(
            transfer_id,
            payload.len() as u64,
            digest_of(&payload),
            RemoteBulkMimeClass::Archive,
        )
        .unwrap();

        // Out-of-order first chunk is refused.
        assert!(matches!(
            write_chunk(&reference, 1, &payload[..10]),
            Err(BulkStagingError::ChunkIndexGap)
        ));

        let accepted = write_chunk(&reference, 0, &payload[..STAGED_CHUNK_BYTES]).unwrap();
        assert_eq!(accepted.next_chunk_index, 1);
        assert!(!accepted.complete);
        // A gap is refused.
        assert!(matches!(
            write_chunk(&reference, 5, &payload[STAGED_CHUNK_BYTES..]),
            Err(BulkStagingError::ChunkIndexGap)
        ));
        let done = write_chunk(&reference, 1, &payload[STAGED_CHUNK_BYTES..]).unwrap();
        assert!(done.complete);
        assert_eq!(done.received_bytes, payload.len() as u64);
        assert_eq!(take(&reference).unwrap(), payload);
    }

    #[test]
    fn bulk_staging_exact_chunk_replay_is_idempotent_and_mismatches_fail_closed() {
        let first = vec![0x41; STAGED_CHUNK_BYTES];
        let second = b"terminal bulk source".to_vec();
        let mut payload = first.clone();
        payload.extend_from_slice(&second);
        let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(id(31))
        .unwrap();
        let reference = RemoteBulkTransferRef::new(
            transfer_id,
            payload.len() as u64,
            digest_of(&payload),
            RemoteBulkMimeClass::Opaque,
        )
        .unwrap();
        let owner = BulkTransferOwner::for_attached_identity(Uuid::from_u128(7), b"actor-a");

        let accepted = write_chunk_owned(&reference, &owner, 0, &first).unwrap();
        assert_eq!(accepted.next_chunk_index, 1);
        assert_eq!(accepted.received_bytes, first.len() as u64);
        assert!(!accepted.complete);

        // A lost acknowledgement is retried with the same reference and body.
        // It reports the same durable staging frontier and does not duplicate
        // bytes, which makes 64KiB..8MiB remote submission replay safe.
        let replay = write_chunk_owned(&reference, &owner, 0, &first).unwrap();
        assert_eq!(replay, accepted);
        assert!(matches!(
            write_chunk_owned(&reference, &owner, 0, &first[..1]),
            Err(BulkStagingError::ChunkReplayMismatch)
        ));
        assert!(matches!(
            write_chunk_owned(&reference, &owner, 0, b"different"),
            Err(BulkStagingError::ChunkReplayMismatch)
        ));

        let complete = write_chunk_owned(&reference, &owner, 1, &second).unwrap();
        assert!(complete.complete);
        let completed_replay = write_chunk_owned(&reference, &owner, 1, &second).unwrap();
        assert_eq!(completed_replay, complete);
        assert_eq!(take_owned(&reference, &owner).unwrap(), payload);
    }

    #[test]
    fn bulk_staging_reassembles_an_exact_8mib_opaque_user_source() {
        let payload = vec![b'x'; 8 * 1024 * 1024];
        let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(id(32))
        .unwrap();
        let reference = RemoteBulkTransferRef::new(
            transfer_id,
            payload.len() as u64,
            digest_of(&payload),
            RemoteBulkMimeClass::Opaque,
        )
        .unwrap();
        let owner = BulkTransferOwner::for_attached_identity(Uuid::from_u128(8), b"actor-a");

        let expected_chunks = chunk_count(payload.len() as u64);
        assert!(
            expected_chunks > 1,
            "the exact boundary must use bulk chunking"
        );
        for (index, chunk) in payload.chunks(STAGED_CHUNK_BYTES).enumerate() {
            let accepted = write_chunk_owned(&reference, &owner, index as u32, chunk).unwrap();
            assert_eq!(accepted.next_chunk_index, index as u32 + 1);
            assert_eq!(accepted.complete, index as u32 + 1 == expected_chunks);
        }
        assert_eq!(take_owned(&reference, &owner).unwrap(), payload);
    }

    #[test]
    fn bulk_staging_rejects_corrupted_payloads() {
        let payload = vec![7u8; 128];
        let transfer_id = cockpit_proto::bulk_transfer::transfer_id_from_bytes(id(3))
        .unwrap();
        // Reference claims a digest the bytes will not match.
        let reference = RemoteBulkTransferRef::new(
            transfer_id,
            payload.len() as u64,
            [0u8; 32],
            RemoteBulkMimeClass::Opaque,
        )
        .unwrap();
        let owner = BulkTransferOwner::for_attached_identity(Uuid::from_u128(9), b"actor-a");
        assert!(matches!(
            write_chunk_owned(&reference, &owner, 0, &payload),
            Err(BulkStagingError::DigestMismatch)
        ));
        // The failed transfer left nothing behind.
        assert!(matches!(
            take_owned(&reference, &owner),
            Err(BulkStagingError::UnknownTransfer)
        ));
    }

    #[test]
    fn bulk_staging_chunk_fits_one_bulk_lane_payload() {
        // Both sides are constants, so this is a compile-time assertion.
        const { assert!(STAGED_CHUNK_BYTES <= cockpit_proto::bulk_transfer::MAX_BULK_CHUNK_PAYLOAD_BYTES) };
        // Base64 of a full chunk stays within the advertised chunk bound.
        const {
            assert!(
                4 * STAGED_CHUNK_BYTES.div_ceil(3)
                    <= cockpit_proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES
            )
        };
    }
}
