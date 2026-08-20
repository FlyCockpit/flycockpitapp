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

use cockpit_proto::remote_transport::bulk::{
    MAX_TRANSFER_BYTES, RemoteBulkMimeClass, RemoteBulkTransferRef,
};
use cockpit_proto::remote_transport::lane::BULK_MAX_PAYLOAD_BYTES;
use sha2::{Digest as _, Sha256};

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

const _: () = assert!(STAGED_CHUNK_BYTES < BULK_MAX_PAYLOAD_BYTES);

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
}

#[derive(Debug)]
struct StagedTransfer {
    total_length: u64,
    sha256: [u8; 32],
    mime_class: RemoteBulkMimeClass,
    bytes: Vec<u8>,
    next_chunk_index: u32,
    complete: bool,
    /// Monotonic milliseconds at the last operation that touched this transfer.
    touched_ms: u64,
}

#[derive(Debug, Default)]
struct Store {
    transfers: HashMap<[u8; 16], StagedTransfer>,
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
    fn remove(&mut self, key: &[u8; 16]) -> Option<StagedTransfer> {
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

/// Stage bytes the daemon produced (export) and return their reference.
pub fn stage(
    bytes: &[u8],
    mime_class: RemoteBulkMimeClass,
    transfer_id_bytes: [u8; 16],
) -> Result<RemoteBulkTransferRef, BulkStagingError> {
    let total_length = bytes.len() as u64;
    if total_length > mime_class.max_total_length() || total_length > MAX_TRANSFER_BYTES {
        return Err(BulkStagingError::ClassLimit);
    }
    let sha256 = digest_of(bytes);
    let now = now_ms();
    let mut guard = store().lock().expect("bulk staging poisoned");
    guard.expire(now);
    // A staged id is immutable identity: refuse to overwrite a live transfer.
    // Silently replacing it would let a redacted-export id be restaged as a raw
    // `Export` (or vice versa) under a reader that already verified its kind.
    if guard.transfers.contains_key(&transfer_id_bytes) {
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
        transfer_id_bytes,
        StagedTransfer {
            total_length,
            sha256,
            mime_class,
            bytes: bytes.to_vec(),
            next_chunk_index: chunk_count(total_length),
            complete: true,
            touched_ms: now,
        },
    );
    drop(guard);

    let transfer_id = cockpit_proto::remote_protocol_id::tag_protocol_id_bytes::<
        cockpit_proto::remote_protocol_id::kind::Transfer,
    >(transfer_id_bytes)
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
    if chunk.len() > STAGED_CHUNK_BYTES {
        return Err(BulkStagingError::ChunkTooLarge);
    }
    let total_length = reference.total_length_value();
    if total_length > reference.mime_class.max_total_length() {
        return Err(BulkStagingError::ClassLimit);
    }
    let key = *reference.transfer_id.as_bytes();
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
            key,
            StagedTransfer {
                total_length,
                sha256: reference.sha256,
                mime_class: reference.mime_class,
                // Deliberately *not* `with_capacity(total_length)`: the length
                // is a peer's claim, not a delivery. Storage grows with bytes
                // that actually arrive, so declaring 512 MiB and sending one
                // empty chunk costs a reservation, never 512 MiB of memory.
                bytes: Vec::new(),
                next_chunk_index: 0,
                complete: false,
                touched_ms: now,
            },
        );
    }

    let entry = guard.transfers.get_mut(&key).expect("present");
    if entry.complete {
        // A completed transfer is terminal; a late chunk cannot reopen it.
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
    let entry = guard
        .transfers
        .get_mut(&transfer_id_bytes)
        .ok_or(BulkStagingError::UnknownTransfer)?;
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
        guard.remove(&transfer_id_bytes);
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
    let entry = guard
        .transfers
        .get_mut(&transfer_id_bytes)
        .ok_or(BulkStagingError::UnknownTransfer)?;
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
        guard.remove(&transfer_id_bytes);
    }
    Ok((chunk, last))
}

/// Take a completed transfer's bytes, verifying length and digest first.
pub fn take(reference: &RemoteBulkTransferRef) -> Result<Vec<u8>, BulkStagingError> {
    let key = *reference.transfer_id.as_bytes();
    let now = now_ms();
    let mut guard = store().lock().expect("bulk staging poisoned");
    guard.expire(now);
    let entry = guard
        .transfers
        .get(&key)
        .ok_or(BulkStagingError::UnknownTransfer)?;
    if !entry.complete {
        return Err(BulkStagingError::Incomplete);
    }
    if entry.total_length != reference.total_length_value() {
        return Err(BulkStagingError::LengthOverrun);
    }
    if entry.sha256 != reference.sha256 || digest_of(&entry.bytes) != reference.sha256 {
        return Err(BulkStagingError::DigestMismatch);
    }
    // The class is part of the transfer's identity: a reference may not be
    // re-labelled to borrow a larger class limit.
    if entry.mime_class != reference.mime_class {
        return Err(BulkStagingError::ClassLimit);
    }
    let removed = guard.remove(&key).expect("present");
    Ok(removed.bytes)
}

/// Drop a staged transfer without reading it (cancellation / cleanup).
pub fn discard(transfer_id_bytes: [u8; 16]) {
    let mut guard = store().lock().expect("bulk staging poisoned");
    guard.remove(&transfer_id_bytes);
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
        let transfer_id = cockpit_proto::remote_protocol_id::tag_protocol_id_bytes::<
            cockpit_proto::remote_protocol_id::kind::Transfer,
        >(id(60))
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
        let entry = guard.transfers.get(&id(60)).expect("staged");
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
        let transfer_id = cockpit_proto::remote_protocol_id::tag_protocol_id_bytes::<
            cockpit_proto::remote_protocol_id::kind::Transfer,
        >(id(70))
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
        let transfer_id = cockpit_proto::remote_protocol_id::tag_protocol_id_bytes::<
            cockpit_proto::remote_protocol_id::kind::Transfer,
        >(id(90))
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
        let transfer_id = cockpit_proto::remote_protocol_id::tag_protocol_id_bytes::<
            cockpit_proto::remote_protocol_id::kind::Transfer,
        >(id(95))
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
        let transfer_id = cockpit_proto::remote_protocol_id::tag_protocol_id_bytes::<
            cockpit_proto::remote_protocol_id::kind::Transfer,
        >(id(120))
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
        struct DrainOnDrop(Vec<[u8; 16]>);
        impl Drop for DrainOnDrop {
            fn drop(&mut self) {
                for id in &self.0 {
                    discard(*id);
                }
            }
        }

        let empty_digest = digest_of(&[]);
        let baseline = staged_bytes();
        let mut staged = DrainOnDrop(Vec::new());
        let mut refused = None;

        // Sustained distinct zero-length transfers from one peer.
        for nth in 0..(MAX_STAGED_TRANSFERS * 2) {
            let mut raw = [0u8; 16];
            raw[0] = 0xC0;
            raw[1..9].copy_from_slice(&(nth as u64).to_be_bytes());
            let transfer_id = cockpit_proto::remote_protocol_id::tag_protocol_id_bytes::<
                cockpit_proto::remote_protocol_id::kind::Transfer,
            >(raw)
            .unwrap();
            let reference = RemoteBulkTransferRef::new(
                transfer_id,
                0,
                empty_digest,
                RemoteBulkMimeClass::Opaque,
            )
            .unwrap();
            match write_chunk(&reference, 0, &[]) {
                Ok(_) => staged.0.push(raw),
                Err(error) => {
                    refused = Some(error);
                    break;
                }
            }
        }

        let accepted = staged.0.len();
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
        let transfer_id = cockpit_proto::remote_protocol_id::tag_protocol_id_bytes::<
            cockpit_proto::remote_protocol_id::kind::Transfer,
        >(id(2))
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
    fn bulk_staging_rejects_corrupted_payloads() {
        let payload = vec![7u8; 128];
        let transfer_id = cockpit_proto::remote_protocol_id::tag_protocol_id_bytes::<
            cockpit_proto::remote_protocol_id::kind::Transfer,
        >(id(3))
        .unwrap();
        // Reference claims a digest the bytes will not match.
        let reference = RemoteBulkTransferRef::new(
            transfer_id,
            payload.len() as u64,
            [0u8; 32],
            RemoteBulkMimeClass::Opaque,
        )
        .unwrap();
        assert!(matches!(
            write_chunk(&reference, 0, &payload),
            Err(BulkStagingError::DigestMismatch)
        ));
        // The failed transfer left nothing behind.
        assert!(matches!(
            take(&reference),
            Err(BulkStagingError::UnknownTransfer)
        ));
    }

    #[test]
    fn bulk_staging_chunk_fits_one_bulk_lane_payload() {
        // Both sides are constants, so this is a compile-time assertion.
        const { assert!(STAGED_CHUNK_BYTES < BULK_MAX_PAYLOAD_BYTES) };
        // Base64 of a full chunk stays within the advertised chunk bound.
        const {
            assert!(
                4 * STAGED_CHUNK_BYTES.div_ceil(3)
                    <= cockpit_proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES
            )
        };
    }
}
