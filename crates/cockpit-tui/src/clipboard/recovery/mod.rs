//! Opt-in private clipboard recovery artifact.
//!
//! When `tui.clipboard_recovery` is [`ClipboardRecovery::PrivateFile`], the
//! central clipboard delivery service ([`crate::clipboard::ClipboardService`])
//! writes one bounded, owner-only recovery file every time a copy fails or
//! lands unverified (an unacknowledged OSC52 emission). `Off` — the default —
//! performs zero content filesystem operations: [`observe_delivery`] returns
//! immediately without touching the directory at all.
//!
//! Every containment/ownership check that decides whether an on-disk entry
//! is safe to open, keep, or must be reported (and never touched) lives in
//! [`policy`] as pure, syscall-free functions; [`unix`] and [`windows`]
//! populate the platform stat structs from real OS state and defer to it.
//! [`doctor`] reports only metadata (presence, age, size, unsafe-entry
//! count) — never artifact content.

mod doctor;
mod policy;
#[cfg(test)]
mod tests;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix::{CheckedEntry, DirHandle};
#[cfg(windows)]
use windows::{CheckedEntry, DirHandle};

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rand::Rng;

pub use cockpit_config::extended::ClipboardRecovery;
pub use doctor::doctor_lines;
pub use policy::Violation;

use crate::clipboard::types::Confidence;

/// 1 MiB cap on the recovered content. A request over this cap is skipped
/// entirely — never truncated, never partially written.
pub const MAX_ARTIFACT_BYTES: usize = 1024 * 1024;

/// A live artifact older than this is treated as expired and is pruned on
/// the next reconcile (write or startup) rather than kept indefinitely.
pub const ARTIFACT_EXPIRY: Duration = Duration::from_secs(10 * 60);

const RECOVERY_DIR_NAME: &str = "clipboard-recovery";

/// Why no artifact was written. Never carries content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    RecoveryOff,
    ContentConfirmedDelivered,
    ContentEmpty,
    ContentTooLarge,
}

/// Result of one [`observe_delivery`] call. Never carries content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    Skipped(SkipReason),
    Written { unsafe_entries_reported: usize },
    WriteFailed,
}

/// The real, per-user recovery directory: under Cockpit's state directory,
/// outside any workspace, owner-only.
pub fn recovery_dir_path() -> io::Result<PathBuf> {
    let state = cockpit_config::config::resolve::cockpit_state_dir()
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(state.join(RECOVERY_DIR_NAME))
}

/// Central hook: called by the clipboard delivery service after every
/// request completes, with its final [`Confidence`]. `content` is the
/// plain text that was attempted; it is either written verbatim to the
/// bounded private artifact or never touches storage at all — it is never
/// logged, returned, or included in any error produced here.
pub fn observe_delivery(
    mode: ClipboardRecovery,
    confidence: Confidence,
    content: &str,
) -> RecoveryOutcome {
    if let Some(reason) = skip_reason(mode, confidence, content) {
        return RecoveryOutcome::Skipped(reason);
    }
    match recovery_dir_path() {
        Ok(dir) => observe_delivery_write(&dir, content),
        Err(_) => RecoveryOutcome::WriteFailed,
    }
}

/// The no-I/O half of [`observe_delivery`]'s dispatch: whether this
/// delivery should be skipped, and why. Pulled out (rather than inlined)
/// so it is directly unit-testable without ever touching a filesystem —
/// and so a directory-injecting test exercises this exact function, not a
/// hand-copied reimplementation of it that could silently drift from the
/// real dispatch.
fn skip_reason(
    mode: ClipboardRecovery,
    confidence: Confidence,
    content: &str,
) -> Option<SkipReason> {
    if mode == ClipboardRecovery::Off {
        return Some(SkipReason::RecoveryOff);
    }
    if matches!(confidence, Confidence::Confirmed) {
        return Some(SkipReason::ContentConfirmedDelivered);
    }
    if content.is_empty() {
        return Some(SkipReason::ContentEmpty);
    }
    if content.len() > MAX_ARTIFACT_BYTES {
        return Some(SkipReason::ContentTooLarge);
    }
    None
}

/// The I/O half of [`observe_delivery`]'s dispatch, with the directory
/// injectable so tests exercise the real write path against a scratch
/// directory instead of the real per-user one.
fn observe_delivery_write(dir: &Path, content: &str) -> RecoveryOutcome {
    match write_artifact(dir, content.as_bytes()) {
        Ok(report) => RecoveryOutcome::Written {
            unsafe_entries_reported: report.unsafe_entries_reported,
        },
        Err(_) => RecoveryOutcome::WriteFailed,
    }
}

/// Outcome of writing a new artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteReport {
    pub unsafe_entries_reported: usize,
}

/// Write a new artifact, replacing the previous live one.
///
/// Order matters, and every barrier in it is a real durability barrier, not
/// just a write ordering:
/// 1. Create + write + fsync the new file's *data*.
/// 2. fsync the *directory* — without this, the new file's directory entry
///    is not guaranteed durable even though its data is, and a crash could
///    persist a later retirement without ever persisting the addition,
///    destroying the only recovery copy. This barrier is propagated as a
///    hard error, never swallowed, because the caller must not believe the
///    artifact is safely written when it might not be.
/// 3. Only now retire every previously-verified artifact (re-verified
///    immediately before each removal — see [`retire_verified`]).
/// 4. fsync the directory again so the retirement(s) are durable too.
///
/// A crash between steps 2 and 4 leaves two valid artifacts rather than
/// zero; the next reconcile (the next write, or [`reconcile_startup`])
/// collapses that back to one.
pub fn write_artifact(dir_root: &Path, bytes: &[u8]) -> io::Result<WriteReport> {
    let dir = DirHandle::open_or_create(dir_root)?;
    let inspected = inspect(&dir)?;

    let name = random_artifact_name();
    let mut file = dir.create_file_exclusive(&name)?;
    if let Err(error) = std::io::Write::write_all(&mut file, bytes) {
        drop(file);
        // M1: an ENOSPC/EIO partial write must not leave a fresh,
        // perfectly-permissioned-but-truncated file for a later reconcile
        // to accept as valid.
        let _ = dir.remove_file(&name);
        return Err(error);
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        let _ = dir.remove_file(&name);
        return Err(error);
    }
    drop(file);

    // Barrier 2: the new entry must be durable before anything is retired.
    dir.sync()?;

    // Retire every previously-verified artifact only now that the new one
    // is durable. Unsafe entries were never opened above and are never
    // touched here either — they are reported by count only.
    retire_verified(&dir, inspected.verified_newest_first)?;

    // Barrier 4: the retirement(s) are durable too.
    dir.sync()?;

    Ok(WriteReport {
        unsafe_entries_reported: inspected.unsafe_entries_reported,
    })
}

/// Remove every entry in `stale`, re-verifying each one immediately before
/// removal (M5) and tying the actual deletion to that verified object
/// rather than to its name a second time (the follow-up finding on M5):
/// an `inspect()` result can go stale between the scan and the removal,
/// and — on Unix — even a fresh re-verification-by-name can itself go
/// stale in the gap before the subsequent by-name `unlinkat`. Both
/// platform `remove_verified` implementations close that as tightly as
/// their OS allows: Windows deletes via the still-open verified handle
/// itself (`FileDispositionInfo`, no reopen, no gap at all); Unix — which
/// has no fd-based unlink — re-checks the verified handle's own identity
/// immediately adjacent to the `unlinkat` call rather than trusting a
/// scan-time record. Either way, a name that no longer identifies the
/// verified object is left exactly as found, never unlinked on the
/// strength of an earlier check alone.
fn retire_verified(dir: &DirHandle, stale: Vec<VerifiedEntry>) -> io::Result<()> {
    for entry in stale {
        if let CheckedEntry::Ok(verified) = dir.open_file_verified(&entry.name)? {
            dir.remove_verified(&entry.name, verified)?;
        }
    }
    Ok(())
}

/// Report from a startup/idempotent reconcile pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileReport {
    pub kept: bool,
    pub removed: usize,
    pub unsafe_entries_reported: usize,
}

/// Verify every entry, keep only the newest non-expired verified artifact,
/// and remove every other verified entry (crash duplicates, expired
/// artifacts). Unsafe entries are reported by count and never opened
/// further or deleted. Safe to call repeatedly — a second call with
/// nothing left to prune is a no-op.
pub fn reconcile_startup(dir_root: &Path) -> io::Result<ReconcileReport> {
    let dir = DirHandle::open_or_create(dir_root)?;
    let mut inspected = inspect(&dir)?;
    let kept = !inspected.verified_newest_first.is_empty()
        && !is_expired(inspected.verified_newest_first[0].mtime);
    let to_remove = if kept {
        inspected.verified_newest_first.split_off(1)
    } else {
        std::mem::take(&mut inspected.verified_newest_first)
    };
    let removed = to_remove.len();
    retire_verified(&dir, to_remove)?;
    // Propagated, not swallowed: a caller (startup, or `/doctor` triggering
    // a manual reconcile) must know when the cleanup itself did not
    // durably land, the same durability-honesty requirement as
    // `write_artifact`'s barriers.
    dir.sync()?;
    Ok(ReconcileReport {
        kept,
        removed,
        unsafe_entries_reported: inspected.unsafe_entries_reported,
    })
}

/// Metadata-only status for `/doctor`. Never opens the artifact for
/// reading and never returns its bytes — only presence, age, size, and the
/// count of entries that failed containment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactStatus {
    pub present: bool,
    pub age: Option<Duration>,
    pub expired: bool,
    pub size_bytes: Option<u64>,
    pub unsafe_entries_reported: usize,
}

/// Read-only inspection: performs no writes, no deletes, never reads
/// artifact content, and — unlike [`write_artifact`]/[`reconcile_startup`]
/// — never creates the recovery directory if it does not already exist
/// (a `/doctor` check must not be the thing that first brings a
/// content-bearing directory into existence).
pub fn artifact_status(dir_root: &Path) -> io::Result<ArtifactStatus> {
    if !dir_root.exists() {
        return Ok(ArtifactStatus {
            present: false,
            age: None,
            expired: false,
            size_bytes: None,
            unsafe_entries_reported: 0,
        });
    }
    let dir = DirHandle::open_or_create(dir_root)?;
    let inspected = inspect(&dir)?;
    match inspected.verified_newest_first.first() {
        None => Ok(ArtifactStatus {
            present: false,
            age: None,
            expired: false,
            size_bytes: None,
            unsafe_entries_reported: inspected.unsafe_entries_reported,
        }),
        Some(entry) => {
            let age = SystemTime::now()
                .duration_since(entry.mtime)
                .unwrap_or(Duration::ZERO);
            Ok(ArtifactStatus {
                present: true,
                age: Some(age),
                expired: is_expired(entry.mtime),
                size_bytes: Some(entry.size_bytes),
                unsafe_entries_reported: inspected.unsafe_entries_reported,
            })
        }
    }
}

struct VerifiedEntry {
    name: String,
    mtime: SystemTime,
    size_bytes: u64,
}

struct Inspection {
    /// Verified-safe entries, newest first.
    verified_newest_first: Vec<VerifiedEntry>,
    unsafe_entries_reported: usize,
}

/// Test-only read-tracking seam: counts every byte-level `Read::read` call
/// made through [`ReadTrackedFile`], so `doctor`/`inspect` tests can prove
/// — at runtime, not just by inspecting rendered output — that content is
/// never read, not merely that it never leaked into a string. Zero-cost in
/// production: outside `#[cfg(test)]`, [`inspect`] never wraps the file at
/// all and this counter does not exist.
#[cfg(test)]
pub(crate) static ARTIFACT_CONTENT_READS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
struct ReadTrackedFile(std::fs::File);

#[cfg(test)]
impl std::ops::Deref for ReadTrackedFile {
    type Target = std::fs::File;
    fn deref(&self) -> &std::fs::File {
        &self.0
    }
}

#[cfg(test)]
impl io::Read for ReadTrackedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        ARTIFACT_CONTENT_READS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.0.read(buf)
    }
}

/// List, reopen, and verify every entry. Read-only: never deletes, never
/// reads file content, only stats each verified handle.
fn inspect(dir: &DirHandle) -> io::Result<Inspection> {
    let mut verified = Vec::new();
    let mut unsafe_count = 0usize;
    for name in dir.list_names()? {
        match dir.open_file_verified(&name)? {
            CheckedEntry::Missing => {}
            CheckedEntry::Unsafe => unsafe_count += 1,
            CheckedEntry::Ok(file) => {
                // In test builds, `file` is a read-tracking wrapper: it
                // still stats fine via `Deref`, but a `Read::read` call
                // anywhere in this arm — today or in a future edit — is
                // now something a test can actually observe.
                #[cfg(test)]
                let file = ReadTrackedFile(file);
                let metadata = file.metadata()?;
                let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                verified.push(VerifiedEntry {
                    name,
                    mtime,
                    size_bytes: metadata.len(),
                });
            }
        }
    }
    verified.sort_by_key(|entry| std::cmp::Reverse(entry.mtime));
    Ok(Inspection {
        verified_newest_first: verified,
        unsafe_entries_reported: unsafe_count,
    })
}

fn is_expired(mtime: SystemTime) -> bool {
    SystemTime::now()
        .duration_since(mtime)
        .map(|age| age > ARTIFACT_EXPIRY)
        .unwrap_or(false)
}

/// A random, non-content-derived artifact file name.
fn random_artifact_name() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let mut name = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(name, "{byte:02x}");
    }
    name
}
