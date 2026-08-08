//! Cross-platform atomic no-clobber file publication for `/copy … file
//! <path>`.
//!
//! Every platform implementation opens (and, for the leaf directory,
//! verifies) the destination's parent directory once, without following a
//! symlink/reparse point, and keeps that single opened identity for every
//! subsequent operation: creating the same-directory temp file, writing and
//! flushing it, and publishing it under the final name. There is no
//! check-then-rename anywhere in this module — the "does the target exist"
//! answer always comes from the one atomic publish primitive itself
//! (`renameat2(RENAME_NOREPLACE)`/`linkat` on Linux, `renameatx_np(...,
//! RENAME_EXCL)` on macOS, `SetFileInformationByHandle(FileRenameInfoEx)`
//! without `FILE_RENAME_FLAG_REPLACE_IF_EXISTS` on Windows), so an existing
//! target, a target that appears mid-operation, or a parent swapped for a
//! symlink/junction all fail the same way: the target is preserved and
//! nothing is overwritten.
//!
//! If the running OS lacks the required primitive,
//! [`PublishError::UnsupportedAtomicNoClobber`] is returned — there is no
//! overwrite/check-then-rename fallback, ever.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

/// 1 MiB cap on the `/copy … file` payload. Enforced here (not only at the
/// slash-command parser) so any caller of [`publish_no_clobber`] gets the
/// same bound.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// A successful publication. Carries only metadata — never the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub path: PathBuf,
    pub bytes_written: u64,
    /// `false` only on Unix, only when the atomic rename itself succeeded
    /// (the target now exists under its final name with the right bytes)
    /// but the follow-up parent-directory fsync failed — durability of
    /// that fact is unconfirmed, though the write is real. Always `true`
    /// on Windows, which has no separate directory-fsync step to fail
    /// independently of the rename. Callers must show this differently
    /// from an ordinary success, and MUST NOT show it as a failure: the
    /// file is genuinely on disk either way.
    pub durability_confirmed: bool,
}

/// Every failure mode. Every variant is safe to show in a toast/error: none
/// of them can carry copied plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    /// The target name is already in use (existing file, directory,
    /// symlink/reparse point, or one that appeared during the race window)
    /// — preserved untouched.
    TargetExists,
    /// The parent directory does not exist. Parent creation is out of
    /// scope — the destination directory must already exist.
    ParentMissing,
    /// The parent path resolves to something other than a directory
    /// (including a symlink/junction/reparse point at the parent itself).
    ParentNotADirectory,
    /// The payload exceeds [`MAX_PAYLOAD_BYTES`].
    PayloadTooLarge { max: usize },
    /// The running OS/filesystem lacks the required atomic no-clobber
    /// primitive. Never a signal to fall back to overwrite or
    /// check-then-rename — those paths do not exist in this module.
    UnsupportedAtomicNoClobber,
    /// Cancelled before publication; only the verified temp file (never the
    /// target) was removed.
    Cancelled,
    /// Any other I/O failure, reduced to a content-free message (path and
    /// OS error text only — never the payload).
    Io(String),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetExists => write!(f, "target already exists"),
            Self::ParentMissing => write!(f, "parent directory does not exist"),
            Self::ParentNotADirectory => write!(f, "parent path is not a directory"),
            Self::PayloadTooLarge { max } => write!(f, "payload exceeds {max} bytes"),
            Self::UnsupportedAtomicNoClobber => {
                write!(
                    f,
                    "atomic no-clobber file publication is not supported here"
                )
            }
            Self::Cancelled => write!(f, "cancelled"),
            Self::Io(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for PublishError {}

/// Publish `bytes` to `target` with an exact atomic no-clobber guarantee.
///
/// `target`'s parent directory must already exist; this function never
/// creates it. On success, `target` did not exist a moment before this call
/// returned and now contains exactly `bytes`, fully flushed. On any
/// [`PublishError`], `target` is exactly as it was before the call.
///
/// `is_cancelled` is checked exactly once, after the temp file is written
/// and fsynced but before the atomic publish step. If it returns `true` at
/// that checkpoint, only the verified temp file is removed and this
/// returns [`PublishError::Cancelled`] — the target name is never touched
/// either way. Once that checkpoint has passed, cancellation has no more
/// effect: the call proceeds to publish and reports success.
pub fn publish_no_clobber(
    target: &Path,
    bytes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Published, PublishError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(PublishError::PayloadTooLarge {
            max: MAX_PAYLOAD_BYTES,
        });
    }
    #[cfg(unix)]
    {
        unix::publish(target, bytes, is_cancelled)
    }
    #[cfg(windows)]
    {
        windows::publish(target, bytes, is_cancelled)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, bytes, is_cancelled);
        Err(PublishError::UnsupportedAtomicNoClobber)
    }
}
