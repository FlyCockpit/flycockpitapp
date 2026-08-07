//! Unix atomic no-clobber publish: openat-relative temp create, then a
//! single no-replace rename under the held parent directory descriptor.
//!
//! Linux gets `renameat2(RENAME_NOREPLACE)`, falling back to `linkat` +
//! verified temp `unlinkat` only on `ENOSYS`/`EINVAL` (a kernel/filesystem
//! that lacks the syscall) — never on `EEXIST`, which is the real "target
//! exists" answer both primitives agree on. macOS uses
//! `renameatx_np(..., RENAME_EXCL)`, both names resolved through the same
//! held parent descriptor; `renamex_np`/path-based `rename` are never used.
//! Every other Unix falls back to `linkat` + `unlinkat`, the POSIX-portable
//! no-replace primitive.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use super::{Published, PublishError};

fn cstring(component: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(component.as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path component"))
}

/// A held, no-follow parent-directory descriptor plus the verified basename
/// to publish under.
struct OpenedParent {
    dir: File,
    parent_dir: PathBuf,
    dest_name: CString,
}

fn open_parent_nofollow(target: &Path) -> Result<OpenedParent, PublishError> {
    let parent = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = target
        .file_name()
        .ok_or_else(|| PublishError::Io("target has no file name".to_string()))?;
    // Open the *original*, uncanonicalized parent path directly with
    // `O_NOFOLLOW`. This matters: `O_NOFOLLOW` only ever protects the final
    // path component, so calling `std::fs::canonicalize` first — which
    // resolves every symlink, including the leaf — before opening would
    // silently defeat it (the open would then see the *already-resolved*
    // real path and have nothing left to refuse). Ancestor components may
    // still be symlinks (e.g. macOS's `/var` -> `/private/var`); only the
    // parent directory itself must not be.
    let parent_c = cstring(parent.as_os_str()).map_err(|e| PublishError::Io(e.to_string()))?;
    // SAFETY: `parent_c` is a live NUL-terminated string for the call; the
    // returned fd is transferred exactly once into `File`.
    let fd = unsafe {
        libc::open(
            parent_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(libc::ENOTDIR) | Some(libc::ELOOP) => PublishError::ParentNotADirectory,
            Some(libc::ENOENT) => PublishError::ParentMissing,
            _ => PublishError::Io(format!("opening parent directory: {error}")),
        });
    }
    // SAFETY: `fd` was just returned by `open` and is uniquely owned.
    let dir = unsafe { File::from_raw_fd(fd) };
    let dest_name = cstring(name).map_err(|e| PublishError::Io(e.to_string()))?;
    Ok(OpenedParent {
        dir,
        parent_dir: parent.to_path_buf(),
        dest_name,
    })
}

/// Create a same-directory, randomly named temp file: `O_CREAT|O_EXCL|
/// O_NOFOLLOW`, mode `0600`.
fn create_temp_exclusive(parent: &File) -> io::Result<(File, CString)> {
    let mut rng_bytes = [0u8; 16];
    {
        use rand::Rng;
        rand::rng().fill_bytes(&mut rng_bytes);
    }
    let mut name = String::from(".cockpit-copy-");
    use std::fmt::Write as _;
    for byte in rng_bytes {
        let _ = write!(name, "{byte:02x}");
    }
    name.push_str(".tmp");
    let cname = CString::new(name).expect("hex temp name has no NUL");
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `parent` is a live descriptor and `cname` stays alive for the
    // call.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            cname.as_ptr(),
            flags,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `openat` and is uniquely owned.
    Ok((unsafe { File::from_raw_fd(fd) }, cname))
}

/// A file's identity for the purpose of noticing a name got swapped out
/// from under us: (device, inode). Never the content.
fn file_identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    (metadata.dev(), metadata.ino())
}

/// Reopen `name` relative to `parent` (no-follow) and return its identity,
/// without ever reading its content.
fn reopen_and_identify(parent: &File, name: &CStr) -> io::Result<(u64, u64)> {
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `parent` is live and `name` stays alive for the call.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `openat` and is uniquely owned.
    let file = unsafe { File::from_raw_fd(fd) };
    Ok(file_identity(&file.metadata()?))
}

fn unlink_temp(parent: &File, name: &CStr) {
    // SAFETY: `parent` is live and `name` stays alive for the call. Removal
    // of our own not-yet-published temp file; failure is best-effort (the
    // file is orphaned, never the caller's target).
    unsafe {
        libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0);
    }
}

/// The exact platform no-replace publish primitive, abstracted so tests can
/// assert the syscall/flag contract (which syscall, which flag, no
/// replace-if-exists) without a real filesystem, and simulate a kernel
/// that lacks `renameat2` (`ENOSYS`/`EINVAL`) without needing one.
pub(super) trait PublishBackend {
    fn rename_no_replace(&mut self, parent_fd: RawFd, from: &CStr, to: &CStr) -> Result<(), BackendError>;
}

/// The three I/O barriers around publication that are *not* the rename
/// itself, abstracted the same way as [`PublishBackend`] so each one is
/// independently injectable in tests: a short/failed write, a failed temp
/// -file fsync, and a failed parent-directory fsync (the barrier this
/// module's durability guarantee actually rests on) all need their own
/// coverage, not just the rename step. Default methods delegate to the
/// real syscalls, so [`RealIo`] needs no code of its own; a test-only fake
/// overrides exactly the one method it wants to fail.
pub(super) trait PublishIo {
    fn write_payload(&mut self, temp: &mut File, bytes: &[u8]) -> io::Result<()> {
        std::io::Write::write_all(temp, bytes)
    }
    fn sync_temp(&mut self, temp: &File) -> io::Result<()> {
        temp.sync_all()
    }
    fn sync_parent(&mut self, parent: &File) -> io::Result<()> {
        parent.sync_all()
    }
}

/// The real, unfaked I/O barriers — every method uses [`PublishIo`]'s
/// default (real syscall) implementation.
pub(super) struct RealIo;
impl PublishIo for RealIo {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackendError {
    TargetExists,
    Unsupported,
    Other,
}

/// Linux: `renameat2(RENAME_NOREPLACE)` via the raw syscall (no stable
/// `libc::renameat2` binding exists), falling back to `linkat` + verified
/// `unlinkat` only when the kernel/filesystem lacks the syscall.
#[cfg(target_os = "linux")]
pub(super) struct RealBackend;

#[cfg(target_os = "linux")]
impl PublishBackend for RealBackend {
    fn rename_no_replace(&mut self, parent_fd: RawFd, from: &CStr, to: &CStr) -> Result<(), BackendError> {
        const RENAME_NOREPLACE: libc::c_uint = 1;
        // SAFETY: `parent_fd` is a live descriptor; `from`/`to` stay alive
        // for the call. Same source and destination directory (self-rename
        // within the verified parent), so a single fd is used for both.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent_fd,
                from.as_ptr(),
                parent_fd,
                to.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EEXIST) => Err(BackendError::TargetExists),
            Some(libc::ENOSYS) | Some(libc::EINVAL) => linkat_fallback(parent_fd, from, to),
            _ => Err(BackendError::Other),
        }
    }
}

/// The portable `linkat` + `unlinkat` no-replace pair, used when
/// `renameat2` is unavailable (Linux ENOSYS/EINVAL) and on every other
/// Unix. `linkat` alone never replaces an existing destination — it fails
/// `EEXIST` on its own — but unlike `renameat2` it does not remove `from`;
/// it only adds `to` as a second hard link to the same inode. Every caller
/// of [`PublishBackend`] relies on "Ok means `from` no longer exists" (the
/// real `renameat2` syscall's contract) to know the temp file was consumed
/// rather than left behind holding a duplicate copy of the payload next to
/// the published file, so this function restores that contract itself
/// before returning `Ok`. Not used on macOS, which never falls back to
/// `linkat` (its `renameatx_np` path is used exclusively).
#[cfg(not(target_os = "macos"))]
pub(super) fn linkat_fallback(parent_fd: RawFd, from: &CStr, to: &CStr) -> Result<(), BackendError> {
    // SAFETY: `parent_fd` is a live descriptor; `from`/`to` stay alive for
    // the call.
    let linked = unsafe { libc::linkat(parent_fd, from.as_ptr(), parent_fd, to.as_ptr(), 0) };
    if linked == 0 {
        // Best-effort: if this unlink fails the publish itself already
        // succeeded, so it is still reported as `Ok`, but the orphaned
        // temp is a real (bounded, single-file) leak in that case.
        // SAFETY: same liveness argument as above.
        unsafe {
            libc::unlinkat(parent_fd, from.as_ptr(), 0);
        }
        return Ok(());
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::EEXIST) => Err(BackendError::TargetExists),
        Some(libc::ENOSYS) => Err(BackendError::Unsupported),
        _ => Err(BackendError::Other),
    }
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
pub(super) struct RealBackend;

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
impl PublishBackend for RealBackend {
    fn rename_no_replace(&mut self, parent_fd: RawFd, from: &CStr, to: &CStr) -> Result<(), BackendError> {
        linkat_fallback(parent_fd, from, to)
    }
}

/// macOS: `renameatx_np(..., RENAME_EXCL)`, both names relative to the same
/// verified opened parent directory. Declared manually (rather than
/// depending on the pinned `libc` version exporting it by name) because it
/// is a stable `libSystem` entry point on every supported macOS release —
/// path-based `renamex_np`/`rename` are never used.
#[cfg(target_os = "macos")]
pub(super) struct RealBackend;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn renameatx_np(
        fromfd: libc::c_int,
        from: *const libc::c_char,
        tofd: libc::c_int,
        to: *const libc::c_char,
        flags: libc::c_uint,
    ) -> libc::c_int;
}

#[cfg(target_os = "macos")]
impl PublishBackend for RealBackend {
    fn rename_no_replace(&mut self, parent_fd: RawFd, from: &CStr, to: &CStr) -> Result<(), BackendError> {
        // From <sys/fcntl.h>: RENAME_EXCL fails rather than replacing an
        // existing destination.
        const RENAME_EXCL: libc::c_uint = 0x0004;
        // SAFETY: `parent_fd` is a live descriptor; `from`/`to` stay alive
        // for the call.
        let result =
            unsafe { renameatx_np(parent_fd, from.as_ptr(), parent_fd, to.as_ptr(), RENAME_EXCL) };
        if result == 0 {
            return Ok(());
        }
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::EEXIST) => Err(BackendError::TargetExists),
            Some(libc::ENOSYS) | Some(libc::ENOTSUP) => Err(BackendError::Unsupported),
            _ => Err(BackendError::Other),
        }
    }
}

pub(super) fn publish(
    target: &Path,
    bytes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Published, PublishError> {
    publish_with(&mut RealBackend, &mut RealIo, target, bytes, is_cancelled)
}

pub(super) fn publish_with<B: PublishBackend, IO: PublishIo>(
    backend: &mut B,
    io_ops: &mut IO,
    target: &Path,
    bytes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Published, PublishError> {
    let parent = open_parent_nofollow(target)?;
    let (mut temp, temp_name) =
        create_temp_exclusive(&parent.dir).map_err(|e| PublishError::Io(format!("creating temp file: {e}")))?;

    if let Err(error) = io_ops.write_payload(&mut temp, bytes) {
        unlink_temp(&parent.dir, &temp_name);
        return Err(PublishError::Io(format!("writing temp file: {error}")));
    }
    if let Err(error) = io_ops.sync_temp(&temp) {
        unlink_temp(&parent.dir, &temp_name);
        return Err(PublishError::Io(format!("fsync temp file: {error}")));
    }
    // Capture the temp file's identity (device + inode) before dropping
    // the handle. `rename`/`renameat2`/`linkat` are inherently name-based
    // on Unix (there is no fd-based rename), so between this point and the
    // publish call below, the *name* — not this handle — is what a
    // same-directory-writable attacker could unlink and replace with
    // their own content under the same (128-bit random) name. That would
    // make the eventual name-based rename publish *their* bytes, not
    // ours, while still reporting success. Re-checking identity after
    // publish (below) turns that from a silent content swap into a
    // detected failure.
    let expected_identity = match temp.metadata() {
        Ok(metadata) => file_identity(&metadata),
        Err(error) => {
            unlink_temp(&parent.dir, &temp_name);
            return Err(PublishError::Io(format!("stat temp file: {error}")));
        }
    };
    drop(temp);

    // The one cancellation checkpoint: after the temp file is durable, but
    // before the atomic publish. Before this point there is nothing to
    // cancel (the temp file is not yet visible under any name a caller
    // could observe); after this point, cancellation has no more effect.
    if is_cancelled() {
        unlink_temp(&parent.dir, &temp_name);
        return Err(PublishError::Cancelled);
    }

    let publish_result = backend.rename_no_replace(parent.dir.as_raw_fd(), &temp_name, &parent.dest_name);
    match publish_result {
        Ok(()) => {
            // Re-verify identity: reopen the just-published name (relative
            // to the same held parent, no-follow) and compare its
            // (device, inode) to the temp file we actually wrote. A
            // mismatch means the name was swapped out from under us
            // between the fsync above and this rename — the published
            // bytes are not ours, and this must not report success.
            match reopen_and_identify(&parent.dir, &parent.dest_name) {
                Ok(identity) if identity == expected_identity => {}
                Ok(_) => {
                    return Err(PublishError::Io(
                        "publishing file: published entry identity mismatch (name was replaced during publish)"
                            .to_string(),
                    ));
                }
                Err(error) => {
                    return Err(PublishError::Io(format!(
                        "publishing file: verifying published identity: {error}"
                    )));
                }
            }
            // fsync the parent so the new directory entry is durable. The
            // rename has *already happened* — the target genuinely exists
            // on disk under its final name with the right bytes — so an
            // EIO/ENOSPC here is not the same fact as "nothing was
            // published" and must not be reported through the same `Err`
            // path a caller would read as "the copy failed": that would
            // tell the user their file is missing when it is not. It is
            // also not an ordinary success: the durability of the
            // directory entry itself is unconfirmed. `Published`'s
            // `durability_confirmed` flag carries exactly that
            // distinction to the caller.
            let durability_confirmed = io_ops.sync_parent(&parent.dir).is_ok();
            Ok(Published {
                path: parent.parent_dir.join(target.file_name().unwrap_or_default()),
                bytes_written: bytes.len() as u64,
                durability_confirmed,
            })
        }
        Err(BackendError::TargetExists) => {
            unlink_temp(&parent.dir, &temp_name);
            Err(PublishError::TargetExists)
        }
        Err(BackendError::Unsupported) => {
            unlink_temp(&parent.dir, &temp_name);
            Err(PublishError::UnsupportedAtomicNoClobber)
        }
        Err(BackendError::Other) => {
            unlink_temp(&parent.dir, &temp_name);
            Err(PublishError::Io(
                "atomic no-clobber publish failed".to_string(),
            ))
        }
    }
}
