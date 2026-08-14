//! Fail-closed private filesystem discipline for sensitive local state.
//!
//! On Unix this module enforces owner-only permissions (`0700` directories,
//! `0600` files) through held, no-follow file descriptors: a directory or file
//! is opened `O_NOFOLLOW`, its ownership and mode are verified through the held
//! descriptor (never a re-resolved path), a hard-linked secret is refused, and
//! every failure to establish the guarantee is a typed [`PrivateFsError`] the
//! caller can match on — never a warning followed by `Ok(())`. A pre-existing
//! directory is repaired only when it is self-owned and reached through a
//! no-follow open, then re-verified.
//!
//! Crash-atomic replacement ([`write_private_file`]) is orchestrated above the
//! platform layer and applies on every platform: the payload is written to a
//! temp file in the same directory, fsynced, renamed over the target, and (on
//! Unix) the directory is fsynced.
//!
//! # Platform honesty
//!
//! On non-Unix this build enforces **none** of the security properties above:
//! no no-follow / reparse-point refusal at any component, no handle-anchored
//! verification, no ownership verification, no link-count refusal, no
//! owner-only DACL, and no directory durability barrier. Only the crash-atomic
//! replacement carries over, and it is a durability guarantee, not a security
//! claim. `private-fs-windows-parity` closes that gap; until it lands,
//! [`PRIVATE_FS_POLICY`] reports every security field as `false` there, which
//! is the truth.

use std::path::Path;

use anyhow::{Context, Result};

pub(crate) mod held_directory;

// ------------------------------------------------------------------------
// Typed, matchable, fail-closed errors
// ------------------------------------------------------------------------

/// A private-filesystem guarantee that could not be established.
///
/// Declared complete and uncfg'd, including the variants only the Windows arm
/// will produce once `private-fs-windows-parity` lands, so no caller has to
/// re-match when it does. On non-Unix the security variants are simply never
/// constructed yet.
#[derive(Debug, thiserror::Error)]
pub enum PrivateFsError {
    /// The object exists but its mode/DACL is wrong and could not be corrected.
    #[error("{0}: permissions are insecure and could not be made private")]
    InsecurePermissions(String),
    /// A symlink or reparse point, an unsafe path component, a non-absolute
    /// root, a `..` component, or a wrong file type.
    #[error("{0}: refused for containment")]
    Containment(String),
    /// `st_uid` is not the effective uid (Unix), or the DACL does not verify as
    /// cockpit-owned (Windows).
    #[error("{0}: not owned by this user")]
    NotOwned(String),
    /// The link count is not 1: a hard-linked secret can never be made private
    /// because the other link may live in a directory the attacker controls.
    #[error("{0}: has more than one hard link")]
    MultiplyLinked(String),
    /// Any other I/O failure, carrying its context and the underlying error.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

impl PrivateFsError {
    fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

// ------------------------------------------------------------------------
// Pure ownership / containment verdict (platform-independent)
// ------------------------------------------------------------------------

/// What a held object is, for the ownership verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

/// The mode/DACL outcome, supplied as a *parameter* so the verdict is a pure
/// function testable without a foreign uid, and so `private-fs-windows-parity`
/// can plug its DACL verdict into the same seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionOutcome {
    Private,
    Insecure,
}

/// Pure ownership/containment verdict over a held object's stat facts.
///
/// Platform-independent and total; unit-tested exhaustively on every platform.
/// The link-count requirement applies only when a regular file is required — a
/// directory legitimately has more than one link (`.` plus its entries).
pub fn private_object_verdict(
    label: &str,
    owner_id: u64,
    effective_owner_id: u64,
    link_count: u64,
    required: EntryKind,
    actual: EntryKind,
    permission: PermissionOutcome,
) -> Result<(), PrivateFsError> {
    if actual != required {
        return Err(PrivateFsError::Containment(format!(
            "{label}: expected a {required:?} but found a {actual:?}"
        )));
    }
    if owner_id != effective_owner_id {
        return Err(PrivateFsError::NotOwned(format!(
            "{label}: owned by uid {owner_id}, not {effective_owner_id}"
        )));
    }
    if required == EntryKind::File && link_count != 1 {
        return Err(PrivateFsError::MultiplyLinked(format!(
            "{label}: has {link_count} hard links"
        )));
    }
    if permission != PermissionOutcome::Private {
        return Err(PrivateFsError::InsecurePermissions(label.to_string()));
    }
    Ok(())
}

// ------------------------------------------------------------------------
// Truthful policy constant
// ------------------------------------------------------------------------

/// The owner-only protection this build actually applies, per platform.
///
/// A truthful report, asserted against real on-disk behaviour by
/// `private_fs_security_policy_matches_platform`, never against its own literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateFsPolicy {
    /// Unix directory mode enforced with `fchmod` and re-verified on open.
    pub unix_dir_mode: u32,
    /// Unix file mode enforced and re-verified on open.
    pub unix_file_mode: u32,
    /// Whether Unix modes are enforced on this build.
    pub unix_mode_enforced: bool,
    /// Whether an explicit owner-only DACL is written and verified on Windows.
    /// `false` in this prompt; `private-fs-windows-parity` flips it.
    pub windows_dacl_enforced: bool,
    /// Whether a symlink/reparse point is refused at every guarded component.
    pub reparse_rejected: bool,
    /// Whether object ownership is verified against the effective user.
    pub ownership_verified: bool,
    /// Whether a hard-linked secret is refused.
    pub link_count_verified: bool,
    /// Whether a real directory `fsync` durability barrier is available.
    pub directory_fsync_available: bool,
}

impl PrivateFsPolicy {
    /// Whether this build enforces the full owner-only security discipline
    /// (no-follow refusal, ownership, link-count, and a durability barrier).
    /// Consumers such as `make-export-redaction` gate on this rather than on
    /// `cfg!(unix)` directly, so the guarantee is reported from one place.
    pub const fn enforced(&self) -> bool {
        self.unix_mode_enforced
            && self.reparse_rejected
            && self.ownership_verified
            && self.link_count_verified
            && self.directory_fsync_available
    }
}

/// The protection this build actually applies. Every security field is `false`
/// on non-Unix, which is the truth until `private-fs-windows-parity` lands.
pub const PRIVATE_FS_POLICY: PrivateFsPolicy = PrivateFsPolicy {
    unix_dir_mode: 0o700,
    unix_file_mode: 0o600,
    unix_mode_enforced: cfg!(unix),
    windows_dacl_enforced: false,
    reparse_rejected: cfg!(unix),
    ownership_verified: cfg!(unix),
    link_count_verified: cfg!(unix),
    directory_fsync_available: cfg!(unix),
};

// ------------------------------------------------------------------------
// Unix held-descriptor primitives
// ------------------------------------------------------------------------

#[cfg(unix)]
fn effective_uid() -> u64 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    u64::from(unsafe { libc::geteuid() })
}

/// Open an existing directory no-follow. A symlink at the final component
/// yields `ELOOP`; a non-directory yields `ENOTDIR`; neither is followed.
#[cfg(unix)]
fn open_dir_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// Classify a no-follow open failure: a symlink or wrong file type is a
/// containment refusal, everything else is I/O.
#[cfg(unix)]
fn classify_dir_open_error(path: &Path, error: std::io::Error) -> PrivateFsError {
    match error.raw_os_error() {
        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR => {
            PrivateFsError::Containment(format!(
                "directory {}: not a real directory (symlink or wrong type)",
                path.display()
            ))
        }
        _ => PrivateFsError::io(format!("opening directory {}", path.display()), error),
    }
}

/// Verify a held directory descriptor and, if it is self-owned but its mode
/// drifted (an umask accident), repair it through the same descriptor and
/// re-verify. A foreign-owned directory is refused, never chmod'ed.
#[cfg(unix)]
fn verify_and_repair_dir(dir: &std::fs::File, label: &Path) -> Result<(), PrivateFsError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let meta = dir
        .metadata()
        .map_err(|e| PrivateFsError::io(format!("stat {}", label.display()), e))?;
    let owner = u64::from(meta.uid());
    let euid = effective_uid();
    let mut mode = meta.mode() & 0o777;
    if mode != 0o700 {
        if owner != euid {
            return Err(PrivateFsError::NotOwned(format!(
                "directory {}",
                label.display()
            )));
        }
        dir.set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(|e| PrivateFsError::io(format!("chmod 0700 {}", label.display()), e))?;
        mode = dir
            .metadata()
            .map_err(|e| PrivateFsError::io(format!("re-stat {}", label.display()), e))?
            .mode()
            & 0o777;
    }
    let actual = if meta.is_dir() {
        EntryKind::Directory
    } else {
        EntryKind::File
    };
    let permission = if mode == 0o700 {
        PermissionOutcome::Private
    } else {
        PermissionOutcome::Insecure
    };
    private_object_verdict(
        &format!("directory {}", label.display()),
        owner,
        euid,
        meta.nlink(),
        EntryKind::Directory,
        actual,
        permission,
    )
}

// ------------------------------------------------------------------------
// ensure_private_dir
// ------------------------------------------------------------------------

/// Ensure `path` is an owner-only (`0700`) directory, creating it if absent and
/// repairing a self-owned wide directory. A symlinked leaf, a foreign owner, or
/// a non-directory is refused. Symlinked *ancestors* stay legitimate (macOS
/// resolves `/var` to `/private/var`): only the final component is opened
/// no-follow and mode-enforced.
#[cfg(unix)]
pub fn ensure_private_dir(path: &Path) -> Result<(), PrivateFsError> {
    match open_dir_nofollow(path) {
        Ok(dir) => verify_and_repair_dir(&dir, path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)
                    .map_err(|e| PrivateFsError::io(format!("creating {}", parent.display()), e))?;
            }
            match std::fs::create_dir(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(PrivateFsError::io(format!("creating {}", path.display()), e));
                }
            }
            let dir = open_dir_nofollow(path).map_err(|e| classify_dir_open_error(path, e))?;
            verify_and_repair_dir(&dir, path)
        }
        Err(error) => Err(classify_dir_open_error(path, error)),
    }
}

#[cfg(not(unix))]
pub fn ensure_private_dir(path: &Path) -> Result<(), PrivateFsError> {
    // Non-Unix: no security enforcement (see the module docs and
    // `PRIVATE_FS_POLICY`). `private-fs-windows-parity` supplies the real arm.
    std::fs::create_dir_all(path)
        .map_err(|e| PrivateFsError::io(format!("creating {}", path.display()), e))
}

/// Ensure the parent directory of `path` is private, so a file written there is
/// not exposed by a world-traversable parent.
pub fn ensure_parent_dir_private(path: &Path) -> Result<(), PrivateFsError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        ensure_private_dir(parent)?;
    }
    Ok(())
}

/// For a **user-chosen output location**: create the parent directory private
/// if it does not exist, but never tighten a directory the user already has (a
/// shared `0755` project folder must keep its mode). A symlinked leaf is still
/// refused. This is the one place tightening a pre-existing user directory
/// would be hostile.
#[cfg(unix)]
pub fn ensure_output_parent_private(path: &Path) -> Result<(), PrivateFsError> {
    match open_dir_nofollow(path) {
        // Exists and is a real directory: leave the user's mode untouched.
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ensure_private_dir(path),
        Err(error) => Err(classify_dir_open_error(path, error)),
    }
}

#[cfg(not(unix))]
pub fn ensure_output_parent_private(path: &Path) -> Result<(), PrivateFsError> {
    std::fs::create_dir_all(path)
        .map_err(|e| PrivateFsError::io(format!("creating {}", path.display()), e))
}

// ------------------------------------------------------------------------
// repair_private_file (fail-closed)
// ------------------------------------------------------------------------

/// Bring an existing secret file to exactly `0600`, refusing rather than
/// warning. The file is opened no-follow (a symlink is `Containment`); a
/// foreign owner is `NotOwned`; a hard-linked file is `MultiplyLinked` (its
/// alias may live in an attacker-controlled directory); the mode is repaired
/// through the held descriptor and re-verified, yielding `InsecurePermissions`
/// if it is not `0600` afterwards. Unlike the previous implementation, no
/// branch returns `Ok(())` while leaving the file insecure.
// Test seam: fires once, between the initial stat and the authoritative
// post-chmod re-verify of `repair_private_file`, so a test can inject a hard
// link (or ownership change) in exactly that window and prove the re-verify
// reads it. A no-op in production.
#[cfg(all(unix, test))]
thread_local! {
    static REPAIR_AFTER_STAT_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(unix, test))]
fn run_repair_after_stat_hook() {
    if let Some(hook) = REPAIR_AFTER_STAT_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

#[cfg(all(unix, not(test)))]
fn run_repair_after_stat_hook() {}

#[cfg(unix)]
pub fn repair_private_file(path: &Path, label: &str) -> Result<(), PrivateFsError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(code) if code == libc::ELOOP => PrivateFsError::Containment(format!(
                "{label} file {}: is a symlink",
                path.display()
            )),
            _ => PrivateFsError::io(format!("opening {label} file {}", path.display()), error),
        })?;

    let euid = effective_uid();

    // An initial read of the held fd decides whether a repair is needed. It is
    // NOT the authority: it only gates the chmod so a foreign object is never
    // touched. The final verdict is built from a fresh post-chmod fstat below.
    let initial = file
        .metadata()
        .map_err(|e| PrivateFsError::io(format!("stat {label} file {}", path.display()), e))?;

    run_repair_after_stat_hook();

    if initial.mode() & 0o777 != 0o600 {
        if !initial.is_file() {
            return Err(PrivateFsError::Containment(format!(
                "{label} file {}: not a regular file",
                path.display()
            )));
        }
        if u64::from(initial.uid()) != euid {
            return Err(PrivateFsError::NotOwned(format!(
                "{label} file {}",
                path.display()
            )));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                PrivateFsError::io(format!("chmod 0600 {label} file {}", path.display()), e)
            })?;
    }

    // Authoritative verdict: re-`fstat` the HELD fd and build the verdict
    // entirely from that post-chmod metadata — owner, link count, kind, and
    // mode — so a hard link or ownership change injected after the initial stat
    // (a same-UID TOCTOU) is caught and refused, never passed through on stale
    // metadata.
    let held = file
        .metadata()
        .map_err(|e| PrivateFsError::io(format!("re-stat {label} file {}", path.display()), e))?;
    let actual = if held.is_file() {
        EntryKind::File
    } else {
        EntryKind::Directory
    };
    let permission = if held.mode() & 0o777 == 0o600 {
        PermissionOutcome::Private
    } else {
        PermissionOutcome::Insecure
    };
    private_object_verdict(
        &format!("{label} file {}", path.display()),
        u64::from(held.uid()),
        euid,
        held.nlink(),
        EntryKind::File,
        actual,
        permission,
    )
}

/// Read a private file through a held, no-follow descriptor: the file is opened
/// `O_NOFOLLOW`, then verified (regular file, self-owned, `nlink == 1`, exactly
/// `0600`) through that same descriptor **before** a single byte is read, and
/// the bytes are read from the held fd. Returns `Ok(None)` for a genuinely
/// absent file (a missing secret is not a compromise), and a typed
/// `PrivateFsError` for a symlink / foreign / hard-linked / wide file — so no
/// permissive credential-read path exists.
#[cfg(unix)]
pub fn read_private_file(path: &Path, label: &str) -> Result<Option<Vec<u8>>, PrivateFsError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(match error.raw_os_error() {
                Some(code) if code == libc::ELOOP => PrivateFsError::Containment(format!(
                    "{label} file {}: is a symlink",
                    path.display()
                )),
                _ => PrivateFsError::io(format!("opening {label} file {}", path.display()), error),
            });
        }
    };

    let meta = file
        .metadata()
        .map_err(|e| PrivateFsError::io(format!("stat {label} file {}", path.display()), e))?;
    let actual = if meta.is_file() {
        EntryKind::File
    } else {
        EntryKind::Directory
    };
    let permission = if meta.mode() & 0o777 == 0o600 {
        PermissionOutcome::Private
    } else {
        PermissionOutcome::Insecure
    };
    private_object_verdict(
        &format!("{label} file {}", path.display()),
        u64::from(meta.uid()),
        effective_uid(),
        meta.nlink(),
        EntryKind::File,
        actual,
        permission,
    )?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| PrivateFsError::io(format!("reading {label} file {}", path.display()), e))?;
    Ok(Some(bytes))
}

#[cfg(not(unix))]
pub fn read_private_file(path: &Path, _label: &str) -> Result<Option<Vec<u8>>, PrivateFsError> {
    // Non-Unix: no security enforcement (see the module docs and
    // `PRIVATE_FS_POLICY`). `private-fs-windows-parity` supplies the real arm.
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(PrivateFsError::io(format!("reading {}", path.display()), error)),
    }
}

#[cfg(not(unix))]
pub fn repair_private_file(_path: &Path, _label: &str) -> Result<(), PrivateFsError> {
    // Non-Unix: no security enforcement (see the module docs and
    // `PRIVATE_FS_POLICY`). `private-fs-windows-parity` supplies the real arm.
    Ok(())
}

// ------------------------------------------------------------------------
// write_private_file (crash-atomic, every platform)
// ------------------------------------------------------------------------

/// Directory the atomic-write temp file is created in, so the final rename
/// stays on the same filesystem (a cross-directory rename is not atomic). A
/// bare filename with no parent — or an empty parent — resolves to the current
/// directory.
fn atomic_write_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(unix)]
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let dir = atomic_write_dir(path);

    // Hold the destination directory's descriptor before the write so the
    // post-rename fsync is issued against an opened handle rather than a fresh
    // path lookup. NOTE: the temp create and `persist` below still resolve
    // `dir`/`path` by name, so a *same-uid* rename of `dir` between this open and
    // the rename could still redirect the write; that residual window is out of
    // the cross-user threat model (the parent is a 0700 owner-only directory
    // verified through its own held fd, so only the owner can race it). Fully
    // handle-anchored writes (openat/renameat relative to this fd) land with the
    // `private-fs-primitive-consolidation` follow-up.
    let dir_handle = std::fs::File::open(dir)
        .with_context(|| format!("opening {} for the durability barrier", dir.display()))?;

    // Crash-safe atomic replacement: write the full payload into a fresh temp
    // entry in the SAME directory, fsync it, rename it over the target, then
    // fsync the held directory descriptor so the rename itself is durable. A
    // crash at any point leaves either the previous file intact or the complete
    // new file, never a truncated or half-written secret. The temp entry is
    // created O_EXCL and moded to 0600 *before* any bytes are written, and
    // `NamedTempFile` removes it on every error path — so a failed write never
    // leaves a partial file at the target and never widens permissions.
    let mut temp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("creating temp file for {}", path.display()))?;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 temp file for {}", path.display()))?;
    temp.write_all(bytes)
        .with_context(|| format!("writing temp file for {}", path.display()))?;
    temp.as_file_mut()
        .flush()
        .with_context(|| format!("flushing temp file for {}", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("fsync temp file for {}", path.display()))?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("atomically replacing {}", path.display()))?;

    dir_handle
        .sync_all()
        .with_context(|| format!("fsync directory {}", dir.display()))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let dir = atomic_write_dir(path);

    // Crash-safe atomic replacement is orchestrated above the platform layer and
    // needs no platform security primitive, so it applies here too: temp-create
    // in the same directory, write, fsync the file, then rename over the target.
    // This is a DURABILITY guarantee only. This build enforces none of the
    // private_fs security properties on non-Unix — no no-follow/reparse refusal,
    // no handle-anchored verification, no ownership check, no link-count refusal,
    // no owner-only DACL, and no directory fsync barrier; `private-fs-windows-parity`
    // closes that gap.
    let mut temp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("creating temp file for {}", path.display()))?;
    temp.write_all(bytes)
        .with_context(|| format!("writing temp file for {}", path.display()))?;
    temp.as_file_mut()
        .flush()
        .with_context(|| format!("flushing temp file for {}", path.display()))?;
    temp.as_file()
        .sync_all()
        .with_context(|| format!("fsync temp file for {}", path.display()))?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("atomically replacing {}", path.display()))?;
    Ok(())
}

/// Write a secret-bearing session-export artifact, failing closed on any build
/// whose platform cannot enforce the private-file security discipline.
///
/// A session export (redacted or, via the explicit local opt-in, raw) always
/// contains material that must never land world-readable — API keys, tokens,
/// SSH material, and prompt/response bodies. On a platform where
/// [`PRIVATE_FS_POLICY`] does not report `enforced()` (every field `false` on
/// non-Unix until `private-fs-windows-parity` lands), we refuse to write the
/// export rather than emit a file without the 0600 / ownership / no-follow
/// guarantees. Callers on such platforms surface the error and produce no
/// output file. On an enforcing platform this is exactly
/// [`write_private_file`]; the gate is additive and consumes the single
/// policy witness rather than re-deciding `cfg!(unix)`.
pub fn write_private_export_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if !PRIVATE_FS_POLICY.enforced() {
        anyhow::bail!(
            "refusing to write export `{}`: this build does not enforce private-file \
             security (0600 permissions, ownership, and no-follow); \
             `private-fs-windows-parity` closes this gap",
            path.display()
        );
    }
    write_private_file(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- pure verdict (platform-independent) ------------------------------

    #[test]
    fn private_fs_security_ownership_verdict_rejects_foreign_owner_and_multiple_links() {
        // Self-owned, single-linked, correct-mode regular file: accepted.
        assert!(
            private_object_verdict(
                "f",
                1000,
                1000,
                1,
                EntryKind::File,
                EntryKind::File,
                PermissionOutcome::Private
            )
            .is_ok()
        );
        // Foreign owner -> NotOwned.
        assert!(matches!(
            private_object_verdict(
                "f",
                1001,
                1000,
                1,
                EntryKind::File,
                EntryKind::File,
                PermissionOutcome::Private
            ),
            Err(PrivateFsError::NotOwned(_))
        ));
        // A regular file with two links -> MultiplyLinked.
        assert!(matches!(
            private_object_verdict(
                "f",
                1000,
                1000,
                2,
                EntryKind::File,
                EntryKind::File,
                PermissionOutcome::Private
            ),
            Err(PrivateFsError::MultiplyLinked(_))
        ));
        // A directory where a file is required, and vice versa -> Containment.
        assert!(matches!(
            private_object_verdict(
                "f",
                1000,
                1000,
                1,
                EntryKind::File,
                EntryKind::Directory,
                PermissionOutcome::Private
            ),
            Err(PrivateFsError::Containment(_))
        ));
        assert!(matches!(
            private_object_verdict(
                "d",
                1000,
                1000,
                1,
                EntryKind::Directory,
                EntryKind::File,
                PermissionOutcome::Private
            ),
            Err(PrivateFsError::Containment(_))
        ));
        // Wrong mode -> InsecurePermissions.
        assert!(matches!(
            private_object_verdict(
                "f",
                1000,
                1000,
                1,
                EntryKind::File,
                EntryKind::File,
                PermissionOutcome::Insecure
            ),
            Err(PrivateFsError::InsecurePermissions(_))
        ));
        // A directory with two links (natural for directories) is accepted: the
        // link-count rule must not apply when a directory is required.
        assert!(
            private_object_verdict(
                "d",
                1000,
                1000,
                2,
                EntryKind::Directory,
                EntryKind::Directory,
                PermissionOutcome::Private
            )
            .is_ok()
        );
    }

    // -- policy vs. real on-disk behaviour (platform-independent) ---------

    #[test]
    fn private_fs_security_policy_matches_platform() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("state").join("cockpit");
        ensure_private_dir(&sub).expect("ensure private dir");
        let file = sub.join("secret");
        write_private_file(&file, b"payload").expect("write private file");

        assert_eq!(PRIVATE_FS_POLICY.unix_mode_enforced, cfg!(unix));
        assert_eq!(PRIVATE_FS_POLICY.reparse_rejected, cfg!(unix));
        assert_eq!(PRIVATE_FS_POLICY.ownership_verified, cfg!(unix));
        assert_eq!(PRIVATE_FS_POLICY.link_count_verified, cfg!(unix));
        assert_eq!(PRIVATE_FS_POLICY.directory_fsync_available, cfg!(unix));
        // Not implemented in this prompt; `private-fs-windows-parity` flips it.
        assert!(!PRIVATE_FS_POLICY.windows_dacl_enforced);
        assert_eq!(PRIVATE_FS_POLICY.enforced(), cfg!(unix));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dmode = std::fs::metadata(&sub).unwrap().permissions().mode() & 0o777;
            let fmode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(dmode, PRIVATE_FS_POLICY.unix_dir_mode);
            assert_eq!(fmode, PRIVATE_FS_POLICY.unix_file_mode);

            // `reparse_rejected` is real: a symlinked directory target is refused.
            let victim = dir.path().join("victim");
            std::fs::create_dir(&victim).unwrap();
            let link = dir.path().join("link-dir");
            std::os::unix::fs::symlink(&victim, &link).unwrap();
            assert!(matches!(
                ensure_private_dir(&link),
                Err(PrivateFsError::Containment(_))
            ));
        }
    }

    // -- ensure_private_dir refuses a symlinked leaf (Unix) ---------------

    #[cfg(unix)]
    #[test]
    fn private_fs_security_ensure_dir_refuses_symlinked_leaf_without_touching_victim() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        // A victim directory OUTSIDE the tree at mode 0755.
        let victim = root.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o755)).unwrap();
        // A symlink planted at the target leaf, pointing at the victim.
        let target = root.path().join("cockpit");
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        let result = ensure_private_dir(&target);

        assert!(
            matches!(result, Err(PrivateFsError::Containment(_))),
            "a symlinked leaf must be refused"
        );
        let vmode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(vmode, 0o755, "the victim directory must keep its 0755 mode");
    }

    // -- repair refuses a hard-linked secret (Unix) -----------------------

    #[cfg(unix)]
    #[test]
    fn private_fs_security_repair_refuses_hard_linked_target() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("credentials.json");
        std::fs::write(&target, b"SENTINEL").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = dir.path().join("alias");
        std::fs::hard_link(&target, &alias).unwrap();

        let result = repair_private_file(&target, "credential");

        assert!(
            matches!(result, Err(PrivateFsError::MultiplyLinked(_))),
            "a hard-linked secret must be refused, not repaired"
        );
        assert_eq!(
            std::fs::read(&alias).unwrap(),
            b"SENTINEL",
            "the attacker-visible alias must be untouched"
        );
    }

    // -- repair fails closed and re-verifies (Unix) -----------------------

    #[cfg(unix)]
    #[test]
    fn private_fs_security_repair_fails_closed_and_reverifies() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");

        // (a) A 0644 self-owned regular file is repaired to exactly 0600.
        let file = dir.path().join("creds");
        std::fs::write(&file, b"x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        repair_private_file(&file, "credential").expect("repair 0644 -> 0600");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // (b) A symlink at the path is refused, and its target keeps its mode.
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"v").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(matches!(
            repair_private_file(&link, "credential"),
            Err(PrivateFsError::Containment(_))
        ));
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644,
            "the symlink target must keep its original mode"
        );
    }

    // -- repair re-verifies link count from POST-chmod held-fd metadata ---

    // A hard link injected between the initial stat and the authoritative
    // post-chmod verdict must be caught by the re-`fstat` of the held fd —
    // repairing the mode to 0600 is not enough if a same-UID attacker aliased
    // the inode meanwhile. Against a verdict built from the pre-chmod stat this
    // returns `Ok`, so the test fails without the fix.
    #[cfg(unix)]
    #[test]
    fn private_fs_security_repair_reverifies_link_count_after_chmod() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("creds");
        std::fs::write(&target, b"SECRET").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();

        let alias = dir.path().join("alias");
        let target_for_hook = target.clone();
        let alias_for_hook = alias.clone();
        super::REPAIR_AFTER_STAT_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::hard_link(&target_for_hook, &alias_for_hook).expect("inject hard link");
            }));
        });

        let result = repair_private_file(&target, "credential");

        assert!(
            matches!(result, Err(PrivateFsError::MultiplyLinked(_))),
            "a hard link injected after the initial stat must be caught by the re-fstat"
        );
        // Precondition: the injection really happened in the repair window.
        assert!(alias.exists(), "the attacker alias must exist");
    }

    // -- credential READ is fail-closed through a held fd -----------------

    #[cfg(unix)]
    #[test]
    fn private_fs_security_read_refuses_unprovable_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");

        // A genuinely absent file is an empty store, not a compromise.
        assert!(matches!(
            read_private_file(&dir.path().join("absent"), "credential"),
            Ok(None)
        ));

        // A valid 0600 self-owned file is read.
        let good = dir.path().join("good");
        std::fs::write(&good, b"PAYLOAD").unwrap();
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_private_file(&good, "credential").unwrap(),
            Some(b"PAYLOAD".to_vec())
        );

        // A world-readable (0644) file is refused before any byte is read.
        let wide = dir.path().join("wide");
        std::fs::write(&wide, b"LEAK").unwrap();
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_private_file(&wide, "credential"),
            Err(PrivateFsError::InsecurePermissions(_))
        ));

        // A symlink to a 0600 victim is refused; the victim is never opened.
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"VICTIM-SECRET").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(matches!(
            read_private_file(&link, "credential"),
            Err(PrivateFsError::Containment(_))
        ));
    }

    // -- output parent: created private, pre-existing left untouched ------

    #[cfg(unix)]
    #[test]
    fn private_fs_security_export_parent_created_private_but_preexisting_untouched() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");

        // A cockpit-created export parent is 0700.
        let created = root.path().join("new-export-dir");
        ensure_output_parent_private(&created).expect("create private output parent");
        assert_eq!(
            std::fs::metadata(&created).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // A pre-existing user directory (a shared 0755 project folder) is left
        // exactly as the user had it — tightening it would be hostile. A broken
        // implementation that routed through `ensure_private_dir` would chmod it
        // to 0700 and fail this assertion.
        let user = root.path().join("project");
        std::fs::create_dir(&user).unwrap();
        std::fs::set_permissions(&user, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_output_parent_private(&user).expect("leave user dir alone");
        assert_eq!(
            std::fs::metadata(&user).unwrap().permissions().mode() & 0o777,
            0o755,
            "a pre-existing user directory must not be tightened"
        );
    }

    // -- crash-atomic write (kept from the atomic-writer task) ------------

    // `write_private_file` creates the file at exactly 0600.
    #[cfg(unix)]
    #[test]
    fn private_fs_security_write_creates_file_at_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("secret");

        write_private_file(&target, b"top-secret-payload").expect("write should succeed");

        let mode = std::fs::metadata(&target)
            .expect("target exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "credential file must be 0600, got {mode:04o}");
        assert_eq!(
            std::fs::read(&target).expect("read target"),
            b"top-secret-payload"
        );
    }

    // Replacing an existing file swaps in the WHOLE new payload atomically and
    // leaves no temp litter behind.
    #[test]
    fn private_fs_security_write_replaces_existing_content_atomically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("creds.json");

        write_private_file(&target, b"OLD-CONTENT").expect("first write");
        write_private_file(&target, b"NEW-CONTENT-COMPLETE").expect("second write");

        assert_eq!(
            std::fs::read(&target).expect("read target"),
            b"NEW-CONTENT-COMPLETE",
            "content must be the full new payload, never partial or concatenated"
        );

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .map(|e| e.expect("dir entry").file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("creds.json")],
            "no temp file may survive a successful write; found {entries:?}"
        );
    }

    // A failed write leaves the pre-existing victim byte-identical. Today's
    // in-place `create(true).truncate(true)` opens the existing file for write
    // (which needs no directory-write permission), truncates the sentinel, and
    // writes the secret into it; the atomic writer instead fails at temp
    // creation and never touches the target.
    #[cfg(unix)]
    #[test]
    fn private_fs_security_write_failure_leaves_prior_content_intact() {
        use std::os::unix::fs::PermissionsExt;

        // A read-only directory does not stop root; skip rather than assert a
        // guarantee the platform cannot provide for uid 0.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("secret");
        std::fs::write(&target, b"SENTINEL-KEEP").expect("seed victim");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("chmod victim");

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
            .expect("chmod dir read-only");

        let result = write_private_file(&target, b"NEW-SECRET-PAYLOAD");

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore dir mode");

        assert!(
            result.is_err(),
            "write into a read-only directory must fail closed, not truncate the target"
        );
        let after = std::fs::read(&target).expect("victim still readable");
        assert_eq!(
            after, b"SENTINEL-KEEP",
            "the pre-existing secret must be byte-identical after a failed write"
        );
        assert!(
            !after.windows(b"NEW-SECRET-PAYLOAD".len()).any(|w| w == b"NEW-SECRET-PAYLOAD"),
            "the new secret must never be written into the victim on a failed write"
        );
    }
}
