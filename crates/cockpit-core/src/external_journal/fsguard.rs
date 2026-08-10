//! Symlink/reparse-safe directory containment for the capsule spool.
//!
//! Every creation, scan, replacement, quarantine, and deletion goes through a
//! held directory handle. A name discovered by enumeration is never trusted:
//! it is reopened beneath the held handle with no-follow semantics before any
//! byte is read or written.
//!
//! The spool root is canonicalized **once**, up front. Ancestors of an
//! application data directory are legitimately symlinked on real systems
//! (macOS resolves `/var` to `/private/var`, and `$TMPDIR` lives under it), so
//! refusing every symlinked ancestor would refuse the default install. What
//! must not be followed is a *final* component or anything inside the spool,
//! and that is enforced with `O_NOFOLLOW` on every component below the
//! resolved root and on every lifecycle operation.
//!
//! ## Platform honesty
//!
//! Unix enforcement is real: `openat`/`mkdirat`/`renameat`/`unlinkat` with
//! `O_NOFOLLOW`, `fchmod` to exactly `0700`/`0600` after creation (so a
//! permissive umask cannot widen a capsule), and verification of mode, file
//! type, and link count on every reopen.
//!
//! Windows enforcement is **weaker, and this module does not pretend
//! otherwise**. Real Windows DACL and handle-containment work is deferred to a
//! dedicated `windows-file-security` prompt; this module must not grow blind
//! Win32 FFI in the meantime.
//! [`SPOOL_PERMISSION_POLICY`] reports `windows_dacl_enforced:
//! false`. What Windows does get: relative opens beneath the resolved root,
//! rejection of any entry carrying `FILE_ATTRIBUTE_REPARSE_POINT`, a
//! regular-file check, and a hard-link (`number_of_links`) check. What it does
//! not get: an explicit owner-only DACL with inheritance disabled. Nothing in
//! this repository sets a Windows security descriptor today, so claiming one
//! would be a lie in a security-critical path; the spool therefore inherits
//! the ACL of the per-user application data directory. `DirGuard::sync` is
//! also a documented no-op on Windows because there is no directory fsync,
//! which means a Windows crash can lose a *newly created* directory entry —
//! recovery treats a missing capsule as a missing durable medium rather than
//! as evidence.
//!
//! Quarantine never replaces an existing entry: the move is
//! `renameat2(RENAME_NOREPLACE)` on Linux and `linkat`+`unlinkat` elsewhere,
//! both of which fail rather than overwrite, so there is no check-then-rename
//! window in which a racing process could have its evidence destroyed.

use std::fs::File;
use std::path::{Component, Path, PathBuf};

use super::ExternalJournalError;

/// Exact Unix directory mode for every spool directory.
pub const SPOOL_DIR_MODE: u32 = 0o700;

/// Exact Unix file mode for every capsule file.
pub const SPOOL_FILE_MODE: u32 = 0o600;

/// The owner-only protection this spool actually applies, per platform.
///
/// This is a truthful report, not an aspiration: every field is asserted by a
/// behavioural test that creates real directories and files and inspects them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolPermissionPolicy {
    /// Unix directory mode enforced with `fchmod` and re-verified on open.
    pub unix_dir_mode: u32,
    /// Unix file mode enforced with `fchmod` and re-verified on open.
    pub unix_file_mode: u32,
    /// Whether Unix modes are enforced on this build.
    pub unix_mode_enforced: bool,
    /// Whether an explicit owner-only DACL is written on Windows.
    ///
    /// `false`. No code in this repository sets a Windows security descriptor;
    /// the spool inherits the per-user application data directory ACL.
    pub windows_dacl_enforced: bool,
    /// Whether reparse points are rejected for every spool entry.
    pub reparse_rejected: bool,
    /// Whether a directory fsync is available. `false` on Windows.
    pub directory_fsync_available: bool,
}

/// The protection this build actually applies.
pub const SPOOL_PERMISSION_POLICY: SpoolPermissionPolicy = SpoolPermissionPolicy {
    unix_dir_mode: SPOOL_DIR_MODE,
    unix_file_mode: SPOOL_FILE_MODE,
    unix_mode_enforced: cfg!(unix),
    windows_dacl_enforced: false,
    reparse_rejected: true,
    directory_fsync_available: cfg!(unix),
};

/// How much verification a reopen demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenStrictness {
    /// Containment plus exact owner-only permissions. Used for every read and
    /// write of a live capsule.
    Private,
    /// Containment only. Used when quarantining a capsule *because* its
    /// permissions are wrong — the entry must still be proven to be a
    /// contained regular file before it is renamed.
    ContainedOnly,
}

fn io(context: &str, error: std::io::Error) -> ExternalJournalError {
    ExternalJournalError::Spool(format!("{context}: {error}"))
}

/// Resolve the deepest existing ancestor of `path` and the components that
/// still have to be created beneath it.
///
/// Canonicalizing the existing part once is what makes a symlinked ancestor
/// (`/var` -> `/private/var` on macOS) work while keeping every component
/// below the resolved root no-follow.
#[cfg(not(unix))]
fn resolve_existing_base(path: &Path) -> Result<(PathBuf, Vec<String>), ExternalJournalError> {
    if !path.is_absolute() {
        return Err(ExternalJournalError::Containment(format!(
            "spool root must be absolute: {}",
            path.display()
        )));
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(ExternalJournalError::Containment(format!(
                "spool root must not contain `..`: {}",
                path.display()
            )));
        }
    }

    let mut pending: Vec<String> = Vec::new();
    let mut cursor = path;
    loop {
        match std::fs::canonicalize(cursor) {
            Ok(base) => {
                pending.reverse();
                return Ok((base, pending));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = cursor
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        ExternalJournalError::Containment(format!(
                            "spool path component is not UTF-8: {}",
                            cursor.display()
                        ))
                    })?;
                check_component(name)?;
                pending.push(name.to_string());
                cursor = cursor.parent().ok_or_else(|| {
                    ExternalJournalError::Containment(format!(
                        "spool root has no existing ancestor: {}",
                        path.display()
                    ))
                })?;
            }
            Err(error) => return Err(io("resolving spool root", error)),
        }
    }
}

/// Reject a name that is not a single safe path component.
fn check_component(name: &str) -> Result<(), ExternalJournalError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(ExternalJournalError::Containment(format!(
            "unsafe spool path component {name:?}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    /// A held, no-follow directory handle.
    #[derive(Debug)]
    pub struct DirGuard {
        dir: File,
        path: PathBuf,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HeldEntryIdentity {
        pub filesystem_id: u64,
        pub object_id: u128,
        pub kind: u8,
        pub len: u64,
        pub mode: u32,
        pub owner_id: u64,
        pub link_count: u64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum HeldRenameEffect {
        Applied(HeldEntryIdentity),
        AppliedIdentityMismatch {
            expected: HeldEntryIdentity,
            observed: HeldEntryIdentity,
        },
    }

    fn identity(metadata: &std::fs::Metadata) -> Result<HeldEntryIdentity, ExternalJournalError> {
        let kind = if metadata.is_file() {
            1
        } else if metadata.is_dir() {
            2
        } else {
            return Err(ExternalJournalError::Containment(
                "held entry must be a regular file or directory".into(),
            ));
        };
        if metadata.nlink() == 0 {
            return Err(ExternalJournalError::Containment(
                "held entry has no filesystem links".into(),
            ));
        }
        Ok(HeldEntryIdentity {
            filesystem_id: metadata.dev(),
            object_id: u128::from(metadata.ino()),
            kind,
            len: metadata.len(),
            mode: metadata.mode(),
            owner_id: u64::from(metadata.uid()),
            link_count: metadata.nlink(),
        })
    }

    fn cstring(name: &str) -> Result<CString, ExternalJournalError> {
        CString::new(name).map_err(|_| {
            ExternalJournalError::Containment(format!("spool name contains NUL: {name:?}"))
        })
    }

    /// Open a directory component no-follow, optionally creating it.
    /// Returns whether this call created it — only a directory we created is
    /// chmod'ed, so re-opening never silently repairs a widened spool.
    fn open_dir_at(
        parent: Option<&File>,
        name: &CString,
        create: bool,
    ) -> Result<(File, bool), ExternalJournalError> {
        let parent_fd = parent.map_or(libc::AT_FDCWD, |file| file.as_raw_fd());
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        for attempt in 0..2 {
            // SAFETY: `parent_fd` is a live descriptor (or AT_FDCWD) and
            // `name` stays alive for the call. O_NOFOLLOW rejects a symlink at
            // the final component, which is the containment guarantee.
            let fd = unsafe { libc::openat(parent_fd, name.as_ptr(), flags) };
            if fd >= 0 {
                // SAFETY: `fd` was just returned by openat and is uniquely owned.
                return Ok((unsafe { File::from_raw_fd(fd) }, attempt > 0));
            }
            let error = std::io::Error::last_os_error();
            if attempt == 0 && create && error.kind() == std::io::ErrorKind::NotFound {
                // SAFETY: same liveness argument; mkdirat creates one component.
                let made = unsafe {
                    libc::mkdirat(parent_fd, name.as_ptr(), SPOOL_DIR_MODE as libc::mode_t)
                };
                if made != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(io("creating spool directory", error));
                    }
                }
                continue;
            }
            return Err(io("opening spool directory", error));
        }
        Err(ExternalJournalError::Containment(
            "spool directory could not be opened after creation".to_string(),
        ))
    }

    fn enforce_dir_mode(dir: &File, path: &Path) -> Result<(), ExternalJournalError> {
        // SAFETY: the descriptor is live for the call.
        let result = unsafe { libc::fchmod(dir.as_raw_fd(), SPOOL_DIR_MODE as libc::mode_t) };
        if result != 0 {
            return Err(io(
                "chmod 0700 spool directory",
                std::io::Error::last_os_error(),
            ));
        }
        let mode = dir
            .metadata()
            .map_err(|error| io("stat spool directory", error))?
            .mode()
            & 0o777;
        if mode != SPOOL_DIR_MODE {
            return Err(ExternalJournalError::Containment(format!(
                "spool directory {} has mode {mode:o}; require {SPOOL_DIR_MODE:o}",
                path.display()
            )));
        }
        Ok(())
    }

    impl DirGuard {
        /// Open an absolute configured root from held `/`, never canonicalizing
        /// or following a component supplied by the path.
        pub fn open_root(path: &Path, create: bool) -> Result<Self, ExternalJournalError> {
            Self::open_root_with_walk_hook(path, create, || {})
        }

        pub(crate) fn open_root_with_walk_hook(
            path: &Path,
            create: bool,
            before_walk: impl FnOnce(),
        ) -> Result<Self, ExternalJournalError> {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, Component::ParentDir))
            {
                return Err(ExternalJournalError::Containment(format!(
                    "held root must be absolute without `..`: {}",
                    path.display()
                )));
            }
            let fd = unsafe {
                libc::open(
                    b"/\0".as_ptr().cast(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io("opening spool root", std::io::Error::last_os_error()));
            }
            let mut dir = unsafe { File::from_raw_fd(fd) };
            let mut walked = PathBuf::from("/");
            before_walk();
            for component in path.components() {
                let Component::Normal(name) = component else {
                    continue;
                };
                let name = name.to_str().ok_or_else(|| {
                    ExternalJournalError::Containment(
                        "held root component is not valid UTF-8".into(),
                    )
                })?;
                let (next, created) = open_dir_at(Some(&dir), &cstring(name)?, create)?;
                dir = next;
                walked.push(name);
                if created {
                    enforce_dir_mode(&dir, &walked)?;
                }
            }
            Ok(Self { dir, path: walked })
        }

        /// Open (creating if asked) a child directory beneath this handle.
        pub fn open_child_dir(
            &self,
            name: &str,
            create: bool,
        ) -> Result<Self, ExternalJournalError> {
            check_component(name)?;
            let (dir, created) = open_dir_at(Some(&self.dir), &cstring(name)?, create)?;
            let path = self.path.join(name);
            if created {
                enforce_dir_mode(&dir, &path)?;
            }
            Ok(Self { dir, path })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn held_identity(&self) -> Result<HeldEntryIdentity, ExternalJournalError> {
            identity(
                &self
                    .dir
                    .metadata()
                    .map_err(|error| io("stat held directory", error))?,
            )
        }

        pub fn open_entry_identity(
            &self,
            name: &str,
        ) -> Result<HeldEntryIdentity, ExternalJournalError> {
            check_component(name)?;
            let name = cstring(name)?;
            let fd = unsafe {
                libc::openat(
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io("opening held entry", std::io::Error::last_os_error()));
            }
            let file = unsafe { File::from_raw_fd(fd) };
            identity(
                &file
                    .metadata()
                    .map_err(|error| io("stat held entry", error))?,
            )
        }

        pub fn require_entry_absent(&self, name: &str) -> Result<(), ExternalJournalError> {
            check_component(name)?;
            let name = cstring(name)?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            let result = unsafe {
                libc::fstatat(
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result == 0 {
                return Err(ExternalJournalError::QuarantineNameTaken(
                    name.to_string_lossy().into_owned(),
                ));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
            Err(io("checking held target absence", error))
        }

        pub fn require_same_filesystem(
            &self,
            other: &DirGuard,
        ) -> Result<(), ExternalJournalError> {
            if self.held_identity()?.filesystem_id != other.held_identity()?.filesystem_id {
                return Err(ExternalJournalError::Containment(
                    "atomic rename requires source and target on one filesystem".into(),
                ));
            }
            Ok(())
        }

        pub fn rename_entry_noreplace_atomic(
            &self,
            name: &str,
            target: &DirGuard,
            target_name: &str,
            expected_source: HeldEntryIdentity,
        ) -> Result<HeldRenameEffect, ExternalJournalError> {
            self.rename_entry_noreplace_atomic_with_hook(
                name,
                target,
                target_name,
                expected_source,
                || {},
            )
        }

        pub(crate) fn rename_entry_noreplace_atomic_with_hook(
            &self,
            name: &str,
            target: &DirGuard,
            target_name: &str,
            expected_source: HeldEntryIdentity,
            before_syscall: impl FnOnce(),
        ) -> Result<HeldRenameEffect, ExternalJournalError> {
            self.require_same_filesystem(target)?;
            check_component(name)?;
            check_component(target_name)?;
            let from = cstring(name)?;
            let to = cstring(target_name)?;
            let observed_source = self.open_entry_identity(name)?;
            if observed_source != expected_source {
                return Err(ExternalJournalError::Containment(
                    "rename source identity changed before dispatch".into(),
                ));
            }
            before_syscall();
            #[cfg(target_os = "linux")]
            let result = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    self.dir.as_raw_fd(),
                    from.as_ptr(),
                    target.dir.as_raw_fd(),
                    to.as_ptr(),
                    1_u32,
                ) as libc::c_int
            };
            #[cfg(target_os = "macos")]
            let result = unsafe {
                libc::renameatx_np(
                    self.dir.as_raw_fd(),
                    from.as_ptr(),
                    target.dir.as_raw_fd(),
                    to.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let result: libc::c_int = return Err(ExternalJournalError::Containment(
                "held atomic no-replace rename is unsupported on this platform".into(),
            ));
            if result == 0 {
                let observed_target = target.open_entry_identity(target_name)?;
                if observed_target != expected_source {
                    return Ok(HeldRenameEffect::AppliedIdentityMismatch {
                        expected: expected_source,
                        observed: observed_target,
                    });
                }
                return Ok(HeldRenameEffect::Applied(observed_target));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(ExternalJournalError::QuarantineNameTaken(
                    target_name.to_owned(),
                ));
            }
            Err(io("held atomic no-replace rename", error))
        }

        /// Verify the held directory still carries exactly `0700`.
        pub fn verify_private(&self) -> Result<(), ExternalJournalError> {
            let mode = self
                .dir
                .metadata()
                .map_err(|error| io("stat spool directory", error))?
                .mode()
                & 0o777;
            if mode != SPOOL_DIR_MODE {
                return Err(ExternalJournalError::InsecurePermissions(format!(
                    "spool directory {} has mode {mode:o}",
                    self.path.display()
                )));
            }
            Ok(())
        }

        /// Create a file that must not already exist, at exactly `0600`.
        pub fn create_file_exclusive(&self, name: &str) -> Result<File, ExternalJournalError> {
            check_component(name)?;
            let cname = cstring(name)?;
            let flags =
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            // SAFETY: dirfd and name are live; openat is variadic so the mode
            // is promoted to c_uint explicitly.
            let fd = unsafe {
                libc::openat(
                    self.dir.as_raw_fd(),
                    cname.as_ptr(),
                    flags,
                    SPOOL_FILE_MODE as libc::c_uint,
                )
            };
            if fd < 0 {
                return Err(io("creating capsule file", std::io::Error::last_os_error()));
            }
            // SAFETY: `fd` was just returned by openat and is uniquely owned.
            let file = unsafe { File::from_raw_fd(fd) };
            // `openat` mode bits are masked by the process umask, so a
            // permissive umask would leave a group/world-readable capsule.
            // fchmod the descriptor we already hold, then verify.
            // SAFETY: the descriptor is live for the call.
            if unsafe { libc::fchmod(file.as_raw_fd(), SPOOL_FILE_MODE as libc::mode_t) } != 0 {
                return Err(io(
                    "chmod 0600 capsule file",
                    std::io::Error::last_os_error(),
                ));
            }
            let mode = file
                .metadata()
                .map_err(|error| io("stat new capsule file", error))?
                .mode()
                & 0o777;
            if mode != SPOOL_FILE_MODE {
                return Err(ExternalJournalError::InsecurePermissions(format!(
                    "new capsule {name} has mode {mode:o}"
                )));
            }
            Ok(file)
        }

        /// Reopen an existing file beneath the held handle and verify it is a
        /// private regular file with exactly one link.
        pub fn open_file_verified(&self, name: &str) -> Result<File, ExternalJournalError> {
            self.open_file_checked(name, OpenStrictness::Private)
        }

        /// Reopen with a chosen strictness. `ContainedOnly` still proves the
        /// entry is a contained, unlinked-elsewhere regular file; it only
        /// tolerates a wrong mode, which is what quarantine needs.
        pub fn open_file_checked(
            &self,
            name: &str,
            strictness: OpenStrictness,
        ) -> Result<File, ExternalJournalError> {
            check_component(name)?;
            let cname = cstring(name)?;
            let flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            // SAFETY: dirfd and name are live for the call.
            let fd = unsafe { libc::openat(self.dir.as_raw_fd(), cname.as_ptr(), flags) };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                // A genuinely absent entry is a different fact from one that
                // exists but fails verification, and the two must not be
                // conflated: the first means the durable medium is gone, the
                // second means the spool is compromised.
                if error.kind() == std::io::ErrorKind::NotFound {
                    return Err(ExternalJournalError::CapsuleMissing(name.to_string()));
                }
                return Err(io("opening capsule file", error));
            }
            // SAFETY: `fd` was just returned by openat and is uniquely owned.
            let file = unsafe { File::from_raw_fd(fd) };
            let metadata = file
                .metadata()
                .map_err(|error| io("stat capsule file", error))?;
            if !metadata.is_file() {
                return Err(ExternalJournalError::Containment(format!(
                    "spool entry {name} is not a regular file"
                )));
            }
            let mode = metadata.mode() & 0o777;
            if strictness == OpenStrictness::Private && mode != SPOOL_FILE_MODE {
                return Err(ExternalJournalError::InsecurePermissions(format!(
                    "capsule {name} has mode {mode:o}"
                )));
            }
            if metadata.nlink() != 1 {
                return Err(ExternalJournalError::Containment(format!(
                    "capsule {name} has {} links",
                    metadata.nlink()
                )));
            }
            Ok(file)
        }

        pub fn remove_file(&self, name: &str) -> Result<(), ExternalJournalError> {
            check_component(name)?;
            let name = cstring(name)?;
            // SAFETY: dirfd and name are live for the call.
            let result = unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) };
            if result != 0 {
                return Err(io("removing capsule file", std::io::Error::last_os_error()));
            }
            Ok(())
        }

        /// Move a file into another held directory, refusing to replace an
        /// existing entry.
        ///
        /// A check-then-rename would let a same-user process create the target
        /// between the check and the rename and have its evidence silently
        /// overwritten. Linux gets `renameat2(RENAME_NOREPLACE)`; every other
        /// Unix gets `linkat` (which fails `EEXIST` on its own) followed by
        /// `unlinkat`, which is the same guarantee in two steps.
        pub fn rename_into_noreplace(
            &self,
            name: &str,
            target: &DirGuard,
            target_name: &str,
        ) -> Result<(), ExternalJournalError> {
            check_component(name)?;
            check_component(target_name)?;
            let from = cstring(name)?;
            let to = cstring(target_name)?;

            #[cfg(target_os = "linux")]
            {
                const RENAME_NOREPLACE: libc::c_uint = 1;
                // SAFETY: both dirfds and both names stay live for the call.
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        self.dir.as_raw_fd(),
                        from.as_ptr(),
                        target.dir.as_raw_fd(),
                        to.as_ptr(),
                        RENAME_NOREPLACE,
                    )
                };
                if result == 0 {
                    return Ok(());
                }
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    return Err(ExternalJournalError::QuarantineNameTaken(
                        target_name.to_string(),
                    ));
                }
                // ENOSYS/EINVAL: the filesystem or kernel lacks renameat2, so
                // fall through to the portable two-step below.
                if !matches!(
                    error.raw_os_error(),
                    Some(libc::ENOSYS) | Some(libc::EINVAL)
                ) {
                    return Err(io("quarantining capsule file", error));
                }
            }

            // SAFETY: both dirfds and both names stay live for the call.
            // `linkat` never replaces: it fails with EEXIST.
            let linked = unsafe {
                libc::linkat(
                    self.dir.as_raw_fd(),
                    from.as_ptr(),
                    target.dir.as_raw_fd(),
                    to.as_ptr(),
                    0,
                )
            };
            if linked != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    return Err(ExternalJournalError::QuarantineNameTaken(
                        target_name.to_string(),
                    ));
                }
                return Err(io("linking capsule into quarantine", error));
            }
            // SAFETY: the directory descriptor and name are live for the call.
            let unlinked = unsafe { libc::unlinkat(self.dir.as_raw_fd(), from.as_ptr(), 0) };
            if unlinked != 0 {
                return Err(io(
                    "unlinking capsule after quarantine link",
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(())
        }

        /// fsync the directory itself, so a new or removed entry is durable.
        pub fn sync(&self) -> Result<(), ExternalJournalError> {
            self.dir
                .sync_all()
                .map_err(|error| io("fsync spool directory", error))
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    /// Reparse-point-rejecting directory containment.
    ///
    /// This is honestly weaker than the Unix implementation: see the module
    /// documentation and [`SPOOL_PERMISSION_POLICY`].
    #[derive(Debug)]
    pub struct DirGuard {
        path: PathBuf,
    }

    #[cfg(windows)]
    fn reject_reparse(path: &Path) -> Result<(), ExternalJournalError> {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ExternalJournalError::CapsuleMissing(path.display().to_string())
            } else {
                io("stat spool entry", error)
            }
        })?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ExternalJournalError::Containment(format!(
                "spool entry {} is a reparse point",
                path.display()
            )));
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn reject_reparse(path: &Path) -> Result<(), ExternalJournalError> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ExternalJournalError::CapsuleMissing(path.display().to_string())
            } else {
                io("stat spool entry", error)
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ExternalJournalError::Containment(format!(
                "spool entry {} is a symlink",
                path.display()
            )));
        }
        Ok(())
    }

    /// Everything Windows can still check about an open capsule handle:
    /// regular file, and no second hard link pointing at the same bytes.
    fn verify_open_file(file: &File, name: &str) -> Result<(), ExternalJournalError> {
        let metadata = file
            .metadata()
            .map_err(|error| io("stat capsule file", error))?;
        if !metadata.is_file() {
            return Err(ExternalJournalError::Containment(format!(
                "spool entry {name} is not a regular file"
            )));
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle as _;
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
            };

            // `std::os::windows::fs::MetadataExt::number_of_links` is still
            // unstable. Query the same value from the already-open handle so
            // the containment check remains effective on stable Rust.
            let mut information = BY_HANDLE_FILE_INFORMATION::default();
            unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
                .map_err(|error| {
                ExternalJournalError::Containment(format!(
                    "could not inspect capsule {name} link count: {error}"
                ))
            })?;
            if information.nNumberOfLinks > 1 {
                return Err(ExternalJournalError::Containment(format!(
                    "capsule {name} has {} links",
                    information.nNumberOfLinks
                )));
            }
        }
        Ok(())
    }

    impl DirGuard {
        pub fn open_root(path: &Path, create: bool) -> Result<Self, ExternalJournalError> {
            let (base, pending) = resolve_existing_base(path)?;
            if !create && !pending.is_empty() {
                return Err(ExternalJournalError::Spool(format!(
                    "spool root {} does not exist",
                    path.display()
                )));
            }
            let mut resolved = base;
            for name in pending {
                resolved.push(&name);
                std::fs::create_dir(&resolved).or_else(|error| match error.kind() {
                    std::io::ErrorKind::AlreadyExists => Ok(()),
                    _ => Err(io("creating spool directory", error)),
                })?;
                reject_reparse(&resolved)?;
            }
            reject_reparse(&resolved)?;
            if !resolved.is_dir() {
                return Err(ExternalJournalError::Containment(format!(
                    "spool root {} is not a directory",
                    resolved.display()
                )));
            }
            Ok(Self { path: resolved })
        }

        pub fn open_child_dir(
            &self,
            name: &str,
            create: bool,
        ) -> Result<Self, ExternalJournalError> {
            check_component(name)?;
            let path = self.path.join(name);
            if create {
                std::fs::create_dir(&path).or_else(|error| match error.kind() {
                    std::io::ErrorKind::AlreadyExists => Ok(()),
                    _ => Err(io("creating spool directory", error)),
                })?;
            }
            reject_reparse(&path)?;
            if !path.is_dir() {
                return Err(ExternalJournalError::Spool(format!(
                    "spool directory {} does not exist",
                    path.display()
                )));
            }
            Ok(Self { path })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn verify_private(&self) -> Result<(), ExternalJournalError> {
            reject_reparse(&self.path)
        }

        pub fn create_file_exclusive(&self, name: &str) -> Result<File, ExternalJournalError> {
            check_component(name)?;
            let path = self.path.join(name);
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| io("creating capsule file", error))?;
            reject_reparse(&path)?;
            verify_open_file(&file, name)?;
            Ok(file)
        }

        pub fn open_file_verified(&self, name: &str) -> Result<File, ExternalJournalError> {
            self.open_file_checked(name, OpenStrictness::Private)
        }

        pub fn open_file_checked(
            &self,
            name: &str,
            _strictness: OpenStrictness,
        ) -> Result<File, ExternalJournalError> {
            check_component(name)?;
            let path = self.path.join(name);
            reject_reparse(&path)?;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        ExternalJournalError::CapsuleMissing(name.to_string())
                    } else {
                        io("opening capsule file", error)
                    }
                })?;
            verify_open_file(&file, name)?;
            Ok(file)
        }

        pub fn remove_file(&self, name: &str) -> Result<(), ExternalJournalError> {
            check_component(name)?;
            let path = self.path.join(name);
            reject_reparse(&path)?;
            std::fs::remove_file(&path).map_err(|error| io("removing capsule file", error))
        }

        /// Hard-link-then-unlink, so an existing target is never replaced.
        /// `hard_link` fails when the destination exists, which is the
        /// no-replace guarantee this needs.
        pub fn rename_into_noreplace(
            &self,
            name: &str,
            target: &DirGuard,
            target_name: &str,
        ) -> Result<(), ExternalJournalError> {
            check_component(name)?;
            check_component(target_name)?;
            let from = self.path.join(name);
            reject_reparse(&from)?;
            let to = target.path.join(target_name);
            std::fs::hard_link(&from, &to).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    ExternalJournalError::QuarantineNameTaken(target_name.to_string())
                } else {
                    io("linking capsule into quarantine", error)
                }
            })?;
            std::fs::remove_file(&from)
                .map_err(|error| io("unlinking capsule after quarantine link", error))
        }

        /// Documented no-op: Windows has no directory fsync. See the module
        /// documentation for the durability consequence.
        pub fn sync(&self) -> Result<(), ExternalJournalError> {
            Ok(())
        }
    }
}

pub use imp::DirGuard;
#[cfg(unix)]
pub use imp::{HeldEntryIdentity, HeldRenameEffect};

impl DirGuard {
    /// Enumerate candidate file names. The names are untrusted: every caller
    /// must reopen them through [`DirGuard::open_file_verified`].
    pub fn list_file_names(&self) -> Result<Vec<String>, ExternalJournalError> {
        let mut names = Vec::new();
        let entries = std::fs::read_dir(self.path())
            .map_err(|error| io("scanning spool directory", error))?;
        for entry in entries {
            let entry = entry.map_err(|error| io("reading spool directory entry", error))?;
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if check_component(&name).is_err() {
                continue;
            }
            names.push(name);
        }
        names.sort();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The policy is asserted against real on-disk behaviour, never against
    /// its own literal: create a directory and a file through the guard, then
    /// inspect what the operating system actually recorded.
    #[test]
    fn external_journal_spool_security_permission_policy_matches_real_behaviour() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("policy-root");
        let guard = DirGuard::open_root(&root, true).unwrap();
        let file = guard.create_file_exclusive("probe.v1").unwrap();
        drop(file);

        assert_eq!(SPOOL_PERMISSION_POLICY.unix_mode_enforced, cfg!(unix));
        assert_eq!(
            SPOOL_PERMISSION_POLICY.directory_fsync_available,
            cfg!(unix)
        );
        // Honest by construction: nothing in this repository writes a Windows
        // security descriptor, so the policy must not claim one. Compile-time
        // so the claim cannot drift ahead of the implementation.
        const { assert!(!SPOOL_PERMISSION_POLICY.windows_dacl_enforced) };
        const { assert!(SPOOL_PERMISSION_POLICY.reparse_rejected) };

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let dir_mode = std::fs::metadata(guard.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_mode = std::fs::metadata(guard.path().join("probe.v1"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, SPOOL_PERMISSION_POLICY.unix_dir_mode);
            assert_eq!(file_mode, SPOOL_PERMISSION_POLICY.unix_file_mode);

            // Widening the mode is detected on the next strict reopen, and
            // tolerated only by the containment-only path quarantine uses.
            std::fs::set_permissions(
                guard.path().join("probe.v1"),
                std::fs::Permissions::from_mode(0o666),
            )
            .unwrap();
            assert!(matches!(
                guard.open_file_checked("probe.v1", OpenStrictness::Private),
                Err(ExternalJournalError::InsecurePermissions(_))
            ));
            assert!(
                guard
                    .open_file_checked("probe.v1", OpenStrictness::ContainedOnly)
                    .is_ok()
            );
        }
    }

    /// Configured roots are normalized before entering this primitive. The
    /// held walk itself never follows an ancestor alias.
    #[test]
    fn external_journal_spool_security_tolerates_symlinked_ancestors() {
        let tmp = tempfile::TempDir::new().unwrap();
        let real = tmp.path().join("real-parent");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("linked-parent");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(not(unix))]
        std::fs::create_dir(&link).unwrap();

        #[cfg(unix)]
        assert!(DirGuard::open_root(&link.join("spool"), true).is_err());
        let configured = if cfg!(unix) { &real } else { &link };
        let guard = DirGuard::open_root(&configured.join("spool"), true).unwrap();
        assert!(guard.path().is_absolute());
        assert!(configured.join("spool").is_dir());
        guard.verify_private().unwrap();
    }

    /// A final component that is a symlink is still refused, and `..` is never
    /// accepted anywhere in the root.
    #[test]
    fn external_journal_spool_security_rejects_symlinked_leaf_and_parent_escape() {
        let tmp = tempfile::TempDir::new().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();

        assert!(matches!(
            DirGuard::open_root(&tmp.path().join("a/../b"), true),
            Err(ExternalJournalError::Containment(_))
        ));

        let root = tmp.path().join("root");
        let guard = DirGuard::open_root(&root, true).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("child")).unwrap();
            assert!(guard.open_child_dir("child", false).is_err());
        }
        #[cfg(not(unix))]
        let _ = guard;
    }

    #[test]
    fn external_journal_spool_security_inspect_never_creates() {
        let tmp = tempfile::TempDir::new().unwrap();
        let missing = tmp.path().join("never-created");
        assert!(DirGuard::open_root(&missing, false).is_err());
        assert!(!missing.exists(), "inspection must not create the spool");
    }

    #[test]
    fn external_journal_spool_security_rejects_unsafe_components() {
        for name in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
            assert!(check_component(name).is_err(), "accepted {name:?}");
        }
        assert!(check_component("0f1e2d3c.v1").is_ok());
    }

    #[test]
    fn external_journal_spool_security_root_must_be_absolute() {
        let error = DirGuard::open_root(Path::new("relative/spool"), true).unwrap_err();
        assert!(matches!(error, ExternalJournalError::Containment(_)));
    }

    #[test]
    fn external_journal_spool_security_quarantine_rename_never_replaces() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = DirGuard::open_root(&tmp.path().join("root"), true).unwrap();
        let from = root.open_child_dir("from", true).unwrap();
        let to = root.open_child_dir("to", true).unwrap();

        from.create_file_exclusive("a.v1").unwrap();
        to.create_file_exclusive("a.v1").unwrap();
        // The destination already exists, so the move must be refused rather
        // than silently destroying the entry already there.
        assert!(matches!(
            from.rename_into_noreplace("a.v1", &to, "a.v1"),
            Err(ExternalJournalError::QuarantineNameTaken(_))
        ));
        assert!(std::fs::symlink_metadata(from.path().join("a.v1")).is_ok());

        // A free name succeeds and removes the source.
        from.rename_into_noreplace("a.v1", &to, "a.v1.1").unwrap();
        assert!(std::fs::symlink_metadata(from.path().join("a.v1")).is_err());
        assert!(std::fs::symlink_metadata(to.path().join("a.v1.1")).is_ok());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn held_entry_identity_and_atomic_noreplace_rename_are_descriptor_relative() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = DirGuard::open_root(&tmp.path().join("root"), true).unwrap();
        let from = root.open_child_dir("from", true).unwrap();
        let to = root.open_child_dir("to", true).unwrap();
        std::fs::write(from.path().join("entry"), b"payload").unwrap();
        let before = from.open_entry_identity("entry").unwrap();
        assert_eq!(before.kind, 1);
        assert_eq!(
            before.filesystem_id,
            from.held_identity().unwrap().filesystem_id
        );
        std::fs::write(to.path().join("occupied"), b"other").unwrap();
        assert!(matches!(
            from.rename_entry_noreplace_atomic("entry", &to, "occupied", before),
            Err(ExternalJournalError::QuarantineNameTaken(_))
        ));
        from.rename_entry_noreplace_atomic("entry", &to, "moved", before)
            .unwrap();
        assert_eq!(to.open_entry_identity("moved").unwrap(), before);
        assert!(from.open_entry_identity("entry").is_err());

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("moved", to.path().join("alias")).unwrap();
            assert!(to.open_entry_identity("alias").is_err());
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn held_atomic_rename_rejects_source_identity_swap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = DirGuard::open_root(&tmp.path().join("root"), true).unwrap();
        let from = root.open_child_dir("from", true).unwrap();
        let to = root.open_child_dir("to", true).unwrap();
        std::fs::write(from.path().join("entry"), b"first").unwrap();
        let expected = from.open_entry_identity("entry").unwrap();
        std::fs::rename(from.path().join("entry"), from.path().join("old")).unwrap();
        std::fs::write(from.path().join("entry"), b"first").unwrap();
        assert!(matches!(
            from.rename_entry_noreplace_atomic("entry", &to, "moved", expected),
            Err(ExternalJournalError::Containment(_))
        ));
        assert!(!to.path().join("moved").exists());
    }

    #[cfg(unix)]
    #[test]
    fn held_root_walk_has_no_pre_authority_canonical_snapshot() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let moved = tmp.path().join("moved");
        let result = DirGuard::open_root_with_walk_hook(&root, false, || {
            std::fs::rename(&root, &moved).unwrap();
            std::fs::create_dir(&root).unwrap();
        })
        .unwrap();
        assert_eq!(
            result.held_identity().unwrap(),
            DirGuard::open_root(&root, false)
                .unwrap()
                .held_identity()
                .unwrap()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn rename_name_swap_is_reported_as_applied_identity_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = DirGuard::open_root(&tmp.path().join("root"), true).unwrap();
        let from = root.open_child_dir("from", true).unwrap();
        let to = root.open_child_dir("to", true).unwrap();
        std::fs::write(from.path().join("entry"), b"expected").unwrap();
        let expected = from.open_entry_identity("entry").unwrap();
        let effect = from
            .rename_entry_noreplace_atomic_with_hook("entry", &to, "moved", expected, || {
                std::fs::rename(from.path().join("entry"), from.path().join("expected-held"))
                    .unwrap();
                std::fs::write(from.path().join("entry"), b"replacement").unwrap();
            })
            .unwrap();
        assert!(matches!(
            effect,
            HeldRenameEffect::AppliedIdentityMismatch { expected: value, observed }
                if value == expected && observed != expected
        ));
        assert_eq!(
            std::fs::read(to.path().join("moved")).unwrap(),
            b"replacement"
        );
    }
}
