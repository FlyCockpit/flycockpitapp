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
//! On Windows the KEK-file slice is fail-closed: [`write_private_file`],
//! [`read_private_file`], [`repair_private_file`], and [`ensure_private_dir`]
//! refuse a reparse point (junction / symlink / mount-point) at every existing
//! path component of the file and its parent, apply and re-read a protected
//! owner-only DACL (`D:P(A;;FA;;;OW)(A;;FA;;;SY)` — owner + SYSTEM full
//! access, no Everyone / Users / Authenticated Users / inherited extra
//! principal), refuse a hard-linked secret, and treat every failure as a typed
//! [`PrivateFsError`]. Verification is through the written object; a verify
//! failure deletes-or-refuses the file. [`PRIVATE_FS_POLICY.windows_dacl_enforced`]
//! is `true` on Windows because that apply/verify path is live, not a stub.
//!
//! Full no-follow / directory-fsync parity (`private-fs-windows-parity`) is
//! still later: [`PRIVATE_FS_POLICY.enforced()`] stays Unix-only until a real
//! directory `fsync` and the rest of the Unix discipline exist on Windows.
//! Other non-Unix, non-Windows builds still enforce none of the security
//! properties — only crash-atomic replacement, which is durability, not a
//! security claim.
//!
//! Session-export writes ([`write_private_export_file`]) additionally gate
//! on [`PrivateFsPolicy::export_file_discipline_enforced`] and are NOT
//! Unix-only: on Windows the export writer enforces the same file-level
//! discipline (reparse refusal at every component, hostile-target refusal,
//! a staged temp file that is BORN with the protected owner-only DACL — a
//! create-time `SECURITY_ATTRIBUTES`, the Windows twin of the Unix `0600`
//! at-create, so no create-then-harden window exists — verified through the
//! held handle before any export byte is written and re-verified through the
//! written object afterwards, delete-or-refuse on verify failure) while,
//! like the Unix export funnel, never tightening the user-chosen output
//! parent directory.

use std::path::Path;
use std::{ffi::OsStr, path::PathBuf};

use anyhow::{Context, Result};

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub mod held_directory;

/// Canonical Unix held-fd syscalls (`openat`/`mkdirat`/`fchmod`/`unlinkat`/
/// `linkat`/`renameat2`/`fstatat`) shared by this module, the external-journal
/// spool `DirGuard`, and the held-directory authority, so the no-follow
/// fd-anchored discipline is implemented in exactly one place.
#[cfg(unix)]
pub mod held_fd;

/// Canonical Windows held-handle NT primitives (`NtCreateFile` relative
/// opens, `NtSetInformationFile` rename/disposition, `NtQueryDirectoryFile`
/// enumeration) — the Windows twin of [`held_fd`] — so the no-reparse,
/// handle-anchored discipline behind skill mutations is implemented in
/// exactly one audited place.
#[cfg(windows)]
pub mod held_nt;

// ------------------------------------------------------------------------
// Typed, matchable, fail-closed errors
// ------------------------------------------------------------------------

/// A private-filesystem guarantee that could not be established.
///
/// Declared complete and uncfg'd, including the variants the Windows KEK-file
/// arm already produces (`InsecurePermissions`, `Containment`,
/// `MultiplyLinked`, `NotOwned`) so no caller has to re-match as
/// `private-fs-windows-parity` fills in the remaining Unix-parity fields.
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
    /// `true` on Windows: apply/verify is live (`D:P(A;;FA;;;OW)(A;;FA;;;SY)`).
    /// Must stay in lock-step with real on-disk behaviour — never a no-op.
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

    /// Whether this build enforces the private-FILE discipline a session
    /// export write requires: link-planting refusal at every component,
    /// ownership verification, hard-link refusal, and enforced owner-only
    /// permissions on the written file itself (Unix `0600` modes, or the
    /// live protected owner-only DACL apply/verify on Windows).
    ///
    /// This is the witness [`write_private_export_file`] gates on. It is
    /// deliberately NOT [`Self::enforced()`]: the directory-`fsync` durability
    /// barrier is Unix-only (Windows has no directory fsync) and is a
    /// durability property, not a secrecy one — both export writers fsync the
    /// staged file before the atomic publish. On Windows this still requires
    /// the four real witnesses whose apply/verify paths are live in
    /// [`write_private_export_file`]; on any other platform it stays `false`
    /// and the export write fails closed.
    pub const fn export_file_discipline_enforced(&self) -> bool {
        if cfg!(unix) {
            self.enforced()
        } else {
            self.windows_dacl_enforced
                && self.reparse_rejected
                && self.ownership_verified
                && self.link_count_verified
        }
    }
}

/// The protection this build actually applies. Unix mode/ownership/link-count
/// /directory-fsync fields stay Unix-only. `windows_dacl_enforced` is the
/// truthful KEK-file DACL witness (`cfg!(windows)`), not an aspiration.
pub const PRIVATE_FS_POLICY: PrivateFsPolicy = PrivateFsPolicy {
    unix_dir_mode: 0o700,
    unix_file_mode: 0o600,
    unix_mode_enforced: cfg!(unix),
    windows_dacl_enforced: cfg!(windows),
    reparse_rejected: cfg!(unix) || cfg!(windows),
    ownership_verified: cfg!(unix) || cfg!(windows),
    link_count_verified: cfg!(unix) || cfg!(windows),
    directory_fsync_available: cfg!(unix),
};

/// Resolve the platform's best private runtime root for ephemeral secret
/// materialization. Linux/Android semantics stay strict: use only
/// `$XDG_RUNTIME_DIR`. macOS falls back only to the OS-provided per-user
/// Darwin temp root when XDG is absent. Other platforms report no suitable
/// runtime root.
pub fn private_runtime_root() -> Option<PathBuf> {
    private_runtime_root_from(
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        darwin_user_temp_dir(),
    )
}

fn private_runtime_root_from(
    xdg_runtime_dir: Option<&OsStr>,
    darwin_user_temp_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    absolute_non_empty_path(xdg_runtime_dir).or_else(|| {
        #[cfg(target_os = "macos")]
        {
            darwin_user_temp_dir
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = darwin_user_temp_dir;
            None
        }
    })
}

fn absolute_non_empty_path(value: Option<&OsStr>) -> Option<PathBuf> {
    let path = PathBuf::from(value?);
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return None;
    }
    Some(path)
}

#[cfg(target_os = "macos")]
fn darwin_user_temp_dir() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;

    let length = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
    if length == 0 {
        return None;
    }
    let mut buffer = vec![0_u8; length];
    let written = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if written == 0 {
        return None;
    }
    let without_nul = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    let path = OsStr::from_bytes(&buffer[..without_nul]);
    absolute_non_empty_path(Some(path))
}

#[cfg(not(target_os = "macos"))]
fn darwin_user_temp_dir() -> Option<PathBuf> {
    None
}

#[cfg(target_os = "macos")]
fn device_id_matches(stat_device: libc::dev_t, metadata_device: u64) -> bool {
    // Darwin `dev_t` is i32 and `MetadataExt::dev()` sign-extends it, so a
    // negative device id must compare equal rather than fail conversion — a
    // `try_from` here reports a false mismatch for a genuinely matching inode
    // and trips the fail-closed substitution check. Matches every other site.
    stat_device as u64 == metadata_device
}

#[cfg(all(unix, not(target_os = "macos")))]
fn device_id_matches(stat_device: libc::dev_t, metadata_device: u64) -> bool {
    stat_device == metadata_device
}

// ------------------------------------------------------------------------
// Windows DACL / reparse policy seam (platform-independent)
// ------------------------------------------------------------------------

/// Audited owner-only DACL applied to the Windows KEK file and its parent.
/// Protected DACL, owner + SYSTEM full access only. Reviewed equivalent of
/// goal-scratch's descriptor; do not weaken.
pub const WINDOWS_OWNER_ONLY_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)";

/// A well-known Windows principal the KEK DACL policy distinguishes.
///
/// Injected into [`windows_dacl_permission_outcome`] so the ACE verdict can
/// be unit-tested on every CI host without a Windows runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsDaclPrincipal {
    /// Object owner (`OW`) or the creating user's SID.
    Owner,
    /// Local SYSTEM (`SY` / `S-1-5-18`).
    System,
    /// Everyone / World (`WD` / `S-1-1-0`).
    Everyone,
    /// Builtin Users (`BU` / `S-1-5-32-545`).
    Users,
    /// Authenticated Users (`AU` / `S-1-5-11`).
    AuthenticatedUsers,
    /// Any other SID. Never owner-only.
    Other,
}

/// One ACE in an injected Windows DACL, used by the policy seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsDaclAce {
    pub principal: WindowsDaclPrincipal,
    pub allow_full_access: bool,
}

/// Owner-only DACL verdict over an injected ACE list.
///
/// A private descriptor is a **protected** DACL whose allow-full-access ACEs
/// are exactly owner + SYSTEM. Everyone / Users / Authenticated Users / any
/// other principal, a missing owner or SYSTEM ACE, an unprotected DACL, or a
/// non-full-access ACE is [`PermissionOutcome::Insecure`].
pub fn windows_dacl_permission_outcome(
    protected: bool,
    aces: &[WindowsDaclAce],
) -> PermissionOutcome {
    if !protected {
        return PermissionOutcome::Insecure;
    }
    let mut saw_owner = false;
    let mut saw_system = false;
    for ace in aces {
        if !ace.allow_full_access {
            return PermissionOutcome::Insecure;
        }
        match ace.principal {
            WindowsDaclPrincipal::Owner => saw_owner = true,
            WindowsDaclPrincipal::System => saw_system = true,
            WindowsDaclPrincipal::Everyone
            | WindowsDaclPrincipal::Users
            | WindowsDaclPrincipal::AuthenticatedUsers
            | WindowsDaclPrincipal::Other => return PermissionOutcome::Insecure,
        }
    }
    if saw_owner && saw_system {
        PermissionOutcome::Private
    } else {
        PermissionOutcome::Insecure
    }
}

/// Parse a Windows SDDL DACL into the same ACE verdict the policy seam uses.
///
/// Recognises `OW`/`SY`/`WD`/`BU`/`AU` and the well-known SID forms those
/// aliases expand to. The unit seam injects strings; the Windows KEK-file
/// verify path re-reads the on-disk descriptor and runs it through this
/// same function (with the SDDL owner SID so `OW` expansions still count
/// as [`WindowsDaclPrincipal::Owner`]).
pub fn windows_dacl_permission_from_sddl(sddl: &str) -> PermissionOutcome {
    windows_dacl_permission_from_sddl_with_owner(sddl, sddl_owner(sddl))
}

fn windows_dacl_permission_from_sddl_with_owner(
    sddl: &str,
    owner_sid: Option<&str>,
) -> PermissionOutcome {
    let Some(dacl) = sddl_dacl_body(sddl) else {
        return PermissionOutcome::Insecure;
    };
    let protected = dacl.starts_with('P');
    let aces = parse_sddl_aces(dacl, owner_sid);
    windows_dacl_permission_outcome(protected, &aces)
}

fn sddl_dacl_body(sddl: &str) -> Option<&str> {
    let start = sddl.find("D:")?;
    let rest = &sddl[start + 2..];
    let end = rest.find("S:").unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Owner SID/alias from an `O:` SDDL prefix (`O:SYD:P…`, `O:S-1-5-21-…G:…D:…`).
fn sddl_owner(sddl: &str) -> Option<&str> {
    let rest = sddl.strip_prefix("O:")?;
    let end = ["G:", "D:", "S:"]
        .iter()
        .filter_map(|marker| rest.find(marker))
        .min()
        .unwrap_or(rest.len());
    let owner = &rest[..end];
    if owner.is_empty() { None } else { Some(owner) }
}

fn parse_sddl_aces(dacl: &str, owner_sid: Option<&str>) -> Vec<WindowsDaclAce> {
    let mut aces = Vec::new();
    let mut rest = dacl;
    while let Some(open) = rest.find('(') {
        let after = &rest[open + 1..];
        let Some(close) = after.find(')') else {
            break;
        };
        let body = &after[..close];
        rest = &after[close + 1..];
        let parts: Vec<&str> = body.split(';').collect();
        if parts.len() < 6 {
            aces.push(WindowsDaclAce {
                principal: WindowsDaclPrincipal::Other,
                allow_full_access: false,
            });
            continue;
        }
        let allow_full_access = parts[0] == "A" && parts[2].contains("FA");
        let sid = parts[5];
        let principal = windows_dacl_principal_from_sid(sid, owner_sid);
        aces.push(WindowsDaclAce {
            principal,
            allow_full_access,
        });
    }
    aces
}

fn windows_dacl_principal_from_sid(sid: &str, owner_sid: Option<&str>) -> WindowsDaclPrincipal {
    if sid.eq_ignore_ascii_case("OW") {
        return WindowsDaclPrincipal::Owner;
    }
    if sid.eq_ignore_ascii_case("SY") || sid.eq_ignore_ascii_case("S-1-5-18") {
        return WindowsDaclPrincipal::System;
    }
    if sid.eq_ignore_ascii_case("WD") || sid.eq_ignore_ascii_case("S-1-1-0") {
        return WindowsDaclPrincipal::Everyone;
    }
    if sid.eq_ignore_ascii_case("BU") || sid.eq_ignore_ascii_case("S-1-5-32-545") {
        return WindowsDaclPrincipal::Users;
    }
    if sid.eq_ignore_ascii_case("AU") || sid.eq_ignore_ascii_case("S-1-5-11") {
        return WindowsDaclPrincipal::AuthenticatedUsers;
    }
    if owner_sid.is_some_and(|owner| owner.eq_ignore_ascii_case(sid)) {
        return WindowsDaclPrincipal::Owner;
    }
    WindowsDaclPrincipal::Other
}

/// Observed facts for one path component, injected into the reparse seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathComponentFact {
    pub exists: bool,
    pub is_reparse: bool,
}

/// Refuse any existing reparse/junction/symlink component. Missing components
/// (a file that has not been created yet) are not reparses.
pub fn private_path_reparse_verdict(
    label: &str,
    components: &[PathComponentFact],
) -> Result<(), PrivateFsError> {
    for (index, component) in components.iter().enumerate() {
        if component.exists && component.is_reparse {
            return Err(PrivateFsError::Containment(format!(
                "{label}: path component {index} is a reparse point"
            )));
        }
    }
    Ok(())
}

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

/// Whether a symlink component may be followed, decided **from the held parent
/// directory fd's own metadata** (never the symlink entry's). Following is
/// permitted only when the parent directory is owned by root (uid 0) *and* has
/// no group/world write bit (`mode & 0o022 == 0`): a directory a non-root
/// attacker cannot create, rename, or unlink entries in, so the symlink entry is
/// immutable to the attacker and cannot have been planted or relocated there.
///
/// Gating on the parent (not the symlink) closes two holes in an inode-owner
/// check: the symlink entry — not its inode — is what an attacker who controls a
/// writable parent can swap or relocate, and the parent fd is already held so the
/// decision is TOCTOU-free. The one legitimate case still works: Fedora's
/// `/home` -> `/var/home` lives directly in `/`, which is root-owned `0755`.
#[cfg(unix)]
fn parent_permits_symlink_follow(parent_uid: u32, parent_mode: u32) -> bool {
    parent_uid == 0 && (parent_mode & 0o022) == 0
}

/// Resolve `path` to a held directory fd via a **no-follow component walk** from
/// a trusted root, optionally creating each missing component.
///
/// This is the confused-deputy defence: the directory is never resolved by
/// following an attacker-influenceable symlink. Every component is opened
/// `O_DIRECTORY|O_NOFOLLOW` from the held parent fd; a symlink component is
/// refused with `Containment` **unless the held parent directory is root-owned
/// and not group/world-writable** (see [`parent_permits_symlink_follow`]) — the
/// only place a symlink an attacker cannot have planted can live (e.g. Fedora
/// `/home` -> `/var/home` in `/`) — in which case it is followed once and the
/// walk continues no-follow beneath it. No component reachable in an
/// attacker-writable directory is ever resolved by following a symlink.
///
/// With `create`, a missing component is made with `mkdirat` (then re-opened
/// no-follow — a symlink raced into the name after `mkdirat` is still refused)
/// and `fchmod`'ed to exactly `0700` through its held fd. Without `create`, a
/// missing component surfaces the underlying `NotFound` so callers can branch.
#[cfg(unix)]
fn walk_private_dir(path: &Path, create: bool) -> Result<std::fs::File, PrivateFsError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Component;

    // Decompose into a trusted anchor plus the ordered normal components.
    let mut absolute = false;
    let mut names: Vec<&std::ffi::OsStr> = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::Normal(name) => names.push(name),
            Component::ParentDir => {
                return Err(PrivateFsError::Containment(format!(
                    "{}: refused, path contains `..`",
                    path.display()
                )));
            }
            Component::Prefix(_) => {
                return Err(PrivateFsError::Containment(format!(
                    "{}: refused, unexpected path prefix",
                    path.display()
                )));
            }
        }
    }

    // The anchor is either the filesystem root (`/` can never be a symlink) or,
    // for a relative path, the current directory. Both are trusted starting
    // points; only the components below are attacker-influenceable.
    let anchor = if absolute {
        unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        }
    } else {
        unsafe {
            libc::open(
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        }
    };
    if anchor < 0 {
        return Err(PrivateFsError::io(
            format!("opening filesystem anchor for {}", path.display()),
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: `anchor` was just returned by open and is uniquely owned.
    let mut dir = unsafe { std::fs::File::from_raw_fd(anchor) };

    for name in names {
        let cname = CString::new(name.as_bytes()).map_err(|_| {
            PrivateFsError::Containment(format!(
                "{}: path component {name:?} contains NUL",
                path.display()
            ))
        })?;

        // First try the component as an existing no-follow directory.
        let existing = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                cname.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if existing >= 0 {
            // SAFETY: `existing` was just returned by openat and is uniquely owned.
            dir = unsafe { std::fs::File::from_raw_fd(existing) };
            continue;
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            // A symlink component. Decide whether it may be followed from the
            // HELD PARENT fd's metadata (TOCTOU-free) — never from the symlink
            // entry. Follow once only when the parent is a directory a non-root
            // attacker cannot write entries into (root-owned, no group/world
            // write), so the symlink could not have been planted or relocated
            // there. Otherwise refuse every symlink component.
            // A symlink component surfaces as ELOOP, or — on Linux, opening a
            // symlink with O_DIRECTORY|O_NOFOLLOW — as ENOTDIR (errno 20), which
            // also covers a genuine non-directory. Decide follow/refuse from the
            // HELD PARENT fd's metadata (TOCTOU-free) — never from the entry.
            // Follow once only when the parent is a directory a non-root attacker
            // cannot write entries into (root-owned, no group/world write), so the
            // symlink could not have been planted, relocated, or swapped there.
            Some(code) if code == libc::ELOOP || code == libc::ENOTDIR => {
                use std::os::unix::fs::MetadataExt;
                let pmeta = dir.metadata().map_err(|e| {
                    PrivateFsError::io(
                        format!("stat parent of component {name:?} under {}", path.display()),
                        e,
                    )
                })?;
                if !parent_permits_symlink_follow(pmeta.uid(), pmeta.mode()) {
                    return Err(PrivateFsError::Containment(format!(
                        "component {name:?} under {} is a symlink or non-directory in an \
                         attacker-writable or non-root-owned directory",
                        path.display()
                    )));
                }
                // The parent is root-owned and not group/world-writable, so a
                // non-root attacker cannot modify the entry — it is immutable to
                // them. `fstatat` no-follow distinguishes a (followable, trusted
                // system) symlink such as Fedora `/home`->`/var/home` from a
                // genuine non-directory; TOCTOU-free because the parent cannot
                // change under a non-root attacker.
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                let rc = unsafe {
                    libc::fstatat(
                        dir.as_raw_fd(),
                        cname.as_ptr(),
                        stat.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if rc != 0 {
                    return Err(PrivateFsError::io(
                        format!("stat component {name:?} under {}", path.display()),
                        std::io::Error::last_os_error(),
                    ));
                }
                // SAFETY: `fstatat` returned 0, so `stat` is initialised.
                let stat = unsafe { stat.assume_init() };
                if stat.st_mode & libc::S_IFMT != libc::S_IFLNK {
                    return Err(PrivateFsError::Containment(format!(
                        "component {name:?} under {} is not a directory",
                        path.display()
                    )));
                }
                // Follow the trusted-parent system symlink once; the walk resumes
                // no-follow beneath it. Safe: the parent is immutable to a
                // non-root attacker, so there is no swap window.
                let followed = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        cname.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                };
                if followed < 0 {
                    return Err(PrivateFsError::io(
                        format!(
                            "following trusted-parent symlink component {name:?} under {}",
                            path.display()
                        ),
                        std::io::Error::last_os_error(),
                    ));
                }
                // SAFETY: `followed` was just returned by openat and is uniquely owned.
                dir = unsafe { std::fs::File::from_raw_fd(followed) };
            }
            Some(code) if code == libc::ENOENT => {
                if !create {
                    return Err(PrivateFsError::io(
                        format!("opening directory {}", path.display()),
                        error,
                    ));
                }
                // Create the missing component, then re-open it no-follow so a
                // symlink raced into the name after `mkdirat` is still refused.
                let made = unsafe { libc::mkdirat(dir.as_raw_fd(), cname.as_ptr(), 0o700) };
                let created = if made == 0 {
                    true
                } else {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        false
                    } else {
                        return Err(PrivateFsError::io(
                            format!(
                                "creating directory component {name:?} under {}",
                                path.display()
                            ),
                            error,
                        ));
                    }
                };
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        cname.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    let error = std::io::Error::last_os_error();
                    return Err(match error.raw_os_error() {
                        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR => {
                            PrivateFsError::Containment(format!(
                                "component {name:?} under {} is a symlink or non-directory",
                                path.display()
                            ))
                        }
                        _ => PrivateFsError::io(
                            format!(
                                "opening directory component {name:?} under {}",
                                path.display()
                            ),
                            error,
                        ),
                    });
                }
                // SAFETY: `fd` was just returned by openat and is uniquely owned.
                dir = unsafe { std::fs::File::from_raw_fd(fd) };
                if created {
                    // `File::set_permissions` is `fchmod` on the held fd.
                    dir.set_permissions(std::fs::Permissions::from_mode(0o700))
                        .map_err(|e| {
                            PrivateFsError::io(
                                format!("chmod 0700 component {name:?} under {}", path.display()),
                                e,
                            )
                        })?;
                }
            }
            _ => {
                return Err(classify_dir_open_error(path, error));
            }
        }
    }
    Ok(dir)
}

// ------------------------------------------------------------------------
// ensure_private_dir
// ------------------------------------------------------------------------

/// Ensure `path` is an owner-only (`0700`) directory, creating it if absent and
/// repairing a self-owned wide directory. Resolution is a no-follow component
/// walk from a trusted root ([`walk_private_dir`]): a symlinked leaf, a
/// symlinked *intermediate component* (whether pre-existing or raced in), a
/// foreign owner, or a non-directory is refused. A symlink component is followed
/// only when its held parent directory is root-owned and not group/world-writable
/// (so an attacker could not have placed it) — any symlink reachable in an
/// attacker-writable directory is `Containment`, closing the confused-deputy
/// window an attacker-controlled ancestor would otherwise open.
#[cfg(unix)]
pub fn ensure_private_dir(path: &Path) -> Result<(), PrivateFsError> {
    let dir = walk_private_dir(path, true)?;
    verify_and_repair_dir(&dir, path)
}

/// Open an **existing** private directory to a held fd via the same no-follow
/// component walk, then verify/repair it to `0700`/self-owned. Public so a
/// caller performing several effects in one directory (e.g. log rotation plus a
/// re-open) can anchor them all to a single held fd rather than re-resolving the
/// path between steps.
#[cfg(unix)]
pub fn open_private_dir_handle(dir: &Path) -> Result<std::fs::File, PrivateFsError> {
    let handle = walk_private_dir(dir, false)?;
    verify_and_repair_dir(&handle, dir)?;
    Ok(handle)
}

/// Read one non-secret, user-owned regular file through a held parent directory
/// without imposing the secret-store `0600` policy. This is for repository
/// inputs such as shared agent definitions, where ordinary `0644` checkout
/// modes are valid but a symlink, foreign owner, hard link, special file, or
/// component substitution must still fail closed.
#[cfg(unix)]
pub fn read_owned_file_nofollow(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, PrivateFsError> {
    use std::io::Read as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = match walk_private_dir(parent_path, false) {
        Ok(parent) => parent,
        Err(PrivateFsError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let parent_meta = parent.metadata().map_err(|error| {
        PrivateFsError::io(
            format!("statting {label} parent {}", parent_path.display()),
            error,
        )
    })?;
    private_object_verdict(
        &format!("{label} parent {}", parent_path.display()),
        u64::from(parent_meta.uid()),
        effective_uid(),
        parent_meta.nlink(),
        EntryKind::Directory,
        if parent_meta.is_dir() {
            EntryKind::Directory
        } else {
            EntryKind::File
        },
        PermissionOutcome::Private,
    )?;

    let leaf = path.file_name().ok_or_else(|| {
        PrivateFsError::Containment(format!("{label} {}: missing file name", path.display()))
    })?;
    let leaf = std::ffi::CString::new(leaf.as_bytes()).map_err(|_| {
        PrivateFsError::Containment(format!(
            "{label} {}: file name contains NUL",
            path.display()
        ))
    })?;
    // O_NONBLOCK is required before fstat: opening a FIFO read-only can block
    // indefinitely even though the held object would subsequently be rejected.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(match error.raw_os_error() {
            Some(code) if code == libc::ELOOP => {
                PrivateFsError::Containment(format!("{label} {}: is a symlink", path.display()))
            }
            _ => PrivateFsError::io(format!("opening {label} {}", path.display()), error),
        });
    }
    // SAFETY: openat returned a unique descriptor owned by this File.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| {
        PrivateFsError::io(format!("statting {label} {}", path.display()), error)
    })?;
    private_object_verdict(
        &format!("{label} {}", path.display()),
        u64::from(metadata.uid()),
        effective_uid(),
        metadata.nlink(),
        EntryKind::File,
        if metadata.is_file() {
            EntryKind::File
        } else {
            EntryKind::Directory
        },
        PermissionOutcome::Private,
    )?;
    if metadata.len() > max_bytes {
        return Err(PrivateFsError::Containment(format!(
            "{label} {}: exceeds {max_bytes} byte limit",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            PrivateFsError::io(format!("reading {label} {}", path.display()), error)
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(PrivateFsError::Containment(format!(
            "{label} {}: exceeds {max_bytes} byte limit",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

/// Windows counterpart for non-secret repository inputs. The parent chain is
/// retained and every leaf is opened relative with reparse refusal, but an
/// ordinary inherited/shared ACL is permitted and never rewritten.
#[cfg(windows)]
pub fn read_owned_file_nofollow(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, PrivateFsError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(PrivateFsError::io(
                format!("probing {label} {}", path.display()),
                error,
            ));
        }
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| PrivateFsError::io("resolving current directory", error))?
            .join(parent)
    };
    let leaf = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| {
            PrivateFsError::Containment(format!(
                "{label} {}: missing portable file name",
                path.display()
            ))
        })?;
    let max_bytes = usize::try_from(max_bytes).map_err(|_| {
        PrivateFsError::Containment(format!(
            "{label} {}: byte limit exceeds platform size",
            path.display()
        ))
    })?;
    let authority = held_directory::HeldWorkspaceDirectoryAuthority::open_existing(&parent)
        .map_err(|error| {
            PrivateFsError::Containment(format!(
                "opening retained {label} parent {}: {error:#}",
                parent.display()
            ))
        })?;
    authority
        .read_regular_file_relative_bounded_optional(&[leaf], max_bytes)
        .map_err(|error| {
            PrivateFsError::Containment(format!(
                "reading retained {label} {}: {error:#}",
                path.display()
            ))
        })
}

#[cfg(not(any(unix, windows)))]
pub fn read_owned_file_nofollow(
    path: &Path,
    label: &str,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, PrivateFsError> {
    use std::io::Read as _;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(PrivateFsError::io(
                format!("statting {label} {}", path.display()),
                error,
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(PrivateFsError::Containment(format!(
            "{label} {}: not a bounded regular non-link file",
            path.display()
        )));
    }
    let mut file = std::fs::File::open(path).map_err(|error| {
        PrivateFsError::io(format!("opening {label} {}", path.display()), error)
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            PrivateFsError::io(format!("reading {label} {}", path.display()), error)
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(PrivateFsError::Containment(format!(
            "{label} {}: exceeds {max_bytes} byte limit",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

pub const MAX_NOFOLLOW_DIRECTORY_TREE_ENTRIES: usize = 4_096;
pub const MAX_NOFOLLOW_DIRECTORY_TREE_DEPTH: usize = 32;

/// Read a bounded directory tree through one pinned root directory and
/// no-follow, fd-relative opens for every descendant. Names returned by
/// `readdir` are never resolved as paths: each is opened with `openat` against
/// the directory handle that produced it, closing metadata/read and
/// read-dir/descend symlink swap windows.
#[cfg(unix)]
pub fn read_nofollow_directory_tree(
    root: &Path,
    per_file_limit: u64,
    total_limit: u64,
) -> std::result::Result<std::collections::BTreeMap<String, Vec<u8>>, PrivateFsError> {
    fn visit(
        dir: &std::fs::File,
        relative_dir: &Path,
        root: &Path,
        per_file_limit: u64,
        total_limit: u64,
        depth: usize,
        total: &mut u64,
        entries: &mut usize,
        files: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) -> std::result::Result<(), PrivateFsError> {
        use std::ffi::{CStr, CString};
        use std::io::Read as _;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::ffi::OsStringExt as _;

        let duplicated = unsafe { libc::dup(dir.as_raw_fd()) };
        if duplicated < 0 {
            return Err(PrivateFsError::io(
                format!("duplicating directory handle for {}", root.display()),
                std::io::Error::last_os_error(),
            ));
        }
        let stream = unsafe { libc::fdopendir(duplicated) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(duplicated) };
            return Err(PrivateFsError::io(
                format!("opening directory stream for {}", root.display()),
                error,
            ));
        }

        let result = (|| {
            loop {
                let Some(entry) = read_directory_entry(stream).map_err(|error| {
                    PrivateFsError::io(
                        format!("enumerating package directory under {}", root.display()),
                        error,
                    )
                })?
                else {
                    break;
                };
                let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                *entries = entries.checked_add(1).ok_or_else(|| {
                    PrivateFsError::Containment(format!(
                        "{}: package entry count overflow",
                        root.display()
                    ))
                })?;
                if *entries > MAX_NOFOLLOW_DIRECTORY_TREE_ENTRIES {
                    return Err(PrivateFsError::Containment(format!(
                        "{}: package exceeds its entry count limit",
                        root.display()
                    )));
                }
                // Package paths use `/` as their portable component separator.
                // A backslash is a legal Unix filename byte but a separator on
                // Windows; normalizing it here used to let `a\\b` overwrite the
                // digest entry for `a/b`. Reject the ambiguous package rather
                // than changing either filename's identity.
                if name.contains(&b'\\') {
                    return Err(PrivateFsError::Containment(format!(
                        "{}: package entry name contains a cross-platform path separator",
                        root.display()
                    )));
                }
                let cname = CString::new(name).map_err(|_| {
                    PrivateFsError::Containment(format!(
                        "{}: directory entry contains NUL",
                        root.display()
                    ))
                })?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        cname.as_ptr(),
                        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    let error = std::io::Error::last_os_error();
                    return Err(match error.raw_os_error() {
                        Some(code) if code == libc::ELOOP => PrivateFsError::Containment(format!(
                            "{}: package entry is a symlink",
                            root.display()
                        )),
                        _ => PrivateFsError::io(
                            format!("opening package entry under {}", root.display()),
                            error,
                        ),
                    });
                }
                let mut held = unsafe { std::fs::File::from_raw_fd(fd) };
                let metadata = held.metadata().map_err(|error| {
                    PrivateFsError::io(
                        format!("statting held package entry under {}", root.display()),
                        error,
                    )
                })?;
                let os_name = std::ffi::OsString::from_vec(name.to_vec());
                let relative = relative_dir.join(os_name);
                if metadata.is_dir() {
                    if depth >= MAX_NOFOLLOW_DIRECTORY_TREE_DEPTH {
                        return Err(PrivateFsError::Containment(format!(
                            "{}: package exceeds its directory depth limit",
                            root.display()
                        )));
                    }
                    visit(
                        &held,
                        &relative,
                        root,
                        per_file_limit,
                        total_limit,
                        depth + 1,
                        total,
                        entries,
                        files,
                    )?;
                    continue;
                }
                if !metadata.is_file() {
                    return Err(PrivateFsError::Containment(format!(
                        "{}: package entry is not a regular file or directory",
                        root.display()
                    )));
                }
                let mut bytes = Vec::new();
                held.by_ref()
                    .take(per_file_limit.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .map_err(|error| {
                        PrivateFsError::io(
                            format!("reading held package entry under {}", root.display()),
                            error,
                        )
                    })?;
                if bytes.len() as u64 > per_file_limit {
                    return Err(PrivateFsError::Containment(format!(
                        "{}: package file exceeds {per_file_limit} byte limit",
                        root.display()
                    )));
                }
                *total = total.saturating_add(bytes.len() as u64);
                if *total > total_limit {
                    return Err(PrivateFsError::Containment(format!(
                        "{}: package exceeds {total_limit} byte limit",
                        root.display()
                    )));
                }
                let key = relative.to_str().ok_or_else(|| {
                    PrivateFsError::Containment(format!(
                        "{}: package entry name is not UTF-8",
                        root.display()
                    ))
                })?;
                if files.insert(key.to_string(), bytes).is_some() {
                    return Err(PrivateFsError::Containment(format!(
                        "{}: package entry path collides with another entry",
                        root.display()
                    )));
                }
            }
            Ok(())
        })();
        unsafe { libc::closedir(stream) };
        result
    }

    let root_handle = walk_private_dir(root, false)?;
    let mut files = std::collections::BTreeMap::new();
    let mut total = 0;
    let mut entries = 0;
    visit(
        &root_handle,
        Path::new(""),
        root,
        per_file_limit,
        total_limit,
        0,
        &mut total,
        &mut entries,
        &mut files,
    )?;
    Ok(files)
}

/// Windows package traversal is rooted in a retained directory handle and
/// uses relative no-reparse opens for every enumerated descendant. It shares
/// the workspace authority implementation so there is no metadata-then-path
/// fallback on this platform.
#[cfg(windows)]
pub fn read_nofollow_directory_tree(
    root: &Path,
    per_file_limit: u64,
    total_limit: u64,
) -> std::result::Result<std::collections::BTreeMap<String, Vec<u8>>, PrivateFsError> {
    let per_file_limit = usize::try_from(per_file_limit).map_err(|_| {
        PrivateFsError::Containment("package per-file limit exceeds platform size".into())
    })?;
    let total_limit = usize::try_from(total_limit).map_err(|_| {
        PrivateFsError::Containment("package total limit exceeds platform size".into())
    })?;
    let authority = held_directory::HeldWorkspaceDirectoryAuthority::open_existing(root)
        .map_err(|error| PrivateFsError::Containment(format!("opening held package: {error:#}")))?;
    authority
        .read_directory_tree_relative_bounded(
            &[],
            per_file_limit,
            total_limit,
            MAX_NOFOLLOW_DIRECTORY_TREE_ENTRIES,
            MAX_NOFOLLOW_DIRECTORY_TREE_DEPTH,
        )
        .map_err(|error| {
            PrivateFsError::Containment(format!("reading held package tree: {error:#}"))
        })?
        .ok_or_else(|| {
            PrivateFsError::Containment("held package root disappeared after open".into())
        })
}

/// Platforms without fd/handle-relative traversal must fail closed. A
/// metadata check followed by `read_dir`/`read` would permit a link swap.
#[cfg(not(any(unix, windows)))]
pub fn read_nofollow_directory_tree(
    root: &Path,
    _: u64,
    _: u64,
) -> std::result::Result<std::collections::BTreeMap<String, Vec<u8>>, PrivateFsError> {
    Err(PrivateFsError::Containment(format!(
        "secure package traversal is unavailable for {}",
        root.display()
    )))
}

#[cfg(unix)]
fn read_directory_entry(stream: *mut libc::DIR) -> std::io::Result<Option<*mut libc::dirent>> {
    set_readdir_errno_zero();
    // SAFETY: callers keep `stream` alive until this call returns and consume
    // the returned entry before the next call on the same stream.
    let entry = unsafe { libc::readdir(stream) };
    classify_readdir_result(entry, std::io::Error::last_os_error())
}

#[cfg(unix)]
fn classify_readdir_result(
    entry: *mut libc::dirent,
    error: std::io::Error,
) -> std::io::Result<Option<*mut libc::dirent>> {
    if !entry.is_null() {
        return Ok(Some(entry));
    }
    if error.raw_os_error() == Some(0) {
        Ok(None)
    } else {
        Err(error)
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "dragonfly",
    target_os = "emscripten",
    target_os = "hurd",
    target_os = "redox"
))]
fn set_readdir_errno_zero() {
    // SAFETY: errno is thread-local and this thread is about to call readdir.
    unsafe { *libc::__errno_location() = 0 }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "freebsd"
))]
fn set_readdir_errno_zero() {
    // SAFETY: errno is thread-local and this thread is about to call readdir.
    unsafe { *libc::__error() = 0 }
}

#[cfg(any(target_os = "android", target_os = "netbsd", target_os = "openbsd"))]
fn set_readdir_errno_zero() {
    // SAFETY: errno is thread-local and this thread is about to call readdir.
    unsafe { *libc::__errno() = 0 }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "dragonfly",
        target_os = "emscripten",
        target_os = "hurd",
        target_os = "redox",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))
))]
compile_error!("secure package traversal has no verified errno accessor on this Unix target");

/// Atomically rename a directory without replacing an existing destination.
///
/// This is a narrow filesystem effect primitive for callers that already own
/// the higher-level policy and recovery flow around the source and destination
/// paths. It therefore preserves the raw collision signal instead of mapping it
/// to a policy-specific error type.
#[cfg(any(unix, windows))]
pub fn rename_directory_noreplace(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::ffi::OsStrExt as _;

        let source_parent = source.parent().context("source directory has no parent")?;
        let destination_parent = destination
            .parent()
            .context("destination directory has no parent")?;
        let source_dir = open_private_dir_handle(source_parent)
            .map_err(anyhow::Error::from)
            .context("opening source parent directory")?;
        let destination_dir = open_private_dir_handle(destination_parent)
            .map_err(anyhow::Error::from)
            .context("opening destination parent directory")?;
        let source_name = CString::new(
            source
                .file_name()
                .context("source directory has no file name")?
                .as_bytes(),
        )?;
        let destination_name = CString::new(
            destination
                .file_name()
                .context("destination directory has no file name")?
                .as_bytes(),
        )?;
        held_fd::rename_noreplace(
            source_dir.as_raw_fd(),
            &source_name,
            destination_dir.as_raw_fd(),
            &destination_name,
        )
        .map_err(anyhow::Error::from)
        .context("renaming directory without replacement")?;
        return Ok(());
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn MoveFileExW(
                existing_file_name: *const u16,
                new_file_name: *const u16,
                flags: u32,
            ) -> i32;
        }

        const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
        let source_wide = source
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let destination_wide = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let ok = unsafe {
            MoveFileExW(
                source_wide.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            return Err(anyhow::Error::from(std::io::Error::last_os_error())).context(format!(
                "renaming directory without replacement from {} to {}",
                source.display(),
                destination.display()
            ));
        }
        return Ok(());
    }
}

#[cfg(windows)]
pub fn ensure_private_dir(path: &Path) -> Result<(), PrivateFsError> {
    ensure_windows_private_dir(path)
}

#[cfg(not(any(unix, windows)))]
pub fn ensure_private_dir(path: &Path) -> Result<(), PrivateFsError> {
    // Other non-Unix: no security enforcement (see the module docs and
    // `PRIVATE_FS_POLICY`).
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

#[cfg(windows)]
pub fn ensure_output_parent_private(path: &Path) -> Result<(), PrivateFsError> {
    ensure_windows_output_parent_private(path)
}

#[cfg(not(any(unix, windows)))]
pub fn ensure_output_parent_private(path: &Path) -> Result<(), PrivateFsError> {
    std::fs::create_dir_all(path)
        .map_err(|e| PrivateFsError::io(format!("creating {}", path.display()), e))
}

// ------------------------------------------------------------------------
// repair_private_file (fail-closed)
// ------------------------------------------------------------------------

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

/// Bring an existing secret file to exactly `0600`, refusing rather than
/// warning. The file is opened no-follow (a symlink is `Containment`); a
/// foreign owner is `NotOwned`; a hard-linked file is `MultiplyLinked` (its
/// alias may live in an attacker-controlled directory); the mode is repaired
/// through the held descriptor and re-verified, yielding `InsecurePermissions`
/// if it is not `0600` afterwards. Unlike the previous implementation, no
/// branch returns `Ok(())` while leaving the file insecure.
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

#[cfg(windows)]
pub fn read_private_file(path: &Path, label: &str) -> Result<Option<Vec<u8>>, PrivateFsError> {
    use std::io::Read;
    let Some(mut file) = open_windows_private_file(path, label)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| PrivateFsError::io(format!("reading {label} file {}", path.display()), e))?;
    Ok(Some(bytes))
}

#[cfg(not(any(unix, windows)))]
pub fn read_private_file(path: &Path, _label: &str) -> Result<Option<Vec<u8>>, PrivateFsError> {
    // Other non-Unix: no security enforcement (see the module docs and
    // `PRIVATE_FS_POLICY`).
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(PrivateFsError::io(
            format!("reading {}", path.display()),
            error,
        )),
    }
}

#[cfg(windows)]
pub fn repair_private_file(path: &Path, label: &str) -> Result<(), PrivateFsError> {
    refuse_windows_reparse_components(path)?;
    match verify_windows_private_path(path, label) {
        Ok(()) => Ok(()),
        Err(PrivateFsError::InsecurePermissions(_)) => {
            // Repair-and-reverify only when the object is self-owned and the
            // resulting DACL verifies. `set_private` fails closed if we cannot
            // write an owner-only descriptor (including a foreign owner).
            apply_windows_owner_only_dacl(path)?;
            verify_windows_private_path(path, label)
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(any(unix, windows)))]
pub fn repair_private_file(_path: &Path, _label: &str) -> Result<(), PrivateFsError> {
    // Other non-Unix: no security enforcement (see the module docs and
    // `PRIVATE_FS_POLICY`).
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

/// Create a fresh `O_EXCL` temp entry moded `0600`, anchored to the held
/// destination-directory fd. `O_EXCL` guarantees a brand-new name (never an
/// attacker's pre-existing symlink) and `O_NOFOLLOW` is belt-and-suspenders;
/// `0600` is set at create time so no byte is ever written through a wider mode.
#[cfg(unix)]
fn openat_create_private_excl(
    dir: &std::fs::File,
    name: &std::ffi::CStr,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            // Variadic `openat` mode: promote to `c_uint` (`mode_t` is `u16` on
            // Apple targets, which cannot be passed to a C variadic directly).
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat and is uniquely owned.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Create a uniquely-named temp entry beneath the held directory fd, retrying a
/// bounded number of times on the (vanishing) chance an `O_EXCL` name collides.
#[cfg(unix)]
fn create_temp_in(
    dir: &std::fs::File,
    target: &Path,
) -> Result<(std::fs::File, std::ffi::CString)> {
    use rand::Rng as _;
    for _ in 0..32 {
        let mut raw = [0u8; 16];
        rand::rng().fill_bytes(&mut raw);
        let name = format!(".tmp-{}", hex_lower(&raw));
        let cname = std::ffi::CString::new(name).expect("hex temp name has no NUL");
        match openat_create_private_excl(dir, &cname) {
            Ok(file) => return Ok((file, cname)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(anyhow::Error::from(error))
                    .with_context(|| format!("creating temp file for {}", target.display()));
            }
        }
    }
    anyhow::bail!(
        "could not create a unique temp file for {}",
        target.display()
    )
}

/// Best-effort `unlinkat` cleanup of a temp entry beneath the held fd. Errors
/// are ignored: the temp is already unreachable to callers, and the failure
/// path that triggers cleanup carries its own error.
#[cfg(unix)]
fn unlinkat_best_effort(dir: &std::fs::File, name: &std::ffi::CStr) {
    use std::os::fd::AsRawFd;
    // SAFETY: `dir` is a live directory fd and `name` lives across the call.
    unsafe {
        libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
    }
}

/// Refuse a hostile pre-existing write target, probed no-follow through the
/// held directory fd (`fstatat` + `AT_SYMLINK_NOFOLLOW`). A symlink, a
/// directory, a non-regular file, or a hard-linked (`nlink != 1`) target is
/// refused so the atomic rename never silently replaces an attacker-planted
/// object nor lets a secret become visible through a second hard link. An
/// absent target (fresh create) and an owner's own singly-linked regular file
/// (the intentional credential-overwrite case) are permitted.
#[cfg(unix)]
fn refuse_hostile_target(
    dir: &std::fs::File,
    name: &std::ffi::CStr,
    label: &Path,
) -> Result<(), PrivateFsError> {
    use std::os::fd::AsRawFd;

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(PrivateFsError::io(
            format!("probing write target {}", label.display()),
            error,
        ));
    }
    // SAFETY: `fstatat` returned 0, so `stat` is initialised.
    let stat = unsafe { stat.assume_init() };
    let kind = stat.st_mode & libc::S_IFMT;
    if kind == libc::S_IFLNK {
        return Err(PrivateFsError::Containment(format!(
            "{}: write target is a symlink",
            label.display()
        )));
    }
    if kind != libc::S_IFREG {
        return Err(PrivateFsError::Containment(format!(
            "{}: write target is not a regular file",
            label.display()
        )));
    }
    if stat.st_nlink != 1 {
        return Err(PrivateFsError::MultiplyLinked(format!(
            "{}: write target has {} hard links",
            label.display(),
            stat.st_nlink
        )));
    }
    Ok(())
}

#[cfg(unix)]
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    write_private_file_unix(path, bytes, PrivateWritePublish::Replace)
}

/// Crash-atomic create that fails if the destination already exists.
///
/// Same fd-anchored staging as [`write_private_file`], but the publish step
/// uses `renameat2(RENAME_NOREPLACE)` (or `linkat`, which also refuses to
/// replace) so two concurrent first-run writers cannot overwrite each other.
#[cfg(unix)]
pub fn write_private_file_exclusive(path: &Path, bytes: &[u8]) -> Result<()> {
    write_private_file_unix(path, bytes, PrivateWritePublish::Exclusive)
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum PrivateWritePublish {
    Replace,
    Exclusive,
}

#[cfg(unix)]
fn write_private_file_unix(path: &Path, bytes: &[u8], publish: PrivateWritePublish) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let dir = atomic_write_dir(path);
    let final_name = path.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "write target {} has no final path component",
            path.display()
        )
    })?;
    // Hold the destination directory through a no-follow component walk from a
    // trusted root (`walk_private_dir`): no ancestor is resolved by following a
    // symlink reachable in an attacker-writable directory, so an attacker who
    // controls an ancestor of a user-chosen export directory cannot redirect the
    // write elsewhere (a symlink is followed only when its held parent is
    // root-owned and not group/world-writable). Every subsequent effect — temp
    // create, target probe, rename, durability fsync — is then anchored to THIS
    // fd via openat/fstatat/renameat, so there is no path re-resolution between
    // the open and the use. The directory's own mode/ownership is not enforced
    // here because this shared funnel also backs user-chosen session exports,
    // whose destination is legitimately a shared (non-0700, possibly not
    // self-owned) directory; the secret's confidentiality is carried by the 0600
    // O_EXCL temp, the non-following renameat, and the hostile-target refusal
    // below, and the credential path establishes its 0700 parent through
    // `ensure_parent_dir_private` before ever reaching this funnel.
    let dir_handle = walk_private_dir(dir, false)?;
    write_private_file_in_held_dir(&dir_handle, final_name, path, bytes, publish)
}

/// Crash-atomically replace a private file relative to an already-held
/// directory descriptor.
///
/// The caller owns the directory capability and keeps it open across any
/// operation that selected this destination. This is for state whose logical
/// root can be renamed or replaced while it is being generated: publishing
/// through the retained descriptor ensures the final rename cannot be
/// redirected to a replacement pathname.
#[cfg(unix)]
pub fn write_private_file_in_dir_fd(
    dir_fd: &std::fs::File,
    name: &std::ffi::OsStr,
    display_path: &Path,
    bytes: &[u8],
) -> Result<()> {
    write_private_file_in_held_dir(
        dir_fd,
        name,
        display_path,
        bytes,
        PrivateWritePublish::Replace,
    )
}

/// Same fd-anchored private publication as [`write_private_file_in_dir_fd`],
/// but fail if `name` already exists. Callers that retain a directory authority
/// across an ephemeral secret's full lifetime use this to avoid re-resolving
/// the parent pathname.
#[cfg(unix)]
pub fn write_private_file_exclusive_in_dir_fd(
    dir_fd: &std::fs::File,
    name: &std::ffi::OsStr,
    display_path: &Path,
    bytes: &[u8],
) -> Result<()> {
    write_private_file_in_held_dir(
        dir_fd,
        name,
        display_path,
        bytes,
        PrivateWritePublish::Exclusive,
    )
}

#[cfg(unix)]
fn write_private_file_in_held_dir(
    dir_handle: &std::fs::File,
    final_name: &std::ffi::OsStr,
    path: &Path,
    bytes: &[u8],
    publish: PrivateWritePublish,
) -> Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let final_c = std::ffi::CString::new(final_name.as_bytes())
        .with_context(|| format!("write target {} name contains NUL", path.display()))?;

    // Refuse a hostile pre-existing target (symlink / directory / hard-linked)
    // before writing; the rename below is non-following regardless, so a secret
    // is never disclosed through a planted link even under a race.
    refuse_hostile_target(&dir_handle, &final_c, path)?;

    // Crash-safe atomic replacement, fully fd-anchored: write the payload into a
    // fresh O_EXCL temp entry (moded 0600 at create) beneath the held dir fd,
    // fsync it, renameat it over the target relative to the SAME fd, then fsync
    // the held directory fd so the rename itself is durable. A crash at any
    // point leaves either the previous file intact or the complete new file.
    let (mut temp, temp_c) = create_temp_in(&dir_handle, path)?;
    let staged = (|| -> Result<()> {
        temp.write_all(bytes)
            .with_context(|| format!("writing temp file for {}", path.display()))?;
        temp.flush()
            .with_context(|| format!("flushing temp file for {}", path.display()))?;
        temp.sync_all()
            .with_context(|| format!("fsync temp file for {}", path.display()))?;
        Ok(())
    })();
    if let Err(error) = staged {
        unlinkat_best_effort(&dir_handle, &temp_c);
        return Err(error);
    }

    // Integrity guard against a source-substitution race in an attacker-writable
    // export directory: the renameat below re-looks-up the temp by NAME, so a
    // different-uid attacker with write access to the directory could unlink our
    // `.tmp-<rand>` entry and replace it (with their own file or a symlink)
    // between the O_EXCL create and this rename, causing us to publish THEIR
    // inode under the final name. Confidentiality is unaffected — the secret
    // bytes live only in our held 0600 inode, never written through the name —
    // but to also preserve integrity we re-`fstatat` the name no-follow and
    // require it to still be our held inode (matching st_dev/st_ino from the
    // held fd's fstat), aborting the publish on mismatch. This is best-effort:
    // the fstatat→renameat pair is itself a window, so a fully race-free publish
    // would need O_TMPFILE + linkat(AT_EMPTY_PATH), which is not portable here;
    // the residual is an integrity-only substitution possible solely in a
    // user-chosen, attacker-writable export directory, never for credentials
    // (whose parent is a self-owned 0700 directory no other user can write).
    {
        use std::os::unix::fs::MetadataExt as _;
        let held = temp
            .metadata()
            .with_context(|| format!("fstat temp file for {}", path.display()))?;
        let mut named = std::mem::MaybeUninit::<libc::stat>::uninit();
        let stat_ok = unsafe {
            libc::fstatat(
                dir_handle.as_raw_fd(),
                temp_c.as_ptr(),
                named.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0;
        // SAFETY: only read `named` when fstatat succeeded.
        let matches = stat_ok && {
            let named = unsafe { named.assume_init() };
            device_id_matches(named.st_dev, held.dev()) && named.st_ino == held.ino()
        };
        if !matches {
            unlinkat_best_effort(&dir_handle, &temp_c);
            anyhow::bail!(
                "aborting write of {}: staged temp entry was substituted before publish",
                path.display()
            );
        }
    }

    // renameat within the held directory fd: atomic, and it replaces the target
    // NAME without following a symlink at that name. Exclusive first-run
    // creates use renameat2(RENAME_NOREPLACE) / linkat so a loser cannot
    // overwrite the winner's KEK.
    let renamed = match publish {
        PrivateWritePublish::Replace => unsafe {
            libc::renameat(
                dir_handle.as_raw_fd(),
                temp_c.as_ptr(),
                dir_handle.as_raw_fd(),
                final_c.as_ptr(),
            )
        },
        PrivateWritePublish::Exclusive => {
            match exclusive_publish_in_dir(&dir_handle, &temp_c, &final_c) {
                Ok(()) => 0,
                Err(error) => {
                    unlinkat_best_effort(&dir_handle, &temp_c);
                    return Err(anyhow::Error::from(error)).with_context(|| {
                        format!(
                            "exclusive create of {} lost the race or failed",
                            path.display()
                        )
                    });
                }
            }
        }
    };
    if renamed != 0 {
        let error = std::io::Error::last_os_error();
        unlinkat_best_effort(&dir_handle, &temp_c);
        return Err(anyhow::Error::from(error))
            .with_context(|| format!("atomically replacing {}", path.display()));
    }

    dir_handle
        .sync_all()
        .with_context(|| format!("fsync directory for {}", path.display()))?;
    Ok(())
}

/// Publish a staged temp name onto `dest` without replacing an existing file.
/// Linux/macOS use `renameat2(RENAME_NOREPLACE)` / `renameatx_np(RENAME_EXCL)`;
/// if the kernel or filesystem lacks that, `linkat` (which itself fails
/// `EEXIST`) plus `unlinkat` of the temp is the same guarantee in two steps.
#[cfg(unix)]
fn exclusive_publish_in_dir(
    dir_handle: &std::fs::File,
    from: &std::ffi::CStr,
    to: &std::ffi::CStr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        match held_fd::rename_noreplace(dir_handle.as_raw_fd(), from, dir_handle.as_raw_fd(), to) {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOSYS) | Some(libc::EINVAL)
                ) => {}
            Err(error) => return Err(error),
        }
    }

    held_fd::linkat(dir_handle.as_raw_fd(), from, dir_handle.as_raw_fd(), to, 0)?;
    let _ = held_fd::unlinkat(dir_handle.as_raw_fd(), from, 0);
    Ok(())
}

/// Access pattern for [`open_private_file_at`], keeping libc flags off the call
/// sites. `ReadWrite` is `O_RDWR` (lock files); `Append` is `O_WRONLY|O_APPEND`
/// (rotating logs). Both add `O_CREAT` and never `O_TRUNC`.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateFileAccess {
    ReadWrite,
    Append,
}

/// Open (creating if absent) a `0600` owner-only file `name` inside an
/// **already-held, verified** private directory fd `dir_fd`. The file is opened
/// via `openat` with `O_NOFOLLOW` (a symlink at the name is refused with
/// `Containment`, never followed into an attacker's file), then `fchmod`'ed to
/// `0600` through the held fd and re-verified (self-owned, singly-linked,
/// regular, exactly `0600`) via `fstat` on the fd. Never uses `O_TRUNC`, so an
/// existing lock file or log survives. Callers holding a directory fd across
/// several effects (e.g. log rotation + re-open) use this so every operation is
/// anchored to the SAME fd with no path re-resolution between steps.
#[cfg(unix)]
pub fn open_private_file_in_dir_fd(
    dir_fd: &std::fs::File,
    name: &std::ffi::OsStr,
    access: PrivateFileAccess,
    label: &str,
) -> Result<std::fs::File, PrivateFsError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let cname = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        PrivateFsError::Containment(format!("{label}: file name {name:?} contains NUL"))
    })?;
    let access_flags = match access {
        PrivateFileAccess::ReadWrite => libc::O_RDWR,
        PrivateFileAccess::Append => libc::O_WRONLY | libc::O_APPEND,
    };
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            cname.as_ptr(),
            access_flags | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(code) if code == libc::ELOOP => {
                PrivateFsError::Containment(format!("{label}: {name:?} is a symlink"))
            }
            _ => PrivateFsError::io(format!("opening {label} file {name:?}"), error),
        });
    }
    // SAFETY: `fd` was just returned by openat and is uniquely owned.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };

    // Enforce 0600 through the held fd (fchmod, not a path chmod) then verify.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| PrivateFsError::io(format!("chmod 0600 {label} file"), e))?;
    let meta = file
        .metadata()
        .map_err(|e| PrivateFsError::io(format!("stat {label} file"), e))?;
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
        &format!("{label} file"),
        u64::from(meta.uid()),
        effective_uid(),
        meta.nlink(),
        EntryKind::File,
        actual,
        permission,
    )?;
    Ok(file)
}

/// Open (creating if absent) a `0600` owner-only file `name` inside the private
/// directory `parent`. `parent` is resolved to a held fd by the no-follow
/// component walk ([`open_private_dir_handle`]) — so no ancestor is reached by
/// following a user/attacker-owned symlink — then the file is opened through
/// that fd by [`open_private_file_in_dir_fd`].
#[cfg(unix)]
pub fn open_private_file_at(
    parent: &Path,
    name: &std::ffi::OsStr,
    access: PrivateFileAccess,
    label: &str,
) -> Result<std::fs::File, PrivateFsError> {
    let dir_fd = open_private_dir_handle(parent)?;
    open_private_file_in_dir_fd(&dir_fd, name, access, label)
}

#[cfg(windows)]
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    refuse_windows_reparse_components(path)?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && parent != Path::new(".")
    {
        ensure_private_dir(parent)?;
    }
    refuse_windows_hostile_target(path)?;

    let dir = atomic_write_dir(path);
    // The staged temp is born with the protected owner-only DACL. The parent
    // was just tightened, but tightening does not propagate to new files: the
    // applied directory descriptor carries no inheritable ACE flags, so a
    // plain create would land under the token-default DACL (owner + SYSTEM +
    // Administrators) and only be hardened after the secret bytes are
    // already staged — the same create-then-harden window the export writer
    // closes at create time.
    let mut temp = tempfile::Builder::new()
        .make_in(dir, create_windows_private_file_exclusive)
        .with_context(|| format!("creating temp file for {}", path.display()))?;
    let staged = (|| -> Result<()> {
        // Fail closed before any secret byte lands: the born DACL must
        // verify owner-only through the held handle, not merely through the
        // create call that supplied it.
        verify_windows_open_file(temp.as_file(), temp.path(), "staged KEK")?;
        temp.write_all(bytes)
            .with_context(|| format!("writing temp file for {}", path.display()))?;
        temp.as_file_mut()
            .flush()
            .with_context(|| format!("flushing temp file for {}", path.display()))?;
        temp.as_file()
            .sync_all()
            .with_context(|| format!("fsync temp file for {}", path.display()))?;
        Ok(())
    })();
    if let Err(error) = staged {
        return Err(error);
    }
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("atomically replacing {}", path.display()))?;
    // Persist is path-based. Finalize re-walks every component, re-opens the
    // written object nofollow, and re-verifies DACL/links through that handle.
    // A swap after the preflight walk is fail-closed here, not a warning.
    if let Err(error) = finalize_windows_private_file(path) {
        if let Err(cleanup) = std::fs::remove_file(path) {
            return Err(PrivateFsError::InsecurePermissions(format!(
                "{}: post-write verify failed ({error}); leftover KEK could not be deleted ({cleanup})",
                path.display()
            ))
            .into());
        }
        return Err(error.into());
    }
    Ok(())
}

/// Crash-atomic create that fails if the destination already exists.
/// `NamedTempFile::persist_noclobber` refuses to replace, so two first-run
/// writers cannot overwrite each other's KEK.
#[cfg(windows)]
pub fn write_private_file_exclusive(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    refuse_windows_reparse_components(path)?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && parent != Path::new(".")
    {
        ensure_private_dir(parent)?;
    }
    refuse_windows_hostile_target(path)?;

    let dir = atomic_write_dir(path);
    // The staged temp is born with the protected owner-only DACL. The parent
    // was just tightened, but tightening does not propagate to new files: the
    // applied directory descriptor carries no inheritable ACE flags, so a
    // plain create would land under the token-default DACL (owner + SYSTEM +
    // Administrators) and only be hardened after the secret bytes are
    // already staged — the same create-then-harden window the export writer
    // closes at create time.
    let mut temp = tempfile::Builder::new()
        .make_in(dir, create_windows_private_file_exclusive)
        .with_context(|| format!("creating temp file for {}", path.display()))?;
    let staged = (|| -> Result<()> {
        // Fail closed before any secret byte lands: the born DACL must
        // verify owner-only through the held handle, not merely through the
        // create call that supplied it.
        verify_windows_open_file(temp.as_file(), temp.path(), "staged KEK")?;
        temp.write_all(bytes)
            .with_context(|| format!("writing temp file for {}", path.display()))?;
        temp.as_file_mut()
            .flush()
            .with_context(|| format!("flushing temp file for {}", path.display()))?;
        temp.as_file()
            .sync_all()
            .with_context(|| format!("fsync temp file for {}", path.display()))?;
        Ok(())
    })();
    if let Err(error) = staged {
        return Err(error);
    }
    temp.persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "exclusive create of {} lost the race or failed",
                path.display()
            )
        })?;
    if let Err(error) = finalize_windows_private_file(path) {
        if let Err(cleanup) = std::fs::remove_file(path) {
            return Err(PrivateFsError::InsecurePermissions(format!(
                "{}: post-write verify failed ({error}); leftover KEK could not be deleted ({cleanup})",
                path.display()
            ))
            .into());
        }
        return Err(error.into());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let dir = atomic_write_dir(path);

    // Crash-safe atomic replacement is orchestrated above the platform layer and
    // needs no platform security primitive, so it applies here too: temp-create
    // in the same directory, write, fsync the file, then rename over the target.
    // This is a DURABILITY guarantee only. Non-Windows, non-Unix builds enforce
    // none of the private_fs security properties.
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

#[cfg(not(any(unix, windows)))]
pub fn write_private_file_exclusive(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let dir = atomic_write_dir(path);
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
    temp.persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "exclusive create of {} lost the race or failed",
                path.display()
            )
        })?;
    Ok(())
}

/// Unlink a private file. Missing is success. Follows the same no-follow /
/// reparse refusal as the writers; does not print secret bytes.
#[cfg(unix)]
pub fn delete_private_file(path: &Path) -> Result<(), PrivateFsError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let Some(name) = path.file_name() else {
        return Err(PrivateFsError::Containment(format!(
            "{}: delete target has no file name",
            path.display()
        )));
    };
    let dir = match walk_private_dir(parent, false) {
        Ok(dir) => dir,
        Err(PrivateFsError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let cname = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        PrivateFsError::Containment(format!("{}: file name contains NUL", path.display()))
    })?;
    let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(PrivateFsError::io(
            format!("unlinking {}", path.display()),
            error,
        ));
    }
    let _ = dir.sync_all();
    Ok(())
}

#[cfg(windows)]
pub fn delete_private_file(path: &Path) -> Result<(), PrivateFsError> {
    refuse_windows_reparse_components(path)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PrivateFsError::io(
            format!("unlinking {}", path.display()),
            error,
        )),
    }
}

#[cfg(not(any(unix, windows)))]
pub fn delete_private_file(path: &Path) -> Result<(), PrivateFsError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PrivateFsError::io(
            format!("unlinking {}", path.display()),
            error,
        )),
    }
}

// ------------------------------------------------------------------------
// Windows KEK-file DACL / reparse / link-count (fail-closed)
// ------------------------------------------------------------------------

#[cfg(windows)]
fn windows_metadata_is_reparse(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn refuse_windows_reparse_components(path: &Path) -> Result<(), PrivateFsError> {
    use std::path::{Component, PathBuf};

    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(PrivateFsError::Containment(format!(
            "{}: refused, path contains `..`",
            path.display()
        )));
    }
    let mut current = PathBuf::new();
    let mut facts = Vec::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            facts.push(PathComponentFact {
                exists: true,
                is_reparse: false,
            });
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => facts.push(PathComponentFact {
                exists: true,
                is_reparse: windows_metadata_is_reparse(&meta),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                facts.push(PathComponentFact {
                    exists: false,
                    is_reparse: false,
                });
                break;
            }
            Err(error) => {
                return Err(PrivateFsError::io(
                    format!("stat {}", current.display()),
                    error,
                ));
            }
        }
    }
    private_path_reparse_verdict(&path.display().to_string(), &facts)
}

#[cfg(windows)]
fn windows_hard_link_count(file: &std::fs::File) -> Result<u64, PrivateFsError> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct ByHandleFileInformation {
        attributes: u32,
        creation_low: u32,
        creation_high: u32,
        access_low: u32,
        access_high: u32,
        write_low: u32,
        write_high: u32,
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            file: *mut core::ffi::c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }
    let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        return Err(PrivateFsError::io(
            "GetFileInformationByHandle",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: GetFileInformationByHandle returned success, so `info` is written.
    Ok(u64::from(unsafe { info.assume_init() }.links))
}

#[cfg(windows)]
fn map_windows_dacl_error(path: &Path, err: anyhow::Error) -> PrivateFsError {
    PrivateFsError::InsecurePermissions(format!("{}: {err}", path.display()))
}

#[cfg(windows)]
fn apply_windows_owner_only_dacl(path: &Path) -> Result<(), PrivateFsError> {
    crate::goal_scratch::set_private(path).map_err(|err| map_windows_dacl_error(path, err))
}

/// Create a brand-new file that is BORN with the protected owner-only DACL
/// (create-time `SECURITY_ATTRIBUTES`), instead of being created with the
/// process token's default DACL and hardened afterwards — the Windows twin
/// of the Unix `openat_create_private_excl` mode argument, where `0600` is
/// set at create time so no byte is ever written through a wider mode.
///
/// Born-private is load-bearing, not stylistic. A newly created file does
/// NOT inherit the parent directory's DACL: the owner-only descriptor this
/// module applies to directories carries no inheritable ACE flags, so a
/// create-then-harden sequence stages the secret under the token-default
/// DACL (owner + SYSTEM + Administrators, and whatever else the token
/// grants) for the whole write. Windows DACLs gate *opens*, not
/// already-held handles, so a co-tenant of a deliberately-never-tightened
/// export directory who opens the staged file in that window keeps reading
/// export bytes written after the harden — and a directory-write co-tenant
/// can plant a hard link whose alias survives the delete-or-refuse cleanup
/// (which removes only the published name). Creating through this helper
/// closes the window: the object never exists with any broader DACL.
///
/// `CREATE_NEW` guarantees a brand-new name (never an attacker's
/// pre-existing object, the `O_EXCL` twin). The share mode matches `std`'s
/// `OpenOptions` default (read/write/delete) so tempfile's path-based
/// publish keeps working while the handle is held; secrecy is carried by the
/// born DACL, exactly like the Unix arm's `0600` mode carries it.
#[cfg(windows)]
fn create_windows_private_file_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::ptr;

    /// Win32 `SECURITY_ATTRIBUTES`: carries the owner-only descriptor to the
    /// create call so the object is born private.
    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut core::ffi::c_void,
        inherit_handle: i32,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor: *const u16,
            revision: u32,
            security_descriptor: *mut *mut core::ffi::c_void,
            size: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            filename: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut SecurityAttributes,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
        fn LocalFree(memory: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    const SDDL_REVISION_1: u32 = 1;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
    const INVALID_HANDLE_VALUE: *mut core::ffi::c_void = -1isize as _;

    let sid = crate::named_pipe::current_user_sid().map_err(std::io::Error::other)?;
    // The same protected descriptor the finalize pass re-applies: explicit
    // owner (no inherited extra principals), current user + SYSTEM only.
    let sddl = format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)");
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

    let mut descriptor = ptr::null_mut();
    // SAFETY: `wide_sddl` is NUL-terminated, the out-pointer is valid, and the
    // LocalAlloc'd descriptor is freed exactly once below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let mut attributes = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        security_descriptor: descriptor,
        inherit_handle: 0,
    };
    // SAFETY: `wide_path` is NUL-terminated and `attributes` stays live across
    // the call; CreateFileW copies the descriptor into the new object, so the
    // converted descriptor can be freed immediately after it returns.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &mut attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY,
            ptr::null_mut(),
        )
    };
    unsafe { LocalFree(descriptor) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `handle` was just returned by CreateFileW and is solely owned.
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

/// Open an existing path without following a final-component reparse.
#[cfg(windows)]
fn open_windows_file_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Re-read the security descriptor through the held object, not the apply call.
#[cfg(windows)]
fn windows_sddl_from_handle(file: &std::fs::File) -> Result<String, PrivateFsError> {
    use std::os::windows::io::AsRawHandle as _;
    use std::ptr;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetSecurityInfo(
            handle: *mut core::ffi::c_void,
            object_type: u32,
            security_information: u32,
            owner: *mut *mut core::ffi::c_void,
            group: *mut *mut core::ffi::c_void,
            dacl: *mut *mut core::ffi::c_void,
            sacl: *mut *mut core::ffi::c_void,
            descriptor: *mut *mut core::ffi::c_void,
        ) -> u32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor: *mut core::ffi::c_void,
            revision: u32,
            security_information: u32,
            string_descriptor: *mut *mut u16,
            string_length: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }
    const SE_FILE_OBJECT: u32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 4;
    let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut descriptor = ptr::null_mut();
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            information,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 || descriptor.is_null() {
        return Err(PrivateFsError::InsecurePermissions(format!(
            "could not re-read DACL through the written object (GetSecurityInfo {result})"
        )));
    }
    let mut sddl = ptr::null_mut();
    let mut length = 0_u32;
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            information,
            &mut sddl,
            &mut length,
        )
    };
    unsafe { LocalFree(descriptor) };
    if converted == 0 || sddl.is_null() {
        return Err(PrivateFsError::InsecurePermissions(
            "could not convert the re-read DACL to SDDL for verification".into(),
        ));
    }
    let value = String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(sddl, usize::try_from(length).unwrap_or(0))
    });
    unsafe { LocalFree(sddl.cast()) };
    Ok(value)
}

#[cfg(windows)]
fn verify_windows_open_file(
    file: &std::fs::File,
    path: &Path,
    label: &str,
) -> Result<(), PrivateFsError> {
    let meta = file
        .metadata()
        .map_err(|e| PrivateFsError::io(format!("stat {label} file {}", path.display()), e))?;
    if windows_metadata_is_reparse(&meta) {
        return Err(PrivateFsError::Containment(format!(
            "{label} file {}: is a reparse point",
            path.display()
        )));
    }
    if !meta.is_file() {
        return Err(PrivateFsError::Containment(format!(
            "{label} file {}: not a regular file",
            path.display()
        )));
    }
    let links = windows_hard_link_count(file)?;
    if links != 1 {
        return Err(PrivateFsError::MultiplyLinked(format!(
            "{label} file {}: has {links} hard links",
            path.display()
        )));
    }
    // Policy-seam verdict over the re-read descriptor (not the apply call).
    let sddl = windows_sddl_from_handle(file)?;
    if windows_dacl_permission_from_sddl(&sddl) != PermissionOutcome::Private {
        return Err(PrivateFsError::InsecurePermissions(format!(
            "{label} {}: DACL is not owner+SYSTEM only",
            path.display()
        )));
    }
    // Current-user ownership: a foreign-owned object with an owner-only DACL
    // is still `NotOwned`. `set_private` / `verify_private_dacl_handle` refuse
    // to treat another user's SID as cockpit-owned.
    crate::goal_scratch::verify_private_dacl_handle(file)
        .map_err(|err| PrivateFsError::NotOwned(format!("{label} {}: {err}", path.display())))
}

#[cfg(windows)]
fn verify_windows_private_path(path: &Path, label: &str) -> Result<(), PrivateFsError> {
    refuse_windows_reparse_components(path)?;
    let file = open_windows_file_nofollow(path).map_err(|error| {
        PrivateFsError::io(format!("opening {label} file {}", path.display()), error)
    })?;
    verify_windows_open_file(&file, path, label)
}

#[cfg(windows)]
fn open_windows_private_file(
    path: &Path,
    label: &str,
) -> Result<Option<std::fs::File>, PrivateFsError> {
    refuse_windows_reparse_components(path)?;
    let file = match open_windows_file_nofollow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(PrivateFsError::io(
                format!("opening {label} file {}", path.display()),
                error,
            ));
        }
    };
    verify_windows_open_file(&file, path, label)?;
    Ok(Some(file))
}

#[cfg(windows)]
fn finalize_windows_private_file(path: &Path) -> Result<(), PrivateFsError> {
    refuse_windows_reparse_components(path)?;
    apply_windows_owner_only_dacl(path)?;
    verify_windows_private_path(path, "private file")
}

#[cfg(windows)]
fn refuse_windows_hostile_target(path: &Path) -> Result<(), PrivateFsError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(PrivateFsError::io(
                format!("probing write target {}", path.display()),
                error,
            ));
        }
    };
    if windows_metadata_is_reparse(&meta) {
        return Err(PrivateFsError::Containment(format!(
            "{}: write target is a reparse point",
            path.display()
        )));
    }
    if !meta.is_file() {
        return Err(PrivateFsError::Containment(format!(
            "{}: write target is not a regular file",
            path.display()
        )));
    }
    let file = open_windows_file_nofollow(path).map_err(|error| {
        PrivateFsError::io(format!("opening write target {}", path.display()), error)
    })?;
    let links = windows_hard_link_count(&file)?;
    if links != 1 {
        return Err(PrivateFsError::MultiplyLinked(format!(
            "{}: write target has {links} hard links",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn ensure_windows_private_dir(path: &Path) -> Result<(), PrivateFsError> {
    use std::path::{Component, PathBuf};

    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(PrivateFsError::Containment(format!(
            "{}: refused, path contains `..`",
            path.display()
        )));
    }
    let mut current = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        let is_leaf = index + 1 == components.len();
        if matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                if windows_metadata_is_reparse(&meta) {
                    return Err(PrivateFsError::Containment(format!(
                        "directory {}: is a reparse point",
                        current.display()
                    )));
                }
                if !meta.is_dir() {
                    return Err(PrivateFsError::Containment(format!(
                        "directory {}: not a real directory",
                        current.display()
                    )));
                }
                if is_leaf {
                    apply_windows_owner_only_dacl(&current)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|e| {
                    PrivateFsError::io(format!("creating {}", current.display()), e)
                })?;
                apply_windows_owner_only_dacl(&current)?;
            }
            Err(error) => {
                return Err(PrivateFsError::io(
                    format!("stat {}", current.display()),
                    error,
                ));
            }
        }
    }
    // Fail-closed: a path that contains a real directory component must
    // re-read as owner-only. A stub apply would leave the tempfile default
    // DACL and this verify returns InsecurePermissions.
    if components
        .iter()
        .any(|component| matches!(component, Component::Normal(_)))
    {
        crate::goal_scratch::verify_private_dacl(path)
            .map_err(|err| map_windows_dacl_error(path, err))?;
    }
    Ok(())
}

/// Windows twin of the Unix `ensure_output_parent_private` contract for a
/// **user-chosen output location**: create the parent private (owner-only
/// DACL, reparse refused at every component) when it does not exist, but
/// never tighten a directory the user already has — a pre-existing shared
/// directory keeps its ACL exactly as the user configured it. A pre-existing
/// path that is a reparse point or not a real directory is refused
/// (`Containment`) instead of being written through.
#[cfg(windows)]
fn ensure_windows_output_parent_private(path: &Path) -> Result<(), PrivateFsError> {
    use std::path::Component;

    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(PrivateFsError::Containment(format!(
            "{}: refused, path contains `..`",
            path.display()
        )));
    }
    refuse_windows_reparse_components(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if windows_metadata_is_reparse(&meta) {
                return Err(PrivateFsError::Containment(format!(
                    "directory {}: is a reparse point",
                    path.display()
                )));
            }
            if !meta.is_dir() {
                return Err(PrivateFsError::Containment(format!(
                    "directory {}: not a real directory",
                    path.display()
                )));
            }
            // Exists and is a real directory: leave the user's ACL untouched.
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure_windows_private_dir(path)
        }
        Err(error) => Err(PrivateFsError::io(
            format!("stat {}", path.display()),
            error,
        )),
    }
}

/// Write a secret-bearing session-export artifact, failing closed on any build
/// whose platform cannot enforce the private-file security discipline.
///
/// A session export (redacted or, via the explicit local opt-in, raw) always
/// contains material that must never land world-readable — API keys, tokens,
/// SSH material, and prompt/response bodies. The gate consumes the single
/// truthful witness [`PrivateFsPolicy::export_file_discipline_enforced`] —
/// owner-only permissions on the written file, ownership verification,
/// hard-link refusal, and no-follow containment — rather than re-deciding
/// `cfg!` at the call site. On Unix this is exactly [`write_private_file`]
/// (the full discipline, including the directory fsync); on Windows it is the
/// DACL-equivalent export writer, which enforces the same file-level
/// guarantees through the live protected owner-only DACL apply/verify path
/// and, like the Unix export funnel, never tightens the user-chosen output
/// parent directory. On a platform whose policy does not report the witness
/// we refuse to write the export rather than emit a file without those
/// guarantees; callers surface the error and produce no output file. Do not
/// weaken this gate: a platform becomes eligible only by enforcing, reported
/// through the policy witness, never by editing the gate away.
pub fn write_private_export_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if !PRIVATE_FS_POLICY.export_file_discipline_enforced() {
        anyhow::bail!(
            "refusing to write export `{}`: this build does not enforce private-file \
             security (owner-only permissions, ownership, and no-follow containment)",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        return write_private_file(path, bytes);
    }
    #[cfg(windows)]
    {
        return write_windows_private_export_file(path, bytes);
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Unreachable on this platform — the policy witness is `false` above
        // and already refused — but kept explicit so a future platform must
        // grow a real writer rather than fall through to an unpoliced write.
        anyhow::bail!(
            "no private export writer exists on this platform for `{}`",
            path.display()
        );
    }
}

/// Windows export writer — the DACL twin of the Unix export write funnel.
///
/// Enforces the same file-level discipline the KEK writer does — reparse
/// refusal at every existing path component, hostile-target refusal (a
/// reparse point, a non-regular file, or a hard-linked alias at the
/// destination), a staged temp file that is BORN with the protected
/// owner-only DACL (create-time `SECURITY_ATTRIBUTES`, so no
/// create-then-harden window exists even though the user-chosen parent is
/// never tightened) and verifies it through the held handle before any
/// export byte is written, an atomic replace, and a finalize pass that
/// re-applies and re-verifies the DACL through the written object
/// (delete-or-refuse on any verify failure) — while never touching the
/// parent directory's ACL. A user-chosen export directory is legitimately
/// shared; like the Unix funnel (which never tightens a `0755` parent), the
/// export's confidentiality is carried by the file's own owner-only DACL,
/// not by tightening the directory the user picked.
#[cfg(windows)]
fn write_windows_private_export_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    refuse_windows_reparse_components(path)?;
    refuse_windows_hostile_target(path)?;

    let dir = atomic_write_dir(path);
    // The staged temp is born with the protected owner-only DACL: the
    // user-chosen output directory is deliberately never tightened, and
    // Windows DACLs gate *opens*, not already-held handles — a
    // create-then-harden sequence would leave a window in which a co-tenant
    // of the directory could open the staged export and keep reading bytes
    // written after the harden, or plant a hard link whose alias survives
    // the final delete-or-refuse cleanup.
    let mut temp = tempfile::Builder::new()
        .make_in(dir, create_windows_private_file_exclusive)
        .with_context(|| format!("creating temp file for {}", path.display()))?;
    let staged = (|| -> Result<()> {
        // Fail closed before any export byte lands: the born DACL must
        // verify owner-only through the held handle, not merely through the
        // create call that supplied it.
        verify_windows_open_file(temp.as_file(), temp.path(), "staged export")?;
        temp.write_all(bytes)
            .with_context(|| format!("writing temp file for {}", path.display()))?;
        temp.as_file_mut()
            .flush()
            .with_context(|| format!("flushing temp file for {}", path.display()))?;
        temp.as_file()
            .sync_all()
            .with_context(|| format!("fsync temp file for {}", path.display()))?;
        Ok(())
    })();
    if let Err(error) = staged {
        return Err(error);
    }
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("atomically replacing {}", path.display()))?;
    if let Err(error) = finalize_windows_private_file(path) {
        if let Err(cleanup) = std::fs::remove_file(path) {
            return Err(PrivateFsError::InsecurePermissions(format!(
                "{}: post-write verify failed ({error}); leftover export could not be \
                 deleted ({cleanup})",
                path.display()
            ))
            .into());
        }
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

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
        assert_eq!(
            PRIVATE_FS_POLICY.reparse_rejected,
            cfg!(unix) || cfg!(windows)
        );
        assert_eq!(
            PRIVATE_FS_POLICY.ownership_verified,
            cfg!(unix) || cfg!(windows)
        );
        assert_eq!(
            PRIVATE_FS_POLICY.link_count_verified,
            cfg!(unix) || cfg!(windows)
        );
        assert_eq!(PRIVATE_FS_POLICY.directory_fsync_available, cfg!(unix));
        // Honest by construction: the flag tracks the live apply/verify arm,
        // never a stub. A no-op apply/verify with this true fails below.
        const { assert!(PRIVATE_FS_POLICY.windows_dacl_enforced == cfg!(windows)) };
        assert_eq!(PRIVATE_FS_POLICY.windows_dacl_enforced, cfg!(windows));
        assert_eq!(
            PRIVATE_FS_POLICY.windows_dacl_enforced,
            windows_dacl_is_actually_enforced(&file)
        );
        assert_eq!(PRIVATE_FS_POLICY.enforced(), cfg!(unix));
        // The export write witness: true wherever a real private-export file
        // writer enforces (Unix full discipline, Windows live DACL apply/verify
        // arm), false everywhere else.
        assert_eq!(
            PRIVATE_FS_POLICY.export_file_discipline_enforced(),
            cfg!(unix) || cfg!(windows)
        );

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

    #[test]
    fn private_runtime_root_prefers_absolute_xdg_runtime_dir() {
        let resolved = private_runtime_root_from(
            Some(OsStr::new("/xdg-runtime")),
            Some(PathBuf::from("/darwin-temp")),
        );
        assert_eq!(resolved, Some(PathBuf::from("/xdg-runtime")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_runtime_root_uses_only_darwin_temp_root_when_xdg_is_absent() {
        let resolved = private_runtime_root_from(None, Some(PathBuf::from("/darwin-temp")));
        assert_eq!(resolved, Some(PathBuf::from("/darwin-temp")));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn private_runtime_root_fails_closed_without_absolute_xdg_runtime_dir() {
        let resolved = private_runtime_root_from(None, Some(PathBuf::from("/darwin-temp")));
        assert_eq!(resolved, None);
    }

    /// Compare `windows_dacl_enforced` to real apply/verify, not the constant.
    ///
    /// If the flag is true while verify is a no-op, applying a world-readable
    /// DACL would still "verify" and this returns false — failing the policy
    /// test. On non-Windows there is no apply/verify, so the answer is false.
    fn windows_dacl_is_actually_enforced(path: &std::path::Path) -> bool {
        #[cfg(windows)]
        {
            if crate::goal_scratch::verify_private_dacl(path).is_err() {
                return false;
            }
            crate::goal_scratch::apply_test_windows_dacl(path, "D:P(A;;FA;;;WD)")
                .expect("test helper must be able to apply a world-readable DACL");
            let rejected = matches!(
                verify_windows_private_path(path, "policy-probe"),
                Err(PrivateFsError::InsecurePermissions(_))
            );
            let _ = crate::goal_scratch::set_private(path);
            rejected
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            false
        }
    }

    fn owner_only_aces() -> [WindowsDaclAce; 2] {
        [
            WindowsDaclAce {
                principal: WindowsDaclPrincipal::Owner,
                allow_full_access: true,
            },
            WindowsDaclAce {
                principal: WindowsDaclPrincipal::System,
                allow_full_access: true,
            },
        ]
    }

    fn ace(principal: WindowsDaclPrincipal) -> WindowsDaclAce {
        WindowsDaclAce {
            principal,
            allow_full_access: true,
        }
    }

    #[test]
    fn private_fs_windows_dacl_policy_seam() {
        assert_eq!(
            windows_dacl_permission_outcome(true, &owner_only_aces()),
            PermissionOutcome::Private
        );
        assert_eq!(
            windows_dacl_permission_from_sddl(WINDOWS_OWNER_ONLY_SDDL),
            PermissionOutcome::Private
        );

        for forbidden in [
            WindowsDaclPrincipal::Everyone,
            WindowsDaclPrincipal::Users,
            WindowsDaclPrincipal::AuthenticatedUsers,
        ] {
            assert_eq!(
                windows_dacl_permission_outcome(true, &[ace(forbidden)]),
                PermissionOutcome::Insecure,
                "{forbidden:?} alone must fail"
            );
            assert_eq!(
                windows_dacl_permission_outcome(
                    true,
                    &[
                        ace(WindowsDaclPrincipal::Owner),
                        ace(WindowsDaclPrincipal::System),
                        ace(forbidden),
                    ]
                ),
                PermissionOutcome::Insecure,
                "owner+SYSTEM plus {forbidden:?} must fail"
            );
        }

        assert_eq!(
            windows_dacl_permission_from_sddl("D:P(A;;FA;;;WD)"),
            PermissionOutcome::Insecure
        );
        assert_eq!(
            windows_dacl_permission_from_sddl("D:P(A;;FA;;;BU)"),
            PermissionOutcome::Insecure
        );
        assert_eq!(
            windows_dacl_permission_from_sddl("D:P(A;;FA;;;AU)"),
            PermissionOutcome::Insecure
        );
        assert_eq!(
            windows_dacl_permission_from_sddl("D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;WD)"),
            PermissionOutcome::Insecure
        );
        assert_eq!(
            windows_dacl_permission_from_sddl("D:(A;;FA;;;OW)(A;;FA;;;SY)"),
            PermissionOutcome::Insecure,
            "unprotected DACL must fail"
        );
        assert_eq!(
            windows_dacl_permission_outcome(false, &owner_only_aces()),
            PermissionOutcome::Insecure
        );
        assert_eq!(
            windows_dacl_permission_outcome(
                true,
                &[WindowsDaclAce {
                    principal: WindowsDaclPrincipal::Owner,
                    allow_full_access: false,
                }]
            ),
            PermissionOutcome::Insecure
        );

        // Expanded well-known SIDs (what ConvertSecurityDescriptor… emits).
        assert_eq!(
            windows_dacl_permission_from_sddl("D:P(A;;FA;;;S-1-1-0)"),
            PermissionOutcome::Insecure
        );
        assert_eq!(
            windows_dacl_permission_from_sddl("D:P(A;;FA;;;S-1-5-32-545)"),
            PermissionOutcome::Insecure
        );
        assert_eq!(
            windows_dacl_permission_from_sddl("D:P(A;;FA;;;S-1-5-11)"),
            PermissionOutcome::Insecure
        );
        assert_eq!(
            windows_dacl_permission_from_sddl(
                "O:S-1-5-21-1D:P(A;;FA;;;S-1-5-21-1)(A;;FA;;;S-1-5-18)"
            ),
            PermissionOutcome::Private,
            "re-read SDDL must treat the owner SID plus SYSTEM as private"
        );
        assert_eq!(
            windows_dacl_permission_from_sddl_with_owner(
                "D:P(A;;FA;;;S-1-5-21-1)(A;;FA;;;SY)",
                Some("S-1-5-21-1")
            ),
            PermissionOutcome::Private
        );
        assert_eq!(
            windows_dacl_permission_from_sddl(
                "O:S-1-5-21-1D:P(A;;FA;;;S-1-5-21-1)(A;;FA;;;SY)(A;;FA;;;WD)"
            ),
            PermissionOutcome::Insecure
        );
    }

    #[test]
    fn vault_windows_kek_file_refuses_reparse() {
        assert!(
            private_path_reparse_verdict(
                "kek",
                &[
                    PathComponentFact {
                        exists: true,
                        is_reparse: false,
                    },
                    PathComponentFact {
                        exists: true,
                        is_reparse: true,
                    },
                ]
            )
            .is_err_and(|e| matches!(e, PrivateFsError::Containment(_))),
            "a reparse parent component must be Containment"
        );
        assert!(
            private_path_reparse_verdict(
                "kek",
                &[
                    PathComponentFact {
                        exists: true,
                        is_reparse: false,
                    },
                    PathComponentFact {
                        exists: true,
                        is_reparse: false,
                    },
                    PathComponentFact {
                        exists: true,
                        is_reparse: true,
                    },
                ]
            )
            .is_err_and(|e| matches!(e, PrivateFsError::Containment(_))),
            "a reparse final component must be Containment"
        );
        assert!(
            private_path_reparse_verdict(
                "kek",
                &[
                    PathComponentFact {
                        exists: true,
                        is_reparse: false,
                    },
                    PathComponentFact {
                        exists: false,
                        is_reparse: false,
                    },
                ]
            )
            .is_ok(),
            "a missing final component is not a reparse"
        );

        #[cfg(windows)]
        {
            let root = tempfile::tempdir().expect("tempdir");
            let real = root.path().join("real");
            std::fs::create_dir(&real).unwrap();
            let junction = root.path().join("junc");
            create_windows_junction(&junction, &real);
            let kek = junction.join("wrap.key");
            let error = write_private_file(&kek, b"kek-bytes").expect_err("reparse parent");
            assert!(
                matches!(
                    error.downcast_ref::<PrivateFsError>(),
                    Some(PrivateFsError::Containment(_))
                ),
                "reparse parent must be Containment, got {error:?}"
            );

            let store = root.path().join("store");
            ensure_private_dir(&store).expect("private store");
            let link_name = store.join("wrap.key");
            create_windows_junction(&link_name, &real);
            let error =
                write_private_file(&link_name, b"kek-bytes").expect_err("reparse final component");
            assert!(
                matches!(
                    error.downcast_ref::<PrivateFsError>(),
                    Some(PrivateFsError::Containment(_))
                ),
                "reparse final component must be Containment, got {error:?}"
            );
        }
    }

    #[cfg(windows)]
    fn create_windows_junction(link: &std::path::Path, target: &std::path::Path) {
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .status()
            .expect("run mklink");
        assert!(
            status.success(),
            "mklink /J {} -> {} failed",
            link.display(),
            target.display()
        );
    }

    #[cfg(windows)]
    #[test]
    fn vault_windows_kek_file_owner_only_dacl() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kek = dir.path().join("wrap.key");
        write_private_file(&kek, b"kek-bytes-32................").expect("write KEK");
        crate::goal_scratch::verify_private_dacl(&kek)
            .expect("write_private_file must leave an owner-only DACL");
        crate::goal_scratch::verify_private_dacl(kek.parent().expect("parent"))
            .expect("KEK parent must have the same owner-only DACL");

        crate::goal_scratch::apply_test_windows_dacl(&kek, "D:P(A;;FA;;;WD)")
            .expect("inject world-readable DACL");
        assert!(
            matches!(
                verify_windows_private_path(&kek, "kek"),
                Err(PrivateFsError::InsecurePermissions(_))
            ),
            "verify must refuse a world-readable KEK DACL"
        );
        assert!(
            matches!(
                read_private_file(&kek, "kek"),
                Err(PrivateFsError::InsecurePermissions(_))
            ),
            "subsequent KEK open must refuse a world-readable DACL"
        );
    }

    #[cfg(windows)]
    #[test]
    fn vault_windows_kek_file_refuses_hard_link() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kek = dir.path().join("wrap.key");
        write_private_file(&kek, b"kek-bytes-32................").expect("write KEK");
        let alias = dir.path().join("wrap.key.alias");
        std::fs::hard_link(&kek, &alias).expect("create hard link");
        let error = write_private_file(&kek, b"replacement-kek.............").expect_err("nlink>1");
        assert!(
            matches!(
                error.downcast_ref::<PrivateFsError>(),
                Some(PrivateFsError::MultiplyLinked(_))
            ),
            "hard-linked KEK must be MultiplyLinked, got {error:?}"
        );
        assert!(
            matches!(
                read_private_file(&kek, "kek"),
                Err(PrivateFsError::MultiplyLinked(_))
            ),
            "subsequent open of a hard-linked KEK must refuse"
        );
    }

    // -- Windows export writes: private file, untouched parent ------------

    // `write_private_export_file` on Windows must enforce the file-level
    // discipline (owner-only DACL, single link, no reparse, real file) while
    // leaving the user-chosen output directory's ACL exactly as it was — the
    // same non-tightening contract the Unix export funnel has.
    #[cfg(windows)]
    #[test]
    fn export_windows_write_is_private_and_never_tightens_parent() {
        let root = tempfile::tempdir().expect("tempdir");

        // A pre-existing user directory keeps its default (inherited) ACL: it
        // does NOT verify as protected owner-only before or after the export.
        assert!(
            crate::goal_scratch::verify_private_dacl(root.path()).is_err(),
            "the fixture must start as a non-owner-only directory"
        );
        ensure_output_parent_private(root.path()).expect("existing parent accepted untouched");
        assert!(
            crate::goal_scratch::verify_private_dacl(root.path()).is_err(),
            "a pre-existing user directory must not be tightened"
        );

        let target = root.path().join("session-export.zip");
        write_private_export_file(&target, b"EXPORT-BYTES").expect("export write succeeds");
        assert_eq!(
            std::fs::read(&target).expect("read export"),
            b"EXPORT-BYTES"
        );
        verify_windows_private_path(&target, "export")
            .expect("the written export must verify owner-only and singly-linked");
        assert!(
            crate::goal_scratch::verify_private_dacl(root.path()).is_err(),
            "the shared parent's ACL must still not have been rewritten"
        );

        // A MISSING parent is created private (owner-only DACL), mirroring
        // the Unix arm's 0700 create.
        let created = root.path().join("made-up-export-dir");
        ensure_output_parent_private(&created).expect("missing parent created private");
        crate::goal_scratch::verify_private_dacl(&created)
            .expect("a cockpit-created export parent must be owner-only");
        let nested = created.join("deep.zip");
        write_private_export_file(&nested, b"NESTED").expect("write into created parent");
        verify_windows_private_path(&nested, "export").expect("nested export verifies private");
    }

    // The staged file is BORN owner-only — the Windows twin of the Unix
    // `0600`-at-create. This must hold inside a shared parent whose ACL is
    // deliberately never tightened (no create-then-harden window in which a
    // co-tenant of the output directory could open the staged export and
    // keep reading bytes written after a later harden), and it must verify
    // through the held handle before any byte is written.
    #[cfg(windows)]
    #[test]
    fn windows_private_create_is_born_owner_only_in_a_shared_parent() {
        let root = tempfile::tempdir().expect("tempdir");
        assert!(
            crate::goal_scratch::verify_private_dacl(root.path()).is_err(),
            "fixture parent must start as a non-owner-only directory"
        );
        let staged = root.path().join(".tmp-born");
        let file = create_windows_private_file_exclusive(&staged).expect("born-private create");
        verify_windows_open_file(&file, &staged, "staged export")
            .expect("the born DACL must verify owner-only through the held handle");
        drop(file);
        crate::goal_scratch::verify_private_dacl(&staged)
            .expect("a newly staged file must be born with the protected owner-only DACL");
    }

    // The Windows export writer refuses the same hostile targets the Unix
    // funnel does: a reparse point (junction) at the destination or an
    // ancestor, a non-regular destination, and a hard-linked alias.
    #[cfg(windows)]
    #[test]
    fn export_windows_write_refuses_reparse_directory_and_hard_link_targets() {
        let root = tempfile::tempdir().expect("tempdir");
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();

        // Junction at the destination: refused, nothing written through it.
        let junction_target = root.path().join("junc.zip");
        create_windows_junction(&junction_target, &real);
        let error =
            write_private_export_file(&junction_target, b"EXPORT").expect_err("reparse target");
        assert!(
            matches!(
                error.downcast_ref::<PrivateFsError>(),
                Some(PrivateFsError::Containment(_))
            ),
            "a reparse-point destination must be Containment, got {error:?}"
        );

        // Reparse on an ANCESTOR of the destination: refused before writing.
        let junction_parent = root.path().join("junc-parent");
        create_windows_junction(&junction_parent, &real);
        let error = write_private_export_file(&junction_parent.join("export.zip"), b"EXPORT")
            .expect_err("reparse ancestor");
        assert!(
            matches!(
                error.downcast_ref::<PrivateFsError>(),
                Some(PrivateFsError::Containment(_))
            ),
            "a reparse-point ancestor must be Containment, got {error:?}"
        );
        assert!(
            !real.join("export.zip").exists(),
            "no export may land through the junction ancestor"
        );

        // A plain directory at the destination: refused, not written through.
        let dir_target = root.path().join("dir-target");
        std::fs::create_dir(&dir_target).unwrap();
        let error =
            write_private_export_file(&dir_target, b"EXPORT").expect_err("directory target");
        assert!(
            matches!(
                error.downcast_ref::<PrivateFsError>(),
                Some(PrivateFsError::Containment(_))
            ),
            "a directory destination must be Containment, got {error:?}"
        );

        // A hard-linked existing destination: refused (the alias could read
        // the export), and the alias still sees only its own bytes.
        let linked = root.path().join("linked.zip");
        write_private_export_file(&linked, b"ORIGINAL").expect("initial export");
        let alias = root.path().join("alias.zip");
        std::fs::hard_link(&linked, &alias).expect("create hard link");
        let error = write_private_export_file(&linked, b"REPLACEMENT").expect_err("nlink>1");
        assert!(
            matches!(
                error.downcast_ref::<PrivateFsError>(),
                Some(PrivateFsError::MultiplyLinked(_))
            ),
            "a hard-linked destination must be MultiplyLinked, got {error:?}"
        );
        assert_eq!(
            std::fs::read(&alias).expect("read alias"),
            b"ORIGINAL",
            "the replacement must never have been published through the link"
        );
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
            !after
                .windows(b"NEW-SECRET-PAYLOAD".len())
                .any(|w| w == b"NEW-SECRET-PAYLOAD"),
            "the new secret must never be written into the victim on a failed write"
        );
    }

    // -- handle-anchored write refuses a symlinked target (Unix, AC5) -----

    // A symlink planted at the write target must be refused (`Containment`) and
    // the victim it points to must be byte-identical and never observe the
    // secret. The predecessor's path-based `persist` silently *replaced* the
    // symlink and returned `Ok(())`; the fd-anchored funnel refuses the
    // hostile pre-existing target explicitly via an `fstatat` no-follow probe.
    #[cfg(unix)]
    #[test]
    fn private_fs_security_write_refuses_symlinked_target_without_disclosing_bytes() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        // Victim with a known sentinel, OUTSIDE the write directory.
        let victim = root.path().join("victim-secret");
        std::fs::write(&victim, b"VICTIM-SENTINEL").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();

        // A private 0700 write directory with a symlink planted at the target.
        let dir = root.path().join("store");
        ensure_private_dir(&dir).expect("ensure private dir");
        let target = dir.join("creds.json");
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        let error = write_private_file(&target, b"TOP-SECRET-PAYLOAD").unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<PrivateFsError>(),
                Some(PrivateFsError::Containment(_))
            ),
            "a symlinked write target must be refused with Containment, got {error:?}"
        );
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"VICTIM-SENTINEL",
            "the symlink victim must be byte-identical"
        );
        assert!(
            !std::fs::read(&victim)
                .unwrap()
                .windows(b"TOP-SECRET-PAYLOAD".len())
                .any(|w| w == b"TOP-SECRET-PAYLOAD"),
            "the secret must never reach the victim"
        );
    }

    // -- handle-anchored write refuses a hard-linked target (Unix, AC6) ---

    // A hard link to the write target (nlink != 1) must be refused
    // (`MultiplyLinked`) so a secret is never placed at an inode an attacker
    // still aliases. The predecessor's `persist` returned `Ok(())` here.
    #[cfg(unix)]
    #[test]
    fn private_fs_security_write_refuses_hard_linked_target() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = dir.path().join("creds.json");
        std::fs::write(&target, b"OLD").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = dir.path().join("attacker-alias");
        std::fs::hard_link(&target, &alias).unwrap();

        let error = write_private_file(&target, b"NEW-SECRET-PAYLOAD").unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<PrivateFsError>(),
                Some(PrivateFsError::MultiplyLinked(_))
            ),
            "a hard-linked write target must be refused with MultiplyLinked, got {error:?}"
        );
        assert!(
            !std::fs::read(&alias)
                .unwrap()
                .windows(b"NEW-SECRET-PAYLOAD".len())
                .any(|w| w == b"NEW-SECRET-PAYLOAD"),
            "the attacker alias must never observe the secret"
        );
    }

    // -- write funnel still serves a shared (export) parent (Unix) --------

    // The funnel also backs user-chosen session exports, whose destination is a
    // legitimately shared, non-0700 directory the user may not own. Writing into
    // a self-owned 0755 directory must still succeed and still produce a 0600
    // file — a regression guard against re-imposing a 0700/owned parent check.
    #[cfg(unix)]
    #[test]
    fn private_fs_security_write_succeeds_into_shared_parent_for_exports() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        let shared = root.path().join("shared-export-dir");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();

        let target = shared.join("export.json");
        write_private_file(&target, b"EXPORTED-BYTES").expect("write into a 0755 shared parent");

        assert_eq!(std::fs::read(&target).unwrap(), b"EXPORTED-BYTES");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600,
            "the exported secret file must still be 0600"
        );
        assert_eq!(
            std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777,
            0o755,
            "the shared parent must not be tightened"
        );
    }

    // -- ensure refuses a symlinked intermediate component (Unix, AC4) ----

    // A symlink planted at an intermediate component that `ensure_private_dir`
    // must create is refused (`Containment`) and no directory is created beneath
    // the symlink's (dangling) target — the fix for `create_dir_all` following
    // symlinks at each component. The component-wise `mkdirat` fails `EEXIST` on
    // the planted symlink and the no-follow `openat` then rejects it with ELOOP.
    #[cfg(unix)]
    #[test]
    fn private_fs_security_ensure_dir_refuses_symlinked_intermediate_component() {
        let root = tempfile::tempdir().expect("tempdir");
        // A dangling symlink at the intermediate component `mid`, pointing where
        // `create_dir_all` would have created the victim tree.
        let victim = root.path().join("victim-tree");
        let mid = root.path().join("mid");
        std::os::unix::fs::symlink(&victim, &mid).unwrap();

        let target = mid.join("leaf");
        let result = ensure_private_dir(&target);

        assert!(
            matches!(result, Err(PrivateFsError::Containment(_))),
            "a symlinked intermediate component must be refused, got {result:?}"
        );
        assert!(
            !victim.exists(),
            "no directory may be created through the intermediate symlink"
        );
        assert!(
            !target.exists(),
            "the leaf must not be created beneath the victim"
        );
    }

    // -- ensure refuses an intermediate symlink to a REAL dir (Unix, A) ---

    // The confused-deputy regression for FINDING A: an attacker who controls an
    // ancestor plants an intermediate symlink pointing at a REAL directory they
    // own. The previous following-resolution (canonicalize / `O_DIRECTORY`
    // without `O_NOFOLLOW`) would have resolved THROUGH it and created the leaf
    // inside the attacker's directory. The no-follow component walk refuses the
    // symlink component (its parent — a user tempdir — is not a trusted,
    // root-owned, non-writable directory) with `Containment` and creates nothing.
    #[cfg(unix)]
    #[test]
    fn private_fs_security_ensure_dir_refuses_intermediate_symlink_to_real_dir() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        // A REAL attacker-controlled directory the symlink points into.
        let victim = root.path().join("attacker-dir");
        std::fs::create_dir(&victim).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o700)).unwrap();

        // The intermediate component `mid` is a (user-owned) symlink to victim.
        let mid = root.path().join("mid");
        std::os::unix::fs::symlink(&victim, &mid).unwrap();

        let target = mid.join("state").join("cockpit");
        let result = ensure_private_dir(&target);

        assert!(
            matches!(result, Err(PrivateFsError::Containment(_))),
            "an intermediate symlink to a real dir must be refused, got {result:?}"
        );
        assert!(
            !victim.join("state").exists(),
            "nothing may be created inside the attacker's real directory"
        );
    }

    // -- open_private_dir_handle refuses a swapped directory symlink (B) --

    // FINDING B rests on this primitive: log rotation opens the directory once
    // through `open_private_dir_handle` and does every unlinkat/renameat/open
    // relative to that fd. If the directory entry is swapped for a symlink, the
    // no-follow walk refuses it (`Containment`) rather than operating inside the
    // attacker's target — so rotation can never delete/rename in a redirected
    // directory. The victim's contents are left untouched.
    #[cfg(unix)]
    #[test]
    fn private_fs_security_open_private_dir_handle_refuses_symlinked_dir() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        let victim = root.path().join("victim-logs");
        std::fs::create_dir(&victim).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(victim.join("cockpit.log.1"), b"VICTIM-BACKUP").unwrap();

        let link = root.path().join("logdir");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let result = open_private_dir_handle(&link);
        assert!(
            matches!(result, Err(PrivateFsError::Containment(_))),
            "a symlinked directory must be refused, got {result:?}"
        );
        assert_eq!(
            std::fs::read(victim.join("cockpit.log.1")).unwrap(),
            b"VICTIM-BACKUP",
            "the victim directory's contents must be untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nofollow_directory_tree_refuses_symlinked_file_and_directory_entries() {
        let root = tempfile::tempdir().expect("tempdir");
        let package = root.path().join("agent-package");
        let victim = root.path().join("victim");
        std::fs::create_dir(&package).unwrap();
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("secret.md"), b"victim").unwrap();
        std::os::unix::fs::symlink(victim.join("secret.md"), package.join("agent.md")).unwrap();
        std::os::unix::fs::symlink(&victim, package.join("subagents")).unwrap();

        let result = read_nofollow_directory_tree(&package, 1024, 4096);
        assert!(matches!(result, Err(PrivateFsError::Containment(_))));
        assert_eq!(std::fs::read(victim.join("secret.md")).unwrap(), b"victim");
    }

    #[cfg(unix)]
    #[test]
    fn nofollow_directory_tree_rejects_cross_platform_separator_collision() {
        let root = tempfile::tempdir().expect("tempdir");
        let package = root.path().join("agent-package");
        std::fs::create_dir_all(package.join("subagents")).unwrap();
        std::fs::write(package.join("subagents").join("helper.md"), b"nested").unwrap();
        std::fs::write(package.join("subagents\\helper.md"), b"unix-name").unwrap();

        let result = read_nofollow_directory_tree(&package, 1024, 4096);
        assert!(
            matches!(result, Err(PrivateFsError::Containment(ref message)) if message.contains("cross-platform path separator")),
            "portable package path collision must fail closed: {result:?}"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn public_nofollow_directory_tree_refuses_excess_depth() {
        let root = tempfile::tempdir().expect("tempdir");
        let package = root.path().join("agent-package");
        let mut nested = package.clone();
        for index in 0..=MAX_NOFOLLOW_DIRECTORY_TREE_DEPTH {
            nested.push(format!("level-{index}"));
        }
        std::fs::create_dir_all(&nested).expect("nested package directories");
        std::fs::write(nested.join("agent.md"), b"definition").expect("nested package file");

        let error = read_nofollow_directory_tree(&package, 1_024, 4_096)
            .expect_err("public traversal must enforce its shared depth cap");
        assert!(error.to_string().contains("directory depth limit"));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn public_nofollow_directory_tree_refuses_excess_entry_count() {
        let root = tempfile::tempdir().expect("tempdir");
        let package = root.path().join("agent-package");
        std::fs::create_dir(&package).expect("package directory");
        for index in 0..=MAX_NOFOLLOW_DIRECTORY_TREE_ENTRIES {
            std::fs::write(package.join(format!("entry-{index}")), b"").expect("package entry");
        }

        let error = read_nofollow_directory_tree(&package, 1_024, 4_096)
            .expect_err("public traversal must enforce its shared entry cap");
        assert!(error.to_string().contains("entry count limit"));
    }

    #[cfg(windows)]
    #[test]
    fn nofollow_directory_tree_uses_windows_held_handle_traversal() {
        let root = tempfile::tempdir().expect("tempdir");
        let package = root.path().join("agent-package");
        std::fs::create_dir_all(package.join("subagents")).expect("package directories");
        std::fs::write(package.join("agent.md"), b"root").expect("package root");
        std::fs::write(package.join("subagents/helper.md"), b"child").expect("package child");

        let files = read_nofollow_directory_tree(&package, 1024, 4096)
            .expect("held Windows package traversal");
        assert_eq!(files.get("agent.md").map(Vec::as_slice), Some(&b"root"[..]));
        assert_eq!(
            files.get("subagents/helper.md").map(Vec::as_slice),
            Some(&b"child"[..])
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn held_workspace_tree_refuses_excess_entry_count_before_collection() {
        let root = tempfile::tempdir().expect("tempdir");
        let package = root.path().join("agent-package");
        std::fs::create_dir(&package).expect("package directory");
        for name in ["agent.md", "one.md", "two.md"] {
            std::fs::write(package.join(name), b"definition").expect("package file");
        }
        let authority = held_directory::HeldWorkspaceDirectoryAuthority::open_existing(root.path())
            .expect("held workspace authority");

        let error = authority
            .read_directory_tree_relative_bounded(&["agent-package"], 1_024, 4_096, 2, 8)
            .expect_err("third entry must exceed the tree cap");
        assert!(error.to_string().contains("entry count limit"));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn held_workspace_tree_refuses_excess_depth_before_recursion() {
        let root = tempfile::tempdir().expect("tempdir");
        let package = root.path().join("agent-package");
        std::fs::create_dir_all(package.join("one").join("two"))
            .expect("nested package directories");
        std::fs::write(package.join("one/two/agent.md"), b"definition")
            .expect("nested package file");
        let authority = held_directory::HeldWorkspaceDirectoryAuthority::open_existing(root.path())
            .expect("held workspace authority");

        let error = authority
            .read_directory_tree_relative_bounded(&["agent-package"], 1_024, 4_096, 16, 1)
            .expect_err("second nested directory must exceed the tree cap");
        assert!(error.to_string().contains("directory depth limit"));
    }

    #[cfg(unix)]
    #[test]
    fn owned_nofollow_reader_accepts_normal_repository_file_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("tempdir");
        let agents = root.path().join(".cockpit").join("agents");
        std::fs::create_dir_all(&agents).expect("agents directory");
        let definition = agents.join("reviewer.md");
        std::fs::write(&definition, b"repository definition").expect("definition");
        std::fs::set_permissions(&definition, std::fs::Permissions::from_mode(0o644))
            .expect("normal repository mode");

        assert_eq!(
            read_owned_file_nofollow(&definition, "shared definition", 1024)
                .expect("0644 shared definition is safe")
                .expect("definition exists"),
            b"repository definition"
        );
        assert_eq!(
            std::fs::metadata(&definition)
                .expect("definition metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644,
            "a non-secret read must not rewrite repository permissions"
        );
    }

    #[cfg(windows)]
    #[test]
    fn owned_nofollow_reader_accepts_normal_repository_acl() {
        let root = tempfile::tempdir().expect("tempdir");
        let agents = root.path().join(".cockpit").join("agents");
        std::fs::create_dir_all(&agents).expect("agents directory");
        let definition = agents.join("reviewer.md");
        std::fs::write(&definition, b"repository definition").expect("definition");
        crate::goal_scratch::apply_test_windows_dacl(&definition, "D:P(A;;FA;;;WD)")
            .expect("apply ordinary shared repository ACL");

        assert_eq!(
            read_owned_file_nofollow(&definition, "shared definition", 1024)
                .expect("normal repository ACL is safe for a non-secret held read")
                .expect("definition exists"),
            b"repository definition"
        );
        assert!(
            crate::goal_scratch::verify_private_dacl(&definition).is_err(),
            "the non-secret reader must not require or rewrite a secret-store DACL"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nofollow_readers_reject_fifo_without_waiting_for_a_writer() {
        use std::os::unix::ffi::OsStrExt as _;

        let root = tempfile::tempdir().expect("tempdir");
        let package = root.path().join("agent-package");
        std::fs::create_dir(&package).expect("package");
        let fifo = package.join("agent.md");
        let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
        let created = unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) };
        assert_eq!(
            created,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        assert!(matches!(
            read_owned_file_nofollow(&fifo, "shared definition", 1024),
            Err(PrivateFsError::Containment(_))
        ));
        assert!(matches!(
            read_nofollow_directory_tree(&package, 1024, 4096),
            Err(PrivateFsError::Containment(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn readdir_null_distinguishes_end_of_stream_from_enumeration_failure() {
        assert!(
            classify_readdir_result(std::ptr::null_mut(), std::io::Error::from_raw_os_error(0),)
                .unwrap()
                .is_none(),
            "zero errno is the only null readdir result treated as EOF"
        );
        let error = classify_readdir_result(
            std::ptr::null_mut(),
            std::io::Error::from_raw_os_error(libc::EIO),
        )
        .expect_err("nonzero readdir errno must fail enumeration");
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    // -- symlink-follow gate decides on the PARENT dir, not the symlink (A) --

    // The follow decision must depend only on the held parent directory being one
    // a non-root attacker cannot write entries into. A root-owned symlink sitting
    // in a NON-root or writable directory must be REFUSED (the old inode-owner
    // exception would have followed it); only a root-owned, non-group/world-
    // writable parent (e.g. `/` at 0755, where Fedora's `/home` symlink lives)
    // permits the single follow.
    #[cfg(unix)]
    #[test]
    fn private_fs_security_symlink_follow_gate_is_parent_based() {
        // Legitimate system case: root-owned 0755 parent (e.g. `/`) -> follow.
        assert!(parent_permits_symlink_follow(0, 0o40755));
        assert!(parent_permits_symlink_follow(0, 0o755));
        assert!(parent_permits_symlink_follow(0, 0o700));

        // Root-owned but group- or world-writable parent -> REFUSE (an attacker
        // in the writable group/world could have planted the symlink entry).
        assert!(!parent_permits_symlink_follow(0, 0o775)); // group-writable
        assert!(!parent_permits_symlink_follow(0, 0o757)); // world-writable
        assert!(!parent_permits_symlink_follow(0, 0o1777)); // sticky /tmp-like

        // Non-root-owned parent -> REFUSE regardless of mode, even for a symlink
        // whose own inode is root-owned: the entry lives in a dir the user (a
        // would-be attacker) controls and can relocate a root-owned symlink into.
        assert!(!parent_permits_symlink_follow(1000, 0o755));
        assert!(!parent_permits_symlink_follow(1000, 0o700));
    }
}
