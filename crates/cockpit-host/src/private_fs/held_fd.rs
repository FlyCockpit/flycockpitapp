//! Canonical Unix held-fd filesystem syscalls for the `private_fs` family.
//!
//! This module is the SINGLE home for the raw, fd-anchored, no-follow syscalls
//! (`openat`/`mkdirat`/`fchmod`/`unlinkat`/`linkat`/`renameat2`/`fstatat`) used
//! by the `private_fs` primitives and their in-crate consumers — the
//! external-journal spool directory guards and the held-directory authority
//! [`crate::private_fs::held_directory`]. Before this
//! consolidation each consumer re-implemented the same discipline; collapsing
//! them here means the containment guarantee (a name is always reopened
//! `O_NOFOLLOW` beneath a held directory fd, never re-resolved through a path)
//! lives in exactly one audited place.
//!
//! Each function is a thin wrapper that encapsulates the `unsafe` FFI and returns
//! a plain [`std::io::Result`]. Errno classification and mapping to a consumer's
//! own error type stay at the call site, so this module carries no policy — only
//! the syscall. The wrappers deliberately do not verify ownership/mode/link-count
//! (that is the caller's verdict); they only perform the effect and hand back the
//! held descriptor or the raw error.
//!
//! All descriptors are returned as owned [`std::fs::File`] values built from a
//! freshly-returned fd, so the fd is closed exactly once when the `File` drops.

use std::ffi::CStr;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, RawFd};

/// Flags for a no-follow directory walk that requires **search**, not **read**,
/// on existing components.
///
/// `O_RDONLY` on a directory demands `+r`, so a traverse-only ancestor
/// (`0711`/`0751` `/home`, or owner-`0111`) fails with `EACCES` even though
/// `mkdir`/`create_dir_all` would succeed. Linux `O_PATH` obtains a dirfd
/// without that read check; POSIX `O_SEARCH` is the same permission model on
/// Apple. Subsequent `openat`/`mkdirat` on the held fd still require `+x`.
pub fn directory_search_flags() -> libc::c_int {
    let nofollow = libc::O_NOFOLLOW | libc::O_CLOEXEC;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        libc::O_PATH | libc::O_DIRECTORY | nofollow
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        libc::O_SEARCH | nofollow
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        libc::O_RDONLY | libc::O_DIRECTORY | nofollow
    }
}

/// Open the filesystem root `/` as a held, no-follow directory fd. `/` can never
/// be a symlink, so this is the trusted anchor for a no-follow component walk.
///
/// Uses `O_RDONLY`: callers that need to traverse execute-only ancestors
/// should use [`open_fs_root_search`] instead.
pub fn open_fs_root() -> io::Result<File> {
    // SAFETY: `open` has no preconditions; the C string literal is NUL-terminated.
    let fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `open` and is uniquely owned.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Open `/` as the trusted anchor for a no-follow **search** walk. Does not
/// require read permission on `/` itself.
pub fn open_fs_root_search() -> io::Result<File> {
    // SAFETY: `open` has no preconditions; the C string literal is NUL-terminated.
    let fd = unsafe { libc::open(c"/".as_ptr(), directory_search_flags()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `open` and is uniquely owned.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// `openat(dir_fd, name, flags)` with no creation mode (no `O_CREAT`). The caller
/// supplies the exact flags, which must include `O_NOFOLLOW` for containment.
/// `dir_fd` may be a live directory fd or `libc::AT_FDCWD`.
pub fn openat(dir_fd: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: `dir_fd` is a live directory fd (or AT_FDCWD) and `name` outlives
    // the call.
    let fd = unsafe { libc::openat(dir_fd, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `openat` and is uniquely owned.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// `openat(dir_fd, name, flags, mode)` — the creating form. `mode` is passed to
/// the C variadic as `c_uint` (`mode_t` is `u16` on Apple targets and cannot be
/// passed to a variadic directly). Callers include `O_CREAT` in `flags`; note the
/// kernel masks `mode` by the process umask, so a caller wanting an exact mode
/// must follow with [`fchmod`].
pub fn openat_mode(
    dir_fd: RawFd,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::c_uint,
) -> io::Result<File> {
    // SAFETY: `dir_fd` is a live directory fd and `name` outlives the call;
    // `openat` is variadic so `mode` is passed as an explicit `c_uint`.
    let fd = unsafe { libc::openat(dir_fd, name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `openat` and is uniquely owned.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// `mkdirat(dir_fd, name, mode)` — create one directory component beneath the
/// held fd. `mode` is masked by the umask, so a caller wanting an exact mode
/// re-opens the component and [`fchmod`]s it.
pub fn mkdirat(dir_fd: RawFd, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: `dir_fd` is a live directory fd and `name` outlives the call.
    if unsafe { libc::mkdirat(dir_fd, name.as_ptr(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `fchmod(fd, mode)` on a held descriptor — set the exact mode through the fd
/// (never a re-resolved path). Linux `O_PATH` descriptors reject this with
/// `EBADF`; use [`fchmod_held_inode`] when the fd may be `O_PATH`.
pub fn fchmod(fd: RawFd, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: `fd` is a live descriptor for the duration of the call.
    if unsafe { libc::fchmod(fd, mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set `mode` on the inode of a held descriptor. Unlike [`fchmod`], this
/// accepts Linux `O_PATH` descriptors.
///
/// `fchmod` returns `EBADF` on `O_PATH`. `fchmodat2(AT_EMPTY_PATH)` would name
/// the held inode, but locked `libc` 0.2.189 does not define `SYS_fchmodat2`
/// for `aarch64-unknown-linux-gnu` (a first-party dist target), and Ubuntu
/// 22.04 kernels return `ENOSYS` even where the constant exists. Linux
/// therefore chmods `/proc/self/fd/{n}`, which follows the procfs magic
/// symlink to exactly that inode on 2.6.39+ without a path re-walk of the
/// original entry. Other Unix targets `fchmod` a search-capable fd.
pub fn fchmod_held_inode(fd: RawFd, mode: libc::mode_t) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        chmod_proc_self_fd(fd, mode)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        fchmod(fd, mode)
    }
}

/// `chmod("/proc/self/fd/{n}")` — operate on the inode of a held (possibly
/// `O_PATH`) descriptor. Fail closed if `/proc` is missing.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn chmod_proc_self_fd(fd: RawFd, mode: libc::mode_t) -> io::Result<()> {
    let path = CString::new(format!("/proc/self/fd/{fd}")).map_err(io::Error::other)?;
    // SAFETY: `path` is a valid C string naming this process's already-held fd.
    // `chmod` follows the procfs magic symlink to that inode and does not
    // re-resolve the original directory entry.
    if unsafe { libc::chmod(path.as_ptr(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `unlinkat(dir_fd, name, flags)` beneath the held fd. `flags` is `0` for a
/// file or `AT_REMOVEDIR` for a directory.
pub fn unlinkat(dir_fd: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: `dir_fd` is a live directory fd and `name` outlives the call.
    if unsafe { libc::unlinkat(dir_fd, name.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `renameat` relative to held directory descriptors.  Unlike a path based
/// rename, both names are resolved from capabilities the caller already owns;
/// callers that must refuse replacement use [`rename_noreplace`] instead.
pub fn renameat(from_dir_fd: RawFd, from: &CStr, to_dir_fd: RawFd, to: &CStr) -> io::Result<()> {
    // SAFETY: both directory descriptors are live and the one-component C
    // strings outlive this call.
    if unsafe { libc::renameat(from_dir_fd, from.as_ptr(), to_dir_fd, to.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `linkat(from_dir_fd, from, to_dir_fd, to, flags)`. `linkat` never replaces an
/// existing target: it fails with `EEXIST`, which is the no-replace guarantee the
/// spool quarantine and the held-directory publication both rely on.
pub fn linkat(
    from_dir_fd: RawFd,
    from: &CStr,
    to_dir_fd: RawFd,
    to: &CStr,
    flags: libc::c_int,
) -> io::Result<()> {
    // SAFETY: both dir fds are live and both names outlive the call.
    if unsafe { libc::linkat(from_dir_fd, from.as_ptr(), to_dir_fd, to.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `fstatat(dir_fd, name, AT_SYMLINK_NOFOLLOW)` — stat a name beneath the held fd
/// without following a final-component symlink. A `NotFound` error means the
/// entry is genuinely absent; the caller decides what that means.
pub fn fstatat_nofollow(dir_fd: RawFd, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `dir_fd` is a live directory fd, `name` outlives the call, and
    // `stat` is a valid out-pointer.
    let result = unsafe {
        libc::fstatat(
            dir_fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fstatat` returned 0, so `stat` is initialised.
    Ok(unsafe { stat.assume_init() })
}

/// Atomic no-replace rename relative to held directory fds. Linux uses
/// `renameat2(RENAME_NOREPLACE)`; macOS uses `renameatx_np(RENAME_EXCL)`. Both
/// fail (`EEXIST`) rather than overwriting an existing target, so there is no
/// check-then-rename window. Callers on kernels/filesystems lacking `renameat2`
/// see `ENOSYS`/`EINVAL` and fall back to a `linkat`+`unlinkat` two-step.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
pub fn rename_noreplace(
    from_dir_fd: RawFd,
    from: &CStr,
    to_dir_fd: RawFd,
    to: &CStr,
) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: both dir fds are live and both names outlive the call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from_dir_fd,
            from.as_ptr(),
            to_dir_fd,
            to.as_ptr(),
            1_u32, // RENAME_NOREPLACE
        ) as libc::c_int
    };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    // SAFETY: both dir fds are live and both names outlive the call.
    let result = unsafe {
        libc::renameatx_np(
            from_dir_fd,
            from.as_ptr(),
            to_dir_fd,
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Fail closed where the platform has no atomic no-replace directory rename.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
pub fn rename_noreplace(
    _from_dir_fd: RawFd,
    _from: &CStr,
    _to_dir_fd: RawFd,
    _to: &CStr,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace rename is unavailable on this platform",
    ))
}
