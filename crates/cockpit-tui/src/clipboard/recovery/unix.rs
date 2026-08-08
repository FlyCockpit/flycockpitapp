//! Unix directory containment for the private clipboard recovery artifact.
//!
//! Every creation, read, and removal goes through a held, no-follow
//! directory file descriptor opened relative to a once-resolved root. A
//! name discovered by enumeration is never trusted: it is reopened beneath
//! the held descriptor with `O_NOFOLLOW` before any byte is written or
//! read, and every reopen is re-verified against
//! [`super::policy::verify_unix_file`].

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::policy::{self, EXPECTED_DIR_MODE, EXPECTED_FILE_MODE, UnixDirStat, UnixFileStat};

fn io_err(context: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

fn cstring(name: &str) -> io::Result<CString> {
    CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("NUL in {name:?}")))
}

/// A held, no-follow recovery directory handle.
pub struct DirHandle {
    dir: File,
    path: PathBuf,
}

impl DirHandle {
    /// Open (creating if missing) the recovery directory at exactly
    /// `path`. `path`'s parent is created with ordinary (non-hardened)
    /// `create_dir_all` — it is the shared, already-existing Cockpit state
    /// directory, not the private artifact directory — and only the final
    /// component is opened/created no-follow at exactly `0700`.
    pub fn open_or_create(path: &Path) -> io::Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
        std::fs::create_dir_all(parent).map_err(|e| io_err("creating state directory", e))?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 path"))?;
        let canonical_parent =
            std::fs::canonicalize(parent).map_err(|e| io_err("resolving state directory", e))?;
        let parent_c = cstring(canonical_parent.to_string_lossy().as_ref())?;
        // SAFETY: `parent_c` is a live NUL-terminated string for the call;
        // the returned fd is transferred exactly once into `File`.
        let parent_fd = unsafe {
            libc::open(
                parent_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if parent_fd < 0 {
            return Err(io_err(
                "opening state directory",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: `parent_fd` was just returned by `open` and is uniquely owned.
        let parent_dir = unsafe { File::from_raw_fd(parent_fd) };

        let name_c = cstring(name)?;
        let (dir, created) = open_dir_at(&parent_dir, &name_c)?;
        if created {
            enforce_dir_mode(&dir)?;
        }
        let handle = Self {
            dir,
            path: canonical_parent.join(name),
        };
        handle.verify_private()?;
        Ok(handle)
    }

    pub fn verify_private(&self) -> io::Result<()> {
        let stat = dir_stat(&self.dir)?;
        policy::verify_unix_dir(stat)
            .map_err(|v| io::Error::other(format!("recovery directory failed containment: {v:?}")))
    }

    /// Create a new file that must not already exist, at exactly `0600`.
    pub fn create_file_exclusive(&self, name: &str) -> io::Result<File> {
        let cname = cstring(name)?;
        let flags =
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: the directory descriptor and name stay live for the call.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                cname.as_ptr(),
                flags,
                EXPECTED_FILE_MODE as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io_err(
                "creating recovery artifact",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: `fd` was just returned by `openat` and is uniquely owned.
        let file = unsafe { File::from_raw_fd(fd) };
        // `openat` mode bits are masked by the process umask, so fchmod the
        // descriptor we already hold and re-verify.
        // SAFETY: the descriptor is live for the call.
        if unsafe { libc::fchmod(file.as_raw_fd(), EXPECTED_FILE_MODE as libc::mode_t) } != 0 {
            return Err(io_err(
                "chmod 0600 recovery artifact",
                io::Error::last_os_error(),
            ));
        }
        let stat = file_stat(&file)?;
        policy::verify_unix_file(stat, current_uid()).map_err(|v| {
            io::Error::other(format!("new recovery artifact failed containment: {v:?}"))
        })?;
        Ok(file)
    }

    /// Reopen-and-classify an untrusted enumerated name in one step,
    /// without ever letting an unsafe entry abort the whole scan.
    ///
    /// A symlink can never succeed here at all — `O_NOFOLLOW` makes the
    /// `openat` itself fail with `ELOOP`, not a post-open stat mismatch —
    /// and the same is true of a directory (`EISDIR`) or anything else the
    /// kernel refuses to open `O_RDWR`. Every such failure, along with a
    /// successful open that fails [`policy::verify_unix_file`], is
    /// [`CheckedEntry::Unsafe`]: reported by count, left exactly as found.
    pub fn open_file_verified(&self, name: &str) -> io::Result<CheckedEntry> {
        let cname = cstring(name)?;

        // Type pre-check via `fstatat(AT_SYMLINK_NOFOLLOW)`, before ever
        // calling `openat`. A regular file is the only type this ever
        // opens: a FIFO opened `O_RDWR` does not block on Linux/macOS, but
        // it is still a real interaction with the pipe (it can complete a
        // peer's blocked `open()` as a side effect), and a device node
        // opened `O_RDWR` can have arbitrary driver-defined effects —
        // "unsafe entries are never opened" means never, not "never
        // blockingly". This costs one extra syscall and leaves a narrow,
        // irreducible-without-`O_PATH`-reopen-by-fd TOCTOU between this
        // check and the `openat` below, the same trade-off already
        // accepted for every other name-based operation in this module.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: dirfd and name are live for the call; `stat` is a valid,
        // exactly-sized out-pointer.
        let statted = unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                cname.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if statted != 0 {
            let error = io::Error::last_os_error();
            return Ok(if error.kind() == io::ErrorKind::NotFound {
                CheckedEntry::Missing
            } else {
                CheckedEntry::Unsafe
            });
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            // Symlink, FIFO, socket, device, or directory: never opened.
            return Ok(CheckedEntry::Unsafe);
        }

        let flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: dirfd and name are live for the call.
        let fd = unsafe { libc::openat(self.dir.as_raw_fd(), cname.as_ptr(), flags) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            return Ok(if error.kind() == io::ErrorKind::NotFound {
                CheckedEntry::Missing
            } else {
                CheckedEntry::Unsafe
            });
        }
        // SAFETY: `fd` was just returned by `openat` and is uniquely owned.
        let file = unsafe { File::from_raw_fd(fd) };
        let stat = file_stat(&file)?;
        Ok(match policy::verify_unix_file(stat, current_uid()) {
            Ok(()) => CheckedEntry::Ok(file),
            Err(_) => CheckedEntry::Unsafe,
        })
    }

    pub fn remove_file(&self, name: &str) -> io::Result<()> {
        let cname = cstring(name)?;
        // SAFETY: dirfd and name are live for the call.
        let result = unsafe { libc::unlinkat(self.dir.as_raw_fd(), cname.as_ptr(), 0) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(io_err("removing recovery artifact", error));
        }
        Ok(())
    }

    /// Remove `name` only if it still identifies the exact same file as
    /// `verified` — the handle already opened and verified by
    /// [`Self::open_file_verified`]. `unlink`/`unlinkat` are inherently
    /// name-based on Unix (there is no "delete this fd" primitive the way
    /// Windows has `FileDispositionInfo`), so this cannot be made fully
    /// atomic; what it does do is compare against the identity of the
    /// *still-open verified handle* (never a stale scan-time record)
    /// immediately adjacent to the `unlinkat` call, closing the wide gap
    /// that previously existed between verification and a much-later
    /// by-name removal. A mismatch (the name was swapped) or the name
    /// already being gone both leave the entry exactly as found — neither
    /// is an error.
    pub fn remove_verified(&self, name: &str, verified: File) -> io::Result<bool> {
        let expected = file_identity(
            &verified
                .metadata()
                .map_err(|e| io_err("stat verified handle", e))?,
        );
        let cname = cstring(name)?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: dirfd and name are live for the call; `stat` is a valid,
        // exactly-sized out-pointer. `AT_SYMLINK_NOFOLLOW` matches the
        // no-follow contract everywhere else in this module.
        let statted = unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                cname.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        drop(verified);
        if statted != 0 {
            // Gone since verification: nothing to remove, not an error.
            return Ok(false);
        }
        if (stat.st_dev as u64, stat.st_ino as u64) != expected {
            // Swapped since verification: leave whatever is there now
            // exactly as found.
            return Ok(false);
        }
        // SAFETY: dirfd and name are live for the call.
        let result = unsafe { libc::unlinkat(self.dir.as_raw_fd(), cname.as_ptr(), 0) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(io_err("removing recovery artifact", error));
        }
        Ok(true)
    }

    /// List raw entry names. Untrusted: every caller must reopen each name
    /// through [`Self::open_file_verified`] before touching it.
    pub fn list_names(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.path).map_err(|e| io_err("scanning directory", e))? {
            let entry = entry.map_err(|e| io_err("reading directory entry", e))?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    /// fsync the directory itself, so a create/remove is durable.
    pub fn sync(&self) -> io::Result<()> {
        self.dir.sync_all()
    }
}

fn open_dir_at(parent: &File, name: &CString) -> io::Result<(File, bool)> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    for attempt in 0..2 {
        // SAFETY: `parent` is a live descriptor and `name` stays alive for
        // the call. `O_NOFOLLOW` rejects a symlink at the final component.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd >= 0 {
            // SAFETY: `fd` was just returned by `openat` and is uniquely owned.
            return Ok((unsafe { File::from_raw_fd(fd) }, attempt > 0));
        }
        let error = io::Error::last_os_error();
        if attempt == 0 && error.kind() == io::ErrorKind::NotFound {
            // SAFETY: same liveness argument; `mkdirat` creates one component.
            let made = unsafe {
                libc::mkdirat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    EXPECTED_DIR_MODE as libc::mode_t,
                )
            };
            if made != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(io_err("creating recovery directory", error));
                }
            }
            continue;
        }
        return Err(io_err("opening recovery directory", error));
    }
    Err(io::Error::other(
        "recovery directory could not be opened after creation",
    ))
}

fn enforce_dir_mode(dir: &File) -> io::Result<()> {
    // SAFETY: the descriptor is live for the call.
    if unsafe { libc::fchmod(dir.as_raw_fd(), EXPECTED_DIR_MODE as libc::mode_t) } != 0 {
        return Err(io_err(
            "chmod 0700 recovery directory",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn dir_stat(dir: &File) -> io::Result<UnixDirStat> {
    let metadata = dir.metadata().map_err(|e| io_err("stat directory", e))?;
    Ok(UnixDirStat {
        is_directory: metadata.is_dir(),
        // A descriptor opened with `O_NOFOLLOW` never resolves through a
        // symlink component; the containment check here is defense in
        // depth against a caller misusing a raw `File`, not a live gap.
        is_symlink: false,
        mode_bits: metadata.mode() & 0o777,
    })
}

fn file_stat(file: &File) -> io::Result<UnixFileStat> {
    let metadata = file.metadata().map_err(|e| io_err("stat file", e))?;
    Ok(UnixFileStat {
        is_regular_file: metadata.is_file(),
        is_symlink: false,
        mode_bits: metadata.mode() & 0o777,
        uid: metadata.uid(),
        nlink: metadata.nlink(),
    })
}

/// A file's identity for the purpose of noticing a name got swapped out
/// from under a verify-then-act sequence: (device, inode). Never content.
fn file_identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

/// Result of opening-and-verifying an untrusted enumerated name.
pub enum CheckedEntry {
    Missing,
    Unsafe,
    Ok(File),
}

pub fn current_uid() -> u32 {
    // SAFETY: `getuid` has no preconditions and never fails.
    unsafe { libc::getuid() }
}
