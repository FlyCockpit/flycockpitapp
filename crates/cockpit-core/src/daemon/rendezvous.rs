//! Canonical local-daemon file layout and rendezvous metadata.
//!
//! Keep this API narrow: the future supervisor can take ownership of the
//! directory, rendezvous, and start-lock files without changing daemon users.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use cockpit_host::daemon_lifecycle::{DaemonPidReceipt, ProcessStartIdentity};

pub const SOCKET_DIR_ENV: &str = "COCKPIT_SOCKET_DIR";
const SOCKET_PATH_RESERVE: usize = 32;

#[derive(Debug, Clone)]
pub struct Files {
    pub directory: PathBuf,
    pub socket: PathBuf,
    pub pid: PathBuf,
    pub rendezvous: PathBuf,
    pub start_lock: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Stable supervisor process. Before the supervised layout this was also
    /// the serving daemon process.
    pub pid: u32,
    pub start_time: ProcessStartIdentity,
    pub socket_path: PathBuf,
    pub protocol_version: u32,
    pub daemon_version: String,
    /// Current serving worker. `None` when the record is published by an
    /// unsupervised (single-process) daemon owner.
    pub worker_pid: Option<u32>,
    /// Monotonic worker generation owned by the supervisor.
    pub generation: u64,
    /// Supervisor-owned start clock, preserved across worker generations.
    pub opened_at_unix_ms: u64,
    // These retain the generation binding and lifetime policy used by the
    // existing lifecycle code while the public rendezvous fields stay simple.
    pub(crate) receipt: DaemonPidReceipt,
    pub(crate) ephemeral: bool,
}

pub fn resolve(database_path: &Path) -> Result<Files> {
    let identity = absolute_identity(database_path)?;
    let hash = identity_hash(&identity);

    let directory = if let Some(override_dir) = std::env::var_os(SOCKET_DIR_ENV) {
        let directory = PathBuf::from(override_dir);
        if !directory.is_dir() {
            anyhow::bail!(
                "{SOCKET_DIR_ENV} must name an existing directory: {}",
                directory.display()
            );
        }
        cockpit_host::private_fs::ensure_private_dir(&directory)
            .with_context(|| format!("securing {SOCKET_DIR_ENV}={}", directory.display()))?;
        directory
    } else {
        let xdg = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .map(|root| root.join("cockpit").join(&hash));
        match xdg {
            Some(candidate) if socket_path_fits(&candidate.join("cockpit.sock")) => candidate,
            _ => per_user_tmp_root(&hash)?.join("cockpit").join(&hash),
        }
    };

    let socket = directory.join("cockpit.sock");
    if !socket_path_fits(&socket) {
        if std::env::var_os(SOCKET_DIR_ENV).is_some() {
            anyhow::bail!(
                "{SOCKET_DIR_ENV} produces a daemon socket path longer than the platform limit: {}",
                socket.display()
            );
        }
        anyhow::bail!(
            "computed daemon socket path is longer than the platform limit: {}; set \
             {SOCKET_DIR_ENV} to a shorter existing directory",
            socket.display()
        );
    }
    cockpit_host::private_fs::ensure_private_dir(&directory)
        .with_context(|| format!("securing socket directory {}", directory.display()))?;
    Ok(Files {
        socket,
        pid: directory.join("daemon.pid"),
        rendezvous: directory.join("daemon.json"),
        start_lock: directory.join("start.lock"),
        directory,
    })
}

/// Stable directory component used by test harnesses and the later daemon
/// supervisor without requiring either to mutate process environment.
pub fn identity_hash(database_path: &Path) -> String {
    let mut hasher = Sha256::new();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        hasher.update(database_path.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        for unit in database_path.as_os_str().encode_wide() {
            hasher.update(unit.to_le_bytes());
        }
    }
    #[cfg(not(any(unix, windows)))]
    hasher.update(database_path.as_os_str().to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn absolute_identity(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("resolving current directory for daemon database identity")?
            .join(path))
    }
}

#[cfg(unix)]
fn per_user_tmp_root(hash: &str) -> Result<PathBuf> {
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let name = format!("cockpit-{uid}");
    let temp_root = std::env::temp_dir().join(&name);
    let short_root = Path::new("/tmp").join(&name);
    per_user_tmp_root_from_candidates(hash, [temp_root, short_root])
}

#[cfg(unix)]
fn per_user_tmp_root_from_candidates(
    hash: &str,
    candidates: impl IntoIterator<Item = PathBuf>,
) -> Result<PathBuf> {
    let mut attempted = Vec::new();
    for root in candidates {
        if attempted.iter().any(|(candidate, _)| candidate == &root) {
            continue;
        }
        let socket = root.join("cockpit").join(hash).join("cockpit.sock");
        if !socket_path_fits(&socket) {
            attempted.push((root, "socket path is too long".to_string()));
            continue;
        }
        match cockpit_host::private_fs::ensure_private_dir(&root) {
            Ok(()) => return Ok(root),
            Err(error) => attempted.push((root, format!("cannot secure directory: {error}"))),
        }
    }
    let attempted = attempted
        .into_iter()
        .map(|(path, reason)| format!("{} ({reason})", path.display()))
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        "no short private per-user daemon socket root is available; set {SOCKET_DIR_ENV} to a \
         shorter existing directory; tried: {attempted}"
    )
}

#[cfg(windows)]
fn per_user_tmp_root(_hash: &str) -> Result<PathBuf> {
    let root = std::env::temp_dir().join("cockpit-runtime");
    cockpit_host::private_fs::ensure_private_dir(&root)
        .with_context(|| format!("securing per-user runtime root {}", root.display()))?;
    Ok(root)
}

#[cfg(not(any(unix, windows)))]
fn per_user_tmp_root(_hash: &str) -> Result<PathBuf> {
    Ok(std::env::temp_dir().join("cockpit-runtime"))
}

#[cfg(unix)]
fn socket_path_fits(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let sun_len = std::mem::size_of::<libc::sockaddr_un>()
        - std::mem::offset_of!(libc::sockaddr_un, sun_path);
    path.as_os_str().as_bytes().len() < sun_len.saturating_sub(SOCKET_PATH_RESERVE)
}

#[cfg(not(unix))]
fn socket_path_fits(_path: &Path) -> bool {
    true
}

pub fn read(path: &Path) -> Option<Record> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

pub fn write(path: &Path, record: &Record) -> Result<()> {
    let data = serde_json::to_vec_pretty(record).context("serializing daemon rendezvous")?;
    cockpit_host::private_fs::write_private_file(path, &data)
        .with_context(|| format!("writing daemon endpoint rendezvous {}", path.display()))
}

#[derive(Debug)]
pub struct StartLock(std::fs::File);

impl StartLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("opening daemon start lock {}", path.display()))?;
            // SAFETY: file owns a valid descriptor for this blocking flock.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(std::io::Error::last_os_error()).context("locking daemon start file");
            }
            Ok(Self(file))
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle as _;
            use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx};
            let file = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(path)?;
            // SAFETY: OVERLAPPED is a plain C record whose all-zero state is
            // valid for a synchronous whole-file lock.
            let mut overlapped = unsafe { std::mem::zeroed() };
            // SAFETY: the file and OVERLAPPED remain valid for this synchronous call.
            if unsafe {
                LockFileEx(
                    file.as_raw_handle(),
                    LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error()).context("locking daemon start file");
            }
            Ok(Self(file))
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(Self(std::fs::File::open(path)?))
        }
    }
}

impl Drop for StartLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            // SAFETY: the descriptor remains live until this drop completes.
            let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle as _;
            use windows_sys::Win32::Storage::FileSystem::UnlockFile;
            // SAFETY: the handle remains live until this drop completes.
            let _ = unsafe { UnlockFile(self.0.as_raw_handle(), 0, 0, u32::MAX, u32::MAX) };
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt as _;

    #[test]
    fn oversized_darwin_style_temp_root_falls_back_to_short_candidate() {
        let fixture = tempfile::tempdir().expect("temp root fixture");
        let long = fixture.path().join("x".repeat(100)).join("cockpit-501");
        let short = fixture.path().join("s");
        let hash = "0123456789abcdef01234567";

        let selected =
            per_user_tmp_root_from_candidates(hash, [long.clone(), short.clone()]).unwrap();

        assert_eq!(selected, short);
        assert!(
            long.join("cockpit")
                .join(hash)
                .join("cockpit.sock")
                .as_os_str()
                .as_bytes()
                .len()
                >= 72,
            "fixture must exceed Darwin sun_path minus the leak-reveal reserve"
        );
        assert!(
            Path::new("/tmp")
                .join("cockpit-501")
                .join("cockpit")
                .join(hash)
                .join("cockpit.sock")
                .as_os_str()
                .as_bytes()
                .len()
                < 72,
            "the production /tmp fallback must fit Darwin with reserve"
        );
    }

    #[test]
    fn unavailable_computed_roots_suggest_an_override_without_claiming_one_was_set() {
        let hash = "0123456789abcdef01234567";
        let first = PathBuf::from("/").join("a".repeat(200));
        let second = PathBuf::from("/").join("b".repeat(200));

        let error = per_user_tmp_root_from_candidates(hash, [first, second])
            .expect_err("oversized computed roots must fail");
        let text = error.to_string();

        assert!(text.contains("set COCKPIT_SOCKET_DIR"), "{text}");
        assert!(!text.contains("COCKPIT_SOCKET_DIR produces"), "{text}");
    }
}
