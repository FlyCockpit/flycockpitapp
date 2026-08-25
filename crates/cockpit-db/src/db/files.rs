//! DB-owned filesystem helpers for the local SQLite store and sidecars.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};

#[cfg(test)]
static SIDECAR_SYNC_FAILURE_PATH: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(crate) fn force_sidecar_parent_sync_failure_for_test(path: Option<PathBuf>) {
    *SIDECAR_SYNC_FAILURE_PATH
        .lock()
        .expect("sidecar sync failure hook poisoned") = path;
}

#[cfg(unix)]
fn sidecar_parent_sync_forced_failure(path: &Path) -> bool {
    #[cfg(test)]
    {
        return SIDECAR_SYNC_FAILURE_PATH
            .lock()
            .expect("sidecar sync failure hook poisoned")
            .as_deref()
            == Some(path);
    }
    #[cfg(not(test))]
    {
        let _ = path;
        false
    }
}

/// Process-independent guard for database boot, backup, and migration.
///
/// The lock file is persistent, but ownership is held by the kernel on this
/// open file description. A crashed process therefore cannot leave stale
/// ownership behind (unlike a create-new or PID-file protocol).
pub(crate) struct DatabaseOwnerLock {
    _file: std::fs::File,
}

impl DatabaseOwnerLock {
    pub(crate) fn acquire(database: &Path) -> Result<Self> {
        let lock_path = database.with_extension("boot.lock");
        ensure_parent_dir_private(&lock_path)?;
        create_private_file_if_missing(&lock_path)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("opening database boot lock {}", lock_path.display()))?;
        repair_private_file(&lock_path, "database boot lock")?;
        file.try_lock().with_context(|| {
            format!(
                "database already has a live exclusive owner at {}",
                lock_path.display()
            )
        })?;
        Ok(Self { _file: file })
    }
}

/// Non-mutating diagnostic ownership. It can coexist with other diagnostic
/// readers, but never with the daemon's exclusive lifetime owner.
pub(crate) struct DatabaseDiagnosticLock {
    _file: std::fs::File,
}

impl DatabaseDiagnosticLock {
    pub(crate) fn try_acquire(database: &Path) -> Result<Self> {
        let lock_path = database.with_extension("boot.lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&lock_path)
            .with_context(|| format!("opening database ownership lock {}", lock_path.display()))?;
        file.try_lock_shared().with_context(|| {
            format!(
                "database is owned by a live daemon; diagnostics must use its RPC: {}",
                database.display()
            )
        })?;
        Ok(Self { _file: file })
    }
}

pub(crate) fn cockpit_data_dir() -> Result<PathBuf> {
    if let Ok(s) = std::env::var("XDG_DATA_HOME")
        && !s.trim().is_empty()
    {
        return Ok(PathBuf::from(s).join("cockpit"));
    }
    let base = dirs::data_dir().context("could not locate user data dir")?;
    Ok(base.join("cockpit"))
}

pub(crate) struct PhaseTimer {
    span: &'static str,
    start: Instant,
    last: Instant,
}

impl PhaseTimer {
    pub(crate) fn start(span: &'static str) -> Self {
        let now = Instant::now();
        Self {
            span,
            start: now,
            last: now,
        }
    }

    pub(crate) fn phase(&mut self, name: &str) {
        let now = Instant::now();
        let phase_ms = now.duration_since(self.last).as_secs_f64() * 1000.0;
        let total_ms = now.duration_since(self.start).as_secs_f64() * 1000.0;
        tracing::info!(
            target: "cockpit::startup",
            span = self.span,
            phase = name,
            phase_ms = format_args!("{phase_ms:.1}"),
            total_ms = format_args!("{total_ms:.1}"),
            "startup phase"
        );
        self.last = now;
    }

    pub(crate) fn done(self) {
        let total_ms = self.start.elapsed().as_secs_f64() * 1000.0;
        tracing::info!(
            target: "cockpit::startup",
            span = self.span,
            total_ms = format_args!("{total_ms:.1}"),
            "startup complete"
        );
    }
}

#[cfg(all(unix, not(test)))]
struct UmaskGuard(libc::mode_t);

#[cfg(all(unix, test))]
struct UmaskGuard;

#[cfg(all(unix, not(test)))]
impl UmaskGuard {
    fn set(mask: libc::mode_t) -> Self {
        // SAFETY: `umask` is process-global but atomic at the libc boundary.
        // Keep guarded operations small and restore in Drop.
        let previous = unsafe { libc::umask(mask) };
        Self(previous)
    }
}

#[cfg(all(unix, test))]
impl UmaskGuard {
    fn set(_mask: libc::mode_t) -> Self {
        Self
    }
}

#[cfg(all(unix, not(test)))]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: Restores the process umask captured by `set`.
        unsafe {
            libc::umask(self.0);
        }
    }
}

#[cfg(unix)]
pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    {
        let _umask = UmaskGuard::set(0o077);
        std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", path.display()))?;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o700 {
        anyhow::bail!(
            "refusing to use {}: expected private directory mode 0700, got {mode:03o}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))
}

pub(crate) fn ensure_parent_dir_private(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn repair_private_file(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path)
        .with_context(|| format!("checking {label} file {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if (mode & 0o077 != 0 || mode & 0o200 == 0 || mode & 0o400 == 0)
        && let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    {
        tracing::warn!(
            error = %e,
            path = %path.display(),
            "{label} file permissions are insecure and could not be repaired"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn repair_private_file(_path: &Path, _label: &str) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn create_private_file_if_missing(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    match opts.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).with_context(|| format!("creating {}", path.display())),
    }
}

#[cfg(not(unix))]
pub(crate) fn create_private_file_if_missing(path: &Path) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    match opts.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).with_context(|| format!("creating {}", path.display())),
    }
}

/// Publish a new DB-owned sidecar through a fully durable, private temporary
/// file. The final pathname becomes visible only after its bytes are synced;
/// syncing the parent then makes the rename durable before SQLite may refer to
/// it. `destination` must not already exist (callers use non-reusable names).
pub(crate) fn publish_private_file_durable(destination: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = destination
        .parent()
        .context("durable sidecar destination has no parent")?;
    ensure_private_dir(parent)?;
    let file_name = destination
        .file_name()
        .context("durable sidecar destination has no filename")?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::now_v7()));

    struct TempGuard(PathBuf);
    impl Drop for TempGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _guard = TempGuard(temporary.clone());
    #[cfg(unix)]
    let file_result = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
    };
    #[cfg(not(unix))]
    let file_result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary);
    let mut file = file_result.with_context(|| format!("creating {}", temporary.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", temporary.display()))?;
    drop(file);
    #[cfg(unix)]
    {
        // `hard_link` is the portable Unix no-replace publication primitive:
        // destination creation is atomic and fails with AlreadyExists under a
        // racing publisher. Both paths are in the same private directory, so
        // this cannot cross filesystems. Removing the temporary name leaves
        // the fully synced inode reachable at exactly one final pathname.
        std::fs::hard_link(&temporary, destination).with_context(|| {
            format!(
                "publishing durable sidecar {} as {} without replacement",
                temporary.display(),
                destination.display()
            )
        })?;
        std::fs::remove_file(&temporary)
            .with_context(|| format!("removing published temporary {}", temporary.display()))?;
    }
    #[cfg(not(unix))]
    {
        anyhow::ensure!(
            !destination.exists(),
            "refusing to replace existing durable sidecar {}",
            destination.display()
        );
        std::fs::rename(&temporary, destination).with_context(|| {
            format!(
                "publishing durable sidecar {} as {}",
                temporary.display(),
                destination.display()
            )
        })?;
        std::mem::forget(_guard);
    }
    #[cfg(windows)]
    let directory = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            // FILE_FLAG_BACKUP_SEMANTICS is required to open a directory.
            .custom_flags(0x0200_0000)
            .open(parent)
    };
    #[cfg(not(windows))]
    let directory = std::fs::File::open(parent);
    let directory =
        directory.with_context(|| format!("opening sidecar parent {}", parent.display()))?;
    directory
        .sync_all()
        .with_context(|| format!("syncing sidecar parent {}", parent.display()))
}

/// Unlink a DB-owned sidecar beneath `base` without following any path
/// component, then durably commit the directory-entry change. Missing is
/// success, but still syncs the parent directory so a retry after an uncertain
/// prior unlink cannot discard its durable cleanup intent prematurely.
#[cfg(unix)]
pub(crate) fn delete_relative_file_durable_nofollow(base: &Path, relative: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    let components = relative.components().collect::<Vec<_>>();
    anyhow::ensure!(!components.is_empty(), "sidecar cleanup path is empty");
    anyhow::ensure!(
        components
            .iter()
            .all(|component| matches!(component, std::path::Component::Normal(_))),
        "sidecar cleanup path must be relative and normalized"
    );
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(base)
        .with_context(|| format!("opening sidecar cleanup base {}", base.display()))?;
    let mut durable_parent = base.to_path_buf();
    for component in &components[..components.len() - 1] {
        let std::path::Component::Normal(name) = component else {
            unreachable!("components were validated")
        };
        durable_parent.push(name);
        let name = CString::new(name.as_bytes()).context("sidecar directory contains NUL")?;
        // SAFETY: `directory` is a live directory fd and `name` contains one
        // validated normal component. O_NOFOLLOW refuses a raced symlink.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "opening sidecar cleanup directory beneath {}",
                    base.display()
                )
            });
        }
        // SAFETY: successful `openat` returned a newly owned descriptor.
        directory = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    let std::path::Component::Normal(name) = components.last().expect("nonempty validated path")
    else {
        unreachable!("components were validated")
    };
    let name = CString::new(name.as_bytes()).context("sidecar filename contains NUL")?;
    // SAFETY: held parent fd plus a single literal filename; unlinkat never
    // follows a symlink in the final component.
    let rc = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error).context("unlinking delegation payload sidecar");
        }
    }
    anyhow::ensure!(
        !sidecar_parent_sync_forced_failure(&durable_parent),
        "injected delegation payload sidecar parent fsync failure"
    );
    directory
        .sync_all()
        .context("fsyncing delegation payload sidecar parent")
}

#[cfg(windows)]
pub(crate) fn delete_relative_file_durable_nofollow(base: &Path, relative: &Path) -> Result<()> {
    let _ = (base, relative);
    anyhow::bail!(
        "durable no-follow sidecar deletion is unsupported on Windows; cleanup is retained for a future safe implementation"
    )
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn delete_relative_file_durable_nofollow(base: &Path, relative: &Path) -> Result<()> {
    let path = base.join(relative);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("unlinking delegation payload sidecar"),
    }
}
