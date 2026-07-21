//! DB-owned filesystem helpers for the local SQLite store and sidecars.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};

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

#[cfg(unix)]
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut file = opts
        .open(path)
        .with_context(|| format!("opening {} for write", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
