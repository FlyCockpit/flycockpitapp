//! Best-effort private filesystem permissions for sensitive local state.

use std::path::Path;

use anyhow::{Context, Result};

#[cfg(unix)]
struct UmaskGuard(libc::mode_t);

#[cfg(unix)]
impl UmaskGuard {
    fn set(mask: libc::mode_t) -> Self {
        // SAFETY: `umask` is process-global but atomic at the libc boundary.
        // Keep guarded operations small and restore in Drop.
        let previous = unsafe { libc::umask(mask) };
        Self(previous)
    }
}

#[cfg(unix)]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: Restores the process umask captured by `set`.
        unsafe {
            libc::umask(self.0);
        }
    }
}

#[cfg(unix)]
pub fn with_private_umask<T>(mask: libc::mode_t, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let _umask = UmaskGuard::set(mask);
    f()
}

#[cfg(unix)]
pub fn ensure_private_dir(path: &Path) -> Result<()> {
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
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    // Non-Unix platforms do not expose POSIX mode bits; protection follows
    // the platform filesystem defaults.
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))
}

#[cfg(unix)]
pub fn ensure_parent_dir_private(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn ensure_parent_dir_private(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
pub fn repair_private_file(path: &Path, label: &str) -> Result<()> {
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
pub fn repair_private_file(_path: &Path, _label: &str) -> Result<()> {
    // Non-Unix platforms do not expose POSIX mode bits; protection follows
    // the platform filesystem defaults.
    Ok(())
}

#[cfg(unix)]
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
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
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
