use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest as _, Sha256};

use crate::config::MAX_WORKSPACE_CONFIG_FILE_BYTES;

/// Read a project- or user-layer config file with
/// [`MAX_WORKSPACE_CONFIG_FILE_BYTES`] applied *during* IO. Absence is
/// `Ok(None)`. Over-cap, non-regular files, and other IO fail closed so a
/// giant `.cockpit/config.json` cannot OOM the daemon.
pub(crate) fn read_workspace_config_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match cockpit_host::bounded::read_at_most(path, MAX_WORKSPACE_CONFIG_FILE_BYTES as u64) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(cockpit_host::bounded::BoundedIoError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(cockpit_host::bounded::BoundedIoError::Limit { actual, limit, .. }) => {
            anyhow::bail!(
                "{} exceeds the {limit} byte limit ({actual} bytes)",
                path.display()
            )
        }
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// UTF-8 body of a workspace config file. Absence is `Ok(None)`. Over-cap,
/// non-regular files, and invalid UTF-8 fail closed.
pub(crate) fn read_workspace_config_text(path: &Path) -> Result<Option<String>> {
    match read_workspace_config_bytes(path)? {
        None => Ok(None),
        Some(bytes) => {
            let text =
                String::from_utf8(bytes).with_context(|| format!("reading {}", path.display()))?;
            Ok(Some(text))
        }
    }
}

#[cfg(test)]
mod workspace_config_read_tests {
    #[test]
    fn over_cap_fails_closed_and_absence_is_none() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("gone.json");
        assert!(
            super::read_workspace_config_text(&missing)
                .unwrap()
                .is_none()
        );

        let small = temp.path().join("ok.json");
        std::fs::write(&small, "{}").unwrap();
        assert_eq!(
            super::read_workspace_config_text(&small)
                .unwrap()
                .as_deref(),
            Some("{}")
        );

        let over = temp.path().join("over.json");
        let handle = std::fs::File::create(&over).unwrap();
        handle
            .set_len(super::MAX_WORKSPACE_CONFIG_FILE_BYTES as u64 + 1)
            .unwrap();
        drop(handle);
        let err = super::read_workspace_config_text(&over).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("exceeds the") && text.contains("byte limit"),
            "{text}"
        );

        let err = crate::config::read_config_file_nofollow(&over).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("exceeds the byte limit"), "{text}");
    }
}

#[cfg(unix)]
fn ensure_dir_exists_private_if_created(path: &Path) -> Result<()> {
    open_directory_nofollow(path, true, false).map(drop)
}

#[cfg(unix)]
fn path_component_cstring(component: &std::ffi::OsStr) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt as _;

    std::ffi::CString::new(component.as_bytes())
        .with_context(|| format!("path component contains NUL: {component:?}"))
}

#[cfg(unix)]
fn open_start_directory(absolute: bool) -> Result<std::fs::File> {
    use std::os::fd::FromRawFd as _;

    let path = if absolute { c"/" } else { c"." };
    // SAFETY: `path` is a live NUL-terminated C string. On success ownership
    // of the returned descriptor is transferred exactly once to `File`.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("opening config path traversal anchor");
    }
    // SAFETY: `fd` was just returned by `open` and is uniquely owned.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_directory_component(
    parent: &std::fs::File,
    component: &std::ffi::OsStr,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let component = path_component_cstring(component)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    // SAFETY: both the directory fd and component string remain live for the
    // call. O_NOFOLLOW rejects a symlink in the component being opened.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `openat` and is uniquely owned.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn mkdir_directory_component(
    parent: &std::fs::File,
    component: &std::ffi::OsStr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let component = path_component_cstring(component)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    // SAFETY: the directory fd and component string remain live for the call.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn chmod_directory_private(directory: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    // SAFETY: the file descriptor is live and refers to an O_DIRECTORY handle.
    let result = unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn open_directory_nofollow(
    path: &Path,
    create_missing: bool,
    make_final_private: bool,
) -> Result<std::fs::File> {
    use std::path::Component;

    let path = normalize_macos_system_path(path);
    let mut directory = open_start_directory(path.is_absolute())?;
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir => Some(std::ffi::OsString::from("..")),
            Component::Normal(component) => Some(component.to_os_string()),
            Component::Prefix(_) => None,
        })
        .collect::<Vec<_>>();

    for (index, component) in components.iter().enumerate() {
        let is_final = index + 1 == components.len();
        let (next, created) = match open_directory_component(&directory, component) {
            Ok(next) => (next, false),
            Err(error) if create_missing && error.kind() == std::io::ErrorKind::NotFound => {
                match mkdir_directory_component(&directory, component) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "creating no-follow directory component {:?} for {}",
                                component,
                                path.display()
                            )
                        });
                    }
                }
                let next = open_directory_component(&directory, component).with_context(|| {
                    format!(
                        "opening newly created no-follow directory component {:?} for {}",
                        component,
                        path.display()
                    )
                })?;
                (next, true)
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "opening no-follow directory component {:?} for {}",
                        component,
                        path.display()
                    )
                });
            }
        };
        if created || (make_final_private && is_final) {
            chmod_directory_private(&next).with_context(|| {
                format!("chmod 0700 directory component for {}", path.display())
            })?;
        }
        directory = next;
    }
    Ok(directory)
}

// macOS exposes `/var` and `/tmp` as root-owned symlinks into `/private`.
// Keep component traversal no-follow for caller-controlled paths while using
// their physical spelling for these two immutable system aliases.
pub(crate) fn normalize_macos_system_path(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        for (alias, physical) in [("/var", "/private/var"), ("/tmp", "/private/tmp")] {
            if let Ok(remainder) = path.strip_prefix(alias) {
                return Path::new(physical).join(remainder);
            }
        }
    }
    path.to_path_buf()
}

#[cfg(unix)]
fn open_parent_directory_nofollow(path: &Path) -> Result<(std::fs::File, std::ffi::OsString)> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("config path has no file name: {}", path.display()))?;
    let directory = open_directory_nofollow(parent, false, false)?;
    Ok((directory, file_name.to_os_string()))
}

#[cfg(unix)]
fn open_file_at_nofollow(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> Result<std::fs::File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let name = path_component_cstring(name)?;
    // SAFETY: the directory fd and name remain live for the call; callers
    // supply O_NOFOLLOW and creation flags appropriate to the file role.
    // Cast mode to c_uint: openat is variadic, and on macOS mode_t is u16
    // which cannot be passed to a variadic function without promotion.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("opening no-follow config file");
    }
    // SAFETY: `fd` was just returned by `openat` and is uniquely owned.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn rename_file_at(
    parent: &std::fs::File,
    source: &std::ffi::OsStr,
    destination: &std::ffi::OsStr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let source = path_component_cstring(source)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let destination = path_component_cstring(destination)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    // SAFETY: both names and the shared parent descriptor remain live.
    let result = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlink_file_at(parent: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let name = path_component_cstring(name)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    // SAFETY: the directory descriptor and name remain live for the call.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn chmod_file_private(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    // SAFETY: the descriptor is live for the call.
    let result = unsafe { libc::fchmod(file.as_raw_fd(), 0o600) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn ensure_private_dir(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    open_directory_nofollow(path, true, true).map(drop)
}

#[cfg(windows)]
fn ensure_private_dir(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    open_windows_directory_nofollow(path, true).map(drop)
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))
}

#[cfg(windows)]
fn ensure_dir_exists_private_if_created(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    open_windows_directory_nofollow(path, true).map(drop)
}

#[cfg(all(not(unix), not(windows)))]
fn ensure_dir_exists_private_if_created(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))
}

pub fn ensure_parent_dir_private(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    Ok(())
}

/// Create a Cockpit-owned directory, keep its final component private, and
/// prove that it accepts a create/remove cycle. Global configuration uses
/// this during persistent daemon boot so a later onboarding write cannot be
/// blocked by a missing or unwritable directory.
pub(crate) fn ensure_private_writable_dir(path: &Path) -> Result<()> {
    ensure_private_dir(path)?;
    #[cfg(any(unix, windows))]
    {
        let directory = open_directory_handle_nofollow(path)?;
        return probe_directory_writable_from_retained_directory(&directory, path);
    }
    #[cfg(all(not(unix), not(windows)))]
    Ok(())
}

/// Ensure a file's parent exists without taking ownership of an existing
/// directory.
///
/// Explicit config paths may legitimately live directly in a shared parent
/// such as `/tmp`. Cockpit must not chmod that parent. Directories created by
/// this call are private, while directories that already exist retain their
/// caller-managed permissions.
#[cfg(unix)]
pub fn ensure_parent_dir_exists_private_if_created(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    ensure_dir_exists_private_if_created(parent)
}

#[cfg(windows)]
pub fn ensure_parent_dir_exists_private_if_created(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    ensure_dir_exists_private_if_created(parent)
}

#[cfg(all(not(unix), not(windows)))]
pub fn ensure_parent_dir_exists_private_if_created(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    Ok(())
}

/// Ensure a config file's parent according to ownership of its config layer.
///
/// Conventional Cockpit layer directories are product-owned and may be
/// repaired to private permissions. An explicit config can instead be placed
/// directly in a caller-owned/shared directory; that existing directory must
/// retain its permissions. Provider files inherit the policy of the config
/// directory above their `providers/` directory.
pub fn ensure_config_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let config_dir = if parent.file_name().is_some_and(|name| name == "providers") {
        parent.parent().unwrap_or(parent)
    } else {
        parent
    };

    // The global layer is created only by `ensure_global_config_dir`. A
    // file write, mutation lock, or journal replay must not scaffold a
    // missing `~/.config/cockpit` as a side effect — ephemeral/diagnostic
    // owners rely on that exclusivity.
    crate::config::dirs::refuse_missing_global_config_dir(config_dir)?;

    if is_cockpit_owned_config_dir(config_dir) {
        ensure_private_dir(config_dir)?;
        if parent != config_dir {
            ensure_private_dir(parent)?;
        }
    } else {
        ensure_parent_dir_exists_private_if_created(path)?;
    }
    Ok(())
}

fn is_cockpit_owned_config_dir(path: &Path) -> bool {
    if std::env::var_os(crate::config::dirs::COCKPIT_CONFIG_ENV)
        .filter(|value| !value.is_empty())
        .and_then(|value| {
            std::path::PathBuf::from(value)
                .parent()
                .map(Path::to_path_buf)
        })
        .as_deref()
        == Some(path)
    {
        // An explicit override is caller-owned even when its directory happens
        // to have a conventional Cockpit basename.
        return false;
    }

    if crate::config::dirs::global_config_dir().is_ok_and(|global| path == global) {
        return true;
    }

    crate::config::resolve::cockpit_data_dir_unchecked()
        .map(|data_dir| path.starts_with(data_dir.join("local-configs")))
        .unwrap_or(false)
}

/// Stable cross-process lock for one `config.json` mutation target.
///
/// Config files are replaced atomically, so locking the destination inode
/// would not serialize the next writer. Instead every target has a
/// deterministic private sibling lock leaf. Path-based callers open that leaf
/// through the target's no-follow parent directory; retained callers open the
/// exact same leaf through their held directory descriptor. This makes locks
/// for different config directories independent while preserving serialization
/// between ambient and retained writers of the same logical config file.
/// The lock file is deliberately retained after release: OS advisory locks are
/// released automatically when the owning descriptor/process dies, so deleting
/// a "stale" leaf would only add a replacement race.
/// A held cross-process config mutation lock.
///
/// Deliberately `!Send`: the re-entrancy depth that lets journal recovery run
/// under an already-held lock is a *thread-local*. Moving a guard to another
/// thread would leave the acquiring thread's depth stuck above zero (recovery
/// would skip a real lock) and the receiving thread's depth below it,
/// underflowing on drop. Keeping the guard pinned to its acquiring thread
/// makes that class of corruption unrepresentable.
pub(crate) struct ConfigMutationLock {
    /// `None` means this guard does not own an OS lock leaf: either this
    /// thread already holds the matching identity (re-entrant), or the
    /// target parent does not exist yet so no sibling lock leaf can be
    /// held. Creating that parent is reserved for the creating acquire
    /// paths; a different target never shares this shortcut.
    _file: Option<std::fs::File>,
    identity: String,
    _not_send: std::marker::PhantomData<*const ()>,
}

thread_local! {
    /// Re-entrancy depths for mutation locks on this thread, keyed by their
    /// immutable target identity. A scalar global depth would incorrectly
    /// treat a lock on config A as authority to mutate config B.
    ///
    /// The OS lock is per open file description, so a second `acquire` on the
    /// same thread would deadlock against the guard this thread already holds.
    /// Journal recovery runs both standalone and inside an in-flight mutation,
    /// so it consults this depth instead of blindly re-locking.
    static MUTATION_LOCK_DEPTHS: std::cell::RefCell<HashMap<String, u32>> =
        std::cell::RefCell::new(HashMap::new());
}

impl ConfigMutationLock {
    pub(crate) fn acquire(target: &Path) -> Result<Self> {
        ensure_config_parent_dir(target)?;
        let target_identity = mutation_lock_identity(target);
        let (parent, lock_leaf, display_path) = open_mutation_lock_parent(target)?;
        let identity = mutation_lock_runtime_identity(&parent, &target_identity)?;
        if Self::is_held_identity(&identity) {
            return Ok(Self::enter(None, identity));
        }
        let file = open_private_lock_file_at(&parent, &lock_leaf, &display_path)?;
        file.lock()
            .with_context(|| format!("locking config mutation at {}", display_path.display()))?;
        Ok(Self::enter(Some(file), identity))
    }

    pub(crate) fn acquire_cancellable(
        target: &Path,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Self> {
        ensure_config_parent_dir(target)?;
        let target_identity = mutation_lock_identity(target);
        let (parent, lock_leaf, display_path) = open_mutation_lock_parent(target)?;
        let identity = mutation_lock_runtime_identity(&parent, &target_identity)?;
        if Self::is_held_identity(&identity) {
            if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                anyhow::bail!("active-model config mutation was cancelled");
            }
            return Ok(Self::enter(None, identity));
        }
        let file = open_private_lock_file_at(&parent, &lock_leaf, &display_path)?;
        loop {
            if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                anyhow::bail!("active-model config mutation was cancelled");
            }
            match file.try_lock() {
                Ok(()) => {
                    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                        anyhow::bail!("active-model config mutation was cancelled");
                    }
                    return Ok(Self::enter(Some(file), identity));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(error).with_context(|| {
                        format!("locking config mutation at {}", display_path.display())
                    });
                }
            }
        }
    }

    /// Try to acquire the mutation lock, polling until the deadline. Returns
    /// `Ok(None)` when the deadline elapses without acquiring the lock (it
    /// remained busy). Re-entrant acquisition on the same thread succeeds
    /// immediately regardless of the deadline.
    ///
    /// A missing parent directory is uncontended (`Ok(Some(_))`) and is not
    /// created. First-write targets for onboarding reads and pre-socket
    /// publication must survive a fresh install; only the creating acquire
    /// paths and authorized write helpers may mkdir the parent.
    pub(crate) fn acquire_until(
        target: &Path,
        deadline: std::time::Instant,
    ) -> Result<Option<Self>> {
        let target_identity = mutation_lock_identity(target);
        let Some((parent, lock_leaf, display_path)) = try_open_mutation_lock_parent(target)? else {
            // No sibling lock leaf can exist until a creating acquire (or
            // write helper) mkdirs the parent. Treat the first-write target
            // as uncontended rather than failing the publication lock, and
            // rather than creating the global layer as a read side-effect.
            return Ok(Some(Self::enter(
                None,
                missing_parent_mutation_lock_identity(&target_identity),
            )));
        };
        let identity = mutation_lock_runtime_identity(&parent, &target_identity)?;
        if Self::is_held_identity(&identity) {
            return Ok(Some(Self::enter(None, identity)));
        }
        let file = open_private_lock_file_at(&parent, &lock_leaf, &display_path)?;
        loop {
            if std::time::Instant::now() >= deadline {
                return Ok(None);
            }
            match file.try_lock() {
                Ok(()) => {
                    return Ok(Some(Self::enter(Some(file), identity)));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(error).with_context(|| {
                        format!("locking config mutation at {}", display_path.display())
                    });
                }
            }
        }
    }

    /// Acquire the target's deterministic lock leaf relative to an already
    /// verified directory capability. The caller must pass the canonical
    /// target identity that the ambient backend uses for the same config file.
    pub(crate) fn acquire_retained(
        directory: &std::fs::File,
        canonical_target: &Path,
        display_parent: &Path,
    ) -> Result<Self> {
        // `canonical_target` was captured with the retained directory. Do not
        // canonicalize/open its parent again here: that would turn lock
        // selection itself into a post-attach pathname authority read.
        let target_identity = mutation_lock_identity_from_canonical(canonical_target);
        let identity = mutation_lock_runtime_identity(directory, &target_identity)?;
        if Self::is_held_identity(&identity) {
            return Ok(Self::enter(None, identity));
        }
        let lock_leaf = mutation_lock_leaf_for_identity(&target_identity);
        let display_path = display_parent.join(&lock_leaf);
        let file = open_private_lock_file_at(directory, &lock_leaf, &display_path)?;
        file.lock().with_context(|| {
            format!(
                "locking retained config mutation at {}",
                display_path.display()
            )
        })?;
        Ok(Self::enter(Some(file), identity))
    }

    /// Cancellable counterpart of [`Self::acquire_retained`]. The lock leaf
    /// is still opened through the held directory, so cancellation never
    /// falls back to a current pathname lookup.
    pub(crate) fn acquire_retained_cancellable(
        directory: &std::fs::File,
        canonical_target: &Path,
        display_parent: &Path,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Self> {
        let target_identity = mutation_lock_identity_from_canonical(canonical_target);
        let identity = mutation_lock_runtime_identity(directory, &target_identity)?;
        if Self::is_held_identity(&identity) {
            if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                anyhow::bail!("active-model config mutation was cancelled");
            }
            return Ok(Self::enter(None, identity));
        }
        let lock_leaf = mutation_lock_leaf_for_identity(&target_identity);
        let display_path = display_parent.join(&lock_leaf);
        let file = open_private_lock_file_at(directory, &lock_leaf, &display_path)?;
        loop {
            if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                anyhow::bail!("active-model config mutation was cancelled");
            }
            match file.try_lock() {
                Ok(()) => {
                    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                        anyhow::bail!("active-model config mutation was cancelled");
                    }
                    return Ok(Self::enter(Some(file), identity));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(error).with_context(|| {
                        format!(
                            "locking retained config mutation at {}",
                            display_path.display()
                        )
                    });
                }
            }
        }
    }

    fn enter(file: Option<std::fs::File>, identity: String) -> Self {
        MUTATION_LOCK_DEPTHS.with(|depths| {
            let mut depths = depths.borrow_mut();
            *depths.entry(identity.clone()).or_default() += 1;
        });
        Self {
            _file: file,
            identity,
            _not_send: std::marker::PhantomData,
        }
    }

    /// True while this thread already owns the exact target's mutation lock.
    pub(crate) fn is_held_by_current_thread(target: &Path) -> Result<bool> {
        let target_identity = mutation_lock_identity(target);
        match try_open_mutation_lock_parent(target)? {
            None => Ok(Self::is_held_identity(
                &missing_parent_mutation_lock_identity(&target_identity),
            )),
            Some((parent, _, _)) => {
                let identity = mutation_lock_runtime_identity(&parent, &target_identity)?;
                Ok(Self::is_held_identity(&identity))
            }
        }
    }

    fn is_held_identity(identity: &str) -> bool {
        MUTATION_LOCK_DEPTHS.with(|depths| depths.borrow().get(identity).copied().unwrap_or(0) > 0)
    }
}

impl Drop for ConfigMutationLock {
    fn drop(&mut self) {
        MUTATION_LOCK_DEPTHS.with(|depths| {
            let mut depths = depths.borrow_mut();
            let Some(depth) = depths.get_mut(&self.identity) else {
                debug_assert!(false, "config mutation lock depth missing on drop");
                return;
            };
            *depth = depth.saturating_sub(1);
            if *depth == 0 {
                depths.remove(&self.identity);
            }
        });
    }
}

fn mutation_lock_identity(target: &Path) -> String {
    let absolute = std::path::absolute(target).unwrap_or_else(|_| target.to_path_buf());
    let canonical = match (absolute.parent(), absolute.file_name()) {
        (Some(parent), Some(name)) => std::fs::canonicalize(parent)
            .map(|parent| parent.join(name))
            .unwrap_or(absolute),
        _ => absolute,
    };
    mutation_lock_identity_from_canonical(&canonical)
}

fn mutation_lock_identity_from_canonical(canonical_target: &Path) -> String {
    canonical_target.to_string_lossy().into_owned()
}

/// Re-entrancy identity when the target parent does not exist, so no
/// directory inode can be paired with the path. Distinct from a runtime
/// identity taken after a creating acquire mkdirs the parent.
fn missing_parent_mutation_lock_identity(target_identity: &str) -> String {
    format!("missing-parent:{target_identity}")
}

/// Pair the canonical config-leaf identity with the actual directory object
/// that contains its lock leaf. A pathname can be swapped and later reused;
/// that replacement is intentionally a different re-entrancy identity even
/// though it has the same spelling and deterministic lock-file name.
fn mutation_lock_runtime_identity(
    directory: &std::fs::File,
    target_identity: &str,
) -> Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = directory.metadata()?;
        return Ok(format!(
            "unix:{}:{}:{target_identity}",
            metadata.dev(),
            metadata.ino()
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(directory.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let file = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        return Ok(format!(
            "windows:{}:{file}:{target_identity}",
            info.dwVolumeSerialNumber
        ));
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let metadata = directory.metadata()?;
        return Ok(format!(
            "portable:{}:{}:{target_identity}",
            metadata.len(),
            metadata
                .modified()?
                .elapsed()
                .unwrap_or_default()
                .as_nanos()
        ));
    }
}

fn mutation_lock_leaf_for_identity(identity: &str) -> std::ffi::OsString {
    let mut hasher = Sha256::new();
    hasher.update(b"cockpit-effective-default-lock-v1\0");
    hasher.update(identity.as_bytes());
    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    std::ffi::OsString::from(format!(".cockpit-effective-default-lock-{digest}.lock"))
}

fn mutation_lock_leaf(target: &Path) -> std::ffi::OsString {
    mutation_lock_leaf_for_identity(&mutation_lock_identity(target))
}

#[cfg(unix)]
fn open_mutation_lock_parent(
    target: &Path,
) -> Result<(std::fs::File, std::ffi::OsString, PathBuf)> {
    let (parent, _) = open_parent_directory_nofollow(target)?;
    let leaf = mutation_lock_leaf(target);
    let display = target
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&leaf);
    Ok((parent, leaf, display))
}

#[cfg(windows)]
fn open_mutation_lock_parent(
    target: &Path,
) -> Result<(std::fs::File, std::ffi::OsString, PathBuf)> {
    let (parent, _) = open_windows_parent_directory_nofollow(target, false)?;
    let leaf = mutation_lock_leaf(target);
    let display = target
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&leaf);
    Ok((parent, leaf, display))
}

#[cfg(all(not(unix), not(windows)))]
fn open_mutation_lock_parent(
    target: &Path,
) -> Result<(std::fs::File, std::ffi::OsString, PathBuf)> {
    let parent_path = target.parent().unwrap_or_else(|| Path::new("."));
    let parent = std::fs::File::open(parent_path)?;
    let leaf = mutation_lock_leaf(target);
    let display = parent_path.join(&leaf);
    Ok((parent, leaf, display))
}

/// Open the target's parent for a sibling lock leaf. `Ok(None)` means the
/// parent is absent — the bounded wait treats that as uncontended rather
/// than creating the directory or failing the publication lock.
fn try_open_mutation_lock_parent(
    target: &Path,
) -> Result<Option<(std::fs::File, std::ffi::OsString, PathBuf)>> {
    match open_mutation_lock_parent(target) {
        Ok(parts) => Ok(Some(parts)),
        Err(error) if root_cause_is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Read a file without ever traversing a symlink or reparse point in its final
/// component. Returns `Ok(None)` when the file does not exist so callers can
/// fail closed on every other error instead of silently treating an
/// inaccessible journal as absent.
pub(crate) fn read_file_nofollow(path: &Path) -> Result<Option<Vec<u8>>> {
    #[cfg(unix)]
    {
        let (parent, file_name) = match open_parent_directory_nofollow(path) {
            Ok(parts) => parts,
            Err(error) if root_cause_is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let file = match open_file_at_nofollow(
            &parent,
            &file_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        ) {
            Ok(file) => file,
            Err(error) if root_cause_is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        read_all(file, path).map(Some)
    }
    #[cfg(windows)]
    {
        use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_READ_ATTRIBUTES, FILE_READ_DATA, SYNCHRONIZE,
        };

        let (parent, name) = match open_windows_parent_directory_nofollow(path, false) {
            Ok(parts) => parts,
            Err(error) if root_cause_is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let file = match open_windows_relative_nofollow(
            &parent,
            &name,
            false,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("opening {}", path.display()));
            }
        };
        reject_windows_reparse_handle(&file, path)?;
        read_all(file, path).map(Some)
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
        }
    }
}

/// Read a final-component-no-follow file while bounding the allocation made
/// for its contents.  This is deliberately separate from [`read_file_nofollow`]:
/// callers which need to classify an untrusted durable control record before
/// deciding whether any other pathname operation is permitted must not first
/// allocate an attacker-sized journal.
pub(crate) fn read_file_nofollow_bounded(path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>> {
    #[cfg(unix)]
    {
        let (parent, file_name) = match open_parent_directory_nofollow(path) {
            Ok(parts) => parts,
            Err(error) if root_cause_is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut file = match open_file_at_nofollow(
            &parent,
            &file_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        ) {
            Ok(file) => file,
            Err(error) if root_cause_is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        read_all_bounded(&mut file, path, max_bytes).map(Some)
    }
    #[cfg(windows)]
    {
        use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_READ_ATTRIBUTES, FILE_READ_DATA, SYNCHRONIZE,
        };

        let (parent, name) = match open_windows_parent_directory_nofollow(path, false) {
            Ok(parts) => parts,
            Err(error) if root_cause_is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut file = match open_windows_relative_nofollow(
            &parent,
            &name,
            false,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("opening {}", path.display()));
            }
        };
        reject_windows_reparse_handle(&file, path)?;
        read_all_bounded(&mut file, path, max_bytes).map(Some)
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        use std::io::Read as _;

        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", path.display()));
            }
        };
        let metadata = file
            .metadata()
            .with_context(|| format!("inspecting {}", path.display()))?;
        anyhow::ensure!(
            metadata.is_file(),
            "{} is not a regular file",
            path.display()
        );
        anyhow::ensure!(
            metadata.len() <= max_bytes as u64,
            "{} exceeds the byte limit",
            path.display()
        );
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {}", path.display()))?;
        anyhow::ensure!(
            bytes.len() <= max_bytes,
            "{} exceeds the byte limit",
            path.display()
        );
        Ok(Some(bytes))
    }
}

/// Read a no-follow file and return the held handle, bytes, and identity.
///
/// `max_bytes` caps the allocation made for contents. Config callers pass
/// [`MAX_WORKSPACE_CONFIG_FILE_BYTES`]. Terminal-ingress callers pass `None`
/// because those files are daemon-managed and admission-capped at write.
pub(crate) fn read_file_nofollow_with_identity(
    path: &Path,
    writable: bool,
    enforce_private: bool,
    max_bytes: Option<usize>,
) -> Result<Option<(std::fs::File, Vec<u8>, super::TerminalIngressFileIdentity)>> {
    #[cfg(unix)]
    let (parent, file_name) = match open_parent_directory_nofollow(path) {
        Ok(parts) => parts,
        Err(error) if root_cause_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    #[cfg(windows)]
    let (parent, file_name) = match open_windows_parent_directory_nofollow(path, false) {
        Ok(parts) => parts,
        Err(error) if root_cause_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    // Callers that later scrub the held exact object (truncating it through the
    // retained descriptor) must open read-write; pure readers stay read-only.
    #[cfg(unix)]
    let access = if writable {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };
    #[cfg(unix)]
    let file = match open_file_at_nofollow(
        &parent,
        &file_name,
        access | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        Err(error) if root_cause_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    #[cfg(windows)]
    let file = {
        use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, SYNCHRONIZE,
        };
        let mut access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        if writable {
            access |= FILE_WRITE_DATA;
        }
        match open_windows_relative_nofollow(&parent, &file_name, false, access, FILE_OPEN) {
            Ok(file) => file,
            Err(error) if root_cause_is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        }
    };
    #[cfg(all(not(unix), not(windows)))]
    let file = if writable {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?
    } else {
        std::fs::File::open(path)?
    };
    let before = file.metadata()?;
    if !before.is_file() {
        anyhow::bail!("terminal ingress entry is not a regular file");
    }
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt as _;
        if enforce_private
            && (before.uid() != unsafe { libc::geteuid() }
                || before.mode() & 0o777 != 0o600
                || before.nlink() != 1)
        {
            anyhow::bail!("terminal ingress file ownership, mode, or link count changed");
        }
        super::TerminalIngressFileIdentity {
            volume: before.dev(),
            file: before.ino(),
            links: before.nlink().try_into().unwrap_or(u32::MAX),
        }
    };
    #[cfg(windows)]
    let identity = {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if enforce_private {
            verify_windows_protected_dacl(&file)?;
        }
        super::TerminalIngressFileIdentity {
            volume: u64::from(info.dwVolumeSerialNumber),
            file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            links: info.nNumberOfLinks,
        }
    };
    #[cfg(windows)]
    if enforce_private && identity.links != 1 {
        anyhow::bail!("terminal ingress file link count changed");
    }
    #[cfg(all(not(unix), not(windows)))]
    let identity = super::TerminalIngressFileIdentity {
        volume: 0,
        file: 0,
        links: 1,
    };
    let mut file = file;
    let bytes = match max_bytes {
        Some(max) => read_all_bounded(&mut file, path, max)?,
        None => read_all(&mut file, path)?,
    };
    Ok(Some((file, bytes, identity)))
}

pub(crate) fn open_directory_handle_nofollow(path: &Path) -> Result<std::fs::File> {
    #[cfg(unix)]
    {
        open_directory_nofollow(path, false, false)
    }
    #[cfg(windows)]
    {
        open_windows_directory_nofollow(path, false)
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!("refusing non-directory or symlink {}", path.display());
        }
        std::fs::File::open(path).map_err(Into::into)
    }
}

/// Prove that an already-open directory capability still denotes the
/// directory currently named by `path`. This is used only while constructing a
/// descriptor: once construction succeeds, callers must retain and use the
/// handle rather than repeating a pathname lookup.
pub(crate) fn directory_handle_matches_path(
    directory: &std::fs::File,
    path: &Path,
) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let named = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let held = directory.metadata()?;
        return Ok(named.is_dir()
            && held.is_dir()
            && named.dev() == held.dev()
            && named.ino() == held.ino());
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let named = match open_windows_directory_nofollow(path, false) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let mut held_info = BY_HANDLE_FILE_INFORMATION::default();
        let mut named_info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(directory.as_raw_handle(), &mut held_info) } == 0
            || unsafe { GetFileInformationByHandle(named.as_raw_handle(), &mut named_info) } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        return Ok(
            held_info.dwVolumeSerialNumber == named_info.dwVolumeSerialNumber
                && held_info.nFileIndexHigh == named_info.nFileIndexHigh
                && held_info.nFileIndexLow == named_info.nFileIndexLow,
        );
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let named = std::fs::canonicalize(path)?;
        let held = directory.metadata()?;
        let current = std::fs::metadata(named)?;
        return Ok(held.is_dir() && current.is_dir());
    }
}

pub(crate) fn read_leaf_from_directory_handle(
    directory: &std::fs::File,
    leaf: &std::ffi::OsStr,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    read_leaf_from_directory_handle_with_identity(directory, leaf, max_bytes)
        .map(|(bytes, _)| bytes)
}

pub(crate) fn read_leaf_from_directory_handle_with_identity(
    directory: &std::fs::File,
    leaf: &std::ffi::OsStr,
    max_bytes: usize,
) -> Result<(Vec<u8>, super::TerminalIngressFileIdentity)> {
    if Path::new(leaf).components().count() != 1
        || matches!(
            Path::new(leaf).components().next(),
            None | Some(std::path::Component::CurDir)
                | Some(std::path::Component::ParentDir)
                | Some(std::path::Component::RootDir)
                | Some(std::path::Component::Prefix(_))
        )
    {
        anyhow::bail!("retained-directory read requires one normal leaf component");
    }
    #[cfg(unix)]
    let mut file = open_file_at_nofollow(
        directory,
        leaf,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    #[cfg(windows)]
    let mut file = {
        use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_READ_ATTRIBUTES, FILE_READ_DATA, SYNCHRONIZE,
        };
        open_windows_relative_nofollow(
            directory,
            leaf,
            false,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
        )?
    };
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = (directory, leaf, max_bytes);
        anyhow::bail!("retained-directory reads are unsupported on this platform");
    }
    #[cfg(any(unix, windows))]
    {
        use std::io::Read as _;
        #[cfg(windows)]
        reject_windows_reparse_handle(&file, Path::new(leaf))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > max_bytes as u64 {
            anyhow::bail!("retained-directory leaf is not a bounded regular file");
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            anyhow::bail!("retained-directory leaf exceeds the byte limit");
        }
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt as _;
            super::TerminalIngressFileIdentity {
                volume: metadata.dev(),
                file: metadata.ino(),
                links: metadata.nlink().try_into().unwrap_or(u32::MAX),
            }
        };
        #[cfg(windows)]
        let identity = {
            use std::os::windows::io::AsRawHandle as _;
            use windows_sys::Win32::Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
            };
            let mut info = BY_HANDLE_FILE_INFORMATION::default();
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            super::TerminalIngressFileIdentity {
                volume: u64::from(info.dwVolumeSerialNumber),
                file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
                links: info.nNumberOfLinks,
            }
        };
        Ok((bytes, identity))
    }
}

/// Capability-relative counterpart to [`read_leaf_from_directory_handle`] for
/// a nested, normal relative path. The retained root stays authoritative for
/// the entire traversal.
pub(crate) fn read_relative_file_from_directory_handle(
    directory: &std::fs::File,
    relative: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let components: Vec<_> = relative.components().collect();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        anyhow::bail!("retained-directory relative read requires normal path components");
    }
    let mut current = directory.try_clone()?;
    for component in &components[..components.len() - 1] {
        let std::path::Component::Normal(component) = component else {
            unreachable!("validated normal path component");
        };
        current = open_retained_child_directory_optional(&current, component)?
            .context("knowledge resource directory does not exist")?;
    }
    let std::path::Component::Normal(leaf) = components[components.len() - 1] else {
        unreachable!("validated normal path component");
    };
    read_leaf_from_directory_handle(&current, leaf, max_bytes)
}

/// Read one optional, bounded regular leaf beneath an already-open directory.
///
/// This is the capability-relative counterpart of [`read_file_nofollow`].
/// The directory handle, not `display_path`, is the filesystem authority;
/// the latter is deliberately diagnostic-only.  Keeping the optional/not-found
/// distinction here prevents callers that hold an attach-time directory from
/// accidentally reopening a mutable absolute path just to check whether a
/// transaction artifact exists.
pub(crate) fn read_optional_leaf_from_directory_handle(
    directory: &std::fs::File,
    leaf: &std::ffi::OsStr,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    match read_leaf_from_directory_handle(directory, leaf, max_bytes) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

const WORKSPACE_CONFIG_MAX_PROVIDER_FILES: usize = 256;

/// Capture the project-local Cockpit layer from an already-retained workspace
/// directory.  The path is intentionally fixed: the daemon never accepts a
/// caller-supplied config path at this authority boundary.
pub(crate) fn snapshot_workspace_config_layer_from_retained_directory(
    directory: &std::fs::File,
) -> Result<crate::config::WorkspaceConfigLayerSnapshot> {
    // A retained directory protects identity, not concurrent mutations within
    // that directory.  Capture twice and publish only an identical complete
    // view; bounded churn is a typed failure rather than an A/B mixture.
    const STABLE_CAPTURE_ATTEMPTS: usize = 3;
    for _ in 0..STABLE_CAPTURE_ATTEMPTS {
        let first = snapshot_workspace_config_layer_once(directory)?;
        let second = snapshot_workspace_config_layer_once(directory)?;
        if first.digest == second.digest {
            return Ok(second);
        }
    }
    anyhow::bail!("workspace configuration changed during retained snapshot capture")
}

pub(crate) fn snapshot_workspace_config_layer_from_retained_config_directory(
    directory: &std::fs::File,
    config_leaf: &std::ffi::OsStr,
    canonical_config_path: &Path,
    journal_leaf: Option<&std::ffi::OsStr>,
    backup_leaf: Option<&std::ffi::OsStr>,
) -> Result<crate::config::WorkspaceConfigLayerSnapshot> {
    validate_single_leaf(config_leaf)?;
    if let Some(journal_leaf) = journal_leaf {
        validate_single_leaf(journal_leaf)?;
    }
    if let Some(backup_leaf) = backup_leaf {
        validate_single_leaf(backup_leaf)?;
    }
    anyhow::ensure!(
        journal_leaf.is_some() == backup_leaf.is_some(),
        "retained effective-default journal and backup descriptors must be paired"
    );
    const STABLE_CAPTURE_ATTEMPTS: usize = 3;
    for _ in 0..STABLE_CAPTURE_ATTEMPTS {
        let first = snapshot_workspace_config_directory_once(
            directory,
            config_leaf,
            canonical_config_path,
            journal_leaf,
            backup_leaf,
        )?;
        let second = snapshot_workspace_config_directory_once(
            directory,
            config_leaf,
            canonical_config_path,
            journal_leaf,
            backup_leaf,
        )?;
        if first.digest == second.digest {
            return Ok(second);
        }
    }
    anyhow::bail!("workspace configuration changed during retained snapshot capture")
}

fn snapshot_workspace_config_layer_once(
    directory: &std::fs::File,
) -> Result<crate::config::WorkspaceConfigLayerSnapshot> {
    let Some(cockpit) =
        open_retained_child_directory_optional(directory, std::ffi::OsStr::new(".cockpit"))?
    else {
        return Ok(workspace_snapshot(None, Vec::new(), None));
    };
    snapshot_workspace_config_directory_once(
        &cockpit,
        std::ffi::OsStr::new("config.json"),
        &Path::new(".cockpit").join("config.json"),
        None,
        None,
    )
}

fn validate_single_leaf(leaf: &std::ffi::OsStr) -> Result<()> {
    let mut components = Path::new(leaf).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => anyhow::bail!("retained workspace config leaf must be one normal path component"),
    }
}

fn snapshot_workspace_config_directory_once(
    cockpit: &std::fs::File,
    config_leaf: &std::ffi::OsStr,
    canonical_config_path: &Path,
    journal_leaf: Option<&std::ffi::OsStr>,
    backup_leaf: Option<&std::ffi::OsStr>,
) -> Result<crate::config::WorkspaceConfigLayerSnapshot> {
    let config_json =
        read_retained_leaf_optional(cockpit, config_leaf, MAX_WORKSPACE_CONFIG_FILE_BYTES)?;
    let (config_json, effective_default_artifact_digest) = match (journal_leaf, backup_leaf) {
        (Some(journal_leaf), Some(backup_leaf)) => {
            let journal = read_retained_leaf_optional(
                cockpit,
                journal_leaf,
                MAX_WORKSPACE_CONFIG_FILE_BYTES,
            )?;
            let backup =
                read_retained_leaf_optional(cockpit, backup_leaf, MAX_WORKSPACE_CONFIG_FILE_BYTES)?;
            (
                crate::config::effective_default::project_retained_effective_default_bytes(
                    canonical_config_path,
                    config_json,
                    journal.as_deref(),
                    backup.as_deref(),
                )?,
                effective_default_artifact_digest(journal.as_deref(), backup.as_deref()),
            )
        }
        (None, None) => (config_json, None),
        _ => unreachable!("paired retained journal descriptors were validated above"),
    };
    let Some(providers) =
        open_retained_child_directory_optional(cockpit, std::ffi::OsStr::new("providers"))?
    else {
        return Ok(workspace_snapshot(
            config_json,
            Vec::new(),
            effective_default_artifact_digest,
        ));
    };

    let mut provider_files = Vec::new();
    for name in retained_directory_names(&providers)? {
        if provider_files.len() >= WORKSPACE_CONFIG_MAX_PROVIDER_FILES {
            anyhow::bail!("workspace provider layer exceeds its file limit");
        }
        let path = Path::new(&name);
        let Some(id) = crate::config::providers::provider_id_from_file_name(path) else {
            // Non-provider files are not part of this layer; never follow or
            // inspect them merely to decide that fact.
            continue;
        };
        let bytes =
            read_leaf_from_directory_handle(&providers, &name, MAX_WORKSPACE_CONFIG_FILE_BYTES)?;
        provider_files.push((id, bytes));
    }
    provider_files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(workspace_snapshot(
        config_json,
        provider_files,
        effective_default_artifact_digest,
    ))
}

fn workspace_snapshot(
    config_json: Option<Vec<u8>>,
    provider_files: Vec<(String, Vec<u8>)>,
    effective_default_artifact_digest: Option<String>,
) -> crate::config::WorkspaceConfigLayerSnapshot {
    use sha2::{Digest as _, Sha256};

    // Domain/type/length framing makes this digest suitable as an immutable
    // input to daemon snapshot publication; distinct boundaries cannot alias.
    let mut hasher = Sha256::new();
    hasher.update(b"cockpit-workspace-config-layer-v1");
    match &config_json {
        Some(bytes) => {
            hasher.update([1]);
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        None => hasher.update([0]),
    }
    match &effective_default_artifact_digest {
        Some(digest) => {
            hasher.update([1]);
            hasher.update((digest.len() as u64).to_be_bytes());
            hasher.update(digest.as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update((provider_files.len() as u64).to_be_bytes());
    for (id, bytes) in &provider_files {
        hasher.update((id.len() as u64).to_be_bytes());
        hasher.update(id.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    crate::config::WorkspaceConfigLayerSnapshot {
        origin: None,
        config_json,
        provider_files,
        effective_default_artifact_digest,
        digest: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    }
}

pub(crate) fn empty_workspace_config_layer_snapshot() -> crate::config::WorkspaceConfigLayerSnapshot
{
    workspace_snapshot(None, Vec::new(), None)
}

/// Replace only the captured `config.json` bytes while preserving the exact
/// retained provider-file inventory. Used by a capability-bound default-write
/// preview to ask what an active-model clear would expose without reopening a
/// layer by pathname.
pub(crate) fn workspace_config_layer_snapshot_with_config_json(
    snapshot: &crate::config::WorkspaceConfigLayerSnapshot,
    config_json: Option<Vec<u8>>,
) -> crate::config::WorkspaceConfigLayerSnapshot {
    workspace_snapshot(
        config_json,
        snapshot.provider_files.clone(),
        snapshot.effective_default_artifact_digest.clone(),
    )
    .with_origin(snapshot.origin.clone())
}

fn effective_default_artifact_digest(
    journal: Option<&[u8]>,
    backup: Option<&[u8]>,
) -> Option<String> {
    use sha2::{Digest as _, Sha256};

    if journal.is_none() && backup.is_none() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"cockpit-retained-effective-default-artifacts-v1");
    for artifact in [journal, backup] {
        match artifact {
            Some(bytes) => {
                hasher.update([1]);
                hasher.update((bytes.len() as u64).to_be_bytes());
                hasher.update(bytes);
            }
            None => hasher.update([0]),
        }
    }
    Some(
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn read_retained_leaf_optional(
    directory: &std::fs::File,
    leaf: &std::ffi::OsStr,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    read_optional_leaf_from_directory_handle(directory, leaf, max_bytes)
}

#[cfg(unix)]
pub(crate) fn open_retained_child_directory_optional(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
) -> Result<Option<std::fs::File>> {
    match open_file_at_nofollow(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => {
            if !file.metadata()?.is_dir() {
                anyhow::bail!("retained workspace config component is not a directory");
            }
            Ok(Some(file))
        }
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn retained_directory_names(directory: &std::fs::File) -> Result<Vec<std::ffi::OsString>> {
    use std::ffi::{CStr, OsStr};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error())
            .context("duplicating retained provider directory");
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(std::io::Error::last_os_error())
            .context("enumerating retained provider directory");
    }
    let mut names = Vec::new();
    loop {
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        #[cfg(not(target_os = "macos"))]
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            #[cfg(target_os = "macos")]
            let errno_code = unsafe { *libc::__error() };
            #[cfg(not(target_os = "macos"))]
            let errno_code = unsafe { *libc::__errno_location() };
            unsafe { libc::closedir(stream) };
            if errno_code != 0 {
                return Err(std::io::Error::from_raw_os_error(errno_code))
                    .context("reading retained provider directory");
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsStr::from_bytes(name).to_os_string());
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(windows)]
pub(crate) fn open_retained_child_directory_optional(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
) -> Result<Option<std::fs::File>> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_TRAVERSE, SYNCHRONIZE,
    };
    match open_windows_relative_nofollow(
        parent,
        name,
        true,
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
    ) {
        Ok(file) => {
            reject_windows_reparse_handle(&file, Path::new(name))?;
            if !file.metadata()?.is_dir() {
                anyhow::bail!("retained workspace config component is not a directory");
            }
            Ok(Some(file))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(windows)]
fn retained_directory_names(directory: &std::fs::File) -> Result<Vec<std::ffi::OsString>> {
    use std::os::windows::ffi::OsStringExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_BOTH_DIR_INFO, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
        GetFileInformationByHandleEx,
    };
    let mut names = Vec::new();
    let mut restart = true;
    loop {
        let mut buffer = vec![0u8; 64 * 1024];
        let class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
            )
        };
        restart = false;
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                break;
            }
            return Err(error).context("enumerating retained provider directory");
        }
        let mut offset = 0usize;
        loop {
            let info = unsafe { &*(buffer.as_ptr().add(offset).cast::<FILE_ID_BOTH_DIR_INFO>()) };
            let length = info.FileNameLength as usize / 2;
            let name = std::ffi::OsString::from_wide(unsafe {
                std::slice::from_raw_parts(info.FileName.as_ptr(), length)
            });
            if name != "." && name != ".." {
                names.push(name);
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            offset = offset
                .checked_add(info.NextEntryOffset as usize)
                .filter(|offset| *offset < buffer.len())
                .ok_or_else(|| {
                    anyhow::anyhow!("invalid Windows retained provider enumeration offset")
                })?;
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(all(not(unix), not(windows)))]
pub(crate) fn open_retained_child_directory_optional(
    _: &std::fs::File,
    _: &std::ffi::OsStr,
) -> Result<Option<std::fs::File>> {
    anyhow::bail!("retained workspace config snapshots are unsupported on this platform")
}

#[cfg(all(not(unix), not(windows)))]
fn retained_directory_names(_: &std::fs::File) -> Result<Vec<std::ffi::OsString>> {
    anyhow::bail!("retained workspace config snapshots are unsupported on this platform")
}

struct KnowledgeSnapshotLimits {
    max_files: usize,
    max_entries: usize,
    max_depth: usize,
    max_file_bytes: usize,
    max_total_bytes: usize,
}

pub(crate) fn snapshot_markdown_tree_nofollow(
    root: &Path,
    max_files: usize,
    max_entries: usize,
    max_depth: usize,
    max_file_bytes: usize,
    max_total_bytes: usize,
) -> Result<Vec<(PathBuf, String)>> {
    let root_handle = open_directory_handle_nofollow(root)?;
    snapshot_markdown_tree_from_retained_directory_nofollow(
        &root_handle,
        max_files,
        max_entries,
        max_depth,
        max_file_bytes,
        max_total_bytes,
    )
}

pub(crate) fn snapshot_markdown_tree_from_retained_directory_nofollow(
    root_handle: &std::fs::File,
    max_files: usize,
    max_entries: usize,
    max_depth: usize,
    max_file_bytes: usize,
    max_total_bytes: usize,
) -> Result<Vec<(PathBuf, String)>> {
    let mut output = Vec::new();
    let mut total = 0usize;
    let mut entries = 0usize;
    let limits = KnowledgeSnapshotLimits {
        max_files,
        max_entries,
        max_depth,
        max_file_bytes,
        max_total_bytes,
    };
    snapshot_markdown_directory(
        root_handle,
        Path::new(""),
        &mut output,
        &mut total,
        &mut entries,
        0,
        &limits,
    )?;
    output.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(output)
}

fn accept_markdown_document(
    relative: PathBuf,
    mut file: std::fs::File,
    output: &mut Vec<(PathBuf, String)>,
    total: &mut usize,
    max_files: usize,
    max_file_bytes: usize,
    max_total_bytes: usize,
) -> Result<()> {
    use std::io::{Read as _, Seek as _};
    let before = file.metadata()?;
    if !before.is_file() || before.len() > max_file_bytes as u64 || output.len() >= max_files {
        anyhow::bail!("knowledge document exceeds the retained snapshot bounds");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(max_file_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    file.rewind()?;
    let mut verification = Vec::with_capacity(bytes.len());
    (&mut file)
        .take(max_file_bytes as u64 + 1)
        .read_to_end(&mut verification)?;
    let after = file.metadata()?;
    if bytes.len() > max_file_bytes
        || bytes != verification
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        anyhow::bail!("knowledge document changed during retained snapshot");
    }
    *total = total
        .checked_add(bytes.len())
        .filter(|total| *total <= max_total_bytes)
        .ok_or_else(|| anyhow::anyhow!("knowledge snapshot exceeds its aggregate byte limit"))?;
    output.push((
        relative,
        String::from_utf8(bytes).context("knowledge document is not valid UTF-8")?,
    ));
    Ok(())
}

#[cfg(unix)]
fn snapshot_markdown_directory(
    directory: &std::fs::File,
    relative: &Path,
    output: &mut Vec<(PathBuf, String)>,
    total: &mut usize,
    entries: &mut usize,
    depth: usize,
    limits: &KnowledgeSnapshotLimits,
) -> Result<()> {
    use std::ffi::{CStr, OsStr};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    if depth > limits.max_depth {
        anyhow::bail!("knowledge snapshot exceeds its directory depth limit");
    }
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error()).context("duplicating knowledge directory");
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(std::io::Error::last_os_error()).context("enumerating knowledge directory");
    }
    let mut names = Vec::new();
    loop {
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        #[cfg(not(target_os = "macos"))]
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            #[cfg(target_os = "macos")]
            let errno_code = unsafe { *libc::__error() };
            #[cfg(not(target_os = "macos"))]
            let errno_code = unsafe { *libc::__errno_location() };
            unsafe { libc::closedir(stream) };
            if errno_code != 0 {
                return Err(std::io::Error::from_raw_os_error(errno_code))
                    .context("reading retained knowledge directory");
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." || name.starts_with(b".") {
            continue;
        }
        names.push(OsStr::from_bytes(name).to_os_string());
    }
    names.sort();
    for name in names {
        *entries = entries
            .checked_add(1)
            .filter(|entries| *entries <= limits.max_entries)
            .ok_or_else(|| anyhow::anyhow!("knowledge snapshot exceeds its entry limit"))?;
        let component = path_component_cstring(&name)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("opening retained knowledge descendant {name:?}"));
        }
        let child = unsafe { std::fs::File::from_raw_fd(fd) };
        let metadata = child.metadata()?;
        let child_relative = relative.join(&name);
        if metadata.is_dir() {
            snapshot_markdown_directory(
                &child,
                &child_relative,
                output,
                total,
                entries,
                depth + 1,
                limits,
            )?;
        } else if metadata.is_file() && child_relative.extension().is_some_and(|ext| ext == "md") {
            accept_markdown_document(
                child_relative,
                child,
                output,
                total,
                limits.max_files,
                limits.max_file_bytes,
                limits.max_total_bytes,
            )?;
        } else if metadata.file_type().is_symlink() {
            anyhow::bail!("knowledge snapshot refused a symbolic link");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn snapshot_markdown_directory(
    directory: &std::fs::File,
    relative: &Path,
    output: &mut Vec<(PathBuf, String)>,
    total: &mut usize,
    entries: &mut usize,
    depth: usize,
    limits: &KnowledgeSnapshotLimits,
) -> Result<()> {
    use std::os::windows::ffi::OsStringExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
    use windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ID_BOTH_DIR_INFO, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
        FILE_TRAVERSE, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
        GetFileInformationByHandleEx, SYNCHRONIZE,
    };

    if depth > limits.max_depth {
        anyhow::bail!("knowledge snapshot exceeds its directory depth limit");
    }
    let mut names = Vec::new();
    let mut restart = true;
    loop {
        let mut buffer = vec![0u8; 64 * 1024];
        let class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
            )
        };
        restart = false;
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                break;
            }
            return Err(error).context("enumerating retained Windows knowledge directory");
        }
        let mut offset = 0usize;
        loop {
            let info = unsafe { &*(buffer.as_ptr().add(offset).cast::<FILE_ID_BOTH_DIR_INFO>()) };
            let length = info.FileNameLength as usize / 2;
            let name = std::ffi::OsString::from_wide(unsafe {
                std::slice::from_raw_parts(info.FileName.as_ptr(), length)
            });
            if name != "." && name != ".." && !name.to_string_lossy().starts_with('.') {
                names.push((name, info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0));
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            offset = offset
                .checked_add(info.NextEntryOffset as usize)
                .filter(|offset| *offset < buffer.len())
                .ok_or_else(|| anyhow::anyhow!("invalid Windows directory enumeration offset"))?;
        }
    }
    names.sort_by(|left, right| left.0.cmp(&right.0));
    for (name, directory_hint) in names {
        *entries = entries
            .checked_add(1)
            .filter(|entries| *entries <= limits.max_entries)
            .ok_or_else(|| anyhow::anyhow!("knowledge snapshot exceeds its entry limit"))?;
        let child_relative = relative.join(&name);
        let child = open_windows_relative_nofollow(
            directory,
            &name,
            false,
            if directory_hint {
                FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE
            } else {
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE
            },
            FILE_OPEN,
        )?;
        reject_windows_reparse_handle(&child, &child_relative)?;
        let metadata = child.metadata()?;
        if metadata.is_dir() {
            snapshot_markdown_directory(
                &child,
                &child_relative,
                output,
                total,
                entries,
                depth + 1,
                limits,
            )?;
        } else if metadata.is_file() && child_relative.extension().is_some_and(|ext| ext == "md") {
            accept_markdown_document(
                child_relative,
                child,
                output,
                total,
                limits.max_files,
                limits.max_file_bytes,
                limits.max_total_bytes,
            )?;
        }
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn snapshot_markdown_directory(
    _: &std::fs::File,
    _: &Path,
    _: &mut Vec<(PathBuf, String)>,
    _: &mut usize,
    _: &mut usize,
    _: usize,
    _: &KnowledgeSnapshotLimits,
) -> Result<()> {
    anyhow::bail!("retained knowledge snapshots are unsupported on this platform")
}

#[cfg(windows)]
fn verify_windows_protected_dacl(file: &std::fs::File) -> Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetKernelObjectSecurity, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner, IsWellKnownSid, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    let mut expected_owner = current_windows_user_sid()?;
    let security_information = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
    let mut needed = 0u32;
    unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle(),
            security_information,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut descriptor = vec![0u8; needed as usize];
    if unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle(),
            security_information,
            descriptor.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe {
        GetSecurityDescriptorControl(descriptor.as_mut_ptr().cast(), &mut control, &mut revision)
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if control & SE_DACL_PROTECTED == 0 {
        anyhow::bail!("terminal ingress DACL is not protected");
    }
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorOwner(
            descriptor.as_mut_ptr().cast(),
            &mut owner,
            &mut owner_defaulted,
        )
    } == 0
        || owner.is_null()
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // EqualSid's Windows binding takes mutable PSID pointers even though it
    // only compares their contents.
    if unsafe { EqualSid(owner, expected_owner.as_mut_ptr().cast()) } == 0 {
        anyhow::bail!("terminal ingress object owner is not the daemon user");
    }
    let mut dacl_present = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_mut_ptr().cast(),
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        anyhow::bail!("terminal ingress file has no protected DACL");
    }
    let ace_count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(ace_count) {
        let mut raw_ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let header = raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>();
        let ace_type = unsafe { (*header).AceType };
        // ACCESS_ALLOWED_ACE_TYPE is zero. Fail closed on object/callback
        // allow ACE shapes because their SID offsets differ.
        if ace_type == 0 {
            let allowed = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
            let sid = unsafe { std::ptr::addr_of_mut!((*allowed).SidStart).cast() };
            let approved = unsafe {
                EqualSid(sid, expected_owner.as_mut_ptr().cast()) != 0
                    || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
            };
            if !approved {
                anyhow::bail!("terminal ingress DACL grants an unapproved SID");
            }
        } else if matches!(ace_type, 5 | 9 | 11) {
            anyhow::bail!("terminal ingress DACL contains an unsupported allow ACE");
        }
    }
    Ok(())
}

#[cfg(windows)]
fn current_windows_user_sid() -> Result<Vec<u8>> {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use windows_sys::Wdk::Storage::FileSystem::{NtOpenProcessToken, NtQueryInformationToken};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::{GetLengthSid, TOKEN_QUERY, TOKEN_USER, TokenUser};

    let mut token: HANDLE = std::ptr::null_mut();
    let status = unsafe { NtOpenProcessToken((-1isize) as HANDLE, TOKEN_QUERY, &mut token) };
    if status < 0 || token.is_null() {
        anyhow::bail!("opening current process token failed with NTSTATUS {status:#x}");
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut needed = 0u32;
    unsafe {
        NtQueryInformationToken(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed < std::mem::size_of::<TOKEN_USER>() as u32 {
        anyhow::bail!("current process token returned no user SID");
    }
    let mut info = vec![0u8; needed as usize];
    let status = unsafe {
        NtQueryInformationToken(
            token.as_raw_handle(),
            TokenUser,
            info.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if status < 0 {
        anyhow::bail!("querying current process user SID failed with NTSTATUS {status:#x}");
    }
    let sid = unsafe { (*(info.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    if sid.is_null() {
        anyhow::bail!("current process token has a null user SID");
    }
    let sid_len = unsafe { GetLengthSid(sid) };
    if sid_len == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut owned = vec![0u8; sid_len as usize];
    unsafe { std::ptr::copy_nonoverlapping(sid.cast::<u8>(), owned.as_mut_ptr(), owned.len()) };
    Ok(owned)
}

fn read_all(mut file: impl std::io::Read, path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(bytes)
}

fn read_all_bounded(file: &mut std::fs::File, path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    anyhow::ensure!(
        metadata.len() <= max_bytes as u64,
        "{} exceeds the byte limit",
        path.display()
    );
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(64 * 1024));
    std::io::Read::take(file, max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > max_bytes {
        anyhow::bail!("{} exceeds the byte limit", path.display());
    }
    Ok(bytes)
}

fn root_cause_is_not_found(error: &anyhow::Error) -> bool {
    error
        .root_cause()
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

/// Atomically replace `path` with owner-only private content.
///
/// This is the one platform file-security abstraction used for the
/// effective-default rollback snapshot and journal.
///
/// **Unix:** the replacement is created `O_NOFOLLOW`/`O_EXCL` at mode `0600`
/// and re-`fchmod`ded to `0600` after the rename, so the snapshot is
/// owner-only regardless of umask. This is enforced and asserted in tests.
///
/// **Windows:** every path component is opened relative to a retained parent
/// handle with `FILE_OPEN_REPARSE_POINT`, and any reparse point is rejected —
/// no junction or symlink can redirect the snapshot outside its config
/// directory, and a component swapped after preparation cannot redirect the
/// commit. The file's DACL is **inherited from its parent directory** rather
/// than being set explicitly: cockpit-owned config directories are created
/// through [`ensure_private_dir`], but a user-chosen `COCKPIT_CONFIG`
/// directory keeps whatever ACL it already had. An explicit owner-only
/// security descriptor is not applied here; treat Windows confidentiality as
/// "inherits the config directory's ACL", not "owner-only by construction".
pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    prepare_atomic_write(path, contents)?.commit()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let (parent, file_name) = open_parent_directory_nofollow(path)?;
        let file = open_file_at_nofollow(
            &parent,
            &file_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
        chmod_file_private(&file).with_context(|| format!("chmod 0600 {}", path.display()))?;
        debug_assert_eq!(
            file.metadata()
                .with_context(|| format!("stat {}", path.display()))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    Ok(())
}

/// fsync a directory so a rename or unlink inside it is durable.
///
/// Unlike the best-effort syncs inside [`PreparedAtomicWrite`], a failure here
/// is propagated: the effective-default journal treats an fsync failure as a
/// typed failure rather than a silent success.
///
/// **Platform limits.** On Unix this is a real `fsync(2)` on a directory
/// descriptor opened without following symlinks, so a rename or unlink in that
/// directory is durable when it returns. On Windows there is no directory
/// flush: `FlushFileBuffers` is not defined for directory handles, and NTFS
/// orders metadata through its own journal. The Windows branch therefore only
/// re-validates that the path is still a real directory and not a reparse
/// point — it detects a swapped component but provides **no** durability
/// barrier. Crash-consistency claims for Windows rest on NTFS metadata
/// journaling, not on this call.
pub(crate) fn fsync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let directory = open_directory_nofollow(path, false, false)?;
        directory
            .sync_all()
            .with_context(|| format!("fsync directory {}", path.display()))
    }
    #[cfg(windows)]
    {
        let directory = open_windows_directory_nofollow(path, false)?;
        // No durability barrier is available here (see the doc comment).
        // Confirm the handle is a real directory and not a reparse point so a
        // swapped component still fails closed.
        reject_windows_reparse_handle(&directory, path)?;
        Ok(())
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let directory = std::fs::File::open(path)
            .with_context(|| format!("opening directory {}", path.display()))?;
        directory
            .sync_all()
            .with_context(|| format!("fsync directory {}", path.display()))
    }
}

#[cfg(unix)]
fn open_private_lock_file_at(
    parent: &std::fs::File,
    file_name: &std::ffi::OsStr,
    display_path: &Path,
) -> Result<std::fs::File> {
    let file = open_file_at_nofollow(
        parent,
        file_name,
        libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .with_context(|| format!("opening config mutation lock {}", display_path.display()))?;
    chmod_file_private(&file).with_context(|| format!("chmod 0600 {}", display_path.display()))?;
    Ok(file)
}

#[cfg(windows)]
fn open_private_lock_file_at(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    display_path: &Path,
) -> Result<std::fs::File> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN_IF;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, SYNCHRONIZE,
    };

    let file = open_windows_relative_nofollow(
        parent,
        name,
        false,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN_IF,
    )
    .with_context(|| format!("opening config mutation lock {}", display_path.display()))?;
    reject_windows_reparse_handle(&file, display_path)?;
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn open_private_lock_file_at(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    display_path: &Path,
) -> Result<std::fs::File> {
    let path = display_path;
    let _ = parent;
    let _ = name;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening config mutation lock {}", path.display()))
}

/// A same-directory, synced replacement that is invisible until commit.
/// Dropping an uncommitted value removes its private temporary file and leaves
/// the destination unchanged.
pub(crate) struct PreparedAtomicWrite {
    #[cfg(all(not(unix), not(windows)))]
    tmp_path: Option<PathBuf>,
    #[cfg(all(not(unix), not(windows)))]
    path: PathBuf,
    parent: PathBuf,
    #[cfg(any(unix, windows))]
    parent_dir: std::fs::File,
    #[cfg(unix)]
    tmp_name: Option<std::ffi::OsString>,
    #[cfg(windows)]
    tmp_file: Option<std::fs::File>,
    #[cfg(any(unix, windows))]
    destination_name: std::ffi::OsString,
}

impl PreparedAtomicWrite {
    pub(crate) fn commit(mut self) -> Result<()> {
        #[cfg(unix)]
        {
            let tmp_name = self
                .tmp_name
                .as_ref()
                .expect("prepared atomic write always has a temporary name");
            rename_file_at(&self.parent_dir, tmp_name, &self.destination_name)
                .with_context(|| format!("replacing {}", self.parent.display()))?;
            self.tmp_name = None;
            self.parent_dir
                .sync_all()
                .context("fsync config directory after replacement")?;
            Ok(())
        }
        #[cfg(windows)]
        {
            let tmp_file = self
                .tmp_file
                .as_ref()
                .expect("prepared atomic write always retains its temporary file");
            rename_open_file_on_windows(tmp_file, &self.parent_dir, &self.destination_name, true)
                .with_context(|| format!("replacing {}", self.parent.display()))?;
            self.tmp_file = None;
            self.parent_dir
                .sync_all()
                .context("fsync config directory after replacement")?;
            Ok(())
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            let tmp_path = self
                .tmp_path
                .as_ref()
                .expect("prepared atomic write always has a temporary path");
            replace_atomic_file(tmp_path, &self.path)
                .with_context(|| format!("replacing {}", self.path.display()))?;
            self.tmp_path = None;
            std::fs::File::open(&self.parent)
                .and_then(|dir| dir.sync_all())
                .context("fsync config directory after replacement")?;
            Ok(())
        }
    }

    pub(crate) fn commit_noreplace(mut self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            use std::os::unix::ffi::OsStrExt as _;
            let tmp_name = self
                .tmp_name
                .as_ref()
                .expect("prepared atomic write has a temporary name");
            let source = std::ffi::CString::new(tmp_name.as_bytes())?;
            let destination = std::ffi::CString::new(self.destination_name.as_bytes())?;
            // SAFETY: names are NUL-free and both operations are relative to
            // the same retained directory descriptor. linkat is an atomic
            // no-replace publication; unlink removes only the staging name.
            let linked = unsafe {
                libc::linkat(
                    self.parent_dir.as_raw_fd(),
                    source.as_ptr(),
                    self.parent_dir.as_raw_fd(),
                    destination.as_ptr(),
                    0,
                )
            };
            if linked != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("publishing private file without replacement");
            }
            unlink_file_at(&self.parent_dir, tmp_name)?;
            self.tmp_name = None;
            self.parent_dir.sync_all()?;
            Ok(())
        }
        #[cfg(windows)]
        {
            let tmp_file = self
                .tmp_file
                .as_ref()
                .expect("prepared atomic write retains its temporary file");
            rename_open_file_on_windows(tmp_file, &self.parent_dir, &self.destination_name, false)?;
            self.tmp_file = None;
            self.parent_dir.sync_all()?;
            Ok(())
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            if self.path.exists() {
                anyhow::bail!("destination already exists");
            }
            self.commit()
        }
    }
}

#[cfg(all(not(windows), not(unix)))]
fn replace_atomic_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

impl Drop for PreparedAtomicWrite {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(tmp_name) = self.tmp_name.take() {
            let _ = unlink_file_at(&self.parent_dir, &tmp_name);
        }
        #[cfg(windows)]
        if let Some(tmp_file) = self.tmp_file.take() {
            let _ = remove_open_file_on_windows(&tmp_file);
        }
        #[cfg(all(not(unix), not(windows)))]
        if let Some(tmp_path) = self.tmp_path.take() {
            let _ = std::fs::remove_file(tmp_path);
        }
    }
}

/// A file removal bound to handles opened during preparation. Unix retains the
/// parent directory descriptor; Windows opens every path component relative to
/// its retained parent and retains the final file handle. A path-component swap
/// therefore cannot redirect commit into an attacker-controlled directory.
#[derive(Debug)]
pub(crate) struct PreparedFileRemoval {
    path: PathBuf,
    #[cfg(unix)]
    parent_dir: std::fs::File,
    #[cfg(unix)]
    file_name: std::ffi::OsString,
    #[cfg(windows)]
    file: Option<std::fs::File>,
}

impl PreparedFileRemoval {
    pub(crate) fn commit(self) -> Result<()> {
        #[cfg(unix)]
        {
            match unlink_file_at(&self.parent_dir, &self.file_name) {
                Ok(()) => {
                    let _ = self.parent_dir.sync_all();
                    Ok(())
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => {
                    Err(error).with_context(|| format!("removing {}", self.path.display()))
                }
            }
        }
        #[cfg(windows)]
        {
            let Some(file) = self.file else {
                return Ok(());
            };
            remove_open_file_on_windows(&file)
                .with_context(|| format!("removing {}", self.path.display()))
        }
        #[cfg(not(any(unix, windows)))]
        {
            match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => {
                    Err(error).with_context(|| format!("removing {}", self.path.display()))
                }
            }
        }
    }
}

pub(crate) fn prepare_file_removal(path: &Path) -> Result<PreparedFileRemoval> {
    #[cfg(unix)]
    let (parent_dir, file_name) = open_parent_directory_nofollow(path)?;
    #[cfg(windows)]
    let file = open_file_for_removal_on_windows(path)?;
    Ok(PreparedFileRemoval {
        path: path.to_path_buf(),
        #[cfg(unix)]
        parent_dir,
        #[cfg(unix)]
        file_name,
        #[cfg(windows)]
        file,
    })
}

#[cfg(windows)]
fn open_file_for_removal_on_windows(path: &Path) -> Result<Option<std::fs::File>> {
    let (anchor_path, names) = windows_absolute_path_parts(path)?;
    let Some((file_name, parent_names)) = names.split_last() else {
        anyhow::bail!("Windows removal path has no file name: {}", path.display());
    };

    let mut directory = open_windows_directory_anchor(&anchor_path)
        .with_context(|| format!("opening removal path anchor {}", anchor_path.display()))?;
    reject_windows_reparse_handle(&directory, &anchor_path)?;
    let mut traversed = anchor_path;
    for name in parent_names {
        traversed.push(name);
        directory = match open_windows_child_nofollow(&directory, name, true, false) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "opening removal directory component {}",
                        traversed.display()
                    )
                });
            }
        };
        reject_windows_reparse_handle(&directory, &traversed)?;
    }

    let result = open_windows_child_nofollow(&directory, file_name, false, true);
    let file = match result {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("opening {} for removal", path.display()));
        }
    };
    reject_windows_reparse_handle(&file, path)?;
    Ok(Some(file))
}

#[cfg(windows)]
fn windows_absolute_path_parts(path: &Path) -> Result<(PathBuf, Vec<std::ffi::OsString>)> {
    use std::path::Component;

    let absolute = std::path::absolute(path)
        .with_context(|| format!("resolving absolute Windows path {}", path.display()))?;
    let mut components = absolute.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        anyhow::bail!("Windows path has no volume prefix: {}", path.display());
    };
    let Some(Component::RootDir) = components.next() else {
        anyhow::bail!("Windows path is not absolute: {}", path.display());
    };

    let mut anchor = PathBuf::from(prefix.as_os_str());
    anchor.push(Path::new(r"\"));
    let mut names = Vec::new();
    for component in components {
        match component {
            Component::CurDir => {}
            Component::ParentDir => names.push(std::ffi::OsString::from("..")),
            Component::Normal(name) => names.push(name.to_os_string()),
            Component::Prefix(_) | Component::RootDir => {
                anyhow::bail!(
                    "Windows path contains an unexpected root component: {}",
                    path.display()
                );
            }
        }
    }
    Ok((anchor, names))
}

#[cfg(windows)]
fn open_windows_directory_nofollow(path: &Path, create_missing: bool) -> Result<std::fs::File> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_TRAVERSE, SYNCHRONIZE,
    };

    open_windows_directory_nofollow_with_final_access(
        path,
        create_missing,
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
    )
}

#[cfg(windows)]
fn open_windows_directory_nofollow_with_final_access(
    path: &Path,
    create_missing: bool,
    final_desired_access: u32,
) -> Result<std::fs::File> {
    use windows_sys::Wdk::Storage::FileSystem::{FILE_CREATE, FILE_OPEN};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_TRAVERSE, SYNCHRONIZE, WRITE_DAC,
    };

    let (anchor, names) = windows_absolute_path_parts(path)?;
    let mut directory = open_windows_directory_anchor(&anchor)
        .with_context(|| format!("opening Windows path anchor {}", anchor.display()))?;
    reject_windows_reparse_handle(&directory, &anchor)?;
    let mut traversed = anchor;
    let final_index = names.len().saturating_sub(1);
    for (index, name) in names.into_iter().enumerate() {
        traversed.push(&name);
        let desired_access = if index == final_index {
            final_desired_access
        } else {
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE
        };
        directory = match open_windows_relative_nofollow(
            &directory,
            &name,
            true,
            desired_access,
            FILE_OPEN,
        ) {
            Ok(directory) => directory,
            Err(error) if create_missing && error.kind() == std::io::ErrorKind::NotFound => {
                match open_windows_relative_nofollow(
                    &directory,
                    &name,
                    true,
                    desired_access | WRITE_DAC,
                    FILE_CREATE,
                ) {
                    Ok(directory) => {
                        protect_windows_dacl(&directory)?;
                        verify_windows_protected_dacl(&directory)?;
                        directory
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        open_windows_relative_nofollow(
                            &directory,
                            &name,
                            true,
                            desired_access,
                            FILE_OPEN,
                        )
                        .with_context(|| {
                            format!(
                                "opening concurrently created Windows directory {}",
                                traversed.display()
                            )
                        })?
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("creating Windows directory {}", traversed.display())
                        });
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "opening Windows directory component {}",
                        traversed.display()
                    )
                });
            }
        };
        reject_windows_reparse_handle(&directory, &traversed)?;
    }
    Ok(directory)
}

#[cfg(windows)]
fn open_windows_parent_directory_nofollow(
    path: &Path,
    create_missing: bool,
) -> Result<(std::fs::File, std::ffi::OsString)> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Windows path has no file name: {}", path.display()))?;
    Ok((
        open_windows_directory_nofollow(parent, create_missing)?,
        name.to_os_string(),
    ))
}

#[cfg(windows)]
fn open_windows_parent_directory_for_rename_nofollow(
    path: &Path,
    create_missing: bool,
) -> Result<(std::fs::File, std::ffi::OsString)> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ADD_FILE, FILE_READ_ATTRIBUTES, FILE_TRAVERSE, SYNCHRONIZE,
    };

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Windows path has no file name: {}", path.display()))?;
    Ok((
        open_windows_directory_nofollow_with_final_access(
            parent,
            create_missing,
            FILE_ADD_FILE | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )?,
        name.to_os_string(),
    ))
}

#[cfg(windows)]
fn open_windows_directory_anchor(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
    };

    std::fs::OpenOptions::new()
        .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(windows)]
fn open_windows_child_nofollow(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    directory: bool,
    delete_access: bool,
) -> std::io::Result<std::fs::File> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_READ_ATTRIBUTES, FILE_TRAVERSE, SYNCHRONIZE,
    };

    let desired_access = FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
        | if directory { FILE_TRAVERSE } else { 0 }
        | if delete_access { DELETE } else { 0 };
    open_windows_relative_nofollow(parent, name, directory, desired_access, FILE_OPEN)
}

#[cfg(windows)]
fn open_windows_relative_nofollow(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    directory: bool,
    desired_access: u32,
    create_disposition: u32,
) -> std::io::Result<std::fs::File> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_FOR_BACKUP_INTENT,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let mut name_wide = name.encode_wide().collect::<Vec<_>>();
    if name_wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows path component contains NUL",
        ));
    }
    let byte_len = name_wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows path component is too long",
            )
        })?;
    let unicode_name = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: name_wide.as_mut_ptr(),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: std::ptr::from_ref(&unicode_name),
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    let mut io_status = IO_STATUS_BLOCK::default();
    let open_options = FILE_OPEN_REPARSE_POINT
        | FILE_OPEN_FOR_BACKUP_INTENT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
    // SAFETY: the retained parent handle, component buffer, object attributes,
    // and status block all remain live for the call. A single-component name
    // with RootDirectory makes lookup relative to the exact retained parent.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &object_attributes,
            &mut io_status,
            std::ptr::null(),
            if directory {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            },
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            create_disposition,
            open_options,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: this conversion is total for NTSTATUS values and does not
        // dereference pointers or depend on thread-local last-error state.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }
    // SAFETY: NtCreateFile returned success and transferred one owned handle.
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn reject_windows_reparse_handle(file: &std::fs::File, path: &Path) -> Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FileAttributeTagInfo,
        GetFileInformationByHandleEx,
    };

    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: the file handle and correctly sized output buffer remain live
    // for the call.
    let queried = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            std::ptr::from_mut(&mut info).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if queried == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("checking Windows path component {}", path.display()));
    }
    if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        anyhow::bail!(
            "refusing Windows reparse-point component {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn rename_open_file_on_windows(
    file: &std::fs::File,
    parent: &std::fs::File,
    destination: &std::ffi::OsStr,
    replace_existing: bool,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_RENAME_INFO, FileRenameInfo, SetFileInformationByHandle,
    };

    let mut destination_wide = destination.encode_wide().collect::<Vec<_>>();
    if destination_wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows destination name contains NUL",
        ));
    }
    let name_bytes = destination_wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows destination name is too long",
            )
        })?;
    // `FileNameLength` excludes the terminator, but the kernel's
    // FileRenameInformation parser requires one to be present in the buffer.
    // Supplying only the counted UTF-16 units is rejected by Windows with
    // ERROR_INVALID_PARAMETER.
    destination_wide.push(0);
    // `FILE_RENAME_INFO` is variable-length. Its Rust `size_of` includes
    // trailing alignment padding, which is not part of the record passed to
    // Windows; supply the fixed header, the counted name, and its NUL.
    let total_bytes = std::mem::offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(name_bytes as usize)
        .and_then(|length| length.checked_add(std::mem::size_of::<u16>()))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows rename buffer is too large",
            )
        })?;
    let word_bytes = std::mem::size_of::<usize>();
    let mut storage = vec![0usize; total_bytes.div_ceil(word_bytes)];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `storage` is pointer-aligned and large enough for the fixed
    // header plus the UTF-16 destination bytes and terminator. The parent and
    // source handles remain live for the subsequent rename call.
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace_existing;
        (*info).RootDirectory = parent.as_raw_handle();
        (*info).FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(
            destination_wide.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            destination_wide.len(),
        );
    }
    // SAFETY: the source handle was opened with DELETE access, and `info`
    // points to a live, correctly sized FILE_RENAME_INFO whose relative name
    // is resolved under the retained parent handle.
    let renamed = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            total_bytes as u32,
        )
    };
    if renamed != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn remove_open_file_on_windows(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the file handle remains live for the call and was opened with
    // DELETE access. `disposition` has the exact layout and size required by
    // FileDispositionInfo. Deletion is bound to this handle, so swapping any
    // parent path after preparation cannot redirect it to another file.
    let removed = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            std::ptr::from_ref(&disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if removed != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(crate) fn remove_file_nofollow(path: &Path) -> Result<()> {
    prepare_file_removal(path)?.commit()
}

#[cfg(unix)]
fn link_unlink_noreplace(
    source_parent: &std::fs::File,
    source_name: &std::ffi::CStr,
    destination_parent: &std::fs::File,
    destination_name: &std::ffi::CStr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    // SAFETY: all descriptors and component strings remain live. linkat
    // atomically fails when the destination already exists.
    let linked = unsafe {
        libc::linkat(
            source_parent.as_raw_fd(),
            source_name.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            0,
        )
    };
    if linked != 0 {
        return Err(std::io::Error::last_os_error());
    }
    destination_parent.sync_all()?;
    // SAFETY: the retained source parent and component remain live.
    let unlinked = unsafe { libc::unlinkat(source_parent.as_raw_fd(), source_name.as_ptr(), 0) };
    if unlinked != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn rename_file_nofollow(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        let Some((held_source, _, expected_identity)) = read_file_nofollow_with_identity(
            source,
            false,
            false,
            Some(MAX_WORKSPACE_CONFIG_FILE_BYTES),
        )?
        else {
            anyhow::bail!("rename source disappeared: {}", source.display());
        };
        let (source_parent, source_name) = open_parent_directory_nofollow(source)?;
        let (destination_parent, destination_name) = open_parent_directory_nofollow(destination)?;
        let source_name_c = path_component_cstring(&source_name)?;
        let destination_name_c = path_component_cstring(&destination_name)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the retained parent descriptor and component string remain
        // live; AT_SYMLINK_NOFOLLOW makes this an entry-kind proof.
        let stated = unsafe {
            libc::fstatat(
                source_parent.as_raw_fd(),
                source_name_c.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stated != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("stating rename source {}", source.display()));
        }
        // SAFETY: fstatat initialized the record on success.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            anyhow::bail!(
                "refusing to rename non-regular config file {}",
                source.display()
            );
        }
        let entry_identity = super::TerminalIngressFileIdentity {
            // `dev_t` is u64 on Linux but i32 on Darwin, so widen explicitly.
            // This matches what `MetadataExt::dev()` does internally, keeping
            // both sides of the identity comparison byte-identical.
            volume: stat.st_dev as u64,
            file: stat.st_ino as u64,
            // `u64::from` first: Darwin `nlink_t` is u16, which would make a
            // direct `try_into` an infallible conversion there and trip
            // clippy::unnecessary_fallible_conversions under -D warnings.
            links: u32::try_from(u64::from(stat.st_nlink)).unwrap_or(u32::MAX),
        };
        if entry_identity != expected_identity {
            anyhow::bail!(
                "rename source identity changed after its parent was retained: {}",
                source.display()
            );
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // SAFETY: both retained directory descriptors and component
            // strings remain live. RENAME_NOREPLACE makes destination
            // existence an atomic conflict rather than overwriting it.
            let renamed = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    source_parent.as_raw_fd(),
                    source_name_c.as_ptr(),
                    destination_parent.as_raw_fd(),
                    destination_name_c.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if renamed != 0 {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.raw_os_error(),
                    Some(code) if code == libc::ENOSYS || code == libc::EINVAL
                ) {
                    link_unlink_noreplace(
                        &source_parent,
                        &source_name_c,
                        &destination_parent,
                        &destination_name_c,
                    )
                    .with_context(|| {
                        format!(
                            "linking without replacement {} to {} after renameat2 was unavailable",
                            source.display(),
                            destination.display()
                        )
                    })?;
                } else {
                    return Err(error).with_context(|| {
                        format!(
                            "renaming without replacement {} to {}",
                            source.display(),
                            destination.display()
                        )
                    });
                }
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            // Portable retained-directory fallback: linkat publishes the
            // destination only when absent, then unlinkat removes the source.
            // If unlink fails both names safely reference the same inode and
            // recovery reports a conflict instead of losing either file.
            link_unlink_noreplace(
                &source_parent,
                &source_name_c,
                &destination_parent,
                &destination_name_c,
            )
            .with_context(|| {
                format!(
                    "linking without replacement {} to {}",
                    source.display(),
                    destination.display()
                )
            })?;
        }
        source_parent.sync_all()?;
        destination_parent.sync_all()?;
        let Some((destination_file, _, actual_identity)) = read_file_nofollow_with_identity(
            destination,
            false,
            false,
            Some(MAX_WORKSPACE_CONFIG_FILE_BYTES),
        )?
        else {
            anyhow::bail!(
                "rename destination disappeared before identity verification: {}",
                destination.display()
            );
        };
        if actual_identity != expected_identity {
            anyhow::bail!(
                "rename namespace changed during no-replace move from {} to {}; durable caller recovery must reconcile both names",
                source.display(),
                destination.display()
            );
        }
        // Keep both handles alive through the post-move identity proof. This
        // binds the accepted destination to the exact regular file validated
        // before any namespace operation.
        drop(destination_file);
        drop(held_source);
        Ok(())
    }
    #[cfg(windows)]
    {
        let (source_parent, source_name) = open_windows_parent_directory_nofollow(source, false)?;
        let source_file = open_windows_child_nofollow(&source_parent, &source_name, false, true)
            .with_context(|| format!("opening rename source {}", source.display()))?;
        reject_windows_reparse_handle(&source_file, source)?;
        let (destination_parent, destination_name) =
            open_windows_parent_directory_for_rename_nofollow(destination, false)?;
        rename_open_file_on_windows(&source_file, &destination_parent, &destination_name, false)
            .with_context(|| {
                format!("renaming {} to {}", source.display(), destination.display())
            })?;
        source_parent.sync_all()?;
        destination_parent.sync_all()?;
        Ok(())
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = (source, destination);
        anyhow::bail!("identity-bound config rename is unsupported on this platform")
    }
}

pub(crate) fn same_file_identity_nofollow(left: &Path, right: &Path) -> Result<bool> {
    let Some((_, _, left_identity)) = read_file_nofollow_with_identity(
        left,
        false,
        false,
        Some(MAX_WORKSPACE_CONFIG_FILE_BYTES),
    )?
    else {
        return Ok(false);
    };
    let Some((_, _, right_identity)) = read_file_nofollow_with_identity(
        right,
        false,
        false,
        Some(MAX_WORKSPACE_CONFIG_FILE_BYTES),
    )?
    else {
        return Ok(false);
    };
    Ok(left_identity == right_identity)
}

/// Replace one trusted config leaf atomically.
///
/// Higher-level configuration sagas use this only to restore bytes they
/// captured under their publication authority after a later participant
/// failed. It is not a general uncoordinated file-write escape hatch.
pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    prepare_atomic_write(path, contents)?.commit()
}

pub(crate) fn prepare_atomic_write(path: &Path, contents: &[u8]) -> Result<PreparedAtomicWrite> {
    ensure_config_parent_dir(path)?;
    prepare_atomic_write_in_existing_parent(path, contents)
}

fn prepare_atomic_write_in_existing_parent(
    path: &Path,
    contents: &[u8],
) -> Result<PreparedAtomicWrite> {
    #[cfg(any(unix, windows))]
    {
        #[cfg(unix)]
        let (parent_dir, destination_name) = open_parent_directory_nofollow(path)?;
        #[cfg(windows)]
        let (parent_dir, destination_name) =
            open_windows_parent_directory_for_rename_nofollow(path, false)?;
        return prepare_atomic_write_from_retained_directory(
            parent_dir,
            &destination_name,
            path,
            contents,
        );
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config.json");
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let tmp_name =
            std::ffi::OsString::from(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
        let tmp_path = parent.join(&tmp_name);
        let mut tmp = open_private_atomic_temp(&tmp_path)?;
        std::io::Write::write_all(&mut tmp, contents)
            .with_context(|| format!("writing temporary file {}", tmp_path.display()))?;
        tmp.sync_all()
            .with_context(|| format!("syncing temporary file {}", tmp_path.display()))?;
        drop(tmp);
        Ok(PreparedAtomicWrite {
            tmp_path: Some(tmp_path),
            path: path.to_path_buf(),
            parent: parent.to_path_buf(),
        })
    }
}

/// Prepare an atomic replacement directly under an already-open directory.
///
/// The returned writer retains that directory handle through publication, so
/// a rename/reparse-point replacement of the directory's original pathname
/// cannot redirect the write. `display_path` is used only in diagnostics and
/// must never be reopened by this helper.
#[cfg(any(unix, windows))]
pub(crate) fn prepare_atomic_write_from_retained_directory(
    parent_dir: std::fs::File,
    destination_name: &std::ffi::OsStr,
    display_path: &Path,
    contents: &[u8],
) -> Result<PreparedAtomicWrite> {
    validate_single_leaf(destination_name)?;
    let parent = display_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = destination_name.to_str().unwrap_or("config.json");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let tmp_name =
        std::ffi::OsString::from(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let tmp_path = parent.join(&tmp_name);
    #[cfg(unix)]
    let mut tmp = open_private_atomic_temp_at(&parent_dir, &tmp_name, &tmp_path)?;
    #[cfg(windows)]
    let mut tmp = open_windows_private_atomic_temp(&parent_dir, &tmp_name, &tmp_path)?;
    std::io::Write::write_all(&mut tmp, contents)
        .with_context(|| format!("writing temporary file {}", tmp_path.display()))?;
    tmp.sync_all()
        .with_context(|| format!("syncing temporary file {}", tmp_path.display()))?;
    #[cfg(not(windows))]
    drop(tmp);
    Ok(PreparedAtomicWrite {
        parent: parent.to_path_buf(),
        parent_dir,
        #[cfg(unix)]
        tmp_name: Some(tmp_name),
        #[cfg(windows)]
        tmp_file: Some(tmp),
        destination_name: destination_name.to_os_string(),
    })
}

/// Atomically replace one leaf under a retained directory.  This is the
/// capability-relative mutation primitive used by attached-session config
/// transactions; it never resolves the original directory path again.
#[cfg(any(unix, windows))]
pub(crate) fn atomic_write_leaf_from_retained_directory(
    directory: &std::fs::File,
    leaf: &std::ffi::OsStr,
    display_path: &Path,
    contents: &[u8],
) -> Result<()> {
    prepare_atomic_write_from_retained_directory(
        directory.try_clone()?,
        leaf,
        display_path,
        contents,
    )?
    .commit()
}

/// Prove a retained directory accepts a private create/remove cycle without
/// reopening its pathname. The probe leaf is opened with exclusive creation,
/// so it can never replace an attacker-controlled existing file merely to
/// answer a writability question.
#[cfg(any(unix, windows))]
pub(crate) fn probe_directory_writable_from_retained_directory(
    directory: &std::fs::File,
    display_parent: &Path,
) -> Result<()> {
    use std::io::Write as _;

    for attempt in 0..3u8 {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let leaf = std::ffi::OsString::from(format!(
            ".cockpit-write-probe-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        let display = display_parent.join(&leaf);
        #[cfg(unix)]
        let created = open_private_atomic_temp_at(directory, &leaf, &display);
        #[cfg(windows)]
        let created = open_windows_private_atomic_temp(directory, &leaf, &display);
        let mut probe = match created {
            Ok(file) => file,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|source| source.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                continue;
            }
            Err(error) => return Err(error).with_context(|| format!("creating {display:?}")),
        };
        probe.write_all(b"probe")?;
        probe.sync_all()?;
        drop(probe);
        remove_leaf_from_retained_directory(directory, &leaf, &display)?;
        return Ok(());
    }
    anyhow::bail!("could not allocate a private retained-directory writability probe")
}

/// Probe an existing regular leaf for write permission without replacing it.
///
/// Directory writability is not enough: an atomic rename can still replace a
/// `0400` config file when its parent is writable. A missing leaf is allowed
/// so first-time creation can proceed after the directory probe.
pub(crate) fn probe_existing_leaf_writable_from_retained_directory(
    directory: &std::fs::File,
    leaf: &std::ffi::OsStr,
    display_path: &Path,
) -> Result<()> {
    validate_single_leaf(leaf)?;
    #[cfg(unix)]
    {
        match open_file_at_nofollow(
            directory,
            leaf,
            libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        ) {
            Ok(_) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(error) => Err(error)
                .with_context(|| format!("probing writability of {}", display_path.display())),
        }
    }
    #[cfg(not(unix))]
    {
        match std::fs::OpenOptions::new().write(true).open(display_path) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error)
                .with_context(|| format!("probing writability of {}", display_path.display())),
        }
    }
}

/// Remove one optional regular leaf relative to a retained directory.
///
/// As with [`atomic_write_leaf_from_retained_directory`], the directory
/// capability is retained across the namespace operation.  A missing leaf is
/// already absent, while every other failure remains observable to the
/// journal caller.
#[cfg(any(unix, windows))]
pub(crate) fn remove_leaf_from_retained_directory(
    directory: &std::fs::File,
    leaf: &std::ffi::OsStr,
    display_path: &Path,
) -> Result<()> {
    validate_single_leaf(leaf)?;
    #[cfg(unix)]
    {
        match unlink_file_at(directory, leaf) {
            Ok(()) => directory.sync_all().with_context(|| {
                format!(
                    "fsync config directory after removing {}",
                    display_path.display()
                )
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("removing {}", display_path.display()))
            }
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
        use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_READ_ATTRIBUTES, SYNCHRONIZE};
        let file = match open_windows_relative_nofollow(
            directory,
            leaf,
            false,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("opening {} for removal", display_path.display()));
            }
        };
        reject_windows_reparse_handle(&file, display_path)?;
        remove_open_file_on_windows(&file)
            .with_context(|| format!("removing {}", display_path.display()))?;
        // Windows has no directory fsync primitive; this mirrors the audited
        // pathname writer's post-rename best-effort sync.
        let _ = directory.sync_all();
        Ok(())
    }
}

/// List stale private atomic-write temporaries through an already-open
/// directory.  Cleanup is deliberately capability-relative for the same
/// reason as journal removal: after a config parent has been captured, a
/// pathname replacement must not redirect crash-debris deletion elsewhere.
///
/// Both supported platforms enumerate from the retained directory handle;
/// Windows uses its existing `GetFileInformationByHandleEx` implementation
/// rather than reopening the original directory spelling.
#[cfg(unix)]
pub(crate) fn stale_private_temp_leaves_from_retained_directory(
    directory: &std::fs::File,
    stale_after: std::time::Duration,
) -> Result<Vec<std::ffi::OsString>> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut leaves = Vec::new();
    for leaf in retained_directory_names(directory)? {
        let bytes = leaf.as_bytes();
        if bytes == b"." || bytes == b".." || !bytes.starts_with(b".") || !bytes.ends_with(b".tmp")
        {
            continue;
        }
        let name = path_component_cstring(&leaf)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the retained directory fd, name, and output storage remain
        // live; AT_SYMLINK_NOFOLLOW rejects a planted symlink.
        let stated = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stated != 0 {
            continue;
        }
        // SAFETY: fstatat initialized `stat` on success.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_mode & 0o777 != 0o600
            || stat.st_mtime < 0
            || now.saturating_sub(stat.st_mtime as u64) < stale_after.as_secs()
        {
            continue;
        }
        leaves.push(leaf);
    }
    Ok(leaves)
}

#[cfg(windows)]
pub(crate) fn stale_private_temp_leaves_from_retained_directory(
    directory: &std::fs::File,
    stale_after: std::time::Duration,
) -> Result<Vec<std::ffi::OsString>> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
    use windows_sys::Win32::Storage::FileSystem::{FILE_READ_ATTRIBUTES, SYNCHRONIZE};

    let mut leaves = Vec::new();
    for leaf in retained_directory_names(directory)? {
        let display = Path::new(&leaf);
        let display_name = display.to_string_lossy();
        if !display_name.starts_with('.') || !display_name.ends_with(".tmp") {
            continue;
        }
        let file = match open_windows_relative_nofollow(
            directory,
            &leaf,
            false,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("opening retained temporary for cleanup"),
        };
        if reject_windows_reparse_handle(&file, display).is_err()
            || verify_windows_protected_dacl(&file).is_err()
        {
            continue;
        }
        let Ok(metadata) = file.metadata() else {
            continue;
        };
        if !metadata.is_file()
            || !metadata
                .modified()
                .ok()
                .and_then(|modified| std::time::SystemTime::now().duration_since(modified).ok())
                .is_some_and(|age| age >= stale_after)
        {
            continue;
        }
        leaves.push(leaf);
    }
    Ok(leaves)
}

#[cfg(all(not(unix), not(windows)))]
pub(crate) fn stale_private_temp_leaves_from_retained_directory(
    _directory: &std::fs::File,
    _stale_after: std::time::Duration,
) -> Result<Vec<std::ffi::OsString>> {
    Ok(Vec::new())
}

#[cfg(windows)]
fn open_windows_private_atomic_temp(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    display_path: &Path,
) -> Result<std::fs::File> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_CREATE;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, SYNCHRONIZE,
        WRITE_DAC,
    };

    let file = open_windows_relative_nofollow(
        parent,
        name,
        false,
        DELETE
            | FILE_WRITE_DATA
            | FILE_WRITE_ATTRIBUTES
            | FILE_READ_ATTRIBUTES
            | SYNCHRONIZE
            | WRITE_DAC,
        FILE_CREATE,
    )
    .with_context(|| format!("creating temporary file {}", display_path.display()))?;
    reject_windows_reparse_handle(&file, display_path)?;
    protect_windows_dacl(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn protect_windows_dacl(file: &std::fs::File) -> Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetKernelObjectSecurity, PROTECTED_DACL_SECURITY_INFORMATION,
        SetKernelObjectSecurity,
    };
    let mut needed = 0u32;
    // First call obtains the exact self-relative descriptor size.
    unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle(),
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut descriptor = vec![0u8; needed as usize];
    if unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle(),
            DACL_SECURITY_INFORMATION,
            descriptor.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe {
        SetKernelObjectSecurity(
            file.as_raw_handle(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.as_mut_ptr().cast(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn open_private_atomic_temp_at(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    display_path: &Path,
) -> Result<std::fs::File> {
    let file = open_file_at_nofollow(
        parent,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .with_context(|| format!("creating temporary file {}", display_path.display()))?;
    chmod_file_private(&file).with_context(|| format!("chmod 0600 {}", display_path.display()))?;
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn open_private_atomic_temp(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("creating temporary file {}", path.display()))
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::symlink;

    #[test]
    fn modes_session_setup_retained_workspace_snapshot_ignores_unrelated_effective_default_artifacts()
     {
        let temp = tempfile::tempdir().unwrap();
        let cockpit = temp.path().join(".cockpit");
        std::fs::create_dir(&cockpit).unwrap();
        let config = cockpit.join("config.json");
        std::fs::write(&config, "{}\n").unwrap();
        std::fs::write(
            cockpit.join(".cockpit-active-model-journal-interrupted.json"),
            "{\"phase\":\"prepared\"}",
        )
        .unwrap();

        let canonical_config = std::fs::canonicalize(&config).unwrap();
        let journal = crate::config::effective_default::journal_path_for_layer(&canonical_config);
        let backup = crate::config::effective_default::backup_path_for_layer(&canonical_config);
        let retained = std::fs::File::open(&cockpit).unwrap();
        let snapshot = super::snapshot_workspace_config_layer_from_retained_config_directory(
            &retained,
            std::ffi::OsStr::new("config.json"),
            &canonical_config,
            journal.file_name(),
            backup.file_name(),
        )
        .expect("an unrelated transaction artifact does not alter selected-leaf capture");
        assert_eq!(snapshot.config_json.as_deref(), Some(&b"{}\n"[..]));
    }

    #[test]
    fn relative_explicit_config_in_current_directory_needs_no_parent_creation() {
        super::ensure_parent_dir_exists_private_if_created(std::path::Path::new("config.json"))
            .expect("an empty relative parent denotes the current directory");
    }

    #[test]
    fn atomic_write_rejects_symlinked_parent_component() {
        let temp = tempfile::tempdir().unwrap();
        let attacker = temp.path().join("attacker");
        std::fs::create_dir(&attacker).unwrap();
        let link = temp.path().join("config-parent");
        symlink(&attacker, &link).unwrap();

        let target = link.join("config.json");
        let error = super::atomic_write(&target, b"secret").unwrap_err();

        assert!(
            format!("{error:#}").contains("no-follow directory component"),
            "{error:#}"
        );
        assert!(
            !attacker.join("config.json").exists(),
            "a symlinked shared parent must never receive the config"
        );
    }

    #[test]
    fn prepared_atomic_write_stays_bound_to_open_parent_across_symlink_swap() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("config-parent");
        let relocated = temp.path().join("relocated-parent");
        let attacker = temp.path().join("attacker");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&attacker).unwrap();
        let target = parent.join("config.json");

        let prepared = super::prepare_atomic_write(&target, b"authoritative").unwrap();
        std::fs::rename(&parent, &relocated).unwrap();
        symlink(&attacker, &parent).unwrap();
        prepared.commit().unwrap();

        assert_eq!(
            std::fs::read(relocated.join("config.json")).unwrap(),
            b"authoritative"
        );
        assert!(
            !attacker.join("config.json").exists(),
            "rename must use the retained parent fd, not the swapped path"
        );
    }

    #[test]
    fn private_file_is_owner_only_and_refuses_a_symlinked_parent() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let backup = temp.path().join(".cockpit-active-model.backup");
        super::write_private_file(&backup, b"prior config bytes").unwrap();
        assert_eq!(std::fs::read(&backup).unwrap(), b"prior config bytes");
        assert_eq!(
            std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600,
            "the rollback snapshot must stay owner-only"
        );

        let attacker = temp.path().join("attacker");
        std::fs::create_dir(&attacker).unwrap();
        let link = temp.path().join("linked-config-dir");
        symlink(&attacker, &link).unwrap();
        let error =
            super::write_private_file(&link.join(".cockpit-active-model.backup"), b"secret")
                .unwrap_err();
        assert!(
            format!("{error:#}").contains("no-follow directory component"),
            "{error:#}"
        );
        assert!(!attacker.join(".cockpit-active-model.backup").exists());
    }

    #[test]
    fn read_file_nofollow_refuses_a_symlinked_file_and_reports_absence() {
        let temp = tempfile::tempdir().unwrap();
        assert!(
            super::read_file_nofollow(&temp.path().join("missing.json"))
                .unwrap()
                .is_none()
        );

        let outside = temp.path().join("outside.json");
        std::fs::write(&outside, b"outside").unwrap();
        let link = temp.path().join("journal.json");
        symlink(&outside, &link).unwrap();
        let error = super::read_file_nofollow(&link).unwrap_err();
        assert!(
            format!("{error:#}").contains("no-follow"),
            "a symlinked journal must fail closed, got {error:#}"
        );
    }

    #[test]
    fn prepared_file_removal_stays_bound_to_open_parent_across_symlink_swap() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("providers");
        let relocated = temp.path().join("relocated-providers");
        let attacker = temp.path().join("attacker");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&attacker).unwrap();
        std::fs::write(parent.join("provider.json"), b"owned").unwrap();
        std::fs::write(attacker.join("provider.json"), b"outside").unwrap();

        let prepared = super::prepare_file_removal(&parent.join("provider.json")).unwrap();
        std::fs::rename(&parent, &relocated).unwrap();
        symlink(&attacker, &parent).unwrap();
        prepared.commit().unwrap();

        assert!(!relocated.join("provider.json").exists());
        assert_eq!(
            std::fs::read(attacker.join("provider.json")).unwrap(),
            b"outside",
            "unlink must use the retained parent fd, not the swapped path"
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::os::windows::fs::symlink_dir;

    #[test]
    fn atomic_write_rejects_preexisting_intermediate_reparse_point() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join(".cockpit");
        let attacker = temp.path().join("attacker-providers");
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::create_dir(&attacker).unwrap();
        std::fs::write(attacker.join("provider.json"), b"outside").unwrap();
        symlink_dir(&attacker, config_dir.join("providers")).unwrap();

        let error = super::atomic_write(
            &config_dir.join("providers").join("provider.json"),
            b"secret",
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("reparse-point component"));
        assert_eq!(
            std::fs::read(attacker.join("provider.json")).unwrap(),
            b"outside",
            "a pre-existing junction must never redirect an atomic config write"
        );
    }

    #[test]
    fn prepared_atomic_write_stays_bound_to_open_parent_across_junction_swap() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("config-parent");
        let relocated = temp.path().join("relocated-parent");
        let attacker = temp.path().join("attacker");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&attacker).unwrap();
        std::fs::write(parent.join("config.json"), b"old-owned").unwrap();
        std::fs::write(attacker.join("config.json"), b"outside").unwrap();

        let prepared =
            super::prepare_atomic_write(&parent.join("config.json"), b"authoritative").unwrap();
        std::fs::rename(&parent, &relocated).unwrap();
        symlink_dir(&attacker, &parent).unwrap();
        prepared.commit().unwrap();

        assert_eq!(
            std::fs::read(relocated.join("config.json")).unwrap(),
            b"authoritative"
        );
        assert_eq!(
            std::fs::read(attacker.join("config.json")).unwrap(),
            b"outside",
            "handle-bound replacement must not follow the swapped parent path"
        );
    }

    #[test]
    fn prepared_file_removal_rejects_preexisting_intermediate_reparse_point() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join(".cockpit");
        let attacker = temp.path().join("attacker-providers");
        std::fs::create_dir(&config_dir).unwrap();
        std::fs::create_dir(&attacker).unwrap();
        std::fs::write(attacker.join("provider.json"), b"outside").unwrap();
        symlink_dir(&attacker, config_dir.join("providers")).unwrap();

        let error =
            super::prepare_file_removal(&config_dir.join("providers").join("provider.json"))
                .unwrap_err();

        assert!(format!("{error:#}").contains("reparse-point component"));
        assert_eq!(
            std::fs::read(attacker.join("provider.json")).unwrap(),
            b"outside",
            "a pre-existing junction must never redirect provider deletion"
        );
    }

    /// Windows has no owner-only ACL construction here — the file inherits
    /// its parent directory's DACL. What this asserts is what is actually
    /// guaranteed: the content lands at the intended path, and no reparse
    /// point can redirect it.
    #[test]
    fn private_file_refuses_a_reparse_point_parent_and_replaces_in_place() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join(".cockpit");
        std::fs::create_dir(&config_dir).unwrap();
        let backup = config_dir.join(".cockpit-active-model.backup");
        super::write_private_file(&backup, b"prior config bytes").unwrap();
        assert_eq!(std::fs::read(&backup).unwrap(), b"prior config bytes");

        let attacker = temp.path().join("attacker");
        std::fs::create_dir(&attacker).unwrap();
        let junction = temp.path().join("linked-config-dir");
        symlink_dir(&attacker, &junction).unwrap();
        let error =
            super::write_private_file(&junction.join(".cockpit-active-model.backup"), b"secret")
                .unwrap_err();
        assert!(format!("{error:#}").contains("reparse-point component"));
        assert!(!attacker.join(".cockpit-active-model.backup").exists());
    }

    #[test]
    fn read_file_nofollow_refuses_a_reparse_point_and_reports_absence() {
        let temp = tempfile::tempdir().unwrap();
        assert!(
            super::read_file_nofollow(&temp.path().join("missing.json"))
                .unwrap()
                .is_none()
        );

        let attacker = temp.path().join("attacker");
        std::fs::create_dir(&attacker).unwrap();
        std::fs::write(attacker.join("journal.json"), b"outside").unwrap();
        let junction = temp.path().join("linked");
        symlink_dir(&attacker, &junction).unwrap();
        let error = super::read_file_nofollow(&junction.join("journal.json")).unwrap_err();
        assert!(format!("{error:#}").contains("reparse-point component"));
    }

    #[test]
    fn prepared_file_removal_stays_bound_to_open_file_across_parent_junction_swap() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("providers");
        let relocated = temp.path().join("relocated-providers");
        let attacker = temp.path().join("attacker");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&attacker).unwrap();
        std::fs::write(parent.join("provider.json"), b"owned").unwrap();
        std::fs::write(attacker.join("provider.json"), b"outside").unwrap();

        let prepared = super::prepare_file_removal(&parent.join("provider.json")).unwrap();
        std::fs::rename(&parent, &relocated).unwrap();
        symlink_dir(&attacker, &parent).unwrap();
        prepared.commit().unwrap();

        assert!(!relocated.join("provider.json").exists());
        assert_eq!(
            std::fs::read(attacker.join("provider.json")).unwrap(),
            b"outside",
            "handle-bound deletion must not follow the swapped parent path"
        );
    }
}

#[cfg(test)]
mod mutation_lock_tests {
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn target_local_locks_do_not_serialize_independent_config_directories() {
        let temp = tempfile::tempdir().unwrap();
        let a_dir = temp.path().join("a");
        let b_dir = temp.path().join("b");
        std::fs::create_dir_all(&a_dir).unwrap();
        std::fs::create_dir_all(&b_dir).unwrap();
        let a = a_dir.join("config.json");
        let b = b_dir.join("config.json");
        let _a_guard = super::ConfigMutationLock::acquire(&a).unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _b_guard = super::ConfigMutationLock::acquire(&b).unwrap();
            ready_tx.send(()).unwrap();
        });
        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("a lock for config A must not block independent config B");
    }

    #[test]
    fn retained_and_ambient_writers_serialize_on_the_same_target_lock_leaf() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join("config");
        std::fs::create_dir_all(&config_dir).unwrap();
        let target = config_dir.join("config.json");
        let canonical = std::fs::canonicalize(&config_dir)
            .unwrap()
            .join("config.json");
        let guard = super::ConfigMutationLock::acquire(&canonical).unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let retained_dir = config_dir.clone();
        std::thread::spawn(move || {
            let directory = std::fs::File::open(&retained_dir).unwrap();
            let _retained_guard =
                super::ConfigMutationLock::acquire_retained(&directory, &canonical, &retained_dir)
                    .unwrap();
            ready_tx.send(()).unwrap();
        });
        assert!(
            ready_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "the retained writer must wait for the ambient target lock"
        );
        drop(guard);
        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the retained writer acquires once the shared target lock releases");
        assert!(
            !target.exists(),
            "locking must not create or replace the config leaf itself"
        );
    }

    #[test]
    fn bounded_lock_treats_a_missing_parent_as_uncontended_without_creating_it() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("providers");
        let target = parent.join("default.json");
        assert!(
            !parent.exists(),
            "fixture must start without the lock parent"
        );
        let guard = super::ConfigMutationLock::acquire_until(
            &target,
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .expect("missing parent must not fail the bounded lock")
        .expect("missing parent is uncontended");
        assert!(
            !parent.exists(),
            "bounded lock must not mkdir a missing parent"
        );
        assert!(
            super::ConfigMutationLock::is_held_by_current_thread(&target).unwrap(),
            "the vacuous first-write guard is held on this thread"
        );
        drop(guard);
        assert!(
            !super::ConfigMutationLock::is_held_by_current_thread(&target).unwrap(),
            "dropping the vacuous guard releases the missing-parent identity"
        );

        let _write = super::ConfigMutationLock::acquire(&target).unwrap();
        assert!(
            parent.is_dir(),
            "the creating acquire path still mkdirs the parent"
        );
    }

    #[test]
    fn bounded_lock_does_not_create_a_missing_global_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let global = crate::config::dirs::global_config_dir().unwrap();
        let target = crate::config::providers::provider_file_path_for_dir(&global, "default")
            .expect("valid provider id");
        assert!(
            !global.is_dir(),
            "fresh-install fixture must not pre-create the global layer"
        );

        let guard = super::ConfigMutationLock::acquire_until(
            &target,
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .expect("fresh-install first-write target must pass the bounded lock")
        .expect("missing global parent is uncontended");
        assert!(
            !global.is_dir(),
            "bounded lock must not create the global config directory"
        );
        drop(guard);

        crate::config::dirs::ensure_global_config_dir().unwrap();
        assert!(global.is_dir());
        assert!(
            !global.join("providers").exists(),
            "ensuring the global dir must not create providers/"
        );
        let guard = super::ConfigMutationLock::acquire_until(
            &target,
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .unwrap()
        .expect("missing providers/ under an existing global layer is uncontended");
        assert!(
            !global.join("providers").exists(),
            "bounded lock must not create providers/ as a read side-effect"
        );
        drop(guard);

        let _write = super::ConfigMutationLock::acquire(&target).unwrap();
        assert!(
            global.join("providers").is_dir(),
            "the creating acquire path still mkdirs providers/"
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }
}
