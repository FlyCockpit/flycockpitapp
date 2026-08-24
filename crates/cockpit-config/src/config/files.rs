use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

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

    if dirs::home_dir()
        .is_some_and(|home| path == home.join(".config/cockpit") || path == home.join(".cockpit"))
    {
        return true;
    }

    crate::config::resolve::cockpit_data_dir()
        .map(|data_dir| path.starts_with(data_dir.join("local-configs")))
        .unwrap_or(false)
}

/// Stable cross-process lock shared by every `config.json` mutation.
///
/// Config files are replaced atomically, so locking the destination inode
/// would not serialize the next writer. A separate state-directory lock keeps
/// the read/merge/replace sequence coherent across provider and extended
/// configuration writers, including explicit `COCKPIT_CONFIG` targets.
/// A held cross-process config mutation lock.
///
/// Deliberately `!Send`: the re-entrancy depth that lets journal recovery run
/// under an already-held lock is a *thread-local*. Moving a guard to another
/// thread would leave the acquiring thread's depth stuck above zero (recovery
/// would skip a real lock) and the receiving thread's depth below it,
/// underflowing on drop. Keeping the guard pinned to its acquiring thread
/// makes that class of corruption unrepresentable.
pub(crate) struct ConfigMutationLock {
    _file: std::fs::File,
    _not_send: std::marker::PhantomData<*const ()>,
}

thread_local! {
    /// Re-entrancy depth for the cross-process mutation lock on this thread.
    ///
    /// The OS lock is per open file description, so a second `acquire` on the
    /// same thread would deadlock against the guard this thread already holds.
    /// Journal recovery runs both standalone and inside an in-flight mutation,
    /// so it consults this depth instead of blindly re-locking.
    static MUTATION_LOCK_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

impl ConfigMutationLock {
    pub(crate) fn acquire(_target: &Path) -> Result<Self> {
        let lock_path = mutation_lock_path()?;
        ensure_parent_dir_private(&lock_path)?;

        let file = open_private_lock_file(&lock_path)?;
        file.lock()
            .with_context(|| format!("locking config mutation at {}", lock_path.display()))?;
        Ok(Self::enter(file))
    }

    pub(crate) fn acquire_cancellable(
        _target: &Path,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Self> {
        let lock_path = mutation_lock_path()?;
        ensure_parent_dir_private(&lock_path)?;

        let file = open_private_lock_file(&lock_path)?;
        loop {
            if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                anyhow::bail!("active-model config mutation was cancelled");
            }
            match file.try_lock() {
                Ok(()) => {
                    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                        anyhow::bail!("active-model config mutation was cancelled");
                    }
                    return Ok(Self::enter(file));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(error).with_context(|| {
                        format!("locking config mutation at {}", lock_path.display())
                    });
                }
            }
        }
    }

    fn enter(file: std::fs::File) -> Self {
        MUTATION_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self {
            _file: file,
            _not_send: std::marker::PhantomData,
        }
    }

    /// True while this thread already owns the cross-process mutation lock.
    pub(crate) fn is_held_by_current_thread() -> bool {
        MUTATION_LOCK_DEPTH.with(std::cell::Cell::get) > 0
    }
}

impl Drop for ConfigMutationLock {
    fn drop(&mut self) {
        MUTATION_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

fn mutation_lock_path() -> Result<PathBuf> {
    Ok(crate::config::resolve::cockpit_state_dir()?
        .join("config-locks")
        .join("effective-config.lock"))
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

pub(crate) fn read_file_nofollow_with_identity(
    path: &Path,
    writable: bool,
    enforce_private: bool,
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
    let file = open_file_at_nofollow(
        &parent,
        &file_name,
        access | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
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
        open_windows_relative_nofollow(&parent, &file_name, false, access, FILE_OPEN)?
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
    let bytes = read_all(&mut file, path)?;
    Ok(Some((file, bytes, identity)))
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

#[cfg(any(unix, windows))]
fn read_all(mut file: impl std::io::Read, path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(bytes)
}

#[cfg(any(unix, windows))]
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
fn open_private_lock_file(path: &Path) -> Result<std::fs::File> {
    let (parent, file_name) = open_parent_directory_nofollow(path)?;
    let file = open_file_at_nofollow(
        &parent,
        &file_name,
        libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .with_context(|| format!("opening config mutation lock {}", path.display()))?;
    chmod_file_private(&file).with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok(file)
}

#[cfg(windows)]
fn open_private_lock_file(path: &Path) -> Result<std::fs::File> {
    use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN_IF;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, SYNCHRONIZE,
    };

    let (parent, name) = open_windows_parent_directory_nofollow(path, false)?;
    let file = open_windows_relative_nofollow(
        &parent,
        &name,
        false,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN_IF,
    )
    .with_context(|| format!("opening config mutation lock {}", path.display()))?;
    reject_windows_reparse_handle(&file, path)?;
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn open_private_lock_file(path: &Path) -> Result<std::fs::File> {
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

pub(crate) fn rename_file_nofollow(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
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
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "renaming without replacement {} to {}",
                        source.display(),
                        destination.display()
                    )
                });
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            // Portable retained-directory fallback: linkat publishes the
            // destination only when absent, then unlinkat removes the source.
            // If unlink fails both names safely reference the same inode and
            // recovery reports a conflict instead of losing either file.
            // SAFETY: all descriptors and component strings remain live.
            let linked = unsafe {
                libc::linkat(
                    source_parent.as_raw_fd(),
                    source_name_c.as_ptr(),
                    destination_parent.as_raw_fd(),
                    destination_name_c.as_ptr(),
                    0,
                )
            };
            if linked != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "linking without replacement {} to {}",
                        source.display(),
                        destination.display()
                    )
                });
            }
            destination_parent.sync_all()?;
            // SAFETY: the retained source parent and component remain live.
            let unlinked =
                unsafe { libc::unlinkat(source_parent.as_raw_fd(), source_name_c.as_ptr(), 0) };
            if unlinked != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!("removing linked rename source {}", source.display())
                });
            }
        }
        source_parent.sync_all()?;
        destination_parent.sync_all()?;
        return Ok(());
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
        return Ok(());
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = (source, destination);
        anyhow::bail!("identity-bound config rename is unsupported on this platform")
    }
}

pub(crate) fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
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
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.json");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    #[cfg(unix)]
    let (parent_dir, destination_name) = open_parent_directory_nofollow(path)?;
    #[cfg(windows)]
    let (parent_dir, destination_name) =
        open_windows_parent_directory_for_rename_nofollow(path, false)?;
    #[cfg(any(unix, windows))]
    let tmp_name =
        std::ffi::OsString::from(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    #[cfg(all(not(unix), not(windows)))]
    let tmp_name =
        std::ffi::OsString::from(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let tmp_path = parent.join(&tmp_name);
    #[cfg(unix)]
    let mut tmp = open_private_atomic_temp_at(&parent_dir, &tmp_name, &tmp_path)?;
    #[cfg(windows)]
    let mut tmp = open_windows_private_atomic_temp(&parent_dir, &tmp_name, &tmp_path)?;
    #[cfg(all(not(unix), not(windows)))]
    let mut tmp = open_private_atomic_temp(&tmp_path)?;
    std::io::Write::write_all(&mut tmp, contents)
        .with_context(|| format!("writing temporary file {}", tmp_path.display()))?;
    tmp.sync_all()
        .with_context(|| format!("syncing temporary file {}", tmp_path.display()))?;
    #[cfg(not(windows))]
    drop(tmp);
    Ok(PreparedAtomicWrite {
        #[cfg(all(not(unix), not(windows)))]
        tmp_path: Some(tmp_path),
        #[cfg(all(not(unix), not(windows)))]
        path: path.to_path_buf(),
        parent: parent.to_path_buf(),
        #[cfg(any(unix, windows))]
        parent_dir,
        #[cfg(unix)]
        tmp_name: Some(tmp_name),
        #[cfg(windows)]
        tmp_file: Some(tmp),
        #[cfg(any(unix, windows))]
        destination_name,
    })
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
