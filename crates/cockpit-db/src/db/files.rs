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
    let path = if let Ok(s) = std::env::var("XDG_DATA_HOME")
        && !s.trim().is_empty()
    {
        PathBuf::from(s).join("cockpit")
    } else {
        let base = dirs::data_dir().context("could not locate user data dir")?;
        base.join("cockpit")
    };
    #[cfg(any(test, feature = "test-support"))]
    {
        use cockpit_test_support::home_isolation::{CockpitHomeKind, finalize_test_cockpit_path};
        return Ok(finalize_test_cockpit_path(path, CockpitHomeKind::Data));
    }
    #[cfg(not(any(test, feature = "test-support")))]
    Ok(path)
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
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    {
        let _umask = UmaskGuard::set(0o077);
        std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    }
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening private directory {}", path.display()))?;
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspecting private directory {}", path.display()))?;
    let effective_uid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.is_dir() && metadata.uid() == effective_uid,
        "refusing to use {}: expected a current-user-owned non-symlink directory",
        path.display()
    );
    directory
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 held directory {}", path.display()))?;
    let mode = directory
        .metadata()
        .with_context(|| format!("rechecking private directory {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    anyhow::ensure!(
        mode == 0o700,
        "refusing to use {}: expected private directory mode 0700, got {mode:03o}",
        path.display()
    );
    Ok(())
}

#[cfg(windows)]
pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const DIRECTORY_SECURITY_ACCESS: u32 = 0x0002_0000 | 0x0004_0000 | 0x0010_0000 | 0x0000_0080;

    reject_windows_reparse_components(path)?;
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    reject_windows_reparse_components(path)?;
    // Excluding FILE_SHARE_DELETE makes this held handle a rename/delete lease
    // while the descriptor is inspected and repaired. Long-lived callers that
    // need the lease retain their own handle after this preflight.
    let directory = std::fs::OpenOptions::new()
        .read(true)
        // READ_CONTROL | WRITE_DAC | SYNCHRONIZE | FILE_READ_ATTRIBUTES.
        .access_mode(DIRECTORY_SECURITY_ACCESS)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("opening private directory {}", path.display()))?;
    let metadata = directory
        .metadata()
        .with_context(|| format!("inspecting private directory {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "refusing to use {}: expected a non-reparse directory",
        path.display()
    );
    set_private_windows_dacl_handle(&directory)
        .with_context(|| format!("securing private directory {}", path.display()))?;
    verify_private_windows_dacl_handle(&directory)
        .with_context(|| format!("verifying private directory {}", path.display()))
}

#[cfg(windows)]
fn reject_windows_reparse_components(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let mut traversed = PathBuf::new();
    for component in path.components() {
        traversed.push(component.as_os_str());
        match std::fs::symlink_metadata(&traversed) {
            Ok(metadata) => anyhow::ensure!(
                metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                "refusing private database path with reparse component {}",
                traversed.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspecting database path component {}", traversed.display())
                });
            }
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
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

#[cfg(windows)]
pub(crate) fn repair_private_file(path: &Path, label: &str) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SECURITY_ACCESS: u32 = 0xC000_0000 | 0x0002_0000 | 0x0004_0000;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(FILE_SECURITY_ACCESS)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("opening {label} file {}", path.display()))?;
    set_private_windows_dacl_handle(&file)
        .with_context(|| format!("securing {label} file {}", path.display()))?;
    verify_private_windows_dacl_handle(&file)
        .with_context(|| format!("verifying {label} file {}", path.display()))
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn repair_private_file(_path: &Path, _label: &str) -> Result<()> {
    Ok(())
}

/// Apply a protected current-user-and-SYSTEM-only full-control DACL to an
/// already-open Windows filesystem object, then verify the descriptor through
/// that same handle. Path-based ACL inspection is deliberately insufficient:
/// a reparse or rename race must not redirect the security decision.
#[cfg(windows)]
pub(crate) fn set_private_windows_dacl_handle(file: &std::fs::File) -> Result<()> {
    use std::os::windows::io::AsRawHandle as _;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            value: *const u16,
            revision: u32,
            descriptor: *mut *mut core::ffi::c_void,
            length: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorOwner(
            descriptor: *mut core::ffi::c_void,
            owner: *mut *mut core::ffi::c_void,
            defaulted: *mut i32,
        ) -> i32;
        fn GetSecurityDescriptorDacl(
            descriptor: *mut core::ffi::c_void,
            present: *mut i32,
            dacl: *mut *mut core::ffi::c_void,
            defaulted: *mut i32,
        ) -> i32;
        fn SetSecurityInfo(
            handle: *mut core::ffi::c_void,
            object_type: u32,
            information: u32,
            owner: *mut core::ffi::c_void,
            group: *mut core::ffi::c_void,
            dacl: *mut core::ffi::c_void,
            sacl: *mut core::ffi::c_void,
        ) -> u32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    const SE_FILE_OBJECT: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 4;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

    let sid = current_windows_user_sid()?;
    let sddl = format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)");
    let wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    anyhow::ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } != 0,
        "building private database DACL failed"
    );
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut ignored = 0;
    let valid = unsafe {
        GetSecurityDescriptorOwner(descriptor, &mut owner, &mut ignored) != 0
            && GetSecurityDescriptorDacl(descriptor, &mut ignored, &mut dacl, &mut ignored) != 0
    };
    if !valid || owner.is_null() || dacl.is_null() {
        unsafe { LocalFree(descriptor) };
        anyhow::bail!("extracting private database DACL failed");
    }
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    unsafe { LocalFree(descriptor) };
    anyhow::ensure!(
        result == 0,
        "setting private database DACL failed ({result})"
    );
    verify_private_windows_dacl_handle(file)
}

#[cfg(windows)]
pub(crate) fn verify_private_windows_dacl_handle(file: &std::fs::File) -> Result<()> {
    use std::os::windows::io::AsRawHandle as _;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetSecurityInfo(
            handle: *mut core::ffi::c_void,
            object_type: u32,
            information: u32,
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
    let mut descriptor = std::ptr::null_mut();
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            information,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    anyhow::ensure!(
        result == 0 && !descriptor.is_null(),
        "reading database object security descriptor failed ({result})"
    );
    let mut sddl = std::ptr::null_mut();
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
    anyhow::ensure!(
        converted != 0 && !sddl.is_null(),
        "converting database object security descriptor failed"
    );
    let value = String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(sddl, usize::try_from(length).unwrap_or(0))
    });
    unsafe { LocalFree(sddl.cast()) };
    validate_private_windows_sddl(&value)
}

#[cfg(windows)]
fn validate_private_windows_sddl(sddl: &str) -> Result<()> {
    let owner = sddl
        .strip_prefix("O:")
        .and_then(|value| value.split_once("D:"))
        .map(|(owner, _)| owner);
    let ace_sids = sddl
        .split(";;FA;;;")
        .skip(1)
        .filter_map(|value| value.split(')').next())
        .collect::<Vec<_>>();
    let current_user = current_windows_user_sid()?;
    anyhow::ensure!(
        sddl.contains("D:P")
            && sddl.matches('(').count() == 2
            && sddl.matches("(A;").count() == 2
            && owner == Some(current_user.as_str())
            && ace_sids.contains(&current_user.as_str())
            && ace_sids
                .iter()
                .any(|sid| *sid == "SY" || *sid == "S-1-5-18"),
        "database object DACL is not protected current-user-and-SYSTEM-only full control"
    );
    Ok(())
}

#[cfg(windows)]
fn current_windows_user_sid() -> Result<String> {
    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut core::ffi::c_void,
        attributes: u32,
    }
    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(
            process_handle: *mut core::ffi::c_void,
            desired_access: u32,
            token_handle: *mut *mut core::ffi::c_void,
        ) -> i32;
        fn GetTokenInformation(
            token_handle: *mut core::ffi::c_void,
            token_information_class: u32,
            token_information: *mut core::ffi::c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *mut core::ffi::c_void, string_sid: *mut *mut u16) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
        fn LocalFree(memory: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    let mut token = std::ptr::null_mut();
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error()).context("opening process token");
        }
        let mut needed = 0_u32;
        GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 {
            CloseHandle(token);
            return Err(std::io::Error::last_os_error()).context("reading process SID size");
        }
        let mut buffer = vec![0_u8; usize::try_from(needed)?];
        if GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            CloseHandle(token);
            return Err(std::io::Error::last_os_error()).context("reading process SID");
        }
        let token_user = &*buffer.as_ptr().cast::<TokenUser>();
        let mut sid_text = std::ptr::null_mut();
        if ConvertSidToStringSidW(token_user.user.sid, &mut sid_text) == 0 {
            CloseHandle(token);
            return Err(std::io::Error::last_os_error()).context("formatting process SID");
        }
        let mut length = 0_usize;
        while *sid_text.add(length) != 0 {
            length += 1;
        }
        let result = String::from_utf16_lossy(std::slice::from_raw_parts(sid_text, length));
        LocalFree(sid_text.cast());
        CloseHandle(token);
        Ok(result)
    }
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

    let names: Vec<&std::ffi::OsStr> = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name),
            _ => anyhow::bail!("sidecar cleanup path must be relative and normalized"),
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(!names.is_empty(), "sidecar cleanup path is empty");
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(base)
        .with_context(|| format!("opening sidecar cleanup base {}", base.display()))?;
    let mut durable_parent = base.to_path_buf();
    for name in &names[..names.len() - 1] {
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
    let name = names.last().expect("nonempty validated path");
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

#[cfg(all(test, windows))]
mod windows_acl_tests {
    use super::*;

    #[test]
    fn database_private_dacl_policy_rejects_extra_and_inherited_access() {
        let sid = current_windows_user_sid().unwrap();
        let private = format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)");
        validate_private_windows_sddl(&private).unwrap();

        let everyone = format!("{private}(A;;FA;;;WD)");
        assert!(validate_private_windows_sddl(&everyone).is_err());
        let inherited = format!("O:{sid}D:(A;;FA;;;{sid})(A;;FA;;;SY)");
        assert!(validate_private_windows_sddl(&inherited).is_err());
        let wrong_owner = format!("O:SYD:P(A;;FA;;;{sid})(A;;FA;;;SY)");
        assert!(validate_private_windows_sddl(&wrong_owner).is_err());
        let extra_deny = format!("{private}(D;;FA;;;WD)");
        assert!(validate_private_windows_sddl(&extra_deny).is_err());
    }
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
