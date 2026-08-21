use std::path::{Path, PathBuf};

#[cfg(windows)]
use anyhow::ensure;
use anyhow::{Context, Result, bail};
use uuid::Uuid;

const ROLES: [&str; 4] = ["planner", "worker", "evaluator", "skeptic"];

#[derive(Debug)]
pub struct GoalScratchRoot {
    #[cfg(not(unix))]
    parent: PathBuf,
    root: PathBuf,
    #[cfg(unix)]
    parent_handle: std::fs::File,
    #[cfg(unix)]
    root_handle: std::fs::File,
}

impl GoalScratchRoot {
    pub fn create(goal_id: Uuid) -> Result<Self> {
        #[cfg(unix)]
        let parent = std::env::temp_dir().join(format!(
            "cockpit-goals-{}",
            // SAFETY: geteuid has no preconditions and does not expose secrets.
            unsafe { libc::geteuid() }
        ));
        #[cfg(not(unix))]
        let parent = std::env::temp_dir().join("cockpit-goals");
        Self::create_in(&parent, goal_id)
    }

    pub fn create_in(parent: &Path, goal_id: Uuid) -> Result<Self> {
        #[cfg(unix)]
        return create_in_unix(parent, goal_id);
        #[cfg(not(unix))]
        {
            create_checked_dir(&parent)?;
            let root = parent.join(goal_id.to_string());
            create_checked_dir(&root)?;
            for role in ROLES {
                create_checked_dir(&root.join(role))?;
            }
            Ok(Self {
                parent: parent.to_path_buf(),
                root,
            })
        }
    }

    pub fn role(&self, role: &str) -> Result<PathBuf> {
        if !ROLES.contains(&role) {
            bail!("unknown goal scratch role");
        }
        #[cfg(unix)]
        openat_private_dir(&self.root_handle, role)?;
        let path = self.root.join(role);
        #[cfg(not(unix))]
        verify_checked_dir(&path)?;
        Ok(path)
    }

    pub fn cleanup(self) -> Result<()> {
        #[cfg(unix)]
        {
            for role in ROLES {
                unlinkat_dir(&self.root_handle, role)?;
            }
            let name = self
                .root
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .ok_or_else(|| anyhow::anyhow!("invalid goal scratch root name"))?;
            unlinkat_dir(&self.parent_handle, name).context("removing terminal goal scratch root")
        }
        #[cfg(not(unix))]
        {
            verify_checked_dir(&self.root)?;
            verify_checked_dir(&self.parent)?;
            if self.root.parent() != Some(self.parent.as_path()) {
                bail!("refusing to remove goal scratch outside the private root");
            }
            std::fs::remove_dir_all(&self.root).context("removing terminal goal scratch root")
        }
    }
}

#[cfg(unix)]
fn create_in_unix(parent: &Path, goal_id: Uuid) -> Result<GoalScratchRoot> {
    let parent_handle = ensure_private_dir_tree(parent)?;
    let root_name = goal_id.to_string();
    mkdirat_private(&parent_handle, &root_name)?;
    let root_handle = openat_private_dir(&parent_handle, &root_name)?;
    for role in ROLES {
        mkdirat_private(&root_handle, role)?;
        openat_private_dir(&root_handle, role)?;
    }
    Ok(GoalScratchRoot {
        root: parent.join(&root_name),
        parent_handle,
        root_handle,
    })
}

#[cfg(unix)]
fn ensure_private_dir_tree(path: &Path) -> Result<std::fs::File> {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let start = if path.is_absolute() { "/" } else { "." };
    let start = std::ffi::CString::new(start)?;
    // SAFETY: the path is NUL terminated; the returned descriptor is owned.
    let fd = unsafe {
        libc::open(
            start.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("opening scratch path anchor");
    }
    // SAFETY: `fd` was newly returned by open and has unique ownership.
    let mut current: std::fs::File = unsafe { OwnedFd::from_raw_fd(fd) }.into();
    let parent_path = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("goal scratch parent has no parent directory"))?;
    for component in parent_path.components() {
        let std::path::Component::Normal(name) = component else {
            if matches!(
                component,
                std::path::Component::RootDir | std::path::Component::CurDir
            ) {
                continue;
            }
            bail!("goal scratch path contains an unsafe component");
        };
        let name = std::str::from_utf8(name.as_bytes())
            .context("goal scratch path component is not UTF-8")?;
        current = openat_dir_nofollow(&current, name)?;
    }
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| anyhow::anyhow!("invalid goal scratch parent name"))?;
    mkdirat_private(&current, name)?;
    openat_private_dir(&current, name)
}

#[cfg(unix)]
fn component_cstring(name: &str) -> Result<std::ffi::CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        bail!("unsafe goal scratch component");
    }
    Ok(std::ffi::CString::new(name)?)
}

#[cfg(unix)]
fn mkdirat_private(parent: &std::fs::File, name: &str) -> Result<()> {
    use std::os::fd::AsRawFd;
    let name = component_cstring(name)?;
    // SAFETY: parent is a live directory descriptor and name is NUL terminated.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        return Ok(());
    }
    Err(error).context("creating private goal scratch directory")
}

#[cfg(unix)]
fn openat_private_dir(parent: &std::fs::File, name: &str) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let file = openat_dir_nofollow(parent, name)?;
    let meta = file.metadata()?;
    if meta.uid() != unsafe { libc::geteuid() } || meta.permissions().mode() & 0o777 != 0o700 {
        bail!("goal scratch component failed owner/mode checks");
    }
    Ok(file)
}

#[cfg(unix)]
fn openat_dir_nofollow(parent: &std::fs::File, name: &str) -> Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let name = component_cstring(name)?;
    // SAFETY: parent is live and name is NUL terminated. O_NOFOLLOW rejects links.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("opening goal scratch component");
    }
    // SAFETY: `fd` is newly owned.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) }.into())
}

#[cfg(unix)]
fn unlinkat_dir(parent: &std::fs::File, name: &str) -> Result<()> {
    use std::os::fd::AsRawFd;
    let name = component_cstring(name)?;
    // SAFETY: parent is live and unlinkat operates on the literal child name.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error()).context("removing goal scratch directory");
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_checked_dir(path: &Path) -> Result<()> {
    #[cfg(windows)]
    verify_no_reparse_components(path.parent().unwrap_or(path))?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_dir() || meta.file_type().is_symlink() => bail!(
            "goal scratch path is a link or non-directory: {}",
            path.display()
        ),
        Ok(_) => verify_checked_dir(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path).with_context(|| format!("creating {}", path.display()))?;
            set_private(path)?;
            verify_checked_dir(path)
        }
        Err(error) => Err(error).with_context(|| format!("checking {}", path.display())),
    }
}

#[cfg(all(unix, test))]
fn set_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn set_private(path: &Path) -> Result<()> {
    apply_windows_dacl(path, "D:P(A;;FA;;;OW)(A;;FA;;;SY)")?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        verify_checked_dir(path)
    } else {
        verify_private_dacl(path)
    }
}

#[cfg(windows)]
fn apply_windows_dacl(path: &Path, descriptor_text: &str) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor: *const u16,
            revision: u32,
            security_descriptor: *mut *mut core::ffi::c_void,
            size: *mut u32,
        ) -> i32;
        fn SetFileSecurityW(
            file_name: *const u16,
            security_information: u32,
            security_descriptor: *mut core::ffi::c_void,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    let sddl: Vec<u16> = std::ffi::OsStr::new(descriptor_text)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: both strings are NUL-terminated, the descriptor out-pointer is
    // valid, and LocalFree releases the Windows-owned allocation exactly once.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("building private goal DACL");
        }
        let applied = SetFileSecurityW(wide_path.as_ptr(), 0x0000_0004, descriptor);
        LocalFree(descriptor);
        if applied == 0 {
            return Err(std::io::Error::last_os_error()).context("applying private goal DACL");
        }
    }
    Ok(())
}

#[cfg(all(windows, test))]
pub(crate) fn apply_test_windows_dacl(path: &Path, descriptor: &str) -> Result<()> {
    apply_windows_dacl(path, descriptor)
}

#[cfg(windows)]
fn verify_checked_dir(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    verify_no_reparse_components(path)?;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!(
            "goal scratch directory is a reparse point or non-directory: {}",
            path.display()
        );
    }
    verify_private_dacl(path)?;
    Ok(())
}

#[cfg(windows)]
fn verify_no_reparse_components(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current.as_os_str().is_empty() {
            continue;
        }
        let meta = std::fs::symlink_metadata(&current)?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("goal scratch path contains a reparse-point component");
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn verify_private_dacl(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetFileSecurityW(
            file_name: *const u16,
            requested_information: u32,
            security_descriptor: *mut core::ffi::c_void,
            length: u32,
            length_needed: *mut u32,
        ) -> i32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security_descriptor: *mut core::ffi::c_void,
            revision: u32,
            security_information: u32,
            string_security_descriptor: *mut *mut u16,
            string_length: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const SECURITY_INFORMATION: u32 = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut needed = 0_u32;
    // SAFETY: this first call intentionally supplies a null buffer to obtain its size.
    unsafe {
        GetFileSecurityW(
            wide_path.as_ptr(),
            SECURITY_INFORMATION,
            ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(std::io::Error::last_os_error()).context("reading goal scratch DACL size");
    }
    let mut descriptor = vec![0_u8; usize::try_from(needed)?];
    let mut sddl_ptr = ptr::null_mut();
    let mut sddl_len = 0_u32;
    // SAFETY: buffers are sized by Windows and all output pointers remain valid.
    unsafe {
        if GetFileSecurityW(
            wide_path.as_ptr(),
            SECURITY_INFORMATION,
            descriptor.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
            || ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.as_mut_ptr().cast(),
                1,
                SECURITY_INFORMATION,
                &mut sddl_ptr,
                &mut sddl_len,
            ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("reading goal scratch DACL");
        }
        let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(
            sddl_ptr,
            usize::try_from(sddl_len).unwrap_or(0),
        ));
        LocalFree(sddl_ptr.cast());
        validate_private_sddl(&sddl)?;
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn verify_private_dacl_handle(file: &std::fs::File) -> Result<()> {
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
    ensure!(
        result == 0 && !descriptor.is_null(),
        "reading held directory security descriptor failed ({result})"
    );
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
    ensure!(
        converted != 0 && !sddl.is_null(),
        "converting held directory security descriptor failed"
    );
    let value = String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(sddl, usize::try_from(length).unwrap_or(0))
    });
    unsafe { LocalFree(sddl.cast()) };
    validate_private_sddl(&value)
}

#[cfg(windows)]
pub(crate) fn set_private_dacl_handle(file: &std::fs::File) -> Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use std::ptr;
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
    const OWNER_SECURITY_INFORMATION: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 4;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    let sid = current_windows_user_sid()?;
    let sddl = format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)");
    let wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor = ptr::null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } != 0,
        "building private held-artifact DACL failed"
    );
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut ignored = 0;
    let valid = unsafe {
        GetSecurityDescriptorOwner(descriptor, &mut owner, &mut ignored) != 0
            && GetSecurityDescriptorDacl(descriptor, &mut ignored, &mut dacl, &mut ignored) != 0
    };
    if !valid || owner.is_null() || dacl.is_null() {
        unsafe { LocalFree(descriptor) };
        bail!("extracting private held-artifact DACL failed");
    }
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    unsafe { LocalFree(descriptor) };
    ensure!(
        result == 0,
        "setting private held-artifact DACL failed ({result})"
    );
    verify_private_dacl_handle(file)
}

#[cfg(windows)]
fn validate_private_sddl(sddl: &str) -> Result<()> {
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
    ensure!(
        sddl.contains("D:P")
            && sddl.matches("(A;").count() == 2
            && owner == Some(current_user.as_str())
            && ace_sids.contains(&current_user.as_str())
            && ace_sids
                .iter()
                .any(|sid| *sid == "SY" || *sid == "S-1-5-18"),
        "private DACL is not protected current-user-and-SYSTEM-only full control"
    );
    Ok(())
}

#[cfg(windows)]
fn current_windows_user_sid() -> Result<String> {
    use std::ptr;

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
    let mut token = ptr::null_mut();
    // SAFETY: all handles and output pointers follow the documented Win32 contracts.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error()).context("opening process token");
        }
        let mut needed = 0_u32;
        GetTokenInformation(token, TOKEN_USER_CLASS, ptr::null_mut(), 0, &mut needed);
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
        let mut sid_text = ptr::null_mut();
        if ConvertSidToStringSidW(token_user.user.sid, &mut sid_text) == 0 {
            CloseHandle(token);
            return Err(std::io::Error::last_os_error()).context("formatting process SID");
        }
        let mut len = 0_usize;
        while *sid_text.add(len) != 0 {
            len += 1;
        }
        let result = String::from_utf16_lossy(std::slice::from_raw_parts(sid_text, len));
        LocalFree(sid_text.cast());
        CloseHandle(token);
        Ok(result)
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("goal scratch security requires an owner-check implementation");

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn goal_scratch_root_rejects_symlink_and_cleans_terminal_root() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("goals");
        let scratch = GoalScratchRoot::create_in(&parent, Uuid::nil()).unwrap();
        let root = scratch.root.clone();
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::remove_dir(root.join("planner")).unwrap();
        symlink(&target, root.join("planner")).unwrap();
        assert!(scratch.role("planner").is_err());
        std::fs::remove_file(root.join("planner")).unwrap();
        std::fs::create_dir(root.join("planner")).unwrap();
        set_private(&root.join("planner")).unwrap();
        scratch.cleanup().unwrap();
        assert!(!root.exists());
    }

    #[cfg(windows)]
    #[test]
    fn goal_scratch_root_rejects_windows_reparse_point() {
        let temp = tempfile::tempdir().unwrap();
        let scratch = GoalScratchRoot::create_in(&temp.path().join("goals"), Uuid::nil()).unwrap();
        let planner = scratch.root.join("planner");
        std::fs::remove_dir(&planner).unwrap();
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let status = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&planner)
            .arg(&target)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(scratch.role("planner").is_err());
    }
}
