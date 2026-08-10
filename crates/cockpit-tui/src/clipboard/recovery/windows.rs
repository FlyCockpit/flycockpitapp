//! Windows directory/file security for the private clipboard recovery
//! artifact.
//!
//! Unlike the rest of this workspace's Windows containment code (which
//! honestly inherits the parent directory's ACL and does not set an
//! explicit security descriptor — see
//! `cockpit-core::external_journal::fsguard`), the recovery artifact needs
//! a genuine owner-only guarantee because it can hold recovered clipboard
//! plaintext. The recovery directory is created with a protected DACL
//! (`SE_DACL_PROTECTED`, no inherited ACEs) containing exactly two
//! container/object-inherit `ACCESS_ALLOWED` entries: the current user and
//! `LocalSystem`, both full control. Every file is opened relative to the
//! held, already-verified directory handle (`NtCreateFile` with
//! `RootDirectory`) and its own DACL is verified to be no broader than that
//! policy before it is ever read or trusted. A chmod-equivalent (setting
//! bits without verifying who can actually read them) is never accepted
//! here as privacy enforcement.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, RawHandle};
use std::path::{Path, PathBuf};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GENERIC_READ, HANDLE, LocalFree, OBJ_CASE_INSENSITIVE,
    RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
    EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl, GetTokenInformation,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FileAttributeTagInfo, FileStandardInfo, GetFileInformationByHandleEx, READ_CONTROL,
    SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::policy::{self, WindowsDirStat, WindowsFileStat};

/// The exact `FILE_ALL_ACCESS` numeric mask SDDL's `FA` alias resolves to.
/// Any ACE granting a different mask is rejected as broader (or narrower —
/// either way, not the exact policy) than intended.
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

fn last_error(context: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("{context}: {}", io::Error::last_os_error()),
    )
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// An owned handle, closed on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` is a live, uniquely owned handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// An owned self-relative security descriptor, freed with `LocalFree`.
struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, which
            // documents `LocalFree` as the matching deallocator.
            unsafe {
                LocalFree(self.0 as _);
            }
        }
    }
}

/// The current process user's SID, in both raw (`PSID`-comparable) and
/// SDDL string form.
struct CurrentUserSid {
    /// Owned bytes backing a `TOKEN_USER` buffer; `sid_ptr()` points inside.
    buffer: Vec<u8>,
    sid_offset: usize,
    string_form: String,
}

impl CurrentUserSid {
    fn sid_ptr(&self) -> PSID {
        // SAFETY: `sid_offset` was computed from the same buffer below and
        // stays within bounds for the buffer's lifetime.
        unsafe { self.buffer.as_ptr().add(self.sid_offset) as PSID }
    }

    fn resolve() -> io::Result<Self> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
        // closing; `token` is a valid out-pointer for the call.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 {
            return Err(last_error("opening process token"));
        }
        let _token = OwnedHandle(token);

        let mut needed: u32 = 0;
        // SAFETY: a zero-length probe call is documented to fail and report
        // the required size in `needed`.
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            return Err(io::Error::other("could not size TOKEN_USER"));
        }
        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: `buffer` is exactly `needed` bytes, matching the size the
        // probe call reported.
        let queried = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr() as *mut c_void,
                needed,
                &mut needed,
            )
        };
        if queried == 0 {
            return Err(last_error("querying TOKEN_USER"));
        }
        // SAFETY: `buffer` holds a live `TOKEN_USER` as populated above.
        let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
        let sid_ptr = token_user.User.Sid;
        let sid_offset = sid_ptr as usize - buffer.as_ptr() as usize;

        let mut string_ptr: windows_sys::core::PWSTR = std::ptr::null_mut();
        // SAFETY: `sid_ptr` points inside `buffer`, which stays alive for
        // the call; the output pointer is freed with `LocalFree` below.
        let converted = unsafe { ConvertSidToStringSidW(sid_ptr, &mut string_ptr) };
        if converted == 0 {
            return Err(last_error("converting current-user SID to string"));
        }
        let string_form = read_wide_c_string(string_ptr);
        // SAFETY: `string_ptr` was allocated by `ConvertSidToStringSidW`.
        unsafe {
            LocalFree(string_ptr as _);
        }

        Ok(Self {
            buffer,
            sid_offset,
            string_form,
        })
    }
}

/// Read a NUL-terminated wide string without taking ownership of it.
fn read_wide_c_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: `ptr` is a live NUL-terminated wide string for the duration
    // of this scan.
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
    }
    // SAFETY: `ptr..ptr+len` is the scanned, live wide-character range.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

/// The exact SDDL for the recovery directory's security descriptor,
/// pulled out as a pure string-building function — no FFI, no `unsafe` —
/// so it is independently testable without a Windows host or any injected
/// syscall seam. `P` = protected DACL (blocks inheritance from the parent,
/// and is not itself auto-inherited); `OICI` = object-inherit/container
/// -inherit so new files created inside pick up the same two ACEs; `FA` =
/// exactly `FILE_ALL_ACCESS`. `SY` is the well-known LocalSystem SID
/// alias. The real ACE-by-ACE verification this SDDL is meant to produce
/// (`verify_owner_only_dacl`, below) still requires real
/// `GetSecurityInfo`/`GetAclInformation`/`GetAce` calls and is not covered
/// by this extraction — see the module-level note on Windows adapter test
/// coverage for why that remains unaddressed here.
fn owner_only_sddl(owner_sid: &str) -> String {
    format!("O:{owner_sid}G:{owner_sid}D:P(A;OICI;FA;;;{owner_sid})(A;OICI;FA;;;SY)")
}

fn build_owner_only_descriptor(owner_sid: &str) -> io::Result<OwnedSecurityDescriptor> {
    let sddl = owner_only_sddl(owner_sid);
    let wide_sddl = wide(&sddl);
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `wide_sddl` is a live NUL-terminated string for the call; the
    // returned descriptor is owned exactly once by `OwnedSecurityDescriptor`.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(last_error(
            "building recovery directory security descriptor",
        ));
    }
    Ok(OwnedSecurityDescriptor(descriptor))
}

fn reject_reparse(handle: HANDLE, expect_directory: bool) -> io::Result<()> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: `handle` is live; `info` is exactly sized for the class.
    let queried = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            std::ptr::from_mut(&mut info).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if queried == 0 {
        return Err(last_error("checking reparse attribute"));
    }
    if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other("recovery entry is a reparse point"));
    }
    let is_dir = info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if is_dir != expect_directory {
        return Err(io::Error::other("recovery entry has the wrong file type"));
    }
    Ok(())
}

/// Verify a handle's DACL is protected and exactly `{owner: FA, SYSTEM:
/// FA}` (directory) or no broader than that same policy (file, which may
/// legitimately have inherited, non-protected copies of the same two
/// ACEs).
fn verify_owner_only_dacl(
    handle: HANDLE,
    owner: &CurrentUserSid,
    require_protected: bool,
) -> io::Result<bool> {
    let mut owner_sid: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `handle` is live; every out-pointer is a valid local.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner_sid,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    // SAFETY: `descriptor` was allocated by `GetSecurityInfo` and is freed
    // exactly once here; `owner_sid`/`dacl` point inside it and must not
    // outlive it.
    let _descriptor = OwnedSecurityDescriptor(descriptor);

    // SAFETY: both SIDs are live for the comparison.
    let owner_matches = unsafe { EqualSid(owner_sid, owner.sid_ptr()) } != 0;
    if !owner_matches {
        return Ok(false);
    }

    if require_protected {
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        // SAFETY: `descriptor` is the live descriptor held above.
        let queried =
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
        if queried == 0 {
            return Err(last_error("reading security descriptor control bits"));
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Ok(false);
        }
    }

    if dacl.is_null() {
        // A null (all-access) DACL is never the owner-only policy.
        return Ok(false);
    }
    let mut size_info = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is live for the call.
    let sized = unsafe {
        GetAclInformation(
            dacl,
            std::ptr::from_mut(&mut size_info).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if sized == 0 {
        return Err(last_error("reading DACL size"));
    }
    if size_info.AceCount != 2 {
        return Ok(false);
    }
    let system_sid = well_known_local_system_sid()?;
    for index in 0..size_info.AceCount {
        let mut ace_ptr: *mut c_void = std::ptr::null_mut();
        // SAFETY: `dacl` is live and `index` is within `AceCount`.
        let got = unsafe { GetAce(dacl, index, &mut ace_ptr) };
        if got == 0 {
            return Err(last_error("reading ACE"));
        }
        // SAFETY: a successfully returned ACE from a DACL built with only
        // `ACCESS_ALLOWED_ACE` entries has that exact layout.
        let ace = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
        if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace.Mask != FILE_ALL_ACCESS {
            return Ok(false);
        }
        let sid_ptr = std::ptr::addr_of!(ace.SidStart) as PSID;
        // SAFETY: both SIDs are live for the comparison.
        let is_owner = unsafe { EqualSid(sid_ptr, owner.sid_ptr()) } != 0;
        // SAFETY: same as above.
        let is_system = unsafe { EqualSid(sid_ptr, system_sid.as_ptr() as PSID) } != 0;
        if !is_owner && !is_system {
            return Ok(false);
        }
    }
    Ok(true)
}

fn well_known_local_system_sid() -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, SECURITY_MAX_SID_SIZE, WinLocalSystemSid,
    };
    let mut buffer = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = buffer.len() as u32;
    // SAFETY: `buffer` is exactly `len` bytes, matching what `CreateWellKnownSid` requires.
    let created = unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            std::ptr::null_mut(),
            buffer.as_mut_ptr() as PSID,
            &mut len,
        )
    };
    if created == 0 {
        return Err(last_error("resolving LocalSystem SID"));
    }
    buffer.truncate(len as usize);
    Ok(buffer)
}

fn open_relative_nofollow(
    parent: HANDLE,
    name: &str,
    directory: bool,
    desired_access: u32,
    create_disposition: u32,
) -> io::Result<std::fs::File> {
    let mut name_wide = wide(name);
    name_wide.pop(); // UNICODE_STRING is not NUL-terminated.
    let byte_len = (name_wide.len() * std::mem::size_of::<u16>()) as u16;
    let unicode_name = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: name_wide.as_mut_ptr(),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
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
    // SAFETY: `parent` is a live, retained directory handle; the name
    // buffer, object attributes, and status block all remain live for the
    // call. Resolution is relative to `RootDirectory` only — never a path.
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
        // SAFETY: total for NTSTATUS values; no pointer dereference.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    // SAFETY: `NtCreateFile` returned success and transferred one owned handle.
    Ok(unsafe { std::fs::File::from_raw_handle(handle as RawHandle) })
}

/// Result of opening-and-verifying an untrusted enumerated name.
pub enum CheckedEntry {
    Missing,
    Unsafe,
    Ok(std::fs::File),
}

/// A held, security-verified recovery directory handle.
pub struct DirHandle {
    dir: std::fs::File,
    path: PathBuf,
    owner: CurrentUserSid,
}

impl DirHandle {
    pub fn sync(&self) -> io::Result<()> {
        self.dir.sync_all()
    }

    pub fn open_or_create(path: &Path) -> io::Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
        std::fs::create_dir_all(parent)?;

        let owner = CurrentUserSid::resolve()?;
        let descriptor = build_owner_only_descriptor(&owner.string_form)?;
        let wide_path = wide(&path.to_string_lossy());
        let mut attrs = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        // SAFETY: `wide_path` and `attrs` are live for the call. Creating
        // with an explicit descriptor avoids the race of creating with
        // default security and fixing it up afterwards.
        let created = unsafe {
            windows_sys::Win32::Storage::FileSystem::CreateDirectoryW(wide_path.as_ptr(), &attrs)
        };
        let _ = &mut attrs;
        if created == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                return Err(last_error("creating recovery directory"));
            }
        }

        // Open by handle, no-follow, backup semantics required for directories.
        // Same bug class as the `/copy file` publisher's fix (B4): this is
        // `CreateFileW` (Win32), not `NtCreateFile` (NT), so the
        // disposition must be the Win32 `OPEN_EXISTING`, not the NT-style
        // `FILE_OPEN` — they share numeric space
        // (`Wdk::FILE_OPEN == 1 == Win32::CREATE_NEW`), so passing the NT
        // constant here compiled but meant "fail unless the directory does
        // not exist yet", the opposite of what a reopen-after-create needs.
        let wide_open = wide(&path.to_string_lossy());
        let handle = unsafe {
            windows_sys::Win32::Storage::FileSystem::CreateFileW(
                wide_open.as_ptr(),
                FILE_READ_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING,
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                    | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(last_error("opening recovery directory"));
        }
        // SAFETY: `handle` was just returned by `CreateFileW` and is uniquely owned.
        let dir = unsafe { std::fs::File::from_raw_handle(handle as RawHandle) };

        let this = Self {
            dir,
            path: path.to_path_buf(),
            owner,
        };
        this.verify_private()?;
        Ok(this)
    }

    fn dir_handle(&self) -> HANDLE {
        self.dir.as_raw_handle() as HANDLE
    }

    pub fn verify_private(&self) -> io::Result<()> {
        reject_reparse(self.dir_handle(), true).map_err(|e| {
            io::Error::other(format!("recovery directory reparse check failed: {e}"))
        })?;
        let dacl_ok = verify_owner_only_dacl(self.dir_handle(), &self.owner, true)?;
        let stat = WindowsDirStat {
            is_reparse_point: false,
            is_directory: true,
            dacl_is_owner_only_and_protected: dacl_ok,
            owner_is_current_user: dacl_ok,
        };
        policy::verify_windows_dir(stat)
            .map_err(|v| io::Error::other(format!("recovery directory failed containment: {v:?}")))
    }

    pub fn create_file_exclusive(&self, name: &str) -> io::Result<std::fs::File> {
        let file = open_relative_nofollow(
            self.dir_handle(),
            name,
            false,
            DELETE
                | FILE_WRITE_DATA
                | FILE_WRITE_ATTRIBUTES
                | FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE,
            FILE_CREATE,
        )?;
        let stat = self.stat_open_file(&file)?;
        policy::verify_windows_file(stat).map_err(|v| {
            io::Error::other(format!("new recovery artifact failed containment: {v:?}"))
        })?;
        Ok(file)
    }

    /// Reopen-and-classify an untrusted enumerated name in one step,
    /// without ever letting an unsafe entry abort the whole scan.
    ///
    /// Opened with `FILE_NON_DIRECTORY_FILE`, so an actual directory fails
    /// the open itself (`STATUS_FILE_IS_A_DIRECTORY`) rather than needing a
    /// post-open check; a junction/symlink reparse point is opened
    /// successfully (via `FILE_OPEN_REPARSE_POINT`, never followed) so it
    /// can be inspected and rejected by [`policy::verify_windows_file`].
    /// Every open failure other than "does not exist", along with a
    /// successful open that fails containment, is [`CheckedEntry::Unsafe`]:
    /// reported by count, left exactly as found.
    pub fn open_file_verified(&self, name: &str) -> io::Result<CheckedEntry> {
        match open_relative_nofollow(
            self.dir_handle(),
            name,
            false,
            DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE | GENERIC_READ,
            FILE_OPEN,
        ) {
            Ok(file) => {
                let stat = self.stat_open_file(&file)?;
                Ok(match policy::verify_windows_file(stat) {
                    Ok(()) => CheckedEntry::Ok(file),
                    Err(_) => CheckedEntry::Unsafe,
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(CheckedEntry::Missing),
            Err(_) => Ok(CheckedEntry::Unsafe),
        }
    }

    fn stat_open_file(&self, file: &std::fs::File) -> io::Result<WindowsFileStat> {
        let handle = file.as_raw_handle() as HANDLE;
        let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
        // SAFETY: `handle` is live; `tag` is exactly sized for the class.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                std::ptr::from_mut(&mut tag).cast(),
                std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        let is_reparse_point = tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        let is_directory = tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;

        let mut standard = FILE_STANDARD_INFO::default();
        // SAFETY: same as above.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileStandardInfo,
                std::ptr::from_mut(&mut standard).cast(),
                std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
            )
        };

        let dacl_ok = verify_owner_only_dacl(handle, &self.owner, false).unwrap_or(false);

        Ok(WindowsFileStat {
            is_reparse_point,
            is_directory,
            nlink: standard.NumberOfLinks,
            owner_is_current_user: dacl_ok,
            dacl_within_directory_policy: dacl_ok,
            // The file was opened via `NtCreateFile` with `RootDirectory`
            // set to this held, already-verified directory handle, so by
            // kernel-enforced construction its parent is exactly this
            // directory — there is no path re-resolution anywhere in this
            // call chain that could have redirected it.
            parent_identity_matches: true,
        })
    }

    pub fn remove_file(&self, name: &str) -> io::Result<()> {
        match open_relative_nofollow(self.dir_handle(), name, false, DELETE, FILE_OPEN) {
            Ok(file) => {
                use windows_sys::Win32::Storage::FileSystem::{
                    FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
                };
                let disposition = FILE_DISPOSITION_INFO {
                    DeleteFile: true as _,
                };
                // SAFETY: `file` was opened with `DELETE` access; `disposition`
                // matches the exact layout `FileDispositionInfo` requires.
                let removed = unsafe {
                    SetFileInformationByHandle(
                        file.as_raw_handle() as HANDLE,
                        FileDispositionInfo,
                        std::ptr::from_ref(&disposition).cast(),
                        std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                    )
                };
                if removed == 0 {
                    return Err(last_error("removing recovery artifact"));
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Delete exactly the file identified by `verified` — the handle
    /// already opened and verified by [`Self::open_file_verified`] —
    /// ignoring whatever name currently resolves to on disk (`name` is
    /// accepted only so callers can share one signature with the Unix
    /// implementation; it plays no role here). Unlike [`Self::remove_file`]
    /// (which reopens by name and is exactly the name-based TOCTOU this
    /// exists to avoid), `FileDispositionInfo` operates on the handle
    /// itself: Windows deletes the underlying file object the handle
    /// refers to regardless of whether that name has since been reused
    /// for something else. `verified` was already opened with `DELETE`
    /// access by `open_file_verified`, so no reopen is needed at all —
    /// zero gap between verification and removal.
    pub fn remove_verified(&self, _name: &str, verified: std::fs::File) -> io::Result<bool> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
        };
        let disposition = FILE_DISPOSITION_INFO {
            DeleteFile: true as _,
        };
        // SAFETY: `verified` was opened with `DELETE` access; `disposition`
        // matches the exact layout `FileDispositionInfo` requires.
        let removed = unsafe {
            SetFileInformationByHandle(
                verified.as_raw_handle() as HANDLE,
                FileDispositionInfo,
                std::ptr::from_ref(&disposition).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        };
        if removed == 0 {
            return Err(last_error("removing recovery artifact"));
        }
        Ok(true)
    }

    pub fn list_names(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Documented no-op: Windows has no directory fsync. A crash between a
    /// create/remove and the next reconcile is tolerated by the
    /// newest-wins/never-touch-unsafe-entries reconcile policy, not by
    /// durability here.
    pub fn sync(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_only_sddl_grants_exactly_owner_and_local_system_full_control() {
        let sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        let sddl = owner_only_sddl(sid);
        assert_eq!(
            sddl,
            "O:S-1-5-21-1111111111-2222222222-3333333333-1001\
             G:S-1-5-21-1111111111-2222222222-3333333333-1001\
             D:P(A;OICI;FA;;;S-1-5-21-1111111111-2222222222-3333333333-1001)\
             (A;OICI;FA;;;SY)"
        );
        // Protected (`P`): no inheritance from the parent directory.
        assert!(sddl.contains("D:P("));
        // Exactly two ACEs: the owner and LocalSystem (`SY`), full control
        // (`FA`), nothing else — no `WD` (Everyone), no `AU` (Authenticated
        // Users), no broader alias of any kind.
        assert_eq!(sddl.matches("FA;;;").count(), 2);
        assert!(sddl.contains(";SY)"));
        assert!(!sddl.contains("WD"));
        assert!(!sddl.contains("AU"));
    }

    #[test]
    fn owner_only_sddl_is_stable_across_different_sids() {
        // A different owner SID must appear in every slot that names the
        // owner (O:, G:, and the first ACE) and nowhere else.
        let sid = "S-1-5-21-9-9-9-500";
        let sddl = owner_only_sddl(sid);
        assert_eq!(sddl.matches(sid).count(), 3);
    }
}
