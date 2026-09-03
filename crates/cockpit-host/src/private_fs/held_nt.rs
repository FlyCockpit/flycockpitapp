//! Canonical Windows handle-anchored NT filesystem primitives.
//!
//! This module is the Windows twin of [`super::held_fd`] (which is the
//! Unix-only sibling declared beside it): the SINGLE home for the raw,
//! directory-handle-anchored, no-reparse operations (`NtCreateFile` relative
//! opens, `NtSetInformationFile` rename/disposition, and
//! `NtQueryDirectoryFile` enumeration) used by the skill-manage mutation
//! layer. Like `held_fd`, each function is a thin wrapper that encapsulates
//! the `unsafe` FFI and returns a plain [`std::io::Result`]; NTSTATUS
//! classification beyond the mapped [`std::io::ErrorKind`]s stays at the
//! call site, so ownership/permission/identity policy lives with the
//! caller. What this module does own is the containment discipline itself:
//!
//! - every child lookup is anchored beneath a retained directory handle
//!   (`RootDirectory` + single-component `ObjectName`) and never
//!   re-resolved through a path;
//! - a reparse point is opened as itself (`FILE_OPEN_REPARSE_POINT`) and
//!   then refused by attribute check rather than followed — the twin of
//!   `O_NOFOLLOW` plus the post-open type check;
//! - a relative name may never contain a separator, `.`, `..`, or NUL,
//!   which is what keeps a hostile spelling from escaping the held root
//!   through an NT path-walk;
//! - publication renames are no-replace by construction
//!   (`ReplaceIfExists = 0`), and deletes are verified observable.
//!
//! All handles are returned as owned [`std::fs::File`] values built from a
//! freshly-returned `HANDLE`, so the handle is closed exactly once when the
//! `File` drops.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Component, Path};

type Handle = *mut core::ffi::c_void;
const INVALID_HANDLE_VALUE: Handle = isize::MIN as Handle;
const STATUS_SUCCESS_MIN: i32 = 0;
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
const STATUS_NOT_A_DIRECTORY: i32 = 0xC000_010B_u32 as i32;
const STATUS_NO_MORE_FILES: i32 = 0x8000_0006_u32 as i32;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_DONT_REPARSE: u32 = 0x1000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const DELETE: u32 = 0x0001_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
/// read | write | delete: every retained handle shares delete so staged
/// renames and disposition deletes are never blocked by our own survey
/// handles, exactly like the Unix staging descriptors.
const FILE_SHARE_ALL: u32 = 0x7;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_RENAME_INFORMATION_CLASS: u32 = 10;
const FILE_DISPOSITION_INFORMATION_CLASS: u32 = 13;
const FILE_NAMES_INFORMATION_CLASS: u32 = 12;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: Handle,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *mut core::ffi::c_void,
    security_quality_of_service: *mut core::ffi::c_void,
}

#[repr(C)]
struct IoStatusBlock {
    status: isize,
    information: usize,
}

#[repr(C)]
struct ByHandleFileInformation {
    attributes: u32,
    creation_low: u32,
    creation_high: u32,
    access_low: u32,
    access_high: u32,
    write_low: u32,
    write_high: u32,
    volume_serial: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[repr(C)]
struct FileDispositionInformation {
    delete_file: u8,
}

#[repr(C)]
struct FileRenameInformation {
    replace_if_exists: u8,
    root_directory: Handle,
    file_name_length: u32,
    file_name: [u16; 1],
}

#[repr(C)]
struct FileNamesInformation {
    next_entry_offset: u32,
    file_index: u32,
    file_name_length: u32,
    file_name: [u16; 1],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file: *mut Handle,
        access: u32,
        attributes: *const ObjectAttributes,
        io: *mut IoStatusBlock,
        allocation: *const i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const core::ffi::c_void,
        ea_len: u32,
    ) -> i32;
    fn NtSetInformationFile(
        file: Handle,
        io: *mut IoStatusBlock,
        information: *const core::ffi::c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn NtQueryDirectoryFile(
        file: Handle,
        event: Handle,
        apc_routine: *mut core::ffi::c_void,
        apc_context: *mut core::ffi::c_void,
        io: *mut IoStatusBlock,
        information: *mut core::ffi::c_void,
        length: u32,
        information_class: u32,
        return_single_entry: u8,
        file_name: *const UnicodeString,
        restart_scan: u8,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *mut core::ffi::c_void,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn GetFileInformationByHandle(file: Handle, information: *mut ByHandleFileInformation) -> i32;
    fn FlushFileBuffers(file: Handle) -> i32;
}

// ------------------------------------------------------------------------
// Typed error mapping
// ------------------------------------------------------------------------

/// Map an NTSTATUS to an [`std::io::Error`] whose kind the caller can match
/// (`NotFound` for a missing final name or missing path, `AlreadyExists`
/// for a create/rename collision, `PermissionDenied` for access denial).
/// Every other status carries the raw NTSTATUS in its message so a
/// fail-closed caller can still diagnose it.
fn io_from_status(status: i32) -> io::Error {
    let kind = match status as u32 {
        STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND => io::ErrorKind::NotFound,
        STATUS_OBJECT_NAME_COLLISION => io::ErrorKind::AlreadyExists,
        STATUS_ACCESS_DENIED => io::ErrorKind::PermissionDenied,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(
        kind,
        format!("NT syscall failed with NTSTATUS {status:#010x}"),
    )
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

// ------------------------------------------------------------------------
// Component validation (defense in depth)
// ------------------------------------------------------------------------

/// Encode and validate a single-component name for a relative open. A name
/// containing a separator or NUL could make the NT path-walk escape the
/// held root, so those are refused here regardless of what the caller
/// already checked.
fn component_units(name: &OsStr) -> io::Result<Vec<u16>> {
    let units = name.encode_wide().collect::<Vec<_>>();
    if units.is_empty() || units.len() > (u16::MAX as usize / 2) {
        return Err(invalid_input(
            "held Windows component name is empty or too long",
        ));
    }
    if name == std::ffi::OsStr::new(".")
        || name == std::ffi::OsStr::new("..")
        || units.contains(&0)
        || units.contains(&b'\\' as u16)
        || units.contains(&b'/' as u16)
    {
        return Err(invalid_input(
            "held Windows component name contains an unsafe character",
        ));
    }
    Ok(units)
}

// ------------------------------------------------------------------------
// Raw relative create
// ------------------------------------------------------------------------

/// The single relative-open core. `object_attributes` selects the
/// exact-case (enumerated) vs case-insensitive lookup; `options` carries the
/// directory / non-directory / open-reparse-point flags. The caller
/// classifies the returned handle.
fn create_relative(
    parent: &std::fs::File,
    name: &OsStr,
    access: u32,
    disposition: u32,
    options: u32,
    object_attributes: u32,
) -> io::Result<std::fs::File> {
    let units = component_units(name)?;
    let mut owned = units;
    let unicode = UnicodeString {
        length: (owned.len() * 2) as u16,
        maximum_length: (owned.len() * 2) as u16,
        buffer: owned.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle(),
        object_name: &unicode,
        attributes: object_attributes,
        security_descriptor: core::ptr::null_mut(),
        security_quality_of_service: core::ptr::null_mut(),
    };
    let mut io = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let mut raw: Handle = core::ptr::null_mut();
    // SAFETY: all pointers above stay alive for the duration of the call,
    // and `raw` is only written by the syscall on success.
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &attributes,
            &mut io,
            core::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_ALL,
            disposition,
            options,
            core::ptr::null(),
            0,
        )
    };
    if status < STATUS_SUCCESS_MIN || raw.is_null() {
        return Err(io_from_status(status));
    }
    // SAFETY: the syscall returned a fresh, uniquely owned handle.
    Ok(unsafe { std::fs::File::from_raw_handle(raw) })
}

fn handle_information(file: &std::fs::File) -> io::Result<ByHandleFileInformation> {
    let mut info: ByHandleFileInformation = unsafe { core::mem::zeroed() };
    // SAFETY: `info` is a valid, correctly sized output buffer.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

fn handle_is_reparse(file: &std::fs::File) -> io::Result<bool> {
    Ok(handle_information(file)?.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

/// Refuse a reparse point that a `FILE_OPEN_REPARSE_POINT` relative open
/// handed back: opening the reparse point itself is exactly how no-follow is
/// implemented, but every *traversal* caller must fail closed here instead
/// of silently operating on the link.
fn refuse_reparse(file: std::fs::File) -> io::Result<std::fs::File> {
    if handle_is_reparse(&file)? {
        return Err(invalid_input("held Windows child is a reparse point"));
    }
    Ok(file)
}

// ------------------------------------------------------------------------
// Identity
// ------------------------------------------------------------------------

/// Stable Windows directory/file identity: volume serial plus the file
/// index, the twin of the Unix `(st_dev, st_ino)` pair. Mutable metadata is
/// deliberately excluded. (ReFS 128-bit file IDs truncate into the 64-bit
/// index here; the comparison is still an inequality check between two
/// live handles, never an authorization proof by itself.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
}

/// The kind of a no-follow probed entry. A reparse point (junction, symlink,
/// mount point) is its own kind, the twin of the Unix `S_IFLNK` refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    File,
    ReparsePoint,
}

pub fn handle_identity(file: &std::fs::File) -> io::Result<HandleIdentity> {
    let info = handle_information(file)?;
    Ok(HandleIdentity {
        volume_serial: info.volume_serial,
        file_index: ((info.file_index_high as u64) << 32) | (info.file_index_low as u64),
    })
}

pub fn handle_is_directory(file: &std::fs::File) -> io::Result<bool> {
    Ok(handle_information(file)?.attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
}

pub fn flush(file: &std::fs::File) -> io::Result<()> {
    // SAFETY: the handle is owned by the live `File`.
    if unsafe { FlushFileBuffers(file.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ------------------------------------------------------------------------
// Volume root
// ------------------------------------------------------------------------

/// Open the drive root of an absolute local path (`C:\...` or its verbatim
/// `\\?\C:\...` spelling) without following a reparse point. This is the
/// trusted anchor for a no-reparse component walk, the twin of
/// [`super::held_fd::open_fs_root`].
pub fn open_volume_root(path: &Path) -> io::Result<std::fs::File> {
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            std::path::Prefix::Disk(letter) | std::path::Prefix::VerbatimDisk(letter) => letter,
            _ => {
                return Err(invalid_input(
                    "only local Windows volumes support held skill authority",
                ));
            }
        },
        _ => {
            return Err(invalid_input(
                "Windows held skill root requires an absolute drive path",
            ));
        }
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(invalid_input(
            "Windows held skill root requires a rooted path",
        ));
    }
    let root = format!("{}:\\", char::from(drive));
    let wide = std::ffi::OsStr::new(&root)
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: `wide` is a NUL-terminated path buffer valid for the call.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_ALL,
            core::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            core::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the syscall returned a fresh, uniquely owned handle.
    Ok(unsafe { std::fs::File::from_raw_handle(raw) })
}

// ------------------------------------------------------------------------
// Child opens / creates
// ------------------------------------------------------------------------

/// Open one existing directory child through the held parent, refusing a
/// reparse point and a wrong-kind entry.
pub fn open_dir_child(parent: &std::fs::File, name: &OsStr) -> io::Result<std::fs::File> {
    let file = create_relative(
        parent,
        name,
        GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
    )?;
    refuse_reparse(file)
}

/// Exact-case variant of [`open_dir_child`] for names that came from an
/// enumeration: a case-sensitive NTFS directory may hold both `Foo` and
/// `foo`, and a case-insensitive reopen could pick the wrong sibling.
pub fn open_dir_child_enumerated(
    parent: &std::fs::File,
    name: &OsStr,
) -> io::Result<std::fs::File> {
    let file = create_relative(
        parent,
        name,
        GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        OBJ_DONT_REPARSE,
    )?;
    refuse_reparse(file)
}

/// Open one existing regular-file child through the held parent, refusing a
/// reparse point and a directory.
pub fn open_file_child(parent: &std::fs::File, name: &OsStr) -> io::Result<std::fs::File> {
    let file = create_relative(
        parent,
        name,
        GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
    )?;
    refuse_reparse(file)
}

/// Create one directory child. A collision maps to
/// [`io::ErrorKind::AlreadyExists`] so the open-or-create race ladder can
/// tolerate it.
pub fn create_dir_child(parent: &std::fs::File, name: &OsStr) -> io::Result<()> {
    let file = create_relative(
        parent,
        name,
        GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_CREATE,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
    )?;
    refuse_reparse(file)?;
    Ok(())
}

/// Create one regular-file child exclusively (the twin of Unix
/// `O_CREAT|O_EXCL|O_NOFOLLOW` staging). The file inherits the parent
/// directory's default security: skill package content is ordinary user
/// workspace data, not a private secret, so there is no born-private DACL
/// requirement here (unlike the export/KEK funnels).
pub fn create_file_exclusive_child(
    parent: &std::fs::File,
    name: &OsStr,
) -> io::Result<std::fs::File> {
    create_relative(
        parent,
        name,
        GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
    )
}

// ------------------------------------------------------------------------
// No-follow probe
// ------------------------------------------------------------------------

/// Classify one child entry through the held parent without following a
/// reparse point. `Ok(None)` means the name is absent. The ladder tries the
/// proven directory open first and falls back to the proven regular-file
/// open, so only exercised open modes are used; a reparse point of either
/// shape is opened as itself and reported as [`EntryKind::ReparsePoint`].
pub fn entry_kind_nofollow(parent: &std::fs::File, name: &OsStr) -> io::Result<Option<EntryKind>> {
    let directory_open = create_relative(
        parent,
        name,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
    );
    let opened = match directory_open {
        Ok(file) => Some(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if is_status(&error, STATUS_NOT_A_DIRECTORY) => None,
        Err(error) => return Err(error),
    };
    let file = match opened {
        Some(file) => file,
        None => {
            match create_relative(
                parent,
                name,
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            ) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            }
        }
    };
    let info = handle_information(&file)?;
    if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Ok(Some(EntryKind::ReparsePoint));
    }
    if info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Ok(Some(EntryKind::Directory));
    }
    Ok(Some(EntryKind::File))
}

fn is_status(error: &io::Error, status: i32) -> bool {
    error
        .to_string()
        .contains(&format!("NTSTATUS {status:#010x}"))
}

// ------------------------------------------------------------------------
// Rename / delete effects
// ------------------------------------------------------------------------

/// Open the rename/delete subject with `DELETE` access under the right kind
/// flags. The subject is always opened as the entry itself
/// (`FILE_OPEN_REPARSE_POINT`): renaming a handle that followed a reparse
/// point would move the *target*, never the link, so the no-reparse open is
/// what makes a hostile substitution fail closed at identity checks instead
/// of redirecting the effect.
fn open_subject(
    parent: &std::fs::File,
    name: &OsStr,
    directory: bool,
) -> io::Result<std::fs::File> {
    let options = if directory {
        FILE_DIRECTORY_FILE
    } else {
        FILE_NON_DIRECTORY_FILE
    } | FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT;
    create_relative(
        parent,
        name,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        options,
        OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
    )
}

/// Rename a child between held parents, publishing without replacement (a
/// hostile destination collision fails instead of overwriting). The twin of
/// Unix `renameat2(..., RENAME_NOREPLACE)`.
pub fn rename_child_noreplace(
    source_parent: &std::fs::File,
    source: &OsStr,
    destination_parent: &std::fs::File,
    destination: &OsStr,
) -> io::Result<()> {
    rename_child(
        source_parent,
        source,
        destination_parent,
        destination,
        false,
    )
}

/// Rename a child between held parents, replacing an existing regular
/// destination. The twin of Unix `renameat`. Only the atomic-write publish
/// step may use this, and only after the destination was probed to be a
/// non-reparse regular file.
pub fn rename_child_replace(
    source_parent: &std::fs::File,
    source: &OsStr,
    destination_parent: &std::fs::File,
    destination: &OsStr,
) -> io::Result<()> {
    rename_child(source_parent, source, destination_parent, destination, true)
}

fn rename_child(
    source_parent: &std::fs::File,
    source: &OsStr,
    destination_parent: &std::fs::File,
    destination: &OsStr,
    replace_if_exists: bool,
) -> io::Result<()> {
    // The subject's kind must be known before it can be opened for DELETE;
    // a missing subject is the caller's NotFound to report.
    let Some(kind) = entry_kind_nofollow(source_parent, source)? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "held Windows rename source does not exist",
        ));
    };
    let subject = open_subject(source_parent, source, kind == EntryKind::Directory)?;
    let to = component_units(destination)?;
    // FILE_RENAME_INFORMATION: the replace flag, the held destination
    // parent as `RootDirectory`, and the single-component relative name.
    let name_offset = core::mem::offset_of!(FileRenameInformation, file_name);
    let mut buffer = vec![0u8; name_offset + to.len() * 2];
    // SAFETY: `buffer` is sized for the full packed record and the raw
    // pointer writes below stay within its bounds.
    unsafe {
        let info = buffer.as_mut_ptr().cast::<FileRenameInformation>();
        (*info).replace_if_exists = u8::from(replace_if_exists);
        (*info).root_directory = destination_parent.as_raw_handle();
        (*info).file_name_length = (to.len() * 2) as u32;
        core::ptr::copy_nonoverlapping(
            to.as_ptr().cast::<u8>(),
            buffer.as_mut_ptr().add(name_offset),
            to.len() * 2,
        );
    }
    let mut io = IoStatusBlock {
        status: 0,
        information: 0,
    };
    // SAFETY: `buffer` holds a valid packed FileRenameInformation record
    // for the duration of the call.
    let status = unsafe {
        NtSetInformationFile(
            subject.as_raw_handle(),
            &mut io,
            buffer.as_ptr().cast(),
            buffer.len() as u32,
            FILE_RENAME_INFORMATION_CLASS,
        )
    };
    drop(subject);
    if status < STATUS_SUCCESS_MIN {
        return Err(io_from_status(status));
    }
    Ok(())
}

/// Delete one regular-file child through the held parent (the twin of
/// `unlinkat(..., 0)`). The deletion is verified observable: a pending
/// disposition that never took effect is an error, never a silent no-op.
pub fn unlink_child(parent: &std::fs::File, name: &OsStr) -> io::Result<()> {
    delete_child(parent, name, EntryKind::File, false)
}

/// Exact-case variant of [`unlink_child`] for enumerated names.
pub fn unlink_child_enumerated(parent: &std::fs::File, name: &OsStr) -> io::Result<()> {
    delete_child(parent, name, EntryKind::File, true)
}

/// Delete one empty directory child through the held parent (the twin of
/// `unlinkat(..., AT_REMOVEDIR)`). A non-empty directory fails closed.
pub fn remove_dir_child(parent: &std::fs::File, name: &OsStr) -> io::Result<()> {
    delete_child(parent, name, EntryKind::Directory, false)
}

/// Exact-case variant of [`remove_dir_child`] for enumerated names.
pub fn remove_dir_child_enumerated(parent: &std::fs::File, name: &OsStr) -> io::Result<()> {
    delete_child(parent, name, EntryKind::Directory, true)
}

fn delete_child(
    parent: &std::fs::File,
    name: &OsStr,
    expected: EntryKind,
    enumerated: bool,
) -> io::Result<()> {
    let Some(kind) = entry_kind_nofollow(parent, name)? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "held Windows delete subject does not exist",
        ));
    };
    if kind != expected {
        return Err(invalid_input(
            "held Windows delete subject has the wrong kind",
        ));
    }
    let object_attributes = if enumerated {
        OBJ_DONT_REPARSE
    } else {
        OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
    };
    let options = if expected == EntryKind::Directory {
        FILE_DIRECTORY_FILE
    } else {
        FILE_NON_DIRECTORY_FILE
    } | FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT;
    let subject = create_relative(
        parent,
        name,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        options,
        object_attributes,
    )?;
    let info = FileDispositionInformation { delete_file: 1 };
    let mut io = IoStatusBlock {
        status: 0,
        information: 0,
    };
    // SAFETY: `info` is a valid one-byte FileDispositionInformation record.
    let status = unsafe {
        NtSetInformationFile(
            subject.as_raw_handle(),
            &mut io,
            (&info as *const FileDispositionInformation).cast(),
            core::mem::size_of::<FileDispositionInformation>() as u32,
            FILE_DISPOSITION_INFORMATION_CLASS,
        )
    };
    if status < STATUS_SUCCESS_MIN {
        let error = io_from_status(status);
        drop(subject);
        return Err(error);
    }
    drop(subject);
    // The disposition completes when the last handle closes; verify the
    // entry is really gone so a non-empty directory (or any other pending
    // delete that failed at close time) is reported as an error.
    if entry_kind_nofollow(parent, name)?.is_some() {
        return Err(io::Error::other("held Windows delete did not take effect"));
    }
    Ok(())
}

// ------------------------------------------------------------------------
// Enumeration
// ------------------------------------------------------------------------

/// List the child names of a held directory without following any reparse
/// point. Names are length-prefixed UTF-16 records, never NUL-terminated;
/// `.` and `..` are excluded. The twin of the Unix `readdir` walk. The
/// caller re-opens each name through the same held handle with the
/// exact-case (`_enumerated`) variants so a case-sensitive directory cannot
/// redirect a delete onto a case-twin sibling.
pub fn list_children(dir: &std::fs::File) -> io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    let mut restart = true;
    loop {
        // u64 backing storage so the native records stay aligned.
        let mut storage = vec![0u64; 8 * 1024];
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        // SAFETY: `storage` is a valid, sized, aligned buffer for the
        // duration of the call.
        let status = unsafe {
            NtQueryDirectoryFile(
                dir.as_raw_handle(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut io,
                storage.as_mut_ptr().cast(),
                (storage.len() * core::mem::size_of::<u64>()) as u32,
                FILE_NAMES_INFORMATION_CLASS,
                1,
                core::ptr::null(),
                u8::from(restart),
            )
        };
        restart = false;
        if status == STATUS_NO_MORE_FILES {
            break;
        }
        if status < STATUS_SUCCESS_MIN {
            return Err(io_from_status(status));
        }
        let header_len = core::mem::offset_of!(FileNamesInformation, file_name);
        if io.information < header_len {
            return Err(io::Error::other(
                "held Windows enumeration returned a truncated record",
            ));
        }
        // SAFETY: `storage` holds at least one complete record; the fields
        // below are validated against `io.information` before the name is
        // read.
        let record = storage.as_ptr().cast::<FileNamesInformation>();
        if unsafe { (*record).next_entry_offset } != 0 {
            return Err(io::Error::other(
                "single-entry held Windows enumeration returned a chained record",
            ));
        }
        let name_bytes = unsafe { (*record).file_name_length } as usize;
        if name_bytes % 2 != 0 || header_len + name_bytes > io.information {
            return Err(io::Error::other(
                "held Windows enumeration returned an invalid name",
            ));
        }
        // SAFETY: the name units lie within the buffer for `name_bytes`.
        let units = unsafe {
            core::slice::from_raw_parts(
                core::ptr::addr_of!((*record).file_name).cast::<u16>(),
                name_bytes / 2,
            )
        };
        let name = OsString::from_wide(units);
        if name != std::ffi::OsString::from(".") && name != std::ffi::OsString::from("..") {
            names.push(name);
        }
    }
    Ok(names)
}

// ------------------------------------------------------------------------
// Tests (Windows runner only; see UNCHECKED-FILES.md at the repo root)
// ------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt as _;

    /// Open the test directory itself as a held handle through plain std
    /// APIs: `FILE_FLAG_BACKUP_SEMANTICS` as a custom flag is what lets
    /// `OpenOptions` hand back a directory handle on Windows. The tests keep
    /// the `TempDir` guard alive so the tree exists for the whole test.
    fn held_test_root() -> (tempfile::TempDir, std::fs::File) {
        let temp = tempfile::TempDir::new().unwrap();
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS as i32)
            .open(temp.path())
            .unwrap();
        (temp, handle)
    }

    #[test]
    fn open_dir_child_refuses_reparse_and_wrong_kind() {
        let (temp, root) = held_test_root();
        std::fs::write(temp.path().join("leaf"), b"file").unwrap();
        assert!(open_dir_child(&root, std::ffi::OsStr::new("leaf")).is_err());
        assert!(open_file_child(&root, std::ffi::OsStr::new("missing")).is_err());
        std::fs::create_dir(temp.path().join("target")).unwrap();
        if std::os::windows::fs::symlink_dir(temp.path().join("target"), temp.path().join("alias"))
            .is_ok()
        {
            assert!(open_dir_child(&root, std::ffi::OsStr::new("alias")).is_err());
            assert_eq!(
                entry_kind_nofollow(&root, std::ffi::OsStr::new("alias"))
                    .unwrap()
                    .unwrap(),
                EntryKind::ReparsePoint
            );
        }
    }

    #[test]
    fn create_and_rename_and_delete_children() {
        let (temp, root) = held_test_root();
        create_dir_child(&root, std::ffi::OsStr::new("pkg")).unwrap();
        assert_eq!(
            entry_kind_nofollow(&root, std::ffi::OsStr::new("pkg"))
                .unwrap()
                .unwrap(),
            EntryKind::Directory
        );
        // Collision maps to AlreadyExists.
        assert_eq!(
            create_dir_child(&root, std::ffi::OsStr::new("pkg"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        // Rename publishes without replacement and a missing source is
        // the caller's NotFound.
        rename_child_noreplace(
            &root,
            std::ffi::OsStr::new("pkg"),
            &root,
            std::ffi::OsStr::new("staged"),
        )
        .unwrap();
        assert_eq!(
            rename_child_noreplace(
                &root,
                std::ffi::OsStr::new("missing"),
                &root,
                std::ffi::OsStr::new("other"),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::NotFound
        );
        let mut file = create_file_exclusive_child(&root, std::ffi::OsStr::new("data")).unwrap();
        use std::io::Write as _;
        file.write_all(b"held").unwrap();
        drop(file);
        unlink_child(&root, std::ffi::OsStr::new("data")).unwrap();
        assert!(
            entry_kind_nofollow(&root, std::ffi::OsStr::new("data"))
                .unwrap()
                .is_none()
        );
        remove_dir_child(&root, std::ffi::OsStr::new("staged")).unwrap();
        // Deleting a non-empty directory fails closed.
        std::fs::create_dir(temp.path().join("full")).unwrap();
        std::fs::write(temp.path().join("full").join("leaf.txt"), b"content").unwrap();
        assert!(remove_dir_child(&root, std::ffi::OsStr::new("full")).is_err());
        assert!(
            entry_kind_nofollow(&root, std::ffi::OsStr::new("full"))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn list_children_names_are_relative_and_bounded() {
        let (_temp, root) = held_test_root();
        create_dir_child(&root, std::ffi::OsStr::new("a")).unwrap();
        create_dir_child(&root, std::ffi::OsStr::new("b")).unwrap();
        let mut names = list_children(&root).unwrap();
        names.sort();
        assert_eq!(
            names,
            vec![OsString::from("a"), OsString::from("b")],
            "no . or .. entries"
        );
        // Separator and traversal spellings are refused outright, so a
        // hostile name can never escape the held root.
        assert!(open_dir_child(&root, std::ffi::OsStr::new("..\\escape")).is_err());
        assert!(open_dir_child(&root, std::ffi::OsStr::new("a/b")).is_err());
        assert!(open_dir_child(&root, std::ffi::OsStr::new("..")).is_err());
    }
}
