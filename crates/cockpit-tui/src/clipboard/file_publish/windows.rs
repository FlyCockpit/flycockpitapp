//! Windows atomic no-clobber publish: a handle-relative temp create, then
//! `SetFileInformationByHandle(FileRenameInfoEx)` with
//! `RootDirectory` set to the held parent directory handle and no
//! `FILE_RENAME_FLAG_REPLACE_IF_EXISTS` bit. `MoveFileExW` and path-based
//! check/rename are never used.

use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, RawHandle};
use std::path::Path;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE,
    RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FileAttributeTagInfo, FileRenameInfoEx,
    FlushFileBuffers, GetFileInformationByHandleEx, SYNCHRONIZE, SetFileInformationByHandle,
    WriteFile,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::{PublishError, Published};

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn last_error(context: &str) -> PublishError {
    PublishError::Io(format!("{context}: {}", io::Error::last_os_error()))
}

fn open_parent_nofollow(parent: &Path) -> Result<std::fs::File, PublishError> {
    let wide_path = wide(parent.as_os_str());
    // SAFETY: `wide_path` is a live NUL-terminated string for the call.
    // `FILE_FLAG_OPEN_REPARSE_POINT` means a reparse point at the parent
    // itself is opened rather than followed, so it can be rejected below
    // instead of silently traversed.
    let handle = unsafe {
        windows_sys::Win32::Storage::FileSystem::CreateFileW(
            wide_path.as_ptr(),
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            // `CreateFileW`'s `dwCreationDisposition` uses the Win32
            // `FILE_CREATION_DISPOSITION` values, NOT the NT
            // `NTCREATEFILE_CREATE_DISPOSITION` values used elsewhere in
            // this module for `NtCreateFile` — they share numeric space
            // (`Wdk::FILE_OPEN == 1 == Win32::CREATE_NEW`) so mixing them
            // up compiles silently but is a different verb. The parent
            // directory is never created by this module (the destination
            // directory must already exist), so this must be
            // `OPEN_EXISTING`, not the NT-style `FILE_OPEN`.
            windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        return Err(if error.kind() == io::ErrorKind::NotFound {
            PublishError::ParentMissing
        } else {
            PublishError::Io(format!("opening parent directory: {error}"))
        });
    }
    // SAFETY: `handle` was just returned by `CreateFileW` and is uniquely owned.
    let file = unsafe { std::fs::File::from_raw_handle(handle as RawHandle) };
    reject_reparse_and_require_directory(file.as_raw_handle() as HANDLE)?;
    Ok(file)
}

fn reject_reparse_and_require_directory(handle: HANDLE) -> Result<(), PublishError> {
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
        return Err(last_error("checking parent directory"));
    }
    if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PublishError::ParentNotADirectory);
    }
    if info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(PublishError::ParentNotADirectory);
    }
    Ok(())
}

fn open_relative(
    parent: HANDLE,
    name: &std::ffi::OsStr,
    desired_access: u32,
    create_disposition: u32,
) -> io::Result<std::fs::File> {
    let mut name_wide = wide(name);
    name_wide.pop();
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
        | FILE_NON_DIRECTORY_FILE;
    // SAFETY: `parent` is a live, retained directory handle; the name
    // buffer, object attributes, and status block remain live for the
    // call. Resolution is relative to `RootDirectory` only — never a path.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &object_attributes,
            &mut io_status,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
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

fn write_all_and_flush(file: &std::fs::File, bytes: &[u8]) -> io::Result<()> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut offset = 0usize;
    while offset < bytes.len() {
        let mut written: u32 = 0;
        // SAFETY: `handle` is live; the slice covers `bytes[offset..]`.
        let ok = unsafe {
            WriteFile(
                handle,
                bytes[offset..].as_ptr(),
                (bytes.len() - offset) as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
        }
        offset += written as usize;
    }
    // SAFETY: `handle` is live for the call.
    if unsafe { FlushFileBuffers(handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Publish the open temp handle under `dest_name`, resolved relative to
/// the held parent handle, with no replace-if-exists bit set.
fn publish_no_replace(
    temp: &std::fs::File,
    parent: HANDLE,
    dest_name: &std::ffi::OsStr,
) -> io::Result<()> {
    let dest_wide = wide(dest_name);
    let name_bytes = ((dest_wide.len() - 1) * std::mem::size_of::<u16>()) as u32;
    let header_bytes = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let total_bytes = header_bytes + name_bytes as usize;
    let word_bytes = std::mem::size_of::<usize>();
    let mut storage = vec![0usize; total_bytes.div_ceil(word_bytes)];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `storage` is pointer-aligned and large enough for the fixed
    // header plus the exact UTF-16 destination bytes (no trailing NUL —
    // `FileNameLength` is exact). `parent` is the live, retained directory
    // handle; `temp` was opened with `DELETE` access.
    unsafe {
        (*info).Anonymous.Flags = 0; // No `FILE_RENAME_FLAG_REPLACE_IF_EXISTS`.
        (*info).RootDirectory = parent;
        (*info).FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(
            dest_wide.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            dest_wide.len() - 1,
        );
    }
    // SAFETY: `info` points to a live, correctly sized rename-info buffer.
    let renamed = unsafe {
        SetFileInformationByHandle(
            temp.as_raw_handle() as HANDLE,
            FileRenameInfoEx,
            info.cast(),
            total_bytes as u32,
        )
    };
    if renamed != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn publish(
    target: &Path,
    bytes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Published, PublishError> {
    let parent_path = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dest_name = target
        .file_name()
        .ok_or_else(|| PublishError::Io("target has no file name".to_string()))?;
    let parent = open_parent_nofollow(parent_path)?;
    let parent_handle = parent.as_raw_handle() as HANDLE;

    let temp_name = format!(".cockpit-copy-{:032x}.tmp", temp_suffix());
    let temp_name_os: std::ffi::OsString = temp_name.into();
    let temp = open_relative(
        parent_handle,
        &temp_name_os,
        DELETE
            | FILE_WRITE_DATA
            | FILE_WRITE_ATTRIBUTES
            | FILE_READ_ATTRIBUTES
            | GENERIC_READ
            | SYNCHRONIZE,
        FILE_CREATE,
    )
    .map_err(|e| PublishError::Io(format!("creating temp file: {e}")))?;

    if let Err(error) = write_all_and_flush(&temp, bytes) {
        remove_open_file(&temp);
        return Err(PublishError::Io(format!("writing temp file: {error}")));
    }

    if is_cancelled() {
        remove_open_file(&temp);
        return Err(PublishError::Cancelled);
    }

    match publish_no_replace(&temp, parent_handle, dest_name) {
        // `SetFileInformationByHandle(FileRenameInfoEx)` completing without
        // error is NTFS-transactional for the rename itself; unlike POSIX
        // there is no separate directory-fsync step that can fail
        // independently afterward, so there is no partial state to
        // represent here — durability is always confirmed on success.
        Ok(()) => Ok(Published {
            path: parent_path.join(dest_name),
            bytes_written: bytes.len() as u64,
            durability_confirmed: true,
        }),
        Err(error) => {
            remove_open_file(&temp);
            if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
                Err(PublishError::TargetExists)
            } else {
                Err(PublishError::Io(format!("publishing file: {error}")))
            }
        }
    }
}

fn remove_open_file(file: &std::fs::File) {
    use windows_sys::Win32::Storage::FileSystem::{FILE_DISPOSITION_INFO, FileDispositionInfo};
    let disposition = FILE_DISPOSITION_INFO {
        DeleteFile: true as _,
    };
    // SAFETY: `file` was opened with `DELETE` access; `disposition` matches
    // the exact layout `FileDispositionInfo` requires. Cleanup of our own
    // not-yet-published temp file only — never the caller's target.
    unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileDispositionInfo,
            std::ptr::from_ref(&disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        );
    }
}

fn temp_suffix() -> u128 {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    u128::from_le_bytes(bytes)
}
