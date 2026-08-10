//! Held directory authority for security-sensitive publication.
//!
//! Operational authority is the open directory handle, never the diagnostic
//! path retained for errors.  Callers persist [`DirectoryIdentity`] and must
//! carry this capability through every filesystem effect.

use std::fs::File;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectoryIdentity {
    pub(crate) platform: &'static str,
    pub(crate) stable_digest: String,
    pub(crate) canonical_binding_digest: String,
}

#[derive(Debug)]
pub(crate) struct HeldDirectoryAuthority {
    imp: imp::HeldDirectory,
    identity: DirectoryIdentity,
}

impl HeldDirectoryAuthority {
    pub(crate) fn open_existing(path: &Path) -> Result<Self> {
        let imp = imp::HeldDirectory::open_existing(path)?;
        let identity = imp.identity()?;
        Ok(Self { imp, identity })
    }

    pub(crate) fn identity(&self) -> &DirectoryIdentity {
        &self.identity
    }

    /// A diagnostic spelling only. It is never filesystem authority.
    pub(crate) fn diagnostic_path(&self) -> &Path {
        self.imp.diagnostic_path()
    }

    pub(crate) fn create_file_exclusive(&self, name: &str) -> Result<File> {
        validate_component(name)?;
        self.imp.create_file_exclusive(name)
    }

    pub(crate) fn rename_noreplace(&self, from: &str, to: &str) -> Result<()> {
        validate_component(from)?;
        validate_component(to)?;
        self.imp.rename_noreplace(from, to)
    }

    pub(crate) fn unlink(&self, name: &str) -> Result<()> {
        validate_component(name)?;
        self.imp.unlink(name)
    }

    pub(crate) fn sync(&self) -> Result<()> {
        self.imp.sync()
    }
}

fn validate_component(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value != "." && value != ".." && !value.contains(['/', '\\', '\0']),
        "unsafe held-directory entry name"
    );
    Ok(())
}

fn digest(parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    crate::intel::hex_lower(&hash.finalize())
}

#[cfg(unix)]
mod imp {
    use std::ffi::{CString, OsStr};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    use super::*;

    #[derive(Debug)]
    pub(super) struct HeldDirectory {
        dir: File,
        diagnostic_path: PathBuf,
    }

    impl HeldDirectory {
        pub(super) fn open_existing(path: &Path) -> Result<Self> {
            ensure!(path.is_absolute(), "held directory path must be absolute");
            let mut names = Vec::new();
            for component in path.components() {
                match component {
                    Component::RootDir => {}
                    Component::Normal(name) => names.push(name.as_bytes().to_vec()),
                    _ => anyhow::bail!("held directory path is not canonical lexical input"),
                }
            }
            let mut dir = open_absolute_root()?;
            let mut walked = PathBuf::from("/");
            for bytes in &names {
                let name = CString::new(bytes.as_slice()).context("directory component has NUL")?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error()).with_context(|| {
                        format!(
                            "opening held directory component {:?}",
                            OsStr::from_bytes(bytes)
                        )
                    });
                }
                dir = unsafe { File::from_raw_fd(fd) };
                walked.push(OsStr::from_bytes(bytes));
            }
            let metadata = dir.metadata()?;
            ensure!(metadata.is_dir(), "held authority is not a directory");
            ensure!(
                metadata.uid() == unsafe { libc::geteuid() },
                "held directory owner differs from daemon user"
            );
            ensure!(
                metadata.mode() & 0o777 == 0o700,
                "held directory must have mode 0700"
            );
            Ok(Self {
                dir,
                diagnostic_path: walked,
            })
        }

        pub(super) fn identity(&self) -> Result<DirectoryIdentity> {
            let metadata = self.dir.metadata()?;
            let dev = metadata.dev().to_be_bytes();
            let ino = metadata.ino().to_be_bytes();
            let uid = metadata.uid().to_be_bytes();
            let mode = (metadata.mode() & 0o7777).to_be_bytes();
            let stable_digest = digest(&[b"held-directory-unix-v1", &dev, &ino, &uid, &mode]);
            let canonical_binding_digest =
                digest(&[b"held-directory-binding-unix-v1", stable_digest.as_bytes()]);
            Ok(DirectoryIdentity {
                platform: "unix-v1",
                stable_digest,
                canonical_binding_digest,
            })
        }

        pub(super) fn diagnostic_path(&self) -> &Path {
            &self.diagnostic_path
        }

        pub(super) fn create_file_exclusive(&self, name: &str) -> Result<File> {
            let name = CString::new(name)?;
            let fd = unsafe {
                libc::openat(
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600 as libc::mode_t,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("exclusive held-directory create");
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        }

        pub(super) fn rename_noreplace(&self, from: &str, to: &str) -> Result<()> {
            let from = CString::new(from)?;
            let to = CString::new(to)?;
            #[cfg(target_os = "linux")]
            {
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        self.dir.as_raw_fd(),
                        from.as_ptr(),
                        self.dir.as_raw_fd(),
                        to.as_ptr(),
                        1u32,
                    )
                };
                if result == 0 {
                    return Ok(());
                }
                let error = std::io::Error::last_os_error();
                if !matches!(
                    error.raw_os_error(),
                    Some(libc::ENOSYS) | Some(libc::EINVAL)
                ) {
                    return Err(error).context("held-directory no-replace rename");
                }
            }
            let linked = unsafe {
                libc::linkat(
                    self.dir.as_raw_fd(),
                    from.as_ptr(),
                    self.dir.as_raw_fd(),
                    to.as_ptr(),
                    0,
                )
            };
            if linked != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("held-directory no-replace link");
            }
            let removed = unsafe { libc::unlinkat(self.dir.as_raw_fd(), from.as_ptr(), 0) };
            if removed != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("held-directory source unlink");
            }
            Ok(())
        }

        pub(super) fn unlink(&self, name: &str) -> Result<()> {
            let name = CString::new(name)?;
            ensure!(
                unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) } == 0,
                "held-directory unlink failed: {}",
                std::io::Error::last_os_error()
            );
            Ok(())
        }
        pub(super) fn sync(&self) -> Result<()> {
            self.dir.sync_all().context("sync held directory")
        }
    }

    fn open_absolute_root() -> Result<File> {
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("opening filesystem root");
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use std::ptr;

    use super::*;

    type Handle = *mut c_void;
    const INVALID_HANDLE_VALUE: Handle = -1_isize as Handle;
    const STATUS_SUCCESS_MIN: i32 = 0;
    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    const OBJ_DONT_REPARSE: u32 = 0x1000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    const FILE_SHARE_ALL: u32 = 0x7;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_DIRECTORY_FILE: u32 = 0x1;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

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
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
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
            ea: *const c_void,
            ea_len: u32,
        ) -> i32;
        fn NtSetInformationFile(
            file: Handle,
            io: *mut IoStatusBlock,
            information: *const c_void,
            length: u32,
            class: u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut c_void,
            creation: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn GetFileInformationByHandle(
            file: Handle,
            information: *mut ByHandleFileInformation,
        ) -> i32;
        fn FlushFileBuffers(file: Handle) -> i32;
    }

    #[derive(Debug)]
    pub(super) struct HeldDirectory {
        dir: File,
        diagnostic_path: PathBuf,
    }
    impl HeldDirectory {
        pub(super) fn open_existing(path: &Path) -> Result<Self> {
            use std::path::Prefix;
            ensure!(path.is_absolute(), "held directory path must be absolute");
            let mut components = path.components();
            let drive = match components.next() {
                Some(Component::Prefix(prefix)) => match prefix.kind() {
                    Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
                    _ => anyhow::bail!("only local Windows volumes support held authority"),
                },
                _ => anyhow::bail!("Windows held authority requires an absolute drive path"),
            };
            ensure!(
                matches!(components.next(), Some(Component::RootDir)),
                "Windows held authority requires rooted path"
            );
            let root = format!("{}:\\", char::from(drive));
            let root_wide = std::ffi::OsStr::new(&root)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let raw = unsafe {
                CreateFileW(
                    root_wide.as_ptr(),
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_ALL,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    ptr::null_mut(),
                )
            };
            ensure!(
                raw != INVALID_HANDLE_VALUE,
                "opening held Windows volume root failed: {}",
                std::io::Error::last_os_error()
            );
            let mut dir = unsafe { File::from_raw_handle(raw) };
            for component in components {
                let Component::Normal(name) = component else {
                    anyhow::bail!("Windows held directory path is not lexical")
                };
                let wide = name.encode_wide().collect::<Vec<_>>();
                dir = open_relative(
                    &dir,
                    &wide,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )?;
                verify_directory_handle(&dir)?;
            }
            verify_directory_handle(&dir)?;
            verify_private_dacl_handle(&dir)?;
            Ok(Self {
                dir,
                diagnostic_path: path.to_path_buf(),
            })
        }
        pub(super) fn identity(&self) -> Result<DirectoryIdentity> {
            let info = handle_information(&self.dir)?;
            let volume = info.volume_serial.to_be_bytes();
            let high = info.file_index_high.to_be_bytes();
            let low = info.file_index_low.to_be_bytes();
            let stable_digest = digest(&[b"held-directory-windows-v1", &volume, &high, &low]);
            let canonical_binding_digest = digest(&[
                b"held-directory-binding-windows-v1",
                stable_digest.as_bytes(),
            ]);
            Ok(DirectoryIdentity {
                platform: "windows-v1",
                stable_digest,
                canonical_binding_digest,
            })
        }
        pub(super) fn diagnostic_path(&self) -> &Path {
            &self.diagnostic_path
        }
        pub(super) fn create_file_exclusive(&self, name: &str) -> Result<File> {
            let wide = std::ffi::OsStr::new(name).encode_wide().collect::<Vec<_>>();
            let file = open_relative(
                &self.dir,
                &wide,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE,
                GENERIC_READ
                    | GENERIC_WRITE
                    | DELETE
                    | SYNCHRONIZE
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES,
            )?;
            verify_regular_handle(&file)?;
            Ok(file)
        }
        pub(super) fn rename_noreplace(&self, from: &str, to: &str) -> Result<()> {
            let from = std::ffi::OsStr::new(from).encode_wide().collect::<Vec<_>>();
            let file = open_relative(
                &self.dir,
                &from,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            )?;
            let to = std::ffi::OsStr::new(to).encode_wide().collect::<Vec<_>>();
            // FILE_RENAME_INFORMATION: ReplaceIfExists=false, RootDirectory=held dir.
            let name_offset = std::mem::offset_of!(FileRenameInformation, file_name);
            let mut buffer = vec![0u8; name_offset + to.len() * 2];
            unsafe {
                let info = buffer.as_mut_ptr().cast::<FileRenameInformation>();
                (*info).replace_if_exists = 0;
                (*info).root_directory = self.dir.as_raw_handle();
                (*info).file_name_length = (to.len() * 2) as u32;
                ptr::copy_nonoverlapping(
                    to.as_ptr().cast::<u8>(),
                    buffer.as_mut_ptr().add(name_offset),
                    to.len() * 2,
                );
            }
            let mut io = IoStatusBlock {
                status: 0,
                information: 0,
            };
            let status = unsafe {
                NtSetInformationFile(
                    file.as_raw_handle(),
                    &mut io,
                    buffer.as_ptr().cast(),
                    buffer.len() as u32,
                    10,
                )
            };
            ensure!(
                status >= STATUS_SUCCESS_MIN,
                "held Windows no-replace rename failed with NTSTATUS {status:#x}"
            );
            Ok(())
        }
        pub(super) fn unlink(&self, name: &str) -> Result<()> {
            let wide = std::ffi::OsStr::new(name).encode_wide().collect::<Vec<_>>();
            let file = open_relative(
                &self.dir,
                &wide,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
                DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            )?;
            let info = FileDispositionInformation { delete_file: 1 };
            let mut io = IoStatusBlock {
                status: 0,
                information: 0,
            };
            let status = unsafe {
                NtSetInformationFile(
                    file.as_raw_handle(),
                    &mut io,
                    (&info as *const FileDispositionInformation).cast(),
                    size_of::<FileDispositionInformation>() as u32,
                    13,
                )
            };
            ensure!(
                status >= STATUS_SUCCESS_MIN,
                "held Windows unlink failed with NTSTATUS {status:#x}"
            );
            Ok(())
        }
        pub(super) fn sync(&self) -> Result<()> {
            ensure!(
                unsafe { FlushFileBuffers(self.dir.as_raw_handle()) } != 0,
                "syncing held Windows directory failed: {}",
                std::io::Error::last_os_error()
            );
            Ok(())
        }
    }

    fn open_relative(
        parent: &File,
        name: &[u16],
        disposition: u32,
        kind: u32,
        access: u32,
    ) -> Result<File> {
        ensure!(
            !name.is_empty() && name.len() <= (u16::MAX as usize / 2),
            "invalid Windows relative name"
        );
        let mut owned = name.to_vec();
        let unicode = UnicodeString {
            length: (owned.len() * 2) as u16,
            maximum_length: (owned.len() * 2) as u16,
            buffer: owned.as_mut_ptr(),
        };
        let attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: parent.as_raw_handle(),
            object_name: &unicode,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut raw = ptr::null_mut();
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                access,
                &attributes,
                &mut io,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_ALL,
                disposition,
                kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        ensure!(
            status >= STATUS_SUCCESS_MIN && !raw.is_null(),
            "held Windows relative open failed with NTSTATUS {status:#x}"
        );
        Ok(unsafe { File::from_raw_handle(raw) })
    }

    fn handle_information(file: &File) -> Result<ByHandleFileInformation> {
        let mut info = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
            "querying held Windows identity failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(info)
    }
    fn verify_directory_handle(file: &File) -> Result<()> {
        let info = handle_information(file)?;
        ensure!(
            info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "held Windows directory is a reparse point"
        );
        ensure!(
            file.metadata()?.is_dir(),
            "held Windows authority component is not a directory"
        );
        Ok(())
    }
    fn verify_regular_handle(file: &File) -> Result<()> {
        let info = handle_information(file)?;
        ensure!(
            info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && info.links == 1
                && file.metadata()?.is_file(),
            "held Windows entry is not a singly-linked non-reparse regular file"
        );
        Ok(())
    }

    fn verify_private_dacl_handle(file: &File) -> Result<()> {
        crate::goal_scratch::verify_private_dacl_handle(file)
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::*;
    #[derive(Debug)]
    pub(super) struct HeldDirectory;
    impl HeldDirectory {
        pub(super) fn open_existing(_: &Path) -> Result<Self> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn identity(&self) -> Result<DirectoryIdentity> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn diagnostic_path(&self) -> &Path {
            Path::new("")
        }
        pub(super) fn create_file_exclusive(&self, _: &str) -> Result<File> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn rename_noreplace(&self, _: &str, _: &str) -> Result<()> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn unlink(&self, _: &str) -> Result<()> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn sync(&self) -> Result<()> {
            anyhow::bail!("held directory authority is unavailable")
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    #[test]
    fn descriptor_walk_rejects_alias_and_survives_path_replacement() {
        let temp = tempfile::TempDir::new().unwrap();
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = temp.path().join("alias");
        symlink(&target, &alias).unwrap();
        assert!(HeldDirectoryAuthority::open_existing(&alias).is_err());
        let held = HeldDirectoryAuthority::open_existing(&target).unwrap();
        let original = held.identity().clone();
        std::fs::rename(&target, temp.path().join("moved")).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_ne!(
            original,
            HeldDirectoryAuthority::open_existing(&target)
                .unwrap()
                .identity()
                .clone()
        );
        let mut file = held.create_file_exclusive("proof.tmp").unwrap();
        file.write_all(b"held").unwrap();
        assert!(temp.path().join("moved/proof.tmp").is_file());
        assert!(!target.join("proof.tmp").exists());
    }

    #[test]
    fn exclusive_publication_never_replaces_target() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = HeldDirectoryAuthority::open_existing(temp.path()).unwrap();
        held.create_file_exclusive("temp")
            .unwrap()
            .write_all(b"new")
            .unwrap();
        held.create_file_exclusive("output")
            .unwrap()
            .write_all(b"old")
            .unwrap();
        assert!(held.rename_noreplace("temp", "output").is_err());
        assert_eq!(std::fs::read(temp.path().join("output")).unwrap(), b"old");
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::io::Write as _;
    use std::os::windows::fs::symlink_dir;

    use super::*;

    #[test]
    fn held_windows_authority_rejects_reparse_and_publishes_noreplace() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        let held = HeldDirectoryAuthority::open_existing(&output).unwrap();
        held.create_file_exclusive("temporary")
            .unwrap()
            .write_all(b"new")
            .unwrap();
        held.create_file_exclusive("published")
            .unwrap()
            .write_all(b"old")
            .unwrap();
        assert!(held.rename_noreplace("temporary", "published").is_err());
        assert_eq!(std::fs::read(output.join("published")).unwrap(), b"old");
        let alias = temp.path().join("alias");
        if symlink_dir(&output, &alias).is_ok() {
            assert!(HeldDirectoryAuthority::open_existing(&alias).is_err());
        }
    }

    #[test]
    fn held_windows_capability_survives_name_replacement() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        let held = HeldDirectoryAuthority::open_existing(&output).unwrap();
        let original = held.identity().clone();
        let moved = temp.path().join("moved");
        std::fs::rename(&output, &moved).unwrap();
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        assert_ne!(
            original,
            HeldDirectoryAuthority::open_existing(&output)
                .unwrap()
                .identity()
                .clone()
        );
        held.create_file_exclusive("proof").unwrap();
        assert!(moved.join("proof").is_file());
        assert!(!output.join("proof").exists());
    }
}
