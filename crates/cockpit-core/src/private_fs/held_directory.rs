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
        canonical_components: Vec<Vec<u8>>,
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
                canonical_components: names,
            })
        }

        pub(super) fn identity(&self) -> Result<DirectoryIdentity> {
            let metadata = self.dir.metadata()?;
            let dev = metadata.dev().to_be_bytes();
            let ino = metadata.ino().to_be_bytes();
            let uid = metadata.uid().to_be_bytes();
            let mode = (metadata.mode() & 0o7777).to_be_bytes();
            let stable_digest = digest(&[b"held-directory-unix-v1", &dev, &ino, &uid, &mode]);
            let mut binding = Sha256::new();
            binding.update(b"held-directory-components-v1");
            for component in &self.canonical_components {
                binding.update((component.len() as u32).to_be_bytes());
                binding.update(component);
            }
            binding.update(dev);
            binding.update(ino);
            Ok(DirectoryIdentity {
                platform: "unix-v1",
                stable_digest,
                canonical_binding_digest: crate::intel::hex_lower(&binding.finalize()),
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

#[cfg(not(unix))]
mod imp {
    use super::*;

    #[derive(Debug)]
    pub(super) struct HeldDirectory;
    impl HeldDirectory {
        pub(super) fn open_existing(_path: &Path) -> Result<Self> {
            anyhow::bail!("held directory authority is unavailable on this platform")
        }
        pub(super) fn identity(&self) -> Result<DirectoryIdentity> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn diagnostic_path(&self) -> &Path {
            Path::new("")
        }
        pub(super) fn create_file_exclusive(&self, _name: &str) -> Result<File> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn rename_noreplace(&self, _from: &str, _to: &str) -> Result<()> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn unlink(&self, _name: &str) -> Result<()> {
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
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn descriptor_walk_rejects_alias_and_survives_path_replacement() {
        let temp = tempfile::TempDir::new().unwrap();
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let alias = temp.path().join("alias");
        symlink(&target, &alias).unwrap();
        assert!(HeldDirectoryAuthority::open_existing(&alias).is_err());
        let held = HeldDirectoryAuthority::open_existing(&target).unwrap();
        let original = held.identity().clone();
        std::fs::rename(&target, temp.path().join("moved")).unwrap();
        std::fs::create_dir(&target).unwrap();
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
