//! Pure, platform-agnostic containment/permission verification for the
//! private clipboard recovery artifact directory.
//!
//! Every platform syscall layer (`unix`, `windows`) populates one of the
//! stat structs below from real OS state and then defers to these pure
//! functions to decide whether an entry is safe to open, keep as the live
//! artifact, or must be reported — and never opened or deleted — as unsafe.
//! Keeping the decision syscall-free is what makes every containment,
//! ownership, and reparse edge case in the acceptance criteria unit
//! testable without a real filesystem or a real Windows security
//! descriptor.

/// Exact Unix file mode required for the recovery artifact.
pub const EXPECTED_FILE_MODE: u32 = 0o600;
/// Exact Unix directory mode required for the recovery directory.
pub const EXPECTED_DIR_MODE: u32 = 0o700;

/// What the Unix syscall layer observed about one artifact file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixFileStat {
    pub is_regular_file: bool,
    pub is_symlink: bool,
    pub mode_bits: u32,
    pub uid: u32,
    pub nlink: u64,
}

/// What the Unix syscall layer observed about the recovery directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixDirStat {
    pub is_directory: bool,
    pub is_symlink: bool,
    pub mode_bits: u32,
}

/// What the Windows syscall layer observed about one artifact file,
/// relative to the already-verified recovery directory handle.
///
/// Constructed by production code only on `cfg(windows)`
/// (`recovery::windows`); on every other target its only callers are this
/// module's own cross-platform unit tests below, which exist specifically
/// so the Windows verification *logic* is exercised without a Windows
/// host. The `allow` is scoped to non-Windows targets only — it must not
/// hide a genuinely unused type on Windows itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct WindowsFileStat {
    pub is_reparse_point: bool,
    pub is_directory: bool,
    pub nlink: u32,
    pub owner_is_current_user: bool,
    /// Every ACE on the file's DACL grants no more than the directory's
    /// owner-only policy (current-user + LocalSystem, full control, no
    /// other principal, no broader mask).
    pub dacl_within_directory_policy: bool,
    /// The file's containing directory is the exact verified recovery
    /// directory handle, not a substituted parent.
    pub parent_identity_matches: bool,
}

/// What the Windows syscall layer observed about the recovery directory
/// itself. See [`WindowsFileStat`]'s doc comment for why the non-Windows
/// `allow` is here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
pub struct WindowsDirStat {
    pub is_reparse_point: bool,
    pub is_directory: bool,
    /// The DACL is protected (`SE_DACL_PROTECTED`, no inherited ACEs) and
    /// contains exactly the current-user and LocalSystem full-control ACEs.
    pub dacl_is_owner_only_and_protected: bool,
    pub owner_is_current_user: bool,
}

/// Why an on-disk (or on-volume) entry was refused. Never carries a path or
/// any file content — every variant is safe to log or show in `/doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    NotRegularFile,
    IsDirectory,
    Symlink,
    WrongMode { expected: u32, actual: u32 },
    WrongOwner,
    HardLinked { nlink: u64 },
    ReparsePoint,
    DaclTooBroad,
    ParentIdentityMismatch,
}

pub fn verify_unix_file(stat: UnixFileStat, expected_uid: u32) -> Result<(), Violation> {
    if stat.is_symlink {
        return Err(Violation::Symlink);
    }
    if !stat.is_regular_file {
        return Err(Violation::NotRegularFile);
    }
    if stat.mode_bits != EXPECTED_FILE_MODE {
        return Err(Violation::WrongMode {
            expected: EXPECTED_FILE_MODE,
            actual: stat.mode_bits,
        });
    }
    if stat.uid != expected_uid {
        return Err(Violation::WrongOwner);
    }
    if stat.nlink != 1 {
        return Err(Violation::HardLinked { nlink: stat.nlink });
    }
    Ok(())
}

pub fn verify_unix_dir(stat: UnixDirStat) -> Result<(), Violation> {
    if stat.is_symlink {
        return Err(Violation::Symlink);
    }
    if !stat.is_directory {
        return Err(Violation::NotRegularFile);
    }
    if stat.mode_bits != EXPECTED_DIR_MODE {
        return Err(Violation::WrongMode {
            expected: EXPECTED_DIR_MODE,
            actual: stat.mode_bits,
        });
    }
    Ok(())
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn verify_windows_file(stat: WindowsFileStat) -> Result<(), Violation> {
    if stat.is_reparse_point {
        return Err(Violation::ReparsePoint);
    }
    if stat.is_directory {
        return Err(Violation::IsDirectory);
    }
    if stat.nlink != 1 {
        return Err(Violation::HardLinked {
            nlink: stat.nlink as u64,
        });
    }
    if !stat.owner_is_current_user {
        return Err(Violation::WrongOwner);
    }
    if !stat.dacl_within_directory_policy {
        return Err(Violation::DaclTooBroad);
    }
    if !stat.parent_identity_matches {
        return Err(Violation::ParentIdentityMismatch);
    }
    Ok(())
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn verify_windows_dir(stat: WindowsDirStat) -> Result<(), Violation> {
    if stat.is_reparse_point {
        return Err(Violation::ReparsePoint);
    }
    if !stat.is_directory {
        return Err(Violation::NotRegularFile);
    }
    if !stat.owner_is_current_user {
        return Err(Violation::WrongOwner);
    }
    if !stat.dacl_is_owner_only_and_protected {
        return Err(Violation::DaclTooBroad);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_unix_file() -> UnixFileStat {
        UnixFileStat {
            is_regular_file: true,
            is_symlink: false,
            mode_bits: EXPECTED_FILE_MODE,
            uid: 1000,
            nlink: 1,
        }
    }

    #[test]
    fn unix_file_accepts_exact_private_regular_single_link_owned_file() {
        assert_eq!(verify_unix_file(ok_unix_file(), 1000), Ok(()));
    }

    #[test]
    fn unix_file_rejects_symlink() {
        let stat = UnixFileStat {
            is_symlink: true,
            ..ok_unix_file()
        };
        assert_eq!(verify_unix_file(stat, 1000), Err(Violation::Symlink));
    }

    #[test]
    fn unix_file_rejects_non_regular() {
        let stat = UnixFileStat {
            is_regular_file: false,
            ..ok_unix_file()
        };
        assert_eq!(
            verify_unix_file(stat, 1000),
            Err(Violation::NotRegularFile)
        );
    }

    #[test]
    fn unix_file_rejects_widened_mode() {
        let stat = UnixFileStat {
            mode_bits: 0o644,
            ..ok_unix_file()
        };
        assert_eq!(
            verify_unix_file(stat, 1000),
            Err(Violation::WrongMode {
                expected: 0o600,
                actual: 0o644
            })
        );
    }

    #[test]
    fn unix_file_rejects_foreign_owner() {
        assert_eq!(
            verify_unix_file(ok_unix_file(), 1001),
            Err(Violation::WrongOwner)
        );
    }

    #[test]
    fn unix_file_rejects_hardlinked() {
        let stat = UnixFileStat {
            nlink: 2,
            ..ok_unix_file()
        };
        assert_eq!(
            verify_unix_file(stat, 1000),
            Err(Violation::HardLinked { nlink: 2 })
        );
    }

    fn ok_unix_dir() -> UnixDirStat {
        UnixDirStat {
            is_directory: true,
            is_symlink: false,
            mode_bits: EXPECTED_DIR_MODE,
        }
    }

    #[test]
    fn unix_dir_accepts_exact_private_directory() {
        assert_eq!(verify_unix_dir(ok_unix_dir()), Ok(()));
    }

    #[test]
    fn unix_dir_rejects_symlink_and_widened_mode() {
        assert_eq!(
            verify_unix_dir(UnixDirStat {
                is_symlink: true,
                ..ok_unix_dir()
            }),
            Err(Violation::Symlink)
        );
        assert_eq!(
            verify_unix_dir(UnixDirStat {
                mode_bits: 0o755,
                ..ok_unix_dir()
            }),
            Err(Violation::WrongMode {
                expected: 0o700,
                actual: 0o755
            })
        );
    }

    fn ok_windows_file() -> WindowsFileStat {
        WindowsFileStat {
            is_reparse_point: false,
            is_directory: false,
            nlink: 1,
            owner_is_current_user: true,
            dacl_within_directory_policy: true,
            parent_identity_matches: true,
        }
    }

    #[test]
    fn windows_file_accepts_exact_owner_only_single_link_non_reparse_file() {
        assert_eq!(verify_windows_file(ok_windows_file()), Ok(()));
    }

    #[test]
    fn windows_file_rejects_reparse_point() {
        assert_eq!(
            verify_windows_file(WindowsFileStat {
                is_reparse_point: true,
                ..ok_windows_file()
            }),
            Err(Violation::ReparsePoint)
        );
    }

    #[test]
    fn windows_file_rejects_directory_masquerading_as_artifact() {
        assert_eq!(
            verify_windows_file(WindowsFileStat {
                is_directory: true,
                ..ok_windows_file()
            }),
            Err(Violation::IsDirectory)
        );
    }

    #[test]
    fn windows_file_rejects_hardlinked() {
        assert_eq!(
            verify_windows_file(WindowsFileStat {
                nlink: 2,
                ..ok_windows_file()
            }),
            Err(Violation::HardLinked { nlink: 2 })
        );
    }

    #[test]
    fn windows_file_rejects_foreign_owner() {
        assert_eq!(
            verify_windows_file(WindowsFileStat {
                owner_is_current_user: false,
                ..ok_windows_file()
            }),
            Err(Violation::WrongOwner)
        );
    }

    #[test]
    fn windows_file_rejects_broadened_dacl() {
        assert_eq!(
            verify_windows_file(WindowsFileStat {
                dacl_within_directory_policy: false,
                ..ok_windows_file()
            }),
            Err(Violation::DaclTooBroad)
        );
    }

    #[test]
    fn windows_file_rejects_parent_replacement() {
        assert_eq!(
            verify_windows_file(WindowsFileStat {
                parent_identity_matches: false,
                ..ok_windows_file()
            }),
            Err(Violation::ParentIdentityMismatch)
        );
    }

    fn ok_windows_dir() -> WindowsDirStat {
        WindowsDirStat {
            is_reparse_point: false,
            is_directory: true,
            dacl_is_owner_only_and_protected: true,
            owner_is_current_user: true,
        }
    }

    #[test]
    fn windows_dir_accepts_protected_owner_only_directory() {
        assert_eq!(verify_windows_dir(ok_windows_dir()), Ok(()));
    }

    #[test]
    fn windows_dir_rejects_junction_or_symlink_reparse() {
        assert_eq!(
            verify_windows_dir(WindowsDirStat {
                is_reparse_point: true,
                ..ok_windows_dir()
            }),
            Err(Violation::ReparsePoint)
        );
    }

    #[test]
    fn windows_dir_rejects_unprotected_or_broadened_dacl() {
        assert_eq!(
            verify_windows_dir(WindowsDirStat {
                dacl_is_owner_only_and_protected: false,
                ..ok_windows_dir()
            }),
            Err(Violation::DaclTooBroad)
        );
    }
}
