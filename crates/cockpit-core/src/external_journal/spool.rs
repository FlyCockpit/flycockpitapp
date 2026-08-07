//! Fixed, private, owner-only capsule spool on the filesystem.
//!
//! The spool is one application-data subdirectory, never configurable per
//! operation. Capsule files are named from internal UUID/version values only.
//! Every capsule is created exclusively, physically allocated to its full
//! 65,536 bytes (never a sparse truncate), sentinel-verified in both slots,
//! fsynced, and its parent directory fsynced — all before any external
//! handoff. After handoff only an already-allocated slot is rewritten in
//! place, so recovery never needs a new file, directory entry, or disk block.

use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use uuid::Uuid;

use super::ExternalJournalError;
use super::capsule::{CAPSULE_BYTES, SLOT_BYTES, sentinel_slot_bytes};
use super::fsguard::{DirGuard, OpenStrictness};

/// Fixed subdirectory of the application data root.
pub const SPOOL_DIR_NAME: &str = "external-journal-spool";

/// Live capsules.
const CAPSULES_DIR: &str = "capsules";

/// Capsules withheld from import pending operator attention.
const QUARANTINE_DIR: &str = "quarantine";

/// Capsule file-name suffix. Carries the on-disk format version only.
const CAPSULE_SUFFIX: &str = ".v1";

/// How many quarantine names are tried before giving up.
const QUARANTINE_NAME_ATTEMPTS: u32 = 1024;

/// Deterministic fault points, exercised only by in-crate tests. There is no
/// public or configuration path that reaches these.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SpoolFaults {
    pub fail_allocate: bool,
    pub fail_sentinel_verify: bool,
    pub fail_file_fsync: bool,
    pub fail_parent_fsync: bool,
    pub fail_slot_write: Option<u8>,
    pub fail_slot_fsync: Option<u8>,
}

/// The capsule spool.
#[derive(Debug)]
pub struct Spool {
    root: DirGuard,
    capsules: DirGuard,
    quarantine: DirGuard,
    faults: Mutex<SpoolFaults>,
}

/// The one fixed application-data spool root. Never per-operation.
pub(crate) fn default_spool_root() -> Result<PathBuf, ExternalJournalError> {
    Ok(crate::config::resolve::cockpit_data_dir()
        .map_err(|error| ExternalJournalError::Spool(error.to_string()))?
        .join(SPOOL_DIR_NAME))
}

/// Internal-only capsule file name.
fn capsule_file_name(capsule_uuid: Uuid) -> String {
    format!("{capsule_uuid}{CAPSULE_SUFFIX}")
}

/// Parse a capsule file name back to its UUID, rejecting anything else.
///
/// The mapping is bijective on purpose: only the canonical lowercase
/// hyphenated form is accepted, so an enumerated name can always be replaced
/// by the regenerated canonical one before the file is reopened.
fn capsule_uuid_from_name(name: &str) -> Option<Uuid> {
    let stem = name.strip_suffix(CAPSULE_SUFFIX)?;
    let parsed = Uuid::parse_str(stem).ok()?;
    (parsed.hyphenated().to_string() == stem).then_some(parsed)
}

/// What a reopen of a capsule found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsulePresence {
    /// A contained, owner-only, singly-linked regular file.
    Verified,
    /// No such directory entry.
    Missing,
    /// Present but not trustworthy: insecure mode, extra hard link, symlink,
    /// reparse point, or not a regular file.
    Unverifiable { detail: String },
}

/// Whether a spool handle may create or repair anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoolAccess {
    /// Create the fixed directories if they are missing. Only newly created
    /// directories get their mode set; an existing one is verified, never
    /// repaired, so a widened spool surfaces instead of being papered over.
    Create,
    /// Read-only. Creates nothing, repairs nothing, and fails if the spool
    /// does not exist. Status surfaces use this.
    Inspect,
}

impl Spool {
    /// Open the spool beneath an absolute root.
    pub fn open_at(root: &Path, access: SpoolAccess) -> Result<Self, ExternalJournalError> {
        let create = access == SpoolAccess::Create;
        let root = DirGuard::open_root(root, create)?;
        let capsules = root.open_child_dir(CAPSULES_DIR, create)?;
        let quarantine = root.open_child_dir(QUARANTINE_DIR, create)?;
        let spool = Self {
            root,
            capsules,
            quarantine,
            faults: Mutex::new(SpoolFaults::default()),
        };
        // Verify rather than repair, in both modes. An insecure spool is an
        // integrity fact the caller must act on, not something to fix silently.
        spool.verify_permissions()?;
        Ok(spool)
    }

    /// Open the fixed application-data spool, creating it if needed.
    pub fn open_default() -> Result<Self, ExternalJournalError> {
        Self::open_at(&default_spool_root()?, SpoolAccess::Create)
    }

    /// Read-only inspection of the fixed spool for status surfaces.
    ///
    /// Returns `None` when the spool has never been created. It never creates
    /// a directory and never changes a mode, so the doctor line reports what
    /// is really on disk.
    pub fn inspect_default() -> Result<Option<Self>, ExternalJournalError> {
        let root = default_spool_root()?;
        if !root.is_dir() {
            return Ok(None);
        }
        Self::open_at(&root, SpoolAccess::Inspect).map(Some)
    }

    pub fn root_path(&self) -> &Path {
        self.root.path()
    }

    pub fn quarantine_path(&self) -> PathBuf {
        self.quarantine.path().to_path_buf()
    }

    /// Verify the held directories still carry owner-only permissions.
    pub fn verify_permissions(&self) -> Result<(), ExternalJournalError> {
        self.root.verify_private()?;
        self.capsules.verify_private()?;
        self.quarantine.verify_private()
    }

    #[cfg(test)]
    pub(crate) fn set_faults(&self, faults: SpoolFaults) {
        *self.faults.lock().expect("spool fault mutex") = faults;
    }

    fn faults(&self) -> SpoolFaults {
        *self.faults.lock().expect("spool fault mutex")
    }

    /// Create and fully provision one capsule.
    ///
    /// If allocation, write, verification, or either fsync fails, the partial
    /// file is removed and the caller must not hand off anything.
    pub fn create_capsule(&self, capsule_uuid: Uuid) -> Result<(), ExternalJournalError> {
        self.verify_permissions()?;
        let name = capsule_file_name(capsule_uuid);
        let faults = self.faults();

        let mut file = self.capsules.create_file_exclusive(&name)?;
        let provision = (|| -> Result<(), ExternalJournalError> {
            if faults.fail_allocate {
                return Err(ExternalJournalError::Spool(
                    "injected capsule allocation failure".to_string(),
                ));
            }
            physically_allocate(&file, CAPSULE_BYTES)?;

            // The sentinel write is itself the non-sparse guarantee: every one
            // of the 65,536 bytes is written explicitly, never truncated into
            // existence.
            let mut sentinel = Vec::with_capacity(CAPSULE_BYTES);
            sentinel.extend_from_slice(&sentinel_slot_bytes(capsule_uuid, 0));
            sentinel.extend_from_slice(&sentinel_slot_bytes(capsule_uuid, 1));
            debug_assert_eq!(sentinel.len(), CAPSULE_BYTES);
            file.seek(SeekFrom::Start(0))
                .map_err(|error| spool_io("seeking new capsule", error))?;
            file.write_all(&sentinel)
                .map_err(|error| spool_io("writing capsule sentinel", error))?;

            if faults.fail_file_fsync {
                return Err(ExternalJournalError::Spool(
                    "injected capsule fsync failure".to_string(),
                ));
            }
            file.sync_all()
                .map_err(|error| spool_io("fsyncing new capsule", error))?;

            if faults.fail_parent_fsync {
                return Err(ExternalJournalError::Spool(
                    "injected capsule parent-directory fsync failure".to_string(),
                ));
            }
            self.capsules.sync()?;

            if faults.fail_sentinel_verify {
                return Err(ExternalJournalError::Spool(
                    "injected capsule sentinel verification failure".to_string(),
                ));
            }
            // Reread both slots through a freshly verified handle.
            let mut verify = self.capsules.open_file_verified(&name)?;
            let mut readback = vec![0u8; CAPSULE_BYTES];
            verify
                .seek(SeekFrom::Start(0))
                .map_err(|error| spool_io("seeking capsule for verification", error))?;
            verify
                .read_exact(&mut readback)
                .map_err(|error| spool_io("reading capsule for verification", error))?;
            if readback != sentinel {
                return Err(ExternalJournalError::Spool(
                    "capsule sentinel readback mismatch".to_string(),
                ));
            }
            let len = verify
                .metadata()
                .map_err(|error| spool_io("stat capsule", error))?
                .len();
            if len != CAPSULE_BYTES as u64 {
                return Err(ExternalJournalError::Spool(format!(
                    "capsule is {len} bytes; expected {CAPSULE_BYTES}"
                )));
            }
            Ok(())
        })();

        // Release the write handle before any cleanup so platforms that refuse
        // to unlink an open file still leave nothing behind.
        drop(file);
        if provision.is_err() {
            // Zero external handoff occurred, so the half-provisioned capsule
            // is removed rather than retained.
            let _ = self.capsules.remove_file(&name);
            let _ = self.capsules.sync();
        }
        provision
    }

    /// Rewrite one already-allocated slot in place, fsync it, and verify the
    /// readback. Never extends, truncates, renames, or allocates.
    pub fn write_slot(
        &self,
        capsule_uuid: Uuid,
        slot_index: u8,
        bytes: &[u8],
    ) -> Result<(), ExternalJournalError> {
        if bytes.len() != SLOT_BYTES {
            return Err(ExternalJournalError::Spool(format!(
                "slot payload is {} bytes; expected {SLOT_BYTES}",
                bytes.len()
            )));
        }
        if slot_index > 1 {
            return Err(ExternalJournalError::Spool(format!(
                "slot index {slot_index} is out of range"
            )));
        }
        let faults = self.faults();
        if faults.fail_slot_write == Some(slot_index) {
            return Err(ExternalJournalError::Spool(format!(
                "injected slot {slot_index} write failure"
            )));
        }
        let name = capsule_file_name(capsule_uuid);
        let mut file = self.capsules.open_file_verified(&name)?;
        let len = file
            .metadata()
            .map_err(|error| spool_io("stat capsule", error))?
            .len();
        if len != CAPSULE_BYTES as u64 {
            return Err(ExternalJournalError::Spool(format!(
                "capsule is {len} bytes; refusing to write an unallocated slot"
            )));
        }
        let offset = u64::from(slot_index) * SLOT_BYTES as u64;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| spool_io("seeking capsule slot", error))?;
        file.write_all(bytes)
            .map_err(|error| spool_io("writing capsule slot", error))?;

        if faults.fail_slot_fsync == Some(slot_index) {
            return Err(ExternalJournalError::Spool(format!(
                "injected slot {slot_index} fsync failure"
            )));
        }
        file.sync_all()
            .map_err(|error| spool_io("fsyncing capsule slot", error))?;

        let readback = self.read_slot(capsule_uuid, slot_index)?;
        if readback != bytes {
            return Err(ExternalJournalError::Spool(
                "capsule slot readback mismatch".to_string(),
            ));
        }
        Ok(())
    }

    /// Read one slot's raw bytes.
    pub fn read_slot(
        &self,
        capsule_uuid: Uuid,
        slot_index: u8,
    ) -> Result<Vec<u8>, ExternalJournalError> {
        if slot_index > 1 {
            return Err(ExternalJournalError::Spool(format!(
                "slot index {slot_index} is out of range"
            )));
        }
        let name = capsule_file_name(capsule_uuid);
        let mut file = self.capsules.open_file_verified(&name)?;
        let offset = u64::from(slot_index) * SLOT_BYTES as u64;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| spool_io("seeking capsule slot", error))?;
        let mut bytes = vec![0u8; SLOT_BYTES];
        file.read_exact(&mut bytes)
            .map_err(|error| spool_io("reading capsule slot", error))?;
        Ok(bytes)
    }

    /// Whether the capsule file exists beneath the held handle.
    pub fn capsule_exists(&self, capsule_uuid: Uuid) -> bool {
        matches!(
            self.capsule_presence(capsule_uuid),
            CapsulePresence::Verified
        )
    }

    /// Distinguish "the durable medium is gone" from "the entry exists but
    /// cannot be trusted".
    ///
    /// Conflating the two is dangerous in opposite directions: treating a
    /// compromised capsule as missing would release its reservation and
    /// downgrade its evidence while leaving a hostile file in place, and
    /// treating a missing one as compromised would quarantine nothing and
    /// block dispatch forever.
    pub fn capsule_presence(&self, capsule_uuid: Uuid) -> CapsulePresence {
        match self
            .capsules
            .open_file_verified(&capsule_file_name(capsule_uuid))
        {
            Ok(_) => CapsulePresence::Verified,
            Err(ExternalJournalError::CapsuleMissing(_)) => CapsulePresence::Missing,
            Err(error) => CapsulePresence::Unverifiable {
                detail: error.to_string(),
            },
        }
    }

    /// Physically allocated bytes across live capsules.
    pub fn allocated_bytes(&self) -> Result<u64, ExternalJournalError> {
        let mut total = 0u64;
        for capsule_uuid in self.list_capsules()? {
            let file = self
                .capsules
                .open_file_verified(&capsule_file_name(capsule_uuid))?;
            total = total
                .checked_add(
                    file.metadata()
                        .map_err(|error| spool_io("stat capsule", error))?
                        .len(),
                )
                .ok_or_else(|| {
                    ExternalJournalError::Spool("allocated byte total overflow".to_string())
                })?;
        }
        Ok(total)
    }

    /// Capsule identities discovered by enumeration. Every name is reopened
    /// and verified beneath the held handle before it is returned.
    pub fn list_capsules(&self) -> Result<Vec<Uuid>, ExternalJournalError> {
        let mut out = Vec::new();
        for name in self.capsules.list_file_names()? {
            let Some(capsule_uuid) = capsule_uuid_from_name(&name) else {
                continue;
            };
            // Reopen by the regenerated canonical name rather than trusting
            // the enumerated entry.
            if self.capsule_presence(capsule_uuid) != CapsulePresence::Missing {
                out.push(capsule_uuid);
            }
        }
        out.sort();
        Ok(out)
    }

    /// Names under `capsules/` that are not valid capsule files. These are
    /// treated as hostile and quarantined rather than parsed.
    pub fn list_foreign_entries(&self) -> Result<Vec<String>, ExternalJournalError> {
        Ok(self
            .capsules
            .list_file_names()?
            .into_iter()
            .filter(|name| capsule_uuid_from_name(name).is_none())
            .collect())
    }

    /// Move an entry into quarantine under the first free name.
    ///
    /// The no-replace rename is what makes this safe: a same-user process can
    /// create the candidate name between our attempt and the next, and the
    /// only correct response is to try another name, never to overwrite. There
    /// is no check-then-rename window because there is no check.
    fn quarantine_under_free_name(&self, name: &str) -> Result<String, ExternalJournalError> {
        for suffix in 0..=QUARANTINE_NAME_ATTEMPTS {
            let candidate = if suffix == 0 {
                name.to_string()
            } else {
                format!("{name}.{suffix}")
            };
            match self
                .capsules
                .rename_into_noreplace(name, &self.quarantine, &candidate)
            {
                Ok(()) => return Ok(candidate),
                Err(ExternalJournalError::QuarantineNameTaken(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(ExternalJournalError::Spool(format!(
            "no free quarantine name for {name}"
        )))
    }

    /// Move a capsule into quarantine without leaving the held root.
    ///
    /// The reopen is **enforced**, not advisory: renaming an entry we could
    /// not prove to be a contained regular file would be exactly the blind
    /// replacement this containment layer exists to prevent. Containment-only
    /// strictness is deliberate — a capsule whose mode was widened is a thing
    /// we quarantine, so a mode failure must not stop us quarantining it.
    pub fn quarantine_capsule(&self, capsule_uuid: Uuid) -> Result<(), ExternalJournalError> {
        let name = capsule_file_name(capsule_uuid);
        let verified = self
            .capsules
            .open_file_checked(&name, OpenStrictness::ContainedOnly)?;
        drop(verified);
        self.quarantine_under_free_name(&name)?;
        self.capsules.sync()?;
        self.quarantine.sync()
    }

    /// Move an arbitrary foreign entry into quarantine by name.
    ///
    /// A foreign entry may legitimately be anything — including a symlink an
    /// attacker planted — so it is not opened. `renameat` beneath the two held
    /// directory handles acts on the directory entry itself and never follows
    /// it, which is what keeps the operation contained.
    pub fn quarantine_foreign_entry(&self, name: &str) -> Result<(), ExternalJournalError> {
        self.quarantine_under_free_name(name)?;
        self.capsules.sync()?;
        self.quarantine.sync()
    }

    /// Quarantined entries.
    pub fn list_quarantined(&self) -> Result<Vec<String>, ExternalJournalError> {
        self.quarantine.list_file_names()
    }

    /// Remove a capsule. Callers must confirm the terminal state in SQLite
    /// first; this function does not know about journal state.
    pub fn remove_capsule(&self, capsule_uuid: Uuid) -> Result<(), ExternalJournalError> {
        self.capsules
            .remove_file(&capsule_file_name(capsule_uuid))?;
        self.capsules.sync()
    }
}

fn spool_io(context: &str, error: std::io::Error) -> ExternalJournalError {
    ExternalJournalError::Spool(format!("{context}: {error}"))
}

/// Ask the platform to back the whole extent. The explicit full-extent write
/// that follows is the portable guarantee; this is the extra, cheap one.
#[cfg(target_os = "linux")]
fn physically_allocate(file: &std::fs::File, len: usize) -> Result<(), ExternalJournalError> {
    use std::os::fd::AsRawFd as _;

    // SAFETY: the descriptor is live for the call and `len` is a constant.
    let result = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, len as libc::off_t) };
    if result != 0 {
        return Err(spool_io(
            "allocating capsule extent",
            std::io::Error::from_raw_os_error(result),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn physically_allocate(_file: &std::fs::File, _len: usize) -> Result<(), ExternalJournalError> {
    // No portable preallocation primitive. The explicit 65,536-byte write in
    // `create_capsule` is what guarantees the extent is backed.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_journal::capsule::{CapsuleSlot, choose_slot};
    use crate::external_journal::keys::SpoolKeyRing;
    use crate::external_journal::projection::{Digest, OperationBody, SanitizedProjection};
    use cockpit_db::external_journal::ExternalJournalState;

    fn ring() -> SpoolKeyRing {
        SpoolKeyRing::for_test(&[(1, [5u8; 32])], 1).unwrap()
    }

    fn projection() -> Vec<u8> {
        SanitizedProjection::new(OperationBody::ImageGeneration {
            request_digest: Digest::of(b"request"),
            image_count: 1,
        })
        .encode()
        .unwrap()
    }

    fn slot(
        operation_id: Uuid,
        index: u8,
        version: u64,
        state: ExternalJournalState,
    ) -> CapsuleSlot {
        CapsuleSlot {
            slot_index: index,
            operation_id,
            journal_version: version,
            key_version: 1,
            state,
            updated_at_wall_ms: 1_000,
            projection: projection(),
        }
    }

    fn spool(tmp: &tempfile::TempDir) -> Spool {
        Spool::open_at(&tmp.path().join("spool"), SpoolAccess::Create).unwrap()
    }

    #[test]
    fn external_journal_spool_security_creates_owner_only_directories() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        spool.verify_permissions().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for path in [
                spool.root_path().to_path_buf(),
                spool.root_path().join("capsules"),
                spool.quarantine_path(),
            ] {
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o700, "{} has mode {mode:o}", path.display());
            }
        }
    }

    #[test]
    fn external_journal_spool_security_file_names_are_internal_uuids_only() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        let capsule_uuid = Uuid::new_v4();
        spool.create_capsule(capsule_uuid).unwrap();

        let names = std::fs::read_dir(spool.root_path().join("capsules"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![format!("{capsule_uuid}.v1")]);
        assert_eq!(capsule_uuid_from_name(&names[0]), Some(capsule_uuid));
        assert_eq!(capsule_uuid_from_name("notes.txt"), None);
        assert_eq!(capsule_uuid_from_name("../escape.v1"), None);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(spool.root_path().join("capsules").join(&names[0]))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn external_journal_recovery_capsule_is_exactly_64_kib_and_non_sparse() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        let capsule_uuid = Uuid::new_v4();
        spool.create_capsule(capsule_uuid).unwrap();

        let path = spool
            .root_path()
            .join("capsules")
            .join(format!("{capsule_uuid}.v1"));
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), 65_536);
        assert_eq!(spool.allocated_bytes().unwrap(), 65_536);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            // A sparse truncate would report far fewer 512-byte blocks.
            assert!(
                metadata.blocks() * 512 >= 65_536,
                "capsule is sparse: {} blocks",
                metadata.blocks()
            );
        }

        // Both slots hold their distinct sentinel patterns.
        assert_eq!(
            spool.read_slot(capsule_uuid, 0).unwrap(),
            sentinel_slot_bytes(capsule_uuid, 0)
        );
        assert_eq!(
            spool.read_slot(capsule_uuid, 1).unwrap(),
            sentinel_slot_bytes(capsule_uuid, 1)
        );
    }

    #[test]
    fn external_journal_recovery_capsule_creation_is_exclusive() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        let capsule_uuid = Uuid::new_v4();
        spool.create_capsule(capsule_uuid).unwrap();
        assert!(spool.create_capsule(capsule_uuid).is_err());
    }

    #[test]
    fn external_journal_recovery_capsule_fault_injection_leaves_nothing_behind() {
        for faults in [
            SpoolFaults {
                fail_allocate: true,
                ..SpoolFaults::default()
            },
            SpoolFaults {
                fail_file_fsync: true,
                ..SpoolFaults::default()
            },
            SpoolFaults {
                fail_parent_fsync: true,
                ..SpoolFaults::default()
            },
            SpoolFaults {
                fail_sentinel_verify: true,
                ..SpoolFaults::default()
            },
        ] {
            let tmp = tempfile::TempDir::new().unwrap();
            let spool = spool(&tmp);
            spool.set_faults(faults);
            let capsule_uuid = Uuid::new_v4();
            assert!(
                spool.create_capsule(capsule_uuid).is_err(),
                "{faults:?} should have failed"
            );
            assert!(!spool.capsule_exists(capsule_uuid));
            assert!(spool.list_capsules().unwrap().is_empty());
            assert_eq!(spool.allocated_bytes().unwrap(), 0);
        }
    }

    #[test]
    fn external_journal_recovery_capsule_slot_write_never_allocates() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        let keys = ring();
        let operation_id = Uuid::new_v4();
        let capsule_uuid = Uuid::new_v4();
        spool.create_capsule(capsule_uuid).unwrap();

        for (index, version, state) in [
            (0u8, 1u64, ExternalJournalState::Prepared),
            (1, 2, ExternalJournalState::Dispatching),
            (0, 3, ExternalJournalState::SubmissionUnknown),
        ] {
            let encoded = slot(operation_id, index, version, state)
                .encode(&keys)
                .unwrap();
            spool.write_slot(capsule_uuid, index, &encoded).unwrap();
            let path = spool
                .root_path()
                .join("capsules")
                .join(format!("{capsule_uuid}.v1"));
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 65_536);
        }
        assert_eq!(spool.list_capsules().unwrap(), vec![capsule_uuid]);

        // The unique highest authenticated slot wins.
        let first = CapsuleSlot::decode(
            &spool.read_slot(capsule_uuid, 0).unwrap(),
            operation_id,
            &keys,
        );
        let second = CapsuleSlot::decode(
            &spool.read_slot(capsule_uuid, 1).unwrap(),
            operation_id,
            &keys,
        );
        match choose_slot(first, second) {
            crate::external_journal::capsule::SlotChoice::Authentic(chosen) => {
                assert_eq!(chosen.journal_version, 3);
                assert_eq!(chosen.state, ExternalJournalState::SubmissionUnknown);
            }
            other => panic!("expected an authentic slot, got {other:?}"),
        }
    }

    #[test]
    fn external_journal_recovery_capsule_slot_write_faults_are_reported() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        let keys = ring();
        let operation_id = Uuid::new_v4();
        let capsule_uuid = Uuid::new_v4();
        spool.create_capsule(capsule_uuid).unwrap();
        let encoded = slot(operation_id, 1, 2, ExternalJournalState::Dispatching)
            .encode(&keys)
            .unwrap();

        spool.set_faults(SpoolFaults {
            fail_slot_write: Some(1),
            ..SpoolFaults::default()
        });
        assert!(spool.write_slot(capsule_uuid, 1, &encoded).is_err());

        spool.set_faults(SpoolFaults {
            fail_slot_fsync: Some(1),
            ..SpoolFaults::default()
        });
        assert!(spool.write_slot(capsule_uuid, 1, &encoded).is_err());

        spool.set_faults(SpoolFaults::default());
        spool.write_slot(capsule_uuid, 1, &encoded).unwrap();
    }

    #[test]
    fn external_journal_spool_security_quarantine_stays_inside_the_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        let capsule_uuid = Uuid::new_v4();
        spool.create_capsule(capsule_uuid).unwrap();
        spool.quarantine_capsule(capsule_uuid).unwrap();

        assert!(spool.list_capsules().unwrap().is_empty());
        assert_eq!(
            spool.list_quarantined().unwrap(),
            vec![format!("{capsule_uuid}.v1")]
        );
        assert!(
            spool.quarantine_path().starts_with(spool.root_path()),
            "quarantine escaped the spool root"
        );
    }

    #[test]
    fn external_journal_spool_security_foreign_entries_are_never_parsed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        let capsules = spool.root_path().join("capsules");
        std::fs::write(capsules.join("evil.txt"), b"payload").unwrap();
        std::fs::write(capsules.join("not-a-uuid.v1"), b"payload").unwrap();

        assert!(spool.list_capsules().unwrap().is_empty());
        let mut foreign = spool.list_foreign_entries().unwrap();
        foreign.sort();
        assert_eq!(foreign, vec!["evil.txt", "not-a-uuid.v1"]);
        for name in foreign {
            spool.quarantine_foreign_entry(&name).unwrap();
        }
        assert!(spool.list_foreign_entries().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn external_journal_spool_security_rejects_symlink_replacement() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        let capsule_uuid = Uuid::new_v4();
        spool.create_capsule(capsule_uuid).unwrap();

        // A racing attacker swaps the capsule for a symlink pointing outside.
        let outside = tmp.path().join("outside.bin");
        std::fs::write(&outside, vec![0u8; CAPSULE_BYTES]).unwrap();
        let capsule_path = spool
            .root_path()
            .join("capsules")
            .join(format!("{capsule_uuid}.v1"));
        std::fs::remove_file(&capsule_path).unwrap();
        std::os::unix::fs::symlink(&outside, &capsule_path).unwrap();

        // Every lifecycle operation refuses to follow it.
        let zeros = vec![0u8; SLOT_BYTES];
        assert!(spool.read_slot(capsule_uuid, 0).is_err());
        assert!(spool.write_slot(capsule_uuid, 0, &zeros).is_err());
        assert!(!spool.capsule_exists(capsule_uuid));
        // But the entry stays *visible* to the sweep. Reporting it as absent
        // would hide a hostile file from both the ledger and the orphan scan;
        // it is surfaced as unverifiable so recovery quarantines and blocks.
        assert_eq!(spool.list_capsules().unwrap(), vec![capsule_uuid]);
        assert!(matches!(
            spool.capsule_presence(capsule_uuid),
            CapsulePresence::Unverifiable { .. }
        ));
        // The target outside the spool is untouched.
        assert_eq!(std::fs::read(&outside).unwrap(), vec![0u8; CAPSULE_BYTES]);
    }

    #[cfg(unix)]
    #[test]
    fn external_journal_spool_security_rejects_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        let capsule_uuid = Uuid::new_v4();
        spool.create_capsule(capsule_uuid).unwrap();
        let capsule_path = spool
            .root_path()
            .join("capsules")
            .join(format!("{capsule_uuid}.v1"));
        std::fs::set_permissions(&capsule_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let error = spool.read_slot(capsule_uuid, 0).unwrap_err();
        assert!(
            matches!(error, ExternalJournalError::InsecurePermissions(_)),
            "unexpected error: {error:?}"
        );

        std::fs::set_permissions(
            spool.root_path().join("capsules"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(matches!(
            spool.verify_permissions(),
            Err(ExternalJournalError::InsecurePermissions(_))
        ));
    }

    #[test]
    fn external_journal_spool_security_presence_separates_missing_from_untrusted() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        let capsule_uuid = Uuid::new_v4();
        assert_eq!(
            spool.capsule_presence(capsule_uuid),
            CapsulePresence::Missing
        );
        spool.create_capsule(capsule_uuid).unwrap();
        assert_eq!(
            spool.capsule_presence(capsule_uuid),
            CapsulePresence::Verified
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                spool
                    .root_path()
                    .join("capsules")
                    .join(format!("{capsule_uuid}.v1")),
                std::fs::Permissions::from_mode(0o666),
            )
            .unwrap();
            assert!(matches!(
                spool.capsule_presence(capsule_uuid),
                CapsulePresence::Unverifiable { .. }
            ));
        }

        spool.remove_capsule(capsule_uuid).unwrap();
        assert_eq!(
            spool.capsule_presence(capsule_uuid),
            CapsulePresence::Missing
        );
    }

    #[cfg(unix)]
    #[test]
    fn external_journal_spool_security_rejects_hard_linked_capsule() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool = spool(&tmp);
        let capsule_uuid = Uuid::new_v4();
        spool.create_capsule(capsule_uuid).unwrap();
        let capsule_path = spool
            .root_path()
            .join("capsules")
            .join(format!("{capsule_uuid}.v1"));
        std::fs::hard_link(&capsule_path, tmp.path().join("shadow.bin")).unwrap();
        assert!(spool.read_slot(capsule_uuid, 0).is_err());
    }
}
