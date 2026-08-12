//! SQLite-backed persistence for daemon custody records and the monotonic
//! generation high-water sequence. Schema lives in `cockpit-db`'s
//! `0001_initial.sql` (`remote_daemon_custody_records`,
//! `remote_daemon_custody_generation_seq`).
//!
//! Generation reservation ([`SqliteCustodyStore::reserve_generation`]) is an
//! atomic single-transaction bump, so concurrent providers can never reserve the
//! same generation. The key is then created for `(handle, generation)` and the
//! record is committed; a crash between reservation and commit merely SKIPS a
//! generation (monotonicity is preserved — a skipped number is never reused).
//! `destroy` deletes the record but never touches the sequence, so a destroyed +
//! regenerated identity always receives a strictly greater generation.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cockpit_db::Db;
use cockpit_proto::remote_device_identity_enrollment::{
    RemoteIdentityCustodyClassV1 as CustodyClass, RemoteIdentityCustodyError,
    RemoteIdentityCustodyHandleId, RemoteIdentityP256PublicKey,
    RemoteIdentityPresenceModeV1 as PresenceMode, RemoteSubjectKindV1 as SubjectKind,
};
use rusqlite::{OptionalExtension, params};

use super::{DaemonCustodyProfile, DaemonGenerationRecord};

fn backend(error: impl std::fmt::Display) -> RemoteIdentityCustodyError {
    RemoteIdentityCustodyError::Unavailable(format!("custody store backend: {error}"))
}

/// The fields required to insert a fresh custody record. The generation was
/// already reserved from the monotonic sequence by
/// [`SqliteCustodyStore::reserve_generation`].
#[derive(Debug, Clone, Copy)]
pub struct NewCustodyRecord {
    pub handle_id: [u8; 16],
    pub subject_kind: SubjectKind,
    pub custody_class: CustodyClass,
    pub presence_mode: PresenceMode,
    pub profile: DaemonCustodyProfile,
    pub generation: u64,
    pub public_key: RemoteIdentityP256PublicKey,
    pub evidence_digest: [u8; 32],
}

/// SQLite-backed daemon custody store over a `cockpit-db` handle.
pub struct SqliteCustodyStore {
    db: Db,
    /// Test-only failpoint: when set, [`Self::update_rotation`] returns an error
    /// WITHOUT touching the database, letting tests assert that a failed
    /// rotation publish leaves the old record + old key intact (the previous
    /// generation's key is never retired before the new one is durable).
    rotation_update_failpoint: Arc<AtomicBool>,
}

impl SqliteCustodyStore {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            rotation_update_failpoint: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Arm/disarm the rotation-publish failpoint (tests only).
    pub fn set_rotation_update_failpoint(&self, fail: bool) {
        self.rotation_update_failpoint.store(fail, Ordering::SeqCst);
    }

    /// Atomically reserve the next monotonic generation, returning it. The bump
    /// is a single write transaction, so concurrent reservations (serialized by
    /// SQLite's write lock) can never hand out the same generation twice.
    pub fn reserve_generation(&self) -> Result<u64, RemoteIdentityCustodyError> {
        self.db
            .blocking_write_for_sync_ui(move |conn| {
                let tx = conn.unchecked_transaction()?;
                let generation = allocate_next_generation(&tx)?;
                tx.commit()?;
                Ok(generation)
            })
            .map_err(backend)
    }

    /// Insert a fresh record with its already-reserved generation.
    pub fn insert_record(
        &self,
        new: NewCustodyRecord,
        created_at: i64,
    ) -> Result<(), RemoteIdentityCustodyError> {
        self.db
            .blocking_write_for_sync_ui(move |conn| {
                conn.execute(
                    "INSERT INTO remote_daemon_custody_records (
                         handle_id, subject_kind, custody_class, presence_mode, profile,
                         generation, public_key_x, public_key_y, evidence_digest, created_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        new.handle_id.as_slice(),
                        new.subject_kind as u8 as i64,
                        new.custody_class as u8 as i64,
                        new.presence_mode as u8 as i64,
                        new.profile.platform_label(),
                        new.generation as i64,
                        new.public_key.x.as_slice(),
                        new.public_key.y.as_slice(),
                        new.evidence_digest.as_slice(),
                        created_at,
                    ],
                )?;
                Ok(())
            })
            .map_err(backend)
    }

    /// Durably flip an existing record to the new (already-reserved) generation
    /// and its new key — the rotation "publish" step. Errors if the handle does
    /// not exist. The caller retires the previous generation's key only after
    /// this returns `Ok`.
    pub fn update_rotation(
        &self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
        new_public_key: RemoteIdentityP256PublicKey,
        new_evidence_digest: [u8; 32],
        created_at: i64,
    ) -> Result<(), RemoteIdentityCustodyError> {
        if self.rotation_update_failpoint.load(Ordering::SeqCst) {
            return Err(RemoteIdentityCustodyError::Unavailable(
                "injected rotation publish failure".into(),
            ));
        }
        let handle_bytes = handle.0;
        self.db
            .blocking_write_for_sync_ui(move |conn| {
                let affected = conn.execute(
                    "UPDATE remote_daemon_custody_records
                       SET generation = ?2, public_key_x = ?3, public_key_y = ?4,
                           evidence_digest = ?5, created_at = ?6
                     WHERE handle_id = ?1",
                    params![
                        handle_bytes.as_slice(),
                        generation as i64,
                        new_public_key.x.as_slice(),
                        new_public_key.y.as_slice(),
                        new_evidence_digest.as_slice(),
                        created_at,
                    ],
                )?;
                if affected == 0 {
                    return Err(anyhow::anyhow!("rotation target handle not found"));
                }
                Ok(())
            })
            .map_err(backend)
    }

    /// Load a record by handle. Returns `None` if absent.
    pub fn load_record(
        &self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<Option<DaemonGenerationRecord>, RemoteIdentityCustodyError> {
        let handle_bytes = handle.0;
        let row = self
            .db
            .blocking_read_for_sync_ui(move |conn| {
                conn.query_row(
                    "SELECT subject_kind, custody_class, presence_mode, profile, generation,
                            public_key_x, public_key_y, evidence_digest
                       FROM remote_daemon_custody_records WHERE handle_id = ?1",
                    params![handle_bytes.as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                            row.get::<_, Vec<u8>>(7)?,
                        ))
                    },
                )
                .optional()
                .map_err(anyhow::Error::from)
            })
            .map_err(backend)?;

        let Some((subject_kind, custody_class, presence_mode, profile, generation, x, y, digest)) =
            row
        else {
            return Ok(None);
        };

        let record = DaemonGenerationRecord {
            handle_id: handle,
            public_key: public_key_from_columns(&x, &y)?,
            subject_kind: SubjectKind::try_from(u8::try_from(subject_kind).unwrap_or(0))
                .map_err(|e| RemoteIdentityCustodyError::InvalidEvidence(e.to_string()))?,
            custody_class: CustodyClass::try_from(u8::try_from(custody_class).unwrap_or(0))
                .map_err(|e| RemoteIdentityCustodyError::InvalidEvidence(e.to_string()))?,
            presence_mode: PresenceMode::try_from(u8::try_from(presence_mode).unwrap_or(0))
                .map_err(|e| RemoteIdentityCustodyError::InvalidEvidence(e.to_string()))?,
            profile: DaemonCustodyProfile::from_label(&profile).ok_or_else(|| {
                RemoteIdentityCustodyError::InvalidEvidence(format!(
                    "unknown persisted custody profile: {profile}"
                ))
            })?,
            generation: u64::try_from(generation)
                .map_err(|e| RemoteIdentityCustodyError::InvalidEvidence(e.to_string()))?,
            evidence_digest: digest.as_slice().try_into().map_err(|_| {
                RemoteIdentityCustodyError::InvalidEvidence("evidence digest length".into())
            })?,
        };
        Ok(Some(record))
    }

    /// Delete a record by handle. Returns whether a row was removed. The
    /// generation sequence is deliberately untouched.
    pub fn delete_record(
        &self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<bool, RemoteIdentityCustodyError> {
        let handle_bytes = handle.0;
        self.db
            .blocking_write_for_sync_ui(move |conn| {
                let affected = conn.execute(
                    "DELETE FROM remote_daemon_custody_records WHERE handle_id = ?1",
                    params![handle_bytes.as_slice()],
                )?;
                Ok(affected > 0)
            })
            .map_err(backend)
    }

    /// The current generation high-water mark (0 when nothing has been issued).
    pub fn current_high_water(&self) -> Result<u64, RemoteIdentityCustodyError> {
        let value = self
            .db
            .blocking_read_for_sync_ui(|conn| {
                conn.query_row(
                    "SELECT high_water FROM remote_daemon_custody_generation_seq WHERE id = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(anyhow::Error::from)
            })
            .map_err(backend)?;
        Ok(value.and_then(|v| u64::try_from(v).ok()).unwrap_or(0))
    }
}

fn public_key_from_columns(
    x: &[u8],
    y: &[u8],
) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
    Ok(RemoteIdentityP256PublicKey {
        x: x.try_into().map_err(|_| {
            RemoteIdentityCustodyError::InvalidEvidence("public key x length".into())
        })?,
        y: y.try_into().map_err(|_| {
            RemoteIdentityCustodyError::InvalidEvidence("public key y length".into())
        })?,
    })
}

/// Bump the monotonic generation sequence by one inside the current
/// transaction and return the new value. The sequence row is created on first
/// use. The `remote_daemon_custody_generation_seq_monotonic` trigger rejects any
/// decrease at the database level as a defense in depth.
fn allocate_next_generation(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<u64> {
    tx.execute(
        "INSERT OR IGNORE INTO remote_daemon_custody_generation_seq (id, high_water)
         VALUES (1, 0)",
        [],
    )?;
    tx.execute(
        "UPDATE remote_daemon_custody_generation_seq SET high_water = high_water + 1 WHERE id = 1",
        [],
    )?;
    let generation: i64 = tx.query_row(
        "SELECT high_water FROM remote_daemon_custody_generation_seq WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    Ok(generation as u64)
}
