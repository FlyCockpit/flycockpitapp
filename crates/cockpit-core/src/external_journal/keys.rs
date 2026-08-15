//! Versioned spool HMAC key material.
//!
//! Keys come from the daemon-owned wrap-key vault through a journal consumer
//! reference. They are exactly 32 bytes. No plaintext key, DEK, or KEK bytes
//! appear in SQLite coordination tables, filenames, spool bytes, logs, export,
//! or diagnostics: this module resolves them once into a memory-only ring and
//! hands out borrows. Vault tables may hold AEAD ciphertext of the same root.
//!
//! The consumer-reference lifecycle is the load-bearing half. A version is
//! reserved here, activated in the same SQLite transaction that writes the
//! capsule row making it reachable (`Db::reserve_external_journal_capsule`),
//! and released in the same transaction that removes the last capsule row
//! referencing it. That is what "rotation keeps every referenced version
//! available until all records using it are imported or quarantined" means
//! mechanically. A version that no longer resolves makes its records
//! unauthenticated — never silently trusted.

use std::collections::BTreeMap;

use cockpit_db::Db;
use cockpit_db::external_journal::{
    EXTERNAL_JOURNAL_SPOOL_CONSUMER_KIND, EXTERNAL_JOURNAL_SPOOL_NAMESPACE,
    external_journal_spool_consumer_exists_conn, external_journal_spool_key_reference_id,
};

use crate::secure_key::{ConsumerReconciler, SecureKeyBytes, SecureKeyError, SecureKeyHandle};

use super::ExternalJournalError;

/// A memory-only ring of versioned 32-byte spool keys.
#[derive(Clone)]
pub struct SpoolKeyRing {
    active_version: u32,
    keys: BTreeMap<u32, SecureKeyBytes>,
    /// Whether these versions are backed by native secure-store consumer
    /// references that must be activated and released with the capsule ledger.
    secure_store_backed: bool,
}

impl std::fmt::Debug for SpoolKeyRing {
    /// Versions only. Key material is never rendered anywhere.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpoolKeyRing")
            .field("active_version", &self.active_version)
            .field("versions", &self.keys.keys().collect::<Vec<_>>())
            .field("secure_store_backed", &self.secure_store_backed)
            .finish()
    }
}

impl SpoolKeyRing {
    /// Build a ring, rejecting a missing active version.
    pub fn new(
        active_version: u32,
        keys: BTreeMap<u32, SecureKeyBytes>,
        secure_store_backed: bool,
    ) -> Result<Self, ExternalJournalError> {
        if !keys.contains_key(&active_version) {
            return Err(ExternalJournalError::UnknownKeyVersion(active_version));
        }
        Ok(Self {
            active_version,
            keys,
            secure_store_backed,
        })
    }

    /// The version new slots are written under.
    pub fn active_version(&self) -> u32 {
        self.active_version
    }

    /// Whether capsule writes must activate a secure-store consumer reference.
    pub fn secure_store_backed(&self) -> bool {
        self.secure_store_backed
    }

    /// Borrow the active key.
    pub fn active_key(&self) -> Result<&SecureKeyBytes, ExternalJournalError> {
        self.key_for_version(self.active_version)
    }

    /// Borrow a specific version. A retired or never-seen version is an error
    /// rather than a fallback, so its records quarantine instead of importing.
    pub fn key_for_version(&self, version: u32) -> Result<&SecureKeyBytes, ExternalJournalError> {
        self.keys
            .get(&version)
            .ok_or(ExternalJournalError::UnknownKeyVersion(version))
    }

    /// Versions currently resolvable.
    pub fn retained_versions(&self) -> Vec<u32> {
        self.keys.keys().copied().collect()
    }

    /// Resolve the active key plus every still-referenced version from the
    /// native secure store, reserving a consumer reference for each.
    ///
    /// `referenced` comes from the SQLite capsule ledger, which is what makes
    /// version retention mechanical rather than aspirational.
    pub async fn load_from_secure_store(
        handle: &SecureKeyHandle,
        referenced: &[i64],
    ) -> Result<Self, ExternalJournalError> {
        let (active_version, active_key) = handle
            .create_or_load(EXTERNAL_JOURNAL_SPOOL_NAMESPACE)
            .await
            .map_err(|error| ExternalJournalError::KeyStore(error.to_string()))?;
        reserve_version(handle, active_version).await?;

        let mut keys = BTreeMap::new();
        keys.insert(version_u32(active_version)?, active_key);
        for version in referenced {
            let version = *version;
            if keys.contains_key(&version_u32(version)?) {
                continue;
            }
            // A version that no longer resolves is deliberately left out: its
            // capsules fail authentication and are quarantined, never trusted.
            if let Ok((resolved, key)) = handle
                .load_version(EXTERNAL_JOURNAL_SPOOL_NAMESPACE, version)
                .await
            {
                reserve_version(handle, resolved).await?;
                keys.insert(version_u32(resolved)?, key);
            }
        }
        Self::new(version_u32(active_version)?, keys, true)
    }

    /// Deterministic in-memory ring for tests. No OS keyring is touched and no
    /// consumer reference exists, so capsule writes skip activation.
    #[cfg(test)]
    pub fn for_test(
        keys: &[(u32, [u8; crate::secure_key::KEY_BYTE_LEN])],
        active_version: u32,
    ) -> Result<Self, ExternalJournalError> {
        let map = keys
            .iter()
            .map(|(version, bytes)| (*version, SecureKeyBytes::from_array(*bytes)))
            .collect();
        Self::new(active_version, map, false)
    }
}

async fn reserve_version(
    handle: &SecureKeyHandle,
    version: i64,
) -> Result<(), ExternalJournalError> {
    let reference_id = external_journal_spool_key_reference_id(version);
    handle
        .reserve(
            &reference_id,
            EXTERNAL_JOURNAL_SPOOL_NAMESPACE,
            version,
            EXTERNAL_JOURNAL_SPOOL_CONSUMER_KIND,
            &reference_id,
        )
        .await
        .map(|_| ())
        .map_err(|error| ExternalJournalError::KeyStore(error.to_string()))
}

fn version_u32(version: i64) -> Result<u32, ExternalJournalError> {
    u32::try_from(version)
        .map_err(|_| ExternalJournalError::KeyStore(format!("key version {version} out of range")))
}

/// Reconciles `external_journal_spool` consumer references against the capsule
/// ledger.
///
/// Production previously registered [`crate::secure_key::FailClosedReconciler`]
/// for every kind, which would have left spool key references permanently
/// unreconcilable. A version exists exactly while a capsule row references it;
/// every other kind is delegated, so existing fail-closed behaviour is
/// unchanged.
pub struct ExternalJournalSpoolReconciler {
    db: Db,
}

impl std::fmt::Debug for ExternalJournalSpoolReconciler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExternalJournalSpoolReconciler")
    }
}

impl ExternalJournalSpoolReconciler {
    pub fn new(db: Db) -> Self {
        Self { db }
    }
}

impl ConsumerReconciler for ExternalJournalSpoolReconciler {
    fn consumer_exists(&self, kind: &str, id: &str) -> Result<bool, SecureKeyError> {
        if kind != EXTERNAL_JOURNAL_SPOOL_CONSUMER_KIND {
            // Unchanged fail-closed behaviour for every other kind.
            return crate::secure_key::FailClosedReconciler.consumer_exists(kind, id);
        }
        let consumer_id = id.to_string();
        // The reconciler runs on the secure-key actor's own OS thread, never a
        // Tokio worker, so a blocking read is the correct call here. An error
        // propagates rather than reading as "consumer gone": treating a
        // database failure as absence would release a key version that live
        // capsules still need.
        self.db
            .blocking_read_for_sync_ui(move |conn| {
                external_journal_spool_consumer_exists_conn(conn, &consumer_id)
            })
            .map_err(|error| SecureKeyError::Internal(format!("{error:#}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_key::KEY_BYTE_LEN;

    #[test]
    fn external_journal_spool_security_ring_never_renders_key_material() {
        let ring = SpoolKeyRing::for_test(&[(1, [0xABu8; KEY_BYTE_LEN])], 1).unwrap();
        let rendered = format!("{ring:?}");
        assert!(rendered.contains("active_version"));
        assert!(!rendered.contains("171"), "decimal key bytes leaked");
        assert!(!rendered.contains("ab"), "hex key bytes leaked");
        // The individual key also renders redacted.
        assert_eq!(
            format!("{:?}", ring.active_key().unwrap()),
            "SecureKeyBytes([REDACTED; 32])"
        );
    }

    #[test]
    fn external_journal_spool_security_ring_rejects_missing_active_version() {
        assert!(matches!(
            SpoolKeyRing::for_test(&[(1, [1u8; KEY_BYTE_LEN])], 2),
            Err(ExternalJournalError::UnknownKeyVersion(2))
        ));
    }

    #[test]
    fn external_journal_spool_security_ring_retains_referenced_versions() {
        let ring = SpoolKeyRing::for_test(&[(1, [1u8; KEY_BYTE_LEN]), (4, [4u8; KEY_BYTE_LEN])], 4)
            .unwrap();
        assert_eq!(ring.retained_versions(), vec![1, 4]);
        assert_eq!(ring.active_version(), 4);
        assert!(!ring.secure_store_backed());
        assert!(ring.key_for_version(1).is_ok());
        assert!(matches!(
            ring.key_for_version(2),
            Err(ExternalJournalError::UnknownKeyVersion(2))
        ));
    }

    #[test]
    fn external_journal_spool_security_reference_ids_are_internal_only() {
        assert_eq!(
            external_journal_spool_key_reference_id(7),
            "external-journal-spool:v7"
        );
        assert!(!external_journal_spool_key_reference_id(7).contains('/'));
    }

    #[tokio::test]
    async fn external_journal_spool_security_reconciler_tracks_the_capsule_ledger() {
        use cockpit_db::external_journal::{
            CapsulePartition, ExternalJournalDigest, ExternalJournalToken, PrepareExternalOperation,
        };

        let db = Db::open_in_memory().unwrap();
        let reconciler = ExternalJournalSpoolReconciler::new(db.clone());
        let reference = external_journal_spool_key_reference_id(5);

        // Nothing references version 5 yet.
        assert!(
            !reconciler
                .consumer_exists(EXTERNAL_JOURNAL_SPOOL_CONSUMER_KIND, &reference)
                .unwrap()
        );

        let record = db
            .prepare_external_operation(
                PrepareExternalOperation {
                    operation_kind: ExternalJournalToken::parse("computer_input").unwrap(),
                    owner_session_id: ExternalJournalToken::parse("session-a").unwrap(),
                    idempotency_key: ExternalJournalToken::parse("k1").unwrap(),
                    payload_digest: ExternalJournalDigest::of(b"payload"),
                    payload_len: 16,
                    provider_idempotency: None,
                },
                1_000,
            )
            .await
            .unwrap()
            .record()
            .clone();
        db.reserve_external_journal_capsule(
            record.operation_id,
            uuid::Uuid::new_v4(),
            5,
            CapsulePartition::Admission,
            false,
            1_000,
        )
        .await
        .unwrap();

        assert!(
            reconciler
                .consumer_exists(EXTERNAL_JOURNAL_SPOOL_CONSUMER_KIND, &reference)
                .unwrap()
        );
        // Other kinds keep the previous fail-closed stance.
        assert!(
            reconciler
                .consumer_exists("sealed_state", "anything")
                .is_err()
        );
        // An unparseable spool consumer id is an error, never a silent "gone".
        assert!(
            reconciler
                .consumer_exists(EXTERNAL_JOURNAL_SPOOL_CONSUMER_KIND, "not-a-reference")
                .is_err()
        );
    }
}
