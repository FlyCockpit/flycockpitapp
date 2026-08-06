//! Sync saga worker logic run exclusively on the secure-key actor thread.

use crate::db::Db;
use crate::db::installation_identity::InstallationIdentity;
use crate::db::secure_key::{
    ProvisionPhase, ReserveResult, RetirePhase, RetirePrepareResult, SecureKeyConsumerRef,
    SecureKeyRefState, SecureKeySagaKind, SecureKeyVersionRow, SecureKeyVersionState,
    activate_version_metadata_conn, delete_pending_version_conn, delete_saga_conn,
    ensure_namespace_conn, get_namespace_conn, get_ref_by_id_conn, get_saga_conn, get_version_conn,
    list_namespaces_conn, list_open_sagas_conn, list_recon_refs_conn, list_versions_conn,
    mark_consumer_ref_released_conn, mark_version_retired_conn, prepare_provision_conn,
    prepare_retire_conn, reserve_consumer_ref_conn, set_saga_phase_conn,
};

// Note: all SQLite + native I/O for this module runs on the dedicated actor thread.

use super::consumer::{ConsumerReconciler, activate_ref_in_tx, begin_release_in_tx};
use super::error::SecureKeyError;
use super::key_material::{SecureKeyBytes, generate_key_bytes, key_digest};
use super::manifest::NamespaceManifest;
use super::namespace::{Namespace, SECURE_KEY_SERVICE, manifest_account, version_account};
use super::native_store::NativeKeyStore;

/// Safe metadata for list operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMetadata {
    pub version: i64,
    pub state: SecureKeyVersionState,
    pub key_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceMetadata {
    pub namespace: String,
    pub active_version: Option<i64>,
    pub versions: Vec<VersionMetadata>,
}

pub struct Worker<'a> {
    pub db: &'a Db,
    pub store: &'a dyn NativeKeyStore,
    pub installation: &'a InstallationIdentity,
    pub reconciler: &'a dyn ConsumerReconciler,
}

impl Worker<'_> {
    pub(crate) fn tx<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<T, SecureKeyError> + Send + 'static,
    ) -> Result<T, SecureKeyError>
    where
        T: Send + 'static,
    {
        // Db blocking API is anyhow::Result; nest SecureKeyError so typed failures survive.
        match self.db.blocking_write_for_sync_maintenance(move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            match f(conn) {
                Ok(v) => {
                    conn.execute_batch("COMMIT;")?;
                    Ok::<Result<T, SecureKeyError>, anyhow::Error>(Ok(v))
                }
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK;");
                    Ok(Err(e))
                }
            }
        }) {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(SecureKeyError::Internal(e.to_string())),
        }
    }

    pub(crate) fn read<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<T, SecureKeyError> + Send + 'static,
    ) -> Result<T, SecureKeyError>
    where
        T: Send + 'static,
    {
        // Writer path for simplicity (in-memory + file both support write closure reads).
        match self.db.blocking_write_for_sync_maintenance(move |conn| {
            Ok::<Result<T, SecureKeyError>, anyhow::Error>(f(conn))
        }) {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(SecureKeyError::Internal(e.to_string())),
        }
    }

    pub fn startup_reconcile(&self) -> Result<(), SecureKeyError> {
        // Hard manifest invariants before any saga resume — never rewrite history
        // from a corrupt active∈retired manifest even if an open saga exists.
        let namespaces = self.read(|conn| {
            list_namespaces_conn(conn).map_err(|e| SecureKeyError::Internal(e.to_string()))
        })?;
        for ns_row in &namespaces {
            let ns = Namespace::parse(&ns_row.namespace)?;
            self.pre_resume_manifest_invariants(&ns)?;
        }
        // Resume interrupted sealed-state writes before consumers observe slots.
        self.sealed_startup_resume_all()?;
        // Conservatively re-pin sealed_state consumer refs from valid native slots.
        for ns_row in &namespaces {
            if let Ok(ns) = Namespace::parse(&ns_row.namespace) {
                // Fail closed: cannot start with unreconciled sealed-state retention.
                self.sealed_reconcile_key_refs(&ns)?;
            }
        }
        // Drive every open saga to completion (or Corrupt).
        let sagas = self.read(|conn| {
            list_open_sagas_conn(conn).map_err(|e| SecureKeyError::Internal(e.to_string()))
        })?;
        for saga in sagas {
            match saga.kind {
                SecureKeySagaKind::Provision => self.resume_provision(&saga.op_id)?,
                SecureKeySagaKind::Retire => self.resume_retire(&saga.op_id)?,
            }
        }
        // Reference reconciliation.
        let refs = self.read(|conn| {
            list_recon_refs_conn(conn).map_err(|e| SecureKeyError::Internal(e.to_string()))
        })?;
        for r in refs {
            self.reconcile_ref(&r)?;
        }
        // Unexplained active-version / manifest mismatches must fail closed before serving.
        for ns_row in namespaces {
            let ns = Namespace::parse(&ns_row.namespace)?;
            self.check_consistency(&ns)?;
        }
        Ok(())
    }

    /// Fail closed on corrupt manifests that must never be resumed over.
    fn pre_resume_manifest_invariants(&self, namespace: &Namespace) -> Result<(), SecureKeyError> {
        let account = manifest_account(self.installation.as_hex(), namespace)?;
        let m = match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
            Ok(s) => NamespaceManifest::from_bytes(s.as_slice())?,
            Err(SecureKeyError::NotFound(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        m.verify_binding(self.installation.as_hex(), namespace)?;
        if let Some(mav) = m.active_version
            && m.retired.contains(&mav)
        {
            return Err(SecureKeyError::Corrupt(format!(
                "manifest active version {mav} is also listed retired (pre-resume)"
            )));
        }
        Ok(())
    }

    fn reconcile_ref(&self, r: &SecureKeyConsumerRef) -> Result<(), SecureKeyError> {
        let exists = match self
            .reconciler
            .consumer_exists(&r.consumer_kind, &r.consumer_id)
        {
            Ok(v) => v,
            Err(_) => {
                // Unknown kind: fail closed — retain.
                return Ok(());
            }
        };
        match r.state {
            SecureKeyRefState::Reserved if !exists => {
                // Orphaned reservation; safe to release.
                let id = r.reference_id.clone();
                self.tx(move |conn| {
                    mark_consumer_ref_released_conn(conn, &id)
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                    Ok(())
                })?;
            }
            SecureKeyRefState::Releasing if !exists => {
                let id = r.reference_id.clone();
                self.tx(move |conn| {
                    mark_consumer_ref_released_conn(conn, &id)
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                    Ok(())
                })?;
            }
            _ => {
                // Existing consumer or conservative retention.
            }
        }
        Ok(())
    }

    /// Drive open sagas for `namespace`, then fail closed on unexplained mismatch.
    pub(crate) fn ensure_namespace_ready(
        &self,
        namespace: &Namespace,
    ) -> Result<(), SecureKeyError> {
        self.pre_resume_manifest_invariants(namespace)?;
        // 1) Resume sealed-state write sagas first so an interrupted invalid target
        //    can be explained/removed before slot reconciliation sees it as Corrupt.
        self.sealed_resume_open_sagas_for(namespace)?;
        // 2) Re-pin sealed_state refs from valid native slots before any Retire resume.
        //    A rolled-back consumer ref must never authorize deleting a key still named
        //    by a sealed slot (AC4).
        self.sealed_reconcile_key_refs(namespace)?;
        let ns = namespace.as_str().to_owned();
        let open = self.read({
            let ns = ns.clone();
            move |conn| {
                Ok(list_open_sagas_conn(conn)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))?
                    .into_iter()
                    .filter(|s| s.namespace == ns)
                    .collect::<Vec<_>>())
            }
        })?;
        for saga in open {
            match saga.kind {
                SecureKeySagaKind::Provision => self.resume_provision(&saga.op_id)?,
                SecureKeySagaKind::Retire => self.resume_retire(&saga.op_id)?,
            }
        }
        self.check_consistency(namespace)
    }

    pub fn create_or_load(
        &self,
        namespace: &Namespace,
    ) -> Result<(i64, SecureKeyBytes), SecureKeyError> {
        self.ensure_namespace_ready(namespace)?;
        let ns = namespace.as_str().to_owned();
        let existing = self.read({
            let ns = ns.clone();
            move |conn| {
                get_namespace_conn(conn, &ns).map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;
        if let Some(row) = existing
            && let Some(v) = row.active_version
        {
            return self.load_version_after_consistent(namespace, v);
        }
        // Create next version via provision saga (v1 when empty).
        self.provision_new(namespace)
    }

    pub fn load_version(
        &self,
        namespace: &Namespace,
        version: i64,
    ) -> Result<(i64, SecureKeyBytes), SecureKeyError> {
        self.ensure_namespace_ready(namespace)?;
        self.load_version_after_consistent(namespace, version)
    }

    /// Load a key version without resuming open provision/retire sagas.
    /// Used by sealed-state probe/reconcile so retirement cannot run before
    /// native slots re-pin their consumer refs.
    pub(crate) fn load_version_after_consistent(
        &self,
        namespace: &Namespace,
        version: i64,
    ) -> Result<(i64, SecureKeyBytes), SecureKeyError> {
        let ns = namespace.as_str().to_owned();
        let row = self.read({
            let ns = ns.clone();
            move |conn| {
                get_version_conn(conn, &ns, version)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;
        let Some(row) = row else {
            return Err(SecureKeyError::NotFound(format!(
                "version {version} missing in {}",
                namespace.as_str()
            )));
        };
        match row.state {
            SecureKeyVersionState::Active | SecureKeyVersionState::Retained => {}
            SecureKeyVersionState::Pending => {
                return Err(SecureKeyError::NotFound(
                    "version pending activation".into(),
                ));
            }
            SecureKeyVersionState::Retiring | SecureKeyVersionState::Retired => {
                return Err(SecureKeyError::NotFound(
                    "version retiring or retired".into(),
                ));
            }
        }
        let account = version_account(self.installation.as_hex(), namespace, version)?;
        // Active/Retained coordination proves the item must exist: missing is Corrupt.
        let secret = match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
            Ok(s) => s,
            Err(SecureKeyError::NotFound(_)) => {
                return Err(SecureKeyError::Corrupt(format!(
                    "native item missing for {} version {version}",
                    row.state.as_str()
                )));
            }
            Err(e) => return Err(e),
        };
        let key = secret.into_key_bytes()?;
        let digest = key_digest(&key);
        if digest != row.key_digest {
            return Err(SecureKeyError::Corrupt(
                "key digest mismatch vs coordination row".into(),
            ));
        }
        Ok((version, key))
    }

    pub fn rotate(&self, namespace: &Namespace) -> Result<(i64, SecureKeyBytes), SecureKeyError> {
        // Ensure namespace exists with an active version first.
        let _ = self.create_or_load(namespace)?;
        self.provision_new(namespace)
    }

    pub fn list_metadata(
        &self,
        namespace: &Namespace,
    ) -> Result<NamespaceMetadata, SecureKeyError> {
        self.ensure_namespace_ready(namespace)?;
        let ns = namespace.as_str().to_owned();
        self.read(move |conn| {
            let row = get_namespace_conn(conn, &ns)
                .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
            let Some(row) = row else {
                return Err(SecureKeyError::NotFound(format!("namespace {ns} missing")));
            };
            let versions = list_versions_conn(conn, &ns)
                .map_err(|e| SecureKeyError::Internal(e.to_string()))?
                .into_iter()
                .filter(|v| {
                    !matches!(
                        v.state,
                        SecureKeyVersionState::Pending | SecureKeyVersionState::Retired
                    )
                })
                .map(|v| VersionMetadata {
                    version: v.version,
                    state: v.state,
                    key_digest: v.key_digest,
                })
                .collect();
            Ok(NamespaceMetadata {
                namespace: row.namespace,
                active_version: row.active_version,
                versions,
            })
        })
    }

    pub fn reserve(
        &self,
        reference_id: &str,
        namespace: &Namespace,
        version: i64,
        consumer_kind: &str,
        consumer_id: &str,
    ) -> Result<SecureKeyConsumerRef, SecureKeyError> {
        self.ensure_namespace_ready(namespace)?;
        let reference_id = reference_id.to_owned();
        let ns = namespace.as_str().to_owned();
        let consumer_kind = consumer_kind.to_owned();
        let consumer_id = consumer_id.to_owned();
        self.tx(move |conn| {
            match reserve_consumer_ref_conn(
                conn,
                &reference_id,
                &ns,
                version,
                &consumer_kind,
                &consumer_id,
            )
            .map_err(|e| SecureKeyError::Internal(e.to_string()))?
            {
                ReserveResult::Reserved(r) | ReserveResult::Idempotent(r) => Ok(r),
                ReserveResult::Retiring => Err(SecureKeyError::Retiring {
                    namespace: ns,
                    version,
                }),
                ReserveResult::NotFound => Err(SecureKeyError::NotFound(
                    "version not found for reservation".into(),
                )),
                ReserveResult::NotReservable { state } => Err(SecureKeyError::Invalid(format!(
                    "version not reservable in state {state:?}"
                ))),
                ReserveResult::Conflict => Err(SecureKeyError::Invalid(
                    "consumer reference conflict".into(),
                )),
            }
        })
    }

    pub fn activate_ref(&self, reference_id: &str) -> Result<(), SecureKeyError> {
        let reference_id = reference_id.to_owned();
        self.tx(move |conn| activate_ref_in_tx(conn, &reference_id))
    }

    pub fn begin_release_ref(&self, reference_id: &str) -> Result<(), SecureKeyError> {
        let reference_id = reference_id.to_owned();
        self.tx(move |conn| begin_release_in_tx(conn, &reference_id))
    }

    pub fn complete_release_ref(&self, reference_id: &str) -> Result<(), SecureKeyError> {
        let reference_id = reference_id.to_owned();
        let row = self.read({
            let id = reference_id.clone();
            move |conn| {
                get_ref_by_id_conn(conn, &id).map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;
        let Some(row) = row else {
            return Err(SecureKeyError::NotFound("reference not found".into()));
        };
        if !matches!(
            row.state,
            SecureKeyRefState::Releasing | SecureKeyRefState::Reserved
        ) {
            return Err(SecureKeyError::NotFound(
                "reference not in releasing state".into(),
            ));
        }
        match self
            .reconciler
            .consumer_exists(&row.consumer_kind, &row.consumer_id)
        {
            Ok(true) => Ok(()), // still reachable; retain
            Err(_) => Ok(()),   // unknown kind: fail closed
            Ok(false) => self.tx(move |conn| {
                mark_consumer_ref_released_conn(conn, &reference_id)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                Ok(())
            }),
        }
    }

    pub fn retire(&self, namespace: &Namespace, version: i64) -> Result<(), SecureKeyError> {
        self.ensure_namespace_ready(namespace)?;
        let ns = namespace.as_str().to_owned();
        let prepare = self.tx({
            let ns = ns.clone();
            move |conn| {
                prepare_retire_conn(conn, &ns, version)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;
        match prepare {
            RetirePrepareResult::Prepared { op_id }
            | RetirePrepareResult::AlreadyRetiring { op_id } => self.resume_retire(&op_id),
            RetirePrepareResult::InUse(info) => Err(SecureKeyError::InUse(info)),
            RetirePrepareResult::AlreadyRetired => Ok(()),
            RetirePrepareResult::ActiveVersion => Err(SecureKeyError::ActiveVersion {
                namespace: ns,
                version,
            }),
            RetirePrepareResult::NotFound => Err(SecureKeyError::NotFound(format!(
                "version {version} not retireable"
            ))),
            RetirePrepareResult::CorruptResidue => Err(SecureKeyError::Corrupt(format!(
                "version {version} is Retiring without open retire saga"
            ))),
        }
    }

    fn provision_new(
        &self,
        namespace: &Namespace,
    ) -> Result<(i64, SecureKeyBytes), SecureKeyError> {
        let key = generate_key_bytes();
        let digest = key_digest(&key);
        let ns = namespace.as_str().to_owned();
        let (op_id, version) = self.tx({
            let ns = ns.clone();
            let digest = digest.clone();
            move |conn| {
                ensure_namespace_conn(conn, &ns)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                prepare_provision_conn(conn, &ns, &digest)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;
        // Hold key only for write; resume loads from native after written.
        self.write_native_key(namespace, version, &key)?;
        self.tx({
            let op_id = op_id.clone();
            move |conn| {
                set_saga_phase_conn(conn, &op_id, ProvisionPhase::NativeItemWritten.as_str())
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))
            }
        })?;
        drop(key); // zeroized
        self.resume_provision(&op_id)?;
        self.load_version(namespace, version)
    }

    fn write_native_key(
        &self,
        namespace: &Namespace,
        version: i64,
        key: &SecureKeyBytes,
    ) -> Result<(), SecureKeyError> {
        let account = version_account(self.installation.as_hex(), namespace, version)?;
        self.store
            .set_secret(SECURE_KEY_SERVICE, &account, key.as_ref())
    }

    pub fn resume_provision(&self, op_id: &str) -> Result<(), SecureKeyError> {
        let saga = self.read({
            let op_id = op_id.to_owned();
            move |conn| {
                get_saga_conn(conn, &op_id)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))?
                    .ok_or_else(|| SecureKeyError::NotFound("provision saga missing".into()))
            }
        })?;
        if saga.kind != SecureKeySagaKind::Provision {
            return Err(SecureKeyError::Corrupt("saga kind mismatch".into()));
        }
        let namespace = Namespace::parse(&saga.namespace)?;
        let version = saga.version;
        let expected_digest = saga
            .key_digest
            .clone()
            .ok_or_else(|| SecureKeyError::Corrupt("provision saga missing digest".into()))?;
        let phase = ProvisionPhase::parse(&saga.phase)
            .map_err(|e| SecureKeyError::Corrupt(e.to_string()))?;

        let account = version_account(self.installation.as_hex(), &namespace, version)?;
        let manifest_acct = manifest_account(self.installation.as_hex(), &namespace)?;

        match phase {
            ProvisionPhase::Prepared => {
                // Prepared records the expected digest. Resume only when the exact
                // account holds that digest (write completed before phase advance).
                // Unrecorded items at this account (wrong/unrelated content) are
                // removed after exact account verification and never promoted.
                // Missing item: drop pending coordination; do not invent key bytes.
                match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
                    Ok(secret) => {
                        let key = match secret.into_key_bytes() {
                            Ok(k) => k,
                            Err(_) => {
                                // Unparsable content at exact account: remove orphan, drop pending.
                                // Delete must succeed (or NotFound) so we never drop saga while
                                // leaving an untracked native item.
                                match self.store.delete_secret(SECURE_KEY_SERVICE, &account) {
                                    Ok(()) | Err(SecureKeyError::NotFound(_)) => {}
                                    Err(e) => return Err(e),
                                }
                                self.drop_prepared_pending(op_id, &namespace, version)?;
                                // Abandoned prepare cleaned; caller may re-provision.
                                return Ok(());
                            }
                        };
                        if key_digest(&key) != expected_digest {
                            // Proven unrecorded orphan at exact account: remove, never adopt.
                            match self.store.delete_secret(SECURE_KEY_SERVICE, &account) {
                                Ok(()) | Err(SecureKeyError::NotFound(_)) => {}
                                Err(e) => return Err(e),
                            }
                            self.drop_prepared_pending(op_id, &namespace, version)?;
                            return Ok(());
                        }
                        // Recorded write: advance to Written and continue.
                        self.tx({
                            let op_id = op_id.to_owned();
                            move |conn| {
                                set_saga_phase_conn(
                                    conn,
                                    &op_id,
                                    ProvisionPhase::NativeItemWritten.as_str(),
                                )
                                .map_err(|e| SecureKeyError::Internal(e.to_string()))
                            }
                        })?;
                        self.resume_provision(op_id)
                    }
                    Err(SecureKeyError::NotFound(_)) => {
                        // Crash before native write: drop abandoned Prepared coordination.
                        self.drop_prepared_pending(op_id, &namespace, version)?;
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            ProvisionPhase::NativeItemWritten => {
                // Verify by reread. Missing item after Written is Corrupt (not NotFound).
                let secret = match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
                    Ok(s) => s,
                    Err(SecureKeyError::NotFound(_)) => {
                        return Err(SecureKeyError::Corrupt(
                            "native item missing after NativeItemWritten".into(),
                        ));
                    }
                    Err(e) => return Err(e),
                };
                let key = secret.into_key_bytes()?;
                if key_digest(&key) != expected_digest {
                    return Err(SecureKeyError::Corrupt(
                        "native item verify digest mismatch".into(),
                    ));
                }
                self.tx({
                    let op_id = op_id.to_owned();
                    move |conn| {
                        set_saga_phase_conn(
                            conn,
                            &op_id,
                            ProvisionPhase::NativeItemVerified.as_str(),
                        )
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))
                    }
                })?;
                self.resume_provision(op_id)
            }
            ProvisionPhase::NativeItemVerified => {
                // Advance manifest write + reread. Blank init only when no prior
                // activated history exists; never rewrite history on missing manifest.
                let mut manifest = self.load_manifest_for_provision_advance(&namespace)?;
                manifest.advance_active(version, &expected_digest);
                let bytes = manifest.to_bytes()?;
                self.store
                    .set_secret(SECURE_KEY_SERVICE, &manifest_acct, &bytes)?;
                // Reread verify.
                let read_back = self.store.get_secret(SECURE_KEY_SERVICE, &manifest_acct)?;
                let verified = NamespaceManifest::from_bytes(read_back.as_slice())?;
                verified.verify_binding(self.installation.as_hex(), &namespace)?;
                if verified.active_version != Some(version) {
                    return Err(SecureKeyError::Corrupt(
                        "manifest active_version not advanced".into(),
                    ));
                }
                match verified.versions.get(&version.to_string()) {
                    Some(d) if d == &expected_digest => {}
                    _ => {
                        return Err(SecureKeyError::Corrupt(
                            "manifest version digest missing or mismatched on reread".into(),
                        ));
                    }
                }
                self.tx({
                    let op_id = op_id.to_owned();
                    move |conn| {
                        set_saga_phase_conn(
                            conn,
                            &op_id,
                            ProvisionPhase::ManifestAdvancedAndVerified.as_str(),
                        )
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))
                    }
                })?;
                self.resume_provision(op_id)
            }
            ProvisionPhase::ManifestAdvancedAndVerified => {
                // Metadata activation.
                let ns = namespace.as_str().to_owned();
                let op = op_id.to_owned();
                self.tx(move |conn| {
                    activate_version_metadata_conn(conn, &ns, version)
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                    set_saga_phase_conn(conn, &op, ProvisionPhase::MetadataActivated.as_str())
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))
                })?;
                self.resume_provision(op_id)
            }
            ProvisionPhase::MetadataActivated => {
                let op = op_id.to_owned();
                self.tx(move |conn| {
                    set_saga_phase_conn(conn, &op, ProvisionPhase::Committed.as_str())
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                    delete_saga_conn(conn, &op).map_err(|e| SecureKeyError::Internal(e.to_string()))
                })?;
                Ok(())
            }
            ProvisionPhase::Committed => Ok(()),
        }
    }

    fn drop_prepared_pending(
        &self,
        op_id: &str,
        namespace: &Namespace,
        version: i64,
    ) -> Result<(), SecureKeyError> {
        let op = op_id.to_owned();
        let ns = namespace.as_str().to_owned();
        self.tx(move |conn| {
            delete_saga_conn(conn, &op).map_err(|e| SecureKeyError::Internal(e.to_string()))?;
            delete_pending_version_conn(conn, &ns, version)
                .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
            Ok(())
        })
    }

    pub fn resume_retire(&self, op_id: &str) -> Result<(), SecureKeyError> {
        let saga = self.read({
            let op_id = op_id.to_owned();
            move |conn| {
                get_saga_conn(conn, &op_id)
                    .map_err(|e| SecureKeyError::Internal(e.to_string()))?
                    .ok_or_else(|| SecureKeyError::NotFound("retire saga missing".into()))
            }
        })?;
        if saga.kind != SecureKeySagaKind::Retire {
            return Err(SecureKeyError::Corrupt("saga kind mismatch".into()));
        }
        let namespace = Namespace::parse(&saga.namespace)?;
        let version = saga.version;
        let phase =
            RetirePhase::parse(&saga.phase).map_err(|e| SecureKeyError::Corrupt(e.to_string()))?;
        let account = version_account(self.installation.as_hex(), &namespace, version)?;
        let manifest_acct = manifest_account(self.installation.as_hex(), &namespace)?;

        match phase {
            RetirePhase::Prepared => {
                // Prepared must only exist for Retiring versions; Active+Prepared is corrupt.
                let ns = namespace.as_str().to_owned();
                let state = self.read({
                    let ns = ns.clone();
                    move |conn| {
                        get_version_conn(conn, &ns, version)
                            .map_err(|e| SecureKeyError::Internal(e.to_string()))
                    }
                })?;
                match state.map(|r| r.state) {
                    Some(SecureKeyVersionState::Retiring) => {}
                    other => {
                        return Err(SecureKeyError::Corrupt(format!(
                            "retire Prepared requires Retiring state, got {other:?}"
                        )));
                    }
                }
                // Delete is idempotent: already-absent is success (crash resume).
                match self.store.delete_secret(SECURE_KEY_SERVICE, &account) {
                    Ok(()) | Err(SecureKeyError::NotFound(_)) => {}
                    Err(e) => return Err(e),
                }
                // Verify absent.
                match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
                    Err(SecureKeyError::NotFound(_)) => {}
                    Ok(_) => {
                        return Err(SecureKeyError::Corrupt(
                            "native item still present after delete".into(),
                        ));
                    }
                    Err(e) => return Err(e),
                }
                self.tx({
                    let op_id = op_id.to_owned();
                    move |conn| {
                        set_saga_phase_conn(
                            conn,
                            &op_id,
                            RetirePhase::NativeItemDeletedAndVerifiedAbsent.as_str(),
                        )
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))
                    }
                })?;
                self.resume_retire(op_id)
            }
            RetirePhase::NativeItemDeletedAndVerifiedAbsent => {
                // Missing/corrupt manifest is Corrupt — never blank-init and rewrite history.
                let mut manifest = self.load_manifest_required(&namespace)?;
                manifest.mark_retired(version);
                let bytes = manifest.to_bytes()?;
                self.store
                    .set_secret(SECURE_KEY_SERVICE, &manifest_acct, &bytes)?;
                let read_back = self.store.get_secret(SECURE_KEY_SERVICE, &manifest_acct)?;
                let verified = NamespaceManifest::from_bytes(read_back.as_slice())?;
                verified.verify_binding(self.installation.as_hex(), &namespace)?;
                if !verified.retired.contains(&version) {
                    return Err(SecureKeyError::Corrupt(
                        "manifest missing retired version".into(),
                    ));
                }
                self.tx({
                    let op_id = op_id.to_owned();
                    move |conn| {
                        set_saga_phase_conn(
                            conn,
                            &op_id,
                            RetirePhase::ManifestRetiredAndVerified.as_str(),
                        )
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))
                    }
                })?;
                self.resume_retire(op_id)
            }
            RetirePhase::ManifestRetiredAndVerified => {
                let ns = namespace.as_str().to_owned();
                let op = op_id.to_owned();
                self.tx(move |conn| {
                    mark_version_retired_conn(conn, &ns, version)
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                    set_saga_phase_conn(conn, &op, RetirePhase::MetadataRetired.as_str())
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))
                })?;
                self.resume_retire(op_id)
            }
            RetirePhase::MetadataRetired => {
                let op = op_id.to_owned();
                self.tx(move |conn| {
                    set_saga_phase_conn(conn, &op, RetirePhase::Committed.as_str())
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                    delete_saga_conn(conn, &op).map_err(|e| SecureKeyError::Internal(e.to_string()))
                })?;
                Ok(())
            }
            RetirePhase::Committed => Ok(()),
        }
    }

    /// Load manifest; missing or corrupt is always Corrupt (no blank rewrite).
    fn load_manifest_required(
        &self,
        namespace: &Namespace,
    ) -> Result<NamespaceManifest, SecureKeyError> {
        let account = manifest_account(self.installation.as_hex(), namespace)?;
        match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
            Ok(secret) => {
                let m = NamespaceManifest::from_bytes(secret.as_slice())?;
                m.verify_binding(self.installation.as_hex(), namespace)?;
                Ok(m)
            }
            Err(SecureKeyError::NotFound(_)) => Err(SecureKeyError::Corrupt(
                "manifest missing; refusing blank rewrite".into(),
            )),
            Err(e) => Err(e),
        }
    }

    /// Manifest advance for provision: blank init only with no prior version history.
    fn load_manifest_for_provision_advance(
        &self,
        namespace: &Namespace,
    ) -> Result<NamespaceManifest, SecureKeyError> {
        let account = manifest_account(self.installation.as_hex(), namespace)?;
        match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
            Ok(secret) => {
                let m = NamespaceManifest::from_bytes(secret.as_slice())?;
                m.verify_binding(self.installation.as_hex(), namespace)?;
                Ok(m)
            }
            Err(SecureKeyError::NotFound(_)) => {
                let ns = namespace.as_str().to_owned();
                let has_prior_history = self.read(move |conn| {
                    let versions = list_versions_conn(conn, &ns)
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                    Ok(versions.iter().any(|v| {
                        matches!(
                            v.state,
                            SecureKeyVersionState::Active
                                | SecureKeyVersionState::Retained
                                | SecureKeyVersionState::Retiring
                                | SecureKeyVersionState::Retired
                        )
                    }))
                })?;
                if has_prior_history {
                    return Err(SecureKeyError::Corrupt(
                        "manifest missing with prior version history".into(),
                    ));
                }
                Ok(NamespaceManifest::new(
                    self.installation.as_hex(),
                    namespace,
                ))
            }
            Err(e) => Err(e),
        }
    }

    /// Detect unexplained SQLite/manifest disagreement (no open saga).
    pub fn check_consistency(&self, namespace: &Namespace) -> Result<(), SecureKeyError> {
        let ns = namespace.as_str().to_owned();
        let (active, open_sagas, versions): (Option<i64>, Vec<_>, Vec<SecureKeyVersionRow>) = self
            .read({
                let ns = ns.clone();
                move |conn| {
                    let active = get_namespace_conn(conn, &ns)
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))?
                        .and_then(|r| r.active_version);
                    let sagas = list_open_sagas_conn(conn)
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))?
                        .into_iter()
                        .filter(|s| s.namespace == ns)
                        .collect();
                    let versions = list_versions_conn(conn, &ns)
                        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
                    Ok((active, sagas, versions))
                }
            })?;
        // Only versions with a recorded open saga may be mid-flight. Unrelated
        // disagreement is still Corrupt even when some other saga is open.
        let open_versions: std::collections::HashSet<i64> =
            open_sagas.iter().map(|s| s.version).collect();
        // Pending/Retiring without an open saga for that version is residue.
        for v in &versions {
            if matches!(
                v.state,
                SecureKeyVersionState::Pending | SecureKeyVersionState::Retiring
            ) && !open_versions.contains(&v.version)
            {
                return Err(SecureKeyError::Corrupt(format!(
                    "version {} in {:?} without open saga",
                    v.version, v.state
                )));
            }
        }
        let account = manifest_account(self.installation.as_hex(), namespace)?;
        let manifest = match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
            Ok(s) => Some(NamespaceManifest::from_bytes(s.as_slice())?),
            Err(SecureKeyError::NotFound(_)) => None,
            Err(e) => return Err(e),
        };
        let retained_or_active: Vec<_> = versions
            .iter()
            .filter(|v| {
                matches!(
                    v.state,
                    SecureKeyVersionState::Active | SecureKeyVersionState::Retained
                ) && !open_versions.contains(&v.version)
            })
            .collect();
        if manifest.is_none() && !retained_or_active.is_empty() {
            return Err(SecureKeyError::Corrupt(
                "Active/Retained versions without manifest".into(),
            ));
        }
        if let Some(m) = &manifest {
            m.verify_binding(self.installation.as_hex(), namespace)?;
            // Active pointer mismatch is only deferred when an open Provision saga
            // for the manifest or SQLite active version can explain the advance.
            // A retire saga for an inactive version never explains this mismatch.
            if m.active_version != active {
                // Only a Provision saga for the *manifest's* advanced version can
                // explain a forward mismatch (manifest ahead of SQLite metadata).
                let explained = open_sagas.iter().any(|s| {
                    s.kind == SecureKeySagaKind::Provision && Some(s.version) == m.active_version
                });
                if !explained {
                    return Err(SecureKeyError::Corrupt(
                        "manifest/SQLite active_version mismatch without explaining provision saga"
                            .into(),
                    ));
                }
            }
            // Active SQLite version must never appear in manifest.retired.
            // Valid retirement moves SQLite to Retiring before rewriting the
            // manifest; an open saga cannot explain Active+retired.
            if let Some(av) = active
                && m.retired.contains(&av)
            {
                return Err(SecureKeyError::Corrupt(format!(
                    "SQLite active version {av} is listed retired in manifest"
                )));
            }
            if let Some(mav) = m.active_version
                && m.retired.contains(&mav)
            {
                return Err(SecureKeyError::Corrupt(format!(
                    "manifest active version {mav} is also listed retired"
                )));
            }
            // Reverse: every non-retired, non-in-flight manifest version must exist
            // in SQLite as Active or Retained with matching digest.
            for (ver_str, man_digest) in &m.versions {
                let Ok(ver) = ver_str.parse::<i64>() else {
                    return Err(SecureKeyError::Corrupt(format!(
                        "manifest version key not i64: {ver_str}"
                    )));
                };
                if m.retired.contains(&ver) || open_versions.contains(&ver) {
                    continue;
                }
                match versions.iter().find(|v| v.version == ver) {
                    Some(row)
                        if matches!(
                            row.state,
                            SecureKeyVersionState::Active | SecureKeyVersionState::Retained
                        ) && &row.key_digest == man_digest => {}
                    Some(row) => {
                        return Err(SecureKeyError::Corrupt(format!(
                            "manifest version {ver} disagrees with SQLite state {:?}",
                            row.state
                        )));
                    }
                    None => {
                        return Err(SecureKeyError::Corrupt(format!(
                            "manifest version {ver} missing from SQLite without open saga"
                        )));
                    }
                }
            }
        } else if let Some(av) = active {
            let explained = open_sagas
                .iter()
                .any(|s| s.kind == SecureKeySagaKind::Provision && s.version == av);
            if !explained {
                return Err(SecureKeyError::Corrupt(
                    "SQLite active version without manifest".into(),
                ));
            }
        }
        // Duplicate Active ownership.
        let actives: Vec<_> = versions
            .iter()
            .filter(|v| v.state == SecureKeyVersionState::Active)
            .collect();
        if actives.len() > 1 {
            return Err(SecureKeyError::Corrupt(
                "duplicate active version ownership".into(),
            ));
        }
        // Active version row must match namespace pointer when that version is
        // not itself mid-saga.
        if let Some(av) = active {
            if !open_versions.contains(&av) {
                match versions.iter().find(|v| v.version == av) {
                    Some(row) if row.state == SecureKeyVersionState::Active => {}
                    Some(_) => {
                        return Err(SecureKeyError::Corrupt(
                            "namespace active_version row not in Active state".into(),
                        ));
                    }
                    None => {
                        return Err(SecureKeyError::Corrupt(
                            "namespace active_version missing version row".into(),
                        ));
                    }
                }
            }
        } else if actives.len() == 1 {
            let only = actives[0].version;
            let explained = open_sagas
                .iter()
                .any(|s| s.kind == SecureKeySagaKind::Provision && s.version == only);
            if !explained {
                return Err(SecureKeyError::Corrupt(
                    "Active version row without namespace active_version pointer".into(),
                ));
            }
        }
        // Every Active/Retained version must have a native item matching digest,
        // and when a manifest exists, digests must match SQLite.
        for v in &retained_or_active {
            if let Some(m) = &manifest {
                let Some(man_digest) = m.versions.get(&v.version.to_string()) else {
                    return Err(SecureKeyError::Corrupt(format!(
                        "SQLite version {} missing from manifest",
                        v.version
                    )));
                };
                if man_digest != &v.key_digest {
                    return Err(SecureKeyError::Corrupt(format!(
                        "manifest/SQLite digest mismatch for version {}",
                        v.version
                    )));
                }
            }
            let account = version_account(self.installation.as_hex(), namespace, v.version)?;
            match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
                Ok(secret) => {
                    let key = secret.into_key_bytes()?;
                    if key_digest(&key) != v.key_digest {
                        return Err(SecureKeyError::Corrupt(format!(
                            "native item digest mismatch for version {}",
                            v.version
                        )));
                    }
                }
                Err(SecureKeyError::NotFound(_)) => {
                    return Err(SecureKeyError::Corrupt(format!(
                        "missing native item for Active/Retained version {}",
                        v.version
                    )));
                }
                Err(e) => return Err(e),
            }
        }
        // Retired agreement: SQLite Retired ↔ manifest.retired, native absent.
        // Versions with open sagas are excluded (explained mid-flight).
        if let Some(m) = &manifest {
            for v in versions.iter().filter(|v| {
                v.state == SecureKeyVersionState::Retired && !open_versions.contains(&v.version)
            }) {
                if !m.retired.contains(&v.version) {
                    return Err(SecureKeyError::Corrupt(format!(
                        "SQLite Retired version {} missing from manifest.retired",
                        v.version
                    )));
                }
            }
            for &ver in &m.retired {
                if open_versions.contains(&ver) {
                    continue;
                }
                match versions.iter().find(|v| v.version == ver) {
                    Some(row) if row.state == SecureKeyVersionState::Retired => {}
                    Some(row) => {
                        return Err(SecureKeyError::Corrupt(format!(
                            "manifest retired version {ver} but SQLite state is {:?}",
                            row.state
                        )));
                    }
                    None => {
                        return Err(SecureKeyError::Corrupt(format!(
                            "manifest retired version {ver} missing from SQLite"
                        )));
                    }
                }
            }
        } else {
            let any_retired = versions.iter().any(|v| {
                v.state == SecureKeyVersionState::Retired && !open_versions.contains(&v.version)
            });
            if any_retired {
                return Err(SecureKeyError::Corrupt(
                    "SQLite Retired versions without manifest".into(),
                ));
            }
        }
        for v in versions.iter().filter(|v| {
            v.state == SecureKeyVersionState::Retired && !open_versions.contains(&v.version)
        }) {
            let account = version_account(self.installation.as_hex(), namespace, v.version)?;
            match self.store.get_secret(SECURE_KEY_SERVICE, &account) {
                Err(SecureKeyError::NotFound(_)) => {}
                Ok(_) => {
                    return Err(SecureKeyError::Corrupt(format!(
                        "native item still present for Retired version {}",
                        v.version
                    )));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
