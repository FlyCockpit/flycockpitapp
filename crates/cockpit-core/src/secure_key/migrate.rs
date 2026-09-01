//! Durable KEK-placement migrate saga.
//!
//! Authority switches only in the SQLite activation transaction.

use std::sync::Arc;

use cockpit_db::secret_vault::{
    SecretVaultFileKekMode, SecretVaultPlacement, SecretVaultSagaPhase, delete_passphrase_kdf_conn,
    insert_saga_conn, list_open_sagas_conn, load_authority_conn, set_saga_phase_conn,
    upsert_authority_with_file_kek_mode_conn,
};
use cockpit_proto::FeatureCapabilityState;
use uuid::Uuid;

use crate::db::Db;

use super::error::SecureKeyError;
use super::kek_store::KekStore;
use super::key_material::SecureKeyBytes;
use super::platform::KeyringProbeResult;
use super::vault::SecretVault;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultFaultPoint {
    BeforeDestWrite,
    AfterDestWrite,
    BeforeActivation,
    InsideActivation,
    AfterActivation,
    BeforeSourceDelete,
    AfterSourceDelete,
    BeforeComplete,
}

#[derive(Clone, Default)]
pub struct VaultFault {
    pub fail_at: Option<VaultFaultPoint>,
}

impl VaultFault {
    pub fn at(point: VaultFaultPoint) -> Self {
        Self {
            fail_at: Some(point),
        }
    }

    pub(crate) fn check(&self, point: VaultFaultPoint) -> Result<(), SecureKeyError> {
        if self.fail_at == Some(point) {
            return Err(SecureKeyError::Internal(format!(
                "injected vault fault at {point:?}"
            )));
        }
        Ok(())
    }
}

pub fn reject_keyring_if_unavailable(probe: &KeyringProbeResult) -> Result<(), SecureKeyError> {
    if probe.state != FeatureCapabilityState::Available {
        return Err(SecureKeyError::KekUnavailable {
            reason: probe.reason.clone(),
            fix_command: probe
                .fix_command
                .clone()
                .or_else(|| Some(super::resolve::DEFAULT_FIX_COMMAND.to_string())),
        });
    }
    Ok(())
}

pub fn reject_database_kek_if_keyring_available(
    probe: &KeyringProbeResult,
) -> Result<(), SecureKeyError> {
    if probe.state == FeatureCapabilityState::Available {
        return Err(SecureKeyError::Invalid(
            "cannot place the wrap-key KEK in the database while the OS keyring is available"
                .into(),
        ));
    }
    Ok(())
}

pub fn migrate_kek_placement(
    vault: &SecretVault,
    dest: Arc<dyn KekStore>,
    dest_placement: SecretVaultPlacement,
    probe: &KeyringProbeResult,
    fault: &VaultFault,
) -> Result<SecretVault, SecureKeyError> {
    if dest_placement == SecretVaultPlacement::Keyring {
        reject_keyring_if_unavailable(probe)?;
    }
    if dest_placement == SecretVaultPlacement::Database {
        reject_database_kek_if_keyring_available(probe)?;
        if dest.file_kek_mode() == Some(SecretVaultFileKekMode::Passphrase) {
            return Err(SecureKeyError::Invalid(
                "migrating an existing vault to a passphrase KEK requires an explicit rewrap and is not supported"
                    .into(),
            ));
        }
    }
    let authority = vault
        .db()
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?
        .ok_or_else(|| SecureKeyError::Corrupt("secret vault authority missing".into()))?;
    let source_placement = authority.active_placement;
    let source_file_kek_mode = source_file_kek_mode(&authority, vault.kek_store().as_ref())?;
    let dest_file_kek_mode = validate_store_mode(dest_placement, dest.as_ref())?;
    if source_placement == dest_placement {
        if source_file_kek_mode != dest_file_kek_mode {
            return Err(SecureKeyError::Invalid(
                "changing a database vault's KEK mode requires an explicit rewrap and is not supported"
                    .into(),
            ));
        }
        return SecretVault::open(vault.db().clone(), dest, vault_installation(vault));
    }
    let source = vault.kek_store().clone();
    let kek_version = vault.kek_version();
    let kek = source.read_kek(kek_version)?.into_key_bytes()?;
    let fingerprint = vault.kek_fingerprint();
    let op_id = Uuid::new_v4().to_string();
    vault
        .db()
        .blocking_write_for_sync_maintenance({
            let op_id = op_id.clone();
            let fingerprint = fingerprint.clone();
            move |conn| {
                insert_saga_conn(
                    conn,
                    &op_id,
                    source_placement,
                    source_file_kek_mode,
                    dest_placement,
                    dest_file_kek_mode,
                    &fingerprint,
                    SecretVaultSagaPhase::Prepared,
                )
            }
        })
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    run_migrate_from_prepared(
        vault.db(),
        &op_id,
        source,
        dest,
        source_placement,
        dest_placement,
        &kek,
        kek_version,
        vault.kek_version(),
        vault.key_version(),
        &fingerprint,
        fault,
        vault_installation(vault),
    )
}

fn vault_installation(
    vault: &SecretVault,
) -> crate::db::installation_identity::InstallationIdentity {
    crate::db::installation_identity::InstallationIdentity::from_hex_checked(
        vault.installation_hex(),
    )
    .expect("vault installation hex is valid")
}

#[allow(clippy::too_many_arguments)]
fn run_migrate_from_prepared(
    db: &Db,
    op_id: &str,
    source: Arc<dyn KekStore>,
    dest: Arc<dyn KekStore>,
    _source_placement: SecretVaultPlacement,
    dest_placement: SecretVaultPlacement,
    kek: &SecureKeyBytes,
    kek_version: i64,
    authority_kek_version: i64,
    _key_version: i64,
    fingerprint: &str,
    fault: &VaultFault,
    installation: crate::db::installation_identity::InstallationIdentity,
) -> Result<SecretVault, SecureKeyError> {
    fault.check(VaultFaultPoint::BeforeDestWrite)?;
    dest.write_kek(kek_version, kek.as_ref())?;
    fault.check(VaultFaultPoint::AfterDestWrite)?;

    let dest_kek = dest.read_kek(kek_version)?.into_key_bytes()?;
    if dest_kek.as_ref() != kek.as_ref() {
        return Err(SecureKeyError::Corrupt(
            "destination KEK does not match source".into(),
        ));
    }
    let probe_vault = SecretVault::open(db.clone(), dest.clone(), installation.clone())?;
    let _ = probe_vault.unwrap_active_dek_with(&dest_kek)?;
    let dest_file_kek_mode = validate_store_mode(dest_placement, dest.as_ref())?;

    fault.check(VaultFaultPoint::BeforeActivation)?;
    db.blocking_write_for_sync_maintenance({
        let op_id = op_id.to_owned();
        let fingerprint = fingerprint.to_owned();
        let fault = fault.clone();
        move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            let result = (|| {
                upsert_authority_with_file_kek_mode_conn(
                    conn,
                    dest_placement,
                    dest_placement,
                    dest_file_kek_mode,
                    &fingerprint,
                    authority_kek_version,
                    1,
                )?;
                set_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::Activated)?;
                fault
                    .check(VaultFaultPoint::InsideActivation)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                Ok(())
            })();
            match result {
                Ok(()) => {
                    conn.execute_batch("COMMIT;")?;
                    Ok(())
                }
                Err(error) => {
                    let _ = conn.execute_batch("ROLLBACK;");
                    Err(error)
                }
            }
        }
    })
    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    fault.check(VaultFaultPoint::AfterActivation)?;

    fault.check(VaultFaultPoint::BeforeSourceDelete)?;
    source.delete_kek(kek_version)?;
    if source.kek_present(kek_version)? {
        return Err(SecureKeyError::Corrupt(
            "source KEK still present after delete".into(),
        ));
    }
    db.blocking_write_for_sync_maintenance({
        let op_id = op_id.to_owned();
        move |conn| set_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::SourceDeleted)
    })
    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    fault.check(VaultFaultPoint::AfterSourceDelete)?;

    fault.check(VaultFaultPoint::BeforeComplete)?;
    db.blocking_write_for_sync_maintenance({
        let op_id = op_id.to_owned();
        let source_file_kek_mode = source.file_kek_mode();
        move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            let result = (|| {
                if source_file_kek_mode == Some(SecretVaultFileKekMode::Passphrase) {
                    delete_passphrase_kdf_conn(conn)?;
                }
                set_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::Complete)
            })();
            match result {
                Ok(()) => {
                    conn.execute_batch("COMMIT;")?;
                    Ok(())
                }
                Err(error) => {
                    let _ = conn.execute_batch("ROLLBACK;");
                    Err(error)
                }
            }
        }
    })
    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;

    SecretVault::open(db.clone(), dest, installation)
}

/// Resume an incomplete migrate saga. Destination is authoritative only after
/// the activation row says so. `source` is required while the source can
/// still contain a durable KEK; an activated passphrase source is already
/// retired after a process restart and therefore needs no passphrase-derived
/// store.
pub fn resume_kek_migrate(
    db: &Db,
    source: Option<Arc<dyn KekStore>>,
    dest: Arc<dyn KekStore>,
    dest_placement: SecretVaultPlacement,
    probe: &KeyringProbeResult,
    fault: &VaultFault,
) -> Result<Option<SecretVault>, SecureKeyError> {
    let open = db
        .blocking_write_for_sync_maintenance(list_open_sagas_conn)
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    let Some(saga) = open.into_iter().next() else {
        return Ok(None);
    };
    if saga.dest_placement != dest_placement {
        return Err(SecureKeyError::Corrupt(
            "migration recovery destination does not match the durable saga".into(),
        ));
    }
    if validate_store_mode(saga.dest_placement, dest.as_ref())? != saga.dest_file_kek_mode {
        return Err(SecureKeyError::Corrupt(
            "migration recovery destination KEK mode does not match the durable saga".into(),
        ));
    }
    if saga.dest_placement == SecretVaultPlacement::Keyring {
        reject_keyring_if_unavailable(probe)?;
    }
    if saga.dest_placement == SecretVaultPlacement::Database {
        reject_database_kek_if_keyring_available(probe)?;
    }
    let authority = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?
        .ok_or_else(|| SecureKeyError::Corrupt("secret vault authority missing".into()))?;
    let installation = db
        .blocking_write_for_sync_maintenance(|conn| {
            crate::db::installation_identity::ensure_installation_identity_conn(conn)
        })
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    let kek_version = authority.kek_version;
    match saga.phase {
        SecretVaultSagaPhase::Prepared => {
            let source = required_recovery_source(source, &saga)?;
            let kek = source.read_kek(kek_version)?.into_key_bytes()?;
            let vault = run_migrate_from_prepared(
                db,
                &saga.op_id,
                source,
                dest,
                saga.source_placement,
                dest_placement,
                &kek,
                kek_version,
                authority.kek_version,
                1,
                &saga.kek_fingerprint,
                fault,
                installation,
            )?;
            Ok(Some(vault))
        }
        SecretVaultSagaPhase::Activated => {
            if !passphrase_source_is_already_retired(&saga) {
                let source = required_recovery_source(source, &saga)?;
                source.delete_kek(kek_version)?;
                if source.kek_present(kek_version)? {
                    return Err(SecureKeyError::Corrupt(
                        "source KEK still present after delete".into(),
                    ));
                }
            }
            db.blocking_write_for_sync_maintenance({
                let op_id = saga.op_id.clone();
                move |conn| set_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::SourceDeleted)
            })
            .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
            complete_saga_and_cleanup_passphrase_kdf(db, &saga)?;
            Ok(Some(SecretVault::open(db.clone(), dest, installation)?))
        }
        SecretVaultSagaPhase::SourceDeleted => {
            complete_saga_and_cleanup_passphrase_kdf(db, &saga)?;
            Ok(Some(SecretVault::open(db.clone(), dest, installation)?))
        }
        SecretVaultSagaPhase::Complete => {
            Ok(Some(SecretVault::open(db.clone(), dest, installation)?))
        }
    }
}

fn passphrase_source_is_already_retired(
    saga: &cockpit_db::secret_vault::SecretVaultSagaRow,
) -> bool {
    saga.source_placement == SecretVaultPlacement::Database
        && saga.source_file_kek_mode == Some(SecretVaultFileKekMode::Passphrase)
}

fn required_recovery_source(
    source: Option<Arc<dyn KekStore>>,
    saga: &cockpit_db::secret_vault::SecretVaultSagaRow,
) -> Result<Arc<dyn KekStore>, SecureKeyError> {
    let source = source.ok_or_else(|| {
        SecureKeyError::Corrupt(
            "migration recovery requires the source KEK store for this saga phase".into(),
        )
    })?;
    if validate_store_mode(saga.source_placement, source.as_ref())? != saga.source_file_kek_mode {
        return Err(SecureKeyError::Corrupt(
            "migration recovery source KEK mode does not match the durable saga".into(),
        ));
    }
    Ok(source)
}

fn complete_saga_and_cleanup_passphrase_kdf(
    db: &Db,
    saga: &cockpit_db::secret_vault::SecretVaultSagaRow,
) -> Result<(), SecureKeyError> {
    db.blocking_write_for_sync_maintenance({
        let op_id = saga.op_id.clone();
        let source_file_kek_mode = saga.source_file_kek_mode;
        move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            let result = (|| {
                if source_file_kek_mode == Some(SecretVaultFileKekMode::Passphrase) {
                    delete_passphrase_kdf_conn(conn)?;
                }
                set_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::Complete)
            })();
            match result {
                Ok(()) => {
                    conn.execute_batch("COMMIT;")?;
                    Ok(())
                }
                Err(error) => {
                    let _ = conn.execute_batch("ROLLBACK;");
                    Err(error)
                }
            }
        }
    })
    .map_err(|e| SecureKeyError::Internal(e.to_string()))
}

fn source_file_kek_mode(
    authority: &cockpit_db::secret_vault::SecretVaultAuthorityRow,
    source: &dyn KekStore,
) -> Result<Option<SecretVaultFileKekMode>, SecureKeyError> {
    let mode = validate_store_mode(authority.active_placement, source)?;
    if mode != authority.file_kek_mode {
        return Err(SecureKeyError::Corrupt(
            "source KEK mode does not match the active vault authority".into(),
        ));
    }
    Ok(mode)
}

fn validate_store_mode(
    placement: SecretVaultPlacement,
    store: &dyn KekStore,
) -> Result<Option<SecretVaultFileKekMode>, SecureKeyError> {
    if store.placement() != placement {
        return Err(SecureKeyError::Corrupt(
            "KEK store placement does not match the vault placement".into(),
        ));
    }
    let mode = store.file_kek_mode();
    if placement == SecretVaultPlacement::Keyring && mode.is_some() {
        return Err(SecureKeyError::Corrupt(
            "keyring KEK store unexpectedly declares a file KEK mode".into(),
        ));
    }
    if placement == SecretVaultPlacement::Database && mode.is_none() {
        return Err(SecureKeyError::Corrupt(
            "database KEK store is missing its durable file KEK mode".into(),
        ));
    }
    Ok(mode)
}
