//! Durable KEK-placement migrate saga.
//!
//! Authority switches only in the SQLite activation transaction.

use std::sync::Arc;

use cockpit_db::secret_vault::{
    SecretVaultPlacement, SecretVaultSagaPhase, insert_saga_conn, list_open_sagas_conn,
    load_authority_conn, set_saga_phase_conn, upsert_authority_conn,
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
    let authority = vault
        .db()
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?
        .ok_or_else(|| SecureKeyError::Corrupt("secret vault authority missing".into()))?;
    let source_placement = authority.active_placement;
    if source_placement == dest_placement {
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
                    dest_placement,
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

    fault.check(VaultFaultPoint::BeforeActivation)?;
    db.blocking_write_for_sync_maintenance({
        let op_id = op_id.to_owned();
        let fingerprint = fingerprint.to_owned();
        let fault = fault.clone();
        move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            let result = (|| {
                let existing_complete = load_authority_conn(conn)?
                    .map(|row| row.unification_complete)
                    .unwrap_or(false);
                upsert_authority_conn(
                    conn,
                    dest_placement,
                    dest_placement,
                    &fingerprint,
                    authority_kek_version,
                    1,
                    existing_complete,
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
    .map_err(|e| {
        if e.to_string().contains("injected vault fault") {
            SecureKeyError::Internal(e.to_string())
        } else {
            SecureKeyError::Internal(e.to_string())
        }
    })?;
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
        move |conn| set_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::Complete)
    })
    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;

    SecretVault::open(db.clone(), dest, installation)
}

/// Resume an incomplete migrate saga. Destination is authoritative only after
/// the activation row says so.
pub fn resume_kek_migrate(
    db: &Db,
    source: Arc<dyn KekStore>,
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
    if saga.dest_placement == SecretVaultPlacement::Keyring {
        reject_keyring_if_unavailable(probe)?;
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
            source.delete_kek(kek_version)?;
            db.blocking_write_for_sync_maintenance({
                let op_id = saga.op_id.clone();
                move |conn| set_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::SourceDeleted)
            })
            .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
            db.blocking_write_for_sync_maintenance({
                let op_id = saga.op_id.clone();
                move |conn| set_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::Complete)
            })
            .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
            Ok(Some(SecretVault::open(db.clone(), dest, installation)?))
        }
        SecretVaultSagaPhase::SourceDeleted => {
            db.blocking_write_for_sync_maintenance({
                let op_id = saga.op_id.clone();
                move |conn| set_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::Complete)
            })
            .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
            Ok(Some(SecretVault::open(db.clone(), dest, installation)?))
        }
        SecretVaultSagaPhase::Complete => {
            Ok(Some(SecretVault::open(db.clone(), dest, installation)?))
        }
    }
}
