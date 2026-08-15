//! Durable remaining-store import into the wrap-key vault.
//!
//! Same activation machine as KEK migrate: copy → verify → activate (same
//! SQLite transaction as the store-authoritative marker) → delete source →
//! complete. `unification_complete` flips only when every remaining store has
//! activated or no-op'd.

use std::path::{Path, PathBuf};

#[cfg(test)]
use cockpit_db::secret_vault::load_import_saga_for_store_conn;
use cockpit_db::secret_vault::{
    SecretVaultKind, SecretVaultSagaPhase, SecretVaultStore, SecretVaultStoreAuthority,
    all_stores_vault_authoritative_conn, insert_import_saga_conn, list_open_import_sagas_conn,
    load_store_state_conn, set_import_saga_phase_conn, set_unification_complete_conn,
    upsert_store_state_conn,
};
use uuid::Uuid;

use rusqlite::OptionalExtension;

use crate::credentials::{self, CredentialStore};
use crate::db::Db;
use crate::sealed::compartment::{self, SealedCompartment, SealedCompartmentKey};

use super::error::SecureKeyError;
use super::migrate::{VaultFault, VaultFaultPoint};
use super::vault::SecretVault;

const SUBSCRIPTION_ACK_PREFIX: &str = "subscription-oauth-ack:";

pub fn session_sealed_item_id(session_id: &str, value_id: &str, version: i64) -> String {
    format!("{session_id}/{value_id}/v{version}")
}

pub fn redaction_table_item_id(session_id: &str) -> String {
    session_id.to_string()
}

pub fn store_is_vault_authoritative(
    db: &Db,
    store: SecretVaultStore,
) -> Result<bool, SecureKeyError> {
    db.blocking_write_for_sync_maintenance(move |conn| {
        Ok(matches!(
            load_store_state_conn(conn, store)?,
            Some(row) if row.authoritative == SecretVaultStoreAuthority::Vault
        ))
    })
    .map_err(|e| SecureKeyError::Internal(e.to_string()))
}

/// Import leftover plaintext stores. Safe to call on every boot.
pub fn unify_remaining_stores(
    vault: &SecretVault,
    fault: &VaultFault,
) -> Result<(), SecureKeyError> {
    resume_open_import_sagas(vault, fault)?;
    for store in SecretVaultStore::all() {
        if store_is_vault_authoritative(vault.db(), store)? {
            continue;
        }
        import_store(vault, store, fault)?;
    }
    maybe_mark_unification_complete(vault.db(), fault)?;
    Ok(())
}

fn resume_open_import_sagas(vault: &SecretVault, fault: &VaultFault) -> Result<(), SecureKeyError> {
    let open = vault
        .db()
        .blocking_write_for_sync_maintenance(list_open_import_sagas_conn)
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    for saga in open {
        resume_import_saga(vault, &saga.op_id, saga.store, saga.phase, fault)?;
    }
    Ok(())
}

fn import_store(
    vault: &SecretVault,
    store: SecretVaultStore,
    fault: &VaultFault,
) -> Result<(), SecureKeyError> {
    let op_id = format!("import:{}:{}", store.as_str(), Uuid::new_v4());
    vault
        .db()
        .blocking_write_for_sync_maintenance({
            let op_id = op_id.clone();
            move |conn| insert_import_saga_conn(conn, &op_id, store, SecretVaultSagaPhase::Prepared)
        })
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    run_import_from_prepared(vault, &op_id, store, fault)
}

fn resume_import_saga(
    vault: &SecretVault,
    op_id: &str,
    store: SecretVaultStore,
    phase: SecretVaultSagaPhase,
    fault: &VaultFault,
) -> Result<(), SecureKeyError> {
    match phase {
        SecretVaultSagaPhase::Prepared => run_import_from_prepared(vault, op_id, store, fault),
        SecretVaultSagaPhase::Activated => {
            delete_source_after_activation(vault, store)?;
            mark_source_deleted(vault.db(), op_id)?;
            fault.check(VaultFaultPoint::AfterSourceDelete)?;
            complete_import(vault, op_id, fault)
        }
        SecretVaultSagaPhase::SourceDeleted => complete_import(vault, op_id, fault),
        SecretVaultSagaPhase::Complete => Ok(()),
    }
}

fn run_import_from_prepared(
    vault: &SecretVault,
    op_id: &str,
    store: SecretVaultStore,
    fault: &VaultFault,
) -> Result<(), SecureKeyError> {
    copy_and_verify(vault, store)?;
    fault.check(VaultFaultPoint::BeforeActivation)?;
    activate_store(vault, op_id, store, fault)?;
    fault.check(VaultFaultPoint::AfterActivation)?;
    fault.check(VaultFaultPoint::BeforeSourceDelete)?;
    delete_source_after_activation(vault, store)?;
    mark_source_deleted(vault.db(), op_id)?;
    fault.check(VaultFaultPoint::AfterSourceDelete)?;
    complete_import(vault, op_id, fault)
}

fn copy_and_verify(vault: &SecretVault, store: SecretVaultStore) -> Result<(), SecureKeyError> {
    match store {
        SecretVaultStore::Credentials => import_credentials(vault),
        SecretVaultStore::SealedCompartment => import_sealed_compartment(vault),
        SecretVaultStore::SessionSealedValue => import_session_sealed_values(vault),
        SecretVaultStore::RedactionTable => import_redaction_tables(vault),
    }
}

fn activate_store(
    vault: &SecretVault,
    op_id: &str,
    store: SecretVaultStore,
    fault: &VaultFault,
) -> Result<(), SecureKeyError> {
    vault
        .db()
        .blocking_write_for_sync_maintenance({
            let op_id = op_id.to_owned();
            let fault = fault.clone();
            move |conn| {
                conn.execute_batch("BEGIN IMMEDIATE;")?;
                let result = (|| {
                    upsert_store_state_conn(conn, store, SecretVaultStoreAuthority::Vault)?;
                    set_import_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::Activated)?;
                    clear_plaintext_source_columns_conn(conn, store)?;
                    if all_stores_vault_authoritative_conn(conn)? {
                        set_unification_complete_conn(conn, true)?;
                    }
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
        .map_err(|e| SecureKeyError::Internal(e.to_string()))
}

fn mark_source_deleted(db: &Db, op_id: &str) -> Result<(), SecureKeyError> {
    db.blocking_write_for_sync_maintenance({
        let op_id = op_id.to_owned();
        move |conn| set_import_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::SourceDeleted)
    })
    .map_err(|e| SecureKeyError::Internal(e.to_string()))
}

fn complete_import(
    vault: &SecretVault,
    op_id: &str,
    fault: &VaultFault,
) -> Result<(), SecureKeyError> {
    fault.check(VaultFaultPoint::BeforeComplete)?;
    vault
        .db()
        .blocking_write_for_sync_maintenance({
            let op_id = op_id.to_owned();
            move |conn| {
                conn.execute_batch("BEGIN IMMEDIATE;")?;
                let result = (|| {
                    set_import_saga_phase_conn(conn, &op_id, SecretVaultSagaPhase::Complete)?;
                    if all_stores_vault_authoritative_conn(conn)? {
                        set_unification_complete_conn(conn, true)?;
                    }
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
        .map_err(|e| SecureKeyError::Internal(e.to_string()))
}

fn maybe_mark_unification_complete(db: &Db, _fault: &VaultFault) -> Result<(), SecureKeyError> {
    db.blocking_write_for_sync_maintenance(|conn| {
        if all_stores_vault_authoritative_conn(conn)? {
            set_unification_complete_conn(conn, true)?;
        }
        Ok(())
    })
    .map_err(|e| SecureKeyError::Internal(e.to_string()))
}

fn credentials_source_path(db: &Db) -> Option<PathBuf> {
    let db_path = db.path()?;
    let default_db = crate::db::Db::default_path().ok();
    if default_db.as_deref() == Some(db_path) {
        return credentials::default_path();
    }
    db_path
        .parent()
        .map(|parent| parent.join("credentials.json"))
}

fn sealed_compartment_source_path(db: &Db) -> Option<PathBuf> {
    let db_path = db.path()?;
    let default_db = crate::db::Db::default_path().ok();
    if default_db.as_deref() == Some(db_path) {
        return compartment::default_compartment_path();
    }
    db_path
        .parent()
        .map(|parent| parent.join("sealed-compartment.json"))
}

fn import_credentials(vault: &SecretVault) -> Result<(), SecureKeyError> {
    let Some(path) = credentials_source_path(vault.db()) else {
        return Ok(());
    };
    if !path.exists() {
        return Ok(());
    }
    let file = CredentialStore::open_legacy_file(path).map_err(|e| {
        SecureKeyError::Corrupt(format!("credentials.json is corrupt; leaving file: {e}"))
    })?;
    let mut expected: Vec<(SecretVaultKind, String, Vec<u8>)> = Vec::new();
    for (id, value) in file.records_for_import() {
        let kind = if id.starts_with(SUBSCRIPTION_ACK_PREFIX) {
            SecretVaultKind::SubscriptionAck
        } else {
            SecretVaultKind::CredentialRecord
        };
        let bytes = serde_json::to_vec(&value)
            .map_err(|e| SecureKeyError::Internal(format!("serializing credential record: {e}")))?;
        expected.push((kind, id, bytes));
    }
    for (name, secret) in file.secrets_for_import() {
        expected.push((SecretVaultKind::NamedSecret, name, secret.into_bytes()));
    }
    for (kind, id, bytes) in &expected {
        vault.put_item(*kind, id, bytes)?;
        let got = vault.get_item(*kind, id)?;
        if got.as_slice() != bytes.as_slice() {
            return Err(SecureKeyError::Corrupt(
                "credential import verify mismatch".into(),
            ));
        }
    }
    Ok(())
}

fn import_sealed_compartment(vault: &SecretVault) -> Result<(), SecureKeyError> {
    let Some(path) = sealed_compartment_source_path(vault.db()) else {
        return Ok(());
    };
    if !path.exists() {
        return Ok(());
    }
    let file = SealedCompartment::at(path);
    let entries = file.load_for_import().map_err(|e| {
        SecureKeyError::Corrupt(format!(
            "sealed-compartment.json is corrupt; leaving file: {e}"
        ))
    })?;
    for (locator, literal) in entries {
        let key = SealedCompartmentKey::parse(&locator)
            .map_err(|e| SecureKeyError::Corrupt(format!("sealed locator: {e}")))?;
        let bytes = literal.as_bytes().to_vec();
        vault.put_item(SecretVaultKind::SealedCompartment, key.as_str(), &bytes)?;
        let got = vault.get_item(SecretVaultKind::SealedCompartment, key.as_str())?;
        if got.as_slice() != bytes.as_slice() {
            return Err(SecureKeyError::Corrupt(
                "sealed compartment import verify mismatch".into(),
            ));
        }
    }
    Ok(())
}

fn import_session_sealed_values(vault: &SecretVault) -> Result<(), SecureKeyError> {
    let rows = vault
        .db()
        .blocking_write_for_sync_maintenance(|conn| {
            let mut stmt = conn.prepare(
                "SELECT session_id, value_id, value FROM sealed_values WHERE value IS NOT NULL AND value != ''",
            )?;
            let mapped = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            mapped
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(anyhow::Error::from)
        })
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    for (session_id, value_id, literal) in rows {
        let version = vault
            .db()
            .blocking_write_for_sync_maintenance({
                let session_id = session_id.clone();
                let value_id = value_id.clone();
                move |conn| {
                    let version: i64 = conn
                        .query_row(
                            "SELECT COALESCE(active_version, 1) FROM sealed_value_records
                              WHERE scope = 'session' AND scope_key = ?1 AND name = ?2",
                            rusqlite::params![session_id, value_id],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(anyhow::Error::from)?
                        .unwrap_or(1);
                    Ok(version.max(1))
                }
            })
            .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
        let item_id = session_sealed_item_id(&session_id, &value_id, version);
        vault.put_item(
            SecretVaultKind::SessionSealedValue,
            &item_id,
            literal.as_bytes(),
        )?;
        let got = vault.get_item(SecretVaultKind::SessionSealedValue, &item_id)?;
        if got.as_slice() != literal.as_bytes() {
            return Err(SecureKeyError::Corrupt(
                "session sealed value import verify mismatch".into(),
            ));
        }
    }
    Ok(())
}

fn import_redaction_tables(vault: &SecretVault) -> Result<(), SecureKeyError> {
    let rows = vault
        .db()
        .blocking_write_for_sync_maintenance(|conn| {
            let mut stmt = conn.prepare(
                "SELECT session_id, redaction_table_json FROM sessions
                  WHERE redaction_table_json IS NOT NULL AND redaction_table_json != ''",
            )?;
            let mapped = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            mapped
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(anyhow::Error::from)
        })
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    for (session_id, json) in rows {
        let item_id = redaction_table_item_id(&session_id);
        vault.put_item(SecretVaultKind::RedactionTable, &item_id, json.as_bytes())?;
        let got = vault.get_item(SecretVaultKind::RedactionTable, &item_id)?;
        if got.as_slice() != json.as_bytes() {
            return Err(SecureKeyError::Corrupt(
                "redaction table import verify mismatch".into(),
            ));
        }
    }
    Ok(())
}

fn clear_plaintext_source_columns_conn(
    conn: &rusqlite::Connection,
    store: SecretVaultStore,
) -> anyhow::Result<()> {
    match store {
        SecretVaultStore::SessionSealedValue => {
            conn.execute(
                "UPDATE sealed_values SET value = NULL
                  WHERE value IS NOT NULL AND value != ''",
                [],
            )?;
        }
        SecretVaultStore::RedactionTable => {
            conn.execute(
                "UPDATE sessions SET redaction_table_json = NULL
                  WHERE redaction_table_json IS NOT NULL AND redaction_table_json != ''",
                [],
            )?;
        }
        SecretVaultStore::Credentials | SecretVaultStore::SealedCompartment => {}
    }
    Ok(())
}

fn delete_source_after_activation(
    vault: &SecretVault,
    store: SecretVaultStore,
) -> Result<(), SecureKeyError> {
    match store {
        SecretVaultStore::Credentials => {
            if let Some(path) = credentials_source_path(vault.db()) {
                delete_legacy_file_and_sidecars(&path)?;
            }
        }
        SecretVaultStore::SealedCompartment => {
            if let Some(path) = sealed_compartment_source_path(vault.db()) {
                delete_legacy_file_and_sidecars(&path)?;
            }
        }
        SecretVaultStore::SessionSealedValue => {
            vault
                .db()
                .blocking_write_for_sync_maintenance(|conn| {
                    conn.execute(
                        "UPDATE sealed_values SET value = NULL
                          WHERE value IS NOT NULL AND value != ''",
                        [],
                    )?;
                    Ok(())
                })
                .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
        }
        SecretVaultStore::RedactionTable => {
            vault
                .db()
                .blocking_write_for_sync_maintenance(|conn| {
                    conn.execute(
                        "UPDATE sessions SET redaction_table_json = NULL
                          WHERE redaction_table_json IS NOT NULL AND redaction_table_json != ''",
                        [],
                    )?;
                    Ok(())
                })
                .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
        }
    }
    Ok(())
}

fn delete_legacy_file_and_sidecars(path: &Path) -> Result<(), SecureKeyError> {
    let _ = std::fs::remove_file(path);
    let lock = lock_sidecar(path);
    let _ = std::fs::remove_file(&lock);
    if let Some(parent) = path.parent() {
        let base = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("credentials.json");
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with(base) && (name.ends_with(".tmp") || name.ends_with(".lock")) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
    if path.exists() {
        return Err(SecureKeyError::Corrupt(format!(
            "legacy source still present after delete: {}",
            path.display()
        )));
    }
    Ok(())
}

fn lock_sidecar(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    path.with_file_name(name)
}

/// Test helper: run only the credentials import saga against a specific file.
#[cfg(test)]
pub fn import_credentials_from_path(
    vault: &SecretVault,
    path: &Path,
    fault: &VaultFault,
) -> Result<(), SecureKeyError> {
    if path.exists() {
        let file = CredentialStore::open_legacy_file(path.to_path_buf()).map_err(|e| {
            SecureKeyError::Corrupt(format!("credentials.json is corrupt; leaving file: {e}"))
        })?;
        for (id, value) in file.records_for_import() {
            let kind = if id.starts_with(SUBSCRIPTION_ACK_PREFIX) {
                SecretVaultKind::SubscriptionAck
            } else {
                SecretVaultKind::CredentialRecord
            };
            let bytes = serde_json::to_vec(&value).map_err(|e| {
                SecureKeyError::Internal(format!("serializing credential record: {e}"))
            })?;
            vault.put_item(kind, &id, &bytes)?;
            let got = vault.get_item(kind, &id)?;
            if got.as_slice() != bytes.as_slice() {
                return Err(SecureKeyError::Corrupt(
                    "credential import verify mismatch".into(),
                ));
            }
        }
        for (name, secret) in file.secrets_for_import() {
            vault.put_item(SecretVaultKind::NamedSecret, &name, secret.as_bytes())?;
            let got = vault.get_item(SecretVaultKind::NamedSecret, &name)?;
            if got.as_slice() != secret.as_bytes() {
                return Err(SecureKeyError::Corrupt(
                    "named secret import verify mismatch".into(),
                ));
            }
        }
    }
    let op_id = format!("import:credentials:{}", Uuid::new_v4());
    vault
        .db()
        .blocking_write_for_sync_maintenance({
            let op_id = op_id.clone();
            move |conn| {
                insert_import_saga_conn(
                    conn,
                    &op_id,
                    SecretVaultStore::Credentials,
                    SecretVaultSagaPhase::Prepared,
                )
            }
        })
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    fault.check(VaultFaultPoint::BeforeActivation)?;
    activate_store(vault, &op_id, SecretVaultStore::Credentials, fault)?;
    fault.check(VaultFaultPoint::AfterActivation)?;
    fault.check(VaultFaultPoint::BeforeSourceDelete)?;
    delete_legacy_file_and_sidecars(path)?;
    mark_source_deleted(vault.db(), &op_id)?;
    fault.check(VaultFaultPoint::AfterSourceDelete)?;
    complete_import(vault, &op_id, fault)
}

#[cfg(test)]
pub fn import_sealed_compartment_from_path(
    vault: &SecretVault,
    path: &Path,
    fault: &VaultFault,
) -> Result<(), SecureKeyError> {
    if path.exists() {
        let file = SealedCompartment::at(path.to_path_buf());
        let entries = file.load_for_import().map_err(|e| {
            SecureKeyError::Corrupt(format!("sealed-compartment.json is corrupt: {e}"))
        })?;
        for (locator, literal) in entries {
            let bytes = literal.as_bytes().to_vec();
            vault.put_item(SecretVaultKind::SealedCompartment, &locator, &bytes)?;
            let got = vault.get_item(SecretVaultKind::SealedCompartment, &locator)?;
            if got.as_slice() != bytes.as_slice() {
                return Err(SecureKeyError::Corrupt(
                    "sealed compartment import verify mismatch".into(),
                ));
            }
        }
    }
    let op_id = format!("import:sealed_compartment:{}", Uuid::new_v4());
    vault
        .db()
        .blocking_write_for_sync_maintenance({
            let op_id = op_id.clone();
            move |conn| {
                insert_import_saga_conn(
                    conn,
                    &op_id,
                    SecretVaultStore::SealedCompartment,
                    SecretVaultSagaPhase::Prepared,
                )
            }
        })
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    fault.check(VaultFaultPoint::BeforeActivation)?;
    activate_store(vault, &op_id, SecretVaultStore::SealedCompartment, fault)?;
    fault.check(VaultFaultPoint::AfterActivation)?;
    delete_legacy_file_and_sidecars(path)?;
    mark_source_deleted(vault.db(), &op_id)?;
    complete_import(vault, &op_id, fault)
}

#[cfg(test)]
pub fn resume_credentials_import_after_activation(
    vault: &SecretVault,
    path: &Path,
    fault: &VaultFault,
) -> Result<(), SecureKeyError> {
    let saga = vault
        .db()
        .blocking_write_for_sync_maintenance(|conn| {
            load_import_saga_for_store_conn(conn, SecretVaultStore::Credentials)
        })
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?
        .ok_or_else(|| SecureKeyError::Corrupt("credentials import saga missing".into()))?;
    match saga.phase {
        SecretVaultSagaPhase::Activated => {
            delete_legacy_file_and_sidecars(path)?;
            mark_source_deleted(vault.db(), &saga.op_id)?;
            complete_import(vault, &saga.op_id, fault)
        }
        SecretVaultSagaPhase::SourceDeleted => complete_import(vault, &saga.op_id, fault),
        SecretVaultSagaPhase::Prepared => {
            run_import_from_prepared(vault, &saga.op_id, SecretVaultStore::Credentials, fault)
        }
        SecretVaultSagaPhase::Complete => Ok(()),
    }
}

#[cfg(test)]
mod activation_column_tests {
    use super::*;
    use crate::db::Db;
    use crate::db::installation_identity::ensure_installation_identity_conn;
    use crate::secure_key::MemoryKekStore;
    use cockpit_proto::SecretStorePlacement;
    use std::sync::Arc;

    fn init_vault(db: &Db) -> SecretVault {
        let installation = db
            .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
            .unwrap();
        let kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
        SecretVault::initialize(db.clone(), kek, installation, 1, 1).unwrap()
    }

    #[test]
    fn import_session_sealed_and_redaction_nulls_columns_after_activation_crash() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let session = db
            .blocking_write_for_sync_maintenance(|conn| {
                Db::insert_session_row_conn(
                    conn,
                    &Db::build_new_session_row_conn(conn, "p", "/repo", "Build")?,
                )
            })
            .unwrap();
        db.blocking_write_for_sync_maintenance({
            let sid = session.session_id.to_string();
            move |conn| {
                conn.execute(
                    "INSERT INTO sealed_values (session_id, value_id, value, reason, origin, created_at)
                     VALUES (?1, 'legacy', 'legacy-plaintext-literal', 'r', 'user', 1)",
                    rusqlite::params![sid],
                )?;
                conn.execute(
                    "UPDATE sessions SET redaction_table_json = ?1 WHERE session_id = ?2",
                    rusqlite::params!["{\"entries\":[\"legacy-redaction-secret\"]}", sid],
                )?;
                Ok(())
            }
        })
        .unwrap();

        let vault = init_vault(&db);
        import_store(
            &vault,
            SecretVaultStore::SessionSealedValue,
            &VaultFault::at(VaultFaultPoint::AfterActivation),
        )
        .unwrap_err();
        let sealed_value: Option<String> = db
            .blocking_write_for_sync_maintenance({
                let sid = session.session_id.to_string();
                move |conn| {
                    Ok(conn.query_row(
                        "SELECT value FROM sealed_values WHERE session_id = ?1 AND value_id = 'legacy'",
                        rusqlite::params![sid],
                        |row| row.get(0),
                    )?)
                }
            })
            .unwrap();
        assert!(
            sealed_value
                .as_deref()
                .is_none_or(|raw| raw != "legacy-plaintext-literal"),
            "activation commit must NULL sealed_values.value even if AfterActivation crashes"
        );
        assert!(store_is_vault_authoritative(&db, SecretVaultStore::SessionSealedValue).unwrap());

        import_store(
            &vault,
            SecretVaultStore::RedactionTable,
            &VaultFault::at(VaultFaultPoint::AfterActivation),
        )
        .unwrap_err();
        let redaction: Option<String> = db
            .blocking_write_for_sync_maintenance({
                let sid = session.session_id.to_string();
                move |conn| {
                    Ok(conn.query_row(
                        "SELECT redaction_table_json FROM sessions WHERE session_id = ?1",
                        rusqlite::params![sid],
                        |row| row.get(0),
                    )?)
                }
            })
            .unwrap();
        assert!(
            redaction
                .as_deref()
                .is_none_or(|raw| !raw.contains("legacy-redaction-secret")),
            "activation commit must NULL sessions.redaction_table_json even if AfterActivation crashes"
        );
        assert!(store_is_vault_authoritative(&db, SecretVaultStore::RedactionTable).unwrap());
    }
}
