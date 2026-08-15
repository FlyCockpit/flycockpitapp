//! Wrap-key vault, first-run, migrate, and import tests.
//!
//! Injected KekStore / vault only. No real OS keyring. No process env mutation.

use std::sync::Arc;

use cockpit_db::secret_vault::{
    SecretVaultKind, SecretVaultPlacement, count_active_keys_conn, insert_key_conn,
    load_authority_conn, load_item_conn,
};
use cockpit_proto::{FeatureCapabilityState, SecretStoreIntent, SecretStorePlacement};

use crate::db::Db;
use crate::db::installation_identity::ensure_installation_identity_conn;
use crate::redact::start_standalone_redaction_key_resolver_with;
use crate::secure_key::fake::FakeNativeStore;
use crate::secure_key::{
    FileKekStore, KekStore, KeyringProbeResult, MemoryKekStore, SecretStoreInjected, SecretVault,
    VaultFault, VaultFaultPoint, VaultNativeStore, ensure_secret_vault, kek_dir_for_db,
    migrate_kek_placement, reject_keyring_if_unavailable, resolve_secret_store, resume_kek_migrate,
};

use super::error::SecureKeyError;
use super::key_material::generate_key_bytes;
use super::namespace::{REDACTION_HISTORY_V1_NAMESPACE, SECURE_KEY_SERVICE, version_account};
use super::native_store::NativeKeyStore;
use super::vault::{item_aad, substitute_item_ciphertext, tamper_item_ciphertext, wrap_aad};

fn available_probe() -> KeyringProbeResult {
    KeyringProbeResult {
        state: FeatureCapabilityState::Available,
        reason: "platform keyring can hold a wrapping key".into(),
        fix_command: None,
        remedy_text: None,
    }
}

fn missing_probe() -> KeyringProbeResult {
    KeyringProbeResult {
        state: FeatureCapabilityState::Missing,
        reason: "secret service unavailable".into(),
        fix_command: Some("install gnome-keyring".into()),
        remedy_text: None,
    }
}

fn file_env() -> (tempfile::TempDir, Db, Arc<MemoryKekStore>) {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    (tmp, db, kek)
}

fn init_vault(db: &Db, kek: Arc<MemoryKekStore>) -> SecretVault {
    let installation = db
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .unwrap();
    SecretVault::initialize(db.clone(), kek, installation, 1, 1).unwrap()
}

fn assert_no_plaintext_bytes(db: &Db, needle: &[u8]) {
    db.blocking_write_for_sync_maintenance({
        let needle = needle.to_vec();
        move |conn| {
            for table in [
                "secure_key_versions",
                "secure_key_sagas",
                "secure_key_consumer_refs",
                "secret_vault_authority",
                "secret_vault_keys",
                "secret_vault_items",
                "secret_vault_sagas",
            ] {
                let exists: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )?;
                if exists == 0 {
                    continue;
                }
                let mut stmt = conn.prepare(&format!("SELECT * FROM {table}"))?;
                let col_count = stmt.column_count();
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    for i in 0..col_count {
                        if let Ok(blob) = row.get_ref(i)?.as_blob() {
                            assert!(
                                blob != needle.as_slice(),
                                "{table} column {i} held raw key/DEK/KEK bytes"
                            );
                        }
                    }
                }
            }
            Ok(())
        }
    })
    .unwrap();
}

#[test]
fn vault_unification_complete_only_after_all_stores() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let vault = init_vault(&db, kek);
    assert!(
        !db.blocking_write_for_sync_maintenance(load_authority_conn)
            .unwrap()
            .unwrap()
            .unification_complete
    );
    crate::secure_key::unify_remaining_stores(
        &vault,
        &VaultFault::at(VaultFaultPoint::BeforeComplete),
    )
    .unwrap_err();
    let mid = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert!(
        !mid.unification_complete,
        "a boot that crashes before every store completes stays 0"
    );
    crate::secure_key::unify_remaining_stores(&vault, &VaultFault::default()).unwrap();
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert!(row.unification_complete);
}

#[test]
fn wrap_key_vault_round_trip_and_aead() {
    let (_tmp, db, kek) = file_env();
    let vault = init_vault(&db, kek);
    let root = generate_key_bytes();
    vault
        .put_item(
            SecretVaultKind::SecureKeyRoot,
            "redaction-history/v1",
            root.as_ref(),
        )
        .unwrap();
    let got = vault
        .get_item(SecretVaultKind::SecureKeyRoot, "redaction-history/v1")
        .unwrap();
    assert_eq!(got.as_slice(), root.as_ref());
    vault
        .delete_item(SecretVaultKind::SecureKeyRoot, "missing")
        .unwrap();
    vault
        .delete_item(SecretVaultKind::SecureKeyRoot, "redaction-history/v1")
        .unwrap();
    assert!(matches!(
        vault.get_item(SecretVaultKind::SecureKeyRoot, "redaction-history/v1"),
        Err(SecureKeyError::NotFound(_))
    ));
    assert_no_plaintext_bytes(&db, root.as_ref());
}

#[test]
fn wrap_key_vault_rejects_tampered_ciphertext() {
    let (_tmp, db, kek) = file_env();
    let vault = init_vault(&db, kek);
    let root = generate_key_bytes();
    vault
        .put_item(SecretVaultKind::SecureKeyRoot, "a", root.as_ref())
        .unwrap();
    tamper_item_ciphertext(&db, SecretVaultKind::SecureKeyRoot, "a", |c| {
        if let Some(b) = c.last_mut() {
            *b ^= 0xff;
        }
    })
    .unwrap();
    let err = vault
        .get_item(SecretVaultKind::SecureKeyRoot, "a")
        .unwrap_err();
    assert!(matches!(err, SecureKeyError::Corrupt(_)), "{err:?}");
}

#[test]
fn wrap_key_vault_rejects_wrong_kek() {
    let (_tmp, db, kek) = file_env();
    let vault = init_vault(&db, kek.clone());
    vault
        .put_item(SecretVaultKind::SecureKeyRoot, "a", b"secret-bytes")
        .unwrap();
    let other = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    other.write_kek(1, generate_key_bytes().as_ref()).unwrap();
    let installation = db
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .unwrap();
    let err = SecretVault::open(db.clone(), other, installation).unwrap_err();
    assert!(
        matches!(err, SecureKeyError::Corrupt(_)),
        "wrong KEK must not unwrap: {err:?}"
    );
}

#[test]
fn wrap_key_vault_rejects_nonce_reuse() {
    let (_tmp, db, kek) = file_env();
    let vault = init_vault(&db, kek);
    let nonce = [7u8; 12];
    vault
        .put_item_with_nonce(SecretVaultKind::SecureKeyRoot, "a", b"one", Some(nonce))
        .unwrap();
    let err = vault
        .put_item_with_nonce(SecretVaultKind::SecureKeyRoot, "b", b"two", Some(nonce))
        .unwrap_err();
    assert!(
        matches!(err, SecureKeyError::Corrupt(ref m) if m.contains("nonce reuse")),
        "{err:?}"
    );
    let err = vault
        .put_item_with_nonce(SecretVaultKind::SecureKeyRoot, "a", b"three", Some(nonce))
        .unwrap_err();
    assert!(
        matches!(err, SecureKeyError::Corrupt(ref m) if m.contains("nonce reuse")),
        "same-item nonce reuse must fail closed: {err:?}"
    );
}

#[test]
fn wrap_key_vault_rejects_row_substitution() {
    let (_tmp, db, kek) = file_env();
    let vault = init_vault(&db, kek);
    vault
        .put_item(SecretVaultKind::SecureKeyRoot, "item-a", b"alpha-secret")
        .unwrap();
    vault
        .put_item(SecretVaultKind::SecureKeyRoot, "item-b", b"beta-secret")
        .unwrap();
    substitute_item_ciphertext(
        &db,
        SecretVaultKind::SecureKeyRoot,
        "item-a",
        SecretVaultKind::SecureKeyRoot,
        "item-b",
    )
    .unwrap();
    let err = vault
        .get_item(SecretVaultKind::SecureKeyRoot, "item-b")
        .unwrap_err();
    assert!(matches!(err, SecureKeyError::Corrupt(_)), "{err:?}");
}

#[test]
fn wrap_key_vault_rejects_aad_mismatch() {
    let (_tmp, db, kek) = file_env();
    let vault = init_vault(&db, kek);
    vault
        .put_item(SecretVaultKind::SecureKeyRoot, "item-a", b"payload")
        .unwrap();
    let bad = item_aad(
        SecretVaultKind::SealedState,
        "item-a",
        vault.key_version(),
        vault.kek_version(),
        vault.installation_hex(),
    );
    let err = vault
        .decrypt_item_with_aad(SecretVaultKind::SecureKeyRoot, "item-a", &bad)
        .unwrap_err();
    assert!(matches!(err, SecureKeyError::Corrupt(_)), "{err:?}");
    let _ = wrap_aad(1, 1, 1, vault.installation_hex());
}

#[test]
fn wrap_key_vault_rejects_second_active_dek() {
    let (_tmp, db, kek) = file_env();
    let _vault = init_vault(&db, kek);
    db.blocking_write_for_sync_maintenance(|conn| {
        let err = insert_key_conn(conn, 2, 1, &[3u8; 12], &[4u8; 48], true);
        assert!(err.is_err(), "second active DEK insert must fail");
        assert_eq!(count_active_keys_conn(conn)?, 1);
        conn.execute_batch("DROP INDEX secret_vault_keys_one_active")?;
        insert_key_conn(conn, 2, 1, &[5u8; 12], &[6u8; 48], true)?;
        assert_eq!(count_active_keys_conn(conn)?, 2);
        Ok(())
    })
    .unwrap();
    let installation = db
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .unwrap();
    let other = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let err = SecretVault::open(db.clone(), other, installation).unwrap_err();
    assert!(
        matches!(err, SecureKeyError::Corrupt(ref m) if m.contains("exactly one active DEK")),
        "{err:?}"
    );
}

#[test]
fn wrap_key_vault_wrap_txn_rollback_leaves_one_active_dek() {
    let (_tmp, db, kek) = file_env();
    let vault = init_vault(&db, kek.clone());
    vault
        .put_item(SecretVaultKind::SecureKeyRoot, "canary", b"still-here")
        .unwrap();
    let err = vault.rewrap_active_dek(true).unwrap_err();
    assert!(err.to_string().contains("injected rewrap"), "{err}");
    db.blocking_write_for_sync_maintenance(|conn| {
        assert_eq!(count_active_keys_conn(conn)?, 1);
        Ok(())
    })
    .unwrap();
    let opened = SecretVault::open(
        db.clone(),
        kek,
        db.blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
            .unwrap(),
    )
    .unwrap();
    let got = opened
        .get_item(SecretVaultKind::SecureKeyRoot, "canary")
        .unwrap();
    assert_eq!(got.as_slice(), b"still-here");
}

#[cfg(unix)]
#[test]
fn vault_unix_owner_only_modes() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("cockpit.db");
    let db = Db::open(&db_path).unwrap();
    let kek_dir = tmp.path().join("secret-vault");
    let file_kek = Arc::new(FileKekStore::new(kek_dir.clone()).unwrap());
    let installation = db
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .unwrap();
    let vault = SecretVault::initialize(db.clone(), file_kek, installation, 1, 1).unwrap();
    vault
        .put_item(SecretVaultKind::SecureKeyRoot, "a", b"root-bytes")
        .unwrap();
    let kek_path = crate::secure_key::kek_file_path(&kek_dir, 1);
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&kek_path), 0o600);
    assert_eq!(mode(&kek_dir), 0o700);
    assert_eq!(mode(&db_path), 0o600);
    for suffix in ["-wal", "-shm"] {
        let sidecar = std::path::PathBuf::from(format!("{}{suffix}", db_path.display()));
        if sidecar.exists() {
            assert_eq!(mode(&sidecar), 0o600, "{}", sidecar.display());
        }
    }
    for leftover in std::fs::read_dir(&kek_dir).unwrap() {
        let path = leftover.unwrap().path();
        assert_eq!(mode(&path), 0o600, "{}", path.display());
    }
}

#[test]
fn vault_windows_refuses_database_mode_without_dacl() {
    #[cfg(windows)]
    {
        if !crate::private_fs::PRIVATE_FS_POLICY.windows_dacl_enforced {
            let tmp = tempfile::TempDir::new().unwrap();
            let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
            let err = ensure_secret_vault(
                &db,
                &available_probe(),
                &tmp.path().join("secret-vault"),
                SecretStoreInjected::default(),
            )
            .unwrap_err();
            assert!(
                err.reason.contains("DACL") || err.reason.contains("Windows"),
                "{err:?}"
            );
            return;
        }
    }
    #[cfg(not(windows))]
    {
        assert!(
            crate::private_fs::PRIVATE_FS_POLICY.unix_mode_enforced
                || !crate::private_fs::PRIVATE_FS_POLICY.windows_dacl_enforced
        );
    }
}

#[test]
fn first_run_persists_database_even_when_keyring_available() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let effective = ensure_secret_vault(
        &db,
        &available_probe(),
        &tmp.path().join("secret-vault"),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            keyring_kek: Some(keyring_kek.clone()),
            legacy_keyring: None,
        },
    )
    .unwrap();
    assert_eq!(effective.snapshot.intent, SecretStoreIntent::Database);
    assert_eq!(
        effective.snapshot.effective_placement,
        SecretStorePlacement::Database
    );
    assert_eq!(file_kek.len(), 1);
    assert_eq!(keyring_kek.len(), 0);
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.intent, SecretVaultPlacement::Database);
    assert_eq!(row.active_placement, SecretVaultPlacement::Database);
    assert!(
        row.unification_complete,
        "empty leftover stores no-op activate and set unification_complete = 1"
    );
}

#[test]
fn first_run_persists_database_when_keyring_missing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let effective = ensure_secret_vault(
        &db,
        &missing_probe(),
        &tmp.path().join("secret-vault"),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            ..SecretStoreInjected::default()
        },
    )
    .unwrap();
    assert_eq!(
        effective.snapshot.effective_placement,
        SecretStorePlacement::Database
    );
    assert_eq!(file_kek.len(), 1);
}

#[test]
fn keyring_mode_fails_closed_when_keyring_drops() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let first = ensure_secret_vault(
        &db,
        &available_probe(),
        &tmp.path().join("secret-vault"),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            keyring_kek: Some(keyring_kek.clone()),
            legacy_keyring: None,
        },
    )
    .unwrap();
    let vault = migrate_kek_placement(
        &first.vault,
        keyring_kek.clone(),
        SecretVaultPlacement::Keyring,
        &available_probe(),
        &VaultFault::default(),
    )
    .unwrap();
    drop(vault);
    let file_before = file_kek.len();
    let err = match ensure_secret_vault(
        &db,
        &missing_probe(),
        &tmp.path().join("secret-vault"),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            keyring_kek: Some(keyring_kek.clone()),
            legacy_keyring: None,
        },
    ) {
        Err(err) => err,
        Ok(_) => panic!("keyring-down must fail closed"),
    };
    assert!(err.reason.contains("unavailable") || err.intent == SecretStoreIntent::Keyring);
    let snap = err.snapshot();
    assert_eq!(snap.intent, SecretStoreIntent::Keyring);
    assert_eq!(snap.effective_placement, SecretStorePlacement::Unavailable);
    assert!(snap.fail_closed_reason.is_some());
    assert!(snap.fix_command.is_some());
    assert_eq!(file_kek.len(), file_before);
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.intent, SecretVaultPlacement::Keyring);
    assert_eq!(row.active_placement, SecretVaultPlacement::Keyring);
}

#[test]
fn reject_keyring_secret_store_when_capability_missing() {
    let err = reject_keyring_if_unavailable(&missing_probe()).unwrap_err();
    assert!(
        matches!(err, SecureKeyError::KekUnavailable { .. }),
        "{err:?}"
    );
}

#[test]
fn secret_store_migrate_fails_closed_before_activation() {
    let (_tmp, db, file_kek) = file_env();
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let vault = init_vault(&db, file_kek.clone());
    let err = migrate_kek_placement(
        &vault,
        keyring_kek.clone(),
        SecretVaultPlacement::Keyring,
        &available_probe(),
        &VaultFault::at(VaultFaultPoint::BeforeDestWrite),
    )
    .unwrap_err();
    assert!(err.to_string().contains("injected vault fault"), "{err}");
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.active_placement, SecretVaultPlacement::Database);
    assert_eq!(file_kek.len(), 1);
    assert_eq!(keyring_kek.len(), 0);
}

#[test]
fn secret_store_migrate_activation_txn_rollback() {
    let (_tmp, db, file_kek) = file_env();
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let vault = init_vault(&db, file_kek.clone());
    let err = migrate_kek_placement(
        &vault,
        keyring_kek.clone(),
        SecretVaultPlacement::Keyring,
        &available_probe(),
        &VaultFault::at(VaultFaultPoint::InsideActivation),
    )
    .unwrap_err();
    assert!(err.to_string().contains("injected vault fault"), "{err}");
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.active_placement, SecretVaultPlacement::Database);
    assert_eq!(row.intent, SecretVaultPlacement::Database);
    let reopened = SecretVault::open(
        db.clone(),
        file_kek,
        db.blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reopened.kek_version(), 1);
}

#[test]
fn secret_store_migrate_resumes_after_activation() {
    let (_tmp, db, file_kek) = file_env();
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let vault = init_vault(&db, file_kek.clone());
    let _ = migrate_kek_placement(
        &vault,
        keyring_kek.clone(),
        SecretVaultPlacement::Keyring,
        &available_probe(),
        &VaultFault::at(VaultFaultPoint::AfterActivation),
    )
    .unwrap_err();
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.active_placement, SecretVaultPlacement::Keyring);
    resume_kek_migrate(
        &db,
        file_kek.clone(),
        keyring_kek.clone(),
        SecretVaultPlacement::Keyring,
        &available_probe(),
        &VaultFault::default(),
    )
    .unwrap();
    assert_eq!(file_kek.len(), 0);
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.active_placement, SecretVaultPlacement::Keyring);
}

#[test]
fn secret_store_migrate_resumes_after_source_delete() {
    let (_tmp, db, file_kek) = file_env();
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let vault = init_vault(&db, file_kek.clone());
    let _ = migrate_kek_placement(
        &vault,
        keyring_kek.clone(),
        SecretVaultPlacement::Keyring,
        &available_probe(),
        &VaultFault::at(VaultFaultPoint::BeforeComplete),
    )
    .unwrap_err();
    resume_kek_migrate(
        &db,
        file_kek.clone(),
        keyring_kek.clone(),
        SecretVaultPlacement::Keyring,
        &available_probe(),
        &VaultFault::default(),
    )
    .unwrap();
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.active_placement, SecretVaultPlacement::Keyring);
}

#[test]
fn secret_store_migrate_to_keyring_removes_file_kek() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let kek_dir = tmp.path().join("secret-vault");
    let file_kek = Arc::new(FileKekStore::new(kek_dir.clone()).unwrap());
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let installation = db
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .unwrap();
    let vault = SecretVault::initialize(db.clone(), file_kek.clone(), installation, 1, 1).unwrap();
    vault
        .put_item(SecretVaultKind::SecureKeyRoot, "canary", b"payload")
        .unwrap();
    let migrated = migrate_kek_placement(
        &vault,
        keyring_kek.clone(),
        SecretVaultPlacement::Keyring,
        &available_probe(),
        &VaultFault::default(),
    )
    .unwrap();
    assert!(
        file_kek.residue_paths().is_empty(),
        "{:?}",
        file_kek.residue_paths()
    );
    let got = migrated
        .get_item(SecretVaultKind::SecureKeyRoot, "canary")
        .unwrap();
    assert_eq!(got.as_slice(), b"payload");
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert!(
        row.unification_complete,
        "KEK migrate must preserve unification_complete"
    );
}

#[test]
fn secret_store_migrate_to_database_removes_keyring_kek() {
    let (_tmp, db, file_kek) = file_env();
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let vault = init_vault(&db, file_kek.clone());
    vault
        .put_item(SecretVaultKind::SecureKeyRoot, "canary", b"payload")
        .unwrap();
    let on_keyring = migrate_kek_placement(
        &vault,
        keyring_kek.clone(),
        SecretVaultPlacement::Keyring,
        &available_probe(),
        &VaultFault::default(),
    )
    .unwrap();
    let back = migrate_kek_placement(
        &on_keyring,
        file_kek.clone(),
        SecretVaultPlacement::Database,
        &available_probe(),
        &VaultFault::default(),
    )
    .unwrap();
    assert_eq!(keyring_kek.len(), 0);
    let got = back
        .get_item(SecretVaultKind::SecureKeyRoot, "canary")
        .unwrap();
    assert_eq!(got.as_slice(), b"payload");
}

#[test]
fn import_legacy_secure_key_roots_then_drop_keyring_items() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let installation = db
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .unwrap();
    let legacy = FakeNativeStore::new();
    let ns = super::namespace::Namespace::parse(REDACTION_HISTORY_V1_NAMESPACE).unwrap();
    let account = version_account(installation.as_hex(), &ns, 1).unwrap();
    let root = generate_key_bytes();
    legacy
        .set_secret(SECURE_KEY_SERVICE, &account, root.as_ref())
        .unwrap();
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let effective = ensure_secret_vault(
        &db,
        &available_probe(),
        &tmp.path().join("secret-vault"),
        SecretStoreInjected {
            file_kek: Some(file_kek),
            keyring_kek: Some(keyring_kek.clone()),
            legacy_keyring: Some(Arc::new(legacy.clone())),
        },
    )
    .unwrap();
    let got = effective
        .vault
        .get_item(SecretVaultKind::SecureKeyRoot, &account)
        .unwrap();
    assert_eq!(got.as_slice(), root.as_ref());
    assert!(legacy.get_secret(SECURE_KEY_SERVICE, &account).is_err());
    assert_eq!(keyring_kek.len(), 0);
}

#[test]
fn ask_first_run_uses_database_when_keyring_available() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let (actor, _resolver) = start_standalone_redaction_key_resolver_with(
        &db,
        &available_probe(),
        Some(tmp.path().join("secret-vault")),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            keyring_kek: Some(keyring_kek.clone()),
            legacy_keyring: None,
        },
    )
    .unwrap();
    drop(actor);
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.active_placement, SecretVaultPlacement::Database);
    assert_eq!(file_kek.len(), 1);
    assert_eq!(keyring_kek.len(), 0);
}

#[test]
fn ask_first_run_uses_database_when_keyring_missing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let (_actor, _) = start_standalone_redaction_key_resolver_with(
        &db,
        &missing_probe(),
        Some(tmp.path().join("secret-vault")),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            ..SecretStoreInjected::default()
        },
    )
    .unwrap();
    assert_eq!(file_kek.len(), 1);
}

#[test]
fn ask_keyring_mode_fails_closed_without_file_kek() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let first = ensure_secret_vault(
        &db,
        &available_probe(),
        &tmp.path().join("secret-vault"),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            keyring_kek: Some(keyring_kek.clone()),
            legacy_keyring: None,
        },
    )
    .unwrap();
    let _ = migrate_kek_placement(
        &first.vault,
        keyring_kek.clone(),
        SecretVaultPlacement::Keyring,
        &available_probe(),
        &VaultFault::default(),
    )
    .unwrap();
    let before = file_kek.len();
    let err = match start_standalone_redaction_key_resolver_with(
        &db,
        &missing_probe(),
        Some(tmp.path().join("secret-vault")),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            keyring_kek: Some(keyring_kek),
            legacy_keyring: None,
        },
    ) {
        Err(err) => err,
        Ok(_) => panic!("keyring-down standalone resolver must fail closed"),
    };
    assert!(
        err.to_string().contains("KEK unavailable") || err.to_string().contains("unavailable"),
        "{err}"
    );
    assert_eq!(file_kek.len(), before);
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.intent, SecretVaultPlacement::Keyring);
    assert_eq!(row.active_placement, SecretVaultPlacement::Keyring);
}

#[test]
fn persisted_database_never_opens_platform_store() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    ensure_secret_vault(
        &db,
        &missing_probe(),
        &tmp.path().join("secret-vault"),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            ..SecretStoreInjected::default()
        },
    )
    .unwrap();
    // Second start with database authority must not need a keyring store.
    let again = ensure_secret_vault(
        &db,
        &missing_probe(),
        &tmp.path().join("secret-vault"),
        SecretStoreInjected {
            file_kek: Some(file_kek),
            keyring_kek: None,
            legacy_keyring: None,
        },
    )
    .unwrap();
    assert_eq!(
        again.snapshot.effective_placement,
        SecretStorePlacement::Database
    );
}

#[test]
fn resolve_first_run_is_always_database() {
    let decision = resolve_secret_store(None, &available_probe()).unwrap();
    assert_eq!(decision, SecretVaultPlacement::Database);
}

#[test]
fn vault_native_store_round_trip() {
    let (_tmp, db, kek) = file_env();
    let vault = Arc::new(init_vault(&db, kek));
    let store = VaultNativeStore::new(vault);
    store
        .set_secret(SECURE_KEY_SERVICE, "acct/v00000001", b"root")
        .unwrap();
    let got = store
        .get_secret(SECURE_KEY_SERVICE, "acct/v00000001")
        .unwrap();
    assert_eq!(got.as_slice(), b"root");
}

#[test]
fn kek_dir_for_file_db_is_sibling() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let dir = kek_dir_for_db(&db).unwrap();
    assert_eq!(dir, tmp.path().join("secret-vault"));
}

#[test]
fn debug_does_not_print_key_bytes() {
    let (_tmp, db, kek) = file_env();
    let vault = init_vault(&db, kek);
    let dbg = format!("{vault:?}");
    assert!(dbg.contains("SecretVault"));
    assert!(!dbg.contains("kek:"));
    db.blocking_write_for_sync_maintenance(|conn| {
        let item = load_item_conn(conn, SecretVaultKind::SecureKeyRoot, "missing")?;
        assert!(item.is_none());
        Ok(())
    })
    .unwrap();
}
