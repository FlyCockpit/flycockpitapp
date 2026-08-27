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

#[test]
fn owner_mutation_publishes_and_rolls_back_on_redaction_failure() {
    let (_tmp, db, kek) = file_env();
    let vault = Arc::new(init_vault(&db, kek));
    let publications = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let publications_for_hook = publications.clone();
    vault.install_owner_redaction_publisher(Arc::new(move || {
        publications_for_hook.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }));

    vault
        .mutate_owner_item(
            SecretVaultKind::NamedSecret,
            "mcp:example",
            Some(br#"{"access_token":"fresh-access-token-value"}"#),
        )
        .unwrap();
    assert_eq!(publications.load(std::sync::atomic::Ordering::SeqCst), 1);

    vault.install_owner_redaction_publisher(Arc::new(|| {
        Err("injected publication failure".to_string())
    }));
    assert!(
        vault
            .mutate_owner_item(
                SecretVaultKind::NamedSecret,
                "mcp:example",
                Some(br#"{"access_token":"replacement-access-token-value"}"#),
            )
            .is_err()
    );
    let restored = vault
        .get_item(SecretVaultKind::NamedSecret, "mcp:example")
        .unwrap();
    assert_eq!(
        restored.as_slice(),
        br#"{"access_token":"fresh-access-token-value"}"#
    );
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
    SecretVault::initialize(
        db.clone(),
        kek,
        installation,
        1,
        1,
        SecretVaultPlacement::Database,
    )
    .unwrap()
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
    let vault = SecretVault::initialize(
        db.clone(),
        file_kek,
        installation,
        1,
        1,
        SecretVaultPlacement::Database,
    )
    .unwrap();
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
        if !cockpit_host::private_fs::PRIVATE_FS_POLICY.windows_dacl_enforced {
            let tmp = tempfile::TempDir::new().unwrap();
            let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
            let err = match ensure_secret_vault(
                &db,
                &available_probe(),
                &tmp.path().join("secret-vault"),
                SecretStoreInjected::default(),
            ) {
                Ok(_) => panic!("database-mode vault must require a protected Windows DACL"),
                Err(err) => err,
            };
            assert!(
                err.reason.contains("DACL") || err.reason.contains("Windows"),
                "{err:?}"
            );
            return;
        }
    }
    #[cfg(not(windows))]
    {
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(
                cockpit_host::private_fs::PRIVATE_FS_POLICY.unix_mode_enforced
                    || !cockpit_host::private_fs::PRIVATE_FS_POLICY.windows_dacl_enforced
            );
        }
    }
}

#[test]
fn initialize_deletes_kek_when_authority_txn_fails() {
    // First initialize commits authority. A second initialize against a
    // fresh store writes a KEK then fails the authority txn. Cleanup must
    // delete that untracked KEK so a later open of the first vault works.
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let first = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let first_vault = init_vault(&db, first.clone());
    first_vault
        .put_item(SecretVaultKind::SecureKeyRoot, "canary", b"payload")
        .unwrap();
    assert_eq!(first.len(), 1);
    let orphan = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let installation = db
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .unwrap();
    let err = SecretVault::initialize(
        db.clone(),
        orphan.clone(),
        installation,
        1,
        1,
        SecretVaultPlacement::Keyring,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("already"),
        "second initialize must fail the authority txn: {err:?}"
    );
    assert_eq!(orphan.len(), 0, "failed initialize must not leave a KEK");
    assert_eq!(first.len(), 1);
    let reopened = SecretVault::open(
        db.clone(),
        first.clone(),
        db.blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
            .unwrap(),
    )
    .unwrap();
    let got = reopened
        .get_item(SecretVaultKind::SecureKeyRoot, "canary")
        .unwrap();
    assert_eq!(got.as_slice(), b"payload");
}

#[test]
fn first_run_keyring_first_not_file_first() {
    first_run_persists_keyring_when_available();
}

#[test]
fn first_run_persists_keyring_when_available() {
    // Old production persisted dest=database on first-run even with an
    // available probe. This expectation rejects that path: an available
    // injected probe plus keyring KekStore must persist keyring.
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
    assert_eq!(effective.snapshot.intent, SecretStoreIntent::Keyring);
    assert_eq!(
        effective.snapshot.effective_placement,
        SecretStorePlacement::Keyring
    );
    assert_eq!(keyring_kek.len(), 1);
    assert_eq!(file_kek.len(), 0);
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.intent, SecretVaultPlacement::Keyring);
    assert_eq!(row.active_placement, SecretVaultPlacement::Keyring);
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
    assert_eq!(effective.snapshot.intent, SecretStoreIntent::Database);
    assert_eq!(
        effective.snapshot.effective_placement,
        SecretStorePlacement::Database
    );
    assert_eq!(file_kek.len(), 1);
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.intent, SecretVaultPlacement::Database);
    assert_eq!(row.active_placement, SecretVaultPlacement::Database);
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
    assert_eq!(
        first.snapshot.effective_placement,
        SecretStorePlacement::Keyring
    );
    drop(first);
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
fn resume_activated_database_migrate_rejects_available_keyring() {
    // dest=database activate then crash. Resume with an available probe
    // must reject before deleting the keyring source KEK.
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
    let vault = first.vault.as_ref();
    let err = migrate_kek_placement(
        vault,
        file_kek.clone(),
        SecretVaultPlacement::Database,
        &missing_probe(),
        &VaultFault::at(VaultFaultPoint::AfterActivation),
    )
    .unwrap_err();
    assert!(err.to_string().contains("injected vault fault"), "{err}");
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.active_placement, SecretVaultPlacement::Database);
    assert_eq!(keyring_kek.len(), 1);
    assert_eq!(file_kek.len(), 1);
    let err = resume_kek_migrate(
        &db,
        keyring_kek.clone(),
        file_kek.clone(),
        SecretVaultPlacement::Database,
        &available_probe(),
        &VaultFault::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, SecureKeyError::Invalid(ref m) if m.contains("database") && m.contains("keyring")),
        "{err:?}"
    );
    assert_eq!(keyring_kek.len(), 1);
    assert_eq!(file_kek.len(), 1);
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.active_placement, SecretVaultPlacement::Database);
}

#[test]
fn ensure_secret_vault_reloads_authority_after_resume() {
    // Prepared saga (dest KEK written, authority still database). Resume
    // activates keyring and deletes the file KEK. Boot must re-read
    // authority before open; the stale Database row would open the
    // deleted file store and fail.
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let kek_dir = tmp.path().join("secret-vault");
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let vault = init_vault(&db, file_kek.clone());
    vault
        .put_item(SecretVaultKind::SecureKeyRoot, "canary", b"payload")
        .unwrap();
    let err = migrate_kek_placement(
        &vault,
        keyring_kek.clone(),
        SecretVaultPlacement::Keyring,
        &available_probe(),
        &VaultFault::at(VaultFaultPoint::AfterDestWrite),
    )
    .unwrap_err();
    assert!(err.to_string().contains("injected vault fault"), "{err}");
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.active_placement, SecretVaultPlacement::Database);
    assert_eq!(file_kek.len(), 1);
    assert_eq!(keyring_kek.len(), 1);

    let effective = ensure_secret_vault(
        &db,
        &available_probe(),
        &kek_dir,
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            keyring_kek: Some(keyring_kek.clone()),
            legacy_keyring: None,
        },
    )
    .unwrap();
    assert_eq!(effective.snapshot.intent, SecretStoreIntent::Keyring);
    assert_eq!(
        effective.snapshot.effective_placement,
        SecretStorePlacement::Keyring
    );
    assert_eq!(file_kek.len(), 0);
    assert_eq!(keyring_kek.len(), 1);
    let got = effective
        .vault
        .get_item(SecretVaultKind::SecureKeyRoot, "canary")
        .unwrap();
    assert_eq!(got.as_slice(), b"payload");
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.intent, SecretVaultPlacement::Keyring);
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
    let vault = SecretVault::initialize(
        db.clone(),
        file_kek.clone(),
        installation,
        1,
        1,
        SecretVaultPlacement::Database,
    )
    .unwrap();
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
    assert_eq!(row.active_placement, SecretVaultPlacement::Keyring);
}

#[test]
fn available_keyring_rejects_database_kek_placement() {
    // Old production allowed dest=database beside an available keyring.
    // Decision 6 rejects that: intent/active must stay keyring.
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
    assert_eq!(
        first.snapshot.effective_placement,
        SecretStorePlacement::Keyring
    );
    let err = crate::secure_key::migrate_installation_kek(
        &db,
        SecretStorePlacement::Database,
        &available_probe(),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            keyring_kek: Some(keyring_kek.clone()),
            legacy_keyring: None,
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, SecureKeyError::Invalid(ref m) if m.contains("database") && m.contains("keyring")),
        "{err:?}"
    );
    assert_eq!(keyring_kek.len(), 1);
    assert_eq!(file_kek.len(), 0);
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.intent, SecretVaultPlacement::Keyring);
    assert_eq!(row.active_placement, SecretVaultPlacement::Keyring);
}

#[test]
fn available_keyring_rejects_noop_database_kek_placement() {
    // First-run without a keyring persists database. Once the probe is
    // available, dest=database must still be a typed reject — even when
    // active_placement is already database. The old same-placement early
    // return accepted that request and left the file KEK in place.
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let first = ensure_secret_vault(
        &db,
        &missing_probe(),
        &tmp.path().join("secret-vault"),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            keyring_kek: Some(keyring_kek.clone()),
            legacy_keyring: None,
        },
    )
    .unwrap();
    assert_eq!(
        first.snapshot.effective_placement,
        SecretStorePlacement::Database
    );
    assert_eq!(file_kek.len(), 1);
    let err = crate::secure_key::migrate_installation_kek(
        &db,
        SecretStorePlacement::Database,
        &available_probe(),
        SecretStoreInjected {
            file_kek: Some(file_kek.clone()),
            keyring_kek: Some(keyring_kek.clone()),
            legacy_keyring: None,
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, SecureKeyError::Invalid(ref m) if m.contains("database") && m.contains("keyring")),
        "{err:?}"
    );
    assert_eq!(file_kek.len(), 1);
    assert_eq!(keyring_kek.len(), 0);
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.intent, SecretVaultPlacement::Database);
    assert_eq!(row.active_placement, SecretVaultPlacement::Database);
}

#[test]
fn secret_store_migrate_to_database_rejected_when_keyring_available() {
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
    let err = migrate_kek_placement(
        &on_keyring,
        file_kek.clone(),
        SecretVaultPlacement::Database,
        &available_probe(),
        &VaultFault::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, SecureKeyError::Invalid(ref m) if m.contains("database") && m.contains("keyring")),
        "available keyring must reject dest=database: {err:?}"
    );
    assert_eq!(keyring_kek.len(), 1);
    assert_eq!(file_kek.len(), 0);
    let row = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .unwrap()
        .unwrap();
    assert_eq!(row.intent, SecretVaultPlacement::Keyring);
    assert_eq!(row.active_placement, SecretVaultPlacement::Keyring);
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
    assert_eq!(keyring_kek.len(), 1);
    assert_eq!(
        effective.snapshot.effective_placement,
        SecretStorePlacement::Keyring
    );
}

#[test]
fn ask_first_run_uses_keyring_when_available() {
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
    assert_eq!(row.active_placement, SecretVaultPlacement::Keyring);
    assert_eq!(keyring_kek.len(), 1);
    assert_eq!(file_kek.len(), 0);
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
    assert_eq!(
        first.snapshot.effective_placement,
        SecretStorePlacement::Keyring
    );
    drop(first);
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
fn resolve_first_run_is_keyring_when_available() {
    let decision = resolve_secret_store(None, &available_probe()).unwrap();
    assert_eq!(decision, SecretVaultPlacement::Keyring);
}

#[test]
fn resolve_first_run_is_database_when_keyring_missing() {
    let decision = resolve_secret_store(None, &missing_probe()).unwrap();
    assert_eq!(decision, SecretVaultPlacement::Database);
}

fn failed_probe() -> KeyringProbeResult {
    KeyringProbeResult {
        state: FeatureCapabilityState::Failed,
        reason: "platform keyring probe thread panicked".into(),
        fix_command: None,
        remedy_text: Some("The OS keyring probe panicked while a Tokio runtime was active.".into()),
    }
}

#[test]
fn resolve_first_run_does_not_persist_database_when_keyring_probe_failed() {
    let error =
        resolve_secret_store(None, &failed_probe()).expect_err("failed probe is not a placement");
    assert!(error.reason.contains("panicked"), "{}", error.reason);
    assert_eq!(error.intent, SecretStoreIntent::Unconfigured);
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

#[test]
fn ensure_secret_vault_boots_on_folded_schema() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let keyring_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
    let effective = ensure_secret_vault(
        &db,
        &available_probe(),
        &tmp.path().join("secret-vault"),
        SecretStoreInjected {
            file_kek: Some(file_kek),
            keyring_kek: Some(keyring_kek),
            legacy_keyring: None,
        },
    )
    .expect("fresh 0001-only DB must boot the vault");
    assert_eq!(
        effective.snapshot.effective_placement,
        SecretStorePlacement::Keyring
    );
    db.blocking_write_for_sync_maintenance(|conn| {
        let leftover_state = format!("{}{}", "secret_vault_store", "_state");
        let leftover_import = format!("{}{}", "secret_vault_import", "_sagas");
        for table in [leftover_state, leftover_import] {
            let exists: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table.as_str()],
                |row| row.get(0),
            )?;
            assert_eq!(exists, 0, "{table} must not exist after boot");
        }
        Ok(())
    })
    .unwrap();
    let memory = Db::open_in_memory().unwrap();
    crate::secure_key::vault_for_db(&memory).expect("in-memory vault_for_db boots folded schema");
}

#[test]
fn unify_remaining_stores_removed_before_table_drop() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root");
    let needles = [
        format!("{}{}", "unify_remaining", "_stores"),
        format!("{}{}", "secret_vault_store", "_state"),
        format!("{}{}", "secret_vault_import", "_sagas"),
        format!("{}{}", "upsert_store_state", "_conn"),
        format!("{}{}", "import_credentials_from", "_path"),
        format!("{}{}", "resume_credentials_import_after", "_activation"),
        format!("{}{}", "import_sealed_compartment_from", "_path"),
        format!("{}{}", "store_is_vault", "_authoritative"),
    ];
    let mut hits = Vec::new();
    for crate_rel in ["crates/cockpit-core", "crates/cockpit-db"] {
        walk_skipping_comments(&repo.join(crate_rel), &needles, &mut hits);
    }
    assert!(
        hits.is_empty(),
        "dual-store importer symbols must be gone: {hits:?}"
    );
}

fn walk_skipping_comments(root: &std::path::Path, needles: &[String], hits: &mut Vec<String>) {
    let entries = std::fs::read_dir(root)
        .unwrap_or_else(|e| panic!("required scan root unreadable {}: {e}", root.display()));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|e| panic!("required scan dirent unreadable {}: {e}", root.display()));
        let path = entry.path();
        if path.is_dir() {
            if entry.file_name() == "target" {
                continue;
            }
            walk_skipping_comments(&path, needles, hits);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs")
            && path.extension().and_then(|e| e.to_str()) != Some("sql")
        {
            continue;
        }
        // Guard tests legitimately name the forbidden symbols inside their
        // assertions (e.g. the sibling `unify_remaining_stores_stays_gone`).
        // Only production/SQL source may revive the dual-store importer, so
        // exclude test sources to keep the two guards mutually satisfiable.
        let is_test_source = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
            || path
                .components()
                .any(|component| component.as_os_str() == "tests");
        if is_test_source {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("required scan file unreadable {}: {e}", path.display()));
        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                continue;
            }
            if trimmed.starts_with("fn ") && trimmed.contains("removed_before_table_drop") {
                continue;
            }
            for needle in needles {
                if trimmed.contains(needle.as_str()) {
                    hits.push(format!("{}:{}:{trimmed}", path.display(), idx + 1));
                }
            }
        }
    }
}
