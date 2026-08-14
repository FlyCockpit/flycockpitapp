//! Installation-scoped KEK placement. Authority is the SQLite singleton.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cockpit_db::installation_identity::{InstallationIdentity, ensure_installation_identity_conn};
use cockpit_db::secret_vault::{
    SecretVaultAuthorityRow, SecretVaultPlacement, list_open_sagas_conn, load_authority_conn,
};
use cockpit_proto::{SecretStoreIntent, SecretStorePlacement, SecretStoreSnapshot};

use crate::db::Db;

use super::error::SecureKeyError;
use super::kek_store::{FileKekStore, KekStore, KeyringKekStore, file_kek_supported};
use super::namespace::{
    LEAK_REPORT_V1_NAMESPACE, Namespace, REDACTION_HISTORY_V1_NAMESPACE, SECURE_KEY_SERVICE,
    manifest_account, version_account,
};
use super::native_store::{KeyringNativeStore, NativeKeyStore};
use super::platform::KeyringProbeResult;
use super::sealed_state::{SealedSlot, sealed_state_account};
use super::vault::SecretVault;
use super::vault_store::classify_account;

pub const DEFAULT_FIX_COMMAND: &str = "Install and unlock a platform keyring (Linux Secret Service, macOS Keychain, or Windows Credential Manager).";

/// Injected stores for tests. Production leaves these `None`.
#[derive(Default)]
pub struct SecretStoreInjected {
    pub file_kek: Option<Arc<dyn KekStore>>,
    pub keyring_kek: Option<Arc<dyn KekStore>>,
    pub legacy_keyring: Option<Arc<dyn NativeKeyStore>>,
}

pub struct EffectiveSecretStore {
    pub vault: Arc<SecretVault>,
    pub snapshot: SecretStoreSnapshot,
    pub placement: SecretStorePlacement,
}

#[derive(Debug, Clone)]
pub struct KekUnavailable {
    pub reason: String,
    pub fix_command: Option<String>,
    pub intent: SecretStoreIntent,
}

impl KekUnavailable {
    pub fn snapshot(&self) -> SecretStoreSnapshot {
        SecretStoreSnapshot {
            intent: self.intent,
            effective_placement: SecretStorePlacement::Unavailable,
            fail_closed_reason: Some(self.reason.clone()),
            fix_command: self.fix_command.clone(),
        }
    }

    pub fn into_error(self) -> SecureKeyError {
        SecureKeyError::KekUnavailable {
            reason: self.reason,
            fix_command: self.fix_command,
        }
    }
}

impl From<KekUnavailable> for SecureKeyError {
    fn from(value: KekUnavailable) -> Self {
        value.into_error()
    }
}

pub fn kek_dir_for_db(db: &Db) -> Result<PathBuf, SecureKeyError> {
    let path = db.path().ok_or_else(|| {
        SecureKeyError::Internal(
            "in-memory database has no KEK directory; inject KekStore / file-backed Db".into(),
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        SecureKeyError::Internal("database path has no parent for KEK directory".into())
    })?;
    Ok(parent.join("secret-vault"))
}

pub fn keyring_available(probe: &KeyringProbeResult) -> bool {
    probe.state.is_available()
}

fn placement_intent(placement: SecretVaultPlacement) -> SecretStoreIntent {
    match placement {
        SecretVaultPlacement::Database => SecretStoreIntent::Database,
        SecretVaultPlacement::Keyring => SecretStoreIntent::Keyring,
    }
}

fn placement_effective(placement: SecretVaultPlacement) -> SecretStorePlacement {
    match placement {
        SecretVaultPlacement::Database => SecretStorePlacement::Database,
        SecretVaultPlacement::Keyring => SecretStorePlacement::Keyring,
    }
}

pub fn project_secret_store_snapshot(
    authority: Option<&SecretVaultAuthorityRow>,
    probe: &KeyringProbeResult,
) -> SecretStoreSnapshot {
    let Some(row) = authority else {
        return SecretStoreSnapshot::unconfigured_placeholder();
    };
    match row.active_placement {
        SecretVaultPlacement::Database => SecretStoreSnapshot {
            intent: SecretStoreIntent::Database,
            effective_placement: SecretStorePlacement::Database,
            fail_closed_reason: None,
            fix_command: None,
        },
        SecretVaultPlacement::Keyring if keyring_available(probe) => SecretStoreSnapshot {
            intent: SecretStoreIntent::Keyring,
            effective_placement: SecretStorePlacement::Keyring,
            fail_closed_reason: None,
            fix_command: None,
        },
        SecretVaultPlacement::Keyring => SecretStoreSnapshot {
            intent: SecretStoreIntent::Keyring,
            effective_placement: SecretStorePlacement::Unavailable,
            fail_closed_reason: Some(probe.reason.clone()),
            fix_command: probe
                .fix_command
                .clone()
                .or_else(|| Some(DEFAULT_FIX_COMMAND.to_string())),
        },
    }
}

/// Pure placement decision. First-run (no row) is always database.
pub fn resolve_secret_store(
    authority: Option<&SecretVaultAuthorityRow>,
    keyring_probe: &KeyringProbeResult,
) -> Result<SecretVaultPlacement, KekUnavailable> {
    match authority {
        None => Ok(SecretVaultPlacement::Database),
        Some(row) => match row.active_placement {
            SecretVaultPlacement::Database => Ok(SecretVaultPlacement::Database),
            SecretVaultPlacement::Keyring if keyring_available(keyring_probe) => {
                Ok(SecretVaultPlacement::Keyring)
            }
            SecretVaultPlacement::Keyring => Err(KekUnavailable {
                reason: keyring_probe.reason.clone(),
                fix_command: keyring_probe
                    .fix_command
                    .clone()
                    .or_else(|| Some(DEFAULT_FIX_COMMAND.to_string())),
                intent: SecretStoreIntent::Keyring,
            }),
        },
    }
}

pub fn ensure_secret_vault(
    db: &Db,
    keyring_probe: &KeyringProbeResult,
    kek_dir: &Path,
    injected: SecretStoreInjected,
) -> Result<EffectiveSecretStore, KekUnavailable> {
    let installation = db
        .blocking_write_for_sync_maintenance(|conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            let result = ensure_installation_identity_conn(conn);
            match &result {
                Ok(_) => conn.execute_batch("COMMIT;")?,
                Err(_) => {
                    let _ = conn.execute_batch("ROLLBACK;");
                }
            }
            result
        })
        .map_err(|e| KekUnavailable {
            reason: format!("installation identity: {e}"),
            fix_command: None,
            intent: SecretStoreIntent::Unconfigured,
        })?;

    let authority = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .map_err(|e| KekUnavailable {
            reason: format!("reading secret vault authority: {e}"),
            fix_command: None,
            intent: SecretStoreIntent::Unconfigured,
        })?;

    if let Some(auth) = authority.as_ref() {
        resume_open_kek_migrate(db, kek_dir, &installation, &injected, keyring_probe, auth)?;
    }

    let first_run = authority.is_none();
    let placement = resolve_secret_store(authority.as_ref(), keyring_probe)?;

    let kek_store =
        kek_store_for_placement(placement, kek_dir, &installation, &injected, first_run)?;

    let vault = if first_run {
        match SecretVault::initialize(db.clone(), kek_store.clone(), installation.clone(), 1, 1) {
            Ok(vault) => vault,
            Err(error) if error.to_string().contains("already") => {
                SecretVault::open(db.clone(), kek_store, installation).map_err(|e| {
                    KekUnavailable {
                        reason: e.to_string(),
                        fix_command: None,
                        intent: SecretStoreIntent::Database,
                    }
                })?
            }
            Err(error) => {
                return Err(KekUnavailable {
                    reason: error.to_string(),
                    fix_command: None,
                    intent: SecretStoreIntent::Database,
                });
            }
        }
    } else {
        SecretVault::open(db.clone(), kek_store, installation).map_err(|e| KekUnavailable {
            reason: e.to_string(),
            fix_command: match &e {
                SecureKeyError::KekUnavailable { fix_command, .. } => fix_command.clone(),
                _ => None,
            },
            intent: placement_intent(placement),
        })?
    };

    if first_run {
        import_legacy_secure_key_roots(&vault, keyring_probe, injected.legacy_keyring.as_deref())
            .map_err(|e| KekUnavailable {
            reason: format!("importing legacy secure-key roots: {e}"),
            fix_command: None,
            intent: SecretStoreIntent::Database,
        })?;
    }

    let snapshot = SecretStoreSnapshot {
        intent: placement_intent(placement),
        effective_placement: placement_effective(placement),
        fail_closed_reason: None,
        fix_command: None,
    };
    Ok(EffectiveSecretStore {
        vault: Arc::new(vault),
        snapshot,
        placement: placement_effective(placement),
    })
}

fn resume_open_kek_migrate(
    db: &Db,
    kek_dir: &Path,
    installation: &InstallationIdentity,
    injected: &SecretStoreInjected,
    keyring_probe: &KeyringProbeResult,
    _authority: &SecretVaultAuthorityRow,
) -> Result<(), KekUnavailable> {
    let open = db
        .blocking_write_for_sync_maintenance(list_open_sagas_conn)
        .map_err(|e| KekUnavailable {
            reason: format!("listing secret vault sagas: {e}"),
            fix_command: None,
            intent: SecretStoreIntent::Unconfigured,
        })?;
    let Some(saga) = open.into_iter().next() else {
        return Ok(());
    };
    let source = kek_store_for_placement(
        saga.source_placement,
        kek_dir,
        installation,
        injected,
        false,
    )?;
    let dest =
        kek_store_for_placement(saga.dest_placement, kek_dir, installation, injected, false)?;
    super::migrate::resume_kek_migrate(
        db,
        source,
        dest,
        saga.dest_placement,
        keyring_probe,
        &super::migrate::VaultFault::default(),
    )
    .map_err(|e| KekUnavailable {
        reason: format!("resuming KEK migrate: {e}"),
        fix_command: match &e {
            SecureKeyError::KekUnavailable { fix_command, .. } => fix_command.clone(),
            _ => None,
        },
        intent: placement_intent(saga.dest_placement),
    })?;
    Ok(())
}

fn kek_store_for_placement(
    placement: SecretVaultPlacement,
    kek_dir: &Path,
    installation: &InstallationIdentity,
    injected: &SecretStoreInjected,
    first_run: bool,
) -> Result<Arc<dyn KekStore>, KekUnavailable> {
    match placement {
        SecretVaultPlacement::Database => {
            if let Some(store) = &injected.file_kek {
                return Ok(store.clone());
            }
            if first_run {
                file_kek_supported().map_err(|e| match e {
                    SecureKeyError::KekUnavailable {
                        reason,
                        fix_command,
                    } => KekUnavailable {
                        reason,
                        fix_command,
                        intent: SecretStoreIntent::Database,
                    },
                    other => KekUnavailable {
                        reason: other.to_string(),
                        fix_command: None,
                        intent: SecretStoreIntent::Database,
                    },
                })?;
            }
            FileKekStore::new(kek_dir.to_path_buf())
                .map(|s| Arc::new(s) as Arc<dyn KekStore>)
                .map_err(|e| KekUnavailable {
                    reason: e.to_string(),
                    fix_command: None,
                    intent: SecretStoreIntent::Database,
                })
        }
        SecretVaultPlacement::Keyring => {
            if let Some(store) = &injected.keyring_kek {
                return Ok(store.clone());
            }
            Ok(Arc::new(KeyringKekStore::new(installation.as_hex())) as Arc<dyn KekStore>)
        }
    }
}

pub fn import_legacy_secure_key_roots(
    vault: &SecretVault,
    keyring_probe: &KeyringProbeResult,
    injected_legacy: Option<&dyn NativeKeyStore>,
) -> Result<(), SecureKeyError> {
    let store: Box<dyn NativeKeyStore> = match injected_legacy {
        Some(legacy) => {
            // Use a thin wrapper that forwards to the borrowed store via clone
            // of FakeNativeStore / injected Arc at the caller.
            return import_from_store(vault, legacy);
        }
        None if keyring_available(keyring_probe)
            && keyring_core::get_default_store().is_some() =>
        {
            Box::new(KeyringNativeStore)
        }
        None => return Ok(()),
    };
    import_from_store(vault, store.as_ref())
}

fn import_from_store(
    vault: &SecretVault,
    store: &dyn NativeKeyStore,
) -> Result<(), SecureKeyError> {
    let installation = vault.installation_hex();
    let mut accounts = store.list_accounts(SECURE_KEY_SERVICE)?;
    if accounts.is_empty() {
        accounts.extend(known_legacy_accounts(installation)?);
    }
    for account in accounts {
        if !account.starts_with(installation) {
            continue;
        }
        if account.contains("/kek/") {
            continue;
        }
        let secret = match store.get_secret(SECURE_KEY_SERVICE, &account) {
            Ok(s) => s,
            Err(SecureKeyError::NotFound(_)) => continue,
            Err(e) => return Err(e),
        };
        let kind = classify_account(&account);
        vault.put_item(kind, &account, secret.as_slice())?;
        let read_back = vault.get_item(kind, &account)?;
        if read_back.as_slice() != secret.as_slice() {
            return Err(SecureKeyError::Corrupt(
                "legacy import verify mismatch".into(),
            ));
        }
        store.delete_secret(SECURE_KEY_SERVICE, &account)?;
    }
    Ok(())
}

fn known_legacy_accounts(installation: &str) -> Result<Vec<String>, SecureKeyError> {
    let mut out = Vec::new();
    for ns in [
        REDACTION_HISTORY_V1_NAMESPACE,
        crate::db::external_journal::EXTERNAL_JOURNAL_SPOOL_NAMESPACE,
        LEAK_REPORT_V1_NAMESPACE,
    ] {
        let namespace = Namespace::parse(ns)?;
        out.push(manifest_account(installation, &namespace)?);
        out.push(version_account(installation, &namespace, 1)?);
        out.push(sealed_state_account(
            installation,
            &namespace,
            SealedSlot::A,
        )?);
        out.push(sealed_state_account(
            installation,
            &namespace,
            SealedSlot::B,
        )?);
    }
    Ok(out)
}
