//! Installation-scoped KEK placement. Authority is the SQLite singleton.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cockpit_db::installation_identity::{InstallationIdentity, ensure_installation_identity_conn};
use cockpit_db::secret_vault::{
    SecretVaultAuthorityRow, SecretVaultFileKekMode, SecretVaultPlacement, list_open_sagas_conn,
    load_authority_conn, load_passphrase_kdf_conn,
};
use cockpit_proto::{SecretStoreIntent, SecretStorePlacement, SecretStoreSnapshot};

use crate::db::Db;

use super::error::SecureKeyError;
use super::kek_store::{
    FileKekStore, KekStore, KeyringKekStore, Passphrase, PassphraseKdfParams, PassphraseKekStore,
    file_kek_supported,
};
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
pub const MACHINE_BOUND_FILE_VAULT_WARNING: &str =
    "The machine-bound file vault is weaker than the OS keychain against a local-root attacker.";

/// First-run placement chosen by onboarding. `Automatic` preserves the
/// established keyring-when-available behavior; the file choices deliberately
/// override it and are persisted in the vault authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FirstRunSecretStoreIntent {
    #[default]
    Automatic,
    Keyring,
    FileMachineBound,
    FilePassphrase,
}

impl FirstRunSecretStoreIntent {
    fn placement(self) -> Option<SecretVaultPlacement> {
        match self {
            Self::Automatic => None,
            Self::Keyring => Some(SecretVaultPlacement::Keyring),
            Self::FileMachineBound | Self::FilePassphrase => Some(SecretVaultPlacement::Database),
        }
    }

    fn file_kek_mode(self) -> Option<SecretVaultFileKekMode> {
        match self {
            Self::FileMachineBound => Some(SecretVaultFileKekMode::MachineBound),
            Self::FilePassphrase => Some(SecretVaultFileKekMode::Passphrase),
            Self::Automatic | Self::Keyring => None,
        }
    }
}

/// Input supplied by onboarding when bootstrapping or reopening a vault. A
/// passphrase is consumed to derive the KEK once, then zeroized.
#[derive(Default)]
pub struct SecretVaultOpenOptions {
    pub first_run_intent: FirstRunSecretStoreIntent,
    pub passphrase: Option<Passphrase>,
}

/// Read-only status for onboarding. It deliberately reuses the platform probe
/// fields (including remedy text) rather than duplicating platform policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstRunSecretStoreCapabilities {
    pub keyring: KeyringProbeResult,
    pub file_vault_available: bool,
    pub file_vault_reason: Option<String>,
    pub file_vault_fix_command: Option<String>,
    pub machine_bound_warning: &'static str,
}

pub fn first_run_secret_store_capabilities(
    keyring: &KeyringProbeResult,
) -> FirstRunSecretStoreCapabilities {
    match file_kek_supported() {
        Ok(()) => FirstRunSecretStoreCapabilities {
            keyring: keyring.clone(),
            file_vault_available: true,
            file_vault_reason: None,
            file_vault_fix_command: None,
            machine_bound_warning: MACHINE_BOUND_FILE_VAULT_WARNING,
        },
        Err(SecureKeyError::KekUnavailable {
            reason,
            fix_command,
        }) => FirstRunSecretStoreCapabilities {
            keyring: keyring.clone(),
            file_vault_available: false,
            file_vault_reason: Some(reason),
            file_vault_fix_command: fix_command,
            machine_bound_warning: MACHINE_BOUND_FILE_VAULT_WARNING,
        },
        Err(error) => FirstRunSecretStoreCapabilities {
            keyring: keyring.clone(),
            file_vault_available: false,
            file_vault_reason: Some(error.to_string()),
            file_vault_fix_command: None,
            machine_bound_warning: MACHINE_BOUND_FILE_VAULT_WARNING,
        },
    }
}

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

fn keyring_probe_failed(probe: &KeyringProbeResult) -> bool {
    matches!(probe.state, cockpit_proto::FeatureCapabilityState::Failed)
}

/// Durable KEK migrate used by Settings and the daemon request.
///
/// Opens the current vault from the authority row, writes the destination
/// KEK, verifies unwrap, activates `secret_vault_authority`, and purges the
/// source. Does not write a layered `secretStore` config key.
pub fn secret_store_dest_placement(
    dest: SecretStorePlacement,
) -> Result<SecretVaultPlacement, SecureKeyError> {
    match dest {
        SecretStorePlacement::Database => Ok(SecretVaultPlacement::Database),
        SecretStorePlacement::Keyring => Ok(SecretVaultPlacement::Keyring),
        SecretStorePlacement::Unavailable => Err(SecureKeyError::Internal(
            "cannot migrate the wrap-key vault to an unavailable placement".into(),
        )),
    }
}

pub fn migrate_installation_kek(
    db: &Db,
    dest: SecretStorePlacement,
    probe: &KeyringProbeResult,
    injected: SecretStoreInjected,
) -> Result<SecretStoreSnapshot, SecureKeyError> {
    let dest = secret_store_dest_placement(dest)?;
    let kek_dir = kek_dir_for_db(db)?;
    let current = ensure_secret_vault(
        db,
        probe,
        &kek_dir,
        SecretStoreInjected {
            file_kek: injected.file_kek.clone(),
            keyring_kek: injected.keyring_kek.clone(),
            legacy_keyring: None,
        },
    )
    .map_err(SecureKeyError::from)?;
    let installation = crate::db::installation_identity::InstallationIdentity::from_hex_checked(
        current.vault.installation_hex(),
    )
    .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    let dest_store = kek_store_for_placement(dest, &kek_dir, &installation, &injected, false)
        .map_err(SecureKeyError::from)?;
    let _ = super::migrate::migrate_kek_placement(
        &current.vault,
        dest_store,
        dest,
        probe,
        &super::migrate::VaultFault::default(),
    )?;
    let authority = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    Ok(project_secret_store_snapshot(authority.as_ref(), probe))
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

/// Pure placement decision. First-run (no row) is keyring when the probe is
/// available, otherwise database.
pub fn resolve_secret_store(
    authority: Option<&SecretVaultAuthorityRow>,
    keyring_probe: &KeyringProbeResult,
) -> Result<SecretVaultPlacement, KekUnavailable> {
    resolve_secret_store_with_intent(
        authority,
        keyring_probe,
        FirstRunSecretStoreIntent::Automatic,
    )
}

/// Pure placement decision with the persisted first-run choice. A file intent
/// may select the file vault even while the keyring probe is available.
pub fn resolve_secret_store_with_intent(
    authority: Option<&SecretVaultAuthorityRow>,
    keyring_probe: &KeyringProbeResult,
    first_run_intent: FirstRunSecretStoreIntent,
) -> Result<SecretVaultPlacement, KekUnavailable> {
    match authority {
        None if first_run_intent == FirstRunSecretStoreIntent::Keyring
            && !keyring_available(keyring_probe) =>
        {
            Err(KekUnavailable {
                reason: keyring_probe.reason.clone(),
                fix_command: keyring_probe
                    .fix_command
                    .clone()
                    .or_else(|| Some(DEFAULT_FIX_COMMAND.to_string())),
                intent: SecretStoreIntent::Keyring,
            })
        }
        None if let Some(placement) = first_run_intent.placement() => Ok(placement),
        None if keyring_available(keyring_probe) => Ok(SecretVaultPlacement::Keyring),
        None if keyring_probe_failed(keyring_probe) => Err(KekUnavailable {
            reason: keyring_probe.reason.clone(),
            fix_command: keyring_probe
                .fix_command
                .clone()
                .or_else(|| Some(DEFAULT_FIX_COMMAND.to_string())),
            intent: SecretStoreIntent::Unconfigured,
        }),
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
    ensure_secret_vault_with_options(
        db,
        keyring_probe,
        kek_dir,
        injected,
        SecretVaultOpenOptions::default(),
    )
}

/// Open or initialize the vault using a first-run placement and optional
/// passphrase. The derived passphrase KEK is retained only by the returned
/// vault/store for the daemon lifetime.
pub fn ensure_secret_vault_with_options(
    db: &Db,
    keyring_probe: &KeyringProbeResult,
    kek_dir: &Path,
    injected: SecretStoreInjected,
    mut options: SecretVaultOpenOptions,
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

    let mut authority = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .map_err(|e| KekUnavailable {
            reason: format!("reading secret vault authority: {e}"),
            fix_command: None,
            intent: SecretStoreIntent::Unconfigured,
        })?;

    if authority.is_none()
        && options.passphrase.is_some()
        && options.first_run_intent != FirstRunSecretStoreIntent::FilePassphrase
    {
        return Err(KekUnavailable {
            reason: "a passphrase may be supplied only with the FilePassphrase first-run intent"
                .into(),
            fix_command: None,
            intent: SecretStoreIntent::Unconfigured,
        });
    }
    if authority.is_none()
        && options.first_run_intent == FirstRunSecretStoreIntent::FilePassphrase
        && options.passphrase.is_none()
    {
        return Err(KekUnavailable {
            reason: "first-run passphrase vault initialization requires a passphrase".into(),
            fix_command: None,
            intent: SecretStoreIntent::Database,
        });
    }

    if let Some(auth) = authority.as_ref() {
        resume_open_kek_migrate(
            db,
            kek_dir,
            &installation,
            &injected,
            keyring_probe,
            auth,
            &mut options.passphrase,
        )?;
        // Resume may activate a new placement and delete the source KEK.
        // Re-read before resolve/open so we do not open the deleted store.
        authority = db
            .blocking_write_for_sync_maintenance(load_authority_conn)
            .map_err(|e| KekUnavailable {
                reason: format!("reloading secret vault authority after resume: {e}"),
                fix_command: None,
                intent: SecretStoreIntent::Unconfigured,
            })?;
    }

    if authority
        .as_ref()
        .is_some_and(|row| row.file_kek_mode != Some(SecretVaultFileKekMode::Passphrase))
        && options.passphrase.is_some()
    {
        return Err(KekUnavailable {
            reason: "a passphrase was supplied for a vault that is not passphrase-backed".into(),
            fix_command: None,
            intent: SecretStoreIntent::Unconfigured,
        });
    }

    let first_run = authority.is_none();
    let placement = resolve_secret_store_with_intent(
        authority.as_ref(),
        keyring_probe,
        options.first_run_intent,
    )?;

    let file_kek_mode = authority
        .as_ref()
        .and_then(|row| row.file_kek_mode)
        .or_else(|| options.first_run_intent.file_kek_mode())
        .or_else(|| {
            (placement == SecretVaultPlacement::Database)
                .then_some(SecretVaultFileKekMode::MachineBound)
        });
    let kek_store = kek_store_for_vault(
        db,
        placement,
        file_kek_mode,
        kek_dir,
        &installation,
        &injected,
        first_run,
        &mut options.passphrase,
    )?;

    let vault = if first_run {
        match SecretVault::initialize(
            db.clone(),
            kek_store.clone(),
            installation.clone(),
            1,
            1,
            placement,
        ) {
            Ok(vault) => vault,
            Err(error) if error.to_string().contains("already") => {
                SecretVault::open(db.clone(), kek_store, installation).map_err(|e| {
                    KekUnavailable {
                        reason: e.to_string(),
                        fix_command: None,
                        intent: placement_intent(placement),
                    }
                })?
            }
            Err(error) => {
                return Err(KekUnavailable {
                    reason: error.to_string(),
                    fix_command: None,
                    intent: placement_intent(placement),
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
            intent: placement_intent(placement),
        })?;
    }

    let authority = db
        .blocking_write_for_sync_maintenance(load_authority_conn)
        .map_err(|e| KekUnavailable {
            reason: format!("reading secret vault authority: {e}"),
            fix_command: None,
            intent: placement_intent(placement),
        })?;
    let snapshot = project_secret_store_snapshot(authority.as_ref(), keyring_probe);
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
    passphrase: &mut Option<Passphrase>,
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
    let dest = kek_store_for_vault(
        db,
        saga.dest_placement,
        saga.dest_file_kek_mode,
        kek_dir,
        installation,
        injected,
        false,
        passphrase,
    )?;
    // Before activation the source is still authoritative and must be opened
    // to recover the KEK. After activation, a passphrase source has no
    // durable KEK to retire: its `delete_kek` only clears a process-local
    // derived value, which cannot survive the crash being recovered from.
    // Other source stores still need opening in Activated to delete their
    // durable KEK. SourceDeleted and Complete never need the retired store.
    let source = match saga.phase {
        cockpit_db::secret_vault::SecretVaultSagaPhase::Prepared => Some(kek_store_for_vault(
            db,
            saga.source_placement,
            saga.source_file_kek_mode,
            kek_dir,
            installation,
            injected,
            false,
            passphrase,
        )?),
        cockpit_db::secret_vault::SecretVaultSagaPhase::Activated
            if !passphrase_source_is_already_retired(&saga) =>
        {
            Some(kek_store_for_vault(
                db,
                saga.source_placement,
                saga.source_file_kek_mode,
                kek_dir,
                installation,
                injected,
                false,
                passphrase,
            )?)
        }
        cockpit_db::secret_vault::SecretVaultSagaPhase::Activated
        | cockpit_db::secret_vault::SecretVaultSagaPhase::SourceDeleted
        | cockpit_db::secret_vault::SecretVaultSagaPhase::Complete => None,
    };
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

fn passphrase_source_is_already_retired(
    saga: &cockpit_db::secret_vault::SecretVaultSagaRow,
) -> bool {
    saga.source_placement == SecretVaultPlacement::Database
        && saga.source_file_kek_mode == Some(SecretVaultFileKekMode::Passphrase)
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

fn kek_store_for_vault(
    db: &Db,
    placement: SecretVaultPlacement,
    file_kek_mode: Option<SecretVaultFileKekMode>,
    kek_dir: &Path,
    installation: &InstallationIdentity,
    injected: &SecretStoreInjected,
    first_run: bool,
    passphrase: &mut Option<Passphrase>,
) -> Result<Arc<dyn KekStore>, KekUnavailable> {
    match (placement, file_kek_mode) {
        (SecretVaultPlacement::Database, Some(SecretVaultFileKekMode::Passphrase)) => {
            let passphrase = passphrase.take().ok_or_else(|| KekUnavailable {
                reason: "this passphrase vault requires the passphrase after every daemon restart"
                    .into(),
                fix_command: None,
                intent: SecretStoreIntent::Database,
            })?;
            let store = if first_run {
                PassphraseKekStore::new_first_run(passphrase)
            } else {
                let row = db
                    .blocking_write_for_sync_maintenance(load_passphrase_kdf_conn)
                    .map_err(|error| KekUnavailable {
                        reason: format!("loading passphrase vault KDF parameters: {error}"),
                        fix_command: None,
                        intent: SecretStoreIntent::Database,
                    })?
                    .ok_or_else(|| KekUnavailable {
                        reason: "passphrase vault KDF parameters are missing".into(),
                        fix_command: None,
                        intent: SecretStoreIntent::Database,
                    })?;
                let params = PassphraseKdfParams::from_db(row).map_err(|error| KekUnavailable {
                    reason: error.to_string(),
                    fix_command: None,
                    intent: SecretStoreIntent::Database,
                })?;
                PassphraseKekStore::open(passphrase, params)
            };
            store
                .map(|store| Arc::new(store) as Arc<dyn KekStore>)
                .map_err(|error| KekUnavailable {
                    reason: error.to_string(),
                    fix_command: None,
                    intent: SecretStoreIntent::Database,
                })
        }
        (SecretVaultPlacement::Database, None) => Err(KekUnavailable {
            reason: "database vault authority is missing its durable file KEK mode".into(),
            fix_command: None,
            intent: SecretStoreIntent::Database,
        }),
        (SecretVaultPlacement::Database, _) => {
            kek_store_for_placement(placement, kek_dir, installation, injected, first_run)
        }
        (SecretVaultPlacement::Keyring, _) => {
            kek_store_for_placement(placement, kek_dir, installation, injected, first_run)
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
        None if keyring_available(keyring_probe) && keyring_core::get_default_store().is_some() => {
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

/// Open or initialize the wrap-key vault for this database.
///
/// File-backed DBs use the installation KEK directory. In-memory DBs use a
/// process-local `MemoryKekStore` keyed by installation identity so tests can
/// persist vault items without a path.
pub fn open_for_db(db: &Db) -> Result<Arc<SecretVault>, SecureKeyError> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    use cockpit_db::installation_identity::ensure_installation_identity_conn;
    use cockpit_proto::SecretStorePlacement;

    use super::kek_store::MemoryKekStore;

    if db.path().is_some() {
        let kek_dir = kek_dir_for_db(db)?;
        let probe = if cfg!(test) || std::env::var_os("COCKPIT_TEST_NO_KEYRING").is_some() {
            super::platform::KeyringProbeResult {
                state: cockpit_proto::FeatureCapabilityState::Missing,
                reason: "tests must not use the host OS keyring".into(),
                fix_command: None,
                remedy_text: None,
            }
        } else {
            super::platform::probe_platform_keyring()
        };
        return Ok(
            ensure_secret_vault(db, &probe, &kek_dir, SecretStoreInjected::default())?.vault,
        );
    }

    static MEMORY_KEKS: OnceLock<Mutex<HashMap<String, Arc<MemoryKekStore>>>> = OnceLock::new();
    let installation = db
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .map_err(|e| SecureKeyError::Internal(e.to_string()))?;
    let hex = installation.as_hex().to_string();
    let kek = {
        let map = MEMORY_KEKS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut guard = map.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .entry(hex)
            .or_insert_with(|| Arc::new(MemoryKekStore::new(SecretStorePlacement::Database)))
            .clone()
    };
    match SecretVault::open(db.clone(), kek.clone(), installation.clone()) {
        Ok(vault) => Ok(Arc::new(vault)),
        Err(_) => {
            let vault = SecretVault::initialize(
                db.clone(),
                kek,
                installation,
                1,
                1,
                SecretVaultPlacement::Database,
            )?;
            Ok(Arc::new(vault))
        }
    }
}

pub fn vault_for_db(db: &Db) -> Result<Arc<SecretVault>, SecureKeyError> {
    open_for_db(db)
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

#[cfg(feature = "test-support")]
pub fn test_open_db(path: &std::path::Path) -> Db {
    Db::open(path).expect("test db")
}

#[cfg(feature = "test-support")]
pub fn test_available_keyring_probe() -> KeyringProbeResult {
    KeyringProbeResult {
        state: cockpit_proto::FeatureCapabilityState::Available,
        reason: "platform keyring can hold a wrapping key".into(),
        fix_command: None,
        remedy_text: None,
    }
}

#[cfg(feature = "test-support")]
pub fn test_missing_keyring_probe() -> KeyringProbeResult {
    KeyringProbeResult {
        state: cockpit_proto::FeatureCapabilityState::Missing,
        reason: "secret service unavailable".into(),
        fix_command: Some("install gnome-keyring".into()),
        remedy_text: None,
    }
}

#[cfg(feature = "test-support")]
pub struct TestInjectedVault {
    db: Db,
    pub file_kek: std::sync::Arc<super::kek_store::MemoryKekStore>,
    pub keyring_kek: std::sync::Arc<super::kek_store::MemoryKekStore>,
    kek_dir: std::path::PathBuf,
}

#[cfg(feature = "test-support")]
impl TestInjectedVault {
    pub fn first_run_database(tmp: &std::path::Path) -> Self {
        use super::kek_store::MemoryKekStore;
        let db = test_open_db(&tmp.join("cockpit.db"));
        let file_kek = std::sync::Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
        let keyring_kek = std::sync::Arc::new(MemoryKekStore::new(SecretStorePlacement::Keyring));
        let kek_dir = tmp.join("secret-vault");
        let _ = ensure_secret_vault(
            &db,
            &test_missing_keyring_probe(),
            &kek_dir,
            SecretStoreInjected {
                file_kek: Some(file_kek.clone()),
                keyring_kek: Some(keyring_kek.clone()),
                legacy_keyring: None,
            },
        )
        .expect("first-run database vault");
        Self {
            db,
            file_kek,
            keyring_kek,
            kek_dir,
        }
    }

    pub fn promote_to_keyring(&self) {
        let current = ensure_secret_vault(
            &self.db,
            &test_available_keyring_probe(),
            &self.kek_dir,
            self.injected(),
        )
        .expect("open vault for promote");
        let _ = super::migrate::migrate_kek_placement(
            &current.vault,
            self.keyring_kek.clone(),
            SecretVaultPlacement::Keyring,
            &test_available_keyring_probe(),
            &super::migrate::VaultFault::default(),
        )
        .expect("promote to keyring");
    }

    pub fn injected(&self) -> SecretStoreInjected {
        SecretStoreInjected {
            file_kek: Some(self.file_kek.clone()),
            keyring_kek: Some(self.keyring_kek.clone()),
            legacy_keyring: None,
        }
    }

    pub fn migrate(
        &self,
        dest: SecretStorePlacement,
    ) -> Result<SecretStoreSnapshot, SecureKeyError> {
        migrate_installation_kek(
            &self.db,
            dest,
            &test_available_keyring_probe(),
            self.injected(),
        )
    }
}
