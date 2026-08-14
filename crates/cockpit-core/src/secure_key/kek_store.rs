//! KEK placement adapters. The KEK never lives in SQLite.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cockpit_proto::SecretStorePlacement;

use crate::private_fs::{
    PRIVATE_FS_POLICY, delete_private_file, ensure_private_dir, read_private_file,
    write_private_file,
};

use super::error::SecureKeyError;
use super::key_material::TempSecret;
use super::native_store::{KeyringNativeStore, NativeKeyStore};

pub const KEK_SERVICE: &str = "dev.flycockpit.secret-vault";

/// Injected KEK store. Production uses a `private_fs` file or one keyring item.
pub trait KekStore: Send + Sync {
    fn placement(&self) -> SecretStorePlacement;

    fn write_kek(&self, version: i64, bytes: &[u8]) -> Result<(), SecureKeyError>;

    /// First-run create: fail if a KEK already exists so two boots cannot
    /// overwrite the winning wrap key.
    fn write_kek_exclusive(&self, version: i64, bytes: &[u8]) -> Result<(), SecureKeyError> {
        if self.kek_present(version)? {
            return Err(SecureKeyError::Internal(
                "KEK already exists; concurrent first-run lost the file race".into(),
            ));
        }
        self.write_kek(version, bytes)
    }

    fn read_kek(&self, version: i64) -> Result<TempSecret, SecureKeyError>;

    /// Missing item is success.
    fn delete_kek(&self, version: i64) -> Result<(), SecureKeyError>;

    fn kek_present(&self, version: i64) -> Result<bool, SecureKeyError> {
        match self.read_kek(version) {
            Ok(_) => Ok(true),
            Err(SecureKeyError::NotFound(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Residue paths a successful migrate must not leave behind (file stores).
    fn residue_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }
}

impl fmt::Debug for dyn KekStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KekStore")
            .field("placement", &self.placement())
            .finish()
    }
}

pub fn file_kek_supported() -> Result<(), SecureKeyError> {
    if cfg!(windows) && !PRIVATE_FS_POLICY.windows_dacl_enforced {
        return Err(SecureKeyError::KekUnavailable {
            reason: "Windows file KEK requires an owner-only DACL (PRIVATE_FS_POLICY.windows_dacl_enforced)"
                .into(),
            fix_command: Some(
                "Upgrade to a build that enforces the Windows owner-only KEK DACL.".into(),
            ),
        });
    }
    if !cfg!(unix) && !cfg!(windows) {
        return Err(SecureKeyError::KekUnavailable {
            reason: "file KEK is unsupported on this platform".into(),
            fix_command: None,
        });
    }
    Ok(())
}

pub fn kek_file_path(dir: &Path, version: i64) -> PathBuf {
    dir.join(format!("kek.v{version}"))
}

pub fn keyring_kek_account(installation_hex: &str, version: i64) -> String {
    format!("{installation_hex}/kek/v{version}")
}

/// Owner-only file KEK under `dir`.
pub struct FileKekStore {
    dir: PathBuf,
}

impl FileKekStore {
    pub fn new(dir: PathBuf) -> Result<Self, SecureKeyError> {
        file_kek_supported()?;
        ensure_private_dir(&dir).map_err(|e| SecureKeyError::KekUnavailable {
            reason: format!("cannot create private KEK directory: {e}"),
            fix_command: None,
        })?;
        Ok(Self { dir })
    }
}

impl fmt::Debug for FileKekStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileKekStore")
            .field("dir", &self.dir)
            .finish()
    }
}

impl KekStore for FileKekStore {
    fn placement(&self) -> SecretStorePlacement {
        SecretStorePlacement::Database
    }

    fn write_kek(&self, version: i64, bytes: &[u8]) -> Result<(), SecureKeyError> {
        file_kek_supported()?;
        let path = kek_file_path(&self.dir, version);
        write_private_file(&path, bytes).map_err(|e| SecureKeyError::KekUnavailable {
            reason: format!("writing file KEK: {e}"),
            fix_command: None,
        })
    }

    fn read_kek(&self, version: i64) -> Result<TempSecret, SecureKeyError> {
        let path = kek_file_path(&self.dir, version);
        match read_private_file(&path, "kek") {
            Ok(Some(bytes)) => Ok(TempSecret::from_vec(bytes)),
            Ok(None) => Err(SecureKeyError::NotFound("file KEK missing".into())),
            Err(e) => Err(SecureKeyError::KekUnavailable {
                reason: format!("reading file KEK: {e}"),
                fix_command: None,
            }),
        }
    }

    fn delete_kek(&self, version: i64) -> Result<(), SecureKeyError> {
        let path = kek_file_path(&self.dir, version);
        delete_private_file(&path)
            .map_err(|e| SecureKeyError::Internal(format!("deleting file KEK: {e}")))?;
        // Also drop leftover crash-atomic temps in this directory.
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with(".tmp-") {
                    let _ = delete_private_file(&entry.path());
                }
            }
        }
        Ok(())
    }

    fn residue_paths(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("kek.") || name.starts_with(".tmp-") {
                    out.push(entry.path());
                }
            }
        }
        out
    }
}

/// One keyring item per KEK version. Uses the already-registered default store.
pub struct KeyringKekStore {
    native: KeyringNativeStore,
    installation_hex: String,
}

impl KeyringKekStore {
    pub fn new(installation_hex: impl Into<String>) -> Self {
        Self {
            native: KeyringNativeStore,
            installation_hex: installation_hex.into(),
        }
    }
}

impl fmt::Debug for KeyringKekStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyringKekStore")
            .field("installation", &self.installation_hex)
            .finish()
    }
}

impl KekStore for KeyringKekStore {
    fn placement(&self) -> SecretStorePlacement {
        SecretStorePlacement::Keyring
    }

    fn write_kek(&self, version: i64, bytes: &[u8]) -> Result<(), SecureKeyError> {
        self.native.set_secret(
            KEK_SERVICE,
            &keyring_kek_account(&self.installation_hex, version),
            bytes,
        )
    }

    fn read_kek(&self, version: i64) -> Result<TempSecret, SecureKeyError> {
        self.native.get_secret(
            KEK_SERVICE,
            &keyring_kek_account(&self.installation_hex, version),
        )
    }

    fn delete_kek(&self, version: i64) -> Result<(), SecureKeyError> {
        self.native.delete_secret(
            KEK_SERVICE,
            &keyring_kek_account(&self.installation_hex, version),
        )
    }
}

/// In-memory KEK store for tests. Never opens a real OS keyring.
#[derive(Clone)]
pub struct MemoryKekStore {
    placement: SecretStorePlacement,
    items: Arc<Mutex<std::collections::BTreeMap<i64, Vec<u8>>>>,
}

impl MemoryKekStore {
    pub fn new(placement: SecretStorePlacement) -> Self {
        Self {
            placement,
            items: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        }
    }

    pub fn len(&self) -> usize {
        self.items.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

impl fmt::Debug for MemoryKekStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryKekStore")
            .field("placement", &self.placement)
            .field("count", &self.len())
            .finish()
    }
}

impl KekStore for MemoryKekStore {
    fn placement(&self) -> SecretStorePlacement {
        self.placement
    }

    fn write_kek(&self, version: i64, bytes: &[u8]) -> Result<(), SecureKeyError> {
        self.items
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(version, bytes.to_vec());
        Ok(())
    }

    fn read_kek(&self, version: i64) -> Result<TempSecret, SecureKeyError> {
        let g = self.items.lock().unwrap_or_else(|p| p.into_inner());
        let bytes = g
            .get(&version)
            .cloned()
            .ok_or_else(|| SecureKeyError::NotFound("memory KEK missing".into()))?;
        Ok(TempSecret::from_vec(bytes))
    }

    fn delete_kek(&self, version: i64) -> Result<(), SecureKeyError> {
        self.items
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&version);
        Ok(())
    }
}
