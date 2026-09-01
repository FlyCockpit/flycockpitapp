//! KEK placement adapters. The KEK never lives in SQLite.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use cockpit_proto::SecretStorePlacement;
use rand::Rng;
use zeroize::{Zeroize, Zeroizing};

use cockpit_host::private_fs::{
    PRIVATE_FS_POLICY, delete_private_file, ensure_private_dir, read_private_file,
    write_private_file, write_private_file_exclusive,
};

use super::error::SecureKeyError;
use super::key_material::{KEY_BYTE_LEN, SecureKeyBytes, TempSecret};
use super::native_store::{KeyringNativeStore, NativeKeyStore};

pub const KEK_SERVICE: &str = "dev.flycockpit.secret-vault";
pub const PASSPHRASE_KDF_MEMORY_KIB: u32 = 19_456;
pub const PASSPHRASE_KDF_ITERATIONS: u32 = 2;
pub const PASSPHRASE_KDF_PARALLELISM: u32 = 1;
pub const PASSPHRASE_KDF_SALT_LEN: usize = 16;
pub const PASSPHRASE_KDF_MAX_MEMORY_KIB: u32 = 65_536;
pub const PASSPHRASE_KDF_MAX_ITERATIONS: u32 = 10;
pub const PASSPHRASE_KDF_MAX_PARALLELISM: u32 = 4;
pub const PASSPHRASE_KDF_MAX_SALT_LEN: usize = 64;

/// Non-secret Argon2id metadata persisted beside a passphrase vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseKdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: Vec<u8>,
}

impl PassphraseKdfParams {
    pub fn owasp_default() -> Self {
        let mut salt = vec![0_u8; PASSPHRASE_KDF_SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        Self {
            memory_kib: PASSPHRASE_KDF_MEMORY_KIB,
            iterations: PASSPHRASE_KDF_ITERATIONS,
            parallelism: PASSPHRASE_KDF_PARALLELISM,
            salt,
        }
    }

    pub(crate) fn from_db(
        row: cockpit_db::secret_vault::SecretVaultPassphraseKdfRow,
    ) -> Result<Self, SecureKeyError> {
        let params = Self {
            memory_kib: row.memory_kib,
            iterations: row.iterations,
            parallelism: row.parallelism,
            salt: row.salt,
        };
        params.validate()?;
        Ok(params)
    }

    pub(crate) fn to_db(&self) -> cockpit_db::secret_vault::SecretVaultPassphraseKdfRow {
        cockpit_db::secret_vault::SecretVaultPassphraseKdfRow {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
            salt: self.salt.clone(),
        }
    }

    fn validate(&self) -> Result<(), SecureKeyError> {
        if !(8..=PASSPHRASE_KDF_MAX_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(SecureKeyError::Corrupt(format!(
                "passphrase KDF memory cost {} KiB is outside the supported range 8..={PASSPHRASE_KDF_MAX_MEMORY_KIB}",
                self.memory_kib
            )));
        }
        if !(1..=PASSPHRASE_KDF_MAX_ITERATIONS).contains(&self.iterations) {
            return Err(SecureKeyError::Corrupt(format!(
                "passphrase KDF iteration count {} is outside the supported range 1..={PASSPHRASE_KDF_MAX_ITERATIONS}",
                self.iterations
            )));
        }
        if !(1..=PASSPHRASE_KDF_MAX_PARALLELISM).contains(&self.parallelism) {
            return Err(SecureKeyError::Corrupt(format!(
                "passphrase KDF parallelism {} is outside the supported range 1..={PASSPHRASE_KDF_MAX_PARALLELISM}",
                self.parallelism
            )));
        }
        if !(PASSPHRASE_KDF_SALT_LEN..=PASSPHRASE_KDF_MAX_SALT_LEN).contains(&self.salt.len()) {
            return Err(SecureKeyError::Corrupt(format!(
                "passphrase KDF salt length {} is outside the supported range {PASSPHRASE_KDF_SALT_LEN}..={PASSPHRASE_KDF_MAX_SALT_LEN}",
                self.salt.len()
            )));
        }
        Ok(())
    }
}

/// Caller-owned passphrase bytes. This consumes the input allocation and
/// zeroizes it on every return path; callers should avoid creating a `String`
/// copy before handing bytes to this type.
pub struct Passphrase(Zeroizing<Vec<u8>>);

impl Passphrase {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SecureKeyError> {
        if bytes.is_empty() {
            let mut bytes = bytes;
            bytes.zeroize();
            return Err(SecureKeyError::Invalid(
                "passphrase vault requires a non-empty passphrase".into(),
            ));
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase([REDACTED])")
    }
}

/// Explicit Argon2 workspace. The KDF crate's `zeroize` feature clears its
/// transient stack buffers; this wrapper additionally clears all 19 MiB of
/// caller-owned memory before it is returned to the allocator.
struct Argon2WorkMemory(Vec<Block>);

impl Argon2WorkMemory {
    fn new(block_count: usize) -> Result<Self, SecureKeyError> {
        let mut blocks = Vec::new();
        blocks
            .try_reserve_exact(block_count)
            .map_err(|error| SecureKeyError::KekUnavailable {
                reason: format!("allocating passphrase KDF workspace: {error}"),
                fix_command: None,
            })?;
        for _ in 0..block_count {
            blocks.push(Block::default());
        }
        Ok(Self(blocks))
    }
}

impl AsMut<[Block]> for Argon2WorkMemory {
    fn as_mut(&mut self) -> &mut [Block] {
        self.0.as_mut_slice()
    }
}

impl Drop for Argon2WorkMemory {
    fn drop(&mut self) {
        for block in &mut self.0 {
            block.as_mut().fill(0);
        }
    }
}

/// Injected KEK store. Production uses a `private_fs` file or one keyring item.
pub trait KekStore: Send + Sync {
    fn placement(&self) -> SecretStorePlacement;

    /// The durable file-vault mode, if this is a file-backed placement.
    fn file_kek_mode(&self) -> Option<cockpit_db::secret_vault::SecretVaultFileKekMode> {
        None
    }

    /// Non-secret parameters that must be stored atomically with a newly
    /// initialized passphrase vault.
    fn passphrase_kdf_params(&self) -> Option<PassphraseKdfParams> {
        None
    }

    /// Material to wrap the first vault DEK with. The passphrase store returns
    /// its single Argon2id-derived KEK; all other stores generate a random KEK.
    fn initial_kek(&self) -> Result<SecureKeyBytes, SecureKeyError> {
        Ok(super::key_material::generate_key_bytes())
    }

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

    fn file_kek_mode(&self) -> Option<cockpit_db::secret_vault::SecretVaultFileKekMode> {
        Some(cockpit_db::secret_vault::SecretVaultFileKekMode::MachineBound)
    }

    fn write_kek(&self, version: i64, bytes: &[u8]) -> Result<(), SecureKeyError> {
        file_kek_supported()?;
        let path = kek_file_path(&self.dir, version);
        write_private_file(&path, bytes).map_err(|e| SecureKeyError::KekUnavailable {
            reason: format!("writing file KEK: {e}"),
            fix_command: None,
        })
    }

    fn write_kek_exclusive(&self, version: i64, bytes: &[u8]) -> Result<(), SecureKeyError> {
        file_kek_supported()?;
        let path = kek_file_path(&self.dir, version);
        write_private_file_exclusive(&path, bytes).map_err(|e| {
            if error_is_already_exists(&e) {
                SecureKeyError::Internal(
                    "KEK already exists; concurrent first-run lost the file race".into(),
                )
            } else {
                SecureKeyError::KekUnavailable {
                    reason: format!("writing file KEK exclusively: {e}"),
                    fix_command: None,
                }
            }
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

/// Database/file-vault KEK derived once from an in-memory passphrase. No KEK
/// bytes are written to disk: the database holds only wrapped vault keys and
/// the non-secret Argon2id parameters/salt.
pub struct PassphraseKekStore {
    kek: Mutex<Option<SecureKeyBytes>>,
    params: PassphraseKdfParams,
}

impl PassphraseKekStore {
    pub fn new_first_run(passphrase: Passphrase) -> Result<Self, SecureKeyError> {
        Self::from_passphrase(passphrase, PassphraseKdfParams::owasp_default())
    }

    pub fn open(
        passphrase: Passphrase,
        params: PassphraseKdfParams,
    ) -> Result<Self, SecureKeyError> {
        Self::from_passphrase(passphrase, params)
    }

    fn from_passphrase(
        passphrase: Passphrase,
        params: PassphraseKdfParams,
    ) -> Result<Self, SecureKeyError> {
        file_kek_supported()?;
        let kek = derive_passphrase_kek(passphrase, &params)?;
        Ok(Self {
            kek: Mutex::new(Some(kek)),
            params,
        })
    }

    fn ensure_matches(&self, bytes: &[u8]) -> Result<(), SecureKeyError> {
        if bytes != self.kek()?.as_ref() {
            return Err(SecureKeyError::Corrupt(
                "passphrase-derived KEK does not match vault initialization material".into(),
            ));
        }
        Ok(())
    }

    fn kek(&self) -> Result<SecureKeyBytes, SecureKeyError> {
        self.kek
            .lock()
            .map_err(|_| SecureKeyError::Internal("passphrase KEK lock poisoned".into()))?
            .as_ref()
            .cloned()
            .ok_or_else(|| SecureKeyError::NotFound("passphrase KEK has been retired".into()))
    }
}

fn derive_passphrase_kek(
    passphrase: Passphrase,
    params: &PassphraseKdfParams,
) -> Result<SecureKeyBytes, SecureKeyError> {
    params.validate()?;
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_BYTE_LEN),
    )
    .map_err(|error| {
        SecureKeyError::Invalid(format!("invalid passphrase KDF parameters: {error}"))
    })?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params.clone());
    let mut output = Zeroizing::new([0_u8; KEY_BYTE_LEN]);
    let mut memory = Argon2WorkMemory::new(argon_params.block_count())?;
    argon
        .hash_password_into_with_memory(
            passphrase.as_bytes(),
            &params.salt,
            output.as_mut(),
            &mut memory,
        )
        .map_err(|error| SecureKeyError::KekUnavailable {
            reason: format!("deriving passphrase vault KEK: {error}"),
            fix_command: None,
        })?;
    Ok(SecureKeyBytes::from_zeroizing_array(output))
}

impl fmt::Debug for PassphraseKekStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassphraseKekStore")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl KekStore for PassphraseKekStore {
    fn placement(&self) -> SecretStorePlacement {
        SecretStorePlacement::Database
    }

    fn file_kek_mode(&self) -> Option<cockpit_db::secret_vault::SecretVaultFileKekMode> {
        Some(cockpit_db::secret_vault::SecretVaultFileKekMode::Passphrase)
    }

    fn passphrase_kdf_params(&self) -> Option<PassphraseKdfParams> {
        Some(self.params.clone())
    }

    fn initial_kek(&self) -> Result<SecureKeyBytes, SecureKeyError> {
        self.kek()
    }

    fn write_kek(&self, _version: i64, bytes: &[u8]) -> Result<(), SecureKeyError> {
        self.ensure_matches(bytes)?;
        Ok(())
    }

    fn write_kek_exclusive(&self, _version: i64, bytes: &[u8]) -> Result<(), SecureKeyError> {
        self.ensure_matches(bytes)?;
        Ok(())
    }

    fn read_kek(&self, _version: i64) -> Result<TempSecret, SecureKeyError> {
        Ok(TempSecret::from_vec(self.kek()?.as_ref().to_vec()))
    }

    fn delete_kek(&self, _version: i64) -> Result<(), SecureKeyError> {
        let _ = self
            .kek
            .lock()
            .map_err(|_| SecureKeyError::Internal("passphrase KEK lock poisoned".into()))?
            .take();
        Ok(())
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

fn error_is_already_exists(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists)
            || cause.to_string().contains("lost the race")
    })
}

impl KekStore for MemoryKekStore {
    fn placement(&self) -> SecretStorePlacement {
        self.placement
    }

    fn file_kek_mode(&self) -> Option<cockpit_db::secret_vault::SecretVaultFileKekMode> {
        (self.placement == SecretStorePlacement::Database)
            .then_some(cockpit_db::secret_vault::SecretVaultFileKekMode::MachineBound)
    }

    fn write_kek(&self, version: i64, bytes: &[u8]) -> Result<(), SecureKeyError> {
        self.items
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(version, bytes.to_vec());
        Ok(())
    }

    fn write_kek_exclusive(&self, version: i64, bytes: &[u8]) -> Result<(), SecureKeyError> {
        let mut items = self.items.lock().unwrap_or_else(|p| p.into_inner());
        if items.contains_key(&version) {
            return Err(SecureKeyError::Internal(
                "KEK already exists; concurrent first-run lost the file race".into(),
            ));
        }
        items.insert(version, bytes.to_vec());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn memory_exclusive_create_rejects_second_writer() {
        let store = MemoryKekStore::new(SecretStorePlacement::Database);
        store.write_kek_exclusive(1, b"first").unwrap();
        let err = store.write_kek_exclusive(1, b"second").unwrap_err();
        assert!(
            matches!(err, SecureKeyError::Internal(ref m) if m.contains("already exists")),
            "{err:?}"
        );
        assert_eq!(store.read_kek(1).unwrap().as_slice(), b"first");
    }

    #[test]
    fn file_exclusive_create_rejects_second_writer() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileKekStore::new(tmp.path().to_path_buf()).unwrap();
        store.write_kek_exclusive(1, b"first-kek-bytes").unwrap();
        let err = store
            .write_kek_exclusive(1, b"second-kek-bytes")
            .unwrap_err();
        assert!(
            matches!(err, SecureKeyError::Internal(ref m) if m.contains("already exists")),
            "{err:?}"
        );
        assert_eq!(store.read_kek(1).unwrap().as_slice(), b"first-kek-bytes");
    }

    #[test]
    fn file_exclusive_create_only_one_concurrent_winner() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileKekStore::new(tmp.path().to_path_buf()).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let a = store.clone();
        let b = store.clone();
        let start_a = barrier.clone();
        let start_b = barrier;
        let left = std::thread::spawn(move || {
            start_a.wait();
            a.write_kek_exclusive(1, b"winner-a")
        });
        let right = std::thread::spawn(move || {
            start_b.wait();
            b.write_kek_exclusive(1, b"winner-b")
        });
        let results = [left.join().unwrap(), right.join().unwrap()];
        let wins = results.iter().filter(|r| r.is_ok()).count();
        let losses = results.iter().filter(|r| r.is_err()).count();
        assert_eq!(
            wins, 1,
            "exactly one exclusive create must succeed: {results:?}"
        );
        assert_eq!(losses, 1, "the loser must fail closed: {results:?}");
        let kept = store.read_kek(1).unwrap();
        assert!(
            kept.as_slice() == b"winner-a" || kept.as_slice() == b"winner-b",
            "kept {:?}",
            kept.as_slice()
        );
    }
}
