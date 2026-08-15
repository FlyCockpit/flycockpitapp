//! Wrap-key vault: ChaCha20-Poly1305 wrap + item AEAD keyed by an unwrapped DEK.

use std::fmt;
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use cockpit_db::secret_vault::{
    SecretVaultKind, VAULT_ALGORITHM, VAULT_NONCE_LEN, VAULT_TAG_LEN, VAULT_WRAP_VERSION,
    VAULT_WRAPPED_DEK_LEN, count_active_keys_conn, deactivate_key_conn, delete_item_conn,
    insert_key_conn, is_unique_constraint, list_item_ids_conn, load_active_key_conn,
    load_authority_conn, load_item_conn, upsert_item_conn,
};
use rand::Rng;
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::db::Db;
use crate::db::installation_identity::InstallationIdentity;

use super::error::SecureKeyError;
use super::kek_store::KekStore;
use super::key_material::{KEY_BYTE_LEN, SecureKeyBytes, TempSecret, generate_key_bytes};

const UNIT: u8 = 0x1f;
const NONCE_RETRY_LIMIT: usize = 8;

#[derive(Clone)]
pub struct SecretVault {
    db: Db,
    kek_store: Arc<dyn KekStore>,
    installation: InstallationIdentity,
    kek: SecureKeyBytes,
    dek: SecureKeyBytes,
    kek_version: i64,
    key_version: i64,
}

impl fmt::Debug for SecretVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretVault")
            .field("installation", &self.installation.as_hex())
            .field("kek_version", &self.kek_version)
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl SecretVault {
    pub fn kek_store(&self) -> &Arc<dyn KekStore> {
        &self.kek_store
    }

    pub fn installation_hex(&self) -> &str {
        self.installation.as_hex()
    }

    pub fn kek_version(&self) -> i64 {
        self.kek_version
    }

    pub fn key_version(&self) -> i64 {
        self.key_version
    }

    pub fn kek_fingerprint(&self) -> String {
        fingerprint_key(&self.kek)
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Open an existing vault: exactly one active DEK, unwrap with the KEK.
    pub fn open(
        db: Db,
        kek_store: Arc<dyn KekStore>,
        installation: InstallationIdentity,
    ) -> Result<Self, SecureKeyError> {
        Self::open_from_parts(db, kek_store, installation)
    }

    /// First-run: write file/memory KEK, persist authority + wrapped DEK.
    pub fn initialize(
        db: Db,
        kek_store: Arc<dyn KekStore>,
        installation: InstallationIdentity,
        kek_version: i64,
        key_version: i64,
    ) -> Result<Self, SecureKeyError> {
        let kek = generate_key_bytes();
        kek_store.write_kek_exclusive(kek_version, kek.as_ref())?;
        let dek = generate_key_bytes();
        let wrap_nonce = random_nonce();
        let wrap_aad = wrap_aad(
            kek_version,
            VAULT_WRAP_VERSION,
            key_version,
            installation.as_hex(),
        );
        let wrapped = aead_encrypt(kek.as_array(), &wrap_nonce, &wrap_aad, dek.as_ref())?;
        if wrapped.len() != VAULT_WRAPPED_DEK_LEN {
            return Err(SecureKeyError::Corrupt(format!(
                "wrapped DEK length {} != {VAULT_WRAPPED_DEK_LEN}",
                wrapped.len()
            )));
        }
        let fingerprint = fingerprint_key(&kek);
        db.blocking_write_for_sync_maintenance({
            let fingerprint = fingerprint.clone();
            move |conn| {
                conn.execute_batch("BEGIN IMMEDIATE;")?;
                let result = (|| {
                    if count_active_keys_conn(conn)? != 0 {
                        anyhow::bail!("vault already has an active DEK");
                    }
                    if load_authority_conn(conn)?.is_some() {
                        anyhow::bail!("secret vault authority already exists");
                    }
                    cockpit_db::secret_vault::upsert_authority_conn(
                        conn,
                        cockpit_db::secret_vault::SecretVaultPlacement::Database,
                        cockpit_db::secret_vault::SecretVaultPlacement::Database,
                        &fingerprint,
                        kek_version,
                        VAULT_WRAP_VERSION,
                        false,
                    )?;
                    insert_key_conn(conn, key_version, kek_version, &wrap_nonce, &wrapped, true)?;
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
        .map_err(map_db_err)?;
        Ok(Self {
            db,
            kek_store,
            installation,
            kek,
            dek,
            kek_version,
            key_version,
        })
    }

    pub fn put_item(
        &self,
        kind: SecretVaultKind,
        item_id: &str,
        plaintext: &[u8],
    ) -> Result<(), SecureKeyError> {
        self.put_item_with_nonce(kind, item_id, plaintext, None)
    }

    /// Encrypt and upsert on an already-open connection so callers can compose
    /// vault writes with sealed-scope / journal rows in one SQLite transaction.
    pub fn put_item_on_conn(
        &self,
        conn: &rusqlite::Connection,
        kind: SecretVaultKind,
        item_id: &str,
        plaintext: &[u8],
    ) -> Result<(), SecureKeyError> {
        self.put_item_on_conn_with_nonce(conn, kind, item_id, plaintext, None)
    }

    pub fn put_item_on_conn_with_nonce(
        &self,
        conn: &rusqlite::Connection,
        kind: SecretVaultKind,
        item_id: &str,
        plaintext: &[u8],
        forced_nonce: Option<[u8; VAULT_NONCE_LEN]>,
    ) -> Result<(), SecureKeyError> {
        let aad = item_aad(
            kind,
            item_id,
            self.key_version,
            self.kek_version,
            self.installation.as_hex(),
        );
        for attempt in 0..NONCE_RETRY_LIMIT {
            let nonce = match forced_nonce {
                Some(n) if attempt == 0 => n,
                Some(_) => {
                    return Err(SecureKeyError::Corrupt("vault item nonce reuse".into()));
                }
                None => random_nonce(),
            };
            let ciphertext = aead_encrypt(self.dek.as_array(), &nonce, &aad, plaintext)?;
            let nonce_taken: bool = conn
                .query_row(
                    "SELECT 1 FROM secret_vault_items
                     WHERE key_version = ?1 AND nonce = ?2",
                    rusqlite::params![self.key_version, nonce.as_slice()],
                    |_| Ok(true),
                )
                .optional()
                .map_err(|e| SecureKeyError::Internal(e.to_string()))?
                .unwrap_or(false);
            if nonce_taken {
                continue;
            }
            match upsert_item_conn(conn, kind, item_id, self.key_version, &nonce, &ciphertext) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    if error
                        .downcast_ref::<rusqlite::Error>()
                        .is_some_and(is_unique_constraint)
                        || error.to_string().contains("UNIQUE")
                    {
                        continue;
                    }
                    return Err(map_db_err(error));
                }
            }
        }
        Err(SecureKeyError::Corrupt("vault item nonce reuse".into()))
    }

    pub fn get_item_on_conn(
        &self,
        conn: &rusqlite::Connection,
        kind: SecretVaultKind,
        item_id: &str,
    ) -> Result<TempSecret, SecureKeyError> {
        let row = load_item_conn(conn, kind, item_id)
            .map_err(map_db_err)?
            .ok_or_else(|| SecureKeyError::NotFound(format!("vault item {item_id}")))?;
        let aad = item_aad(
            kind,
            item_id,
            row.key_version,
            self.kek_version,
            self.installation.as_hex(),
        );
        decrypt_item(&self.dek, &row.nonce, &row.ciphertext, &aad)
    }

    pub fn delete_item_on_conn(
        &self,
        conn: &rusqlite::Connection,
        kind: SecretVaultKind,
        item_id: &str,
    ) -> Result<(), SecureKeyError> {
        delete_item_conn(conn, kind, item_id).map_err(map_db_err)?;
        Ok(())
    }

    pub fn put_item_with_nonce(
        &self,
        kind: SecretVaultKind,
        item_id: &str,
        plaintext: &[u8],
        forced_nonce: Option<[u8; VAULT_NONCE_LEN]>,
    ) -> Result<(), SecureKeyError> {
        let aad = item_aad(
            kind,
            item_id,
            self.key_version,
            self.kek_version,
            self.installation.as_hex(),
        );
        let mut last_unique = None;
        for attempt in 0..NONCE_RETRY_LIMIT {
            let nonce = match forced_nonce {
                Some(n) if attempt == 0 => n,
                Some(_) => {
                    return Err(SecureKeyError::Corrupt("vault item nonce reuse".into()));
                }
                None => random_nonce(),
            };
            let ciphertext = aead_encrypt(self.dek.as_array(), &nonce, &aad, plaintext)?;
            let outcome = self
                .db
                .blocking_write_for_sync_maintenance({
                    let item_id = item_id.to_owned();
                    let key_version = self.key_version;
                    move |conn| {
                        let nonce_taken: bool = conn
                            .query_row(
                                "SELECT 1 FROM secret_vault_items
                                 WHERE key_version = ?1 AND nonce = ?2",
                                rusqlite::params![key_version, nonce.as_slice()],
                                |_| Ok(true),
                            )
                            .optional()
                            .map_err(anyhow::Error::from)?
                            .unwrap_or(false);
                        if nonce_taken {
                            return Ok(true);
                        }
                        match upsert_item_conn(
                            conn,
                            kind,
                            &item_id,
                            key_version,
                            &nonce,
                            &ciphertext,
                        ) {
                            Ok(()) => Ok(false),
                            Err(error) => {
                                if error
                                    .downcast_ref::<rusqlite::Error>()
                                    .is_some_and(is_unique_constraint)
                                    || error.to_string().contains("UNIQUE")
                                {
                                    Ok(true)
                                } else {
                                    Err(error)
                                }
                            }
                        }
                    }
                })
                .map_err(map_db_err)?;
            if !outcome {
                return Ok(());
            }
            last_unique = Some(());
        }
        let _ = last_unique;
        Err(SecureKeyError::Corrupt("vault item nonce reuse".into()))
    }

    pub fn get_item(
        &self,
        kind: SecretVaultKind,
        item_id: &str,
    ) -> Result<TempSecret, SecureKeyError> {
        let row = self
            .db
            .blocking_write_for_sync_maintenance({
                let item_id = item_id.to_owned();
                move |conn| load_item_conn(conn, kind, &item_id)
            })
            .map_err(map_db_err)?
            .ok_or_else(|| SecureKeyError::NotFound(format!("vault item {item_id}")))?;
        let aad = item_aad(
            kind,
            item_id,
            row.key_version,
            self.kek_version,
            self.installation.as_hex(),
        );
        decrypt_item(&self.dek, &row.nonce, &row.ciphertext, &aad)
    }

    /// Decrypt using a caller-supplied AAD (tests only).
    pub fn decrypt_item_with_aad(
        &self,
        kind: SecretVaultKind,
        item_id: &str,
        aad: &[u8],
    ) -> Result<TempSecret, SecureKeyError> {
        let row = self
            .db
            .blocking_write_for_sync_maintenance({
                let item_id = item_id.to_owned();
                move |conn| load_item_conn(conn, kind, &item_id)
            })
            .map_err(map_db_err)?
            .ok_or_else(|| SecureKeyError::NotFound(format!("vault item {item_id}")))?;
        decrypt_item(&self.dek, &row.nonce, &row.ciphertext, aad)
    }

    pub fn delete_item(&self, kind: SecretVaultKind, item_id: &str) -> Result<(), SecureKeyError> {
        self.db
            .blocking_write_for_sync_maintenance({
                let item_id = item_id.to_owned();
                move |conn| delete_item_conn(conn, kind, &item_id)
            })
            .map_err(map_db_err)?;
        Ok(())
    }

    pub fn list_item_ids(&self, kind: SecretVaultKind) -> Result<Vec<String>, SecureKeyError> {
        if kind == SecretVaultKind::SealedCompartment {
            return Err(SecureKeyError::Internal(
                "sealed compartment listing is not exposed".into(),
            ));
        }
        self.db
            .blocking_write_for_sync_maintenance(move |conn| list_item_ids_conn(conn, kind))
            .map_err(map_db_err)
    }

    /// Rewrap the active DEK under a new wrap nonce. Used by rotate tests.
    pub fn rewrap_active_dek(&self, fail_after_insert: bool) -> Result<(), SecureKeyError> {
        let new_version = self.key_version + 1;
        let wrap_nonce = random_nonce();
        let wrap_aad = wrap_aad(
            self.kek_version,
            VAULT_WRAP_VERSION,
            new_version,
            self.installation.as_hex(),
        );
        let wrapped = aead_encrypt(
            self.kek.as_array(),
            &wrap_nonce,
            &wrap_aad,
            self.dek.as_ref(),
        )?;
        self.db
            .blocking_write_for_sync_maintenance({
                let old = self.key_version;
                let kek_version = self.kek_version;
                move |conn| {
                    conn.execute_batch("BEGIN IMMEDIATE;")?;
                    let result = (|| {
                        deactivate_key_conn(conn, old)?;
                        insert_key_conn(
                            conn,
                            new_version,
                            kek_version,
                            &wrap_nonce,
                            &wrapped,
                            true,
                        )?;
                        if fail_after_insert {
                            anyhow::bail!("injected rewrap failure");
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
            .map_err(map_db_err)
    }

    pub fn unwrap_active_dek_with(
        &self,
        kek: &SecureKeyBytes,
    ) -> Result<SecureKeyBytes, SecureKeyError> {
        let row = self
            .db
            .blocking_write_for_sync_maintenance(load_active_key_conn)
            .map_err(map_db_err)?
            .ok_or_else(|| SecureKeyError::Corrupt("no active vault DEK".into()))?;
        unwrap_dek(kek, &row, self.installation.as_hex())
    }
}

impl SecretVault {
    pub fn open_from_parts(
        db: Db,
        kek_store: Arc<dyn KekStore>,
        installation: InstallationIdentity,
    ) -> Result<Self, SecureKeyError> {
        let snapshot = db
            .blocking_write_for_sync_maintenance(|conn| {
                let active = count_active_keys_conn(conn)?;
                if active != 1 {
                    return Ok(Err(SecureKeyError::Corrupt(format!(
                        "expected exactly one active DEK, found {active}"
                    ))));
                }
                let row = match load_active_key_conn(conn)? {
                    Some(row) => row,
                    None => {
                        return Ok(Err(SecureKeyError::Corrupt("no active vault DEK".into())));
                    }
                };
                Ok(Ok(row))
            })
            .map_err(map_db_err)??;
        if snapshot.algorithm != VAULT_ALGORITHM || snapshot.wrap_version != VAULT_WRAP_VERSION {
            return Err(SecureKeyError::Corrupt(
                "unsupported vault wrap algorithm".into(),
            ));
        }
        let kek = kek_store.read_kek(snapshot.kek_version)?.into_key_bytes()?;
        let dek = unwrap_dek(&kek, &snapshot, installation.as_hex())?;
        Ok(Self {
            db,
            kek_store,
            installation,
            kek,
            dek,
            kek_version: snapshot.kek_version,
            key_version: snapshot.key_version,
        })
    }
}

fn unwrap_dek(
    kek: &SecureKeyBytes,
    row: &cockpit_db::secret_vault::SecretVaultKeyRow,
    installation_hex: &str,
) -> Result<SecureKeyBytes, SecureKeyError> {
    if row.wrapped_dek.len() != VAULT_WRAPPED_DEK_LEN {
        return Err(SecureKeyError::Corrupt(format!(
            "wrapped DEK length {} != {VAULT_WRAPPED_DEK_LEN}",
            row.wrapped_dek.len()
        )));
    }
    let aad = wrap_aad(
        row.kek_version,
        row.wrap_version,
        row.key_version,
        installation_hex,
    );
    let nonce = nonce_from_slice(&row.wrap_nonce)?;
    let plain = aead_decrypt(kek.as_array(), &nonce, &aad, &row.wrapped_dek)?;
    if plain.len() != KEY_BYTE_LEN {
        return Err(SecureKeyError::Corrupt(format!(
            "unwrapped DEK length {} != {KEY_BYTE_LEN}",
            plain.len()
        )));
    }
    let mut arr = Zeroizing::new([0u8; KEY_BYTE_LEN]);
    arr.copy_from_slice(&plain);
    Ok(SecureKeyBytes::from_array(*arr))
}

fn decrypt_item(
    dek: &SecureKeyBytes,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<TempSecret, SecureKeyError> {
    if ciphertext.len() < VAULT_TAG_LEN {
        return Err(SecureKeyError::Corrupt(
            "vault item ciphertext too short".into(),
        ));
    }
    let nonce = nonce_from_slice(nonce)?;
    let plain = aead_decrypt(dek.as_array(), &nonce, aad, ciphertext)?;
    Ok(TempSecret::from_vec(plain.to_vec()))
}

pub fn wrap_aad(
    kek_version: i64,
    wrap_version: i64,
    key_version: i64,
    installation: &str,
) -> Vec<u8> {
    let mut out = Vec::from(b"cockpit/secret-vault/wrap/v1".as_slice());
    out.push(UNIT);
    out.extend_from_slice(format!("kek_version={kek_version}").as_bytes());
    out.push(UNIT);
    out.extend_from_slice(format!("wrap_version={wrap_version}").as_bytes());
    out.push(UNIT);
    out.extend_from_slice(format!("key_version={key_version}").as_bytes());
    out.push(UNIT);
    out.extend_from_slice(format!("installation={installation}").as_bytes());
    out
}

pub fn item_aad(
    kind: SecretVaultKind,
    item_id: &str,
    key_version: i64,
    kek_version: i64,
    installation: &str,
) -> Vec<u8> {
    let mut out = Vec::from(b"cockpit/secret-vault/item/v1".as_slice());
    out.push(UNIT);
    out.extend_from_slice(format!("kind={}", kind.as_str()).as_bytes());
    out.push(UNIT);
    out.extend_from_slice(format!("item_id={item_id}").as_bytes());
    out.push(UNIT);
    out.extend_from_slice(format!("key_version={key_version}").as_bytes());
    out.push(UNIT);
    out.extend_from_slice(format!("kek_version={kek_version}").as_bytes());
    out.push(UNIT);
    out.extend_from_slice(format!("installation={installation}").as_bytes());
    out
}

pub fn fingerprint_key(key: &SecureKeyBytes) -> String {
    Sha256::digest(key.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn random_nonce() -> [u8; VAULT_NONCE_LEN] {
    let mut nonce = [0u8; VAULT_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

fn nonce_from_slice(bytes: &[u8]) -> Result<[u8; VAULT_NONCE_LEN], SecureKeyError> {
    bytes
        .try_into()
        .map_err(|_| SecureKeyError::Corrupt("vault nonce length != 12".into()))
}

pub fn aead_encrypt(
    key: &[u8; KEY_BYTE_LEN],
    nonce: &[u8; VAULT_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SecureKeyError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SecureKeyError::Internal("vault aead encrypt failed".into()))
}

pub fn aead_decrypt(
    key: &[u8; KEY_BYTE_LEN],
    nonce: &[u8; VAULT_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SecureKeyError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plain = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SecureKeyError::Corrupt("vault aead authentication failed".into()))?;
    Ok(Zeroizing::new(plain))
}

fn map_db_err(err: anyhow::Error) -> SecureKeyError {
    SecureKeyError::Internal(err.to_string())
}

/// Tamper helpers for tests (no secret material in the names).
pub fn tamper_item_ciphertext(
    db: &Db,
    kind: SecretVaultKind,
    item_id: &str,
    mutate: impl FnOnce(&mut Vec<u8>) + Send + 'static,
) -> Result<(), SecureKeyError> {
    let item_id = item_id.to_owned();
    db.blocking_write_for_sync_maintenance(move |conn| {
        let mut row =
            load_item_conn(conn, kind, &item_id)?.ok_or_else(|| anyhow::anyhow!("item missing"))?;
        mutate(&mut row.ciphertext);
        conn.execute(
            "UPDATE secret_vault_items SET ciphertext = ?1 WHERE kind = ?2 AND item_id = ?3",
            rusqlite::params![row.ciphertext, kind.as_str(), item_id],
        )?;
        Ok(())
    })
    .map_err(map_db_err)
}

pub fn substitute_item_ciphertext(
    db: &Db,
    from_kind: SecretVaultKind,
    from_id: &str,
    to_kind: SecretVaultKind,
    to_id: &str,
) -> Result<(), SecureKeyError> {
    let from_id = from_id.to_owned();
    let to_id = to_id.to_owned();
    db.blocking_write_for_sync_maintenance(move |conn| {
        let src = load_item_conn(conn, from_kind, &from_id)?
            .ok_or_else(|| anyhow::anyhow!("source item missing"))?;
        // Copy ciphertext onto dest. Keep dest's nonce so UNIQUE(key_version,
        // nonce) still holds; AAD binds kind+item_id so decrypt of dest fails.
        conn.execute(
            "UPDATE secret_vault_items SET ciphertext = ?1
             WHERE kind = ?2 AND item_id = ?3",
            rusqlite::params![src.ciphertext, to_kind.as_str(), to_id],
        )?;
        Ok(())
    })
    .map_err(map_db_err)
}
