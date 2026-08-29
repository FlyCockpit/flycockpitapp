//! Wrap-key vault: ChaCha20-Poly1305 wrap + item AEAD keyed by an unwrapped DEK.

use std::fmt;
use std::sync::{Arc, Mutex};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use cockpit_db::secret_vault::{
    SecretVaultItemRow, SecretVaultKind, SecretVaultPlacement, VAULT_ALGORITHM, VAULT_NONCE_LEN,
    VAULT_TAG_LEN, VAULT_WRAP_VERSION, VAULT_WRAPPED_DEK_LEN, count_active_keys_conn,
    deactivate_key_conn, delete_item_conn, ensure_inventory_generation_conn, insert_key_conn,
    is_unique_constraint, list_inventory_page_conn, list_item_ids_conn, load_active_key_conn,
    load_authority_conn, load_item_conn, upsert_item_conn,
};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use rand::Rng;
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

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
    /// Daemon owner-mutation publication hook.  This is deliberately kept on
    /// the shared vault handle so refreshes performed deep in MCP client
    /// code cannot commit a named secret without publishing the active
    /// redaction table.
    owner_redaction_publisher: Arc<Mutex<Option<OwnerRedactionPublisher>>>,
}

pub type OwnerRedactionPublisher = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

/// Exact state of one owner-visible item at a durable inventory generation.
/// The generation remains part of the token when the row is absent, so an
/// ABA delete cannot compare equal to the absence produced by the operation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecretVaultItemSnapshot {
    pub generation: u64,
    pub row: Option<SecretVaultItemRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecretVaultMutation {
    pub prior: SecretVaultItemSnapshot,
    pub after: SecretVaultItemSnapshot,
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
    /// Install the daemon-owned redaction publication callback.  The callback
    /// is process-local and never persisted with vault state.
    pub fn install_owner_redaction_publisher(&self, publisher: OwnerRedactionPublisher) {
        *self
            .owner_redaction_publisher
            .lock()
            .expect("owner redaction publisher mutex poisoned") = Some(publisher);
    }

    fn publish_owner_redaction(&self) -> Result<(), SecureKeyError> {
        let publisher = self
            .owner_redaction_publisher
            .lock()
            .expect("owner redaction publisher mutex poisoned")
            .clone();
        if let Some(publisher) = publisher {
            publisher().map_err(SecureKeyError::Internal)?;
        }
        Ok(())
    }

    /// Mutate one owner-visible item and publish the current redaction table.
    /// If publication fails, restore the exact prior row unless another
    /// writer has advanced the same item.
    pub fn mutate_owner_item(
        &self,
        kind: SecretVaultKind,
        item_id: &str,
        plaintext: Option<&[u8]>,
    ) -> Result<(), SecureKeyError> {
        let mutation = self.mutate_item(kind, item_id, plaintext)?;
        if let Err(error) = self.publish_owner_redaction() {
            self.restore_item_if_unchanged(kind, item_id, &mutation.after, mutation.prior.row.as_ref())
                .map_err(|rollback| SecureKeyError::Internal(format!(
                    "owner redaction publication failed: {error:?}; vault rollback failed: {rollback:?}"
                )))?;
            return Err(error);
        }
        Ok(())
    }

    /// Guarded owner mutation for a named secret: the cross-kind/foreign-owner
    /// ownership guard, the AEAD mutate, and the ownership claim run in ONE
    /// `BEGIN IMMEDIATE` transaction, so a write that does not own the name fails
    /// closed (no vault mutation, no claim) rather than stomping a secret owned by
    /// a different kind/workspace. On success the owner redaction table is
    /// published, compensating the vault write if publication fails — matching
    /// [`Self::mutate_owner_item`]. This is the funnel MCP OAuth token refresh
    /// uses (a refresh must own the name it rotates).
    pub fn mutate_owner_named_secret_guarded(
        &self,
        item_id: &str,
        plaintext: &[u8],
        owner_kind: &str,
        project_root: &str,
    ) -> Result<(), SecureKeyError> {
        let item_id_owned = item_id.to_owned();
        let plaintext_owned = plaintext.to_vec();
        let owner_kind_owned = owner_kind.to_owned();
        let project_root_owned = project_root.to_owned();
        let vault = self.clone();
        let mutation = self
            .db
            .blocking_write_for_sync_maintenance(move |conn| {
                ensure_inventory_generation_conn(conn).map_err(map_db_err)?;
                conn.execute_batch("BEGIN IMMEDIATE;")
                    .map_err(|error| SecureKeyError::Internal(error.to_string()))?;
                let result = (|| -> Result<SecretVaultMutation, SecureKeyError> {
                    // Fail closed if a foreign kind/workspace owns this name.
                    crate::secret_ownership::reject_conflicting_named_ownership_on_conn(
                        conn,
                        &item_id_owned,
                        &owner_kind_owned,
                        &project_root_owned,
                    )
                    .map_err(|error| SecureKeyError::Internal(error.to_string()))?;
                    let mutation = vault.mutate_item_on_conn(
                        conn,
                        SecretVaultKind::NamedSecret,
                        &item_id_owned,
                        Some(&plaintext_owned),
                    )?;
                    crate::secret_ownership::claim_named_reference_on_conn(
                        conn,
                        &item_id_owned,
                        &owner_kind_owned,
                        &project_root_owned,
                    )
                    .map_err(|error| SecureKeyError::Internal(error.to_string()))?;
                    Ok(mutation)
                })();
                match result {
                    Ok(mutation) => {
                        conn.execute_batch("COMMIT;")
                            .map_err(|error| SecureKeyError::Internal(error.to_string()))?;
                        Ok(mutation)
                    }
                    Err(error) => {
                        let _ = conn.execute_batch("ROLLBACK;");
                        Err(error.into())
                    }
                }
            })
            .map_err(map_db_err)?;
        if let Err(error) = self.publish_owner_redaction() {
            self.restore_item_if_unchanged(
                SecretVaultKind::NamedSecret,
                item_id,
                &mutation.after,
                mutation.prior.row.as_ref(),
            )
            .map_err(|rollback| {
                SecureKeyError::Internal(format!(
                    "owner redaction publication failed: {error:?}; vault rollback failed: {rollback:?}"
                ))
            })?;
            return Err(error);
        }
        Ok(())
    }

    /// Compute a daemon-held keyed identity for replay ledgers. The digest is
    /// stable for this daemon/vault key and request bytes, but unlike a plain
    /// SHA-256 it is not an offline verifier for secret-bearing requests.
    pub fn keyed_request_identity(&self, domain: &[u8], request: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(self.dek.as_ref())
            .expect("SecretVault DEK always has the fixed key length");
        mac.update(domain);
        mac.update(request);
        mac.finalize().into_bytes().into()
    }

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

    /// Produce an installation- and vault-keyed, domain-separated identity.
    /// This is suitable for equality/replay fences persisted outside the vault:
    /// unlike a raw content digest it is not an offline guessing oracle.
    pub fn keyed_identity(&self, domain: &[u8], value: &[u8]) -> [u8; 32] {
        let mut derivation =
            HmacSha256::new_from_slice(self.kek.as_ref()).expect("HMAC accepts any key length");
        derivation.update(b"flycockpit.vault-identity-key.v1\0");
        derivation.update(self.installation.as_hex().as_bytes());
        derivation.update(b"\0");
        derivation.update(domain);
        let mut derived = Zeroizing::new([0_u8; 32]);
        derived.copy_from_slice(&derivation.finalize().into_bytes());
        let mut identity =
            HmacSha256::new_from_slice(derived.as_slice()).expect("HMAC accepts any key length");
        identity.update(value);
        identity.finalize().into_bytes().into()
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

    /// First-run: write the chosen placement's KEK, persist authority + wrapped DEK.
    pub fn initialize(
        db: Db,
        kek_store: Arc<dyn KekStore>,
        installation: InstallationIdentity,
        kek_version: i64,
        key_version: i64,
        placement: SecretVaultPlacement,
    ) -> Result<Self, SecureKeyError> {
        let kek = generate_key_bytes();
        kek_store.write_kek_exclusive(kek_version, kek.as_ref())?;
        let kek_store_for_cleanup = kek_store.clone();
        let db_for_cleanup = db.clone();
        let ours = fingerprint_key(&kek);
        let built = (|| -> Result<Self, SecureKeyError> {
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
                        ensure_inventory_generation_conn(conn)?;
                        if count_active_keys_conn(conn)? != 0 {
                            anyhow::bail!("vault already has an active DEK");
                        }
                        if load_authority_conn(conn)?.is_some() {
                            anyhow::bail!("secret vault authority already exists");
                        }
                        cockpit_db::secret_vault::upsert_authority_conn(
                            conn,
                            placement,
                            placement,
                            &fingerprint,
                            kek_version,
                            VAULT_WRAP_VERSION,
                        )?;
                        insert_key_conn(
                            conn,
                            key_version,
                            kek_version,
                            &wrap_nonce,
                            &wrapped,
                            true,
                        )?;
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
                owner_redaction_publisher: Arc::new(Mutex::new(None)),
            })
        })();
        if built.is_err() {
            // Do not delete a KEK that another first-run already committed.
            let committed = db_for_cleanup
                .blocking_write_for_sync_maintenance(load_authority_conn)
                .ok()
                .flatten();
            if committed.is_none_or(|row| row.kek_fingerprint != ours) {
                let _ = kek_store_for_cleanup.delete_kek(kek_version);
            }
        }
        built
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
                Ok(()) => {
                    return Ok(());
                }
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

    /// Delete an item inside a caller-owned SQLite transaction without
    /// decrypting its payload. Corrupt ciphertext therefore remains
    /// removable, and an absent item is an idempotent success.
    pub fn delete_item_on_conn(
        &self,
        conn: &rusqlite::Connection,
        kind: SecretVaultKind,
        item_id: &str,
    ) -> Result<(), SecureKeyError> {
        delete_item_conn(conn, kind, item_id).map_err(map_db_err)?;
        Ok(())
    }

    /// Mutate one owner-visible item and capture the exact before/after
    /// encrypted rows and durable inventory generations in the same SQLite
    /// writer transaction. Keeping mutation and capture together closes the
    /// window in which another process could write between them.
    pub fn mutate_item(
        &self,
        kind: SecretVaultKind,
        item_id: &str,
        plaintext: Option<&[u8]>,
    ) -> Result<SecretVaultMutation, SecureKeyError> {
        let item_id = item_id.to_owned();
        let plaintext = plaintext.map(ToOwned::to_owned);
        let vault = self.clone();
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                ensure_inventory_generation_conn(conn).map_err(map_db_err)?;
                conn.execute_batch("BEGIN IMMEDIATE;")
                    .map_err(|error| SecureKeyError::Internal(error.to_string()))?;
                let result = vault.mutate_item_on_conn(conn, kind, &item_id, plaintext.as_deref());
                match result {
                    Ok(value) => {
                        conn.execute_batch("COMMIT;")
                            .map_err(|error| SecureKeyError::Internal(error.to_string()))?;
                        Ok(value)
                    }
                    Err(error) => {
                        let _ = conn.execute_batch("ROLLBACK;");
                        Err(error.into())
                    }
                }
            })
            .map_err(map_db_err)
    }

    /// Apply an item mutation on a caller-owned SQLite transaction and return
    /// the compare-and-restore token used by redaction publication
    /// compensation. The caller must already hold the transaction's writer
    /// lock; unlike [`Self::mutate_item`], this method neither starts nor
    /// commits a transaction.
    pub fn mutate_item_on_conn(
        &self,
        conn: &rusqlite::Connection,
        kind: SecretVaultKind,
        item_id: &str,
        plaintext: Option<&[u8]>,
    ) -> Result<SecretVaultMutation, SecureKeyError> {
        let prior_row = load_item_conn(conn, kind, item_id).map_err(map_db_err)?;
        if prior_row.is_some() {
            // Preserve fail-closed behavior for corrupt rows before allowing
            // compensation to bind to them.
            self.get_item_on_conn(conn, kind, item_id)?;
        }
        let prior_revision: u64 = conn
            .query_row(
                "SELECT revision FROM secret_vault_item_revisions
                 WHERE kind = ?1 AND item_id = ?2",
                rusqlite::params![kind.as_str(), item_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|error| SecureKeyError::Internal(error.to_string()))?
            .unwrap_or(0)
            .try_into()
            .map_err(|_| SecureKeyError::Corrupt("invalid vault item revision".into()))?;
        let prior = SecretVaultItemSnapshot {
            generation: prior_revision,
            row: prior_row,
        };
        match plaintext {
            Some(value) => self.put_item_on_conn(conn, kind, item_id, value)?,
            None => {
                delete_item_conn(conn, kind, item_id).map_err(map_db_err)?;
            }
        }
        let after_revision: u64 = conn
            .query_row(
                "SELECT revision FROM secret_vault_item_revisions
                 WHERE kind = ?1 AND item_id = ?2",
                rusqlite::params![kind.as_str(), item_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| SecureKeyError::Internal(error.to_string()))?
            .try_into()
            .map_err(|_| SecureKeyError::Corrupt("invalid vault item revision".into()))?;
        let after = SecretVaultItemSnapshot {
            generation: after_revision,
            row: load_item_conn(conn, kind, item_id).map_err(map_db_err)?,
        };
        Ok(SecretVaultMutation { prior, after })
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

    /// Current durable inventory generation. SQLite triggers bump this on
    /// every visible vault write (including direct and cross-process writes),
    /// so a caller can cheaply detect whether the vault changed since a prior
    /// read without decrypting any item.
    pub fn current_inventory_generation(&self) -> Result<u64, SecureKeyError> {
        self.db
            .blocking_write_for_sync_maintenance(|conn| {
                cockpit_db::secret_vault::inventory_generation_conn(conn)
            })
            .map_err(map_db_err)
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

    /// Restore one item only if its raw encrypted row is still exactly the
    /// state supplied as `expected`. The compare and replacement happen in a
    /// single writer transaction, so a different daemon cannot have its
    /// newer same-item write overwritten by redaction compensation.
    pub fn restore_item_if_unchanged(
        &self,
        kind: SecretVaultKind,
        item_id: &str,
        expected: &SecretVaultItemSnapshot,
        prior: Option<&SecretVaultItemRow>,
    ) -> Result<bool, SecureKeyError> {
        let item_id = item_id.to_owned();
        let expected = expected.clone();
        let prior = prior.cloned();
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                conn.execute_batch("BEGIN IMMEDIATE;")?;
                let result = (|| {
                    let current = load_item_conn(conn, kind, &item_id)?;
                    let revision: u64 = conn
                        .query_row(
                            "SELECT revision FROM secret_vault_item_revisions
                             WHERE kind = ?1 AND item_id = ?2",
                            rusqlite::params![kind.as_str(), item_id],
                            |row| row.get::<_, i64>(0),
                        )
                        .optional()?
                        .unwrap_or(0)
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid vault item revision"))?;
                    if revision != expected.generation || current != expected.row {
                        return Ok(false);
                    }
                    let next_revision: i64 = revision
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("vault item revision overflow"))?
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("vault item revision overflow"))?;
                    match prior.as_ref() {
                        Some(row) => {
                            conn.execute(
                                "INSERT INTO secret_vault_items
                                    (kind, item_id, key_version, nonce, ciphertext, created_at, updated_at, revision)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                                 ON CONFLICT(kind, item_id) DO UPDATE SET
                                    key_version = excluded.key_version,
                                    nonce = excluded.nonce,
                                    ciphertext = excluded.ciphertext,
                                    created_at = excluded.created_at,
                                    updated_at = excluded.updated_at,
                                    revision = excluded.revision",
                                rusqlite::params![
                                    row.kind.as_str(),
                                    row.item_id,
                                    row.key_version,
                                    row.nonce,
                                    row.ciphertext,
                                    row.created_at,
                                    row.updated_at,
                                    next_revision,
                                ],
                            )?;
                        }
                        None => {
                            delete_item_conn(conn, kind, &item_id)?;
                        }
                    }
                    conn.execute(
                        "INSERT INTO secret_vault_item_revisions (kind, item_id, revision)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(kind, item_id) DO UPDATE SET revision = excluded.revision",
                        rusqlite::params![kind.as_str(), item_id, next_revision],
                    )?;
                    Ok(true)
                })();
                match result {
                    Ok(value) => {
                        conn.execute_batch("COMMIT;")?;
                        Ok(value)
                    }
                    Err(error) => {
                        let _ = conn.execute_batch("ROLLBACK;");
                        Err(error)
                    }
                }
            })
            .map_err(map_db_err)
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

    pub fn list_inventory_page(
        &self,
        after: Option<(&str, &str)>,
        limit: usize,
    ) -> Result<cockpit_db::secret_vault::SecretVaultInventoryPage, SecureKeyError> {
        let after = after.map(|(kind, item_id)| (kind.to_string(), item_id.to_string()));
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                ensure_inventory_generation_conn(conn)?;
                list_inventory_page_conn(
                    conn,
                    after
                        .as_ref()
                        .map(|(kind, item_id)| (kind.as_str(), item_id.as_str())),
                    limit,
                    cockpit_proto::MAX_OWNER_INVENTORY_TOTAL_ENTRIES,
                )
            })
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
                ensure_inventory_generation_conn(conn)?;
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
            owner_redaction_publisher: Arc::new(Mutex::new(None)),
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
#[allow(dead_code)]
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

#[allow(dead_code)]
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

pub fn session_sealed_item_id(session_id: &str, value_id: &str, version: i64) -> String {
    format!("{session_id}/{value_id}/v{version}")
}

pub fn redaction_table_item_id(session_id: &str) -> String {
    session_id.to_string()
}
