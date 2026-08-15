//! SQLite accessors for the wrap-key secret vault.
//!
//! Tables hold AEAD ciphertext and wrapped DEKs only. KEK bytes and DEK
//! plaintext never live here. Coordination sagas carry fingerprints, not keys.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};

use crate::db::Db;

pub const VAULT_WRAP_VERSION: i64 = 1;
pub const VAULT_ALGORITHM: &str = "chacha20poly1305";
pub const VAULT_NONCE_LEN: usize = 12;
pub const VAULT_TAG_LEN: usize = 16;
pub const VAULT_WRAPPED_DEK_LEN: usize = 32 + VAULT_TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretVaultPlacement {
    Database,
    Keyring,
}

impl SecretVaultPlacement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Keyring => "keyring",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "database" => Ok(Self::Database),
            "keyring" => Ok(Self::Keyring),
            other => bail!("unknown secret vault placement: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretVaultKind {
    SecureKeyRoot,
    SecureKeyManifest,
    SealedState,
    CredentialRecord,
    NamedSecret,
    SubscriptionAck,
    SealedCompartment,
    SessionSealedValue,
    RedactionTable,
}

impl SecretVaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecureKeyRoot => "secure_key_root",
            Self::SecureKeyManifest => "secure_key_manifest",
            Self::SealedState => "sealed_state",
            Self::CredentialRecord => "credential_record",
            Self::NamedSecret => "named_secret",
            Self::SubscriptionAck => "subscription_ack",
            Self::SealedCompartment => "sealed_compartment",
            Self::SessionSealedValue => "session_sealed_value",
            Self::RedactionTable => "redaction_table",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "secure_key_root" => Ok(Self::SecureKeyRoot),
            "secure_key_manifest" => Ok(Self::SecureKeyManifest),
            "sealed_state" => Ok(Self::SealedState),
            "credential_record" => Ok(Self::CredentialRecord),
            "named_secret" => Ok(Self::NamedSecret),
            "subscription_ack" => Ok(Self::SubscriptionAck),
            "sealed_compartment" => Ok(Self::SealedCompartment),
            "session_sealed_value" => Ok(Self::SessionSealedValue),
            "redaction_table" => Ok(Self::RedactionTable),
            other => bail!("unknown secret vault kind: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretVaultSagaPhase {
    Prepared,
    Activated,
    SourceDeleted,
    Complete,
}

impl SecretVaultSagaPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Activated => "activated",
            Self::SourceDeleted => "source_deleted",
            Self::Complete => "complete",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "prepared" => Ok(Self::Prepared),
            "activated" => Ok(Self::Activated),
            "source_deleted" => Ok(Self::SourceDeleted),
            "complete" => Ok(Self::Complete),
            other => bail!("unknown secret vault saga phase: {other}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVaultAuthorityRow {
    pub intent: SecretVaultPlacement,
    pub active_placement: SecretVaultPlacement,
    pub kek_fingerprint: String,
    pub kek_version: i64,
    pub wrap_version: i64,
    pub unification_complete: bool,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVaultKeyRow {
    pub key_version: i64,
    pub kek_version: i64,
    pub wrap_version: i64,
    pub algorithm: String,
    pub wrap_nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub active: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVaultItemRow {
    pub kind: SecretVaultKind,
    pub item_id: String,
    pub key_version: i64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVaultSagaRow {
    pub op_id: String,
    pub source_placement: SecretVaultPlacement,
    pub dest_placement: SecretVaultPlacement,
    pub kek_fingerprint: String,
    pub phase: SecretVaultSagaPhase,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretVaultStore {
    Credentials,
    SealedCompartment,
    SessionSealedValue,
    RedactionTable,
}

impl SecretVaultStore {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credentials => "credentials",
            Self::SealedCompartment => "sealed_compartment",
            Self::SessionSealedValue => "session_sealed_value",
            Self::RedactionTable => "redaction_table",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "credentials" => Ok(Self::Credentials),
            "sealed_compartment" => Ok(Self::SealedCompartment),
            "session_sealed_value" => Ok(Self::SessionSealedValue),
            "redaction_table" => Ok(Self::RedactionTable),
            other => bail!("unknown secret vault store: {other}"),
        }
    }

    pub fn all() -> [Self; 4] {
        [
            Self::Credentials,
            Self::SealedCompartment,
            Self::SessionSealedValue,
            Self::RedactionTable,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretVaultStoreAuthority {
    Legacy,
    Vault,
}

impl SecretVaultStoreAuthority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Vault => "vault",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "legacy" => Ok(Self::Legacy),
            "vault" => Ok(Self::Vault),
            other => bail!("unknown secret vault store authority: {other}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVaultStoreStateRow {
    pub store: SecretVaultStore,
    pub authoritative: SecretVaultStoreAuthority,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVaultImportSagaRow {
    pub op_id: String,
    pub store: SecretVaultStore,
    pub phase: SecretVaultSagaPhase,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Db {
    pub async fn secret_vault_load_authority(&self) -> Result<Option<SecretVaultAuthorityRow>> {
        self.read(load_authority_conn).await
    }
}

pub fn load_authority_conn(conn: &rusqlite::Connection) -> Result<Option<SecretVaultAuthorityRow>> {
    conn.query_row(
        "SELECT intent, active_placement, kek_fingerprint, kek_version, wrap_version,
                unification_complete, updated_at
         FROM secret_vault_authority WHERE id = 1",
        [],
        map_authority_row,
    )
    .optional()
    .context("loading secret vault authority")
}

fn map_authority_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretVaultAuthorityRow> {
    let intent: String = row.get(0)?;
    let placement: String = row.get(1)?;
    let complete: i64 = row.get(5)?;
    Ok(SecretVaultAuthorityRow {
        intent: SecretVaultPlacement::parse(&intent).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        active_placement: SecretVaultPlacement::parse(&placement).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        kek_fingerprint: row.get(2)?,
        kek_version: row.get(3)?,
        wrap_version: row.get(4)?,
        unification_complete: complete != 0,
        updated_at: row.get(6)?,
    })
}

pub fn upsert_authority_conn(
    conn: &rusqlite::Connection,
    intent: SecretVaultPlacement,
    active_placement: SecretVaultPlacement,
    kek_fingerprint: &str,
    kek_version: i64,
    wrap_version: i64,
    unification_complete: bool,
) -> Result<()> {
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO secret_vault_authority
            (id, intent, active_placement, kek_fingerprint, kek_version, wrap_version,
             unification_complete, updated_at)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(id) DO UPDATE SET
            intent = excluded.intent,
            active_placement = excluded.active_placement,
            kek_fingerprint = excluded.kek_fingerprint,
            kek_version = excluded.kek_version,
            wrap_version = excluded.wrap_version,
            unification_complete = excluded.unification_complete,
            updated_at = excluded.updated_at",
        params![
            intent.as_str(),
            active_placement.as_str(),
            kek_fingerprint,
            kek_version,
            wrap_version,
            if unification_complete { 1 } else { 0 },
            now
        ],
    )
    .context("upserting secret vault authority")?;
    Ok(())
}

pub fn count_active_keys_conn(conn: &rusqlite::Connection) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM secret_vault_keys WHERE active = 1",
        [],
        |row| row.get(0),
    )
    .context("counting active vault DEKs")
}

pub fn load_active_key_conn(conn: &rusqlite::Connection) -> Result<Option<SecretVaultKeyRow>> {
    conn.query_row(
        "SELECT key_version, kek_version, wrap_version, algorithm, wrap_nonce, wrapped_dek,
                active, created_at
         FROM secret_vault_keys WHERE active = 1",
        [],
        map_key_row,
    )
    .optional()
    .context("loading active vault DEK")
}

pub fn load_key_conn(
    conn: &rusqlite::Connection,
    key_version: i64,
) -> Result<Option<SecretVaultKeyRow>> {
    conn.query_row(
        "SELECT key_version, kek_version, wrap_version, algorithm, wrap_nonce, wrapped_dek,
                active, created_at
         FROM secret_vault_keys WHERE key_version = ?1",
        [key_version],
        map_key_row,
    )
    .optional()
    .context("loading vault DEK")
}

fn map_key_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretVaultKeyRow> {
    let active: i64 = row.get(6)?;
    Ok(SecretVaultKeyRow {
        key_version: row.get(0)?,
        kek_version: row.get(1)?,
        wrap_version: row.get(2)?,
        algorithm: row.get(3)?,
        wrap_nonce: row.get(4)?,
        wrapped_dek: row.get(5)?,
        active: active != 0,
        created_at: row.get(7)?,
    })
}

pub fn insert_key_conn(
    conn: &rusqlite::Connection,
    key_version: i64,
    kek_version: i64,
    wrap_nonce: &[u8],
    wrapped_dek: &[u8],
    active: bool,
) -> Result<()> {
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO secret_vault_keys
            (key_version, kek_version, wrap_version, algorithm, wrap_nonce, wrapped_dek,
             active, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            key_version,
            kek_version,
            VAULT_WRAP_VERSION,
            VAULT_ALGORITHM,
            wrap_nonce,
            wrapped_dek,
            if active { 1 } else { 0 },
            now
        ],
    )
    .context("inserting wrapped DEK")?;
    Ok(())
}

pub fn deactivate_key_conn(conn: &rusqlite::Connection, key_version: i64) -> Result<()> {
    let n = conn
        .execute(
            "UPDATE secret_vault_keys SET active = 0 WHERE key_version = ?1",
            [key_version],
        )
        .context("deactivating vault DEK")?;
    if n == 0 {
        bail!("vault DEK {key_version} not found");
    }
    Ok(())
}

pub fn upsert_item_conn(
    conn: &rusqlite::Connection,
    kind: SecretVaultKind,
    item_id: &str,
    key_version: i64,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<()> {
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO secret_vault_items
            (kind, item_id, key_version, nonce, ciphertext, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(kind, item_id) DO UPDATE SET
            key_version = excluded.key_version,
            nonce = excluded.nonce,
            ciphertext = excluded.ciphertext,
            updated_at = excluded.updated_at",
        params![kind.as_str(), item_id, key_version, nonce, ciphertext, now],
    )
    .context("upserting vault item")?;
    Ok(())
}

pub fn load_item_conn(
    conn: &rusqlite::Connection,
    kind: SecretVaultKind,
    item_id: &str,
) -> Result<Option<SecretVaultItemRow>> {
    conn.query_row(
        "SELECT kind, item_id, key_version, nonce, ciphertext, created_at, updated_at
         FROM secret_vault_items WHERE kind = ?1 AND item_id = ?2",
        params![kind.as_str(), item_id],
        map_item_row,
    )
    .optional()
    .context("loading vault item")
}

pub fn delete_item_conn(
    conn: &rusqlite::Connection,
    kind: SecretVaultKind,
    item_id: &str,
) -> Result<bool> {
    let n = conn
        .execute(
            "DELETE FROM secret_vault_items WHERE kind = ?1 AND item_id = ?2",
            params![kind.as_str(), item_id],
        )
        .context("deleting vault item")?;
    Ok(n > 0)
}

pub fn list_item_ids_conn(
    conn: &rusqlite::Connection,
    kind: SecretVaultKind,
) -> Result<Vec<String>> {
    if kind == SecretVaultKind::SealedCompartment {
        bail!("sealed compartment listing is not exposed");
    }
    let mut stmt = conn
        .prepare("SELECT item_id FROM secret_vault_items WHERE kind = ?1 ORDER BY item_id ASC")?;
    let rows = stmt.query_map([kind.as_str()], |row| row.get(0))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing vault item ids")
}

pub fn list_items_conn(conn: &rusqlite::Connection) -> Result<Vec<SecretVaultItemRow>> {
    let mut stmt = conn.prepare(
        "SELECT kind, item_id, key_version, nonce, ciphertext, created_at, updated_at
         FROM secret_vault_items
         WHERE kind != 'sealed_compartment'
         ORDER BY kind ASC, item_id ASC",
    )?;
    let rows = stmt.query_map([], map_item_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing vault items")
}

fn map_item_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretVaultItemRow> {
    let kind: String = row.get(0)?;
    Ok(SecretVaultItemRow {
        kind: SecretVaultKind::parse(&kind).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        item_id: row.get(1)?,
        key_version: row.get(2)?,
        nonce: row.get(3)?,
        ciphertext: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

pub fn insert_saga_conn(
    conn: &rusqlite::Connection,
    op_id: &str,
    source: SecretVaultPlacement,
    dest: SecretVaultPlacement,
    kek_fingerprint: &str,
    phase: SecretVaultSagaPhase,
) -> Result<()> {
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO secret_vault_sagas
            (op_id, source_placement, dest_placement, kek_fingerprint, phase, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![
            op_id,
            source.as_str(),
            dest.as_str(),
            kek_fingerprint,
            phase.as_str(),
            now
        ],
    )
    .context("inserting secret vault saga")?;
    Ok(())
}

pub fn load_saga_conn(
    conn: &rusqlite::Connection,
    op_id: &str,
) -> Result<Option<SecretVaultSagaRow>> {
    conn.query_row(
        "SELECT op_id, source_placement, dest_placement, kek_fingerprint, phase, created_at, updated_at
         FROM secret_vault_sagas WHERE op_id = ?1",
        [op_id],
        map_saga_row,
    )
    .optional()
    .context("loading secret vault saga")
}

pub fn list_open_sagas_conn(conn: &rusqlite::Connection) -> Result<Vec<SecretVaultSagaRow>> {
    let mut stmt = conn.prepare(
        "SELECT op_id, source_placement, dest_placement, kek_fingerprint, phase, created_at, updated_at
         FROM secret_vault_sagas
         WHERE phase != 'complete'
         ORDER BY created_at ASC, op_id ASC",
    )?;
    let rows = stmt.query_map([], map_saga_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing open secret vault sagas")
}

pub fn set_saga_phase_conn(
    conn: &rusqlite::Connection,
    op_id: &str,
    phase: SecretVaultSagaPhase,
) -> Result<()> {
    let now = Utc::now().timestamp();
    let n = conn
        .execute(
            "UPDATE secret_vault_sagas SET phase = ?1, updated_at = ?2 WHERE op_id = ?3",
            params![phase.as_str(), now, op_id],
        )
        .context("updating secret vault saga phase")?;
    if n == 0 {
        bail!("secret vault saga not found: {op_id}");
    }
    Ok(())
}

fn map_saga_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretVaultSagaRow> {
    let source: String = row.get(1)?;
    let dest: String = row.get(2)?;
    let phase: String = row.get(4)?;
    Ok(SecretVaultSagaRow {
        op_id: row.get(0)?,
        source_placement: SecretVaultPlacement::parse(&source).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        dest_placement: SecretVaultPlacement::parse(&dest).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        kek_fingerprint: row.get(3)?,
        phase: SecretVaultSagaPhase::parse(&phase).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

pub fn upsert_store_state_conn(
    conn: &rusqlite::Connection,
    store: SecretVaultStore,
    authoritative: SecretVaultStoreAuthority,
) -> Result<()> {
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO secret_vault_store_state (store, authoritative, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(store) DO UPDATE SET
            authoritative = excluded.authoritative,
            updated_at = excluded.updated_at",
        params![store.as_str(), authoritative.as_str(), now],
    )
    .context("upserting secret vault store state")?;
    Ok(())
}

pub fn load_store_state_conn(
    conn: &rusqlite::Connection,
    store: SecretVaultStore,
) -> Result<Option<SecretVaultStoreStateRow>> {
    conn.query_row(
        "SELECT store, authoritative, updated_at FROM secret_vault_store_state WHERE store = ?1",
        [store.as_str()],
        map_store_state_row,
    )
    .optional()
    .context("loading secret vault store state")
}

pub fn list_store_states_conn(
    conn: &rusqlite::Connection,
) -> Result<Vec<SecretVaultStoreStateRow>> {
    let mut stmt = conn.prepare(
        "SELECT store, authoritative, updated_at FROM secret_vault_store_state ORDER BY store ASC",
    )?;
    let rows = stmt.query_map([], map_store_state_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing secret vault store states")
}

fn map_store_state_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretVaultStoreStateRow> {
    let store: String = row.get(0)?;
    let authoritative: String = row.get(1)?;
    Ok(SecretVaultStoreStateRow {
        store: SecretVaultStore::parse(&store).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        authoritative: SecretVaultStoreAuthority::parse(&authoritative).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        updated_at: row.get(2)?,
    })
}

pub fn insert_import_saga_conn(
    conn: &rusqlite::Connection,
    op_id: &str,
    store: SecretVaultStore,
    phase: SecretVaultSagaPhase,
) -> Result<()> {
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO secret_vault_import_sagas (op_id, store, phase, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?4)",
        params![op_id, store.as_str(), phase.as_str(), now],
    )
    .context("inserting secret vault import saga")?;
    Ok(())
}

pub fn load_import_saga_conn(
    conn: &rusqlite::Connection,
    op_id: &str,
) -> Result<Option<SecretVaultImportSagaRow>> {
    conn.query_row(
        "SELECT op_id, store, phase, created_at, updated_at
         FROM secret_vault_import_sagas WHERE op_id = ?1",
        [op_id],
        map_import_saga_row,
    )
    .optional()
    .context("loading secret vault import saga")
}

pub fn load_import_saga_for_store_conn(
    conn: &rusqlite::Connection,
    store: SecretVaultStore,
) -> Result<Option<SecretVaultImportSagaRow>> {
    conn.query_row(
        "SELECT op_id, store, phase, created_at, updated_at
         FROM secret_vault_import_sagas
         WHERE store = ?1
         ORDER BY created_at DESC, op_id DESC
         LIMIT 1",
        [store.as_str()],
        map_import_saga_row,
    )
    .optional()
    .context("loading secret vault import saga for store")
}

pub fn list_open_import_sagas_conn(
    conn: &rusqlite::Connection,
) -> Result<Vec<SecretVaultImportSagaRow>> {
    let mut stmt = conn.prepare(
        "SELECT op_id, store, phase, created_at, updated_at
         FROM secret_vault_import_sagas
         WHERE phase != 'complete'
         ORDER BY created_at ASC, op_id ASC",
    )?;
    let rows = stmt.query_map([], map_import_saga_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing open secret vault import sagas")
}

pub fn set_import_saga_phase_conn(
    conn: &rusqlite::Connection,
    op_id: &str,
    phase: SecretVaultSagaPhase,
) -> Result<()> {
    let now = Utc::now().timestamp();
    let n = conn
        .execute(
            "UPDATE secret_vault_import_sagas SET phase = ?1, updated_at = ?2 WHERE op_id = ?3",
            params![phase.as_str(), now, op_id],
        )
        .context("updating secret vault import saga phase")?;
    if n == 0 {
        bail!("secret vault import saga not found: {op_id}");
    }
    Ok(())
}

fn map_import_saga_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretVaultImportSagaRow> {
    let store: String = row.get(1)?;
    let phase: String = row.get(2)?;
    Ok(SecretVaultImportSagaRow {
        op_id: row.get(0)?,
        store: SecretVaultStore::parse(&store).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        phase: SecretVaultSagaPhase::parse(&phase).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

pub fn set_unification_complete_conn(conn: &rusqlite::Connection, complete: bool) -> Result<()> {
    let now = Utc::now().timestamp();
    let n = conn
        .execute(
            "UPDATE secret_vault_authority SET unification_complete = ?1, updated_at = ?2 WHERE id = 1",
            params![if complete { 1 } else { 0 }, now],
        )
        .context("updating secret vault unification_complete")?;
    if n == 0 {
        bail!("secret vault authority missing");
    }
    Ok(())
}

pub fn all_stores_vault_authoritative_conn(conn: &rusqlite::Connection) -> Result<bool> {
    for store in SecretVaultStore::all() {
        match load_store_state_conn(conn, store)? {
            Some(row) if row.authoritative == SecretVaultStoreAuthority::Vault => {}
            _ => return Ok(false),
        }
    }
    Ok(true)
}

pub fn is_unique_constraint(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(info, _) => {
            info.code == rusqlite::ErrorCode::ConstraintViolation
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn secret_vault_authority_is_singleton() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_write_for_sync_maintenance(|conn| {
            upsert_authority_conn(
                conn,
                SecretVaultPlacement::Database,
                SecretVaultPlacement::Database,
                "abc",
                1,
                1,
                false,
            )?;
            let row = load_authority_conn(conn)?.expect("authority");
            assert_eq!(row.intent, SecretVaultPlacement::Database);
            assert_eq!(row.active_placement, SecretVaultPlacement::Database);
            assert!(!row.unification_complete);
            let err = conn.execute(
                "INSERT INTO secret_vault_authority
                    (id, intent, active_placement, kek_fingerprint, kek_version, wrap_version,
                     unification_complete, updated_at)
                 VALUES (2, 'database', 'database', 'x', 1, 1, 0, 0)",
                [],
            );
            assert!(err.is_err(), "id != 1 must fail");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn secret_vault_rejects_second_active_dek() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_write_for_sync_maintenance(|conn| {
            let nonce1 = [1u8; 12];
            let nonce2 = [2u8; 12];
            let wrapped = [9u8; 48];
            insert_key_conn(conn, 1, 1, &nonce1, &wrapped, true)?;
            let err = insert_key_conn(conn, 2, 1, &nonce2, &wrapped, true);
            assert!(err.is_err(), "second active DEK must fail");
            assert_eq!(count_active_keys_conn(conn)?, 1);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn secret_vault_tables_have_no_kek_or_dek_plaintext_columns() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_write_for_sync_maintenance(|conn| {
            for table in [
                "secret_vault_authority",
                "secret_vault_keys",
                "secret_vault_items",
                "secret_vault_sagas",
            ] {
                let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
                let cols: Vec<String> = stmt
                    .query_map([], |row| row.get::<_, String>(1))?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                for col in &cols {
                    let lower = col.to_ascii_lowercase();
                    assert_ne!(lower, "kek", "{table}.{col}");
                    assert_ne!(lower, "dek", "{table}.{col}");
                    assert!(!lower.contains("plaintext"), "{table}.{col}");
                }
            }
            Ok(())
        })
        .unwrap();
    }
}
