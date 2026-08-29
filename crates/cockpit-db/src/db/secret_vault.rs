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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecretVaultKind {
    SecureKeyRoot,
    SecureKeyManifest,
    SealedState,
    CredentialRecord,
    NamedSecret,
    /// Command-backed named secret: the encrypted payload holds ONLY the argv
    /// spec (non-secret metadata). The resolved output is never persisted. The
    /// kind is authenticated plaintext metadata, so inventory can distinguish a
    /// command secret from a literal `NamedSecret` without decrypting any
    /// literal value.
    Command,
    SubscriptionAck,
    SealedCompartment,
    SessionSealedValue,
    RedactionTable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVaultInventoryItem {
    pub kind: SecretVaultKind,
    pub item_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVaultInventoryPage {
    pub items: Vec<SecretVaultInventoryItem>,
    pub snapshot: String,
    pub total_entries: usize,
    pub has_more: bool,
}

impl SecretVaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecureKeyRoot => "secure_key_root",
            Self::SecureKeyManifest => "secure_key_manifest",
            Self::SealedState => "sealed_state",
            Self::CredentialRecord => "credential_record",
            Self::NamedSecret => "named_secret",
            Self::Command => "command_secret",
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
            "command_secret" => Ok(Self::Command),
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecretVaultItemRow {
    pub kind: SecretVaultKind,
    pub item_id: String,
    pub key_version: i64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Monotonic fence for this item. Unlike the inventory generation this
    /// does not change when a different owner item is mutated.
    pub revision: u64,
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

/// Verify the durable owner-inventory schema installed by the database
/// migration. Schema changes are migration-owned; vault operations must never
/// repair a live database with ad-hoc DDL while another process may be using
/// it.
pub fn ensure_inventory_generation_conn(conn: &rusqlite::Connection) -> Result<()> {
    for table in [
        "secret_vault_items",
        "secret_vault_item_revisions",
        "secret_vault_inventory_state",
    ] {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get::<_, i64>(0).map(|value| value != 0),
        )?;
        if !exists {
            bail!("secret vault schema is missing migrated table `{table}`");
        }
    }
    let has_revision = conn
        .prepare("PRAGMA table_info(secret_vault_items)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .any(|name| name == "revision");
    if !has_revision {
        bail!("secret vault schema is missing migrated column `revision`");
    }
    for trigger in [
        "secret_vault_inventory_insert_generation",
        "secret_vault_inventory_update_generation",
        "secret_vault_inventory_delete_generation",
    ] {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1)",
            [trigger],
            |row| row.get::<_, i64>(0).map(|value| value != 0),
        )?;
        if !exists {
            bail!("secret vault schema is missing migrated trigger `{trigger}`");
        }
    }
    Ok(())
}

pub fn inventory_generation_conn(conn: &rusqlite::Connection) -> Result<u64> {
    let generation: i64 = conn.query_row(
        "SELECT generation FROM secret_vault_inventory_state WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    u64::try_from(generation).context("secret vault inventory generation is invalid")
}

impl Db {
    pub async fn secret_vault_load_authority(&self) -> Result<Option<SecretVaultAuthorityRow>> {
        self.read(load_authority_conn).await
    }
}

pub fn load_authority_conn(conn: &rusqlite::Connection) -> Result<Option<SecretVaultAuthorityRow>> {
    conn.query_row(
        "SELECT intent, active_placement, kek_fingerprint, kek_version, wrap_version,
                updated_at
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
        updated_at: row.get(5)?,
    })
}

pub fn upsert_authority_conn(
    conn: &rusqlite::Connection,
    intent: SecretVaultPlacement,
    active_placement: SecretVaultPlacement,
    kek_fingerprint: &str,
    kek_version: i64,
    wrap_version: i64,
) -> Result<()> {
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO secret_vault_authority
            (id, intent, active_placement, kek_fingerprint, kek_version, wrap_version,
             updated_at)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(id) DO UPDATE SET
            intent = excluded.intent,
            active_placement = excluded.active_placement,
            kek_fingerprint = excluded.kek_fingerprint,
            kek_version = excluded.kek_version,
            wrap_version = excluded.wrap_version,
            updated_at = excluded.updated_at",
        params![
            intent.as_str(),
            active_placement.as_str(),
            kek_fingerprint,
            kek_version,
            wrap_version,
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
    with_immediate_transaction(conn, || {
        upsert_item_locked(conn, kind, item_id, key_version, nonce, ciphertext)
    })
}

fn upsert_item_locked(
    conn: &rusqlite::Connection,
    kind: SecretVaultKind,
    item_id: &str,
    key_version: i64,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<()> {
    let now = Utc::now().timestamp();
    let revision: i64 = conn
        .query_row(
            "SELECT revision FROM secret_vault_item_revisions
             WHERE kind = ?1 AND item_id = ?2",
            params![kind.as_str(), item_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0_i64)
        .checked_add(1)
        .context("vault item revision overflow")?;
    conn.execute(
        "INSERT INTO secret_vault_item_revisions (kind, item_id, revision)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(kind, item_id) DO UPDATE SET revision = excluded.revision",
        params![kind.as_str(), item_id, revision],
    )?;
    conn.execute(
        "INSERT INTO secret_vault_items
            (kind, item_id, key_version, nonce, ciphertext, created_at, updated_at, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)
         ON CONFLICT(kind, item_id) DO UPDATE SET
            key_version = excluded.key_version,
            nonce = excluded.nonce,
            ciphertext = excluded.ciphertext,
            updated_at = excluded.updated_at,
            revision = excluded.revision",
        params![
            kind.as_str(),
            item_id,
            key_version,
            nonce,
            ciphertext,
            now,
            revision
        ],
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
        "SELECT kind, item_id, key_version, nonce, ciphertext, created_at, updated_at, revision
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
    with_immediate_transaction(conn, || delete_item_locked(conn, kind, item_id))
}

fn delete_item_locked(
    conn: &rusqlite::Connection,
    kind: SecretVaultKind,
    item_id: &str,
) -> Result<bool> {
    let revision: i64 = conn
        .query_row(
            "SELECT revision FROM secret_vault_item_revisions
             WHERE kind = ?1 AND item_id = ?2",
            params![kind.as_str(), item_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0_i64)
        .checked_add(1)
        .context("vault item revision overflow")?;
    conn.execute(
        "INSERT INTO secret_vault_item_revisions (kind, item_id, revision)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(kind, item_id) DO UPDATE SET revision = excluded.revision",
        params![kind.as_str(), item_id, revision],
    )?;
    let n = conn
        .execute(
            "DELETE FROM secret_vault_items WHERE kind = ?1 AND item_id = ?2",
            params![kind.as_str(), item_id],
        )
        .context("deleting vault item")?;
    Ok(n > 0)
}

/// Serialize an item mutation while preserving callers that already own a
/// broader transaction (for example `mutate_item`).  Autocommit callers are
/// the important case here: a revision read followed by its write must not
/// be interleaved with another daemon/process mutating the same item.
fn with_immediate_transaction<T>(
    conn: &rusqlite::Connection,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let owns_transaction = conn.is_autocommit();
    if owns_transaction {
        conn.execute_batch("BEGIN IMMEDIATE;")
            .context("beginning secret vault item mutation")?;
    }
    let result = operation();
    match result {
        Ok(value) if owns_transaction => conn
            .execute_batch("COMMIT;")
            .context("committing secret vault item mutation")
            .map(|()| value),
        Ok(value) => Ok(value),
        Err(error) => {
            if owns_transaction {
                let _ = conn.execute_batch("ROLLBACK;");
            }
            Err(error)
        }
    }
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

/// Return a bounded, keyset-paginated owner inventory. The caller supplies a
/// reliable mutation-generation token; this function only performs a bounded
/// overflow probe and never loads or aggregates the full inventory.
pub fn list_inventory_page_conn(
    conn: &rusqlite::Connection,
    after: Option<(&str, &str)>,
    limit: usize,
    max_total_entries: usize,
) -> Result<SecretVaultInventoryPage> {
    if limit == 0 {
        bail!("inventory page limit must be positive");
    }
    if max_total_entries == 0 {
        bail!("inventory total bound must be positive");
    }
    // The generation token, bounded overflow probe, and page rows must all
    // come from one SQLite snapshot.  A read pool connection may otherwise
    // observe a trigger writer between any two of those statements.  An
    // explicit deferred transaction establishes the snapshot at the first
    // read and keeps it until the page is complete.
    conn.execute_batch("BEGIN DEFERRED;")
        .context("beginning secret vault inventory read transaction")?;
    let result = list_inventory_page_snapshot_conn(conn, after, limit, max_total_entries);
    match result {
        Ok(page) => {
            if let Err(error) = conn.execute_batch("COMMIT;") {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(error).context("committing secret vault inventory read transaction")
            } else {
                Ok(page)
            }
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(error)
        }
    }
}

fn list_inventory_page_snapshot_conn(
    conn: &rusqlite::Connection,
    after: Option<(&str, &str)>,
    limit: usize,
    max_total_entries: usize,
) -> Result<SecretVaultInventoryPage> {
    let generation = inventory_generation_conn(conn)?;
    // Count only up to the advertised hard bound plus one. This is an
    // overflow probe, not an unbounded aggregate scan; the caller rejects
    // the page when the extra row is present.
    let mut count_stmt = conn.prepare(
        "SELECT 1
         FROM secret_vault_items
         WHERE kind IN ('named_secret', 'credential_record', 'subscription_ack')
         LIMIT ?1",
    )?;
    let mut count_rows = count_stmt.query([i64::try_from(max_total_entries + 1)?])?;
    let mut total_entries = 0usize;
    while count_rows.next()?.is_some() {
        total_entries += 1;
    }
    let (after_kind, after_item) = after
        .map(|(kind, item)| (Some(kind), Some(item)))
        .unwrap_or((None, None));
    let mut stmt = conn.prepare(
        "SELECT kind, item_id
         FROM secret_vault_items
         WHERE kind IN ('named_secret', 'credential_record', 'subscription_ack')
           AND (
             ?1 IS NULL
             OR item_id > ?2
             OR (item_id = ?2 AND kind > ?3)
           )
         ORDER BY item_id ASC, kind ASC
         LIMIT ?4",
    )?;
    let mut rows = stmt.query(rusqlite::params![
        after_item,
        after_item,
        after_kind,
        i64::try_from(limit.saturating_add(1)).context("inventory page limit overflow")?,
    ])?;
    let mut items = Vec::with_capacity(limit.min(128));
    while let Some(row) = rows.next()? {
        items.push(SecretVaultInventoryItem {
            kind: SecretVaultKind::parse(&row.get::<_, String>(0)?)?,
            item_id: row.get(1)?,
        });
    }
    let has_more = items.len() > limit;
    if has_more {
        items.truncate(limit);
    }
    Ok(SecretVaultInventoryPage {
        items,
        snapshot: generation.to_string(),
        total_entries,
        has_more,
    })
}

pub fn list_items_conn(conn: &rusqlite::Connection) -> Result<Vec<SecretVaultItemRow>> {
    let mut stmt = conn.prepare(
        "SELECT kind, item_id, key_version, nonce, ciphertext, created_at, updated_at, revision
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
        revision: u64::try_from(row.get::<_, i64>(7)?).map_err(|_| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Integer,
                Box::new(std::io::Error::other("negative vault item revision")),
            )
        })?,
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
            )?;
            let row = load_authority_conn(conn)?.expect("authority");
            assert_eq!(row.intent, SecretVaultPlacement::Database);
            assert_eq!(row.active_placement, SecretVaultPlacement::Database);
            let err = conn.execute(
                "INSERT INTO secret_vault_authority
                    (id, intent, active_placement, kek_fingerprint, kek_version, wrap_version,
                     updated_at)
                 VALUES (2, 'database', 'database', 'x', 1, 1, 0)",
                [],
            );
            assert!(err.is_err(), "id != 1 must fail");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn command_kind_round_trips_and_is_storable() {
        // The distinct command_secret kind must serialize, parse, and pass the
        // 0001 CHECK constraint. A missing CHECK arm would make the insert fail.
        assert_eq!(SecretVaultKind::Command.as_str(), "command_secret");
        assert_eq!(
            SecretVaultKind::parse("command_secret").unwrap(),
            SecretVaultKind::Command
        );
        let db = Db::open_in_memory().unwrap();
        db.blocking_write_for_sync_maintenance(|conn| {
            insert_key_conn(conn, 1, 1, &[5u8; 12], &[6u8; 48], true)?;
            upsert_item_conn(conn, SecretVaultKind::Command, "cmd", 1, &[7; 12], &[0; 16])?;
            let row = load_item_conn(conn, SecretVaultKind::Command, "cmd")?
                .expect("stored command_secret row");
            assert_eq!(row.kind, SecretVaultKind::Command);
            // A literal named secret with the same id is a DIFFERENT item, so a
            // command spec never shadows or is shadowed by a literal.
            assert!(load_item_conn(conn, SecretVaultKind::NamedSecret, "cmd")?.is_none());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn command_kind_mutation_does_not_advance_inventory_generation() {
        // command_secret is storage-only until its wire kind + inventory read
        // path land together (inc4). Because nothing can enumerate it yet, its
        // mutations must NOT advance the durable inventory cursor — otherwise an
        // invisible kind would churn the inventory version / conflict paginated
        // reads. A literal named_secret write in the same test proves the
        // trigger is otherwise live.
        let db = Db::open_in_memory().unwrap();
        db.blocking_write_for_sync_maintenance(|conn| {
            ensure_inventory_generation_conn(conn)?;
            insert_key_conn(conn, 1, 1, &[3u8; 12], &[4u8; 48], true)?;
            let before = inventory_generation_conn(conn)?;
            upsert_item_conn(conn, SecretVaultKind::Command, "cmd", 1, &[8; 12], &[1; 16])?;
            assert_eq!(
                inventory_generation_conn(conn)?,
                before,
                "a command-secret mutation must not advance the inventory cursor in inc1"
            );
            // Control: a literal named-secret mutation DOES advance it, proving
            // the trigger is live and the command_secret exclusion is deliberate.
            upsert_item_conn(
                conn,
                SecretVaultKind::NamedSecret,
                "lit",
                1,
                &[9; 12],
                &[2; 16],
            )?;
            assert!(inventory_generation_conn(conn)? > before);
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
    fn inventory_generation_is_durable_and_tracks_direct_writes() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_write_for_sync_maintenance(|conn| {
            ensure_inventory_generation_conn(conn)?;
            let before = inventory_generation_conn(conn)?;
            let nonce = [7u8; 12];
            let wrapped = [9u8; 48];
            insert_key_conn(conn, 1, 1, &nonce, &wrapped, true)?;
            // Simulate a writer that bypasses SecretVault but uses the shared
            // SQLite database: the durable trigger must still invalidate a
            // cursor held by another daemon process.
            upsert_item_conn(
                conn,
                SecretVaultKind::NamedSecret,
                "direct",
                1,
                &[8; 12],
                &[0; 16],
            )?;
            let after_insert = inventory_generation_conn(conn)?;
            assert!(after_insert > before);
            conn.execute(
                "DELETE FROM secret_vault_items WHERE kind = 'named_secret' AND item_id = 'direct'",
                [],
            )?;
            assert!(inventory_generation_conn(conn)? > after_insert);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn inventory_page_keeps_generation_and_rows_on_one_sqlite_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let db = Db::open(&path).unwrap();
        db.blocking_write_for_sync_maintenance(|conn| {
            ensure_inventory_generation_conn(conn)?;
            insert_key_conn(conn, 1, 1, &[9; 12], &[8; 48], true)?;
            upsert_item_conn(
                conn,
                SecretVaultKind::NamedSecret,
                "before",
                1,
                &[1; 12],
                &[2; 16],
            )?;
            Ok(())
        })
        .unwrap();

        // Model a second daemon process with independent SQLite connections.
        // The reader starts its snapshot before the writer commits a new
        // inventory row, then runs the same bounded generation/count/page
        // sequence used by list_inventory_page_conn.
        let reader = rusqlite::Connection::open(&path).unwrap();
        reader
            .execute_batch("PRAGMA busy_timeout = 5000; BEGIN DEFERRED;")
            .unwrap();
        let generation_before = inventory_generation_conn(&reader).unwrap();
        let writer = rusqlite::Connection::open(&path).unwrap();
        writer.execute_batch("PRAGMA busy_timeout = 5000;").unwrap();
        upsert_item_conn(
            &writer,
            SecretVaultKind::NamedSecret,
            "after",
            1,
            &[3; 12],
            &[4; 16],
        )
        .unwrap();

        let page = list_inventory_page_snapshot_conn(&reader, None, 10, 10).unwrap();
        assert_eq!(page.snapshot, generation_before.to_string());
        assert_eq!(page.total_entries, 1);
        assert_eq!(
            page.items
                .iter()
                .map(|item| item.item_id.as_str())
                .collect::<Vec<_>>(),
            vec!["before"]
        );
        reader.execute_batch("ROLLBACK;").unwrap();
    }

    #[test]
    fn same_item_revision_allocation_is_atomic_across_connections() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("vault.db");
        let db = Db::open(&path).unwrap();
        db.blocking_write_for_sync_maintenance(ensure_inventory_generation_conn)
            .unwrap();
        drop(db);

        let left = rusqlite::Connection::open(&path).unwrap();
        let right = rusqlite::Connection::open(&path).unwrap();
        left.execute_batch("PRAGMA busy_timeout = 5000;").unwrap();
        right.execute_batch("PRAGMA busy_timeout = 5000;").unwrap();
        insert_key_conn(&left, 1, 1, &[9; 12], &[8; 48], true).unwrap();
        let start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let left_start = std::sync::Arc::clone(&start);
        let right_start = std::sync::Arc::clone(&start);
        let left_thread = std::thread::spawn(move || {
            left_start.wait();
            upsert_item_conn(
                &left,
                SecretVaultKind::NamedSecret,
                "same-item",
                1,
                &[1; 12],
                &[2; 16],
            )
        });
        let right_thread = std::thread::spawn(move || {
            right_start.wait();
            upsert_item_conn(
                &right,
                SecretVaultKind::NamedSecret,
                "same-item",
                1,
                &[3; 12],
                &[4; 16],
            )
        });
        left_thread.join().unwrap().unwrap();
        right_thread.join().unwrap().unwrap();

        let reader = rusqlite::Connection::open(&path).unwrap();
        let item = load_item_conn(&reader, SecretVaultKind::NamedSecret, "same-item")
            .unwrap()
            .expect("same-item row");
        let revision: i64 = reader
            .query_row(
                "SELECT revision FROM secret_vault_item_revisions
                 WHERE kind = 'named_secret' AND item_id = 'same-item'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(item.revision, 2);
        assert_eq!(revision, 2);
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

    #[test]
    fn vault_schema_lives_only_in_0001() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/db/migrations");
        let mut saw_initial = false;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".sql") {
                continue;
            }
            let sql = std::fs::read_to_string(entry.path()).unwrap();
            if name == "0001_initial.sql" {
                saw_initial = true;
                assert!(sql.contains("CREATE TABLE secret_vault_authority"));
                assert!(sql.contains("CREATE TABLE secret_vault_keys"));
                assert!(sql.contains("CREATE TABLE secret_vault_items"));
                assert!(sql.contains("CREATE TABLE secret_vault_sagas"));
                assert!(
                    !sql.contains(&format!("{}{}", "secret_vault_store", "_state")),
                    "0001 must not define leftover dual-store tables"
                );
                assert!(
                    !sql.contains(&format!("{}{}", "secret_vault_import", "_sagas")),
                    "0001 must not define leftover import sagas"
                );
            } else {
                assert!(
                    !sql.contains("secret_vault_"),
                    "{name} must not define vault objects"
                );
                assert!(
                    !name.contains("0004") && !name.contains("0005"),
                    "folded vault migrations must not remain on disk: {name}"
                );
            }
        }
        assert!(saw_initial, "0001_initial.sql must exist");
    }

    #[test]
    fn sealed_values_value_is_nullable_in_0001() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_write_for_sync_maintenance(|conn| {
            conn.execute(
                "INSERT INTO sessions (session_id, project_id, project_root, started_at_unix_ms, last_active_at_unix_ms)
                 VALUES ('00000000-0000-4000-8000-000000000001', 'p', '/p', 1, 1)",
                [],
            )?;
            conn.execute(
                "INSERT INTO sealed_values (session_id, value_id, value, reason, origin, created_at)
                 VALUES ('00000000-0000-4000-8000-000000000001', 'v', NULL, 'r', 'user', 1)",
                [],
            )?;
            let stored: Option<String> = conn.query_row(
                "SELECT value FROM sealed_values WHERE session_id = '00000000-0000-4000-8000-000000000001' AND value_id = 'v'",
                [],
                |row| row.get(0),
            )?;
            assert!(stored.is_none(), "fresh 0001 must accept a NULL sealed value");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn unification_tables_do_not_exist() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_write_for_sync_maintenance(|conn| {
            let mut stmt =
                conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
            let tables: Vec<String> = stmt
                .query_map([], |row| row.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let leftover_state = format!("{}{}", "secret_vault_store", "_state");
            let leftover_import = format!("{}{}", "secret_vault_import", "_sagas");
            assert!(
                !tables.iter().any(|name| name == &leftover_state),
                "folded schema must not create {leftover_state}"
            );
            assert!(
                !tables.iter().any(|name| name == &leftover_import),
                "folded schema must not create {leftover_import}"
            );
            let mut info = conn.prepare("PRAGMA table_info(secret_vault_authority)")?;
            let cols: Vec<String> = info
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let leftover_col = format!("{}{}", "unification", "_complete");
            assert!(
                !cols.iter().any(|col| col == &leftover_col),
                "authority must not keep {leftover_col}"
            );
            Ok(())
        })
        .unwrap();
    }
}
