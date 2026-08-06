//! SQLite coordination for the daemon-owned native secure key store.
//!
//! Key bytes never live here — only version/saga/reference metadata and safe
//! digests. Consumer ciphertext tables integrate via transaction-scoped
//! reference methods on the same connection.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// Lifecycle of a coordinated key version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureKeyVersionState {
    Pending,
    Active,
    Retained,
    Retiring,
    Retired,
}

impl SecureKeyVersionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Active => "Active",
            Self::Retained => "Retained",
            Self::Retiring => "Retiring",
            Self::Retired => "Retired",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "Pending" => Ok(Self::Pending),
            "Active" => Ok(Self::Active),
            "Retained" => Ok(Self::Retained),
            "Retiring" => Ok(Self::Retiring),
            "Retired" => Ok(Self::Retired),
            other => bail!("unknown secure key version state: {other}"),
        }
    }

    /// Whether new consumer reservations are allowed.
    pub fn allows_reservation(self) -> bool {
        matches!(self, Self::Active | Self::Retained)
    }
}

/// Cross-store saga kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureKeySagaKind {
    Provision,
    Retire,
}

impl SecureKeySagaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provision => "Provision",
            Self::Retire => "Retire",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "Provision" => Ok(Self::Provision),
            "Retire" => Ok(Self::Retire),
            other => bail!("unknown secure key saga kind: {other}"),
        }
    }
}

/// Provision saga phases (persisted, idempotently resumed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionPhase {
    Prepared,
    NativeItemWritten,
    NativeItemVerified,
    ManifestAdvancedAndVerified,
    MetadataActivated,
    Committed,
}

impl ProvisionPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "Prepared",
            Self::NativeItemWritten => "NativeItemWritten",
            Self::NativeItemVerified => "NativeItemVerified",
            Self::ManifestAdvancedAndVerified => "ManifestAdvancedAndVerified",
            Self::MetadataActivated => "MetadataActivated",
            Self::Committed => "Committed",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "Prepared" => Ok(Self::Prepared),
            "NativeItemWritten" => Ok(Self::NativeItemWritten),
            "NativeItemVerified" => Ok(Self::NativeItemVerified),
            "ManifestAdvancedAndVerified" => Ok(Self::ManifestAdvancedAndVerified),
            "MetadataActivated" => Ok(Self::MetadataActivated),
            "Committed" => Ok(Self::Committed),
            other => bail!("unknown provision phase: {other}"),
        }
    }
}

/// Retirement saga phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetirePhase {
    Prepared,
    NativeItemDeletedAndVerifiedAbsent,
    ManifestRetiredAndVerified,
    MetadataRetired,
    Committed,
}

impl RetirePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "Prepared",
            Self::NativeItemDeletedAndVerifiedAbsent => "NativeItemDeletedAndVerifiedAbsent",
            Self::ManifestRetiredAndVerified => "ManifestRetiredAndVerified",
            Self::MetadataRetired => "MetadataRetired",
            Self::Committed => "Committed",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "Prepared" => Ok(Self::Prepared),
            "NativeItemDeletedAndVerifiedAbsent" => Ok(Self::NativeItemDeletedAndVerifiedAbsent),
            "ManifestRetiredAndVerified" => Ok(Self::ManifestRetiredAndVerified),
            "MetadataRetired" => Ok(Self::MetadataRetired),
            "Committed" => Ok(Self::Committed),
            other => bail!("unknown retire phase: {other}"),
        }
    }
}

/// Consumer reference lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureKeyRefState {
    Reserved,
    Active,
    Releasing,
    Released,
}

impl SecureKeyRefState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "Reserved",
            Self::Active => "Active",
            Self::Releasing => "Releasing",
            Self::Released => "Released",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "Reserved" => Ok(Self::Reserved),
            "Active" => Ok(Self::Active),
            "Releasing" => Ok(Self::Releasing),
            "Released" => Ok(Self::Released),
            other => bail!("unknown secure key ref state: {other}"),
        }
    }

    pub fn blocks_retirement(self) -> bool {
        matches!(self, Self::Reserved | Self::Active | Self::Releasing)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureKeyNamespaceRow {
    pub namespace: String,
    pub active_version: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureKeyVersionRow {
    pub namespace: String,
    pub version: i64,
    pub state: SecureKeyVersionState,
    pub key_digest: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureKeySagaRow {
    pub op_id: String,
    pub namespace: String,
    pub kind: SecureKeySagaKind,
    pub version: i64,
    pub phase: String,
    pub key_digest: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Exact consumer reference tuple (no key material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureKeyConsumerRef {
    pub reference_id: String,
    pub namespace: String,
    pub version: i64,
    pub consumer_kind: String,
    pub consumer_id: String,
    pub state: SecureKeyRefState,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Safe metadata for InUse retirement failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureKeyInUseInfo {
    pub namespace: String,
    pub version: i64,
    pub blocking_refs: Vec<SecureKeyConsumerRef>,
}

/// Outcome of attempting retirement Prepared CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetirePrepareResult {
    Prepared {
        op_id: String,
    },
    InUse(SecureKeyInUseInfo),
    AlreadyRetiring {
        op_id: String,
    },
    AlreadyRetired,
    ActiveVersion,
    NotFound,
    /// Retiring without an open retire saga — unexplained residue.
    CorruptResidue,
}

/// Outcome of reservation CAS against Retiring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveResult {
    Reserved(SecureKeyConsumerRef),
    Idempotent(SecureKeyConsumerRef),
    Retiring,
    NotReservable { state: SecureKeyVersionState },
    NotFound,
    Conflict,
}

impl Db {
    pub async fn secure_key_list_open_sagas(&self) -> Result<Vec<SecureKeySagaRow>> {
        self.read(list_open_sagas_conn).await
    }
}

// ---- Namespace / version helpers (connection-scoped) -----------------------

pub fn ensure_namespace_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
) -> Result<SecureKeyNamespaceRow> {
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO secure_key_namespaces (namespace, active_version, created_at, updated_at)
         VALUES (?1, NULL, ?2, ?2)
         ON CONFLICT(namespace) DO NOTHING",
        params![namespace, now],
    )
    .context("ensuring secure key namespace")?;
    get_namespace_conn(conn, namespace)?
        .with_context(|| format!("namespace missing after ensure: {namespace}"))
}

pub fn get_namespace_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
) -> Result<Option<SecureKeyNamespaceRow>> {
    conn.query_row(
        "SELECT namespace, active_version, created_at, updated_at
         FROM secure_key_namespaces WHERE namespace = ?1",
        [namespace],
        |row| {
            Ok(SecureKeyNamespaceRow {
                namespace: row.get(0)?,
                active_version: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
            })
        },
    )
    .optional()
    .context("loading secure key namespace")
}

pub fn list_namespaces_conn(conn: &rusqlite::Connection) -> Result<Vec<SecureKeyNamespaceRow>> {
    let mut stmt = conn.prepare(
        "SELECT namespace, active_version, created_at, updated_at
         FROM secure_key_namespaces ORDER BY namespace ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(SecureKeyNamespaceRow {
            namespace: row.get(0)?,
            active_version: row.get(1)?,
            created_at: row.get(2)?,
            updated_at: row.get(3)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing secure key namespaces")
}

pub fn list_versions_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
) -> Result<Vec<SecureKeyVersionRow>> {
    let mut stmt = conn.prepare(
        "SELECT namespace, version, state, key_digest, created_at, updated_at
         FROM secure_key_versions WHERE namespace = ?1 ORDER BY version ASC",
    )?;
    let rows = stmt.query_map([namespace], map_version_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing secure key versions")
}

pub fn get_version_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
    version: i64,
) -> Result<Option<SecureKeyVersionRow>> {
    conn.query_row(
        "SELECT namespace, version, state, key_digest, created_at, updated_at
         FROM secure_key_versions WHERE namespace = ?1 AND version = ?2",
        params![namespace, version],
        map_version_row,
    )
    .optional()
    .context("loading secure key version")
}

fn map_version_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecureKeyVersionRow> {
    let state: String = row.get(2)?;
    Ok(SecureKeyVersionRow {
        namespace: row.get(0)?,
        version: row.get(1)?,
        state: SecureKeyVersionState::parse(&state).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        key_digest: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

/// Next monotonic version for a namespace (max+1, or 1).
pub fn next_version_number_conn(conn: &rusqlite::Connection, namespace: &str) -> Result<i64> {
    let max: Option<i64> = conn
        .query_row(
            "SELECT MAX(version) FROM secure_key_versions WHERE namespace = ?1",
            [namespace],
            |row| row.get(0),
        )
        .context("reading max secure key version")?;
    Ok(max.unwrap_or(0) + 1)
}

// ---- Provision prepare / phase advance -------------------------------------

/// Persist Prepared provision: reserve next version as Pending + saga row.
pub fn prepare_provision_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
    key_digest: &str,
) -> Result<(String, i64)> {
    ensure_namespace_conn(conn, namespace)?;
    let version = next_version_number_conn(conn, namespace)?;
    let op_id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO secure_key_versions
            (namespace, version, state, key_digest, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![
            namespace,
            version,
            SecureKeyVersionState::Pending.as_str(),
            key_digest,
            now
        ],
    )
    .context("inserting pending secure key version")?;
    conn.execute(
        "INSERT INTO secure_key_sagas
            (op_id, namespace, kind, version, phase, key_digest, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![
            op_id,
            namespace,
            SecureKeySagaKind::Provision.as_str(),
            version,
            ProvisionPhase::Prepared.as_str(),
            key_digest,
            now
        ],
    )
    .context("inserting provision saga")?;
    Ok((op_id, version))
}

pub fn set_saga_phase_conn(conn: &rusqlite::Connection, op_id: &str, phase: &str) -> Result<()> {
    let now = Utc::now().timestamp();
    let n = conn
        .execute(
            "UPDATE secure_key_sagas SET phase = ?1, updated_at = ?2 WHERE op_id = ?3",
            params![phase, now, op_id],
        )
        .context("updating secure key saga phase")?;
    if n == 0 {
        bail!("secure key saga not found: {op_id}");
    }
    Ok(())
}

pub fn get_saga_conn(conn: &rusqlite::Connection, op_id: &str) -> Result<Option<SecureKeySagaRow>> {
    conn.query_row(
        "SELECT op_id, namespace, kind, version, phase, key_digest, created_at, updated_at
         FROM secure_key_sagas WHERE op_id = ?1",
        [op_id],
        map_saga_row,
    )
    .optional()
    .context("loading secure key saga")
}

fn map_saga_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecureKeySagaRow> {
    let kind: String = row.get(2)?;
    Ok(SecureKeySagaRow {
        op_id: row.get(0)?,
        namespace: row.get(1)?,
        kind: SecureKeySagaKind::parse(&kind).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        version: row.get(3)?,
        phase: row.get(4)?,
        key_digest: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

pub fn list_open_sagas_conn(conn: &rusqlite::Connection) -> Result<Vec<SecureKeySagaRow>> {
    let mut stmt = conn.prepare(
        "SELECT op_id, namespace, kind, version, phase, key_digest, created_at, updated_at
         FROM secure_key_sagas
         WHERE phase != 'Committed'
         ORDER BY created_at ASC, op_id ASC",
    )?;
    let rows = stmt.query_map([], map_saga_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing open secure key sagas")
}

/// Activate version metadata: Pending -> Active (or first active); demote prior Active to Retained.
pub fn activate_version_metadata_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
    version: i64,
) -> Result<()> {
    let now = Utc::now().timestamp();
    let prior = get_namespace_conn(conn, namespace)?.and_then(|ns| ns.active_version);
    if let Some(prev) = prior
        && prev != version
    {
        conn.execute(
            "UPDATE secure_key_versions SET state = ?1, updated_at = ?2
             WHERE namespace = ?3 AND version = ?4 AND state = ?5",
            params![
                SecureKeyVersionState::Retained.as_str(),
                now,
                namespace,
                prev,
                SecureKeyVersionState::Active.as_str()
            ],
        )
        .context("retaining prior active version")?;
    }
    let n = conn
        .execute(
            "UPDATE secure_key_versions SET state = ?1, updated_at = ?2
             WHERE namespace = ?3 AND version = ?4 AND state = ?5",
            params![
                SecureKeyVersionState::Active.as_str(),
                now,
                namespace,
                version,
                SecureKeyVersionState::Pending.as_str()
            ],
        )
        .context("activating secure key version")?;
    if n == 0 {
        // Idempotent if already Active.
        let row = get_version_conn(conn, namespace, version)?;
        match row.map(|r| r.state) {
            Some(SecureKeyVersionState::Active) => {}
            other => bail!("cannot activate version {version} in {namespace}: state={other:?}"),
        }
    }
    conn.execute(
        "UPDATE secure_key_namespaces SET active_version = ?1, updated_at = ?2
         WHERE namespace = ?3",
        params![version, now, namespace],
    )
    .context("setting namespace active version")?;
    Ok(())
}

pub fn delete_saga_conn(conn: &rusqlite::Connection, op_id: &str) -> Result<()> {
    conn.execute("DELETE FROM secure_key_sagas WHERE op_id = ?1", [op_id])
        .context("deleting secure key saga")?;
    Ok(())
}

pub fn mark_saga_committed_conn(conn: &rusqlite::Connection, op_id: &str) -> Result<()> {
    set_saga_phase_conn(conn, op_id, ProvisionPhase::Committed.as_str())?;
    // Keep Committed rows briefly for diagnostics; drop after phase set.
    // Spec: Committed is terminal; removing the row is fine for hygiene.
    delete_saga_conn(conn, op_id)
}

// ---- Retirement ------------------------------------------------------------

pub fn prepare_retire_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
    version: i64,
) -> Result<RetirePrepareResult> {
    let Some(row) = get_version_conn(conn, namespace, version)? else {
        return Ok(RetirePrepareResult::NotFound);
    };
    match row.state {
        SecureKeyVersionState::Active => return Ok(RetirePrepareResult::ActiveVersion),
        SecureKeyVersionState::Retired => return Ok(RetirePrepareResult::AlreadyRetired),
        SecureKeyVersionState::Retiring => {
            if let Some(saga) = find_open_retire_saga_conn(conn, namespace, version)? {
                return Ok(RetirePrepareResult::AlreadyRetiring { op_id: saga.op_id });
            }
            // Retiring without an open retire saga is unexplained residue → Corrupt.
            return Ok(RetirePrepareResult::CorruptResidue);
        }
        SecureKeyVersionState::Retained => {}
        SecureKeyVersionState::Pending => return Ok(RetirePrepareResult::NotFound),
    }

    let blocking = list_blocking_refs_conn(conn, namespace, version)?;
    if !blocking.is_empty() {
        return Ok(RetirePrepareResult::InUse(SecureKeyInUseInfo {
            namespace: namespace.to_owned(),
            version,
            blocking_refs: blocking,
        }));
    }

    let op_id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    if row.state == SecureKeyVersionState::Retained {
        let n = conn
            .execute(
                "UPDATE secure_key_versions SET state = ?1, updated_at = ?2
                 WHERE namespace = ?3 AND version = ?4 AND state = ?5",
                params![
                    SecureKeyVersionState::Retiring.as_str(),
                    now,
                    namespace,
                    version,
                    SecureKeyVersionState::Retained.as_str()
                ],
            )
            .context("CAS version to Retiring")?;
        if n == 0 {
            let again = get_version_conn(conn, namespace, version)?;
            return match again.map(|r| r.state) {
                Some(SecureKeyVersionState::Retiring) => {
                    if let Some(saga) = find_open_retire_saga_conn(conn, namespace, version)? {
                        Ok(RetirePrepareResult::AlreadyRetiring { op_id: saga.op_id })
                    } else {
                        insert_retire_saga_conn(conn, &op_id, namespace, version, now)?;
                        Ok(RetirePrepareResult::Prepared { op_id })
                    }
                }
                Some(SecureKeyVersionState::Retired) => Ok(RetirePrepareResult::AlreadyRetired),
                Some(SecureKeyVersionState::Active) => Ok(RetirePrepareResult::ActiveVersion),
                _ => {
                    let blocking = list_blocking_refs_conn(conn, namespace, version)?;
                    if !blocking.is_empty() {
                        Ok(RetirePrepareResult::InUse(SecureKeyInUseInfo {
                            namespace: namespace.to_owned(),
                            version,
                            blocking_refs: blocking,
                        }))
                    } else {
                        Ok(RetirePrepareResult::NotFound)
                    }
                }
            };
        }
    }
    // Retained CAS succeeded, or already Retiring without saga.
    insert_retire_saga_conn(conn, &op_id, namespace, version, now)?;
    Ok(RetirePrepareResult::Prepared { op_id })
}

fn insert_retire_saga_conn(
    conn: &rusqlite::Connection,
    op_id: &str,
    namespace: &str,
    version: i64,
    now: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO secure_key_sagas
            (op_id, namespace, kind, version, phase, key_digest, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?6)",
        params![
            op_id,
            namespace,
            SecureKeySagaKind::Retire.as_str(),
            version,
            RetirePhase::Prepared.as_str(),
            now
        ],
    )
    .context("inserting retire saga")?;
    Ok(())
}

fn find_open_retire_saga_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
    version: i64,
) -> Result<Option<SecureKeySagaRow>> {
    conn.query_row(
        "SELECT op_id, namespace, kind, version, phase, key_digest, created_at, updated_at
         FROM secure_key_sagas
         WHERE namespace = ?1 AND version = ?2 AND kind = ?3 AND phase != 'Committed'
         ORDER BY created_at ASC LIMIT 1",
        params![namespace, version, SecureKeySagaKind::Retire.as_str()],
        map_saga_row,
    )
    .optional()
    .context("finding open retire saga")
}

pub fn mark_version_retired_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
    version: i64,
) -> Result<()> {
    let now = Utc::now().timestamp();
    conn.execute(
        "UPDATE secure_key_versions SET state = ?1, updated_at = ?2
         WHERE namespace = ?3 AND version = ?4",
        params![
            SecureKeyVersionState::Retired.as_str(),
            now,
            namespace,
            version
        ],
    )
    .context("marking version retired")?;
    Ok(())
}

// ---- Consumer references ---------------------------------------------------

pub fn list_blocking_refs_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
    version: i64,
) -> Result<Vec<SecureKeyConsumerRef>> {
    let mut stmt = conn.prepare(
        "SELECT reference_id, namespace, version, consumer_kind, consumer_id, state,
                created_at, updated_at
         FROM secure_key_consumer_refs
         WHERE namespace = ?1 AND version = ?2
           AND state IN ('Reserved', 'Active', 'Releasing')
         ORDER BY created_at ASC, reference_id ASC",
    )?;
    let rows = stmt.query_map(params![namespace, version], map_ref_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing blocking consumer refs")
}

fn map_ref_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecureKeyConsumerRef> {
    let state: String = row.get(5)?;
    Ok(SecureKeyConsumerRef {
        reference_id: row.get(0)?,
        namespace: row.get(1)?,
        version: row.get(2)?,
        consumer_kind: row.get(3)?,
        consumer_id: row.get(4)?,
        state: SecureKeyRefState::parse(&state).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

/// Reserve a consumer reference. Idempotent only for the same full tuple.
///
/// Released rows are re-armable only for the sealed_state consumer kind (dual-slot
/// key retention may re-pin after SQLite rollback). All other consumers treat
/// Released as terminal for that reference_id.
pub fn reserve_consumer_ref_conn(
    conn: &rusqlite::Connection,
    reference_id: &str,
    namespace: &str,
    version: i64,
    consumer_kind: &str,
    consumer_id: &str,
) -> Result<ReserveResult> {
    let Some(ver) = get_version_conn(conn, namespace, version)? else {
        return Ok(ReserveResult::NotFound);
    };

    let sealed_rearm = consumer_kind == SEALED_STATE_CONSUMER_KIND;

    // Idempotent same-tuple first (even if version is now Retiring/Retired).
    if let Some(existing) = get_ref_by_id_conn(conn, reference_id)? {
        if existing.namespace == namespace
            && existing.version == version
            && existing.consumer_kind == consumer_kind
            && existing.consumer_id == consumer_id
        {
            if existing.state == SecureKeyRefState::Released && sealed_rearm {
                conn.execute(
                    "DELETE FROM secure_key_consumer_refs WHERE reference_id = ?1 AND state = ?2",
                    params![reference_id, SecureKeyRefState::Released.as_str()],
                )
                .context("clearing released sealed-state ref for re-reserve")?;
            } else {
                // Active/Reserved/Releasing: idempotent. Non-sealed Released: terminal.
                return Ok(ReserveResult::Idempotent(existing));
            }
        } else {
            return Ok(ReserveResult::Conflict);
        }
    }
    if let Some(existing) =
        get_ref_by_tuple_conn(conn, namespace, version, consumer_kind, consumer_id)?
    {
        if existing.reference_id == reference_id {
            if existing.state == SecureKeyRefState::Released && sealed_rearm {
                conn.execute(
                    "DELETE FROM secure_key_consumer_refs WHERE reference_id = ?1 AND state = ?2",
                    params![reference_id, SecureKeyRefState::Released.as_str()],
                )
                .context("clearing released sealed-state ref for re-reserve")?;
            } else {
                return Ok(ReserveResult::Idempotent(existing));
            }
        } else if existing.state != SecureKeyRefState::Released {
            return Ok(ReserveResult::Conflict);
        } else if sealed_rearm {
            conn.execute(
                "DELETE FROM secure_key_consumer_refs WHERE reference_id = ?1 AND state = ?2",
                params![existing.reference_id, SecureKeyRefState::Released.as_str()],
            )
            .context("clearing released sealed-state tuple ref for re-reserve")?;
        } else {
            return Ok(ReserveResult::Conflict);
        }
    }

    // New reservations only while Active/Retained.
    if ver.state == SecureKeyVersionState::Retiring {
        return Ok(ReserveResult::Retiring);
    }
    if !ver.state.allows_reservation() {
        return Ok(ReserveResult::NotReservable { state: ver.state });
    }

    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO secure_key_consumer_refs
            (reference_id, namespace, version, consumer_kind, consumer_id, state,
             created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![
            reference_id,
            namespace,
            version,
            consumer_kind,
            consumer_id,
            SecureKeyRefState::Reserved.as_str(),
            now
        ],
    )
    .context("inserting consumer ref")?;
    Ok(ReserveResult::Reserved(SecureKeyConsumerRef {
        reference_id: reference_id.to_owned(),
        namespace: namespace.to_owned(),
        version,
        consumer_kind: consumer_kind.to_owned(),
        consumer_id: consumer_id.to_owned(),
        state: SecureKeyRefState::Reserved,
        created_at: now,
        updated_at: now,
    }))
}

pub fn get_ref_by_id_conn(
    conn: &rusqlite::Connection,
    reference_id: &str,
) -> Result<Option<SecureKeyConsumerRef>> {
    conn.query_row(
        "SELECT reference_id, namespace, version, consumer_kind, consumer_id, state,
                created_at, updated_at
         FROM secure_key_consumer_refs WHERE reference_id = ?1",
        [reference_id],
        map_ref_row,
    )
    .optional()
    .context("loading consumer ref by id")
}

pub fn get_ref_by_tuple_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
    version: i64,
    consumer_kind: &str,
    consumer_id: &str,
) -> Result<Option<SecureKeyConsumerRef>> {
    conn.query_row(
        "SELECT reference_id, namespace, version, consumer_kind, consumer_id, state,
                created_at, updated_at
         FROM secure_key_consumer_refs
         WHERE namespace = ?1 AND version = ?2
           AND consumer_kind = ?3 AND consumer_id = ?4",
        params![namespace, version, consumer_kind, consumer_id],
        map_ref_row,
    )
    .optional()
    .context("loading consumer ref by tuple")
}

/// Reserved -> Active in the same transaction that makes consumer data reachable.
pub fn activate_consumer_ref_conn(conn: &rusqlite::Connection, reference_id: &str) -> Result<bool> {
    let now = Utc::now().timestamp();
    let n = conn
        .execute(
            "UPDATE secure_key_consumer_refs SET state = ?1, updated_at = ?2
             WHERE reference_id = ?3 AND state = ?4",
            params![
                SecureKeyRefState::Active.as_str(),
                now,
                reference_id,
                SecureKeyRefState::Reserved.as_str()
            ],
        )
        .context("activating consumer ref")?;
    if n > 0 {
        return Ok(true);
    }
    // Idempotent if already Active.
    match get_ref_by_id_conn(conn, reference_id)? {
        Some(r) if r.state == SecureKeyRefState::Active => Ok(true),
        _ => Ok(false),
    }
}

/// Active -> Releasing in the same transaction that makes consumer data unreachable.
pub fn begin_release_consumer_ref_conn(
    conn: &rusqlite::Connection,
    reference_id: &str,
) -> Result<bool> {
    let now = Utc::now().timestamp();
    let n = conn
        .execute(
            "UPDATE secure_key_consumer_refs SET state = ?1, updated_at = ?2
             WHERE reference_id = ?3 AND state = ?4",
            params![
                SecureKeyRefState::Releasing.as_str(),
                now,
                reference_id,
                SecureKeyRefState::Active.as_str()
            ],
        )
        .context("beginning consumer ref release")?;
    if n > 0 {
        return Ok(true);
    }
    match get_ref_by_id_conn(conn, reference_id)? {
        Some(r) if r.state == SecureKeyRefState::Releasing => Ok(true),
        _ => Ok(false),
    }
}

/// Releasing -> Released (actor reconciliation).
pub fn mark_consumer_ref_released_conn(
    conn: &rusqlite::Connection,
    reference_id: &str,
) -> Result<bool> {
    let now = Utc::now().timestamp();
    let n = conn
        .execute(
            "UPDATE secure_key_consumer_refs SET state = ?1, updated_at = ?2
             WHERE reference_id = ?3 AND state IN (?4, ?5)",
            params![
                SecureKeyRefState::Released.as_str(),
                now,
                reference_id,
                SecureKeyRefState::Releasing.as_str(),
                SecureKeyRefState::Reserved.as_str()
            ],
        )
        .context("marking consumer ref released")?;
    Ok(n > 0)
}

pub fn list_recon_refs_conn(conn: &rusqlite::Connection) -> Result<Vec<SecureKeyConsumerRef>> {
    let mut stmt = conn.prepare(
        "SELECT reference_id, namespace, version, consumer_kind, consumer_id, state,
                created_at, updated_at
         FROM secure_key_consumer_refs
         WHERE state IN ('Reserved', 'Releasing')
         ORDER BY created_at ASC, reference_id ASC",
    )?;
    let rows = stmt.query_map([], map_ref_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing recon consumer refs")
}

/// Delete a Pending version row that never activated (orphan cleanup of SQLite side).
pub fn delete_pending_version_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
    version: i64,
) -> Result<()> {
    conn.execute(
        "DELETE FROM secure_key_versions
         WHERE namespace = ?1 AND version = ?2 AND state = ?3",
        params![namespace, version, SecureKeyVersionState::Pending.as_str()],
    )
    .context("deleting pending version")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Sealed-state write sagas (dual-slot CAS coordination)
// ---------------------------------------------------------------------------

/// Consumer kind for sealed-state key retention references.
pub const SEALED_STATE_CONSUMER_KIND: &str = "sealed_state";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedStateSagaPhase {
    Prepared,
    RefReserved,
    NativeWritten,
    NativeVerified,
    RefActivated,
}

impl SealedStateSagaPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "Prepared",
            Self::RefReserved => "RefReserved",
            Self::NativeWritten => "NativeWritten",
            Self::NativeVerified => "NativeVerified",
            Self::RefActivated => "RefActivated",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "Prepared" => Ok(Self::Prepared),
            "RefReserved" => Ok(Self::RefReserved),
            "NativeWritten" => Ok(Self::NativeWritten),
            "NativeVerified" => Ok(Self::NativeVerified),
            "RefActivated" => Ok(Self::RefActivated),
            other => bail!("unknown sealed state saga phase: {other}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedStateSagaRow {
    pub op_id: String,
    pub namespace: String,
    pub target_slot: String,
    pub target_account: String,
    /// Decimal text encoding of a full u64 generation.
    pub expected_generation: u64,
    /// Decimal text encoding of a full u64 generation.
    pub new_generation: u64,
    pub payload_digest_hex: String,
    /// Hex digest of the payload expected at CAS start; empty string for create.
    pub expected_payload_digest_hex: String,
    /// Prior current slot suffix (`state-a`/`state-b`) or empty for create.
    pub prior_slot: String,
    pub key_version: i64,
    pub phase: SealedStateSagaPhase,
    pub created_at: i64,
    pub updated_at: i64,
}

#[allow(clippy::too_many_arguments)]
pub fn insert_sealed_state_saga_conn(
    conn: &rusqlite::Connection,
    op_id: &str,
    namespace: &str,
    target_slot: &str,
    target_account: &str,
    expected_generation: u64,
    new_generation: u64,
    payload_digest_hex: &str,
    expected_payload_digest_hex: &str,
    prior_slot: &str,
    key_version: i64,
) -> Result<()> {
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO sealed_state_sagas
            (op_id, namespace, target_slot, target_account, expected_generation,
             new_generation, payload_digest_hex, expected_payload_digest_hex, prior_slot,
             key_version, phase, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)",
        params![
            op_id,
            namespace,
            target_slot,
            target_account,
            expected_generation.to_string(),
            new_generation.to_string(),
            payload_digest_hex,
            expected_payload_digest_hex,
            prior_slot,
            key_version,
            SealedStateSagaPhase::Prepared.as_str(),
            now
        ],
    )
    .context("inserting sealed state saga")?;
    Ok(())
}

pub fn set_sealed_state_saga_phase_conn(
    conn: &rusqlite::Connection,
    op_id: &str,
    phase: SealedStateSagaPhase,
) -> Result<()> {
    let now = Utc::now().timestamp();
    let n = conn
        .execute(
            "UPDATE sealed_state_sagas SET phase = ?1, updated_at = ?2 WHERE op_id = ?3",
            params![phase.as_str(), now, op_id],
        )
        .context("updating sealed state saga phase")?;
    if n == 0 {
        bail!("sealed state saga not found: {op_id}");
    }
    Ok(())
}

const SEALED_SAGA_SELECT: &str = "SELECT op_id, namespace, target_slot, target_account,
    expected_generation, new_generation, payload_digest_hex, expected_payload_digest_hex,
    prior_slot, key_version, phase, created_at, updated_at
 FROM sealed_state_sagas";

pub fn get_sealed_state_saga_conn(
    conn: &rusqlite::Connection,
    op_id: &str,
) -> Result<Option<SealedStateSagaRow>> {
    conn.query_row(
        &format!("{SEALED_SAGA_SELECT} WHERE op_id = ?1"),
        [op_id],
        map_sealed_state_saga_row,
    )
    .optional()
    .context("loading sealed state saga")
}

pub fn list_open_sealed_state_sagas_conn(
    conn: &rusqlite::Connection,
) -> Result<Vec<SealedStateSagaRow>> {
    let mut stmt = conn.prepare(&format!(
        "{SEALED_SAGA_SELECT} ORDER BY created_at ASC, op_id ASC"
    ))?;
    let rows = stmt.query_map([], map_sealed_state_saga_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing sealed state sagas")
}

pub fn get_sealed_state_saga_for_namespace_conn(
    conn: &rusqlite::Connection,
    namespace: &str,
) -> Result<Option<SealedStateSagaRow>> {
    conn.query_row(
        &format!("{SEALED_SAGA_SELECT} WHERE namespace = ?1 ORDER BY created_at ASC LIMIT 1"),
        [namespace],
        map_sealed_state_saga_row,
    )
    .optional()
    .context("loading sealed state saga by namespace")
}

pub fn delete_sealed_state_saga_conn(conn: &rusqlite::Connection, op_id: &str) -> Result<()> {
    conn.execute("DELETE FROM sealed_state_sagas WHERE op_id = ?1", [op_id])
        .context("deleting sealed state saga")?;
    Ok(())
}

fn map_sealed_state_saga_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SealedStateSagaRow> {
    let phase: String = row.get(10)?;
    let expected_s: String = row.get(4)?;
    let new_s: String = row.get(5)?;
    let expected_generation = expected_s.parse::<u64>().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(e.to_string())),
        )
    })?;
    let new_generation = new_s.parse::<u64>().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(e.to_string())),
        )
    })?;
    Ok(SealedStateSagaRow {
        op_id: row.get(0)?,
        namespace: row.get(1)?,
        target_slot: row.get(2)?,
        target_account: row.get(3)?,
        expected_generation,
        new_generation,
        payload_digest_hex: row.get(6)?,
        expected_payload_digest_hex: row.get(7)?,
        prior_slot: row.get(8)?,
        key_version: row.get(9)?,
        phase: SealedStateSagaPhase::parse(&phase).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                10,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

/// Stable reference_id for a sealed-state key retention ref.
pub fn sealed_state_ref_id(namespace: &str, key_version: i64) -> String {
    format!("sealed-state:{namespace}:v{key_version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reserve_activate_release_lifecycle() {
        let db = Db::open_in_memory().unwrap();
        db.write(|conn| {
            ensure_namespace_conn(conn, "leak-report/v1")?;
            let now = Utc::now().timestamp();
            conn.execute(
                "INSERT INTO secure_key_versions
                    (namespace, version, state, key_digest, created_at, updated_at)
                 VALUES (?1, 1, ?2, 'digest', ?3, ?3)",
                params![
                    "leak-report/v1",
                    SecureKeyVersionState::Active.as_str(),
                    now
                ],
            )?;
            conn.execute(
                "UPDATE secure_key_namespaces SET active_version = 1 WHERE namespace = ?1",
                ["leak-report/v1"],
            )?;
            let r = reserve_consumer_ref_conn(conn, "ref-1", "leak-report/v1", 1, "test", "c1")?;
            assert!(matches!(r, ReserveResult::Reserved(_)));
            assert!(activate_consumer_ref_conn(conn, "ref-1")?);
            assert!(begin_release_consumer_ref_conn(conn, "ref-1")?);
            assert!(mark_consumer_ref_released_conn(conn, "ref-1")?);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn reservation_rejected_when_retiring() {
        let db = Db::open_in_memory().unwrap();
        db.write(|conn| {
            ensure_namespace_conn(conn, "ns")?;
            let now = Utc::now().timestamp();
            conn.execute(
                "INSERT INTO secure_key_versions
                    (namespace, version, state, key_digest, created_at, updated_at)
                 VALUES ('ns', 1, ?1, 'd', ?2, ?2)",
                params![SecureKeyVersionState::Retiring.as_str(), now],
            )?;
            let r = reserve_consumer_ref_conn(conn, "r", "ns", 1, "k", "c")?;
            assert!(matches!(r, ReserveResult::Retiring));
            Ok(())
        })
        .await
        .unwrap();
    }
}
