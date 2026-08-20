//! Scoped sealed-value records, cross-store lifecycle sagas, and the exact
//! action-grant tuple.
//!
//! This module owns the durable half of owner-managed sealed values across
//! Session, Project, and Global scope. It stores **identity and lifecycle
//! metadata only**. Session literals stay in the pre-existing `sealed_values`
//! table; Project and Global literals live in a dedicated sealed-value
//! compartment outside this database, reachable only through the random opaque
//! exact key held in [`SealedValueRecordRow::compartment_key`].
//!
//! Two properties are load-bearing and are enforced here rather than left to
//! callers:
//!
//! * **No enumeration oracle.** There is no count, prefix, existence, or
//!   "does this name exist" query in this module's agent-reachable surface.
//!   Inventory is a single owner-only list of safe metadata; every other
//!   lookup is by exact `record_id` or by the exact `(scope, scope_key, name)`
//!   triple that only the Owner can form.
//! * **No resolvable partial state.** A record is resolvable only when
//!   `active_version >= 1` and `deleted_at_ms IS NULL`. Every cross-store
//!   lifecycle change stages its new compartment locator in a saga row first,
//!   so an interrupted create or rotate is non-resolvable or still pinned to
//!   the previous version — never half-live.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::fmt;

use crate::db::Db;

/// Scope of a sealed-value record. Session is the default for new values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SealedScopeKind {
    Session,
    Project,
    Global,
}

impl SealedScopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Project => "project",
            Self::Global => "global",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "session" => Ok(Self::Session),
            "project" => Ok(Self::Project),
            "global" => Ok(Self::Global),
            other => bail!("unknown sealed value scope: {other}"),
        }
    }

    /// Whether this scope keeps its literal outside SQLite, in the sealed
    /// compartment. Only these scopes need a cross-store saga.
    pub fn is_persistent_compartment(self) -> bool {
        matches!(self, Self::Project | Self::Global)
    }
}

impl fmt::Display for SealedScopeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One sealed-value record. Carries no literal and no key material.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedValueRecordRow {
    pub record_id: String,
    pub scope: SealedScopeKind,
    pub scope_key: String,
    pub name: String,
    pub description: String,
    pub owner_principal: String,
    pub active_version: i64,
    pub compartment_key: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub deleted_at_ms: Option<i64>,
}

impl SealedValueRecordRow {
    /// A record is usable only once its create saga has committed and it has
    /// not been deleted. This is the single resolvability predicate; nothing
    /// else in the tree may re-derive it.
    pub fn is_resolvable(&self) -> bool {
        self.deleted_at_ms.is_none()
            && self.active_version >= 1
            && (!self.scope.is_persistent_compartment() || self.compartment_key.is_some())
    }
}

/// The locator is not secret-derived, but it is still a capability handle:
/// keep it out of logs by construction.
impl fmt::Debug for SealedValueRecordRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedValueRecordRow")
            .field("record_id", &self.record_id)
            .field("scope", &self.scope)
            .field("scope_key", &self.scope_key)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("owner_principal", &self.owner_principal)
            .field("active_version", &self.active_version)
            .field(
                "compartment_key",
                &self.compartment_key.as_ref().map(|_| "<locator>"),
            )
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .field("deleted_at_ms", &self.deleted_at_ms)
            .finish()
    }
}

/// Which lifecycle change a saga row is resuming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedSagaKind {
    Create,
    Rotate,
    Delete,
}

impl SealedSagaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Rotate => "rotate",
            Self::Delete => "delete",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "create" => Ok(Self::Create),
            "rotate" => Ok(Self::Rotate),
            "delete" => Ok(Self::Delete),
            other => bail!("unknown sealed value saga kind: {other}"),
        }
    }

    /// `create` and `rotate` roll **back** when interrupted before commit —
    /// the previous state is always the safe one. `delete` rolls **forward**,
    /// because prepare already made the record non-resolvable and re-admitting
    /// a deleted value would be the unsafe direction.
    pub fn rolls_forward_when_prepared(self) -> bool {
        matches!(self, Self::Delete)
    }
}

/// Saga phase. The row exists only while the saga is unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedSagaPhase {
    Prepared,
    Committed,
}

impl SealedSagaPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Committed => "committed",
        }
    }

    pub fn parse(raw: &str) -> Result<Self> {
        match raw {
            "prepared" => Ok(Self::Prepared),
            "committed" => Ok(Self::Committed),
            other => bail!("unknown sealed value saga phase: {other}"),
        }
    }
}

/// One unresolved cross-store lifecycle saga.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedSagaRow {
    pub op_id: String,
    pub record_id: String,
    pub kind: SealedSagaKind,
    pub phase: SealedSagaPhase,
    pub target_version: i64,
    pub prepared_compartment_key: Option<String>,
    pub superseded_compartment_key: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl fmt::Debug for SealedSagaRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSagaRow")
            .field("op_id", &self.op_id)
            .field("record_id", &self.record_id)
            .field("kind", &self.kind)
            .field("phase", &self.phase)
            .field("target_version", &self.target_version)
            .field(
                "prepared_compartment_key",
                &self.prepared_compartment_key.as_ref().map(|_| "<locator>"),
            )
            .field(
                "superseded_compartment_key",
                &self
                    .superseded_compartment_key
                    .as_ref()
                    .map(|_| "<locator>"),
            )
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .finish()
    }
}

/// The exact grant tuple. Every targeting column is exact; there is no
/// wildcard target, environment name, child id, or caller dispatch identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedActionGrantRow {
    pub grant_id: String,
    pub record_id: String,
    pub value_version: i64,
    pub project_key: String,
    pub session_id: String,
    pub session_generation: i64,
    pub action_id: String,
    pub action_revision: i64,
    pub use_epoch: i64,
    pub issued_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
}

/// The exact tuple an authorization request must present. Constructing this
/// requires already knowing every targeting field, so it cannot be used to
/// probe for grants that a caller does not already name exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedGrantSelector {
    pub record_id: String,
    pub action_id: String,
    pub project_key: String,
    pub session_id: String,
    pub session_generation: i64,
}

/// A newly issued grant plus the freshly written row.
#[derive(Debug, Clone)]
pub struct NewSealedActionGrant {
    pub grant_id: String,
    pub record_id: String,
    pub value_version: i64,
    pub project_key: String,
    pub session_id: String,
    pub session_generation: i64,
    pub action_id: String,
    pub action_revision: i64,
    pub issued_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

/// The authoritative outcome of winning a use claim.
///
/// Read back inside the claiming transaction, so every field describes the
/// record as it was at the instant the claim succeeded — not as it was when
/// authorization read it. Carries the locator, never the literal.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedClaimedUse {
    pub grant_id: String,
    pub record_id: String,
    pub scope: SealedScopeKind,
    pub scope_key: String,
    pub name: String,
    pub active_version: i64,
    pub compartment_key: Option<String>,
}

impl fmt::Debug for SealedClaimedUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedClaimedUse")
            .field("grant_id", &self.grant_id)
            .field("record_id", &self.record_id)
            .field("scope", &self.scope)
            .field("active_version", &self.active_version)
            .field(
                "compartment_key",
                &self.compartment_key.as_ref().map(|_| "<locator>"),
            )
            .finish()
    }
}

/// Everything needed to stage a record before its literal exists anywhere.
#[derive(Debug, Clone)]
pub struct NewSealedValueRecord {
    pub record_id: String,
    pub scope: SealedScopeKind,
    pub scope_key: String,
    pub name: String,
    pub description: String,
    pub owner_principal: String,
    pub created_at_ms: i64,
}

const RECORD_COLUMNS: &str = "record_id, scope, scope_key, name, description, owner_principal, \
     active_version, compartment_key, created_at_ms, updated_at_ms, deleted_at_ms";

const SAGA_COLUMNS: &str = "op_id, record_id, kind, phase, target_version, \
     prepared_compartment_key, superseded_compartment_key, created_at_ms, updated_at_ms";

const GRANT_COLUMNS: &str = "grant_id, record_id, value_version, project_key, session_id, \
     session_generation, action_id, action_revision, use_epoch, issued_at_ms, expires_at_ms, \
     revoked_at_ms";

fn decode_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<SealedValueRecordRow> {
    let scope: String = row.get(1)?;
    Ok(SealedValueRecordRow {
        record_id: row.get(0)?,
        scope: SealedScopeKind::parse(&scope)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?,
        scope_key: row.get(2)?,
        name: row.get(3)?,
        description: row.get(4)?,
        owner_principal: row.get(5)?,
        active_version: row.get(6)?,
        compartment_key: row.get(7)?,
        created_at_ms: row.get(8)?,
        updated_at_ms: row.get(9)?,
        deleted_at_ms: row.get(10)?,
    })
}

fn decode_saga(row: &rusqlite::Row<'_>) -> rusqlite::Result<SealedSagaRow> {
    let kind: String = row.get(2)?;
    let phase: String = row.get(3)?;
    Ok(SealedSagaRow {
        op_id: row.get(0)?,
        record_id: row.get(1)?,
        kind: SealedSagaKind::parse(&kind)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?,
        phase: SealedSagaPhase::parse(&phase)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?,
        target_version: row.get(4)?,
        prepared_compartment_key: row.get(5)?,
        superseded_compartment_key: row.get(6)?,
        created_at_ms: row.get(7)?,
        updated_at_ms: row.get(8)?,
    })
}

fn decode_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<SealedActionGrantRow> {
    Ok(SealedActionGrantRow {
        grant_id: row.get(0)?,
        record_id: row.get(1)?,
        value_version: row.get(2)?,
        project_key: row.get(3)?,
        session_id: row.get(4)?,
        session_generation: row.get(5)?,
        action_id: row.get(6)?,
        action_revision: row.get(7)?,
        use_epoch: row.get(8)?,
        issued_at_ms: row.get(9)?,
        expires_at_ms: row.get(10)?,
        revoked_at_ms: row.get(11)?,
    })
}

fn record_conn(conn: &Connection, record_id: &str) -> Result<Option<SealedValueRecordRow>> {
    conn.query_row(
        &format!("SELECT {RECORD_COLUMNS} FROM sealed_value_records WHERE record_id = ?1"),
        params![record_id],
        decode_record,
    )
    .optional()
    .context("reading sealed value record")
}

fn saga_for_record_conn(conn: &Connection, record_id: &str) -> Result<Option<SealedSagaRow>> {
    conn.query_row(
        &format!("SELECT {SAGA_COLUMNS} FROM sealed_value_sagas WHERE record_id = ?1"),
        params![record_id],
        decode_saga,
    )
    .optional()
    .context("reading sealed value saga")
}

fn name_tombstoned_conn(
    conn: &Connection,
    scope: SealedScopeKind,
    scope_key: &str,
    name: &str,
) -> Result<bool> {
    let hit: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sealed_value_name_tombstones
              WHERE scope = ?1 AND scope_key = ?2 AND name = ?3",
            params![scope.as_str(), scope_key, name],
            |row| row.get(0),
        )
        .optional()
        .context("checking sealed value name tombstone")?;
    Ok(hit.is_some())
}

/// Connection-scoped body of [`Db::create_session_sealed_value`]. Exposed so a
/// caller (the sealed-adoption journaling seam in `cockpit-core`) can compose
/// the session sealed-row write with a protected-history append in one
/// transaction; a failure of either rolls back both.
pub fn create_session_sealed_value_conn(
    conn: &Connection,
    record: &NewSealedValueRecord,
    _literal: &str,
    reason: &str,
    origin: &str,
) -> Result<SealedValueRecordRow> {
    if record.scope != SealedScopeKind::Session {
        bail!("create_session_sealed_value is only for session scope");
    }
    if name_tombstoned_conn(conn, record.scope, &record.scope_key, &record.name)? {
        bail!("sealed value name was retired and is never reused");
    }
    conn.execute(
        "INSERT INTO sealed_value_records
             (record_id, scope, scope_key, name, description, owner_principal,
              active_version, compartment_key, created_at_ms, updated_at_ms, deleted_at_ms)
         VALUES (?1, 'session', ?2, ?3, ?4, ?5, 0, NULL, ?6, ?6, NULL)",
        params![
            record.record_id,
            record.scope_key,
            record.name,
            record.description,
            record.owner_principal,
            record.created_at_ms,
        ],
    )
    .context("creating session sealed value record")?;
    conn.execute(
        "INSERT INTO sealed_values (session_id, value_id, value, reason, origin, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(session_id, value_id) DO UPDATE SET
           value = excluded.value, reason = excluded.reason,
           origin = excluded.origin, created_at = excluded.created_at",
        params![
            record.scope_key,
            record.name,
            Option::<String>::None,
            reason,
            origin,
            record.created_at_ms / 1_000,
        ],
    )
    .context("writing session sealed literal")?;
    conn.execute(
        "UPDATE sealed_value_records SET active_version = 1, updated_at_ms = ?2
          WHERE record_id = ?1 AND active_version = 0",
        params![record.record_id, record.created_at_ms],
    )
    .context("promoting session sealed value create")?;
    record_conn(conn, &record.record_id)?.context("created session sealed value record vanished")
}

/// Stage a session create at `active_version = 0` without promoting it.
pub fn stage_session_sealed_create_conn(
    conn: &Connection,
    record: &NewSealedValueRecord,
    reason: &str,
    origin: &str,
) -> Result<SealedValueRecordRow> {
    if record.scope != SealedScopeKind::Session {
        bail!("stage_session_sealed_create is only for session scope");
    }
    if name_tombstoned_conn(conn, record.scope, &record.scope_key, &record.name)? {
        bail!("sealed value name was retired and is never reused");
    }
    conn.execute(
        "INSERT INTO sealed_value_records
             (record_id, scope, scope_key, name, description, owner_principal,
              active_version, compartment_key, created_at_ms, updated_at_ms, deleted_at_ms)
         VALUES (?1, 'session', ?2, ?3, ?4, ?5, 0, NULL, ?6, ?6, NULL)",
        params![
            record.record_id,
            record.scope_key,
            record.name,
            record.description,
            record.owner_principal,
            record.created_at_ms,
        ],
    )
    .context("staging session sealed value record")?;
    conn.execute(
        "INSERT INTO sealed_values (session_id, value_id, value, reason, origin, created_at)
         VALUES (?1, ?2, NULL, ?3, ?4, ?5)
         ON CONFLICT(session_id, value_id) DO UPDATE SET
           value = NULL, reason = excluded.reason,
           origin = excluded.origin, created_at = excluded.created_at",
        params![
            record.scope_key,
            record.name,
            reason,
            origin,
            record.created_at_ms / 1_000,
        ],
    )
    .context("writing session sealed metadata")?;
    record_conn(conn, &record.record_id)?.context("staged session sealed value record vanished")
}

pub fn promote_session_sealed_create_conn(
    conn: &Connection,
    record_id: &str,
    now_ms: i64,
) -> Result<SealedValueRecordRow> {
    conn.execute(
        "UPDATE sealed_value_records SET active_version = 1, updated_at_ms = ?2
          WHERE record_id = ?1 AND active_version = 0 AND deleted_at_ms IS NULL",
        params![record_id, now_ms],
    )
    .context("promoting session sealed value create")?;
    record_conn(conn, record_id)?.context("promoted session sealed value record vanished")
}

/// Connection-scoped body of [`Db::rotate_session_sealed_value`]. See
/// [`create_session_sealed_value_conn`] for why the conn-scoped form exists.
pub fn rotate_session_sealed_value_conn(
    conn: &Connection,
    record_id: &str,
    _literal: &str,
    now_ms: i64,
) -> Result<SealedValueRecordRow> {
    let existing = record_conn(conn, record_id)?.context("sealed value record no longer exists")?;
    if existing.scope != SealedScopeKind::Session {
        bail!("rotate_session_sealed_value is only for session scope");
    }
    if !existing.is_resolvable() {
        bail!("sealed value record is not resolvable and cannot rotate");
    }
    conn.execute(
        "UPDATE sealed_values SET value = NULL, created_at = ?3
          WHERE session_id = ?1 AND value_id = ?2",
        params![existing.scope_key, existing.name, now_ms / 1_000],
    )
    .context("rotating session sealed literal")?;
    conn.execute(
        "UPDATE sealed_value_records
            SET active_version = active_version + 1, updated_at_ms = ?2
          WHERE record_id = ?1",
        params![record_id, now_ms],
    )
    .context("bumping session sealed value version")?;
    // Fence in the same transaction that bumped the version, so a use holding a
    // v1 grant can never be handed the v2 literal.
    revoke_grants_for_record_conn(conn, record_id, now_ms)?;
    record_conn(conn, record_id)?.context("rotated session sealed value record vanished")
}

impl Db {
    /// Stage a new record. The record is inserted at `active_version = 0`, so
    /// it is not resolvable until its create saga commits.
    ///
    /// For a compartment-backed scope this also writes the `prepared` saga row
    /// carrying the staged locator, in the same transaction, so a crash between
    /// the two is impossible.
    pub async fn prepare_sealed_value_create(
        &self,
        record: NewSealedValueRecord,
        op_id: String,
        prepared_compartment_key: Option<String>,
    ) -> Result<SealedValueRecordRow> {
        self.transaction(move |conn| {
            // Session scope has no staged locator to carry, so this path would
            // insert a record with no literal under it and `commit_sealed_
            // value_create` would then publish it as resolvable — a name that
            // resolves to nothing. Sessions create in one transaction via
            // `create_session_sealed_value`. The directory refuses this at its
            // own layer too; the guard belongs here as well so every generic
            // saga entry point rejects session scope at the store boundary,
            // rather than relying on the caller above it to have checked.
            if record.scope == SealedScopeKind::Session {
                bail!(
                    "session-scope sealed values are created in a single transaction, not a saga"
                );
            }
            if name_tombstoned_conn(conn, record.scope, &record.scope_key, &record.name)? {
                bail!("sealed value name was retired and is never reused");
            }
            conn.execute(
                "INSERT INTO sealed_value_records
                     (record_id, scope, scope_key, name, description, owner_principal,
                      active_version, compartment_key, created_at_ms, updated_at_ms, deleted_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, NULL, ?7, ?7, NULL)",
                params![
                    record.record_id,
                    record.scope.as_str(),
                    record.scope_key,
                    record.name,
                    record.description,
                    record.owner_principal,
                    record.created_at_ms,
                ],
            )
            .context("staging sealed value record")?;
            if record.scope.is_persistent_compartment() {
                let key = prepared_compartment_key
                    .clone()
                    .context("compartment-backed sealed value requires a staged locator")?;
                insert_saga_conn(
                    conn,
                    &op_id,
                    &record.record_id,
                    SealedSagaKind::Create,
                    1,
                    Some(&key),
                    None,
                    record.created_at_ms,
                )?;
            }
            record_conn(conn, &record.record_id)?
                .context("staged sealed value record vanished inside its own transaction")
        })
        .await
    }

    /// Promote a staged record to `active_version = 1` and mark its saga
    /// committed. After this returns the record is resolvable.
    pub async fn commit_sealed_value_create(
        &self,
        record_id: String,
        compartment_key: Option<String>,
        now_ms: i64,
    ) -> Result<SealedValueRecordRow> {
        self.transaction(move |conn| {
            let existing =
                record_conn(conn, &record_id)?.context("sealed value record no longer exists")?;
            if existing.deleted_at_ms.is_some() {
                bail!("sealed value record was deleted before its create committed");
            }
            if existing.active_version != 0 {
                bail!("sealed value create already committed");
            }
            conn.execute(
                "UPDATE sealed_value_records
                    SET active_version = 1, compartment_key = ?2, updated_at_ms = ?3
                  WHERE record_id = ?1",
                params![record_id, compartment_key, now_ms],
            )
            .context("committing sealed value create")?;
            mark_saga_committed_conn(conn, &record_id, now_ms)?;
            record_conn(conn, &record_id)?.context("committed sealed value record vanished")
        })
        .await
    }

    /// Create a session-scope sealed value.
    ///
    /// Session literals live in the wrap-key vault. The record is staged at
    /// `active_version = 0`, the vault item is written, then the record is
    /// promoted to `active_version >= 1` in the same SQLite transaction as the
    /// vault row. An interrupted create is non-resolvable, never half-live.
    pub async fn create_session_sealed_value(
        &self,
        record: NewSealedValueRecord,
        literal: String,
        reason: String,
        origin: String,
    ) -> Result<SealedValueRecordRow> {
        self.transaction(move |conn| {
            create_session_sealed_value_conn(conn, &record, &literal, &reason, &origin)
        })
        .await
    }

    /// Rotate a session-scope sealed value in one transaction.
    pub async fn rotate_session_sealed_value(
        &self,
        record_id: String,
        literal: String,
        now_ms: i64,
    ) -> Result<SealedValueRecordRow> {
        self.transaction(move |conn| {
            rotate_session_sealed_value_conn(conn, &record_id, &literal, now_ms)
        })
        .await
    }

    /// Delete a session-scope sealed value and its literal in one transaction,
    /// tombstoning the name so it is never reused.
    pub async fn delete_session_sealed_value(
        &self,
        record_id: String,
        now_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| delete_session_sealed_value_conn(conn, &record_id, now_ms))
            .await
    }

    /// Delete the session sealed value that the daemon's `DeleteSealedValue`
    /// request names — by `(session_id, value_id)` rather than by record id.
    ///
    /// A session-scope *scoped* value is dual-written: the record lives in
    /// `sealed_value_records` and its literal in the legacy `sealed_values`
    /// table (see [`Db::create_session_sealed_value`]). Deleting only the
    /// legacy row — which is what this request used to do — reported success
    /// while leaving the record behind: still `is_resolvable()`, but with no
    /// literal under it. That is exactly the resolvable-partial-state the
    /// lifecycle forbids, and it also skipped the name tombstone and left
    /// outstanding grants unfenced.
    ///
    /// A scoped record therefore wins and takes the full scoped path. The bare
    /// legacy delete survives only for rows that predate the scoped subsystem
    /// and have no record of their own. The lookup and the delete share one
    /// transaction so a concurrent create cannot slip between them.
    pub async fn delete_sealed_value_for_session(
        &self,
        session_id: String,
        value_id: String,
        now_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let record_id: Option<String> = conn
                .query_row(
                    // Deliberately *not* filtered on `deleted_at_ms IS NULL`.
                    // A record soft-deleted by a half-finished lifecycle still
                    // owns a live literal in `sealed_values`; skipping it here
                    // fell through to the legacy branch, which deleted the
                    // literal and left the record row behind. Any session
                    // record matching the name wins, tombstoned or not, so the
                    // shared cleanup always removes both stores together.
                    "SELECT record_id FROM sealed_value_records
                      WHERE scope = 'session' AND scope_key = ?1 AND name = ?2",
                    params![session_id, value_id],
                    |row| row.get(0),
                )
                .optional()
                .context("looking up session sealed value record")?;
            if let Some(record_id) = record_id {
                return delete_session_sealed_value_conn(conn, &record_id, now_ms);
            }
            Ok(conn
                .execute(
                    "DELETE FROM sealed_values WHERE session_id = ?1 AND value_id = ?2",
                    params![session_id, value_id],
                )
                .context("deleting legacy sealed value")?
                > 0)
        })
        .await
    }

    /// Stage a rotation. The record keeps serving its current version until
    /// [`Db::commit_sealed_value_rotate`] runs, so an interrupted rotation
    /// leaves the previous version live rather than a half-written new one.
    pub async fn prepare_sealed_value_rotate(
        &self,
        record_id: String,
        op_id: String,
        prepared_compartment_key: String,
        now_ms: i64,
    ) -> Result<i64> {
        self.transaction(move |conn| {
            let existing =
                record_conn(conn, &record_id)?.context("sealed value record no longer exists")?;
            if !existing.is_resolvable() {
                bail!("sealed value record is not resolvable and cannot rotate");
            }
            if !existing.scope.is_persistent_compartment() {
                bail!("session-scope sealed values rotate in a single store, not a saga");
            }
            if saga_for_record_conn(conn, &record_id)?.is_some() {
                bail!("a sealed value lifecycle saga is already in flight for this record");
            }
            let target = existing.active_version + 1;
            insert_saga_conn(
                conn,
                &op_id,
                &record_id,
                SealedSagaKind::Rotate,
                target,
                Some(&prepared_compartment_key),
                existing.compartment_key.as_deref(),
                now_ms,
            )?;
            Ok(target)
        })
        .await
    }

    /// Publish the staged rotation: point the record at the new locator and
    /// bump `active_version` monotonically.
    pub async fn commit_sealed_value_rotate(
        &self,
        record_id: String,
        now_ms: i64,
    ) -> Result<SealedValueRecordRow> {
        self.transaction(move |conn| {
            let saga = saga_for_record_conn(conn, &record_id)?
                .context("no sealed value rotation is in flight for this record")?;
            if saga.kind != SealedSagaKind::Rotate {
                bail!("in-flight sealed value saga is not a rotation");
            }
            let staged = saga
                .prepared_compartment_key
                .clone()
                .context("rotation saga has no staged locator")?;
            conn.execute(
                "UPDATE sealed_value_records
                    SET active_version = ?2, compartment_key = ?3, updated_at_ms = ?4
                  WHERE record_id = ?1 AND active_version < ?2",
                params![record_id, saga.target_version, staged, now_ms],
            )
            .context("committing sealed value rotation")?;
            // A published rotation retires every grant pinned to the previous
            // version, in the same transaction that published it.
            revoke_grants_for_record_conn(conn, &record_id, now_ms)?;
            mark_saga_committed_conn(conn, &record_id, now_ms)?;
            record_conn(conn, &record_id)?.context("rotated sealed value record vanished")
        })
        .await
    }

    /// Stage a delete. Prepare immediately makes the record non-resolvable and
    /// writes the name tombstone, so use is denied from this instant even if
    /// the process dies before the row and literal are reclaimed.
    pub async fn prepare_sealed_value_delete(
        &self,
        record_id: String,
        op_id: String,
        now_ms: i64,
    ) -> Result<Option<SealedSagaRow>> {
        self.transaction(move |conn| {
            let Some(existing) = record_conn(conn, &record_id)? else {
                return Ok(None);
            };
            // A session literal lives in `sealed_values`, which this saga
            // cannot reach: the saga carries only compartment locators, and a
            // session record's are always NULL (schema CHECK). Staging a
            // delete here would tombstone the name and fence the grants while
            // leaving the literal behind, and the committing half would then
            // drop the record and strand that literal with nothing pointing at
            // it. Session deletes are single-transaction by construction, so
            // refuse — exactly as `prepare_sealed_value_rotate` does.
            if existing.scope == SealedScopeKind::Session {
                bail!("session-scope sealed values delete in a single store, not a saga");
            }
            if existing.deleted_at_ms.is_none() {
                conn.execute(
                    "UPDATE sealed_value_records
                        SET deleted_at_ms = ?2, updated_at_ms = ?2 WHERE record_id = ?1",
                    params![record_id, now_ms],
                )
                .context("marking sealed value record deleted")?;
                conn.execute(
                    "INSERT OR IGNORE INTO sealed_value_name_tombstones
                         (scope, scope_key, name, retired_at_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        existing.scope.as_str(),
                        existing.scope_key,
                        existing.name,
                        now_ms
                    ],
                )
                .context("tombstoning sealed value name")?;
            }
            // Fence every outstanding grant in the same transaction that made
            // the record non-resolvable, so no in-flight authorization can win
            // a claim after this instant.
            revoke_grants_for_record_conn(conn, &record_id, now_ms)?;
            if saga_for_record_conn(conn, &record_id)?.is_none() {
                insert_saga_conn(
                    conn,
                    &op_id,
                    &record_id,
                    SealedSagaKind::Delete,
                    existing.active_version,
                    None,
                    existing.compartment_key.as_deref(),
                    now_ms,
                )?;
            } else {
                // Convert the in-flight saga to a delete *without touching
                // either locator column*. Both slots already hold exactly the
                // keys cleanup must reclaim, in every reachable conversion:
                //
                //   committed rotate  prepared = new live key  superseded = pre-rotation key
                //   prepared rotate   prepared = staged key    superseded = live key
                //   committed create  prepared = live key      superseded = NULL
                //   prepared create   prepared = staged key    superseded = NULL
                //
                // At most one saga exists per record (`uq_sealed_value_sagas_
                // record`), and both create and rotate refuse to start while
                // one is in flight, so those four are the only cases.
                //
                // Writing the record's *current* key into `superseded` here is
                // what the committed-rotation case cannot survive: it replaced
                // the pre-rotation key with the new live one, leaving both
                // slots equal. Recovery then reclaimed the live key twice and
                // stranded the pre-rotation literal on disk with nothing
                // referencing it — an un-reclaimed plaintext secret that no
                // later operation could ever find. A delete reclaims *both*
                // slots (`SealedValueStore::reclaim_saga_keys`), so preserving
                // them unmodified is both necessary and sufficient.
                conn.execute(
                    "UPDATE sealed_value_sagas
                        SET kind = 'delete', phase = 'prepared', updated_at_ms = ?2
                      WHERE record_id = ?1",
                    params![record_id, now_ms],
                )
                .context("converting in-flight sealed value saga to a delete")?;
            }
            saga_for_record_conn(conn, &record_id)
        })
        .await
    }

    /// Reclaim the record row. The literal is reclaimed by the caller after
    /// this commits, driven by the surviving `committed` saga row.
    pub async fn commit_sealed_value_delete(&self, record_id: String, now_ms: i64) -> Result<bool> {
        self.transaction(move |conn| {
            mark_saga_committed_conn(conn, &record_id, now_ms)?;
            // `prepare_sealed_value_delete` refuses session scope, so no new
            // session delete saga can be staged. A row staged by an older
            // binary can still be sitting in the table, though, and recovery
            // drives it straight here — `SealedSagaRow` carries no scope, so
            // recovery cannot filter it out itself. Refusing would wedge that
            // recovery loop forever on a record whose literal is still live.
            // Route it through the same single-transaction cleanup the
            // supported path uses instead, which removes both stores,
            // tombstones the name, and fences outstanding grants.
            if let Some(existing) = record_conn(conn, &record_id)?
                && existing.scope == SealedScopeKind::Session
            {
                return delete_session_sealed_value_conn(conn, &record_id, now_ms);
            }
            let removed = conn
                .execute(
                    "DELETE FROM sealed_value_records WHERE record_id = ?1",
                    params![record_id],
                )
                .context("deleting sealed value record")?;
            Ok(removed > 0)
        })
        .await
    }

    /// Undo a prepared create or rotate. The record either disappears (create)
    /// or stays pinned to its previous version and locator (rotate).
    pub async fn rollback_sealed_value_saga(&self, record_id: String) -> Result<()> {
        self.transaction(move |conn| {
            let Some(saga) = saga_for_record_conn(conn, &record_id)? else {
                return Ok(());
            };
            if saga.kind == SealedSagaKind::Create {
                conn.execute(
                    "DELETE FROM sealed_value_records WHERE record_id = ?1 AND active_version = 0",
                    params![record_id],
                )
                .context("rolling back staged sealed value record")?;
            }
            conn.execute(
                "DELETE FROM sealed_value_sagas WHERE record_id = ?1",
                params![record_id],
            )
            .context("clearing sealed value saga")?;
            Ok(())
        })
        .await
    }

    /// Drop a resolved saga row once its compartment cleanup has run.
    pub async fn finish_sealed_value_saga(&self, op_id: String) -> Result<()> {
        self.write(move |conn| {
            conn.execute(
                "DELETE FROM sealed_value_sagas WHERE op_id = ?1",
                params![op_id],
            )
            .context("clearing finished sealed value saga")?;
            Ok(())
        })
        .await
    }

    /// Every unresolved saga, oldest first. This is the recovery work list.
    pub async fn unresolved_sealed_value_sagas(&self) -> Result<Vec<SealedSagaRow>> {
        self.read(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {SAGA_COLUMNS} FROM sealed_value_sagas ORDER BY created_at_ms ASC, op_id ASC"
            ))?;
            let rows = stmt
                .query_map([], decode_saga)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("listing unresolved sealed value sagas")?;
            Ok(rows)
        })
        .await
    }

    /// Exact lookup by immutable record id.
    pub async fn sealed_value_record(
        &self,
        record_id: String,
    ) -> Result<Option<SealedValueRecordRow>> {
        self.read(move |conn| record_conn(conn, &record_id)).await
    }

    /// Owner-only safe inventory. Returns metadata for every live record in
    /// one scope; there is no count, prefix, or existence variant of this.
    pub async fn sealed_value_inventory(
        &self,
        scope: SealedScopeKind,
        scope_key: String,
    ) -> Result<Vec<SealedValueRecordRow>> {
        self.read(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {RECORD_COLUMNS} FROM sealed_value_records
                  WHERE scope = ?1 AND scope_key = ?2 AND deleted_at_ms IS NULL
                  ORDER BY name ASC"
            ))?;
            let rows = stmt
                .query_map(params![scope.as_str(), scope_key], decode_record)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("listing sealed value inventory")?;
            Ok(rows)
        })
        .await
    }

    /// Owner-only: every live sealed value across every scope, oldest-first.
    ///
    /// This is the machine-wide inventory the sealed-owner channel serves when
    /// no scope filter is given. Each row carries its own scope + scope key, so
    /// the caller can project a fully-qualified inventory item. Deleted records
    /// are excluded. Reachable only from the owner-gated dispatch path.
    pub async fn list_all_sealed_value_records(&self) -> Result<Vec<SealedValueRecordRow>> {
        self.read(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {RECORD_COLUMNS} FROM sealed_value_records
                  WHERE deleted_at_ms IS NULL
                  ORDER BY created_at_ms ASC, record_id ASC"
            ))?;
            let rows = stmt
                .query_map([], decode_record)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("listing all sealed value records")?;
            Ok(rows)
        })
        .await
    }

    /// Owner-only: has this canonical name already been retired in this scope?
    /// Reachable only from the Owner lifecycle path, never from a use path.
    pub async fn sealed_value_name_retired(
        &self,
        scope: SealedScopeKind,
        scope_key: String,
        name: String,
    ) -> Result<bool> {
        self.read(move |conn| name_tombstoned_conn(conn, scope, &scope_key, &name))
            .await
    }

    /// Resolve one session-scope literal at an **exact claimed version**.
    ///
    /// The version is not decoration. A session literal lives in a mutable row
    /// keyed by `(session_id, name)`, so re-reading it by record id alone
    /// would hand back whatever is there *now* — meaning a use that claimed v1
    /// could be given the v2 literal if a rotation landed in between. Passing
    /// the claimed version and requiring it to still be live turns that race
    /// into a denial, which is safe, instead of a silent substitution, which
    /// is not.
    ///
    /// Version fence for a session-scoped sealed value.
    ///
    /// Returns `Some((scope_key, name))` only when the live `active_version`
    /// equals `claimed_version`. The plaintext no longer lives in
    /// `sealed_values.value` (NULL after vault unification); the caller must
    /// unwrap the vault item keyed by those fields + the claimed version.
    /// A single `SELECT` against the record row is still the atomic fence:
    /// rotate advances `active_version` in the same transaction that writes
    /// the new vault item, so a stale claim sees no row.
    pub async fn sealed_session_version_fence(
        &self,
        record_id: String,
        claimed_version: i64,
    ) -> Result<Option<(String, String)>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT r.scope_key, r.name
                   FROM sealed_value_records r
                  WHERE r.record_id = ?1
                    AND r.scope = ?2
                    AND r.deleted_at_ms IS NULL
                    AND r.active_version >= 1
                    AND r.active_version = ?3",
                params![
                    record_id,
                    SealedScopeKind::Session.as_str(),
                    claimed_version
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context("fencing session sealed literal version")
        })
        .await
    }

    /// Grant one Global sealed value to one canonical project.
    pub async fn grant_sealed_global_to_project(
        &self,
        record_id: String,
        project_key: String,
        now_ms: i64,
    ) -> Result<()> {
        self.write(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO sealed_global_project_grants
                     (record_id, project_key, granted_at_ms) VALUES (?1, ?2, ?3)",
                params![record_id, project_key, now_ms],
            )
            .context("granting global sealed value to project")?;
            Ok(())
        })
        .await
    }

    /// Exact check that a Global record reaches one canonical project.
    pub async fn sealed_global_reaches_project(
        &self,
        record_id: String,
        project_key: String,
    ) -> Result<bool> {
        self.read(move |conn| {
            let hit: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM sealed_global_project_grants
                      WHERE record_id = ?1 AND project_key = ?2",
                    params![record_id, project_key],
                    |row| row.get(0),
                )
                .optional()
                .context("checking global sealed value project reach")?;
            Ok(hit.is_some())
        })
        .await
    }

    /// Issue an exact action grant.
    pub async fn issue_sealed_action_grant(
        &self,
        grant: NewSealedActionGrant,
    ) -> Result<SealedActionGrantRow> {
        self.transaction(move |conn| {
            let record = record_conn(conn, &grant.record_id)?
                .context("cannot grant an action on a missing sealed value")?;
            if !record.is_resolvable() {
                bail!("cannot grant an action on a non-resolvable sealed value");
            }
            conn.execute(
                "INSERT INTO sealed_action_grants
                     (grant_id, record_id, value_version, project_key, session_id,
                      session_generation, action_id, action_revision, use_epoch,
                      issued_at_ms, expires_at_ms, revoked_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, NULL)",
                params![
                    grant.grant_id,
                    grant.record_id,
                    grant.value_version,
                    grant.project_key,
                    grant.session_id,
                    grant.session_generation,
                    grant.action_id,
                    grant.action_revision,
                    grant.issued_at_ms,
                    grant.expires_at_ms,
                ],
            )
            .context("issuing sealed action grant")?;
            conn.query_row(
                &format!("SELECT {GRANT_COLUMNS} FROM sealed_action_grants WHERE grant_id = ?1"),
                params![grant.grant_id],
                decode_grant,
            )
            .context("reading issued sealed action grant")
        })
        .await
    }

    /// Look up the single grant matching an exact tuple. Metadata only — no
    /// literal is touched, which is what lets authorization complete before
    /// any lookup.
    pub async fn sealed_action_grant_for(
        &self,
        selector: SealedGrantSelector,
    ) -> Result<Option<SealedActionGrantRow>> {
        self.read(move |conn| {
            conn.query_row(
                &format!(
                    "SELECT {GRANT_COLUMNS} FROM sealed_action_grants
                      WHERE record_id = ?1 AND action_id = ?2 AND project_key = ?3
                        AND session_id = ?4 AND session_generation = ?5"
                ),
                params![
                    selector.record_id,
                    selector.action_id,
                    selector.project_key,
                    selector.session_id,
                    selector.session_generation,
                ],
                decode_grant,
            )
            .optional()
            .context("reading sealed action grant")
        })
        .await
    }

    /// Every action grant issued for one `(session, generation)`, regardless of
    /// liveness. The caller applies revocation/expiry/version/revision liveness
    /// (the marker predicate) on top; this is a pure metadata read.
    pub async fn sealed_action_grants_for_session(
        &self,
        session_id: String,
        session_generation: i64,
    ) -> Result<Vec<SealedActionGrantRow>> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {GRANT_COLUMNS} FROM sealed_action_grants
                      WHERE session_id = ?1 AND session_generation = ?2"
                ))
                .context("preparing sealed grants for session")?;
            let rows = stmt
                .query_map(params![session_id, session_generation], decode_grant)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("reading sealed grants for session")?;
            Ok(rows)
        })
        .await
    }

    /// Deterministic compare-and-swap ownership of one use.
    ///
    /// This is the **authoritative** gate, not a formality on top of an
    /// earlier read. The `UPDATE` re-checks revocation, expiry, *and* the
    /// record's live lifecycle and version inside the writer transaction, and
    /// the locator is read back in that same transaction and returned. A
    /// caller therefore cannot resolve a literal from the stale row it read
    /// before authorization: the stale locator is not merely unused, it is
    /// unpassable, because `resolve_literal` takes what this returns.
    ///
    /// Returns `None` for the loser of a race, for a revoked or expired grant,
    /// and for a record that was deleted or rotated since it was read.
    pub async fn claim_sealed_action_grant(
        &self,
        grant_id: String,
        expected_epoch: i64,
        now_ms: i64,
    ) -> Result<Option<SealedClaimedUse>> {
        self.transaction(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE sealed_action_grants
                        SET use_epoch = use_epoch + 1
                      WHERE grant_id = ?1 AND use_epoch = ?2 AND revoked_at_ms IS NULL
                        AND (expires_at_ms IS NULL OR expires_at_ms > ?3)
                        AND EXISTS (
                            SELECT 1 FROM sealed_value_records r
                             WHERE r.record_id = sealed_action_grants.record_id
                               AND r.deleted_at_ms IS NULL
                               AND r.active_version >= 1
                               AND r.active_version = sealed_action_grants.value_version
                               AND (r.scope = 'session' OR r.compartment_key IS NOT NULL)
                        )",
                    params![grant_id, expected_epoch, now_ms],
                )
                .context("claiming sealed action grant")?;
            if changed != 1 {
                return Ok(None);
            }
            let record_id: String = conn
                .query_row(
                    "SELECT record_id FROM sealed_action_grants WHERE grant_id = ?1",
                    params![grant_id],
                    |row| row.get(0),
                )
                .context("reading claimed grant record id")?;
            let record = record_conn(conn, &record_id)?
                .context("claimed sealed value record vanished inside its own transaction")?;
            Ok(Some(SealedClaimedUse {
                grant_id,
                record_id: record.record_id,
                scope: record.scope,
                scope_key: record.scope_key,
                name: record.name,
                active_version: record.active_version,
                compartment_key: record.compartment_key,
            }))
        })
        .await
    }

    /// Revoke a grant. Revocation is one-way and denies use immediately.
    pub async fn revoke_sealed_action_grant(&self, grant_id: String, now_ms: i64) -> Result<bool> {
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE sealed_action_grants SET revoked_at_ms = ?2
                      WHERE grant_id = ?1 AND revoked_at_ms IS NULL",
                    params![grant_id, now_ms],
                )
                .context("revoking sealed action grant")?;
            Ok(changed > 0)
        })
        .await
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_saga_conn(
    conn: &Connection,
    op_id: &str,
    record_id: &str,
    kind: SealedSagaKind,
    target_version: i64,
    prepared_compartment_key: Option<&str>,
    superseded_compartment_key: Option<&str>,
    now_ms: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO sealed_value_sagas
             (op_id, record_id, kind, phase, target_version, prepared_compartment_key,
              superseded_compartment_key, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, 'prepared', ?4, ?5, ?6, ?7, ?7)",
        params![
            op_id,
            record_id,
            kind.as_str(),
            target_version,
            prepared_compartment_key,
            superseded_compartment_key,
            now_ms,
        ],
    )
    .context("staging sealed value saga")?;
    Ok(())
}

/// Remove a session-scope record, its literal and its grants, and tombstone
/// the name — on one connection, so callers can compose it into a larger
/// transaction instead of reimplementing the steps and drifting apart.
fn delete_session_sealed_value_conn(
    conn: &Connection,
    record_id: &str,
    now_ms: i64,
) -> Result<bool> {
    let Some(existing) = record_conn(conn, record_id)? else {
        return Ok(false);
    };
    if existing.scope != SealedScopeKind::Session {
        bail!("delete_session_sealed_value is only for session scope");
    }
    conn.execute(
        "INSERT OR IGNORE INTO sealed_value_name_tombstones
             (scope, scope_key, name, retired_at_ms) VALUES ('session', ?1, ?2, ?3)",
        params![existing.scope_key, existing.name, now_ms],
    )
    .context("tombstoning session sealed value name")?;
    conn.execute(
        "DELETE FROM sealed_values WHERE session_id = ?1 AND value_id = ?2",
        params![existing.scope_key, existing.name],
    )
    .context("deleting session sealed literal")?;
    revoke_grants_for_record_conn(conn, record_id, now_ms)?;
    let removed = conn
        .execute(
            "DELETE FROM sealed_value_records WHERE record_id = ?1",
            params![record_id],
        )
        .context("deleting session sealed value record")?;
    Ok(removed > 0)
}

/// Revoke every live grant on one record. Used by the transitions that make a
/// prior version or the record itself unusable.
fn revoke_grants_for_record_conn(conn: &Connection, record_id: &str, now_ms: i64) -> Result<()> {
    conn.execute(
        "UPDATE sealed_action_grants SET revoked_at_ms = ?2
          WHERE record_id = ?1 AND revoked_at_ms IS NULL",
        params![record_id, now_ms],
    )
    .context("fencing sealed action grants")?;
    Ok(())
}

fn mark_saga_committed_conn(conn: &Connection, record_id: &str, now_ms: i64) -> Result<()> {
    conn.execute(
        "UPDATE sealed_value_sagas SET phase = 'committed', updated_at_ms = ?2
          WHERE record_id = ?1",
        params![record_id, now_ms],
    )
    .context("committing sealed value saga")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_record(scope: SealedScopeKind, scope_key: &str, name: &str) -> NewSealedValueRecord {
        NewSealedValueRecord {
            record_id: uuid::Uuid::new_v4().to_string(),
            scope,
            scope_key: scope_key.to_string(),
            name: name.to_string(),
            description: "deployment credential".to_string(),
            owner_principal: "owner".to_string(),
            created_at_ms: 1_000,
        }
    }

    /// Seed a live session-scope sealed value: a `sessions` row (the literal
    /// table has a foreign key to it), its record, and its literal.
    async fn seeded_session_value(db: &Db) -> (String, String) {
        let session = db.create_session("p", "/repo", "Build").await.unwrap();
        let session_key = session.session_id.to_string();
        let record = new_record(SealedScopeKind::Session, &session_key, "prod_token");
        db.create_session_sealed_value(
            record.clone(),
            "SECRET".into(),
            "deploy".into(),
            "user".into(),
        )
        .await
        .unwrap();
        (session_key, record.record_id)
    }

    /// Stage the state an older binary could leave behind: a session record
    /// soft-deleted with a `delete` saga open over it. Written with raw SQL
    /// precisely because the guard under test now refuses to produce it.
    async fn stage_stale_session_delete_saga(db: &Db, record_id: &str) {
        let record_id = record_id.to_string();
        db.transaction(move |conn| {
            conn.execute(
                "UPDATE sealed_value_records SET deleted_at_ms = 2000 WHERE record_id = ?1",
                params![record_id],
            )?;
            conn.execute(
                "INSERT INTO sealed_value_sagas
                     (op_id, record_id, kind, phase, target_version,
                      prepared_compartment_key, superseded_compartment_key,
                      created_at_ms, updated_at_ms)
                 VALUES ('stale-op', ?1, 'delete', 'prepared', 1, NULL, NULL, 2000, 2000)",
                params![record_id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    /// The saga carries only compartment locators, and a session record has
    /// none — so the generic delete saga can never reclaim a session literal.
    /// It must refuse rather than half-delete, exactly as rotate does.
    #[tokio::test]
    async fn generic_delete_saga_refuses_session_scope() {
        let db = Db::open_in_memory().unwrap();
        let (session_key, record_id) = seeded_session_value(&db).await;

        let err = db
            .prepare_sealed_value_delete(record_id.clone(), "op-1".into(), 2_000)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("single store"), "unexpected error: {err}");

        // The refusal left the value completely intact: still resolvable, its
        // literal still present, and its name not retired.
        let row = db
            .sealed_value_record(record_id)
            .await
            .unwrap()
            .expect("record survives a refused delete");
        assert!(row.is_resolvable());
        let session_uuid = uuid::Uuid::parse_str(&session_key).unwrap();
        assert!(
            db.sealed_value_exists(session_uuid, "prod_token")
                .await
                .unwrap()
        );
        assert!(
            !db.sealed_value_name_retired(
                SealedScopeKind::Session,
                session_key,
                "prod_token".into()
            )
            .await
            .unwrap()
        );
    }

    /// Recovery drives committed sagas straight into `commit_sealed_value_
    /// delete` and cannot filter by scope, because a saga row carries none.
    /// A stale session row must therefore be finished through the shared
    /// cleanup — never by dropping the record and stranding its literal.
    #[tokio::test]
    async fn committing_a_stale_session_delete_saga_clears_both_stores() {
        let db = Db::open_in_memory().unwrap();
        let (session_key, record_id) = seeded_session_value(&db).await;
        stage_stale_session_delete_saga(&db, &record_id).await;

        assert!(
            db.commit_sealed_value_delete(record_id.clone(), 3_000)
                .await
                .unwrap()
        );

        assert!(db.sealed_value_record(record_id).await.unwrap().is_none());
        let session_uuid = uuid::Uuid::parse_str(&session_key).unwrap();
        assert!(
            !db.sealed_value_exists(session_uuid, "prod_token")
                .await
                .unwrap(),
            "literal must not survive the record"
        );
        assert!(
            db.sealed_value_name_retired(
                SealedScopeKind::Session,
                session_key,
                "prod_token".into()
            )
            .await
            .unwrap(),
            "the shared cleanup path always tombstones the name"
        );
    }

    /// The daemon's delete-by-name path used to skip soft-deleted records and
    /// fall through to a legacy-only delete, which removed the literal and
    /// left the record behind. Any session record matching the name wins now.
    #[tokio::test]
    async fn deleting_by_session_key_cleans_up_a_half_deleted_record() {
        let db = Db::open_in_memory().unwrap();
        let (session_key, record_id) = seeded_session_value(&db).await;
        stage_stale_session_delete_saga(&db, &record_id).await;

        assert!(
            db.delete_sealed_value_for_session(session_key.clone(), "prod_token".into(), 3_000)
                .await
                .unwrap()
        );

        assert!(
            db.sealed_value_record(record_id).await.unwrap().is_none(),
            "the record must not outlive its literal"
        );
        let session_uuid = uuid::Uuid::parse_str(&session_key).unwrap();
        assert!(
            !db.sealed_value_exists(session_uuid, "prod_token")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn staged_record_is_not_resolvable_until_create_commits() {
        let db = Db::open_in_memory().unwrap();
        let record = new_record(SealedScopeKind::Project, "proj", "deploy_token");
        let staged = db
            .prepare_sealed_value_create(record.clone(), "op-1".into(), Some("locator-a".into()))
            .await
            .unwrap();
        assert!(!staged.is_resolvable());
        assert_eq!(staged.active_version, 0);

        let committed = db
            .commit_sealed_value_create(record.record_id.clone(), Some("locator-a".into()), 2_000)
            .await
            .unwrap();
        assert!(committed.is_resolvable());
        assert_eq!(committed.active_version, 1);
    }

    #[tokio::test]
    async fn rotation_keeps_previous_version_live_until_commit() {
        let db = Db::open_in_memory().unwrap();
        let record = new_record(SealedScopeKind::Global, "", "org_token");
        db.prepare_sealed_value_create(record.clone(), "op-1".into(), Some("locator-a".into()))
            .await
            .unwrap();
        db.commit_sealed_value_create(record.record_id.clone(), Some("locator-a".into()), 2_000)
            .await
            .unwrap();
        db.finish_sealed_value_saga("op-1".into()).await.unwrap();

        let target = db
            .prepare_sealed_value_rotate(
                record.record_id.clone(),
                "op-2".into(),
                "locator-b".into(),
                3_000,
            )
            .await
            .unwrap();
        assert_eq!(target, 2);
        let mid = db
            .sealed_value_record(record.record_id.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mid.active_version, 1, "old version stays live while staged");
        assert_eq!(mid.compartment_key.as_deref(), Some("locator-a"));

        let rotated = db
            .commit_sealed_value_rotate(record.record_id.clone(), 4_000)
            .await
            .unwrap();
        assert_eq!(rotated.active_version, 2);
        assert_eq!(rotated.compartment_key.as_deref(), Some("locator-b"));
    }

    #[tokio::test]
    async fn deleted_names_are_never_reused() {
        let db = Db::open_in_memory().unwrap();
        let record = new_record(SealedScopeKind::Project, "proj", "deploy_token");
        db.prepare_sealed_value_create(record.clone(), "op-1".into(), Some("locator-a".into()))
            .await
            .unwrap();
        db.commit_sealed_value_create(record.record_id.clone(), Some("locator-a".into()), 2_000)
            .await
            .unwrap();
        db.prepare_sealed_value_delete(record.record_id.clone(), "op-2".into(), 3_000)
            .await
            .unwrap();
        db.commit_sealed_value_delete(record.record_id.clone(), 3_100)
            .await
            .unwrap();

        let again = new_record(SealedScopeKind::Project, "proj", "deploy_token");
        let error = db
            .prepare_sealed_value_create(again, "op-3".into(), Some("locator-c".into()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("never reused"), "{error}");
    }

    #[tokio::test]
    async fn grant_claim_is_a_deterministic_compare_and_swap() {
        let db = Db::open_in_memory().unwrap();
        // A grant cascades from its session, so the session must exist.
        let session = db.create_session("proj", "/repo", "Build").await.unwrap();
        let session_id = session.session_id.to_string();
        let record = new_record(SealedScopeKind::Project, "proj", "deploy_token");
        db.prepare_sealed_value_create(record.clone(), "op-1".into(), Some("locator-a".into()))
            .await
            .unwrap();
        db.commit_sealed_value_create(record.record_id.clone(), Some("locator-a".into()), 2_000)
            .await
            .unwrap();

        let grant = db
            .issue_sealed_action_grant(NewSealedActionGrant {
                grant_id: "grant-1".into(),
                record_id: record.record_id.clone(),
                value_version: 1,
                project_key: "proj".into(),
                session_id: session_id.clone(),
                session_generation: 0,
                action_id: "act".into(),
                action_revision: 1,
                issued_at_ms: 2_100,
                expires_at_ms: None,
            })
            .await
            .unwrap();
        assert_eq!(grant.use_epoch, 0);

        // The winner gets the locator, read inside the claiming transaction.
        let claimed = db
            .claim_sealed_action_grant("grant-1".into(), 0, 2_200)
            .await
            .unwrap()
            .expect("first claim wins");
        assert_eq!(claimed.active_version, 1);
        assert_eq!(claimed.compartment_key.as_deref(), Some("locator-a"));
        assert!(
            db.claim_sealed_action_grant("grant-1".into(), 0, 2_200)
                .await
                .unwrap()
                .is_none(),
            "the loser of the race claims nothing"
        );
        assert!(
            db.claim_sealed_action_grant("grant-1".into(), 1, 2_300)
                .await
                .unwrap()
                .is_some()
        );

        db.revoke_sealed_action_grant("grant-1".into(), 2_400)
            .await
            .unwrap();
        assert!(
            db.claim_sealed_action_grant("grant-1".into(), 2, 2_500)
                .await
                .unwrap()
                .is_none(),
            "a revoked grant is never claimable"
        );
    }

    /// The claim is authoritative: a record made non-resolvable after
    /// authorization read it cannot be claimed, so no stale locator escapes.
    #[tokio::test]
    async fn claim_refuses_a_record_deleted_or_rotated_since_authorization() {
        for transition in ["delete", "rotate"] {
            let db = Db::open_in_memory().unwrap();
            let session = db.create_session("proj", "/repo", "Build").await.unwrap();
            let session_id = session.session_id.to_string();
            let record = new_record(SealedScopeKind::Project, "proj", "deploy_token");
            db.prepare_sealed_value_create(record.clone(), "op-1".into(), Some("locator-a".into()))
                .await
                .unwrap();
            db.commit_sealed_value_create(
                record.record_id.clone(),
                Some("locator-a".into()),
                2_000,
            )
            .await
            .unwrap();
            db.finish_sealed_value_saga("op-1".into()).await.unwrap();
            db.issue_sealed_action_grant(NewSealedActionGrant {
                grant_id: "grant-1".into(),
                record_id: record.record_id.clone(),
                value_version: 1,
                project_key: "proj".into(),
                session_id: session_id.clone(),
                session_generation: 0,
                action_id: "act".into(),
                action_revision: 1,
                issued_at_ms: 2_100,
                expires_at_ms: None,
            })
            .await
            .unwrap();

            if transition == "delete" {
                db.prepare_sealed_value_delete(record.record_id.clone(), "op-2".into(), 3_000)
                    .await
                    .unwrap();
            } else {
                db.prepare_sealed_value_rotate(
                    record.record_id.clone(),
                    "op-2".into(),
                    "locator-b".into(),
                    3_000,
                )
                .await
                .unwrap();
                db.commit_sealed_value_rotate(record.record_id.clone(), 3_100)
                    .await
                    .unwrap();
            }

            assert!(
                db.claim_sealed_action_grant("grant-1".into(), 0, 3_200)
                    .await
                    .unwrap()
                    .is_none(),
                "a grant must not be claimable after a {transition}"
            );
        }
    }
}
