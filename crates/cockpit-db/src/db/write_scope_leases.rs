//! Durable hierarchical write-scope leases, transfers, and permits.
//!
//! A **lease** is one owner's exclusive write authority over a canonical
//! directory subtree. A **transfer** moves a strict sub-scope from a parent
//! lease to a child lease through an ordered, crash-safe phase sequence. A
//! **permit** is the durable-generation right to perform one filesystem
//! mutation, or to run arbitrary user code that can influence a scope.
//!
//! This module is storage only: it enforces compare-and-swap, generation
//! monotonicity, and phase ordering, but it never decides policy. Containment,
//! backend capability, and barrier ordering live in
//! `cockpit-core::write_scope`.
//!
//! Rows carry canonical paths and opaque owner ids — never commands,
//! environment, output, or secrets.

use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// Valid durable lease states.
pub const LEASE_STATES: &[&str] = &[
    "active",
    "transferring",
    "delegated",
    "returning",
    "released",
];
pub const LEASE_TERMINAL_STATES: &[&str] = &["released"];

/// Valid durable transfer phases, in advance order.
pub const TRANSFER_PHASES: &[&str] = &[
    "prepared",
    "parent_excluded",
    "child_activated",
    "child_terminal",
    "parent_restored",
    "committed",
];

/// Valid permit kinds.
pub const PERMIT_KINDS: &[&str] = &["mutation", "execution"];

/// Ordinal of a transfer phase, matching the SQL adjacency trigger.
pub fn transfer_phase_ordinal(phase: &str) -> Option<usize> {
    TRANSFER_PHASES.iter().position(|p| *p == phase)
}

/// The legal authority transition graph. Duplicated here (not imported from
/// `cockpit-core`, which sits above this crate) so the storage layer refuses an
/// illegal transition on its own rather than trusting its caller. The SQL
/// trigger `write_scope_leases_legal_transition` enforces the same set.
pub const LEGAL_LEASE_TRANSITIONS: &[(&str, &str)] = &[
    ("active", "transferring"),
    ("active", "released"),
    ("transferring", "delegated"),
    ("transferring", "active"),
    ("delegated", "transferring"),
    ("delegated", "returning"),
    ("delegated", "released"),
    ("returning", "active"),
    ("returning", "delegated"),
    ("returning", "released"),
];

pub fn is_legal_lease_transition(from: &str, to: &str) -> bool {
    LEGAL_LEASE_TRANSITIONS.contains(&(from, to))
}

// ---------------------------------------------------------------------------
// leases
// ---------------------------------------------------------------------------

/// One owner's durable write authority over a canonical subtree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteScopeLeaseRow {
    pub lease_id: Uuid,
    pub parent_lease_id: Option<Uuid>,
    pub session_id: Uuid,
    pub task_id: Option<String>,
    pub scope_path: String,
    pub generation: u64,
    pub state: String,
    pub owner_id: String,
    pub version: u64,
    pub created_at_wall_ms: i64,
    pub updated_at_wall_ms: i64,
    pub released_at_wall_ms: Option<i64>,
}

const LEASE_COLS: &str = "lease_id, parent_lease_id, session_id, task_id, scope_path, \
    generation, state, owner_id, version, created_at_wall_ms, updated_at_wall_ms, \
    released_at_wall_ms";

fn parse_uuid(raw: &str, idx: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn map_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<WriteScopeLeaseRow> {
    let parent: Option<String> = row.get(1)?;
    Ok(WriteScopeLeaseRow {
        lease_id: parse_uuid(&row.get::<_, String>(0)?, 0)?,
        parent_lease_id: match parent {
            Some(raw) => Some(parse_uuid(&raw, 1)?),
            None => None,
        },
        session_id: parse_uuid(&row.get::<_, String>(2)?, 2)?,
        task_id: row.get(3)?,
        scope_path: row.get(4)?,
        generation: row.get::<_, i64>(5)? as u64,
        state: row.get(6)?,
        owner_id: row.get(7)?,
        version: row.get::<_, i64>(8)? as u64,
        created_at_wall_ms: row.get(9)?,
        updated_at_wall_ms: row.get(10)?,
        released_at_wall_ms: row.get(11)?,
    })
}

/// Compare-and-swap inputs for a lease authority transition.
///
/// Every field of the expectation must match or the CAS returns `None`. A
/// losing contender therefore never mutates authority.
#[derive(Debug, Clone)]
pub struct CasWriteScopeLease {
    pub lease_id: Uuid,
    pub expected_state: String,
    pub expected_generation: u64,
    pub expected_version: u64,
    pub new_state: String,
    /// New generation. Must be >= the expected generation; the SQL trigger
    /// rejects any decrement even if a caller miscomputes.
    pub new_generation: u64,
    pub now_wall_ms: i64,
    pub released: bool,
}

// ---------------------------------------------------------------------------
// transfers
// ---------------------------------------------------------------------------

/// One parent→child strict sub-scope delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteScopeTransferRow {
    pub transfer_id: Uuid,
    pub session_id: Uuid,
    pub parent_lease_id: Uuid,
    pub child_lease_id: Option<Uuid>,
    pub sub_scope_path: String,
    pub phase: String,
    pub prepare_parent_generation: u64,
    pub parent_generation: u64,
    pub child_generation: Option<u64>,
    pub restored_parent_generation: Option<u64>,
    pub backend_kind: String,
    pub capability: String,
    pub unsupported_reason: Option<String>,
    pub containment_id: Option<Uuid>,
    /// The containment's own generation counter — never a lease generation.
    pub containment_generation: Option<u64>,
    /// Inode identity recorded for the publication target at child start.
    pub publication_identity: Option<String>,
    pub execution_permit_id: Option<Uuid>,
    pub recovery_phase: Option<String>,
    pub version: u64,
    pub created_at_wall_ms: i64,
    pub updated_at_wall_ms: i64,
}

const TRANSFER_COLS: &str = "transfer_id, session_id, parent_lease_id, child_lease_id, \
    sub_scope_path, phase, prepare_parent_generation, parent_generation, child_generation, \
    restored_parent_generation, backend_kind, capability, unsupported_reason, containment_id, \
    containment_generation, publication_identity, execution_permit_id, recovery_phase, version, \
    created_at_wall_ms, updated_at_wall_ms";

fn map_transfer(row: &rusqlite::Row<'_>) -> rusqlite::Result<WriteScopeTransferRow> {
    let child: Option<String> = row.get(3)?;
    let containment: Option<String> = row.get(13)?;
    let permit: Option<String> = row.get(16)?;
    Ok(WriteScopeTransferRow {
        transfer_id: parse_uuid(&row.get::<_, String>(0)?, 0)?,
        session_id: parse_uuid(&row.get::<_, String>(1)?, 1)?,
        parent_lease_id: parse_uuid(&row.get::<_, String>(2)?, 2)?,
        child_lease_id: match child {
            Some(raw) => Some(parse_uuid(&raw, 3)?),
            None => None,
        },
        sub_scope_path: row.get(4)?,
        phase: row.get(5)?,
        prepare_parent_generation: row.get::<_, i64>(6)? as u64,
        parent_generation: row.get::<_, i64>(7)? as u64,
        child_generation: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
        restored_parent_generation: row.get::<_, Option<i64>>(9)?.map(|v| v as u64),
        backend_kind: row.get(10)?,
        capability: row.get(11)?,
        unsupported_reason: row.get(12)?,
        containment_id: match containment {
            Some(raw) => Some(parse_uuid(&raw, 13)?),
            None => None,
        },
        containment_generation: row.get::<_, Option<i64>>(14)?.map(|v| v as u64),
        publication_identity: row.get(15)?,
        execution_permit_id: match permit {
            Some(raw) => Some(parse_uuid(&raw, 16)?),
            None => None,
        },
        recovery_phase: row.get(17)?,
        version: row.get::<_, i64>(18)? as u64,
        created_at_wall_ms: row.get(19)?,
        updated_at_wall_ms: row.get(20)?,
    })
}

/// Compare-and-swap inputs for a transfer phase advance.
#[derive(Debug, Clone)]
pub struct CasWriteScopeTransfer {
    pub transfer_id: Uuid,
    pub expected_phase: String,
    pub expected_version: u64,
    pub new_phase: String,
    pub now_wall_ms: i64,
    /// Set at ChildActivated. Write-once (SQL trigger).
    pub child_lease_id: Option<Uuid>,
    pub parent_generation: Option<u64>,
    pub child_generation: Option<u64>,
    pub restored_parent_generation: Option<u64>,
    pub containment_id: Option<Uuid>,
    pub containment_generation: Option<u64>,
    pub publication_identity: Option<Option<String>>,
    pub execution_permit_id: Option<Uuid>,
    pub recovery_phase: Option<Option<String>>,
}

// ---------------------------------------------------------------------------
// permits
// ---------------------------------------------------------------------------

/// A durable-generation mutation or execution-wide write permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteScopePermitRow {
    pub permit_id: Uuid,
    pub session_id: Uuid,
    pub lease_id: Uuid,
    pub generation: u64,
    pub kind: String,
    /// The filesystem operation this permit protects (`write_content`,
    /// `rename`, `symlink`, ...). Drives the conflict rule.
    pub influence_kind: String,
    /// Highest ancestor whose namespace this operation can influence. Overlap
    /// is computed against this, never the bare target path.
    pub influence_root: String,
    pub target_path: String,
    pub state: String,
    pub containment_id: Option<Uuid>,
    pub acquired_at_wall_ms: i64,
    pub released_at_wall_ms: Option<i64>,
}

const PERMIT_COLS: &str = "permit_id, session_id, lease_id, generation, kind, influence_kind, \
    influence_root, target_path, state, containment_id, acquired_at_wall_ms, released_at_wall_ms";

fn map_permit(row: &rusqlite::Row<'_>) -> rusqlite::Result<WriteScopePermitRow> {
    let containment: Option<String> = row.get(9)?;
    Ok(WriteScopePermitRow {
        permit_id: parse_uuid(&row.get::<_, String>(0)?, 0)?,
        session_id: parse_uuid(&row.get::<_, String>(1)?, 1)?,
        lease_id: parse_uuid(&row.get::<_, String>(2)?, 2)?,
        generation: row.get::<_, i64>(3)? as u64,
        kind: row.get(4)?,
        influence_kind: row.get(5)?,
        influence_root: row.get(6)?,
        target_path: row.get(7)?,
        state: row.get(8)?,
        containment_id: match containment {
            Some(raw) => Some(parse_uuid(&raw, 9)?),
            None => None,
        },
        acquired_at_wall_ms: row.get(10)?,
        released_at_wall_ms: row.get(11)?,
    })
}

impl Db {
    // ---- leases -----------------------------------------------------------

    /// Insert a lease. Used for the session root authority and for a delegated
    /// child at ChildActivated.
    pub async fn insert_write_scope_lease(
        &self,
        row: WriteScopeLeaseRow,
    ) -> Result<WriteScopeLeaseRow> {
        if !LEASE_STATES.contains(&row.state.as_str()) {
            bail!("invalid write scope lease state {}", row.state);
        }
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO write_scope_leases (
                    lease_id, parent_lease_id, session_id, task_id, scope_path, generation,
                    state, owner_id, version, created_at_wall_ms, updated_at_wall_ms,
                    released_at_wall_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    row.lease_id.to_string(),
                    row.parent_lease_id.map(|id| id.to_string()),
                    row.session_id.to_string(),
                    row.task_id,
                    row.scope_path,
                    row.generation as i64,
                    row.state,
                    row.owner_id,
                    row.version as i64,
                    row.created_at_wall_ms,
                    row.updated_at_wall_ms,
                    row.released_at_wall_ms,
                ],
            )
            .context("inserting write_scope_lease")?;
            get_lease_conn(conn, row.lease_id)?
                .ok_or_else(|| anyhow::anyhow!("write_scope_lease missing after insert"))
        })
        .await
    }

    pub async fn get_write_scope_lease(
        &self,
        lease_id: Uuid,
    ) -> Result<Option<WriteScopeLeaseRow>> {
        self.read(move |conn| get_lease_conn(conn, lease_id)).await
    }

    /// Compare-and-swap a lease's authority state.
    ///
    /// Returns `None` when the expectation (state + generation + version) does
    /// not match — a stale contender loses without mutating authority. On
    /// success the version always advances, which is what makes concurrent
    /// same-parent transfers linearize.
    pub async fn cas_write_scope_lease(
        &self,
        cas: CasWriteScopeLease,
    ) -> Result<Option<WriteScopeLeaseRow>> {
        if !LEASE_STATES.contains(&cas.expected_state.as_str()) {
            bail!("invalid expected lease state {}", cas.expected_state);
        }
        if !LEASE_STATES.contains(&cas.new_state.as_str()) {
            bail!("invalid new lease state {}", cas.new_state);
        }
        if cas.new_generation < cas.expected_generation {
            bail!(
                "lease generation would decrement: {} -> {}",
                cas.expected_generation,
                cas.new_generation
            );
        }
        // The storage layer refuses an illegal transition itself; it does not
        // trust the caller to have checked. `active -> delegated` would skip the
        // exclusion barrier, `released -> *` would resurrect dead authority.
        if cas.expected_state != cas.new_state
            && !is_legal_lease_transition(&cas.expected_state, &cas.new_state)
        {
            bail!(
                "illegal write scope lease transition: {} -> {}",
                cas.expected_state,
                cas.new_state
            );
        }
        self.write(move |conn| {
            let released_at = if cas.released {
                Some(cas.now_wall_ms)
            } else {
                None
            };
            let n = conn
                .execute(
                    "UPDATE write_scope_leases SET
                        state = ?1,
                        generation = ?2,
                        version = version + 1,
                        updated_at_wall_ms = ?3,
                        released_at_wall_ms = COALESCE(?4, released_at_wall_ms)
                     WHERE lease_id = ?5
                       AND state = ?6
                       AND generation = ?7
                       AND version = ?8",
                    params![
                        cas.new_state,
                        cas.new_generation as i64,
                        cas.now_wall_ms,
                        released_at,
                        cas.lease_id.to_string(),
                        cas.expected_state,
                        cas.expected_generation as i64,
                        cas.expected_version as i64,
                    ],
                )
                .context("cas write_scope_lease")?;
            if n == 0 {
                return Ok(None);
            }
            get_lease_conn(conn, cas.lease_id)
        })
        .await
    }

    pub async fn list_write_scope_leases_for_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<WriteScopeLeaseRow>> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {LEASE_COLS} FROM write_scope_leases
                     WHERE session_id = ?1 ORDER BY created_at_wall_ms ASC, lease_id ASC"
                ))
                .context("preparing list_write_scope_leases_for_session")?;
            let rows = stmt
                .query_map(params![session_id.to_string()], map_lease)
                .context("querying write scope leases")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding write_scope_lease")?);
            }
            Ok(out)
        })
        .await
    }

    /// Direct children of a lease, in creation order.
    pub async fn list_child_write_scope_leases(
        &self,
        parent_lease_id: Uuid,
    ) -> Result<Vec<WriteScopeLeaseRow>> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {LEASE_COLS} FROM write_scope_leases
                     WHERE parent_lease_id = ?1 ORDER BY created_at_wall_ms ASC, lease_id ASC"
                ))
                .context("preparing list_child_write_scope_leases")?;
            let rows = stmt
                .query_map(params![parent_lease_id.to_string()], map_lease)
                .context("querying child write scope leases")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding write_scope_lease")?);
            }
            Ok(out)
        })
        .await
    }

    /// Leases that still hold authority (block session deletion / clean
    /// shutdown until released).
    pub async fn list_live_write_scope_leases(
        &self,
        session_id: Option<Uuid>,
    ) -> Result<Vec<WriteScopeLeaseRow>> {
        self.read(move |conn| {
            let mut out = Vec::new();
            match session_id {
                Some(session_id) => {
                    let mut stmt = conn
                        .prepare(&format!(
                            "SELECT {LEASE_COLS} FROM write_scope_leases
                             WHERE session_id = ?1 AND state != 'released'
                             ORDER BY created_at_wall_ms ASC, lease_id ASC"
                        ))
                        .context("preparing live session leases")?;
                    let rows = stmt
                        .query_map(params![session_id.to_string()], map_lease)
                        .context("querying live session leases")?;
                    for row in rows {
                        out.push(row.context("decoding write_scope_lease")?);
                    }
                }
                None => {
                    let mut stmt = conn
                        .prepare(&format!(
                            "SELECT {LEASE_COLS} FROM write_scope_leases
                             WHERE state != 'released'
                             ORDER BY created_at_wall_ms ASC, lease_id ASC"
                        ))
                        .context("preparing live leases")?;
                    let rows = stmt
                        .query_map([], map_lease)
                        .context("querying live leases")?;
                    for row in rows {
                        out.push(row.context("decoding write_scope_lease")?);
                    }
                }
            }
            Ok(out)
        })
        .await
    }

    // ---- transfers --------------------------------------------------------

    pub async fn insert_write_scope_transfer(
        &self,
        row: WriteScopeTransferRow,
    ) -> Result<WriteScopeTransferRow> {
        if !TRANSFER_PHASES.contains(&row.phase.as_str()) {
            bail!("invalid write scope transfer phase {}", row.phase);
        }
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO write_scope_transfers (
                    transfer_id, session_id, parent_lease_id, child_lease_id, sub_scope_path,
                    phase, prepare_parent_generation, parent_generation, child_generation,
                    restored_parent_generation, backend_kind, capability, unsupported_reason,
                    containment_id, containment_generation, publication_identity,
                    execution_permit_id, recovery_phase, version,
                    created_at_wall_ms, updated_at_wall_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                           ?16, ?17, ?18, ?19, ?20, ?21)",
                params![
                    row.transfer_id.to_string(),
                    row.session_id.to_string(),
                    row.parent_lease_id.to_string(),
                    row.child_lease_id.map(|id| id.to_string()),
                    row.sub_scope_path,
                    row.phase,
                    row.prepare_parent_generation as i64,
                    row.parent_generation as i64,
                    row.child_generation.map(|v| v as i64),
                    row.restored_parent_generation.map(|v| v as i64),
                    row.backend_kind,
                    row.capability,
                    row.unsupported_reason,
                    row.containment_id.map(|id| id.to_string()),
                    row.containment_generation.map(|v| v as i64),
                    row.publication_identity,
                    row.execution_permit_id.map(|id| id.to_string()),
                    row.recovery_phase,
                    row.version as i64,
                    row.created_at_wall_ms,
                    row.updated_at_wall_ms,
                ],
            )
            .context("inserting write_scope_transfer")?;
            get_transfer_conn(conn, row.transfer_id)?
                .ok_or_else(|| anyhow::anyhow!("write_scope_transfer missing after insert"))
        })
        .await
    }

    /// Atomically perform the Prepared CAS on the parent lease **and** insert
    /// the transfer row.
    ///
    /// These must not be two autocommits: a crash between them would leave the
    /// parent stranded in `transferring` with no row for
    /// [`Self::list_open_write_scope_transfers`] to reconcile, so its authority
    /// could never be recovered. Returns `None` when the CAS loses, in which
    /// case no transfer row is written either.
    pub async fn prepare_write_scope_transfer(
        &self,
        cas: CasWriteScopeLease,
        row: WriteScopeTransferRow,
    ) -> Result<Option<(WriteScopeLeaseRow, WriteScopeTransferRow)>> {
        if !is_legal_lease_transition(&cas.expected_state, &cas.new_state) {
            bail!(
                "illegal write scope lease transition: {} -> {}",
                cas.expected_state,
                cas.new_state
            );
        }
        if cas.new_generation < cas.expected_generation {
            bail!("lease generation would decrement");
        }
        self.write(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let updated = tx
                .execute(
                    "UPDATE write_scope_leases SET
                        state = ?1,
                        generation = ?2,
                        version = version + 1,
                        updated_at_wall_ms = ?3
                     WHERE lease_id = ?4 AND state = ?5 AND generation = ?6 AND version = ?7",
                    params![
                        cas.new_state,
                        cas.new_generation as i64,
                        cas.now_wall_ms,
                        cas.lease_id.to_string(),
                        cas.expected_state,
                        cas.expected_generation as i64,
                        cas.expected_version as i64,
                    ],
                )
                .context("prepare: cas parent lease")?;
            if updated == 0 {
                // Lost the race. Roll back so no transfer row exists either.
                tx.rollback().ok();
                return Ok(None);
            }
            tx.execute(
                "INSERT INTO write_scope_transfers (
                    transfer_id, session_id, parent_lease_id, child_lease_id, sub_scope_path,
                    phase, prepare_parent_generation, parent_generation, child_generation,
                    restored_parent_generation, backend_kind, capability, unsupported_reason,
                    containment_id, containment_generation, publication_identity,
                    execution_permit_id, recovery_phase, version,
                    created_at_wall_ms, updated_at_wall_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                           ?16, ?17, ?18, ?19, ?20, ?21)",
                params![
                    row.transfer_id.to_string(),
                    row.session_id.to_string(),
                    row.parent_lease_id.to_string(),
                    row.child_lease_id.map(|id| id.to_string()),
                    row.sub_scope_path,
                    row.phase,
                    row.prepare_parent_generation as i64,
                    row.parent_generation as i64,
                    row.child_generation.map(|v| v as i64),
                    row.restored_parent_generation.map(|v| v as i64),
                    row.backend_kind,
                    row.capability,
                    row.unsupported_reason,
                    row.containment_id.map(|id| id.to_string()),
                    row.containment_generation.map(|v| v as i64),
                    row.publication_identity,
                    row.execution_permit_id.map(|id| id.to_string()),
                    row.recovery_phase,
                    row.version as i64,
                    row.created_at_wall_ms,
                    row.updated_at_wall_ms,
                ],
            )
            .context("prepare: insert transfer")?;
            let lease = get_lease_conn(&tx, cas.lease_id)?
                .ok_or_else(|| anyhow::anyhow!("lease missing after prepare"))?;
            let transfer = get_transfer_conn(&tx, row.transfer_id)?
                .ok_or_else(|| anyhow::anyhow!("transfer missing after prepare"))?;
            tx.commit()?;
            Ok(Some((lease, transfer)))
        })
        .await
    }

    /// Durably attach a containment ticket, its generation, the execution
    /// permit, and the publication identity to a transfer that is still at
    /// `prepared`.
    ///
    /// This runs *before* user code is released. Without it a crash between
    /// releasing user code and the ParentExcluded CAS would leave a transfer
    /// that looks like it never activated, so recovery would retire it and
    /// restore parent authority while the child's code was still running.
    ///
    /// Deliberately does not bump `version`: the caller holds the coordinator's
    /// serial lock for the whole transfer, so no concurrent phase CAS exists,
    /// and leaving the version alone keeps the caller's captured row valid.
    pub async fn attach_write_scope_transfer_ownership(
        &self,
        transfer_id: Uuid,
        containment_id: Uuid,
        containment_generation: u64,
        execution_permit_id: Uuid,
        publication_identity: Option<String>,
        now_wall_ms: i64,
    ) -> Result<Option<WriteScopeTransferRow>> {
        self.write(move |conn| {
            let n = conn
                .execute(
                    "UPDATE write_scope_transfers SET
                        containment_id = ?1,
                        containment_generation = ?2,
                        execution_permit_id = ?3,
                        publication_identity = ?4,
                        updated_at_wall_ms = ?5
                     WHERE transfer_id = ?6 AND phase = 'prepared'",
                    params![
                        containment_id.to_string(),
                        containment_generation as i64,
                        execution_permit_id.to_string(),
                        publication_identity,
                        now_wall_ms,
                        transfer_id.to_string(),
                    ],
                )
                .context("attach write_scope_transfer ownership")?;
            if n == 0 {
                return Ok(None);
            }
            get_transfer_conn(conn, transfer_id)
        })
        .await
    }

    /// Activate the delegated child atomically: insert the child lease, attach
    /// it to the transfer (ChildActivated), and move the parent to Delegated —
    /// all in ONE transaction.
    ///
    /// As three separate commits a crash after the insert left an orphan
    /// `active` child lease while the transfer still had no `child_lease_id`;
    /// recovery would then treat the transfer as never-activated, retire it and
    /// reactivate the parent, so parent and orphan child both held authority
    /// over the same subtree.
    #[allow(clippy::too_many_arguments)]
    pub async fn activate_write_scope_child(
        &self,
        child: WriteScopeLeaseRow,
        transfer_cas: CasWriteScopeTransfer,
        parent_cas: CasWriteScopeLease,
    ) -> Result<
        Option<(
            WriteScopeLeaseRow,
            WriteScopeTransferRow,
            WriteScopeLeaseRow,
        )>,
    > {
        if !is_legal_lease_transition(&parent_cas.expected_state, &parent_cas.new_state) {
            bail!(
                "illegal write scope lease transition: {} -> {}",
                parent_cas.expected_state,
                parent_cas.new_state
            );
        }
        self.write(move |conn| {
            let tx = conn.unchecked_transaction()?;

            tx.execute(
                "INSERT INTO write_scope_leases (
                    lease_id, parent_lease_id, session_id, task_id, scope_path, generation,
                    state, owner_id, version, created_at_wall_ms, updated_at_wall_ms,
                    released_at_wall_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    child.lease_id.to_string(),
                    child.parent_lease_id.map(|id| id.to_string()),
                    child.session_id.to_string(),
                    child.task_id,
                    child.scope_path,
                    child.generation as i64,
                    child.state,
                    child.owner_id,
                    child.version as i64,
                    child.created_at_wall_ms,
                    child.updated_at_wall_ms,
                    child.released_at_wall_ms,
                ],
            )
            .context("activate: insert child lease")?;

            let attached = tx
                .execute(
                    "UPDATE write_scope_transfers SET
                        phase = ?1,
                        child_lease_id = ?2,
                        child_generation = ?3,
                        version = version + 1,
                        updated_at_wall_ms = ?4
                     WHERE transfer_id = ?5 AND phase = ?6 AND version = ?7",
                    params![
                        transfer_cas.new_phase,
                        child.lease_id.to_string(),
                        transfer_cas.child_generation.map(|v| v as i64),
                        transfer_cas.now_wall_ms,
                        transfer_cas.transfer_id.to_string(),
                        transfer_cas.expected_phase,
                        transfer_cas.expected_version as i64,
                    ],
                )
                .context("activate: attach child to transfer")?;
            if attached == 0 {
                tx.rollback().ok();
                return Ok(None);
            }

            let moved = tx
                .execute(
                    "UPDATE write_scope_leases SET
                        state = ?1,
                        generation = ?2,
                        version = version + 1,
                        updated_at_wall_ms = ?3
                     WHERE lease_id = ?4 AND state = ?5 AND generation = ?6 AND version = ?7",
                    params![
                        parent_cas.new_state,
                        parent_cas.new_generation as i64,
                        parent_cas.now_wall_ms,
                        parent_cas.lease_id.to_string(),
                        parent_cas.expected_state,
                        parent_cas.expected_generation as i64,
                        parent_cas.expected_version as i64,
                    ],
                )
                .context("activate: move parent to delegated")?;
            if moved == 0 {
                tx.rollback().ok();
                return Ok(None);
            }

            let child_row = get_lease_conn(&tx, child.lease_id)?
                .ok_or_else(|| anyhow::anyhow!("child lease missing after activate"))?;
            let transfer_row = get_transfer_conn(&tx, transfer_cas.transfer_id)?
                .ok_or_else(|| anyhow::anyhow!("transfer missing after activate"))?;
            let parent_row = get_lease_conn(&tx, parent_cas.lease_id)?
                .ok_or_else(|| anyhow::anyhow!("parent lease missing after activate"))?;
            tx.commit()?;
            Ok(Some((child_row, transfer_row, parent_row)))
        })
        .await
    }

    /// Retire a transfer that never activated a child.
    ///
    /// Only legal while `child_lease_id IS NULL`: no authority was ever handed
    /// over, so closing the row hands nothing to anyone. Recovery uses this to
    /// clear an abandoned Prepared/ParentExcluded row instead of leaving it to
    /// be rediscovered forever. The SQL trigger enforces the same precondition.
    pub async fn abandon_write_scope_transfer(
        &self,
        transfer_id: Uuid,
        expected_phase: String,
        expected_version: u64,
        reason: String,
        now_wall_ms: i64,
    ) -> Result<Option<WriteScopeTransferRow>> {
        self.write(move |conn| {
            let n = conn
                .execute(
                    "UPDATE write_scope_transfers SET
                        phase = 'committed',
                        recovery_phase = ?1,
                        unsupported_reason = COALESCE(unsupported_reason, ?2),
                        version = version + 1,
                        updated_at_wall_ms = ?3
                     WHERE transfer_id = ?4
                       AND phase = ?5
                       AND version = ?6
                       AND child_lease_id IS NULL",
                    params![
                        "reconciled",
                        reason,
                        now_wall_ms,
                        transfer_id.to_string(),
                        expected_phase,
                        expected_version as i64,
                    ],
                )
                .context("abandon write_scope_transfer")?;
            if n == 0 {
                return Ok(None);
            }
            get_transfer_conn(conn, transfer_id)
        })
        .await
    }

    pub async fn get_write_scope_transfer(
        &self,
        transfer_id: Uuid,
    ) -> Result<Option<WriteScopeTransferRow>> {
        self.read(move |conn| get_transfer_conn(conn, transfer_id))
            .await
    }

    /// Advance a transfer one phase under CAS. Returns `None` on a stale
    /// expectation. The SQL triggers additionally refuse any rewind and any
    /// advance past Prepared without a Proven backend.
    pub async fn cas_write_scope_transfer_phase(
        &self,
        cas: CasWriteScopeTransfer,
    ) -> Result<Option<WriteScopeTransferRow>> {
        if !TRANSFER_PHASES.contains(&cas.expected_phase.as_str()) {
            bail!("invalid expected transfer phase {}", cas.expected_phase);
        }
        if !TRANSFER_PHASES.contains(&cas.new_phase.as_str()) {
            bail!("invalid new transfer phase {}", cas.new_phase);
        }
        // Phases advance by exactly one step. Skipping one would, for example,
        // let ParentRestored land while the child token is still live.
        let from_ord = transfer_phase_ordinal(&cas.expected_phase)
            .ok_or_else(|| anyhow::anyhow!("unknown phase {}", cas.expected_phase))?;
        let to_ord = transfer_phase_ordinal(&cas.new_phase)
            .ok_or_else(|| anyhow::anyhow!("unknown phase {}", cas.new_phase))?;
        if to_ord != from_ord + 1 {
            bail!(
                "write scope transfer phase must advance one step: {} -> {}",
                cas.expected_phase,
                cas.new_phase
            );
        }
        self.write(move |conn| {
            let current = match get_transfer_conn(conn, cas.transfer_id)? {
                Some(row) => row,
                None => return Ok(None),
            };
            if current.phase != cas.expected_phase || current.version != cas.expected_version {
                return Ok(None);
            }
            let child_lease = match cas.child_lease_id {
                Some(id) => Some(id.to_string()),
                None => current.child_lease_id.map(|id| id.to_string()),
            };
            let parent_generation = cas.parent_generation.unwrap_or(current.parent_generation);
            let child_generation = cas.child_generation.or(current.child_generation);
            let restored = cas
                .restored_parent_generation
                .or(current.restored_parent_generation);
            let containment = match cas.containment_id {
                Some(id) => Some(id.to_string()),
                None => current.containment_id.map(|id| id.to_string()),
            };
            let permit = match cas.execution_permit_id {
                Some(id) => Some(id.to_string()),
                None => current.execution_permit_id.map(|id| id.to_string()),
            };
            let recovery = match cas.recovery_phase {
                Some(v) => v,
                None => current.recovery_phase,
            };
            let containment_generation = cas
                .containment_generation
                .or(current.containment_generation);
            let publication_identity = match cas.publication_identity {
                Some(v) => v,
                None => current.publication_identity,
            };
            let n = conn
                .execute(
                    "UPDATE write_scope_transfers SET
                        phase = ?1,
                        child_lease_id = ?2,
                        parent_generation = ?3,
                        child_generation = ?4,
                        restored_parent_generation = ?5,
                        containment_id = ?6,
                        containment_generation = ?7,
                        publication_identity = ?8,
                        execution_permit_id = ?9,
                        recovery_phase = ?10,
                        version = version + 1,
                        updated_at_wall_ms = ?11
                     WHERE transfer_id = ?12 AND phase = ?13 AND version = ?14",
                    params![
                        cas.new_phase,
                        child_lease,
                        parent_generation as i64,
                        child_generation.map(|v| v as i64),
                        restored.map(|v| v as i64),
                        containment,
                        containment_generation.map(|v| v as i64),
                        publication_identity,
                        permit,
                        recovery,
                        cas.now_wall_ms,
                        cas.transfer_id.to_string(),
                        cas.expected_phase,
                        cas.expected_version as i64,
                    ],
                )
                .context("cas write_scope_transfer phase")?;
            if n == 0 {
                return Ok(None);
            }
            get_transfer_conn(conn, cas.transfer_id)
        })
        .await
    }

    /// Transfers that have not reached Committed. These are exactly the rows
    /// startup recovery must reconcile.
    pub async fn list_open_write_scope_transfers(
        &self,
        session_id: Option<Uuid>,
    ) -> Result<Vec<WriteScopeTransferRow>> {
        self.read(move |conn| {
            let mut out = Vec::new();
            match session_id {
                Some(session_id) => {
                    let mut stmt = conn
                        .prepare(&format!(
                            "SELECT {TRANSFER_COLS} FROM write_scope_transfers
                             WHERE session_id = ?1 AND phase != 'committed'
                             ORDER BY created_at_wall_ms ASC, transfer_id ASC"
                        ))
                        .context("preparing open session transfers")?;
                    let rows = stmt
                        .query_map(params![session_id.to_string()], map_transfer)
                        .context("querying open session transfers")?;
                    for row in rows {
                        out.push(row.context("decoding write_scope_transfer")?);
                    }
                }
                None => {
                    let mut stmt = conn
                        .prepare(&format!(
                            "SELECT {TRANSFER_COLS} FROM write_scope_transfers
                             WHERE phase != 'committed'
                             ORDER BY created_at_wall_ms ASC, transfer_id ASC"
                        ))
                        .context("preparing open transfers")?;
                    let rows = stmt
                        .query_map([], map_transfer)
                        .context("querying open transfers")?;
                    for row in rows {
                        out.push(row.context("decoding write_scope_transfer")?);
                    }
                }
            }
            Ok(out)
        })
        .await
    }

    /// The transfer that a given execution permit was reserved for.
    ///
    /// Used to tell a *handover* permit (the one that created a lease) apart
    /// from a sibling's permit, which is the difference between "nested
    /// delegation works" and "nested delegation deadlocks on itself".
    pub async fn get_write_scope_transfer_by_execution_permit(
        &self,
        execution_permit_id: Uuid,
    ) -> Result<Option<WriteScopeTransferRow>> {
        self.read(move |conn| {
            conn.query_row(
                &format!(
                    "SELECT {TRANSFER_COLS} FROM write_scope_transfers
                     WHERE execution_permit_id = ?1"
                ),
                params![execution_permit_id.to_string()],
                map_transfer,
            )
            .optional()
            .context("get_write_scope_transfer_by_execution_permit")
        })
        .await
    }

    /// Open transfers whose parent is `parent_lease_id` — i.e. sub-scopes this
    /// lease has delegated and not yet reclaimed.
    pub async fn list_open_write_scope_transfers_for_parent(
        &self,
        parent_lease_id: Uuid,
    ) -> Result<Vec<WriteScopeTransferRow>> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {TRANSFER_COLS} FROM write_scope_transfers
                     WHERE parent_lease_id = ?1 AND phase != 'committed'
                     ORDER BY created_at_wall_ms ASC, transfer_id ASC"
                ))
                .context("preparing open transfers for parent")?;
            let rows = stmt
                .query_map(params![parent_lease_id.to_string()], map_transfer)
                .context("querying open transfers for parent")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding write_scope_transfer")?);
            }
            Ok(out)
        })
        .await
    }

    /// Every transfer whose parent is `parent_lease_id`, in creation order.
    /// The coordinator subtracts the still-delegated ones from the parent's
    /// base scope to get its effective authority.
    pub async fn list_write_scope_transfers_for_parent(
        &self,
        parent_lease_id: Uuid,
    ) -> Result<Vec<WriteScopeTransferRow>> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {TRANSFER_COLS} FROM write_scope_transfers
                     WHERE parent_lease_id = ?1
                     ORDER BY created_at_wall_ms ASC, transfer_id ASC"
                ))
                .context("preparing parent transfers")?;
            let rows = stmt
                .query_map(params![parent_lease_id.to_string()], map_transfer)
                .context("querying parent transfers")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding write_scope_transfer")?);
            }
            Ok(out)
        })
        .await
    }

    // ---- permits ----------------------------------------------------------

    pub async fn insert_write_scope_permit(
        &self,
        row: WriteScopePermitRow,
    ) -> Result<WriteScopePermitRow> {
        if !PERMIT_KINDS.contains(&row.kind.as_str()) {
            bail!("invalid write scope permit kind {}", row.kind);
        }
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO write_scope_permits (
                    permit_id, session_id, lease_id, generation, kind, influence_kind,
                    influence_root, target_path, state, containment_id, acquired_at_wall_ms,
                    released_at_wall_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    row.permit_id.to_string(),
                    row.session_id.to_string(),
                    row.lease_id.to_string(),
                    row.generation as i64,
                    row.kind,
                    row.influence_kind,
                    row.influence_root,
                    row.target_path,
                    row.state,
                    row.containment_id.map(|id| id.to_string()),
                    row.acquired_at_wall_ms,
                    row.released_at_wall_ms,
                ],
            )
            .context("inserting write_scope_permit")?;
            get_permit_conn(conn, row.permit_id)?
                .ok_or_else(|| anyhow::anyhow!("write_scope_permit missing after insert"))
        })
        .await
    }

    pub async fn get_write_scope_permit(
        &self,
        permit_id: Uuid,
    ) -> Result<Option<WriteScopePermitRow>> {
        self.read(move |conn| get_permit_conn(conn, permit_id))
            .await
    }

    /// Release a held permit. Idempotent-safe: returns `None` when the permit
    /// was already released, so a caller cannot double-drain a barrier.
    pub async fn release_write_scope_permit(
        &self,
        permit_id: Uuid,
        now_wall_ms: i64,
    ) -> Result<Option<WriteScopePermitRow>> {
        self.write(move |conn| {
            let n = conn
                .execute(
                    "UPDATE write_scope_permits SET state = 'released', released_at_wall_ms = ?1
                     WHERE permit_id = ?2 AND state = 'held'",
                    params![now_wall_ms, permit_id.to_string()],
                )
                .context("releasing write_scope_permit")?;
            if n == 0 {
                return Ok(None);
            }
            get_permit_conn(conn, permit_id)
        })
        .await
    }

    /// Every still-held permit, optionally scoped to a session. A transfer
    /// barrier drains against this set.
    pub async fn list_held_write_scope_permits(
        &self,
        session_id: Option<Uuid>,
    ) -> Result<Vec<WriteScopePermitRow>> {
        self.read(move |conn| {
            let mut out = Vec::new();
            match session_id {
                Some(session_id) => {
                    let mut stmt = conn
                        .prepare(&format!(
                            "SELECT {PERMIT_COLS} FROM write_scope_permits
                             WHERE session_id = ?1 AND state = 'held'
                             ORDER BY acquired_at_wall_ms ASC, permit_id ASC"
                        ))
                        .context("preparing held session permits")?;
                    let rows = stmt
                        .query_map(params![session_id.to_string()], map_permit)
                        .context("querying held session permits")?;
                    for row in rows {
                        out.push(row.context("decoding write_scope_permit")?);
                    }
                }
                None => {
                    let mut stmt = conn
                        .prepare(&format!(
                            "SELECT {PERMIT_COLS} FROM write_scope_permits
                             WHERE state = 'held'
                             ORDER BY acquired_at_wall_ms ASC, permit_id ASC"
                        ))
                        .context("preparing held permits")?;
                    let rows = stmt
                        .query_map([], map_permit)
                        .context("querying held permits")?;
                    for row in rows {
                        out.push(row.context("decoding write_scope_permit")?);
                    }
                }
            }
            Ok(out)
        })
        .await
    }

    /// Held permits belonging to one lease.
    pub async fn list_held_write_scope_permits_for_lease(
        &self,
        lease_id: Uuid,
    ) -> Result<Vec<WriteScopePermitRow>> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {PERMIT_COLS} FROM write_scope_permits
                     WHERE lease_id = ?1 AND state = 'held'
                     ORDER BY acquired_at_wall_ms ASC, permit_id ASC"
                ))
                .context("preparing lease permits")?;
            let rows = stmt
                .query_map(params![lease_id.to_string()], map_permit)
                .context("querying lease permits")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding write_scope_permit")?);
            }
            Ok(out)
        })
        .await
    }
}

fn get_lease_conn(
    conn: &rusqlite::Connection,
    lease_id: Uuid,
) -> Result<Option<WriteScopeLeaseRow>> {
    conn.query_row(
        &format!("SELECT {LEASE_COLS} FROM write_scope_leases WHERE lease_id = ?1"),
        params![lease_id.to_string()],
        map_lease,
    )
    .optional()
    .context("get_write_scope_lease")
}

fn get_transfer_conn(
    conn: &rusqlite::Connection,
    transfer_id: Uuid,
) -> Result<Option<WriteScopeTransferRow>> {
    conn.query_row(
        &format!("SELECT {TRANSFER_COLS} FROM write_scope_transfers WHERE transfer_id = ?1"),
        params![transfer_id.to_string()],
        map_transfer,
    )
    .optional()
    .context("get_write_scope_transfer")
}

fn get_permit_conn(
    conn: &rusqlite::Connection,
    permit_id: Uuid,
) -> Result<Option<WriteScopePermitRow>> {
    conn.query_row(
        &format!("SELECT {PERMIT_COLS} FROM write_scope_permits WHERE permit_id = ?1"),
        params![permit_id.to_string()],
        map_permit,
    )
    .optional()
    .context("get_write_scope_permit")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seed_session(db: &Db) -> Uuid {
        db.create_session("proj", "/tmp/write-scope-test", "orchestrator-build")
            .await
            .unwrap()
            .session_id
    }

    fn root_lease(session_id: Uuid) -> WriteScopeLeaseRow {
        WriteScopeLeaseRow {
            lease_id: Uuid::new_v4(),
            parent_lease_id: None,
            session_id,
            task_id: None,
            scope_path: "/ws".into(),
            generation: 1,
            state: "active".into(),
            owner_id: "root".into(),
            version: 1,
            created_at_wall_ms: 1000,
            updated_at_wall_ms: 1000,
            released_at_wall_ms: None,
        }
    }

    fn transfer_for(
        session_id: Uuid,
        parent_lease_id: Uuid,
        sub_scope: &str,
        capability: &str,
    ) -> WriteScopeTransferRow {
        WriteScopeTransferRow {
            transfer_id: Uuid::new_v4(),
            session_id,
            parent_lease_id,
            child_lease_id: None,
            sub_scope_path: sub_scope.into(),
            phase: "prepared".into(),
            prepare_parent_generation: 1,
            parent_generation: 2,
            child_generation: None,
            restored_parent_generation: None,
            backend_kind: "fake_proven".into(),
            capability: capability.into(),
            unsupported_reason: None,
            containment_id: None,
            containment_generation: None,
            publication_identity: None,
            execution_permit_id: None,
            recovery_phase: Some("pending".into()),
            version: 1,
            created_at_wall_ms: 1000,
            updated_at_wall_ms: 1000,
        }
    }

    #[tokio::test]
    async fn lease_cas_requires_state_generation_and_version() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let lease = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();

        // Prepared: Active(g) -> Transferring(g+1).
        let bumped = db
            .cas_write_scope_lease(CasWriteScopeLease {
                lease_id: lease.lease_id,
                expected_state: "active".into(),
                expected_generation: 1,
                expected_version: 1,
                new_state: "transferring".into(),
                new_generation: 2,
                now_wall_ms: 2000,
                released: false,
            })
            .await
            .unwrap()
            .expect("first CAS wins");
        assert_eq!(bumped.generation, 2);
        assert_eq!(bumped.version, 2);

        // A contender that observed the pre-CAS view loses outright.
        assert!(
            db.cas_write_scope_lease(CasWriteScopeLease {
                lease_id: lease.lease_id,
                expected_state: "active".into(),
                expected_generation: 1,
                expected_version: 1,
                new_state: "transferring".into(),
                new_generation: 2,
                now_wall_ms: 2100,
                released: false,
            })
            .await
            .unwrap()
            .is_none()
        );

        // Right state+generation but stale version still loses.
        assert!(
            db.cas_write_scope_lease(CasWriteScopeLease {
                lease_id: lease.lease_id,
                expected_state: "transferring".into(),
                expected_generation: 2,
                expected_version: 1,
                new_state: "delegated".into(),
                new_generation: 3,
                now_wall_ms: 2200,
                released: false,
            })
            .await
            .unwrap()
            .is_none()
        );
    }

    #[tokio::test]
    async fn lease_generation_never_decrements_or_resurrects() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let lease = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();

        let err = db
            .cas_write_scope_lease(CasWriteScopeLease {
                lease_id: lease.lease_id,
                expected_state: "active".into(),
                expected_generation: 5,
                expected_version: 1,
                new_state: "transferring".into(),
                new_generation: 4,
                now_wall_ms: 2000,
                released: false,
            })
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("decrement"), "{err:#}");

        // Release, then prove a released lease is final.
        let released = db
            .cas_write_scope_lease(CasWriteScopeLease {
                lease_id: lease.lease_id,
                expected_state: "active".into(),
                expected_generation: 1,
                expected_version: 1,
                new_state: "released".into(),
                new_generation: 2,
                now_wall_ms: 3000,
                released: true,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(released.released_at_wall_ms, Some(3000));

        let err = db
            .cas_write_scope_lease(CasWriteScopeLease {
                lease_id: lease.lease_id,
                expected_state: "released".into(),
                expected_generation: 2,
                expected_version: 2,
                new_state: "active".into(),
                new_generation: 3,
                now_wall_ms: 4000,
                released: false,
            })
            .await
            .unwrap_err();
        // The Rust transition graph refuses first, before SQL is reached. The
        // `released_is_final` trigger is an independent second line of defence,
        // proven separately in `the_sql_triggers_refuse_independently_of_rust`.
        let msg = format!("{err:#}");
        assert!(
            msg.contains("illegal write scope lease transition: released -> active"),
            "the Rust precheck must refuse the resurrection: {msg}"
        );
    }

    #[tokio::test]
    async fn transfer_phase_advances_forward_only_and_needs_proven_backend() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let lease = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();
        let t = db
            .insert_write_scope_transfer(transfer_for(
                session_id,
                lease.lease_id,
                "/ws/a",
                "proven",
            ))
            .await
            .unwrap();

        let excluded = db
            .cas_write_scope_transfer_phase(CasWriteScopeTransfer {
                transfer_id: t.transfer_id,
                expected_phase: "prepared".into(),
                expected_version: 1,
                new_phase: "parent_excluded".into(),
                now_wall_ms: 2000,
                child_lease_id: None,
                parent_generation: Some(2),
                child_generation: None,
                restored_parent_generation: None,
                containment_id: None,
                containment_generation: None,
                publication_identity: None,
                execution_permit_id: None,
                recovery_phase: None,
            })
            .await
            .unwrap()
            .expect("advance to parent_excluded");
        assert_eq!(excluded.phase, "parent_excluded");
        assert_eq!(excluded.version, 2);

        // Rewinding is refused by the trigger, not merely by convention.
        let err = db
            .cas_write_scope_transfer_phase(CasWriteScopeTransfer {
                transfer_id: t.transfer_id,
                expected_phase: "parent_excluded".into(),
                expected_version: 2,
                new_phase: "prepared".into(),
                now_wall_ms: 2100,
                child_lease_id: None,
                parent_generation: None,
                child_generation: None,
                restored_parent_generation: None,
                containment_id: None,
                containment_generation: None,
                publication_identity: None,
                execution_permit_id: None,
                recovery_phase: None,
            })
            .await
            .unwrap_err();
        // The Rust adjacency check refuses before SQL is reached.
        let msg = format!("{err:#}");
        assert!(
            msg.contains("phase must advance one step"),
            "the Rust adjacency check must refuse: {msg}"
        );
        assert!(!msg.contains("durable constraint"), "{msg}");
    }

    #[tokio::test]
    async fn unsupported_transfer_can_never_leave_prepared() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let lease = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();
        let t = db
            .insert_write_scope_transfer(transfer_for(
                session_id,
                lease.lease_id,
                "/ws/a",
                "unsupported",
            ))
            .await
            .unwrap();

        let err = db
            .cas_write_scope_transfer_phase(CasWriteScopeTransfer {
                transfer_id: t.transfer_id,
                expected_phase: "prepared".into(),
                expected_version: 1,
                new_phase: "parent_excluded".into(),
                now_wall_ms: 2000,
                child_lease_id: None,
                parent_generation: None,
                child_generation: None,
                restored_parent_generation: None,
                containment_id: None,
                containment_generation: None,
                publication_identity: None,
                execution_permit_id: None,
                recovery_phase: None,
            })
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("proven"), "{err:#}");
    }

    #[tokio::test]
    async fn child_lease_attachment_is_write_once() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let parent = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();

        let mut child_row = root_lease(session_id);
        child_row.parent_lease_id = Some(parent.lease_id);
        child_row.scope_path = "/ws/a".into();
        child_row.owner_id = "child".into();
        let child = db.insert_write_scope_lease(child_row).await.unwrap();

        let mut other_row = root_lease(session_id);
        other_row.parent_lease_id = Some(parent.lease_id);
        other_row.scope_path = "/ws/b".into();
        other_row.owner_id = "other".into();
        let other = db.insert_write_scope_lease(other_row).await.unwrap();

        let t = db
            .insert_write_scope_transfer(transfer_for(
                session_id,
                parent.lease_id,
                "/ws/a",
                "proven",
            ))
            .await
            .unwrap();
        let t = db
            .cas_write_scope_transfer_phase(CasWriteScopeTransfer {
                transfer_id: t.transfer_id,
                expected_phase: "prepared".into(),
                expected_version: 1,
                new_phase: "parent_excluded".into(),
                now_wall_ms: 2000,
                child_lease_id: None,
                parent_generation: None,
                child_generation: None,
                restored_parent_generation: None,
                containment_id: None,
                containment_generation: None,
                publication_identity: None,
                execution_permit_id: None,
                recovery_phase: None,
            })
            .await
            .unwrap()
            .unwrap();
        let t = db
            .cas_write_scope_transfer_phase(CasWriteScopeTransfer {
                transfer_id: t.transfer_id,
                expected_phase: "parent_excluded".into(),
                expected_version: t.version,
                new_phase: "child_activated".into(),
                now_wall_ms: 2100,
                child_lease_id: Some(child.lease_id),
                parent_generation: None,
                child_generation: Some(3),
                restored_parent_generation: None,
                containment_id: None,
                containment_generation: None,
                publication_identity: None,
                execution_permit_id: None,
                recovery_phase: None,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(t.child_lease_id, Some(child.lease_id));

        let err = db
            .cas_write_scope_transfer_phase(CasWriteScopeTransfer {
                transfer_id: t.transfer_id,
                expected_phase: "child_activated".into(),
                expected_version: t.version,
                new_phase: "child_terminal".into(),
                now_wall_ms: 2200,
                child_lease_id: Some(other.lease_id),
                parent_generation: None,
                child_generation: None,
                restored_parent_generation: None,
                containment_id: None,
                containment_generation: None,
                publication_identity: None,
                execution_permit_id: None,
                recovery_phase: None,
            })
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("write-once"), "{err:#}");
    }

    #[tokio::test]
    async fn the_durable_layer_refuses_illegal_transitions_itself() {
        // The storage layer must not rely on its caller having checked: an
        // `active -> delegated` jump would skip the exclusion barrier entirely.
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let lease = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();

        let err = db
            .cas_write_scope_lease(CasWriteScopeLease {
                lease_id: lease.lease_id,
                expected_state: "active".into(),
                expected_generation: 1,
                expected_version: 1,
                new_state: "delegated".into(),
                new_generation: 2,
                now_wall_ms: 2000,
                released: false,
            })
            .await
            .unwrap_err();
        // Pin the RUST layer specifically. The SQL trigger uses a different
        // message ("rejected by durable constraint"), so if this precheck were
        // deleted the update would reach SQL and this assertion would fail —
        // which is the whole point of asserting the layer, not just the refusal.
        let msg = format!("{err:#}");
        assert!(
            msg.contains("illegal write scope lease transition: active -> delegated"),
            "the Rust precheck must be what refuses: {msg}"
        );
        assert!(
            !msg.contains("durable constraint"),
            "the Rust precheck must refuse before SQL is reached: {msg}"
        );

        // The row is untouched.
        let after = db
            .get_write_scope_lease(lease.lease_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.state, "active");
        assert_eq!(after.generation, 1);

        // The legal graph matches what the state machine declares.
        assert!(is_legal_lease_transition("active", "transferring"));
        assert!(is_legal_lease_transition("delegated", "transferring"));
        assert!(is_legal_lease_transition("returning", "delegated"));
        assert!(!is_legal_lease_transition("active", "delegated"));
        assert!(!is_legal_lease_transition("released", "active"));
    }

    /// The SQL triggers must refuse on their own, with the Rust prechecks
    /// bypassed entirely.
    ///
    /// Redundant defences decay to one unless each is tested independently: a
    /// test that only calls the Rust API stays green if the trigger is deleted,
    /// and a test that only exercises the trigger stays green if the Rust check
    /// is deleted. This one issues raw SQL, so nothing but the trigger can
    /// refuse it.
    #[tokio::test]
    async fn the_sql_triggers_refuse_independently_of_rust() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let lease = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();
        let lease_id = lease.lease_id.to_string();

        // 1. Illegal transition, straight to SQL: active -> delegated skips the
        //    exclusion barrier.
        let id = lease_id.clone();
        let err = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE write_scope_leases
                     SET state = 'delegated', version = version + 1
                     WHERE lease_id = ?1",
                    params![id],
                )
                .map_err(anyhow::Error::from)
            })
            .await
            .expect_err("the trigger must refuse an illegal transition");
        assert!(
            format!("{err:#}").contains("rejected by durable constraint"),
            "expected the SQL trigger to refuse: {err:#}"
        );

        // The row is untouched.
        let after = db
            .get_write_scope_lease(lease.lease_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.state, "active");

        // 2. Generation monotonicity, straight to SQL.
        let id = lease_id.clone();
        let err = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE write_scope_leases SET generation = 0 WHERE lease_id = ?1",
                    params![id],
                )
                .map_err(anyhow::Error::from)
            })
            .await
            .expect_err("the trigger must refuse a generation decrement");
        assert!(
            format!("{err:#}").contains("must never decrement"),
            "{err:#}"
        );

        // 3. Scope immutability, straight to SQL.
        let id = lease_id.clone();
        let err = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE write_scope_leases SET scope_path = '/elsewhere' WHERE lease_id = ?1",
                    params![id],
                )
                .map_err(anyhow::Error::from)
            })
            .await
            .expect_err("the trigger must refuse re-pointing a lease");
        assert!(format!("{err:#}").contains("immutable"), "{err:#}");

        // 4. Released is final, straight to SQL.
        db.cas_write_scope_lease(CasWriteScopeLease {
            lease_id: lease.lease_id,
            expected_state: "active".into(),
            expected_generation: 1,
            expected_version: 1,
            new_state: "released".into(),
            new_generation: 2,
            now_wall_ms: 3000,
            released: true,
        })
        .await
        .unwrap()
        .unwrap();
        let id = lease_id.clone();
        let err = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE write_scope_leases
                     SET state = 'active', generation = generation + 1, version = version + 1
                     WHERE lease_id = ?1",
                    params![id],
                )
                .map_err(anyhow::Error::from)
            })
            .await
            .expect_err("the trigger must refuse resurrecting a released lease");
        assert!(format!("{err:#}").contains("final"), "{err:#}");
    }

    /// The transfer-phase triggers likewise refuse on their own.
    #[tokio::test]
    async fn the_sql_transfer_triggers_refuse_independently_of_rust() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let lease = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();
        let t = db
            .insert_write_scope_transfer(transfer_for(
                session_id,
                lease.lease_id,
                "/ws/a",
                "proven",
            ))
            .await
            .unwrap();
        let tid = t.transfer_id.to_string();

        // Skipping phases, straight to SQL. `child_lease_id IS NULL` here, and
        // the trigger deliberately permits retiring an unactivated transfer, so
        // aim at a skip that is NOT that exemption.
        let id = tid.clone();
        let err = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE write_scope_transfers SET phase = 'child_activated' WHERE transfer_id = ?1",
                    params![id],
                )
                .map_err(anyhow::Error::from)
            })
            .await
            .expect_err("the trigger must refuse a two-step advance");
        assert!(
            format!("{err:#}").contains("rejected by durable constraint"),
            "{err:#}"
        );

        // Rewinding, straight to SQL.
        let id = tid.clone();
        db.write(move |conn| {
            conn.execute(
                "UPDATE write_scope_transfers SET phase = 'parent_excluded' WHERE transfer_id = ?1",
                params![id],
            )
            .map_err(anyhow::Error::from)
        })
        .await
        .expect("a one-step advance is allowed");
        let id = tid.clone();
        let err = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE write_scope_transfers SET phase = 'prepared' WHERE transfer_id = ?1",
                    params![id],
                )
                .map_err(anyhow::Error::from)
            })
            .await
            .expect_err("the trigger must refuse a rewind");
        assert!(format!("{err:#}").contains("rewind"), "{err:#}");

        // The sub-scope is immutable, straight to SQL.
        let id = tid.clone();
        let err = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE write_scope_transfers SET sub_scope_path = '/ws/b' WHERE transfer_id = ?1",
                    params![id],
                )
                .map_err(anyhow::Error::from)
            })
            .await
            .expect_err("the trigger must refuse re-pointing the sub-scope");
        assert!(format!("{err:#}").contains("immutable"), "{err:#}");
    }

    #[tokio::test]
    async fn transfer_phases_must_advance_exactly_one_step() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let lease = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();
        let t = db
            .insert_write_scope_transfer(transfer_for(
                session_id,
                lease.lease_id,
                "/ws/a",
                "proven",
            ))
            .await
            .unwrap();

        // prepared -> committed skips every barrier in between.
        let err = db
            .cas_write_scope_transfer_phase(CasWriteScopeTransfer {
                transfer_id: t.transfer_id,
                expected_phase: "prepared".into(),
                expected_version: 1,
                new_phase: "committed".into(),
                now_wall_ms: 2000,
                child_lease_id: None,
                parent_generation: None,
                child_generation: None,
                restored_parent_generation: None,
                containment_id: None,
                containment_generation: None,
                publication_identity: None,
                execution_permit_id: None,
                recovery_phase: None,
            })
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("phase must advance one step"), "{msg}");
        assert!(!msg.contains("durable constraint"), "{msg}");
        assert_eq!(
            db.get_write_scope_transfer(t.transfer_id)
                .await
                .unwrap()
                .unwrap()
                .phase,
            "prepared"
        );
    }

    #[tokio::test]
    async fn prepare_is_atomic_and_a_loser_writes_no_transfer_row() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let lease = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();

        let cas = CasWriteScopeLease {
            lease_id: lease.lease_id,
            expected_state: "active".into(),
            expected_generation: 1,
            expected_version: 1,
            new_state: "transferring".into(),
            new_generation: 2,
            now_wall_ms: 2000,
            released: false,
        };
        let row = transfer_for(session_id, lease.lease_id, "/ws/a", "proven");
        let first_id = row.transfer_id;
        let (parent, transfer) = db
            .prepare_write_scope_transfer(cas.clone(), row)
            .await
            .unwrap()
            .expect("first prepare wins");
        assert_eq!(parent.state, "transferring");
        assert_eq!(transfer.phase, "prepared");

        // A stale contender loses AND leaves no orphan transfer row behind.
        let loser_row = transfer_for(session_id, lease.lease_id, "/ws/b", "proven");
        let loser_id = loser_row.transfer_id;
        assert!(
            db.prepare_write_scope_transfer(cas, loser_row)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_write_scope_transfer(loser_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_write_scope_transfer(first_id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn only_an_unactivated_transfer_may_be_abandoned() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let parent = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();
        let t = db
            .insert_write_scope_transfer(transfer_for(
                session_id,
                parent.lease_id,
                "/ws/a",
                "proven",
            ))
            .await
            .unwrap();

        let retired = db
            .abandon_write_scope_transfer(
                t.transfer_id,
                "prepared".into(),
                t.version,
                "never activated".into(),
                3000,
            )
            .await
            .unwrap()
            .expect("an unactivated transfer may be retired");
        assert_eq!(retired.phase, "committed");
        assert_eq!(retired.recovery_phase.as_deref(), Some("reconciled"));
    }

    #[tokio::test]
    async fn permits_release_once_and_list_while_held() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let lease = db
            .insert_write_scope_lease(root_lease(session_id))
            .await
            .unwrap();

        let permit = db
            .insert_write_scope_permit(WriteScopePermitRow {
                permit_id: Uuid::new_v4(),
                session_id,
                lease_id: lease.lease_id,
                generation: 1,
                kind: "execution".into(),
                influence_kind: "rename".into(),
                influence_root: "/ws".into(),
                target_path: "/ws/a".into(),
                state: "held".into(),
                containment_id: Some(Uuid::new_v4()),
                acquired_at_wall_ms: 1000,
                released_at_wall_ms: None,
            })
            .await
            .unwrap();

        assert_eq!(
            db.list_held_write_scope_permits(Some(session_id))
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            db.release_write_scope_permit(permit.permit_id, 2000)
                .await
                .unwrap()
                .is_some()
        );
        // Second release is a no-op, so a barrier cannot be drained twice.
        assert!(
            db.release_write_scope_permit(permit.permit_id, 2100)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_held_write_scope_permits(Some(session_id))
                .await
                .unwrap()
                .is_empty()
        );
    }
}
