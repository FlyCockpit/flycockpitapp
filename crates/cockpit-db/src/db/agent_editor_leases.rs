//! Durable, owner-bound external-editor lease persistence.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use super::Db;

const COMPLETION_CLAIM_MS: i64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEditorLeaseRow {
    pub owner_digest: String,
    pub client_operation_id: String,
    pub lease_id: String,
    pub project_root: String,
    pub agent_name: String,
    pub consumed_revision: String,
    /// Opaque id of the owner-bound encrypted replay payload in the secret
    /// vault. SQLite never stores the editor markdown itself.
    pub snapshot_handle: Option<String>,
    /// Vault-keyed replay identity; never a raw digest of the document.
    pub snapshot_identity: [u8; 32],
    pub state: String,
    /// Vault-keyed, domain-separated completion identity.
    pub completion_identity: Option<[u8; 32]>,
    /// Opaque id of the owner-bound encrypted completion payload. It exists
    /// only while a completion is being reconciled and is cleared atomically
    /// with the terminal receipt.
    pub completion_handle: Option<String>,
    pub completion_operation_id: Option<String>,
    /// Durable filesystem-publication phase. `intent` is recorded while the
    /// cross-process publication lock is held and before bytes are replaced;
    /// `published` additionally proves the revision returned by that replace.
    pub publication_phase: String,
    /// Vault-keyed identities of the exact target bytes before and after the
    /// planned publication. They permit crash recovery without storing agent
    /// markdown in SQLite.
    pub consumed_projection_identity: Option<String>,
    pub intended_projection_identity: Option<String>,
    /// Revision produced by the filesystem publication owned by this exact
    /// completion claim.  Once present, later edits cannot make the original
    /// commit ambiguous.
    pub publication_result_revision: Option<String>,
    pub consumed_config_generation: Option<u64>,
    pub result_config_generation: Option<u64>,
    pub terminal_result_json: Option<String>,
    pub terminal_error_json: Option<String>,
    pub expires_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

pub enum AgentEditorCompletionClaim {
    Execute(AgentEditorLeaseRow),
    Pending,
    Terminal(AgentEditorLeaseRow),
}

impl Db {
    pub async fn agent_editor_lease_by_operation(
        &self,
        owner_digest: String,
        client_operation_id: String,
    ) -> Result<Option<AgentEditorLeaseRow>> {
        self.read(move |conn| by_operation(conn, &owner_digest, &client_operation_id))
            .await
    }

    pub async fn agent_editor_lease_by_id(
        &self,
        lease_id: String,
    ) -> Result<Option<AgentEditorLeaseRow>> {
        self.read(move |conn| by_id(conn, &lease_id)).await
    }

    pub async fn expired_open_agent_editor_leases(
        &self,
        now_unix_ms: i64,
    ) -> Result<Vec<AgentEditorLeaseRow>> {
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT owner_digest,client_operation_id,lease_id,project_root,agent_name,consumed_revision,snapshot_handle,snapshot_identity,state,completion_identity,completion_handle,completion_operation_id,publication_phase,consumed_projection_identity,intended_projection_identity,publication_result_revision,consumed_config_generation,result_config_generation,terminal_result_json,terminal_error_json,expires_at_unix_ms,updated_at_unix_ms
                 FROM agent_editor_leases
                 WHERE state='open' AND expires_at_unix_ms < ?1
                 ORDER BY expires_at_unix_ms ASC LIMIT 128",
            )?;
            let rows = statement
                .query_map([now_unix_ms], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    pub async fn recoverable_agent_editor_completions(
        &self,
        stale_before_unix_ms: i64,
    ) -> Result<Vec<AgentEditorLeaseRow>> {
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT owner_digest,client_operation_id,lease_id,project_root,agent_name,consumed_revision,snapshot_handle,snapshot_identity,state,completion_identity,completion_handle,completion_operation_id,publication_phase,consumed_projection_identity,intended_projection_identity,publication_result_revision,consumed_config_generation,result_config_generation,terminal_result_json,terminal_error_json,expires_at_unix_ms,updated_at_unix_ms
                 FROM agent_editor_leases
                 WHERE state='completing' AND updated_at_unix_ms <= ?1
                 ORDER BY updated_at_unix_ms ASC LIMIT 128",
            )?;
            statement
                .query_map([stale_before_unix_ms], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        })
        .await
    }

    pub async fn insert_agent_editor_lease(&self, row: AgentEditorLeaseRow) -> Result<()> {
        self.write(move |conn| {
            insert_agent_editor_lease_conn(conn, &row)?;
            Ok(())
        })
        .await
    }
}

pub fn insert_agent_editor_lease_conn(conn: &Connection, row: &AgentEditorLeaseRow) -> Result<()> {
    conn.execute(
                "INSERT INTO agent_editor_leases
                 (owner_digest,client_operation_id,lease_id,project_root,agent_name,
                  consumed_revision,snapshot_handle,snapshot_identity,state,completion_identity,completion_handle,completion_operation_id,publication_phase,consumed_projection_identity,intended_projection_identity,publication_result_revision,consumed_config_generation,result_config_generation,terminal_result_json,terminal_error_json,
                  expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'open',NULL,NULL,NULL,'none',NULL,NULL,NULL,NULL,NULL,NULL,NULL,?9,?10,?10)",
                params![
                    &row.owner_digest,
                    &row.client_operation_id,
                    &row.lease_id,
                    &row.project_root,
                    &row.agent_name,
                    &row.consumed_revision,
                    &row.snapshot_handle,
                    row.snapshot_identity.as_slice(),
                    row.expires_at_unix_ms,
                    now_ms()
                ],
            )?;
    Ok(())
}

/// Record the exact before/after projection identities while the caller owns
/// the filesystem publication lock. This is the durable pre-publication
/// boundary used to classify a crash between atomic replace and receipt.
impl Db {
    /// Persist an editor intent while the caller owns the cross-process agent
    /// publication lock. This narrow synchronous exception keeps the SQLite
    /// fence and filesystem replacement in one ordered critical section and
    /// deliberately does not expose an arbitrary database closure.
    pub fn prepare_agent_editor_publication_under_publication_lock(
        &self,
        lease_id: String,
        completion_identity: [u8; 32],
        completion_operation_id: String,
        consumed_projection_identity: String,
        intended_projection_identity: String,
        consumed_config_generation: u64,
        result_config_generation: u64,
    ) -> Result<()> {
        let consumed_config_generation = i64::try_from(consumed_config_generation)
            .context("agent editor consumed config generation overflow")?;
        let result_config_generation = i64::try_from(result_config_generation)
            .context("agent editor result config generation overflow")?;
        self.write_blocking_unguarded(move |conn| {
            let changed = conn.execute(
                "UPDATE agent_editor_leases
                SET publication_phase='intent',consumed_projection_identity=?4,
                    intended_projection_identity=?5,consumed_config_generation=?6,
                    result_config_generation=?7,updated_at_unix_ms=?8
              WHERE lease_id=?1 AND state='completing' AND completion_identity=?2
                AND completion_operation_id=?3 AND publication_phase='none'",
                params![
                    lease_id,
                    completion_identity.as_slice(),
                    completion_operation_id,
                    consumed_projection_identity,
                    intended_projection_identity,
                    consumed_config_generation,
                    result_config_generation,
                    now_ms()
                ],
            )?;
            if changed != 1 {
                bail!("agent editor publication lost its durable intent reservation");
            }
            Ok(())
        })
    }
}

pub fn record_agent_editor_publication_conn(
    conn: &Connection,
    lease_id: &str,
    completion_identity: [u8; 32],
    completion_operation_id: &str,
    result_revision: &str,
) -> Result<()> {
    let changed = conn.execute(
        "UPDATE agent_editor_leases
            SET publication_phase='published',publication_result_revision=?4,updated_at_unix_ms=?5
          WHERE lease_id=?1 AND state='completing' AND completion_identity=?2
            AND completion_operation_id=?3 AND publication_phase='intent'
            AND publication_result_revision IS NULL",
        params![
            lease_id,
            completion_identity.as_slice(),
            completion_operation_id,
            result_revision,
            now_ms()
        ],
    )?;
    if changed != 1 {
        bail!("agent editor publication lost its durable reservation");
    }
    Ok(())
}

impl Db {
    /// Persist exact publication evidence while the caller still owns the
    /// cross-process agent publication lock.
    pub fn record_agent_editor_publication_under_publication_lock(
        &self,
        lease_id: String,
        completion_identity: [u8; 32],
        completion_operation_id: String,
        result_revision: String,
    ) -> Result<()> {
        self.write_blocking_unguarded(move |conn| {
            record_agent_editor_publication_conn(
                conn,
                &lease_id,
                completion_identity,
                &completion_operation_id,
                &result_revision,
            )
        })
    }
}

pub fn finish_agent_editor_completion_conn(
    conn: &Connection,
    lease_id: &str,
    completion_hash: [u8; 32],
    completion_operation_id: &str,
    terminal_result_json: &str,
    consumed_config_generation: u64,
    result_config_generation: u64,
) -> Result<()> {
    let consumed_config_generation = i64::try_from(consumed_config_generation)
        .context("agent editor consumed config generation overflow")?;
    let result_config_generation = i64::try_from(result_config_generation)
        .context("agent editor result config generation overflow")?;
    let changed = conn.execute(
        "UPDATE agent_editor_leases SET state='terminal',snapshot_handle=NULL,completion_handle=NULL,terminal_result_json=?4,terminal_error_json=NULL,consumed_config_generation=COALESCE(consumed_config_generation,?5),result_config_generation=COALESCE(result_config_generation,?6),updated_at_unix_ms=?7 WHERE lease_id=?1 AND state='completing' AND completion_identity=?2 AND completion_operation_id=?3 AND (consumed_config_generation IS NULL OR consumed_config_generation=?5) AND (result_config_generation IS NULL OR result_config_generation=?6)",
        params![lease_id, completion_hash.as_slice(), completion_operation_id, terminal_result_json, consumed_config_generation, result_config_generation, now_ms()],
    )?;
    if changed != 1 {
        bail!("agent editor lease completion lost its durable reservation");
    }
    Ok(())
}

pub fn fail_agent_editor_completion_conn(
    conn: &Connection,
    lease_id: &str,
    completion_identity: [u8; 32],
    completion_operation_id: &str,
    terminal_error_json: &str,
) -> Result<()> {
    let changed = conn.execute(
        "UPDATE agent_editor_leases SET state='terminal',snapshot_handle=NULL,completion_handle=NULL,terminal_result_json=NULL,terminal_error_json=?4,updated_at_unix_ms=?5 WHERE lease_id=?1 AND state='completing' AND completion_identity=?2 AND completion_operation_id=?3",
        params![lease_id, completion_identity.as_slice(), completion_operation_id, terminal_error_json, now_ms()],
    )?;
    if changed != 1 {
        bail!("agent editor lease failure lost its durable reservation");
    }
    Ok(())
}

pub fn reserve_agent_editor_completion_conn(
    conn: &Connection,
    lease_id: &str,
    owner_digest: &str,
    completion_hash: [u8; 32],
    completion_handle: &str,
    completion_operation_id: &str,
    force_reclaim: bool,
) -> Result<AgentEditorCompletionClaim> {
    let row = by_id(conn, &lease_id)?.context("agent editor lease is absent")?;
    if row.owner_digest != owner_digest {
        bail!("agent editor lease belongs to another owner");
    }
    if let Some(existing) = row.completion_identity
        && existing != completion_hash
    {
        bail!("agent editor lease was settled with different content");
    }
    if let Some(existing) = row.completion_operation_id.as_deref()
        && existing != completion_operation_id
    {
        bail!("agent editor lease was settled by a different client operation");
    }
    if let Some(existing) = row.completion_handle.as_deref()
        && existing != completion_handle
    {
        bail!("agent editor lease completion payload is inconsistent");
    }
    match row.state.as_str() {
        "terminal" => return Ok(AgentEditorCompletionClaim::Terminal(row)),
        // Exact durable publication evidence outranks the short executor
        // claim. Any exact retry may finish the metadata-only terminal
        // receipt without reopening or republishing the filesystem target.
        "completing" if row.publication_result_revision.is_some() => {
            return Ok(AgentEditorCompletionClaim::Execute(row));
        }
        "completing"
            if !force_reclaim
                && row.updated_at_unix_ms.saturating_add(COMPLETION_CLAIM_MS) > now_ms() =>
        {
            return Ok(AgentEditorCompletionClaim::Pending);
        }
        "completing" => {
            let changed = conn.execute("UPDATE agent_editor_leases SET updated_at_unix_ms=?2 WHERE lease_id=?1 AND state='completing' AND updated_at_unix_ms=?3", params![lease_id, now_ms(), row.updated_at_unix_ms])?;
            if changed != 1 {
                return Ok(AgentEditorCompletionClaim::Pending);
            }
            return Ok(AgentEditorCompletionClaim::Execute(
                by_id(conn, &lease_id)?.context("agent editor lease disappeared")?,
            ));
        }
        "open" => {}
        _ => bail!("agent editor lease has an invalid state"),
    }
    let changed = conn.execute("UPDATE agent_editor_leases SET state='completing',snapshot_handle=NULL,completion_identity=?2,completion_handle=?3,completion_operation_id=?4,updated_at_unix_ms=?5 WHERE lease_id=?1 AND state='open'", params![lease_id, completion_hash.as_slice(), completion_handle, completion_operation_id, now_ms()])?;
    if changed != 1 {
        return Ok(AgentEditorCompletionClaim::Pending);
    }
    Ok(AgentEditorCompletionClaim::Execute(
        by_id(conn, &lease_id)?.context("agent editor lease disappeared")?,
    ))
}

pub const AGENT_EDITOR_COMPLETION_CLAIM_MS: i64 = COMPLETION_CLAIM_MS;

fn by_operation(
    conn: &Connection,
    owner: &str,
    operation: &str,
) -> Result<Option<AgentEditorLeaseRow>> {
    query(
        conn,
        "owner_digest=?1 AND client_operation_id=?2",
        params![owner, operation],
    )
}

fn by_id(conn: &Connection, lease_id: &str) -> Result<Option<AgentEditorLeaseRow>> {
    query(conn, "lease_id=?1", params![lease_id])
}

fn query<P: rusqlite::Params>(
    conn: &Connection,
    predicate: &str,
    params: P,
) -> Result<Option<AgentEditorLeaseRow>> {
    let sql = format!(
        "SELECT owner_digest,client_operation_id,lease_id,project_root,agent_name,consumed_revision,snapshot_handle,snapshot_identity,state,completion_identity,completion_handle,completion_operation_id,publication_phase,consumed_projection_identity,intended_projection_identity,publication_result_revision,consumed_config_generation,result_config_generation,terminal_result_json,terminal_error_json,expires_at_unix_ms,updated_at_unix_ms FROM agent_editor_leases WHERE {predicate}"
    );
    conn.query_row(&sql, params, map_row)
        .optional()
        .map_err(Into::into)
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentEditorLeaseRow> {
    let snapshot_identity: Vec<u8> = row.get(7)?;
    let snapshot_identity = snapshot_identity
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let identity: Option<Vec<u8>> = row.get(9)?;
    let identity = identity
        .map(|bytes| bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()?;
    Ok(AgentEditorLeaseRow {
        owner_digest: row.get(0)?,
        client_operation_id: row.get(1)?,
        lease_id: row.get(2)?,
        project_root: row.get(3)?,
        agent_name: row.get(4)?,
        consumed_revision: row.get(5)?,
        snapshot_handle: row.get(6)?,
        snapshot_identity,
        state: row.get(8)?,
        completion_identity: identity,
        completion_handle: row.get(10)?,
        completion_operation_id: row.get(11)?,
        publication_phase: row.get(12)?,
        consumed_projection_identity: row.get(13)?,
        intended_projection_identity: row.get(14)?,
        publication_result_revision: row.get(15)?,
        consumed_config_generation: row
            .get::<_, Option<i64>>(16)?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        result_config_generation: row
            .get::<_, Option<i64>>(17)?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        terminal_result_json: row.get(18)?,
        terminal_error_json: row.get(19)?,
        expires_at_unix_ms: row.get(20)?,
        updated_at_unix_ms: row.get(21)?,
    })
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
