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
                "SELECT owner_digest,client_operation_id,lease_id,project_root,agent_name,consumed_revision,snapshot_handle,snapshot_identity,state,completion_identity,terminal_result_json,terminal_error_json,expires_at_unix_ms,updated_at_unix_ms
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

    pub async fn abandoned_agent_editor_completions(
        &self,
        cutoff_unix_ms: i64,
    ) -> Result<Vec<AgentEditorLeaseRow>> {
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT owner_digest,client_operation_id,lease_id,project_root,agent_name,consumed_revision,snapshot_handle,snapshot_identity,state,completion_identity,terminal_result_json,terminal_error_json,expires_at_unix_ms,updated_at_unix_ms
                 FROM agent_editor_leases
                 WHERE state='completing' AND updated_at_unix_ms <= ?1
                 ORDER BY updated_at_unix_ms ASC LIMIT 128",
            )?;
            let rows = statement
                .query_map([cutoff_unix_ms], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
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
                  consumed_revision,snapshot_handle,snapshot_identity,state,completion_identity,terminal_result_json,terminal_error_json,
                  expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'open',NULL,NULL,NULL,?9,?10,?10)",
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

pub fn finish_agent_editor_completion_conn(
    conn: &Connection,
    lease_id: &str,
    completion_hash: [u8; 32],
    terminal_result_json: &str,
) -> Result<()> {
    let changed = conn.execute(
        "UPDATE agent_editor_leases SET state='terminal',snapshot_handle=NULL,terminal_result_json=?3,terminal_error_json=NULL,updated_at_unix_ms=?4 WHERE lease_id=?1 AND state='completing' AND completion_identity=?2",
        params![lease_id, completion_hash.as_slice(), terminal_result_json, now_ms()],
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
    terminal_error_json: &str,
) -> Result<()> {
    let changed = conn.execute(
        "UPDATE agent_editor_leases SET state='terminal',snapshot_handle=NULL,terminal_result_json=NULL,terminal_error_json=?3,updated_at_unix_ms=?4 WHERE lease_id=?1 AND state='completing' AND completion_identity=?2",
        params![lease_id, completion_identity.as_slice(), terminal_error_json, now_ms()],
    )?;
    if changed != 1 {
        bail!("agent editor lease failure lost its durable reservation");
    }
    Ok(())
}

impl Db {
    pub async fn reserve_agent_editor_completion(
        &self,
        lease_id: String,
        owner_digest: String,
        completion_hash: [u8; 32],
    ) -> Result<AgentEditorCompletionClaim> {
        self.transaction(move |conn| {
            let row = by_id(conn, &lease_id)?.context("agent editor lease is absent")?;
            if row.owner_digest != owner_digest { bail!("agent editor lease belongs to another owner"); }
            if let Some(existing) = row.completion_identity
                && existing != completion_hash { bail!("agent editor lease was settled with different content"); }
            match row.state.as_str() {
                "terminal" => return Ok(AgentEditorCompletionClaim::Terminal(row)),
                "completing" if row.updated_at_unix_ms.saturating_add(COMPLETION_CLAIM_MS) > now_ms() => return Ok(AgentEditorCompletionClaim::Pending),
                "completing" => {
                    let changed = conn.execute("UPDATE agent_editor_leases SET updated_at_unix_ms=?2 WHERE lease_id=?1 AND state='completing' AND updated_at_unix_ms=?3", params![lease_id, now_ms(), row.updated_at_unix_ms])?;
                    if changed != 1 { return Ok(AgentEditorCompletionClaim::Pending); }
                    return Ok(AgentEditorCompletionClaim::Execute(by_id(conn, &lease_id)?.context("agent editor lease disappeared")?));
                }
                "open" => {}
                _ => bail!("agent editor lease has an invalid state"),
            }
            let changed = conn.execute("UPDATE agent_editor_leases SET state='completing',completion_identity=?2,updated_at_unix_ms=?3 WHERE lease_id=?1 AND state='open'", params![lease_id, completion_hash.as_slice(), now_ms()])?;
            if changed != 1 { return Ok(AgentEditorCompletionClaim::Pending); }
            Ok(AgentEditorCompletionClaim::Execute(by_id(conn, &lease_id)?.context("agent editor lease disappeared")?))
        }).await
    }

    pub async fn finish_agent_editor_completion(
        &self,
        lease_id: String,
        completion_hash: [u8; 32],
        terminal_result_json: String,
    ) -> Result<()> {
        self.write(move |conn| {
            finish_agent_editor_completion_conn(
                conn,
                &lease_id,
                completion_hash,
                &terminal_result_json,
            )
        })
        .await
    }
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
        "SELECT owner_digest,client_operation_id,lease_id,project_root,agent_name,consumed_revision,snapshot_handle,snapshot_identity,state,completion_identity,terminal_result_json,terminal_error_json,expires_at_unix_ms,updated_at_unix_ms FROM agent_editor_leases WHERE {predicate}"
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
        terminal_result_json: row.get(10)?,
        terminal_error_json: row.get(11)?,
        expires_at_unix_ms: row.get(12)?,
        updated_at_unix_ms: row.get(13)?,
    })
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
