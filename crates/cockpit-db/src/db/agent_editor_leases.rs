//! Durable, owner-bound external-editor lease persistence.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use super::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEditorLeaseRow {
    pub owner_digest: String,
    pub client_operation_id: String,
    pub lease_id: String,
    pub project_root: String,
    pub agent_name: String,
    pub consumed_revision: String,
    pub snapshot_json: String,
    pub state: String,
    pub completion_hash: Option<[u8; 32]>,
    pub terminal_result_json: Option<String>,
    pub expires_at_unix_ms: i64,
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

    pub async fn insert_agent_editor_lease(&self, row: AgentEditorLeaseRow) -> Result<()> {
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO agent_editor_leases
                 (owner_digest,client_operation_id,lease_id,project_root,agent_name,
                  consumed_revision,snapshot_json,state,completion_hash,terminal_result_json,
                  expires_at_unix_ms,created_at_unix_ms,updated_at_unix_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,'open',NULL,NULL,?8,?9,?9)",
                params![
                    row.owner_digest,
                    row.client_operation_id,
                    row.lease_id,
                    row.project_root,
                    row.agent_name,
                    row.consumed_revision,
                    row.snapshot_json,
                    row.expires_at_unix_ms,
                    now_ms()
                ],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn reserve_agent_editor_completion(
        &self,
        lease_id: String,
        owner_digest: String,
        completion_hash: [u8; 32],
    ) -> Result<AgentEditorLeaseRow> {
        self.transaction(move |conn| {
            let row = by_id(conn, &lease_id)?.context("agent editor lease is absent")?;
            if row.owner_digest != owner_digest { bail!("agent editor lease belongs to another owner"); }
            if let Some(existing) = row.completion_hash
                && existing != completion_hash { bail!("agent editor lease was settled with different content"); }
            if row.state == "open" {
                conn.execute("UPDATE agent_editor_leases SET state='completing',completion_hash=?2,updated_at_unix_ms=?3 WHERE lease_id=?1 AND state='open'", params![lease_id, completion_hash.as_slice(), now_ms()])?;
            }
            by_id(conn, &lease_id)?.context("agent editor lease disappeared")
        }).await
    }

    pub async fn finish_agent_editor_completion(
        &self,
        lease_id: String,
        completion_hash: [u8; 32],
        terminal_result_json: String,
    ) -> Result<()> {
        self.write(move |conn| {
            let changed = conn.execute("UPDATE agent_editor_leases SET state='terminal',terminal_result_json=?3,updated_at_unix_ms=?4 WHERE lease_id=?1 AND state='completing' AND completion_hash=?2", params![lease_id, completion_hash.as_slice(), terminal_result_json, now_ms()])?;
            if changed != 1 { bail!("agent editor lease completion lost its durable reservation"); }
            Ok(())
        }).await
    }

    pub async fn reopen_agent_editor_completion(
        &self,
        lease_id: String,
        completion_hash: [u8; 32],
    ) -> Result<()> {
        self.write(move |conn| {
            conn.execute("UPDATE agent_editor_leases SET state='open',completion_hash=NULL,updated_at_unix_ms=?3 WHERE lease_id=?1 AND state='completing' AND completion_hash=?2", params![lease_id, completion_hash.as_slice(), now_ms()])?;
            Ok(())
        }).await
    }
}

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
        "SELECT owner_digest,client_operation_id,lease_id,project_root,agent_name,consumed_revision,snapshot_json,state,completion_hash,terminal_result_json,expires_at_unix_ms FROM agent_editor_leases WHERE {predicate}"
    );
    conn.query_row(&sql, params, |row| {
        let hash: Option<Vec<u8>> = row.get(8)?;
        let hash = hash
            .map(|bytes| bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?;
        Ok(AgentEditorLeaseRow {
            owner_digest: row.get(0)?,
            client_operation_id: row.get(1)?,
            lease_id: row.get(2)?,
            project_root: row.get(3)?,
            agent_name: row.get(4)?,
            consumed_revision: row.get(5)?,
            snapshot_json: row.get(6)?,
            state: row.get(7)?,
            completion_hash: hash,
            terminal_result_json: row.get(9)?,
            expires_at_unix_ms: row.get(10)?,
        })
    })
    .optional()
    .map_err(Into::into)
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
