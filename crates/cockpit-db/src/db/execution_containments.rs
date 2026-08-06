//! Durable execution containment recovery rows.
//!
//! Rows bind a generation-scoped platform containment object to a session and
//! operation. Safe locators/digests only — never command args, environment,
//! output, PIDs-as-oracle, or secrets.

use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// Valid durable containment states.
pub const CONTAINMENT_STATES: &[&str] = &["creating", "active", "stopping", "empty", "uncertain"];

/// Durable row for one containment generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionContainmentRow {
    pub containment_id: Uuid,
    pub session_id: Uuid,
    pub operation_id: String,
    pub generation: u64,
    pub platform_kind: String,
    pub state: String,
    pub guarantee: String,
    pub platform_locator_json: String,
    pub runtime_context_digest: Option<String>,
    pub unsupported_reason: Option<String>,
    pub created_at_wall_ms: i64,
    pub updated_at_wall_ms: i64,
    pub emptied_at_wall_ms: Option<i64>,
}

const SELECT_COLS: &str = "containment_id, session_id, operation_id, generation, platform_kind, \
    state, guarantee, platform_locator_json, runtime_context_digest, unsupported_reason, \
    created_at_wall_ms, updated_at_wall_ms, emptied_at_wall_ms";

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ExecutionContainmentRow> {
    let containment_id = Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let session_id = Uuid::parse_str(&row.get::<_, String>(1)?).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(ExecutionContainmentRow {
        containment_id,
        session_id,
        operation_id: row.get(2)?,
        generation: row.get::<_, i64>(3)? as u64,
        platform_kind: row.get(4)?,
        state: row.get(5)?,
        guarantee: row.get(6)?,
        platform_locator_json: row.get(7)?,
        runtime_context_digest: row.get(8)?,
        unsupported_reason: row.get(9)?,
        created_at_wall_ms: row.get(10)?,
        updated_at_wall_ms: row.get(11)?,
        emptied_at_wall_ms: row.get(12)?,
    })
}

/// Inputs for a containment state compare-and-swap.
#[derive(Debug, Clone)]
pub struct CasExecutionContainment {
    pub containment_id: Uuid,
    pub expected_state: String,
    pub expected_generation: u64,
    pub new_state: String,
    pub now_wall_ms: i64,
    pub platform_locator_json: Option<String>,
    pub runtime_context_digest: Option<Option<String>>,
    pub unsupported_reason: Option<Option<String>>,
    pub emptied_at_wall_ms: Option<Option<i64>>,
}

impl Db {
    /// Insert a Creating row before platform allocation.
    pub async fn insert_execution_containment(
        &self,
        row: ExecutionContainmentRow,
    ) -> Result<ExecutionContainmentRow> {
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO execution_containments (
                    containment_id, session_id, operation_id, generation, platform_kind,
                    state, guarantee, platform_locator_json, runtime_context_digest,
                    unsupported_reason, created_at_wall_ms, updated_at_wall_ms,
                    emptied_at_wall_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    row.containment_id.to_string(),
                    row.session_id.to_string(),
                    row.operation_id,
                    row.generation as i64,
                    row.platform_kind,
                    row.state,
                    row.guarantee,
                    row.platform_locator_json,
                    row.runtime_context_digest,
                    row.unsupported_reason,
                    row.created_at_wall_ms,
                    row.updated_at_wall_ms,
                    row.emptied_at_wall_ms,
                ],
            )
            .context("inserting execution_containment")?;
            get_execution_containment_conn(conn, row.containment_id)?
                .ok_or_else(|| anyhow::anyhow!("execution_containment missing after insert"))
        })
        .await
    }

    pub async fn get_execution_containment(
        &self,
        containment_id: Uuid,
    ) -> Result<Option<ExecutionContainmentRow>> {
        self.read(move |conn| get_execution_containment_conn(conn, containment_id))
            .await
    }

    /// Compare-and-swap state with optional generation match.
    pub async fn cas_execution_containment_state(
        &self,
        cas: CasExecutionContainment,
    ) -> Result<Option<ExecutionContainmentRow>> {
        if !CONTAINMENT_STATES.contains(&cas.expected_state.as_str()) {
            bail!("invalid expected containment state {}", cas.expected_state);
        }
        if !CONTAINMENT_STATES.contains(&cas.new_state.as_str()) {
            bail!("invalid new containment state {}", cas.new_state);
        }
        self.write(move |conn| {
            let current = match get_execution_containment_conn(conn, cas.containment_id)? {
                Some(row) => row,
                None => return Ok(None),
            };
            if current.state != cas.expected_state || current.generation != cas.expected_generation
            {
                return Ok(None);
            }
            let locator = cas
                .platform_locator_json
                .unwrap_or(current.platform_locator_json);
            let digest = match cas.runtime_context_digest {
                Some(v) => v,
                None => current.runtime_context_digest,
            };
            let reason = match cas.unsupported_reason {
                Some(v) => v,
                None => current.unsupported_reason,
            };
            let emptied = match cas.emptied_at_wall_ms {
                Some(v) => v,
                None => {
                    if cas.new_state == "empty" {
                        Some(cas.now_wall_ms)
                    } else {
                        current.emptied_at_wall_ms
                    }
                }
            };
            let n = conn
                .execute(
                    "UPDATE execution_containments SET
                        state = ?1,
                        platform_locator_json = ?2,
                        runtime_context_digest = ?3,
                        unsupported_reason = ?4,
                        updated_at_wall_ms = ?5,
                        emptied_at_wall_ms = ?6
                     WHERE containment_id = ?7
                       AND state = ?8
                       AND generation = ?9",
                    params![
                        cas.new_state,
                        locator,
                        digest,
                        reason,
                        cas.now_wall_ms,
                        emptied,
                        cas.containment_id.to_string(),
                        cas.expected_state,
                        cas.expected_generation as i64,
                    ],
                )
                .context("cas execution_containment state")?;
            if n == 0 {
                return Ok(None);
            }
            get_execution_containment_conn(conn, cas.containment_id)
        })
        .await
    }

    /// Bump generation and reset to Creating for recovery/replacement.
    pub async fn bump_execution_containment_generation(
        &self,
        containment_id: Uuid,
        expected_generation: u64,
        now_wall_ms: i64,
        platform_locator_json: &str,
    ) -> Result<Option<ExecutionContainmentRow>> {
        let platform_locator_json = platform_locator_json.to_string();
        self.write(move |conn| {
            let n = conn
                .execute(
                    "UPDATE execution_containments SET
                        generation = generation + 1,
                        state = 'creating',
                        platform_locator_json = ?1,
                        runtime_context_digest = NULL,
                        unsupported_reason = NULL,
                        updated_at_wall_ms = ?2,
                        emptied_at_wall_ms = NULL
                     WHERE containment_id = ?3
                       AND generation = ?4",
                    params![
                        platform_locator_json,
                        now_wall_ms,
                        containment_id.to_string(),
                        expected_generation as i64,
                    ],
                )
                .context("bump execution_containment generation")?;
            if n == 0 {
                return Ok(None);
            }
            get_execution_containment_conn(conn, containment_id)
        })
        .await
    }

    pub async fn list_execution_containments_for_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ExecutionContainmentRow>> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {SELECT_COLS} FROM execution_containments
                     WHERE session_id = ?1
                     ORDER BY created_at_wall_ms ASC"
                ))
                .context("preparing list_execution_containments_for_session")?;
            let rows = stmt
                .query_map(params![session_id.to_string()], map_row)
                .context("querying list_execution_containments_for_session")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding execution_containment")?);
            }
            Ok(out)
        })
        .await
    }

    /// Rows that are not ProvenEmpty (block session deletion / clean shutdown).
    pub async fn list_nonempty_execution_containments(
        &self,
        session_id: Option<Uuid>,
    ) -> Result<Vec<ExecutionContainmentRow>> {
        self.read(move |conn| {
            let mut out = Vec::new();
            if let Some(session_id) = session_id {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {SELECT_COLS} FROM execution_containments
                         WHERE session_id = ?1 AND state != 'empty'
                         ORDER BY created_at_wall_ms ASC"
                    ))
                    .context("preparing nonempty session containments")?;
                let rows = stmt
                    .query_map(params![session_id.to_string()], map_row)
                    .context("querying nonempty session containments")?;
                for row in rows {
                    out.push(row.context("decoding execution_containment")?);
                }
            } else {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT {SELECT_COLS} FROM execution_containments
                         WHERE state != 'empty'
                         ORDER BY created_at_wall_ms ASC"
                    ))
                    .context("preparing nonempty containments")?;
                let rows = stmt
                    .query_map([], map_row)
                    .context("querying nonempty containments")?;
                for row in rows {
                    out.push(row.context("decoding execution_containment")?);
                }
            }
            Ok(out)
        })
        .await
    }

    pub async fn list_all_execution_containments(&self) -> Result<Vec<ExecutionContainmentRow>> {
        self.read(|conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {SELECT_COLS} FROM execution_containments
                     ORDER BY created_at_wall_ms ASC"
                ))
                .context("preparing list_all_execution_containments")?;
            let rows = stmt
                .query_map([], map_row)
                .context("querying list_all_execution_containments")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding execution_containment")?);
            }
            Ok(out)
        })
        .await
    }

    /// Mark a session as deleting. Idempotent.
    pub async fn mark_session_deleting(&self, session_id: Uuid) -> Result<bool> {
        self.write(move |conn| {
            let n = conn
                .execute(
                    "UPDATE sessions SET lifecycle = 'deleting'
                     WHERE session_id = ?1 AND lifecycle = 'active'",
                    params![session_id.to_string()],
                )
                .context("mark_session_deleting")?;
            Ok(n > 0)
        })
        .await
    }

    pub async fn session_lifecycle(&self, session_id: Uuid) -> Result<Option<String>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT lifecycle FROM sessions WHERE session_id = ?1",
                params![session_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .context("session_lifecycle")
        })
        .await
    }

    pub async fn is_session_deleting(&self, session_id: Uuid) -> Result<bool> {
        Ok(self.session_lifecycle(session_id).await?.as_deref() == Some("deleting"))
    }
}

fn get_execution_containment_conn(
    conn: &rusqlite::Connection,
    containment_id: Uuid,
) -> Result<Option<ExecutionContainmentRow>> {
    conn.query_row(
        &format!("SELECT {SELECT_COLS} FROM execution_containments WHERE containment_id = ?1"),
        params![containment_id.to_string()],
        map_row,
    )
    .optional()
    .context("get_execution_containment")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    async fn seed_session(db: &Db) -> Uuid {
        let row = db
            .create_session("proj", "/tmp/containment-test", "orchestrator-build")
            .await
            .unwrap();
        row.session_id
    }

    fn sample_row(session_id: Uuid) -> ExecutionContainmentRow {
        ExecutionContainmentRow {
            containment_id: Uuid::new_v4(),
            session_id,
            operation_id: "op-1".into(),
            generation: 1,
            platform_kind: "fake".into(),
            state: "creating".into(),
            guarantee: "proven".into(),
            platform_locator_json: "{}".into(),
            runtime_context_digest: None,
            unsupported_reason: None,
            created_at_wall_ms: 1000,
            updated_at_wall_ms: 1000,
            emptied_at_wall_ms: None,
        }
    }

    #[tokio::test]
    async fn insert_cas_and_nonempty_listing() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let row = sample_row(session_id);
        let id = row.containment_id;
        db.insert_execution_containment(row).await.unwrap();

        let cas = db
            .cas_execution_containment_state(CasExecutionContainment {
                containment_id: id,
                expected_state: "creating".into(),
                expected_generation: 1,
                new_state: "active".into(),
                now_wall_ms: 2000,
                platform_locator_json: Some(r#"{"loc":"x"}"#.into()),
                runtime_context_digest: None,
                unsupported_reason: None,
                emptied_at_wall_ms: None,
            })
            .await
            .unwrap()
            .expect("cas should succeed");
        assert_eq!(cas.state, "active");
        assert!(cas.platform_locator_json.contains("loc"));

        let nonempty = db
            .list_nonempty_execution_containments(Some(session_id))
            .await
            .unwrap();
        assert_eq!(nonempty.len(), 1);

        let empty = db
            .cas_execution_containment_state(CasExecutionContainment {
                containment_id: id,
                expected_state: "active".into(),
                expected_generation: 1,
                new_state: "empty".into(),
                now_wall_ms: 3000,
                platform_locator_json: None,
                runtime_context_digest: None,
                unsupported_reason: None,
                emptied_at_wall_ms: None,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(empty.state, "empty");
        assert_eq!(empty.emptied_at_wall_ms, Some(3000));
        assert!(
            db.list_nonempty_execution_containments(Some(session_id))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn generation_bump_rejects_stale() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        let row = sample_row(session_id);
        let id = row.containment_id;
        db.insert_execution_containment(row).await.unwrap();
        let bumped = db
            .bump_execution_containment_generation(id, 1, 5000, r#"{"g":2}"#)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bumped.generation, 2);
        assert_eq!(bumped.state, "creating");
        assert!(
            db.bump_execution_containment_generation(id, 1, 6000, "{}")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn mark_session_deleting_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_session(&db).await;
        assert!(db.mark_session_deleting(session_id).await.unwrap());
        assert!(!db.mark_session_deleting(session_id).await.unwrap());
        assert!(db.is_session_deleting(session_id).await.unwrap());
    }
}
