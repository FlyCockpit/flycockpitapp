//! Private durable replay authority for one provider-emitted tool-call turn.
//!
//! Unlike the exportable `tool_call_scheduling` timeline event, these rows may
//! contain canonical wire input. They are never projected by session export;
//! their only consumer is local crash recovery.

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, params};
use serde_json::Value;
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone)]
pub struct TurnSchedulerContinuationInput {
    pub source_index: usize,
    pub call_id: String,
    pub provider_item_id: Option<String>,
    pub provider_call_id: Option<String>,
    pub resolved_tool: String,
    pub wire_input: Value,
    pub classification: String,
}

#[derive(Debug, Clone)]
pub struct TurnSchedulerContinuationRow {
    pub turn_id: Uuid,
    pub agent_id: String,
    pub source_index: usize,
    pub call_id: String,
    pub provider_item_id: Option<String>,
    pub provider_call_id: Option<String>,
    pub resolved_tool: String,
    pub wire_input: Value,
    pub classification: String,
    pub terminal_outcome: Option<String>,
}

impl Db {
    pub async fn persist_turn_scheduler_plan(
        &self,
        session_id: Uuid,
        turn_id: Uuid,
        agent_id: String,
        calls: Vec<TurnSchedulerContinuationInput>,
        created_at_unix_ms: i64,
    ) -> Result<()> {
        ensure!(!calls.is_empty(), "turn scheduler plan must contain calls");
        self.transaction(move |conn| {
            for call in calls {
                let source_index = i64::try_from(call.source_index)
                    .context("turn scheduler source index overflow")?;
                let wire_input_json = serde_json::to_string(&call.wire_input)
                    .context("serializing turn scheduler wire input")?;
                conn.execute(
                    "INSERT INTO turn_scheduler_continuations (
                         session_id, turn_id, agent_id, source_index, call_id,
                         provider_item_id, provider_call_id, resolved_tool,
                         wire_input_json, classification, terminal_outcome,
                         created_at_unix_ms, settled_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11, NULL)",
                    params![
                        session_id.to_string(),
                        turn_id.to_string(),
                        &agent_id,
                        source_index,
                        call.call_id,
                        call.provider_item_id,
                        call.provider_call_id,
                        call.resolved_tool,
                        wire_input_json,
                        call.classification,
                        created_at_unix_ms,
                    ],
                )
                .context("inserting turn scheduler continuation")?;
            }
            Ok(())
        })
        .await
    }

    pub async fn settle_turn_scheduler_call(
        &self,
        session_id: Uuid,
        turn_id: Uuid,
        call_id: String,
        terminal_outcome: String,
        settled_at_unix_ms: i64,
    ) -> Result<()> {
        self.write(move |conn| {
            let changed = conn.execute(
                "UPDATE turn_scheduler_continuations
                    SET terminal_outcome = ?1, settled_at_unix_ms = ?2
                  WHERE session_id = ?3 AND turn_id = ?4 AND call_id = ?5
                    AND terminal_outcome IS NULL",
                params![
                    terminal_outcome,
                    settled_at_unix_ms,
                    session_id.to_string(),
                    turn_id.to_string(),
                    call_id,
                ],
            )?;
            ensure!(
                changed == 1,
                "turn scheduler call was absent or already settled"
            );
            Ok(())
        })
        .await
    }

    pub fn list_turn_scheduler_continuations_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<Vec<TurnSchedulerContinuationRow>> {
        let mut stmt = conn.prepare(
            "SELECT turn_id, agent_id, source_index, call_id, provider_item_id,
                    provider_call_id, resolved_tool, wire_input_json,
                    classification, terminal_outcome
               FROM turn_scheduler_continuations
              WHERE session_id = ?1
              ORDER BY created_at_unix_ms, turn_id, source_index",
        )?;
        let rows = stmt.query_map([session_id.to_string()], |row| {
            let turn_id: String = row.get(0)?;
            let agent_id: String = row.get(1)?;
            let source_index: i64 = row.get(2)?;
            let wire_input_json: String = row.get(7)?;
            Ok((
                turn_id,
                agent_id,
                source_index,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                wire_input_json,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
            ))
        })?;
        rows.map(|row| {
            let (
                turn_id,
                agent_id,
                source_index,
                call_id,
                provider_item_id,
                provider_call_id,
                resolved_tool,
                wire_input_json,
                classification,
                terminal_outcome,
            ) = row?;
            Ok(TurnSchedulerContinuationRow {
                turn_id: Uuid::parse_str(&turn_id).context("invalid scheduler turn id")?,
                agent_id,
                source_index: usize::try_from(source_index)
                    .context("invalid scheduler source index")?,
                call_id,
                provider_item_id,
                provider_call_id,
                resolved_tool,
                wire_input: serde_json::from_str(&wire_input_json)
                    .context("invalid scheduler wire input")?,
                classification,
                terminal_outcome,
            })
        })
        .collect()
    }
}
