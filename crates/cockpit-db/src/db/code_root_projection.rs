//! Durable, redacted delivery projection for ACP Code-root attachments.
//!
//! This module intentionally knows nothing about ACP capabilities or wire
//! records. The daemon projection writer supplies an already-bounded kind and
//! JSON object; this leaf stores ordering, opaque cursor mapping, and durable
//! logical-client ACK state.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

pub const MAX_CODE_ROOT_PROJECTION_PAYLOAD_BYTES: usize = 512 * 1024;
pub const MAX_CODE_ROOT_DELIVERY_PAGE: u16 = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRootProjectionDeliveryRow {
    pub sequence: i64,
    pub delivery_id: Uuid,
    pub replay_cursor: String,
    pub session_id: Uuid,
    pub kind: String,
    pub payload_json: String,
    pub created_at_unix_ms: i64,
}

impl Db {
    pub async fn append_code_root_projection_delivery(
        &self,
        session_id: Uuid,
        kind: &str,
        source_key: Option<&str>,
        payload_json: &str,
        created_at_unix_ms: i64,
    ) -> Result<CodeRootProjectionDeliveryRow> {
        validate_projection_input(kind, payload_json)?;
        let kind = kind.to_owned();
        let source_key = source_key.map(str::to_owned);
        let payload_json = payload_json.to_owned();
        self.write(move |conn| {
            Self::append_code_root_projection_delivery_conn(
                conn,
                session_id,
                &kind,
                source_key.as_deref(),
                &payload_json,
                created_at_unix_ms,
            )
        })
        .await
    }

    pub fn append_code_root_projection_delivery_conn(
        conn: &Connection,
        session_id: Uuid,
        kind: &str,
        source_key: Option<&str>,
        payload_json: &str,
        created_at_unix_ms: i64,
    ) -> Result<CodeRootProjectionDeliveryRow> {
        validate_projection_input(kind, payload_json)?;
        let delivery_id = Uuid::new_v4();
        let replay_cursor = Uuid::new_v4().simple().to_string();
        let inserted = conn.execute(
            "INSERT INTO code_root_projection_deliveries
             (delivery_id, replay_cursor, session_id, source_key, kind, payload_json, created_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(session_id, kind, source_key) WHERE source_key IS NOT NULL DO NOTHING",
            params![
                delivery_id.to_string(),
                replay_cursor,
                session_id.to_string(),
                source_key,
                kind,
                payload_json,
                created_at_unix_ms,
            ],
        )
        .context("inserting Code-root projection delivery")?;
        if inserted == 0 {
            let source_key = source_key.context("deduplicated projection requires source key")?;
            return conn
                .query_row(
                    "SELECT sequence, delivery_id, replay_cursor, session_id, kind,
                            payload_json, created_at_unix_ms
                     FROM code_root_projection_deliveries
                     WHERE session_id = ?1 AND kind = ?2 AND source_key = ?3",
                    params![session_id.to_string(), kind, source_key],
                    decode_delivery,
                )
                .context("reading existing Code-root projection delivery");
        }
        let sequence = conn.last_insert_rowid();
        Ok(CodeRootProjectionDeliveryRow {
            sequence,
            delivery_id,
            replay_cursor,
            session_id,
            kind: kind.to_owned(),
            payload_json: payload_json.to_owned(),
            created_at_unix_ms,
        })
    }

    pub async fn read_code_root_projection_deliveries(
        &self,
        session_id: Uuid,
        after_cursor: Option<&str>,
        limit: u16,
    ) -> Result<Vec<CodeRootProjectionDeliveryRow>> {
        ensure!(
            (1..=MAX_CODE_ROOT_DELIVERY_PAGE).contains(&limit),
            "Code-root delivery limit must be 1..={MAX_CODE_ROOT_DELIVERY_PAGE}"
        );
        let after_cursor = after_cursor.map(str::to_owned);
        self.read(move |conn| {
            let after_sequence = match after_cursor {
                Some(cursor) => conn
                    .query_row(
                        "SELECT sequence FROM code_root_projection_deliveries
                         WHERE session_id = ?1 AND replay_cursor = ?2",
                        params![session_id.to_string(), cursor],
                        |row| row.get(0),
                    )
                    .optional()
                    .context("resolving Code-root replay cursor")?
                    .ok_or_else(|| anyhow::anyhow!("unknown Code-root replay cursor"))?,
                None => 0,
            };
            let mut statement = conn.prepare(
                "SELECT sequence, delivery_id, replay_cursor, session_id, kind,
                        payload_json, created_at_unix_ms
                 FROM code_root_projection_deliveries
                 WHERE session_id = ?1 AND sequence > ?2
                 ORDER BY sequence ASC LIMIT ?3",
            )?;
            let rows = statement.query_map(
                params![session_id.to_string(), after_sequence, i64::from(limit)],
                decode_delivery,
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .context("reading Code-root projection deliveries")
        })
        .await
    }

    pub async fn acknowledge_code_root_projection(
        &self,
        session_id: Uuid,
        logical_client_id: &str,
        through_cursor: &str,
        updated_at_unix_ms: i64,
    ) -> Result<()> {
        ensure!(
            !logical_client_id.is_empty()
                && logical_client_id.len() <= 128
                && logical_client_id
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic()),
            "invalid Code-root logical client id"
        );
        let logical_client_id = logical_client_id.to_owned();
        let through_cursor = through_cursor.to_owned();
        self.write(move |conn| {
            let sequence: i64 = conn
                .query_row(
                    "SELECT sequence FROM code_root_projection_deliveries
                     WHERE session_id = ?1 AND replay_cursor = ?2",
                    params![session_id.to_string(), through_cursor],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or_else(|| anyhow::anyhow!("unknown Code-root replay cursor"))?;
            conn.execute(
                "INSERT INTO code_root_replay_cursors
                 (session_id, logical_client_id, acknowledged_sequence, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(session_id, logical_client_id) DO UPDATE SET
                    acknowledged_sequence = max(acknowledged_sequence, excluded.acknowledged_sequence),
                    updated_at_unix_ms = CASE
                        WHEN excluded.acknowledged_sequence >= acknowledged_sequence
                        THEN excluded.updated_at_unix_ms ELSE updated_at_unix_ms END",
                params![
                    session_id.to_string(),
                    logical_client_id,
                    sequence,
                    updated_at_unix_ms,
                ],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn code_root_replay_cursor_for_client(
        &self,
        session_id: Uuid,
        logical_client_id: &str,
    ) -> Result<Option<String>> {
        ensure!(
            !logical_client_id.is_empty()
                && logical_client_id.len() <= 128
                && logical_client_id
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic()),
            "invalid Code-root logical client id"
        );
        let logical_client_id = logical_client_id.to_owned();
        self.read(move |conn| {
            conn.query_row(
                "SELECT delivery.replay_cursor
                 FROM code_root_replay_cursors AS acknowledged
                 JOIN code_root_projection_deliveries AS delivery
                   ON delivery.session_id = acknowledged.session_id
                  AND delivery.sequence = acknowledged.acknowledged_sequence
                 WHERE acknowledged.session_id = ?1
                   AND acknowledged.logical_client_id = ?2",
                params![session_id.to_string(), logical_client_id],
                |row| row.get(0),
            )
            .optional()
            .context("reading durable Code-root replay cursor")
        })
        .await
    }
}

fn validate_projection_input(kind: &str, payload_json: &str) -> Result<()> {
    if !matches!(
        kind,
        "history" | "attention" | "root_state_changed" | "client_incompatible"
    ) {
        bail!("unsupported Code-root projection kind");
    }
    ensure!(
        payload_json.len() <= MAX_CODE_ROOT_PROJECTION_PAYLOAD_BYTES,
        "Code-root projection payload exceeds limit"
    );
    let payload: serde_json::Value =
        serde_json::from_str(payload_json).context("parsing Code-root projection payload")?;
    ensure!(
        payload.is_object(),
        "Code-root projection payload must be an object"
    );
    Ok(())
}

fn decode_delivery(row: &rusqlite::Row<'_>) -> rusqlite::Result<CodeRootProjectionDeliveryRow> {
    let delivery_id: String = row.get(1)?;
    let session_id: String = row.get(3)?;
    Ok(CodeRootProjectionDeliveryRow {
        sequence: row.get(0)?,
        delivery_id: Uuid::parse_str(&delivery_id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        replay_cursor: row.get(2)?,
        session_id: Uuid::parse_str(&session_id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        kind: row.get(4)?,
        payload_json: row.get(5)?,
        created_at_unix_ms: row.get(6)?,
    })
}
