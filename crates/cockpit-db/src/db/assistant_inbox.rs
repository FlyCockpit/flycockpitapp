//! Durable per-assistant inbox items raised by persistent assistant threads.
//!
//! The inbox is deliberately assistant-scoped rather than a thread-to-thread
//! transport.  A raised item always retains both the raising thread and the
//! main session backlink, while the main session owns delivery at a later turn
//! boundary.  This keeps an arriving item out of a warm prompt prefix.

use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{Db, sessions::SessionRow};

/// Product limit for an assistant's raise amplification during one rolling
/// hour.  It applies before a row is inserted, so a raise → spawn → raise
/// cycle remains bounded even when every cycle uses a fresh thread.
pub const MAX_RAISES_PER_ASSISTANT_PER_HOUR: i64 = 32;

/// Product limit for not-yet-delivered work visible in one assistant inbox.
pub const MAX_PENDING_INBOX_ITEMS_PER_ASSISTANT: i64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistantInboxDelivery {
    Immediate,
    Defer,
    Notify,
}

impl AssistantInboxDelivery {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::Defer => "defer",
            Self::Notify => "notify",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "immediate" => Ok(Self::Immediate),
            "defer" => Ok(Self::Defer),
            "notify" => Ok(Self::Notify),
            other => Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                format!("unknown assistant inbox delivery `{other}`").into(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssistantInboxItem {
    pub inbox_item_id: Uuid,
    pub assistant_name: String,
    pub main_session_id: Uuid,
    pub raising_session_id: Uuid,
    pub summary: String,
    pub delivery: AssistantInboxDelivery,
    pub created_at_unix_ms: i64,
    pub delivered_at_unix_ms: Option<i64>,
}

impl AssistantInboxItem {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let inbox_item_id: String = row.get("inbox_item_id")?;
        let main_session_id: String = row.get("main_session_id")?;
        let raising_session_id: String = row.get("raising_session_id")?;
        let delivery: String = row.get("delivery")?;
        Ok(Self {
            inbox_item_id: Uuid::parse_str(&inbox_item_id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    error.into(),
                )
            })?,
            assistant_name: row.get("assistant_name")?,
            main_session_id: Uuid::parse_str(&main_session_id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    error.into(),
                )
            })?,
            raising_session_id: Uuid::parse_str(&raising_session_id).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    error.into(),
                )
            })?,
            summary: row.get("summary")?,
            delivery: AssistantInboxDelivery::parse(&delivery)?,
            created_at_unix_ms: row.get("created_at_unix_ms")?,
            delivered_at_unix_ms: row.get("delivered_at_unix_ms")?,
        })
    }
}

impl Db {
    /// Insert a structured item into the owning assistant's inbox.
    ///
    /// Only a durable assistant thread may raise.  The target is resolved by
    /// walking the thread's parent chain to its non-thread root; callers never
    /// supply a destination, which prevents point-to-point thread messaging.
    pub async fn raise_assistant_inbox_item(
        &self,
        raising_session_id: Uuid,
        summary: String,
        delivery: AssistantInboxDelivery,
    ) -> Result<AssistantInboxItem> {
        let summary = summary.trim().to_string();
        ensure!(
            !summary.is_empty(),
            "assistant inbox summary must not be empty"
        );
        ensure!(
            summary.len() <= 4_000,
            "assistant inbox summary exceeds 4000 bytes"
        );
        let inbox_item_id = Uuid::new_v4();
        let now = Utc::now().timestamp_millis();
        self.transaction(move |conn| {
            let raising = session_row(conn, raising_session_id)?;
            ensure!(
                raising.is_assistant_thread,
                "`raise` is available only from a persistent assistant thread"
            );
            let assistant_name = raising
                .assistant_name
                .clone()
                .context("assistant thread has no assistant owner")?;
            let main = assistant_main_session(conn, &raising, &assistant_name)?;

            let recent: i64 = conn.query_row(
                "SELECT COUNT(*) FROM assistant_inbox_items
                   WHERE assistant_name = ?1 AND created_at_unix_ms >= ?2",
                params![assistant_name, now - 60 * 60 * 1_000],
                |row| row.get(0),
            )?;
            ensure!(
                recent < MAX_RAISES_PER_ASSISTANT_PER_HOUR,
                "assistant inbox raise guard reached; wait before raising again"
            );
            let pending: i64 = conn.query_row(
                "SELECT COUNT(*) FROM assistant_inbox_items
                   WHERE assistant_name = ?1 AND delivered_at_unix_ms IS NULL",
                params![assistant_name],
                |row| row.get(0),
            )?;
            ensure!(
                pending < MAX_PENDING_INBOX_ITEMS_PER_ASSISTANT,
                "assistant inbox already has the maximum pending items"
            );

            conn.execute(
                "INSERT INTO assistant_inbox_items(
                    inbox_item_id, assistant_name, main_session_id,
                    raising_session_id, summary, delivery, created_at_unix_ms
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    inbox_item_id.to_string(),
                    assistant_name,
                    main.session_id.to_string(),
                    raising_session_id.to_string(),
                    summary,
                    delivery.as_str(),
                    now,
                ],
            )
            .context("inserting assistant inbox item")?;
            assistant_inbox_item_conn(conn, inbox_item_id)?.context("inserted inbox item missing")
        })
        .await
    }

    /// User-visible inbox entries for one main assistant session.  Delivered
    /// items stay visible as history; callers select the unread badge by
    /// filtering `delivered_at_unix_ms IS NULL` in the same durable query.
    pub async fn assistant_inbox_for_main(
        &self,
        main_session_id: Uuid,
        include_delivered: bool,
        limit: u32,
    ) -> Result<Vec<AssistantInboxItem>> {
        self.read(move |conn| {
            let sql = if include_delivered {
                "SELECT * FROM assistant_inbox_items WHERE main_session_id = ?1
                   ORDER BY created_at_unix_ms DESC, inbox_item_id DESC LIMIT ?2"
            } else {
                "SELECT * FROM assistant_inbox_items
                   WHERE main_session_id = ?1 AND delivered_at_unix_ms IS NULL
                   ORDER BY created_at_unix_ms ASC, inbox_item_id ASC LIMIT ?2"
            };
            let mut statement = conn
                .prepare(sql)
                .context("preparing assistant inbox page")?;
            let rows = statement.query_map(
                params![main_session_id.to_string(), limit],
                AssistantInboxItem::from_row,
            )?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .context("decoding assistant inbox page")
        })
        .await
    }

    /// Atomically claim the items that are allowed to enter a main turn.
    /// `notify` items deliberately never appear here: remote notification is
    /// a later remote-track delivery and must not wake or inject agent work.
    pub async fn claim_assistant_inbox_for_delivery(
        &self,
        main_session_id: Uuid,
        include_deferred: bool,
    ) -> Result<Vec<AssistantInboxItem>> {
        let now = Utc::now().timestamp_millis();
        self.transaction(move |conn| {
            let mode_filter = if include_deferred {
                "('immediate', 'defer')"
            } else {
                "('immediate')"
            };
            let sql = format!(
                "SELECT * FROM assistant_inbox_items
                   WHERE main_session_id = ?1 AND delivered_at_unix_ms IS NULL
                     AND delivery IN {mode_filter}
                   ORDER BY created_at_unix_ms ASC, inbox_item_id ASC"
            );
            let mut statement = conn
                .prepare(&sql)
                .context("preparing inbox delivery claim")?;
            let items = statement
                .query_map(
                    params![main_session_id.to_string()],
                    AssistantInboxItem::from_row,
                )?
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("decoding inbox delivery claim")?;
            for item in &items {
                let changed = conn.execute(
                    "UPDATE assistant_inbox_items
                       SET delivered_at_unix_ms = ?1
                     WHERE inbox_item_id = ?2 AND delivered_at_unix_ms IS NULL",
                    params![now, item.inbox_item_id.to_string()],
                )?;
                ensure!(changed == 1, "assistant inbox delivery claim raced");
            }
            Ok(items)
        })
        .await
    }
}

fn session_row(conn: &Connection, session_id: Uuid) -> Result<SessionRow> {
    conn.query_row(
        "SELECT * FROM sessions WHERE session_id = ?1",
        params![session_id.to_string()],
        SessionRow::from_row,
    )
    .optional()
    .context("reading assistant inbox session")?
    .context("assistant inbox session does not exist")
}

fn assistant_main_session(
    conn: &Connection,
    raising: &SessionRow,
    assistant_name: &str,
) -> Result<SessionRow> {
    let mut current = raising.clone();
    for _ in 0..32 {
        let Some(parent_id) = current.parent_session_id else {
            ensure!(
                !current.is_assistant_thread,
                "assistant thread ancestry has no main session"
            );
            ensure!(
                current.assistant_name.as_deref() == Some(assistant_name),
                "assistant thread ancestry crossed assistant ownership"
            );
            return Ok(current);
        };
        current = session_row(conn, parent_id)?;
    }
    bail!("assistant thread ancestry exceeds maximum depth")
}

fn assistant_inbox_item_conn(
    conn: &Connection,
    inbox_item_id: Uuid,
) -> Result<Option<AssistantInboxItem>> {
    conn.query_row(
        "SELECT * FROM assistant_inbox_items WHERE inbox_item_id = ?1",
        params![inbox_item_id.to_string()],
        AssistantInboxItem::from_row,
    )
    .optional()
    .context("reading assistant inbox item")
}
