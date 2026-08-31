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

/// Corrupt session ancestry must not turn inbox delivery into an unbounded
/// database walk. This is deliberately independent from the per-hour raise
/// limit: a valid thread lineage can contain every currently permitted raise.
const MAX_ASSISTANT_THREAD_ANCESTRY_DEPTH: usize = 128;

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
    pub operation_scope: String,
    pub operation_id: String,
    pub summary: String,
    pub delivery: AssistantInboxDelivery,
    pub created_at_unix_ms: i64,
    pub delivered_at_unix_ms: Option<i64>,
    pub human_read_at_unix_ms: Option<i64>,
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
            operation_scope: row.get("operation_scope")?,
            operation_id: row.get("operation_id")?,
            summary: row.get("summary")?,
            delivery: AssistantInboxDelivery::parse(&delivery)?,
            created_at_unix_ms: row.get("created_at_unix_ms")?,
            delivered_at_unix_ms: row.get("delivered_at_unix_ms")?,
            human_read_at_unix_ms: row.get("human_read_at_unix_ms")?,
        })
    }
}

impl Db {
    /// Insert a structured item into the owning assistant's inbox.
    ///
    /// Only a durable assistant thread may raise. `operation_scope` is the
    /// daemon-owned inference/replay attempt identity; `operation_id` is the
    /// provider's retry correlation within that scope. The target is resolved
    /// by walking the thread's parent chain to its non-thread root; callers
    /// never supply a destination, which prevents point-to-point thread
    /// messaging.
    pub async fn raise_assistant_inbox_item(
        &self,
        raising_session_id: Uuid,
        operation_scope: String,
        operation_id: String,
        summary: String,
        delivery: AssistantInboxDelivery,
    ) -> Result<AssistantInboxItem> {
        let summary = summary.trim().to_string();
        ensure!(
            !operation_scope.is_empty(),
            "assistant inbox operation scope must not be empty"
        );
        ensure!(
            operation_scope.len() <= 128,
            "assistant inbox operation scope exceeds 128 bytes"
        );
        ensure!(
            !operation_id.is_empty(),
            "assistant inbox operation id must not be empty"
        );
        ensure!(
            operation_id.len() <= 1_024,
            "assistant inbox operation id exceeds 1024 bytes"
        );
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

            if let Some(existing) = conn
                .query_row(
                    "SELECT * FROM assistant_inbox_items
                       WHERE raising_session_id = ?1
                         AND operation_scope = ?2
                         AND operation_id = ?3",
                    params![raising_session_id.to_string(), operation_scope, operation_id],
                    AssistantInboxItem::from_row,
                )
                .optional()
                .context("reading prior assistant inbox operation")?
            {
                ensure!(
                    existing.summary == summary && existing.delivery == delivery,
                    "assistant inbox operation identity was reused with different arguments"
                );
                return Ok(existing);
            }

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
                   WHERE assistant_name = ?1 AND delivered_at_unix_ms IS NULL
                     AND delivery <> 'notify'",
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
                    raising_session_id, operation_scope, operation_id, summary, delivery, created_at_unix_ms
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    inbox_item_id.to_string(),
                    assistant_name,
                    main.session_id.to_string(),
                    raising_session_id.to_string(),
                    operation_scope,
                    operation_id,
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

    /// User-visible inbox entries for one main assistant session. Delivered
    /// items stay visible as history; human-read state is deliberately
    /// independent of agent delivery.
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

    /// Read the items that are allowed to enter a main turn without consuming
    /// them. The driver acknowledges the returned identities only after the
    /// turn accepts them, so cancellation and prompt/driver errors are safely
    /// retryable.
    /// `notify` items deliberately never appear here: remote notification is
    /// a later remote-track delivery and must not wake or inject agent work.
    pub async fn claim_assistant_inbox_for_delivery(
        &self,
        main_session_id: Uuid,
        include_deferred: bool,
    ) -> Result<Vec<AssistantInboxItem>> {
        self.read(move |conn| {
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
            Ok(items)
        })
        .await
    }

    /// Acknowledge a previously read delivery batch after the driver has
    /// successfully accepted it. This is idempotent for retry-safe cleanup.
    pub async fn acknowledge_assistant_inbox_delivery(
        &self,
        main_session_id: Uuid,
        inbox_item_ids: Vec<Uuid>,
    ) -> Result<()> {
        if inbox_item_ids.is_empty() {
            return Ok(());
        }
        let now = Utc::now().timestamp_millis();
        self.transaction(move |conn| {
            for inbox_item_id in inbox_item_ids {
                let matched = conn.execute(
                    "UPDATE assistant_inbox_items
                       SET delivered_at_unix_ms = COALESCE(delivered_at_unix_ms, ?1)
                     WHERE inbox_item_id = ?2 AND main_session_id = ?3",
                    params![now, inbox_item_id.to_string(), main_session_id.to_string()],
                )?;
                ensure!(
                    matched == 1,
                    "assistant inbox acknowledgement target missing"
                );
            }
            Ok(())
        })
        .await
    }

    /// Mark exactly the inbox items the human opened as read. This does not
    /// change agent-delivery state, so immediate/deferred work remains safely
    /// retryable and notify-only entries can clear the human-visible badge.
    /// The operation is idempotent and rejects a cross-session identity rather
    /// than silently acknowledging an item the caller was not authorized to
    /// view.
    pub async fn acknowledge_assistant_inbox_human_read(
        &self,
        main_session_id: Uuid,
        inbox_item_ids: Vec<Uuid>,
    ) -> Result<()> {
        if inbox_item_ids.is_empty() {
            return Ok(());
        }
        let now = Utc::now().timestamp_millis();
        self.transaction(move |conn| {
            for inbox_item_id in inbox_item_ids {
                let matched = conn.execute(
                    "UPDATE assistant_inbox_items
                       SET human_read_at_unix_ms = COALESCE(human_read_at_unix_ms, ?1)
                     WHERE inbox_item_id = ?2 AND main_session_id = ?3",
                    params![now, inbox_item_id.to_string(), main_session_id.to_string()],
                )?;
                ensure!(
                    matched == 1,
                    "assistant inbox human-read acknowledgement target missing"
                );
            }
            Ok(())
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
    let mut visited = std::collections::HashSet::new();
    for _ in 0..MAX_ASSISTANT_THREAD_ANCESTRY_DEPTH {
        ensure!(
            visited.insert(current.session_id),
            "assistant thread ancestry contains a cycle"
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_log::SessionEventKind;

    async fn assistant_with_thread(db: &Db) -> (SessionRow, SessionRow) {
        db.upsert_assistant("helper", "/tmp/helper", "{}", &"0".repeat(64))
            .await
            .unwrap();
        let main = db
            .create_assistant_session("project", "/project", "Build", "helper")
            .await
            .unwrap();
        let anchor = db
            .insert_session_event(
                main.session_id,
                SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &serde_json::json!({"text": "anchor"}),
            )
            .await
            .unwrap();
        let thread = db
            .create_thread(main.session_id, anchor.to_string())
            .await
            .unwrap();
        (main, thread)
    }

    #[tokio::test]
    async fn raise_operation_is_idempotent_and_argument_bound() {
        let db = Db::open_in_memory().unwrap();
        let (_, thread) = assistant_with_thread(&db).await;
        let first = db
            .raise_assistant_inbox_item(
                thread.session_id,
                "turn-1".into(),
                "call-1".into(),
                "result".into(),
                AssistantInboxDelivery::Immediate,
            )
            .await
            .unwrap();
        let retry = db
            .raise_assistant_inbox_item(
                thread.session_id,
                "turn-1".into(),
                "call-1".into(),
                "result".into(),
                AssistantInboxDelivery::Immediate,
            )
            .await
            .unwrap();
        assert_eq!(first.inbox_item_id, retry.inbox_item_id);
        assert!(
            db.raise_assistant_inbox_item(
                thread.session_id,
                "turn-1".into(),
                "call-1".into(),
                "different".into(),
                AssistantInboxDelivery::Immediate,
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("reused with different arguments")
        );
    }

    #[tokio::test]
    async fn recycled_provider_operation_id_is_distinct_in_a_new_daemon_scope() {
        let db = Db::open_in_memory().unwrap();
        let (_, thread) = assistant_with_thread(&db).await;
        let first = db
            .raise_assistant_inbox_item(
                thread.session_id,
                "turn-1".into(),
                "provider-call-1".into(),
                "first result".into(),
                AssistantInboxDelivery::Immediate,
            )
            .await
            .unwrap();
        let later = db
            .raise_assistant_inbox_item(
                thread.session_id,
                "turn-2".into(),
                "provider-call-1".into(),
                "later result".into(),
                AssistantInboxDelivery::Defer,
            )
            .await
            .unwrap();

        assert_ne!(first.inbox_item_id, later.inbox_item_id);
        assert_eq!(later.operation_scope, "turn-2");
    }

    #[tokio::test]
    async fn delivery_claim_respects_immediate_defer_and_notify() {
        let db = Db::open_in_memory().unwrap();
        let (main, thread) = assistant_with_thread(&db).await;
        for (operation, delivery) in [
            ("immediate", AssistantInboxDelivery::Immediate),
            ("defer", AssistantInboxDelivery::Defer),
            ("notify", AssistantInboxDelivery::Notify),
        ] {
            db.raise_assistant_inbox_item(
                thread.session_id,
                "turn-1".into(),
                operation.into(),
                operation.into(),
                delivery,
            )
            .await
            .unwrap();
        }
        let immediate = db
            .claim_assistant_inbox_for_delivery(main.session_id, false)
            .await
            .unwrap();
        assert_eq!(immediate.len(), 1);
        assert_eq!(immediate[0].delivery, AssistantInboxDelivery::Immediate);
        let retried = db
            .claim_assistant_inbox_for_delivery(main.session_id, false)
            .await
            .unwrap();
        assert_eq!(retried, immediate, "an unacknowledged claim must retry");
        db.acknowledge_assistant_inbox_delivery(
            main.session_id,
            immediate.iter().map(|item| item.inbox_item_id).collect(),
        )
        .await
        .unwrap();
        let deferred = db
            .claim_assistant_inbox_for_delivery(main.session_id, true)
            .await
            .unwrap();
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].delivery, AssistantInboxDelivery::Defer);
        db.acknowledge_assistant_inbox_delivery(
            main.session_id,
            deferred.iter().map(|item| item.inbox_item_id).collect(),
        )
        .await
        .unwrap();
        let visible = db
            .assistant_inbox_for_main(main.session_id, true, 10)
            .await
            .unwrap();
        assert_eq!(visible.len(), 3);
        assert!(visible.iter().any(|item| {
            item.delivery == AssistantInboxDelivery::Notify
                && item.delivered_at_unix_ms.is_none()
                && item.human_read_at_unix_ms.is_none()
                && item.raising_session_id == thread.session_id
        }));
    }

    #[tokio::test]
    async fn human_read_acknowledgement_is_independent_of_agent_delivery() {
        let db = Db::open_in_memory().unwrap();
        let (main, thread) = assistant_with_thread(&db).await;
        let immediate = db
            .raise_assistant_inbox_item(
                thread.session_id,
                "turn-1".into(),
                "immediate".into(),
                "agent delivery must not clear the human badge".into(),
                AssistantInboxDelivery::Immediate,
            )
            .await
            .unwrap();
        let notify = db
            .raise_assistant_inbox_item(
                thread.session_id,
                "turn-1".into(),
                "notify".into(),
                "notify must clear when the human opens the inbox".into(),
                AssistantInboxDelivery::Notify,
            )
            .await
            .unwrap();

        db.acknowledge_assistant_inbox_delivery(main.session_id, vec![immediate.inbox_item_id])
            .await
            .unwrap();
        let after_delivery = db
            .assistant_inbox_for_main(main.session_id, true, 10)
            .await
            .unwrap();
        assert!(
            after_delivery
                .iter()
                .all(|item| item.human_read_at_unix_ms.is_none())
        );
        let unread_after_delivery = db
            .list_session_summaries(Some("project"), None, 10)
            .await
            .unwrap()
            .into_iter()
            .find(|summary| summary.session_id == main.session_id)
            .unwrap()
            .assistant_inbox_unread;
        assert_eq!(unread_after_delivery, 2);

        db.acknowledge_assistant_inbox_human_read(
            main.session_id,
            vec![immediate.inbox_item_id, notify.inbox_item_id],
        )
        .await
        .unwrap();
        let after_human_read = db
            .assistant_inbox_for_main(main.session_id, true, 10)
            .await
            .unwrap();
        assert!(
            after_human_read
                .iter()
                .all(|item| item.human_read_at_unix_ms.is_some())
        );
        assert!(after_human_read.iter().any(|item| {
            item.inbox_item_id == notify.inbox_item_id && item.delivered_at_unix_ms.is_none()
        }));
        let unread_after_human_read = db
            .list_session_summaries(Some("project"), None, 10)
            .await
            .unwrap()
            .into_iter()
            .find(|summary| summary.session_id == main.session_id)
            .unwrap()
            .assistant_inbox_unread;
        assert_eq!(unread_after_human_read, 0);
    }

    #[tokio::test]
    async fn notify_does_not_exhaust_agent_work_pending_guard() {
        let db = Db::open_in_memory().unwrap();
        let (_, thread) = assistant_with_thread(&db).await;
        for index in 0..MAX_PENDING_INBOX_ITEMS_PER_ASSISTANT + 1 {
            db.raise_assistant_inbox_item(
                thread.session_id,
                "turn-notify".into(),
                format!("notify-{index}"),
                format!("notify {index}"),
                AssistantInboxDelivery::Notify,
            )
            .await
            .unwrap();
        }
        db.raise_assistant_inbox_item(
            thread.session_id,
            "turn-after-notify".into(),
            "immediate-after-notify".into(),
            "still accepted".into(),
            AssistantInboxDelivery::Immediate,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn raise_spawn_raise_amplification_is_bounded_per_assistant() {
        let db = Db::open_in_memory().unwrap();
        let (_, mut thread) = assistant_with_thread(&db).await;
        for index in 0..MAX_RAISES_PER_ASSISTANT_PER_HOUR {
            db.raise_assistant_inbox_item(
                thread.session_id,
                format!("turn-{index}"),
                format!("call-{index}"),
                format!("raise {index}"),
                AssistantInboxDelivery::Notify,
            )
            .await
            .unwrap();
            let anchor = db
                .insert_session_event(
                    thread.session_id,
                    SessionEventKind::AssistantMessage,
                    Some("Build"),
                    None,
                    &serde_json::json!({"text": "spawn"}),
                )
                .await
                .unwrap();
            thread = db
                .create_thread(thread.session_id, anchor.to_string())
                .await
                .unwrap();
        }
        assert!(
            db.raise_assistant_inbox_item(
                thread.session_id,
                "turn-over-bound".into(),
                "over-bound".into(),
                "must fail".into(),
                AssistantInboxDelivery::Notify,
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("raise guard reached")
        );
    }
}
