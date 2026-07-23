//! Pinned messages — a lightweight "come back to this later" reference
//! the TUI lets the user place on any conversation message (migration
//! `0025_pins.sql`).
//!
//! A pin is a REFERENCE by stable id — `(session_id, seq)` where `seq` is
//! the [`session_events`](crate::db::session_log) PRIMARY KEY of a
//! `user_message` / `assistant_message` row — never a snapshot of the
//! text. Because `/prune` and `/compact` never mutate `session_events`
//! (they touch only the in-memory wire payload), the original full message
//! text in `session_events.data_json` stays durable, so
//! [`Db::list_pins_with_text`] always resolves a pin's ORIGINAL text even
//! after pruning/compaction.
//!
//! Pins are TUI/DB state only; nothing here ever enters the outbound model
//! prompt (token economy, priority #2).
//!
//! Pinning is idempotent: `(session_id, seq)` is a UNIQUE primary key, so
//! [`pin_message`] uses `INSERT OR IGNORE` and a re-pin is a no-op.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;
use crate::db::session_log::now_ms;

/// A pinned message resolved against the durable transcript: the pin's
/// `seq`, whether the referenced message is a user or assistant message,
/// and its ORIGINAL full text (pulled from `session_events.data_json`, so
/// it survives `/prune` + `/compact`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedMessage {
    /// The referenced `session_events.seq`.
    pub seq: i64,
    /// `true` for an assistant message, `false` for a user message.
    pub is_assistant: bool,
    /// The original message text from the durable transcript.
    pub text: String,
}

impl Db {
    /// Pin the message at `(session_id, seq)`. Idempotent: pinning an
    /// already-pinned message is a no-op (no error). Returns `true` when a
    /// new pin was created, `false` when it was already pinned.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn pin_message(&self, session_id: Uuid, seq: i64) -> Result<bool> {
        let pinned_ms = now_ms();
        self.write_blocking(move |conn| {
            let n = conn
                .execute(
                    "INSERT OR IGNORE INTO pins (session_id, seq, pinned_ms)
                     VALUES (?1, ?2, ?3)",
                    params![session_id.to_string(), seq, pinned_ms],
                )
                .context("inserting pin")?;
            Ok(n == 1)
        })
    }

    /// Unpin the message at `(session_id, seq)`. Returns `true` when a pin
    /// was removed, `false` when there was none. The unpin path for both
    /// `d` (delete) and checking a checklist item in `/pins`.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn unpin_message(&self, session_id: Uuid, seq: i64) -> Result<bool> {
        self.write_blocking(move |conn| {
            let n = conn
                .execute(
                    "DELETE FROM pins WHERE session_id = ?1 AND seq = ?2",
                    params![session_id.to_string(), seq],
                )
                .context("deleting pin")?;
            Ok(n == 1)
        })
    }

    /// Whether the message at `(session_id, seq)` is currently pinned.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn is_pinned(&self, session_id: Uuid, seq: i64) -> Result<bool> {
        self.read_blocking(|conn| {
            let found: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM pins WHERE session_id = ?1 AND seq = ?2",
                    params![session_id.to_string(), seq],
                    |row| row.get(0),
                )
                .optional()
                .context("querying pin")?;
            Ok(found.is_some())
        })
    }

    /// Toggle the pin state of `(session_id, seq)`. Returns the NEW state
    /// (`true` = now pinned). The natural affordance for the mouse control
    /// and the message-pick mode.
    pub fn toggle_pin(&self, session_id: Uuid, seq: i64) -> Result<bool> {
        if self.is_pinned(session_id, seq)? {
            self.unpin_message(session_id, seq)?;
            Ok(false)
        } else {
            self.pin_message(session_id, seq)?;
            Ok(true)
        }
    }

    /// Count of pinned messages for one session. `0` when none — the
    /// below-input indicator and the `/sessions` per-session chrome read
    /// this.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn count_pins(&self, session_id: Uuid) -> Result<i64> {
        self.read_blocking(|conn| {
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM pins WHERE session_id = ?1",
                    [session_id.to_string()],
                    |row| row.get(0),
                )
                .context("counting pins")?;
            Ok(n)
        })
    }

    /// The `seq`s pinned in one session, in pin order (oldest pin first).
    /// Bare seqs, no text — for callers that only need the set (e.g. the
    /// mouse control's pinned/unpinned decision per rendered message).
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_pin_seqs(&self, session_id: Uuid) -> Result<Vec<i64>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT seq FROM pins WHERE session_id = ?1 ORDER BY pinned_ms ASC, rowid ASC",
                )
                .context("preparing list_pin_seqs")?;
            let rows = stmt
                .query_map([session_id.to_string()], |row| row.get::<_, i64>(0))
                .context("querying pin seqs")?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.context("decoding pin seq")?);
            }
            Ok(out)
        })
    }

    /// Pinned messages for one session, in pin order, each resolved
    /// against the DURABLE transcript: the original text is read from
    /// `session_events.data_json` via a join, so it renders correctly even
    /// after `/prune` or `/compact` (which never touch `session_events`).
    /// The `/pins` review checklist consumes this.
    ///
    /// A pin whose referenced event row is missing is skipped (the FK
    /// CASCADE makes this unreachable in practice, but the read stays
    /// defensive).
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_pins_with_text(&self, session_id: Uuid) -> Result<Vec<PinnedMessage>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT e.seq, e.type, e.data_json
                       FROM pins p
                       JOIN session_events e ON e.seq = p.seq
                      WHERE p.session_id = ?1
                      ORDER BY p.pinned_ms ASC, p.rowid ASC",
                )
                .context("preparing list_pins_with_text")?;
            let rows = stmt
                .query_map([session_id.to_string()], |row| {
                    let seq: i64 = row.get(0)?;
                    let kind: String = row.get(1)?;
                    let data_json: String = row.get(2)?;
                    Ok((seq, kind, data_json))
                })
                .context("querying pins with text")?;
            let mut out = Vec::new();
            for r in rows {
                let (seq, kind, data_json) = r.context("decoding pin row")?;
                let data: serde_json::Value =
                    serde_json::from_str(&data_json).context("deserializing event data_json")?;
                let text = data
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                out.push(PinnedMessage {
                    seq,
                    is_assistant: kind == "assistant_message",
                    text,
                });
            }
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_log::SessionEventKind;
    use serde_json::json;

    /// Record a user/assistant message event and return its seq — the
    /// stable id a pin references.
    fn record_msg(db: &Db, sid: Uuid, kind: SessionEventKind, text: &str) -> i64 {
        db.insert_session_event(sid, kind, Some("Auto"), None, &json!({ "text": text }))
            .unwrap()
    }

    #[tokio::test]
    async fn pin_unpin_list_and_count() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Auto").await.unwrap();
        let sid = s.session_id;
        let u = record_msg(&db, sid, SessionEventKind::UserMessage, "hello");
        let a = record_msg(&db, sid, SessionEventKind::AssistantMessage, "hi there");

        assert_eq!(db.count_pins(sid).unwrap(), 0);
        assert!(!db.is_pinned(sid, u).unwrap());

        assert!(db.pin_message(sid, u).unwrap(), "first pin created");
        assert!(db.pin_message(sid, a).unwrap());
        assert_eq!(db.count_pins(sid).unwrap(), 2);
        assert!(db.is_pinned(sid, u).unwrap());
        assert_eq!(db.list_pin_seqs(sid).unwrap(), vec![u, a]);

        assert!(db.unpin_message(sid, u).unwrap(), "pin removed");
        assert_eq!(db.count_pins(sid).unwrap(), 1);
        assert!(!db.is_pinned(sid, u).unwrap());
        assert_eq!(db.list_pin_seqs(sid).unwrap(), vec![a]);
    }

    #[tokio::test]
    async fn pinning_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Auto").await.unwrap();
        let sid = s.session_id;
        let u = record_msg(&db, sid, SessionEventKind::UserMessage, "hello");

        assert!(db.pin_message(sid, u).unwrap(), "first pin returns true");
        assert!(
            !db.pin_message(sid, u).unwrap(),
            "second pin is a no-op (false)"
        );
        assert_eq!(db.count_pins(sid).unwrap(), 1, "still exactly one pin");
    }

    #[tokio::test]
    async fn toggle_flips_state() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Auto").await.unwrap();
        let sid = s.session_id;
        let u = record_msg(&db, sid, SessionEventKind::UserMessage, "hello");

        assert!(db.toggle_pin(sid, u).unwrap(), "toggle on → now pinned");
        assert!(db.is_pinned(sid, u).unwrap());
        assert!(!db.toggle_pin(sid, u).unwrap(), "toggle off → now unpinned");
        assert!(!db.is_pinned(sid, u).unwrap());
    }

    #[tokio::test]
    async fn list_pins_resolves_role_and_text_in_order() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Auto").await.unwrap();
        let sid = s.session_id;
        let u = record_msg(&db, sid, SessionEventKind::UserMessage, "the question");
        let a = record_msg(&db, sid, SessionEventKind::AssistantMessage, "the answer");

        db.pin_message(sid, a).unwrap();
        db.pin_message(sid, u).unwrap();

        let pins = db.list_pins_with_text(sid).unwrap();
        // Pin order (oldest pin first): assistant was pinned first.
        assert_eq!(pins.len(), 2);
        assert_eq!(pins[0].seq, a);
        assert!(pins[0].is_assistant);
        assert_eq!(pins[0].text, "the answer");
        assert_eq!(pins[1].seq, u);
        assert!(!pins[1].is_assistant);
        assert_eq!(pins[1].text, "the question");
    }

    /// Durable-text-recovery property: a pin's ORIGINAL text is retrievable
    /// from `session_events` even after a simulated `/prune` or `/compact`
    /// — which mutate only the in-memory wire payload, never the
    /// `session_events` rows. We simulate that by leaving `session_events`
    /// untouched (the real prune/compact code path) and confirming the pin
    /// still resolves the full original text.
    #[tokio::test]
    async fn pinned_text_survives_prune_and_compact() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Auto").await.unwrap();
        let sid = s.session_id;
        let original = "FULL ORIGINAL MESSAGE BODY with lots of content here";
        let a = record_msg(&db, sid, SessionEventKind::AssistantMessage, original);
        db.pin_message(sid, a).unwrap();

        // Simulate `/prune` + `/compact`: both append timeline markers and
        // touch only the in-memory wire payload; they NEVER UPDATE/DELETE
        // session_events rows. Record the boundary events the real paths
        // record, then confirm the pinned row is unchanged.
        db.insert_session_event(
            sid,
            SessionEventKind::ContextPruned,
            Some("Auto"),
            None,
            &json!({ "bodies": 1 }),
        )
        .unwrap();
        db.insert_session_event(
            sid,
            SessionEventKind::SessionCompacted,
            Some("Auto"),
            None,
            &json!({ "successor": "abc123" }),
        )
        .unwrap();

        // The pin still resolves the ORIGINAL full text from the durable
        // transcript.
        let listed = db.list_pins_with_text(sid).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].seq, a);
        assert!(listed[0].is_assistant);
        assert_eq!(listed[0].text, original);
    }

    #[tokio::test]
    async fn pins_are_scoped_per_session() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_session("p", "/x", "Auto").await.unwrap();
        let b = db.create_session("p", "/y", "Auto").await.unwrap();
        let ua = record_msg(&db, a.session_id, SessionEventKind::UserMessage, "in a");
        let ub = record_msg(&db, b.session_id, SessionEventKind::UserMessage, "in b");
        db.pin_message(a.session_id, ua).unwrap();
        db.pin_message(b.session_id, ub).unwrap();

        assert_eq!(db.count_pins(a.session_id).unwrap(), 1);
        assert_eq!(db.count_pins(b.session_id).unwrap(), 1);
        assert_eq!(db.list_pin_seqs(a.session_id).unwrap(), vec![ua]);
        assert_eq!(db.list_pin_seqs(b.session_id).unwrap(), vec![ub]);
    }

    #[tokio::test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    async fn pin_cascades_when_session_deleted() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Auto").await.unwrap();
        let sid = s.session_id;
        let u = record_msg(&db, sid, SessionEventKind::UserMessage, "hello");
        db.pin_message(sid, u).unwrap();
        assert_eq!(db.count_pins(sid).unwrap(), 1);

        db.write_blocking(move |conn| {
            conn.execute(
                "DELETE FROM sessions WHERE session_id = ?1",
                [sid.to_string()],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(db.count_pins(sid).unwrap(), 0, "pin cascaded with session");
    }
}
