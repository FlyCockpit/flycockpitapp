//! `subagent_handles` reads/writes — re-queryable subagents (GOALS §3c).
//!
//! When a read-only noninteractive subagent reports back in `normal` mode,
//! its full transcript is persisted here keyed by an opaque handle surfaced
//! to the caller. A follow-up `task(resume_handle=…)` rehydrates the
//! transcript and re-runs the subagent with full knowledge of what it
//! already did. Persist-and-rehydrate (migration `0021`) so a re-query
//! survives a daemon restart; the `docs` pipeline never reaches this path,
//! so a handle never points at a docs run.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// A rehydrated subagent handle: which agent it was, and the JSON-encoded
/// transcript (`Vec<rig::message::Message>`) to rebuild its context from.
pub struct SubagentHandle {
    pub agent: String,
    pub cwd: Option<String>,
    pub transcript_json: String,
}

impl Db {
    /// Persist (or replace) a subagent's transcript under `handle`, scoped
    /// to `session_id`. `transcript_json` is the JSON-serialized message
    /// history. Idempotent on the handle (upsert) so re-reporting under the
    /// same handle refreshes the stored transcript.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn save_subagent_handle(
        &self,
        handle: &str,
        session_id: Uuid,
        agent: &str,
        cwd: Option<&str>,
        transcript_json: &str,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let handle = handle.to_owned();
        let agent = agent.to_owned();
        let cwd = cwd.map(str::to_owned);
        let transcript_json = transcript_json.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO subagent_handles
                     (handle, session_id, agent, cwd, transcript_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                 ON CONFLICT (handle) DO UPDATE SET
                     cwd = excluded.cwd,
                     transcript_json = excluded.transcript_json,
                     updated_at = excluded.updated_at",
                params![
                    handle,
                    session_id.to_string(),
                    agent,
                    cwd,
                    transcript_json,
                    now
                ],
            )
            .context("inserting subagent_handle")?;
            Ok(())
        })
    }

    /// Load a subagent handle scoped to `session_id`. Returns `None` when
    /// the handle is unknown / evicted / belongs to a different session —
    /// the caller turns that into a clear "spawn a fresh subagent" error
    /// (never a silent cold start).
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn load_subagent_handle(
        &self,
        handle: &str,
        session_id: Uuid,
    ) -> Result<Option<SubagentHandle>> {
        self.read_blocking(|conn| {
            let row = conn
                .query_row(
                    "SELECT agent, cwd, transcript_json FROM subagent_handles
                      WHERE handle = ?1 AND session_id = ?2",
                    params![handle, session_id.to_string()],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, Option<String>>(1)?,
                            r.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
                .context("querying subagent_handle")?;
            Ok(row.map(|(agent, cwd, transcript_json)| SubagentHandle {
                agent,
                cwd,
                transcript_json,
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn save_load_round_trip_and_scopes_to_session() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "explore").await.unwrap();
        let other = db.create_session("p", "/x", "explore").await.unwrap();
        db.save_subagent_handle("h1", s.session_id, "explore", Some("/repo/a"), "[1,2,3]")
            .unwrap();

        let got = db
            .load_subagent_handle("h1", s.session_id)
            .unwrap()
            .unwrap();
        assert_eq!(got.agent, "explore");
        assert_eq!(got.cwd.as_deref(), Some("/repo/a"));
        assert_eq!(got.transcript_json, "[1,2,3]");

        // Unknown handle → None (the stale-handle path).
        assert!(
            db.load_subagent_handle("nope", s.session_id)
                .unwrap()
                .is_none()
        );
        // Right handle, wrong session → None (scoped).
        assert!(
            db.load_subagent_handle("h1", other.session_id)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn save_upserts_transcript() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "explore").await.unwrap();
        db.save_subagent_handle("h1", s.session_id, "explore", Some("/repo/a"), "[1]")
            .unwrap();
        db.save_subagent_handle("h1", s.session_id, "explore", Some("/repo/b"), "[1,2]")
            .unwrap();
        let got = db
            .load_subagent_handle("h1", s.session_id)
            .unwrap()
            .unwrap();
        assert_eq!(got.cwd.as_deref(), Some("/repo/b"));
        assert_eq!(got.transcript_json, "[1,2]");
    }
}
