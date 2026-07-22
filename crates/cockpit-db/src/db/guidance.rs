//! Guidance-baseline storage for live instructions-file diff injection
//! (prompt `instructions-file-live-diff.md`, migration 0016).
//!
//! Two pieces:
//! - the per-session baseline hash on the `sessions` row
//!   (`guidance_baseline_hash`): the content hash of the guidance body
//!   baked into this session's frozen system block, NULL when no guidance
//!   file resolved at session start;
//! - the content-addressed `guidance_contents` table (`hash → contents`),
//!   which stores the baseline plus every subsequent injected version so a
//!   diff can always be computed from the prior stored body.
//!
//! All writes are idempotent: the content store dedups on hash
//! (`INSERT OR IGNORE`), and advancing the baseline is a single UPDATE.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// The per-session guidance baseline: the `(path, hash)` of the guidance
/// body baked into this session's frozen system block. Absent when no
/// guidance file resolved at session start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuidanceBaseline {
    /// Absolute path of the resolved guidance file the baseline came from.
    pub path: String,
    /// Content hash of the baseline body.
    pub hash: String,
}

impl Db {
    /// Read the session's stored guidance baseline. `None` when the
    /// session row doesn't exist or the baseline columns are NULL (no
    /// guidance file resolved at session start — feature inert for that
    /// session).
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn guidance_baseline(&self, session_id: Uuid) -> Result<Option<GuidanceBaseline>> {
        self.read_blocking(|conn| {
            let row: Option<(Option<String>, Option<String>)> = conn
                .query_row(
                    "SELECT guidance_baseline_path, guidance_baseline_hash
                     FROM sessions WHERE session_id = ?1",
                    [session_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .context("reading guidance baseline")?;
            Ok(match row {
                Some((Some(path), Some(hash))) => Some(GuidanceBaseline { path, hash }),
                _ => None,
            })
        })
    }

    /// Set (or clear, with `None`) the session's guidance baseline path +
    /// hash together. Used both for the start-of-session snapshot and to
    /// advance the baseline after a change is injected. The two columns are
    /// always written as a unit so they never disagree.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn set_guidance_baseline(
        &self,
        session_id: Uuid,
        baseline: Option<&GuidanceBaseline>,
    ) -> Result<()> {
        let (path, hash) = match baseline {
            Some(b) => (Some(b.path.clone()), Some(b.hash.clone())),
            None => (None, None),
        };
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions
                 SET guidance_baseline_path = ?1, guidance_baseline_hash = ?2
                 WHERE session_id = ?3",
                params![path, hash, session_id.to_string()],
            )
            .context("setting guidance baseline")?;
            Ok(())
        })
    }

    /// Idempotently store a guidance body keyed by its content hash.
    /// Content-addressed: a second insert of the same hash is a no-op
    /// (`INSERT OR IGNORE`), so repeated snapshots of unchanged content
    /// never churn the row.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn put_guidance_contents(&self, hash: &str, contents: &str) -> Result<()> {
        let now = Utc::now().timestamp();
        let hash = hash.to_owned();
        let contents = contents.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO guidance_contents (hash, contents, created_at)
                 VALUES (?1, ?2, ?3)",
                params![hash, contents, now],
            )
            .context("inserting guidance_contents")?;
            Ok(())
        })
    }

    /// Fetch the stored guidance body for a hash, or `None` if absent.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn guidance_contents(&self, hash: &str) -> Result<Option<String>> {
        self.read_blocking(|conn| {
            let contents: Option<String> = conn
                .query_row(
                    "SELECT contents FROM guidance_contents WHERE hash = ?1",
                    [hash],
                    |row| row.get(0),
                )
                .optional()
                .context("reading guidance_contents")?;
            Ok(contents)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline(path: &str, hash: &str) -> GuidanceBaseline {
        GuidanceBaseline {
            path: path.to_string(),
            hash: hash.to_string(),
        }
    }

    #[test]
    fn baseline_round_trips_and_defaults_null() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        // Fresh session: no baseline yet.
        assert_eq!(db.guidance_baseline(s.session_id).unwrap(), None);
        db.set_guidance_baseline(s.session_id, Some(&baseline("/x/AGENTS.md", "deadbeef")))
            .unwrap();
        assert_eq!(
            db.guidance_baseline(s.session_id).unwrap(),
            Some(baseline("/x/AGENTS.md", "deadbeef"))
        );
        // Advance (same path, new hash).
        db.set_guidance_baseline(s.session_id, Some(&baseline("/x/AGENTS.md", "cafef00d")))
            .unwrap();
        assert_eq!(
            db.guidance_baseline(s.session_id).unwrap(),
            Some(baseline("/x/AGENTS.md", "cafef00d"))
        );
        // Clear.
        db.set_guidance_baseline(s.session_id, None).unwrap();
        assert_eq!(db.guidance_baseline(s.session_id).unwrap(), None);
    }

    #[test]
    fn guidance_contents_insert_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        db.put_guidance_contents("h1", "first body").unwrap();
        // Re-inserting the same hash with different contents must NOT
        // overwrite (content-addressed: the hash IS the identity).
        db.put_guidance_contents("h1", "tampered body").unwrap();
        assert_eq!(
            db.guidance_contents("h1").unwrap().as_deref(),
            Some("first body")
        );
        // A new hash stores independently.
        db.put_guidance_contents("h2", "second body").unwrap();
        assert_eq!(
            db.guidance_contents("h2").unwrap().as_deref(),
            Some("second body")
        );
        // Absent hash returns None.
        assert_eq!(db.guidance_contents("missing").unwrap(), None);
    }

    #[test]
    fn baseline_none_for_missing_session() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.guidance_baseline(Uuid::new_v4()).unwrap(), None);
    }
}
