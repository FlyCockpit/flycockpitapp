//! `seed_tools` reads/writes — `/compact` fresh-thread handoff seeds.
//!
//! When `/compact` creates a new session, the derived seed-tool plan
//! (read-only / idempotent calls reconstructing the working set) is
//! persisted here keyed by the *new* session id. That session's worker
//! drains and re-executes them on its first turn — never replaying the
//! old output (`plan.md` T6.e).

use anyhow::{Context, Result};
use rusqlite::params;
use serde_json::Value;
use uuid::Uuid;

use crate::db::Db;

/// One seed-tool to re-execute at the start of a compacted session.
///
/// Carries the tool name + the canonical args from the prior call; the new
/// session dispatches it fresh and never replays the old output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeedTool {
    pub tool: String,
    pub args: Value,
}

impl Db {
    /// Persist the seed-tool plan for a (new) session, in order. Replaces
    /// any existing rows for that session id.
    pub fn set_seed_tools(&self, session_id: Uuid, seeds: &[SeedTool]) -> Result<()> {
        self.set_seed_tools_inner(session_id, seeds, None)
    }

    fn set_seed_tools_inner(
        &self,
        session_id: Uuid,
        seeds: &[SeedTool],
        #[cfg_attr(not(test), allow(unused_variables))] fail_after_inserts: Option<usize>,
    ) -> Result<()> {
        let seeds = seeds.to_vec();
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin set_seed_tools tx")?;
            tx.execute(
                "DELETE FROM seed_tools WHERE session_id = ?1",
                params![session_id.to_string()],
            )
            .context("clearing prior seed_tools")?;
            for (seq, seed) in seeds.iter().enumerate() {
                let args = serde_json::to_string(&seed.args).context("serializing seed args")?;
                tx.execute(
                    "INSERT INTO seed_tools (session_id, seq, tool, args_json)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![session_id.to_string(), seq as i64, seed.tool, args],
                )
                .context("inserting seed_tool")?;
                #[cfg(test)]
                if fail_after_inserts == Some(seq + 1) {
                    anyhow::bail!("injected set_seed_tools failure");
                }
            }
            tx.commit().context("commit set_seed_tools tx")?;
            Ok(())
        })
    }

    /// Drain the seed-tool plan for a session: return it in order, then
    /// delete the rows so it never re-fires. Empty vec when none.
    pub fn take_seed_tools(&self, session_id: Uuid) -> Result<Vec<SeedTool>> {
        self.take_seed_tools_inner(session_id, false)
    }

    fn take_seed_tools_inner(
        &self,
        session_id: Uuid,
        #[cfg_attr(not(test), allow(unused_variables))] fail_after_delete: bool,
    ) -> Result<Vec<SeedTool>> {
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin take_seed_tools tx")?;
            let mut stmt = tx
                .prepare(
                    "SELECT tool, args_json FROM seed_tools
                      WHERE session_id = ?1 ORDER BY seq ASC",
                )
                .context("preparing take_seed_tools")?;
            let rows = stmt
                .query_map(params![session_id.to_string()], |r| {
                    let tool: String = r.get(0)?;
                    let args_json: String = r.get(1)?;
                    Ok((tool, args_json))
                })
                .context("querying seed_tools")?;
            let mut out = Vec::new();
            for r in rows {
                let (tool, args_json) = r.context("decoding seed_tool row")?;
                let args = serde_json::from_str(&args_json).unwrap_or_else(|e| {
                    tracing::warn!(
                        error = %e,
                        session_id = %session_id,
                        tool = %tool,
                        "malformed seed_tool args_json; using null args for compatibility"
                    );
                    serde_json::Value::Null
                });
                out.push(SeedTool { tool, args });
            }
            drop(stmt);
            tx.execute(
                "DELETE FROM seed_tools WHERE session_id = ?1",
                params![session_id.to_string()],
            )
            .context("clearing drained seed_tools")?;
            #[cfg(test)]
            if fail_after_delete {
                anyhow::bail!("injected take_seed_tools failure");
            }
            tx.commit().context("commit take_seed_tools tx")?;
            Ok(out)
        })
    }

    #[cfg(test)]
    fn set_seed_tools_fail_after_inserts(
        &self,
        session_id: Uuid,
        seeds: &[SeedTool],
        fail_after_inserts: usize,
    ) -> Result<()> {
        self.set_seed_tools_inner(session_id, seeds, Some(fail_after_inserts))
    }

    #[cfg(test)]
    fn take_seed_tools_fail_after_delete(&self, session_id: Uuid) -> Result<Vec<SeedTool>> {
        self.take_seed_tools_inner(session_id, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn seed(tool: &str, path: &str) -> SeedTool {
        SeedTool {
            tool: tool.into(),
            args: json!({ "path": path }),
        }
    }

    fn stored_seed_tools(db: &Db, session_id: Uuid) -> Vec<SeedTool> {
        db.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT tool, args_json FROM seed_tools
                     WHERE session_id = ?1 ORDER BY seq ASC",
                )
                .unwrap();
            let rows = stmt
                .query_map(params![session_id.to_string()], |r| {
                    let tool: String = r.get(0)?;
                    let args_json: String = r.get(1)?;
                    Ok(SeedTool {
                        tool,
                        args: serde_json::from_str(&args_json).unwrap(),
                    })
                })
                .unwrap();
            Ok(rows.map(|r| r.unwrap()).collect())
        })
        .unwrap()
    }

    #[test]
    fn set_take_round_trip_and_clears() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let seeds = vec![seed("read", "/a.rs"), seed("outline", "/b.rs")];
        db.set_seed_tools(s.session_id, &seeds).unwrap();

        let taken = db.take_seed_tools(s.session_id).unwrap();
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].tool, "read");
        assert_eq!(taken[1].tool, "outline");

        // Draining deletes — a second take is empty.
        let again = db.take_seed_tools(s.session_id).unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn failed_replacement_rolls_back_prior_plan() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let original = vec![seed("read", "/a.rs"), seed("outline", "/b.rs")];
        db.set_seed_tools(s.session_id, &original).unwrap();

        let replacement = vec![
            seed("read", "/new-a.rs"),
            seed("outline", "/new-b.rs"),
            seed("grep", "/new-c.rs"),
        ];
        let err = db
            .set_seed_tools_fail_after_inserts(s.session_id, &replacement, 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("injected set_seed_tools failure"), "{err}");
        assert_eq!(stored_seed_tools(&db, s.session_id), original);
    }

    #[test]
    fn empty_seed_list_clears_prior_rows_atomically() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        db.set_seed_tools(s.session_id, &[seed("read", "/a.rs")])
            .unwrap();

        db.set_seed_tools(s.session_id, &[]).unwrap();
        assert!(stored_seed_tools(&db, s.session_id).is_empty());
    }

    #[test]
    fn failed_drain_rolls_back_delete_for_retry() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let seeds = vec![seed("read", "/a.rs"), seed("outline", "/b.rs")];
        db.set_seed_tools(s.session_id, &seeds).unwrap();

        let err = db
            .take_seed_tools_fail_after_delete(s.session_id)
            .unwrap_err()
            .to_string();
        assert!(err.contains("injected take_seed_tools failure"), "{err}");
        assert_eq!(stored_seed_tools(&db, s.session_id), seeds);

        let retry = db.take_seed_tools(s.session_id).unwrap();
        assert_eq!(retry.len(), 2);
        assert_eq!(retry[0].tool, "read");
        assert_eq!(retry[1].tool, "outline");
        assert!(db.take_seed_tools(s.session_id).unwrap().is_empty());
    }

    #[test]
    fn malformed_args_json_still_drains_as_null_compatibly() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        db.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO seed_tools (session_id, seq, tool, args_json)
                 VALUES (?1, 0, 'read', '{malformed')",
                params![s.session_id.to_string()],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();

        let taken = db.take_seed_tools(s.session_id).unwrap();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].tool, "read");
        assert_eq!(taken[0].args, serde_json::Value::Null);
        assert!(db.take_seed_tools(s.session_id).unwrap().is_empty());
    }
}
