//! `skill_pairs` reads/writes — persisted ownership for user-invoked skills.
//!
//! A `/skill` slash command is folded into root history as a synthetic
//! assistant `skill` tool call plus matching tool_result. The driver strips
//! non-steering pairs owned by an outgoing primary at swap time; this table is
//! the durable mirror so resume and compaction retain that ownership.

use anyhow::{Context, Result};
use rusqlite::params;
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillPairRow {
    pub call_id: String,
    pub owner: String,
    pub intentional_steer: bool,
}

impl Db {
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn save_skill_pair(
        &self,
        session_id: Uuid,
        call_id: &str,
        owner: &str,
        intentional_steer: bool,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let call_id = call_id.to_owned();
        let owner = owner.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO skill_pairs
                    (session_id, call_id, owner, intentional_steer, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT (session_id, call_id) DO UPDATE SET
                    owner = excluded.owner,
                    intentional_steer = excluded.intentional_steer,
                    updated_at = excluded.updated_at",
                params![
                    session_id.to_string(),
                    call_id,
                    owner,
                    if intentional_steer { 1_i64 } else { 0_i64 },
                    now
                ],
            )
            .context("upserting skill_pair")?;
            Ok(())
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_skill_pairs(&self, session_id: Uuid) -> Result<Vec<SkillPairRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT call_id, owner, intentional_steer
                     FROM skill_pairs
                     WHERE session_id = ?1
                     ORDER BY created_at, call_id",
                )
                .context("preparing skill_pair query")?;
            let rows = stmt
                .query_map(params![session_id.to_string()], |row| {
                    Ok(SkillPairRow {
                        call_id: row.get(0)?,
                        owner: row.get(1)?,
                        intentional_steer: row.get::<_, i64>(2)? != 0,
                    })
                })
                .context("querying skill_pairs")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("reading skill_pair row")?);
            }
            Ok(out)
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn delete_skill_pairs<I, S>(&self, session_id: Uuid, call_ids: I) -> Result<usize>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let ids: Vec<String> = call_ids
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin skill_pair delete")?;
            let mut deleted = 0;
            {
                let mut stmt = tx
                    .prepare("DELETE FROM skill_pairs WHERE session_id = ?1 AND call_id = ?2")
                    .context("preparing skill_pair delete")?;
                for id in &ids {
                    deleted += stmt
                        .execute(params![session_id.to_string(), id])
                        .context("deleting skill_pair")?;
                }
            }
            tx.commit().context("commit skill_pair delete")?;
            Ok(deleted)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_list_delete_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        db.save_skill_pair(s.session_id, "skillslash-1", "Build", false)
            .unwrap();
        db.save_skill_pair(s.session_id, "skillslash-2", "Plan", true)
            .unwrap();

        assert_eq!(
            db.list_skill_pairs(s.session_id).unwrap(),
            vec![
                SkillPairRow {
                    call_id: "skillslash-1".into(),
                    owner: "Build".into(),
                    intentional_steer: false,
                },
                SkillPairRow {
                    call_id: "skillslash-2".into(),
                    owner: "Plan".into(),
                    intentional_steer: true,
                },
            ]
        );

        assert_eq!(
            db.delete_skill_pairs(s.session_id, ["skillslash-1"])
                .unwrap(),
            1
        );
        let remaining = db.list_skill_pairs(s.session_id).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].call_id, "skillslash-2");
    }
}
