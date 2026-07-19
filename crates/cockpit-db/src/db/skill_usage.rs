//! Agent Skills usage ledger and curator snapshot metadata.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};

use crate::db::Db;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillCreatedBy {
    Foreground,
    Background,
}

impl SkillCreatedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Foreground => "foreground",
            Self::Background => "background",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "background" => Self::Background,
            _ => Self::Foreground,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillUsageState {
    Active,
    Stale,
    Archived,
}

impl SkillUsageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Archived => "archived",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "stale" => Self::Stale,
            "archived" => Self::Archived,
            _ => Self::Active,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillUsageRow {
    pub name: String,
    pub source_path: String,
    pub archive_path: Option<String>,
    pub created_by: SkillCreatedBy,
    pub use_count: u64,
    pub view_count: u64,
    pub last_used_at: Option<i64>,
    pub last_viewed_at: Option<i64>,
    pub patch_count: u64,
    pub last_patched_at: Option<i64>,
    pub created_at: i64,
    pub state: SkillUsageState,
    pub pinned: bool,
    pub archived_at: Option<i64>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillUsageSeed {
    pub name: String,
    pub source_path: String,
    pub created_by: SkillCreatedBy,
    pub created_at: i64,
    pub pinned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillCuratorSnapshotRow {
    pub id: String,
    pub path: String,
    pub reason: String,
    pub created_at: i64,
}

impl Db {
    pub fn ensure_skill_usage(&self, seed: SkillUsageSeed, now: i64) -> Result<SkillUsageRow> {
        let name = seed.name.clone();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO skill_usage (
                    name, source_path, created_by, use_count, view_count,
                    patch_count, created_at, state, pinned, updated_at
                 ) VALUES (?1, ?2, ?3, 0, 0, 0, ?4, 'active', ?5, ?6)
                 ON CONFLICT(name) DO UPDATE SET
                    source_path = excluded.source_path,
                    created_by = excluded.created_by,
                    created_at = MIN(skill_usage.created_at, excluded.created_at),
                    pinned = CASE WHEN skill_usage.pinned = 1 OR excluded.pinned = 1 THEN 1 ELSE 0 END,
                    updated_at = excluded.updated_at",
                params![
                    seed.name,
                    seed.source_path,
                    seed.created_by.as_str(),
                    seed.created_at,
                    if seed.pinned { 1_i64 } else { 0_i64 },
                    now
                ],
            )
            .context("upserting skill usage seed")?;
            skill_usage_by_name_conn(conn, &name)?
                .ok_or_else(|| anyhow::anyhow!("skill usage row missing after upsert"))
        })
    }

    pub fn record_skill_use(
        &self,
        seed: SkillUsageSeed,
        viewed: bool,
        now: i64,
    ) -> Result<SkillUsageRow> {
        let name = seed.name.clone();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO skill_usage (
                    name, source_path, created_by, use_count, view_count,
                    last_used_at, last_viewed_at, patch_count, created_at,
                    state, pinned, archived_at, updated_at
                 ) VALUES (
                    ?1, ?2, ?3, 1, ?4, ?5, ?6, 0, ?7,
                    'active', ?8, NULL, ?5
                 )
                 ON CONFLICT(name) DO UPDATE SET
                    source_path = excluded.source_path,
                    created_by = excluded.created_by,
                    use_count = skill_usage.use_count + 1,
                    view_count = skill_usage.view_count + CASE WHEN ?4 = 1 THEN 1 ELSE 0 END,
                    last_used_at = ?5,
                    last_viewed_at = CASE WHEN ?4 = 1 THEN ?5 ELSE skill_usage.last_viewed_at END,
                    created_at = MIN(skill_usage.created_at, excluded.created_at),
                    state = 'active',
                    pinned = CASE WHEN skill_usage.pinned = 1 OR excluded.pinned = 1 THEN 1 ELSE 0 END,
                    archive_path = NULL,
                    archived_at = NULL,
                    updated_at = ?5",
                params![
                    seed.name,
                    seed.source_path,
                    seed.created_by.as_str(),
                    if viewed { 1_i64 } else { 0_i64 },
                    now,
                    viewed.then_some(now),
                    seed.created_at,
                    if seed.pinned { 1_i64 } else { 0_i64 },
                ],
            )
            .context("recording skill use")?;
            skill_usage_by_name_conn(conn, &name)?
                .ok_or_else(|| anyhow::anyhow!("skill usage row missing after use"))
        })
    }

    pub fn record_skill_patch(&self, seed: SkillUsageSeed, now: i64) -> Result<SkillUsageRow> {
        let name = seed.name.clone();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO skill_usage (
                    name, source_path, created_by, use_count, view_count,
                    patch_count, last_patched_at, created_at, state, pinned, updated_at
                 ) VALUES (?1, ?2, ?3, 0, 0, 1, ?4, ?5, 'active', ?6, ?4)
                 ON CONFLICT(name) DO UPDATE SET
                    source_path = excluded.source_path,
                    created_by = excluded.created_by,
                    patch_count = skill_usage.patch_count + 1,
                    last_patched_at = ?4,
                    created_at = MIN(skill_usage.created_at, excluded.created_at),
                    state = CASE WHEN skill_usage.state = 'archived' THEN 'archived' ELSE 'active' END,
                    pinned = CASE WHEN skill_usage.pinned = 1 OR excluded.pinned = 1 THEN 1 ELSE 0 END,
                    updated_at = ?4",
                params![
                    seed.name,
                    seed.source_path,
                    seed.created_by.as_str(),
                    now,
                    seed.created_at,
                    if seed.pinned { 1_i64 } else { 0_i64 },
                ],
            )
            .context("recording skill patch")?;
            skill_usage_by_name_conn(conn, &name)?
                .ok_or_else(|| anyhow::anyhow!("skill usage row missing after patch"))
        })
    }

    pub fn get_skill_usage(&self, name: &str) -> Result<Option<SkillUsageRow>> {
        let name = name.to_string();
        self.read_blocking(move |conn| skill_usage_by_name_conn(conn, &name))
    }

    pub fn list_skill_usage(&self) -> Result<Vec<SkillUsageRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM skill_usage ORDER BY state, name")
                .context("preparing skill usage list")?;
            stmt.query_map([], skill_usage_from_row)
                .context("querying skill usage")?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("reading skill usage rows")
        })
    }

    pub fn set_skill_usage_pinned(&self, name: &str, pinned: bool, now: i64) -> Result<()> {
        let name = name.to_string();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE skill_usage SET pinned = ?2, updated_at = ?3 WHERE name = ?1",
                params![name, if pinned { 1_i64 } else { 0_i64 }, now],
            )
            .context("updating skill pin")?;
            Ok(())
        })
    }

    pub fn set_skill_usage_state(
        &self,
        name: &str,
        state: SkillUsageState,
        archive_path: Option<String>,
        archived_at: Option<i64>,
        now: i64,
    ) -> Result<()> {
        let name = name.to_string();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE skill_usage
                 SET state = ?2, archive_path = ?3, archived_at = ?4, updated_at = ?5
                 WHERE name = ?1",
                params![name, state.as_str(), archive_path, archived_at, now],
            )
            .context("updating skill usage state")?;
            Ok(())
        })
    }

    pub fn restore_skill_usage_rows(&self, rows: Vec<SkillUsageRow>) -> Result<()> {
        self.write_blocking(move |conn| {
            let mut stmt = conn.prepare(
                "INSERT INTO skill_usage (
                        name, source_path, archive_path, created_by, use_count, view_count,
                        last_used_at, last_viewed_at, patch_count, last_patched_at,
                        created_at, state, pinned, archived_at, updated_at
                     ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
                     )
                     ON CONFLICT(name) DO UPDATE SET
                        source_path = excluded.source_path,
                        archive_path = excluded.archive_path,
                        created_by = excluded.created_by,
                        use_count = excluded.use_count,
                        view_count = excluded.view_count,
                        last_used_at = excluded.last_used_at,
                        last_viewed_at = excluded.last_viewed_at,
                        patch_count = excluded.patch_count,
                        last_patched_at = excluded.last_patched_at,
                        created_at = excluded.created_at,
                        state = excluded.state,
                        pinned = excluded.pinned,
                        archived_at = excluded.archived_at,
                        updated_at = excluded.updated_at",
            )?;
            for row in rows {
                stmt.execute(params![
                    row.name,
                    row.source_path,
                    row.archive_path,
                    row.created_by.as_str(),
                    row.use_count as i64,
                    row.view_count as i64,
                    row.last_used_at,
                    row.last_viewed_at,
                    row.patch_count as i64,
                    row.last_patched_at,
                    row.created_at,
                    row.state.as_str(),
                    if row.pinned { 1_i64 } else { 0_i64 },
                    row.archived_at,
                    row.updated_at,
                ])
                .context("restoring skill usage row")?;
            }
            Ok(())
        })
    }

    pub fn insert_skill_curator_snapshot(
        &self,
        id: &str,
        path: &str,
        reason: &str,
        created_at: i64,
    ) -> Result<()> {
        let id = id.to_string();
        let path = path.to_string();
        let reason = reason.to_string();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO skill_curator_snapshots (id, path, reason, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id, path, reason, created_at],
            )
            .context("recording skill curator snapshot")?;
            Ok(())
        })
    }

    pub fn list_skill_curator_snapshots(&self) -> Result<Vec<SkillCuratorSnapshotRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, path, reason, created_at
                     FROM skill_curator_snapshots
                     ORDER BY created_at DESC, id DESC",
                )
                .context("preparing skill curator snapshot list")?;
            stmt.query_map([], |row| {
                Ok(SkillCuratorSnapshotRow {
                    id: row.get(0)?,
                    path: row.get(1)?,
                    reason: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })
            .context("querying skill curator snapshots")?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("reading skill curator snapshots")
        })
    }

    pub fn delete_skill_curator_snapshot_rows(&self, ids: Vec<String>) -> Result<()> {
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin skill curator snapshot cleanup")?;
            {
                let mut stmt = tx
                    .prepare("DELETE FROM skill_curator_snapshots WHERE id = ?1")
                    .context("preparing skill curator snapshot cleanup")?;
                for id in ids {
                    stmt.execute([id])
                        .context("deleting skill curator snapshot row")?;
                }
            }
            tx.commit()
                .context("commit skill curator snapshot cleanup")?;
            Ok(())
        })
    }
}

fn skill_usage_by_name_conn(
    conn: &rusqlite::Connection,
    name: &str,
) -> Result<Option<SkillUsageRow>> {
    conn.query_row(
        "SELECT * FROM skill_usage WHERE name = ?1",
        [name],
        skill_usage_from_row,
    )
    .optional()
    .context("querying skill usage row")
}

fn skill_usage_from_row(row: &Row<'_>) -> rusqlite::Result<SkillUsageRow> {
    let created_by: String = row.get("created_by")?;
    let state: String = row.get("state")?;
    let use_count: i64 = row.get("use_count")?;
    let view_count: i64 = row.get("view_count")?;
    let patch_count: i64 = row.get("patch_count")?;
    Ok(SkillUsageRow {
        name: row.get("name")?,
        source_path: row.get("source_path")?,
        archive_path: row.get("archive_path")?,
        created_by: SkillCreatedBy::parse(&created_by),
        use_count: use_count.max(0) as u64,
        view_count: view_count.max(0) as u64,
        last_used_at: row.get("last_used_at")?,
        last_viewed_at: row.get("last_viewed_at")?,
        patch_count: patch_count.max(0) as u64,
        last_patched_at: row.get("last_patched_at")?,
        created_at: row.get("created_at")?,
        state: SkillUsageState::parse(&state),
        pinned: row.get::<_, i64>("pinned")? != 0,
        archived_at: row.get("archived_at")?,
        updated_at: row.get("updated_at")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_usage_round_trip_counts_uses() {
        let db = Db::open_in_memory().unwrap();
        let seed = SkillUsageSeed {
            name: "deploy".into(),
            source_path: "/tmp/deploy/SKILL.md".into(),
            created_by: SkillCreatedBy::Background,
            created_at: 100,
            pinned: false,
        };

        let first = db.record_skill_use(seed.clone(), true, 200).unwrap();
        let second = db.record_skill_use(seed, true, 300).unwrap();

        assert_eq!(first.use_count, 1);
        assert_eq!(second.use_count, 2);
        assert_eq!(second.view_count, 2);
        assert_eq!(second.last_used_at, Some(300));
        assert_eq!(second.last_viewed_at, Some(300));
        assert_eq!(second.state, SkillUsageState::Active);
    }
}
