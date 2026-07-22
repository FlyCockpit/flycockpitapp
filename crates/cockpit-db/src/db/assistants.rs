//! Persistent assistant registry rows.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};

use crate::db::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssistantRow {
    pub name: String,
    pub created_at: i64,
    pub home_dir: String,
    pub config_json: String,
    pub content_hash: String,
}

impl AssistantRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            name: row.get("name")?,
            created_at: row.get("created_at")?,
            home_dir: row.get("home_dir")?,
            config_json: row.get("config_json")?,
            content_hash: row.get("content_hash")?,
        })
    }
}

impl Db {
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn upsert_assistant(
        &self,
        name: &str,
        home_dir: &str,
        config_json: &str,
        content_hash: &str,
    ) -> Result<AssistantRow> {
        let name = name.to_string();
        let home_dir = home_dir.to_string();
        let config_json = config_json.to_string();
        let content_hash = content_hash.to_string();
        self.write_blocking(move |conn| {
            let created_at = Utc::now().timestamp();
            conn.execute(
                "INSERT INTO assistants (name, created_at, home_dir, config_json, content_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(name) DO UPDATE SET
                    home_dir = excluded.home_dir,
                    config_json = excluded.config_json,
                    content_hash = excluded.content_hash",
                params![name, created_at, home_dir, config_json, content_hash],
            )
            .context("upserting assistant")?;
            get_assistant_conn(conn, &name)?
                .ok_or_else(|| anyhow::anyhow!("assistant `{name}` was not persisted"))
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn get_assistant(&self, name: &str) -> Result<Option<AssistantRow>> {
        let name = name.to_string();
        self.read_blocking(move |conn| get_assistant_conn(conn, &name))
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_assistants(&self) -> Result<Vec<AssistantRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM assistants ORDER BY name ASC")
                .context("preparing assistant list")?;
            let rows = stmt
                .query_map([], AssistantRow::from_row)
                .context("querying assistants")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding assistant row")?);
            }
            Ok(out)
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn delete_assistant(&self, name: &str) -> Result<bool> {
        let name = name.to_string();
        self.write_blocking(move |conn| {
            let changed = conn
                .execute("DELETE FROM assistants WHERE name = ?1", params![name])
                .context("deleting assistant")?;
            Ok(changed > 0)
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn update_assistant_config(&self, name: &str, config_json: &str) -> Result<()> {
        let name = name.to_string();
        let config_json = config_json.to_string();
        self.write_blocking(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE assistants SET config_json = ?2 WHERE name = ?1",
                    params![name, config_json],
                )
                .context("updating assistant config")?;
            if changed == 0 {
                anyhow::bail!("assistant `{name}` does not exist");
            }
            Ok(())
        })
    }
}

fn get_assistant_conn(conn: &rusqlite::Connection, name: &str) -> Result<Option<AssistantRow>> {
    conn.query_row(
        "SELECT * FROM assistants WHERE name = ?1",
        params![name],
        AssistantRow::from_row,
    )
    .optional()
    .context("loading assistant")
}
