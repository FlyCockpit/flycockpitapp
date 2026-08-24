//! Persistent assistant registry rows.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};

use crate::db::Db;

fn validate_content_hash(content_hash: &str) -> Result<()> {
    if content_hash.len() != 64
        || !content_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("assistant content hash must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

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
    pub async fn upsert_assistant(
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
        self.write(move |conn| {
            Db::upsert_assistant_conn(conn, &name, &home_dir, &config_json, &content_hash)
        })
        .await
    }

    pub async fn get_assistant(&self, name: &str) -> Result<Option<AssistantRow>> {
        let name = name.to_string();
        self.read(move |conn| Db::get_assistant_conn(conn, &name))
            .await
    }

    pub async fn list_assistants(&self) -> Result<Vec<AssistantRow>> {
        self.read(Db::list_assistants_conn).await
    }

    pub async fn delete_assistant(&self, name: &str) -> Result<bool> {
        let name = name.to_string();
        self.write(move |conn| {
            let changed = conn
                .execute("DELETE FROM assistants WHERE name = ?1", params![name])
                .context("deleting assistant")?;
            Ok(changed > 0)
        })
        .await
    }

    /// Delete exactly the registry generation represented by `expected`.
    /// Every mutable row field participates so a concurrent update cannot be
    /// erased after a client confirmed an older snapshot.
    pub async fn delete_assistant_if_unchanged(&self, expected: AssistantRow) -> Result<bool> {
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM assistants
                     WHERE name = ?1 AND created_at = ?2 AND home_dir = ?3
                       AND config_json = ?4 AND content_hash = ?5",
                    params![
                        expected.name,
                        expected.created_at,
                        expected.home_dir,
                        expected.config_json,
                        expected.content_hash,
                    ],
                )
                .context("conditionally deleting assistant")?;
            Ok(changed > 0)
        })
        .await
    }

    pub async fn update_assistant_config(&self, name: &str, config_json: &str) -> Result<()> {
        let name = name.to_string();
        let config_json = config_json.to_string();
        self.write(move |conn| {
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
        .await
    }

    /// Update only the identity-file digests when every authority-bearing row
    /// field still matches the snapshot used to read those files.
    pub async fn update_assistant_identity_hashes_cas(
        &self,
        expected: AssistantRow,
        config_json: &str,
    ) -> Result<AssistantRow> {
        let config_json = config_json.to_string();
        serde_json::from_str::<serde_json::Value>(&config_json)
            .context("assistant config must be valid JSON")?;
        self.write(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE assistants SET config_json = ?6
                     WHERE name = ?1 AND created_at = ?2 AND home_dir = ?3
                       AND config_json = ?4 AND content_hash = ?5",
                    params![
                        expected.name,
                        expected.created_at,
                        expected.home_dir,
                        expected.config_json,
                        expected.content_hash,
                        config_json,
                    ],
                )
                .context("compare-and-swap assistant identity hashes")?;
            if changed != 1 {
                anyhow::bail!("assistant registry changed while identity files were read");
            }
            Db::get_assistant_conn(conn, &expected.name)?
                .ok_or_else(|| anyhow::anyhow!("assistant disappeared after identity update"))
        })
        .await
    }

    pub async fn update_assistant_content_hash_cas(
        &self,
        name: &str,
        home_dir: &str,
        config_json: &str,
        expected_hash: &str,
        next_hash: &str,
    ) -> Result<AssistantRow> {
        validate_content_hash(expected_hash)?;
        validate_content_hash(next_hash)?;
        let name = name.to_string();
        let home_dir = home_dir.to_string();
        let config_json = config_json.to_string();
        let expected_hash = expected_hash.to_string();
        let next_hash = next_hash.to_string();
        self.write(move |conn| {
            let changed = conn.execute(
                "UPDATE assistants SET content_hash=?5 WHERE name=?1 AND home_dir=?2 AND config_json=?3 AND content_hash=?4",
                params![name, home_dir, config_json, expected_hash, next_hash],
            ).context("compare-and-swap assistant definition revision")?;
            if changed != 1 {
                anyhow::bail!("assistant registry changed before definition commit");
            }
            Db::get_assistant_conn(conn, &name)?
                .ok_or_else(|| anyhow::anyhow!("assistant `{name}` disappeared after update"))
        }).await
    }

    pub fn upsert_assistant_conn(
        conn: &rusqlite::Connection,
        name: &str,
        home_dir: &str,
        config_json: &str,
        content_hash: &str,
    ) -> Result<AssistantRow> {
        validate_content_hash(content_hash)?;
        serde_json::from_str::<serde_json::Value>(config_json)
            .context("assistant config must be valid JSON")?;
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
        Db::get_assistant_conn(conn, name)?
            .ok_or_else(|| anyhow::anyhow!("assistant `{name}` was not persisted"))
    }

    pub fn get_assistant_conn(
        conn: &rusqlite::Connection,
        name: &str,
    ) -> Result<Option<AssistantRow>> {
        conn.query_row(
            "SELECT * FROM assistants WHERE name = ?1",
            params![name],
            AssistantRow::from_row,
        )
        .optional()
        .context("loading assistant")
    }

    pub fn list_assistants_conn(conn: &rusqlite::Connection) -> Result<Vec<AssistantRow>> {
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
    }
}
