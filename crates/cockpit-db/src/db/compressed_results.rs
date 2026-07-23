//! Durable store for retrievable compressed tool results.

use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CompressedToolResultEntry {
    pub hash: String,
    pub session_id: Uuid,
    pub agent_id: String,
    pub tool: String,
    pub call_id: String,
    pub original_byte_len: usize,
    pub compressed_byte_len: Option<usize>,
    pub created_at: i64,
    pub kind: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct NewCompressedToolResult<'a> {
    pub session_id: Uuid,
    pub agent_id: &'a str,
    pub tool: &'a str,
    pub call_id: &'a str,
    pub original_byte_len: usize,
    pub compressed_byte_len: Option<usize>,
    pub created_at: i64,
    pub kind: &'a str,
    pub content: &'a str,
}

pub fn compressed_result_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(content.as_bytes());
    let mut out = String::with_capacity(24);
    for byte in digest.iter().take(12) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

impl Db {
    pub fn insert_compressed_tool_result(
        &self,
        hash: &str,
        entry: NewCompressedToolResult<'_>,
    ) -> Result<()> {
        let hash = hash.to_owned();
        let session_id = entry.session_id;
        let agent_id = entry.agent_id.to_owned();
        let tool = entry.tool.to_owned();
        let call_id = entry.call_id.to_owned();
        let original_byte_len = entry.original_byte_len;
        let compressed_byte_len = entry.compressed_byte_len;
        let created_at = entry.created_at;
        let kind = entry.kind.to_owned();
        let content = entry.content.to_owned();
        self.insert_compressed_tool_results(vec![CompressedToolResultEntry {
            hash,
            session_id,
            agent_id,
            tool,
            call_id,
            original_byte_len,
            compressed_byte_len,
            created_at,
            kind,
            content,
        }])
    }

    /// Atomically persist every recoverable original needed by one private
    /// prune transform. Compaction uses this only after its handoff plan fits,
    /// so an aborted compaction leaves neither partial rows nor false markers.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn insert_compressed_tool_results(
        &self,
        entries: Vec<CompressedToolResultEntry>,
    ) -> Result<()> {
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("starting compressed_tool_results batch")?;
            for entry in entries {
                let existing: Option<String> = tx
                    .query_row(
                        "SELECT content
                           FROM compressed_tool_results
                          WHERE session_id = ?1 AND hash = ?2",
                        params![entry.session_id.to_string(), entry.hash],
                        |row| row.get(0),
                    )
                    .optional()
                    .context("querying compressed_tool_results collision candidate")?;
                if let Some(existing) = existing {
                    if existing == entry.content {
                        continue;
                    }
                    bail!("compressed tool result hash collision for {}", entry.hash);
                }

                tx.execute(
                    "INSERT INTO compressed_tool_results (
                        hash, session_id, agent_id, tool, call_id,
                        original_byte_len, compressed_byte_len, created_at, kind, content
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        entry.hash,
                        entry.session_id.to_string(),
                        entry.agent_id,
                        entry.tool,
                        entry.call_id,
                        entry.original_byte_len as i64,
                        entry.compressed_byte_len.map(|n| n as i64),
                        entry.created_at,
                        entry.kind,
                        entry.content,
                    ],
                )
                .context("inserting compressed_tool_result")?;
            }
            tx.commit()
                .context("committing compressed_tool_results batch")
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn compressed_tool_result(
        &self,
        session_id: Uuid,
        hash: &str,
    ) -> Result<Option<CompressedToolResultEntry>> {
        self.read_blocking(|conn| {
            conn.query_row(
                "SELECT hash, session_id, agent_id, tool, call_id,
                        original_byte_len, compressed_byte_len, created_at, kind, content
                   FROM compressed_tool_results
                  WHERE session_id = ?1 AND hash = ?2",
                params![session_id.to_string(), hash],
                decode_entry,
            )
            .optional()
            .context("querying compressed_tool_result")
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn session_has_compressed_tool_results(&self, session_id: Uuid) -> Result<bool> {
        self.read_blocking(|conn| {
            let exists: i64 = conn
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM compressed_tool_results WHERE session_id = ?1
                     )",
                    [session_id.to_string()],
                    |row| row.get(0),
                )
                .context("checking compressed_tool_results presence")?;
            Ok(exists != 0)
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_compressed_tool_results(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<CompressedToolResultEntry>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT hash, session_id, agent_id, tool, call_id,
                            original_byte_len, compressed_byte_len, created_at, kind, content
                       FROM compressed_tool_results
                      WHERE session_id = ?1
                      ORDER BY created_at ASC, rowid ASC",
                )
                .context("preparing list_compressed_tool_results")?;
            let rows = stmt
                .query_map([session_id.to_string()], decode_entry)
                .context("querying compressed_tool_results")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding compressed_tool_result")?);
            }
            Ok(out)
        })
    }
}

fn decode_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<CompressedToolResultEntry> {
    let session_id: String = row.get("session_id")?;
    let original_byte_len: i64 = row.get("original_byte_len")?;
    let compressed_byte_len: Option<i64> = row.get("compressed_byte_len")?;
    Ok(CompressedToolResultEntry {
        hash: row.get("hash")?,
        session_id: Uuid::parse_str(&session_id).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
        })?,
        agent_id: row.get("agent_id")?,
        tool: row.get("tool")?,
        call_id: row.get("call_id")?,
        original_byte_len: original_byte_len.max(0) as usize,
        compressed_byte_len: compressed_byte_len.map(|n| n.max(0) as usize),
        created_at: row.get("created_at")?,
        kind: row.get("kind")?,
        content: row.get("content")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stores_retrieves_and_rejects_collision() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let hash = "0123456789abcdefabcdef12";
        db.insert_compressed_tool_result(
            hash,
            NewCompressedToolResult {
                session_id: session.session_id,
                agent_id: "Build",
                tool: "bash",
                call_id: "call-1",
                original_byte_len: 9,
                compressed_byte_len: Some(3),
                created_at: 123,
                kind: "truncated",
                content: "redacted\n",
            },
        )
        .unwrap();
        db.insert_compressed_tool_result(
            hash,
            NewCompressedToolResult {
                session_id: session.session_id,
                agent_id: "Build",
                tool: "bash",
                call_id: "call-1",
                original_byte_len: 9,
                compressed_byte_len: Some(3),
                created_at: 123,
                kind: "truncated",
                content: "redacted\n",
            },
        )
        .unwrap();

        let row = db
            .compressed_tool_result(session.session_id, hash)
            .unwrap()
            .expect("stored");
        assert_eq!(row.content, "redacted\n");
        assert!(
            db.session_has_compressed_tool_results(session.session_id)
                .unwrap()
        );

        let err = db
            .insert_compressed_tool_result(
                hash,
                NewCompressedToolResult {
                    session_id: session.session_id,
                    agent_id: "Build",
                    tool: "bash",
                    call_id: "call-2",
                    original_byte_len: 5,
                    compressed_byte_len: Some(2),
                    created_at: 124,
                    kind: "truncated",
                    content: "other",
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("hash collision"));
    }
}
