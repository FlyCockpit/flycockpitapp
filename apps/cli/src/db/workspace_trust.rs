//! Workspace trust decisions (migration 0045).

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use crate::db::Db;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceTrustMode {
    Trust,
    IgnoreConfig,
    Untrusted,
}

impl WorkspaceTrustMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trust => "trust",
            Self::IgnoreConfig => "ignore-config",
            Self::Untrusted => "untrusted",
        }
    }
}

impl fmt::Display for WorkspaceTrustMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for WorkspaceTrustMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "trust" => Ok(Self::Trust),
            "ignore-config" => Ok(Self::IgnoreConfig),
            "untrusted" => Ok(Self::Untrusted),
            other => bail!("unknown workspace trust mode `{other}`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceTrustDecision {
    pub root_path: String,
    pub mode: WorkspaceTrustMode,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Db {
    pub fn set_workspace_trust(
        &self,
        root_path: &std::path::Path,
        mode: WorkspaceTrustMode,
    ) -> Result<WorkspaceTrustDecision> {
        let root = normalize_trust_root(root_path)?;
        let now = now_epoch_seconds();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO workspace_trust (root_path, mode, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(root_path) DO UPDATE SET
                    mode = excluded.mode,
                    updated_at = excluded.updated_at",
                params![root, mode.as_str(), now],
            )
            .context("upserting workspace_trust decision")?;

            query_decision_by_root(conn, &root)?
                .context("workspace_trust decision missing after upsert")
        })
    }

    pub fn workspace_trust_by_root(
        &self,
        root_path: &std::path::Path,
    ) -> Result<Option<WorkspaceTrustDecision>> {
        let root = normalize_trust_root(root_path)?;
        self.read_blocking(|conn| query_decision_by_root(conn, &root))
    }

    pub fn workspace_trust_for_path(
        &self,
        path: &std::path::Path,
    ) -> Result<Option<WorkspaceTrustDecision>> {
        let resolved = crate::config::trust::resolve_trust_root(path)?;
        self.workspace_trust_by_root(&resolved.root)
    }
}

fn normalize_trust_root(root_path: &std::path::Path) -> Result<String> {
    Ok(crate::config::trust::resolve_trust_root(root_path)?
        .root
        .to_string_lossy()
        .into_owned())
}

fn query_decision_by_root(conn: &Connection, root: &str) -> Result<Option<WorkspaceTrustDecision>> {
    conn.query_row(
        "SELECT root_path, mode, created_at, updated_at
           FROM workspace_trust
          WHERE root_path = ?1",
        [root],
        decode_decision,
    )
    .optional()
    .context("querying workspace_trust decision")
}

fn decode_decision(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkspaceTrustDecision> {
    let mode: String = row.get("mode")?;
    Ok(WorkspaceTrustDecision {
        root_path: row.get("root_path")?,
        mode: WorkspaceTrustMode::from_str(&mode).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            )
        })?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

fn now_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_update_and_read_workspace_trust_decision() {
        let db = Db::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let canonical_root = root.canonicalize().unwrap().display().to_string();

        assert!(db.workspace_trust_by_root(root).unwrap().is_none());

        let first = db
            .set_workspace_trust(root, WorkspaceTrustMode::Trust)
            .unwrap();
        assert_eq!(first.mode, WorkspaceTrustMode::Trust);
        assert_eq!(first.root_path, canonical_root);
        assert_eq!(first.created_at, first.updated_at);

        let second = db
            .set_workspace_trust(root, WorkspaceTrustMode::IgnoreConfig)
            .unwrap();
        assert_eq!(second.mode, WorkspaceTrustMode::IgnoreConfig);
        assert_eq!(second.root_path, first.root_path);
        assert_eq!(second.created_at, first.created_at);
        assert!(second.updated_at >= first.updated_at);

        let loaded = db.workspace_trust_by_root(root).unwrap().expect("stored");
        assert_eq!(loaded, second);
    }

    #[test]
    fn set_workspace_trust_stores_resolved_root_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(tmp.path())
            .status()
            .expect("run git init");
        assert!(status.success());
        let subdir = tmp.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        let lexical_variant = subdir.join("..");
        let canonical_root = tmp.path().canonicalize().unwrap().display().to_string();

        let db = Db::open_in_memory().unwrap();
        let stored = db
            .set_workspace_trust(&lexical_variant, WorkspaceTrustMode::Trust)
            .unwrap();

        assert_eq!(stored.root_path, canonical_root);
        assert_eq!(
            db.workspace_trust_by_root(tmp.path())
                .unwrap()
                .expect("stored")
                .root_path,
            stored.root_path
        );
        assert_eq!(
            db.workspace_trust_for_path(&subdir)
                .unwrap()
                .expect("stored")
                .mode,
            WorkspaceTrustMode::Trust
        );
    }

    #[test]
    fn lookup_by_subdir_uses_resolved_trust_root() {
        let tmp = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(tmp.path())
            .status()
            .expect("run git init");
        assert!(status.success());
        let subdir = tmp.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();

        let db = Db::open_in_memory().unwrap();
        db.set_workspace_trust(tmp.path(), WorkspaceTrustMode::Untrusted)
            .unwrap();

        let loaded = db
            .workspace_trust_for_path(&subdir)
            .unwrap()
            .expect("stored");
        assert_eq!(
            loaded.root_path,
            tmp.path().canonicalize().unwrap().display().to_string()
        );
        assert_eq!(loaded.mode, WorkspaceTrustMode::Untrusted);
    }
}
