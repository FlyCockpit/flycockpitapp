//! Daemon-owned on-disk bodies for large `cockpit://` text artifacts.
//!
//! SQLite retains only immutable accounting and an inline preview.  The
//! relative path is carried in validated artifact provenance so the database
//! layer remains a storage leaf and never receives filesystem authority.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, ensure};
use uuid::Uuid;

const ROOT: &str = "text-artifacts";

pub fn write(session_id: Uuid, content: &str) -> Result<String> {
    let relative = PathBuf::from(ROOT)
        .join(session_id.to_string())
        .join(format!("{}.txt", Uuid::new_v4()));
    let path = state_root()?.join(&relative);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("artifact blob path has no parent"))?;
    cockpit_host::private_fs::ensure_private_dir(parent)
        .with_context(|| format!("creating private artifact directory {}", parent.display()))?;
    cockpit_host::private_fs::write_private_file_exclusive(&path, content.as_bytes())
        .with_context(|| format!("creating private artifact blob {}", path.display()))?;
    relative
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("artifact blob path is not UTF-8"))
}

pub fn read(relative: &str) -> Result<String> {
    let path = resolve(relative)?;
    let bytes = cockpit_host::private_fs::read_private_file(&path, "text artifact blob")?
        .ok_or_else(|| anyhow!("text artifact blob {} is missing", path.display()))?;
    String::from_utf8(bytes).with_context(|| format!("decoding {}", path.display()))
}

pub fn remove(relative: &str) -> Result<()> {
    let path = resolve(relative)?;
    cockpit_host::private_fs::delete_private_file(&path)
        .with_context(|| format!("removing {}", path.display()))
}

pub fn read_artifact_content(artifact: &crate::db::text_artifacts::TextArtifact) -> Result<String> {
    match path_from_provenance(&artifact.provenance_json)? {
        Some(path) => read(&path),
        None => Ok(artifact.content.clone()),
    }
}

pub fn list_session_blob_paths(
    artifacts: &[crate::db::text_artifacts::TextArtifact],
) -> Result<Vec<String>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut paths = Vec::new();
    for artifact in artifacts {
        if let Some(path) = path_from_provenance(&artifact.provenance_json)?
            && seen.insert(path.clone())
        {
            paths.push(path);
        }
    }
    Ok(paths)
}

pub fn remove_many(paths: &[String]) -> Result<()> {
    for path in paths {
        remove(path)?;
    }
    Ok(())
}

/// Replay the DB-owned cleanup journal.  An intent is retired only after the
/// no-follow private-file deletion succeeds (or proves the file is absent).
pub async fn reconcile_cleanup_intents(db: &crate::db::Db) -> Result<usize> {
    let paths = db.pending_text_artifact_blob_cleanup_intents().await?;
    let mut completed = 0usize;
    let mut cleaned_sessions = std::collections::BTreeSet::new();
    for path in paths {
        if let Err(error) = remove(&path) {
            tracing::warn!(%error, %path, "text artifact blob cleanup remains pending");
            continue;
        }
        if let Some(session) = Path::new(&path)
            .components()
            .nth(1)
            .and_then(|component| match component {
                Component::Normal(value) => value.to_str(),
                _ => None,
            })
            .and_then(|value| Uuid::parse_str(value).ok())
        {
            cleaned_sessions.insert(session);
        }
        completed += usize::from(db.complete_text_artifact_blob_cleanup_intent(path).await?);
    }
    for session_id in cleaned_sessions {
        remove_session(session_id)?;
    }
    Ok(completed)
}

/// Best-effort session cleanup after the ledger's owning session transaction
/// commits. A missing directory is already a successful cleanup outcome.
pub fn remove_session(session_id: Uuid) -> Result<()> {
    let path = state_root()?.join(ROOT).join(session_id.to_string());
    // Verify the whole path before the recursive convenience operation.  The
    // directory is daemon-private, so no untrusted writer can race a checked
    // component into a symlink after this point.
    if path.exists() {
        cockpit_host::private_fs::ensure_private_dir(&path)
            .with_context(|| format!("opening private artifact directory {}", path.display()))?;
    }
    match fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

pub fn path_from_provenance(provenance_json: &str) -> Result<Option<String>> {
    let value: serde_json::Value =
        serde_json::from_str(provenance_json).context("parsing text artifact provenance")?;
    value
        .get("blob_path")
        .and_then(serde_json::Value::as_str)
        .map(|path| {
            let _ = resolve(path)?;
            Ok(path.to_owned())
        })
        .transpose()
}

fn state_root() -> Result<PathBuf> {
    cockpit_config::config::resolve::cockpit_state_dir().context("resolving daemon state directory")
}

fn resolve(relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    ensure!(!path.is_absolute(), "artifact blob path must be relative");
    ensure!(
        path.starts_with(ROOT),
        "artifact blob path escapes artifact store"
    );
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "artifact blob path is not normalized"
    );
    Ok(state_root()?.join(path))
}
