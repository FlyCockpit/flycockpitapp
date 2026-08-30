//! Daemon-owned on-disk bodies for large `cockpit://` text artifacts.
//!
//! SQLite retains only immutable accounting and an inline preview.  The
//! relative path is carried in validated artifact provenance so the database
//! layer remains a storage leaf and never receives filesystem authority.

use std::fs::{self, OpenOptions};
use std::io::Write;
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
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    relative
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("artifact blob path is not UTF-8"))
}

pub fn read(relative: &str) -> Result<String> {
    let path = resolve(relative)?;
    fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
}

pub fn remove(relative: &str) -> Result<()> {
    let path = resolve(relative)?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

/// Best-effort session cleanup after the ledger's owning session transaction
/// commits. A missing directory is already a successful cleanup outcome.
pub fn remove_session(session_id: Uuid) -> Result<()> {
    let path = state_root()?.join(ROOT).join(session_id.to_string());
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
