//! Workspace HEAD/ref/index receipts and artifact path-hash preconditions.

use std::path::Path;

use anyhow::{Context, Result};

use crate::db::workspace_lease_artifacts::WorkspaceDigest;
use crate::git;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceReceipt {
    pub head: String,
    pub head_digest: WorkspaceDigest,
    pub git_ref: String,
    pub ref_digest: WorkspaceDigest,
    pub index: String,
    pub index_digest: WorkspaceDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPreconditions {
    pub receipt: WorkspaceReceipt,
    pub touched_paths: Vec<String>,
    pub untracked_paths: Vec<String>,
    pub touched_manifest_digest: WorkspaceDigest,
    pub untracked_manifest_digest: WorkspaceDigest,
}

pub fn capture_workspace_receipt(dir: &Path) -> Result<WorkspaceReceipt> {
    let dir = git::resolve_git_path(dir)?;
    let head = git::head_sha(&dir)?;
    let git_ref = git::head_ref_name(&dir)?;
    let index = git::index_stage_text(&dir)?;
    Ok(WorkspaceReceipt {
        head_digest: WorkspaceDigest::of(head.as_bytes()),
        ref_digest: WorkspaceDigest::of(git_ref.as_bytes()),
        index_digest: WorkspaceDigest::of(index.as_bytes()),
        head,
        git_ref,
        index,
    })
}

/// Preconditions for an artifact's touched/untracked paths hashed at HEAD
/// (absent if the path is not in HEAD). Integration later hashes the same
/// paths in the live target working tree.
pub fn preconditions_for_paths(
    dir: &Path,
    touched: &[String],
    untracked: &[String],
) -> Result<ArtifactPreconditions> {
    let dir = git::resolve_git_path(dir)?;
    let receipt = capture_workspace_receipt(&dir)?;
    Ok(ArtifactPreconditions {
        touched_manifest_digest: head_manifest(&dir, touched)?,
        untracked_manifest_digest: head_manifest(&dir, untracked)?,
        receipt,
        touched_paths: touched.to_vec(),
        untracked_paths: untracked.to_vec(),
    })
}

pub fn live_manifest(dir: &Path, paths: &[String]) -> Result<WorkspaceDigest> {
    git::manifest_digest(dir, paths.iter().map(String::as_str))
}

pub fn repository_id(dir: &Path) -> Result<String> {
    let dir = git::resolve_git_path(dir)?;
    let common = git::run_git_checked(&dir, &["rev-parse", "--git-common-dir"])?;
    let common = git::resolve_git_path(&dir.join(common.trim()))?;
    Ok(WorkspaceDigest::of(common.to_string_lossy().as_bytes())
        .as_str()
        .to_string())
}

pub fn canonical_root(dir: &Path) -> Result<String> {
    let root = git::find_worktree_root(dir)
        .ok_or_else(|| anyhow::anyhow!("`{}` is not inside a git worktree", dir.display()))?;
    let root = git::resolve_git_path(&root)?;
    Ok(root.to_string_lossy().into_owned())
}

fn head_manifest(dir: &Path, paths: &[String]) -> Result<WorkspaceDigest> {
    let mut acc = String::new();
    let mut ordered = paths.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    for path in &ordered {
        let digest = head_path_digest(dir, path)?;
        acc.push_str(path);
        acc.push('\0');
        acc.push_str(digest.as_str());
        acc.push('\n');
    }
    Ok(WorkspaceDigest::of(acc.as_bytes()))
}

fn head_path_digest(dir: &Path, relative: &str) -> Result<WorkspaceDigest> {
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.split(['/', '\\']).any(|part| part == "..")
    {
        anyhow::bail!("refusing escaped path `{relative}`");
    }
    let spec = format!("HEAD:{relative}");
    let out = git::run_git(dir, &["show", &spec]).with_context(|| {
        format!(
            "reading HEAD blob for `{}` in `{}`",
            relative,
            dir.display()
        )
    })?;
    if out.success {
        Ok(WorkspaceDigest::of(out.stdout.as_bytes()))
    } else {
        Ok(WorkspaceDigest::of(b"absent"))
    }
}
