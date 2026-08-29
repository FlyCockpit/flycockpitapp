//! Workspace HEAD/ref/index receipts and artifact path-hash preconditions.

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::db::workspace_lease_artifacts::WorkspaceDigest;
use crate::git;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
/// paths in the live target working tree through the same path-identity
/// encoding, so a clean target whose worktree still matches that HEAD
/// snapshot compares equal. Git tree mode is part of the identity so
/// symlink/executable metadata drift cannot hide behind equal blob contents.
/// Live regular-file mode is the filesystem executable bit on Unix and the
/// git index mode elsewhere, so a clean `100755` blob compares equal on
/// hosts that do not expose an executable bit.
pub fn preconditions_for_paths(
    dir: &Path,
    touched: &[String],
    untracked: &[String],
) -> Result<ArtifactPreconditions> {
    let dir = git::resolve_git_path(dir)?;
    let receipt = capture_workspace_receipt(&dir)?;
    Ok(ArtifactPreconditions {
        touched_manifest_digest: git::head_manifest_digest(
            &dir,
            touched.iter().map(String::as_str),
        )?,
        untracked_manifest_digest: git::head_manifest_digest(
            &dir,
            untracked.iter().map(String::as_str),
        )?,
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
