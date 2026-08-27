//! Task-artifact production over the durable `task_artifacts` accessors.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use uuid::Uuid;

use crate::db::Db;
use crate::db::workspace_lease_artifacts::{
    ArtifactResultClass, NewTaskArtifact, RedactedArtifactResult, TaskArtifactIntegrationReceipt,
    TaskArtifactRow, WorkspaceDigest,
};
use crate::git::{self, UncommittedPatch};

use super::receipt::{self, ArtifactPreconditions};

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            root: state_dir.into().join("task-artifacts"),
        }
    }

    pub fn artifact_dir(&self, id: Uuid) -> PathBuf {
        self.root.join(id.to_string())
    }

    pub fn write_payload(
        &self,
        id: Uuid,
        patch: &UncommittedPatch,
        preconditions: &ArtifactPreconditions,
    ) -> Result<()> {
        let dir = self.artifact_dir(id);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating artifact store `{}`", dir.display()))?;
        std::fs::write(dir.join("patch.diff"), patch.diff.as_bytes())
            .context("writing artifact patch")?;
        std::fs::write(
            dir.join("touched.txt"),
            preconditions.touched_paths.join("\n"),
        )
        .context("writing touched manifest")?;
        std::fs::write(
            dir.join("untracked.txt"),
            preconditions.untracked_paths.join("\n"),
        )
        .context("writing untracked manifest")?;
        Ok(())
    }

    pub fn load_patch(&self, id: Uuid) -> Result<UncommittedPatch> {
        let dir = self.artifact_dir(id);
        let diff = std::fs::read_to_string(dir.join("patch.diff"))
            .with_context(|| format!("loading patch for artifact `{id}`"))?;
        let touched = read_path_list(&dir.join("touched.txt"))?;
        let untracked = read_path_list(&dir.join("untracked.txt"))?;
        Ok(UncommittedPatch {
            diff,
            touched_paths: touched,
            untracked_paths: untracked,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProducedArtifact {
    pub row: TaskArtifactRow,
    pub patch: UncommittedPatch,
    pub preconditions: ArtifactPreconditions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentVisibleArtifact {
    pub artifact: TaskArtifactRow,
    pub receipt: Option<TaskArtifactIntegrationReceipt>,
    pub touched_paths: Vec<String>,
    pub untracked_paths: Vec<String>,
}

pub async fn produce_artifact(
    db: &Db,
    store: &ArtifactStore,
    source_worktree: &Path,
    source_workspace_lease_id: Uuid,
    session_id: Uuid,
    agent_instance_id: Uuid,
    now_ms: i64,
    validation_receipt_digest: WorkspaceDigest,
    base_receipt: Option<&receipt::WorkspaceReceipt>,
) -> Result<ProducedArtifact> {
    let patch = git::capture_uncommitted_patch(source_worktree)
        .context("capturing uncommitted artifact patch")?;
    let mut preconditions = receipt::preconditions_for_paths(
        source_worktree,
        &patch.touched_paths,
        &patch.untracked_paths,
    )?;
    if let Some(base) = base_receipt {
        preconditions.receipt = base.clone();
    }
    let parent_result = RedactedArtifactResult::new(
        ArtifactResultClass::Produced,
        WorkspaceDigest::of(patch.diff.as_bytes()),
    );
    let row = db
        .create_task_artifact(
            NewTaskArtifact {
                source_workspace_lease_id,
                session_id,
                agent_instance_id,
                base_head_digest: preconditions.receipt.head_digest.clone(),
                base_ref_digest: preconditions.receipt.ref_digest.clone(),
                base_index_digest: preconditions.receipt.index_digest.clone(),
                touched_manifest_digest: preconditions.touched_manifest_digest.clone(),
                untracked_manifest_digest: preconditions.untracked_manifest_digest.clone(),
                ordered_patch_digest: patch.digest(),
                validation_receipt_digest,
                parent_result,
            },
            now_ms,
        )
        .await
        .context("persisting task artifact")?;
    store.write_payload(row.artifact_id, &patch, &preconditions)?;
    let ref_name = format!("refs/cockpit/artifacts/{}", row.artifact_id);
    git::store_private_blob_ref(source_worktree, &ref_name, patch.diff.as_bytes())
        .context("storing private artifact blob ref")?;
    Ok(ProducedArtifact {
        row,
        patch,
        preconditions,
    })
}

pub async fn surface_for_parent(
    db: &Db,
    store: &ArtifactStore,
    session_id: Uuid,
) -> Result<Vec<ParentVisibleArtifact>> {
    let artifacts = db.list_task_artifacts_for_session(session_id).await?;
    let receipts = db
        .list_task_artifact_integration_receipts_for_session(session_id)
        .await?;
    let mut out = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let receipt = receipts
            .iter()
            .find(|row| row.artifact_id == artifact.artifact_id)
            .cloned();
        let (touched_paths, untracked_paths) = match store.load_patch(artifact.artifact_id) {
            Ok(patch) => (patch.touched_paths, patch.untracked_paths),
            Err(_) => (Vec::new(), Vec::new()),
        };
        out.push(ParentVisibleArtifact {
            artifact,
            receipt,
            touched_paths,
            untracked_paths,
        });
    }
    Ok(out)
}

pub fn assert_no_transcripts(visible: &[ParentVisibleArtifact]) -> Result<()> {
    for item in visible {
        let encoded = serde_json::to_string(&item.artifact.parent_result)
            .context("encoding parent-visible artifact result")?;
        if encoded.contains("transcript") || encoded.contains("messages") {
            bail!("parent-visible artifact leaked a child transcript");
        }
    }
    Ok(())
}

fn read_path_list(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading `{}`", path.display()))?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}
