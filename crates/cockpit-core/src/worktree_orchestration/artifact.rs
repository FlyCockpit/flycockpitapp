//! Task-artifact production over the durable `task_artifacts` accessors.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use uuid::Uuid;

use crate::db::Db;
use crate::db::workspace_lease_artifacts::{
    ArtifactCasOutcome, ArtifactResultClass, NewTaskArtifact, RedactedArtifactResult,
    TaskArtifactIntegrationReceipt, TaskArtifactRow, TaskArtifactState, WorkspaceDigest,
};
use crate::git::{self, UncommittedPatch};

use super::conflict::{ConflictResolution, ConflictSpecialistRequest};
use super::receipt::{self, ArtifactPreconditions};

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct IntegrationJournalArtifact {
    artifact_id: Uuid,
    session_id: Uuid,
    agent_instance_id: Uuid,
    integrating_revision: i64,
    expected_state: String,
}

/// Fan-out has two distinct baselines: the target's pre-fan-out receipt and
/// the linked child's own checkout receipt. A child worktree never shares the
/// primary worktree index, so these must not be conflated.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FanoutReceipts {
    pub target: receipt::WorkspaceReceipt,
    pub child: receipt::WorkspaceReceipt,
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

    fn fanout_receipt_path(&self, lease_id: Uuid) -> PathBuf {
        self.root
            .join("fanout-receipts")
            .join(format!("{lease_id}.json"))
    }

    fn conflict_handoff_path(&self, lease_id: Uuid, kind: &str) -> PathBuf {
        self.root
            .join("conflict-handoffs")
            .join(format!("{lease_id}.{kind}.json"))
    }

    /// Durable parent-to-specialist handoff. The parent supplies only the two
    /// captured artifacts; it never accepts a replacement patch in a tool
    /// argument.
    pub(crate) fn write_conflict_request(&self, request: &ConflictSpecialistRequest) -> Result<()> {
        self.write_conflict_handoff(request.lease_id, "request", request)
    }

    pub(crate) fn conflict_request(&self, lease_id: Uuid) -> Result<ConflictSpecialistRequest> {
        self.read_conflict_handoff(lease_id, "request")
    }

    /// The specialist's closed verdict and a patch captured from its isolated
    /// worktree form the only return channel.
    pub(crate) fn write_conflict_resolution(
        &self,
        lease_id: Uuid,
        resolution: &ConflictResolution,
    ) -> Result<()> {
        self.write_conflict_handoff(lease_id, "result", resolution)
    }

    pub(crate) fn conflict_resolution(&self, lease_id: Uuid) -> Result<ConflictResolution> {
        self.read_conflict_handoff(lease_id, "result")
    }

    fn write_conflict_handoff<T: serde::Serialize>(
        &self,
        lease_id: Uuid,
        kind: &str,
        value: &T,
    ) -> Result<()> {
        let path = self.conflict_handoff_path(lease_id, kind);
        let parent = path.parent().expect("conflict handoff has parent");
        std::fs::create_dir_all(parent)?;
        let pending = parent.join(format!(".{lease_id}.{kind}.pending"));
        std::fs::write(&pending, serde_json::to_vec(value)?)?;
        std::fs::File::open(&pending)?.sync_all()?;
        std::fs::rename(&pending, &path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn read_conflict_handoff<T: serde::de::DeserializeOwned>(
        &self,
        lease_id: Uuid,
        kind: &str,
    ) -> Result<T> {
        let path = self.conflict_handoff_path(lease_id, kind);
        serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("decoding conflict handoff `{}`", path.display()))
    }

    /// The fan-out receipt is durable before a child can make edits.  It is
    /// deliberately separate from the artifact payload: artifact production
    /// must not reconstruct a base from a child that has already changed.
    pub(crate) fn write_fanout_receipts(
        &self,
        lease_id: Uuid,
        target: &receipt::WorkspaceReceipt,
        child: &receipt::WorkspaceReceipt,
    ) -> Result<()> {
        let path = self.fanout_receipt_path(lease_id);
        let parent = path.parent().expect("fanout receipt has parent");
        std::fs::create_dir_all(parent)?;
        let pending = parent.join(format!(".{lease_id}.pending"));
        std::fs::write(
            &pending,
            serde_json::to_vec(&FanoutReceipts {
                target: target.clone(),
                child: child.clone(),
            })?,
        )?;
        std::fs::File::open(&pending)?.sync_all()?;
        std::fs::rename(&pending, &path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub(crate) fn fanout_receipts(&self, lease_id: Uuid) -> Result<FanoutReceipts> {
        let path = self.fanout_receipt_path(lease_id);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("loading fan-out receipt `{}`", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("decoding fan-out receipt `{}`", path.display()))
    }

    fn integration_journal_dir(&self) -> PathBuf {
        self.root.join("integration-journal")
    }

    /// Publish an fsync-visible intent before mutating an integration target.
    /// Recovery never guesses: any intent whose target no longer has its exact
    /// pre-apply receipt is surfaced as an operator-visible reconciliation
    /// failure instead of silently deleting edits.
    pub(crate) fn begin_integration_journal(
        &self,
        target: &Path,
        patch: &UncommittedPatch,
        before: &crate::git::ByteIdenticalReceipt,
        artifacts: &[(TaskArtifactRow, UncommittedPatch)],
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let dir = self.integration_journal_dir();
        std::fs::create_dir_all(&dir)?;
        let pending = dir.join(format!(".{id}.pending"));
        let journal = dir.join(format!("{id}.json"));
        let patch_file = dir.join(format!("{id}.patch"));
        std::fs::write(
            &pending,
            serde_json::json!({
                "attempt_id": id,
                "target": target.to_string_lossy(),
                "head": before.head,
                "ref": before.git_ref,
                "index": before.index,
                "worktree": before.worktree,
                "patch": patch_file.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
                "artifacts": artifacts.iter().map(|(row, _)| IntegrationJournalArtifact {
                    artifact_id: row.artifact_id,
                    session_id: row.session_id,
                    agent_instance_id: row.agent_instance_id,
                    integrating_revision: row.revision,
                    expected_state: TaskArtifactState::Integrating.as_str().to_owned(),
                }).collect::<Vec<_>>(),
            })
            .to_string(),
        )?;
        std::fs::write(&patch_file, &patch.diff)?;
        std::fs::File::open(&pending)?.sync_all()?;
        std::fs::File::open(&patch_file)?.sync_all()?;
        std::fs::rename(&pending, &journal)?;
        std::fs::File::open(&dir)?.sync_all()?;
        Ok(id)
    }

    pub(crate) fn finish_integration_journal(&self, id: Uuid) -> Result<()> {
        let dir = self.integration_journal_dir();
        let journal = dir.join(format!("{id}.json"));
        let patch = dir.join(format!("{id}.patch"));
        if journal.exists() {
            std::fs::remove_file(journal)?;
        }
        if patch.exists() {
            std::fs::remove_file(patch)?;
        }
        Ok(())
    }

    pub(crate) async fn reconcile_integration_journals(
        &self,
        db: &Db,
        session_id: Uuid,
        now_ms: i64,
    ) -> Result<()> {
        let dir = self.integration_journal_dir();
        if dir.exists() {
            for entry in std::fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                    continue;
                }
                let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                let artifacts: Vec<IntegrationJournalArtifact> =
                    serde_json::from_value(value.get("artifacts").cloned().ok_or_else(|| {
                        anyhow::anyhow!("integration journal has no artifact attempt records")
                    })?)?;
                if artifacts
                    .iter()
                    .all(|artifact| artifact.session_id != session_id)
                {
                    continue;
                }
                if artifacts
                    .iter()
                    .any(|artifact| artifact.session_id != session_id)
                {
                    bail!(
                        "integration journal mixes session identities; retaining it for inspection"
                    );
                }
                let target = value
                    .get("target")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("integration journal has no target"))?;
                let live = crate::git::byte_identical_receipt(Path::new(target))?;
                let unchanged = value.get("head").and_then(serde_json::Value::as_str)
                    == Some(live.head.as_str())
                    && value.get("ref").and_then(serde_json::Value::as_str)
                        == Some(live.git_ref.as_str())
                    && value.get("index").and_then(serde_json::Value::as_str)
                        == Some(live.index.as_str())
                    && value.get("worktree").and_then(serde_json::Value::as_str)
                        == Some(live.worktree.as_str());
                if unchanged {
                    for artifact in &artifacts {
                        if artifact.expected_state != TaskArtifactState::Integrating.as_str() {
                            bail!("integration journal has an invalid expected artifact state");
                        }
                        match db
                            .retry_task_artifact_integration(
                                artifact.session_id,
                                artifact.agent_instance_id,
                                artifact.artifact_id,
                                artifact.integrating_revision,
                                now_ms,
                            )
                            .await
                            .context(
                                "releasing stranded integrating artifact after unchanged target",
                            )? {
                            ArtifactCasOutcome::Transitioned(_)
                            | ArtifactCasOutcome::AlreadyTerminal(_) => {}
                            ArtifactCasOutcome::RevisionConflict => bail!(
                                "integration journal artifact `{}` no longer matches its integrating attempt",
                                artifact.artifact_id
                            ),
                        }
                    }
                    let id = path
                        .file_stem()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| anyhow::anyhow!("invalid integration journal name"))?;
                    self.finish_integration_journal(Uuid::parse_str(id)?)?;
                } else {
                    // If the database receipt was committed before the process
                    // crashed, this is a successful integration whose cleanup was
                    // interrupted. Do not report it as a stranded filesystem edit.
                    let mut completed = true;
                    for artifact in &artifacts {
                        let row = db
                            .task_artifact(
                                artifact.session_id,
                                artifact.agent_instance_id,
                                artifact.artifact_id,
                            )
                            .await?;
                        completed &=
                            row.is_some_and(|row| row.state == TaskArtifactState::Integrated);
                    }
                    if completed {
                        let id = path
                            .file_stem()
                            .and_then(|name| name.to_str())
                            .ok_or_else(|| anyhow::anyhow!("invalid integration journal name"))?;
                        self.finish_integration_journal(Uuid::parse_str(id)?)?;
                        continue;
                    }
                    bail!(
                        "unreconciled integration intent `{}`: target changed after an interrupted filesystem apply; refusing automatic rollback",
                        path.display()
                    );
                }
            }
        }
        // `integrate_locked` never applies a patch before publishing a
        // journal. Therefore, after every journal has either been reconciled
        // or failed closed above, an integrating row without a receipt cannot
        // describe a target mutation; it is precisely the crash window after
        // a DB claim and before journal publication. Release only those rows.
        db.release_receiptless_integrating_artifacts_for_recovery(session_id, now_ms)
            .await
            .context("releasing journal-less integrating artifacts")?;
        Ok(())
    }

    pub fn write_payload(
        &self,
        id: Uuid,
        patch: &UncommittedPatch,
        preconditions: &ArtifactPreconditions,
    ) -> Result<()> {
        let dir = self.artifact_dir(id);
        std::fs::create_dir_all(&self.root)
            .with_context(|| format!("creating artifact store `{}`", self.root.display()))?;
        let pending = self.root.join(format!(".{id}.pending"));
        if pending.exists() || dir.exists() {
            bail!(
                "artifact publication path already exists; refusing to overwrite a prior payload"
            );
        }
        std::fs::create_dir(&pending).context("creating pending artifact publication")?;
        std::fs::write(pending.join("patch.diff"), patch.diff.as_bytes())
            .context("writing artifact patch")?;
        std::fs::write(
            pending.join("touched.json"),
            serde_json::to_vec(&preconditions.touched_paths)?,
        )
        .context("writing touched manifest")?;
        std::fs::write(
            pending.join("untracked.json"),
            serde_json::to_vec(&preconditions.untracked_paths)?,
        )
        .context("writing untracked manifest")?;
        for name in ["patch.diff", "touched.json", "untracked.json"] {
            std::fs::File::open(pending.join(name))?.sync_all()?;
        }
        // A crash after a payload file is synced but before the directory is
        // synced may otherwise lose its name.  The database row is written
        // only after this publication sequence completes.
        std::fs::File::open(&pending)?.sync_all()?;
        std::fs::rename(&pending, &dir).context("publishing artifact payload atomically")?;
        std::fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    pub fn load_patch(&self, row: &TaskArtifactRow) -> Result<UncommittedPatch> {
        let id = row.artifact_id;
        let dir = self.artifact_dir(id);
        let diff = std::fs::read_to_string(dir.join("patch.diff"))
            .with_context(|| format!("loading patch for artifact `{id}`"))?;
        let touched = read_path_list(&dir.join("touched.json"))?;
        let untracked = read_path_list(&dir.join("untracked.json"))?;
        let patch = UncommittedPatch {
            diff,
            touched_paths: touched,
            untracked_paths: untracked,
        };
        patch.validate_paths()?;
        if patch.digest() != row.ordered_patch_digest {
            bail!("artifact `{id}` payload digest does not match its durable receipt");
        }
        Ok(patch)
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
    base_receipts: Option<&FanoutReceipts>,
) -> Result<ProducedArtifact> {
    let patch = git::capture_uncommitted_patch(source_worktree)
        .context("capturing uncommitted artifact patch")?;
    produce_artifact_from_patch(
        db,
        store,
        source_worktree,
        source_workspace_lease_id,
        session_id,
        agent_instance_id,
        now_ms,
        validation_receipt_digest,
        base_receipts,
        patch,
    )
    .await
}

/// Persist the immutable patch that was validated by the caller.  Do not
/// recapture here: re-reading a changed worker tree would make validation
/// evidence describe different bytes than the artifact we publish.
#[allow(clippy::too_many_arguments)]
pub async fn produce_artifact_from_patch(
    db: &Db,
    store: &ArtifactStore,
    source_worktree: &Path,
    source_workspace_lease_id: Uuid,
    session_id: Uuid,
    agent_instance_id: Uuid,
    now_ms: i64,
    validation_receipt_digest: WorkspaceDigest,
    base_receipts: Option<&FanoutReceipts>,
    patch: UncommittedPatch,
) -> Result<ProducedArtifact> {
    let base_receipts = base_receipts
        .context("artifact production requires the complete fan-out pre-edit receipt")?;
    let live = receipt::capture_workspace_receipt(source_worktree)?;
    // A staged child edit is artifact content, not a base change: the patch is
    // captured against HEAD while the durable target pre-edit index receipt is
    // retained below.  Only changing the checkout HEAD invalidates the child
    // base; requiring the clean child index here would reject valid staged
    // work and encourage callers to unstage it.
    if live.head_digest != base_receipts.child.head_digest {
        bail!(
            "refusing artifact production after the child HEAD or index changed from its pre-edit receipt"
        );
    }
    patch.validate_paths()?;
    let mut preconditions = receipt::preconditions_for_paths(
        source_worktree,
        &patch.touched_paths,
        &patch.untracked_paths,
    )?;
    // The manifests are captured from the source tree's base HEAD; the
    // complete, pre-edit fan-out receipt supplies the durable identity (in
    // particular the index), never the post-edit child receipt.
    preconditions.receipt = base_receipts.target.clone();
    let parent_result = RedactedArtifactResult::new(
        ArtifactResultClass::Produced,
        WorkspaceDigest::of(patch.diff.as_bytes()),
    );
    let artifact_id = Uuid::new_v4();
    store.write_payload(artifact_id, &patch, &preconditions)?;
    let ref_name = format!("refs/cockpit/artifacts/{artifact_id}");
    git::store_private_blob_ref(source_worktree, &ref_name, patch.diff.as_bytes())
        .context("storing private artifact blob ref")?;
    let row = db
        .create_task_artifact_with_id(
            artifact_id,
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
    agent_instance_id: Uuid,
) -> Result<Vec<ParentVisibleArtifact>> {
    let artifacts = db
        .list_task_artifacts_for_session(session_id)
        .await?
        .into_iter()
        .filter(|artifact| artifact.agent_instance_id == agent_instance_id)
        .collect::<Vec<_>>();
    let receipts = db
        .list_task_artifact_integration_receipts_for_session(session_id)
        .await?;
    let mut out = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let receipt = receipts
            .iter()
            .find(|row| row.artifact_id == artifact.artifact_id && row.session_id == session_id)
            .cloned();
        let patch = store.load_patch(&artifact)?;
        let (touched_paths, untracked_paths) = (patch.touched_paths, patch.untracked_paths);
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
    let raw = std::fs::read(path).with_context(|| format!("reading `{}`", path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("decoding `{}`", path.display()))
}
