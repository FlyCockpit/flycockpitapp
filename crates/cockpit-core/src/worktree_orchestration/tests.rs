use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::TempDir;
use uuid::Uuid;

use crate::db::Db;
use crate::db::agent_tree_decisions::{
    AgentInstanceState, AgentTransitionOutcome, NewAgentInstance,
};
use crate::db::workspace_lease_artifacts::{
    NewWorkspaceLease, TaskArtifactState, WorkspaceDigest,
    WorkspaceLeaseKind as DbWorkspaceLeaseKind, WorkspaceLeaseState,
};
use crate::db::write_scope_leases::WriteScopeLeaseRow;
use crate::git;
use crate::locks::LockManager;
use crate::workspace_lease::{self, WorkspaceLease, WorkspaceLeaseKind, WorkspaceLeaseOps};

use super::*;

struct Harness {
    _tmp: TempDir,
    repo: PathBuf,
    state: PathBuf,
    db: Db,
    orch: WorktreeOrchestrator,
    now: i64,
}

async fn harness() -> Harness {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    init_repo(&repo);
    let db = Db::open_in_memory().unwrap();
    let session = db
        .create_session("orch", repo.to_str().unwrap(), "root")
        .await
        .unwrap();
    let agent = db
        .create_agent_instance(
            NewAgentInstance {
                session_id: session.session_id,
                parent_agent_instance_id: None,
                task_delegation_job_id: None,
                task_delegation_child_uuid: None,
                resolved_profile_snapshot_id: None,
                workspace_ref: None,
                auto_answer_enabled: false,
            },
            1,
        )
        .await
        .unwrap();
    assert!(matches!(
        db.transition_agent_instance(
            session.session_id,
            agent.agent_instance_id,
            0,
            AgentInstanceState::Running,
            r#"{"state":"running"}"#,
            2
        )
        .await
        .unwrap(),
        AgentTransitionOutcome::Transitioned(_)
    ));
    let scope = Uuid::new_v4();
    let root = git::resolve_git_path(&repo).unwrap();
    let root_s = root.to_string_lossy().into_owned();
    db.insert_write_scope_lease(WriteScopeLeaseRow {
        lease_id: scope,
        parent_lease_id: None,
        session_id: session.session_id,
        task_id: None,
        scope_path: root_s,
        generation: 1,
        state: "active".into(),
        owner_id: agent.agent_instance_id.to_string(),
        version: 0,
        created_at_wall_ms: 3,
        updated_at_wall_ms: 3,
        released_at_wall_ms: None,
    })
    .await
    .unwrap();
    let receipt = capture_workspace_receipt(&root).unwrap();
    let root_lease = db
        .create_workspace_lease(
            NewWorkspaceLease {
                session_id: session.session_id,
                agent_instance_id: agent.agent_instance_id,
                write_scope_lease_id: scope,
                parent_workspace_lease_id: None,
                canonical_repository_id: receipt_repository_id(&root).unwrap(),
                canonical_root: root.to_string_lossy().into_owned(),
                kind: DbWorkspaceLeaseKind::SameRoot,
                allowed_ops: WorkspaceLeaseOps::for_coding().to_bits(),
                base_sha_digest: receipt.head_digest,
                base_ref_digest: receipt.ref_digest,
                managed_path: root.to_string_lossy().into_owned(),
                private_ref_digest: WorkspaceDigest::of(b"test-root"),
                expires_at_unix_ms: workspace_lease::now_unix_ms()
                    .saturating_add(24 * 60 * 60 * 1000),
            },
            3,
        )
        .await
        .unwrap();
    let locks = Arc::new(LockManager::in_memory(db.clone()));
    let orch = WorktreeOrchestrator::new(OrchestratorInit {
        db: db.clone(),
        locks,
        state_dir: state.clone(),
        session_id: session.session_id,
        agent_instance_id: agent.agent_instance_id,
        lock_identity: "orchestrator".into(),
        primary_repo: repo.clone(),
        parent_workspace_lease_id: root_lease.workspace_lease_id,
        parent_workspace_lease_revision: root_lease.revision,
        write_scope_lease_id: scope,
        write_scope_generation: 1,
        write_scope_revision: 0,
    })
    .unwrap();
    Harness {
        _tmp: tmp,
        repo,
        state,
        db,
        orch,
        now: 10,
    }
}

fn init_repo(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    git::run_git_checked(dir, &["init", "-q", "-b", "main"]).unwrap();
    git::run_git_checked(dir, &["config", "user.email", "t@t"]).unwrap();
    git::run_git_checked(dir, &["config", "user.name", "t"]).unwrap();
    git::run_git_checked(dir, &["config", "commit.gpgsign", "false"]).unwrap();
    for (name, body) in [
        ("a.txt", "a0\n"),
        ("b.txt", "b0\n"),
        ("c.txt", "c0\n"),
        ("shared.txt", "s0\n"),
    ] {
        std::fs::write(dir.join(name), body).unwrap();
        git::run_git_checked(dir, &["add", "--", name]).unwrap();
    }
    git::run_git_checked(dir, &["commit", "-q", "-m", "init"]).unwrap();
}

fn write_uncommitted(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join(name), body).unwrap();
}

#[cfg(unix)]
fn cargo_shim(dir: &Path, log: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("cargo");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$PWD $*\" >> {}\nexit 0\n",
        log.display()
    );
    std::fs::write(&bin, script).unwrap();
    let mut perms = std::fs::metadata(&bin).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&bin, perms).unwrap();
    bin
}

fn commits(dir: &Path) -> u64 {
    git::commit_count(dir).unwrap()
}

fn index_text(dir: &Path) -> String {
    git::index_stage_text(dir).unwrap()
}

#[tokio::test]
async fn direct_uncommitted_edit_cancel_preserves_visible_edits() {
    let mut h = harness().await;
    let before = git::byte_identical_receipt(&h.repo).unwrap();
    h.orch.edit_in_place();
    write_uncommitted(&h.repo, "a.txt", "edited-in-place\n");
    let cancelled = h.orch.cancel_edit_in_place().unwrap();
    assert!(cancelled.cancelled);
    assert_eq!(
        std::fs::read_to_string(h.repo.join("a.txt")).unwrap(),
        "edited-in-place\n"
    );
    assert_ne!(git::byte_identical_receipt(&h.repo).unwrap(), before);
    assert_eq!(commits(&h.repo), 1);
}

#[tokio::test]
async fn three_orthogonal_child_artifacts_apply_uncommitted() {
    let mut h = harness().await;
    let start_commits = commits(&h.repo);
    let start_index = index_text(&h.repo);
    let children = h
        .orch
        .fan_out(
            vec![
                FanOutSpec { label: "a".into() },
                FanOutSpec { label: "b".into() },
                FanOutSpec { label: "c".into() },
            ],
            h.now,
        )
        .await
        .unwrap();
    for child in &children {
        assert_eq!(
            h.orch
                .store()
                .fanout_receipts(child.lease.workspace_lease_id)
                .unwrap(),
            super::artifact::FanoutReceipts {
                target: child.base_receipt.clone(),
                child: capture_workspace_receipt(&child.path).unwrap(),
            },
            "artifact production must load the durable pre-fan-out receipt, not rebuild one after edits"
        );
        let branch =
            git::run_git_checked(&child.path, &["rev-parse", "--abbrev-ref", "HEAD"]).unwrap();
        let expected = format!("cockpit-lease/{}", child.lease.workspace_lease_id);
        assert_eq!(branch.trim(), expected);
        assert_eq!(
            child.lease.private_ref_digest,
            WorkspaceDigest::of(expected),
            "fan-out lease and on-disk worktree must share one private identity"
        );
        assert!(
            WorkspaceLease::from_row(&child.lease)
                .unwrap()
                .identity_matches_disk()
        );
        let launch_lease = workspace_lease::load_lease_from_task_argument(
            &h.db,
            h.orch.session_id(),
            Some(h.orch.agent_instance_id()),
            Some(&child.lease.workspace_lease_id.to_string()),
        )
        .await
        .expect("normal managed-child task admission must accept fan-out authority")
        .expect("managed child lease must load for task launch");
        assert!(launch_lease.is_durable_host_issued_managed_worktree());
        assert!(workspace_lease::authorizes_managed_worktree_cwd(
            Some(&launch_lease),
            &child.path
        ));
    }
    write_uncommitted(&children[0].path, "a.txt", "a1\n");
    write_uncommitted(&children[1].path, "b.txt", "b1\n");
    write_uncommitted(&children[2].path, "c.txt", "c1\n");
    let mut ids = Vec::new();
    for child in &children {
        let produced = h
            .orch
            .produce_from_child(child, h.now + 1, WorkspaceDigest::of(b"ok"))
            .await
            .unwrap();
        ids.push(produced.row.artifact_id);
    }
    let result = h.orch.apply_uncommitted(ids, h.now + 2).await.unwrap();
    match result {
        IntegrationResult::Integrated { artifacts, .. } => {
            assert_eq!(artifacts.len(), 3);
            assert!(
                artifacts
                    .iter()
                    .all(|row| row.state == TaskArtifactState::Integrated)
            );
        }
        other => panic!("expected integrated, got {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(h.repo.join("a.txt")).unwrap(),
        "a1\n"
    );
    assert_eq!(
        std::fs::read_to_string(h.repo.join("b.txt")).unwrap(),
        "b1\n"
    );
    assert_eq!(
        std::fs::read_to_string(h.repo.join("c.txt")).unwrap(),
        "c1\n"
    );
    assert_eq!(commits(&h.repo), start_commits);
    assert_eq!(index_text(&h.repo), start_index);
    super::capability::no_user_visible_commit(start_commits, commits(&h.repo)).unwrap();
    assert!(super::capability::artifact_is_terminal(
        TaskArtifactState::Integrated
    ));
}

#[tokio::test]
async fn ordered_merge_is_commitless_and_deterministic() {
    let mut h = harness().await;
    let children = h
        .orch
        .fan_out(
            vec![
                FanOutSpec {
                    label: "first".into(),
                },
                FanOutSpec {
                    label: "second".into(),
                },
            ],
            h.now,
        )
        .await
        .unwrap();
    write_uncommitted(&children[0].path, "a.txt", "first\n");
    write_uncommitted(&children[1].path, "b.txt", "second\n");
    let first = h
        .orch
        .produce_from_child(&children[0], h.now + 1, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    let second = h
        .orch
        .produce_from_child(&children[1], h.now + 2, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    let before_head = git::head_sha(&h.repo).unwrap();
    let result = h
        .orch
        .merge_selected(
            vec![first.row.artifact_id, second.row.artifact_id],
            h.now + 3,
        )
        .await
        .unwrap();
    match result {
        IntegrationResult::Integrated { private_ref, .. } => {
            assert!(
                private_ref
                    .as_deref()
                    .is_some_and(|name| name.starts_with("refs/cockpit/")),
                "{private_ref:?}"
            );
        }
        other => panic!("expected merge integrated: {other:?}"),
    }
    assert_eq!(git::head_sha(&h.repo).unwrap(), before_head);
    assert_eq!(commits(&h.repo), 1);
    assert_eq!(
        std::fs::read_to_string(h.repo.join("a.txt")).unwrap(),
        "first\n"
    );
    assert_eq!(
        std::fs::read_to_string(h.repo.join("b.txt")).unwrap(),
        "second\n"
    );
}

#[tokio::test]
async fn overlapping_conflict_makes_zero_target_edits() {
    let mut h = harness().await;
    let before = git::byte_identical_receipt(&h.repo).unwrap();
    let children = h
        .orch
        .fan_out(
            vec![
                FanOutSpec {
                    label: "left".into(),
                },
                FanOutSpec {
                    label: "right".into(),
                },
            ],
            h.now,
        )
        .await
        .unwrap();
    write_uncommitted(&children[0].path, "shared.txt", "left\n");
    write_uncommitted(&children[1].path, "shared.txt", "right\n");
    let left = h
        .orch
        .produce_from_child(&children[0], h.now + 1, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    let right = h
        .orch
        .produce_from_child(&children[1], h.now + 2, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    let result = h
        .orch
        .apply_uncommitted(vec![left.row.artifact_id, right.row.artifact_id], h.now + 3)
        .await
        .unwrap();
    match result {
        IntegrationResult::Conflict {
            target_receipt,
            artifacts,
            ..
        } => {
            assert_eq!(target_receipt, before);
            assert!(
                artifacts
                    .iter()
                    .all(|row| row.state == TaskArtifactState::Conflict)
            );
        }
        other => panic!("expected conflict: {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(h.repo.join("shared.txt")).unwrap(),
        "s0\n"
    );
    assert_eq!(commits(&h.repo), 1);
}

#[tokio::test]
async fn bounded_specialist_handoff_requires_parent_acceptance_and_uses_its_worktree_patch() {
    let mut h = harness().await;
    let children = h
        .orch
        .fan_out(
            vec![
                FanOutSpec {
                    label: "left".into(),
                },
                FanOutSpec {
                    label: "right".into(),
                },
            ],
            h.now,
        )
        .await
        .unwrap();
    write_uncommitted(&children[0].path, "shared.txt", "left\n");
    write_uncommitted(&children[1].path, "shared.txt", "right\n");
    let left = h
        .orch
        .produce_from_child(&children[0], h.now + 1, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    let right = h
        .orch
        .produce_from_child(&children[1], h.now + 2, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    let request = h
        .orch
        .request_conflict_specialist(left.row.artifact_id, right.row.artifact_id, h.now + 3)
        .await
        .unwrap();
    let specialist_row =
        h.db.workspace_lease(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            request.lease_id,
        )
        .await
        .unwrap()
        .unwrap();
    let specialist =
        super::ConflictSpecialist::bounded_by(WorkspaceLease::from_row(&specialist_row).unwrap());
    std::fs::write(
        specialist.lease().visibility_root.join("shared.txt"),
        "combined\n",
    )
    .unwrap();
    h.orch
        .submit_conflict_resolution(specialist, super::ConflictSpecialistVerdict::Combined)
        .unwrap();
    let result = h
        .orch
        .integrate_with_conflict_specialist(
            vec![left.row.artifact_id, right.row.artifact_id],
            IntegrationMode::ApplyUncommitted,
            request.lease_id,
            true,
            h.now + 4,
        )
        .await
        .unwrap();
    assert!(matches!(result, IntegrationResult::Integrated { .. }));
    assert_eq!(
        std::fs::read_to_string(h.repo.join("shared.txt")).unwrap(),
        "combined\n"
    );
}

#[tokio::test]
async fn dirty_unrelated_target_is_left_untouched() {
    let mut h = harness().await;
    std::fs::write(h.repo.join("dirt.txt"), "stay\n").unwrap();
    let children = h
        .orch
        .fan_out(vec![FanOutSpec { label: "a".into() }], h.now)
        .await
        .unwrap();
    write_uncommitted(&children[0].path, "a.txt", "a1\n");
    // Worker edits may legitimately be staged. Artifact production must use
    // the pre-fan-out target index receipt rather than treating this child
    // index delta as a changed checkout base.
    git::run_git_checked(&children[0].path, &["add", "--", "a.txt"]).unwrap();
    let produced = h
        .orch
        .produce_from_child(&children[0], h.now + 1, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    assert!(
        h.orch
            .store()
            .load_patch(&produced.row)
            .unwrap()
            .diff
            .contains("a1")
    );
    let result = h
        .orch
        .apply_uncommitted(vec![produced.row.artifact_id], h.now + 2)
        .await
        .unwrap();
    assert!(matches!(result, IntegrationResult::Integrated { .. }));
    assert_eq!(
        std::fs::read_to_string(h.repo.join("a.txt")).unwrap(),
        "a1\n"
    );
    assert_eq!(
        std::fs::read_to_string(h.repo.join("dirt.txt")).unwrap(),
        "stay\n"
    );
}

#[tokio::test]
async fn staged_unrelated_primary_change_does_not_block_child_artifact() {
    let mut h = harness().await;
    std::fs::write(h.repo.join("staged-unrelated.txt"), "keep-staged\n").unwrap();
    git::run_git_checked(&h.repo, &["add", "--", "staged-unrelated.txt"]).unwrap();
    let start_index = index_text(&h.repo);
    let children = h
        .orch
        .fan_out(vec![FanOutSpec { label: "a".into() }], h.now)
        .await
        .unwrap();
    write_uncommitted(&children[0].path, "a.txt", "a1\n");
    let produced = h
        .orch
        .produce_from_child(&children[0], h.now + 1, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    assert!(matches!(
        h.orch
            .apply_uncommitted(vec![produced.row.artifact_id], h.now + 2)
            .await
            .unwrap(),
        IntegrationResult::Integrated { .. }
    ));
    assert_eq!(index_text(&h.repo), start_index);
    assert_eq!(
        std::fs::read_to_string(h.repo.join("staged-unrelated.txt")).unwrap(),
        "keep-staged\n"
    );
}

#[tokio::test]
async fn changed_head_index_touched_and_untracked_receipts_are_stale() {
    let mut h = harness().await;
    let children = h
        .orch
        .fan_out(vec![FanOutSpec { label: "a".into() }], h.now)
        .await
        .unwrap();
    write_uncommitted(&children[0].path, "a.txt", "a1\n");
    let produced = h
        .orch
        .produce_from_child(&children[0], h.now + 1, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();

    git::run_git_checked(
        &h.repo,
        &["commit", "-q", "--allow-empty", "-m", "move-head"],
    )
    .unwrap();
    let before = git::byte_identical_receipt(&h.repo).unwrap();
    let result = h
        .orch
        .apply_uncommitted(vec![produced.row.artifact_id], h.now + 2)
        .await
        .unwrap();
    match result {
        IntegrationResult::Stale {
            reason,
            target_receipt,
            ..
        } => {
            assert_eq!(reason, StaleReason::Head);
            assert_eq!(target_receipt, before);
        }
        other => panic!("expected head stale: {other:?}"),
    }

    let mut h = harness().await;
    let children = h
        .orch
        .fan_out(vec![FanOutSpec { label: "a".into() }], h.now)
        .await
        .unwrap();
    write_uncommitted(&children[0].path, "a.txt", "a1\n");
    let produced = h
        .orch
        .produce_from_child(&children[0], h.now + 1, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    std::fs::write(h.repo.join("staged.txt"), "x\n").unwrap();
    git::run_git_checked(&h.repo, &["add", "--", "staged.txt"]).unwrap();
    let before = git::byte_identical_receipt(&h.repo).unwrap();
    let result = h
        .orch
        .apply_uncommitted(vec![produced.row.artifact_id], h.now + 2)
        .await
        .unwrap();
    match result {
        IntegrationResult::Stale {
            reason,
            target_receipt,
            ..
        } => {
            assert_eq!(reason, StaleReason::Index);
            assert_eq!(target_receipt, before);
        }
        other => panic!("expected index stale: {other:?}"),
    }

    let mut h = harness().await;
    let children = h
        .orch
        .fan_out(vec![FanOutSpec { label: "a".into() }], h.now)
        .await
        .unwrap();
    write_uncommitted(&children[0].path, "a.txt", "a1\n");
    let produced = h
        .orch
        .produce_from_child(&children[0], h.now + 1, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    write_uncommitted(&h.repo, "a.txt", "target-dirty\n");
    let before = git::byte_identical_receipt(&h.repo).unwrap();
    let result = h
        .orch
        .apply_uncommitted(vec![produced.row.artifact_id], h.now + 2)
        .await
        .unwrap();
    match result {
        IntegrationResult::Stale {
            reason,
            target_receipt,
            ..
        } => {
            assert_eq!(reason, StaleReason::TouchedPaths);
            assert_eq!(target_receipt, before);
        }
        other => panic!("expected touched stale: {other:?}"),
    }

    let mut h = harness().await;
    let children = h
        .orch
        .fan_out(vec![FanOutSpec { label: "u".into() }], h.now)
        .await
        .unwrap();
    write_uncommitted(&children[0].path, "fresh.txt", "from-child\n");
    let produced = h
        .orch
        .produce_from_child(&children[0], h.now + 1, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    write_uncommitted(&h.repo, "fresh.txt", "already-here\n");
    let before = git::byte_identical_receipt(&h.repo).unwrap();
    let result = h
        .orch
        .apply_uncommitted(vec![produced.row.artifact_id], h.now + 2)
        .await
        .unwrap();
    match result {
        IntegrationResult::Stale {
            reason,
            target_receipt,
            ..
        } => {
            assert_eq!(reason, StaleReason::UntrackedPaths);
            assert_eq!(target_receipt, before);
        }
        other => panic!("expected untracked stale: {other:?}"),
    }
}

#[tokio::test]
async fn cancelled_integration_leaves_target_byte_identical() {
    let mut h = harness().await;
    let before = git::byte_identical_receipt(&h.repo).unwrap();
    let children = h
        .orch
        .fan_out(vec![FanOutSpec { label: "a".into() }], h.now)
        .await
        .unwrap();
    write_uncommitted(&children[0].path, "a.txt", "a1\n");
    let produced = h
        .orch
        .produce_from_child(&children[0], h.now + 1, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    h.orch.cancel_token().cancel();
    let result = h
        .orch
        .apply_uncommitted(vec![produced.row.artifact_id], h.now + 2)
        .await
        .unwrap();
    match result {
        IntegrationResult::Cancelled { target_receipt, .. } => {
            assert_eq!(target_receipt, before);
        }
        other => panic!("expected cancelled: {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(h.repo.join("a.txt")).unwrap(),
        "a0\n"
    );
}

#[tokio::test]
async fn restart_recovery_marks_missing_worktree_uncertain_without_deleting() {
    let mut h = harness().await;
    let children = h
        .orch
        .fan_out(
            vec![FanOutSpec {
                label: "gone".into(),
            }],
            h.now,
        )
        .await
        .unwrap();
    let path = children[0].path.clone();
    assert!(path.exists());
    std::fs::remove_dir_all(&path).unwrap();
    let recovered = h.orch.recover(h.now + 5).await.unwrap();
    assert!(
        recovered
            .iter()
            .any(|row| row.state == WorkspaceLeaseState::Uncertain)
    );
    assert!(
        !path.exists(),
        "recovery must not recreate a missing worktree"
    );
}

#[tokio::test]
async fn cleanup_removes_the_managed_private_branch_before_marking_cleaned() {
    let mut h = harness().await;
    let child = h
        .orch
        .fan_out(
            vec![FanOutSpec {
                label: "cleanup".into(),
            }],
            h.now,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    let branch = format!("cockpit-lease/{}", child.lease.workspace_lease_id);
    assert!(
        git::run_git_checked(
            &h.repo,
            &[
                "show-ref",
                "--verify",
                "--quiet",
                &format!("refs/heads/{branch}")
            ]
        )
        .is_ok()
    );
    let cleaned = h
        .orch
        .cleanup_child(&child, child.lease.expires_at_unix_ms + 1)
        .await
        .unwrap();
    assert!(matches!(
        cleaned,
        super::lifecycle::CleanupOutcome::Cleaned(ref row)
            if row.state == WorkspaceLeaseState::Cleaned
    ));
    assert!(!child.path.exists());
    assert!(
        !git::run_git(
            &h.repo,
            &[
                "show-ref",
                "--verify",
                "--quiet",
                &format!("refs/heads/{branch}")
            ]
        )
        .unwrap()
        .success
    );
}

#[tokio::test]
async fn cleanup_refusal_releases_the_cleaning_claim_for_retry() {
    let mut h = harness().await;
    let mut child = h
        .orch
        .fan_out(
            vec![FanOutSpec {
                label: "dirty-cleanup".into(),
            }],
            h.now,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    write_uncommitted(&child.path, "a.txt", "must-retain\n");
    let grace = match h
        .db
        .grace_retain_workspace_lease(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            child.lease.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected grace transition: {other:?}"),
    };
    child.lease = grace;
    let outcome = h.orch.cleanup_child(&child, h.now + 2).await.unwrap();
    assert!(matches!(
        outcome,
        super::lifecycle::CleanupOutcome::Denied {
            reason: super::lifecycle::CleanupDenial::Dirty,
            ref row,
        } if row.state == WorkspaceLeaseState::Grace
    ));
    let durable =
        h.db.workspace_lease(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(durable.state, WorkspaceLeaseState::Grace);
    assert!(
        child.path.exists(),
        "a refused clean removal must retain the worktree"
    );
}

#[tokio::test]
async fn recovery_releases_orphaned_cleaning_claim_for_retry() {
    let mut h = harness().await;
    let mut child = h
        .orch
        .fan_out(
            vec![FanOutSpec {
                label: "orphaned-cleaning".into(),
            }],
            h.now,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    let grace = match h
        .db
        .grace_retain_workspace_lease(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            child.lease.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected grace transition: {other:?}"),
    };
    let cleaning = match h
        .db
        .claim_workspace_lease_cleanup(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            grace.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected cleaning claim: {other:?}"),
    };
    assert_eq!(cleaning.state, WorkspaceLeaseState::Cleaning);
    let recovered = h.orch.recover(h.now + 2).await.unwrap();
    let row = recovered
        .iter()
        .find(|row| row.workspace_lease_id == child.lease.workspace_lease_id)
        .expect("recovered orphaned cleaning lease");
    assert_eq!(row.state, WorkspaceLeaseState::Grace);
    child.lease = row.clone();
    let outcome = h.orch.cleanup_child(&child, h.now + 3).await.unwrap();
    assert!(matches!(
        outcome,
        super::lifecycle::CleanupOutcome::Cleaned(_)
    ));
    assert!(!child.path.exists());
}

#[tokio::test]
async fn explicit_cleanup_resumes_orphaned_cleaning_claim() {
    let mut h = harness().await;
    let child = h
        .orch
        .fan_out(
            vec![FanOutSpec {
                label: "operator-cleaning".into(),
            }],
            h.now,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    let grace = match h
        .db
        .grace_retain_workspace_lease(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            child.lease.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected grace transition: {other:?}"),
    };
    let cleaning = match h
        .db
        .claim_workspace_lease_cleanup(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            grace.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected cleaning claim: {other:?}"),
    };
    assert_eq!(cleaning.state, WorkspaceLeaseState::Cleaning);
    workspace_lease::explicitly_clean_managed_worktree(
        &h.db,
        h.orch.session_id(),
        h.orch.agent_instance_id(),
        child.lease.workspace_lease_id,
    )
    .await
    .unwrap();
    let durable =
        h.db.workspace_lease(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(durable.state, WorkspaceLeaseState::Cleaned);
    assert!(!child.path.exists());
}

#[tokio::test]
async fn cancelled_cleanup_releases_orphaned_cleaning_claim() {
    let mut h = harness().await;
    let child = h
        .orch
        .fan_out(
            vec![FanOutSpec {
                label: "cancelled-cleaning".into(),
            }],
            h.now,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    let grace = match h
        .db
        .grace_retain_workspace_lease(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            child.lease.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected grace transition: {other:?}"),
    };
    let cleaning = match h
        .db
        .claim_workspace_lease_cleanup(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            grace.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected cleaning claim: {other:?}"),
    };
    let mut child = child;
    child.lease = cleaning;
    h.orch.cancel_token().cancel();
    let outcome = h.orch.cleanup_child(&child, h.now + 2).await.unwrap();
    assert!(matches!(
        outcome,
        super::lifecycle::CleanupOutcome::Denied { .. }
    ));
    let durable =
        h.db.workspace_lease(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(durable.state, WorkspaceLeaseState::Grace);
    assert!(child.path.exists());
}

#[tokio::test]
async fn recovery_does_not_release_live_cleaning_claim_or_admit_a_pin() {
    let mut h = harness().await;
    let mut child = h
        .orch
        .fan_out(
            vec![FanOutSpec {
                label: "live-cleaning".into(),
            }],
            h.now,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    let grace = match h
        .db
        .grace_retain_workspace_lease(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            child.lease.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected grace transition: {other:?}"),
    };
    let cleaning = match h
        .db
        .claim_workspace_lease_cleanup(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            grace.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected cleaning claim: {other:?}"),
    };
    assert_eq!(cleaning.state, WorkspaceLeaseState::Cleaning);
    child.lease = cleaning.clone();
    let live = workspace_lease::try_acquire_live_cleaning_claim(
        h.orch.session_id(),
        child.lease.workspace_lease_id,
    )
    .expect("live cleaning claim must be free before the deleter holds it");

    let recovered = h.orch.recover(h.now + 2).await.unwrap();
    let row = recovered
        .iter()
        .find(|row| row.workspace_lease_id == child.lease.workspace_lease_id)
        .expect("live cleaning lease stays visible to recovery");
    assert_eq!(
        row.state,
        WorkspaceLeaseState::Cleaning,
        "recovery must not drop a live deleter back to pinnable grace"
    );
    assert!(
        h.orch.pin_child(&child, h.now + 2).await.is_err(),
        "pin must refuse a live cleaning claim"
    );
    assert!(child.path.exists());

    drop(live);
    let recovered = h.orch.recover(h.now + 3).await.unwrap();
    let row = recovered
        .iter()
        .find(|row| row.workspace_lease_id == child.lease.workspace_lease_id)
        .expect("orphaned cleaning lease after the live deleter exits");
    assert_eq!(row.state, WorkspaceLeaseState::Grace);
    child.lease = row.clone();
    let pinned = h.orch.pin_child(&child, h.now + 4).await.unwrap();
    assert!(pinned.pinned_at_unix_ms.is_some());
    assert!(child.path.exists());
}

#[tokio::test]
async fn overlapping_cleanup_waits_for_live_cleaning_claim() {
    let mut h = harness().await;
    let child = h
        .orch
        .fan_out(
            vec![FanOutSpec {
                label: "overlap-cleaning".into(),
            }],
            h.now,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    let grace = match h
        .db
        .grace_retain_workspace_lease(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            child.lease.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected grace transition: {other:?}"),
    };
    let cleaning = match h
        .db
        .claim_workspace_lease_cleanup(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            grace.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected cleaning claim: {other:?}"),
    };
    let live = workspace_lease::try_acquire_live_cleaning_claim(
        h.orch.session_id(),
        child.lease.workspace_lease_id,
    )
    .expect("live cleaning claim must be free before the deleter holds it");

    let db = h.db.clone();
    let session = h.orch.session_id();
    let agent = h.orch.agent_instance_id();
    let lease_id = child.lease.workspace_lease_id;
    let revision = cleaning.revision;
    let primary = h.orch.primary_repo().to_path_buf();
    let cleanup = tokio::spawn(async move {
        super::lifecycle::cleanup_managed_worktree(
            &db, session, agent, lease_id, revision, 300, &primary, None,
        )
        .await
    });

    tokio::task::yield_now().await;
    let recovered = h.orch.recover(h.now + 2).await.unwrap();
    let row = recovered
        .iter()
        .find(|row| row.workspace_lease_id == lease_id)
        .expect("live overlapping cleanup stays cleaning");
    assert_eq!(row.state, WorkspaceLeaseState::Cleaning);
    assert!(child.path.exists());

    drop(live);
    let outcome = cleanup.await.expect("cleanup task").expect("cleanup");
    assert!(matches!(
        outcome,
        super::lifecycle::CleanupOutcome::Cleaned(_)
    ));
    assert!(!child.path.exists());
}

#[tokio::test]
async fn cleanup_missing_path_keeps_private_ref_and_marks_real_ambiguity() {
    let mut h = harness().await;
    let mut child = h
        .orch
        .fan_out(
            vec![FanOutSpec {
                label: "missing-cleanup".into(),
            }],
            h.now,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    let branch = format!("cockpit-lease/{}", child.lease.workspace_lease_id);
    std::fs::remove_dir_all(&child.path).unwrap();
    let grace = match h
        .db
        .grace_retain_workspace_lease(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            child.lease.workspace_lease_id,
            child.lease.revision,
            h.now + 1,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::LeaseCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected grace transition: {other:?}"),
    };
    child.lease = grace;
    let outcome = h.orch.cleanup_child(&child, h.now + 2).await.unwrap();
    assert!(matches!(
        outcome,
        super::lifecycle::CleanupOutcome::Denied {
            reason: super::lifecycle::CleanupDenial::Uncertain,
            ref row,
        } if row.state == WorkspaceLeaseState::Uncertain
            && row.uncertain_reason == Some(crate::db::workspace_lease_artifacts::WorkspaceLeaseTerminalReason::MissingManagedPath)
    ));
    assert!(
        git::run_git_checked(
            &h.repo,
            &[
                "show-ref",
                "--verify",
                "--quiet",
                &format!("refs/heads/{branch}")
            ]
        )
        .is_ok(),
        "a missing managed path is not proof that its private ref is safe to delete"
    );
}

#[tokio::test]
async fn restart_releases_the_pre_journal_integrating_crash_gap() {
    let mut h = harness().await;
    let child = h
        .orch
        .fan_out(
            vec![FanOutSpec {
                label: "journal-gap".into(),
            }],
            h.now,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    write_uncommitted(&child.path, "a.txt", "artifact\n");
    let artifact = h
        .orch
        .produce_from_child(&child, h.now + 1, WorkspaceDigest::of(b"journal-gap"))
        .await
        .unwrap();
    let integrating = match h
        .db
        .begin_task_artifact_integration(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            artifact.row.artifact_id,
            artifact.row.revision,
            h.now + 2,
        )
        .await
        .unwrap()
    {
        crate::db::workspace_lease_artifacts::ArtifactCasOutcome::Transitioned(row) => row,
        other => panic!("unexpected pre-journal crash-gap setup: {other:?}"),
    };
    h.orch.recover(h.now + 3).await.unwrap();
    let recovered =
        h.db.task_artifact(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            artifact.row.artifact_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.state, TaskArtifactState::Produced);
    assert_eq!(recovered.revision, integrating.revision + 1);
    assert!(
        h.db.task_artifact_integration_receipt(
            h.orch.session_id(),
            h.orch.agent_instance_id(),
            artifact.row.artifact_id,
        )
        .await
        .unwrap()
        .is_none(),
        "the recovery reset is allowed only before a target mutation has an immutable receipt"
    );
}

#[tokio::test]
async fn pin_and_uncertain_worktrees_are_not_force_removed() {
    let mut h = harness().await;
    let children = h
        .orch
        .fan_out(
            vec![
                FanOutSpec {
                    label: "pin".into(),
                },
                FanOutSpec {
                    label: "unc".into(),
                },
            ],
            h.now,
        )
        .await
        .unwrap();
    let pinned = h.orch.pin_child(&children[0], h.now + 1).await.unwrap();
    assert!(pinned.pinned_at_unix_ms.is_some());
    super::lifecycle::retain_managed_worktree(&pinned);
    let outcome = h.orch.cleanup_child(&children[0], h.now + 2).await.unwrap();
    assert!(matches!(
        outcome,
        super::lifecycle::CleanupOutcome::Denied {
            reason: super::lifecycle::CleanupDenial::Pinned,
            ..
        }
    ));
    assert!(children[0].path.exists());

    h.db.mark_workspace_lease_uncertain(
        h.orch.session_id(),
        h.orch.agent_instance_id(),
        children[1].lease.workspace_lease_id,
        children[1].lease.revision,
        crate::db::workspace_lease_artifacts::WorkspaceLeaseTerminalReason::RestartUncertain,
        h.now + 3,
    )
    .await
    .unwrap();
    let outcome = h.orch.cleanup_child(&children[1], h.now + 4).await.unwrap();
    assert!(matches!(
        outcome,
        super::lifecycle::CleanupOutcome::Denied {
            reason: super::lifecycle::CleanupDenial::Uncertain,
            ..
        }
    ));
    assert!(children[1].path.exists());

    let src = include_str!("capability.rs");
    assert!(
        !src.contains("git::worktree_remove("),
        "orchestration must not call forced worktree_remove"
    );
    let life = include_str!("lifecycle.rs");
    assert!(
        !life.contains("git::worktree_remove("),
        "lifecycle must not call forced worktree_remove"
    );
}

#[tokio::test]
async fn conflict_specialist_cannot_read_primary_or_sibling() {
    let mut h = harness().await;
    let children = h
        .orch
        .fan_out(
            vec![
                FanOutSpec {
                    label: "spec".into(),
                },
                FanOutSpec {
                    label: "sib".into(),
                },
            ],
            h.now,
        )
        .await
        .unwrap();
    let specialist = h.orch.issue_conflict_specialist(h.now + 1).await.unwrap();
    let err = specialist
        .read_path(&h.repo.join("a.txt"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("outside integration lease"), "{err}");
    let err = specialist
        .read_path(&children[1].path.join("a.txt"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("outside integration lease"), "{err}");
    specialist
        .read_path(&specialist.lease().visibility_root.join("a.txt"))
        .unwrap();
    super::capability::assert_not_force_removing(include_str!("capability.rs")).unwrap();
}

#[tokio::test]
async fn parent_surfaces_artifacts_without_child_transcripts() {
    let mut h = harness().await;
    let children = h
        .orch
        .fan_out(vec![FanOutSpec { label: "a".into() }], h.now)
        .await
        .unwrap();
    write_uncommitted(&children[0].path, "a.txt", "a1\n");
    h.orch
        .produce_from_child(&children[0], h.now + 1, WorkspaceDigest::of(b"v"))
        .await
        .unwrap();
    let visible = h.orch.surface_for_parent().await.unwrap();
    assert_eq!(visible.len(), 1);
    assert!(!visible[0].touched_paths.is_empty());
    super::artifact::assert_no_transcripts(&visible).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn rust_validation_uses_wrapper_and_restores_receipt() {
    let h = harness().await;
    let log = h.state.join("cargo.log");
    let shim = cargo_shim(&h.state, &log);
    let mut validation = CandidateValidation::for_primary(&h.repo).with_locks(
        h.orch.lock_manager().clone(),
        h.orch.lock_identity().to_string(),
        h.orch.session_id(),
    );
    validation.cargo_bin = shim;
    let before = git::byte_identical_receipt(&h.repo).unwrap();
    let mut overlay = BTreeMap::new();
    overlay.insert(PathBuf::from("a.txt"), b"overlay\n".to_vec());
    let evidence = validation
        .validate_overlay(&overlay, &["test", "--offline"])
        .await
        .unwrap();
    assert_eq!(evidence.wrapper, wt_test_wrapper_path());
    assert!(evidence.restored);
    assert_eq!(evidence.exit_code, 0);
    assert_eq!(git::byte_identical_receipt(&h.repo).unwrap(), before);
    assert_eq!(
        std::fs::read_to_string(h.repo.join("a.txt")).unwrap(),
        "a0\n"
    );
    let logged = std::fs::read_to_string(&log).unwrap();
    assert!(logged.contains("test --offline"), "{logged}");
}

#[cfg(unix)]
#[tokio::test]
async fn worker_worktrees_never_invoke_cargo() {
    let mut h = harness().await;
    let children = h
        .orch
        .fan_out(
            vec![FanOutSpec {
                label: "worker".into(),
            }],
            h.now,
        )
        .await
        .unwrap();
    let err = worker_must_not_invoke_cargo(&children[0].path)
        .unwrap_err()
        .to_string();
    assert!(err.contains("must not invoke cargo"), "{err}");

    let log = h.state.join("worker-cargo.log");
    let shim = cargo_shim(&h.state, &log);
    let mut validation = CandidateValidation::for_primary(&children[0].path).with_locks(
        h.orch.lock_manager().clone(),
        h.orch.lock_identity().to_string(),
        h.orch.session_id(),
    );
    validation.cargo_bin = shim;
    let mut overlay = BTreeMap::new();
    overlay.insert(PathBuf::from("a.txt"), b"x\n".to_vec());
    let err = validation
        .validate_overlay(&overlay, &["test"])
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("must not invoke cargo"), "{err}");
    assert!(
        !log.exists() || std::fs::read_to_string(&log).unwrap().is_empty(),
        "worker worktree invoked cargo"
    );

    let output = std::process::Command::new(wt_test_wrapper_path())
        .current_dir(&children[0].path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("managed worktree"), "{stderr}");
}

#[tokio::test]
async fn candidate_validation_requires_lock_manager_and_serializes_affected_paths() {
    let h = harness().await;
    let mut overlay = BTreeMap::new();
    overlay.insert(PathBuf::from("a.txt"), b"overlay\n".to_vec());
    let unlocked = CandidateValidation::for_primary(&h.repo);
    let err = unlocked
        .validate_overlay(&overlay, &["test", "--offline"])
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("LockManager"),
        "unlocked validation must fail closed: {err}"
    );

    let before = git::byte_identical_receipt(&h.repo).unwrap();
    h.orch
        .lock_manager()
        .acquire(&h.repo.join("a.txt"), "writer", h.orch.session_id())
        .await
        .unwrap();
    let mut validation = CandidateValidation::for_primary(&h.repo).with_locks(
        h.orch.lock_manager().clone(),
        h.orch.lock_identity().to_string(),
        h.orch.session_id(),
    );
    validation.cargo_bin = PathBuf::from("true");
    let err = validation
        .validate_overlay(&overlay, &["test", "--offline"])
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("held by") || err.contains("lock"),
        "validation must serialize on LockManager paths: {err}"
    );
    let after = git::byte_identical_receipt(&h.repo).unwrap();
    assert_eq!(
        after, before,
        "a lock-conflicted validation must not overlay the primary tree"
    );
    assert_eq!(
        std::fs::read_to_string(h.repo.join("a.txt")).unwrap(),
        "a0\n"
    );
}

#[cfg(unix)]
fn wait_deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(5)
}

#[cfg(unix)]
#[tokio::test]
async fn dropped_overlay_validation_restores_receipt_and_releases_exclusive_hold() {
    let h = harness().await;
    let mut validation = CandidateValidation::for_primary(&h.repo).with_locks(
        h.orch.lock_manager().clone(),
        h.orch.lock_identity().to_string(),
        h.orch.session_id(),
    );
    validation.wrapper = PathBuf::from("sleep");
    let mut overlay = BTreeMap::new();
    overlay.insert(PathBuf::from("a.txt"), b"overlay\n".to_vec());
    let file = h.repo.join("a.txt");
    let join = tokio::spawn(async move { validation.validate_overlay(&overlay, &["60"]).await });

    let deadline = wait_deadline();
    while std::fs::read_to_string(&file).unwrap() != "overlay\n" {
        assert!(
            deadline
                .checked_duration_since(std::time::Instant::now())
                .is_some(),
            "overlay was never applied before the validation future was dropped"
        );
        tokio::task::yield_now().await;
    }

    join.abort();
    let _ = join.await;
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "a0\n",
        "dropping validate_overlay after apply must restore the prevalidation tree"
    );
    assert!(
        h.orch.lock_manager().holder(&h.repo).is_none(),
        "dropping validate_overlay must release the repository-root exclusive lock"
    );
    assert!(
        h.orch.lock_manager().holder(&file).is_none(),
        "dropping validate_overlay must release affected-path exclusive locks"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn dropped_patch_validation_restores_receipt_and_releases_exclusive_hold() {
    let h = harness().await;
    write_uncommitted(&h.repo, "a.txt", "candidate\n");
    let patch = git::capture_uncommitted_patch(&h.repo).unwrap();
    write_uncommitted(&h.repo, "a.txt", "a0\n");
    let mut validation = CandidateValidation::for_primary(&h.repo).with_locks(
        h.orch.lock_manager().clone(),
        h.orch.lock_identity().to_string(),
        h.orch.session_id(),
    );
    validation.wrapper = PathBuf::from("sleep");
    let file = h.repo.join("a.txt");
    let join = tokio::spawn(async move { validation.validate_patch(&patch, &["60"]).await });

    let deadline = wait_deadline();
    while std::fs::read_to_string(&file).unwrap() != "candidate\n" {
        assert!(
            deadline
                .checked_duration_since(std::time::Instant::now())
                .is_some(),
            "candidate patch was never applied before the validation future was dropped"
        );
        tokio::task::yield_now().await;
    }

    join.abort();
    let _ = join.await;
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "a0\n",
        "dropping validate_patch after apply must reverse the candidate"
    );
    assert!(
        h.orch.lock_manager().holder(&h.repo).is_none(),
        "dropping validate_patch must release the repository-root exclusive lock"
    );
    assert!(
        h.orch.lock_manager().holder(&file).is_none(),
        "dropping validate_patch must release affected-path exclusive locks"
    );
}

/// Wrapper that plants a SIGTERM-ignoring descendant writing `target`.
/// PID-only `kill_on_drop` leaves that writer alive after restore.
///
/// Overlay restore is `std::fs::write` of captured bytes, so `target` may be
/// the overlaid path: restore still succeeds, and a later overwrite fails the
/// stickiness check. That overlay twin is the canonical kill-before-restore
/// proof for a restore primitive that can clobber dirty contents.
#[cfg(unix)]
fn descendant_mutator_script(target: &Path, ready: &Path) -> String {
    format!(
        "trap '' TERM\n( trap '' TERM; while true; do printf 'dirty\\n' > '{}'; sleep 0.05; done ) &\ntouch '{}'\nsleep 60",
        target.display(),
        ready.display()
    )
}

/// Same SIGTERM-ignoring descendant, but it overwrites `target` only once that
/// path already matches `expected` (the prevalidation bytes).
///
/// Production patch restore is `git apply --reverse` and needs `target` to
/// still match the candidate. A continuous overwrite would fail reverse-apply
/// even after group SIGKILL-and-wait, so this defers mutation until restore
/// has rewritten the file. If descendants survive until then, they dirty
/// `target` and the stickiness check fails — including under PID-only
/// `kill_on_drop` and restore-before-kill Drop order.
#[cfg(unix)]
fn descendant_post_restore_mutator_script(
    target: &Path,
    expected: &Path,
    heartbeat: &Path,
    ready: &Path,
) -> String {
    format!(
        "trap '' TERM\n( trap '' TERM; while true; do printf 'dirty\\n' > '{heartbeat}'; if cmp -s '{target}' '{expected}'; then printf 'dirty\\n' > '{target}'; fi; sleep 0.05; done ) &\ntouch '{ready}'\nsleep 60",
        heartbeat = heartbeat.display(),
        target = target.display(),
        expected = expected.display(),
        ready = ready.display(),
    )
}

#[cfg(unix)]
async fn wait_for_path(path: &Path) {
    let deadline = wait_deadline();
    while !path.exists() {
        assert!(
            deadline
                .checked_duration_since(std::time::Instant::now())
                .is_some(),
            "timed out waiting for {}",
            path.display()
        );
        tokio::task::yield_now().await;
    }
}

#[cfg(unix)]
async fn assert_restored_and_descendants_dead(file: &Path, expected: &str, message: &str) {
    assert_eq!(
        std::fs::read_to_string(file).unwrap(),
        expected,
        "{message}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        std::fs::read_to_string(file).unwrap(),
        expected,
        "wrapper descendants kept mutating after restore and exclusive-lock release"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn dropped_overlay_validation_kills_wrapper_descendants_before_restore() {
    let h = harness().await;
    let file = h.repo.join("a.txt");
    let ready = h.repo.join("wrapper-ready");
    let script = descendant_mutator_script(&file, &ready);
    let mut validation = CandidateValidation::for_primary(&h.repo).with_locks(
        h.orch.lock_manager().clone(),
        h.orch.lock_identity().to_string(),
        h.orch.session_id(),
    );
    validation.wrapper = PathBuf::from("sh");
    let mut overlay = BTreeMap::new();
    overlay.insert(PathBuf::from("a.txt"), b"overlay\n".to_vec());
    let join = tokio::spawn(async move {
        validation
            .validate_overlay(&overlay, &["-c", &script])
            .await
    });

    wait_for_path(&ready).await;
    join.abort();
    let _ = join.await;
    assert_restored_and_descendants_dead(
        &file,
        "a0\n",
        "dropping validate_overlay must restore the prevalidation tree after killing wrapper descendants",
    )
    .await;
    assert!(
        h.orch.lock_manager().holder(&h.repo).is_none(),
        "dropping validate_overlay must release the repository-root exclusive lock"
    );
    assert!(
        h.orch.lock_manager().holder(&file).is_none(),
        "dropping validate_overlay must release affected-path exclusive locks"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn dropped_patch_validation_kills_wrapper_descendants_before_restore() {
    let h = harness().await;
    write_uncommitted(&h.repo, "a.txt", "candidate\n");
    let patch = git::capture_uncommitted_patch(&h.repo).unwrap();
    write_uncommitted(&h.repo, "a.txt", "a0\n");
    let file = h.repo.join("a.txt");
    let heartbeat = h.repo.join("wrapper-heartbeat");
    let ready = h.repo.join("wrapper-ready");
    // Compare-target lives outside the repo so reverse-apply never sees it.
    let expected = h.repo.parent().unwrap().join("wrapper-restored-expected");
    std::fs::write(&expected, "a0\n").unwrap();
    let script = descendant_post_restore_mutator_script(&file, &expected, &heartbeat, &ready);
    let mut validation = CandidateValidation::for_primary(&h.repo).with_locks(
        h.orch.lock_manager().clone(),
        h.orch.lock_identity().to_string(),
        h.orch.session_id(),
    );
    validation.wrapper = PathBuf::from("sh");
    let join =
        tokio::spawn(async move { validation.validate_patch(&patch, &["-c", &script]).await });

    wait_for_path(&ready).await;
    wait_for_path(&heartbeat).await;
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "candidate\n",
        "patched path must still match the applied candidate so reverse-apply can restore"
    );
    join.abort();
    let _ = join.await;
    assert_restored_and_descendants_dead(
        &file,
        "a0\n",
        "dropping validate_patch must reverse the candidate after killing wrapper descendants",
    )
    .await;
    assert!(
        h.orch.lock_manager().holder(&h.repo).is_none(),
        "dropping validate_patch must release the repository-root exclusive lock"
    );
    assert!(
        h.orch.lock_manager().holder(&file).is_none(),
        "dropping validate_patch must release affected-path exclusive locks"
    );
}

#[test]
fn orchestration_actions_are_the_optional_capability_set() {
    let _ = OrchestrationCapability;
    assert_eq!(
        OrchestrationAction::parse("edit_in_place").unwrap(),
        OrchestrationAction::EditInPlace
    );
    assert_eq!(
        OrchestrationAction::parse("fan_out").unwrap(),
        OrchestrationAction::FanOut
    );
    assert_eq!(
        OrchestrationAction::parse("merge_selected").unwrap(),
        OrchestrationAction::MergeSelected
    );
    assert_eq!(
        OrchestrationAction::parse("apply_uncommitted").unwrap(),
        OrchestrationAction::ApplyUncommitted
    );
}

#[test]
fn managed_worktree_kind_is_required_for_fan_out_paths() {
    let tmp = TempDir::new().unwrap();
    let id = Uuid::new_v4();
    let path = workspace_lease::managed_worktree_path(tmp.path(), id);
    std::fs::create_dir_all(&path).unwrap();
    let lease = WorkspaceLease::ephemeral(
        WorkspaceLeaseKind::ManagedWorktree,
        path.clone(),
        WorkspaceLeaseOps::for_coding(),
        workspace_lease::now_unix_ms() + 60_000,
    );
    assert!(lease.covers_path(&path.join("x")));
    assert!(!lease.covers_path(&tmp.path().join("repo/x")));
}

#[test]
fn produce_and_integrate_hash_the_same_path_identity_on_a_clean_target() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    init_repo(&repo);

    let pre = super::receipt::preconditions_for_paths(&repo, &["a.txt".into()], &[]).unwrap();
    assert_eq!(
        pre.touched_manifest_digest,
        super::receipt::live_manifest(&repo, &["a.txt".into()]).unwrap(),
        "HEAD snapshot of an existing file must equal the live worktree hash on a clean target"
    );

    let pre_new =
        super::receipt::preconditions_for_paths(&repo, &[], &["fresh.txt".into()]).unwrap();
    assert_eq!(
        pre_new.untracked_manifest_digest,
        super::receipt::live_manifest(&repo, &["fresh.txt".into()]).unwrap(),
        "a path absent from HEAD must equal the live hash while the target also lacks it"
    );

    write_uncommitted(&repo, "a.txt", "target-dirty\n");
    assert_ne!(
        pre.touched_manifest_digest,
        super::receipt::live_manifest(&repo, &["a.txt".into()]).unwrap()
    );
}

#[test]
fn produce_and_integrate_hash_the_same_path_identity_for_a_clean_executable_blob() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    init_repo(&repo);
    std::fs::write(repo.join("tool.sh"), "#!/bin/sh\n").unwrap();
    git::run_git_checked(&repo, &["add", "--", "tool.sh"]).unwrap();
    git::run_git_checked(&repo, &["update-index", "--chmod=+x", "--", "tool.sh"]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(repo.join("tool.sh"))
            .unwrap()
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(repo.join("tool.sh"), perms).unwrap();
    }
    git::run_git_checked(&repo, &["commit", "-q", "-m", "exec"]).unwrap();

    let pre = super::receipt::preconditions_for_paths(&repo, &["tool.sh".into()], &[]).unwrap();
    assert_eq!(
        pre.touched_manifest_digest,
        super::receipt::live_manifest(&repo, &["tool.sh".into()]).unwrap(),
        "HEAD snapshot of a 100755 blob must equal the live worktree hash on a clean target"
    );
}

#[test]
fn newline_paths_use_nul_framed_artifact_manifests() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    init_repo(&repo);
    let unusual = "line\nbreak.rs";
    std::fs::write(repo.join(unusual), "fn changed() {}\n").unwrap();

    let patch = git::capture_uncommitted_patch(&repo).unwrap();
    assert_eq!(patch.untracked_paths, vec![unusual.to_owned()]);
    assert!(patch.touched_paths.contains(&unusual.to_owned()));

    let digest =
        crate::worktree_orchestration::receipt::live_manifest(&repo, &patch.touched_paths).unwrap();
    assert_ne!(digest, WorkspaceDigest::of(b""));
}
