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
    TaskArtifactState, WorkspaceDigest, WorkspaceLeaseState,
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
    let locks = Arc::new(LockManager::in_memory(db.clone()));
    let orch = WorktreeOrchestrator::new(OrchestratorInit {
        db: db.clone(),
        locks,
        state_dir: state.clone(),
        session_id: session.session_id,
        agent_instance_id: agent.agent_instance_id,
        lock_identity: "orchestrator".into(),
        primary_repo: repo.clone(),
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
                .fanout_receipt(child.lease.workspace_lease_id)
                .unwrap(),
            child.base_receipt,
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
async fn dirty_unrelated_target_is_left_untouched() {
    let mut h = harness().await;
    std::fs::write(h.repo.join("dirt.txt"), "stay\n").unwrap();
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
    let lease = WorkspaceLease::from_row(&children[0].lease).unwrap();
    let specialist = h.orch.conflict_specialist_for(lease);
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
        .read_path(&children[0].path.join("a.txt"))
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
    let mut validation = CandidateValidation::for_primary(&h.repo);
    validation.cargo_bin = shim;
    let before = git::byte_identical_receipt(&h.repo).unwrap();
    let mut overlay = BTreeMap::new();
    overlay.insert(PathBuf::from("a.txt"), b"overlay\n".to_vec());
    let evidence = validation
        .validate_overlay(&overlay, &["test", "--offline"])
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
    let mut validation = CandidateValidation::for_primary(&children[0].path);
    validation.cargo_bin = shim;
    let mut overlay = BTreeMap::new();
    overlay.insert(PathBuf::from("a.txt"), b"x\n".to_vec());
    let err = validation
        .validate_overlay(&overlay, &["test"])
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
    assert!(!lease.covers_path(tmp.path().join("repo/x")));
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
