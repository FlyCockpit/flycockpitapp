//! Retain, pin, cleanup, and recovery for managed worktrees.

use std::path::Path;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db::Db;
use crate::db::workspace_lease_artifacts::{
    LeaseCasOutcome, WorkspaceLeaseRow, WorkspaceLeaseState, WorkspaceLeaseTerminalReason,
};
use crate::git;
use crate::workspace_lease;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupDenial {
    Pinned,
    Uncertain,
    Dirty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupOutcome {
    Cleaned(WorkspaceLeaseRow),
    Denied {
        reason: CleanupDenial,
        row: WorkspaceLeaseRow,
    },
}

pub async fn pin_managed_worktree(
    db: &Db,
    session: Uuid,
    agent: Uuid,
    lease_id: Uuid,
    expected_revision: i64,
    now_ms: i64,
) -> Result<WorkspaceLeaseRow> {
    match db
        .pin_workspace_lease(session, agent, lease_id, expected_revision, now_ms)
        .await
        .context("pinning managed worktree")?
    {
        LeaseCasOutcome::Transitioned(row) | LeaseCasOutcome::AlreadyTerminal(row) => Ok(row),
        LeaseCasOutcome::RevisionConflict => {
            bail!("pin raced a concurrent workspace-lease revision")
        }
    }
}

/// Grace-retain: leave the path in place. Never force-deletes.
pub fn retain_managed_worktree(lease: &WorkspaceLeaseRow) {
    tracing::debug!(
        lease = %lease.workspace_lease_id,
        path = %lease.managed_path,
        "retaining managed worktree"
    );
}

/// Host-authorized cleanup. Refuses pinned and uncertain trees and never
/// calls the forced `worktree_remove` helper.
///
/// `cleaning` is an exclusive filesystem-deletion claim. Process death
/// recovery releases it back to `grace`; this function also resumes an
/// already-`cleaning` row so operator cleanup and a cancelled/timed-out
/// cleaner have a matching exit. Pin still refuses `Cleaning`.
pub async fn cleanup_managed_worktree(
    db: &Db,
    session: Uuid,
    agent: Uuid,
    lease_id: Uuid,
    expected_revision: i64,
    now_ms: i64,
    primary_repo: &Path,
    cancel: Option<&CancellationToken>,
) -> Result<CleanupOutcome> {
    let Some(row) = db.workspace_lease(session, agent, lease_id).await? else {
        bail!("workspace lease `{lease_id}` is not owned");
    };
    if row.pinned_at_unix_ms.is_some() {
        return Ok(CleanupOutcome::Denied {
            reason: CleanupDenial::Pinned,
            row,
        });
    }
    if row.state == WorkspaceLeaseState::Uncertain {
        return Ok(CleanupOutcome::Denied {
            reason: CleanupDenial::Uncertain,
            row,
        });
    }
    let mut row = row;
    let mut revision = expected_revision;
    if row.state == WorkspaceLeaseState::Cleaning {
        if row.revision != expected_revision {
            bail!("cleanup raced a concurrent workspace-lease revision");
        }
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            return release_cancelled_cleanup(db, session, agent, lease_id, revision, now_ms).await;
        }
    } else {
        if row.state == WorkspaceLeaseState::Active {
            if row.expires_at_unix_ms > now_ms {
                bail!(
                    "workspace lease `{}` is still live; wait for grace before cleanup",
                    lease_id
                );
            }
            match db
                .expire_workspace_lease(session, agent, lease_id, revision, now_ms)
                .await
                .context("expiring workspace lease before cleanup")?
            {
                LeaseCasOutcome::Transitioned(updated) => {
                    revision = updated.revision;
                    row = updated;
                }
                LeaseCasOutcome::AlreadyTerminal(updated) => {
                    return Ok(CleanupOutcome::Cleaned(updated));
                }
                LeaseCasOutcome::RevisionConflict => {
                    bail!("expire raced a concurrent workspace-lease revision")
                }
            }
        }
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            bail!("managed worktree cleanup was cancelled before claiming the exclusive deletion");
        }
        // Claim the lifecycle revision *before* examining/removing filesystem
        // state. A pin that arrives after this CAS is refused, while one that won
        // before it leaves `row` stale and prevents removal.
        match db
            .claim_workspace_lease_cleanup(session, agent, lease_id, revision, now_ms)
            .await
            .context("claiming managed worktree cleanup")?
        {
            LeaseCasOutcome::Transitioned(updated) => {
                revision = updated.revision;
                row = updated;
            }
            LeaseCasOutcome::AlreadyTerminal(updated) => {
                return Ok(CleanupOutcome::Cleaned(updated));
            }
            LeaseCasOutcome::RevisionConflict => {
                bail!("cleanup raced a concurrent workspace-lease revision")
            }
        }
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            return release_cancelled_cleanup(db, session, agent, lease_id, revision, now_ms).await;
        }
    }
    let managed = Path::new(&row.managed_path);
    // Rebuild from the row we are about to clean, rather than trusting a
    // check performed during startup or an earlier lifecycle transition. A
    // missing path is not evidence that its private ref is safe to delete:
    // it may be a partial checkout, a replaced mount, or an interrupted host
    // operation. Prove the full disk identity before *either* cleanup effect.
    let lease = workspace_lease::WorkspaceLease::from_row(&row)?;
    if !lease.identity_matches_disk() {
        let ambiguity = if managed.exists() {
            WorkspaceLeaseTerminalReason::IdentityMismatch
        } else {
            WorkspaceLeaseTerminalReason::MissingManagedPath
        };
        let retained = match db
            .mark_workspace_lease_uncertain(session, agent, lease_id, revision, ambiguity, now_ms)
            .await
            .context("retaining managed worktree without an identity proof")?
        {
            LeaseCasOutcome::Transitioned(updated) | LeaseCasOutcome::AlreadyTerminal(updated) => {
                updated
            }
            // A concurrent lifecycle owner may have changed the row, but
            // cleanup still must retain its private ref and on-disk path.
            LeaseCasOutcome::RevisionConflict => row,
        };
        return Ok(CleanupOutcome::Denied {
            reason: CleanupDenial::Uncertain,
            row: retained,
        });
    }
    if cancel.is_some_and(CancellationToken::is_cancelled) {
        return release_cancelled_cleanup(db, session, agent, lease_id, revision, now_ms).await;
    }
    match git::worktree_remove_clean(primary_repo, managed) {
        Ok(()) => {}
        Err(error) => {
            tracing::debug!(%error, "clean worktree remove refused; not forcing");
            let released = match db
                .release_workspace_lease_cleanup(session, agent, lease_id, revision, now_ms)
                .await
                .context("releasing refused managed-worktree cleanup claim")?
            {
                LeaseCasOutcome::Transitioned(updated)
                | LeaseCasOutcome::AlreadyTerminal(updated) => updated,
                LeaseCasOutcome::RevisionConflict => db
                    .workspace_lease(session, agent, lease_id)
                    .await?
                    .context("workspace lease disappeared while releasing cleanup claim")?,
            };
            return Ok(CleanupOutcome::Denied {
                reason: if released.state == WorkspaceLeaseState::Uncertain {
                    CleanupDenial::Uncertain
                } else {
                    CleanupDenial::Dirty
                },
                row: released,
            });
        }
    }
    // A linked worktree owns a private local branch.  `git worktree remove`
    // deliberately leaves that branch behind, so deleting only the directory
    // leaks `refs/heads/cockpit-lease/<id>` and makes a future UUID collision
    // fail mysteriously.  This deletion is part of cleanup's durable effect:
    // if it cannot be proven, retain the lifecycle row as uncertain rather
    // than claiming the lease is cleaned.
    let branch = format!("cockpit-lease/{lease_id}");
    if let Err(error) = git::branch_delete(primary_repo, &branch) {
        let retained = match db
            .mark_workspace_lease_uncertain(
                session,
                agent,
                lease_id,
                revision,
                WorkspaceLeaseTerminalReason::RestartUncertain,
                now_ms,
            )
            .await
            .context("retaining worktree after private ref cleanup failure")?
        {
            LeaseCasOutcome::Transitioned(updated) | LeaseCasOutcome::AlreadyTerminal(updated) => {
                updated
            }
            LeaseCasOutcome::RevisionConflict => row,
        };
        tracing::warn!(%error, %branch, "managed worktree removed but private ref cleanup failed");
        return Ok(CleanupOutcome::Denied {
            reason: CleanupDenial::Uncertain,
            row: retained,
        });
    }
    match db
        .clean_workspace_lease(session, agent, lease_id, revision, true, now_ms)
        .await
        .context("marking workspace lease cleaned")?
    {
        LeaseCasOutcome::Transitioned(updated) => Ok(CleanupOutcome::Cleaned(updated)),
        LeaseCasOutcome::AlreadyTerminal(updated) => Ok(CleanupOutcome::Cleaned(updated)),
        LeaseCasOutcome::RevisionConflict => {
            bail!("cleanup raced a concurrent workspace-lease revision")
        }
    }
}

async fn release_cancelled_cleanup(
    db: &Db,
    session: Uuid,
    agent: Uuid,
    lease_id: Uuid,
    revision: i64,
    now_ms: i64,
) -> Result<CleanupOutcome> {
    let released = match db
        .release_workspace_lease_cleanup(session, agent, lease_id, revision, now_ms)
        .await
        .context("releasing cancelled managed-worktree cleanup claim")?
    {
        LeaseCasOutcome::Transitioned(updated) | LeaseCasOutcome::AlreadyTerminal(updated) => {
            updated
        }
        LeaseCasOutcome::RevisionConflict => db
            .workspace_lease(session, agent, lease_id)
            .await?
            .context("workspace lease disappeared while releasing cancelled cleanup claim")?,
    };
    Ok(CleanupOutcome::Denied {
        reason: if released.state == WorkspaceLeaseState::Uncertain {
            CleanupDenial::Uncertain
        } else {
            CleanupDenial::Dirty
        },
        row: released,
    })
}

pub async fn recover_managed_worktrees(
    db: &Db,
    session: Uuid,
    now_ms: i64,
) -> Result<Vec<WorkspaceLeaseRow>> {
    workspace_lease::recover_session_workspace_leases(db, session, now_ms).await
}
