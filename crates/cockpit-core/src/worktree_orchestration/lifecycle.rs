//! Retain, pin, cleanup, and recovery for managed worktrees.

use std::path::Path;

use anyhow::{Context, Result, bail};
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
pub async fn cleanup_managed_worktree(
    db: &Db,
    session: Uuid,
    agent: Uuid,
    lease_id: Uuid,
    expected_revision: i64,
    now_ms: i64,
    primary_repo: &Path,
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
    let managed = Path::new(&row.managed_path);
    if managed.exists() {
        // Rebuild from the row we are about to clean, rather than trusting a
        // check performed during startup or an earlier lifecycle transition.
        // A clean linked worktree can be replaced between those points.
        let lease = workspace_lease::WorkspaceLease::from_row(&row)?;
        if !lease.identity_matches_disk() {
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
                .context("retaining identity-mismatched managed worktree")?
            {
                LeaseCasOutcome::Transitioned(updated)
                | LeaseCasOutcome::AlreadyTerminal(updated) => updated,
                // A concurrent lifecycle owner may have changed the row, but
                // cleanup still must retain the on-disk path.
                LeaseCasOutcome::RevisionConflict => row,
            };
            return Ok(CleanupOutcome::Denied {
                reason: CleanupDenial::Uncertain,
                row: retained,
            });
        }
        match git::worktree_remove_clean(primary_repo, managed) {
            Ok(()) => {}
            Err(error) => {
                tracing::debug!(%error, "clean worktree remove refused; not forcing");
                return Ok(CleanupOutcome::Denied {
                    reason: CleanupDenial::Dirty,
                    row,
                });
            }
        }
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

pub async fn recover_managed_worktrees(
    db: &Db,
    session: Uuid,
    now_ms: i64,
) -> Result<Vec<WorkspaceLeaseRow>> {
    workspace_lease::recover_session_workspace_leases(db, session, now_ms).await
}
