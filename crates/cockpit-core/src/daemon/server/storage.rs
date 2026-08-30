//! Daemon-owned storage accounting and cleanup plans.
//!
//! The UI receives measurements and single-use preview ids only. It never gets
//! a path-shaped deletion API or a direct SQLite handle.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use uuid::Uuid;

use super::{DaemonContext, ErrorCode, ErrorPayload, Response, internal};

const MANAGEMENT_HINT_BYTES: u64 = 512 * 1024 * 1024;
const PREVIEW_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
struct StoredPreview {
    preview: cockpit_proto::StorageCleanupPreview,
    orphan_paths: Vec<PathBuf>,
    issued_at: Instant,
}

static PREVIEWS: OnceLock<Mutex<HashMap<Uuid, StoredPreview>>> = OnceLock::new();

fn previews() -> &'static Mutex<HashMap<Uuid, StoredPreview>> {
    PREVIEWS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) async fn report(ctx: &DaemonContext) -> Result<Response, ErrorPayload> {
    let (categories, orphaned_workspace_storage) = collect_usage(ctx).map_err(internal)?;
    let total_bytes = categories.iter().fold(0_u64, |total, category| {
        total.saturating_add(category.total_bytes)
    });
    let hint_seen = ctx
        .db
        .app_flag_seen("storage-management-hint")
        .await
        .map_err(internal)?;
    Ok(Response::StorageReport {
        total_bytes,
        categories,
        orphaned_workspace_storage,
        show_management_hint: total_bytes > MANAGEMENT_HINT_BYTES && !hint_seen,
    })
}

pub(super) async fn preview(
    ctx: &DaemonContext,
    target: cockpit_proto::StorageCleanupTarget,
) -> Result<Response, ErrorPayload> {
    let (items, bytes_to_free, orphan_paths) = preview_target(ctx, &target).await?;
    let preview = cockpit_proto::StorageCleanupPreview {
        preview_id: Uuid::new_v4(),
        target,
        items,
        bytes_to_free,
    };
    let preview_id = preview.preview_id;
    let mut plans = previews()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    plans.retain(|_, plan| plan.issued_at.elapsed() <= PREVIEW_TTL);
    plans.insert(
        preview_id,
        StoredPreview {
            preview: preview.clone(),
            orphan_paths,
            issued_at: Instant::now(),
        },
    );
    Ok(Response::StorageCleanupPreview { preview })
}

pub(super) async fn execute(
    ctx: &DaemonContext,
    preview_id: Uuid,
) -> Result<Response, ErrorPayload> {
    let plan = {
        let mut plans = previews()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(plan) = plans.remove(&preview_id) else {
            return Err(invalid_preview());
        };
        if plan.issued_at.elapsed() > PREVIEW_TTL {
            return Err(invalid_preview());
        }
        plan
    };

    match &plan.preview.target {
        cockpit_proto::StorageCleanupTarget::ArchiveSessionsOlderThan { .. } => {
            for item in &plan.preview.items {
                let session_id = Uuid::parse_str(&item.label).map_err(|_| {
                    internal(anyhow::anyhow!(
                        "storage preview contains invalid session id"
                    ))
                })?;
                super::sessions::archive_session(ctx, session_id, false).await?;
            }
        }
        cockpit_proto::StorageCleanupTarget::PermanentlyDeleteSessions { .. } => {
            for item in &plan.preview.items {
                let session_id = Uuid::parse_str(&item.label).map_err(|_| {
                    internal(anyhow::anyhow!(
                        "storage preview contains invalid session id"
                    ))
                })?;
                super::sessions::delete_session(ctx, session_id).await?;
            }
        }
        cockpit_proto::StorageCleanupTarget::RemoveOrphanedWorkspaceStorage { .. } => {
            for path in &plan.orphan_paths {
                remove_previewed_directory(path).map_err(internal)?;
            }
        }
    }
    Ok(Response::StorageCleanupCompleted {
        bytes_freed: plan.preview.bytes_to_free,
    })
}

fn invalid_preview() -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Conflict,
        message: "storage cleanup preview is missing or expired; preview again before deleting"
            .into(),
    }
}

async fn preview_target(
    ctx: &DaemonContext,
    target: &cockpit_proto::StorageCleanupTarget,
) -> Result<(Vec<cockpit_proto::StorageCleanupItem>, u64, Vec<PathBuf>), ErrorPayload> {
    match target {
        cockpit_proto::StorageCleanupTarget::ArchiveSessionsOlderThan {
            age_days,
            include_renamed_or_pinned,
        } => {
            ensure!(*age_days > 0, "storage archive age must be positive").map_err(internal)?;
            let cutoff = chrono::Utc::now()
                .timestamp_millis()
                .saturating_sub(i64::from(*age_days).saturating_mul(24 * 60 * 60 * 1_000));
            let candidates = ctx
                .db
                .storage_sessions_older_than(cutoff, *include_renamed_or_pinned)
                .await
                .map_err(internal)?;
            let items = candidates
                .into_iter()
                .map(|candidate| cockpit_proto::StorageCleanupItem {
                    // Session id is opaque and is revalidated by the daemon at execution.
                    label: candidate.session_id.to_string(),
                    bytes: 0,
                    last_used_at_unix_ms: Some(candidate.last_active_at_unix_ms),
                })
                .collect();
            Ok((items, 0, Vec::new()))
        }
        cockpit_proto::StorageCleanupTarget::PermanentlyDeleteSessions { session_ids } => {
            let mut items = Vec::with_capacity(session_ids.len());
            let mut bytes_to_free = 0_u64;
            for session_id in session_ids {
                let Some(session) = ctx.db.get_session(*session_id).await.map_err(internal)? else {
                    return Err(ErrorPayload {
                        code: ErrorCode::UnknownSession,
                        message: format!("unknown session {session_id}"),
                    });
                };
                let scratch = crate::session::workspace_scratch_path_for_session(
                    &session.project_id,
                    *session_id,
                )
                .map_err(internal)?;
                let bytes = directory_bytes(&scratch).map_err(internal)?;
                bytes_to_free = bytes_to_free.saturating_add(bytes);
                items.push(cockpit_proto::StorageCleanupItem {
                    label: session_id.to_string(),
                    bytes,
                    last_used_at_unix_ms: Some(session.last_active_at_unix_ms),
                });
            }
            Ok((items, bytes_to_free, Vec::new()))
        }
        cockpit_proto::StorageCleanupTarget::RemoveOrphanedWorkspaceStorage { project_ids } => {
            let mut items = Vec::new();
            let mut bytes_to_free = 0_u64;
            let mut paths = Vec::new();
            for project_id in project_ids {
                let Some((root, last_used_at_unix_ms)) =
                    crate::session::workspace_storage_details_for_project_id(project_id)
                        .map_err(internal)?
                else {
                    continue;
                };
                // A missing path is only a suggestion. The preview makes the
                // condition explicit; execution is still user-confirmed.
                if root.exists() {
                    continue;
                }
                let workspace =
                    crate::session::workspace_dir_for_project_id(project_id).map_err(internal)?;
                let local_config =
                    cockpit_config::config::dirs::local_config_dir_for(&root).map_err(internal)?;
                let bytes = directory_bytes(&workspace)
                    .map_err(internal)?
                    .saturating_add(directory_bytes(&local_config).map_err(internal)?);
                bytes_to_free = bytes_to_free.saturating_add(bytes);
                items.push(cockpit_proto::StorageCleanupItem {
                    label: project_id.clone(),
                    bytes,
                    last_used_at_unix_ms: Some(last_used_at_unix_ms),
                });
                paths.extend([workspace, local_config]);
            }
            Ok((items, bytes_to_free, paths))
        }
    }
}

fn collect_usage(
    ctx: &DaemonContext,
) -> Result<(
    Vec<cockpit_proto::StorageCategoryUsage>,
    Vec<cockpit_proto::StorageCleanupItem>,
)> {
    let data_dir = cockpit_config::config::resolve::cockpit_data_dir()?;
    let state_dir = cockpit_config::config::resolve::cockpit_state_dir()?;
    let db_path = ctx
        .db
        .path()
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("cockpit.db"));
    let ledger_bytes = file_bytes(&db_path)
        .saturating_add(file_bytes(&PathBuf::from(format!(
            "{}-wal",
            db_path.display()
        ))))
        .saturating_add(file_bytes(&PathBuf::from(format!(
            "{}-shm",
            db_path.display()
        ))));
    let workspace_bytes = directory_bytes(&state_dir.join("workspaces"))?;
    let local_configs_bytes = directory_bytes(&data_dir.join("local-configs"))?;
    let entries = [
        (cockpit_proto::StorageCategory::Ledger, ledger_bytes, 0),
        (
            cockpit_proto::StorageCategory::WorkspaceScratch,
            workspace_bytes,
            0,
        ),
        (
            cockpit_proto::StorageCategory::LocalConfigs,
            local_configs_bytes,
            0,
        ),
        (
            cockpit_proto::StorageCategory::Worktrees,
            directory_bytes(&state_dir.join("worktrees"))?,
            0,
        ),
        (
            cockpit_proto::StorageCategory::TaskArtifacts,
            directory_bytes(&state_dir.join("task-artifacts"))?,
            0,
        ),
        (
            cockpit_proto::StorageCategory::ComputerCapture,
            directory_bytes(&state_dir.join("computer-capture"))?,
            0,
        ),
        (
            cockpit_proto::StorageCategory::ResultBlobs,
            directory_bytes(&state_dir.join("result-blobs"))?,
            0,
        ),
        (
            cockpit_proto::StorageCategory::SessionTmp,
            directory_bytes(&state_dir.join("tmp"))?,
            0,
        ),
    ];
    let mut categories: Vec<_> = entries
        .into_iter()
        .map(
            |(category, total_bytes, reclaimable_bytes)| cockpit_proto::StorageCategoryUsage {
                category,
                total_bytes,
                reclaimable_bytes,
            },
        )
        .collect();

    let mut orphans = Vec::new();
    let workspaces = state_dir.join("workspaces");
    if let Ok(entries) = std::fs::read_dir(workspaces) {
        for entry in entries.flatten() {
            let Some(project_id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some((root, last_used_at_unix_ms)) =
                crate::session::workspace_storage_details_for_project_id(&project_id)?
            else {
                continue;
            };
            if !root.exists() {
                let workspace_bytes = directory_bytes(&entry.path())?;
                let local_config = cockpit_config::config::dirs::local_config_dir_for(&root)?;
                let local_config_bytes = directory_bytes(&local_config)?;
                orphans.push(cockpit_proto::StorageCleanupItem {
                    label: project_id,
                    bytes: workspace_bytes.saturating_add(local_config_bytes),
                    last_used_at_unix_ms: Some(last_used_at_unix_ms),
                });
                for category in &mut categories {
                    match category.category {
                        cockpit_proto::StorageCategory::WorkspaceScratch => {
                            category.reclaimable_bytes =
                                category.reclaimable_bytes.saturating_add(workspace_bytes);
                        }
                        cockpit_proto::StorageCategory::LocalConfigs => {
                            category.reclaimable_bytes = category
                                .reclaimable_bytes
                                .saturating_add(local_config_bytes);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok((categories, orphans))
}

fn file_bytes(path: &Path) -> u64 {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

fn directory_bytes(path: &Path) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let mut bytes = 0_u64;
    for entry in walkdir::WalkDir::new(path).follow_links(false) {
        let entry = entry.with_context(|| format!("walking `{}`", path.display()))?;
        if entry.file_type().is_file() {
            bytes = bytes.saturating_add(entry.metadata()?.len());
        }
    }
    Ok(bytes)
}

fn remove_previewed_directory(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting `{}`", path.display()));
        }
    };
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "refusing to remove non-directory storage target `{}`",
        path.display()
    );
    std::fs::remove_dir_all(path).with_context(|| format!("removing `{}`", path.display()))
}
