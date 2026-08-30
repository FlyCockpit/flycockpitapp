//! Daemon-owned storage accounting and cleanup plans.
//!
//! The UI receives measurements and single-use preview ids only. It never gets
//! a path-shaped deletion API or a direct SQLite handle.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{DaemonContext, ErrorCode, ErrorPayload, Response, internal};

const MANAGEMENT_HINT_BYTES: u64 = 512 * 1024 * 1024;
const PREVIEW_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
struct StoredPreview {
    cleanup: CleanupPlan,
    issued_at: Instant,
}

/// The mutable objects that a preview authorizes. This never crosses the
/// protocol boundary: the wire preview stays presentation-only while the
/// daemon retains the identity snapshots needed to reject a stale execution.
#[derive(Clone)]
enum CleanupPlan {
    ArchiveSessions {
        candidates: Vec<crate::db::sessions::StorageSessionCandidate>,
        include_renamed_or_pinned: bool,
    },
    PermanentlyDeleteSessions {
        roots: Vec<Uuid>,
        candidates: Vec<crate::db::sessions::StorageSessionCandidate>,
        directories: Vec<DirectorySnapshot>,
    },
    RemoveOrphanedWorkspaceStorage {
        orphan_roots: Vec<PathBuf>,
        directories: Vec<DirectorySnapshot>,
    },
}

struct PreviewContents {
    items: Vec<cockpit_proto::StorageCleanupItem>,
    bytes_to_free: u64,
    cleanup: CleanupPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectorySnapshot {
    path: PathBuf,
    entries: Vec<DirectorySnapshotEntry>,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectorySnapshotEntry {
    relative_path: PathBuf,
    kind: DirectoryEntryKind,
    bytes: u64,
    modified: Option<std::time::SystemTime>,
    digest: Option<[u8; 32]>,
    symlink_target: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryEntryKind {
    Directory,
    File,
    Symlink,
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
    let hint_version = ctx
        .db
        .read(|conn| crate::db::Db::app_flag_version_conn(conn, "storage-management-hint"))
        .await
        .map_err(internal)?;
    Ok(Response::StorageReport {
        total_bytes,
        categories,
        orphaned_workspace_storage,
        show_management_hint: total_bytes > MANAGEMENT_HINT_BYTES && hint_version == 0,
        storage_management_hint_version: hint_version,
    })
}

pub(super) async fn preview(
    ctx: &DaemonContext,
    target: cockpit_proto::StorageCleanupTarget,
) -> Result<Response, ErrorPayload> {
    let contents = preview_target(ctx, &target).await?;
    let preview = cockpit_proto::StorageCleanupPreview {
        preview_id: Uuid::new_v4(),
        target,
        items: contents.items,
        bytes_to_free: contents.bytes_to_free,
    };
    let preview_id = preview.preview_id;
    let mut plans = previews()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    plans.retain(|_, plan| plan.issued_at.elapsed() <= PREVIEW_TTL);
    plans.insert(
        preview_id,
        StoredPreview {
            cleanup: contents.cleanup,
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

    let bytes_freed = match plan.cleanup {
        CleanupPlan::ArchiveSessions {
            candidates,
            include_renamed_or_pinned,
        } => {
            let unchanged = ctx
                .db
                .archive_storage_sessions_if_unchanged(candidates, include_renamed_or_pinned)
                .await
                .map_err(internal)?;
            if !unchanged {
                return Err(invalid_preview());
            }
            0
        }
        CleanupPlan::PermanentlyDeleteSessions {
            roots,
            candidates,
            directories,
        } => {
            verify_directory_snapshots(&directories).map_err(internal)?;
            // This transaction is the preview's linearization point. It checks
            // every root and descendant as one forest and commits the durable
            // `deleting` fence before any worker is stopped or invocation is
            // terminalized. A stale preview therefore has no destructive side
            // effect, including when a later root would otherwise fail.
            let unchanged = ctx
                .db
                .fence_storage_sessions_if_unchanged(roots.clone(), candidates.clone())
                .await
                .map_err(internal)?;
            if !unchanged {
                return Err(invalid_preview());
            }
            for root in &roots {
                super::sessions::prepare_session_deletion(ctx, *root).await?;
                ctx.db
                    .terminalize_session_run_invocations(
                        *root,
                        super::run_invocation::wall_ms_now(),
                    )
                    .await
                    .map_err(internal)?;
            }
            // Filesystem cleanup is a deletion precondition: do not remove
            // relational ownership if the session's result-blob namespace
            // cannot be proven absent.
            let bytes_freed = remove_previewed_directories(&directories).map_err(internal)?;
            let unchanged = ctx
                .db
                .delete_fenced_storage_sessions(roots, candidates)
                .await
                .map_err(internal)?;
            if !unchanged {
                return Err(invalid_preview());
            }
            bytes_freed
        }
        CleanupPlan::RemoveOrphanedWorkspaceStorage {
            orphan_roots,
            directories,
        } => {
            for root in orphan_roots {
                if root.exists() {
                    return Err(invalid_preview());
                }
            }
            verify_directory_snapshots(&directories).map_err(internal)?;
            remove_previewed_directories(&directories).map_err(internal)?
        }
    };
    Ok(Response::StorageCleanupCompleted { bytes_freed })
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
) -> Result<PreviewContents, ErrorPayload> {
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
                .iter()
                .map(|candidate| cockpit_proto::StorageCleanupItem {
                    // Session id is opaque and is atomically revalidated by the
                    // daemon at execution with its reviewed state.
                    label: candidate.session_id.to_string(),
                    bytes: 0,
                    last_used_at_unix_ms: Some(candidate.last_active_at_unix_ms),
                })
                .collect();
            Ok(PreviewContents {
                items,
                bytes_to_free: 0,
                cleanup: CleanupPlan::ArchiveSessions {
                    candidates,
                    include_renamed_or_pinned: *include_renamed_or_pinned,
                },
            })
        }
        cockpit_proto::StorageCleanupTarget::PermanentlyDeleteSessions { session_ids } => {
            let mut selected = HashSet::new();
            let mut subtrees = Vec::with_capacity(session_ids.len());
            for session_id in session_ids {
                if !selected.insert(*session_id) {
                    continue;
                }
                let subtree = ctx
                    .db
                    .session_subtree_ids(*session_id)
                    .await
                    .map_err(internal)?;
                if subtree.is_empty() {
                    return Err(ErrorPayload {
                        code: ErrorCode::UnknownSession,
                        message: format!("unknown session {session_id}"),
                    });
                }
                subtrees.push((*session_id, subtree));
            }
            // A selected ancestor already covers a selected descendant. Keep a
            // canonical forest so execution cannot delete a root and then
            // silently no-op a second reviewed root.
            let roots: Vec<_> = subtrees
                .iter()
                .filter_map(|(root, _)| {
                    let covered_by_another_root = subtrees
                        .iter()
                        .any(|(other_root, subtree)| other_root != root && subtree.contains(root));
                    (!covered_by_another_root).then_some(*root)
                })
                .collect();
            let mut candidate_ids = HashSet::new();
            for (_, subtree) in &subtrees {
                candidate_ids.extend(subtree.iter().copied());
            }
            let mut session_storage = Vec::with_capacity(candidate_ids.len());
            let mut directories = Vec::with_capacity(candidate_ids.len().saturating_mul(2));
            for session_id in candidate_ids {
                let Some(session) = ctx.db.get_session(session_id).await.map_err(internal)? else {
                    return Err(invalid_preview());
                };
                if session.ended_at_unix_ms.is_none() {
                    return Err(ErrorPayload {
                        code: ErrorCode::Conflict,
                        message: format!("session {session_id} is active; end it before deleting"),
                    });
                }
                let scratch = crate::session::workspace_scratch_path_for_session(
                    &session.project_id,
                    session_id,
                )
                .map_err(internal)?;
                let result_blobs =
                    result_blob_directory_for_session(session_id).map_err(internal)?;
                let scratch_snapshot = directory_snapshot(scratch).map_err(internal)?;
                let result_blob_snapshot = directory_snapshot(result_blobs).map_err(internal)?;
                let candidate = crate::db::sessions::StorageSessionCandidate {
                    session_id,
                    project_id: session.project_id,
                    title: session.title,
                    last_active_at_unix_ms: session.last_active_at_unix_ms,
                };
                session_storage.push((candidate, scratch_snapshot, result_blob_snapshot));
            }
            session_storage.sort_by_key(|(candidate, _, _)| candidate.session_id);
            let mut candidates = Vec::with_capacity(session_storage.len());
            let mut items = Vec::with_capacity(session_storage.len());
            let mut bytes_to_free = 0_u64;
            for (candidate, scratch_snapshot, result_blob_snapshot) in session_storage {
                let bytes = scratch_snapshot
                    .bytes
                    .saturating_add(result_blob_snapshot.bytes);
                bytes_to_free = bytes_to_free.saturating_add(bytes);
                items.push(cockpit_proto::StorageCleanupItem {
                    label: candidate.session_id.to_string(),
                    bytes,
                    last_used_at_unix_ms: Some(candidate.last_active_at_unix_ms),
                });
                candidates.push(candidate);
                directories.extend([scratch_snapshot, result_blob_snapshot]);
            }
            Ok(PreviewContents {
                items,
                bytes_to_free,
                cleanup: CleanupPlan::PermanentlyDeleteSessions {
                    roots,
                    candidates,
                    directories,
                },
            })
        }
        cockpit_proto::StorageCleanupTarget::RemoveOrphanedWorkspaceStorage { project_ids } => {
            let mut items = Vec::new();
            let mut bytes_to_free = 0_u64;
            let mut orphan_roots = Vec::new();
            let mut directories = Vec::new();
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
                let workspace_snapshot = directory_snapshot(workspace).map_err(internal)?;
                let local_config_snapshot = directory_snapshot(local_config).map_err(internal)?;
                let bytes = workspace_snapshot
                    .bytes
                    .saturating_add(local_config_snapshot.bytes);
                bytes_to_free = bytes_to_free.saturating_add(bytes);
                items.push(cockpit_proto::StorageCleanupItem {
                    label: project_id.clone(),
                    bytes,
                    last_used_at_unix_ms: Some(last_used_at_unix_ms),
                });
                orphan_roots.push(root);
                directories.extend([workspace_snapshot, local_config_snapshot]);
            }
            Ok(PreviewContents {
                items,
                bytes_to_free,
                cleanup: CleanupPlan::RemoveOrphanedWorkspaceStorage {
                    orphan_roots,
                    directories,
                },
            })
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
            directory_bytes(&data_dir.join("computer-capture"))?,
            0,
        ),
        (
            cockpit_proto::StorageCategory::ResultBlobs,
            directory_bytes(&state_dir.join("result-blobs"))?,
            0,
        ),
        (
            cockpit_proto::StorageCategory::SessionShims,
            directory_bytes(&data_dir.join("session-shims"))?,
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

/// The per-session result-blob namespace. Result writers must place a
/// session's files below this opaque id directory so permanent session deletion
/// has one unambiguous, daemon-owned filesystem target.
pub(crate) fn result_blob_directory_for_session(session_id: Uuid) -> Result<PathBuf> {
    Ok(cockpit_config::config::resolve::cockpit_state_dir()?
        .join("result-blobs")
        .join(session_id.to_string()))
}

fn directory_snapshot(path: PathBuf) -> Result<DirectorySnapshot> {
    let root_metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DirectorySnapshot {
                path,
                entries: Vec::new(),
                bytes: 0,
            });
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting `{}`", path.display()));
        }
    };
    ensure!(
        root_metadata.is_dir() && !root_metadata.file_type().is_symlink(),
        "refusing to snapshot non-directory storage target `{}`",
        path.display()
    );
    let mut entries = Vec::new();
    let mut bytes = 0_u64;
    for entry in walkdir::WalkDir::new(&path).follow_links(false) {
        let entry = entry.with_context(|| format!("walking `{}`", path.display()))?;
        let entry_path = entry.path();
        let metadata = std::fs::symlink_metadata(entry_path)
            .with_context(|| format!("inspecting `{}`", entry_path.display()))?;
        let kind = if metadata.file_type().is_dir() {
            DirectoryEntryKind::Directory
        } else if metadata.file_type().is_file() {
            DirectoryEntryKind::File
        } else if metadata.file_type().is_symlink() {
            DirectoryEntryKind::Symlink
        } else {
            anyhow::bail!(
                "refusing to snapshot unsupported storage entry `{}`",
                entry_path.display()
            );
        };
        let digest = if kind == DirectoryEntryKind::File {
            let mut file = std::fs::File::open(entry_path)
                .with_context(|| format!("opening `{}`", entry_path.display()))?;
            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file
                    .read(&mut buffer)
                    .with_context(|| format!("reading `{}`", entry_path.display()))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            bytes = bytes.saturating_add(metadata.len());
            Some(hasher.finalize().into())
        } else {
            None
        };
        let symlink_target = (kind == DirectoryEntryKind::Symlink)
            .then(|| std::fs::read_link(entry_path))
            .transpose()
            .with_context(|| format!("reading symlink `{}`", entry_path.display()))?;
        entries.push(DirectorySnapshotEntry {
            relative_path: entry_path
                .strip_prefix(&path)
                .context("stripping storage snapshot prefix")?
                .to_path_buf(),
            kind,
            bytes: metadata.len(),
            modified: metadata.modified().ok(),
            digest,
            symlink_target,
        });
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(DirectorySnapshot {
        path,
        entries,
        bytes,
    })
}

fn verify_directory_snapshots(snapshots: &[DirectorySnapshot]) -> Result<()> {
    for snapshot in snapshots {
        ensure!(
            directory_snapshot(snapshot.path.clone())? == *snapshot,
            "storage target changed after preview: `{}`",
            snapshot.path.display()
        );
    }
    Ok(())
}

/// Fence each pathname out of the production writer namespace before the final
/// snapshot and recursive removal. `rename` is atomic within the owned parent:
/// after it succeeds, a writer resolving the normal scratch/config/blob path
/// can only create content at the old name, which is deliberately left outside
/// the staged deletion tree. The final comparison is made *after* that fence,
/// so content written before the fence is never silently swept up either.
fn remove_previewed_directories(snapshots: &[DirectorySnapshot]) -> Result<u64> {
    let staged = stage_previewed_directories(snapshots)?;
    let mut bytes_freed = 0_u64;
    for snapshot in &staged {
        // This is intentionally after the namespace fence, rather than a
        // second check against a writer-visible pathname. No production writer
        // can re-enter the staged tree by resolving its ordinary path.
        ensure!(
            directory_snapshot(snapshot.path.clone())? == *snapshot,
            "storage target changed after preview: `{}`",
            snapshot.path.display()
        );
        remove_previewed_directory(&snapshot.path)?;
        ensure!(
            directory_is_absent(&snapshot.path)?,
            "storage target remains after removal: `{}`",
            snapshot.path.display()
        );
        bytes_freed = bytes_freed.saturating_add(snapshot.bytes);
    }
    Ok(bytes_freed)
}

fn stage_previewed_directories(snapshots: &[DirectorySnapshot]) -> Result<Vec<DirectorySnapshot>> {
    let mut staged = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        let metadata = match std::fs::symlink_metadata(&snapshot.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // An absent directory has no bytes and no recursive-removal
                // target. It was already represented by the preview snapshot.
                ensure!(
                    snapshot.entries.is_empty() && snapshot.bytes == 0,
                    "storage target disappeared after preview: `{}`",
                    snapshot.path.display()
                );
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspecting `{}`", snapshot.path.display()));
            }
        };
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "refusing to stage non-directory storage target `{}`",
            snapshot.path.display()
        );
        let parent = snapshot
            .path
            .parent()
            .context("storage target has no parent")?;
        let name = snapshot
            .path
            .file_name()
            .context("storage target has no file name")?
            .to_string_lossy();
        let staged_path = parent.join(format!(".{name}.storage-cleanup-{}", Uuid::now_v7()));
        std::fs::rename(&snapshot.path, &staged_path).with_context(|| {
            format!(
                "fencing storage target `{}` as `{}`",
                snapshot.path.display(),
                staged_path.display()
            )
        })?;
        let mut staged_snapshot = snapshot.clone();
        staged_snapshot.path = staged_path;
        staged.push(staged_snapshot);
    }
    Ok(staged)
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

fn directory_is_absent(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error).with_context(|| format!("inspecting `{}`", path.display())),
    }
}
