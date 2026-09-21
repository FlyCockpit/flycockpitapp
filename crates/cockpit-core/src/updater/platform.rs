//! Platform binary placement and production supervisor/lock adapters.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use super::traits::{BinaryReplacer, SupervisorMaintenanceClient, UpdateLockStore};
use super::types::{
    SupervisorMaintenanceRequest, UpdateApplyReceipt, UpdateLockRecord, UpdaterError,
};

#[derive(Debug, Clone)]
pub struct PlatformBinaryReplacer {
    installed: PathBuf,
}

impl PlatformBinaryReplacer {
    pub fn new(installed: PathBuf) -> Self {
        Self { installed }
    }
}

#[async_trait]
impl BinaryReplacer for PlatformBinaryReplacer {
    async fn stage_and_swap(
        &self,
        staged: &PathBuf,
        _receipt: &mut UpdateApplyReceipt,
    ) -> Result<(), UpdaterError> {
        replace_binary(staged, &self.installed)
    }
}

fn sibling_temp(installed: &Path) -> Result<PathBuf, UpdaterError> {
    let name = installed
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            UpdaterError::Replacement("installed binary has no UTF-8 file name".into())
        })?;
    Ok(installed.with_file_name(format!(".{name}.update-{}", uuid::Uuid::now_v7())))
}

fn copy_to_sibling(staged: &Path, installed: &Path) -> Result<PathBuf, UpdaterError> {
    let temp = sibling_temp(installed)?;
    std::fs::copy(staged, &temp)
        .map_err(|error| UpdaterError::io("copying update beside installed binary", error))?;
    if let Ok(metadata) = std::fs::metadata(installed) {
        std::fs::set_permissions(&temp, metadata.permissions())
            .map_err(|error| UpdaterError::io("preserving installed binary permissions", error))?;
    }
    Ok(temp)
}

#[cfg(not(windows))]
fn replace_binary(staged: &Path, installed: &Path) -> Result<(), UpdaterError> {
    #[cfg(target_os = "macos")]
    use std::os::unix::fs::MetadataExt;

    #[cfg(target_os = "macos")]
    let old_inode = std::fs::metadata(installed)
        .map_err(|error| UpdaterError::io("reading installed binary inode", error))?
        .ino();
    let temp = copy_to_sibling(staged, installed)?;
    if let Err(error) = std::fs::rename(&temp, installed) {
        let _ = std::fs::remove_file(&temp);
        return Err(UpdaterError::io(
            "atomically replacing installed binary",
            error,
        ));
    }
    #[cfg(target_os = "macos")]
    {
        let new_inode = std::fs::metadata(installed)
            .map_err(|error| UpdaterError::io("verifying replacement binary inode", error))?
            .ino();
        if old_inode == new_inode {
            return Err(UpdaterError::Replacement(
                "macOS binary replacement did not change the inode".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn replace_binary(staged: &Path, installed: &Path) -> Result<(), UpdaterError> {
    let temp = copy_to_sibling(staged, installed)?;
    let previous = previous_binary_path(installed);
    if previous.exists() {
        std::fs::remove_file(&previous)
            .map_err(|error| UpdaterError::io("removing stale previous executable", error))?;
    }
    std::fs::rename(installed, &previous)
        .map_err(|error| UpdaterError::io("renaming installed executable aside", error))?;
    if let Err(error) = std::fs::rename(&temp, installed) {
        let _ = std::fs::rename(&previous, installed);
        let _ = std::fs::remove_file(&temp);
        return Err(UpdaterError::io("activating replacement executable", error));
    }
    Ok(())
}

#[cfg(windows)]
fn previous_binary_path(installed: &Path) -> PathBuf {
    installed.with_file_name("cockpit.previous.exe")
}

/// Remove Windows' rename-aside executable only after the replacement has
/// successfully started. Other platforms have no deferred file.
pub fn cleanup_previous_binary_after_successful_start() -> Result<(), UpdaterError> {
    #[cfg(windows)]
    {
        let installed = std::env::current_exe()
            .map_err(|error| UpdaterError::io("resolving started executable", error))?;
        let previous = previous_binary_path(&installed);
        if previous.exists() {
            std::fs::remove_file(previous)
                .map_err(|error| UpdaterError::io("cleaning previous executable", error))?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct LiveSupervisorMaintenanceClient {
    installed: PathBuf,
}

impl LiveSupervisorMaintenanceClient {
    pub fn new(installed: PathBuf) -> Self {
        Self { installed }
    }
}

#[async_trait]
impl SupervisorMaintenanceClient for LiveSupervisorMaintenanceClient {
    async fn request_maintenance(
        &self,
        _request: SupervisorMaintenanceRequest,
    ) -> Result<(), UpdaterError> {
        let paths = crate::daemon::DaemonPaths::resolve_canonical().map_err(|error| {
            UpdaterError::Supervisor(format!("resolving supervisor: {error:#}"))
        })?;
        let before = crate::daemon::supervisor::request(
            &paths,
            crate::daemon::supervisor::AdminCommand::Status,
        )
        .await
        .map_err(|error| {
            UpdaterError::Supervisor(format!("reading supervisor uptime: {error:#}"))
        })?;
        let before_uptime = match before {
            crate::daemon::supervisor::AdminResponse::Status { uptime_ms, .. } => uptime_ms,
            other => {
                return Err(UpdaterError::Supervisor(format!(
                    "supervisor returned unexpected pre-upgrade response: {other:?}"
                )));
            }
        };
        let response = crate::daemon::supervisor::request(
            &paths,
            crate::daemon::supervisor::AdminCommand::Upgrade {
                binary: self.installed.clone(),
            },
        )
        .await
        .map_err(|error| {
            UpdaterError::Supervisor(format!("requesting supervisor upgrade: {error:#}"))
        })?;
        match response {
            crate::daemon::supervisor::AdminResponse::Rolled { uptime_ms, .. }
                if uptime_ms >= before_uptime =>
            {
                Ok(())
            }
            crate::daemon::supervisor::AdminResponse::Rolled { .. } => Err(
                UpdaterError::Supervisor("supervisor roll did not preserve uptime".into()),
            ),
            crate::daemon::supervisor::AdminResponse::Error { message, .. } => Err(
                UpdaterError::Supervisor(format!("supervisor upgrade failed: {message}")),
            ),
            other => Err(UpdaterError::Supervisor(format!(
                "supervisor returned unexpected upgrade response: {other:?}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileUpdateLockStore {
    path: PathBuf,
}

impl FileUpdateLockStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait]
impl UpdateLockStore for FileUpdateLockStore {
    async fn acquire_exclusive(&self, record: &UpdateLockRecord) -> Result<(), UpdaterError> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options
            .open(&self.path)
            .map_err(|error| UpdaterError::Lock(format!("acquiring update lock: {error}")))?;
        let bytes = serde_json::to_vec(record)
            .map_err(|error| UpdaterError::Lock(format!("encoding update lock: {error}")))?;
        file.write_all(&bytes)
            .map_err(|error| UpdaterError::Lock(format!("writing update lock: {error}")))?;
        file.sync_all()
            .map_err(|error| UpdaterError::Lock(format!("syncing update lock: {error}")))
    }

    async fn release(&self, _update_id: uuid::Uuid) -> Result<(), UpdaterError> {
        std::fs::remove_file(&self.path)
            .map_err(|error| UpdaterError::Lock(format!("releasing update lock: {error}")))
    }
}
