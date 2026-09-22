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
        staged: &Path,
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
            // A still-running predecessor can retain the rename-aside image.
            // Cleanup is deliberately best effort and must never block startup.
            let _ = std::fs::remove_file(previous);
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
        loop {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            match options.open(&self.path) {
                Ok(mut file) => {
                    let bytes = serde_json::to_vec(record).map_err(|error| {
                        UpdaterError::Lock(format!("encoding update lock: {error}"))
                    })?;
                    file.write_all(&bytes).map_err(|error| {
                        UpdaterError::Lock(format!("writing update lock: {error}"))
                    })?;
                    return file.sync_all().map_err(|error| {
                        UpdaterError::Lock(format!("syncing update lock: {error}"))
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing = read_lock_record(&self.path)?;
                    if update_lock_owner_is_live(&existing) {
                        return Err(UpdaterError::Lock(
                            "another live process is applying an update".into(),
                        ));
                    }
                    std::fs::remove_file(&self.path).map_err(|error| {
                        UpdaterError::Lock(format!("reclaiming stale update lock: {error}"))
                    })?;
                }
                Err(error) => {
                    return Err(UpdaterError::Lock(format!(
                        "acquiring update lock: {error}"
                    )));
                }
            }
        }
    }

    async fn release(&self, update_id: uuid::Uuid) -> Result<(), UpdaterError> {
        let existing = read_lock_record(&self.path)?;
        if existing.update_id != update_id {
            return Err(UpdaterError::Lock(
                "refusing to release an update lock owned by another update".into(),
            ));
        }
        std::fs::remove_file(&self.path)
            .map_err(|error| UpdaterError::Lock(format!("releasing update lock: {error}")))
    }
}

fn read_lock_record(path: &Path) -> Result<UpdateLockRecord, UpdaterError> {
    let bytes = std::fs::read(path)
        .map_err(|error| UpdaterError::Lock(format!("reading update lock: {error}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| UpdaterError::Lock(format!("decoding update lock: {error}")))
}

fn update_lock_owner_is_live(record: &UpdateLockRecord) -> bool {
    cockpit_host::daemon_lifecycle::process_start_identity(record.owner_pid).is_ok_and(|identity| {
        record.owner_start_id == format!("{}:{}", identity.primary, identity.secondary)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn live_maintenance_client_requests_one_upgrade_and_preserves_admin_uptime() {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

        let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
        let paths = crate::daemon::DaemonPaths::resolve_canonical().unwrap();
        let admin = crate::daemon::supervisor::admin_socket(&paths).unwrap();
        let listener = tokio::net::UnixListener::bind(&admin).unwrap();
        let installed = PathBuf::from("/receipt-authorized/bin/cockpit");
        let expected_binary = installed.clone();
        let server = tokio::spawn(async move {
            for (expected, response) in [
                (
                    crate::daemon::supervisor::AdminCommand::Status,
                    crate::daemon::supervisor::AdminResponse::Status {
                        version: crate::daemon::supervisor::ADMIN_PROTOCOL_VERSION,
                        supervisor_pid: 10,
                        worker_pid: 101,
                        generation: 4,
                        uptime_ms: 5_000,
                        last_handover: None,
                    },
                ),
                (
                    crate::daemon::supervisor::AdminCommand::Upgrade {
                        binary: expected_binary,
                    },
                    crate::daemon::supervisor::AdminResponse::Rolled {
                        version: crate::daemon::supervisor::ADMIN_PROTOCOL_VERSION,
                        old_worker_pid: 101,
                        worker_pid: 202,
                        generation: 5,
                        uptime_ms: 5_750,
                    },
                ),
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = tokio::io::BufReader::new(stream);
                let mut line = Vec::new();
                reader.read_until(b'\n', &mut line).await.unwrap();
                let request: crate::daemon::supervisor::AdminRequest =
                    serde_json::from_slice(&line).unwrap();
                assert_eq!(request.command, expected);
                let mut stream = reader.into_inner();
                let mut response = serde_json::to_vec(&response).unwrap();
                response.push(b'\n');
                stream.write_all(&response).await.unwrap();
            }
        });

        LiveSupervisorMaintenanceClient::new(installed)
            .request_maintenance(SupervisorMaintenanceRequest {
                update_id: uuid::Uuid::now_v7(),
                target_version: "9.9.9".into(),
                installed_path_digest: "fixture".into(),
            })
            .await
            .unwrap();
        server.await.unwrap();
    }

    fn lock_record(update_id: uuid::Uuid, owner_start_id: String) -> UpdateLockRecord {
        UpdateLockRecord {
            update_id,
            owner_pid: std::process::id(),
            owner_start_id,
            installed_path_digest: "test".into(),
            state: super::super::types::UpdateLockState::Held,
            revision: 1,
        }
    }

    #[tokio::test]
    async fn stale_lock_is_reclaimed_but_a_live_owner_is_not() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(".cockpit-update.lock");
        let store = FileUpdateLockStore::new(path.clone());
        let live_id = uuid::Uuid::now_v7();
        let identity =
            cockpit_host::daemon_lifecycle::process_start_identity(std::process::id()).unwrap();
        let live = lock_record(
            live_id,
            format!("{}:{}", identity.primary, identity.secondary),
        );
        std::fs::write(&path, serde_json::to_vec(&live).unwrap()).unwrap();
        assert!(
            store
                .acquire_exclusive(&lock_record(uuid::Uuid::now_v7(), "new".into()))
                .await
                .is_err()
        );

        let stale = lock_record(uuid::Uuid::now_v7(), "recycled-pid".into());
        std::fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
        let replacement = lock_record(uuid::Uuid::now_v7(), "new".into());
        store.acquire_exclusive(&replacement).await.unwrap();
        assert_eq!(
            read_lock_record(&path).unwrap().update_id,
            replacement.update_id
        );
        store.release(replacement.update_id).await.unwrap();
    }

    #[tokio::test]
    async fn release_refuses_a_different_update_id() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(".cockpit-update.lock");
        let store = FileUpdateLockStore::new(path.clone());
        let record = lock_record(uuid::Uuid::now_v7(), "owner".into());
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(store.release(uuid::Uuid::now_v7()).await.is_err());
        assert!(path.exists());
    }
}
