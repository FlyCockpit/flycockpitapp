use super::*;

pub use crate::db::retention::RetentionConfig;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonConfig {
    #[serde(default)]
    pub uploads: DaemonUploadLimitsConfig,
    /// Whether a newly acquired ledger owner remains alive after its last
    /// terminal client exits. Existing persistent owners are always attached
    /// regardless of this default.
    #[serde(default = "default_background_agents")]
    pub background_agents: bool,
    /// Machine-local daemon bootstrap composition. Defaults preserve native
    /// keyring and container-environment detection behavior.
    #[serde(default)]
    pub boot: DaemonBootConfig,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonSecretStoreBackend {
    #[default]
    Auto,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonBootConfig {
    /// Select platform keyring auto-detection or the production file-backed
    /// wrapping-key store.
    #[serde(default)]
    pub secret_store_backend: DaemonSecretStoreBackend,
    /// Absolute directory containing file-backed vault wrapping keys. It must
    /// remain beneath the installation database's private parent directory;
    /// arbitrary cross-authority vault moves are deliberately unsupported.
    /// When omitted, `<database-parent>/secret-vault` is used.
    #[serde(default)]
    pub secret_store_path: Option<PathBuf>,
    /// Paths read to determine whether Cockpit itself runs in a container.
    /// Isolated installations may point these at harmless private files.
    #[serde(default)]
    pub container_probe_paths: DaemonContainerProbePaths,
}

impl Default for DaemonBootConfig {
    fn default() -> Self {
        Self {
            secret_store_backend: DaemonSecretStoreBackend::Auto,
            secret_store_path: None,
            container_probe_paths: DaemonContainerProbePaths::default(),
        }
    }
}

impl DaemonBootConfig {
    /// Validate installation-scoped paths before any probe or vault IO. These
    /// values are never resolved relative to a project working directory.
    pub fn validate_paths(&self) -> anyhow::Result<()> {
        if let Some(path) = &self.secret_store_path {
            validate_absolute_clean_path("secret_store_path", path)?;
        }
        for (name, path) in [
            ("docker_env", &self.container_probe_paths.docker_env),
            ("container_env", &self.container_probe_paths.container_env),
            ("init_cgroup", &self.container_probe_paths.init_cgroup),
            ("self_mountinfo", &self.container_probe_paths.self_mountinfo),
        ] {
            validate_absolute_clean_path(name, path)?;
            match std::fs::symlink_metadata(path) {
                Ok(metadata) => anyhow::ensure!(
                    metadata.file_type().is_file(),
                    "daemon container probe `{name}` must be a regular file"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

fn validate_absolute_clean_path(name: &str, path: &std::path::Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        path.is_absolute(),
        "daemon boot `{name}` path must be absolute"
    );
    anyhow::ensure!(
        !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir)),
        "daemon boot `{name}` path must not contain parent traversal"
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonContainerProbePaths {
    pub docker_env: PathBuf,
    pub container_env: PathBuf,
    pub init_cgroup: PathBuf,
    pub self_mountinfo: PathBuf,
}

impl Default for DaemonContainerProbePaths {
    fn default() -> Self {
        Self {
            docker_env: PathBuf::from("/.dockerenv"),
            container_env: PathBuf::from("/run/.containerenv"),
            init_cgroup: PathBuf::from("/proc/1/cgroup"),
            self_mountinfo: PathBuf::from("/proc/self/mountinfo"),
        }
    }
}

const fn default_background_agents() -> bool {
    true
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            uploads: DaemonUploadLimitsConfig::default(),
            background_agents: true,
            boot: DaemonBootConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonUploadLimitsConfig {
    /// Maximum pending uploads per connected client.
    #[serde(default = "default_daemon_uploads_per_client")]
    pub per_client_uploads: usize,
    /// Maximum pending uploads across the daemon.
    #[serde(default = "default_daemon_uploads_global")]
    pub global_uploads: usize,
    /// Maximum bytes per individual attachment upload. The daemon clamps this
    /// to the image-upload protocol ceiling (`MAX_SINGLE_IMAGE_BYTES`).
    #[serde(default = "default_daemon_uploads_per_upload_bytes")]
    pub per_upload_bytes: usize,
    /// Maximum pending attachment bytes across the daemon.
    #[serde(default = "default_daemon_uploads_global_bytes")]
    pub global_bytes: usize,
}

impl Default for DaemonUploadLimitsConfig {
    fn default() -> Self {
        Self {
            per_client_uploads: default_daemon_uploads_per_client(),
            global_uploads: default_daemon_uploads_global(),
            per_upload_bytes: default_daemon_uploads_per_upload_bytes(),
            global_bytes: default_daemon_uploads_global_bytes(),
        }
    }
}

pub const MAX_SINGLE_IMAGE_BYTES: usize = crate::config::media_budget::PASTE_MAX_SINGLE_IMAGE_BYTES;

default_const!(default_daemon_uploads_per_client, usize, 4);

default_const!(default_daemon_uploads_global, usize, 32);

default_const!(
    default_daemon_uploads_per_upload_bytes,
    usize,
    MAX_SINGLE_IMAGE_BYTES
);

default_const!(
    default_daemon_uploads_global_bytes,
    usize,
    256 * 1024 * 1024
);

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{DaemonConfig, DaemonSecretStoreBackend};

    #[test]
    fn background_agents_defaults_to_persistent_owners() {
        assert!(DaemonConfig::default().background_agents);
    }

    #[test]
    fn missing_background_agents_deserializes_to_persistent_owners() {
        let config: DaemonConfig =
            serde_json::from_value(serde_json::json!({})).expect("daemon config");

        assert!(config.background_agents);
    }

    #[test]
    fn background_agents_deserializes_as_a_boolean() {
        let config: DaemonConfig = serde_json::from_value(serde_json::json!({
            "background_agents": false
        }))
        .expect("daemon config");

        assert!(!config.background_agents);
    }

    #[test]
    fn boot_composition_defaults_to_native_detection() {
        let config: DaemonConfig = serde_json::from_value(serde_json::json!({})).unwrap();

        assert_eq!(
            config.boot.secret_store_backend,
            DaemonSecretStoreBackend::Auto
        );
        assert_eq!(config.boot.secret_store_path, None);
        assert_eq!(
            config.boot.container_probe_paths,
            super::DaemonContainerProbePaths::default()
        );
    }

    #[test]
    fn boot_composition_accepts_file_vault_and_isolated_probe_paths() {
        let config: DaemonConfig = serde_json::from_value(serde_json::json!({
            "boot": {
                "secret_store_backend": "file",
                "secret_store_path": "/isolated/home/vault",
                "container_probe_paths": {
                    "docker_env": "/isolated/probes/dockerenv",
                    "container_env": "/isolated/probes/containerenv",
                    "init_cgroup": "/isolated/probes/cgroup",
                    "self_mountinfo": "/isolated/probes/mountinfo"
                }
            }
        }))
        .unwrap();

        assert_eq!(
            config.boot.secret_store_backend,
            DaemonSecretStoreBackend::File
        );
        assert_eq!(
            config.boot.secret_store_path,
            Some(PathBuf::from("/isolated/home/vault"))
        );
        assert_eq!(
            config.boot.container_probe_paths.init_cgroup,
            PathBuf::from("/isolated/probes/cgroup")
        );
    }

    #[test]
    fn boot_paths_reject_relative_traversal_and_non_files() {
        let mut boot = super::DaemonBootConfig::default();
        boot.secret_store_path = Some(PathBuf::from("relative/vault"));
        assert!(
            boot.validate_paths()
                .unwrap_err()
                .to_string()
                .contains("absolute")
        );

        boot.secret_store_path = Some(PathBuf::from("/safe/../escape"));
        assert!(
            boot.validate_paths()
                .unwrap_err()
                .to_string()
                .contains("parent traversal")
        );

        let temp = tempfile::tempdir().unwrap();
        boot.secret_store_path = Some(temp.path().join("vault"));
        boot.container_probe_paths.docker_env = temp.path().to_path_buf();
        assert!(
            boot.validate_paths()
                .unwrap_err()
                .to_string()
                .contains("regular file")
        );
    }
}
