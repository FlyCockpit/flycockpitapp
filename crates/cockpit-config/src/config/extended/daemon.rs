use super::*;

pub use crate::db::retention::RetentionConfig;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonConfig {
    #[serde(default)]
    pub uploads: DaemonUploadLimitsConfig,
    #[serde(default)]
    pub autostart: DaemonAutostart,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            uploads: DaemonUploadLimitsConfig::default(),
            autostart: DaemonAutostart::Shared,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DaemonAutostart {
    #[default]
    Shared,
    Private,
    Ask,
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

pub const MAX_SINGLE_IMAGE_BYTES: usize = 4 * 1024 * 1024;

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
