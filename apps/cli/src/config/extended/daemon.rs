use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DaemonConfig {
    #[serde(default)]
    pub uploads: DaemonUploadLimitsConfig,
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

default_const!(default_daemon_uploads_per_client, usize, 4);

default_const!(default_daemon_uploads_global, usize, 32);

default_const!(
    default_daemon_uploads_per_upload_bytes,
    usize,
    crate::daemon::proto::MAX_SINGLE_IMAGE_BYTES
);

default_const!(
    default_daemon_uploads_global_bytes,
    usize,
    256 * 1024 * 1024
);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Payload-row retention window in days.
    #[serde(default = "default_retention_payload_window_days")]
    pub payload_window_days: u32,
    /// Whole-session retention window in days.
    #[serde(default)]
    pub session_window_days: u32,
    /// Periodic retention sweep interval in hours.
    #[serde(default = "default_retention_sweep_interval_hours")]
    pub sweep_interval_hours: u32,
    /// Deleted-row threshold for vacuum.
    #[serde(default = "default_retention_vacuum_min_deletions")]
    pub vacuum_min_deletions: u64,
    /// Vacuum interval in days.
    #[serde(default = "default_retention_vacuum_interval_days")]
    pub vacuum_interval_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            payload_window_days: default_retention_payload_window_days(),
            session_window_days: 0,
            sweep_interval_hours: default_retention_sweep_interval_hours(),
            vacuum_min_deletions: default_retention_vacuum_min_deletions(),
            vacuum_interval_days: default_retention_vacuum_interval_days(),
        }
    }
}

default_const!(default_retention_payload_window_days, u32, 30);

default_const!(default_retention_sweep_interval_hours, u32, 6);

default_const!(default_retention_vacuum_min_deletions, u64, 1000);

default_const!(default_retention_vacuum_interval_days, u32, 7);
