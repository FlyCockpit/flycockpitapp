use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepoStatus {
    pub branch: String,
    pub staged: u32,
    pub unstaged: u32,
    pub unpushed: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LaunchInfo {
    pub version: String,
    pub session_id: Option<uuid::Uuid>,
    pub session_short_id: Option<String>,
    pub provider_line: String,
    pub active_model: Option<(String, String)>,
    pub active_model_diverged: bool,
    pub active_model_is_favorite: bool,
    pub active_model_is_trusted: bool,
    pub active_model_max_context: Option<u32>,
    pub active_model_supports_images: bool,
    pub cwd: PathBuf,
    pub cwd_display: String,
    pub repo_status: Option<RepoStatus>,
    pub agent_name: String,
    pub user_name: Option<String>,
    pub banner_enabled: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LaunchBundle {
    pub launch: LaunchInfo,
    pub providers: cockpit_config::config::providers::ProvidersConfig,
    pub extended: cockpit_config::config::extended::ExtendedConfig,
}
