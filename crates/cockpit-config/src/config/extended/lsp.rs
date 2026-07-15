use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub auto_install: LspAutoInstall,
    #[serde(default)]
    pub diagnostics: LspDiagnosticsConfig,
    #[serde(default = "default_lsp_idle_ttl_secs")]
    pub idle_ttl_secs: u64,
    #[serde(default = "default_lsp_max_cached_clients")]
    pub max_cached_clients: usize,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub servers: HashMap<String, LspServerConfig>,
}

default_const!(default_lsp_idle_ttl_secs, u64, 30 * 60);

default_const!(default_lsp_max_cached_clients, usize, 16);

impl Default for LspConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_install: LspAutoInstall::Ask,
            diagnostics: LspDiagnosticsConfig::default(),
            idle_ttl_secs: default_lsp_idle_ttl_secs(),
            max_cached_clients: default_lsp_max_cached_clients(),
            servers: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LspAutoInstall {
    #[default]
    Ask,
    On,
    Off,
}

impl LspAutoInstall {
    pub fn cycled(self) -> Self {
        match self {
            Self::Ask => Self::On,
            Self::On => Self::Off,
            Self::Off => Self::Ask,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspDiagnosticsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_lsp_other_files_limit")]
    pub other_files_limit: usize,
    #[serde(default = "default_lsp_per_file_limit")]
    pub per_file_limit: usize,
    #[serde(default)]
    pub severity: LspDiagnosticSeverity,
    #[serde(default = "default_lsp_debounce_ms")]
    pub debounce_ms: u64,
    #[serde(default = "default_lsp_document_timeout_ms")]
    pub document_timeout_ms: u64,
    #[serde(default = "default_lsp_workspace_timeout_ms")]
    pub workspace_timeout_ms: u64,
}

impl Default for LspDiagnosticsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            other_files_limit: default_lsp_other_files_limit(),
            per_file_limit: default_lsp_per_file_limit(),
            severity: LspDiagnosticSeverity::Error,
            debounce_ms: default_lsp_debounce_ms(),
            document_timeout_ms: default_lsp_document_timeout_ms(),
            workspace_timeout_ms: default_lsp_workspace_timeout_ms(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LspDiagnosticSeverity {
    #[default]
    Error,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LspServerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_command: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_markers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_guidance: Option<String>,
}

default_const!(default_lsp_other_files_limit, usize, 5);

default_const!(default_lsp_per_file_limit, usize, 20);

default_const!(default_lsp_debounce_ms, u64, 150);

default_const!(default_lsp_document_timeout_ms, u64, 5000);

default_const!(default_lsp_workspace_timeout_ms, u64, 10000);
