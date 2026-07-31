use super::*;

pub const DEFAULT_DELEGATION_MAX_PARALLEL: usize = 4;

default_const!(
    default_delegation_max_parallel,
    usize,
    DEFAULT_DELEGATION_MAX_PARALLEL
);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationConfig {
    #[serde(rename = "maxParallel", default = "default_delegation_max_parallel")]
    pub max_parallel: usize,
    #[serde(
        rename = "recursionEnabled",
        alias = "recursion_enabled",
        default = "default_true"
    )]
    pub recursion_enabled: bool,
    #[serde(
        rename = "defaultRecursionDepth",
        alias = "default_recursion_depth",
        default
    )]
    pub default_recursion_depth: u32,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub recursion: std::collections::BTreeMap<String, DelegationRecursionPolicy>,
}

impl Default for DelegationConfig {
    fn default() -> Self {
        Self {
            max_parallel: default_delegation_max_parallel(),
            recursion_enabled: true,
            default_recursion_depth: 0,
            recursion: std::collections::BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationRecursionPolicy {
    #[serde(
        rename = "allowedTargets",
        alias = "allowed_targets",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allowed_targets: Vec<String>,
    #[serde(
        rename = "defaultDepth",
        alias = "default_depth",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub default_depth: Option<u32>,
    #[serde(
        rename = "maxDepth",
        alias = "max_depth",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_depth: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeepthinkConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReviewConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_participants: Vec<String>,
}

pub fn persist_review_default_participants(cwd: &Path, participants: Vec<String>) -> Result<()> {
    let path = nearest_project_config_path(cwd);
    let mut doc = ExtendedConfigDoc::load(&path)?;
    let mut cfg = doc.config();
    cfg.review.default_participants = participants;
    doc.write(&cfg)
}

// Fixed recursion bounds for the internal recursive-spawn scheduler.
pub const DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH: u32 = 3;
pub const DEFAULT_RECURSIVE_SPAWN_MAX_CONCURRENCY: usize = 8;
