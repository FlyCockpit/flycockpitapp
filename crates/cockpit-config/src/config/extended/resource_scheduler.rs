use super::*;

pub const DEFAULT_RESOURCE_POOL_CAPACITY: u32 = 1;
pub const DEFAULT_RESOURCE_SCHEDULER_MAX_QUEUED: usize = 128;

/// Daemon-owned resource scheduler config. It defines named permit pools; the
/// scheduler enforces permit counts only and does not apply OS resource limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceSchedulerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub pools: ResourceSchedulerPoolsConfig,
    #[serde(default)]
    pub limits: ResourceSchedulerLimitsConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ResourceSchedulerRuleConfig>,
}

impl Default for ResourceSchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pools: ResourceSchedulerPoolsConfig::default(),
            limits: ResourceSchedulerLimitsConfig::default(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourceSchedulerPoolsConfig {
    #[serde(default)]
    pub cpu: ResourcePoolConfig,
    #[serde(default)]
    pub memory: ResourcePoolConfig,
    #[serde(flatten, default)]
    pub other: std::collections::BTreeMap<String, ResourcePoolConfig>,
}

impl ResourceSchedulerPoolsConfig {
    pub fn as_map(&self) -> std::collections::BTreeMap<String, ResourcePoolConfig> {
        let mut pools = self.other.clone();
        pools.insert("cpu".to_string(), self.cpu.clone());
        pools.insert("memory".to_string(), self.memory.clone());
        pools
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePoolConfig {
    #[serde(default = "default_resource_pool_capacity")]
    pub capacity: u32,
}

impl Default for ResourcePoolConfig {
    fn default() -> Self {
        Self {
            capacity: default_resource_pool_capacity(),
        }
    }
}

default_const!(
    default_resource_pool_capacity,
    u32,
    DEFAULT_RESOURCE_POOL_CAPACITY
);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceSchedulerLimitsConfig {
    #[serde(
        rename = "maxQueued",
        default = "default_resource_scheduler_max_queued"
    )]
    pub max_queued: usize,
}

impl Default for ResourceSchedulerLimitsConfig {
    fn default() -> Self {
        Self {
            max_queued: default_resource_scheduler_max_queued(),
        }
    }
}

default_const!(
    default_resource_scheduler_max_queued,
    usize,
    DEFAULT_RESOURCE_SCHEDULER_MAX_QUEUED
);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceSchedulerRuleConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subcommand: Option<String>,
    #[serde(
        rename = "approvalKey",
        alias = "approval_key",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub approval_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub resources: std::collections::BTreeMap<String, u32>,
}
