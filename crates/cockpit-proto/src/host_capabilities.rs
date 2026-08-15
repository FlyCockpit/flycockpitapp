//! Daemon-owned host capability snapshot wire types.
//!
//! Settings, `/sandbox`, the setup wizard, session spawn, wrap-key vault boot,
//! and secret-store KEK placement consult this snapshot. The TUI in-process
//! doctor compose is not this authority.

use serde::{Deserialize, Serialize};

/// Closed feature-capability states used by settings/spawn/vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureCapabilityState {
    Available,
    Missing,
    Unsupported,
    Failed,
}

impl FeatureCapabilityState {
    pub fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// One feature row (`secret_store.keyring`, `sandbox.host`, …).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureCapabilityRow {
    pub id: String,
    pub state: FeatureCapabilityState,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remedy_text: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependency_ids: Vec<String>,
}

/// Catalog-row view state matching the doctor projection vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogDependencyState {
    Pending,
    Available,
    Missing,
    Incompatible,
    TimedOut,
    Failed,
    Unknown,
    NotApplicable,
}

/// Catalog-row importance matching the doctor projection vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogDependencyImportance {
    RequiredForDefaultSafety,
    RequiredWhenFeatureSelected,
    OptionalIntegration,
    OptionalAccelerator,
}

/// Catalog-row execution target matching the doctor projection vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogExecutionTarget {
    Host,
    Container,
}

/// One doctor-shaped catalog dependency row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogDependencyRow {
    pub id: String,
    pub state: CatalogDependencyState,
    pub importance: CatalogDependencyImportance,
    pub target: CatalogExecutionTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remedy: Option<serde_json::Value>,
    pub reason: String,
}

/// Installation-scoped secret-store intent. Not a layered config key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStoreIntent {
    Unconfigured,
    Database,
    Keyring,
}

/// Live effective KEK placement projected onto the snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStorePlacement {
    Unavailable,
    Database,
    Keyring,
}

/// Projection of the installation-scoped authority row plus the keyring probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretStoreSnapshot {
    pub intent: SecretStoreIntent,
    pub effective_placement: SecretStorePlacement,
    #[serde(default)]
    pub fail_closed_reason: Option<String>,
    #[serde(default)]
    pub fix_command: Option<String>,
    /// `secret_vault_authority.unification_complete`. Settings must not
    /// enable backend switching until this is true.
    #[serde(default)]
    pub unification_complete: bool,
}

impl SecretStoreSnapshot {
    /// Placeholder published until `sqlite-native-key-store` fills live values.
    pub fn unconfigured_placeholder() -> Self {
        Self {
            intent: SecretStoreIntent::Unconfigured,
            effective_placement: SecretStorePlacement::Unavailable,
            fail_closed_reason: None,
            fix_command: None,
            unification_complete: false,
        }
    }
}

/// Daemon-owned host capability snapshot.
///
/// Wire JSON is `{ features, dependencies, secretStore }` plus a generation
/// tag used to discard stale refreshes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCapabilitySnapshot {
    pub generation: u64,
    pub features: Vec<FeatureCapabilityRow>,
    pub dependencies: Vec<CatalogDependencyRow>,
    #[serde(rename = "secretStore")]
    pub secret_store: SecretStoreSnapshot,
}

impl HostCapabilitySnapshot {
    pub fn feature(&self, id: &str) -> Option<&FeatureCapabilityRow> {
        self.features.iter().find(|row| row.id == id)
    }

    pub fn dependency(&self, id: &str) -> Option<&CatalogDependencyRow> {
        self.dependencies.iter().find(|row| row.id == id)
    }
}
