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
}

impl SecretStoreSnapshot {
    /// Placeholder published until `sqlite-native-key-store` fills live values.
    pub fn unconfigured_placeholder() -> Self {
        Self {
            intent: SecretStoreIntent::Unconfigured,
            effective_placement: SecretStorePlacement::Unavailable,
            fail_closed_reason: None,
            fix_command: None,
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
    pub fn unpublished() -> Self {
        Self {
            generation: 0,
            features: Vec::new(),
            dependencies: Vec::new(),
            secret_store: SecretStoreSnapshot::unconfigured_placeholder(),
        }
    }

    pub fn feature(&self, id: &str) -> Option<&FeatureCapabilityRow> {
        self.features.iter().find(|row| row.id == id)
    }

    pub fn dependency(&self, id: &str) -> Option<&CatalogDependencyRow> {
        self.dependencies.iter().find(|row| row.id == id)
    }
}

#[cfg(test)]
mod snapshot_shape_tests {
    use super::*;

    #[test]
    fn unification_complete_absent_from_wire_and_core() {
        let snapshot = SecretStoreSnapshot::unconfigured_placeholder();
        let encoded = serde_json::to_value(&snapshot).expect("serialize snapshot");
        let leftover = format!("{}{}", "unification", "_complete");
        assert!(
            encoded.get(&leftover).is_none(),
            "SecretStoreSnapshot must not emit {leftover}"
        );
        assert!(
            encoded.get("intent").is_some() && encoded.get("effective_placement").is_some(),
            "intent/placement stay on the wire: {encoded}"
        );

        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root");
        let mut hits = Vec::new();
        for rel in [
            "crates/cockpit-db",
            "crates/cockpit-core",
            "crates/cockpit-proto",
            "crates/cockpit-tui",
            "packages/cockpit-protocol/fixtures",
        ] {
            walk_for_needle(&repo.join(rel), &leftover, &mut hits);
        }
        assert!(
            hits.is_empty(),
            "{leftover} must not remain in wire/core/TUI/fixtures: {hits:?}"
        );
    }

    fn walk_for_needle(root: &std::path::Path, needle: &str, hits: &mut Vec<String>) {
        let entries = std::fs::read_dir(root)
            .unwrap_or_else(|e| panic!("required scan root unreadable {}: {e}", root.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|e| {
                panic!("required scan dirent unreadable {}: {e}", root.display())
            });
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name();
                if name == "target" || name == "node_modules" || name == "dist" {
                    continue;
                }
                walk_for_needle(&path, needle, hits);
                continue;
            }
            let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if !matches!(ext, "rs" | "sql" | "json" | "ts") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!("required scan file unreadable {}: {e}", path.display())
            });
            for (idx, line) in text.lines().enumerate() {
                if !line.contains(needle) {
                    continue;
                }
                let trimmed = line.trim();
                if trimmed.starts_with("fn ") && trimmed.contains("absent_from_wire") {
                    continue;
                }
                hits.push(format!("{}:{}:{trimmed}", path.display(), idx + 1));
            }
        }
    }
}
