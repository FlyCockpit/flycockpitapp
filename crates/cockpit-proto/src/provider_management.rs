use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// One daemon-owned provider-layer edit. The snapshot capability, rather than
/// a client-supplied path, selects the authoritative layer.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProviderMutationBatch {
    #[serde(default)]
    pub upserts: Vec<ProviderMutationUpsert>,
    #[serde(default)]
    pub deletes: Vec<ProviderMutationDelete>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ProviderLayerMetadataPatch>,
}

impl std::fmt::Debug for ProviderMutationBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderMutationBatch")
            .field("upsert_count", &self.upserts.len())
            .field("deletes", &self.deletes)
            .field("metadata", &self.metadata)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProviderMutationUpsert {
    pub provider_id: String,
    pub entry: cockpit_config::config::providers::ProviderEntry,
    /// Positional with `entry.headers`. Values are zeroized as soon as daemon
    /// dispatch takes ownership; Debug never reveals their contents.
    pub header_secrets: Vec<Option<ProviderSecretValue>>,
}

impl std::fmt::Debug for ProviderMutationUpsert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderMutationUpsert")
            .field("provider_id", &self.provider_id)
            .field("entry", &"[REDACTED HEADERS]")
            .field("header_secret_count", &self.header_secrets.len())
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMutationDelete {
    pub provider_id: String,
    #[serde(default)]
    pub delete_stored_secrets: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderLayerMetadataPatch {
    pub category_defaults: BTreeMap<String, cockpit_config::config::providers::ProviderModelRef>,
    pub on_unlisted_models_fetch: cockpit_config::config::providers::OnUnlistedModelsFetch,
}

#[derive(Clone)]
pub struct ProviderSecretValue(Zeroizing<String>);

impl ProviderSecretValue {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn take(mut self) -> String {
        std::mem::take(&mut self.0)
    }

    pub fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::fmt::Debug for ProviderSecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderSecretValue([REDACTED])")
    }
}

impl Serialize for ProviderSecretValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for ProviderSecretValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_secret_debug_is_redacted_and_wire_round_trip_is_single_owner() {
        let sentinel = "provider-secret-sentinel";
        let value = ProviderSecretValue::new(sentinel.into());
        assert!(!format!("{value:?}").contains(sentinel));
        let wire = serde_json::to_string(&value).unwrap();
        assert_eq!(wire, format!("\"{sentinel}\""));
        let decoded: ProviderSecretValue = serde_json::from_str(&wire).unwrap();
        let decoded = decoded.into_zeroizing();
        assert_eq!(decoded.as_str(), sentinel);
    }
}
