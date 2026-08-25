use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

impl ProviderMutationBatch {
    /// Stable, non-secret identity for UI/daemon receipt correlation. Secret
    /// bytes are represented only by positional presence bits.
    pub fn sanitized_intent_hash(&self) -> Result<String, serde_json::Error> {
        let upserts = self.upserts.iter().map(|upsert| {
            serde_json::json!({
                "provider_id": upsert.provider_id,
                "entry": upsert.entry,
                "header_secret_present": upsert.header_secrets.iter().map(Option::is_some).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>();
        let encoded = serde_json::to_vec(&serde_json::json!({
            "upserts": upserts,
            "deletes": self.deletes,
            "metadata": self.metadata,
        }))?;
        Ok(Sha256::digest(encoded)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
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
    /// Optional owner-selected default model. Absence preserves the current
    /// layer value; setup uses `Some` to make its selected model authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_model: Option<cockpit_config::config::providers::ActiveModelRef>,
}

#[derive(Clone)]
pub struct ProviderSecretValue(Zeroizing<String>);

impl ProviderSecretValue {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut *self.0))
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

    #[test]
    fn provider_mutation_intent_identifies_secret_presence_without_secret_bytes() {
        fn batch(secret: &str) -> ProviderMutationBatch {
            let mut entry = cockpit_config::config::providers::ProviderEntry::default();
            entry
                .headers
                .push(cockpit_config::config::providers::HeaderSpec {
                    name: "authorization".into(),
                    value: "********".into(),
                });
            ProviderMutationBatch {
                upserts: vec![ProviderMutationUpsert {
                    provider_id: "example".into(),
                    entry,
                    header_secrets: vec![Some(ProviderSecretValue::new(secret.into()))],
                }],
                deletes: Vec::new(),
                metadata: None,
            }
        }

        let first = batch("first-secret");
        let second = batch("different-secret");
        assert_eq!(
            first.sanitized_intent_hash().unwrap(),
            second.sanitized_intent_hash().unwrap()
        );
        let mut absent = batch("unused");
        absent.upserts[0].header_secrets[0] = None;
        assert_ne!(
            first.sanitized_intent_hash().unwrap(),
            absent.sanitized_intent_hash().unwrap()
        );
    }
}
