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
            let mut entry = upsert.entry.clone();
            for (index, header) in entry.headers.iter_mut().enumerate() {
                if upsert
                    .header_secrets
                    .get(index)
                    .is_some_and(Option::is_some)
                {
                    header.value = "[STAGED_SECRET]".into();
                }
            }
            serde_json::json!({
                "provider_id": upsert.provider_id,
                "entry": entry,
                "model_patch": upsert.model_patch,
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
    /// Revision-bound delta over the complete effective model inventory.
    /// Unchanged inherited rows never travel back in an ordinary settings edit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_patch: Option<ProviderModelPatch>,
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

/// A bounded edit to a possibly paged, composed model inventory. The digest
/// binds the complete pre-edit inventory in addition to the layer capability CAS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderModelPatch {
    pub base_digest: String,
    pub upserts: Vec<cockpit_config::config::providers::ModelEntry>,
    pub deletes: Vec<String>,
    /// Present only when the owner changes membership/order. Unchanged catalogs
    /// do not pay to resend their complete id sequence on a favorite/header edit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<Vec<String>>,
}

impl ProviderModelPatch {
    pub fn between(
        before: &[cockpit_config::config::providers::ModelEntry],
        after: &[cockpit_config::config::providers::ModelEntry],
    ) -> Result<Self, serde_json::Error> {
        let prior = before
            .iter()
            .map(|model| Ok((model.id.as_str(), serde_json::to_vec(model)?)))
            .collect::<Result<BTreeMap<_, _>, serde_json::Error>>()?;
        let next_ids = after
            .iter()
            .map(|model| model.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let mut upserts = Vec::new();
        for model in after {
            if prior.get(model.id.as_str()) != Some(&serde_json::to_vec(model)?) {
                upserts.push(model.clone());
            }
        }
        let before_order = before
            .iter()
            .map(|model| model.id.clone())
            .collect::<Vec<_>>();
        let after_order = after
            .iter()
            .map(|model| model.id.clone())
            .collect::<Vec<_>>();
        let order = (before_order != after_order).then_some(after_order);
        Ok(Self {
            order,
            base_digest: Self::digest(before)?,
            upserts,
            deletes: before
                .iter()
                .filter(|prior| !next_ids.contains(prior.id.as_str()))
                .map(|model| model.id.clone())
                .collect(),
        })
    }

    fn digest(
        models: &[cockpit_config::config::providers::ModelEntry],
    ) -> Result<String, serde_json::Error> {
        Ok(Sha256::digest(serde_json::to_vec(models)?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    pub fn apply(
        &self,
        models: &mut Vec<cockpit_config::config::providers::ModelEntry>,
    ) -> Result<(), String> {
        if Self::digest(models).map_err(|error| error.to_string())? != self.base_digest {
            return Err("provider model inventory changed; reload before saving".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        for id in self
            .deletes
            .iter()
            .map(String::as_str)
            .chain(self.upserts.iter().map(|model| model.id.as_str()))
        {
            if !ids.insert(id) {
                return Err("provider model patch contains duplicate ids".into());
            }
        }
        if let Some(order) = &self.order {
            let expected = models
                .iter()
                .filter(|model| !self.deletes.contains(&model.id))
                .map(|model| model.id.as_str())
                .chain(self.upserts.iter().map(|model| model.id.as_str()))
                .collect::<std::collections::BTreeSet<_>>();
            let actual = order
                .iter()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            if actual != expected || actual.len() != order.len() {
                return Err(
                    "provider model patch order does not match its complete membership".into(),
                );
            }
        }
        models.retain(|model| !self.deletes.contains(&model.id));
        for model in &self.upserts {
            if let Some(prior) = models.iter_mut().find(|prior| prior.id == model.id) {
                *prior = model.clone();
            } else {
                models.push(model.clone());
            }
        }
        // Restore the requested order only after validating all membership.
        if let Some(order) = &self.order {
            let mut entries = std::mem::take(models)
                .into_iter()
                .map(|model| (model.id.clone(), model))
                .collect::<BTreeMap<_, _>>();
            *models = order
                .iter()
                .map(|id| entries.remove(id).expect("validated model order"))
                .collect();
        }
        Ok(())
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
pub enum ProviderSecretValue {
    Literal(Zeroizing<String>),
    DetectedEnvironment {
        template_id: String,
        variable: String,
    },
}

impl ProviderSecretValue {
    pub fn new(value: String) -> Self {
        Self::Literal(Zeroizing::new(value))
    }

    pub fn detected_environment(template_id: String, variable: String) -> Self {
        Self::DetectedEnvironment {
            template_id,
            variable,
        }
    }

    pub fn into_literal(self) -> Option<Zeroizing<String>> {
        match self {
            Self::Literal(mut value) => Some(Zeroizing::new(std::mem::take(&mut *value))),
            Self::DetectedEnvironment { .. } => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Literal(value) if value.is_empty())
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Literal(value) => value.len(),
            Self::DetectedEnvironment {
                template_id,
                variable,
            } => template_id.len() + variable.len(),
        }
    }
}

#[cfg(feature = "remote")]
impl crate::remote_operation_fcor::CanonicalFcorValueV1 for ProviderSecretValue {
    fn encode_fcor_value_v1(
        &self,
        out: &mut crate::remote_operation_fcor::CanonicalParamsV1,
    ) -> anyhow::Result<()> {
        // FCOR backs remote idempotency. It must distinguish a literal from a
        // detected-environment reference (and distinguish their values), but
        // its canonical buffer is not zeroizing, so it may never receive a
        // literal secret. Hash a tagged representation instead.
        let mut digest = Sha256::new();
        match self {
            Self::Literal(value) => {
                digest.update(b"literal\\0");
                digest.update(value.as_bytes());
            }
            Self::DetectedEnvironment {
                template_id,
                variable,
            } => {
                digest.update(b"detected-environment\\0");
                digest.update(template_id.as_bytes());
                digest.update(b"\\0");
                digest.update(variable.as_bytes());
            }
        }
        let digest = digest.finalize();
        out.push_bytes(&digest)
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
        match self {
            Self::Literal(value) => serializer.serialize_str(value.as_str()),
            Self::DetectedEnvironment {
                template_id,
                variable,
            } => serde_json::json!({
                "source": "detected_environment",
                "template_id": template_id,
                "variable": variable,
            })
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ProviderSecretValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Literal(String),
            Detected {
                source: String,
                template_id: String,
                variable: String,
            },
        }
        match Wire::deserialize(deserializer)? {
            Wire::Literal(value) => Ok(Self::new(value)),
            Wire::Detected {
                source,
                template_id,
                variable,
            } if source == "detected_environment" => {
                Ok(Self::detected_environment(template_id, variable))
            }
            Wire::Detected { .. } => {
                Err(serde::de::Error::custom("unknown provider secret source"))
            }
        }
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
        let decoded = decoded.into_literal().unwrap();
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
                    model_patch: None,
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
        let mut literal = batch("first-secret");
        literal.upserts[0].entry.headers[0].value = "guessable-credential".into();
        assert_eq!(
            first.sanitized_intent_hash().unwrap(),
            literal.sanitized_intent_hash().unwrap(),
            "a staged header's literal bytes must not influence its public intent digest"
        );
        let mut absent = batch("unused");
        absent.upserts[0].header_secrets[0] = None;
        assert_ne!(
            first.sanitized_intent_hash().unwrap(),
            absent.sanitized_intent_hash().unwrap()
        );
    }
}

#[cfg(test)]
mod model_patch_tests {
    use super::*;
    use cockpit_config::config::providers::ModelEntry;

    #[test]
    fn model_patch_preserves_unchanged_rows_and_rejects_stale_or_duplicate_inventory() {
        let before = vec![
            ModelEntry {
                id: "global".into(),
                name: Some("g".repeat(180 * 1024)),
                ..Default::default()
            },
            ModelEntry {
                id: "authored".into(),
                manual: true,
                favorite: true,
                name: Some("l".repeat(180 * 1024)),
                ..Default::default()
            },
        ];
        let mut after = before.clone();
        after[0].favorite = true;
        let patch = ProviderModelPatch::between(&before, &after).unwrap();
        assert_eq!(patch.upserts.len(), 1);
        assert!(serde_json::to_vec(&patch).unwrap().len() < crate::MAX_OWNER_PROVIDER_ENTRY_BYTES);
        let mut actual = before.clone();
        patch.apply(&mut actual).unwrap();
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&after).unwrap()
        );
        let old = serde_json::to_value(&actual).unwrap();
        assert!(
            patch
                .apply(&mut actual)
                .unwrap_err()
                .contains("inventory changed")
        );
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            old,
            "stale delta makes no changes"
        );
        let mut reordered = before.clone();
        reordered.reverse();
        let reorder = ProviderModelPatch::between(&before, &reordered).unwrap();
        assert!(reorder.upserts.is_empty());
        let mut actual = before.clone();
        reorder.apply(&mut actual).unwrap();
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&reordered).unwrap(),
            "owner ordering survives a bounded delta"
        );
        let mut invalid = reorder;
        invalid.order = Some(vec!["global".into()]);
        let mut actual = before.clone();
        assert!(invalid.apply(&mut actual).unwrap_err().contains("order"));
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&before).unwrap(),
            "invalid order makes no changes"
        );
        let empty = ProviderModelPatch::between(&before, &[]).unwrap();
        let mut actual = before.clone();
        empty.apply(&mut actual).unwrap();
        assert!(actual.is_empty(), "complete empty membership");
        let mut duplicate = ProviderModelPatch::between(&before, &after).unwrap();
        duplicate.deletes.push("global".into());
        let mut actual = before.clone();
        assert!(
            duplicate
                .apply(&mut actual)
                .unwrap_err()
                .contains("duplicate")
        );
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
    }
}

/// Complete catalogs are read separately when a durable receipt would be too
/// large. Current is materialized by the local client after a correlated read.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProviderCatalogReadback {
    #[default]
    Inline,
    Required,
    Current {
        snapshot_session_id: String,
        layer_id: String,
        owner_root: String,
        base_revision: String,
        config_generation: u64,
    },
}
impl ProviderCatalogReadback {
    pub fn is_inline(&self) -> bool {
        matches!(self, Self::Inline)
    }
}
