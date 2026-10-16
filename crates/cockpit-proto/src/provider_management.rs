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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub updates: Vec<cockpit_config::config::providers::ModelEntryFieldPatch>,
    pub deletes: Vec<String>,
    /// Present only when the owner changes membership/order. Unchanged catalogs
    /// and clears do not pay to resend an implied id sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<Vec<String>>,
    /// Sparse alternative to full order for large composed catalogs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub moves: Vec<cockpit_config::config::providers::ModelPlacement>,
    /// Empty membership is constant size even when the base has long IDs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub clear: bool,
}

impl ProviderModelPatch {
    pub fn between(
        before: &[cockpit_config::config::providers::ModelEntry],
        after: &[cockpit_config::config::providers::ModelEntry],
    ) -> Result<Self, serde_json::Error> {
        let prior = before
            .iter()
            .map(|model| (model.id.as_str(), model))
            .collect::<BTreeMap<_, _>>();
        let next_ids = after
            .iter()
            .map(|model| model.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let mut upserts = Vec::new();
        let mut updates = Vec::new();
        for model in after {
            if let Some(prior) = prior.get(model.id.as_str()) {
                if serde_json::to_vec(prior)? != serde_json::to_vec(model)? {
                    // Both IDs come from this lookup; serialization is the only
                    // fallible operation in the field diff.
                    updates.push(
                        cockpit_config::config::providers::ModelEntryFieldPatch::between(
                            prior, model,
                        )
                        .map_err(<serde_json::Error as serde::ser::Error>::custom)?,
                    );
                }
            } else {
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
        let changed = before_order != after_order;
        let clear = changed && after.is_empty();
        let deletes = if clear {
            Vec::new()
        } else {
            before
                .iter()
                .filter(|prior| !next_ids.contains(prior.id.as_str()))
                .map(|model| model.id.clone())
                .collect::<Vec<_>>()
        };
        // Select centrally for settings, CLI, and every other producer. Compare
        // complete serialized patches, without a separate full-order cutoff.
        // Metadata contributes the same bytes to either (entry, patch) tuple,
        // so the smaller patch also minimizes the complete ingress charge.
        let mut baseline = before_order;
        baseline.retain(|id| !deletes.contains(id));
        baseline.extend(upserts.iter().map(|row| row.id.clone()));
        let moves = if changed && !clear {
            cockpit_config::config::providers::ModelPlacement::between(&baseline, &after_order)
        } else {
            Vec::new()
        };
        let mut patch = Self {
            // Clear already supplies complete empty membership. Sending an
            // empty order as well can strand an otherwise fitting request.
            order: None,
            moves,
            clear,
            base_digest: Self::digest(before)?,
            upserts,
            updates,
            deletes,
        };
        if changed && !clear {
            let mut full = patch.clone();
            full.order = Some(after_order);
            full.moves.clear();
            if serde_json::to_vec(&full)?.len() <= serde_json::to_vec(&patch)?.len() {
                patch = full;
            }
        }
        Ok(patch)
    }

    /// Ordinary producers charge metadata and model intent together. If the
    /// fast representation does not fit, search all unique-ID move schedules
    /// against the remaining request bytes before reporting an oversized edit.
    pub fn between_for_entry(
        before: &[cockpit_config::config::providers::ModelEntry],
        after: &[cockpit_config::config::providers::ModelEntry],
        entry: &cockpit_config::config::providers::ProviderEntry,
    ) -> Result<Self, serde_json::Error> {
        let patch = Self::between(before, after)?;
        let mut metadata = entry.clone();
        metadata.models.clear();
        if serde_json::to_vec(&(&metadata, Some(&patch)))?.len()
            <= crate::MAX_OWNER_PROVIDER_ENTRY_BYTES
        {
            return Ok(patch);
        }
        let order = after.iter().map(|row| row.id.clone()).collect::<Vec<_>>();
        let next = order.iter().collect::<std::collections::BTreeSet<_>>();
        let mut baseline = before
            .iter()
            .filter(|row| next.contains(&row.id))
            .map(|row| row.id.clone())
            .collect::<Vec<_>>();
        baseline.extend(patch.upserts.iter().map(|row| row.id.clone()));
        let mut sparse = patch.clone();
        sparse.order = None;
        sparse.moves = vec![cockpit_config::config::providers::ModelPlacement {
            id: String::new(),
            after: None,
        }];
        let framing = serde_json::to_vec(&(&metadata, Some(&sparse)))?.len()
            - serde_json::to_vec(&sparse.moves)?.len();
        if let Some(budget) = crate::MAX_OWNER_PROVIDER_ENTRY_BYTES.checked_sub(framing)
            && let Some(moves) = cockpit_config::config::providers::ModelPlacement::find_fitting(
                &baseline,
                &order,
                &std::collections::BTreeSet::new(),
                budget,
                |_| Ok::<_, serde_json::Error>(true),
            )?
        {
            sparse.moves = moves;
            return Ok(sparse);
        }
        Ok(patch)
    }

    /// Preserve this layer's authored rows/edits while recording only the
    /// changes over the complete, revision-bound effective inventory.
    pub fn apply_to_layer(
        &self,
        effective: &[cockpit_config::config::providers::ModelEntry],
        layer: &mut cockpit_config::config::providers::ProviderEntry,
    ) -> Result<(), String> {
        let mut after = effective.to_vec();
        self.apply(&mut after)?;
        let replacements = self
            .upserts
            .iter()
            .map(|model| model.id.as_str())
            .chain(
                self.updates
                    .iter()
                    .filter(|update| update.replace)
                    .map(|update| update.id.as_str()),
            )
            .collect::<std::collections::BTreeSet<_>>();
        layer.models.retain(|model| {
            !self.deletes.contains(&model.id) && !replacements.contains(model.id.as_str())
        });
        layer.model_field_patches.retain(|model| {
            !self.deletes.contains(&model.id) && !replacements.contains(model.id.as_str())
        });
        for id in &replacements {
            let model = after
                .iter()
                .find(|model| model.id == *id)
                .expect("validated replacement row");
            layer.model_field_patches.push(
                cockpit_config::config::providers::ModelEntryFieldPatch::replacement(model)
                    .map_err(|error| error.to_string())?,
            );
        }
        for update in self.updates.iter().filter(|update| !update.replace) {
            if let Some(model) = layer.models.iter_mut().find(|model| model.id == update.id) {
                update
                    .evict_authored_fields(model)
                    .map_err(|error| error.to_string())?;
            }
            if let Some(prior) = layer
                .model_field_patches
                .iter_mut()
                .find(|prior| prior.id == update.id)
            {
                prior.extend(update);
            } else {
                layer.model_field_patches.push(update.clone());
            }
        }
        if self.clear {
            layer.models.clear();
            layer.model_field_patches.clear();
            layer.models_replace = true;
        }
        // Clear carries complete membership authority even without a wire
        // order. Erase old placements/tombstones and replace any prior order,
        // exactly as for an explicit empty order; none may resurrect rows.
        if self.clear
            || self.order.is_some()
            || (layer.model_order.is_some()
                && (!self.deletes.is_empty() || !self.upserts.is_empty() || !self.moves.is_empty()))
        {
            layer.model_order = Some(after.iter().map(|row| row.id.clone()).collect());
            layer.model_membership.placements.clear();
            let next = after
                .iter()
                .map(|row| row.id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            layer.model_membership.deletes = layer
                .model_membership
                .deletes
                .iter()
                .chain(&self.deletes)
                .filter(|id| !self.clear && !next.contains(id.as_str()))
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
        } else if !self.deletes.is_empty()
            || !self.upserts.is_empty()
            || !self.moves.is_empty()
            || self.updates.iter().any(|update| update.replace)
        {
            let next_ids = after
                .iter()
                .map(|row| row.id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let moved = layer
                .model_membership
                .placements
                .iter()
                .map(|p| p.id.as_str())
                .chain(self.moves.iter().map(|p| p.id.as_str()))
                .chain(self.upserts.iter().map(|row| row.id.as_str()))
                .chain(
                    self.updates
                        .iter()
                        .filter(|update| update.replace)
                        .map(|update| update.id.as_str()),
                )
                .collect::<std::collections::BTreeSet<_>>();
            let order = after.iter().map(|row| row.id.clone()).collect::<Vec<_>>();
            let mut placements =
                cockpit_config::config::providers::ModelPlacement::for_pinned_order(&order, &moved);
            // Preserve validated programs as well as canonical insertion
            // forests. On a fresh sparse layer this admits ANY incoming anchor
            // schedule. On an existing layer, disjoint pure-order programs can
            // be concatenated exactly without discarding previous pins. A
            // deletion touching a prior pin/anchor can invalidate the program.
            // Unrelated deletions commute with it and must not destroy a
            // fitting temporary-handle schedule.
            let old_pins = layer
                .model_membership
                .placements
                .iter()
                .map(|p| p.id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let can_append = old_pins.is_empty()
                || (layer.model_membership.placements.iter().all(|p| {
                    !self.deletes.contains(&p.id)
                        && !p.after.as_ref().is_some_and(|id| self.deletes.contains(id))
                }) && self.moves.iter().all(|p| !old_pins.contains(p.id.as_str())));
            if can_append
                && self.upserts.is_empty()
                && !self.updates.iter().any(|update| update.replace)
            {
                let mut program = layer.model_membership.placements.clone();
                program.extend(self.moves.iter().cloned());
                if serde_json::to_vec(&program)
                    .map_err(|error| error.to_string())?
                    .len()
                    <= serde_json::to_vec(&placements)
                        .map_err(|error| error.to_string())?
                        .len()
                {
                    placements = program;
                }
            }
            let deletes = layer
                .model_membership
                .deletes
                .iter()
                .chain(&self.deletes)
                .filter(|id| !next_ids.contains(id.as_str()))
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            layer.model_membership.deletes = deletes.into_iter().collect();
            layer.model_membership.placements = placements;
        }
        Ok(())
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
        if models
            .iter()
            .map(|row| &row.id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != models.len()
        {
            return Err("provider model inventory contains duplicate ids".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        for id in self
            .deletes
            .iter()
            .map(String::as_str)
            .chain(self.upserts.iter().map(|model| model.id.as_str()))
            .chain(self.updates.iter().map(|model| model.id.as_str()))
        {
            if !ids.insert(id) {
                return Err("provider model patch contains duplicate ids".into());
            }
        }
        if self.order.is_some() && !self.moves.is_empty() {
            return Err("provider model patch contains conflicting order operations".into());
        }
        if self.clear
            && (!self.deletes.is_empty()
                || !self.upserts.is_empty()
                || !self.updates.is_empty()
                || !self.moves.is_empty()
                || self.order.as_ref().is_some_and(|order| !order.is_empty()))
        {
            return Err("provider model clear contains other operations".into());
        }
        let mut moved = std::collections::BTreeSet::new();
        if self.moves.iter().any(|p| !moved.insert(&p.id)) {
            return Err("provider model patch contains duplicate order placements".into());
        }
        if self
            .deletes
            .iter()
            .any(|id| !models.iter().any(|row| &row.id == id))
        {
            return Err("provider model delete has no existing row".into());
        }
        let mut updated_models = if self.clear {
            Vec::new()
        } else {
            models.clone()
        };
        for update in &self.updates {
            let model = updated_models
                .iter_mut()
                .find(|model| model.id == update.id)
                .ok_or_else(|| "provider model field patch has no existing row".to_string())?;
            let mut value = serde_json::to_value(&*model).map_err(|error| error.to_string())?;
            update
                .apply_value(&mut value)
                .map_err(|error| error.to_string())?;
            *model = serde_json::from_value(value).map_err(|error| error.to_string())?;
        }
        if let Some(order) = &self.order {
            let expected = updated_models
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
        updated_models.retain(|model| !self.deletes.contains(&model.id));
        for model in &self.upserts {
            if let Some(prior) = updated_models.iter_mut().find(|prior| prior.id == model.id) {
                *prior = model.clone();
            } else {
                updated_models.push(model.clone());
            }
        }
        let mut moved_order = updated_models
            .iter()
            .map(|row| row.id.clone())
            .collect::<Vec<_>>();
        for placement in &self.moves {
            placement
                .apply(&mut moved_order, true)
                .map_err(|error| error.to_string())?;
        }
        let order = self.order.as_ref().unwrap_or(&moved_order);
        // Restore the requested order only after validating all membership.
        {
            let mut entries = updated_models
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
    fn model_patch_owned_values_are_evicted_before_a_replacement_value_is_persisted() {
        let mut own = ModelEntry {
            id: "same".into(),
            name: Some("old".repeat(60 * 1024)),
            ..Default::default()
        };
        own.extra
            .insert("owned".into(), serde_json::json!("x".repeat(20 * 1024)));
        let mut row = own.clone();
        row.extra.insert(
            "inherited".into(),
            serde_json::json!("z".repeat(190 * 1024)),
        );
        let before = vec![row];
        let mut after = before.clone();
        after[0].name = Some("new".repeat(60 * 1024));
        let mut layer = cockpit_config::config::providers::ProviderEntry {
            models: vec![own],
            ..Default::default()
        };
        let patch = ProviderModelPatch {
            base_digest: ProviderModelPatch::digest(&before).unwrap(),
            upserts: Vec::new(),
            updates: vec![
                cockpit_config::config::providers::ModelEntryFieldPatch::between(
                    &before[0], &after[0],
                )
                .unwrap(),
            ],
            deletes: Vec::new(),
            order: None,
            moves: Vec::new(),
            clear: false,
        };
        patch.apply_to_layer(&before, &mut layer).unwrap();
        assert!(
            layer.models[0].name.is_none(),
            "overwritten owned data must not survive beside its replacement"
        );
        assert!(
            serde_json::to_vec(&layer).unwrap().len() < crate::MAX_OWNER_PROVIDER_ENTRY_BYTES,
            "no duplicate old value or unchanged inherited extra in durable intent"
        );
        let mut cleared = after.clone();
        cleared[0].extra.clear();
        let patch = ProviderModelPatch {
            base_digest: ProviderModelPatch::digest(&after).unwrap(),
            upserts: Vec::new(),
            updates: vec![
                cockpit_config::config::providers::ModelEntryFieldPatch::between(
                    &after[0],
                    &cleared[0],
                )
                .unwrap(),
            ],
            deletes: Vec::new(),
            order: None,
            moves: Vec::new(),
            clear: false,
        };
        patch.apply_to_layer(&after, &mut layer).unwrap();
        assert!(
            layer.models[0].extra.is_empty(),
            "removed owned data must be evicted physically"
        );
        let mut actual = serde_json::to_value(&before[0]).unwrap();
        layer.model_field_patches[0]
            .apply_value(&mut actual)
            .unwrap();
        assert_eq!(actual, serde_json::to_value(&cleared[0]).unwrap());
    }

    #[test]
    fn model_patch_new_rows_replace_hidden_lower_images_without_inheriting_old_fields() {
        use cockpit_config::config::{
            WorkspaceConfigLayerSnapshot,
            providers::{ConfigDoc, ProviderEntry},
        };
        let visible = ModelEntry {
            id: "visible".into(),
            context_length: Some(4242),
            ..Default::default()
        };
        let hidden = ModelEntry {
            id: "hidden".into(),
            name: Some("stale hidden field".into()),
            favorite: true,
            ..Default::default()
        };
        let lower = ProviderEntry {
            url: "https://example.com".into(),
            models: vec![visible.clone(), hidden.clone()],
            ..Default::default()
        };
        let mut layer = ProviderEntry {
            url: lower.url.clone(),
            models: vec![hidden],
            model_order: Some(vec!["visible".into()]),
            ..Default::default()
        };
        let before = vec![visible.clone()];
        let after = vec![
            visible,
            ModelEntry {
                id: "hidden".into(),
                manual: true,
                ..Default::default()
            },
        ];
        ProviderModelPatch::between(&before, &after)
            .unwrap()
            .apply_to_layer(&before, &mut layer)
            .unwrap();
        assert!(
            !layer.models.iter().any(|model| model.id == "hidden"),
            "old hidden authored image is removed"
        );
        let snapshot = |entry: &ProviderEntry| WorkspaceConfigLayerSnapshot {
            origin: None,
            project_root: None,
            config_json: None,
            provider_files: vec![("p".into(), serde_json::to_vec(entry).unwrap())],
            effective_default_artifact_digest: None,
            digest: "layer".into(),
        };
        let actual = ConfigDoc::providers_from_workspace_layer_snapshots(&[
            snapshot(&lower),
            snapshot(&layer),
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_value(&actual.providers["p"].models).unwrap(),
            serde_json::to_value(&after).unwrap(),
            "new row cannot inherit hidden name/favorite/metadata"
        );
    }

    #[test]
    fn model_patch_large_composed_unchanged_inventory_stays_in_its_owner_layers() {
        let before = vec![ModelEntry {
            id: "same".into(),
            name: Some("unchanged ".repeat(48 * 1024)),
            ..Default::default()
        }];
        assert!(serde_json::to_vec(&before).unwrap().len() > crate::MAX_OWNER_PROVIDER_ENTRY_BYTES);
        let patch = ProviderModelPatch::between(&before, &before).unwrap();
        assert!(patch.upserts.is_empty() && patch.updates.is_empty());
        let mut layer = cockpit_config::config::providers::ProviderEntry::default();
        patch.apply_to_layer(&before, &mut layer).unwrap();
        assert!(
            layer.models.is_empty(),
            "unchanged composed rows must remain in their owning layers"
        );
        assert!(layer.model_field_patches.is_empty());
    }

    #[test]
    fn model_patch_large_composed_rows_remain_sparse_and_repeated_edits_accumulate() {
        let mut row = ModelEntry {
            id: "same".into(),
            name: Some("name".repeat(48 * 1024)),
            ..Default::default()
        };
        row.extra.insert(
            "owner_note".into(),
            serde_json::json!("owner".repeat(48 * 1024)),
        );
        let before = vec![row];
        assert!(serde_json::to_vec(&before).unwrap().len() > crate::MAX_OWNER_PROVIDER_ENTRY_BYTES);
        let mut after = before.clone();
        after[0].favorite = true;
        let patch = ProviderModelPatch::between(&before, &after).unwrap();
        assert!(
            serde_json::to_vec(&patch).unwrap().len() < 1024,
            "favorite delta never contains unchanged composed fields"
        );
        let mut layer = cockpit_config::config::providers::ProviderEntry::default();
        patch.apply_to_layer(&before, &mut layer).unwrap();
        assert!(
            layer.models.is_empty(),
            "durable sparse edit must not materialize inherited rows"
        );
        assert_eq!(layer.model_field_patches.len(), 1);
        let mut again = after.clone();
        again[0].context_length = Some(4242);
        ProviderModelPatch::between(&after, &again)
            .unwrap()
            .apply_to_layer(&after, &mut layer)
            .unwrap();
        assert_eq!(layer.model_field_patches.len(), 1, "same-row edits compose");
        assert_eq!(
            layer.model_field_patches[0].set["favorite"],
            serde_json::json!(true)
        );
        assert_eq!(
            layer.model_field_patches[0].set["context_length"],
            serde_json::json!(4242)
        );
        let mut actual = serde_json::to_value(&before[0]).unwrap();
        layer.model_field_patches[0]
            .apply_value(&mut actual)
            .unwrap();
        assert_eq!(actual, serde_json::to_value(&again[0]).unwrap());
        let mut invalid = ProviderModelPatch::between(&before, &after).unwrap();
        invalid.updates[0]
            .set
            .insert("id".into(), serde_json::json!("other"));
        let mut actual = before.clone();
        assert!(invalid.apply(&mut actual).unwrap_err().contains("identity"));
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(&before).unwrap(),
            "invalid fields make no changes"
        );
    }

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
        assert!(patch.upserts.is_empty(), "existing rows use field deltas");
        assert_eq!(patch.updates.len(), 1);
        assert_eq!(
            patch.updates[0].set,
            BTreeMap::from([("favorite".into(), serde_json::json!(true))])
        );
        assert!(patch.updates[0].remove.is_empty());
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
    #[test]
    fn model_patch_clear_without_wire_order_replaces_all_prior_membership_authority() {
        use cockpit_config::config::providers::{ModelPlacement, ProviderEntry};
        let before = vec![ModelEntry {
            id: "owned".into(),
            favorite: true,
            ..Default::default()
        }];
        let patch = ProviderModelPatch::between(&before, &[]).unwrap();
        assert!(patch.clear);
        assert!(patch.order.is_none());
        assert_eq!(serde_json::to_vec(&patch).unwrap().len(), 121);
        for prior_order in [None, Some(vec!["owned".into()])] {
            let mut layer = ProviderEntry {
                models: before.clone(),
                model_order: prior_order,
                ..Default::default()
            };
            layer.model_field_patches.push(
                cockpit_config::config::providers::ModelEntryFieldPatch::replacement(&before[0])
                    .unwrap(),
            );
            layer.model_membership.deletes = vec!["hidden".into()];
            layer.model_membership.placements = vec![ModelPlacement {
                id: "owned".into(),
                after: None,
            }];
            patch.apply_to_layer(&before, &mut layer).unwrap();
            assert!(layer.models.is_empty());
            assert!(layer.model_field_patches.is_empty());
            assert!(layer.models_replace);
            assert_eq!(layer.model_order, Some(Vec::new()));
            assert!(layer.model_membership.deletes.is_empty());
            assert!(layer.model_membership.placements.is_empty());
        }
        let mut stale = Vec::new();
        assert!(
            patch
                .apply(&mut stale)
                .unwrap_err()
                .contains("inventory changed")
        );
        assert!(stale.is_empty());
    }

    #[test]
    fn model_patch_sparse_membership_permutations_and_repeated_edits_preserve_all_rows() {
        use cockpit_config::config::{
            WorkspaceConfigLayerSnapshot,
            providers::{ConfigDoc, ProviderEntry},
        };
        fn permutations(ids: &mut [String], start: usize, all: &mut Vec<Vec<String>>) {
            if start == ids.len() {
                all.push(ids.to_vec());
                return;
            }
            for index in start..ids.len() {
                ids.swap(start, index);
                permutations(ids, start + 1, all);
                ids.swap(start, index);
            }
        }
        let lower = ProviderEntry {
            url: "https://example.com".into(),
            models: (0..5)
                .map(|i| ModelEntry {
                    id: format!("row-{i}-{}", "x".repeat(4096)),
                    name: Some(format!("owner-{i}")),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        let snapshot = |entry: &ProviderEntry| WorkspaceConfigLayerSnapshot {
            origin: None,
            project_root: None,
            config_json: None,
            provider_files: vec![("p".into(), serde_json::to_vec(entry).unwrap())],
            effective_default_artifact_digest: None,
            digest: "layer".into(),
        };
        let mut ids = lower
            .models
            .iter()
            .map(|row| row.id.clone())
            .collect::<Vec<_>>();
        let mut orders = Vec::new();
        permutations(&mut ids, 0, &mut orders);
        let mut layer = ProviderEntry {
            url: lower.url.clone(),
            ..Default::default()
        };
        let mut before = lower.models.clone();
        for order in orders {
            let after = order
                .iter()
                .map(|id| {
                    lower
                        .models
                        .iter()
                        .find(|row| &row.id == id)
                        .unwrap()
                        .clone()
                })
                .collect::<Vec<_>>();
            let patch = ProviderModelPatch::between(&before, &after).unwrap();
            // Full orders above 16 KiB are now permitted. Whichever form is
            // selected must cost no more than the alternative complete patch.
            let mut alternative = patch.clone();
            if patch.order.is_some() {
                alternative.order = None;
                alternative.moves = cockpit_config::config::providers::ModelPlacement::between(
                    &before.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
                    &order,
                );
            } else if before.iter().map(|row| &row.id).ne(order.iter()) {
                alternative.order = Some(order.clone());
                alternative.moves.clear();
            }
            assert!(
                serde_json::to_vec(&patch).unwrap().len()
                    <= serde_json::to_vec(&alternative).unwrap().len()
            );
            assert!(patch.upserts.is_empty() && patch.updates.is_empty());
            let mut applied = before.clone();
            patch.apply(&mut applied).unwrap();
            assert_eq!(
                serde_json::to_value(&applied).unwrap(),
                serde_json::to_value(&after).unwrap()
            );
            patch.apply_to_layer(&before, &mut layer).unwrap();
            assert!(
                layer.models.is_empty() && layer.model_field_patches.is_empty(),
                "reorder never materializes inherited rows"
            );
            let actual = ConfigDoc::providers_from_workspace_layer_snapshots(&[
                snapshot(&lower),
                snapshot(&layer),
            ])
            .unwrap();
            assert_eq!(
                serde_json::to_value(&actual.providers["p"].models).unwrap(),
                serde_json::to_value(&after).unwrap(),
                "cumulative durable reorder must preserve every exact row"
            );
            before = after;
        }
        // Moving one row across the entire catalog takes one operation in
        // either direction, including IDs longer than ordinary catalog IDs.
        let mut rotated = before.clone();
        rotated.rotate_left(1);
        let patch = ProviderModelPatch::between(&before, &rotated).unwrap();
        assert_eq!(patch.moves.len(), 1);
        let reverse = ProviderModelPatch::between(&rotated, &before).unwrap();
        assert_eq!(reverse.moves.len(), 1);
        let encoded = serde_json::to_vec(&patch).unwrap();
        let decoded: ProviderModelPatch = serde_json::from_slice(&encoded).unwrap();
        let mut actual = before.clone();
        decoded.apply(&mut actual).unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(rotated).unwrap()
        );
    }

    #[test]
    fn model_patch_non_immediate_program_preserves_tombstones_and_existing_pins() {
        use cockpit_config::config::{
            WorkspaceConfigLayerSnapshot,
            providers::{ConfigDoc, ModelPlacement, ProviderEntry},
        };
        let ids = ["a".into(), "b".repeat(900), "c".into(), "d".repeat(900)];
        let rows = ids
            .iter()
            .enumerate()
            .map(|(i, id)| ModelEntry {
                id: id.clone(),
                name: Some(format!("independent-{i}")),
                favorite: i % 2 == 0,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let snapshot = |entry: &ProviderEntry| WorkspaceConfigLayerSnapshot {
            origin: None,
            project_root: None,
            config_json: None,
            provider_files: vec![("p".into(), serde_json::to_vec(entry).unwrap())],
            effective_default_artifact_digest: None,
            digest: "layer".into(),
        };
        let mut lower = ProviderEntry {
            models: rows.clone(),
            ..Default::default()
        };
        lower.models.push(ModelEntry {
            id: "deleted-inherited".into(),
            ..Default::default()
        });
        let mut layer = ProviderEntry::default();
        layer
            .model_membership
            .deletes
            .push("deleted-inherited".into());
        let after = [1, 0, 3, 2].map(|i| rows[i].clone());
        let mut patch = ProviderModelPatch::between(&rows, &after).unwrap();
        patch.order = None;
        // `c` is a temporary cheap anchor: its final position is AFTER `a`.
        // Rewriting this as `a after b` duplicates the long inherited b ID.
        patch.moves = vec![
            ModelPlacement {
                id: ids[0].clone(),
                after: Some(ids[2].clone()),
            },
            ModelPlacement {
                id: ids[2].clone(),
                after: Some(ids[3].clone()),
            },
        ];
        let mut applied = rows.clone();
        patch.apply(&mut applied).unwrap();
        assert_eq!(
            serde_json::to_value(&applied).unwrap(),
            serde_json::to_value(&after).unwrap()
        );
        patch.apply_to_layer(&rows, &mut layer).unwrap();
        assert_eq!(
            layer.model_membership.placements, patch.moves,
            "retain a smaller valid non-immediate program"
        );
        assert_eq!(layer.model_membership.deletes, ["deleted-inherited"]);
        let merged = ConfigDoc::providers_from_workspace_layer_snapshots(&[
            snapshot(&lower),
            snapshot(&layer),
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_value(&merged.providers["p"].models).unwrap(),
            serde_json::to_value(&after).unwrap()
        );
        let mut next = after.to_vec();
        next.rotate_left(1);
        let next_patch = ProviderModelPatch::between(&after, &next).unwrap();
        let previous_pins = layer
            .model_membership
            .placements
            .iter()
            .map(|p| p.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        next_patch.apply_to_layer(&after, &mut layer).unwrap();
        assert!(layer.model_order.is_none());
        let actual_pins = layer
            .model_membership
            .placements
            .iter()
            .map(|p| p.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            previous_pins.is_subset(&actual_pins),
            "never discard old pins"
        );
        assert_eq!(layer.model_membership.deletes, ["deleted-inherited"]);
        let merged = ConfigDoc::providers_from_workspace_layer_snapshots(&[
            snapshot(&lower),
            snapshot(&layer),
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_value(&merged.providers["p"].models).unwrap(),
            serde_json::to_value(&next).unwrap()
        );
        assert!(layer.models.is_empty() && layer.model_field_patches.is_empty());
    }

    #[test]
    fn byte_bounded_large_reverse_selects_fitting_full_order_after_sparse_lower_bound() {
        let before = (0..10_000)
            .map(|i| ModelEntry {
                id: format!("row-{i:05}"),
                name: Some(format!("image-{i}")),
                favorite: i % 7 == 0,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let mut after = before.clone();
        after.reverse();
        let patch = ProviderModelPatch::between(&before, &after).unwrap();
        assert!(patch.upserts.is_empty() && patch.updates.is_empty() && patch.moves.is_empty());
        assert_eq!(
            patch.order.as_ref().unwrap(),
            &after.iter().map(|row| row.id.clone()).collect::<Vec<_>>()
        );
        assert!(serde_json::to_vec(&patch).unwrap().len() < crate::MAX_OWNER_PROVIDER_ENTRY_BYTES);
        let mut actual = before.clone();
        patch.apply(&mut actual).unwrap();
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&after).unwrap()
        );
        let mut layer = cockpit_config::config::providers::ProviderEntry::default();
        patch.apply_to_layer(&before, &mut layer).unwrap();
        assert_eq!(layer.model_order, patch.order);
        assert!(layer.models.is_empty() && layer.model_field_patches.is_empty());
        assert!(serde_json::to_vec(&layer).unwrap().len() < crate::MAX_OWNER_PROVIDER_ENTRY_BYTES);
    }

    #[test]
    fn model_patch_sparse_membership_invalid_operations_make_no_changes() {
        use cockpit_config::config::providers::ModelPlacement;
        let before = (0..5)
            .map(|i| ModelEntry {
                id: format!("row-{i}-{}", "x".repeat(4096)),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let mut after = before.clone();
        after.rotate_left(1);
        let valid = ProviderModelPatch::between(&before, &after).unwrap();
        let mut variants = Vec::new();
        let mut invalid = valid.clone();
        invalid.moves[0].after = Some("missing".into());
        variants.push(invalid);
        let mut invalid = valid.clone();
        invalid.moves[0].id = "missing".into();
        variants.push(invalid);
        let mut invalid = valid.clone();
        invalid.moves.push(invalid.moves[0].clone());
        variants.push(invalid);
        let mut invalid = valid.clone();
        invalid.moves[0] = ModelPlacement {
            id: before[0].id.clone(),
            after: Some(before[0].id.clone()),
        };
        variants.push(invalid);
        let mut invalid = valid.clone();
        invalid.clear = true;
        variants.push(invalid);
        let mut invalid = valid.clone();
        invalid.order = Some(after.iter().map(|row| row.id.clone()).collect());
        variants.push(invalid);
        for invalid in variants {
            let mut actual = before.clone();
            assert!(invalid.apply(&mut actual).is_err());
            assert_eq!(
                serde_json::to_value(&actual).unwrap(),
                serde_json::to_value(&before).unwrap(),
                "invalid order/membership is atomic"
            );
            let mut layer = cockpit_config::config::providers::ProviderEntry::default();
            let old = serde_json::to_value(&layer).unwrap();
            assert!(invalid.apply_to_layer(&before, &mut layer).is_err());
            assert_eq!(
                serde_json::to_value(&layer).unwrap(),
                old,
                "invalid intent never mutates authored state"
            );
        }
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

#[cfg(test)]
mod request_budget_tests {
    use super::*;
    use cockpit_config::config::providers::{ModelEntry, ProviderEntry};

    #[test]
    fn model_patch_complete_request_budget_searches_beyond_eager_inventory_size() {
        let ids: [String; 9] = [
            "u".into(),
            "v".into(),
            "w".into(),
            "a".into(),
            "B".repeat(900),
            "c".into(),
            "D".repeat(900),
            "e".into(),
            "F".repeat(900),
        ];
        let before = ids
            .into_iter()
            .enumerate()
            .map(|(i, id)| ModelEntry {
                id,
                name: Some(format!("whole-image-{i}")),
                favorite: i % 2 == 0,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let after = [0, 1, 2, 4, 3, 7, 6, 5, 8].map(|i| before[i].clone());
        let fast = ProviderModelPatch::between(&before, &after).unwrap();
        let mut metadata = ProviderEntry {
            name: Some(String::new()),
            ..Default::default()
        };
        let bytes = serde_json::to_vec(&(&metadata, Some(&fast))).unwrap().len();
        metadata.name = Some("n".repeat(crate::MAX_OWNER_PROVIDER_ENTRY_BYTES - bytes + 200));
        assert!(
            serde_json::to_vec(&(&metadata, Some(&fast))).unwrap().len()
                > crate::MAX_OWNER_PROVIDER_ENTRY_BYTES
        );
        let fitting = ProviderModelPatch::between_for_entry(&before, &after, &metadata).unwrap();
        assert!(
            serde_json::to_vec(&(&metadata, Some(&fitting)))
                .unwrap()
                .len()
                <= crate::MAX_OWNER_PROVIDER_ENTRY_BYTES
        );
        let mut actual = before;
        fitting.apply(&mut actual).unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(after).unwrap()
        );
    }
}

#[cfg(test)]
mod durable_full_order_tests {
    use super::*;
    use cockpit_config::config::{
        WorkspaceConfigLayerSnapshot,
        providers::{ConfigDoc, ModelEntry, ModelPlacement, ProviderEntry},
    };

    #[test]
    fn model_patch_full_order_retains_tombstones_and_surviving_pin_authority() {
        let rows = ["a", "b", "c", "gone"].map(|id| ModelEntry {
            id: id.into(),
            name: Some(format!("image-{id}")),
            ..Default::default()
        });
        let after = [rows[2].clone(), rows[0].clone()];
        let mut patch = ProviderModelPatch::between(&rows[..3], &after).unwrap();
        patch.order = Some(after.iter().map(|row| row.id.clone()).collect());
        patch.moves.clear();
        let lower = ProviderEntry {
            models: rows.to_vec(),
            ..Default::default()
        };
        let mut layer = ProviderEntry::default();
        layer.model_membership.deletes.push("gone".into());
        layer.model_membership.placements.push(ModelPlacement {
            id: "a".into(),
            after: None,
        });
        patch.apply_to_layer(&rows[..3], &mut layer).unwrap();
        assert_eq!(layer.model_membership.deletes, ["b", "gone"]);
        assert_eq!(layer.model_order, Some(vec!["c".into(), "a".into()]));
        let snapshot = |entry: &ProviderEntry| WorkspaceConfigLayerSnapshot {
            origin: None,
            project_root: None,
            config_json: None,
            provider_files: vec![("p".into(), serde_json::to_vec(entry).unwrap())],
            effective_default_artifact_digest: None,
            digest: "layer".into(),
        };
        let read = ConfigDoc::providers_from_workspace_layer_snapshots(&[
            snapshot(&lower),
            snapshot(&layer),
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_value(&read.providers["p"].models).unwrap(),
            serde_json::to_value(&after).unwrap()
        );
    }
}

#[cfg(test)]
mod large_prefix_admission_tests {
    use super::*;
    use cockpit_config::config::providers::{ModelEntry, ProviderEntry};

    #[test]
    fn model_patch_complete_request_budget_large_unchanged_prefix_meets_rpc_deadline() {
        let ids = (0..10_000)
            .map(|i| format!("prefix-{i:05}"))
            .chain([
                "a".into(),
                "B".repeat(900),
                "c".into(),
                "D".repeat(900),
                "e".into(),
                "F".repeat(900),
            ])
            .collect::<Vec<_>>();
        let before = ids
            .into_iter()
            .map(|id| ModelEntry {
                id,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let source = ProviderEntry {
            models: before.clone(),
            ..Default::default()
        };
        assert!(serde_json::to_vec(&source).unwrap().len() < crate::MAX_OWNER_PROVIDER_ENTRY_BYTES);
        let after = before[..10_000]
            .iter()
            .cloned()
            .chain([1, 0, 4, 3, 2, 5].map(|i| before[10_000 + i].clone()))
            .collect::<Vec<_>>();
        let fast = ProviderModelPatch::between(&before, &after).unwrap();
        let mut metadata = ProviderEntry {
            name: Some(String::new()),
            ..Default::default()
        };
        let bytes = serde_json::to_vec(&(&metadata, Some(&fast))).unwrap().len();
        metadata.name = Some("n".repeat(crate::MAX_OWNER_PROVIDER_ENTRY_BYTES - bytes + 200));
        assert!(
            serde_json::to_vec(&(&metadata, Some(&fast))).unwrap().len()
                > crate::MAX_OWNER_PROVIDER_ENTRY_BYTES
        );
        let input = before.clone();
        let target = after.clone();
        let header = metadata.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ =
                send.send(ProviderModelPatch::between_for_entry(&input, &target, &header).unwrap());
        });
        let patch = receive
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect(
                "a fitting complete request must finish inside the30-second owner RPC deadline",
            );
        worker.join().unwrap();
        assert!(
            serde_json::to_vec(&(&metadata, Some(&patch)))
                .unwrap()
                .len()
                <= crate::MAX_OWNER_PROVIDER_ENTRY_BYTES
        );
        let mut applied = before;
        patch.apply(&mut applied).unwrap();
        assert_eq!(
            serde_json::to_value(applied).unwrap(),
            serde_json::to_value(after).unwrap()
        );
    }
}
