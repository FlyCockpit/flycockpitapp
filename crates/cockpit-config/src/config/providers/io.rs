use super::*;

use std::collections::HashMap;

/// How an atomic active-model mutation should treat an existing effective
/// default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveModelWriteMode {
    /// Replace the effective default, even when one already exists.
    Replace,
    /// Write only when the effective layered config has no default.
    InitializeIfMissing,
}

/// Read+write a provider config layer while preserving fields cockpit
/// doesn't model. Global provider metadata lives in `config.json`; provider
/// entries live in sibling `providers/*.json` files.
pub struct ConfigDoc {
    pub path: PathBuf,
    pub(crate) raw: Value,
    pub(crate) originally_loaded_providers: BTreeMap<String, ProviderEntry>,
}

thread_local! {
    static LOAD_EFFECTIVE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub fn reset_load_effective_call_count() {
    LOAD_EFFECTIVE_CALLS.with(|calls| calls.set(0));
}

pub fn load_effective_call_count() -> usize {
    LOAD_EFFECTIVE_CALLS.with(std::cell::Cell::get)
}

/// Advance and return the per-thread effective-resolution generation.
///
/// Every effective resolution — including the ones journal recovery and the
/// effective-default mutation perform under the lock — stamps a distinct
/// generation so a caller can order snapshots deterministically.
///
/// The counter is thread-local and monotonic *per thread*, so it orders
/// snapshots within one resolution context, not across threads. It is also the
/// counter [`load_effective_call_count`] exposes, so any code path that
/// resolves the effective config now advances it: a test asserting an exact
/// call count must account for the resolutions the mutation and recovery paths
/// perform under the lock, not only its own `load_effective` calls.
pub(crate) fn next_load_effective_generation() -> u64 {
    LOAD_EFFECTIVE_CALLS.with(|calls| {
        let next = calls.get().saturating_add(1);
        calls.set(next);
        next as u64
    })
}

impl ConfigDoc {
    /// Load the effective provider config for `cwd` by merging every
    /// applicable config layer from least-specific to most-specific.
    /// `COCKPIT_CONFIG` supplies the only config.json path when set; provider
    /// files live beside that file under `providers/`.
    pub fn load_effective(cwd: &Path) -> ProvidersConfig {
        // Layer discovery happens exactly once per load; recovery, masking,
        // and the merge all reuse the same resolved list.
        let paths = crate::config::dirs::config_file_paths_for_load(cwd);
        Self::load_effective_from_paths(&paths)
    }

    /// Resolve the effective config from an already-discovered layer list.
    ///
    /// Journal recovery is an effective-config resolution barrier: a fresh
    /// client never observes a half-committed default. Config-only journals
    /// are finished here; a session-bearing journal needs daemon session
    /// authority, so its layer is *masked* with the recorded prior bytes
    /// instead until startup/attach can converge it.
    pub fn load_effective_from_paths(paths: &[PathBuf]) -> ProvidersConfig {
        match Self::try_load_effective_from_paths(paths) {
            Ok(providers) => providers,
            Err(error) => {
                // Infallible callers still must not observe a half-committed
                // default. Degrade to the safest resolution available: drop
                // `active_model` from every unmaskable layer so the default
                // falls back to a layer that is not mid-transaction.
                tracing::error!(
                    %error,
                    "serving a degraded effective config: a pending default-model transaction could not be masked"
                );
                let generation = next_load_effective_generation();
                let (mut masks, unmaskable) =
                    crate::config::effective_default::masked_layers(paths);
                for path in unmaskable {
                    masks.insert(path, b"{}\n".to_vec());
                }
                Self::providers_from_paths_with_masks(paths, &masks)
                    .with_resolution_generation(generation)
            }
        }
    }

    /// Fallible effective resolution.
    ///
    /// Fails closed when a layer has a pending effective-default journal that
    /// can neither be recovered nor masked: its bytes may already hold the
    /// target of an unfinished transaction, and merging them would expose a
    /// half-committed default. Daemon-facing loads use this so attach reports
    /// a typed error instead of serving an ambiguous snapshot.
    pub fn try_load_effective_from_paths(paths: &[PathBuf]) -> Result<ProvidersConfig> {
        use crate::config::effective_default;

        effective_default::recover_layer_journals(
            paths,
            effective_default::JournalRecovery::read_only(),
        )
        .context("recovering a pending default-model transaction")?;
        let generation = next_load_effective_generation();
        let (mut masks, mut unmaskable) = effective_default::masked_layers(paths);
        let mut merged = Self::providers_from_paths_with_masks(paths, &masks);
        // The probe and the merge both ran outside the cross-process mutation
        // lock. A journal that appeared in between would have been merged
        // unmasked, so re-check once and redo the merge if the picture moved.
        if masks.is_empty()
            && unmaskable.is_empty()
            && effective_default::any_journal_present(paths)
        {
            let reprobed = effective_default::masked_layers(paths);
            masks = reprobed.0;
            unmaskable = reprobed.1;
            if !masks.is_empty() {
                merged = Self::providers_from_paths_with_masks(paths, &masks);
            }
        }
        if !unmaskable.is_empty() {
            anyhow::bail!(
                "{} configuration layer(s) have a pending default-model transaction that cannot be                  masked; run `cockpit doctor` to inspect the journal",
                unmaskable.len()
            );
        }
        Ok(merged.with_resolution_generation(generation))
    }

    pub fn providers_from_paths(paths: &[PathBuf]) -> ProvidersConfig {
        Self::providers_from_paths_with_masks(paths, &HashMap::new())
    }

    /// Masked merge that is **not** a counted effective resolution.
    ///
    /// Pre-attach bootstrap and export read config without resolving
    /// credentials or stamping a resolution generation — that budget is
    /// daemon-side and load-count-gated. They still must not observe a
    /// half-committed default, so they mask pending layers here without
    /// running recovery or consuming a load.
    pub fn providers_from_paths_masked(paths: &[PathBuf]) -> ProvidersConfig {
        use crate::config::effective_default;

        // Same fail-closed rule as the counted path: a layer whose pending
        // journal cannot be masked is degraded to an empty object, because its
        // bytes may already hold the target of an unfinished transaction.
        fn masks_for(paths: &[PathBuf]) -> (HashMap<PathBuf, Vec<u8>>, bool) {
            let (mut masks, unmaskable) = effective_default::masked_layers(paths);
            let degraded = !unmaskable.is_empty();
            for path in unmaskable {
                tracing::error!(
                    "masking a pending default-model transaction failed; serving this layer as empty"
                );
                masks.insert(path, b"{}\n".to_vec());
            }
            (masks, degraded)
        }

        let (masks, _) = masks_for(paths);
        let mut merged = Self::providers_from_paths_with_masks(paths, &masks);
        // The probe and the merge both ran outside the cross-process mutation
        // lock, so a journal that appeared in between would have been merged
        // unmasked. Re-check once and redo the merge if the picture moved.
        if masks.is_empty() && effective_default::any_journal_present(paths) {
            let (masks, _) = masks_for(paths);
            if !masks.is_empty() {
                merged = Self::providers_from_paths_with_masks(paths, &masks);
            }
        }
        merged
    }

    /// Merge layers, substituting `masks[path]` for a layer's `config.json`
    /// bytes. Provider files beside a masked layer are unaffected — only the
    /// layer-wide metadata (including `active_model`) is masked.
    pub(crate) fn providers_from_paths_with_masks(
        paths: &[PathBuf],
        masks: &HashMap<PathBuf, Vec<u8>>,
    ) -> ProvidersConfig {
        let mut merged = Value::Object(Map::new());
        for path in paths {
            let mask = masks.get(path).map(Vec::as_slice);
            if mask.is_none() && !path.exists() {
                merge_provider_files_for_layer(&mut merged, path);
                continue;
            }
            match Self::load_with_mask(path, mask) {
                Ok(doc) => {
                    let mut layer = doc.raw.clone();
                    warn_inline_providers_ignored(path, &layer);
                    warn_malformed_provider_layer_metadata(path, &layer);
                    if let Some(obj) = layer.as_object_mut() {
                        obj.remove("providers");
                    }
                    deep_merge_value(&mut merged, &layer);
                }
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skipping malformed config layer");
                }
            }
            merge_provider_files_for_layer(&mut merged, path);
        }
        Self {
            path: PathBuf::new(),
            raw: merged,
            originally_loaded_providers: BTreeMap::new(),
        }
        .providers()
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::load_with_mask(path, None)
    }

    fn load_with_mask(path: &Path, mask: Option<&[u8]>) -> Result<Self> {
        let path = config_path_for_layer_path(path);
        let raw_str = match mask {
            Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            None if path.exists() => std::fs::read_to_string(&path)
                .with_context(|| format!("reading config.json at {}", path.display()))?,
            None => "{}".to_string(),
        };
        let raw: Value = if raw_str.trim().is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_str(&raw_str)
                .with_context(|| format!("parsing config.json at {}", path.display()))?
        };
        let raw = match raw {
            Value::Object(_) => raw,
            other => {
                anyhow::bail!("expected config.json root to be an object, found {other:?}")
            }
        };
        let mut providers = ProvidersConfig::default();
        load_provider_files_into_config(&path, &mut providers);
        Ok(Self {
            path,
            raw,
            originally_loaded_providers: providers.providers,
        })
    }

    /// Extract the typed view of layer-wide provider metadata plus provider
    /// files from this document's sibling `providers/` directory.
    pub fn providers(&self) -> ProvidersConfig {
        let mut cfg = ProvidersConfig::default();
        warn_inline_providers_ignored(&self.path, &self.raw);
        if let Some(v) = self.raw.get("on_unlisted_models_fetch")
            && let Some(parsed) = parse_provider_metadata_field::<OnUnlistedModelsFetch>(
                &self.path,
                "on_unlisted_models_fetch",
                v,
            )
        {
            cfg.on_unlisted_models_fetch = Some(parsed);
        }
        if let Some(v) = self.raw.get("active_model")
            && let Some(parsed) =
                parse_provider_metadata_field::<ActiveModelRef>(&self.path, "active_model", v)
        {
            cfg.active_model = Some(parsed);
        }
        if let Some(v) = self.raw.get("category_defaults")
            && let Some(parsed) = parse_provider_metadata_field::<BTreeMap<String, ProviderModelRef>>(
                &self.path,
                "category_defaults",
                v,
            )
        {
            cfg.category_defaults = parsed;
        }
        if !self.path.as_os_str().is_empty() {
            cfg.providers.clone_from(&self.originally_loaded_providers);
        } else if let Some(map) = self.raw.get("providers").and_then(Value::as_object) {
            for (id, v) in map {
                if let Some(obj) = v.as_object()
                    && let Err(e) = reject_legacy_redact_fields(id, obj)
                {
                    tracing::warn!(provider = %id, error = %e, "skipping malformed provider entry");
                    continue;
                }
                match serde_json::from_value::<ProviderEntry>(v.clone()) {
                    Ok(entry) => {
                        cfg.providers.insert(id.clone(), entry);
                    }
                    Err(error) => {
                        tracing::warn!(
                            path = %self.path.display(),
                            provider = %id,
                            %error,
                            "skipping malformed inline provider entry"
                        );
                    }
                }
            }
        }
        cfg
    }

    /// Replace the typed provider layer and persist to disk.
    pub fn write(&mut self, cfg: &ProvidersConfig) -> Result<()> {
        let originally_loaded = self.providers();
        let _lock = ConfigMutationLock::acquire(&self.path)?;
        let mut current = Self::load(&self.path)?;
        current.set_layer_metadata_raw(
            cfg,
            originally_loaded.on_unlisted_models_fetch != cfg.on_unlisted_models_fetch,
            originally_loaded.category_defaults != cfg.category_defaults,
        )?;
        current.persist_raw_unlocked()?;
        current.merge_provider_files_unlocked(&self.originally_loaded_providers, &cfg.providers)?;
        self.refresh_from_disk_unlocked()
    }

    /// Persist layer-wide provider metadata.
    ///
    /// `active_model` is deliberately absent: it is layer-wide *default*
    /// policy, not provider-owned metadata, and is only ever written by
    /// [`crate::config::effective_default::mutate_effective_default`].
    fn set_layer_metadata_raw(
        &mut self,
        cfg: &ProvidersConfig,
        replace_unlisted_policy: bool,
        replace_category_defaults: bool,
    ) -> Result<()> {
        let obj = self.raw.as_object_mut().expect("root is an object");
        obj.remove("providers");
        if replace_unlisted_policy {
            match cfg.on_unlisted_models_fetch {
                Some(v) => {
                    let s =
                        serde_json::to_value(v).context("serializing on_unlisted_models_fetch")?;
                    obj.insert("on_unlisted_models_fetch".to_string(), s);
                }
                None => {
                    obj.remove("on_unlisted_models_fetch");
                }
            }
        }
        if replace_category_defaults {
            if cfg.category_defaults.is_empty() {
                obj.remove("category_defaults");
            } else {
                let value = serde_json::to_value(&cfg.category_defaults)
                    .context("serializing category_defaults")?;
                obj.insert("category_defaults".to_string(), value);
            }
        }
        Ok(())
    }

    pub fn write_provider_models(
        &mut self,
        provider_id: &str,
        models: &[ModelEntry],
        models_fetched_at: Option<chrono::DateTime<chrono::Utc>>,
        model_catalog: ProviderModelCatalog,
        last_model_fetch: Option<ModelFetchStatus>,
    ) -> Result<()> {
        let _lock = ConfigMutationLock::acquire(&self.path)?;
        let mut provider = self.provider_raw_object(provider_id)?;
        provider.insert(
            "models".to_string(),
            serde_json::to_value(models).context("serializing provider models")?,
        );
        match models_fetched_at.as_ref() {
            Some(ts) => {
                provider.insert(
                    "models_fetched_at".to_string(),
                    serde_json::to_value(ts).context("serializing models_fetched_at")?,
                );
            }
            None => {
                provider.remove("models_fetched_at");
            }
        }
        if model_catalog.is_live() {
            provider.remove("model_catalog");
        } else {
            provider.insert(
                "model_catalog".to_string(),
                serde_json::to_value(model_catalog).context("serializing model_catalog")?,
            );
        }
        match last_model_fetch {
            Some(status) => {
                provider.insert(
                    "last_model_fetch".to_string(),
                    serde_json::to_value(status).context("serializing last_model_fetch")?,
                );
            }
            None => {
                provider.remove("last_model_fetch");
            }
        }
        self.persist_provider_raw_unlocked(provider_id, provider)?;
        self.refresh_from_disk_unlocked()
    }

    pub fn write_unlisted_models_policy(
        &mut self,
        on_unlisted_models_fetch: Option<OnUnlistedModelsFetch>,
    ) -> Result<()> {
        let _lock = ConfigMutationLock::acquire(&self.path)?;
        let mut current = Self::load(&self.path)?;
        let obj = current.raw.as_object_mut().expect("root is an object");
        match on_unlisted_models_fetch {
            Some(v) => {
                let value =
                    serde_json::to_value(v).context("serializing on_unlisted_models_fetch")?;
                obj.insert("on_unlisted_models_fetch".to_string(), value);
            }
            None => {
                obj.remove("on_unlisted_models_fetch");
            }
        }
        current.persist_raw_unlocked()?;
        self.refresh_from_disk_unlocked()
    }

    pub fn write_model_favorite(
        &mut self,
        provider_id: &str,
        model_id: &str,
        favorite: bool,
    ) -> Result<()> {
        let _lock = ConfigMutationLock::acquire(&self.path)?;
        let mut provider = self.provider_raw_object(provider_id)?;
        let models = provider
            .entry("models".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if !models.is_array() {
            *models = Value::Array(Vec::new());
        }
        let models = models.as_array_mut().expect("models reset to array");
        let mut found = false;
        for model in models.iter_mut() {
            let Some(model_obj) = model.as_object_mut() else {
                continue;
            };
            if model_obj.get("id").and_then(Value::as_str) == Some(model_id) {
                model_obj.insert("favorite".to_string(), Value::Bool(favorite));
                found = true;
                break;
            }
        }
        if !found {
            let mut model = Map::new();
            model.insert("id".to_string(), Value::String(model_id.to_string()));
            model.insert("favorite".to_string(), Value::Bool(favorite));
            models.push(Value::Object(model));
        }
        self.persist_provider_raw_unlocked(provider_id, provider)?;
        self.refresh_from_disk_unlocked()
    }

    pub fn write_model_wizard_fields(
        &mut self,
        provider_id: &str,
        model: &ModelEntry,
    ) -> Result<()> {
        let _lock = ConfigMutationLock::acquire(&self.path)?;
        let mut provider = self.provider_raw_object(provider_id)?;
        let models = provider
            .entry("models".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if !models.is_array() {
            *models = Value::Array(Vec::new());
        }
        let models = models.as_array_mut().expect("models reset to array");
        let serialized = serde_json::to_value(model).context("serializing model wizard fields")?;
        let Value::Object(serialized) = serialized else {
            unreachable!("ModelEntry serializes to object");
        };
        let mut found = false;
        for raw_model in models.iter_mut() {
            let Some(model_obj) = raw_model.as_object_mut() else {
                continue;
            };
            if model_obj.get("id").and_then(Value::as_str) == Some(model.id.as_str()) {
                for key in MODEL_WIZARD_MODEL_FIELD_KEYS {
                    model_obj.remove(*key);
                    if let Some(value) = serialized.get(*key) {
                        model_obj.insert((*key).to_string(), value.clone());
                    }
                }
                found = true;
                break;
            }
        }
        if !found {
            let mut model_obj = Map::new();
            model_obj.insert("id".to_string(), Value::String(model.id.clone()));
            for key in MODEL_WIZARD_MODEL_FIELD_KEYS {
                if let Some(value) = serialized.get(*key) {
                    model_obj.insert((*key).to_string(), value.clone());
                }
            }
            models.push(Value::Object(model_obj));
        }
        self.persist_provider_raw_unlocked(provider_id, provider)?;
        self.refresh_from_disk_unlocked()
    }

    fn persist_raw_unlocked(&self) -> Result<()> {
        let pretty = serde_json::to_string_pretty(&self.raw).context("serializing config.json")?;
        atomic_write(&self.path, format!("{pretty}\n").as_bytes())?;
        Ok(())
    }

    fn provider_raw_object(&self, provider_id: &str) -> Result<Map<String, Value>> {
        let path = provider_file_path_for_config(&self.path, provider_id)?;
        if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("reading provider config at {}", path.display()))?;
            let value: Value = if raw.trim().is_empty() {
                Value::Object(Map::new())
            } else {
                serde_json::from_str(&raw)
                    .with_context(|| format!("parsing provider config at {}", path.display()))?
            };
            return match value {
                Value::Object(map) => Ok(map),
                other => anyhow::bail!(
                    "expected provider config root to be an object at {}, found {other:?}",
                    path.display()
                ),
            };
        }

        Ok(Map::new())
    }

    fn persist_provider_raw_unlocked(
        &self,
        provider_id: &str,
        provider: Map<String, Value>,
    ) -> Result<()> {
        let path = provider_file_path_for_config(&self.path, provider_id)?;
        let pretty = serde_json::to_string_pretty(&Value::Object(provider))
            .context("serializing provider")?;
        atomic_write(&path, format!("{pretty}\n").as_bytes())?;
        Ok(())
    }

    fn merge_provider_files_unlocked(
        &self,
        originally_loaded: &BTreeMap<String, ProviderEntry>,
        requested: &BTreeMap<String, ProviderEntry>,
    ) -> Result<()> {
        for id in originally_loaded.keys() {
            if requested.contains_key(id) {
                continue;
            }
            let path = provider_file_path_for_config(&self.path, id)?;
            remove_file_nofollow(&path)
                .with_context(|| format!("removing provider config {}", path.display()))?;
        }

        for (id, requested_entry) in requested {
            validate_provider_id_for_filename(id)?;
            let original_entry = originally_loaded.get(id);
            let requested_raw = serialize_json_object(requested_entry, "provider")?;
            let original_raw = original_entry
                .map(|entry| serialize_json_object(entry, "provider"))
                .transpose()?;
            if original_raw.as_ref() == Some(&requested_raw) {
                continue;
            }

            let provider_path = provider_file_path_for_config(&self.path, id)?;
            let provider_exists = provider_path.exists();
            let mut raw = self.provider_raw_object(id)?;
            match original_entry {
                Some(_) if provider_exists => {
                    merge_changed_provider_fields(
                        &mut raw,
                        original_raw.as_ref().expect("serialized original provider"),
                        &requested_raw,
                    );
                }
                Some(_) => {
                    raw = requested_raw;
                }
                None => {
                    for key in PROVIDER_SKIPPED_KEYS {
                        if !requested_raw.contains_key(*key) {
                            raw.remove(*key);
                        }
                    }
                    for (key, value) in requested_raw {
                        raw.insert(key, value);
                    }
                }
            }
            self.persist_provider_raw_unlocked(id, raw)?;
        }
        Ok(())
    }

    fn refresh_from_disk_unlocked(&mut self) -> Result<()> {
        let refreshed = Self::load(&self.path)?;
        self.raw = refreshed.raw;
        self.originally_loaded_providers = refreshed.originally_loaded_providers;
        Ok(())
    }
}

fn serialize_json_object<T: Serialize>(value: &T, label: &str) -> Result<Map<String, Value>> {
    let serialized = serde_json::to_value(value).with_context(|| format!("serializing {label}"))?;
    let Value::Object(serialized) = serialized else {
        unreachable!("{label} serializes to an object");
    };
    Ok(serialized)
}

fn merge_changed_provider_fields(
    current: &mut Map<String, Value>,
    original: &Map<String, Value>,
    requested: &Map<String, Value>,
) {
    apply_changed_object_fields(current, original, requested, Some("models"));
    merge_changed_models(current, original.get("models"), requested.get("models"));
}

fn apply_changed_object_fields(
    current: &mut Map<String, Value>,
    original: &Map<String, Value>,
    requested: &Map<String, Value>,
    excluded_key: Option<&str>,
) {
    let keys = original
        .keys()
        .chain(requested.keys())
        .filter(|key| excluded_key != Some(key.as_str()))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for key in keys {
        if original.get(&key) == requested.get(&key) {
            continue;
        }
        match requested.get(&key) {
            Some(value) => {
                current.insert(key, value.clone());
            }
            None => {
                current.remove(&key);
            }
        }
    }
}

fn merge_changed_models(
    current_provider: &mut Map<String, Value>,
    original: Option<&Value>,
    requested: Option<&Value>,
) {
    if original == requested {
        return;
    }
    let original = models_by_id(original);
    let requested = models_by_id(requested);
    let current_models = current_provider
        .entry("models".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if !current_models.is_array() {
        *current_models = Value::Array(Vec::new());
    }
    let current_models = current_models
        .as_array_mut()
        .expect("models reset to array");

    current_models.retain(|model| {
        let Some(id) = model
            .as_object()
            .and_then(|model| model.get("id"))
            .and_then(Value::as_str)
        else {
            return true;
        };
        original.contains_key(id) == requested.contains_key(id) || !original.contains_key(id)
    });

    for (id, requested_model) in requested {
        let original_model = original.get(&id);
        if original_model == Some(&requested_model) {
            continue;
        }
        let current_model = current_models.iter_mut().find_map(|model| {
            let model = model.as_object_mut()?;
            (model.get("id").and_then(Value::as_str) == Some(id.as_str())).then_some(model)
        });
        if let Some(current_model) = current_model {
            let empty = Map::new();
            apply_changed_object_fields(
                current_model,
                original_model.unwrap_or(&empty),
                &requested_model,
                None,
            );
        } else {
            current_models.push(Value::Object(requested_model));
        }
    }
}

fn models_by_id(value: Option<&Value>) -> BTreeMap<String, Map<String, Value>> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|model| {
            let model = model.as_object()?;
            let id = model.get("id")?.as_str()?.to_string();
            Some((id, model.clone()))
        })
        .collect()
}

pub fn is_xai_grok_provider(provider_id: &str, entry: &ProviderEntry) -> bool {
    let provider_id = provider_id.to_ascii_lowercase();
    provider_id == "grok"
        || provider_id == "grok-oauth"
        || entry
            .credential_ref
            .as_deref()
            .is_some_and(|credential| credential.eq_ignore_ascii_case("grok-oauth"))
        || entry.url.to_ascii_lowercase().contains("api.x.ai")
        || metadata_mentions_xai_grok(&entry.provider_metadata)
        || entry
            .models
            .iter()
            .any(|model| metadata_mentions_xai_grok(&model.provider_metadata))
}

fn metadata_mentions_xai_grok(metadata: &Map<String, Value>) -> bool {
    metadata.values().any(value_mentions_xai_grok)
}

fn value_mentions_xai_grok(value: &Value) -> bool {
    match value {
        Value::String(s) => {
            let s = s.to_ascii_lowercase();
            s.contains("xai") || s.contains("x.ai") || s.contains("grok")
        }
        Value::Array(items) => items.iter().any(value_mentions_xai_grok),
        Value::Object(obj) => obj.values().any(value_mentions_xai_grok),
        _ => false,
    }
}

fn parse_provider_metadata_field<T>(path: &Path, key: &'static str, value: &Value) -> Option<T>
where
    T: DeserializeOwned,
{
    match serde_json::from_value::<T>(value.clone()) {
        Ok(parsed) => Some(parsed),
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                key,
                %error,
                "skipping malformed provider config field"
            );
            None
        }
    }
}

fn warn_malformed_provider_layer_metadata(path: &Path, layer: &Value) {
    if let Some(value) = layer.get("on_unlisted_models_fetch") {
        let _ = parse_provider_metadata_field::<OnUnlistedModelsFetch>(
            path,
            "on_unlisted_models_fetch",
            value,
        );
    }
    if let Some(value) = layer.get("active_model") {
        let _ = parse_provider_metadata_field::<ActiveModelRef>(path, "active_model", value);
    }
    if let Some(value) = layer.get("category_defaults") {
        let _ = parse_provider_metadata_field::<BTreeMap<String, ProviderModelRef>>(
            path,
            "category_defaults",
            value,
        );
    }
}

fn warn_inline_providers_ignored(path: &Path, raw: &Value) {
    if path.as_os_str().is_empty() || raw.get("providers").is_none() {
        return;
    }
    static WARNED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    let warned = WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    if !warned
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(path.to_path_buf())
    {
        return;
    }
    tracing::warn!(
        path = %path.display(),
        "inline providers in config.json are no longer read; move providers to providers/<provider-id>.json"
    );
}

fn merge_provider_files_for_layer(merged: &mut Value, config_path: &Path) {
    let Some(config_dir) = config_path.parent() else {
        return;
    };
    let providers_dir = config_dir.join(PROVIDERS_DIR);
    let Ok(entries) = std::fs::read_dir(&providers_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(id) = provider_id_from_file_name(&path) else {
            tracing::warn!(path = %path.display(), "skipping invalid provider config filename");
            continue;
        };
        match load_provider_raw_file(&path) {
            Ok(mut provider) => {
                let url_changed = provider.get("url").is_some_and(|new_url| {
                    merged
                        .get("providers")
                        .and_then(Value::as_object)
                        .and_then(|providers| providers.get(&id))
                        .and_then(Value::as_object)
                        .and_then(|previous| previous.get("url"))
                        .is_some_and(|previous_url| new_url != previous_url)
                });
                if url_changed {
                    provider
                        .entry("credential_ref".to_string())
                        .or_insert(Value::Null);
                    provider
                        .entry("headers".to_string())
                        .or_insert_with(|| Value::Array(Vec::new()));
                }
                let mut layer = Map::new();
                let mut providers = Map::new();
                providers.insert(id, Value::Object(provider));
                layer.insert("providers".to_string(), Value::Object(providers));
                deep_merge_value(merged, &Value::Object(layer));
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    provider = %id,
                    %error,
                    "skipping malformed provider config file"
                );
            }
        }
    }
}

fn load_provider_files_into_config(config_path: &Path, cfg: &mut ProvidersConfig) {
    let mut merged = Value::Object(Map::new());
    merge_provider_files_for_layer(&mut merged, config_path);
    if let Some(map) = merged.get("providers").and_then(Value::as_object) {
        for (id, v) in map {
            if let Some(obj) = v.as_object()
                && let Err(e) = reject_legacy_redact_fields(id, obj)
            {
                tracing::warn!(provider = %id, error = %e, "skipping malformed provider entry");
                continue;
            }
            match serde_json::from_value::<ProviderEntry>(v.clone()) {
                Ok(entry) => {
                    cfg.providers.insert(id.clone(), entry);
                }
                Err(e) => {
                    tracing::warn!(provider = %id, error = %e, "skipping malformed provider entry");
                }
            }
        }
    }
}

pub fn load_provider_raw_file(path: &Path) -> Result<Map<String, Value>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading provider config at {}", path.display()))?;
    let value: Value = if raw.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(&raw)
            .with_context(|| format!("parsing provider config at {}", path.display()))?
    };
    match value {
        Value::Object(map) => {
            if let Some(id) = provider_id_from_file_name(path) {
                reject_legacy_redact_fields(&id, &map)?;
            }
            Ok(map)
        }
        other => anyhow::bail!(
            "expected provider config root to be an object at {}, found {other:?}",
            path.display()
        ),
    }
}

fn reject_legacy_redact_fields(provider_id: &str, provider: &Map<String, Value>) -> Result<()> {
    if provider.contains_key("redact") {
        anyhow::bail!(
            "provider `{provider_id}` uses legacy `redact`; use `trust: \"trusted\"` to disable outbound redaction or `trust: \"untrusted\"` to keep it enabled"
        );
    }
    if let Some(models) = provider.get("models").and_then(Value::as_array) {
        for model in models {
            let Some(model) = model.as_object() else {
                continue;
            };
            if model.contains_key("redact") {
                let model_id = model
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("<unknown>");
                anyhow::bail!(
                    "model `{provider_id}:{model_id}` uses legacy `redact`; use `trust: \"trusted\"` to disable outbound redaction or `trust: \"untrusted\"` to keep it enabled"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod atomic_write_tests {
    #[test]
    fn prepared_write_publishes_only_at_commit_and_replaces_existing_destination() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("config.json");
        std::fs::write(&destination, b"old contents").unwrap();

        let prepared =
            crate::config::files::prepare_atomic_write(&destination, b"new contents").unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"old contents");

        prepared.commit().unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"new contents");
        assert_eq!(
            std::fs::read_dir(temp.path()).unwrap().count(),
            1,
            "the committed temporary replacement must not remain beside the destination"
        );
    }
}
