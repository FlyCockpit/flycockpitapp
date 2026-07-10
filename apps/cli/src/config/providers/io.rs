use super::*;

/// Read+write a provider config layer while preserving fields cockpit
/// doesn't model. Global provider metadata lives in `config.json`; provider
/// entries live in sibling `providers/*.json` files.
pub struct ConfigDoc {
    pub path: PathBuf,
    pub(crate) raw: Value,
}

#[cfg(test)]
thread_local! {
    static LOAD_EFFECTIVE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_load_effective_call_count() {
    LOAD_EFFECTIVE_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn load_effective_call_count() -> usize {
    LOAD_EFFECTIVE_CALLS.with(std::cell::Cell::get)
}

impl ConfigDoc {
    /// Load the effective provider config for `cwd` by merging every
    /// applicable config layer from least-specific to most-specific.
    /// `COCKPIT_CONFIG` supplies the only config.json path when set; provider
    /// files live beside that file under `providers/`.
    pub fn load_effective(cwd: &Path) -> ProvidersConfig {
        #[cfg(test)]
        LOAD_EFFECTIVE_CALLS.with(|calls| calls.set(calls.get() + 1));
        let paths = crate::config::dirs::config_file_paths_for_load(cwd);
        Self::providers_from_paths(&paths)
    }

    pub(crate) fn providers_from_paths(paths: &[PathBuf]) -> ProvidersConfig {
        let mut merged = Value::Object(Map::new());
        for path in paths {
            if !path.exists() {
                merge_provider_files_for_layer(&mut merged, path);
                continue;
            }
            match Self::load(path) {
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
        }
        .providers()
    }

    pub fn load(path: &Path) -> Result<Self> {
        let path = config_path_for_layer_path(path);
        let raw_str = if path.exists() {
            std::fs::read_to_string(&path)
                .with_context(|| format!("reading config.json at {}", path.display()))?
        } else {
            "{}".to_string()
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
        Ok(Self { path, raw })
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
            load_provider_files_into_config(&self.path, &mut cfg);
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
        let obj = self.raw.as_object_mut().expect("root is an object");
        obj.remove("providers");
        match cfg.on_unlisted_models_fetch {
            Some(v) => {
                let s = serde_json::to_value(v).context("serializing on_unlisted_models_fetch")?;
                obj.insert("on_unlisted_models_fetch".to_string(), s);
            }
            None => {
                obj.remove("on_unlisted_models_fetch");
            }
        }
        match &cfg.active_model {
            Some(active) => {
                let s = serde_json::to_value(active).context("serializing active_model")?;
                obj.insert("active_model".to_string(), s);
            }
            None => {
                obj.remove("active_model");
            }
        }
        if cfg.category_defaults.is_empty() {
            obj.remove("category_defaults");
        } else {
            let value = serde_json::to_value(&cfg.category_defaults)
                .context("serializing category_defaults")?;
            obj.insert("category_defaults".to_string(), value);
        }
        self.persist_raw()?;
        self.replace_provider_files(&cfg.providers)?;
        Ok(())
    }

    pub fn write_active_model(&mut self, active: Option<&ActiveModelRef>) -> Result<()> {
        let obj = self.raw.as_object_mut().expect("root is an object");
        match active {
            Some(active) => {
                let value = serde_json::to_value(active).context("serializing active_model")?;
                obj.insert("active_model".to_string(), value);
            }
            None => {
                obj.remove("active_model");
            }
        }
        self.persist_raw()
    }

    pub fn write_provider_models(
        &mut self,
        provider_id: &str,
        models: &[ModelEntry],
        models_fetched_at: Option<chrono::DateTime<chrono::Utc>>,
        model_catalog: ProviderModelCatalog,
        last_model_fetch: Option<ModelFetchStatus>,
    ) -> Result<()> {
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
        self.persist_provider_raw(provider_id, provider)
    }

    pub fn write_unlisted_models_policy(
        &mut self,
        on_unlisted_models_fetch: Option<OnUnlistedModelsFetch>,
    ) -> Result<()> {
        let obj = self.raw.as_object_mut().expect("root is an object");
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
        self.persist_raw()
    }

    pub fn write_model_favorite(
        &mut self,
        provider_id: &str,
        model_id: &str,
        favorite: bool,
    ) -> Result<()> {
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
        self.persist_provider_raw(provider_id, provider)
    }

    fn persist_raw(&self) -> Result<()> {
        let pretty = serde_json::to_string_pretty(&self.raw).context("serializing config.json")?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, format!("{pretty}\n"))
            .with_context(|| format!("writing {}", self.path.display()))?;
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

    fn persist_provider_raw(&self, provider_id: &str, provider: Map<String, Value>) -> Result<()> {
        let path = provider_file_path_for_config(&self.path, provider_id)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let pretty = serde_json::to_string_pretty(&Value::Object(provider))
            .context("serializing provider")?;
        std::fs::write(&path, format!("{pretty}\n"))
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    fn replace_provider_files(&self, providers: &BTreeMap<String, ProviderEntry>) -> Result<()> {
        let dir = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(PROVIDERS_DIR);
        if dir.exists() {
            for entry in std::fs::read_dir(&dir)
                .with_context(|| format!("reading providers directory {}", dir.display()))?
            {
                let entry = entry?;
                let path = entry.path();
                let Some(id) = provider_id_from_file_name(&path) else {
                    continue;
                };
                if !providers.contains_key(&id) {
                    match std::fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            return Err(e).with_context(|| format!("removing {}", path.display()));
                        }
                    }
                }
            }
        }
        for (id, entry) in providers {
            validate_provider_id_for_filename(id)?;
            let mut raw = self.provider_raw_object(id)?;
            let serialized = serde_json::to_value(entry).context("serializing provider")?;
            let Value::Object(serialized) = serialized else {
                unreachable!("ProviderEntry serializes to object");
            };
            for key in PROVIDER_SKIPPED_KEYS {
                if !serialized.contains_key(*key) {
                    raw.remove(*key);
                }
            }
            for (key, value) in serialized {
                raw.insert(key, value);
            }
            self.persist_provider_raw(id, raw)?;
        }
        Ok(())
    }
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
            Ok(provider) => {
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

pub(crate) fn load_provider_raw_file(path: &Path) -> Result<Map<String, Value>> {
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
