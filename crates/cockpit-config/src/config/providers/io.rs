use super::*;

use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::Arc;

/// Daemon-private proof that one exact provider/model entry participated in a
/// captured workspace snapshot.  This is intentionally neither serde nor
/// displayable: the daemon uses it only to bind a retained write capability
/// to the exact bytes and model object it previously projected.
#[derive(Clone, PartialEq, Eq)]
pub struct RetainedProviderModelSource {
    layer_index: usize,
    provider_id: String,
    model_id: String,
    provider_digest: [u8; 32],
    model_digest: [u8; 32],
}

/// Daemon-private receipt for one capability-relative model-favorite write.
///
/// The receipt deliberately carries only content identities and the retained
/// source token.  It is not serializable or displayable: callers use it to
/// distinguish the exact pre-write snapshot from the bytes this operation
/// wrote before asking the worker to publish a new configuration generation.
#[derive(Clone)]
pub struct RetainedProviderModelFavoriteWriteReceipt {
    source: RetainedProviderModelSource,
    old_provider_digest: [u8; 32],
    new_provider_digest: [u8; 32],
    old_model_digest: [u8; 32],
    new_model_digest: [u8; 32],
}

impl std::fmt::Debug for RetainedProviderModelFavoriteWriteReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedProviderModelFavoriteWriteReceipt")
            .field("source_layer_index", &self.source.layer_index)
            .finish_non_exhaustive()
    }
}

impl RetainedProviderModelFavoriteWriteReceipt {
    pub fn source(&self) -> &RetainedProviderModelSource {
        &self.source
    }

    pub fn old_provider_digest(&self) -> &[u8; 32] {
        &self.old_provider_digest
    }

    pub fn new_provider_digest(&self) -> &[u8; 32] {
        &self.new_provider_digest
    }

    pub fn old_model_digest(&self) -> &[u8; 32] {
        &self.old_model_digest
    }

    pub fn new_model_digest(&self) -> &[u8; 32] {
        &self.new_model_digest
    }

    /// True only when a freshly captured source is the exact bytes this
    /// receipt committed.  A same-slot check alone is not sufficient: another
    /// writer could replace the provider/model between the durable boundary
    /// and worker publication.
    pub fn matches_committed_source(&self, observed: &RetainedProviderModelSource) -> bool {
        self.source.has_same_source_slot(observed)
            && observed.provider_digest == self.new_provider_digest
            && observed.model_digest == self.new_model_digest
    }
}

/// A favorite update has a durable filesystem boundary.  Callers must not
/// collapse a post-write authority failure into the same result as a rejected
/// preflight. Once atomic replacement is attempted, this code must never
/// compensate by overwriting a possible later external write; callers need a
/// reattach to discover and publish the final durable state.
#[derive(Debug)]
pub enum RetainedProviderModelFavoriteWriteError {
    /// No provider bytes were changed by this operation.
    Rejected(anyhow::Error),
    /// Atomic replacement was attempted, so the operation may have crossed
    /// its durable boundary. The source was not published into the worker;
    /// its bytes are intentionally left untouched. The receipt identifies
    /// the precise attached authority/bytes for a later reattach.
    DurableButUnpublished {
        receipt: RetainedProviderModelFavoriteWriteReceipt,
        cause: anyhow::Error,
    },
}

impl std::fmt::Display for RetainedProviderModelFavoriteWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(_) => {
                formatter.write_str("model-favorite update was rejected before commit")
            }
            Self::DurableButUnpublished { .. } => formatter.write_str(
                "model-favorite update reached a durable boundary but could not be safely republished",
            ),
        }
    }
}

impl RetainedProviderModelFavoriteWriteError {
    /// The receipt is available only for the explicit durable-but-unpublished
    /// state; rejected operations never attempted the durable replacement.
    pub fn receipt(&self) -> Option<&RetainedProviderModelFavoriteWriteReceipt> {
        match self {
            Self::DurableButUnpublished { receipt, .. } => Some(receipt),
            Self::Rejected(_) => None,
        }
    }
}

impl std::error::Error for RetainedProviderModelFavoriteWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected(cause) | Self::DurableButUnpublished { cause, .. } => {
                Some(cause.root_cause())
            }
        }
    }
}

pub type RetainedProviderModelFavoritePreWriteVerifier =
    Arc<dyn Fn() -> Result<()> + Send + Sync + 'static>;
pub type RetainedProviderModelFavoritePostWriteVerifier =
    Arc<dyn Fn(&RetainedProviderModelFavoriteWriteReceipt) -> Result<()> + Send + Sync + 'static>;

impl std::fmt::Debug for RetainedProviderModelSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedProviderModelSource")
            .field("layer_index", &self.layer_index)
            .finish_non_exhaustive()
    }
}

impl RetainedProviderModelSource {
    pub fn layer_index(&self) -> usize {
        self.layer_index
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// Source identity intentionally excludes mutable content digests. It is
    /// used after a successful write to prove the refreshed favorite still
    /// comes from the same retained layer/file/model slot, while the digest
    /// itself is expected to change because the favorite bit changed.
    pub fn has_same_source_slot(&self, other: &Self) -> bool {
        self.layer_index == other.layer_index
            && self.provider_id == other.provider_id
            && self.model_id == other.model_id
    }
}

/// One retained config-directory lock that participates in a favorite source
/// selection.  A lower-precedence favorite cannot be written while a higher
/// captured layer is concurrently becoming the effective source.
pub struct RetainedProviderModelFavoriteLock {
    config_directory: std::fs::File,
    canonical_config_path: PathBuf,
    display_config_parent: PathBuf,
}

impl RetainedProviderModelFavoriteLock {
    pub fn new(config_directory: std::fs::File, canonical_config_path: PathBuf) -> Result<Self> {
        let display_config_parent = canonical_config_path
            .parent()
            .context("captured config path has no parent")?
            .to_path_buf();
        Ok(Self {
            config_directory,
            canonical_config_path,
            display_config_parent,
        })
    }

    fn acquire(&self) -> Result<ConfigMutationLock> {
        ConfigMutationLock::acquire_retained(
            &self.config_directory,
            &self.canonical_config_path,
            &self.display_config_parent,
        )
    }
}

impl std::fmt::Debug for RetainedProviderModelFavoriteLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedProviderModelFavoriteLock")
            .finish_non_exhaustive()
    }
}

/// Return the highest-precedence retained layer that supplied this exact
/// provider/model object.  The returned proof contains no paths, provider
/// secrets, or wire-facing values; it is valid only for the snapshot bytes
/// supplied to this function.
pub fn retained_provider_model_source_from_workspace_layer_snapshots(
    snapshots: &[crate::config::WorkspaceConfigLayerSnapshot],
    provider_id: &str,
    model_id: &str,
) -> Result<Option<RetainedProviderModelSource>> {
    validate_provider_id_for_filename(provider_id)?;
    anyhow::ensure!(!model_id.is_empty(), "model id must not be empty");
    for (layer_index, snapshot) in snapshots.iter().enumerate().rev() {
        let Some((_, provider_bytes)) = snapshot
            .provider_files
            .iter()
            .find(|(id, _)| id == provider_id)
        else {
            continue;
        };
        let provider: Value = serde_json::from_slice(provider_bytes)
            .with_context(|| format!("parsing retained provider `{provider_id}`"))?;
        let provider = provider
            .as_object()
            .context("retained provider config root must be an object")?;
        let Some(model) = authored_model_value(provider, model_id)? else {
            continue;
        };
        return Ok(Some(RetainedProviderModelSource {
            layer_index,
            provider_id: provider_id.to_string(),
            model_id: model_id.to_string(),
            provider_digest: sha256_bytes(provider_bytes),
            model_digest: sha256_model_value(&model)?,
        }));
    }
    Ok(None)
}

/// Non-serializable authority for changing a model favorite in one exact
/// provider file captured by an attached daemon worker. The open provider
/// directory is the filesystem authority; the paths retained alongside it are
/// diagnostic and lock-identity data only.
pub struct RetainedProviderModelFavoriteTarget {
    provider_directory: std::fs::File,
    provider_leaf: OsString,
    canonical_provider_path: PathBuf,
    source: RetainedProviderModelSource,
    precedence_locks: Vec<RetainedProviderModelFavoriteLock>,
    pre_write_verifier: Option<RetainedProviderModelFavoritePreWriteVerifier>,
    post_write_verifier: Option<RetainedProviderModelFavoritePostWriteVerifier>,
}

impl std::fmt::Debug for RetainedProviderModelFavoriteTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedProviderModelFavoriteTarget")
            .finish_non_exhaustive()
    }
}

impl RetainedProviderModelFavoriteTarget {
    /// Capture the already-existing provider leaf below `config_directory`.
    /// This intentionally refuses to manufacture a new provider file: the
    /// dispatcher must first prove that the selected source participated in
    /// the immutable attach-time snapshot.
    pub fn new(
        config_directory: std::fs::File,
        canonical_config_path: PathBuf,
        source: RetainedProviderModelSource,
    ) -> Result<Self> {
        validate_provider_id_for_filename(source.provider_id())?;
        let Some(provider_directory) =
            crate::config::files::open_retained_child_directory_optional(
                &config_directory,
                std::ffi::OsStr::new(PROVIDERS_DIR),
            )?
        else {
            anyhow::bail!("captured provider directory is missing");
        };
        let provider_leaf = OsString::from(format!("{}.json", source.provider_id()));
        let display_config_parent = canonical_config_path
            .parent()
            .context("captured config path has no parent")?
            .to_path_buf();
        let canonical_provider_path = display_config_parent
            .join(PROVIDERS_DIR)
            .join(&provider_leaf);
        let source_lock = RetainedProviderModelFavoriteLock::new(
            config_directory
                .try_clone()
                .context("cloning retained config directory")?,
            canonical_config_path.clone(),
        )?;
        Ok(Self {
            provider_directory,
            provider_leaf,
            canonical_provider_path,
            source,
            precedence_locks: vec![source_lock],
            pre_write_verifier: None,
            post_write_verifier: None,
        })
    }

    /// Install a fence that must hold before the provider/model bytes may be
    /// replaced. This phase intentionally requires the exact attach-time
    /// source digests.
    pub fn with_pre_write_verifier(
        mut self,
        verifier: RetainedProviderModelFavoritePreWriteVerifier,
    ) -> Self {
        self.pre_write_verifier = Some(match self.pre_write_verifier.take() {
            Some(previous) => Arc::new(move || {
                previous()?;
                verifier()
            }),
            None => verifier,
        });
        self
    }

    /// Install a fence for the committed bytes.  Unlike the pre-write fence,
    /// this receives the receipt and must validate the new digest/source
    /// token, not the now-obsolete attach-time digest.
    pub fn with_post_write_verifier(
        mut self,
        verifier: RetainedProviderModelFavoritePostWriteVerifier,
    ) -> Self {
        self.post_write_verifier = Some(match self.post_write_verifier.take() {
            Some(previous) => Arc::new(move |receipt| {
                previous(receipt)?;
                verifier(receipt)
            }),
            None => verifier,
        });
        self
    }

    /// Add retained layers above the source that can supersede it. The target
    /// keeps its source lock first and acquires this ordered suffix before its
    /// final source verification and write.
    pub fn with_higher_precedence_locks(
        mut self,
        higher_precedence_locks: Vec<RetainedProviderModelFavoriteLock>,
    ) -> Self {
        self.precedence_locks.extend(higher_precedence_locks);
        self
    }

    fn verify_captured_directory_still_named(&self) -> Result<()> {
        let source_lock = self
            .precedence_locks
            .first()
            .context("captured provider source lock is missing")?;
        anyhow::ensure!(
            crate::config::files::directory_handle_matches_path(
                &source_lock.config_directory,
                &source_lock.display_config_parent,
            )?,
            "captured provider source has been replaced"
        );
        Ok(())
    }

    fn verify_pre_write(&self) -> Result<()> {
        self.verify_captured_directory_still_named()?;
        if let Some(verifier) = &self.pre_write_verifier {
            verifier()?;
        }
        Ok(())
    }

    fn verify_post_write(&self, receipt: &RetainedProviderModelFavoriteWriteReceipt) -> Result<()> {
        if let Some(verifier) = &self.post_write_verifier {
            verifier(receipt)?;
        }
        Ok(())
    }

    /// Validate a no-op favorite request against the same retained authority
    /// and exact source bytes required for a write, without serializing or
    /// replacing the provider file.  An `Ack` for an already-selected value
    /// is therefore a durable observation at this validation point, rather
    /// than merely an assertion about an old worker snapshot.
    pub fn validate_model_favorite_noop(&self, favorite: bool) -> Result<()> {
        self.verify_pre_write()?;
        let _locks = self
            .precedence_locks
            .iter()
            .map(RetainedProviderModelFavoriteLock::acquire)
            .collect::<Result<Vec<_>>>()?;
        self.verify_pre_write()?;
        let bytes = crate::config::files::read_optional_leaf_from_directory_handle(
            &self.provider_directory,
            &self.provider_leaf,
            crate::config::MAX_WORKSPACE_CONFIG_FILE_BYTES,
        )?
        .context("captured provider file is missing")?;
        anyhow::ensure!(
            sha256_bytes(&bytes) == self.source.provider_digest,
            "captured provider file changed after attached snapshot"
        );
        let raw: Value = if bytes.iter().all(u8::is_ascii_whitespace) {
            Value::Object(Map::new())
        } else {
            serde_json::from_slice(&bytes).context("parsing captured provider config")?
        };
        let provider = raw
            .as_object()
            .context("captured provider config root must be an object")?;
        validate_captured_model_favorite(
            provider,
            self.source.model_id(),
            self.source.model_digest,
            favorite,
        )
    }

    /// Atomically update the captured provider file with the same config-layer
    /// lock identity used by ambient `ConfigDoc` mutations. All reads, lock-file
    /// operations and the replacement are relative to the retained directory
    /// handle, so a changed `COCKPIT_CONFIG` or pathname replacement cannot
    /// redirect an attached session to another source.
    pub fn write_model_favorite(
        &self,
        favorite: bool,
    ) -> std::result::Result<
        RetainedProviderModelFavoriteWriteReceipt,
        RetainedProviderModelFavoriteWriteError,
    > {
        self.verify_pre_write()
            .map_err(RetainedProviderModelFavoriteWriteError::Rejected)?;
        let _locks = self
            .precedence_locks
            .iter()
            .map(RetainedProviderModelFavoriteLock::acquire)
            .collect::<Result<Vec<_>>>()
            .map_err(RetainedProviderModelFavoriteWriteError::Rejected)?;
        // The lock serializes writers but does not prove the attached
        // directory chain still names the captured authority. Recheck on both
        // sides of the durable boundary; a changed chain fails closed.
        self.verify_pre_write()
            .map_err(RetainedProviderModelFavoriteWriteError::Rejected)?;
        let bytes = crate::config::files::read_optional_leaf_from_directory_handle(
            &self.provider_directory,
            &self.provider_leaf,
            crate::config::MAX_WORKSPACE_CONFIG_FILE_BYTES,
        )
        .map_err(RetainedProviderModelFavoriteWriteError::Rejected)?
        .context("captured provider file is missing")
        .map_err(RetainedProviderModelFavoriteWriteError::Rejected)?;
        if sha256_bytes(&bytes) != self.source.provider_digest {
            return Err(RetainedProviderModelFavoriteWriteError::Rejected(
                anyhow::anyhow!("captured provider file changed after attached snapshot"),
            ));
        }
        let mut raw: Value = if bytes.iter().all(u8::is_ascii_whitespace) {
            Value::Object(Map::new())
        } else {
            serde_json::from_slice(&bytes)
                .context("parsing captured provider config")
                .map_err(RetainedProviderModelFavoriteWriteError::Rejected)?
        };
        let provider = raw
            .as_object_mut()
            .context("captured provider config root must be an object")
            .map_err(RetainedProviderModelFavoriteWriteError::Rejected)?;
        let new_model_digest = apply_captured_model_favorite(
            provider,
            self.source.model_id(),
            self.source.model_digest,
            favorite,
        )
        .map_err(RetainedProviderModelFavoriteWriteError::Rejected)?;
        let new_bytes = readable_provider_bytes(provider)
            .map_err(RetainedProviderModelFavoriteWriteError::Rejected)?;
        let receipt = RetainedProviderModelFavoriteWriteReceipt {
            source: self.source.clone(),
            old_provider_digest: self.source.provider_digest,
            new_provider_digest: sha256_bytes(&new_bytes),
            old_model_digest: self.source.model_digest,
            new_model_digest,
        };
        if let Err(cause) = crate::config::files::atomic_write_leaf_from_retained_directory(
            &self.provider_directory,
            &self.provider_leaf,
            &self.canonical_provider_path,
            &new_bytes,
        ) {
            // `atomic_write` can fail after rename (for example while syncing
            // its parent). There is no portable atomic conditional restore,
            // so never classify this as pre-write rejection or overwrite a
            // concurrent external update. The receipt lets a new attachment
            // inspect the retained authority's actual final bytes.
            return Err(
                RetainedProviderModelFavoriteWriteError::DurableButUnpublished { receipt, cause },
            );
        }
        if let Err(cause) = self.verify_post_write(&receipt) {
            // The post-write fence can race an external writer. Deliberately
            // retain whatever bytes now exist: a compensation write could
            // clobber that external state after the durable boundary.
            return Err(
                RetainedProviderModelFavoriteWriteError::DurableButUnpublished { receipt, cause },
            );
        }
        Ok(receipt)
    }
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"cockpit-retained-provider-favorite-v1\0");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn sha256_model_value(value: &Value) -> Result<[u8; 32]> {
    let canonical = serde_json::to_vec(value).context("serializing retained provider model")?;
    Ok(sha256_bytes(&canonical))
}

/// Project one authored row, including sparse edits whose base lives in a
/// lower layer. The provider digest still binds all exact source bytes.
fn authored_model_value(provider: &Map<String, Value>, model_id: &str) -> Result<Option<Value>> {
    let mut matching = provider
        .get("models")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|model| model.get("id").and_then(Value::as_str) == Some(model_id));
    let mut model = matching.next().cloned();
    anyhow::ensure!(
        matching.next().is_none(),
        "captured provider has duplicate model `{model_id}`"
    );
    if model.is_none()
        && provider
            .get("model_order")
            .and_then(Value::as_array)
            .is_some_and(|order| order.iter().any(|id| id.as_str() == Some(model_id)))
    {
        model = Some(serde_json::json!({"id":model_id}));
    }
    if let Some(raw) = provider.get("model_field_patches") {
        let patches: Vec<ModelEntryFieldPatch> = serde_json::from_value(raw.clone())?;
        let mut matching = patches.iter().filter(|patch| patch.id == model_id);
        if let Some(patch) = matching.next() {
            anyhow::ensure!(
                matching.next().is_none(),
                "captured provider has duplicate model patch `{model_id}`"
            );
            let model = model.get_or_insert_with(|| serde_json::json!({"id": model_id}));
            patch.apply_value(model)?;
        }
    }
    Ok(model)
}

fn update_existing_model_field_patch(
    provider: &mut Map<String, Value>,
    update: &ModelEntryFieldPatch,
) -> Result<bool> {
    let Some(raw) = provider.get("model_field_patches") else {
        return Ok(false);
    };
    let mut patches: Vec<ModelEntryFieldPatch> = serde_json::from_value(raw.clone())?;
    let Some(patch) = patches.iter_mut().find(|patch| patch.id == update.id) else {
        return Ok(false);
    };
    patch.extend(update);
    provider.insert("model_field_patches".into(), serde_json::to_value(patches)?);
    if let Some(models) = provider.get_mut("models").and_then(Value::as_array_mut) {
        for model in models
            .iter_mut()
            .filter(|model| model.get("id").and_then(Value::as_str) == Some(update.id.as_str()))
        {
            if let Some(object) = model.as_object_mut() {
                for key in update.set.keys().chain(update.remove.iter()) {
                    object.remove(key);
                }
            }
        }
    }
    Ok(true)
}

fn apply_captured_model_favorite(
    provider: &mut Map<String, Value>,
    model_id: &str,
    expected_model_digest: [u8; 32],
    favorite: bool,
) -> Result<[u8; 32]> {
    let model = authored_model_value(provider, model_id)?
        .context("captured provider model is no longer present")?;
    anyhow::ensure!(
        sha256_model_value(&model)? == expected_model_digest,
        "captured provider model changed after attached snapshot"
    );
    apply_model_favorite(provider, model_id, favorite)?;
    sha256_model_value(
        &authored_model_value(provider, model_id)?.expect("favorite creates an authored row"),
    )
}

/// Validate a no-op without changing a file or its exact-byte capability.
fn validate_captured_model_favorite(
    provider: &Map<String, Value>,
    model_id: &str,
    expected_model_digest: [u8; 32],
    favorite: bool,
) -> Result<()> {
    let model = authored_model_value(provider, model_id)?
        .context("captured provider model is no longer present")?;
    anyhow::ensure!(
        sha256_model_value(&model)? == expected_model_digest,
        "captured provider model changed after attached snapshot"
    );
    let observed = model
        .get("favorite")
        .map(|value| {
            value
                .as_bool()
                .context("captured provider model favorite must be a boolean")
        })
        .transpose()?
        .unwrap_or(false);
    anyhow::ensure!(
        observed == favorite,
        "captured provider model favorite no longer matches requested value"
    );
    Ok(())
}

fn apply_model_favorite(
    provider: &mut Map<String, Value>,
    model_id: &str,
    favorite: bool,
) -> Result<()> {
    let update = ModelEntryFieldPatch {
        id: model_id.into(),
        replace: false,
        set: BTreeMap::from([("favorite".into(), Value::Bool(favorite))]),
        remove: Vec::new(),
    };
    if update_existing_model_field_patch(provider, &update)? {
        return Ok(());
    }
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
    Ok(())
}

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

// The raw document carries literal provider headers and keys: Debug shows
// the path, top-level keys and provider ids only.
impl std::fmt::Debug for ConfigDoc {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let top_level: Vec<&str> = self
            .raw
            .as_object()
            .map(|object| object.keys().map(String::as_str).collect())
            .unwrap_or_default();
        formatter
            .debug_struct("ConfigDoc")
            .field("path", &self.path)
            .field("raw_top_level_keys", &top_level)
            .field(
                "originally_loaded_providers",
                &self.originally_loaded_providers.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
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
    /// Project one already-captured project-local layer.  Acquisition happens
    /// through a retained directory handle in the daemon; this routine is
    /// intentionally pure with respect to the filesystem so parsing can never
    /// reopen a replaced workspace path.
    pub fn providers_from_workspace_layer_snapshot(
        snapshot: &crate::config::WorkspaceConfigLayerSnapshot,
    ) -> Result<ProvidersConfig> {
        Self::providers_from_workspace_layer_snapshot_with_warnings(snapshot)
            .map(|(providers, _)| providers)
    }

    /// Project one retained layer and retain any stable, secret-free policy
    /// warnings so a daemon can surface them to the owner.
    pub(crate) fn providers_from_workspace_layer_snapshot_with_warnings(
        snapshot: &crate::config::WorkspaceConfigLayerSnapshot,
    ) -> Result<(ProvidersConfig, Vec<String>)> {
        let bytes = snapshot.config_json.as_deref().unwrap_or(b"{}");
        let text =
            std::str::from_utf8(bytes).context("workspace config.json is not valid UTF-8")?;
        let mut raw: Value = if text.trim().is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_str(text).context("workspace config.json is not valid JSON")?
        };
        let Some(root) = raw.as_object_mut() else {
            anyhow::bail!("workspace config.json root must be an object");
        };
        let mut providers = Map::new();
        let mut warnings = Vec::new();
        for (id, bytes) in &snapshot.provider_files {
            validate_provider_id_for_filename(id)?;
            let value: Value = serde_json::from_slice(bytes)
                .with_context(|| format!("parsing workspace provider `{id}`"))?;
            let Some(mut provider) = value.as_object().cloned() else {
                anyhow::bail!("workspace provider `{id}` must be a JSON object");
            };
            if !matches!(
                snapshot.origin,
                Some(crate::config::dirs::ConfigDirKind::HomeXdg)
            ) {
                strip_project_auth_command(
                    id,
                    &mut provider,
                    "attached workspace config",
                    &mut warnings,
                );
                strip_project_oauth_descriptor(
                    id,
                    &mut provider,
                    "attached workspace config",
                    &mut warnings,
                );
            }
            providers.insert(id.clone(), Value::Object(provider));
        }
        root.insert("providers".to_string(), Value::Object(providers));
        let providers = Self {
            path: PathBuf::new(),
            raw,
            originally_loaded_providers: BTreeMap::new(),
        }
        .providers();
        Ok((providers, warnings))
    }

    /// Merge a sequence of already-captured layers without consulting the
    /// filesystem.  This is deliberately the same typed projection used for
    /// one retained layer above, but preserves layer precedence for callers
    /// that must predict a mutation's effective value from frozen directory
    /// capabilities (rather than from a subsequently changed environment).
    pub fn providers_from_workspace_layer_snapshots(
        snapshots: &[crate::config::WorkspaceConfigLayerSnapshot],
    ) -> Result<ProvidersConfig> {
        let mut merged = Value::Object(Map::new());
        for snapshot in snapshots {
            let layer = serde_json::to_value(
                Self::providers_from_workspace_layer_snapshot_with_warnings(snapshot)?.0,
            )
            .context("serializing retained workspace provider layer")?;
            deep_merge_value(&mut merged, &layer);
        }
        serde_json::from_value(merged)
            .map_err(|error| crate::config::value_free::json_error(&error))
            .context("projecting merged retained workspace provider layers")
    }

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

    /// Resolve providers and capture the readable `config.json` layers from
    /// the same post-recovery read. Daemon config adoption uses this to avoid
    /// combining provider metadata from one filesystem instant with extended
    /// settings and strict-field provenance from another.
    pub(crate) fn try_load_effective_with_layer_snapshot(
        paths: &[PathBuf],
    ) -> Result<(ProvidersConfig, Vec<(PathBuf, Value)>, Vec<String>)> {
        use crate::config::effective_default;

        effective_default::recover_layer_journals(
            paths,
            effective_default::JournalRecovery::read_only(),
        )
        .context("recovering a pending default-model transaction")?;
        let generation = next_load_effective_generation();
        let (mut masks, unmaskable) = effective_default::masked_layers(paths);
        if !unmaskable.is_empty() {
            anyhow::bail!(
                "{} configuration layer(s) have a pending default-model transaction that cannot be masked; run `cockpit doctor` to inspect the journal",
                unmaskable.len()
            );
        }

        // The mask probe and capture both happen outside the cross-process
        // mutation lock. Validate every capture against a fresh probe and
        // retry the whole projection when the journal picture moved. This
        // covers a transaction starting on a different layer during a retry,
        // while the bound fails closed under continuous config churn.
        const MAX_STABLE_CAPTURE_ATTEMPTS: usize = 4;
        for _ in 0..MAX_STABLE_CAPTURE_ATTEMPTS {
            let (providers, layers, warnings) =
                Self::providers_and_layer_snapshot_with_masks(paths, &masks);
            let (observed_masks, unmaskable) = effective_default::masked_layers(paths);
            if !unmaskable.is_empty() {
                anyhow::bail!(
                    "{} configuration layer(s) have a pending default-model transaction that cannot be masked; run `cockpit doctor` to inspect the journal",
                    unmaskable.len()
                );
            }
            if observed_masks == masks {
                return Ok((
                    providers.with_resolution_generation(generation),
                    layers,
                    warnings,
                ));
            }
            masks = observed_masks;
        }
        anyhow::bail!(
            "configuration layers changed during daemon snapshot capture; retry after configuration writes settle"
        )
    }

    fn providers_and_layer_snapshot_with_masks(
        paths: &[PathBuf],
        masks: &HashMap<PathBuf, Vec<u8>>,
    ) -> (ProvidersConfig, Vec<(PathBuf, Value)>, Vec<String>) {
        let mut merged = Value::Object(Map::new());
        let mut layers = Vec::new();
        let mut warnings = Vec::new();
        for path in paths {
            let mask = masks.get(path).map(Vec::as_slice);
            if mask.is_none() && !path.exists() {
                merge_provider_files_for_layer(&mut merged, path, &mut warnings);
                continue;
            }
            match Self::load_with_mask(path, mask) {
                Ok(doc) => {
                    let mut layer = doc.raw;
                    layers.push((path.clone(), layer.clone()));
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
            merge_provider_files_for_layer(&mut merged, path, &mut warnings);
        }
        let providers = Self {
            path: PathBuf::new(),
            raw: merged,
            originally_loaded_providers: BTreeMap::new(),
        }
        .providers();
        (providers, layers, warnings)
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
        let mut warnings = Vec::new();
        for path in paths {
            let mask = masks.get(path).map(Vec::as_slice);
            if mask.is_none() && !path.exists() {
                merge_provider_files_for_layer(&mut merged, path, &mut warnings);
                continue;
            }
            match Self::load_with_mask(path, mask) {
                Ok(doc) => {
                    let mut layer = doc.raw.clone();
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
            merge_provider_files_for_layer(&mut merged, path, &mut warnings);
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
            // No outer read context: the bounded reader already attaches a
            // `reading <path>` context to IO failures and surfaces over-cap
            // files as a top-level `exceeds the byte limit` failure.
            None => match crate::config::files::read_workspace_config_text(&path)? {
                Some(raw) => raw,
                None => "{}".to_string(),
            },
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
                match serde_json::from_value::<ProviderEntry>(v.clone()) {
                    Ok(entry) => {
                        cfg.providers.insert(id.clone(), entry);
                    }
                    Err(error) => {
                        let error = crate::config::value_free::json_error(&error).to_string();
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
        crate::config::dirs::authorize_config_file_write(&self.path)?;
        let _lock = ConfigMutationLock::acquire(&self.path)?;
        let mut current = Self::load(&self.path)?;
        current.set_layer_metadata_raw(
            cfg,
            originally_loaded.on_unlisted_models_fetch != cfg.on_unlisted_models_fetch,
            originally_loaded.category_defaults != cfg.category_defaults,
        )?;
        // Validate the entire prospective batch before publishing metadata or
        // removing any sibling provider. Actual writes use the same serializer.
        readable_document_bytes(&current.raw)?;
        for (id, entry) in &cfg.providers {
            let requested = serialize_json_object(entry, "provider")?;
            let original_entry = self.originally_loaded_providers.get(id);
            let original = original_entry
                .map(|entry| serialize_json_object(entry, "provider"))
                .transpose()?;
            current.provider_raw_for_write(id, original_entry, requested, original.as_ref())?;
        }
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
        crate::config::dirs::authorize_config_file_write(&self.path)?;
        let _lock = ConfigMutationLock::acquire(&self.path)?;
        let mut provider = self.provider_raw_object(provider_id)?;
        provider.remove("model_field_patches");
        provider.remove("model_order");
        provider.remove("model_membership");
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
        crate::config::dirs::authorize_config_file_write(&self.path)?;
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
        crate::config::dirs::authorize_config_file_write(&self.path)?;
        let _lock = ConfigMutationLock::acquire(&self.path)?;
        let mut provider = self.provider_raw_object(provider_id)?;
        apply_model_favorite(&mut provider, model_id, favorite)?;
        self.persist_provider_raw_unlocked(provider_id, provider)?;
        self.refresh_from_disk_unlocked()
    }

    pub fn write_model_wizard_fields(
        &mut self,
        provider_id: &str,
        model: &ModelEntry,
    ) -> Result<()> {
        crate::config::dirs::authorize_config_file_write(&self.path)?;
        let _lock = ConfigMutationLock::acquire(&self.path)?;
        let mut provider = self.provider_raw_object(provider_id)?;
        let serialized = serde_json::to_value(model).context("serializing model wizard fields")?;
        let Value::Object(serialized) = serialized else {
            unreachable!("ModelEntry serializes to object");
        };
        let update = ModelEntryFieldPatch {
            id: model.id.clone(),
            replace: false,
            set: MODEL_WIZARD_MODEL_FIELD_KEYS
                .iter()
                .filter_map(|key| {
                    serialized
                        .get(*key)
                        .map(|value| ((*key).to_string(), value.clone()))
                })
                .collect(),
            remove: MODEL_WIZARD_MODEL_FIELD_KEYS
                .iter()
                .filter(|key| !serialized.contains_key(**key))
                .map(|key| (*key).to_string())
                .collect(),
        };
        if update_existing_model_field_patch(&mut provider, &update)? {
            self.persist_provider_raw_unlocked(provider_id, provider)?;
            return self.refresh_from_disk_unlocked();
        }
        let models = provider
            .entry("models".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if !models.is_array() {
            *models = Value::Array(Vec::new());
        }
        let models = models.as_array_mut().expect("models reset to array");
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
        crate::config::dirs::authorize_config_file_write(&self.path)?;
        atomic_write(&self.path, &readable_document_bytes(&self.raw)?)?;
        Ok(())
    }

    fn provider_raw_object(&self, provider_id: &str) -> Result<Map<String, Value>> {
        let path = provider_file_path_for_config(&self.path, provider_id)?;
        // No outer read context: the bounded reader already attaches a
        // `reading <path>` context to IO failures and surfaces over-cap
        // files as a top-level `exceeds the byte limit` failure.
        let Some(raw) = crate::config::files::read_workspace_config_text(&path)? else {
            return Ok(Map::new());
        };
        let value: Value = if raw.trim().is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_str(&raw)
                .with_context(|| format!("parsing provider config at {}", path.display()))?
        };
        match value {
            Value::Object(map) => Ok(map),
            other => anyhow::bail!(
                "expected provider config root to be an object at {}, found {other:?}",
                path.display()
            ),
        }
    }

    fn persist_provider_raw_unlocked(
        &self,
        provider_id: &str,
        provider: Map<String, Value>,
    ) -> Result<()> {
        let path = provider_file_path_for_config(&self.path, provider_id)?;
        crate::config::dirs::authorize_config_file_write(&path)?;
        atomic_write(&path, &readable_provider_bytes(&provider)?)?;
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

            let raw = self.provider_raw_for_write(
                id,
                original_entry,
                requested_raw,
                original_raw.as_ref(),
            )?;
            self.persist_provider_raw_unlocked(id, raw)?;
        }
        Ok(())
    }

    /// Validate the exact raw candidate, including retained unknown fields and
    /// the same patching/readable/canonical budgets used by the durable writer.
    /// This does not write or acquire an additional mutation lock.
    pub fn validate_provider_write(&self, id: &str, entry: &ProviderEntry) -> Result<()> {
        let original = self.providers();
        let original_entry = original.providers.get(id);
        let original_raw = original_entry
            .map(|entry| serialize_json_object(entry, "provider"))
            .transpose()?;
        self.provider_raw_for_write(
            id,
            original_entry,
            serialize_json_object(entry, "provider")?,
            original_raw.as_ref(),
        )?;
        Ok(())
    }

    /// Remaining canonical bytes for a nonempty placement vector in this
    /// exact raw write. Retained unknown fields use the same patching as the
    /// writer. This is a search bound only; candidates still require complete
    /// raw validation (including pretty-document size) before publication.
    pub fn provider_placement_byte_budget(&self, id: &str, entry: &ProviderEntry) -> Result<usize> {
        let mut probe = entry.clone();
        probe.model_membership.placements = vec![super::ModelPlacement {
            id: String::new(),
            after: None,
        }];
        let original = self.providers();
        let original_entry = original.providers.get(id);
        let original_raw = original_entry
            .map(|entry| serialize_json_object(entry, "provider"))
            .transpose()?;
        let raw = self.provider_raw_for_write(
            id,
            original_entry,
            serialize_json_object(&probe, "provider")?,
            original_raw.as_ref(),
        )?;
        // The probe can equal an already oversized raw layer. Charge it even
        // when the ordinary unchanged-write fast path skipped serialization.
        readable_provider_bytes(&raw)?;
        let framing = serde_json::to_vec(&raw)?.len()
            - serde_json::to_vec(&probe.model_membership.placements)?.len();
        Ok(super::MAX_AUTHORED_PROVIDER_ENTRY_BYTES - framing)
    }

    fn provider_raw_for_write(
        &self,
        id: &str,
        original_entry: Option<&ProviderEntry>,
        requested_raw: Map<String, Value>,
        original_raw: Option<&Map<String, Value>>,
    ) -> Result<Map<String, Value>> {
        let changed = original_raw != Some(&requested_raw);
        let provider_path = provider_file_path_for_config(&self.path, id)?;
        let provider_exists = provider_path.exists();
        let mut raw = self.provider_raw_object(id)?;
        match original_entry {
            Some(_) if provider_exists => {
                merge_changed_provider_fields(
                    &mut raw,
                    original_raw.expect("serialized original provider"),
                    &requested_raw,
                );
                for key in PROVIDER_SKIPPED_KEYS {
                    if !requested_raw.contains_key(*key) {
                        raw.remove(*key);
                    }
                }
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
        if changed {
            readable_provider_bytes(&raw)?;
        }
        Ok(raw)
    }

    /// Resolve the exact prospective files through the same merge as reads,
    /// without writing a file or changing ambient process/thread state.
    pub fn providers_from_paths_after_writes(
        paths: &[PathBuf],
        writes: &BTreeMap<PathBuf, ProvidersConfig>,
    ) -> Result<ProvidersConfig> {
        let mut merged = Value::Object(Map::new());
        let mut warnings = Vec::new();
        for path in paths {
            if let Some(requested) = writes.get(path) {
                let mut doc = Self::load(path)?;
                let original = doc.providers();
                doc.set_layer_metadata_raw(
                    requested,
                    original.on_unlisted_models_fetch != requested.on_unlisted_models_fetch,
                    original.category_defaults != requested.category_defaults,
                )?;
                readable_document_bytes(&doc.raw)?;
                let mut layer = doc.raw.clone();
                if let Some(object) = layer.as_object_mut() {
                    object.remove("providers");
                }
                deep_merge_value(&mut merged, &layer);
                for (id, entry) in &requested.providers {
                    let requested_raw = serialize_json_object(entry, "provider")?;
                    let original_raw = original
                        .providers
                        .get(id)
                        .map(|entry| serialize_json_object(entry, "provider"))
                        .transpose()?;
                    let raw = doc.provider_raw_for_write(
                        id,
                        original.providers.get(id),
                        requested_raw,
                        original_raw.as_ref(),
                    )?;
                    // Apply project executable-config stripping and URL-change
                    // credential tombstones exactly as ordinary file reads do.
                    merge_provider_raw_for_layer(&mut merged, path, id, raw, &mut warnings);
                }
            } else {
                // Re-read raw files so omitted/default fields and URL-change
                // tombstones keep their ordinary layered semantics.
                if path.exists() {
                    let mut raw = Self::load(path)?.raw;
                    if let Some(object) = raw.as_object_mut() {
                        object.remove("providers");
                    }
                    deep_merge_value(&mut merged, &raw);
                }
                merge_provider_files_for_layer(&mut merged, path, &mut warnings);
            }
        }
        Ok(Self {
            path: PathBuf::new(),
            raw: merged,
            originally_loaded_providers: BTreeMap::new(),
        }
        .providers())
    }

    fn refresh_from_disk_unlocked(&mut self) -> Result<()> {
        let refreshed = Self::load(&self.path)?;
        self.raw = refreshed.raw;
        self.originally_loaded_providers = refreshed.originally_loaded_providers;
        Ok(())
    }
}

/// Same pretty JSON plus newline that the durable writer publishes. Parsed
/// views omit unknown provider keys, so charge these bytes before writing too.
fn readable_provider_bytes(value: &Map<String, Value>) -> Result<Vec<u8>> {
    let bytes = readable_document_bytes(value)?;
    if serde_json::to_vec(value)?.len() > super::MAX_AUTHORED_PROVIDER_ENTRY_BYTES {
        return Err(ProviderWriteValidationError::AuthoredEntryTooLarge.into());
    }
    Ok(bytes)
}

fn readable_document_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec_pretty(value).context("serializing provider/config layer")?;
    bytes.push(b'\n');
    if bytes.len() > crate::config::MAX_WORKSPACE_CONFIG_FILE_BYTES {
        return Err(ProviderWriteValidationError::DocumentTooLarge.into());
    }
    Ok(bytes)
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
    let requested_order = requested
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|model| {
            model
                .as_object()
                .and_then(|model| model.get("id"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
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

    // Model order is user-visible (and fetches intentionally put the current
    // upstream catalog before retained manual/unlisted entries). Preserve the
    // requested order after applying field-level conflict resolution; any
    // concurrent model the caller did not know about remains at the tail.
    let mut ordered = Vec::with_capacity(current_models.len());
    for id in requested_order {
        if let Some(index) = current_models.iter().position(|model| {
            model
                .as_object()
                .and_then(|model| model.get("id"))
                .and_then(Value::as_str)
                == Some(id.as_str())
        }) {
            ordered.push(current_models.remove(index));
        }
    }
    ordered.append(current_models);
    *current_models = ordered;
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
        // The immutable template identity covers renamed or proxied xAI
        // entries; it no longer depends on fetched model metadata, which is
        // not persisted (#545) and misfired on aggregators whose catalogs
        // merely list `x-ai/grok-*` models (OpenRouter).
        || entry
            .template
            .as_deref()
            .is_some_and(|template| matches!(template, "grok" | "grok-oauth"))
        || metadata_mentions_xai_grok(&entry.provider_metadata)
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
            let error = crate::config::value_free::json_error(&error).to_string();
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

fn merge_provider_files_for_layer(
    merged: &mut Value,
    config_path: &Path,
    warnings: &mut Vec<String>,
) {
    merge_provider_files_for_layer_mode(merged, config_path, warnings, false);
}

fn merge_provider_files_for_layer_mode(
    merged: &mut Value,
    config_path: &Path,
    warnings: &mut Vec<String>,
    preserve_authored_models: bool,
) {
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
                let authored = preserve_authored_models.then(|| provider.clone());
                merge_provider_raw_for_layer(merged, config_path, &id, provider, warnings);
                if let Some(authored) = authored {
                    for key in [
                        "models",
                        "model_field_patches",
                        "model_order",
                        "model_membership",
                    ] {
                        if let Some(value) = authored.get(key) {
                            merged["providers"][&id][key] = value.clone();
                        } else if let Some(provider) = merged["providers"][&id].as_object_mut() {
                            provider.remove(key);
                        }
                    }
                }
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

fn merge_provider_raw_for_layer(
    merged: &mut Value,
    config_path: &Path,
    id: &str,
    mut provider: Map<String, Value>,
    warnings: &mut Vec<String>,
) {
    if !config_path_is_global_user_layer(config_path) {
        strip_project_auth_command(id, &mut provider, "project provider config", warnings);
        strip_project_oauth_descriptor(id, &mut provider, "project provider config", warnings);
    }
    let url_changed = provider.get("url").is_some_and(|new_url| {
        merged
            .get("providers")
            .and_then(Value::as_object)
            .and_then(|providers| providers.get(id))
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
        // A higher-precedence destination must never inherit a
        // host-executed global credential producer. `null` is a
        // deliberate deep-merge tombstone for the optional field.
        provider
            .entry("auth_command".to_string())
            .or_insert(Value::Null);
        provider.entry("oauth".to_string()).or_insert(Value::Null);
    }
    let mut layer = Map::new();
    let mut providers = Map::new();
    providers.insert(id.to_string(), Value::Object(provider));
    layer.insert("providers".to_string(), Value::Object(providers));
    deep_merge_value(merged, &Value::Object(layer));
}

/// Only the canonical platform global config file has global authority.
/// Machine-local per-cwd, project `.cockpit`, attached workspace snapshots,
/// and `COCKPIT_CONFIG` are project scoped for executable configuration.
fn config_path_is_global_user_layer(config_path: &Path) -> bool {
    crate::config::dirs::global_config_file_unchecked().is_ok_and(|global| config_path == global)
}

fn strip_project_auth_command(
    provider_id: &str,
    provider: &mut Map<String, Value>,
    source: &'static str,
    warnings: &mut Vec<String>,
) -> bool {
    if provider.remove("auth_command").is_none() {
        return false;
    }
    tracing::warn!(
        provider = %provider_id,
        source,
        "ignored project-scoped provider auth_command; executable authentication is global-only"
    );
    warnings.push(
        "ignored project-scoped provider auth_command; executable authentication is global-only"
            .to_string(),
    );
    true
}

fn strip_project_oauth_descriptor(
    provider_id: &str,
    provider: &mut Map<String, Value>,
    source: &'static str,
    warnings: &mut Vec<String>,
) -> bool {
    if provider.remove("oauth").is_none() {
        return false;
    }
    tracing::warn!(
        provider = %provider_id,
        source,
        "ignored project-scoped provider OAuth descriptor; token endpoints are global-only"
    );
    warnings.push(
        "ignored project-scoped provider OAuth descriptor; token endpoints are global-only"
            .to_string(),
    );
    true
}

fn load_provider_files_into_config(config_path: &Path, cfg: &mut ProvidersConfig) {
    let mut merged = Value::Object(Map::new());
    merge_provider_files_for_layer_mode(&mut merged, config_path, &mut Vec::new(), true);
    if let Some(map) = merged.get("providers").and_then(Value::as_object) {
        for (id, v) in map {
            match serde_json::from_value::<ProviderEntry>(v.clone()) {
                Ok(entry) => {
                    cfg.providers.insert(id.clone(), entry);
                }
                Err(e) => {
                    let e = crate::config::value_free::json_error(&e).to_string();
                    tracing::warn!(provider = %id, error = %e, "skipping malformed provider entry");
                }
            }
        }
    }
}

pub fn load_provider_raw_file(path: &Path) -> Result<Map<String, Value>> {
    // No outer read context: the bounded reader already attaches a
    // `reading <path>` context to IO failures and surfaces over-cap
    // files as a top-level `exceeds the byte limit` failure.
    let raw = crate::config::files::read_workspace_config_text(path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "reading provider config at {}: file not found",
            path.display()
        )
    })?;
    let value: Value = if raw.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(&raw)
            .with_context(|| format!("parsing provider config at {}", path.display()))?
    };
    match value {
        Value::Object(map) => Ok(map),
        other => anyhow::bail!(
            "expected provider config root to be an object at {}, found {other:?}",
            path.display()
        ),
    }
}

#[cfg(test)]
mod atomic_write_tests {
    use serde_json::{Map, Value};

    use super::{strip_project_auth_command, strip_project_oauth_descriptor};

    #[test]
    fn sparse_membership_raw_writer_enforces_single_authored_budget_before_any_write() {
        use super::super::{
            ConfigDoc, ModelEntry, ModelMembershipPatch, ModelPlacement, OnUnlistedModelsFetch,
            ProviderEntry, ProvidersConfig,
        };
        use std::collections::BTreeMap;
        let _env = cockpit_test_support::TestEnvGuard::isolated_cockpit_home();
        let path = crate::config::dirs::global_config_file().unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{}").unwrap();
        let mut config = ProvidersConfig::default();
        config.providers.insert(
            "p".into(),
            ProviderEntry {
                url: "https://example.com".into(),
                models: vec![ModelEntry {
                    id: "owner".into(),
                    name: Some("x".repeat(240 * 1024)),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let mut doc = ConfigDoc::load(&path).unwrap();
        doc.write(&config).unwrap();
        let provider_path = path.parent().unwrap().join("providers/p.json");
        let original_provider = std::fs::read(&provider_path).unwrap();
        let original_config = std::fs::read(&path).unwrap();
        let mut desired = doc.providers();
        desired.on_unlisted_models_fetch = Some(OnUnlistedModelsFetch::Ask);
        desired.providers.get_mut("p").unwrap().model_membership = ModelMembershipPatch {
            deletes: vec!["deleted".into()],
            placements: vec![ModelPlacement {
                id: "owner".into(),
                after: None,
            }],
        };
        // The delta itself fits ingress, but the total authored layer does not.
        desired
            .providers
            .get_mut("p")
            .unwrap()
            .models
            .push(ModelEntry {
                id: "new".into(),
                name: Some("y".repeat(32 * 1024)),
                ..Default::default()
            });
        let error = ConfigDoc::providers_from_paths_after_writes(
            std::slice::from_ref(&path),
            &BTreeMap::from([(path.clone(), desired.clone())]),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("authored provider entry exceeds"),
            "{error}"
        );
        let error = doc.write(&desired).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("authored provider entry exceeds"),
            "{error}"
        );
        assert_eq!(std::fs::read(&provider_path).unwrap(), original_provider);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original_config,
            "failed preflight must not write layer metadata"
        );
    }

    #[test]
    fn authored_model_edits_do_not_fabricate_rows_omitted_from_the_authored_file() {
        use super::ConfigDoc;
        let _env = cockpit_test_support::TestEnvGuard::isolated_cockpit_home();
        let path = crate::config::dirs::global_config_file().unwrap();
        std::fs::create_dir_all(path.parent().unwrap().join("providers")).unwrap();
        std::fs::write(&path, "{}").unwrap();
        let provider_path = path.parent().unwrap().join("providers/p.json");
        std::fs::write(&provider_path,r#"{"url":"https://example.com","model_field_patches":[{"id":"same","set":{"favorite":true},"remove":[]}]}"#).unwrap();
        let mut doc = ConfigDoc::load(&path).unwrap();
        let mut desired = doc.providers();
        assert!(
            desired.providers["p"].models.is_empty(),
            "authored view must not materialize sparse rows"
        );
        assert_eq!(desired.providers["p"].model_field_patches.len(), 1);
        desired.providers.get_mut("p").unwrap().name = Some("metadata edit".into());
        doc.write(&desired).unwrap();
        let raw = super::load_provider_raw_file(&provider_path).unwrap();
        assert!(
            !raw.contains_key("models"),
            "unchanged omitted authored rows stay omitted after save"
        );
        let effective = ConfigDoc::providers_from_paths(&[path]);
        assert!(effective.providers["p"].models[0].favorite);
    }

    #[test]
    fn sparse_model_edits_keep_multi_megabyte_composed_rows_in_their_owner_layers() {
        use super::super::{ConfigDoc, ModelEntryFieldPatch};
        use std::collections::BTreeMap;
        let _env = cockpit_test_support::TestEnvGuard::isolated_cockpit_home();
        let root = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for index in 0..12 {
            let path = root.path().join(format!("layer-{index}/config.json"));
            std::fs::create_dir_all(path.parent().unwrap().join("providers")).unwrap();
            std::fs::write(&path, "{}").unwrap();
            let row = serde_json::json!({"id":"same", "extra": {format!("owner-{index}"): "x".repeat(190*1024)}});
            std::fs::write(
                path.parent().unwrap().join("providers/p.json"),
                serde_json::to_vec(
                    &serde_json::json!({"url":"https://example.com", "models":[row]}),
                )
                .unwrap(),
            )
            .unwrap();
            paths.push(path);
        }
        let path = paths.last().unwrap();
        let mut doc = ConfigDoc::load(path).unwrap();
        let before = ConfigDoc::providers_from_paths(&paths);
        assert!(
            serde_json::to_vec(&before.providers["p"].models[0])
                .unwrap()
                .len()
                > crate::config::MAX_WORKSPACE_CONFIG_FILE_BYTES
        );
        let mut desired = doc.providers();
        desired
            .providers
            .get_mut("p")
            .unwrap()
            .model_field_patches
            .push(ModelEntryFieldPatch {
                id: "same".into(),
                replace: false,
                set: BTreeMap::from([("favorite".into(), Value::Bool(true))]),
                remove: Vec::new(),
            });
        let preview = ConfigDoc::providers_from_paths_after_writes(
            &paths,
            &BTreeMap::from([(path.clone(), desired.clone())]),
        )
        .unwrap();
        doc.write(&desired).unwrap();
        let actual = ConfigDoc::providers_from_paths(&paths);
        assert_eq!(
            serde_json::to_value(&preview).unwrap(),
            serde_json::to_value(&actual).unwrap()
        );
        assert!(actual.providers["p"].models[0].favorite);
        assert_eq!(
            actual.providers["p"].models[0].extra,
            before.providers["p"].models[0].extra
        );
        let authored = doc.providers();
        assert_eq!(
            authored.providers["p"].model_field_patches.len(),
            1,
            "authored deltas survive ConfigDoc reload"
        );
        assert!(
            std::fs::metadata(path.parent().unwrap().join("providers/p.json"))
                .unwrap()
                .len()
                < 256 * 1024
        );
        doc.write_model_favorite("p", "same", false).unwrap();
        let actual = ConfigDoc::providers_from_paths(&paths);
        assert!(
            !actual.providers["p"].models[0].favorite,
            "direct favorite supersedes prior sparse edit"
        );
        assert_eq!(
            actual.providers["p"].models[0].extra,
            before.providers["p"].models[0].extra
        );
        let mut desired = doc.providers();
        desired.providers.get_mut("p").unwrap().model_order = Some(Vec::new());
        doc.write(&desired).unwrap();
        assert!(
            ConfigDoc::providers_from_paths(&paths).providers["p"]
                .models
                .is_empty()
        );
        assert!(
            ConfigDoc::providers_from_paths(&paths).providers["p"]
                .model_order
                .is_none(),
            "effective view consumes authoring instructions"
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_favorite_obeys_authored_budget_before_replacing_the_captured_file() {
        use super::*;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::create_dir(root.path().join("providers")).unwrap();
        let provider_path = root.path().join("providers/p.json");
        let mut raw =
            serde_json::json!({"url":"https://example.com","models":[{"id":"same","name":""}]});
        let overhead = serde_json::to_vec(&raw).unwrap().len();
        raw["models"][0]["name"] = Value::String(
            "x".repeat(super::super::MAX_AUTHORED_PROVIDER_ENTRY_BYTES - overhead - 1),
        );
        let bytes = serde_json::to_vec(&raw).unwrap();
        assert!(bytes.len() < super::super::MAX_AUTHORED_PROVIDER_ENTRY_BYTES);
        std::fs::write(&provider_path, &bytes).unwrap();
        let source = retained_provider_model_source_from_workspace_layer_snapshots(
            &[crate::config::WorkspaceConfigLayerSnapshot {
                origin: None,
                project_root: None,
                config_json: None,
                provider_files: vec![("p".into(), bytes.clone())],
                effective_default_artifact_digest: None,
                digest: "source".into(),
            }],
            "p",
            "same",
        )
        .unwrap()
        .unwrap();
        let target = RetainedProviderModelFavoriteTarget::new(
            std::fs::File::open(root.path()).unwrap(),
            std::fs::canonicalize(&path).unwrap(),
            source,
        )
        .unwrap();
        let error = target.write_model_favorite(true).unwrap_err();
        let RetainedProviderModelFavoriteWriteError::Rejected(cause) = error else {
            panic!("budget must reject before the durable boundary")
        };
        assert!(
            cause
                .to_string()
                .contains("authored provider entry exceeds"),
            "{cause}"
        );
        assert_eq!(std::fs::read(&provider_path).unwrap(), bytes);
    }

    #[cfg(unix)]
    #[test]
    fn retained_favorite_uses_the_sparse_edit_layer_and_supersedes_its_field() {
        use super::*;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::create_dir(root.path().join("providers")).unwrap();
        let provider_path = root.path().join("providers/p.json");
        std::fs::write(&provider_path,r#"{"url":"https://example.com","models":[],"model_field_patches":[{"id":"same","replace":true,"set":{"favorite":true,"name":"fresh image"},"remove":[]}]}"#).unwrap();
        let source_for = |bytes: Vec<u8>| {
            retained_provider_model_source_from_workspace_layer_snapshots(
                &[crate::config::WorkspaceConfigLayerSnapshot {
                    origin: None,
                    project_root: None,
                    config_json: None,
                    provider_files: vec![("p".into(), bytes)],
                    effective_default_artifact_digest: None,
                    digest: "source".into(),
                }],
                "p",
                "same",
            )
            .unwrap()
            .expect("sparse source")
        };
        let source = source_for(std::fs::read(&provider_path).unwrap());
        let target = RetainedProviderModelFavoriteTarget::new(
            std::fs::File::open(root.path()).unwrap(),
            std::fs::canonicalize(&path).unwrap(),
            source,
        )
        .unwrap();
        target.validate_model_favorite_noop(true).unwrap();
        let receipt = target.write_model_favorite(false).unwrap();
        assert!(
            receipt.matches_committed_source(&source_for(std::fs::read(&provider_path).unwrap()))
        );
        let raw = load_provider_raw_file(&provider_path).unwrap();
        assert!(
            !authored_model_value(&raw, "same").unwrap().unwrap()["favorite"]
                .as_bool()
                .unwrap()
        );
        let source = source_for(std::fs::read(&provider_path).unwrap());
        let next = RetainedProviderModelFavoriteTarget::new(
            std::fs::File::open(root.path()).unwrap(),
            std::fs::canonicalize(&path).unwrap(),
            source,
        )
        .unwrap();
        next.validate_model_favorite_noop(false).unwrap();
        next.write_model_favorite(true).unwrap();
        let mut doc = ConfigDoc::load(&path).unwrap();
        doc.write_model_wizard_fields(
            "p",
            &ModelEntry {
                id: "same".into(),
                system_prompt: Some("fresh prompt".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let effective = ConfigDoc::providers_from_paths(&[path]);
        let model = &effective.providers["p"].models[0];
        assert!(
            model.favorite,
            "direct favorite survives a replacement-row reset"
        );
        assert_eq!(model.name.as_deref(), Some("fresh image"));
        assert_eq!(
            model.system_prompt.as_deref(),
            Some("fresh prompt"),
            "wizard fields override replacement-row values"
        );
    }

    #[test]
    fn explicit_model_membership_has_a_retained_favorite_source_without_a_lower_row() {
        let membership = serde_json::json!({"model_order":["same"]});
        assert!(
            super::authored_model_value(membership.as_object().unwrap(), "same")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn prospective_layer_write_matches_actual_raw_patch_and_reloaded_composition() {
        use super::super::{ConfigDoc, ModelEntry};
        use std::collections::BTreeMap;
        let _env = cockpit_test_support::TestEnvGuard::isolated_cockpit_home();
        let global = crate::config::dirs::global_config_file().unwrap();
        std::fs::create_dir_all(global.parent().unwrap().join("providers")).unwrap();
        std::fs::write(&global, "{}").unwrap();
        std::fs::write(global.parent().unwrap().join("providers/p.json"), r#"{"url":"https://example.com","models":[{"id":"a","name":"retained"},{"id":"b"}],"opaque_field":{"keep":true}}"#).unwrap();
        let paths = vec![global.clone()];
        for models in [
            vec![ModelEntry {
                id: "a".into(),
                name: Some("fresh".into()),
                ..Default::default()
            }],
            Vec::new(),
        ] {
            let mut doc = ConfigDoc::load(&global).unwrap();
            let mut desired = doc.providers();
            desired.providers.get_mut("p").unwrap().models = models;
            desired.providers.get_mut("p").unwrap().models_replace = true;
            let before = std::fs::read(global.parent().unwrap().join("providers/p.json")).unwrap();
            let preview = ConfigDoc::providers_from_paths_after_writes(
                &paths,
                &BTreeMap::from([(global.clone(), desired.clone())]),
            )
            .unwrap();
            assert_eq!(
                std::fs::read(global.parent().unwrap().join("providers/p.json")).unwrap(),
                before,
                "preflight must not write"
            );
            doc.write(&desired).unwrap();
            let actual = ConfigDoc::providers_from_paths(&paths);
            assert_eq!(
                serde_json::to_value(&preview).unwrap(),
                serde_json::to_value(&actual).unwrap()
            );
            assert_eq!(
                super::load_provider_raw_file(&global.parent().unwrap().join("providers/p.json"))
                    .unwrap()["opaque_field"],
                serde_json::json!({"keep":true})
            );
        }
    }

    #[test]
    fn project_auth_command_is_ignored_and_reported() {
        let mut provider = Map::from_iter([
            (
                "url".into(),
                Value::String("https://example.test/v1".into()),
            ),
            (
                "auth_command".into(),
                serde_json::json!(["/definitely/must/not/run"]),
            ),
        ]);

        let mut warnings = Vec::new();
        let warned = strip_project_auth_command(
            "custom",
            &mut provider,
            "test project config",
            &mut warnings,
        );

        assert!(
            warned,
            "stripping the command must surface a warning signal"
        );
        assert!(!provider.contains_key("auth_command"));
        assert_eq!(provider["url"], "https://example.test/v1");
        assert_eq!(
            warnings,
            [
                "ignored project-scoped provider auth_command; executable authentication is global-only"
            ]
        );
    }

    #[test]
    fn project_oauth_descriptor_is_ignored_and_reported() {
        let mut provider = Map::from_iter([
            (
                "url".into(),
                Value::String("https://example.test/v1".into()),
            ),
            (
                "oauth".into(),
                serde_json::json!({
                    "flow": "device_code",
                    "device_endpoint": "https://attacker.test/device",
                    "token_endpoint": "https://attacker.test/token",
                    "client_id": "client",
                    "headers": [{"name":"Authorization","value":"Bearer {access_token}"}]
                }),
            ),
        ]);

        let mut warnings = Vec::new();
        let warned = strip_project_oauth_descriptor(
            "custom",
            &mut provider,
            "test project config",
            &mut warnings,
        );

        assert!(warned);
        assert!(!provider.contains_key("oauth"));
        assert_eq!(
            warnings,
            ["ignored project-scoped provider OAuth descriptor; token endpoints are global-only"]
        );
    }

    #[test]
    fn retained_project_layer_cannot_replace_global_auth_command() {
        let snapshot = |origin, command: &str| crate::config::WorkspaceConfigLayerSnapshot {
            origin,
            project_root: None,
            config_json: None,
            provider_files: vec![(
                "custom".into(),
                serde_json::to_vec(&serde_json::json!({
                    "url": "https://example.test/v1",
                    "auth": "command",
                    "auth_command": [command],
                    "models": [{ "id": "model" }]
                }))
                .unwrap(),
            )],
            effective_default_artifact_digest: None,
            digest: command.into(),
        };
        let global = snapshot(
            Some(crate::config::dirs::ConfigDirKind::HomeXdg),
            "/trusted/global-helper",
        );
        let project = snapshot(
            Some(crate::config::dirs::ConfigDirKind::Project),
            "/must/not/execute",
        );

        let providers =
            super::ConfigDoc::providers_from_workspace_layer_snapshots(&[global, project]).unwrap();

        assert_eq!(
            providers.providers["custom"].auth_command.as_deref(),
            Some(["/trusted/global-helper".to_string()].as_slice())
        );
    }

    #[test]
    fn project_url_override_clears_global_auth_command() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project/config.json");
        std::fs::create_dir_all(project.parent().unwrap().join("providers")).unwrap();
        std::fs::write(
            project.parent().unwrap().join("providers/custom.json"),
            r#"{"url":"https://project.example/v1"}"#,
        )
        .unwrap();

        let mut merged = serde_json::json!({
            "providers": {
                "custom": {
                    "url": "https://global.example/v1",
                    "auth_command": ["trusted-helper"]
                }
            }
        });
        super::merge_provider_files_for_layer(&mut merged, &project, &mut Vec::new());
        assert_eq!(
            merged["providers"]["custom"]["url"],
            "https://project.example/v1"
        );
        assert!(merged["providers"]["custom"]["auth_command"].is_null());
    }

    #[test]
    fn daemon_snapshot_load_returns_project_auth_command_warning() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("project/config.json");
        std::fs::create_dir_all(config.parent().unwrap().join("providers")).unwrap();
        std::fs::write(
            config.parent().unwrap().join("providers/custom.json"),
            r#"{"url":"https://project.example/v1","auth_command":["must-not-run"]}"#,
        )
        .unwrap();

        let (providers, _layers, warnings) =
            super::ConfigDoc::try_load_effective_with_layer_snapshot(&[config]).unwrap();
        assert!(providers.providers["custom"].auth_command.is_none());
        assert_eq!(
            warnings,
            [
                "ignored project-scoped provider auth_command; executable authentication is global-only"
            ]
        );
    }

    #[test]
    fn auth_command_schema_rejects_empty_argv() {
        let error = serde_json::from_value::<super::ProviderEntry>(serde_json::json!({
            "auth": "command",
            "auth_command": []
        }))
        .unwrap_err();

        assert!(error.to_string().contains("non-empty executable"));
    }

    #[test]
    fn load_fails_closed_when_config_json_exceeds_the_workspace_cap() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");
        let handle = std::fs::File::create(&path).unwrap();
        handle
            .set_len(crate::config::MAX_WORKSPACE_CONFIG_FILE_BYTES as u64 + 1)
            .unwrap();
        drop(handle);
        let err = super::ConfigDoc::load(&path).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("exceeds the") && text.contains("byte limit"),
            "{text}"
        );
    }

    #[test]
    fn load_provider_raw_file_fails_closed_when_over_cap() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("custom.json");
        let handle = std::fs::File::create(&path).unwrap();
        handle
            .set_len(crate::config::MAX_WORKSPACE_CONFIG_FILE_BYTES as u64 + 1)
            .unwrap();
        drop(handle);
        let err = super::load_provider_raw_file(&path).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("exceeds the") && text.contains("byte limit"),
            "{text}"
        );
    }

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

#[cfg(test)]
mod codex_r2_doc_probe {
    use super::*;
    #[test]
    fn codex_r2_config_doc_debug_is_value_free() {
        let secret = "NovelConfigDoc515Secret78529";
        let doc = ConfigDoc {
            path: std::path::PathBuf::from("config.json"),
            raw: serde_json::json!({"providers":{"sample":{"headers":[{"name":"Authorization","value":format!("Bearer {secret}")}]}}}),
            originally_loaded_providers: BTreeMap::new(),
        };
        assert!(
            !format!("{doc:?}").contains(secret),
            "raw config document Debug leaks header value"
        );
    }
}
