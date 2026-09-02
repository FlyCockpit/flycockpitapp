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
        let Some(models) = provider.get("models").and_then(Value::as_array) else {
            continue;
        };
        let mut matching = models.iter().filter(|model| {
            model
                .as_object()
                .and_then(|model| model.get("id"))
                .and_then(Value::as_str)
                == Some(model_id)
        });
        let Some(model) = matching.next() else {
            continue;
        };
        anyhow::ensure!(
            matching.next().is_none(),
            "retained provider `{provider_id}` contains duplicate model `{model_id}`"
        );
        return Ok(Some(RetainedProviderModelSource {
            layer_index,
            provider_id: provider_id.to_string(),
            model_id: model_id.to_string(),
            provider_digest: sha256_bytes(provider_bytes),
            model_digest: sha256_model_value(model)?,
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
        let pretty = serde_json::to_string_pretty(&Value::Object(provider.clone()))
            .context("serializing captured provider config")
            .map_err(RetainedProviderModelFavoriteWriteError::Rejected)?;
        let new_bytes = format!("{pretty}\n").into_bytes();
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

/// Retained favorite writes differ deliberately from the ambient edit helper:
/// an attached session may update only the model object it actually observed.
/// It must never manufacture a model after a source has changed.
fn apply_captured_model_favorite(
    provider: &mut Map<String, Value>,
    model_id: &str,
    expected_model_digest: [u8; 32],
    favorite: bool,
) -> Result<[u8; 32]> {
    let models = provider
        .get_mut("models")
        .and_then(Value::as_array_mut)
        .context("captured provider models are missing or malformed")?;
    let matches = models
        .iter()
        .enumerate()
        .filter_map(|(index, model)| {
            (model
                .as_object()
                .and_then(|model| model.get("id"))
                .and_then(Value::as_str)
                == Some(model_id))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    let index = *matches
        .first()
        .context("captured provider model is no longer present")?;
    anyhow::ensure!(
        matches.len() == 1,
        "captured provider now contains duplicate model `{model_id}`"
    );
    let model = &mut models[index];
    anyhow::ensure!(
        sha256_model_value(model)? == expected_model_digest,
        "captured provider model changed after attached snapshot"
    );
    let model = model
        .as_object_mut()
        .context("captured provider model must be an object")?;
    model.insert("favorite".to_string(), Value::Bool(favorite));
    sha256_model_value(&Value::Object(model.clone()))
}

/// Prove that the exact captured model object is still present and already
/// carries the requested favorite. This is deliberately separate from the
/// mutating helper so a no-op RPC never reformats a provider file.
fn validate_captured_model_favorite(
    provider: &Map<String, Value>,
    model_id: &str,
    expected_model_digest: [u8; 32],
    favorite: bool,
) -> Result<()> {
    let models = provider
        .get("models")
        .and_then(Value::as_array)
        .context("captured provider models are missing or malformed")?;
    let mut matching = models.iter().filter(|model| {
        model
            .as_object()
            .and_then(|model| model.get("id"))
            .and_then(Value::as_str)
            == Some(model_id)
    });
    let model = matching
        .next()
        .context("captured provider model is no longer present")?;
    anyhow::ensure!(
        matching.next().is_none(),
        "captured provider has duplicate model `{model_id}`"
    );
    anyhow::ensure!(
        sha256_model_value(model)? == expected_model_digest,
        "captured provider model changed after attached snapshot"
    );
    let model = model
        .as_object()
        .context("captured provider model must be an object")?;
    let observed_favorite = match model.get("favorite") {
        Some(value) => value
            .as_bool()
            .context("captured provider model favorite must be a boolean")?,
        None => false,
    };
    anyhow::ensure!(
        observed_favorite == favorite,
        "captured provider model favorite no longer matches requested value"
    );
    Ok(())
}

fn apply_model_favorite(provider: &mut Map<String, Value>, model_id: &str, favorite: bool) {
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
            reject_legacy_redact_fields(id, &provider)?;
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
            None => match crate::config::files::read_workspace_config_text(&path)
                .with_context(|| format!("reading config.json at {}", path.display()))?
            {
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
        apply_model_favorite(&mut provider, model_id, favorite);
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
        let Some(raw) = crate::config::files::read_workspace_config_text(&path)
            .with_context(|| format!("reading provider config at {}", path.display()))?
        else {
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

fn merge_provider_files_for_layer(
    merged: &mut Value,
    config_path: &Path,
    warnings: &mut Vec<String>,
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
            Ok(mut provider) => {
                if !config_path_is_global_user_layer(config_path) {
                    strip_project_auth_command(
                        &id,
                        &mut provider,
                        "project provider config",
                        warnings,
                    );
                    strip_project_oauth_descriptor(
                        &id,
                        &mut provider,
                        "project provider config",
                        warnings,
                    );
                }
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

/// Only the canonical platform global config file has global authority.
/// Machine-local per-cwd, project `.cockpit`, attached workspace snapshots,
/// and `COCKPIT_CONFIG` are project scoped for executable configuration.
fn config_path_is_global_user_layer(config_path: &Path) -> bool {
    crate::config::dirs::global_config_file().is_ok_and(|global| config_path == global)
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
    merge_provider_files_for_layer(&mut merged, config_path, &mut Vec::new());
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
    let raw = crate::config::files::read_workspace_config_text(path)
        .with_context(|| format!("reading provider config at {}", path.display()))?
        .ok_or_else(|| {
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
            "provider `{provider_id}` uses legacy `redact`; use `trust: \"trusted\"` for host-mediated capture or `trust: \"untrusted\"` to disable capture (sealed inference remains reference-only for every trust level)"
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
                    "model `{provider_id}:{model_id}` uses legacy `redact`; use `trust: \"trusted\"` for host-mediated capture or `trust: \"untrusted\"` to disable capture (sealed inference remains reference-only for every trust level)"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod atomic_write_tests {
    use serde_json::{Map, Value};

    use super::{strip_project_auth_command, strip_project_oauth_descriptor};

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
