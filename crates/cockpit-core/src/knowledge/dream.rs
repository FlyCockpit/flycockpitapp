//! Governed knowledge synthesis over explicitly attached sessions.
//!
//! The model-facing orchestrator may fan out one layer of read-only workers,
//! but its only durable product is a provider-neutral [`DreamChangeSet`]. This
//! module owns selection, target-union redaction, human provenance protection,
//! sink dispatch, and completion-ledger ordering.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    Citation, KnowledgeConcept, KnowledgeDreamCommit, KnowledgeDreamGitOutcome,
    KnowledgeDreamWrite, apply_knowledge_dream_writes, apply_registered_knowledge_dream,
    parse_bundle,
};
use crate::config::extended::{ExtendedConfig, KnowledgeBaseRegistryEntry, KnowledgeBaseSource};
use crate::config::providers::{ModelTrust, ProvidersConfig};
use crate::db::knowledge_dreams::DreamSessionSource;
use crate::db::session_search::HistoryCallerTrust;
use crate::redact::RedactionTable;
use crate::session::Session;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConceptProvenance {
    Human,
    Agent,
    Dream,
}

impl ConceptProvenance {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Dream => "dream",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConceptUpsert {
    pub id: String,
    #[serde(rename = "type")]
    pub concept_type: String,
    pub title: Option<String>,
    pub body: String,
    #[serde(default)]
    pub citations: Vec<Citation>,
    pub provenance: ConceptProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DreamChangeSet {
    pub knowledge_base_id: String,
    pub source_session_ids: Vec<Uuid>,
    pub upserts: Vec<ConceptUpsert>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDreamModel {
    pub provider: String,
    pub model: String,
}

impl ResolvedDreamModel {
    pub fn reference(&self) -> String {
        format!("{}:{}", self.provider, self.model)
    }
}

/// Match the existing transcript/search model-trust boundary for the source
/// descriptions delivered by `knowledge_dream_sources`.
pub(crate) fn history_caller_trust(
    model: &ResolvedDreamModel,
    providers: &ProvidersConfig,
) -> HistoryCallerTrust {
    if providers
        .resolve_trust(&model.provider, &model.model)
        .is_trusted()
    {
        HistoryCallerTrust::Trusted
    } else {
        HistoryCallerTrust::Untrusted
    }
}

pub fn resolve_dream_model(
    knowledge_base: &KnowledgeBaseRegistryEntry,
    config: &ExtendedConfig,
    providers: &ProvidersConfig,
) -> Result<ResolvedDreamModel> {
    let reference = knowledge_base
        .dream_model
        .as_deref()
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .or_else(|| config.dream_model_ref())
        .with_context(|| {
            format!(
                "knowledge base `{}` has no dream model (set dreamModel, dream_model, or utility_model)",
                knowledge_base.id
            )
        })?;
    let (provider, model) = reference
        .split_once(':')
        .or_else(|| reference.split_once('/'))
        .with_context(|| format!("dream model `{reference}` must be provider:model"))?;
    ensure!(
        !provider.trim().is_empty() && !model.trim().is_empty(),
        "dream model `{reference}` must be provider:model"
    );
    if knowledge_base.trust_required
        && providers.resolve_trust(provider, model) != ModelTrust::Trusted
    {
        bail!(
            "knowledge base `{}` requires a trusted dream model; `{reference}` resolves untrusted",
            knowledge_base.id
        );
    }
    Ok(ResolvedDreamModel {
        provider: provider.to_owned(),
        model: model.to_owned(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DreamRunOutcome {
    NothingToDream,
    Applied {
        sessions_dreamed: usize,
        concepts_written: usize,
        sink: KnowledgeDreamGitOutcome,
    },
    Deferred {
        sessions_pending: usize,
        sink: KnowledgeDreamGitOutcome,
    },
}

#[async_trait]
pub trait DreamSink: Send + Sync {
    async fn apply(
        &self,
        model: &ResolvedDreamModel,
        change_set: &DreamChangeSet,
        cancel: CancellationToken,
    ) -> Result<KnowledgeDreamGitOutcome>;
}

/// The only launch sink. Git/fencing remains encapsulated in the existing KB
/// provider transaction; the engine sees only this interface and its outcome.
pub struct LocalGitSink {
    session: Arc<Session>,
    cwd: PathBuf,
    allowed_knowledge_bases: Option<BTreeSet<String>>,
    config: ExtendedConfig,
}

/// TODO(hosted dream service): add `RemoteSink` when hosted KB writes can
/// submit authenticated change sets to the server. It deliberately has no
/// launch implementation; `LocalGitSink` is the sole current sink.
pub struct RemoteSink;

impl LocalGitSink {
    pub fn new(
        session: Arc<Session>,
        cwd: PathBuf,
        allowed_knowledge_bases: Option<BTreeSet<String>>,
        config: ExtendedConfig,
    ) -> Self {
        Self {
            session,
            cwd,
            allowed_knowledge_bases,
            config,
        }
    }
}

#[async_trait]
impl DreamSink for LocalGitSink {
    async fn apply(
        &self,
        model: &ResolvedDreamModel,
        change_set: &DreamChangeSet,
        cancel: CancellationToken,
    ) -> Result<KnowledgeDreamGitOutcome> {
        let change_set = change_set.clone();
        let commit = KnowledgeDreamCommit {
            knowledge_base_id: change_set.knowledge_base_id.clone(),
            model: model.reference(),
            sessions_dreamed: change_set.source_session_ids.len(),
            concepts_written: change_set.upserts.len(),
            data_files_written: 0,
        };
        apply_registered_knowledge_dream(
            &self.session,
            &self.cwd,
            self.allowed_knowledge_bases.as_ref(),
            &self.config,
            &commit,
            cancel,
            move |root| apply_change_set_to_local_bundle(root, &change_set),
        )
        .await
    }
}

fn apply_change_set_to_local_bundle(root: &Path, change_set: &DreamChangeSet) -> Result<()> {
    let existing = parse_bundle(root)?;
    let by_id: BTreeMap<&str, &KnowledgeConcept> = existing
        .concepts
        .iter()
        .map(|concept| (concept.id.as_str(), concept))
        .collect();
    for upsert in &change_set.upserts {
        if let Some(concept) = by_id.get(upsert.id.as_str())
            && concept.provenance == ConceptProvenance::Human
        {
            bail!(
                "dream cannot modify human-provenance concept `{}`",
                upsert.id
            );
        }
    }

    let writes = change_set
        .upserts
        .iter()
        .map(|upsert| {
            let mut frontmatter = BTreeMap::new();
            frontmatter.insert("id".to_owned(), upsert.id.clone());
            frontmatter.insert(
                "provenance".to_owned(),
                ConceptProvenance::Dream.as_str().to_owned(),
            );
            if let Some(title) = &upsert.title {
                frontmatter.insert("title".to_owned(), title.clone());
            }
            let concept = KnowledgeConcept {
                id: upsert.id.clone(),
                path: PathBuf::from(format!("{}.md", upsert.id)),
                concept_type: upsert.concept_type.clone(),
                provenance: ConceptProvenance::Dream,
                frontmatter,
                body: upsert.body.clone(),
                citations: upsert.citations.clone(),
                valid_from: None,
                supersedes: Vec::new(),
                invalidated_by: None,
            };
            KnowledgeDreamWrite {
                path: concept.path.to_string_lossy().into_owned(),
                content: super::serialize_concept(&concept),
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        writes.len() <= super::MAX_KNOWLEDGE_FILES,
        "dream change set exceeds the knowledge file-count limit"
    );
    let mut total_bytes = 0_usize;
    for write in &writes {
        ensure!(
            write.content.len() <= super::MAX_KNOWLEDGE_FILE_BYTES,
            "dream concept `{}` exceeds the knowledge file size limit",
            write.path
        );
        total_bytes = total_bytes
            .checked_add(write.content.len())
            .context("dream change-set size overflow")?;
    }
    ensure!(
        total_bytes <= super::MAX_KNOWLEDGE_TOTAL_BYTES,
        "dream change set exceeds the aggregate knowledge size limit"
    );
    apply_knowledge_dream_writes(root, &writes)
}

pub struct DreamEngine {
    session: Arc<Session>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CanonicalDreamProjectRoot(String);

impl CanonicalDreamProjectRoot {
    pub(crate) fn from_request_root(
        requested_root: &str,
    ) -> std::result::Result<Self, crate::daemon::server::ErrorPayload> {
        let canonical = crate::daemon::fs_api::canonical_project_root(requested_root)?;
        Self::from_canonical_path(&canonical).map_err(|error| crate::daemon::server::ErrorPayload {
            code: crate::daemon::server::ErrorCode::RootMissing,
            message: error.to_string(),
        })
    }

    pub(crate) fn from_session_path(path: &Path) -> Result<Self> {
        let canonical = std::fs::canonicalize(path).with_context(|| {
            format!(
                "canonicalizing knowledge dream project root {}",
                path.display()
            )
        })?;
        Self::from_canonical_path(&canonical)
    }

    /// Reuse a persisted root identity that was canonicalized earlier when the
    /// session row was created. This preserves the exact DB/lock key even if
    /// the directory has since been deleted.
    pub(crate) fn from_persisted_canonical_root(project_root: &str) -> Result<Self> {
        let path = Path::new(project_root);
        ensure!(
            path.is_absolute(),
            "knowledge dream project root must be absolute"
        );
        ensure!(
            path.to_str().is_some(),
            "knowledge dream project root is not valid UTF-8"
        );
        Ok(Self(project_root.to_owned()))
    }

    pub(crate) fn from_canonical_path(path: &Path) -> Result<Self> {
        ensure!(
            path.is_absolute(),
            "knowledge dream project root must be absolute"
        );
        ensure!(
            path.is_dir(),
            "knowledge dream project root must be a directory"
        );
        Ok(Self(
            path.to_str()
                .context("knowledge dream project root is not valid UTF-8")?
                .to_owned(),
        ))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl DreamEngine {
    pub fn new(session: Arc<Session>) -> Self {
        Self { session }
    }

    /// Validate and apply the final merge produced by the orchestrator. The
    /// orchestrator and its one worker layer never receive a write capability.
    pub async fn apply_orchestrated_change_set(
        &self,
        knowledge_base: &KnowledgeBaseRegistryEntry,
        config: &ExtendedConfig,
        providers: &ProvidersConfig,
        executing_model: &str,
        reader_redaction: &RedactionTable,
        change_set: DreamChangeSet,
        sink: &dyn DreamSink,
        cancel: CancellationToken,
    ) -> Result<DreamRunOutcome> {
        // Daemon advisory serialization covers selection through ledger
        // commit. LocalGitSink additionally holds #138's cross-process/root
        // fence around the filesystem transaction.
        let project_root =
            CanonicalDreamProjectRoot::from_session_path(&self.session.project_root)?;
        let dream_lock = knowledge_dream_lock_for_root(&project_root, &knowledge_base.id);
        let _dream_guard = tokio::select! {
            guard = dream_lock.lock() => guard,
            () = cancel.cancelled() => bail!("knowledge dream cancelled while waiting for the KB lock"),
        };
        ensure!(
            matches!(&knowledge_base.source, KnowledgeBaseSource::Local { .. }),
            "remote dream submission is hosted and not implemented"
        );
        let model = resolve_dream_model(knowledge_base, config, providers)?;
        ensure!(
            model.reference() == executing_model,
            "knowledge base `{}` must dream with `{}`, not `{executing_model}`",
            knowledge_base.id,
            model.reference()
        );
        ensure!(
            change_set.knowledge_base_id == knowledge_base.id,
            "dream change set targets the wrong knowledge base"
        );

        let consumer = self.session.db.ensure_installation_identity().await?;
        let sources = self
            .session
            .db
            .undreamed_sessions_for_knowledge_base(
                &knowledge_base.id,
                project_root.as_str(),
                consumer.as_hex(),
                history_caller_trust(&model, providers),
            )
            .await?;
        if sources.is_empty() {
            ensure!(
                change_set.source_session_ids.is_empty() && change_set.upserts.is_empty(),
                "knowledge base `{}` has no undreamed attached sessions",
                knowledge_base.id
            );
            return Ok(DreamRunOutcome::NothingToDream);
        }
        validate_exact_source_set(&sources, &change_set.source_session_ids)?;

        // Reuse #130's target-union seam: reader + machine-scoped sealed
        // literals once, then each attached source session's persisted table.
        let mut redaction = self
            .session
            .with_machine_scoped_sealed_redactions(reader_redaction)
            .await?;
        for source in &sources {
            redaction = self
                .session
                .recall_redaction_table_from_base(&redaction, source.session_id)
                .await?;
        }
        let redacted = redact_and_validate_change_set(change_set, &redaction)?;
        let sink_outcome = sink.apply(&model, &redacted, cancel).await?;
        if matches!(sink_outcome, KnowledgeDreamGitOutcome::Deferred { .. }) {
            return Ok(DreamRunOutcome::Deferred {
                sessions_pending: sources.len(),
                sink: sink_outcome,
            });
        }
        let source_ids = sources
            .iter()
            .map(|source| source.session_id)
            .collect::<Vec<_>>();
        self.session
            .db
            .record_knowledge_dream_completion(
                &knowledge_base.id,
                project_root.as_str(),
                consumer.as_hex(),
                &source_ids,
            )
            .await?;
        Ok(DreamRunOutcome::Applied {
            sessions_dreamed: source_ids.len(),
            concepts_written: redacted.upserts.len(),
            sink: sink_outcome,
        })
    }
}

pub(crate) fn knowledge_dream_lock_for_root(
    project_root: &CanonicalDreamProjectRoot,
    kb_id: &str,
) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let key = knowledge_dream_lock_key(project_root, kb_id);
    let mut locks = LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("knowledge dream lock registry poisoned");
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

pub(crate) fn knowledge_dream_run_lock_for_root(
    project_root: &CanonicalDreamProjectRoot,
    kb_id: &str,
) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let key = knowledge_dream_lock_key(project_root, kb_id);
    let mut locks = LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("knowledge dream run-lock registry poisoned");
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

fn knowledge_dream_lock_key(project_root: &CanonicalDreamProjectRoot, kb_id: &str) -> String {
    format!("{}\u{0}{kb_id}", project_root.as_str())
}

/// Deterministic instruction for the custom dream orchestrator turn. Native
/// delegation policy already limits subagents to one layer; this prompt makes
/// the partition/merge contract and cheap-read policy explicit.
pub fn build_dream_prompt(knowledge_base_id: &str) -> String {
    format!(
        "Run a knowledge dream for `{knowledge_base_id}`. First call \
         knowledge_dream_sources for exactly this KB. If it returns no sessions, report that and \
         stop. Partition the returned sessions across one layer of read-only subagents. Give each \
         subagent the cheap title/description summaries first; it may call session_read for a \
         narrow transcript/tool-result-collapsed window only when a proposed concept needs more \
         evidence. Subagents only propose dream-provenance concept upserts and must not spawn. \
         Merge and deduplicate their proposals yourself, preserve human-authored concepts, then \
         call knowledge_dream_apply once with the exact source session IDs and the final \
         provider-neutral upserts. Do not write KB files or invoke Git directly."
    )
}

fn validate_exact_source_set(expected: &[DreamSessionSource], submitted: &[Uuid]) -> Result<()> {
    let expected = expected
        .iter()
        .map(|source| source.session_id)
        .collect::<BTreeSet<_>>();
    let submitted_count = submitted.len();
    let submitted = submitted.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        submitted.len() == submitted_count,
        "dream source session ids contain duplicates"
    );
    ensure!(
        expected == submitted,
        "dream source set changed; rerun against the current attached, undreamed sessions"
    );
    Ok(())
}

fn redact_and_validate_change_set(
    mut change_set: DreamChangeSet,
    redaction: &RedactionTable,
) -> Result<DreamChangeSet> {
    let mut ids = BTreeSet::new();
    for upsert in &mut change_set.upserts {
        ensure!(
            upsert.provenance == ConceptProvenance::Dream,
            "dream upsert `{}` must carry dream provenance",
            upsert.id
        );
        upsert.id = redaction.scrub(&upsert.id);
        upsert.concept_type = redaction.scrub(&upsert.concept_type);
        upsert.title = upsert.title.take().map(|title| redaction.scrub(&title));
        upsert.body = redaction.scrub(&upsert.body);
        for citation in &mut upsert.citations {
            citation.label = redaction.scrub(&citation.label);
            citation.target = redaction.scrub(&citation.target);
        }
        ensure!(valid_concept_id(&upsert.id), "invalid dream concept id");
        ensure!(
            !upsert.concept_type.trim().is_empty(),
            "concept type is empty"
        );
        ensure!(ids.insert(upsert.id.clone()), "duplicate dream concept id");
    }
    Ok(change_set)
}

fn valid_concept_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::extended::{KnowledgeBaseEmbeddingOwnership, KnowledgeBaseMergePolicy};
    use crate::config::providers::{ModelEntry, ProviderEntry};

    fn entry(trust_required: bool) -> KnowledgeBaseRegistryEntry {
        KnowledgeBaseRegistryEntry {
            id: "kb".into(),
            name: "Knowledge".into(),
            description: "test".into(),
            source: KnowledgeBaseSource::Local {
                path: PathBuf::from("kb"),
            },
            embedding_ownership: KnowledgeBaseEmbeddingOwnership::Local,
            dream_model: None,
            dream_schedule: None,
            trust_required,
            merge_policy: KnowledgeBaseMergePolicy::Auto,
        }
    }

    fn providers(trust: ModelTrust) -> ProvidersConfig {
        let mut providers = ProvidersConfig::default();
        providers.providers.insert(
            "p".into(),
            ProviderEntry {
                trust: Some(trust),
                models: vec![ModelEntry {
                    id: "dream".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        providers
    }

    #[test]
    fn model_cascade_and_trust_bar_are_enforced() {
        let mut config = ExtendedConfig {
            utility_model: Some("p:utility".into()),
            dream_model: Some("p:dream".into()),
            ..Default::default()
        };
        assert_eq!(
            resolve_dream_model(&entry(false), &config, &providers(ModelTrust::Untrusted))
                .unwrap()
                .reference(),
            "p:dream"
        );
        let mut overridden = entry(false);
        overridden.dream_model = Some("p:kb-specific".into());
        assert_eq!(
            resolve_dream_model(&overridden, &config, &providers(ModelTrust::Untrusted))
                .unwrap()
                .reference(),
            "p:kb-specific"
        );
        config.knowledge_bases.clear();
        assert!(
            resolve_dream_model(&entry(true), &config, &providers(ModelTrust::Untrusted)).is_err()
        );
        assert!(
            resolve_dream_model(&entry(true), &config, &providers(ModelTrust::Trusted)).is_ok()
        );
    }

    #[test]
    fn seeded_secret_is_scrubbed_before_sink_input() {
        let secret = "seeded-dream-secret-141";
        let table = RedactionTable::empty()
            .with_forced_literal(secret.into(), "dream-test".into())
            .unwrap()
            .enforced();
        let redacted = redact_and_validate_change_set(
            DreamChangeSet {
                knowledge_base_id: "kb".into(),
                source_session_ids: vec![Uuid::now_v7()],
                upserts: vec![ConceptUpsert {
                    id: "deploy".into(),
                    concept_type: "procedure".into(),
                    title: Some(format!("Deploy with {secret}")),
                    body: format!("Never persist {secret}"),
                    citations: vec![Citation {
                        label: format!("source {secret}"),
                        target: "session:test".into(),
                    }],
                    provenance: ConceptProvenance::Dream,
                }],
            },
            &table,
        )
        .unwrap();
        let serialized = serde_json::to_string(&redacted).unwrap();
        assert!(!serialized.contains(secret));
        assert!(serialized.contains(table.placeholder()));
    }

    #[test]
    fn local_sink_refuses_human_concept_replacement() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("policy.md"),
            "---\nid: policy\ntype: rule\nprovenance: human\n---\n\nKeep this.\n",
        )
        .unwrap();
        let error = apply_change_set_to_local_bundle(
            root.path(),
            &DreamChangeSet {
                knowledge_base_id: "kb".into(),
                source_session_ids: vec![Uuid::now_v7()],
                upserts: vec![ConceptUpsert {
                    id: "policy".into(),
                    concept_type: "rule".into(),
                    title: None,
                    body: "Replace this".into(),
                    citations: Vec::new(),
                    provenance: ConceptProvenance::Dream,
                }],
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("human-provenance"));
        assert!(
            std::fs::read_to_string(root.path().join("policy.md"))
                .unwrap()
                .contains("Keep this")
        );
    }

    #[test]
    fn knowledge_dream_locks_are_root_scoped() {
        let first = CanonicalDreamProjectRoot("/workspace-a".into());
        let first_alias = CanonicalDreamProjectRoot("/workspace-a".into());
        let second_root_id = CanonicalDreamProjectRoot("/workspace-b".into());
        let first_lock = knowledge_dream_lock_for_root(&first, "kb");
        let first_again = knowledge_dream_lock_for_root(&first_alias, "kb");
        let second_root = knowledge_dream_lock_for_root(&second_root_id, "kb");
        let second_kb = knowledge_dream_lock_for_root(&first, "other");
        assert!(Arc::ptr_eq(&first_lock, &first_again));
        assert!(!Arc::ptr_eq(&first_lock, &second_root));
        assert!(!Arc::ptr_eq(&first_lock, &second_kb));

        let run_first = knowledge_dream_run_lock_for_root(&first, "kb");
        let run_first_again = knowledge_dream_run_lock_for_root(&first_alias, "kb");
        let run_second = knowledge_dream_run_lock_for_root(&second_root_id, "kb");
        assert!(Arc::ptr_eq(&run_first, &run_first_again));
        assert!(!Arc::ptr_eq(&run_first, &run_second));
    }

    #[test]
    fn canonical_dream_project_root_collapses_lexical_aliases() {
        let root = tempfile::tempdir().unwrap();
        let canonical = CanonicalDreamProjectRoot::from_session_path(root.path()).unwrap();
        let alias =
            CanonicalDreamProjectRoot::from_request_root(root.path().join(".").to_str().unwrap())
                .unwrap();
        assert_eq!(canonical, alias);
    }

    #[test]
    fn persisted_canonical_root_survives_deleted_workspace_for_detach_identity() {
        let root = tempfile::tempdir().unwrap();
        let canonical = CanonicalDreamProjectRoot::from_session_path(root.path()).unwrap();
        let persisted = canonical.as_str().to_owned();
        std::fs::remove_dir_all(root.path()).unwrap();

        let restored =
            CanonicalDreamProjectRoot::from_persisted_canonical_root(&persisted).unwrap();
        assert_eq!(restored.as_str(), persisted);
        assert!(CanonicalDreamProjectRoot::from_request_root(&persisted).is_err());
    }
}
