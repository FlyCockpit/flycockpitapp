//! OKF v0.1 knowledge bundles and disposable retrieval indexes.
//!
//! Cockpit treats local OKF markdown as the source of truth. The SQLite file
//! is a derived cache: delete it and it rebuilds from markdown. A named KB is
//! accessed exclusively through [`KbProvider`], allowing hosted retrieval to
//! replace the local implementation without caller churn. Embeddings and
//! vector tables never enter `cockpit.db`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::c_char;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[cfg(test)]
use crate::config::extended::RedactConfig;
use crate::config::extended::{
    ExtendedConfig, KnowledgeBaseEmbeddingOwnership, KnowledgeBaseMergePolicy,
    KnowledgeBaseRegistryEntry, KnowledgeBaseSource,
};
use crate::db::workspace_trust::WorkspaceTrustMode;
use crate::embeddings::{Embedder, OpenAiCompatEmbedder};
use crate::engine::message::Message;
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input, typed_args};
use crate::redact::RedactionTable;
use crate::session::Session;

/// Durable, paid projection of local KB chunks.  This database deliberately
/// contains no OKF metadata or FTS state, so rebuilding the other sidecar can
/// reuse its vectors without talking to an embedding provider.
pub(crate) const EMBEDDINGS_FILE: &str = "embeddings.sqlite";
/// Disposable local projection of a KB's OKF markdown and sibling resources.
pub(crate) const INDEX_FILE: &str = "index.sqlite";
pub(crate) const INDEX_LOGIC_VERSION: i64 = 2;
const CHUNK_TARGET_TOKENS: usize = 400;
const CHUNK_OVERLAP_TOKENS: usize = 80;
const DEFAULT_SEARCH_LIMIT: usize = 6;
const MEMORY_SEARCH_TOOL_NAME: &str = "memory_search";
const MAX_KNOWLEDGE_FILES: usize = 4096;
const MAX_KNOWLEDGE_ENTRIES: usize = 8192;
const MAX_KNOWLEDGE_DEPTH: usize = 32;
const MAX_KNOWLEDGE_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_KNOWLEDGE_TOTAL_BYTES: usize = 64 * 1024 * 1024;

#[cfg(test)]
pub(crate) fn runtime_attached_tool_names() -> &'static [&'static str] {
    &[MEMORY_SEARCH_TOOL_NAME]
}

unsafe extern "C" {
    #[link_name = "sqlite3_vec_init"]
    fn sqlite3_vec_init_for_connection(
        db: *mut rusqlite::ffi::sqlite3,
        pz_err_msg: *mut *mut c_char,
        p_api: *const rusqlite::ffi::sqlite3_api_routines,
    ) -> std::os::raw::c_int;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnowledgeBundle {
    pub root: PathBuf,
    pub index_md: Option<String>,
    pub log_md: Option<String>,
    pub concepts: Vec<KnowledgeConcept>,
    resources: Vec<KnowledgeResource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KnowledgeResource {
    concept_id: String,
    path: PathBuf,
    body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KnowledgeConcept {
    pub id: String,
    pub path: PathBuf,
    #[serde(rename = "type")]
    pub concept_type: String,
    pub frontmatter: BTreeMap<String, String>,
    pub body: String,
    pub citations: Vec<Citation>,
    pub valid_from: Option<String>,
    pub supersedes: Vec<String>,
    pub invalidated_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Citation {
    pub label: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SearchResult {
    pub knowledge_base_id: String,
    pub knowledge_base_name: String,
    pub concept_id: String,
    pub source_path: String,
    pub chunk_index: usize,
    pub snippet: String,
    pub citations: Vec<Citation>,
    pub score: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IndexStats {
    pub embedded_chunks: usize,
    pub reused_files: usize,
    pub indexed_files: usize,
}

#[derive(Clone)]
pub(crate) struct AttachedKnowledgeBase {
    entry: KnowledgeBaseRegistryEntry,
    provider: Arc<dyn KbProvider>,
}

#[derive(Debug, Clone)]
struct ChunkDoc {
    concept_id: String,
    source_path: String,
    chunk_index: usize,
    body: String,
    citations: Vec<Citation>,
}

/// Provider-neutral knowledge-base access. Retrieval callers submit text and
/// receive cited results; local embedding and vector search remain an
/// implementation detail of [`LocalKb`].
#[async_trait]
pub(crate) trait KbProvider: Send + Sync {
    async fn is_available(&self) -> Result<bool>;
    async fn retrieve(&self, query: &str, limit: usize) -> Result<Vec<SearchResult>>;
    fn with_embedder(&self, embedder: Arc<dyn Embedder>) -> Arc<dyn KbProvider>;
}

#[derive(Clone)]
struct LocalKb {
    entry: KnowledgeBaseRegistryEntry,
    root: PathBuf,
    snapshot: Option<KnowledgeBundle>,
    sidecars: KbSidecars,
    sidecar_lock: Arc<tokio::sync::Mutex<()>>,
    embedder: Option<Arc<dyn Embedder>>,
}

#[derive(Debug, Clone)]
struct KbSidecars {
    embeddings: PathBuf,
    index: PathBuf,
}

impl KbSidecars {
    fn in_root(root: &Path) -> Self {
        Self {
            embeddings: root.join(EMBEDDINGS_FILE),
            index: root.join(INDEX_FILE),
        }
    }
}

fn sidecar_lock(sidecars: &KbSidecars) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = locks
        .lock()
        .expect("knowledge sidecar lock registry poisoned");
    if let Some(lock) = locks.get(&sidecars.embeddings).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(sidecars.embeddings.clone(), Arc::downgrade(&lock));
    lock
}

fn has_git_marker_in_ancestors(root: &Path) -> bool {
    root.ancestors()
        .any(|ancestor| ancestor.join(".git").exists())
}

fn ensure_sidecars_gitignored(root: &Path, sidecars: &KbSidecars) -> Result<()> {
    let sidecar_paths: Vec<_> = [&sidecars.embeddings, &sidecars.index]
        .into_iter()
        .filter_map(|path| path.strip_prefix(root).ok())
        .collect();
    // Assistant sidecars deliberately live in Flycockpit's private cache, not
    // in the installed assistant bundle. There is nothing in that source tree
    // to ignore in this case.
    if sidecar_paths.is_empty() {
        return Ok(());
    }
    let prefix = match Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--show-prefix"])
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8(output.stdout).context("reading knowledge repository Git prefix")?
        }
        Ok(_) if !has_git_marker_in_ancestors(root) => return Ok(()),
        Ok(output) => bail!(
            "checking Git ignore rules for local knowledge base {} failed: {}",
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(_) if !has_git_marker_in_ancestors(root) => return Ok(()),
        Err(error) => return Err(error).context("running Git to protect knowledge sidecars"),
    };
    let exclude = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--git-path", "info/exclude"])
        .output()
        .context("locating local knowledge repository exclusion file")?;
    if !exclude.status.success() {
        bail!(
            "locating Git exclusion file for local knowledge base {} failed: {}",
            root.display(),
            String::from_utf8_lossy(&exclude.stderr).trim()
        );
    }
    let exclude_path = PathBuf::from(
        String::from_utf8(exclude.stdout)
            .context("reading local knowledge repository exclusion path")?
            .trim(),
    );
    let exclude_path = if exclude_path.is_absolute() {
        exclude_path
    } else {
        root.join(exclude_path)
    };
    let prefix = prefix.trim().trim_matches('/');
    let root_prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}/")
    };
    let mut rules = String::from("# Flycockpit generated knowledge sidecars\n");
    for path in sidecar_paths {
        rules.push('/');
        rules.push_str(&root_prefix);
        rules.push_str(&rel_string(path));
        rules.push('\n');
    }
    let existing = match fs::read_to_string(&exclude_path) {
        Ok(existing) => existing,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("reading Git exclusion file {}", exclude_path.display()));
        }
    };
    if !existing.contains(&rules) {
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&exclude_path)
            .with_context(|| format!("opening Git exclusion file {}", exclude_path.display()))?;
        if !existing.is_empty() && !existing.ends_with('\n') {
            file.write_all(b"\n")?;
        }
        file.write_all(rules.as_bytes())?;
        file.sync_data()?;
    }
    Ok(())
}

struct RemoteKb {
    entry: KnowledgeBaseRegistryEntry,
}

impl LocalKb {
    fn new(
        entry: KnowledgeBaseRegistryEntry,
        root: PathBuf,
        snapshot: Option<KnowledgeBundle>,
        sidecars: KbSidecars,
        embedder: Option<Arc<dyn Embedder>>,
    ) -> Self {
        Self {
            entry,
            root,
            snapshot,
            sidecar_lock: sidecar_lock(&sidecars),
            sidecars,
            embedder,
        }
    }

    /// Build an assistant provider while its installation identity has been
    /// resolved. The local provider owns this filesystem read so registry
    /// assembly never needs to know how local KB contents are represented.
    fn assistant(
        entry: KnowledgeBaseRegistryEntry,
        root: PathBuf,
        snapshot_root: PathBuf,
        sidecars: KbSidecars,
    ) -> Result<Option<Self>> {
        let Some(snapshot) = Self::snapshot_assistant(&root, snapshot_root)? else {
            return Ok(None);
        };
        Ok(Some(Self::new(entry, root, Some(snapshot), sidecars, None)))
    }

    fn snapshot_assistant(root: &Path, snapshot_root: PathBuf) -> Result<Option<KnowledgeBundle>> {
        let handle = match cockpit_config::config::open_config_directory_nofollow(root) {
            Ok(handle) => handle,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("opening assistant knowledge root {}", root.display())
                });
            }
        };
        let documents =
            cockpit_config::config::snapshot_markdown_tree_from_retained_directory_nofollow(
                &handle,
                MAX_KNOWLEDGE_FILES,
                MAX_KNOWLEDGE_ENTRIES,
                MAX_KNOWLEDGE_DEPTH,
                MAX_KNOWLEDGE_FILE_BYTES,
                MAX_KNOWLEDGE_TOTAL_BYTES,
            )?;
        // Both markdown and referenced sibling data are read through `handle`.
        // The public source paths below remain synthetic so results never
        // disclose an assistant's private installation path.
        let mut snapshot = parse_bundle_snapshot(root.to_path_buf(), documents, &handle)?;
        snapshot.root = snapshot_root;
        Ok(Some(snapshot))
    }
}

#[async_trait]
impl KbProvider for LocalKb {
    async fn is_available(&self) -> Result<bool> {
        if self.snapshot.is_some() {
            return Ok(true);
        }
        match cockpit_config::config::open_config_directory_nofollow(&self.root) {
            Ok(handle) => {
                drop(handle);
                Ok(true)
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(false)
            }
            Err(error) => Err(error).with_context(|| {
                format!(
                    "opening local knowledge base `{}` at {}",
                    self.entry.id,
                    self.root.display()
                )
            }),
        }
    }

    async fn retrieve(&self, query: &str, limit: usize) -> Result<Vec<SearchResult>> {
        if !self.is_available().await? {
            bail!(
                "local knowledge base `{}` does not exist at {}",
                self.entry.id,
                self.root.display()
            );
        }
        let embedder = self.embedder.clone().context(
            "local knowledge retrieval requires an embedding model configured by its provider",
        )?;
        let query_vector = embedder
            .embed(&[query])
            .await
            .context("embedding local knowledge search query")?
            .into_iter()
            .next()
            .context("embedding query returned no vector")?;
        if query_vector.is_empty() {
            bail!("embedding query returned an empty vector");
        }
        let _sidecar_guard = self.sidecar_lock.lock().await;
        let (index, _) = match &self.snapshot {
            Some(snapshot) => {
                KnowledgeIndex::open_snapshot_locked(
                    snapshot.clone(),
                    self.sidecars.clone(),
                    embedder,
                    Some(query_vector.len()),
                )
                .await?
            }
            None => {
                let bundle = parse_bundle(&self.root)?;
                KnowledgeIndex::open_snapshot_locked(
                    bundle,
                    self.sidecars.clone(),
                    embedder,
                    Some(query_vector.len()),
                )
                .await?
            }
        };
        let mut results = index.search_with_vector(&query_vector, query, limit)?;
        for result in &mut results {
            result.knowledge_base_id = self.entry.id.clone();
            result.knowledge_base_name = self.entry.name.clone();
        }
        Ok(results)
    }

    fn with_embedder(&self, embedder: Arc<dyn Embedder>) -> Arc<dyn KbProvider> {
        Arc::new(Self {
            embedder: Some(embedder),
            ..self.clone()
        })
    }
}

#[async_trait]
impl KbProvider for RemoteKb {
    async fn is_available(&self) -> Result<bool> {
        bail!(
            "remote knowledge base `{}` is configured but hosted retrieval is not implemented",
            self.entry.id
        )
    }

    async fn retrieve(&self, _query: &str, _limit: usize) -> Result<Vec<SearchResult>> {
        // TODO(#136): implement hosted KbProvider retrieval for remote-owned KBs.
        bail!("remote knowledge-base providers are not implemented")
    }

    fn with_embedder(&self, _embedder: Arc<dyn Embedder>) -> Arc<dyn KbProvider> {
        Arc::new(Self {
            entry: self.entry.clone(),
        })
    }
}

pub(crate) fn parse_bundle(root: impl AsRef<Path>) -> Result<KnowledgeBundle> {
    let root = root.as_ref().to_path_buf();
    let handle = cockpit_config::config::open_config_directory_nofollow(&root)?;
    let documents =
        cockpit_config::config::snapshot_markdown_tree_from_retained_directory_nofollow(
            &handle,
            MAX_KNOWLEDGE_FILES,
            MAX_KNOWLEDGE_ENTRIES,
            MAX_KNOWLEDGE_DEPTH,
            MAX_KNOWLEDGE_FILE_BYTES,
            MAX_KNOWLEDGE_TOTAL_BYTES,
        )?;
    parse_bundle_snapshot(root, documents, &handle)
}

fn validate_unique_concept_ids(root: &Path, concepts: &[KnowledgeConcept]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for concept in concepts {
        if !ids.insert(concept.id.as_str()) {
            bail!(
                "knowledge bundle {} contains duplicate concept ID `{}`",
                root.display(),
                concept.id
            );
        }
    }
    Ok(())
}

fn finish_bundle(
    root: PathBuf,
    root_handle: &std::fs::File,
    index_md: Option<String>,
    log_md: Option<String>,
    mut concepts: Vec<KnowledgeConcept>,
    markdown_files: usize,
    markdown_bytes: usize,
) -> Result<KnowledgeBundle> {
    concepts.sort_by(|a, b| a.path.cmp(&b.path));
    validate_unique_concept_ids(&root, &concepts)?;
    let resources = load_referenced_resources(
        &root,
        root_handle,
        &concepts,
        markdown_files,
        markdown_bytes,
    )?;
    Ok(KnowledgeBundle {
        root,
        index_md,
        log_md,
        concepts,
        resources,
    })
}

fn load_referenced_resources(
    root: &Path,
    root_handle: &std::fs::File,
    concepts: &[KnowledgeConcept],
    markdown_files: usize,
    markdown_bytes: usize,
) -> Result<Vec<KnowledgeResource>> {
    let mut resources = Vec::new();
    let mut total_bytes = markdown_bytes;
    let mut files = markdown_files;
    for concept in concepts {
        let Some(resource) = concept.frontmatter.get("resource") else {
            continue;
        };
        let resource_path = PathBuf::from(resource);
        if resource_path.is_absolute()
            || resource_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!(
                "knowledge concept {} has an invalid resource path `{resource}`",
                root.join(&concept.path).display()
            );
        }
        let extension = resource_path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "csv" | "jsonl" | "ndjson") {
            bail!(
                "knowledge resource {} must be a .csv, .jsonl, or .ndjson file",
                resource_path.display()
            );
        }
        let relative = concept
            .path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(&resource_path);
        let absolute = root.join(&relative);
        files = files
            .checked_add(1)
            .filter(|count| *count <= MAX_KNOWLEDGE_FILES)
            .ok_or_else(|| {
                anyhow::anyhow!("knowledge snapshot exceeds its resource count limit")
            })?;
        let bytes = cockpit_config::config::read_config_relative_file_from_retained_directory(
            root_handle,
            &relative,
            MAX_KNOWLEDGE_FILE_BYTES,
        )
        .with_context(|| format!("reading knowledge resource {}", absolute.display()))?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_KNOWLEDGE_TOTAL_BYTES)
            .ok_or_else(|| {
                anyhow::anyhow!("knowledge snapshot exceeds its aggregate byte limit")
            })?;
        resources.push(KnowledgeResource {
            concept_id: concept.id.clone(),
            path: relative,
            body: String::from_utf8(bytes).with_context(|| {
                format!("knowledge resource {} is not UTF-8", absolute.display())
            })?,
        });
    }
    Ok(resources)
}

fn parse_bundle_snapshot(
    root: PathBuf,
    documents: Vec<(PathBuf, String)>,
    root_handle: &std::fs::File,
) -> Result<KnowledgeBundle> {
    let markdown_files = documents.len();
    let markdown_bytes = documents.iter().map(|(_, body)| body.len()).sum();
    let mut index_md = None;
    let mut log_md = None;
    let mut concepts = Vec::new();
    for (rel, body) in documents {
        match rel.to_string_lossy().as_ref() {
            "index.md" => index_md = Some(body),
            "log.md" => log_md = Some(body),
            _ => {
                if let Some(concept) = parse_concept(&root, rel, &body)? {
                    concepts.push(concept);
                }
            }
        }
    }
    finish_bundle(
        root,
        root_handle,
        index_md,
        log_md,
        concepts,
        markdown_files,
        markdown_bytes,
    )
}

pub(crate) fn serialize_concept(concept: &KnowledgeConcept) -> String {
    let mut frontmatter = concept.frontmatter.clone();
    frontmatter.insert("type".to_string(), concept.concept_type.clone());
    if let Some(valid_from) = &concept.valid_from {
        frontmatter.insert("valid_from".to_string(), valid_from.clone());
    }
    if !concept.supersedes.is_empty() {
        frontmatter.insert(
            "supersedes".to_string(),
            format!(
                "[{}]",
                concept
                    .supersedes
                    .iter()
                    .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    if let Some(invalidated_by) = &concept.invalidated_by {
        frontmatter.insert("invalidated_by".to_string(), invalidated_by.clone());
    }

    let mut out = String::from("---\n");
    for (key, value) in frontmatter {
        out.push_str(&key);
        out.push_str(": ");
        out.push_str(&value);
        out.push('\n');
    }
    out.push_str("---\n\n");
    out.push_str(concept.body.trim());
    out.push('\n');
    if !concept.citations.is_empty() {
        out.push_str("\n# Citations\n\n");
        for citation in &concept.citations {
            out.push_str("- [");
            out.push_str(&citation.label);
            out.push_str("](");
            out.push_str(&citation.target);
            out.push_str(")\n");
        }
    }
    out
}

fn parse_concept(root: &Path, rel: PathBuf, raw: &str) -> Result<Option<KnowledgeConcept>> {
    let Some((frontmatter, markdown)) = split_frontmatter(raw) else {
        return Ok(None);
    };
    let Some(concept_type) = frontmatter.get("type").cloned() else {
        bail!(
            "knowledge concept {} is missing required `type` frontmatter",
            root.join(&rel).display()
        );
    };
    let (body, citations) = split_citations(markdown);
    let id = frontmatter
        .get("id")
        .cloned()
        .unwrap_or_else(|| rel.with_extension("").to_string_lossy().replace('\\', "/"));
    Ok(Some(KnowledgeConcept {
        id,
        path: rel,
        concept_type,
        valid_from: frontmatter.get("valid_from").cloned(),
        supersedes: parse_string_list(frontmatter.get("supersedes")),
        invalidated_by: frontmatter.get("invalidated_by").cloned(),
        frontmatter,
        body: body.trim().to_string(),
        citations,
    }))
}

fn split_frontmatter(raw: &str) -> Option<(BTreeMap<String, String>, &str)> {
    let rest = raw
        .strip_prefix("---\n")
        .or_else(|| raw.strip_prefix("---\r\n"))?;
    let end = rest.find("\n---")?;
    let fm = &rest[..end];
    let body = rest[end + "\n---".len()..]
        .strip_prefix("\r\n")
        .or_else(|| rest[end + "\n---".len()..].strip_prefix('\n'))
        .unwrap_or(&rest[end + "\n---".len()..]);
    let map = parse_frontmatter_map(fm);
    Some((map, body))
}

fn parse_frontmatter_map(fm: &str) -> BTreeMap<String, String> {
    if let Ok(serde_yaml::Value::Mapping(mapping)) = serde_yaml::from_str::<serde_yaml::Value>(fm) {
        let mut out = BTreeMap::new();
        for (key, value) in mapping {
            let Some(key) = key.as_str() else {
                continue;
            };
            out.insert(key.to_string(), yaml_value_to_string(value));
        }
        return out;
    }

    let mut map = BTreeMap::new();
    for line in fm.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            map.insert(
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            );
        }
    }
    map
}

fn yaml_value_to_string(value: serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::Null => String::new(),
        serde_yaml::Value::Bool(value) => value.to_string(),
        serde_yaml::Value::Number(value) => value.to_string(),
        serde_yaml::Value::String(value) => value,
        serde_yaml::Value::Sequence(values) => format!(
            "[{}]",
            values
                .into_iter()
                .map(yaml_value_to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => serde_yaml::to_string(&other)
            .unwrap_or_default()
            .lines()
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn split_citations(markdown: &str) -> (String, Vec<Citation>) {
    let Some(pos) = markdown.find("\n# Citations") else {
        return (markdown.to_string(), Vec::new());
    };
    let body = markdown[..pos].to_string();
    let citations = markdown[pos..]
        .lines()
        .filter_map(parse_citation_line)
        .collect();
    (body, citations)
}

fn parse_citation_line(line: &str) -> Option<Citation> {
    let line = line.trim();
    let inner = line.strip_prefix("- [")?;
    let (label, rest) = inner.split_once("](")?;
    let target = rest.strip_suffix(')')?;
    Some(Citation {
        label: label.to_string(),
        target: target.to_string(),
    })
}

fn parse_string_list(value: Option<&String>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let trimmed = value.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed
        .split(',')
        .map(|s| s.trim().trim_matches('"').trim_matches('\''))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

pub(crate) struct KnowledgeIndex {
    #[allow(dead_code)]
    bundle: KnowledgeBundle,
    index: Connection,
    embeddings: Connection,
}

impl KnowledgeIndex {
    pub(crate) async fn open(
        root: impl AsRef<Path>,
        embedder: Arc<dyn Embedder>,
    ) -> Result<(Self, IndexStats)> {
        Self::open_with_query_dimensions(root, embedder, None).await
    }

    async fn open_with_query_dimensions(
        root: impl AsRef<Path>,
        embedder: Arc<dyn Embedder>,
        query_dimensions: Option<usize>,
    ) -> Result<(Self, IndexStats)> {
        let root = root.as_ref().to_path_buf();
        let bundle = parse_bundle(&root)?;
        let sidecars = KbSidecars::in_root(&root);
        let lock = sidecar_lock(&sidecars);
        let _guard = lock.lock().await;
        Self::open_snapshot_locked(bundle, sidecars, embedder, query_dimensions).await
    }

    /// Caller must hold the per-KB sidecar lock. No SQLite connection crosses
    /// the await in `sync_embeddings`, so this remains valid in KbProvider's
    /// required Send future.
    async fn open_snapshot_locked(
        bundle: KnowledgeBundle,
        sidecars: KbSidecars,
        embedder: Arc<dyn Embedder>,
        query_dimensions: Option<usize>,
    ) -> Result<(Self, IndexStats)> {
        ensure_sidecars_gitignored(&bundle.root, &sidecars)?;
        let index = open_index_connection(&sidecars.index)?;
        ensure_index_schema(&index)?;
        rebuild_index(&index, &bundle)?;
        let stats = sync_embeddings(
            &sidecars.embeddings,
            &bundle,
            embedder.as_ref(),
            query_dimensions,
        )
        .await?;
        let embeddings = open_embeddings_connection(&sidecars.embeddings)?;
        ensure_embeddings_schema(&embeddings)?;
        Ok((
            Self {
                bundle,
                index,
                embeddings,
            },
            stats,
        ))
    }

    pub(crate) fn search_with_vector(
        &self,
        query_vector: &[f32],
        keyword_query: &str,
        limit: usize,
    ) -> Result<Vec<SearchResult>> {
        if keyword_query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let vector_arm = vector_search(
            &self.embeddings,
            &self.index,
            query_vector,
            limit.max(DEFAULT_SEARCH_LIMIT),
        )?;
        let keyword_arm =
            keyword_search(&self.index, keyword_query, limit.max(DEFAULT_SEARCH_LIMIT))?;
        let merged = rrf_merge(&self.index, vector_arm, keyword_arm, limit)?;
        Ok(merged)
    }

    #[cfg(test)]
    fn set_logic_version_for_test(&self, version: i64) -> Result<()> {
        self.index.execute(
            "INSERT INTO intel_meta(key, value) VALUES('index_logic_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![version.to_string()],
        )?;
        Ok(())
    }
}

fn open_private_sidecar_connection(sidecar: &Path, label: &str) -> Result<Connection> {
    if !sidecar.exists() {
        match cockpit_host::private_fs::write_private_file_exclusive(sidecar, b"") {
            Ok(()) => {}
            Err(error) if sidecar.exists() => {
                cockpit_host::private_fs::repair_private_file(sidecar, label)
                    .map_err(anyhow::Error::from)
                    .context("securing concurrently-created knowledge sidecar")?;
                tracing::debug!(%error, "knowledge sidecar was created concurrently");
            }
            Err(error) => return Err(error).context("creating private knowledge sidecar"),
        }
    } else {
        cockpit_host::private_fs::repair_private_file(sidecar, label)
            .map_err(anyhow::Error::from)?;
    }
    Connection::open(sidecar)
        .with_context(|| format!("opening knowledge sidecar {}", sidecar.display()))
}

fn open_index_connection(sidecar: &Path) -> Result<Connection> {
    open_private_sidecar_connection(sidecar, "knowledge index sidecar")
}

fn open_embeddings_connection(sidecar: &Path) -> Result<Connection> {
    let conn = open_private_sidecar_connection(sidecar, "knowledge embeddings sidecar")?;
    load_sqlite_vec_for_sidecar(&conn)?;
    Ok(conn)
}

fn load_sqlite_vec_for_sidecar(conn: &Connection) -> Result<()> {
    // Keep the dependency linked while avoiding sqlite3_auto_extension, which
    // would globally affect future main-DB connections.
    let _ = sqlite_vec::sqlite3_vec_init as unsafe extern "C" fn();
    let rc = unsafe {
        sqlite3_vec_init_for_connection(conn.handle(), std::ptr::null_mut(), std::ptr::null())
    };
    if rc != rusqlite::ffi::SQLITE_OK {
        bail!("loading sqlite-vec for knowledge sidecar failed with sqlite rc {rc}");
    }
    Ok(())
}

fn ensure_index_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS intel_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS concepts (
            id TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            type TEXT NOT NULL,
            title TEXT,
            description TEXT,
            resource TEXT,
            tags_json TEXT NOT NULL,
            timestamp TEXT,
            frontmatter_json TEXT NOT NULL,
            body TEXT NOT NULL,
            citations_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS concept_frontmatter (
            concept_id TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY(concept_id, key),
            FOREIGN KEY(concept_id) REFERENCES concepts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS chunks (
            id INTEGER PRIMARY KEY,
            concept_id TEXT NOT NULL,
            source_path TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            body TEXT NOT NULL,
            citations_json TEXT NOT NULL,
            FOREIGN KEY(concept_id) REFERENCES concepts(id) ON DELETE CASCADE
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
            body,
            concept_id UNINDEXED,
            content='chunks',
            content_rowid='id'
        );
        CREATE TABLE IF NOT EXISTS structured_rows (
            id INTEGER PRIMARY KEY,
            concept_id TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            source_path TEXT NOT NULL,
            table_name TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            values_json TEXT NOT NULL,
            FOREIGN KEY(concept_id) REFERENCES concepts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS structured_values (
            row_id INTEGER NOT NULL,
            column_name TEXT NOT NULL,
            value_type TEXT NOT NULL,
            value_text TEXT,
            value_integer INTEGER,
            value_real REAL,
            value_boolean INTEGER,
            PRIMARY KEY(row_id, column_name),
            FOREIGN KEY(row_id) REFERENCES structured_rows(id) ON DELETE CASCADE
        );
        "#,
    )?;
    Ok(())
}

fn ensure_embeddings_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS embedding_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS embedded_chunks (
            id INTEGER PRIMARY KEY,
            content_hash TEXT NOT NULL UNIQUE,
            body TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

fn rebuild_index(conn: &Connection, bundle: &KnowledgeBundle) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "DELETE FROM structured_values; DELETE FROM structured_rows; DELETE FROM chunks_fts; \
         DELETE FROM chunks; DELETE FROM concept_frontmatter; DELETE FROM concepts;",
    )?;
    for concept in &bundle.concepts {
        let path = rel_string(&concept.path);
        tx.execute(
            "INSERT INTO concepts(id, path, type, title, description, resource, tags_json, timestamp, frontmatter_json, body, citations_json)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                concept.id,
                path,
                concept.concept_type,
                concept.frontmatter.get("title"),
                concept.frontmatter.get("description"),
                concept.frontmatter.get("resource"),
                serde_json::to_string(&parse_string_list(concept.frontmatter.get("tags")))?,
                concept.frontmatter.get("timestamp"),
                serde_json::to_string(&concept.frontmatter)?,
                concept.body,
                serde_json::to_string(&concept.citations)?,
            ],
        )?;
        for (key, value) in &concept.frontmatter {
            tx.execute(
                "INSERT INTO concept_frontmatter(concept_id, key, value) VALUES(?1, ?2, ?3)",
                params![concept.id, key, value],
            )?;
        }
        for chunk in chunk_concept(concept, &path) {
            let hash = content_hash(&chunk.body);
            tx.execute(
                "INSERT INTO chunks(concept_id, source_path, chunk_index, content_hash, body, citations_json)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    chunk.concept_id,
                    chunk.source_path,
                    chunk.chunk_index as i64,
                    hash,
                    chunk.body,
                    serde_json::to_string(&chunk.citations)?,
                ],
            )?;
            let rowid = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO chunks_fts(rowid, body, concept_id) VALUES(?1, ?2, ?3)",
                params![rowid, chunk.body, chunk.concept_id],
            )?;
        }
        project_markdown_tables(&tx, concept)?;
    }
    for resource in &bundle.resources {
        project_resource(&tx, resource)?;
    }
    tx.execute(
        "INSERT INTO intel_meta(key, value) VALUES('index_logic_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![INDEX_LOGIC_VERSION.to_string()],
    )?;
    tx.commit()?;
    Ok(())
}

fn project_markdown_tables(conn: &Connection, concept: &KnowledgeConcept) -> Result<()> {
    let lines: Vec<&str> = concept.body.lines().collect();
    let mut index = 0;
    let mut table_index = 0;
    while index + 1 < lines.len() {
        let Some(headers) = markdown_table_row(lines[index]) else {
            index += 1;
            continue;
        };
        if !markdown_table_separator(lines[index + 1], headers.len()) {
            index += 1;
            continue;
        }
        let table_name = format!("markdown:{}:{table_index}", rel_string(&concept.path));
        table_index += 1;
        index += 2;
        let mut row_index = 0;
        while index < lines.len() {
            let Some(values) = markdown_table_row(lines[index]) else {
                break;
            };
            if values.len() != headers.len() {
                break;
            }
            let values = headers
                .iter()
                .cloned()
                .zip(values.into_iter().map(|value| typed_value(&value)))
                .collect();
            insert_structured_row(
                conn,
                &concept.id,
                "markdown-table",
                &rel_string(&concept.path),
                &table_name,
                row_index,
                values,
            )?;
            row_index += 1;
            index += 1;
        }
    }
    Ok(())
}

fn markdown_table_row(line: &str) -> Option<Vec<String>> {
    let line = line.trim();
    let line = line.strip_prefix('|')?.strip_suffix('|')?;
    let values: Vec<String> = line
        .split('|')
        .map(|value| value.trim().to_string())
        .collect();
    (!values.is_empty()).then_some(values)
}

fn markdown_table_separator(line: &str, columns: usize) -> bool {
    markdown_table_row(line).is_some_and(|cells| {
        cells.len() == columns
            && cells.iter().all(|cell| {
                let cell = cell.trim_matches(':').trim();
                cell.len() >= 3 && cell.bytes().all(|byte| byte == b'-')
            })
    })
}

fn project_resource(conn: &Connection, resource: &KnowledgeResource) -> Result<()> {
    let source_path = rel_string(&resource.path);
    let extension = resource
        .path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "csv" => {
            let mut reader = csv::ReaderBuilder::new()
                .flexible(false)
                .from_reader(resource.body.as_bytes());
            let headers: Vec<String> = reader.headers()?.iter().map(str::to_string).collect();
            for (row_index, record) in reader.records().enumerate() {
                let record = record?;
                let values = headers
                    .iter()
                    .cloned()
                    .zip(record.iter().map(|value| typed_value(value)))
                    .collect();
                insert_structured_row(
                    conn,
                    &resource.concept_id,
                    "resource-csv",
                    &source_path,
                    &format!("resource:{source_path}"),
                    row_index,
                    values,
                )?;
            }
        }
        "jsonl" | "ndjson" => {
            for (row_index, line) in resource
                .body
                .lines()
                .filter(|line| !line.trim().is_empty())
                .enumerate()
            {
                let value: serde_json::Value = serde_json::from_str(line).with_context(|| {
                    format!("parsing JSON Lines knowledge resource {source_path}")
                })?;
                let object = value.as_object().with_context(|| {
                    format!("JSON Lines knowledge resource {source_path} must contain objects")
                })?;
                let values = object
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect();
                insert_structured_row(
                    conn,
                    &resource.concept_id,
                    "resource-jsonl",
                    &source_path,
                    &format!("resource:{source_path}"),
                    row_index,
                    values,
                )?;
            }
        }
        _ => unreachable!("resource extensions are validated during bundle parsing"),
    }
    Ok(())
}

fn typed_value(value: &str) -> serde_json::Value {
    if let Ok(value) = value.parse::<i64>() {
        return serde_json::Value::from(value);
    }
    if let Ok(value) = value.parse::<f64>() {
        return serde_json::Value::from(value);
    }
    if let Ok(value) = value.parse::<bool>() {
        return serde_json::Value::from(value);
    }
    serde_json::Value::String(value.to_string())
}

fn insert_structured_row(
    conn: &Connection,
    concept_id: &str,
    source_kind: &str,
    source_path: &str,
    table_name: &str,
    row_index: usize,
    values: BTreeMap<String, serde_json::Value>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO structured_rows(concept_id, source_kind, source_path, table_name, row_index, values_json)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            concept_id,
            source_kind,
            source_path,
            table_name,
            row_index as i64,
            serde_json::to_string(&values)?,
        ],
    )?;
    let row_id = conn.last_insert_rowid();
    for (column_name, value) in values {
        let (value_type, text, integer, real, boolean) = match value {
            serde_json::Value::Null => ("null", None, None, None, None),
            serde_json::Value::Bool(value) => {
                ("boolean", None, None, None, Some(if value { 1 } else { 0 }))
            }
            serde_json::Value::Number(value) if value.is_i64() => {
                ("integer", None, value.as_i64(), None, None)
            }
            serde_json::Value::Number(value) => ("real", None, None, value.as_f64(), None),
            serde_json::Value::String(value) => ("text", Some(value), None, None, None),
            value => (
                "json",
                Some(serde_json::to_string(&value)?),
                None,
                None,
                None,
            ),
        };
        conn.execute(
            "INSERT INTO structured_values(row_id, column_name, value_type, value_text, value_integer, value_real, value_boolean)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![row_id, column_name, value_type, text, integer, real, boolean],
        )?;
    }
    Ok(())
}

async fn sync_embeddings(
    sidecar: &Path,
    bundle: &KnowledgeBundle,
    embedder: &dyn Embedder,
    query_dimensions: Option<usize>,
) -> Result<IndexStats> {
    let mut chunks = BTreeMap::new();
    for concept in &bundle.concepts {
        for chunk in chunk_concept(concept, &rel_string(&concept.path)) {
            chunks
                .entry(content_hash(&chunk.body))
                .or_insert(chunk.body);
        }
    }
    let model_identity = embedder.identity();
    let prepared = prepare_embedding_sync(sidecar, &chunks, &model_identity, query_dimensions)?;
    let reused_files = if prepared.reset {
        0
    } else {
        bundle
            .concepts
            .iter()
            .filter(|concept| {
                chunk_concept(concept, &rel_string(&concept.path))
                    .iter()
                    .all(|chunk| !prepared.missing.contains_key(&content_hash(&chunk.body)))
            })
            .count()
    };
    if prepared.missing.is_empty() && !prepared.reset {
        return Ok(IndexStats {
            embedded_chunks: 0,
            reused_files,
            indexed_files: 0,
        });
    }
    // All SQLite connections were dropped by prepare_embedding_sync before the
    // awaited paid call. The caller's per-KB mutex owns this work interval.
    let vectors = embed_chunks(&prepared.missing, embedder, query_dimensions).await?;
    store_embeddings(
        sidecar,
        &prepared.missing,
        vectors,
        prepared.reset,
        &model_identity,
    )?;
    Ok(IndexStats {
        embedded_chunks: prepared.missing.len(),
        reused_files,
        indexed_files: bundle.concepts.len().saturating_sub(reused_files),
    })
}

struct PreparedEmbeddingSync {
    missing: BTreeMap<String, String>,
    reset: bool,
}

fn prepare_embedding_sync(
    sidecar: &Path,
    chunks: &BTreeMap<String, String>,
    model_identity: &str,
    query_dimensions: Option<usize>,
) -> Result<PreparedEmbeddingSync> {
    let conn = open_embeddings_connection(sidecar)?;
    ensure_embeddings_schema(&conn)?;
    let stored_model = stored_embedding_model_identity(&conn)?;
    let model_changed = match stored_model {
        Some(stored) => stored != model_identity,
        None => {
            table_exists(&conn, "vec_chunks")?
                || conn
                    .query_row("SELECT 1 FROM embedded_chunks LIMIT 1", [], |_| Ok(()))
                    .optional()?
                    .is_some()
        }
    };
    let dimensions_changed = query_dimensions
        .zip(stored_embedding_dimensions(&conn)?)
        .is_some_and(|(query, stored)| query != stored);
    let reset = model_changed || dimensions_changed;
    let mut missing = BTreeMap::new();
    for (hash, body) in chunks {
        let present = !reset
            && conn
                .query_row(
                    "SELECT 1 FROM embedded_chunks WHERE content_hash=?1",
                    params![hash],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
        if !present {
            missing.insert(hash.clone(), body.clone());
        }
    }
    Ok(PreparedEmbeddingSync { missing, reset })
}

async fn embed_chunks(
    chunks: &BTreeMap<String, String>,
    embedder: &dyn Embedder,
    query_dimensions: Option<usize>,
) -> Result<Vec<Vec<f32>>> {
    if chunks.is_empty() {
        return Ok(Vec::new());
    }
    let texts: Vec<&str> = chunks.values().map(String::as_str).collect();
    let vectors = embedder
        .embed(&texts)
        .await
        .context("embedding knowledge chunks")?;
    if vectors.len() != texts.len() {
        bail!(
            "knowledge embedder returned {} vectors for {} chunks",
            vectors.len(),
            texts.len()
        );
    }
    let dimension = vectors
        .first()
        .map(Vec::len)
        .filter(|dimension| *dimension > 0)
        .context("knowledge embedder returned an empty vector")?;
    if vectors.iter().any(|vector| vector.len() != dimension) {
        bail!("knowledge embedder returned mixed vector dimensions");
    }
    if let Some(query) = query_dimensions
        && query != dimension
    {
        bail!(
            "knowledge embedder returned {dimension}-dimensional document vectors for a {query}-dimensional query vector"
        );
    }
    Ok(vectors)
}

fn store_embeddings(
    sidecar: &Path,
    chunks: &BTreeMap<String, String>,
    vectors: Vec<Vec<f32>>,
    reset: bool,
    model_identity: &str,
) -> Result<()> {
    let conn = open_embeddings_connection(sidecar)?;
    ensure_embeddings_schema(&conn)?;
    let tx = conn.unchecked_transaction()?;
    if reset {
        clear_embeddings(&tx)?;
    }
    if let Some(vector) = vectors.first() {
        ensure_vec_table(&tx, vector.len())?;
    }
    set_embedding_model_identity(&tx, model_identity)?;
    for ((hash, body), vector) in chunks.iter().zip(vectors) {
        tx.execute(
            "INSERT INTO embedded_chunks(content_hash, body) VALUES(?1, ?2)",
            params![hash, body],
        )?;
        let rowid = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO vec_chunks(rowid, embedding) VALUES(?1, vec_f32(?2))",
            params![rowid, vector_json(&vector)],
        )
        .context("inserting sqlite-vec knowledge vector")?;
    }
    tx.commit()?;
    Ok(())
}

fn stored_embedding_model_identity(conn: &Connection) -> Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM embedding_meta WHERE key='embedding_model_identity'",
        [],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn set_embedding_model_identity(conn: &Connection, identity: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO embedding_meta(key, value) VALUES('embedding_model_identity', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![identity],
    )?;
    Ok(())
}

fn stored_embedding_dimensions(conn: &Connection) -> Result<Option<usize>> {
    Ok(conn
        .query_row(
            "SELECT value FROM embedding_meta WHERE key='embedding_dimensions'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .and_then(|value| value.parse().ok()))
}

fn clear_embeddings(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        DROP TABLE IF EXISTS vec_chunks;
        DELETE FROM embedded_chunks;
        DELETE FROM embedding_meta;
        "#,
    )?;
    Ok(())
}

fn ensure_vec_table(conn: &Connection, dimensions: usize) -> Result<()> {
    let stored = stored_embedding_dimensions(conn)?;
    if stored == Some(dimensions) && table_exists(conn, "vec_chunks")? {
        return Ok(());
    }
    if stored.is_some_and(|stored| stored != dimensions) {
        bail!("knowledge embedding dimensions changed from {stored} to {dimensions}");
    }
    conn.execute_batch("DROP TABLE IF EXISTS vec_chunks;")?;
    conn.execute(
        &format!("CREATE VIRTUAL TABLE vec_chunks USING vec0(embedding float[{dimensions}])"),
        [],
    )?;
    conn.execute(
        "INSERT INTO embedding_meta(key, value) VALUES('embedding_dimensions', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![dimensions.to_string()],
    )?;
    Ok(())
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE name=?1",
            params![name],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn chunk_concept(concept: &KnowledgeConcept, path: &str) -> Vec<ChunkDoc> {
    chunk_text(&concept.body)
        .into_iter()
        .enumerate()
        .map(|(chunk_index, body)| ChunkDoc {
            concept_id: concept.id.clone(),
            source_path: path.to_string(),
            chunk_index,
            body,
            citations: concept.citations.clone(),
        })
        .collect()
}

fn chunk_text(text: &str) -> Vec<String> {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut start = 0;
    while start < words.len() {
        let end = (start + CHUNK_TARGET_TOKENS).min(words.len());
        out.push(words[start..end].join(" "));
        if end == words.len() {
            break;
        }
        start = end.saturating_sub(CHUNK_OVERLAP_TOKENS);
    }
    out
}

fn content_hash(body: &str) -> String {
    use sha2::{Digest as _, Sha256};
    format!("{:x}", Sha256::digest(body.as_bytes()))
}

fn rel_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn vector_json(vector: &[f32]) -> String {
    serde_json::to_string(vector).unwrap_or_else(|_| "[]".to_string())
}

fn vector_search(
    embeddings: &Connection,
    index: &Connection,
    vector: &[f32],
    limit: usize,
) -> Result<Vec<i64>> {
    if !table_exists(embeddings, "vec_chunks")? {
        return Ok(Vec::new());
    }
    if stored_embedding_dimensions(embeddings)?.is_some_and(|stored| stored != vector.len()) {
        bail!(
            "knowledge query vector dimension {} does not match durable embedding dimension",
            vector.len()
        );
    }
    let mut stmt = embeddings.prepare(
        "SELECT rowid FROM vec_chunks
         WHERE embedding MATCH vec_f32(?1) AND k = ?2
         ORDER BY distance",
    )?;
    let rows = stmt.query_map(params![vector_json(vector), (limit * 4) as i64], |row| {
        row.get::<_, i64>(0)
    })?;
    let mut out = Vec::new();
    for row in rows {
        let embedding_id = row?;
        let hash: String = embeddings.query_row(
            "SELECT content_hash FROM embedded_chunks WHERE id=?1",
            params![embedding_id],
            |row| row.get(0),
        )?;
        let mut matching = index.prepare("SELECT id FROM chunks WHERE content_hash=?1")?;
        let matching_rows = matching.query_map(params![hash], |row| row.get::<_, i64>(0))?;
        for matching_row in matching_rows {
            out.push(matching_row?);
            if out.len() >= limit {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

fn keyword_search(conn: &Connection, query: &str, limit: usize) -> Result<Vec<i64>> {
    let fts = fts_query(query);
    if fts.is_empty() {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT rowid FROM chunks_fts
         WHERE chunks_fts MATCH ?1
         ORDER BY bm25(chunks_fts)
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![fts, limit as i64], |row| row.get::<_, i64>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn fts_query(query: &str) -> String {
    query
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("\"{}\"", s.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" OR ")
}

fn rrf_merge(
    conn: &Connection,
    vector_arm: Vec<i64>,
    keyword_arm: Vec<i64>,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    let mut scores: HashMap<i64, f64> = HashMap::new();
    for (rank, rowid) in vector_arm.into_iter().enumerate() {
        *scores.entry(rowid).or_default() += 1.0 / (60.0 + rank as f64 + 1.0);
    }
    for (rank, rowid) in keyword_arm.into_iter().enumerate() {
        *scores.entry(rowid).or_default() += 1.0 / (60.0 + rank as f64 + 1.0);
    }
    let mut ranked: Vec<(i64, f64)> = scores.into_iter().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked.truncate(limit);

    let mut out = Vec::new();
    for (rowid, score) in ranked {
        let result = conn.query_row(
            "SELECT concept_id, source_path, chunk_index, body, citations_json
             FROM chunks WHERE id=?1",
            params![rowid],
            |row| {
                let citations_json: String = row.get(4)?;
                let citations: Vec<Citation> =
                    serde_json::from_str(&citations_json).unwrap_or_default();
                Ok(SearchResult {
                    knowledge_base_id: String::new(),
                    knowledge_base_name: String::new(),
                    concept_id: row.get(0)?,
                    source_path: row.get(1)?,
                    chunk_index: row.get::<_, i64>(2)? as usize,
                    snippet: row.get(3)?,
                    citations,
                    score,
                })
            },
        )?;
        out.push(result);
    }
    Ok(out)
}

pub(crate) fn render_injection(
    results: &[SearchResult],
    max_tokens: usize,
    redact: &RedactionTable,
) -> Option<String> {
    if results.is_empty() || max_tokens == 0 {
        return None;
    }
    let mut out = String::from("[knowledge]\nRelevant cited memory from attached OKF bundles:\n");
    for result in results {
        let citation = citation_label(result);
        out.push_str("- ");
        out.push_str(&result.concept_id);
        out.push_str(" — ");
        out.push_str(&short_summary(&result.snippet));
        out.push_str(" [");
        out.push_str(&citation);
        out.push_str("]\n");
        let scrubbed = redact.scrub(&out);
        if crate::tokens::count(&scrubbed) > max_tokens {
            out.push_str("- [knowledge truncated by token budget]\n");
            break;
        }
    }
    let scrubbed = redact.scrub(&out);
    Some(token_cap(&scrubbed, max_tokens))
}

pub(crate) fn retrieval_query_from_turn(history: &[Message], prompt: &Message) -> String {
    let mut parts = history
        .iter()
        .rev()
        .take(6)
        .filter_map(message_text)
        .collect::<Vec<_>>();
    parts.reverse();
    if let Some(text) = message_text(prompt) {
        parts.push(text);
    }
    parts.join("\n")
}

fn message_text(message: &Message) -> Option<String> {
    let text = match message {
        Message::User { content } => crate::engine::message::extract_user_text(content),
        Message::Assistant { content, .. } => crate::engine::message::extract_text(content),
        Message::System { content } => content.clone(),
    };
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn citation_label(result: &SearchResult) -> String {
    let citation = result
        .citations
        .first()
        .map(|citation| format!("{}: {}", citation.label, citation.target))
        .unwrap_or_else(|| format!("{}#chunk-{}", result.source_path, result.chunk_index));
    format!(
        "{} (knowledge base: {} / {})",
        citation, result.knowledge_base_name, result.knowledge_base_id
    )
}

fn short_summary(snippet: &str) -> String {
    let cleaned = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.chars().count() <= 240 {
        cleaned
    } else {
        format!("{}…", cleaned.chars().take(240).collect::<String>())
    }
}

fn token_cap(body: &str, max_tokens: usize) -> String {
    if crate::tokens::count(body) <= max_tokens {
        return body.to_string();
    }
    let mut out = String::new();
    for word in body.split_whitespace() {
        let candidate = if out.is_empty() {
            word.to_string()
        } else {
            format!("{out} {word}")
        };
        if crate::tokens::count(&candidate) > max_tokens.saturating_sub(8) {
            break;
        }
        out = candidate;
    }
    out.push_str(" [knowledge truncated]");
    out
}

pub(crate) async fn inject_knowledge_for_turn(
    history: &mut Vec<Message>,
    session: &Session,
    cwd: &Path,
    definition: Option<&crate::agents::AgentDef>,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    query: &str,
    redact: Arc<RedactionTable>,
) {
    let extended = config.extended();
    let bundles = match attached_bundles(
        session,
        cwd,
        definition.and_then(crate::agents::AgentDef::allowed_knowledge_bases),
        &extended,
    )
    .await
    {
        Ok(bundles) => bundles,
        Err(error) => {
            tracing::warn!(%error, "refusing knowledge injection because knowledge attachment resolution failed");
            return;
        }
    };
    if bundles.is_empty() {
        return;
    }
    match production_embedder(&extended, config, redact.clone(), session).await {
        Ok(Some(embedder)) => {
            match retrieve_from_knowledge_bases(&bundles, embedder, query, DEFAULT_SEARCH_LIMIT)
                .await
            {
                Ok(results) => {
                    if let Some(block) =
                        render_injection(&results, extended.knowledge_inject_max_tokens, &redact)
                    {
                        history.push(Message::user(block));
                    }
                }
                Err(error) => tracing::warn!(%error, "knowledge retrieval failed"),
            }
        }
        Ok(None) => {
            tracing::debug!("knowledge bundle attached but no embedding_model is configured")
        }
        Err(error) => tracing::warn!(%error, "building knowledge embedder failed"),
    }
}

async fn production_embedder(
    extended: &ExtendedConfig,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    redact: Arc<RedactionTable>,
    session: &Session,
) -> Result<Option<Arc<dyn Embedder>>> {
    let providers = config.providers();
    let resolved = match providers.resolve_embedding_model(extended) {
        Ok(resolved) => resolved,
        Err(error) if extended.embedding_model_ref().is_none() => {
            tracing::debug!(%error, "embedding model unavailable for knowledge retrieval");
            return Ok(None);
        }
        Err(error) => return Err(error).context("resolving embedding model for knowledge"),
    };
    // Owner-scoped resolution: the embedding provider request may only resolve
    // `$secret:` names owned by (provider, this session's project root).
    let store = session.provider_credential_store(&providers)?;
    let embedder =
        OpenAiCompatEmbedder::for_resolved_model_with_store(&providers, &resolved, redact, store)
            .await?;
    Ok(Some(Arc::new(embedder)))
}

async fn retrieve_from_knowledge_bases(
    knowledge_bases: &[AttachedKnowledgeBase],
    embedder: Arc<dyn Embedder>,
    query: &str,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    let mut all = Vec::new();
    let mut available_providers = Vec::new();
    for knowledge_base in knowledge_bases {
        match knowledge_base.provider.is_available().await {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(
                    knowledge_base = %knowledge_base.entry.id,
                    "skipping unavailable knowledge provider"
                );
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "checking availability of knowledge base `{}`",
                        knowledge_base.entry.id
                    )
                });
            }
        }
        available_providers.push(knowledge_base.provider.with_embedder(embedder.clone()));
    }
    for provider in available_providers {
        all.extend(provider.retrieve(query, limit).await?);
    }
    all.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    all.truncate(limit);
    Ok(all)
}

pub(crate) async fn attached_bundles_available(
    session: &Session,
    cwd: &Path,
    allowed_knowledge_bases: Option<&BTreeSet<String>>,
    config: &crate::daemon::session_worker::SessionConfigHandle,
) -> bool {
    let extended = config.extended();
    match attached_bundles(session, cwd, allowed_knowledge_bases, &extended).await {
        Ok(bundles) => {
            let mut available = false;
            for knowledge_base in bundles {
                match knowledge_base.provider.is_available().await {
                    Ok(true) => available = true,
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            knowledge_base = %knowledge_base.entry.id,
                            "knowledge provider availability check failed closed"
                        );
                        return false;
                    }
                }
            }
            available
        }
        Err(error) => {
            tracing::warn!(%error, "knowledge registry availability check failed closed");
            false
        }
    }
}

pub(crate) async fn attached_bundles(
    session: &Session,
    cwd: &Path,
    allowed_knowledge_bases: Option<&BTreeSet<String>>,
    extended: &ExtendedConfig,
) -> Result<Vec<AttachedKnowledgeBase>> {
    let mut seen = BTreeSet::new();
    let mut knowledge_bases = Vec::new();
    let mut registry = Vec::with_capacity(extended.knowledge_bases.len() + 1);
    if let Some(assistant) = assistant_knowledge_registry_entry(session).await? {
        registry.push(assistant);
    }
    registry.extend(
        extended
            .knowledge_bases
            .iter()
            .cloned()
            .map(workspace_knowledge_base),
    );
    for RegistryKnowledgeBase { entry, local } in registry {
        validate_registry_entry(&entry)?;
        if !seen.insert(entry.id.clone()) {
            bail!(
                "knowledge base registry contains duplicate ID `{}`",
                entry.id
            );
        }
        if allowed_knowledge_bases.is_some_and(|ids| !ids.contains(&entry.id)) {
            continue;
        }
        if entry.trust_required
            && !crate::config::trust::runtime_policy()
                .is_some_and(|policy| policy.mode == WorkspaceTrustMode::Trust)
        {
            continue;
        }
        let local = local.map(|local| {
            let root = if local.root.is_absolute() {
                local.root
            } else {
                cwd.join(local.root)
            };
            let sidecars = local.sidecars.unwrap_or_else(|| KbSidecars::in_root(&root));
            RegistryLocalKb {
                root,
                assistant_snapshot_root: local.assistant_snapshot_root,
                sidecars: Some(sidecars),
            }
        });
        let Some(provider) = provider_for(entry.clone(), local)? else {
            continue;
        };
        knowledge_bases.push(AttachedKnowledgeBase { entry, provider });
    }
    Ok(knowledge_bases)
}

#[derive(Debug, Clone)]
struct RegistryKnowledgeBase {
    entry: KnowledgeBaseRegistryEntry,
    local: Option<RegistryLocalKb>,
}

#[derive(Debug, Clone)]
struct RegistryLocalKb {
    root: PathBuf,
    assistant_snapshot_root: Option<PathBuf>,
    sidecars: Option<KbSidecars>,
}

fn workspace_knowledge_base(entry: KnowledgeBaseRegistryEntry) -> RegistryKnowledgeBase {
    let local = match &entry.source {
        KnowledgeBaseSource::Local { path } => Some(RegistryLocalKb {
            root: path.clone(),
            assistant_snapshot_root: None,
            sidecars: None,
        }),
        KnowledgeBaseSource::Remote { .. } => None,
    };
    RegistryKnowledgeBase { entry, local }
}

async fn assistant_knowledge_registry_entry(
    session: &Session,
) -> Result<Option<RegistryKnowledgeBase>> {
    let Some(name) = &session.assistant_name else {
        return Ok(None);
    };
    let Some(snapshot) = crate::assistants::snapshot(&session.db, name)
        .await
        .with_context(|| format!("validating assistant `{name}` knowledge root"))?
    else {
        return Ok(None);
    };
    let root = crate::assistants::validate_row_home(&snapshot.row)?.join("knowledge");
    let config: crate::assistants::AssistantConfig =
        serde_json::from_str(&snapshot.row.config_json)
            .context("parsing assistant identity for knowledge cache")?;
    if config.installation_id.is_nil() {
        bail!("assistant knowledge has no installation identity");
    }
    let cache_root = crate::config::resolve::cockpit_data_dir()?.join("knowledge-indexes");
    cockpit_host::private_fs::ensure_private_dir(&cache_root)?;
    let entry = KnowledgeBaseRegistryEntry {
        id: format!("assistant-{}", config.installation_id),
        name: format!("Assistant: {name}"),
        description: format!("Knowledge installed with assistant `{name}`."),
        source: KnowledgeBaseSource::Local { path: root.clone() },
        embedding_ownership: KnowledgeBaseEmbeddingOwnership::Local,
        dream_model: None,
        dream_schedule: None,
        trust_required: false,
        merge_policy: KnowledgeBaseMergePolicy::Auto,
    };
    Ok(Some(RegistryKnowledgeBase {
        entry,
        local: Some(RegistryLocalKb {
            root,
            assistant_snapshot_root: Some(PathBuf::from(format!(
                "assistant://{}/knowledge",
                snapshot.row.name
            ))),
            sidecars: Some(KbSidecars::in_root(
                &cache_root.join(config.installation_id.to_string()),
            )),
        }),
    }))
}

fn validate_registry_entry(entry: &KnowledgeBaseRegistryEntry) -> Result<()> {
    if entry.id.is_empty()
        || !entry
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("knowledge base IDs must be non-empty ASCII alphanumeric, `-`, or `_`");
    }
    if entry.name.trim().is_empty() || entry.description.trim().is_empty() {
        bail!(
            "knowledge base `{}` requires a non-empty name and description",
            entry.id
        );
    }
    match (
        &entry.source,
        entry.embedding_ownership,
        entry.trust_required,
    ) {
        (KnowledgeBaseSource::Local { .. }, KnowledgeBaseEmbeddingOwnership::Local, _) => {}
        (
            KnowledgeBaseSource::Remote { url },
            KnowledgeBaseEmbeddingOwnership::RemoteOwned,
            false,
        ) if !url.trim().is_empty() => {}
        (KnowledgeBaseSource::Local { .. }, KnowledgeBaseEmbeddingOwnership::RemoteOwned, _) => {
            bail!(
                "local knowledge base `{}` must use local embedding ownership",
                entry.id
            )
        }
        (KnowledgeBaseSource::Remote { .. }, KnowledgeBaseEmbeddingOwnership::Local, _) => {
            bail!(
                "remote knowledge base `{}` must use remote-owned embeddings",
                entry.id
            )
        }
        (KnowledgeBaseSource::Remote { .. }, _, true) => {
            bail!(
                "remote knowledge base `{}` cannot require local trust",
                entry.id
            )
        }
        (KnowledgeBaseSource::Remote { .. }, _, false) => {
            bail!(
                "remote knowledge base `{}` requires a non-empty URL",
                entry.id
            )
        }
    }
    Ok(())
}

fn provider_for(
    entry: KnowledgeBaseRegistryEntry,
    local: Option<RegistryLocalKb>,
) -> Result<Option<Arc<dyn KbProvider>>> {
    match (entry.source.clone(), local) {
        (KnowledgeBaseSource::Local { .. }, Some(local)) => {
            let sidecars = local
                .sidecars
                .context("local knowledge provider has no sidecar paths")?;
            if let Some(snapshot_root) = local.assistant_snapshot_root {
                cockpit_host::private_fs::ensure_private_dir(
                    sidecars
                        .index
                        .parent()
                        .context("assistant knowledge index has no parent")?,
                )?;
                return LocalKb::assistant(entry, local.root, snapshot_root, sidecars).map(
                    |provider| provider.map(|provider| Arc::new(provider) as Arc<dyn KbProvider>),
                );
            }
            Ok(Some(Arc::new(LocalKb::new(
                entry, local.root, None, sidecars, None,
            ))))
        }
        (KnowledgeBaseSource::Remote { .. }, None) => Ok(Some(Arc::new(RemoteKb { entry }))),
        _ => bail!(
            "knowledge base `{}` has an invalid provider resolution",
            entry.id
        ),
    }
}

pub(crate) async fn with_memory_search_if_attached(
    toolbox: crate::engine::tool::ToolBox,
    session: &Session,
    cwd: &Path,
    definition: Option<&crate::agents::AgentDef>,
    config: &crate::daemon::session_worker::SessionConfigHandle,
) -> crate::engine::tool::ToolBox {
    let allowed_knowledge_bases = definition
        .and_then(crate::agents::AgentDef::allowed_knowledge_bases)
        .cloned();
    if attached_bundles_available(session, cwd, allowed_knowledge_bases.as_ref(), config).await {
        toolbox.with(Arc::new(MemorySearchTool {
            allowed_knowledge_bases,
        }))
    } else {
        toolbox.without(MEMORY_SEARCH_TOOL_NAME)
    }
}

/// A turn-toolbox instance binds the executing agent definition's KB
/// restriction.  The tool can therefore refresh workspace configuration at
/// call time without re-resolving a mutable, same-named agent definition.
pub(crate) struct MemorySearchTool {
    allowed_knowledge_bases: Option<BTreeSet<String>>,
}

#[derive(Debug, Deserialize)]
struct MemorySearchArgs {
    query: String,
    #[serde(default)]
    limit: Option<usize>,
}

#[async_trait]
impl Tool for MemorySearchTool {
    fn name(&self) -> &str {
        MEMORY_SEARCH_TOOL_NAME
    }

    fn description(&self) -> &str {
        "search attached OKF memory bundles with citations"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Search attached named OKF knowledge bases for a specific query and return cited ranked results."
                .to_string(),
        )
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "search query" },
                "limit": { "type": "integer", "minimum": 1, "maximum": 20, "description": "maximum results" }
            },
            "required": ["query"],
            "additionalProperties": false
        })
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: MemorySearchArgs = typed_args(args)?;
        if args.query.trim().is_empty() {
            return Err(invalid_input("memory_search query must not be empty"));
        }
        let extended = ctx.config.extended();
        let bundles = attached_bundles(
            &ctx.session,
            &ctx.cwd,
            self.allowed_knowledge_bases.as_ref(),
            &extended,
        )
        .await?;
        if bundles.is_empty() {
            return Ok(ToolOutput::text(
                "No attached knowledge bundles are available.",
            ));
        }
        let Some(embedder) =
            production_embedder(&extended, &ctx.config, ctx.redact.clone(), &ctx.session).await?
        else {
            return Ok(ToolOutput::text(
                "No embedding_model is configured, so memory_search cannot build the knowledge index.",
            ));
        };
        let limit = args.limit.unwrap_or(DEFAULT_SEARCH_LIMIT).clamp(1, 20);
        let results = retrieve_from_knowledge_bases(&bundles, embedder, &args.query, limit).await?;
        let content = render_tool_results(&results, ctx.redact.as_ref());
        Ok(ToolOutput::text(content))
    }
}

fn render_tool_results(results: &[SearchResult], redact: &RedactionTable) -> String {
    if results.is_empty() {
        return "No matching memory entries.".to_string();
    }
    let mut out = String::from("memory_search results:\n");
    for result in results {
        out.push_str("- ");
        out.push_str(&result.concept_id);
        out.push_str(" — ");
        out.push_str(&short_summary(&result.snippet));
        out.push_str(" [");
        out.push_str(&citation_label(result));
        out.push_str("]\n");
    }
    redact.scrub(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    struct MockEmbedder;
    struct DimEmbedder(usize);
    struct CountingEmbedder {
        calls: Arc<AtomicUsize>,
    }
    struct NamedCountingEmbedder {
        identity: &'static str,
        calls: Arc<AtomicUsize>,
    }
    struct SlowCountingEmbedder {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Embedder for MockEmbedder {
        async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            Ok(texts.iter().map(|text| mock_vector(text)).collect())
        }

        fn identity(&self) -> String {
            "mock-v1".to_string()
        }
    }

    #[async_trait]
    impl Embedder for DimEmbedder {
        async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            Ok(texts
                .iter()
                .map(|text| {
                    let mut vector = vec![0.0; self.0];
                    if !vector.is_empty() && text.contains("deploy") {
                        vector[0] = 1.0;
                    }
                    vector
                })
                .collect())
        }

        fn identity(&self) -> String {
            "dimension-test-model".to_string()
        }
    }

    #[async_trait]
    impl Embedder for CountingEmbedder {
        async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            self.calls.fetch_add(texts.len(), Ordering::SeqCst);
            Ok(texts.iter().map(|text| mock_vector(text)).collect())
        }

        fn identity(&self) -> String {
            "counting-v1".to_string()
        }
    }

    #[async_trait]
    impl Embedder for NamedCountingEmbedder {
        async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            self.calls.fetch_add(texts.len(), Ordering::SeqCst);
            Ok(texts.iter().map(|text| mock_vector(text)).collect())
        }

        fn identity(&self) -> String {
            self.identity.to_string()
        }
    }

    #[async_trait]
    impl Embedder for SlowCountingEmbedder {
        async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            self.calls.fetch_add(texts.len(), Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(texts.iter().map(|text| mock_vector(text)).collect())
        }

        fn identity(&self) -> String {
            "slow-counting-v1".to_string()
        }
    }

    fn mock_embedder() -> Arc<dyn Embedder> {
        Arc::new(MockEmbedder)
    }

    fn mock_vector(text: &str) -> Vec<f32> {
        let text = text.to_ascii_lowercase();
        let deploy = if text.contains("deploy")
            || text.contains("release")
            || text.contains("green")
            || text.contains("ship")
            || text.contains("launch")
        {
            1.0
        } else {
            0.0
        };
        let exact_anchor = if text.trim() == "e_connreset-7749" {
            1.0
        } else if deploy > 0.0 {
            0.8
        } else {
            0.0
        };
        let incident = if text.contains("rotate") || text.contains("relay token") {
            -1.0
        } else {
            0.0
        };
        vec![exact_anchor, deploy, incident]
    }

    fn write_bundle(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("index.md"), "# Index\n\n- [[deploy]]\n").unwrap();
        fs::write(root.join("log.md"), "# Log\n\n- 2026-07-16 seeded\n").unwrap();
        fs::write(
            root.join("deploy.md"),
            r#"---
type: decision
valid_from: 2026-07-16
supersedes:
  - old-deploy
invalidated_by: future-deploy
---

Release handoff should use the green deploy pipeline and wait for health checks.

# Citations

- [runbook](docs/deploy.md)
"#,
        )
        .unwrap();
        fs::write(
            root.join("error.md"),
            r#"---
type: incident
---

If workers emit E_CONNRESET-7749, rotate the relay token before retrying.

# Citations

- [incident](incidents/e-connreset.md)
"#,
        )
        .unwrap();
    }

    #[test]
    fn okf_bundle_parse_roundtrip() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());

        let bundle = parse_bundle(tmp.path()).unwrap();
        assert!(bundle.index_md.as_ref().unwrap().contains("# Index"));
        assert!(bundle.log_md.as_ref().unwrap().contains("# Log"));
        let deploy = bundle.concepts.iter().find(|c| c.id == "deploy").unwrap();
        assert_eq!(deploy.concept_type, "decision");
        assert_eq!(deploy.valid_from.as_deref(), Some("2026-07-16"));
        assert_eq!(deploy.supersedes, vec!["old-deploy"]);
        assert_eq!(deploy.invalidated_by.as_deref(), Some("future-deploy"));
        assert_eq!(deploy.citations[0].label, "runbook");

        let roundtrip = serialize_concept(deploy);
        fs::write(tmp.path().join("roundtrip.md"), roundtrip).unwrap();
        let reparsed = parse_bundle(tmp.path()).unwrap();
        assert!(reparsed.concepts.iter().any(|c| c.id == "roundtrip"));
    }

    #[test]
    fn okf_bundle_permissive_consumption_negative_cases() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path()).unwrap();
        fs::write(tmp.path().join("notes.md"), "plain markdown is ignored").unwrap();
        fs::write(
            tmp.path().join("unknown.md"),
            "---\ntype: made-up\nunknown: yes\n---\n\nBroken [[missing]] link.",
        )
        .unwrap();
        fs::write(
            tmp.path().join("missing-type.md"),
            "---\nid: nope\n---\n\nbody",
        )
        .unwrap();

        let err = parse_bundle(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("required `type`"));
        fs::remove_file(tmp.path().join("missing-type.md")).unwrap();
        let bundle = parse_bundle(tmp.path()).unwrap();
        assert_eq!(bundle.concepts.len(), 1);
        assert_eq!(bundle.concepts[0].concept_type, "made-up");
    }

    #[test]
    fn referenced_resources_share_the_markdown_snapshot_byte_budget() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("data.csv"), "id\n1\n").unwrap();
        let handle = cockpit_config::config::open_config_directory_nofollow(tmp.path()).unwrap();
        let mut frontmatter = BTreeMap::new();
        frontmatter.insert("resource".to_string(), "data.csv".to_string());
        let concept = KnowledgeConcept {
            id: "catalog".to_string(),
            path: PathBuf::from("catalog.md"),
            concept_type: "catalog".to_string(),
            frontmatter,
            body: String::new(),
            citations: Vec::new(),
            valid_from: None,
            supersedes: Vec::new(),
            invalidated_by: None,
        };
        let error = load_referenced_resources(
            tmp.path(),
            &handle,
            &[concept],
            0,
            MAX_KNOWLEDGE_TOTAL_BYTES,
        )
        .unwrap_err();
        assert!(error.to_string().contains("aggregate byte limit"));
    }

    #[tokio::test]
    async fn index_projects_markdown_tables_and_referenced_resources() {
        let tmp = TempDir::new().unwrap();
        let concept_dir = tmp.path().join("services/api");
        fs::create_dir_all(&concept_dir).unwrap();
        fs::write(
            concept_dir.join("inventory.csv"),
            "sku,count,active\nA-1,4,true\n",
        )
        .unwrap();
        fs::write(
            concept_dir.join("structured.md"),
            r#"---
type: catalog
title: Inventory
description: Current inventory
resource: inventory.csv
tags: [warehouse, current]
timestamp: 2026-08-29T12:00:00Z
---

| owner | priority |
| --- | --- |
| operations | 1 |
"#,
        )
        .unwrap();

        let (index, _) = KnowledgeIndex::open(tmp.path(), mock_embedder())
            .await
            .unwrap();
        let markdown_rows: i64 = index
            .index
            .query_row(
                "SELECT COUNT(*) FROM structured_rows WHERE source_kind='markdown-table'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let resource_rows: i64 = index
            .index
            .query_row(
                "SELECT COUNT(*) FROM structured_rows WHERE source_kind='resource-csv'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let count: i64 = index
            .index
            .query_row(
                "SELECT value_integer FROM structured_values
                 WHERE column_name='count' AND value_type='integer'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(markdown_rows, 1);
        assert_eq!(resource_rows, 1);
        assert_eq!(count, 4);
    }

    #[tokio::test]
    async fn index_rebuilds_from_bundle() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let calls = Arc::new(AtomicUsize::new(0));
        let embedder: Arc<dyn Embedder> = Arc::new(CountingEmbedder {
            calls: calls.clone(),
        });
        let (index, _) = KnowledgeIndex::open(tmp.path(), embedder.clone())
            .await
            .unwrap();
        let query_vector = mock_embedder()
            .embed(&["release shipping procedure"])
            .await
            .unwrap()
            .remove(0);
        let first = index
            .search_with_vector(&query_vector, "release shipping procedure", 3)
            .unwrap();
        drop(index);
        let before_rebuild = calls.load(Ordering::SeqCst);
        fs::remove_file(tmp.path().join(INDEX_FILE)).unwrap();
        let (rebuilt, stats) = KnowledgeIndex::open(tmp.path(), embedder).await.unwrap();
        let second = rebuilt
            .search_with_vector(&query_vector, "release shipping procedure", 3)
            .unwrap();
        assert_eq!(ids(&first), ids(&second));
        assert_eq!(stats.embedded_chunks, 0);
        assert_eq!(calls.load(Ordering::SeqCst), before_rebuild);
    }

    #[tokio::test]
    async fn local_git_knowledge_sidecars_are_ignored_in_repository_metadata() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let init = Command::new("git")
            .arg("init")
            .arg(tmp.path())
            .status()
            .unwrap();
        assert!(init.success());
        let _ = KnowledgeIndex::open(tmp.path(), mock_embedder())
            .await
            .unwrap();
        for sidecar in [EMBEDDINGS_FILE, INDEX_FILE] {
            let ignored = Command::new("git")
                .arg("-C")
                .arg(tmp.path())
                .args(["check-ignore", "-q", sidecar])
                .status()
                .unwrap();
            assert!(
                ignored.success(),
                "{sidecar} must be ignored in a KB Git repository"
            );
        }
    }

    #[tokio::test]
    async fn index_version_bump_rebuilds_only_disposable_index() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let (index, _) = KnowledgeIndex::open(tmp.path(), mock_embedder())
            .await
            .unwrap();
        index.set_logic_version_for_test(0).unwrap();
        drop(index);
        let (_, stats) = KnowledgeIndex::open(tmp.path(), mock_embedder())
            .await
            .unwrap();
        assert_eq!(stats.embedded_chunks, 0, "{stats:?}");
        assert_eq!(stats.reused_files, 2);
    }

    #[tokio::test]
    async fn index_incremental_by_hash() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let (_, first) = KnowledgeIndex::open(tmp.path(), mock_embedder())
            .await
            .unwrap();
        assert!(first.embedded_chunks >= 2);
        fs::write(
            tmp.path().join("error.md"),
            "---\ntype: incident\n---\n\nIf workers emit E_CONNRESET-7749, rotate token and restart one worker.\n",
        )
        .unwrap();
        let (_, second) = KnowledgeIndex::open(tmp.path(), mock_embedder())
            .await
            .unwrap();
        assert_eq!(second.indexed_files, 1);
        assert!(second.reused_files >= 1);
    }

    #[tokio::test]
    async fn index_dimension_change_reembeds_unchanged_content() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let (_, first) = KnowledgeIndex::open_with_query_dimensions(
            tmp.path(),
            Arc::new(DimEmbedder(3)),
            Some(3),
        )
        .await
        .unwrap();
        assert!(first.embedded_chunks >= 2);

        let (index, second) = KnowledgeIndex::open_with_query_dimensions(
            tmp.path(),
            Arc::new(DimEmbedder(4)),
            Some(4),
        )
        .await
        .unwrap();
        assert_eq!(second.reused_files, 0);
        assert_eq!(second.indexed_files, 2);
        assert!(second.embedded_chunks >= 2);
        let query = DimEmbedder(4).embed(&["deploy"]).await.unwrap().remove(0);
        let results = index.search_with_vector(&query, "deploy", 2).unwrap();
        assert!(results.iter().any(|result| result.concept_id == "deploy"));
    }

    #[tokio::test]
    async fn index_model_identity_change_reembeds_unchanged_content() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let first_calls = Arc::new(AtomicUsize::new(0));
        let first: Arc<dyn Embedder> = Arc::new(NamedCountingEmbedder {
            identity: "model-a",
            calls: first_calls.clone(),
        });
        let (_, first_stats) = KnowledgeIndex::open(tmp.path(), first).await.unwrap();
        assert_eq!(
            first_calls.load(Ordering::SeqCst),
            first_stats.embedded_chunks
        );

        let second_calls = Arc::new(AtomicUsize::new(0));
        let second: Arc<dyn Embedder> = Arc::new(NamedCountingEmbedder {
            identity: "model-b",
            calls: second_calls.clone(),
        });
        let (_, second_stats) = KnowledgeIndex::open(tmp.path(), second).await.unwrap();
        assert_eq!(second_stats.reused_files, 0);
        assert_eq!(
            second_calls.load(Ordering::SeqCst),
            first_stats.embedded_chunks
        );
    }

    #[tokio::test]
    async fn concurrent_index_opens_embed_each_chunk_once() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let calls = Arc::new(AtomicUsize::new(0));
        let embedder: Arc<dyn Embedder> = Arc::new(SlowCountingEmbedder {
            calls: calls.clone(),
        });
        let root = tmp.path().to_path_buf();
        let (first, second) = tokio::join!(
            KnowledgeIndex::open(root.clone(), embedder.clone()),
            KnowledgeIndex::open(root, embedder),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        let expected = first.1.embedded_chunks.max(second.1.embedded_chunks);
        assert_eq!(calls.load(Ordering::SeqCst), expected);
    }

    #[tokio::test]
    async fn hybrid_retrieval_covers_both() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let (index, _) = KnowledgeIndex::open(tmp.path(), mock_embedder())
            .await
            .unwrap();
        let exact_vector = mock_embedder()
            .embed(&["E_CONNRESET-7749"])
            .await
            .unwrap()
            .remove(0);
        let paraphrase_vector = mock_embedder()
            .embed(&["how should I ship a launch safely"])
            .await
            .unwrap()
            .remove(0);

        let vector_only_exact = rrf_merge(
            &index.index,
            vector_search(&index.embeddings, &index.index, &exact_vector, 1).unwrap(),
            vec![],
            1,
        )
        .unwrap();
        let keyword_only_exact = rrf_merge(
            &index.index,
            vec![],
            keyword_search(&index.index, "E_CONNRESET-7749", 1).unwrap(),
            1,
        )
        .unwrap();
        let vector_only_paraphrase = rrf_merge(
            &index.index,
            vector_search(&index.embeddings, &index.index, &paraphrase_vector, 1).unwrap(),
            vec![],
            1,
        )
        .unwrap();
        let keyword_only_paraphrase = rrf_merge(
            &index.index,
            vec![],
            keyword_search(&index.index, "ship launch safely", 1).unwrap(),
            1,
        )
        .unwrap();
        assert!(
            !vector_only_exact.iter().any(|r| r.concept_id == "error"),
            "exact-id fixture should need the keyword arm"
        );
        assert!(keyword_only_exact.iter().any(|r| r.concept_id == "error"));
        assert!(
            vector_only_paraphrase
                .iter()
                .any(|r| r.concept_id == "deploy")
        );
        assert!(
            !keyword_only_paraphrase
                .iter()
                .any(|r| r.concept_id == "deploy"),
            "paraphrase fixture should need the vector arm"
        );

        let exact = index
            .search_with_vector(&exact_vector, "E_CONNRESET-7749", 2)
            .unwrap();
        let paraphrase = index
            .search_with_vector(&paraphrase_vector, "ship launch safely", 2)
            .unwrap();

        assert!(exact.iter().any(|r| r.concept_id == "error"));
        assert!(paraphrase.iter().any(|r| r.concept_id == "deploy"));
    }

    #[test]
    fn knowledge_injection_capped_and_redacted() {
        let redact = {
            let cfg = RedactConfig {
                enabled: true,
                denylist: vec!["sk-secret".to_string()],
                placeholder: "[redacted]".to_string(),
                ..RedactConfig::default()
            };
            RedactionTable::build(&cfg, Path::new(".")).unwrap()
        };
        let results = vec![SearchResult {
            knowledge_base_id: "project".to_string(),
            knowledge_base_name: "Project".to_string(),
            concept_id: "deploy".to_string(),
            source_path: "deploy.md".to_string(),
            chunk_index: 0,
            snippet: "Use sk-secret and the green deploy pipeline with citations.".to_string(),
            citations: vec![Citation {
                label: "runbook".to_string(),
                target: "docs/deploy.md".to_string(),
            }],
            score: 1.0,
        }];
        let rendered = render_injection(&results, 80, &redact).unwrap();
        assert!(rendered.contains("runbook"));
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("sk-secret"));
        assert!(crate::tokens::count(&rendered) <= 80);
    }

    #[tokio::test]
    async fn project_bundle_trust_gated() {
        let _env = crate::test_env::lock_async().await;
        crate::config::trust::clear_runtime_policy_for_tests();
        let tmp = TempDir::new().unwrap();
        let project_bundle = tmp.path().join(".cockpit/knowledge");
        write_bundle(&project_bundle);
        let session = test_session(tmp.path()).await;
        let extended = ExtendedConfig {
            knowledge_bases: vec![project_knowledge_registry_entry()],
            ..Default::default()
        };

        assert!(
            attached_bundles(&session, tmp.path(), None, &extended)
                .await
                .unwrap()
                .is_empty()
        );
        crate::config::trust::set_runtime_policy(
            trust_root(tmp.path()),
            WorkspaceTrustMode::Untrusted,
        );
        assert!(
            attached_bundles(&session, tmp.path(), None, &extended)
                .await
                .unwrap()
                .is_empty()
        );
        crate::config::trust::set_runtime_policy(trust_root(tmp.path()), WorkspaceTrustMode::Trust);
        assert_eq!(
            attached_bundles(&session, tmp.path(), None, &extended)
                .await
                .unwrap()
                .len(),
            1
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[tokio::test]
    async fn executing_definition_snapshot_restricts_workspace_knowledge_registry() {
        let _env = crate::test_env::lock_async().await;
        let tmp = TempDir::new().unwrap();
        let session = test_session(tmp.path()).await;
        let mut agent = crate::agents::embedded_default("Plan").unwrap();
        agent.vnext.as_mut().unwrap().allowed_knowledge_bases =
            Some(BTreeSet::from(["project".to_string()]));

        let mut project = project_knowledge_registry_entry();
        project.trust_required = false;
        let mut private = project.clone();
        private.id = "private-notes".to_string();
        private.name = "Private notes".to_string();
        private.source = KnowledgeBaseSource::Local {
            path: PathBuf::from("private-notes"),
        };
        let extended = ExtendedConfig {
            knowledge_bases: vec![project, private],
            ..Default::default()
        };

        // This value comes from the executing agent's definition snapshot;
        // selection therefore does not require name-based re-resolution.
        let attached = attached_bundles(
            &session,
            tmp.path(),
            agent.allowed_knowledge_bases(),
            &extended,
        )
        .await
        .unwrap();
        assert_eq!(attached.len(), 1);
        assert_eq!(attached[0].entry.id, "project");
    }

    #[tokio::test]
    async fn installed_assistant_knowledge_is_attached_as_a_verified_registry_entry() {
        let env = crate::test_env::lock_async().await;
        let tmp = TempDir::new().unwrap();
        env.set_var("XDG_DATA_HOME", tmp.path());
        let db = crate::db::Db::open_in_memory().unwrap();
        let home = crate::assistants::default_home_dir("helper-bot").unwrap();
        let installation_id = uuid::Uuid::from_u128(42);
        crate::assistants::create_assistant_with_installation_id(
            &db,
            crate::assistants::CreateAssistantSpec {
                name: "helper-bot".to_string(),
                description: "Helper bot".to_string(),
                prompt: "Help with tests.".to_string(),
                home_dir: home.clone(),
            },
            installation_id,
        )
        .await
        .unwrap();
        write_bundle(&home.join("knowledge"));
        let session = crate::session::Session::create_assistant_deferred_for_test(
            db,
            tmp.path().to_path_buf(),
            "helper-bot",
            "helper-bot",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        let attached = attached_bundles(&session, tmp.path(), None, &ExtendedConfig::default())
            .await
            .unwrap();
        assert_eq!(attached.len(), 1);
        assert_eq!(attached[0].entry.id, format!("assistant-{installation_id}"));
        assert!(attached[0].provider.is_available().await.unwrap());

        fs::remove_dir_all(home.join("knowledge")).unwrap();
        fs::create_dir_all(home.join("knowledge")).unwrap();
        fs::write(
            home.join("knowledge/replacement.md"),
            "---\ntype: replacement\n---\n\nReplacement knowledge must not be read.\n",
        )
        .unwrap();
        let results = attached[0]
            .provider
            .with_embedder(mock_embedder())
            .retrieve("release shipping procedure", DEFAULT_SEARCH_LIMIT)
            .await
            .unwrap();
        assert!(results.iter().any(|result| result.concept_id == "deploy"));
        assert!(
            !results
                .iter()
                .any(|result| result.concept_id == "replacement")
        );
    }

    #[tokio::test]
    async fn unavailable_knowledge_bases_do_not_block_available_retrieval() {
        let _env = crate::test_env::lock_async().await;
        let tmp = TempDir::new().unwrap();
        let knowledge_root = tmp.path().join("available");
        write_bundle(&knowledge_root);
        let session = test_session(tmp.path()).await;
        let available = KnowledgeBaseRegistryEntry {
            id: "available".to_string(),
            name: "Available".to_string(),
            description: "Available local knowledge".to_string(),
            source: KnowledgeBaseSource::Local {
                path: PathBuf::from("available"),
            },
            embedding_ownership: KnowledgeBaseEmbeddingOwnership::Local,
            dream_model: None,
            dream_schedule: None,
            trust_required: false,
            merge_policy: KnowledgeBaseMergePolicy::Auto,
        };
        let mut missing = available.clone();
        missing.id = "missing".to_string();
        missing.name = "Missing".to_string();
        missing.source = KnowledgeBaseSource::Local {
            path: PathBuf::from("missing"),
        };
        let extended = ExtendedConfig {
            knowledge_bases: vec![available, missing],
            ..Default::default()
        };

        let attached = attached_bundles(&session, tmp.path(), None, &extended)
            .await
            .unwrap();
        let results = retrieve_from_knowledge_bases(
            &attached,
            mock_embedder(),
            "release shipping procedure",
            DEFAULT_SEARCH_LIMIT,
        )
        .await
        .unwrap();
        assert!(
            results
                .iter()
                .any(|result| result.knowledge_base_id == "available")
        );
    }

    #[tokio::test]
    async fn configured_remote_knowledge_fails_retrieval_closed() {
        let _env = crate::test_env::lock_async().await;
        let tmp = TempDir::new().unwrap();
        let knowledge_root = tmp.path().join("available");
        write_bundle(&knowledge_root);
        let session = test_session(tmp.path()).await;
        let available = KnowledgeBaseRegistryEntry {
            id: "available".to_string(),
            name: "Available".to_string(),
            description: "Available local knowledge".to_string(),
            source: KnowledgeBaseSource::Local {
                path: PathBuf::from("available"),
            },
            embedding_ownership: KnowledgeBaseEmbeddingOwnership::Local,
            dream_model: None,
            dream_schedule: None,
            trust_required: false,
            merge_policy: KnowledgeBaseMergePolicy::Auto,
        };
        let remote = KnowledgeBaseRegistryEntry {
            id: "hosted".to_string(),
            name: "Hosted".to_string(),
            description: "Deferred hosted knowledge".to_string(),
            source: KnowledgeBaseSource::Remote {
                url: "https://knowledge.example.test".to_string(),
            },
            embedding_ownership: KnowledgeBaseEmbeddingOwnership::RemoteOwned,
            dream_model: None,
            dream_schedule: None,
            trust_required: false,
            merge_policy: KnowledgeBaseMergePolicy::Auto,
        };
        let extended = ExtendedConfig {
            knowledge_bases: vec![available, remote],
            ..Default::default()
        };

        let attached = attached_bundles(&session, tmp.path(), None, &extended)
            .await
            .unwrap();
        let error = retrieve_from_knowledge_bases(
            &attached,
            mock_embedder(),
            "release shipping procedure",
            DEFAULT_SEARCH_LIMIT,
        )
        .await
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("hosted"));
        assert!(diagnostic.contains("not implemented"));

        fs::create_dir_all(tmp.path().join(".cockpit")).unwrap();
        fs::write(
            tmp.path().join(".cockpit/config.json"),
            r#"{"knowledgeBases":[{"id":"available","name":"Available","description":"Available local knowledge","source":{"kind":"local","path":"available"},"embeddingOwnership":"local","trustRequired":false,"mergePolicy":"auto"},{"id":"hosted","name":"Hosted","description":"Deferred hosted knowledge","source":{"kind":"remote","url":"https://knowledge.example.test"},"embeddingOwnership":"remote-owned","trustRequired":false,"mergePolicy":"auto"}]}"#,
        )
        .unwrap();
        assert!(
            !attached_bundles_available(
                &session,
                tmp.path(),
                None,
                &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(
                    tmp.path()
                )
            )
            .await
        );
    }

    #[tokio::test]
    async fn memory_search_tool_gated() {
        let _env = crate::test_env::lock_async().await;
        crate::config::trust::clear_runtime_policy_for_tests();
        let tmp = TempDir::new().unwrap();
        let session = test_session(tmp.path()).await;
        let base = crate::engine::tool::ToolBox::new();
        assert!(
            !with_memory_search_if_attached(
                base.clone(),
                &session,
                tmp.path(),
                None,
                &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(
                    tmp.path()
                )
            )
            .await
            .names()
            .contains(&"memory_search")
        );

        write_bundle(&tmp.path().join(".cockpit/knowledge"));
        fs::create_dir_all(tmp.path().join(".cockpit")).unwrap();
        fs::write(
            tmp.path().join(".cockpit/config.json"),
            r#"{"knowledgeBases":[{"id":"project","name":"Project","description":"Workspace project knowledge","source":{"kind":"local","path":".cockpit/knowledge"},"embeddingOwnership":"local","trustRequired":true,"mergePolicy":"auto"}]}"#,
        )
        .unwrap();
        crate::config::trust::set_runtime_policy(trust_root(tmp.path()), WorkspaceTrustMode::Trust);
        assert!(
            with_memory_search_if_attached(
                base,
                &session,
                tmp.path(),
                None,
                &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(
                    tmp.path()
                )
            )
            .await
            .names()
            .contains(&"memory_search")
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[tokio::test]
    async fn main_db_has_no_vectors() {
        let tmp = TempDir::new().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).unwrap();
        db.read(|conn| {
            // Vector/embedding STORAGE (tables, indexes, views) must never live
            // in the main DB, and no object may pull in the sqlite-vec `vec0`
            // module. Triggers named for the image-generation "cancellation
            // vector" domain concept are not vector storage and are excluded.
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE (type IN ('table','index','view')
                        AND (lower(name) LIKE '%vector%'
                             OR lower(name) LIKE '%embedding%'))
                    OR lower(sql) LIKE '%vec0%'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(count, 0);
            let err = conn
                .query_row("SELECT vec_version()", [], |row| row.get::<_, String>(0))
                .unwrap_err();
            assert!(err.to_string().contains("no such function"));
            Ok(())
        })
        .await
        .unwrap();
    }

    fn ids(results: &[SearchResult]) -> Vec<String> {
        results.iter().map(|r| r.concept_id.clone()).collect()
    }

    fn project_knowledge_registry_entry() -> KnowledgeBaseRegistryEntry {
        KnowledgeBaseRegistryEntry {
            id: "project".to_string(),
            name: "Project".to_string(),
            description: "Workspace project knowledge".to_string(),
            source: KnowledgeBaseSource::Local {
                path: PathBuf::from(".cockpit/knowledge"),
            },
            embedding_ownership: KnowledgeBaseEmbeddingOwnership::Local,
            dream_model: None,
            dream_schedule: None,
            trust_required: true,
            merge_policy: crate::config::extended::KnowledgeBaseMergePolicy::Auto,
        }
    }

    async fn test_session(root: &Path) -> Session {
        let db = crate::db::Db::open(&root.join("cockpit.db")).unwrap();
        let project_root = root.to_str().unwrap().to_string();
        let row = db
            .write(move |conn| {
                let row = crate::db::Db::build_new_session_row_conn(
                    conn,
                    "project",
                    &project_root,
                    "test",
                )?;
                crate::db::Db::insert_session_row_conn(conn, &row)
            })
            .await
            .unwrap();
        Session::resume_for_test(
            db,
            row.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .unwrap()
    }

    fn trust_root(root: &Path) -> crate::config::trust::TrustRoot {
        crate::config::trust::TrustRoot {
            opened_path: root.to_path_buf(),
            root: root.to_path_buf(),
            kind: crate::config::trust::TrustRootKind::Directory,
        }
    }
}
