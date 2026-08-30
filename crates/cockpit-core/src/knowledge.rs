//! OKF v0.1 knowledge bundles and disposable retrieval indexes.
//!
//! Cockpit treats local OKF markdown as the source of truth. The SQLite file
//! is a derived cache: delete it and it rebuilds from markdown. A named KB is
//! accessed exclusively through [`KbProvider`], allowing hosted retrieval to
//! replace the local implementation without caller churn. Embeddings and
//! vector tables never enter `cockpit.db`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::c_char;
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

pub(crate) const SIDE_CAR_FILE: &str = ".cockpit-knowledge.sqlite";
pub(crate) const INDEX_LOGIC_VERSION: i64 = 1;
const CHUNK_TARGET_TOKENS: usize = 400;
const CHUNK_OVERLAP_TOKENS: usize = 80;
const DEFAULT_SEARCH_LIMIT: usize = 6;
const MEMORY_SEARCH_TOOL_NAME: &str = "memory_search";
const KNOWLEDGE_RETRIEVE_TOOL_NAME: &str = "knowledge_retrieve";
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
    sidecar_path: PathBuf,
    embedder: Option<Arc<dyn Embedder>>,
}

struct RemoteKb {
    entry: KnowledgeBaseRegistryEntry,
}

impl LocalKb {
    fn new(
        entry: KnowledgeBaseRegistryEntry,
        root: PathBuf,
        snapshot: Option<KnowledgeBundle>,
        sidecar_path: PathBuf,
        embedder: Option<Arc<dyn Embedder>>,
    ) -> Self {
        Self {
            entry,
            root,
            snapshot,
            sidecar_path,
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
        sidecar_path: PathBuf,
    ) -> Result<Option<Self>> {
        let Some(snapshot) = Self::snapshot_assistant(&root, snapshot_root)? else {
            return Ok(None);
        };
        Ok(Some(Self::new(
            entry,
            root,
            Some(snapshot),
            sidecar_path,
            None,
        )))
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
        drop(handle);
        let documents = cockpit_config::config::snapshot_markdown_tree_nofollow(
            root,
            MAX_KNOWLEDGE_FILES,
            MAX_KNOWLEDGE_ENTRIES,
            MAX_KNOWLEDGE_DEPTH,
            MAX_KNOWLEDGE_FILE_BYTES,
            MAX_KNOWLEDGE_TOTAL_BYTES,
        )?;
        parse_bundle_snapshot(snapshot_root, documents).map(Some)
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
        let (index, _) = match &self.snapshot {
            Some(snapshot) => {
                KnowledgeIndex::open_snapshot(snapshot.clone(), self.sidecar_path.clone(), embedder)
                    .await?
            }
            None => KnowledgeIndex::open(&self.root, embedder).await?,
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

struct ReindexPlan {
    concepts: Vec<KnowledgeConcept>,
    stats: IndexStats,
    stored_dimensions: Option<usize>,
    force_clear_before_apply: bool,
}

struct EmbeddedConcept {
    concept: KnowledgeConcept,
    path: String,
    hash: String,
    chunks: Vec<(ChunkDoc, Vec<f32>)>,
}

pub(crate) fn parse_bundle(root: impl AsRef<Path>) -> Result<KnowledgeBundle> {
    let root = root.as_ref().to_path_buf();
    let documents = cockpit_config::config::snapshot_markdown_tree_nofollow(
        &root,
        MAX_KNOWLEDGE_FILES,
        MAX_KNOWLEDGE_ENTRIES,
        MAX_KNOWLEDGE_DEPTH,
        MAX_KNOWLEDGE_FILE_BYTES,
        MAX_KNOWLEDGE_TOTAL_BYTES,
    )?;
    parse_bundle_snapshot(root, documents)
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
    index_md: Option<String>,
    log_md: Option<String>,
    mut concepts: Vec<KnowledgeConcept>,
) -> Result<KnowledgeBundle> {
    concepts.sort_by(|a, b| a.path.cmp(&b.path));
    validate_unique_concept_ids(&root, &concepts)?;
    Ok(KnowledgeBundle {
        root,
        index_md,
        log_md,
        concepts,
    })
}

fn parse_bundle_snapshot(
    root: PathBuf,
    documents: Vec<(PathBuf, String)>,
) -> Result<KnowledgeBundle> {
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
    finish_bundle(root, index_md, log_md, concepts)
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

async fn embedding_dimensions_probe(embedder: &dyn Embedder) -> Result<usize> {
    let dimensions = embedder
        .embed(&["cockpit knowledge embedding dimension probe"])
        .await
        .context("probing knowledge embedding dimensions")?
        .into_iter()
        .next()
        .context("embedding dimension probe returned no vector")?
        .len();
    if dimensions == 0 {
        bail!("embedding dimension probe returned an empty vector");
    }
    Ok(dimensions)
}

fn sidecar_vec_table_exists(sidecar: &Path) -> Result<bool> {
    if !sidecar.exists() {
        return Ok(false);
    }
    let conn = open_sidecar_connection(sidecar)?;
    table_exists(&conn, "vec_chunks")
}

pub(crate) struct KnowledgeIndex {
    #[allow(dead_code)]
    bundle: KnowledgeBundle,
    conn: Connection,
}

impl KnowledgeIndex {
    pub(crate) async fn open(
        root: impl AsRef<Path>,
        embedder: Arc<dyn Embedder>,
    ) -> Result<(Self, IndexStats)> {
        let root = root.as_ref().to_path_buf();
        let bundle = parse_bundle(&root)?;
        Self::open_snapshot(bundle, root.join(SIDE_CAR_FILE), embedder).await
    }

    async fn open_snapshot(
        bundle: KnowledgeBundle,
        sidecar_path: PathBuf,
        embedder: Arc<dyn Embedder>,
    ) -> Result<(Self, IndexStats)> {
        let conn = open_sidecar_connection(&sidecar_path)?;
        ensure_schema(&conn)?;
        let mut plan = plan_reindex(&conn, &bundle)?;
        drop(conn);
        if !bundle.concepts.is_empty() {
            let current_dimensions = embedding_dimensions_probe(embedder.as_ref()).await?;
            let dimensions_changed = plan
                .stored_dimensions
                .is_some_and(|stored| stored != current_dimensions);
            let dimensions_missing_for_existing_table =
                plan.stored_dimensions.is_none() && sidecar_vec_table_exists(&sidecar_path)?;
            if dimensions_changed || dimensions_missing_for_existing_table {
                plan.concepts = bundle.concepts.clone();
                plan.stats.reused_files = 0;
                plan.stats.indexed_files = plan.concepts.len();
                plan.force_clear_before_apply = true;
            }
        }
        let (embedded, embedded_chunks) =
            embed_planned_concepts(&plan.concepts, embedder.as_ref()).await?;
        let conn = open_sidecar_connection(&sidecar_path)?;
        ensure_schema(&conn)?;
        if plan.force_clear_before_apply {
            clear_index(&conn)?;
        }
        let mut stats = plan.stats;
        stats.embedded_chunks = embedded_chunks;
        apply_embedded_concepts(&conn, embedded)?;
        conn.execute(
            "INSERT INTO intel_meta(key, value) VALUES('index_logic_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![INDEX_LOGIC_VERSION.to_string()],
        )?;
        Ok((Self { bundle, conn }, stats))
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
        let vector_arm = vector_search(&self.conn, query_vector, limit.max(DEFAULT_SEARCH_LIMIT))?;
        let keyword_arm =
            keyword_search(&self.conn, keyword_query, limit.max(DEFAULT_SEARCH_LIMIT))?;
        let merged = rrf_merge(&self.conn, vector_arm, keyword_arm, limit)?;
        Ok(merged)
    }

    #[cfg(test)]
    fn set_logic_version_for_test(&self, version: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO intel_meta(key, value) VALUES('index_logic_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![version.to_string()],
        )?;
        Ok(())
    }
}

fn open_sidecar_connection(sidecar: &Path) -> Result<Connection> {
    if !sidecar.exists() {
        match cockpit_host::private_fs::write_private_file_exclusive(sidecar, b"") {
            Ok(()) => {}
            Err(error) if sidecar.exists() => {
                cockpit_host::private_fs::repair_private_file(sidecar, "knowledge sidecar")
                    .map_err(anyhow::Error::from)
                    .context("securing concurrently-created knowledge sidecar")?;
                tracing::debug!(%error, "knowledge sidecar was created concurrently");
            }
            Err(error) => return Err(error).context("creating private knowledge sidecar"),
        }
    } else {
        cockpit_host::private_fs::repair_private_file(sidecar, "knowledge sidecar")
            .map_err(anyhow::Error::from)?;
    }
    let conn = Connection::open(sidecar)
        .with_context(|| format!("opening knowledge sidecar {}", sidecar.display()))?;
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

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS intel_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS source_files (
            path TEXT PRIMARY KEY,
            hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS concepts (
            id TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            concept_type TEXT NOT NULL,
            body TEXT NOT NULL,
            citations_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chunks (
            id INTEGER PRIMARY KEY,
            concept_id TEXT NOT NULL,
            source_path TEXT NOT NULL,
            chunk_index INTEGER NOT NULL,
            body TEXT NOT NULL,
            citations_json TEXT NOT NULL
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
            body,
            concept_id UNINDEXED,
            content='chunks',
            content_rowid='id'
        );
        "#,
    )?;
    Ok(())
}

fn plan_reindex(conn: &Connection, bundle: &KnowledgeBundle) -> Result<ReindexPlan> {
    let stored_version: Option<i64> = conn
        .query_row(
            "SELECT value FROM intel_meta WHERE key='index_logic_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .and_then(|value| value.parse().ok());
    let mut stats = IndexStats {
        embedded_chunks: 0,
        reused_files: 0,
        indexed_files: 0,
    };
    if stored_version != Some(INDEX_LOGIC_VERSION) {
        clear_index(conn)?;
    }
    let stored_dimensions = stored_embedding_dimensions(conn)?;
    let force_clear_before_apply = false;

    let bundle_paths: BTreeSet<String> = bundle
        .concepts
        .iter()
        .map(|concept| rel_string(&concept.path))
        .collect();
    let indexed_paths = indexed_paths(conn)?;
    for old in indexed_paths.difference(&bundle_paths) {
        delete_file(conn, old)?;
    }

    let mut concepts_to_index = Vec::new();
    for concept in &bundle.concepts {
        let path = rel_string(&concept.path);
        let hash = content_hash(&serialize_concept(concept));
        let old_hash: Option<String> = conn
            .query_row(
                "SELECT hash FROM source_files WHERE path=?1",
                params![path],
                |row| row.get(0),
            )
            .optional()?;
        if old_hash.as_deref() == Some(hash.as_str()) {
            stats.reused_files += 1;
            continue;
        }
        delete_file(conn, &path)?;
        stats.indexed_files += 1;
        concepts_to_index.push(concept.clone());
    }

    Ok(ReindexPlan {
        concepts: concepts_to_index,
        stats,
        stored_dimensions,
        force_clear_before_apply,
    })
}

fn stored_embedding_dimensions(conn: &Connection) -> Result<Option<usize>> {
    Ok(conn
        .query_row(
            "SELECT value FROM intel_meta WHERE key='embedding_dimensions'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .and_then(|value| value.parse().ok()))
}

fn clear_index(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        DROP TABLE IF EXISTS vec_chunks;
        DELETE FROM chunks_fts;
        DELETE FROM chunks;
        DELETE FROM concepts;
        DELETE FROM source_files;
        DELETE FROM intel_meta WHERE key IN ('index_logic_version', 'embedding_dimensions');
        "#,
    )?;
    Ok(())
}

fn indexed_paths(conn: &Connection) -> Result<BTreeSet<String>> {
    let mut stmt = conn.prepare("SELECT path FROM source_files")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = BTreeSet::new();
    for row in rows {
        out.insert(row?);
    }
    Ok(out)
}

fn delete_file(conn: &Connection, path: &str) -> Result<()> {
    let ids = chunk_ids_for_file(conn, path)?;
    for id in ids {
        conn.execute("DELETE FROM vec_chunks WHERE rowid=?1", params![id])
            .ok();
        conn.execute("DELETE FROM chunks_fts WHERE rowid=?1", params![id])?;
    }
    conn.execute("DELETE FROM chunks WHERE source_path=?1", params![path])?;
    conn.execute("DELETE FROM concepts WHERE path=?1", params![path])?;
    conn.execute("DELETE FROM source_files WHERE path=?1", params![path])?;
    Ok(())
}

fn chunk_ids_for_file(conn: &Connection, path: &str) -> Result<Vec<i64>> {
    let mut stmt = conn.prepare("SELECT id FROM chunks WHERE source_path=?1")?;
    let rows = stmt.query_map(params![path], |row| row.get::<_, i64>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

async fn embed_planned_concepts(
    concepts: &[KnowledgeConcept],
    embedder: &dyn Embedder,
) -> Result<(Vec<EmbeddedConcept>, usize)> {
    let mut embedded = Vec::new();
    let mut embedded_chunks = 0;
    for concept in concepts {
        let path = rel_string(&concept.path);
        let hash = content_hash(&serialize_concept(concept));
        let chunks = chunk_concept(concept, &path);
        if chunks.is_empty() {
            continue;
        }
        let texts: Vec<&str> = chunks.iter().map(|chunk| chunk.body.as_str()).collect();
        let embeddings = embedder
            .embed(&texts)
            .await
            .context("embedding knowledge chunks")?;
        if embeddings.len() != chunks.len() {
            bail!(
                "knowledge embedder returned {} vectors for {} chunks",
                embeddings.len(),
                chunks.len()
            );
        }
        let chunks: Vec<(ChunkDoc, Vec<f32>)> = chunks.into_iter().zip(embeddings).collect();
        embedded_chunks += chunks.len();
        embedded.push(EmbeddedConcept {
            concept: concept.clone(),
            path,
            hash,
            chunks,
        });
    }
    Ok((embedded, embedded_chunks))
}

fn apply_embedded_concepts(conn: &Connection, embedded: Vec<EmbeddedConcept>) -> Result<()> {
    for embedded in embedded {
        let Some(dim) = embedded
            .chunks
            .first()
            .map(|(_, vector)| vector.len())
            .filter(|dim| *dim > 0)
        else {
            continue;
        };
        ensure_vec_table(conn, dim)?;
        conn.execute(
            "INSERT OR REPLACE INTO concepts(id, path, concept_type, body, citations_json)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                embedded.concept.id,
                embedded.path,
                embedded.concept.concept_type,
                embedded.concept.body,
                serde_json::to_string(&embedded.concept.citations)?,
            ],
        )?;
        for (chunk, embedding) in &embedded.chunks {
            if embedding.len() != dim {
                bail!("knowledge embedder returned mixed vector dimensions");
            }
            insert_chunk(conn, chunk, embedding)?;
        }
        conn.execute(
            "INSERT OR REPLACE INTO source_files(path, hash) VALUES(?1, ?2)",
            params![embedded.path, embedded.hash],
        )?;
    }
    Ok(())
}

fn insert_chunk(conn: &Connection, chunk: &ChunkDoc, embedding: &[f32]) -> Result<()> {
    conn.execute(
        "INSERT INTO chunks(concept_id, source_path, chunk_index, body, citations_json)
         VALUES(?1, ?2, ?3, ?4, ?5)",
        params![
            chunk.concept_id,
            chunk.source_path,
            chunk.chunk_index as i64,
            chunk.body,
            serde_json::to_string(&chunk.citations)?,
        ],
    )?;
    let rowid = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO chunks_fts(rowid, body, concept_id) VALUES(?1, ?2, ?3)",
        params![rowid, chunk.body, chunk.concept_id],
    )?;
    conn.execute(
        "INSERT INTO vec_chunks(rowid, embedding) VALUES(?1, vec_f32(?2))",
        params![rowid, vector_json(embedding)],
    )
    .context("inserting sqlite-vec knowledge vector")?;
    Ok(())
}

fn ensure_vec_table(conn: &Connection, dimensions: usize) -> Result<()> {
    let stored = stored_embedding_dimensions(conn)?;
    if stored == Some(dimensions) && table_exists(conn, "vec_chunks")? {
        return Ok(());
    }
    if stored.is_some_and(|stored| stored != dimensions) {
        clear_index(conn)?;
    }
    conn.execute_batch("DROP TABLE IF EXISTS vec_chunks;")?;
    conn.execute(
        &format!("CREATE VIRTUAL TABLE vec_chunks USING vec0(embedding float[{dimensions}])"),
        [],
    )?;
    conn.execute(
        "INSERT INTO intel_meta(key, value) VALUES('embedding_dimensions', ?1)
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
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn rel_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn vector_json(vector: &[f32]) -> String {
    serde_json::to_string(vector).unwrap_or_else(|_| "[]".to_string())
}

fn vector_search(conn: &Connection, vector: &[f32], limit: usize) -> Result<Vec<i64>> {
    if !table_exists(conn, "vec_chunks")? {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT rowid FROM vec_chunks
         WHERE embedding MATCH vec_f32(?1) AND k = ?2
         ORDER BY distance",
    )?;
    let rows = stmt.query_map(params![vector_json(vector), limit as i64], |row| {
        row.get::<_, i64>(0)
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
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
    let mut seen_attachment_ids = BTreeSet::new();
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
    for RegistryKnowledgeBase { mut entry, local } in registry {
        if !seen.insert(entry.id.clone()) {
            bail!(
                "knowledge base registry contains duplicate ID `{}`",
                entry.id
            );
        }
        let local = local.map(|local| {
            let root = if local.root.is_absolute() {
                local.root
            } else {
                cwd.join(local.root)
            };
            let sidecar_path = local
                .sidecar_path
                .unwrap_or_else(|| root.join(SIDE_CAR_FILE));
            RegistryLocalKb {
                root,
                assistant_snapshot_root: local.assistant_snapshot_root,
                sidecar_path: Some(sidecar_path),
            }
        });
        // Relative local paths are interpreted against this invocation's
        // workspace root. Bind the ledger key to that resolved source, not the
        // spelling in config, so the identity always matches the provider's
        // concrete root.
        if let Some(local) = &local {
            entry.source = KnowledgeBaseSource::Local {
                path: local.root.clone(),
            };
        }
        validate_registry_entry(&entry)?;
        let attachment_id = entry.attachment_id();
        if !seen_attachment_ids.insert(attachment_id) {
            bail!(
                "knowledge base registry contains duplicate attachment ID `{}`",
                attachment_id
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
    sidecar_path: Option<PathBuf>,
}

fn workspace_knowledge_base(entry: KnowledgeBaseRegistryEntry) -> RegistryKnowledgeBase {
    let local = match &entry.source {
        KnowledgeBaseSource::Local { path } => Some(RegistryLocalKb {
            root: path.clone(),
            assistant_snapshot_root: None,
            sidecar_path: None,
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
    let entry = KnowledgeBaseRegistryEntry::new(
        format!("assistant-{}", config.installation_id),
        format!("Assistant: {name}"),
        format!("Knowledge installed with assistant `{name}`."),
        KnowledgeBaseSource::Local { path: root.clone() },
        KnowledgeBaseEmbeddingOwnership::Local,
        None,
        None,
        false,
        KnowledgeBaseMergePolicy::Auto,
    )
    .with_host_attachment_identity(config.installation_id);
    Ok(Some(RegistryKnowledgeBase {
        entry,
        local: Some(RegistryLocalKb {
            root,
            assistant_snapshot_root: Some(PathBuf::from(format!(
                "assistant://{}/knowledge",
                snapshot.row.name
            ))),
            sidecar_path: Some(cache_root.join(format!("{}.sqlite", config.installation_id))),
        }),
    }))
}

fn validate_registry_entry(entry: &KnowledgeBaseRegistryEntry) -> Result<()> {
    if entry.attachment_id().is_nil() {
        bail!("knowledge base attachment IDs must not be nil");
    }
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
            let sidecar_path = local
                .sidecar_path
                .context("local knowledge provider has no sidecar path")?;
            if let Some(snapshot_root) = local.assistant_snapshot_root {
                return LocalKb::assistant(entry, local.root, snapshot_root, sidecar_path).map(
                    |provider| provider.map(|provider| Arc::new(provider) as Arc<dyn KbProvider>),
                );
            }
            Ok(Some(Arc::new(LocalKb::new(
                entry,
                local.root,
                None,
                sidecar_path,
                None,
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

/// Read-only retrieval surface used by the built-in `knowledge` specialist.
///
/// KB results always flow through [`KbProvider`]. When dream has recorded a
/// watermark for every attached KB, the same call searches the bounded set of
/// sessions active after the oldest boundary. Before dream has recorded its
/// first boundary, it conservatively searches matching project sessions and
/// reports that no history can yet be proven dreamed. The DB search applies the
/// caller's history-trust filter before results reach the normal redaction
/// chokepoint.
pub(crate) struct KnowledgeRetrieveTool {
    allowed_knowledge_bases: Option<BTreeSet<String>>,
}

impl KnowledgeRetrieveTool {
    pub(crate) fn new(allowed_knowledge_bases: Option<BTreeSet<String>>) -> Self {
        Self {
            allowed_knowledge_bases,
        }
    }
}

#[async_trait]
impl Tool for KnowledgeRetrieveTool {
    fn name(&self) -> &str {
        KNOWLEDGE_RETRIEVE_TOOL_NAME
    }

    fn description(&self) -> &str {
        "retrieve cited knowledge-base results and bounded undreamed-session updates"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Search attached knowledge bases through their configured providers, then search sessions newer than the recorded dream watermark when every attached KB has one. Before the first watermark, conservatively search a bounded set of matching project sessions and say that no history can yet be proven dreamed. Returns concept-path and session references plus explicit freshness notes."
                .to_string(),
        )
    }

    fn effect(&self) -> crate::engine::tool::ToolEffect {
        crate::engine::tool::ToolEffect::ReadOnly
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "retrieval query" },
                "limit": { "type": "integer", "minimum": 1, "maximum": 20, "description": "maximum cited results from each source" }
            },
            "required": ["query"],
            "additionalProperties": false
        })
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: MemorySearchArgs = typed_args(args)?;
        if args.query.trim().is_empty() {
            return Err(invalid_input("knowledge_retrieve query must not be empty"));
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
                "No attached knowledge bundles are available; no fresh-session subset was searched.",
            ));
        }

        let limit = args.limit.unwrap_or(DEFAULT_SEARCH_LIMIT).clamp(1, 20);
        let results =
            match production_embedder(&extended, &ctx.config, ctx.redact.clone(), &ctx.session)
                .await?
            {
                Some(embedder) => {
                    retrieve_from_knowledge_bases(&bundles, embedder, &args.query, limit).await?
                }
                None => Vec::new(),
            };
        let freshness = retrieve_undreamed_session_hits(&bundles, &args.query, limit, ctx).await?;
        Ok(ToolOutput::text(render_knowledge_retrieval(
            &results,
            &freshness,
            ctx.redact.as_ref(),
        )))
    }
}

struct FreshSessionRetrieval {
    hits: Vec<crate::db::session_search::SearchHit>,
    watermark_knowledge_bases: Vec<String>,
    oldest_watermark_unix_ms: Option<i64>,
    missing_watermark_knowledge_bases: Vec<String>,
}

async fn retrieve_undreamed_session_hits(
    bundles: &[AttachedKnowledgeBase],
    query: &str,
    limit: usize,
    ctx: &ToolCtx,
) -> Result<FreshSessionRetrieval> {
    let project_uuid = ctx
        .session
        .db
        .authoritative_project_uuid(&ctx.session.project_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("authoritative project UUID is unavailable"))?;
    let mut watermark_knowledge_bases = Vec::new();
    let mut missing_watermark_knowledge_bases = Vec::new();
    let mut oldest_watermark_unix_ms = None;
    for bundle in bundles {
        match ctx
            .session
            .db
            .knowledge_dream_watermark(crate::db::knowledge_dreams::KnowledgeDreamLedgerKey {
                project_uuid,
                knowledge_base_attachment_id: bundle.entry.attachment_id(),
            })
            .await?
        {
            Some(watermark) => {
                watermark_knowledge_bases.push(bundle.entry.id.clone());
                oldest_watermark_unix_ms = Some(
                    oldest_watermark_unix_ms
                        .map(|oldest: i64| oldest.min(watermark.last_dreamed_at_unix_ms))
                        .unwrap_or(watermark.last_dreamed_at_unix_ms),
                );
            }
            None => missing_watermark_knowledge_bases.push(bundle.entry.id.clone()),
        }
    }

    // A missing watermark is not evidence that history has been dreamed. On
    // first use (and whenever any attached KB lacks a ledger row), search the
    // project's matching session history conservatively instead of silently
    // returning no fresh results. Once every attached KB has a boundary, the
    // oldest one safely bounds the shared candidate set.
    let (since, search_enabled) = if missing_watermark_knowledge_bases.is_empty() {
        match oldest_watermark_unix_ms {
            // `search_candidates_for_trust` is inclusive but dream's contract
            // is strictly after the watermark. `checked_add` makes the
            // representable upper boundary correctly yield no sessions.
            Some(watermark) => (watermark.checked_add(1), watermark != i64::MAX),
            None => (None, false),
        }
    } else {
        (None, true)
    };
    let hits = if search_enabled {
        let pool = limit.saturating_mul(3).clamp(limit, 60) as u32;
        ctx.session
            .db
            .search_candidates_for_trust(
                query,
                Some(ctx.session.project_id.as_str()),
                None,
                since,
                pool,
                crate::tools::session_search::caller_history_trust(ctx),
            )
            .await?
            .into_iter()
            .take(limit)
            .collect()
    } else {
        Vec::new()
    };
    Ok(FreshSessionRetrieval {
        hits,
        watermark_knowledge_bases,
        oldest_watermark_unix_ms,
        missing_watermark_knowledge_bases,
    })
}

fn render_knowledge_retrieval(
    results: &[SearchResult],
    freshness: &FreshSessionRetrieval,
    redact: &RedactionTable,
) -> String {
    let mut out = String::from("knowledge_retrieve results:\n");
    if results.is_empty() {
        out.push_str(
            "- No matching knowledge-base entries (or no embedding model is configured).\n",
        );
    } else {
        out.push_str("Knowledge-base citations:\n");
        for result in results {
            out.push_str("- ");
            out.push_str(&result.concept_id);
            out.push_str(" — ");
            out.push_str(&short_summary(&result.snippet));
            out.push_str(" [");
            out.push_str(&citation_label(result));
            out.push_str("]\n");
        }
    }

    if !freshness.missing_watermark_knowledge_bases.is_empty() {
        out.push_str(
            "Fresh-session staleness check: no dream watermark is recorded for every attached KB, so a bounded set of matching sessions from this project was searched conservatively; no session history can yet be proven dreamed into those KBs.\n",
        );
        render_fresh_session_hits(&mut out, &freshness.hits);
    } else {
        match freshness.oldest_watermark_unix_ms {
            Some(watermark) => {
                out.push_str(
                    "Fresh-session staleness check: searched this project's sessions active after ",
                );
                out.push_str(&watermark.to_string());
                out.push_str(" for KB(s) ");
                out.push_str(&freshness.watermark_knowledge_bases.join(", "));
                out.push_str(". These sessions may not yet be dreamed into those KBs.\n");
                render_fresh_session_hits(&mut out, &freshness.hits);
            }
            None => out.push_str(
                "Fresh-session staleness check: no eligible fresh-session boundary is available.\n",
            ),
        }
    }
    if !freshness.missing_watermark_knowledge_bases.is_empty() {
        out.push_str("KB(s) without a dream watermark: ");
        out.push_str(&freshness.missing_watermark_knowledge_bases.join(", "));
        out.push_str(".\n");
    }
    redact.scrub(&out)
}

fn render_fresh_session_hits(out: &mut String, hits: &[crate::db::session_search::SearchHit]) {
    if hits.is_empty() {
        out.push_str("- No matching undreamed-session updates.\n");
    } else {
        out.push_str("Undreamed-session citations:\n");
        for hit in hits {
            let fallback_reference = hit.session_id.to_string();
            let reference = hit.short_id.as_deref().unwrap_or(&fallback_reference);
            out.push_str("- session ");
            out.push_str(reference);
            out.push_str(" — ");
            out.push_str(hit.title.as_deref().unwrap_or("(untitled)"));
            out.push_str(" — ");
            out.push_str(&short_summary(&hit.snippet));
            out.push_str(" [session ref: ");
            out.push_str(&hit.session_id.to_string());
            out.push_str("]\n");
        }
    }
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
    use tempfile::TempDir;

    struct MockEmbedder;
    struct DimEmbedder(usize);

    #[async_trait]
    impl Embedder for MockEmbedder {
        async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
            Ok(texts.iter().map(|text| mock_vector(text)).collect())
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

    #[test]
    fn composite_retrieval_renders_kb_and_undreamed_session_citations() {
        let results = vec![SearchResult {
            knowledge_base_id: "project".to_string(),
            knowledge_base_name: "Project knowledge".to_string(),
            concept_id: "deploy-policy".to_string(),
            source_path: "concepts/deploy.md".to_string(),
            chunk_index: 0,
            snippet: "Deploy through the green lane.".to_string(),
            citations: Vec::new(),
            score: 1.0,
        }];
        let session_id = uuid::Uuid::new_v4();
        let freshness = FreshSessionRetrieval {
            hits: vec![crate::db::session_search::SearchHit {
                session_id,
                short_id: Some("ab12cd".to_string()),
                title: Some("Recent deploy discussion".to_string()),
                last_active_at_unix_ms: 101,
                snippet: "The rollout is waiting for approval.".to_string(),
                bm25: -1.0,
            }],
            watermark_knowledge_bases: vec!["project".to_string()],
            oldest_watermark_unix_ms: Some(100),
            missing_watermark_knowledge_bases: Vec::new(),
        };

        let rendered = render_knowledge_retrieval(&results, &freshness, &RedactionTable::empty());
        assert!(rendered.contains("concepts/deploy.md#chunk-0"));
        assert!(rendered.contains("session ab12cd"));
        assert!(rendered.contains(&session_id.to_string()));
        assert!(rendered.contains("may not yet be dreamed"));
    }

    #[tokio::test]
    async fn fresh_retrieval_includes_the_current_session_before_the_first_watermark() {
        let tmp = TempDir::new().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.session
            .db
            .insert_session_event(
                ctx.session.id,
                crate::db::session_log::SessionEventKind::UserMessage,
                None,
                None,
                &json!({ "text": "current session has the windfall launch decision" }),
            )
            .await
            .unwrap();
        let entry = project_knowledge_registry_entry();
        let bundles = vec![AttachedKnowledgeBase {
            provider: Arc::new(RemoteKb {
                entry: entry.clone(),
            }),
            entry,
        }];

        let freshness = retrieve_undreamed_session_hits(&bundles, "windfall", 6, &ctx)
            .await
            .unwrap();

        assert_eq!(
            freshness.missing_watermark_knowledge_bases,
            vec!["project".to_string()]
        );
        assert!(
            freshness
                .hits
                .iter()
                .any(|hit| hit.session_id == ctx.session.id)
        );
    }

    #[tokio::test]
    async fn replacement_kb_source_does_not_reuse_the_previous_dream_watermark() {
        let tmp = TempDir::new().unwrap();
        let session = test_session(tmp.path()).await;
        let original = project_knowledge_registry_entry();
        let mut replacement = original.clone();
        replacement.source = KnowledgeBaseSource::Local {
            path: PathBuf::from(".cockpit/replacement-knowledge"),
        };
        let project_uuid = session
            .db
            .authoritative_project_uuid(&session.project_id)
            .await
            .unwrap()
            .unwrap();
        let original_key = crate::db::knowledge_dreams::KnowledgeDreamLedgerKey {
            project_uuid,
            knowledge_base_attachment_id: original.attachment_id(),
        };
        let replacement_key = crate::db::knowledge_dreams::KnowledgeDreamLedgerKey {
            project_uuid,
            knowledge_base_attachment_id: replacement.attachment_id(),
        };

        assert_ne!(
            original_key.knowledge_base_attachment_id,
            replacement_key.knowledge_base_attachment_id
        );
        session
            .db
            .record_knowledge_dream_watermark(original_key, 100, 110)
            .await
            .unwrap();
        assert!(
            session
                .db
                .knowledge_dream_watermark(replacement_key)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn fresh_retrieval_reports_its_conservative_first_use_search() {
        let freshness = FreshSessionRetrieval {
            hits: Vec::new(),
            watermark_knowledge_bases: Vec::new(),
            oldest_watermark_unix_ms: None,
            missing_watermark_knowledge_bases: vec!["project".to_string()],
        };

        let rendered = render_knowledge_retrieval(&[], &freshness, &RedactionTable::empty());
        assert!(rendered.contains("searched conservatively"));
        assert!(rendered.contains("no session history can yet be proven dreamed"));
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

    #[tokio::test]
    async fn index_rebuilds_from_bundle() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let (index, _) = KnowledgeIndex::open(tmp.path(), mock_embedder())
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
        fs::remove_file(tmp.path().join(SIDE_CAR_FILE)).unwrap();
        let (rebuilt, _) = KnowledgeIndex::open(tmp.path(), mock_embedder())
            .await
            .unwrap();
        let second = rebuilt
            .search_with_vector(&query_vector, "release shipping procedure", 3)
            .unwrap();
        assert_eq!(ids(&first), ids(&second));
    }

    #[tokio::test]
    async fn index_version_bump_reindexes() {
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
        assert!(stats.embedded_chunks >= 2, "{stats:?}");
        assert_eq!(stats.reused_files, 0);
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
    async fn index_dimension_change_reindexes_all_hash_reused_files() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let (_, first) = KnowledgeIndex::open(tmp.path(), Arc::new(DimEmbedder(3)))
            .await
            .unwrap();
        assert!(first.embedded_chunks >= 2);

        let (index, second) = KnowledgeIndex::open(tmp.path(), Arc::new(DimEmbedder(4)))
            .await
            .unwrap();
        assert_eq!(second.reused_files, 0);
        assert!(second.indexed_files >= 2);
        assert!(second.embedded_chunks >= 2);
        let query = DimEmbedder(4).embed(&["deploy"]).await.unwrap().remove(0);
        let results = index.search_with_vector(&query, "deploy", 2).unwrap();
        assert!(results.iter().any(|result| result.concept_id == "deploy"));
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
            &index.conn,
            vector_search(&index.conn, &exact_vector, 1).unwrap(),
            vec![],
            1,
        )
        .unwrap();
        let keyword_only_exact = rrf_merge(
            &index.conn,
            vec![],
            keyword_search(&index.conn, "E_CONNRESET-7749", 1).unwrap(),
            1,
        )
        .unwrap();
        let vector_only_paraphrase = rrf_merge(
            &index.conn,
            vector_search(&index.conn, &paraphrase_vector, 1).unwrap(),
            vec![],
            1,
        )
        .unwrap();
        let keyword_only_paraphrase = rrf_merge(
            &index.conn,
            vec![],
            keyword_search(&index.conn, "ship launch safely", 1).unwrap(),
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
        let available = KnowledgeBaseRegistryEntry::new(
            "available".to_string(),
            "Available".to_string(),
            "Available local knowledge".to_string(),
            KnowledgeBaseSource::Local {
                path: PathBuf::from("available"),
            },
            KnowledgeBaseEmbeddingOwnership::Local,
            None,
            None,
            false,
            KnowledgeBaseMergePolicy::Auto,
        );
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
        let available = KnowledgeBaseRegistryEntry::new(
            "available".to_string(),
            "Available".to_string(),
            "Available local knowledge".to_string(),
            KnowledgeBaseSource::Local {
                path: PathBuf::from("available"),
            },
            KnowledgeBaseEmbeddingOwnership::Local,
            None,
            None,
            false,
            KnowledgeBaseMergePolicy::Auto,
        );
        let remote = KnowledgeBaseRegistryEntry::new(
            "hosted".to_string(),
            "Hosted".to_string(),
            "Deferred hosted knowledge".to_string(),
            KnowledgeBaseSource::Remote {
                url: "https://knowledge.example.test".to_string(),
            },
            KnowledgeBaseEmbeddingOwnership::RemoteOwned,
            None,
            None,
            false,
            KnowledgeBaseMergePolicy::Auto,
        );
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
        KnowledgeBaseRegistryEntry::new(
            "project".to_string(),
            "Project".to_string(),
            "Workspace project knowledge".to_string(),
            KnowledgeBaseSource::Local {
                path: PathBuf::from(".cockpit/knowledge"),
            },
            KnowledgeBaseEmbeddingOwnership::Local,
            None,
            None,
            true,
            crate::config::extended::KnowledgeBaseMergePolicy::Auto,
        )
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
