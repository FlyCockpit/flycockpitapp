//! OKF v0.1 knowledge bundles and disposable per-bundle retrieval indexes.
//!
//! Cockpit treats the markdown bundle as the source of truth. The SQLite file
//! inside each bundle is a derived cache: delete it and it rebuilds from the
//! markdown. The cache is intentionally per-bundle so embeddings and vector
//! tables never enter the main `cockpit.db`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::c_char;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::extended::ExtendedConfig;
#[cfg(test)]
use crate::config::extended::RedactConfig;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachedBundle {
    pub scope: BundleScope,
    pub root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BundleScope {
    Assistant,
    Project,
}

#[derive(Debug, Clone)]
struct ChunkDoc {
    concept_id: String,
    source_path: String,
    chunk_index: usize,
    body: String,
    citations: Vec<Citation>,
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
    let mut index_md = None;
    let mut log_md = None;
    let mut concepts = Vec::new();

    for path in markdown_files(&root)? {
        let rel = path.strip_prefix(&root).unwrap_or(&path).to_path_buf();
        let body = fs::read_to_string(&path)
            .with_context(|| format!("reading knowledge file {}", path.display()))?;
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

    concepts.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(KnowledgeBundle {
        root,
        index_md,
        log_md,
        concepts,
    })
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

fn markdown_files(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    collect_markdown_files(root, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_markdown_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_markdown_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "md") {
            out.push(path);
        }
    }
    Ok(())
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

fn sidecar_vec_table_exists(root: &Path) -> Result<bool> {
    if !root.join(SIDE_CAR_FILE).exists() {
        return Ok(false);
    }
    let conn = open_sidecar_connection(root)?;
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
        fs::create_dir_all(&root)
            .with_context(|| format!("creating knowledge bundle {}", root.display()))?;
        let bundle = parse_bundle(&root)?;
        let conn = open_sidecar_connection(&root)?;
        ensure_schema(&conn)?;
        let mut plan = plan_reindex(&conn, &bundle)?;
        drop(conn);
        if !bundle.concepts.is_empty() {
            let current_dimensions = embedding_dimensions_probe(embedder.as_ref()).await?;
            let dimensions_changed = plan
                .stored_dimensions
                .is_some_and(|stored| stored != current_dimensions);
            let dimensions_missing_for_existing_table =
                plan.stored_dimensions.is_none() && sidecar_vec_table_exists(&root)?;
            if dimensions_changed || dimensions_missing_for_existing_table {
                plan.concepts = bundle.concepts.clone();
                plan.stats.reused_files = 0;
                plan.stats.indexed_files = plan.concepts.len();
                plan.force_clear_before_apply = true;
            }
        }
        let (embedded, embedded_chunks) =
            embed_planned_concepts(&plan.concepts, embedder.as_ref()).await?;
        let conn = open_sidecar_connection(&root)?;
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

fn open_sidecar_connection(root: &Path) -> Result<Connection> {
    let conn = Connection::open(root.join(SIDE_CAR_FILE))
        .with_context(|| format!("opening knowledge sidecar in {}", root.display()))?;
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
    result
        .citations
        .first()
        .map(|citation| format!("{}: {}", citation.label, citation.target))
        .unwrap_or_else(|| format!("{}#chunk-{}", result.source_path, result.chunk_index))
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
    config: &crate::daemon::session_worker::SessionConfigHandle,
    query: &str,
    redact: Arc<RedactionTable>,
) {
    let extended = config.extended();
    let bundles = attached_bundles(session, cwd, &extended);
    if bundles.is_empty() {
        return;
    }
    match production_embedder(&extended, config, redact.clone()).await {
        Ok(Some(embedder)) => {
            match search_bundles(&bundles, embedder, query, DEFAULT_SEARCH_LIMIT).await {
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
    let embedder = OpenAiCompatEmbedder::for_resolved_model(
        &providers,
        &resolved,
        redact,
        Arc::new(AtomicBool::new(extended.trusted_only)),
    )
    .await?;
    Ok(Some(Arc::new(embedder)))
}

async fn search_bundles(
    bundles: &[AttachedBundle],
    embedder: Arc<dyn Embedder>,
    query: &str,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    let query_vector = embedder
        .embed(&[query])
        .await
        .context("embedding knowledge search query")?
        .into_iter()
        .next()
        .context("embedding query returned no vector")?;
    let mut all = Vec::new();
    for bundle in bundles {
        let (index, _) = KnowledgeIndex::open(&bundle.root, embedder.clone()).await?;
        all.extend(index.search_with_vector(&query_vector, query, limit)?);
    }
    all.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    all.truncate(limit);
    Ok(all)
}

pub(crate) fn attached_bundles_available(
    session: &Session,
    cwd: &Path,
    config: &crate::daemon::session_worker::SessionConfigHandle,
) -> bool {
    let extended = config.extended();
    !attached_bundles(session, cwd, &extended).is_empty()
}

pub(crate) fn attached_bundles(
    session: &Session,
    cwd: &Path,
    extended: &ExtendedConfig,
) -> Vec<AttachedBundle> {
    let mut bundles = Vec::new();
    if let Some(name) = &session.assistant_name
        && let Ok(Some(row)) = session.db.get_assistant(name)
    {
        let root = Path::new(&row.home_dir).join("knowledge");
        if root.exists() {
            bundles.push(AttachedBundle {
                scope: BundleScope::Assistant,
                root,
            });
        }
    }

    let project_root = cwd.join(".cockpit").join("knowledge");
    if extended.project_knowledge && project_bundle_trusted() && project_root.exists() {
        bundles.push(AttachedBundle {
            scope: BundleScope::Project,
            root: project_root,
        });
    }
    bundles
}

fn project_bundle_trusted() -> bool {
    crate::config::trust::runtime_policy()
        .is_some_and(|policy| policy.mode == WorkspaceTrustMode::Trust)
}

pub(crate) fn with_memory_search_if_attached(
    toolbox: crate::engine::tool::ToolBox,
    session: &Session,
    cwd: &Path,
    config: &crate::daemon::session_worker::SessionConfigHandle,
) -> crate::engine::tool::ToolBox {
    if attached_bundles_available(session, cwd, config) {
        toolbox.with(Arc::new(MemorySearchTool))
    } else {
        toolbox.without("memory_search")
    }
}

pub(crate) struct MemorySearchTool;

#[derive(Debug, Deserialize)]
struct MemorySearchArgs {
    query: String,
    #[serde(default)]
    limit: Option<usize>,
}

#[async_trait]
impl Tool for MemorySearchTool {
    fn name(&self) -> &str {
        "memory_search"
    }

    fn description(&self) -> &str {
        "search attached OKF memory bundles with citations"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Search assistant/project OKF memory for a specific query and return cited ranked results."
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
        let bundles = attached_bundles(&ctx.session, &ctx.cwd, &extended);
        if bundles.is_empty() {
            return Ok(ToolOutput::text(
                "No attached knowledge bundles are available.",
            ));
        }
        let Some(embedder) =
            production_embedder(&extended, &ctx.config, ctx.redact.clone()).await?
        else {
            return Ok(ToolOutput::text(
                "No embedding_model is configured, so memory_search cannot build the knowledge index.",
            ));
        };
        let limit = args.limit.unwrap_or(DEFAULT_SEARCH_LIMIT).clamp(1, 20);
        let results = search_bundles(&bundles, embedder, &args.query, limit).await?;
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

    #[test]
    fn project_bundle_trust_gated() {
        let _env = crate::test_env::lock();
        crate::config::trust::clear_runtime_policy_for_tests();
        let tmp = TempDir::new().unwrap();
        let project_bundle = tmp.path().join(".cockpit/knowledge");
        write_bundle(&project_bundle);
        let session = test_session(tmp.path());
        let extended = ExtendedConfig {
            project_knowledge: true,
            ..Default::default()
        };

        assert!(attached_bundles(&session, tmp.path(), &extended).is_empty());
        crate::config::trust::set_runtime_policy(
            trust_root(tmp.path()),
            WorkspaceTrustMode::Untrusted,
        );
        assert!(attached_bundles(&session, tmp.path(), &extended).is_empty());
        crate::config::trust::set_runtime_policy(trust_root(tmp.path()), WorkspaceTrustMode::Trust);
        assert_eq!(attached_bundles(&session, tmp.path(), &extended).len(), 1);
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn memory_search_tool_gated() {
        let _env = crate::test_env::lock();
        crate::config::trust::clear_runtime_policy_for_tests();
        let tmp = TempDir::new().unwrap();
        let session = test_session(tmp.path());
        let base = crate::engine::tool::ToolBox::new();
        assert!(
            !with_memory_search_if_attached(
                base.clone(),
                &session,
                tmp.path(),
                &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(
                    tmp.path()
                )
            )
            .names()
            .contains(&"memory_search")
        );

        write_bundle(&tmp.path().join(".cockpit/knowledge"));
        fs::create_dir_all(tmp.path().join(".cockpit")).unwrap();
        fs::write(
            tmp.path().join(".cockpit/config.json"),
            r#"{"project_knowledge": true}"#,
        )
        .unwrap();
        crate::config::trust::set_runtime_policy(trust_root(tmp.path()), WorkspaceTrustMode::Trust);
        assert!(
            with_memory_search_if_attached(
                base,
                &session,
                tmp.path(),
                &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(
                    tmp.path()
                )
            )
            .names()
            .contains(&"memory_search")
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[tokio::test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db-async-intel-and-knowledge"
    )]
    async fn main_db_has_no_vectors() {
        let tmp = TempDir::new().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).unwrap();
        db.read_blocking(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE lower(name) LIKE '%vector%'
                    OR lower(name) LIKE '%embedding%'
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
        .unwrap();
    }

    fn ids(results: &[SearchResult]) -> Vec<String> {
        results.iter().map(|r| r.concept_id.clone()).collect()
    }

    #[allow(deprecated)]
    fn test_session(root: &Path) -> Session {
        let db = crate::db::Db::open(&root.join("cockpit.db")).unwrap();
        let project_root = root.to_str().unwrap().to_string();
        let row = db
            .write_blocking(move |conn| {
                let row = crate::db::Db::build_new_session_row_conn(
                    conn,
                    "project",
                    &project_root,
                    "test",
                )?;
                crate::db::Db::insert_session_row_conn(conn, &row)
            })
            .unwrap();
        Session::resume(db, row.session_id).unwrap().unwrap()
    }

    fn trust_root(root: &Path) -> crate::config::trust::TrustRoot {
        crate::config::trust::TrustRoot {
            opened_path: root.to_path_buf(),
            root: root.to_path_buf(),
            kind: crate::config::trust::TrustRootKind::Directory,
        }
    }
}
