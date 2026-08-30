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
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use rusqlite::{Connection, MAIN_DB, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use crate::config::extended::RedactConfig;
use crate::config::extended::{
    ExtendedConfig, KnowledgeBaseEmbeddingOwnership, KnowledgeBaseMergePolicy,
    KnowledgeBaseRegistryEntry, KnowledgeBaseSource,
};
use crate::db::workspace_trust::WorkspaceTrustMode;
use crate::embeddings::{Embedder, OpenAiCompatEmbedder};
use crate::engine::message::Message;
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input, typed_args};
use crate::redact::RedactionTable;
use crate::session::Session;

/// Immutable knowledge-base facts captured when a root definition is bound.
/// This renders into that root's cached system prefix; live dream completion
/// deliberately never rewrites it, and instead becomes a one-turn history
/// injection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct KnowledgeBasePromptSnapshot {
    entries: Vec<KnowledgeBasePromptSnapshotEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KnowledgeBasePromptSnapshotEntry {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) last_dreamed_at_unix_ms: Option<i64>,
    #[serde(default)]
    pub(crate) dream_completion_revision: i64,
}

impl KnowledgeBasePromptSnapshot {
    pub(crate) fn capture(
        config: &ExtendedConfig,
        conn: &rusqlite::Connection,
        project_root: &str,
        assistant_name: Option<&str>,
        allowed_knowledge_bases: Option<&BTreeSet<String>>,
        trust_mode: WorkspaceTrustMode,
    ) -> Result<Self> {
        let consumer = crate::db::installation_identity::ensure_installation_identity_conn(conn)?;
        let attached = prompt_snapshot_entries_from_registry(
            assistant_knowledge_registry_entry_for_session_start(conn, assistant_name)?,
            config,
            Path::new(project_root),
            allowed_knowledge_bases,
            trust_mode,
        )?;
        let entries = attached
            .into_iter()
            .map(|entry| {
                let completion = crate::db::knowledge_dreams::knowledge_dream_completion_conn(
                    conn,
                    &entry.id,
                    project_root,
                    consumer.as_hex(),
                )?;
                Ok(KnowledgeBasePromptSnapshotEntry {
                    id: entry.id.clone(),
                    name: entry.name,
                    description: entry.description,
                    last_dreamed_at_unix_ms: completion
                        .map(|completion| completion.completed_at_unix_ms),
                    dream_completion_revision: completion
                        .map_or(0, |completion| completion.revision),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { entries })
    }

    pub(crate) fn from_json_str(raw: &str) -> Self {
        if raw.trim().is_empty() {
            return Self::default();
        }
        match serde_json::from_str(raw) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(%error, "failed to decode knowledge-base prompt snapshot");
                Self::default()
            }
        }
    }

    pub(crate) fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub(crate) fn render_system_block(&self) -> String {
        if self.entries.is_empty() {
            return String::new();
        }

        let mut out = String::from("Knowledge bases (root-definition snapshot):\n");
        for entry in &self.entries {
            out.push_str("- ");
            out.push_str(&entry.name);
            out.push_str(" (id: ");
            out.push_str(&entry.id);
            out.push_str("): ");
            out.push_str(&entry.description);
            out.push('\n');
            out.push_str("  Last dreamed at: ");
            match entry.last_dreamed_at_unix_ms {
                Some(timestamp) => out.push_str(&format_dream_timestamp(timestamp)),
                None => out.push_str("never"),
            }
            out.push('\n');
        }
        out.push_str(
            "Newer information may live in sessions after these timestamps; search it through the retrieval subagent.\n",
        );
        out
    }

    pub(crate) fn entries(&self) -> &[KnowledgeBasePromptSnapshotEntry] {
        &self.entries
    }
}

pub(crate) fn format_dream_timestamp(timestamp_unix_ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(timestamp_unix_ms)
        .map(|timestamp| timestamp.to_rfc3339())
        .unwrap_or_else(|| format!("invalid unix-ms timestamp {timestamp_unix_ms}"))
}

pub(crate) mod dream;
pub use dream::build_dream_prompt;

/// Durable, paid projection of local KB chunks.  This database deliberately
/// contains no OKF metadata or FTS state, so rebuilding the other sidecar can
/// reuse its vectors without talking to an embedding provider.
pub(crate) const EMBEDDINGS_FILE: &str = "embeddings.sqlite";
/// Disposable local projection of a KB's OKF markdown and sibling resources.
pub(crate) const INDEX_FILE: &str = "index.sqlite";
/// Per-machine artifacts which must never enter a KB's Git history. Keeping
/// the complete list here makes a newly initialized KB safe before any dream
/// state service starts.
const KB_MACHINE_STATE_GITIGNORE: &[&str] = &[
    EMBEDDINGS_FILE,
    INDEX_FILE,
    "dreamed-ledger",
    "dreamed-ledger.sqlite",
    "dreamed-ledger/",
    "watermarks",
    "watermarks.sqlite",
    "watermarks/",
    "schedule-state",
    "schedule-state.sqlite",
    "schedule-state/",
    "sealed-material/",
];
pub(crate) const INDEX_LOGIC_VERSION: i64 = 2;
const CHUNK_TARGET_TOKENS: usize = 400;
const CHUNK_OVERLAP_TOKENS: usize = 80;
const DEFAULT_SEARCH_LIMIT: usize = 6;
const MEMORY_SEARCH_TOOL_NAME: &str = "memory_search";
const KNOWLEDGE_RETRIEVE_TOOL_NAME: &str = "knowledge_retrieve";
const KNOWLEDGE_DREAM_SOURCES_TOOL_NAME: &str = "knowledge_dream_sources";
const KNOWLEDGE_DREAM_APPLY_TOOL_NAME: &str = "knowledge_dream_apply";
const MAX_KNOWLEDGE_FILES: usize = 4096;
const MAX_KNOWLEDGE_ENTRIES: usize = 8192;
const MAX_KNOWLEDGE_DEPTH: usize = 32;
const MAX_KNOWLEDGE_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_KNOWLEDGE_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// A non-secret, host-authenticated generation marker for local KB sealed
/// values. The marker is ignored by git and carries a host-keyed binding to
/// the concrete source directory and marker file objects. A copied marker is
/// therefore not a capability: only the daemon that owns the vault key can
/// validate it for its original source object.
const SEALED_KNOWLEDGE_BASE_ID_FILE: &str = ".flycockpit-sealed-kb-id";
const SEALED_KNOWLEDGE_BASE_MARKER_VERSION: &str = "v1";
const SEALED_KNOWLEDGE_BASE_MARKER_BINDING_DOMAIN: &[u8] =
    b"flycockpit/knowledge-base-sealed-marker/v1";

#[cfg(test)]
pub(crate) fn runtime_attached_tool_names() -> &'static [&'static str] {
    &[
        MEMORY_SEARCH_TOOL_NAME,
        KNOWLEDGE_RETRIEVE_TOOL_NAME,
        KNOWLEDGE_DREAM_SOURCES_TOOL_NAME,
        KNOWLEDGE_DREAM_APPLY_TOOL_NAME,
    ]
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

impl KnowledgeConcept {
    /// Build a concept produced by the governed dream pipeline.  Provenance is
    /// represented in the stable OKF frontmatter rather than as a parallel
    /// in-memory field, so parsed and newly-created concepts have one source
    /// of truth.
    pub(crate) fn dream(
        id: String,
        concept_type: String,
        title: Option<String>,
        body: String,
        citations: Vec<Citation>,
    ) -> Self {
        let mut frontmatter = BTreeMap::new();
        frontmatter.insert("id".to_owned(), id.clone());
        frontmatter.insert("provenance".to_owned(), "dream".to_owned());
        if let Some(title) = title {
            frontmatter.insert("title".to_owned(), title);
        }
        Self {
            path: PathBuf::from(format!("{id}.md")),
            id,
            concept_type,
            frontmatter,
            body,
            citations,
            valid_from: None,
            supersedes: Vec::new(),
            invalidated_by: None,
        }
    }

    /// Return the source-of-truth OKF provenance marker, when supplied.
    pub(crate) fn provenance(&self) -> Option<&str> {
        self.frontmatter.get("provenance").map(String::as_str)
    }

    /// Resolve this concept's KB-scoped symbolic references at read time.
    /// Markdown serialization never calls this method, so the source tree and
    /// git only ever receive the symbolic token.
    pub(crate) async fn body_for_reader(
        &self,
        kb_id: &crate::sealed::SealedKnowledgeBaseId,
        resolver: &dyn crate::sealed::SealedResolver,
        trusted_reader: bool,
    ) -> Result<String> {
        crate::sealed::resolve_kb_markdown(&self.body, kb_id, resolver, trusted_reader).await
    }
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
    sealed_id: crate::sealed::SealedKnowledgeBaseId,
}

/// The KBs a concrete model may access, plus local KB IDs withheld by the
/// trusted-model policy. Keeping the denial separate from an empty registry
/// lets tool callers report access denial without ever resolving a provider
/// or reading a restricted source.
pub(crate) struct AttachedKnowledgeBases {
    bundles: Vec<AttachedKnowledgeBase>,
    denied_knowledge_base_ids: Vec<String>,
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
    /// Apply model-produced OKF output through the provider that owns the KB.
    /// Dream execution must use this rather than resolving a local root itself,
    /// so local Git transactions and future hosted writes stay interchangeable.
    fn apply_dream(
        &self,
        dream: &KnowledgeDreamCommit,
        mutation: &dyn KnowledgeDreamMutation,
        cancel: &CancellationToken,
    ) -> Result<KnowledgeDreamGitOutcome>;
    fn with_embedder(&self, embedder: Arc<dyn Embedder>) -> Arc<dyn KbProvider>;
}

/// The model-facing dream executor supplies the OKF mutation after it has
/// selected and validated its output. It receives only the provider's
/// transaction root, never a separately resolved KB pathname.
pub(crate) trait KnowledgeDreamMutation: Send + Sync {
    fn apply(&self, root: &Path) -> Result<()>;
}

struct ClosureKnowledgeDreamMutation<F>(F);

impl<F> KnowledgeDreamMutation for ClosureKnowledgeDreamMutation<F>
where
    F: Fn(&Path) -> Result<()> + Send + Sync,
{
    fn apply(&self, root: &Path) -> Result<()> {
        (self.0)(root)
    }
}

#[derive(Clone)]
struct LocalKb {
    entry: KnowledgeBaseRegistryEntry,
    root: PathBuf,
    snapshot: Option<KnowledgeBundle>,
    sidecars: KbSidecars,
    embedder: Option<Arc<dyn Embedder>>,
    immutable_snapshot: bool,
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

    /// Resolve the already-existing parent directories before using sidecar
    /// paths as an identity. Registry entries may spell one KB through a
    /// symlink or a lexical alias; the sidecar filenames themselves are not
    /// allowed to be symlinks and are checked separately when opened.
    fn canonicalized(&self) -> Result<Self> {
        fn canonical_sidecar(path: &Path) -> Result<PathBuf> {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .context("knowledge sidecar has no parent directory")?;
            let name = path
                .file_name()
                .context("knowledge sidecar has no file name")?;
            Ok(fs::canonicalize(parent)
                .with_context(|| {
                    format!(
                        "canonicalizing knowledge sidecar parent {}",
                        parent.display()
                    )
                })?
                .join(name))
        }

        Ok(Self {
            embeddings: canonical_sidecar(&self.embeddings)?,
            index: canonical_sidecar(&self.index)?,
        })
    }

    fn root(&self) -> &Path {
        self.embeddings
            .parent()
            .expect("knowledge sidecar path always has its KB root as a parent")
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

/// Process-wide ownership of a KB while a provider call is in flight.
///
/// This fence is deliberately independent of either SQLite sidecar *and* the
/// replaceable KB directory. Generated files and the entire KB root may be
/// replaced while an embedding request is in flight. The Unix fence is a
/// stable, private lock outside the KB, keyed by its canonical pathname; the
/// retained directory descriptor separately anchors every sidecar read and
/// publish to the root that was present when ownership began. On Windows a
/// no-delete lease additionally keeps that root and its ancestors from being
/// replaced while path-based sidecar operations are in flight. Windows also
/// uses a named kernel mutex derived from the canonical pathname.
struct SidecarProcessLock {
    directory: fs::File,
    root: PathBuf,
    root_identity: String,
    #[cfg(unix)]
    fence: fs::File,
    #[cfg(windows)]
    _directory_lease: cockpit_host::private_fs::held_directory::WindowsWorkspaceExecutionLease,
    #[cfg(windows)]
    mutex: std::os::windows::io::OwnedHandle,
}

impl SidecarProcessLock {
    #[cfg(unix)]
    fn try_acquire(sidecars: &KbSidecars) -> Result<Option<Self>> {
        let authority = cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(sidecars.root())
            .with_context(|| {
                format!(
                    "retaining knowledge base directory for process lock {}",
                    sidecars.root().display()
                )
            })?;
        let root_identity = authority.identity().to_string();
        let directory = authority
            .retained_directory_handle()
            .context("cloning retained knowledge base directory")?;
        let lock_dir =
            cockpit_config::config::resolve::cockpit_state_dir()?.join("knowledge-sidecar-locks");
        cockpit_host::private_fs::ensure_private_dir(&lock_dir)
            .map_err(anyhow::Error::from)
            .context("preparing private knowledge sidecar lock directory")?;
        let identity = sidecars.root().as_os_str().as_encoded_bytes();
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(identity);
        let leaf = format!(
            "{}.lock",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let fence = cockpit_host::private_fs::open_private_file_at(
            &lock_dir,
            std::ffi::OsStr::new(&leaf),
            cockpit_host::private_fs::PrivateFileAccess::ReadWrite,
            "knowledge sidecar process lock",
        )
        .map_err(anyhow::Error::from)
        .context("opening stable knowledge sidecar process lock")?;
        match try_lock_sidecar_fence(&fence)? {
            true => Ok(Some(Self {
                directory,
                root: sidecars.root().to_path_buf(),
                root_identity,
                fence,
            })),
            false => Ok(None),
        }
    }

    #[cfg(windows)]
    fn try_acquire(sidecars: &KbSidecars) -> Result<Option<Self>> {
        use sha2::{Digest as _, Sha256};
        use std::ffi::OsStr;
        use std::os::windows::{
            ffi::OsStrExt as _,
            io::{AsRawHandle as _, FromRawHandle as _},
        };
        use std::ptr;
        use windows_sys::Win32::Foundation::{FALSE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};

        let identity: Vec<u8> = sidecars
            .root()
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect();
        let name = format!(
            "Global\\FlycockpitKnowledgeSidecar-{:x}",
            Sha256::digest(identity)
        );
        let name: Vec<u16> = OsStr::new(&name).encode_wide().chain(Some(0)).collect();
        // SAFETY: the name is NUL-terminated and the returned handle is owned
        // by this process once wrapped below.
        let handle = unsafe { CreateMutexW(ptr::null(), FALSE, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error()).context("creating knowledge sidecar mutex");
        }
        // SAFETY: CreateMutexW returned a valid owned handle above.
        let mutex = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle as _) };
        // SAFETY: mutex is a valid mutex handle. A zero timeout makes this
        // acquisition polling-compatible without blocking the Tokio runtime.
        match unsafe { WaitForSingleObject(mutex.as_raw_handle() as _, 0) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => {
                // A named mutex serializes callers by stable KB spelling, but
                // does not itself retain the directory object. Take the
                // retained authority and its no-delete lease only after the
                // mutex is owned, so the snapshot and every later path-based
                // sidecar operation refer to one unreplaceable root identity.
                let authority = cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(sidecars.root())
                    .with_context(|| {
                        format!(
                            "retaining knowledge base directory for process lock {}",
                            sidecars.root().display()
                        )
                    })?;
                let directory_lease = authority
                    .acquire_windows_execution_lease(sidecars.root())
                    .with_context(|| {
                        format!(
                            "leasing knowledge base directory for process lock {}",
                            sidecars.root().display()
                        )
                    })?;
                let directory = authority
                    .retained_directory_handle()
                    .context("cloning retained knowledge base directory")?;
                Ok(Some(Self {
                    directory,
                    root: sidecars.root().to_path_buf(),
                    root_identity: authority.identity().to_string(),
                    _directory_lease: directory_lease,
                    mutex,
                }))
            }
            WAIT_TIMEOUT => Ok(None),
            result => Err(io::Error::last_os_error()).with_context(|| {
                format!("waiting for knowledge sidecar mutex failed with result {result}")
            }),
        }
    }
}

impl SidecarProcessLock {
    /// Return the root capability selected while the process fence was
    /// acquired. Source snapshots and generated sidecars must use this exact
    /// directory rather than reopen its diagnostic path spelling.
    fn directory(&self) -> &fs::File {
        &self.directory
    }

    fn revalidate_root(&self) -> Result<()> {
        let current = cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(&self.root)
            .with_context(|| {
                format!(
                    "reopening knowledge base root selected by process lock {}",
                    self.root.display()
                )
            })?;
        if current.identity() != self.root_identity {
            bail!(
                "knowledge base root changed while its process lock was held; refusing to mutate a replacement"
            );
        }
        Ok(())
    }

    /// A mutation path bound to the retained directory object.
    ///
    /// Unix exposes open file descriptors as directories. Linux provides that
    /// view under `/proc/self/fd`; the other supported Unix targets, including
    /// macOS, provide it under `/dev/fd`. Every Git subprocess and dream
    /// writer uses this spelling, so a later rename or replacement of the
    /// diagnostic pathname cannot redirect the transaction to a new KB root.
    #[cfg(unix)]
    fn mutation_root(&self) -> PathBuf {
        use std::os::fd::AsRawFd as _;

        #[cfg(target_os = "linux")]
        let descriptor_directory = "/proc/self/fd";
        #[cfg(not(target_os = "linux"))]
        let descriptor_directory = "/dev/fd";
        PathBuf::from(format!(
            "{descriptor_directory}/{}",
            self.directory.as_raw_fd()
        ))
    }

    /// Windows keeps a no-delete lease while operations use the selected
    /// pathname. Unix always uses the descriptor-bound path above.
    #[cfg(windows)]
    fn mutation_root(&self) -> PathBuf {
        self.root.clone()
    }
}

impl Drop for SidecarProcessLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Err(error) = unlock_sidecar_fence(&self.fence) {
            tracing::warn!(%error, "releasing knowledge sidecar process lock failed");
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle as _;
            use windows_sys::Win32::System::Threading::ReleaseMutex;

            // SAFETY: this instance acquired the mutex in try_acquire and has
            // not released it yet. Closing the OwnedHandle follows this call.
            if unsafe { ReleaseMutex(self.mutex.as_raw_handle() as _) } == 0 {
                tracing::warn!(error = %io::Error::last_os_error(), "releasing knowledge sidecar process lock failed");
            }
        }
    }
}

async fn acquire_process_sidecar_lock(sidecars: &KbSidecars) -> Result<SidecarProcessLock> {
    loop {
        if let Some(lock) = SidecarProcessLock::try_acquire(sidecars)? {
            return Ok(lock);
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// Acquire the cross-process fence before reading source bytes. Returning both
/// values makes it impossible for callers to discard the directory capability
/// that selected the snapshot and later publish into a separately reopened KB
/// pathname.
async fn snapshot_bundle_with_sidecar_fence(
    sidecars: &KbSidecars,
) -> Result<(KnowledgeBundle, SidecarProcessLock)> {
    let process_lock = acquire_process_sidecar_lock(sidecars).await?;
    let bundle =
        parse_bundle_from_retained_root(sidecars.root().to_path_buf(), process_lock.directory())?;
    Ok((bundle, process_lock))
}

#[cfg(unix)]
fn try_lock_sidecar_fence(fence: &fs::File) -> Result<bool> {
    use std::os::fd::AsRawFd;

    // SAFETY: `fence` stays open for the lifetime of SidecarProcessLock.
    // flock is advisory, non-blocking, and operates on this valid descriptor.
    let rc = unsafe { libc::flock(fence.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.kind() {
        io::ErrorKind::WouldBlock => Ok(false),
        _ => Err(error).context("locking stable knowledge sidecar fence"),
    }
}

#[cfg(unix)]
fn unlock_sidecar_fence(fence: &fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    // SAFETY: this is the matching unlock for a lock acquired on `directory`.
    if unsafe { libc::flock(fence.as_raw_fd(), libc::LOCK_UN) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(unix, windows)))]
impl SidecarProcessLock {
    fn try_acquire(_sidecars: &KbSidecars) -> Result<Option<Self>> {
        bail!("knowledge sidecar process locking is unsupported on this platform")
    }
}

fn has_git_marker_in_ancestors(root: &Path) -> bool {
    let contains_git_marker = |path: &Path| {
        path.ancestors()
            .any(|ancestor| ancestor.join(".git").exists())
    };
    contains_git_marker(root)
        || fs::canonicalize(root).is_ok_and(|canonical_root| contains_git_marker(&canonical_root))
}

fn ensure_sidecars_gitignored(root: &Path, sidecars: &KbSidecars) -> Result<()> {
    // Sidecars were canonicalized for lock identity. Resolve the KB root the
    // same way before deciding which artifacts are inside a Git worktree.
    // Assistant snapshot roots are synthetic (`assistant://...`) and simply
    // remain outside their private cache sidecars.
    let sidecar_root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let sidecar_paths: Vec<_> = [&sidecars.embeddings, &sidecars.index]
        .into_iter()
        .filter_map(|path| path.strip_prefix(&sidecar_root).ok())
        .collect();
    // Assistant sidecars deliberately live in Flycockpit's private cache, not
    // in the installed assistant bundle. There is nothing in that source tree
    // to ignore in this case.
    if sidecar_paths.is_empty() {
        return Ok(());
    }
    let prefix = match crate::git::run_git(root, &["rev-parse", "--show-prefix"]) {
        Ok(output) if output.success => output.stdout,
        Ok(_) if !has_git_marker_in_ancestors(root) => return Ok(()),
        Ok(output) => bail!(
            "checking Git ignore rules for local knowledge base {} failed: {}",
            root.display(),
            output.stderr.trim()
        ),
        Err(_) if !has_git_marker_in_ancestors(root) => return Ok(()),
        Err(error) => return Err(error).context("running Git to protect knowledge sidecars"),
    };
    let exclude = crate::git::run_git(root, &["rev-parse", "--git-path", "info/exclude"])
        .context("locating local knowledge repository exclusion file")?;
    if !exclude.success {
        bail!(
            "locating Git exclusion file for local knowledge base {} failed: {}",
            root.display(),
            exclude.stderr.trim()
        );
    }
    let exclude_path = PathBuf::from(exclude.stdout.trim());
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
    for path in &sidecar_paths {
        rules.push('/');
        rules.push_str(&root_prefix);
        rules.push_str(&rel_string(path));
        rules.push('\n');
    }
    for path in KB_MACHINE_STATE_GITIGNORE {
        // The index and embeddings paths above can be relocated for assistant
        // snapshots, while these are always per-KB-root state names.  Keep
        // both forms: duplicate ignore patterns are harmless and make the
        // generated exclusion file self-contained for ordinary local KBs.
        rules.push('/');
        rules.push_str(&root_prefix);
        rules.push_str(path);
        rules.push('\n');
    }

    // Ignore rules do not apply retroactively to an index entry. Refuse before
    // SQLite can mutate a committed derived artifact; removing it from Git is
    // an explicit repository-owner action, never an implicit side effect.
    let mut protected_paths: Vec<String> =
        sidecar_paths.iter().map(|path| rel_string(path)).collect();
    protected_paths.extend(
        KB_MACHINE_STATE_GITIGNORE
            .iter()
            .map(|path| path.trim_end_matches('/').to_string()),
    );
    protected_paths.sort();
    protected_paths.dedup();
    for path in protected_paths {
        let repository_path = format!("{root_prefix}{path}");
        let repository_pathspec = format!(":(top){repository_path}");
        let tracked = crate::git::run_git(root, &["ls-files", "--", &repository_pathspec])
            .context("checking whether knowledge sidecar is tracked by Git")?;
        if !tracked.success {
            bail!(
                "checking whether knowledge sidecar {} is tracked by Git failed: {}",
                repository_path,
                tracked.stderr.trim()
            );
        }
        if !tracked.stdout.trim().is_empty() {
            bail!(
                "knowledge sidecar {} is tracked by Git; remove it from the repository before using this knowledge base",
                repository_path
            );
        }
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

/// Metadata for one durable dream projection. The dream executor supplies
/// this with its validated OKF mutation; this layer deliberately does not
/// know how a model produced those files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeDreamCommit {
    pub knowledge_base_id: String,
    pub model: String,
    pub sessions_dreamed: usize,
    pub concepts_written: usize,
    pub data_files_written: usize,
}

/// Git is an optional durability enhancement for a local KB.  A deferred
/// result never rolls back already-written OKF files: dream is re-runnable
/// from its durable ledger and the local repository retains any local commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnowledgeDreamGitOutcome {
    Skipped {
        reason: String,
    },
    NoChanges {
        branch: String,
    },
    Committed {
        commit: String,
        branch: String,
        pushed: bool,
    },
    Deferred {
        branch: Option<String>,
        commit: Option<String>,
        reason: String,
    },
}

enum PreparedKnowledgeGit {
    Active {
        branch: String,
        remote: Option<String>,
        restore_branch: Option<String>,
    },
    Skipped(String),
    Deferred(String),
}

/// Wait for the write fence without pinning an async executor worker.  The
/// caller supplies the turn/shutdown cancellation token, which is consulted
/// between non-blocking lock attempts.  Once the fence is acquired, the
/// transaction deliberately runs to its clean commit/defer boundary rather
/// than abandoning Git halfway through a mutation.
fn acquire_knowledge_write_process_lock_cancellable(
    root: &Path,
    cancel: &CancellationToken,
) -> Result<SidecarProcessLock> {
    let sidecars = KbSidecars::in_root(root).canonicalized()?;
    loop {
        if cancel.is_cancelled() {
            bail!("knowledge dream write cancelled while waiting for the knowledge base fence");
        }
        if let Some(lock) = SidecarProcessLock::try_acquire(&sidecars)? {
            return Ok(lock);
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

/// Apply a dream's OKF mutation inside the KB's Git transaction boundary.
///
/// Git is intentionally best-effort only when it is unavailable. A Git
/// repository that cannot be prepared safely defers *before* model output so
/// the ledger can rerun the dream against a clean worktree. We never
/// force-push.
pub(crate) fn apply_knowledge_dream<F>(
    root: &Path,
    merge_policy: KnowledgeBaseMergePolicy,
    dream: &KnowledgeDreamCommit,
    apply: F,
) -> Result<KnowledgeDreamGitOutcome>
where
    F: FnOnce(&Path) -> Result<()>,
{
    apply_knowledge_dream_cancellable(root, merge_policy, dream, &CancellationToken::new(), apply)
}

/// Blocking Git transaction used by the async provider boundary below and by
/// focused synchronous tests.  Cancellation is intentionally honored before
/// the callback is entered; after that point rollback/commit must complete so
/// a cancelled request never leaves a staged or rebasing repository behind.
fn apply_knowledge_dream_cancellable<F>(
    root: &Path,
    merge_policy: KnowledgeBaseMergePolicy,
    dream: &KnowledgeDreamCommit,
    cancel: &CancellationToken,
    apply: F,
) -> Result<KnowledgeDreamGitOutcome>
where
    F: FnOnce(&Path) -> Result<()>,
{
    fs::create_dir_all(root)
        .with_context(|| format!("creating local knowledge base {}", root.display()))?;
    // The model mutation itself is fenced, not just Git. Losing the private
    // process fence is a hard error because otherwise two daemons can write
    // the same OKF files concurrently.
    let process_lock = acquire_knowledge_write_process_lock_cancellable(root, cancel)?;
    process_lock.revalidate_root()?;
    let mutation_root = process_lock.mutation_root();
    let prepared = prepare_knowledge_git(&mutation_root, merge_policy, &dream.knowledge_base_id);

    if let PreparedKnowledgeGit::Deferred(reason) = &prepared {
        return Ok(KnowledgeDreamGitOutcome::Deferred {
            branch: None,
            commit: None,
            reason: reason.clone(),
        });
    }

    let before_paths = match &prepared {
        PreparedKnowledgeGit::Active { .. } => match versioned_knowledge_paths(&mutation_root) {
            Ok(paths) => Some(paths),
            Err(error) => {
                // Parsing the pre-write bundle is required to record deletions
                if let PreparedKnowledgeGit::Active {
                    restore_branch: Some(restore_branch),
                    ..
                } = &prepared
                {
                    let _ = restore_knowledge_branch(&mutation_root, restore_branch);
                }
                return Ok(KnowledgeDreamGitOutcome::Deferred {
                    branch: None,
                    commit: None,
                    reason: format!("validating existing knowledge for Git failed: {error}"),
                });
            }
        },
        PreparedKnowledgeGit::Skipped(_) => None,
        PreparedKnowledgeGit::Deferred(_) => unreachable!("deferred preparation returned early"),
    };

    // The supplied path is descriptor-bound on Linux and has been proven to
    // name the held root everywhere else. Callers must write only through it.
    if cancel.is_cancelled() {
        bail!("knowledge dream write cancelled before applying model output");
    }
    process_lock.revalidate_root()?;
    let applied = apply(&mutation_root);
    if let Err(error) = applied {
        if matches!(&prepared, PreparedKnowledgeGit::Active { .. })
            && let Err(cleanup_error) = restore_knowledge_dream_worktree(&mutation_root)
        {
            return Err(error.context(format!(
                "knowledge dream apply failed and its Git transaction could not be cleaned for re-entry: {cleanup_error}"
            )));
        }
        if let PreparedKnowledgeGit::Active {
            restore_branch: Some(restore_branch),
            ..
        } = &prepared
        {
            // The apply closure can fail after a review branch was selected.
            // Best-effort restoration preserves the accepted branch whenever
            // Git can safely switch back; an uncommitted failed write remains
            // visible as dirty state and prevents a later dream from taking it.
            let _ = restore_knowledge_branch(&mutation_root, restore_branch);
        }
        return Err(error);
    }

    let outcome = match prepared {
        PreparedKnowledgeGit::Skipped(reason) => Ok(KnowledgeDreamGitOutcome::Skipped { reason }),
        PreparedKnowledgeGit::Deferred(reason) => Ok(KnowledgeDreamGitOutcome::Deferred {
            branch: None,
            commit: None,
            reason,
        }),
        PreparedKnowledgeGit::Active {
            branch,
            remote,
            restore_branch,
        } => {
            let outcome = match commit_knowledge_dream(
                &mutation_root,
                &branch,
                remote.as_deref(),
                dream,
                before_paths
                    .as_ref()
                    .expect("active Git preparation has a baseline"),
            ) {
                Ok(outcome) => Ok(outcome),
                Err(error) => Ok(KnowledgeDreamGitOutcome::Deferred {
                    branch: Some(branch.clone()),
                    commit: None,
                    reason: format!("recording dream history failed: {error}"),
                }),
            };
            if let Some(restore_branch) = restore_branch
                && let Err(error) = restore_knowledge_branch(&mutation_root, &restore_branch)
            {
                let commit = outcome
                    .as_ref()
                    .ok()
                    .and_then(|outcome| dream_outcome_commit(outcome));
                return Ok(KnowledgeDreamGitOutcome::Deferred {
                    branch: Some(branch),
                    commit,
                    reason: format!(
                        "restoring the knowledge base branch after review failed: {error}"
                    ),
                });
            }
            outcome
        }
    };
    outcome
}

fn prepare_knowledge_git(
    root: &Path,
    merge_policy: KnowledgeBaseMergePolicy,
    knowledge_base_id: &str,
) -> PreparedKnowledgeGit {
    let probe = match crate::git::run_git(root, &["rev-parse", "--show-toplevel"]) {
        Ok(probe) => probe,
        Err(error) => return PreparedKnowledgeGit::Skipped(format!("Git is unavailable: {error}")),
    };
    let root_identity = match fs::canonicalize(root) {
        Ok(identity) => identity,
        Err(error) => {
            return PreparedKnowledgeGit::Deferred(format!(
                "resolving the knowledge base root failed: {error}"
            ));
        }
    };
    let uses_enclosing_worktree = probe.success
        && fs::canonicalize(probe.stdout.trim())
            .map(|worktree| worktree != root_identity)
            .unwrap_or(true);
    if !probe.success || uses_enclosing_worktree {
        // A KB nested in a user project must become a nested repository of
        // its own. Never fetch, checkout, or commit through the enclosing
        // worktree just because Git happened to find it from this path.
        let initialized = match crate::git::run_git(root, &["init", "-q"]) {
            Ok(initialized) => initialized,
            Err(error) => {
                return PreparedKnowledgeGit::Skipped(format!("Git is unavailable: {error}"));
            }
        };
        if !initialized.success {
            return PreparedKnowledgeGit::Deferred(format!(
                "initializing the knowledge Git repository failed: {}",
                initialized.stderr.trim()
            ));
        }
        let main = match crate::git::run_git(root, &["symbolic-ref", "HEAD", "refs/heads/main"]) {
            Ok(main) => main,
            Err(error) => {
                return PreparedKnowledgeGit::Deferred(format!(
                    "setting the knowledge repository default branch failed: {error}"
                ));
            }
        };
        if !main.success {
            return PreparedKnowledgeGit::Deferred(format!(
                "setting the knowledge repository default branch failed: {}",
                main.stderr.trim()
            ));
        }
    }

    let sidecars = match KbSidecars::in_root(root).canonicalized() {
        Ok(sidecars) => sidecars,
        Err(error) => {
            return PreparedKnowledgeGit::Deferred(format!(
                "resolving knowledge machine-state paths failed: {error}"
            ));
        }
    };
    if let Err(error) = ensure_sidecars_gitignored(root, &sidecars) {
        return PreparedKnowledgeGit::Deferred(format!(
            "protecting knowledge machine state from Git failed: {error}"
        ));
    }

    let has_head = match knowledge_git_has_head(root) {
        Ok(has_head) => has_head,
        Err(error) => return PreparedKnowledgeGit::Deferred(error.to_string()),
    };
    if !has_head && let Err(error) = initialize_knowledge_git_history(root, knowledge_base_id) {
        return PreparedKnowledgeGit::Deferred(error.to_string());
    }

    // A clean worktree is required for every run, including local-only KBs.
    // This prevents any pre-existing manual change from being staged under a
    // dream's audit message. Newly initialized KBs first receive the explicit
    // initialization commit above, so their existing valid content is not
    // misattributed to the first dream either.
    let clean = match knowledge_git_worktree_clean(root) {
        Ok(clean) => clean,
        Err(error) => return PreparedKnowledgeGit::Deferred(error.to_string()),
    };
    if !clean {
        return PreparedKnowledgeGit::Deferred(
            "knowledge repository has local changes; deferring dream history".to_string(),
        );
    }

    let current_branch = match knowledge_git_branch(root) {
        Ok(branch) => branch,
        Err(error) => return PreparedKnowledgeGit::Deferred(error.to_string()),
    };
    let remote = match knowledge_git_remote(root) {
        Ok(remote) => remote,
        Err(error) => return PreparedKnowledgeGit::Deferred(error.to_string()),
    };
    let branch = match knowledge_git_base_branch(root, &current_branch) {
        Ok(branch) => branch,
        Err(error) => return PreparedKnowledgeGit::Deferred(error.to_string()),
    };
    if current_branch != branch {
        if let Err(error) = restore_knowledge_branch(root, &branch) {
            return PreparedKnowledgeGit::Deferred(error.to_string());
        }
    }

    if let Some(remote_name) = remote.as_deref() {
        if let Err(error) = knowledge_git_fetch(root, remote_name) {
            return PreparedKnowledgeGit::Deferred(error.to_string());
        }
        // A prior run can have committed successfully yet deferred after a
        // transport failure.  Synchronize that already-created commit before
        // invoking the deterministic model mutation again: otherwise the
        // retry can be a no-op and the remote would remain behind forever.
        if let Err(error) = synchronize_pending_knowledge_dream_pushes(
            root,
            remote_name,
            &branch,
            knowledge_base_id,
        ) {
            return PreparedKnowledgeGit::Deferred(error.to_string());
        }
    }

    let restore_branch = branch.clone();
    let branch = match merge_policy {
        KnowledgeBaseMergePolicy::Auto => {
            if let Some(remote_name) = remote.as_deref()
                && let Err(error) =
                    knowledge_git_rebase_remote_branch(root, remote_name, &branch, true)
            {
                return PreparedKnowledgeGit::Deferred(error.to_string());
            }
            branch
        }
        KnowledgeBaseMergePolicy::Review => {
            let review_branch = format!(
                "cockpit/dream/{}/{}",
                git_branch_component(knowledge_base_id),
                uuid::Uuid::new_v4().simple()
            );
            let base = remote
                .as_deref()
                .and_then(|remote_name| knowledge_git_remote_ref(root, remote_name, &branch).ok())
                .flatten();
            let checkout = if let Some(base) = base.as_deref() {
                knowledge_git(root, &["checkout", "-q", "-b", &review_branch, base])
            } else {
                knowledge_git(root, &["checkout", "-q", "-b", &review_branch])
            };
            match checkout {
                Ok(checkout) if checkout.success => review_branch,
                Ok(checkout) => {
                    return PreparedKnowledgeGit::Deferred(format!(
                        "creating knowledge review branch failed: {}",
                        checkout.stderr.trim()
                    ));
                }
                Err(error) => return PreparedKnowledgeGit::Deferred(error.to_string()),
            }
        }
    };

    PreparedKnowledgeGit::Active {
        restore_branch: (merge_policy == KnowledgeBaseMergePolicy::Review)
            .then_some(restore_branch),
        branch,
        remote,
    }
}

fn commit_knowledge_dream(
    root: &Path,
    branch: &str,
    remote: Option<&str>,
    dream: &KnowledgeDreamCommit,
    before_paths: &BTreeSet<PathBuf>,
) -> Result<KnowledgeDreamGitOutcome> {
    let paths = match versioned_knowledge_paths(root) {
        Ok(paths) => paths,
        Err(error) => {
            return Ok(KnowledgeDreamGitOutcome::Deferred {
                branch: Some(branch.to_string()),
                commit: None,
                reason: format!("validating dream output for Git failed: {error}"),
            });
        }
    };
    let paths: BTreeSet<_> = paths.union(before_paths).cloned().collect();
    if paths.is_empty() {
        return Ok(KnowledgeDreamGitOutcome::NoChanges {
            branch: branch.to_string(),
        });
    }

    let mut add_args = vec!["add".to_string(), "--".to_string()];
    add_args.extend(paths.iter().map(|path| rel_string(path)));
    let add_refs: Vec<_> = add_args.iter().map(String::as_str).collect();
    let add = match knowledge_git(root, &add_refs) {
        Ok(add) => add,
        Err(error) => {
            return deferred_knowledge_dream_after_rollback(
                root,
                branch,
                "staging dream output",
                error.to_string(),
            );
        }
    };
    if !add.success {
        return deferred_knowledge_dream_after_rollback(
            root,
            branch,
            "staging dream output",
            add.stderr.trim().to_string(),
        );
    }

    let mut cached_args = vec![
        "diff".to_string(),
        "--cached".to_string(),
        "--name-only".to_string(),
        "--".to_string(),
    ];
    cached_args.extend(paths.iter().map(|path| rel_string(path)));
    let cached_refs: Vec<_> = cached_args.iter().map(String::as_str).collect();
    let changed = match knowledge_git(root, &cached_refs) {
        Ok(changed) => changed,
        Err(error) => {
            return deferred_knowledge_dream_after_rollback(
                root,
                branch,
                "checking staged dream output",
                error.to_string(),
            );
        }
    };
    if !changed.success {
        return deferred_knowledge_dream_after_rollback(
            root,
            branch,
            "checking staged dream output",
            changed.stderr.trim().to_string(),
        );
    }
    if changed.stdout.trim().is_empty() {
        // `git add` can update the index even when no selected path is
        // ultimately different from HEAD. Restore it before reporting a
        // no-op so the next ledger retry observes the same clean boundary.
        restore_knowledge_dream_worktree(root)?;
        return Ok(KnowledgeDreamGitOutcome::NoChanges {
            branch: branch.to_string(),
        });
    }

    let message = structured_dream_commit_message(dream);
    let mut commit_args = vec![
        "-c".to_string(),
        "user.name=Flycockpit".to_string(),
        "-c".to_string(),
        "user.email=knowledge@flycockpit.invalid".to_string(),
        "-c".to_string(),
        "commit.gpgSign=false".to_string(),
        "commit".to_string(),
        "--only".to_string(),
        "-m".to_string(),
        message,
    ];
    commit_args.push("--".to_string());
    commit_args.extend(paths.iter().map(|path| rel_string(path)));
    let commit_refs: Vec<_> = commit_args.iter().map(String::as_str).collect();
    let committed = match knowledge_git(root, &commit_refs) {
        Ok(committed) => committed,
        Err(error) => {
            return deferred_knowledge_dream_after_rollback(
                root,
                branch,
                "committing dream output",
                error.to_string(),
            );
        }
    };
    if !committed.success {
        return deferred_knowledge_dream_after_rollback(
            root,
            branch,
            "committing dream output",
            committed.stderr.trim().to_string(),
        );
    }
    let commit = crate::git::head_sha(root)?;

    let Some(remote) = remote else {
        return Ok(KnowledgeDreamGitOutcome::Committed {
            commit,
            branch: branch.to_string(),
            pushed: false,
        });
    };
    if knowledge_git_push(root, remote, branch)?.success {
        return Ok(KnowledgeDreamGitOutcome::Committed {
            commit,
            branch: branch.to_string(),
            pushed: true,
        });
    }

    // A rejected push is the normal concurrent-writer case. Fetch, rebase,
    // and try once more. A conflict is aborted so the next ledger-driven dream
    // run starts from a clean repository; no force-push is ever attempted.
    if let Err(error) = knowledge_git_fetch(root, remote) {
        return Ok(KnowledgeDreamGitOutcome::Deferred {
            branch: Some(branch.to_string()),
            commit: Some(commit),
            reason: error.to_string(),
        });
    }
    if let Err(error) = knowledge_git_rebase_remote_branch(root, remote, branch, true) {
        return Ok(KnowledgeDreamGitOutcome::Deferred {
            branch: Some(branch.to_string()),
            commit: Some(commit),
            reason: error.to_string(),
        });
    }
    let pushed = knowledge_git_push(root, remote, branch)?;
    if pushed.success {
        Ok(KnowledgeDreamGitOutcome::Committed {
            commit: crate::git::head_sha(root)?,
            branch: branch.to_string(),
            pushed: true,
        })
    } else {
        Ok(KnowledgeDreamGitOutcome::Deferred {
            branch: Some(branch.to_string()),
            commit: Some(commit),
            reason: format!(
                "pushing dream output was rejected after rebase retry: {}",
                pushed.stderr.trim()
            ),
        })
    }
}

/// Restore the clean transaction boundary observed before a dream callback
/// ran. `prepare_knowledge_git` refuses to proceed unless the worktree is
/// clean, so every tracked or untracked non-ignored path created here belongs
/// to this failed dream attempt (including a hook side effect). Ignored
/// machine-local sidecars deliberately survive `git clean`.
fn restore_knowledge_dream_worktree(root: &Path) -> Result<()> {
    let reset = knowledge_git(root, &["reset", "--hard", "HEAD"])?;
    if !reset.success {
        bail!(
            "resetting failed knowledge dream index and worktree failed: {}",
            reset.stderr.trim()
        );
    }
    let clean = knowledge_git(root, &["clean", "-fd"])?;
    if !clean.success {
        bail!(
            "removing failed knowledge dream output failed: {}",
            clean.stderr.trim()
        );
    }
    if !knowledge_git_worktree_clean(root)? {
        bail!("failed knowledge dream cleanup left the repository dirty");
    }
    Ok(())
}

fn deferred_knowledge_dream_after_rollback(
    root: &Path,
    branch: &str,
    operation: &str,
    failure: String,
) -> Result<KnowledgeDreamGitOutcome> {
    match restore_knowledge_dream_worktree(root) {
        Ok(()) => Ok(KnowledgeDreamGitOutcome::Deferred {
            branch: Some(branch.to_string()),
            commit: None,
            reason: format!("{operation} failed: {failure}"),
        }),
        Err(cleanup_error) => Ok(KnowledgeDreamGitOutcome::Deferred {
            branch: Some(branch.to_string()),
            commit: None,
            reason: format!(
                "{operation} failed: {failure}; refusing automatic re-entry because cleanup failed: {cleanup_error}"
            ),
        }),
    }
}

fn versioned_knowledge_paths(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let bundle = parse_bundle(root)?;
    let mut paths = BTreeSet::new();
    if bundle.index_md.is_some() {
        paths.insert(PathBuf::from("index.md"));
    }
    if bundle.log_md.is_some() {
        paths.insert(PathBuf::from("log.md"));
    }
    paths.extend(bundle.concepts.into_iter().map(|concept| concept.path));
    paths.extend(bundle.resources.into_iter().map(|resource| resource.path));
    Ok(paths)
}

/// Record the KB's pre-dream source state separately from dream output. This
/// runs only for a newly initialized repository, before the dream callback,
/// so ordinary local edits cannot be silently attributed to that dream.
fn initialize_knowledge_git_history(root: &Path, knowledge_base_id: &str) -> Result<()> {
    let paths = versioned_knowledge_paths(root)?;
    if !paths.is_empty() {
        let mut add_args = vec!["add".to_string(), "--".to_string()];
        add_args.extend(paths.iter().map(|path| rel_string(path)));
        let add_refs: Vec<_> = add_args.iter().map(String::as_str).collect();
        let add = knowledge_git(root, &add_refs)?;
        if !add.success {
            bail!(
                "staging the initial knowledge snapshot failed: {}",
                add.stderr.trim()
            );
        }
    }

    let message = format!(
        "knowledge(kb={}): initialize repository",
        git_message_field(knowledge_base_id)
    );
    let mut commit_args = vec![
        "-c".to_string(),
        "user.name=Flycockpit".to_string(),
        "-c".to_string(),
        "user.email=knowledge@flycockpit.invalid".to_string(),
        "-c".to_string(),
        "commit.gpgSign=false".to_string(),
        "commit".to_string(),
        "--allow-empty".to_string(),
        "-m".to_string(),
        message,
    ];
    if !paths.is_empty() {
        commit_args.push("--only".to_string());
        commit_args.push("--".to_string());
        commit_args.extend(paths.iter().map(|path| rel_string(path)));
    }
    let commit_refs: Vec<_> = commit_args.iter().map(String::as_str).collect();
    let committed = knowledge_git(root, &commit_refs)?;
    if !committed.success {
        bail!(
            "committing the initial knowledge snapshot failed: {}",
            committed.stderr.trim()
        );
    }
    Ok(())
}

fn structured_dream_commit_message(dream: &KnowledgeDreamCommit) -> String {
    format!(
        "dream(kb={}): sessions={} model={} concepts={} data_files={}",
        git_message_field(&dream.knowledge_base_id),
        dream.sessions_dreamed,
        git_message_field(&dream.model),
        dream.concepts_written,
        dream.data_files_written,
    )
}

fn git_message_field(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-")
}

fn dream_outcome_commit(outcome: &KnowledgeDreamGitOutcome) -> Option<String> {
    match outcome {
        KnowledgeDreamGitOutcome::Committed { commit, .. }
        | KnowledgeDreamGitOutcome::Deferred {
            commit: Some(commit),
            ..
        } => Some(commit.clone()),
        KnowledgeDreamGitOutcome::Skipped { .. }
        | KnowledgeDreamGitOutcome::NoChanges { .. }
        | KnowledgeDreamGitOutcome::Deferred { commit: None, .. } => None,
    }
}

fn knowledge_git(root: &Path, args: &[&str]) -> Result<crate::git::GitOutcome> {
    crate::git::run_git(root, args)
        .with_context(|| format!("running knowledge Git command `git {}`", args.join(" ")))
}

fn knowledge_git_branch(root: &Path) -> Result<String> {
    let branch = knowledge_git(root, &["symbolic-ref", "--quiet", "--short", "HEAD"])?;
    if !branch.success {
        bail!("knowledge repository has no writable branch");
    }
    let branch = branch.stdout.trim();
    if branch.is_empty() || branch.starts_with('-') {
        bail!("knowledge repository reported an invalid branch name");
    }
    Ok(branch.to_string())
}

/// The accepted KB branch is `main` whenever it exists. This makes a prior
/// review proposal unable to become the base of a later auto or review run.
/// Older repositories without `main` retain their current checked-out branch
/// as the explicit fallback rather than guessing at a branch name.
fn knowledge_git_base_branch(root: &Path, current_branch: &str) -> Result<String> {
    let main = knowledge_git(
        root,
        &["show-ref", "--verify", "--quiet", "refs/heads/main"],
    )?;
    if main.success {
        return Ok("main".to_string());
    }
    Ok(current_branch.to_string())
}

fn restore_knowledge_branch(root: &Path, branch: &str) -> Result<()> {
    let checkout = knowledge_git(root, &["checkout", "-q", branch])?;
    if !checkout.success {
        bail!(
            "checking out the accepted knowledge branch `{branch}` failed: {}",
            checkout.stderr.trim()
        );
    }
    Ok(())
}

fn knowledge_git_remote(root: &Path) -> Result<Option<String>> {
    let remote = knowledge_git(root, &["remote", "get-url", "origin"])?;
    if !remote.success {
        return Ok(None);
    }
    Ok(Some("origin".to_string()))
}

fn knowledge_git_has_head(root: &Path) -> Result<bool> {
    Ok(knowledge_git(root, &["rev-parse", "--verify", "--quiet", "HEAD"])?.success)
}

fn knowledge_git_worktree_clean(root: &Path) -> Result<bool> {
    let status = knowledge_git(root, &["status", "--porcelain=v1"])?;
    if !status.success {
        bail!(
            "checking knowledge repository status failed: {}",
            status.stderr.trim()
        );
    }
    Ok(status.stdout.trim().is_empty())
}

fn knowledge_git_fetch(root: &Path, remote: &str) -> Result<()> {
    let fetched = knowledge_git(root, &["fetch", "--prune", remote])?;
    if !fetched.success {
        bail!(
            "fetching knowledge remote failed: {}",
            fetched.stderr.trim()
        );
    }
    Ok(())
}

fn knowledge_git_remote_ref(root: &Path, remote: &str, branch: &str) -> Result<Option<String>> {
    let reference = format!("refs/remotes/{remote}/{branch}");
    let found = knowledge_git(root, &["rev-parse", "--verify", "--quiet", &reference])?;
    if found.success {
        Ok(Some(reference))
    } else {
        Ok(None)
    }
}

fn knowledge_git_rebase_remote_branch(
    root: &Path,
    remote: &str,
    branch: &str,
    has_head: bool,
) -> Result<()> {
    let Some(reference) = knowledge_git_remote_ref(root, remote, branch)? else {
        return Ok(());
    };
    if !has_head {
        let checkout = knowledge_git(root, &["checkout", "-q", "-B", branch, &reference])?;
        if !checkout.success {
            bail!(
                "checking out remote knowledge branch failed: {}",
                checkout.stderr.trim()
            );
        }
        return Ok(());
    }
    let rebase = knowledge_git(root, &["rebase", &reference])?;
    if rebase.success {
        return Ok(());
    }
    let abort = knowledge_git(root, &["rebase", "--abort"])?;
    if !abort.success {
        bail!(
            "rebasing knowledge output failed and Git could not abort safely: {}",
            abort.stderr.trim()
        );
    }
    bail!(
        "rebasing knowledge output deferred: {}",
        rebase.stderr.trim()
    )
}

fn knowledge_git_push(root: &Path, remote: &str, branch: &str) -> Result<crate::git::GitOutcome> {
    let destination = format!("HEAD:refs/heads/{branch}");
    knowledge_git(root, &["push", remote, &destination])
}

/// Finish publication of commits retained locally by an earlier deferred
/// dream.  This happens before the next mutation, so a ledger retry whose
/// deterministic write is now empty still catches the remote up.  The base
/// branch is rebased first; review branches are independent proposals and are
/// pushed by explicit refspec without checking them out or rebasing them onto
/// a newly accepted base.
fn synchronize_pending_knowledge_dream_pushes(
    root: &Path,
    remote: &str,
    base_branch: &str,
    knowledge_base_id: &str,
) -> Result<()> {
    synchronize_pending_knowledge_base_branch(root, remote, base_branch)?;

    let review_prefix = format!("cockpit/dream/{}/", git_branch_component(knowledge_base_id));
    let branches = knowledge_git(
        root,
        &[
            "for-each-ref",
            "--format=%(refname:short)",
            "refs/heads/cockpit/dream",
        ],
    )?;
    if !branches.success {
        bail!(
            "listing pending knowledge review branches failed: {}",
            branches.stderr.trim()
        );
    }
    for branch in branches
        .stdout
        .lines()
        .map(str::trim)
        .filter(|branch| !branch.is_empty() && branch.starts_with(&review_prefix))
    {
        let remote_contains_branch = knowledge_git_remote_ref(root, remote, branch)?
            .map(|remote_ref| knowledge_git_is_ancestor(root, branch, &remote_ref))
            .transpose()?
            .unwrap_or(false);
        if remote_contains_branch {
            continue;
        }
        let destination = format!("refs/heads/{branch}:refs/heads/{branch}");
        let pushed = knowledge_git(root, &["push", remote, &destination])?;
        if !pushed.success {
            bail!(
                "pushing pending knowledge review branch `{branch}` failed: {}",
                pushed.stderr.trim()
            );
        }
    }
    Ok(())
}

fn synchronize_pending_knowledge_base_branch(
    root: &Path,
    remote: &str,
    branch: &str,
) -> Result<()> {
    if let Some(remote_ref) = knowledge_git_remote_ref(root, remote, branch)? {
        if !knowledge_git_is_ancestor(root, &remote_ref, branch)? {
            knowledge_git_rebase_remote_branch(root, remote, branch, true)?;
        }
        if knowledge_git_is_ancestor(root, branch, &remote_ref)? {
            return Ok(());
        }
    }
    let pushed = knowledge_git_push(root, remote, branch)?;
    if !pushed.success {
        bail!(
            "pushing pending knowledge dream commit failed: {}",
            pushed.stderr.trim()
        );
    }
    Ok(())
}

fn knowledge_git_is_ancestor(root: &Path, ancestor: &str, descendant: &str) -> Result<bool> {
    let check = knowledge_git(root, &["merge-base", "--is-ancestor", ancestor, descendant])?;
    if check.success {
        return Ok(true);
    }
    // Git uses exit status 1 for the ordinary "not an ancestor" result.
    // Any stderr is instead a malformed/missing ref and must fail closed.
    if check.stderr.trim().is_empty() {
        return Ok(false);
    }
    bail!(
        "checking pending knowledge history ancestry failed: {}",
        check.stderr.trim()
    )
}

fn git_branch_component(value: &str) -> String {
    let component: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect();
    if component.is_empty() {
        "knowledge".to_string()
    } else {
        component
    }
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
        immutable_snapshot: bool,
    ) -> Self {
        Self {
            entry,
            root,
            snapshot,
            sidecars,
            embedder,
            immutable_snapshot,
        }
    }
}

#[async_trait]
impl KbProvider for LocalKb {
    async fn is_available(&self) -> Result<bool> {
        Ok(self.snapshot.is_some())
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
        // A missing KB remains reportable as unavailable. Once it exists,
        // canonicalize its sidecars immediately before locking so aliases in
        // registry entries converge on one in-process identity. The process
        // fence must be acquired before reading markdown: it retains the KB
        // object that will receive the derived sidecars.
        let sidecars = self.sidecars.canonicalized()?;
        let sidecar_lock = sidecar_lock(&sidecars);
        let _sidecar_guard = sidecar_lock.lock().await;
        let (index, _) = match &self.snapshot {
            Some(snapshot) => {
                let process_lock = acquire_process_sidecar_lock(&sidecars).await?;
                KnowledgeIndex::open_snapshot_locked(
                    snapshot.clone(),
                    sidecars.clone(),
                    &process_lock,
                    embedder,
                    Some(query_vector.len()),
                )
                .await?
            }
            None => {
                let (bundle, process_lock) = snapshot_bundle_with_sidecar_fence(&sidecars).await?;
                KnowledgeIndex::open_snapshot_locked(
                    bundle,
                    sidecars,
                    &process_lock,
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

    fn apply_dream(
        &self,
        dream: &KnowledgeDreamCommit,
        mutation: &dyn KnowledgeDreamMutation,
        cancel: &CancellationToken,
    ) -> Result<KnowledgeDreamGitOutcome> {
        if self.immutable_snapshot {
            bail!(
                "assistant knowledge base `{}` is an immutable installation snapshot and cannot receive dreams",
                self.entry.id
            );
        }
        apply_knowledge_dream_cancellable(
            &self.root,
            self.entry.merge_policy,
            dream,
            cancel,
            |root| mutation.apply(root),
        )
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

    fn apply_dream(
        &self,
        _dream: &KnowledgeDreamCommit,
        _mutation: &dyn KnowledgeDreamMutation,
        _cancel: &CancellationToken,
    ) -> Result<KnowledgeDreamGitOutcome> {
        bail!(
            "remote knowledge-base dream writes are hosted and not implemented for `{}`",
            self.entry.id
        )
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
    parse_bundle_from_retained_root(root, &handle)
}

/// Parse a bundle from a retained root capability. The path is retained for
/// diagnostics only; every markdown and sibling-resource read is anchored to
/// `handle`, so callers can carry one KB object identity from snapshot through
/// sidecar publication.
fn parse_bundle_from_retained_root(root: PathBuf, handle: &fs::File) -> Result<KnowledgeBundle> {
    let documents =
        cockpit_config::config::snapshot_markdown_tree_from_retained_directory_nofollow(
            handle,
            MAX_KNOWLEDGE_FILES,
            MAX_KNOWLEDGE_ENTRIES,
            MAX_KNOWLEDGE_DEPTH,
            MAX_KNOWLEDGE_FILE_BYTES,
            MAX_KNOWLEDGE_TOTAL_BYTES,
        )?;
    parse_bundle_snapshot(root, documents, handle)
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
        let sidecars = KbSidecars::in_root(&root).canonicalized()?;
        let lock = sidecar_lock(&sidecars);
        let _guard = lock.lock().await;
        // Selecting the process fence before the source snapshot makes the
        // retained directory capability the sole identity for this rebuild.
        // A replacement of the root can therefore only be observed by the
        // next rebuild; it cannot receive this rebuild's old projection.
        let (bundle, process_lock) = snapshot_bundle_with_sidecar_fence(&sidecars).await?;
        Self::open_snapshot_locked(bundle, sidecars, &process_lock, embedder, query_dimensions)
            .await
    }

    /// Caller must hold the per-KB sidecar lock and the process fence that was
    /// acquired before snapshotting the source. SQLite receives only verified
    /// sidecar bytes and runs in memory; no SQLite connection crosses the
    /// await in `sync_embeddings`, so this remains valid in KbProvider's
    /// required Send future.
    async fn open_snapshot_locked(
        bundle: KnowledgeBundle,
        sidecars: KbSidecars,
        process_lock: &SidecarProcessLock,
        embedder: Arc<dyn Embedder>,
        query_dimensions: Option<usize>,
    ) -> Result<(Self, IndexStats)> {
        // The process-level lock is acquired before the source snapshot and
        // retained across the provider await in `sync_embeddings`. It
        // complements the in-process Tokio mutex held by the caller and makes
        // different daemon data directories serialize their paid work against
        // the same external KB. It also serializes the Git exclusion update
        // before either sidecar can be opened.
        ensure_sidecars_gitignored(&bundle.root, &sidecars)?;
        let index = open_index_connection(&sidecars.index, process_lock)?;
        ensure_index_schema(&index)?;
        rebuild_index(&index, &bundle)?;
        persist_private_sidecar_connection(&index, &sidecars.index, process_lock)?;
        let stats = sync_embeddings(
            &sidecars.embeddings,
            process_lock,
            &bundle,
            embedder.as_ref(),
            query_dimensions,
        )
        .await?;
        let embeddings = open_embeddings_connection(&sidecars.embeddings, process_lock)?;
        ensure_embeddings_schema(&embeddings)?;
        persist_private_sidecar_connection(&embeddings, &sidecars.embeddings, process_lock)?;
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
}

fn read_private_sidecar_bytes(
    sidecar: &Path,
    label: &str,
    process_lock: &SidecarProcessLock,
) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        let name = sidecar
            .file_name()
            .context("knowledge sidecar has no file name")?;
        let mut file = cockpit_host::private_fs::open_private_file_in_dir_fd(
            &process_lock.directory,
            name,
            cockpit_host::private_fs::PrivateFileAccess::ReadWrite,
            label,
        )
        .map_err(anyhow::Error::from)
        .context("opening retained private knowledge sidecar")?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .with_context(|| format!("reading knowledge sidecar {label}"))?;
        return Ok(bytes);
    }
    #[cfg(not(unix))]
    {
        let _ = process_lock;
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
        cockpit_host::private_fs::read_private_file(sidecar, label)
            .map_err(anyhow::Error::from)?
            .context("knowledge sidecar disappeared before its verified read")
    }
}

fn open_private_sidecar_connection(
    sidecar: &Path,
    label: &str,
    process_lock: &SidecarProcessLock,
) -> Result<Connection> {
    let bytes = read_private_sidecar_bytes(sidecar, label, process_lock)?;
    let mut conn = Connection::open_in_memory().context("opening in-memory knowledge sidecar")?;
    if !bytes.is_empty() {
        conn.deserialize_read_exact(MAIN_DB, bytes.as_slice(), bytes.len(), false)
            .with_context(|| format!("loading verified knowledge sidecar {}", sidecar.display()))?;
    }
    Ok(conn)
}

fn persist_private_sidecar_connection(
    conn: &Connection,
    sidecar: &Path,
    process_lock: &SidecarProcessLock,
) -> Result<()> {
    let bytes = conn
        .serialize(MAIN_DB)
        .with_context(|| format!("serializing knowledge sidecar {}", sidecar.display()))?;
    #[cfg(unix)]
    {
        let name = sidecar
            .file_name()
            .context("knowledge sidecar has no file name")?;
        cockpit_host::private_fs::write_private_file_in_dir_fd(
            &process_lock.directory,
            name,
            sidecar,
            &bytes,
        )
        .with_context(|| format!("publishing knowledge sidecar {}", sidecar.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = process_lock;
        cockpit_host::private_fs::write_private_file(sidecar, &bytes)
            .with_context(|| format!("publishing knowledge sidecar {}", sidecar.display()))?;
    }
    Ok(())
}

fn open_index_connection(sidecar: &Path, process_lock: &SidecarProcessLock) -> Result<Connection> {
    open_private_sidecar_connection(sidecar, "knowledge index sidecar", process_lock)
}

fn open_embeddings_connection(
    sidecar: &Path,
    process_lock: &SidecarProcessLock,
) -> Result<Connection> {
    let conn =
        open_private_sidecar_connection(sidecar, "knowledge embeddings sidecar", process_lock)?;
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
    if stored_index_logic_version(conn)? != Some(INDEX_LOGIC_VERSION) {
        // The index is deliberately disposable. A version mismatch means its
        // table layout is not trustworthy, so discard every schema object we
        // own before recreating the current projection. Do not apply a
        // migration here: only embeddings.sqlite preserves paid state.
        conn.execute_batch(
            r#"
            DROP TABLE IF EXISTS structured_values;
            DROP TABLE IF EXISTS structured_rows;
            DROP TABLE IF EXISTS chunks_fts;
            DROP TABLE IF EXISTS chunks;
            DROP TABLE IF EXISTS concept_frontmatter;
            DROP TABLE IF EXISTS concepts;
            DROP TABLE IF EXISTS intel_meta;
            "#,
        )?;
    }
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

fn stored_index_logic_version(conn: &Connection) -> Result<Option<i64>> {
    if !table_exists(conn, "intel_meta")? {
        return Ok(None);
    }
    Ok(conn
        .query_row(
            "SELECT value FROM intel_meta WHERE key='index_logic_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .and_then(|value| value.parse().ok()))
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
    process_lock: &SidecarProcessLock,
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
    let prepared = prepare_embedding_sync(
        sidecar,
        process_lock,
        &chunks,
        &model_identity,
        query_dimensions,
    )?;
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
    // All in-memory SQLite connections were dropped by prepare_embedding_sync
    // before the awaited paid call. The caller's per-KB mutex owns this work
    // interval.
    let vectors = embed_chunks(&prepared.missing, embedder, query_dimensions).await?;
    store_embeddings(
        sidecar,
        process_lock,
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
    process_lock: &SidecarProcessLock,
    chunks: &BTreeMap<String, String>,
    model_identity: &str,
    query_dimensions: Option<usize>,
) -> Result<PreparedEmbeddingSync> {
    let conn = open_embeddings_connection(sidecar, process_lock)?;
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
    process_lock: &SidecarProcessLock,
    chunks: &BTreeMap<String, String>,
    vectors: Vec<Vec<f32>>,
    reset: bool,
    model_identity: &str,
) -> Result<()> {
    let conn = open_embeddings_connection(sidecar, process_lock)?;
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
    persist_private_sidecar_connection(&conn, sidecar, process_lock)?;
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
    if let Some(stored) = stored.filter(|&stored| stored != dimensions) {
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
    crate::intel::hex_lower(&Sha256::digest(body.as_bytes()))
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
    executing_model_trusted: bool,
) {
    let extended = config.extended();
    let providers = config.providers();
    if let Err(error) = validate_dream_models(&extended, &providers) {
        tracing::warn!(%error, "refusing knowledge injection because dream-model policy is invalid");
        return;
    }
    let attachments = match attached_bundles(
        session,
        cwd,
        definition.and_then(crate::agents::AgentDef::allowed_knowledge_bases),
        &extended,
        executing_model_trusted,
    )
    .await
    {
        Ok(bundles) => bundles,
        Err(error) => {
            tracing::warn!(%error, "refusing knowledge injection because knowledge attachment resolution failed");
            return;
        }
    };
    if attachments.bundles.is_empty() {
        return;
    }
    match production_embedder(&extended, config, redact.clone(), session).await {
        Ok(Some(embedder)) => {
            match retrieve_from_knowledge_bases(
                &attachments.bundles,
                embedder,
                query,
                DEFAULT_SEARCH_LIMIT,
                Some(&crate::sealed::LocalVaultResolver::new(
                    session.secret_vault().clone(),
                )),
                executing_model_trusted,
            )
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
    resolver: Option<&dyn crate::sealed::SealedResolver>,
    trusted_reader: bool,
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
        available_providers.push((
            knowledge_base.sealed_id.clone(),
            knowledge_base.provider.with_embedder(embedder.clone()),
        ));
    }
    for (kb_id, provider) in available_providers {
        let mut results = provider.retrieve(query, limit).await?;
        if let Some(resolver) = resolver {
            for result in &mut results {
                result.snippet = crate::sealed::resolve_kb_markdown(
                    &result.snippet,
                    &kb_id,
                    resolver,
                    trusted_reader,
                )
                .await?;
            }
        }
        all.extend(results);
    }
    all.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    all.truncate(limit);
    Ok(all)
}

pub(crate) async fn attached_bundles(
    session: &Session,
    cwd: &Path,
    allowed_knowledge_bases: Option<&BTreeSet<String>>,
    extended: &ExtendedConfig,
    executing_model_trusted: bool,
) -> Result<AttachedKnowledgeBases> {
    let assistant = assistant_knowledge_registry_entry(session).await?;
    let mut seen = BTreeSet::new();
    let mut seen_attachment_ids = BTreeSet::new();
    let mut knowledge_bases = Vec::new();
    let mut denied_knowledge_base_ids = Vec::new();
    let mut registry = Vec::with_capacity(extended.knowledge_bases.len() + 1);
    if let Some(assistant) = assistant {
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
        let mut local = local.map(|local| {
            let root = if local.root.is_absolute() {
                local.root
            } else {
                cwd.join(local.root)
            };
            let sidecars = local.sidecars.unwrap_or_else(|| KbSidecars::in_root(&root));
            RegistryLocalKb {
                root,
                assistant_snapshot_root: local.assistant_snapshot_root,
                snapshot: local.snapshot,
                sidecars: Some(sidecars),
            }
        });
        // Relative local paths are interpreted against this invocation's
        // workspace root. Workspace-local sources are then bound to the
        // concrete directory object, not merely that path spelling. This
        // prevents a replacement directory (or a changed symlink target) from
        // inheriting the predecessor's dream boundary. Installer-owned entries
        // already carry their installation identity and intentionally retain it.
        if let Some(local) = &mut local {
            if !entry.has_bound_attachment_identity() {
                match local_source_attachment_identity(&local.root)? {
                    Some((root, attachment_id)) => {
                        // Workspace-local sidecars live beside the source and
                        // must follow a canonicalized root. Assistant-owned
                        // sidecars intentionally live in their private cache
                        // and retain that separate location.
                        if local
                            .sidecars
                            .as_ref()
                            .is_some_and(|sidecars| sidecars.root() == local.root)
                        {
                            local.sidecars = Some(KbSidecars::in_root(&root));
                        }
                        local.root = root;
                        entry = entry.with_bound_attachment_identity(attachment_id);
                    }
                    // An unavailable local provider cannot serve KB results.
                    // Give it an invocation-local identity so fresh-session
                    // retrieval never mistakes a predecessor's boundary for
                    // proof that this absent source has been dreamed.
                    None => entry = entry.with_bound_attachment_identity(uuid::Uuid::new_v4()),
                }
            }
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
        if entry.trust_required && !executing_model_trusted {
            denied_knowledge_base_ids.push(entry.id.clone());
            continue;
        }
        let sealed_id = if let Some(local) = &mut local {
            let Some((snapshot, sealed_id)) =
                capture_local_sealed_knowledge_base(&local.root, session.secret_vault().as_ref())?
            else {
                continue;
            };
            if local.assistant_snapshot_root.is_none() {
                // The workspace directory is the replaceable source, never a
                // cache authority. Keep its derived index in the daemon's
                // private data directory so a pathname successor cannot
                // inject cached snippets after we captured the source.
                let cache_root =
                    crate::config::resolve::cockpit_data_dir()?.join("knowledge-indexes");
                cockpit_host::private_fs::ensure_private_dir(&cache_root)?;
                local.sidecars = Some(KbSidecars::in_root(&cache_root.join(sealed_id.to_string())));
            }
            local.snapshot = Some(snapshot);
            sealed_id
        } else {
            sealed_knowledge_base_identity(&entry, session.secret_vault().as_ref())?
        };
        let Some(provider) = provider_for(entry.clone(), local)? else {
            continue;
        };
        knowledge_bases.push(AttachedKnowledgeBase {
            entry,
            provider,
            sealed_id,
        });
    }
    Ok(AttachedKnowledgeBases {
        bundles: knowledge_bases,
        denied_knowledge_base_ids,
    })
}

/// Resolve the entries that can appear in a root's frozen KB prompt. This
/// deliberately applies the same registry, attachment-identity, allow-list,
/// trust, and local-source availability rules as live attachment resolution.
/// It stops before creating sealed identities or providers because snapshot
/// capture runs with the session-row transaction rather than a live session
/// vault.
fn prompt_snapshot_entries_from_registry(
    assistant: Option<RegistryKnowledgeBase>,
    extended: &ExtendedConfig,
    cwd: &Path,
    allowed_knowledge_bases: Option<&BTreeSet<String>>,
    trust_mode: WorkspaceTrustMode,
) -> Result<Vec<KnowledgeBaseRegistryEntry>> {
    let mut seen = BTreeSet::new();
    let mut seen_attachment_ids = BTreeSet::new();
    let mut entries = Vec::new();
    let mut registry = Vec::with_capacity(extended.knowledge_bases.len() + 1);
    if let Some(assistant) = assistant {
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
        if let Some(local) = local {
            let root = if local.root.is_absolute() {
                local.root
            } else {
                cwd.join(local.root)
            };
            if !entry.has_bound_attachment_identity() {
                let Some((root, attachment_id)) = local_source_attachment_identity(&root)? else {
                    continue;
                };
                entry = entry.with_bound_attachment_identity(attachment_id);
                entry.source = KnowledgeBaseSource::Local { path: root };
            } else {
                entry.source = KnowledgeBaseSource::Local { path: root };
            }
            let KnowledgeBaseSource::Local { path } = &entry.source else {
                unreachable!("local registry entry must retain its local source");
            };
            if !local_knowledge_base_available_for_prompt(path)? {
                continue;
            }
        }
        validate_registry_entry(&entry)?;
        if !seen_attachment_ids.insert(entry.attachment_id()) {
            bail!(
                "knowledge base registry contains duplicate attachment ID `{}`",
                entry.attachment_id()
            );
        }
        if allowed_knowledge_bases.is_some_and(|ids| !ids.contains(&entry.id)) {
            continue;
        }
        if entry.trust_required && trust_mode != WorkspaceTrustMode::Trust {
            continue;
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Probe a local source with the same bounded, retained-descriptor snapshot
/// used by live attachment resolution. Prompt capture only needs to know
/// whether the KB can supply content; sealed identity assignment remains a
/// live-session concern.
fn local_knowledge_base_available_for_prompt(root: &Path) -> Result<bool> {
    let source = match cockpit_config::config::open_config_directory_nofollow(root) {
        Ok(source) => source,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(false);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening knowledge base source {}", root.display()));
        }
    };
    let documents =
        cockpit_config::config::snapshot_markdown_tree_from_retained_directory_nofollow(
            &source,
            MAX_KNOWLEDGE_FILES,
            MAX_KNOWLEDGE_ENTRIES,
            MAX_KNOWLEDGE_DEPTH,
            MAX_KNOWLEDGE_FILE_BYTES,
            MAX_KNOWLEDGE_TOTAL_BYTES,
        )
        .with_context(|| format!("snapshotting knowledge base source {}", root.display()))?;
    parse_bundle_snapshot(root.to_path_buf(), documents, &source)?;
    Ok(true)
}

/// Resolve a model-visible registry label to the immutable attachment identity
/// that seals values for that concrete KB source. The label never becomes part
/// of a token or vault locator, so deleting and recreating a label cannot
/// inherit the predecessor's sealed namespace.
pub(crate) async fn sealed_knowledge_base_id_for_tool(
    ctx: &ToolCtx,
    registry_id: &str,
) -> Result<crate::sealed::SealedKnowledgeBaseId> {
    let extended = ctx.config.extended();
    validate_dream_models(&extended, &ctx.config.providers())?;
    let attachments = attached_bundles(
        &ctx.session,
        &ctx.cwd,
        None,
        &extended,
        ctx.knowledge_access_trusted,
    )
    .await?;
    if attachments
        .denied_knowledge_base_ids
        .iter()
        .any(|id| id == registry_id)
    {
        bail!(knowledge_access_denied_message(&[registry_id.to_string()]));
    }
    let entry = attachments
        .bundles
        .iter()
        .find(|bundle| bundle.entry.id == registry_id)
        .map(|bundle| &bundle.entry)
        .context("knowledge base is unavailable or not attached")?;
    ensure_sealed_knowledge_base_identity(entry, ctx.session.secret_vault().as_ref())
}

/// Resolve the Owner's registry label to the exact immutable namespace bound
/// into a KB-copy action. Unlike a normal KB read, this may create the empty
/// non-secret marker: the Owner is explicitly authorizing a future custody
/// transfer, and this makes the first copy possible without creating a dummy
/// vault value merely to learn an ID.
pub(crate) fn sealed_knowledge_base_id_for_owner(
    cwd: &Path,
    extended: &ExtendedConfig,
    registry_id: &str,
    vault: &crate::secure_key::SecretVault,
) -> Result<crate::sealed::SealedKnowledgeBaseId> {
    let mut matches = extended
        .knowledge_bases
        .iter()
        .filter(|entry| entry.id == registry_id);
    let mut entry = matches
        .next()
        .cloned()
        .context("knowledge base is not configured")?;
    if matches.next().is_some() {
        bail!("knowledge base registry contains duplicate ID `{registry_id}`");
    }
    if let KnowledgeBaseSource::Local { path } = &entry.source {
        entry.source = KnowledgeBaseSource::Local {
            path: if path.is_absolute() {
                path.clone()
            } else {
                cwd.join(path)
            },
        };
    }
    ensure_sealed_knowledge_base_identity(&entry, vault)
}

/// Stable sealed-value identity for one KB source object.
///
/// Local KBs use a durable, random generation marker, never filesystem
/// metadata. Filesystem identities are recyclable, so deriving a capability
/// namespace from a path/inode (or Windows creation tuple) could transfer old
/// vault entries to a replacement directory. A read-only attachment lacking a
/// marker receives an invocation-local ID; any committed token then fails
/// closed. The marker is created only by the sealed authoring path below.
fn capture_local_sealed_knowledge_base(
    root: &Path,
    vault: &crate::secure_key::SecretVault,
) -> Result<Option<(KnowledgeBundle, crate::sealed::SealedKnowledgeBaseId)>> {
    let source = match cockpit_config::config::open_config_directory_nofollow(root) {
        Ok(source) => source,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening knowledge base source {}", root.display()));
        }
    };
    let sealed_id = sealed_knowledge_base_identity_from_retained_source(root, &source, vault)?;
    let documents =
        cockpit_config::config::snapshot_markdown_tree_from_retained_directory_nofollow(
            &source,
            MAX_KNOWLEDGE_FILES,
            MAX_KNOWLEDGE_ENTRIES,
            MAX_KNOWLEDGE_DEPTH,
            MAX_KNOWLEDGE_FILE_BYTES,
            MAX_KNOWLEDGE_TOTAL_BYTES,
        )
        .with_context(|| format!("snapshotting knowledge base source {}", root.display()))?;
    Ok(Some((
        parse_bundle_snapshot(root.to_path_buf(), documents, &source)?,
        sealed_id,
    )))
}

fn sealed_knowledge_base_identity(
    entry: &KnowledgeBaseRegistryEntry,
    vault: &crate::secure_key::SecretVault,
) -> Result<crate::sealed::SealedKnowledgeBaseId> {
    let KnowledgeBaseSource::Local { path } = &entry.source else {
        return crate::sealed::SealedKnowledgeBaseId::from_attachment_id(entry.attachment_id());
    };
    let root = match std::fs::canonicalize(path) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return crate::sealed::SealedKnowledgeBaseId::from_attachment_id(uuid::Uuid::new_v4());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("resolving knowledge base source {}", path.display()));
        }
    };
    if !std::fs::metadata(&root)
        .with_context(|| format!("reading knowledge base source {}", root.display()))?
        .is_dir()
    {
        bail!(
            "knowledge base source {} is not a directory",
            root.display()
        );
    }
    let source = cockpit_config::config::open_config_directory_nofollow(&root)
        .with_context(|| format!("opening knowledge base source {}", root.display()))?;
    sealed_knowledge_base_identity_from_retained_source(&root, &source, vault)
}

fn sealed_knowledge_base_identity_from_retained_source(
    root: &Path,
    source: &std::fs::File,
    vault: &crate::secure_key::SecretVault,
) -> Result<crate::sealed::SealedKnowledgeBaseId> {
    if !cockpit_config::config::directory_handle_matches_path(source, root)? {
        bail!(
            "knowledge base source {} was replaced while resolving its sealed identity",
            root.display()
        );
    }
    read_sealed_knowledge_base_marker_from_retained_source(root, source, vault)?.map_or_else(
        || crate::sealed::SealedKnowledgeBaseId::from_attachment_id(uuid::Uuid::new_v4()),
        crate::sealed::SealedKnowledgeBaseId::from_attachment_id,
    )
}

/// Return the KB namespace after durably assigning one when the Owner/model
/// first authors a sealed value. This is the only mutation of the marker: KB
/// reads never create state and therefore cannot bless a replacement object.
fn ensure_sealed_knowledge_base_identity(
    entry: &KnowledgeBaseRegistryEntry,
    vault: &crate::secure_key::SecretVault,
) -> Result<crate::sealed::SealedKnowledgeBaseId> {
    let KnowledgeBaseSource::Local { path } = &entry.source else {
        return crate::sealed::SealedKnowledgeBaseId::from_attachment_id(entry.attachment_id());
    };
    let root = std::fs::canonicalize(path)
        .with_context(|| format!("resolving knowledge base source {}", path.display()))?;
    if !std::fs::metadata(&root)
        .with_context(|| format!("reading knowledge base source {}", root.display()))?
        .is_dir()
    {
        bail!(
            "knowledge base source {} is not a directory",
            root.display()
        );
    }
    let source = cockpit_config::config::open_config_directory_nofollow(&root)
        .with_context(|| format!("opening knowledge base source {}", root.display()))?;
    if !cockpit_config::config::directory_handle_matches_path(&source, &root)? {
        bail!(
            "knowledge base source {} was replaced while assigning its sealed identity",
            root.display()
        );
    }
    if let Some(id) = read_sealed_knowledge_base_marker_from_retained_source(&root, &source, vault)?
    {
        return crate::sealed::SealedKnowledgeBaseId::from_attachment_id(id);
    }

    let marker = sealed_knowledge_base_marker_path(&root);
    let generated = uuid::Uuid::new_v4();
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
    {
        Ok(mut file) => {
            if !cockpit_config::config::directory_handle_matches_path(&source, &root)? {
                bail!(
                    "knowledge base source {} was replaced while assigning its sealed identity",
                    root.display()
                );
            }
            file.write_all(SEALED_KNOWLEDGE_BASE_MARKER_VERSION.as_bytes())?;
            file.write_all(b"\n")?;
            file.write_all(generated.to_string().as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            let marker_identity = sealed_marker_object_identity(&file)?;
            let binding =
                sealed_knowledge_base_marker_binding(&root, &source, marker_identity, generated)?;
            let tag = vault.keyed_identity(SEALED_KNOWLEDGE_BASE_MARKER_BINDING_DOMAIN, &binding);
            file.write_all(crate::intel::hex_lower(&tag).as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            sync_sealed_knowledge_base_marker_directory(&source, &root)?;
            if !cockpit_config::config::directory_handle_matches_path(&source, &root)? {
                bail!(
                    "knowledge base source {} was replaced while assigning its sealed identity",
                    root.display()
                );
            }
            crate::sealed::SealedKnowledgeBaseId::from_attachment_id(generated)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_sealed_knowledge_base_marker_from_retained_source(
                &root, &source, vault,
            )?
            .context(
                "knowledge-base sealed identity marker appeared but is not a regular marker file",
            )?;
            crate::sealed::SealedKnowledgeBaseId::from_attachment_id(existing)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "creating knowledge-base sealed identity marker {}",
                marker.display()
            )
        }),
    }
}

fn sealed_knowledge_base_marker_path(root: &Path) -> PathBuf {
    root.join(SEALED_KNOWLEDGE_BASE_ID_FILE)
}

fn read_sealed_knowledge_base_marker_from_retained_source(
    root: &Path,
    source: &std::fs::File,
    vault: &crate::secure_key::SecretVault,
) -> Result<Option<uuid::Uuid>> {
    let (raw, marker_identity) =
        match cockpit_config::config::read_config_leaf_from_retained_directory_with_identity(
            source,
            std::ffi::OsStr::new(SEALED_KNOWLEDGE_BASE_ID_FILE),
            1024,
        ) {
            Ok(value) => value,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => {
                return Err(error).context("reading knowledge-base sealed identity marker");
            }
        };
    let raw =
        String::from_utf8(raw).context("knowledge-base sealed identity marker is not UTF-8")?;
    let mut lines = raw.split_terminator('\n');
    let version = lines
        .next()
        .context("knowledge-base sealed identity marker version is missing")?;
    let id = lines
        .next()
        .context("knowledge-base sealed identity marker UUID is missing")?;
    let tag = lines
        .next()
        .context("knowledge-base sealed identity marker binding is missing")?;
    if version != SEALED_KNOWLEDGE_BASE_MARKER_VERSION
        || lines.next().is_some()
        || !raw.ends_with('\n')
        || raw.contains('\r')
    {
        bail!("knowledge-base sealed identity marker has invalid content");
    }
    let id = uuid::Uuid::parse_str(id)
        .context("knowledge-base sealed identity marker must contain a UUID")?;
    let binding = sealed_knowledge_base_marker_binding(root, source, marker_identity, id)?;
    let expected = crate::intel::hex_lower(
        &vault.keyed_identity(SEALED_KNOWLEDGE_BASE_MARKER_BINDING_DOMAIN, &binding),
    );
    if tag != expected {
        bail!(
            "knowledge-base sealed identity marker does not belong to this source object; remove it before authoring a new sealed value"
        );
    }
    Ok(Some(id))
}

/// Build the authenticated evidence for the exact source object that owns a
/// marker. The random namespace is never derived from these mutable platform
/// identifiers; they only make a copied marker fail validation. Binding both
/// directory and marker objects also turns an inode-reuse event into a paired
/// ABA condition rather than a namespace derivation.
fn sealed_knowledge_base_marker_binding(
    root: &Path,
    source: &std::fs::File,
    marker_identity: cockpit_config::config::TerminalIngressFileIdentity,
    id: uuid::Uuid,
) -> Result<Vec<u8>> {
    let mut binding = b"flycockpit/knowledge-base-sealed-marker-binding/v1\0".to_vec();
    append_attachment_identity_component(&mut binding, root.to_string_lossy().as_bytes());
    append_attachment_identity_component(&mut binding, id.as_bytes());
    append_sealed_marker_object_identity(&mut binding, sealed_marker_object_identity(source)?);
    append_sealed_marker_object_identity(&mut binding, marker_identity);
    Ok(binding)
}

fn append_sealed_marker_object_identity(
    binding: &mut Vec<u8>,
    identity: cockpit_config::config::TerminalIngressFileIdentity,
) {
    binding.extend_from_slice(&identity.volume.to_le_bytes());
    binding.extend_from_slice(&identity.file.to_le_bytes());
}

fn sealed_marker_object_identity(
    file: &std::fs::File,
) -> Result<cockpit_config::config::TerminalIngressFileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = file.metadata()?;
        return Ok(cockpit_config::config::TerminalIngressFileIdentity {
            volume: metadata.dev(),
            file: metadata.ino(),
            links: metadata.nlink().try_into().unwrap_or(u32::MAX),
        });
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
            .context("querying held Windows knowledge-base marker identity")?;
        return Ok(cockpit_config::config::TerminalIngressFileIdentity {
            volume: u64::from(information.dwVolumeSerialNumber),
            file: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
            links: information.nNumberOfLinks,
        });
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        bail!(
            "knowledge-base sealed markers require filesystem object identities on this platform"
        );
    }
}

fn sync_sealed_knowledge_base_marker_directory(root: &std::fs::File, display: &Path) -> Result<()> {
    root.sync_all().with_context(|| {
        format!(
            "fsync knowledge base source directory {}",
            display.display()
        )
    })
}

fn validate_dream_models(
    extended: &ExtendedConfig,
    providers: &crate::config::providers::ProvidersConfig,
) -> Result<()> {
    cockpit_config::config::extended::validate_knowledge_base_registry(
        &extended.knowledge_bases,
        providers,
    )
}

#[derive(Debug)]
struct ResolvedLocalKnowledgeBase {
    id: String,
    root: PathBuf,
    trust_required: bool,
}

/// Resolve the local portion of the effective registry for a native tool
/// frame. Remote knowledge bases intentionally contribute no filesystem
/// capability: they remain available only through retrieval tools.
async fn resolved_local_knowledge_bases(ctx: &ToolCtx) -> Result<Vec<ResolvedLocalKnowledgeBase>> {
    let mut registry = Vec::with_capacity(ctx.config.extended().knowledge_bases.len() + 1);
    // Native filesystem admission must not make every ordinary tool operation
    // depend on an assistant snapshot read. The snapshot is an additional KB
    // source, not a prerequisite for using unrelated workspace files. A
    // successfully resolved source is still fenced below; an unavailable one
    // cannot contribute a filesystem capability.
    match assistant_knowledge_registry_entry(&ctx.session).await {
        Ok(Some(assistant)) => registry.push(assistant.entry),
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, "ignoring unavailable assistant knowledge source for native path policy")
        }
    }
    registry.extend(ctx.config.extended().knowledge_bases.iter().cloned());

    let mut local = Vec::new();
    for entry in registry {
        let KnowledgeBaseSource::Local { path } = entry.source else {
            continue;
        };
        let root = if path.is_absolute() {
            path
        } else {
            ctx.cwd.join(path)
        };
        // A dangling source must not brick a read of an unrelated path. Keep
        // its lexical root in the policy so a target beneath that configured
        // path remains fail-closed; once the source becomes resolvable the
        // normal symlink-aware effective path replaces this fallback.
        let root = crate::tools::sandbox::effective_native_path(&root).unwrap_or(root);
        local.push(ResolvedLocalKnowledgeBase {
            id: entry.id,
            root,
            trust_required: entry.trust_required,
        });
    }
    Ok(local)
}

fn native_knowledge_base_permitted(
    ctx: &ToolCtx,
    knowledge_base: &ResolvedLocalKnowledgeBase,
) -> bool {
    !ctx.allowed_knowledge_bases
        .as_ref()
        .is_some_and(|allowed| !allowed.contains(&knowledge_base.id))
        && (!knowledge_base.trust_required || ctx.executing_model_trusted)
}

/// Return the registry-resolved local roots that the calling agent may read.
/// This is intentionally a read-only capability: native writes continue
/// through the ordinary path-approval and write gates.
pub(crate) async fn attached_local_knowledge_roots(ctx: &ToolCtx) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    for knowledge_base in resolved_local_knowledge_bases(ctx).await? {
        if !native_knowledge_base_permitted(ctx, &knowledge_base) {
            continue;
        }
        if !roots.iter().any(|root| root == &knowledge_base.root) {
            roots.push(knowledge_base.root);
        }
    }
    Ok(roots)
}

/// Return every registry-resolved local root that is not a native read
/// capability for this frame. Recursive native tools use this to keep a walk
/// rooted in the workspace from crossing into a nested, withheld KB.
pub(crate) async fn denied_native_local_knowledge_roots(ctx: &ToolCtx) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    for knowledge_base in resolved_local_knowledge_bases(ctx).await? {
        if !native_knowledge_base_permitted(ctx, &knowledge_base)
            && !roots.iter().any(|root| root == &knowledge_base.root)
        {
            roots.push(knowledge_base.root);
        }
    }
    Ok(roots)
}

/// Validate a native path that falls under a configured local KB. Returns
/// whether the path is in an attached local KB so the native sandbox can add
/// that root to its implicit read set. A configured but non-attached KB is a
/// hard refusal and therefore cannot be reached through a path approval.
pub(crate) async fn check_native_local_knowledge_path_access(
    ctx: &ToolCtx,
    path: &Path,
) -> Result<bool> {
    let mut attached = false;
    for knowledge_base in resolved_local_knowledge_bases(ctx).await? {
        if !cockpit_host::path_containment::contained_under(&knowledge_base.root, path) {
            continue;
        }
        if ctx
            .allowed_knowledge_bases
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&knowledge_base.id))
        {
            bail!(
                "access denied: `{}` is in local knowledge base `{}` which is not attached to this agent",
                path.display(),
                knowledge_base.id
            );
        }
        if knowledge_base.trust_required && !ctx.executing_model_trusted {
            bail!(
                "access denied: `{}` is in a local knowledge base that requires a trusted model",
                path.display()
            );
        }
        // Overlapping KB roots are an intersection of capabilities. A later
        // containing root may be restricted even when an earlier one is not.
        attached = true;
    }
    Ok(attached)
}

/// Return local KB roots withheld from this native/shell frame. The result is
/// shared by opaque-host and shell confinement gates so a source that is not
/// attached to this agent (or requires a trusted executor) cannot be reached
/// through an ordinary filesystem surface.
pub(crate) fn denied_local_knowledge_roots(ctx: &ToolCtx) -> Result<Vec<PathBuf>> {
    denied_local_knowledge_roots_for_model(
        &ctx.cwd,
        &ctx.config.extended(),
        ctx.allowed_knowledge_bases.as_ref(),
        ctx.executing_model_trusted,
    )
}

/// Return every configured local KB root. Shell execution uses this separate
/// write fence: an attached source may be readable there, but generic shell
/// writes must never mutate a KB outside the dream/human-owned paths.
pub(crate) fn configured_local_knowledge_roots(
    cwd: &Path,
    extended: &ExtendedConfig,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for entry in &extended.knowledge_bases {
        let KnowledgeBaseSource::Local { path } = &entry.source else {
            continue;
        };
        let root = if path.is_absolute() {
            path.clone()
        } else {
            cwd.join(path)
        };
        let root = crate::tools::sandbox::effective_native_path(&root).unwrap_or(root);
        if !roots.iter().any(|existing| existing == &root) {
            roots.push(root);
        }
    }
    roots
}

/// Return canonical local KB roots withheld from a model without requiring a
/// full tool context. Driver-owned execution paths (for example scheduled
/// shell jobs) use this before a [`ToolCtx`] exists.
pub(crate) fn denied_local_knowledge_roots_for_model(
    cwd: &Path,
    extended: &ExtendedConfig,
    allowed_knowledge_bases: Option<&BTreeSet<String>>,
    executing_model_trusted: bool,
) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    for entry in &extended.knowledge_bases {
        if !allowed_knowledge_bases.is_some_and(|allowed| !allowed.contains(&entry.id))
            && (!entry.trust_required || executing_model_trusted)
        {
            continue;
        }
        let KnowledgeBaseSource::Local { path } = &entry.source else {
            continue;
        };
        let root = if path.is_absolute() {
            path.clone()
        } else {
            cwd.join(path)
        };
        let root = crate::tools::sandbox::effective_native_path(&root).unwrap_or(root);
        if !roots.iter().any(|existing| existing == &root) {
            roots.push(root);
        }
    }
    Ok(roots)
}

/// Reject a direct native filesystem operation on a protected KB source.
pub(crate) fn ensure_local_knowledge_path_access(ctx: &ToolCtx, path: &Path) -> Result<()> {
    for root in denied_local_knowledge_roots(ctx)? {
        if cockpit_host::path_containment::contained_under(&root, path) {
            bail!(
                "access denied: `{}` is in a local knowledge base that requires a trusted model",
                path.display()
            );
        }
    }
    Ok(())
}

/// Reject a local media path that resolves inside a protected KB before the
/// media authority opens its held descriptor. Media path sources are always
/// relative to the session project root; unlike ordinary native tools, they do
/// not pass through `check_native_access`.
pub(crate) fn ensure_local_knowledge_media_path_access(ctx: &ToolCtx, path: &str) -> Result<()> {
    let path = Path::new(path);
    // Match the local media authority's lexical policy. It rejects absolute,
    // dot, and parent components itself, so leave those invalid spellings to
    // that existence-hiding admission path rather than probing them here.
    if path
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Ok(());
    }
    let candidate = ctx.session.project_root.join(path);
    let effective = crate::tools::sandbox::effective_native_path(&candidate).map_err(|error| {
        anyhow::anyhow!(
            "cannot resolve local media source `{}` for knowledge-base access: {error}",
            path.display()
        )
    })?;
    ensure_local_knowledge_path_access(ctx, &effective)
}

/// Workspace-wide inspection and opaque host-proxy tools cannot safely prove
/// which files a model-authored request will touch before it executes. Deny
/// their entire operation whenever that root contains a trust-required local
/// KB. Targeted native tools use [`ensure_local_knowledge_path_access`]
/// instead.
pub(crate) fn ensure_workspace_tool_access(ctx: &ToolCtx, tool_name: &str) -> Result<()> {
    const UNBOUNDED_HOST_ACCESS_TOOLS: &[&str] = &[
        "code",
        "context_pack",
        "change_impact",
        "circular",
        "deps",
        "glob",
        "graph",
        "grep",
        "hot",
        "harness_invoke",
        // An MCP script can invoke any configured third-party server. The
        // server's runtime capability is not knowable from the outer script,
        // so this is an opaque host-filesystem proxy just like a workspace
        // walker when a local KB requires a trusted model.
        "mcp",
        "search",
        "symbol_find",
        "tree",
        "word",
        "worktree_orchestrate",
    ];
    if UNBOUNDED_HOST_ACCESS_TOOLS.contains(&tool_name)
        && !denied_local_knowledge_roots(ctx)?.is_empty()
    {
        bail!(
            "access denied: `{tool_name}` cannot inspect this workspace because it contains a local knowledge base that requires a trusted model"
        );
    }
    Ok(())
}

/// Reject MCP server access for an untrusted model when a configured local KB
/// requires a trusted model. A configured server is arbitrary host code: its
/// initialization, discovery, and tool calls can all inspect the filesystem,
/// so this must fence the connection boundary rather than only named tools.
pub(crate) fn ensure_mcp_host_access(ctx: &ToolCtx) -> Result<()> {
    if denied_local_knowledge_roots(ctx)?.is_empty() {
        return Ok(());
    }
    bail!(
        "access denied: MCP is unavailable because this workspace contains a local knowledge base that requires a trusted model"
    );
}

/// Resolve a workspace-local KB to the filesystem object that owns it.
///
/// The identity includes the canonical target so symlink spelling is never the
/// identity, a stable identity of the target directory, and a digest of the
/// bounded Markdown snapshot the KB actually serves. A dream writer records
/// its boundary after committing its KB output, so it binds that boundary to
/// the resulting source snapshot. An unrelated replacement, whether it swaps
/// the directory, changes a symlink target, or rewrites the source in place,
/// therefore cannot inherit the predecessor's boundary. A missing root is
/// unavailable rather than a ledger lookup candidate.
fn local_source_attachment_identity(root: &Path) -> Result<Option<(PathBuf, uuid::Uuid)>> {
    let root = match std::fs::canonicalize(root) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("resolving local knowledge base source {}", root.display())
            });
        }
    };
    let source = cockpit_config::config::open_config_directory_nofollow(&root)
        .with_context(|| format!("opening local knowledge base source {}", root.display()))?;
    if !cockpit_config::config::directory_handle_matches_path(&source, &root)? {
        bail!(
            "local knowledge base source {} was replaced while attaching it",
            root.display()
        );
    }
    let metadata = source
        .metadata()
        .with_context(|| format!("reading local knowledge base source {}", root.display()))?;
    if !metadata.is_dir() {
        bail!(
            "local knowledge base source {} is not a directory",
            root.display()
        );
    }

    let mut name = b"flycockpit/knowledge-local-attachment/v2\0".to_vec();
    append_attachment_identity_component(&mut name, root.to_string_lossy().as_bytes());

    let source_identity = sealed_marker_object_identity(&source)?;
    name.extend_from_slice(&source_identity.volume.to_le_bytes());
    name.extend_from_slice(&source_identity.file.to_le_bytes());
    let mut documents =
        cockpit_config::config::snapshot_markdown_tree_from_retained_directory_nofollow(
            &source,
            MAX_KNOWLEDGE_FILES,
            MAX_KNOWLEDGE_ENTRIES,
            MAX_KNOWLEDGE_DEPTH,
            MAX_KNOWLEDGE_FILE_BYTES,
            MAX_KNOWLEDGE_TOTAL_BYTES,
        )
        .with_context(|| {
            format!(
                "snapshotting local knowledge base source {}",
                root.display()
            )
        })?;
    documents.sort_by(|(left, _), (right, _)| left.cmp(right));
    let mut source_fingerprint = Sha256::new();
    source_fingerprint.update(b"flycockpit/knowledge-local-source/v1\0");
    for (path, body) in documents {
        update_attachment_identity_component(
            &mut source_fingerprint,
            path.to_string_lossy().as_bytes(),
        );
        update_attachment_identity_component(&mut source_fingerprint, body.as_bytes());
    }
    let source_fingerprint: [u8; 32] = source_fingerprint.finalize().into();
    name.extend_from_slice(&source_fingerprint);

    Ok(Some((
        root,
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, &name),
    )))
}

fn append_attachment_identity_component(name: &mut Vec<u8>, component: &[u8]) {
    name.extend_from_slice(&(component.len() as u64).to_le_bytes());
    name.extend_from_slice(component);
}

fn update_attachment_identity_component(hasher: &mut Sha256, component: &[u8]) {
    hasher.update((component.len() as u64).to_le_bytes());
    hasher.update(component);
}

/// Production dream-write entry point. The daemon's dream executor supplies
/// its validated OKF mutation here; this function resolves the same
/// workspace/agent registry as retrieval and dispatches through `KbProvider`.
/// Consequently a local dream cannot bypass the Git fence, and a hosted KB
/// fails closed until its provider implements the hosted write contract.
pub(crate) async fn apply_registered_knowledge_dream<F>(
    session: &Session,
    cwd: &Path,
    allowed_knowledge_bases: Option<&BTreeSet<String>>,
    extended: &ExtendedConfig,
    knowledge_access_trusted: bool,
    dream: &KnowledgeDreamCommit,
    cancel: CancellationToken,
    mutation: F,
) -> Result<KnowledgeDreamGitOutcome>
where
    F: Fn(&Path) -> Result<()> + Send + Sync + 'static,
{
    if cancel.is_cancelled() {
        bail!("knowledge dream write cancelled before resolving its provider");
    }
    let bundles = attached_bundles(
        session,
        cwd,
        allowed_knowledge_bases,
        extended,
        knowledge_access_trusted,
    )
    .await?;
    let knowledge_base = bundles
        .bundles
        .into_iter()
        .find(|knowledge_base| knowledge_base.entry.id == dream.knowledge_base_id)
        .with_context(|| {
            format!(
                "dream target knowledge base `{}` is not attached to this workspace/agent",
                dream.knowledge_base_id
            )
        })?;
    let provider = knowledge_base.provider;
    let dream = dream.clone();
    tokio::task::spawn_blocking(move || {
        provider.apply_dream(&dream, &ClosureKnowledgeDreamMutation(mutation), &cancel)
    })
    .await
    .context("knowledge dream write task terminated before completing")?
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
    snapshot: Option<KnowledgeBundle>,
    sidecars: Option<KbSidecars>,
}

fn workspace_knowledge_base(entry: KnowledgeBaseRegistryEntry) -> RegistryKnowledgeBase {
    let local = match &entry.source {
        KnowledgeBaseSource::Local { path } => Some(RegistryLocalKb {
            root: path.clone(),
            assistant_snapshot_root: None,
            snapshot: None,
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
    assistant_knowledge_registry_entry_from_row(&snapshot.row).map(Some)
}

/// Session creation already owns the database connection that will store the
/// frozen snapshot, so it cannot re-enter the async assistant snapshot
/// coordinator. It still resolves the assistant registry entry through the
/// same validated row-to-entry conversion used by live retrieval.
fn assistant_knowledge_registry_entry_for_session_start(
    conn: &rusqlite::Connection,
    name: Option<&str>,
) -> Result<Option<RegistryKnowledgeBase>> {
    let Some(name) = name else {
        return Ok(None);
    };
    crate::assistants::validate_assistant_name(name)?;
    let row = crate::db::Db::get_assistant_conn(conn, name)?.with_context(|| {
        format!("assistant `{name}` disappeared while capturing knowledge snapshot")
    })?;
    assistant_knowledge_registry_entry_from_row(&row).map(Some)
}

fn assistant_knowledge_registry_entry_from_row(
    row: &cockpit_db::assistants::AssistantRow,
) -> Result<RegistryKnowledgeBase> {
    let root = crate::assistants::validate_row_home(row)?.join("knowledge");
    let config: crate::assistants::AssistantConfig = serde_json::from_str(&row.config_json)
        .context("parsing assistant identity for knowledge cache")?;
    if config.installation_id.is_nil() {
        bail!("assistant knowledge has no installation identity");
    }
    let cache_root = crate::config::resolve::cockpit_data_dir()?.join("knowledge-indexes");
    cockpit_host::private_fs::ensure_private_dir(&cache_root)?;
    let entry = KnowledgeBaseRegistryEntry::new(
        format!("assistant-{}", config.installation_id),
        format!("Assistant: {}", row.name),
        format!("Knowledge installed with assistant `{}`.", row.name),
        KnowledgeBaseSource::Local { path: root.clone() },
        KnowledgeBaseEmbeddingOwnership::Local,
        None,
        None,
        false,
        KnowledgeBaseMergePolicy::Auto,
    )
    .with_bound_attachment_identity(config.installation_id);
    Ok(RegistryKnowledgeBase {
        entry,
        local: Some(RegistryLocalKb {
            root,
            assistant_snapshot_root: Some(PathBuf::from(format!(
                "assistant://{}/knowledge",
                row.name
            ))),
            snapshot: None,
            sidecars: Some(KbSidecars::in_root(
                &cache_root.join(config.installation_id.to_string()),
            )),
        }),
    })
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
            let has_assistant_snapshot_root = local.assistant_snapshot_root.is_some();
            let snapshot = local
                .snapshot
                .context("local knowledge provider has no retained source snapshot")?;
            let snapshot = if let Some(snapshot_root) = local.assistant_snapshot_root {
                KnowledgeBundle {
                    root: snapshot_root,
                    ..snapshot
                }
            } else {
                snapshot
            };
            let sidecars = local
                .sidecars
                .context("local knowledge provider has no sidecar paths")?;
            Ok(Some(Arc::new(LocalKb::new(
                entry,
                local.root,
                Some(snapshot),
                sidecars,
                None,
                has_assistant_snapshot_root,
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
    executing_model: &str,
    executing_model_trusted: bool,
) -> crate::engine::tool::ToolBox {
    let allowed_knowledge_bases = definition
        .and_then(crate::agents::AgentDef::allowed_knowledge_bases)
        .cloned();
    // Keep the search schema present for the whole agent lifetime. Attachment
    // state is deliberately resolved in `MemorySearchTool::call`, where an
    // absent bundle produces the normal content-free availability result
    // instead of churning the provider's cacheable tools array.
    let toolbox = toolbox.with(Arc::new(MemorySearchTool {
        allowed_knowledge_bases: allowed_knowledge_bases.clone(),
    }));
    let extended = config.extended();
    let dream_writes_enabled = attached_bundles(
        session,
        cwd,
        allowed_knowledge_bases.as_ref(),
        &extended,
        executing_model_trusted,
    )
    .await
    .is_ok_and(|bundles| {
        bundles.bundles.iter().any(|knowledge_base| {
            knowledge_base.entry.dream_model.as_deref() == Some(executing_model)
                && matches!(
                    &knowledge_base.entry.source,
                    KnowledgeBaseSource::Local { .. }
                )
        })
    });
    if dream_writes_enabled && definition.is_some_and(|definition| definition.name == "Dream") {
        toolbox
            .with(Arc::new(KnowledgeDreamApplyTool {
                allowed_knowledge_bases: allowed_knowledge_bases.clone(),
                executing_model: executing_model.to_string(),
            }))
            .with(Arc::new(KnowledgeDreamSourcesTool {
                allowed_knowledge_bases,
                executing_model: executing_model.to_string(),
            }))
    } else {
        toolbox
            .without(KNOWLEDGE_DREAM_SOURCES_TOOL_NAME)
            .without(KNOWLEDGE_DREAM_APPLY_TOOL_NAME)
    }
}

fn knowledge_access_denied_message(knowledge_base_ids: &[String]) -> String {
    format!(
        "Access denied: local knowledge base(s) {} require a trusted model.",
        knowledge_base_ids.join(", ")
    )
}

/// A turn-toolbox instance binds the executing agent definition's KB
/// restriction.  The tool can therefore refresh workspace configuration at
/// call time without re-resolving a mutable, same-named agent definition.
pub(crate) struct MemorySearchTool {
    allowed_knowledge_bases: Option<BTreeSet<String>>,
}

/// The production model-facing dream executor.  It accepts a complete,
/// validated OKF projection rather than a filesystem path, and invokes the
/// registered-provider boundary so local writes always pass through the Git
/// transaction/fence.  It is advertised only for attached local KBs that
/// configure the model executing this turn.
pub(crate) struct KnowledgeDreamApplyTool {
    allowed_knowledge_bases: Option<BTreeSet<String>>,
    executing_model: String,
}

pub(crate) struct KnowledgeDreamSourcesTool {
    allowed_knowledge_bases: Option<BTreeSet<String>>,
    executing_model: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KnowledgeDreamSourcesArgs {
    knowledge_base_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KnowledgeDreamApplyArgs {
    knowledge_base_id: String,
    source_session_ids: Vec<uuid::Uuid>,
    writes: Vec<KnowledgeDreamWrite>,
}

#[derive(Debug, Clone, Deserialize)]
struct KnowledgeDreamWrite {
    path: String,
    content: String,
}

#[async_trait]
impl Tool for KnowledgeDreamSourcesTool {
    fn name(&self) -> &str {
        KNOWLEDGE_DREAM_SOURCES_TOOL_NAME
    }

    fn description(&self) -> &str {
        "List the consent-attached sessions that still need to be dreamed"
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": { "knowledgeBaseId": { "type": "string" } },
            "required": ["knowledgeBaseId"],
            "additionalProperties": false
        })
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: KnowledgeDreamSourcesArgs = typed_args(args)?;
        let extended = ctx.config.extended();
        let providers = ctx.config.providers();
        let bundles = attached_bundles(
            &ctx.session,
            &ctx.cwd,
            self.allowed_knowledge_bases.as_ref(),
            &extended,
            ctx.knowledge_access_trusted,
        )
        .await?;
        let knowledge_base = bundles
            .bundles
            .iter()
            .find(|bundle| bundle.entry.id == args.knowledge_base_id)
            .context("dream target knowledge base is not attached")?;
        let model = dream::resolve_dream_model(&knowledge_base.entry, &extended, &providers)?;
        ensure!(
            model.reference() == self.executing_model,
            "knowledge base `{}` must dream with `{}`",
            knowledge_base.entry.id,
            model.reference()
        );
        let consumer = ctx.session.db.ensure_installation_identity().await?;
        let project_root = dream::CanonicalDreamProjectRoot::from_session_path(&ctx.cwd)?;
        ctx.session
            .acquire_dream_run_fence(&project_root, &knowledge_base.entry.id, &ctx.cancel)
            .await?;
        let mut sources = ctx
            .session
            .db
            .undreamed_sessions_for_knowledge_base(
                &knowledge_base.entry.id,
                project_root.as_str(),
                consumer.as_hex(),
                dream::history_caller_trust(&model, &providers),
            )
            .await?;
        let redaction_base = ctx
            .session
            .with_machine_scoped_sealed_redactions(&ctx.redact)
            .await?;
        for source in &mut sources {
            let redactor = ctx
                .session
                .recall_redaction_table_from_base(&redaction_base, source.session_id)?;
            source.title = source.title.take().map(|title| redactor.scrub(&title));
            source.description = redactor.scrub(&source.description);
        }
        let ids = sources
            .iter()
            .map(|source| source.session_id)
            .collect::<BTreeSet<_>>();
        let output = serde_json::to_string_pretty(
            &sources
                .into_iter()
                .map(|source| {
                    json!({
                        "sessionId": source.session_id,
                        "title": source.title,
                        "description": source.description,
                        "lastActiveAtUnixMs": source.last_active_at_unix_ms,
                    })
                })
                .collect::<Vec<_>>(),
        )?;
        *ctx.dream_read_scope
            .write()
            .expect("dream read scope lock poisoned") = Some(ids);
        Ok(ToolOutput::text(output))
    }
}

#[async_trait]
impl Tool for KnowledgeDreamApplyTool {
    fn name(&self) -> &str {
        KNOWLEDGE_DREAM_APPLY_TOOL_NAME
    }

    fn description(&self) -> &str {
        "Commit validated dream-produced OKF files to an attached knowledge base"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Write the complete changed OKF concept/resource files from a completed knowledge dream. \
             The named KB must be attached and configured with a dream model. Submit exactly the \
             sourceSessionIds returned by knowledge_dream_sources, plus full contents for every \
             changed root-level file. The daemon \
             validates the resulting OKF bundle, records a structured Git commit when available, and \
             safely defers remote publication rather than force-pushing."
                .to_string(),
        )
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::Mutating
    }

    fn parameters(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "knowledgeBaseId": {
                    "type": "string",
                    "description": "Attached local knowledge base ID"
                },
                "sourceSessionIds": {
                    "type": "array",
                    "minItems": 1,
                    "items": { "type": "string", "format": "uuid" },
                    "description": "Exact source IDs returned by knowledge_dream_sources"
                },
                "writes": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Single root-level OKF .md or referenced .csv/.jsonl/.ndjson file"
                            },
                            "content": {
                                "type": "string",
                                "description": "Complete replacement contents for this file"
                            }
                        },
                        "required": ["path", "content"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["knowledgeBaseId", "sourceSessionIds", "writes"],
            "additionalProperties": false
        })
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: KnowledgeDreamApplyArgs = typed_args(args)?;
        if args.knowledge_base_id.trim().is_empty() {
            return Err(invalid_input(
                "knowledgeDreamApply knowledgeBaseId must not be empty",
            ));
        }
        if args.source_session_ids.is_empty() {
            return Err(invalid_input(
                "knowledgeDreamApply sourceSessionIds must not be empty",
            ));
        }
        let submitted_sources = args
            .source_session_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        ensure!(
            submitted_sources.len() == args.source_session_ids.len(),
            "knowledgeDreamApply sourceSessionIds must not contain duplicates"
        );
        let scoped_sources = crate::tools::session_search::established_dream_read_scope(ctx)?
            .context("knowledge_dream_apply requires a prior knowledge_dream_sources call")?;
        ensure!(
            scoped_sources == submitted_sources,
            "knowledge_dream_apply sourceSessionIds must exactly match the current consent scope"
        );
        let writes = validate_knowledge_dream_writes(args.writes)?;
        let extended = ctx.config.extended();
        let bundles = attached_bundles(
            &ctx.session,
            &ctx.cwd,
            self.allowed_knowledge_bases.as_ref(),
            &extended,
            ctx.knowledge_access_trusted,
        )
        .await?;
        /* Retrieval implementation is defined below beside the stable memory search surface.
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
                    boundary_knowledge_bases: Vec<String>,
                    oldest_boundary_session_event_seq: Option<i64>,
                    missing_boundary_knowledge_bases: Vec<String>,
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
                    let mut boundary_knowledge_bases = Vec::new();
                    let mut missing_boundary_knowledge_bases = Vec::new();
                    let mut oldest_boundary_session_event_seq = None;
                    for bundle in bundles {
                        match ctx
                            .session
                            .db
                            .knowledge_dream_boundary(crate::db::knowledge_dreams::KnowledgeDreamLedgerKey {
                                project_uuid,
                                knowledge_base_attachment_id: bundle.entry.attachment_id(),
                            })
                            .await?
                        {
                            Some(boundary) => {
                                boundary_knowledge_bases.push(bundle.entry.id.clone());
                                oldest_boundary_session_event_seq = Some(
                                    oldest_boundary_session_event_seq
                                        .map(|oldest: i64| oldest.min(boundary.last_dreamed_session_event_seq))
                                        .unwrap_or(boundary.last_dreamed_session_event_seq),
                                );
                            }
                            None => missing_boundary_knowledge_bases.push(bundle.entry.id.clone()),
                        }
                    }

                    // A missing ordering boundary is not evidence that history has been dreamed. On
                    // first use (and whenever any attached KB lacks a ledger row), search the
                    // project's matching session history conservatively instead of silently
                    // returning no fresh results. Once every attached KB has a boundary, the
                    // oldest exact event boundary safely bounds the shared candidate set.
                    let (after_session_event_seq, search_enabled) = if missing_boundary_knowledge_bases.is_empty() {
                        match oldest_boundary_session_event_seq {
                            // The DB predicate is strictly greater than this durable global
                            // event sequence. A later commit receives a greater sequence even
                            // when it shares the dream snapshot's millisecond timestamp.
                            Some(boundary) => (Some(boundary), true),
                            None => (None, false),
                        }
                    } else {
                        (None, true)
                    };
                    let hits = if search_enabled {
                        let pool = limit.saturating_mul(3).clamp(limit, 60) as u32;
                        let caller_trust = crate::tools::session_search::caller_history_trust(ctx);
                        let hits = match after_session_event_seq {
                            Some(boundary) => {
                                ctx.session
                                    .db
                                    .search_candidates_after_session_event_seq_for_trust(
                                        query,
                                        Some(ctx.session.project_id.as_str()),
                                        None,
                                        boundary,
                                        pool,
                                        caller_trust,
                                    )
                                    .await?
                            }
                            None => {
                                ctx.session
                                    .db
                                    .search_candidates_for_trust(
                                        query,
                                        Some(ctx.session.project_id.as_str()),
                                        None,
                                        None,
                                        pool,
                                        caller_trust,
                                    )
                                    .await?
                            }
                        };
                        hits.into_iter().take(limit).collect()
                    } else {
                        Vec::new()
                    };
                    Ok(FreshSessionRetrieval {
                        hits,
                        boundary_knowledge_bases,
                        oldest_boundary_session_event_seq,
                        missing_boundary_knowledge_bases,
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

                    if !freshness.missing_boundary_knowledge_bases.is_empty() {
                        out.push_str(
                            "Fresh-session staleness check: no dream ordering boundary is recorded for every attached KB, so a bounded set of matching sessions from this project was searched conservatively; no session history can yet be proven dreamed into those KBs.\n",
                        );
                        render_fresh_session_hits(&mut out, &freshness.hits);
                    } else {
                        match freshness.oldest_boundary_session_event_seq {
                            Some(boundary) => {
                                out.push_str(
                                    "Fresh-session staleness check: searched this project's sessions with events after dream boundary sequence ",
                                );
                                out.push_str(&boundary.to_string());
                                out.push_str(" for KB(s) ");
                                out.push_str(&freshness.boundary_knowledge_bases.join(", "));
                                out.push_str(". These sessions may not yet be dreamed into those KBs.\n");
                                render_fresh_session_hits(&mut out, &freshness.hits);
                            }
                            None => out.push_str(
                                "Fresh-session staleness check: no eligible fresh-session boundary is available.\n",
                            ),
                        }
                    }
                    if !freshness.missing_boundary_knowledge_bases.is_empty() {
                        out.push_str("KB(s) without a dream ordering boundary: ");
                        out.push_str(&freshness.missing_boundary_knowledge_bases.join(", "));
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
        */
        let knowledge_base = bundles
            .bundles
            .iter()
            .find(|knowledge_base| knowledge_base.entry.id == args.knowledge_base_id)
            .with_context(|| {
                format!(
                    "dream target knowledge base `{}` is not attached to this workspace/agent",
                    args.knowledge_base_id
                )
            })?;
        if !matches!(
            &knowledge_base.entry.source,
            KnowledgeBaseSource::Local { .. }
        ) {
            bail!(
                "remote knowledge-base dream writes are hosted and not implemented for `{}`",
                knowledge_base.entry.id
            );
        }
        let configured_model = knowledge_base
            .entry
            .dream_model
            .as_deref()
            .with_context(|| {
                format!(
                    "knowledge base `{}` has no configured dream model",
                    knowledge_base.entry.id
                )
            })?;
        if configured_model != self.executing_model {
            bail!(
                "knowledge base `{}` is configured to dream with `{configured_model}`, not the executing model `{}`",
                knowledge_base.entry.id,
                self.executing_model
            );
        }
        let concepts_written = writes
            .iter()
            .filter(|write| is_knowledge_dream_concept_path(&write.path))
            .count();
        let data_files_written = writes.len().saturating_sub(concepts_written);
        let dream = KnowledgeDreamCommit {
            knowledge_base_id: args.knowledge_base_id.clone(),
            model: self.executing_model.clone(),
            sessions_dreamed: args.source_session_ids.len(),
            concepts_written,
            data_files_written,
        };
        let project_root = dream::CanonicalDreamProjectRoot::from_session_path(&ctx.cwd)?;
        let run_fence = ctx
            .session
            .take_dream_run_fence(&project_root, &args.knowledge_base_id)?;
        let cancel = dream_write_cancellation(ctx);
        let session = ctx.session.clone();
        let cwd = ctx.cwd.clone();
        let allowed_knowledge_bases = self.allowed_knowledge_bases.clone();
        let knowledge_access_trusted = ctx.knowledge_access_trusted;
        let knowledge_base_id = args.knowledge_base_id;
        let source_session_ids = args.source_session_ids;
        // The provider write is blocking and can outlive a dispatcher timeout.
        // Keep the exact fence through the completion ledger in a detached task
        // so a second dream cannot select the same sources while it finishes.
        let apply = tokio::spawn(async move {
            let _run_fence = run_fence;
            let outcome = apply_registered_knowledge_dream(
                &session,
                &cwd,
                allowed_knowledge_bases.as_ref(),
                &extended,
                knowledge_access_trusted,
                &dream,
                cancel.cancel.clone(),
                move |root| apply_knowledge_dream_writes(root, &writes),
            )
            .await?;
            if !matches!(outcome, KnowledgeDreamGitOutcome::Deferred { .. }) {
                let consumer = session.db.ensure_installation_identity().await?;
                session
                    .db
                    .record_knowledge_dream_completion(
                        &knowledge_base_id,
                        project_root.as_str(),
                        consumer.as_hex(),
                        &source_session_ids,
                    )
                    .await?;
            }
            Ok::<_, anyhow::Error>(outcome)
        });
        let outcome = apply
            .await
            .context("knowledge dream owner task terminated before completion")??;
        Ok(render_knowledge_dream_outcome(outcome))
    }
}

struct DreamWriteCancellation {
    cancel: CancellationToken,
    shutdown_watcher: tokio::task::JoinHandle<()>,
}

impl Drop for DreamWriteCancellation {
    fn drop(&mut self) {
        self.shutdown_watcher.abort();
    }
}

fn dream_write_cancellation(ctx: &ToolCtx) -> DreamWriteCancellation {
    let cancel = ctx.cancel.child_token();
    let shutdown = ctx.shutdown_gate.clone();
    let shutdown_cancel = cancel.clone();
    let shutdown_watcher = tokio::spawn(async move {
        let mut updates = shutdown.subscribe();
        loop {
            if shutdown.is_draining() {
                shutdown_cancel.cancel();
                return;
            }
            if updates.changed().await.is_err() {
                shutdown_cancel.cancel();
                return;
            }
        }
    });
    DreamWriteCancellation {
        cancel,
        shutdown_watcher,
    }
}

fn validate_knowledge_dream_writes(
    writes: Vec<KnowledgeDreamWrite>,
) -> Result<Vec<KnowledgeDreamWrite>> {
    if writes.is_empty() {
        return Err(invalid_input(
            "knowledgeDreamApply writes must not be empty",
        ));
    }
    let mut paths = BTreeSet::new();
    let mut total_bytes = 0_usize;
    for write in &writes {
        let path = Path::new(&write.path);
        let mut components = path.components();
        let Some(std::path::Component::Normal(leaf)) = components.next() else {
            return Err(invalid_input(format!(
                "knowledgeDreamApply path `{}` must be a single file at the knowledge-base root",
                write.path
            )));
        };
        if components.next().is_some() || leaf != std::ffi::OsStr::new(&write.path) {
            return Err(invalid_input(format!(
                "knowledgeDreamApply path `{}` must be a single file at the knowledge-base root",
                write.path
            )));
        }
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !matches!(extension.as_str(), "md" | "csv" | "jsonl" | "ndjson") {
            return Err(invalid_input(format!(
                "knowledgeDreamApply path `{}` must end in .md, .csv, .jsonl, or .ndjson",
                write.path
            )));
        }
        if KB_MACHINE_STATE_GITIGNORE.contains(&write.path.as_str()) {
            return Err(invalid_input(format!(
                "knowledgeDreamApply path `{}` is reserved for machine-local state",
                write.path
            )));
        }
        if !paths.insert(write.path.clone()) {
            return Err(invalid_input(format!(
                "knowledgeDreamApply contains duplicate path `{}`",
                write.path
            )));
        }
        if write.content.len() > MAX_KNOWLEDGE_FILE_BYTES {
            return Err(invalid_input(format!(
                "knowledgeDreamApply file `{}` exceeds the knowledge file size limit",
                write.path
            )));
        }
        total_bytes = total_bytes
            .checked_add(write.content.len())
            .ok_or_else(|| {
                invalid_input(
                    "knowledgeDreamApply content length overflowed the knowledge size limit",
                )
            })?;
        if total_bytes > MAX_KNOWLEDGE_TOTAL_BYTES {
            return Err(invalid_input(
                "knowledgeDreamApply writes exceed the aggregate knowledge size limit",
            ));
        }
    }
    Ok(writes)
}

fn is_knowledge_dream_concept_path(path: &str) -> bool {
    path.ends_with(".md") && !matches!(path, "index.md" | "log.md")
}

fn apply_knowledge_dream_writes(root: &Path, writes: &[KnowledgeDreamWrite]) -> Result<()> {
    // Git provides the rollback boundary for a tracked KB.  Git is optional,
    // though, so preserve the exact pre-write file set here as well: a later
    // write failure or a failed OKF validation must not leave a Git-absent KB
    // partially projected.
    let rollback = KnowledgeDreamWriteRollback::capture(root, writes)?;
    let applied = (|| {
        for write in writes {
            fs::write(root.join(&write.path), &write.content)
                .with_context(|| format!("writing dream output {}", write.path))?;
        }
        // Validate in the transaction callback so malformed model output is
        // never retained as a partially applied KB.
        let versioned = versioned_knowledge_paths(root)?;
        for write in writes {
            if !versioned.contains(&PathBuf::from(&write.path)) {
                bail!(
                    "dream output {} is not a committed OKF document or referenced data file",
                    write.path
                );
            }
        }
        Ok(())
    })();
    if let Err(error) = applied {
        rollback.restore().with_context(|| {
            format!("dream output apply failed ({error:#}) and restoring the pre-dream write set")
        })?;
        return Err(error);
    }
    Ok(())
}

/// File-level rollback boundary for the production dream-write projection.
/// `KnowledgeDreamApplyArgs` permits only distinct root-level files, so this
/// captures precisely the paths the model is allowed to replace and never
/// touches derived sidecars or unrelated user files.
struct KnowledgeDreamWriteRollback {
    root: PathBuf,
    originals: BTreeMap<PathBuf, Option<Vec<u8>>>,
}

impl KnowledgeDreamWriteRollback {
    fn capture(root: &Path, writes: &[KnowledgeDreamWrite]) -> Result<Self> {
        let mut originals = BTreeMap::new();
        for write in writes {
            let path = PathBuf::from(&write.path);
            let target = root.join(&path);
            let contents = match fs::read(&target) {
                Ok(contents) => Some(contents),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("capturing pre-dream output {}", write.path));
                }
            };
            originals.insert(path, contents);
        }
        Ok(Self {
            root: root.to_path_buf(),
            originals,
        })
    }

    fn restore(self) -> Result<()> {
        for (path, contents) in self.originals {
            let target = self.root.join(&path);
            match contents {
                Some(contents) => fs::write(&target, contents)
                    .with_context(|| format!("restoring pre-dream output {}", path.display()))?,
                None => match fs::remove_file(&target) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("removing failed dream output {}", path.display())
                        });
                    }
                },
            }
        }
        Ok(())
    }
}

fn render_knowledge_dream_outcome(outcome: KnowledgeDreamGitOutcome) -> ToolOutput {
    let text = match outcome {
        KnowledgeDreamGitOutcome::Skipped { reason } => {
            format!("Knowledge dream applied; Git history was skipped: {reason}")
        }
        KnowledgeDreamGitOutcome::NoChanges { branch } => {
            format!("Knowledge dream produced no versioned changes on `{branch}`.")
        }
        KnowledgeDreamGitOutcome::Committed {
            commit,
            branch,
            pushed,
        } => format!(
            "Knowledge dream committed `{commit}` on `{branch}`{}.",
            if pushed { " and pushed it" } else { "" }
        ),
        KnowledgeDreamGitOutcome::Deferred {
            branch,
            commit,
            reason,
        } => format!(
            "Knowledge dream output was retained{}{}; synchronization deferred: {reason}",
            branch
                .as_deref()
                .map(|branch| format!(" on `{branch}`"))
                .unwrap_or_default(),
            commit
                .as_deref()
                .map(|commit| format!(" at `{commit}`"))
                .unwrap_or_default(),
        ),
    };
    ToolOutput::text(text)
}

/// Read-only retrieval surface used by the built-in `knowledge` specialist.
/// It combines cited KB matches with a bounded view of sessions that may have
/// advanced since the shared dream boundary.
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
            "Search attached knowledge bases through their configured providers and return cited results plus a bounded, trust-filtered view of sessions newer than the recorded dream boundary."
                .to_string(),
        )
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
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
        let providers = ctx.config.providers();
        validate_dream_models(&extended, &providers)?;
        let bundles = attached_bundles(
            &ctx.session,
            &ctx.cwd,
            self.allowed_knowledge_bases.as_ref(),
            &extended,
            ctx.knowledge_access_trusted,
        )
        .await?;
        if bundles.bundles.is_empty() {
            if !bundles.denied_knowledge_base_ids.is_empty() {
                return Err(anyhow::anyhow!(knowledge_access_denied_message(
                    &bundles.denied_knowledge_base_ids
                )));
            }
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
                    retrieve_from_knowledge_bases(
                        &bundles.bundles,
                        embedder,
                        &args.query,
                        limit,
                        Some(&crate::sealed::LocalVaultResolver::new(
                            ctx.session.secret_vault().clone(),
                        )),
                        ctx.knowledge_access_trusted,
                    )
                    .await?
                }
                None => Vec::new(),
            };
        let freshness =
            retrieve_undreamed_session_hits(&bundles.bundles, &args.query, limit, ctx).await?;
        Ok(ToolOutput::text(render_knowledge_retrieval(
            &results,
            &freshness,
            ctx.redact.as_ref(),
        )))
    }
}

struct FreshSessionRetrieval {
    hits: Vec<crate::db::session_search::SearchHit>,
    boundary_knowledge_bases: Vec<String>,
    oldest_boundary_session_event_seq: Option<i64>,
    missing_boundary_knowledge_bases: Vec<String>,
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
    let mut boundary_knowledge_bases = Vec::new();
    let mut missing_boundary_knowledge_bases = Vec::new();
    let mut oldest_boundary_session_event_seq = None;
    for bundle in bundles {
        match ctx
            .session
            .db
            .knowledge_dream_boundary(crate::db::knowledge_dreams::KnowledgeDreamLedgerKey {
                project_uuid,
                knowledge_base_attachment_id: bundle.entry.attachment_id(),
            })
            .await?
        {
            Some(boundary) => {
                boundary_knowledge_bases.push(bundle.entry.id.clone());
                oldest_boundary_session_event_seq = Some(
                    oldest_boundary_session_event_seq
                        .map(|oldest: i64| oldest.min(boundary.last_dreamed_session_event_seq))
                        .unwrap_or(boundary.last_dreamed_session_event_seq),
                );
            }
            None => missing_boundary_knowledge_bases.push(bundle.entry.id.clone()),
        }
    }
    let (after_session_event_seq, search_enabled) = if missing_boundary_knowledge_bases.is_empty() {
        match oldest_boundary_session_event_seq {
            Some(boundary) => (Some(boundary), true),
            None => (None, false),
        }
    } else {
        (None, true)
    };
    let hits = if search_enabled {
        let pool = limit.saturating_mul(3).clamp(limit, 60) as u32;
        let caller_trust = crate::tools::session_search::caller_history_trust(ctx);
        let hits = match after_session_event_seq {
            Some(boundary) => {
                ctx.session
                    .db
                    .search_candidates_after_session_event_seq_for_trust(
                        query,
                        Some(ctx.session.project_id.as_str()),
                        None,
                        boundary,
                        pool,
                        caller_trust,
                    )
                    .await?
            }
            None => {
                ctx.session
                    .db
                    .search_candidates_for_trust(
                        query,
                        Some(ctx.session.project_id.as_str()),
                        None,
                        None,
                        pool,
                        caller_trust,
                    )
                    .await?
            }
        };
        hits.into_iter().take(limit).collect()
    } else {
        Vec::new()
    };
    Ok(FreshSessionRetrieval {
        hits,
        boundary_knowledge_bases,
        oldest_boundary_session_event_seq,
        missing_boundary_knowledge_bases,
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
            out.push_str(&format!(
                "- {} — {} [{}]\n",
                result.concept_id,
                short_summary(&result.snippet),
                citation_label(result),
            ));
        }
    }
    match freshness.oldest_boundary_session_event_seq {
        Some(boundary) if freshness.missing_boundary_knowledge_bases.is_empty() => out.push_str(&format!(
            "Fresh-session staleness check: searched this project's sessions with events after dream boundary sequence {boundary} for KB(s) {}.\n",
            freshness.boundary_knowledge_bases.join(", "),
        )),
        _ => out.push_str("Fresh-session staleness check: no dream ordering boundary is recorded for every attached KB, so matching project sessions were searched conservatively.\n"),
    }
    if !freshness.missing_boundary_knowledge_bases.is_empty() {
        out.push_str("KB(s) without a dream ordering boundary: ");
        out.push_str(&freshness.missing_boundary_knowledge_bases.join(", "));
        out.push_str(".\n");
    }
    if freshness.hits.is_empty() {
        out.push_str("- No matching undreamed-session updates.\n");
    } else {
        out.push_str("Undreamed-session citations:\n");
        for hit in &freshness.hits {
            out.push_str(&format!(
                "- session {} — {} — {} [session ref: {}]\n",
                hit.short_id.as_deref().unwrap_or_default(),
                hit.title.as_deref().unwrap_or("(untitled)"),
                short_summary(&hit.snippet),
                hit.session_id,
            ));
        }
    }
    redact.scrub(&out)
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
        let providers = ctx.config.providers();
        validate_dream_models(&extended, &providers)?;
        let bundles = attached_bundles(
            &ctx.session,
            &ctx.cwd,
            self.allowed_knowledge_bases.as_ref(),
            &extended,
            ctx.knowledge_access_trusted,
        )
        .await?;
        if bundles.bundles.is_empty() {
            if !bundles.denied_knowledge_base_ids.is_empty() {
                return Err(anyhow::anyhow!(knowledge_access_denied_message(
                    &bundles.denied_knowledge_base_ids
                )));
            }
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
        let results = retrieve_from_knowledge_bases(
            &bundles.bundles,
            embedder,
            &args.query,
            limit,
            Some(&crate::sealed::LocalVaultResolver::new(
                ctx.session.secret_vault().clone(),
            )),
            ctx.knowledge_access_trusted,
        )
        .await?;
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

    #[test]
    fn knowledge_prompt_snapshot_renders_stable_identity_and_frozen_freshness() {
        let snapshot = KnowledgeBasePromptSnapshot::from_json_str(
            r#"{"entries":[{"id":"team","name":"Team Notes","description":"Decisions and conventions","last_dreamed_at_unix_ms":0}]}"#,
        );

        let first = snapshot.render_system_block();
        let second = snapshot.render_system_block();
        assert_eq!(first, second, "cached KB prefix must be byte-stable");
        assert!(first.contains("Team Notes (id: team): Decisions and conventions"));
        assert!(first.contains("Last dreamed at: 1970-01-01T00:00:00+00:00"));
        assert!(first.contains("Newer information may live in sessions"));
        assert!(!first.contains("undreamed"));
    }

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
                project_id: "project".to_string(),
                short_id: Some("ab12cd".to_string()),
                title: Some("Recent deploy discussion".to_string()),
                last_active_at_unix_ms: 101,
                snippet: "The rollout is waiting for approval.".to_string(),
                bm25: -1.0,
            }],
            boundary_knowledge_bases: vec!["project".to_string()],
            oldest_boundary_session_event_seq: Some(100),
            missing_boundary_knowledge_bases: Vec::new(),
        };

        let rendered = render_knowledge_retrieval(&results, &freshness, &RedactionTable::empty());
        assert!(rendered.contains("concepts/deploy.md#chunk-0"));
        assert!(rendered.contains("session ab12cd"));
        assert!(rendered.contains(&session_id.to_string()));
        assert!(rendered.contains("may not yet be dreamed"));
    }

    #[tokio::test]
    async fn fresh_retrieval_includes_the_current_session_before_the_first_boundary() {
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
            sealed_id: crate::sealed::SealedKnowledgeBaseId::parse(
                "4b3a7cd2-2af9-4f1f-bf8f-7f4cb32b59a9",
            )
            .unwrap(),
        }];

        let freshness = retrieve_undreamed_session_hits(&bundles, "windfall", 6, &ctx)
            .await
            .unwrap();

        assert_eq!(
            freshness.missing_boundary_knowledge_bases,
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
    async fn fresh_retrieval_uses_the_event_sequence_boundary_not_a_timestamp() {
        let tmp = TempDir::new().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let entry = project_knowledge_registry_entry();
        let bundles = vec![AttachedKnowledgeBase {
            provider: Arc::new(RemoteKb {
                entry: entry.clone(),
            }),
            entry,
            sealed_id: crate::sealed::SealedKnowledgeBaseId::parse(
                "4b3a7cd2-2af9-4f1f-bf8f-7f4cb32b59a9",
            )
            .unwrap(),
        }];
        let first = ctx
            .session
            .db
            .insert_session_event(
                ctx.session.id,
                crate::db::session_log::SessionEventKind::UserMessage,
                None,
                None,
                &json!({ "text": "windfall decision before dream" }),
            )
            .await
            .unwrap();
        let project_uuid = ctx
            .session
            .db
            .authoritative_project_uuid(&ctx.session.project_id)
            .await
            .unwrap()
            .unwrap();
        let boundary = ctx
            .session
            .db
            .snapshot_knowledge_dream_boundary(project_uuid)
            .await
            .unwrap();
        assert_eq!(boundary, first);
        ctx.session
            .db
            .record_knowledge_dream_boundary(
                crate::db::knowledge_dreams::KnowledgeDreamLedgerKey {
                    project_uuid,
                    knowledge_base_attachment_id: bundles[0].entry.attachment_id(),
                },
                boundary,
                0,
            )
            .await
            .unwrap();

        let before_later_event = retrieve_undreamed_session_hits(&bundles, "windfall", 6, &ctx)
            .await
            .unwrap();
        assert!(before_later_event.hits.is_empty());

        let later = ctx
            .session
            .db
            .insert_session_event(
                ctx.session.id,
                crate::db::session_log::SessionEventKind::UserMessage,
                None,
                None,
                &json!({ "text": "post-dream activity" }),
            )
            .await
            .unwrap();
        assert!(later > boundary);

        let after_later_event = retrieve_undreamed_session_hits(&bundles, "windfall", 6, &ctx)
            .await
            .unwrap();
        assert!(
            after_later_event
                .hits
                .iter()
                .any(|hit| hit.session_id == ctx.session.id)
        );
    }

    #[tokio::test]
    async fn replacement_kb_directory_at_the_same_path_does_not_reuse_the_previous_dream_boundary()
    {
        let tmp = TempDir::new().unwrap();
        let session = test_session(tmp.path()).await;
        let root = tmp.path().join("knowledge");
        write_bundle(&root);
        let entry = KnowledgeBaseRegistryEntry::new(
            "project".to_string(),
            "Project".to_string(),
            "Workspace project knowledge".to_string(),
            KnowledgeBaseSource::Local {
                path: PathBuf::from("knowledge"),
            },
            KnowledgeBaseEmbeddingOwnership::Local,
            None,
            None,
            false,
            KnowledgeBaseMergePolicy::Auto,
        );
        let extended = ExtendedConfig {
            knowledge_bases: vec![entry],
            ..Default::default()
        };
        let original = attached_bundles(&session, tmp.path(), None, &extended, true)
            .await
            .unwrap()
            .bundles
            .pop()
            .unwrap()
            .entry;
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
        session
            .db
            .record_knowledge_dream_boundary(original_key, 100, 110)
            .await
            .unwrap();

        fs::remove_dir_all(&root).unwrap();
        write_bundle(&root);
        let replacement = attached_bundles(&session, tmp.path(), None, &extended, true)
            .await
            .unwrap()
            .bundles
            .pop()
            .unwrap()
            .entry;
        let replacement_key = crate::db::knowledge_dreams::KnowledgeDreamLedgerKey {
            project_uuid,
            knowledge_base_attachment_id: replacement.attachment_id(),
        };

        assert_ne!(
            original_key.knowledge_base_attachment_id,
            replacement_key.knowledge_base_attachment_id
        );
        assert!(
            session
                .db
                .knowledge_dream_boundary(replacement_key)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn replacement_kb_directory_at_the_same_path_gets_a_fresh_sealed_namespace() {
        let tmp = TempDir::new().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let root = tmp.path().join("knowledge");
        write_bundle(&root);
        let entry = KnowledgeBaseRegistryEntry::new(
            "project".to_string(),
            "Project".to_string(),
            "Workspace project knowledge".to_string(),
            KnowledgeBaseSource::Local { path: root.clone() },
            KnowledgeBaseEmbeddingOwnership::Local,
            None,
            None,
            false,
            KnowledgeBaseMergePolicy::Auto,
        );

        let original = ensure_sealed_knowledge_base_identity(&entry, &vault).unwrap();
        assert_eq!(
            sealed_knowledge_base_identity(&entry, &vault).unwrap(),
            original
        );

        fs::remove_dir_all(&root).unwrap();
        write_bundle(&root);
        let replacement = ensure_sealed_knowledge_base_identity(&entry, &vault).unwrap();

        assert_ne!(original, replacement);
        assert_eq!(
            sealed_knowledge_base_identity(&entry, &vault).unwrap(),
            replacement
        );
    }

    #[test]
    fn retained_sealed_kb_capture_cannot_be_redirected_by_a_path_replacement() {
        let tmp = TempDir::new().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let root = tmp.path().join("knowledge");
        write_bundle(&root);
        let entry = KnowledgeBaseRegistryEntry::new(
            "project".to_string(),
            "Project".to_string(),
            "Workspace project knowledge".to_string(),
            KnowledgeBaseSource::Local { path: root.clone() },
            KnowledgeBaseEmbeddingOwnership::Local,
            None,
            None,
            false,
            KnowledgeBaseMergePolicy::Auto,
        );
        let original = ensure_sealed_knowledge_base_identity(&entry, &vault).unwrap();
        let (captured, captured_id) = capture_local_sealed_knowledge_base(&root, &vault)
            .unwrap()
            .unwrap();

        fs::remove_dir_all(&root).unwrap();
        write_bundle(&root);
        fs::write(
            root.join("deploy.md"),
            "---\ntype: decision\n---\n\nreplacement directory content\n",
        )
        .unwrap();

        assert_eq!(captured_id, original);
        assert!(
            captured
                .concepts
                .iter()
                .any(|concept| serialize_concept(concept).contains("green deploy pipeline"))
        );
        assert!(
            captured.concepts.iter().all(
                |concept| !serialize_concept(concept).contains("replacement directory content")
            )
        );
    }

    #[test]
    fn copied_sealed_namespace_marker_cannot_authorize_a_replacement_kb() {
        let tmp = TempDir::new().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let root = tmp.path().join("knowledge");
        write_bundle(&root);
        let entry = KnowledgeBaseRegistryEntry::new(
            "project".to_string(),
            "Project".to_string(),
            "Workspace project knowledge".to_string(),
            KnowledgeBaseSource::Local { path: root.clone() },
            KnowledgeBaseEmbeddingOwnership::Local,
            None,
            None,
            false,
            KnowledgeBaseMergePolicy::Auto,
        );

        ensure_sealed_knowledge_base_identity(&entry, &vault).unwrap();
        let copied_marker = fs::read(sealed_knowledge_base_marker_path(&root)).unwrap();

        fs::remove_dir_all(&root).unwrap();
        write_bundle(&root);
        fs::write(sealed_knowledge_base_marker_path(&root), copied_marker).unwrap();

        let error = sealed_knowledge_base_identity(&entry, &vault).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not belong to this source object")
        );
        let error = ensure_sealed_knowledge_base_identity(&entry, &vault).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not belong to this source object")
        );
    }

    #[test]
    fn owner_can_pin_a_configured_kb_label_before_the_first_sealed_copy() {
        let tmp = TempDir::new().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let root = tmp.path().join("knowledge");
        write_bundle(&root);
        let extended = ExtendedConfig {
            knowledge_bases: vec![KnowledgeBaseRegistryEntry::new(
                "project".to_string(),
                "Project".to_string(),
                "Workspace project knowledge".to_string(),
                KnowledgeBaseSource::Local {
                    path: PathBuf::from("knowledge"),
                },
                KnowledgeBaseEmbeddingOwnership::Local,
                None,
                None,
                false,
                KnowledgeBaseMergePolicy::Auto,
            )],
            ..Default::default()
        };

        let pinned =
            sealed_knowledge_base_id_for_owner(tmp.path(), &extended, "project", &vault).unwrap();

        assert_eq!(
            sealed_knowledge_base_id_for_owner(tmp.path(), &extended, "project", &vault).unwrap(),
            pinned
        );
        assert!(sealed_knowledge_base_marker_path(&root).is_file());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn changed_local_kb_symlink_target_has_a_new_attachment_identity() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let session = test_session(tmp.path()).await;
        let first_target = tmp.path().join("first-knowledge");
        let second_target = tmp.path().join("second-knowledge");
        let link = tmp.path().join("knowledge");
        write_bundle(&first_target);
        write_bundle(&second_target);
        symlink(&first_target, &link).unwrap();
        let entry = KnowledgeBaseRegistryEntry::new(
            "project".to_string(),
            "Project".to_string(),
            "Workspace project knowledge".to_string(),
            KnowledgeBaseSource::Local {
                path: PathBuf::from("knowledge"),
            },
            KnowledgeBaseEmbeddingOwnership::Local,
            None,
            None,
            false,
            KnowledgeBaseMergePolicy::Auto,
        );
        let extended = ExtendedConfig {
            knowledge_bases: vec![entry],
            ..Default::default()
        };
        let first = attached_bundles(&session, tmp.path(), None, &extended, true)
            .await
            .unwrap()
            .bundles
            .pop()
            .unwrap()
            .entry;

        fs::remove_file(&link).unwrap();
        symlink(&second_target, &link).unwrap();
        let second = attached_bundles(&session, tmp.path(), None, &extended, true)
            .await
            .unwrap()
            .bundles
            .pop()
            .unwrap()
            .entry;

        assert_ne!(first.attachment_id(), second.attachment_id());
    }

    #[test]
    fn rewritten_local_kb_source_has_a_new_attachment_identity() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let (_, first) = local_source_attachment_identity(tmp.path())
            .unwrap()
            .unwrap();

        fs::write(
            tmp.path().join("deploy.md"),
            "---\ntype: decision\n---\n\nA replacement knowledge source.",
        )
        .unwrap();
        let (_, second) = local_source_attachment_identity(tmp.path())
            .unwrap()
            .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn fresh_retrieval_reports_its_conservative_first_use_search() {
        let freshness = FreshSessionRetrieval {
            hits: Vec::new(),
            boundary_knowledge_bases: Vec::new(),
            oldest_boundary_session_event_seq: None,
            missing_boundary_knowledge_bases: vec!["project".to_string()],
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
    async fn local_git_knowledge_rejects_tracked_sidecars() {
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
        let add = Command::new("git")
            .arg("-C")
            .arg(tmp.path())
            .args(["add", "--", EMBEDDINGS_FILE, INDEX_FILE])
            .status()
            .unwrap();
        assert!(add.success());

        let error = match KnowledgeIndex::open(tmp.path(), mock_embedder()).await {
            Ok(_) => panic!("tracked sidecars must be rejected before opening"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("is tracked by Git"), "{error:#}");
    }

    #[test]
    fn local_git_knowledge_refuses_indeterminate_tracked_file_check() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let init = Command::new("git")
            .arg("init")
            .arg(tmp.path())
            .status()
            .unwrap();
        assert!(init.success());
        // rev-parse remains usable, but ls-files cannot establish whether a
        // generated sidecar is tracked when the repository index is corrupt.
        fs::write(tmp.path().join(".git/index"), b"not a Git index").unwrap();
        let sidecars = KbSidecars::in_root(tmp.path()).canonicalized().unwrap();
        let error = ensure_sidecars_gitignored(tmp.path(), &sidecars).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("checking whether knowledge sidecar"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn index_version_bump_rebuilds_only_disposable_index() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let (index, _) = KnowledgeIndex::open(tmp.path(), mock_embedder())
            .await
            .unwrap();
        drop(index);
        fs::remove_file(tmp.path().join(INDEX_FILE)).unwrap();
        let stale = Connection::open(tmp.path().join(INDEX_FILE)).unwrap();
        stale
            .execute_batch(
                "CREATE TABLE intel_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); \
                 INSERT INTO intel_meta(key, value) VALUES('index_logic_version', '0'); \
                 CREATE TABLE concepts (id TEXT PRIMARY KEY);",
            )
            .unwrap();
        drop(stale);

        let (_, stats) = KnowledgeIndex::open(tmp.path(), mock_embedder())
            .await
            .unwrap();
        assert_eq!(stats.embedded_chunks, 0, "{stats:?}");
        assert_eq!(stats.reused_files, 2);
        let current = Connection::open(tmp.path().join(INDEX_FILE)).unwrap();
        let has_current_concept_schema: bool = current
            .prepare("PRAGMA table_info(concepts)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
            .iter()
            .any(|column| column == "frontmatter_json");
        assert!(has_current_concept_schema);
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

    #[cfg(unix)]
    #[test]
    fn process_lock_survives_knowledge_root_replacement() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("knowledge");
        fs::create_dir(&root).unwrap();
        let sidecars = KbSidecars::in_root(&root).canonicalized().unwrap();
        let first = SidecarProcessLock::try_acquire(&sidecars)
            .unwrap()
            .expect("first owner acquires the stable KB fence");

        let displaced = tmp.path().join("knowledge-displaced");
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();
        let replacement = KbSidecars::in_root(&root).canonicalized().unwrap();

        assert!(
            SidecarProcessLock::try_acquire(&replacement)
                .unwrap()
                .is_none(),
            "replacement of the KB directory must not create a second lock domain"
        );
        cockpit_host::private_fs::write_private_file_in_dir_fd(
            &first.directory,
            std::ffi::OsStr::new(EMBEDDINGS_FILE),
            &sidecars.embeddings,
            b"old root only",
        )
        .unwrap();
        assert_eq!(
            fs::read(displaced.join(EMBEDDINGS_FILE)).unwrap(),
            b"old root only"
        );
        assert!(!replacement.embeddings.exists());

        // The mutation root must remain anchored to `first.directory`, not
        // the recycled pathname. This uses the same descriptor-backed path
        // passed to dream writers and Git on every Unix target.
        let mutation_root = first.mutation_root();
        fs::write(mutation_root.join("held-root-marker"), b"held root only").unwrap();
        assert_eq!(
            fs::read(displaced.join("held-root-marker")).unwrap(),
            b"held root only"
        );
        assert!(!root.join("held-root-marker").exists());
        drop(first);
        assert!(
            SidecarProcessLock::try_acquire(&replacement)
                .unwrap()
                .is_some()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fenced_snapshot_publishes_only_to_its_retained_knowledge_root() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("knowledge");
        fs::create_dir(&root).unwrap();
        write_bundle(&root);
        let sidecars = KbSidecars::in_root(&root).canonicalized().unwrap();

        // This is the production ordering: acquire the stable fence and
        // retained root first, then take the source snapshot through that
        // capability. Replacing the pathname after this point must not move
        // either the snapshot or its derived sidecar publication.
        let (bundle, lock) = snapshot_bundle_with_sidecar_fence(&sidecars).await.unwrap();
        assert!(bundle.concepts.iter().any(|concept| concept.id == "deploy"));

        let displaced = tmp.path().join("knowledge-displaced");
        fs::rename(&root, &displaced).unwrap();
        fs::create_dir(&root).unwrap();
        write_bundle(&root);

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE retained_snapshot_identity (id INTEGER PRIMARY KEY);")
            .unwrap();
        persist_private_sidecar_connection(&conn, &sidecars.index, &lock).unwrap();

        assert!(displaced.join(INDEX_FILE).is_file());
        assert!(
            !root.join(INDEX_FILE).exists(),
            "a replacement KB must never receive the prior root's projection"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_connection_never_reopens_a_replaced_pathname() {
        let tmp = TempDir::new().unwrap();
        let sidecars = KbSidecars::in_root(tmp.path()).canonicalized().unwrap();
        let lock = SidecarProcessLock::try_acquire(&sidecars)
            .unwrap()
            .expect("first owner acquires the stable KB fence");
        let conn = open_index_connection(&sidecars.index, &lock).unwrap();

        fs::remove_file(&sidecars.index).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("attacker.sqlite"), &sidecars.index).unwrap();

        // This schema mutation is strictly in memory. Persistence re-checks
        // the destination through the retained root and fails closed rather
        // than letting SQLite reopen the replacement symlink.
        conn.execute_batch("CREATE TABLE retained_identity_test (id INTEGER PRIMARY KEY);")
            .unwrap();
        let error = persist_private_sidecar_connection(&conn, &sidecars.index, &lock).unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error:#}");
        assert!(!tmp.path().join("attacker.sqlite").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_process_lock_does_not_overlap_embeddings_sqlite() {
        let tmp = TempDir::new().unwrap();
        let sidecars = KbSidecars::in_root(tmp.path()).canonicalized().unwrap();
        let _lock = SidecarProcessLock::try_acquire(&sidecars)
            .unwrap()
            .expect("first owner acquires the named mutex");
        let conn = open_embeddings_connection(&sidecars.embeddings, &_lock).unwrap();
        ensure_embeddings_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO embedding_meta(key, value) VALUES('lock-test', 'ok')",
            [],
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_index_opens_through_symlink_alias_embed_each_chunk_once() {
        let tmp = TempDir::new().unwrap();
        let aliases = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let alias = aliases.path().join("knowledge-alias");
        std::os::unix::fs::symlink(tmp.path(), &alias).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let embedder: Arc<dyn Embedder> = Arc::new(SlowCountingEmbedder {
            calls: calls.clone(),
        });
        let (first, second) = tokio::join!(
            KnowledgeIndex::open(tmp.path(), embedder.clone()),
            KnowledgeIndex::open(alias, embedder),
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
    async fn project_bundle_requires_a_trusted_model() {
        let _env = crate::test_env::lock_async().await;
        let tmp = TempDir::new().unwrap();
        let project_bundle = tmp.path().join(".cockpit/knowledge");
        write_bundle(&project_bundle);
        let session = test_session(tmp.path()).await;
        let extended = ExtendedConfig {
            knowledge_bases: vec![project_knowledge_registry_entry()],
            ..Default::default()
        };

        let denied = attached_bundles(&session, tmp.path(), None, &extended, false)
            .await
            .unwrap();
        assert!(denied.bundles.is_empty());
        assert_eq!(
            denied.denied_knowledge_base_ids,
            vec!["project".to_string()]
        );

        let allowed = attached_bundles(&session, tmp.path(), None, &extended, true)
            .await
            .unwrap();
        assert_eq!(allowed.bundles.len(), 1);
    }

    #[test]
    fn trust_required_kb_rejects_an_untrusted_dream_model() {
        let mut entry = project_knowledge_registry_entry();
        entry.dream_model = Some("untrusted-provider:dreamer".to_string());
        let error = validate_dream_models(
            &ExtendedConfig {
                knowledge_bases: vec![entry],
                ..Default::default()
            },
            &crate::config::providers::ProvidersConfig::default(),
        )
        .expect_err("an untrusted dream model must be rejected for a trust-required KB");

        assert!(error.to_string().contains("requires a trusted dreamModel"));
        assert!(error.to_string().contains("untrusted-provider:dreamer"));
    }

    #[tokio::test]
    async fn remote_kb_rejects_trust_required_with_a_clear_error() {
        let tmp = TempDir::new().unwrap();
        let session = test_session(tmp.path()).await;
        let entry = KnowledgeBaseRegistryEntry::new(
            "hosted".to_string(),
            "Hosted".to_string(),
            "Hosted knowledge".to_string(),
            KnowledgeBaseSource::Remote {
                url: "https://knowledge.example.test".to_string(),
            },
            KnowledgeBaseEmbeddingOwnership::RemoteOwned,
            None,
            None,
            true,
            KnowledgeBaseMergePolicy::Auto,
        );
        let error = attached_bundles(
            &session,
            tmp.path(),
            None,
            &ExtendedConfig {
                knowledge_bases: vec![entry],
                ..Default::default()
            },
            false,
        )
        .await
        .err()
        .expect("remote KBs cannot enforce local model trust");

        assert!(error.to_string().contains("cannot require local trust"));
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
            true,
        )
        .await
        .unwrap();
        assert_eq!(attached.bundles.len(), 1);
        assert_eq!(attached.bundles[0].entry.id, "project");
    }

    #[test]
    fn prompt_snapshot_uses_its_carried_trust_authority_for_attachments() {
        let tmp = TempDir::new().unwrap();
        write_bundle(&tmp.path().join("available"));
        let db = crate::db::Db::open_in_memory().unwrap();
        let mut available = project_knowledge_registry_entry();
        available.id = "available".to_string();
        available.name = "Available".to_string();
        available.trust_required = false;
        available.source = KnowledgeBaseSource::Local {
            path: PathBuf::from("available"),
        };
        let mut restricted = available.clone();
        restricted.id = "restricted".to_string();
        restricted.name = "Restricted".to_string();
        restricted.trust_required = true;
        let config = ExtendedConfig {
            knowledge_bases: vec![available, restricted],
            ..Default::default()
        };
        let allowed = BTreeSet::from(["available".to_string(), "restricted".to_string()]);
        let root = tmp.path().to_string_lossy().into_owned();

        let snapshot = db
            .blocking_write_for_sync_maintenance(move |conn| {
                KnowledgeBasePromptSnapshot::capture(
                    &config,
                    conn,
                    &root,
                    None,
                    Some(&allowed),
                    WorkspaceTrustMode::Trust,
                )
            })
            .unwrap();

        assert_eq!(snapshot.entries().len(), 2);
        assert_eq!(snapshot.entries()[0].id, "available");
        assert_eq!(snapshot.entries()[1].id, "restricted");
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

        let attached = attached_bundles(
            &session,
            tmp.path(),
            None,
            &ExtendedConfig::default(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(attached.bundles.len(), 1);
        assert_eq!(
            attached.bundles[0].entry.id,
            format!("assistant-{installation_id}")
        );
        assert!(attached.bundles[0].provider.is_available().await.unwrap());

        fs::remove_dir_all(home.join("knowledge")).unwrap();
        fs::create_dir_all(home.join("knowledge")).unwrap();
        fs::write(
            home.join("knowledge/replacement.md"),
            "---\ntype: replacement\n---\n\nReplacement knowledge must not be read.\n",
        )
        .unwrap();
        let results = attached.bundles[0]
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

        let attached = attached_bundles(&session, tmp.path(), None, &extended, false)
            .await
            .unwrap();
        let results = retrieve_from_knowledge_bases(
            &attached.bundles,
            mock_embedder(),
            "release shipping procedure",
            DEFAULT_SEARCH_LIMIT,
            None,
            false,
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

        let attached = attached_bundles(&session, tmp.path(), None, &extended, false)
            .await
            .unwrap();
        let error = retrieve_from_knowledge_bases(
            &attached.bundles,
            mock_embedder(),
            "release shipping procedure",
            DEFAULT_SEARCH_LIMIT,
            None,
            false,
        )
        .await
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("hosted"));
        assert!(diagnostic.contains("not implemented"));
    }

    #[tokio::test]
    async fn memory_search_tool_schema_is_stable_when_bundles_change() {
        let _env = crate::test_env::lock_async().await;
        let tmp = TempDir::new().unwrap();
        let session = test_session(tmp.path()).await;
        let base = crate::engine::tool::ToolBox::new();
        assert!(
            with_memory_search_if_attached(
                base.clone(),
                &session,
                tmp.path(),
                None,
                &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(
                    tmp.path()
                ),
                "openai:gpt-5",
                false,
            )
            .await
            .names()
            .contains(&"memory_search")
        );

        write_bundle(&tmp.path().join(".cockpit/knowledge"));
        fs::create_dir_all(tmp.path().join(".cockpit")).unwrap();
        fs::write(
            tmp.path().join(".cockpit/config.json"),
            r#"{"knowledgeBases":[{"id":"project","name":"Project","description":"Workspace project knowledge","source":{"kind":"local","path":".cockpit/knowledge"},"embeddingOwnership":"local","dreamModel":"openai:gpt-5","trustRequired":true,"mergePolicy":"auto"}]}"#,
        )
        .unwrap();
        let untrusted_toolbox = with_memory_search_if_attached(
            base.clone(),
            &session,
            tmp.path(),
            None,
            &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
            "openai:gpt-5",
            false,
        )
        .await;
        assert!(untrusted_toolbox.names().contains(&"memory_search"));
        assert!(
            !untrusted_toolbox
                .names()
                .contains(&KNOWLEDGE_DREAM_APPLY_TOOL_NAME)
        );
        let attached_toolbox = with_memory_search_if_attached(
            base,
            &session,
            tmp.path(),
            None,
            &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
            "openai:gpt-5",
            true,
        )
        .await;
        let attached = attached_toolbox.names();
        assert!(attached.contains(&"memory_search"));
        assert!(attached.contains(&KNOWLEDGE_DREAM_APPLY_TOOL_NAME));
        let mismatched_toolbox = with_memory_search_if_attached(
            crate::engine::tool::ToolBox::new(),
            &session,
            tmp.path(),
            None,
            &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
            "anthropic:claude",
            true,
        )
        .await;
        assert!(mismatched_toolbox.names().contains(&"memory_search"));
        assert!(
            !mismatched_toolbox
                .names()
                .contains(&KNOWLEDGE_DREAM_APPLY_TOOL_NAME)
        );
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

    fn test_dream(knowledge_base_id: &str) -> KnowledgeDreamCommit {
        KnowledgeDreamCommit {
            knowledge_base_id: knowledge_base_id.to_string(),
            model: "openai:gpt-5".to_string(),
            sessions_dreamed: 2,
            concepts_written: 1,
            data_files_written: 0,
        }
    }

    fn configure_knowledge_git(root: &Path) {
        crate::git::run_git_checked(root, &["config", "user.email", "dream@test.invalid"]).unwrap();
        crate::git::run_git_checked(root, &["config", "user.name", "Dream test"]).unwrap();
        crate::git::run_git_checked(root, &["config", "commit.gpgsign", "false"]).unwrap();
    }

    fn write_dream_concept(root: &Path, name: &str, body: &str) {
        fs::write(
            root.join(format!("{name}.md")),
            format!("---\ntype: memory\n---\n\n{body}\n"),
        )
        .unwrap();
    }

    #[test]
    fn invalid_dream_projection_restores_the_prewrite_file_set() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let original_index = fs::read_to_string(tmp.path().join("index.md")).unwrap();
        let error = apply_knowledge_dream_writes(
            tmp.path(),
            &[
                KnowledgeDreamWrite {
                    path: "index.md".to_string(),
                    content: "# Changed index\n".to_string(),
                },
                KnowledgeDreamWrite {
                    path: "orphan.csv".to_string(),
                    content: "id,value\n1,orphan\n".to_string(),
                },
            ],
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("orphan.csv"));
        assert_eq!(
            fs::read_to_string(tmp.path().join("index.md")).unwrap(),
            original_index
        );
        assert!(!tmp.path().join("orphan.csv").exists());
    }

    #[test]
    fn unconfigured_local_knowledge_dreams_commit_structured_history_by_concept_file() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let first = apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("personal"),
            |root| {
                write_dream_concept(root, "first-concept", "First dream output.");
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(
            first,
            KnowledgeDreamGitOutcome::Committed { pushed: false, .. }
        ));

        let second = apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("personal"),
            |root| {
                write_dream_concept(root, "second-concept", "Second dream output.");
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(
            second,
            KnowledgeDreamGitOutcome::Committed { pushed: false, .. }
        ));
        let log = crate::git::run_git_checked(tmp.path(), &["log", "--format=%s", "-2"]).unwrap();
        assert!(
            log.contains(
                "dream(kb=personal): sessions=2 model=openai:gpt-5 concepts=1 data_files=0"
            )
        );
        let author =
            crate::git::run_git_checked(tmp.path(), &["log", "-1", "--format=%an <%ae>"]).unwrap();
        assert_eq!(author.trim(), "Flycockpit <knowledge@flycockpit.invalid>");
        assert!(tmp.path().join("first-concept.md").is_file());
        assert!(tmp.path().join("second-concept.md").is_file());
    }

    #[test]
    fn cancelled_dream_does_not_enter_the_fenced_mutation() {
        let tmp = TempDir::new().unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = apply_knowledge_dream_cancellable(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("personal"),
            &cancel,
            |root| {
                fs::write(root.join("must-not-apply.md"), "not reached")?;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("cancelled while waiting"));
        assert!(!tmp.path().join("must-not-apply.md").exists());
    }

    #[test]
    fn advanced_remote_rebases_and_retries_a_nonconflicting_dream_push() {
        let tmp = TempDir::new().unwrap();
        let remote = tmp.path().join("knowledge-remote.git");
        let remote_arg = remote.to_string_lossy().into_owned();
        crate::git::run_git_checked(tmp.path(), &["init", "-q", "--bare", &remote_arg]).unwrap();

        let seed = tmp.path().join("seed");
        fs::create_dir(&seed).unwrap();
        write_bundle(&seed);
        crate::git::run_git_checked(&seed, &["init", "-q"]).unwrap();
        configure_knowledge_git(&seed);
        crate::git::run_git_checked(&seed, &["add", "--all"]).unwrap();
        crate::git::run_git_checked(&seed, &["commit", "-q", "-m", "seed"]).unwrap();
        crate::git::run_git_checked(&seed, &["branch", "-M", "main"]).unwrap();
        crate::git::run_git_checked(&seed, &["remote", "add", "origin", &remote_arg]).unwrap();
        crate::git::run_git_checked(&seed, &["push", "-q", "origin", "main"]).unwrap();

        let root = tmp.path().join("writer");
        let root_arg = root.to_string_lossy().into_owned();
        crate::git::run_git_checked(
            tmp.path(),
            &["clone", "-q", "--branch", "main", &remote_arg, &root_arg],
        )
        .unwrap();
        configure_knowledge_git(&root);

        let outcome = apply_knowledge_dream(
            &root,
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("shared"),
            |root| {
                write_dream_concept(root, "local-concept", "Local dream output.");

                // This commit lands after the writer's pre-apply fetch, so
                // the first push is rejected. The Git transaction must fetch,
                // rebase this distinct concept file, and retry without force.
                let other = tmp.path().join("other-writer");
                let other_arg = other.to_string_lossy().into_owned();
                crate::git::run_git_checked(
                    tmp.path(),
                    &["clone", "-q", "--branch", "main", &remote_arg, &other_arg],
                )
                .unwrap();
                configure_knowledge_git(&other);
                write_dream_concept(&other, "remote-concept", "Remote writer output.");
                crate::git::run_git_checked(&other, &["add", "--all"]).unwrap();
                crate::git::run_git_checked(&other, &["commit", "-q", "-m", "remote advance"])
                    .unwrap();
                crate::git::run_git_checked(&other, &["push", "-q", "origin", "main"]).unwrap();
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(
            outcome,
            KnowledgeDreamGitOutcome::Committed { pushed: true, .. }
        ));
        crate::git::run_git_checked(&root, &["fetch", "-q", "origin"]).unwrap();
        let remote_tree =
            crate::git::run_git_checked(&root, &["ls-tree", "-r", "--name-only", "origin/main"])
                .unwrap();
        assert!(remote_tree.contains("local-concept.md"));
        assert!(remote_tree.contains("remote-concept.md"));
    }

    #[cfg(unix)]
    #[test]
    fn deferred_local_commit_is_pushed_before_a_noop_ledger_retry() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = TempDir::new().unwrap();
        let remote = tmp.path().join("knowledge-remote.git");
        let remote_arg = remote.to_string_lossy().into_owned();
        crate::git::run_git_checked(tmp.path(), &["init", "-q", "--bare", &remote_arg]).unwrap();

        let seed = tmp.path().join("seed");
        fs::create_dir(&seed).unwrap();
        write_bundle(&seed);
        crate::git::run_git_checked(&seed, &["init", "-q"]).unwrap();
        configure_knowledge_git(&seed);
        crate::git::run_git_checked(&seed, &["add", "--all"]).unwrap();
        crate::git::run_git_checked(&seed, &["commit", "-q", "-m", "seed"]).unwrap();
        crate::git::run_git_checked(&seed, &["branch", "-M", "main"]).unwrap();
        crate::git::run_git_checked(&seed, &["remote", "add", "origin", &remote_arg]).unwrap();
        crate::git::run_git_checked(&seed, &["push", "-q", "origin", "main"]).unwrap();

        let root = tmp.path().join("writer");
        let root_arg = root.to_string_lossy().into_owned();
        crate::git::run_git_checked(
            tmp.path(),
            &["clone", "-q", "--branch", "main", &remote_arg, &root_arg],
        )
        .unwrap();
        configure_knowledge_git(&root);
        let hook = root.join(".git/hooks/pre-push");
        fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
        let mut permissions = fs::metadata(&hook).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&hook, permissions).unwrap();

        let deferred = apply_knowledge_dream(
            &root,
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("shared"),
            |root| {
                write_dream_concept(root, "deferred", "Retained local dream output.");
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(
            deferred,
            KnowledgeDreamGitOutcome::Deferred {
                commit: Some(_),
                ..
            }
        ));
        fs::remove_file(&hook).unwrap();

        let retry = apply_knowledge_dream(
            &root,
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("shared"),
            |root| {
                write_dream_concept(root, "deferred", "Retained local dream output.");
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(retry, KnowledgeDreamGitOutcome::NoChanges { .. }));
        crate::git::run_git_checked(&root, &["fetch", "-q", "origin"]).unwrap();
        let remote_tree =
            crate::git::run_git_checked(&root, &["ls-tree", "-r", "--name-only", "origin/main"])
                .unwrap();
        assert!(remote_tree.contains("deferred.md"));
    }

    #[test]
    fn rebase_conflict_defers_the_next_dream_before_it_mutates() {
        let tmp = TempDir::new().unwrap();
        let remote = tmp.path().join("knowledge-remote.git");
        let remote_arg = remote.to_string_lossy().into_owned();
        crate::git::run_git_checked(tmp.path(), &["init", "-q", "--bare", &remote_arg]).unwrap();

        let seed = tmp.path().join("seed");
        fs::create_dir(&seed).unwrap();
        write_bundle(&seed);
        crate::git::run_git_checked(&seed, &["init", "-q"]).unwrap();
        configure_knowledge_git(&seed);
        crate::git::run_git_checked(&seed, &["add", "--all"]).unwrap();
        crate::git::run_git_checked(&seed, &["commit", "-q", "-m", "seed"]).unwrap();
        crate::git::run_git_checked(&seed, &["branch", "-M", "main"]).unwrap();
        crate::git::run_git_checked(&seed, &["remote", "add", "origin", &remote_arg]).unwrap();
        crate::git::run_git_checked(&seed, &["push", "-q", "origin", "main"]).unwrap();

        let root = tmp.path().join("writer");
        let root_arg = root.to_string_lossy().into_owned();
        crate::git::run_git_checked(
            tmp.path(),
            &["clone", "-q", "--branch", "main", &remote_arg, &root_arg],
        )
        .unwrap();

        let first = apply_knowledge_dream(
            &root,
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("shared"),
            |root| {
                write_dream_concept(root, "deploy", "Local conflicting dream output.");

                let other = tmp.path().join("other-writer");
                let other_arg = other.to_string_lossy().into_owned();
                crate::git::run_git_checked(
                    tmp.path(),
                    &["clone", "-q", "--branch", "main", &remote_arg, &other_arg],
                )
                .unwrap();
                configure_knowledge_git(&other);
                write_dream_concept(&other, "deploy", "Remote conflicting dream output.");
                crate::git::run_git_checked(&other, &["add", "--all"]).unwrap();
                crate::git::run_git_checked(&other, &["commit", "-q", "-m", "remote conflict"])
                    .unwrap();
                crate::git::run_git_checked(&other, &["push", "-q", "origin", "main"]).unwrap();
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(first, KnowledgeDreamGitOutcome::Deferred { .. }));
        assert!(
            crate::git::run_git_checked(&root, &["status", "--porcelain"])
                .unwrap()
                .is_empty(),
            "the rejected-push rebase must abort to a clean worktree"
        );

        let second = apply_knowledge_dream(
            &root,
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("shared"),
            |root| {
                write_dream_concept(root, "must-not-apply", "Deferred re-entry output.");
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(second, KnowledgeDreamGitOutcome::Deferred { .. }));
        assert!(!root.join("must-not-apply.md").exists());
        assert!(
            crate::git::run_git_checked(&root, &["status", "--porcelain"])
                .unwrap()
                .is_empty(),
            "a deferred re-entry must preserve the clean local commit"
        );
    }

    #[test]
    fn review_knowledge_dream_commits_on_a_dedicated_branch() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let outcome = apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Review,
            &test_dream("team"),
            |root| {
                write_dream_concept(root, "review-concept", "Needs human review.");
                Ok(())
            },
        )
        .unwrap();
        let KnowledgeDreamGitOutcome::Committed { branch, pushed, .. } = outcome else {
            panic!("review dream must commit on its review branch");
        };
        assert!(!pushed);
        assert!(branch.starts_with("cockpit/dream/team/"));
        assert_eq!(
            crate::git::current_branch(tmp.path()).unwrap().as_deref(),
            Some("main"),
            "review output must not become the working base for a later dream"
        );
    }

    #[test]
    fn an_auto_dream_after_review_starts_from_the_accepted_branch() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        let review = apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Review,
            &test_dream("team"),
            |root| {
                write_dream_concept(root, "review-only", "Pending review.");
                Ok(())
            },
        )
        .unwrap();
        let KnowledgeDreamGitOutcome::Committed {
            branch: review_branch,
            ..
        } = review
        else {
            panic!("review dream must commit");
        };

        let auto = apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("team"),
            |root| {
                write_dream_concept(root, "accepted-base", "Accepted-base dream.");
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(
            auto,
            KnowledgeDreamGitOutcome::Committed { ref branch, .. } if branch == "main"
        ));
        let ancestor = crate::git::run_git(
            tmp.path(),
            &["merge-base", "--is-ancestor", &review_branch, "main"],
        )
        .unwrap();
        assert!(
            !ancestor.success,
            "accepted history must not include the pending review branch"
        );
    }

    #[test]
    fn deleted_knowledge_paths_are_staged_in_the_dream_commit() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("personal"),
            |root| {
                write_dream_concept(root, "obsolete", "To be removed.");
                Ok(())
            },
        )
        .unwrap();

        let outcome = apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("personal"),
            |root| {
                fs::remove_file(root.join("obsolete.md")).unwrap();
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(
            outcome,
            KnowledgeDreamGitOutcome::Committed { .. }
        ));
        let changed = crate::git::run_git_checked(
            tmp.path(),
            &["show", "--format=", "--name-status", "HEAD"],
        )
        .unwrap();
        assert!(changed.contains("D\tobsolete.md"));
    }

    #[test]
    fn local_manual_edits_defer_a_later_dream_before_it_mutates() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("personal"),
            |root| {
                write_dream_concept(root, "first", "First dream.");
                Ok(())
            },
        )
        .unwrap();
        write_dream_concept(tmp.path(), "manual", "Manual knowledge.");

        let outcome = apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("personal"),
            |root| {
                write_dream_concept(root, "must-not-commit", "Deferred dream.");
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(outcome, KnowledgeDreamGitOutcome::Deferred { .. }));
        let history =
            crate::git::run_git_checked(tmp.path(), &["log", "--format=%s", "-1"]).unwrap();
        assert!(history.contains("dream(kb=personal)"));
        let status = crate::git::run_git_checked(tmp.path(), &["status", "--porcelain"]).unwrap();
        assert!(status.contains("manual.md"));
        assert!(!tmp.path().join("must-not-commit.md").exists());
    }

    #[cfg(unix)]
    #[test]
    fn failed_post_staging_commit_restores_a_clean_retriable_worktree() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("personal"),
            |root| {
                write_dream_concept(root, "first", "First dream.");
                Ok(())
            },
        )
        .unwrap();

        let hook = tmp.path().join(".git/hooks/pre-commit");
        fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
        let mut permissions = fs::metadata(&hook).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&hook, permissions).unwrap();
        let failed = apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("personal"),
            |root| {
                write_dream_concept(root, "retry", "This commit hook rejects once.");
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(failed, KnowledgeDreamGitOutcome::Deferred { .. }));
        assert!(
            crate::git::run_git_checked(tmp.path(), &["status", "--porcelain"])
                .unwrap()
                .is_empty(),
            "a failed commit must leave neither staged nor unstaged dream output"
        );
        assert!(!tmp.path().join("retry.md").exists());

        fs::remove_file(&hook).unwrap();
        let retry = apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("personal"),
            |root| {
                write_dream_concept(root, "retry", "The ledger retry commits cleanly.");
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(retry, KnowledgeDreamGitOutcome::Committed { .. }));
    }

    #[test]
    fn nested_knowledge_base_initializes_its_own_repository() {
        let tmp = TempDir::new().unwrap();
        let workspace = tmp.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        crate::git::run_git_checked(&workspace, &["init", "-q", "-b", "main"]).unwrap();
        let root = workspace.join(".cockpit/knowledge");
        write_bundle(&root);

        let outcome = apply_knowledge_dream(
            &root,
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("project"),
            |root| {
                write_dream_concept(root, "isolated", "KB-only history.");
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(
            outcome,
            KnowledgeDreamGitOutcome::Committed { .. }
        ));
        let kb_top = crate::git::run_git_checked(&root, &["rev-parse", "--show-toplevel"]).unwrap();
        assert_eq!(
            fs::canonicalize(kb_top.trim()).unwrap(),
            fs::canonicalize(&root).unwrap()
        );
        assert_eq!(
            crate::git::current_branch(&workspace).unwrap().as_deref(),
            Some("main")
        );
    }

    #[test]
    fn knowledge_machine_state_is_ignored_when_history_is_initialized() {
        let tmp = TempDir::new().unwrap();
        write_bundle(tmp.path());
        apply_knowledge_dream(
            tmp.path(),
            KnowledgeBaseMergePolicy::Auto,
            &test_dream("personal"),
            |root| {
                for name in KB_MACHINE_STATE_GITIGNORE {
                    let path = root.join(name.trim_end_matches('/'));
                    if name.ends_with('/') {
                        fs::create_dir_all(path).unwrap();
                    } else {
                        fs::write(path, "local only").unwrap();
                    }
                }
                write_dream_concept(root, "ignored-state", "State is private.");
                Ok(())
            },
        )
        .unwrap();
        for name in KB_MACHINE_STATE_GITIGNORE {
            let ignored = crate::git::run_git(
                tmp.path(),
                &["check-ignore", "-q", name.trim_end_matches('/')],
            )
            .unwrap();
            assert!(ignored.success, "{name} must be ignored in a KB repository");
        }
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
}
