//! Daemon-owned installed-agent file/operation coordinator.
//!
//! The CLI/TUI only render `cockpit_proto::AgentInstallation*V1` values. This
//! module owns source parsing, workspace authorization, staged files, and the
//! durable idempotency/journal state. The prerequisite DB installation module
//! remains the sole binding/snapshot/revision mutation authority.

use std::collections::BTreeMap;
use std::collections::HashMap;
#[cfg(any(unix, windows))]
use std::collections::HashSet;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(any(unix, windows))]
use std::sync::Mutex;
#[cfg(any(unix, windows))]
use std::sync::OnceLock;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use base64::Engine;
use cockpit_config::config::providers::ProvidersConfig;
#[cfg(debug_assertions)]
use cockpit_config::config::providers::{ModelCapabilities, ModelEntry, ProviderEntry};
use cockpit_db::db::Db;
use cockpit_db::db::agent_installations::{
    AgentInstallationInput, AgentInstallationRow, AgentInstallationScope,
    AgentReplacementCompensationReceipt, InstallAgentOutcome, SessionSetupDbSnapshot,
    SessionSetupInstallationSnapshotRow,
};
use cockpit_db::db::installation_operations::{
    BeginInstallationOperation, InstallationJournalCheckpoint, InstallationJournalRow,
    InstallationOperationKind, InstallationOperationState,
};
use cockpit_proto::{
    AGENT_INSTALLATION_DTO_VERSION, AgentInstallationBeginV1, AgentInstallationBindingOutcomeV1,
    AgentInstallationChoiceV1, AgentInstallationErrorCodeV1, AgentInstallationErrorV1,
    AgentInstallationExecutionKindV1, AgentInstallationOperationKind, AgentInstallationReadV1,
    AgentInstallationReceiptStatusV1, AgentInstallationRecordV1, AgentInstallationResultV1,
    AgentInstallationScopeWire, AgentInstallationSlotBindingStateV1, AgentInstallationSlotStatusV1,
    AgentInstallationSubmitChoiceV1, AgentInstallationUnmatchedRecommendationV1,
    SESSION_SETUP_DTO_VERSION, SessionSetupAgentCandidateV1, SessionSetupLockedReasonV1,
    SessionSetupModelSlotV1, SessionSetupSnapshotV1, SessionSetupUnavailableReasonV1,
};
use futures::StreamExt;
use futures::stream::BoxStream;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) const PACKAGE_CHILD_SOURCE_MARKER: &str = "#package-subagent:";

pub(crate) fn is_package_child_installation(row: &AgentInstallationRow) -> bool {
    row.source_identity.contains(PACKAGE_CHILD_SOURCE_MARKER)
}

const MAX_AGENT_MARKDOWN_BYTES: usize = 1024 * 1024;
const MAX_AGENT_PACKAGE_BYTES: usize = 4 * 1024 * 1024;
/// Hook files share the bounded retained-workspace config policy.  Keep this
/// explicit at the acquisition boundary: parser errors may be warnings, but
/// an oversized capability-backed source is not safe to read or publish.
const MAX_HOOK_CONFIG_BYTES: usize = cockpit_config::config::MAX_WORKSPACE_CONFIG_FILE_BYTES;
/// Workspace hook executables are copied once into a daemon-private bundle so
/// a source pathname can never be reopened after attach. This is intentionally
/// larger than the config cap while still bounding memory and disk use.
const MAX_RETAINED_HOOK_EXECUTABLE_BYTES: usize = 64 * 1024 * 1024;
/// A one-megabyte config could otherwise name arbitrarily many distinct
/// executables. Bound the whole live source bundle as well as each file.
const MAX_RETAINED_HOOK_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
const MAX_RETAINED_HOOK_BUNDLES_PER_SOURCE: usize = 128;
#[cfg(any(unix, windows))]
const MAX_RETAINED_HOOK_BUNDLE_BYTES_PER_WORKER: usize = 256 * 1024 * 1024;
#[cfg(any(unix, windows))]
const MAX_RETAINED_HOOK_BUNDLES_PER_WORKER: usize = 256;
const GITHUB_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

#[derive(serde::Serialize, serde::Deserialize)]
struct BindChoiceSet {
    installation_id: String,
    definition_digest: String,
    #[serde(default)]
    expected_observation_revision: u64,
    /// Binding generation observed when this exact choice set was created.
    /// It is server-only continuation state: submit uses it as the DB CAS so
    /// a legitimate rebind advances the current route while a concurrent
    /// change is refused rather than overwritten.
    #[serde(default)]
    expected_binding_revision: Option<u64>,
    choices: Vec<AgentInstallationChoiceV1>,
    unmatched_recommendations: Vec<AgentInstallationUnmatchedRecommendationV1>,
    /// Server-only route lookup. Profile handles are daemon-local credential
    /// owners and must never be reconstructed from, or exposed as, provider
    /// aliases in the wire DTO.
    routes: Vec<DurableBindingRoute>,
    /// A concrete ModelSlot must retain its authored explicit/first default;
    /// old/open-slot continuations derive the default from the submission.
    #[serde(default)]
    authored_default_required: bool,
    #[serde(default)]
    parent_receipt_status: Option<AgentInstallationReceiptStatusV1>,
    #[serde(default)]
    parent_source_revision: Option<String>,
    /// The exact choice selected by a `--yes` request. This is durable so a
    /// retry never re-ranks a changed local provider catalog or asks the user
    /// to finish a previously non-interactive operation manually.
    #[serde(default)]
    auto_choice_id: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DurableBindingRoute {
    choice_id: String,
    slot_id: String,
    model_id: String,
    provider_profile_handle: String,
    /// True when this route implements ModelSlot's explicit/first authored
    /// default. Choice ids are positional aliases and never define this bit.
    #[serde(default)]
    authored_default: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct JournalStagedSource {
    target_name: String,
    digest: String,
    commit_sha: String,
    markdown_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalAgentSource {
    pub owner: String,
    pub repository: String,
    pub requested_revision: Option<String>,
    pub markdown_path: String,
}

impl CanonicalAgentSource {
    pub fn parse(locator: &str) -> Result<Self> {
        ensure!(
            !locator.contains("://") && !locator.contains('\\'),
            "source must be OWNER/REPO[@REV]:PATH, not a URL or filesystem path"
        );
        let (repo_ref, markdown_path) = locator
            .split_once(':')
            .context("source must contain one ':' before its Markdown path")?;
        ensure!(
            !markdown_path.is_empty() && markdown_path.ends_with(".md"),
            "source path must be a non-empty Markdown path"
        );
        ensure!(
            !markdown_path.contains(':')
                && !markdown_path.starts_with('/')
                && !markdown_path.split('/').any(|part| {
                    part.is_empty()
                        || part == "."
                        || part == ".."
                        || !part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                        })
                }),
            "source path must not traverse"
        );
        let (repo, requested_revision) = match repo_ref.split_once('@') {
            Some((repo, revision)) => {
                ensure!(
                    !revision.is_empty()
                        && revision.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                        }),
                    "source revision is invalid"
                );
                (repo, Some(revision.to_owned()))
            }
            None => (repo_ref, None),
        };
        let (owner, repository) = repo
            .split_once('/')
            .context("source repository must be OWNER/REPO")?;
        ensure!(
            !owner.is_empty() && !repository.is_empty() && !repository.contains('/'),
            "source repository must be OWNER/REPO"
        );
        for value in [owner, repository] {
            ensure!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
                "source owner/repository contains unsupported characters"
            );
        }
        Ok(Self {
            owner: owner.to_owned(),
            repository: repository.to_owned(),
            requested_revision,
            markdown_path: markdown_path.to_owned(),
        })
    }
    pub fn identity(&self) -> String {
        format!("{}/{}:{}", self.owner, self.repository, self.markdown_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedAgentSource {
    pub commit_sha: String,
    pub markdown: Vec<u8>,
}

#[async_trait]
pub trait AgentInstallationFetcher: Send + Sync {
    /// Resolve through an HTTPS-only GitHub transport. Implementations must
    /// reject redirects and use daemon-local credential-store auth if needed.
    async fn fetch_github_markdown(
        &self,
        source: &CanonicalAgentSource,
    ) -> Result<FetchedAgentSource>;
}

#[async_trait]
pub trait AgentWorkspaceAuthorizer: Send + Sync {
    /// The input is client-provided only at this boundary. Return an opaque
    /// canonical workspace id and a daemon-owned canonical path for writes.
    async fn authorize_workspace(&self, client_path: &str) -> Result<(String, PathBuf)>;
}

/// Attach-time proof for a local workspace root. It couples canonical path
/// spelling with the underlying directory identity so a later path reuse
/// cannot silently inherit an attached session's private/shared scope.
pub struct AuthorizedWorkspaceRoot {
    canonical_path: PathBuf,
    identity_digest: [u8; 32],
    /// An owned directory capability captured at attach.  All workspace-shared
    /// definition reads must stay beneath this handle; `canonical_path` is
    /// only a canonical identity spelling and is never read as authority.
    held_directory: Arc<cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority>,
}

#[derive(Debug, PartialEq, Eq)]
enum WorkspaceSharedDefinitionBytes {
    Flat(Vec<u8>),
    Package(BTreeMap<String, Vec<u8>>),
}

impl Clone for AuthorizedWorkspaceRoot {
    fn clone(&self) -> Self {
        Self {
            canonical_path: self.canonical_path.clone(),
            identity_digest: self.identity_digest,
            held_directory: Arc::clone(&self.held_directory),
        }
    }
}

impl PartialEq for AuthorizedWorkspaceRoot {
    fn eq(&self, other: &Self) -> bool {
        self.canonical_path == other.canonical_path && self.identity_digest == other.identity_digest
    }
}

impl Eq for AuthorizedWorkspaceRoot {}

impl std::fmt::Debug for AuthorizedWorkspaceRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedWorkspaceRoot")
            .finish_non_exhaustive()
    }
}

impl AuthorizedWorkspaceRoot {
    pub fn capture(path: &Path) -> Result<Self> {
        let canonical_path =
            std::fs::canonicalize(path).context("canonicalizing authorized workspace")?;
        let held_directory = Arc::new(
            cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(
                &canonical_path,
            )?,
        );
        let mut hasher = Sha256::new();
        hasher.update(b"cockpit-workspace-root-identity-v1");
        hasher.update(held_directory.identity().as_bytes());
        Ok(Self {
            canonical_path,
            identity_digest: hasher.finalize().into(),
            held_directory,
        })
    }

    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    pub(crate) fn read_regular_file_relative(&self, components: &[&str]) -> Result<Vec<u8>> {
        self.held_directory.read_regular_file_relative(components)
    }

    pub fn verify(&self, path: &Path) -> Result<PathBuf> {
        let observed = Self::capture(path)?;
        ensure!(
            observed.canonical_path == self.canonical_path
                && observed.identity_digest == self.identity_digest,
            "attached workspace identity changed"
        );
        Ok(observed.canonical_path)
    }

    fn read_workspace_shared_definition(
        &self,
        name: &str,
    ) -> Result<WorkspaceSharedDefinitionBytes> {
        ensure!(
            !name.is_empty()
                && name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                }),
            "invalid workspace agent filename"
        );
        if let Some(files) = self.held_directory.read_directory_tree_relative_bounded(
            &[".cockpit", "agents", name],
            MAX_AGENT_MARKDOWN_BYTES,
            MAX_AGENT_PACKAGE_BYTES,
        )? {
            return Ok(WorkspaceSharedDefinitionBytes::Package(files));
        }
        let filename = format!("{name}.md");
        let bytes = self.held_directory.read_regular_file_relative_bounded(
            &[".cockpit", "agents", &filename],
            MAX_AGENT_MARKDOWN_BYTES,
        )?;
        Ok(WorkspaceSharedDefinitionBytes::Flat(bytes))
    }

    /// Clone the held directory descriptor for a lower-level capability
    /// operation. The returned handle remains rooted at the captured object;
    /// callers must never substitute `canonical_path` as filesystem authority.
    fn retained_directory_handle(&self) -> Result<std::fs::File> {
        self.held_directory.retained_directory_handle()
    }

    #[cfg(windows)]
    fn acquire_windows_execution_lease(
        &self,
    ) -> Result<cockpit_host::private_fs::held_directory::WindowsWorkspaceExecutionLease> {
        self.held_directory
            .acquire_windows_execution_lease(&self.canonical_path)
    }
}

/// Worker-owned authority for the exact configuration sources that
/// participated in attach-time discovery. It retains each source directory
/// separately so a later rename/replacement fails closed instead of allowing
/// a refresh to read a successor through pathname discovery. Global source
/// handles are config-only capabilities, never workspace authority.
#[derive(Clone)]
pub(crate) struct WorkerWorkspaceConfigAuthority {
    pub(crate) attached_root: AuthorizedWorkspaceRoot,
    config_layers: Vec<WorkspaceConfigLayerAuthority>,
    /// Every global, project, or explicit layer selected at attachment,
    /// retained in precedence order. This is separate from `config_layers`,
    /// which is the project/explicit-only hook authority. The complete chain
    /// drives provider provenance, worker reloads, and default clear
    /// projection without consulting a new `COCKPIT_CONFIG`.
    default_effective_layers: Vec<RetainedDefaultWriteTargetAuthority>,
    /// Exact spellings selected before their parent capabilities were
    /// captured. These are comparison data only: all later reads use the
    /// matching retained directory, never this path.
    retained_source_paths: Vec<PathBuf>,
    default_write_target: Option<RetainedDefaultWriteTargetAuthority>,
    exclusive_config_override: bool,
    hook_sources: Vec<cockpit_config::config::extended::hooks::HookConfigSource>,
    hook_source_layer_indexes: Vec<Option<usize>>,
    #[cfg(any(unix, windows))]
    hook_execution_budget: Arc<Mutex<RetainedHookExecutionBudget>>,
    config_watch_paths: crate::daemon::config_source::ConfigWatchPaths,
}

#[derive(Clone)]
struct WorkspaceConfigLayerAuthority {
    config_directory: AuthorizedWorkspaceRoot,
    config_leaf: OsString,
    effective_default_journal_leaf: OsString,
    effective_default_backup_leaf: OsString,
}

/// Non-serializable authority for one captured project/explicit hook source.
/// It keeps the config-parent capability used to find the executable separate
/// from the attached workspace capability used as the child cwd. Relative
/// executables are resolved beside their config file, but hooks historically
/// run in the project root; conflating the two changes hook behavior and lets
/// an explicit config choose an unintended cwd.
///
/// Nothing in this type is included in protocol, config, audit, or debug
/// data; the config crate only sees it through its narrow launch trait.
struct RetainedHookExecutionAuthority {
    #[cfg(any(unix, windows))]
    executable_source_directory: AuthorizedWorkspaceRoot,
    #[cfg(any(unix, windows))]
    working_directory: AuthorizedWorkspaceRoot,
    #[cfg(any(unix, windows))]
    bundles: Mutex<RetainedHookExecutionBundles>,
    #[cfg(any(unix, windows))]
    bundle_root: Arc<RetainedHookExecutionBundleRoot>,
    #[cfg(any(unix, windows))]
    bundle_budget: Arc<Mutex<RetainedHookExecutionBudget>>,
}

#[cfg(any(unix, windows))]
#[derive(Default)]
struct RetainedHookExecutionBundles {
    bundles: BTreeMap<Vec<String>, Arc<RetainedHookExecutionBundle>>,
    total_bytes: usize,
}

/// Shared by all retained sources in this worker, including old and new
/// turn-pinned snapshots during refresh. This prevents many project layers
/// from multiplying the per-source snapshot cap.
#[cfg(any(unix, windows))]
#[derive(Default)]
struct RetainedHookExecutionBudget {
    total_bytes: usize,
    total_bundles: usize,
}

/// One collision-free, owner-private executable snapshot. Its `TempDir`
/// deletes the bundle when the registry/config snapshot retires. The root
/// lease keeps its parent alive while an in-flight hook has only this bundle.
#[cfg(any(unix, windows))]
struct RetainedHookExecutionBundle {
    _directory: tempfile::TempDir,
    executable: PathBuf,
    /// Exact bytes copied from the no-follow source descriptor. Kept only as
    /// private provenance for the bundle's lifetime; it is never surfaced in
    /// hook metadata or wire data.
    _source_sha256: [u8; 32],
    #[cfg(unix)]
    workspace_cwd: Arc<std::fs::File>,
    #[cfg(windows)]
    // The workspace lease is acquired per launch. Keeping only the immutable
    // authority here means attach/refresh remain available if another process
    // transiently prevents a no-delete cwd lease.
    _windows_bundle_marker: (),
    #[cfg(any(unix, windows))]
    _root: Arc<RetainedHookExecutionBundleRoot>,
    #[cfg(any(unix, windows))]
    budget: Arc<Mutex<RetainedHookExecutionBudget>>,
    #[cfg(any(unix, windows))]
    byte_len: usize,
}

#[cfg(any(unix, windows))]
impl Drop for RetainedHookExecutionBundle {
    fn drop(&mut self) {
        let mut budget = self
            .budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        budget.total_bytes = budget.total_bytes.saturating_sub(self.byte_len);
        budget.total_bundles = budget.total_bundles.saturating_sub(1);
    }
}

/// Process-private parent for hook snapshots. It lives under Cockpit's
/// private daemon state, not an ambient shared temporary directory. The open
/// flock identifies a live owner so later daemon starts can reclaim only
/// abandoned roots after a crash without touching a concurrently-running
/// daemon's hooks.
#[cfg(unix)]
struct RetainedHookExecutionBundleRoot {
    _directory: tempfile::TempDir,
    _lease: std::fs::File,
    path: PathBuf,
}

#[cfg(any(unix, windows))]
static ACTIVE_HOOK_EXECUTION_ROOTS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

#[cfg(any(unix, windows))]
fn active_hook_execution_roots() -> &'static Mutex<HashSet<PathBuf>> {
    ACTIVE_HOOK_EXECUTION_ROOTS.get_or_init(|| Mutex::new(HashSet::new()))
}

#[cfg(unix)]
impl RetainedHookExecutionBundleRoot {
    const PREFIX: &'static str = "hook-execution-";
    const STALE_SCAN_LIMIT: usize = 128;
    const UNLEASED_REAP_AGE: std::time::Duration = std::time::Duration::from_secs(60);

    fn create() -> std::result::Result<Self, String> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let state_root = cockpit_config::config::resolve::cockpit_state_dir()
            .map_err(|error| format!("locating daemon hook state directory failed: {error:#}"))?
            .join("hook-execution");
        cockpit_host::private_fs::ensure_private_dir(&state_root)
            .map_err(|error| format!("securing daemon hook state directory failed: {error}"))?;
        // `pre_exec` changes the child cwd before the absolute bundle program
        // is executed. Canonicalize after the private no-follow setup so an
        // otherwise relative XDG value can never turn that program into a
        // source-cwd-relative lookup.
        let state_root = std::fs::canonicalize(&state_root).map_err(|error| {
            format!("canonicalizing daemon hook state directory failed: {error}")
        })?;
        Self::reap_abandoned_roots(&state_root);
        let directory = tempfile::Builder::new()
            .prefix(Self::PREFIX)
            .tempdir_in(&state_root)
            .map_err(|error| format!("creating hook execution root failed: {error}"))?;
        let path = directory.path().to_path_buf();
        active_hook_execution_roots()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(path.clone());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|error| {
                active_hook_execution_roots()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&path);
                format!("securing hook execution root failed: {error}")
            })?;
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join(".lease"))
            .map_err(|error| {
                active_hook_execution_roots()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&path);
                format!("creating hook execution root lease failed: {error}")
            })?;
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            active_hook_execution_roots()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&path);
            return Err(format!(
                "locking hook execution root lease failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            _directory: directory,
            _lease: lease,
            path,
        })
    }

    fn reap_abandoned_roots(state_root: &Path) {
        use std::os::fd::AsRawFd as _;

        let Ok(entries) = std::fs::read_dir(state_root) else {
            return;
        };
        for entry in entries.flatten().take(Self::STALE_SCAN_LIMIT) {
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with(Self::PREFIX)
                || !entry.file_type().is_ok_and(|kind| kind.is_dir())
            {
                continue;
            }
            let root = entry.path();
            if active_hook_execution_roots()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains(&root)
            {
                continue;
            }
            let Ok(lease) = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(root.join(".lease"))
            else {
                // A crash can occur in the tiny interval after `tempdir_in`
                // creates the root but before its lease file is durable. Do
                // not race a peer that is actively initializing; reclaim only
                // a clearly old unleased prefix root on a later startup.
                let old_unleased_root = std::fs::metadata(&root)
                    .and_then(|metadata| metadata.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age >= Self::UNLEASED_REAP_AGE);
                if old_unleased_root {
                    let _ = std::fs::remove_dir_all(root);
                }
                continue;
            };
            // A live daemon holds this lock. Reclaim only an abandoned root;
            // errors are intentionally best-effort housekeeping and never
            // widen execution to the source pathname.
            if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }

    fn path(&self) -> &Path {
        self._directory.path()
    }
}

#[cfg(unix)]
impl Drop for RetainedHookExecutionBundleRoot {
    fn drop(&mut self) {
        active_hook_execution_roots()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.path);
    }
}

/// Windows counterpart to the Unix flock-backed bundle root. The private
/// state directory gives the root its ACL boundary. Its `.lease` is opened
/// without `FILE_SHARE_DELETE`, which makes `remove_dir_all` fail while a
/// daemon still owns the root and succeed after a crash closed every handle.
/// The field order intentionally drops the lease before `TempDir` attempts
/// cleanup.
#[cfg(windows)]
struct RetainedHookExecutionBundleRoot {
    _lease: Option<std::fs::File>,
    _directory: tempfile::TempDir,
    path: PathBuf,
}

#[cfg(windows)]
impl RetainedHookExecutionBundleRoot {
    const PREFIX: &'static str = "hook-execution-";
    const STALE_SCAN_LIMIT: usize = 128;
    const UNLEASED_REAP_AGE: std::time::Duration = std::time::Duration::from_secs(60);

    fn create() -> std::result::Result<Self, String> {
        use std::os::windows::fs::OpenOptionsExt as _;
        // Win32 FILE_SHARE_READ | FILE_SHARE_WRITE. Keep this local rather
        // than widening the core's process-containment `windows-sys` feature
        // surface solely for two documented share-mode bits.
        const FILE_SHARE_READ_WRITE: u32 = 0x3;

        let state_root = cockpit_config::config::resolve::cockpit_state_dir()
            .map_err(|error| format!("locating daemon hook state directory failed: {error:#}"))?
            .join("hook-execution");
        cockpit_host::private_fs::ensure_private_dir(&state_root)
            .map_err(|error| format!("securing daemon hook state directory failed: {error}"))?;
        let state_root = std::fs::canonicalize(&state_root).map_err(|error| {
            format!("canonicalizing daemon hook state directory failed: {error}")
        })?;
        Self::reap_abandoned_roots(&state_root);
        let directory = tempfile::Builder::new()
            .prefix(Self::PREFIX)
            .tempdir_in(&state_root)
            .map_err(|error| format!("creating hook execution root failed: {error}"))?;
        // `tempfile` does not itself promise the strict daemon DACL contract
        // on Windows. Verify/repair the directory before the executable bundle
        // or its liveness lease is created beneath it.
        cockpit_host::private_fs::ensure_private_dir(directory.path()).map_err(|error| {
            format!("securing private Windows hook execution root failed: {error}")
        })?;
        let path = directory.path().to_path_buf();
        active_hook_execution_roots()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(path.clone());
        let lease_path = directory.path().join(".lease");
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            // Permit normal reads/writes but deny delete/rename while live.
            .share_mode(FILE_SHARE_READ_WRITE)
            .open(&lease_path)
            .map_err(|error| {
                active_hook_execution_roots()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&path);
                format!("creating Windows hook execution root lease failed: {error}")
            })?;
        cockpit_host::private_fs::repair_private_file(&lease_path, "hook execution root lease")
            .map_err(|error| {
                active_hook_execution_roots()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&path);
                format!("securing Windows hook execution root lease failed: {error}")
            })?;
        Ok(Self {
            _lease: Some(lease),
            _directory: directory,
            path,
        })
    }

    fn reap_abandoned_roots(state_root: &Path) {
        let Ok(entries) = std::fs::read_dir(state_root) else {
            return;
        };
        for entry in entries.flatten().take(Self::STALE_SCAN_LIMIT) {
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with(Self::PREFIX)
                || !entry.file_type().is_ok_and(|kind| kind.is_dir())
            {
                continue;
            }
            let root = entry.path();
            if active_hook_execution_roots()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains(&root)
            {
                continue;
            }
            let lease = root.join(".lease");
            if !lease.exists() {
                let old_unleased_root = std::fs::metadata(&root)
                    .and_then(|metadata| metadata.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age >= Self::UNLEASED_REAP_AGE);
                if old_unleased_root {
                    let _ = std::fs::remove_dir_all(root);
                }
                continue;
            }
            // Mirror the Unix flock pre-check: `remove_dir_all` is not atomic,
            // so relying on the still-open `.lease` to make it *fail* would
            // already have deleted a live peer daemon's unprotected `bundle-*`
            // executables (silently fail-opening its pinned hooks) before the
            // removal reached the lease. Probe `.lease` for DELETE access
            // first: the live owner opened it without FILE_SHARE_DELETE, so
            // this open fails with a sharing violation while the owner runs and
            // succeeds only once every handle closed on process exit. Reclaim
            // the root only after that probe proves it abandoned.
            use std::os::windows::fs::OpenOptionsExt as _;
            const DELETE: u32 = 0x0001_0000;
            const FILE_SHARE_READ_WRITE_DELETE: u32 = 0x7;
            if std::fs::OpenOptions::new()
                .access_mode(DELETE)
                .share_mode(FILE_SHARE_READ_WRITE_DELETE)
                .open(&lease)
                .is_ok()
            {
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }

    fn path(&self) -> &Path {
        self._directory.path()
    }
}

#[cfg(windows)]
impl Drop for RetainedHookExecutionBundleRoot {
    fn drop(&mut self) {
        active_hook_execution_roots()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.path);
        // Close the no-delete handle before `TempDir`'s field drop removes the
        // root. This also makes an otherwise abandoned crash root reclaimable.
        let _ = self._lease.take();
    }
}

#[cfg(any(unix, windows))]
impl cockpit_config::config::extended::hooks::HookExecutionLease for RetainedHookExecutionBundle {}

impl RetainedHookExecutionAuthority {
    fn new(
        _executable_source_directory: AuthorizedWorkspaceRoot,
        _working_directory: AuthorizedWorkspaceRoot,
        #[cfg(any(unix, windows))] bundle_budget: Arc<Mutex<RetainedHookExecutionBudget>>,
    ) -> std::result::Result<Self, String> {
        Ok(Self {
            #[cfg(any(unix, windows))]
            executable_source_directory: _executable_source_directory,
            #[cfg(any(unix, windows))]
            working_directory: _working_directory,
            #[cfg(any(unix, windows))]
            bundles: Mutex::new(RetainedHookExecutionBundles::default()),
            #[cfg(any(unix, windows))]
            bundle_root: Arc::new(RetainedHookExecutionBundleRoot::create()?),
            #[cfg(any(unix, windows))]
            bundle_budget,
        })
    }

    #[cfg(any(unix, windows))]
    fn bundle_for(
        &self,
        relative_components: &[String],
    ) -> std::result::Result<Arc<RetainedHookExecutionBundle>, String> {
        let mut bundles = self
            .bundles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(bundle) = bundles.bundles.get(relative_components) {
            return Ok(Arc::clone(bundle));
        }
        if bundles.bundles.len() >= MAX_RETAINED_HOOK_BUNDLES_PER_SOURCE {
            return Err("retained hook bundle exceeds the executable count limit".to_owned());
        }
        let bundle = self.materialize(relative_components, &mut bundles.total_bytes)?;
        bundles
            .bundles
            .insert(relative_components.to_vec(), Arc::clone(&bundle));
        Ok(bundle)
    }

    #[cfg(unix)]
    fn materialize(
        &self,
        relative_components: &[String],
        total_bytes: &mut usize,
    ) -> std::result::Result<Arc<RetainedHookExecutionBundle>, String> {
        let components = relative_components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let source = self
            .executable_source_directory
            .held_directory
            .read_regular_executable_file_relative_bounded(
                &components,
                MAX_RETAINED_HOOK_EXECUTABLE_BYTES,
            )
            .map_err(|error| format!("opening retained hook executable failed: {error:#}"))?;
        if !source.executable {
            return Err("retained hook executable is not executable".to_owned());
        }
        let source_sha256: [u8; 32] = Sha256::digest(&source.bytes).into();
        let new_total = total_bytes
            .checked_add(source.bytes.len())
            .ok_or_else(|| "retained hook bundle size overflow".to_owned())?;
        if new_total > MAX_RETAINED_HOOK_BUNDLE_BYTES {
            return Err("retained hook bundle exceeds the total byte limit".to_owned());
        }
        let mut worker_budget = self
            .bundle_budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if worker_budget.total_bundles >= MAX_RETAINED_HOOK_BUNDLES_PER_WORKER
            || worker_budget
                .total_bytes
                .checked_add(source.bytes.len())
                .is_none_or(|total| total > MAX_RETAINED_HOOK_BUNDLE_BYTES_PER_WORKER)
        {
            return Err("retained hook bundle exceeds the worker budget".to_owned());
        }

        let directory = tempfile::Builder::new()
            .prefix("bundle-")
            .tempdir_in(self.bundle_root.path())
            .map_err(|error| format!("creating private hook execution bundle failed: {error}"))?;
        // `tempfile` creates a private directory on supported Unix targets;
        // set it explicitly as a defense against platform/umask drift before
        // placing an executable in it.
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("securing private hook execution bundle failed: {error}"))?;
        let leaf = relative_components
            .last()
            .ok_or_else(|| "retained hook executable has no leaf".to_owned())?;
        // The directory is collision-free; preserve the source basename and
        // extension inside it so ordinary shebang/interpreter dispatch sees
        // the expected script suffix without ever reopening the source path.
        let executable = directory.path().join(leaf);
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&executable)
            .map_err(|error| {
                format!("creating private hook executable snapshot failed: {error}")
            })?;
        output
            .write_all(&source.bytes)
            .and_then(|()| output.sync_all())
            .map_err(|error| format!("writing private hook executable snapshot failed: {error}"))?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| format!("securing private hook executable snapshot failed: {error}"),
        )?;
        // Config-parent authority only opens the executable. Preserve the
        // historical attached project root as the child cwd through its own
        // retained handle: a script must never resolve project-relative files
        // through a mutable config parent (notably `COCKPIT_CONFIG`).
        let workspace_cwd = Arc::new(self.working_directory.retained_directory_handle().map_err(
            |error| format!("cloning retained hook workspace directory failed: {error:#}"),
        )?);
        *total_bytes = new_total;
        worker_budget.total_bytes += source.bytes.len();
        worker_budget.total_bundles += 1;
        Ok(Arc::new(RetainedHookExecutionBundle {
            _directory: directory,
            executable,
            _source_sha256: source_sha256,
            workspace_cwd,
            _root: Arc::clone(&self.bundle_root),
            budget: Arc::clone(&self.bundle_budget),
            byte_len: source.bytes.len(),
        }))
    }

    /// Windows uses the same handle-relative, bounded source read as Unix,
    /// then writes a private immutable bundle with the original basename and
    /// extension. Keeping `.cmd` / `.bat` / `.exe` spellings lets the normal
    /// Windows `Command` semantics select the appropriate interpreter without
    /// ever reopening the mutable workspace source pathname.
    #[cfg(windows)]
    fn materialize(
        &self,
        relative_components: &[String],
        total_bytes: &mut usize,
    ) -> std::result::Result<Arc<RetainedHookExecutionBundle>, String> {
        let components = relative_components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let source = self
            .executable_source_directory
            .held_directory
            .read_regular_executable_file_relative_bounded(
                &components,
                MAX_RETAINED_HOOK_EXECUTABLE_BYTES,
            )
            .map_err(|error| format!("opening retained hook executable failed: {error:#}"))?;
        let source_sha256: [u8; 32] = Sha256::digest(&source.bytes).into();
        let new_total = total_bytes
            .checked_add(source.bytes.len())
            .ok_or_else(|| "retained hook bundle size overflow".to_owned())?;
        if new_total > MAX_RETAINED_HOOK_BUNDLE_BYTES {
            return Err("retained hook bundle exceeds the total byte limit".to_owned());
        }
        let mut worker_budget = self
            .bundle_budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if worker_budget.total_bundles >= MAX_RETAINED_HOOK_BUNDLES_PER_WORKER
            || worker_budget
                .total_bytes
                .checked_add(source.bytes.len())
                .is_none_or(|total| total > MAX_RETAINED_HOOK_BUNDLE_BYTES_PER_WORKER)
        {
            return Err("retained hook bundle exceeds the worker budget".to_owned());
        }

        let directory = tempfile::Builder::new()
            .prefix("bundle-")
            .tempdir_in(self.bundle_root.path())
            .map_err(|error| format!("creating private hook execution bundle failed: {error}"))?;
        cockpit_host::private_fs::ensure_private_dir(directory.path()).map_err(|error| {
            format!("securing private Windows hook execution bundle failed: {error}")
        })?;
        let leaf = relative_components
            .last()
            .ok_or_else(|| "retained hook executable has no leaf".to_owned())?;
        let executable = directory.path().join(leaf);
        {
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&executable)
                .map_err(|error| {
                    format!("creating private Windows hook executable snapshot failed: {error}")
                })?;
            output
                .write_all(&source.bytes)
                .and_then(|()| output.sync_all())
                .map_err(|error| {
                    format!("writing private Windows hook executable snapshot failed: {error}")
                })?;
        }
        cockpit_host::private_fs::repair_private_file(&executable, "hook execution bundle")
            .map_err(|error| {
                format!("securing private Windows hook executable snapshot failed: {error}")
            })?;
        *total_bytes = new_total;
        worker_budget.total_bytes += source.bytes.len();
        worker_budget.total_bundles += 1;
        Ok(Arc::new(RetainedHookExecutionBundle {
            _directory: directory,
            executable,
            _source_sha256: source_sha256,
            _windows_bundle_marker: (),
            _root: Arc::clone(&self.bundle_root),
            budget: Arc::clone(&self.bundle_budget),
            byte_len: source.bytes.len(),
        }))
    }
}

impl cockpit_config::config::extended::hooks::RetainedHookExecutionAuthority
    for RetainedHookExecutionAuthority
{
    fn launch(
        &self,
        relative_components: &[String],
    ) -> std::result::Result<cockpit_config::config::extended::hooks::HookExecutionLaunch, String>
    {
        #[cfg(unix)]
        {
            let bundle = self.bundle_for(relative_components)?;
            return Ok(
                cockpit_config::config::extended::hooks::HookExecutionLaunch::retained(
                    bundle.executable.clone(),
                    cockpit_config::config::extended::hooks::HookWorkingDirectory::RetainedUnixDirectory(
                        Arc::clone(&bundle.workspace_cwd),
                    ),
                    bundle,
                ),
            );
        }

        #[cfg(windows)]
        {
            let bundle = self.bundle_for(relative_components)?;
            // `CreateProcess` needs a path for the cwd. Acquire a fresh lease
            // for this child only; it retains the complete no-delete workspace
            // chain and is revalidated immediately before spawn. The bundle is
            // already immutable, so a source replacement can never alter the
            // program this launch executes.
            let cwd = Arc::new(
                self.working_directory
                    .acquire_windows_execution_lease()
                    .map_err(|error| {
                        format!("acquiring retained Windows hook cwd lease failed: {error:#}")
                    })?,
            );
            return Ok(
                cockpit_config::config::extended::hooks::HookExecutionLaunch::retained(
                    bundle.executable.clone(),
                    cockpit_config::config::extended::hooks::HookWorkingDirectory::RetainedWindowsDirectory(
                        cwd,
                    ),
                    bundle,
                ),
            );
        }

        #[cfg(all(not(unix), not(windows)))]
        {
            let _ = relative_components;
            Err("retained relative workspace hooks are unsupported on this platform".to_owned())
        }
    }
}

/// One config source selected while the worker was attached. This is
/// intentionally distinct from `config_layers`: the latter is the
/// project/explicit-only hook authority, while this complete effective chain
/// retains global, project, and explicit config sources for snapshot
/// provenance and capability-relative mutations. It never turns a global
/// source into workspace authority.
#[derive(Clone)]
struct RetainedDefaultWriteTargetAuthority {
    config_directory: AuthorizedWorkspaceRoot,
    config_leaf: OsString,
    effective_default_journal_leaf: OsString,
    effective_default_backup_leaf: OsString,
    canonical_config_path: PathBuf,
    scope: cockpit_config::config::effective_default::EffectiveDefaultScope,
}

fn capture_retained_default_layer(
    project_root: &Path,
    config_path: &Path,
    exclusive_config_override: bool,
) -> Result<RetainedDefaultWriteTargetAuthority> {
    let config_directory_path = config_path
        .parent()
        .context("effective default target has no parent")?;
    // Capture once.  Splitting the canonical-path lookup from the retained
    // handle acquisition would permit a directory replacement between those
    // two observations and manufacture a mixed identity descriptor.
    let config_directory = AuthorizedWorkspaceRoot::capture(config_directory_path)?;
    let config_leaf = config_path
        .file_name()
        .context("effective default target has no filename")?
        .to_os_string();
    let canonical_config_path = config_directory.canonical_path().join(&config_leaf);
    let effective_default_journal_leaf =
        crate::config::effective_default::journal_path_for_layer(&canonical_config_path)
            .file_name()
            .context("effective-default journal has no file name")?
            .to_os_string();
    let effective_default_backup_leaf =
        crate::config::effective_default::backup_path_for_layer(&canonical_config_path)
            .file_name()
            .context("effective-default backup has no file name")?
            .to_os_string();
    let scope = if exclusive_config_override {
        cockpit_config::config::effective_default::EffectiveDefaultScope::ExplicitOverride
    } else {
        crate::config::dirs::discover_config_dirs(project_root)
            .into_iter()
            .find(|directory| directory.path.join(crate::config::dirs::CONFIG_FILE) == config_path)
            .map(|directory| {
                cockpit_config::config::effective_default::EffectiveDefaultScope::from_dir_kind(
                    &directory.kind,
                )
            })
            // A custom nonexclusive source can only arise from a test/config
            // adapter. Its exact parent capability remains authoritative.
            .unwrap_or(cockpit_config::config::effective_default::EffectiveDefaultScope::Project)
    };
    Ok(RetainedDefaultWriteTargetAuthority {
        config_directory,
        config_leaf,
        effective_default_journal_leaf,
        effective_default_backup_leaf,
        canonical_config_path,
        scope,
    })
}

impl WorkerWorkspaceConfigAuthority {
    pub(crate) fn capture(
        project_root: &Path,
        trust_policy: &crate::config::trust::WorkspaceTrustPolicy,
    ) -> Result<Self> {
        let attached_root = AuthorizedWorkspaceRoot::capture(project_root)?;
        // Freeze the exact effective source selection at attach. In
        // particular, `COCKPIT_CONFIG` collapses normal discovery to one
        // permitted file; retaining every conventional `.cockpit` ancestor
        // would silently change its precedence. Every selected config source
        // (including trusted global layers) is retained below for the worker
        // snapshot and provider mutations. Hook source selection remains
        // separate so a global source never becomes workspace authority.
        let (effective_paths, layer_paths, exclusive_config_override, hook_sources) =
            crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
                let effective_paths = crate::config::dirs::config_file_paths_for_load(project_root);
                let explicit_override = std::env::var_os(crate::config::dirs::COCKPIT_CONFIG_ENV)
                    .is_some_and(|value| !value.is_empty());
                let hook_sources = crate::config::extended::hooks::hook_sources_for_config_paths(
                    project_root,
                    effective_paths.clone(),
                    explicit_override,
                );
                if explicit_override && !effective_paths.is_empty() {
                    // An explicit override is the one effective config file,
                    // including a non-project file used while IgnoreConfig is
                    // selected. Its parent + basename are retained below as a
                    // capability-bound descriptor. A conventional project
                    // override is absent from `effective_paths` under
                    // IgnoreConfig and therefore stays excluded.
                    (effective_paths.clone(), effective_paths, true, hook_sources)
                } else {
                    let project_layers = crate::config::dirs::discover_config_dirs(project_root)
                        .into_iter()
                        .filter(|dir| {
                            matches!(&dir.kind, crate::config::dirs::ConfigDirKind::Project)
                        })
                        .map(|dir| {
                            (
                                dir.path.clone(),
                                dir.path.join(crate::config::dirs::CONFIG_FILE),
                            )
                        })
                        .collect::<Vec<_>>();
                    let layer_paths = effective_paths
                        .iter()
                        .filter_map(|effective_path| {
                            project_layers
                                .iter()
                                .find(|(_, config_path)| config_path == effective_path)
                                .map(|(_, config_path)| config_path.clone())
                        })
                        .collect::<Vec<_>>();
                    (effective_paths, layer_paths, false, hook_sources)
                }
            });
        let hook_source_layer_indexes = hook_sources
            .iter()
            .map(|source| layer_paths.iter().position(|path| path == &source.path))
            .collect();
        let config_watch_paths = crate::daemon::config_source::ConfigWatchPaths::new(
            effective_paths.clone(),
            effective_paths
                .iter()
                .filter_map(|path| path.parent().map(|parent| parent.join("providers")))
                .collect(),
        );
        let mut config_layers = Vec::with_capacity(layer_paths.len());
        for config_path in layer_paths {
            let config_directory = config_path.parent().context("config layer has no parent")?;
            let config_leaf = config_path
                .file_name()
                .context("config layer has no file name")?
                .to_os_string();
            let effective_default_journal_leaf =
                crate::config::effective_default::journal_path_for_layer(&config_path)
                    .file_name()
                    .context("effective-default journal has no file name")?
                    .to_os_string();
            let effective_default_backup_leaf =
                crate::config::effective_default::backup_path_for_layer(&config_path)
                    .file_name()
                    .context("effective-default backup has no file name")?
                    .to_os_string();
            config_layers.push(WorkspaceConfigLayerAuthority {
                config_directory: AuthorizedWorkspaceRoot::capture(config_directory)?,
                config_leaf,
                effective_default_journal_leaf,
                effective_default_backup_leaf,
            });
        }
        let default_effective_layers = effective_paths
            .iter()
            .map(|config_path| {
                capture_retained_default_layer(project_root, config_path, exclusive_config_override)
            })
            .collect::<Result<Vec<_>>>()?;
        // `effective_paths` is low-to-high precedence, so the final retained
        // descriptor is the exact layer selected by the shared default-write
        // rule. Cloning it keeps the full chain available for clear preview.
        let default_write_target = default_effective_layers.last().cloned();
        Ok(Self {
            attached_root,
            config_layers,
            default_effective_layers,
            retained_source_paths: effective_paths,
            default_write_target,
            exclusive_config_override,
            hook_sources,
            hook_source_layer_indexes,
            #[cfg(any(unix, windows))]
            hook_execution_budget: Arc::new(Mutex::new(RetainedHookExecutionBudget::default())),
            config_watch_paths,
        })
    }

    pub(crate) fn capture_workspace_config_layers(
        &self,
    ) -> Result<cockpit_config::config::WorkspaceConfigLayerSnapshotChain> {
        self.verify()?;
        let mut layers = Vec::with_capacity(self.config_layers.len());
        for layer in &self.config_layers {
            let directory = layer.config_directory.retained_directory_handle()?;
            let canonical_config_path = layer
                .config_directory
                .canonical_path()
                .join(&layer.config_leaf);
            layers.push(
                cockpit_config::config::snapshot_workspace_config_layer_from_retained_config_directory(
                    &directory,
                    &layer.config_leaf,
                    &canonical_config_path,
                    Some(&layer.effective_default_journal_leaf),
                    Some(&layer.effective_default_backup_leaf),
                )?,
            );
        }
        Ok(
            cockpit_config::config::workspace_config_layer_snapshot_chain_with_exclusive(
                layers,
                self.exclusive_config_override,
            ),
        )
    }

    /// Resolve hooks from the immutable attach-time source selection. The
    /// files themselves remain live for the ordinary config refresh path, but
    /// a later `COCKPIT_CONFIG` override cannot redirect this worker to an
    /// unrelated source tree.
    pub(crate) fn resolve_hooks(
        &self,
    ) -> Result<cockpit_config::config::extended::hooks::HookRegistry> {
        self.resolve_hooks_with_policy(None)
    }

    /// Resolve the frozen source set under the *current* database trust
    /// policy. Project layers stay retained so a later Trust decision can use
    /// the attach-time capability, but IgnoreConfig removes their hooks from
    /// the live registry without reopening discovery. An already-authorized
    /// explicit `COCKPIT_CONFIG` remains its original one-layer contract.
    pub(crate) fn resolve_hooks_for_policy(
        &self,
        policy: &crate::config::trust::WorkspaceTrustPolicy,
    ) -> Result<cockpit_config::config::extended::hooks::HookRegistry> {
        self.resolve_hooks_with_policy(Some(policy))
    }

    fn resolve_hooks_with_policy(
        &self,
        policy: Option<&crate::config::trust::WorkspaceTrustPolicy>,
    ) -> Result<cockpit_config::config::extended::hooks::HookRegistry> {
        match policy {
            Some(policy) => self.verify_retained_config_source_chain_for_policy(policy)?,
            None => self.verify_retained_config_source_chain()?,
        }
        let mut captured = Vec::with_capacity(self.hook_sources.len());
        // Project and explicit sources are parsed from bytes opened through a
        // held directory.  Keep the corresponding execution authority keyed
        // by the exact source path so that source-relative handlers never
        // regress to reopening that spelling after a failed refresh.
        let mut retained_execution_source_directories = HashMap::new();
        for (source, layer_index) in self
            .hook_sources
            .iter()
            .zip(&self.hook_source_layer_indexes)
        {
            let bytes = match layer_index {
                Some(index) => {
                    if !self.hook_source_is_projected(source, policy) {
                        continue;
                    }
                    let layer = self
                        .config_layers
                        .get(*index)
                        .context("retained hook source layer is missing")?;
                    let leaf = layer
                        .config_leaf
                        .to_str()
                        .context("retained hook config leaf is not UTF-8")?;
                    // Acquisition failures for a workspace/explicit source
                    // are authority failures, not recoverable parse warnings.
                    // In particular this bounds the allocation before a
                    // hostile hook file can reach the parser.
                    let bytes = layer
                        .config_directory
                        .held_directory
                        .read_regular_file_relative_bounded(&[leaf], MAX_HOOK_CONFIG_BYTES)?;
                    retained_execution_source_directories
                        .insert(source.path.clone(), layer.config_directory.clone());
                    captured.push((source.clone(), Ok(Some(bytes))));
                    continue;
                }
                // Trusted global sources use their separately retained
                // config-parent capability too. A project or explicit source
                // without a captured layer is an authority invariant failure,
                // never a reason to fall back to reopening its mutable
                // pathname.
                None => match &source.kind {
                    cockpit_config::config::extended::hooks::HookSourceKind::Layer(
                        crate::config::dirs::ConfigDirKind::HomeXdg
                        | crate::config::dirs::ConfigDirKind::HomeDot
                        | crate::config::dirs::ConfigDirKind::MachineLocal,
                    ) => self.read_retained_global_hook_source(source),
                    cockpit_config::config::extended::hooks::HookSourceKind::Layer(
                        crate::config::dirs::ConfigDirKind::Project,
                    )
                    | cockpit_config::config::extended::hooks::HookSourceKind::Explicit => {
                        Err("workspace hook source was not retained at attach".to_owned())
                    }
                },
            };
            captured.push((source.clone(), bytes));
        }
        let mut registry =
            cockpit_config::config::extended::hooks::resolve_hooks_from_captured_sources(&captured);
        // Construct the daemon-private bundle root only if this refresh
        // actually contains a retained relative handler. Bare/absolute project
        // hooks retain their existing behavior and do not acquire a new state
        // directory dependency just because their config source is attached.
        let mut retained_execution_authorities = HashMap::new();
        for hook in &mut registry.hooks {
            if matches!(
                &hook.execution,
                cockpit_config::config::extended::hooks::HookExecutionProvenance::RetainedRelative {
                    ..
                }
            ) {
                let authority = match retained_execution_authorities.get(&hook.source_config_path) {
                    Some(authority) => Arc::clone(authority),
                    None => {
                        let executable_source_directory = retained_execution_source_directories
                            .get(&hook.source_config_path)
                            .context("retained hook execution source is missing")?;
                        let authority = Arc::new(
                            RetainedHookExecutionAuthority::new(
                                executable_source_directory.clone(),
                                self.attached_root.clone(),
                                #[cfg(any(unix, windows))]
                                Arc::clone(&self.hook_execution_budget),
                            )
                            .map_err(anyhow::Error::msg)?,
                        );
                        retained_execution_authorities
                            .insert(hook.source_config_path.clone(), Arc::clone(&authority));
                        authority
                    }
                };
                hook.bind_retained_execution_authority(Arc::clone(&authority)
                    as Arc<
                        dyn cockpit_config::config::extended::hooks::RetainedHookExecutionAuthority,
                    >)
                .map_err(anyhow::Error::msg)?;
                // Snapshot the source program while its whole retained source
                // chain is still verified. Windows deliberately stops here:
                // only the eventual child launch acquires the no-delete cwd
                // lease, so an unrelated temporary share conflict cannot make
                // attach or watcher refresh fail.
                #[cfg(any(unix, windows))]
                let cockpit_config::config::extended::hooks::HookExecutionProvenance::RetainedRelative {
                    components,
                    ..
                } = &hook.execution
                else {
                    unreachable!("retained hook authority was bound to an ambient hook")
                };
                #[cfg(any(unix, windows))]
                authority
                    .bundle_for(components)
                    .map_err(anyhow::Error::msg)?;
                #[cfg(all(not(unix), not(windows)))]
                hook.retained_execution_launch()
                    .map_err(anyhow::Error::msg)?;
            }
        }
        match policy {
            Some(policy) => self.verify_retained_config_source_chain_for_policy(policy)?,
            None => self.verify_retained_config_source_chain()?,
        }
        Ok(registry)
    }

    /// Watch paths are notification hints only, but their selection is still
    /// frozen with the worker authority so a later `COCKPIT_CONFIG` change
    /// cannot make a worker configured from A watch B instead.
    pub(crate) fn config_watch_paths(&self) -> crate::daemon::config_source::ConfigWatchPaths {
        self.config_watch_paths.clone()
    }

    /// Return the project/explicit endpoint-repair target selected by the
    /// same complete attach-time source snapshot. This remains deliberately
    /// narrower than favorite mutation: a global source gets an exact
    /// capability for `SetModelFavorite`, but is not workspace-local endpoint
    /// repair authority. Selection never consults `COCKPIT_CONFIG` or fresh
    /// discovery.
    pub(crate) fn provider_write_target(
        &self,
        snapshot: &cockpit_config::config::WorkspaceConfigLayerSnapshotChain,
        provider_id: &str,
    ) -> Option<PathBuf> {
        if cockpit_config::config::providers::validate_provider_id_for_filename(provider_id)
            .is_err()
            || snapshot.layers.len() != self.default_effective_layers.len()
            || !snapshot.exclusive
        {
            return None;
        }
        let mut fallback = None;
        let mut defining = None;
        for layer in &self.config_layers {
            let index = self.default_effective_layers.iter().position(|retained| {
                retained.config_directory.identity_digest == layer.config_directory.identity_digest
                    && retained.config_leaf == layer.config_leaf
            })?;
            let captured = snapshot.layers.get(index)?;
            let config_path = layer
                .config_directory
                .canonical_path()
                .join(&layer.config_leaf);
            let provider_path = cockpit_config::config::providers::provider_file_path_for_config(
                &config_path,
                provider_id,
            )
            .ok()?;
            fallback = Some(provider_path.clone());
            if captured
                .provider_files
                .iter()
                .any(|(id, _)| id == provider_id)
            {
                defining = Some(provider_path);
            }
        }
        defining.or(fallback)
    }

    /// Materialize the frozen effective-default target as a config-crate
    /// capability. The returned descriptor owns a clone of the retained
    /// directory handle, so the mutation never reopens this pathname after
    /// attachment.
    pub(crate) fn retained_effective_default_target(
        self: &Arc<Self>,
    ) -> Result<cockpit_config::config::effective_default::RetainedEffectiveDefaultTarget> {
        self.verify()?;
        let target = self
            .default_write_target
            .as_ref()
            .context("no retained cockpit config layer applies to this attached session")?;
        target
            .config_directory
            .verify(target.config_directory.canonical_path())?;
        let verifier_authority = Arc::clone(self);
        cockpit_config::config::effective_default::RetainedEffectiveDefaultTarget::new(
            target.config_directory.retained_directory_handle()?,
            target.config_leaf.clone(),
            target.effective_default_journal_leaf.clone(),
            target.effective_default_backup_leaf.clone(),
            target.canonical_config_path.clone(),
            self.attached_root.canonical_path().to_path_buf(),
            target.scope.clone(),
        )
        .map(|target| {
            target.with_verifier(Arc::new(move || {
                verifier_authority.verify_default_effective_layers()
            }))
        })
    }

    /// Return the highest-precedence default target that is enabled by the
    /// *current* attached workspace policy.  Retaining a project capability at
    /// attach is deliberately not permission to keep writing it after a
    /// Trust -> IgnoreConfig change: the retained capability exists only so a
    /// later Trust refresh can reuse the same identity without rediscovery.
    pub(crate) fn retained_effective_default_target_for_policy(
        self: &Arc<Self>,
        policy: &crate::config::trust::WorkspaceTrustPolicy,
    ) -> Result<cockpit_config::config::effective_default::RetainedEffectiveDefaultTarget> {
        self.verify_retained_config_source_chain_for_policy(policy)?;
        let target = self
            .default_effective_layers
            .iter()
            .rev()
            .find(|layer| self.retained_layer_is_projected(layer, policy))
            .context(
                "no retained cockpit config layer applies under the current workspace trust policy",
            )?;
        target
            .config_directory
            .verify(target.config_directory.canonical_path())?;
        let verifier_authority = Arc::clone(self);
        let policy = policy.clone();
        cockpit_config::config::effective_default::RetainedEffectiveDefaultTarget::new(
            target.config_directory.retained_directory_handle()?,
            target.config_leaf.clone(),
            target.effective_default_journal_leaf.clone(),
            target.effective_default_backup_leaf.clone(),
            target.canonical_config_path.clone(),
            self.attached_root.canonical_path().to_path_buf(),
            target.scope.clone(),
        )
        .map(|target| {
            target.with_verifier(Arc::new(move || {
                verifier_authority.verify_retained_config_source_chain_for_policy(&policy)
            }))
        })
    }

    /// Return whether an attached default-update id is still pending in a
    /// retained source that the *current* policy no longer projects. This is
    /// read-only and capability-relative: it never recovers, mutates, or
    /// rediscover paths below the hidden project source. Without this guard a
    /// retry of an A-bound project operation after Trust -> IgnoreConfig could
    /// miss A's journal and reuse the same id for a new global mutation.
    pub(crate) fn hidden_retained_default_update_is_pending(
        &self,
        policy: &crate::config::trust::WorkspaceTrustPolicy,
        session_id: uuid::Uuid,
        default_update_id: uuid::Uuid,
    ) -> Result<bool> {
        for layer in self
            .default_effective_layers
            .iter()
            .filter(|layer| !self.retained_layer_is_projected(layer, policy))
        {
            // Hold/verify the exact directory identity before taking its
            // target-local lock. The descriptor reads only the already-open
            // source A, never a replacement selected by a mutable pathname.
            layer
                .config_directory
                .verify(layer.config_directory.canonical_path())?;
            let target =
                cockpit_config::config::effective_default::RetainedEffectiveDefaultTarget::new(
                    layer.config_directory.retained_directory_handle()?,
                    layer.config_leaf.clone(),
                    layer.effective_default_journal_leaf.clone(),
                    layer.effective_default_backup_leaf.clone(),
                    layer.canonical_config_path.clone(),
                    self.attached_root.canonical_path().to_path_buf(),
                    layer.scope.clone(),
                )?;
            let Some(correlation) = target.retained_transaction_correlation()? else {
                continue;
            };
            if matches!(
                correlation,
                cockpit_config::config::effective_default::TransactionCorrelation::RetainedDefaultUpdate {
                    session_id: journal_session_id,
                    default_update_id: journal_default_update_id,
                    ..
                } if journal_session_id == session_id && journal_default_update_id == default_update_id
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Materialize a favorite-write capability from a source proof retained in
    /// the current worker snapshot. This never re-captures layers or follows
    /// a later `COCKPIT_CONFIG`: the proof chooses one exact captured layer,
    /// provider file digest, and model object.
    pub(crate) fn retained_provider_model_favorite_target(
        self: &Arc<Self>,
        source: cockpit_config::config::providers::RetainedProviderModelSource,
    ) -> Result<cockpit_config::config::providers::RetainedProviderModelFavoriteTarget> {
        self.retained_provider_model_favorite_target_for_selection(source, None)
    }

    /// Build a favorite-write capability from the current policy projection.
    /// This is intentionally separate from the worker's attach authority: a
    /// Trust -> IgnoreConfig transition must still permit an observed global
    /// source, but must not let a stale project source write after it has been
    /// removed from the projected configuration.
    pub(crate) fn retained_provider_model_favorite_target_for_policy(
        self: &Arc<Self>,
        source: cockpit_config::config::providers::RetainedProviderModelSource,
        policy: &crate::config::trust::WorkspaceTrustPolicy,
    ) -> Result<cockpit_config::config::providers::RetainedProviderModelFavoriteTarget> {
        self.retained_provider_model_favorite_target_for_selection(source, Some(policy.clone()))
    }

    fn retained_provider_model_favorite_target_for_selection(
        self: &Arc<Self>,
        source: cockpit_config::config::providers::RetainedProviderModelSource,
        policy: Option<crate::config::trust::WorkspaceTrustPolicy>,
    ) -> Result<cockpit_config::config::providers::RetainedProviderModelFavoriteTarget> {
        cockpit_config::config::providers::validate_provider_id_for_filename(source.provider_id())?;
        match policy.as_ref() {
            Some(policy) => self.verify_retained_config_source_chain_for_policy(policy)?,
            None => self.verify_retained_config_source_chain()?,
        }
        let source_layer_index = source.layer_index();
        let selected = self
            .default_effective_layers
            .get(source_layer_index)
            .context("provider source proof refers to an unknown retained layer")?;
        if let Some(policy) = policy.as_ref() {
            anyhow::ensure!(
                self.retained_layer_is_projected(selected, policy),
                "provider source is no longer enabled by the current workspace trust policy"
            );
        }
        selected
            .config_directory
            .verify(selected.config_directory.canonical_path())?;
        let higher_precedence_locks = self
            .default_effective_layers
            .iter()
            .skip(source_layer_index.saturating_add(1))
            .filter(|layer| {
                policy
                    .as_ref()
                    .is_none_or(|policy| self.retained_layer_is_projected(layer, policy))
            })
            .map(|layer| {
                cockpit_config::config::providers::RetainedProviderModelFavoriteLock::new(
                    layer.config_directory.retained_directory_handle()?,
                    layer
                        .config_directory
                        .canonical_path()
                        .join(&layer.config_leaf),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let source_for_freshness = source.clone();
        let verifier_authority = Arc::clone(self);
        let policy_for_pre_write = policy.clone();
        let policy_for_post_write = policy.clone();
        cockpit_config::config::providers::RetainedProviderModelFavoriteTarget::new(
            selected.config_directory.retained_directory_handle()?,
            selected
                .config_directory
                .canonical_path()
                .join(&selected.config_leaf),
            source,
        )
        .map(|target| target.with_higher_precedence_locks(higher_precedence_locks))
        .map(|target| {
            let pre_write_authority = Arc::clone(&verifier_authority);
            let pre_write_source = source_for_freshness.clone();
            target.with_pre_write_verifier(Arc::new(move || {
                match policy_for_pre_write.as_ref() {
                    Some(policy) => pre_write_authority
                        .verify_retained_config_source_chain_for_policy(policy),
                    None => pre_write_authority.verify_retained_config_source_chain(),
                }
                .context("retained provider source authority changed")?;
                let snapshots = match policy_for_pre_write.as_ref() {
                    Some(policy) => pre_write_authority.capture_retained_config_source_chain(policy),
                    None => pre_write_authority.capture_retained_effective_default_layer_chain(),
                }?;
                let observed = cockpit_config::config::providers::retained_provider_model_source_from_workspace_layer_snapshots(
                    &snapshots.layers,
                    pre_write_source.provider_id(),
                    pre_write_source.model_id(),
                )?
                .context("captured provider/model source is no longer present")?;
                anyhow::ensure!(
                    observed == pre_write_source,
                    "captured provider/model source changed after attached snapshot"
                );
                Ok(())
            }))
            .with_post_write_verifier(Arc::new(move |receipt| {
                match policy_for_post_write.as_ref() {
                    Some(policy) => verifier_authority
                        .verify_retained_config_source_chain_for_policy(policy),
                    None => verifier_authority.verify_retained_config_source_chain(),
                }
                .context("retained provider source authority changed")?;
                let snapshots = match policy_for_post_write.as_ref() {
                    Some(policy) => verifier_authority.capture_retained_config_source_chain(policy),
                    None => verifier_authority.capture_retained_effective_default_layer_chain(),
                }?;
                let observed = cockpit_config::config::providers::retained_provider_model_source_from_workspace_layer_snapshots(
                    &snapshots.layers,
                    source_for_freshness.provider_id(),
                    source_for_freshness.model_id(),
                )?
                .context("captured provider/model source is no longer present")?;
                anyhow::ensure!(
                    receipt.matches_committed_source(&observed),
                    "captured provider/model source changed after retained favorite write"
                );
                Ok(())
            }))
        })
    }

    /// Resolve the effective provider view after applying an update to the
    /// retained write target, entirely from the directories selected at
    /// attachment.  This is used before a clear is journaled: recording
    /// `None` would make a later crash-recovery receipt lie whenever a lower
    /// layer provides the inherited default.
    pub(crate) fn projected_effective_default_after_retained_update(
        &self,
        requested: Option<&cockpit_config::config::providers::ActiveModelRef>,
    ) -> Result<cockpit_config::config::providers::ProvidersConfig> {
        let mut snapshots = self.capture_retained_effective_default_layer_snapshots()?;
        let Some(target) = snapshots.last_mut() else {
            anyhow::bail!("no retained cockpit config layer applies to this attached session");
        };
        let bytes =
            cockpit_config::config::effective_default::projected_config_bytes_for_default_update(
                target.config_json.as_deref().unwrap_or(b"{}"),
                requested,
            )?;
        *target = cockpit_config::config::workspace_config_layer_snapshot_with_config_json(
            target,
            Some(bytes),
        );
        cockpit_config::config::providers::ConfigDoc::providers_from_workspace_layer_snapshots(
            &snapshots,
        )
    }

    /// Policy-scoped counterpart used by attached default-model mutations.
    /// Empty retained slots preserve provider provenance indices, but the
    /// selected write target is the final *projected* layer rather than the
    /// final attach-time layer.
    pub(crate) fn projected_effective_default_after_retained_update_for_policy(
        &self,
        policy: &crate::config::trust::WorkspaceTrustPolicy,
        requested: Option<&cockpit_config::config::providers::ActiveModelRef>,
    ) -> Result<cockpit_config::config::providers::ProvidersConfig> {
        let mut chain = self.capture_retained_config_source_chain_for_policy(policy)?;
        let index = self
            .default_effective_layers
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, layer)| {
                self.retained_layer_is_projected(layer, policy)
                    .then_some(index)
            })
            .context(
                "no retained cockpit config layer applies under the current workspace trust policy",
            )?;
        let target = chain
            .layers
            .get_mut(index)
            .context("retained policy projection lost its default target")?;
        let bytes =
            cockpit_config::config::effective_default::projected_config_bytes_for_default_update(
                target.config_json.as_deref().unwrap_or(b"{}"),
                requested,
            )?;
        *target = cockpit_config::config::workspace_config_layer_snapshot_with_config_json(
            target,
            Some(bytes),
        );
        cockpit_config::config::providers::ConfigDoc::providers_from_workspace_layer_snapshots(
            &chain.layers,
        )
    }

    /// Snapshot attach-time sources through the current policy projection.
    /// Global source capabilities are always projected. Conventional project
    /// slots become empty when `IgnoreConfig` is current; retained slot
    /// ordering remains stable for provider-source proofs. An attach-time
    /// explicit override preserves its original one-layer semantics.
    pub(crate) fn capture_retained_config_source_chain(
        &self,
        policy: &crate::config::trust::WorkspaceTrustPolicy,
    ) -> Result<cockpit_config::config::WorkspaceConfigLayerSnapshotChain> {
        self.capture_retained_config_source_chain_for_policy(policy)
    }

    fn capture_retained_config_source_chain_for_policy(
        &self,
        policy: &crate::config::trust::WorkspaceTrustPolicy,
    ) -> Result<cockpit_config::config::WorkspaceConfigLayerSnapshotChain> {
        self.verify_retained_config_source_chain_for_policy(policy)?;
        let mut snapshots = Vec::with_capacity(self.default_effective_layers.len());
        for layer in &self.default_effective_layers {
            if self.retained_layer_is_projected(layer, policy) {
                let directory = layer.config_directory.retained_directory_handle()?;
                snapshots.push(
                    cockpit_config::config::snapshot_workspace_config_layer_from_retained_config_directory(
                        &directory,
                        &layer.config_leaf,
                        &layer.canonical_config_path,
                        Some(&layer.effective_default_journal_leaf),
                        Some(&layer.effective_default_backup_leaf),
                    )?,
                );
            } else {
                snapshots.push(cockpit_config::config::empty_workspace_config_layer_snapshot());
            }
        }
        self.verify_retained_config_source_chain_for_policy(policy)?;
        Ok(
            cockpit_config::config::workspace_config_layer_snapshot_chain_with_exclusive(
                snapshots, true,
            ),
        )
    }

    /// Compatibility name for the complete chain consumed by a retained
    /// default-model transaction. The chain is shared with ordinary worker
    /// source provenance; its identity does not depend on that mutation.
    pub(crate) fn capture_retained_effective_default_layer_chain(
        &self,
    ) -> Result<cockpit_config::config::WorkspaceConfigLayerSnapshotChain> {
        Ok(
            cockpit_config::config::workspace_config_layer_snapshot_chain_with_exclusive(
                self.capture_retained_effective_default_layer_snapshots()?,
                true,
            ),
        )
    }

    fn capture_retained_effective_default_layer_snapshots(
        &self,
    ) -> Result<Vec<cockpit_config::config::WorkspaceConfigLayerSnapshot>> {
        self.verify_default_effective_layers()?;
        let mut snapshots = Vec::with_capacity(self.default_effective_layers.len());
        for layer in &self.default_effective_layers {
            let directory = layer.config_directory.retained_directory_handle()?;
            let snapshot = cockpit_config::config::snapshot_workspace_config_layer_from_retained_config_directory(
                &directory,
                &layer.config_leaf,
                &layer.canonical_config_path,
                Some(&layer.effective_default_journal_leaf),
                Some(&layer.effective_default_backup_leaf),
            )?;
            snapshots.push(snapshot);
        }
        self.verify_default_effective_layers()?;
        Ok(snapshots)
    }

    /// Validate every retained directory identity before a worker publishes or
    /// serves a configuration-derived result.  The attached root alone is not
    /// sufficient: an ancestor `.cockpit` layer can be replaced while a moved
    /// descendant preserves the session root's inode.
    pub(crate) fn verify(&self) -> Result<()> {
        self.attached_root
            .verify(self.attached_root.canonical_path())?;
        for layer in &self.config_layers {
            layer
                .config_directory
                .verify(layer.config_directory.canonical_path())?;
        }
        if let Some(target) = &self.default_write_target {
            target
                .config_directory
                .verify(target.config_directory.canonical_path())?;
        }
        Ok(())
    }

    /// Identity fence for every config source captured at attachment. This
    /// validates global source provenance without treating a global directory
    /// as workspace authority.
    pub(crate) fn verify_retained_config_source_chain(&self) -> Result<()> {
        self.verify()?;
        for layer in &self.default_effective_layers {
            layer
                .config_directory
                .verify(layer.config_directory.canonical_path())?;
        }
        Ok(())
    }

    fn retained_layer_is_projected(
        &self,
        layer: &RetainedDefaultWriteTargetAuthority,
        policy: &crate::config::trust::WorkspaceTrustPolicy,
    ) -> bool {
        match &layer.scope {
            cockpit_config::config::effective_default::EffectiveDefaultScope::User
            | cockpit_config::config::effective_default::EffectiveDefaultScope::MachineLocal => {
                true
            }
            cockpit_config::config::effective_default::EffectiveDefaultScope::Project => {
                policy.mode == crate::db::workspace_trust::WorkspaceTrustMode::Trust
            }
            cockpit_config::config::effective_default::EffectiveDefaultScope::ExplicitOverride => {
                // This flag is attached only to a one-file explicit override;
                // it is not a chain-wide authorization override. An external
                // explicit file historically remains effective in
                // IgnoreConfig, whereas a conventional project override was
                // never captured in that mode.
                self.exclusive_config_override
            }
        }
    }

    fn hook_source_is_projected(
        &self,
        source: &cockpit_config::config::extended::hooks::HookConfigSource,
        policy: Option<&crate::config::trust::WorkspaceTrustPolicy>,
    ) -> bool {
        let Some(policy) = policy else {
            return true;
        };
        match &source.kind {
            cockpit_config::config::extended::hooks::HookSourceKind::Layer(
                crate::config::dirs::ConfigDirKind::HomeXdg
                | crate::config::dirs::ConfigDirKind::HomeDot
                | crate::config::dirs::ConfigDirKind::MachineLocal,
            ) => true,
            cockpit_config::config::extended::hooks::HookSourceKind::Layer(
                crate::config::dirs::ConfigDirKind::Project,
            ) => policy.mode == crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            cockpit_config::config::extended::hooks::HookSourceKind::Explicit => {
                self.exclusive_config_override
            }
        }
    }

    /// Verify only source identities that the current policy permits us to
    /// project. A conventional project directory can be replaced while a
    /// session is IgnoreConfig without invalidating the still-authorized
    /// global configuration; a later Trust refresh rechecks it before use.
    pub(crate) fn verify_retained_config_source_chain_for_policy(
        &self,
        policy: &crate::config::trust::WorkspaceTrustPolicy,
    ) -> Result<()> {
        self.attached_root
            .verify(self.attached_root.canonical_path())?;
        for layer in &self.default_effective_layers {
            if self.retained_layer_is_projected(layer, policy) {
                layer
                    .config_directory
                    .verify(layer.config_directory.canonical_path())?;
            }
        }
        Ok(())
    }

    fn read_retained_global_hook_source(
        &self,
        source: &cockpit_config::config::extended::hooks::HookConfigSource,
    ) -> std::result::Result<Option<Vec<u8>>, String> {
        let index = self
            .retained_source_paths
            .iter()
            .position(|path| path == &source.path)
            .ok_or_else(|| "trusted global hook source was not retained at attach".to_owned())?;
        let layer = self
            .default_effective_layers
            .get(index)
            .ok_or_else(|| "trusted global hook source layer is missing".to_owned())?;
        let leaf = layer
            .config_leaf
            .to_str()
            .ok_or_else(|| "retained global hook config leaf is not UTF-8".to_owned())?;
        match layer
            .config_directory
            .held_directory
            .read_regular_file_relative_bounded(&[leaf], MAX_HOOK_CONFIG_BYTES)
        {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error)
                if error
                    .chain()
                    .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
                    .any(|cause| cause.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error.to_string()),
        }
    }

    /// The default-model transaction uses the same complete retained source
    /// chain as provider provenance and worker refresh.
    pub(crate) fn verify_retained_effective_default_chain(&self) -> Result<()> {
        self.verify_retained_config_source_chain()
    }

    /// Opaque receipt binding for one retained `SetDefaultModel` linearization.
    ///
    /// This intentionally hashes immutable attach-time directory identities,
    /// the exact one-leaf transaction descriptor, and the generation published
    /// into the worker after the retained reload.  It never serializes a path,
    /// config body, provider credential, or workspace name.  The caller must
    /// invoke this only after its final complete-chain verification; this
    /// method repeats that verification so no caller can accidentally mint a
    /// receipt for a stale attach capability.
    pub(crate) fn retained_effective_default_authority_binding(
        &self,
        config_generation: u64,
    ) -> Result<cockpit_config::config::effective_default::DefaultUpdateAuthorityBinding> {
        self.verify_retained_effective_default_chain()?;
        let target = self
            .default_write_target
            .as_ref()
            .context("no retained cockpit config layer applies to this attached session")?;
        let mut hasher = Sha256::new();
        hasher.update(b"cockpit-retained-default-receipt-authority-v1\0");
        hasher.update(self.attached_root.identity_digest);
        hasher.update([u8::from(self.exclusive_config_override)]);
        hasher.update((self.default_effective_layers.len() as u64).to_le_bytes());
        for layer in &self.default_effective_layers {
            // Directory identity and leaf/artifact names together describe
            // exactly the capability-relative transaction target without
            // exposing any of them in the public receipt.
            hasher.update(layer.config_directory.identity_digest);
            for leaf in [
                &layer.config_leaf,
                &layer.effective_default_journal_leaf,
                &layer.effective_default_backup_leaf,
            ] {
                let bytes = leaf.as_encoded_bytes();
                hasher.update((bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
            }
        }
        // Bind the selected descriptor again explicitly.  This makes a future
        // change to effective-layer ordering fail closed even if its final
        // element happened to have the same directory identity.
        hasher.update(target.config_directory.identity_digest);
        for leaf in [
            &target.config_leaf,
            &target.effective_default_journal_leaf,
            &target.effective_default_backup_leaf,
        ] {
            let bytes = leaf.as_encoded_bytes();
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        hasher.update(target.scope.as_str().as_bytes());
        hasher.update(config_generation.to_le_bytes());
        cockpit_config::config::effective_default::DefaultUpdateAuthorityBinding::new(
            crate::intel::hex_lower(&hasher.finalize()),
            config_generation,
        )
    }

    /// Create a public-safe receipt binding for the policy projection that
    /// actually authorized a default-model write. Only the projected source
    /// scope and selected target are part of the opaque digest: a receipt
    /// sealed for a trusted project target cannot replay while that target is
    /// hidden by IgnoreConfig, while a global-only target remains valid across
    /// a policy transition that does not alter its authority.
    pub(crate) fn retained_effective_default_authority_binding_for_policy(
        &self,
        policy: &crate::config::trust::WorkspaceTrustPolicy,
        config_generation: u64,
    ) -> Result<cockpit_config::config::effective_default::DefaultUpdateAuthorityBinding> {
        self.verify_retained_config_source_chain_for_policy(policy)?;
        let target = self
            .default_effective_layers
            .iter()
            .rev()
            .find(|layer| self.retained_layer_is_projected(layer, policy))
            .context(
                "no retained cockpit config layer applies under the current workspace trust policy",
            )?;
        let projected = self
            .default_effective_layers
            .iter()
            .filter(|layer| self.retained_layer_is_projected(layer, policy))
            .collect::<Vec<_>>();
        let mut hasher = Sha256::new();
        hasher.update(b"cockpit-retained-default-receipt-authority-v2\0");
        hasher.update(self.attached_root.identity_digest);
        hasher.update([u8::from(self.exclusive_config_override)]);
        hasher.update((projected.len() as u64).to_le_bytes());
        for layer in projected {
            hasher.update(layer.config_directory.identity_digest);
            for leaf in [
                &layer.config_leaf,
                &layer.effective_default_journal_leaf,
                &layer.effective_default_backup_leaf,
            ] {
                let bytes = leaf.as_encoded_bytes();
                hasher.update((bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
            }
        }
        hasher.update(target.config_directory.identity_digest);
        for leaf in [
            &target.config_leaf,
            &target.effective_default_journal_leaf,
            &target.effective_default_backup_leaf,
        ] {
            let bytes = leaf.as_encoded_bytes();
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        hasher.update(target.scope.as_str().as_bytes());
        hasher.update(config_generation.to_le_bytes());
        cockpit_config::config::effective_default::DefaultUpdateAuthorityBinding::new(
            crate::intel::hex_lower(&hasher.finalize()),
            config_generation,
        )
    }

    fn verify_default_effective_layers(&self) -> Result<()> {
        self.verify_retained_effective_default_chain()
    }
}

/// Default local-daemon workspace authority. The socket authentication layer
/// has already established local-owner identity before this runs; canonical
/// paths are used only internally and are hashed before becoming the opaque
/// DB/protocol workspace identity.
pub struct LocalDaemonWorkspaceAuthorizer {
    authorized_roots: Vec<AuthorizedWorkspaceRoot>,
}

impl LocalDaemonWorkspaceAuthorizer {
    /// The daemon dispatcher supplies roots it has already authorized for the
    /// owner principal. This boundary never treats an arbitrary canonical
    /// client string as workspace authority.
    pub fn new(authorized_roots: Vec<PathBuf>) -> Result<Self> {
        let authorized_roots = authorized_roots
            .into_iter()
            .map(|path| AuthorizedWorkspaceRoot::capture(&path))
            .collect::<Result<Vec<_>>>()?;
        Self::from_captured_roots(authorized_roots)
    }

    pub fn from_captured_roots(authorized_roots: Vec<AuthorizedWorkspaceRoot>) -> Result<Self> {
        ensure!(
            !authorized_roots.is_empty(),
            "daemon has no authorized workspace roots"
        );
        Ok(Self { authorized_roots })
    }
}

#[async_trait]
impl AgentWorkspaceAuthorizer for LocalDaemonWorkspaceAuthorizer {
    async fn authorize_workspace(&self, client_path: &str) -> Result<(String, PathBuf)> {
        let requested = Path::new(client_path);
        let path = self
            .authorized_roots
            .iter()
            .find_map(|root| root.verify(requested).ok())
            .context("requested workspace is not authorized for this daemon client")?;
        Ok((canonical_workspace_id(&path), path))
    }
}

pub(crate) fn canonical_workspace_id(path: &Path) -> String {
    let identity = sha256_hex(path.to_string_lossy().as_bytes());
    format!("workspace:{identity}")
}

/// HTTPS-only GitHub fetcher. Redirects are disabled rather than followed;
/// GitHub private-source authorization failures remain a redacted daemon
/// error. Credential injection is intentionally a separate daemon vault
/// adapter, never a DTO field.
pub struct GithubHttpsAgentFetcher {
    transport: Arc<dyn GithubHttpTransport>,
    /// Read once from daemon custody. It never crosses a DTO, journal, DB
    /// record, error string, or tracing field.
    authorization: Option<String>,
}

/// Internal request boundary for the concrete GitHub fetcher. This is not a
/// protocol DTO and deliberately has no serializer or Debug implementation:
/// `authorization` stays in daemon process memory and never reaches a
/// journal, operation receipt, error, or tracing field.
struct GithubHttpRequest {
    url: String,
    authorization: Option<String>,
    timeout: std::time::Duration,
}

struct GithubHttpResponse {
    status: u16,
    content_length: Option<u64>,
    body: BoxStream<'static, Result<Vec<u8>>>,
}

#[async_trait]
trait GithubHttpTransport: Send + Sync {
    async fn get(&self, request: GithubHttpRequest) -> Result<GithubHttpResponse>;
}

struct ReqwestGithubHttpTransport {
    client: reqwest::Client,
}

#[async_trait]
impl GithubHttpTransport for ReqwestGithubHttpTransport {
    async fn get(&self, request: GithubHttpRequest) -> Result<GithubHttpResponse> {
        ensure!(
            request.url.starts_with("https://"),
            "GitHub source transport only permits HTTPS"
        );
        let request_builder = match request.authorization {
            Some(header) => self
                .client
                .get(&request.url)
                .header(reqwest::header::AUTHORIZATION, header),
            None => self.client.get(&request.url),
        };
        // Keep an explicit per-request deadline in addition to the client
        // default so a future transport/client configuration change cannot
        // silently remove the 20-second daemon fetch bound.
        let response = tokio::time::timeout(request.timeout, request_builder.send())
            .await
            .context("GitHub source request exceeded 20-second timeout")??;
        let status = response.status().as_u16();
        let content_length = response.content_length();
        let body = response
            .bytes_stream()
            .map(|chunk| {
                chunk
                    .map(|bytes| bytes.to_vec())
                    .map_err(anyhow::Error::from)
            })
            .boxed();
        Ok(GithubHttpResponse {
            status,
            content_length,
            body,
        })
    }
}

impl GithubHttpsAgentFetcher {
    pub fn new(vault: Arc<crate::secure_key::SecretVault>) -> Result<Self> {
        let credentials = crate::credentials::CredentialStore::from_vault(vault)
            .context("opening daemon credential store for GitHub source access")?;
        // This is a daemon-local credential-store entry, deliberately not an
        // ambient GH_TOKEN/GITHUB_TOKEN fallback. A missing entry simply makes
        // a private source return the same redacted authorization error.
        let authorization = credentials
            .named_secret("github-source-token")
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned);
        Ok(Self {
            transport: Arc::new(ReqwestGithubHttpTransport {
                client: reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(GITHUB_FETCH_TIMEOUT)
                    .user_agent("flycockpit-agent-installation")
                    .build()
                    .context("building GitHub installation client")?,
            }),
            authorization,
        })
    }

    #[cfg(test)]
    fn with_transport(
        transport: Arc<dyn GithubHttpTransport>,
        authorization: Option<String>,
    ) -> Self {
        Self {
            transport,
            authorization,
        }
    }

    async fn request(&self, url: String) -> Result<GithubHttpResponse> {
        self.transport
            .get(GithubHttpRequest {
                url,
                authorization: self
                    .authorization
                    .as_ref()
                    .map(|token| format!("Bearer {token}")),
                timeout: GITHUB_FETCH_TIMEOUT,
            })
            .await
    }
}

async fn read_github_response_body(response: GithubHttpResponse) -> Result<Vec<u8>> {
    ensure!(
        response
            .content_length
            .is_none_or(|length| length <= MAX_AGENT_MARKDOWN_BYTES as u64),
        "GitHub response exceeds 1MiB"
    );
    let mut bytes = Vec::new();
    let mut body = response.body;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.context("streaming GitHub response")?;
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_AGENT_MARKDOWN_BYTES,
            "GitHub response exceeds 1MiB"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[async_trait]
impl AgentInstallationFetcher for GithubHttpsAgentFetcher {
    async fn fetch_github_markdown(
        &self,
        source: &CanonicalAgentSource,
    ) -> Result<FetchedAgentSource> {
        let revision = source.requested_revision.as_deref().unwrap_or("HEAD");
        let commit_url = format!(
            "https://api.github.com/repos/{}/{}/commits/{}",
            source.owner, source.repository, revision
        );
        let commit = self
            .request(commit_url)
            .await
            .context("requesting GitHub commit")?;
        ensure!(
            (200..300).contains(&commit.status),
            "GitHub source authorization or commit resolution failed"
        );
        let value: serde_json::Value = serde_json::from_slice(
            &read_github_response_body(commit)
                .await
                .context("reading GitHub commit response")?,
        )
        .context("decoding GitHub commit response")?;
        let commit_sha = value
            .get("sha")
            .and_then(serde_json::Value::as_str)
            .context("GitHub commit response did not contain a SHA")?
            .to_owned();
        ensure!(
            is_commit_sha(&commit_sha),
            "GitHub commit response contained invalid SHA"
        );
        let raw_url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}/{}",
            source.owner, source.repository, commit_sha, source.markdown_path
        );
        let response = self
            .request(raw_url)
            .await
            .context("requesting GitHub agent Markdown")?;
        ensure!(
            (200..300).contains(&response.status),
            "GitHub agent source authorization or fetch failed"
        );
        // Keep the bounded-reader error as the outer error so callers can
        // distinguish the hard 1MiB rejection from a transport failure.
        let bytes = read_github_response_body(response).await?;
        Ok(FetchedAgentSource {
            commit_sha,
            markdown: bytes,
        })
    }
}

pub struct AgentInstallationService {
    db: Db,
    daemon_agents_dir: PathBuf,
    fetcher: Arc<dyn AgentInstallationFetcher>,
    workspaces: Arc<dyn AgentWorkspaceAuthorizer>,
    providers: ProvidersConfig,
}

/// The durable context carried from an install/update publication into the
/// optional binding continuation. Grouping it prevents this internal handoff
/// from drifting into an unstructured long argument list.
struct BindBeginInput {
    request: AgentInstallationBeginV1,
    workspace_id: Option<String>,
    workspace_root: Option<PathBuf>,
    now: i64,
    installed_id: Option<Uuid>,
    parent_receipt_status: Option<AgentInstallationReceiptStatusV1>,
    parent_source_revision: Option<String>,
}

/// Development-only process-boundary fixture switch.  It is deliberately
/// compiled out of release artifacts: production daemons always construct the
/// HTTPS/vault-backed service and cannot be redirected by an environment
/// variable.  The fixture file is test data, not a user configuration format.
#[cfg(debug_assertions)]
pub const DEBUG_AGENT_INSTALLATION_FIXTURE_ENV: &str = "COCKPIT_DEBUG_AGENT_INSTALLATION_FIXTURE";

#[cfg(debug_assertions)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DebugAgentInstallationFixture {
    commit_sha: String,
    markdown: String,
    workspace_path: PathBuf,
    #[serde(default)]
    providers: std::collections::BTreeMap<String, DebugFixtureProvider>,
}

#[cfg(debug_assertions)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DebugFixtureProvider {
    #[serde(default)]
    template: Option<String>,
    #[serde(default)]
    models: Vec<DebugFixtureModel>,
}

#[cfg(debug_assertions)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DebugFixtureModel {
    id: String,
    #[serde(default)]
    context_length: Option<u32>,
    #[serde(default)]
    capabilities: ModelCapabilities,
}

#[cfg(debug_assertions)]
struct DebugFixtureFetcher {
    source: FetchedAgentSource,
}

#[cfg(debug_assertions)]
#[async_trait]
impl AgentInstallationFetcher for DebugFixtureFetcher {
    async fn fetch_github_markdown(
        &self,
        _source: &CanonicalAgentSource,
    ) -> Result<FetchedAgentSource> {
        Ok(self.source.clone())
    }
}

#[cfg(debug_assertions)]
struct DebugFixtureWorkspaceAuthorizer {
    workspace: PathBuf,
}

#[cfg(debug_assertions)]
#[async_trait]
impl AgentWorkspaceAuthorizer for DebugFixtureWorkspaceAuthorizer {
    async fn authorize_workspace(&self, client_path: &str) -> Result<(String, PathBuf)> {
        let requested = std::fs::canonicalize(client_path)
            .context("canonicalizing debug fixture workspace request")?;
        ensure!(
            requested == self.workspace,
            "debug fixture workspace request is not authorized"
        );
        Ok(("workspace:debug-fixture".to_owned(), self.workspace.clone()))
    }
}

/// Construct the immutable scripted coordinator used by debug integration
/// daemons.  The JSON contains only markdown, a commit SHA, provider catalog
/// data, and an authorized workspace path; credentials and HTTP routing are
/// intentionally not representable here.
#[cfg(debug_assertions)]
pub fn debug_fixture_daemon_service(
    db: Db,
    daemon_paths: &crate::daemon::DaemonPaths,
) -> Result<Option<AgentInstallationService>> {
    let Some(path) = std::env::var_os(DEBUG_AGENT_INSTALLATION_FIXTURE_ENV) else {
        return Ok(None);
    };
    let raw = std::fs::read(&path).context("reading debug agent-installation fixture")?;
    let fixture: DebugAgentInstallationFixture =
        serde_json::from_slice(&raw).context("decoding debug agent-installation fixture")?;
    ensure!(
        is_commit_sha(&fixture.commit_sha),
        "debug agent-installation fixture commit SHA is invalid"
    );
    ensure!(
        fixture.markdown.len() <= MAX_AGENT_MARKDOWN_BYTES,
        "debug agent-installation fixture Markdown exceeds 1MiB"
    );
    let workspace = std::fs::canonicalize(&fixture.workspace_path)
        .context("canonicalizing debug fixture workspace")?;
    ensure!(
        workspace.is_dir(),
        "debug fixture workspace is not a directory"
    );
    let state = daemon_paths
        .pid_file
        .parent()
        .context("daemon pid file has no state directory")?;
    let providers = ProvidersConfig {
        providers: fixture
            .providers
            .into_iter()
            .map(|(profile, provider)| {
                ensure!(
                    !profile.trim().is_empty(),
                    "debug fixture provider profile must not be empty"
                );
                let entry = ProviderEntry {
                    template: provider.template,
                    models: provider
                        .models
                        .into_iter()
                        .map(|model| ModelEntry {
                            id: model.id,
                            context_length: model.context_length,
                            capabilities: model.capabilities,
                            ..ModelEntry::default()
                        })
                        .collect(),
                    ..ProviderEntry::default()
                };
                Ok((profile, entry))
            })
            .collect::<Result<_>>()?,
        ..ProvidersConfig::default()
    };
    Ok(Some(AgentInstallationService::new(
        db,
        state.join("agents"),
        Arc::new(DebugFixtureFetcher {
            source: FetchedAgentSource {
                commit_sha: fixture.commit_sha,
                markdown: fixture.markdown.into_bytes(),
            },
        }),
        Arc::new(DebugFixtureWorkspaceAuthorizer { workspace }),
        providers,
    )))
}

impl AgentInstallationService {
    pub fn new(
        db: Db,
        daemon_agents_dir: PathBuf,
        fetcher: Arc<dyn AgentInstallationFetcher>,
        workspaces: Arc<dyn AgentWorkspaceAuthorizer>,
        providers: ProvidersConfig,
    ) -> Self {
        Self {
            db,
            daemon_agents_dir,
            fetcher,
            workspaces,
            providers,
        }
    }

    pub async fn begin(
        &self,
        request: AgentInstallationBeginV1,
        now_unix_ms: i64,
    ) -> AgentInstallationResultV1 {
        match self.begin_inner(request, now_unix_ms).await {
            Ok(result) => result,
            Err(error) => redacted_error(error),
        }
    }

    async fn begin_inner(
        &self,
        request: AgentInstallationBeginV1,
        now: i64,
    ) -> Result<AgentInstallationResultV1> {
        ensure!(
            request.dto_version == AGENT_INSTALLATION_DTO_VERSION,
            "unsupported installation DTO version"
        );
        validate_idempotency_key(&request.idempotency_key)?;
        let (workspace_id, workspace_root) = self
            .resolve_scope(request.scope, request.workspace_path.as_deref())
            .await?;
        // Read before fetching so a retry with a durable journal can recover
        // its pinned staged source rather than consulting a mutable ref. For a
        // fresh shared request, an existing file is reconciled (not blindly
        // refused) before any operation/journal/installation mutation.
        let existing_operation = self
            .db
            .installation_operation(request.idempotency_key.clone())
            .await?;
        // A fresh update authorizes its explicit target before it asks a
        // remote source anything (or creates an idempotency row). This makes
        // a wrong scope, workspace, source, or UUID a pure refusal. A replay
        // deliberately skips this branch: its durable operation/journal is
        // the source of truth and a terminal receipt always wins.
        let fresh_update_target = if existing_operation.is_none()
            && request.operation == AgentInstallationOperationKind::Update
        {
            ensure!(
                request.replace_acknowledged,
                "update requires explicit replacement acknowledgement"
            );
            Some(
                self.validate_update_target(&request, workspace_id.as_deref())
                    .await?,
            )
        } else {
            None
        };
        // Parse and fetch all fresh install/update requests before creating an
        // operation. In particular, an invalid manifest must never leave an
        // orphan operation or owned file behind. Nonterminal recovery never
        // enters this branch and instead uses its pinned staged bytes below.
        let fresh_prefetched = if existing_operation.is_none()
            && matches!(
                request.operation,
                AgentInstallationOperationKind::Install | AgentInstallationOperationKind::Update
            ) {
            Some(
                self.prefetch_fresh_source(
                    &request,
                    fresh_update_target
                        .as_ref()
                        .map(|target| target.source_agent_id.as_str()),
                )
                .await?,
            )
        } else {
            None
        };
        let fresh_staged_journal = fresh_prefetched
            .as_ref()
            .map(|fetched| staged_source_journal_metadata(&request.source_locator, fetched))
            .transpose()?;
        if existing_operation.is_none()
            && request.scope == AgentInstallationScopeWire::WorkspaceShared
            && matches!(
                request.operation,
                AgentInstallationOperationKind::Install | AgentInstallationOperationKind::Update
            )
        {
            self.preflight_shared_collision(
                &request,
                workspace_id.as_deref(),
                workspace_root.as_deref(),
                fresh_prefetched
                    .as_ref()
                    .expect("fresh install/update source was prefetched"),
            )
            .await?;
        }
        let fingerprint = request_fingerprint(&request, workspace_id.as_deref());
        let kind = operation_kind(request.operation);
        let begun = match fresh_staged_journal {
            Some((staged_file_metadata_json, expected_digest)) => {
                self.db
                    .begin_installation_operation_with_staged_journal(
                        request.idempotency_key.clone(),
                        fingerprint,
                        kind,
                        workspace_id.clone(),
                        staged_file_metadata_json,
                        expected_digest,
                        now,
                    )
                    .await?
            }
            None => {
                self.db
                    .begin_installation_operation(
                        request.idempotency_key.clone(),
                        fingerprint,
                        kind,
                        workspace_id.clone(),
                        now,
                    )
                    .await?
            }
        };
        let created = match begun {
            BeginInstallationOperation::KeyConflict => {
                bail!("idempotency key was previously used for a different request")
            }
            BeginInstallationOperation::Replay(operation) => {
                if operation.terminal_receipt_json.is_some() {
                    return replay_operation(operation.terminal_receipt_json.as_deref());
                }
                if let Some(continuation) = self
                    .db
                    .installation_continuation_for_operation(operation.operation_id)
                    .await?
                {
                    let choice_set: BindChoiceSet =
                        serde_json::from_str(&continuation.choice_set_json)
                            .context("stored installation choice set is corrupt")?;
                    validate_durable_choice_set(&choice_set)?;
                    if let Some(choice_id) = choice_set.auto_choice_id {
                        ensure!(
                            continuation.submitted_choice_id.as_deref().is_none()
                                || continuation.submitted_choice_id.as_deref()
                                    == Some(choice_id.as_str()),
                            "durable automatic choice was claimed by a different choice"
                        );
                        // A crash can occur after the continuation claim and
                        // before binding or terminalization. Resume this exact
                        // durable selection; never refetch or rerank.
                        return Ok(self
                            .submit_choice(
                                AgentInstallationSubmitChoiceV1 {
                                    dto_version: AGENT_INSTALLATION_DTO_VERSION,
                                    continuation_token: continuation.continuation_token.to_string(),
                                    choice_id: Some(choice_id),
                                    defer: false,
                                },
                                now,
                            )
                            .await);
                    }
                    if operation.state == InstallationOperationState::PendingChoice {
                        return Ok(AgentInstallationResultV1::NeedsChoice {
                            continuation_token: continuation.continuation_token.to_string(),
                            choices: choice_set.choices,
                            unmatched_recommendations: choice_set.unmatched_recommendations,
                            expires_at_unix_ms: continuation.expires_at_unix_ms,
                        });
                    }
                }
                // A crash after durable begin is resumed under the original
                // operation id/fingerprint. The journal below decides which
                // file checkpoint remains; this never creates a second DB
                // binding/snapshot/revision mutation.
                false
            }
            BeginInstallationOperation::Created(_) => true,
        };
        match request.operation {
            AgentInstallationOperationKind::Install | AgentInstallationOperationKind::Update => {
                self.install_or_update(
                    request,
                    workspace_id,
                    workspace_root,
                    now,
                    created.then_some(fresh_update_target).flatten(),
                    created.then_some(fresh_prefetched).flatten(),
                )
                .await
            }
            AgentInstallationOperationKind::Create => {
                self.create(request, workspace_id, workspace_root, now)
                    .await
            }
            AgentInstallationOperationKind::Bind => {
                self.bind_begin(BindBeginInput {
                    request,
                    workspace_id,
                    workspace_root,
                    now,
                    installed_id: None,
                    parent_receipt_status: None,
                    parent_source_revision: None,
                })
                .await
            }
        }
    }

    pub async fn submit_choice(
        &self,
        request: AgentInstallationSubmitChoiceV1,
        now: i64,
    ) -> AgentInstallationResultV1 {
        let result = async {
            ensure!(
                request.dto_version == AGENT_INSTALLATION_DTO_VERSION,
                "unsupported installation DTO version"
            );
            let token = Uuid::parse_str(&request.continuation_token)
                .context("invalid continuation token")?;
            let state = self
                .db
                .installation_continuation_state(token)
                .await?
                .context("unknown installation continuation")?;
            let mut continuation = state.continuation;
            // A terminal receipt wins every expiry/retry race.  Check it
            // before attempting the continuation CAS so a late submit never
            // manufactures a second outcome.
            let current_operation = state.operation;
            if let Some(receipt) = current_operation.terminal_receipt_json.as_deref() {
                return serde_json::from_str(receipt)
                    .context("stored installation receipt is corrupt");
            }
            let choice_set: BindChoiceSet = serde_json::from_str(&continuation.choice_set_json)
                .context("stored installation choice set is corrupt")?;
            validate_durable_choice_set(&choice_set)?;
            ensure!(
                request.defer ^ request.choice_id.is_some(),
                "submit exactly one installation choice or defer it"
            );
            let submitted_choice = if request.defer {
                "__deferred__"
            } else {
                request
                    .choice_id
                    .as_deref()
                    .context("missing installation choice")?
            };
            if !request.defer {
                // This must happen before either CAS. An unknown choice must
                // never wedge a still-pending continuation as claimed.
                ensure!(
                    choice_set
                        .choices
                        .iter()
                        .any(|choice| choice.choice_id == submitted_choice),
                    "unknown installation choice"
                );
            }
            let operation = if continuation.expires_at_unix_ms <= now {
                let timeout = receipt(
                    continuation.operation_id,
                    AgentInstallationReceiptStatusV1::TimedOut,
                    None,
                    None,
                );
                if let Some(operation) = self
                    .db
                    .expire_installation_continuation(token, now, serde_json::to_string(&timeout)?)
                    .await?
                {
                    return replay_operation(operation.terminal_receipt_json.as_deref());
                }
                let state = self
                    .db
                    .installation_continuation_state(token)
                    .await?
                    .context("installation continuation disappeared")?;
                if let Some(receipt) = state.operation.terminal_receipt_json.as_deref() {
                    return serde_json::from_str(receipt)
                        .context("stored installation receipt is corrupt");
                }
                ensure!(
                    state.continuation.submitted_choice_id.as_deref() == Some(submitted_choice),
                    "continuation expired or was claimed by another choice"
                );
                continuation = state.continuation;
                state.operation
            } else {
                match self
                    .db
                    .claim_installation_continuation(token, submitted_choice.to_owned(), now)
                    .await?
                {
                    Some(operation) => operation,
                    None => {
                        let state = self
                            .db
                            .installation_continuation_state(token)
                            .await?
                            .context("installation continuation disappeared")?;
                        if let Some(receipt) = state.operation.terminal_receipt_json.as_deref() {
                            return serde_json::from_str(receipt)
                                .context("stored installation receipt is corrupt");
                        }
                        ensure!(
                            state.continuation.submitted_choice_id.as_deref()
                                == Some(submitted_choice),
                            "unknown, expired, or already claimed installation choice"
                        );
                        continuation = state.continuation;
                        state.operation
                    }
                }
            };
            let choice_set: BindChoiceSet = serde_json::from_str(&continuation.choice_set_json)
                .context("stored installation choice set is corrupt")?;
            validate_durable_choice_set(&choice_set)?;
            if request.defer {
                let slot_id = choice_set
                    .choices
                    .first()
                    .context("stored choice set has no selectable choices")?
                    .slot_id
                    .as_str();
                let status = if slot_id == "primary" {
                    AgentInstallationReceiptStatusV1::PrimaryUnusable
                } else {
                    AgentInstallationReceiptStatusV1::OptionalUnbound
                };
                let installation_id = Uuid::parse_str(&choice_set.installation_id)
                    .context("stored installation id is invalid")?;
                let receipt = binding_terminal_receipt(
                    operation.operation_id,
                    choice_set.parent_receipt_status,
                    choice_set.parent_source_revision.clone(),
                    status,
                    installation_id,
                );
                self.db
                    .finish_installation_operation(
                        operation.operation_id,
                        serde_json::to_string(&receipt)?,
                        now,
                    )
                    .await?;
                return Ok(receipt);
            }
            let choice = choice_set
                .choices
                .iter()
                .find(|choice| choice.choice_id == submitted_choice)
                .context("submitted installation choice was not offered")?;
            let installation_id = Uuid::parse_str(&choice_set.installation_id)
                .context("stored installation id is invalid")?;
            let bindings =
                binding_inputs_for_submission(&choice_set, &choice.slot_id, submitted_choice)?;
            let outcome = self
                .db
                .bind_agent_slot_set(cockpit_db::db::agent_installations::AgentBindSlotSetInput {
                    installation_id,
                    expected_observation_revision: choice_set.expected_observation_revision,
                    expected_definition_digest: choice_set.definition_digest.clone(),
                    expected_binding_revision: choice_set.expected_binding_revision,
                    idempotency_key: operation.operation_id.to_string(),
                    request_fingerprint: operation.request_fingerprint.clone(),
                    bindings,
                    now_unix_ms: now,
                })
                .await?;
            let refusal = terminal_bind_refusal_code(&outcome);
            if let Some(code) = refusal {
                // Claiming a continuation transfers responsibility for a
                // terminal outcome to this operation. A stale or incompatible
                // DB result is not a transport failure: persist the same
                // typed, redacted result before returning so replay, a
                // same-choice CAS loser, and an expiry race can never strand
                // it in `claimed`/`running`.
                let refusal = typed_installation_error(code);
                self.db
                    .finish_installation_operation(
                        operation.operation_id,
                        serde_json::to_string(&refusal)?,
                        now,
                    )
                    .await?;
                return Ok(refusal);
            }
            let receipt = binding_terminal_receipt(
                operation.operation_id,
                choice_set.parent_receipt_status,
                choice_set.parent_source_revision.clone(),
                AgentInstallationReceiptStatusV1::Bound,
                installation_id,
            );
            let json = serde_json::to_string(&receipt)?;
            self.db
                .finish_installation_operation(operation.operation_id, json, now)
                .await?;
            Ok(receipt)
        }
        .await;
        result.unwrap_or_else(redacted_error)
    }

    async fn bind_begin(&self, input: BindBeginInput) -> Result<AgentInstallationResultV1> {
        let BindBeginInput {
            request,
            workspace_id,
            workspace_root,
            now,
            installed_id,
            parent_receipt_status,
            parent_source_revision,
        } = input;
        let operation = self
            .db
            .installation_operation(request.idempotency_key.clone())
            .await?
            .context("binding operation was not recorded")?;
        let installation_id = match installed_id {
            Some(id) => id,
            None => Uuid::parse_str(&request.source_locator)
                .context("bind source_locator must be an installation id")?,
        };
        let installation = self
            .db
            .agent_installation(installation_id)
            .await?
            .context("agent installation was not found")?;
        ensure!(
            installation.scope == db_scope(request.scope)
                && installation.canonical_workspace_id == workspace_id,
            "installation does not belong to requested scope"
        );
        let observation = self
            .db
            .agent_observation(installation_id)
            .await?
            .context("agent installation has no observation")?;
        ensure!(
            observation.reviewed && observation.observed_digest == installation.source_digest,
            "agent installation is unreviewed or no longer current"
        );
        let name = installation
            .source_agent_id
            .rsplit('/')
            .next()
            .context("invalid installed agent id")?;
        let target = existing_owned_definition_path(
            &self.daemon_agents_dir,
            workspace_root.as_deref(),
            request.scope,
            name,
        )?;
        ensure_no_reparse_components(target.parent().context("owned target missing parent")?)?;
        reject_reparse_leaf(&target)?;
        let definition = crate::agents::load_owned_definition(
            &target,
            name,
            installation_definition_scope(installation.scope, &installation.source_agent_id),
        )
        .context("loading daemon-owned agent definition")?;
        let vnext = definition
            .vnext
            .as_ref()
            .context("installed definition is not vNext")?;
        let slot_id = request.requested_slot.as_deref().unwrap_or("primary");
        let slot = vnext
            .model_slots
            .get(slot_id)
            .context("requested model slot does not exist")?;
        let expected_binding_revision = self
            .db
            .current_agent_binding(
                installation_id,
                installation.source_digest.clone(),
                slot_id.to_owned(),
            )
            .await?
            .map(|binding| binding.binding_revision);
        // `setup_offerings` assigns custom-provider tokens from the canonical
        // provider-map order. Keep that identity on the offering through
        // ranking/filtering; a compatible-slice index is never a provider
        // identity.
        let offerings = setup_offerings(&self.providers);
        let ranked = crate::agents::ranked_compatible_offerings(slot, &offerings, &self.providers);
        if ranked.is_empty() {
            let status = if slot_id == "primary" {
                AgentInstallationReceiptStatusV1::PrimaryUnusable
            } else {
                AgentInstallationReceiptStatusV1::OptionalUnbound
            };
            let receipt = binding_terminal_receipt(
                operation.operation_id,
                parent_receipt_status,
                parent_source_revision.clone(),
                status,
                installation_id,
            );
            self.db
                .finish_installation_operation(
                    operation.operation_id,
                    serde_json::to_string(&receipt)?,
                    now,
                )
                .await?;
            return Ok(receipt);
        }
        let (choices, unmatched_recommendations) = binding_choices(slot_id, slot, &ranked);
        let routes = durable_binding_routes(slot, &ranked, &choices)?;
        let automatic_choice = if request.auto_select_first_exact {
            match automatic_binding_choice(slot, &choices, &routes) {
                Some(choice) => Some(choice),
                None => {
                    let status = if slot_id == "primary" {
                        AgentInstallationReceiptStatusV1::PrimaryUnusable
                    } else {
                        AgentInstallationReceiptStatusV1::OptionalUnbound
                    };
                    let receipt = binding_terminal_receipt(
                        operation.operation_id,
                        parent_receipt_status,
                        parent_source_revision.clone(),
                        status,
                        installation_id,
                    );
                    self.db
                        .finish_installation_operation(
                            operation.operation_id,
                            serde_json::to_string(&receipt)?,
                            now,
                        )
                        .await?;
                    return Ok(receipt);
                }
            }
        } else {
            None
        };
        let continuation = self
            .db
            .create_installation_continuation(
                operation.operation_id,
                serde_json::to_string(&BindChoiceSet {
                    installation_id: installation_id.to_string(),
                    definition_digest: installation.source_digest.clone(),
                    expected_observation_revision: observation.observation_revision,
                    expected_binding_revision,
                    choices: choices.clone(),
                    unmatched_recommendations: unmatched_recommendations.clone(),
                    routes,
                    authored_default_required: !slot.models.is_empty(),
                    parent_receipt_status,
                    parent_source_revision,
                    auto_choice_id: automatic_choice.clone(),
                })?,
                now + 600_000,
                now,
            )
            .await?;
        if let Some(choice_id) = automatic_choice {
            return Ok(self
                .submit_choice(
                    AgentInstallationSubmitChoiceV1 {
                        dto_version: AGENT_INSTALLATION_DTO_VERSION,
                        continuation_token: continuation.continuation_token.to_string(),
                        choice_id: Some(choice_id),
                        defer: false,
                    },
                    now,
                )
                .await);
        }
        Ok(AgentInstallationResultV1::NeedsChoice {
            continuation_token: continuation.continuation_token.to_string(),
            choices,
            unmatched_recommendations,
            expires_at_unix_ms: continuation.expires_at_unix_ms,
        })
    }

    pub async fn list(&self, request: AgentInstallationReadV1) -> AgentInstallationResultV1 {
        let result = async {
            ensure!(
                request.dto_version == AGENT_INSTALLATION_DTO_VERSION,
                "unsupported installation DTO version"
            );
            let (workspace_id, workspace_root) = self
                .resolve_scope(request.scope, request.workspace_path.as_deref())
                .await?;
            let rows = self
                .db
                .list_agent_installations(db_scope(request.scope), workspace_id)
                .await?;
            let mut installations = Vec::with_capacity(rows.len());
            for row in rows
                .into_iter()
                .filter(|row| !is_package_child_installation(row))
            {
                installations.push(self.record(row, workspace_root.as_deref()).await?);
            }
            Ok(AgentInstallationResultV1::Listed { installations })
        }
        .await;
        result.unwrap_or_else(redacted_error)
    }

    pub async fn inspect(&self, request: AgentInstallationReadV1) -> AgentInstallationResultV1 {
        let result = async {
            ensure!(
                request.dto_version == AGENT_INSTALLATION_DTO_VERSION,
                "unsupported installation DTO version"
            );
            let (workspace_id, workspace_root) = self
                .resolve_scope(request.scope, request.workspace_path.as_deref())
                .await?;
            let id = request
                .installation_id
                .context("inspect requires installation id")?;
            let installation_id = Uuid::parse_str(&id).context("invalid installation id")?;
            let row = self.db.agent_installation(installation_id).await?;
            let row = row.filter(|row| {
                row.scope == db_scope(request.scope)
                    && row.canonical_workspace_id == workspace_id
                    && !is_package_child_installation(row)
            });
            Ok(AgentInstallationResultV1::Inspected {
                installation: match row {
                    Some(row) => Some(self.record(row, workspace_root.as_deref()).await?),
                    None => None,
                },
            })
        }
        .await;
        result.unwrap_or_else(redacted_error)
    }

    /// Build the read-only session-setup projection from an already-authorized
    /// workspace and a daemon-owned selected installation.  This intentionally
    /// shares installed-definition parsing, current-binding reads, and exact
    /// profile ranking with installation binding; it never accepts a provider
    /// profile handle, a source path, or a client-selected agent identity.
    pub async fn session_setup_snapshot(
        &self,
        session_id: Uuid,
        canonical_workspace_id: String,
        workspace_root: Option<&AuthorizedWorkspaceRoot>,
        providers: &ProvidersConfig,
        config_generation: u64,
        global_config_generation: u64,
        config_fingerprint: &str,
        project_sources_projected: bool,
    ) -> Result<SessionSetupSnapshotV1> {
        // Filesystem reads cannot join SQLite's snapshot, so retry a bounded
        // number of times if installation/profile/binding state changes while
        // they are read. Never publish a torn "revision" for later CAS.
        for _ in 0..3 {
            let db_snapshot = self
                .db
                .session_setup_snapshot(session_id, canonical_workspace_id.clone())
                .await?;
            let selected_installation_id = db_snapshot.selected_installation_id;
            let mut rows = db_snapshot.installations.clone();
            rows.retain(|row| !is_package_child_installation(&row.installation));
            rows.sort_by(|left, right| {
                setup_scope_rank(left.installation.scope)
                    .cmp(&setup_scope_rank(right.installation.scope))
                    .then_with(|| {
                        left.installation
                            .source_agent_id
                            .cmp(&right.installation.source_agent_id)
                    })
                    .then_with(|| {
                        left.installation
                            .installation_id
                            .cmp(&right.installation.installation_id)
                    })
            });
            let mut projections = Vec::with_capacity(rows.len());
            for row in &rows {
                let selected = selected_installation_id == Some(row.installation.installation_id);
                projections.push(self.session_setup_candidate(
                    row,
                    workspace_root,
                    providers,
                    selected,
                    project_sources_projected,
                )?);
            }
            // Definition files sit outside SQLite. Reproject them before the
            // final DB validation and publish only if their exact vNext
            // digests and the public projection are unchanged. This is
            // deliberately a bounded retry rather than a daemon-wide lock
            // across file IO.
            let mut confirmed = Vec::with_capacity(rows.len());
            for row in &rows {
                let selected = selected_installation_id == Some(row.installation.installation_id);
                confirmed.push(self.session_setup_candidate(
                    row,
                    workspace_root,
                    providers,
                    selected,
                    project_sources_projected,
                )?);
            }
            if projections != confirmed {
                continue;
            }
            // Re-read every durable input after the final external reads, so
            // the revision never claims a mixture of two DB authority views.
            let after = self
                .db
                .session_setup_snapshot(session_id, canonical_workspace_id.clone())
                .await?;
            if session_setup_db_snapshot_fingerprint(&db_snapshot)
                != session_setup_db_snapshot_fingerprint(&after)
            {
                continue;
            }
            let candidates = projections
                .into_iter()
                .map(|projection| projection.candidate)
                .collect::<Vec<_>>();
            let revision = session_setup_revision(
                selected_installation_id,
                &candidates,
                &session_setup_db_snapshot_fingerprint(&after),
                config_generation,
                global_config_generation,
                config_fingerprint,
            );
            return Ok(SessionSetupSnapshotV1 {
                dto_version: SESSION_SETUP_DTO_VERSION,
                session_id: session_id.to_string(),
                revision,
                config_generation,
                selected_installation_id: selected_installation_id.map(|id| id.to_string()),
                candidates,
            });
        }
        bail!("session setup authority changed while projecting snapshot; retry request")
    }

    /// Convenience boundary for daemon dispatch. Its root is taken from an
    /// already-authorized attached-session handle, never from request data;
    /// derive the same opaque identity used by the installation boundary
    /// without narrowing the query to the daemon process's startup cwd.
    pub async fn session_setup_snapshot_for_attached_workspace(
        &self,
        session_id: Uuid,
        workspace_root: &AuthorizedWorkspaceRoot,
        providers: &ProvidersConfig,
        config_generation: u64,
        global_config_generation: u64,
        config_fingerprint: &str,
        project_sources_projected: bool,
    ) -> Result<SessionSetupSnapshotV1> {
        let (workspace_id, canonical_workspace_root) = self
            .workspaces
            .authorize_workspace(&workspace_root.canonical_path().to_string_lossy())
            .await
            .context("authorizing attached session workspace")?;
        ensure!(
            canonical_workspace_root == workspace_root.canonical_path(),
            "attached workspace authorization returned a different canonical root"
        );
        self.session_setup_snapshot(
            session_id,
            workspace_id,
            Some(workspace_root),
            providers,
            config_generation,
            global_config_generation,
            config_fingerprint,
            project_sources_projected,
        )
        .await
    }

    fn session_setup_candidate(
        &self,
        row: &SessionSetupInstallationSnapshotRow,
        workspace_root: Option<&AuthorizedWorkspaceRoot>,
        providers: &ProvidersConfig,
        selected: bool,
        project_sources_projected: bool,
    ) -> Result<SessionSetupCandidateProjection> {
        // `record` remains the one wire projection for source/version/digest
        // and current binding state.  If the daemon can no longer read the
        // owned definition, preserve the non-secret durable identity while
        // making the candidate explicitly unavailable instead of leaking IO
        // details or silently selecting a fallback.
        let mut installation = setup_installation_record(&row.installation);
        let name = match row.installation.source_agent_id.rsplit('/').next() {
            Some(name) => name,
            None => return Ok(SessionSetupCandidateProjection::unavailable(row, selected)),
        };
        let definition = match row.installation.scope {
            AgentInstallationScope::WorkspaceShared => {
                // A workspace-shared definition is a PROJECT source. When the
                // current trust policy does not project project sources (e.g.
                // Trust -> IgnoreConfig), it must not be read or rendered — the
                // redaction invariant is one-directional. Project it as
                // unavailable rather than opening the project agent file, the
                // same gate `retained_layer_is_projected`/`hook_source_is_projected`
                // apply to project config and hooks.
                if !project_sources_projected {
                    return Ok(SessionSetupCandidateProjection::unavailable(row, selected));
                }
                let Some(workspace_root) = workspace_root else {
                    return Ok(SessionSetupCandidateProjection::unavailable(row, selected));
                };
                match workspace_root.read_workspace_shared_definition(name) {
                    Ok(WorkspaceSharedDefinitionBytes::Flat(bytes)) => {
                        match std::str::from_utf8(&bytes).ok().and_then(|text| {
                            crate::agents::parse_agent(
                                text,
                                name,
                                PathBuf::from("<attached-workspace-agent>"),
                            )
                            .ok()
                        }) {
                            Some(definition) => definition,
                            None => {
                                return Ok(SessionSetupCandidateProjection::unavailable(
                                    row, selected,
                                ));
                            }
                        }
                    }
                    Ok(WorkspaceSharedDefinitionBytes::Package(files)) => {
                        match crate::agents::load_workspace_package_from_files(name, files) {
                            Ok(definition) => definition,
                            Err(_) => {
                                return Ok(SessionSetupCandidateProjection::unavailable(
                                    row, selected,
                                ));
                            }
                        }
                    }
                    Err(_) => {
                        return Ok(SessionSetupCandidateProjection::unavailable(row, selected));
                    }
                }
            }
            // Workspace-private definitions are daemon-owned state beneath
            // `daemon_agents_dir/private/<opaque-id>`; the attached root only
            // supplies that opaque key and is never used as filesystem
            // authority. Workspace-shared definitions above are the only
            // setup files resolved beneath a user workspace.
            AgentInstallationScope::Global | AgentInstallationScope::WorkspacePrivate => {
                let path = match setup_definition_path(
                    &self.daemon_agents_dir,
                    &row.installation,
                    workspace_root.map(AuthorizedWorkspaceRoot::canonical_path),
                ) {
                    Ok(path) => path,
                    Err(_) => {
                        return Ok(SessionSetupCandidateProjection::unavailable(row, selected));
                    }
                };
                match crate::agents::load_owned_definition(
                    &path,
                    name,
                    installation_definition_scope(
                        row.installation.scope,
                        &row.installation.source_agent_id,
                    ),
                ) {
                    Ok(definition) => definition,
                    Err(_) => {
                        return Ok(SessionSetupCandidateProjection::unavailable(row, selected));
                    }
                }
            }
        };
        let observed_digest = match definition.vnext_digest_bytes() {
            Ok(bytes) => sha256_hex(&bytes),
            Err(_) => return Ok(SessionSetupCandidateProjection::unavailable(row, selected)),
        };
        let Some(vnext) = definition.vnext else {
            return Ok(SessionSetupCandidateProjection::unavailable(row, selected));
        };
        let rebind_required = row.observation.as_ref().is_none_or(|observation| {
            !observation.reviewed || observation.observed_digest != observed_digest
        });
        let current_binding_sets = row.bindings.iter().cloned().fold(
            std::collections::BTreeMap::<_, Vec<_>>::new(),
            |mut bindings, binding| {
                bindings
                    .entry(binding.slot_id.clone())
                    .or_default()
                    .push(binding);
                bindings
            },
        );
        let current_defaults = current_binding_sets
            .iter()
            .filter_map(|(slot_id, bindings)| {
                bindings
                    .iter()
                    .find(|binding| binding.is_default)
                    .cloned()
                    .map(|binding| (slot_id.clone(), binding))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        // Shared definition records intentionally omit private binding state
        // from generic install/list RPCs. This attached, owner-local session
        // snapshot is the one presentation boundary that can safely render
        // the redacted state for every scope, still without a profile handle.
        installation.bindings = vnext
            .model_slots
            .iter()
            .map(|(slot_id, slot)| match current_defaults.get(slot_id) {
                Some(binding) => AgentInstallationSlotStatusV1 {
                    slot_id: slot_id.clone(),
                    state: if rebind_required {
                        AgentInstallationSlotBindingStateV1::RebindRequired
                    } else {
                        AgentInstallationSlotBindingStateV1::Bound
                    },
                    model_id: binding.model_id.clone(),
                },
                None => AgentInstallationSlotStatusV1 {
                    slot_id: slot_id.clone(),
                    state: if rebind_required {
                        AgentInstallationSlotBindingStateV1::RebindRequired
                    } else if slot_id == "primary" || slot.purpose.eq_ignore_ascii_case("primary") {
                        AgentInstallationSlotBindingStateV1::PrimaryUnusable
                    } else {
                        AgentInstallationSlotBindingStateV1::OptionalUnbound
                    },
                    model_id: String::new(),
                },
            })
            .collect();
        let offerings = setup_offerings(providers);
        let slots = vnext
            .model_slots
            .iter()
            .map(|(slot_id, slot)| {
                if rebind_required {
                    return SessionSetupModelSlotV1 {
                        slot_id: slot_id.clone(),
                        choices: Vec::new(),
                        choice_routes: Vec::new(),
                        allowed_choice_ids: Vec::new(),
                        unmatched_recommendations: Vec::new(),
                        unavailable_reason: Some(SessionSetupUnavailableReasonV1::RebindRequired),
                        default_choice_id: None,
                    };
                }
                let ranked =
                    crate::agents::ranked_compatible_offerings(slot, &offerings, providers);
                let (choices, unmatched_recommendations) = binding_choices(slot_id, slot, &ranked);
                let choice_routes = session_setup_choice_routes(&choices, &ranked);
                let bound_offering_ids = current_binding_sets
                    .get(slot_id)
                    .into_iter()
                    .flatten()
                    .filter_map(|binding| {
                        ranked
                            .iter()
                            .position(|offering| {
                                offering.provider_profile_handle == binding.provider_profile_handle
                                    && offering.model_id == binding.model_id
                            })
                            .map(|index| format!("offering-{index}"))
                    })
                    .collect::<std::collections::BTreeSet<_>>();
                let allowed_choice_ids = choices
                    .iter()
                    .filter(|choice| bound_offering_ids.contains(&choice.offering_id))
                    .map(|choice| choice.choice_id.clone())
                    .collect();
                let default_choice_id = current_defaults.get(slot_id).and_then(|binding| {
                    ranked
                        .iter()
                        .position(|offering| {
                            offering.provider_profile_handle == binding.provider_profile_handle
                                && offering.model_id == binding.model_id
                        })
                        .and_then(|index| {
                            let offering_id = format!("offering-{index}");
                            choices
                                .iter()
                                .find(|choice| choice.offering_id == offering_id)
                                .map(|choice| choice.choice_id.clone())
                        })
                });
                SessionSetupModelSlotV1 {
                    slot_id: slot_id.clone(),
                    unavailable_reason: choices
                        .is_empty()
                        .then_some(SessionSetupUnavailableReasonV1::NoHardCompatibleLocalModel),
                    choices,
                    choice_routes,
                    allowed_choice_ids,
                    unmatched_recommendations,
                    default_choice_id,
                }
            })
            .collect();
        Ok(SessionSetupCandidateProjection {
            candidate: SessionSetupAgentCandidateV1 {
                installation,
                selected,
                slots,
                locked_reason: rebind_required
                    .then_some(SessionSetupLockedReasonV1::RebindRequired),
            },
            definition_digest: Some(observed_digest),
        })
    }

    async fn validate_update_target(
        &self,
        request: &AgentInstallationBeginV1,
        workspace_id: Option<&str>,
    ) -> Result<AgentInstallationRow> {
        ensure!(
            request.operation == AgentInstallationOperationKind::Update,
            "only update has an installation target"
        );
        let source = CanonicalAgentSource::parse(&request.source_locator)?;
        let installation_id = Uuid::parse_str(
            request
                .target_installation_id
                .as_deref()
                .context("update requires target installation id")?,
        )
        .context("update target installation id is invalid")?;
        let installation = self
            .db
            .agent_installation(installation_id)
            .await?
            .context("update target installation was not found")?;
        ensure!(
            installation.scope == db_scope(request.scope)
                && installation.canonical_workspace_id.as_deref() == workspace_id,
            "update target installation does not belong to requested scope"
        );
        ensure!(
            installation.source_identity == source.identity(),
            "update source does not match target installation provenance"
        );
        Ok(installation)
    }

    /// Validate all immutable source facts that are knowable before an
    /// operation exists. The returned bytes are passed directly to staging so
    /// a valid fresh request fetches exactly once, while an invalid source or
    /// manifest has no durable side effects.
    async fn prefetch_fresh_source(
        &self,
        request: &AgentInstallationBeginV1,
        expected_agent_id: Option<&str>,
    ) -> Result<FetchedAgentSource> {
        let source = CanonicalAgentSource::parse(&request.source_locator)?;
        let name = source
            .markdown_path
            .rsplit('/')
            .next()
            .and_then(|value| value.strip_suffix(".md"))
            .filter(|value| !value.is_empty())
            .context("source Markdown path has no agent filename")?;
        let fetched = self
            .fetcher
            .fetch_github_markdown(&source)
            .await
            .context("fetching GitHub agent source")?;
        ensure!(
            is_commit_sha(&fetched.commit_sha),
            "source fetch did not resolve an immutable commit SHA"
        );
        ensure!(
            fetched.markdown.len() <= MAX_AGENT_MARKDOWN_BYTES,
            "fetched agent Markdown exceeds 1MiB"
        );
        let markdown = std::str::from_utf8(&fetched.markdown)
            .context("fetched agent Markdown is not UTF-8")?;
        let definition =
            crate::agents::parse_agent(markdown, name, PathBuf::from("<daemon-fetched-agent>"))
                .context("invalid fetched AgentDef")?;
        let vnext = definition
            .vnext
            .as_ref()
            .context("installed agent must be a vNext AgentDef")?;
        let defined_name = vnext
            .agent_id
            .rsplit('/')
            .next()
            .context("vNext agent id has no final name")?;
        ensure!(
            defined_name == name,
            "installed AgentDef id must use the source Markdown filename"
        );
        ensure!(
            !crate::agents::is_builtin_agent(defined_name),
            "daemon installation may not impersonate a protected builtin agent"
        );
        if let Some(expected_agent_id) = expected_agent_id {
            ensure!(
                vnext.agent_id == expected_agent_id,
                "update source AgentDef identity does not match target installation"
            );
        }
        Ok(fetched)
    }

    /// A fresh workspace-shared request may touch a user-visible path only
    /// after proving it is absent or byte/provenance-identical. The immutable
    /// source has already been fetched and validated before this check, so
    /// preflight cannot make an invalid manifest durable or refetch a moving
    /// revision.
    async fn preflight_shared_collision(
        &self,
        request: &AgentInstallationBeginV1,
        workspace_id: Option<&str>,
        workspace_root: Option<&Path>,
        fetched: &FetchedAgentSource,
    ) -> Result<()> {
        let source = CanonicalAgentSource::parse(&request.source_locator)?;
        let name = source
            .markdown_path
            .rsplit('/')
            .next()
            .and_then(|value| value.strip_suffix(".md"))
            .filter(|value| !value.is_empty())
            .context("source Markdown path has no agent filename")?;
        let target = owned_path(
            &self.daemon_agents_dir,
            workspace_root,
            AgentInstallationScopeWire::WorkspaceShared,
            name,
        )?;
        ensure_no_reparse_components(target.parent().context("owned target missing parent")?)?;
        reject_reparse_leaf(&target)?;
        if !owned_file_exists(&target, false)? {
            return Ok(());
        }
        ensure!(
            is_commit_sha(&fetched.commit_sha)
                && fetched.markdown.len() <= MAX_AGENT_MARKDOWN_BYTES,
            "shared collision source did not resolve an immutable bounded commit"
        );
        let markdown = std::str::from_utf8(&fetched.markdown)
            .context("shared collision source Markdown is not UTF-8")?;
        let definition = crate::agents::parse_agent(
            markdown,
            name,
            PathBuf::from("<daemon-shared-collision-check>"),
        )?;
        let vnext = definition
            .vnext
            .as_ref()
            .context("shared collision source is not a vNext AgentDef")?;
        let defined_name = vnext
            .agent_id
            .rsplit('/')
            .next()
            .context("shared collision AgentDef has no filename")?;
        ensure!(
            defined_name == name,
            "installed AgentDef id must use the source Markdown filename"
        );
        let definition_digest = sha256_hex(&definition.vnext_digest_bytes()?);
        let exact = target_digest(&target)? == sha256_hex(&fetched.markdown)
            && self
                .db
                .agent_installation_by_source(
                    AgentInstallationScope::WorkspaceShared,
                    workspace_id.map(str::to_owned),
                    vnext.agent_id.clone(),
                )
                .await?
                .is_some_and(|existing| {
                    existing.source_identity == source.identity()
                        && existing.source_revision.as_deref() == Some(fetched.commit_sha.as_str())
                        && existing.source_digest == definition_digest
                });
        ensure!(exact, "dirty shared owned agent file collision");
        Ok(())
    }

    async fn install_or_update(
        &self,
        request: AgentInstallationBeginV1,
        workspace_id: Option<String>,
        workspace_root: Option<PathBuf>,
        now: i64,
        update_target: Option<AgentInstallationRow>,
        prefetched: Option<FetchedAgentSource>,
    ) -> Result<AgentInstallationResultV1> {
        let source = CanonicalAgentSource::parse(&request.source_locator)?;
        let name = source
            .markdown_path
            .rsplit('/')
            .next()
            .and_then(|value| value.strip_suffix(".md"))
            .filter(|value| !value.is_empty())
            .context("source Markdown path has no agent filename")?;
        ensure!(
            !crate::agents::is_builtin_agent(name),
            "daemon installation may not overwrite a protected builtin agent"
        );
        let update_target_id = if request.operation == AgentInstallationOperationKind::Update {
            Some(
                Uuid::parse_str(
                    request
                        .target_installation_id
                        .as_deref()
                        .context("update requires target installation id")?,
                )
                .context("update target installation id is invalid")?,
            )
        } else {
            ensure!(
                request.target_installation_id.is_none(),
                "only update may include a target installation id"
            );
            None
        };
        let operation = self
            .db
            .installation_operation(request.idempotency_key.clone())
            .await?
            .context("installation operation was not recorded")?;
        let target = owned_path(
            &self.daemon_agents_dir,
            workspace_root.as_deref(),
            request.scope,
            name,
        )?;
        ensure_no_reparse_components(target.parent().context("owned target missing parent")?)?;
        reject_reparse_leaf(&target)?;
        let prior_journal = self.db.installation_journal(operation.operation_id).await?;
        // A freshly-created operation already has its immutable source journal
        // (atomically with the operation row), but has not yet observed the
        // owned target. Treat that narrow state like a fresh preflight on a
        // retry; once the observation is persisted, recovery uses it instead
        // of reinterpreting a published file as a new collision.
        let needs_owned_target_preflight = prior_journal.as_ref().is_none_or(|journal| {
            journal.checkpoint == InstallationJournalCheckpoint::Staged
                && journal.prior_file_metadata_json.is_none()
        });
        let fetched = match prior_journal.as_ref().and_then(journal_staged_source) {
            Some(source) => source?,
            None => match prefetched {
                Some(source) => source,
                None => self
                    .fetcher
                    .fetch_github_markdown(&source)
                    .await
                    .context("fetching GitHub agent source")?,
            },
        };
        ensure!(
            is_commit_sha(&fetched.commit_sha),
            "source fetch did not resolve an immutable commit SHA"
        );
        ensure!(
            fetched.markdown.len() <= MAX_AGENT_MARKDOWN_BYTES,
            "fetched agent Markdown exceeds 1MiB"
        );
        let markdown = std::str::from_utf8(&fetched.markdown)
            .context("fetched agent Markdown is not UTF-8")?;
        let definition =
            crate::agents::parse_agent(markdown, name, PathBuf::from("<daemon-fetched-agent>"))
                .context("invalid fetched AgentDef")?;
        ensure!(
            definition.vnext.is_some(),
            "installed agent must be a vNext AgentDef"
        );
        let defined_name = definition
            .vnext
            .as_ref()
            .expect("checked vnext")
            .agent_id
            .rsplit('/')
            .next()
            .context("vNext agent id has no final name")?;
        ensure!(
            defined_name == name,
            "installed AgentDef id must use the source Markdown filename"
        );
        ensure!(
            !crate::agents::is_builtin_agent(defined_name),
            "daemon installation may not impersonate a protected builtin agent"
        );
        if let Some(target) = update_target.as_ref() {
            ensure!(
                definition.vnext.as_ref().expect("checked vnext").agent_id
                    == target.source_agent_id,
                "update source AgentDef identity does not match target installation"
            );
        }
        let digest = sha256_hex(&fetched.markdown);
        let definition_digest = sha256_hex(&definition.vnext_digest_bytes()?);
        // A workspace-shared definition belongs to the workspace, not merely
        // to this daemon.  Detect a hand edit or a competing definition before
        // staging, journaling, or invoking the installation transaction.  The
        // one permitted collision is an exact already-installed copy, which
        // is a no-op even when a caller used a fresh operation key.
        if needs_owned_target_preflight
            && request.scope == AgentInstallationScopeWire::WorkspaceShared
            && owned_file_exists(&target, false)?
            && target_digest(&target)? == digest
            && let Some(existing) = self
                .db
                .agent_installation_by_source(
                    db_scope(request.scope),
                    workspace_id.clone(),
                    definition
                        .vnext
                        .as_ref()
                        .expect("checked vnext")
                        .agent_id
                        .clone(),
                )
                .await?
            && existing.source_identity == source.identity()
            && existing.source_revision.as_deref() == Some(fetched.commit_sha.as_str())
            && existing.source_digest == definition_digest
        {
            let install_status = if request.operation == AgentInstallationOperationKind::Install {
                AgentInstallationReceiptStatusV1::Installed
            } else {
                AgentInstallationReceiptStatusV1::Updated
            };
            let receipt = receipt(
                operation.operation_id,
                install_status,
                Some(existing.installation_id.to_string()),
                Some(fetched.commit_sha.clone()),
            );
            if request.auto_select_first_exact {
                return self
                    .bind_begin(BindBeginInput {
                        request,
                        workspace_id,
                        workspace_root,
                        now,
                        installed_id: Some(existing.installation_id),
                        parent_receipt_status: Some(install_status),
                        parent_source_revision: Some(fetched.commit_sha),
                    })
                    .await;
            }
            self.db
                .finish_installation_operation(
                    operation.operation_id,
                    serde_json::to_string(&receipt)?,
                    now,
                )
                .await?;
            return Ok(receipt);
        }
        if needs_owned_target_preflight
            && request.scope == AgentInstallationScopeWire::WorkspaceShared
            && owned_file_exists(&target, false)?
        {
            bail!("dirty shared owned agent file collision")
        }
        // Replacement is explicit, never permission to overwrite an edited
        // daemon-owned copy. `source_digest` is the canonical complete vNext
        // Markdown digest (including the prompt body), so this catches both
        // frontmatter and body edits before any stage/journal/DB mutation.
        if needs_owned_target_preflight
            && request.replace_acknowledged
            && owned_file_exists(&target, false)?
        {
            let existing = match update_target_id {
                Some(target_id) => self
                    .db
                    .agent_installation(target_id)
                    .await?
                    .context("replacement target installation disappeared")?,
                None => self
                    .db
                    .agent_installation_by_source(
                        db_scope(request.scope),
                        workspace_id.clone(),
                        definition
                            .vnext
                            .as_ref()
                            .expect("checked vnext")
                            .agent_id
                            .clone(),
                    )
                    .await?
                    .context("replacement target installation disappeared")?,
            };
            let current = crate::agents::parse_agent(
                std::str::from_utf8(&read_owned_file(
                    &target,
                    "reading owned agent before replacement",
                )?)
                .context("owned agent before replacement is not UTF-8")?,
                name,
                target.clone(),
            )
            .context("dirty shared owned agent file collision")?;
            let current_digest = sha256_hex(&current.vnext_digest_bytes()?);
            ensure!(
                current_digest == existing.source_digest,
                "dirty shared owned agent file collision"
            );
        }
        if needs_owned_target_preflight
            && owned_file_exists(&target, false)?
            && !request.replace_acknowledged
        {
            bail!("owned agent file collision requires explicit replacement acknowledgement")
        }
        let mut journal = prior_journal.unwrap_or(InstallationJournalRow {
            journal_id: Uuid::new_v4(),
            operation_id: operation.operation_id,
            checkpoint: InstallationJournalCheckpoint::Staged,
            staged_file_metadata_json: Some(serde_json::to_string(&JournalStagedSource {
                target_name: name.to_owned(),
                digest: digest.clone(),
                commit_sha: fetched.commit_sha.clone(),
                markdown_base64: base64::engine::general_purpose::STANDARD
                    .encode(&fetched.markdown),
            })?),
            prior_file_metadata_json: prior_file_metadata(&target, operation.operation_id)?,
            expected_digest: digest.clone(),
        });
        if journal.prior_file_metadata_json.is_none() {
            // This update is intentionally durable before staging: after a
            // crash, recovery can prove whether a user changed the owned
            // target rather than treating a file swap as the original copy.
            journal.prior_file_metadata_json =
                prior_file_metadata(&target, operation.operation_id)?;
            self.db
                .record_installation_journal(journal.clone(), now)
                .await?;
        }
        ensure!(
            journal.expected_digest == digest,
            "recovery source digest changed for the original installation request"
        );
        if checkpoint_rank(journal.checkpoint)
            >= checkpoint_rank(InstallationJournalCheckpoint::DbCommitted)
            && let Some(replacement) = journal_replacement_receipt(&journal).transpose()?
            && self
                .db
                .agent_replacement_is_compensated(replacement)
                .await?
        {
            // A prior publish failure was compensated atomically but the
            // daemon crashed before writing its terminal receipt. Never repeat
            // the replacement or touch its immutable historical snapshots.
            rollback_stage(&target, operation.operation_id);
            discard_prior_backup(&target, operation.operation_id)?;
            let receipt = receipt(
                operation.operation_id,
                AgentInstallationReceiptStatusV1::Refused,
                None,
                Some(fetched.commit_sha),
            );
            self.db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::Complete,
                        ..journal
                    },
                    now,
                )
                .await?;
            self.db
                .finish_installation_operation(
                    operation.operation_id,
                    serde_json::to_string(&receipt)?,
                    now,
                )
                .await?;
            return Ok(receipt);
        }
        if journal.checkpoint == InstallationJournalCheckpoint::Staged {
            stage_file(&target, operation.operation_id, &fetched.markdown)?;
            self.db
                .record_installation_journal(journal.clone(), now)
                .await?;
        }
        if request.replace_acknowledged
            && journal.checkpoint == InstallationJournalCheckpoint::Staged
        {
            ensure!(
                prior_file_is_unchanged(&target, journal.prior_file_metadata_json.as_deref())?,
                "owned agent file changed after replacement was staged"
            );
        }
        let installation_input = AgentInstallationInput {
            installation_id: operation.operation_id,
            scope: db_scope(request.scope),
            canonical_workspace_id: workspace_id.clone(),
            source_agent_id: definition
                .vnext
                .as_ref()
                .expect("checked vnext")
                .agent_id
                .clone(),
            source_identity: source.identity(),
            source_revision: Some(fetched.commit_sha.clone()),
            source_digest: definition_digest,
            // The operation creation time is durable. Replays must never
            // substitute their retry clock into replacement provenance.
            fetched_at_unix_ms: operation.created_at_unix_ms,
        };
        // A process can die after replace_agent's atomic DB transaction but
        // before recording DbCommitted. The persisted replacement receipt is
        // the durable generation identity for that narrow window; recognize
        // the exact committed generation before considering any new mutation.
        let committed_replacement = if journal.checkpoint == InstallationJournalCheckpoint::Staged {
            match journal_replacement_receipt(&journal).transpose()? {
                Some(replacement) => {
                    ensure!(
                        replacement.replacement_operation_id == operation.operation_id,
                        "stored replacement receipt belongs to another operation"
                    );
                    (match update_target_id {
                        Some(target_id) => self.db.agent_installation(target_id).await?,
                        None => {
                            self.db
                                .agent_installation_by_source(
                                    installation_input.scope,
                                    installation_input.canonical_workspace_id.clone(),
                                    installation_input.source_agent_id.clone(),
                                )
                                .await?
                        }
                    })
                    .filter(|row| replacement_receipt_matches_committed(row, &replacement))
                }
                None => None,
            }
        } else {
            None
        };
        let installation = if checkpoint_rank(journal.checkpoint)
            >= checkpoint_rank(InstallationJournalCheckpoint::DbCommitted)
        {
            // The journal checkpoint is the replay authority: do not issue a
            // second install/replace transaction after a crash between its DB
            // commit and file publication.
            let row = (match update_target_id {
                Some(target_id) => self.db.agent_installation(target_id).await?,
                None => {
                    self.db
                        .agent_installation_by_source(
                            installation_input.scope,
                            installation_input.canonical_workspace_id.clone(),
                            installation_input.source_agent_id.clone(),
                        )
                        .await?
                }
            })
            .context("DB-committed installation disappeared during recovery")?;
            ensure!(
                row.source_identity == installation_input.source_identity
                    && row.source_revision == installation_input.source_revision
                    && row.source_digest == installation_input.source_digest
                    && row.deleted_at_unix_ms.is_none(),
                "DB-committed installation provenance changed during recovery"
            );
            row
        } else if let Some(row) = committed_replacement {
            row
        } else {
            // Update owns a concrete target id. Do not first ask the generic
            // source-identity insert path to discover a replacement target:
            // that lookup is appropriate only for an unaddressed Install.
            let outcome = match update_target_id {
                Some(_) => InstallAgentOutcome::Conflict,
                None => self.db.install_agent(installation_input.clone()).await?,
            };
            match outcome {
                InstallAgentOutcome::Installed(row)
                | InstallAgentOutcome::AlreadyInstalled(row) => row,
                InstallAgentOutcome::Conflict => {
                    ensure!(
                        request.replace_acknowledged,
                        "agent installation collides with a different installed definition; explicit replacement acknowledgement is required"
                    );
                    let existing = match update_target_id {
                        Some(target_id) => self
                            .db
                            .agent_installation(target_id)
                            .await?
                            .context("replacement target installation disappeared")?,
                        None => self
                            .db
                            .agent_installation_by_source(
                                installation_input.scope,
                                installation_input.canonical_workspace_id.clone(),
                                installation_input.source_agent_id.clone(),
                            )
                            .await?
                            .context("replacement target installation disappeared")?,
                    };
                    let replacement = match journal_replacement_receipt(&journal).transpose()? {
                        Some(receipt) => {
                            ensure!(
                                receipt.installation_id == existing.installation_id
                                    && receipt.replacement_source_identity
                                        == installation_input.source_identity
                                    && receipt.replacement_source_revision
                                        == installation_input.source_revision
                                    && receipt.replacement_source_digest
                                        == installation_input.source_digest
                                    && receipt.replacement_operation_id == operation.operation_id,
                                "stored replacement compensation receipt does not match recovery request"
                            );
                            receipt
                        }
                        None => {
                            self.db
                                .agent_replacement_compensation_receipt(
                                    existing.installation_id,
                                    installation_input.clone(),
                                    operation.created_at_unix_ms,
                                )
                                .await?
                        }
                    };
                    journal.prior_file_metadata_json = Some(with_replacement_receipt(
                        journal.prior_file_metadata_json.as_deref(),
                        &replacement,
                    )?);
                    // Persist the receipt before the replacement transaction.
                    // A DB-committed crash can then restore the exact prior
                    // mutable state without creating a second revision or
                    // binding.
                    self.db
                        .record_installation_journal(journal.clone(), now)
                        .await?;
                    match if let Some(target_id) = update_target_id {
                        self.db
                            .replace_agent_at(
                                target_id,
                                installation_input,
                                operation.created_at_unix_ms,
                            )
                            .await?
                    } else {
                        self.db
                            .replace_agent(installation_input, operation.created_at_unix_ms)
                            .await?
                    } {
                        InstallAgentOutcome::Installed(row)
                        | InstallAgentOutcome::AlreadyInstalled(row) => row,
                        InstallAgentOutcome::Conflict => {
                            bail!("agent installation replacement conflicted")
                        }
                    }
                }
            }
        };
        if let Some(target) = update_target.as_ref() {
            ensure!(
                installation.installation_id == target.installation_id,
                "update source resolves to a different installation"
            );
        }
        if checkpoint_rank(journal.checkpoint)
            < checkpoint_rank(InstallationJournalCheckpoint::DbCommitted)
        {
            self.db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::DbCommitted,
                        ..journal.clone()
                    },
                    now,
                )
                .await?;
        }
        if checkpoint_rank(journal.checkpoint)
            < checkpoint_rank(InstallationJournalCheckpoint::FileRenamed)
        {
            if let Err(error) = publish_stage(
                &target,
                operation.operation_id,
                &digest,
                request.replace_acknowledged,
            ) {
                if let Some(replacement) = journal_replacement_receipt(&journal).transpose()? {
                    ensure!(
                        !owned_file_exists(
                            &prior_backup_path(&target, operation.operation_id)?,
                            false,
                        )?,
                        "publish failed while preserving the prior file backup; recovery must not discard it"
                    );
                    self.db.compensate_agent_replacement(replacement).await?;
                    rollback_stage(&target, operation.operation_id);
                    discard_prior_backup(&target, operation.operation_id)?;
                    let receipt = receipt(
                        operation.operation_id,
                        AgentInstallationReceiptStatusV1::Refused,
                        None,
                        Some(fetched.commit_sha),
                    );
                    self.db
                        .record_installation_journal(
                            InstallationJournalRow {
                                checkpoint: InstallationJournalCheckpoint::Complete,
                                ..journal
                            },
                            now,
                        )
                        .await?;
                    self.db
                        .finish_installation_operation(
                            operation.operation_id,
                            serde_json::to_string(&receipt)?,
                            now,
                        )
                        .await?;
                    return Ok(receipt);
                }
                return Err(error);
            }
            self.db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::FileRenamed,
                        ..journal.clone()
                    },
                    now,
                )
                .await?;
        } else {
            ensure!(
                target_digest(&target)? == digest,
                "published installation file digest changed during recovery"
            );
        }
        let install_status = if request.operation == AgentInstallationOperationKind::Install {
            AgentInstallationReceiptStatusV1::Installed
        } else {
            AgentInstallationReceiptStatusV1::Updated
        };
        let receipt = receipt(
            operation.operation_id,
            install_status,
            Some(installation.installation_id.to_string()),
            Some(fetched.commit_sha.clone()),
        );
        self.db
            .record_installation_journal(
                InstallationJournalRow {
                    checkpoint: InstallationJournalCheckpoint::Complete,
                    ..journal
                },
                now,
            )
            .await?;
        if request.auto_select_first_exact {
            let result = self
                .bind_begin(BindBeginInput {
                    request,
                    workspace_id,
                    workspace_root,
                    now,
                    installed_id: Some(installation.installation_id),
                    parent_receipt_status: Some(install_status),
                    parent_source_revision: Some(fetched.commit_sha),
                })
                .await?;
            discard_prior_backup(&target, operation.operation_id)?;
            return Ok(result);
        }
        self.db
            .finish_installation_operation(
                operation.operation_id,
                serde_json::to_string(&receipt)?,
                now,
            )
            .await?;
        discard_prior_backup(&target, operation.operation_id)?;
        Ok(receipt)
    }

    async fn create(
        &self,
        request: AgentInstallationBeginV1,
        workspace_id: Option<String>,
        workspace_root: Option<PathBuf>,
        now: i64,
    ) -> Result<AgentInstallationResultV1> {
        // Create accepts a declarative identity, never a client filesystem
        // path. The daemon owns both the generated Markdown filename and its
        // destination below the authorized scope root.
        let agent_id = request
            .source_locator
            .strip_prefix("authored/")
            .filter(|name| !name.is_empty() && !name.contains('/'))
            .context("created agent identity must be authored/NAME")?;
        ensure!(
            !agent_id.is_empty()
                && agent_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "created agent id is invalid"
        );
        ensure!(
            !crate::agents::is_builtin_agent(agent_id),
            "daemon create may not overwrite a protected builtin agent"
        );
        let operation = self
            .db
            .installation_operation(request.idempotency_key.clone())
            .await?
            .context("installation operation was not recorded")?;
        let execution_kind = request
            .execution_kind
            .context("create requires an explicit execution kind")?;
        let primary_slot = request
            .primary_slot_id
            .as_deref()
            .context("create requires an explicit primary slot id")?;
        ensure!(
            !primary_slot.is_empty()
                && primary_slot.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'
                        || byte == b'_'
                }),
            "create primary slot id is invalid"
        );
        let markdown = minimal_template(agent_id, execution_kind, primary_slot);
        let digest = sha256_hex(markdown.as_bytes());
        let definition = crate::agents::parse_agent(
            &markdown,
            agent_id,
            PathBuf::from("<daemon-created-agent>"),
        )?;
        let definition_digest = sha256_hex(&definition.vnext_digest_bytes()?);
        let target = owned_path(
            &self.daemon_agents_dir,
            workspace_root.as_deref(),
            request.scope,
            agent_id,
        )?;
        ensure_no_reparse_components(target.parent().context("owned target missing parent")?)?;
        reject_reparse_leaf(&target)?;
        let prior_journal = self.db.installation_journal(operation.operation_id).await?;
        ensure!(
            prior_journal.is_some() || !owned_file_exists(&target, false)?,
            "agent create collision; refusing to overwrite an owned definition"
        );
        let journal = prior_journal.unwrap_or(InstallationJournalRow {
            journal_id: Uuid::new_v4(),
            operation_id: operation.operation_id,
            checkpoint: InstallationJournalCheckpoint::Staged,
            staged_file_metadata_json: Some(
                serde_json::json!({"target_name": agent_id, "digest": digest}).to_string(),
            ),
            prior_file_metadata_json: None,
            expected_digest: digest.clone(),
        });
        ensure!(
            journal.expected_digest == digest,
            "recovery template digest changed for the original create request"
        );
        if journal.checkpoint == InstallationJournalCheckpoint::Staged {
            stage_file(&target, operation.operation_id, markdown.as_bytes())?;
            self.db
                .record_installation_journal(journal.clone(), now)
                .await?;
        }
        let outcome = self
            .db
            .install_agent(AgentInstallationInput {
                installation_id: operation.operation_id,
                scope: db_scope(request.scope),
                canonical_workspace_id: workspace_id,
                source_agent_id: format!("authored/{agent_id}"),
                source_identity: format!("daemon-create:{agent_id}"),
                source_revision: None,
                source_digest: definition_digest,
                fetched_at_unix_ms: now,
            })
            .await?;
        let installation = match outcome {
            InstallAgentOutcome::Installed(row) | InstallAgentOutcome::AlreadyInstalled(row) => row,
            InstallAgentOutcome::Conflict => {
                rollback_stage(&target, operation.operation_id);
                bail!("agent create collision")
            }
        };
        if checkpoint_rank(journal.checkpoint)
            < checkpoint_rank(InstallationJournalCheckpoint::DbCommitted)
        {
            self.db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::DbCommitted,
                        ..journal.clone()
                    },
                    now,
                )
                .await?;
        }
        if checkpoint_rank(journal.checkpoint)
            < checkpoint_rank(InstallationJournalCheckpoint::FileRenamed)
        {
            publish_stage(&target, operation.operation_id, &digest, false)?;
            self.db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::FileRenamed,
                        ..journal.clone()
                    },
                    now,
                )
                .await?;
        } else {
            ensure!(
                target_digest(&target)? == digest,
                "published create file digest changed during recovery"
            );
        }
        let receipt = receipt(
            operation.operation_id,
            AgentInstallationReceiptStatusV1::Created,
            Some(installation.installation_id.to_string()),
            None,
        );
        self.db
            .record_installation_journal(
                InstallationJournalRow {
                    checkpoint: InstallationJournalCheckpoint::Complete,
                    ..journal
                },
                now,
            )
            .await?;
        self.db
            .finish_installation_operation(
                operation.operation_id,
                serde_json::to_string(&receipt)?,
                now,
            )
            .await?;
        discard_prior_backup(&target, operation.operation_id)?;
        Ok(receipt)
    }

    async fn resolve_scope(
        &self,
        scope: AgentInstallationScopeWire,
        path: Option<&str>,
    ) -> Result<(Option<String>, Option<PathBuf>)> {
        match scope {
            AgentInstallationScopeWire::Global => {
                ensure!(
                    path.is_none(),
                    "global installation must not include workspace path"
                );
                Ok((None, None))
            }
            AgentInstallationScopeWire::WorkspacePrivate
            | AgentInstallationScopeWire::WorkspaceShared => {
                let path = path.context("workspace installation requires workspace path")?;
                let (id, root) = self
                    .workspaces
                    .authorize_workspace(path)
                    .await
                    .context("workspace authorization failed")?;
                ensure!(
                    !id.is_empty(),
                    "workspace authorization returned empty identity"
                );
                Ok((Some(id), Some(root)))
            }
        }
    }

    async fn record(
        &self,
        row: cockpit_db::db::agent_installations::AgentInstallationRow,
        workspace_root: Option<&Path>,
    ) -> Result<AgentInstallationRecordV1> {
        // Shared definitions are portable by construction. Local provider
        // handles, effective bindings, and even their derived status belong
        // to a user's private daemon state and must not appear in a shared
        // list/inspect DTO (including an empty/unbound status inferred here).
        let bindings = if row.scope == AgentInstallationScope::WorkspaceShared {
            Vec::new()
        } else {
            let current_bindings = self
                .db
                .current_agent_bindings(row.installation_id, row.source_digest.clone())
                .await?
                .into_iter()
                .filter(|binding| binding.is_default)
                .map(|binding| (binding.slot_id, binding.model_id))
                .collect::<std::collections::BTreeMap<_, _>>();
            let name = row
                .source_agent_id
                .rsplit('/')
                .next()
                .context("installed agent id has no filename")?;
            let path = existing_owned_definition_path(
                &self.daemon_agents_dir,
                workspace_root,
                match row.scope {
                    AgentInstallationScope::Global => AgentInstallationScopeWire::Global,
                    AgentInstallationScope::WorkspacePrivate => {
                        AgentInstallationScopeWire::WorkspacePrivate
                    }
                    AgentInstallationScope::WorkspaceShared => unreachable!("shared is handled"),
                },
                name,
            )?;
            let definition = crate::agents::load_owned_definition(
                &path,
                name,
                installation_definition_scope(row.scope, &row.source_agent_id),
            )?;
            let observed_digest = sha256_hex(&definition.vnext_digest_bytes()?);
            let observation = self.db.agent_observation(row.installation_id).await?;
            let rebind_required = observation.is_none_or(|observation| {
                !observation.reviewed || observation.observed_digest != observed_digest
            });
            definition
                .vnext
                .context("installed agent is not a vNext definition")?
                .model_slots
                .iter()
                .map(|(slot_id, slot)| match current_bindings.get(slot_id) {
                    Some(model_id) => AgentInstallationSlotStatusV1 {
                        slot_id: slot_id.clone(),
                        state: if rebind_required {
                            AgentInstallationSlotBindingStateV1::RebindRequired
                        } else {
                            AgentInstallationSlotBindingStateV1::Bound
                        },
                        model_id: model_id.clone(),
                    },
                    None => AgentInstallationSlotStatusV1 {
                        slot_id: slot_id.clone(),
                        state: if rebind_required {
                            AgentInstallationSlotBindingStateV1::RebindRequired
                        } else if slot_id == "primary"
                            || slot.purpose.eq_ignore_ascii_case("primary")
                        {
                            AgentInstallationSlotBindingStateV1::PrimaryUnusable
                        } else {
                            AgentInstallationSlotBindingStateV1::OptionalUnbound
                        },
                        model_id: String::new(),
                    },
                })
                .collect()
        };
        Ok(AgentInstallationRecordV1 {
            installation_id: row.installation_id.to_string(),
            scope: match row.scope {
                AgentInstallationScope::Global => AgentInstallationScopeWire::Global,
                AgentInstallationScope::WorkspacePrivate => {
                    AgentInstallationScopeWire::WorkspacePrivate
                }
                AgentInstallationScope::WorkspaceShared => {
                    AgentInstallationScopeWire::WorkspaceShared
                }
            },
            source_agent_id: row.source_agent_id,
            source_identity: row.source_identity,
            source_revision: row.source_revision,
            source_digest: row.source_digest,
            installation_revision: row.installation_revision,
            bindings,
        })
    }
}

/// Construct the production daemon coordinator. The state directory is
/// daemon-owned; workspace-shared files are routed below the daemon-authorized
/// workspace root by `owned_path` and never returned over the protocol.
pub fn default_daemon_service(
    db: Db,
    daemon_paths: &crate::daemon::DaemonPaths,
    secret_vault: Arc<crate::secure_key::SecretVault>,
    providers: ProvidersConfig,
    authorized_workspace_roots: Vec<PathBuf>,
) -> Result<AgentInstallationService> {
    let authorized_workspace_roots = authorized_workspace_roots
        .into_iter()
        .map(|path| AuthorizedWorkspaceRoot::capture(&path))
        .collect::<Result<Vec<_>>>()?;
    default_daemon_service_with_captured_workspace_roots(
        db,
        daemon_paths,
        secret_vault,
        providers,
        authorized_workspace_roots,
    )
}

/// Same production coordinator, but retains an attach-time workspace proof
/// instead of recapturing whatever later occupies the original pathname.
pub fn default_daemon_service_with_captured_workspace_roots(
    db: Db,
    daemon_paths: &crate::daemon::DaemonPaths,
    secret_vault: Arc<crate::secure_key::SecretVault>,
    providers: ProvidersConfig,
    authorized_workspace_roots: Vec<AuthorizedWorkspaceRoot>,
) -> Result<AgentInstallationService> {
    let state = daemon_paths
        .pid_file
        .parent()
        .context("daemon pid file has no state directory")?;
    Ok(AgentInstallationService::new(
        db,
        state.join("agents"),
        Arc::new(GithubHttpsAgentFetcher::new(secret_vault)?),
        Arc::new(LocalDaemonWorkspaceAuthorizer::from_captured_roots(
            authorized_workspace_roots,
        )?),
        providers,
    ))
}

fn operation_kind(value: AgentInstallationOperationKind) -> InstallationOperationKind {
    match value {
        AgentInstallationOperationKind::Install => InstallationOperationKind::Install,
        AgentInstallationOperationKind::Update => InstallationOperationKind::Update,
        AgentInstallationOperationKind::Bind => InstallationOperationKind::Bind,
        AgentInstallationOperationKind::Create => InstallationOperationKind::Create,
    }
}
fn db_scope(value: AgentInstallationScopeWire) -> AgentInstallationScope {
    match value {
        AgentInstallationScopeWire::Global => AgentInstallationScope::Global,
        AgentInstallationScopeWire::WorkspacePrivate => AgentInstallationScope::WorkspacePrivate,
        AgentInstallationScopeWire::WorkspaceShared => AgentInstallationScope::WorkspaceShared,
    }
}

fn installation_definition_scope(
    scope: AgentInstallationScope,
    source_agent_id: &str,
) -> crate::agents::DefinitionScope {
    match scope {
        AgentInstallationScope::WorkspaceShared => crate::agents::DefinitionScope::Workspace,
        AgentInstallationScope::Global | AgentInstallationScope::WorkspacePrivate
            if source_agent_id.starts_with("local/") =>
        {
            crate::agents::DefinitionScope::DaemonLocal
        }
        AgentInstallationScope::Global if source_agent_id.starts_with("cockpit/") => {
            crate::agents::DefinitionScope::BuiltinOverride
        }
        AgentInstallationScope::Global | AgentInstallationScope::WorkspacePrivate => {
            crate::agents::DefinitionScope::Workspace
        }
    }
}
fn request_fingerprint(request: &AgentInstallationBeginV1, workspace: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!(
        "v{}:{:?}:{:?}:{}:{}:{}:{}:{}",
        request.dto_version,
        request.operation,
        request.scope,
        workspace.unwrap_or(""),
        request.source_locator,
        request.target_installation_id.as_deref().unwrap_or(""),
        request.replace_acknowledged,
        request.requested_slot.as_deref().unwrap_or("")
    ));
    hasher.update(format!(
        ":{:?}:{}:{}",
        request.execution_kind,
        request.primary_slot_id.as_deref().unwrap_or(""),
        request.auto_select_first_exact,
    ));
    crate::intel::hex_lower(&hasher.finalize())
}
fn sha256_hex(bytes: &[u8]) -> String {
    crate::intel::hex_lower(&Sha256::digest(bytes))
}
fn is_commit_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn validate_idempotency_key(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 256,
        "invalid idempotency key"
    );
    Ok(())
}
fn owned_path(
    global: &Path,
    workspace: Option<&Path>,
    scope: AgentInstallationScopeWire,
    name: &str,
) -> Result<PathBuf> {
    ensure!(
        !name.contains('/') && !name.contains('\\') && !name.is_empty(),
        "invalid agent filename"
    );
    Ok(match scope {
        AgentInstallationScopeWire::Global => global.join(format!("{name}.md")),
        // Workspace-private definitions are daemon-owned state, not a
        // workspace file.  The daemon-authorized path only contributes a
        // stable opaque directory key and is never serialized or returned.
        AgentInstallationScopeWire::WorkspacePrivate => global
            .join("private")
            .join(sha256_hex(
                workspace
                    .context("missing workspace root")?
                    .to_string_lossy()
                    .as_bytes(),
            ))
            .join(format!("{name}.md")),
        AgentInstallationScopeWire::WorkspaceShared => workspace
            .context("missing workspace root")?
            .join(".cockpit/agents")
            .join(format!("{name}.md")),
    })
}

fn existing_owned_definition_path(
    global: &Path,
    workspace: Option<&Path>,
    scope: AgentInstallationScopeWire,
    name: &str,
) -> Result<PathBuf> {
    let flat = owned_path(global, workspace, scope, name)?;
    let package = flat.with_file_name(name);
    if std::fs::symlink_metadata(&package)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        && std::fs::symlink_metadata(package.join("agent.md"))
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
    {
        return Ok(package);
    }
    if std::fs::symlink_metadata(&flat)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
    {
        return Ok(flat);
    }
    Ok(flat)
}
fn stage_path(target: &Path, operation: Uuid) -> Result<PathBuf> {
    let filename = target
        .file_name()
        .context("owned target missing filename")?
        .to_string_lossy();
    Ok(target.with_file_name(format!(".{filename}.{operation}.staged")))
}
fn stage_file(target: &Path, operation: Uuid, bytes: &[u8]) -> Result<()> {
    let staged = stage_path(target, operation)?;
    if owned_file_exists(&staged, true)? {
        ensure!(
            target_digest(&staged)? == sha256_hex(bytes),
            "existing staged agent definition differs from durable source"
        );
        return Ok(());
    }
    write_staged_nofollow(&staged, bytes)?;
    Ok(())
}
fn prior_backup_path(target: &Path, operation: Uuid) -> Result<PathBuf> {
    let filename = target
        .file_name()
        .context("owned target missing filename")?
        .to_string_lossy();
    Ok(target.with_file_name(format!(".{filename}.{operation}.prior")))
}
fn publish_stage(
    target: &Path,
    operation: Uuid,
    expected_digest: &str,
    replace: bool,
) -> Result<()> {
    let staged = stage_path(target, operation)?;
    ensure_no_reparse_components(target.parent().context("owned target missing parent")?)?;
    reject_reparse_leaf(&staged)?;
    reject_reparse_leaf(target)?;
    let bytes = read_owned_file(&staged, "reading staged daemon-owned agent definition")?;
    ensure!(
        sha256_hex(&bytes) == expected_digest,
        "staged agent digest changed before publish"
    );
    let backup = prior_backup_path(target, operation)?;
    reject_reparse_leaf(&backup)?;
    if owned_file_exists(target, false)?
        && owned_file_exists(&backup, false)?
        && target_digest(target)? == expected_digest
    {
        return Ok(());
    }
    if owned_file_exists(target, false)? {
        ensure!(
            !owned_file_exists(&backup, false)?,
            "owned prior backup name is already occupied"
        );
        ensure!(
            replace,
            "owned agent file became dirty/collided before publish"
        );
        rename_owned_file(target, &backup)
            .context("backing up prior daemon-owned agent definition")?;
    };
    match rename_owned_file(&staged, target) {
        Ok(()) => {}
        Err(error) => {
            if owned_file_exists(&backup, false)? {
                ensure!(
                    !owned_file_exists(target, false)?,
                    "publish failed after creating an unexpected target; preserving prior backup"
                );
                rename_owned_file(&backup, target).context(
                    "restoring prior daemon-owned agent definition after publish failure",
                )?;
            }
            return Err(error).context("publishing daemon-owned agent definition");
        }
    }
    Ok(())
}

fn ensure_no_reparse_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                let reparse = metadata.file_type().is_symlink()
                    || cfg!(windows) && {
                        #[cfg(windows)]
                        {
                            use std::os::windows::fs::MetadataExt;
                            metadata.file_attributes() & 0x400 != 0
                        }
                        #[cfg(not(windows))]
                        {
                            false
                        }
                    };
                ensure!(
                    !reparse,
                    "agent installation path contains a symlink or reparse point"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error).context("inspecting agent installation path"),
        }
    }
    Ok(())
}

fn reject_reparse_leaf(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let reparse = metadata.file_type().is_symlink()
                || cfg!(windows) && {
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::MetadataExt;
                        metadata.file_attributes() & 0x400 != 0
                    }
                    #[cfg(not(windows))]
                    {
                        false
                    }
                };
            ensure!(
                !reparse,
                "agent installation file is a symlink or reparse point"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspecting agent installation file"),
    }
    Ok(())
}

fn write_staged_nofollow(path: &Path, bytes: &[u8]) -> Result<()> {
    write_owned_file_new(path, bytes, "creating no-follow staged agent definition")
}

#[cfg(unix)]
fn owned_parent(path: &Path, create: bool) -> Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let parent = path.parent().context("owned target missing parent")?;
    let root = CString::new("/").expect("literal has no NUL");
    // SAFETY: root is a valid NUL-terminated path and the returned descriptor
    // is immediately owned by File. Every descendant is opened relative to
    // that held descriptor with O_NOFOLLOW, so a pathname swap cannot redirect
    // a later read/write/rename outside the inspected directory identity.
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    ensure!(
        root_fd >= 0,
        "opening filesystem root for owned agent path failed"
    );
    // SAFETY: open returned a unique owned descriptor above.
    let mut current = unsafe { std::fs::File::from_raw_fd(root_fd) };
    for component in parent.components() {
        use std::path::Component;
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                let name =
                    CString::new(name.as_bytes()).context("owned agent path contains NUL")?;
                // SAFETY: current is a held directory descriptor and name is a
                // NUL-terminated single component (never an absolute path).
                let mut next = unsafe {
                    libc::openat(
                        std::os::fd::AsRawFd::as_raw_fd(&current),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    )
                };
                if next < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
                    && create
                {
                    // SAFETY: mkdirat is anchored to the held parent and name
                    // is a validated one-component relative pathname.
                    let created = unsafe {
                        libc::mkdirat(
                            std::os::fd::AsRawFd::as_raw_fd(&current),
                            name.as_ptr(),
                            0o700,
                        )
                    };
                    if created < 0
                        && std::io::Error::last_os_error().kind()
                            != std::io::ErrorKind::AlreadyExists
                    {
                        return Err(std::io::Error::last_os_error())
                            .context("creating owned agent directory");
                    }
                    // SAFETY: same held parent/name as above.
                    next = unsafe {
                        libc::openat(
                            std::os::fd::AsRawFd::as_raw_fd(&current),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                        )
                    };
                }
                ensure!(
                    next >= 0,
                    "opening owned agent directory without following links failed"
                );
                // SAFETY: openat returned a unique owned descriptor.
                current = unsafe { std::fs::File::from_raw_fd(next) };
            }
            Component::ParentDir | Component::Prefix(_) => {
                bail!("owned agent path contains an unsupported component")
            }
        }
    }
    Ok(current)
}

#[cfg(unix)]
fn owned_leaf(path: &Path) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    let leaf = path
        .file_name()
        .context("owned agent path has no filename")?;
    std::ffi::CString::new(leaf.as_bytes()).context("owned agent filename contains NUL")
}

#[cfg(unix)]
fn owned_file_exists(path: &Path, create_parent: bool) -> Result<bool> {
    use std::os::fd::AsRawFd;
    let parent = match owned_parent(path, create_parent) {
        Ok(parent) => parent,
        Err(error) if !create_parent => {
            match std::fs::symlink_metadata(path.parent().context("owned target missing parent")?) {
                Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(false);
                }
                _ => return Err(error),
            }
        }
        Err(error) => return Err(error),
    };
    let leaf = owned_leaf(path)?;
    // SAFETY: held directory descriptor plus a one-component NUL pathname.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        return match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::NotFound => Ok(false),
            _ => Err(std::io::Error::last_os_error()).context("inspecting owned agent file"),
        };
    }
    ensure!(
        stat.st_mode & libc::S_IFMT == libc::S_IFREG,
        "owned agent file is not a regular non-link file"
    );
    Ok(true)
}

#[cfg(unix)]
fn read_owned_file(path: &Path, context: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    let parent = owned_parent(path, false)?;
    let leaf = owned_leaf(path)?;
    // SAFETY: held directory descriptor plus a one-component NUL pathname.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    ensure!(fd >= 0, "{context}");
    // SAFETY: openat returned a unique owned descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata().with_context(|| context.to_owned())?;
    ensure!(metadata.is_file(), "owned agent file is not regular");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| context.to_owned())?;
    Ok(bytes)
}

#[cfg(unix)]
fn write_owned_file_new(path: &Path, bytes: &[u8], context: &str) -> Result<()> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    let parent = owned_parent(path, true)?;
    let leaf = owned_leaf(path)?;
    // SAFETY: held directory descriptor plus a one-component NUL pathname.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    ensure!(fd >= 0, "{context}");
    // SAFETY: openat returned a unique owned descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(bytes).with_context(|| context.to_owned())?;
    file.sync_all().context("syncing owned agent definition")?;
    Ok(())
}

#[cfg(unix)]
fn rename_owned_file(from: &Path, to: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    ensure!(
        from.parent() == to.parent(),
        "owned agent rename must stay within one held directory"
    );
    let parent = owned_parent(from, false)?;
    let from = owned_leaf(from)?;
    let to = owned_leaf(to)?;
    // `linkat` + `unlinkat` is a no-replace move for regular files. Unlike
    // renameat, it cannot overwrite a path an attacker creates after our
    // held-directory inspection; both names remain relative to one FD.
    // SAFETY: both names are one-component paths resolved by the held FD.
    let linked = unsafe {
        libc::linkat(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            0,
        )
    };
    ensure!(
        linked == 0,
        "publishing owned agent file would overwrite an existing path"
    );
    // SAFETY: same held descriptor and one-component source name as above.
    let removed = unsafe { libc::unlinkat(parent.as_raw_fd(), from.as_ptr(), 0) };
    ensure!(removed == 0, "removing moved owned agent file failed");
    Ok(())
}

#[cfg(unix)]
fn remove_owned_file(path: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    let parent = owned_parent(path, false)?;
    let leaf = owned_leaf(path)?;
    // SAFETY: held directory descriptor plus a one-component NUL pathname.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), leaf.as_ptr(), 0) };
    ensure!(result == 0, "removing owned agent file failed");
    Ok(())
}

// Windows has no openat equivalent in Win32.  Use NtCreateFile's RootDirectory
// with OBJ_DONT_REPARSE instead: every component and leaf is resolved from a
// still-held parent handle, never by re-walking the diagnostic path.
#[cfg(windows)]
mod held_windows_agent_files {
    use std::ffi::{OsStr, c_void};
    use std::io::{Read, Write};
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use std::path::{Component, Path, Prefix};
    use std::{fs::File, ptr};

    use anyhow::{Context, Result, bail, ensure};

    type Handle = *mut c_void;
    const INVALID_HANDLE: Handle = -1_isize as Handle;
    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    const OBJ_DONT_REPARSE: u32 = 0x1000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_SHARE_ALL: u32 = 0x7;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_DIRECTORY_FILE: u32 = 0x1;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const OPEN_EXISTING: u32 = 3;
    const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: Handle,
        object_name: *const UnicodeString,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
    }
    #[repr(C)]
    struct IoStatusBlock {
        status: isize,
        information: usize,
    }
    #[repr(C)]
    struct ByHandleFileInformation {
        attributes: u32,
        creation_low: u32,
        creation_high: u32,
        access_low: u32,
        access_high: u32,
        write_low: u32,
        write_high: u32,
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[repr(C)]
    struct FileRenameInformation {
        replace_if_exists: u8,
        root_directory: Handle,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            file: *mut Handle,
            access: u32,
            attributes: *const ObjectAttributes,
            io: *mut IoStatusBlock,
            allocation: *const i64,
            file_attributes: u32,
            share: u32,
            disposition: u32,
            options: u32,
            ea: *const c_void,
            ea_len: u32,
        ) -> i32;
        fn NtSetInformationFile(
            file: Handle,
            io: *mut IoStatusBlock,
            information: *const c_void,
            length: u32,
            class: u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut c_void,
            creation: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn GetFileInformationByHandle(
            file: Handle,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    fn wide_component(value: &OsStr) -> Result<Vec<u16>> {
        let value = value.encode_wide().collect::<Vec<_>>();
        ensure!(
            !value.is_empty() && value.len() <= u16::MAX as usize / 2,
            "invalid Windows owned path component"
        );
        Ok(value)
    }
    fn verify_directory(file: &File) -> Result<()> {
        let mut info = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
        ensure!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
            "querying held Windows directory identity failed"
        );
        ensure!(
            info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 && file.metadata()?.is_dir(),
            "held Windows agent directory is a reparse point or not a directory"
        );
        Ok(())
    }
    fn verify_file(file: &File) -> Result<()> {
        let mut info = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
        ensure!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
            "querying held Windows file identity failed"
        );
        ensure!(
            info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 && file.metadata()?.is_file(),
            "held Windows agent file is a reparse point or not regular"
        );
        Ok(())
    }
    fn open_relative(
        parent: &File,
        name: &[u16],
        disposition: u32,
        kind: u32,
        access: u32,
    ) -> std::result::Result<File, i32> {
        let mut name = name.to_vec();
        let unicode = UnicodeString {
            length: (name.len() * 2) as u16,
            maximum_length: (name.len() * 2) as u16,
            buffer: name.as_mut_ptr(),
        };
        let attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: parent.as_raw_handle(),
            object_name: &unicode,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut raw = ptr::null_mut();
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                access,
                &attributes,
                &mut io,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_ALL,
                disposition,
                kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        if status < 0 || raw.is_null() {
            Err(status)
        } else {
            Ok(unsafe { File::from_raw_handle(raw) })
        }
    }
    fn parent(path: &Path, create: bool) -> Result<File> {
        let mut components = path
            .parent()
            .context("owned target missing parent")?
            .components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
                _ => bail!("owned Windows agent path must use a local drive"),
            },
            _ => bail!("owned Windows agent path must be absolute"),
        };
        ensure!(
            matches!(components.next(), Some(Component::RootDir)),
            "owned Windows agent path must be rooted"
        );
        let root = format!("{}:\\", char::from(drive));
        let root = OsStr::new(&root)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe {
            CreateFileW(
                root.as_ptr(),
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_ALL,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        ensure!(
            raw != INVALID_HANDLE,
            "opening held Windows volume root failed"
        );
        let mut current = unsafe { File::from_raw_handle(raw) };
        verify_directory(&current)?;
        for component in components {
            let Component::Normal(name) = component else {
                bail!("owned Windows agent path contains an unsupported component")
            };
            let name = wide_component(name)?;
            let next = match open_relative(
                &current,
                &name,
                FILE_OPEN,
                FILE_DIRECTORY_FILE,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            ) {
                Ok(file) => file,
                Err(STATUS_OBJECT_NAME_NOT_FOUND) if create => open_relative(
                    &current,
                    &name,
                    FILE_CREATE,
                    FILE_DIRECTORY_FILE,
                    GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )
                .map_err(|status| {
                    anyhow::anyhow!(
                        "creating held Windows agent directory failed with NTSTATUS {status:#x}"
                    )
                })?,
                Err(status) => {
                    bail!("opening held Windows agent directory failed with NTSTATUS {status:#x}")
                }
            };
            verify_directory(&next)?;
            current = next;
        }
        Ok(current)
    }
    fn leaf(path: &Path) -> Result<Vec<u16>> {
        wide_component(
            path.file_name()
                .context("owned Windows agent path has no filename")?,
        )
    }
    pub fn exists(path: &Path, create_parent: bool) -> Result<bool> {
        let parent = parent(path, create_parent)?;
        match open_relative(
            &parent,
            &leaf(path)?,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        ) {
            Ok(file) => {
                verify_file(&file)?;
                Ok(true)
            }
            Err(STATUS_OBJECT_NAME_NOT_FOUND) => Ok(false),
            Err(status) => {
                bail!("opening held Windows agent file failed with NTSTATUS {status:#x}")
            }
        }
    }
    pub fn read(path: &Path, context: &str) -> Result<Vec<u8>> {
        let parent = parent(path, false)?;
        let mut file = open_relative(
            &parent,
            &leaf(path)?,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )
        .map_err(|status| anyhow::anyhow!("{context}: NTSTATUS {status:#x}"))?;
        verify_file(&file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .with_context(|| context.to_owned())?;
        Ok(bytes)
    }
    pub fn create(path: &Path, bytes: &[u8], context: &str) -> Result<()> {
        let parent = parent(path, true)?;
        let mut file = open_relative(
            &parent,
            &leaf(path)?,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
            GENERIC_WRITE | GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )
        .map_err(|status| anyhow::anyhow!("{context}: NTSTATUS {status:#x}"))?;
        verify_file(&file)?;
        file.write_all(bytes).with_context(|| context.to_owned())?;
        file.sync_all()
            .context("syncing owned Windows agent definition")?;
        Ok(())
    }
    pub fn rename(from: &Path, to: &Path) -> Result<()> {
        ensure!(
            from.parent() == to.parent(),
            "owned Windows agent rename must stay within one held directory"
        );
        let parent = parent(from, false)?;
        let source = open_relative(
            &parent,
            &leaf(from)?,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            GENERIC_READ | GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )
        .map_err(|status| {
            anyhow::anyhow!("opening held Windows rename source failed with NTSTATUS {status:#x}")
        })?;
        verify_file(&source)?;
        let target = leaf(to)?;
        let offset = std::mem::offset_of!(FileRenameInformation, file_name);
        let mut buffer = vec![0u8; offset + target.len() * 2];
        unsafe {
            let info = buffer.as_mut_ptr().cast::<FileRenameInformation>();
            (*info).replace_if_exists = 0;
            (*info).root_directory = parent.as_raw_handle();
            (*info).file_name_length = (target.len() * 2) as u32;
            ptr::copy_nonoverlapping(
                target.as_ptr().cast::<u8>(),
                buffer.as_mut_ptr().add(offset),
                target.len() * 2,
            );
        }
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let status = unsafe {
            NtSetInformationFile(
                source.as_raw_handle(),
                &mut io,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                10,
            )
        };
        ensure!(
            status >= 0,
            "held Windows no-replace agent rename failed with NTSTATUS {status:#x}"
        );
        Ok(())
    }
    pub fn remove(path: &Path) -> Result<()> {
        let parent = parent(path, false)?;
        let file = open_relative(
            &parent,
            &leaf(path)?,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )
        .map_err(|status| {
            anyhow::anyhow!("opening held Windows removal target failed with NTSTATUS {status:#x}")
        })?;
        verify_file(&file)?;
        #[repr(C)]
        struct Disposition {
            delete_file: u8,
        }
        let value = Disposition { delete_file: 1 };
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut io,
                (&raw const value).cast(),
                size_of::<Disposition>() as u32,
                13,
            )
        };
        ensure!(
            status >= 0,
            "held Windows agent removal failed with NTSTATUS {status:#x}"
        );
        Ok(())
    }
}

#[cfg(windows)]
fn owned_file_exists(path: &Path, create_parent: bool) -> Result<bool> {
    held_windows_agent_files::exists(path, create_parent)
}
#[cfg(windows)]
fn read_owned_file(path: &Path, context: &str) -> Result<Vec<u8>> {
    held_windows_agent_files::read(path, context)
}
#[cfg(windows)]
fn write_owned_file_new(path: &Path, bytes: &[u8], context: &str) -> Result<()> {
    held_windows_agent_files::create(path, bytes, context)
}
#[cfg(windows)]
fn rename_owned_file(from: &Path, to: &Path) -> Result<()> {
    held_windows_agent_files::rename(from, to)
}
#[cfg(windows)]
fn remove_owned_file(path: &Path) -> Result<()> {
    held_windows_agent_files::remove(path)
}

#[cfg(all(not(unix), not(windows)))]
fn owned_file_exists(path: &Path, _create_parent: bool) -> Result<bool> {
    ensure_no_reparse_components(path.parent().context("owned target missing parent")?)?;
    reject_reparse_leaf(path)?;
    Ok(path.exists())
}

#[cfg(all(not(unix), not(windows)))]
fn read_owned_file(path: &Path, context: &str) -> Result<Vec<u8>> {
    ensure!(owned_file_exists(path, false)?, "{context}");
    std::fs::read(path).with_context(|| context.to_owned())
}

#[cfg(all(not(unix), not(windows)))]
fn write_owned_file_new(path: &Path, bytes: &[u8], context: &str) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    std::fs::create_dir_all(path.parent().context("owned target missing parent")?)?;
    let mut file = options.open(path).with_context(|| context.to_owned())?;
    use std::io::Write;
    file.write_all(bytes).with_context(|| context.to_owned())?;
    file.sync_all().context("syncing owned agent definition")?;
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn rename_owned_file(from: &Path, to: &Path) -> Result<()> {
    ensure!(
        owned_file_exists(from, false)?,
        "owned source file disappeared"
    );
    ensure_no_reparse_components(to.parent().context("owned target missing parent")?)?;
    reject_reparse_leaf(to)?;
    std::fs::hard_link(from, to).context("publishing owned agent file without replacement")?;
    std::fs::remove_file(from).context("removing moved owned agent file")
}

#[cfg(all(not(unix), not(windows)))]
fn remove_owned_file(path: &Path) -> Result<()> {
    ensure!(owned_file_exists(path, false)?, "owned file disappeared");
    std::fs::remove_file(path).context("removing owned agent file")
}
fn rollback_stage(target: &Path, operation: Uuid) {
    if let Ok(staged) = stage_path(target, operation) {
        let _ = remove_owned_file(&staged);
    }
}
fn prior_file_metadata(path: &Path, operation: Uuid) -> Result<Option<String>> {
    if !owned_file_exists(path, false)? {
        return Ok(Some(serde_json::json!({"present": false}).to_string()));
    };
    let bytes = read_owned_file(path, "reading existing owned agent file")?;
    Ok(Some(serde_json::json!({"present": true, "digest": sha256_hex(&bytes), "backup_name": prior_backup_path(path, operation)?.file_name().and_then(|name| name.to_str()).unwrap_or_default()}).to_string()))
}

fn with_replacement_receipt(
    prior_file_metadata_json: Option<&str>,
    receipt: &AgentReplacementCompensationReceipt,
) -> Result<String> {
    let mut metadata = prior_file_metadata_json
        .map(serde_json::from_str::<serde_json::Value>)
        .transpose()
        .context("decoding prior file metadata before replacement")?
        .unwrap_or_else(|| serde_json::json!({}));
    let object = metadata
        .as_object_mut()
        .context("prior file metadata must be a JSON object")?;
    object.insert(
        "replacement_compensation_receipt".into(),
        serde_json::to_value(receipt).context("encoding replacement compensation receipt")?,
    );
    serde_json::to_string(&metadata).context("encoding replacement file metadata")
}

fn journal_replacement_receipt(
    journal: &InstallationJournalRow,
) -> Option<Result<AgentReplacementCompensationReceipt>> {
    let metadata = journal.prior_file_metadata_json.as_deref()?;
    let parsed = match serde_json::from_str::<serde_json::Value>(metadata) {
        Ok(value) => value,
        Err(error) => return Some(Err(error).context("decoding prior file metadata")),
    };
    parsed
        .get("replacement_compensation_receipt")
        .cloned()
        .map(|value| {
            serde_json::from_value(value).context("decoding replacement compensation receipt")
        })
}

fn replacement_receipt_matches_committed(
    row: &cockpit_db::db::agent_installations::AgentInstallationRow,
    receipt: &AgentReplacementCompensationReceipt,
) -> bool {
    row.installation_id == receipt.installation_id
        && row.source_identity == receipt.replacement_source_identity
        && row.source_revision == receipt.replacement_source_revision
        && row.source_digest == receipt.replacement_source_digest
        && row.fetched_at_unix_ms == receipt.replacement_fetched_at_unix_ms
        && row.installation_revision == receipt.prior_installation_revision + 1
        && row.deleted_at_unix_ms.is_none()
}

fn discard_prior_backup(target: &Path, operation: Uuid) -> Result<()> {
    let backup = prior_backup_path(target, operation)?;
    if owned_file_exists(&backup, false)? {
        remove_owned_file(&backup).context("removing committed prior agent backup")?;
    }
    Ok(())
}
fn prior_file_is_unchanged(path: &Path, metadata: Option<&str>) -> Result<bool> {
    let Some(metadata) = metadata else {
        return Ok(!owned_file_exists(path, false)?);
    };
    let parsed = serde_json::from_str::<serde_json::Value>(metadata).ok();
    if parsed
        .as_ref()
        .and_then(|value| value.get("present"))
        .and_then(serde_json::Value::as_bool)
        == Some(false)
    {
        return Ok(!owned_file_exists(path, false)?);
    }
    let expected = parsed.and_then(|value| {
        value
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    });
    Ok(expected.is_some_and(|expected| {
        owned_file_exists(path, false).unwrap_or(false)
            && target_digest(path)
                .map(|actual| actual == expected)
                .unwrap_or(false)
    }))
}
fn target_digest(path: &Path) -> Result<String> {
    Ok(sha256_hex(&read_owned_file(
        path,
        "reading published daemon-owned agent definition",
    )?))
}

/// Build the redacted immutable journal payload before the DB transaction
/// creates an operation. The source was already fully fetched and parsed; the
/// transaction below persists this exact SHA/byte sequence alongside the
/// operation so a crash cannot make a same-key retry consult a moving ref.
fn staged_source_journal_metadata(
    source_locator: &str,
    fetched: &FetchedAgentSource,
) -> Result<(String, String)> {
    let source = CanonicalAgentSource::parse(source_locator)?;
    let target_name = source
        .markdown_path
        .rsplit('/')
        .next()
        .and_then(|value| value.strip_suffix(".md"))
        .filter(|value| !value.is_empty())
        .context("source Markdown path has no agent filename")?;
    let digest = sha256_hex(&fetched.markdown);
    let metadata = serde_json::to_string(&JournalStagedSource {
        target_name: target_name.to_owned(),
        digest: digest.clone(),
        commit_sha: fetched.commit_sha.clone(),
        markdown_base64: base64::engine::general_purpose::STANDARD.encode(&fetched.markdown),
    })?;
    Ok((metadata, digest))
}
fn checkpoint_rank(value: InstallationJournalCheckpoint) -> u8 {
    match value {
        InstallationJournalCheckpoint::Staged => 0,
        InstallationJournalCheckpoint::DbCommitted => 1,
        InstallationJournalCheckpoint::FileRenamed => 2,
        InstallationJournalCheckpoint::Complete => 3,
    }
}

/// Recover the exact staged source before contacting a mutable ref again. The
/// journal stores only bounded Markdown bytes and an immutable resolved SHA;
/// credentials, URLs, workspace paths, and provider routes never enter it.
fn journal_staged_source(row: &InstallationJournalRow) -> Option<Result<FetchedAgentSource>> {
    let metadata = row.staged_file_metadata_json.as_deref()?;
    let decoded: JournalStagedSource = match serde_json::from_str(metadata) {
        Ok(value) => value,
        // Old/no-content test fixtures deliberately exercise the fetch path.
        Err(_) => return None,
    };
    Some((|| {
        ensure!(
            is_commit_sha(&decoded.commit_sha)
                && decoded.digest.len() == 64
                && !decoded.target_name.is_empty(),
            "stored staged source metadata is invalid"
        );
        let markdown = base64::engine::general_purpose::STANDARD
            .decode(decoded.markdown_base64)
            .context("decoding staged source Markdown")?;
        ensure!(
            markdown.len() <= MAX_AGENT_MARKDOWN_BYTES && sha256_hex(&markdown) == decoded.digest,
            "stored staged source digest is invalid"
        );
        Ok(FetchedAgentSource {
            commit_sha: decoded.commit_sha,
            markdown,
        })
    })())
}

/// Materialize a binding choice for every documented author-recommendation /
/// local-offering collision.  Do not collapse two author recommendations that
/// happen to name the same local offering: each has different provenance and
/// remains independently reviewable.  Conversely, an upstream identity is
/// display metadata only; exact `(provider_id, model_id)` aliases are the
/// sole matching mechanism.
fn binding_choices(
    slot_id: &str,
    slot: &crate::agents::ModelSlot,
    compatible: &[crate::agents::AgentProfileModelOffering],
) -> (
    Vec<AgentInstallationChoiceV1>,
    Vec<AgentInstallationUnmatchedRecommendationV1>,
) {
    let mut choices = Vec::new();
    let mut unmatched = Vec::new();
    let mut exact_offerings = std::collections::BTreeSet::new();
    let wire_offerings = compatible
        .iter()
        .enumerate()
        .map(|(index, offering)| {
            (
                offering.offering_id.as_str(),
                (format!("offering-{index}"), offering.provider_id.clone()),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for (recommendation_index, recommendation) in slot.suggested_models.iter().enumerate() {
        let before = choices.len();
        let mut recommendation_offerings = std::collections::BTreeSet::new();
        for alias in &recommendation.provider_aliases {
            for offering in compatible.iter().filter(|offering| {
                offering.provider_id == alias.provider_id && offering.model_id == alias.model_id
            }) {
                // One offering may appear through duplicate-looking route
                // metadata, but a recommendation has one selectable route.
                if !recommendation_offerings.insert(offering.offering_id.clone()) {
                    continue;
                }
                exact_offerings.insert(offering.offering_id.clone());
                let (offering_id, provider_id) = wire_offerings
                    .get(offering.offering_id.as_str())
                    .expect("compatible offering identity disappeared")
                    .clone();
                choices.push(AgentInstallationChoiceV1 {
                    choice_id: format!("choice-{recommendation_index}-{offering_id}"),
                    slot_id: slot_id.to_owned(),
                    offering_id,
                    provider_id,
                    model_id: offering.model_id.clone(),
                    recommendation_id: Some(recommendation.recommendation_id.clone()),
                    canonical_upstream_identity: Some(recommendation.upstream_identity.clone()),
                    author_label: recommendation.author_label.clone(),
                    rationale: recommendation.rationale.clone(),
                    author_suggested: true,
                    exact_alias_match: true,
                });
            }
        }
        if choices.len() == before {
            unmatched.push(AgentInstallationUnmatchedRecommendationV1 {
                recommendation_id: recommendation.recommendation_id.clone(),
                canonical_upstream_identity: recommendation.upstream_identity.clone(),
                author_label: recommendation.author_label.clone(),
                rationale: recommendation.rationale.clone(),
            });
        }
    }
    // `ranked_compatible_offerings` has already applied hard capability
    // checks and stable author/alias/offering ordering.  The remaining local
    // offerings are compatible but unsuggested; callers may select them
    // without an acknowledgement.
    for offering in compatible
        .iter()
        .filter(|offering| !exact_offerings.contains(&offering.offering_id))
    {
        let (offering_id, provider_id) = wire_offerings
            .get(offering.offering_id.as_str())
            .expect("compatible offering identity disappeared")
            .clone();
        choices.push(AgentInstallationChoiceV1 {
            choice_id: format!("choice-local-{offering_id}"),
            slot_id: slot_id.to_owned(),
            offering_id,
            provider_id,
            model_id: offering.model_id.clone(),
            recommendation_id: None,
            canonical_upstream_identity: None,
            author_label: None,
            rationale: None,
            author_suggested: false,
            exact_alias_match: false,
        });
    }
    (choices, unmatched)
}

fn session_setup_choice_routes(
    choices: &[AgentInstallationChoiceV1],
    compatible: &[crate::agents::AgentProfileModelOffering],
) -> Vec<cockpit_proto::SessionSetupModelChoiceRouteV1> {
    choices
        .iter()
        .map(|choice| {
            let offering = compatible
                .iter()
                .enumerate()
                .find(|(index, _)| choice.offering_id == format!("offering-{index}"))
                .map(|(_, offering)| offering)
                .expect("setup choice lost its exact ranked offering");
            cockpit_proto::SessionSetupModelChoiceRouteV1 {
                choice_id: choice.choice_id.clone(),
                route_choice_id: cockpit_proto::focused_model_binding_choice_id(
                    &offering.provider_profile_handle,
                    &offering.provider_id,
                    &offering.model_id,
                ),
            }
        })
        .collect()
}

fn setup_scope_rank(scope: AgentInstallationScope) -> u8 {
    match scope {
        AgentInstallationScope::Global => 0,
        AgentInstallationScope::WorkspacePrivate => 1,
        AgentInstallationScope::WorkspaceShared => 2,
    }
}

pub(crate) fn setup_definition_path(
    daemon_agents_dir: &Path,
    row: &AgentInstallationRow,
    workspace_root: Option<&Path>,
) -> Result<PathBuf> {
    if is_package_child_installation(row) {
        let (parent_source_agent_id, child_name) = row
            .source_agent_id
            .rsplit_once('/')
            .context("package child installation has no parent identity")?;
        let parent_name = parent_source_agent_id
            .rsplit('/')
            .next()
            .context("package child installation parent has no filename")?;
        let scope = match row.scope {
            AgentInstallationScope::Global => AgentInstallationScopeWire::Global,
            AgentInstallationScope::WorkspacePrivate => {
                AgentInstallationScopeWire::WorkspacePrivate
            }
            AgentInstallationScope::WorkspaceShared => AgentInstallationScopeWire::WorkspaceShared,
        };
        let parent =
            existing_owned_definition_path(daemon_agents_dir, workspace_root, scope, parent_name)?;
        ensure!(
            parent.is_dir(),
            "package child parent is not a package directory"
        );
        return Ok(parent
            .join(crate::agents::PACKAGE_SUBAGENTS_DIR)
            .join(format!("{child_name}.md")));
    }
    let name = row
        .source_agent_id
        .rsplit('/')
        .next()
        .context("installed agent id has no filename")?;
    let scope = match row.scope {
        AgentInstallationScope::Global => AgentInstallationScopeWire::Global,
        AgentInstallationScope::WorkspacePrivate => AgentInstallationScopeWire::WorkspacePrivate,
        AgentInstallationScope::WorkspaceShared => AgentInstallationScopeWire::WorkspaceShared,
    };
    existing_owned_definition_path(daemon_agents_dir, workspace_root, scope, name)
}

fn unavailable_setup_candidate(
    row: AgentInstallationRow,
    selected: bool,
) -> SessionSetupAgentCandidateV1 {
    SessionSetupAgentCandidateV1 {
        installation: AgentInstallationRecordV1 {
            installation_id: row.installation_id.to_string(),
            scope: match row.scope {
                AgentInstallationScope::Global => AgentInstallationScopeWire::Global,
                AgentInstallationScope::WorkspacePrivate => {
                    AgentInstallationScopeWire::WorkspacePrivate
                }
                AgentInstallationScope::WorkspaceShared => {
                    AgentInstallationScopeWire::WorkspaceShared
                }
            },
            source_agent_id: row.source_agent_id,
            source_identity: row.source_identity,
            source_revision: row.source_revision,
            source_digest: row.source_digest,
            installation_revision: row.installation_revision,
            bindings: Vec::new(),
        },
        selected,
        slots: Vec::new(),
        locked_reason: Some(SessionSetupLockedReasonV1::DefinitionUnavailable),
    }
}

/// One locally projected candidate plus the exact vNext definition digest
/// observed while deriving it. The digest never crosses the protocol on its
/// own; it lets the snapshot builder prove the external definition did not
/// change between projection and publication.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionSetupCandidateProjection {
    candidate: SessionSetupAgentCandidateV1,
    definition_digest: Option<String>,
}

impl SessionSetupCandidateProjection {
    fn unavailable(row: &SessionSetupInstallationSnapshotRow, selected: bool) -> Self {
        Self {
            candidate: unavailable_setup_candidate(row.installation.clone(), selected),
            definition_digest: None,
        }
    }
}

fn setup_installation_record(row: &AgentInstallationRow) -> AgentInstallationRecordV1 {
    AgentInstallationRecordV1 {
        installation_id: row.installation_id.to_string(),
        scope: match row.scope {
            AgentInstallationScope::Global => AgentInstallationScopeWire::Global,
            AgentInstallationScope::WorkspacePrivate => {
                AgentInstallationScopeWire::WorkspacePrivate
            }
            AgentInstallationScope::WorkspaceShared => AgentInstallationScopeWire::WorkspaceShared,
        },
        source_agent_id: row.source_agent_id.clone(),
        source_identity: row.source_identity.clone(),
        source_revision: row.source_revision.clone(),
        source_digest: row.source_digest.clone(),
        installation_revision: row.installation_revision,
        bindings: Vec::new(),
    }
}

fn session_setup_db_snapshot_fingerprint(snapshot: &SessionSetupDbSnapshot) -> String {
    let mut hasher = Sha256::new();
    // This fingerprint is an authority/CAS input, not an ad-hoc cache key.
    // Every field is framed with its name, type, and length so two distinct
    // SQLite projections cannot collide merely by concatenating variable-size
    // strings or optional values.  The digest is never a serialization or a
    // transport for any of the private fields it covers.
    hasher.update(b"cockpit-session-setup-db-snapshot-fingerprint-v1");
    let selected_installation_id = snapshot.selected_installation_id.map(|id| id.to_string());
    session_setup_fingerprint_optional_text(
        &mut hasher,
        "selected_installation_id",
        selected_installation_id.as_deref(),
    );
    session_setup_fingerprint_u64(
        &mut hasher,
        "installation_count",
        snapshot.installations.len() as u64,
    );
    for candidate in &snapshot.installations {
        let installation = &candidate.installation;
        session_setup_fingerprint_field(&mut hasher, "installation", "begin", &[]);
        session_setup_fingerprint_text(
            &mut hasher,
            "installation_id",
            &installation.installation_id.to_string(),
        );
        session_setup_fingerprint_text(
            &mut hasher,
            "scope",
            match installation.scope {
                AgentInstallationScope::Global => "global",
                AgentInstallationScope::WorkspacePrivate => "workspace_private",
                AgentInstallationScope::WorkspaceShared => "workspace_shared",
            },
        );
        session_setup_fingerprint_optional_text(
            &mut hasher,
            "canonical_workspace_id",
            installation.canonical_workspace_id.as_deref(),
        );
        session_setup_fingerprint_text(
            &mut hasher,
            "source_agent_id",
            &installation.source_agent_id,
        );
        session_setup_fingerprint_text(
            &mut hasher,
            "source_identity",
            &installation.source_identity,
        );
        session_setup_fingerprint_optional_text(
            &mut hasher,
            "source_revision",
            installation.source_revision.as_deref(),
        );
        session_setup_fingerprint_text(&mut hasher, "source_digest", &installation.source_digest);
        session_setup_fingerprint_i64(
            &mut hasher,
            "fetched_at_unix_ms",
            installation.fetched_at_unix_ms,
        );
        session_setup_fingerprint_u64(
            &mut hasher,
            "installation_revision",
            installation.installation_revision,
        );
        session_setup_fingerprint_optional_i64(
            &mut hasher,
            "deleted_at_unix_ms",
            installation.deleted_at_unix_ms,
        );
        if let Some(observation) = &candidate.observation {
            session_setup_fingerprint_field(&mut hasher, "observation", "present", &[1]);
            session_setup_fingerprint_text(
                &mut hasher,
                "observation_installation_id",
                &observation.installation_id.to_string(),
            );
            session_setup_fingerprint_text(
                &mut hasher,
                "observed_digest",
                &observation.observed_digest,
            );
            session_setup_fingerprint_u64(
                &mut hasher,
                "observation_revision",
                observation.observation_revision,
            );
            session_setup_fingerprint_bool(&mut hasher, "reviewed", observation.reviewed);
            session_setup_fingerprint_i64(
                &mut hasher,
                "observed_at_unix_ms",
                observation.observed_at_unix_ms,
            );
        } else {
            session_setup_fingerprint_field(&mut hasher, "observation", "present", &[0]);
        }
        session_setup_fingerprint_u64(
            &mut hasher,
            "binding_count",
            candidate.bindings.len() as u64,
        );
        for binding in &candidate.bindings {
            session_setup_fingerprint_field(&mut hasher, "binding", "begin", &[]);
            session_setup_fingerprint_text(
                &mut hasher,
                "binding_id",
                &binding.binding_id.to_string(),
            );
            session_setup_fingerprint_text(
                &mut hasher,
                "binding_installation_id",
                &binding.installation_id.to_string(),
            );
            session_setup_fingerprint_text(
                &mut hasher,
                "binding_definition_digest",
                &binding.definition_digest,
            );
            session_setup_fingerprint_text(&mut hasher, "slot_id", &binding.slot_id);
            session_setup_fingerprint_text(
                &mut hasher,
                "provider_profile_handle",
                &binding.provider_profile_handle,
            );
            session_setup_fingerprint_text(&mut hasher, "model_id", &binding.model_id);
            session_setup_fingerprint_field(
                &mut hasher,
                "provenance_payload",
                "bytes",
                &binding.provenance_payload,
            );
            session_setup_fingerprint_text(
                &mut hasher,
                "provenance_digest",
                &binding.provenance_digest,
            );
            session_setup_fingerprint_bool(
                &mut hasher,
                "hard_capability_verified",
                binding.hard_capability_verified,
            );
            session_setup_fingerprint_u64(
                &mut hasher,
                "binding_revision",
                binding.binding_revision,
            );
            session_setup_fingerprint_optional_i64(
                &mut hasher,
                "retired_at_unix_ms",
                binding.retired_at_unix_ms,
            );
            session_setup_fingerprint_i64(
                &mut hasher,
                "created_at_unix_ms",
                binding.created_at_unix_ms,
            );
        }
    }
    crate::intel::hex_lower(&hasher.finalize())
}

fn session_setup_fingerprint_field(
    hasher: &mut Sha256,
    field_name: &str,
    type_name: &str,
    value: &[u8],
) {
    for part in [field_name.as_bytes(), type_name.as_bytes(), value] {
        hasher.update(
            u64::try_from(part.len())
                .expect("session setup fingerprint field length fits u64")
                .to_be_bytes(),
        );
        hasher.update(part);
    }
}

fn session_setup_fingerprint_text(hasher: &mut Sha256, field_name: &str, value: &str) {
    session_setup_fingerprint_field(hasher, field_name, "text", value.as_bytes());
}

fn session_setup_fingerprint_optional_text(
    hasher: &mut Sha256,
    field_name: &str,
    value: Option<&str>,
) {
    match value {
        Some(value) => session_setup_fingerprint_field(
            hasher,
            field_name,
            "optional-text:some",
            value.as_bytes(),
        ),
        None => session_setup_fingerprint_field(hasher, field_name, "optional-text:none", &[]),
    }
}

fn session_setup_fingerprint_u64(hasher: &mut Sha256, field_name: &str, value: u64) {
    session_setup_fingerprint_field(hasher, field_name, "u64", &value.to_be_bytes());
}

fn session_setup_fingerprint_i64(hasher: &mut Sha256, field_name: &str, value: i64) {
    session_setup_fingerprint_field(hasher, field_name, "i64", &value.to_be_bytes());
}

fn session_setup_fingerprint_optional_i64(
    hasher: &mut Sha256,
    field_name: &str,
    value: Option<i64>,
) {
    match value {
        Some(value) => session_setup_fingerprint_field(
            hasher,
            field_name,
            "optional-i64:some",
            &value.to_be_bytes(),
        ),
        None => session_setup_fingerprint_field(hasher, field_name, "optional-i64:none", &[]),
    }
}

fn session_setup_fingerprint_bool(hasher: &mut Sha256, field_name: &str, value: bool) {
    session_setup_fingerprint_field(hasher, field_name, "bool", &[u8::from(value)]);
}

pub(crate) fn setup_offerings(
    providers: &ProvidersConfig,
) -> Vec<crate::agents::AgentProfileModelOffering> {
    providers
        .providers
        .iter()
        .enumerate()
        .flat_map(|(provider_index, (provider_profile_handle, entry))| {
            let provider_id = entry.template.clone().unwrap_or_else(|| {
                // Custom-provider map keys are daemon-local credential routes;
                // the wire carries this deterministic display token instead.
                format!("configured-provider-{provider_index}")
            });
            entry
                .models
                .iter()
                .enumerate()
                .map(
                    move |(model_index, model)| crate::agents::AgentProfileModelOffering {
                        offering_id: format!("offering-{provider_index}-{model_index}"),
                        provider_profile_handle: provider_profile_handle.clone(),
                        provider_id: provider_id.clone(),
                        model_id: model.id.clone(),
                    },
                )
        })
        .collect()
}

/// A daemon-private exact-content revision for the provider inventory. The
/// serialized configuration can contain credential references, so this digest
/// never crosses the protocol boundary; only its inclusion in the final
/// snapshot revision makes a configuration replacement detectable.
pub(crate) fn session_setup_config_fingerprint(providers: &ProvidersConfig) -> Result<String> {
    Ok(sha256_hex(
        &serde_json::to_vec(providers).context("serializing setup provider snapshot")?,
    ))
}

fn session_setup_revision(
    selected_installation_id: Option<Uuid>,
    candidates: &[SessionSetupAgentCandidateV1],
    db_snapshot_fingerprint: &str,
    config_generation: u64,
    global_config_generation: u64,
    config_fingerprint: &str,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(
        selected_installation_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
    );
    hasher.update(db_snapshot_fingerprint.as_bytes());
    hasher.update(config_generation.to_be_bytes());
    hasher.update(global_config_generation.to_be_bytes());
    hasher.update(config_fingerprint.as_bytes());
    // The canonical DTO contains only public/redacted data and captures every
    // visible availability, recommendation, and binding-state change. Hash it
    // rather than maintaining a second, inevitably incomplete revision view.
    hasher.update(serde_json::to_vec(candidates).expect("session setup DTO serializes"));
    let digest = hasher.finalize();
    // Bound the revision to JS `Number.MAX_SAFE_INTEGER` (2^53 - 1). The
    // TypeScript wire mirror validates it with `safeU64NumberSchema` and uses
    // it as an exact CAS token; a full-range u64 exceeds that cap ~99.95% of
    // the time and, above 2^53, cannot survive a `JSON.parse`/`stringify`
    // round-trip. Masking a uniform SHA-256 prefix to 53 bits preserves ~2^53
    // of change-detection space, which is ample for an opaque snapshot label.
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix is eight bytes"),
    ) & ((1u64 << 53) - 1)
}

/// Persist the daemon-local profile route selected while choices are built.
/// A wire choice only identifies the portable provider alias; a restart must
/// never infer a credential-owning profile from that alias again.
fn durable_binding_routes(
    slot: &crate::agents::ModelSlot,
    compatible: &[crate::agents::AgentProfileModelOffering],
    choices: &[AgentInstallationChoiceV1],
) -> Result<Vec<DurableBindingRoute>> {
    let mut route_ids = std::collections::BTreeSet::new();
    let mut routes = Vec::with_capacity(choices.len());
    for choice in choices {
        ensure!(
            route_ids.insert(choice.choice_id.clone()),
            "daemon emitted duplicate installation choice id"
        );
        let matches = compatible
            .iter()
            .enumerate()
            .filter(|(index, offering)| {
                choice.provider_id == offering.provider_id
                    && choice.model_id == offering.model_id
                    && choice.offering_id == format!("offering-{index}")
            })
            .map(|(_, offering)| &offering.provider_profile_handle)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1 && !matches[0].trim().is_empty(),
            "selected installation choice has no exact daemon-local provider profile route"
        );
        let offering = compatible
            .iter()
            .find(|offering| {
                offering.provider_profile_handle.as_str() == matches[0].as_str()
                    && offering.model_id.as_str() == choice.model_id.as_str()
            })
            .context("selected installation route offering disappeared")?;
        let authored_default = slot.default_model().is_some_and(|default| {
            default.provider_id.as_str() == offering.provider_id.as_str()
                && default.model_id.as_str() == offering.model_id.as_str()
        });
        routes.push(DurableBindingRoute {
            choice_id: choice.choice_id.clone(),
            slot_id: choice.slot_id.clone(),
            model_id: choice.model_id.clone(),
            provider_profile_handle: matches[0].clone(),
            authored_default,
        });
    }
    Ok(routes)
}

/// Return the exact redacted provider identity used by setup/install wire
/// projections for one credential-owning profile route. The profile handle is
/// construction-only and is never an acceptable display fallback.
pub(crate) fn wire_provider_id_for_profile_route(
    providers: &ProvidersConfig,
    provider_profile_handle: &str,
    model_id: &str,
) -> Option<String> {
    let matches = setup_offerings(providers)
        .into_iter()
        .filter(|offering| {
            offering.provider_profile_handle == provider_profile_handle
                && offering.model_id == model_id
        })
        .map(|offering| offering.provider_id)
        .collect::<std::collections::BTreeSet<_>>();
    (matches.len() == 1)
        .then(|| matches.into_iter().next())
        .flatten()
}

/// Map a session-setup / installation wire choice back to the config-map key
/// `Model::for_provider` can look up. The wire `provider_id` is a display
/// token for custom providers (`configured-provider-{index}`) and must never
/// be persisted as the live route.
pub(crate) fn resolvable_provider_handle_for_choice(
    providers: &ProvidersConfig,
    choice: &AgentInstallationChoiceV1,
) -> Option<String> {
    let offerings = setup_offerings(providers);
    let mut handles = std::collections::BTreeSet::new();
    for offering in &offerings {
        if offering.model_id == choice.model_id
            && (offering.provider_id == choice.provider_id
                || offering.provider_profile_handle == choice.provider_id)
        {
            handles.insert(offering.provider_profile_handle.clone());
        }
    }
    if providers.providers.contains_key(&choice.provider_id) {
        handles.insert(choice.provider_id.clone());
    }
    if handles.len() == 1 {
        handles.into_iter().next()
    } else {
        None
    }
}

/// Legacy open-slot `--yes` is deliberately narrower than normal interactive
/// ranking. Concrete `models` slots are handled by `automatic_binding_choice`.
fn first_exact_author_choice(choices: &[AgentInstallationChoiceV1]) -> Option<String> {
    choices
        .iter()
        .find(|choice| choice.author_suggested && choice.exact_alias_match)
        .map(|choice| choice.choice_id.clone())
}

/// `--yes` follows the authored ModelSlot default when the slot declares a
/// concrete model set. Suggested-model provenance is the legacy fallback only
/// for an open slot.
fn automatic_binding_choice(
    slot: &crate::agents::ModelSlot,
    choices: &[AgentInstallationChoiceV1],
    routes: &[DurableBindingRoute],
) -> Option<String> {
    if slot.default_model().is_some() {
        return choices
            .iter()
            .find(|choice| {
                routes
                    .iter()
                    .any(|route| route.choice_id == choice.choice_id && route.authored_default)
            })
            .map(|choice| choice.choice_id.clone());
    }
    first_exact_author_choice(choices)
}

/// Reduce positional/recommendation choice aliases to the durable route set.
/// The submitted choice selects a route, but a concrete ModelSlot retains its
/// authored explicit/first default. Open slots retain the historical submitted
/// choice default.
fn binding_inputs_for_submission(
    choice_set: &BindChoiceSet,
    slot_id: &str,
    submitted_choice: &str,
) -> Result<Vec<cockpit_db::db::agent_installations::AgentBindingInput>> {
    let slot_routes = choice_set
        .routes
        .iter()
        .filter(|route| route.slot_id == slot_id)
        .collect::<Vec<_>>();
    ensure!(
        !slot_routes.is_empty(),
        "stored installation choice slot has no routes"
    );
    let submitted_route = slot_routes
        .iter()
        .find(|route| route.choice_id == submitted_choice)
        .context("submitted installation choice has no durable route")?;
    let submitted_key = (
        submitted_route.provider_profile_handle.clone(),
        submitted_route.model_id.clone(),
    );

    let mut durable = std::collections::BTreeMap::new();
    for route in slot_routes {
        ensure!(
            !route.provider_profile_handle.trim().is_empty(),
            "stored installation choice has no exact daemon-local profile route"
        );
        let slot_choice = choice_set
            .choices
            .iter()
            .find(|candidate| {
                candidate.slot_id == route.slot_id
                    && candidate.choice_id == route.choice_id
                    && candidate.model_id == route.model_id
            })
            .context("stored installation route has no selectable choice")?;
        let key = (
            route.provider_profile_handle.clone(),
            route.model_id.clone(),
        );
        match durable.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((route, slot_choice));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                ensure!(
                    entry.get().0.authored_default == route.authored_default,
                    "choice aliases disagree about the authored slot default"
                );
                // Preserve the submitted alias as provenance for its durable
                // route; otherwise stable choice order supplies the evidence.
                if route.choice_id == submitted_choice {
                    entry.insert((route, slot_choice));
                }
            }
        }
    }

    let authored_defaults = durable
        .iter()
        .filter(|(_, (route, _))| choice_set.authored_default_required && route.authored_default)
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    ensure!(
        authored_defaults.len() <= 1,
        "authored slot default resolves to multiple durable provider routes"
    );
    ensure!(
        !choice_set.authored_default_required || authored_defaults.len() == 1,
        "concrete model slot has no unique durable authored default route"
    );
    let default_key = authored_defaults.first().cloned().unwrap_or(submitted_key);
    let bindings = durable
        .into_iter()
        .map(|(key, (route, slot_choice))| {
            let payload = serde_json::to_vec(slot_choice)?;
            Ok(cockpit_db::db::agent_installations::AgentBindingInput {
                slot_id: route.slot_id.clone(),
                provider_profile_handle: route.provider_profile_handle.clone(),
                model_id: route.model_id.clone(),
                provenance_digest: sha256_hex(&payload),
                provenance_payload: payload,
                hard_capability_verified: true,
                is_default: key == default_key,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        bindings.iter().filter(|binding| binding.is_default).count() == 1,
        "binding set must retain exactly one durable default"
    );
    Ok(bindings)
}

fn terminal_bind_refusal_code(
    outcome: &cockpit_db::db::agent_installations::BindAgentOutcome,
) -> Option<AgentInstallationErrorCodeV1> {
    use cockpit_db::db::agent_installations::BindAgentOutcome;
    match outcome {
        BindAgentOutcome::Bound(_) | BindAgentOutcome::AlreadyBound(_) => None,
        BindAgentOutcome::Incompatible => Some(AgentInstallationErrorCodeV1::IncompatibleModel),
        BindAgentOutcome::RebindRequired
        | BindAgentOutcome::Conflict
        | BindAgentOutcome::Deleted
        | BindAgentOutcome::NotFound => Some(AgentInstallationErrorCodeV1::StaleBinding),
    }
}

fn validate_durable_choice_set(choice_set: &BindChoiceSet) -> Result<()> {
    ensure!(
        !choice_set.installation_id.trim().is_empty()
            && !choice_set.definition_digest.trim().is_empty(),
        "stored installation choice set is incomplete"
    );
    ensure!(
        choice_set.expected_observation_revision > 0,
        "stored installation choice set has an invalid observation revision"
    );
    ensure!(
        choice_set
            .expected_binding_revision
            .is_none_or(|revision| revision > 0),
        "stored installation choice set has an invalid binding revision"
    );
    let choice_ids = choice_set
        .choices
        .iter()
        .map(|choice| choice.choice_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        choice_ids.len() == choice_set.choices.len(),
        "stored installation choice set has duplicate choice ids"
    );
    if let Some(auto_choice_id) = choice_set.auto_choice_id.as_deref() {
        ensure!(
            choice_set.choices.iter().any(|choice| {
                choice.choice_id == auto_choice_id
                    && ((choice.author_suggested && choice.exact_alias_match)
                        || (choice_set.authored_default_required
                            && choice_set.routes.iter().any(|route| {
                                route.choice_id == choice.choice_id && route.authored_default
                            })))
            }),
            "stored automatic installation choice is not an authored default/exact route"
        );
    }
    let mut route_ids = std::collections::BTreeSet::new();
    for route in &choice_set.routes {
        ensure!(
            choice_ids.contains(route.choice_id.as_str())
                && !route.slot_id.trim().is_empty()
                && !route.model_id.trim().is_empty()
                && !route.provider_profile_handle.trim().is_empty()
                && route_ids.insert((
                    route.slot_id.as_str(),
                    route.choice_id.as_str(),
                    route.provider_profile_handle.as_str(),
                    route.model_id.as_str(),
                )),
            "stored installation choice route is invalid"
        );
    }
    ensure!(
        route_ids.len() == choice_ids.len(),
        "stored installation choice set is missing a daemon-local profile route"
    );
    Ok(())
}

fn minimal_template(
    name: &str,
    execution_kind: AgentInstallationExecutionKindV1,
    primary_slot: &str,
) -> String {
    let execution_kind = match execution_kind {
        AgentInstallationExecutionKindV1::Assistant => "assistant",
        AgentInstallationExecutionKindV1::Coding => "coding",
        AgentInstallationExecutionKindV1::Computer => "computer",
    };
    format!(
        "---\nschemaVersion: 2\nagentId: authored/{name}\nexecutionKind: {execution_kind}\ndescription: Custom {name} agent\nmodelSlots:\n  {primary_slot}:\n    purpose: Primary model\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: true\n---\n\nYou are the `{name}` Cockpit agent.\n"
    )
}
fn receipt(
    operation_id: Uuid,
    status: AgentInstallationReceiptStatusV1,
    installation_id: Option<String>,
    source_revision: Option<String>,
) -> AgentInstallationResultV1 {
    AgentInstallationResultV1::Receipt {
        operation_id: operation_id.to_string(),
        status,
        installation_id,
        source_revision,
        binding_outcome: None,
    }
}
fn binding_terminal_receipt(
    operation_id: Uuid,
    parent_status: Option<AgentInstallationReceiptStatusV1>,
    parent_source_revision: Option<String>,
    binding_status: AgentInstallationReceiptStatusV1,
    installation_id: Uuid,
) -> AgentInstallationResultV1 {
    let Some(status) = parent_status else {
        return receipt(
            operation_id,
            binding_status,
            Some(installation_id.to_string()),
            None,
        );
    };
    let binding_outcome = match binding_status {
        AgentInstallationReceiptStatusV1::Bound => AgentInstallationBindingOutcomeV1::Bound,
        AgentInstallationReceiptStatusV1::OptionalUnbound => {
            AgentInstallationBindingOutcomeV1::OptionalUnbound
        }
        AgentInstallationReceiptStatusV1::PrimaryUnusable => {
            AgentInstallationBindingOutcomeV1::PrimaryUnusable
        }
        _ => unreachable!("binding continuations only use binding terminal statuses"),
    };
    AgentInstallationResultV1::Receipt {
        operation_id: operation_id.to_string(),
        status,
        installation_id: Some(installation_id.to_string()),
        source_revision: parent_source_revision,
        binding_outcome: Some(binding_outcome),
    }
}
fn replay_operation(receipt_json: Option<&str>) -> Result<AgentInstallationResultV1> {
    let receipt = receipt_json.context("installation operation is still in progress")?;
    serde_json::from_str(receipt).context("stored installation receipt is corrupt")
}
fn redacted_error(error: anyhow::Error) -> AgentInstallationResultV1 {
    // `anyhow::Error::to_string()` only yields the outer context. Classifying
    // from the complete local error chain keeps private credential failures
    // and dirty-file invariants typed while the returned DTO stays fixed and
    // redacted.
    let text = format!("{error:#}");
    let code = if text.contains("idempotency") {
        AgentInstallationErrorCodeV1::IdempotencyConflict
    } else if text.contains("workspace authorization") {
        AgentInstallationErrorCodeV1::UnauthorizedWorkspace
    } else if text.contains("authorization") || text.contains("private") {
        AgentInstallationErrorCodeV1::PrivateSourceUnauthorized
    } else if text.contains("unknown installation choice") {
        AgentInstallationErrorCodeV1::UnknownChoice
    } else if text.contains("stale") || text.contains("rebind") || text.contains("claimed") {
        AgentInstallationErrorCodeV1::StaleBinding
    } else if text.contains("incompatible") {
        AgentInstallationErrorCodeV1::IncompatibleModel
    } else if text.contains("continuation") || text.contains("expired") {
        AgentInstallationErrorCodeV1::ContinuationExpired
    } else if text.contains("dirty shared") {
        AgentInstallationErrorCodeV1::DirtySharedFile
    } else if text.contains("collision") || text.contains("dirty") {
        AgentInstallationErrorCodeV1::Collision
    // Source-locator grammar errors legitimately mention a Markdown path, but
    // are invalid requests rather than invalid fetched definitions. Keep this
    // branch tied to parsed-definition contract failures only. This must
    // precede the generic fetch classification because the durable parse
    // boundary is intentionally named "invalid fetched AgentDef".
    } else if text.contains("vNext")
        || text.contains("invalid fetched AgentDef")
        || text.contains("fetched agent Markdown")
    {
        AgentInstallationErrorCodeV1::InvalidDefinition
    } else if text.contains("fetch") {
        AgentInstallationErrorCodeV1::FetchFailed
    } else {
        AgentInstallationErrorCodeV1::InvalidRequest
    };
    typed_installation_error(code)
}

fn typed_installation_error(code: AgentInstallationErrorCodeV1) -> AgentInstallationResultV1 {
    AgentInstallationResultV1::Error {
        error: AgentInstallationErrorV1 {
            code,
            message: "agent installation request was refused; inspect daemon logs for redacted diagnostics".into(),
        },
    }
}

/// Test-only durable fixture shared by the installation service and the
/// daemon endpoint.  It deliberately uses the public DB mutation boundaries
/// instead of inserting profile rows by hand: the selected installation,
/// observation, binding, preparation receipt, and immutable profile are all
/// subject to the same CAS and canonical-payload checks as production.
#[cfg(test)]
pub(crate) mod session_setup_test_support {
    use super::*;
    use cockpit_config::config::providers::{ActiveModelRef, ModelEntry, ProviderEntry};
    use cockpit_db::db::agent_installations::{
        AgentBindingExpectation, AgentBindingInput, AgentBindingRevision, AgentBindingRevisionMap,
        AgentExecutionKind, AgentSessionCreateInput, BindAgentOutcome, ObserveAgentOutcome,
        PrepareAgentSessionInput, PrepareAgentSessionOutcome, ProviderAlias,
        RedactedAgentProfileSnapshot, RedactedBindingEvidence, RedactedQuestionPolicy,
    };

    pub(crate) const SELECTED_PROFILE_HANDLE: &str = "credential-profile-sentinel";

    #[derive(Debug, Clone)]
    pub(crate) struct SessionSetupFixture {
        pub session_id: Uuid,
        pub selected_installation_id: Uuid,
        pub workspace_id: String,
    }

    pub(crate) fn providers() -> ProvidersConfig {
        let mut providers = ProvidersConfig::default();
        for (profile, model_id) in [
            ("profile-a", "exact-a"),
            ("profile-b", "exact-b"),
            ("profile-local", "compatible"),
        ] {
            providers.providers.insert(
                profile.into(),
                ProviderEntry {
                    template: Some("openai-compatible".into()),
                    // Worker construction is real, but the fixture never
                    // dispatches inference. A no-auth loopback endpoint keeps
                    // the endpoint test hermetic.
                    url: "http://127.0.0.1:9/v1".into(),
                    models: vec![ModelEntry {
                        id: model_id.into(),
                        context_length: Some(128),
                        ..ModelEntry::default()
                    }],
                    ..ProviderEntry::default()
                },
            );
        }
        // The endpoint fixture resumes a real ordinary worker.  Its immutable
        // agent receipt is independent of the ordinary session default, but
        // resume still requires one to construct a usable worker.
        providers.active_model = Some(ActiveModelRef {
            provider: "profile-a".into(),
            model: "exact-a".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        });
        providers
    }

    pub(crate) fn add_refreshed_offering(providers: &mut ProvidersConfig) {
        providers.providers.insert(
            "profile-refreshed".into(),
            ProviderEntry {
                template: Some("openai-compatible".into()),
                url: "http://127.0.0.1:9/v1".into(),
                models: vec![ModelEntry {
                    id: "compatible-after-refresh".into(),
                    context_length: Some(128),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
    }

    /// Materialize the normal project-local provider layer consumed by the
    /// production `ConfigSource`.  Provider entries deliberately live in the
    /// sibling `providers/` directory: inline entries in `config.json` are
    /// ignored by the long-term configuration grammar.
    pub(crate) fn write_workspace_provider_layer(
        workspace: &Path,
        providers: &ProvidersConfig,
    ) -> Result<()> {
        let config_path = workspace.join(".cockpit/config.json");
        std::fs::create_dir_all(
            config_path
                .parent()
                .context("workspace config path has no parent")?,
        )?;
        let layer_metadata = serde_json::json!({
            "active_model": &providers.active_model,
        });
        std::fs::write(&config_path, serde_json::to_vec(&layer_metadata)?)?;
        for (profile, entry) in &providers.providers {
            let provider_path =
                crate::config::providers::provider_file_path_for_config(&config_path, profile)?;
            std::fs::create_dir_all(
                provider_path
                    .parent()
                    .context("workspace provider path has no parent")?,
            )?;
            std::fs::write(provider_path, serde_json::to_vec(entry)?)?;
        }
        Ok(())
    }

    fn markdown(agent_id: &str, required_capability: &str) -> String {
        format!(
            "---\ndescription: setup fixture\nschemaVersion: 2\nagentId: {agent_id}\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 1\n    requiredCapabilities: [{required_capability}]\n    locality: any\n    allowDefaultFallback: false\n    suggestedModels:\n      - recommendationId: first\n        upstreamIdentity: upstream/first\n        providerAliases:\n          - providerId: openai-compatible\n            modelId: exact-a\n      - recommendationId: second\n        upstreamIdentity: upstream/second\n        providerAliases:\n          - providerId: openai-compatible\n            modelId: exact-b\n      - recommendationId: missing\n        upstreamIdentity: upstream/missing\n---\nfixture body\n"
        )
    }

    fn digest(name: &str, markdown: &str) -> Result<String> {
        let definition = crate::agents::parse_agent(
            markdown,
            name,
            PathBuf::from(format!("<{name}-session-setup-fixture>")),
        )?;
        Ok(sha256_hex(&definition.vnext_digest_bytes()?))
    }

    fn workspace_id(workspace: &Path) -> String {
        format!(
            "workspace:{}",
            sha256_hex(workspace.to_string_lossy().as_bytes())
        )
    }

    fn input(
        installation_id: Uuid,
        scope: AgentInstallationScope,
        canonical_workspace_id: Option<String>,
        name: &str,
        source_digest: String,
    ) -> AgentInstallationInput {
        AgentInstallationInput {
            installation_id,
            scope,
            canonical_workspace_id,
            source_agent_id: format!("authored/{name}"),
            source_identity: format!("fixture/repository:agents/{name}.md"),
            source_revision: Some("a".repeat(40)),
            source_digest,
            fetched_at_unix_ms: 1,
        }
    }

    async fn install_observe_and_maybe_bind(
        db: &Db,
        input: AgentInstallationInput,
        binding: Option<(&str, &str)>,
    ) -> Result<()> {
        let installation_id = input.installation_id;
        let definition_digest = input.source_digest.clone();
        ensure!(matches!(
            db.install_agent(input).await?,
            InstallAgentOutcome::Installed(_)
        ));
        ensure!(matches!(
            db.observe_agent_definition(installation_id, definition_digest.clone(), 2)
                .await?,
            ObserveAgentOutcome::Current(_)
        ));
        if let Some((profile_handle, model_id)) = binding {
            let provenance_payload = format!("fixture-provenance:{installation_id}").into_bytes();
            ensure!(matches!(
                db.bind_agent_model(
                    installation_id,
                    definition_digest,
                    None,
                    format!("fixture-bind-{installation_id}"),
                    "fixture-binding-request".into(),
                    AgentBindingInput {
                        slot_id: "primary".into(),
                        provider_profile_handle: profile_handle.into(),
                        model_id: model_id.into(),
                        provenance_digest: sha256_hex(&provenance_payload),
                        provenance_payload,
                        hard_capability_verified: true,
                        is_default: true,
                    },
                    3,
                )
                .await?,
                BindAgentOutcome::Bound(_)
            ));
        }
        Ok(())
    }

    /// Seed global, workspace-private, and workspace-shared collisions plus
    /// explicit stale and hard-capability-unavailable candidates.  The private
    /// candidate is selected through `prepare_agent_session`, not a raw SQL
    /// insertion, so callers exercise the exact durable profile boundary.
    pub(crate) async fn seed(
        db: &Db,
        daemon_agents_dir: &Path,
        workspace: &Path,
    ) -> Result<SessionSetupFixture> {
        let workspace = std::fs::canonicalize(workspace)
            .context("canonicalizing session-setup fixture workspace")?;
        std::fs::create_dir_all(workspace.join(".cockpit/agents"))?;
        let workspace_id = workspace_id(&workspace);
        let reviewer = markdown("authored/reviewer", "text_generation");
        let reviewer_digest = digest("reviewer", &reviewer)?;
        let unavailable = markdown("authored/unavailable", "tool_calling");
        let unavailable_digest = digest("unavailable", &unavailable)?;
        let stale_observed = markdown("authored/stale", "text_generation");
        let stale_observed_digest = digest("stale", &stale_observed)?;
        // The durable observation/binding records the reviewed definition,
        // while the owned file simulates an ordinary source update that has
        // not yet been rebound. This is the real stale path, rather than an
        // artificially incomplete installation row.
        let stale = stale_observed.replace("minContextTokens: 1", "minContextTokens: 2");

        let global_id = Uuid::now_v7();
        let selected_installation_id = Uuid::now_v7();
        let shared_id = Uuid::now_v7();
        let unavailable_id = Uuid::now_v7();
        let stale_id = Uuid::now_v7();

        for (path, bytes) in [
            (
                owned_path(
                    daemon_agents_dir,
                    None,
                    AgentInstallationScopeWire::Global,
                    "reviewer",
                )?,
                reviewer.as_bytes(),
            ),
            (
                owned_path(
                    daemon_agents_dir,
                    Some(&workspace),
                    AgentInstallationScopeWire::WorkspacePrivate,
                    "reviewer",
                )?,
                reviewer.as_bytes(),
            ),
            (
                owned_path(
                    daemon_agents_dir,
                    None,
                    AgentInstallationScopeWire::Global,
                    "unavailable",
                )?,
                unavailable.as_bytes(),
            ),
            (
                owned_path(
                    daemon_agents_dir,
                    None,
                    AgentInstallationScopeWire::Global,
                    "stale",
                )?,
                stale.as_bytes(),
            ),
        ] {
            write_owned_file_new(&path, bytes, "writing session-setup fixture definition")?;
        }
        std::fs::write(workspace.join(".cockpit/agents/reviewer.md"), &reviewer)?;

        install_observe_and_maybe_bind(
            db,
            input(
                global_id,
                AgentInstallationScope::Global,
                None,
                "reviewer",
                reviewer_digest.clone(),
            ),
            Some(("credential-profile-global", "exact-a")),
        )
        .await?;
        install_observe_and_maybe_bind(
            db,
            input(
                selected_installation_id,
                AgentInstallationScope::WorkspacePrivate,
                Some(workspace_id.clone()),
                "reviewer",
                reviewer_digest.clone(),
            ),
            Some((SELECTED_PROFILE_HANDLE, "exact-a")),
        )
        .await?;
        install_observe_and_maybe_bind(
            db,
            input(
                shared_id,
                AgentInstallationScope::WorkspaceShared,
                Some(workspace_id.clone()),
                "reviewer",
                reviewer_digest.clone(),
            ),
            Some(("credential-profile-shared", "exact-a")),
        )
        .await?;
        // A valid, observed definition whose requirement lacks hard evidence
        // must remain visible but non-selectable.
        install_observe_and_maybe_bind(
            db,
            input(
                unavailable_id,
                AgentInstallationScope::Global,
                None,
                "unavailable",
                unavailable_digest,
            ),
            None,
        )
        .await?;
        // A durable stale observation must not be silently replaced with a
        // current config choice.
        install_observe_and_maybe_bind(
            db,
            input(
                stale_id,
                AgentInstallationScope::Global,
                None,
                "stale",
                stale_observed_digest,
            ),
            Some(("credential-profile-stale", "exact-a")),
        )
        .await?;

        let selected = db
            .agent_installation(selected_installation_id)
            .await?
            .context("selected session-setup fixture installation disappeared")?;
        let observation = db
            .agent_observation(selected_installation_id)
            .await?
            .context("selected session-setup fixture observation disappeared")?;
        let binding = db
            .current_agent_binding(
                selected_installation_id,
                reviewer_digest.clone(),
                "primary".into(),
            )
            .await?
            .context("selected session-setup fixture binding disappeared")?;
        let profile = RedactedAgentProfileSnapshot {
            agent_id: "authored/reviewer".into(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: Vec::new(),
            question_policy: RedactedQuestionPolicy::Off,
            verification_regions: Vec::new(),
            bindings: vec![RedactedBindingEvidence {
                slot_id: "primary".into(),
                binding_revision: binding.binding_revision,
                provider_profile_handle: SELECTED_PROFILE_HANDLE.into(),
                model_id: "exact-a".into(),
                selected_provider_alias: ProviderAlias {
                    provider_id: "openai-compatible".into(),
                    model_id: "exact-a".into(),
                },
                provenance_digest: binding.provenance_digest.clone(),
                hard_capability_verified: true,
                is_default: true,
            }],
            child_bindings: Vec::new(),
        };
        let canonical_snapshot_payload = serde_json::to_vec(&profile)?;
        let binding_revision_map_payload = serde_json::to_vec(&AgentBindingRevisionMap {
            bindings: vec![AgentBindingRevision {
                slot_id: "primary".into(),
                provider_profile_handle: binding.provider_profile_handle.clone(),
                model_id: "test-model".into(),
                binding_revision: binding.binding_revision,
            }],
        })?;
        let session_id = Uuid::now_v7();
        ensure!(matches!(
            db.prepare_agent_session(PrepareAgentSessionInput {
                session_id,
                session_create: AgentSessionCreateInput {
                    project_id: "session-setup-fixture-project".into(),
                    project_root: workspace.to_string_lossy().into_owned(),
                    active_agent: "reviewer".into(),
                    started_at_unix_ms: 4,
                    last_active_at_unix_ms: 4,
                },
                existing_session_claim_token: None,
                idempotency_key: "session-setup-fixture-prepare".into(),
                request_fingerprint: "session-setup-fixture-prepare-v1".into(),
                installation_id: selected_installation_id,
                expected_installation_revision: selected.installation_revision,
                expected_observation_revision: observation.observation_revision,
                expected_definition_digest: reviewer_digest,
                expected_bindings: vec![AgentBindingExpectation {
                    slot_id: "primary".into(),
                    provider_profile_handle: binding.provider_profile_handle.clone(),
                    model_id: "test-model".into(),
                    expected_binding_revision: binding.binding_revision,
                }],
                expected_children: Vec::new(),
                snapshot_schema_version: 1,
                canonical_snapshot_digest: sha256_hex(&canonical_snapshot_payload),
                canonical_snapshot_payload,
                binding_revision_map_digest: sha256_hex(&binding_revision_map_payload),
                binding_revision_map_payload,
                now_unix_ms: 4,
            })
            .await?,
            PrepareAgentSessionOutcome::Prepared(_)
        ));
        Ok(SessionSetupFixture {
            session_id,
            selected_installation_id,
            workspace_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{
        AgentProfileModelOffering, ModelCapability, ModelLocality, ModelRecommendation, ModelSlot,
        ProviderAlias,
    };
    use cockpit_config::config::providers::{ModelEntry, ProviderEntry};
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RecordedGithubRequest {
        url: String,
        authorization: Option<String>,
        timeout: std::time::Duration,
    }

    struct ScriptedGithubTransport {
        responses: Mutex<VecDeque<GithubHttpResponse>>,
        requests: Mutex<Vec<RecordedGithubRequest>>,
    }

    impl ScriptedGithubTransport {
        fn new(responses: Vec<GithubHttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<RecordedGithubRequest> {
            std::mem::take(&mut *self.requests.lock().expect("request lock"))
        }
    }

    #[async_trait]
    impl GithubHttpTransport for ScriptedGithubTransport {
        async fn get(&self, request: GithubHttpRequest) -> Result<GithubHttpResponse> {
            self.requests
                .lock()
                .expect("request lock")
                .push(RecordedGithubRequest {
                    url: request.url,
                    authorization: request.authorization,
                    timeout: request.timeout,
                });
            self.responses
                .lock()
                .expect("response lock")
                .pop_front()
                .context("unexpected GitHub HTTP request")
        }
    }

    fn github_response(
        status: u16,
        content_length: Option<u64>,
        chunks: Vec<Vec<u8>>,
    ) -> GithubHttpResponse {
        GithubHttpResponse {
            status,
            content_length,
            body: futures::stream::iter(chunks.into_iter().map(Ok)).boxed(),
        }
    }

    fn github_commit_response(sha: &str) -> GithubHttpResponse {
        github_response(
            200,
            None,
            vec![format!(r#"{{"sha":"{sha}"}}"#).into_bytes()],
        )
    }

    fn github_source() -> CanonicalAgentSource {
        CanonicalAgentSource::parse("owner/repository@release-1:agents/helper.md")
            .expect("canonical GitHub source")
    }

    #[tokio::test]
    async fn agent_installation_daemon_github_fetcher_pins_commit_uses_timeout_and_keeps_auth_out_of_output()
     {
        let sha = "b".repeat(40);
        let transport = Arc::new(ScriptedGithubTransport::new(vec![
            github_commit_response(&sha),
            github_response(200, Some(5), vec![b"hello".to_vec()]),
        ]));
        let secret = "github-private-token-not-persisted";
        let fetcher =
            GithubHttpsAgentFetcher::with_transport(transport.clone(), Some(secret.to_owned()));

        let fetched = fetcher
            .fetch_github_markdown(&github_source())
            .await
            .expect("pinned fetch succeeds");
        assert_eq!(fetched.commit_sha, sha);
        assert_eq!(fetched.markdown, b"hello");
        assert!(!format!("{fetched:?}").contains(secret));

        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].url,
            "https://api.github.com/repos/owner/repository/commits/release-1"
        );
        assert_eq!(
            requests[1].url,
            format!("https://raw.githubusercontent.com/owner/repository/{sha}/agents/helper.md")
        );
        for request in &requests {
            assert_eq!(
                request.authorization.as_deref(),
                Some(format!("Bearer {secret}").as_str())
            );
            assert_eq!(request.timeout, GITHUB_FETCH_TIMEOUT);
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_github_fetcher_rejects_redirects_without_leaking_auth() {
        let sha = "c".repeat(40);
        let secret = "github-redirect-token";
        let transport = Arc::new(ScriptedGithubTransport::new(vec![
            github_commit_response(&sha),
            github_response(302, Some(0), vec![]),
        ]));
        let fetcher =
            GithubHttpsAgentFetcher::with_transport(transport.clone(), Some(secret.to_owned()));

        let error = fetcher
            .fetch_github_markdown(&github_source())
            .await
            .expect_err("redirect must not be followed");
        assert!(
            error
                .to_string()
                .contains("GitHub agent source authorization or fetch failed")
        );
        assert!(!format!("{error:#}").contains(secret));
        assert_eq!(transport.requests().len(), 2);
    }

    #[tokio::test]
    async fn agent_installation_daemon_github_fetcher_enforces_content_length_and_stream_hard_caps()
    {
        let sha = "d".repeat(40);
        let declared_oversize = GithubHttpsAgentFetcher::with_transport(
            Arc::new(ScriptedGithubTransport::new(vec![
                github_commit_response(&sha),
                github_response(200, Some(MAX_AGENT_MARKDOWN_BYTES as u64 + 1), vec![]),
            ])),
            None,
        );
        let error = declared_oversize
            .fetch_github_markdown(&github_source())
            .await
            .expect_err("Content-Length above 1MiB must reject before body read");
        assert!(error.to_string().contains("exceeds 1MiB"));

        let streamed_oversize = GithubHttpsAgentFetcher::with_transport(
            Arc::new(ScriptedGithubTransport::new(vec![
                github_commit_response(&sha),
                github_response(
                    200,
                    None,
                    vec![vec![b'x'; MAX_AGENT_MARKDOWN_BYTES], vec![b'y']],
                ),
            ])),
            None,
        );
        let error = streamed_oversize
            .fetch_github_markdown(&github_source())
            .await
            .expect_err("stream crossing 1MiB must reject");
        assert!(error.to_string().contains("exceeds 1MiB"));
    }

    #[tokio::test]
    async fn agent_installation_daemon_github_fetcher_accepts_exactly_one_mib() {
        let sha = "e".repeat(40);
        let fetcher = GithubHttpsAgentFetcher::with_transport(
            Arc::new(ScriptedGithubTransport::new(vec![
                github_commit_response(&sha),
                github_response(
                    200,
                    Some(MAX_AGENT_MARKDOWN_BYTES as u64),
                    vec![vec![b'x'; MAX_AGENT_MARKDOWN_BYTES]],
                ),
            ])),
            None,
        );
        let fetched = fetcher
            .fetch_github_markdown(&github_source())
            .await
            .expect("exactly 1MiB is permitted");
        assert_eq!(fetched.commit_sha, sha);
        assert_eq!(fetched.markdown.len(), MAX_AGENT_MARKDOWN_BYTES);
    }

    #[derive(Clone)]
    enum FetchReply {
        Source(FetchedAgentSource),
        Failure(String),
    }

    #[derive(Clone)]
    struct MockFetcher {
        reply: Arc<Mutex<FetchReply>>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl AgentInstallationFetcher for MockFetcher {
        async fn fetch_github_markdown(
            &self,
            _source: &CanonicalAgentSource,
        ) -> Result<FetchedAgentSource> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.reply.lock().expect("mock fetcher lock").clone() {
                FetchReply::Source(source) => Ok(source),
                FetchReply::Failure(message) => bail!(message),
            }
        }
    }

    #[derive(Clone)]
    struct MockWorkspaceAuthorizer {
        root: PathBuf,
        allowed: bool,
    }

    #[async_trait]
    impl AgentWorkspaceAuthorizer for MockWorkspaceAuthorizer {
        async fn authorize_workspace(&self, client_path: &str) -> Result<(String, PathBuf)> {
            ensure!(
                self.allowed && client_path == "workspace-request",
                "mock workspace denied"
            );
            Ok(("workspace:test".into(), self.root.clone()))
        }
    }

    /// A deterministic daemon-service harness.  It supplies a source fetcher
    /// and workspace authority at the daemon boundary, so these tests never
    /// touch GitHub, a credential store, the caller's filesystem, or timing.
    struct ServiceHarness {
        _root: tempfile::TempDir,
        db: Db,
        service: AgentInstallationService,
        fetcher: MockFetcher,
    }

    impl ServiceHarness {
        fn new(reply: FetchReply) -> Self {
            Self::with_providers(reply, ProvidersConfig::default())
        }

        fn with_providers(reply: FetchReply, providers: ProvidersConfig) -> Self {
            let root = tempfile::tempdir().expect("temporary daemon root");
            let fetcher = MockFetcher {
                reply: Arc::new(Mutex::new(reply)),
                calls: Arc::new(AtomicUsize::new(0)),
            };
            let db = Db::open_in_memory().expect("test DB");
            let service = AgentInstallationService::new(
                db.clone(),
                root.path().join("daemon-agents"),
                Arc::new(fetcher.clone()),
                Arc::new(MockWorkspaceAuthorizer {
                    root: root.path().join("workspace"),
                    allowed: true,
                }),
                providers,
            );
            Self {
                _root: root,
                db,
                service,
                fetcher,
            }
        }

        fn request(key: &str) -> AgentInstallationBeginV1 {
            AgentInstallationBeginV1 {
                dto_version: AGENT_INSTALLATION_DTO_VERSION,
                idempotency_key: key.into(),
                operation: AgentInstallationOperationKind::Install,
                scope: AgentInstallationScopeWire::Global,
                workspace_path: None,
                source_locator: "owner/repo@main:agents/helper.md".into(),
                target_installation_id: None,
                replace_acknowledged: false,
                requested_slot: None,
                execution_kind: None,
                primary_slot_id: None,
                auto_select_first_exact: false,
            }
        }

        fn fetched() -> FetchedAgentSource {
            FetchedAgentSource {
                commit_sha: "a".repeat(40),
                markdown: b"---\ndescription: helper\nschemaVersion: 2\nagentId: authored/helper\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\nbody\n".to_vec(),
            }
        }

        fn target(&self) -> PathBuf {
            self._root.path().join("daemon-agents/helper.md")
        }
    }

    fn binding_providers() -> ProvidersConfig {
        let mut providers = ProvidersConfig::default();
        for (profile, provider_id, model_id) in [
            ("profile-a", "vendor", "exact-a"),
            ("profile-b", "vendor", "exact-b"),
            ("profile-local", "local", "compatible"),
        ] {
            let entry = ProviderEntry {
                template: Some(provider_id.into()),
                models: vec![ModelEntry {
                    id: model_id.into(),
                    context_length: Some(128),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            };
            providers.providers.insert(profile.into(), entry);
        }
        providers
    }

    fn fetched_with_binding_choices(required_capability: &str) -> FetchedAgentSource {
        FetchedAgentSource {
            commit_sha: "b".repeat(40),
            markdown: format!(
                "---\ndescription: helper\nschemaVersion: 2\nagentId: authored/helper\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 1\n    requiredCapabilities: [{required_capability}]\n    locality: any\n    allowDefaultFallback: false\n    suggestedModels:\n      - recommendationId: first\n        upstreamIdentity: upstream/first\n        providerAliases:\n          - providerId: vendor\n            modelId: exact-a\n      - recommendationId: second\n        upstreamIdentity: upstream/second\n        providerAliases:\n          - providerId: vendor\n            modelId: exact-b\n      - recommendationId: missing\n        upstreamIdentity: upstream/missing\n  optional:\n    purpose: optional\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n    suggestedModels:\n      - recommendationId: first\n        upstreamIdentity: upstream/first\n        providerAliases:\n          - providerId: vendor\n            modelId: exact-a\n---\nbody\n"
            )
            .into_bytes(),
        }
    }

    fn fetched_definition_digest(fetched: &FetchedAgentSource) -> String {
        let markdown = std::str::from_utf8(&fetched.markdown).expect("fixture utf8");
        let definition =
            crate::agents::parse_agent(markdown, "helper", PathBuf::from("fixture.md"))
                .expect("fixture definition");
        sha256_hex(&definition.vnext_digest_bytes().expect("fixture digest"))
    }

    #[test]
    fn agent_installation_daemon_update_target_is_part_of_the_idempotency_fingerprint() {
        let mut first = ServiceHarness::request("update-target-fingerprint");
        first.operation = AgentInstallationOperationKind::Update;
        first.target_installation_id = Some("00000000-0000-0000-0000-000000000001".into());
        let mut second = first.clone();
        second.target_installation_id = Some("00000000-0000-0000-0000-000000000002".into());
        assert_ne!(
            request_fingerprint(&first, None),
            request_fingerprint(&second, None)
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_update_without_target_refuses_before_fetch_or_mutation() {
        let harness = ServiceHarness::new(FetchReply::Failure("must not fetch".into()));
        let mut request = ServiceHarness::request("update-requires-target");
        request.operation = AgentInstallationOperationKind::Update;
        request.replace_acknowledged = true;
        let AgentInstallationResultV1::Error { error } = harness.service.begin(request, 1).await
        else {
            panic!("update without durable target must be refused")
        };
        assert_eq!(error.code, AgentInstallationErrorCodeV1::InvalidRequest);
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn agent_installation_daemon_invalid_manifest_is_typed_and_creates_no_operation_or_file()
    {
        let harness = ServiceHarness::new(FetchReply::Source(FetchedAgentSource {
            commit_sha: "d".repeat(40),
            markdown: b"---\ndescription: invalid\nschemaVersion: 2\nagentId: authored/helper\nexecutionKind: coding\n---\nmissing slots\n".to_vec(),
        }));
        let result = harness
            .service
            .begin(ServiceHarness::request("invalid-manifest"), 1)
            .await;
        assert!(matches!(
            result,
            AgentInstallationResultV1::Error { error }
                if error.code == AgentInstallationErrorCodeV1::InvalidDefinition
        ));
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 1);
        assert!(
            harness
                .db
                .installation_operation("invalid-manifest".into())
                .await
                .expect("read invalid manifest operation")
                .is_none()
        );
        assert!(
            harness
                .db
                .list_agent_installations(AgentInstallationScope::Global, None)
                .await
                .expect("list invalid manifest installations")
                .is_empty()
        );
        assert!(!harness.target().exists());
    }

    #[tokio::test]
    async fn agent_installation_daemon_atomic_begin_replays_pinned_source_after_crash_without_refetch()
     {
        let harness = ServiceHarness::new(FetchReply::Source(ServiceHarness::fetched()));
        let request = ServiceHarness::request("atomic-begin-crash");
        let fetched = ServiceHarness::fetched();
        let (staged_file_metadata_json, expected_digest) =
            staged_source_journal_metadata(&request.source_locator, &fetched)
                .expect("serialize pinned staged source");
        let BeginInstallationOperation::Created(operation) = harness
            .db
            .begin_installation_operation_with_staged_journal(
                request.idempotency_key.clone(),
                request_fingerprint(&request, None),
                InstallationOperationKind::Install,
                None,
                staged_file_metadata_json,
                expected_digest,
                1,
            )
            .await
            .expect("atomic operation and journal")
        else {
            panic!("fixture must create an operation")
        };
        assert!(
            harness
                .db
                .installation_journal(operation.operation_id)
                .await
                .expect("read atomic journal")
                .is_some(),
            "there is no operation-created/journal-not-separate crash state"
        );
        *harness.fetcher.reply.lock().expect("fetcher reply") =
            FetchReply::Failure("moving ref must not be consulted on recovery".into());
        let result = harness.service.begin(request, 99).await;
        assert!(matches!(
            result,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Installed,
                source_revision: Some(ref revision),
                ..
            } if revision == &"a".repeat(40)
        ));
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn agent_installation_daemon_update_rejects_mismatched_target_without_mutation() {
        let harness = ServiceHarness::new(FetchReply::Failure("must not fetch".into()));
        let installation_id = Uuid::new_v4();
        harness
            .db
            .install_agent(AgentInstallationInput {
                installation_id,
                scope: AgentInstallationScope::Global,
                canonical_workspace_id: None,
                source_agent_id: "authored/helper".into(),
                source_identity: "owner/other:agents/helper.md".into(),
                source_revision: Some("b".repeat(40)),
                source_digest: "c".repeat(64),
                fetched_at_unix_ms: 1,
            })
            .await
            .expect("seed mismatched target");
        let mut request = ServiceHarness::request("update-target-mismatch");
        request.operation = AgentInstallationOperationKind::Update;
        request.target_installation_id = Some(installation_id.to_string());
        request.replace_acknowledged = true;
        let AgentInstallationResultV1::Error { error } = harness.service.begin(request, 2).await
        else {
            panic!("mismatched update target must be refused")
        };
        assert_eq!(error.code, AgentInstallationErrorCodeV1::InvalidRequest);
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
        assert!(
            harness
                .db
                .installation_operation("update-target-mismatch".into())
                .await
                .expect("read operation")
                .is_none(),
            "a mismatched target must not create an operation row"
        );
        assert_eq!(
            harness
                .db
                .agent_installation(installation_id)
                .await
                .expect("read target")
                .expect("target remains")
                .source_identity,
            "owner/other:agents/helper.md"
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_create_uses_authored_identity_and_refuses_collision() {
        let harness = ServiceHarness::new(FetchReply::Failure("create does not fetch".into()));
        let mut request = ServiceHarness::request("create-authored");
        request.operation = AgentInstallationOperationKind::Create;
        request.source_locator = "authored/new-helper".into();
        request.execution_kind = Some(AgentInstallationExecutionKindV1::Coding);
        request.primary_slot_id = Some("primary".into());
        let AgentInstallationResultV1::Receipt {
            status: AgentInstallationReceiptStatusV1::Created,
            installation_id: Some(installation_id),
            ..
        } = harness.service.begin(request, 1).await
        else {
            panic!("daemon create must accept authored/NAME")
        };
        assert!(Uuid::parse_str(&installation_id).is_ok());
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);

        let mut collision = ServiceHarness::request("create-authored-collision");
        collision.operation = AgentInstallationOperationKind::Create;
        collision.source_locator = "authored/new-helper".into();
        collision.execution_kind = Some(AgentInstallationExecutionKindV1::Coding);
        collision.primary_slot_id = Some("primary".into());
        let AgentInstallationResultV1::Error { error } = harness.service.begin(collision, 2).await
        else {
            panic!("same scope authored identity must not overwrite")
        };
        assert_eq!(error.code, AgentInstallationErrorCodeV1::Collision);
    }

    #[tokio::test]
    async fn agent_installation_daemon_bind_matrix_preserves_suggestions_allows_local_and_handles_defer_and_rebind()
     {
        let harness = ServiceHarness::with_providers(
            FetchReply::Source(fetched_with_binding_choices("text_generation")),
            binding_providers(),
        );
        let AgentInstallationResultV1::Receipt {
            installation_id: Some(installation_id),
            ..
        } = harness
            .service
            .begin(ServiceHarness::request("bind-matrix-install"), 1)
            .await
        else {
            panic!("scripted install must create an installation")
        };

        let bind = |key: &str, slot: &str| AgentInstallationBeginV1 {
            idempotency_key: key.into(),
            operation: AgentInstallationOperationKind::Bind,
            source_locator: installation_id.clone(),
            requested_slot: Some(slot.into()),
            ..ServiceHarness::request(key)
        };
        let AgentInstallationResultV1::NeedsChoice {
            continuation_token,
            choices,
            unmatched_recommendations,
            ..
        } = harness
            .service
            .begin(bind("bind-local", "primary"), 2)
            .await
        else {
            panic!("compatible routes must require a daemon choice")
        };
        assert_eq!(
            choices
                .iter()
                .map(|choice| choice.recommendation_id.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("first"), Some("second"), None]
        );
        assert!(choices[0].exact_alias_match && choices[0].author_suggested);
        assert!(choices[1].exact_alias_match && choices[1].author_suggested);
        assert!(!choices[2].author_suggested && !choices[2].exact_alias_match);
        assert_eq!(
            unmatched_recommendations[0].canonical_upstream_identity,
            "upstream/missing"
        );
        let local_choice = choices[2].choice_id.clone();
        assert!(matches!(
            harness
                .service
                .submit_choice(
                    AgentInstallationSubmitChoiceV1 {
                        dto_version: AGENT_INSTALLATION_DTO_VERSION,
                        continuation_token,
                        choice_id: Some(local_choice),
                        defer: false,
                    },
                    3,
                )
                .await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Bound,
                ..
            }
        ));

        let AgentInstallationResultV1::NeedsChoice {
            continuation_token,
            choices,
            ..
        } = harness
            .service
            .begin(bind("bind-rebind", "primary"), 4)
            .await
        else {
            panic!("rebind must create a fresh daemon choice")
        };
        assert!(matches!(
            harness
                .service
                .submit_choice(
                    AgentInstallationSubmitChoiceV1 {
                        dto_version: AGENT_INSTALLATION_DTO_VERSION,
                        continuation_token,
                        choice_id: Some(choices[1].choice_id.clone()),
                        defer: false,
                    },
                    5,
                )
                .await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Bound,
                ..
            }
        ));

        for (key, slot, status) in [
            (
                "bind-defer-optional",
                "optional",
                AgentInstallationReceiptStatusV1::OptionalUnbound,
            ),
            (
                "bind-defer-primary",
                "primary",
                AgentInstallationReceiptStatusV1::PrimaryUnusable,
            ),
        ] {
            let AgentInstallationResultV1::NeedsChoice {
                continuation_token, ..
            } = harness.service.begin(bind(key, slot), 6).await
            else {
                panic!("{slot} must offer a deferrable choice")
            };
            assert!(matches!(
                harness
                    .service
                    .submit_choice(
                        AgentInstallationSubmitChoiceV1 {
                            dto_version: AGENT_INSTALLATION_DTO_VERSION,
                            continuation_token,
                            choice_id: None,
                            defer: true,
                        },
                        7,
                    )
                    .await,
                AgentInstallationResultV1::Receipt { status: actual, .. } if actual == status
            ));
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_bind_refuses_unknown_hard_capability_without_mutating_bindings()
     {
        let harness = ServiceHarness::with_providers(
            FetchReply::Source(fetched_with_binding_choices("tool_calling")),
            binding_providers(),
        );
        let AgentInstallationResultV1::Receipt {
            installation_id: Some(installation_id),
            ..
        } = harness
            .service
            .begin(ServiceHarness::request("unknown-capability-install"), 1)
            .await
        else {
            panic!("install must succeed before the bind check")
        };
        let result = harness
            .service
            .begin(
                AgentInstallationBeginV1 {
                    idempotency_key: "unknown-capability-bind".into(),
                    operation: AgentInstallationOperationKind::Bind,
                    source_locator: installation_id,
                    requested_slot: Some("primary".into()),
                    ..ServiceHarness::request("unknown-capability-bind")
                },
                2,
            )
            .await;
        assert!(matches!(
            result,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::PrimaryUnusable,
                ..
            }
        ));
        assert_eq!(
            harness
                .db
                .read(|conn| {
                    Ok(
                        conn.query_row("SELECT COUNT(*) FROM agent_model_bindings", [], |row| {
                            row.get::<_, i64>(0)
                        })?,
                    )
                })
                .await
                .expect("binding count"),
            0
        );
    }

    fn slot(
        required: Vec<ModelCapability>,
        recommendations: Vec<ModelRecommendation>,
    ) -> ModelSlot {
        ModelSlot {
            purpose: "fixture slot".into(),
            min_context_tokens: 8,
            required_capabilities: required,
            locality: ModelLocality::Any,
            allow_default_fallback: false,
            suggested_models: recommendations,
            models: Vec::new(),
        }
    }

    fn recommendation(id: &str, upstream: &str, aliases: &[(&str, &str)]) -> ModelRecommendation {
        ModelRecommendation {
            recommendation_id: id.into(),
            upstream_identity: upstream.into(),
            provider_aliases: aliases
                .iter()
                .map(|(provider_id, model_id)| ProviderAlias {
                    provider_id: (*provider_id).into(),
                    model_id: (*model_id).into(),
                })
                .collect(),
            author_label: Some(format!("label-{id}")),
            rationale: Some(format!("why-{id}")),
        }
    }

    fn providers_for(offerings: &[AgentProfileModelOffering]) -> ProvidersConfig {
        let mut providers = ProvidersConfig::default();
        for offering in offerings {
            providers
                .providers
                .entry(offering.provider_id.clone())
                .or_insert_with(ProviderEntry::default)
                .models
                .push(ModelEntry {
                    id: offering.model_id.clone(),
                    context_length: Some(128),
                    ..ModelEntry::default()
                });
        }
        providers
    }

    async fn prepare_recovery_checkpoint(
        harness: &ServiceHarness,
        request: &AgentInstallationBeginV1,
        checkpoint: InstallationJournalCheckpoint,
    ) -> Uuid {
        let operation = match harness
            .db
            .begin_installation_operation(
                request.idempotency_key.clone(),
                request_fingerprint(request, None),
                InstallationOperationKind::Install,
                None,
                1,
            )
            .await
            .expect("begin operation")
        {
            BeginInstallationOperation::Created(operation) => operation,
            _ => panic!("expected fresh operation"),
        };
        let fetched = ServiceHarness::fetched();
        let digest = sha256_hex(&fetched.markdown);
        let target = harness.target();
        stage_file(&target, operation.operation_id, &fetched.markdown).expect("stage fixture");
        let journal = InstallationJournalRow {
            journal_id: Uuid::new_v4(),
            operation_id: operation.operation_id,
            checkpoint: InstallationJournalCheckpoint::Staged,
            staged_file_metadata_json: Some(
                serde_json::to_string(&JournalStagedSource {
                    target_name: "helper".into(),
                    digest: digest.clone(),
                    commit_sha: fetched.commit_sha.clone(),
                    markdown_base64: base64::engine::general_purpose::STANDARD
                        .encode(&fetched.markdown),
                })
                .expect("staged source metadata"),
            ),
            prior_file_metadata_json: None,
            expected_digest: digest,
        };
        harness
            .db
            .record_installation_journal(journal.clone(), 2)
            .await
            .expect("staged journal");
        if checkpoint_rank(checkpoint)
            >= checkpoint_rank(InstallationJournalCheckpoint::DbCommitted)
        {
            harness
                .db
                .install_agent(AgentInstallationInput {
                    installation_id: operation.operation_id,
                    scope: AgentInstallationScope::Global,
                    canonical_workspace_id: None,
                    source_agent_id: "authored/helper".into(),
                    source_identity: "owner/repo:agents/helper.md".into(),
                    source_revision: Some(fetched.commit_sha.clone()),
                    source_digest: fetched_definition_digest(&fetched),
                    fetched_at_unix_ms: 1,
                })
                .await
                .expect("fixture installation");
            harness
                .db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::DbCommitted,
                        ..journal.clone()
                    },
                    3,
                )
                .await
                .expect("DB checkpoint");
        }
        if checkpoint_rank(checkpoint)
            >= checkpoint_rank(InstallationJournalCheckpoint::FileRenamed)
        {
            publish_stage(
                &target,
                operation.operation_id,
                &sha256_hex(&fetched.markdown),
                false,
            )
            .expect("publish fixture");
            harness
                .db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::FileRenamed,
                        ..journal
                    },
                    4,
                )
                .await
                .expect("rename checkpoint");
        }
        operation.operation_id
    }

    async fn prepare_pending_choice(
        harness: &ServiceHarness,
        key: &str,
        expires_at_unix_ms: i64,
        requested_operation: AgentInstallationOperationKind,
        auto: bool,
    ) -> (AgentInstallationBeginV1, Uuid, Uuid, String) {
        let installation_id = Uuid::new_v4();
        let definition_digest = "d".repeat(64);
        harness
            .db
            .install_agent(AgentInstallationInput {
                installation_id,
                scope: AgentInstallationScope::Global,
                canonical_workspace_id: None,
                source_agent_id: "authored/helper".into(),
                source_identity: "owner/repo:agents/helper.md".into(),
                source_revision: Some("a".repeat(40)),
                source_digest: definition_digest.clone(),
                fetched_at_unix_ms: 1,
            })
            .await
            .expect("fixture installation");
        let mut replay_request = ServiceHarness::request(key);
        replay_request.operation = requested_operation;
        replay_request.auto_select_first_exact = auto;
        if requested_operation == AgentInstallationOperationKind::Bind {
            replay_request.source_locator = installation_id.to_string();
        }
        let operation = match harness
            .db
            .begin_installation_operation(
                key.into(),
                request_fingerprint(&replay_request, None),
                operation_kind(requested_operation),
                None,
                1,
            )
            .await
            .expect("begin choice operation")
        {
            BeginInstallationOperation::Created(operation) => operation,
            _ => panic!("expected fresh choice operation"),
        };
        let choice_id = "choice-exact".to_owned();
        let choice_set = BindChoiceSet {
            installation_id: installation_id.to_string(),
            definition_digest,
            expected_observation_revision: 1,
            expected_binding_revision: None,
            choices: vec![AgentInstallationChoiceV1 {
                choice_id: choice_id.clone(),
                slot_id: "primary".into(),
                offering_id: "local-route".into(),
                provider_id: "display-provider".into(),
                model_id: "model".into(),
                recommendation_id: Some("author-default".into()),
                canonical_upstream_identity: Some("upstream/model".into()),
                author_label: None,
                rationale: None,
                author_suggested: true,
                exact_alias_match: true,
            }],
            unmatched_recommendations: vec![],
            routes: vec![DurableBindingRoute {
                choice_id: choice_id.clone(),
                slot_id: "primary".into(),
                model_id: "model".into(),
                provider_profile_handle: "opaque-profile-handle".into(),
                authored_default: false,
            }],
            authored_default_required: false,
            parent_receipt_status: match requested_operation {
                AgentInstallationOperationKind::Install => {
                    Some(AgentInstallationReceiptStatusV1::Installed)
                }
                AgentInstallationOperationKind::Update => {
                    Some(AgentInstallationReceiptStatusV1::Updated)
                }
                AgentInstallationOperationKind::Bind | AgentInstallationOperationKind::Create => {
                    None
                }
            },
            parent_source_revision: matches!(
                requested_operation,
                AgentInstallationOperationKind::Install | AgentInstallationOperationKind::Update
            )
            .then(|| "a".repeat(40)),
            auto_choice_id: auto.then_some(choice_id.clone()),
        };
        let continuation = harness
            .db
            .create_installation_continuation(
                operation.operation_id,
                serde_json::to_string(&choice_set).expect("choice set JSON"),
                expires_at_unix_ms,
                1,
            )
            .await
            .expect("choice continuation");
        (
            replay_request,
            operation.operation_id,
            continuation.continuation_token,
            choice_id,
        )
    }
    #[test]
    fn agent_installation_daemon_source_parser_refuses_urls_traversal_and_non_markdown() {
        assert!(CanonicalAgentSource::parse("owner/repo@main:agents/helper.md").is_ok());
        for source in [
            "https://github.com/owner/repo:a.md",
            "owner/repo:../a.md",
            "owner/repo:a.txt",
            "owner/repo:a.md:extra",
            "owner/repo@main/next:agents/helper.md",
            "owner/repo@main?ref=x:agents/helper.md",
            "owner/repo@main%2fnext:agents/helper.md",
            "owner/repo:agents/helper?.md",
        ] {
            assert!(CanonicalAgentSource::parse(source).is_err(), "{source}");
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_refuses_source_filename_and_agent_id_mismatch() {
        let mut fetched = ServiceHarness::fetched();
        fetched.markdown = String::from_utf8(fetched.markdown)
            .expect("fixture UTF-8")
            .replace("agentId: authored/helper", "agentId: authored/different")
            .into_bytes();
        let harness = ServiceHarness::new(FetchReply::Source(fetched));
        let AgentInstallationResultV1::Error { error } = harness
            .service
            .begin(ServiceHarness::request("different-filename"), 1)
            .await
        else {
            panic!("filename mismatch must be refused")
        };
        assert_eq!(error.code, AgentInstallationErrorCodeV1::InvalidRequest);
    }
    #[test]
    fn agent_installation_daemon_template_is_minimal_and_provider_free() {
        let template = minimal_template(
            "helper",
            AgentInstallationExecutionKindV1::Coding,
            "primary",
        );
        assert!(template.contains("agentId: authored/helper"));
        assert!(!template.contains("provider"));
        assert!(!template.contains("credential"));
    }

    #[test]
    fn agent_installation_daemon_redacts_fetch_and_workspace_failures() {
        for detail in [
            "fetch failed: Bearer ghp_secret_value",
            "workspace authorization failed for /private/workspace",
        ] {
            let AgentInstallationResultV1::Error { error } =
                redacted_error(anyhow::anyhow!(detail))
            else {
                panic!("expected redacted error")
            };
            assert!(!error.message.contains("ghp_secret_value"));
            assert!(!error.message.contains("/private/workspace"));
        }
    }

    #[test]
    fn agent_installation_daemon_classifies_fetched_definitions_before_generic_fetches() {
        for (detail, expected) in [
            (
                "fetching GitHub agent source: invalid fetched AgentDef: modelSlots is required",
                AgentInstallationErrorCodeV1::InvalidDefinition,
            ),
            (
                "source Markdown path has no agent filename",
                AgentInstallationErrorCodeV1::InvalidRequest,
            ),
            (
                "update source AgentDef identity does not match target installation",
                AgentInstallationErrorCodeV1::InvalidRequest,
            ),
            (
                "fetching GitHub agent source: remote response failed",
                AgentInstallationErrorCodeV1::FetchFailed,
            ),
        ] {
            let AgentInstallationResultV1::Error { error } =
                redacted_error(anyhow::anyhow!(detail))
            else {
                panic!("expected typed installation refusal")
            };
            assert_eq!(
                error.code, expected,
                "unexpected classification for {detail}"
            );
        }
    }

    #[test]
    fn agent_installation_daemon_replacement_backup_names_are_operation_scoped() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("helper.md");
        let first = prior_backup_path(&target, Uuid::nil()).unwrap();
        let second = prior_backup_path(&target, Uuid::new_v4()).unwrap();
        assert_ne!(first, second);
        assert!(
            first
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".prior")
        );
    }

    #[cfg(unix)]
    #[test]
    fn agent_installation_daemon_owned_file_helpers_refuse_leaf_and_ancestor_symlink_swaps() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        let parent = root.path().join("agents");
        std::fs::create_dir_all(&parent).expect("parent");
        let target = parent.join("helper.md");
        std::fs::write(outside.path().join("helper.md"), "outside").expect("outside file");
        symlink(outside.path().join("helper.md"), &target).expect("leaf symlink");
        assert!(read_owned_file(&target, "test").is_err());
        std::fs::remove_file(&target).expect("remove leaf link");
        let moved = root.path().join("agents-old");
        std::fs::rename(&parent, &moved).expect("move parent");
        symlink(outside.path(), &parent).expect("ancestor symlink");
        assert!(write_owned_file_new(&target, b"owned", "test").is_err());
    }

    #[tokio::test]
    async fn agent_installation_daemon_mocked_fetch_private_auth_and_workspace_mismatch_are_redacted()
     {
        let harness = ServiceHarness::new(FetchReply::Failure(
            "private GitHub authorization rejected Bearer ghp_never_return_this".into(),
        ));
        let result = harness
            .service
            .begin(ServiceHarness::request("private"), 1)
            .await;
        let AgentInstallationResultV1::Error { error } = result else {
            panic!("private fetch must fail")
        };
        assert_eq!(
            error.code,
            AgentInstallationErrorCodeV1::PrivateSourceUnauthorized
        );
        assert!(!error.message.contains("ghp_never_return_this"));

        let denied = AgentInstallationService::new(
            harness.db.clone(),
            harness._root.path().join("other-agents"),
            Arc::new(harness.fetcher.clone()),
            Arc::new(MockWorkspaceAuthorizer {
                root: harness._root.path().join("workspace"),
                allowed: false,
            }),
            ProvidersConfig::default(),
        );
        let mut request = ServiceHarness::request("workspace-mismatch");
        request.scope = AgentInstallationScopeWire::WorkspaceShared;
        request.workspace_path = Some("workspace-request".into());
        let AgentInstallationResultV1::Error { error } = denied.begin(request, 2).await else {
            panic!("workspace mismatch must fail")
        };
        assert_eq!(
            error.code,
            AgentInstallationErrorCodeV1::UnauthorizedWorkspace
        );
        assert!(!error.message.contains("workspace-request"));
    }

    #[tokio::test]
    async fn agent_installation_daemon_local_workspace_authorizer_refuses_unlisted_root() {
        let allowed = tempfile::tempdir().expect("allowed workspace");
        let denied = tempfile::tempdir().expect("unlisted workspace");
        let authorizer = LocalDaemonWorkspaceAuthorizer::new(vec![allowed.path().to_path_buf()])
            .expect("authorizer");
        assert!(
            authorizer
                .authorize_workspace(denied.path().to_string_lossy().as_ref())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn modes_session_setup_workspace_identity_is_canonical_and_fails_closed_for_missing_roots()
     {
        let allowed = tempfile::tempdir().expect("allowed workspace");
        let authorizer = LocalDaemonWorkspaceAuthorizer::new(vec![allowed.path().to_path_buf()])
            .expect("authorizer");
        let (canonical_id, canonical_root) = authorizer
            .authorize_workspace(allowed.path().to_string_lossy().as_ref())
            .await
            .expect("canonical root is authorized");
        let (dot_id, dot_root) = authorizer
            .authorize_workspace(allowed.path().join(".").to_string_lossy().as_ref())
            .await
            .expect("dot spelling is canonicalized");
        assert_eq!(dot_id, canonical_id);
        assert_eq!(dot_root, canonical_root);
        assert!(
            authorizer
                .authorize_workspace(allowed.path().join("missing").to_string_lossy().as_ref())
                .await
                .is_err()
        );
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn modes_session_setup_workspace_identity_ignores_mutable_directory_state() {
        let workspace = tempfile::tempdir().expect("workspace");
        let authorizer = LocalDaemonWorkspaceAuthorizer::new(vec![workspace.path().to_path_buf()])
            .expect("authorizer");
        let workspace_path = workspace.path().to_string_lossy().into_owned();

        std::fs::write(workspace.path().join("ordinary.txt"), "ordinary content")
            .expect("write child file");
        std::fs::create_dir(workspace.path().join("ordinary-dir")).expect("create child directory");
        authorizer
            .authorize_workspace(&workspace_path)
            .await
            .expect("ordinary child creation must retain workspace authority");
        std::fs::remove_file(workspace.path().join("ordinary.txt")).expect("remove child file");
        std::fs::remove_dir(workspace.path().join("ordinary-dir")).expect("remove child directory");
        authorizer
            .authorize_workspace(&workspace_path)
            .await
            .expect("ordinary child removal must retain workspace authority");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let original_mode = std::fs::metadata(workspace.path())
                .expect("workspace metadata")
                .permissions()
                .mode()
                & 0o777;
            let changed_mode = (original_mode ^ 0o040) | 0o700;
            std::fs::set_permissions(
                workspace.path(),
                std::fs::Permissions::from_mode(changed_mode),
            )
            .expect("change workspace metadata");
            authorizer
                .authorize_workspace(&workspace_path)
                .await
                .expect("ordinary metadata changes must retain workspace authority");
            std::fs::set_permissions(
                workspace.path(),
                std::fs::Permissions::from_mode(original_mode),
            )
            .expect("restore workspace metadata");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn modes_session_setup_workspace_identity_rejects_symlink_and_renamed_root_substitution()
    {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().expect("workspace parent");
        let allowed = parent.path().join("allowed");
        let replacement = parent.path().join("replacement");
        let alias = parent.path().join("alias");
        std::fs::create_dir(&allowed).expect("allowed root");
        std::fs::create_dir(&replacement).expect("replacement root");
        symlink(&allowed, &alias).expect("workspace alias");
        let authorizer =
            LocalDaemonWorkspaceAuthorizer::new(vec![allowed.clone()]).expect("authorizer");
        let (direct_id, direct_root) = authorizer
            .authorize_workspace(allowed.to_string_lossy().as_ref())
            .await
            .expect("direct root");
        let (alias_id, alias_root) = authorizer
            .authorize_workspace(alias.to_string_lossy().as_ref())
            .await
            .expect("canonical symlink alias");
        assert_eq!(alias_id, direct_id);
        assert_eq!(alias_root, direct_root);
        std::fs::rename(&allowed, parent.path().join("moved")).expect("rename allowed root");
        std::fs::rename(&replacement, &allowed).expect("replace pathname");
        assert!(
            authorizer
                .authorize_workspace(allowed.to_string_lossy().as_ref())
                .await
                .is_err(),
            "renamed/replaced root must not inherit authority"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn modes_session_setup_workspace_shared_reads_hold_attach_directory_across_both_projections() {
        let parent = tempfile::tempdir().expect("workspace parent");
        let workspace = parent.path().join("workspace");
        let moved = parent.path().join("workspace-attached");
        let replacement = parent.path().join("workspace-replacement");
        std::fs::create_dir_all(workspace.join(".cockpit/agents")).expect("workspace agents");
        std::fs::write(
            workspace.join(".cockpit/agents/helper.md"),
            "first attached definition",
        )
        .expect("attached definition");
        let proof = AuthorizedWorkspaceRoot::capture(&workspace).expect("capture workspace");

        // This is the first projection pass. The held root reads the attached
        // directory, not a spelling that an attacker can replace afterwards.
        assert_eq!(
            proof
                .read_workspace_shared_definition("helper")
                .expect("first projection read"),
            WorkspaceSharedDefinitionBytes::Flat(b"first attached definition".to_vec())
        );

        // Deterministically swap the absolute spelling between the two
        // projection passes, then restore it. A path-based second pass would
        // observe the replacement while a final identity check could be fooled
        // by the restore; the held capability must continue reading the
        // original attached directory throughout.
        std::fs::rename(&workspace, &moved).expect("move attached workspace");
        std::fs::create_dir_all(replacement.join(".cockpit/agents")).expect("replacement agents");
        std::fs::write(
            replacement.join(".cockpit/agents/helper.md"),
            "replacement definition",
        )
        .expect("replacement definition");
        std::fs::rename(&replacement, &workspace).expect("install replacement spelling");
        assert_eq!(
            proof
                .read_workspace_shared_definition("helper")
                .expect("second projection read"),
            WorkspaceSharedDefinitionBytes::Flat(b"first attached definition".to_vec())
        );
        std::fs::rename(&workspace, &replacement).expect("remove replacement spelling");
        std::fs::rename(&moved, &workspace).expect("restore original spelling");
        assert!(
            proof.verify(&workspace).is_ok(),
            "a final pathname identity check alone cannot reveal a completed swap-and-restore"
        );
        assert_eq!(
            proof
                .read_workspace_shared_definition("helper")
                .expect("post-restore projection read"),
            WorkspaceSharedDefinitionBytes::Flat(b"first attached definition".to_vec())
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn modes_session_setup_workspace_shared_reader_preserves_package_tree_and_precedence() {
        let workspace = tempfile::tempdir().expect("workspace");
        let agents = workspace.path().join(".cockpit/agents");
        let package = agents.join("helper");
        std::fs::create_dir_all(package.join("subagents")).expect("package directories");
        std::fs::write(agents.join("helper.md"), "shadowed flat definition")
            .expect("flat definition");
        std::fs::write(
            package.join(crate::agents::PACKAGE_ROOT_FILE),
            markdown("authored/helper", "text_generation"),
        )
        .expect("package root");
        std::fs::write(package.join("mcp.json"), "{}\n").expect("package support file");
        let proof = AuthorizedWorkspaceRoot::capture(workspace.path()).expect("capture workspace");
        let WorkspaceSharedDefinitionBytes::Package(files) = proof
            .read_workspace_shared_definition("helper")
            .expect("held package read")
        else {
            panic!("package directory must win over its flat sibling")
        };
        assert!(files.contains_key(crate::agents::PACKAGE_ROOT_FILE));
        assert_eq!(
            files.get("mcp.json").map(Vec::as_slice),
            Some(b"{}\n".as_slice())
        );
        let definition = crate::agents::load_workspace_package_from_files("helper", files)
            .expect("held package bytes parse without reopening a path");
        assert_eq!(
            definition
                .vnext
                .as_ref()
                .map(|vnext| vnext.agent_id.as_str()),
            Some("authored/helper")
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn modes_session_setup_retained_hook_refresh_rejects_swap_and_never_parses_replacement() {
        let parent = tempfile::tempdir().expect("workspace parent");
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(parent.path());
        let ancestor = parent.path().join("ancestor");
        let workspace = ancestor.join("workspace");
        let moved_ancestor = parent.path().join("ancestor-attached");
        std::fs::create_dir_all(ancestor.join(".cockpit")).expect("ancestor config directory");
        std::fs::create_dir_all(workspace.join(".cockpit")).expect("workspace config directory");
        std::fs::write(
            ancestor.join(".cockpit/config.json"),
            r#"{"hooks":{"sessionStart":[{"command":["retained-ancestor-hook"]}]}}"#,
        )
        .expect("retained ancestor hook");
        std::fs::write(workspace.join(".cockpit/config.json"), "{}\n").expect("workspace config");
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&workspace)
                .expect("workspace trust root"),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let authority = WorkerWorkspaceConfigAuthority::capture(&workspace, &policy)
            .expect("capture retained workspace config authority");
        assert!(
            authority
                .resolve_hooks()
                .expect("initial retained hook projection")
                .hooks
                .iter()
                .any(|hook| hook.command == ["retained-ancestor-hook"])
        );

        let source_index = authority
            .hook_sources
            .iter()
            .position(|source| {
                source.kind
                    == cockpit_config::config::extended::hooks::HookSourceKind::Layer(
                        crate::config::dirs::ConfigDirKind::Project,
                    )
                    && source.path == ancestor.join(".cockpit/config.json")
            })
            .expect("retained ancestor hook source");
        let layer_index = authority.hook_source_layer_indexes[source_index]
            .expect("retained ancestor hook layer");
        let source = authority.hook_sources[source_index].clone();

        // Hold the old ancestor under its open directory capability while an
        // attacker owns the former absolute spelling. A live worker rejects
        // the replacement at the final identity check; the capability bytes
        // that would be parsed during a swap are still the retained bytes,
        // never the attacker's pathname contents.
        std::fs::rename(&ancestor, &moved_ancestor).expect("move retained ancestor");
        std::fs::create_dir_all(ancestor.join(".cockpit")).expect("replacement ancestor config");
        std::fs::write(
            ancestor.join(".cockpit/config.json"),
            r#"{"hooks":{"sessionStart":[{"command":["attacker-hook"]}]}}"#,
        )
        .expect("replacement ancestor hook");
        assert!(
            authority.resolve_hooks().is_err(),
            "replacement fails closed"
        );

        let retained_bytes = authority.config_layers[layer_index]
            .config_directory
            .read_regular_file_relative(&["config.json"])
            .expect("read hook bytes through retained ancestor handle");
        let parsed = cockpit_config::config::extended::hooks::resolve_hooks_from_captured_sources(
            &[(source, Ok(Some(retained_bytes)))],
        );
        assert!(
            parsed
                .hooks
                .iter()
                .any(|hook| hook.command == ["retained-ancestor-hook"])
        );
        assert!(
            !parsed
                .hooks
                .iter()
                .any(|hook| hook.command == ["attacker-hook"])
        );

        std::fs::remove_dir_all(&ancestor).expect("remove replacement ancestor");
        std::fs::rename(&moved_ancestor, &ancestor).expect("restore retained ancestor");
        let restored = authority
            .resolve_hooks()
            .expect("restored retained hook refresh");
        assert!(
            restored
                .hooks
                .iter()
                .any(|hook| hook.command == ["retained-ancestor-hook"])
        );
        assert!(
            !restored
                .hooks
                .iter()
                .any(|hook| hook.command == ["attacker-hook"])
        );
    }

    #[test]
    fn retained_favorite_rejects_higher_layer_insertion_before_any_lower_write() {
        let parent = tempfile::tempdir().expect("workspace parent");
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(parent.path());
        let ancestor = parent.path().join("ancestor");
        let workspace = ancestor.join("workspace");
        let ancestor_config = ancestor.join(".cockpit/config.json");
        let workspace_config = workspace.join(".cockpit/config.json");
        std::fs::create_dir_all(ancestor_config.parent().expect("ancestor config parent"))
            .expect("ancestor config parent");
        std::fs::create_dir_all(workspace_config.parent().expect("workspace config parent"))
            .expect("workspace config parent");
        std::fs::write(&ancestor_config, "{}\n").expect("ancestor config");
        std::fs::write(&workspace_config, "{}\n").expect("workspace config");
        let lower_provider =
            cockpit_config::config::providers::provider_file_path_for_config(&ancestor_config, "p")
                .expect("lower provider path");
        std::fs::create_dir_all(lower_provider.parent().expect("lower provider parent"))
            .expect("lower provider parent");
        std::fs::write(
            &lower_provider,
            r#"{ "models": [{ "id": "m", "name": "lower" }] }"#,
        )
        .expect("lower provider");
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&workspace)
                .expect("workspace trust root"),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let authority = Arc::new(
            WorkerWorkspaceConfigAuthority::capture(&workspace, &policy)
                .expect("capture retained config authority"),
        );
        let snapshot = authority
            .capture_retained_effective_default_layer_chain()
            .expect("initial complete retained provider snapshot");
        let source = cockpit_config::config::providers::retained_provider_model_source_from_workspace_layer_snapshots(
            &snapshot.layers,
            "p",
            "m",
        )
        .expect("source parse")
        .expect("lower source");
        assert_eq!(source.layer_index(), 0, "ancestor supplies initial model");
        let target = authority
            .retained_provider_model_favorite_target(source)
            .expect("build retained favorite capability");

        // The higher layer participated in attach but did not initially
        // define p/m. Its insert must be caught before the lower source can
        // be modified (and the same verifier is repeated under every source
        // lock for an insertion racing the first check).
        let higher_provider = cockpit_config::config::providers::provider_file_path_for_config(
            &workspace_config,
            "p",
        )
        .expect("higher provider path");
        std::fs::create_dir_all(higher_provider.parent().expect("higher provider parent"))
            .expect("higher provider parent");
        std::fs::write(
            &higher_provider,
            r#"{ "models": [{ "id": "m", "name": "higher" }] }"#,
        )
        .expect("insert higher provider source");
        let lower_before = std::fs::read(&lower_provider).expect("lower bytes before rejection");
        assert!(target.write_model_favorite(true).is_err());
        assert_eq!(
            std::fs::read(&lower_provider).expect("lower bytes after rejection"),
            lower_before,
            "a stale lower source must not be mutated after higher-layer insertion",
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_favorite_global_source_rejects_replaced_global_directory() {
        let home = tempfile::tempdir().expect("isolated Cockpit home");
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let workspace = tempfile::tempdir().expect("workspace");
        let global_dir = home.path().join("home/.config/cockpit");
        let global_config = global_dir.join("config.json");
        std::fs::create_dir_all(&global_dir).expect("global config directory");
        std::fs::write(&global_config, r#"{"providers":{"global":{}}}"#).expect("global config");
        let provider = cockpit_config::config::providers::provider_file_path_for_config(
            &global_config,
            "global",
        )
        .expect("global provider path");
        std::fs::create_dir_all(provider.parent().expect("global provider parent"))
            .expect("global providers directory");
        std::fs::write(
            &provider,
            r#"{"models":[{"id":"m","name":"captured","favorite":false}]}"#,
        )
        .expect("global provider");
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(workspace.path())
                .expect("workspace trust root"),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let authority = Arc::new(
            WorkerWorkspaceConfigAuthority::capture(workspace.path(), &policy)
                .expect("capture global retained authority"),
        );
        let snapshot = authority
            .capture_retained_effective_default_layer_chain()
            .expect("capture complete global source chain");
        let source = cockpit_config::config::providers::retained_provider_model_source_from_workspace_layer_snapshots(
            &snapshot.layers,
            "global",
            "m",
        )
        .expect("parse global source")
        .expect("global source proof");
        let target = authority
            .retained_provider_model_favorite_target(source)
            .expect("build global retained favorite capability");

        let replacement = home.path().join("replacement-cockpit");
        let replacement_config = replacement.join("config.json");
        std::fs::create_dir_all(&replacement).expect("replacement global directory");
        std::fs::write(&replacement_config, r#"{"providers":{"global":{}}}"#)
            .expect("replacement config");
        let replacement_provider =
            cockpit_config::config::providers::provider_file_path_for_config(
                &replacement_config,
                "global",
            )
            .expect("replacement provider path");
        std::fs::create_dir_all(
            replacement_provider
                .parent()
                .expect("replacement provider parent"),
        )
        .expect("replacement providers directory");
        std::fs::write(
            &replacement_provider,
            r#"{"models":[{"id":"m","name":"replacement","favorite":false}]}"#,
        )
        .expect("replacement provider");
        let replacement_bytes = std::fs::read(&replacement_provider).expect("replacement bytes");
        std::fs::rename(&global_dir, home.path().join("moved-global"))
            .expect("move captured global directory");
        std::fs::rename(&replacement, &global_dir).expect("install replacement global directory");

        assert!(target.write_model_favorite(true).is_err());
        assert_eq!(
            std::fs::read(global_dir.join("providers/global.json"))
                .expect("replacement bytes after failure"),
            replacement_bytes,
            "a global directory replacement must never be reopened or mutated"
        );
    }

    #[test]
    fn retained_favorite_uses_higher_project_source_over_global_source() {
        let home = tempfile::tempdir().expect("isolated Cockpit home");
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let workspace = tempfile::tempdir().expect("workspace");
        let global_config = home.path().join("home/.config/cockpit/config.json");
        let project_config = workspace.path().join(".cockpit/config.json");
        for config in [&global_config, &project_config] {
            std::fs::create_dir_all(config.parent().expect("config parent")).unwrap();
            std::fs::write(config, r#"{"providers":{"p":{}}}"#).unwrap();
            let provider =
                cockpit_config::config::providers::provider_file_path_for_config(config, "p")
                    .expect("provider path");
            std::fs::create_dir_all(provider.parent().expect("provider parent")).unwrap();
            std::fs::write(
                provider,
                r#"{"models":[{"id":"m","name":"configured","favorite":false}]}"#,
            )
            .unwrap();
        }
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(workspace.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let authority = Arc::new(
            WorkerWorkspaceConfigAuthority::capture(workspace.path(), &policy)
                .expect("capture global and project sources"),
        );
        let snapshot = authority
            .capture_retained_effective_default_layer_chain()
            .expect("complete source chain");
        let source = cockpit_config::config::providers::retained_provider_model_source_from_workspace_layer_snapshots(
            &snapshot.layers,
            "p",
            "m",
        )
        .expect("parse layered source")
        .expect("effective project source");
        let project_layer = snapshot
            .layers
            .iter()
            .rposition(|layer| {
                layer
                    .provider_files
                    .iter()
                    .any(|(provider, _)| provider == "p")
            })
            .expect("at least one p source");
        assert_eq!(
            source.layer_index(),
            project_layer,
            "the highest project p source must supply the effective model"
        );
        authority
            .retained_provider_model_favorite_target(source)
            .expect("project retained target")
            .write_model_favorite(true)
            .expect("project favorite update");
        let global =
            cockpit_config::config::providers::ConfigDoc::providers_from_paths(&[global_config]);
        let project =
            cockpit_config::config::providers::ConfigDoc::providers_from_paths(&[project_config]);
        assert!(!global.providers["p"].models[0].favorite);
        assert!(project.providers["p"].models[0].favorite);
    }

    #[test]
    fn retained_favorite_ignore_config_uses_global_without_project_authority() {
        let home = tempfile::tempdir().expect("isolated Cockpit home");
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let workspace = tempfile::tempdir().expect("workspace");
        let global_config = home.path().join("home/.config/cockpit/config.json");
        let project_config = workspace.path().join(".cockpit/config.json");
        for (config, name) in [(&global_config, "global"), (&project_config, "project")] {
            std::fs::create_dir_all(config.parent().expect("config parent")).unwrap();
            std::fs::write(config, r#"{"providers":{"p":{}}}"#).unwrap();
            let provider =
                cockpit_config::config::providers::provider_file_path_for_config(config, "p")
                    .expect("provider path");
            std::fs::create_dir_all(provider.parent().expect("provider parent")).unwrap();
            std::fs::write(
                provider,
                format!(r#"{{"models":[{{"id":"m","name":"{name}","favorite":false}}]}}"#),
            )
            .unwrap();
        }
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(workspace.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        };
        let authority = Arc::new(
            WorkerWorkspaceConfigAuthority::capture(workspace.path(), &policy)
                .expect("capture global-only attached source"),
        );
        let snapshot = authority
            .capture_retained_effective_default_layer_chain()
            .expect("global-only retained chain");
        let source = cockpit_config::config::providers::retained_provider_model_source_from_workspace_layer_snapshots(
            &snapshot.layers,
            "p",
            "m",
        )
        .expect("parse global-only source")
        .expect("global source remains mutable");
        authority
            .retained_provider_model_favorite_target(source)
            .expect("global retained target under IgnoreConfig")
            .write_model_favorite(true)
            .expect("global favorite update under IgnoreConfig");
        let global =
            cockpit_config::config::providers::ConfigDoc::providers_from_paths(&[global_config]);
        let project =
            cockpit_config::config::providers::ConfigDoc::providers_from_paths(&[project_config]);
        assert!(global.providers["p"].models[0].favorite);
        assert!(!project.providers["p"].models[0].favorite);
    }

    #[test]
    fn retained_source_projection_tracks_trust_transitions_without_rediscovery() {
        let home = tempfile::tempdir().expect("isolated Cockpit home");
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(home.path());
        let workspace = tempfile::tempdir().expect("workspace");
        let global_config = home.path().join("home/.config/cockpit/config.json");
        let project_config = workspace.path().join(".cockpit/config.json");
        for (config, rounds, hook, name) in [
            (&global_config, 11, "global-hook", "global"),
            (&project_config, 22, "project-hook", "project"),
        ] {
            std::fs::create_dir_all(config.parent().expect("config parent")).unwrap();
            std::fs::write(
                config,
                format!(
                    r#"{{"providers":{{"p":{{}}}},"maxPrimaryRounds":{rounds},"hooks":{{"sessionStart":[{{"command":["{hook}"]}}]}}}}"#,
                ),
            )
            .unwrap();
            let provider =
                cockpit_config::config::providers::provider_file_path_for_config(config, "p")
                    .expect("provider path");
            std::fs::create_dir_all(provider.parent().expect("provider parent")).unwrap();
            std::fs::write(
                provider,
                format!(r#"{{"models":[{{"id":"m","name":"{name}","favorite":false}}]}}"#),
            )
            .unwrap();
        }
        let trusted = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(workspace.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let authority = Arc::new(
            WorkerWorkspaceConfigAuthority::capture(workspace.path(), &trusted)
                .expect("capture both retained scopes"),
        );
        let source = crate::daemon::config_source::ConfigSource::production();
        let trusted_chain = authority
            .capture_retained_config_source_chain(&trusted)
            .expect("trusted source projection");
        let (_, trusted_extended) = source
            .load_effective_for_daemon_with_retained_workspace_layer(
                workspace.path(),
                &trusted,
                &trusted_chain,
            )
            .expect("trusted projected config");
        assert_eq!(trusted_extended.max_primary_rounds, 22);
        assert!(
            authority
                .resolve_hooks_for_policy(&trusted)
                .expect("trusted hooks")
                .hooks
                .iter()
                .any(|hook| hook.command == ["project-hook"])
        );
        let trusted_source = cockpit_config::config::providers::retained_provider_model_source_from_workspace_layer_snapshots(
            &trusted_chain.layers,
            "p",
            "m",
        )
        .expect("trusted source parse")
        .expect("project source proof");

        let mut ignored = trusted.clone();
        ignored.mode = crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig;
        let trusted_default_authority = authority
            .retained_effective_default_authority_binding_for_policy(&trusted, 41)
            .expect("trusted default authority");
        let ignored_default_authority = authority
            .retained_effective_default_authority_binding_for_policy(&ignored, 41)
            .expect("IgnoreConfig default authority");
        assert_ne!(
            trusted_default_authority.authority_revision,
            ignored_default_authority.authority_revision,
            "a receipt sealed for a project-authorized default must not replay after IgnoreConfig"
        );
        authority
            .retained_effective_default_target_for_policy(&ignored)
            .expect("IgnoreConfig chooses a retained global default target");
        let ignored_chain = authority
            .capture_retained_config_source_chain(&ignored)
            .expect("global-only policy projection");
        let ignored_providers =
            cockpit_config::config::providers::ConfigDoc::providers_from_workspace_layer_snapshots(
                &ignored_chain.layers,
            )
            .expect("global-only provider view");
        assert_eq!(
            ignored_providers.providers["p"].models[0].name.as_deref(),
            Some("global")
        );
        let (_, ignored_extended) = source
            .load_effective_for_daemon_with_retained_workspace_layer(
                workspace.path(),
                &ignored,
                &ignored_chain,
            )
            .expect("ignored projected config");
        assert_eq!(ignored_extended.max_primary_rounds, 11);
        let ignored_hooks = authority
            .resolve_hooks_for_policy(&ignored)
            .expect("global-only hooks");
        assert!(
            ignored_hooks
                .hooks
                .iter()
                .any(|hook| hook.command == ["global-hook"])
        );
        assert!(
            !ignored_hooks
                .hooks
                .iter()
                .any(|hook| hook.command == ["project-hook"])
        );
        assert!(
            authority
                .retained_provider_model_favorite_target_for_policy(trusted_source, &ignored,)
                .is_err(),
            "a project source observed before IgnoreConfig cannot remain mutable",
        );
        let global_source = cockpit_config::config::providers::retained_provider_model_source_from_workspace_layer_snapshots(
            &ignored_chain.layers,
            "p",
            "m",
        )
        .expect("ignored source parse")
        .expect("global source proof");
        authority
            .retained_provider_model_favorite_target_for_policy(global_source, &ignored)
            .expect("global source stays capability-backed under IgnoreConfig")
            .write_model_favorite(true)
            .expect("global favorite update");
        let global =
            cockpit_config::config::providers::ConfigDoc::providers_from_paths(&[global_config]);
        let project =
            cockpit_config::config::providers::ConfigDoc::providers_from_paths(&[project_config]);
        assert!(global.providers["p"].models[0].favorite);
        assert!(!project.providers["p"].models[0].favorite);

        let trusted_again = authority
            .capture_retained_config_source_chain(&trusted)
            .expect("Trust may re-enable only the captured project capability");
        let providers_again =
            cockpit_config::config::providers::ConfigDoc::providers_from_workspace_layer_snapshots(
                &trusted_again.layers,
            )
            .expect("restored provider view");
        assert_eq!(
            providers_again.providers["p"].models[0].name.as_deref(),
            Some("project")
        );
        assert!(
            authority
                .resolve_hooks_for_policy(&trusted)
                .expect("restored project hooks")
                .hooks
                .iter()
                .any(|hook| hook.command == ["project-hook"])
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn modes_session_setup_retained_relative_hook_snapshot_survives_swap_and_updates_normally()
     {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let parent = tempfile::tempdir().expect("workspace parent");
        let _env =
            cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at_async(parent.path()).await;
        let workspace = parent.path().join("workspace");
        let moved = parent.path().join("workspace-attached");
        let executable = workspace.join(".cockpit/hooks/check");
        std::fs::create_dir_all(executable.parent().expect("hook parent")).expect("hook parent");
        std::fs::write(
            workspace.join(".cockpit/config.json"),
            r#"{"hooks":{"sessionStart":[{"command":["./hooks/check"]}]}}"#,
        )
        .expect("hook config");
        std::fs::write(workspace.join("project-sentinel"), b"attached-project-v1\n")
            .expect("attached project sentinel");
        std::fs::write(
            &executable,
            b"#!/bin/sh\nIFS= read -r value < project-sentinel\nprintf '%s\\n' \"$value\"\n",
        )
        .expect("attached hook");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .expect("make attached hook executable");
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&workspace)
                .expect("workspace trust root"),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let authority = WorkerWorkspaceConfigAuthority::capture(&workspace, &policy)
            .expect("capture workspace config authority");
        let initial = authority.resolve_hooks().expect("initial hook registry");
        let initial_launch = initial.hooks[0]
            .retained_execution_launch()
            .expect("initial retained launch")
            .expect("relative hook is retained");
        assert_eq!(
            std::fs::read(initial_launch.executable()).expect("read private v1 snapshot"),
            b"#!/bin/sh\nIFS= read -r value < project-sentinel\nprintf '%s\\n' \"$value\"\n"
        );
        let cockpit_config::config::extended::hooks::HookWorkingDirectory::RetainedUnixDirectory(
            initial_cwd,
        ) = initial_launch.working_directory()
        else {
            panic!("a retained relative hook must carry an fd-backed workspace cwd");
        };
        assert_eq!(
            initial_cwd
                .metadata()
                .expect("retained workspace cwd metadata")
                .ino(),
            std::fs::metadata(&workspace)
                .expect("workspace metadata")
                .ino(),
            "the executable may come from .cockpit, but project-relative script reads use the attached workspace root"
        );
        let (stdout, spawn_failed, timed_out) =
            crate::engine::agent::hooks::spawn_real_hook_child_for_test(
                initial_launch.executable(),
                &[],
                &std::collections::BTreeMap::new(),
                initial_launch.working_directory(),
                "",
                std::time::Duration::from_secs(5),
            )
            .await;
        assert!(
            !spawn_failed && !timed_out,
            "retained hook launches from private bundle"
        );
        assert_eq!(stdout, "attached-project-v1\n");

        // A failing watcher refresh leaves this old registry live. Its program
        // must stay the immutable v1 snapshot even while the original spelling
        // is controlled by a replacement workspace.
        std::fs::rename(&workspace, &moved).expect("move attached workspace");
        let replacement_executable = workspace.join(".cockpit/hooks/check");
        std::fs::create_dir_all(
            replacement_executable
                .parent()
                .expect("replacement hook parent"),
        )
        .expect("replacement hook parent");
        std::fs::write(
            workspace.join(".cockpit/config.json"),
            r#"{"hooks":{"sessionStart":[{"command":["./hooks/check"]}]}}"#,
        )
        .expect("replacement hook config");
        std::fs::write(&replacement_executable, b"#!/bin/sh\necho attacker\n")
            .expect("replacement hook");
        std::fs::write(workspace.join("project-sentinel"), b"attacker-project\n")
            .expect("replacement project sentinel");
        std::fs::set_permissions(
            &replacement_executable,
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("make replacement hook executable");
        assert!(
            authority.resolve_hooks().is_err(),
            "replacement must fail closed"
        );
        assert_eq!(
            std::fs::read(initial_launch.executable()).expect("read retained v1 after swap"),
            b"#!/bin/sh\nIFS= read -r value < project-sentinel\nprintf '%s\\n' \"$value\"\n",
            "last-good registry cannot execute the replacement path"
        );
        assert_eq!(
            initial_cwd
                .metadata()
                .expect("retained cwd survives workspace swap")
                .ino(),
            std::fs::metadata(&moved)
                .expect("moved original workspace metadata")
                .ino(),
            "the retained child cwd stays attached to the original project rather than replacement .cockpit"
        );
        let (stdout, spawn_failed, timed_out) =
            crate::engine::agent::hooks::spawn_real_hook_child_for_test(
                initial_launch.executable(),
                &[],
                &std::collections::BTreeMap::new(),
                initial_launch.working_directory(),
                "",
                std::time::Duration::from_secs(5),
            )
            .await;
        assert!(
            !spawn_failed && !timed_out,
            "retained bundle remains executable after swap"
        );
        assert_eq!(
            stdout, "attached-project-v1\n",
            "the private v1 script reads the original attached project, never replacement cwd"
        );

        std::fs::remove_dir_all(&workspace).expect("remove replacement workspace");
        std::fs::rename(&moved, &workspace).expect("restore attached workspace");

        // The retained openat walk refuses a replacement intermediate
        // directory instead of following it while reconstructing a hook.
        let hooks = workspace.join(".cockpit/hooks");
        let parked_hooks = workspace.join(".cockpit/hooks-attached");
        std::fs::rename(&hooks, &parked_hooks).expect("park original hooks directory");
        std::os::unix::fs::symlink(parent.path(), &hooks).expect("install hostile hook symlink");
        assert!(
            authority.resolve_hooks().is_err(),
            "intermediate symlink must not be traversed"
        );
        std::fs::remove_file(&hooks).expect("remove hostile hook symlink");
        std::fs::rename(&parked_hooks, &hooks).expect("restore hooks directory");

        // A normal in-place update of the still-authorized source produces a
        // new v2 bundle while the live v1 bundle remains immutable.
        std::fs::write(
            &executable,
            b"#!/bin/sh\nIFS= read -r value < project-sentinel\nprintf '%s\\n' \"$value\"\n# attached-v2\n",
        )
        .expect("updated hook");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .expect("keep updated hook executable");
        let updated = authority.resolve_hooks().expect("normal hook refresh");
        let updated_launch = updated.hooks[0]
            .retained_execution_launch()
            .expect("updated retained launch")
            .expect("relative hook is retained");
        assert_eq!(
            std::fs::read(updated_launch.executable()).expect("read private v2 snapshot"),
            b"#!/bin/sh\nIFS= read -r value < project-sentinel\nprintf '%s\\n' \"$value\"\n# attached-v2\n"
        );
        assert_eq!(
            std::fs::read(initial_launch.executable()).expect("read private v1 after update"),
            b"#!/bin/sh\nIFS= read -r value < project-sentinel\nprintf '%s\\n' \"$value\"\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn modes_session_setup_reclaims_only_unleased_hook_bundle_roots_after_crash() {
        let parent = tempfile::tempdir().expect("state parent");
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(parent.path());
        let state_root = cockpit_config::config::resolve::cockpit_state_dir()
            .expect("state directory")
            .join("hook-execution");
        cockpit_host::private_fs::ensure_private_dir(&state_root).expect("secure state root");
        let orphan = tempfile::Builder::new()
            .prefix(RetainedHookExecutionBundleRoot::PREFIX)
            .tempdir_in(&state_root)
            .expect("orphan root")
            .keep();
        std::fs::write(orphan.join(".lease"), b"abandoned").expect("orphan lease");

        let live = RetainedHookExecutionBundleRoot::create().expect("new live root");
        assert!(
            !orphan.exists(),
            "a new daemon root reclaims an unlocked crash leftover"
        );
        assert!(live.path().exists(), "the current leased root remains live");
        let second_live = RetainedHookExecutionBundleRoot::create().expect("second live root");
        assert!(
            live.path().exists() && second_live.path().exists(),
            "same-process live roots are never mistaken for abandoned state"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn modes_session_setup_windows_retained_relative_hook_uses_private_cmd_bundle_and_no_delete_cwd_lease()
     {
        let parent = tempfile::tempdir().expect("workspace parent");
        let _env =
            cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at_async(parent.path()).await;
        let workspace = parent.path().join("workspace");
        let moved = parent.path().join("workspace-attached");
        std::fs::create_dir_all(workspace.join(".cockpit/hooks")).expect("hook parent");
        std::fs::write(
            workspace.join(".cockpit/config.json"),
            r#"{"hooks":{"sessionStart":[{"command":["./hooks/check.cmd"]}]}}"#,
        )
        .expect("hook config");
        let source = workspace.join(".cockpit/hooks/check.cmd");
        std::fs::write(&source, "@type project-sentinel\r\n").expect("hook executable");
        std::fs::write(workspace.join("project-sentinel"), "attached-project\r\n")
            .expect("cwd sentinel");
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&workspace)
                .expect("workspace trust root"),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let authority = WorkerWorkspaceConfigAuthority::capture(&workspace, &policy)
            .expect("capture workspace config authority");
        let registry = authority
            .resolve_hooks()
            .expect("attach/refresh snapshots the source program without acquiring a cwd lease");
        let launch = registry.hooks[0]
            .retained_execution_launch()
            .expect("Windows launch lease acquisition")
            .expect("relative hook has a retained launch");
        assert_ne!(launch.executable(), source.as_path());
        assert_eq!(
            launch
                .executable()
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("cmd"),
            "private snapshot retains the suffix required for normal Command/.cmd dispatch"
        );
        assert_eq!(
            std::fs::read(launch.executable()).expect("read private bundled script"),
            b"@type project-sentinel\r\n",
            "source replacement cannot alter the retained program"
        );
        let cockpit_config::config::extended::hooks::HookWorkingDirectory::RetainedWindowsDirectory(
            cwd,
        ) = launch.working_directory()
        else {
            panic!("Windows retained hook must carry the typed cwd lease")
        };
        assert_eq!(
            cockpit_config::config::extended::hooks::RetainedWindowsHookWorkingDirectory::canonical_path(
                cwd.as_ref(),
            ),
            workspace.as_path()
        );
        cockpit_config::config::extended::hooks::RetainedWindowsHookWorkingDirectory::revalidate_before_spawn(cwd.as_ref())
            .expect("captured workspace cwd still names its held FileId");

        // `Command::new` deliberately retains Rust's native `.cmd` handling:
        // it invokes the system command interpreter with Rust's batch-safe
        // argument construction. Execute the bundled command through the real
        // runner to prove the original extension is preserved, the attached
        // workspace remains the cwd, and a clean child environment is enough.
        let system_root = std::env::var("SystemRoot").expect("Windows SystemRoot");
        let child_env = std::collections::BTreeMap::from([
            ("SystemRoot".to_owned(), system_root.clone()),
            ("WINDIR".to_owned(), system_root),
        ]);
        let (stdout, spawn_failed, timed_out) =
            crate::engine::agent::hooks::spawn_real_hook_child_for_test(
                launch.executable(),
                &[],
                &child_env,
                launch.working_directory(),
                "",
                std::time::Duration::from_secs(5),
            )
            .await;
        assert!(
            !spawn_failed && !timed_out,
            "private bundled .cmd must preserve normal Command dispatch"
        );
        assert_eq!(
            stdout.trim(),
            "attached-project",
            "private bundled .cmd runs in the attached workspace cwd"
        );

        // The no-delete lease blocks a root A -> B substitution during the
        // whole child lifetime. Do not weaken this to a post-hoc comparison:
        // CreateProcess only accepts this same canonical path spelling.
        assert!(
            std::fs::rename(&workspace, &moved).is_err(),
            "live retained cwd lease blocks workspace rename/replacement"
        );

        // Replacing either an intermediate directory or the source executable
        // is a normal future refresh, but cannot change this
        // in-flight/last-good bundle.
        let hooks = workspace.join(".cockpit/hooks");
        let parked_hooks = workspace.join(".cockpit/hooks-attached");
        std::fs::rename(&hooks, &parked_hooks).expect("move attached hook directory");
        std::fs::create_dir_all(&hooks).expect("replacement intermediate directory");
        std::fs::write(hooks.join("check.cmd"), "@echo intermediate-attacker\r\n")
            .expect("replacement intermediate executable");
        assert_eq!(
            std::fs::read(launch.executable())
                .expect("read original private bundle after intermediate swap"),
            b"@type project-sentinel\r\n"
        );
        std::fs::remove_dir_all(&hooks).expect("remove replacement intermediate directory");
        std::fs::rename(&parked_hooks, &hooks).expect("restore attached hook directory");
        std::fs::write(&source, "@echo attacker\r\n").expect("replace source executable");
        assert_eq!(
            std::fs::read(launch.executable()).expect("read original private bundle"),
            b"@type project-sentinel\r\n"
        );

        // Dropping the launch releases the cwd lease. Once A is moved and B
        // occupies the old spelling, the original registry refuses a new
        // launch rather than ever executing B's source or using B as cwd.
        drop(launch);
        std::fs::rename(&workspace, &moved).expect("lease cleanup permits root rename");
        std::fs::create_dir_all(workspace.join(".cockpit/hooks")).expect("replacement hook parent");
        std::fs::write(
            workspace.join(".cockpit/config.json"),
            r#"{"hooks":{"sessionStart":[{"command":["./hooks/check.cmd"]}]}}"#,
        )
        .expect("replacement hook config");
        std::fs::write(
            workspace.join(".cockpit/hooks/check.cmd"),
            "@echo replacement\r\n",
        )
        .expect("replacement source executable");
        assert!(
            registry.hooks[0].retained_execution_launch().is_err(),
            "identity-mismatched B must not receive a retained launch"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn modes_session_setup_windows_retained_hook_cwd_lease_lives_through_child_exit() {
        let parent = tempfile::tempdir().expect("workspace parent");
        let _env =
            cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at_async(parent.path()).await;
        let workspace = parent.path().join("workspace");
        let moved = parent.path().join("workspace-attached");
        let system_root = std::env::var("SystemRoot").expect("Windows SystemRoot");
        let cmd = Path::new(&system_root).join("System32").join("cmd.exe");
        let source = workspace.join(".cockpit/hooks/cmd.exe");
        std::fs::create_dir_all(source.parent().expect("hook parent")).expect("hook parent");
        std::fs::copy(&cmd, &source).expect("copy normal Windows executable source");
        std::fs::write(
            workspace.join(".cockpit/config.json"),
            r#"{"hooks":{"sessionStart":[{"command":["./hooks/cmd.exe"]}]}}"#,
        )
        .expect("hook config");
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&workspace)
                .expect("workspace trust root"),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let authority = WorkerWorkspaceConfigAuthority::capture(&workspace, &policy)
            .expect("capture workspace config authority");
        let registry = authority
            .resolve_hooks()
            .expect("snapshot executable bundle");
        let launch = registry.hooks[0]
            .retained_execution_launch()
            .expect("acquire cwd lease")
            .expect("retained exe launch");
        assert_eq!(
            launch
                .executable()
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("exe")
        );
        let executable = launch.executable().to_path_buf();
        let working_directory = launch.working_directory().clone();
        let mut child_env = std::collections::BTreeMap::new();
        child_env.insert("SystemRoot".to_owned(), system_root.clone());
        child_env.insert("WINDIR".to_owned(), system_root.clone());
        // The private bundled cmd.exe writes a project-relative sentinel, then
        // remains alive long enough for the test to prove the cwd lease stays
        // held until wait/reap. No source pathname is used after launch.
        let child_args = vec![
            "/d".to_owned(),
            "/c".to_owned(),
            "echo attached>child-started & %SystemRoot%\\System32\\ping.exe -n 3 127.0.0.1 > nul"
                .to_owned(),
        ];
        drop(launch);
        let child = tokio::spawn(async move {
            crate::engine::agent::hooks::spawn_real_hook_child_for_test(
                &executable,
                &child_args,
                &child_env,
                &working_directory,
                "",
                std::time::Duration::from_secs(10),
            )
            .await
        });
        let sentinel = workspace.join("child-started");
        for _ in 0..40 {
            if sentinel.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            sentinel.exists(),
            "child ran in retained attached workspace cwd"
        );
        assert!(
            std::fs::rename(&workspace, &moved).is_err(),
            "cwd path cannot be renamed while the retained child is live"
        );
        let (_stdout, spawn_failed, timed_out) = child.await.expect("child task join");
        assert!(
            !spawn_failed && !timed_out,
            "private bundled .exe completed normally"
        );
        std::fs::rename(&workspace, &moved)
            .expect("lease closes after child wait/reap and permits cleanup");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn modes_session_setup_oversized_project_hook_config_fails_closed_before_parse() {
        let parent = tempfile::tempdir().expect("workspace parent");
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(parent.path());
        let workspace = parent.path().join("workspace");
        let config = workspace.join(".cockpit/config.json");
        std::fs::create_dir_all(config.parent().expect("project config parent"))
            .expect("project config parent");
        std::fs::write(&config, vec![b'x'; MAX_HOOK_CONFIG_BYTES + 1])
            .expect("oversized project hook config");
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&workspace)
                .expect("workspace trust root"),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let authority = WorkerWorkspaceConfigAuthority::capture(&workspace, &policy)
            .expect("capture project hook authority");
        assert!(
            authority.resolve_hooks().is_err(),
            "oversized retained project hook source must fail closed"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn modes_session_setup_oversized_explicit_hook_config_fails_closed_before_parse() {
        let parent = tempfile::tempdir().expect("workspace parent");
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(parent.path());
        let workspace = parent.path().join("workspace");
        let explicit = parent.path().join("explicit/config.json");
        std::fs::create_dir_all(&workspace).expect("workspace");
        std::fs::create_dir_all(explicit.parent().expect("explicit config parent"))
            .expect("explicit config parent");
        std::fs::write(&explicit, vec![b'x'; MAX_HOOK_CONFIG_BYTES + 1])
            .expect("oversized explicit hook config");
        env.set_cockpit_config(&explicit);
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&workspace)
                .expect("workspace trust root"),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let authority = WorkerWorkspaceConfigAuthority::capture(&workspace, &policy)
            .expect("capture explicit hook authority");
        assert!(
            authority.resolve_hooks().is_err(),
            "oversized retained explicit hook source must fail closed"
        );
    }

    #[cfg(windows)]
    #[test]
    fn modes_session_setup_windows_workspace_identity_rejects_replaced_directory() {
        let parent = tempfile::tempdir().expect("workspace parent");
        let workspace = parent.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace root");
        let proof = AuthorizedWorkspaceRoot::capture(&workspace)
            .expect("capture opened Windows directory identity");

        std::fs::rename(&workspace, parent.path().join("workspace-original"))
            .expect("move original workspace");
        std::fs::create_dir(&workspace).expect("replacement workspace");
        assert!(
            proof.verify(&workspace).is_err(),
            "a replacement directory must have a different volume/file id proof"
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_recovers_each_file_checkpoint_without_duplicate_installation_mutation()
     {
        for (index, checkpoint) in [
            InstallationJournalCheckpoint::Staged,
            InstallationJournalCheckpoint::DbCommitted,
            InstallationJournalCheckpoint::FileRenamed,
        ]
        .into_iter()
        .enumerate()
        {
            let harness = ServiceHarness::new(FetchReply::Failure("must not refetch".into()));
            let request = ServiceHarness::request(&format!("checkpoint-{index}"));
            let operation = prepare_recovery_checkpoint(&harness, &request, checkpoint).await;
            let result = harness.service.begin(request.clone(), 10).await;
            assert!(matches!(
                result,
                AgentInstallationResultV1::Receipt {
                    status: AgentInstallationReceiptStatusV1::Installed,
                    ..
                }
            ));
            let journal = harness
                .db
                .installation_journal(operation)
                .await
                .expect("journal lookup")
                .expect("journal exists");
            assert_eq!(journal.checkpoint, InstallationJournalCheckpoint::Complete);
            let rows = harness
                .db
                .list_agent_installations(AgentInstallationScope::Global, None)
                .await
                .expect("list installs");
            assert_eq!(rows.len(), 1, "checkpoint {checkpoint:?}");
            assert_eq!(
                target_digest(&harness.target()).expect("published target"),
                sha256_hex(&ServiceHarness::fetched().markdown)
            );
            assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_db_committed_replacement_compensation_replays_refused_without_refetching()
     {
        let harness = ServiceHarness::new(FetchReply::Failure("must not refetch".into()));
        let request = ServiceHarness::request("replacement-compensation");
        let operation = match harness
            .db
            .begin_installation_operation(
                request.idempotency_key.clone(),
                request_fingerprint(&request, None),
                InstallationOperationKind::Install,
                None,
                1,
            )
            .await
            .expect("begin operation")
        {
            BeginInstallationOperation::Created(operation) => operation,
            _ => panic!("expected fresh operation"),
        };
        let fetched = ServiceHarness::fetched();
        let definition_digest = fetched_definition_digest(&fetched);
        let original = AgentInstallationInput {
            installation_id: Uuid::new_v4(),
            scope: AgentInstallationScope::Global,
            canonical_workspace_id: None,
            source_agent_id: "authored/helper".into(),
            source_identity: "owner/old:agents/helper.md".into(),
            source_revision: Some("b".repeat(40)),
            source_digest: "c".repeat(64),
            fetched_at_unix_ms: 1,
        };
        let original_id = original.installation_id;
        harness
            .db
            .install_agent(original.clone())
            .await
            .expect("original installation");
        let replacement = AgentInstallationInput {
            installation_id: operation.operation_id,
            scope: AgentInstallationScope::Global,
            canonical_workspace_id: None,
            source_agent_id: "authored/helper".into(),
            source_identity: "owner/repo:agents/helper.md".into(),
            source_revision: Some(fetched.commit_sha.clone()),
            source_digest: definition_digest,
            fetched_at_unix_ms: 2,
        };
        let compensation = harness
            .db
            .agent_replacement_compensation_receipt(original_id, replacement.clone(), 2)
            .await
            .expect("capture prior replacement state");
        harness
            .db
            .replace_agent(replacement, 2)
            .await
            .expect("replace installation");
        harness
            .db
            .compensate_agent_replacement(compensation.clone())
            .await
            .expect("compensate failed publish");
        let staged_digest = sha256_hex(&fetched.markdown);
        let journal = InstallationJournalRow {
            journal_id: Uuid::new_v4(),
            operation_id: operation.operation_id,
            checkpoint: InstallationJournalCheckpoint::DbCommitted,
            staged_file_metadata_json: Some(
                serde_json::to_string(&JournalStagedSource {
                    target_name: "helper".into(),
                    digest: staged_digest.clone(),
                    commit_sha: fetched.commit_sha.clone(),
                    markdown_base64: base64::engine::general_purpose::STANDARD
                        .encode(&fetched.markdown),
                })
                .expect("journal source"),
            ),
            prior_file_metadata_json: Some(
                with_replacement_receipt(None, &compensation).expect("compensation receipt"),
            ),
            expected_digest: staged_digest,
        };
        harness
            .db
            .record_installation_journal(journal, 3)
            .await
            .expect("DB-committed journal");
        assert!(matches!(
            harness.service.begin(request, 4).await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Refused,
                ..
            }
        ));
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
        let restored = harness
            .db
            .agent_installation(original_id)
            .await
            .expect("installation read")
            .expect("original installation remains");
        assert_eq!(restored.source_identity, original.source_identity);
        assert_eq!(
            harness
                .db
                .installation_journal(operation.operation_id)
                .await
                .expect("journal read")
                .expect("journal exists")
                .checkpoint,
            InstallationJournalCheckpoint::Complete
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_recovers_replace_committed_before_checkpoint_at_a_later_retry_time()
     {
        let harness = ServiceHarness::new(FetchReply::Failure("must not refetch".into()));
        let mut request = ServiceHarness::request("replace-before-db-checkpoint");
        request.replace_acknowledged = true;
        let operation = match harness
            .db
            .begin_installation_operation(
                request.idempotency_key.clone(),
                request_fingerprint(&request, None),
                InstallationOperationKind::Install,
                None,
                1,
            )
            .await
            .expect("begin operation")
        {
            BeginInstallationOperation::Created(operation) => operation,
            _ => panic!("expected fresh operation"),
        };
        let old_markdown = b"old daemon-owned definition".to_vec();
        let original = AgentInstallationInput {
            installation_id: Uuid::new_v4(),
            scope: AgentInstallationScope::Global,
            canonical_workspace_id: None,
            source_agent_id: "authored/helper".into(),
            source_identity: "owner/old:agents/helper.md".into(),
            source_revision: Some("b".repeat(40)),
            source_digest: sha256_hex(&old_markdown),
            fetched_at_unix_ms: 0,
        };
        let original_id = original.installation_id;
        harness
            .db
            .install_agent(original.clone())
            .await
            .expect("original installation");
        std::fs::create_dir_all(
            harness
                .target()
                .parent()
                .expect("target has daemon-owned parent"),
        )
        .expect("create daemon-owned parent");
        std::fs::write(harness.target(), &old_markdown).expect("write owned fixture");

        let fetched = ServiceHarness::fetched();
        let replacement = AgentInstallationInput {
            installation_id: operation.operation_id,
            scope: AgentInstallationScope::Global,
            canonical_workspace_id: None,
            source_agent_id: "authored/helper".into(),
            source_identity: "owner/repo:agents/helper.md".into(),
            source_revision: Some(fetched.commit_sha.clone()),
            source_digest: fetched_definition_digest(&fetched),
            fetched_at_unix_ms: operation.created_at_unix_ms,
        };
        let compensation = harness
            .db
            .agent_replacement_compensation_receipt(
                original_id,
                replacement.clone(),
                operation.created_at_unix_ms,
            )
            .await
            .expect("replacement receipt");
        harness
            .db
            .replace_agent(replacement, operation.created_at_unix_ms)
            .await
            .expect("commit replacement before checkpoint");
        let digest = sha256_hex(&fetched.markdown);
        harness
            .db
            .record_installation_journal(
                InstallationJournalRow {
                    journal_id: Uuid::new_v4(),
                    operation_id: operation.operation_id,
                    checkpoint: InstallationJournalCheckpoint::Staged,
                    staged_file_metadata_json: Some(
                        serde_json::to_string(&JournalStagedSource {
                            target_name: "helper".into(),
                            digest: digest.clone(),
                            commit_sha: fetched.commit_sha.clone(),
                            markdown_base64: base64::engine::general_purpose::STANDARD
                                .encode(&fetched.markdown),
                        })
                        .expect("staged source"),
                    ),
                    prior_file_metadata_json: Some(
                        with_replacement_receipt(
                            prior_file_metadata(&harness.target(), operation.operation_id)
                                .expect("prior metadata")
                                .as_deref(),
                            &compensation,
                        )
                        .expect("replacement receipt metadata"),
                    ),
                    expected_digest: digest,
                },
                2,
            )
            .await
            .expect("persist staged journal before simulated crash");

        assert!(matches!(
            harness.service.begin(request, 99).await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Installed,
                ..
            }
        ));
        let row = harness
            .db
            .agent_installation(original_id)
            .await
            .expect("read replacement")
            .expect("replacement exists");
        assert_eq!(row.source_revision, Some(fetched.commit_sha));
        assert_eq!(
            row.installation_revision, 2,
            "recovery must not replace twice"
        );
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn agent_installation_daemon_complete_checkpoint_replays_without_refetch_or_mutation() {
        let harness = ServiceHarness::new(FetchReply::Failure("must not fetch".into()));
        let request = ServiceHarness::request("complete-replay");
        let operation = match harness
            .db
            .begin_installation_operation(
                request.idempotency_key.clone(),
                request_fingerprint(&request, None),
                InstallationOperationKind::Install,
                None,
                1,
            )
            .await
            .expect("begin operation")
        {
            BeginInstallationOperation::Created(operation) => operation,
            _ => panic!("expected operation"),
        };
        let expected = receipt(
            operation.operation_id,
            AgentInstallationReceiptStatusV1::Installed,
            Some("existing-installation".into()),
            Some("a".repeat(40)),
        );
        harness
            .db
            .record_installation_journal(
                InstallationJournalRow {
                    journal_id: Uuid::new_v4(),
                    operation_id: operation.operation_id,
                    checkpoint: InstallationJournalCheckpoint::Complete,
                    staged_file_metadata_json: None,
                    prior_file_metadata_json: None,
                    expected_digest: "fixture-digest".into(),
                },
                2,
            )
            .await
            .expect("complete journal");
        harness
            .db
            .finish_installation_operation(
                operation.operation_id,
                serde_json::to_string(&expected).expect("receipt JSON"),
                2,
            )
            .await
            .expect("finish operation");
        assert_eq!(harness.service.begin(request, 3).await, expected);
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn agent_installation_daemon_unknown_choice_does_not_claim_and_valid_retry_binds() {
        let harness = ServiceHarness::new(FetchReply::Failure("fetch is irrelevant".into()));
        let (_, operation_id, token, choice_id) = prepare_pending_choice(
            &harness,
            "unknown-choice",
            100,
            AgentInstallationOperationKind::Bind,
            false,
        )
        .await;
        let unknown = harness
            .service
            .submit_choice(
                AgentInstallationSubmitChoiceV1 {
                    dto_version: AGENT_INSTALLATION_DTO_VERSION,
                    continuation_token: token.to_string(),
                    choice_id: Some("not-issued".into()),
                    defer: false,
                },
                2,
            )
            .await;
        assert!(matches!(
            unknown,
            AgentInstallationResultV1::Error {
                error: AgentInstallationErrorV1 {
                    code: AgentInstallationErrorCodeV1::UnknownChoice,
                    ..
                }
            }
        ));
        let pending = harness
            .db
            .installation_operation_by_id(operation_id)
            .await
            .expect("operation lookup")
            .expect("operation exists");
        assert_eq!(pending.state, InstallationOperationState::PendingChoice);
        assert_eq!(
            harness
                .db
                .installation_continuation(token)
                .await
                .expect("continuation lookup")
                .expect("continuation exists")
                .submitted_choice_id,
            None
        );
        assert!(matches!(
            harness
                .service
                .submit_choice(
                    AgentInstallationSubmitChoiceV1 {
                        dto_version: AGENT_INSTALLATION_DTO_VERSION,
                        continuation_token: token.to_string(),
                        choice_id: Some(choice_id),
                        defer: false,
                    },
                    3,
                )
                .await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Bound,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn agent_installation_daemon_defer_is_terminal_and_same_choice_submit_replays_receipt() {
        let harness = ServiceHarness::new(FetchReply::Failure("fetch is irrelevant".into()));
        let (_, _, token, _) = prepare_pending_choice(
            &harness,
            "defer-choice",
            100,
            AgentInstallationOperationKind::Bind,
            false,
        )
        .await;
        let request = AgentInstallationSubmitChoiceV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            continuation_token: token.to_string(),
            choice_id: None,
            defer: true,
        };
        let (first, second) = tokio::join!(
            harness.service.submit_choice(request.clone(), 2),
            harness.service.submit_choice(request, 2),
        );
        for result in [first, second] {
            assert!(matches!(
                result,
                AgentInstallationResultV1::Receipt {
                    status: AgentInstallationReceiptStatusV1::PrimaryUnusable,
                    ..
                }
            ));
        }
    }

    #[test]
    fn agent_installation_daemon_every_non_successful_bind_outcome_has_a_typed_terminal_code() {
        use cockpit_db::db::agent_installations::BindAgentOutcome;

        for outcome in [
            BindAgentOutcome::RebindRequired,
            BindAgentOutcome::Conflict,
            BindAgentOutcome::Deleted,
            BindAgentOutcome::NotFound,
        ] {
            assert_eq!(
                terminal_bind_refusal_code(&outcome),
                Some(AgentInstallationErrorCodeV1::StaleBinding)
            );
        }
        assert_eq!(
            terminal_bind_refusal_code(&BindAgentOutcome::Incompatible),
            Some(AgentInstallationErrorCodeV1::IncompatibleModel)
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_claimed_stale_bind_terminalizes_and_replays() {
        let harness = ServiceHarness::new(FetchReply::Failure("fetch is irrelevant".into()));
        let (replay_request, operation_id, token, choice_id) = prepare_pending_choice(
            &harness,
            "stale-terminal",
            100,
            AgentInstallationOperationKind::Bind,
            false,
        )
        .await;
        let state = harness
            .db
            .installation_continuation_state(token)
            .await
            .expect("continuation state")
            .expect("continuation exists");
        let choices: BindChoiceSet =
            serde_json::from_str(&state.continuation.choice_set_json).expect("choice set");
        let installation_id = Uuid::parse_str(&choices.installation_id).expect("installation id");
        harness
            .db
            .delete_agent_installation(installation_id, 2)
            .await
            .expect("delete fixture installation");
        let request = AgentInstallationSubmitChoiceV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            continuation_token: token.to_string(),
            choice_id: Some(choice_id),
            defer: false,
        };
        let first = harness.service.submit_choice(request.clone(), 3).await;
        assert!(matches!(
            &first,
            AgentInstallationResultV1::Error {
                error: AgentInstallationErrorV1 {
                    code: AgentInstallationErrorCodeV1::StaleBinding,
                    ..
                }
            }
        ));
        let operation = harness
            .db
            .installation_operation_by_id(operation_id)
            .await
            .expect("operation read")
            .expect("operation exists");
        assert_eq!(operation.state, InstallationOperationState::Terminal);
        assert_eq!(harness.service.submit_choice(request, 4).await, first);
        let BeginInstallationOperation::Replay(replayed) = harness
            .db
            .begin_installation_operation(
                "stale-terminal".into(),
                request_fingerprint(&replay_request, None),
                InstallationOperationKind::Bind,
                None,
                4,
            )
            .await
            .expect("same-key begin replay")
        else {
            panic!("terminal same-key begin must replay")
        };
        assert_eq!(
            serde_json::from_str::<AgentInstallationResultV1>(
                replayed
                    .terminal_receipt_json
                    .as_deref()
                    .expect("terminal receipt")
            )
            .expect("redacted receipt"),
            first
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_shared_dirty_collision_refuses_before_installation_or_binding_mutation()
     {
        let harness = ServiceHarness::new(FetchReply::Source(ServiceHarness::fetched()));
        let workspace = harness._root.path().join("workspace/.cockpit/agents");
        std::fs::create_dir_all(&workspace).expect("shared agent dir");
        std::fs::write(workspace.join("helper.md"), "hand edited").expect("dirty file");
        let mut request = ServiceHarness::request("shared-dirty");
        request.scope = AgentInstallationScopeWire::WorkspaceShared;
        request.workspace_path = Some("workspace-request".into());
        let AgentInstallationResultV1::Error { error } = harness.service.begin(request, 1).await
        else {
            panic!("dirty shared file must refuse")
        };
        assert_eq!(error.code, AgentInstallationErrorCodeV1::DirtySharedFile);
        let installs = harness
            .db
            .list_agent_installations(
                AgentInstallationScope::WorkspaceShared,
                Some("workspace:test".into()),
            )
            .await
            .expect("list shared installs");
        assert!(installs.is_empty());
        let bindings = harness
            .db
            .read(|conn| {
                Ok(
                    conn.query_row("SELECT COUNT(*) FROM agent_model_bindings", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                )
            })
            .await
            .expect("binding count");
        assert_eq!(bindings, 0);
    }

    #[tokio::test]
    async fn agent_installation_daemon_dirty_update_never_overwrites_the_owned_copy() {
        let harness = ServiceHarness::new(FetchReply::Source(ServiceHarness::fetched()));
        let AgentInstallationResultV1::Receipt {
            installation_id: Some(installation_id),
            ..
        } = harness
            .service
            .begin(ServiceHarness::request("dirty-update-install"), 1)
            .await
        else {
            panic!("initial install must succeed")
        };
        std::fs::write(harness.target(), "locally modified agent").expect("modify owned copy");
        *harness.fetcher.reply.lock().expect("fetcher reply") = FetchReply::Source(FetchedAgentSource {
            commit_sha: "c".repeat(40),
            markdown: b"---\ndescription: refreshed helper\nschemaVersion: 2\nagentId: authored/helper\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\nrefreshed\n".to_vec(),
        });
        let result = harness
            .service
            .begin(
                AgentInstallationBeginV1 {
                    idempotency_key: "dirty-update".into(),
                    operation: AgentInstallationOperationKind::Update,
                    source_locator: "owner/repo@main:agents/helper.md".into(),
                    target_installation_id: Some(installation_id.clone()),
                    replace_acknowledged: true,
                    ..ServiceHarness::request("dirty-update")
                },
                2,
            )
            .await;
        assert!(matches!(
            result,
            AgentInstallationResultV1::Error { error }
                if error.code == AgentInstallationErrorCodeV1::DirtySharedFile
        ));
        assert_eq!(
            std::fs::read_to_string(harness.target()).expect("owned copy remains readable"),
            "locally modified agent"
        );
        assert_eq!(
            harness
                .db
                .agent_installation(Uuid::parse_str(&installation_id).expect("installation id"))
                .await
                .expect("read installation")
                .expect("installation remains")
                .source_revision,
            Some("a".repeat(40))
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_shared_exact_ref_path_and_digest_replays_without_collision()
    {
        let harness = ServiceHarness::new(FetchReply::Source(ServiceHarness::fetched()));
        let mut first = ServiceHarness::request("shared-first");
        first.scope = AgentInstallationScopeWire::WorkspaceShared;
        first.workspace_path = Some("workspace-request".into());
        assert!(matches!(
            harness.service.begin(first, 1).await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Installed,
                ..
            }
        ));
        let mut replay = ServiceHarness::request("shared-exact-replay");
        replay.scope = AgentInstallationScopeWire::WorkspaceShared;
        replay.workspace_path = Some("workspace-request".into());
        assert!(matches!(
            harness.service.begin(replay, 2).await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Installed,
                ..
            }
        ));
        assert_eq!(
            harness
                .db
                .list_agent_installations(
                    AgentInstallationScope::WorkspaceShared,
                    Some("workspace:test".into()),
                )
                .await
                .expect("shared installations")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_install_yes_keeps_install_receipt_and_replays_it() {
        let harness = ServiceHarness::new(FetchReply::Source(ServiceHarness::fetched()));
        let mut request = ServiceHarness::request("install-yes-replay");
        request.auto_select_first_exact = true;
        let first = harness.service.begin(request.clone(), 1).await;
        assert!(matches!(
            &first,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Installed,
                binding_outcome: Some(AgentInstallationBindingOutcomeV1::PrimaryUnusable),
                ..
            }
        ));
        assert_eq!(harness.service.begin(request, 2).await, first);
    }

    fn assert_yes_result_for_kind(
        kind: AgentInstallationOperationKind,
        result: &AgentInstallationResultV1,
    ) {
        match (kind, result) {
            (
                AgentInstallationOperationKind::Install,
                AgentInstallationResultV1::Receipt {
                    status: AgentInstallationReceiptStatusV1::Installed,
                    binding_outcome: Some(AgentInstallationBindingOutcomeV1::Bound),
                    ..
                },
            )
            | (
                AgentInstallationOperationKind::Update,
                AgentInstallationResultV1::Receipt {
                    status: AgentInstallationReceiptStatusV1::Updated,
                    binding_outcome: Some(AgentInstallationBindingOutcomeV1::Bound),
                    ..
                },
            )
            | (
                AgentInstallationOperationKind::Bind,
                AgentInstallationResultV1::Receipt {
                    status: AgentInstallationReceiptStatusV1::Bound,
                    binding_outcome: None,
                    ..
                },
            ) => {}
            _ => panic!("unexpected automatic result for {kind:?}: {result:?}"),
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_yes_replay_resumes_the_original_kind_and_exact_choice() {
        for (label, kind) in [
            ("install", AgentInstallationOperationKind::Install),
            ("update", AgentInstallationOperationKind::Update),
            ("bind", AgentInstallationOperationKind::Bind),
        ] {
            let harness = ServiceHarness::new(FetchReply::Failure("must not fetch".into()));
            let (request, operation_id, token, choice_id) = prepare_pending_choice(
                &harness,
                &format!("yes-before-submit-{label}"),
                100,
                kind,
                true,
            )
            .await;

            // Crash before automatic submission: a same-key begin must use
            // the persisted exact choice rather than call the fetcher or
            // recompute provider ranking.
            let result = harness.service.begin(request.clone(), 2).await;
            assert_yes_result_for_kind(kind, &result);
            assert_eq!(harness.service.begin(request.clone(), 3).await, result);
            let operation = harness
                .db
                .installation_operation_by_id(operation_id)
                .await
                .expect("operation read")
                .expect("operation exists");
            assert_eq!(operation.kind, operation_kind(kind));
            assert_eq!(
                operation.request_fingerprint,
                request_fingerprint(&request, None)
            );
            assert_eq!(operation.state, InstallationOperationState::Terminal);
            assert_eq!(
                serde_json::from_str::<AgentInstallationResultV1>(
                    operation
                        .terminal_receipt_json
                        .as_deref()
                        .expect("terminal receipt")
                )
                .expect("receipt JSON"),
                result
            );
            let continuation = harness
                .db
                .installation_continuation(token)
                .await
                .expect("continuation read")
                .expect("continuation exists");
            let persisted: BindChoiceSet =
                serde_json::from_str(&continuation.choice_set_json).expect("choice set");
            assert_eq!(
                persisted.auto_choice_id.as_deref(),
                Some(choice_id.as_str())
            );
            assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_yes_claim_crash_retries_the_original_kind_and_receipt() {
        for (label, kind) in [
            ("install", AgentInstallationOperationKind::Install),
            ("update", AgentInstallationOperationKind::Update),
            ("bind", AgentInstallationOperationKind::Bind),
        ] {
            let harness = ServiceHarness::new(FetchReply::Failure("must not fetch".into()));
            let (request, operation_id, token, choice_id) = prepare_pending_choice(
                &harness,
                &format!("yes-during-submit-{label}"),
                100,
                kind,
                true,
            )
            .await;

            // Simulate a process loss immediately after the continuation CAS
            // succeeds. The retry has to re-enter that exact claim instead of
            // treating the parent Install/Update as a fresh fetch operation.
            assert!(
                harness
                    .db
                    .claim_installation_continuation(token, choice_id.clone(), 2)
                    .await
                    .expect("claim continuation")
                    .is_some()
            );
            let result = harness.service.begin(request.clone(), 3).await;
            assert_yes_result_for_kind(kind, &result);
            assert_eq!(harness.service.begin(request.clone(), 4).await, result);
            let operation = harness
                .db
                .installation_operation_by_id(operation_id)
                .await
                .expect("operation read")
                .expect("operation exists");
            assert_eq!(operation.kind, operation_kind(kind));
            assert_eq!(
                operation.request_fingerprint,
                request_fingerprint(&request, None)
            );
            assert_eq!(operation.state, InstallationOperationState::Terminal);
            assert_eq!(
                serde_json::from_str::<AgentInstallationResultV1>(
                    operation
                        .terminal_receipt_json
                        .as_deref()
                        .expect("terminal receipt")
                )
                .expect("receipt JSON"),
                result
            );
            assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn agent_installation_daemon_binding_choices_keep_author_collisions_alias_order_and_unsuggested_offerings_distinct()
     {
        let offerings = vec![
            AgentProfileModelOffering {
                offering_id: "a-route".into(),
                provider_profile_handle: "profile-a".into(),
                provider_id: "provider".into(),
                model_id: "exact".into(),
            },
            AgentProfileModelOffering {
                offering_id: "b-route".into(),
                provider_profile_handle: "profile-b".into(),
                provider_id: "provider".into(),
                model_id: "exact".into(),
            },
            AgentProfileModelOffering {
                offering_id: "fuzzy-route".into(),
                provider_profile_handle: "profile-c".into(),
                provider_id: "provider".into(),
                model_id: "exact-latest".into(),
            },
        ];
        let slot = slot(
            vec![ModelCapability::TextGeneration],
            vec![
                recommendation("first", "upstream/one", &[("provider", "exact")]),
                recommendation("second", "upstream/two", &[("provider", "exact")]),
                recommendation("unmatched", "upstream/three", &[("other", "missing")]),
            ],
        );
        let ranked = crate::agents::ranked_compatible_offerings(
            &slot,
            &offerings,
            &providers_for(&offerings),
        );
        let (choices, unmatched) = binding_choices("primary", &slot, &ranked);
        assert_eq!(
            choices
                .iter()
                .map(|choice| choice.choice_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "choice-0-offering-0",
                "choice-0-offering-1",
                "choice-1-offering-0",
                "choice-1-offering-1",
                "choice-local-offering-2",
            ]
        );
        assert!(choices[..4].iter().all(|choice| {
            choice.exact_alias_match
                && choice.author_suggested
                && choice.canonical_upstream_identity.is_some()
        }));
        assert!(!choices[4].author_suggested);
        assert!(
            !choices[4].exact_alias_match,
            "fuzzy names must not match aliases"
        );
        assert_eq!(unmatched.len(), 1);
        assert_eq!(unmatched[0].recommendation_id, "unmatched");
        assert_eq!(
            first_exact_author_choice(&choices).as_deref(),
            Some("choice-0-offering-0"),
            "--yes selects only the first ordered exact author route"
        );
        assert!(first_exact_author_choice(&choices[4..]).is_none());
    }

    #[test]
    fn modes_session_setup_exact_alias_order_unmatched_and_unsuggested_are_stable() {
        let offerings = vec![
            AgentProfileModelOffering {
                offering_id: "route-b".into(),
                provider_profile_handle: "credential-profile-b".into(),
                provider_id: "vendor".into(),
                model_id: "matching".into(),
            },
            AgentProfileModelOffering {
                offering_id: "route-a".into(),
                provider_profile_handle: "credential-profile-a".into(),
                provider_id: "vendor".into(),
                model_id: "matching".into(),
            },
            AgentProfileModelOffering {
                offering_id: "route-fuzzy".into(),
                provider_profile_handle: "credential-profile-c".into(),
                provider_id: "vendor".into(),
                model_id: "matching-newer".into(),
            },
        ];
        let slot = slot(
            vec![ModelCapability::TextGeneration],
            vec![
                recommendation("first", "upstream/one", &[("vendor", "matching")]),
                recommendation("missing", "upstream/missing", &[("elsewhere", "none")]),
            ],
        );
        let ranked = crate::agents::ranked_compatible_offerings(
            &slot,
            &offerings,
            &providers_for(&offerings),
        );
        let (choices, unmatched) = binding_choices("primary", &slot, &ranked);
        assert_eq!(
            choices
                .iter()
                .map(|choice| choice.recommendation_id.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("first"), Some("first"), None]
        );
        assert_eq!(unmatched[0].recommendation_id, "missing");
        assert_eq!(choices[2].model_id, "matching-newer");
        let wire = serde_json::to_string(&choices).expect("setup choices serialize");
        assert!(!wire.contains("credential-profile"));
        assert!(choices.iter().all(|choice| {
            choice.exact_alias_match == choice.author_suggested
                || (!choice.exact_alias_match && !choice.author_suggested)
        }));
    }

    #[test]
    fn modes_session_setup_unavailable_reason_is_closed_and_nonselectable() {
        let slot = SessionSetupModelSlotV1 {
            slot_id: "primary".into(),
            choices: Vec::new(),
            choice_routes: Vec::new(),
            allowed_choice_ids: Vec::new(),
            unmatched_recommendations: vec![AgentInstallationUnmatchedRecommendationV1 {
                recommendation_id: "requires-tools".into(),
                canonical_upstream_identity: "upstream/tools".into(),
                author_label: None,
                rationale: None,
            }],
            default_choice_id: None,
            unavailable_reason: Some(SessionSetupUnavailableReasonV1::NoHardCompatibleLocalModel),
        };
        let encoded = serde_json::to_value(&slot).expect("slot serializes");
        assert_eq!(
            encoded["unavailable_reason"],
            "no_hard_compatible_local_model"
        );
        assert!(encoded.get("choices").is_none());
        assert_eq!(
            encoded["unmatched_recommendations"][0]["recommendation_id"],
            "requires-tools"
        );
    }

    #[tokio::test]
    async fn modes_session_setup_service_snapshot_projects_seeded_scopes_choices_and_redaction() {
        use cockpit_db::db::agent_installations::{AgentBindingInput, BindAgentOutcome};
        use rusqlite::params;

        let providers = binding_providers();
        let harness = ServiceHarness::with_providers(
            FetchReply::Failure("snapshot fixture never fetches".into()),
            providers.clone(),
        );
        let workspace = harness._root.path().join("workspace");
        std::fs::create_dir_all(workspace.join(".cockpit/agents")).expect("workspace agents");
        let workspace_root = AuthorizedWorkspaceRoot::capture(&workspace).expect("workspace proof");
        let workspace_id = "workspace:test".to_owned();

        let reviewer = String::from_utf8(fetched_with_binding_choices("text_generation").markdown)
            .expect("fixture UTF-8")
            .replace("authored/helper", "authored/reviewer");
        let locked = reviewer.replace("authored/reviewer", "authored/locked");
        let definition_digest = |name: &str, markdown: &str| {
            let definition = crate::agents::parse_agent(
                markdown,
                name,
                PathBuf::from(format!("<{name}-fixture>")),
            )
            .expect("fixture definition");
            sha256_hex(
                &definition
                    .vnext_digest_bytes()
                    .expect("fixture vNext digest"),
            )
        };
        let reviewer_digest = definition_digest("reviewer", &reviewer);

        let global_id = Uuid::now_v7();
        let private_id = Uuid::now_v7();
        let shared_id = Uuid::now_v7();
        let locked_id = Uuid::now_v7();
        let install =
            |installation_id, scope, workspace_id: Option<String>, name: &str, digest: String| {
                AgentInstallationInput {
                    installation_id,
                    scope,
                    canonical_workspace_id: workspace_id,
                    source_agent_id: format!("authored/{name}"),
                    source_identity: format!("fixture/repository:agents/{name}.md"),
                    source_revision: Some("a".repeat(40)),
                    source_digest: digest,
                    fetched_at_unix_ms: 1,
                }
            };
        for input in [
            install(
                global_id,
                AgentInstallationScope::Global,
                None,
                "reviewer",
                reviewer_digest.clone(),
            ),
            install(
                private_id,
                AgentInstallationScope::WorkspacePrivate,
                Some(workspace_id.clone()),
                "reviewer",
                reviewer_digest.clone(),
            ),
            install(
                shared_id,
                AgentInstallationScope::WorkspaceShared,
                Some(workspace_id.clone()),
                "reviewer",
                reviewer_digest.clone(),
            ),
            // The durable observation intentionally differs from the held
            // definition. This verifies that a stale binding is exposed as a
            // closed, non-selectable rebind requirement rather than guessed.
            install(
                locked_id,
                AgentInstallationScope::Global,
                None,
                "locked",
                "f".repeat(64),
            ),
        ] {
            assert!(matches!(
                harness
                    .db
                    .install_agent(input)
                    .await
                    .expect("seed installation"),
                InstallAgentOutcome::Installed(_)
            ));
        }

        let daemon_agents = harness._root.path().join("daemon-agents");
        for path in [
            owned_path(
                &daemon_agents,
                None,
                AgentInstallationScopeWire::Global,
                "reviewer",
            )
            .expect("global definition path"),
            owned_path(
                &daemon_agents,
                Some(workspace_root.canonical_path()),
                AgentInstallationScopeWire::WorkspacePrivate,
                "reviewer",
            )
            .expect("private definition path"),
            owned_path(
                &daemon_agents,
                None,
                AgentInstallationScopeWire::Global,
                "locked",
            )
            .expect("locked definition path"),
        ] {
            std::fs::create_dir_all(path.parent().expect("definition parent"))
                .expect("definition parent");
        }
        std::fs::write(
            owned_path(
                &daemon_agents,
                None,
                AgentInstallationScopeWire::Global,
                "reviewer",
            )
            .expect("global definition path"),
            &reviewer,
        )
        .expect("global definition");
        std::fs::write(
            owned_path(
                &daemon_agents,
                Some(workspace_root.canonical_path()),
                AgentInstallationScopeWire::WorkspacePrivate,
                "reviewer",
            )
            .expect("private definition path"),
            &reviewer,
        )
        .expect("private definition");
        std::fs::write(workspace.join(".cockpit/agents/reviewer.md"), &reviewer)
            .expect("shared definition");
        std::fs::write(
            owned_path(
                &daemon_agents,
                None,
                AgentInstallationScopeWire::Global,
                "locked",
            )
            .expect("locked definition path"),
            &locked,
        )
        .expect("locked definition");

        for (installation_id, profile_handle) in [
            (global_id, "credential-profile-global"),
            (private_id, "credential-profile-private"),
            (shared_id, "credential-profile-shared"),
        ] {
            let provenance_payload = format!("fixture-provenance:{installation_id}").into_bytes();
            assert!(matches!(
                harness
                    .db
                    .bind_agent_model(
                        installation_id,
                        reviewer_digest.clone(),
                        None,
                        format!("bind-{installation_id}"),
                        "fixture-bind".into(),
                        AgentBindingInput {
                            slot_id: "primary".into(),
                            provider_profile_handle: profile_handle.into(),
                            model_id: "exact-a".into(),
                            provenance_digest: sha256_hex(&provenance_payload),
                            provenance_payload,
                            hard_capability_verified: true,
                            is_default: true,
                        },
                        2,
                    )
                    .await
                    .expect("seed binding"),
                BindAgentOutcome::Bound(_)
            ));
        }

        let session = harness
            .db
            .create_session(
                "fixture-project",
                workspace.to_string_lossy().as_ref(),
                "reviewer",
            )
            .await
            .expect("session");
        let snapshot_id = Uuid::now_v7();
        let selected_digest = reviewer_digest.clone();
        let selected_id = private_id;
        let session_id = session.session_id;
        harness
            .db
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO agent_profile_snapshots(\
                        snapshot_id,session_id,installation_id,schema_version,canonical_payload,\
                        canonical_payload_digest,definition_digest,binding_revision_map_payload,\
                        binding_revision_map_digest,created_at_unix_ms\
                     ) VALUES(?1,?2,?3,1,?4,?5,?6,?7,?8,1)",
                    params![
                        snapshot_id.to_string(),
                        session_id.to_string(),
                        selected_id.to_string(),
                        b"fixture-profile".as_slice(),
                        "a".repeat(64),
                        selected_digest,
                        b"fixture-bindings".as_slice(),
                        "b".repeat(64),
                    ],
                )?;
                Ok(())
            })
            .await
            .expect("selected immutable profile");

        let fingerprint =
            session_setup_config_fingerprint(&providers).expect("provider fingerprint");
        let snapshot = harness
            .service
            .session_setup_snapshot(
                session_id,
                workspace_id,
                Some(&workspace_root),
                &providers,
                41,
                77,
                &fingerprint,
                true,
            )
            .await
            .expect("seeded service snapshot");
        let again = harness
            .service
            .session_setup_snapshot(
                session_id,
                "workspace:test".into(),
                Some(&workspace_root),
                &providers,
                41,
                77,
                &fingerprint,
                true,
            )
            .await
            .expect("repeat seeded service snapshot");

        assert_eq!(
            snapshot, again,
            "same durable/service authority is deterministic"
        );
        assert_eq!(snapshot.session_id, session_id.to_string());
        assert_eq!(snapshot.config_generation, 41);
        assert_ne!(snapshot.revision, 0);
        assert_eq!(
            snapshot.selected_installation_id,
            Some(private_id.to_string())
        );
        assert_eq!(
            snapshot
                .candidates
                .iter()
                .map(|candidate| (
                    candidate.installation.scope,
                    candidate.installation.source_agent_id.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![
                (AgentInstallationScopeWire::Global, "authored/locked"),
                (AgentInstallationScopeWire::Global, "authored/reviewer"),
                (
                    AgentInstallationScopeWire::WorkspacePrivate,
                    "authored/reviewer"
                ),
                (
                    AgentInstallationScopeWire::WorkspaceShared,
                    "authored/reviewer"
                ),
            ],
            "scope collisions must remain separate and stably ordered"
        );
        let private = snapshot
            .candidates
            .iter()
            .find(|candidate| candidate.installation.installation_id == private_id.to_string())
            .expect("selected private candidate");
        assert!(private.selected);
        let primary = private
            .slots
            .iter()
            .find(|slot| slot.slot_id == "primary")
            .expect("private primary slot");
        assert_eq!(
            primary
                .choices
                .iter()
                .map(|choice| choice.recommendation_id.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("first"), Some("second"), None],
            "exact author aliases precede compatible-but-unsuggested models"
        );
        assert!(
            primary.choices[..2]
                .iter()
                .all(|choice| choice.author_suggested && choice.exact_alias_match)
        );
        assert_eq!(primary.choices[2].model_id, "compatible");
        assert!(!primary.choices[2].author_suggested && !primary.choices[2].exact_alias_match);
        assert_eq!(
            primary.allowed_choice_ids,
            primary.choices[..2]
                .iter()
                .map(|choice| choice.choice_id.clone())
                .collect::<Vec<_>>(),
            "slot-first routes must include only live bound offerings, including their provenance aliases"
        );
        assert_eq!(primary.unmatched_recommendations.len(), 1);
        assert_eq!(
            primary.unmatched_recommendations[0].recommendation_id,
            "missing"
        );
        let locked = snapshot
            .candidates
            .iter()
            .find(|candidate| candidate.installation.installation_id == locked_id.to_string())
            .expect("stale candidate");
        assert_eq!(
            locked.locked_reason,
            Some(SessionSetupLockedReasonV1::RebindRequired)
        );
        assert!(locked.slots.iter().all(|slot| {
            slot.choices.is_empty()
                && slot.unavailable_reason == Some(SessionSetupUnavailableReasonV1::RebindRequired)
        }));

        let response = cockpit_proto::Response::SessionSetupSnapshot {
            snapshot: snapshot.clone(),
        };
        let wire = serde_json::to_string(&response).expect("full Rust wire serialization");
        let decoded: cockpit_proto::Response = serde_json::from_str(&wire).expect("wire decode");
        assert_eq!(
            serde_json::to_string(&decoded).expect("re-encode Rust wire"),
            wire
        );
        assert!(!wire.contains("credential-profile"));
        assert!(!wire.contains(workspace.to_string_lossy().as_ref()));
        assert!(!wire.contains(daemon_agents.to_string_lossy().as_ref()));
    }

    #[tokio::test]
    async fn modes_session_setup_service_snapshot_uses_durable_prepared_fixture() {
        let providers = session_setup_test_support::providers();
        let harness = ServiceHarness::with_providers(
            FetchReply::Failure("session setup fixture never fetches".into()),
            providers.clone(),
        );
        let workspace = harness._root.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace root");
        let daemon_agents = harness._root.path().join("daemon-agents");
        let fixture = session_setup_test_support::seed(&harness.db, &daemon_agents, &workspace)
            .await
            .expect("durable session-setup fixture");
        let workspace_root =
            AuthorizedWorkspaceRoot::capture(&workspace).expect("attached workspace proof");
        let fingerprint =
            session_setup_config_fingerprint(&providers).expect("provider fingerprint");
        let snapshot = harness
            .service
            .session_setup_snapshot(
                fixture.session_id,
                fixture.workspace_id,
                Some(&workspace_root),
                &providers,
                41,
                77,
                &fingerprint,
                true,
            )
            .await
            .expect("durable fixture setup snapshot");

        assert_eq!(
            snapshot.selected_installation_id,
            Some(fixture.selected_installation_id.to_string())
        );
        assert!(snapshot
            .candidates
            .iter()
            .any(|candidate| candidate.installation.scope == AgentInstallationScopeWire::Global));
        assert!(snapshot.candidates.iter().any(|candidate| {
            candidate.installation.scope == AgentInstallationScopeWire::WorkspacePrivate
                && candidate.installation.source_agent_id == "authored/reviewer"
                && candidate.selected
        }));
        assert!(snapshot.candidates.iter().any(|candidate| {
            candidate.installation.source_agent_id == "authored/unavailable"
                && candidate.slots.iter().all(|slot| {
                    slot.unavailable_reason
                        == Some(SessionSetupUnavailableReasonV1::NoHardCompatibleLocalModel)
                })
        }));
        let wire =
            serde_json::to_string(&cockpit_proto::Response::SessionSetupSnapshot { snapshot })
                .expect("redacted setup response");
        assert!(!wire.contains(session_setup_test_support::SELECTED_PROFILE_HANDLE));
        assert!(!wire.contains(workspace.to_string_lossy().as_ref()));
    }

    #[tokio::test]
    async fn modes_session_setup_untrusted_project_source_is_not_rendered() {
        let providers = session_setup_test_support::providers();
        let harness = ServiceHarness::with_providers(
            FetchReply::Failure("session setup fixture never fetches".into()),
            providers.clone(),
        );
        let workspace = harness._root.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace root");
        let daemon_agents = harness._root.path().join("daemon-agents");
        let fixture = session_setup_test_support::seed(&harness.db, &daemon_agents, &workspace)
            .await
            .expect("durable session-setup fixture");
        let workspace_root =
            AuthorizedWorkspaceRoot::capture(&workspace).expect("attached workspace proof");
        let fingerprint =
            session_setup_config_fingerprint(&providers).expect("provider fingerprint");
        let shared_scope = AgentInstallationScopeWire::WorkspaceShared;

        // Trusted: the workspace-shared (project) definition is read, so the
        // candidate is not "definition unavailable".
        let trusted = harness
            .service
            .session_setup_snapshot(
                fixture.session_id,
                fixture.workspace_id.clone(),
                Some(&workspace_root),
                &providers,
                41,
                77,
                &fingerprint,
                true,
            )
            .await
            .expect("trusted setup snapshot");
        let trusted_shared = trusted
            .candidates
            .iter()
            .find(|candidate| candidate.installation.scope == shared_scope)
            .expect("trusted workspace-shared candidate");
        assert_ne!(
            trusted_shared.locked_reason,
            Some(SessionSetupLockedReasonV1::DefinitionUnavailable),
            "a trusted project source has its definition read"
        );

        // Untrusted (Trust -> IgnoreConfig): the project source must not be read
        // or rendered; only its daemon-owned durable identity remains.
        let untrusted = harness
            .service
            .session_setup_snapshot(
                fixture.session_id,
                fixture.workspace_id,
                Some(&workspace_root),
                &providers,
                41,
                77,
                &fingerprint,
                false,
            )
            .await
            .expect("untrusted setup snapshot");
        let untrusted_shared = untrusted
            .candidates
            .iter()
            .find(|candidate| candidate.installation.scope == shared_scope)
            .expect("untrusted workspace-shared candidate still listed by durable identity");
        assert_eq!(
            untrusted_shared.locked_reason,
            Some(SessionSetupLockedReasonV1::DefinitionUnavailable),
            "an untrusted project source must not render its definition"
        );
        assert!(
            untrusted_shared.slots.is_empty(),
            "an untrusted project source renders no slots or choices"
        );
    }

    #[test]
    fn modes_session_setup_scope_collisions_remain_distinct_and_revision_is_deterministic() {
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let candidate = |installation_id: Uuid, scope: AgentInstallationScopeWire| {
            SessionSetupAgentCandidateV1 {
                installation: AgentInstallationRecordV1 {
                    installation_id: installation_id.to_string(),
                    scope,
                    source_agent_id: "authored/reviewer".into(),
                    source_identity: "publisher/repository:agents/reviewer.md".into(),
                    source_revision: Some("a".repeat(40)),
                    source_digest: "b".repeat(64),
                    installation_revision: 3,
                    bindings: Vec::new(),
                },
                selected: installation_id == id_b,
                slots: Vec::new(),
                locked_reason: None,
            }
        };
        let candidates = vec![
            candidate(id_a, AgentInstallationScopeWire::Global),
            candidate(id_b, AgentInstallationScopeWire::WorkspacePrivate),
        ];
        let revision = session_setup_revision(
            Some(id_b),
            &candidates,
            "db-authority",
            7,
            11,
            "provider-authority",
        );
        assert_eq!(
            revision,
            session_setup_revision(
                Some(id_b),
                &candidates,
                "db-authority",
                7,
                11,
                "provider-authority",
            )
        );
        assert_ne!(
            revision,
            session_setup_revision(
                Some(id_b),
                &candidates,
                "db-authority",
                7,
                11,
                "replacement-provider-authority",
            ),
            "a private provider snapshot replacement must invalidate setup CAS authority"
        );
        assert_ne!(
            revision,
            session_setup_revision(
                Some(id_b),
                &candidates,
                "db-authority",
                7,
                12,
                "provider-authority",
            ),
            "a global config authority change must invalidate setup CAS authority"
        );
        let encoded = serde_json::to_string(&candidates).expect("candidates serialize");
        assert!(encoded.contains("global"));
        assert!(encoded.contains("workspace_private"));
        assert_ne!(
            candidates[0].installation.installation_id,
            candidates[1].installation.installation_id
        );
        assert!(!candidates[0].selected);
        assert!(candidates[1].selected);
    }

    #[test]
    fn modes_session_setup_config_fingerprint_tracks_private_provider_authority() {
        let baseline = ProvidersConfig::default();
        let mut changed = ProvidersConfig::default();
        changed.providers.insert(
            "daemon-local-profile".into(),
            ProviderEntry {
                url: "https://provider.example.test/v1".into(),
                ..ProviderEntry::default()
            },
        );
        assert_ne!(
            session_setup_config_fingerprint(&baseline).expect("baseline fingerprint"),
            session_setup_config_fingerprint(&changed).expect("changed fingerprint"),
            "private provider-route changes must invalidate setup authority even when the public generation is unchanged"
        );
    }

    #[test]
    fn modes_session_setup_db_fingerprint_frames_names_types_and_lengths() {
        let one = 1_u64.to_be_bytes();
        let digest = |fields: &[(&str, &str, &[u8])]| {
            let mut hasher = Sha256::new();
            hasher.update(b"cockpit-session-setup-db-snapshot-fingerprint-v1");
            for (name, type_name, value) in fields {
                session_setup_fingerprint_field(&mut hasher, name, type_name, value);
            }
            crate::intel::hex_lower(&hasher.finalize())
        };
        // Both inputs flatten to `abc` under the former concatenation scheme.
        // Their framed authority representations must remain distinct.
        assert_ne!(
            digest(&[
                ("selected_installation_id", "text", b"a"),
                ("installation_id", "text", b"bc"),
            ]),
            digest(&[
                ("selected_installation_id", "text", b"ab"),
                ("installation_id", "text", b"c"),
            ]),
        );
        assert_ne!(
            digest(&[("source_revision", "optional-text:none", b"")]),
            digest(&[("source_revision", "optional-text:some", b"")]),
        );
        assert_ne!(
            digest(&[("binding_revision", "u64", &one)]),
            digest(&[("binding_revision", "text", b"1")]),
        );
    }

    #[test]
    fn agent_installation_daemon_binding_choices_refuse_unknown_hard_capabilities() {
        let offerings = vec![AgentProfileModelOffering {
            offering_id: "candidate".into(),
            provider_profile_handle: "profile".into(),
            provider_id: "provider".into(),
            model_id: "model".into(),
        }];
        let slot = slot(
            vec![
                ModelCapability::TextGeneration,
                ModelCapability::ToolCalling,
            ],
            vec![recommendation(
                "needs-tools",
                "upstream/tools",
                &[("provider", "model")],
            )],
        );
        let ranked = crate::agents::ranked_compatible_offerings(
            &slot,
            &offerings,
            &providers_for(&offerings),
        );
        assert!(
            ranked.is_empty(),
            "unknown host capability must fail closed"
        );
        let (choices, unmatched) = binding_choices("primary", &slot, &ranked);
        assert!(choices.is_empty());
        assert_eq!(unmatched[0].recommendation_id, "needs-tools");
    }

    #[test]
    fn agent_installation_daemon_choice_routes_preserve_exact_profile_handles_without_leaking_them()
    {
        let offerings = vec![
            AgentProfileModelOffering {
                offering_id: "profile-work:model".into(),
                provider_profile_handle: "profile-work".into(),
                provider_id: "vendor".into(),
                model_id: "model".into(),
            },
            AgentProfileModelOffering {
                offering_id: "profile-personal:model".into(),
                provider_profile_handle: "profile-personal".into(),
                provider_id: "vendor".into(),
                model_id: "model".into(),
            },
        ];
        let slot = slot(
            vec![ModelCapability::TextGeneration],
            vec![recommendation(
                "recommended",
                "upstream/vendor-model",
                &[("vendor", "model")],
            )],
        );
        let mut providers = ProvidersConfig::default();
        for profile_handle in ["profile-work", "profile-personal"] {
            let entry = ProviderEntry {
                template: Some("vendor".into()),
                models: vec![ModelEntry {
                    id: "model".into(),
                    context_length: Some(128),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            };
            providers.providers.insert(profile_handle.into(), entry);
        }
        let ranked = crate::agents::ranked_compatible_offerings(&slot, &offerings, &providers);
        let (choices, _) = binding_choices("primary", &slot, &ranked);
        let routes =
            durable_binding_routes(&slot, &ranked, &choices).expect("exact durable routes");
        let wire_routes = session_setup_choice_routes(&choices, &ranked);
        assert_eq!(routes.len(), 2);
        assert_eq!(wire_routes.len(), 2);
        assert_ne!(
            wire_routes[0].route_choice_id, wire_routes[1].route_choice_id,
            "same-display credential profiles require distinct opaque setup routes"
        );
        let wire_json = serde_json::to_string(&wire_routes).expect("wire choice routes");
        assert!(!wire_json.contains("profile-work"));
        assert!(!wire_json.contains("profile-personal"));
        assert_eq!(
            routes
                .iter()
                .map(|route| route.provider_profile_handle.as_str())
                .collect::<Vec<_>>(),
            vec!["profile-personal", "profile-work"]
        );
        let wire = serde_json::to_string(&choices).expect("wire choices");
        assert!(!wire.contains("profile-work"));
        assert!(!wire.contains("profile-personal"));
        let needs_choice_wire = serde_json::to_string(&AgentInstallationResultV1::NeedsChoice {
            continuation_token: "redacted-continuation".into(),
            choices: choices.clone(),
            unmatched_recommendations: vec![],
            expires_at_unix_ms: 1,
        })
        .expect("wire result");
        assert!(!needs_choice_wire.contains("profile-work"));
        assert!(!needs_choice_wire.contains("profile-personal"));
        let error_wire = serde_json::to_string(&redacted_error(anyhow::anyhow!(
            "profile-work credential route failed"
        )))
        .expect("redacted error wire");
        assert!(!error_wire.contains("profile-work"));
        assert!(!error_wire.contains("credential route"));
        let durable = serde_json::to_string(&routes).expect("durable route mapping");
        assert!(durable.contains("profile-work"));
        assert!(durable.contains("profile-personal"));
        assert!(!durable.contains("credential"));
        let mut persisted = BindChoiceSet {
            installation_id: Uuid::new_v4().to_string(),
            definition_digest: "definition-digest".into(),
            expected_observation_revision: 1,
            expected_binding_revision: None,
            choices,
            unmatched_recommendations: vec![],
            routes,
            authored_default_required: false,
            parent_receipt_status: None,
            parent_source_revision: None,
            auto_choice_id: None,
        };
        assert!(validate_durable_choice_set(&persisted).is_ok());
        persisted.routes.push(DurableBindingRoute {
            choice_id: persisted.routes[0].choice_id.clone(),
            slot_id: persisted.routes[0].slot_id.clone(),
            model_id: persisted.routes[0].model_id.clone(),
            provider_profile_handle: "profile-other".into(),
            authored_default: false,
        });
        assert!(validate_durable_choice_set(&persisted).is_err());
    }

    #[test]
    fn binding_submission_deduplicates_choice_aliases_and_preserves_authored_default() {
        let offerings = vec![
            AgentProfileModelOffering {
                offering_id: "route-a".into(),
                provider_profile_handle: "profile".into(),
                provider_id: "vendor".into(),
                model_id: "model-a".into(),
            },
            AgentProfileModelOffering {
                offering_id: "route-b".into(),
                provider_profile_handle: "profile".into(),
                provider_id: "vendor".into(),
                model_id: "model-b".into(),
            },
        ];
        let mut authored_slot = slot(vec![ModelCapability::TextGeneration], vec![]);
        authored_slot.models = vec![
            crate::agents::SlotModelRef {
                provider_id: "vendor".into(),
                model_id: "model-a".into(),
                default: false,
            },
            crate::agents::SlotModelRef {
                provider_id: "vendor".into(),
                model_id: "model-b".into(),
                default: false,
            },
        ];
        let (choices, _) = binding_choices("primary", &authored_slot, &offerings);
        let routes = durable_binding_routes(&authored_slot, &offerings, &choices).unwrap();
        assert_eq!(
            automatic_binding_choice(&authored_slot, &choices, &routes).as_deref(),
            Some(choices[0].choice_id.as_str()),
            "--yes must select the first authored model without suggestedModels"
        );
        let mut choice_set = BindChoiceSet {
            installation_id: Uuid::new_v4().to_string(),
            definition_digest: "digest".into(),
            expected_observation_revision: 1,
            expected_binding_revision: None,
            choices: choices.clone(),
            unmatched_recommendations: vec![],
            routes,
            authored_default_required: true,
            parent_receipt_status: None,
            parent_source_revision: None,
            auto_choice_id: None,
        };
        choice_set.auto_choice_id = Some(choices[0].choice_id.clone());
        assert!(validate_durable_choice_set(&choice_set).is_ok());
        choice_set.auto_choice_id = None;
        let bindings =
            binding_inputs_for_submission(&choice_set, "primary", &choices[1].choice_id).unwrap();
        assert_eq!(bindings.len(), 2);
        assert!(
            bindings
                .iter()
                .find(|binding| binding.model_id == "model-a")
                .is_some_and(|binding| binding.is_default),
            "selecting an alternate route must not redefine the authored default"
        );

        let alias_slot = slot(
            vec![ModelCapability::TextGeneration],
            vec![
                recommendation("first", "upstream/one", &[("vendor", "model-a")]),
                recommendation("second", "upstream/two", &[("vendor", "model-a")]),
            ],
        );
        let alias_offerings = &offerings[..1];
        let (alias_choices, _) = binding_choices("primary", &alias_slot, alias_offerings);
        let alias_routes =
            durable_binding_routes(&alias_slot, alias_offerings, &alias_choices).unwrap();
        let alias_set = BindChoiceSet {
            choices: alias_choices.clone(),
            routes: alias_routes,
            authored_default_required: false,
            ..choice_set
        };
        let alias_bindings =
            binding_inputs_for_submission(&alias_set, "primary", &alias_choices[1].choice_id)
                .unwrap();
        assert_eq!(alias_bindings.len(), 1);
        assert!(alias_bindings[0].is_default);
        assert_eq!(
            serde_json::from_slice::<AgentInstallationChoiceV1>(
                &alias_bindings[0].provenance_payload
            )
            .unwrap()
            .choice_id,
            alias_choices[1].choice_id,
            "submitted alias supplies provenance for its deduplicated durable route"
        );
    }

    #[test]
    fn agent_installation_daemon_custom_profile_key_never_becomes_a_wire_provider_id() {
        let offerings = vec![AgentProfileModelOffering {
            offering_id: "profile-secret:model".into(),
            provider_profile_handle: "profile-secret".into(),
            provider_id: "configured-provider-7".into(),
            model_id: "model".into(),
        }];
        let slot = slot(vec![ModelCapability::TextGeneration], vec![]);
        let (choices, _) = binding_choices("primary", &slot, &offerings);
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].provider_id, "configured-provider-7");
        let wire = serde_json::to_string(&choices).expect("wire choices");
        assert!(!wire.contains("profile-secret"));
        let routes = durable_binding_routes(&slot, &offerings, &choices).expect("durable route");
        assert_eq!(routes[0].provider_profile_handle, "profile-secret");
    }

    #[test]
    fn agent_installation_resolvable_handle_maps_custom_display_token() {
        let mut providers = ProvidersConfig::default();
        providers.providers.insert(
            "profile-secret".into(),
            ProviderEntry {
                template: None,
                models: vec![ModelEntry {
                    id: "glm".into(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let choice = AgentInstallationChoiceV1 {
            choice_id: "choice-local-offering-0".into(),
            slot_id: "primary".into(),
            offering_id: "offering-0".into(),
            provider_id: "configured-provider-0".into(),
            model_id: "glm".into(),
            recommendation_id: None,
            canonical_upstream_identity: None,
            author_label: None,
            rationale: None,
            author_suggested: false,
            exact_alias_match: false,
        };
        assert_eq!(
            resolvable_provider_handle_for_choice(&providers, &choice).as_deref(),
            Some("profile-secret")
        );
    }

    #[test]
    fn prepared_child_route_uses_shared_wire_identity_without_profile_handle_leak() {
        let mut providers = ProvidersConfig::default();
        providers.providers.insert(
            "credential-profile-handle".into(),
            ProviderEntry {
                template: None,
                models: vec![ModelEntry {
                    id: "child-model".into(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let display = wire_provider_id_for_profile_route(
            &providers,
            "credential-profile-handle",
            "child-model",
        )
        .expect("exact custom route");
        assert_eq!(display, "configured-provider-0");
        assert!(!display.contains("credential-profile-handle"));
    }

    #[test]
    fn daemon_owned_resolution_prefers_package_over_flat_like_public_resolution() {
        let root = tempfile::tempdir().expect("tempdir");
        let flat = root.path().join("reviewer.md");
        std::fs::write(&flat, "flat").expect("flat definition");
        let package = root.path().join("reviewer");
        std::fs::create_dir(&package).expect("package directory");
        std::fs::write(package.join("agent.md"), "package").expect("package definition");

        assert_eq!(
            existing_owned_definition_path(
                root.path(),
                None,
                AgentInstallationScopeWire::Global,
                "reviewer",
            )
            .expect("resolved owned definition"),
            package
        );
        assert_eq!(
            crate::agents::agent_path_in(root.path(), "reviewer"),
            package
        );
    }

    /// This target is intentionally exercised by `cargo test --release` in
    /// the release matrix.  The fixture loader and its environment variable
    /// are both cfg(debug_assertions), so a release daemon has no selectable
    /// scripted-fetch path at all.
    #[cfg(not(debug_assertions))]
    #[test]
    fn agent_installation_daemon_release_build_compiles_out_debug_fixture_control() {
        assert!(!cfg!(debug_assertions));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn agent_installation_daemon_debug_fixture_rejects_credential_or_transport_fields() {
        let commit_sha = "b".repeat(40);
        let value = serde_json::json!({
            "commit_sha": commit_sha,
            "markdown": "fixture",
            "workspace_path": ".",
            "providers": {
                "profile": {
                    "template": "vendor",
                    "headers": [{"name": "Authorization", "value": "not-allowed"}]
                }
            }
        });
        assert!(serde_json::from_value::<DebugAgentInstallationFixture>(value).is_err());
    }
}
