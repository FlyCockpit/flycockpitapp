//! Workspace trust root resolution and runtime enforcement.

use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use anyhow::{Context, Result, bail};

use crate::db::workspace_trust::WorkspaceTrustMode;

pub const COCKPIT_TRUST_ROOT_ENV: &str = "COCKPIT_TRUST_ROOT";
pub const COCKPIT_TRUST_MODE_ENV: &str = "COCKPIT_TRUST_MODE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRoot {
    pub opened_path: PathBuf,
    pub root: PathBuf,
    pub kind: TrustRootKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRootKind {
    Git,
    Directory,
}

impl TrustRootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::Directory => "directory",
        }
    }
}

pub fn resolve_trust_root(path: &Path) -> Result<TrustRoot> {
    let opened_path = canonical_dir_path(path)?;
    if let Some(root) = find_worktree_root(&opened_path) {
        return Ok(TrustRoot {
            opened_path,
            root: root
                .canonicalize()
                .with_context(|| format!("canonicalizing git root {}", root.display()))?,
            kind: TrustRootKind::Git,
        });
    }

    Ok(TrustRoot {
        root: opened_path.clone(),
        opened_path,
        kind: TrustRootKind::Directory,
    })
}

fn find_worktree_root(path: &Path) -> Option<PathBuf> {
    let cwd = if path.is_dir() { path } else { path.parent()? };
    let output = Command::new("git")
        .current_dir(cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        None
    } else {
        Some(PathBuf::from(root))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceTrustPolicy {
    pub root: TrustRoot,
    pub mode: WorkspaceTrustMode,
}

/// A DB-resolved policy plus the durable per-root revision that selected it.
/// The revision is intentionally kept separate from [`WorkspaceTrustPolicy`]:
/// task/thread policy propagation describes authority, whereas this value is a
/// short-lived daemon publication fence and must never be inherited ambiently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedWorkspaceTrustPolicy {
    pub policy: WorkspaceTrustPolicy,
    pub revision: i64,
}

/// A fail-closed workspace-trust decision refusal. Keeping this distinct from
/// path-resolution and database failures lets daemon clients branch on trust
/// without mislabeling storage faults as user decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceTrustError {
    Unset { root: PathBuf },
    Untrusted { root: PathBuf },
}

impl std::fmt::Display for WorkspaceTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unset { root } => write!(
                f,
                "workspace trust is not set for {}. Open the TUI once or run `cockpit trust set {} --mode trust|ignore-config|untrusted`.",
                root.display(),
                root.display()
            ),
            Self::Untrusted { root } => write!(
                f,
                "workspace {} is untrusted and cannot be opened. Change it with `cockpit trust set {} --mode trust|ignore-config`.",
                root.display(),
                root.display()
            ),
        }
    }
}

impl std::error::Error for WorkspaceTrustError {}

/// A daemon worker keeps this cell for its lifetime.  A workspace-trust
/// update replaces the value only after the daemon has published the matching
/// retained config snapshot.  Keeping the cell rather than a copied policy in
/// a task-local is important: a long-lived driver must not retain `Trust`
/// after the durable decision becomes `IgnoreConfig`.
pub type SharedWorkspaceTrustPolicy = Arc<RwLock<WorkspaceTrustPolicy>>;

static RUNTIME_POLICY: OnceLock<Mutex<Option<WorkspaceTrustPolicy>>> = OnceLock::new();
tokio::task_local! {
    static TASK_POLICY: SharedWorkspaceTrustPolicy;
}
thread_local! {
    static THREAD_POLICY: std::cell::RefCell<Option<WorkspaceTrustPolicy>> = const { std::cell::RefCell::new(None) };
}

fn runtime_policy_cell() -> &'static Mutex<Option<WorkspaceTrustPolicy>> {
    RUNTIME_POLICY.get_or_init(|| Mutex::new(None))
}

pub fn set_runtime_policy(root: TrustRoot, mode: WorkspaceTrustMode) {
    // SAFETY: callers invoke this during command startup before we spawn
    // daemon/builder children that must inherit the same trust policy.
    unsafe {
        std::env::set_var(COCKPIT_TRUST_ROOT_ENV, &root.root);
        std::env::set_var(COCKPIT_TRUST_MODE_ENV, mode.as_str());
    }
    let mut guard = runtime_policy_cell()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = Some(WorkspaceTrustPolicy { root, mode });
}

pub fn clear_runtime_policy_for_tests() {
    let mut guard = runtime_policy_cell()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = None;
    unsafe {
        std::env::remove_var(COCKPIT_TRUST_ROOT_ENV);
        std::env::remove_var(COCKPIT_TRUST_MODE_ENV);
    }
}

pub fn runtime_policy() -> Option<WorkspaceTrustPolicy> {
    if let Ok(policy) = TASK_POLICY.try_with(read_shared_workspace_trust_policy) {
        return Some(policy);
    }
    if let Some(policy) = THREAD_POLICY.with(|cell| cell.borrow().clone()) {
        return Some(policy);
    }
    if let Some(policy) = runtime_policy_cell()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return Some(policy);
    }
    None
}

#[must_use = "dropping the guard immediately restores the previous workspace trust policy"]
pub struct ThreadWorkspaceTrustGuard {
    previous: Option<WorkspaceTrustPolicy>,
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for ThreadWorkspaceTrustGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        THREAD_POLICY.with(|cell| {
            *cell.borrow_mut() = previous;
        });
    }
}

/// Install a workspace-trust policy for synchronous work on the current
/// thread. Async code must use [`scope_workspace_trust_policy`] so the policy
/// follows the task if Tokio moves it between worker threads.
pub fn enter_workspace_trust_policy(policy: WorkspaceTrustPolicy) -> ThreadWorkspaceTrustGuard {
    let previous = THREAD_POLICY.with(|cell| cell.replace(Some(policy)));
    ThreadWorkspaceTrustGuard {
        previous,
        _not_send: std::marker::PhantomData,
    }
}

pub fn with_workspace_trust_policy<T>(policy: WorkspaceTrustPolicy, f: impl FnOnce() -> T) -> T {
    let _guard = enter_workspace_trust_policy(policy);
    f()
}

pub fn shared_workspace_trust_policy(policy: WorkspaceTrustPolicy) -> SharedWorkspaceTrustPolicy {
    Arc::new(RwLock::new(policy))
}

pub fn read_shared_workspace_trust_policy(
    policy: &SharedWorkspaceTrustPolicy,
) -> WorkspaceTrustPolicy {
    policy
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Replace the policy observed by an already-running daemon worker.  This is
/// deliberately a narrow operation: callers must first publish a matching
/// capability-projected snapshot under the daemon's publication coordinator.
pub fn replace_shared_workspace_trust_policy(
    policy: &SharedWorkspaceTrustPolicy,
    replacement: WorkspaceTrustPolicy,
) {
    *policy
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = replacement;
}

pub async fn scope_workspace_trust_policy<F, T>(policy: WorkspaceTrustPolicy, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    scope_shared_workspace_trust_policy(shared_workspace_trust_policy(policy), f).await
}

/// Scope async work to a mutable daemon-owned policy cell.  Normal callers
/// should use [`scope_workspace_trust_policy`]; this exists for long-lived
/// session workers whose durable trust decision can change while they run.
pub async fn scope_shared_workspace_trust_policy<F, T>(
    policy: SharedWorkspaceTrustPolicy,
    f: F,
) -> T
where
    F: std::future::Future<Output = T>,
{
    TASK_POLICY.scope(policy, f).await
}

/// Return the effective policy for propagation into blocking worker threads.
/// Task-local trust does not cross thread or database executor boundaries.
pub fn current_workspace_trust_policy() -> Option<WorkspaceTrustPolicy> {
    runtime_policy()
}

pub fn project_config_allowed(cockpit_dir: &Path) -> bool {
    project_config_allowed_for_policy(cockpit_dir, runtime_policy().as_ref())
}

/// [`project_config_allowed`] against an explicit policy rather than the
/// ambient one. `None` (no policy resolved) fails closed.
pub fn project_config_allowed_for_policy(
    cockpit_dir: &Path,
    policy: Option<&WorkspaceTrustPolicy>,
) -> bool {
    let Some(policy) = policy else {
        return false;
    };
    if policy.mode == WorkspaceTrustMode::Trust {
        return true;
    }
    !path_is_project_cockpit_layer(cockpit_dir, &policy.root.root)
}

pub fn project_config_write_allowed(cockpit_dir: &Path) -> bool {
    project_config_allowed(cockpit_dir)
}

pub async fn enforce_noninteractive_workspace_trust(
    db: &crate::db::Db,
    path: &Path,
) -> Result<WorkspaceTrustPolicy> {
    let policy = resolve_workspace_trust_policy_from_db(db, path).await?;
    set_runtime_policy(policy.root.clone(), policy.mode);
    Ok(policy)
}

pub async fn resolve_workspace_trust_policy_from_db(
    db: &crate::db::Db,
    path: &Path,
) -> Result<WorkspaceTrustPolicy> {
    Ok(
        resolve_workspace_trust_policy_with_revision_from_db(db, path)
            .await?
            .policy,
    )
}

/// Resolve trust for a persisted artifact whose workspace may no longer
/// exist. A missing workspace cannot contribute a project config layer, so an
/// `IgnoreConfig` policy over its already-persisted lexical root is the
/// fail-closed historical projection. Other filesystem errors, including a
/// broken symlink, remain hard failures. Live attach/open paths must continue
/// to use [`resolve_workspace_trust_policy_from_db`].
pub async fn resolve_historical_workspace_trust_policy_from_db(
    db: &crate::db::Db,
    path: &Path,
) -> Result<WorkspaceTrustPolicy> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => resolve_workspace_trust_policy_from_db(db, path).await,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The persisted root is absolute; a relative one is refused
            // rather than resolved against the process working directory.
            anyhow::ensure!(
                path.is_absolute(),
                "historical workspace {} is not an absolute path",
                path.display()
            );
            let root = comparable_path(path)
                .with_context(|| format!("inspecting historical workspace {}", path.display()))?;
            Ok(WorkspaceTrustPolicy {
                root: TrustRoot {
                    opened_path: root.clone(),
                    root,
                    kind: TrustRootKind::Directory,
                },
                mode: WorkspaceTrustMode::IgnoreConfig,
            })
        }
        Err(error) => Err(error)
            .with_context(|| format!("inspecting historical workspace {}", path.display())),
    }
}

/// Resolve the policy and its durable generation in one database observation.
/// Callers that perform asynchronous preflight before publishing a worker or a
/// replacement snapshot must retain `revision` and re-read it at the final
/// publication fence.
pub async fn resolve_workspace_trust_policy_with_revision_from_db(
    db: &crate::db::Db,
    path: &Path,
) -> Result<ResolvedWorkspaceTrustPolicy> {
    let root = resolve_trust_root(path)?;
    let Some(decision) = db.workspace_trust_by_root(&root.root).await? else {
        return Err(WorkspaceTrustError::Unset {
            root: root.root.clone(),
        }
        .into());
    };
    match decision.mode {
        WorkspaceTrustMode::Untrusted => Err(WorkspaceTrustError::Untrusted {
            root: root.root.clone(),
        }
        .into()),
        mode => Ok(ResolvedWorkspaceTrustPolicy {
            policy: WorkspaceTrustPolicy { root, mode },
            revision: decision.revision,
        }),
    }
}

pub fn apply_trusted_workspace(root: TrustRoot, mode: WorkspaceTrustMode) -> Result<()> {
    match mode {
        WorkspaceTrustMode::Untrusted => bail!(
            "workspace {} is untrusted and cannot be opened. Change it with `cockpit trust set {} --mode trust|ignore-config`.",
            root.root.display(),
            root.root.display()
        ),
        mode => {
            set_runtime_policy(root, mode);
            Ok(())
        }
    }
}

/// Whether `path` is (or lies inside) a project `.cockpit` configuration
/// layer relative to `trust_root`: some location the path passes through —
/// the entry as spelled in its canonical parent, or its resolved target — has
/// a `.cockpit` component whose parent is the trust root, an ancestor of it,
/// or a directory inside it. See [`traversal_locations`].
///
/// A path that cannot be classified (relative, dangling link, I/O error) is a
/// project layer: it cannot be proven outside the root (fail closed).
pub fn path_is_project_cockpit_layer(path: &Path, trust_root: &Path) -> bool {
    classify_project_cockpit_layer(path, trust_root).unwrap_or(true)
}

fn classify_project_cockpit_layer(path: &Path, trust_root: &Path) -> std::io::Result<bool> {
    let root = comparable_path(trust_root)?;
    Ok(traversal_locations(path)?
        .iter()
        .any(|location| location_in_project_cockpit(location, &root)))
}

/// Whether `path` has a `.cockpit` component in any location it passes
/// through, whatever root it belongs to. Without a trust policy no root is
/// known, so every such path is treated as a project layer.
fn path_traverses_any_cockpit_dir(path: &Path) -> std::io::Result<bool> {
    Ok(traversal_locations(path)?.iter().any(|location| {
        location.components().any(
            |component| matches!(component, Component::Normal(name) if is_cockpit_dir_name(name)),
        )
    }))
}

/// The one write-side trust decision for a configuration file under an
/// explicit policy (`None`: no policy is in force). A file that passes
/// through a project `.cockpit` directory (see
/// [`path_is_project_cockpit_layer`]) is writable only under `Trust`; with no
/// policy, every file that passes through any `.cockpit` directory is
/// refused. Files elsewhere (the global and machine-local layers, an operator
/// override outside every project) need no trust.
pub fn config_file_write_decision(
    path: &Path,
    policy: Option<&WorkspaceTrustPolicy>,
) -> Result<(), ConfigWriteRefusal> {
    match policy {
        Some(policy) if policy.mode == WorkspaceTrustMode::Trust => Ok(()),
        Some(policy) => match classify_project_cockpit_layer(path, &policy.root.root) {
            Ok(false) => Ok(()),
            Ok(true) => Err(ConfigWriteRefusal::UntrustedProjectLayer),
            Err(_) => Err(ConfigWriteRefusal::Unclassifiable),
        },
        None => match path_traverses_any_cockpit_dir(path) {
            Ok(false) => Ok(()),
            Ok(true) => Err(ConfigWriteRefusal::NoWorkspacePolicy),
            Err(_) => Err(ConfigWriteRefusal::Unclassifiable),
        },
    }
}

/// Why a configuration write was refused by workspace trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigWriteRefusal {
    /// The file sits in a project `.cockpit` layer the policy does not trust.
    UntrustedProjectLayer,
    /// The file sits in a `.cockpit` layer and no workspace-trust policy is
    /// in force, so it cannot be proven trusted.
    NoWorkspacePolicy,
    /// The path could not be classified (relative, a dangling link, or an
    /// I/O error while resolving it).
    Unclassifiable,
}

impl std::fmt::Display for ConfigWriteRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UntrustedProjectLayer => {
                "it is in a project .cockpit layer that workspace trust does not allow writing"
            }
            Self::NoWorkspacePolicy => {
                "it is in a project .cockpit layer and no workspace-trust decision is in force"
            }
            Self::Unclassifiable => "its location could not be resolved to check workspace trust",
        })
    }
}

/// Whether an ambient-trust-gated path (skill or agent definition directory,
/// a command's working directory) must be ignored: outside `Trust`, every
/// path any of whose traversed locations (entry as spelled, or resolved
/// target) is at or under the trust root is blocked. No policy blocks
/// everything, and an unclassifiable path is blocked (fail closed).
pub fn path_blocked_by_workspace_trust(path: &Path) -> bool {
    let Some(policy) = runtime_policy() else {
        return true;
    };
    if policy.mode == WorkspaceTrustMode::Trust {
        return false;
    }
    let classify = || -> std::io::Result<bool> {
        let root = comparable_path(&policy.root.root)?;
        Ok(traversal_locations(path)?
            .iter()
            .any(|location| location.starts_with(&root)))
    };
    classify().unwrap_or(true)
}

fn is_cockpit_dir_name(name: &std::ffi::OsStr) -> bool {
    // Case-insensitive volumes (the macOS and Windows defaults) open
    // `.COCKPIT` as `.cockpit`.
    #[cfg(any(target_os = "macos", windows))]
    {
        name.to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(".cockpit"))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        name == ".cockpit"
    }
}

/// Whether `location` has a `.cockpit` component whose parent is `root`, an
/// ancestor of `root`, or a directory inside `root`.
fn location_in_project_cockpit(location: &Path, root: &Path) -> bool {
    let mut parent = PathBuf::new();
    for component in location.components() {
        if let Component::Normal(name) = component
            && is_cockpit_dir_name(name)
            && (root.starts_with(&parent) || parent.starts_with(root))
        {
            return true;
        }
        parent.push(component.as_os_str());
    }
    false
}

/// Every location the filesystem visits when it opens `path`: for each
/// component, its *entry* (the component as spelled, inside the canonical
/// form of everything before it) and, when the entry exists, its *resolved*
/// form (`canonicalize`). Trust must judge both — the entry because a
/// `.cockpit` that is itself a symlink is still the project's `.cockpit`
/// layer, and the resolved form because a link elsewhere can lead into one.
///
/// Relative input is refused rather than resolved against the process
/// working directory. `..` is applied to the canonical prefix (the physical
/// parent, as the kernel applies it), never popped lexically across a link.
/// A missing tail is appended as spelled (it contains no links). A dangling
/// link or any error other than absence is an error; callers fail closed.
fn traversal_locations(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    Ok(walk_path(path)?.0)
}

/// The canonical form of `path`'s existing prefix plus its missing tail, as
/// the same walk as [`traversal_locations`] computes it.
fn comparable_path(path: &Path) -> std::io::Result<PathBuf> {
    Ok(walk_path(path)?.1)
}

fn walk_path(path: &Path) -> std::io::Result<(Vec<PathBuf>, PathBuf)> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "`{}` is relative; workspace trust never resolves against the working directory",
                path.display()
            ),
        ));
    }
    let mut locations = Vec::new();
    let mut current = PathBuf::new();
    // Number of trailing components of `current` that do not exist. They are
    // plain names (a missing entry cannot be a link), so popping them is exact.
    let mut missing = 0usize;
    for component in path.components() {
        match component {
            Component::Prefix(_) => current.push(component.as_os_str()),
            Component::RootDir => {
                current.push(component.as_os_str());
                current = std::fs::canonicalize(&current)?;
            }
            Component::CurDir => {}
            Component::ParentDir => {
                missing = missing.saturating_sub(1);
                // `current` is canonical or a missing tail over a canonical
                // prefix, so its parent is the physical parent.
                current.pop();
            }
            Component::Normal(name) => {
                let entry = current.join(name);
                locations.push(entry.clone());
                if missing > 0 {
                    missing += 1;
                    current = entry;
                    continue;
                }
                match std::fs::canonicalize(&entry) {
                    Ok(resolved) => {
                        refuse_unprovable_reparse_spelling(&entry, name)?;
                        locations.push(resolved.clone());
                        current = resolved;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        match std::fs::symlink_metadata(&entry) {
                            Err(absent) if absent.kind() == std::io::ErrorKind::NotFound => {
                                missing = 1;
                                current = entry;
                            }
                            Ok(_) => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::NotFound,
                                    format!("`{}` is a dangling link", entry.display()),
                                ));
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }
    }
    Ok((locations, current))
}

/// On Windows an entry may be spelled by its 8.3 short name (`COCKPI~1`).
/// For an ordinary entry the resolved form carries the long name, but for a
/// reparse point (symlink or junction) the resolved form is the target, so
/// the entry's own long name is never observed. Such a spelling cannot be
/// classified and is refused.
#[cfg(windows)]
fn refuse_unprovable_reparse_spelling(entry: &Path, name: &std::ffi::OsStr) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let short_spelling = name.to_string_lossy().contains('~');
    if short_spelling
        && std::fs::symlink_metadata(entry)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "`{}` is a link spelled by a short name; spell it by its long name",
                entry.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn refuse_unprovable_reparse_spelling(
    _entry: &Path,
    _name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    Ok(())
}

fn canonical_dir_path(path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", path.display()))?;
    if canonical.is_dir() {
        return Ok(canonical);
    }

    canonical
        .parent()
        .map(Path::to_path_buf)
        .context("path has no parent directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_init(path: &Path) {
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(path)
            .status()
            .expect("run git init");
        assert!(status.success(), "git init failed in {}", path.display());
    }

    #[test]
    fn non_git_directory_is_its_own_trust_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = resolve_trust_root(tmp.path()).unwrap();

        assert_eq!(root.opened_path, tmp.path().canonicalize().unwrap());
        assert_eq!(root.root, tmp.path().canonicalize().unwrap());
        assert_eq!(root.kind, TrustRootKind::Directory);
    }

    #[test]
    fn git_subdirectory_inherits_worktree_root() {
        let tmp = tempfile::tempdir().unwrap();
        git_init(tmp.path());
        let subdir = tmp.path().join("a/b");
        std::fs::create_dir_all(&subdir).unwrap();

        let root = resolve_trust_root(&subdir).unwrap();

        assert_eq!(root.root, tmp.path().canonicalize().unwrap());
        assert_eq!(root.kind, TrustRootKind::Git);
    }

    #[test]
    fn nested_git_repository_is_separate_trust_root() {
        let tmp = tempfile::tempdir().unwrap();
        git_init(tmp.path());
        let nested = tmp.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        git_init(&nested);
        let nested_subdir = nested.join("src");
        std::fs::create_dir(&nested_subdir).unwrap();

        let root = resolve_trust_root(&nested_subdir).unwrap();

        assert_eq!(root.root, nested.canonicalize().unwrap());
        assert_eq!(root.kind, TrustRootKind::Git);
    }

    #[test]
    fn lexical_variants_resolve_to_same_canonical_root() {
        let tmp = tempfile::tempdir().unwrap();
        let subdir = tmp.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();

        let direct = resolve_trust_root(tmp.path()).unwrap();
        let variant = resolve_trust_root(&subdir.join("..")).unwrap();

        assert_eq!(direct.root, variant.root);
    }

    #[test]
    fn absent_policy_disallows_project_config() {
        let _env = crate::test_env::lock();
        clear_runtime_policy_for_tests();
        let tmp = tempfile::tempdir().unwrap();
        assert!(!project_config_allowed(&tmp.path().join(".cockpit")));
    }

    #[test]
    fn absent_policy_blocks_trust_gated_paths() {
        let _env = crate::test_env::lock();
        clear_runtime_policy_for_tests();
        let tmp = tempfile::tempdir().unwrap();
        assert!(path_blocked_by_workspace_trust(tmp.path()));
    }

    #[tokio::test]
    async fn noninteractive_trust_enforcement_fails_without_decision() {
        let _env = crate::test_env::lock_async().await;
        clear_runtime_policy_for_tests();
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let err = enforce_noninteractive_workspace_trust(&db, tmp.path())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("workspace trust is not set"));
        clear_runtime_policy_for_tests();
    }

    #[tokio::test]
    async fn noninteractive_trust_enforcement_rejects_untrusted() {
        let _env = crate::test_env::lock_async().await;
        clear_runtime_policy_for_tests();
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let root = resolve_trust_root(tmp.path()).unwrap();
        db.set_workspace_trust(&root.root, WorkspaceTrustMode::Untrusted)
            .await
            .unwrap();
        let err = enforce_noninteractive_workspace_trust(&db, tmp.path())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("is untrusted"));
        clear_runtime_policy_for_tests();
    }

    #[tokio::test]
    async fn noninteractive_trust_enforcement_accepts_ignore_config() {
        let _env = crate::test_env::lock_async().await;
        clear_runtime_policy_for_tests();
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let root = resolve_trust_root(tmp.path()).unwrap();
        db.set_workspace_trust(&root.root, WorkspaceTrustMode::IgnoreConfig)
            .await
            .unwrap();
        let policy = enforce_noninteractive_workspace_trust(&db, tmp.path())
            .await
            .unwrap();
        assert_eq!(policy.mode, WorkspaceTrustMode::IgnoreConfig);
        assert_eq!(
            runtime_policy().map(|policy| policy.mode),
            Some(WorkspaceTrustMode::IgnoreConfig)
        );
        clear_runtime_policy_for_tests();
    }

    #[test]
    fn runtime_policy_ignores_ambient_env_without_process_cell() {
        let env = crate::test_env::lock();
        clear_runtime_policy_for_tests();
        let tmp = tempfile::tempdir().unwrap();
        env.set_var(COCKPIT_TRUST_ROOT_ENV, tmp.path());
        env.set_var(COCKPIT_TRUST_MODE_ENV, "trust");

        assert!(
            runtime_policy().is_none(),
            "ambient COCKPIT_TRUST_* env vars must not forge runtime trust"
        );
        clear_runtime_policy_for_tests();
    }

    #[tokio::test]
    async fn shared_task_policy_observes_live_replacement() {
        let tmp = tempfile::tempdir().unwrap();
        let root = resolve_trust_root(tmp.path()).unwrap();
        let shared = shared_workspace_trust_policy(WorkspaceTrustPolicy {
            root: root.clone(),
            mode: WorkspaceTrustMode::Trust,
        });
        let replacement = WorkspaceTrustPolicy {
            root,
            mode: WorkspaceTrustMode::IgnoreConfig,
        };
        let shared_for_scope = shared.clone();

        scope_shared_workspace_trust_policy(shared_for_scope, async {
            assert_eq!(
                current_workspace_trust_policy().map(|policy| policy.mode),
                Some(WorkspaceTrustMode::Trust)
            );
            replace_shared_workspace_trust_policy(&shared, replacement);
            assert_eq!(
                current_workspace_trust_policy().map(|policy| policy.mode),
                Some(WorkspaceTrustMode::IgnoreConfig)
            );
        })
        .await;
    }

    #[test]
    fn project_layer_above_trust_root_is_classified() {
        let tmp = tempfile::tempdir().unwrap();
        let parent_cockpit = tmp.path().join("evil/.cockpit");
        let nested_root = tmp.path().join("evil/sub");
        std::fs::create_dir_all(&parent_cockpit).unwrap();
        std::fs::create_dir_all(&nested_root).unwrap();

        assert!(path_is_project_cockpit_layer(&parent_cockpit, &nested_root));
        assert!(path_is_project_cockpit_layer(
            &nested_root.join(".cockpit"),
            &nested_root
        ));
        assert!(!path_is_project_cockpit_layer(
            &tmp.path().join("home/.cockpit"),
            &nested_root
        ));
    }
}
