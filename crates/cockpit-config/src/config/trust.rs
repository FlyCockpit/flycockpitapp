//! Workspace trust root resolution and runtime enforcement.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

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

static RUNTIME_POLICY: OnceLock<Mutex<Option<WorkspaceTrustPolicy>>> = OnceLock::new();
tokio::task_local! {
    static TASK_POLICY: WorkspaceTrustPolicy;
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
    if let Ok(policy) = TASK_POLICY.try_with(Clone::clone) {
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

pub fn with_workspace_trust_policy<T>(policy: WorkspaceTrustPolicy, f: impl FnOnce() -> T) -> T {
    struct ResetGuard(Option<WorkspaceTrustPolicy>);

    impl Drop for ResetGuard {
        fn drop(&mut self) {
            let previous = self.0.take();
            THREAD_POLICY.with(|cell| {
                *cell.borrow_mut() = previous;
            });
        }
    }

    let previous = THREAD_POLICY.with(|cell| cell.replace(Some(policy)));
    let _guard = ResetGuard(previous);
    f()
}

pub async fn scope_workspace_trust_policy<F, T>(policy: WorkspaceTrustPolicy, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    TASK_POLICY.scope(policy, f).await
}

pub fn project_config_allowed(cockpit_dir: &Path) -> bool {
    let Some(policy) = runtime_policy() else {
        return true;
    };
    if policy.mode == WorkspaceTrustMode::Trust {
        return true;
    }
    !path_is_project_cockpit_layer(cockpit_dir, &policy.root.root)
}

pub fn project_config_write_allowed(cockpit_dir: &Path) -> bool {
    project_config_allowed(cockpit_dir)
}

pub fn enforce_noninteractive_workspace_trust(
    db: &crate::db::Db,
    path: &Path,
) -> Result<WorkspaceTrustPolicy> {
    let policy = resolve_workspace_trust_policy_from_db(db, path)?;
    set_runtime_policy(policy.root.clone(), policy.mode);
    Ok(policy)
}

pub fn resolve_workspace_trust_policy_from_db(
    db: &crate::db::Db,
    path: &Path,
) -> Result<WorkspaceTrustPolicy> {
    let root = resolve_trust_root(path)?;
    let Some(decision) = db.workspace_trust_by_root(&root.root)? else {
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
        mode => Ok(WorkspaceTrustPolicy { root, mode }),
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

pub fn path_is_project_cockpit_under_root(path: &Path, trust_root: &Path) -> bool {
    let cockpit = trust_root.join(".cockpit");
    path == cockpit || path.starts_with(&cockpit)
}

pub fn path_is_project_cockpit_layer(path: &Path, trust_root: &Path) -> bool {
    let path = lexical_absolute(path);
    let trust_root = lexical_absolute(trust_root);
    if path_is_project_cockpit_under_root(&path, &trust_root) {
        return true;
    }
    path.file_name().is_some_and(|name| name == ".cockpit")
        && trust_root.starts_with(path.parent().unwrap_or_else(|| Path::new("/")))
}

pub fn path_blocked_by_workspace_trust(path: &Path) -> bool {
    let Some(policy) = runtime_policy() else {
        return false;
    };
    if policy.mode == WorkspaceTrustMode::Trust {
        return false;
    }
    let path = lexical_absolute(path);
    let root = lexical_absolute(&policy.root.root);
    path == root || path.starts_with(root)
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

fn lexical_absolute(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    lexical_normalize(&abs)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
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
    fn noninteractive_trust_enforcement_fails_without_decision() {
        clear_runtime_policy_for_tests();
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let err = enforce_noninteractive_workspace_trust(&db, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("workspace trust is not set"));
        clear_runtime_policy_for_tests();
    }

    #[test]
    fn noninteractive_trust_enforcement_rejects_untrusted() {
        clear_runtime_policy_for_tests();
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let root = resolve_trust_root(tmp.path()).unwrap();
        db.set_workspace_trust(&root.root, WorkspaceTrustMode::Untrusted)
            .unwrap();
        let err = enforce_noninteractive_workspace_trust(&db, tmp.path()).unwrap_err();
        assert!(err.to_string().contains("is untrusted"));
        clear_runtime_policy_for_tests();
    }

    #[test]
    fn noninteractive_trust_enforcement_accepts_ignore_config() {
        clear_runtime_policy_for_tests();
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let root = resolve_trust_root(tmp.path()).unwrap();
        db.set_workspace_trust(&root.root, WorkspaceTrustMode::IgnoreConfig)
            .unwrap();
        let policy = enforce_noninteractive_workspace_trust(&db, tmp.path()).unwrap();
        assert_eq!(policy.mode, WorkspaceTrustMode::IgnoreConfig);
        assert_eq!(
            runtime_policy().map(|policy| policy.mode),
            Some(WorkspaceTrustMode::IgnoreConfig)
        );
        clear_runtime_policy_for_tests();
    }

    #[test]
    fn runtime_policy_ignores_ambient_env_without_process_cell() {
        clear_runtime_policy_for_tests();
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var(COCKPIT_TRUST_ROOT_ENV, tmp.path());
            std::env::set_var(COCKPIT_TRUST_MODE_ENV, "trust");
        }

        assert!(
            runtime_policy().is_none(),
            "ambient COCKPIT_TRUST_* env vars must not forge runtime trust"
        );
        clear_runtime_policy_for_tests();
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
