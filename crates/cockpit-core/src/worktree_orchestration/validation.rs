//! Serialized Rust candidate validation in the primary integration tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::git::{self, UncommittedPatch};
use crate::locks::LockManager;

use super::integration::{acquire_exclusive_target_paths, release_exclusive_target_paths};

/// Evidence recorded with an artifact. Never includes a cargo invocation
/// from a worker worktree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationEvidence {
    pub wrapper: PathBuf,
    pub primary: PathBuf,
    pub argv: Vec<String>,
    pub exit_code: i32,
    pub restored: bool,
}

#[derive(Debug, Clone)]
pub struct CandidateValidation {
    pub primary: PathBuf,
    pub wrapper: PathBuf,
    pub cargo_bin: PathBuf,
    cancel: Option<CancellationToken>,
    locks: Option<Arc<LockManager>>,
    lock_identity: String,
    session: Uuid,
}

impl CandidateValidation {
    pub fn for_primary(primary: impl Into<PathBuf>) -> Self {
        Self {
            primary: primary.into(),
            wrapper: wt_test_wrapper_path(),
            cargo_bin: PathBuf::from("cargo"),
            cancel: None,
            locks: None,
            lock_identity: String::new(),
            session: Uuid::nil(),
        }
    }

    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Bind the daemon `LockManager` used by integration and write/edit tools.
    /// Candidate validation mutates the primary tree and must serialize on
    /// those same path keys.
    pub fn with_locks(
        mut self,
        locks: Arc<LockManager>,
        lock_identity: impl Into<String>,
        session: Uuid,
    ) -> Self {
        self.locks = Some(locks);
        self.lock_identity = lock_identity.into();
        self.session = session;
        self
    }

    /// Apply `overlay` in the primary tree under the workspace lock domain and
    /// the wrapper lock, run the wrapper, and restore the exact prevalidation
    /// receipt on success or failure. Worker worktrees are refused before any
    /// command is spawned.
    pub async fn validate_overlay(
        &self,
        overlay: &BTreeMap<PathBuf, Vec<u8>>,
        cargo_args: &[&str],
    ) -> Result<ValidationEvidence> {
        worker_must_not_invoke_cargo(&self.primary)?;
        let affected = overlay.keys().map(|rel| self.primary.join(rel));
        self.with_exclusive_target(affected, || self.validate_overlay_held(overlay, cargo_args))
            .await
    }

    /// Validate the exact commitless artifact in the primary tree. This is
    /// intentionally separate from worker execution: the worker only creates
    /// the patch, while Cargo is invoked through `wt-test.sh` in primary.
    pub async fn validate_patch(
        &self,
        patch: &UncommittedPatch,
        cargo_args: &[&str],
    ) -> Result<ValidationEvidence> {
        worker_must_not_invoke_cargo(&self.primary)?;
        patch.validate_paths()?;
        let affected = patch
            .touched_paths
            .iter()
            .chain(&patch.untracked_paths)
            .map(|rel| self.primary.join(rel));
        self.with_exclusive_target(affected, || self.validate_patch_held(patch, cargo_args))
            .await
    }

    async fn with_exclusive_target<F>(
        &self,
        affected: impl IntoIterator<Item = PathBuf>,
        mutate: F,
    ) -> Result<ValidationEvidence>
    where
        F: FnOnce() -> Result<ValidationEvidence>,
    {
        let locks = self.locks.as_ref().context(
            "candidate validation requires the workspace LockManager; refusing unlocked primary-tree mutation",
        )?;
        let held = acquire_exclusive_target_paths(
            locks,
            &self.lock_identity,
            self.session,
            &self.primary,
            affected,
        )
        .await?;
        let result = mutate();
        release_exclusive_target_paths(locks, &self.lock_identity, self.session, held).await;
        result
    }

    fn validate_overlay_held(
        &self,
        overlay: &BTreeMap<PathBuf, Vec<u8>>,
        cargo_args: &[&str],
    ) -> Result<ValidationEvidence> {
        let _lock = ValidationLock::acquire(&self.primary, self.cancel.as_ref())?;
        let snapshot = PathOverlaySnapshot::capture(&self.primary, overlay.keys().cloned())?;
        let pre = git::byte_identical_receipt(&self.primary)?;
        let run = (|| {
            apply_overlay(&self.primary, overlay)?;
            run_wrapper(self, cargo_args)
        })();
        snapshot.restore(&self.primary)?;
        let post = git::byte_identical_receipt(&self.primary)?;
        if pre != post {
            bail!("candidate validation failed to restore the prevalidation receipt");
        }
        let mut evidence = run?;
        evidence.restored = true;
        Ok(evidence)
    }

    fn validate_patch_held(
        &self,
        patch: &UncommittedPatch,
        cargo_args: &[&str],
    ) -> Result<ValidationEvidence> {
        let _lock = ValidationLock::acquire(&self.primary, self.cancel.as_ref())?;
        let pre = git::byte_identical_receipt(&self.primary)?;
        if !git::apply_uncommitted_patch_check(&self.primary, &patch.diff)? {
            bail!("candidate patch cannot be applied to the primary validation tree");
        }
        git::apply_uncommitted_patch(&self.primary, &patch.diff)?;
        // Keep wrapper launch/result and reversal independent. A wrapper that
        // cannot be spawned is still a validation attempt whose temporary
        // patch must be reversed before its error reaches the caller.
        let run = run_wrapper(self, cargo_args);
        let reversed = git::reverse_uncommitted_patch(&self.primary, &patch.diff);
        let post = git::byte_identical_receipt(&self.primary)?;
        if pre != post {
            bail!("candidate validation failed to restore the prevalidation receipt");
        }
        reversed.context("reversing candidate patch after validation attempt")?;
        let mut evidence = run?;
        evidence.restored = true;
        Ok(evidence)
    }
}

pub fn evidence_digest(
    evidence: &ValidationEvidence,
) -> crate::db::workspace_lease_artifacts::WorkspaceDigest {
    let mut encoded = evidence.wrapper.to_string_lossy().into_owned();
    encoded.push('\0');
    encoded.push_str(&evidence.primary.to_string_lossy());
    encoded.push('\0');
    encoded.push_str(&evidence.argv.join("\u{1f}"));
    encoded.push('\0');
    encoded.push_str(&evidence.exit_code.to_string());
    encoded.push('\0');
    encoded.push_str(if evidence.restored {
        "restored"
    } else {
        "not-restored"
    });
    crate::db::workspace_lease_artifacts::WorkspaceDigest::of(encoded)
}

pub fn worker_must_not_invoke_cargo(cwd: &Path) -> Result<()> {
    let effective = cockpit_host::path_containment::effective_path(cwd).with_context(|| {
        format!(
            "refusing cargo; cannot prove `{}` is not a worker worktree",
            cwd.display()
        )
    })?;
    if is_managed_worktree_path(&effective) {
        bail!(
            "worker worktrees must not invoke cargo (cwd `{}`)",
            cwd.display()
        );
    }
    let gitdir =
        git::run_git_checked(&effective, &["rev-parse", "--git-dir"]).with_context(|| {
            format!(
                "refusing cargo; cannot prove `{}` is not a linked worker worktree",
                cwd.display()
            )
        })?;
    let gitdir = gitdir.trim();
    if gitdir.contains("/.git/worktrees/") || gitdir.contains("\\.git\\worktrees\\") {
        bail!(
            "worker worktrees must not invoke cargo (linked git worktree `{}`)",
            cwd.display()
        );
    }
    Ok(())
}

/// A managed directory is recognized structurally, not by trusting an
/// unverified path helper. Linked-worktree detection below is the second
/// proof and catches paths that were moved or reached through a symlink.
fn is_managed_worktree_path(cwd: &Path) -> bool {
    let Some(parent) = cwd.parent() else {
        return false;
    };
    parent.file_name().is_some_and(|name| name == "worktrees")
        && cwd
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| Uuid::parse_str(name).is_ok())
}

pub fn wt_test_wrapper_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("scripts")
        .join("wt-test.sh")
}

fn run_wrapper(
    validation: &CandidateValidation,
    cargo_args: &[&str],
) -> Result<ValidationEvidence> {
    worker_must_not_invoke_cargo(&validation.primary)?;
    let output = Command::new(&validation.wrapper)
        .args(cargo_args)
        .current_dir(&validation.primary)
        .env("WT_TEST_PRIMARY", &validation.primary)
        .env("WT_TEST_CARGO", &validation.cargo_bin)
        .env("WT_TEST_LOCK_HELD", "1")
        .output()
        .with_context(|| {
            format!(
                "launching `{}` in `{}`",
                validation.wrapper.display(),
                validation.primary.display()
            )
        })?;
    Ok(ValidationEvidence {
        wrapper: validation.wrapper.clone(),
        primary: validation.primary.clone(),
        argv: cargo_args.iter().map(|arg| (*arg).to_string()).collect(),
        exit_code: output.status.code().unwrap_or(-1),
        restored: false,
    })
}

struct ValidationLock {
    path: PathBuf,
    nonce: String,
}

impl ValidationLock {
    fn acquire(primary: &Path, cancel: Option<&CancellationToken>) -> Result<Self> {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| primary.join("target"));
        std::fs::create_dir_all(&target)?;
        let path = target.join("wt-test.lock");
        let nonce = format!("{}-{}", std::process::id(), Uuid::new_v4());
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            if cancel.is_some_and(CancellationToken::is_cancelled) {
                bail!("candidate-validation lock acquisition was cancelled");
            }
            match publish_validation_lock(&target, &path, &nonce) {
                Ok(()) => return Ok(Self { path, nonce }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    reclaim_stale_validation_lock(&path)?;
                    if std::time::Instant::now() >= deadline {
                        bail!(
                            "timed out waiting for candidate-validation lock `{}`",
                            path.display()
                        );
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => return Err(error).context("acquiring candidate-validation lock"),
            }
        }
    }
}

impl Drop for ValidationLock {
    fn drop(&mut self) {
        let owner = std::fs::read_to_string(&self.path).unwrap_or_default();
        if owner.split_whitespace().nth(1) == Some(self.nonce.as_str()) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Write owner identity first, then publish it atomically onto the well-known
/// lock name via hard-link. Waiters therefore never observe a published lock
/// without an owner, which closes the mkdir-then-write steal window.
fn publish_validation_lock(target: &Path, path: &Path, nonce: &str) -> std::io::Result<()> {
    let claim = target.join(format!(
        ".wt-test.lock.claim-{}-{}",
        std::process::id(),
        nonce
    ));
    std::fs::write(&claim, format!("{} {nonce}\n", std::process::id()))?;
    match std::fs::hard_link(&claim, path) {
        Ok(()) => {
            let _ = std::fs::remove_file(&claim);
            Ok(())
        }
        Err(error) => {
            let _ = std::fs::remove_file(&claim);
            Err(error)
        }
    }
}

fn reclaim_stale_validation_lock(path: &Path) -> Result<()> {
    let owner = match std::fs::read_to_string(path) {
        Ok(owner) => owner,
        // A published lock always has owner bytes. Missing/unreadable is not
        // proof of death: it is the window a waiter used to steal a live claim.
        Err(_) => return Ok(()),
    };
    let Some(pid) = owner
        .split_whitespace()
        .next()
        .and_then(|raw| raw.parse::<u32>().ok())
    else {
        return Ok(());
    };
    if owner_process_is_live(pid) {
        return Ok(());
    }
    let tombstone = path.with_file_name(format!(
        ".wt-test.lock.stale-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    match std::fs::rename(path, &tombstone) {
        Ok(()) => {
            let _ = std::fs::remove_file(&tombstone);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("claiming stale candidate-validation lock"),
    }
    Ok(())
}

fn owner_process_is_live(pid: u32) -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|status| status.success())
            .unwrap_or(true)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

struct PathOverlaySnapshot {
    files: BTreeMap<PathBuf, Option<Vec<u8>>>,
}

impl PathOverlaySnapshot {
    fn capture(root: &Path, paths: impl IntoIterator<Item = PathBuf>) -> Result<Self> {
        let mut files = BTreeMap::new();
        for rel in paths {
            validate_overlay_path(root, &rel)?;
            let abs = root.join(&rel);
            let bytes = if abs.exists() {
                Some(std::fs::read(&abs).with_context(|| format!("snapshot `{}`", abs.display()))?)
            } else {
                None
            };
            files.insert(rel, bytes);
        }
        Ok(Self { files })
    }

    fn restore(&self, root: &Path) -> Result<()> {
        for (rel, bytes) in &self.files {
            let abs = root.join(rel);
            match bytes {
                Some(content) => {
                    if let Some(parent) = abs.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&abs, content)
                        .with_context(|| format!("restoring `{}`", abs.display()))?;
                }
                None if abs.exists() => {
                    std::fs::remove_file(&abs)
                        .with_context(|| format!("removing overlay `{}`", abs.display()))?;
                }
                None => {}
            }
        }
        Ok(())
    }
}

fn apply_overlay(root: &Path, overlay: &BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
    for (rel, bytes) in overlay {
        validate_overlay_path(root, rel)?;
        let abs = root.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&abs, bytes)
            .with_context(|| format!("applying overlay `{}`", abs.display()))?;
    }
    Ok(())
}

fn validate_overlay_path(root: &Path, rel: &Path) -> Result<()> {
    if rel.as_os_str().is_empty()
        || rel.is_absolute()
        || rel.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        bail!(
            "validation overlay path `{}` is not a confined relative path",
            rel.display()
        );
    }
    let canonical_root = std::fs::canonicalize(root)
        .with_context(|| format!("canonicalizing validation root `{}`", root.display()))?;
    let mut parent = root
        .join(rel)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.to_path_buf());
    while !parent.exists() {
        let Some(next) = parent.parent() else {
            bail!("validation overlay parent escaped its root");
        };
        parent = next.to_path_buf();
    }
    let canonical_parent = std::fs::canonicalize(&parent)?;
    if !canonical_parent.starts_with(&canonical_root) {
        bail!(
            "validation overlay path `{}` escapes the primary tree",
            rel.display()
        );
    }
    let target = root.join(rel);
    // lstat the overlay leaf. `Path::exists` follows links, so a dangling
    // symlink looks absent and `std::fs::write` would create the destination
    // outside the primary tree.
    match std::fs::symlink_metadata(&target) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("validation overlay target `{}` is a symlink", rel.display());
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| {
                format!("inspecting validation overlay target `{}`", rel.display())
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_owner_is_not_reclaimed_as_stale() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("wt-test.lock");
        std::fs::write(&lock, "").unwrap();
        reclaim_stale_validation_lock(&lock).unwrap();
        assert!(
            lock.exists(),
            "a published name with no readable owner must not be stolen"
        );
        std::fs::write(&lock, "not-a-pid nonce\n").unwrap();
        reclaim_stale_validation_lock(&lock).unwrap();
        assert!(
            lock.exists(),
            "an unparseable owner is not proof of death and must not be stolen"
        );
    }

    #[cfg(unix)]
    #[test]
    fn dead_owner_pid_is_reclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("wt-test.lock");
        // PID 1 is init/launchd and is live on Unix. A pid well above
        // typical pid_max, still in the positive pid_t range, should be dead.
        std::fs::write(&lock, "999999999 dead-nonce\n").unwrap();
        reclaim_stale_validation_lock(&lock).unwrap();
        assert!(
            !lock.exists(),
            "a lock whose owner pid is not live must be reclaimed"
        );
    }

    #[test]
    fn unproven_identity_refuses_cargo() {
        let dir = tempfile::tempdir().unwrap();
        let err = worker_must_not_invoke_cargo(dir.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot prove") || err.contains("must not invoke cargo"),
            "{err}"
        );
    }

    #[test]
    fn missing_overlay_target_is_a_confined_relative_path() {
        let dir = tempfile::tempdir().unwrap();
        validate_overlay_path(dir.path(), Path::new("new.txt")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_overlay_target_is_refused_before_write() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("primary");
        let outside = dir.path().join("escaped.txt");
        std::fs::create_dir_all(&root).unwrap();
        symlink(&outside, root.join("link.txt")).unwrap();
        assert!(!outside.exists(), "fixture symlink must be dangling");

        let rel = Path::new("link.txt");
        let err = validate_overlay_path(&root, rel).unwrap_err().to_string();
        assert!(err.contains("is a symlink"), "{err}");

        let mut overlay = BTreeMap::new();
        overlay.insert(rel.to_path_buf(), b"escaped-payload\n".to_vec());
        let err = apply_overlay(&root, &overlay).unwrap_err().to_string();
        assert!(err.contains("is a symlink"), "{err}");
        assert!(
            !outside.exists(),
            "apply_overlay must not follow a dangling overlay symlink"
        );

        let err = PathOverlaySnapshot::capture(&root, [rel.to_path_buf()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("is a symlink"), "{err}");
        assert!(
            !outside.exists(),
            "overlay snapshot must not follow a dangling overlay symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn live_symlink_overlay_target_is_refused() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("primary");
        let outside = dir.path().join("secret.txt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&outside, "secret\n").unwrap();
        symlink(&outside, root.join("link.txt")).unwrap();

        let err = validate_overlay_path(&root, Path::new("link.txt"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("is a symlink"), "{err}");

        let mut overlay = BTreeMap::new();
        overlay.insert(PathBuf::from("link.txt"), b"overwritten\n".to_vec());
        let err = apply_overlay(&root, &overlay).unwrap_err().to_string();
        assert!(err.contains("is a symlink"), "{err}");
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "secret\n");
    }
}
