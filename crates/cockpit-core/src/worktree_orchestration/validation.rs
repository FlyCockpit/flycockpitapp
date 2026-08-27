//! Serialized Rust candidate validation in the primary integration tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;

use crate::git::{self, ByteIdenticalReceipt, UncommittedPatch};

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
}

impl CandidateValidation {
    pub fn for_primary(primary: impl Into<PathBuf>) -> Self {
        Self {
            primary: primary.into(),
            wrapper: wt_test_wrapper_path(),
            cargo_bin: PathBuf::from("cargo"),
            cancel: None,
        }
    }

    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Apply `overlay` in the primary tree under the wrapper lock, run the
    /// wrapper, and restore the exact prevalidation receipt on success or
    /// failure. Worker worktrees are refused before any command is spawned.
    pub fn validate_overlay(
        &self,
        overlay: &BTreeMap<PathBuf, Vec<u8>>,
        cargo_args: &[&str],
    ) -> Result<ValidationEvidence> {
        worker_must_not_invoke_cargo(&self.primary)?;
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

    /// Validate the exact commitless artifact in the primary tree. This is
    /// intentionally separate from worker execution: the worker only creates
    /// the patch, while Cargo is invoked through `wt-test.sh` in primary.
    pub fn validate_patch(
        &self,
        patch: &UncommittedPatch,
        cargo_args: &[&str],
    ) -> Result<ValidationEvidence> {
        worker_must_not_invoke_cargo(&self.primary)?;
        patch.validate_paths()?;
        let _lock = ValidationLock::acquire(&self.primary, self.cancel.as_ref())?;
        let pre = git::byte_identical_receipt(&self.primary)?;
        if !git::apply_uncommitted_patch_check(&self.primary, &patch.diff)? {
            bail!("candidate patch cannot be applied to the primary validation tree");
        }
        let run = (|| {
            git::apply_uncommitted_patch(&self.primary, &patch.diff)?;
            let evidence = run_wrapper(self, cargo_args);
            git::reverse_uncommitted_patch(&self.primary, &patch.diff)?;
            evidence
        })();
        let post = git::byte_identical_receipt(&self.primary)?;
        if pre != post {
            bail!("candidate validation failed to restore the prevalidation receipt");
        }
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
    if is_managed_worktree_directory(cwd) {
        bail!(
            "worker worktrees must not invoke cargo (cwd `{}`)",
            cwd.display()
        );
    }
    if let Ok(gitdir) = git::run_git_checked(cwd, &["rev-parse", "--git-dir"]) {
        let gitdir = gitdir.trim();
        if gitdir.contains("/.git/worktrees/") || gitdir.contains("\\.git\\worktrees\\") {
            bail!(
                "worker worktrees must not invoke cargo (linked git worktree `{}`)",
                cwd.display()
            );
        }
    }
    Ok(())
}

/// A managed directory is recognized structurally, not by trusting an
/// unverified path helper. Linked-worktree detection below is the second
/// proof and catches paths that were moved or reached through a symlink.
fn is_managed_worktree_directory(cwd: &Path) -> bool {
    let Ok(cwd) = cockpit_host::path_containment::effective_path(cwd) else {
        return false;
    };
    let Some(parent) = cwd.parent() else {
        return false;
    };
    parent.file_name().is_some_and(|name| name == "worktrees")
        && cwd
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| uuid::Uuid::parse_str(name).is_ok())
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
        let path = target.join("wt-test.lock.dir");
        let nonce = format!("{}-{}", std::process::id(), uuid::Uuid::new_v4());
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            if cancel.is_some_and(CancellationToken::is_cancelled) {
                bail!("candidate-validation lock acquisition was cancelled");
            }
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    std::fs::write(
                        path.join("owner"),
                        format!("{} {nonce}\n", std::process::id()),
                    )?;
                    return Ok(Self { path, nonce });
                }
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
        let owner = std::fs::read_to_string(self.path.join("owner")).unwrap_or_default();
        if owner.split_whitespace().nth(1) == Some(self.nonce.as_str()) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn reclaim_stale_validation_lock(path: &Path) -> Result<()> {
    let owner = std::fs::read_to_string(path.join("owner")).unwrap_or_default();
    let pid = owner
        .split_whitespace()
        .next()
        .and_then(|raw| raw.parse::<u32>().ok());
    let stale = pid.is_none();
    #[cfg(unix)]
    {
        // kill(0) is an advisory liveness probe: we only reclaim a lock with
        // a missing/invalid owner or a demonstrably dead owner.
        if let Some(pid) = pid {
            let live = std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status()
                .map(|status| status.success())
                .unwrap_or(true);
            let stale = stale || !live;
            return reclaim_stale_validation_lock_if_needed(path, stale);
        }
    }
    #[cfg(not(unix))]
    return reclaim_stale_validation_lock_if_needed(path, stale);
    #[cfg(unix)]
    reclaim_stale_validation_lock_if_needed(path, stale)
}

fn reclaim_stale_validation_lock_if_needed(path: &Path, stale: bool) -> Result<()> {
    if !stale {
        return Ok(());
    }
    // Never delete the name we merely inspected: atomically move it aside so
    // a successful contender cannot have its new owner publication removed.
    let tombstone = path.with_file_name(format!(
        ".wt-test.lock.stale-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    match std::fs::rename(path, &tombstone) {
        Ok(()) => std::fs::remove_dir_all(&tombstone)
            .context("reclaiming stale candidate-validation lock")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("claiming stale candidate-validation lock"),
    }
    Ok(())
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
    if target.exists() && std::fs::symlink_metadata(&target)?.file_type().is_symlink() {
        bail!("validation overlay target `{}` is a symlink", rel.display());
    }
    Ok(())
}
