//! Serialized Rust candidate validation in the primary integration tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::git::{self, UncommittedPatch};
use crate::locks::LockManager;

use super::integration::ExclusiveTargetHold;

/// Refresh exclusive target-path locks while candidate validation mutates the
/// primary tree. Must stay well below [`crate::locks::LOCK_IDLE_TIMEOUT`] so
/// the daemon sweeper cannot reclaim a live overlay/apply/cargo/restore hold.
const VALIDATION_LOCK_REFRESH: Duration = super::integration::EXCLUSIVE_HOLD_REFRESH;

/// Cap for Drop-path process-group SIGKILL wait. SIGKILL is immediate; this
/// only bounds an unkillable leftover (D-state, or a process that left the
/// group) so restore and exclusive-lock release can still proceed.
const WRAPPER_GROUP_TEARDOWN: Duration = Duration::from_secs(2);

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
    /// receipt on success, failure, timeout, cancel, or drop. Worker worktrees
    /// are refused before any command is spawned.
    pub async fn validate_overlay(
        &self,
        overlay: &BTreeMap<PathBuf, Vec<u8>>,
        cargo_args: &[&str],
    ) -> Result<ValidationEvidence> {
        worker_must_not_invoke_cargo(&self.primary)?;
        let affected = overlay.keys().map(|rel| self.primary.join(rel));
        self.with_exclusive_target(affected, async {
            self.validate_overlay_held(overlay, cargo_args).await
        })
        .await
    }

    /// Validate the exact commitless artifact in the primary tree. This is
    /// intentionally separate from worker execution: the worker only creates
    /// the patch, while Cargo is invoked through `wt-test.sh` in primary.
    /// The applied patch is reversed on success, failure, timeout, cancel, or
    /// drop.
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
        self.with_exclusive_target(affected, async {
            self.validate_patch_held(patch, cargo_args).await
        })
        .await
    }

    async fn with_exclusive_target(
        &self,
        affected: impl IntoIterator<Item = PathBuf>,
        mutate: impl std::future::Future<Output = Result<ValidationEvidence>>,
    ) -> Result<ValidationEvidence> {
        let locks = self.locks.as_ref().context(
            "candidate validation requires the workspace LockManager; refusing unlocked primary-tree mutation",
        )?;
        let hold = ExclusiveTargetHold::acquire(
            locks.clone(),
            self.lock_identity.clone(),
            self.session,
            &self.primary,
            affected,
        )
        .await?;
        // Same `(session, lock_identity)` re-acquire is idempotent and does
        // not refresh `touched`. Tool-dispatch `touch_holder` runs only at
        // call start, so a blocking cargo wrapper would idle-expire after
        // LOCK_IDLE_TIMEOUT unless this hold keeps the deadline live.
        let result =
            keep_exclusive_hold_live(locks, &self.lock_identity, self.session, mutate).await;
        hold.release().await;
        result
    }

    async fn validate_overlay_held(
        &self,
        overlay: &BTreeMap<PathBuf, Vec<u8>>,
        cargo_args: &[&str],
    ) -> Result<ValidationEvidence> {
        let _lock = ValidationLock::acquire(&self.primary, self.cancel.as_ref())?;
        let mut snapshot = PathOverlaySnapshot::capture(&self.primary, overlay.keys().cloned())?;
        let pre = git::byte_identical_receipt(&self.primary)?;
        let run = async {
            apply_overlay(&self.primary, overlay)?;
            run_wrapper(self, cargo_args).await
        }
        .await;
        snapshot.restore()?;
        let post = git::byte_identical_receipt(&self.primary)?;
        if pre != post {
            bail!("candidate validation failed to restore the prevalidation receipt");
        }
        let mut evidence = run?;
        evidence.restored = true;
        Ok(evidence)
    }

    async fn validate_patch_held(
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
        // Armed before the first await after apply so dispatcher drop
        // (timeout/cancel) reverses even when run_wrapper never returns.
        let mut applied = AppliedPatch::after_apply(self.primary.clone(), patch.diff.clone());
        // Keep wrapper launch/result and reversal independent. A wrapper that
        // cannot be spawned is still a validation attempt whose temporary
        // patch must be reversed before its error reaches the caller.
        let run = run_wrapper(self, cargo_args).await;
        let reversed = applied.reverse();
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

/// Keep exclusive target-path locks live against [`LockManager::sweep_expired`]
/// for the whole validation mutation future, including `run_wrapper`.
async fn keep_exclusive_hold_live<T>(
    locks: &LockManager,
    lock_identity: &str,
    session: Uuid,
    mutate: impl std::future::Future<Output = T>,
) -> T {
    tokio::pin!(mutate);
    // First tick is one interval in the future so a paused test clock can
    // advance exactly one refresh without racing an immediate interval fire.
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + VALIDATION_LOCK_REFRESH,
        VALIDATION_LOCK_REFRESH,
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            result = &mut mutate => return result,
            _ = interval.tick() => {
                locks.touch_holder(lock_identity, session).await;
            }
        }
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

async fn run_wrapper(
    validation: &CandidateValidation,
    cargo_args: &[&str],
) -> Result<ValidationEvidence> {
    worker_must_not_invoke_cargo(&validation.primary)?;
    // Async so `keep_exclusive_hold_live` can `touch_holder` on the same
    // runtime while cargo mutates the overlaid primary tree. A blocking
    // `Command::output()` would starve the heartbeat (and the sweeper) on
    // a current-thread runtime.
    let mut cmd = tokio::process::Command::new(&validation.wrapper);
    cmd.args(cargo_args)
        .current_dir(&validation.primary)
        .env("WT_TEST_PRIMARY", &validation.primary)
        .env("WT_TEST_CARGO", &validation.cargo_bin)
        .env("WT_TEST_LOCK_HELD", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    // Own a process group so Drop SIGKILLs cargo and rustc/test-binary
    // descendants before overlay/patch restore. Tokio `kill_on_drop` is
    // SIGKILL of the wrapper PID only; `wt-test.sh` `exec`s cargo into
    // that PID when `WT_TEST_LOCK_HELD=1`.
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = GroupedWrapper {
        child: cmd.spawn().with_context(|| {
            format!(
                "launching `{}` in `{}`",
                validation.wrapper.display(),
                validation.primary.display()
            )
        })?,
    };
    let status = child.wait().await.with_context(|| {
        format!(
            "waiting for `{}` in `{}`",
            validation.wrapper.display(),
            validation.primary.display()
        )
    })?;
    Ok(ValidationEvidence {
        wrapper: validation.wrapper.clone(),
        primary: validation.primary.clone(),
        argv: cargo_args.iter().map(|arg| (*arg).to_string()).collect(),
        exit_code: status.code().unwrap_or(-1),
        restored: false,
    })
}

/// Wrapper child whose Drop SIGKILLs the process group and waits until it
/// is gone. Sibling destructors (`AppliedPatch`, `PathOverlaySnapshot`,
/// `ExclusiveTargetHold`) must not run while cargo descendants still write.
struct GroupedWrapper {
    child: tokio::process::Child,
}

impl GroupedWrapper {
    async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait().await
    }
}

impl Drop for GroupedWrapper {
    fn drop(&mut self) {
        cockpit_host::process::terminate_group_kill_wait(&mut self.child, WRAPPER_GROUP_TEARDOWN);
    }
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
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|status| status.success())
            .unwrap_or(true)
    }
    #[cfg(windows)]
    {
        windows_owner_process_is_live(pid)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        true
    }
}

#[cfg(windows)]
fn windows_owner_process_is_live(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const ERROR_ACCESS_DENIED: i32 = 5;
    const STILL_ACTIVE: u32 = 259;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        // Access denied means the process exists but we cannot inspect it.
        // Fail closed: never steal a lock from a running owner we cannot see.
        return std::io::Error::last_os_error().raw_os_error() == Some(ERROR_ACCESS_DENIED);
    }
    let mut code = 0u32;
    let queried = unsafe { GetExitCodeProcess(handle, &mut code) };
    unsafe {
        CloseHandle(handle);
    }
    if queried == 0 {
        return true;
    }
    code == STILL_ACTIVE
}

/// Applied uncommitted candidate. Drop reverses the diff so dispatcher
/// timeout/cancel cannot leave the primary tree mutated.
struct AppliedPatch {
    primary: PathBuf,
    diff: String,
    armed: bool,
}

impl AppliedPatch {
    fn after_apply(primary: PathBuf, diff: String) -> Self {
        Self {
            primary,
            diff,
            armed: true,
        }
    }

    fn reverse(&mut self) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        git::reverse_uncommitted_patch(&self.primary, &self.diff)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for AppliedPatch {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        if let Err(error) = git::reverse_uncommitted_patch(&self.primary, &self.diff) {
            tracing::warn!(
                primary = %self.primary.display(),
                error = %error,
                "candidate validation patch reverse on drop failed"
            );
        }
    }
}

#[derive(Debug)]
struct PathOverlaySnapshot {
    root: PathBuf,
    files: BTreeMap<PathBuf, Option<Vec<u8>>>,
}

impl PathOverlaySnapshot {
    fn capture(root: &Path, paths: impl IntoIterator<Item = PathBuf>) -> Result<Self> {
        let mut files = BTreeMap::new();
        for rel in paths {
            validate_overlay_path(root, &rel)?;
            let abs = root.join(&rel);
            let bytes = match crate::resource_limits::read_for_tool(&abs) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.is_not_found() => None,
                Err(error) => {
                    return Err(error).context(format!("snapshot `{}`", abs.display()));
                }
            };
            files.insert(rel, bytes);
        }
        Ok(Self {
            root: root.to_path_buf(),
            files,
        })
    }

    fn restore(&mut self) -> Result<()> {
        self.restore_files()?;
        self.files.clear();
        Ok(())
    }

    fn restore_files(&self) -> Result<()> {
        for (rel, bytes) in &self.files {
            let abs = self.root.join(rel);
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

impl Drop for PathOverlaySnapshot {
    fn drop(&mut self) {
        if self.files.is_empty() {
            return;
        }
        if let Err(error) = self.restore_files() {
            tracing::warn!(
                root = %self.root.display(),
                error = %error,
                "candidate validation overlay restore on drop failed"
            );
        }
        self.files.clear();
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
    use std::sync::Arc;

    use crate::db::Db;
    use crate::locks::{LOCK_IDLE_TIMEOUT, LockManager};

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

    #[test]
    fn dead_owner_pid_is_reclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("wt-test.lock");
        // PID 1 is init/launchd and is live on Unix. A pid well above
        // typical pid_max / Windows PID space, still in the u32 range,
        // should be dead on every supported host.
        std::fs::write(&lock, "999999999 dead-nonce\n").unwrap();
        reclaim_stale_validation_lock(&lock).unwrap();
        assert!(
            !lock.exists(),
            "a lock whose owner pid is not live must be reclaimed"
        );
    }

    #[test]
    fn live_owner_pid_is_not_reclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("wt-test.lock");
        std::fs::write(&lock, format!("{} live-nonce\n", std::process::id())).unwrap();
        reclaim_stale_validation_lock(&lock).unwrap();
        assert!(
            lock.exists(),
            "a lock whose owner pid is this process must not be stolen"
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

    async fn lock_session() -> (Arc<LockManager>, Uuid) {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .write(|conn| {
                crate::db::Db::insert_session_row_conn(
                    conn,
                    &crate::db::Db::build_new_session_row_conn(conn, "p", "/x", "builder")?,
                )
            })
            .await
            .unwrap();
        (Arc::new(LockManager::in_memory(db)), session.session_id)
    }

    #[tokio::test(start_paused = true)]
    async fn exclusive_target_hold_survives_idle_sweep_while_mutation_runs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let file = root.join("a.txt");
        std::fs::write(&file, "x\n").unwrap();
        let (locks, session) = lock_session().await;
        let validation = CandidateValidation::for_primary(&root).with_locks(
            locks.clone(),
            "orchestrator",
            session,
        );
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            validation
                .with_exclusive_target([file.clone()], async {
                    release_rx.await.ok();
                    Ok(ValidationEvidence {
                        wrapper: PathBuf::from("test"),
                        primary: PathBuf::from("test"),
                        argv: Vec::new(),
                        exit_code: 0,
                        restored: false,
                    })
                })
                .await
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while locks.holder(&root).is_none() {
            assert!(
                deadline
                    .checked_duration_since(std::time::Instant::now())
                    .is_some(),
                "exclusive target lock was never acquired"
            );
            tokio::task::yield_now().await;
        }
        // Park inside keep_exclusive_hold_live's interval wait so the next
        // advance refreshes an already-held exclusive claim.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        let now = chrono::Utc::now().timestamp();
        let expired = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
        locks.set_holder_touched_for_test("orchestrator", session, expired);
        tokio::time::advance(VALIDATION_LOCK_REFRESH).await;
        while locks.holder_touched_for_test("orchestrator", session) == Some(expired) {
            assert!(
                deadline
                    .checked_duration_since(std::time::Instant::now())
                    .is_some(),
                "exclusive validation hold was not refreshed while mutation ran"
            );
            tokio::task::yield_now().await;
        }

        let reclaimed = locks.sweep_expired(now).await.unwrap();
        assert!(
            reclaimed.is_empty(),
            "exclusive validation hold must stay live against sweep_expired while mutation runs: {reclaimed:?}"
        );
        assert!(
            locks.holder(&root).is_some(),
            "repository-root exclusive lock must still be held"
        );

        let _ = release_tx.send(());
        join.await.unwrap().unwrap();
        assert!(
            locks.holder(&root).is_none(),
            "exclusive validation hold must release after mutation"
        );
    }

    #[tokio::test]
    async fn dropped_exclusive_target_hold_releases_path_locks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let file = root.join("a.txt");
        std::fs::write(&file, "x\n").unwrap();
        let (locks, session) = lock_session().await;
        let validation = CandidateValidation::for_primary(&root).with_locks(
            locks.clone(),
            "orchestrator",
            session,
        );
        let join = tokio::spawn({
            let file = file.clone();
            async move {
                validation
                    .with_exclusive_target(
                        [file],
                        std::future::pending::<Result<ValidationEvidence>>(),
                    )
                    .await
            }
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while locks.holder(&root).is_none() {
            assert!(
                deadline
                    .checked_duration_since(std::time::Instant::now())
                    .is_some(),
                "exclusive target lock was never acquired"
            );
            tokio::task::yield_now().await;
        }

        join.abort();
        let _ = join.await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            locks.holder(&root).is_none(),
            "dropping the exclusive validation future must release path locks"
        );
        assert!(
            locks.holder(&file).is_none(),
            "dropping the exclusive validation future must release affected-path locks"
        );
    }

    #[test]
    fn run_wrapper_owns_a_process_group_and_waits_for_group_death_on_drop() {
        let source = include_str!("validation.rs");
        let process_group = ["process_group", "(0)"].concat();
        let kill_wait = ["terminate_group_kill", "_wait"].concat();
        let grouped = ["Grouped", "Wrapper"].concat();
        assert!(
            source.contains(&process_group),
            "run_wrapper must put the cargo wrapper in its own process group"
        );
        assert!(
            source.contains(&kill_wait),
            "wrapper Drop must wait for cargo descendants to die before restore"
        );
        assert!(
            source.contains(&grouped),
            "run_wrapper must own the Child so Drop can wait for the process group"
        );
    }

    #[test]
    fn overlay_snapshot_drop_restores_prevalidation_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let rel = PathBuf::from("a.txt");
        std::fs::write(dir.path().join(&rel), "before\n").unwrap();
        let snapshot = PathOverlaySnapshot::capture(dir.path(), [rel.clone()]).unwrap();
        std::fs::write(dir.path().join(&rel), "overlay\n").unwrap();
        drop(snapshot);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(&rel)).unwrap(),
            "before\n",
            "Drop of an overlay snapshot must restore captured bytes"
        );
    }

    #[test]
    fn overlay_snapshot_refuses_an_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let rel = PathBuf::from("huge.bin");
        let handle = std::fs::File::create(dir.path().join(&rel)).unwrap();
        handle
            .set_len(crate::resource_limits::ResourceLimits::defaults().fs_read_max_file_bytes + 1)
            .unwrap();
        drop(handle);
        let err = PathOverlaySnapshot::capture(dir.path(), [rel])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("byte limit") || err.contains("snapshot"),
            "{err}"
        );
    }

    #[test]
    fn overlay_restore_disarms_drop() {
        let dir = tempfile::tempdir().unwrap();
        let rel = PathBuf::from("a.txt");
        std::fs::write(dir.path().join(&rel), "before\n").unwrap();
        let mut snapshot = PathOverlaySnapshot::capture(dir.path(), [rel.clone()]).unwrap();
        std::fs::write(dir.path().join(&rel), "overlay\n").unwrap();
        snapshot.restore().unwrap();
        std::fs::write(dir.path().join(&rel), "after-restore\n").unwrap();
        drop(snapshot);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(&rel)).unwrap(),
            "after-restore\n",
            "explicit restore must disarm Drop so a later write is not clobbered"
        );
    }

    #[test]
    fn applied_patch_drop_reverses_uncommitted_diff() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root).unwrap();
        crate::git::run_git_checked(root, &["init", "-q", "-b", "main"]).unwrap();
        crate::git::run_git_checked(root, &["config", "user.email", "t@t"]).unwrap();
        crate::git::run_git_checked(root, &["config", "user.name", "t"]).unwrap();
        crate::git::run_git_checked(root, &["config", "commit.gpgsign", "false"]).unwrap();
        std::fs::write(root.join("a.txt"), "before\n").unwrap();
        crate::git::run_git_checked(root, &["add", "--", "a.txt"]).unwrap();
        crate::git::run_git_checked(root, &["commit", "-q", "-m", "init"]).unwrap();

        std::fs::write(root.join("a.txt"), "candidate\n").unwrap();
        let patch = crate::git::capture_uncommitted_patch(root).unwrap();
        std::fs::write(root.join("a.txt"), "before\n").unwrap();
        crate::git::apply_uncommitted_patch(root, &patch.diff).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "candidate\n"
        );
        drop(AppliedPatch::after_apply(
            root.to_path_buf(),
            patch.diff.clone(),
        ));
        assert_eq!(
            std::fs::read_to_string(root.join("a.txt")).unwrap(),
            "before\n",
            "Drop of an applied candidate patch must reverse it"
        );
    }
}
