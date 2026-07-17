//! Path-confinement helpers (sandboxing part 2).
//!
//! Two distinct confinement modes live here:
//!
//! 1. [`confine`] / [`within_root`] — the **hard-deny** path the `docs`
//!    answerer (Docs.2) uses. It runs inside untrusted third-party
//!    source and is denied `bash`, network, and write precisely so it
//!    cannot escape the package directory; `grep`/`glob` are its only
//!    filesystem reach, so both hard-confine every path to the cwd root
//!    with **no escalation prompt**. This path must never gain one.
//!
//! 2. [`check_native_access`] — the **escalate-on-miss** path the native
//!    cockpit tools (`read`, `readlock`, `editunlock`, `writeunlock`,
//!    the intel/`search` tools) use (sandboxing part 2). A target inside
//!    cwd or the session tmp dir is allowed silently; one outside
//!    consults part 1's path-grant store and, if not granted, raises
//!    part 1's approval prompt **naming the exact path**. This is pure
//!    path-checking — it works on every platform, Windows included —
//!    and is independent of the zerobox shell sandbox.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::engine::tool::{ToolCtx, ToolOutput, invalid_input};
use crate::tools::shell_sandbox::SandboxPathAccess;

/// Confine `arg` to `root`. `arg` may be relative (joined onto `root`)
/// or absolute. Returns the canonicalized path **iff** it resolves to a
/// location at or under the canonicalized `root`; otherwise an
/// invalid-input error (the model is trying to read outside the
/// sandbox). The candidate must exist — canonicalization resolves
/// symlinks, which is the whole point.
pub fn confine(root: &Path, arg: &str) -> Result<PathBuf> {
    let canonical_root = canonical_root(root)?;
    let joined = if Path::new(arg).is_absolute() {
        PathBuf::from(arg)
    } else {
        canonical_root.join(arg)
    };
    let canonical = std::fs::canonicalize(&joined)
        .map_err(|e| invalid_input(format!("cannot access `{arg}` within sandbox: {e}")))?;
    if canonical.starts_with(&canonical_root) {
        Ok(canonical)
    } else {
        Err(invalid_input(format!(
            "`{arg}` resolves outside the package sandbox; access denied"
        )))
    }
}

/// Canonicalize the sandbox root once. A root that doesn't exist or
/// isn't canonicalizable is a hard error — the tools cannot operate
/// without a confining anchor.
pub fn canonical_root(root: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(root)
        .map_err(|e| invalid_input(format!("sandbox root `{}` unusable: {e}", root.display())))
}

/// Verify an already-discovered absolute path (e.g. a walk entry) stays
/// within `canonical_root`. Resolves symlinks so a symlink inside the
/// tree pointing out is rejected. Returns `true` when safe to surface.
pub fn within_root(canonical_root: &Path, candidate: &Path) -> bool {
    match std::fs::canonicalize(candidate) {
        Ok(c) => c.starts_with(canonical_root),
        // Unreadable/broken entries are simply not surfaced.
        Err(_) => false,
    }
}

// ---- native-tool confinement (sandboxing part 2) --------------------------

/// Confine a native cockpit tool's path access to the session boundary,
/// escalating via part 1's approval prompt on a miss (sandboxing part 2).
///
/// `path` is the already-resolved absolute target the tool is about to
/// touch (callers go through [`crate::tools::common::resolve`] first).
/// The boundary is the session cwd plus the per-session tmp dir — both
/// "inside." A path inside the boundary is allowed silently. A path
/// outside consults part 1's path-grant store via `ctx`; if not granted,
/// it raises part 1's approval prompt **naming the exact path** and, on a
/// non-`Once` grant, persists it. On deny it returns an invalid-input
/// error the tool surfaces verbatim.
///
/// Skips entirely when the session has sandboxing disabled (the
/// `/sandbox off` / `--no-sandbox` path) — confinement is off, so every
/// path is allowed. When no approver is wired (a degraded state such as
/// seed-tool re-execution before the approver exists), already-proven
/// in-boundary paths continue to work, but unproven or out-of-boundary
/// paths fail closed because there is no safe prompt path.
///
/// Returns the syscall-effective path that was checked. Callers that
/// touch disk should use this path rather than the original spelling.
pub async fn check_native_access(
    ctx: &ToolCtx,
    path: &Path,
    required: SandboxPathAccess,
) -> Result<PathBuf> {
    let effective = match effective_native_path(path) {
        Ok(path) => path,
        Err(err) if !ctx.session.sandbox_enabled() => {
            tracing::debug!(path = %path.display(), reason = %err, "native path could not be canonicalized while sandboxing is disabled");
            path.to_path_buf()
        }
        Err(err) => {
            let Some(approver) = ctx.approver.as_ref() else {
                return Err(invalid_input(format!(
                    "`{}` cannot be proven inside the session boundary: {err}",
                    path.display()
                )));
            };
            let decision = approver.approve_path(path, required).await?;
            if decision.is_allowed() {
                return Ok(path.to_path_buf());
            }
            if matches!(decision, crate::approval::Decision::NoninteractiveDeny) {
                return Err(invalid_input(crate::approval::NONINTERACTIVE_RUN_DENIAL));
            }
            return Err(invalid_input(format!(
                "`{}` is outside the session boundary and access was denied",
                path.display()
            )));
        }
    };

    if !ctx.session.sandbox_enabled() || within_boundary(ctx, &effective) {
        return Ok(effective);
    }

    let Some(approver) = ctx.approver.as_ref() else {
        return Err(invalid_input(format!(
            "`{}` is outside the session boundary and cannot be approved in this context",
            effective.display()
        )));
    };
    let decision = approver.approve_path(&effective, required).await?;
    if decision.is_allowed() {
        Ok(effective)
    } else if matches!(decision, crate::approval::Decision::NoninteractiveDeny) {
        Err(invalid_input(crate::approval::NONINTERACTIVE_RUN_DENIAL))
    } else {
        Err(invalid_input(format!(
            "`{}` is outside the session boundary and access was denied",
            effective.display()
        )))
    }
}

// ---- gitignore read-allowlist gate (read/readlock only) ------------------

/// Gate a `read`/`readlock` of `resolved` on gitignore status
/// (implementation note). Returns `Ok(None)` to let the
/// read proceed, or `Ok(Some(refusal))` — a **non-fatal** [`ToolOutput`] the
/// tool returns verbatim — when the read is refused (defensive against weak
/// models: a clear message, never a crash, never silent).
///
/// A path that is **not** gitignored, or one re-permitted by the effective
/// allowlist (persisted per-layer config ∪ the session set), reads silently.
/// A gitignored, un-allowlisted path raises the two-stage approval; on
/// approval the read proceeds (and the chosen glob is recorded per the
/// persistence choice — `once` records nothing); on rejection the rejection
/// is remembered for the session (no re-prompt) and a refusal is returned.
/// Non-interactive (no approver) → deny with the same clear refusal, never
/// blocking.
pub async fn check_gitignore_read(
    ctx: &ToolCtx,
    resolved: &Path,
) -> anyhow::Result<Option<ToolOutput>> {
    let effective = effective_native_path(resolved);
    let resolved = effective
        .as_ref()
        .ok()
        .map(PathBuf::as_path)
        .unwrap_or(resolved);

    // The matching/glob root: the enclosing git worktree (so recorded globs
    // re-match the same way config-resolved globs do), else the session cwd.
    let root = crate::git::find_worktree_root(resolved).unwrap_or_else(|| ctx.cwd.clone());

    // Effective allowlist = persisted per-layer config ∪ session set.
    let mut allow = crate::config::extended::resolve_gitignore_allow(&ctx.cwd);
    allow.extend(ctx.session.gitignore_session_allow());

    if crate::gitignore::is_permitted(resolved, &root, &allow) {
        return Ok(None);
    }

    let display = resolved.display().to_string();

    // Already rejected this session → same refusal, no re-prompt.
    if ctx.session.gitignore_rejected(&display) {
        return Ok(Some(gitignore_refusal(&display)));
    }

    // No approver (headless / background) → deny with a clear result.
    let Some(approver) = ctx.approver.as_ref() else {
        return Ok(Some(gitignore_refusal(&display)));
    };

    // Build the glob shapes + the project-relative parent label for stage 1.
    let (file_glob, parent_glob, parent_label) = gitignore_globs(resolved, &root);

    let outcome = approver
        .approve_gitignore_read(&display, &parent_label, &file_glob, &parent_glob)
        .await?;
    match outcome {
        crate::approval::GitignoreReadOutcome::ApproveOnce => Ok(None),
        crate::approval::GitignoreReadOutcome::ApproveSession { glob } => {
            ctx.session.add_gitignore_session_allow(glob);
            // Push the now-current full session allowlist to attached client(s)
            // so the `@`-tag popup re-includes this entry without a restart
            // (implementation note). Full-list
            // replace; only the allow-set is broadcast (never the reject-memory).
            ctx.interrupts
                .emit_gitignore_allow(ctx.session.id, ctx.session.gitignore_session_allow());
            Ok(None)
        }
        crate::approval::GitignoreReadOutcome::ApproveProject { glob } => {
            if let Err(e) =
                crate::config::extended::append_gitignore_allow_to_project(&ctx.cwd, &glob)
            {
                // A persist failure must not strand the approved read: allow it
                // this once and surface the failure in the log (priority #1).
                tracing::warn!(error = %e, glob, "persisting gitignore allowlist glob failed; allowing once");
            }
            Ok(None)
        }
        crate::approval::GitignoreReadOutcome::Reject => {
            ctx.session.remember_gitignore_reject(display.clone());
            Ok(Some(gitignore_refusal(&display)))
        }
        crate::approval::GitignoreReadOutcome::NoninteractiveReject => Ok(Some(ToolOutput::text(
            crate::approval::NONINTERACTIVE_RUN_DENIAL,
        ))),
    }
}

/// The terse, model-facing refusal returned when a gitignored read is denied
/// (token economy §10: one sentence, no rationale dump).
fn gitignore_refusal(display: &str) -> ToolOutput {
    ToolOutput::text(format!(
        "Refused: `{display}` is gitignored and the user declined to allow reading it; use a different file or ask the user to allowlist it with `/gitignore-allow`."
    ))
}

/// Compute the stage-1 glob shapes for `resolved` relative to `root`: the
/// exact-file glob, the parent-directory glob (e.g. `relative/parent/`), and
/// the human `./relative/parent/` label shown on the parent option. Falls
/// back to absolute forms when `resolved` lies outside `root`.
fn gitignore_globs(resolved: &Path, root: &Path) -> (String, String, String) {
    let rel = resolved.strip_prefix(root).ok();
    let file_glob = match rel {
        Some(r) => normalize_slashes(r),
        None => resolved.display().to_string(),
    };
    let parent_rel = rel.and_then(|r| r.parent());
    let parent_glob = match parent_rel {
        Some(p) if p.as_os_str().is_empty() => String::new(),
        Some(p) => format!("{}/", normalize_slashes(p)),
        None => match resolved.parent() {
            Some(p) => format!("{}/", p.display()),
            None => String::new(),
        },
    };
    let parent_label = if parent_glob.is_empty() {
        "./".to_string()
    } else {
        format!("./{parent_glob}")
    };
    (file_glob, parent_glob, parent_label)
}

fn normalize_slashes(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Whether `path` is inside the session boundary: at/under the canonical
/// session cwd or per-session tmp dir. `path` must already be the
/// syscall-effective path returned by [`effective_native_path`].
fn within_boundary(ctx: &ToolCtx, path: &Path) -> bool {
    path_inside_boundary(path, &ctx.cwd, ctx.session.tmp_dir().as_deref())
}

pub(crate) fn outside_session_boundary(
    path: &Path,
    root: &Path,
    tmp_dir: Option<&Path>,
) -> Option<PathBuf> {
    let effective = effective_native_path(path).unwrap_or_else(|_| path.to_path_buf());
    if path_inside_boundary(&effective, root, tmp_dir) {
        None
    } else {
        Some(effective)
    }
}

fn path_inside_boundary(candidate: &Path, root: &Path, tmp_dir: Option<&Path>) -> bool {
    if let Ok(root) = std::fs::canonicalize(root)
        && candidate.starts_with(&root)
    {
        return true;
    }
    if let Some(tmp) = tmp_dir
        && let Ok(tmp) = std::fs::canonicalize(tmp)
        && candidate.starts_with(&tmp)
    {
        return true;
    }
    false
}

#[derive(Debug, Clone)]
pub(crate) struct BoundaryPathError(String);

impl std::fmt::Display for BoundaryPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BoundaryPathError {}

pub(crate) fn effective_native_path(
    path: &Path,
) -> std::result::Result<PathBuf, BoundaryPathError> {
    let mut current = path;
    loop {
        match std::fs::canonicalize(current) {
            Ok(base) => return append_unresolved_tail(base, path, current),
            Err(err) => {
                if std::fs::symlink_metadata(current)
                    .map(|meta| meta.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    return Err(BoundaryPathError(format!(
                        "symlink `{}` cannot be resolved: {err}",
                        current.display()
                    )));
                }
                let Some(parent) = current.parent() else {
                    return Err(BoundaryPathError(format!(
                        "no existing parent for `{}`",
                        path.display()
                    )));
                };
                if parent == current {
                    return Err(BoundaryPathError(format!(
                        "no existing parent for `{}`",
                        path.display()
                    )));
                }
                current = parent;
            }
        }
    }
}

fn append_unresolved_tail(
    mut base: PathBuf,
    original: &Path,
    existing_prefix: &Path,
) -> std::result::Result<PathBuf, BoundaryPathError> {
    let tail = original
        .strip_prefix(existing_prefix)
        .unwrap_or_else(|_| Path::new(""));
    for component in tail.components() {
        match component {
            std::path::Component::Normal(part) => base.push(part),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(BoundaryPathError(format!(
                    "unresolved parent traversal in `{}`",
                    original.display()
                )));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
        }
    }
    if base.file_name() == Some(OsStr::new("..")) {
        return Err(BoundaryPathError(format!(
            "unresolved parent traversal in `{}`",
            original.display()
        )));
    }
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confine_allows_paths_under_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/file.txt"), "hi").unwrap();
        let resolved = confine(root, "sub/file.txt").unwrap();
        assert!(resolved.ends_with("sub/file.txt"));
        // Absolute-but-inside also allowed.
        let abs = root.join("sub/file.txt");
        assert!(confine(root, &abs.to_string_lossy()).is_ok());
    }

    #[test]
    fn confine_refuses_parent_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        // A sibling secret outside the root.
        std::fs::write(tmp.path().join("secret.txt"), "topsecret").unwrap();
        // `..` traversal must be refused.
        let err = confine(&root, "../secret.txt").unwrap_err();
        assert!(
            err.to_string().contains("outside the package sandbox")
                || err.to_string().contains("cannot access"),
            "got: {err}"
        );
    }

    #[test]
    fn confine_refuses_symlink_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let secret = tmp.path().join("outside.txt");
        std::fs::write(&secret, "leak").unwrap();
        // A symlink INSIDE the root pointing at a file OUTSIDE it.
        let link = root.join("escape");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&secret, &link).unwrap();
        let err = confine(&root, "escape").unwrap_err();
        assert!(
            err.to_string().contains("outside the package sandbox"),
            "symlink escape must be refused, got: {err}"
        );
        // And the walk-entry guard rejects it too.
        let cr = canonical_root(&root).unwrap();
        assert!(!within_root(&cr, &link));
    }

    #[test]
    fn within_root_accepts_inside() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.txt"), "x").unwrap();
        let cr = canonical_root(root).unwrap();
        assert!(within_root(&cr, &root.join("a.txt")));
    }

    // ---- native-tool confinement (sandboxing part 2) ----------------------

    use std::sync::Arc;

    use crate::approval::Approver;
    use crate::approval::ID_APPROVE_SESSION;
    use crate::approval::store::GrantStore;
    use crate::daemon::proto::ResolveResponse;
    use crate::engine::interrupt::InterruptHub;
    use crate::engine::tool::ToolCtx;

    fn symlink_file(target: &std::path::Path, link: &std::path::Path) {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(target, link).unwrap();
    }

    fn spawn_cancel_next_path_prompt(ctx: &ToolCtx) -> tokio::task::JoinHandle<()> {
        let db = ctx.session.db.clone();
        let sid = ctx.session.id;
        let hub = ctx.interrupts.clone();
        tokio::spawn(async move {
            let iid = loop {
                if let Some(row) = db.list_open_interrupts(sid).unwrap().first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(iid, ResolveResponse::Cancel));
        })
    }

    /// Build a `ToolCtx` rooted at `cwd` with sandboxing ON and an
    /// approver wired to a detached interrupt hub, so a prompt can be
    /// resolved from a sibling task.
    fn sandboxed_ctx(cwd: &std::path::Path) -> ToolCtx {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db.clone(), cwd.to_path_buf(), "builder").unwrap();
        session.set_sandbox_enabled(true);
        let sid = session.id;
        let locks = Arc::new(crate::locks::LockManager::from_db(db.clone()).unwrap());
        let cfg = crate::config::extended::RedactConfig::default();
        let redact = Arc::new(crate::redact::RedactionTable::build(&cfg, cwd).unwrap());
        let hub = Arc::new(InterruptHub::detached());
        let store = GrantStore::new(db.clone(), sid, cwd.to_path_buf());
        let approver = Arc::new(Approver::new(store, db, sid, "builder", hub.clone()));
        ToolCtx {
            agent_id: "builder".to_string(),
            llm_mode: crate::config::extended::LlmMode::Normal,
            locks,
            session: Arc::new(session),
            cwd: cwd.to_path_buf(),
            redact,
            interrupts: hub,
            cancel: tokio_util::sync::CancellationToken::new(),
            approver: Some(approver),
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
            root_agent_frame: true,
            context_usage: None,
            has_tree: false,
            has_bash: false,
            events: None,
            lsp: None,
            resource_scheduler: None,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    #[tokio::test]
    async fn native_inside_cwd_allowed_without_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        // A path under cwd is allowed silently — no client attached, so a
        // prompt would block forever; this returns immediately.
        let inside = tmp.path().join("src/main.rs");
        check_native_access(&ctx, &inside, SandboxPathAccess::Read)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn native_inside_session_tmp_allowed_without_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        // The per-session tmp dir counts as inside the boundary.
        let tmp_dir = ctx.session.tmp_dir().expect("session tmp dir");
        let scratch = tmp_dir.join("scratch.txt");
        check_native_access(&ctx, &scratch, SandboxPathAccess::Read)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn native_parent_traversal_stays_inside() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        // `cwd/sub/../keep.txt` resolves back inside cwd when the traversed
        // parent exists — no prompt.
        std::fs::create_dir(tmp.path().join("sub")).unwrap();
        let traversed = tmp.path().join("sub/../keep.txt");
        check_native_access(&ctx, &traversed, SandboxPathAccess::Read)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn native_missing_inside_path_allowed_without_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        let target = tmp.path().join("new/nested/file.txt");
        check_native_access(&ctx, &target, SandboxPathAccess::Read)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn native_symlink_escape_prompts_instead_of_silent_allow() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, "secret").unwrap();
        let link = tmp.path().join("link.txt");
        symlink_file(&secret, &link);
        let ctx = sandboxed_ctx(tmp.path());

        let resolver = spawn_cancel_next_path_prompt(&ctx);
        let err = check_native_access(&ctx, &link, SandboxPathAccess::Read)
            .await
            .unwrap_err();
        resolver.await.unwrap();
        assert!(
            err.to_string().contains("outside the session boundary"),
            "symlink escape must not be silently allowed: {err}"
        );
    }

    #[tokio::test]
    async fn native_symlink_parent_escape_prompts_for_create_path() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let link = tmp.path().join("outside-dir");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(outside.path(), &link).unwrap();
        let target = link.join("new-file.txt");
        let ctx = sandboxed_ctx(tmp.path());

        let resolver = spawn_cancel_next_path_prompt(&ctx);
        let err = check_native_access(&ctx, &target, SandboxPathAccess::Read)
            .await
            .unwrap_err();
        resolver.await.unwrap();
        assert!(
            err.to_string().contains("outside the session boundary"),
            "symlink parent create path must not be silently allowed: {err}"
        );
    }

    #[tokio::test]
    async fn native_symlink_dotdot_escape_prompts_for_file_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let outside_parent = tempfile::tempdir().unwrap();
        let outside_child = outside_parent.path().join("child");
        std::fs::create_dir(&outside_child).unwrap();
        std::fs::write(outside_parent.path().join("secret.txt"), "secret").unwrap();
        let link = tmp.path().join("link-dir");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_child, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&outside_child, &link).unwrap();
        let target = link.join("../secret.txt");

        for surface in ["read", "write", "edit"] {
            let ctx = sandboxed_ctx(tmp.path());
            let resolver = spawn_cancel_next_path_prompt(&ctx);
            let err = check_native_access(&ctx, &target, SandboxPathAccess::Read)
                .await
                .unwrap_err();
            resolver.await.unwrap();
            assert!(
                err.to_string().contains("outside the session boundary"),
                "{surface} symlink plus .. escape must not be silently allowed: {err}"
            );
        }
    }

    #[tokio::test]
    async fn native_disabled_skips_check() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        // Sandbox off → every path allowed, even far outside, no prompt.
        check_native_access(
            &ctx,
            std::path::Path::new("/etc/shadow"),
            SandboxPathAccess::Read,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn native_outside_granted_allows_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        let target = outside.path().join("notes.txt");

        // Resolve the raised prompt with a Session-scope grant.
        let db = ctx.session.db.clone();
        let sid = ctx.session.id;
        let hub = ctx.interrupts.clone();
        let resolver = tokio::spawn(async move {
            let iid = loop {
                if let Some(row) = db.list_open_interrupts(sid).unwrap().first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(
                iid,
                ResolveResponse::Single {
                    selected_id: ID_APPROVE_SESSION.into(),
                }
            ));
        });
        // First access prompts → granted → allowed.
        check_native_access(&ctx, &target, SandboxPathAccess::Read)
            .await
            .unwrap();
        resolver.await.unwrap();

        // A second access to the same path is now granted with no prompt
        // (would block forever otherwise — no client attached).
        check_native_access(&ctx, &target, SandboxPathAccess::Read)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn native_read_grant_does_not_authorize_write_access() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        let target = outside.path().join("notes.txt");
        std::fs::write(&target, "notes").unwrap();
        let store = GrantStore::new(ctx.session.db.clone(), ctx.session.id, ctx.cwd.clone());
        store
            .record_path(
                outside.path(),
                crate::approval::store::Scope::Session,
                SandboxPathAccess::Read,
            )
            .unwrap();

        check_native_access(&ctx, &target, SandboxPathAccess::Read)
            .await
            .unwrap();

        let resolver = spawn_cancel_next_path_prompt(&ctx);
        let err = check_native_access(&ctx, &target, SandboxPathAccess::ReadWrite)
            .await
            .unwrap_err();
        resolver.await.unwrap();
        assert!(
            err.to_string().contains("outside the session boundary"),
            "read-only grant must not authorize write access: {err}"
        );
    }

    #[tokio::test]
    async fn native_outside_denied_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        let target = outside.path().join("secret.txt");

        let db = ctx.session.db.clone();
        let sid = ctx.session.id;
        let hub = ctx.interrupts.clone();
        let resolver = tokio::spawn(async move {
            let iid = loop {
                if let Some(row) = db.list_open_interrupts(sid).unwrap().first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(iid, ResolveResponse::Cancel));
        });
        let err = check_native_access(&ctx, &target, SandboxPathAccess::Read)
            .await
            .unwrap_err();
        resolver.await.unwrap();
        assert!(
            err.to_string().contains("outside the session boundary"),
            "got: {err}"
        );
        // The exact path is named in the error.
        assert!(err.to_string().contains("secret.txt"), "got: {err}");
    }

    #[tokio::test]
    async fn native_no_approver_allows_proven_inside_but_fails_closed_outside() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = sandboxed_ctx(tmp.path());
        ctx.approver = None;

        check_native_access(
            &ctx,
            &tmp.path().join("inside.txt"),
            SandboxPathAccess::Read,
        )
        .await
        .unwrap();

        let outside = tempfile::tempdir().unwrap();
        let err = check_native_access(&ctx, &outside.path().join("x.txt"), SandboxPathAccess::Read)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot be approved")
                || err.to_string().contains("cannot be proven"),
            "missing approver must fail closed for unproven outside paths: {err}"
        );
    }

    // ---- gitignore read-allowlist gate ------------------------------------

    /// Build a git worktree with a `.gitignore` ignoring `target/` + `.env`,
    /// plus a tracked source file, and a ctx rooted there.
    fn gitignore_ctx(cwd: &std::path::Path) -> ToolCtx {
        std::fs::create_dir_all(cwd.join(".git")).unwrap();
        std::fs::write(cwd.join(".gitignore"), "target/\n.env\n").unwrap();
        std::fs::create_dir_all(cwd.join("target/debug")).unwrap();
        std::fs::write(cwd.join("target/debug/app"), "bin").unwrap();
        std::fs::write(cwd.join(".env"), "SECRET=x").unwrap();
        std::fs::create_dir_all(cwd.join("src")).unwrap();
        std::fs::write(cwd.join("src/main.rs"), "fn main() {}").unwrap();
        sandboxed_ctx(cwd)
    }

    /// A non-gitignored path reads silently — the gate returns `None` with no
    /// prompt (a detached hub would block forever if it prompted).
    #[tokio::test]
    async fn gitignore_gate_permits_tracked_file_silently() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gitignore_ctx(tmp.path());
        let out = check_gitignore_read(&ctx, &tmp.path().join("src/main.rs"))
            .await
            .unwrap();
        assert!(out.is_none(), "tracked file must read silently");
    }

    /// A session-allowlisted gitignored path reads silently (no prompt).
    #[tokio::test]
    async fn gitignore_gate_permits_session_allowlisted() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gitignore_ctx(tmp.path());
        ctx.session.add_gitignore_session_allow("target/");
        let out = check_gitignore_read(&ctx, &tmp.path().join("target/debug/app"))
            .await
            .unwrap();
        assert!(out.is_none(), "session-allowlisted path must read silently");
    }

    /// No approver (headless) → a gitignored, un-allowlisted path is denied
    /// with a clear, non-fatal refusal — never blocks.
    #[tokio::test]
    async fn gitignore_gate_headless_denies_with_refusal() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = gitignore_ctx(tmp.path());
        ctx.approver = None;
        let out = check_gitignore_read(&ctx, &tmp.path().join(".env"))
            .await
            .unwrap();
        let refusal = out.expect("gitignored read must be refused headless");
        assert!(refusal.content.contains("gitignored"));
        assert!(refusal.content.contains(".env"));
    }

    #[tokio::test]
    async fn gitignore_gate_uses_canonical_symlink_target() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = gitignore_ctx(tmp.path());
        ctx.approver = None;
        let link = tmp.path().join("visible-env");
        symlink_file(&tmp.path().join(".env"), &link);

        let out = check_gitignore_read(&ctx, &link).await.unwrap();
        let refusal = out.expect("symlink to gitignored file must be refused");
        assert!(refusal.content.contains("gitignored"));
        assert!(refusal.content.contains(".env"));
    }

    /// A remembered session rejection short-circuits to the same refusal with
    /// no prompt (avoids re-prompt thrash).
    #[tokio::test]
    async fn gitignore_gate_remembered_rejection_refuses_without_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gitignore_ctx(tmp.path());
        let display = std::fs::canonicalize(tmp.path().join(".env"))
            .unwrap_or_else(|_| tmp.path().join(".env"))
            .display()
            .to_string();
        ctx.session.remember_gitignore_reject(display);
        // An approver IS wired, but the remembered rejection means no prompt is
        // raised (a detached hub would block forever otherwise).
        let out = check_gitignore_read(&ctx, &tmp.path().join(".env"))
            .await
            .unwrap();
        assert!(out.is_some(), "remembered rejection must refuse again");
    }

    /// The two-stage approval flow: stage 1 "Approve file" + stage 2 "Approve
    /// for this session" allows the read and records the file glob in the
    /// session allowlist, so a second read is silent.
    #[tokio::test]
    async fn gitignore_gate_two_stage_session_approval() {
        use crate::approval::{ID_GITIGNORE_FILE, ID_SESSION};
        use crate::daemon::proto::ResolveResponse;
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gitignore_ctx(tmp.path());
        let db = ctx.session.db.clone();
        let sid = ctx.session.id;
        let hub = ctx.interrupts.clone();
        // Resolve stage 1 (file), then stage 2 (session). The detached hub
        // doesn't clear the DB open-interrupt row, so wait for a *new* id at
        // stage 2 (mirrors the compound-command approval test).
        let resolver = tokio::spawn(async move {
            let iid1 = loop {
                if let Some(row) = db.list_open_interrupts(sid).unwrap().first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(
                iid1,
                ResolveResponse::Single {
                    selected_id: ID_GITIGNORE_FILE.into(),
                }
            ));
            let iid2 = loop {
                if let Some(row) = db
                    .list_open_interrupts(sid)
                    .unwrap()
                    .iter()
                    .find(|r| r.interrupt_id != iid1)
                {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(
                iid2,
                ResolveResponse::Single {
                    selected_id: ID_SESSION.into(),
                }
            ));
        });
        let out = check_gitignore_read(&ctx, &tmp.path().join(".env"))
            .await
            .unwrap();
        resolver.await.unwrap();
        assert!(out.is_none(), "approved read proceeds");
        // The session allowlist now holds the `.env` file glob → silent reread.
        let out2 = check_gitignore_read(&ctx, &tmp.path().join(".env"))
            .await
            .unwrap();
        assert!(out2.is_none(), "session glob recorded → silent reread");
    }

    #[tokio::test]
    async fn gitignore_gate_preserves_noninteractive_run_denial_and_audit_source() {
        use crate::daemon::proto::ResolveResponse;
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gitignore_ctx(tmp.path());
        let db = ctx.session.db.clone();
        let sid = ctx.session.id;
        let hub = ctx.interrupts.clone();
        let resolver = tokio::spawn(async move {
            let interrupt_id = loop {
                if let Some(row) = db.list_open_interrupts(sid).unwrap().first() {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            assert!(hub.resolve(
                interrupt_id,
                ResolveResponse::Freetext {
                    text: crate::approval::NONINTERACTIVE_RUN_DENIAL.to_string(),
                },
            ));
        });

        let out = check_gitignore_read(&ctx, &tmp.path().join(".env"))
            .await
            .unwrap()
            .expect("noninteractive denial output");
        resolver.await.unwrap();
        assert_eq!(out.content, crate::approval::NONINTERACTIVE_RUN_DENIAL);
        let event = ctx
            .session
            .db
            .list_session_events(sid)
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "permission_decision")
            .expect("permission decision audit event");
        assert_eq!(event.data["source"], "headless_auto_reject");
    }
}
