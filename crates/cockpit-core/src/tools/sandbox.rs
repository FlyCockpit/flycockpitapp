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
//!    cockpit tools (`read`, `edit`, `write`,
//!    the intel/`search` tools) use (sandboxing part 2). A target inside
//!    cwd or the session tmp dir is allowed silently; one outside
//!    consults part 1's path-grant store and, if not granted, raises
//!    part 1's approval prompt **naming the exact path**. This is pure
//!    path-checking — it works on every platform, Windows included —
//!    and is independent of the zerobox shell sandbox. `/sandbox off`
//!    disables shell confinement, not native path approval: an unconfined
//!    native file operation outside the boundary still takes grant-or-ask.

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
/// The boundary is the session cwd plus both session scratch directories —
/// ephemeral tmp and durable workspace scratch — and the calling agent's
/// attached local knowledge-base roots for reads. KB roots are read-only here;
/// writes remain outside the boundary and retain their ordinary gates.
/// A path inside the boundary is allowed silently. A path
/// outside consults part 1's path-grant store via `ctx`; if not granted,
/// it raises part 1's approval prompt **naming the exact path** and, on a
/// non-`Once` grant, persists it. On deny it returns an invalid-input
/// error the tool surfaces verbatim.
///
/// This is not governed by `/sandbox off`: that switch controls the
/// zerobox shell sandbox only. Native file access has no separate user
/// control; an out-of-boundary native operation is unconfined and therefore
/// takes grant-or-ask, with path grants avoiding repeated prompts at the
/// chosen scope. When no approver is wired (a degraded state such as
/// headless/tool contexts before an approver exists, already-proven
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
    // A review cage is a hard outer boundary. Apply it before every authority
    // branch, including a workspace lease: a leased attached KB must not
    // escape a package-scoped background review task.
    let cage_path = effective_native_path(path).unwrap_or_else(|_| path.to_path_buf());
    if let Some(cage) = &ctx.review_cage
        && cage.auto_deny_approvals()
        && !cage.preauthorizes_package_path(&cage_path)
    {
        return Err(invalid_input(format!(
            "`{}` is outside the session boundary and background review cannot approve it",
            cage_path.display()
        )));
    }

    // A workspace lease is a hard filesystem boundary, not an additional
    // source of approval. In particular, a stale lease or a workspace path
    // outside its visibility root must never fall through to the ambient
    // `approve_path` flow. The session's own durable scratch is the explicit
    // capability exception: it remains read/write for the leased agent even
    // when the workspace lease is read-only.
    if let Some(lease) = ctx.workspace_lease.as_deref() {
        if !lease.is_live(crate::workspace_lease::now_unix_ms()) {
            crate::workspace_lease::expire_active_workspace_lease_if_due(&ctx.session.db, lease)
                .await
                .map_err(|error| {
                    invalid_input(format!(
                        "`{}` is denied because workspace lease `{}` is expired or revoked, and the durable row could not be moved off Active: {error:#}",
                        path.display(),
                        lease.id
                    ))
                })?;
            return Err(invalid_input(format!(
                "`{}` is denied because workspace lease `{}` is expired or revoked",
                path.display(),
                lease.id
            )));
        }
        let effective = effective_native_path(path).map_err(|err| {
            invalid_input(format!(
                "`{}` cannot be proven inside workspace lease `{}`: {err}",
                path.display(),
                lease.id
            ))
        })?;
        let session_scratch = ctx.session.workspace_scratch_dir();
        let is_session_scratch =
            cockpit_host::path_containment::contained_under(&session_scratch, &effective);
        let permitted = match required {
            SandboxPathAccess::Read => lease.allows_read(),
            SandboxPathAccess::ReadWrite => lease.allows_write(),
        };
        if !permitted && !is_session_scratch {
            return Err(invalid_input(format!(
                "`{}` is denied by workspace lease `{}` operation authority",
                path.display(),
                lease.id
            )));
        }
        if !lease.covers_path(&effective) && !is_session_scratch {
            return Err(invalid_input(format!(
                "`{}` is outside workspace lease visibility `{}`",
                effective.display(),
                lease.visibility_root.display()
            )));
        }
        let attached_local_knowledge =
            crate::knowledge::check_native_local_knowledge_path_access(ctx, &effective)
                .await
                .map_err(|error| invalid_input(error.to_string()))?;
        if attached_local_knowledge && required != SandboxPathAccess::Read {
            return Err(invalid_input(format!(
                "`{}` is in a local knowledge base; generic native writes are denied",
                effective.display()
            )));
        }
        return Ok(effective);
    }

    let effective = match effective_native_path(path) {
        Ok(path) => path,
        Err(err) => {
            // Even when a final symlink/path cannot be resolved, a generic
            // approval must not turn a configured KB spelling into write
            // authority. The lexical target is sufficient for the configured
            // root check; an unresolved target still cannot acquire an
            // implicit read capability.
            let local_knowledge =
                crate::knowledge::check_native_local_knowledge_path_access(ctx, path)
                    .await
                    .map_err(|error| invalid_input(error.to_string()))?;
            if local_knowledge && required != SandboxPathAccess::Read {
                return Err(invalid_input(format!(
                    "`{}` is in a local knowledge base; generic native writes are denied",
                    path.display()
                )));
            }
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

    // Configured local KBs are a hard filesystem boundary. This common
    // native-path choke point covers read, write, edit, LSP, skills, and every
    // future native tool that obtains host-path authority through this helper.
    let attached_local_knowledge =
        crate::knowledge::check_native_local_knowledge_path_access(ctx, &effective)
            .await
            .map_err(|error| invalid_input(error.to_string()))?;

    if attached_local_knowledge && required != SandboxPathAccess::Read {
        return Err(invalid_input(format!(
            "`{}` is in a local knowledge base; generic native writes are denied",
            effective.display()
        )));
    }

    if within_boundary(ctx, &effective)
        || (required == SandboxPathAccess::Read && attached_local_knowledge)
    {
        return Ok(effective);
    }

    if let Some(cage) = &ctx.review_cage {
        if cage.preauthorizes_package_path(&effective) {
            return Ok(effective);
        }
        // `auto_deny_approvals()` was applied above, before a KB capability
        // could be considered. A preauthorized package may continue through
        // the ordinary in-boundary/approval path.
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

/// The exact path-access candidate used by `approve_path` and the concrete
/// filesystem boundary.  Keeping this projection here prevents a native tool
/// from checking one spelling before an async gate and then claiming a
/// differently-normalized spelling when it actually reaches the host.
pub(crate) fn native_access_effect(path: &Path, required: SandboxPathAccess) -> serde_json::Value {
    serde_json::json!({
        "access": {
            "path": path.display().to_string(),
            "required_access": format!("{required:?}"),
        }
    })
}

/// Claim the exact native path capability at the final filesystem boundary.
///
/// [`check_native_access`] deliberately runs early: it can prompt and wait,
/// while later validation, lock acquisition, and revision changes may take an
/// arbitrary amount of time.  An allow from that early gate is therefore not
/// ambient authority for the first metadata/read/write/LSP access.  Every
/// native caller invokes this immediately before its first host access, after
/// its other gates.  Outside a host-approval handoff this is intentionally a
/// no-op, preserving in-boundary and isolated callers.
pub(crate) async fn recheck_native_access_effect_boundary(
    path: &Path,
    required: SandboxPathAccess,
) -> Result<()> {
    crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
        "native_filesystem_access",
        &[native_access_effect(path, required)],
    )
    .await
}

/// Revalidate an already-claimed native path at a read-only stability probe
/// while leaving a later, still-ready content mutation claim untouched.
pub(crate) async fn recheck_claimed_native_access_stability_boundary(
    path: &Path,
    required: SandboxPathAccess,
) -> Result<()> {
    crate::engine::interrupt::recheck_current_claimed_host_approval_effect_boundary(
        "native_filesystem_stability_read",
        &[native_access_effect(path, required)],
    )
    .await
}

// ---- gitignore read-allowlist gate (read only) ------------------

/// Gate a `read` of `resolved` on gitignore status
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

    let secret_path = ctx
        .session
        .secret_path_matcher(&ctx.config.extended().redact)
        .is_secret_path(resolved);
    if (secret_path && crate::gitignore::allowlist_matches(resolved, &root, &allow))
        || (!secret_path && crate::gitignore::is_permitted(resolved, &root, &allow))
    {
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
        crate::approval::GitignoreReadOutcome::ApproveOnce => {
            // The read gate is the final common choke point for read/glob/
            // grep/intel callers. Claim the exact once-only authorization
            // before it returns permission to cross the filesystem boundary.
            if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                "gitignore_read_authorization",
                &[serde_json::json!({"effect": "gitignore_read_once"})],
            )
            .await
            .is_err()
            {
                return Ok(Some(gitignore_refusal(&display)));
            }
            Ok(None)
        }
        crate::approval::GitignoreReadOutcome::ApproveSession { glob } => {
            if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                "gitignore_session_allow_persistence",
                &[serde_json::json!({
                    "persist_grant": {"glob": &glob, "scope": "session"}
                })],
            )
            .await
            .is_err()
            {
                return Ok(Some(gitignore_refusal(&display)));
            }
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
            if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                "gitignore_project_allow_persistence",
                &[serde_json::json!({
                    "persist_grant": {"glob": &glob, "scope": "project"}
                })],
            )
            .await
            .is_err()
            {
                return Ok(Some(gitignore_refusal(&display)));
            }
            if let Err(e) =
                crate::config::extended::append_gitignore_allow_to_project(&ctx.cwd, &glob)
            {
                // The selected durable capability included this exact project
                // allowlist mutation. Do not silently downgrade it to a
                // one-off read when the mutation did not commit: that would
                // execute an effect different from the user-selected
                // candidate and incorrectly complete its receipt.
                tracing::warn!(error = %e, glob, "persisting gitignore allowlist glob failed; rejecting selected capability");
                crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
                return Ok(Some(gitignore_refusal(&display)));
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
        "Refused: `{display}` is secret-bearing or gitignored and the user declined to allow reading it; use a different file or ask the user to allowlist it with `/gitignore-allow`."
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
/// True when an in-workspace path targets the workspace configuration
/// directory. Callers use this only for write authorization; reads remain silent.
pub(crate) fn is_workspace_cockpit_path(cwd: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(cwd) else {
        return false;
    };
    relative
        .components()
        .any(|component| component.as_os_str() == ".cockpit")
}

fn within_boundary(ctx: &ToolCtx, path: &Path) -> bool {
    if let Some(lease) = ctx.workspace_lease.as_ref() {
        if !lease.is_live(crate::workspace_lease::now_unix_ms()) {
            return false;
        }
        if lease.covers_path(path) {
            return true;
        }
        // Session scratch remains usable; sibling worktrees and the primary
        // repository are not implicit lease visibility.
        let tmp_dir = ctx.session.tmp_dir();
        let workspace_scratch_dir = ctx.session.workspace_scratch_dir();
        return tmp_dir
            .iter()
            .chain(std::iter::once(&workspace_scratch_dir))
            .any(|scratch| cockpit_host::path_containment::contained_under(scratch, path));
    }
    let tmp_dir = ctx.session.tmp_dir();
    let workspace_scratch_dir = ctx.session.workspace_scratch_dir();
    path_inside_boundary(
        path,
        &ctx.cwd,
        tmp_dir.as_deref(),
        Some(&workspace_scratch_dir),
    )
}

pub(crate) fn outside_session_boundary(
    path: &Path,
    root: &Path,
    tmp_dir: Option<&Path>,
    workspace_scratch_dir: Option<&Path>,
) -> Option<PathBuf> {
    let effective = effective_native_path(path).unwrap_or_else(|_| path.to_path_buf());
    if path_inside_boundary(&effective, root, tmp_dir, workspace_scratch_dir) {
        None
    } else {
        Some(effective)
    }
}

fn path_inside_boundary(
    candidate: &Path,
    root: &Path,
    tmp_dir: Option<&Path>,
    workspace_scratch_dir: Option<&Path>,
) -> bool {
    if cockpit_host::path_containment::contained_under(root, candidate) {
        return true;
    }
    if let Some(tmp) = tmp_dir
        && cockpit_host::path_containment::contained_under(tmp, candidate)
    {
        return true;
    }
    if let Some(scratch) = workspace_scratch_dir
        && cockpit_host::path_containment::contained_under(scratch, candidate)
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
        spawn_resolve_next_path_prompt(ctx, ResolveResponse::Cancel)
    }

    fn spawn_resolve_next_path_prompt(
        ctx: &ToolCtx,
        response: ResolveResponse,
    ) -> tokio::task::JoinHandle<()> {
        let db = ctx.session.db.clone();
        let sid = ctx.session.id;
        let hub = ctx.interrupts.clone();
        tokio::spawn(async move {
            let iid = loop {
                let open = db.list_open_interrupts(sid).await.unwrap();
                if let Some(row) = open.iter().find(|row| hub.has_waiter(row.interrupt_id)) {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            db.resolve_interrupt(iid, &response).await.unwrap();
            assert!(hub.resolve(iid, response));
        })
    }

    /// Build a `ToolCtx` rooted at `cwd` with sandboxing ON and an
    /// approver wired to a detached interrupt hub, so a prompt can be
    /// resolved from a sibling task.
    fn sandboxed_ctx(cwd: &std::path::Path) -> ToolCtx {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = crate::session::Session::create_for_test(
            db.clone(),
            cwd.to_path_buf(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        session.set_sandbox_enabled(true);
        let sid = session.id;
        let locks = Arc::new(crate::locks::LockManager::in_memory(db.clone()));
        let cfg = crate::config::extended::RedactConfig::default();
        let redact = Arc::new(crate::redact::RedactionTable::build(&cfg, cwd).unwrap());
        let hub = Arc::new(InterruptHub::detached());
        let store = GrantStore::new(
            db.clone(),
            sid,
            cwd.to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(cwd),
        );
        let approver = Arc::new(Approver::new(store, db, sid, "builder", hub.clone()));
        ToolCtx {
            agent_id: "builder".to_string(),
            allowed_knowledge_bases: None,
            executing_model_trusted: false,
            knowledge_access_trusted: false,
            caller_model: None,
            agent_instance_id: None,
            lock_identity: "builder".to_string().clone(),
            write_scope: None,
            dream_read_scope: std::sync::Arc::new(std::sync::RwLock::new(None)),
            workspace_lease: None,
            current_tool_call_id: None,
            tool_steering: crate::agents::ToolSteering::Terse,
            locks,
            session: Arc::new(session),
            cwd: cwd.to_path_buf(),
            redact,
            interrupts: hub,
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: crate::daemon::shutdown::ShutdownSignal::new(),
            approver: Some(approver),
            image_generation_dispatch: None,
            transcription_dispatch: None,
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            root_agent_frame: true,
            skill_write_origin: crate::skills::manage::SkillWriteOrigin::Foreground,
            review_cage: None,
            context_usage: None,
            available_tools: Arc::new(std::collections::HashSet::new()),
            mcp_builtin_registry: Arc::new(crate::mcp::builtin::BuiltinRegistry::default_with(
                Vec::new(),
            )),
            has_tree: false,
            has_bash: false,
            events: None,
            lsp: None,
            resource_scheduler: None,
            media_authority: None,
            media_availability: crate::tool_media_authority::MediaToolAvailability::unavailable(),
            config: crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(cwd),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::for_cwd(cwd),
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
    async fn leased_native_access_allows_durable_workspace_scratch() {
        let lease_root = tempfile::tempdir().unwrap();
        let mut ctx = sandboxed_ctx(lease_root.path());
        ctx.workspace_lease = Some(Arc::new(crate::workspace_lease::WorkspaceLease::ephemeral(
            crate::workspace_lease::WorkspaceLeaseKind::SameRoot,
            lease_root.path().to_path_buf(),
            crate::workspace_lease::WorkspaceLeaseOps::none(),
            crate::workspace_lease::now_unix_ms() + 60_000,
        )));
        let scratch_file = ctx.session.workspace_scratch_dir().join("scratch.txt");

        check_native_access(&ctx, &scratch_file, SandboxPathAccess::ReadWrite)
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
    async fn workspace_lease_does_not_bypass_trust_required_local_knowledge() {
        let tmp = tempfile::tempdir().unwrap();
        let knowledge_root = tmp.path().join("knowledge");
        std::fs::create_dir(&knowledge_root).unwrap();
        let target = knowledge_root.join("notes.md");

        let mut ctx = sandboxed_ctx(tmp.path());
        let mut extended = crate::config::extended::ExtendedConfig::default();
        extended
            .knowledge_bases
            .push(crate::config::extended::KnowledgeBaseRegistryEntry::new(
                "private".to_string(),
                "Private".to_string(),
                "Trusted local knowledge".to_string(),
                crate::config::extended::KnowledgeBaseSource::Local {
                    path: std::path::PathBuf::from("knowledge"),
                },
                crate::config::extended::KnowledgeBaseEmbeddingOwnership::Local,
                None,
                None,
                true,
                crate::config::extended::KnowledgeBaseMergePolicy::Auto,
            ));
        ctx.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                extended,
            ),
        );
        ctx.workspace_lease = Some(Arc::new(crate::workspace_lease::WorkspaceLease::ephemeral(
            crate::workspace_lease::WorkspaceLeaseKind::SameRoot,
            tmp.path().to_path_buf(),
            crate::workspace_lease::WorkspaceLeaseOps::for_coding(),
            crate::workspace_lease::now_unix_ms() + 60_000,
        )));

        let error = check_native_access(&ctx, &target, SandboxPathAccess::ReadWrite)
            .await
            .expect_err("an untrusted leased agent must not access a protected local KB");
        assert!(
            error
                .to_string()
                .contains("local knowledge base that requires a trusted model"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn attached_local_knowledge_is_in_the_native_read_boundary_only() {
        let workspace = tempfile::tempdir().unwrap();
        let attached = tempfile::tempdir().unwrap();
        let withheld = tempfile::tempdir().unwrap();
        let attached_note = attached.path().join("concept.md");
        let withheld_note = withheld.path().join("concept.md");
        std::fs::write(&attached_note, "attached").unwrap();
        std::fs::write(&withheld_note, "withheld").unwrap();

        let mut ctx = sandboxed_ctx(workspace.path());
        ctx.allowed_knowledge_bases =
            Some(std::collections::BTreeSet::from(["attached".to_string()]));
        let mut extended = crate::config::extended::ExtendedConfig::default();
        for (id, path) in [("attached", attached.path()), ("withheld", withheld.path())] {
            extended.knowledge_bases.push(
                crate::config::extended::KnowledgeBaseRegistryEntry::new(
                    id.to_string(),
                    id.to_string(),
                    format!("{id} local knowledge"),
                    crate::config::extended::KnowledgeBaseSource::Local {
                        path: path.to_path_buf(),
                    },
                    crate::config::extended::KnowledgeBaseEmbeddingOwnership::Local,
                    None,
                    None,
                    false,
                    crate::config::extended::KnowledgeBaseMergePolicy::Auto,
                ),
            );
        }
        ctx.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                extended,
            ),
        );

        let checked = check_native_access(&ctx, &attached_note, SandboxPathAccess::Read)
            .await
            .expect("attached local knowledge reads without a path approval");
        assert_eq!(checked, attached_note);

        ctx.approver = None;
        let write = check_native_access(&ctx, &attached_note, SandboxPathAccess::ReadWrite)
            .await
            .expect_err("local knowledge write remains outside the implicit read boundary");
        assert!(
            write
                .to_string()
                .contains("generic native writes are denied"),
            "unexpected write result: {write:#}"
        );

        let denied = check_native_access(&ctx, &withheld_note, SandboxPathAccess::Read)
            .await
            .expect_err("non-attached local knowledge must not be path-approved");
        assert!(
            denied.to_string().contains("not attached to this agent"),
            "unexpected denial: {denied:#}"
        );
    }

    #[tokio::test]
    async fn nested_local_knowledge_requires_every_containing_root_to_be_attached() {
        let workspace = tempfile::tempdir().unwrap();
        let nested = workspace.path().join("private");
        std::fs::create_dir_all(&nested).unwrap();
        let note = nested.join("note.md");
        std::fs::write(&note, "private").unwrap();

        let mut ctx = sandboxed_ctx(workspace.path());
        ctx.allowed_knowledge_bases = Some(std::collections::BTreeSet::from(["outer".to_string()]));
        let mut extended = crate::config::extended::ExtendedConfig::default();
        for (id, path) in [
            ("outer", workspace.path().to_path_buf()),
            ("inner", nested.clone()),
        ] {
            extended.knowledge_bases.push(
                crate::config::extended::KnowledgeBaseRegistryEntry::new(
                    id.to_string(),
                    id.to_string(),
                    format!("{id} local knowledge"),
                    crate::config::extended::KnowledgeBaseSource::Local { path },
                    crate::config::extended::KnowledgeBaseEmbeddingOwnership::Local,
                    None,
                    None,
                    false,
                    crate::config::extended::KnowledgeBaseMergePolicy::Auto,
                ),
            );
        }
        ctx.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                extended,
            ),
        );

        let error = check_native_access(&ctx, &note, SandboxPathAccess::Read)
            .await
            .expect_err("a nested, unattached KB must win over its attached parent");
        assert!(
            error.to_string().contains("not attached to this agent"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn delegated_trusted_knowledge_access_does_not_grant_native_kb_reads() {
        let workspace = tempfile::tempdir().unwrap();
        let knowledge = tempfile::tempdir().unwrap();
        let note = knowledge.path().join("note.md");
        std::fs::write(&note, "protected").unwrap();
        let mut ctx = sandboxed_ctx(workspace.path());
        ctx.executing_model_trusted = false;
        ctx.knowledge_access_trusted = true;
        let mut extended = crate::config::extended::ExtendedConfig::default();
        extended
            .knowledge_bases
            .push(crate::config::extended::KnowledgeBaseRegistryEntry::new(
                "trusted".to_string(),
                "Trusted".to_string(),
                "Trusted local knowledge".to_string(),
                crate::config::extended::KnowledgeBaseSource::Local {
                    path: knowledge.path().to_path_buf(),
                },
                crate::config::extended::KnowledgeBaseEmbeddingOwnership::Local,
                None,
                None,
                true,
                crate::config::extended::KnowledgeBaseMergePolicy::Auto,
            ));
        ctx.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                extended,
            ),
        );

        let error = check_native_access(&ctx, &note, SandboxPathAccess::Read)
            .await
            .expect_err("delegated trust must not become raw filesystem authority");
        assert!(
            error.to_string().contains("requires a trusted model"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn review_cage_denies_an_attached_kb_outside_its_package() {
        let workspace = tempfile::tempdir().unwrap();
        let package = tempfile::tempdir().unwrap();
        let knowledge = tempfile::tempdir().unwrap();
        let note = knowledge.path().join("note.md");
        std::fs::write(&note, "attached").unwrap();
        let mut ctx = sandboxed_ctx(workspace.path());
        ctx.review_cage = Some(
            crate::engine::tool::ReviewCage::skills_review_with_package_roots([package
                .path()
                .to_path_buf()]),
        );
        let mut extended = crate::config::extended::ExtendedConfig::default();
        extended
            .knowledge_bases
            .push(crate::config::extended::KnowledgeBaseRegistryEntry::new(
                "attached".to_string(),
                "Attached".to_string(),
                "Attached local knowledge".to_string(),
                crate::config::extended::KnowledgeBaseSource::Local {
                    path: knowledge.path().to_path_buf(),
                },
                crate::config::extended::KnowledgeBaseEmbeddingOwnership::Local,
                None,
                None,
                false,
                crate::config::extended::KnowledgeBaseMergePolicy::Auto,
            ));
        ctx.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                extended,
            ),
        );
        ctx.workspace_lease = Some(Arc::new(crate::workspace_lease::WorkspaceLease::ephemeral(
            crate::workspace_lease::WorkspaceLeaseKind::SameRoot,
            knowledge.path().to_path_buf(),
            crate::workspace_lease::WorkspaceLeaseOps::for_coding(),
            crate::workspace_lease::now_unix_ms() + 60_000,
        )));

        let error = check_native_access(&ctx, &note, SandboxPathAccess::Read)
            .await
            .expect_err("a review cage must remain a hard outer boundary even with a lease");
        assert!(
            error
                .to_string()
                .contains("background review cannot approve"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn remote_knowledge_contributes_no_native_read_root() {
        let workspace = tempfile::tempdir().unwrap();
        let mut ctx = sandboxed_ctx(workspace.path());
        let mut extended = crate::config::extended::ExtendedConfig::default();
        extended
            .knowledge_bases
            .push(crate::config::extended::KnowledgeBaseRegistryEntry::new(
                "hosted".to_string(),
                "Hosted".to_string(),
                "Hosted knowledge".to_string(),
                crate::config::extended::KnowledgeBaseSource::Remote {
                    url: "https://knowledge.example.test/team".to_string(),
                },
                crate::config::extended::KnowledgeBaseEmbeddingOwnership::RemoteOwned,
                None,
                None,
                false,
                crate::config::extended::KnowledgeBaseMergePolicy::Auto,
            ));
        ctx.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                extended,
            ),
        );

        assert!(
            crate::knowledge::attached_local_knowledge_roots(&ctx)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn review_cage_native_access_uses_preauthorized_skill_package_root() {
        let cwd = tempfile::tempdir().unwrap();
        let skills = tempfile::tempdir().unwrap();
        let package = skills.path().join("reviewed");
        std::fs::create_dir_all(&package).unwrap();
        let mut ctx = crate::tools::common::test_ctx(cwd.path());
        ctx.review_cage = Some(
            crate::engine::tool::ReviewCage::skills_review_with_package_roots([package.clone()]),
        );

        let checked = check_native_access(
            &ctx,
            &package.join("references/new.md"),
            SandboxPathAccess::ReadWrite,
        )
        .await
        .unwrap();
        assert!(checked.starts_with(&package));

        let err = check_native_access(
            &ctx,
            &skills.path().join("other/SKILL.md"),
            SandboxPathAccess::ReadWrite,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("outside the session boundary"), "{err}");
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
    async fn native_access_symlink_escape_still_rejected_with_sandbox_off() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, "secret").unwrap();
        let link = tmp.path().join("link.txt");
        symlink_file(&secret, &link);
        let ctx = sandboxed_ctx(tmp.path());
        ctx.session.set_sandbox_enabled(false);

        let resolver = spawn_cancel_next_path_prompt(&ctx);
        let err = check_native_access(&ctx, &link, SandboxPathAccess::Read)
            .await
            .unwrap_err();
        resolver.await.unwrap();
        assert!(
            err.to_string().contains("outside the session boundary"),
            "sandbox-off symlink escape must remain approval-gated: {err}"
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
    async fn native_access_parent_traversal_still_rejected_with_sandbox_off() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut ctx = sandboxed_ctx(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        ctx.approver = None;
        let target = outside.path().join("missing/../secret.txt");

        let err = check_native_access(&ctx, &target, SandboxPathAccess::Read)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("unresolved parent traversal in"),
            "unresolved parent traversal must remain rejected: {err}"
        );
    }

    #[test]
    fn confine_hard_deny_path_still_never_prompts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let secret = tmp.path().join("outside.txt");
        std::fs::write(&secret, "secret").unwrap();
        let link = root.join("escape");
        symlink_file(&secret, &link);

        let err = confine(&root, "escape").unwrap_err();
        assert!(
            err.to_string().contains("outside the package sandbox"),
            "hard-deny confine path must refuse without an approval seam: {err}"
        );
    }

    #[tokio::test]
    async fn native_access_prompts_outside_boundary_with_sandbox_off() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        let target = outside.path().join("secret.txt");
        std::fs::write(&target, "secret").unwrap();

        let resolver = spawn_cancel_next_path_prompt(&ctx);
        let err = check_native_access(&ctx, &target, SandboxPathAccess::Read)
            .await
            .unwrap_err();
        resolver.await.unwrap();
        assert!(
            err.to_string()
                .contains("outside the session boundary and access was denied"),
            "sandbox-off outside path must be approval-gated: {err}"
        );
    }

    #[tokio::test]
    async fn native_access_granted_path_is_silent_with_sandbox_off() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        let target = outside.path().join("notes.txt");
        std::fs::write(&target, "notes").unwrap();
        let store = GrantStore::new(
            ctx.session.db.clone(),
            ctx.session.id,
            ctx.cwd.clone(),
            ctx.config.clone(),
        );
        store
            .record_path(
                outside.path(),
                crate::approval::store::Scope::Session,
                SandboxPathAccess::Read,
            )
            .await
            .unwrap();

        check_native_access(&ctx, &target, SandboxPathAccess::Read)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn native_access_unprovable_path_prompts_with_sandbox_off() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        ctx.session.set_sandbox_enabled(false);
        let broken = outside.path().join("broken-link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path().join("missing"), &broken).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(outside.path().join("missing"), &broken).unwrap();

        let resolver = spawn_cancel_next_path_prompt(&ctx);
        let err = check_native_access(&ctx, &broken, SandboxPathAccess::Read)
            .await
            .unwrap_err();
        resolver.await.unwrap();
        assert!(
            err.to_string()
                .contains("outside the session boundary and access was denied"),
            "sandbox-off unprovable path must prompt instead of passing through raw: {err}"
        );
    }

    #[tokio::test]
    async fn native_access_behavior_unchanged_with_sandbox_on() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ctx = sandboxed_ctx(tmp.path());
        assert!(ctx.session.sandbox_enabled());

        check_native_access(
            &ctx,
            &tmp.path().join("inside.txt"),
            SandboxPathAccess::Read,
        )
        .await
        .unwrap();

        let target = outside.path().join("secret.txt");
        std::fs::write(&target, "secret").unwrap();
        let resolver = spawn_cancel_next_path_prompt(&ctx);
        let err = check_native_access(&ctx, &target, SandboxPathAccess::Read)
            .await
            .unwrap_err();
        resolver.await.unwrap();
        assert!(
            err.to_string()
                .contains("outside the session boundary and access was denied"),
            "sandbox-on outside behavior should remain approval-gated: {err}"
        );
    }

    #[tokio::test]
    async fn native_access_without_approver_denies_in_both_sandbox_states() {
        for sandbox_enabled in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            let mut ctx = sandboxed_ctx(tmp.path());
            ctx.session.set_sandbox_enabled(sandbox_enabled);
            ctx.approver = None;
            let target = outside.path().join("x.txt");
            std::fs::write(&target, "x").unwrap();

            let err = check_native_access(&ctx, &target, SandboxPathAccess::Read)
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("cannot be approved"),
                "missing approver must fail closed with sandbox_enabled={sandbox_enabled}: {err}"
            );
        }
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
                let open = db.list_open_interrupts(sid).await.unwrap();
                if let Some(row) = open.iter().find(|row| hub.has_waiter(row.interrupt_id)) {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            let response = ResolveResponse::Single {
                selected_id: ID_APPROVE_SESSION.into(),
            };
            db.resolve_interrupt(iid, &response).await.unwrap();
            assert!(hub.resolve(iid, response));
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
        let store = GrantStore::new(
            ctx.session.db.clone(),
            ctx.session.id,
            ctx.cwd.clone(),
            ctx.config.clone(),
        );
        store
            .record_path(
                outside.path(),
                crate::approval::store::Scope::Session,
                SandboxPathAccess::Read,
            )
            .await
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
                let open = db.list_open_interrupts(sid).await.unwrap();
                if let Some(row) = open.iter().find(|row| hub.has_waiter(row.interrupt_id)) {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            let response = ResolveResponse::Cancel;
            db.resolve_interrupt(iid, &response).await.unwrap();
            assert!(hub.resolve(iid, response));
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

    /// A committed secret path still uses the same approval gate.
    #[tokio::test]
    async fn secret_path_gate_denies_non_gitignored_env_file_headless() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = gitignore_ctx(tmp.path());
        ctx.approver = None;
        let path = tmp.path().join(".env.production");
        std::fs::write(&path, "TOKEN=long-secret-value").unwrap();
        let refusal = check_gitignore_read(&ctx, &path)
            .await
            .unwrap()
            .expect("secret path must be gated");
        assert!(refusal.content.contains("secret-bearing"));
        assert!(refusal.content.contains(".env.production"));
    }

    #[tokio::test]
    async fn secret_path_gate_honors_explicit_session_allow() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = gitignore_ctx(tmp.path());
        ctx.approver = None;
        let path = tmp.path().join(".env.production");
        std::fs::write(&path, "TOKEN=long-secret-value").unwrap();
        ctx.session.add_gitignore_session_allow(".env.production");
        assert!(check_gitignore_read(&ctx, &path).await.unwrap().is_none());
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
        use crate::approval::{ID_APPROVE_SESSION, ID_GITIGNORE_FILE};
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
                let open = db.list_open_interrupts(sid).await.unwrap();
                if let Some(row) = open.iter().find(|row| hub.has_waiter(row.interrupt_id)) {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            let response = ResolveResponse::Single {
                selected_id: ID_GITIGNORE_FILE.into(),
            };
            db.resolve_interrupt(iid1, &response).await.unwrap();
            assert!(hub.resolve(iid1, response));
            let iid2 = loop {
                let open = db.list_open_interrupts(sid).await.unwrap();
                if let Some(row) = open
                    .iter()
                    .find(|r| r.interrupt_id != iid1 && hub.has_waiter(r.interrupt_id))
                {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            let response = ResolveResponse::Single {
                selected_id: ID_APPROVE_SESSION.into(),
            };
            db.resolve_interrupt(iid2, &response).await.unwrap();
            assert!(hub.resolve(iid2, response));
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
                let open = db.list_open_interrupts(sid).await.unwrap();
                if let Some(row) = open.iter().find(|row| hub.has_waiter(row.interrupt_id)) {
                    break row.interrupt_id;
                }
                tokio::task::yield_now().await;
            };
            let response = ResolveResponse::Freetext {
                text: crate::approval::NONINTERACTIVE_RUN_DENIAL.to_string(),
            };
            db.resolve_interrupt(interrupt_id, &response).await.unwrap();
            assert!(hub.resolve(interrupt_id, response));
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
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "permission_decision")
            .expect("permission decision audit event");
        assert_eq!(event.data["source"], "headless_auto_reject");
    }
}

#[cfg(test)]
mod cockpit_path_tests {
    use super::is_workspace_cockpit_path;

    #[test]
    fn cockpit_dir_traversal_is_caught() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = std::fs::canonicalize(tmp.path()).unwrap();
        let path = cwd.join(".cockpit").join("mcp.json");
        assert!(is_workspace_cockpit_path(&cwd, &path));
        assert!(!is_workspace_cockpit_path(&cwd, &cwd.join("src/main.rs")));
    }
}
