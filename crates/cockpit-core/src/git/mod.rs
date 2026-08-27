//! Tiny git helpers for the TUI status line + redaction-table scoping.
//!
//! We shell out to `git` (matching kctx-local/ralph-rs's choice) rather
//! than depending on `git2`/`libgit2`. Reasons: smaller binary, respects
//! the user's git config and SSH keys, no version-skew breakage.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result};

pub use cockpit_proto::RepoStatus;

/// Compact staged/unstaged/unpushed counts for branch chrome and startup
/// welcome text.
pub fn repo_counts(repo: &RepoStatus) -> String {
    let mut parts = Vec::new();
    if repo.staged > 0 {
        parts.push(format!("+{}", repo.staged));
    }
    if repo.unstaged > 0 {
        parts.push(format!("~{}", repo.unstaged));
    }
    if repo.unpushed > 0 {
        parts.push(format!("^{}", repo.unpushed));
    }
    parts.join(" ")
}

/// Walk `path` and its ancestors looking for a `.git` directory; return
/// the worktree root (the parent of `.git`). Returns `None` if not in a
/// git repo.
pub fn find_worktree_root(path: &Path) -> Option<PathBuf> {
    let cwd = if path.is_dir() { path } else { path.parent()? };
    let output = run_optional_command("git", cwd, &["rev-parse", "--show-toplevel"])?;

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

/// Current branch name, or `None` if not in a git repo or detached HEAD.
pub fn current_branch(worktree: &Path) -> Result<Option<String>> {
    let Some(output) =
        run_optional_command("git", worktree, &["rev-parse", "--abbrev-ref", "HEAD"])
    else {
        return Ok(None);
    };

    if !output.status.success() {
        return Ok(None);
    }

    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if branch.is_empty() || branch == "HEAD" {
        Ok(None)
    } else {
        Ok(Some(branch))
    }
}

pub fn repo_status(worktree: &Path) -> Result<Option<RepoStatus>> {
    let Some(branch) = current_branch(worktree)? else {
        return Ok(None);
    };

    // `--no-renames`: the pill only needs staged/unstaged/untracked counts,
    // and rename detection is O(n)-ish extra matching cockpit never uses. A
    // rename then counts as a delete + an untracked entry instead of one `R`
    // — a negligible difference in an already-approximate pill. We keep the
    // default untracked enumeration (no `-uno`) so the pill still reflects
    // untracked changes.
    let Some(output) = run_optional_command(
        "git",
        worktree,
        &["status", "--porcelain=v1", "--no-renames"],
    ) else {
        return Ok(None);
    };

    let mut staged = 0;
    let mut unstaged = 0;
    if output.status.success() {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.starts_with("??") {
                unstaged += 1;
                continue;
            }
            let bytes = line.as_bytes();
            if let Some(x) = bytes.first()
                && *x != b' '
            {
                staged += 1;
            }
            if let Some(y) = bytes.get(1)
                && *y != b' '
            {
                unstaged += 1;
            }
        }
    }

    let unpushed = unpushed_commits(worktree)?;

    Ok(Some(RepoStatus {
        branch,
        staged,
        unstaged,
        unpushed,
    }))
}

fn unpushed_commits(worktree: &Path) -> Result<u32> {
    let Some(output) = run_optional_command(
        "git",
        worktree,
        &["rev-list", "--count", "@{upstream}..HEAD"],
    ) else {
        return Ok(0);
    };

    if !output.status.success() {
        return Ok(0);
    }

    let count = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .unwrap_or(0);
    Ok(count)
}

fn run_optional_command(command: &str, cwd: &Path, args: &[&str]) -> Option<Output> {
    if command == "git"
        && crate::external_runtime::require_live_available_for_launch(
            crate::external_runtime::ID_GIT,
            cwd,
        )
        .is_err()
    {
        return None;
    }
    match Command::new(command).args(args).current_dir(cwd).output() {
        Ok(output) => Some(output),
        Err(error) => {
            tracing::debug!(
                command = %format!("{} {}", command, args.join(" ")),
                cwd = %cwd.display(),
                %error,
                "failed to launch optional git command"
            );
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Worktree + merge-queue plumbing (plan.md §4.1, worktree-proposal.md).
//
// The plan executor (`engine::exec`) runs each parallel step in its own git
// worktree on its own branch, then lands completed branches through a serial
// merge queue. All git interaction goes through `git` CLI (same rationale as
// above: respect the user's config/SSH keys, no libgit2 version skew). These
// helpers are cross-platform — git's own path handling normalizes separators
// on Windows, and worktree paths are passed as `&Path` throughout.
// ---------------------------------------------------------------------------

/// Result of a git invocation that may legitimately fail (e.g. a rebase
/// hitting a conflict). Captures the pieces callers branch on rather than
/// erroring on a non-zero exit.
#[derive(Debug, Clone)]
pub struct GitOutcome {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Run `git <args>` in `dir`, returning the captured outcome. A failure to
/// *launch* git (binary missing) is an `Err`; a non-zero git exit is a
/// `GitOutcome { success: false, .. }` the caller inspects.
pub fn run_git(dir: &Path, args: &[&str]) -> Result<GitOutcome> {
    crate::external_runtime::require_live_available_for_launch(
        crate::external_runtime::ID_GIT,
        dir,
    )
    .map_err(|err| anyhow::anyhow!("git blocked by external-runtime health: {err}"))?;
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("launching `git {}`", args.join(" ")))?;
    Ok(GitOutcome {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Run `git <args>` in `dir` and require success, surfacing stderr on
/// failure. Use for git ops where a non-zero exit is genuinely an error
/// (worktree add/remove, branch create/delete) rather than an expected
/// outcome (rebase conflict).
pub fn run_git_checked(dir: &Path, args: &[&str]) -> Result<String> {
    let out = run_git(dir, args)?;
    if !out.success {
        anyhow::bail!("`git {}` failed: {}", args.join(" "), out.stderr.trim());
    }
    Ok(out.stdout)
}

pub(crate) fn run_git_checked_bytes(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    crate::external_runtime::require_live_available_for_launch(
        crate::external_runtime::ID_GIT,
        dir,
    )
    .map_err(|err| anyhow::anyhow!("git blocked by external-runtime health: {err}"))?;
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("launching `git {}`", args.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

/// Resolve a git path through symlink-aware containment. A dangling symlink
/// or `..` escape fails closed.
pub fn resolve_git_path(path: &Path) -> Result<PathBuf> {
    cockpit_host::path_containment::effective_path(path)
        .with_context(|| format!("git path `{}` does not resolve", path.display()))
}

/// Reject a worktree destination whose syscall-effective path is not under
/// `parent` (symlink and prefix escapes included).
pub fn assert_worktree_destination_under(parent: &Path, path: &Path) -> Result<()> {
    let parent = resolve_git_path(parent)?;
    let path = resolve_git_path(path)?;
    if !cockpit_host::path_containment::contained_under(&parent, &path) && path != parent {
        anyhow::bail!(
            "worktree destination `{}` escapes `{}`",
            path.display(),
            parent.display()
        );
    }
    Ok(())
}

/// Add a worktree at `path` checking out a **new** branch `branch` based on
/// `base` (a branch name or commit). The branch must not already exist
/// (git enforces branch-uniqueness across worktrees). Paths are resolved
/// through symlink-aware containment before they are handed to git.
pub fn worktree_add(repo: &Path, path: &Path, branch: &str, base: &str) -> Result<()> {
    reject_leading_dash("branch", branch)?;
    reject_leading_dash("base", base)?;
    let repo = resolve_git_path(repo)?;
    let path = resolve_git_path(path)?;
    let path = path.to_string_lossy();
    run_git_checked(&repo, &["worktree", "add", &path, "-b", branch, "--", base])?;
    Ok(())
}

/// Remove the worktree at `path`. `--force` drops it even with local
/// modifications. Host-authorized cleanup of an unpinned, certain lease may
/// use this; orchestration must never call it for a pinned or uncertain
/// worktree — use [`worktree_remove_clean`] after those guards.
pub fn worktree_remove(repo: &Path, path: &Path) -> Result<()> {
    let path = path.to_string_lossy();
    run_git_checked(repo, &["worktree", "remove", "--force", &path])?;
    Ok(())
}

/// Resolve the primary checkout for a linked worktree before removing that
/// worktree. `git worktree list --porcelain` reports the main worktree first;
/// use that surviving checkout for follow-up repository operations such as
/// deleting the private branch. Never fall back to the linked checkout: it
/// will be gone after `worktree remove`.
pub fn primary_worktree_root(linked_worktree: &Path) -> Result<PathBuf> {
    let listed = run_git_checked(linked_worktree, &["worktree", "list", "--porcelain"])?;
    let primary = listed
        .lines()
        .find_map(|line| line.strip_prefix("worktree "))
        .filter(|path| !path.is_empty())
        .context("git did not report a primary worktree")?;
    let primary = resolve_git_path(Path::new(primary))?;
    let linked = resolve_git_path(linked_worktree)?;
    if primary == linked {
        anyhow::bail!(
            "managed worktree is unexpectedly the primary checkout; refusing cleanup without a surviving repository location"
        );
    }
    Ok(primary)
}

/// Remove a worktree without `--force`. Fails closed when the tree is dirty
/// or locked, so a pinned/uncertain/in-use tree cannot be clobbered.
pub fn worktree_remove_clean(repo: &Path, path: &Path) -> Result<()> {
    let repo = resolve_git_path(repo)?;
    let path = resolve_git_path(path)?;
    let path = path.to_string_lossy();
    run_git_checked(&repo, &["worktree", "remove", "--", &path])?;
    Ok(())
}

/// Add a detached worktree at `path` based on `base`. No local branch is
/// created, so the checkout is not a user-visible ref.
pub fn worktree_add_detached(repo: &Path, path: &Path, base: &str) -> Result<()> {
    reject_leading_dash("base", base)?;
    let repo = resolve_git_path(repo)?;
    let path = resolve_git_path(path)?;
    let path = path.to_string_lossy();
    run_git_checked(&repo, &["worktree", "add", "--detach", &path, "--", base])?;
    Ok(())
}

/// Prune stale worktree administrative entries (after a manual dir removal).
pub fn worktree_prune(repo: &Path) -> Result<()> {
    run_git_checked(repo, &["worktree", "prune"])?;
    Ok(())
}

/// Delete the local branch `branch` (`-D`, forced — a merged step branch is
/// fast-forwarded into the base so a plain `-d` would also work, but the
/// resolver/abort paths may drop an un-merged branch).
pub fn branch_delete(repo: &Path, branch: &str) -> Result<()> {
    reject_leading_dash("branch", branch)?;
    run_git_checked(repo, &["branch", "-D", "--", branch])?;
    Ok(())
}

/// The current HEAD commit sha of the worktree at `dir`.
pub fn head_sha(dir: &Path) -> Result<String> {
    Ok(run_git_checked(dir, &["rev-parse", "HEAD"])?
        .trim()
        .to_string())
}

/// The unified diff of the worktree against `HEAD` — every uncommitted
/// change, staged or not — as seen from `dir`. Read-only (`git diff` makes
/// no modifications). Used by the read-only `/diff` TUI pane. A non-zero
/// exit (e.g. not a git worktree) surfaces as an `Err`; the pane renders
/// that inline rather than failing to open.
pub fn diff_worktree(dir: &Path) -> Result<String> {
    let out = run_git(dir, &["diff", "HEAD"])?;
    if !out.success {
        anyhow::bail!("`git diff HEAD` failed: {}", out.stderr.trim());
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_git_command_launch_failure_returns_none() {
        let cwd = std::env::current_dir().unwrap();
        let out = run_optional_command(
            "cockpit-definitely-not-a-real-git-binary",
            &cwd,
            &["rev-parse", "--show-toplevel"],
        );

        assert!(out.is_none());
    }

    #[test]
    fn optional_git_command_non_success_still_returns_output() {
        let tmp = tempfile::tempdir().unwrap();
        let out = run_optional_command("git", tmp.path(), &["rev-parse", "--show-toplevel"])
            .expect("git launched");

        assert!(!out.status.success());
    }

    #[test]
    fn leading_dash_refs_are_rejected() {
        let err = reject_leading_dash("branch", "-bad").unwrap_err();
        assert!(format!("{err}").contains("branch"));
        assert!(reject_leading_dash("branch", "feature/good").is_ok());
    }

    #[test]
    fn worktree_destination_rejects_symlink_and_prefix_escapes() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("worktrees");
        let sibling = tmp.path().join("sibling");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        let inside = parent.join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&inside).unwrap();
        assert!(assert_worktree_destination_under(&parent, &inside).is_ok());
        assert!(assert_worktree_destination_under(&parent, &sibling).is_err());
        #[cfg(unix)]
        {
            let escape = parent.join("escape");
            std::os::unix::fs::symlink(&sibling, &escape).unwrap();
            assert!(
                assert_worktree_destination_under(&parent, &escape).is_err(),
                "symlink into a sibling must not count as an in-parent worktree"
            );
        }
    }
}

/// The unified diff of the worktree against the index — unstaged changes only.
pub fn diff_unstaged(dir: &Path) -> Result<String> {
    let out = run_git(dir, &["diff"])?;
    if !out.success {
        anyhow::bail!("`git diff` failed: {}", out.stderr.trim());
    }
    Ok(out.stdout)
}

/// The unified diff of local commits not yet pushed to the configured upstream.
pub fn diff_unpushed(dir: &Path) -> Result<String> {
    let out = run_git(dir, &["diff", "@{upstream}..HEAD"])?;
    if !out.success {
        anyhow::bail!(
            "`git diff @{{upstream}}..HEAD` failed: {}",
            out.stderr.trim()
        );
    }
    Ok(out.stdout)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewSourceCommand {
    pub label: String,
    pub command: String,
    pub diff: String,
}

pub fn review_source_uncommitted(dir: &Path) -> Result<ReviewSourceCommand> {
    Ok(ReviewSourceCommand {
        label: "Uncommitted changes".into(),
        command: "git diff HEAD".into(),
        diff: diff_worktree(dir)?,
    })
}

pub fn review_source_unstaged(dir: &Path) -> Result<ReviewSourceCommand> {
    Ok(ReviewSourceCommand {
        label: "Unstaged changes".into(),
        command: "git diff".into(),
        diff: diff_unstaged(dir)?,
    })
}

pub fn review_source_unpushed(dir: &Path) -> Result<ReviewSourceCommand> {
    Ok(ReviewSourceCommand {
        label: "Unpushed changes".into(),
        command: "git diff @{upstream}..HEAD".into(),
        diff: diff_unpushed(dir)?,
    })
}

pub fn gh_pr_diff(dir: &Path, pr: &str) -> Result<String> {
    // Binary health only — authentication is a separate feature-owned check.
    crate::external_runtime::require_live_available_for_launch(crate::external_runtime::ID_GH, dir)
        .map_err(|err| anyhow::anyhow!("gh blocked by external-runtime health: {err}"))?;
    let output = Command::new("gh")
        .args(["pr", "diff", "--", pr])
        .current_dir(dir)
        .output()
        .with_context(|| "launching `gh pr diff` (is GitHub CLI installed?)")?;
    if !output.status.success() {
        anyhow::bail!(
            "`gh pr diff {pr}` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn review_source_pr(dir: &Path, pr: &str) -> Result<ReviewSourceCommand> {
    let pr = pr.trim();
    Ok(ReviewSourceCommand {
        label: format!("PR {pr}"),
        command: format!("gh pr diff -- {}", shell_single_quote(pr)),
        diff: gh_pr_diff(dir, pr)?,
    })
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// The unified diff of the index against `HEAD` — staged changes only
/// (`git diff --cached`) — as seen from `dir`. Read-only. Used by the
/// `/diff staged` TUI source.
pub fn diff_staged(dir: &Path) -> Result<String> {
    let out = run_git(dir, &["diff", "--cached"])?;
    if !out.success {
        anyhow::bail!("`git diff --cached` failed: {}", out.stderr.trim());
    }
    Ok(out.stdout)
}

fn reject_leading_dash(label: &str, value: &str) -> Result<()> {
    if value.starts_with('-') {
        anyhow::bail!("refusing {label} that starts with `-`: {value}");
    }
    Ok(())
}

/// Symbolic ref at HEAD (`refs/heads/…`) or the literal `detached` when HEAD
/// is not a branch.
pub fn head_ref_name(dir: &Path) -> Result<String> {
    let out = run_git(dir, &["symbolic-ref", "-q", "HEAD"])?;
    if out.success {
        let name = out.stdout.trim();
        if !name.is_empty() {
            return Ok(name.to_string());
        }
    }
    Ok("detached".into())
}

/// Exact index stage listing (`git ls-files --stage`). Byte-identical across
/// a no-op so integration can refuse rather than overwrite on drift.
pub fn index_stage_text(dir: &Path) -> Result<String> {
    Ok(run_git_checked(dir, &["ls-files", "--stage"])?)
}

/// Number of commits reachable from `HEAD`. Used to prove orchestration never
/// creates a user-visible commit.
pub fn commit_count(dir: &Path) -> Result<u64> {
    let raw = run_git_checked(dir, &["rev-list", "--count", "HEAD"])?;
    raw.trim()
        .parse::<u64>()
        .with_context(|| format!("parsing commit count from `{raw}`"))
}

/// Relative paths of tracked files that differ from `HEAD` (staged or not).
pub fn touched_paths_versus_head(dir: &Path) -> Result<Vec<String>> {
    let out = git_allow_diff_exit(run_git(
        dir,
        &["diff", "--name-only", "--no-renames", "HEAD"],
    )?)?;
    Ok(split_path_lines(&out))
}

/// Untracked, non-ignored paths relative to `dir`.
pub fn untracked_paths(dir: &Path) -> Result<Vec<String>> {
    let out = run_git_checked(dir, &["ls-files", "--others", "--exclude-standard"])?;
    Ok(split_path_lines(&out))
}

/// SHA-256 of a worktree-relative path's current bytes, or the fixed
/// `absent` digest when the path does not exist.
pub(crate) fn path_content_digest(
    dir: &Path,
    relative: &str,
) -> Result<crate::db::workspace_lease_artifacts::WorkspaceDigest> {
    use crate::db::workspace_lease_artifacts::WorkspaceDigest;
    reject_relative_escape(relative)?;
    let path = dir.join(relative);
    if !path.exists() {
        return Ok(WorkspaceDigest::of(b"absent"));
    }
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading `{}` for receipt", path.display()))?;
    Ok(WorkspaceDigest::of(&bytes))
}

/// Ordered SHA-256 of `(path, content-digest)` pairs. Empty lists hash the
/// empty byte string.
pub(crate) fn manifest_digest<'a>(
    dir: &Path,
    paths: impl IntoIterator<Item = &'a str>,
) -> Result<crate::db::workspace_lease_artifacts::WorkspaceDigest> {
    use crate::db::workspace_lease_artifacts::WorkspaceDigest;
    let mut acc = String::new();
    let mut ordered: Vec<&str> = paths.into_iter().collect();
    ordered.sort_unstable();
    ordered.dedup();
    for path in ordered {
        let digest = path_content_digest(dir, path)?;
        acc.push_str(path);
        acc.push('\0');
        acc.push_str(digest.as_str());
        acc.push('\n');
    }
    Ok(WorkspaceDigest::of(acc.as_bytes()))
}

/// Unified diff of every uncommitted change (tracked vs HEAD plus untracked
/// files as `/dev/null` diffs). Never stages. `git add -A` is forbidden here.
pub(crate) fn capture_uncommitted_patch(dir: &Path) -> Result<UncommittedPatch> {
    let tracked =
        git_allow_diff_exit(run_git(dir, &["diff", "--binary", "--no-renames", "HEAD"])?)?;
    let untracked = untracked_paths(dir)?;
    let mut diff = tracked;
    for file in &untracked {
        reject_relative_escape(file)?;
        let piece = git_allow_diff_exit(run_git(
            dir,
            &["diff", "--no-index", "--binary", "--", "/dev/null", file],
        )?)?;
        if !diff.ends_with('\n') && !diff.is_empty() && !piece.is_empty() {
            diff.push('\n');
        }
        diff.push_str(&piece);
    }
    let mut touched = touched_paths_versus_head(dir)?;
    for file in &untracked {
        if !touched.iter().any(|p| p == file) {
            touched.push(file.clone());
        }
    }
    touched.sort_unstable();
    touched.dedup();
    Ok(UncommittedPatch {
        diff,
        touched_paths: touched,
        untracked_paths: untracked,
    })
}

/// Apply a unified diff to the working tree only. Does not update the index
/// and does not create a commit.
pub(crate) fn apply_uncommitted_patch(dir: &Path, diff: &str) -> Result<()> {
    if diff.trim().is_empty() {
        return Ok(());
    }
    let tmp = tempfile::NamedTempFile::new().context("creating temporary patch file")?;
    std::fs::write(tmp.path(), diff.as_bytes()).context("writing temporary patch")?;
    let path = tmp.path().to_string_lossy().into_owned();
    let out = run_git(dir, &["apply", "--", &path])?;
    if !out.success {
        anyhow::bail!("`git apply` failed: {}", out.stderr.trim());
    }
    Ok(())
}

/// Reverse a previously applied uncommitted patch, preserving Git modes and
/// symlink objects as well as file contents.
pub(crate) fn reverse_uncommitted_patch(dir: &Path, diff: &str) -> Result<()> {
    if diff.trim().is_empty() {
        return Ok(());
    }
    let tmp = tempfile::NamedTempFile::new().context("creating temporary reverse patch file")?;
    std::fs::write(tmp.path(), diff.as_bytes()).context("writing temporary reverse patch")?;
    let path = tmp.path().to_string_lossy().into_owned();
    let out = run_git(dir, &["apply", "--reverse", "--", &path])?;
    if !out.success {
        anyhow::bail!("`git apply --reverse` failed: {}", out.stderr.trim());
    }
    Ok(())
}

pub(crate) fn delete_private_ref(dir: &Path, ref_name: &str) -> Result<()> {
    if !ref_name.starts_with("refs/cockpit/") {
        anyhow::bail!("private ref `{ref_name}` must be under refs/cockpit/");
    }
    run_git_checked(dir, &["update-ref", "-d", "--", ref_name])?;
    Ok(())
}

/// Dry-run `git apply --check`. A conflict is `Ok(false)`; launch failure is
/// `Err`.
pub(crate) fn apply_uncommitted_patch_check(dir: &Path, diff: &str) -> Result<bool> {
    if diff.trim().is_empty() {
        return Ok(true);
    }
    let tmp = tempfile::NamedTempFile::new().context("creating temporary patch file")?;
    std::fs::write(tmp.path(), diff.as_bytes()).context("writing temporary patch")?;
    let path = tmp.path().to_string_lossy().into_owned();
    let out = run_git(dir, &["apply", "--check", "--", &path])?;
    Ok(out.success)
}

/// Store `bytes` as a git blob and point `ref_name` at it. The ref must live
/// under `refs/cockpit/` so it is not a user-visible branch.
pub(crate) fn store_private_blob_ref(dir: &Path, ref_name: &str, bytes: &[u8]) -> Result<String> {
    reject_leading_dash("ref", ref_name)?;
    if !ref_name.starts_with("refs/cockpit/") {
        anyhow::bail!("private artifact ref `{ref_name}` must be under refs/cockpit/");
    }
    let tmp = tempfile::NamedTempFile::new().context("creating blob payload")?;
    std::fs::write(tmp.path(), bytes).context("writing blob payload")?;
    let path = tmp.path().to_string_lossy().into_owned();
    let sha = run_git_checked(dir, &["hash-object", "-w", "--", &path])?
        .trim()
        .to_string();
    run_git_checked(dir, &["update-ref", "--", ref_name, &sha])?;
    Ok(sha)
}

/// Byte-identical target receipt: HEAD, ref, index, and a digest of every
/// tracked plus untracked path. Used to prove failed integration made no
/// target edit.
pub(crate) fn byte_identical_receipt(dir: &Path) -> Result<ByteIdenticalReceipt> {
    use crate::db::workspace_lease_artifacts::WorkspaceDigest;
    let head = head_sha(dir)?;
    let git_ref = head_ref_name(dir)?;
    let index = index_stage_text(dir)?;
    let mut paths = run_git_checked(dir, &["ls-files", "-c", "-o", "--exclude-standard"])?;
    let mut listed = split_path_lines(&paths);
    listed.sort_unstable();
    listed.dedup();
    paths.clear();
    for rel in &listed {
        let digest = path_content_digest(dir, rel)?;
        paths.push_str(rel);
        paths.push('\0');
        paths.push_str(digest.as_str());
        paths.push('\n');
    }
    // Include Git's raw worktree delta so type and executable-bit changes are
    // part of the byte-identical proof, not just regular-file contents.
    paths.push_str(&run_git_checked(
        dir,
        &["diff", "--raw", "--no-renames", "HEAD"],
    )?);
    Ok(ByteIdenticalReceipt {
        head,
        git_ref,
        index,
        worktree: WorkspaceDigest::of(paths.as_bytes()).as_str().to_string(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ByteIdenticalReceipt {
    pub head: String,
    pub git_ref: String,
    pub index: String,
    pub worktree: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UncommittedPatch {
    pub diff: String,
    pub touched_paths: Vec<String>,
    pub untracked_paths: Vec<String>,
}

impl UncommittedPatch {
    pub fn digest(&self) -> crate::db::workspace_lease_artifacts::WorkspaceDigest {
        crate::db::workspace_lease_artifacts::WorkspaceDigest::of(self.diff.as_bytes())
    }

    pub(crate) fn validate_paths(&self) -> Result<()> {
        for path in self.touched_paths.iter().chain(&self.untracked_paths) {
            reject_relative_escape(path)?;
        }
        Ok(())
    }
}

fn split_path_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn reject_relative_escape(relative: &str) -> Result<()> {
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.starts_with('\\')
        || relative.split(['/', '\\']).any(|part| part == "..")
    {
        anyhow::bail!("refusing escaped worktree-relative path `{relative}`");
    }
    Ok(())
}

/// `git diff` / `git diff --no-index` exit 1 when a diff exists. Treat empty
/// stderr, or a stdout that is already a unified diff, as a successful capture.
fn git_allow_diff_exit(out: GitOutcome) -> Result<String> {
    if out.success || out.stderr.trim().is_empty() || out.stdout.contains("diff --git") {
        return Ok(out.stdout);
    }
    anyhow::bail!("git diff failed: {}", out.stderr.trim());
}
