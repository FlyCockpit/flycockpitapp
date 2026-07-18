//! Tiny git helpers for the TUI status line + redaction-table scoping.
//!
//! We shell out to `git` (matching kctx-local/ralph-rs's choice) rather
//! than depending on `git2`/`libgit2`. Reasons: smaller binary, respects
//! the user's git config and SSH keys, no version-skew breakage.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoStatus {
    pub branch: String,
    pub staged: u32,
    pub unstaged: u32,
    pub unpushed: u32,
}

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

/// Add a worktree at `path` checking out a **new** branch `branch` based on
/// `base` (a branch name or commit). The branch must not already exist
/// (git enforces branch-uniqueness across worktrees).
pub fn worktree_add(repo: &Path, path: &Path, branch: &str, base: &str) -> Result<()> {
    reject_leading_dash("branch", branch)?;
    reject_leading_dash("base", base)?;
    let path = path.to_string_lossy();
    run_git_checked(repo, &["worktree", "add", &path, "-b", branch, "--", base])?;
    Ok(())
}

/// Remove the worktree at `path`. `--force` drops it even with local
/// modifications (the executor owns the worktree; on teardown/abort there is
/// no user state to preserve).
pub fn worktree_remove(repo: &Path, path: &Path) -> Result<()> {
    let path = path.to_string_lossy();
    run_git_checked(repo, &["worktree", "remove", "--force", &path])?;
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
        command: format!("gh pr diff {pr}"),
        diff: gh_pr_diff(dir, pr)?,
    })
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
