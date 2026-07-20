//! Single-path gitignore evaluation + the read-gate allowlist
//! (implementation note).
//!
//! The codebase-intelligence index walk (`crate::intel`) and the composer
//! `@`-tag popup (in the TUI file-tag module) both reach gitignore status through
//! the `ignore` crate's [`ignore::WalkBuilder`], which answers "is this whole
//! tree filtered" but not "is this *one* path ignored". This module provides
//! that single-path predicate over the same `ignore`-crate machinery, plus the
//! per-project allowlist (gitignore-style globs) that re-permits a gitignored
//! path for the `read`/`readlock` tools and the two discovery surfaces.
//!
//! A path is **permitted** when it is *not* gitignored, **or** it matches the
//! effective allowlist. The gate evaluates against the *resolved target* path
//! (symlinks canonicalized), so a symlink into a gitignored directory is
//! judged by its target (GOALS §1e).

use std::path::{Path, PathBuf};

use ignore::Match;
use ignore::gitignore::{Gitignore, GitignoreBuilder};

/// Whether `path` is gitignored under the gitignore stack rooted at its
/// containing repository, honoring nested `.gitignore`s, the global ignore
/// file, `.git/info/exclude`, and ancestor `.gitignore`s up to the worktree
/// root — the same stack [`crate::intel`]'s walk and the `@`-tag popup use
/// (`.hidden(true).git_ignore(true).git_global(true).git_exclude(true)
/// .parents(true)`).
///
/// `path` is canonicalized first so a symlink is judged by its target
/// (GOALS §1e). When the path can't be canonicalized (e.g. it doesn't exist)
/// the lexical path is used. A path with no enclosing git worktree is treated
/// as **not** gitignored (there's no ignore stack to consult).
pub fn is_gitignored(path: &Path) -> bool {
    let resolved = canonicalize_lenient(path);
    let Some(root) = gitignore_root(&resolved) else {
        return false;
    };
    let matcher = build_repo_matcher(&root, &resolved);
    matcher_matches(&matcher, &root, &resolved)
}

fn matcher_matches(matcher: &Gitignore, root: &Path, path: &Path) -> bool {
    if path.strip_prefix(root).is_err() {
        return false;
    }
    matches!(
        matcher.matched_path_or_any_parents(path, path.is_dir()),
        Match::Ignore(_)
    )
}

/// The root the gitignore stack anchors at: the enclosing git worktree root
/// (via `git rev-parse`), else the highest ancestor of `path` that carries a
/// `.git` marker or a `.gitignore` file. Does **not** require a real git repo
/// — like the `ignore`-crate walk's `.require_git(false)`, a directory with a
/// bare `.gitignore` and no `.git` still has its ignore rules honored.
/// `None` when no ancestor carries either marker (no ignore stack to consult).
fn gitignore_root(path: &Path) -> Option<PathBuf> {
    if let Some(root) = crate::git::find_worktree_root(path) {
        return Some(canonicalize_lenient(&root));
    }
    let start = if path.is_dir() { path } else { path.parent()? };
    // Highest ancestor with a `.git` marker (dir or file) wins; failing that,
    // the highest ancestor with a `.gitignore`.
    let mut git_root: Option<PathBuf> = None;
    let mut ignore_root: Option<PathBuf> = None;
    for dir in start.ancestors() {
        if dir.join(".git").exists() {
            git_root = Some(dir.to_path_buf());
        }
        if dir.join(".gitignore").exists() {
            ignore_root = Some(dir.to_path_buf());
        }
    }
    git_root
        .or(ignore_root)
        .map(|root| canonicalize_lenient(&root))
}

/// Whether `path` is permitted for a read: permitted when it is not
/// gitignored, or when it matches `allow` (gitignore-style globs evaluated
/// relative to `project_root`). The single predicate the read gate, the intel
/// walk re-inclusion, and the `@`-tag popup share.
pub fn is_permitted(path: &Path, project_root: &Path, allow: &[String]) -> bool {
    if !is_gitignored(path) {
        return true;
    }
    allowlist_matches(path, project_root, allow)
}

/// Whether `path` matches the allowlist `globs` (gitignore syntax, rooted at
/// `project_root`). A directory glob like `target/` re-permits every path
/// beneath it because [`Gitignore::matched_path_or_any_parents`] walks the
/// path's parents. Used both for the read gate and to re-include a
/// gitignored-but-allowlisted path in the discovery surfaces.
pub fn allowlist_matches(path: &Path, project_root: &Path, globs: &[String]) -> bool {
    let root = canonicalize_lenient(project_root);
    let matcher = build_allowlist_matcher(&root, globs);
    if matcher.is_empty() {
        return false;
    }
    let resolved = canonicalize_lenient(path);
    // The allowlist globs are written as *ignore* patterns; a path the
    // allowlist "ignores" is the one we re-permit.
    matcher_matches(&matcher, &root, &resolved)
}

/// Build a [`Gitignore`] matcher from the allowlist `globs`, rooted at
/// `project_root` so a relative glob (e.g. `target/`) anchors there. Invalid
/// globs are skipped (defensive: a hand-edited config never crashes the gate).
pub fn build_allowlist_matcher(project_root: &Path, globs: &[String]) -> Gitignore {
    let mut builder = GitignoreBuilder::new(project_root);
    for glob in globs {
        let glob = glob.trim();
        if glob.is_empty() {
            continue;
        }
        // `add_line(None, …)` adds one gitignore-syntax pattern; an invalid
        // pattern is skipped rather than aborting the whole matcher.
        let _ = builder.add_line(None, glob);
    }
    builder.build().unwrap_or_else(|_| Gitignore::empty())
}

/// Build the repository's gitignore matcher for a single `target`: every
/// `.gitignore` from the worktree `root` down to the target's directory
/// (so nested + ancestor `.gitignore`s are honored), `.git/info/exclude`, and
/// the user's global ignore file. All patterns anchor at `root`, matching the
/// `ignore`-walk flags used elsewhere (`git_ignore`, `git_global`,
/// `git_exclude`, `parents`).
fn build_repo_matcher(root: &Path, target: &Path) -> Gitignore {
    let mut builder = GitignoreBuilder::new(root);
    // The user's global ignore file (`core.excludesfile`), least specific.
    if let Some(global) = global_ignore_path() {
        let _ = builder.add(global);
    }
    // `.git/info/exclude` (per-repo, not committed).
    let _ = builder.add(root.join(".git/info/exclude"));
    // Every `.gitignore` from the worktree root down to the target's
    // directory, root-first so a deeper file's negation wins.
    for dir in ancestor_dirs_root_first(root, target) {
        let _ = builder.add(dir.join(".gitignore"));
    }
    builder.build().unwrap_or_else(|_| Gitignore::empty())
}

/// The directories from `root` (inclusive) down to `target`'s containing
/// directory (inclusive), root-first. When `target` lies outside `root` the
/// list is just `[root]`.
fn ancestor_dirs_root_first(root: &Path, target: &Path) -> Vec<PathBuf> {
    let start = if target.is_dir() {
        target
    } else {
        target.parent().unwrap_or(target)
    };
    let Ok(rel) = start.strip_prefix(root) else {
        return vec![root.to_path_buf()];
    };
    let mut out = vec![root.to_path_buf()];
    let mut acc = root.to_path_buf();
    for comp in rel.components() {
        acc = acc.join(comp.as_os_str());
        out.push(acc.clone());
    }
    out
}

/// The user's global gitignore file path (`core.excludesfile`), if one is
/// configured and exists. `Gitignore::global()` resolves it internally but
/// doesn't expose the path, so we re-derive it for [`build_repo_matcher`].
fn global_ignore_path() -> Option<PathBuf> {
    // git config core.excludesfile, else $XDG_CONFIG_HOME/git/ignore, else
    // ~/.config/git/ignore — the same precedence git itself uses.
    if let Ok(out) = std::process::Command::new("git")
        .args(["config", "--get", "core.excludesfile"])
        .output()
        && out.status.success()
    {
        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !p.is_empty() {
            let expanded = expand_tilde(&p);
            if expanded.exists() {
                return Some(expanded);
            }
        }
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))?;
    let candidate = base.join("git/ignore");
    candidate.exists().then_some(candidate)
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(p)
}

/// Canonicalize `path`, falling back to the lexical path when it can't be
/// resolved (a not-yet-existing or unreadable path). Symlink resolution is the
/// point: the gate judges a symlink by its target (GOALS §1e).
fn canonicalize_lenient(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repo with a `.gitignore` ignoring `target/` and `.env`: those paths
    /// report gitignored, a tracked source file does not.
    #[test]
    fn detects_gitignored_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // Make it a git worktree so `find_worktree_root` resolves here.
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".gitignore"), "target/\n.env\n").unwrap();
        std::fs::create_dir_all(root.join("target/debug")).unwrap();
        std::fs::write(root.join("target/debug/app"), "bin").unwrap();
        std::fs::write(root.join(".env"), "SECRET=x").unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();

        assert!(is_gitignored(&root.join("target/debug/app")));
        assert!(is_gitignored(&root.join(".env")));
        assert!(!is_gitignored(&root.join("src/main.rs")));
    }

    /// `is_permitted`: a gitignored path is denied unless an allowlist glob
    /// re-permits it; a non-gitignored path is always permitted.

    #[test]
    fn allowlist_outside_root_is_not_matched() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let path = outside.join("target").join("debug.log");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "log").unwrap();

        assert!(!allowlist_matches(&path, &root, &["target/".to_string()]));
    }

    #[test]
    fn allowlist_repermits_gitignored_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".gitignore"), "target/\n.env\n").unwrap();
        std::fs::create_dir_all(root.join("target/debug")).unwrap();
        std::fs::write(root.join("target/debug/app"), "bin").unwrap();
        std::fs::write(root.join(".env"), "SECRET=x").unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();

        let allow = vec!["target/".to_string()];
        // `target/` re-permits everything under target/.
        assert!(is_permitted(&root.join("target/debug/app"), root, &allow));
        // `.env` is still gitignored and not allowlisted → not permitted.
        assert!(!is_permitted(&root.join(".env"), root, &allow));
        // A tracked file is always permitted regardless of the allowlist.
        assert!(is_permitted(&root.join("src/main.rs"), root, &[]));
    }

    /// An empty allowlist matches nothing (it never spuriously permits).
    #[test]
    fn empty_allowlist_matches_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert!(!allowlist_matches(&root.join("anything"), root, &[]));
        assert!(!allowlist_matches(
            &root.join("anything"),
            root,
            &[String::new(), "   ".to_string()]
        ));
    }

    /// A file glob (no trailing slash) re-permits exactly that file.
    #[test]
    fn file_glob_permits_single_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".gitignore"), "*.lock\n").unwrap();
        std::fs::write(root.join("Cargo.lock"), "x").unwrap();
        std::fs::write(root.join("other.lock"), "y").unwrap();

        let allow = vec!["Cargo.lock".to_string()];
        assert!(is_permitted(&root.join("Cargo.lock"), root, &allow));
        assert!(!is_permitted(&root.join("other.lock"), root, &allow));
    }
}
