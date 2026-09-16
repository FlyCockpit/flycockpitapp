//! A tiny, throttled read of the working directory's git state for the header.
//!
//! `excoc tui` runs in a real directory, so — like the onboarding wizard's live
//! `/models` probe — this reaches for real data: the current branch and whether
//! there are uncommitted changes. It shells out to `git` rather than parsing
//! `.git` by hand, and the caller refreshes it on a slow timer so a normal repo
//! never spawns `git` faster than a person could change it.

use std::process::Command;

/// Snapshot of the working directory's git state.
#[derive(Debug, Clone, Default)]
pub struct GitInfo {
    pub is_repo: bool,
    pub branch: Option<String>,
    /// Number of changed (staged, unstaged, or untracked) entries.
    pub changes: usize,
}

impl GitInfo {
    /// The pre-detection state: not (yet) known to be a repo, shown as nothing.
    pub fn unknown() -> Self {
        Self::default()
    }

    /// Query `git` in the current directory. Any failure (not a repo, no `git`)
    /// yields [`GitInfo::unknown`], which the header renders as absent.
    pub fn detect() -> Self {
        let output = Command::new("git")
            .args(["status", "--porcelain=v1", "--branch"])
            .output();
        match output {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                let (branch, changes) = parse_status_branch(&text);
                Self {
                    is_repo: true,
                    branch,
                    changes,
                }
            }
            _ => Self::unknown(),
        }
    }

    pub fn dirty(&self) -> bool {
        self.changes > 0
    }
}

/// Parse `git status --porcelain=v1 --branch`: the leading `## ` line names the
/// branch; every other non-empty line is one changed path.
pub fn parse_status_branch(text: &str) -> (Option<String>, usize) {
    let mut branch = None;
    let mut changes = 0;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            branch = Some(parse_branch_header(rest));
        } else if !line.trim().is_empty() {
            changes += 1;
        }
    }
    (branch, changes)
}

/// Pull the branch name out of the porcelain `## ` header, which can read
/// `main`, `main...origin/main [ahead 1]`, `HEAD (no branch)`, or
/// `No commits yet on main`.
fn parse_branch_header(rest: &str) -> String {
    if let Some(fresh) = rest.strip_prefix("No commits yet on ") {
        return fresh.trim().to_string();
    }
    let tracking_cut = rest.find("...").unwrap_or(rest.len());
    let head = &rest[..tracking_cut];
    head.split_whitespace()
        .next()
        .unwrap_or(head)
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_branch_and_counts_changes() {
        let text = "## main...origin/main [ahead 1]\n M src/a.rs\n?? new.txt\n";
        let (branch, changes) = parse_status_branch(text);
        assert_eq!(branch.as_deref(), Some("main"));
        assert_eq!(changes, 2);
    }

    #[test]
    fn clean_repo_reports_zero_changes() {
        let (branch, changes) = parse_status_branch("## trunk\n");
        assert_eq!(branch.as_deref(), Some("trunk"));
        assert_eq!(changes, 0);
    }

    #[test]
    fn handles_detached_head_and_fresh_repos() {
        assert_eq!(
            parse_status_branch("## HEAD (no branch)\n").0.as_deref(),
            Some("HEAD")
        );
        assert_eq!(
            parse_status_branch("## No commits yet on main\n")
                .0
                .as_deref(),
            Some("main")
        );
    }
}
