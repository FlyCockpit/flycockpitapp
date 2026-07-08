//! Directory autosuggest for the `/settings` packages-directory field.
//!
//! Given the partial path the user has typed, lists existing **directories**
//! on disk that match, ranked for a dropdown + an inline ghost completion
//! (see implementation note). This is a directory
//! *selector*, so:
//!
//! - Only directories are returned — never files.
//! - Hidden (dotfile) directories are included (`~/.config` is reachable).
//! - No gitignore filtering: a system path is routinely outside any git
//!   repo, so this uses a plain [`std::fs::read_dir`], **not** the
//!   gitignore-aware `ignore` walker that `file_tag.rs` uses. The
//!   ranking/formatting shape is borrowed from `file_tag.rs`; the walk is
//!   not.
//!
//! Autosuggest is purely additive: a non-existent / unreadable parent
//! yields no suggestions, and the field still saves whatever free text the
//! user typed.

use std::path::{Path, PathBuf};

/// Visible rows in the dropdown window. Matches the utility-model picker's
/// scroll-window feel (`UTILITY_MODEL_WINDOW`)/the `@`-popup
/// (`MAX_SUGGESTIONS`) so the popup behaves identically.
pub const DIR_SUGGEST_WINDOW: usize = 8;

/// Hard ceiling on suggestions returned. The user can arrow through the
/// whole (windowed) list; this bounds work + memory on a huge directory.
const MAX_RESULTS: usize = 200;

/// Hard ceiling on directory entries *scanned* per call, so a pathological
/// directory with hundreds of thousands of children can't stall the UI.
const MAX_SCAN_ENTRIES: usize = 10_000;

/// One directory suggestion for the dropdown + ghost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirSuggestion {
    /// The directory's own name (no path), e.g. `src` or `.config`. Shown
    /// in the dropdown row.
    pub name: String,
    /// The full value to drop into the field when this entry is accepted:
    /// the typed parent literal (as the user wrote it, including any
    /// leading `~` and the trailing separator) + this dir's name + a
    /// trailing `/` so the user can keep drilling deeper.
    pub replacement: String,
}

/// Split the typed value into the parent literal (everything up to and
/// including the last path separator) and the trailing prefix to match
/// directory names against. A value with no separator has an empty parent
/// literal and is matched entirely as the prefix; a value ending in a
/// separator has an empty prefix (list all children).
///
/// Both `/` and the platform separator are treated as separators so the
/// field accepts forward slashes everywhere (matching how paths are typed
/// in this TUI), and `\` on Windows.
pub fn split_value(value: &str) -> (&str, &str) {
    match last_separator(value) {
        Some(idx) => {
            // Parent literal keeps the separator; prefix is what follows.
            let sep_len = value[idx..].chars().next().map(char::len_utf8).unwrap_or(1);
            (&value[..idx + sep_len], &value[idx + sep_len..])
        }
        None => ("", value),
    }
}

/// Byte index of the last path separator (`/`, or `\` on Windows) in `s`.
fn last_separator(s: &str) -> Option<usize> {
    s.char_indices()
        .rfind(|(_, c)| is_separator(*c))
        .map(|(i, _)| i)
}

fn is_separator(c: char) -> bool {
    c == '/' || (cfg!(windows) && c == '\\')
}

/// Resolve the parent literal into an absolute filesystem directory to
/// list. A leading `~` expands to home (via `shellexpand`, the same dep
/// `src/packages/mod.rs` uses); an absolute path resolves from root; a
/// bare/relative path resolves against `cwd`. An empty parent literal
/// resolves to `cwd` itself.
pub fn resolve_parent(cwd: &Path, parent_literal: &str) -> PathBuf {
    if parent_literal.is_empty() {
        return cwd.to_path_buf();
    }
    let expanded = shellexpand::tilde(parent_literal).into_owned();
    let p = Path::new(&expanded);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

/// Rank key for a candidate name against the lowercased prefix: directories
/// whose name starts with the prefix sort before substring-only matches,
/// then alphabetical (case-insensitive). Returns `None` when the name
/// doesn't match the prefix at all (and so isn't a candidate).
fn match_rank(name: &str, prefix_lower: &str) -> Option<u8> {
    if prefix_lower.is_empty() {
        return Some(0);
    }
    let name_lower = name.to_ascii_lowercase();
    if name_lower.starts_with(prefix_lower) {
        Some(0)
    } else if name_lower.contains(prefix_lower) {
        Some(1)
    } else {
        None
    }
}

/// Suggest existing directories matching the typed `value`, resolved
/// against `cwd`. Returns ranked [`DirSuggestion`]s (prefix matches before
/// substring matches, then alphabetical), capped at [`MAX_RESULTS`].
///
/// A non-existent or unreadable parent, or a directory with no matching
/// children, yields an empty vec — never an error or panic. A single
/// candidate whose name equals the typed prefix exactly is suppressed (it
/// would be a redundant suggestion identical to the current input).
pub fn suggest_dirs(cwd: &Path, value: &str) -> Vec<DirSuggestion> {
    let (parent_literal, prefix) = split_value(value);
    let dir = resolve_parent(cwd, parent_literal);
    let prefix_lower = prefix.to_ascii_lowercase();

    let read = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        // Non-existent / unreadable (permission denied) → no suggestions.
        Err(_) => return Vec::new(),
    };

    // (rank, lowercased name for ordering, original name).
    let mut scored: Vec<(u8, String, String)> = Vec::new();
    let mut scanned = 0usize;
    for ent in read.flatten() {
        scanned += 1;
        if scanned > MAX_SCAN_ENTRIES {
            break;
        }
        // Directories only — resolve type without following symlinks to a
        // file (a symlink to a dir is still navigable). `file_type` avoids
        // a stat per entry where the OS already knows; fall back to a stat
        // for filesystems that report Unknown.
        let is_dir = match ent.file_type() {
            Ok(ft) if ft.is_dir() => true,
            Ok(ft) if ft.is_symlink() => ent.path().is_dir(),
            Ok(_) => false,
            Err(_) => ent.path().is_dir(),
        };
        if !is_dir {
            continue;
        }
        let name = ent.file_name().to_string_lossy().into_owned();
        let Some(rank) = match_rank(&name, &prefix_lower) else {
            continue;
        };
        scored.push((rank, name.to_ascii_lowercase(), name));
        if scored.len() >= MAX_RESULTS {
            // Stop accumulating, but keep scanning is pointless — bail.
            break;
        }
    }

    // Suppress a lone exact-name match equal to the typed prefix: there's
    // nothing to complete and the dropdown row would just echo the input.
    if scored.len() == 1 && !prefix.is_empty() && scored[0].2 == prefix {
        return Vec::new();
    }

    // Prefix-before-substring (rank asc), then alphabetical
    // (case-insensitive, ties broken by the original name for stability).
    scored.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
    });

    scored
        .into_iter()
        .map(|(_, _, name)| {
            let replacement = format!("{parent_literal}{name}/");
            DirSuggestion { name, replacement }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn split_value_no_separator_is_all_prefix() {
        assert_eq!(split_value("foo"), ("", "foo"));
        assert_eq!(split_value(""), ("", ""));
    }

    #[test]
    fn split_value_separates_parent_and_prefix() {
        assert_eq!(split_value("~/sr"), ("~/", "sr"));
        assert_eq!(split_value("/usr/lo"), ("/usr/", "lo"));
        assert_eq!(split_value("a/b/c"), ("a/b/", "c"));
    }

    #[test]
    fn split_value_trailing_separator_empties_prefix() {
        assert_eq!(split_value("~/src/"), ("~/src/", ""));
        assert_eq!(split_value("/"), ("/", ""));
    }

    #[test]
    fn resolve_parent_tilde_expands_home() {
        let cwd = Path::new("/some/cwd");
        let home = dirs::home_dir().expect("home");
        assert_eq!(resolve_parent(cwd, "~/"), home.join(""));
        // `~` alone (no separator can't reach here via split, but the
        // resolver must still expand it) expands to home itself.
        assert_eq!(resolve_parent(cwd, "~"), home);
    }

    #[test]
    fn resolve_parent_absolute_ignores_cwd() {
        let cwd = Path::new("/some/cwd");
        assert_eq!(resolve_parent(cwd, "/usr/"), PathBuf::from("/usr/"));
    }

    #[test]
    fn resolve_parent_relative_joins_cwd() {
        let cwd = Path::new("/some/cwd");
        assert_eq!(resolve_parent(cwd, "sub/"), PathBuf::from("/some/cwd/sub/"));
        // Empty parent literal resolves to cwd itself.
        assert_eq!(resolve_parent(cwd, ""), PathBuf::from("/some/cwd"));
    }

    #[test]
    fn lists_directories_only_not_files() {
        let root = tmp();
        fs::create_dir(root.path().join("alpha")).unwrap();
        fs::write(root.path().join("beta.txt"), "x").unwrap();
        let s = suggest_dirs(root.path(), "");
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["alpha"]);
    }

    #[test]
    fn includes_hidden_directories() {
        let root = tmp();
        fs::create_dir(root.path().join(".config")).unwrap();
        fs::create_dir(root.path().join("visible")).unwrap();
        let s = suggest_dirs(root.path(), "");
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert!(names.contains(&".config"), "hidden dir missing: {names:?}");
        assert!(names.contains(&"visible"));
    }

    #[test]
    fn prefix_filters_and_matches_hidden() {
        let root = tmp();
        fs::create_dir(root.path().join(".config")).unwrap();
        fs::create_dir(root.path().join(".cache")).unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        let s = suggest_dirs(root.path(), ".con");
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec![".config"]);
    }

    #[test]
    fn ranks_prefix_before_substring_then_alpha() {
        let root = tmp();
        // Prefix matches: "apple", "applied". Substring-only: "wrapper"
        // (contains "app" but doesn't start with it). "zzz" doesn't match.
        for d in ["wrapper", "apple", "applied", "zzz"] {
            fs::create_dir(root.path().join(d)).unwrap();
        }
        let s = suggest_dirs(root.path(), "app");
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        // Prefix matches first (alpha: apple, applied), then substring.
        assert_eq!(names, vec!["apple", "applied", "wrapper"]);
    }

    #[test]
    fn alphabetical_within_rank_case_insensitive() {
        let root = tmp();
        for d in ["Bravo", "alpha", "Charlie"] {
            fs::create_dir(root.path().join(d)).unwrap();
        }
        let s = suggest_dirs(root.path(), "");
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "Bravo", "Charlie"]);
    }

    #[test]
    fn replacement_appends_trailing_separator_and_keeps_parent() {
        let root = tmp();
        fs::create_dir(root.path().join("src")).unwrap();
        // Relative prefix, no parent literal.
        let s = suggest_dirs(root.path(), "sr");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "src");
        assert_eq!(s[0].replacement, "src/");

        // Nested parent literal is preserved verbatim in the replacement.
        fs::create_dir(root.path().join("src").join("inner")).unwrap();
        let s = suggest_dirs(root.path(), "src/in");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].replacement, "src/inner/");
    }

    #[test]
    fn trailing_separator_lists_all_children() {
        let root = tmp();
        let parent = root.path().join("parent");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(parent.join("a")).unwrap();
        fs::create_dir(parent.join("b")).unwrap();
        fs::write(parent.join("f.txt"), "x").unwrap();
        let s = suggest_dirs(root.path(), "parent/");
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
        assert_eq!(s[0].replacement, "parent/a/");
    }

    #[test]
    fn nonexistent_parent_yields_empty_no_panic() {
        let root = tmp();
        let s = suggest_dirs(root.path(), "does/not/exist/x");
        assert!(s.is_empty());
    }

    #[test]
    fn no_matches_yields_empty() {
        let root = tmp();
        fs::create_dir(root.path().join("alpha")).unwrap();
        let s = suggest_dirs(root.path(), "zzz");
        assert!(s.is_empty());
    }

    #[test]
    fn exact_single_match_yields_no_suggestion() {
        let root = tmp();
        fs::create_dir(root.path().join("src")).unwrap();
        // Typed value already equals the only match → nothing to complete.
        let s = suggest_dirs(root.path(), "src");
        assert!(s.is_empty(), "redundant exact suggestion: {s:?}");
    }

    #[test]
    fn exact_match_still_shows_when_other_candidates_exist() {
        let root = tmp();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::create_dir(root.path().join("src-extra")).unwrap();
        // "src" is exact but "src-extra" also matches → keep both so the
        // user can pick the longer sibling.
        let s = suggest_dirs(root.path(), "src");
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["src", "src-extra"]);
    }

    #[test]
    fn result_count_is_capped() {
        let root = tmp();
        for n in 0..(MAX_RESULTS + 50) {
            fs::create_dir(root.path().join(format!("dir{n:04}"))).unwrap();
        }
        let s = suggest_dirs(root.path(), "dir");
        assert!(s.len() <= MAX_RESULTS, "got {}", s.len());
    }

    #[test]
    fn unreadable_dir_yields_empty_no_panic() {
        // Point at a path that exists as a *file*, not a directory:
        // `read_dir` errors, and we must treat it as no matches.
        let root = tmp();
        let file = root.path().join("not-a-dir");
        fs::write(&file, "x").unwrap();
        let s = suggest_dirs(&file, "");
        assert!(s.is_empty());
    }
}
