use std::path::{Path, PathBuf};

use anyhow::Result;
use grep_matcher::Matcher;
use grep_regex::RegexMatcher;
use grep_searcher::{BinaryDetection, Searcher, SearcherBuilder, Sink, SinkContext, SinkMatch};
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;

use crate::engine::tool::invalid_input;

#[derive(Debug, Clone)]
pub struct SearchRecord {
    pub path: String,
    pub line_number: u64,
    pub column: Option<usize>,
    pub text: String,
    pub is_context: bool,
}

/// Options for the shared text-search walker.
///
/// The `ignore` crate uses several booleans with "skip" polarity. Keep these
/// comments aligned with `ignore::WalkBuilder` so callers do not accidentally
/// hide files they intend to search.
#[derive(Debug, Clone)]
pub struct SearchOptions {
    /// Regex pattern passed to `grep_regex`.
    pub pattern: String,
    /// When true, search with a case-insensitive regex wrapper.
    pub case_insensitive: bool,
    /// When true, include the first match column in non-context records.
    pub columns: bool,
    /// Number of context lines before and after each match.
    pub context: Option<usize>,
    /// Optional include glob, using `ignore::overrides` syntax.
    pub glob: Option<String>,
    /// Maximum non-context matches before truncating the walk.
    pub max_matches: usize,
    /// Mirrors `ignore::WalkBuilder::hidden`: true means hidden entries are
    /// skipped. Current callers pass false so repo search covers hidden files
    /// that gitignore permits.
    pub hidden: bool,
    /// Mirrors `ignore::WalkBuilder::parents`: true means parent ignore files
    /// are consulted.
    pub parents: bool,
}

#[derive(Debug, Clone)]
pub struct SearchOutcome {
    pub records: Vec<SearchRecord>,
    pub hit_match_cap: bool,
}

pub fn search_records_blocking<F>(
    search_root: &Path,
    display_root: &Path,
    options: &SearchOptions,
    allow_entry: F,
) -> Result<SearchOutcome>
where
    F: Fn(&Path) -> bool,
{
    let effective = if options.case_insensitive {
        format!("(?i){}", options.pattern)
    } else {
        options.pattern.clone()
    };
    let matcher = RegexMatcher::new_line_matcher(&effective).map_err(|e| {
        invalid_input(format!(
            "invalid regex `{}` ({e}); check for unescaped backslashes or unbalanced brackets",
            options.pattern
        ))
    })?;

    let mut walker = WalkBuilder::new(search_root);
    walker
        .hidden(options.hidden)
        .git_ignore(true)
        .git_exclude(true)
        .parents(options.parents)
        .require_git(false)
        .follow_links(false)
        .filter_entry(is_not_dot_git_dir);
    if let Some(glob) = &options.glob {
        let mut overrides = OverrideBuilder::new(search_root);
        overrides.add(glob).map_err(|e| {
            invalid_input(format!(
                "invalid glob `{glob}` ({e}); check the include pattern"
            ))
        })?;
        walker.overrides(overrides.build().map_err(|e| {
            invalid_input(format!(
                "invalid glob `{glob}` ({e}); check the include pattern"
            ))
        })?);
    }

    let mut records = Vec::new();
    let mut match_count = 0usize;
    let mut hit_match_cap = false;

    'walk: for entry in walker.build().flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        if !allow_entry(path) {
            continue;
        }
        let rel = display_path(path, display_root);
        let mut searcher = SearcherBuilder::new()
            .binary_detection(BinaryDetection::quit(0))
            .line_number(true)
            .before_context(options.context.unwrap_or(0))
            .after_context(options.context.unwrap_or(0))
            .build();
        let mut sink = RecordSink {
            rel,
            matcher: &matcher,
            columns: options.columns,
            records: Vec::new(),
            matches: 0,
            max_matches: options.max_matches,
            hit_match_cap: false,
        };
        if searcher.search_path(&matcher, path, &mut sink).is_err() {
            continue;
        }
        match_count += sink.matches;
        hit_match_cap |= sink.hit_match_cap;
        records.extend(sink.records);
        if hit_match_cap || match_count >= options.max_matches {
            hit_match_cap = true;
            break 'walk;
        }
    }

    Ok(SearchOutcome {
        records,
        hit_match_cap,
    })
}

fn display_path(path: &Path, display_root: &Path) -> String {
    path.strip_prefix(display_root)
        .unwrap_or(path)
        .to_string_lossy()
        .trim_start_matches("./")
        .replace('\\', "/")
}

struct RecordSink<'a> {
    rel: String,
    matcher: &'a RegexMatcher,
    columns: bool,
    records: Vec<SearchRecord>,
    matches: usize,
    max_matches: usize,
    hit_match_cap: bool,
}

impl RecordSink<'_> {
    fn push_match(&mut self, mat: &SinkMatch<'_>) -> bool {
        let line_number = mat.line_number().unwrap_or(0);
        let text = trim_line(mat.bytes());
        let column = self
            .columns
            .then(|| first_match_column(self.matcher, text.as_bytes()))
            .flatten();
        self.records.push(SearchRecord {
            path: self.rel.clone(),
            line_number,
            column,
            text,
            is_context: false,
        });
        self.matches += 1;
        if self.matches >= self.max_matches {
            self.hit_match_cap = true;
            return false;
        }
        true
    }

    fn push_context(&mut self, context: &SinkContext<'_>) -> bool {
        self.records.push(SearchRecord {
            path: self.rel.clone(),
            line_number: context.line_number().unwrap_or(0),
            column: None,
            text: trim_line(context.bytes()),
            is_context: true,
        });
        true
    }
}

impl Sink for RecordSink<'_> {
    type Error = std::io::Error;

    fn matched(
        &mut self,
        _searcher: &Searcher,
        mat: &SinkMatch<'_>,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(self.push_match(mat))
    }

    fn context(
        &mut self,
        _searcher: &Searcher,
        context: &SinkContext<'_>,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(self.push_context(context))
    }
}

fn trim_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches(['\r', '\n'])
        .to_string()
}

fn first_match_column(matcher: &RegexMatcher, line: &[u8]) -> Option<usize> {
    matcher.find(line).ok().flatten().map(|mat| mat.start() + 1)
}

pub(crate) fn is_not_dot_git_dir(entry: &ignore::DirEntry) -> bool {
    !(entry.file_type().is_some_and(|t| t.is_dir()) && entry.file_name() == ".git")
}

pub fn normalize_display_root(target: &Path) -> (PathBuf, PathBuf) {
    if target.is_file() {
        let parent = target.parent().unwrap_or(Path::new(".")).to_path_buf();
        (target.to_path_buf(), parent)
    } else {
        (target.to_path_buf(), target.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEEDLE: &str = "hidden_search_unique_needle";

    fn write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    fn options(pattern: &str) -> SearchOptions {
        SearchOptions {
            pattern: pattern.to_string(),
            case_insensitive: false,
            columns: true,
            context: None,
            glob: None,
            max_matches: 100,
            hidden: false,
            parents: true,
        }
    }

    fn search(root: &Path, options: &SearchOptions) -> SearchOutcome {
        search_records_blocking(root, root, options, |_| true).unwrap()
    }

    fn paths(outcome: &SearchOutcome) -> Vec<&str> {
        outcome
            .records
            .iter()
            .filter(|record| !record.is_context)
            .map(|record| record.path.as_str())
            .collect()
    }

    #[test]
    fn search_records_never_descend_into_dot_git() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), ".git/COMMIT_EDITMSG", NEEDLE);
        write(tmp.path(), "nested/.git/HEAD", NEEDLE);
        write(tmp.path(), ".github/workflows/ci.yml", NEEDLE);
        write(tmp.path(), ".gitignore", NEEDLE);

        for hidden in [true, false] {
            let mut opts = options(NEEDLE);
            opts.hidden = hidden;
            let outcome = search(tmp.path(), &opts);
            let found = paths(&outcome);

            assert!(!found.contains(&".git/COMMIT_EDITMSG"), "{found:?}");
            assert!(!found.contains(&"nested/.git/HEAD"), "{found:?}");
        }
    }

    #[test]
    fn search_records_match_dot_github_and_dotfiles() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), ".git/COMMIT_EDITMSG", NEEDLE);
        write(tmp.path(), "nested/.git/HEAD", NEEDLE);
        write(tmp.path(), ".github/workflows/ci.yml", NEEDLE);
        write(tmp.path(), ".gitignore", NEEDLE);
        write(tmp.path(), ".gitattributes", NEEDLE);

        let mut opts = options(NEEDLE);
        opts.hidden = false;
        let outcome = search(tmp.path(), &opts);
        let found = paths(&outcome);

        assert!(found.contains(&".github/workflows/ci.yml"), "{found:?}");
        assert!(found.contains(&".gitignore"), "{found:?}");
        assert!(found.contains(&".gitattributes"), "{found:?}");
        assert!(!found.contains(&".git/COMMIT_EDITMSG"), "{found:?}");
        assert!(!found.contains(&"nested/.git/HEAD"), "{found:?}");
    }

    #[test]
    fn search_records_respect_gitignore() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), ".gitignore", "ignored.txt\n");
        write(tmp.path(), "ignored.txt", NEEDLE);
        write(tmp.path(), "visible.txt", NEEDLE);

        let outcome = search(tmp.path(), &options(NEEDLE));
        let found = paths(&outcome);

        assert!(found.contains(&"visible.txt"), "{found:?}");
        assert!(!found.contains(&"ignored.txt"), "{found:?}");
    }

    #[test]
    fn search_records_honor_allow_entry_guard() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "allowed.txt", NEEDLE);
        write(tmp.path(), "blocked.txt", NEEDLE);
        let blocked = tmp.path().join("blocked.txt");

        let outcome = search_records_blocking(tmp.path(), tmp.path(), &options(NEEDLE), |path| {
            path != blocked
        })
        .unwrap();
        let found = paths(&outcome);

        assert!(found.contains(&"allowed.txt"), "{found:?}");
        assert!(!found.contains(&"blocked.txt"), "{found:?}");
    }

    #[test]
    fn search_records_case_insensitive_and_context_and_glob() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "src/a.rs", "before\nAlpha target\nafter\n");
        write(
            tmp.path(),
            "src/b.txt",
            "Alpha should be excluded by glob\n",
        );

        let mut opts = options("alpha");
        assert!(search(tmp.path(), &opts).records.is_empty());

        opts.case_insensitive = true;
        opts.context = Some(1);
        opts.glob = Some("*.rs".to_string());
        let outcome = search(tmp.path(), &opts);

        assert!(paths(&outcome).contains(&"src/a.rs"), "{outcome:?}");
        assert!(!paths(&outcome).contains(&"src/b.txt"), "{outcome:?}");
        assert!(
            outcome.records.iter().any(|record| record.is_context
                && record.path == "src/a.rs"
                && record.text == "before"),
            "{outcome:?}"
        );
        assert!(
            outcome.records.iter().any(|record| !record.is_context
                && record.path == "src/a.rs"
                && record.column == Some(1)),
            "{outcome:?}"
        );
    }

    #[test]
    fn search_records_report_hit_match_cap() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "a.txt", &format!("{NEEDLE}\n{NEEDLE}\n"));

        let mut opts = options(NEEDLE);
        opts.max_matches = 1;
        let outcome = search(tmp.path(), &opts);

        assert!(outcome.hit_match_cap, "{outcome:?}");
        assert_eq!(
            outcome
                .records
                .iter()
                .filter(|record| !record.is_context)
                .count(),
            1
        );
    }

    #[test]
    fn search_records_invalid_regex_is_invalid_input() {
        let tmp = tempfile::tempdir().unwrap();

        let err = search_records_blocking(tmp.path(), tmp.path(), &options("["), |_| true)
            .unwrap_err()
            .to_string();

        assert!(err.contains("invalid regex `[`"), "{err}");
        assert!(err.contains("unbalanced brackets"), "{err}");
    }
}
