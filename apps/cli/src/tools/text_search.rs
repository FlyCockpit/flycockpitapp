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

#[derive(Debug, Clone)]
pub struct SearchOptions {
    pub pattern: String,
    pub case_insensitive: bool,
    pub columns: bool,
    pub context: Option<usize>,
    pub glob: Option<String>,
    pub max_matches: usize,
    pub hidden: bool,
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
        .follow_links(false);
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

pub fn normalize_display_root(target: &Path) -> (PathBuf, PathBuf) {
    if target.is_file() {
        let parent = target.parent().unwrap_or(Path::new(".")).to_path_buf();
        (target.to_path_buf(), parent)
    } else {
        (target.to_path_buf(), target.to_path_buf())
    }
}
