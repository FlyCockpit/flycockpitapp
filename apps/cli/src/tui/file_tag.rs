//! Composer `@`-tagging: file/directory suggestions + inline expansion.
//!
//! See `the design notes` §1e for the spec. The composer collects `@partial`
//! tokens; this module walks the cwd (gitignore-aware via the `ignore`
//! crate), ranks candidates, and on submit rewrites every `@path[:range]`
//! into a fenced `<file …>` / `<dir …>` block. File blocks use the same
//! line-numbered format as the read tool, with mode-tiered tag caps.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use ignore::WalkBuilder;

use crate::config::extended::LlmMode;
use crate::tools::common::{
    OUTPUT_BYTE_CAP, READ_LINE_CAP, looks_binary, read_slice_with_byte_cap, truncation_marker,
};

/// Maximum number of file suggestions returned to the TUI. The renderer
/// shows a six-row window and scrolls within this bounded candidate list.
pub const MAX_SUGGESTIONS: usize = 100;

/// Target number of rows to fill before the deepening walk stops. This
/// matches the visible suggestion window in the app.
const VISIBLE_SUGGESTION_ROWS: usize = 6;

/// Once a query yields fewer than this many matches at the current
/// depth, [`suggestions`] widens one directory deeper at a time until it
/// reaches this many (or exhausts the subtree). Equal to the visible
/// window so the box is full whenever the tree can fill it.
const DEEPEN_TARGET: usize = VISIBLE_SUGGESTION_ROWS;

/// Hard ceiling on suggestions returned. The user can arrow through the
/// whole list; this just bounds memory/scan work in pathological trees.
const MAX_RESULTS: usize = MAX_SUGGESTIONS;

/// Hard ceiling on filesystem entries scanned per `suggestions` call,
/// so a deepening walk in a huge repo can't stall the UI.
const MAX_WALK_ENTRIES: usize = 10_000;

/// Safety bound on deepening depth (symlinks are not followed, so loops
/// aren't possible; this guards against absurdly deep trees).
const MAX_DEEPEN_DEPTH: usize = 32;

/// Normal-mode max directory entries shown for an `@dir/` inline expansion.
/// Mode-specific caps live in [`TagInlineCaps`].
const DIR_ENTRY_CAP: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagInlineCaps {
    pub max_bytes: usize,
    pub max_lines: usize,
    pub max_dir_entries: usize,
}

impl TagInlineCaps {
    pub fn for_mode(mode: LlmMode) -> Self {
        match mode {
            LlmMode::Defensive => Self {
                max_bytes: OUTPUT_BYTE_CAP,
                max_lines: 500,
                max_dir_entries: 30,
            },
            LlmMode::Normal => Self {
                max_bytes: 48 * 1024,
                max_lines: READ_LINE_CAP,
                max_dir_entries: DIR_ENTRY_CAP,
            },
            LlmMode::Frontier => Self {
                max_bytes: 256 * 1024,
                max_lines: 10_000,
                max_dir_entries: 500,
            },
        }
    }
}

/// One file/directory suggestion the popup renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    /// Display path relative to `cwd` (forward slashes; trailing `/` for
    /// directories).
    pub display: String,
    /// Replacement text inserted on accept (without the leading `@`).
    pub replacement: String,
    /// True if this entry is a directory.
    pub is_dir: bool,
    /// True when this entry is normally gitignored but surfaced because it
    /// matches the read-allowlist (implementation note).
    /// The renderer shows it in a subdued color to mark it as allowed-but-
    /// gitignored.
    pub gitignored: bool,
}

/// Return up to `MAX_SUGGESTIONS` candidates matching `query`, walked
/// from `cwd`. Outside a git repo `ignore` falls back to walking
/// everything readable; inside, gitignored + hidden entries are filtered,
/// except those re-included by the read-allowlist `allow` (gitignore-style
/// globs anchored at the enclosing worktree root), which surface flagged
/// `gitignored = true` so the renderer dims them
/// (implementation note).
pub fn suggestions(
    cwd: &Path,
    query: &str,
    counts: &HashMap<String, u64>,
    allow: &[String],
) -> Vec<Suggestion> {
    // The allowlist anchors at the enclosing worktree root, identical to the
    // read gate's matching root.
    let allow_root = crate::git::find_worktree_root(cwd).unwrap_or_else(|| cwd.to_path_buf());
    let query = query.trim_start_matches('@');
    let (dir_part, name_part) = split_query(query);
    let search_root = if dir_part.is_empty() {
        cwd.to_path_buf()
    } else {
        let resolved = resolve_query_dir(cwd, dir_part);
        // If the query references a missing subdir, fall back to cwd so
        // the popup still shows something (helps catch typos earlier).
        if resolved.is_dir() {
            resolved
        } else {
            cwd.to_path_buf()
        }
    };

    let name_lower = name_part.to_ascii_lowercase();
    let mut out: Vec<Suggestion> = Vec::new();
    // Breadth-first deepening: matches at the current depth come first;
    // if the level doesn't fill the window we descend one level at a
    // time (into *all* subdirs, since a match can live under a
    // non-matching dir name) until we hit `DEEPEN_TARGET` or run out.
    let mut frontier: Vec<PathBuf> = vec![search_root];
    let mut walked = 0usize;
    let mut depth = 0usize;

    while !frontier.is_empty() && depth < MAX_DEEPEN_DEPTH {
        depth += 1;
        let mut level: Vec<Suggestion> = Vec::new();
        let mut next: Vec<PathBuf> = Vec::new();
        let mut bailed = false;
        for dir in &frontier {
            for (path, is_dir, gitignored) in level_entries(dir, &allow_root, allow) {
                walked += 1;
                if walked > MAX_WALK_ENTRIES {
                    bailed = true;
                    break;
                }
                // Descend into every subdir regardless of name match.
                if is_dir {
                    next.push(path.clone());
                }
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if !name_lower.is_empty() && !name.to_ascii_lowercase().starts_with(&name_lower) {
                    continue;
                }
                let rel = match path.strip_prefix(cwd) {
                    Ok(p) => p.to_string_lossy().replace('\\', "/"),
                    Err(_) => path.to_string_lossy().to_string(),
                };
                let display = if is_dir { format!("{rel}/") } else { rel };
                level.push(Suggestion {
                    replacement: display.clone(),
                    display,
                    is_dir,
                    gitignored,
                });
            }
            if bailed {
                break;
            }
        }
        // Directories first, then 30-day usage count desc (keyed on the
        // replacement path), then alphabetical — applied within this
        // depth level so shallower matches stay on top and the deepening
        // fill sits below them. Dirs stay pinned above a more-frequent
        // file.
        level.sort_by(|a, b| match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                let ca = counts.get(&a.replacement).copied().unwrap_or(0);
                let cb = counts.get(&b.replacement).copied().unwrap_or(0);
                cb.cmp(&ca).then_with(|| a.display.cmp(&b.display))
            }
        });
        out.extend(level);
        if out.len() >= MAX_RESULTS {
            out.truncate(MAX_RESULTS);
            break;
        }
        if bailed || out.len() >= DEEPEN_TARGET {
            break;
        }
        frontier = next;
    }

    out.truncate(MAX_RESULTS);
    out
}

/// List the immediate children of `dir`, gitignore-aware (hidden +
/// gitignored entries filtered), returning `(path, is_dir, gitignored)`. A
/// depth-1 `ignore` walk so the full gitignore stack — including ancestor
/// `.gitignore`s — is honored exactly as the crate intends. Gitignored
/// entries matching the read-allowlist `allow` (anchored at `allow_root`) are
/// re-included via a supplementary gitignore-off pass and flagged
/// `gitignored = true` (implementation note).
fn level_entries(dir: &Path, allow_root: &Path, allow: &[String]) -> Vec<(PathBuf, bool, bool)> {
    let mut out: Vec<(PathBuf, bool, bool)> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    let mut walker = WalkBuilder::new(dir);
    walker
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .parents(true)
        .require_git(false)
        .max_depth(Some(1))
        .follow_links(false);
    for dent in walker.build().flatten() {
        if dent.depth() == 0 {
            continue;
        }
        let is_dir = dent.file_type().is_some_and(|t| t.is_dir());
        let path = dent.path().to_path_buf();
        seen.insert(path.clone());
        out.push((path, is_dir, false));
    }

    // Re-include allowlisted-but-gitignored immediate children: a depth-1
    // gitignore-off walk, keeping only entries the allowlist re-permits.
    if !allow.is_empty() {
        let matcher = crate::gitignore::build_allowlist_matcher(allow_root, allow);
        if !matcher.is_empty() {
            let mut wide = WalkBuilder::new(dir);
            wide.hidden(false)
                .git_ignore(false)
                .git_global(false)
                .git_exclude(false)
                .parents(false)
                .require_git(false)
                .max_depth(Some(1))
                .follow_links(false);
            wide.filter_entry(|dent| dent.file_name() != ".git");
            for dent in wide.build().flatten() {
                if dent.depth() == 0 {
                    continue;
                }
                let path = dent.path().to_path_buf();
                if seen.contains(&path) {
                    continue;
                }
                if !crate::gitignore::allowlist_matches(&path, allow_root, allow) {
                    continue;
                }
                let is_dir = dent.file_type().is_some_and(|t| t.is_dir());
                seen.insert(path.clone());
                out.push((path, is_dir, true));
            }
        }
    }
    out
}

/// Split `"src/foo"` into (`"src"`, `"foo"`). A trailing slash means the
/// whole query is the dir part with an empty name filter.
fn split_query(q: &str) -> (&str, &str) {
    if let Some(idx) = q.rfind('/') {
        (&q[..idx], &q[idx + 1..])
    } else {
        ("", q)
    }
}

fn resolve_query_dir(cwd: &Path, dir_part: &str) -> PathBuf {
    let p = Path::new(dir_part);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

/// Parse a tag body like `path/to/file.rs:10-80` into (path, range).
/// `path` is the raw substring after `@`; `range` is `Some((start,end))`
/// 1-indexed inclusive when a `:` suffix is present.
fn parse_tag_body(body: &str) -> (&str, Option<(usize, usize)>) {
    if let Some(colon) = body.rfind(':') {
        let (lhs, rhs) = (&body[..colon], &body[colon + 1..]);
        if let Some(range) = parse_range(rhs) {
            return (lhs, Some(range));
        }
    }
    (body, None)
}

fn parse_range(s: &str) -> Option<(usize, usize)> {
    if let Some((a, b)) = s.split_once('-') {
        let start: usize = a.parse().ok()?;
        let end: usize = b.parse().ok()?;
        if start == 0 || end < start {
            return None;
        }
        Some((start, end))
    } else {
        let n: usize = s.parse().ok()?;
        if n == 0 { None } else { Some((n, n)) }
    }
}

/// One `@`-tag the submit-time pass expanded, surfaced to the chat as a
/// harness-automatic tool-call entry (GOALS §1e; the agent didn't invoke
/// it — the composer did). `ok = false` covers "referenced but not
/// inlined" cases (too large, binary, missing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagExpansion {
    /// `"read"` for files, `"list"` for directories.
    pub tool: &'static str,
    /// The tagged path as the user wrote it (display form).
    pub path: String,
    /// One-line detail for the chat entry, e.g. `142 lines`,
    /// `23 entries`, `9001 lines — referenced, not inlined`.
    pub detail: String,
    /// False when nothing was inlined (renders as a `✗`/skip in chat).
    pub ok: bool,
}

/// Result of [`expand_tags`]: the wire payload (tags rewritten into
/// fenced blocks / references) plus the per-tag expansions to surface in
/// the chat.
#[derive(Debug, Clone, Default)]
pub struct ExpandResult {
    pub wire: String,
    pub expansions: Vec<TagExpansion>,
}

/// Submit-time safety policy for manually typed `@` tags. The popup already
/// walks with gitignore filtering; this gate makes the non-popup path obey
/// the same read allowlist and project boundary rules.
#[derive(Debug, Clone)]
pub struct TagPolicy {
    cwd: PathBuf,
    cwd_resolved: PathBuf,
    allow_root: PathBuf,
    allow: Vec<String>,
    caps: TagInlineCaps,
}

impl TagPolicy {
    #[cfg(test)]
    fn new(cwd: &Path, allow: Vec<String>) -> Self {
        Self::new_for_mode(cwd, allow, LlmMode::Normal)
    }

    pub fn new_for_mode(cwd: &Path, allow: Vec<String>, mode: LlmMode) -> Self {
        let cwd_resolved = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
        let allow_root = crate::git::find_worktree_root(cwd).unwrap_or_else(|| cwd.to_path_buf());
        Self {
            cwd: cwd.to_path_buf(),
            cwd_resolved,
            allow_root,
            allow,
            caps: TagInlineCaps::for_mode(mode),
        }
    }

    fn allow(&self) -> &[String] {
        &self.allow
    }

    fn caps(&self) -> TagInlineCaps {
        self.caps
    }
}

/// True when `path` contains a character that would break the
/// whitespace-terminated tag scanner (currently: any whitespace). Such
/// paths must be quoted (`@"path with spaces"`) — the submit-time pass
/// does this automatically for autocompleted tags.
pub fn needs_quoting(path: &str) -> bool {
    path.chars().any(char::is_whitespace)
}

/// Wrap every tracked accepted-tag path (those containing spaces) in
/// quotes on a copy of `buffer`, so the whitespace-terminated scanner in
/// [`expand_tags`] reads them as one token. Content-matched at each `@`
/// boundary (longest path first) — robust to edits elsewhere in the
/// buffer. The composer shows the unquoted form; only this submit-time
/// copy carries the quotes.
pub fn quote_tracked_tags(buffer: &str, accepted: &[String]) -> String {
    let mut tracked: Vec<&String> = accepted.iter().filter(|p| needs_quoting(p)).collect();
    if tracked.is_empty() {
        return buffer.to_string();
    }
    tracked.sort_by_key(|p| std::cmp::Reverse(p.len()));
    let bytes = buffer.as_bytes();
    let mut out = String::with_capacity(buffer.len() + tracked.len() * 2);
    let mut i = 0;
    while i < buffer.len() {
        let at_boundary = i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'\n' | b'\r');
        if bytes[i] == b'@' && at_boundary {
            let rest = &buffer[i + 1..];
            // Don't double-quote an already-quoted tag.
            if !rest.starts_with('"')
                && let Some(p) = tracked.iter().find(|p| rest.starts_with(p.as_str()))
            {
                out.push('@');
                out.push('"');
                out.push_str(p);
                out.push('"');
                i += 1 + p.len();
                continue;
            }
        }
        let len = char_len_at(buffer, i);
        out.push_str(&buffer[i..i + len]);
        i += len;
    }
    out
}

/// Scan `buffer` for every `@path[:range]` (or quoted `@"path"[:range]`)
/// token and rewrite it into a fenced `<file>` / `<dir>` block. Tokens
/// that can't be inlined (missing, binary, too large) survive verbatim
/// with a `[note: ...]` chip. Returns the wire payload plus the per-tag
/// expansions for the chat (GOALS §1e).
#[cfg(test)]
fn expand_tags(buffer: &str, cwd: &Path) -> ExpandResult {
    expand_tags_inner(buffer, cwd, None)
}

pub fn expand_tags_with_policy(buffer: &str, policy: &TagPolicy) -> ExpandResult {
    expand_tags_inner(buffer, &policy.cwd, Some(policy))
}

fn expand_tags_inner(buffer: &str, cwd: &Path, policy: Option<&TagPolicy>) -> ExpandResult {
    let mut wire = String::with_capacity(buffer.len());
    let mut expansions: Vec<TagExpansion> = Vec::new();
    // Dedup state, per call (one message): a repeated `@`-tag of the same
    // file/dir + range inlines only once. Keyed by `(canonical resolved
    // path, range)` so trivially-different spellings collapse. A later
    // occurrence emits a reference marker and pushes no `TagExpansion`
    // (no second chat row). State never persists across messages.
    let mut seen: std::collections::HashSet<(PathBuf, Option<(usize, usize)>)> =
        std::collections::HashSet::new();
    let bytes = buffer.as_bytes();
    let mut i = 0;
    while i < buffer.len() {
        // `@` starts a tag only at the buffer start or after whitespace,
        // so emails (`user@host`) and mid-word `@` don't trigger.
        let at_boundary = i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'\n' | b'\r');
        if bytes[i] == b'@'
            && at_boundary
            && let Some((consumed, path_part, range, raw)) = parse_tag_at(buffer, i)
        {
            let key = (dedup_key(cwd, path_part), range);
            if seen.contains(&key) {
                // A later occurrence of an already-included tag: emit only
                // a reference marker, push no expansion (no duplicate
                // block, no duplicate chat row).
                wire.push_str(&reference_marker(cwd, path_part));
            } else {
                seen.insert(key);
                let exp = try_inline(cwd, path_part, range, raw, policy);
                wire.push_str(&exp.wire_piece);
                expansions.push(exp.expansion);
            }
            i += consumed;
            continue;
        }
        let len = char_len_at(buffer, i);
        wire.push_str(&buffer[i..i + len]);
        i += len;
    }
    ExpandResult { wire, expansions }
}

/// Dedup key path component: the canonicalized resolved path, falling back
/// to the lexical resolved `PathBuf` when canonicalize fails (missing file)
/// — so a missing file tagged twice still dedups.
fn dedup_key(cwd: &Path, path_part: &str) -> PathBuf {
    let resolved = resolve_path(cwd, path_part);
    std::fs::canonicalize(&resolved).unwrap_or(resolved)
}

/// Reference marker for a deduped repeat, substituted into the wire in
/// place of the inlined block. Names the path as the user wrote it and
/// points back to the earlier mention in the same message.
fn reference_marker(cwd: &Path, path_part: &str) -> String {
    let is_dir = std::fs::metadata(resolve_path(cwd, path_part)).is_ok_and(|m| m.is_dir());
    if is_dir {
        format!("[directory {path_part} — already listed above]")
    } else {
        format!("[file {path_part} — already included above]")
    }
}

/// UTF-8-safe length of the char beginning at byte `i`.
fn char_len_at(s: &str, i: usize) -> usize {
    s[i..].chars().next().map(char::len_utf8).unwrap_or(1)
}

/// `(bytes_consumed_including_@, path, range, raw_token)`.
type ParsedTag<'a> = (usize, &'a str, Option<(usize, usize)>, &'a str);

/// Parse a tag beginning at the `@` byte index `at`. Returns the parsed
/// tag, or `None` for a lone `@` with no body.
fn parse_tag_at(buffer: &str, at: usize) -> Option<ParsedTag<'_>> {
    let after = at + 1;
    let rest = &buffer[after..];
    if let Some(stripped) = rest.strip_prefix('"') {
        // Quoted: @"path"[:range] — read to the closing quote.
        let inner_start = after + 1;
        let close_rel = stripped.find('"')?;
        let path = &buffer[inner_start..inner_start + close_rel];
        if path.is_empty() {
            return None;
        }
        let mut end = inner_start + close_rel + 1; // past closing quote
        let mut range = None;
        if buffer[end..].starts_with(':') {
            let range_start = end + 1;
            let range_end = buffer[range_start..]
                .find(char::is_whitespace)
                .map(|o| range_start + o)
                .unwrap_or(buffer.len());
            if let Some(r) = parse_range(&buffer[range_start..range_end]) {
                range = Some(r);
                end = range_end;
            }
        }
        Some((end - at, path, range, &buffer[at..end]))
    } else {
        // Bare: terminate at the next whitespace.
        let body_end = rest
            .find(char::is_whitespace)
            .map(|o| after + o)
            .unwrap_or(buffer.len());
        if body_end == after {
            return None; // lone '@'
        }
        let body = &buffer[after..body_end];
        let (path, range) = parse_tag_body(body);
        Some((body_end - at, path, range, &buffer[at..body_end]))
    }
}

fn resolve_path(cwd: &Path, path_part: &str) -> PathBuf {
    let expanded = shellexpand::tilde(path_part);
    let p = Path::new(expanded.as_ref());
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

/// What an `@`-tag contributes to the wire payload + how it shows in chat.
struct Expanded {
    /// Substituted into the wire in place of the raw token: either the
    /// fenced block (success) or the raw token followed by a `[note:…]`
    /// (skip / reference).
    wire_piece: String,
    expansion: TagExpansion,
}

fn try_inline(
    cwd: &Path,
    path_part: &str,
    range: Option<(usize, usize)>,
    raw: &str,
    policy: Option<&TagPolicy>,
) -> Expanded {
    let resolved = resolve_path(cwd, path_part);
    if let Some(policy) = policy
        && let Some(blocked) = check_policy(path_part, raw, &resolved, policy)
    {
        return blocked;
    }
    let caps = policy
        .map(TagPolicy::caps)
        .unwrap_or_else(|| TagInlineCaps::for_mode(LlmMode::Normal));
    let meta = match std::fs::metadata(&resolved) {
        Ok(m) => m,
        Err(e) => {
            return skip(
                "read",
                path_part,
                raw,
                format!("could not be inlined: {e}"),
                "not found",
            );
        }
    };

    if meta.is_dir() {
        if range.is_some() {
            return skip(
                "list",
                path_part,
                raw,
                "line range not valid for a directory".into(),
                "skipped",
            );
        }
        let (block, count) = render_directory(&resolved, path_part, policy, caps);
        return Expanded {
            wire_piece: block,
            expansion: TagExpansion {
                tool: "list",
                path: path_part.to_string(),
                detail: format!("{count} entries"),
                ok: true,
            },
        };
    }

    let bytes = match std::fs::read(&resolved) {
        Ok(b) => b,
        Err(e) => {
            return skip(
                "read",
                path_part,
                raw,
                format!("could not be inlined: {e}"),
                "unreadable",
            );
        }
    };
    if looks_binary(&bytes) {
        return skip(
            "read",
            path_part,
            raw,
            "file looks binary".into(),
            "binary, skipped",
        );
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();

    // Over-cap full-file tags are left as a *reference*, not inlined —
    // a multi-thousand-line dump the user may not need is exactly the
    // context bloat the token economy avoids (GOALS §1e / §10). A tag
    // with an explicit range is always inlined (the slice is bounded).
    if range.is_none() {
        let line_count = text.lines().count();
        if line_count > caps.max_lines || bytes.len() > caps.max_bytes {
            let note = format!(
                " [note: @{path_part} is {line_count} lines — not inlined; ask read with offset/limit]"
            );
            return Expanded {
                wire_piece: format!("{raw}{note}"),
                expansion: TagExpansion {
                    tool: "read",
                    path: path_part.to_string(),
                    detail: format!("{line_count} lines — referenced, not inlined"),
                    ok: false,
                },
            };
        }
    }

    let (block, lines_shown) = render_file(&text, path_part, range, caps);
    Expanded {
        wire_piece: block,
        expansion: TagExpansion {
            tool: "read",
            path: path_part.to_string(),
            detail: format!("{lines_shown} lines"),
            ok: true,
        },
    }
}

fn check_policy(
    path_part: &str,
    raw: &str,
    resolved: &Path,
    policy: &TagPolicy,
) -> Option<Expanded> {
    let typed = Path::new(path_part);
    if typed.is_absolute() {
        return Some(skip(
            "read",
            path_part,
            raw,
            "blocked: absolute @tags are not inlined; use a project-relative path".into(),
            "absolute path, blocked",
        ));
    }
    if path_part == "~" || path_part.starts_with("~/") {
        return Some(skip(
            "read",
            path_part,
            raw,
            "blocked: home-relative @tags are not inlined; use a project-relative path".into(),
            "home path, blocked",
        ));
    }

    let target = std::fs::canonicalize(resolved).unwrap_or_else(|_| normalize_lexical(resolved));
    if !target.starts_with(&policy.cwd_resolved) {
        return Some(skip(
            policy_tool_for(resolved),
            path_part,
            raw,
            "blocked: path escapes the project; use an in-project path".into(),
            "outside project, blocked",
        ));
    }

    if !crate::gitignore::is_permitted(&target, &policy.allow_root, policy.allow()) {
        return Some(skip(
            policy_tool_for(resolved),
            path_part,
            raw,
            "blocked: gitignored files are blocked; allow with `/gitignore-allow <path-or-glob>` or edit `/settings`".into(),
            "gitignored, blocked",
        ));
    }

    None
}

fn policy_tool_for(path: &Path) -> &'static str {
    if std::fs::metadata(path).is_ok_and(|m| m.is_dir()) {
        "list"
    } else {
        "read"
    }
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                out.push(component.as_os_str());
            }
        }
    }
    out
}

/// Build a skip `Expanded`: keep the raw token + append a `[note:…]`, and
/// record a not-ok chat entry.
fn skip(tool: &'static str, path: &str, raw: &str, note_body: String, detail: &str) -> Expanded {
    Expanded {
        wire_piece: format!("{raw} [note: @{path} {note_body}]"),
        expansion: TagExpansion {
            tool,
            path: path.to_string(),
            detail: detail.to_string(),
            ok: false,
        },
    }
}

/// Render a file as a line-numbered `<file>` block via the shared `read`
/// formatter. Returns the block and the number of lines shown.
fn render_file(
    text: &str,
    display_path: &str,
    range: Option<(usize, usize)>,
    caps: TagInlineCaps,
) -> (String, usize) {
    let (offset, limit) = match range {
        Some((start, end)) => (start, end - start + 1),
        None => (1, caps.max_lines),
    };
    let slice = read_slice_with_byte_cap(text, offset, limit, caps.max_bytes);
    let lines_shown = slice.numbered.lines().count();
    let mut out = format!("\n<file path=\"{display_path}\">\n{}", slice.numbered);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    if slice.truncated {
        out.push_str(&truncation_marker(slice.next_offset));
        out.push('\n');
    }
    out.push_str("</file>\n");
    (out, lines_shown)
}

/// Internal portable directory listing (no shell-out). Returns the
/// `<dir>` block and the total entry count.
fn render_directory(
    path: &Path,
    display_path: &str,
    policy: Option<&TagPolicy>,
    caps: TagInlineCaps,
) -> (String, usize) {
    let display = if display_path.ends_with('/') {
        display_path.to_string()
    } else {
        format!("{display_path}/")
    };
    let mut entries: Vec<(String, bool, u64)> = Vec::new();
    if let Some(policy) = policy {
        for (entry_path, is_dir, _gitignored) in
            level_entries(path, &policy.allow_root, policy.allow())
        {
            let name = entry_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let size = if is_dir {
                0
            } else {
                std::fs::metadata(&entry_path).map(|m| m.len()).unwrap_or(0)
            };
            entries.push((name, is_dir, size));
        }
    } else if let Ok(rd) = std::fs::read_dir(path) {
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            let (is_dir, size) = match ent.metadata() {
                Ok(m) => (m.is_dir(), m.len()),
                Err(_) => (false, 0),
            };
            entries.push((name, is_dir, size));
        }
    }
    entries.sort_by(|a, b| match (a.1, b.1) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.0.cmp(&b.0),
    });
    let total = entries.len();
    let mut body = String::new();
    for (name, is_dir, size) in entries.iter().take(caps.max_dir_entries) {
        let kind = if *is_dir { "dir" } else { "file" };
        if *is_dir {
            body.push_str(&format!("{name}/ ({kind})\n"));
        } else {
            body.push_str(&format!("{name} ({kind}) {size}\n"));
        }
    }
    if total > caps.max_dir_entries {
        let remaining = total - caps.max_dir_entries;
        body.push_str(&format!(
            "... {remaining} more entries; @-tag a subdirectory or ask explore for a search\n"
        ));
    }
    (format!("\n<dir path=\"{display}\">\n{body}</dir>\n"), total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn tmp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    /// Suggestions with an empty frequency map — these tests exercise
    /// the dirs-first/alpha ordering, not the count tie-breaker.
    fn sug(cwd: &Path, q: &str) -> Vec<Suggestion> {
        suggestions(cwd, q, &HashMap::new(), &[])
    }

    fn policy_for_mode(cwd: &Path, mode: LlmMode) -> TagPolicy {
        TagPolicy::new_for_mode(cwd, Vec::new(), mode)
    }

    fn expand_with_mode(buffer: &str, cwd: &Path, mode: LlmMode) -> ExpandResult {
        let policy = policy_for_mode(cwd, mode);
        expand_tags_with_policy(buffer, &policy)
    }

    fn repeated_lines(line_count: usize, width: usize) -> String {
        let body = "x".repeat(width);
        let mut out = String::new();
        for i in 1..=line_count {
            out.push_str(&format!("line {i:04} {body}\n"));
        }
        out
    }

    #[test]
    fn tag_inline_caps_are_mode_tiered_and_policy_constructs_from_mode() {
        let root = tmp_root();
        for (mode, expected) in [
            (
                LlmMode::Defensive,
                TagInlineCaps {
                    max_bytes: 8 * 1024,
                    max_lines: 500,
                    max_dir_entries: 30,
                },
            ),
            (
                LlmMode::Normal,
                TagInlineCaps {
                    max_bytes: 48 * 1024,
                    max_lines: 2_000,
                    max_dir_entries: 100,
                },
            ),
            (
                LlmMode::Frontier,
                TagInlineCaps {
                    max_bytes: 256 * 1024,
                    max_lines: 10_000,
                    max_dir_entries: 500,
                },
            ),
        ] {
            assert_eq!(TagInlineCaps::for_mode(mode), expected);
            assert_eq!(policy_for_mode(root.path(), mode).caps(), expected);
        }
    }

    #[test]
    fn mode_caps_gate_full_file_tags_by_lines_and_bytes() {
        for mode in [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier] {
            let root = tmp_root();
            let caps = TagInlineCaps::for_mode(mode);

            fs::write(
                root.path().join("within.txt"),
                repeated_lines(caps.max_lines, 1),
            )
            .unwrap();
            let within = expand_with_mode("@within.txt", root.path(), mode);
            assert!(
                within.wire.contains("<file path=\"within.txt\">"),
                "{mode:?}: {}",
                within.wire
            );
            assert!(within.expansions[0].ok, "{mode:?}");

            fs::write(
                root.path().join("too_many_lines.txt"),
                repeated_lines(caps.max_lines + 1, 1),
            )
            .unwrap();
            let too_many_lines = expand_with_mode("@too_many_lines.txt", root.path(), mode);
            assert!(
                !too_many_lines.wire.contains("<file"),
                "{mode:?}: {}",
                too_many_lines.wire
            );
            assert!(
                too_many_lines.wire.contains("not inlined"),
                "{mode:?}: {}",
                too_many_lines.wire
            );
            assert!(!too_many_lines.expansions[0].ok, "{mode:?}");

            fs::write(
                root.path().join("too_many_bytes.txt"),
                "x".repeat(caps.max_bytes + 1),
            )
            .unwrap();
            let too_many_bytes = expand_with_mode("@too_many_bytes.txt", root.path(), mode);
            assert!(
                !too_many_bytes.wire.contains("<file"),
                "{mode:?}: {}",
                too_many_bytes.wire
            );
            assert!(
                too_many_bytes.wire.contains("not inlined"),
                "{mode:?}: {}",
                too_many_bytes.wire
            );
            assert!(!too_many_bytes.expansions[0].ok, "{mode:?}");
        }
    }

    #[test]
    fn mode_caps_scale_range_tag_byte_ceiling() {
        for (lower, higher, lines, width) in [
            (LlmMode::Defensive, LlmMode::Normal, 80, 120),
            (LlmMode::Normal, LlmMode::Frontier, 300, 200),
        ] {
            let root = tmp_root();
            fs::write(root.path().join("range.txt"), repeated_lines(lines, width)).unwrap();

            let lower_res = expand_with_mode(&format!("@range.txt:1-{lines}"), root.path(), lower);
            assert!(
                lower_res.wire.contains("[truncated"),
                "{lower:?}: {}",
                lower_res.wire
            );
            assert!(lower_res.expansions[0].ok, "{lower:?}");

            let higher_res =
                expand_with_mode(&format!("@range.txt:1-{lines}"), root.path(), higher);
            assert!(
                !higher_res.wire.contains("[truncated"),
                "{higher:?}: {}",
                higher_res.wire
            );
            assert_eq!(higher_res.expansions[0].detail, format!("{lines} lines"));
        }

        let root = tmp_root();
        let lines = 1_500;
        fs::write(
            root.path().join("frontier-range.txt"),
            repeated_lines(lines, 200),
        )
        .unwrap();
        let frontier = expand_with_mode(
            &format!("@frontier-range.txt:1-{lines}"),
            root.path(),
            LlmMode::Frontier,
        );
        assert!(
            frontier.wire.contains("[truncated"),
            "wire: {}",
            frontier.wire
        );
    }

    #[test]
    fn mode_caps_scale_directory_listing_limit_and_remaining_count() {
        for mode in [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier] {
            let root = tmp_root();
            let caps = TagInlineCaps::for_mode(mode);
            let dir_name = mode.as_str();
            let dir = root.path().join(dir_name);
            fs::create_dir(&dir).unwrap();
            for i in 0..caps.max_dir_entries + 2 {
                fs::write(dir.join(format!("file-{i:04}.txt")), "x").unwrap();
            }

            let res = expand_with_mode(&format!("@{dir_name}"), root.path(), mode);
            assert_eq!(
                res.wire.matches("(file)").count(),
                caps.max_dir_entries,
                "{mode:?}: {}",
                res.wire
            );
            assert!(
                res.wire.contains(
                    "... 2 more entries; @-tag a subdirectory or ask explore for a search"
                ),
                "{mode:?}: {}",
                res.wire
            );
        }
    }

    #[test]
    fn parse_range_single_and_pair() {
        assert_eq!(parse_range("42"), Some((42, 42)));
        assert_eq!(parse_range("10-80"), Some((10, 80)));
        assert_eq!(parse_range("0"), None);
        assert_eq!(parse_range("10-5"), None);
        assert_eq!(parse_range("nope"), None);
    }

    #[test]
    fn parse_tag_body_splits_path_and_range() {
        assert_eq!(parse_tag_body("foo.rs"), ("foo.rs", None));
        assert_eq!(parse_tag_body("foo.rs:42"), ("foo.rs", Some((42, 42))));
        assert_eq!(parse_tag_body("foo.rs:10-80"), ("foo.rs", Some((10, 80))));
        // Trailing non-range colon survives as part of the path.
        assert_eq!(parse_tag_body("weird:name"), ("weird:name", None));
    }

    #[test]
    fn expand_tags_inlines_existing_file() {
        let root = tmp_root();
        let p = root.path().join("hello.txt");
        fs::write(&p, "hello\nworld\n").unwrap();
        let out = expand_tags("see @hello.txt please", root.path()).wire;
        assert!(out.contains("<file path=\"hello.txt\">"));
        assert!(out.contains("hello"));
        assert!(out.contains("</file>"));
    }

    #[test]
    fn expand_tags_inlines_with_line_numbers() {
        let root = tmp_root();
        fs::write(root.path().join("hello.txt"), "alpha\nbeta\n").unwrap();
        let res = expand_tags("@hello.txt", root.path());
        // Routed through the read formatter → line-numbered output.
        assert!(res.wire.contains("1|alpha"), "wire: {}", res.wire);
        assert!(res.wire.contains("2|beta"), "wire: {}", res.wire);
        assert_eq!(res.expansions.len(), 1);
        assert_eq!(res.expansions[0].tool, "read");
        assert!(res.expansions[0].ok);
    }

    #[test]
    fn expand_tags_over_cap_file_is_referenced_not_inlined() {
        let root = tmp_root();
        let mut big = String::new();
        for i in 0..3000 {
            big.push_str(&format!("line {i}\n"));
        }
        fs::write(root.path().join("big.rs"), big).unwrap();
        let res = expand_tags("@big.rs", root.path());
        // Not inlined: no <file> block; the @path survives + a note.
        assert!(!res.wire.contains("<file"), "wire: {}", res.wire);
        assert!(res.wire.contains("@big.rs"));
        assert!(res.wire.contains("not inlined"));
        assert_eq!(res.expansions.len(), 1);
        assert!(!res.expansions[0].ok);
    }

    #[test]
    fn expand_tags_over_cap_with_range_still_inlines() {
        let root = tmp_root();
        let mut big = String::new();
        for i in 0..3000 {
            big.push_str(&format!("line {i}\n"));
        }
        fs::write(root.path().join("big.rs"), big).unwrap();
        // An explicit range is bounded, so it inlines even on a big file.
        let res = expand_tags("@big.rs:10-12", root.path());
        assert!(res.wire.contains("<file"), "wire: {}", res.wire);
        assert!(res.wire.contains("line 9")); // 1-indexed line 10 == "line 9"
    }

    #[test]
    fn needs_quoting_flags_spaces_only() {
        assert!(needs_quoting("src/my file.rs"));
        assert!(!needs_quoting("src/plain.rs"));
    }

    #[test]
    fn quote_tracked_tags_wraps_spaced_path() {
        let accepted = vec!["src/my file.rs".to_string()];
        let out = quote_tracked_tags("see @src/my file.rs ok", &accepted);
        assert_eq!(out, "see @\"src/my file.rs\" ok");
        // Untracked plain paths are untouched.
        assert_eq!(quote_tracked_tags("see @a.rs", &accepted), "see @a.rs");
    }

    #[test]
    fn expand_tags_inlines_quoted_spaced_path() {
        let root = tmp_root();
        fs::write(root.path().join("my file.rs"), "x = 1\n").unwrap();
        let res = expand_tags("@\"my file.rs\"", root.path());
        assert!(
            res.wire.contains("<file path=\"my file.rs\">"),
            "wire: {}",
            res.wire
        );
        assert!(res.wire.contains("1|x = 1"));
    }

    #[test]
    fn expand_tags_quoted_path_with_range() {
        let root = tmp_root();
        fs::write(root.path().join("my file.rs"), "a\nb\nc\nd\n").unwrap();
        let res = expand_tags("@\"my file.rs\":2-3", root.path());
        assert!(res.wire.contains("2|b"));
        assert!(res.wire.contains("3|c"));
        assert!(!res.wire.contains("1|a"));
    }

    #[test]
    fn expand_tags_handles_line_range() {
        let root = tmp_root();
        let p = root.path().join("nums.txt");
        let mut f = fs::File::create(&p).unwrap();
        for i in 1..=20 {
            writeln!(f, "line{i}").unwrap();
        }
        let out = expand_tags("@nums.txt:5-7", root.path()).wire;
        assert!(out.contains("line5"));
        assert!(out.contains("line6"));
        assert!(out.contains("line7"));
        assert!(!out.contains("line8"));
    }

    #[test]
    fn expand_tags_keeps_missing_file_literal() {
        let root = tmp_root();
        let out = expand_tags("see @nope.rs ok", root.path()).wire;
        assert!(out.contains("@nope.rs"));
        assert!(out.contains("[note: @nope.rs could not be inlined"));
    }

    #[test]
    fn expand_tags_refuses_binary() {
        let root = tmp_root();
        let p = root.path().join("bin.dat");
        fs::write(&p, [0u8, 1, 2, 3, 4, 5]).unwrap();
        let out = expand_tags("@bin.dat", root.path()).wire;
        assert!(out.contains("looks binary"));
        assert!(!out.contains("<file"));
    }

    #[test]
    fn expand_tags_ignores_mid_word_at() {
        let root = tmp_root();
        let out = expand_tags("email me at user@example.com", root.path()).wire;
        assert_eq!(out, "email me at user@example.com");
    }

    #[test]
    fn expand_tags_directory_listing() {
        let root = tmp_root();
        fs::write(root.path().join("a.txt"), "a").unwrap();
        fs::write(root.path().join("b.txt"), "bb").unwrap();
        fs::create_dir(root.path().join("sub")).unwrap();
        let out = expand_tags("@./", root.path()).wire;
        assert!(out.contains("<dir path=\"./\">"));
        assert!(out.contains("sub/ (dir)"));
        assert!(out.contains("a.txt (file)"));
    }

    #[test]
    fn expand_tags_range_out_of_bounds_yields_empty_body() {
        let root = tmp_root();
        fs::write(root.path().join("x.txt"), "only one line\n").unwrap();
        let out = expand_tags("@x.txt:50-60", root.path()).wire;
        // No content, but the block still renders.
        assert!(out.contains("<file path=\"x.txt\">"));
        assert!(out.contains("</file>"));
    }

    #[test]
    fn expand_tags_dedups_same_path_twice() {
        let root = tmp_root();
        fs::write(root.path().join("foo.rs"), "alpha\nbeta\n").unwrap();
        let res = expand_tags("@foo.rs and again @foo.rs", root.path());
        // Exactly one inlined <file> block.
        assert_eq!(res.wire.matches("<file ").count(), 1, "wire: {}", res.wire);
        // The repeat is a reference marker, once.
        assert_eq!(
            res.wire
                .matches("[file foo.rs — already included above]")
                .count(),
            1,
            "wire: {}",
            res.wire
        );
        assert_eq!(res.expansions.len(), 1);
    }

    #[test]
    fn expand_tags_whole_then_range_are_distinct() {
        let root = tmp_root();
        fs::write(root.path().join("foo.rs"), "a\nb\nc\nd\n").unwrap();
        let res = expand_tags("@foo.rs then @foo.rs:1-2", root.path());
        // Range distinguishes the keys → both inline.
        assert_eq!(res.wire.matches("<file ").count(), 2, "wire: {}", res.wire);
        assert!(
            !res.wire.contains("already included above"),
            "wire: {}",
            res.wire
        );
        assert_eq!(res.expansions.len(), 2);
    }

    #[test]
    fn expand_tags_dedups_different_spellings_via_canonicalize() {
        let root = tmp_root();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::write(root.path().join("src/x.rs"), "x = 1\n").unwrap();
        let res = expand_tags("@src/x.rs and @./src/x.rs", root.path());
        // Canonicalization collapses the two spellings to one key.
        assert_eq!(res.wire.matches("<file ").count(), 1, "wire: {}", res.wire);
        assert_eq!(res.expansions.len(), 1);
        assert!(
            res.wire.contains("already included above"),
            "wire: {}",
            res.wire
        );
    }

    #[test]
    fn expand_tags_dedups_directory_twice() {
        let root = tmp_root();
        fs::create_dir(root.path().join("d")).unwrap();
        fs::write(root.path().join("d/a.txt"), "a").unwrap();
        let res = expand_tags("@d and @d", root.path());
        assert_eq!(res.wire.matches("<dir ").count(), 1, "wire: {}", res.wire);
        assert_eq!(res.expansions.len(), 1);
        assert_eq!(res.expansions[0].tool, "list");
        assert!(
            res.wire.contains("[directory d — already listed above]"),
            "wire: {}",
            res.wire
        );
    }

    #[test]
    fn expand_tags_dedups_missing_file_twice() {
        let root = tmp_root();
        let res = expand_tags("@nope.rs and @nope.rs", root.path());
        // First occurrence is the ✗-style (not-ok) expansion; the repeat
        // dedups to a marker with no second expansion.
        assert_eq!(res.expansions.len(), 1);
        assert!(!res.expansions[0].ok);
        assert!(
            res.wire.contains("could not be inlined"),
            "wire: {}",
            res.wire
        );
        assert_eq!(
            res.wire
                .matches("[file nope.rs — already included above]")
                .count(),
            1,
            "wire: {}",
            res.wire
        );
    }

    #[test]
    fn policy_blocks_gitignored_manual_tag_unless_allowed() {
        let root = tmp_root();
        fs::create_dir(root.path().join(".git")).unwrap();
        fs::write(root.path().join(".gitignore"), ".env\n").unwrap();
        fs::write(root.path().join(".env"), "SECRET=1\n").unwrap();

        let policy = TagPolicy::new(root.path(), Vec::new());
        let blocked = expand_tags_with_policy("@.env", &policy);
        assert!(!blocked.wire.contains("<file"), "wire: {}", blocked.wire);
        assert!(
            blocked.wire.contains("gitignored files are blocked"),
            "wire: {}",
            blocked.wire
        );
        assert!(blocked.wire.contains("/gitignore-allow <path-or-glob>"));
        assert_eq!(blocked.expansions[0].detail, "gitignored, blocked");

        let allow = vec![".env".to_string()];
        let allowed_policy = TagPolicy::new(root.path(), allow.clone());
        let allowed = expand_tags_with_policy("@.env", &allowed_policy);
        assert!(
            allowed.wire.contains("<file path=\".env\">"),
            "wire: {}",
            allowed.wire
        );
        assert!(allowed.wire.contains("SECRET=1"), "wire: {}", allowed.wire);

        let popup_none = suggestions(root.path(), "", &HashMap::new(), &[]);
        assert!(!popup_none.iter().any(|s| s.display == ".env"));
        let popup_allowed = suggestions(root.path(), "", &HashMap::new(), &allow);
        assert!(
            popup_allowed
                .iter()
                .any(|s| s.display == ".env" && s.gitignored)
        );
    }

    #[test]
    fn policy_blocks_absolute_home_and_escape_paths() {
        let tmp = tmp_root();
        let cwd = tmp.path().join("project");
        fs::create_dir(&cwd).unwrap();
        fs::write(cwd.join("inside.txt"), "inside\n").unwrap();
        fs::write(tmp.path().join("outside.txt"), "outside\n").unwrap();

        let policy = TagPolicy::new(&cwd, Vec::new());
        let abs =
            expand_tags_with_policy(&format!("@{}", cwd.join("inside.txt").display()), &policy);
        assert!(
            abs.wire.contains("absolute @tags are not inlined"),
            "wire: {}",
            abs.wire
        );

        let home = expand_tags_with_policy("@~/secret.txt", &policy);
        assert!(
            home.wire.contains("home-relative @tags are not inlined"),
            "wire: {}",
            home.wire
        );

        let escape = expand_tags_with_policy("@../outside.txt", &policy);
        assert!(
            escape.wire.contains("path escapes the project"),
            "wire: {}",
            escape.wire
        );

        let missing_inside = expand_tags_with_policy("@missing.txt", &policy);
        assert!(
            missing_inside.wire.contains("could not be inlined"),
            "wire: {}",
            missing_inside.wire
        );
    }

    #[cfg(unix)]
    #[test]
    fn policy_blocks_symlink_targets_outside_cwd() {
        use std::os::unix::fs::symlink;

        let tmp = tmp_root();
        let cwd = tmp.path().join("project");
        fs::create_dir(&cwd).unwrap();
        fs::write(tmp.path().join("outside.txt"), "outside\n").unwrap();
        symlink(tmp.path().join("outside.txt"), cwd.join("link.txt")).unwrap();

        let policy = TagPolicy::new(&cwd, Vec::new());
        let res = expand_tags_with_policy("@link.txt", &policy);
        assert!(
            res.wire.contains("path escapes the project"),
            "wire: {}",
            res.wire
        );
        assert!(!res.wire.contains("outside"), "wire: {}", res.wire);
    }

    #[test]
    fn policy_directory_listing_filters_gitignored_children() {
        let root = tmp_root();
        fs::create_dir(root.path().join(".git")).unwrap();
        fs::write(root.path().join(".gitignore"), "dir/secret.txt\n").unwrap();
        fs::create_dir(root.path().join("dir")).unwrap();
        fs::write(root.path().join("dir/visible.txt"), "ok").unwrap();
        fs::write(root.path().join("dir/secret.txt"), "SECRET").unwrap();

        let policy = TagPolicy::new(root.path(), Vec::new());
        let res = expand_tags_with_policy("@dir", &policy);
        assert!(
            res.wire.contains("visible.txt (file)"),
            "wire: {}",
            res.wire
        );
        assert!(!res.wire.contains("secret.txt"), "wire: {}", res.wire);

        let allowed = TagPolicy::new(root.path(), vec!["dir/secret.txt".to_string()]);
        let res = expand_tags_with_policy("@dir", &allowed);
        assert!(res.wire.contains("secret.txt (file)"), "wire: {}", res.wire);
    }

    #[test]
    fn suggestions_lists_cwd_entries() {
        let root = tmp_root();
        fs::write(root.path().join("alpha.rs"), "").unwrap();
        fs::write(root.path().join("beta.rs"), "").unwrap();
        fs::create_dir(root.path().join("zeta")).unwrap();
        let s = sug(root.path(), "");
        let names: Vec<&str> = s.iter().map(|x| x.display.as_str()).collect();
        // Dir first.
        assert_eq!(names.first().copied(), Some("zeta/"));
        assert!(names.contains(&"alpha.rs"));
    }

    #[test]
    fn suggestions_rank_by_count_then_dirs_pinned() {
        let root = tmp_root();
        fs::write(root.path().join("alpha.rs"), "").unwrap();
        fs::write(root.path().join("beta.rs"), "").unwrap();
        fs::create_dir(root.path().join("zeta")).unwrap();
        // beta is picked more often → ranks above alpha even though alpha
        // sorts first alphabetically. The directory stays pinned on top
        // regardless of the file counts.
        let mut counts = HashMap::new();
        counts.insert("beta.rs".to_string(), 5u64);
        let s = suggestions(root.path(), "", &counts, &[]);
        let names: Vec<&str> = s.iter().map(|x| x.display.as_str()).collect();
        assert_eq!(
            names.first().copied(),
            Some("zeta/"),
            "dir not pinned: {names:?}"
        );
        let a = names.iter().position(|n| *n == "alpha.rs").unwrap();
        let b = names.iter().position(|n| *n == "beta.rs").unwrap();
        assert!(
            b < a,
            "more-frequent beta.rs should outrank alpha.rs: {names:?}"
        );
    }

    /// A gitignored file is hidden from the popup by default, but re-included
    /// (flagged `gitignored = true`) once the read-allowlist matches it
    /// (implementation note).
    #[test]
    fn suggestions_reinclude_allowlisted_gitignored() {
        let root = tmp_root();
        fs::create_dir(root.path().join(".git")).unwrap();
        fs::write(root.path().join(".gitignore"), "secret.txt\n").unwrap();
        fs::write(root.path().join("kept.rs"), "").unwrap();
        fs::write(root.path().join("secret.txt"), "").unwrap();

        // No allowlist → the gitignored file is absent.
        let none = suggestions(root.path(), "", &HashMap::new(), &[]);
        assert!(!none.iter().any(|s| s.display == "secret.txt"));

        // Allowlisted → present and flagged gitignored.
        let allow = vec!["secret.txt".to_string()];
        let with = suggestions(root.path(), "", &HashMap::new(), &allow);
        let entry = with
            .iter()
            .find(|s| s.display == "secret.txt")
            .expect("allowlisted gitignored file surfaces");
        assert!(entry.gitignored, "re-included entry flagged gitignored");
        // The tracked file is present and not flagged.
        let kept = with.iter().find(|s| s.display == "kept.rs").unwrap();
        assert!(!kept.gitignored);
    }

    #[test]
    fn suggestions_prefix_filter() {
        let root = tmp_root();
        fs::write(root.path().join("alpha.rs"), "").unwrap();
        fs::write(root.path().join("beta.rs"), "").unwrap();
        let s = sug(root.path(), "alp");
        let names: Vec<&str> = s.iter().map(|x| x.display.as_str()).collect();
        assert_eq!(names, vec!["alpha.rs"]);
    }

    #[test]
    fn suggestions_deepen_when_shallow_level_is_sparse() {
        // cwd has one file + one subdir; the subdir holds several files.
        // An empty query should deepen into the subdir to fill the list.
        let root = tmp_root();
        fs::write(root.path().join("top.rs"), "").unwrap();
        let sub = root.path().join("sub");
        fs::create_dir(&sub).unwrap();
        for n in ["a.rs", "b.rs", "c.rs", "d.rs"] {
            fs::write(sub.join(n), "").unwrap();
        }
        let s = sug(root.path(), "");
        let names: Vec<&str> = s.iter().map(|x| x.display.as_str()).collect();
        // Level 1 (sub/, top.rs) is only 2 entries → deepen into sub/.
        assert!(names.contains(&"sub/"));
        assert!(names.contains(&"top.rs"));
        assert!(names.contains(&"sub/a.rs"), "deeper entries: {names:?}");
        assert!(names.contains(&"sub/d.rs"), "deeper entries: {names:?}");
    }

    #[test]
    fn suggestions_deepen_prefix_match_finds_nested_file() {
        // Typing a basename that only exists deeper should still surface
        // it via the deepening walk.
        let root = tmp_root();
        let nested = root.path().join("router");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("match.ts"), "").unwrap();
        let s = sug(root.path(), "match");
        let names: Vec<&str> = s.iter().map(|x| x.display.as_str()).collect();
        assert!(names.contains(&"router/match.ts"), "got {names:?}");
    }

    #[test]
    fn suggestions_returns_more_than_window_up_to_internal_cap() {
        // More than six matching files at the top level: the renderer windows
        // them, but the walker returns a bounded scrollable list.
        let root = tmp_root();
        for n in 0..120 {
            fs::write(root.path().join(format!("file{n:03}.rs")), "").unwrap();
        }
        let s = sug(root.path(), "file");
        assert_eq!(
            s.len(),
            MAX_SUGGESTIONS,
            "expected capped matches, got {}",
            s.len()
        );
        assert!(s.iter().any(|s| s.display == "file099.rs"));
        assert!(!s.iter().any(|s| s.display == "file100.rs"));
    }

    #[test]
    fn suggestions_skips_hidden_files() {
        let root = tmp_root();
        fs::write(root.path().join(".hidden"), "").unwrap();
        fs::write(root.path().join("visible.txt"), "").unwrap();
        let s = sug(root.path(), "");
        let names: Vec<&str> = s.iter().map(|x| x.display.as_str()).collect();
        assert!(names.iter().all(|n| *n != ".hidden"));
        assert!(names.contains(&"visible.txt"));
    }
}
