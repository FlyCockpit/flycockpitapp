//! `/diff` pane — a first-class, read-only multi-file diff browser.
//!
//! A full-body modal overlay (matching `/sessions`, `/plans`, `/stats`, and
//! `/permissions`): a left file list with per-file added/deleted counts and
//! a right diff body for the selected file. Sources:
//!
//! - [`DiffSource::Worktree`] (`/diff` / `/diff worktree`) — every
//!   uncommitted change against `HEAD` (`git diff HEAD`).
//! - [`DiffSource::Staged`] (`/diff staged`) — staged-only (`git diff
//!   --cached`).
//! - [`DiffSource::Last`] (`/diff last`) — the most recent agent edit/write
//!   diff captured in the current TUI history, synthesized into a unified
//!   diff so it parses the same way the git sources do.
//!
//! The pane is **read-only**: it never stages, applies, reverts, or edits,
//! and it never invokes a destructive git command — only `git diff`, through
//! the existing the `cockpit_core::git` helpers. Its state is user-facing TUI state
//! only and never enters any outbound model prompt.
//!
//! Diff bodies are parsed **once** at load into per-file sections
//! ([`parse_unified_diff`]); rendering only formats the already-parsed rows
//! and the App's `Paragraph` scroll renders just the visible window, so a
//! huge diff stays responsive. Extremely large file bodies are capped with
//! a one-line summary tail ([`MAX_FILE_ROWS`]).
//!
//! Rendering reuses the existing [`DiffStyle`] setting and the shared diff
//! colors — no second diff theme. Side-by-side degrades to inline on narrow
//! terminals exactly like [`crate::tui::diff`].

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
#[cfg(test)]
use ratatui::Terminal;
#[cfg(test)]
use ratatui::backend::TestBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::tui::diff::SIDE_BY_SIDE_MIN_WIDTH;
use crate::tui::history::HistoryEntry;
use crate::tui::pane::{Pane, ScrollList};
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_config::extended::DiffStyle;

/// Minimum total body width for the two-column (list + diff) layout. Below
/// this the file list is hidden and only the selected diff renders, and
/// side-by-side falls back to inline.
const NARROW_FALLBACK_WIDTH: u16 = 60;

/// Width (in cells) of the file-list column in the two-column layout.
const LIST_WIDTH: u16 = 32;

/// Cap on rendered rows for a single file's diff body. A file longer than
/// this is truncated with a one-line summary so an enormous generated-file
/// diff can't stall the renderer.
const MAX_FILE_ROWS: usize = 4000;

// Shared diff colors — kept in sync with `crate::tui::diff` (whose copies
// are module-private), not a new theme.
const COL_REMOVED: Color = Color::Red;
const COL_ADDED: Color = Color::Green;
const COL_HUNK: Color = Color::Cyan;

/// Side-by-side column separator (mirrors `crate::tui::diff`).
const COL_SEPARATOR: &str = " │ ";

/// Which diff is being shown. The pane loads all three and cycles with
/// `Tab`; this is the cycle order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffSource {
    /// Uncommitted worktree changes vs `HEAD` (staged + unstaged).
    Worktree,
    /// Staged-only changes (`git diff --cached`).
    Staged,
    /// The most recent agent edit/write diff in the current TUI history.
    Last,
}

impl DiffSource {
    fn label(self) -> &'static str {
        match self {
            DiffSource::Worktree => "worktree",
            DiffSource::Staged => "staged",
            DiffSource::Last => "last edit",
        }
    }
}

/// Parse the `/diff` argument into a source. Bare or `worktree` →
/// [`DiffSource::Worktree`]; `staged`/`cached` → [`DiffSource::Staged`];
/// `last` → [`DiffSource::Last`]. Unknown args fall back to `Worktree`
/// (defensive: open the pane on the default rather than refusing).
pub fn parse_source_arg(arg: &str) -> DiffSource {
    match arg.trim().to_ascii_lowercase().as_str() {
        "staged" | "cached" => DiffSource::Staged,
        "last" => DiffSource::Last,
        _ => DiffSource::Worktree,
    }
}

/// Change kind of a parsed file section. Drives the file-list glyph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChangeKind {
    Modified,
    Added,
    Deleted,
    Renamed,
    Binary,
}

impl ChangeKind {
    fn glyph(self) -> &'static str {
        match self {
            ChangeKind::Modified => "M",
            ChangeKind::Added => "A",
            ChangeKind::Deleted => "D",
            ChangeKind::Renamed => "R",
            ChangeKind::Binary => "B",
        }
    }
}

/// One diff line, pre-classified at parse time so rendering is a pure
/// format step.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Row {
    Add(String),
    Remove(String),
    Context(String),
    Hunk(String),
    /// A non-line marker (e.g. a truncation notice) shown as muted text.
    Note(String),
}

/// One file's parsed diff section.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileDiff {
    /// Display path (the `b/` side, or the `a/` side for a deletion).
    path: String,
    kind: ChangeKind,
    added: usize,
    removed: usize,
    rows: Vec<Row>,
}

/// What the pane loaded for the active source: a list of parsed files, or an
/// inline state string (error / empty) shown in place of the file list.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Loaded {
    Files(Vec<FileDiff>),
    State(String),
}

pub struct DiffPane {
    /// Sources in `Tab`-cycle order. Always all three.
    sources: Vec<DiffSource>,
    /// Index into `sources` of the active source.
    active: usize,
    /// Parsed content for the active source.
    loaded: Loaded,
    /// File selector cursor and top visible row of the left file-list window.
    file_list: ScrollList,
    /// Vertical scroll of the diff body (in rendered rows).
    scroll: usize,
    /// Wrap toggle (`w`).
    wrap: bool,
    /// Inline vs side-by-side toggle (`s`); seeded from the config
    /// [`DiffStyle`]. Side-by-side still degrades to inline when narrow.
    side_by_side: bool,
    /// Launch cwd — re-read on a `Tab` source switch to a git source.
    cwd: PathBuf,
    /// The most-recent-edit diff parsed once at open, for the `Last` source.
    last: Loaded,
    /// Body height at last render — drives scroll clamping / paging.
    last_body_height: usize,
    /// Body content rows at last render — drives scroll clamping.
    last_content_rows: usize,
}

impl DiffPane {
    /// The which-key descriptor for this pane (`crate::tui::keys_overlay`).
    pub fn keybindings() -> crate::tui::keys_overlay::KeyGroup {
        use crate::tui::keys_overlay::{KeyBinding, KeyGroup};
        KeyGroup {
            title: "Diff",
            bindings: &[
                KeyBinding {
                    key: "↑/↓ j/k",
                    action: "file",
                    desc: "move between changed files",
                },
                KeyBinding {
                    key: "PgUp/PgDn",
                    action: "scroll",
                    desc: "page the selected diff body",
                },
                KeyBinding {
                    key: "Ctrl+U/D",
                    action: "scroll",
                    desc: "page up or down in the selected diff body",
                },
                KeyBinding {
                    key: "g/G",
                    action: "top/bottom",
                    desc: "jump to the top or bottom of the diff body",
                },
                KeyBinding {
                    key: "Tab",
                    action: "source",
                    desc: "cycle worktree, staged, and last edit",
                },
                KeyBinding {
                    key: "w",
                    action: "wrap",
                    desc: "toggle soft wrapping",
                },
                KeyBinding {
                    key: "s",
                    action: "side-by-side",
                    desc: "toggle side-by-side rendering when wide enough",
                },
                KeyBinding {
                    key: "Esc/q",
                    action: "close",
                    desc: "close the diff pane",
                },
            ],
        }
    }

    /// Open the pane on `source`, reading git diffs from `cwd` and, for the
    /// `last` source, the most recent edit/write diff in `history`. Initial
    /// render mode comes from `diff_style`.
    ///
    /// Never fails to open: a git error or non-worktree cwd becomes an
    /// inline [`Loaded::State`] message.
    pub fn open(
        source: DiffSource,
        cwd: &std::path::Path,
        history: &[HistoryEntry],
        diff_style: DiffStyle,
    ) -> Self {
        let last = last_edit_loaded(history);
        let sources = vec![DiffSource::Worktree, DiffSource::Staged, DiffSource::Last];
        let active = sources.iter().position(|s| *s == source).unwrap_or(0);
        let mut pane = Self {
            sources,
            active,
            loaded: Loaded::State(String::new()),
            file_list: ScrollList::new(),
            scroll: 0,
            wrap: false,
            side_by_side: matches!(diff_style, DiffStyle::SideBySide),
            cwd: cwd.to_path_buf(),
            last,
            last_body_height: 0,
            last_content_rows: 0,
        };
        pane.reload_active();
        pane
    }

    /// Handle a key. Returns `true` when the pane should close.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            KeyCode::Char('d') if ctrl => self.page_down(),
            KeyCode::Char('u') if ctrl => self.page_up(),
            KeyCode::Up | KeyCode::Char('k') => self.move_file(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_file(1),
            KeyCode::PageDown => self.page_down(),
            KeyCode::PageUp => self.page_up(),
            KeyCode::Tab => self.cycle_source(),
            KeyCode::Char('w') => self.wrap = !self.wrap,
            KeyCode::Char('s') => self.side_by_side = !self.side_by_side,
            KeyCode::Char('g') => self.scroll = 0,
            KeyCode::Char('G') => self.scroll = self.max_scroll(),
            _ => {}
        }
        false
    }

    fn file_count(&self) -> usize {
        match &self.loaded {
            Loaded::Files(f) => f.len(),
            Loaded::State(_) => 0,
        }
    }

    /// Move the file cursor by `delta` (wrapping), resetting the diff scroll.
    fn move_file(&mut self, delta: i32) {
        let n = self.file_count();
        if n == 0 {
            return;
        }
        self.file_list.move_by(delta as isize, n);
        self.scroll = 0;
    }

    fn max_scroll(&self) -> usize {
        self.last_content_rows.saturating_sub(self.last_body_height)
    }

    fn page_down(&mut self) {
        self.scroll = (self.scroll + self.last_body_height.max(1)).min(self.max_scroll());
    }

    fn page_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(self.last_body_height.max(1));
    }

    /// Mouse-wheel up one row.
    pub fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    /// Mouse-wheel down one row.
    pub fn scroll_down(&mut self) {
        self.scroll = (self.scroll + 1).min(self.max_scroll());
    }

    /// Cycle to the next source and load it.
    fn cycle_source(&mut self) {
        if self.sources.len() <= 1 {
            return;
        }
        self.active = crate::tui::nav::wrap_next(self.active, self.sources.len());
        self.reload_active();
    }

    /// (Re)load the active source.
    fn reload_active(&mut self) {
        let source = self.sources[self.active];
        self.loaded = match source {
            DiffSource::Last => self.last.clone(),
            DiffSource::Worktree => {
                load_git(cockpit_core::git::diff_worktree(&self.cwd), &self.cwd)
            }
            DiffSource::Staged => load_git(cockpit_core::git::diff_staged(&self.cwd), &self.cwd),
        };
        self.file_list.reset();
        self.scroll = 0;
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        let title = self.title();
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let body = layout[0];
        let help_area = layout[1];

        let narrow = body.width < NARROW_FALLBACK_WIDTH;
        let (list_area, diff_area) = if narrow {
            (None, body)
        } else {
            let cols = Layout::horizontal([Constraint::Length(LIST_WIDTH), Constraint::Min(0)])
                .split(body);
            (Some(cols[0]), cols[1])
        };

        if let Some(list_area) = list_area {
            let list_lines =
                self.visible_file_list_lines(list_area.width as usize, list_area.height as usize);
            frame.render_widget(Paragraph::new(list_lines), list_area);
        }

        let diff_lines = self.diff_body_lines(diff_area.width, narrow);
        self.last_content_rows = content_rows_for_scroll(&diff_lines, diff_area.width, self.wrap);
        self.last_body_height = diff_area.height as usize;
        let max_scroll = self.max_scroll();
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }
        let (visible_lines, scroll_y) = if self.wrap {
            (diff_lines, self.scroll.min(u16::MAX as usize) as u16)
        } else {
            (
                diff_lines
                    .into_iter()
                    .skip(self.scroll)
                    .take(diff_area.height as usize)
                    .collect(),
                0,
            )
        };
        let mut para = Paragraph::new(visible_lines).scroll((scroll_y, 0));
        if self.wrap {
            para = para.wrap(ratatui::widgets::Wrap { trim: false });
        }
        frame.render_widget(para, diff_area);

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                help_text(help_area.width).to_string(),
                muted,
            ))),
            help_area,
        );
    }

    /// Title bar: `/diff` + the active source chip.
    fn title(&self) -> Line<'static> {
        Line::from(vec![
            Span::raw(" /diff "),
            Span::styled(
                format!("source: {} ", self.sources[self.active].label()),
                Style::default().fg(Color::Yellow),
            ),
        ])
    }

    /// The left file-list rows (or the inline-state message when no files).
    fn file_list_lines(&self, width: usize) -> Vec<Line<'static>> {
        match &self.loaded {
            Loaded::State(msg) => vec![Line::from(Span::styled(
                msg.clone(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ))],
            Loaded::Files(files) => files
                .iter()
                .enumerate()
                .map(|(i, f)| file_list_row(f, i == self.file_list.cursor(), width))
                .collect(),
        }
    }

    /// Visible left file-list rows, maintaining a scroll window that keeps
    /// the selected file on-screen independently of the diff body scroll.
    fn visible_file_list_lines(&mut self, width: usize, height: usize) -> Vec<Line<'static>> {
        match &self.loaded {
            Loaded::State(_) => {
                self.file_list.set_scroll(0);
                self.file_list_lines(width)
            }
            Loaded::Files(files) => {
                if height == 0 {
                    return Vec::new();
                }
                self.file_list.clamp_windowed(files.len(), height);
                self.file_list_lines(width)
                    .into_iter()
                    .skip(self.file_list.scroll())
                    .take(height)
                    .collect()
            }
        }
    }

    /// The right diff-body rows for the selected file (or the inline-state
    /// message when no files). `narrow` forces inline regardless of `s`.
    fn diff_body_lines(&self, width: u16, narrow: bool) -> Vec<Line<'static>> {
        let files = match &self.loaded {
            Loaded::State(msg) => {
                return vec![Line::from(Span::styled(
                    msg.clone(),
                    Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
                ))];
            }
            Loaded::Files(files) => files,
        };
        let Some(file) = files.get(self.file_list.cursor()) else {
            return vec![Line::from(Span::styled(
                "no file selected".to_string(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ))];
        };

        let mut out = vec![file_header_line(file)];
        if matches!(file.kind, ChangeKind::Binary) {
            out.push(Line::from(Span::styled(
                "  binary file changed".to_string(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            )));
            return out;
        }

        let use_side_by_side = self.side_by_side && !narrow && width >= SIDE_BY_SIDE_MIN_WIDTH;
        if use_side_by_side {
            out.extend(render_rows_side_by_side(&file.rows, width));
        } else {
            out.extend(render_rows_inline(&file.rows));
        }
        out
    }
}

// ---- source loading --------------------------------------------------------

impl Pane for DiffPane {
    type Outcome = bool;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        DiffPane::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        DiffPane::render(self, frame, area);
    }
}

/// Convert a `git diff` result into a `Loaded`: a parsed file list, a
/// "no changes" empty state, or an inline error (e.g. not a git worktree).
fn load_git(result: anyhow::Result<String>, cwd: &std::path::Path) -> Loaded {
    match result {
        Ok(raw) => {
            let files = parse_unified_diff(&raw);
            if files.is_empty() {
                Loaded::State("no changes".to_string())
            } else {
                Loaded::Files(files)
            }
        }
        Err(_) => {
            // Distinguish "not a worktree" from a generic git error so the
            // message is actionable, without surfacing raw git stderr.
            if cockpit_core::git::find_worktree_root(cwd).is_none() {
                Loaded::State("not a git worktree".to_string())
            } else {
                Loaded::State("could not read git diff".to_string())
            }
        }
    }
}

/// Parse the most-recent edit/write diff in `history` into a `Loaded`. Walks
/// from the end for the newest [`HistoryEntry::Diff`], synthesizes a unified
/// diff from its `old`/`new`, and parses that. Empty state when none.
fn last_edit_loaded(history: &[HistoryEntry]) -> Loaded {
    let Some((path, old, new)) = history.iter().rev().find_map(|e| match e {
        HistoryEntry::Diff { path, old, new, .. } => Some((path.clone(), old.clone(), new.clone())),
        _ => None,
    }) else {
        return Loaded::State("no recent edit in this session".to_string());
    };
    let unified = synthesize_unified(&path, &old, &new);
    let files = parse_unified_diff(&unified);
    if files.is_empty() {
        Loaded::State("no changes".to_string())
    } else {
        Loaded::Files(files)
    }
}

/// Build a `git`-style unified diff for one file from `old`/`new` text,
/// reusing [`similar`] (the same crate `crate::tui::diff` diffs with) so the
/// `Last` source parses identically to a git source.
fn synthesize_unified(path: &str, old: &str, new: &str) -> String {
    use similar::TextDiff;
    let diff = TextDiff::from_lines(old, new);
    let body = diff
        .unified_diff()
        .context_radius(3)
        .header(&format!("a/{path}"), &format!("b/{path}"))
        .to_string();
    format!("diff --git a/{path} b/{path}\n{body}")
}

// ---- unified-diff parser ---------------------------------------------------

/// Parse a unified `git diff` into per-file sections. Splits on
/// `diff --git`, classifies add/delete/rename/binary from the file header,
/// and pre-tags every hunk line. Capped per file at [`MAX_FILE_ROWS`].
fn parse_unified_diff(raw: &str) -> Vec<FileDiff> {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut current: Option<FileDiff> = None;
    // `a/` path captured from the `diff --git a/X b/X` line, used as the
    // display path for a pure deletion (whose `+++` side is `/dev/null`).
    let mut header_a: Option<String> = None;

    let flush = |cur: &mut Option<FileDiff>, files: &mut Vec<FileDiff>| {
        if let Some(f) = cur.take() {
            files.push(f);
        }
    };

    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            flush(&mut current, &mut files);
            let (a, b) = parse_diff_git_paths(rest);
            header_a = a.clone();
            current = Some(FileDiff {
                path: b.or(a).unwrap_or_else(|| "(unknown)".to_string()),
                kind: ChangeKind::Modified,
                added: 0,
                removed: 0,
                rows: Vec::new(),
            });
            continue;
        }
        let Some(file) = current.as_mut() else {
            continue; // preamble before the first `diff --git` (rare)
        };

        if line.starts_with("new file mode") {
            file.kind = ChangeKind::Added;
        } else if line.starts_with("deleted file mode") {
            file.kind = ChangeKind::Deleted;
            // A deletion's display path is the `a/` side.
            if let Some(a) = &header_a {
                file.path = a.clone();
            }
        } else if line.starts_with("rename ") {
            file.kind = ChangeKind::Renamed;
        } else if line.starts_with("Binary files") || line.starts_with("GIT binary patch") {
            file.kind = ChangeKind::Binary;
        } else if let Some(p) = line.strip_prefix("+++ ") {
            if let Some(clean) = clean_diff_path(p) {
                file.path = clean;
            }
        } else if let Some(p) = line.strip_prefix("--- ") {
            // Only use the `a/` side as the path for a pure deletion (the
            // `+++` side is `/dev/null` there).
            if matches!(file.kind, ChangeKind::Deleted)
                && let Some(clean) = clean_diff_path(p)
            {
                file.path = clean;
            }
        } else if line.starts_with("@@") {
            push_row(file, Row::Hunk(line.to_string()));
        } else if let Some(rest) = line.strip_prefix('+') {
            file.added += 1;
            push_row(file, Row::Add(rest.to_string()));
        } else if let Some(rest) = line.strip_prefix('-') {
            file.removed += 1;
            push_row(file, Row::Remove(rest.to_string()));
        } else if let Some(rest) = line.strip_prefix(' ') {
            push_row(file, Row::Context(rest.to_string()));
        } else if line == "\\ No newline at end of file" {
            push_row(file, Row::Note(line.to_string()));
        }
        // `index ...`, `mode ...`, `similarity ...` etc. are dropped.
    }
    flush(&mut current, &mut files);
    files
}

/// Push a body row, capping each file at [`MAX_FILE_ROWS`] with a single
/// truncation note so an enormous file body never explodes the render list.
fn push_row(file: &mut FileDiff, row: Row) {
    if file.rows.len() < MAX_FILE_ROWS {
        file.rows.push(row);
    } else if file.rows.len() == MAX_FILE_ROWS {
        file.rows.push(Row::Note(format!(
            "… diff truncated at {MAX_FILE_ROWS} lines (file too large to render)"
        )));
    }
    // Beyond the cap+1, drop silently.
}

/// Extract the `a/` and `b/` paths from a `diff --git a/X b/Y` tail. Handles
/// the common unquoted case; quoted paths (spaces/unicode) fall back to the
/// `+++`/`---` headers, which the parser also reads.
fn parse_diff_git_paths(rest: &str) -> (Option<String>, Option<String>) {
    // Split into the `a/...` and `b/...` halves. The simplest robust split:
    // find " b/" preceded by an "a/..." start.
    if let Some(a_rest) = rest.strip_prefix("a/")
        && let Some(idx) = a_rest.find(" b/")
    {
        let a = a_rest[..idx].to_string();
        let b = a_rest[idx + 3..].to_string();
        return (Some(a), Some(b));
    }
    (None, None)
}

/// Strip the `a/`/`b/` prefix (and a trailing tab + timestamp git may add)
/// from a `+++`/`---` path. `/dev/null` returns `None` (no real path).
fn clean_diff_path(p: &str) -> Option<String> {
    let p = p.split('\t').next().unwrap_or(p).trim();
    if p == "/dev/null" {
        return None;
    }
    let p = p
        .strip_prefix("a/")
        .or_else(|| p.strip_prefix("b/"))
        .unwrap_or(p);
    Some(p.to_string())
}

fn help_text(width: u16) -> &'static str {
    if width < 76 {
        "q quit  ↑/↓ file  Pg/C-u/d scroll  g/G top/bot  Tab src  w wrap  s side"
    } else {
        "q quit  ↑/↓ file  PgUp/PgDn Ctrl+U/D scroll  g/G top/bottom  Tab source  w wrap  s side-by-side"
    }
}

fn content_rows_for_scroll(lines: &[Line<'_>], width: u16, wrap: bool) -> usize {
    if !wrap || width == 0 {
        return lines.len();
    }
    lines
        .iter()
        .map(|line| line_wrapped_rows(line, width))
        .sum()
}

/// Rows one logical line wraps to at `width` (at least one). Mirrors the
/// question dialog's greedy word-wrap accounting closely enough for scroll
/// limits while preserving the actual Paragraph rendering path.
fn line_wrapped_rows(line: &Line<'_>, width: u16) -> usize {
    let width = width as usize;
    if width == 0 {
        return 1;
    }
    let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
    if text.is_empty() {
        return 1;
    }
    let mut rows = 1usize;
    let mut col = 0usize;
    for word in split_keep_spaces(&text) {
        let w = UnicodeWidthStr::width(word.as_str());
        if w > width {
            if col > 0 {
                rows += 1;
            }
            rows += (w - 1) / width;
            col = w % width;
            if col == 0 {
                col = width;
            }
        } else if col + w > width {
            rows += 1;
            col = w;
        } else {
            col += w;
        }
    }
    rows
}

fn split_keep_spaces(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if ch == ' ' {
            cur.push(ch);
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

// ---- rendering helpers -----------------------------------------------------

/// One file-list row: a change glyph, the path (truncated to fit), and the
/// `+N −M` counts. The cursor row is highlighted.
fn file_list_row(file: &FileDiff, selected: bool, width: usize) -> Line<'static> {
    let counts = format!("+{} −{}", file.added, file.removed);
    // Reserve: 2-col marker/glyph + 1 space + counts + 1 space.
    let reserved = 2 + 1 + counts.chars().count() + 1;
    let path_w = width.saturating_sub(reserved).max(4);
    let path = truncate_path(&file.path, path_w);

    let marker = if selected { "▸" } else { " " };
    let path_style = if selected {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    Line::from(vec![
        Span::raw(marker.to_string()),
        Span::styled(
            file.kind.glyph().to_string(),
            Style::default().fg(kind_color(file.kind)),
        ),
        Span::raw(" "),
        Span::styled(path, path_style),
        Span::raw(" "),
        Span::styled(
            counts,
            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
        ),
    ])
}

fn kind_color(kind: ChangeKind) -> Color {
    match kind {
        ChangeKind::Added => COL_ADDED,
        ChangeKind::Deleted => COL_REMOVED,
        ChangeKind::Renamed => COL_HUNK,
        ChangeKind::Modified => Color::Yellow,
        ChangeKind::Binary => Color::Indexed(MUTED_COLOR_INDEX),
    }
}

/// Header row for the selected file's diff body: path + counts.
fn file_header_line(file: &FileDiff) -> Line<'static> {
    Line::from(vec![
        Span::styled(file.path.clone(), Style::default().fg(COL_HUNK)),
        Span::raw(" "),
        Span::styled(
            format!("(+{} −{})", file.added, file.removed),
            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
        ),
    ])
}

/// Inline (unified) render of a file's rows.
fn render_rows_inline(rows: &[Row]) -> Vec<Line<'static>> {
    rows.iter()
        .map(|row| match row {
            Row::Add(s) => styled_line("+ ", s, Style::default().fg(COL_ADDED)),
            Row::Remove(s) => styled_line("- ", s, Style::default().fg(COL_REMOVED)),
            Row::Context(s) => styled_line("  ", s, Style::default()),
            Row::Hunk(s) => Line::from(Span::styled(s.clone(), Style::default().fg(COL_HUNK))),
            Row::Note(s) => Line::from(Span::styled(
                s.clone(),
                Style::default()
                    .fg(Color::Indexed(MUTED_COLOR_INDEX))
                    .add_modifier(Modifier::DIM),
            )),
        })
        .collect()
}

fn styled_line(prefix: &str, value: &str, style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(prefix.to_string(), style),
        Span::styled(value.to_string(), style),
    ])
}

/// Side-by-side render: removes on the left, adds on the right, re-paired
/// within a contiguous remove/add run (matching `crate::tui::diff`).
fn render_rows_side_by_side(rows: &[Row], width: u16) -> Vec<Line<'static>> {
    let col_w = side_col_width(width);
    let mut out = Vec::new();
    let mut left: Vec<String> = Vec::new();
    let mut right: Vec<String> = Vec::new();

    for row in rows {
        match row {
            Row::Remove(s) => left.push(s.clone()),
            Row::Add(s) => right.push(s.clone()),
            Row::Context(s) => {
                flush_side_pair(&mut left, &mut right, col_w, &mut out);
                let t = pad(s, col_w);
                out.push(side_row(t.clone(), None, t, None));
            }
            Row::Hunk(s) => {
                flush_side_pair(&mut left, &mut right, col_w, &mut out);
                out.push(Line::from(Span::styled(
                    s.clone(),
                    Style::default().fg(COL_HUNK),
                )));
            }
            Row::Note(s) => {
                flush_side_pair(&mut left, &mut right, col_w, &mut out);
                out.push(Line::from(Span::styled(
                    s.clone(),
                    Style::default()
                        .fg(Color::Indexed(MUTED_COLOR_INDEX))
                        .add_modifier(Modifier::DIM),
                )));
            }
        }
    }
    flush_side_pair(&mut left, &mut right, col_w, &mut out);
    out
}

fn flush_side_pair(
    left: &mut Vec<String>,
    right: &mut Vec<String>,
    col_w: usize,
    out: &mut Vec<Line<'static>>,
) {
    let n = left.len().max(right.len());
    for i in 0..n {
        let l = left.get(i).cloned();
        let r = right.get(i).cloned();
        let l_text = pad(l.as_deref().unwrap_or(""), col_w);
        let r_text = pad(r.as_deref().unwrap_or(""), col_w);
        let l_style = l.is_some().then(|| Style::default().fg(COL_REMOVED));
        let r_style = r.is_some().then(|| Style::default().fg(COL_ADDED));
        out.push(side_row(l_text, l_style, r_text, r_style));
    }
    left.clear();
    right.clear();
}

fn side_row(left: String, ls: Option<Style>, right: String, rs: Option<Style>) -> Line<'static> {
    Line::from(vec![
        Span::styled(left, ls.unwrap_or_default()),
        Span::styled(
            COL_SEPARATOR.to_string(),
            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
        ),
        Span::styled(right, rs.unwrap_or_default()),
    ])
}

fn side_col_width(width: u16) -> usize {
    let usable = (width as usize).saturating_sub(COL_SEPARATOR.chars().count());
    (usable / 2).max(4)
}

fn pad(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }

    let display_width = UnicodeWidthStr::width(s);
    if display_width <= width {
        let mut out = s.to_string();
        out.push_str(&" ".repeat(width - display_width));
        return out;
    }

    let content_budget = width.saturating_sub(1);
    let mut out = String::new();
    let mut used = 0;
    for ch in s.chars() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + ch_width > content_budget {
            break;
        }
        out.push(ch);
        used += ch_width;
    }
    out.push('…');
    used += UnicodeWidthChar::width('…').unwrap_or(1);
    let pad = width.saturating_sub(used);
    out.push_str(&" ".repeat(pad));
    out
}

fn suffix_within_display_width(s: &str, width: usize) -> &str {
    let mut used = 0;
    for (idx, ch) in s.char_indices().rev() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + ch_width > width {
            let next = idx + ch.len_utf8();
            return &s[next..];
        }
        used += ch_width;
    }
    s
}

/// Truncate a prefix to `width` display cells without splitting a scalar.
fn prefix_within_display_width(s: &str, width: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for ch in s.chars() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + ch_width > width {
            break;
        }
        out.push(ch);
        used += ch_width;
    }
    out
}

/// Truncate a path to `width` cells, keeping the tail (filename) visible
/// with a leading `…` when it overflows.
fn truncate_path(path: &str, width: usize) -> String {
    if UnicodeWidthStr::width(path) <= width {
        return path.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }

    let tail_budget = width - 1;
    let tail = suffix_within_display_width(path, tail_budget);
    let mut out = String::from("…");
    out.push_str(tail);
    if UnicodeWidthStr::width(out.as_str()) > width {
        let tail = prefix_within_display_width(tail, tail_budget);
        format!("…{tail}")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(lines: &[Line<'static>]) -> Vec<String> {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    fn cells(s: &str) -> usize {
        UnicodeWidthStr::width(s)
    }

    fn separator_start_col(line: &Line<'static>) -> Option<usize> {
        let idx = line
            .spans
            .iter()
            .position(|span| span.content.as_ref() == COL_SEPARATOR)?;
        Some(
            line.spans[..idx]
                .iter()
                .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
                .sum(),
        )
    }

    fn press(code: KeyCode) -> KeyEvent {
        use crossterm::event::{KeyEventKind, KeyEventState};
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn ctrl(ch: char) -> KeyEvent {
        use crossterm::event::{KeyEventKind, KeyEventState};
        KeyEvent {
            code: KeyCode::Char(ch),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn source_arg_parsing() {
        assert_eq!(parse_source_arg(""), DiffSource::Worktree);
        assert_eq!(parse_source_arg("worktree"), DiffSource::Worktree);
        assert_eq!(parse_source_arg("  WorkTree "), DiffSource::Worktree);
        assert_eq!(parse_source_arg("staged"), DiffSource::Staged);
        assert_eq!(parse_source_arg("cached"), DiffSource::Staged);
        assert_eq!(parse_source_arg("last"), DiffSource::Last);
        // Unknown falls back to worktree, not a failure.
        assert_eq!(parse_source_arg("nonsense"), DiffSource::Worktree);
    }

    #[test]
    fn pad_ascii_exact_width() {
        let out = pad("ab", 5);
        assert_eq!(out, "ab   ");
        assert_eq!(cells(&out), 5);
    }

    #[test]
    fn pad_cjk_pads_to_exact_cells() {
        let out = pad("界", 5);
        assert_eq!(cells(&out), 5);
        assert_eq!(out, "界   ");
    }

    #[test]
    fn pad_emoji_pads_to_exact_cells() {
        let out = pad("📌x", 6);
        assert_eq!(cells(&out), 6);
    }

    #[test]
    fn pad_truncates_wide_to_budget_with_ellipsis() {
        let out = pad("界界界", 5);
        assert_eq!(cells(&out), 5);
        assert!(out.ends_with('…'), "{out:?}");
        let prefix = out.trim_end_matches('…');
        assert!(cells(prefix) <= 4, "{out:?}");
    }

    #[test]
    fn pad_does_not_split_wide_char() {
        let out = pad("界界界", 4);
        assert_eq!(cells(&out), 4);
        assert!(out.starts_with("界…"), "{out:?}");
        assert!(!out.starts_with("界界…"), "{out:?}");
    }

    #[test]
    fn pad_width_zero_is_empty() {
        assert_eq!(pad("anything", 0), "");
    }

    #[test]
    fn truncate_path_keeps_tail_within_cells() {
        let out = truncate_path("src/界界界/components/文件.rs", 12);
        assert!(out.starts_with('…'), "{out:?}");
        assert!(out.ends_with("文件.rs"), "{out:?}");
        assert!(cells(&out) <= 12, "{out:?} width {}", cells(&out));
    }

    #[test]
    fn truncate_path_short_path_unchanged() {
        assert_eq!(truncate_path("a.rs", 10), "a.rs");
    }

    #[test]
    fn truncate_path_width_one_is_ellipsis() {
        assert_eq!(truncate_path("longpath", 1), "…");
    }

    #[test]
    fn parses_modified_file_into_counts_and_rows() {
        // Built line-by-line so context lines keep their leading space (a `\`
        // string continuation would strip it).
        let raw = [
            "diff --git a/src/foo.rs b/src/foo.rs",
            "index 1111111..2222222 100644",
            "--- a/src/foo.rs",
            "+++ b/src/foo.rs",
            "@@ -1,3 +1,3 @@",
            " alpha",
            "-beta",
            "+BETA",
            " gamma",
        ]
        .join("\n");
        let files = parse_unified_diff(&raw);
        assert_eq!(files.len(), 1);
        let f = &files[0];
        assert_eq!(f.path, "src/foo.rs");
        assert_eq!(f.kind, ChangeKind::Modified);
        assert_eq!(f.added, 1);
        assert_eq!(f.removed, 1);
        // Rows: hunk, context, remove, add, context.
        assert!(matches!(f.rows[0], Row::Hunk(_)));
        assert!(matches!(&f.rows[2], Row::Remove(s) if s == "beta"));
        assert!(matches!(&f.rows[3], Row::Add(s) if s == "BETA"));
    }

    #[test]
    fn parses_added_and_deleted_files() {
        let raw = "diff --git a/new.txt b/new.txt\n\
new file mode 100644\n\
index 0000000..1111111\n\
--- /dev/null\n\
+++ b/new.txt\n\
@@ -0,0 +1,1 @@\n\
+hello\n\
diff --git a/gone.txt b/gone.txt\n\
deleted file mode 100644\n\
index 1111111..0000000\n\
--- a/gone.txt\n\
+++ /dev/null\n\
@@ -1,1 +0,0 @@\n\
-bye\n";
        let files = parse_unified_diff(raw);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].kind, ChangeKind::Added);
        assert_eq!(files[0].path, "new.txt");
        assert_eq!(files[0].added, 1);
        assert_eq!(files[1].kind, ChangeKind::Deleted);
        // Deletion's display path is the `a/` side, not /dev/null.
        assert_eq!(files[1].path, "gone.txt");
        assert_eq!(files[1].removed, 1);
    }

    #[test]
    fn binary_file_is_one_kind_no_body_lines() {
        let raw = "diff --git a/logo.png b/logo.png\n\
index 1111111..2222222 100644\n\
Binary files a/logo.png and b/logo.png differ\n";
        let files = parse_unified_diff(raw);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].kind, ChangeKind::Binary);
        assert!(files[0].rows.is_empty());
    }

    #[test]
    fn empty_diff_parses_to_no_files() {
        assert!(parse_unified_diff("").is_empty());
    }

    #[test]
    fn load_git_maps_empty_to_no_changes_state() {
        let loaded = load_git(Ok(String::new()), std::path::Path::new("."));
        assert_eq!(loaded, Loaded::State("no changes".to_string()));
    }

    #[test]
    fn load_git_error_in_nonexistent_dir_is_not_a_worktree_state() {
        // A path that isn't a git worktree → inline state, never a panic.
        let loaded = load_git(
            Err(anyhow::anyhow!("boom")),
            std::path::Path::new("/nonexistent-xyzzy"),
        );
        assert_eq!(loaded, Loaded::State("not a git worktree".to_string()));
    }

    #[test]
    fn last_source_empty_when_no_diff_in_history() {
        let loaded = last_edit_loaded(&[]);
        assert_eq!(
            loaded,
            Loaded::State("no recent edit in this session".to_string())
        );
    }

    #[test]
    fn last_source_picks_most_recent_diff_entry() {
        let history = vec![
            HistoryEntry::Diff {
                tool: "edit".into(),
                path: "old.rs".into(),
                old: "x\n".into(),
                new: "y\n".into(),
            },
            HistoryEntry::Diff {
                tool: "edit".into(),
                path: "new.rs".into(),
                old: "a\nb\n".into(),
                new: "a\nB\n".into(),
            },
        ];
        let loaded = last_edit_loaded(&history);
        let Loaded::Files(files) = loaded else {
            panic!("expected files");
        };
        assert_eq!(files.len(), 1);
        // Most recent entry wins.
        assert_eq!(files[0].path, "new.rs");
        assert_eq!(files[0].added, 1);
        assert_eq!(files[0].removed, 1);
    }

    #[test]
    fn pane_renders_file_list_and_selected_body() {
        let raw = "diff --git a/a.rs b/a.rs\n\
--- a/a.rs\n\
+++ b/a.rs\n\
@@ -1,1 +1,1 @@\n\
-one\n\
+ONE\n\
diff --git a/b.rs b/b.rs\n\
--- a/b.rs\n\
+++ b/b.rs\n\
@@ -1,1 +1,1 @@\n\
-two\n\
+TWO\n";
        let files = parse_unified_diff(raw);
        let pane = DiffPane {
            sources: vec![DiffSource::Worktree, DiffSource::Staged, DiffSource::Last],
            active: 0,
            loaded: Loaded::Files(files),
            file_list: ScrollList::new(),
            scroll: 0,
            wrap: false,
            side_by_side: false,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::State(String::new()),
            last_body_height: 100,
            last_content_rows: 0,
        };

        // File list shows both files with counts and a cursor marker.
        let list = texts(&pane.file_list_lines(LIST_WIDTH as usize)).join("\n");
        assert!(list.contains("a.rs"), "{list}");
        assert!(list.contains("b.rs"), "{list}");
        assert!(list.contains("+1 −1"), "{list}");
        assert!(list.contains("▸"), "{list}"); // cursor on the first row

        // Diff body shows the first file's header + inline +/- rows.
        let body = texts(&pane.diff_body_lines(120, false)).join("\n");
        assert!(body.contains("a.rs"), "{body}");
        assert!(body.contains("- one"), "{body}");
        assert!(body.contains("+ ONE"), "{body}");
        // Not the second file's content (only the selected file renders).
        assert!(!body.contains("two"), "{body}");
    }

    #[test]
    fn binary_body_shows_one_line() {
        let files = vec![FileDiff {
            path: "logo.png".into(),
            kind: ChangeKind::Binary,
            added: 0,
            removed: 0,
            rows: Vec::new(),
        }];
        let pane = DiffPane {
            sources: vec![DiffSource::Worktree],
            active: 0,
            loaded: Loaded::Files(files),
            file_list: ScrollList::new(),
            scroll: 0,
            wrap: false,
            side_by_side: false,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::State(String::new()),
            last_body_height: 100,
            last_content_rows: 0,
        };
        let body = texts(&pane.diff_body_lines(120, false)).join("\n");
        assert!(body.contains("binary file changed"), "{body}");
    }

    #[test]
    fn empty_state_renders_in_both_panes() {
        let pane = DiffPane {
            sources: vec![DiffSource::Worktree],
            active: 0,
            loaded: Loaded::State("no changes".to_string()),
            file_list: ScrollList::new(),
            scroll: 0,
            wrap: false,
            side_by_side: false,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::State(String::new()),
            last_body_height: 100,
            last_content_rows: 0,
        };
        let list = texts(&pane.file_list_lines(LIST_WIDTH as usize)).join("\n");
        let body = texts(&pane.diff_body_lines(120, false)).join("\n");
        assert!(list.contains("no changes"), "{list}");
        assert!(body.contains("no changes"), "{body}");
    }

    #[test]
    fn side_by_side_uses_separator_when_wide_and_falls_back_when_narrow() {
        let files = parse_unified_diff(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -1,1 +1,1 @@\n-one\n+ONE\n",
        );
        let mut pane = DiffPane {
            sources: vec![DiffSource::Worktree],
            active: 0,
            loaded: Loaded::Files(files),
            file_list: ScrollList::new(),
            scroll: 0,
            wrap: false,
            side_by_side: true,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::State(String::new()),
            last_body_height: 100,
            last_content_rows: 0,
        };
        // Wide + side-by-side toggle on → column separator present.
        let wide = texts(&pane.diff_body_lines(120, false)).join("\n");
        assert!(wide.contains(COL_SEPARATOR.trim()), "{wide}");
        // Narrow forces inline regardless of the toggle.
        let narrow = texts(&pane.diff_body_lines(40, true)).join("\n");
        assert!(narrow.contains("- one"), "{narrow}");
        assert!(narrow.contains("+ ONE"), "{narrow}");
        // Side-by-side still off here so the toggle stays user-controlled.
        pane.side_by_side = false;
        let inline = texts(&pane.diff_body_lines(120, false)).join("\n");
        assert!(inline.contains("- one"), "{inline}");
    }

    #[test]
    fn side_by_side_columns_align_with_wide_chars() {
        let files = parse_unified_diff(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -1,3 +1,3 @@\n 界 context 📌\n-界界界 hello\n+界 world 📌\n ascii context\n",
        );
        let lines = render_rows_side_by_side(&files[0].rows, 80);
        let cols: Vec<usize> = lines.iter().filter_map(separator_start_col).collect();

        assert!(cols.len() >= 3, "expected side-by-side rows: {cols:?}");
        assert!(
            cols.iter().all(|col| *col == cols[0]),
            "separator columns drifted: {cols:?}"
        );
    }

    #[test]
    fn wrapped_content_rows_count_visual_rows() {
        let lines = vec![
            Line::from("short"),
            Line::from("0123456789"),
            Line::from("word word word"),
        ];
        assert_eq!(content_rows_for_scroll(&lines, 5, false), 3);
        assert_eq!(content_rows_for_scroll(&lines, 5, true), 6);
    }

    #[test]
    fn wrapped_scroll_keys_clamp_to_visual_rows() {
        let mut pane = DiffPane {
            sources: vec![DiffSource::Worktree],
            active: 0,
            loaded: Loaded::State("no changes".into()),
            file_list: ScrollList::new(),
            scroll: 0,
            wrap: true,
            side_by_side: false,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::State(String::new()),
            last_body_height: 3,
            last_content_rows: 8,
        };

        assert!(!pane.handle_key(press(KeyCode::PageDown)));
        assert_eq!(pane.scroll, 3);
        assert!(!pane.handle_key(ctrl('d')));
        assert_eq!(pane.scroll, 5, "clamped at visual bottom");
        assert!(!pane.handle_key(ctrl('u')));
        assert_eq!(pane.scroll, 2);
        assert!(!pane.handle_key(press(KeyCode::PageUp)));
        assert_eq!(pane.scroll, 0);
        assert!(!pane.handle_key(press(KeyCode::Char('G'))));
        assert_eq!(pane.scroll, 5);
        assert!(!pane.handle_key(press(KeyCode::Char('g'))));
        assert_eq!(pane.scroll, 0);
    }

    #[test]
    fn render_large_unwrapped_scroll_does_not_wrap_u16_offset() {
        let rows = (0..70_000)
            .map(|i| Row::Context(format!("line {i}")))
            .collect();
        let file = FileDiff {
            path: "big.txt".into(),
            kind: ChangeKind::Modified,
            added: 70_000,
            removed: 0,
            rows,
        };
        let mut pane = DiffPane {
            sources: vec![DiffSource::Worktree],
            active: 0,
            loaded: Loaded::Files(vec![file]),
            file_list: ScrollList::at(0, 0),
            scroll: 65_537,
            wrap: false,
            side_by_side: false,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::State(String::new()),
            last_body_height: 3,
            last_content_rows: 70_001,
        };
        let backend = TestBackend::new(80, 5);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, 80, 5)))
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let rendered = (0..5)
            .map(|y| (0..80).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("line 65536"), "{rendered}");
    }

    #[test]
    fn help_text_and_keybindings_include_scroll_jumps() {
        let wide = help_text(100);
        assert!(wide.contains("Ctrl+U/D"), "{wide}");
        assert!(wide.contains("g/G"), "{wide}");
        let narrow = help_text(40);
        assert!(narrow.contains("C-u/d"), "{narrow}");
        assert!(narrow.contains("g/G"), "{narrow}");

        let group = DiffPane::keybindings();
        let rows = group
            .bindings
            .iter()
            .map(|b| format!("{} {}", b.key, b.action))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(group.title, "Diff");
        assert!(rows.contains("Ctrl+U/D scroll"), "{rows}");
        assert!(rows.contains("g/G top/bottom"), "{rows}");
    }

    fn many_file_diffs(count: usize) -> Vec<FileDiff> {
        (0..count)
            .map(|i| FileDiff {
                path: format!("file-{i}.rs"),
                kind: ChangeKind::Modified,
                added: 1,
                removed: 1,
                rows: Vec::new(),
            })
            .collect()
    }

    #[test]
    fn file_list_window_keeps_down_selection_visible() {
        let mut pane = DiffPane {
            sources: vec![DiffSource::Worktree],
            active: 0,
            loaded: Loaded::Files(many_file_diffs(8)),
            file_list: ScrollList::at(0, 0),
            scroll: 7,
            wrap: false,
            side_by_side: false,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::State(String::new()),
            last_body_height: 10,
            last_content_rows: 20,
        };

        for _ in 0..5 {
            pane.move_file(1);
        }
        let list = texts(&pane.visible_file_list_lines(LIST_WIDTH as usize, 3)).join("\n");
        assert_eq!(pane.file_list.cursor(), 5);
        assert_eq!(pane.file_list.scroll(), 4);
        assert!(list.contains("file-5.rs"), "{list}");
        assert!(!list.contains("file-0.rs"), "{list}");
        assert_eq!(pane.scroll, 0, "body scroll still resets on file change");
    }

    #[test]
    fn file_list_window_keeps_up_selection_visible() {
        let mut pane = DiffPane {
            sources: vec![DiffSource::Worktree],
            active: 0,
            loaded: Loaded::Files(many_file_diffs(8)),
            file_list: ScrollList::at(6, 5),
            scroll: 0,
            wrap: false,
            side_by_side: false,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::State(String::new()),
            last_body_height: 10,
            last_content_rows: 20,
        };

        for _ in 0..4 {
            pane.move_file(-1);
        }
        let list = texts(&pane.visible_file_list_lines(LIST_WIDTH as usize, 3)).join("\n");
        assert_eq!(pane.file_list.cursor(), 2);
        assert_eq!(pane.file_list.scroll(), 1);
        assert!(list.contains("file-2.rs"), "{list}");
        assert!(!list.contains("file-6.rs"), "{list}");
    }

    #[test]
    fn file_list_window_wraps_to_ends() {
        let mut pane = DiffPane {
            sources: vec![DiffSource::Worktree],
            active: 0,
            loaded: Loaded::Files(many_file_diffs(8)),
            file_list: ScrollList::new(),
            scroll: 0,
            wrap: false,
            side_by_side: false,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::State(String::new()),
            last_body_height: 10,
            last_content_rows: 20,
        };

        pane.move_file(-1);
        let bottom = texts(&pane.visible_file_list_lines(LIST_WIDTH as usize, 3)).join("\n");
        assert_eq!(pane.file_list.cursor(), 7);
        assert_eq!(pane.file_list.scroll(), 5);
        assert!(bottom.contains("file-7.rs"), "{bottom}");

        pane.move_file(1);
        let top = texts(&pane.visible_file_list_lines(LIST_WIDTH as usize, 3)).join("\n");
        assert_eq!(pane.file_list.cursor(), 0);
        assert_eq!(pane.file_list.scroll(), 0);
        assert!(top.contains("file-0.rs"), "{top}");
    }

    #[test]
    fn source_cycle_resets_file_list_scroll() {
        let files = many_file_diffs(5);
        let mut pane = DiffPane {
            sources: vec![DiffSource::Last, DiffSource::Last],
            active: 0,
            loaded: Loaded::Files(files.clone()),
            file_list: ScrollList::at(4, 3),
            scroll: 9,
            wrap: false,
            side_by_side: false,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::Files(files),
            last_body_height: 10,
            last_content_rows: 20,
        };

        pane.cycle_source();
        assert_eq!(pane.file_list.cursor(), 0);
        assert_eq!(pane.scroll, 0);
        assert_eq!(pane.file_list.scroll(), 0);
    }

    #[test]
    fn move_file_wraps_and_resets_scroll() {
        let files = parse_unified_diff(
            "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -1,1 +1,1 @@\n-x\n+y\n\
diff --git a/b.rs b/b.rs\n--- a/b.rs\n+++ b/b.rs\n@@ -1,1 +1,1 @@\n-p\n+q\n",
        );
        let mut pane = DiffPane {
            sources: vec![DiffSource::Worktree],
            active: 0,
            loaded: Loaded::Files(files),
            file_list: ScrollList::at(0, 0),
            scroll: 5,
            wrap: false,
            side_by_side: false,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::State(String::new()),
            last_body_height: 10,
            last_content_rows: 0,
        };
        pane.move_file(1);
        assert_eq!(pane.file_list.cursor(), 1);
        assert_eq!(pane.scroll, 0); // selection reset the scroll
        pane.move_file(1); // wrap last → first
        assert_eq!(pane.file_list.cursor(), 0);
    }

    #[test]
    fn esc_and_q_close() {
        use crossterm::event::{KeyEventKind, KeyEventState};
        let mk = |code| KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        };
        let mut pane = DiffPane {
            sources: vec![DiffSource::Worktree],
            active: 0,
            loaded: Loaded::State("no changes".into()),
            file_list: ScrollList::new(),
            scroll: 0,
            wrap: false,
            side_by_side: false,
            cwd: std::path::PathBuf::from("."),
            last: Loaded::State(String::new()),
            last_body_height: 0,
            last_content_rows: 0,
        };
        assert!(pane.handle_key(mk(KeyCode::Esc)));
        assert!(pane.handle_key(mk(KeyCode::Char('q'))));
        // w / s toggles are inert wrt closing.
        assert!(!pane.handle_key(mk(KeyCode::Char('w'))));
        assert!(pane.wrap);
        assert!(!pane.handle_key(mk(KeyCode::Char('s'))));
    }

    #[test]
    fn huge_file_body_is_capped() {
        let mut raw = String::from(
            "diff --git a/big.txt b/big.txt\n--- a/big.txt\n+++ b/big.txt\n@@ -1,1 +1,99999 @@\n",
        );
        for i in 0..(MAX_FILE_ROWS + 50) {
            raw.push_str(&format!("+line {i}\n"));
        }
        let files = parse_unified_diff(&raw);
        assert_eq!(files.len(), 1);
        // Rows are capped at MAX_FILE_ROWS + 1 (the truncation note).
        assert_eq!(files[0].rows.len(), MAX_FILE_ROWS + 1);
        assert!(matches!(files[0].rows.last(), Some(Row::Note(_))));
    }
}
