//! `/stats` pane (GOALS §15 / §15e).
//!
//! A full-body interactive view over the part-1 roll-up layer
//! ([`cockpit_db::stats::rollup`]). It renders the three §15a sections —
//! token spend per model, tool-call recovery per model, and the
//! language breakdown — with interactive scope (current project / all)
//! and range (7d / all) toggles plus an expandable recovery drilldown.
//!
//! The pane owns no query logic: it opens the session DB read-only
//! ([`Db::open_default`]), runs `rollup`, and re-queries whenever the
//! scope/range toggles change. Stats are local-only (GOALS §15) — the
//! pane reads the DB and sends nothing.
//!
//! Mirrors the [`crate::tui::model_picker`] dialog's shape: a struct
//! with `open` / `handle_key` / `render`, opened over the chat body by
//! `App` and routed input/render like the other full-body overlays.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::tui::pane::{Pane, ScrollList};
use crate::tui::pane_shared::{resolve_project_id, short_id};
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_db::Db;
use cockpit_db::stats::{
    LanguageSection, PriceTable, RecoverySection, StatsRange, StatsRollup, StatsScope, TokenSpend,
};

/// Width (in cells) of the language bar gauge. Hand-rolled `█`/`░`
/// matching the §15e UI sketch; degrades by shortening when the
/// terminal can't fit the full width plus its label.
const BAR_WIDTH: usize = 28;

/// Scope toggle state (GOALS §15a). Maps to [`StatsScope`] at query
/// time; the project arm needs the resolved `project_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeToggle {
    /// Current project (when a `project_id` is available).
    Project,
    /// Every project on this machine.
    All,
}

/// Range toggle state (GOALS §15a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeToggle {
    Last7Days,
    AllTime,
}

impl RangeToggle {
    fn to_range(self) -> StatsRange {
        match self {
            RangeToggle::Last7Days => StatsRange::Last7Days,
            RangeToggle::AllTime => StatsRange::AllTime,
        }
    }

    fn label(self) -> &'static str {
        match self {
            RangeToggle::Last7Days => "7d",
            RangeToggle::AllTime => "all",
        }
    }
}

pub struct StatsPane {
    /// Resolved current-project id, or `None` when the cwd couldn't be
    /// resolved to a project. When `None`, the scope toggle is pinned to
    /// `All` (there's no project to scope to).
    project_id: Option<String>,
    /// Loaded once at open and reloaded only on a toggle change — the
    /// roll-up scan is heavy, so we don't re-run it per frame.
    db: Option<Db>,
    prices: PriceTable,
    scope: ScopeToggle,
    range: RangeToggle,
    /// Latest roll-up, or an error string if the query failed.
    rollup: Result<StatsRollup, String>,
    /// Which recovery `by_model` rows are expanded (drilldown shown).
    /// Indexed by position in `rollup.recovery.by_model`. Reset on a
    /// scope/range change (the model set may differ).
    expanded: Vec<bool>,
    /// Cursor over recovery rows plus vertical body scroll.
    list: ScrollList,
    /// Rendered body height at the last draw — drives scroll clamping.
    last_body_height: usize,
    /// Total rendered body rows at the last draw — drives scroll clamp.
    last_content_rows: usize,
}

impl StatsPane {
    /// Open the pane for `cwd`. Opens the session DB read-only and runs
    /// the first roll-up (current project / 7d by default, per §15a).
    /// DB-open failure is non-fatal — the pane renders an error line
    /// rather than refusing to open, so `/stats` always shows something.
    pub fn open(cwd: &std::path::Path) -> Self {
        let project_id = resolve_project_id(cwd);
        let scope = if project_id.is_some() {
            ScopeToggle::Project
        } else {
            ScopeToggle::All
        };
        let range = RangeToggle::Last7Days;
        let prices = PriceTable::load_default();
        let db = Db::open_default().ok();
        let rollup = run_rollup(db.as_ref(), &project_id, scope, range, &prices);
        let expanded = init_expanded(&rollup);
        Self {
            project_id,
            db,
            prices,
            scope,
            range,
            rollup,
            expanded,
            list: ScrollList::new(),
            last_body_height: 0,
            last_content_rows: 0,
        }
    }

    /// Re-run the roll-up after a scope/range change and reset the
    /// drilldown state (the model set may differ across scopes, so a
    /// stale expand/cursor index would point at the wrong row).
    fn requery(&mut self) {
        self.rollup = run_rollup(
            self.db.as_ref(),
            &self.project_id,
            self.scope,
            self.range,
            &self.prices,
        );
        self.expanded = init_expanded(&self.rollup);
        self.list.reset();
    }

    /// Number of recovery `by_model` rows, used to clamp the cursor.
    fn recovery_rows(&self) -> usize {
        self.rollup
            .as_ref()
            .map(|r| r.recovery.by_model.len())
            .unwrap_or(0)
    }

    /// Handle a key. Returns `true` when the pane should close.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            // Scope toggle — only meaningful when there's a current
            // project to scope to; otherwise inert (pinned to `All`).
            KeyCode::Char('s') if self.project_id.is_some() => {
                self.scope = match self.scope {
                    ScopeToggle::Project => ScopeToggle::All,
                    ScopeToggle::All => ScopeToggle::Project,
                };
                self.requery();
            }
            KeyCode::Char('r') => {
                self.range = match self.range {
                    RangeToggle::Last7Days => RangeToggle::AllTime,
                    RangeToggle::AllTime => RangeToggle::Last7Days,
                };
                self.requery();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let n = self.recovery_rows();
                let prev = self.list.cursor();
                self.list.move_by(-1, n);
                if self.list.cursor() > prev {
                    // Wrapped first → last: jump the body to the bottom so
                    // the now-selected last row is visible.
                    self.list
                        .set_scroll(self.last_content_rows.saturating_sub(self.last_body_height));
                } else {
                    self.ensure_cursor_visible();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = self.recovery_rows();
                let prev = self.list.cursor();
                self.list.move_by(1, n);
                if self.list.cursor() < prev {
                    // Wrapped last → first: jump the body to the top.
                    self.list.set_scroll(0);
                } else {
                    self.ensure_cursor_visible();
                }
            }
            KeyCode::PageUp => {
                self.list.set_scroll(
                    self.list
                        .scroll()
                        .saturating_sub(self.last_body_height.max(1)),
                );
            }
            KeyCode::PageDown => {
                let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
                self.list.set_scroll(
                    (self.list.scroll() + self.last_body_height.max(1)).min(max_scroll),
                );
            }
            KeyCode::Char('g') => self.list.set_scroll(0),
            KeyCode::Char('G') => {
                self.list
                    .set_scroll(self.last_content_rows.saturating_sub(self.last_body_height));
            }
            KeyCode::Enter | KeyCode::Char('e') => {
                // Expand/collapse the recovery row under the cursor.
                if let Some(flag) = self.expanded.get_mut(self.list.cursor()) {
                    *flag = !*flag;
                }
            }
            _ => {}
        }
        false
    }

    /// Scroll the body up by one row (mouse wheel).
    pub fn scroll_up(&mut self) {
        self.list.set_scroll(self.list.scroll().saturating_sub(1));
    }

    /// Scroll the body down by one row (mouse wheel), clamped so the
    /// last row can't scroll above the body floor.
    pub fn scroll_down(&mut self) {
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        self.list
            .set_scroll((self.list.scroll() + 1).min(max_scroll));
    }

    fn ensure_cursor_visible(&mut self) {
        let Some(row) = self.cursor_body_line() else {
            return;
        };
        let height = self.last_body_height.max(1);
        if row < self.list.scroll() {
            self.list.set_scroll(row);
        } else if row >= self.list.scroll() + height {
            self.list.set_scroll(row + 1 - height);
        }
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        self.list.set_scroll(self.list.scroll().min(max_scroll));
    }

    fn cursor_body_line(&self) -> Option<usize> {
        let rollup = self.rollup.as_ref().ok()?;
        if rollup.recovery.by_model.is_empty()
            || self.list.cursor() >= rollup.recovery.by_model.len()
        {
            return None;
        }
        let mut row = section_tokens(&rollup.tokens).len() + 1 + 2;
        for i in 0..self.list.cursor() {
            row += 1;
            if self.expanded.get(i).copied().unwrap_or(false) {
                row +=
                    recovery_drilldown(&rollup.recovery, &rollup.recovery.by_model[i].model).len();
            }
        }
        Some(row)
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        let title = self.title();
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        // Body above, single help line at the bottom.
        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let body = layout[0];
        let help_area = layout[1];

        let lines = self.body_lines(body.width as usize);
        self.last_content_rows = lines.len();
        self.last_body_height = body.height as usize;
        // Clamp scroll to the valid range now that we know the heights.
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        if self.list.scroll() > max_scroll {
            self.list.set_scroll(max_scroll);
        }

        frame.render_widget(
            Paragraph::new(lines).scroll((self.list.scroll() as u16, 0)),
            body,
        );

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "q quit  s scope  r range  ↑/↓ move  e/enter expand  g/G top/bottom".to_string(),
                muted,
            ))),
            help_area,
        );
    }

    /// Title bar: scope + range chips, mirroring the §15e sketch.
    fn title(&self) -> Line<'static> {
        let scope_label = match self.scope {
            ScopeToggle::Project => match &self.project_id {
                Some(id) => format!("project {}", short_id(id)),
                None => "project".to_string(),
            },
            ScopeToggle::All => "all projects".to_string(),
        };
        Line::from(vec![
            Span::raw(" /stats "),
            Span::styled(
                format!("scope: {scope_label} "),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(
                format!("range: {} ", self.range.label()),
                Style::default().fg(Color::Yellow),
            ),
        ])
    }

    /// Assemble every body row as owned [`Line`]s. Pure aside from
    /// reading `self` — the heavy assembly (`section_*`) lives in free
    /// functions so it's unit-testable without an `App`/terminal.
    fn body_lines(&self, width: usize) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();
        match &self.rollup {
            Err(e) => {
                lines.push(Line::from(Span::styled(
                    format!("stats unavailable: {e}"),
                    Style::default().fg(Color::Red),
                )));
            }
            Ok(r) => {
                lines.extend(section_tokens(&r.tokens));
                lines.push(Line::default());
                lines.extend(section_recovery(
                    &r.recovery,
                    &self.expanded,
                    self.list.cursor(),
                ));
                lines.push(Line::default());
                lines.extend(section_language(&r.language, width));
            }
        }
        lines
    }
}

impl Pane for StatsPane {
    type Outcome = bool;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        StatsPane::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        StatsPane::render(self, frame, area);
    }
}

// ---- DB / scope plumbing ---------------------------------------------------

/// Run the roll-up for the current toggles, mapping the toggle state to
/// the part-1 [`StatsScope`] / [`StatsRange`]. Returns the error as a
/// string so the pane can render it inline rather than panicking.
fn run_rollup(
    db: Option<&Db>,
    project_id: &Option<String>,
    scope: ScopeToggle,
    range: RangeToggle,
    prices: &PriceTable,
) -> Result<StatsRollup, String> {
    let Some(db) = db else {
        return Err("could not open the session database".to_string());
    };
    let stats_scope = match scope {
        ScopeToggle::Project => match project_id {
            Some(id) => StatsScope::Project(id.clone()),
            // Defensive: `Project` is never selected without an id, but
            // fall back to `All` rather than failing the query.
            None => StatsScope::All,
        },
        ScopeToggle::All => StatsScope::All,
    };
    let now = chrono::Utc::now().timestamp();
    db.read_blocking(|conn| {
        cockpit_db::stats::rollup(conn, &stats_scope, range.to_range(), prices, false, now)
    })
    .map_err(|e| e.to_string())
}

/// Initial expand flags — all collapsed, one per recovery model row.
fn init_expanded(rollup: &Result<StatsRollup, String>) -> Vec<bool> {
    match rollup {
        Ok(r) => vec![false; r.recovery.by_model.len()],
        Err(_) => Vec::new(),
    }
}

// ---- section renderers (pure) ----------------------------------------------

/// Section 1 — token spend per model (GOALS §15a.1). One header row +
/// one row per model; `(no data)` when empty.
fn section_tokens(t: &TokenSpend) -> Vec<Line<'static>> {
    let mut out = vec![section_header("Token spend")];
    if t.by_model.is_empty() {
        out.push(no_data());
        return out;
    }
    let header = [
        "Model",
        "In",
        "Out",
        "Cached",
        "CacheCreate",
        "Total",
        "Cost",
    ];
    let mut rows: Vec<Vec<String>> = Vec::new();
    for m in &t.by_model {
        rows.push(vec![
            m.model.clone(),
            fmt_count(m.input_tokens),
            fmt_count(m.output_tokens),
            fmt_count(m.cached_input_tokens),
            fmt_count(m.cache_creation_input_tokens),
            fmt_count(m.total_tokens),
            fmt_cost(m.cost_usd),
        ]);
    }
    out.extend(aligned_table(&header, &rows));
    out
}

/// Section 2 — tool-call recovery per model (GOALS §15a.2). Each model
/// is a summary row; the cursor row is marked, and expanded rows show
/// the per-tool and per-(kind, stage) breakdowns underneath.
fn section_recovery(rec: &RecoverySection, expanded: &[bool], cursor: usize) -> Vec<Line<'static>> {
    let mut out = vec![section_header("Tool-call recovery")];
    if rec.by_model.is_empty() {
        out.push(no_data());
        return out;
    }
    // Build the aligned summary rows, then interleave the drilldown
    // after each model the user expanded.
    let header = ["Model", "Calls", "Malformed%", "Recovered%", "Hard-fail%"];
    let mut rows: Vec<Vec<String>> = Vec::new();
    for m in &rec.by_model {
        rows.push(vec![
            m.model.clone(),
            m.calls.to_string(),
            fmt_pct(m.malformed_pct),
            fmt_pct(m.recovered_pct),
            fmt_pct(m.hard_fail_pct),
        ]);
    }
    let widths = column_widths(&header, &rows);
    // Header (indented two cols to align with the marker gutter).
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    out.push(Line::from(Span::styled(
        format!("  {}", join_row(&header_strings(&header), &widths)),
        muted.add_modifier(Modifier::BOLD),
    )));
    for (i, m) in rec.by_model.iter().enumerate() {
        let is_cursor = i == cursor;
        let is_expanded = expanded.get(i).copied().unwrap_or(false);
        let marker = if is_expanded {
            "▾ "
        } else if is_cursor {
            "▸ "
        } else {
            "  "
        };
        let row_style = if is_cursor {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        out.push(Line::from(vec![
            Span::raw(marker.to_string()),
            Span::styled(join_row(&rows[i], &widths), row_style),
        ]));
        if is_expanded {
            out.extend(recovery_drilldown(rec, &m.model));
        }
    }
    out
}

/// Per-tool and per-(kind, stage) breakdown for one model — the
/// expand-on-Enter detail (GOALS §15a.2). Both come pre-aggregated from
/// the roll-up layer; this only filters to `model` and formats.
fn recovery_drilldown(rec: &RecoverySection, model: &str) -> Vec<Line<'static>> {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let mut out: Vec<Line<'static>> = Vec::new();

    let tools: Vec<_> = rec.by_tool.iter().filter(|t| t.model == model).collect();
    if !tools.is_empty() {
        out.push(Line::from(Span::styled(
            "      by tool".to_string(),
            muted.add_modifier(Modifier::ITALIC),
        )));
        for t in tools {
            out.push(Line::from(Span::styled(
                format!(
                    "        {}  {} calls, {} recovered, {} hard-fail",
                    t.tool, t.calls, t.recovered, t.hard_fail
                ),
                muted,
            )));
        }
    }

    let stages: Vec<_> = rec.by_stage.iter().filter(|s| s.model == model).collect();
    if !stages.is_empty() {
        out.push(Line::from(Span::styled(
            "      by kind / stage".to_string(),
            muted.add_modifier(Modifier::ITALIC),
        )));
        for s in stages {
            out.push(Line::from(Span::styled(
                format!(
                    "        {}  {} calls",
                    stage_label(&s.recovery_kind, &s.recovery_stage),
                    s.count
                ),
                muted,
            )));
        }
    }

    if out.is_empty() {
        out.push(Line::from(Span::styled(
            "      (no malformed calls)".to_string(),
            muted.add_modifier(Modifier::ITALIC),
        )));
    }
    out
}

/// Section 3 — language breakdown as a horizontal bar chart (GOALS
/// §15a.3 / §15e): top-8 + `Other`, then non-file activity on its own
/// line below the bars.
fn section_language(lang: &LanguageSection, width: usize) -> Vec<Line<'static>> {
    let mut out = vec![section_header("Language (file-touching tool calls)")];
    if lang.languages.is_empty() {
        out.push(no_data());
    } else {
        // Shrink the bar if the terminal is narrow: reserve room for the
        // 2-col indent, a space, the longest label + pct + count tail.
        let label_w = lang
            .languages
            .iter()
            .map(|l| l.language.chars().count())
            .max()
            .unwrap_or(0);
        let tail = label_w + 22; // "  <label>  99.9%  9999 calls"
        let bar_w = scaled_bar_width(width, tail);
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        for l in &lang.languages {
            let bar = render_bar(l.pct, bar_w);
            out.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(bar, Style::default().fg(Color::Cyan)),
                Span::raw("  "),
                Span::styled(
                    format!("{:<label_w$}", l.language),
                    Style::default().fg(Color::White),
                ),
                Span::raw("  "),
                Span::styled(format!("{:>5}", fmt_pct(l.pct)), muted),
                Span::raw("  "),
                Span::styled(format!("{} calls", l.calls), muted),
            ]));
        }
    }
    // Non-file activity is reported separately, never as a language bar.
    if !lang.non_file.is_empty() {
        let parts: Vec<String> = lang
            .non_file
            .iter()
            .map(|n| format!("{} {}", n.calls, n.tool))
            .collect();
        out.push(Line::default());
        out.push(Line::from(Span::styled(
            format!("  Non-file activity: {}", parts.join(" / ")),
            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
        )));
    }
    out
}

// ---- small pure helpers ----------------------------------------------------

fn section_header(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        title.to_string(),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ))
}

fn no_data() -> Line<'static> {
    Line::from(Span::styled(
        "  (no data)".to_string(),
        Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
    ))
}

/// Build an aligned table (header + rows) as muted-header / white-row
/// [`Line`]s, indented two columns to match the section bodies.
fn aligned_table(header: &[&str], rows: &[Vec<String>]) -> Vec<Line<'static>> {
    let widths = column_widths(header, rows);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let mut out = vec![Line::from(Span::styled(
        format!("  {}", join_row(&header_strings(header), &widths)),
        muted.add_modifier(Modifier::BOLD),
    ))];
    for row in rows {
        out.push(Line::from(Span::styled(
            format!("  {}", join_row(row, &widths)),
            Style::default().fg(Color::White),
        )));
    }
    out
}

fn header_strings(header: &[&str]) -> Vec<String> {
    header.iter().map(|h| h.to_string()).collect()
}

/// Per-column width = max of the header and every cell in that column.
fn column_widths(header: &[&str], rows: &[Vec<String>]) -> Vec<usize> {
    let cols = header.len();
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    widths
}

/// Join one row's cells into a left-aligned, two-space-separated string
/// (the last column isn't padded so trailing whitespace stays minimal).
fn join_row(cells: &[String], widths: &[usize]) -> String {
    let cols = widths.len();
    let mut s = String::new();
    for (i, cell) in cells.iter().enumerate().take(cols) {
        if i > 0 {
            s.push_str("  ");
        }
        if i + 1 == cols {
            s.push_str(cell);
        } else {
            let pad = widths[i].saturating_sub(cell.chars().count());
            s.push_str(cell);
            s.push_str(&" ".repeat(pad));
        }
    }
    s
}

/// Horizontal bar gauge for a 0..100 percentage. `█` for the filled
/// portion, `░` for the rest — matching the §15e UI sketch. Rounds to
/// the nearest cell and clamps into `[0, width]`.
fn render_bar(pct: f64, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let frac = (pct / 100.0).clamp(0.0, 1.0);
    let filled = (frac * width as f64).round() as usize;
    let filled = filled.min(width);
    let mut s = String::with_capacity(width);
    s.push_str(&"█".repeat(filled));
    s.push_str(&"░".repeat(width - filled));
    s
}

/// Bar width for the available terminal width, leaving `tail` columns
/// for the label/pct/count after the bar. Clamps to `[6, BAR_WIDTH]` so
/// the bar stays legible but never overflows a narrow terminal.
fn scaled_bar_width(term_width: usize, tail: usize) -> usize {
    let budget = term_width.saturating_sub(tail);
    budget.clamp(6, BAR_WIDTH).min(term_width.max(1))
}

/// `kind / stage` label, or just `kind` for the synthetic `hard_fail`
/// row (which carries an empty stage). Mirrors the §15e drilldown.
fn stage_label(kind: &str, stage: &str) -> String {
    if stage.is_empty() {
        kind.to_string()
    } else {
        format!("{kind} / {stage}")
    }
}

/// Human-readable token count: `1.2K`, `3.4M`, or the raw number below
/// 1000. Matches the CLI mirror's `fmt_count`.
fn fmt_count(n: i64) -> String {
    let n_abs = n.unsigned_abs();
    if n_abs >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n_abs >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn fmt_pct(p: f64) -> String {
    format!("{p:.1}%")
}

/// Cost: `$0.92`, or the em-dash when the model has no price row
/// (GOALS §15d).
fn fmt_cost(c: Option<f64>) -> String {
    match c {
        Some(v) => format!("${v:.2}"),
        None => "—".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_db::stats::{
        LanguageRow, NonFileRow, RecoveryRow, RecoveryStageRow, RecoveryToolRow,
    };
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    /// Build a pane with a fixed rollup and no DB (so toggles don't
    /// re-query) — exercises the assembly + expand-state logic only.
    fn pane_with(rollup: StatsRollup) -> StatsPane {
        let expanded = vec![false; rollup.recovery.by_model.len()];
        StatsPane {
            project_id: Some("abcdef1234".into()),
            db: None,
            prices: PriceTable::empty(),
            scope: ScopeToggle::Project,
            range: RangeToggle::Last7Days,
            rollup: Ok(rollup),
            expanded,
            list: ScrollList::new(),
            last_body_height: 100,
            last_content_rows: 0,
        }
    }

    fn empty_rollup() -> StatsRollup {
        StatsRollup {
            project_id: Some("p".into()),
            range: "7d".into(),
            tokens: TokenSpend {
                by_model: Vec::new(),
                by_role: None,
            },
            recovery: RecoverySection {
                by_model: Vec::new(),
                by_tool: Vec::new(),
                by_stage: Vec::new(),
            },
            language: LanguageSection {
                languages: Vec::new(),
                total_file_calls: 0,
                non_file: Vec::new(),
            },
        }
    }

    #[test]
    fn bar_fills_proportionally() {
        // Empty/half/full + clamping past the ends.
        assert_eq!(render_bar(0.0, 10), "░".repeat(10));
        assert_eq!(render_bar(100.0, 10), "█".repeat(10));
        let half = render_bar(50.0, 10);
        assert_eq!(half.chars().filter(|c| *c == '█').count(), 5);
        assert_eq!(half.chars().count(), 10);
        // Over-100 clamps to full, negative clamps to empty.
        assert_eq!(render_bar(250.0, 8), "█".repeat(8));
        assert_eq!(render_bar(-5.0, 8), "░".repeat(8));
        // Zero-width never panics.
        assert_eq!(render_bar(50.0, 0), "");
    }

    #[test]
    fn bar_width_degrades_on_narrow_terminals() {
        // Wide terminal → full width; narrow → floor at 6; never wider
        // than the full width.
        assert_eq!(scaled_bar_width(120, 30), BAR_WIDTH);
        assert_eq!(scaled_bar_width(20, 30), 6); // budget underflows → floor
        assert!(scaled_bar_width(40, 30) <= BAR_WIDTH);
    }

    #[test]
    fn fmt_helpers_match_cli() {
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_500), "1.5K");
        assert_eq!(fmt_count(2_000_000), "2.0M");
        assert_eq!(fmt_cost(None), "—");
        assert_eq!(fmt_cost(Some(0.923)), "$0.92");
        assert_eq!(stage_label("hard_fail", ""), "hard_fail");
        assert_eq!(
            stage_label("shape_repair", "wrap_bare_string"),
            "shape_repair / wrap_bare_string"
        );
    }

    #[test]
    fn empty_sections_render_no_data_not_blank() {
        let pane = pane_with(empty_rollup());
        let lines = pane.body_lines(80);
        let text: Vec<String> = lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        let joined = text.join("\n");
        // Each section present with a "(no data)" line rather than an
        // error or a blank screen.
        assert!(joined.contains("Token spend"));
        assert!(joined.contains("Tool-call recovery"));
        assert!(joined.contains("Language"));
        assert_eq!(joined.matches("(no data)").count(), 3);
    }

    #[test]
    fn enter_toggles_drilldown_for_cursor_row() {
        let mut rollup = empty_rollup();
        rollup.recovery.by_model = vec![
            RecoveryRow {
                model: "qwen".into(),
                calls: 10,
                recovered: 2,
                hard_fail: 1,
                malformed_pct: 30.0,
                recovered_pct: 20.0,
                hard_fail_pct: 10.0,
            },
            RecoveryRow {
                model: "opus".into(),
                calls: 5,
                recovered: 0,
                hard_fail: 0,
                malformed_pct: 0.0,
                recovered_pct: 0.0,
                hard_fail_pct: 0.0,
            },
        ];
        rollup.recovery.by_tool = vec![RecoveryToolRow {
            model: "qwen".into(),
            tool: "editunlock".into(),
            calls: 2,
            recovered: 2,
            hard_fail: 0,
        }];
        rollup.recovery.by_stage = vec![RecoveryStageRow {
            model: "qwen".into(),
            recovery_kind: "shape_repair".into(),
            recovery_stage: "wrap_bare_string".into(),
            count: 2,
        }];
        let mut pane = pane_with(rollup);

        // Collapsed: drilldown rows absent.
        let collapsed = render_text(&pane, 80);
        assert!(!collapsed.contains("by tool"));
        assert!(!collapsed.contains("editunlock"));

        // Enter on the cursor row (index 0 = qwen) expands it.
        assert!(!pane.handle_key(press(KeyCode::Enter)));
        assert!(pane.expanded[0]);
        let expanded = render_text(&pane, 80);
        assert!(expanded.contains("by tool"));
        assert!(expanded.contains("editunlock"));
        assert!(expanded.contains("shape_repair / wrap_bare_string"));

        // Enter again collapses.
        assert!(!pane.handle_key(press(KeyCode::Enter)));
        assert!(!pane.expanded[0]);
    }

    #[test]
    fn cursor_moves_and_wraps() {
        let mut rollup = empty_rollup();
        rollup.recovery.by_model = vec![
            RecoveryRow {
                model: "a".into(),
                calls: 1,
                recovered: 0,
                hard_fail: 0,
                malformed_pct: 0.0,
                recovered_pct: 0.0,
                hard_fail_pct: 0.0,
            },
            RecoveryRow {
                model: "b".into(),
                calls: 1,
                recovered: 0,
                hard_fail: 0,
                malformed_pct: 0.0,
                recovered_pct: 0.0,
                hard_fail_pct: 0.0,
            },
        ];
        let mut pane = pane_with(rollup);
        assert_eq!(pane.list.cursor(), 0);
        pane.handle_key(press(KeyCode::Down));
        assert_eq!(pane.list.cursor(), 1);
        // Wrap last → first.
        pane.handle_key(press(KeyCode::Down));
        assert_eq!(pane.list.cursor(), 0);
        // Wrap first → last.
        pane.handle_key(press(KeyCode::Up));
        assert_eq!(pane.list.cursor(), 1);
        pane.handle_key(press(KeyCode::Up));
        assert_eq!(pane.list.cursor(), 0);
    }

    #[test]
    fn cursor_follow_accounts_for_expanded_variable_height_rows() {
        let mut rollup = empty_rollup();
        rollup.tokens.by_model = vec![cockpit_db::stats::TokenRow {
            model: "tok".into(),
            provider: "p".into(),
            input_tokens: 1,
            output_tokens: 1,
            cached_input_tokens: 0,
            cache_creation_input_tokens: 0,
            total_tokens: 2,
            calls: 1,
            cost_usd: None,
        }];
        rollup.recovery.by_model = vec![
            RecoveryRow {
                model: "a".into(),
                calls: 1,
                recovered: 0,
                hard_fail: 0,
                malformed_pct: 0.0,
                recovered_pct: 0.0,
                hard_fail_pct: 0.0,
            },
            RecoveryRow {
                model: "b".into(),
                calls: 1,
                recovered: 0,
                hard_fail: 0,
                malformed_pct: 0.0,
                recovered_pct: 0.0,
                hard_fail_pct: 0.0,
            },
        ];
        rollup.recovery.by_tool = vec![RecoveryToolRow {
            model: "a".into(),
            tool: "edit".into(),
            calls: 1,
            recovered: 0,
            hard_fail: 0,
        }];
        rollup.recovery.by_stage = vec![RecoveryStageRow {
            model: "a".into(),
            recovery_kind: "shape".into(),
            recovery_stage: "wrap".into(),
            count: 1,
        }];
        let mut pane = pane_with(rollup);
        pane.expanded[0] = true;
        pane.last_body_height = 3;
        pane.last_content_rows = pane.body_lines(80).len();

        pane.handle_key(press(KeyCode::Down));

        let selected = pane.cursor_body_line().unwrap();
        assert!(
            selected >= pane.list.scroll(),
            "selected={selected} scroll={}",
            pane.list.scroll()
        );
        assert!(
            selected < pane.list.scroll() + pane.last_body_height,
            "selected={selected} scroll={}",
            pane.list.scroll()
        );
    }

    #[test]
    fn esc_and_q_close_the_pane() {
        let mut pane = pane_with(empty_rollup());
        assert!(pane.handle_key(press(KeyCode::Esc)));
        let mut pane = pane_with(empty_rollup());
        assert!(pane.handle_key(press(KeyCode::Char('q'))));
    }

    #[test]
    fn scope_pinned_to_all_without_a_project() {
        // No project id and no DB: scope starts All and `s` is inert
        // (no project to scope to), so it never flips to Project.
        let mut pane = pane_with(empty_rollup());
        pane.project_id = None;
        pane.scope = ScopeToggle::All;
        pane.handle_key(press(KeyCode::Char('s')));
        assert_eq!(pane.scope, ScopeToggle::All);
    }

    #[test]
    fn language_section_separates_non_file_activity() {
        let mut rollup = empty_rollup();
        rollup.language.languages = vec![
            LanguageRow {
                language: "Rust".into(),
                calls: 189,
                pct: 45.2,
            },
            LanguageRow {
                language: "Other".into(),
                calls: 43,
                pct: 10.4,
            },
        ];
        rollup.language.non_file = vec![
            NonFileRow {
                tool: "bash".into(),
                calls: 412,
            },
            NonFileRow {
                tool: "search".into(),
                calls: 76,
            },
        ];
        let pane = pane_with(rollup);
        let text = render_text(&pane, 100);
        // Languages render as bars; non-file is a separate line, never a
        // bar row.
        assert!(text.contains("Rust"));
        assert!(text.contains("█") || text.contains("░"));
        assert!(text.contains("Non-file activity: 412 bash / 76 search"));
        // "bash" never appears as a language bar row (only in the
        // non-file line).
        let bar_lines: Vec<&str> = text
            .lines()
            .filter(|l| l.contains('█') || l.contains('░'))
            .collect();
        assert!(bar_lines.iter().all(|l| !l.contains("bash")));
    }

    fn render_text(pane: &StatsPane, width: usize) -> String {
        pane.body_lines(width)
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
