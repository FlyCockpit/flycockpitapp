//! `/context` — visual context-window usage overlay.
//!
//! A read-only, dismissable overlay (Esc / `q`) that renders a *snapshot*
//! of how the live context window is filled at the moment it is invoked
//! (not live-updating). It shows:
//!
//! 1. A header total — `<used> / <window> (<pct>%)` in compact k-notation.
//! 2. One full-width horizontal bar split into colored segments, each
//!    sized proportionally to a category's share of the *whole window*
//!    (the trailing dim segment is unused budget).
//! 3. A legend — one entry per non-empty category: a colored swatch, the
//!    category name, and its token count.
//!
//! Categories are derived from what cockpit's chat-context accounting
//! actually composes (the same pieces the chrome's context indicator
//! folds in): the base system prompt, the cached system block (GOALS
//! §17g), the injected guidance/memory file, and the conversation
//! messages. Tool schemas / skills / MCP catalog are assembled engine-side
//! and are not part of the TUI's live context snapshot, so they are not
//! invented here.
//!
//! Token counts are cl100k_base (`crate::tokens::count`) — the same
//! fallback the live context indicator uses pre-flight — and the window
//! size is the active model's `context_length` from provider config
//! (`launch.active_model_max_context`), exactly as the chrome's percentage
//! uses. Mirrors [`crate::tui::skills_pane`]'s `open` / `handle_key` /
//! `render` shape; `App` opens it over the chat body and routes
//! input/render the same way.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::tui::theme::{
    CONTEXT_BLOCK_INDEX, CONTEXT_GUIDANCE_INDEX, CONTEXT_MESSAGES_INDEX, CONTEXT_SYSTEM_INDEX,
    MUTED_COLOR_INDEX,
};

/// Solid block glyph for both the bar segments and the legend swatches.
/// The color carries the category identity, not the glyph (per spec).
const BLOCK: char = '█';

/// Minimum interior width we will draw a segmented bar into. Below this
/// the bar degrades to the header + legend only (the bar would be too
/// coarse to be meaningful), so narrow terminals never panic or overflow.
const MIN_BAR_WIDTH: u16 = 8;

/// One context category: a fixed display name, its palette color, and its
/// token count. Free space is represented separately (see [`bar_segments`])
/// because it has no count to show when the window size is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Category {
    pub name: &'static str,
    pub color_index: u8,
    pub tokens: u64,
}

/// Immutable snapshot of the live context composition, gathered by `App`
/// at the instant `/context` is invoked. Pure data so the pane has no
/// dependency on `App` internals and the sizing/formatting stay testable.
#[derive(Debug, Clone)]
pub struct ContextSnapshot {
    /// Per-category token counts, in render order. Zero-token categories
    /// are kept here (they still count toward the total) and filtered out
    /// of the *legend* at render time.
    pub categories: Vec<Category>,
    /// Active model's context window in tokens, or `None` when the model
    /// declares no known limit — in which case the percentage and the
    /// free-space segment are omitted (no faked denominator).
    pub window: Option<u64>,
    /// Provider-reported prompt-cache usage from the last round-trip:
    /// `(cached_input_tokens, hit_rate)`. `None` until the first round-trip
    /// returns cached reads (prompt `prompt-caching-strategy.md`). Rendered
    /// as a separate footer line — never folded into the category totals,
    /// which are the *local* composition, not provider usage.
    pub cache: Option<(u64, Option<f64>)>,
}

impl ContextSnapshot {
    /// Build the standard chat-context snapshot from its component counts.
    /// Categories are listed in the fixed visual order used by both the
    /// bar and the legend.
    pub fn new(
        base_prompt: u64,
        system_block: u64,
        guidance: u64,
        messages: u64,
        window: Option<u32>,
    ) -> Self {
        Self {
            categories: vec![
                Category {
                    name: "system",
                    color_index: CONTEXT_SYSTEM_INDEX,
                    tokens: base_prompt,
                },
                Category {
                    name: "sys block",
                    color_index: CONTEXT_BLOCK_INDEX,
                    tokens: system_block,
                },
                Category {
                    name: "guidance",
                    color_index: CONTEXT_GUIDANCE_INDEX,
                    tokens: guidance,
                },
                Category {
                    name: "messages",
                    color_index: CONTEXT_MESSAGES_INDEX,
                    tokens: messages,
                },
            ],
            window: window.map(u64::from),
            cache: None,
        }
    }

    /// Attach provider-reported cache usage (cached input tokens + hit rate)
    /// from the last round-trip. Builder-style so `new`'s signature stays
    /// stable for the many call sites that don't have usage to attach.
    pub fn with_cache_usage(mut self, cached_input: u64, hit_rate: Option<f64>) -> Self {
        if cached_input > 0 {
            self.cache = Some((cached_input, hit_rate));
        }
        self
    }

    /// Total tokens used across every category (including zero-token ones,
    /// which contribute nothing but are still summed for honesty).
    fn used(&self) -> u64 {
        self.categories.iter().map(|c| c.tokens).sum()
    }
}

pub struct ContextPane {
    snapshot: ContextSnapshot,
}

impl ContextPane {
    /// Open the overlay over `snapshot`. The snapshot is captured once at
    /// open — the overlay is a still frame, not a live meter.
    pub fn open(snapshot: ContextSnapshot) -> Self {
        Self { snapshot }
    }

    /// Handle a key. Returns `true` when the pane should close. Read-only:
    /// only the dismiss keys are live (Esc / `q`), matching the other
    /// informational overlays.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        matches!(key.code, KeyCode::Esc | KeyCode::Char('q'))
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Line::from(" /context "));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        // Body above, single help line pinned at the bottom.
        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let body = layout[0];
        let help_area = layout[1];

        let lines = body_lines(&self.snapshot, body.width);
        frame.render_widget(Paragraph::new(lines), body);

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled("q quit".to_string(), muted))),
            help_area,
        );
    }
}

/// Format a token count in compact k-notation: `< 1000` verbatim, then
/// `N.Nk` up to a million, then `N.NM`. One decimal place above the
/// thousands threshold (`89_200 → "89.2k"`, `1_000_000 → "1M"`,
/// `910_800 → "910.8k"`). A whole-number magnitude drops the `.0`
/// (`1_000_000 → "1M"`, not `"1.0M"`) so the header reads cleanly.
pub fn k_notation(n: u64) -> String {
    if n < 1_000 {
        return n.to_string();
    }
    if n < 1_000_000 {
        let k = n as f64 / 1_000.0;
        if (k.round() - k).abs() < f64::EPSILON && k.fract() == 0.0 {
            format!("{}k", k as u64)
        } else {
            format!("{k:.1}k")
        }
    } else {
        let m = n as f64 / 1_000_000.0;
        if (m.round() - m).abs() < f64::EPSILON && m.fract() == 0.0 {
            format!("{}M", m as u64)
        } else {
            format!("{m:.1}M")
        }
    }
}

/// The header total line: `<used> / <window> (<pct>%)` when the window is
/// known, or just `<used>` (k-notation, `tokens` suffix) when it isn't —
/// in which case there is no honest denominator, so no percentage.
fn header_text(snapshot: &ContextSnapshot) -> String {
    let used = snapshot.used();
    match snapshot.window {
        Some(window) if window > 0 => {
            let pct = (used.saturating_mul(100) / window).min(999);
            format!("{} / {}  ({}%)", k_notation(used), k_notation(window), pct)
        }
        // Unknown (or zero) window: show the absolute used count only,
        // omitting the percentage and the free-space segment.
        _ => format!("{} tokens", k_notation(used)),
    }
}

/// A single drawn bar segment: a width in cells and the color to fill it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub width: u16,
    pub color_index: u8,
}

/// Lay out the colored bar segments for `categories` across a bar of
/// `bar_width` cells, sizing each segment proportionally to its share of
/// `denom` (the window size when known, else the used total) and filling
/// any remainder with a trailing free-space segment colored `free_index`.
///
/// Widths are apportioned by the **largest-remainder method** so they sum
/// to *exactly* `bar_width` — every cell is assigned, with no gap or
/// overflow at the right edge. Each segment's ideal (fractional) width is
/// floored; the leftover cells are then handed out one each to the
/// segments with the largest fractional remainders. Zero-token categories
/// produce zero-width segments (nothing drawn) but are still part of the
/// apportionment input so the math is total-preserving.
///
/// `free_index` of `None` omits the trailing free segment entirely (used
/// for the unknown-window case, where there is no honest free budget).
pub fn bar_segments(
    categories: &[Category],
    denom: u64,
    bar_width: u16,
    free_index: Option<u8>,
) -> Vec<Segment> {
    if bar_width == 0 || denom == 0 {
        return Vec::new();
    }
    let bar_width = bar_width as u64;

    // Build the apportionment input: one weight per category, plus a
    // trailing free-space weight when a free color is supplied and there
    // is unused budget. Each entry carries its color so the output order
    // matches the legend (categories first, free last).
    let used: u64 = categories.iter().map(|c| c.tokens).sum();
    let mut weights: Vec<(u64, u8)> = categories
        .iter()
        .map(|c| (c.tokens, c.color_index))
        .collect();
    if let Some(idx) = free_index {
        let free = denom.saturating_sub(used);
        weights.push((free, idx));
    }

    // Largest-remainder apportionment of `bar_width` cells over the
    // weights, with `denom` as the divisor. `floor(weight * bar / denom)`
    // is the base allocation; the `bar - sum(base)` leftover cells go to
    // the largest fractional remainders, breaking ties by input order.
    let mut base: Vec<u64> = Vec::with_capacity(weights.len());
    let mut remainders: Vec<(u64, usize)> = Vec::with_capacity(weights.len());
    let mut assigned: u64 = 0;
    for (i, (w, _)) in weights.iter().enumerate() {
        let scaled = w.saturating_mul(bar_width);
        let floor = scaled / denom;
        let rem = scaled % denom;
        base.push(floor);
        assigned += floor;
        remainders.push((rem, i));
    }
    // `assigned <= bar_width` because sum(weight) <= denom (used + free =
    // denom when free is present; used <= denom otherwise). Hand the
    // leftover cells to the largest remainders.
    let mut leftover = bar_width.saturating_sub(assigned);
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (_, i) in &remainders {
        if leftover == 0 {
            break;
        }
        base[*i] += 1;
        leftover -= 1;
    }

    weights
        .iter()
        .zip(base)
        .filter(|(_, w)| *w > 0)
        .map(|((_, color), w)| Segment {
            width: w as u16,
            color_index: *color,
        })
        .collect()
}

/// Assemble every body row as owned [`Line`]s: header, blank, bar, blank,
/// then the legend. Pure (no `App`, no terminal) so the layout/edge-case
/// logic is unit-testable. `width` is the interior body width in cells.
fn body_lines(snapshot: &ContextSnapshot, width: u16) -> Vec<Line<'static>> {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let mut out: Vec<Line<'static>> = Vec::new();

    // Header total.
    out.push(Line::from(Span::styled(
        header_text(snapshot),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    out.push(Line::default());

    // The bar. Apportion against the window when known (so unused budget
    // shows as a trailing dim segment); against the used total otherwise
    // (no free segment — the bar is fully colored by category).
    if width >= MIN_BAR_WIDTH {
        let (denom, free_index) = match snapshot.window {
            Some(w) if w > 0 => (w, Some(MUTED_COLOR_INDEX)),
            _ => (snapshot.used(), None),
        };
        let segments = bar_segments(&snapshot.categories, denom, width, free_index);
        let mut spans: Vec<Span<'static>> = Vec::with_capacity(segments.len());
        for seg in segments {
            spans.push(Span::styled(
                BLOCK.to_string().repeat(seg.width as usize),
                Style::default().fg(Color::Indexed(seg.color_index)),
            ));
        }
        if !spans.is_empty() {
            out.push(Line::from(spans));
            out.push(Line::default());
        }
    }

    // Legend — one entry per non-empty category. Zero-token categories are
    // omitted here (kept out of the clutter) though still summed above.
    let nonempty: Vec<&Category> = snapshot
        .categories
        .iter()
        .filter(|c| c.tokens > 0)
        .collect();
    if nonempty.is_empty() {
        out.push(Line::from(Span::styled(
            "context is empty".to_string(),
            muted,
        )));
    } else {
        for c in nonempty {
            out.push(Line::from(vec![
                Span::styled(
                    format!("{BLOCK} "),
                    Style::default().fg(Color::Indexed(c.color_index)),
                ),
                Span::raw(format!("{}  ", c.name)),
                Span::styled(k_notation(c.tokens), muted),
            ]));
        }
    }
    // The free-budget legend row, when a window is known and any is free.
    if let Some(window) = snapshot.window {
        let free = window.saturating_sub(snapshot.used());
        if window > 0 && free > 0 {
            out.push(Line::from(vec![
                Span::styled(format!("{BLOCK} "), muted),
                Span::raw("free  "),
                Span::styled(k_notation(free), muted),
            ]));
        }
    }

    // Provider-reported cache usage from the last round-trip, on its own
    // footer line so it's read as a separate stat, not a context category
    // (prompt `prompt-caching-strategy.md`).
    if let Some((cached, hit_rate)) = snapshot.cache {
        let label = match hit_rate {
            Some(rate) => format!(
                "cached  {} ({}% hit)",
                k_notation(cached),
                (rate * 100.0).round() as u32
            ),
            None => format!("cached  {}", k_notation(cached)),
        };
        out.push(Line::from(Span::styled(label, muted)));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn cat(name: &'static str, tokens: u64) -> Category {
        Category {
            name,
            color_index: 1,
            tokens,
        }
    }

    fn render_text(snapshot: &ContextSnapshot, width: u16) -> String {
        body_lines(snapshot, width)
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

    #[test]
    fn k_notation_formats_compactly() {
        assert_eq!(k_notation(0), "0");
        assert_eq!(k_notation(820), "820");
        assert_eq!(k_notation(999), "999");
        assert_eq!(k_notation(1_000), "1k");
        assert_eq!(k_notation(89_200), "89.2k");
        assert_eq!(k_notation(910_800), "910.8k");
        assert_eq!(k_notation(1_000_000), "1M");
        assert_eq!(k_notation(1_500_000), "1.5M");
    }

    #[test]
    fn header_shows_pct_when_window_known() {
        // 89.2k used of a 1M window → 8%.
        let snap = ContextSnapshot {
            categories: vec![cat("a", 89_200)],
            window: Some(1_000_000),
            cache: None,
        };
        assert_eq!(header_text(&snap), "89.2k / 1M  (8%)");
    }

    #[test]
    fn header_omits_pct_when_window_unknown() {
        let snap = ContextSnapshot {
            categories: vec![cat("a", 17_300), cat("b", 5_000)],
            window: None,
            cache: None,
        };
        // No "/", no "%", just the absolute used total.
        let h = header_text(&snap);
        assert_eq!(h, "22.3k tokens");
        assert!(!h.contains('%'));
        assert!(!h.contains('/'));
    }

    #[test]
    fn bar_segments_sum_to_exact_width() {
        // Lopsided categories + a free remainder, across an awkward width
        // that doesn't divide evenly: every cell must be assigned.
        let cats = vec![cat("a", 17_300), cat("b", 14_000), cat("c", 63_100)];
        for width in [8u16, 13, 20, 37, 80, 200] {
            let segs = bar_segments(&cats, 1_000_000, width, Some(MUTED_COLOR_INDEX));
            let total: u16 = segs.iter().map(|s| s.width).sum();
            assert_eq!(total, width, "width {width} did not fill exactly");
        }
    }

    #[test]
    fn bar_segments_no_overflow_when_fully_used() {
        // used == denom: no free budget; the bar is fully colored by
        // category and still sums to the exact width (no overflow).
        let cats = vec![cat("a", 300), cat("b", 700)];
        let segs = bar_segments(&cats, 1_000, 33, Some(MUTED_COLOR_INDEX));
        let total: u16 = segs.iter().map(|s| s.width).sum();
        assert_eq!(total, 33);
        // No free segment drawn (it would be zero-width and filtered out).
        assert!(segs.iter().all(|s| s.color_index != MUTED_COLOR_INDEX));
    }

    #[test]
    fn unknown_window_omits_free_segment() {
        // No free color → no trailing free segment; the whole bar is
        // apportioned over the used total and sums to the width exactly.
        let cats = vec![cat("a", 100), cat("b", 200), cat("c", 700)];
        let used = 1_000;
        let segs = bar_segments(&cats, used, 40, None);
        let total: u16 = segs.iter().map(|s| s.width).sum();
        assert_eq!(total, 40);
        assert_eq!(segs.len(), 3, "no free segment appended");
    }

    #[test]
    fn zero_token_categories_omitted_from_legend_but_counted() {
        // `empty` has zero tokens: it must not appear in the legend, but
        // the totals are unaffected (it contributes nothing anyway). A
        // non-empty category still renders.
        let snap = ContextSnapshot {
            categories: vec![cat("system", 1_000), cat("empty", 0)],
            window: Some(10_000),
            cache: None,
        };
        let text = render_text(&snap, 60);
        assert!(text.contains("system"));
        assert!(
            !text.contains("empty"),
            "zero-token category leaked into legend"
        );
        // Free budget (9k) is shown as its own legend row.
        assert!(text.contains("free"));
    }

    /// The provider cache usage renders as a separate footer line with the
    /// hit-rate percent, and is absent when no cache reads were attached
    /// (prompt `prompt-caching-strategy.md`).
    #[test]
    fn cached_usage_renders_as_footer_line() {
        let snap = ContextSnapshot {
            categories: vec![cat("messages", 1_000)],
            window: Some(100_000),
            cache: None,
        }
        .with_cache_usage(8_000, Some(0.8));
        let text = render_text(&snap, 60);
        assert!(text.contains("cached"), "cache footer missing: {text}");
        assert!(text.contains("8k"), "cached token count missing: {text}");
        assert!(text.contains("80% hit"), "hit rate missing: {text}");

        // No cache reads → no footer.
        let snap = ContextSnapshot {
            categories: vec![cat("messages", 1_000)],
            window: Some(100_000),
            cache: None,
        }
        .with_cache_usage(0, None);
        assert!(!render_text(&snap, 60).contains("cached"));
    }

    #[test]
    fn no_free_legend_row_when_window_unknown() {
        let snap = ContextSnapshot {
            categories: vec![cat("system", 1_000)],
            window: None,
            cache: None,
        };
        let text = render_text(&snap, 60);
        assert!(text.contains("system"));
        assert!(
            !text.contains("free"),
            "free row shown without a known window"
        );
    }

    #[test]
    fn narrow_terminal_degrades_without_panic() {
        // Below MIN_BAR_WIDTH the bar is dropped but the header + legend
        // still render — and nothing panics.
        let snap = ContextSnapshot {
            categories: vec![cat("system", 1_000)],
            window: Some(10_000),
            cache: None,
        };
        let text = render_text(&snap, 4);
        assert!(text.contains("system"));
    }

    #[test]
    fn esc_and_q_close_the_pane() {
        let snap = ContextSnapshot {
            categories: vec![cat("a", 1)],
            window: Some(10),
            cache: None,
        };
        let mut pane = ContextPane::open(snap.clone());
        assert!(pane.handle_key(press(KeyCode::Esc)));
        let mut pane = ContextPane::open(snap);
        assert!(pane.handle_key(press(KeyCode::Char('q'))));
    }

    #[test]
    fn new_builds_categories_in_fixed_order() {
        let snap = ContextSnapshot::new(100, 50, 25, 200, Some(1_000));
        let names: Vec<&str> = snap.categories.iter().map(|c| c.name).collect();
        assert_eq!(names, ["system", "sys block", "guidance", "messages"]);
        assert_eq!(snap.used(), 375);
        assert_eq!(snap.window, Some(1_000));
    }
}
