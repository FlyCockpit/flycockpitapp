//! Shared TUI chrome: excoc form helpers, borders, scrollbars, and additive
//! status-line indicators.
//!
//! The fixed path/git chrome and the async-schedule strip moved to the
//! three-row chat header (`crate::tui::chat_header`); agent/model/sandbox
//! pickers live on the composer bottom-border deck. This module keeps the
//! additive transient indicators (longcache, caffeination, lock wait, …).

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, HighlightSpacing, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};

use crate::tui::theme::{
    BRASS, BRASS_INDEX, GOOD, GOOD_INDEX, HOVER_BG, HOVER_BG_INDEX, NIGHT, NIGHT_INDEX,
    resolve_color,
};

#[cfg(feature = "remote")]
use crate::tui::theme::PLAN_YELLOW;
use crate::tui::theme::{MUTED_COLOR_INDEX, WARNING_TEXT};
#[cfg(feature = "remote")]
use cockpit_proto::{ConnectorDisclosure, OrgSyncDisclosure};

/// Which edge of the anchor a popover prefers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopoverSide {
    Above,
    Below,
    Center,
}

/// The single excoc hover rule: brass foreground on the hover wash, bold.
/// Both colours resolve through the terminal's colour capability
/// (`theme::resolve_color`), so a non-truecolor terminal sees the indexed
/// fallbacks.
pub fn chip_style(base: Style, hovered: bool) -> Style {
    if hovered {
        base.bg(resolve_color(HOVER_BG, HOVER_BG_INDEX))
            .fg(resolve_color(BRASS, BRASS_INDEX))
            .add_modifier(Modifier::BOLD)
    } else {
        base
    }
}

/// Paint a one-line chip label inside `rect`, applying [`chip_style`] on hover.
pub fn paint_chip(frame: &mut Frame, rect: Rect, label: &str, base: Style, hovered: bool) {
    if rect.width == 0 || rect.height == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            truncate(label, usize::from(rect.width)),
            chip_style(base, hovered),
        ))),
        rect,
    );
}

/// Replace every cell in `rect` with a space on `color`, so prior glyphs
/// cannot leak through the gaps.
pub fn clear_cells(frame: &mut Frame, rect: Rect, color: Color) {
    let buf = frame.buffer_mut();
    for y in rect.y..rect.bottom() {
        for x in rect.x..rect.right() {
            let cell = &mut buf[(x, y)];
            cell.set_symbol(" ");
            cell.set_fg(color);
            cell.set_bg(color);
        }
    }
}

/// Wash `rect` with a solid background colour, leaving glyphs to whatever is
/// painted on top.
pub fn fill_bg(frame: &mut Frame, rect: Rect, color: Color) {
    let buf = frame.buffer_mut();
    for y in rect.y..rect.bottom() {
        for x in rect.x..rect.right() {
            buf[(x, y)].set_bg(color);
        }
    }
}

fn cols(text: &str) -> u16 {
    Line::from(text).width() as u16
}

/// Sum of label widths plus one-column gaps between them.
pub fn cluster_width(labels: &[String]) -> u16 {
    if labels.is_empty() {
        return 0;
    }
    labels.iter().map(|label| cols(label)).sum::<u16>() + (labels.len() as u16 - 1)
}

/// Rounded block whose border and title share one colour: brass when
/// focused, night when idle. The border colour resolves through the
/// terminal's colour capability.
pub fn rounded_block(title: impl Into<Line<'static>>, focused: bool) -> Block<'static> {
    let border = if focused { BRASS } else { NIGHT };
    let border_index = if focused { BRASS_INDEX } else { NIGHT_INDEX };
    let style = Style::default().fg(resolve_color(border, border_index));
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(style)
        .title(title)
        .title_style(style)
}

/// Success-tinted rounded block (border + title share [`GOOD`]).
pub fn rounded_block_success(title: impl Into<Line<'static>>) -> Block<'static> {
    let style = Style::default().fg(resolve_color(GOOD, GOOD_INDEX));
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(style)
        .title(title)
        .title_style(style)
}

/// `area` with the rightmost column permanently reserved for the scrollbar
/// track — the layout invariant that keeps text from reflowing as the
/// thumb appears and disappears (the reference reserves it in the caller,
/// `render.rs:970-975`). Lay text out in this rect; the track owns the
/// column that is left over.
pub fn scrollbar_content(area: Rect) -> Rect {
    Rect {
        width: area.width.saturating_sub(1),
        ..area
    }
}

/// Vertical scrollbar on the right edge of `area`, with the reference's
/// layout invariant: the rightmost column is **permanently reserved** for
/// the track (via [`scrollbar_content`]), so text never reflows when the
/// thumb appears or disappears.
///
/// Content length is the number of scroll positions (`max_scroll + 1`),
/// not the line count. The track and thumb paint only when there is
/// something to scroll (`total > view`); the column stays reserved either
/// way. Returns the content rect; [`scrollbar_track`] gives the drag
/// target while a thumb is shown. Track and thumb colours resolve through
/// the terminal's colour capability.
pub fn scrollbar(frame: &mut Frame, area: Rect, total: usize, view: usize, offset: usize) -> Rect {
    let content = scrollbar_content(area);
    if total <= view || area.width == 0 || area.height == 0 {
        return content;
    }
    let max_scroll = total.saturating_sub(view);
    let scroll = offset.min(max_scroll);
    let mut state = ScrollbarState::new(max_scroll + 1)
        .position(scroll)
        .viewport_content_length(view);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .track_symbol(Some("│"))
        .thumb_symbol("█")
        .track_style(Style::default().fg(resolve_color(NIGHT, NIGHT_INDEX)))
        .thumb_style(Style::default().fg(resolve_color(BRASS, BRASS_INDEX)));
    frame.render_stateful_widget(scrollbar, area, &mut state);
    content
}

/// The rightmost column of `area` — the only place a vertical scrollbar
/// should accept a click-drag.
pub fn scrollbar_track(area: Rect) -> Rect {
    Rect {
        x: area.right().saturating_sub(1),
        y: area.y,
        width: 1,
        height: area.height,
    }
}

/// Sit a popup on `anchor`: composer pickers open upward and left-align;
/// activity-bar menus open downward and right-align to the pill, then clamp
/// to `screen` so a right-edge pill does not clip.
pub fn place_popover(
    anchor: Rect,
    width: u16,
    height: u16,
    screen: Rect,
    side: PopoverSide,
) -> Rect {
    let width = width.min(screen.width).max(1);
    let height = height.min(screen.height).max(1);
    let mut x = match side {
        PopoverSide::Above => anchor.x,
        PopoverSide::Below => anchor.right().saturating_sub(width),
        PopoverSide::Center => screen.x + screen.width.saturating_sub(width) / 2,
    };
    x = x.max(screen.x);
    if x + width > screen.right() {
        x = screen.right().saturating_sub(width);
    }

    let mut y = match side {
        PopoverSide::Above => anchor.y.saturating_sub(height),
        PopoverSide::Below => anchor.bottom(),
        PopoverSide::Center => screen.y + screen.height.saturating_sub(height) / 2,
    };
    if side == PopoverSide::Below && y + height > screen.bottom() {
        y = anchor.y.saturating_sub(height);
    }
    if side == PopoverSide::Above && y < screen.y {
        y = anchor.bottom();
    }
    y = y.max(screen.y);
    if y + height > screen.bottom() {
        y = screen.bottom().saturating_sub(height);
    }

    Rect {
        x,
        y,
        width,
        height,
    }
}

/// List / row selection idiom from excoc (colours resolve through the
/// terminal's colour capability).
pub fn selection_style() -> Style {
    Style::default()
        .bg(resolve_color(HOVER_BG, HOVER_BG_INDEX))
        .fg(resolve_color(BRASS, BRASS_INDEX))
        .add_modifier(Modifier::BOLD)
}

/// Highlight spacing paired with [`selection_style`].
pub fn selection_highlight_spacing() -> HighlightSpacing {
    HighlightSpacing::Always
}

/// Selection row prefix from excoc pickers.
pub fn selection_highlight_symbol() -> &'static str {
    "› "
}

fn truncate(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= width {
        return text.to_string();
    }
    if width == 1 {
        return "…".to_string();
    }
    let mut out: String = text.chars().take(width - 1).collect();
    out.push('…');
    out
}

#[derive(Debug, Clone)]
pub struct LeftStatus {
    pub spans: Vec<Span<'static>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongcacheStatus {
    enabled: bool,
    supported: bool,
}

impl LongcacheStatus {
    pub const fn new(enabled: bool, supported: bool) -> Self {
        Self { enabled, supported }
    }
}

/// Bottom-left status: additive indicators that are not composer pills
/// (currently longcache). Agent, model, effort, approval, and sandbox live
/// on the composer bottom-border deck.
pub fn left_status(longcache: LongcacheStatus) -> LeftStatus {
    let LongcacheStatus {
        enabled: longcache_enabled,
        supported: longcache_supported,
    } = longcache;
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut col: u16 = 0;

    if longcache_enabled {
        let (label, style) = if longcache_supported {
            ("longcache".to_string(), muted)
        } else {
            (
                "longcache unsupported".to_string(),
                Style::default().fg(Color::Yellow),
            )
        };
        push_span(&mut spans, &mut col, Span::styled(label, style));
    }

    LeftStatus { spans }
}

fn push_span(spans: &mut Vec<Span<'static>>, col: &mut u16, span: Span<'static>) {
    *col = col.saturating_add(span.width() as u16);
    spans.push(span);
}

/// Persistent enterprise session-log sync disclosure. Rendered only while an
/// org policy mandates sync for this instance. Additive to the fixed chrome.
#[cfg(feature = "remote")]
pub fn org_sync_spans(disclosure: Option<&OrgSyncDisclosure>) -> Vec<Span<'static>> {
    let Some(disclosure) = disclosure else {
        return Vec::new();
    };
    vec![Span::styled(
        format!("org sync {} ", disclosure.org_id),
        Style::default().fg(WARNING_TEXT),
    )]
}

/// Persistent remote relay connector indicator. Rendered while remote access is
/// enabled or the daemon has a non-off connector state. Additive to fixed chrome.
#[cfg(feature = "remote")]
pub fn connector_spans(disclosure: Option<&ConnectorDisclosure>) -> Vec<Span<'static>> {
    let Some(disclosure) = disclosure else {
        return Vec::new();
    };
    if !disclosure.enabled && disclosure.status == "off" {
        return Vec::new();
    }
    let style = match disclosure.status.as_str() {
        "connected" => Style::default().fg(Color::Cyan),
        "reconnecting" => Style::default().fg(PLAN_YELLOW),
        _ => Style::default().fg(WARNING_TEXT),
    };
    vec![Span::styled(
        format!("remote {} ", disclosure.status),
        style,
    )]
}

/// Persistent caffeination indicator (`/caffeinate`, GOALS §1a). Rendered
/// **only** while caffeination is active — additive to the fixed chrome,
/// never a permanent slot. Driven by the daemon-broadcast state so the
/// glyph appears (and clears) on every connected client in lockstep.
/// Returns the spans to prepend to the right-hand status line (`☕` plus a
/// trailing space separating it from the cwd), or an empty vec when off.
pub fn caffeinate_glyph_spans(active: bool) -> Vec<Span<'static>> {
    if !active {
        return Vec::new();
    }
    // Cyan reads as "kept awake" without competing with the yellow branch
    // badge; the trailing space keeps it off the cwd text.
    vec![Span::styled(
        "☕ ".to_string(),
        Style::default().fg(Color::Cyan),
    )]
}

/// Transient "waiting for lock" indicator
/// (`readlock-wait-and-lock-expiry.md` historical prompt slug). Rendered
/// **only** while a write/edit implicit acquire in this session is blocked on a
/// lock another agent/session holds — additive to the fixed chrome (cwd +
/// branch + context + active agent, GOALS §1a), never displacing a slot, the same pattern as the `☕`
/// caffeinate glyph. Names the contended path (basename, to stay compact)
/// and the holding agent; clears when the wait ends (lock acquired or
/// cancelled). Yellow reads as "blocked, waiting" without the red of an
/// error. Returns an empty vec when not waiting.
pub fn waiting_for_lock_spans(state: Option<&(String, String)>) -> Vec<Span<'static>> {
    let Some((path, holder)) = state else {
        return Vec::new();
    };
    let name = std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path.as_str());
    vec![Span::styled(
        format!("⏳ waiting for lock on `{name}` (held by `{holder}`) "),
        Style::default().fg(WARNING_TEXT),
    )]
}

/// Side-conversation indicator (`/side`, GOALS §1a). Rendered **only**
/// while a throwaway side conversation is open — additive to the fixed
/// chrome (cwd + branch), never displacing a slot, the same pattern as the
/// `☕` caffeinate glyph. Magenta reads as "you're somewhere temporary"
/// without competing with the yellow branch badge; the trailing space keeps
/// it off the cwd text. Returns an empty vec in the main session.
pub fn side_glyph_spans(active: bool) -> Vec<Span<'static>> {
    if !active {
        return Vec::new();
    }
    vec![Span::styled(
        "⑃ side · /side end ".to_string(),
        Style::default().fg(Color::Magenta),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;

    #[test]
    fn chip_style_applies_excoc_hover_rule() {
        let base = Style::default().fg(Color::Cyan);
        let idle = chip_style(base, false);
        assert_eq!(idle.fg, Some(Color::Cyan));
        assert_eq!(idle.bg, None);

        // Truecolor terminals get the RGB tokens.
        let hover = {
            let _pin = crate::tui::theme::pin_truecolor(true);
            chip_style(base, true)
        };
        assert_eq!(hover.fg, Some(BRASS));
        assert_eq!(hover.bg, Some(HOVER_BG));
        assert!(hover.add_modifier.contains(Modifier::BOLD));

        // Non-truecolor terminals get the indexed fallbacks, never 24-bit
        // SGR.
        let fallback = {
            let _pin = crate::tui::theme::pin_truecolor(false);
            chip_style(base, true)
        };
        assert_eq!(fallback.fg, Some(Color::Indexed(BRASS_INDEX)));
        assert_eq!(fallback.bg, Some(Color::Indexed(HOVER_BG_INDEX)));
        assert!(fallback.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn place_popover_below_flips_upward_when_it_would_clip() {
        let screen = Rect::new(0, 0, 40, 10);
        let anchor = Rect::new(30, 8, 8, 1);
        let rect = place_popover(anchor, 12, 4, screen, PopoverSide::Below);
        assert_eq!(rect.y, anchor.y.saturating_sub(4));
        assert!(rect.y >= screen.y);
        assert!(rect.right() <= screen.right());
    }

    #[test]
    fn place_popover_above_flips_downward_when_it_would_clip() {
        let screen = Rect::new(0, 2, 40, 10);
        let anchor = Rect::new(4, 3, 8, 1);
        let rect = place_popover(anchor, 12, 4, screen, PopoverSide::Above);
        assert_eq!(rect.y, anchor.bottom());
        assert!(rect.bottom() <= screen.bottom());
    }

    #[test]
    fn place_popover_center_clamps_to_screen() {
        let screen = Rect::new(5, 2, 20, 8);
        let anchor = Rect::new(10, 4, 6, 1);
        let rect = place_popover(anchor, 30, 20, screen, PopoverSide::Center);
        assert_eq!(rect.x, screen.x);
        assert_eq!(rect.y, screen.y);
        assert_eq!(rect.width, screen.width);
        assert_eq!(rect.height, screen.height);
    }

    fn scrollbar_bottom_glyph(content_length: usize, view_h: u16, scroll: usize) -> String {
        let mut terminal = Terminal::new(TestBackend::new(1, view_h)).unwrap();
        terminal
            .draw(|frame| {
                scrollbar(
                    frame,
                    frame.area(),
                    content_length,
                    usize::from(view_h),
                    scroll,
                );
            })
            .unwrap();
        terminal.backend().buffer()[(0, view_h - 1)]
            .symbol()
            .to_string()
    }

    #[test]
    fn scrollbar_thumb_reaches_bottom_at_max_scroll() {
        let total = 20usize;
        let view_h = 5u16;
        let max_scroll = total - usize::from(view_h);
        assert_eq!(
            scrollbar_bottom_glyph(total, view_h, max_scroll),
            "█",
            "the thumb must fill the bottom row when scrolled all the way down"
        );
    }

    #[test]
    fn scrollbar_reserves_the_rightmost_column_permanently() {
        // Nothing to scroll: the column is still reserved (content is one
        // column narrower) but nothing is painted in it — text laid out in
        // the returned rect never reflows when the thumb later appears.
        let mut terminal = Terminal::new(TestBackend::new(10, 5)).unwrap();
        let mut content = Rect::default();
        terminal
            .draw(|frame| {
                content = scrollbar(frame, frame.area(), 3, 5, 0);
            })
            .unwrap();
        assert_eq!(content, Rect::new(0, 0, 9, 5));
        let buf = terminal.backend().buffer();
        for y in 0..5u16 {
            assert_eq!(
                buf[(9, y)].symbol(),
                " ",
                "no track painted without overflow (row {y})"
            );
        }

        // With overflow the same content rect is returned and the reserved
        // column carries the track/thumb.
        terminal
            .draw(|frame| {
                content = scrollbar(frame, frame.area(), 20, 5, 0);
            })
            .unwrap();
        assert_eq!(content, Rect::new(0, 0, 9, 5));
        let buf = terminal.backend().buffer();
        for y in 0..5u16 {
            let glyph = buf[(9, y)].symbol();
            assert!(
                glyph == "│" || glyph == "█",
                "reserved column carries the scrollbar (row {y}): {glyph:?}"
            );
        }
        assert_eq!(
            scrollbar_content(Rect::new(2, 3, 1, 4)),
            Rect::new(2, 3, 0, 4)
        );
    }

    #[test]
    fn cluster_width_counts_labels_and_gaps() {
        let labels = vec!["abc".to_string(), "de".to_string()];
        assert_eq!(cluster_width(&labels), 6);
        assert_eq!(cluster_width(&[]), 0);
    }

    /// The waiting-for-lock indicator surfaces the contended path (basename)
    /// and the holder while waiting, and is absent (empty) when not waiting —
    /// the same additive-chrome contract as the ☕ glyph.
    #[test]
    fn waiting_for_lock_indicator_shows_path_and_holder_and_clears() {
        // Not waiting → no spans (never displaces the fixed chrome).
        assert!(waiting_for_lock_spans(None).is_empty());

        // Waiting → one transient span naming the basename + holder.
        let state = ("/repo/src/main.rs".to_string(), "builder".to_string());
        let spans = waiting_for_lock_spans(Some(&state));
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("waiting for lock"), "{text}");
        assert!(text.contains("main.rs"), "names the contended path: {text}");
        assert!(text.contains("builder"), "names the holder: {text}");
        // Yellow ("blocked, waiting"), not the red of an error.
        assert_eq!(spans[0].style.fg, Some(WARNING_TEXT));
    }

    #[test]
    #[cfg(feature = "remote")]
    fn org_sync_spans_disclose_active_policy() {
        let spans = org_sync_spans(Some(&OrgSyncDisclosure {
            org_id: "org-1".to_string(),
            cursor_seq: 7,
            last_synced_at_ms: None,
        }));
        let text: String = spans.iter().map(|span| span.content.as_ref()).collect();
        assert_eq!(text, "org sync org-1 ");
        assert!(org_sync_spans(None).is_empty());
    }

    #[test]
    fn side_glyph_present_only_when_active() {
        // Off in the main session; an additive indicator while a `/side`
        // side conversation is open (never a permanent slot).
        assert!(side_glyph_spans(false).is_empty());
        let spans = side_glyph_spans(true);
        assert_eq!(spans.len(), 1);
        assert!(spans[0].content.contains("side"));
        assert!(spans[0].content.contains("/side end"));
    }

    #[test]
    fn left_status_omits_agent_model_and_sandbox() {
        let text: String = left_status(LongcacheStatus::new(false, true))
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(!text.contains("Build"), "{text}");
        assert!(!text.contains("gpt-test"), "{text}");
        assert!(!text.contains("sandbox"), "{text}");
        assert!(!text.contains("compact"), "{text}");
        assert!(!text.contains("export"), "{text}");
        assert!(!text.contains("tools"), "{text}");
    }

    #[test]
    fn longcache_status_indicator_renders_supported_and_unsupported() {
        let off = left_status(LongcacheStatus::new(false, true));
        let off_text: String = off.spans.iter().map(|span| span.content.as_ref()).collect();
        assert!(!off_text.contains("longcache"), "{off_text}");

        let supported = left_status(LongcacheStatus::new(true, true));
        let supported_text: String = supported
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(supported_text.contains("longcache"), "{supported_text}");
        assert!(!supported_text.contains("unsupported"), "{supported_text}");

        let unsupported = left_status(LongcacheStatus::new(true, false));
        let unsupported_text: String = unsupported
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(
            unsupported_text.contains("longcache unsupported"),
            "{unsupported_text}"
        );
    }
}

#[cfg(all(test, feature = "remote"))]
mod connector_tests {
    use super::*;

    #[test]
    fn connector_spans_render_enabled_state() {
        let disclosure = ConnectorDisclosure {
            enabled: true,
            status: "connected".to_string(),
            relay_url: Some("wss://relay.example/ws".to_string()),
            relay_id: Some("relay-1".to_string()),
            relay_region: Some("iad".to_string()),
            last_error: None,
        };
        let spans = connector_spans(Some(&disclosure));
        assert_eq!(spans[0].content.as_ref(), "remote connected ");
        assert!(connector_spans(None).is_empty());
    }
}
