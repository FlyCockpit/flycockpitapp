//! In-TUI banner rendering (GOALS §1g) — the ratatui `Span` half.
//!
//! The banner art data (planes, palettes), art selection, cell
//! resolution, and the raw-stdout ANSI renderer all live in
//! [`cockpit_core::banner`]; this module imports the resolved cell
//! grid ([`cockpit_core::banner::active_cells`]) and adds only what
//! the TUI needs: styled `Span` rows for the in-TUI banner box, plus
//! its suppression rule.
//!
//! Suppression for the in-TUI banner box (`NO_COLOR` or config
//! `enabled = false`) is handled by [`suppressed_for_tui`]; callers
//! hide the banner panel when it returns `true`.

use cockpit_core::banner::{ResolvedCell, active_cells};
use ratatui::style::{Color, Style};
use ratatui::text::Span;

/// Whether the banner is suppressed for the *in-TUI* box (GOALS §1g
/// rules minus the TTY/width checks, which the TUI handles itself —
/// it's always a TTY, and the box does its own pane-fit check). Returns
/// `true` (suppress) on `enabled = false` or `NO_COLOR`. A truthy
/// `COCKPIT_ROOSTER` no longer suppresses — it swaps the active art to
/// the rooster (see [`cockpit_core::banner::active_cells`]).
pub fn suppressed_for_tui(enabled: bool) -> bool {
    !enabled || std::env::var_os("NO_COLOR").is_some()
}

/// The art as ratatui styled spans — one row per `Vec<Span>`, one span
/// per 2×2 cell group, with no left indent (the in-TUI banner box
/// centers and borders the art itself). Parallel to the raw-stdout
/// renderer in [`cockpit_core::banner`], which bakes ANSI escapes + an
/// indent instead.
pub fn render_styled_lines() -> Vec<Vec<Span<'static>>> {
    active_cells()
        .into_iter()
        .map(|row| row.into_iter().map(cell_span).collect())
        .collect()
}

/// One resolved 2×2 cell group as a ratatui [`Span`] (in-TUI path).
fn cell_span(cell: ResolvedCell) -> Span<'static> {
    match cell {
        None => Span::raw(" "),
        Some((glyph, fg, Some(bg))) => Span::styled(
            glyph,
            Style::default()
                .fg(Color::Indexed(fg))
                .bg(Color::Indexed(bg)),
        ),
        Some((glyph, fg, None)) => Span::styled(glyph, Style::default().fg(Color::Indexed(fg))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_suppresses_tui_box() {
        let env = cockpit_test_support::TestEnvGuard::blocking_lock();
        env.set_var("NO_COLOR", "1");
        let suppressed = suppressed_for_tui(true);
        assert!(suppressed);
    }

    #[test]
    fn disabled_flag_suppresses_tui_box() {
        assert!(suppressed_for_tui(false));
    }
}
