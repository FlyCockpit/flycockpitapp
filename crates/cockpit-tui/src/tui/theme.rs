//! Excoc instrument-panel palette for the whole TUI.
//!
//! Truecolor RGB tokens are the source of truth; [`resolve_color`] picks the
//! nearest 256-color fallback when the terminal does not advertise truecolor.
//! Every paint site that renders one of these tokens routes it through
//! [`resolve_color`] with its paired `*_INDEX` fallback.

use ratatui::style::{Color, Modifier, Style};

/// Bright foreground text.
pub const INK: Color = Color::Rgb(0xF4, 0xEF, 0xE6);
pub const INK_INDEX: u8 = 255;

/// Muted secondary text.
pub const FOG: Color = Color::Rgb(0x8A, 0x9B, 0xB0);
pub const FOG_INDEX: u8 = 109;

/// Accent — selection, primary action, caret, focused borders.
pub const BRASS: Color = Color::Rgb(0xE0, 0xB1, 0x56);
pub const BRASS_INDEX: u8 = 179;

/// Borders and rules at rest.
pub const NIGHT: Color = Color::Rgb(0x4A, 0x5A, 0x6A);
pub const NIGHT_INDEX: u8 = 240;

/// Dimmest text: disabled labels, reasoning traces.
pub const DISABLED: Color = Color::Rgb(0x55, 0x62, 0x70);
pub const DISABLED_INDEX: u8 = 241;

/// Wash behind a hovered or focused row.
pub const HOVER_BG: Color = Color::Rgb(0x2C, 0x38, 0x46);
pub const HOVER_BG_INDEX: u8 = 236;

/// Lifted surface for cards and the sticky header.
pub const SURFACE: Color = Color::Rgb(0x1C, 0x26, 0x30);
pub const SURFACE_INDEX: u8 = 235;

/// Italic placeholder text in empty fields.
pub const PLACEHOLDER: Color = Color::Rgb(0x6A, 0x7A, 0x8A);
pub const PLACEHOLDER_INDEX: u8 = 245;

/// Working — a turn is in flight.
pub const YELLOW: Color = Color::Rgb(0xE0, 0xB1, 0x56);
pub const YELLOW_INDEX: u8 = 179;

/// Waiting on you — the run is parked on your answer.
pub const RED: Color = Color::Rgb(0xD9, 0x6A, 0x6A);
pub const RED_INDEX: u8 = 167;

/// Done / clear.
pub const GREEN: Color = Color::Rgb(0x7F, 0xC9, 0x8A);
pub const GREEN_INDEX: u8 = 114;

/// Interactive subagent gutter — distinct from the brass user-message bar.
pub const TEAL: Color = Color::Rgb(0x4E, 0xC8, 0xC4);
pub const TEAL_INDEX: u8 = 80;

/// Caution rows (onboarding and warnings).
pub const WARN: Color = Color::Rgb(0xD8, 0x8A, 0x5A);
pub const WARN_INDEX: u8 = 173;

/// Success/on — same RGB as [`GREEN`].
pub const GOOD: Color = GREEN;
pub const GOOD_INDEX: u8 = GREEN_INDEX;

// TODO(#434): drop aliases
pub const MUTED_TEXT: Color = FOG;
pub const METADATA_TEXT: Color = FOG;
pub const MUTED_COLOR_INDEX: u8 = FOG_INDEX;
pub const ACCENT_BLUE: Color = BRASS;
pub const ACCENT_BLUE_INDEX: u8 = BRASS_INDEX;
pub const SUBAGENT_ORANGE: Color = TEAL;
pub const SUBAGENT_ORANGE_INDEX: u8 = TEAL_INDEX;
pub const TRANSCRIPT_HOVER_BG: Color = HOVER_BG;
pub const TRANSCRIPT_HOVER_BG_INDEX: u8 = HOVER_BG_INDEX;

// TODO(#434): drop aliases
pub const INK_ANSI: Color = Color::Indexed(INK_INDEX);
pub const FOG_ANSI: Color = Color::Indexed(FOG_INDEX);
pub const BRASS_ANSI: Color = Color::Indexed(BRASS_INDEX);
pub const NIGHT_ANSI: Color = Color::Indexed(NIGHT_INDEX);
pub const GOOD_ANSI: Color = Color::Indexed(GOOD_INDEX);
pub const WARN_ANSI: Color = Color::Indexed(WARN_INDEX);
pub const BAD: Color = RED;
pub const BAD_ANSI: Color = Color::Indexed(RED_INDEX);
pub const DISABLED_ANSI: Color = Color::Indexed(DISABLED_INDEX);
pub const HOVER_BG_ANSI: Color = Color::Indexed(HOVER_BG_INDEX);
pub const PLACEHOLDER_ANSI: Color = Color::Indexed(PLACEHOLDER_INDEX);

/// Border color for the composer/input box and queue strip while the agent
/// is busy (request in flight).
pub const BUSY_BORDER: Color = Color::Indexed(245);
pub const BUSY_BORDER_INDEX: u8 = 245;
pub const IDLE_BORDER: Color = Color::White;
pub const SHELL_MODE_BORDER: Color = Color::Indexed(70);
pub const SHELL_MODE_BADGE_BG: Color = SHELL_MODE_BORDER;

pub const STATUS_BRANCH_BADGE: Color = Color::Indexed(220);
pub const FAVORITE_MODEL: Color = Color::Indexed(178);
pub const CHIP_TEXT: Color = METADATA_TEXT;
pub const DIVIDER_FOCUSED: Color = METADATA_TEXT;
pub const DIVIDER_DIM: Color = Color::Indexed(238);
pub const TOOL_SIDEBAR: Color = Color::Indexed(244);
pub const TOOL_OUTPUT: Color = Color::Indexed(245);
pub const WARNING_TEXT: Color = YELLOW;
pub const SUCCESS_TEXT: Color = GREEN;
pub const ERROR_TEXT: Color = RED;
pub const INFO_TEXT: Color = METADATA_TEXT;

/// Interaction tokens. Hover paint lives in the single excoc chip rule
/// (`crate::tui::chrome::chip_style`: [`HOVER_BG`] + [`BRASS`] + bold);
/// these hover constants stay only as inputs to the contrast matrix.
/// Focus/pressed/destructive stay distinct pressed states.
pub const BUTTON_HOVER_FG: Color = BRASS;
pub const BUTTON_HOVER_BG: Color = HOVER_BG;
pub const BUTTON_FOCUS_FG: Color = Color::Rgb(0xFF, 0xFF, 0xFF);
pub const BUTTON_FOCUS_BG: Color = Color::Rgb(0x37, 0x6C, 0x9A);
pub const BUTTON_PRESSED_FG: Color = Color::Rgb(0xFF, 0xFF, 0xFF);
pub const BUTTON_PRESSED_BG: Color = Color::Rgb(0x21, 0x4A, 0x70);
pub const BUTTON_DESTRUCTIVE_FG: Color = Color::Rgb(0xFF, 0xFF, 0xFF);
pub const BUTTON_DESTRUCTIVE_BG: Color = Color::Rgb(0x8B, 0x2E, 0x3B);
pub const BUTTON_DISABLED_FG: Color = Color::Indexed(244);
pub const ROW_SELECTION_FG: Color = BRASS;
pub const ROW_SELECTION_BG: Color = HOVER_BG;
pub const LINK_BASE_FG: Color = Color::Cyan;
pub const LINK_HOVER_FG: Color = Color::Cyan;

pub fn button_idle_style() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

pub fn button_focus_style() -> Style {
    Style::default()
        .fg(BUTTON_FOCUS_FG)
        .bg(BUTTON_FOCUS_BG)
        .add_modifier(Modifier::BOLD)
}

pub fn button_pressed_style() -> Style {
    Style::default()
        .fg(BUTTON_PRESSED_FG)
        .bg(BUTTON_PRESSED_BG)
        .add_modifier(Modifier::BOLD)
}

pub fn button_disabled_style() -> Style {
    Style::default()
        .fg(BUTTON_DISABLED_FG)
        .add_modifier(Modifier::DIM)
}

pub fn button_destructive_style() -> Style {
    Style::default()
        .fg(BUTTON_DESTRUCTIVE_FG)
        .bg(BUTTON_DESTRUCTIVE_BG)
        .add_modifier(Modifier::BOLD)
}

pub fn row_selection_style() -> Style {
    Style::default().fg(ROW_SELECTION_FG).bg(ROW_SELECTION_BG)
}

/// Plan-yellow (`#f8d749`) used for plan/status affordances.
pub const PLAN_YELLOW: Color = Color::Rgb(0xf8, 0xd7, 0x49);

/// Distinct 256-color palette indices for the `/context` usage overlay's
/// per-category bar segments + legend swatches.
pub const CONTEXT_SYSTEM_INDEX: u8 = 33;
pub const CONTEXT_BLOCK_INDEX: u8 = 213;
pub const CONTEXT_GUIDANCE_INDEX: u8 = 220;
pub const CONTEXT_MESSAGES_INDEX: u8 = 41;

/// Classify a `COLORTERM` value: it advertises 24-bit colour when it
/// contains `truecolor` or `24bit` (case-insensitive). Pure (the value is
/// passed in) so the classification is unit-testable.
fn colorterm_advertises_truecolor(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("truecolor") || value.contains("24bit")
}

/// Whether the terminal advertises 24-bit color via `COLORTERM`. Absent or
/// unrecognized values are treated as non-truecolor. While a
/// [`pin_truecolor`] is installed on this thread (tests and the golden
/// harness only), the pin wins so renders stay byte-identical regardless
/// of the ambient environment.
pub fn supports_truecolor() -> bool {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(capable) = TRUECOLOR_PIN.with(std::cell::Cell::get) {
        return capable;
    }
    std::env::var("COLORTERM")
        .map(|value| colorterm_advertises_truecolor(&value))
        .unwrap_or(false)
}

/// Resolve an RGB token to itself on truecolor terminals, otherwise the
/// nearest indexed fallback. The single funnel through which the RGB
/// palette reaches a terminal; non-RGB colours pass through unchanged.
pub fn resolve_color(truecolor: Color, index: u8) -> Color {
    match truecolor {
        Color::Rgb(r, g, b) if supports_truecolor() => Color::Rgb(r, g, b),
        Color::Rgb(_, _, _) => Color::Indexed(index),
        other => other,
    }
}

// Per-thread capability override behind [`pin_truecolor`]. Tests and the
// golden harness install it so both capability branches are exercised
// deterministically and golden dumps never depend on the ambient
// `COLORTERM`. Never compiled into live rendering.
#[cfg(any(test, feature = "test-support"))]
std::thread_local! {
    static TRUECOLOR_PIN: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// RAII guard that restores the previous capability pin on drop.
#[cfg(any(test, feature = "test-support"))]
pub struct TruecolorPin {
    prev: Option<bool>,
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for TruecolorPin {
    fn drop(&mut self) {
        TRUECOLOR_PIN.with(|cell| cell.set(self.prev));
    }
}

/// Pin the terminal colour capability for this thread, overriding the
/// `COLORTERM` check for the guard's lifetime: the golden-dump determinism
/// seam (dumps must not depend on the ambient `COLORTERM`) and the way
/// tests pin both capability branches of [`resolve_color`]. Live rendering
/// never installs a pin.
#[cfg(any(test, feature = "test-support"))]
pub fn pin_truecolor(capable: bool) -> TruecolorPin {
    let prev = TRUECOLOR_PIN.with(|cell| cell.replace(Some(capable)));
    TruecolorPin { prev }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_palette_matches_excoc_rgb() {
        assert_eq!(INK, Color::Rgb(0xF4, 0xEF, 0xE6));
        assert_eq!(FOG, Color::Rgb(0x8A, 0x9B, 0xB0));
        assert_eq!(BRASS, Color::Rgb(0xE0, 0xB1, 0x56));
        assert_eq!(NIGHT, Color::Rgb(0x4A, 0x5A, 0x6A));
        assert_eq!(DISABLED, Color::Rgb(0x55, 0x62, 0x70));
        assert_eq!(HOVER_BG, Color::Rgb(0x2C, 0x38, 0x46));
        assert_eq!(SURFACE, Color::Rgb(0x1C, 0x26, 0x30));
        assert_eq!(PLACEHOLDER, Color::Rgb(0x6A, 0x7A, 0x8A));
        assert_eq!(YELLOW, Color::Rgb(0xE0, 0xB1, 0x56));
        assert_eq!(RED, Color::Rgb(0xD9, 0x6A, 0x6A));
        assert_eq!(GREEN, Color::Rgb(0x7F, 0xC9, 0x8A));
        assert_eq!(TEAL, Color::Rgb(0x4E, 0xC8, 0xC4));
        assert_eq!(WARN, Color::Rgb(0xD8, 0x8A, 0x5A));
        assert_eq!(GOOD, GREEN);
        assert_eq!(BAD, RED);
    }

    #[test]
    fn legacy_aliases_point_at_unified_tokens() {
        assert_eq!(MUTED_TEXT, FOG);
        assert_eq!(ACCENT_BLUE, BRASS);
        assert_eq!(SUBAGENT_ORANGE, TEAL);
        assert_eq!(TRANSCRIPT_HOVER_BG, HOVER_BG);
        assert_eq!(MUTED_COLOR_INDEX, FOG_INDEX);
        assert_eq!(ACCENT_BLUE_INDEX, BRASS_INDEX);
        assert_eq!(SUBAGENT_ORANGE_INDEX, TEAL_INDEX);
    }

    #[test]
    fn colorterm_classification_pins_both_branches() {
        assert!(colorterm_advertises_truecolor("truecolor"));
        assert!(colorterm_advertises_truecolor("24bit"));
        assert!(colorterm_advertises_truecolor("Truecolor"));
        assert!(colorterm_advertises_truecolor("screen-256color;truecolor"));
        assert!(!colorterm_advertises_truecolor(""));
        assert!(!colorterm_advertises_truecolor("256color"));
        assert!(!colorterm_advertises_truecolor("yes"));
    }

    #[test]
    fn supports_truecolor_follows_colorterm() {
        let env = cockpit_test_support::TestEnvGuard::blocking_lock();
        env.remove_var("COLORTERM");
        assert!(!supports_truecolor(), "absent COLORTERM is non-truecolor");
        env.set_var("COLORTERM", "truecolor");
        assert!(supports_truecolor());
        env.set_var("COLORTERM", "24bit");
        assert!(supports_truecolor());
        env.set_var("COLORTERM", "256color");
        assert!(!supports_truecolor(), "256color is not 24-bit");
    }

    #[test]
    fn resolve_color_pins_both_capability_branches() {
        let resolved = {
            let _pin = pin_truecolor(true);
            resolve_color(BRASS, BRASS_INDEX)
        };
        assert_eq!(resolved, BRASS, "truecolor terminals get the RGB token");

        let resolved = {
            let _pin = pin_truecolor(false);
            resolve_color(BRASS, BRASS_INDEX)
        };
        assert_eq!(
            resolved,
            Color::Indexed(BRASS_INDEX),
            "non-truecolor terminals get the indexed fallback"
        );

        // Non-RGB colours pass through untouched in both branches.
        let passthrough = {
            let _pin = pin_truecolor(false);
            resolve_color(Color::Cyan, BRASS_INDEX)
        };
        assert_eq!(passthrough, Color::Cyan);
    }

    #[test]
    fn indexed_fallbacks_pin_the_documented_indices() {
        assert_eq!(INK_INDEX, 255);
        assert_eq!(FOG_INDEX, 109);
        assert_eq!(BRASS_INDEX, 179);
        assert_eq!(NIGHT_INDEX, 240);
        assert_eq!(DISABLED_INDEX, 241);
        assert_eq!(HOVER_BG_INDEX, 236);
        assert_eq!(SURFACE_INDEX, 235);
        assert_eq!(PLACEHOLDER_INDEX, 245);
        assert_eq!(YELLOW_INDEX, 179);
        assert_eq!(RED_INDEX, 167);
        assert_eq!(GREEN_INDEX, 114);
        assert_eq!(TEAL_INDEX, 80);
        assert_eq!(WARN_INDEX, 173);
        assert_eq!(GOOD_INDEX, GREEN_INDEX);
        // Every `*_ANSI` fallback is the indexed spelling of its token.
        assert_eq!(INK_ANSI, Color::Indexed(255));
        assert_eq!(FOG_ANSI, Color::Indexed(109));
        assert_eq!(BRASS_ANSI, Color::Indexed(179));
        assert_eq!(NIGHT_ANSI, Color::Indexed(240));
        assert_eq!(GOOD_ANSI, Color::Indexed(114));
        assert_eq!(WARN_ANSI, Color::Indexed(173));
        assert_eq!(BAD_ANSI, Color::Indexed(167));
        assert_eq!(DISABLED_ANSI, Color::Indexed(241));
        assert_eq!(HOVER_BG_ANSI, Color::Indexed(236));
        assert_eq!(PLACEHOLDER_ANSI, Color::Indexed(245));
        // Yellow shares BRASS's RGB, so it shares its fallback too.
        assert_eq!(YELLOW_INDEX, BRASS_INDEX);
    }

    #[test]
    fn busy_border_role_stays_visible_and_not_dim_divider() {
        assert_eq!(BUSY_BORDER, Color::Indexed(BUSY_BORDER_INDEX));
        assert_ne!(BUSY_BORDER, DIVIDER_DIM);
        assert!(
            (244..=250).contains(&BUSY_BORDER_INDEX),
            "busy border must stay in the visible-grey band"
        );
    }

    #[test]
    fn ansi_fallbacks_are_indexed_never_reset() {
        for color in [
            INK_ANSI,
            FOG_ANSI,
            BRASS_ANSI,
            NIGHT_ANSI,
            GOOD_ANSI,
            WARN_ANSI,
            BAD_ANSI,
            DISABLED_ANSI,
            HOVER_BG_ANSI,
            PLACEHOLDER_ANSI,
        ] {
            assert!(
                matches!(color, Color::Indexed(_)),
                "ANSI fallback must be indexed, got {color:?}"
            );
            assert_ne!(color, Color::Reset);
        }
    }
}
