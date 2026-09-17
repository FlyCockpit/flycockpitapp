//! Onboarding-scoped instrument-panel palette.
//!
//! Ported from `reference/example-tui` (re-declared there in eight modules).
//! Truecolor tokens are the source of truth; `*_ANSI` are the nearest 256-color
//! fallbacks and must never be `Reset` / terminal-default. Unification with
//! `crate::tui::theme` is #444.
//!
//! Semantics: BRASS = interactive / primary / focus; INK body; FOG secondary
//! and help; NIGHT separators, idle borders, scrollbar track; GOOD success/on;
//! WARN caution; BAD failure; DISABLED unavailable; PLACEHOLDER empty-field
//! hint; HOVER_BG pointer highlight.

use ratatui::style::Color;

pub const INK: Color = Color::Rgb(0xF4, 0xEF, 0xE6);
#[allow(dead_code)] // 256-color fallback until #444 unifies theme selection.
pub const INK_ANSI: Color = Color::Indexed(255);

pub const FOG: Color = Color::Rgb(0x8A, 0x9B, 0xB0);
#[allow(dead_code)] // 256-color fallback until #444 unifies theme selection.
pub const FOG_ANSI: Color = Color::Indexed(109);

pub const BRASS: Color = Color::Rgb(0xE0, 0xB1, 0x56);
#[allow(dead_code)] // 256-color fallback until #444 unifies theme selection.
pub const BRASS_ANSI: Color = Color::Indexed(179);

pub const NIGHT: Color = Color::Rgb(0x4A, 0x5A, 0x6A);
#[allow(dead_code)] // 256-color fallback until #444 unifies theme selection.
pub const NIGHT_ANSI: Color = Color::Indexed(240);

pub const GOOD: Color = Color::Rgb(0x7F, 0xC9, 0x8A);
#[allow(dead_code)] // 256-color fallback until #444 unifies theme selection.
pub const GOOD_ANSI: Color = Color::Indexed(114);

#[allow(dead_code)] // caution rows land in later onboarding screens.
pub const WARN: Color = Color::Rgb(0xD8, 0x8A, 0x5A);
#[allow(dead_code)] // 256-color fallback until #444 unifies theme selection.
pub const WARN_ANSI: Color = Color::Indexed(173);

pub const BAD: Color = Color::Rgb(0xE0, 0x6C, 0x6C);
#[allow(dead_code)] // 256-color fallback until #444 unifies theme selection.
pub const BAD_ANSI: Color = Color::Indexed(167);

pub const DISABLED: Color = Color::Rgb(0x55, 0x62, 0x70);
#[allow(dead_code)] // 256-color fallback until #444 unifies theme selection.
pub const DISABLED_ANSI: Color = Color::Indexed(241);

pub const HOVER_BG: Color = Color::Rgb(0x2C, 0x38, 0x46);
#[allow(dead_code)] // 256-color fallback until #444 unifies theme selection.
pub const HOVER_BG_ANSI: Color = Color::Indexed(236);

pub const PLACEHOLDER: Color = Color::Rgb(0x6A, 0x7A, 0x8A);
#[allow(dead_code)] // 256-color fallback until #444 unifies theme selection.
pub const PLACEHOLDER_ANSI: Color = Color::Indexed(245);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truecolor_tokens_match_excoc() {
        assert_eq!(INK, Color::Rgb(0xF4, 0xEF, 0xE6));
        assert_eq!(FOG, Color::Rgb(0x8A, 0x9B, 0xB0));
        assert_eq!(BRASS, Color::Rgb(0xE0, 0xB1, 0x56));
        assert_eq!(NIGHT, Color::Rgb(0x4A, 0x5A, 0x6A));
        assert_eq!(GOOD, Color::Rgb(0x7F, 0xC9, 0x8A));
        assert_eq!(WARN, Color::Rgb(0xD8, 0x8A, 0x5A));
        assert_eq!(BAD, Color::Rgb(0xE0, 0x6C, 0x6C));
        assert_eq!(DISABLED, Color::Rgb(0x55, 0x62, 0x70));
        assert_eq!(HOVER_BG, Color::Rgb(0x2C, 0x38, 0x46));
        assert_eq!(PLACEHOLDER, Color::Rgb(0x6A, 0x7A, 0x8A));
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
