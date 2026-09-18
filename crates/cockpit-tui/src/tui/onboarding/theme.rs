//! Onboarding palette aliases — unified with [`crate::tui::theme`] (#444).
//!
//! Every name onboarding screens already import stays available here until
//! #434 drops the aliases.

pub use crate::tui::theme::{
    BAD, BAD_ANSI, BRASS, BRASS_ANSI, DISABLED, DISABLED_ANSI, FOG, FOG_ANSI, GOOD, GOOD_ANSI,
    HOVER_BG, HOVER_BG_ANSI, INK, INK_ANSI, NIGHT, NIGHT_ANSI, PLACEHOLDER, PLACEHOLDER_ANSI, RED,
    WARN, WARN_ANSI,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    #[test]
    fn truecolor_tokens_match_excoc() {
        assert_eq!(INK, Color::Rgb(0xF4, 0xEF, 0xE6));
        assert_eq!(FOG, Color::Rgb(0x8A, 0x9B, 0xB0));
        assert_eq!(BRASS, Color::Rgb(0xE0, 0xB1, 0x56));
        assert_eq!(NIGHT, Color::Rgb(0x4A, 0x5A, 0x6A));
        assert_eq!(GOOD, Color::Rgb(0x7F, 0xC9, 0x8A));
        assert_eq!(WARN, Color::Rgb(0xD8, 0x8A, 0x5A));
        assert_eq!(BAD, Color::Rgb(0xD9, 0x6A, 0x6A));
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
