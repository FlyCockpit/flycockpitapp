//! Onboarding palette aliases — unified with [`crate::tui::theme`] (#444).
//!
//! Every name onboarding screens already import stays available here until
//! #434 drops the aliases.

pub use crate::tui::theme::{BAD, BRASS, DISABLED, FOG, GOOD, HOVER_BG, INK, NIGHT, PLACEHOLDER};

#[cfg(test)]
mod tests {
    use super::*;

    /// The alias module adds no colours of its own: every onboarding name
    /// resolves to the unified excoc token, and the legacy `BAD`/`GOOD`
    /// names are the unified `RED`/`GREEN` (#444 collapsed the
    /// near-duplicates). The RGB values and ANSI fallbacks are pinned by
    /// the owning module's tests.
    #[test]
    fn aliases_point_at_the_unified_excoc_palette() {
        use crate::tui::theme as unified;
        assert_eq!(INK, unified::INK);
        assert_eq!(FOG, unified::FOG);
        assert_eq!(BRASS, unified::BRASS);
        assert_eq!(NIGHT, unified::NIGHT);
        assert_eq!(DISABLED, unified::DISABLED);
        assert_eq!(HOVER_BG, unified::HOVER_BG);
        assert_eq!(PLACEHOLDER, unified::PLACEHOLDER);
        assert_eq!(BAD, unified::RED);
        assert_eq!(GOOD, unified::GREEN);
    }
}
