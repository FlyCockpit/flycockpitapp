//! Theme palette + JSON theme loader.
//!
//! Themes live in `~/.config/cockpit/themes/*.json` plus any
//! `.cockpit/themes/` on the discovered config path. Built-ins to ship
//! initially: `system`, `tokyonight`, `gruvbox`.

use ratatui::style::Color;

/// Foreground color index used for muted/secondary text across the TUI
/// (status line, popup descriptions, help text).
pub const MUTED_COLOR_INDEX: u8 = 250;
pub const MUTED_TEXT: Color = Color::Indexed(MUTED_COLOR_INDEX);
pub const METADATA_TEXT: Color = MUTED_TEXT;

/// Border color for the composer/input box and queue strip while the
/// agent is busy (request in flight): a clearly-visible mid-grey —
/// distinct from the white idle border and dimmer than it (so the
/// "agent is working, hold off typing" cue reads as muted) but never
/// near-black/invisible against a dark terminal background.
pub const BUSY_BORDER_INDEX: u8 = 245;
pub const BUSY_BORDER: Color = Color::Indexed(BUSY_BORDER_INDEX);
pub const IDLE_BORDER: Color = Color::White;
pub const SHELL_MODE_BORDER: Color = Color::Indexed(70);
pub const SHELL_MODE_BADGE_BG: Color = SHELL_MODE_BORDER;

/// Accent blue used for the rounded outlines (user-message bubble,
/// launch-banner box). The brighter blue that reads as the app accent
/// against the surrounding chrome.
pub const ACCENT_BLUE_INDEX: u8 = 33;
pub const ACCENT_BLUE: Color = Color::Indexed(ACCENT_BLUE_INDEX);

/// Orange used for a subagent's (child) name in the delegation
/// running-line and the `… worked for …` / `… failed after …` header.
/// Only the child name carries it; the parent name uses the default
/// style.
pub const SUBAGENT_ORANGE_INDEX: u8 = 208;
pub const SUBAGENT_ORANGE: Color = Color::Indexed(SUBAGENT_ORANGE_INDEX);

pub const STATUS_BRANCH_BADGE: Color = Color::Indexed(220);
pub const FAVORITE_MODEL: Color = Color::Indexed(178);
pub const CHIP_TEXT: Color = METADATA_TEXT;
pub const DIVIDER_FOCUSED: Color = METADATA_TEXT;
pub const DIVIDER_DIM: Color = Color::Indexed(238);
pub const TOOL_SIDEBAR: Color = Color::Indexed(244);
pub const TOOL_OUTPUT: Color = Color::Indexed(245);
pub const WARNING_TEXT: Color = Color::Yellow;
pub const SUCCESS_TEXT: Color = Color::Green;
pub const ERROR_TEXT: Color = Color::Red;
pub const INFO_TEXT: Color = METADATA_TEXT;

/// Plan-yellow (`#f8d749`) used for plan/status affordances. Terminals
/// without truecolor support should downgrade this to [`WARNING_TEXT`].
pub const PLAN_YELLOW: Color = Color::Rgb(0xf8, 0xd7, 0x49);

/// Distinct 256-color palette indices for the `/context` usage overlay's
/// per-category bar segments + legend swatches. One color per category;
/// each is visually distinct from its neighbors so the colored bar — not
/// the glyph — carries the category identity. Free space uses
/// [`MUTED_COLOR_INDEX`] (dim) so the used portion reads as the figure.
pub const CONTEXT_SYSTEM_INDEX: u8 = 33; // blue   — base system prompt
pub const CONTEXT_BLOCK_INDEX: u8 = 213; // magenta — cached system block
pub const CONTEXT_GUIDANCE_INDEX: u8 = 220; // yellow — guidance/memory files
pub const CONTEXT_MESSAGES_INDEX: u8 = 41; // green  — conversation messages

#[cfg(test)]
mod tests {
    use super::*;

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
    fn semantic_roles_preserve_current_palette() {
        assert_eq!(MUTED_TEXT, Color::Indexed(250));
        assert_eq!(STATUS_BRANCH_BADGE, Color::Indexed(220));
        assert_eq!(FAVORITE_MODEL, Color::Indexed(178));
        assert_eq!(SHELL_MODE_BORDER, Color::Indexed(70));
        assert_eq!(PLAN_YELLOW, Color::Rgb(0xf8, 0xd7, 0x49));
    }
}
