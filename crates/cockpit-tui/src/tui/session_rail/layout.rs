//! Width-driven session-rail layout. Breakpoints are column counts, never
//! terminal-name heuristics.

/// Persistent cards + transcript/composer.
pub const WIDE_BREAKPOINT: u16 = 80;
/// Compact affordance while unfocused; overlay-sized rail only while focused
/// below this width.
pub const COMPACT_BREAKPOINT: u16 = 56;
/// Inclusive lower bound of the wide-layout rail.
pub const RAIL_MIN_WIDTH: u16 = 28;
/// Inclusive upper bound of the wide-layout rail.
pub const RAIL_MAX_WIDTH: u16 = 36;
/// Compact unfocused column: one-column session-focus affordance.
pub const COMPACT_AFFORDANCE_WIDTH: u16 = 3;

/// How the rail occupies the chat shell at a given terminal width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RailLayoutMode {
    /// The user preference closes the rail regardless of available width.
    HiddenByPreference,
    /// `width >= 80`. Persistent cards; chat consumes the remainder.
    Wide { rail_width: u16 },
    /// `56 <= width < 80`. Cards hidden; one-column focus/search affordance.
    Compact,
    /// `width < 56`. Hidden until the rail is explicitly focused, then an
    /// overlay-sized rail that returns to chat on Escape.
    HiddenUntilFocused,
}

impl RailLayoutMode {
    pub fn from_width(width: u16) -> Self {
        Self::from_width_and_preference(width, true)
    }

    /// Resolve both responsive width and the persisted user preference.
    pub fn from_width_and_preference(width: u16, visible: bool) -> Self {
        if !visible {
            return Self::HiddenByPreference;
        }
        if width >= WIDE_BREAKPOINT {
            let remainder_after_min = width.saturating_sub(RAIL_MIN_WIDTH);
            let rail_width = (width / 4)
                .clamp(RAIL_MIN_WIDTH, RAIL_MAX_WIDTH)
                .min(width.saturating_sub(1).max(RAIL_MIN_WIDTH));
            let rail_width = if remainder_after_min == 0 {
                RAIL_MIN_WIDTH.min(width)
            } else {
                rail_width
            };
            Self::Wide { rail_width }
        } else if width >= COMPACT_BREAKPOINT {
            Self::Compact
        } else {
            Self::HiddenUntilFocused
        }
    }

    /// Columns occupied by the persistent (non-overlay) rail column.
    pub fn persistent_width(self, focused: bool) -> u16 {
        match self {
            Self::HiddenByPreference => 0,
            Self::Wide { rail_width } => rail_width,
            Self::Compact if !focused => COMPACT_AFFORDANCE_WIDTH,
            Self::Compact | Self::HiddenUntilFocused => 0,
        }
    }

    /// Overlay-sized rail width while focused in a non-wide layout.
    pub fn focused_overlay_width(self, frame_width: u16) -> u16 {
        match self {
            Self::HiddenByPreference => 0,
            Self::Wide { rail_width } => rail_width,
            Self::Compact | Self::HiddenUntilFocused => {
                let overlay = RAIL_MAX_WIDTH.min(frame_width.saturating_sub(1));
                overlay.max(RAIL_MIN_WIDTH.min(frame_width))
            }
        }
    }

    pub fn shows_persistent_cards(self) -> bool {
        matches!(self, Self::Wide { .. })
    }

    pub fn shows_cards(self, focused: bool) -> bool {
        match self {
            Self::HiddenByPreference => false,
            Self::Wide { .. } => true,
            Self::Compact | Self::HiddenUntilFocused => focused,
        }
    }

    pub fn occupies_shell(self, focused: bool) -> bool {
        match self {
            Self::HiddenByPreference => false,
            Self::Wide { .. } | Self::Compact => true,
            Self::HiddenUntilFocused => focused,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_breakpoints_are_width_tests() {
        assert!(matches!(
            RailLayoutMode::from_width(80),
            RailLayoutMode::Wide { .. }
        ));
        assert_eq!(RailLayoutMode::from_width(79), RailLayoutMode::Compact);
        assert_eq!(RailLayoutMode::from_width(56), RailLayoutMode::Compact);
        assert_eq!(
            RailLayoutMode::from_width(55),
            RailLayoutMode::HiddenUntilFocused
        );
    }

    #[test]
    fn wide_rail_stays_within_28_36() {
        for width in 80..=400 {
            match RailLayoutMode::from_width(width) {
                RailLayoutMode::Wide { rail_width } => {
                    assert!(
                        (RAIL_MIN_WIDTH..=RAIL_MAX_WIDTH).contains(&rail_width),
                        "width {width} produced rail {rail_width}"
                    );
                }
                other => panic!("expected wide at {width}, got {other:?}"),
            }
        }
    }
}
