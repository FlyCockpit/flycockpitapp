//! Factored "reset this page to defaults" affordance shared by the
//! settings sub-pages (Tools, Skills, Harnesses, Agents, and the
//! category pages — Interface/Behavior/Privacy & Safety/Translation/
//! Profile). One arm/confirm/apply state machine + one button renderer
//! so no page hand-rolls (or copy-pastes) the confirm flow.
//!
//! Usage on a page:
//!   - hold a [`ResetButton`] in the page state (defaults to disarmed);
//!   - place its row in the page's navigable layout and, when the cursor
//!     is on it, route activation keys through [`ResetButton::activate`].
//!     The first activation arms ("press again to confirm"); the second
//!     returns [`ResetOutcome::Apply`] so the page performs its
//!     page-specific reset + save;
//!   - call [`ResetButton::disarm`] on any navigation away / cancel so a
//!     stale "press again" can never silently fire later;
//!   - render the row with [`ResetButton::render_line`].
//!
//! The button owns only the confirm state + its label; *what* a reset
//! does stays on the page (each page resets a different slice of config).

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::theme::MUTED_COLOR_INDEX;

/// Shared arm/confirm state for a page-level reset button. A page embeds
/// one of these and drives it through [`Self::activate`] /
/// [`Self::disarm`].
#[derive(Default)]
pub(super) struct ResetButton {
    /// `true` once the first activation has armed the button: the next
    /// activation confirms. Cleared by [`Self::disarm`] (navigation away
    /// or an explicit cancel) so a stale arm never fires later.
    pending: bool,
}

/// What [`ResetButton::activate`] decided. `Armed` means the caller
/// should re-render (the confirm indicator is now showing) but make no
/// config change; `Apply` means the caller should perform the reset and
/// persist it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(super) enum ResetOutcome {
    /// First activation — the button is now armed; show "press again".
    Armed,
    /// Second activation — perform the page's reset + save now.
    Apply,
}

impl ResetButton {
    /// Whether the button is currently armed (awaiting the confirm
    /// keypress). Drives the pending indicator in [`Self::render_line`].
    pub(super) fn is_pending(&self) -> bool {
        self.pending
    }

    /// Activate the button. The first call arms it ([`ResetOutcome::Armed`]);
    /// the second confirms and disarms ([`ResetOutcome::Apply`]). The
    /// caller performs the actual reset only on `Apply`.
    pub(super) fn activate(&mut self) -> ResetOutcome {
        if self.pending {
            self.pending = false;
            ResetOutcome::Apply
        } else {
            self.pending = true;
            ResetOutcome::Armed
        }
    }

    /// Disarm a pending confirm. Idempotent — safe to call on every
    /// navigation/cancel even when not armed.
    pub(super) fn disarm(&mut self) {
        self.pending = false;
    }

    /// Render the button as a single navigable row. `selected` is whether
    /// the page cursor is on this row; `label` is the action text
    /// (e.g. `"reset to defaults"`). While armed the row turns red and
    /// shows a confirm hint; otherwise it shows the key hint.
    pub(super) fn render_line(&self, selected: bool, label: &str) -> Line<'static> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let marker = if selected { "▸ " } else { "  " };
        if self.pending {
            let red = Style::default().fg(Color::Red).add_modifier(Modifier::BOLD);
            Line::from(vec![
                Span::raw(marker),
                Span::styled(format!("[{label}]"), red),
                Span::styled("  press again to confirm".to_string(), red),
            ])
        } else {
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                muted
            };
            Line::from(vec![
                Span::raw(marker),
                Span::styled(format!("[{label}]"), style),
                Span::styled("  enter: reset".to_string(), muted),
            ])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_activation_arms_second_applies() {
        let mut b = ResetButton::default();
        assert!(!b.is_pending(), "starts disarmed");
        assert_eq!(b.activate(), ResetOutcome::Armed);
        assert!(b.is_pending(), "first activation arms");
        assert_eq!(b.activate(), ResetOutcome::Apply);
        assert!(!b.is_pending(), "applying disarms");
    }

    #[test]
    fn disarm_clears_pending_and_is_idempotent() {
        let mut b = ResetButton::default();
        b.activate();
        assert!(b.is_pending());
        b.disarm();
        assert!(!b.is_pending(), "disarm clears the pending confirm");
        // Idempotent: disarming again is a no-op, and re-activating arms
        // afresh rather than applying.
        b.disarm();
        assert_eq!(
            b.activate(),
            ResetOutcome::Armed,
            "after disarm the next activation arms, never applies"
        );
    }
}
