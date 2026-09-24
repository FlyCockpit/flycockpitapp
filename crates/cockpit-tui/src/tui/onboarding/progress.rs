//! The onboarding step-progress row.
//!
//! The row sits between the screen header and a separating rule, so it must
//! never read as the first item of the option list below it. It therefore
//! uses its own glyph vocabulary, disjoint from every selection glyph the
//! onboarding screens draw (radio `◉`/`○`, checkbox `▣`/`▢`, and the `›`/`▸`
//! list cursors):
//!
//! * completed step: a muted `✓`;
//! * current step: `◆` plus its label, in the accent style;
//! * pending step: a dim `·`.
//!
//! The glyphs alone distinguish the three states, so the row stays legible
//! without colour (`NO_COLOR`, monochrome terminals, colour-blind users).
//!
//! The row degrades in explicit tiers by the width it is given instead of
//! wrapping into its single row (which silently cut off the last steps):
//!
//! 1. [`ProgressTier::Full`]: every step with its label;
//! 2. [`ProgressTier::Compact`]: only the current step keeps its label, the
//!    others are glyph-only;
//! 3. [`ProgressTier::Minimal`]: plain text, `Step 3 of 8 · Secrets`.

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::theme::{BRASS, FOG, NIGHT};

/// One label per onboarding step. Each is the shortened wording of the
/// step's entry-screen title (`Secure your secrets` → `Secrets`,
/// `Background agents` → `Background`), so the row and the header never name
/// the same step differently.
pub(super) const STEPS: [&str; 8] = [
    "Welcome",
    "Name",
    "Secrets",
    "Provider",
    "Model",
    "Agent",
    "Background",
    "Ready",
];

pub(super) const DONE_MARK: &str = "\u{2713}"; // ✓
pub(super) const CURRENT_MARK: &str = "\u{25C6}"; // ◆
pub(super) const PENDING_MARK: &str = "\u{00B7}"; // ·

/// Gap between steps: two cells, so adjacent steps never run together.
const GAP: &str = "  ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProgressTier {
    Full,
    Compact,
    Minimal,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StepState {
    Done,
    Current,
    Pending,
}

impl StepState {
    fn of(index: usize, current: usize) -> Self {
        match index.cmp(&current) {
            std::cmp::Ordering::Less => Self::Done,
            std::cmp::Ordering::Equal => Self::Current,
            std::cmp::Ordering::Greater => Self::Pending,
        }
    }

    fn mark(self) -> &'static str {
        match self {
            Self::Done => DONE_MARK,
            Self::Current => CURRENT_MARK,
            Self::Pending => PENDING_MARK,
        }
    }

    fn style(self) -> Style {
        match self {
            Self::Done => Style::new().fg(FOG),
            Self::Current => Style::new().fg(BRASS).add_modifier(Modifier::BOLD),
            Self::Pending => Style::new().fg(NIGHT),
        }
    }
}

/// The progress row for step `current` (0-based index into [`STEPS`]) laid
/// out for `width` cells: the widest tier that fits. The minimal tier is
/// returned even when it overflows; the caller clips it without wrapping.
pub(super) fn progress_line(current: usize, width: u16) -> (ProgressTier, Line<'static>) {
    let current = current.min(STEPS.len() - 1);
    let width = usize::from(width);
    for tier in [ProgressTier::Full, ProgressTier::Compact] {
        let line = stepped_line(current, tier);
        if line.width() <= width {
            return (tier, line);
        }
    }
    (ProgressTier::Minimal, minimal_line(current))
}

fn stepped_line(current: usize, tier: ProgressTier) -> Line<'static> {
    let mut spans = Vec::with_capacity(STEPS.len() * 2);
    for (index, label) in STEPS.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw(GAP));
        }
        let state = StepState::of(index, current);
        let labelled = tier == ProgressTier::Full || state == StepState::Current;
        let text = if labelled {
            format!("{} {label}", state.mark())
        } else {
            state.mark().to_string()
        };
        spans.push(Span::styled(text, state.style()));
    }
    Line::from(spans)
}

fn minimal_line(current: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("Step {} of {} · ", current + 1, STEPS.len()),
            Style::new().fg(FOG),
        ),
        Span::styled(STEPS[current], StepState::Current.style()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn tiers_degrade_by_width_and_never_exceed_the_area() {
        // Secrets (index 2) at the widths the onboarding column gets on
        // 120/80/60/40-column terminals, plus a sub-40 column.
        let cases = [
            (86, ProgressTier::Full),
            (76, ProgressTier::Compact),
            (56, ProgressTier::Compact),
            (36, ProgressTier::Compact),
            (26, ProgressTier::Minimal),
        ];
        for (width, expected) in cases {
            let (tier, line) = progress_line(2, width);
            assert_eq!(tier, expected, "width {width}: {}", text(&line));
            assert!(line.width() <= usize::from(width), "width {width}");
        }
        assert_eq!(
            text(&progress_line(2, 86).1),
            "✓ Welcome  ✓ Name  ◆ Secrets  · Provider  · Model  · Agent  · Background  · Ready"
        );
        assert_eq!(
            text(&progress_line(2, 76).1),
            "✓  ✓  ◆ Secrets  ·  ·  ·  ·  ·"
        );
        assert_eq!(text(&progress_line(2, 26).1), "Step 3 of 8 · Secrets");
    }

    #[test]
    fn every_step_fits_its_tier_at_each_supported_terminal_width() {
        for current in 0..STEPS.len() {
            // Full needs the wide (120-column) layout; the 80-column
            // column must still carry the current label in compact form.
            assert_eq!(progress_line(current, 86).0, ProgressTier::Full);
            for width in [76, 56, 36] {
                let (tier, line) = progress_line(current, width);
                assert_eq!(tier, ProgressTier::Compact, "step {current} @ {width}");
                assert!(text(&line).contains(STEPS[current]));
            }
        }
    }

    #[test]
    fn states_are_distinguished_by_glyph_not_only_colour() {
        let (_, line) = progress_line(3, 76);
        let marks: Vec<&str> = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .filter(|content| !content.trim().is_empty())
            .map(|content| content.split(' ').next().unwrap())
            .collect();
        assert_eq!(
            marks,
            [
                DONE_MARK,
                DONE_MARK,
                DONE_MARK,
                CURRENT_MARK,
                PENDING_MARK,
                PENDING_MARK,
                PENDING_MARK,
                PENDING_MARK,
            ]
        );
        let distinct: std::collections::BTreeSet<_> = [DONE_MARK, CURRENT_MARK, PENDING_MARK]
            .into_iter()
            .collect();
        assert_eq!(distinct.len(), 3);
    }

    #[test]
    fn progress_glyphs_never_reuse_a_selection_glyph() {
        use crate::tui::chrome::{CHECK_OFF, CHECK_ON, RADIO_OFF, RADIO_ON};
        // Radio/checkbox glyphs, the half-filled marker the old row used,
        // and the list cursors the onboarding screens draw (`›` in search
        // and the Escape menu, `▸` in agent authoring).
        let selection = [
            RADIO_ON.trim(),
            RADIO_OFF.trim(),
            CHECK_ON.trim(),
            CHECK_OFF.trim(),
            "●",
            "◐",
            "›",
            "▸",
        ];
        for current in 0..STEPS.len() {
            for width in [120, 86, 76, 56, 36, 20] {
                let rendered = text(&progress_line(current, width).1);
                for glyph in selection {
                    assert!(
                        !rendered.contains(glyph),
                        "step {current} @ {width} reuses {glyph:?}: {rendered}"
                    );
                }
            }
        }
    }
}
