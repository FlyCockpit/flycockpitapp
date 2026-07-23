use super::*;

impl App {
    /// True while the current inference round is in its reasoning phase:
    /// no assistant text has started yet *and* we're either accumulating
    /// channel reasoning or mid an unclosed leading inline `<think>` block.
    /// Keyed off parser state (not `ThinkingStarted`, which fires for every
    /// round including non-thinking models), so a model that emits no
    /// reasoning never flips the indicator to yellow, while an inline
    /// `<think>` lights it on the open tag — gated on `strip_think`, since
    /// with stripping off a `<think>` tag is literal body, not reasoning.
    pub(super) fn in_thinking_block(&self) -> bool {
        self.pending.as_ref().is_some_and(|p| {
            p.text_started_at.is_none()
                && (!p.reasoning.trim().is_empty() || (p.strip_think && p.inside_think))
        })
    }

    /// Toggle every Ctrl+E reveal row: preflighted user messages reveal their
    /// original input, and compact boundaries reveal their handoff brief.
    pub(super) fn toggle_ctrl_e_reveals(&mut self) {
        let any_hidden = self.history.iter().any(|e| {
            matches!(e, HistoryEntry::User { cleaned: Some(_), expanded, .. } if !*expanded)
                || matches!(
                    e,
                    HistoryEntry::CompactBoundary {
                        handoff: Some(handoff),
                        expanded,
                        ..
                    } if !handoff.trim().is_empty() && !*expanded
                )
        });
        for entry in self.history.iter_mut() {
            match entry {
                HistoryEntry::User {
                    cleaned: Some(_),
                    expanded,
                    ..
                } => *expanded = any_hidden,
                HistoryEntry::CompactBoundary {
                    handoff: Some(handoff),
                    expanded,
                    ..
                } if !handoff.trim().is_empty() => *expanded = any_hidden,
                _ => {}
            }
        }
    }

    pub(super) fn toggle_recent_reasoning(&mut self) {
        let any_collapsed = self.history.iter().any(|entry| {
            matches!(entry,
                HistoryEntry::Agent { reasoning, expanded, .. }
                    if !reasoning.trim().is_empty() && !*expanded)
        });
        for entry in self.history.iter_mut() {
            if let HistoryEntry::Agent {
                expanded,
                reasoning,
                reasoning_offset,
                ..
            } = entry
                && !reasoning.trim().is_empty()
            {
                *expanded = any_collapsed;
                if !*expanded {
                    *reasoning_offset = 0;
                }
            }
        }
    }
}
