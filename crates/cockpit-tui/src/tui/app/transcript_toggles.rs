use super::*;

impl App {
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
