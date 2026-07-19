use super::*;

impl App {
    /// Build the tail of history as plain text lines for the post-
    /// alt-screen dump (GOALS §1d). Capped by `tui.exit_tail_lines`
    /// (default 100). `0` disables the dump entirely; `-1` returns
    /// the whole session. Returns an empty `Vec` when nothing should
    /// be printed.
    pub(super) fn build_exit_tail_lines(&mut self) -> Vec<String> {
        // Finalize any in-flight pending turn first so its text shows
        // up in the dump.
        self.finalize_pending();
        if self.history.is_empty() || self.exit_tail_lines == 0 {
            return Vec::new();
        }
        let plain: Vec<String> = self
            .history
            .iter()
            .flat_map(|entry| {
                let mut lines = entry_to_plain_lines(entry);
                // Match the chat-area visual: one blank row after
                // each user/agent block.
                if matches!(
                    entry,
                    HistoryEntry::User { .. } | HistoryEntry::Agent { .. }
                ) {
                    lines.push(String::new());
                }
                lines
            })
            .collect();
        let tail = if self.exit_tail_lines < 0 {
            plain
        } else {
            let n = self.exit_tail_lines as usize;
            if plain.len() > n {
                plain[plain.len() - n..].to_vec()
            } else {
                plain
            }
        };
        tail.into_iter()
            .map(|line| sanitize_for_raw_stdout(&line))
            .collect()
    }
}

/// Pull `(path, old, new)` out of an edit tool's args. Returns
/// `None` when any field is missing; the caller falls back to the
/// generic Plain rendering in that case.
fn entry_to_plain_lines(entry: &HistoryEntry) -> Vec<String> {
    match entry {
        HistoryEntry::Plain { line }
        | HistoryEntry::CommandError { line }
        | HistoryEntry::Maintenance { line } => vec![line.clone()],
        HistoryEntry::InterruptDecision { decision } => decision
            .lines
            .iter()
            .map(|line| {
                let answer = if decision.cancelled {
                    "dismissed"
                } else {
                    line.answer.as_str()
                };
                let prefix = if decision.permission {
                    "approval"
                } else {
                    "decision"
                };
                format!("{prefix}: {} → {answer}", line.prompt)
            })
            .collect(),
        HistoryEntry::InferenceError {
            summary,
            detail,
            expanded,
        } => {
            let mut out = vec![summary.clone()];
            if *expanded {
                let body = if detail.trim().is_empty() {
                    "No additional inference detail was recorded."
                } else {
                    detail.as_str()
                };
                for line in body.lines() {
                    out.push(format!("  {line}"));
                }
            }
            out
        }
        HistoryEntry::BackupWarning { line } | HistoryEntry::InferenceWarning { line } => {
            vec![line.clone()]
        }
        HistoryEntry::LocalCommand { label, output, .. } => {
            let mut out = vec![label.clone()];
            for line in output.lines() {
                out.push(format!("  {line}"));
            }
            out
        }
        HistoryEntry::ToolLine { tool, summary, .. } => {
            let (_, label) = crate::tui::history::tool_glyph_label(tool, false);
            vec![format!("  {label}: {summary}")]
        }
        HistoryEntry::ToolBox { calls, .. } => calls
            .iter()
            .map(|c| {
                let (_, label) = crate::tui::history::tool_glyph_label(&c.tool, false);
                format!("  {label}: {}", c.summary)
            })
            .collect(),
        HistoryEntry::Diff {
            tool,
            path,
            old,
            new,
        } => {
            // Plain-lines is what the "spill to scrollback" path uses
            // on `/new`. Reduce the diff to a tool-result-style
            // summary plus the textual diff body in unified form —
            // anything fancier would need ratatui Lines which the
            // plain-text dump can't render.
            let added = new.lines().count();
            let removed = old.lines().count();
            let mut out = vec![format!("  ✓ {tool}: {path} (+{added} −{removed})")];
            let diff = similar::TextDiff::from_lines(old.as_str(), new.as_str());
            for group in diff.grouped_ops(3) {
                if out.len() > 1 {
                    out.push("    …".to_string());
                }
                for op in group {
                    for change in diff.iter_changes(&op) {
                        let v = change.value().trim_end_matches('\n');
                        let prefix = match change.tag() {
                            similar::ChangeTag::Delete => "- ",
                            similar::ChangeTag::Insert => "+ ",
                            similar::ChangeTag::Equal => "  ",
                        };
                        out.push(format!("  {prefix}{v}"));
                    }
                }
            }
            out
        }
        HistoryEntry::User {
            text, timestamp, ..
        } => {
            let ts = timestamp.format("%H:%M").to_string();
            let mut out: Vec<String> = vec![format!("[{ts}] you:")];
            for line in text.split('\n') {
                out.push(format!("  {line}"));
            }
            out
        }
        HistoryEntry::UserNote {
            text, timestamp, ..
        } => {
            let ts = timestamp.format("%H:%M").to_string();
            let mut out: Vec<String> = vec![format!("[{ts}] note to self:")];
            for line in text.split('\n') {
                out.push(format!("  {line}"));
            }
            out
        }
        HistoryEntry::SkillAutoInjected { name, reason } => {
            let mut out = vec![format!("/{name} · injected by agent")];
            if let Some(r) = reason {
                out.push(format!("  └ {r}"));
            }
            out
        }
        HistoryEntry::Agent {
            name,
            text,
            reasoning,
            timestamp,
            expanded,
            ..
        } => {
            let ts = timestamp.format("%H:%M").to_string();
            let mut out: Vec<String> = vec![format!("[{ts}] {name}:")];
            if !reasoning.trim().is_empty() && *expanded {
                out.push("  thinking:".to_string());
                for raw in reasoning.lines() {
                    out.push(format!("    {raw}"));
                }
                out.push(String::new());
            }
            // A think-only turn has empty body text — emit just the
            // header (+ reasoning when expanded), never a blank body line.
            if !text.trim().is_empty() {
                for line in text.split('\n') {
                    out.push(format!("  {line}"));
                }
            }
            out
        }
        HistoryEntry::Subagent {
            parent,
            child,
            outcome,
            ..
        } => match outcome {
            // A still-running delegation spilled on `/new`: record the
            // delegation line without the (now-meaningless) live timer.
            None => vec![format!("{parent} delegated to {child}…")],
            Some(o) => {
                let verb = if o.failed {
                    "failed after"
                } else {
                    "worked for"
                };
                let header = format!(
                    "{child} {verb} {}",
                    crate::tui::history::format_compact_duration(o.duration)
                );
                let mut out = vec![header];
                if let Some(status) = &o.status {
                    out.push(format!("  {status}"));
                }
                for line in o.report.lines() {
                    out.push(format!("  {line}"));
                }
                out
            }
        },
        HistoryEntry::CompactBoundary {
            predecessor_short_id,
            seed_tool_count,
            source,
            tokens_before,
            tokens_after,
            tail_kept,
            tail_trimmed,
            handoff,
            expanded,
            ..
        } => {
            let mut lines = vec![format!(
                "compact: source={source} · from {predecessor_short_id} · tokens {tokens_before}→{tokens_after} · tail {tail_kept} kept/{tail_trimmed} trimmed · {seed_tool_count} seed-tool(s)"
            )];
            if *expanded
                && let Some(handoff) = handoff.as_deref().map(str::trim).filter(|s| !s.is_empty())
            {
                lines.extend(handoff.lines().map(|line| format!("    {line}")));
            }
            lines
        }
    }
}
