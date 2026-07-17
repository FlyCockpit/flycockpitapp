//! Rendering: every `render_*` method on `App` plus the small free
//! helpers they call (token formatting, wrap math, row-estimate, the
//! toast overlay). Cluster moved here so `mod.rs` reads as event-loop
//! plumbing instead of paragraph wrangling.

use std::borrow::Cow;
use std::collections::{HashMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::rc::Rc;
use std::time::Duration;

use super::Overlay;

use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::{border, merge::MergeStrategy};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::tui::chrome;
use crate::tui::composer::{
    INPUT_PREFIX, VimMode, display_width, input_prefix_width, truncate_display_width,
    visual_position_for_byte, wrap_display_chunks,
};
use crate::tui::geometry::{INPUT_BORDER, MAX_INPUT_CONTENT, MIN_INPUT_CONTENT, PaneGeometry};
use crate::tui::history::{
    AGENT_INDENT, HistoryEntry, Rendered, ToolCallState, agent_display_label,
    format_status_elapsed, render_entry, render_pending_incremental, thinking_dots_padded,
};
use crate::tui::theme::{
    BUSY_BORDER, CHIP_TEXT, DIVIDER_DIM, DIVIDER_FOCUSED, ERROR_TEXT, IDLE_BORDER, INFO_TEXT,
    MUTED_COLOR_INDEX, MUTED_TEXT, SHELL_MODE_BADGE_BG, SHELL_MODE_BORDER, SUCCESS_TEXT,
    TRANSCRIPT_HOVER_BG, WARNING_TEXT,
};

use super::{
    AUTOCOMPLETE_ROWS, AffordanceTarget, App, HistoryRenderCacheEntry, PaneSide, Selection,
    SuggestionBoxKind, SuggestionBoxRowHit, SuggestionBoxTarget, Toast, ToastKind, TranscriptFind,
    WORKING_MESSAGES,
};

/// Startup grace before the working indicator first appears — prevents
/// quick turns from flashing it on and off.
const STATUS_GRACE: Duration = Duration::from_secs(2);
/// A reasoning block must last at least this long before the indicator
/// flips from the working line to the yellow `Thinking` override.
const THINKING_FLIP_AFTER: Duration = Duration::from_secs(2);

/// The per-row render slices computed by the chat-layout pass: visible
/// lines plus one authoritative metadata record per visible row.
type VisibleRows = (Vec<Line<'static>>, Vec<ChatRowMeta>);

type ChatRows = (Vec<Line<'static>>, Vec<ChatRowMeta>, HashMap<usize, usize>);

pub(super) fn affordance_target_for_row(meta: &ChatRowMeta) -> Option<AffordanceTarget> {
    if let Some(history_index) = meta.subagent_target {
        return Some(AffordanceTarget::Subagent { history_index });
    }
    if let Some(history_index) = meta.chip_target {
        return Some(AffordanceTarget::Chip { history_index });
    }
    if let Some((history_index, call_index)) = meta.tool_call_target {
        return Some(AffordanceTarget::ToolCall {
            history_index,
            call_index,
        });
    }
    if let Some(history_index) = meta.reasoning_window_target {
        return Some(AffordanceTarget::ReasoningWindow { history_index });
    }
    meta.tool_box_target
        .map(|history_index| AffordanceTarget::ToolBox { history_index })
}

fn hover_highlight_full_line(line: &mut Line<'static>) {
    let hover = Style::default().bg(TRANSCRIPT_HOVER_BG);
    line.style = line.style.patch(hover);
    for span in &mut line.spans {
        span.style = span.style.patch(hover);
    }
}

fn push_hover_char(out: &mut Vec<Span<'static>>, ch: char, style: Style) {
    if let Some(last) = out.last_mut()
        && last.style == style
    {
        last.content.to_mut().push(ch);
        return;
    }
    out.push(Span::styled(ch.to_string(), style));
}

fn hover_highlight_range(
    line: &mut Line<'static>,
    hover_start: usize,
    hover_end: usize,
    pad_to: Option<usize>,
) {
    if hover_start >= hover_end {
        return;
    }

    let hover = Style::default().bg(TRANSCRIPT_HOVER_BG);
    let spans = std::mem::take(&mut line.spans);
    let mut patched = Vec::with_capacity(spans.len() + 3);
    let mut col = 0usize;

    for span in spans {
        for ch in span.content.chars() {
            let ch_width = ch.width().unwrap_or(0);
            let in_hover = col < hover_end && col.saturating_add(ch_width) > hover_start;
            let style = if in_hover {
                span.style.patch(hover)
            } else {
                span.style
            };
            push_hover_char(&mut patched, ch, style);
            col = col.saturating_add(ch_width);
        }
    }

    if let Some(pad_to) = pad_to {
        while col < pad_to {
            let style = if (hover_start..hover_end).contains(&col) {
                Style::default().patch(hover)
            } else {
                Style::default()
            };
            push_hover_char(&mut patched, ' ', style);
            col += 1;
        }
    }

    line.spans = patched;
}

fn hover_highlight_line(line: &mut Line<'static>, width: u16) {
    let width = width as usize;
    if width == 0 {
        return;
    }
    let mut hover_start = AGENT_INDENT.min(width);
    let mut hover_end = width.saturating_sub(AGENT_INDENT);
    if hover_start >= hover_end {
        hover_start = 0;
        hover_end = width;
    }
    hover_highlight_range(line, hover_start, hover_end, Some(width));
}

fn hover_highlight_control_chip(line: &mut Line<'static>, hit: PinHit) {
    hover_highlight_range(
        line,
        hit.col_start as usize,
        hit.col_end as usize,
        Some(hit.col_end as usize),
    );
}

fn control_chip_hit_for_row(meta: &ChatRowMeta, hovered: ControlChip) -> Option<PinHit> {
    match hovered {
        ControlChip::Fork { seq } => meta.fork_hit.filter(|hit| hit.seq == seq),
        ControlChip::Pin { seq } => meta.pin_hit.filter(|hit| hit.seq == seq),
    }
}

fn apply_hover_highlight(
    lines: &mut [Line<'static>],
    meta: &[ChatRowMeta],
    hovered: Option<AffordanceTarget>,
    hovered_control_chip: Option<ControlChip>,
    width: u16,
) {
    if hovered.is_none() && hovered_control_chip.is_none() {
        return;
    }
    for (line, meta) in lines.iter_mut().zip(meta) {
        if let Some(hit) =
            hovered_control_chip.and_then(|chip| control_chip_hit_for_row(meta, chip))
        {
            hover_highlight_control_chip(line, hit);
        } else if hovered.is_some_and(|target| affordance_target_for_row(meta) == Some(target)) {
            hover_highlight_line(line, width);
        }
    }
}

fn tool_call_state_id(state: ToolCallState) -> u8 {
    match state {
        ToolCallState::Processing => 0,
        ToolCallState::Success => 1,
        ToolCallState::Failed => 2,
        ToolCallState::BadCall => 3,
    }
}

fn thinking_display_id(value: crate::config::extended::ThinkingDisplay) -> u8 {
    match value {
        crate::config::extended::ThinkingDisplay::Condensed => 0,
        crate::config::extended::ThinkingDisplay::Hidden => 1,
        crate::config::extended::ThinkingDisplay::Verbose => 2,
    }
}

fn diff_style_id(value: crate::config::extended::DiffStyle) -> u8 {
    match value {
        crate::config::extended::DiffStyle::SideBySide => 0,
        crate::config::extended::DiffStyle::Inline => 1,
        crate::config::extended::DiffStyle::Hidden => 2,
    }
}

fn hash_len(hasher: &mut DefaultHasher, value: &str) {
    value.len().hash(hasher);
}

fn history_entry_render_fingerprint(entry: &HistoryEntry) -> u64 {
    let mut hasher = DefaultHasher::new();
    std::mem::discriminant(entry).hash(&mut hasher);
    match entry {
        HistoryEntry::User {
            text,
            cleaned,
            expanded,
            timestamp,
            seq,
            preflight_pending,
            persist_failed,
        } => {
            hash_len(&mut hasher, text);
            cleaned.hash(&mut hasher);
            expanded.hash(&mut hasher);
            timestamp.hash(&mut hasher);
            seq.hash(&mut hasher);
            preflight_pending.hash(&mut hasher);
            persist_failed.hash(&mut hasher);
        }
        HistoryEntry::Plain { line }
        | HistoryEntry::CommandError { line }
        | HistoryEntry::Maintenance { line }
        | HistoryEntry::BackupWarning { line }
        | HistoryEntry::InferenceWarning { line } => hash_len(&mut hasher, line),
        HistoryEntry::InterruptDecision { decision } => {
            decision.permission.hash(&mut hasher);
            decision.cancelled.hash(&mut hasher);
            decision.lines.len().hash(&mut hasher);
            for line in &decision.lines {
                hash_len(&mut hasher, &line.prompt);
                hash_len(&mut hasher, &line.answer);
            }
        }
        HistoryEntry::UserNote { text, timestamp } => {
            hash_len(&mut hasher, text);
            timestamp.hash(&mut hasher);
        }
        HistoryEntry::SkillAutoInjected { name, reason } => {
            hash_len(&mut hasher, name);
            reason.as_ref().map(|value| value.len()).hash(&mut hasher);
        }
        HistoryEntry::InferenceError {
            summary,
            detail,
            expanded,
        } => {
            hash_len(&mut hasher, summary);
            hash_len(&mut hasher, detail);
            expanded.hash(&mut hasher);
        }
        HistoryEntry::Agent {
            name,
            text,
            reasoning,
            timestamp,
            expanded,
            reasoning_offset,
            think_duration,
            seq,
        } => {
            hash_len(&mut hasher, name);
            hash_len(&mut hasher, text);
            hash_len(&mut hasher, reasoning);
            timestamp.hash(&mut hasher);
            expanded.hash(&mut hasher);
            reasoning_offset.hash(&mut hasher);
            think_duration.hash(&mut hasher);
            seq.hash(&mut hasher);
        }
        HistoryEntry::Diff {
            tool,
            path,
            old,
            new,
        } => {
            hash_len(&mut hasher, tool);
            hash_len(&mut hasher, path);
            hash_len(&mut hasher, old);
            hash_len(&mut hasher, new);
        }
        HistoryEntry::ToolBox {
            calls,
            view_offset,
            follow,
        } => {
            view_offset.hash(&mut hasher);
            follow.hash(&mut hasher);
            calls.len().hash(&mut hasher);
            for call in calls {
                hash_len(&mut hasher, &call.call_id);
                hash_len(&mut hasher, &call.tool);
                hash_len(&mut hasher, &call.summary);
                hash_len(&mut hasher, &call.full_input);
                hash_len(&mut hasher, &call.output);
                call.expanded.hash(&mut hasher);
                call.result_offset.hash(&mut hasher);
                tool_call_state_id(call.state).hash(&mut hasher);
                call.hint
                    .as_ref()
                    .map(|value| value.len())
                    .hash(&mut hasher);
            }
        }
        HistoryEntry::ToolLine {
            call_id,
            tool,
            summary,
            state,
        } => {
            hash_len(&mut hasher, call_id);
            hash_len(&mut hasher, tool);
            hash_len(&mut hasher, summary);
            tool_call_state_id(*state).hash(&mut hasher);
        }
        HistoryEntry::LocalCommand {
            label,
            output,
            failed,
        } => {
            hash_len(&mut hasher, label);
            hash_len(&mut hasher, output);
            failed.hash(&mut hasher);
        }
        HistoryEntry::Subagent {
            parent,
            child,
            task_call_id,
            label,
            trusted_only,
            model_trusted,
            routing,
            outcome,
            expanded,
            ..
        } => {
            hash_len(&mut hasher, parent);
            hash_len(&mut hasher, child);
            hash_len(&mut hasher, task_call_id);
            hash_len(&mut hasher, label);
            trusted_only.hash(&mut hasher);
            model_trusted.hash(&mut hasher);
            routing
                .model
                .as_ref()
                .map(|value| value.len())
                .hash(&mut hasher);
            routing
                .location
                .as_ref()
                .map(|value| value.len())
                .hash(&mut hasher);
            routing.fallback.hash(&mut hasher);
            expanded.hash(&mut hasher);
            match outcome {
                Some(outcome) => {
                    hash_len(&mut hasher, &outcome.report);
                    outcome.failed.hash(&mut hasher);
                    outcome.duration.hash(&mut hasher);
                    outcome
                        .status
                        .as_ref()
                        .map(|value| value.len())
                        .hash(&mut hasher);
                }
                None => 0usize.hash(&mut hasher),
            }
        }
        HistoryEntry::CompactBoundary {
            predecessor_short_id,
            seed_tool_count,
            seed_tool_tokens,
            source,
            tokens_before,
            tokens_after,
            tail_kept,
            tail_trimmed,
            handoff,
            expanded,
            result_offset,
            ..
        } => {
            hash_len(&mut hasher, predecessor_short_id);
            seed_tool_count.hash(&mut hasher);
            seed_tool_tokens.hash(&mut hasher);
            hash_len(&mut hasher, source);
            tokens_before.hash(&mut hasher);
            tokens_after.hash(&mut hasher);
            tail_kept.hash(&mut hasher);
            tail_trimmed.hash(&mut hasher);
            handoff.as_ref().map(|value| value.len()).hash(&mut hasher);
            expanded.hash(&mut hasher);
            result_offset.hash(&mut hasher);
        }
    }
    hasher.finish()
}

#[allow(clippy::too_many_arguments)]
fn history_render_signature(
    entry: &HistoryEntry,
    version: u64,
    width: u16,
    thinking: crate::config::extended::ThinkingDisplay,
    md: crate::tui::history::MarkdownOpts,
    diff_style: crate::config::extended::DiffStyle,
    emojis: bool,
    elided: &std::collections::HashSet<String>,
    preflight_dots_ms: u128,
    pin: Option<crate::tui::history::PinControl>,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    version.hash(&mut hasher);
    width.hash(&mut hasher);
    thinking_display_id(thinking).hash(&mut hasher);
    md.agent.hash(&mut hasher);
    md.user.hash(&mut hasher);
    diff_style_id(diff_style).hash(&mut hasher);
    emojis.hash(&mut hasher);

    if let HistoryEntry::User {
        preflight_pending: true,
        ..
    } = entry
    {
        ((preflight_dots_ms / 333) % 4).hash(&mut hasher);
    }

    if let HistoryEntry::Subagent {
        spawned_at,
        outcome: None,
        ..
    } = entry
    {
        let elapsed = spawned_at.elapsed();
        ((elapsed.as_millis() / 333) % 4).hash(&mut hasher);
        elapsed.as_secs().hash(&mut hasher);
    }

    if let HistoryEntry::ToolBox { calls, .. } = entry {
        let mut elided_ids: Vec<&str> = calls
            .iter()
            .filter_map(|call| {
                elided
                    .contains(&call.call_id)
                    .then_some(call.call_id.as_str())
            })
            .collect();
        elided_ids.sort_unstable();
        elided_ids.hash(&mut hasher);
    }

    pin.hash(&mut hasher);
    hasher.finish()
}

/// A clickable control-chip region on one chat row: the message seq plus
/// the half-open `[col_start, col_end)` column range of one visible chip.
/// The owning row records separate fork and pin regions (`pinned-messages`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinHit {
    pub seq: i64,
    pub col_start: u16,
    pub col_end: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlChip {
    Fork { seq: i64 },
    Pin { seq: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChatRowKind {
    Padding,
    Banner,
    Gap,
    Message,
    Chip,
    ToolBox,
    Diff,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChatCopyTarget {
    Message { history_index: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ToolResultScrollMeta {
    pub history_index: usize,
    pub call_index: usize,
    pub offset: usize,
    pub max_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReasoningScrollMeta {
    pub history_index: usize,
    pub offset: usize,
    pub max_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChatRowMeta {
    pub history_index: Option<usize>,
    pub row_kind: ChatRowKind,
    pub copy_target: Option<ChatCopyTarget>,
    pub chip_target: Option<usize>,
    pub subagent_target: Option<usize>,
    pub tool_box_target: Option<usize>,
    pub tool_call_target: Option<(usize, usize)>,
    pub tool_result_scroll: Option<ToolResultScrollMeta>,
    pub reasoning_window_scroll: Option<ReasoningScrollMeta>,
    pub reasoning_window_target: Option<usize>,
    pub diff_path: Option<String>,
    pub pin_hit: Option<PinHit>,
    pub fork_hit: Option<PinHit>,
    pub continuation: bool,
    pub selectable: bool,
}

impl ChatRowMeta {
    fn padding() -> Self {
        Self {
            history_index: None,
            row_kind: ChatRowKind::Padding,
            copy_target: None,
            chip_target: None,
            subagent_target: None,
            tool_box_target: None,
            tool_call_target: None,
            tool_result_scroll: None,
            reasoning_window_scroll: None,
            reasoning_window_target: None,
            diff_path: None,
            pin_hit: None,
            fork_hit: None,
            continuation: false,
            selectable: false,
        }
    }

    fn banner() -> Self {
        Self {
            row_kind: ChatRowKind::Banner,
            ..Self::padding()
        }
    }

    fn gap() -> Self {
        Self {
            row_kind: ChatRowKind::Gap,
            ..Self::padding()
        }
    }

    fn other() -> Self {
        Self {
            row_kind: ChatRowKind::Other,
            ..Self::padding()
        }
    }
}

fn copy_target_for_entry(entry: &HistoryEntry, history_index: usize) -> Option<ChatCopyTarget> {
    match entry {
        HistoryEntry::User { text, .. } | HistoryEntry::Agent { text, .. }
            if !text.trim().is_empty() =>
        {
            Some(ChatCopyTarget::Message { history_index })
        }
        _ => None,
    }
}

fn row_kind_for_entry(entry: &HistoryEntry) -> ChatRowKind {
    match entry {
        HistoryEntry::User { .. } | HistoryEntry::Agent { .. } => ChatRowKind::Message,
        HistoryEntry::ToolBox { .. } | HistoryEntry::CompactBoundary { .. } => ChatRowKind::ToolBox,
        HistoryEntry::Diff { .. } => ChatRowKind::Diff,
        _ => ChatRowKind::Other,
    }
}

impl App {
    pub(super) fn model_summary_history_line(&self) -> String {
        match &self.launch.active_model {
            Some((p, m)) => format!(
                "/model: active model is now {p}/{m}{}",
                if self.launch.active_model_is_favorite {
                    " (★)"
                } else {
                    ""
                }
            ),
            None => "/model: no active model".to_string(),
        }
    }

    pub(super) fn slash_query(&self) -> Option<&str> {
        let rest = self.composer.text().strip_prefix('/')?;
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        Some(&rest[..end])
    }

    pub(super) fn refresh_slash_menu_cache(&self) {
        if self.slash_query().is_none() {
            self.slash_menu_cache.borrow_mut().take();
            return;
        }
        if self.slash_menu_cache.borrow().is_some() {
            return;
        }
        *self.slash_menu_cache.borrow_mut() = Some(super::SlashMenuCache::build(self));
    }

    pub(super) fn slash_description_for(&self, command: &super::SlashCommand) -> String {
        self.refresh_slash_menu_cache();
        if let Some(cache) = self.slash_menu_cache.borrow().as_ref()
            && let Some(description) = cache.description_for(command)
        {
            return description.to_string();
        }
        command.description.to_string()
    }

    /// The frequency-ranked slash matches for the current query, or an
    /// empty list when no slash query is active. The returned list is the
    /// full match set; rendering applies the fixed visible window. The
    /// first entry is the auto-selected top match.
    ///
    /// Discovered skills surface as bare-`/<name>` entries alongside the
    /// builtins (implementation note); builtins rank first
    /// (they shadow any same-named skill — colliding skills were dropped from
    /// `skill_commands` at discovery), then skills in discovery order.
    pub(super) fn slash_suggestions(&self) -> Vec<super::SlashEntry<'_>> {
        match self.slash_query() {
            // While Tab-cycling, the composer holds a completed `/name`
            // but the candidate set stays anchored on the originally-typed
            // stem so the full match list remains visible to cycle through
            // (`slash-command-tab-completion.md`); otherwise match the live
            // query.
            Some(query) => {
                self.refresh_slash_menu_cache();
                let stem = self.slash_cycle_stem.as_deref().unwrap_or(query);
                let mut entries: Vec<super::SlashEntry<'_>> = self
                    .slash_menu_cache
                    .borrow()
                    .as_ref()
                    .map(|cache| super::slash_matches_in(&cache.builtins, stem, &self.usage_slash))
                    .unwrap_or_default()
                    .into_iter()
                    .map(super::SlashEntry::Builtin)
                    .collect();
                entries.extend(
                    self.skill_commands
                        .iter()
                        .filter(|s| s.name.starts_with(stem))
                        .map(super::SlashEntry::Skill),
                );
                entries
            }
            None => Vec::new(),
        }
    }

    /// True when the `@`-popup should be drawn: the composer reports an
    /// active `@partial` token and the user hasn't dismissed it via Esc.
    pub(super) fn at_popup_active(&self) -> bool {
        !self.at_dismissed && self.composer.at_query().is_some()
    }

    pub(super) fn at_suggestions(&self) -> Vec<crate::tui::file_tag::Suggestion> {
        let Some(q) = self.composer.at_query() else {
            self.at_cache.borrow_mut().take();
            return Vec::new();
        };
        // Memo hit: same query as last walk → reuse (cheap clone of a
        // bounded list; far cheaper than re-walking the tree).
        if let Some((cached_q, cached)) = self.at_cache.borrow().as_ref()
            && cached_q == q
        {
            return cached.clone();
        }
        // The read-allowlist re-includes gitignored-but-allowlisted entries
        // (implementation note); resolve the persisted
        // per-layer list for the cwd, then union the daemon-pushed session set
        // ("Approve for this session" approvals,
        // implementation note) so session-only
        // entries render exactly like persisted ones (dimmed, `gitignored`).
        let mut allow = crate::config::extended::resolve_gitignore_allow(&self.launch.cwd);
        allow.extend(self.gitignore_session_allow.clone());
        let walked =
            crate::tui::file_tag::suggestions(&self.launch.cwd, q, &self.usage_tags, &allow);
        *self.at_cache.borrow_mut() = Some((q.to_string(), walked.clone()));
        walked
    }

    pub(super) fn suggestion_box_lines(&self) -> u16 {
        if self.at_popup_active() {
            let rows = self.at_suggestions().len().min(AUTOCOMPLETE_ROWS as usize);
            if rows > 0 {
                return rows as u16 + 2;
            }
        }
        if self.slash_query().is_some() {
            let rows = self
                .slash_suggestions()
                .len()
                .min(AUTOCOMPLETE_ROWS as usize);
            if rows > 0 {
                return rows as u16 + 2;
            }
        }
        if self.show_vim_hint() { 3 } else { 0 }
    }

    /// True when the Normal-mode hint chip should occupy the popup
    /// strip. Hidden when the user has set `vim_mode` to `enabled`
    /// (advanced user; doesn't need the prompt) or `disabled` (vim
    /// off), and when the composer is in Insert mode.
    pub(super) fn show_vim_hint(&self) -> bool {
        self.vim_setting.show_hint()
            && self.composer.vim_enabled()
            && self.composer.vim_mode() == VimMode::Normal
    }

    /// Height of the queued-messages strip above the input box. Zero
    /// when nothing's queued; otherwise top border (1) + N messages +
    /// bottom border (1). Geometry overlaps that bottom border with
    /// the input's top border.
    pub(super) fn queue_lines(&self) -> u16 {
        if self.queue.is_empty() {
            0
        } else {
            2 + self.queue.len() as u16
        }
    }

    pub(super) fn input_height(&self) -> u16 {
        let (term_w, _) = crossterm::terminal::size().unwrap_or((80, 24));
        // Inner content width = terminal width - 2 side rails.
        let wrap_width = (term_w as usize).saturating_sub(2).max(1);
        let prefix = input_prefix_width();
        // Ghost text (implementation note): when a multi-line
        // `long` prediction has been expanded, the box grows to fit the
        // full grey response even though the composer buffer is still
        // empty. Otherwise the box sizes to the real (typed) content; a
        // collapsed/short ghost never grows the box (stays single-line).
        let text = self.composer.text();
        let measured: String = match self.prediction_state.ghost() {
            Some(g) if self.composer.is_empty() && g.box_expanded() => g.full_text().to_string(),
            _ => text.to_string(),
        };
        let visual = input_visual_rows(&measured, prefix, wrap_width);
        (visual as u16).clamp(MIN_INPUT_CONTENT, MAX_INPUT_CONTENT) + INPUT_BORDER
    }

    /// Elapsed time on the cumulative span clock, but only once the
    /// agent has been busy past the startup grace. `None` (→ indicator
    /// hidden) when idle or still inside the grace window.
    pub(super) fn status_span_elapsed(&self) -> Option<Duration> {
        if let Some(status) = &self.daemon_link {
            return Some(status.started_at.elapsed());
        }
        if !self.busy {
            return None;
        }
        let elapsed = self.span_started_at?.elapsed();
        (elapsed >= STATUS_GRACE).then_some(elapsed)
    }

    /// 1 when the working indicator should occupy a row above the queue
    /// strip, else 0.
    pub(super) fn indicator_lines(&self) -> u16 {
        u16::from(self.status_span_elapsed().is_some())
    }

    /// Render the "agent is working" status indicator. Ground state is
    /// the playful working line (muted, span clock); it flips to a
    /// yellow `Thinking` override only while the current reasoning block
    /// has itself lasted past [`THINKING_FLIP_AFTER`], reading as
    /// "working" otherwise so there are no blank gaps after the grace
    /// period. No-op when the indicator shouldn't show.
    pub(super) fn render_status_indicator(&self, frame: &mut ratatui::Frame, area: Rect) {
        let Some(span_elapsed) = self.status_span_elapsed() else {
            return;
        };
        let dots = thinking_dots_padded(self.started_at.elapsed().as_millis());
        let block_elapsed = self.pending.as_ref().map(|p| p.started_at.elapsed());
        let thinking =
            self.in_thinking_block() && block_elapsed.is_some_and(|e| e >= THINKING_FLIP_AFTER);

        if let Some(status) = &self.daemon_link {
            let text = daemon_link_status_text(
                status,
                &dots,
                &format_status_elapsed(status.started_at.elapsed()),
            );
            let line = Line::from(vec![
                Span::raw(" ".repeat(AGENT_INDENT)),
                Span::styled(
                    text,
                    Style::default()
                        .fg(WARNING_TEXT)
                        .add_modifier(Modifier::ITALIC),
                ),
            ]);
            frame.render_widget(Paragraph::new(line), area);
            return;
        }

        // A mid-retry network reconnect overrides everything else
        // (Thinking and the generic working line both): it's the most
        // informative state, signals the call isn't hung, and must never
        // fall back to the generic working spinner while a `Network`-class
        // retry loop is live. Names the unreachable provider/model/url + the
        // current attempt.
        if let Some(reconnect) = &self.reconnect {
            let text =
                reconnect_status_text(reconnect, &dots, &format_status_elapsed(span_elapsed));
            let line = Line::from(vec![
                Span::raw(" ".repeat(AGENT_INDENT)),
                Span::styled(
                    text,
                    Style::default()
                        .fg(WARNING_TEXT)
                        .add_modifier(Modifier::ITALIC),
                ),
            ]);
            frame.render_widget(Paragraph::new(line), area);
            return;
        }

        if let Some((parent, child, spawned_at)) =
            self.history.iter().rev().find_map(|entry| match entry {
                HistoryEntry::Subagent {
                    parent,
                    child,
                    spawned_at,
                    outcome: None,
                    ..
                } => Some((parent.as_str(), child.as_str(), *spawned_at)),
                _ => None,
            })
        {
            let delegate_elapsed = spawned_at.elapsed();
            let mut text = format!(
                "{parent} waiting on {}{} {}",
                agent_display_label(child),
                dots,
                format_status_elapsed(delegate_elapsed)
            );
            if !self.queue.is_empty() {
                text.push_str(&format!(" · {} queued", self.queue.len()));
            } else {
                text.push_str(" · parent continues after report");
            }
            let line = Line::from(vec![
                Span::raw(" ".repeat(AGENT_INDENT)),
                Span::styled(
                    text,
                    Style::default()
                        .fg(Color::Indexed(MUTED_COLOR_INDEX))
                        .add_modifier(Modifier::ITALIC),
                ),
            ]);
            frame.render_widget(Paragraph::new(line), area);
            return;
        }

        let (label, elapsed, color) = if thinking {
            (
                "Thinking",
                block_elapsed.unwrap_or(span_elapsed),
                WARNING_TEXT,
            )
        } else {
            let msg = WORKING_MESSAGES
                .get(self.working_msg_idx)
                .copied()
                .unwrap_or("Working");
            (msg, span_elapsed, Color::Indexed(MUTED_COLOR_INDEX))
        };
        let text = format!("{label}{dots} {}", format_status_elapsed(elapsed));
        let line = Line::from(vec![
            // Match the original in-body "Thinking…" placeholder's left
            // indent so the live status reads as a continuation of the
            // agent column rather than jumping a column.
            Span::raw(" ".repeat(AGENT_INDENT)),
            Span::styled(
                text,
                Style::default().fg(color).add_modifier(Modifier::ITALIC),
            ),
        ]);
        frame.render_widget(Paragraph::new(line), area);
    }

    pub(super) fn total_history_lines(&self) -> u16 {
        // We can't perfectly compute the rendered line count without
        // the area width, but the history geometry caller doesn't have
        // that yet either. Approximate: 1 row per Plain, 3 rows per
        // User (padding + body + padding; multi-line bodies cost more
        // but for sizing this is fine), 2 rows per Agent, plus pending.
        let mut total: u16 = 0;
        let mut prev_agent = false;
        for (idx, entry) in self.history.iter().enumerate() {
            total = total.saturating_add(match entry {
                HistoryEntry::Plain { .. }
                | HistoryEntry::CommandError { .. }
                | HistoryEntry::Maintenance { .. } => 1,
                HistoryEntry::InterruptDecision { decision } => u16::try_from(decision.lines.len())
                    .unwrap_or(u16::MAX)
                    .max(1),
                HistoryEntry::InferenceError {
                    detail, expanded, ..
                } => {
                    if *expanded {
                        detail.lines().count().max(1).saturating_add(1) as u16
                    } else {
                        1
                    }
                }
                HistoryEntry::BackupWarning { .. } | HistoryEntry::InferenceWarning { .. } => 1,
                HistoryEntry::CompactBoundary {
                    handoff, expanded, ..
                } => compact_boundary_row_estimate(handoff.as_deref(), *expanded).saturating_add(1),
                HistoryEntry::ToolLine { .. } => 2, // line + trailing gap
                HistoryEntry::LocalCommand { output, .. } => {
                    // label row + output rows + trailing gap.
                    (output.lines().count() as u16).saturating_add(2)
                }
                HistoryEntry::ToolBox { calls, .. } => {
                    toolbox_row_estimate(calls).saturating_add(1)
                }
                HistoryEntry::Diff { old, new, .. } => diff_row_estimate(old, new),
                HistoryEntry::User {
                    text,
                    cleaned,
                    expanded,
                    ..
                } => {
                    // Size against the *displayed* body: the cleaned form at
                    // rest, the original when revealed (`request-
                    // preflight.md`).
                    let shown = match cleaned {
                        Some(c) if !*expanded => c.as_str(),
                        _ => text.as_str(),
                    };
                    let body = shown.matches('\n').count() as u16 + 1;
                    // Bubble = top border + body + bottom border (+2);
                    // plus the trailing gap row inserted in render_history
                    // (+1) so the chat area gets sized to fit the box.
                    body.saturating_add(3)
                }
                HistoryEntry::UserNote { text, .. } => {
                    // Header row + one row per (unwrapped) body line + trailing
                    // gap. Wrapping costs more, but for sizing this is fine.
                    let body = text.matches('\n').count() as u16 + 1;
                    body.saturating_add(2)
                }
                // The `/{name} · injected by agent` row, plus the muted
                // `  └ <reason>` sub-line when a reason is present (single
                // logical line — wrapping costs more but, like the other
                // estimates here, that's fine for sizing). No trailing gap —
                // it hugs the user message it precedes.
                HistoryEntry::SkillAutoInjected { reason, .. } => 1 + reason.is_some() as u16,
                HistoryEntry::Agent {
                    text,
                    reasoning,
                    expanded,
                    ..
                } => {
                    let body = text.matches('\n').count() as u16 + 1;
                    // When reasoning is collapsed, the chip shares the
                    // first text row (see render_agent), so no extra
                    // chip row to count. When expanded, +1 for chip
                    // plus all the reasoning lines.
                    let mut rows = body;
                    if !reasoning.trim().is_empty() && *expanded {
                        rows = rows.saturating_add(1);
                        let reasoning_rows = reasoning.lines().count();
                        rows = rows.saturating_add(
                            reasoning_rows
                                .min(crate::tui::history::THINKING_VISIBLE)
                                .saturating_add(usize::from(
                                    reasoning_rows > crate::tui::history::THINKING_VISIBLE,
                                )) as u16,
                        );
                    }
                    // Trailing gap row after agent — skipped when the
                    // previous entry was also an agent and when an immediate
                    // ToolBox continues the assistant turn.
                    if !prev_agent
                        && !self
                            .history
                            .get(idx + 1)
                            .is_some_and(|next| matches!(next, HistoryEntry::ToolBox { .. }))
                    {
                        rows = rows.saturating_add(1);
                    }
                    rows
                }
                HistoryEntry::Subagent {
                    outcome, expanded, ..
                } => match outcome {
                    // Running: one live line + trailing gap.
                    None => 2,
                    // Settled: header + body lines (capped to the preview
                    // unless expanded) + possible expand chip + trailing gap.
                    Some(o) => {
                        let body = if o.report.trim().is_empty() {
                            0
                        } else {
                            let lines = o.report.lines().count() as u16;
                            if *expanded {
                                lines.saturating_add(1)
                            } else {
                                lines
                                    .min(crate::tui::history::SUBAGENT_PREVIEW_LINES as u16)
                                    .saturating_add(1)
                            }
                        };
                        body.saturating_add(2)
                    }
                },
            });
            prev_agent = matches!(entry, HistoryEntry::Agent { .. });
        }
        if self.pending.is_some() {
            total = total.saturating_add(1);
        }
        total
    }

    pub(super) fn render(&mut self, frame: &mut ratatui::Frame) {
        let geom = self.geometry();
        let rects = geom.layout(frame.area());
        if self.footer_agent_picker.is_none() && self.footer_mode_picker.is_none() {
            self.footer_picker_row_hits.clear();
        }

        if let Some(prompt) = self.daemon_prompt.as_ref() {
            prompt.render(frame, rects.body);
        } else if self.question_dialog.is_some() {
            // Answering dialog (GOALS §3b): a compact, bottom-anchored
            // overlay above the status row. History stays visible above
            // it (codex bottom-pane style), so render the chat into `body`
            // and the dialog into the `compact` slot. The dialog owns the
            // cursor while it's open.
            self.render_history(frame, rects.body);
            if let Some(dialog) = self.question_dialog.as_mut() {
                // Sync both body regions' scroll viewports to the real
                // overlay geometry so a long prompt and a long option list
                // each stay in view (region split, GOALS §3b). The terminal
                // height drives the Ctrl+E expanded cap.
                dialog.sync_viewport(rects.compact, frame.area().height);
                dialog.render(frame, rects.compact);
            }
        } else if self.dialog.is_active() {
            self.dialog
                .render(frame, rects.body, &mut self.link_registry);
        } else {
            let overlay = std::mem::take(&mut self.overlay);
            match overlay {
                Overlay::ModelPicker(mut picker) => {
                    picker.render(frame, rects.body);
                    self.overlay = Overlay::ModelPicker(picker);
                }
                Overlay::Multireview(dialog) => {
                    dialog.render(frame, rects.body);
                    self.overlay = Overlay::Multireview(dialog);
                }
                other if self.footer_agent_picker.is_some() => {
                    self.overlay = other;
                    self.render_footer_agent_picker(frame, rects.body);
                }
                other if self.footer_mode_picker.is_some() => {
                    self.overlay = other;
                    self.render_footer_mode_picker(frame, rects.body);
                }
                Overlay::Stats(mut pane) => {
                    pane.render(frame, rects.body);
                    self.overlay = Overlay::Stats(pane);
                }
                Overlay::Usage(mut pane) => {
                    pane.render(frame, rects.body);
                    self.overlay = Overlay::Usage(pane);
                }
                Overlay::Sessions(mut pane) => {
                    pane.render(frame, rects.body);
                    let preview_request = if pane.needs_preview_for_selection() {
                        match pane.ensure_preview_for_selection() {
                            Some(crate::tui::sessions_pane::SessionsOutcome::LoadPreview {
                                session_id,
                                before_seq,
                            }) => Some((session_id, before_seq)),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    self.overlay = Overlay::Sessions(pane);
                    if let Some((session_id, before_seq)) = preview_request {
                        self.start_sessions_preview_action(session_id, before_seq);
                    }
                }
                Overlay::Skills(mut pane) => {
                    pane.render(frame, rects.body);
                    self.overlay = Overlay::Skills(pane);
                }
                Overlay::Permissions(mut pane) => {
                    pane.render(frame, rects.body);
                    self.overlay = Overlay::Permissions(pane);
                }
                Overlay::Resources(mut pane) => {
                    pane.render(frame, rects.body);
                    self.overlay = Overlay::Resources(pane);
                }
                Overlay::Quick(dialog) => {
                    dialog.render(frame, rects.body);
                    self.overlay = Overlay::Quick(dialog);
                }
                Overlay::Context(mut pane) => {
                    pane.render(frame, rects.body);
                    self.overlay = Overlay::Context(pane);
                }
                Overlay::Notes(mut pane) => {
                    pane.render(frame, rects.body);
                    self.overlay = Overlay::Notes(pane);
                }
                Overlay::Diff(mut pane) => {
                    pane.render(frame, rects.body);
                    self.overlay = Overlay::Diff(pane);
                }
                Overlay::None => {
                    // Carve the body for an embedded pane (GOALS §1i) when one
                    // is open: fullscreen fills the body, splits divide it. The
                    // chat history renders into whatever's left (or nowhere when
                    // fullscreen). Returns the chat rect, or `None` if hidden.
                    let chat_rect = self.render_pane(frame, rects.body);
                    match chat_rect {
                        Some(chat) => self.render_history(frame, chat),
                        None => self.chat_area = None,
                    }
                    if geom.indicator > 0 {
                        self.render_status_indicator(frame, rects.indicator);
                    }
                    let cursor_pos = self.render_input(frame, rects.input);
                    if geom.queue > 0 {
                        self.render_queue(frame, rects.queue);
                    }
                    if geom.suggestions > 0 {
                        self.render_suggestion_box(frame, rects.suggestions);
                    } else {
                        self.clear_suggestion_box_hits();
                    }
                    // Below-input pin-count indicator (`pinned-messages`). Only
                    // shown when the session has ≥1 pin (geometry gives it a row).
                    if geom.pins > 0 {
                        self.render_pins_indicator(frame, rects.pins);
                    }
                    // Persistent below-input sandbox-down notice (§6.5). Shown while
                    // the shell sandbox can't initialize; geometry gives it rows.
                    // Persistent — it does not time out like a toast.
                    if geom.sandbox_notice > 0 {
                        self.render_sandbox_notice(frame, rects.sandbox_notice);
                    }
                    // Park the real cursor: in the focused pane (when the child
                    // shows one), otherwise in the composer.
                    if self.pane.is_some() && self.pane_focused {
                        if let (Some(rect), Some(pane)) = (self.pane_rect, self.pane.as_ref())
                            && let Some((x, y)) = pane.cursor_in(rect)
                        {
                            frame.set_cursor_position(Position::new(x, y));
                        }
                    } else {
                        frame.set_cursor_position(cursor_pos);
                    }
                }
            }
        }
        self.render_status(frame, rects.status);

        // Toast sits on top of the status line. Rendered before the
        // context menu / text popup so those still cover it if both
        // happen to be active at the same time.
        if let Some(toast) = self.toast.clone() {
            render_toast(frame, rects.status, &toast);
        }

        // `/pins` review checklist overlay (`pinned-messages`): a compact
        // bottom-anchored box listing the session's pinned messages, drawn
        // over the chat while review mode is open. The transcript jumps to
        // the highlighted pin underneath.
        if self.pins_review.is_some() {
            self.render_pins_review(frame, rects.body);
        }

        // Context menu overlay renders LAST so it sits on top of
        // every other pane. The Clear widget inside the renderer
        // wipes the cells under the overlay so the chat / status
        // line don't bleed through.
        if let Some(menu) = self.context_menu.as_ref() {
            crate::tui::context_menu::render_context_menu(frame, frame.area(), menu);
        }

        // Which-key overlay (`which-key-overlay.md`): a bottom-anchored,
        // scrollable, informational panel over the chat body. Rendered last so
        // it sits on top, but anchored to the body so the fixed chrome (status
        // line below, header above) is never permanently covered. Take/restore
        // to satisfy the borrow checker (its render is `&mut self`), like the
        // other panes. It's only ever open when no required-decision dialog is
        // up (the leader is guarded; `/keys` can't be typed during a dialog),
        // so it never obscures a required decision.
        if self.keys_overlay.is_some() {
            let mut overlay = self.keys_overlay.take();
            if let Some(o) = overlay.as_mut() {
                o.render(frame, rects.body);
            }
            self.keys_overlay = overlay;
        }
    }

    /// Render the below-input pin-count indicator (`pinned-messages`):
    /// `📌 N pinned · /pins to review`. Hidden by the geometry when the
    /// session has no pins.
    fn render_pins_indicator(&self, frame: &mut ratatui::Frame, area: Rect) {
        if area.height == 0 {
            return;
        }
        let n = self.pin_count;
        let glyph = if self.use_emojis { "📌 " } else { "" };
        let text = format!("{glyph}{n} pinned · /pins to review");
        let line = Line::from(vec![Span::styled(
            text,
            Style::default().fg(crate::tui::pins_overlay::PIN_YELLOW),
        )]);
        frame.render_widget(Paragraph::new(line), area);
    }

    /// Render the persistent below-input sandbox-down notice (`implementation notes`
    /// §6.5): a red, wrapped, model-independent remedy telling the user to run
    /// `/sandbox off` (plus the `sudo sysctl …=0` command when diagnosed). Stays
    /// until the sandbox is usable / dismissed — it does NOT time out like a
    /// toast. Hidden by the geometry when the sandbox is fine. Pure chrome:
    /// nothing here ever enters the model's context.
    fn render_sandbox_notice(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        self.sandbox_notice_copy_rect = None;
        self.auth_notice_switch_rect = None;
        self.auth_notice_fix_rect = None;
        if area.height == 0 {
            return;
        }
        let Some(text) = self.persistent_notice_text() else {
            return;
        };
        if self.auth_failure_notice.is_some()
            && self.mouse_capture
            && text.starts_with("[switch model] [fix provider] ")
            && area.width >= 31
        {
            self.auth_notice_switch_rect = Some(Rect::new(area.x.saturating_add(1), area.y, 14, 1));
            self.auth_notice_fix_rect = Some(Rect::new(area.x.saturating_add(16), area.y, 14, 1));
            let rest = text
                .strip_prefix("[switch model] [fix provider]")
                .unwrap_or(&text);
            let line = Line::from(vec![
                Span::styled(" ", Style::default().fg(ERROR_TEXT)),
                Span::styled(
                    "[switch model]",
                    Style::default().fg(Color::Black).bg(ERROR_TEXT),
                ),
                Span::raw(" "),
                Span::styled(
                    "[fix provider]",
                    Style::default().fg(Color::Black).bg(ERROR_TEXT),
                ),
                Span::styled(rest.to_string(), Style::default().fg(ERROR_TEXT)),
            ]);
            frame.render_widget(
                Paragraph::new(line).wrap(ratatui::widgets::Wrap { trim: true }),
                area,
            );
            return;
        }
        let has_copy_chip = self
            .sandbox_down_notice
            .as_ref()
            .and_then(|notice| notice.fix_command.as_ref())
            .is_some()
            && self.mouse_capture
            && text.starts_with("[copy] ")
            && area.width >= 7;
        let line = if has_copy_chip {
            self.sandbox_notice_copy_rect = Some(Rect::new(area.x.saturating_add(1), area.y, 6, 1));
            let rest = text.strip_prefix("[copy]").unwrap_or(&text);
            Line::from(vec![
                Span::styled(" ", Style::default().fg(ERROR_TEXT)),
                Span::styled("[copy]", Style::default().fg(Color::Black).bg(ERROR_TEXT)),
                Span::styled(rest.to_string(), Style::default().fg(ERROR_TEXT)),
            ])
        } else {
            Line::from(vec![Span::styled(
                super::sandbox_notice_render_text(&text),
                Style::default().fg(ERROR_TEXT),
            )])
        };
        let para = Paragraph::new(line).wrap(ratatui::widgets::Wrap { trim: true });
        frame.render_widget(para, area);
    }

    /// Render the `/pins` review checklist as a bottom-anchored overlay box
    /// over the chat body.
    fn render_pins_review(&self, frame: &mut ratatui::Frame, body: Rect) {
        let Some(review) = self.pins_review.as_ref() else {
            return;
        };
        let inner_w = body.width.saturating_sub(2);
        let lines = review.render_lines(inner_w);
        // Box height: content + top/bottom border, capped to the body.
        let want = (lines.len() as u16) + 2;
        let h = want.min(body.height.max(3));
        let w = body.width;
        let y = body.y + body.height.saturating_sub(h);
        let rect = Rect::new(body.x, y, w, h);
        frame.render_widget(ratatui::widgets::Clear, rect);
        let block = ratatui::widgets::Block::default()
            .borders(ratatui::widgets::Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(crate::tui::pins_overlay::PIN_YELLOW));
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    /// Border color for the composer/input box and the queue strip,
    /// keyed on busy + shell mode. Shell mode (leading `!`) tints green;
    /// while the agent is busy the border is a visibly-grey muted shade
    /// ([`BUSY_BORDER`]) signalling "hold off typing"; idle is
    /// white. Shared by `render_input` and `render_queue` so the two
    /// borders never drift. The queue strip has no shell mode and passes
    /// `shell_mode = false`.
    fn input_border_color(busy: bool, shell_mode: bool) -> Color {
        if shell_mode {
            SHELL_MODE_BORDER
        } else if busy {
            BUSY_BORDER
        } else {
            IDLE_BORDER
        }
    }

    const CONNECTED_INPUT_STRIP_BORDER_SET: border::Set<'static> = border::Set {
        top_left: "╭",
        top_right: "╮",
        bottom_left: "└",
        bottom_right: "┘",
        vertical_left: "│",
        vertical_right: "│",
        horizontal_top: "─",
        horizontal_bottom: "─",
    };

    /// Render a strip whose bottom border merges into the prompt input's
    /// top border. This is the reusable connected-box chrome for
    /// `tui-suggestion-box-above-input`; callers render the input block
    /// first, then this strip, so ratatui can collapse the overlap.
    fn render_connected_input_top_strip(
        frame: &mut ratatui::Frame,
        area: Rect,
        border_color: Color,
    ) -> Option<Rect> {
        if area.height < 2 || area.width < 5 {
            return None;
        }
        let strip = Rect::new(area.x + 1, area.y, area.width - 2, area.height);
        let content = Rect::new(
            strip.x + 1,
            strip.y + 1,
            strip.width.saturating_sub(2),
            strip.height.saturating_sub(2),
        );
        let block = Block::default()
            .borders(Borders::ALL)
            .border_set(Self::CONNECTED_INPUT_STRIP_BORDER_SET)
            .border_style(Style::default().fg(border_color))
            .merge_borders(MergeStrategy::Exact);
        frame.render_widget(block, strip);
        Some(content)
    }

    /// Queued-messages box. Inset one column from each side of the
    /// input box, with a bottom border that overlaps the input's top
    /// border and relies on ratatui border merging for the junctions.
    pub(super) fn render_queue(&self, frame: &mut ratatui::Frame, area: Rect) {
        if self.queue.is_empty() {
            return;
        }
        // Border tracks the input box: visibly-grey for the whole span
        // the agent is busy (matches the "agent is working, hold off"
        // cue on the input border), white when idle. No shell mode on
        // the queue strip, so it reuses the same helper with
        // `shell_mode = false`.
        let border_color = Self::input_border_color(self.busy, false);
        let Some(content_area) = Self::render_connected_input_top_strip(frame, area, border_color)
        else {
            return;
        };
        let queue_text_style = Style::default().fg(MUTED_TEXT);
        let non_foreground_style = queue_text_style.add_modifier(Modifier::DIM);
        let inner_w = content_area.width.saturating_sub(2).max(1) as usize;
        let mut lines: Vec<Line<'static>> = Vec::with_capacity(self.queue.len());

        for msg in &self.queue {
            let non_foreground = self
                .foreground_input_target
                .as_ref()
                .is_some_and(|target| msg.target.id != target.id);
            let style = if non_foreground {
                non_foreground_style
            } else {
                queue_text_style
            };
            let body = first_line_truncated(
                msg.display_text
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .unwrap_or(&msg.text),
                inner_w,
            );
            let body_w = display_width(&body);
            let annotation = if non_foreground {
                let remaining = inner_w.saturating_sub(body_w);
                if remaining > 0 {
                    first_line_truncated(&format!(" · {}", msg.target.agent), remaining)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            let annotation_w = display_width(&annotation);
            let trailing = inner_w.saturating_sub(body_w + annotation_w);
            let mut spans = vec![Span::raw(" "), Span::styled(body, style)];
            if !annotation.is_empty() {
                spans.push(Span::styled(annotation, style));
            }
            spans.extend([Span::raw(" ".repeat(trailing)), Span::raw(" ")]);
            lines.push(Line::from(spans));
        }

        frame.render_widget(Paragraph::new(lines), content_area);
    }

    /// Build the launch-banner box lines for the current pane, or an
    /// empty `Vec` when the banner is suppressed or doesn't fit. See
    /// [`crate::tui::banner_box`].
    fn banner_box_lines(&self, pane_w: u16, pane_h: u16) -> Vec<Line<'static>> {
        crate::tui::banner_box::build(&self.launch, pane_w, pane_h).unwrap_or_default()
    }

    pub(super) fn refresh_transcript_find_matches(&mut self) {
        let top = self.visible_chat_top_line();
        let Some(find) = self.transcript_find.as_mut() else {
            return;
        };
        find.matches.clear();
        find.current = None;
        if find.query.is_empty() {
            return;
        }
        let query = find.query.to_lowercase();
        find.matches = self
            .chat_find_lines
            .iter()
            .enumerate()
            .filter_map(|(idx, line)| line.to_lowercase().contains(&query).then_some(idx))
            .collect();
        if find.matches.is_empty() {
            return;
        }
        let current = find
            .matches
            .iter()
            .position(|line| *line >= top)
            .unwrap_or(0);
        find.current = Some(current);
        let abs = find.matches[current];
        self.scroll_abs_line_into_view(abs);
    }

    pub(super) fn sync_history_render_versions(&mut self) {
        if self.history_render_versions.len() > self.history.len() {
            self.history_render_versions.truncate(self.history.len());
            self.history_render_fingerprints
                .truncate(self.history.len());
            self.history_render_cache
                .retain(|idx, _| *idx < self.history.len());
        }

        for idx in 0..self.history.len() {
            let fingerprint = history_entry_render_fingerprint(&self.history[idx]);
            if idx >= self.history_render_versions.len() {
                self.history_render_versions
                    .push(self.next_history_render_version);
                self.history_render_fingerprints.push(fingerprint);
                self.next_history_render_version = self.next_history_render_version.wrapping_add(1);
                if self.next_history_render_version == 0 {
                    self.next_history_render_version = 1;
                }
                continue;
            }

            if self.history_render_fingerprints[idx] != fingerprint {
                self.history_render_versions[idx] = self.next_history_render_version;
                self.history_render_fingerprints[idx] = fingerprint;
                self.next_history_render_version = self.next_history_render_version.wrapping_add(1);
                if self.next_history_render_version == 0 {
                    self.next_history_render_version = 1;
                }
            }
        }
    }

    pub(super) fn render_history(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        self.chat_area = Some(area);
        let area_h = area.height as usize;
        self.sync_history_render_versions();
        let previous_top = if self.chat_scroll_offset > 0 {
            Some(chat_visible_top(
                self.chat_total_lines,
                self.chat_visible_lines.max(1),
                self.chat_scroll_offset,
            ))
        } else {
            None
        };

        let mut all: Vec<Line<'static>> = Vec::new();
        let mut row_meta: Vec<ChatRowMeta> = Vec::new();
        // Absolute content line (in `all`) of each pinnable message's first
        // row, by history index — drives the pick arrow + review jump.
        let mut msg_abs_line: std::collections::HashMap<usize, usize> =
            std::collections::HashMap::new();
        for (idx, entry) in self.history.iter().enumerate() {
            // Pinned-message chrome (`pinned-messages`): the pick-mode arrow
            // (when this entry is the pick selection) and/or the clickable
            // mouse controls (`[fork]` + `[pin]`/`[unpin]`, only when mouse
            // mode is on) ride the message itself — inline left of the
            // timestamp for an agent reply, in the top-right border corner
            // for a user bubble. They cost no separate vertical space.
            // The entry's first content line is the next row we push.
            msg_abs_line.insert(idx, all.len());
            let pin = Self::entry_pin_seq(entry).and_then(|seq| {
                let is_pick = self
                    .pin_pick
                    .as_ref()
                    .is_some_and(|p| p.selected_history_index() == idx)
                    || self
                        .fork_pick
                        .as_ref()
                        .is_some_and(|p| p.selected_history_index() == idx)
                    || self
                        .copy_pick_selected_history_index()
                        .is_some_and(|selected| selected == idx);
                let show_control = self.mouse_capture;
                (is_pick || show_control).then_some(crate::tui::history::PinControl {
                    seq,
                    pinned: self.is_seq_pinned_for_render(seq),
                    show_control,
                    is_pick,
                })
            });
            let entry_base = all.len();
            let preflight_dots_ms = self.started_at.elapsed().as_millis();
            let version = self.history_render_versions[idx];
            let sig = history_render_signature(
                entry,
                version,
                area.width,
                self.thinking_setting,
                self.markdown_opts,
                self.diff_style,
                self.use_emojis,
                &self.elided_event_ids,
                preflight_dots_ms,
                pin,
            );
            let rendered = match self.history_render_cache.get(&idx) {
                Some(cached) if cached.sig == sig => Rc::clone(&cached.rendered),
                _ => {
                    let rendered = Rc::new(render_entry(
                        entry,
                        area.width,
                        self.thinking_setting,
                        self.markdown_opts,
                        self.diff_style,
                        self.use_emojis,
                        &self.elided_event_ids,
                        // Same continuously-advancing clock the busy/Thinking spinner
                        // reads, so a preflight-pending row's `Preflight...` dots animate
                        // each 100ms tick (implementation note).
                        preflight_dots_ms,
                        pin,
                    ));
                    self.history_render_cache.insert(
                        idx,
                        HistoryRenderCacheEntry {
                            sig,
                            rendered: Rc::clone(&rendered),
                        },
                    );
                    rendered
                }
            };
            let Rendered {
                lines,
                chip_row,
                continuations,
                tool_call_rows,
                tool_result_scroll_regions,
                reasoning_scroll_region,
                pin_region,
            } = rendered.as_ref();
            let chip_abs = chip_row.map(|cr| all.len() + cr);
            // The clickable pin region (when drawn) lands on `pin_region.row`
            // within this entry's lines — offset into the `all` buffer.
            let pin_abs = pin_region.map(|r| entry_base + r.row);
            let is_box = matches!(entry, HistoryEntry::ToolBox { .. });
            let diff_path = match entry {
                HistoryEntry::Diff { path, .. } => Some(path.clone()),
                _ => None,
            };
            let base_copy = copy_target_for_entry(entry, idx);
            let base_kind = row_kind_for_entry(entry);
            for i in 0..lines.len() {
                let chip_target = if Some(all.len() + i) == chip_abs {
                    Some(idx)
                } else {
                    None
                };
                let subagent_target = if i == 0 && matches!(entry, HistoryEntry::Subagent { .. }) {
                    Some(idx)
                } else {
                    None
                };
                let pin_hit = match pin_region {
                    Some(r) if Some(all.len() + i) == pin_abs => Some(PinHit {
                        seq: r.seq,
                        col_start: r.col_start,
                        col_end: r.col_end,
                    }),
                    _ => None,
                };
                let fork_hit = match pin_region {
                    Some(r) if Some(all.len() + i) == pin_abs => {
                        match (r.fork_col_start, r.fork_col_end) {
                            (Some(col_start), Some(col_end)) => Some(PinHit {
                                seq: r.seq,
                                col_start,
                                col_end,
                            }),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                let row_kind = if chip_target.is_some() || subagent_target.is_some() {
                    ChatRowKind::Chip
                } else {
                    base_kind
                };
                row_meta.push(ChatRowMeta {
                    history_index: Some(idx),
                    row_kind,
                    copy_target: if row_kind == ChatRowKind::Chip {
                        None
                    } else {
                        base_copy
                    },
                    chip_target,
                    subagent_target,
                    tool_box_target: is_box.then_some(idx),
                    tool_call_target: tool_call_rows
                        .get(i)
                        .and_then(|call_index| call_index.map(|call_index| (idx, call_index))),
                    tool_result_scroll: tool_result_scroll_regions
                        .iter()
                        .find(|region| i >= region.row_start && i <= region.row_end)
                        .map(|region| ToolResultScrollMeta {
                            history_index: idx,
                            call_index: region.call_index,
                            offset: region.offset,
                            max_offset: region.max_offset,
                        }),
                    reasoning_window_scroll: reasoning_scroll_region
                        .filter(|region| i >= region.row_start && i <= region.row_end)
                        .map(|region| ReasoningScrollMeta {
                            history_index: idx,
                            offset: region.offset,
                            max_offset: region.max_offset,
                        }),
                    reasoning_window_target: reasoning_scroll_region
                        .filter(|region| i >= region.row_start && i <= region.row_end)
                        .map(|_| idx),
                    diff_path: diff_path.clone(),
                    pin_hit,
                    fork_hit,
                    continuation: false,
                    selectable: row_kind != ChatRowKind::Chip,
                });
            }
            // Each entry's renderer returns one bool per emitted line;
            // pad if there's any mismatch (defensive — shouldn't
            // happen but keeps the parallel arrays in lockstep).
            let mut entry_conts = continuations.clone();
            entry_conts.resize(lines.len(), false);
            for (meta, continuation) in row_meta[entry_base..].iter_mut().zip(entry_conts) {
                meta.continuation = continuation;
            }
            all.extend(lines.iter().cloned());
            // One-line gap after a block so it separates from what
            // follows. Consecutive agents share a block, and an immediate
            // ToolBox continues the assistant turn without an inter-entry gap.
            let gap = match entry {
                HistoryEntry::User { .. }
                | HistoryEntry::ToolBox { .. }
                | HistoryEntry::ToolLine { .. }
                | HistoryEntry::CompactBoundary { .. } => true,
                // An auto-injected-skill row hugs the user message it was
                // injected ahead of — no separating gap (it falls through to
                // the `_ => false` default, called out here for the reader).
                HistoryEntry::SkillAutoInjected { .. } => false,
                HistoryEntry::Agent { .. } => {
                    !idx.checked_sub(1)
                        .map(|i| matches!(self.history[i], HistoryEntry::Agent { .. }))
                        .unwrap_or(false)
                        && !self
                            .history
                            .get(idx + 1)
                            .is_some_and(|next| matches!(next, HistoryEntry::ToolBox { .. }))
                }
                // Settled subagent block gets a trailing gap; the live
                // running line gets none (so it doesn't jump when it
                // settles in place).
                HistoryEntry::Subagent { outcome, .. } => outcome.is_some(),
                _ => false,
            };
            if gap {
                all.push(Line::default());
                row_meta.push(ChatRowMeta::gap());
            }
        }
        if let Some(pending) = &self.pending {
            let cache = self
                .pending_render_cache
                .get_or_insert_with(Default::default);
            let pending_lines = render_pending_incremental(pending, area.width, &mut cache.state);
            for _ in 0..pending_lines.len() {
                row_meta.push(ChatRowMeta::other());
            }
            all.extend(pending_lines);
        } else {
            self.pending_render_cache = None;
        }
        self.history_render_cache
            .retain(|idx, _| *idx < self.history.len());

        if let Some(view) = self.active_subagent_view() {
            if let Some(line) = self.active_subagent_countdown_line() {
                row_meta.push(ChatRowMeta::other());
                all.push(Line::from(vec![Span::styled(
                    line,
                    Style::default()
                        .fg(WARNING_TEXT)
                        .add_modifier(Modifier::ITALIC),
                )]));
            } else if let Some(notice) = &view.notice {
                row_meta.push(ChatRowMeta::other());
                all.push(Line::from(vec![Span::styled(
                    notice.clone(),
                    Style::default()
                        .fg(Color::Indexed(MUTED_COLOR_INDEX))
                        .add_modifier(Modifier::ITALIC),
                )]));
            }
        }

        let (all, row_meta, msg_abs_line) =
            prewrap_chat_rows(all, row_meta, msg_abs_line, area.width as usize);
        // Record the abs-line map for pick/review jump after wrapping so
        // pinned messages target the visual row model used for scrolling.
        self.msg_abs_line = msg_abs_line;

        // The launch-banner box is the topmost scroll entry. Before the first
        // transcript message it centers against a stable frame-height
        // baseline, immune to transient bottom chrome. Once history exists it
        // retains the original centered/slide-up/scroll-off behavior.
        let box_lines = self.banner_box_lines(area.width, area.height);
        let b = box_lines.len();
        let m = all.len();

        // Total scrollable content height, box included — drives the
        // mouse-wheel scrollback clamp.
        self.chat_total_lines = b + m;
        self.chat_visible_lines = area_h;
        self.chat_banner_lines = b;

        if self.transcript_find.is_some() {
            self.chat_find_lines = box_lines
                .iter()
                .chain(all.iter())
                .map(rendered_line_text)
                .collect();
            self.refresh_transcript_find_matches();
        } else {
            self.chat_find_lines.clear();
        }

        let (visible, visible_meta): VisibleRows = if b > 0 && b + m <= area_h {
            // Fits with room to spare: messages stay bottom-aligned and
            // the box floats at the vertical center, sliding up to sit
            // directly above the messages once they'd reach it. Content
            // fits, so there's no scrollback.
            self.chat_scroll_offset = 0;
            let centered_top = if m == 0 {
                let baseline_h = PaneGeometry::baseline_body_height(frame.area().height) as usize;
                baseline_h.saturating_sub(b) / 2
            } else {
                (area_h - b) / 2
            };
            let box_top = centered_top.min(area_h - m - b);
            let msg_top = area_h - m;
            let mut v: Vec<Line<'static>> = (0..area_h).map(|_| Line::default()).collect();
            let mut meta: Vec<ChatRowMeta> = vec![ChatRowMeta::padding(); area_h];
            for (i, line) in box_lines.into_iter().enumerate() {
                v[box_top + i] = line;
                meta[box_top + i] = ChatRowMeta::banner();
            }
            for (i, line) in all.into_iter().enumerate() {
                v[msg_top + i] = line;
            }
            for (i, val) in row_meta.into_iter().enumerate() {
                meta[msg_top + i] = val;
            }
            (v, meta)
        } else {
            // No box, or box + messages overflow the pane: the box is
            // the top of one contiguous, bottom-aligned scroll buffer
            // and scrolls off the top with the oldest messages. Box rows
            // are non-interactive (None / false). With no box this is
            // exactly the previous behavior over `all`.
            let mut combined = box_lines;
            let prefix = combined.len();
            combined.extend(all);
            let mut combined_meta = vec![ChatRowMeta::banner(); prefix];
            combined_meta.extend(row_meta);

            let total = combined.len();
            let max_offset = total.saturating_sub(area_h);
            if let Some(top) = previous_top {
                self.chat_scroll_offset = chat_offset_for_top(total, area_h, top);
            } else if self.chat_scroll_offset > max_offset {
                self.chat_scroll_offset = max_offset;
            }

            if total < area_h {
                let pad = area_h - total;
                let mut v: Vec<Line<'static>> = (0..pad).map(|_| Line::default()).collect();
                let mut meta: Vec<ChatRowMeta> = vec![ChatRowMeta::padding(); pad];
                v.extend(combined);
                meta.extend(combined_meta);
                (v, meta)
            } else {
                let drop = total - area_h - self.chat_scroll_offset;
                let v: Vec<Line<'static>> = combined.into_iter().skip(drop).take(area_h).collect();
                let meta: Vec<ChatRowMeta> =
                    combined_meta.into_iter().skip(drop).take(area_h).collect();
                (v, meta)
            }
        };
        self.chat_row_meta = visible_meta;
        self.clickable_rows = self.chat_row_meta.iter().map(|m| m.chip_target).collect();
        self.box_rows = self
            .chat_row_meta
            .iter()
            .map(|m| m.tool_box_target)
            .collect();
        self.diff_rows = self
            .chat_row_meta
            .iter()
            .map(|m| m.diff_path.clone())
            .collect();
        self.chat_cont_rows = self.chat_row_meta.iter().map(|m| m.continuation).collect();
        self.pin_control_rows = self.chat_row_meta.iter().map(|m| m.pin_hit).collect();
        self.affordance_scroll_regions = self.build_affordance_scroll_regions();

        let mut visible = visible;
        apply_hover_highlight(
            &mut visible,
            &self.chat_row_meta,
            self.hovered_affordance,
            self.hovered_control_chip,
            area.width,
        );
        frame.render_widget(Paragraph::new(visible), area);
        if self.selection.is_some() || self.transcript_find.is_some() {
            // Snapshot the content layer before overlay chrome is rendered.
            // Selection copy must match selectable chat content, not scroll
            // indicators or find UI drawn on top of the paragraph.
            self.chat_text_grid = capture_grid(frame.buffer_mut(), area);
        } else {
            self.chat_text_grid.clear();
        }

        if self.find_owns_bottom_row() {
            render_transcript_find_bar(
                frame.buffer_mut(),
                area,
                self.transcript_find.as_ref(),
                Style::default()
                    .fg(Color::Indexed(MUTED_COLOR_INDEX))
                    .add_modifier(Modifier::DIM),
            );
        } else {
            render_chat_scroll_indicator(
                frame.buffer_mut(),
                area,
                self.chat_scroll_offset,
                self.busy || self.pending.is_some(),
                Style::default()
                    .fg(Color::Indexed(MUTED_COLOR_INDEX))
                    .add_modifier(Modifier::DIM),
            );
        }

        if let Some(find) = self.transcript_find.as_ref() {
            apply_transcript_find_highlight(
                frame.buffer_mut(),
                area,
                find,
                self.chat_total_lines,
                self.chat_visible_lines,
                self.chat_scroll_offset,
                &self.chat_find_lines,
            );
        }

        if let Some(sel) = self.selection {
            // Skip chip rows from highlight: visually, the
            // "▶ thought for Xs (ctrl+t to expand)" line is a
            // control affordance, not message content. Building
            // the bool mask here so apply_selection_highlight stays
            // a free function.
            let chip_row_mask: Vec<bool> = self
                .chat_row_meta
                .iter()
                .map(|meta| !meta.selectable)
                .collect();
            apply_selection_highlight(
                frame.buffer_mut(),
                area,
                sel,
                &chip_row_mask,
                &self.chat_text_grid,
            );
        }
    }

    fn history_position_label(&self) -> Option<String> {
        if self.prompt_history_cursor == 0 || self.prompt_history.is_empty() {
            return None;
        }
        let total = self.prompt_history.len();
        let current = total
            .saturating_sub(self.prompt_history_cursor)
            .saturating_add(1);
        Some(format!("History: {current}/{total}"))
    }

    pub(super) fn render_input(&mut self, frame: &mut ratatui::Frame, area: Rect) -> Position {
        // Stash for the mouse handler so a click can route to
        // click-to-position-cursor (plan.md T8.d).
        self.input_area = Some(area);
        // Visibly-grey border for the whole span the agent is busy;
        // white when idle. Gated on `busy` (not `pending.is_some()`) so
        // it stays dim across reasoning, streaming, AND tool execution —
        // `pending` drops to `None` between tool rounds, which used to
        // flicker the border white mid-turn. BUSY_BORDER_INDEX is a
        // mid-grey: clearly dimmer than white so the "agent is working,
        // hold off typing" signal reads as muted, but never near-black/
        // invisible against the surrounding chrome.
        // Shell mode (GOALS §1k): a leading `!` swaps the top border for
        // a "shell mode" label and tints the border green. Leaves the
        // moment the `!` is gone.
        let shell_mode = self.composer.text().starts_with('!');
        let border_color = Self::input_border_color(self.busy, shell_mode);
        let mut input_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border_color));
        if let Some(label) = self.history_position_label() {
            input_block = input_block.title(Line::from(Span::styled(
                format!(" {label} "),
                Style::default()
                    .fg(Color::Indexed(255))
                    .add_modifier(Modifier::BOLD),
            )));
        } else if shell_mode {
            input_block = input_block.title(Line::from(Span::styled(
                " shell mode ",
                Style::default()
                    .fg(Color::Black)
                    .bg(SHELL_MODE_BADGE_BG)
                    .add_modifier(Modifier::BOLD),
            )));
        }
        let input_inner = input_block.inner(area);

        let prefix_width = input_prefix_width();
        let indent: String = " ".repeat(prefix_width);
        let text = self.composer.text();
        let buf_lines: Vec<&str> = if text.is_empty() {
            vec![""]
        } else {
            text.split('\n').collect()
        };
        // Pre-wrap the composer text ourselves so the rendered visual
        // rows match what `cursor_visual_pos` assumes — `Paragraph::
        // wrap`'s word-wrap algorithm doesn't have a clean way to
        // report the cursor's position back to us, so the two sides
        // would otherwise drift apart on wrapped input.
        let inner_w = input_inner.width as usize;
        let context_chip = self.passive_context_indicator(input_inner);
        let passive_ghost = text.is_empty()
            && self
                .prediction_state
                .ghost()
                .is_some_and(|g| !g.box_expanded());
        let budget = inner_w.saturating_sub(prefix_width).max(1);
        let first_row_budget = if passive_ghost {
            context_chip
                .as_ref()
                .map(|chip| {
                    chip.x
                        .saturating_sub(input_inner.x)
                        .saturating_sub(prefix_width as u16) as usize
                })
                .unwrap_or(budget)
                .max(1)
        } else {
            budget
        };
        let mut lines: Vec<Line<'static>> = Vec::new();
        // Ghost text (implementation note): when the box is
        // empty and a prediction is pending, render the prediction grey
        // (muted) after the prompt prefix — the first line while a
        // multi-line `long` prediction is collapsed, the whole prediction
        // once expanded. The real cursor stays at the start (row 0, just
        // past the prefix); typing or Tab dismisses the ghost.
        let ghost_display = if text.is_empty() {
            self.prediction_state.ghost().map(|g| g.display_text())
        } else {
            None
        };
        if let Some(ghost) = ghost_display {
            let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
            for (li, gline) in ghost.split('\n').enumerate() {
                let chunks = wrap_ghost_line_chunks(
                    gline,
                    budget,
                    if li == 0 { first_row_budget } else { budget },
                );
                for (ci, (start, end, _, _)) in chunks.iter().enumerate() {
                    let chunk_text = gline[*start..*end].to_string();
                    let pre = if li == 0 && ci == 0 {
                        INPUT_PREFIX
                    } else {
                        indent.as_str()
                    };
                    lines.push(Line::from(vec![
                        Span::styled(pre.to_string(), Style::default().fg(Color::White)),
                        Span::styled(chunk_text, muted),
                    ]));
                }
            }
        }
        // Byte offset of the start of the current logical line within the
        // full buffer — used to map a wrapped chunk back to absolute byte
        // ranges so paste-block placeholders render with a distinct style
        // (composer-paste-handling). Lines are split on '\n', so each
        // separator adds one byte.
        let mut line_byte_start = 0usize;
        for (li, line) in buf_lines.iter().enumerate() {
            // When a ghost is rendered the empty real-buffer line is
            // already represented by the ghost's first row (the cursor
            // sits on it); don't also push a blank white line.
            if ghost_display.is_some() {
                break;
            }
            let chunks = wrap_display_chunks(line, budget);
            for (ci, (start, end, _, _)) in chunks.iter().enumerate() {
                let chunk_text = line[*start..*end].to_string();
                let pre = if li == 0 && ci == 0 {
                    INPUT_PREFIX
                } else {
                    indent.as_str()
                };
                let chunk_byte_start = line_byte_start + *start;
                let mut spans = vec![Span::styled(
                    pre.to_string(),
                    Style::default().fg(Color::White),
                )];
                spans.extend(self.paste_styled_spans(&chunk_text, chunk_byte_start));
                lines.push(Line::from(spans));
            }
            // Advance past this line + its '\n' separator.
            line_byte_start += line.len() + 1;
        }

        let (vis_row, vis_col) = visual_position_for_byte(
            self.composer.text(),
            self.composer.cursor(),
            prefix_width,
            inner_w.max(1),
        );
        let cursor_row = vis_row as u16;
        let cursor_col = vis_col as u16;

        let visible_rows = input_inner.height;
        let scroll_y = cursor_row.saturating_sub(visible_rows.saturating_sub(1));
        // No `Wrap` modifier — the lines we just emitted are already
        // visual rows. Letting Paragraph::wrap re-wrap them would
        // desync the cursor again.
        let para = Paragraph::new(lines)
            .block(input_block)
            .scroll((scroll_y, 0));
        frame.render_widget(para, area);

        // Vim visual-mode selection highlight: invert each selected cell
        // (REVERSED), mirroring `apply_selection_highlight`'s approach for
        // chat drag-select. The selection byte range is mapped to visual
        // (row, col) via the same wrap math the cursor uses, so it tracks
        // wrapped lines. Paste blocks are atomic — `visual_range` already
        // widens through them at the buffer layer, so the cell span here is
        // correct without extra work.
        if let Some((lo, hi)) = self.composer.visual_range()
            && hi > lo
        {
            let buf = frame.buffer_mut();
            apply_composer_visual_highlight(
                buf,
                input_inner,
                self.composer.text(),
                lo,
                hi,
                prefix_width,
                inner_w.max(1),
                scroll_y,
            );
        }

        // Context indicator on the top-right of the input box. It is normally
        // fixed chrome, but the composer gets priority: real typed text,
        // expanded prediction ghosts, and too-narrow input areas intentionally
        // hide the chip instead of reserving/editing around it.
        if let Some(chip) = context_chip {
            let chip_area = Rect::new(chip.x, input_inner.y, chip.width, 1);
            let chip = Paragraph::new(Line::from(vec![Span::styled(
                chip.label,
                Style::default().fg(CHIP_TEXT),
            )]));
            frame.render_widget(chip, chip_area);
        }

        Position::new(
            input_inner.x + cursor_col,
            input_inner.y + cursor_row.saturating_sub(scroll_y),
        )
    }

    fn passive_context_indicator(&self, input_inner: Rect) -> Option<ContextIndicatorChip> {
        // Deliberate fixed-chrome exception: active user input owns the whole
        // composer row, so the passive chip hides instead of colliding with
        // typed text.
        if !self.composer.text().is_empty() {
            return None;
        }
        if self
            .prediction_state
            .ghost()
            .is_some_and(|g| g.box_expanded())
        {
            return None;
        }
        let label = self.context_indicator_text();
        let width = display_width(&label) as u16;
        if width + input_prefix_width() as u16 + 1 >= input_inner.width {
            return None;
        }
        Some(ContextIndicatorChip {
            x: input_inner.x + input_inner.width.saturating_sub(width),
            width,
            label,
        })
    }

    /// Split a rendered composer chunk (`text`, whose first char is at
    /// absolute buffer byte `chunk_byte_start`) into styled spans, giving
    /// any bytes covered by a paste-block placeholder a distinct dim-cyan
    /// style (composer-paste-handling). Non-block text keeps the default
    /// white. Returns one span when no block overlaps the chunk (the
    /// common case), so ordinary typing renders exactly as before.
    fn paste_styled_spans(&self, text: &str, chunk_byte_start: usize) -> Vec<Span<'static>> {
        let plain = || {
            vec![Span::styled(
                text.to_string(),
                Style::default().fg(Color::White),
            )]
        };
        if self.paste_registry.is_empty() {
            return plain();
        }
        let blocks = self.paste_registry.blocks();
        let chunk_end = chunk_byte_start + text.len();
        // Quick reject: no block overlaps this chunk.
        if !blocks
            .iter()
            .any(|b| b.start < chunk_end && b.end > chunk_byte_start)
        {
            return plain();
        }
        let block_style = Style::default().fg(Color::Cyan).add_modifier(Modifier::DIM);
        let normal = Style::default().fg(Color::White);
        let mut spans: Vec<Span<'static>> = Vec::new();
        let mut cur = String::new();
        let mut cur_in_block = false;
        let mut byte = chunk_byte_start;
        for ch in text.chars() {
            let in_block = blocks.iter().any(|b| byte >= b.start && byte < b.end);
            if in_block != cur_in_block && !cur.is_empty() {
                let style = if cur_in_block { block_style } else { normal };
                spans.push(Span::styled(std::mem::take(&mut cur), style));
            }
            cur_in_block = in_block;
            cur.push(ch);
            byte += ch.len_utf8();
        }
        if !cur.is_empty() {
            let style = if cur_in_block { block_style } else { normal };
            spans.push(Span::styled(cur, style));
        }
        spans
    }

    /// Build the chrome's context indicator. Format (GOALS §1a):
    /// - With known max:   `ctx 12% → 8% prunable` (current fraction →
    ///   projected fraction after `/prune`)
    /// - Without:          `1.2k tokens, 320 prunable`
    ///
    /// The `prunable` figure is the daemon-authoritative
    /// `prunable_tokens` (from the same `dedup_plan` `/prune` executes),
    /// so the projection the user sees equals what `/prune` then removes
    /// (GOALS §10 stable-contract property).
    pub(super) fn context_indicator_text(&self) -> String {
        // Fresh chat (nothing sent, no provider usage yet): replace the
        // useless `0% prunable` placeholder with the instruction-file
        // size the daemon estimated. Reverts to the usual form once the
        // first round-trip returns usage or any history exists. No
        // guidance file → fall through to the usual form entirely.
        if let Some(label) = fresh_chat_guidance_label(
            self.history.is_empty(),
            self.last_usage.is_some(),
            self.guidance_estimate
                .as_ref()
                .and_then(|e| e.file.as_deref()),
            self.guidance_estimate
                .as_ref()
                .map(|e| e.guidance_tokens)
                .unwrap_or(0),
        ) {
            return label;
        }
        let tokens = self.context_tokens();
        let prunable = self.prunable_tokens;
        let base = match self.launch.active_model_max_context {
            Some(max) if max > 0 => {
                let pct = ((tokens as u64 * 100) / max as u64).min(999) as u32;
                // Projected fraction after a full prune: subtract the
                // prunable tokens from the live count, same denominator.
                let after = (tokens as u64).saturating_sub(prunable);
                let after_pct = ((after * 100) / max as u64).min(999) as u32;
                if prunable == 0 {
                    format!("ctx {pct}%")
                } else {
                    format!("ctx {pct}% → {after_pct}% prunable")
                }
            }
            _ => {
                if prunable == 0 {
                    format!("{} tokens", format_token_count(tokens))
                } else {
                    format!(
                        "{} tokens, {} prunable",
                        format_token_count(tokens),
                        format_token_count(prunable.min(u32::MAX as u64) as u32)
                    )
                }
            }
        };
        // Surface cached tokens + hit rate separately (never folded into the
        // headline) when the last round-trip served cache reads.
        match self.cached_indicator_suffix() {
            Some(suffix) => format!("{base} {suffix}"),
            None => base,
        }
    }

    /// Live token count for the current context. Before the first
    /// round-trip it's the pure local estimate. Once the provider has
    /// reported usage, it's a hybrid: the provider's last authoritative
    /// `input + output` total (anchor) plus a local cl100k_base estimate
    /// of everything streamed since that report. The number therefore
    /// climbs per streamed token and re-snaps to the exact provider
    /// count each time fresh usage arrives, correcting any drift.
    pub(super) fn context_tokens(&self) -> u32 {
        let estimate = self.estimate_context_tokens();
        match self.last_usage {
            Some(u) => {
                // Anchor on the blended total (cached reads excluded — codex
                // precedent, prompt `prompt-caching-strategy.md`) so the
                // headline number reflects freshly-processed tokens, not cache
                // hits. Cached tokens are surfaced separately in the indicator.
                let anchor = u.blended_total().min(u32::MAX as u64) as u32;
                hybrid_context_tokens(anchor, estimate, self.estimate_at_last_usage)
            }
            None => estimate,
        }
    }

    /// Terse cached-token suffix for the context indicator: `· 8.0k cached
    /// (80%)`, where the percent is the input cache hit rate. `None` when the
    /// last round-trip reported no cached reads (so the indicator stays clean
    /// on no-cache providers / cold first turns). Sourced from `last_usage`,
    /// the same provider-authoritative usage the headline anchors on.
    fn cached_indicator_suffix(&self) -> Option<String> {
        let u = self.last_usage?;
        if u.cached_input_tokens == 0 {
            return None;
        }
        let cached = format_token_count(u.cached_input_tokens.min(u32::MAX as u64) as u32);
        match u.hit_rate() {
            Some(rate) => Some(format!(
                "· {cached} cached ({}%)",
                (rate * 100.0).round() as u32
            )),
            None => Some(format!("· {cached} cached")),
        }
    }

    /// cl100k_base token count over the context sent to the model: the
    /// composed system prompt baseline (role prompt + OS + session +
    /// guidance body, resolved at launch into `guidance_estimate`) plus
    /// visible chat content. Including the system prompt keeps the fresh-
    /// chat baseline honest rather than reporting ~0 (the provider's
    /// authoritative usage still re-anchors the count after the first
    /// round-trip). Provider-native counts will replace the local
    /// component where available (GOALS §10 / plan §3h); cl100k_base is
    /// the documented fallback. The finalized-history portion is memoized
    /// (see `history_estimate_tokens`) so the per-frame live counter only
    /// re-tokenizes the small, growing `pending` buffer.
    fn pending_tokens(&self) -> u32 {
        let Some(pending) = &self.pending else {
            self.pending_token_cache.set(None);
            return 0;
        };
        let key = (pending.text.len(), pending.reasoning.len());
        if let Some((cached_key, tokens)) = self.pending_token_cache.get()
            && cached_key == key
        {
            return tokens;
        }
        let tokens = (crate::tokens::count(&pending.text)
            + crate::tokens::count(&pending.reasoning))
        .min(u32::MAX as usize) as u32;
        self.pending_token_cache.set(Some((key, tokens)));
        tokens
    }

    pub(super) fn estimate_context_tokens(&self) -> u32 {
        // The full composed system prompt is a fixed baseline for the
        // session (computed once at launch); it's present on every turn,
        // so fold it into every estimate, not just the fresh one.
        let mut tokens = self
            .guidance_estimate
            .as_ref()
            .map(|e| e.system_tokens + e.model_instruction_tokens)
            .unwrap_or(0)
            .min(u32::MAX as u64) as usize;
        tokens += self.history_estimate_tokens() as usize;
        tokens += self.pending_tokens() as usize;
        // Buffered `<git>` blocks (GOALS §1l) ride the next user
        // message; surface their cost before the user commits to send.
        for block in &self.pending_git_blocks {
            tokens += crate::tokens::count(block);
        }
        tokens.min(u32::MAX as usize) as u32
    }

    /// cl100k_base token count of the conversation-message portion of the
    /// live context: finalized history + the in-flight `pending` buffer +
    /// any buffered `<git>` blocks riding the next user message. This is
    /// exactly the part of [`Self::estimate_context_tokens`] *excluding*
    /// the composed system prompt — the `messages` category of the
    /// `/context` overlay.
    pub(super) fn message_tokens(&self) -> u64 {
        let mut tokens = self.history_estimate_tokens() as u64;
        tokens += self.pending_tokens() as u64;
        for block in &self.pending_git_blocks {
            tokens += crate::tokens::count(block) as u64;
        }
        tokens
    }

    /// Capture an immutable snapshot of the live context composition for
    /// the `/context` overlay. The system prompt is decomposed into its
    /// real sub-buckets (base prompt + cached system block + guidance/
    /// memory file) via the engine's own assembler, and the message
    /// portion is sized the same cl100k_base way the chrome's indicator
    /// uses. The window size is the active model's context limit (the same
    /// `active_model_max_context` the chrome percentage uses); `None` there
    /// drives the unknown-window path (no pct, no free segment).
    pub(super) fn context_snapshot(&self) -> crate::tui::context_pane::ContextSnapshot {
        let short_id = self.launch.session_short_id.as_deref().unwrap_or_default();
        let model_instructions = self
            .guidance_estimate
            .as_ref()
            .map(|e| e.model_instruction_tokens)
            .unwrap_or(0);
        let breakdown =
            crate::engine::builtin::chat_system_prompt_breakdown(&self.launch.cwd, short_id, None);
        let snapshot = crate::tui::context_pane::ContextSnapshot::new(
            model_instructions.max(breakdown.model_instructions),
            breakdown.base_prompt,
            breakdown.system_block,
            breakdown.guidance,
            self.message_tokens(),
            self.launch.active_model_max_context,
        );
        // Attach the last round-trip's provider cache usage (cached input +
        // hit rate) as a separate footer stat (prompt
        // `prompt-caching-strategy.md`); a no-op until cached reads arrive.
        match self.last_usage {
            Some(u) => snapshot.with_cache_usage(u.cached_input_tokens, u.hit_rate()),
            None => snapshot,
        }
    }

    /// cl100k_base count over finalized history only, memoized on a cheap
    /// length signature. History is static while a turn streams, so this
    /// returns from cache on every draw mid-stream — only re-tokenizing
    /// when an entry is appended or edited in place.
    fn history_estimate_tokens(&self) -> u32 {
        let sig = self.history_signature();
        if let Some((cached_sig, val)) = self.history_estimate_cache.get()
            && cached_sig == sig
        {
            return val;
        }
        let val = self.compute_history_tokens();
        self.history_estimate_cache.set(Some((sig, val)));
        val
    }

    fn compute_history_tokens(&self) -> u32 {
        let mut tokens: usize = 0;
        for entry in &self.history {
            tokens += match entry {
                HistoryEntry::User { text, .. } => crate::tokens::count(text),
                HistoryEntry::Plain { line }
                | HistoryEntry::CommandError { line }
                | HistoryEntry::Maintenance { line } => crate::tokens::count(line),
                // UI/export-only acknowledgement of a settled interrupt; the
                // model context receives the actual decision through the
                // daemon event stream, not this rendered row.
                HistoryEntry::InterruptDecision { .. } => 0,
                HistoryEntry::ToolLine { summary, .. } => crate::tokens::count(summary),
                HistoryEntry::ToolBox { calls, .. } => calls
                    .iter()
                    .map(|c| crate::tokens::count(&c.summary) + crate::tokens::count(&c.output))
                    .sum(),
                HistoryEntry::Diff { old, new, .. } => {
                    crate::tokens::count(old) + crate::tokens::count(new)
                }
                HistoryEntry::Agent {
                    text, reasoning, ..
                } => crate::tokens::count(text) + crate::tokens::count(reasoning),
                // The child's report is delivered to the parent as its
                // `task` tool result, so it enters the model's context.
                HistoryEntry::Subagent { outcome, .. } => outcome
                    .as_ref()
                    .map(|o| crate::tokens::count(&o.report))
                    .unwrap_or(0),
                // Local-command output is never sent to the agent
                // (GOALS §1k); `/git`'s agent-bound cost is accounted
                // via `pending_git_blocks`, not here.
                HistoryEntry::LocalCommand { .. } => 0,
                // A TUI-only session-boundary divider; never sent to the
                // agent (the seed-tools' real cost lands as actual turns).
                HistoryEntry::CompactBoundary { .. } => 0,
                // UI-only red error line; never sent to the agent.
                HistoryEntry::InferenceError { .. } => 0,
                // UI-only yellow backup-fallback banner; never sent to the
                // agent (wire-vs-user split, GOALS §14).
                HistoryEntry::BackupWarning { .. } => 0,
                // UI-only yellow slow-stream warning; never sent to the agent.
                HistoryEntry::InferenceWarning { .. } => 0,
                // A `/note` session-history annotation: local/export state
                // only, never sent to the model — so it costs zero context
                // (the critical invariant, mirrored in rehydration).
                HistoryEntry::UserNote { .. } => 0,
                // The auto-injected-skill row is the user-facing half of the
                // wire-vs-user split; the body's real cost lands as the user
                // message it rides, so this row itself costs zero context.
                HistoryEntry::SkillAutoInjected { .. } => 0,
            };
        }
        tokens.min(u32::MAX as usize) as u32
    }

    /// Cheap content-length fingerprint over the same fields
    /// `compute_history_tokens` reads. Detects appends *and* in-place
    /// edits (e.g. tool output landing on an existing `ToolBox`) without
    /// tokenizing; a same-length edit only costs a stale count until the
    /// next real change — fine for a display estimate.
    fn history_signature(&self) -> u64 {
        let mut sig = self.history.len() as u64;
        for entry in &self.history {
            let len = match entry {
                HistoryEntry::User { text, .. } => text.len(),
                HistoryEntry::Plain { line }
                | HistoryEntry::CommandError { line }
                | HistoryEntry::Maintenance { line } => line.len(),
                HistoryEntry::InterruptDecision { decision } => {
                    decision.lines.iter().fold(0usize, |acc, line| {
                        acc + line.prompt.len() + line.answer.len()
                    }) + usize::from(decision.permission)
                        + usize::from(decision.cancelled)
                }
                HistoryEntry::ToolLine { summary, .. } => summary.len(),
                HistoryEntry::ToolBox { calls, .. } => {
                    calls.iter().map(|c| c.summary.len() + c.output.len()).sum()
                }
                HistoryEntry::Diff { old, new, .. } => old.len() + new.len(),
                HistoryEntry::Agent {
                    text, reasoning, ..
                } => text.len() + reasoning.len(),
                // Add 1 for the settled state so the None→Some transition
                // (which adds the report to context) busts the cache even
                // for an empty report.
                HistoryEntry::Subagent { outcome, .. } => {
                    outcome.as_ref().map(|o| o.report.len() + 1).unwrap_or(0)
                }
                HistoryEntry::LocalCommand { .. } => 0,
                HistoryEntry::CompactBoundary {
                    predecessor_short_id,
                    handoff,
                    expanded,
                    ..
                } => {
                    predecessor_short_id.len()
                        + usize::from(*expanded) * handoff.as_ref().map_or(0, |b| b.len())
                }
                HistoryEntry::InferenceError {
                    summary,
                    detail,
                    expanded,
                } => summary.len() + detail.len() + usize::from(*expanded),
                HistoryEntry::BackupWarning { line } => line.len(),
                HistoryEntry::InferenceWarning { line } => line.len(),
                HistoryEntry::UserNote { text, .. } => text.len(),
                HistoryEntry::SkillAutoInjected { name, reason } => {
                    name.len() + reason.as_ref().map_or(0, |r| r.len())
                }
            };
            sig = sig.wrapping_mul(31).wrapping_add(len as u64);
        }
        sig
    }

    pub(super) fn render_suggestion_box(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        self.suggestion_box_area = None;
        self.suggestion_row_hits.clear();
        if area.height < 3 || area.width < 5 {
            return;
        }
        let border_color = Self::input_border_color(self.busy, false);
        let Some(content_area) = Self::render_connected_input_top_strip(frame, area, border_color)
        else {
            return;
        };
        self.suggestion_box_area = Some(area);

        if self.at_popup_active() {
            self.render_at_suggestion_box(frame, area, content_area);
        } else if self.slash_query().is_some() {
            self.render_slash_suggestion_box(frame, area, content_area);
        } else if self.show_vim_hint() {
            self.render_vim_hint_box(frame, content_area);
        }
    }

    pub(super) fn clear_suggestion_box_hits(&mut self) {
        self.suggestion_box_area = None;
        self.suggestion_row_hits.clear();
        self.hovered_suggestion = None;
    }

    fn render_vim_hint_box(&self, frame: &mut ratatui::Frame, content_area: Rect) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let line = Line::from(vec![
            Span::raw(" "),
            Span::styled("Press ", muted),
            Span::styled("`i`", Style::default().fg(WARNING_TEXT)),
            Span::styled(" to resume typing. Disable vim mode in ", muted),
            Span::styled("/settings", muted),
        ]);
        frame.render_widget(Paragraph::new(line), content_area);
    }

    fn render_slash_suggestion_box(
        &mut self,
        frame: &mut ratatui::Frame,
        area: Rect,
        content_area: Rect,
    ) {
        let matches = self.slash_suggestions();
        if matches.is_empty() {
            return;
        }
        let total = matches.len();
        let window = content_area.height.min(AUTOCOMPLETE_ROWS) as usize;
        let mut list = crate::tui::pane::ScrollList::at(
            self.slash_selected.min(total.saturating_sub(1)),
            self.slash_scroll,
        );
        list.clamp_scroll(total, window);
        let selected = list.cursor();
        let offset = list.scroll();
        let name_w = matches.iter().map(|c| c.name().len()).max().unwrap_or(0);
        let visible: Vec<(usize, String, String)> = matches
            .iter()
            .enumerate()
            .skip(offset)
            .take(window)
            .map(|(i, cmd)| (i, cmd.name().to_string(), cmd.description(self).to_string()))
            .collect();
        drop(matches);
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut lines = Vec::new();
        for (row, (i, name, description)) in visible.into_iter().enumerate() {
            let is_sel = i == selected;
            let target = SuggestionBoxTarget {
                kind: SuggestionBoxKind::Slash,
                index: i,
            };
            let marker = if is_sel { "▸ " } else { "  " };
            let name_padded = format!("/{:<width$}", name, width = name_w);
            let name_style = if is_sel {
                Style::default().fg(WARNING_TEXT)
            } else {
                Style::default().fg(Color::White)
            };
            let mut line = Line::from(vec![
                Span::raw(marker),
                Span::styled(name_padded, name_style),
                Span::raw("  "),
                Span::styled(description, muted),
            ]);
            if self.hovered_suggestion == Some(target) {
                hover_highlight_full_line(&mut line);
            }
            lines.push(line);
            self.suggestion_row_hits.push(SuggestionBoxRowHit {
                target,
                rect: Rect::new(
                    content_area.x,
                    content_area.y + row as u16,
                    content_area.width,
                    1,
                ),
            });
        }
        frame.render_widget(Paragraph::new(lines), content_area);
        self.render_suggestion_scrollbar(frame, area, content_area, total, window, offset);
    }

    fn render_at_suggestion_box(
        &mut self,
        frame: &mut ratatui::Frame,
        area: Rect,
        content_area: Rect,
    ) {
        let suggestions = self.at_suggestions();
        if suggestions.is_empty() {
            return;
        }
        let window = content_area.height.min(AUTOCOMPLETE_ROWS) as usize;
        let mut list = crate::tui::pane::ScrollList::at(
            self.at_selected.min(suggestions.len().saturating_sub(1)),
            self.at_scroll,
        );
        list.clamp_scroll(suggestions.len(), window);
        let selected = list.cursor();
        let offset = list.scroll();
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut lines = Vec::new();
        for (row, (i, sug)) in suggestions
            .iter()
            .enumerate()
            .skip(offset)
            .take(window)
            .enumerate()
        {
            let is_sel = i == selected;
            let target = SuggestionBoxTarget {
                kind: SuggestionBoxKind::At,
                index: i,
            };
            let marker = if is_sel { "▸ " } else { "  " };
            let name_style = if is_sel {
                Style::default().fg(WARNING_TEXT)
            } else if sug.gitignored {
                muted
            } else {
                Style::default().fg(Color::White)
            };
            let kind = if sug.is_dir { "dir" } else { "file" };
            let mut spans = vec![
                Span::raw(marker),
                Span::styled(format!("@{}", sug.display), name_style),
                Span::raw("  "),
                Span::styled(kind.to_string(), muted),
            ];
            if sug.gitignored {
                spans.push(Span::raw("  "));
                spans.push(Span::styled("gitignored", muted));
            }
            let mut line = Line::from(spans);
            if self.hovered_suggestion == Some(target) {
                hover_highlight_full_line(&mut line);
            }
            lines.push(line);
            self.suggestion_row_hits.push(SuggestionBoxRowHit {
                target,
                rect: Rect::new(
                    content_area.x,
                    content_area.y + row as u16,
                    content_area.width,
                    1,
                ),
            });
        }
        frame.render_widget(Paragraph::new(lines), content_area);
        self.render_suggestion_scrollbar(
            frame,
            area,
            content_area,
            suggestions.len(),
            window,
            offset,
        );
    }

    fn render_suggestion_scrollbar(
        &self,
        frame: &mut ratatui::Frame,
        area: Rect,
        content_area: Rect,
        total: usize,
        window: usize,
        offset: usize,
    ) {
        if total <= window || window == 0 || area.width < 5 {
            return;
        }
        let scrollbar_area = Rect::new(
            area.x + area.width.saturating_sub(2),
            content_area.y,
            1,
            content_area.height,
        );
        let mut state = ScrollbarState::new(total)
            .position(offset)
            .viewport_content_length(window);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_style(Style::default().fg(MUTED_TEXT))
            .thumb_style(Style::default().fg(WARNING_TEXT));
        frame.render_stateful_widget(scrollbar, scrollbar_area, &mut state);
    }

    /// Lay out and render the embedded pane (GOALS §1i) inside `body`,
    /// resizing the PTY to fit. Returns the rect the chat history should
    /// use (the whole body when no pane, the chat side of a split, or
    /// `None` when a fullscreen pane covers the body). Also stashes the
    /// pane/divider/body rects for the mouse handler.
    pub(super) fn render_pane(&mut self, frame: &mut ratatui::Frame, body: Rect) -> Option<Rect> {
        if self.pane.is_none() {
            self.pane_rect = None;
            self.divider = None;
            self.pane_body = None;
            return Some(body);
        }
        let (chat_rect, pane_rect, divider) = split_body(self.pane_side, self.pane_ratio, body);
        if let Some(pane) = self.pane.as_mut() {
            pane.resize(pane_rect.height, pane_rect.width);
        }
        self.pane_rect = Some(pane_rect);
        self.divider = divider;
        self.pane_body = Some(body);
        if let Some((drect, vertical)) = divider {
            self.render_divider(frame, drect, vertical);
        }
        if let Some(pane) = self.pane.as_ref() {
            pane.render(frame, pane_rect);
        }
        chat_rect
    }

    /// Draw the split divider. Brighter when the pane is focused so the
    /// divider doubles as a focus indicator.
    fn render_divider(&self, frame: &mut ratatui::Frame, rect: Rect, vertical: bool) {
        let color = if self.pane_focused {
            DIVIDER_FOCUSED
        } else {
            DIVIDER_DIM
        };
        let style = Style::default().fg(color);
        if vertical {
            let lines: Vec<Line<'static>> = (0..rect.height)
                .map(|_| Line::from(Span::styled("│", style)))
                .collect();
            frame.render_widget(Paragraph::new(lines), rect);
        } else {
            let bar = "─".repeat(rect.width as usize);
            frame.render_widget(Paragraph::new(Line::from(Span::styled(bar, style))), rect);
        }
    }

    fn render_footer_agent_picker(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        self.footer_picker_row_hits.clear();
        let Some(picker) = self.footer_agent_picker.as_ref() else {
            return;
        };
        let block = Block::default().borders(Borders::ALL).title(" agent ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let current = self
            .agent_path
            .first()
            .map(String::as_str)
            .unwrap_or(self.launch.agent_name.as_str());
        let window = layout[0].height as usize;
        let offset =
            crate::tui::nav::windowed_scroll(picker.cursor, 0, picker.entries.len(), window.max(1));
        let mut lines = Vec::new();
        for (idx, name) in picker.entries.iter().enumerate().skip(offset).take(window) {
            let highlighted = idx == picker.cursor;
            let marker = if highlighted { "▸ " } else { "  " };
            let style = if highlighted {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let mut spans = vec![
                Span::raw(marker.to_string()),
                Span::styled(name.clone(), style),
            ];
            if name == current {
                spans.push(Span::raw("  "));
                spans.push(Span::styled("[current]".to_string(), muted));
            }
            lines.push(Line::from(spans));
            let row = layout[0].y + lines.len() as u16 - 1;
            if row < layout[0].y + layout[0].height {
                self.footer_picker_row_hits.push(super::FooterPickerRowHit {
                    kind: super::FooterPickerKind::Agent,
                    index: idx,
                    rect: Rect::new(layout[0].x, row, layout[0].width, 1),
                });
            }
        }
        if lines.is_empty() {
            lines.push(Line::from(Span::styled("(no agents)".to_string(), muted)));
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "↑/↓  enter: switch  esc: cancel".to_string(),
                muted,
            ))),
            layout[1],
        );
    }

    fn render_footer_mode_picker(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        self.footer_picker_row_hits.clear();
        let Some(picker) = self.footer_mode_picker else {
            return;
        };
        let block = Block::default().borders(Borders::ALL).title(" llm mode ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut lines = Vec::new();
        for (idx, mode) in super::FOOTER_MODE_ORDER.iter().enumerate() {
            let highlighted = idx == picker.cursor;
            let marker = if highlighted { "▸ " } else { "  " };
            let style = if highlighted {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let mut spans = vec![
                Span::raw(marker.to_string()),
                Span::styled(mode.as_str().to_string(), style),
            ];
            if *mode == self.llm_mode {
                spans.push(Span::raw("  "));
                spans.push(Span::styled("[current]".to_string(), muted));
            }
            lines.push(Line::from(spans));
            let row = layout[0].y + idx as u16;
            if row < layout[0].y + layout[0].height {
                self.footer_picker_row_hits.push(super::FooterPickerRowHit {
                    kind: super::FooterPickerKind::Mode,
                    index: idx,
                    rect: Rect::new(layout[0].x, row, layout[0].width, 1),
                });
            }
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "↑/↓  enter: switch  esc: cancel".to_string(),
                muted,
            ))),
            layout[1],
        );
    }

    pub(super) fn render_status(&mut self, frame: &mut ratatui::Frame, area: Rect) {
        // Caffeination glyph (☕) leads the right-hand chrome while active,
        // driven by the daemon-broadcast state (GOALS §1a). Additive to the
        // fixed cwd + branch chrome — never displaces it.
        // Side-conversation indicator (`/side`) leads the right-hand chrome
        // while a throwaway side conversation is open, ahead of the ☕ glyph.
        // Additive to the fixed cwd + branch chrome — never displaces it.
        // Plan-status indicator (`plan-status-chrome-and-resolver.md`) leads
        // the right-hand chrome when this project has unfinished plans, driven
        // by daemon-broadcast state. Additive to the fixed cwd + branch chrome
        // (GOALS §1a) — never displaces it, the same pattern as the ☕ glyph.
        // Transient "waiting for lock" indicator
        // (`readlock-wait-and-lock-expiry.md`) leads the right-hand chrome
        // while a `readlock` is blocked on a contended lock. Additive — never
        // displaces a fixed slot, the same pattern as the ☕ glyph.
        let mut right = chrome::waiting_for_lock_spans(self.waiting_for_lock.as_ref());
        right.extend(chrome::side_glyph_spans(self.side_conversation.is_some()));
        right.extend(chrome::org_sync_spans(self.org_sync_disclosure.as_ref()));
        right.extend(chrome::connector_spans(self.connector_disclosure.as_ref()));
        right.extend(chrome::caffeinate_glyph_spans(self.caffeinate_active));
        right.extend(chrome::status_line_spans(&self.launch));
        let status = chrome::left_status(
            &self.launch,
            self.llm_mode,
            &self.agent_path,
            self.footer_selection,
            self.sandbox_escalation_enabled,
        );
        let mut left = status.spans;
        // Transient async-schedule strip (GOALS §22): only when ≥1 scheduled
        // task is active, appended to the bottom-left so the fixed chrome
        // (model/agent) is undisturbed.
        if !self.active_schedules.is_empty() {
            let scheduled: Vec<(String, String, u64)> = self
                .active_schedules
                .values()
                .map(|j| (j.kind.clone(), j.label.clone(), j.iteration))
                .collect();
            left.extend(chrome::schedule_strip_spans(&scheduled));
        }
        if let Some(hint) = self.copy_pick_target_hint() {
            left.push(Span::styled(" · ", Style::default().fg(DIVIDER_DIM)));
            left.push(Span::styled(
                hint,
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ));
        }
        if self.footer_selection.is_some() {
            left.push(Span::styled(" · ", Style::default().fg(DIVIDER_DIM)));
            left.push(Span::styled(
                "←/→ cycle · enter choose · esc clear".to_string(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ));
        }
        if let Some(status) = &self.idle_reason_status {
            left.push(Span::styled(" · ", Style::default().fg(DIVIDER_DIM)));
            left.push(Span::styled(
                status.text.clone(),
                Style::default().fg(toast_fg(status.kind)),
            ));
        }
        let right_width: u16 = right
            .iter()
            .map(|s| s.width() as u16)
            .sum::<u16>()
            .min(area.width);
        let bottom =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(right_width)]).split(area);
        self.footer_hit_areas = status
            .hits
            .into_iter()
            .filter_map(|hit| {
                let start = hit.start.min(bottom[0].width);
                let end = hit.end.min(bottom[0].width);
                (end > start).then_some(super::FooterHitArea {
                    control: hit.control,
                    rect: Rect::new(bottom[0].x + start, bottom[0].y, end - start, 1),
                })
            })
            .collect();
        frame.render_widget(Paragraph::new(Line::from(left)), bottom[0]);
        frame.render_widget(Paragraph::new(Line::from(right)), bottom[1]);
    }
}

struct ContextIndicatorChip {
    x: u16,
    width: u16,
    label: String,
}

fn toast_fg(kind: ToastKind) -> Color {
    match kind {
        ToastKind::Success => SUCCESS_TEXT,
        ToastKind::Warning => WARNING_TEXT,
        ToastKind::Error => ERROR_TEXT,
        ToastKind::Info => INFO_TEXT,
    }
}

/// Render a toast over the status-line rect. Single line; left-padded
/// one cell; foreground color encodes intent (green/yellow/red/grey).
/// Uses `Clear` so the status text underneath doesn't bleed through.
fn render_toast(frame: &mut ratatui::Frame, status_rect: Rect, toast: &Toast) {
    use ratatui::widgets::Clear;
    if status_rect.height == 0 || status_rect.width == 0 {
        return;
    }
    let fg = toast_fg(toast.kind);
    let text = format!(" {} ", toast.text);
    // Truncate to fit if the message is longer than the status row.
    let max = status_rect.width as usize;
    let display: String = if text.chars().count() > max {
        let cap = max.saturating_sub(1);
        let truncated: String = text.chars().take(cap).collect();
        format!("{truncated}…")
    } else {
        text
    };
    frame.render_widget(Clear, status_rect);
    let para = Paragraph::new(Line::from(Span::styled(
        display,
        Style::default().fg(fg).add_modifier(Modifier::BOLD),
    )));
    frame.render_widget(para, status_rect);
}

fn prewrap_chat_rows(
    lines: Vec<Line<'static>>,
    row_meta: Vec<ChatRowMeta>,
    msg_abs_line: HashMap<usize, usize>,
    width: usize,
) -> ChatRows {
    if width == 0 {
        return (lines, row_meta, msg_abs_line);
    }

    let mut visual_lines = Vec::new();
    let mut visual_meta = Vec::new();
    let mut row_map = HashMap::new();

    for (row, line) in lines.into_iter().enumerate() {
        let wrapped = wrap_line_to_visual_rows(line, width);
        let first_visual = visual_lines.len();
        row_map.insert(row, first_visual);

        for (part_idx, (visual, start_col, end_col)) in wrapped.into_iter().enumerate() {
            visual_lines.push(visual);
            let mut meta = row_meta
                .get(row)
                .cloned()
                .unwrap_or_else(ChatRowMeta::padding);
            meta.continuation = meta.continuation || part_idx > 0;
            meta.pin_hit = meta
                .pin_hit
                .and_then(|hit| pin_hit_for_visual_row(hit, start_col, end_col));
            meta.fork_hit = meta
                .fork_hit
                .and_then(|hit| pin_hit_for_visual_row(hit, start_col, end_col));
            visual_meta.push(meta);
        }
    }

    let msg_abs_line = msg_abs_line
        .into_iter()
        .filter_map(|(idx, row)| row_map.get(&row).copied().map(|visual| (idx, visual)))
        .collect();

    (visual_lines, visual_meta, msg_abs_line)
}

fn pin_hit_for_visual_row(hit: PinHit, start_col: usize, end_col: usize) -> Option<PinHit> {
    let hit_start = hit.col_start as usize;
    let hit_end = hit.col_end as usize;
    let clipped_start = hit_start.max(start_col);
    let clipped_end = hit_end.min(end_col);
    (clipped_start < clipped_end).then_some(PinHit {
        seq: hit.seq,
        col_start: (clipped_start - start_col) as u16,
        col_end: (clipped_end - start_col) as u16,
    })
}

fn wrap_line_to_visual_rows(
    line: Line<'static>,
    width: usize,
) -> Vec<(Line<'static>, usize, usize)> {
    let line_width = line
        .spans
        .iter()
        .map(|span| span.content.as_ref().width())
        .sum::<usize>();
    if line_width <= width {
        return vec![(line, 0, line_width)];
    }

    let mut rows = Vec::new();
    let mut current_spans: Vec<Span<'static>> = Vec::new();
    let mut current_width = 0usize;
    let mut row_start = 0usize;
    let line_style = line.style;
    let line_alignment = line.alignment;

    for span in line.spans {
        for ch in span.content.chars() {
            let ch_width = ch.width().unwrap_or(0);
            if current_width > 0 && current_width + ch_width > width {
                rows.push((
                    Line {
                        spans: std::mem::take(&mut current_spans),
                        style: line_style,
                        alignment: line_alignment,
                    },
                    row_start,
                    row_start + current_width,
                ));
                row_start += current_width;
                current_width = 0;
            }
            current_spans.push(Span {
                content: Cow::Owned(ch.to_string()),
                style: span.style,
            });
            current_width += ch_width;
            if current_width >= width {
                rows.push((
                    Line {
                        spans: std::mem::take(&mut current_spans),
                        style: line_style,
                        alignment: line_alignment,
                    },
                    row_start,
                    row_start + current_width,
                ));
                row_start += current_width;
                current_width = 0;
            }
        }
    }

    if !current_spans.is_empty() || rows.is_empty() {
        rows.push((
            Line {
                spans: current_spans,
                style: line_style,
                alignment: line_alignment,
            },
            row_start,
            row_start + current_width,
        ));
    }
    rows
}

/// Snapshot the chat-area cells into a `(row, col) → symbol` grid so
/// the copy path can reconstruct selected plaintext without redoing
/// ratatui's wrap. Run after `frame.render_widget(...)` so the cells
/// reflect what the user actually sees.
fn capture_grid(buf: &ratatui::buffer::Buffer, area: Rect) -> Vec<Vec<String>> {
    let mut grid = Vec::with_capacity(area.height as usize);
    for y in 0..area.height {
        let mut row = Vec::with_capacity(area.width as usize);
        for x in 0..area.width {
            let abs_x = area.x + x;
            let abs_y = area.y + y;
            if let Some(cell) = buf.cell((abs_x, abs_y)) {
                row.push(cell.symbol().to_string());
            } else {
                row.push(String::new());
            }
        }
        grid.push(row);
    }
    grid
}

fn chat_visible_top(total: usize, visible: usize, offset: usize) -> usize {
    total.saturating_sub(visible).saturating_sub(offset)
}

fn chat_offset_for_top(total: usize, visible: usize, top: usize) -> usize {
    if total <= visible {
        return 0;
    }
    total
        .saturating_sub(visible)
        .saturating_sub(top.min(total.saturating_sub(visible)))
}

/// Apply the drag-select highlight to the chat area. Invert each
/// selected cell's fg/bg via the `REVERSED` modifier — same visual
/// affordance terminal selection uses, and it survives any underlying
/// color theme.
///
/// Highlights only the *content range* of each row: from the first
/// non-whitespace cell to the last non-whitespace cell. Cells outside
/// that range (left/right padding, end-of-line gap) stay un-inverted.
/// In-content spaces (between words) are highlighted so the selection
/// reads as a continuous bar rather than a gappy one. Chip rows
/// (`chip_row_mask`) are skipped entirely.
fn render_chat_scroll_indicator(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    scroll_offset: usize,
    in_progress: bool,
    style: Style,
) {
    if scroll_offset == 0 || area.width == 0 || area.height == 0 {
        return;
    }
    let full = if in_progress {
        format!("↓ streaming ({scroll_offset} more)")
    } else {
        format!("↓ {scroll_offset} more")
    };
    let text = if area.width as usize > full.width() {
        full
    } else if in_progress && area.width as usize > "↓ streaming".width() {
        "↓ streaming".to_string()
    } else if area.width as usize > "↓".width() {
        "↓".to_string()
    } else {
        return;
    };
    let start_x = area
        .x
        .saturating_add(area.width.saturating_sub(1))
        .saturating_sub(text.width() as u16);
    let y = area.y.saturating_add(area.height.saturating_sub(1));
    buf.set_string(start_x, y, text, style);
}

fn rendered_line_text(line: &Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
}

fn render_transcript_find_bar(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    find: Option<&TranscriptFind>,
    style: Style,
) {
    let Some(find) = find else {
        return;
    };
    if area.width == 0 || area.height == 0 {
        return;
    }
    let width = area.width as usize;
    let y = area.y.saturating_add(area.height.saturating_sub(1));
    let counter = if find.query.is_empty() {
        String::new()
    } else if let Some(current) = find.current {
        format!("{}/{}", current + 1, find.matches.len())
    } else {
        "no matches".to_string()
    };
    let prefix = "find: ";
    let cursor = "▏";
    let reserve = if counter.is_empty() {
        0
    } else {
        counter.width() + 1
    };
    let usable = width.saturating_sub(prefix.width() + cursor.width() + reserve);
    let query = if usable == 0 {
        String::new()
    } else {
        tail_ellipsis(&find.query, usable)
    };
    let left = format!("{prefix}{query}{cursor}");
    buf.set_string(area.x, y, left, style);
    if !counter.is_empty() && width > counter.width() + 1 {
        let start_x = area
            .x
            .saturating_add(area.width.saturating_sub(counter.width() as u16));
        buf.set_string(start_x, y, counter, style);
    }
}

fn tail_ellipsis(text: &str, max_width: usize) -> String {
    if text.width() <= max_width {
        return text.to_string();
    }
    if max_width == 0 {
        return String::new();
    }
    if max_width == 1 {
        return "…".to_string();
    }
    let mut out = String::new();
    let mut width = 0usize;
    for ch in text.chars().rev() {
        let ch_width = ch.width().unwrap_or(0);
        if width + ch_width > max_width - 1 {
            break;
        }
        out.insert(0, ch);
        width += ch_width;
    }
    format!("…{out}")
}

fn apply_transcript_find_highlight(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    find: &TranscriptFind,
    total_lines: usize,
    visible_lines: usize,
    scroll_offset: usize,
    lines: &[String],
) {
    let Some(current) = find.current else {
        return;
    };
    let Some(&abs) = find.matches.get(current) else {
        return;
    };
    let rel = if total_lines < area.height as usize {
        area.height as usize - total_lines + abs
    } else {
        let top = total_lines
            .saturating_sub(visible_lines.max(1))
            .saturating_sub(scroll_offset);
        let Some(rel) = abs.checked_sub(top) else {
            return;
        };
        rel
    };
    if rel >= area.height as usize {
        return;
    }
    let Some(line) = lines.get(abs) else {
        return;
    };
    let query = find.query.to_lowercase();
    if query.is_empty() {
        return;
    }
    let folded = line.to_lowercase();
    let Some(start_byte) = folded.find(&query) else {
        return;
    };
    if !line.is_char_boundary(start_byte) {
        return;
    }
    let end_byte = (start_byte + find.query.len()).min(line.len());
    if !line.is_char_boundary(end_byte) {
        return;
    }
    let start_col = line[..start_byte].width();
    let width = line[start_byte..end_byte].width().max(1);
    let y = area.y.saturating_add(rel as u16);
    let first = area.x.saturating_add(start_col as u16);
    let last = first
        .saturating_add(width as u16)
        .saturating_sub(1)
        .min(area.x.saturating_add(area.width.saturating_sub(1)));
    for col in first..=last {
        if let Some(cell) = buf.cell_mut((col, y)) {
            let style = cell.style().add_modifier(Modifier::REVERSED);
            cell.set_style(style);
        }
    }
}

fn apply_selection_highlight(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    sel: Selection,
    chip_row_mask: &[bool],
    chat_text_grid: &[Vec<String>],
) {
    let (start, end) = sel.ordered();
    let left = area.x;
    let right = area.x + area.width.saturating_sub(1);
    let top = area.y;
    let bottom = area.y + area.height.saturating_sub(1);
    for row in start.1..=end.1 {
        if row < top || row > bottom {
            continue;
        }
        let chat_rel = row.saturating_sub(area.y) as usize;
        if chip_row_mask.get(chat_rel).copied().unwrap_or(false) {
            continue;
        }
        let Some(grid_row) = chat_text_grid.get(chat_rel) else {
            continue;
        };
        let Some((content_first, content_last)) = content_bounds(grid_row) else {
            // Row is entirely whitespace (bottom-align padding,
            // blank gap) — nothing to highlight.
            continue;
        };
        let sel_first = if row == start.1 { start.0 } else { left };
        let sel_last = if row == end.1 { end.0 } else { right };
        let content_first_abs = (area.x as usize + content_first) as u16;
        let content_last_abs = (area.x as usize + content_last) as u16;
        let highlight_first = sel_first.max(content_first_abs);
        let highlight_last = sel_last.min(content_last_abs);
        if highlight_first > highlight_last {
            continue;
        }
        for col in highlight_first..=highlight_last {
            if let Some(cell) = buf.cell_mut((col, row)) {
                let mut style = cell.style();
                style = style.add_modifier(ratatui::style::Modifier::REVERSED);
                cell.set_style(style);
            }
        }
    }
}

/// `(first_content_col, last_content_col)` for a row of the chat
/// grid, or `None` if the row is entirely whitespace. Used by the
/// highlight pass to draw the inversion only across content cells.
fn content_bounds(row: &[String]) -> Option<(usize, usize)> {
    let first = row
        .iter()
        .position(|c| !c.chars().all(|ch| ch.is_whitespace()))?;
    let last = row
        .iter()
        .rposition(|c| !c.chars().all(|ch| ch.is_whitespace()))?;
    Some((first, last))
}

/// Extract the plaintext under the active drag-selection from the
/// cached chat grid. Walks the selection in reading order: first row
/// from start.col to row-end, full intermediate rows, last row from
/// row-start to end.col.
///
/// Two refinements on top of the cell-by-cell extraction:
///
/// 1. **Strip the agent-message left padding.** Each row gets at most
///    `AGENT_INDENT` leading spaces removed, preserving any *extra*
///    indent (code-block indentation, list nesting) above that base.
///    `\u{a0}` (NBSP) is intentionally preserved because that's a
///    user-meaningful character.
/// 2. **Selection mask parity.** Rows marked non-selectable in
///    [`ChatRowMeta`] are skipped, matching the highlight pass.
/// 3. **Soft-wrap rejoin.** When a row is a continuation of the
///    previous logical line (per [`ChatRowMeta::continuation`]), join it
///    with a space instead of a newline so a wrapped paragraph pastes as
///    one paragraph, not a stack of short visual lines. Hard line breaks
///    (paragraph boundaries) still produce newlines.
pub(super) fn extract_selection_markdown_source(
    history: &[HistoryEntry],
    row_meta: &[ChatRowMeta],
    area: Rect,
    sel: Selection,
) -> Option<String> {
    let (start, end) = sel.ordered();
    let mut target: Option<ChatCopyTarget> = None;
    let mut selected_lines: Vec<usize> = Vec::new();
    let mut active_target: Option<ChatCopyTarget> = None;
    let mut source_line: Option<usize> = None;

    for (row_idx, meta) in row_meta.iter().enumerate() {
        if meta.copy_target != active_target {
            active_target = meta.copy_target;
            source_line = if meta.copy_target.is_some() && meta.selectable && !meta.continuation {
                Some(0)
            } else {
                None
            };
        } else if meta.copy_target.is_some()
            && meta.selectable
            && !meta.continuation
            && let Some(line) = source_line.as_mut()
        {
            *line += 1;
        }

        let abs_row = area.y.saturating_add(row_idx as u16);
        if abs_row < start.1 || abs_row > end.1 {
            continue;
        }
        if !meta.selectable {
            return None;
        }
        let copy_target = meta.copy_target?;
        if target.is_some_and(|existing| existing != copy_target) {
            return None;
        }
        target = Some(copy_target);
        selected_lines.push(source_line?);
    }

    let ChatCopyTarget::Message { history_index } = target?;
    let source = match history.get(history_index)? {
        HistoryEntry::User { text, .. } | HistoryEntry::Agent { text, .. } => text.as_str(),
        _ => return None,
    };
    let ranges = source_line_ranges(source);
    let first_line = *selected_lines.iter().min()?;
    let last_line = *selected_lines.iter().max()?;
    let start_byte = ranges.get(first_line)?.0;
    let end_byte = ranges.get(last_line)?.1;
    let selected = &source[start_byte..end_byte];
    let selected = selected.strip_suffix('\n').unwrap_or(selected);
    (!selected.is_empty()).then(|| selected.to_string())
}

fn source_line_ranges(source: &str) -> Vec<(usize, usize)> {
    if source.is_empty() {
        return vec![(0, 0)];
    }
    let mut ranges = Vec::new();
    let mut start = 0usize;
    for line in source.split_inclusive('\n') {
        let end = start + line.len();
        ranges.push((start, end));
        start = end;
    }
    ranges
}

pub(super) fn extract_selection_plaintext(
    grid: &[Vec<String>],
    row_meta: &[ChatRowMeta],
    area: Rect,
    sel: Selection,
) -> String {
    use crate::tui::history::AGENT_INDENT;
    let (start, end) = sel.ordered();
    let mut out = String::new();
    let mut first_emitted = true;
    for abs_row in start.1..=end.1 {
        let grid_row = abs_row.saturating_sub(area.y) as usize;
        let Some(meta) = row_meta.get(grid_row) else {
            continue;
        };
        if !meta.selectable {
            continue;
        }
        let Some(row) = grid.get(grid_row) else {
            continue;
        };
        let first_col = if abs_row == start.1 {
            start.0.saturating_sub(area.x) as usize
        } else {
            0
        };
        let last_col = if abs_row == end.1 {
            end.0.saturating_sub(area.x) as usize
        } else {
            row.len().saturating_sub(1)
        };
        let mut line = String::new();
        for col in first_col..=last_col {
            if let Some(symbol) = row.get(col) {
                line.push_str(symbol);
            }
        }
        // Drop trailing spaces — bottom-align padding and end-of-line
        // gaps would otherwise turn into ugly trailing whitespace.
        let trimmed = line.trim_end_matches(' ').to_string();
        // Strip up to AGENT_INDENT leading spaces. Extra indent
        // (code blocks, nested lists) survives.
        let leading_spaces = trimmed.chars().take_while(|c| *c == ' ').count();
        let strip = leading_spaces.min(AGENT_INDENT);
        let stripped: String = trimmed.chars().skip(strip).collect();
        // Join: space for soft-wrap continuations, newline for hard
        // line boundaries. First emitted row never gets a leading
        // separator.
        if first_emitted {
            first_emitted = false;
        } else {
            out.push(if meta.continuation { ' ' } else { '\n' });
        }
        out.push_str(&stripped);
    }
    out
}

/// Rough row count for a history entry. Mirrors the breakdown in
/// `total_history_lines` so the spill math is consistent.
// Retained for the per-entry spill math; not yet called.
#[allow(dead_code)]
fn entry_rendered_rows(entry: &HistoryEntry) -> u16 {
    match entry {
        HistoryEntry::Plain { .. }
        | HistoryEntry::CommandError { .. }
        | HistoryEntry::Maintenance { .. } => 1,
        HistoryEntry::InterruptDecision { decision } => u16::try_from(decision.lines.len())
            .unwrap_or(u16::MAX)
            .max(1),
        HistoryEntry::InferenceError {
            detail, expanded, ..
        } => {
            if *expanded {
                detail.lines().count().max(1).saturating_add(1) as u16
            } else {
                1
            }
        }
        HistoryEntry::BackupWarning { .. } | HistoryEntry::InferenceWarning { .. } => 1,
        HistoryEntry::CompactBoundary {
            handoff, expanded, ..
        } => compact_boundary_row_estimate(handoff.as_deref(), *expanded),
        HistoryEntry::ToolLine { .. } => 1,
        HistoryEntry::LocalCommand { output, .. } => {
            (output.lines().count() as u16).saturating_add(1)
        }
        HistoryEntry::ToolBox { calls, .. } => toolbox_row_estimate(calls),
        HistoryEntry::Diff { old, new, .. } => diff_row_estimate(old, new),
        HistoryEntry::User { text, .. } => (text.matches('\n').count() as u16 + 1) + 2,
        // Header row + one row per body line (no bubble borders).
        HistoryEntry::UserNote { text, .. } => (text.matches('\n').count() as u16 + 1) + 1,
        // The `/{name} · injected by agent` row, plus the `  └ <reason>`
        // sub-line when a reason is present.
        HistoryEntry::SkillAutoInjected { reason, .. } => 1 + reason.is_some() as u16,
        HistoryEntry::Agent {
            text,
            reasoning,
            expanded,
            ..
        } => {
            let mut rows = text.matches('\n').count() as u16 + 1;
            if !reasoning.trim().is_empty() {
                rows = rows.saturating_add(1);
                if *expanded {
                    let reasoning_rows = reasoning.lines().count();
                    rows = rows.saturating_add(
                        reasoning_rows
                            .min(crate::tui::history::THINKING_VISIBLE)
                            .saturating_add(usize::from(
                                reasoning_rows > crate::tui::history::THINKING_VISIBLE,
                            )) as u16,
                    );
                }
            }
            rows
        }
        HistoryEntry::Subagent {
            outcome, expanded, ..
        } => match outcome {
            None => 1,
            Some(o) => {
                if o.report.trim().is_empty() {
                    1
                } else {
                    let lines = o.report.lines().count() as u16;
                    let body = if *expanded {
                        lines.saturating_add(1)
                    } else {
                        lines
                            .min(crate::tui::history::SUBAGENT_PREVIEW_LINES as u16)
                            .saturating_add(1)
                    };
                    body.saturating_add(1)
                }
            }
        },
    }
}

/// `1234 → "1.2k"`, `820 → "820"`. For the context indicator when no
/// max-context is known.
fn format_token_count(n: u32) -> String {
    if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1000.0)
    } else {
        n.to_string()
    }
}

/// The fresh-chat context-indicator label (`X tokens in <file>`), or
/// `None` to fall back to the normal context display. Shown only on a
/// truly fresh chat — no history and no provider usage yet — and only
/// when a guidance file was found (`file` is `Some`). `guidance_tokens`
/// is the guidance-file *body* size; the fallback context display
/// reflects the full system prompt separately. Pure so the
/// trigger/revert logic is unit-testable without standing up an `App`.
fn fresh_chat_guidance_label(
    history_empty: bool,
    has_usage: bool,
    file: Option<&str>,
    guidance_tokens: u64,
) -> Option<String> {
    if !history_empty || has_usage {
        return None;
    }
    let file = file?;
    let n = guidance_tokens.min(u32::MAX as u64) as u32;
    Some(format!("{} tokens in {file}", format_token_count(n)))
}

/// Split `body` for an embedded pane (GOALS §1i). Returns
/// `(chat_rect, pane_rect, divider)` where `divider` is
/// `(rect, is_vertical)`. Fullscreen — and bodies too small to split —
/// give the whole body to the pane with no chat rect and no divider.
fn split_body(
    side: PaneSide,
    ratio: f32,
    body: Rect,
) -> (Option<Rect>, Rect, Option<(Rect, bool)>) {
    let ratio = ratio.clamp(0.15, 0.85);
    match side {
        PaneSide::Full => (None, body, None),
        PaneSide::Left | PaneSide::Right => {
            if body.width < 3 {
                return (None, body, None);
            }
            // Reserve ≥1 col for chat and 1 for the divider.
            let max_pane = body.width.saturating_sub(2);
            let pane_w = ((body.width as f32 * ratio).round() as u16).clamp(1, max_pane);
            let chat_w = body.width - pane_w - 1;
            if side == PaneSide::Left {
                let pane = Rect::new(body.x, body.y, pane_w, body.height);
                let div = Rect::new(body.x + pane_w, body.y, 1, body.height);
                let chat = Rect::new(body.x + pane_w + 1, body.y, chat_w, body.height);
                (Some(chat), pane, Some((div, true)))
            } else {
                let chat = Rect::new(body.x, body.y, chat_w, body.height);
                let div = Rect::new(body.x + chat_w, body.y, 1, body.height);
                let pane = Rect::new(body.x + chat_w + 1, body.y, pane_w, body.height);
                (Some(chat), pane, Some((div, true)))
            }
        }
        PaneSide::Top | PaneSide::Bottom => {
            if body.height < 3 {
                return (None, body, None);
            }
            let max_pane = body.height.saturating_sub(2);
            let pane_h = ((body.height as f32 * ratio).round() as u16).clamp(1, max_pane);
            let chat_h = body.height - pane_h - 1;
            if side == PaneSide::Top {
                let pane = Rect::new(body.x, body.y, body.width, pane_h);
                let div = Rect::new(body.x, body.y + pane_h, body.width, 1);
                let chat = Rect::new(body.x, body.y + pane_h + 1, body.width, chat_h);
                (Some(chat), pane, Some((div, false)))
            } else {
                let chat = Rect::new(body.x, body.y, body.width, chat_h);
                let div = Rect::new(body.x, body.y + chat_h, body.width, 1);
                let pane = Rect::new(body.x, body.y + chat_h + 1, body.width, pane_h);
                (Some(chat), pane, Some((div, false)))
            }
        }
    }
}

/// First line of `s`, hard-clipped to `width` columns with a trailing
/// `…` when truncated. Used by the queue strip; only previews the first
/// line of multi-line queued messages to keep the box compact.
fn first_line_truncated(s: &str, width: usize) -> String {
    truncate_display_width(s, width)
}

fn input_visual_rows(measured: &str, prefix: usize, wrap_width: usize) -> usize {
    let budget = wrap_width.saturating_sub(prefix).max(1);
    let lines: Vec<&str> = if measured.is_empty() {
        vec![""]
    } else {
        measured.split('\n').collect()
    };
    lines
        .iter()
        .map(|line| wrap_display_chunks(line, budget).len().max(1))
        .sum::<usize>()
        .max(1)
}

/// Invert (REVERSED) the cells covering the composer's visual selection
/// byte range `[lo, hi)`. Walks the range char by char, mapping each
/// char's byte offset to a visual (row, col) via the composer display-width
/// mapper
/// and inverting that cell. A linewise selection's trailing `\n` maps to
/// the line-start of the next row; we stop at `hi` so it's never drawn.
/// Cells scrolled out of view (above `scroll_y`) or past the inner area
/// are skipped.
#[allow(clippy::too_many_arguments)]
fn apply_composer_visual_highlight(
    buf: &mut ratatui::buffer::Buffer,
    inner: Rect,
    text: &str,
    lo: usize,
    hi: usize,
    prefix: usize,
    inner_w: usize,
    scroll_y: u16,
) {
    let mut byte = lo;
    while byte < hi {
        let ch = match text[byte..].chars().next() {
            Some(c) => c,
            None => break,
        };
        // A `\n` occupies no visible cell; skip it.
        if ch != '\n' {
            let (vis_row, vis_col) = visual_position_for_byte(text, byte, prefix, inner_w);
            let row = vis_row as u16;
            if row >= scroll_y {
                let screen_row = inner.y + (row - scroll_y);
                let width = crate::tui::composer::display_width_char(ch).max(1);
                for offset in 0..width {
                    let screen_col = inner.x + vis_col as u16 + offset as u16;
                    if screen_row < inner.y + inner.height
                        && screen_col >= inner.x
                        && screen_col < inner.x + inner.width
                        && let Some(cell) = buf.cell_mut((screen_col, screen_row))
                    {
                        let style = cell.style().add_modifier(Modifier::REVERSED);
                        cell.set_style(style);
                    }
                }
            }
        }
        byte += ch.len_utf8();
    }
}

fn wrap_ghost_line_chunks(
    line: &str,
    budget: usize,
    first_row_budget: usize,
) -> Vec<(usize, usize, usize, usize)> {
    if line.is_empty() {
        return vec![(0, 0, 0, 0)];
    }
    let first = first_row_budget.max(1);
    if display_width(line) <= first {
        return vec![(0, line.len(), 0, display_width(line))];
    }

    let mut out = wrap_display_chunks(line, first);
    let Some((_, first_end, _, _)) = out.first().copied() else {
        return vec![(0, 0, 0, 0)];
    };
    out.truncate(1);
    if first_end < line.len() {
        out.extend(
            wrap_display_chunks(&line[first_end..], budget.max(1))
                .into_iter()
                .map(|(start, end, start_col, end_col)| {
                    (start + first_end, end + first_end, start_col, end_col)
                }),
        );
    }
    out
}

/// True for tools that take an `old_string` / `new_string` pair we
/// can render as a diff. `write` / `writeunlock` aren't in here yet
/// because the engine doesn't surface the pre-write file content.
pub(super) fn is_edit_tool(tool: &str) -> bool {
    matches!(tool, "edit" | "editunlock")
}

/// Approximate row count for a `Diff` entry, used by the chat-pane
/// sizing math. SideBySide ≈ max(old, new); Inline ≈ old + new. The
/// chat sizer doesn't know which mode is active at this point, so
/// we use the inline (upper-bound) estimate to avoid undersized
/// panes — slight over-allocation is cheaper than clipping.
pub(super) fn diff_row_estimate(old: &str, new: &str) -> u16 {
    let old_lines = old.matches('\n').count() as u16 + 1;
    let new_lines = new.matches('\n').count() as u16 + 1;
    old_lines.saturating_add(new_lines).saturating_add(1) // +1 for header
}

fn compact_boundary_row_estimate(handoff: Option<&str>, expanded: bool) -> u16 {
    let body = handoff.map(str::trim).filter(|s| !s.is_empty());
    if expanded {
        // One compact call row, five stats/input rows, then the ordinary
        // tool-result viewport (capped at 20 rows).
        6u16.saturating_add(body.map_or(0, |text| text.lines().count().min(20) as u16))
    } else {
        1
    }
}

/// Approximate rendered row count for a `ToolBox`. When every call is
/// collapsed it caps at [`crate::tui::history::TOOLBOX_VISIBLE`]; expanded
/// calls add their full input plus a capped result window. Mirrors
/// `render_toolbox` closely enough for scroll estimates.
pub(super) fn toolbox_row_estimate(calls: &[crate::tui::history::ToolCall]) -> u16 {
    use crate::tui::history::{TOOLBOX_VISIBLE, TOOLCALL_RESULT_VISIBLE, tool_shows_output};
    if !calls.iter().any(|call| call.expanded) {
        return calls.len().clamp(1, TOOLBOX_VISIBLE) as u16;
    }
    let mut rows: u16 = 0;
    for c in calls {
        if !c.expanded {
            rows = rows.saturating_add(1);
            continue;
        }
        let input_rows = c
            .full_input
            .split('\n')
            .map(|line| line.width().max(1))
            .sum::<usize>();
        rows = rows.saturating_add(input_rows as u16);
        if tool_shows_output(&c.tool) && !c.output.is_empty() {
            let result_lines = c.output.lines().count().max(1);
            let indicator_rows = usize::from(c.result_offset > 0)
                + usize::from(
                    result_lines > c.result_offset.saturating_add(TOOLCALL_RESULT_VISIBLE),
                );
            rows = rows.saturating_add(
                result_lines
                    .min(TOOLCALL_RESULT_VISIBLE)
                    .saturating_add(indicator_rows) as u16,
            );
        }
        if c.hint.is_some() {
            rows = rows.saturating_add(1);
        }
    }
    rows.max(1)
}

/// Hybrid live context count: the provider's last authoritative total
/// (`anchor`) plus the local estimate of tokens streamed since it was
/// reported (`estimate - estimate_at_anchor`). The delta saturates at
/// zero so a post-prune estimate dip can't pull the displayed value
/// below the provider's own count; a fresh provider report re-anchors
/// and zeroes the delta, correcting any accumulated drift.
fn hybrid_context_tokens(anchor: u32, estimate: u32, estimate_at_anchor: u32) -> u32 {
    anchor.saturating_add(estimate.saturating_sub(estimate_at_anchor))
}

/// `provider/model` for the reconnect status, collapsing the empty cases so
/// a utility/test target with a blank field still reads cleanly (`provider`,
/// `model`, or `model` alone — never a stray slash).
fn reconnect_target_label(provider: &str, model: &str) -> String {
    match (provider.trim(), model.trim()) {
        ("", "") => "the model server".to_string(),
        ("", m) => m.to_string(),
        (p, "") => p.to_string(),
        (p, m) => format!("{p}/{m}"),
    }
}

/// The full reconnect status line body (sans the agent-column indent): the
/// distinct, never-the-generic-spinner reconnect message naming the
/// unreachable target, the attempt count, and the elapsed clock. Pure so the
/// precedence + formatting is unit-testable.
fn reconnect_status_text(reconnect: &super::ReconnectStatus, dots: &str, elapsed: &str) -> String {
    format!(
        "reconnecting{dots} {} unreachable at {} (attempt {}) {elapsed}",
        reconnect_target_label(&reconnect.provider, &reconnect.model),
        reconnect.url,
        reconnect.attempt,
    )
}

fn daemon_link_status_text(status: &super::DaemonLinkStatus, dots: &str, elapsed: &str) -> String {
    let label = if status.restarting {
        "daemon restarting"
    } else {
        "daemon connection lost"
    };
    format!(
        "{label} — reconnecting{dots} (attempt {}) {elapsed}",
        status.attempt
    )
}

#[cfg(test)]
mod slash_popup_full_list_tests {
    use super::App;
    use crate::tui::app::{AUTOCOMPLETE_ROWS, SuggestionBoxKind, SuggestionBoxTarget};
    use crate::tui::theme::TRANSCRIPT_HOVER_BG;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;

    #[test]
    fn slash_suggestions_returns_full_match_list() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.composer.set("/".to_string());
        app.reset_slash_window();

        let matches = app.slash_suggestions();

        assert!(
            matches.len() > AUTOCOMPLETE_ROWS as usize,
            "bare slash should expose more than the visible window: {}",
            matches.len()
        );
    }

    #[test]
    fn slash_popup_renders_only_visible_window_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.composer.set("/".to_string());
        app.reset_slash_window();
        assert!(app.slash_suggestions().len() > AUTOCOMPLETE_ROWS as usize);

        let height = AUTOCOMPLETE_ROWS + 2;
        let backend = TestBackend::new(100, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                app.render_suggestion_box(frame, Rect::new(0, 0, 100, height));
            })
            .unwrap();

        let filled_rows = terminal
            .backend()
            .buffer()
            .content
            .chunks(100)
            .filter(|row| row.iter().any(|cell| cell.symbol() == "/"))
            .count();
        let scrollbar_cells = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .filter(|cell| cell.symbol() == "█")
            .count();

        assert_eq!(filled_rows, AUTOCOMPLETE_ROWS as usize);
        assert!(scrollbar_cells > 0, "scrollbar thumb should render");
        assert_eq!(app.suggestion_row_hits.len(), AUTOCOMPLETE_ROWS as usize);
    }

    #[test]
    fn slash_popup_render_keeps_wheel_scrolled_offset() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.composer.set("/".to_string());
        app.reset_slash_window();
        assert!(app.slash_suggestions().len() > AUTOCOMPLETE_ROWS as usize);

        app.scroll_slash_window_by(1);
        assert_eq!(app.slash_selected, 0);
        assert_eq!(app.slash_scroll, 1);

        let height = AUTOCOMPLETE_ROWS + 2;
        let backend = TestBackend::new(100, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                app.render_suggestion_box(frame, Rect::new(0, 0, 100, height));
            })
            .unwrap();

        assert_eq!(app.suggestion_row_hits[0].target.index, 1);
        assert!(
            !app.suggestion_row_hits
                .iter()
                .any(|hit| hit.target.index == app.slash_selected)
        );
    }

    #[test]
    fn at_popup_render_keeps_wheel_scrolled_offset_and_clamps() {
        let tmp = tempfile::tempdir().unwrap();
        for name in [
            "alpha.rs",
            "beta.rs",
            "gamma.rs",
            "delta.rs",
            "epsilon.rs",
            "zeta.rs",
            "eta.rs",
            "theta.rs",
            "iota.rs",
        ] {
            std::fs::write(tmp.path().join(name), "").unwrap();
        }
        let mut app = App::new(Some(tmp.path()), false);
        app.composer.set("@".to_string());
        app.reset_at_window();
        let total = app.at_suggestions().len();
        assert!(total > AUTOCOMPLETE_ROWS as usize);

        app.scroll_at_window_by(1);
        assert_eq!(app.at_selected, 0);
        assert_eq!(app.at_scroll, 1);

        let height = AUTOCOMPLETE_ROWS + 2;
        let backend = TestBackend::new(100, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                app.render_suggestion_box(frame, Rect::new(0, 0, 100, height));
            })
            .unwrap();

        assert_eq!(app.suggestion_row_hits[0].target.index, 1);
        assert!(
            !app.suggestion_row_hits
                .iter()
                .any(|hit| hit.target.index == app.at_selected)
        );

        app.at_scroll = usize::MAX;
        terminal
            .draw(|frame| {
                app.render_suggestion_box(frame, Rect::new(0, 0, 100, height));
            })
            .unwrap();
        assert_eq!(
            app.suggestion_row_hits[0].target.index,
            total - AUTOCOMPLETE_ROWS as usize
        );

        app.composer.set("@alpha".to_string());
        terminal
            .draw(|frame| {
                app.render_suggestion_box(frame, Rect::new(0, 0, 100, height));
            })
            .unwrap();
        assert_eq!(app.suggestion_row_hits[0].target.index, 0);
    }

    #[test]
    fn slash_suggestion_hover_paints_hover_background() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.composer.set("/".to_string());
        app.reset_slash_window();
        app.hovered_suggestion = Some(SuggestionBoxTarget {
            kind: SuggestionBoxKind::Slash,
            index: 0,
        });

        let height = AUTOCOMPLETE_ROWS + 2;
        let backend = TestBackend::new(100, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                app.render_suggestion_box(frame, Rect::new(0, 0, 100, height));
            })
            .unwrap();

        let buf = terminal.backend().buffer();
        assert!(
            (0..100).any(|col| buf[(col, 1)].style().bg == Some(TRANSCRIPT_HOVER_BG)),
            "hovered suggestion row should use shared hover background"
        );
    }
}

#[cfg(test)]
mod render_history_spacing_tests {
    use super::{
        App, ChatCopyTarget, ChatRowKind, ControlChip, Selection, TranscriptFind,
        affordance_target_for_row, extract_selection_plaintext,
    };
    use crate::config::extended::{DiffStyle, ThinkingDisplay, VimModeSetting};
    use crate::db::{open_default_call_count, reset_open_default_call_count};
    use crate::engine::message::{QueueItemStatus, QueueTarget, QueuedUserMessage};
    use crate::tokens::{count_call_count, reset_count_call_count};
    use crate::tui::app::{AffordanceTarget, SandboxDownNotice};
    use crate::tui::composer::VimMode;
    use crate::tui::history::{
        HistoryEntry, MarkdownOpts, PendingMsg, PendingRenderState, SubagentRoutingChips, ToolCall,
        ToolCallState, render_entry_call_count, render_pending, render_pending_incremental,
        reset_render_entry_call_count,
    };
    use crate::tui::markdown::{
        render_byte_count as markdown_render_byte_count,
        render_call_count as markdown_render_call_count,
        reset_render_counters as reset_markdown_counters,
    };
    use crate::tui::theme::TRANSCRIPT_HOVER_BG;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;
    use ratatui::style::Modifier;
    use std::rc::Rc;

    fn agent(text: &str) -> HistoryEntry {
        HistoryEntry::Agent {
            name: "Build".to_string(),
            text: text.to_string(),
            reasoning: String::new(),
            timestamp: chrono::Local::now(),
            expanded: false,
            reasoning_offset: 0,
            think_duration: None,
            seq: None,
        }
    }

    fn user(text: &str) -> HistoryEntry {
        HistoryEntry::User {
            text: text.to_string(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            preflight_pending: false,
            persist_failed: false,
        }
    }

    fn pinned_user(text: &str, seq: i64) -> HistoryEntry {
        HistoryEntry::User {
            text: text.to_string(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: Some(seq),
            preflight_pending: false,
            persist_failed: false,
        }
    }

    fn preflight_user(text: &str) -> HistoryEntry {
        HistoryEntry::User {
            text: text.to_string(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            preflight_pending: true,
            persist_failed: false,
        }
    }

    fn tool_box() -> HistoryEntry {
        HistoryEntry::ToolBox {
            calls: vec![ToolCall {
                call_id: "call-1".to_string(),
                tool: "bash".to_string(),
                summary: "ls".to_string(),
                full_input: "ls".to_string(),
                output: String::new(),
                expanded: false,
                result_offset: 0,
                state: ToolCallState::Success,
                hint: None,
            }],
            view_offset: 0,
            follow: true,
        }
    }

    fn expanded_tool_box(output: &str) -> HistoryEntry {
        HistoryEntry::ToolBox {
            calls: vec![ToolCall {
                call_id: "call-1".to_string(),
                tool: "bash".to_string(),
                summary: "printf".to_string(),
                full_input: "printf".to_string(),
                output: output.to_string(),
                expanded: true,
                result_offset: 0,
                state: ToolCallState::Success,
                hint: None,
            }],
            view_offset: 0,
            follow: true,
        }
    }

    fn diff_entry(path: &str) -> HistoryEntry {
        HistoryEntry::Diff {
            tool: "edit".to_string(),
            path: path.to_string(),
            old: "old line\n".to_string(),
            new: "new line\n".to_string(),
        }
    }

    fn compact_boundary(brief: &str) -> HistoryEntry {
        HistoryEntry::CompactBoundary {
            predecessor_short_id: "abc123".to_string(),
            seed_tool_count: 1,
            seed_tool_tokens: 0,
            source: "manual".to_string(),
            trigger_ctx_pct: None,
            tokens_before: 100,
            tokens_after: 50,
            turns_summarized: 1,
            tail_kept: 0,
            tail_trimmed: 0,
            handoff: Some(brief.to_string()),
            expanded: false,
            result_offset: 0,
        }
    }

    fn running_subagent() -> HistoryEntry {
        HistoryEntry::Subagent {
            parent: "Build".to_string(),
            child: "explore".to_string(),
            task_call_id: "call-1".to_string(),
            label: "default".to_string(),
            trusted_only: false,
            model_trusted: true,
            routing: SubagentRoutingChips::default(),
            spawned_at: std::time::Instant::now(),
            outcome: None,
            expanded: false,
        }
    }

    fn render_history_no_selection(app: &mut App, width: u16, height: u16) {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| app.render_history(f, Rect::new(0, 0, width, height)))
            .unwrap();
    }

    fn render_history(app: &mut App, width: u16, height: u16) {
        app.selection = Some(Selection {
            anchor: (0, 0),
            focus: (width.saturating_sub(1), height.saturating_sub(1)),
            active: false,
        });
        render_history_no_selection(app, width, height);
    }

    #[test]
    fn running_subagent_row_exposes_open_target() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.daemon_prompt = None;
        app.history.push(running_subagent());
        app.history_render_versions = vec![0; app.history.len()];
        app.history_render_fingerprints = vec![0; app.history.len()];

        render_history_no_selection(&mut app, 80, 6);

        assert!(
            app.chat_row_meta
                .iter()
                .any(|meta| meta.subagent_target == Some(0)),
            "running subagent row should be openable: {:?}",
            app.chat_row_meta
        );
        assert!(
            app.chat_row_meta
                .iter()
                .any(|meta| affordance_target_for_row(meta)
                    == Some(AffordanceTarget::Subagent { history_index: 0 }))
        );
    }

    #[test]
    fn opening_subagent_view_pushes_and_esc_restores_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.daemon_prompt = None;
        app.history.push(user("root prompt"));
        app.history.push(running_subagent());
        app.history_render_versions = vec![0; app.history.len()];
        app.history_render_fingerprints = vec![0; app.history.len()];

        assert!(app.open_subagent_view_for_history_index(1));
        assert!(app.active_subagent_view().is_some());
        assert_eq!(app.transcript_view_stack.len(), 1);
        assert!(
            app.history.is_empty(),
            "no persisted child rows in this unit test"
        );

        assert!(app.cancel_subagent_countdown_or_return());
        assert!(app.active_subagent_view().is_none());
        assert_eq!(app.history.len(), 2);
        assert_eq!(app.transcript_view_stack.len(), 0);
    }

    #[test]
    fn subagent_report_while_view_open_settles_parent_view() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.daemon_prompt = None;
        app.history.push(running_subagent());
        app.history_render_versions = vec![0; app.history.len()];
        app.history_render_fingerprints = vec![0; app.history.len()];

        assert!(app.open_subagent_view_for_history_index(0));
        app.apply_event(crate::engine::agent::TurnEvent::SubagentReport {
            agent: "explore".to_string(),
            task_call_id: "call-1".to_string(),
            label: "default".to_string(),
            report: "done".to_string(),
            trusted_only: false,
            model_trusted: true,
            routing: serde_json::Value::Null,
        });

        assert!(app.active_subagent_view().is_some_and(|view| view.finished));
        assert!(app.return_from_subagent_view());
        assert!(matches!(
            app.history.first(),
            Some(HistoryEntry::Subagent {
                outcome: Some(outcome),
                ..
            }) if outcome.report == "done"
        ));
    }

    fn render_history_buffer(app: &mut App, width: u16, height: u16) -> ratatui::buffer::Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| app.render_history(f, Rect::new(0, 0, width, height)))
            .unwrap();
        terminal.backend().buffer().clone()
    }

    fn render_app_buffer(app: &mut App, width: u16, height: u16) -> ratatui::buffer::Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        crate::tui::banner_box::with_test_banner_visible(|| {
            terminal.draw(|frame| app.render(frame)).unwrap();
        });
        terminal.backend().buffer().clone()
    }

    fn banner_top_row(buffer: &ratatui::buffer::Buffer, width: u16, height: u16) -> usize {
        (0..height)
            .find(|&y| (0..width).any(|x| buffer[(x, y)].symbol() == "╭"))
            .map(usize::from)
            .expect("launch banner top border")
    }

    fn empty_banner_app(root: &std::path::Path) -> App {
        let mut app = App::new(Some(root), false);
        app.daemon_prompt = None;
        app.launch.banner_enabled = true;
        app.vim_setting = VimModeSetting::Disabled;
        app.composer.set_vim_enabled(false);
        app
    }

    #[test]
    fn banner_row_stable_across_transient_chrome() {
        const WIDTH: u16 = 100;
        const HEIGHT: u16 = 40;
        let tmp = tempfile::tempdir().unwrap();
        for name in ["alpha.rs", "beta.rs", "gamma.rs"] {
            std::fs::write(tmp.path().join(name), "").unwrap();
        }

        let mut idle = empty_banner_app(tmp.path());
        let expected = banner_top_row(&render_app_buffer(&mut idle, WIDTH, HEIGHT), WIDTH, HEIGHT);

        let mut slash_full = empty_banner_app(tmp.path());
        slash_full.composer.set("/");
        slash_full.reset_slash_window();
        assert_eq!(
            banner_top_row(
                &render_app_buffer(&mut slash_full, WIDTH, HEIGHT),
                WIDTH,
                HEIGHT
            ),
            expected
        );

        let mut slash_small = empty_banner_app(tmp.path());
        slash_small.composer.set("/help");
        slash_small.reset_slash_window();
        assert_eq!(
            banner_top_row(
                &render_app_buffer(&mut slash_small, WIDTH, HEIGHT),
                WIDTH,
                HEIGHT
            ),
            expected
        );

        let mut at_popup = empty_banner_app(tmp.path());
        at_popup.composer.set("@");
        at_popup.reset_at_window();
        assert_eq!(
            banner_top_row(
                &render_app_buffer(&mut at_popup, WIDTH, HEIGHT),
                WIDTH,
                HEIGHT
            ),
            expected
        );

        let mut vim_hint = empty_banner_app(tmp.path());
        vim_hint.vim_setting = VimModeSetting::Hint;
        vim_hint.composer.set_vim_enabled(true);
        vim_hint.composer.set_vim_mode(VimMode::Normal);
        assert_eq!(
            banner_top_row(
                &render_app_buffer(&mut vim_hint, WIDTH, HEIGHT),
                WIDTH,
                HEIGHT
            ),
            expected
        );

        let mut tall_input = empty_banner_app(tmp.path());
        tall_input.composer.set("one\ntwo\nthree\nfour\nfive\nsix");
        assert_eq!(
            banner_top_row(
                &render_app_buffer(&mut tall_input, WIDTH, HEIGHT),
                WIDTH,
                HEIGHT
            ),
            expected
        );

        let mut queued = empty_banner_app(tmp.path());
        queued.queue.push(QueuedUserMessage {
            id: uuid::Uuid::new_v4(),
            status: QueueItemStatus::Queued,
            text: "queued".to_string(),
            display_text: None,
            target: QueueTarget::default(),
        });
        assert_eq!(
            banner_top_row(
                &render_app_buffer(&mut queued, WIDTH, HEIGHT),
                WIDTH,
                HEIGHT
            ),
            expected
        );

        let mut pinned = empty_banner_app(tmp.path());
        pinned.pin_count = 1;
        assert_eq!(
            banner_top_row(
                &render_app_buffer(&mut pinned, WIDTH, HEIGHT),
                WIDTH,
                HEIGHT
            ),
            expected
        );

        let mut sandbox = empty_banner_app(tmp.path());
        sandbox.sandbox_down_notice = Some(SandboxDownNotice {
            remedy: "enable unprivileged user namespaces".to_string(),
            fix_command: None,
        });
        assert_eq!(
            banner_top_row(
                &render_app_buffer(&mut sandbox, WIDTH, HEIGHT),
                WIDTH,
                HEIGHT
            ),
            expected
        );
    }

    #[test]
    fn banner_clamped_when_transient_chrome_would_overlap() {
        const WIDTH: u16 = 100;
        const HEIGHT: u16 = 24;
        let tmp = tempfile::tempdir().unwrap();
        let mut app = empty_banner_app(tmp.path());
        app.composer.set("/");
        app.reset_slash_window();

        let buffer = render_app_buffer(&mut app, WIDTH, HEIGHT);
        let top = banner_top_row(&buffer, WIDTH, HEIGHT);
        let banner_height = app.chat_banner_lines;
        let chat = app.chat_area.expect("chat area");
        let rects = app.geometry().layout(Rect::new(0, 0, WIDTH, HEIGHT));

        assert_eq!(top, chat.height as usize - banner_height);
        assert!(top + banner_height <= rects.suggestions.y as usize);
    }

    #[test]
    fn banner_resting_position_unchanged_without_transient_chrome() {
        const WIDTH: u16 = 100;
        const HEIGHT: u16 = 40;
        let tmp = tempfile::tempdir().unwrap();
        let mut app = empty_banner_app(tmp.path());

        let buffer = render_app_buffer(&mut app, WIDTH, HEIGHT);
        let top = banner_top_row(&buffer, WIDTH, HEIGHT);
        let area_h = app.chat_area.expect("chat area").height as usize;

        assert_eq!(top, (area_h - app.chat_banner_lines) / 2);
    }

    #[test]
    fn banner_behavior_unchanged_once_transcript_nonempty() {
        const WIDTH: u16 = 100;
        const HEIGHT: u16 = 32;
        let tmp = tempfile::tempdir().unwrap();
        let mut app = empty_banner_app(tmp.path());
        app.history.push(user("first message"));

        let buffer = render_app_buffer(&mut app, WIDTH, HEIGHT);
        let top = banner_top_row(&buffer, WIDTH, HEIGHT);
        let area_h = app.chat_area.expect("chat area").height as usize;
        let banner_height = app.chat_banner_lines;
        let message_height = app.chat_total_lines - banner_height;
        assert_eq!(
            top,
            ((area_h - banner_height) / 2).min(area_h - message_height - banner_height)
        );

        app.history = (0..40)
            .map(|index| user(&format!("overflow message {index}")))
            .collect();
        let _ = render_app_buffer(&mut app, WIDTH, HEIGHT);
        assert!(
            app.chat_row_meta
                .iter()
                .all(|meta| meta.row_kind != ChatRowKind::Banner),
            "overflow keeps the launch banner above the visible bottom window"
        );
    }

    fn buffer_rows(buffer: &ratatui::buffer::Buffer, width: u16, height: u16) -> Vec<String> {
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn render_calls_after(app: &mut App, width: u16, height: u16) -> usize {
        reset_render_entry_call_count();
        render_history_no_selection(app, width, height);
        render_entry_call_count()
    }

    fn row_text(app: &App, row: usize) -> String {
        app.chat_text_grid[row].concat()
    }

    fn nonblank_rows(app: &App) -> Vec<(usize, String)> {
        app.chat_text_grid
            .iter()
            .enumerate()
            .map(|(idx, row)| (idx, row.concat()))
            .filter(|(_, row)| !row.trim().is_empty())
            .collect()
    }

    fn find_row(app: &App, needle: &str) -> usize {
        app.chat_text_grid
            .iter()
            .position(|row| row.concat().contains(needle))
            .unwrap_or_else(|| {
                panic!(
                    "missing rendered row containing {needle:?} in:\n{}",
                    app.chat_text_grid
                        .iter()
                        .map(|row| row.concat())
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            })
    }

    fn extract_full_selection(app: &App, width: u16, height: u16) -> String {
        extract_selection_plaintext(
            &app.chat_text_grid,
            &app.chat_row_meta,
            Rect::new(0, 0, width, height),
            Selection {
                anchor: (0, 0),
                focus: (width.saturating_sub(1), height.saturating_sub(1)),
                active: false,
            },
        )
    }

    #[test]
    fn render_history_cache_reuses_unchanged_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![user("question"), agent("answer")];

        assert_eq!(render_calls_after(&mut app, 80, 8), 2);
        app.working_msg_idx = app.working_msg_idx.wrapping_add(1);

        assert_eq!(
            render_calls_after(&mut app, 80, 8),
            0,
            "unrelated chrome state should not re-render stable history entries"
        );
    }

    #[test]
    fn render_history_uses_cached_pin_state_without_db_refresh() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.mouse_capture = true;
        let session_id = uuid::Uuid::new_v4();
        app.launch.session_id = Some(session_id);
        app.pinned_seqs_session = Some(session_id);
        app.pinned_seqs_cache.insert(42);
        app.history = vec![pinned_user("pin me", 42)];

        reset_open_default_call_count();
        assert_eq!(render_calls_after(&mut app, 80, 8), 1);
        assert_eq!(open_default_call_count(), 0);
        assert!(
            app.pin_control_rows
                .iter()
                .flatten()
                .any(|hit| hit.seq == 42),
            "render should expose the cached pin control hit region"
        );
        assert_eq!(render_calls_after(&mut app, 80, 8), 0);
        assert_eq!(open_default_call_count(), 0);
    }

    #[test]
    fn pending_render_cache_reuses_unchanged_markdown() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.pending = Some(PendingMsg {
            name: "Build".to_string(),
            text: "**streaming**".to_string(),
            reasoning: String::new(),
            timestamp: chrono::Local::now(),
            started_at: std::time::Instant::now(),
            text_started_at: Some(std::time::Instant::now()),
            inside_think: false,
            body_started: true,
            tag_partial: String::new(),
            seq: None,
            strip_think: true,
        });

        reset_markdown_counters();
        render_history_no_selection(&mut app, 80, 8);
        assert!(markdown_render_call_count() > 0);

        reset_markdown_counters();
        app.working_msg_idx = app.working_msg_idx.wrapping_add(1);
        render_history_no_selection(&mut app, 80, 8);
        assert_eq!(markdown_render_call_count(), 0);

        app.pending.as_mut().unwrap().text.push_str(" more");
        render_history_no_selection(&mut app, 80, 8);
        assert!(markdown_render_call_count() > 0);

        reset_markdown_counters();
        render_history_no_selection(&mut app, 81, 8);
        assert!(markdown_render_call_count() > 0);
    }

    #[test]
    fn pending_incremental_render_matches_full_render_for_markdown_corpus() {
        let cases = [
            "# Heading\n\nParagraph with **bold**, _italic_, and `code`.\n\n",
            "- one\n- two\n  - nested\n\nfinal paragraph\n",
            "> quoted\n> continued\n\nplain\n",
            "name | value\n--- | ---\na | b\n\nnext\n",
            "```rust\nfn main() {\n    println!(\"hi\");\n}\n```\n\nafter fence\n",
            "Setext heading\n---\n\nbody\n",
            "inline math \\(a+b\\) and display:\n\n\\[x^2\\]\n\n",
        ];

        for case in cases {
            let mut msg = PendingMsg {
                name: "Build".to_string(),
                text: String::new(),
                reasoning: String::new(),
                timestamp: chrono::Local::now(),
                started_at: std::time::Instant::now(),
                text_started_at: Some(std::time::Instant::now()),
                inside_think: false,
                body_started: true,
                tag_partial: String::new(),
                seq: None,
                strip_think: true,
            };
            let mut state = PendingRenderState::default();
            for chunk in case.as_bytes().chunks(7) {
                msg.text.push_str(std::str::from_utf8(chunk).unwrap());
                let incremental = render_pending_incremental(&msg, 72, &mut state);
                let full = render_pending(&msg, 72);
                assert_eq!(incremental, full, "case failed after {:?}", msg.text);
            }
        }
    }

    #[test]
    fn pending_incremental_render_matches_full_render_and_bounds_parse_bytes() {
        let mut msg = PendingMsg {
            name: "Build".to_string(),
            text: String::new(),
            reasoning: String::new(),
            timestamp: chrono::Local::now(),
            started_at: std::time::Instant::now(),
            text_started_at: Some(std::time::Instant::now()),
            inside_think: false,
            body_started: true,
            tag_partial: String::new(),
            seq: None,
            strip_think: true,
        };
        let doc = (0..400)
            .map(|idx| format!("paragraph {idx} has **bold** text and `code`\n\n"))
            .collect::<String>();
        let mut state = PendingRenderState::default();
        let mut incremental_bytes = 0usize;

        for chunk in doc.as_bytes().chunks(53) {
            msg.text.push_str(std::str::from_utf8(chunk).unwrap());

            reset_markdown_counters();
            let incremental = render_pending_incremental(&msg, 96, &mut state);
            incremental_bytes += markdown_render_byte_count();

            reset_markdown_counters();
            let full = render_pending(&msg, 96);
            assert_eq!(incremental, full);
        }

        assert!(
            incremental_bytes < doc.len() * 8,
            "incremental parser read {incremental_bytes} bytes for {} bytes of input",
            doc.len()
        );
    }

    #[test]
    fn render_history_cache_invalidates_width_and_render_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![agent("**answer**")];

        assert_eq!(render_calls_after(&mut app, 80, 8), 1);
        assert_eq!(render_calls_after(&mut app, 81, 8), 1);

        app.thinking_setting = ThinkingDisplay::Verbose;
        assert_eq!(render_calls_after(&mut app, 81, 8), 1);

        app.markdown_opts = MarkdownOpts {
            agent: !app.markdown_opts.agent,
            ..app.markdown_opts
        };
        assert_eq!(render_calls_after(&mut app, 81, 8), 1);

        app.diff_style = DiffStyle::Inline;
        assert_eq!(render_calls_after(&mut app, 81, 8), 1);

        app.use_emojis = !app.use_emojis;
        assert_eq!(render_calls_after(&mut app, 81, 8), 1);
        assert_eq!(render_calls_after(&mut app, 81, 8), 0);
    }

    #[test]
    fn render_history_cache_invalidates_entry_pin_and_elision_state() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.use_emojis = false;
        app.history = vec![pinned_user("pin me", 42), tool_box()];

        assert_eq!(render_calls_after(&mut app, 80, 8), 2);

        app.mouse_capture = !app.mouse_capture;
        assert_eq!(
            render_calls_after(&mut app, 80, 8),
            1,
            "pin chrome state should invalidate only the pinnable row"
        );

        app.elided_event_ids.insert("call-1".to_string());
        assert_eq!(
            render_calls_after(&mut app, 80, 8),
            1,
            "elided tool-call state should invalidate the affected toolbox row"
        );
    }

    #[test]
    fn render_history_cache_invalidates_expanded_state_and_preflight_phase() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![agent("answer"), preflight_user("pending")];

        assert_eq!(render_calls_after(&mut app, 80, 8), 2);
        if let HistoryEntry::Agent { expanded, .. } = &mut app.history[0] {
            *expanded = true;
        }
        assert_eq!(render_calls_after(&mut app, 80, 8), 1);

        app.started_at -= std::time::Duration::from_millis(333);
        assert_eq!(
            render_calls_after(&mut app, 80, 8),
            1,
            "pending preflight row should update as animated dots advance"
        );

        if let HistoryEntry::User {
            preflight_pending, ..
        } = &mut app.history[1]
        {
            *preflight_pending = false;
        }
        assert_eq!(render_calls_after(&mut app, 80, 8), 1);
        app.started_at -= std::time::Duration::from_millis(333);
        assert_eq!(
            render_calls_after(&mut app, 80, 8),
            0,
            "settled preflight row should cache again and ignore elapsed time"
        );
    }

    #[test]
    fn render_history_skips_grid_capture_without_selection() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![HistoryEntry::Plain {
            line: "visible text".to_string(),
        }];

        render_history_no_selection(&mut app, 20, 4);
        assert!(app.chat_text_grid.is_empty());

        render_history(&mut app, 20, 4);
        assert_eq!(app.chat_text_grid.len(), 4);
        assert!(
            nonblank_rows(&app)
                .iter()
                .any(|(_, row)| row.contains("visible text"))
        );
    }

    #[test]
    fn render_history_builds_find_lines_only_while_find_is_open() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![user("findable target")];

        render_history_no_selection(&mut app, 40, 8);
        assert!(app.chat_find_lines.is_empty());

        app.transcript_find = Some(TranscriptFind {
            query: "findable".to_string(),
            matches: Vec::new(),
            current: None,
            saved_offset: 0,
        });
        render_history_no_selection(&mut app, 40, 8);

        assert_eq!(app.chat_find_lines.len(), app.chat_total_lines);
        assert!(
            app.chat_find_lines
                .iter()
                .any(|line| line.contains("findable target"))
        );
        assert!(!app.transcript_find.as_ref().unwrap().matches.is_empty());
    }

    #[test]
    fn render_history_cache_hits_reuse_rendered_rc() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![agent("stable cached text")];

        render_history_no_selection(&mut app, 80, 8);
        let first = Rc::clone(&app.history_render_cache.get(&0).unwrap().rendered);

        render_history_no_selection(&mut app, 80, 8);
        let second = Rc::clone(&app.history_render_cache.get(&0).unwrap().rendered);

        assert!(Rc::ptr_eq(&first, &second));
    }

    #[test]
    fn pending_token_count_is_memoized_by_lengths() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.pending = Some(PendingMsg {
            name: "Build".to_string(),
            text: "hello world".to_string(),
            reasoning: "thinking".to_string(),
            timestamp: chrono::Local::now(),
            started_at: std::time::Instant::now(),
            text_started_at: None,
            inside_think: false,
            body_started: true,
            tag_partial: String::new(),
            seq: None,
            strip_think: false,
        });

        reset_count_call_count();
        let first = app.message_tokens();
        assert_eq!(count_call_count(), 2);

        assert_eq!(app.message_tokens(), first);
        assert_eq!(count_call_count(), 2);

        app.pending.as_mut().unwrap().text.push('!');
        let _ = app.message_tokens();
        assert_eq!(count_call_count(), 4);
    }

    #[test]
    fn chat_row_meta_marks_bottom_padding_and_launch_banner_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = true;
        app.history = vec![user("short")];

        render_history_no_selection(&mut app, 100, 24);

        assert_eq!(app.chat_row_meta.len(), app.chat_visible_lines);
        assert!(
            app.chat_row_meta
                .iter()
                .any(|meta| meta.row_kind == ChatRowKind::Padding),
            "under-full chat pane should expose non-content padding rows"
        );
        let banner_rows = app
            .chat_row_meta
            .iter()
            .filter(|meta| meta.row_kind == ChatRowKind::Banner)
            .count();
        assert_eq!(banner_rows, app.chat_banner_lines);
    }

    #[test]
    fn transcript_find_bar_suppresses_scroll_indicator_and_shows_no_match() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![HistoryEntry::Plain {
            line: "visible text".to_string(),
        }];
        app.chat_scroll_offset = 2;
        app.transcript_find = Some(TranscriptFind {
            query: "missing".to_string(),
            matches: Vec::new(),
            current: None,
            saved_offset: 2,
        });

        let buffer = render_history_buffer(&mut app, 40, 4);

        let rows = buffer_rows(&buffer, 40, 4);
        assert!(rows.iter().any(|row| row.contains("find: missing")));
        assert!(rows.iter().any(|row| row.contains("no matches")));
        assert!(rows.iter().all(|row| !row.contains("more")));
    }

    #[test]
    fn transcript_find_highlights_current_match() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![HistoryEntry::Plain {
            line: "alpha needle omega".to_string(),
        }];
        app.transcript_find = Some(TranscriptFind {
            query: "needle".to_string(),
            matches: Vec::new(),
            current: None,
            saved_offset: 0,
        });

        let buf = render_history_buffer(&mut app, 40, 4);
        let row = find_row(&app, "needle") as u16;

        assert!((0..40).any(|col| {
            buf[(col, row)]
                .style()
                .add_modifier
                .contains(Modifier::REVERSED)
        }));
    }

    #[test]
    fn agent_immediately_followed_by_toolbox_has_no_separator_but_toolbox_keeps_gap() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.use_emojis = false;
        app.history = vec![
            user("question"),
            agent("thinking before tool"),
            tool_box(),
            agent("after tool"),
        ];

        render_history(&mut app, 80, 12);

        let user_row = find_row(&app, "question");
        let first_agent_row = find_row(&app, "thinking before tool");
        let tool_row = find_row(&app, "bash");
        let next_agent_row = find_row(&app, "after tool");

        assert!(
            first_agent_row > user_row + 1,
            "user-to-agent spacing remains separated"
        );
        assert_eq!(
            tool_row,
            first_agent_row + 1,
            "toolbox starts directly after the agent row"
        );
        assert!(
            row_text(&app, tool_row + 1).trim().is_empty(),
            "toolbox keeps its trailing separator row"
        );
        assert_eq!(
            next_agent_row,
            tool_row + 2,
            "next distinct block starts after the toolbox separator"
        );

        assert_eq!(
            app.box_rows[tool_row],
            Some(2),
            "toolbox row maps to the ToolBox history index"
        );
        assert_eq!(
            app.box_rows[first_agent_row], None,
            "agent row is not a toolbox click target"
        );
        assert_eq!(
            app.box_rows[tool_row + 1],
            None,
            "separator row is not a toolbox click target"
        );
    }

    #[test]
    fn compact_tool_call_click_expands_and_collapses_handoff() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.use_emojis = false;
        app.history = vec![compact_boundary("handoff line")];

        render_history(&mut app, 80, 20);
        let call_row = find_row(&app, "compact:");
        assert!(
            !nonblank_rows(&app)
                .iter()
                .any(|(_, row)| row.contains("handoff line")),
            "handoff starts collapsed"
        );

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 1,
            row: call_row as u16,
            modifiers: KeyModifiers::empty(),
        });
        render_history(&mut app, 80, 20);
        assert!(
            nonblank_rows(&app)
                .iter()
                .any(|(_, row)| row.contains("handoff line")),
            "tool-call click expands the compact handoff"
        );

        let call_row = find_row(&app, "compact:");
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 1,
            row: call_row as u16,
            modifiers: KeyModifiers::empty(),
        });
        render_history(&mut app, 80, 20);
        assert!(
            !nonblank_rows(&app)
                .iter()
                .any(|(_, row)| row.contains("handoff line")),
            "second tool-call click collapses the compact handoff"
        );
    }

    #[test]
    fn chat_history_prewraps_plain_rows_before_paragraph_rendering() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![HistoryEntry::Plain {
            line: "abcdefghijklmnopqrstuvwxyz".to_string(),
        }];

        render_history(&mut app, 10, 6);

        let rows = nonblank_rows(&app);
        assert_eq!(app.chat_total_lines, 3);
        assert_eq!(app.chat_visible_lines, 6);
        assert_eq!(rows.len(), 3);
        assert!(rows[0].1.contains("  abcdefgh"));
        assert!(rows[1].1.contains("ijklmnopqr"));
        assert!(rows[2].1.contains("stuvwxyz"));
    }

    #[test]
    fn bottom_pinning_uses_wrapped_visual_rows_for_newest_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![HistoryEntry::Plain {
            line: "abcdefghijklmnopqrstuvwxyz".to_string(),
        }];

        render_history(&mut app, 10, 5);

        assert_eq!(row_text(&app, 0).trim(), "");
        assert_eq!(row_text(&app, 1).trim(), "");
        assert!(row_text(&app, 2).contains("  abcdefgh"));
        assert!(row_text(&app, 3).contains("ijklmnopqr"));
        assert!(row_text(&app, 4).contains("stuvwxyz"));
    }

    #[test]
    fn wrapped_toolbox_rows_keep_toolbox_hit_target() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.use_emojis = false;
        app.history = vec![
            user("question"),
            expanded_tool_box("abcdefghijklmnopqrstuv"),
        ];

        render_history(&mut app, 12, 10);

        let first = find_row(&app, "abcdef");
        let second = find_row(&app, "mnopqr");
        assert_eq!(app.box_rows[first], Some(1));
        assert_eq!(app.box_rows[second], Some(1));
    }

    #[test]
    fn chat_row_meta_aligns_with_visible_rows_and_existing_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.use_emojis = false;
        app.history = vec![
            user("question"),
            agent("assistant answer"),
            expanded_tool_box("tool output"),
            diff_entry("src/lib.rs"),
        ];

        render_history(&mut app, 40, 12);

        assert_eq!(app.chat_row_meta.len(), app.chat_visible_lines);
        assert_eq!(app.chat_row_meta.len(), app.chat_text_grid.len());
        assert_eq!(
            app.clickable_rows,
            app.chat_row_meta
                .iter()
                .map(|meta| meta.chip_target)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            app.box_rows,
            app.chat_row_meta
                .iter()
                .map(|meta| meta.tool_box_target)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            app.chat_cont_rows,
            app.chat_row_meta
                .iter()
                .map(|meta| meta.continuation)
                .collect::<Vec<_>>()
        );

        let user_row = find_row(&app, "question");
        let agent_row = find_row(&app, "assistant answer");
        let tool_row = find_row(&app, "bash");
        let diff_row = find_row(&app, "src/lib.rs");
        assert_eq!(app.chat_row_meta[user_row].row_kind, ChatRowKind::Message);
        assert_eq!(
            app.chat_row_meta[user_row].copy_target,
            Some(ChatCopyTarget::Message { history_index: 0 })
        );
        assert_eq!(app.chat_row_meta[agent_row].row_kind, ChatRowKind::Message);
        assert_eq!(
            app.chat_row_meta[agent_row].copy_target,
            Some(ChatCopyTarget::Message { history_index: 1 })
        );
        assert_eq!(app.chat_row_meta[tool_row].row_kind, ChatRowKind::ToolBox);
        assert_eq!(app.chat_row_meta[tool_row].tool_box_target, Some(2));
        assert_eq!(app.chat_row_meta[diff_row].row_kind, ChatRowKind::Diff);
        assert_eq!(
            app.chat_row_meta[diff_row].diff_path.as_deref(),
            Some("src/lib.rs")
        );
    }

    fn row_has_hover_bg(buffer: &ratatui::buffer::Buffer, row: usize, width: u16) -> bool {
        (0..width).any(|col| buffer[(col, row as u16)].style().bg == Some(TRANSCRIPT_HOVER_BG))
    }

    fn assert_row_has_inset_hover(buffer: &ratatui::buffer::Buffer, row: usize, width: u16) {
        assert_ne!(
            buffer[(0, row as u16)].style().bg,
            Some(TRANSCRIPT_HOVER_BG),
            "left transcript margin should stay unhighlighted"
        );
        assert_ne!(
            buffer[(width - 1, row as u16)].style().bg,
            Some(TRANSCRIPT_HOVER_BG),
            "right transcript margin should stay unhighlighted"
        );
        for col in crate::tui::history::AGENT_INDENT as u16
            ..width - crate::tui::history::AGENT_INDENT as u16
        {
            assert_eq!(
                buffer[(col, row as u16)].style().bg,
                Some(TRANSCRIPT_HOVER_BG),
                "column {col} should carry the inset hover background"
            );
        }
    }

    #[test]
    fn hovered_control_chip_highlights_only_selected_chip_glyphs() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.mouse_capture = true;
        app.history = vec![pinned_user("pin me", 42)];

        render_history(&mut app, 80, 8);
        let row = app
            .chat_row_meta
            .iter()
            .position(|meta| meta.fork_hit.is_some() && meta.pin_hit.is_some())
            .expect("fork and pin controls rendered");
        let fork = app.chat_row_meta[row].fork_hit.expect("fork hit");
        let pin = app.chat_row_meta[row].pin_hit.expect("pin hit");

        app.hovered_control_chip = Some(ControlChip::Fork { seq: 42 });
        let fork_buffer = render_history_buffer(&mut app, 80, 8);
        for col in fork.col_start..fork.col_end {
            assert_eq!(
                fork_buffer[(col, row as u16)].style().bg,
                Some(TRANSCRIPT_HOVER_BG),
                "fork column {col} should be highlighted"
            );
        }
        for col in pin.col_start..pin.col_end {
            assert_ne!(
                fork_buffer[(col, row as u16)].style().bg,
                Some(TRANSCRIPT_HOVER_BG),
                "pin column {col} should not be highlighted by fork hover"
            );
        }
        assert_ne!(
            fork_buffer[(fork.col_start - 1, row as u16)].style().bg,
            Some(TRANSCRIPT_HOVER_BG)
        );

        app.hovered_control_chip = Some(ControlChip::Pin { seq: 42 });
        let pin_buffer = render_history_buffer(&mut app, 80, 8);
        for col in pin.col_start..pin.col_end {
            assert_eq!(
                pin_buffer[(col, row as u16)].style().bg,
                Some(TRANSCRIPT_HOVER_BG),
                "pin column {col} should be highlighted"
            );
        }
        for col in fork.col_start..fork.col_end {
            assert_ne!(
                pin_buffer[(col, row as u16)].style().bg,
                Some(TRANSCRIPT_HOVER_BG),
                "fork column {col} should not be highlighted by pin hover"
            );
        }
    }

    #[test]
    fn hovered_tool_call_rows_get_background_highlight_only_while_hovered() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.use_emojis = false;
        app.history = vec![agent("assistant answer"), expanded_tool_box("tool output")];

        render_history(&mut app, 80, 8);
        let agent_row = find_row(&app, "assistant answer");
        let tool_row = find_row(&app, "bash");
        app.selection = None;
        app.hovered_affordance = Some(AffordanceTarget::ToolCall {
            history_index: 1,
            call_index: 0,
        });

        let buffer = render_history_buffer(&mut app, 80, 8);
        assert_row_has_inset_hover(&buffer, tool_row, 80);
        assert!(!row_has_hover_bg(&buffer, agent_row, 80));

        app.hovered_affordance = None;
        let cleared = render_history_buffer(&mut app, 80, 8);
        assert!(!row_has_hover_bg(&cleared, tool_row, 80));
    }

    #[test]
    fn context_copy_resolves_exact_older_assistant_row() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![agent("older answer"), agent("newer answer")];

        render_history(&mut app, 80, 8);
        let older = find_row(&app, "older answer");

        assert_eq!(
            app.message_at_chat_row(older),
            Some(("Build message".to_string(), "older answer".to_string()))
        );
    }

    #[test]
    fn context_copy_resolves_exact_user_row() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![user("copy this user message"), agent("assistant")];

        render_history(&mut app, 80, 8);
        let row = find_row(&app, "copy this user message");

        assert_eq!(
            app.message_at_chat_row(row),
            Some((
                "user message".to_string(),
                "copy this user message".to_string()
            ))
        );
    }

    #[test]
    fn wrapped_message_continuations_resolve_to_same_copy_target() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![
            user("userwrapabcdefghijklmnopqrstuvwxyz"),
            agent("agentwrapabcdefghijklmnopqrstuvwxyz"),
        ];

        render_history(&mut app, 24, 16);

        let user_second = app
            .chat_row_meta
            .iter()
            .position(|meta| {
                meta.copy_target == Some(ChatCopyTarget::Message { history_index: 0 })
                    && meta.continuation
            })
            .expect("wrapped user continuation row");
        assert_eq!(
            app.message_at_chat_row(user_second),
            Some((
                "user message".to_string(),
                "userwrapabcdefghijklmnopqrstuvwxyz".to_string()
            ))
        );

        let agent_second = app
            .chat_row_meta
            .iter()
            .position(|meta| {
                meta.copy_target == Some(ChatCopyTarget::Message { history_index: 1 })
                    && meta.continuation
            })
            .expect("wrapped assistant continuation row");
        assert_eq!(
            app.message_at_chat_row(agent_second),
            Some((
                "Build message".to_string(),
                "agentwrapabcdefghijklmnopqrstuvwxyz".to_string()
            ))
        );
    }

    #[test]
    fn blank_separator_row_has_no_context_copy_target() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![user("question"), agent("answer")];

        render_history(&mut app, 80, 8);
        let blank = app
            .chat_text_grid
            .iter()
            .position(|row| row.concat().trim().is_empty())
            .expect("bottom padding or separator row");

        assert_eq!(app.chat_row_meta[blank].copy_target, None);
        assert_eq!(app.message_at_chat_row(blank), None);
    }

    #[test]
    fn diff_rows_resolve_editor_path_through_row_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![diff_entry("src/main.rs")];

        render_history(&mut app, 80, 8);
        let row = find_row(&app, "src/main.rs");

        assert_eq!(
            app.chat_row_meta[row].diff_path.as_deref(),
            Some("src/main.rs")
        );
        assert_eq!(app.diff_rows[row].as_deref(), Some("src/main.rs"));
    }

    #[test]
    fn selection_copy_skips_collapsed_compact_handoff() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![
            HistoryEntry::Plain {
                line: "before chip".to_string(),
            },
            compact_boundary("hidden brief"),
            HistoryEntry::Plain {
                line: "after chip".to_string(),
            },
        ];
        app.selection = Some(Selection {
            anchor: (0, 0),
            focus: (79, 23),
            active: false,
        });

        let _buffer = render_history_buffer(&mut app, 80, 24);
        let copied = extract_full_selection(&app, 80, 24);

        assert!(copied.contains("before chip"));
        assert!(copied.contains("after chip"));
        assert!(!copied.contains("hidden brief"));
    }

    #[test]
    fn selection_copy_uses_content_grid_before_scroll_indicator_chrome() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = (0..12)
            .map(|idx| HistoryEntry::Plain {
                line: format!("line {idx}"),
            })
            .collect();
        app.chat_scroll_offset = 3;
        app.selection = Some(Selection {
            anchor: (0, 0),
            focus: (23, 4),
            active: false,
        });

        let buffer = render_history_buffer(&mut app, 24, 5);
        let rendered = (0..5)
            .map(|row| {
                (0..24)
                    .filter_map(|col| buffer.cell((col, row)).map(|cell| cell.symbol()))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        let copied = extract_full_selection(&app, 24, 5);

        assert!(
            rendered.contains("more"),
            "scroll indicator should be visible"
        );
        assert!(!copied.contains("more"));
        assert!(!copied.contains('↓'));
    }

    #[test]
    fn wrapped_rows_are_soft_continuations_for_selection_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![HistoryEntry::Plain {
            line: "abcdefghijklmnopqrstuv".to_string(),
        }];

        render_history(&mut app, 10, 4);

        let first = find_row(&app, "  abcdefgh");
        let second = first + 1;
        assert!(!app.chat_cont_rows[first]);
        assert!(app.chat_cont_rows[second]);

        let text = extract_selection_plaintext(
            &app.chat_text_grid,
            &app.chat_row_meta,
            Rect::new(0, 0, 10, 4),
            Selection {
                anchor: (0, first as u16),
                focus: (9, second as u16),
                active: false,
            },
        );
        assert_eq!(text, "abcdefgh ijklmnopqr");
    }

    #[test]
    fn resize_recomputes_visual_row_count_and_clamps_scroll() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = vec![HistoryEntry::Plain {
            line: "abcdefghijklmnopqrstuvwxyz".to_string(),
        }];

        render_history(&mut app, 8, 3);
        let narrow_total = app.chat_total_lines;
        app.chat_scroll_offset = 99;

        render_history(&mut app, 26, 3);

        assert!(narrow_total > app.chat_total_lines);
        assert_eq!(app.chat_total_lines, 2);
        assert_eq!(app.chat_scroll_offset, 0);
    }

    #[test]
    fn chat_scroll_indicator_shows_only_when_off_live_tail() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = (0..10)
            .map(|idx| HistoryEntry::Plain {
                line: format!("line {idx}"),
            })
            .collect();

        let buffer = render_history_buffer(&mut app, 24, 4);
        let rows = buffer_rows(&buffer, 24, 4);
        assert!(rows.iter().all(|row| !row.contains('↓')));

        app.chat_scroll_offset = 3;
        let buffer = render_history_buffer(&mut app, 24, 4);
        let rows = buffer_rows(&buffer, 24, 4);
        assert!(rows.iter().any(|row| row.contains("↓ 3 more")));

        app.chat_scroll_offset = 0;
        let buffer = render_history_buffer(&mut app, 24, 4);
        let rows = buffer_rows(&buffer, 24, 4);
        assert!(rows.iter().all(|row| !row.contains('↓')));
    }

    #[test]
    fn chat_scroll_indicator_degrades_on_narrow_width() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = (0..6)
            .map(|idx| HistoryEntry::Plain {
                line: format!("line {idx}"),
            })
            .collect();
        app.chat_scroll_offset = 2;

        let buffer = render_history_buffer(&mut app, 2, 3);
        let rows = buffer_rows(&buffer, 2, 3);
        assert!(rows.iter().any(|row| row.contains('↓')));
        assert!(rows.iter().all(|row| !row.contains("more")));

        app.chat_scroll_offset = 2;
        let buffer = render_history_buffer(&mut app, 1, 3);
        let rows = buffer_rows(&buffer, 1, 3);
        assert!(rows.iter().all(|row| !row.contains('↓')));
    }

    #[test]
    fn off_live_render_preserves_top_row_when_history_appends() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = (0..10)
            .map(|idx| HistoryEntry::Plain {
                line: format!("line {idx}"),
            })
            .collect();
        app.chat_scroll_offset = 3;
        let before = buffer_rows(&render_history_buffer(&mut app, 24, 4), 24, 4)[0].clone();

        app.history.push(HistoryEntry::Plain {
            line: "new below".to_string(),
        });
        let after = buffer_rows(&render_history_buffer(&mut app, 24, 4), 24, 4)[0].clone();

        assert_eq!(before, after);
        assert!(
            app.chat_scroll_offset > 3,
            "offset should grow to preserve top"
        );
    }

    #[test]
    fn off_live_render_preserves_top_row_when_pending_streams() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = (0..10)
            .map(|idx| HistoryEntry::Plain {
                line: format!("line {idx}"),
            })
            .collect();
        app.chat_scroll_offset = 3;
        let before = buffer_rows(&render_history_buffer(&mut app, 24, 4), 24, 4)[0].clone();

        app.pending = Some(crate::tui::history::PendingMsg {
            name: "Build".to_string(),
            text: "partial response".to_string(),
            reasoning: String::new(),
            timestamp: chrono::Local::now(),
            started_at: std::time::Instant::now(),
            text_started_at: None,
            inside_think: false,
            body_started: false,
            tag_partial: String::new(),
            seq: None,
            strip_think: true,
        });
        let after = buffer_rows(&render_history_buffer(&mut app, 24, 4), 24, 4)[0].clone();

        assert_eq!(before, after);
    }

    #[test]
    fn live_tail_render_follows_appended_content() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = (0..4)
            .map(|idx| HistoryEntry::Plain {
                line: format!("line {idx}"),
            })
            .collect();
        app.chat_scroll_offset = 0;
        app.history.push(HistoryEntry::Plain {
            line: "latest".to_string(),
        });

        let rows = buffer_rows(&render_history_buffer(&mut app, 24, 3), 24, 3);

        assert!(rows.iter().any(|row| row.contains("latest")), "{rows:?}");
        assert_eq!(app.chat_scroll_offset, 0);
    }

    #[test]
    fn fresh_turn_at_live_tail_stays_bottom_pinned() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = (0..12)
            .map(|idx| HistoryEntry::Plain {
                line: format!("context {idx}"),
            })
            .collect();
        app.history.push(HistoryEntry::User {
            text: "new question".to_string(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            preflight_pending: false,
            persist_failed: false,
        });
        app.busy = true;

        let rows = buffer_rows(&render_history_buffer(&mut app, 28, 8), 28, 8);

        let last_nonblank = rows
            .iter()
            .rposition(|row| !row.trim().is_empty())
            .expect("fresh turn renders nonblank rows");
        assert!(
            rows.iter()
                .skip(last_nonblank.saturating_sub(2))
                .any(|row| row.contains("new question")),
            "fresh row should stay at live tail: {rows:?}"
        );
        assert!(
            rows.len() - 1 - last_nonblank <= 1,
            "fresh turn should not append viewport padding: {rows:?}"
        );
        assert_eq!(app.chat_scroll_offset, 0);
    }

    #[test]
    fn chat_scroll_indicator_distinguishes_streaming_below_viewport() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.launch.banner_enabled = false;
        app.history = (0..10)
            .map(|idx| HistoryEntry::Plain {
                line: format!("line {idx}"),
            })
            .collect();
        app.chat_scroll_offset = 3;
        app.busy = true;

        let rows = buffer_rows(&render_history_buffer(&mut app, 32, 4), 32, 4);

        assert!(rows.iter().any(|row| row.contains("streaming")), "{rows:?}");
    }
}

#[cfg(test)]
mod prediction_ghost_context_indicator_tests {
    use super::{App, first_line_truncated, input_visual_rows, wrap_ghost_line_chunks};
    use crate::engine::message::{QueueItemStatus, QueueTarget, QueuedUserMessage};
    use crate::tui::composer::{PredictionGhost, VimMode, display_width, input_prefix_width};
    use crate::tui::theme::MUTED_TEXT;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;
    use ratatui::style::Modifier;

    fn render_input_row(app: &mut App, width: u16) -> String {
        let backend = TestBackend::new(width, 3);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                app.render_input(f, Rect::new(0, 0, width, 3));
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..width).map(|x| buf[(x, 1)].symbol()).collect::<String>()
    }

    fn render_input_top_row(app: &mut App, width: u16) -> String {
        let backend = TestBackend::new(width, 3);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                app.render_input(f, Rect::new(0, 0, width, 3));
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..width).map(|x| buf[(x, 0)].symbol()).collect::<String>()
    }

    fn render_input_buffer(app: &mut App, width: u16, height: u16) -> ratatui::buffer::Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                app.render_input(f, Rect::new(0, 0, width, height));
            })
            .unwrap();
        terminal.backend().buffer().clone()
    }

    fn render_queue_buffer(app: &mut App, width: u16, height: u16) -> ratatui::buffer::Buffer {
        let backend = TestBackend::new(width, height + 2);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                app.render_input(f, Rect::new(0, height - 1, width, 3));
                app.render_queue(f, Rect::new(0, 0, width, height));
            })
            .unwrap();
        terminal.backend().buffer().clone()
    }

    fn row_text(buffer: &ratatui::buffer::Buffer, row: u16, width: u16) -> String {
        (0..width)
            .map(|x| buffer[(x, row)].symbol())
            .collect::<String>()
    }

    fn queued_item(text: &str, target: QueueTarget) -> QueuedUserMessage {
        QueuedUserMessage {
            id: uuid::Uuid::new_v4(),
            status: QueueItemStatus::Queued,
            text: text.to_string(),
            display_text: None,
            target,
        }
    }

    #[test]
    fn queue_connected_chrome_merges_with_input_top_border() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.queue
            .push(queued_item("queued text", QueueTarget::root("Build")));

        let width = 32;
        let buf = render_queue_buffer(&mut app, width, 3);
        let top = row_text(&buf, 0, width);
        let bottom = row_text(&buf, 2, width);

        assert_eq!(top, format!(" ╭{}╮ ", "─".repeat(width as usize - 4)));
        assert_eq!(bottom, format!("╭┴{}┴╮", "─".repeat(width as usize - 4)));
    }

    #[test]
    fn queue_renders_display_text_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let mut item = queued_item(
            "<file path=\"src/lib.rs\">expanded</file>",
            QueueTarget::root("Build"),
        );
        item.display_text = Some("check @src/lib.rs".to_string());
        app.queue.push(item);

        let row = row_text(&render_queue_buffer(&mut app, 50, 3), 1, 50);
        assert!(row.contains("check @src/lib.rs"), "{row:?}");
        assert!(!row.contains("<file"), "{row:?}");
    }

    #[test]
    fn input_visual_rows_measure_cjk_and_emoji_by_display_width() {
        let prefix = input_prefix_width();
        assert_eq!(input_visual_rows("中中", prefix, prefix + 4), 1);
        assert_eq!(input_visual_rows("中中中", prefix, prefix + 4), 2);
        assert_eq!(input_visual_rows("🙂🙂", prefix, prefix + 2), 2);
    }

    #[test]
    fn queue_preview_truncates_by_display_width() {
        let truncated = first_line_truncated("queued: 中中中abc", 14);
        assert!(display_width(&truncated) <= 14);
        assert!(truncated.ends_with('…'));
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    #[test]
    fn queue_foreground_item_uses_existing_style_without_annotation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.foreground_input_target = Some(QueueTarget::root("Build"));
        app.queue
            .push(queued_item("root message", QueueTarget::root("Build")));

        let buf = render_queue_buffer(&mut app, 50, 3);
        let row = row_text(&buf, 1, 50);
        assert!(row.contains("root message"), "{row:?}");
        assert!(
            !row.contains(" · Build"),
            "foreground item is not annotated"
        );
        let x = row.find("root message").unwrap() as u16;
        let style = buf[(x, 1)].style();
        assert_eq!(style.fg, Some(MUTED_TEXT));
        assert!(!style.add_modifier.contains(Modifier::DIM));
    }

    #[test]
    fn queue_non_foreground_item_is_dimmed_and_annotated_by_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.foreground_input_target = Some(QueueTarget::root("Build"));
        app.queue.push(queued_item(
            "child message",
            QueueTarget::child("explore", 1, "call-1", "default"),
        ));

        let buf = render_queue_buffer(&mut app, 56, 3);
        let row = row_text(&buf, 1, 56);
        assert!(row.contains("child message"), "{row:?}");
        assert!(row.contains(" · explore"), "{row:?}");
        assert!(
            !row.contains("task:"),
            "raw target ids must not render: {row:?}"
        );

        for needle in ["child message", "explore"] {
            let x = row.find(needle).unwrap() as u16;
            let style = buf[(x, 1)].style();
            assert_eq!(style.fg, Some(MUTED_TEXT));
            assert!(style.add_modifier.contains(Modifier::DIM));
        }
    }

    #[test]
    fn queue_unknown_foreground_target_marks_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.foreground_input_target = None;
        app.queue.push(queued_item(
            "child message",
            QueueTarget::child("explore", 1, "call-1", "default"),
        ));

        let buf = render_queue_buffer(&mut app, 56, 3);
        let row = row_text(&buf, 1, 56);
        assert!(row.contains("child message"), "{row:?}");
        assert!(
            !row.contains("explore"),
            "missing target info must not annotate"
        );
        assert!(
            !row.contains("task:"),
            "raw target ids must not render: {row:?}"
        );
        for x in 0..56 {
            assert!(
                !buf[(x, 1)].style().add_modifier.contains(Modifier::DIM),
                "no queue cell should be dimmed when foreground target is unknown"
            );
        }
    }

    #[test]
    fn queue_narrow_render_preserves_message_and_border_while_truncating_annotation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.foreground_input_target = Some(QueueTarget::root("Build"));
        app.queue.push(queued_item(
            "queued text",
            QueueTarget::child("verylongagent", 1, "call-1", "default"),
        ));

        let buf = render_queue_buffer(&mut app, 30, 3);
        let top = row_text(&buf, 0, 30);
        let row = row_text(&buf, 1, 30);
        let bottom = row_text(&buf, 2, 30);
        assert!(row.contains("queued text"), "{row:?}");
        assert!(
            !row.contains("task:"),
            "raw target ids must not render: {row:?}"
        );
        assert!(top.contains('╭') && top.contains('╮'), "{top:?}");
        assert!(
            bottom.starts_with('╭') && bottom.ends_with('╮'),
            "{bottom:?}"
        );
    }

    #[test]
    fn visual_selection_highlight_spans_both_cells_of_wide_character() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.composer.insert_str("中a");
        app.composer.set_cursor(0);
        app.composer.begin_visual(VimMode::Visual);

        let buf = render_input_buffer(&mut app, 20, 3);
        let wide_start = 1 + input_prefix_width() as u16;
        assert!(
            buf[(wide_start, 1)]
                .style()
                .add_modifier
                .contains(Modifier::REVERSED),
            "ratatui applies the wide glyph's visible style to its leading cell"
        );
        assert!(
            !buf[(wide_start + 2, 1)]
                .style()
                .add_modifier
                .contains(Modifier::REVERSED),
            "following ASCII cell is outside the visual selection"
        );
    }

    #[test]
    fn history_label_renders_oldest_to_newest_position() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.prompt_history = vec![
            "oldest".to_string(),
            "middle".to_string(),
            "newest".to_string(),
        ];

        app.prompt_history_cursor = 1;
        let newest_row = render_input_top_row(&mut app, 50);
        assert!(newest_row.contains("History: 3/3"), "{newest_row}");

        app.prompt_history_cursor = 3;
        let oldest_row = render_input_top_row(&mut app, 50);
        assert!(oldest_row.contains("History: 1/3"), "{oldest_row}");
    }

    #[test]
    fn history_label_is_hidden_when_not_recalling_and_overrides_shell_title() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.composer.insert_str("!echo hi");

        let shell_row = render_input_top_row(&mut app, 50);
        assert!(shell_row.contains("shell mode"), "{shell_row}");
        assert!(!shell_row.contains("History:"), "{shell_row}");

        app.prompt_history = vec!["!previous".to_string()];
        app.prompt_history_cursor = 1;
        let history_row = render_input_top_row(&mut app, 50);
        assert!(history_row.contains("History: 1/1"), "{history_row}");
        assert!(!history_row.contains("shell mode"), "{history_row}");
    }

    #[test]
    fn empty_composer_shows_context_indicator_when_width_permits() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let label = app.context_indicator_text();

        let row = render_input_row(&mut app, 40);

        assert!(row.contains(&label), "context indicator visible:\n{row}");
    }

    #[test]
    fn typed_composer_text_hides_context_indicator() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let label = app.context_indicator_text();
        app.composer.insert_str("real input");

        let row = render_input_row(&mut app, 40);

        assert!(
            !row.contains(&label),
            "typed text owns the composer row:\n{row}"
        );
        assert!(
            row.contains("real input"),
            "composer text remains visible:\n{row}"
        );
    }

    #[test]
    fn expanded_passive_ghost_hides_context_indicator() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let label = app.context_indicator_text();
        app.prediction_state.ghost = Some(PredictionGhost::new("first\nsecond".to_string(), true));
        app.prediction_state.ghost_mut().unwrap().accept();

        let row = render_input_row(&mut app, 40);

        assert!(
            !row.contains(&label),
            "expanded ghost hides context chip:\n{row}"
        );
        assert!(
            row.contains("first"),
            "expanded ghost still renders:\n{row}"
        );
    }

    #[test]
    fn narrow_input_hides_context_indicator() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let label = app.context_indicator_text();

        let row = render_input_row(&mut app, 10);

        assert!(
            !row.contains(&label),
            "narrow input hides context chip:\n{row}"
        );
    }

    #[test]
    fn passive_ghost_keeps_context_indicator_visible() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.prediction_state.begin_turn();
        app.prediction_state.on_result(
            app.prediction_state.turn(),
            Some("run a deliberately lengthy command that would hit the stats".to_string()),
            false,
            true,
        );
        let label = app.context_indicator_text();

        let row = render_input_row(&mut app, 34);
        let label_col = row.find(&label).expect("context indicator remains visible");
        let ghost_col = row.find("run").expect("passive ghost remains visible");

        assert!(ghost_col < label_col, "ghost starts before stats:\n{row}");
        assert!(
            row[..label_col].contains("run a deliberately"),
            "ghost text is preserved before the stats:\n{row}"
        );
    }

    #[test]
    fn passive_ghost_first_row_reserves_context_indicator_columns() {
        let chunks = wrap_ghost_line_chunks(
            "run a deliberately lengthy command that would hit the stats",
            30,
            18,
        );
        assert!(
            chunks[0].3 <= 18,
            "first ghost row wraps before the reserved context indicator columns"
        );
        assert_eq!(
            &"run a deliberately lengthy command that would hit the stats"
                [chunks[0].0..chunks[0].1],
            "run a ",
            "keeps the existing word-aware wrap behavior"
        );
        assert!(
            chunks
                .iter()
                .skip(1)
                .all(|(_, _, start_col, end_col)| end_col.saturating_sub(*start_col) <= 30),
            "later rows use the ordinary composer width"
        );
    }
}

#[cfg(test)]
mod toast_color_tests {
    use super::toast_fg;
    use crate::tui::app::ToastKind;
    use crate::tui::theme::{ERROR_TEXT, INFO_TEXT, SUCCESS_TEXT, WARNING_TEXT};

    #[test]
    fn toast_kinds_map_to_distinct_intent_colors() {
        assert_eq!(toast_fg(ToastKind::Success), SUCCESS_TEXT);
        assert_eq!(toast_fg(ToastKind::Warning), WARNING_TEXT);
        assert_eq!(toast_fg(ToastKind::Error), ERROR_TEXT);
        assert_eq!(toast_fg(ToastKind::Info), INFO_TEXT);
        assert_ne!(toast_fg(ToastKind::Warning), toast_fg(ToastKind::Error));
        assert_ne!(toast_fg(ToastKind::Warning), toast_fg(ToastKind::Info));
    }
}

#[cfg(test)]
mod input_border_color_tests {
    use super::super::App;

    #[test]
    fn busy_border_is_visible_grey_not_near_black() {
        // Regression guard (prompt `tui-busy-border-too-dark`): the
        // busy-state border must be a visibly-grey mid-shade, never the
        // near-black Indexed(238) that read as invisible. Pin it to the
        // shared constant so a future darkening can't slip back in.
        assert_eq!(
            App::input_border_color(true, false),
            crate::tui::theme::BUSY_BORDER
        );
        // The chosen shade sits in the "visibly grey, dimmer than white"
        // band — far brighter than the old 238.
        let idx = crate::tui::theme::BUSY_BORDER_INDEX;
        assert!(
            (244..=250).contains(&idx),
            "busy border must stay in the visible-grey band"
        );
    }

    #[test]
    fn idle_border_is_white_and_shell_is_green() {
        // Idle (white) and shell-mode (green Indexed(70)) are unchanged.
        assert_eq!(
            App::input_border_color(false, false),
            crate::tui::theme::IDLE_BORDER
        );
        assert_eq!(
            App::input_border_color(true, true),
            crate::tui::theme::SHELL_MODE_BORDER
        );
        // Shell mode wins over busy.
        assert_eq!(
            App::input_border_color(false, true),
            crate::tui::theme::SHELL_MODE_BORDER
        );
    }
}

#[cfg(test)]
mod guidance_label_tests {
    use super::fresh_chat_guidance_label;

    #[test]
    fn shows_on_fresh_chat_with_estimate() {
        // Daemon-estimate-present path: a guidance file was resolved, so
        // the label renders its body size with the filename.
        let label = fresh_chat_guidance_label(true, false, Some("AGENTS.md"), 1234);
        assert_eq!(label.as_deref(), Some("1.2k tokens in AGENTS.md"));
    }

    #[test]
    fn shows_body_tokens_under_one_k() {
        // Local-fallback path mirrors the daemon path here — the label is
        // a pure function of `(file, guidance_tokens)`, so a small raw
        // cl100k count renders without the `k` suffix.
        let label = fresh_chat_guidance_label(true, false, Some("project guidance"), 820);
        assert_eq!(label.as_deref(), Some("820 tokens in project guidance"));
    }

    #[test]
    fn reverts_once_history_or_usage_exists() {
        // History present → revert.
        assert!(fresh_chat_guidance_label(false, false, Some("AGENTS.md"), 1234).is_none());
        // Usage reported → revert.
        assert!(fresh_chat_guidance_label(true, true, Some("AGENTS.md"), 1234).is_none());
    }

    #[test]
    fn no_guidance_file_falls_back() {
        // No-guidance-file path: even on a fresh chat, with no resolved
        // file the label declines so the indicator shows its normal
        // (now full-system-prompt-inclusive) context form.
        assert!(fresh_chat_guidance_label(true, false, None, 0).is_none());
    }
}

#[cfg(test)]
mod hybrid_context_tokens_tests {
    use super::hybrid_context_tokens;

    #[test]
    fn climbs_as_estimate_grows_past_anchor_baseline() {
        // Provider reported 1000 total; the local estimate was 800 at
        // that instant. As streamed tokens push the estimate to 950, the
        // displayed count climbs by the 150-token delta.
        assert_eq!(hybrid_context_tokens(1000, 800, 800), 1000);
        assert_eq!(hybrid_context_tokens(1000, 850, 800), 1050);
        assert_eq!(hybrid_context_tokens(1000, 950, 800), 1150);
    }

    #[test]
    fn delta_floors_at_zero_when_estimate_dips_below_baseline() {
        // A prune can shrink the estimate below the snapshot; the
        // displayed value stays pinned to the provider's total rather
        // than going backwards.
        assert_eq!(hybrid_context_tokens(1000, 700, 800), 1000);
    }
}

#[cfg(test)]
mod reconnect_status_tests {
    use super::super::{DaemonLinkStatus, ReconnectStatus};
    use super::{daemon_link_status_text, reconnect_status_text, reconnect_target_label};
    use std::time::Instant;

    fn status(attempt: u32) -> ReconnectStatus {
        ReconnectStatus {
            attempt,
            provider: "openai-compatible".to_string(),
            model: "glm-4.6".to_string(),
            url: "http://localhost:1234/v1".to_string(),
        }
    }

    #[test]
    fn names_provider_model_url_and_attempt() {
        // The reconnect line reads as a distinct "server unreachable"
        // message — never a playful working line — naming provider/model,
        // the base url, and the current attempt.
        let text = reconnect_status_text(&status(3), "…", "12s");
        assert_eq!(
            text,
            "reconnecting… openai-compatible/glm-4.6 unreachable at \
             http://localhost:1234/v1 (attempt 3) 12s"
        );
        // The attribute the override hinges on: it's NOT a generic working
        // word — it leads with "reconnecting" and carries "unreachable".
        assert!(text.starts_with("reconnecting"));
        assert!(text.contains("unreachable"));
    }

    #[test]
    fn attempt_count_updates() {
        // The same target with a higher attempt renders the incremented
        // number — the status updates as retries proceed.
        assert!(reconnect_status_text(&status(1), "…", "1s").contains("(attempt 1)"));
        assert!(reconnect_status_text(&status(7), "…", "1s").contains("(attempt 7)"));
    }

    #[test]
    fn daemon_link_status_is_distinct_from_inference_reconnect() {
        let status = DaemonLinkStatus {
            restarting: true,
            attempt: 2,
            started_at: Instant::now(),
        };
        let text = daemon_link_status_text(&status, "…", "3s");
        assert_eq!(text, "daemon restarting — reconnecting… (attempt 2) 3s");
        assert!(!text.contains("unreachable at"));

        let lost = DaemonLinkStatus {
            restarting: false,
            attempt: 4,
            started_at: Instant::now(),
        };
        let text = daemon_link_status_text(&lost, "…", "5s");
        assert!(text.starts_with("daemon connection lost"));
        assert!(text.contains("(attempt 4)"));
    }

    #[test]
    fn target_label_collapses_empty_fields() {
        assert_eq!(reconnect_target_label("p", "m"), "p/m");
        assert_eq!(reconnect_target_label("", "m"), "m");
        assert_eq!(reconnect_target_label("p", ""), "p");
        assert_eq!(reconnect_target_label("", ""), "the model server");
    }
}
