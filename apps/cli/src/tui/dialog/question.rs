//! Question-tool wiring over the reusable [`DialogState`] (GOALS §3b).
//!
//! This is the thin, use-case-specific layer the spec calls for: it
//! translates the daemon's [`InterruptQuestionSet`] into dialog
//! [`Page`]s, drives the shared state machine for input, renders the
//! dialog as a compact bottom-anchored overlay above the status row
//! (codex bottom-pane style), and maps the resulting [`Answer`]s back to
//! the proto [`ResolveResponse`]s the `question` tool expects. The
//! approval prompt reuses [`DialogState`] unchanged via its own thin
//! wrapper.

use std::time::Duration;

use crossterm::event::KeyEvent;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use unicode_width::UnicodeWidthStr;
use uuid::Uuid;

use crate::tui::settings::secret_display::mask_value;

use crate::daemon::proto::{
    CommandDetail, InterruptOption, InterruptQuestion, InterruptQuestionSet, ResolveResponse,
    SandboxEscalation,
};
use crate::tui::dialog::{Answer, DialogOption, DialogOutcome, DialogState, Page, PageKind};
use crate::tui::geometry::{MIN_HISTORY_HEIGHT, STATUS_HEIGHT};
use crate::tui::keys_overlay::{DialogBindingId, dialog_binding, dialog_footer_bindings};
use crate::tui::pane::Pane;
use crate::tui::theme::{ACCENT_BLUE_INDEX, MUTED_COLOR_INDEX};

/// Codex-style cap on visible option rows. Longer lists scroll, keeping
/// the focused row in view, instead of clipping.
const MAX_VISIBLE_OPTION_ROWS: usize = 8;

/// Hard ceiling on the *collapsed* overlay's height (rows, incl. border +
/// footer) so a giant question can't eat the whole screen. The dialog
/// sizes to content up to this; beyond it the regions scroll. `Ctrl+E`
/// expands past this up to [`EXPANDED_HEIGHT_NUM`]/[`EXPANDED_HEIGHT_DEN`]
/// of the terminal height.
const MAX_DIALOG_HEIGHT: u16 = 16;

/// Expanded dialog cap as a fraction of terminal height
/// (`EXPANDED_HEIGHT_NUM / EXPANDED_HEIGHT_DEN`): the overlay grows upward
/// to at most this share of the screen, leaving the rest for history + the
/// pinned status row.
const EXPANDED_HEIGHT_NUM: u16 = 5;
const EXPANDED_HEIGHT_DEN: u16 = 6;

/// Minimum visible rows guaranteed to each body region so neither the
/// prompt nor the answers can fully hide the other: the prompt always keeps
/// at least this slice (with `▲/▼ more` when it overflows), and the answer
/// region always keeps at least this slice (enough for the focused option
/// plus a neighbour).
const MIN_PROMPT_ROWS: usize = 2;
const MIN_ANSWER_ROWS: usize = 3;

const CUSTOM_LABEL: &str = "Other…";
const NEXT_LABEL: &str = "Next";

/// Leading hover/cursor glyph on every option row: "▸ " when focused,
/// two spaces otherwise. Both render two cells wide, so the column a row's
/// content starts at is fixed regardless of focus.
const OPTION_CURSOR_HOVERED: &str = "▸ ";
const OPTION_CURSOR_PLAIN: &str = "  ";
/// Rendered width (terminal cells) of the leading cursor glyph. Used to
/// park the real terminal cursor by display column rather than byte length
/// (the hover glyph is multi-byte UTF-8).
const OPTION_CURSOR_WIDTH: usize = 2;

/// What the host should do once the dialog closes.
#[derive(Debug, Clone)]
pub enum QuestionResult {
    /// Send these resolutions back to the daemon for `interrupt_id`.
    Submit {
        interrupt_id: Uuid,
        responses: Vec<ResolveResponse>,
    },
    /// User dismissed: resolve as a cancel.
    Cancel { interrupt_id: Uuid },
}

/// The App-facing question dialog overlay. Owns a [`DialogState`] plus
/// the bits the resolution needs (the interrupt id and the original
/// questions, so option ids map correctly even for select free-text) and
/// the interrupt-level context header.
pub struct QuestionDialog {
    interrupt_id: Uuid,
    /// Interrupt-level context (from `raise_interrupt(description, …)`),
    /// rendered as a muted/italic context header. Empty = omit.
    description: String,
    questions: Vec<InterruptQuestion>,
    state: DialogState,
    result: Option<QuestionResult>,
    /// Terminal height learned at the last render, so [`desired_height`] can
    /// compute the expanded cap (a share of the screen) without the geometry
    /// pass needing the frame size. `0` until the first render.
    last_term_height: u16,
    /// Inner content width learned at the last render, used to measure the
    /// prompt region's wrapped height for the region split + scroll clamp.
    /// `0` until the first render.
    last_inner_width: u16,
    pending_count: usize,
    keyboard_enhancement_active: bool,
}

impl QuestionDialog {
    /// Build the dialog for a raised interrupt. `description` is the
    /// interrupt-level context header (empty to omit). `lockout` is the
    /// configured anti-misfire delay (default 1.5s).
    pub fn new(
        interrupt_id: Uuid,
        description: String,
        set: InterruptQuestionSet,
        lockout: Duration,
    ) -> Self {
        let pages = set.questions.iter().map(page_for).collect();
        let state = DialogState::new(pages, lockout);
        Self {
            interrupt_id,
            description,
            questions: set.questions,
            state,
            result: None,
            last_term_height: 0,
            last_inner_width: 0,
            pending_count: 0,
            keyboard_enhancement_active: true,
        }
    }

    /// Like [`Self::new`] but pre-checks each page's options from
    /// `preselected[page]` (option ids per page). Used by callers that open a
    /// multiselect reflecting current state — e.g. `/toggle-redaction`, whose
    /// two checkboxes start checked to the live per-source redaction state.
    pub fn with_preselected(
        interrupt_id: Uuid,
        description: String,
        set: InterruptQuestionSet,
        lockout: Duration,
        preselected: &[Vec<String>],
    ) -> Self {
        let pages = set.questions.iter().map(page_for).collect();
        let state = DialogState::new_preselected(pages, lockout, preselected);
        Self {
            interrupt_id,
            description,
            questions: set.questions,
            state,
            result: None,
            last_term_height: 0,
            last_inner_width: 0,
            pending_count: 0,
            keyboard_enhancement_active: true,
        }
    }

    pub fn with_keyboard_enhancement_active(mut self, active: bool) -> Self {
        self.keyboard_enhancement_active = active;
        self
    }

    pub fn with_pending_count(mut self, pending_count: usize) -> Self {
        self.pending_count = pending_count;
        self
    }

    pub fn set_pending_count(&mut self, pending_count: usize) {
        self.pending_count = pending_count;
    }

    pub fn interrupt_id(&self) -> Uuid {
        self.interrupt_id
    }

    /// Drain the close result once `handle_key` returned `true`.
    pub fn take_result(&mut self) -> Option<QuestionResult> {
        self.result.take()
    }

    /// Whether the dialog is still in its anti-misfire lockout window
    /// (implementation note). Exposes the inner
    /// [`DialogState::locked`] so the app-layer engagement gate can be
    /// asserted end-to-end (a continuation dialog opens immediately
    /// answerable).
    #[cfg(test)]
    pub fn locked(&self) -> bool {
        self.state.locked()
    }

    /// Whether this dialog is a command/permission **approval** prompt (any
    /// page carries the permission flag) rather than a plain `question`
    /// interrupt. Used by the which-key overlay (`which-key-overlay.md`) to
    /// show the approval-specific `y/n` decision keys.
    pub fn is_approval(&self) -> bool {
        self.questions.iter().any(|q| {
            matches!(
                q,
                InterruptQuestion::Single {
                    permission: true,
                    ..
                }
            )
        })
    }

    /// The command-detail block for the current page, if this is a bash
    /// approval prompt. `None` for every other question.
    fn command_detail(&self) -> Option<&CommandDetail> {
        if self.state.on_confirm_page() {
            return None;
        }
        let idx = self.state.current_page();
        match self.questions.get(idx) {
            Some(InterruptQuestion::Single {
                command_detail: Some(cd),
                ..
            }) => Some(cd.as_ref()),
            _ => None,
        }
    }

    /// The sandbox-escalation block for the current page, if this approval
    /// fired after a confined `bash` run failed (the distinct escalation
    /// variant). `None` for a first-time command approval and every other
    /// question.
    fn sandbox_escalation(&self) -> Option<&SandboxEscalation> {
        if self.state.on_confirm_page() {
            return None;
        }
        let idx = self.state.current_page();
        match self.questions.get(idx) {
            Some(InterruptQuestion::Single {
                sandbox_escalation: Some(esc),
                ..
            }) => Some(esc),
            _ => None,
        }
    }

    /// Intercept the whole-dialog expand toggle and the prompt-region
    /// scroll keys before the generic dialog sees them. `Ctrl+E` toggles
    /// expand; `PageUp`/`PageDown` scroll the prompt region. These are
    /// no-ops in [`DialogState`]'s page handler (it ignores unmatched keys),
    /// but intercepting here keeps them off option navigation. Returns
    /// `true` when the key was consumed.
    fn handle_overlay_key(&mut self, key: KeyEvent) -> bool {
        use crossterm::event::{KeyCode, KeyModifiers};
        if self.state.locked() {
            return false;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('e') if ctrl => {
                self.state.toggle_expanded();
                true
            }
            // PageUp/PageDown scroll the prompt region unambiguously (the
            // dialog never binds them). Ctrl+↑/↓ alias them so the binding
            // is reachable without PgUp/PgDn keys — and Ctrl disambiguates
            // them from option-list navigation.
            KeyCode::PageDown => {
                self.state.scroll_prompt(1);
                true
            }
            KeyCode::PageUp => {
                self.state.scroll_prompt(-1);
                true
            }
            KeyCode::Down if ctrl => {
                self.state.scroll_prompt(1);
                true
            }
            KeyCode::Up if ctrl => {
                self.state.scroll_prompt(-1);
                true
            }
            _ => false,
        }
    }

    /// Route a key. Returns `true` when the dialog wants to close (the
    /// host then drains [`take_result`](Self::take_result)).
    /// Insert pasted text into the focused custom / free-text field.
    pub fn paste(&mut self, text: &str) {
        self.state.paste(text);
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Expand + prompt-scroll keys are handled here and never reach the
        // generic dialog (no collision with option-select / confirm /
        // cancel bindings).
        if self.handle_overlay_key(key) {
            return false;
        }
        match self.state.handle_key(key) {
            DialogOutcome::Continue => false,
            DialogOutcome::Cancel => {
                self.result = Some(QuestionResult::Cancel {
                    interrupt_id: self.interrupt_id,
                });
                true
            }
            DialogOutcome::Submit(answers) => {
                let responses = answers
                    .iter()
                    .zip(self.questions.iter())
                    .map(|(a, q)| answer_to_response(a, q))
                    .collect();
                self.result = Some(QuestionResult::Submit {
                    interrupt_id: self.interrupt_id,
                    responses,
                });
                true
            }
        }
    }

    /// Content-sized height (rows) the bottom-anchored overlay wants.
    /// Collapsed: capped at [`MAX_DIALOG_HEIGHT`]. Expanded (`Ctrl+E`): grows
    /// up to a share of the terminal height (the overlay grows upward,
    /// shrinking history; the status row stays pinned). Includes the top +
    /// bottom border and the footer row. Beyond the cap the two body regions
    /// scroll.
    pub fn desired_height(&self) -> u16 {
        // 1 row each: top border, bottom border, footer hint.
        let chrome: u16 = 3;
        let body = self.body_line_count();
        let want = chrome.saturating_add(body);
        let max = self.effective_height_cap(self.state.is_expanded());
        let low = max.min(4);
        want.clamp(low, max)
    }

    /// Height ceiling after reserving the pinned status row and one row of
    /// history. Expanded mode prefers a 5/6 terminal share and both modes use
    /// the 16-row cap only when the terminal can afford it.
    fn effective_height_cap(&self, expanded: bool) -> u16 {
        if self.last_term_height == 0 {
            return MAX_DIALOG_HEIGHT;
        }
        let reserve = STATUS_HEIGHT.saturating_add(MIN_HISTORY_HEIGHT);
        let afford = self.last_term_height.saturating_sub(reserve).max(1);
        let cap = if expanded {
            let frac =
                self.last_term_height.saturating_mul(EXPANDED_HEIGHT_NUM) / EXPANDED_HEIGHT_DEN;
            frac.max(MAX_DIALOG_HEIGHT)
        } else {
            MAX_DIALOG_HEIGHT
        };
        cap.min(afford)
    }

    /// Number of body lines the current view wants (before capping). Sums the
    /// prompt region (description + prompt + command block, wrapped) and the
    /// answer region (option list capped at [`MAX_VISIBLE_OPTION_ROWS`] rows).
    fn body_line_count(&self) -> u16 {
        if self.state.on_confirm_page() {
            // Title + blank + one row per question + blank + status row, plus
            // the optional description header — all in the (scrollable)
            // prompt region.
            let lines = self.confirm_content_lines();
            return (lines as u16).max(1);
        }
        let prompt = self.prompt_region_height();
        let answer = self.answer_region_want();
        ((prompt + answer) as u16).max(1)
    }

    /// Wrapped line count of the prompt region for the current page, measured
    /// at the last-seen inner width (falls back to unwrapped when width is
    /// unknown, i.e. before the first render).
    fn prompt_region_height(&self) -> usize {
        let lines = self.prompt_region_lines();
        wrapped_height(&lines, self.last_inner_width)
    }

    /// Logical-line count the answer region wants (option/custom/Next rows in
    /// the focused window, descriptions included), capped at
    /// [`MAX_VISIBLE_OPTION_ROWS`] rows. A text page wants its one input row.
    fn answer_region_want(&self) -> usize {
        let page_idx = self.state.current_page();
        let page = &self.state.pages()[page_idx];
        match page.kind {
            PageKind::Text => 1,
            PageKind::Select | PageKind::Multiselect => {
                let rows = self.row_line_counts(page_idx, page);
                let total_rows = rows.len();
                let scroll = self.state.scroll().min(total_rows);
                let shown = MAX_VISIBLE_OPTION_ROWS.min(total_rows.saturating_sub(scroll));
                rows[scroll..scroll + shown]
                    .iter()
                    .copied()
                    .sum::<usize>()
                    .max(1)
            }
        }
    }

    /// Per-row line count for the current page's row list (options, then
    /// the custom affordance, then the multiselect "Next" entry). A row
    /// is one line plus one per description line.
    fn row_line_counts(&self, _page_idx: usize, page: &Page) -> Vec<usize> {
        let mut counts: Vec<usize> = page
            .options
            .iter()
            .map(|o| {
                1 + o
                    .description
                    .as_deref()
                    .map(|description| {
                        let indent = OPTION_CURSOR_WIDTH + 3 + 4;
                        wrap_indented_text(
                            description,
                            indent,
                            self.last_inner_width,
                            Style::default(),
                        )
                        .len()
                    })
                    .unwrap_or(0)
            })
            .collect();
        // Custom affordance: one row (its typed text shares the row).
        // Suppressed on permission pages (no free-text option).
        if page.has_custom() {
            let custom = self.state.custom_text(_page_idx);
            counts.push(if custom.is_empty() {
                1
            } else {
                wrapped_height(
                    &[Line::from(custom.to_string())],
                    self.last_inner_width.saturating_sub(4),
                )
            });
        }
        // Multiselect "Next" entry.
        if page.next_index().is_some() {
            counts.push(1);
        }
        counts
    }

    /// Sync the shared scroll state with the real overlay geometry before a
    /// render (the viewport-sync-before-render hook). Caches the terminal +
    /// inner width (so [`desired_height`] can size the expanded overlay and
    /// the region split can measure wrapped prompt height), then splits the
    /// body into the prompt + answer regions and feeds each region's metrics
    /// to the core so both stay in bounds.
    pub fn sync_viewport(&mut self, compact: Rect, term_height: u16) {
        self.last_term_height = term_height;
        self.last_inner_width = compact.width.saturating_sub(2); // borders
        // Body height = overlay minus border x2 minus the footer row.
        let body_h = compact.height.saturating_sub(3) as usize;

        if self.state.on_confirm_page() {
            // The whole confirm page is one scrollable region; no answer list.
            self.state.set_viewport(0);
            let total = self.confirm_content_lines();
            self.state.set_prompt_metrics(total, body_h);
            return;
        }

        let prompt_want = self.prompt_region_height();
        let answer_want = self.answer_region_want();
        let (prompt_h, answer_h) = split_regions(body_h, prompt_want, answer_want);

        // Prompt region: feed wrapped total + its slice (minus rows the
        // ▲/▼ markers reserve, so scrolled content isn't hidden under them).
        let prompt_visible =
            prompt_h.saturating_sub(self.prompt_marker_rows(prompt_h, prompt_want));
        self.state
            .set_prompt_metrics(prompt_want, prompt_visible.max(1));

        // Answer region: how many option rows fit in `answer_h` lines,
        // capped at the codex row cap, with the focused row kept in view.
        let page_idx = self.state.current_page();
        let page = self.state.pages()[page_idx].clone();
        if matches!(page.kind, PageKind::Text) {
            self.state.set_viewport(0);
            return;
        }
        // The options region carries no "more" markers, so the whole answer
        // slice is available for option rows (no marker-row reservation).
        let rows = self.row_line_counts(page_idx, &page);
        let scroll = self.state.scroll().min(rows.len().saturating_sub(1));
        let mut fit = 0usize;
        let mut used = 0usize;
        for &c in rows.iter().skip(scroll).take(MAX_VISIBLE_OPTION_ROWS) {
            if used + c > answer_h && fit > 0 {
                break;
            }
            used += c;
            fit += 1;
        }
        self.state.set_viewport(fit.max(1));
    }

    /// Rows the prompt region's `▲/▼ more` markers will occupy given its
    /// slice `prompt_h` and total wrapped lines `prompt_want`. Zero when the
    /// prompt fits; one when only the top or bottom is clipped; two when both.
    fn prompt_marker_rows(&self, prompt_h: usize, prompt_want: usize) -> usize {
        if prompt_h == 0 || prompt_want <= prompt_h {
            return 0;
        }
        // Worst case both markers show; the exact value tracks the scroll
        // position, but reserving for both keeps the slice non-overflowing.
        2.min(prompt_h)
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        if area.height == 0 || area.width == 0 {
            return;
        }
        // Anti-misfire lockout: grey border while locked; once interactive,
        // only destructive/privileged approvals tint red.
        let locked = self.state.locked();
        let risk_color = self.current_risk_color();
        let border_color = if locked {
            Color::Indexed(MUTED_COLOR_INDEX)
        } else {
            risk_color.unwrap_or(Color::White)
        };
        let title_base = if self.is_approval() {
            "approval"
        } else {
            "question"
        };
        let mut title = if self.state.page_count() > 1 {
            let n = self.state.page_count();
            let cur = (self.state.current_page() + 1).min(n + 1);
            if self.state.on_confirm_page() {
                format!(" {title_base} · review ")
            } else {
                format!(" {title_base} · {cur}/{n} ")
            }
        } else {
            format!(" {title_base} ")
        };
        if self.pending_count > 0 {
            let waiting = format!("· {} waiting ", self.pending_count);
            title = format!("{}{}", title.trim_end(), waiting);
        }
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        // [ body | footer(1) ].
        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let body = layout[0];
        let body_h = body.height as usize;

        let cursor = if self.state.on_confirm_page() {
            // Confirm page is a single scrollable region filling the body.
            let lines = self.windowed_prompt_lines(self.render_confirm(), body, body_h);
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), body);
            None
        } else {
            // Split the body into the prompt region (top) and the answer
            // region (bottom), each guaranteed a minimum visible slice.
            let prompt_want = self.prompt_region_height();
            let answer_want = self.answer_region_want();
            let (prompt_h, answer_h) = split_regions(body_h, prompt_want, answer_want);
            let parts = Layout::vertical([
                Constraint::Length(prompt_h as u16),
                Constraint::Length(answer_h as u16),
            ])
            .split(body);
            let prompt_rect = parts[0];
            let answer_rect = parts[1];

            // Prompt region (scrollable, with ▲/▼ markers).
            let prompt_lines =
                self.windowed_prompt_lines(self.prompt_region_lines(), prompt_rect, prompt_h);
            frame.render_widget(
                Paragraph::new(prompt_lines).wrap(Wrap { trim: false }),
                prompt_rect,
            );

            // Answer region (option list / freetext input).
            let (answer_lines, cursor) = self.render_answer(answer_rect);
            frame.render_widget(
                Paragraph::new(answer_lines).wrap(Wrap { trim: false }),
                answer_rect,
            );
            cursor
        };

        let hint = if locked {
            "waiting…".to_string()
        } else {
            self.footer_hint_for_width(layout[1].width)
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                hint,
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ))),
            layout[1],
        );

        // Park the real terminal cursor at the active input position
        // (freetext / custom field), once the lockout has cleared.
        if let Some((x, y)) = cursor
            && !locked
        {
            frame.set_cursor_position(Position::new(x, y));
        }
    }

    /// Window a prompt-region line list to its slice `region_h`, applying the
    /// shared prompt-scroll and drawing `▲ more` / `▼ more` markers when it
    /// overflows. Measured by wrapped height so the scroll lands on whole
    /// content lines.
    fn windowed_prompt_lines(
        &self,
        lines: Vec<Line<'static>>,
        rect: Rect,
        region_h: usize,
    ) -> Vec<Line<'static>> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let total = wrapped_height(&lines, rect.width);
        if region_h == 0 || total <= region_h {
            return lines;
        }
        // Expand each logical line into the rows it wraps to, so scrolling +
        // marker reservation operate on display rows (matching `Wrap`).
        let rows = wrap_lines(&lines, rect.width);
        let scroll = self.state.prompt_scroll().min(rows.len().saturating_sub(1));
        let top_more = scroll > 0;
        let mut slice_h = region_h;
        if top_more {
            slice_h = slice_h.saturating_sub(1);
        }
        // Tentatively show `slice_h` rows; reserve one more for the bottom
        // marker if content remains below.
        let mut shown = slice_h.min(rows.len().saturating_sub(scroll));
        let bottom_more = scroll + shown < rows.len();
        if bottom_more && shown > 0 {
            // Re-reserve a row for the bottom marker.
            shown = slice_h
                .saturating_sub(1)
                .min(rows.len().saturating_sub(scroll));
        }
        let mut out: Vec<Line<'static>> = Vec::new();
        if top_more {
            out.push(Line::from(Span::styled("  ▲ more".to_string(), muted)));
        }
        out.extend(rows[scroll..scroll + shown].iter().cloned());
        if scroll + shown < rows.len() {
            out.push(Line::from(Span::styled("  ▼ more".to_string(), muted)));
        }
        out
    }

    fn footer_hint(&self) -> String {
        self.footer_hint_for_width(u16::MAX)
    }

    fn footer_hint_for_width(&self, width: u16) -> String {
        let mut ids: Vec<DialogBindingId> = Vec::new();
        if self.state.is_typing() {
            ids.extend([
                DialogBindingId::TypeAnswer,
                DialogBindingId::Done,
                DialogBindingId::Cancel,
            ]);
            return self.format_footer(ids, width);
        }
        if self.state.on_confirm_page() {
            ids.extend([
                DialogBindingId::Submit,
                DialogBindingId::Back,
                DialogBindingId::Cancel,
            ]);
        } else {
            if self.is_approval() {
                ids.extend([
                    DialogBindingId::ApprovalPick,
                    DialogBindingId::ConfirmAgain,
                    DialogBindingId::Move,
                ]);
            } else if self.state.next_index().is_some() {
                ids.extend([DialogBindingId::Toggle, DialogBindingId::Move]);
            } else {
                ids.extend([
                    DialogBindingId::Pick,
                    DialogBindingId::Move,
                    DialogBindingId::Choose,
                ]);
            }
            if self.state.page_count() > 1 {
                ids.push(DialogBindingId::Questions);
            }
        }
        if self.state.prompt_overflows() {
            ids.push(DialogBindingId::PromptScroll);
        }
        if self.keyboard_enhancement_active {
            ids.push(DialogBindingId::ChatScroll);
        }
        if let Some(expand) = self.expand_binding_id() {
            ids.push(expand);
        }
        if !ids.contains(&DialogBindingId::Cancel) {
            ids.push(DialogBindingId::Cancel);
        }
        self.format_footer(ids, width)
    }

    fn format_footer(&self, ids: Vec<DialogBindingId>, width: u16) -> String {
        let mut rows = dialog_footer_bindings(&ids, self.keyboard_enhancement_active);
        rows.sort_by_key(|row| row.priority);
        let join = |rows: &[&crate::tui::keys_overlay::DialogBinding]| {
            rows.iter()
                .map(|row| row.footer)
                .collect::<Vec<_>>()
                .join("  ·  ")
        };
        let width = width as usize;
        while rows.len() > 2 && UnicodeWidthStr::width(join(&rows).as_str()) > width {
            let Some((idx, _)) = rows.iter().enumerate().max_by_key(|(_, row)| row.priority) else {
                break;
            };
            rows.remove(idx);
        }
        join(&rows)
    }

    fn expand_binding_id(&self) -> Option<DialogBindingId> {
        if self.state.is_expanded() {
            Some(DialogBindingId::Collapse)
        } else if self.state.next_index().is_some() {
            if self.has_more_than_collapsed_fits() {
                Some(DialogBindingId::Expand)
            } else {
                None
            }
        } else if self.has_more_than_collapsed_fits() {
            Some(DialogBindingId::Expand)
        } else {
            None
        }
    }

    /// Footer fragment for the whole-dialog `Ctrl+E` expand toggle. Shown
    /// whenever the dialog is collapsible (expanded) or has more content than
    /// fits (worth expanding); empty when it already fits collapsed.
    fn expand_hint(&self) -> String {
        self.expand_binding_id()
            .map(|id| format!("  ·  {}", dialog_binding(id).footer))
            .unwrap_or_default()
    }

    /// Whether the current view's content exceeds the collapsed overlay's
    /// body budget (so expanding would reveal more). Drives the `ctrl+e:
    /// expand` footer hint.
    fn has_more_than_collapsed_fits(&self) -> bool {
        let collapsed_body = (MAX_DIALOG_HEIGHT.saturating_sub(3)) as usize;
        if self.state.on_confirm_page() {
            return self.confirm_content_lines() > collapsed_body;
        }
        self.prompt_region_height() + self.answer_region_want() > collapsed_body
    }

    /// Build the **prompt region** line list for the current page: the
    /// interrupt description (if any), the bold question prompt, and — for a
    /// bash approval — the full verbatim command-detail block. This region
    /// scrolls independently of the answer region; the command block is no
    /// longer separately collapsible (it lives here and the whole region
    /// scrolls / expands).
    fn prompt_region_lines(&self) -> Vec<Line<'static>> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let page_idx = self.state.current_page();
        let page = &self.state.pages()[page_idx];
        let mut lines: Vec<Line<'static>> = Vec::new();

        // Interrupt-level context header (codex `Reason:` style).
        if !self.description.trim().is_empty() && self.description.trim() != page.prompt.trim() {
            lines.push(Line::from(Span::styled(
                self.description.clone(),
                muted.add_modifier(Modifier::ITALIC),
            )));
            lines.push(Line::default());
        }

        lines.push(Line::from(Span::styled(
            page.prompt.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        )));

        // Bash command-detail block (full verbatim command + highlight +
        // step indicator), below the prompt within the prompt region.
        if let Some(cd) = self.command_detail() {
            lines.push(Line::default());
            lines.extend(self.command_block_lines(cd));
        }

        // Sandbox-escalation block (run-fail-escalate): the honest framing,
        // the confined attempt's exit + stderr, and the cascade warning that
        // a remembered scope removes confinement for future runs. Rendered
        // here in the scrollable prompt region (PageUp/PageDown, Ctrl+E),
        // never asserting the sandbox blocked the command.
        if let Some(esc) = self.sandbox_escalation() {
            lines.push(Line::default());
            lines.extend(self.sandbox_escalation_lines(esc, page.options.len() > 1));
        }
        lines
    }

    /// Build the sandbox-escalation lines: the honest "ran in the sandbox
    /// and failed; cockpit can't confirm the sandbox was the cause" framing,
    /// the confined exit code + (truncated) stderr, and the cascade warning.
    /// `rememberable` is whether the prompt offers remembered scopes (false
    /// for a wrapper — then the choice is Once-only).
    fn sandbox_escalation_lines(
        &self,
        esc: &SandboxEscalation,
        rememberable: bool,
    ) -> Vec<Line<'static>> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut out: Vec<Line<'static>> = Vec::new();

        // Honest framing — failed WHILE sandboxed, not blocked BY it.
        out.push(Line::from(Span::styled(
            "Ran in the sandbox and exited non-zero. It may have been blocked from \
             reading/writing outside the working directory, but that can't be confirmed."
                .to_string(),
            muted,
        )));

        // Confined failure detail: exit + captured stderr.
        out.push(Line::default());
        out.push(Line::from(Span::styled(
            format!("confined exit: {}", esc.confined_exit),
            muted.add_modifier(Modifier::ITALIC),
        )));
        let stderr = esc.confined_stderr.trim_end();
        if !stderr.is_empty() {
            out.push(Line::from(Span::styled(
                "confined stderr:".to_string(),
                muted.add_modifier(Modifier::ITALIC),
            )));
            for line in stderr.split('\n') {
                out.push(Line::from(Span::styled(format!("  {line}"), muted)));
            }
        }

        // Cascade warning.
        out.push(Line::default());
        let warning = if rememberable {
            "Approving re-runs it WITHOUT the sandbox now. \"Once\" applies this time only; \
             a remembered scope (session/project/global) makes future runs of this command \
             skip the sandbox silently, with no prompt."
        } else {
            "Approving re-runs it WITHOUT the sandbox now. This is a wrapper command and \
             can't be remembered — the choice is once only."
        };
        out.push(Line::from(Span::styled(warning.to_string(), muted)));
        out
    }

    /// Render the **answer region** for the current page (option list,
    /// freetext input, or the focused-window slice of a long option list).
    /// Returns the lines plus an optional (x, y) terminal-cursor position for
    /// the active text input, anchored to `area`.
    fn render_answer(&self, area: Rect) -> (Vec<Line<'static>>, Option<(u16, u16)>) {
        let page_idx = self.state.current_page();
        let page = &self.state.pages()[page_idx];
        let accent = Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX));
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut lines: Vec<Line<'static>> = Vec::new();
        let mut cursor: Option<(u16, u16)> = None;
        let mut hovered_rows: Option<(usize, usize)> = None;

        match page.kind {
            PageKind::Text => {
                let typed = self.state.custom_text(page_idx);
                let shown = if page.masked_text() && !typed.is_empty() {
                    mask_value().to_string()
                } else {
                    typed.to_string()
                };
                let style = if self.state.is_typing() {
                    accent
                } else {
                    Style::default().fg(Color::White)
                };
                let row = lines.len() as u16;
                lines.push(Line::from(vec![
                    Span::raw("▌ "),
                    Span::styled(shown.clone(), style),
                ]));
                // Cursor sits after the "▌ " prefix plus the visible caret column.
                let col = if page.masked_text() && !typed.is_empty() {
                    2 + shown.chars().count() as u16
                } else {
                    2 + self.state.custom_cursor_display_col(page_idx) as u16
                };
                cursor = Some((area.x + col, area.y + row));
            }
            PageKind::Select | PageKind::Multiselect => {
                let radio = page.kind_is_select();
                let selected = self.state.selected_ids(page_idx);
                let rows = self.row_line_counts(page_idx, page);
                let total_rows = rows.len();
                let scroll = self.state.scroll().min(total_rows.saturating_sub(1));
                let viewport = self.answer_viewport_rows();
                let shown = viewport.min(total_rows.saturating_sub(scroll));
                let custom_idx = page.options.len();
                let next_idx = page.next_index();

                // The options region carries no "more" markers — the
                // scroll-margin keeps the next option in view, so the
                // overflow affordance is unnecessary. Render the options
                // straight, reclaiming the rows the markers used to reserve.
                for row_idx in scroll..scroll + shown {
                    let hovered = self.state.cursor() == row_idx;
                    let row_start = lines.len();
                    if row_idx < page.options.len() {
                        let opt = &page.options[row_idx];
                        let checked = selected.contains(&opt.id);
                        let marker = match (radio, checked) {
                            (true, true) => "(•) ",
                            (true, false) => "( ) ",
                            (false, true) => "[x] ",
                            (false, false) => "[ ] ",
                        };
                        let num = if row_idx < 9 {
                            format!("{}. ", row_idx + 1)
                        } else {
                            "   ".to_string()
                        };
                        lines.push(self.option_line(&num, marker, &opt.label, hovered));
                        if let Some(desc) = opt.description.as_deref() {
                            // Continuation line aligned under the label
                            // column (cursor + number + marker width).
                            let indent = OPTION_CURSOR_WIDTH
                                + UnicodeWidthStr::width(num.as_str())
                                + UnicodeWidthStr::width(marker);
                            lines.extend(wrap_indented_text(desc, indent, area.width, muted));
                        }
                    } else if row_idx == custom_idx {
                        let typed = self.state.custom_text(page_idx);
                        // Placeholder and typed text are mutually exclusive:
                        // an empty field shows the `Type your own answer`
                        // placeholder; once the user types, the row shows
                        // only what they typed (with the edit marker).
                        let label = if typed.is_empty() {
                            CUSTOM_LABEL.to_string()
                        } else {
                            typed.to_string()
                        };
                        let marker = if self.state.is_typing() && hovered {
                            "✎ "
                        } else if page.kind_is_select() || typed.is_empty() {
                            "+ "
                        } else {
                            "[x] "
                        };
                        let custom_line = self.option_line("", marker, &label, hovered);
                        lines.extend(wrap_lines(&[custom_line], area.width));
                        if self.state.is_typing() && hovered {
                            // Park the cursor at the caret's display column.
                            // The rendered prefix on this row is the
                            // hover/cursor glyph ("▸ ") then the marker
                            // ("✎ ") — both multi-byte, so measure them by
                            // RENDERED WIDTH, not `.len()`. Since fix #1
                            // dropped the label prefix while typing, the
                            // only text before the caret is those two glyphs
                            // plus the typed string up to the caret.
                            let prefix = OPTION_CURSOR_WIDTH
                                + UnicodeWidthStr::width(marker)
                                + self.state.custom_cursor_display_col(page_idx);
                            let col = prefix as u16;
                            let row = (lines.len() - 1) as u16;
                            cursor = Some((area.x + col, area.y + row));
                        }
                    } else if Some(row_idx) == next_idx {
                        lines.push(self.option_line("", "→ ", NEXT_LABEL, hovered));
                    }
                    if hovered {
                        hovered_rows = Some((row_start, lines.len()));
                    }
                }
            }
        }
        let visible_h = area.height as usize;
        if visible_h > 0 && lines.len() > visible_h {
            let start = hovered_rows
                .map(|(_, end)| end.saturating_sub(visible_h))
                .unwrap_or(0)
                .min(lines.len().saturating_sub(visible_h));
            let end = start + visible_h;
            lines = lines[start..end].to_vec();
            cursor = cursor.and_then(|(x, y)| {
                let row = y.saturating_sub(area.y) as usize;
                if (start..end).contains(&row) {
                    Some((x, area.y + (row - start) as u16))
                } else {
                    None
                }
            });
        }
        (lines, cursor)
    }

    /// Test seam: the combined prompt + answer body lines and the answer
    /// cursor, anchored at `area` (mirrors the pre-split `render_page` so the
    /// content-assertion tests stay stable). The cursor's x-column is
    /// unaffected by the region split.
    #[cfg(test)]
    fn render_page(&self, area: Rect) -> (Vec<Line<'static>>, Option<(u16, u16)>) {
        let mut lines = self.prompt_region_lines();
        lines.push(Line::default());
        let (answer, cursor) = self.render_answer(area);
        lines.extend(answer);
        (lines, cursor)
    }

    /// Visible answer rows the core last reported (its `viewport`), falling
    /// back to the codex row cap before the first viewport sync.
    fn answer_viewport_rows(&self) -> usize {
        let v = self.state.viewport();
        if v == 0 {
            MAX_VISIBLE_OPTION_ROWS
        } else {
            v.min(MAX_VISIBLE_OPTION_ROWS)
        }
    }

    /// Build the command-detail block: an optional `step N of M` indicator,
    /// then the full verbatim command rendered as an indented monospace-ish
    /// quoted block with the current constituent's char span highlighted
    /// (underline + accent). The command is shown in full; the enclosing
    /// prompt region scrolls (PageUp/PageDown) and expands (`Ctrl+E`) to
    /// reveal long / multi-line commands.
    fn command_block_lines(&self, cd: &CommandDetail) -> Vec<Line<'static>> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut out: Vec<Line<'static>> = Vec::new();

        // Step indicator (compound commands only).
        if cd.step_count > 1 {
            out.push(Line::from(Span::styled(
                format!("step {} of {}", cd.step, cd.step_count),
                muted.add_modifier(Modifier::ITALIC),
            )));
        }
        if let Some(cwd) = cd.cwd.as_deref() {
            out.push(Line::from(Span::styled(format!("cwd: {cwd}"), muted)));
        }
        if let Some(key) = cd.remembered_key.as_deref() {
            out.push(Line::from(vec![
                Span::styled("remembers: ", muted),
                Span::styled(format!("`{key}`"), Style::default().fg(Color::White)),
            ]));
        }

        // Render each source line, mapping the global char-span highlight
        // onto per-line segments. `char_base` is the running char offset of
        // the current line's start within the whole command.
        let highlight = cd.highlight.map(|h| (h.start as usize, h.end as usize));
        let mut char_base: usize = 0;
        for line in cd.full_command.split('\n') {
            let line_len = line.chars().count();
            out.push(self.command_source_line(line, char_base, line_len, highlight));
            char_base += line_len + 1; // account for the '\n' separator
        }
        if let Some(preview) = cd.write_content.as_ref() {
            out.push(Line::from(Span::styled("content:", muted)));
            if preview.dynamic {
                out.push(Line::from(Span::styled(
                    format!("  {}", sanitize_preview_content(&preview.content)),
                    muted,
                )));
            } else {
                let content = sanitize_preview_content(&preview.content);
                for line in truncated_preview_lines(&content) {
                    out.push(Line::from(Span::styled(
                        format!("  {line}"),
                        Style::default().fg(Color::White),
                    )));
                }
            }
        }
        out.extend(self.command_risk_lines(cd));
        out
    }

    fn current_risk_color(&self) -> Option<Color> {
        self.command_detail()
            .and_then(|cd| cd.risk_tier.as_deref())
            .and_then(risk_tier_border_color)
    }

    fn command_risk_lines(&self, cd: &CommandDetail) -> Vec<Line<'static>> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut out = Vec::new();
        let Some(tier) = cd.risk_tier.as_deref() else {
            return out;
        };
        out.push(Line::default());
        out.push(Line::from(vec![
            Span::styled("risk: ", muted),
            Span::styled(
                tier.to_string(),
                Style::default()
                    .fg(risk_tier_color(tier).unwrap_or(Color::Indexed(MUTED_COLOR_INDEX))),
            ),
        ]));
        if !cd.risk_reasons.is_empty() {
            out.push(Line::from(Span::styled(
                format!("reasons: {}", cd.risk_reasons.join(", ")),
                muted,
            )));
        }
        if !cd.affected_targets.is_empty() {
            out.push(Line::from(Span::styled(
                format!("affected: {}", cd.affected_targets.join(", ")),
                muted,
            )));
        }
        if let Some(cap) = cd.policy_cap.as_deref() {
            out.push(Line::from(Span::styled(format!("scope cap: {cap}"), muted)));
        }
        if !cd.native_tool_hints.is_empty() {
            for hint in &cd.native_tool_hints {
                out.push(Line::from(Span::styled(format!("hint: {hint}"), muted)));
            }
        }
        out
    }

    /// Render one source line of the command block, styling the slice that
    /// falls within the highlight span (if any). `char_base` is this line's
    /// start offset (chars) within the whole command; `highlight` is the
    /// global `[start, end)` char range.
    fn command_source_line(
        &self,
        line: &str,
        char_base: usize,
        line_len: usize,
        highlight: Option<(usize, usize)>,
    ) -> Line<'static> {
        // Indent so the command reads as a distinct quoted block.
        let indent = "  ";
        let plain = Style::default().fg(Color::White);
        let hot = Style::default()
            .fg(Color::Indexed(ACCENT_BLUE_INDEX))
            .add_modifier(Modifier::UNDERLINED | Modifier::BOLD);

        let line_start = char_base;
        let line_end = char_base + line_len;
        let chars: Vec<char> = line.chars().collect();

        match highlight {
            // No highlight, or this line lies entirely outside the span.
            Some((hs, he)) if hs < line_end && he > line_start => {
                // Clamp the span to this line's local char indices.
                let local_start = hs.saturating_sub(line_start).min(line_len);
                let local_end = (he - line_start).min(line_len);
                let mut spans: Vec<Span<'static>> = vec![Span::raw(indent.to_string())];
                if local_start > 0 {
                    spans.push(Span::styled(
                        chars[..local_start].iter().collect::<String>(),
                        plain,
                    ));
                }
                if local_end > local_start {
                    spans.push(Span::styled(
                        chars[local_start..local_end].iter().collect::<String>(),
                        hot,
                    ));
                }
                if local_end < line_len {
                    spans.push(Span::styled(
                        chars[local_end..].iter().collect::<String>(),
                        plain,
                    ));
                }
                Line::from(spans)
            }
            _ => Line::from(vec![
                Span::raw(indent.to_string()),
                Span::styled(line.to_string(), plain),
            ]),
        }
    }

    fn option_line(&self, num: &str, marker: &str, label: &str, hovered: bool) -> Line<'static> {
        let cursor = if hovered {
            OPTION_CURSOR_HOVERED
        } else {
            OPTION_CURSOR_PLAIN
        };
        let style = if hovered {
            Style::default()
                .fg(Color::Indexed(ACCENT_BLUE_INDEX))
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        Line::from(vec![
            Span::raw(cursor.to_string()),
            Span::styled(format!("{num}{marker}{label}"), style),
        ])
    }

    fn render_confirm(&self) -> Vec<Line<'static>> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let red = Style::default().fg(Color::Red);
        let flags = self.state.answered_flags();
        let answers = self.state.collect_answers();
        let mut lines: Vec<Line<'static>> = Vec::new();
        if !self.description.trim().is_empty() {
            lines.push(Line::from(Span::styled(
                self.description.clone(),
                muted.add_modifier(Modifier::ITALIC),
            )));
            lines.push(Line::default());
        }
        lines.push(Line::from(Span::styled(
            "Review your answers".to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::default());
        for (i, q) in self.questions.iter().enumerate() {
            let prompt = question_prompt(q).to_string();
            if flags.get(i).copied().unwrap_or(false) {
                let summary = summarize_answer(answers.get(i), q);
                lines.push(Line::from(vec![
                    Span::styled(format!("{prompt}: "), muted),
                    Span::styled(summary, Style::default().fg(Color::White)),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled(format!("{prompt}: "), muted),
                    Span::styled("⚠ unanswered".to_string(), red),
                ]));
            }
        }
        lines.push(Line::default());
        if flags.iter().all(|f| *f) {
            lines.push(Line::from(Span::styled(
                "Press enter to submit.".to_string(),
                Style::default().fg(Color::Green),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "Answer every question before submitting.".to_string(),
                red,
            )));
        }
        lines
    }

    /// Logical-line count the confirm page wants (measured unwrapped — the
    /// confirm rows are short labels). Drives the confirm-region scroll
    /// metrics + the expand hint.
    fn confirm_content_lines(&self) -> usize {
        let mut lines = 0usize;
        if !self.description.trim().is_empty() {
            lines += 1 + 1; // header + blank
        }
        lines += 1 + 1; // "Review your answers" + blank
        lines += self.questions.len(); // one row per question
        lines += 1 + 1; // blank + status row
        lines
    }
}

/// Split a body of `body_h` rows into a prompt slice and an answer slice so
/// neither region can fully hide the other. Each region is guaranteed a
/// minimum visible slice ([`MIN_PROMPT_ROWS`] / [`MIN_ANSWER_ROWS`], scaled
/// down only when the body itself is tinier than the minimums); a region
/// that wants less than its slice gives the slack back to the other.
fn split_regions(body_h: usize, prompt_want: usize, answer_want: usize) -> (usize, usize) {
    if body_h == 0 {
        return (0, 0);
    }
    // Answers get priority for their focused row; the prompt is guaranteed at
    // least a couple of lines (with a "more" indicator). Scale the floors
    // down if the body can't even hold both.
    let answer_min = MIN_ANSWER_ROWS.min(body_h);
    let prompt_min = MIN_PROMPT_ROWS.min(body_h.saturating_sub(answer_min));

    // Prompt takes what it wants, bounded below by its floor and above by
    // whatever's left after the answer floor; answers take the rest.
    let prompt_h = prompt_want.clamp(prompt_min, body_h.saturating_sub(answer_min));
    let mut answer_h = body_h - prompt_h;

    // If answers want less than their slice, hand the slack to the prompt
    // (a long prompt can use the room; it still scrolls past it).
    if answer_want < answer_h {
        let slack = answer_h - answer_want.max(answer_min);
        answer_h -= slack;
        return (prompt_h + slack, answer_h);
    }
    (prompt_h, answer_h)
}

fn risk_tier_color(tier: &str) -> Option<Color> {
    match tier {
        "destructive" | "privileged" => Some(Color::Red),
        "mutating" => Some(Color::Yellow),
        "ordinary" => Some(Color::Indexed(MUTED_COLOR_INDEX)),
        _ => None,
    }
}

fn risk_tier_border_color(tier: &str) -> Option<Color> {
    match tier {
        "destructive" | "privileged" => Some(Color::Red),
        _ => None,
    }
}

const WRITE_PREVIEW_MAX_LINES: usize = 12;

fn sanitize_preview_content(content: &str) -> String {
    content
        .chars()
        .filter(|ch| *ch == '\n' || !ch.is_control())
        .collect()
}

fn truncated_preview_lines(content: &str) -> Vec<String> {
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() <= WRITE_PREVIEW_MAX_LINES {
        if lines.is_empty() {
            return vec![String::new()];
        }
        return lines.into_iter().map(str::to_string).collect();
    }
    let mut out: Vec<String> = lines
        .iter()
        .take(WRITE_PREVIEW_MAX_LINES)
        .map(|line| (*line).to_string())
        .collect();
    out.push(format!(
        "… (+{} more lines)",
        lines.len() - WRITE_PREVIEW_MAX_LINES
    ));
    out
}

/// Total wrapped-row count for `lines` at terminal width `width`, matching
/// ratatui's `Wrap { trim: false }` closely enough for layout: each logical
/// line takes `ceil(display_width / width)` rows (≥1), greedily word-wrapped
/// with hard breaks for over-long words. `width == 0` falls back to the
/// logical-line count.
fn wrapped_height(lines: &[Line<'_>], width: u16) -> usize {
    if width == 0 {
        return lines.len();
    }
    lines.iter().map(|l| line_wrapped_rows(l, width)).sum()
}

/// Expand each logical line into the individual wrapped display rows it
/// occupies at `width`, so prompt-region scrolling lands on display rows.
/// Style is preserved by keeping each source line's full span set on its
/// first row and emitting blank continuation rows for the wrap remainder —
/// the `Paragraph` re-wraps the visible slice, so continuation rows act only
/// as scroll/height accounting placeholders.
fn wrap_lines(lines: &[Line<'static>], width: u16) -> Vec<Line<'static>> {
    if width == 0 {
        return lines.to_vec();
    }
    let mut out: Vec<Line<'static>> = Vec::new();
    for l in lines {
        let rows = line_wrapped_rows(l, width);
        out.push(l.clone());
        for _ in 1..rows {
            out.push(Line::default());
        }
    }
    out
}

fn wrap_indented_text(text: &str, indent: usize, width: u16, style: Style) -> Vec<Line<'static>> {
    let prefix = " ".repeat(indent);
    let available = (width as usize).saturating_sub(indent).max(1);
    let mut rows = Vec::new();
    let mut current = String::new();
    let mut col = 0usize;
    for word in split_keep_spaces(text) {
        let word_width = UnicodeWidthStr::width(word.as_str());
        if col > 0 && col + word_width > available {
            rows.push(current.trim_end().to_string());
            current.clear();
            col = 0;
        }
        current.push_str(&word);
        col += word_width;
        while col > available {
            rows.push(current.chars().take(available).collect::<String>());
            current = current.chars().skip(available).collect::<String>();
            col = UnicodeWidthStr::width(current.as_str());
        }
    }
    if !current.is_empty() || rows.is_empty() {
        rows.push(current.trim_end().to_string());
    }
    rows.into_iter()
        .map(|row| Line::from(Span::styled(format!("{prefix}{row}"), style)))
        .collect()
}

/// Rows one logical line wraps to at `width` (≥1). Word-wrap with hard
/// breaks for words longer than the line.
fn line_wrapped_rows(line: &Line<'_>, width: u16) -> usize {
    let width = width as usize;
    if width == 0 {
        return 1;
    }
    let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
    if text.is_empty() {
        return 1;
    }
    let mut rows = 1usize;
    let mut col = 0usize;
    for word in split_keep_spaces(&text) {
        let w = UnicodeWidthStr::width(word.as_str());
        if w > width {
            // Over-long word: it starts a fresh row (if the current one has
            // content), then wraps every `width` cells.
            if col > 0 {
                rows += 1;
            }
            rows += (w - 1) / width;
            col = w % width;
            if col == 0 {
                col = width;
            }
        } else if col + w > width {
            rows += 1;
            col = w;
        } else {
            col += w;
        }
    }
    rows
}

/// Split a string into whitespace-preserving chunks (each run of
/// non-spaces, with a single trailing space carried so wrap accounting
/// matches a greedy word-wrapper).
fn split_keep_spaces(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if ch == ' ' {
            cur.push(ch);
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Map one proto question to a dialog page.
fn page_for(q: &InterruptQuestion) -> Page {
    match q {
        InterruptQuestion::Single {
            prompt,
            options,
            allow_freetext,
            permission,
            ..
        } => {
            // A permission/approval `Single` opts into the stripped
            // presentation (no marker, no free-text custom row); a genuine
            // agent question honors the protocol's free-text flag. This is
            // the single place the permission-vs-question distinction is
            // branched on the dialog side — driven by the interrupt's intent,
            // never by inspecting option labels.
            let primary = opts(options.iter().filter(|option| !option.secondary));
            let secondary = opts(options.iter().filter(|option| option.secondary));
            let page = Page::select(prompt.clone(), primary)
                .with_secondary_options(secondary)
                .allow_custom(*allow_freetext);
            if *permission { page.permission() } else { page }
        }
        InterruptQuestion::Multi {
            prompt,
            options,
            allow_freetext,
        } => Page::multiselect(prompt.clone(), opts(options.iter())).allow_custom(*allow_freetext),
        InterruptQuestion::Freetext { prompt, masked } => {
            if *masked {
                Page::text_masked(prompt.clone())
            } else {
                Page::text(prompt.clone())
            }
        }
    }
}

fn opts<'a>(options: impl IntoIterator<Item = &'a InterruptOption>) -> Vec<DialogOption> {
    options
        .into_iter()
        .map(|o| DialogOption {
            id: o.id.clone(),
            label: o.label.clone(),
            description: o.description.clone(),
            secondary: o.secondary,
        })
        .collect()
}

impl Pane for QuestionDialog {
    type Outcome = bool;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        QuestionDialog::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        QuestionDialog::render(self, frame, area);
    }
}

/// Map a dialog [`Answer`] back to the proto [`ResolveResponse`] for its
/// question. The additive multiselect free-text rides as an extra
/// selected id (the option ids are stable; a typed value can't collide
/// with a proposed id, and the tool renders unknown ids verbatim).
fn answer_to_response(answer: &Answer, _q: &InterruptQuestion) -> ResolveResponse {
    match answer {
        Answer::Single { id } => ResolveResponse::Single {
            selected_id: id.clone(),
        },
        Answer::Multi { ids, custom } => {
            let mut selected_ids = ids.clone();
            if let Some(text) = custom {
                selected_ids.push(text.clone());
            }
            ResolveResponse::Multi { selected_ids }
        }
        Answer::Text { text } => ResolveResponse::Freetext { text: text.clone() },
    }
}

fn question_prompt(q: &InterruptQuestion) -> &str {
    match q {
        InterruptQuestion::Single { prompt, .. }
        | InterruptQuestion::Multi { prompt, .. }
        | InterruptQuestion::Freetext { prompt, .. } => prompt,
    }
}

/// One-line confirm-page summary of a page's answer, resolving option
/// ids to labels where possible.
fn summarize_answer(answer: Option<&Answer>, q: &InterruptQuestion) -> String {
    match answer {
        Some(Answer::Single { id }) => label_for(q, id),
        Some(Answer::Multi { ids, custom }) => {
            let mut parts: Vec<String> = ids.iter().map(|id| label_for(q, id)).collect();
            if let Some(text) = custom {
                parts.push(format!("“{text}”"));
            }
            if parts.is_empty() {
                "[none]".to_string()
            } else {
                parts.join(", ")
            }
        }
        Some(Answer::Text { text }) => text.clone(),
        None => "[no answer]".to_string(),
    }
}

fn label_for(q: &InterruptQuestion, id: &str) -> String {
    let options: &[InterruptOption] = match q {
        InterruptQuestion::Single { options, .. } | InterruptQuestion::Multi { options, .. } => {
            options
        }
        InterruptQuestion::Freetext { .. } => &[],
    };
    options
        .iter()
        .find(|o| o.id == id)
        .map(|o| o.label.clone())
        .unwrap_or_else(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn opt(id: &str, label: &str) -> InterruptOption {
        InterruptOption {
            id: id.into(),
            label: label.into(),
            description: None,
            secondary: false,
        }
    }

    fn single_q() -> InterruptQuestionSet {
        InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "DB?".into(),
                options: vec![opt("pg", "Postgres"), opt("sqlite", "SQLite")],
                allow_freetext: true,
                command_detail: None,
                permission: false,
                sandbox_escalation: None,
            }],
        }
    }

    fn dialog(set: InterruptQuestionSet) -> QuestionDialog {
        QuestionDialog::new(Uuid::new_v4(), String::new(), set, Duration::ZERO)
    }

    #[test]
    fn submit_maps_to_single_resolve_response() {
        let iid = Uuid::new_v4();
        // Zero lockout so the dialog is immediately interactive.
        let mut d = QuestionDialog::new(iid, String::new(), single_q(), Duration::ZERO);
        // Hover first option, enter => fast-path submit.
        assert!(d.handle_key(press(KeyCode::Enter)));
        match d.take_result() {
            Some(QuestionResult::Submit {
                interrupt_id,
                responses,
            }) => {
                assert_eq!(interrupt_id, iid);
                assert!(matches!(
                    responses.as_slice(),
                    [ResolveResponse::Single { selected_id }] if selected_id == "pg"
                ));
            }
            other => panic!("expected Submit, got {other:?}"),
        }
    }

    #[test]
    fn number_key_selects_and_submits_single() {
        let iid = Uuid::new_v4();
        let mut d = QuestionDialog::new(iid, String::new(), single_q(), Duration::ZERO);
        // Pressing `2` selects the second option AND advances => fast-path
        // submit (lone question).
        assert!(d.handle_key(press(KeyCode::Char('2'))));
        match d.take_result() {
            Some(QuestionResult::Submit { responses, .. }) => {
                assert!(matches!(
                    responses.as_slice(),
                    [ResolveResponse::Single { selected_id }] if selected_id == "sqlite"
                ));
            }
            other => panic!("expected Submit, got {other:?}"),
        }
    }

    #[test]
    fn single_allow_freetext_false_hides_custom_row() {
        let mut d = dialog(InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "DB?".into(),
                options: vec![opt("pg", "Postgres"), opt("sqlite", "SQLite")],
                allow_freetext: false,
                command_detail: None,
                permission: false,
                sandbox_escalation: None,
            }],
        });

        assert!(!d.state.pages()[0].has_custom());
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.state.cursor(), 1);
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.state.cursor(), 0, "wraps without a custom slot");
        assert!(d.handle_key(press(KeyCode::Enter)));
        match d.take_result() {
            Some(QuestionResult::Submit { responses, .. }) => {
                assert!(matches!(
                    responses.as_slice(),
                    [ResolveResponse::Single { selected_id }] if selected_id == "pg"
                ));
            }
            other => panic!("expected Submit, got {other:?}"),
        }
    }

    #[test]
    fn single_allow_freetext_true_allows_custom_text() {
        let mut d = dialog(single_q());
        assert!(d.state.pages()[0].has_custom());

        d.handle_key(press(KeyCode::Down));
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.state.cursor(), 2, "custom slot is reachable");
        d.handle_key(press(KeyCode::Enter));
        d.handle_key(press(KeyCode::Char('m')));
        d.handle_key(press(KeyCode::Char('y')));
        assert!(d.handle_key(press(KeyCode::Enter)));

        match d.take_result() {
            Some(QuestionResult::Submit { responses, .. }) => {
                assert!(matches!(
                    responses.as_slice(),
                    [ResolveResponse::Freetext { text }] if text == "my"
                ));
            }
            other => panic!("expected Submit, got {other:?}"),
        }
    }

    #[test]
    fn permission_single_suppresses_freetext_even_when_allowed() {
        let mut d = dialog(InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Allow?".into(),
                options: vec![opt("yes", "Yes"), opt("no", "No")],
                allow_freetext: true,
                command_detail: None,
                permission: true,
                sandbox_escalation: None,
            }],
        });

        assert!(!d.state.pages()[0].has_custom());
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.state.cursor(), 1);
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.state.cursor(), 0, "permission page has no custom slot");
    }

    #[test]
    fn esc_maps_to_cancel() {
        let iid = Uuid::new_v4();
        let mut d = QuestionDialog::new(iid, String::new(), single_q(), Duration::ZERO);
        assert!(d.handle_key(press(KeyCode::Esc)));
        assert!(matches!(
            d.take_result(),
            Some(QuestionResult::Cancel { interrupt_id }) if interrupt_id == iid
        ));
    }

    #[test]
    fn multiselect_custom_rides_as_extra_id() {
        let q = InterruptQuestion::Multi {
            prompt: "tags?".into(),
            options: vec![opt("a", "A")],
            allow_freetext: true,
        };
        let answer = Answer::Multi {
            ids: vec!["a".into()],
            custom: Some("custom".into()),
        };
        let resp = answer_to_response(&answer, &q);
        match resp {
            ResolveResponse::Multi { selected_ids } => {
                assert_eq!(selected_ids, vec!["a".to_string(), "custom".to_string()]);
            }
            other => panic!("expected Multi, got {other:?}"),
        }
    }

    #[test]
    fn freetext_opens_in_typing_mode() {
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Freetext {
                prompt: "Name?".into(),
                masked: false,
            }],
        };
        let mut d = dialog(set);
        // No space/enter needed: typing is live immediately. A char lands
        // in the field.
        d.handle_key(press(KeyCode::Char('h')));
        d.handle_key(press(KeyCode::Char('i')));
        // Enter on a lone freetext question submits.
        assert!(d.handle_key(press(KeyCode::Enter)));
        match d.take_result() {
            Some(QuestionResult::Submit { responses, .. }) => {
                assert!(matches!(
                    responses.as_slice(),
                    [ResolveResponse::Freetext { text }] if text == "hi"
                ));
            }
            other => panic!("expected Submit, got {other:?}"),
        }
    }

    #[test]
    fn desired_height_grows_with_descriptions() {
        let plain = dialog(single_q());
        let with_desc = dialog(InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "DB?".into(),
                options: vec![
                    InterruptOption {
                        id: "pg".into(),
                        label: "Postgres".into(),
                        description: Some("Relational, ACID".into()),
                        secondary: false,
                    },
                    InterruptOption {
                        id: "sqlite".into(),
                        label: "SQLite".into(),
                        description: Some("Embedded, single-file".into()),
                        secondary: false,
                    },
                ],
                allow_freetext: true,
                command_detail: None,
                permission: false,
                sandbox_escalation: None,
            }],
        });
        assert!(
            with_desc.desired_height() > plain.desired_height(),
            "per-option descriptions add body lines"
        );
        assert!(with_desc.desired_height() <= MAX_DIALOG_HEIGHT);
    }

    #[test]
    fn render_includes_description_and_context_header() {
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "DB?".into(),
                options: vec![InterruptOption {
                    id: "pg".into(),
                    label: "Postgres".into(),
                    description: Some("Relational engine".into()),
                    secondary: false,
                }],
                allow_freetext: true,
                command_detail: None,
                permission: false,
                sandbox_escalation: None,
            }],
        };
        let d = QuestionDialog::new(
            Uuid::new_v4(),
            "Choosing the storage backend".into(),
            set,
            Duration::ZERO,
        );
        let area = Rect::new(0, 0, 60, 12);
        let (lines, _) = d.render_page(area);
        let text: String = lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("Choosing the storage backend"),
            "context header"
        );
        assert!(text.contains("Relational engine"), "option description");
        assert!(text.contains("Postgres"), "option label");
    }

    /// Flatten a page's rendered body into one string per line.
    fn render_lines(d: &QuestionDialog, area: Rect) -> Vec<String> {
        let (lines, _) = d.render_page(area);
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn footer_and_which_key_shift_page_binding_are_protocol_gated() {
        let off = dialog(single_q()).with_keyboard_enhancement_active(false);
        assert!(!off.footer_hint().contains("shift+pgup/pgdn"));

        let on = dialog(single_q()).with_keyboard_enhancement_active(true);
        assert!(on.footer_hint().contains("shift+pgup/pgdn"));
    }

    #[test]
    fn scrolled_heterogeneous_rows_fit_from_scroll_offset() {
        let mut set = single_q();
        if let InterruptQuestion::Single { options, .. } = &mut set.questions[0] {
            options[0].description = Some("short".into());
            options[1].description = Some("word ".repeat(40) + "tail");
        }
        let mut d = dialog(set);
        let area = Rect::new(0, 0, 60, 8);
        d.sync_viewport(area, 12);
        d.handle_key(press(KeyCode::Down));
        d.sync_viewport(area, 12);

        let answer = d.render_answer(Rect::new(0, 0, 60, 3)).0;
        let text = answer
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains("tail"),
            "tall focused option tail is reachable: {text}"
        );
    }

    #[test]
    fn two_hundred_char_description_at_sixty_cols_keeps_tail_reachable() {
        let mut set = single_q();
        if let InterruptQuestion::Single { options, .. } = &mut set.questions[0] {
            options[0].description = Some(format!("{} tail", "x".repeat(200)));
        }
        let d = dialog(set);
        let answer = d.render_answer(Rect::new(0, 0, 60, 4)).0;
        let text = answer
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("tail"), "{text}");
    }

    #[test]
    fn narrow_width_tall_option_keeps_tail_reachable() {
        let mut set = single_q();
        if let InterruptQuestion::Single { options, .. } = &mut set.questions[0] {
            options[0].description = Some("narrow ".repeat(40) + "tail");
        }
        let d = dialog(set);
        let answer = d.render_answer(Rect::new(0, 0, 40, 3)).0;
        let text = answer
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("tail"), "{text}");
        assert!(!answer.is_empty());
    }

    #[test]
    fn option_description_continuations_use_display_width_indent() {
        let mut set = single_q();
        if let InterruptQuestion::Single { options, .. } = &mut set.questions[0] {
            options[0].description = Some("alpha beta gamma delta epsilon zeta eta theta".into());
        }
        let d = dialog(set);
        let answer = d.render_answer(Rect::new(0, 0, 32, 8)).0;
        let rows = answer
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        let desc_rows = rows
            .iter()
            .filter(|row| {
                row.trim_start().starts_with("alpha") || row.trim_start().starts_with("epsilon")
            })
            .collect::<Vec<_>>();
        assert!(
            desc_rows.iter().all(|row| row.starts_with("         ")),
            "{rows:?}"
        );
        assert!(
            desc_rows.iter().all(|row| !row.starts_with("          ")),
            "indent is display width 9, not byte width 11: {rows:?}"
        );
    }

    #[test]
    fn twelve_option_list_numbers_one_through_nine_only() {
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Pick".into(),
                options: (1..=12)
                    .map(|n| InterruptOption {
                        id: format!("o{n}"),
                        label: format!("Option {n}"),
                        description: None,
                        secondary: false,
                    })
                    .collect(),
                allow_freetext: false,
                command_detail: None,
                permission: false,
                sandbox_escalation: None,
            }],
        };
        let mut d = dialog(set);
        d.sync_viewport(Rect::new(0, 0, 80, 16), 24);
        for _ in 0..8 {
            d.handle_key(press(KeyCode::Down));
        }
        let lines = d.render_answer(Rect::new(0, 0, 80, 16)).0;
        let text = lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("9. ( ) Option 9"));
        assert!(text.contains("   ( ) Option 10"));
        assert!(!text.contains("10. Option 10"));
        assert!(!text.contains("11. Option 11"));
        assert!(!text.contains("12. Option 12"));
    }

    #[test]
    fn multiselect_typed_custom_renders_checked_after_navigation() {
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Multi {
                prompt: "Pick".into(),
                options: vec![InterruptOption {
                    id: "a".into(),
                    label: "A".into(),
                    description: None,
                    secondary: false,
                }],
                allow_freetext: true,
            }],
        };
        let mut d = dialog(set);
        d.handle_key(press(KeyCode::Down)); // custom
        d.handle_key(press(KeyCode::Enter)); // begin typing
        for ch in "custom value".chars() {
            d.handle_key(press(KeyCode::Char(ch)));
        }
        d.handle_key(press(KeyCode::Esc)); // leave typing, keep custom text
        d.handle_key(press(KeyCode::Down)); // navigate to Next

        let text = render_lines(&d, Rect::new(0, 0, 60, 10)).join("\n");
        assert!(text.contains("[x] custom value"), "{text}");
    }

    #[test]
    fn masked_freetext_renders_fixed_mask_but_submits_original_text() {
        let mut d = QuestionDialog::new(
            Uuid::new_v4(),
            "web key".into(),
            InterruptQuestionSet {
                questions: vec![InterruptQuestion::Freetext {
                    prompt: "Paste key".into(),
                    masked: true,
                }],
            },
            DialogState::NO_LOCKOUT,
        );
        d.paste("secret-key-value");
        let rendered = render_lines(&d, Rect::new(0, 0, 80, 10)).join("\n");
        assert!(rendered.contains(mask_value()));
        assert!(!rendered.contains("secret-key-value"));

        let answers = d.state.collect_answers();
        assert_eq!(
            answers,
            vec![crate::tui::dialog::Answer::Text {
                text: "secret-key-value".into()
            }]
        );
    }

    #[test]
    fn cursor_glyph_width_matches_constant() {
        // The parked-cursor math assumes both hover glyphs are
        // OPTION_CURSOR_WIDTH cells; assert that so it can't drift.
        assert_eq!(
            UnicodeWidthStr::width(OPTION_CURSOR_HOVERED),
            OPTION_CURSOR_WIDTH
        );
        assert_eq!(
            UnicodeWidthStr::width(OPTION_CURSOR_PLAIN),
            OPTION_CURSOR_WIDTH
        );
    }

    #[test]
    fn typed_custom_replaces_placeholder_label() {
        let mut d = dialog(single_q());
        let area = Rect::new(0, 0, 60, 12);
        // Empty field: the placeholder shows.
        let before = render_lines(&d, area).join("\n");
        assert!(
            before.contains(CUSTOM_LABEL),
            "empty field shows the placeholder"
        );
        // Move to the custom affordance, begin typing, type "hello".
        d.handle_key(press(KeyCode::Down)); // option 2
        d.handle_key(press(KeyCode::Down)); // custom affordance
        d.handle_key(press(KeyCode::Enter)); // begin typing (empty)
        assert!(d.state.is_typing());
        for c in "hello".chars() {
            d.handle_key(press(KeyCode::Char(c)));
        }
        let (lines, cursor) = d.render_page(area);
        let text: Vec<String> = lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect();
        let joined = text.join("\n");
        // The custom row reads only "hello" with the edit marker — never
        // the "Type your own answer:" prefix.
        assert!(
            text.iter().any(|l| l.contains("✎ hello")),
            "custom row shows the edit marker + typed text: {text:?}"
        );
        assert!(
            !joined.contains(&format!("{CUSTOM_LABEL}: ")),
            "placeholder prefix must not coexist with typed text"
        );
        assert!(
            !joined.contains(&format!("{CUSTOM_LABEL}\nhello"))
                && !text
                    .iter()
                    .any(|l| l.contains(CUSTOM_LABEL) && l.contains("hello")),
            "placeholder and typed text are mutually exclusive"
        );
        // The parked cursor sits immediately after "hello": hover glyph (2)
        // + marker "✎ " (2) + 5 chars = column 9.
        let (cx, _) = cursor.expect("typing parks a cursor");
        let expected = OPTION_CURSOR_WIDTH as u16
            + UnicodeWidthStr::width("✎ ") as u16
            + "hello".chars().count() as u16;
        assert_eq!(cx, area.x + expected, "cursor lands right after `hello`");
    }

    #[test]
    fn clearing_custom_reverts_to_placeholder() {
        let mut d = dialog(single_q());
        let area = Rect::new(0, 0, 60, 12);
        d.handle_key(press(KeyCode::Down));
        d.handle_key(press(KeyCode::Down)); // custom affordance
        d.handle_key(press(KeyCode::Enter)); // begin typing
        d.handle_key(press(KeyCode::Char('x')));
        assert!(render_lines(&d, area).iter().any(|l| l.contains("✎ x")));
        // Delete the only char: row reverts to the placeholder.
        d.handle_key(press(KeyCode::Backspace));
        let joined = render_lines(&d, area).join("\n");
        assert!(
            joined.contains(CUSTOM_LABEL),
            "empty field reverts to the placeholder: {joined}"
        );
    }

    #[test]
    fn cursor_display_col_tracks_multibyte_caret() {
        // A wide/multi-byte char before the caret must shift the parked
        // cursor by its DISPLAY width, not its byte length.
        let mut d = dialog(single_q());
        let area = Rect::new(0, 0, 60, 12);
        d.handle_key(press(KeyCode::Down));
        d.handle_key(press(KeyCode::Down)); // custom affordance
        d.handle_key(press(KeyCode::Enter)); // begin typing
        // "世" is a 3-byte, 2-cell-wide CJK glyph.
        d.handle_key(press(KeyCode::Char('世')));
        d.handle_key(press(KeyCode::Char('a')));
        let (_, cursor) = d.render_page(area);
        let (cx, _) = cursor.expect("typing parks a cursor");
        // hover(2) + marker(2) + width("世a") = 2 + 2 + (2 + 1) = 7.
        let expected = OPTION_CURSOR_WIDTH as u16 + 2 + 3;
        assert_eq!(cx, area.x + expected, "caret tracks display width");
    }

    #[test]
    fn esc_round_trip_preserves_typed_custom_text() {
        let mut d = dialog(single_q());
        let area = Rect::new(0, 0, 60, 12);
        d.handle_key(press(KeyCode::Down));
        d.handle_key(press(KeyCode::Down)); // custom affordance
        d.handle_key(press(KeyCode::Enter)); // begin typing
        for c in "abc".chars() {
            d.handle_key(press(KeyCode::Char(c)));
        }
        // First Esc defocuses; dialog stays open; text intact.
        assert!(!d.handle_key(press(KeyCode::Esc)), "Esc must not close");
        assert!(!d.state.is_typing());
        let joined = render_lines(&d, area).join("\n");
        assert!(joined.contains("abc"), "typed text survives Esc: {joined}");
        // Re-enter typing (Enter on the custom affordance with text present
        // commits on single-select; Space re-enters). Use Space to resume.
        d.handle_key(press(KeyCode::Char(' ')));
        assert!(d.state.is_typing(), "resumes typing");
        assert_eq!(d.state.custom_text(0), "abc", "resumes from same text");
    }

    #[test]
    fn long_list_scrolls_keeping_focus_visible() {
        let options: Vec<InterruptOption> = (0..20)
            .map(|i| opt(&format!("o{i}"), &format!("Option {i}")))
            .collect();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Pick".into(),
                options,
                allow_freetext: true,
                command_detail: None,
                permission: false,
                sandbox_escalation: None,
            }],
        };
        let mut d = dialog(set);
        // Tight overlay: only a few answer rows fit in the answer region.
        let area = Rect::new(0, 0, 60, 11);
        d.sync_viewport(area, 40);
        // Move the cursor well past the initial window.
        for _ in 0..12 {
            d.handle_key(press(KeyCode::Down));
            d.sync_viewport(area, 40);
        }
        // The focused cursor must lie within the rendered window.
        let scroll = d.state.scroll();
        let cursor = d.state.cursor();
        assert!(cursor >= scroll, "cursor not above the window");
        assert!(
            cursor < scroll + MAX_VISIBLE_OPTION_ROWS,
            "cursor not below the window"
        );
        assert!(scroll > 0, "list should have scrolled");
        // scrolloff=1: mid-list, the next option below the cursor is on screen.
        let vp = d.answer_viewport_rows();
        assert!(
            cursor + 1 < scroll + vp,
            "next option below the cursor stays visible (scrolloff=1)"
        );
    }

    /// The options region renders no `▲/▼ more` markers even when the list
    /// overflows its window (the markers were removed; the scroll margin
    /// keeps the next option visible instead).
    #[test]
    fn options_region_has_no_more_markers() {
        let options: Vec<InterruptOption> = (0..20)
            .map(|i| opt(&format!("o{i}"), &format!("Option {i}")))
            .collect();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Pick".into(),
                options,
                allow_freetext: true,
                command_detail: None,
                permission: false,
                sandbox_escalation: None,
            }],
        };
        let mut d = dialog(set);
        let area = Rect::new(0, 0, 60, 11);
        d.sync_viewport(area, 40);
        // Scrolled to the middle of the list: with the old behavior BOTH a
        // leading and trailing marker would show here.
        for _ in 0..8 {
            d.handle_key(press(KeyCode::Down));
            d.sync_viewport(area, 40);
        }
        assert!(d.state.scroll() > 0, "list scrolled into the middle");
        let answer = d.render_answer(Rect::new(0, 0, 60, 8)).0;
        let joined: String = answer
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(
            !joined.contains("more"),
            "options region shows no more markers: {joined}"
        );
        assert!(!joined.contains('▲') && !joined.contains('▼'));
    }

    /// Dropping the marker row reclaims it for an option: the answer viewport
    /// fits one more option than it did when a marker row was reserved.
    #[test]
    fn dropping_marker_reclaims_an_option_row() {
        let options: Vec<InterruptOption> = (0..20)
            .map(|i| opt(&format!("o{i}"), &format!("Option {i}")))
            .collect();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Pick".into(),
                options,
                allow_freetext: true,
                command_detail: None,
                permission: false,
                sandbox_escalation: None,
            }],
        };
        let mut d = dialog(set);
        // Compute the answer slice geometry directly, then confirm the
        // viewport uses the WHOLE slice (no marker-row reservation): for a
        // list of single-line options the fitted viewport equals the slice
        // height (capped at the row cap).
        let area = Rect::new(0, 0, 60, 14);
        d.sync_viewport(area, 40);
        let body_h = (area.height - 3) as usize;
        let (_p, answer_h) =
            split_regions(body_h, d.prompt_region_height(), d.answer_region_want());
        let expected = answer_h.min(MAX_VISIBLE_OPTION_ROWS);
        assert_eq!(
            d.state.viewport(),
            expected,
            "answer viewport uses the full slice with no marker-row reserved"
        );
    }

    // ---- region split (prompt vs answers) -------------------------------

    /// A question with a very long prompt and a real option list, rendered
    /// into a small overlay: BOTH some prompt and some answers must be
    /// visible — neither can fully hide the other.
    fn long_prompt_q() -> InterruptQuestionSet {
        let long: String = "This is a deliberately very long question prompt that wraps across \
            many lines and would, without the region split, consume the entire dialog body and \
            push the answer options off the bottom of the bottom-anchored overlay so the user \
            could not see or reach them at all. "
            .repeat(4);
        InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: long,
                options: vec![
                    opt("a", "First option"),
                    opt("b", "Second option"),
                    opt("c", "Third option"),
                ],
                allow_freetext: true,
                command_detail: None,
                permission: false,
                sandbox_escalation: None,
            }],
        }
    }

    #[test]
    fn long_prompt_never_hides_answers() {
        let mut d = dialog(long_prompt_q());
        // Small overlay (the overflow case the bug was about).
        let compact = Rect::new(0, 0, 50, 10);
        d.sync_viewport(compact, 24);
        let body_h = (compact.height - 3) as usize; // borders + footer
        let prompt_want = d.prompt_region_height();
        let answer_want = d.answer_region_want();
        let (prompt_h, answer_h) = split_regions(body_h, prompt_want, answer_want);
        // The hard guarantee: each region keeps a non-zero, minimum slice.
        assert!(
            prompt_h >= MIN_PROMPT_ROWS.min(body_h),
            "prompt slice too small"
        );
        assert!(
            answer_h >= MIN_ANSWER_ROWS.min(body_h),
            "answer slice too small"
        );
        assert!(prompt_h > 0 && answer_h > 0, "both regions visible");
        assert_eq!(prompt_h + answer_h, body_h, "the split fills the body");
        // The prompt overflows its slice -> it gains scroll markers.
        assert!(prompt_want > prompt_h, "long prompt overflows its slice");
        assert!(d.state.prompt_overflows());
        // At least one focused option row is shown in the answer region.
        let answer = d.render_answer(Rect::new(0, 0, 50, answer_h as u16)).0;
        let joined: String = answer
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(
            joined.contains("First option") || joined.contains("Second option"),
            "an answer option is visible: {joined}"
        );
    }

    #[test]
    fn long_answer_list_never_hides_prompt() {
        // 30 options, short prompt: the answer region must not swallow the
        // whole body — the prompt keeps its minimum slice.
        let options: Vec<InterruptOption> = (0..30)
            .map(|i| opt(&format!("o{i}"), &format!("Option {i}")))
            .collect();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Pick one".into(),
                options,
                allow_freetext: true,
                command_detail: None,
                permission: false,
                sandbox_escalation: None,
            }],
        };
        let mut d = dialog(set);
        let compact = Rect::new(0, 0, 50, 12);
        d.sync_viewport(compact, 24);
        let body_h = (compact.height - 3) as usize;
        let (prompt_h, answer_h) =
            split_regions(body_h, d.prompt_region_height(), d.answer_region_want());
        assert!(
            prompt_h >= MIN_PROMPT_ROWS.min(body_h),
            "prompt kept its slice"
        );
        assert!(answer_h > 0, "answers visible");
        // The prompt text is present in its slice.
        let prompt = d.windowed_prompt_lines(d.prompt_region_lines(), compact, prompt_h);
        let joined: String = prompt
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(joined.contains("Pick one"), "prompt visible: {joined}");
    }

    #[test]
    fn split_regions_guarantees_minimums() {
        // Both want more than the body: each still gets its floor.
        let (p, a) = split_regions(8, 100, 100);
        assert!(p >= MIN_PROMPT_ROWS && a >= MIN_ANSWER_ROWS);
        assert_eq!(p + a, 8);
        // Tiny body: floors scale down but stay non-negative and sum exactly.
        let (p, a) = split_regions(2, 100, 100);
        assert_eq!(p + a, 2);
        // Short answer hands slack to the prompt; both still positive.
        let (p, a) = split_regions(12, 100, 2);
        assert_eq!(p + a, 12);
        assert!(a >= 2 && p >= MIN_PROMPT_ROWS);
        // Zero body -> zero, zero (no panic).
        assert_eq!(split_regions(0, 5, 5), (0, 0));
    }

    #[test]
    fn confirm_page_scrolls_when_long() {
        // A multi-question review with many questions overflows the body; the
        // confirm region scrolls with PageDown and shows `▲/▼ more`.
        let questions: Vec<InterruptQuestion> = (0..15)
            .map(|i| InterruptQuestion::Freetext {
                prompt: format!("Question number {i} with a reasonably long label"),
                masked: false,
            })
            .collect();
        let mut d = QuestionDialog::new(
            Uuid::new_v4(),
            String::new(),
            InterruptQuestionSet { questions },
            Duration::ZERO,
        );
        // Walk to the confirm page: answer each freetext, advancing right.
        for _ in 0..15 {
            d.handle_key(press(KeyCode::Char('x')));
            d.handle_key(press(KeyCode::Right));
        }
        assert!(d.state.on_confirm_page(), "reached the confirm page");
        let compact = Rect::new(0, 0, 60, 10);
        d.sync_viewport(compact, 24);
        assert!(
            d.state.prompt_overflows(),
            "long review overflows its region"
        );
        assert!(d.footer_hint().contains("pgup/pgdn: scroll"));
        // Scroll down; a leading `▲ more` marker appears.
        for _ in 0..3 {
            d.handle_key(press(KeyCode::PageDown));
        }
        assert!(d.state.prompt_scroll() > 0, "confirm region scrolled");
        let body = Rect::new(0, 0, 60, 7);
        let windowed = d.windowed_prompt_lines(d.render_confirm(), body, 7);
        let joined: String = windowed
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect::<String>();
        assert!(
            joined.contains("▲ more"),
            "confirm region shows a more marker"
        );
    }

    // ---- bash command-detail block --------------------------------------

    use crate::daemon::proto::{CharSpan, CommandDetail};

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    /// Build an approval-style dialog: one scope-select `Single` carrying a
    /// command-detail block.
    fn approval_dialog(detail: CommandDetail) -> QuestionDialog {
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Run `cd`?".into(),
                options: vec![
                    opt("once", "Yes, once"),
                    opt("session", "Yes, for this session"),
                ],
                allow_freetext: false,
                command_detail: Some(Box::new(detail)),
                // Bash approval = a permission interrupt (stripped
                // presentation: no marker, no free-text).
                permission: true,
                sandbox_escalation: None,
            }],
        };
        QuestionDialog::new(Uuid::new_v4(), String::new(), set, Duration::ZERO)
    }

    fn base_command_detail() -> CommandDetail {
        CommandDetail {
            full_command: "echo hi".into(),
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        }
    }

    fn line_texts(lines: &[Line<'_>]) -> Vec<String> {
        lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect()
    }

    fn tall_approval_dialog() -> QuestionDialog {
        let cmd: String = (0..200)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        approval_dialog(CommandDetail {
            full_command: cmd,
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        })
    }

    #[test]
    fn risk_tier_border_color_is_destructive_only_but_value_color_is_full_tier() {
        assert_eq!(risk_tier_border_color("ordinary"), None);
        assert_eq!(risk_tier_border_color("mutating"), None);
        assert_eq!(risk_tier_border_color("destructive"), Some(Color::Red));
        assert_eq!(risk_tier_border_color("privileged"), Some(Color::Red));
        assert_eq!(risk_tier_border_color("unknown"), None);

        assert_eq!(
            risk_tier_color("ordinary"),
            Some(Color::Indexed(MUTED_COLOR_INDEX))
        );
        assert_eq!(risk_tier_color("mutating"), Some(Color::Yellow));
        assert_eq!(risk_tier_color("destructive"), Some(Color::Red));
        assert_eq!(risk_tier_color("privileged"), Some(Color::Red));

        for (tier, expected) in [
            ("ordinary", None),
            ("mutating", None),
            ("destructive", Some(Color::Red)),
            ("privileged", Some(Color::Red)),
        ] {
            let mut detail = base_command_detail();
            detail.risk_tier = Some(tier.to_string());
            let d = approval_dialog(detail);
            assert_eq!(d.current_risk_color(), expected, "{tier}");
        }
    }

    #[test]
    fn is_approval_detects_permission_pages_without_command_detail() {
        let path_set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Allow read access to /tmp/x?".into(),
                options: vec![opt("once", "Approve once")],
                allow_freetext: false,
                command_detail: None,
                permission: true,
                sandbox_escalation: None,
            }],
        };
        assert!(dialog(path_set).is_approval());
        assert!(approval_dialog(base_command_detail()).is_approval());
        assert!(!dialog(single_q()).is_approval());
    }

    #[test]
    fn command_block_renders_cwd_remembered_key_and_sanitized_preview() {
        let mut detail = base_command_detail();
        detail.cwd = Some("/workspace/project".into());
        detail.remembered_key = Some("echo hi".into());
        detail.write_content = Some(crate::daemon::proto::WriteContentPreview {
            content: "safe\x1b[2Jbell\x07del\x7f\nnext".into(),
            dynamic: false,
        });
        let d = approval_dialog(detail);
        let lines = line_texts(&d.command_block_lines(d.command_detail().unwrap()));
        let joined = lines.join("\n");

        assert!(joined.contains("cwd: /workspace/project"));
        assert!(joined.contains("remembers: `echo hi`"));
        assert!(joined.contains("  safe[2Jbelldel"));
        assert!(joined.contains("  next"));
        assert!(!joined.chars().any(|ch| ch != '\n' && ch.is_control()));

        let mut detail = base_command_detail();
        detail.cwd = Some("/workspace/project".into());
        let d = approval_dialog(detail);
        let joined = line_texts(&d.command_block_lines(d.command_detail().unwrap())).join("\n");
        assert!(joined.contains("cwd: /workspace/project"));
        assert!(!joined.contains("remembers:"));
    }

    fn render_text(d: &QuestionDialog, area: Rect) -> String {
        render_lines(d, area).join("\n")
    }

    fn rendered_dialog_text(mut d: QuestionDialog, width: u16, height: u16) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| d.render(frame, Rect::new(0, 0, width, height)))
            .expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    #[test]
    fn approval_title_and_plain_question_title_diverge() {
        let d = approval_dialog(CommandDetail {
            full_command: "rm foo".into(),
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: Some("destructive".to_string()),
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        let text = rendered_dialog_text(d, 80, 14);
        assert!(text.contains(" approval "), "{text}");
        let q = QuestionDialog::new(
            Uuid::new_v4(),
            String::new(),
            InterruptQuestionSet {
                questions: vec![InterruptQuestion::Single {
                    prompt: "Pick?".into(),
                    options: vec![opt("a", "A")],
                    allow_freetext: true,
                    command_detail: None,
                    permission: false,
                    sandbox_escalation: None,
                }],
            },
            Duration::ZERO,
        );
        let text = rendered_dialog_text(q, 80, 10);
        assert!(text.contains(" question "), "{text}");
        assert!(!text.contains(" approval "), "{text}");
    }

    #[test]
    fn shows_heading_and_full_command_verbatim() {
        let d = approval_dialog(CommandDetail {
            full_command: "cd /home/christopher/secret-project".into(),
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        let area = Rect::new(0, 0, 80, 16);
        let text = render_text(&d, area);
        assert!(text.contains("Run `cd`?"), "heading unchanged");
        assert!(
            text.contains("cd /home/christopher/secret-project"),
            "full command shown verbatim: {text}"
        );
        // Single-constituent: no step indicator.
        assert!(
            !text.contains("step "),
            "no step indicator for a lone prompt"
        );
    }

    #[test]
    fn approval_command_block_shows_risk_effect_and_policy_metadata() {
        let d = approval_dialog(CommandDetail {
            full_command: "rm foo".into(),
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: Some("destructive".to_string()),
            risk_reasons: vec!["removes files".to_string()],
            affected_targets: vec!["foo".to_string()],
            native_tool_hints: vec!["Use `writeunlock` for durable writes.".to_string()],
            offered_scopes: vec!["once".to_string()],
            policy_cap: Some("once".to_string()),
        });
        let text = render_text(&d, Rect::new(0, 0, 90, 18));
        assert!(text.contains("risk: destructive"), "{text}");
        assert!(text.contains("reasons: removes files"), "{text}");
        assert!(text.contains("affected: foo"), "{text}");
        assert!(text.contains("scope cap: once"), "{text}");
        assert!(text.contains("hint: Use `writeunlock`"), "{text}");
    }

    #[test]
    fn compound_shows_step_indicator_and_highlight() {
        // `git push origin main && cargo build`, second step (cargo build),
        // highlight span over chars [24, 35).
        let cmd = "git push origin main && cargo build";
        let d = approval_dialog(CommandDetail {
            full_command: cmd.into(),
            highlight: Some(CharSpan { start: 24, end: 35 }),
            step: 2,
            step_count: 2,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        let cd = d.command_detail().unwrap().clone();
        let block = d.command_block_lines(&cd);
        let joined: String = block
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("step 2 of 2"), "step indicator: {joined}");
        assert!(joined.contains(cmd), "full command present");
        // The highlighted span renders as its own UNDERLINED span carrying
        // exactly "cargo build".
        let underlined: Vec<String> = block
            .iter()
            .flat_map(|l| l.spans.iter())
            .filter(|s| s.style.add_modifier.contains(Modifier::UNDERLINED))
            .map(|s| s.content.to_string())
            .collect();
        assert_eq!(
            underlined,
            vec!["cargo build".to_string()],
            "the current constituent is the highlighted slice"
        );
    }

    #[test]
    fn long_command_lives_in_scrollable_prompt_region() {
        // A 200-line heredoc-ish command renders in full inside the prompt
        // region (no separate command-block truncation); the region scrolls.
        let cmd: String = (0..200)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let d = approval_dialog(CommandDetail {
            full_command: cmd,
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        // The full command block carries every source line (1 per line).
        let cd = d.command_detail().unwrap().clone();
        let block = d.command_block_lines(&cd);
        assert_eq!(block.len(), 200, "every command line is rendered");
        // In a small overlay the prompt region overflows, so the footer
        // advertises both the whole-dialog expand and the prompt scroll.
        let mut d = d;
        d.sync_viewport(Rect::new(0, 0, 80, 16), 24);
        assert!(
            d.footer_hint().contains("ctrl+e: expand"),
            "expand hint: {}",
            d.footer_hint()
        );
        assert!(
            d.footer_hint().contains("pgup/pgdn: scroll"),
            "prompt-scroll hint when prompt overflows: {}",
            d.footer_hint()
        );
    }

    #[test]
    fn ctrl_e_expands_whole_dialog_upward() {
        // Ctrl+E grows the overlay's desired height beyond the collapsed cap
        // (it grows upward in place; the geometry shrinks history above it).
        let cmd: String = (0..200)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut d = approval_dialog(CommandDetail {
            full_command: cmd,
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        // Learn a terminal height so the expanded cap is computed.
        d.sync_viewport(Rect::new(0, 0, 80, 16), 40);
        let collapsed = d.desired_height();
        assert_eq!(collapsed, MAX_DIALOG_HEIGHT, "collapsed caps at the max");
        // Ctrl+E expands; the overlay now wants more than the collapsed cap.
        assert!(!d.handle_key(ctrl(KeyCode::Char('e'))));
        assert!(d.state.is_expanded());
        d.sync_viewport(Rect::new(0, 0, 80, 16), 40);
        assert!(
            d.desired_height() > MAX_DIALOG_HEIGHT,
            "expanded overlay grows past the collapsed cap"
        );
        // Footer flips to the collapse affordance.
        assert!(d.footer_hint().contains("ctrl+e: collapse"));
        // Ctrl+E again collapses back.
        assert!(!d.handle_key(ctrl(KeyCode::Char('e'))));
        assert!(!d.state.is_expanded());
        assert_eq!(d.desired_height(), MAX_DIALOG_HEIGHT);
    }

    #[test]
    fn expanded_cap_respects_short_terminal() {
        let mut d = tall_approval_dialog();
        d.sync_viewport(Rect::new(0, 0, 80, 10), 12);
        assert!(!d.handle_key(ctrl(KeyCode::Char('e'))));
        d.sync_viewport(Rect::new(0, 0, 80, 10), 12);

        let height = d.desired_height();
        let afford = 12 - STATUS_HEIGHT - MIN_HISTORY_HEIGHT;
        assert!(height <= afford, "height={height}, afford={afford}");
        assert!(height >= 1, "height={height}");
    }

    #[test]
    fn expanded_cap_tall_terminal_unchanged() {
        let mut d = tall_approval_dialog();
        d.sync_viewport(Rect::new(0, 0, 80, 16), 40);
        assert!(!d.handle_key(ctrl(KeyCode::Char('e'))));
        d.sync_viewport(Rect::new(0, 0, 80, 16), 40);

        let height = d.desired_height();
        assert_eq!(height, 40 * EXPANDED_HEIGHT_NUM / EXPANDED_HEIGHT_DEN);
        assert!(height >= MAX_DIALOG_HEIGHT);
    }

    #[test]
    fn collapsed_cap_respects_short_terminal() {
        let mut d = tall_approval_dialog();
        d.sync_viewport(Rect::new(0, 0, 80, 8), 10);

        let height = d.desired_height();
        let afford = 10 - STATUS_HEIGHT - MIN_HISTORY_HEIGHT;
        assert!(height <= afford, "height={height}, afford={afford}");
    }

    #[test]
    fn cap_zero_term_height_returns_max() {
        let mut d = tall_approval_dialog();
        assert!(!d.handle_key(ctrl(KeyCode::Char('e'))));

        assert!(d.desired_height() >= 4);
    }

    #[test]
    fn expanded_request_leaves_status_and_history() {
        let mut d = tall_approval_dialog();
        d.sync_viewport(Rect::new(0, 0, 80, 10), 12);
        assert!(!d.handle_key(ctrl(KeyCode::Char('e'))));
        d.sync_viewport(Rect::new(0, 0, 80, 10), 12);

        let geometry =
            crate::tui::geometry::PaneGeometry::compute(0, 0, 0, 0, 0, 0, 1, 0, d.desired_height());
        assert_eq!(geometry.status, STATUS_HEIGHT);
        assert!(geometry.history >= MIN_HISTORY_HEIGHT);
        assert!(geometry.compact + geometry.status + geometry.history <= 12);
    }

    #[test]
    fn tiny_terminal_no_panic_height_request_is_affordable() {
        let mut d = tall_approval_dialog();
        d.sync_viewport(Rect::new(0, 0, 80, 3), 5);
        assert!(!d.handle_key(ctrl(KeyCode::Char('e'))));
        d.sync_viewport(Rect::new(0, 0, 80, 3), 5);

        assert!(d.desired_height() + STATUS_HEIGHT + MIN_HISTORY_HEIGHT <= 5);
    }

    #[test]
    fn pagedown_scrolls_prompt_region() {
        // PageDown scrolls the prompt region; later command lines come into
        // view, with a leading `▲ more` once scrolled.
        let cmd: String = (0..200)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut d = approval_dialog(CommandDetail {
            full_command: cmd,
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        let area = Rect::new(0, 0, 80, 16);
        d.sync_viewport(area, 24);
        assert_eq!(d.state.prompt_scroll(), 0);
        for _ in 0..5 {
            d.handle_key(press(KeyCode::PageDown));
        }
        assert_eq!(
            d.state.prompt_scroll(),
            5,
            "PageDown advances prompt scroll"
        );
        // Render the prompt region windowed; the leading marker shows.
        let body = Rect::new(0, 0, 80, 13);
        let windowed = d.windowed_prompt_lines(d.prompt_region_lines(), body, 13);
        let joined: String = windowed
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("▲ more"),
            "leading more marker once scrolled"
        );
    }

    #[test]
    fn expand_and_scroll_keys_do_not_leak_to_option_navigation() {
        // Ctrl+E and PageUp/PageDown must not move the option cursor or submit.
        let mut d = approval_dialog(CommandDetail {
            full_command: (0..50)
                .map(|i| format!("l{i}"))
                .collect::<Vec<_>>()
                .join("\n"),
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        d.sync_viewport(Rect::new(0, 0, 80, 16), 24);
        let before = d.state.cursor();
        assert!(!d.handle_key(ctrl(KeyCode::Char('e'))));
        assert!(!d.handle_key(press(KeyCode::PageDown)));
        assert!(!d.handle_key(press(KeyCode::PageUp)));
        assert_eq!(
            d.state.cursor(),
            before,
            "expand/scroll keys never move the option cursor"
        );
        assert!(
            d.take_result().is_none(),
            "no submit/cancel from expand/scroll keys"
        );
    }

    #[test]
    fn non_approval_question_has_no_command_block() {
        // A plain question (no command_detail) renders no command block.
        let d = dialog(single_q());
        assert!(d.command_detail().is_none());
        assert!(d.prompt_region_lines().iter().all(|l| {
            !l.spans
                .iter()
                .any(|s| s.content.contains("step ") || s.content.contains("&&"))
        }));
        // A short question fits collapsed: no expand affordance in the footer.
        assert!(!d.footer_hint().contains("ctrl+e"));
    }

    // ---- permission-prompt presentation (no marker, no freeform) --------

    #[test]
    fn permission_prompt_shows_radio_marker_and_drops_freeform_row() {
        let d = approval_dialog(CommandDetail {
            full_command: "rm -rf /tmp/x".into(),
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        let area = Rect::new(0, 0, 80, 16);
        let text = render_text(&d, area);
        assert!(
            text.contains("( )"),
            "selection marker is visible on a permission prompt"
        );
        assert!(
            !text.contains(CUSTOM_LABEL),
            "no `Type your own answer` row on a permission prompt: {text}"
        );
        // Numbered prefixes + labels survive.
        assert!(
            text.contains("1. ( ) Yes, once"),
            "numbered prefix kept: {text}"
        );
        assert!(text.contains("2. ( ) Yes, for this session"));
    }

    #[test]
    fn permission_prompt_has_no_custom_cursor_slot() {
        // The custom affordance is unreachable: the cursor cycles only
        // through the two options (count == options.len(), not +1).
        let mut d = approval_dialog(CommandDetail {
            full_command: "ls".into(),
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        // Two options -> cursor wraps 0,1,0 (no third "custom" slot).
        assert_eq!(d.state.cursor(), 0);
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.state.cursor(), 1);
        d.handle_key(press(KeyCode::Down));
        assert_eq!(
            d.state.cursor(),
            0,
            "wraps past the last option, no custom row"
        );
        // Typing never engages on a permission prompt.
        d.handle_key(press(KeyCode::Char(' ')));
        assert!(
            !d.state.is_typing(),
            "space never enters typing on a permission prompt"
        );
    }

    #[test]
    fn permission_prompt_number_key_selects_and_enter_chooses() {
        // Deny/cancel and quick-select still work: Esc denies, a number key
        // picks + submits.
        let mut d = approval_dialog(CommandDetail {
            full_command: "ls".into(),
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        assert!(!d.handle_key(press(KeyCode::Char('2'))));
        assert!(d.take_result().is_none(), "number key only selects");
        assert!(d.handle_key(press(KeyCode::Enter)), "Enter confirms");
        match d.take_result() {
            Some(QuestionResult::Submit { responses, .. }) => assert!(matches!(
                responses.as_slice(),
                [ResolveResponse::Single { selected_id }] if selected_id == "session"
            )),
            other => panic!("expected Submit, got {other:?}"),
        }
    }

    #[test]
    fn question_prompt_keeps_radio_and_freeform_row() {
        // The default (question) presentation is unchanged: radio markers
        // and the `Type your own answer` row both render.
        let d = dialog(single_q());
        let area = Rect::new(0, 0, 60, 12);
        let text = render_text(&d, area);
        assert!(
            text.contains("(•)") || text.contains("( )"),
            "radio marker kept: {text}"
        );
        assert!(
            text.contains(CUSTOM_LABEL),
            "freeform row kept on an agent question: {text}"
        );
    }

    #[test]
    fn highlight_span_slices_multibyte_correctly() {
        // `echo héllo && rm x`: highlight the second constituent "rm x" at
        // char span [14, 18). The `é` is multi-byte but char-indexed spans
        // must still slice exactly "rm x".
        let cmd = "echo héllo && rm x";
        let d = approval_dialog(CommandDetail {
            full_command: cmd.into(),
            highlight: Some(CharSpan { start: 14, end: 18 }),
            step: 2,
            step_count: 2,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        let cd = d.command_detail().unwrap().clone();
        let block = d.command_block_lines(&cd);
        let underlined: Vec<String> = block
            .iter()
            .flat_map(|l| l.spans.iter())
            .filter(|s| s.style.add_modifier.contains(Modifier::UNDERLINED))
            .map(|s| s.content.to_string())
            .collect();
        assert_eq!(underlined, vec!["rm x".to_string()]);
    }

    // ---- sandbox-escalation dialog variant ------------------------------

    /// Build the distinct escalation-variant dialog: a scope-select `Single`
    /// reframed for the run-fail-escalate path, carrying the confined exit +
    /// stderr.
    fn escalation_dialog(esc: SandboxEscalation, rememberable: bool) -> QuestionDialog {
        let options = if rememberable {
            vec![
                opt("once", "Yes, once"),
                opt("session", "Yes, for this session"),
            ]
        } else {
            vec![opt("once", "Yes, once")]
        };
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "`cat` failed while sandboxed. Re-run it without the sandbox?".into(),
                options,
                allow_freetext: false,
                command_detail: Some(Box::new(CommandDetail {
                    full_command: "cat /etc/secret".into(),
                    highlight: None,
                    step: 1,
                    step_count: 1,
                    cwd: None,
                    remembered_key: None,
                    write_content: None,
                    risk_tier: None,
                    risk_reasons: Vec::new(),
                    affected_targets: Vec::new(),
                    native_tool_hints: Vec::new(),
                    offered_scopes: Vec::new(),
                    policy_cap: None,
                })),
                permission: true,
                sandbox_escalation: Some(esc),
            }],
        };
        QuestionDialog::new(Uuid::new_v4(), String::new(), set, Duration::ZERO)
    }

    #[test]
    fn escalation_variant_renders_honest_framing_and_confined_detail() {
        let d = escalation_dialog(
            SandboxEscalation {
                confined_exit: 13,
                confined_stderr: "cat: /etc/secret: Permission denied".into(),
            },
            true,
        );
        let area = Rect::new(0, 0, 80, 30);
        let text = render_text(&d, area);
        // Honest framing — failed WHILE sandboxed, never "blocked by".
        assert!(text.contains("failed while sandboxed"), "framing: {text}");
        assert!(text.contains("can't be confirmed"), "honesty: {text}");
        assert!(
            !text.to_lowercase().contains("blocked by the sandbox"),
            "must not assert the sandbox blocked it: {text}"
        );
        // Confined failure detail.
        assert!(text.contains("confined exit: 13"), "exit shown: {text}");
        assert!(text.contains("Permission denied"), "stderr shown: {text}");
        // The ask + cascade warning.
        assert!(
            text.contains("WITHOUT the sandbox"),
            "the ask is the unconfined re-run: {text}"
        );
        assert!(
            text.contains("skip the sandbox silently"),
            "cascade warning for remembered scopes: {text}"
        );
    }

    #[test]
    fn escalation_wrapper_variant_says_once_only() {
        let d = escalation_dialog(
            SandboxEscalation {
                confined_exit: 1,
                confined_stderr: String::new(),
            },
            false,
        );
        let area = Rect::new(0, 0, 80, 30);
        let text = render_text(&d, area);
        assert!(
            text.contains("can't be remembered"),
            "wrapper cascade note: {text}"
        );
        assert!(text.contains("once only"), "once-only for wrapper: {text}");
    }

    #[test]
    fn first_time_approval_has_no_escalation_block() {
        // A fresh approval (no prior confined failure) keeps its current
        // wording: no escalation framing, no confined-exit line.
        let d = approval_dialog(CommandDetail {
            full_command: "cargo build".into(),
            highlight: None,
            step: 1,
            step_count: 1,
            cwd: None,
            remembered_key: None,
            write_content: None,
            risk_tier: None,
            risk_reasons: Vec::new(),
            affected_targets: Vec::new(),
            native_tool_hints: Vec::new(),
            offered_scopes: Vec::new(),
            policy_cap: None,
        });
        assert!(d.sandbox_escalation().is_none());
        let area = Rect::new(0, 0, 80, 20);
        let text = render_text(&d, area);
        assert!(!text.contains("failed while sandboxed"));
        assert!(!text.contains("confined exit"));
    }
}
