#![allow(dead_code)]
//! Reusable answering dialog (GOALS §3b).
//!
//! A modal that **replaces the composer** and walks the user through a
//! sequence of selectable pages ending in a confirm/submit page. The
//! `question` tool wires it today; a later tool-approval prompt reuses
//! the same core without touching it.
//!
//! ## What is generic vs. question-specific
//!
//! The state machine here ([`DialogState`]) knows nothing about
//! questions, proto types, or the daemon. It owns:
//!   - a `Vec<Page>` of [`Select`](PageKind::Select) /
//!     [`Multiselect`](PageKind::Multiselect) / [`Text`](PageKind::Text)
//!     pages, plus an implicit final confirm/submit page,
//!   - the cursor + selection + custom-text-typing state per page,
//!   - page-to-page navigation, validation, the anti-misfire lockout,
//!     and dismissal.
//!
//! On submit it yields a `Vec<`[`Answer`]`>` — one per page, in order —
//! which the *caller* maps to whatever resolution its use-case needs
//! (the `question` tool maps them to `ResolveResponse`s; a tool-approval
//! prompt would map them to an approve/deny decision). That `Answer →
//! resolution` mapping is the only question-specific code, and it lives
//! outside this module (`super::dialog::question`). That is the seam
//! that keeps the core reusable.
//!
//! The render + App-overlay glue is intentionally separate too
//! ([`super::dialog::question::QuestionDialog`]), so a second use-case
//! gets its own thin wrapper over this same state machine.

pub mod question;

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent};

use crate::tui::pane::ScrollList;
use crate::tui::textfield::TextField;

/// One proposed option on a select / multiselect page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialogOption {
    pub id: String,
    pub label: String,
    /// Optional one-line description rendered dimmed under the label.
    /// `None` renders exactly as a label-only option (back-compat).
    pub description: Option<String>,
    pub secondary: bool,
}

impl DialogOption {
    /// Label-only option (no description). Convenience for call sites
    /// (e.g. approval) that never annotate options.
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            description: None,
            secondary: false,
        }
    }
}

/// What a page asks for. The variants mirror the three answer modes; a
/// future use-case could add more without the navigation core caring.
#[derive(Debug, Clone)]
pub enum PageKind {
    /// Choose exactly one option (radio). Toggling a new option clears
    /// the previous selection.
    Select,
    /// Choose any number of options (checkboxes), independently.
    Multiselect,
    /// Free-text only; no option list.
    Text,
}

/// One page of the dialog: a prompt plus its answer mode and options.
#[derive(Debug, Clone)]
pub struct Page {
    pub prompt: String,
    pub kind: PageKind,
    pub options: Vec<DialogOption>,
    secondary_options: Vec<DialogOption>,
    /// Presentation: when `true` this page is rendered in the stripped
    /// **permission/approval** style — no free-text custom affordance.
    /// Default `false` keeps the question
    /// presentation exactly as before. Set only by the approval callers (the
    /// scope dialog and any tool-permission interrupt); every other caller
    /// leaves it at its default.
    pub permission: bool,
    /// Whether select/multiselect pages expose the free-text custom row.
    /// This is protocol/user-intent state, separate from permission styling;
    /// approval pages force it off via [`Self::permission`].
    allow_custom: bool,
    /// Presentation-only: text entry renders a fixed mask instead of the
    /// literal typed value. The collected answer remains the original text.
    masked_text: bool,
}

impl Page {
    pub fn select(prompt: impl Into<String>, options: Vec<DialogOption>) -> Self {
        Self {
            prompt: prompt.into(),
            kind: PageKind::Select,
            options,
            secondary_options: Vec::new(),
            permission: false,
            allow_custom: true,
            masked_text: false,
        }
    }

    pub fn multiselect(prompt: impl Into<String>, options: Vec<DialogOption>) -> Self {
        Self {
            prompt: prompt.into(),
            kind: PageKind::Multiselect,
            options,
            secondary_options: Vec::new(),
            permission: false,
            allow_custom: true,
            masked_text: false,
        }
    }

    pub fn text(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            kind: PageKind::Text,
            options: Vec::new(),
            secondary_options: Vec::new(),
            permission: false,
            allow_custom: false,
            masked_text: false,
        }
    }

    pub fn text_masked(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            kind: PageKind::Text,
            options: Vec::new(),
            secondary_options: Vec::new(),
            permission: false,
            allow_custom: false,
            masked_text: true,
        }
    }

    pub fn masked_text(&self) -> bool {
        self.masked_text
    }

    /// Mark this page as a permission/approval page (stripped presentation:
    /// no selection marker, no free-text custom row). Chainable on any
    /// `select` page. Multiselect/text pages are never permission prompts.
    pub fn permission(mut self) -> Self {
        self.permission = true;
        self.allow_custom = false;
        self
    }

    pub fn allow_custom(mut self, allow: bool) -> Self {
        self.allow_custom = allow;
        self
    }

    pub fn with_secondary_options(mut self, options: Vec<DialogOption>) -> Self {
        self.secondary_options = options;
        self
    }

    fn is_text(&self) -> bool {
        matches!(self.kind, PageKind::Text)
    }

    fn is_select(&self) -> bool {
        matches!(self.kind, PageKind::Select)
    }

    /// True for a radio (`select`) page. Public so the renderer can pick
    /// the radio vs. checkbox glyph.
    pub fn kind_is_select(&self) -> bool {
        self.is_select()
    }

    fn is_multiselect(&self) -> bool {
        matches!(self.kind, PageKind::Multiselect)
    }

    /// Whether this page exposes the free-text "Type your own answer"
    /// affordance. Permission pages suppress it entirely; select/multiselect
    /// pages honor the page's explicit custom-answer flag. `text` pages have
    /// no separate custom affordance (the page *is* the field).
    pub fn has_custom(&self) -> bool {
        !self.is_text() && !self.permission && self.allow_custom
    }

    /// Cursor positions on this page. A `text` page has a single
    /// position (its input). Select and multiselect pages are
    /// `[options…] ([custom])`. A permission page drops the custom
    /// affordance (`[options…]` only).
    fn cursor_count(&self) -> usize {
        if self.is_text() {
            1
        } else if self.has_custom() {
            self.options.len() + 1
        } else {
            self.options.len()
        }
    }

    /// Index of the always-last "Type your own answer" affordance on a
    /// select/multiselect page, or `None` when the page suppresses it
    /// (permission pages). When present it is the row after the options.
    fn custom_index(&self) -> Option<usize> {
        if self.has_custom() {
            Some(self.options.len())
        } else {
            None
        }
    }
}

/// Per-page answer state the user has built so far.
#[derive(Debug, Clone, Default)]
struct PageState {
    /// Selected option ids (radio keeps ≤1; multiselect any number).
    selected: Vec<String>,
    /// The custom / free-text the user typed. For a `text` page this is
    /// the whole answer; for select/multiselect it's the additive
    /// "Type your own answer" value.
    custom: TextField,
}

/// The resolved answer for one page, handed back to the caller on
/// submit. Caller-agnostic — the question wiring maps these to proto
/// `ResolveResponse`s; a different use-case maps them differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// A single chosen option id (select fast-path / radio).
    Single { id: String },
    /// Any number of chosen option ids plus an optional additive
    /// free-text answer (multiselect).
    Multi {
        ids: Vec<String>,
        custom: Option<String>,
    },
    /// A free-text answer (text page, or a select whose only answer was
    /// the custom field).
    Text { text: String },
}

/// Outcome of [`DialogState::handle_key`] — what the overlay host (the
/// TUI `App`) should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialogOutcome {
    /// Stay open; redraw.
    Continue,
    /// User submitted from the confirm page. One [`Answer`] per page, in
    /// order.
    Submit(Vec<Answer>),
    /// User dismissed (Esc). Caller resolves as a cancel.
    Cancel,
}

/// The reusable dialog state machine. Terminal-free and fully testable.
pub struct DialogState {
    pages: Vec<Page>,
    page_states: Vec<PageState>,
    /// Current page index. Equals `pages.len()` on the confirm page.
    page: usize,
    /// Cursor within the current page plus answer-list scroll.
    list: ScrollList,
    /// True while the user is editing the custom / free-text field of
    /// the current page (keystrokes go to the field, not to navigation).
    typing: bool,
    /// When the dialog was created. The anti-misfire lockout runs from
    /// here.
    created_at: Instant,
    lockout: Duration,
    /// Max visible rows the renderer last reported from the physical answer
    /// region. Zero means "unbounded" (no scrolling) until the renderer
    /// reports a cap.
    viewport: usize,
    /// First visible line of the **prompt region** (interrupt description +
    /// question prompt + any command-detail block). The answer region above
    /// uses `scroll`; this independently bounds the prompt region so neither
    /// can fully hide the other. Scrolled with PageUp/PageDown; clamped
    /// against the metrics the renderer reports each frame.
    prompt_scroll: usize,
    /// Total wrapped lines the prompt region wants, as the renderer last
    /// measured it. Drives the prompt-region scroll clamp + "more" markers.
    prompt_lines: usize,
    /// Visible lines the prompt region was last allotted. Zero until the
    /// renderer reports it; the prompt region never scrolls while unbounded.
    prompt_viewport: usize,
    /// Whether the whole dialog is expanded (grown taller in place). Set by
    /// the host's Ctrl+E binding; the renderer reads it to allocate more
    /// height to both regions. Shared here so every DialogState renderer
    /// (question + approval) gets the same toggle.
    expanded: bool,
}

impl DialogState {
    /// The "no lockout" primitive: a dialog built with this `lockout`
    /// opens immediately interactive ([`Self::locked`] is false from
    /// `t=0`). Used for a dialog that directly succeeds another without the
    /// composer ever regaining focus, so the anti-misfire guard — which
    /// only exists to absorb an in-flight composer keystroke on the
    /// composer→dialog edge — must not re-apply
    /// (implementation note). This is a real,
    /// non-test path; the test-only `new_at` seam is distinct.
    pub const NO_LOCKOUT: Duration = Duration::ZERO;

    /// Build the state machine for `pages` with an anti-misfire
    /// `lockout`. `pages` must be non-empty (a dialog with no questions
    /// is a programming error at the call site). Pass [`Self::NO_LOCKOUT`]
    /// to open immediately interactive (a direct dialog→dialog
    /// continuation).
    pub fn new(pages: Vec<Page>, lockout: Duration) -> Self {
        let page_states = pages.iter().map(|_| PageState::default()).collect();
        // A freetext page opens directly in typing mode (the spec: no
        // space/enter to start). Input is still gated by the lockout in
        // `handle_key`, so this only takes effect once the dialog is
        // interactive.
        let typing = pages.first().map(Page::is_text).unwrap_or(false);
        Self {
            pages,
            page_states,
            page: 0,
            list: ScrollList::new(),
            typing,
            created_at: Instant::now(),
            lockout,
            viewport: 0,
            prompt_scroll: 0,
            prompt_lines: 0,
            prompt_viewport: 0,
            expanded: false,
        }
    }

    /// Build the state machine with each page's checkboxes/radios
    /// pre-selected from `preselected[page]` (ids must exist among that
    /// page's options; unknown ids are ignored). Used by callers that open a
    /// multiselect reflecting current state (e.g. `/toggle-redaction`). A
    /// `preselected` shorter than `pages` leaves the trailing pages empty.
    pub fn new_preselected(
        pages: Vec<Page>,
        lockout: Duration,
        preselected: &[Vec<String>],
    ) -> Self {
        let mut state = Self::new(pages, lockout);
        for (page_idx, ids) in preselected.iter().enumerate() {
            let Some(ps) = state.page_states.get_mut(page_idx) else {
                break;
            };
            let valid: Vec<String> = ids
                .iter()
                .filter(|id| state.pages[page_idx].options.iter().any(|o| &o.id == *id))
                .cloned()
                .collect();
            ps.selected = valid;
        }
        state
    }

    /// Test seam: build with an explicit creation instant so the lockout
    /// can be exercised deterministically.
    #[cfg(test)]
    fn new_at(pages: Vec<Page>, lockout: Duration, created_at: Instant) -> Self {
        let mut s = Self::new(pages, lockout);
        s.created_at = created_at;
        s
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn current_page(&self) -> usize {
        self.page
    }

    pub fn cursor(&self) -> usize {
        self.list.cursor()
    }

    pub fn is_typing(&self) -> bool {
        self.typing
    }

    pub fn pages(&self) -> &[Page] {
        &self.pages
    }

    /// True while the dialog is in its non-interactive lockout window.
    /// The host renders a grey border and ignores input until this
    /// returns false (then: white border, interactive). A dialog built
    /// with [`Self::NO_LOCKOUT`] returns false here from `t=0` (elapsed
    /// time is never `< 0`).
    pub fn locked(&self) -> bool {
        self.created_at.elapsed() < self.lockout
    }

    /// True when the confirm page is showing.
    pub fn on_confirm_page(&self) -> bool {
        self.page == self.pages.len()
    }

    /// Whether each page has a usable answer. Drives the confirm page's
    /// "unanswered" flags and gates submit.
    pub fn answered_flags(&self) -> Vec<bool> {
        (0..self.pages.len()).map(|i| self.is_answered(i)).collect()
    }

    fn is_answered(&self, page: usize) -> bool {
        let st = &self.page_states[page];
        match self.pages[page].kind {
            PageKind::Text => !st.custom.text().trim().is_empty(),
            PageKind::Select => !st.selected.is_empty() || !st.custom.text().trim().is_empty(),
            PageKind::Multiselect => true,
        }
    }

    fn all_answered(&self) -> bool {
        (0..self.pages.len()).all(|i| self.is_answered(i))
    }

    /// Read the selected ids on `page` (for rendering check marks).
    pub fn selected_ids(&self, page: usize) -> &[String] {
        &self.page_states[page].selected
    }

    /// Read the custom-text buffer on `page` (for rendering + cursor).
    pub fn custom_text(&self, page: usize) -> &str {
        self.page_states[page].custom.text()
    }

    /// Display-column of the caret within the custom/free-text field on
    /// `page` (rendered width in terminal cells, not chars/bytes). Used to
    /// park the real terminal cursor so it lines up with multi-byte / wide
    /// input.
    pub fn custom_cursor_display_col(&self, page: usize) -> usize {
        self.page_states[page].custom.cursor_display_col()
    }

    /// First visible row index for the current page's option list. The
    /// renderer skips rows before this when the list is taller than the
    /// viewport.
    pub fn scroll(&self) -> usize {
        self.list.scroll()
    }

    /// Visible option rows the renderer last reported.
    /// Zero before the first viewport sync.
    pub fn viewport(&self) -> usize {
        self.viewport
    }

    /// Tell the core how many option rows the renderer can physically show at
    /// once after line-accounting for multi-line rows, and clamp scroll so the
    /// focused cursor stays in view. Called from the renderer each frame with
    /// the height it computed.
    pub fn set_viewport(&mut self, rows: usize) {
        self.viewport = rows;
        self.clamp_scroll();
    }

    /// Keep `scroll` so the focused `cursor` row stays visible with a
    /// symmetric 1-row scroll margin (vim `scrolloff=1`): whenever an option
    /// exists on a side, the option immediately past the cursor in that
    /// direction stays on screen. At the list boundaries (first/last option)
    /// the cursor may sit flush against that edge. No-op when the viewport is
    /// unbounded (`0`), the page has no option list, or the list fully fits.
    ///
    /// The margin degrades gracefully on tiny viewports (1–2 rows) where a
    /// symmetric margin can't fit: the focused cursor is always kept visible
    /// (clamping the cursor into the window wins over honoring the margin).
    fn clamp_scroll(&mut self) {
        if self.viewport == 0 || self.on_confirm_page() {
            self.list.set_scroll(0);
            return;
        }
        let total = self.pages[self.page].cursor_count();
        if total <= self.viewport {
            self.list.set_scroll(0);
            return;
        }
        // Desired 1-row margin, shrunk to fit the viewport: with a window of
        // `viewport` rows we need at least `2*margin + 1` rows to honor a
        // symmetric `margin`, so cap it at `(viewport - 1) / 2`. For
        // viewport >= 3 this is the full 1-row margin; for 1–2 rows it
        // degrades to 0 (cursor kept flush but always visible).
        let margin = 1.min((self.viewport.saturating_sub(1)) / 2);
        // Top edge: keep `margin` rows above the cursor, but never scroll
        // past the first option.
        let want_top = self.list.cursor().saturating_sub(margin);
        if want_top < self.list.scroll() {
            self.list.set_scroll(want_top);
        }
        // Bottom edge: keep `margin` rows below the cursor, but never scroll
        // past the last option.
        let want_bottom = (self.list.cursor() + margin).min(total.saturating_sub(1));
        if want_bottom >= self.list.scroll() + self.viewport {
            self.list.set_scroll(want_bottom + 1 - self.viewport);
        }
        let max_scroll = total.saturating_sub(self.viewport);
        if self.list.scroll() > max_scroll {
            self.list.set_scroll(max_scroll);
        }
    }

    /// Whether the whole dialog is expanded (grown taller in place).
    pub fn is_expanded(&self) -> bool {
        self.expanded
    }

    /// Toggle the whole-dialog expand state (the host's `Ctrl+E`). On
    /// collapse the prompt-region scroll resets so the prompt re-anchors at
    /// the top.
    pub fn toggle_expanded(&mut self) {
        self.expanded = !self.expanded;
        if !self.expanded {
            self.prompt_scroll = 0;
        }
    }

    /// First visible line of the prompt region. The renderer skips lines
    /// before this when the prompt overflows its slice.
    pub fn prompt_scroll(&self) -> usize {
        self.prompt_scroll
    }

    /// Tell the core how tall the prompt region's content is (`total`) and
    /// how many lines it can show at once (`viewport`), and clamp the
    /// prompt scroll. Called from the renderer each frame.
    pub fn set_prompt_metrics(&mut self, total: usize, viewport: usize) {
        self.prompt_lines = total;
        self.prompt_viewport = viewport;
        self.clamp_prompt_scroll();
    }

    /// Whether the prompt region overflows its allotted slice (so the
    /// renderer should draw `▲/▼ more` and the footer should advertise the
    /// prompt-scroll keys).
    pub fn prompt_overflows(&self) -> bool {
        self.prompt_viewport > 0 && self.prompt_lines > self.prompt_viewport
    }

    /// Scroll the prompt region by `delta` lines (PageUp/PageDown),
    /// clamped to its content.
    pub fn scroll_prompt(&mut self, delta: i32) {
        let max = self
            .prompt_lines
            .saturating_sub(self.prompt_viewport.max(1));
        let next = (self.prompt_scroll as i32 + delta).clamp(0, max as i32);
        self.prompt_scroll = next as usize;
    }

    /// Keep the prompt scroll within `[0, prompt_lines - prompt_viewport]`.
    fn clamp_prompt_scroll(&mut self) {
        if self.prompt_viewport == 0 || self.prompt_lines <= self.prompt_viewport {
            self.prompt_scroll = 0;
            return;
        }
        let max = self.prompt_lines - self.prompt_viewport;
        if self.prompt_scroll > max {
            self.prompt_scroll = max;
        }
    }

    /// Insert pasted text into the focused custom / free-text field,
    /// mirroring the text-affecting branch of [`handle_typing_key`]: a text
    /// page resumes editing, a select page clears any radio choice, and the
    /// text is inserted into that page's custom field. Ignored while
    /// [`locked`](Self::locked) or when no field is focusable (no custom
    /// field is shown on the confirm page or while browsing options).
    pub fn paste(&mut self, text: &str) {
        if self.locked() {
            return;
        }
        if self.on_confirm_page() {
            return;
        }
        // A text page that isn't currently in typing mode resumes editing on
        // any text-affecting input (see `handle_page_key`).
        if self.pages[self.page].is_text() {
            self.typing = true;
        }
        if !self.typing {
            return;
        }
        // Match the typing path: typing a custom answer on a single-select
        // page is mutually exclusive with the radio options.
        if self.pages[self.page].is_select() {
            self.page_states[self.page].selected.clear();
        }
        self.page_states[self.page].custom.paste(text);
    }

    /// Apply a key. Returns the outcome the host acts on. Input is
    /// ignored (returns `Continue`) while [`locked`](Self::locked).
    pub fn handle_key(&mut self, key: KeyEvent) -> DialogOutcome {
        if self.locked() {
            return DialogOutcome::Continue;
        }
        // Uniform Esc escalation: a first Esc while typing leaves typing
        // mode (keeping the dialog open and the typed text intact); a
        // subsequent Esc — once typing is off — cancels. On a freetext
        // page this defocuses the field (the next text-affecting key
        // resumes editing, per `handle_page_key`); on a select/multiselect
        // custom field it returns focus to the option list.
        if matches!(key.code, KeyCode::Esc) {
            if self.typing {
                self.typing = false;
                return DialogOutcome::Continue;
            }
            return DialogOutcome::Cancel;
        }
        if self.typing {
            return self.handle_typing_key(key);
        }
        if self.on_confirm_page() {
            return self.handle_confirm_key(key);
        }
        self.handle_page_key(key)
    }

    /// Keys while editing a custom / free-text field.
    fn handle_typing_key(&mut self, key: KeyEvent) -> DialogOutcome {
        // On a freetext page (which opens directly in typing mode),
        // Left/Right at the field boundary step between questions — the
        // only way to leave a text field for a sibling question. Inside
        // the text they move the field cursor as usual.
        if self.pages[self.page].is_text() && self.page_count() > 1 {
            let col = self.page_states[self.page].custom.cursor();
            let len = self.page_states[self.page].custom.text().len();
            if matches!(key.code, KeyCode::Left) && col == 0 {
                return self.prev_page();
            }
            if matches!(key.code, KeyCode::Right) && col == len {
                return self.next_page();
            }
        }
        match key.code {
            KeyCode::Enter => {
                let page = &self.pages[self.page];
                if page.is_text() {
                    // Freetext question: Enter submits/advances (lone
                    // question fast-paths; otherwise step to the next
                    // page / review).
                    return self.fast_path_submit_or_advance();
                }
                // Select/multiselect custom field: Enter commits the typed
                // answer and advances when it supplies an answer.
                self.typing = false;
                if self.page_states[self.page].custom.text().trim().is_empty() {
                    return DialogOutcome::Continue;
                }
                self.fast_path_submit_or_advance()
            }
            _ => {
                // On a single-select page, typing the custom answer is
                // mutually exclusive with the radio options — clear any
                // radio choice as soon as the user types.
                if self.pages[self.page].is_select() {
                    self.page_states[self.page].selected.clear();
                }
                self.page_states[self.page].custom.handle_key(key);
                DialogOutcome::Continue
            }
        }
    }

    /// Keys on a select / multiselect / text page (not typing).
    fn handle_page_key(&mut self, key: KeyEvent) -> DialogOutcome {
        let page = &self.pages[self.page];
        // `text` pages open directly in typing mode (see `new`/`next_page`),
        // so `handle_typing_key` owns them. Reaching here means typing was
        // toggled off with Enter; restore it on the next text-affecting key,
        // and allow page navigation in a multi-question wizard.
        if page.is_text() {
            return match key.code {
                KeyCode::Left | KeyCode::Char('h') => self.prev_page(),
                KeyCode::Right | KeyCode::Char('l') => self.next_page(),
                _ => {
                    // Any other key resumes editing the field.
                    self.typing = true;
                    self.handle_typing_key(key)
                }
            };
        }

        // Number-key instant-select (1–9): target that option directly.
        if let KeyCode::Char(c) = key.code
            && let Some(d) = c.to_digit(10)
            && (1..=9).contains(&d)
        {
            let idx = (d - 1) as usize;
            if idx < page.options.len() {
                return self.number_select(idx);
            }
            return DialogOutcome::Continue;
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_cursor(-1);
                DialogOutcome::Continue
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_cursor(1);
                DialogOutcome::Continue
            }
            KeyCode::Left | KeyCode::Char('h') => self.prev_page(),
            KeyCode::Right | KeyCode::Char('l') => self.next_page(),
            KeyCode::Char(' ') => {
                self.toggle_or_type();
                DialogOutcome::Continue
            }
            KeyCode::Enter => self.enter_on_page(),
            _ => DialogOutcome::Continue,
        }
    }

    /// A number key targeted option `idx`. Single-select: select it and
    /// advance (instant-accept). Multi-select: toggle it, no advance.
    fn number_select(&mut self, idx: usize) -> DialogOutcome {
        if self.pages[self.page].permission
            && self.pages[self.page].options[idx].id == cockpit_core::approval::ID_MORE_OPTIONS
        {
            return self.reveal_secondary_options();
        }
        let id = self.pages[self.page].options[idx].id.clone();
        let is_select = self.pages[self.page].is_select();
        let permission = self.pages[self.page].permission;
        if is_select {
            self.list.set_cursor(idx);
            self.clamp_scroll();
            let st = &mut self.page_states[self.page];
            // Radio + custom are mutually exclusive: choosing a radio
            // clears any typed custom answer.
            st.selected = vec![id];
            st.custom.set("");
            if permission {
                DialogOutcome::Continue
            } else {
                self.fast_path_submit_or_advance()
            }
        } else {
            let st = &mut self.page_states[self.page];
            if let Some(pos) = st.selected.iter().position(|s| *s == id) {
                st.selected.remove(pos);
            } else {
                st.selected.push(id);
            }
            self.list.set_cursor(idx);
            self.clamp_scroll();
            DialogOutcome::Continue
        }
    }

    /// Space on a page: toggle the hovered option, or enter typing mode
    /// on the custom affordance.
    fn toggle_or_type(&mut self) {
        let page = &self.pages[self.page];
        if Some(self.list.cursor()) == page.custom_index() {
            // Hovering "Type your own answer": space begins typing.
            self.begin_custom_typing();
            return;
        }
        let Some(option) = page.options.get(self.list.cursor()) else {
            debug_assert!(
                page.options.is_empty(),
                "dialog cursor {} points past {} option rows",
                self.list.cursor(),
                page.options.len()
            );
            return;
        };
        let id = option.id.clone();
        let is_select = page.is_select();
        let st = &mut self.page_states[self.page];
        if is_select {
            // Radio: toggling a new option replaces the prior selection;
            // toggling the already-selected one clears it. Radio + custom
            // are mutually exclusive, so a fresh selection clears custom.
            if st.selected == [id.clone()] {
                st.selected.clear();
            } else {
                st.selected = vec![id];
                st.custom.set("");
            }
        } else if let Some(pos) = st.selected.iter().position(|s| *s == id) {
            st.selected.remove(pos);
        } else {
            st.selected.push(id);
        }
    }

    /// Begin editing the custom / free-text field of the current page. On
    /// a single-select page the custom answer is mutually exclusive with
    /// the radio options, so entering the field clears any radio choice.
    fn begin_custom_typing(&mut self) {
        if self.pages[self.page].is_select() {
            self.page_states[self.page].selected.clear();
        }
        let current = self.page_states[self.page].custom.text().to_string();
        self.page_states[self.page].custom.set(current);
        self.typing = true;
    }

    /// Enter on a select/multiselect page (cursor mode).
    fn enter_on_page(&mut self) -> DialogOutcome {
        let page = &self.pages[self.page];
        if Some(self.list.cursor()) == page.custom_index() {
            // Enter on the custom affordance always resumes editing; Enter
            // from typing mode is the commit/advance action.
            self.begin_custom_typing();
            return DialogOutcome::Continue;
        }
        // Hovering a proposed option.
        let Some(option) = page.options.get(self.list.cursor()) else {
            debug_assert!(
                page.options.is_empty(),
                "dialog cursor {} points past {} option rows",
                self.list.cursor(),
                page.options.len()
            );
            return DialogOutcome::Continue;
        };
        let id = option.id.clone();
        if page.is_select() {
            if page.permission && id == cockpit_core::approval::ID_MORE_OPTIONS {
                return self.reveal_secondary_options();
            }
            if page.permission && self.page_states[self.page].selected.as_slice() != [id.as_str()] {
                let st = &mut self.page_states[self.page];
                st.selected = vec![id];
                st.custom.set("");
                return DialogOutcome::Continue;
            }
            // Single-select: choose it (mutually exclusive with custom)
            // and auto-advance.
            let st = &mut self.page_states[self.page];
            st.selected = vec![id];
            st.custom.set("");
            self.fast_path_submit_or_advance()
        } else {
            self.fast_path_submit_or_advance()
        }
    }

    fn reveal_secondary_options(&mut self) -> DialogOutcome {
        let page = &mut self.pages[self.page];
        let more_index = page
            .options
            .iter()
            .position(|option| option.id == cockpit_core::approval::ID_MORE_OPTIONS);
        if let Some(index) = more_index {
            page.options.remove(index);
            let first = page.options.len();
            page.options.append(&mut page.secondary_options);
            self.page_states[self.page].selected.clear();
            self.list
                .set_cursor(first.min(page.options.len().saturating_sub(1)));
            self.clamp_scroll();
        }
        DialogOutcome::Continue
    }

    /// Single-question fast path: if this is the only page and it's now
    /// answered, submit immediately; otherwise advance toward the
    /// confirm page.
    fn fast_path_submit_or_advance(&mut self) -> DialogOutcome {
        if self.pages.len() == 1 && self.all_answered() {
            return DialogOutcome::Submit(self.collect_answers());
        }
        self.next_page()
    }

    /// Keys on the confirm/submit page.
    fn handle_confirm_key(&mut self, key: KeyEvent) -> DialogOutcome {
        match key.code {
            KeyCode::Left | KeyCode::Char('h') => self.prev_page(),
            KeyCode::Enter => {
                if self.all_answered() {
                    DialogOutcome::Submit(self.collect_answers())
                } else {
                    // Jump the cursor to the first unanswered page so the
                    // user can fix it; refuse to submit.
                    if let Some(first) = (0..self.pages.len()).find(|&i| !self.is_answered(i)) {
                        self.page = first;
                        self.land_on_page();
                    }
                    DialogOutcome::Continue
                }
            }
            _ => DialogOutcome::Continue,
        }
    }

    /// Move the cursor within the current page, wrapping. Down from the
    /// last position (the custom affordance) wraps to the top.
    fn move_cursor(&mut self, delta: i32) {
        let n = self.pages[self.page].cursor_count() as i32;
        if n == 0 {
            return;
        }
        self.list.move_by(delta as isize, n as usize);
        self.clamp_scroll();
    }

    /// Advance to the next page (or the confirm page). Resets the cursor
    /// and scroll; a freetext page lands directly in typing mode.
    fn next_page(&mut self) -> DialogOutcome {
        if self.page < self.pages.len() {
            self.page += 1;
            self.land_on_page();
        }
        DialogOutcome::Continue
    }

    /// Step back one page. Resets the cursor and scroll.
    fn prev_page(&mut self) -> DialogOutcome {
        if self.page > 0 {
            self.page -= 1;
            self.land_on_page();
        }
        DialogOutcome::Continue
    }

    /// Reset per-page transient state after a page change. Freetext pages
    /// open directly in typing mode (no space/enter to start).
    fn land_on_page(&mut self) {
        self.list.reset();
        self.prompt_scroll = 0;
        self.typing = !self.on_confirm_page() && self.pages[self.page].is_text();
    }

    /// Build the final answer list — one [`Answer`] per page.
    pub fn collect_answers(&self) -> Vec<Answer> {
        self.pages
            .iter()
            .zip(self.page_states.iter())
            .map(|(page, st)| Self::answer_for(page, st))
            .collect()
    }

    fn answer_for(page: &Page, st: &PageState) -> Answer {
        let custom = st.custom.text().trim();
        match page.kind {
            PageKind::Text => Answer::Text {
                text: custom.to_string(),
            },
            PageKind::Select => {
                // A select with a checked option answers Single; a select
                // whose only answer is the custom field answers Text.
                if let Some(id) = st.selected.first() {
                    Answer::Single { id: id.clone() }
                } else {
                    Answer::Text {
                        text: custom.to_string(),
                    }
                }
            }
            PageKind::Multiselect => Answer::Multi {
                ids: st.selected.clone(),
                custom: if custom.is_empty() {
                    None
                } else {
                    Some(custom.to_string())
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn opt(id: &str) -> DialogOption {
        DialogOption::new(id, id.to_uppercase())
    }

    /// Build an already-unlocked single-select dialog for behavior tests.
    fn unlocked(pages: Vec<Page>) -> DialogState {
        DialogState::new_at(
            pages,
            Duration::from_millis(1500),
            Instant::now() - Duration::from_secs(10),
        )
    }

    #[test]
    fn new_preselected_checks_listed_ids_and_ignores_unknown() {
        // `/toggle-redaction` opens a multiselect pre-checked to current
        // state. `new_preselected` must seed exactly the listed (valid) ids.
        let page = Page::multiselect("?", vec![opt("a"), opt("b")]);
        let d = DialogState::new_preselected(
            vec![page],
            Duration::from_millis(1500),
            &[vec!["a".into(), "nonexistent".into()]],
        );
        assert_eq!(d.selected_ids(0), &["a".to_string()]);
    }

    #[test]
    fn new_preselected_empty_leaves_nothing_checked() {
        let page = Page::multiselect("?", vec![opt("a"), opt("b")]);
        let d = DialogState::new_preselected(vec![page], Duration::from_millis(1500), &[vec![]]);
        assert!(d.selected_ids(0).is_empty());
    }

    #[test]
    fn locked_then_unlocked_transition() {
        // Just-created: locked, ignores input.
        let mut d = DialogState::new(
            vec![Page::select("?", vec![opt("a"), opt("b")])],
            Duration::from_millis(50),
        );
        assert!(d.locked(), "fresh dialog must be locked (grey border)");
        assert_eq!(
            d.handle_key(press(KeyCode::Char('j'))),
            DialogOutcome::Continue
        );
        assert_eq!(d.cursor(), 0, "input ignored during lockout");

        // After the lockout window: interactive (white border).
        std::thread::sleep(Duration::from_millis(60));
        assert!(!d.locked(), "lockout must elapse to interactive");
        d.handle_key(press(KeyCode::Char('j')));
        assert_eq!(d.cursor(), 1, "input accepted after lockout");
    }

    #[test]
    fn permission_more_options_reveals_secondary_and_renumbers() {
        let mut more = DialogOption::new(cockpit_core::approval::ID_MORE_OPTIONS, "More options…");
        more.secondary = false;
        let mut secondary_b = opt("b");
        secondary_b.secondary = true;
        let mut secondary_c = opt("c");
        secondary_c.secondary = true;
        let mut page = Page::select("Approve?", vec![opt("a"), more])
            .with_secondary_options(vec![secondary_b, secondary_c]);
        page.permission = true;
        page.allow_custom = false;
        let mut d = unlocked(vec![page]);

        assert_eq!(
            d.handle_key(press(KeyCode::Char('2'))),
            DialogOutcome::Continue
        );
        assert_eq!(d.cursor(), 1, "cursor lands on first revealed row");
        assert_eq!(d.pages[0].options[1].id, "b");

        assert_eq!(
            d.handle_key(press(KeyCode::Char('2'))),
            DialogOutcome::Continue
        );
        assert_eq!(d.selected_ids(0), &["b".to_string()]);
        assert_eq!(
            d.handle_key(press(KeyCode::Enter)),
            DialogOutcome::Submit(vec![Answer::Single {
                id: "b".to_string()
            }])
        );
    }

    #[test]
    fn jk_navigates_and_wraps_through_custom() {
        let mut d = unlocked(vec![Page::select("?", vec![opt("a"), opt("b")])]);
        // 2 options + custom affordance => 3 cursor slots.
        assert_eq!(d.cursor(), 0);
        d.handle_key(press(KeyCode::Char('j')));
        assert_eq!(d.cursor(), 1);
        d.handle_key(press(KeyCode::Char('j')));
        assert_eq!(d.cursor(), 2, "lands on the custom affordance");
        // Down from custom wraps to the top.
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.cursor(), 0);
        // Up from the top wraps to custom.
        d.handle_key(press(KeyCode::Up));
        assert_eq!(d.cursor(), 2);
    }

    #[test]
    fn select_space_is_radio() {
        let mut d = unlocked(vec![Page::select("?", vec![opt("a"), opt("b")])]);
        d.handle_key(press(KeyCode::Char(' '))); // select a
        assert_eq!(d.selected_ids(0), &["a".to_string()]);
        d.handle_key(press(KeyCode::Char('j'))); // hover b
        d.handle_key(press(KeyCode::Char(' '))); // select b -> a cleared
        assert_eq!(d.selected_ids(0), &["b".to_string()]);
        // Toggling the selected one clears it.
        d.handle_key(press(KeyCode::Char(' ')));
        assert!(d.selected_ids(0).is_empty());
    }

    #[test]
    fn dialog_ux_select_enter_advances_space_stays() {
        let mut d = unlocked(vec![
            Page::select("q1", vec![opt("a"), opt("b")]),
            Page::text("q2"),
        ]);

        d.handle_key(press(KeyCode::Char(' ')));
        assert_eq!(d.selected_ids(0), &["a".to_string()]);
        assert_eq!(d.current_page(), 0, "Space selects without advancing");
        d.handle_key(press(KeyCode::Char(' ')));
        assert!(d.selected_ids(0).is_empty(), "Space re-press clears");
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.selected_ids(0), &["a".to_string()]);
        assert_eq!(d.current_page(), 1, "Enter selects and advances");

        let mut approval = unlocked(vec![
            Page::select("Approve?", vec![opt("a"), opt("b")]).permission(),
        ]);
        assert_eq!(
            approval.handle_key(press(KeyCode::Char('1'))),
            DialogOutcome::Continue
        );
        assert_eq!(approval.selected_ids(0), &["a".to_string()]);
    }

    #[test]
    fn multiselect_space_is_independent() {
        let mut d = unlocked(vec![Page::multiselect("?", vec![opt("a"), opt("b")])]);
        d.handle_key(press(KeyCode::Char(' '))); // a
        d.handle_key(press(KeyCode::Char('j')));
        d.handle_key(press(KeyCode::Char(' '))); // b
        assert_eq!(d.selected_ids(0), &["a".to_string(), "b".to_string()]);
        d.handle_key(press(KeyCode::Char('k')));
        d.handle_key(press(KeyCode::Char(' '))); // toggle a off
        assert_eq!(d.selected_ids(0), &["b".to_string()]);
    }

    #[test]
    fn single_question_enter_fast_path_submits() {
        let mut d = unlocked(vec![Page::select("?", vec![opt("a"), opt("b")])]);
        // Hover the first option, enter => choose + submit immediately.
        let out = d.handle_key(press(KeyCode::Enter));
        assert_eq!(
            out,
            DialogOutcome::Submit(vec![Answer::Single { id: "a".into() }])
        );
    }

    #[test]
    fn permission_page_with_no_options_enter_is_noop() {
        let mut d = unlocked(vec![Page::select("?", vec![]).permission()]);
        assert_eq!(d.cursor(), 0);

        let out = d.handle_key(press(KeyCode::Enter));

        assert_eq!(out, DialogOutcome::Continue);
        assert_eq!(d.cursor(), 0);
        assert!(d.selected_ids(0).is_empty());
        assert!(!d.is_typing());
    }

    #[test]
    fn permission_page_with_no_options_space_is_noop() {
        let mut d = unlocked(vec![Page::select("?", vec![]).permission()]);
        assert_eq!(d.cursor(), 0);

        let out = d.handle_key(press(KeyCode::Char(' ')));

        assert_eq!(out, DialogOutcome::Continue);
        assert_eq!(d.cursor(), 0);
        assert!(d.selected_ids(0).is_empty());
        assert!(!d.is_typing());
    }

    #[test]
    fn empty_select_routes_enter_to_custom_text() {
        let mut d = unlocked(vec![Page::select("?", vec![])]);
        assert_eq!(d.cursor(), 0);

        let out = d.handle_key(press(KeyCode::Enter));

        assert_eq!(out, DialogOutcome::Continue);
        assert!(d.is_typing());
        d.handle_key(press(KeyCode::Char('o')));
        d.handle_key(press(KeyCode::Char('k')));

        let out = d.handle_key(press(KeyCode::Enter));
        assert_eq!(
            out,
            DialogOutcome::Submit(vec![Answer::Text { text: "ok".into() }])
        );
    }

    #[test]
    fn custom_text_typing_mode_flow() {
        let mut d = unlocked(vec![Page::select("?", vec![opt("a")])]);
        // Move to the custom affordance (index 1).
        d.handle_key(press(KeyCode::Char('j')));
        assert_eq!(d.cursor(), 1);
        // Nothing typed yet: enter begins typing mode.
        d.handle_key(press(KeyCode::Enter));
        assert!(d.is_typing());
        // Type a couple chars.
        d.handle_key(press(KeyCode::Char('h')));
        d.handle_key(press(KeyCode::Char('i')));
        assert_eq!(d.custom_text(0), "hi");
        // Enter on the single-select custom field (text present) commits +
        // fast-paths to submit (lone question).
        let out = d.handle_key(press(KeyCode::Enter));
        assert_eq!(
            out,
            DialogOutcome::Submit(vec![Answer::Text { text: "hi".into() }])
        );
    }

    #[test]
    fn dialog_ux_custom_row_enter_resumes_typing() {
        let mut d = unlocked(vec![Page::select("?", vec![opt("a")])]);
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.cursor(), 1);

        d.handle_key(press(KeyCode::Enter));
        assert!(d.is_typing(), "empty custom row enters typing");
        d.handle_key(press(KeyCode::Char('h')));
        d.handle_key(press(KeyCode::Char('i')));
        d.handle_key(press(KeyCode::Esc));
        assert!(!d.is_typing());
        assert_eq!(d.custom_text(0), "hi");

        d.handle_key(press(KeyCode::Enter));
        assert!(d.is_typing(), "text-bearing custom row resumes typing");
        d.handle_key(press(KeyCode::Char('!')));
        assert_eq!(d.custom_text(0), "hi!", "resume parks cursor at end");
        assert_eq!(
            d.handle_key(press(KeyCode::Enter)),
            DialogOutcome::Submit(vec![Answer::Text { text: "hi!".into() }])
        );
    }

    #[test]
    fn single_select_custom_and_radio_are_mutually_exclusive() {
        // Two select pages so Enter on a select-custom field advances
        // (leaving the typed custom in place) rather than submitting — that
        // lets us come back and exercise "selecting a radio clears custom".
        let mut d = unlocked(vec![
            Page::select("q1", vec![opt("a"), opt("b")]),
            Page::select("q2", vec![opt("c")]),
        ]);
        // Select a radio option.
        d.handle_key(press(KeyCode::Char(' ')));
        assert_eq!(d.selected_ids(0), &["a".to_string()]);
        // Move to the custom affordance and start typing: the radio choice
        // clears the moment the user types.
        d.handle_key(press(KeyCode::Char('j')));
        d.handle_key(press(KeyCode::Char('j'))); // custom index = 2
        d.handle_key(press(KeyCode::Enter)); // begin typing (empty)
        assert!(d.is_typing());
        d.handle_key(press(KeyCode::Char('x')));
        assert!(
            d.selected_ids(0).is_empty(),
            "typing custom clears the radio"
        );
        assert_eq!(d.custom_text(0), "x");
        // Enter commits the custom answer and advances to q2 (2 pages).
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.current_page(), 1);
        // Back to q1; custom "x" is still present. Pick a radio via number
        // key now that we're in navigation mode: custom text clears.
        d.handle_key(press(KeyCode::Char('h')));
        assert_eq!(d.current_page(), 0);
        assert_eq!(d.custom_text(0), "x");
        d.handle_key(press(KeyCode::Char('1')));
        assert_eq!(d.selected_ids(0), &["a".to_string()]);
        assert!(
            d.custom_text(0).is_empty(),
            "selecting a radio clears custom"
        );
    }

    #[test]
    fn dialog_ux_multiselect_enter_confirms_set() {
        let mut d = unlocked(vec![
            Page::multiselect("q1", vec![opt("a"), opt("b")]),
            Page::text("q2"),
        ]);
        // Space toggles without advancing.
        d.handle_key(press(KeyCode::Char(' ')));
        assert_eq!(d.selected_ids(0), &["a".to_string()]);
        assert_eq!(d.current_page(), 0, "Space stays on multiselect page");
        // Number key toggles a different option without advancing.
        d.handle_key(press(KeyCode::Char('2')));
        assert_eq!(d.selected_ids(0), &["a".to_string(), "b".to_string()]);
        assert_eq!(d.current_page(), 0);
        // Enter confirms the current set and advances.
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.current_page(), 1, "Enter advanced to the next question");
    }

    #[test]
    fn dialog_ux_multiselect_empty_enter_confirms_none() {
        let mut d = unlocked(vec![
            Page::multiselect("q1", vec![opt("a"), opt("b")]),
            Page::text("q2"),
        ]);

        d.handle_key(press(KeyCode::Enter));

        assert_eq!(d.current_page(), 1);
        assert_eq!(
            d.collect_answers()[0],
            Answer::Multi {
                ids: Vec::new(),
                custom: None
            }
        );
    }

    #[test]
    fn multiselect_custom_answer_is_additive() {
        let mut d = unlocked(vec![Page::multiselect("?", vec![opt("a"), opt("b")])]);
        d.handle_key(press(KeyCode::Char(' '))); // check a
        // Go to custom (index 2), type.
        d.handle_key(press(KeyCode::Char('j')));
        d.handle_key(press(KeyCode::Char('j')));
        d.handle_key(press(KeyCode::Char(' '))); // begin typing
        d.handle_key(press(KeyCode::Char('x')));
        d.handle_key(press(KeyCode::Enter)); // exit typing
        let answers = d.collect_answers();
        assert_eq!(
            answers,
            vec![Answer::Multi {
                ids: vec!["a".into()],
                custom: Some("x".into())
            }]
        );
    }

    #[test]
    fn multi_question_nav_and_confirm_validation() {
        let mut d = unlocked(vec![Page::select("q1", vec![opt("a")]), Page::text("q2")]);
        // Page 0 (single-select): Enter selects + auto-advances to page 1
        // (no fast-path submit because there are two pages).
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.selected_ids(0), &["a".to_string()]);
        assert_eq!(d.current_page(), 1, "auto-advanced to the text page");
        // The text page opens directly in typing mode.
        assert!(d.is_typing(), "freetext page opens in typing mode");
        // Enter on the (empty) text page advances to the confirm page.
        d.handle_key(press(KeyCode::Enter));
        assert!(d.on_confirm_page());
        // Enter on confirm with an unanswered q2: refuses, jumps to q2 and
        // re-enters typing mode.
        let out = d.handle_key(press(KeyCode::Enter));
        assert_eq!(out, DialogOutcome::Continue);
        assert_eq!(d.current_page(), 1, "jumped to the unanswered page");
        assert!(d.is_typing(), "landing on the text page re-enters typing");
        // Answer q2 by typing; Enter advances to confirm.
        d.handle_key(press(KeyCode::Char('z')));
        let out = d.handle_key(press(KeyCode::Enter));
        assert_eq!(out, DialogOutcome::Continue);
        assert!(d.on_confirm_page());
        // Enter submits now.
        let out = d.handle_key(press(KeyCode::Enter));
        assert_eq!(
            out,
            DialogOutcome::Submit(vec![
                Answer::Single { id: "a".into() },
                Answer::Text { text: "z".into() },
            ])
        );
    }

    #[test]
    fn esc_exits_typing_before_cancelling_freetext() {
        // Supersedes the old `esc_cancels_even_while_typing`: Esc now
        // escalates. A freetext page opens directly in typing mode.
        let mut d = unlocked(vec![Page::text("q")]);
        assert!(d.is_typing());
        d.handle_key(press(KeyCode::Char('x'))); // mid-typing
        // First Esc leaves typing mode but keeps the dialog open and the
        // typed text intact.
        let out = d.handle_key(press(KeyCode::Esc));
        assert_eq!(out, DialogOutcome::Continue);
        assert!(!d.is_typing(), "first Esc defocuses the field");
        assert_eq!(d.custom_text(0), "x", "Esc preserves typed text");
        // A text-affecting key resumes editing (the existing resume path).
        d.handle_key(press(KeyCode::Char('y')));
        assert!(d.is_typing(), "next key resumes editing");
        assert_eq!(d.custom_text(0), "xy");
        // Defocus again, then a second Esc (typing off) cancels.
        let out = d.handle_key(press(KeyCode::Esc));
        assert_eq!(out, DialogOutcome::Continue);
        assert!(!d.is_typing());
        let out = d.handle_key(press(KeyCode::Esc));
        assert_eq!(out, DialogOutcome::Cancel);
    }

    #[test]
    fn esc_exits_typing_before_cancelling_select_custom() {
        // On a select custom field: first Esc returns focus to the option
        // list (typing off, text preserved), second Esc cancels.
        let mut d = unlocked(vec![Page::select("?", vec![opt("a")])]);
        // Move to the custom affordance and begin typing.
        d.handle_key(press(KeyCode::Char('j')));
        assert_eq!(d.cursor(), 1);
        d.handle_key(press(KeyCode::Enter)); // begin typing (empty)
        assert!(d.is_typing());
        d.handle_key(press(KeyCode::Char('h')));
        d.handle_key(press(KeyCode::Char('i')));
        assert_eq!(d.custom_text(0), "hi");
        // First Esc: defocus the field, dialog stays open, text intact.
        let out = d.handle_key(press(KeyCode::Esc));
        assert_eq!(out, DialogOutcome::Continue);
        assert!(!d.is_typing(), "first Esc returns to option navigation");
        assert_eq!(d.custom_text(0), "hi", "Esc preserves typed text");
        // The cursor is still on the custom affordance (navigation mode).
        assert_eq!(d.cursor(), 1);
        // Second Esc (not typing) cancels.
        let out = d.handle_key(press(KeyCode::Esc));
        assert_eq!(out, DialogOutcome::Cancel);
    }

    #[test]
    fn answered_flags_track_each_page() {
        let mut d = unlocked(vec![Page::select("q1", vec![opt("a")]), Page::text("q2")]);
        assert_eq!(d.answered_flags(), vec![false, false]);
        d.handle_key(press(KeyCode::Char(' '))); // answer q1
        assert_eq!(d.answered_flags(), vec![true, false]);
    }

    #[test]
    fn permission_page_has_no_custom_slot_or_typing() {
        // A permission page drops the custom affordance: the cursor cycles
        // only through the options, and typing mode is unreachable.
        let mut d = unlocked(vec![
            Page::select("?", vec![opt("a"), opt("b")]).permission(),
        ]);
        assert_eq!(d.cursor(), 0);
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.cursor(), 1);
        // Down from the last option wraps to the top — no custom slot.
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.cursor(), 0, "no custom affordance to land on");
        // Space (which would begin custom typing on a question page) is inert.
        d.handle_key(press(KeyCode::Char(' ')));
        assert!(!d.is_typing(), "permission page never enters typing");
        // Enter on an option still selects + submits (lone question).
        let out = d.handle_key(press(KeyCode::Enter));
        assert_eq!(
            out,
            DialogOutcome::Submit(vec![Answer::Single { id: "a".into() }])
        );
    }

    #[test]
    fn question_page_keeps_custom_slot() {
        // The default presentation keeps the custom affordance reachable.
        let mut d = unlocked(vec![Page::select("?", vec![opt("a"), opt("b")])]);
        d.handle_key(press(KeyCode::Down));
        d.handle_key(press(KeyCode::Down)); // lands on the custom slot
        assert_eq!(
            d.cursor(),
            2,
            "custom slot still present on a question page"
        );
        assert!(d.pages()[0].has_custom());
    }

    #[test]
    fn prompt_scroll_clamps_to_content_and_resets_on_collapse() {
        let mut d = unlocked(vec![Page::select("?", vec![opt("a")])]);
        // 20 prompt lines into a 5-line region: max scroll = 15.
        d.set_prompt_metrics(20, 5);
        assert!(d.prompt_overflows());
        d.scroll_prompt(100);
        assert_eq!(d.prompt_scroll(), 15, "clamped to (total - viewport)");
        d.scroll_prompt(-100);
        assert_eq!(d.prompt_scroll(), 0, "clamped at the top");
        // Scroll down, then expand-collapse resets the prompt scroll.
        d.scroll_prompt(7);
        assert_eq!(d.prompt_scroll(), 7);
        d.toggle_expanded();
        assert!(d.is_expanded());
        d.toggle_expanded();
        assert!(!d.is_expanded());
        assert_eq!(d.prompt_scroll(), 0, "collapse re-anchors the prompt");
        // A prompt that fits never reports overflow and pins scroll to 0.
        d.set_prompt_metrics(3, 5);
        assert!(!d.prompt_overflows());
        d.scroll_prompt(5);
        assert_eq!(d.prompt_scroll(), 0);
    }

    #[test]
    fn prompt_scroll_resets_on_page_change() {
        let mut d = unlocked(vec![Page::text("q1"), Page::text("q2")]);
        d.set_prompt_metrics(20, 4);
        d.scroll_prompt(5);
        assert_eq!(d.prompt_scroll(), 5);
        // Advancing to the next page re-anchors the prompt region.
        d.handle_key(press(KeyCode::Right));
        assert_eq!(d.current_page(), 1);
        assert_eq!(d.prompt_scroll(), 0, "page change resets prompt scroll");
    }

    #[test]
    fn viewport_scroll_keeps_focus_in_view() {
        let options: Vec<DialogOption> = (0..12).map(|i| opt(&format!("o{i}"))).collect();
        let mut d = unlocked(vec![Page::select("?", options)]);
        // Window of 4 rows (13 cursor rows total: 12 options + custom).
        d.set_viewport(4);
        assert_eq!(d.scroll(), 0);
        // Move focus down past the window; scroll follows.
        for _ in 0..6 {
            d.handle_key(press(KeyCode::Down));
        }
        assert_eq!(d.cursor(), 6);
        assert!(d.cursor() >= d.scroll());
        assert!(d.cursor() < d.scroll() + 4, "focus stays within the window");
        // scrolloff=1: while moving down (not at the last row) the option just
        // below the cursor stays on screen.
        assert!(
            d.cursor() + 1 < d.scroll() + 4,
            "next option below the cursor is visible (1-row margin)"
        );
        // Move back up above the window; scroll follows up.
        for _ in 0..6 {
            d.handle_key(press(KeyCode::Up));
        }
        assert_eq!(d.cursor(), 0);
        assert_eq!(d.scroll(), 0);
    }

    /// scrolloff=1: in an overflowing list, the option immediately past the
    /// cursor stays visible in the direction of travel — until the boundary,
    /// where the cursor may sit flush against the first/last option.
    #[test]
    fn scroll_margin_keeps_next_option_visible() {
        let options: Vec<DialogOption> = (0..20).map(|i| opt(&format!("o{i}"))).collect();
        let mut d = unlocked(vec![Page::select("?", options.clone())]);
        let total = 21; // 20 options + custom row
        let vp = 5;
        d.set_viewport(vp);
        // Walk all the way down: at every interior position the next option
        // below is on screen; the focused row never leaves the window.
        let last = total - 1;
        for target in 1..=last {
            d.handle_key(press(KeyCode::Down));
            assert_eq!(d.cursor(), target);
            assert!(d.cursor() >= d.scroll(), "cursor above window at {target}");
            assert!(
                d.cursor() < d.scroll() + vp,
                "cursor below window at {target}"
            );
            if target < last {
                assert!(
                    d.cursor() + 1 < d.scroll() + vp,
                    "next option below not visible at {target}"
                );
            } else {
                // Last row: nothing below, cursor sits flush at the bottom edge.
                assert_eq!(d.cursor(), d.scroll() + vp - 1, "last row flush at edge");
            }
        }
        // Walk back up: at every interior position the next option above is on
        // screen; at the first row the cursor sits flush at the top.
        for step in 1..=last {
            d.handle_key(press(KeyCode::Up));
            let target = last - step;
            assert_eq!(d.cursor(), target);
            assert!(d.cursor() >= d.scroll(), "cursor above window at {target}");
            assert!(
                d.cursor() < d.scroll() + vp,
                "cursor below window at {target}"
            );
            if target > 0 {
                assert!(
                    d.cursor() > d.scroll(),
                    "next option above not visible at {target}"
                );
            } else {
                assert_eq!(d.scroll(), 0, "first row flush at top edge");
            }
        }
    }

    /// A list that fully fits the viewport never scrolls and shows no margin
    /// pressure (scroll pinned at 0 regardless of cursor position).
    #[test]
    fn scroll_margin_noop_when_list_fits() {
        let options: Vec<DialogOption> = (0..4).map(|i| opt(&format!("o{i}"))).collect();
        let mut d = unlocked(vec![Page::select("?", options)]);
        // 5 cursor rows, viewport 8 -> everything fits.
        d.set_viewport(8);
        for _ in 0..4 {
            d.handle_key(press(KeyCode::Down));
            assert_eq!(d.scroll(), 0, "fitting list never scrolls");
        }
    }

    /// Tiny windows (1–2 rows) can't fit a symmetric margin: the focused
    /// option must still always be visible, the margin degrading to 0.
    #[test]
    fn scroll_margin_degrades_on_tiny_viewport() {
        let options: Vec<DialogOption> = (0..10).map(|i| opt(&format!("o{i}"))).collect();
        for vp in [1usize, 2usize] {
            let mut d = unlocked(vec![Page::select("?", options.clone())]);
            d.set_viewport(vp);
            for target in 0..11 {
                if target > 0 {
                    d.handle_key(press(KeyCode::Down));
                }
                assert_eq!(d.cursor(), target, "cursor at {target} (vp {vp})");
                assert!(
                    d.cursor() >= d.scroll() && d.cursor() < d.scroll() + vp,
                    "focused option visible at {target} (vp {vp})"
                );
            }
        }
    }
}
