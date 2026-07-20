//! Prompt composer.
//!
//! Vim mode is **default on** (`the design notes` §1b). This deviates from codex
//! (vim is opt-in there) — Vim users shouldn't have to discover a slash
//! command before they can `dd` a line.
//!
//! Modes:
//!   - `Insert`  — standard editor; `Esc` -> Normal.
//!   - `Normal`  — motions `h l w W b B e ge 0 $ gg G f F t T ; , %`
//!     (`j`/`k` navigate prompt history, not buffer lines); edits
//!     `x D C o O i I a A p P`; operators `d c y` over those motions plus
//!     `dd cc yy` and text objects (`iw aw i" a" i( a(` …).
//!   - `Operator` — pending after `d`/`c`/`y`, awaiting a motion or text
//!     object.
//!   - `Visual` / `VisualLine` — charwise (`v`) / linewise (`V`)
//!     selection; motions and text objects extend it, `d`/`x`/`c`/`y`
//!     act on it. In visual mode `j`/`k` move by buffer line.
//!
//! The unnamed [`Register`] holds the last yank/delete/change text and
//! whether it was charwise or linewise; it mirrors to/from the system
//! clipboard at the app layer so OS copies paste with `p`/`P` and yanks
//! are pasteable elsewhere.
//!
//! Reference implementation: codex's `bottom_pane/textarea.rs`.

pub use cockpit_core::welcome::INPUT_PREFIX;

/// Display width of [`INPUT_PREFIX`] in terminal columns. Computed via
/// `unicode-width` so wider glyphs (CJK, emoji) would size correctly if
/// the prefix is ever changed.
pub fn input_prefix_width() -> usize {
    use unicode_width::UnicodeWidthStr;
    INPUT_PREFIX.width()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisualChunk {
    pub line: usize,
    pub row: usize,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_col: usize,
    pub end_col: usize,
}

pub fn display_width(s: &str) -> usize {
    use unicode_width::UnicodeWidthStr;
    s.width()
}

pub fn display_width_char(ch: char) -> usize {
    use unicode_width::UnicodeWidthChar;
    ch.width().unwrap_or(0)
}

pub fn truncate_display_width(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let first = s.lines().next().unwrap_or("");
    if display_width(first) <= width {
        return first.to_string();
    }
    let ellipsis_w = display_width("…");
    let budget = width.saturating_sub(ellipsis_w);
    let mut out = String::new();
    let mut used = 0usize;
    for ch in first.chars() {
        let w = display_width_char(ch);
        if used.saturating_add(w) > budget {
            break;
        }
        out.push(ch);
        used = used.saturating_add(w);
    }
    out.push('…');
    out
}

pub fn wrap_display_chunks(line: &str, budget: usize) -> Vec<(usize, usize, usize, usize)> {
    if line.is_empty() {
        return vec![(0, 0, 0, 0)];
    }
    let budget = budget.max(1);
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < line.len() {
        let mut col = 0usize;
        let mut end = start;
        let mut last_space: Option<(usize, usize)> = None;
        let mut overflow_at: Option<usize> = None;
        for (rel, ch) in line[start..].char_indices() {
            let abs = start + rel;
            let ch_end = abs + ch.len_utf8();
            let w = display_width_char(ch);
            if col > 0 && col.saturating_add(w) > budget {
                overflow_at = Some(abs);
                break;
            }
            end = ch_end;
            col = col.saturating_add(w);
            if ch == ' ' {
                last_space = Some((ch_end, col));
            }
            if col >= budget {
                break;
            }
        }
        if end == start {
            if let Some((_, ch)) = line[start..].char_indices().next() {
                end = start + ch.len_utf8();
                col = display_width_char(ch);
            }
        } else if (overflow_at.is_some() || end < line.len())
            && let Some((space_end, space_col)) = last_space
            && space_end > start
            && space_end < end
        {
            end = space_end;
            col = space_col;
        }
        out.push((start, end, 0, col));
        start = end;
    }
    out
}

pub fn visual_chunks(text: &str, prefix: usize, inner_width: usize) -> Vec<VisualChunk> {
    let budget = inner_width.saturating_sub(prefix).max(1);
    let mut out = Vec::new();
    let mut row = 0usize;
    let mut line_idx = 0usize;
    let mut line_start = 0usize;
    loop {
        let rest = &text[line_start..];
        let line_len = rest.find('\n').unwrap_or(rest.len());
        let line = &rest[..line_len];
        for (start, end, start_col, end_col) in wrap_display_chunks(line, budget) {
            out.push(VisualChunk {
                line: line_idx,
                row,
                start_byte: line_start + start,
                end_byte: line_start + end,
                start_col,
                end_col,
            });
            row += 1;
        }
        if line_start + line_len >= text.len() {
            break;
        }
        line_start += line_len + 1;
        line_idx += 1;
    }
    if out.is_empty() {
        out.push(VisualChunk {
            line: 0,
            row: 0,
            start_byte: 0,
            end_byte: 0,
            start_col: 0,
            end_col: 0,
        });
    }
    out
}

pub fn visual_position_for_byte(
    text: &str,
    byte: usize,
    prefix: usize,
    inner_width: usize,
) -> (usize, usize) {
    let byte = byte.min(text.len());
    let chunks = visual_chunks(text, prefix, inner_width);
    for (idx, chunk) in chunks.iter().enumerate() {
        let is_last = idx + 1 == chunks.len();
        let contains = if is_last {
            byte >= chunk.start_byte && byte <= chunk.end_byte
        } else {
            let at_line_newline =
                byte == chunk.end_byte && text.as_bytes().get(byte).is_some_and(|b| *b == b'\n');
            (byte >= chunk.start_byte && byte < chunk.end_byte) || at_line_newline
        };
        if contains {
            let rel = display_width(&text[chunk.start_byte..byte]);
            return (chunk.row, prefix + chunk.start_col + rel);
        }
    }
    let last = chunks.last().expect("visual chunks non-empty");
    (last.row, prefix + last.end_col)
}

pub fn byte_for_visual_position(
    text: &str,
    row: usize,
    col: usize,
    prefix: usize,
    inner_width: usize,
) -> usize {
    let target = col.saturating_sub(prefix);
    let chunks = visual_chunks(text, prefix, inner_width);
    let Some(chunk) = chunks
        .iter()
        .find(|chunk| chunk.row == row)
        .or_else(|| chunks.last())
    else {
        return 0;
    };
    if col < prefix {
        return chunk.start_byte;
    }
    let mut used = chunk.start_col;
    for (rel, ch) in text[chunk.start_byte..chunk.end_byte].char_indices() {
        let abs = chunk.start_byte + rel;
        let w = display_width_char(ch);
        if target <= used {
            return abs;
        }
        if w > 1 && target < used + w {
            return abs;
        }
        used = used.saturating_add(w);
    }
    chunk.end_byte
}

fn byte_for_display_col(line: &str, col: usize) -> usize {
    let mut used = 0usize;
    for (byte, ch) in line.char_indices() {
        let w = display_width_char(ch);
        if col <= used {
            return byte;
        }
        if w > 1 && col < used + w {
            return byte;
        }
        used = used.saturating_add(w);
    }
    line.len()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VimMode {
    Insert,
    Normal,
    Operator(Operator),
    /// Charwise visual selection (`v`). The highlighted span runs between
    /// the anchor ([`Composer::visual_anchor`]) and the live cursor,
    /// inclusive of the cursor cell.
    Visual,
    /// Linewise visual selection (`V`). The selection spans whole lines
    /// from the anchor's line through the cursor's line.
    VisualLine,
}

/// What the last `f`/`F`/`t`/`T` was, so `;`/`,` can repeat it. `;`
/// repeats in the same direction; `,` reverses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindSpec {
    /// The search target character.
    pub target: char,
    /// `true` for `t`/`T` (till — land one cell shy of the target);
    /// `false` for `f`/`F` (find — land on the target).
    pub till: bool,
    /// `true` for forward (`f`/`t`), `false` for backward (`F`/`T`).
    pub forward: bool,
}

/// The single unnamed register. Holds the text of the last
/// yank/delete/change and whether it was charwise or linewise so paste
/// (`p`/`P`) reinserts with the correct semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Register {
    /// The yanked/deleted text. For a linewise register this always ends
    /// in a trailing `\n`.
    pub text: String,
    /// `true` when the register was populated linewise (`yy`/`dd`/`V`
    /// ops); `false` for charwise.
    pub linewise: bool,
}

/// The two-stage reveal stage of a `long` multi-line prediction
/// (implementation note). A `short` prediction, and a
/// single-line `long` prediction, never enter [`Self::FullGhost`] — they
/// convert to real text on the first Tab (see [`PredictionGhost::accept`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhostStage {
    /// Only the first line of a multi-line `long` prediction is shown as
    /// ghost text; the box stays single-line height. The first Tab moves
    /// to [`Self::FullGhost`].
    CollapsedFirstLine,
    /// The whole multi-line `long` prediction is shown as ghost text and
    /// the box has expanded to fit it. The next Tab converts it to real
    /// editable text.
    FullGhost,
}

/// What a Tab press on a pending ghost prediction should do, returned by
/// [`PredictionGhost::accept`] so the app can apply it to the composer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhostAccept {
    /// Fill the composer with this text as real editable content (does
    /// NOT send). Terminal step — the ghost is consumed.
    Fill(String),
    /// Expand the box and keep showing the full prediction as ghost text
    /// (the first Tab of a multi-line `long` prediction).
    Expand,
}

/// A completed next-message prediction offered as composer ghost text
/// (implementation note). Stored on the app while the input
/// box is empty; shown grey; accepted with Tab in vim insert mode.
///
/// The prediction belongs to the agent turn it was generated for
/// ([`Self::turn`]); a result tagged with a stale turn is discarded rather
/// than shown, so a prior turn's prediction never appears.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredictionGhost {
    /// The bounded prediction text (already mode-capped by
    /// `engine::predict::bound_prediction`).
    text: String,
    /// `true` when the prediction is multi-line AND the mode allows the
    /// two-stage reveal (`long`). A `short` prediction is always treated
    /// as single-line for accept purposes.
    multiline_long: bool,
    /// The two-stage reveal stage. Only meaningful when `multiline_long`.
    stage: GhostStage,
}

impl PredictionGhost {
    /// Build a ghost from a bounded prediction. `long_mode` is true when
    /// the active setting is `long`; only then can a multi-line prediction
    /// use the collapsed→full→real two-Tab reveal. A `short` prediction
    /// (or a single-line `long` one) renders fully and converts on the
    /// first Tab.
    pub fn new(text: String, long_mode: bool) -> Self {
        let multiline_long = long_mode && text.contains('\n');
        Self {
            text,
            multiline_long,
            stage: GhostStage::CollapsedFirstLine,
        }
    }

    /// The text to render as ghost right now: the first line while a
    /// multi-line `long` prediction is collapsed, the whole prediction
    /// otherwise.
    pub fn display_text(&self) -> &str {
        if self.multiline_long && self.stage == GhostStage::CollapsedFirstLine {
            self.text.split('\n').next().unwrap_or("")
        } else {
            &self.text
        }
    }

    /// The full prediction text (every line), regardless of stage. Used
    /// when computing the expanded box height.
    pub fn full_text(&self) -> &str {
        &self.text
    }

    /// True when the box should be sized to the full multi-line prediction
    /// (a `long` prediction whose ghost has been expanded but not yet
    /// converted to real text).
    pub fn box_expanded(&self) -> bool {
        self.multiline_long && self.stage == GhostStage::FullGhost
    }

    /// Apply a Tab press. Returns [`GhostAccept::Expand`] for the first Tab
    /// of a collapsed multi-line `long` prediction (advancing the stage),
    /// or [`GhostAccept::Fill`] with the full text otherwise (the terminal
    /// convert-to-real step).
    pub fn accept(&mut self) -> GhostAccept {
        if self.multiline_long && self.stage == GhostStage::CollapsedFirstLine {
            self.stage = GhostStage::FullGhost;
            GhostAccept::Expand
        } else {
            GhostAccept::Fill(self.text.clone())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    Delete,
    Change,
    Yank,
}

pub struct Composer {
    buffer: String,
    cursor: usize,
    vim_mode: VimMode,
    vim_enabled: bool,
    /// True if the previous Normal-mode key was a `g` — the *next* `g`
    /// completes the `gg` motion (jump to buffer start). Cleared on any
    /// other key. Lives here so app.rs can stay stateless about chord
    /// sequencing.
    pending_g: bool,
    /// Pending `f`/`F`/`t`/`T` find motion — the next char key is the
    /// search target. `None` when no find is pending. Carries the kind
    /// (`till`) and direction so the resolved find can be stored in
    /// [`Self::last_find`] for `;`/`,` to repeat. The `target` is a
    /// placeholder (`'\0'`) until the char key resolves it.
    pending_find: Option<FindSpec>,
    /// The last completed `f`/`F`/`t`/`T`, for `;`/`,` repeat.
    last_find: Option<FindSpec>,
    /// Anchor of the active visual selection (byte offset). `Some` only
    /// while [`Self::vim_mode`] is [`VimMode::Visual`] / `VisualLine`.
    visual_anchor: Option<usize>,
    /// Pending text-object selector after `i`/`a` in operator-pending or
    /// visual mode (`Some(around)`), awaiting the object char (`diw`, `ci"`).
    /// Only used by the self-contained [`Self::handle_vim_key`] editor path
    /// (the app composer tracks this on `App` instead, alongside its
    /// paste-block-aware operators).
    pending_text_object: Option<bool>,
    /// The single unnamed yank/delete register.
    register: Register,
}

impl Composer {
    pub fn new(vim_enabled: bool) -> Self {
        Self {
            buffer: String::new(),
            cursor: 0,
            vim_mode: if vim_enabled {
                VimMode::Normal
            } else {
                VimMode::Insert
            },
            vim_enabled,
            pending_g: false,
            pending_find: None,
            last_find: None,
            visual_anchor: None,
            pending_text_object: None,
            register: Register::default(),
        }
    }

    pub fn set_vim_enabled(&mut self, enabled: bool) {
        self.vim_enabled = enabled;
        if !enabled {
            self.vim_mode = VimMode::Insert;
            self.pending_g = false;
            self.pending_find = None;
            self.visual_anchor = None;
        }
    }

    pub fn pending_g(&self) -> bool {
        self.pending_g
    }

    pub fn set_pending_g(&mut self, on: bool) {
        self.pending_g = on;
    }

    pub fn pending_find(&self) -> Option<FindSpec> {
        self.pending_find
    }

    pub fn set_pending_find(&mut self, spec: Option<FindSpec>) {
        self.pending_find = spec;
    }

    /// Record the last find (used by the operator-pending find path, which
    /// computes the landing point itself via [`Self::find_target`]).
    pub fn set_last_find(&mut self, spec: FindSpec) {
        self.last_find = Some(spec);
    }

    /// Borrow the unnamed register (for the app-layer clipboard mirror).
    pub fn register(&self) -> &Register {
        &self.register
    }

    /// Overwrite the unnamed register (used by the app-layer clipboard
    /// mirror when the OS clipboard differs from the internal register).
    pub fn set_register(&mut self, reg: Register) {
        self.register = reg;
    }

    /// The byte offset a `f`/`F`/`t`/`T` `spec` would land on from the
    /// current cursor, or `None` if the target isn't on the line (in the
    /// search direction). Pure — does not move the cursor. `till` (`t`/`T`)
    /// lands one char shy of the target. Stays within the current line
    /// (never crosses `\n`) and on char boundaries.
    pub fn find_target(&self, spec: FindSpec) -> Option<usize> {
        if spec.forward {
            let line_end = self.buffer[self.cursor..]
                .find('\n')
                .map(|i| self.cursor + i)
                .unwrap_or(self.buffer.len());
            // Search from one char past the cursor so a repeat advances
            // rather than re-landing on the same character.
            let start = self.buffer[self.cursor..line_end]
                .chars()
                .next()
                .map(|c| self.cursor + c.len_utf8())
                .unwrap_or(self.cursor);
            if start > line_end {
                return None;
            }
            // `prev` tracks the char-start immediately before the char
            // under inspection. It starts at the cursor's own char (the
            // char right before `start`), so a `t` matching at `start`
            // lands on the cursor cell, one shy of the target.
            let mut prev = self.cursor;
            for (off, ch) in self.buffer[start..line_end].char_indices() {
                let here = start + off;
                if ch == spec.target {
                    return Some(if spec.till { prev } else { here });
                }
                prev = here;
            }
            None
        } else {
            let line_start = self.buffer[..self.cursor]
                .rfind('\n')
                .map(|i| i + 1)
                .unwrap_or(0);
            let slice = &self.buffer[line_start..self.cursor];
            let mut prev_after = self.cursor;
            for (off, ch) in slice.char_indices().rev() {
                let here = line_start + off;
                if ch == spec.target {
                    // `T` lands one char *after* the target (toward the
                    // original cursor). For a repeated `T`, the cursor is
                    // already there, so `prev_after` skips it.
                    return Some(if spec.till { prev_after } else { here });
                }
                prev_after = here;
            }
            None
        }
    }

    /// Apply a find `spec`: move the cursor to its landing point if the
    /// target is found, and (when `record`) store it as [`Self::last_find`]
    /// for `;`/`,`. Returns `true` when the cursor moved. For a `T` repeat
    /// the cursor already sits one past the target; we skip that immediate
    /// neighbor so `;` advances.
    pub fn apply_find(&mut self, spec: FindSpec, record: bool) -> bool {
        // For backward `t`/`T` repeats, the cursor is already one char
        // past the target — search from one char further back so we don't
        // re-land on the same spot.
        let landed = self.find_target(spec);
        if record {
            self.last_find = Some(spec);
        }
        match landed {
            Some(pos) if pos != self.cursor => {
                self.cursor = pos;
                true
            }
            _ => false,
        }
    }

    /// `;` / `,` — repeat the last `f`/`F`/`t`/`T`. `reverse` (for `,`)
    /// flips the direction. No-op when there's no stored find. The
    /// repeated find is *not* re-recorded (vim keeps the original).
    pub fn repeat_find(&mut self, reverse: bool) -> bool {
        let Some(mut spec) = self.last_find else {
            return false;
        };
        if reverse {
            spec.forward = !spec.forward;
        }
        // For a `t` (forward-till) repeat, the cursor sits just before the
        // target, so a plain search would re-find the same target. Nudge
        // one char forward first, then restore on a miss.
        if spec.till {
            let saved = self.cursor;
            self.step_over_for_till_repeat(spec.forward);
            let moved = self.apply_find(spec, false);
            if !moved {
                self.cursor = saved;
            }
            return moved;
        }
        self.apply_find(spec, false)
    }

    /// Nudge the cursor one char in `forward`'s direction before a `t`/`T`
    /// repeat, so the search clears the adjacent target it currently abuts.
    fn step_over_for_till_repeat(&mut self, forward: bool) {
        if forward {
            if let Some(ch) = self.buffer[self.cursor..].chars().next() {
                let next = self.cursor + ch.len_utf8();
                // Stay on the line.
                if ch != '\n' && next <= self.buffer.len() {
                    self.cursor = next;
                }
            }
        } else if self.cursor > 0
            && let Some((idx, ch)) = self.buffer[..self.cursor].char_indices().next_back()
            && ch != '\n'
        {
            self.cursor = idx;
        }
    }

    /// Test-only `f<char>` convenience wrapper over [`Self::apply_find`].
    /// Production code drives finds through `apply_find` with a built
    /// [`FindSpec`] (so `t`/`T` and `;`/`,` share one path).
    #[cfg(test)]
    pub fn find_char_forward(&mut self, target: char) {
        self.apply_find(
            FindSpec {
                target,
                till: false,
                forward: true,
            },
            true,
        );
    }

    /// Test-only `F<char>` convenience wrapper over [`Self::apply_find`].
    #[cfg(test)]
    pub fn find_char_backward(&mut self, target: char) {
        self.apply_find(
            FindSpec {
                target,
                till: false,
                forward: false,
            },
            true,
        );
    }

    pub fn text(&self) -> &str {
        &self.buffer
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Buffer length in bytes. Used by the paste-block registry to
    /// compute the magnitude of an edit (`len_after - len_before`).
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Set the cursor to an explicit byte offset (clamped to a char
    /// boundary at or before `pos`). Used to snap the cursor onto a
    /// paste-block boundary so it never lands in a block interior
    /// (composer-paste-handling).
    pub fn set_cursor(&mut self, pos: usize) {
        let pos = pos.min(self.buffer.len());
        // Walk back to the nearest char boundary (no-op for ASCII /
        // boundary positions).
        let mut p = pos;
        while p > 0 && !self.buffer.is_char_boundary(p) {
            p -= 1;
        }
        self.cursor = p;
    }

    /// Insert a whole string at the cursor and advance past it. Used by
    /// the paste path to drop a placeholder (or raw pasted text) in one
    /// step so the registry can record the exact byte span.
    pub fn insert_str(&mut self, s: &str) {
        self.buffer.insert_str(self.cursor, s);
        self.cursor += s.len();
    }

    /// Run a cursor-moving motion closure without keeping its effect:
    /// returns the byte offset the motion *would* land on and restores the
    /// original cursor. Used by the paste-block-aware vim operators to
    /// compute a deletion range before deciding whether it crosses a block
    /// (composer-paste-handling).
    pub fn probe_motion<F: FnOnce(&mut Self)>(&mut self, motion: F) -> usize {
        let saved = self.cursor;
        motion(self);
        let landed = self.cursor;
        self.cursor = saved;
        landed
    }

    /// Position the cursor from terminal visual-row/cell coordinates,
    /// using the same display-width soft-wrap model as the input renderer.
    pub fn set_cursor_from_visual_position(
        &mut self,
        row: usize,
        col: usize,
        prefix: usize,
        inner_width: usize,
    ) {
        self.cursor = byte_for_visual_position(&self.buffer, row, col, prefix, inner_width);
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn vim_mode(&self) -> VimMode {
        self.vim_mode
    }

    pub fn set_vim_mode(&mut self, mode: VimMode) {
        self.vim_mode = mode;
    }

    pub fn vim_enabled(&self) -> bool {
        self.vim_enabled
    }

    /// Reset to empty + cursor at start. Used after submit and on `Esc`
    /// while a slash command is being composed.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
    }

    /// Replace the entire buffer content, resetting cursor to end.
    pub fn set(&mut self, text: impl Into<String>) {
        self.buffer = text.into();
        self.cursor = self.buffer.len();
    }

    pub fn insert_char(&mut self, ch: char) {
        self.buffer.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }

    pub fn delete_left(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let previous = self.buffer[..self.cursor]
            .char_indices()
            .last()
            .map(|(idx, _)| idx)
            .unwrap_or(0);
        self.buffer.drain(previous..self.cursor);
        self.cursor = previous;
    }

    /// Drain the byte range `[start, end)` and place the cursor at
    /// `start`. Used by the whole-`@`-tag delete (the range comes from a
    /// tag-boundary scan, so it is always on char boundaries).
    pub fn delete_range(&mut self, start: usize, end: usize) {
        if start >= end || end > self.buffer.len() {
            return;
        }
        self.buffer.drain(start..end);
        self.cursor = start;
    }

    pub fn delete_right(&mut self) {
        if self.cursor >= self.buffer.len() {
            return;
        }
        let next_len = self.buffer[self.cursor..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(0);
        self.buffer.drain(self.cursor..self.cursor + next_len);
    }

    pub fn move_left(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.cursor = self.buffer[..self.cursor]
            .char_indices()
            .last()
            .map(|(idx, _)| idx)
            .unwrap_or(0);
    }

    pub fn move_right(&mut self) {
        if self.cursor >= self.buffer.len() {
            return;
        }
        if let Some(next) = self.buffer[self.cursor..].chars().next() {
            self.cursor += next.len_utf8();
        }
    }

    pub fn move_up(&mut self) {
        let before = &self.buffer[..self.cursor];
        let Some(prev_nl) = before.rfind('\n') else {
            return;
        };
        let curr_line_start = prev_nl + 1;
        let col = display_width(&before[curr_line_start..]);
        let prev_line_end = prev_nl;
        let prev_line_start = self.buffer[..prev_line_end]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let prev_line = &self.buffer[prev_line_start..prev_line_end];
        let target_byte = byte_for_display_col(prev_line, col);
        self.cursor = prev_line_start + target_byte;
    }

    pub fn move_down(&mut self) {
        let buf = &self.buffer;
        let cursor = self.cursor;
        let line_start = buf[..cursor].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let col = display_width(&buf[line_start..cursor]);
        let Some(rel_nl) = buf[cursor..].find('\n') else {
            return;
        };
        let next_line_start = cursor + rel_nl + 1;
        let next_line_end = buf[next_line_start..]
            .find('\n')
            .map(|i| next_line_start + i)
            .unwrap_or(buf.len());
        let next_line = &buf[next_line_start..next_line_end];
        let target_byte = byte_for_display_col(next_line, col);
        self.cursor = next_line_start + target_byte;
    }

    pub fn move_line_start(&mut self) {
        let line_start = self.buffer[..self.cursor]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        self.cursor = line_start;
    }

    pub fn move_line_end(&mut self) {
        let buf = &self.buffer;
        let line_end = buf[self.cursor..]
            .find('\n')
            .map(|i| self.cursor + i)
            .unwrap_or(buf.len());
        self.cursor = line_end;
    }

    /// Move to the start of the buffer (vim `gg`).
    pub fn move_buffer_start(&mut self) {
        self.cursor = 0;
    }

    /// Move to the start of the *last* line of the buffer (vim `G`).
    pub fn move_buffer_end(&mut self) {
        // Land at the start of the final line — matches vim's `G` when
        // no count is given (it goes to the last line, not the last
        // char).
        if let Some(last_nl) = self.buffer.rfind('\n') {
            self.cursor = last_nl + 1;
        } else {
            self.cursor = 0;
        }
    }

    /// Vim word-forward (`w`/`W`). `big_word=true` for `W` — uses
    /// whitespace boundaries only; `big_word=false` for `w` — also
    /// stops at punctuation transitions.
    pub fn move_word_forward(&mut self, big_word: bool) {
        let bytes = self.buffer.as_bytes();
        let n = bytes.len();
        if self.cursor >= n {
            return;
        }
        let classify = |ch: char| -> u8 {
            if ch.is_whitespace() {
                0
            } else if big_word || ch.is_alphanumeric() || ch == '_' {
                1
            } else {
                2 // punctuation (only meaningful for `w`)
            }
        };
        let mut it = self.buffer[self.cursor..].char_indices().peekable();
        let start_class = it.peek().map(|(_, c)| classify(*c)).unwrap_or(0);
        // Step 1: walk past the current class.
        while let Some((_, c)) = it.peek().copied() {
            if classify(c) == start_class && start_class != 0 {
                it.next();
            } else {
                break;
            }
        }
        // Step 2: walk past any whitespace.
        while let Some((_, c)) = it.peek().copied() {
            if c.is_whitespace() {
                it.next();
            } else {
                break;
            }
        }
        if let Some((rel, _)) = it.peek().copied() {
            self.cursor += rel;
        } else {
            self.cursor = n;
        }
    }

    /// Delete from cursor to the position vim-`w`/`W` would land at.
    #[cfg(test)]
    pub fn delete_word_forward(&mut self, big_word: bool) {
        let start = self.cursor;
        self.move_word_forward(big_word);
        let end = self.cursor;
        if end > start {
            self.buffer.drain(start..end);
            self.cursor = start;
        }
    }

    /// Delete from cursor back to the position vim-`b`/`B` would land at.
    #[cfg(test)]
    pub fn delete_word_backward(&mut self, big_word: bool) {
        let end = self.cursor;
        self.move_word_backward(big_word);
        let start = self.cursor;
        if end > start {
            self.buffer.drain(start..end);
        }
    }

    /// `d$` — delete from cursor to end of current line.
    pub fn delete_to_line_end(&mut self) {
        let start = self.cursor;
        self.move_line_end();
        let end = self.cursor;
        if end > start {
            self.buffer.drain(start..end);
            self.cursor = start;
        }
    }

    /// `d0` — delete from cursor back to start of current line.
    #[cfg(test)]
    pub fn delete_to_line_start(&mut self) {
        let end = self.cursor;
        self.move_line_start();
        let start = self.cursor;
        if end > start {
            self.buffer.drain(start..end);
        }
    }

    /// `dd` — delete the line under the cursor (including its trailing
    /// `\n`, so a subsequent paste behaves linewise). On the *last*
    /// line — which has no trailing `\n` to swallow — we delete the
    /// preceding `\n` instead so the buffer doesn't end up with a
    /// dangling empty trailing line. Matches vim's `dd` semantics:
    /// the cursor lands on the start of the previous line.
    pub fn delete_current_line(&mut self) {
        let line_start = self.buffer[..self.cursor]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let trailing_nl = self.buffer[self.cursor..].find('\n');
        let (start, end) = match trailing_nl {
            Some(i) => (line_start, self.cursor + i + 1),
            None if line_start > 0 => {
                // Last line of a multi-line buffer — swallow the
                // newline that precedes us.
                (line_start - 1, self.buffer.len())
            }
            None => {
                // Single-line buffer — just delete the whole thing.
                (0, self.buffer.len())
            }
        };
        self.buffer.drain(start..end);
        self.cursor = start.min(self.buffer.len());
        // Snap to start of the (now-)current line for vim parity.
        let line_start = self.buffer[..self.cursor]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        self.cursor = line_start;
    }

    /// `o` — open a new empty line below the current one and land at
    /// its start. Caller is responsible for switching to Insert mode.
    pub fn open_below(&mut self) {
        self.move_line_end();
        self.insert_char('\n');
    }

    /// `O` — open a new empty line above the current one and land on
    /// it. Caller is responsible for switching to Insert mode.
    pub fn open_above(&mut self) {
        self.move_line_start();
        self.insert_char('\n');
        // insert_char advanced the cursor past the new `\n`; step one
        // byte back so we land at the start of the empty line we just
        // opened. The `\n` is single-byte so byte-decrement is safe.
        self.cursor = self.cursor.saturating_sub(1);
    }

    /// Vim word-backward (`b`/`B`).
    pub fn move_word_backward(&mut self, big_word: bool) {
        if self.cursor == 0 {
            return;
        }
        let classify = |ch: char| -> u8 {
            if ch.is_whitespace() {
                0
            } else if big_word || ch.is_alphanumeric() || ch == '_' {
                1
            } else {
                2
            }
        };
        let before = &self.buffer[..self.cursor];
        let chars: Vec<(usize, char)> = before.char_indices().collect();
        let mut i = chars.len();
        // Step 1: skip whitespace immediately before the cursor.
        while i > 0 && chars[i - 1].1.is_whitespace() {
            i -= 1;
        }
        if i == 0 {
            self.cursor = 0;
            return;
        }
        // Step 2: while previous char is same class as char i-1, keep going.
        let target_class = classify(chars[i - 1].1);
        while i > 0 && classify(chars[i - 1].1) == target_class && target_class != 0 {
            i -= 1;
        }
        self.cursor = chars.get(i).map(|(b, _)| *b).unwrap_or(0);
    }

    /// Word-class of a char for `w`/`b`/`e` motions. `0` whitespace,
    /// `1` word (alnum/underscore, or any non-space when `big_word`),
    /// `2` punctuation (only distinguished for small-word motions).
    fn word_class(ch: char, big_word: bool) -> u8 {
        if ch.is_whitespace() {
            0
        } else if big_word || ch.is_alphanumeric() || ch == '_' {
            1
        } else {
            2
        }
    }

    /// Vim `e`/`E` — move to the end of the current/next word. Lands on
    /// the last char of the word (inclusive), so an operator over `e`
    /// includes that char.
    pub fn move_word_end(&mut self, big_word: bool) {
        let chars: Vec<(usize, char)> = self.buffer.char_indices().collect();
        // Index of the char the cursor sits on.
        let Some(mut i) = chars.iter().position(|(b, _)| *b >= self.cursor) else {
            return;
        };
        // If the cursor is already on a word-end (or whitespace), step
        // forward one so a repeat advances.
        i += 1;
        // Skip whitespace.
        while i < chars.len() && chars[i].1.is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            // No further word — land on the last char of the buffer.
            if let Some((b, _)) = chars.last() {
                self.cursor = *b;
            }
            return;
        }
        let class = Self::word_class(chars[i].1, big_word);
        // Advance to the last char of this run.
        while i + 1 < chars.len()
            && Self::word_class(chars[i + 1].1, big_word) == class
            && class != 0
        {
            i += 1;
        }
        self.cursor = chars[i].0;
    }

    /// Vim `ge`/`gE` — move backward to the end of the previous word.
    /// Lands on the last char of that word.
    pub fn move_word_end_backward(&mut self, big_word: bool) {
        if self.cursor == 0 {
            return;
        }
        let chars: Vec<(usize, char)> = self.buffer.char_indices().collect();
        // Index of the char the cursor sits on (or one past end).
        let mut i = chars
            .iter()
            .position(|(b, _)| *b >= self.cursor)
            .unwrap_or(chars.len());
        // Step back off the current char.
        if i == 0 {
            return;
        }
        i -= 1;
        // If we're mid-word, skip back to the gap first (so we land on the
        // *previous* word's end, not the current char).
        let cur_class = Self::word_class(chars[i].1, big_word);
        if cur_class != 0 {
            while i > 0 && Self::word_class(chars[i - 1].1, big_word) == cur_class {
                i -= 1;
            }
            // `i` now at the start of the current run; step one before it.
            if i == 0 {
                self.cursor = 0;
                return;
            }
            i -= 1;
        }
        // Skip whitespace backward to the previous word's last char.
        while i > 0 && chars[i].1.is_whitespace() {
            i -= 1;
        }
        if chars[i].1.is_whitespace() {
            self.cursor = 0;
        } else {
            self.cursor = chars[i].0;
        }
    }

    /// Vim `%` — jump to the matching bracket of `() [] {}`. From the
    /// cursor, finds the first bracket at/after the cursor on the current
    /// line, then jumps to its match (which may be on another line).
    /// No-op when there's no bracket ahead on the line or no match.
    pub fn match_bracket(&mut self) {
        const PAIRS: [(char, char); 3] = [('(', ')'), ('[', ']'), ('{', '}')];
        // Find the first bracket at/after the cursor on the current line.
        let line_end = self.buffer[self.cursor..]
            .find('\n')
            .map(|i| self.cursor + i)
            .unwrap_or(self.buffer.len());
        let mut bracket_pos = None;
        for (off, ch) in self.buffer[self.cursor..line_end].char_indices() {
            if PAIRS.iter().any(|(o, c)| *o == ch || *c == ch) {
                bracket_pos = Some(self.cursor + off);
                break;
            }
        }
        let Some(pos) = bracket_pos else { return };
        let ch = self.buffer[pos..].chars().next().unwrap();
        // Forward search for an opener; backward for a closer.
        if let Some((open, close)) = PAIRS.iter().find(|(o, _)| *o == ch)
            && let Some(m) = self.scan_match(pos, *open, *close, true)
        {
            self.cursor = m;
        } else if let Some((open, close)) = PAIRS.iter().find(|(_, c)| *c == ch)
            && let Some(m) = self.scan_match(pos, *open, *close, false)
        {
            self.cursor = m;
        }
    }

    /// Scan from `from` (which holds `open` when `forward`, else `close`)
    /// for the matching delimiter, honoring nesting. Returns the byte
    /// offset of the match, or `None` if unbalanced.
    fn scan_match(&self, from: usize, open: char, close: char, forward: bool) -> Option<usize> {
        let mut depth = 0i32;
        if forward {
            for (off, c) in self.buffer[from..].char_indices() {
                if c == open {
                    depth += 1;
                } else if c == close {
                    depth -= 1;
                    if depth == 0 {
                        return Some(from + off);
                    }
                }
            }
        } else {
            for (off, c) in self.buffer[..from + close.len_utf8()].char_indices().rev() {
                if c == close {
                    depth += 1;
                } else if c == open {
                    depth -= 1;
                    if depth == 0 {
                        return Some(off);
                    }
                }
            }
        }
        None
    }

    // ---- Visual selection + register --------------------------------

    /// Enter visual mode at the cursor: anchor the selection here and set
    /// `mode` (must be [`VimMode::Visual`] or `VisualLine`).
    pub fn begin_visual(&mut self, mode: VimMode) {
        self.visual_anchor = Some(self.cursor);
        self.vim_mode = mode;
    }

    /// Leave visual mode (drop the anchor, return to Normal).
    pub fn end_visual(&mut self) {
        self.visual_anchor = None;
        self.vim_mode = VimMode::Normal;
    }

    /// Drop the visual anchor without changing the mode. Used after a
    /// visual operation that sets the post-op mode itself (Change→Insert).
    pub fn clear_visual_anchor(&mut self) {
        self.visual_anchor = None;
    }

    /// Set the visual selection explicitly: anchor at `anchor`, cursor at
    /// `cursor` (both snapped to char boundaries), in charwise visual.
    /// Used when a text object resolves the selection range.
    pub fn set_visual_selection(&mut self, anchor: usize, cursor: usize) {
        self.set_cursor(anchor);
        self.visual_anchor = Some(self.cursor);
        self.set_cursor(cursor);
        self.vim_mode = VimMode::Visual;
    }

    /// The byte range `[start, end)` of the active visual selection,
    /// resolved for the current mode. Charwise is inclusive of the cell
    /// the cursor sits on (so the trailing char is included); linewise
    /// spans whole lines (including the trailing `\n` when one exists).
    /// `None` when not in visual mode.
    pub fn visual_range(&self) -> Option<(usize, usize)> {
        let anchor = self.visual_anchor?;
        match self.vim_mode {
            VimMode::Visual => {
                let (lo, hi) = (anchor.min(self.cursor), anchor.max(self.cursor));
                // Inclusive of the cell at `hi`: extend to the next char
                // boundary (stops at buffer end).
                let hi_inc = self.buffer[hi..]
                    .chars()
                    .next()
                    .map(|c| hi + c.len_utf8())
                    .unwrap_or(hi);
                Some((lo, hi_inc))
            }
            VimMode::VisualLine => {
                let (lo_pos, hi_pos) = (anchor.min(self.cursor), anchor.max(self.cursor));
                let start = self.buffer[..lo_pos]
                    .rfind('\n')
                    .map(|i| i + 1)
                    .unwrap_or(0);
                // Include the trailing newline of the last line when present.
                let end = self.buffer[hi_pos..]
                    .find('\n')
                    .map(|i| hi_pos + i + 1)
                    .unwrap_or(self.buffer.len());
                Some((start, end))
            }
            _ => None,
        }
    }

    /// Yank the byte range `[start, end)` into the register without
    /// modifying the buffer. `linewise` records the register kind.
    pub fn yank_range(&mut self, start: usize, end: usize, linewise: bool) {
        if start >= end || end > self.buffer.len() {
            return;
        }
        let mut text = self.buffer[start..end].to_string();
        if linewise && !text.ends_with('\n') {
            text.push('\n');
        }
        self.register = Register { text, linewise };
    }

    /// `yy` — yank the current line linewise (including a trailing `\n`).
    pub fn yank_current_line(&mut self) {
        let line_start = self.buffer[..self.cursor]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let line_end = self.buffer[self.cursor..]
            .find('\n')
            .map(|i| self.cursor + i + 1)
            .unwrap_or(self.buffer.len());
        self.yank_range(line_start, line_end, true);
    }

    /// Delete the byte range `[start, end)` into the register (the `d`/`c`
    /// path also populates the register, per vim). Leaves the cursor at
    /// `start` clamped to a char boundary. `linewise` records the kind.
    pub fn cut_range(&mut self, start: usize, end: usize, linewise: bool) {
        if start >= end || end > self.buffer.len() {
            return;
        }
        let mut text = self.buffer[start..end].to_string();
        if linewise && !text.ends_with('\n') {
            text.push('\n');
        }
        self.register = Register { text, linewise };
        self.buffer.drain(start..end);
        self.set_cursor(start);
    }

    /// `p` — paste the register after the cursor (charwise) or on the line
    /// below (linewise). Leaves the cursor per vim: for charwise, on the
    /// last pasted char; for linewise, at the start of the first pasted
    /// line. No-op when the register is empty.
    pub fn paste_after(&mut self) {
        if self.register.text.is_empty() {
            return;
        }
        if self.register.linewise {
            // Insert below the current line.
            let line_end = self.buffer[self.cursor..]
                .find('\n')
                .map(|i| self.cursor + i + 1)
                .unwrap_or(self.buffer.len());
            let text = self.linewise_payload();
            // When the current line has no trailing newline (last line),
            // we must insert a leading newline and drop the payload's
            // trailing one so we don't create a dangling empty line.
            if line_end == self.buffer.len() && !self.buffer.ends_with('\n') {
                let body = text.strip_suffix('\n').unwrap_or(&text);
                let insert = format!("\n{body}");
                self.buffer.insert_str(line_end, &insert);
                self.cursor = line_end + 1;
            } else {
                self.buffer.insert_str(line_end, &text);
                self.cursor = line_end;
            }
        } else {
            // Charwise: insert after the cursor cell.
            let at = self.buffer[self.cursor..]
                .chars()
                .next()
                .map(|c| self.cursor + c.len_utf8())
                .unwrap_or(self.cursor);
            self.buffer.insert_str(at, &self.register.text);
            // Land on the last pasted char.
            let end = at + self.register.text.len();
            self.cursor = self.last_char_start_before(end);
        }
    }

    /// `P` — paste the register before the cursor (charwise) or on the
    /// line above (linewise).
    pub fn paste_before(&mut self) {
        if self.register.text.is_empty() {
            return;
        }
        if self.register.linewise {
            let line_start = self.buffer[..self.cursor]
                .rfind('\n')
                .map(|i| i + 1)
                .unwrap_or(0);
            let text = self.linewise_payload();
            self.buffer.insert_str(line_start, &text);
            self.cursor = line_start;
        } else {
            let at = self.cursor;
            self.buffer.insert_str(at, &self.register.text);
            let end = at + self.register.text.len();
            self.cursor = self.last_char_start_before(end);
        }
    }

    /// The linewise register payload, guaranteed to end in `\n` so a
    /// line-paste tiles cleanly.
    fn linewise_payload(&self) -> String {
        if self.register.text.ends_with('\n') {
            self.register.text.clone()
        } else {
            format!("{}\n", self.register.text)
        }
    }

    /// Byte offset of the *start* of the char immediately before `end`
    /// (the last char of a `[start, end)` span). Used to land the cursor
    /// on the last pasted char (vim `p`/`P` semantics). Returns the
    /// nearest char boundary `< end`, or 0 when `end` is at the start.
    fn last_char_start_before(&self, end: usize) -> usize {
        let end = end.min(self.buffer.len());
        self.buffer[..end]
            .char_indices()
            .next_back()
            .map(|(i, _)| i)
            .unwrap_or(0)
    }

    // ---- Text objects -----------------------------------------------

    /// The byte range `[start, end)` of a text object at the cursor, or
    /// `None` when there's no match (e.g. unbalanced quotes/brackets).
    /// `around` selects `a` (include delimiters / trailing whitespace);
    /// otherwise `i` (inner). `obj` is the text-object selector char:
    /// `w` (word), a quote (`"` `'` `` ` ``), or a bracket
    /// (`(` `)` `[` `]` `{` `}` `<` `>`).
    pub fn text_object_range(&self, obj: char, around: bool) -> Option<(usize, usize)> {
        match obj {
            'w' => self.word_object(around),
            '"' | '\'' | '`' => self.quote_object(obj, around),
            '(' | ')' | 'b' => self.bracket_object('(', ')', around),
            '[' | ']' => self.bracket_object('[', ']', around),
            '{' | '}' | 'B' => self.bracket_object('{', '}', around),
            '<' | '>' => self.bracket_object('<', '>', around),
            _ => None,
        }
    }

    /// `iw`/`aw` — the word (or whitespace run) under the cursor. `aw`
    /// also swallows trailing whitespace (or leading, if there's no
    /// trailing), matching vim.
    fn word_object(&self, around: bool) -> Option<(usize, usize)> {
        let chars: Vec<(usize, char)> = self.buffer.char_indices().collect();
        if chars.is_empty() {
            return None;
        }
        let i = chars
            .iter()
            .position(|(b, _)| *b >= self.cursor)
            .unwrap_or(chars.len() - 1)
            .min(chars.len() - 1);
        // Class of the run under the cursor (whitespace counts as a run,
        // matching vim's `iw` on a space).
        let class = Self::word_class(chars[i].1, false);
        let mut lo = i;
        while lo > 0 && Self::word_class(chars[lo - 1].1, false) == class {
            lo -= 1;
        }
        let mut hi = i;
        while hi + 1 < chars.len() && Self::word_class(chars[hi + 1].1, false) == class {
            hi += 1;
        }
        let start = chars[lo].0;
        let mut end = chars[hi].0 + chars[hi].1.len_utf8();
        if around && class != 0 {
            // Swallow trailing whitespace; if none, leading whitespace.
            let mut j = hi + 1;
            let mut swallowed = false;
            while j < chars.len() && chars[j].1.is_whitespace() {
                end = chars[j].0 + chars[j].1.len_utf8();
                j += 1;
                swallowed = true;
            }
            if !swallowed {
                let mut k = lo;
                let mut new_start = start;
                while k > 0 && chars[k - 1].1.is_whitespace() {
                    new_start = chars[k - 1].0;
                    k -= 1;
                }
                return Some((new_start, end));
            }
        }
        Some((start, end))
    }

    /// `i"`/`a"` etc. — the text inside the nearest pair of `q` quotes on
    /// the current line that encloses (or starts at) the cursor. `around`
    /// includes the quote chars. Returns `None` when no matching pair is
    /// found on the line.
    fn quote_object(&self, q: char, around: bool) -> Option<(usize, usize)> {
        let line_start = self.buffer[..self.cursor]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let line_end = self.buffer[self.cursor..]
            .find('\n')
            .map(|i| self.cursor + i)
            .unwrap_or(self.buffer.len());
        let line = &self.buffer[line_start..line_end];
        // Positions (byte offsets within the buffer) of the quote char.
        let quotes: Vec<usize> = line
            .char_indices()
            .filter(|(_, c)| *c == q)
            .map(|(off, _)| line_start + off)
            .collect();
        // Pair them left-to-right; pick the pair whose span contains the
        // cursor (inclusive of the opening quote).
        let mut pi = 0;
        while pi + 1 < quotes.len() {
            let open = quotes[pi];
            let close = quotes[pi + 1];
            if self.cursor >= open && self.cursor <= close {
                return if around {
                    Some((open, close + q.len_utf8()))
                } else {
                    // Inner of an empty pair (`""`) is a zero-width range;
                    // the caller treats start==end as a no-op.
                    Some((open + q.len_utf8(), close))
                };
            }
            pi += 2;
        }
        None
    }

    /// `i(`/`a(` etc. — the text inside the nearest `open`/`close` pair
    /// enclosing the cursor. `around` includes the brackets. Honors
    /// nesting; returns `None` when unbalanced / no enclosing pair.
    fn bracket_object(&self, open: char, close: char, around: bool) -> Option<(usize, usize)> {
        // Find the enclosing opener: scan left tracking depth.
        let open_pos = self.enclosing_open(open, close)?;
        let close_pos = self.scan_match(open_pos, open, close, true)?;
        if around {
            Some((open_pos, close_pos + close.len_utf8()))
        } else {
            Some((open_pos + open.len_utf8(), close_pos))
        }
    }

    /// Byte offset of the opener of the bracket pair that encloses the
    /// cursor (or that the cursor sits on). `None` if not inside a pair.
    fn enclosing_open(&self, open: char, close: char) -> Option<usize> {
        // If the cursor is on an opener, that's our pair.
        if let Some(c) = self.buffer[self.cursor..].chars().next()
            && c == open
        {
            return Some(self.cursor);
        }
        let mut depth = 0i32;
        for (off, c) in self.buffer[..self.cursor].char_indices().rev() {
            if c == close {
                depth += 1;
            } else if c == open {
                if depth == 0 {
                    return Some(off);
                }
                depth -= 1;
            }
        }
        None
    }

    /// Newline count + 1 (or 1 when empty). Useful for sizing the input box.
    // Retained for input-box sizing; not yet called.
    #[allow(dead_code)]
    pub fn line_count(&self) -> usize {
        if self.buffer.is_empty() {
            1
        } else {
            self.buffer.split('\n').count()
        }
    }

    /// Substring after the most-recent `@` if the cursor sits inside an
    /// `@...` token (no whitespace between the `@` and the cursor). The
    /// `@` must itself be at a word boundary (buffer start or after
    /// whitespace) so emails like `user@example.com` don't trigger.
    pub fn at_query(&self) -> Option<&str> {
        let before = &self.buffer[..self.cursor];
        let at_idx = before.rfind('@')?;
        // Whitespace check on the byte preceding `@` (or buffer start).
        if at_idx > 0 {
            let prev = before[..at_idx].chars().next_back()?;
            if !prev.is_whitespace() {
                return None;
            }
        }
        let body = &before[at_idx + 1..];
        // Quoted tag in progress (`@"path with `): the query continues
        // across spaces until the closing quote, so the popup keeps
        // narrowing on a name with spaces. A closing quote before the
        // cursor means the tag is finished — no active query.
        if let Some(inner) = body.strip_prefix('"') {
            if inner.contains('"') {
                return None;
            }
            return Some(inner);
        }
        if body.chars().any(char::is_whitespace) {
            return None;
        }
        Some(body)
    }

    /// Replace the `@partial` immediately left of the cursor with
    /// `@{replacement}`. No-op if no `@` token is active.
    pub fn replace_at_token(&mut self, replacement: &str) {
        let Some(at_idx) = self.buffer[..self.cursor].rfind('@') else {
            return;
        };
        // Confirm boundary — mirror at_query semantics.
        if at_idx > 0 {
            let prev = self.buffer[..at_idx].chars().next_back();
            if !matches!(prev, Some(c) if c.is_whitespace()) {
                return;
            }
        }
        let body_end = self.cursor;
        let mut new = String::with_capacity(self.buffer.len() + replacement.len());
        new.push_str(&self.buffer[..at_idx]);
        new.push('@');
        new.push_str(replacement);
        let new_cursor = new.len();
        new.push_str(&self.buffer[body_end..]);
        self.buffer = new;
        self.cursor = new_cursor;
    }

    /// Cursor's (line, column) measured in terminal display columns.
    pub fn cursor_line_col(&self) -> (usize, usize) {
        let before = &self.buffer[..self.cursor];
        let line = before.matches('\n').count();
        let line_start = before.rfind('\n').map(|i| i + 1).unwrap_or(0);
        let col = display_width(&before[line_start..]);
        (line, col)
    }

    /// Self-contained editor vim-key dispatch for embedded text editors that
    /// reuse this composer as their editing engine (e.g. the notes
    /// scratchpad). It drives the **same** motions/operators/text-objects/
    /// visual-mode/register methods the app composer's dispatch in
    /// `app::input` drives — there is no second vim implementation; this is
    /// the editor-only routing without the composer-app concerns (prompt
    /// history on `j`/`k`, the slash menu, `@`-tagging, paste blocks,
    /// clipboard mirroring, submit-on-Enter). Plain text + multi-line
    /// editing only.
    ///
    /// Returns `true` when the key was consumed as an editing action. When
    /// vim is disabled, only Insert-mode plain editing applies. Esc in Normal
    /// is **not** consumed (returns `false`) so an embedding dialog can use it
    /// to leave edit mode.
    pub fn handle_vim_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::{KeyCode, KeyModifiers};
        if !self.vim_enabled {
            return self.handle_insert_key(key);
        }
        match self.vim_mode {
            VimMode::Insert => {
                if matches!(key.code, KeyCode::Esc) {
                    self.vim_mode = VimMode::Normal;
                    self.move_left();
                    return true;
                }
                self.handle_insert_key(key)
            }
            VimMode::Normal => self.handle_normal_key(key),
            VimMode::Operator(op) => {
                if matches!(key.code, KeyCode::Esc) {
                    self.vim_mode = VimMode::Normal;
                    self.pending_g = false;
                    self.pending_find = None;
                    self.pending_text_object = None;
                    return true;
                }
                let _ = KeyModifiers::empty();
                self.handle_operator_key(op, key)
            }
            VimMode::Visual | VimMode::VisualLine => self.handle_visual_key(key),
        }
    }

    /// Plain Insert-mode editing shared by the vim-on Insert path and the
    /// vim-off path. Returns `true` when the key produced an edit/motion.
    fn handle_insert_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::{KeyCode, KeyModifiers};
        match key.code {
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.insert_char(ch);
                true
            }
            // Ctrl+J / Shift+Enter / Alt+Enter insert a newline.
            KeyCode::Char('j') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.insert_char('\n');
                true
            }
            KeyCode::Enter => {
                self.insert_char('\n');
                true
            }
            KeyCode::Backspace => {
                self.delete_left();
                true
            }
            KeyCode::Delete => {
                self.delete_right();
                true
            }
            KeyCode::Left => {
                self.move_left();
                true
            }
            KeyCode::Right => {
                self.move_right();
                true
            }
            KeyCode::Up => {
                self.move_up();
                true
            }
            KeyCode::Down => {
                self.move_down();
                true
            }
            KeyCode::Home => {
                self.move_line_start();
                true
            }
            KeyCode::End => {
                self.move_line_end();
                true
            }
            _ => false,
        }
    }

    /// Normal-mode dispatch for the embedded-editor path. `j`/`k` move by
    /// buffer line here (no prompt history), and Esc is not consumed.
    fn handle_normal_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;
        // Arrow keys + Backspace/Delete remain live in Normal.
        match key.code {
            KeyCode::Esc => {
                self.pending_g = false;
                return false;
            }
            KeyCode::Left => {
                self.move_left();
                self.pending_g = false;
                return true;
            }
            KeyCode::Right => {
                self.move_right();
                self.pending_g = false;
                return true;
            }
            KeyCode::Up => {
                self.move_up();
                self.pending_g = false;
                return true;
            }
            KeyCode::Down => {
                self.move_down();
                self.pending_g = false;
                return true;
            }
            KeyCode::Char(_) => {}
            _ => return false,
        }
        let KeyCode::Char(ch) = key.code else {
            return false;
        };
        let was_pending_g = self.pending_g;
        let pending_find = self.pending_find;
        self.pending_g = false;
        self.pending_find = None;
        if let Some(mut spec) = pending_find {
            spec.target = ch;
            self.apply_find(spec, true);
            return true;
        }
        if was_pending_g && (ch == 'e' || ch == 'E') {
            self.move_word_end_backward(ch == 'E');
            return true;
        }
        match ch {
            'h' => self.move_left(),
            'l' => self.move_right(),
            'j' => self.move_down(),
            'k' => self.move_up(),
            'w' => self.move_word_forward(false),
            'W' => self.move_word_forward(true),
            'b' => self.move_word_backward(false),
            'B' => self.move_word_backward(true),
            'e' => self.move_word_end(false),
            'E' => self.move_word_end(true),
            '0' => self.move_line_start(),
            '$' => self.move_line_end(),
            'G' => self.move_buffer_end(),
            '%' => self.match_bracket(),
            ';' => {
                self.repeat_find(false);
            }
            ',' => {
                self.repeat_find(true);
            }
            'g' => {
                if was_pending_g {
                    self.move_buffer_start();
                } else {
                    self.pending_g = true;
                }
            }
            'f' => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: false,
                    forward: true,
                })
            }
            'F' => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: false,
                    forward: false,
                })
            }
            't' => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: true,
                    forward: true,
                })
            }
            'T' => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: true,
                    forward: false,
                })
            }
            'v' => self.begin_visual(VimMode::Visual),
            'V' => self.begin_visual(VimMode::VisualLine),
            'i' => self.vim_mode = VimMode::Insert,
            'I' => {
                self.move_line_start();
                self.vim_mode = VimMode::Insert;
            }
            'a' => {
                self.move_right();
                self.vim_mode = VimMode::Insert;
            }
            'A' => {
                self.move_line_end();
                self.vim_mode = VimMode::Insert;
            }
            'x' => {
                let at = self.cursor;
                let end = self.buffer[at..]
                    .chars()
                    .next()
                    .map(|c| at + c.len_utf8())
                    .unwrap_or(at);
                if end > at {
                    self.cut_range(at, end, false);
                }
            }
            'D' => self.delete_to_line_end(),
            'C' => {
                self.delete_to_line_end();
                self.vim_mode = VimMode::Insert;
            }
            'o' => {
                self.open_below();
                self.vim_mode = VimMode::Insert;
            }
            'O' => {
                self.open_above();
                self.vim_mode = VimMode::Insert;
            }
            'p' => self.paste_after(),
            'P' => self.paste_before(),
            'd' => self.vim_mode = VimMode::Operator(Operator::Delete),
            'c' => self.vim_mode = VimMode::Operator(Operator::Change),
            'y' => self.vim_mode = VimMode::Operator(Operator::Yank),
            _ => return false,
        }
        true
    }

    /// Operator-pending dispatch (`d`/`c`/`y` + motion / text object). Mirrors
    /// the app composer's operator handling, sans paste-block widening.
    fn handle_operator_key(&mut self, op: Operator, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;
        // Pending find target (`df<c>`, `ct<c>`).
        if let Some(mut spec) = self.pending_find {
            self.pending_find = None;
            if let KeyCode::Char(ch) = key.code {
                spec.target = ch;
                let from = self.cursor;
                let landed = self.find_target(spec);
                self.last_find = Some(spec);
                if let Some(to) = landed {
                    let hi = if spec.forward {
                        self.buffer[to..]
                            .chars()
                            .next()
                            .map(|c| to + c.len_utf8())
                            .unwrap_or(to)
                    } else {
                        to
                    };
                    let (lo, hi) = if spec.forward { (from, hi) } else { (to, from) };
                    self.apply_operator_range(op, lo, hi);
                    self.finish_operator(op);
                    return true;
                }
            }
            self.vim_mode = VimMode::Normal;
            return true;
        }
        // Pending text object (`diw`, `ca"`).
        if let Some(around) = self.pending_text_object.take() {
            if let KeyCode::Char(obj) = key.code
                && let Some((lo, hi)) = self.text_object_range(obj, around)
                && lo < hi
            {
                self.apply_operator_range(op, lo, hi);
                self.finish_operator(op);
                return true;
            }
            self.vim_mode = VimMode::Normal;
            return true;
        }
        // Pending `g` (`dgg`/`dge`).
        if let KeyCode::Char(c @ ('g' | 'e' | 'E')) = key.code {
            if self.pending_g {
                self.pending_g = false;
                if c == 'g' {
                    let from = self.cursor;
                    let to = self.probe_motion(|s| s.move_buffer_start());
                    self.apply_operator_range(op, to.min(from), to.max(from));
                } else {
                    let big = c == 'E';
                    let from = self.cursor;
                    let to = self.probe_motion(|s| s.move_word_end_backward(big));
                    self.apply_operator_range(op, to.min(from), to.max(from));
                }
                self.finish_operator(op);
                return true;
            }
            if c == 'g' {
                self.pending_g = true;
                return true;
            }
        }
        self.pending_g = false;
        match key.code {
            KeyCode::Char('f') => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: false,
                    forward: true,
                });
                return true;
            }
            KeyCode::Char('F') => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: false,
                    forward: false,
                });
                return true;
            }
            KeyCode::Char('t') => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: true,
                    forward: true,
                });
                return true;
            }
            KeyCode::Char('T') => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: true,
                    forward: false,
                });
                return true;
            }
            KeyCode::Char('i') => {
                self.pending_text_object = Some(false);
                return true;
            }
            KeyCode::Char('a') => {
                self.pending_text_object = Some(true);
                return true;
            }
            _ => {}
        }
        let applied = match key.code {
            KeyCode::Char('w') => self.operator_motion(op, |s| s.move_word_forward(false), false),
            KeyCode::Char('W') => self.operator_motion(op, |s| s.move_word_forward(true), false),
            KeyCode::Char('b') => self.operator_motion(op, |s| s.move_word_backward(false), false),
            KeyCode::Char('B') => self.operator_motion(op, |s| s.move_word_backward(true), false),
            KeyCode::Char('e') => self.operator_motion(op, |s| s.move_word_end(false), true),
            KeyCode::Char('E') => self.operator_motion(op, |s| s.move_word_end(true), true),
            KeyCode::Char('%') => self.operator_motion(op, |s| s.match_bracket(), true),
            KeyCode::Char(';') => self.operator_motion(
                op,
                |s| {
                    s.repeat_find(false);
                },
                false,
            ),
            KeyCode::Char(',') => self.operator_motion(
                op,
                |s| {
                    s.repeat_find(true);
                },
                false,
            ),
            KeyCode::Char('$') => self.operator_motion(op, |s| s.move_line_end(), false),
            KeyCode::Char('0') => self.operator_motion(op, |s| s.move_line_start(), false),
            KeyCode::Char('G') => {
                let len = self.buffer.len();
                self.operator_motion(op, move |s| s.set_cursor(len), false)
            }
            KeyCode::Char('d') if matches!(op, Operator::Delete) => {
                self.delete_current_line();
                true
            }
            KeyCode::Char('c') if matches!(op, Operator::Change) => {
                self.move_line_start();
                self.delete_to_line_end();
                true
            }
            KeyCode::Char('y') if matches!(op, Operator::Yank) => {
                self.yank_current_line();
                true
            }
            _ => false,
        };
        self.finish_operator_applied(op, applied);
        true
    }

    /// Leave operator-pending after a *completed* operator (a find/text-object/
    /// `gg` range that always succeeded): Change → Insert, Delete/Yank →
    /// Normal.
    fn finish_operator(&mut self, op: Operator) {
        self.finish_operator_applied(op, true);
    }

    /// Set the post-operator vim mode. `applied` is whether the operator
    /// covered a non-empty range; a `Change` that matched nothing falls back
    /// to Normal rather than dropping into a stray Insert.
    fn finish_operator_applied(&mut self, op: Operator, applied: bool) {
        self.vim_mode = if applied && matches!(op, Operator::Change) {
            VimMode::Insert
        } else {
            VimMode::Normal
        };
    }

    /// Apply `op` over the range from the cursor to a motion's landing point.
    /// `inclusive` includes the landing char (for `e`/`E`/`%`). Returns
    /// `true` when the range was non-empty.
    fn operator_motion<F>(&mut self, op: Operator, motion: F, inclusive: bool) -> bool
    where
        F: FnOnce(&mut Self),
    {
        let from = self.cursor;
        let to = self.probe_motion(motion);
        if from == to {
            return false;
        }
        let (lo, hi) = if from <= to {
            let hi = if inclusive {
                self.buffer[to..]
                    .chars()
                    .next()
                    .map(|c| to + c.len_utf8())
                    .unwrap_or(to)
            } else {
                to
            };
            (from, hi)
        } else {
            (to, from)
        };
        self.apply_operator_range(op, lo, hi);
        true
    }

    /// Apply `op` charwise over `[lo, hi)`: Yank copies + parks the cursor at
    /// `lo`; Delete/Change cut into the register.
    fn apply_operator_range(&mut self, op: Operator, lo: usize, hi: usize) {
        if lo >= hi {
            return;
        }
        match op {
            Operator::Yank => {
                self.yank_range(lo, hi, false);
                self.set_cursor(lo);
            }
            Operator::Delete | Operator::Change => {
                self.cut_range(lo, hi, false);
            }
        }
    }

    /// Visual-mode dispatch: motions extend the selection; `d`/`x`/`c`/`y`
    /// operate on it. Mirrors the app composer's visual handling.
    fn handle_visual_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;
        let mode = self.vim_mode;
        if let Some(mut spec) = self.pending_find {
            self.pending_find = None;
            if let KeyCode::Char(ch) = key.code {
                spec.target = ch;
                self.apply_find(spec, true);
            }
            return true;
        }
        if let Some(around) = self.pending_text_object.take() {
            if let KeyCode::Char(obj) = key.code
                && let Some((lo, hi)) = self.text_object_range(obj, around)
                && lo < hi
            {
                let last = self.buffer[..hi]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(lo);
                self.set_visual_selection(lo, last);
            }
            return true;
        }
        match key.code {
            KeyCode::Esc => {
                self.end_visual();
                self.pending_g = false;
            }
            KeyCode::Char('v') => {
                if mode == VimMode::Visual {
                    self.end_visual();
                } else {
                    self.vim_mode = VimMode::Visual;
                }
                self.pending_g = false;
            }
            KeyCode::Char('V') => {
                if mode == VimMode::VisualLine {
                    self.end_visual();
                } else {
                    self.vim_mode = VimMode::VisualLine;
                }
                self.pending_g = false;
            }
            KeyCode::Char('i') => self.pending_text_object = Some(false),
            KeyCode::Char('a') => self.pending_text_object = Some(true),
            KeyCode::Char('d') | KeyCode::Char('x') => self.visual_operate(Operator::Delete),
            KeyCode::Char('c') => self.visual_operate(Operator::Change),
            KeyCode::Char('y') => self.visual_operate(Operator::Yank),
            KeyCode::Char('f') => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: false,
                    forward: true,
                })
            }
            KeyCode::Char('F') => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: false,
                    forward: false,
                })
            }
            KeyCode::Char('t') => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: true,
                    forward: true,
                })
            }
            KeyCode::Char('T') => {
                self.pending_find = Some(FindSpec {
                    target: '\0',
                    till: true,
                    forward: false,
                })
            }
            KeyCode::Char(';') => {
                self.repeat_find(false);
            }
            KeyCode::Char(',') => {
                self.repeat_find(true);
            }
            KeyCode::Char('h') | KeyCode::Left => self.move_left(),
            KeyCode::Char('l') | KeyCode::Right => self.move_right(),
            KeyCode::Char('j') | KeyCode::Down => self.move_down(),
            KeyCode::Char('k') | KeyCode::Up => self.move_up(),
            KeyCode::Char('w') => self.move_word_forward(false),
            KeyCode::Char('W') => self.move_word_forward(true),
            KeyCode::Char('b') => self.move_word_backward(false),
            KeyCode::Char('B') => self.move_word_backward(true),
            KeyCode::Char('e') => self.move_word_end(false),
            KeyCode::Char('E') => self.move_word_end(true),
            KeyCode::Char('0') => self.move_line_start(),
            KeyCode::Char('$') => self.move_line_end(),
            KeyCode::Char('G') => self.move_buffer_end(),
            KeyCode::Char('%') => self.match_bracket(),
            KeyCode::Char('g') => {
                if self.pending_g {
                    self.move_buffer_start();
                    self.pending_g = false;
                } else {
                    self.pending_g = true;
                }
            }
            _ => self.pending_g = false,
        }
        true
    }

    /// Apply an operator to the active visual selection, then leave visual
    /// mode (Change → Insert, else Normal).
    fn visual_operate(&mut self, op: Operator) {
        let linewise = self.vim_mode == VimMode::VisualLine;
        let Some((lo, hi)) = self.visual_range() else {
            self.end_visual();
            return;
        };
        if lo >= hi {
            self.end_visual();
            return;
        }
        match op {
            Operator::Yank => {
                self.yank_range(lo, hi, linewise);
                self.set_cursor(lo);
                self.vim_mode = VimMode::Normal;
            }
            Operator::Delete | Operator::Change => {
                self.cut_range(lo, hi, linewise);
                self.vim_mode = if matches!(op, Operator::Change) {
                    VimMode::Insert
                } else {
                    VimMode::Normal
                };
            }
        }
        self.clear_visual_anchor();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str, cursor: usize) -> Composer {
        let mut c = Composer::new(true);
        for ch in text.chars() {
            c.insert_char(ch);
        }
        c.cursor = cursor;
        c
    }

    // ---- handle_vim_key (embedded-editor dispatch) ------------------

    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn display_chunks_wrap_wide_glyphs_by_terminal_columns() {
        let chunks = wrap_display_chunks("中中a", 4);
        assert_eq!(
            chunks,
            vec![(0, "中中".len(), 0, 4), ("中中".len(), "中中a".len(), 0, 1)]
        );
    }

    #[test]
    fn cursor_visual_position_counts_wide_and_zero_width_glyphs() {
        let text = "a中e\u{301}\u{fe0f}";
        let after_wide = "a中".len();
        let after_combining = text.len();

        assert_eq!(visual_position_for_byte(text, after_wide, 2, 20), (0, 5));
        assert_eq!(
            visual_position_for_byte(text, after_combining, 2, 20),
            (0, 6),
            "combining acute and variation selector do not advance columns"
        );
    }

    #[test]
    fn visual_position_to_byte_handles_wide_glyph_cells() {
        let text = "a中b";
        assert_eq!(byte_for_visual_position(text, 0, 2, 2, 20), 0);
        assert_eq!(
            byte_for_visual_position(text, 0, 3, 2, 20),
            1,
            "clicking first cell of wide glyph lands on that glyph"
        );
        assert_eq!(
            byte_for_visual_position(text, 0, 4, 2, 20),
            1,
            "clicking second cell of wide glyph still lands on that glyph"
        );
        assert_eq!(byte_for_visual_position(text, 0, 5, 2, 20), "a中".len());
    }

    #[test]
    fn visual_position_for_byte_uses_next_row_at_wrap_boundary() {
        assert_eq!(visual_position_for_byte("abcd", 2, 1, 3), (1, 1));
    }

    #[test]
    fn visual_position_for_byte_keeps_nonfinal_newline_on_source_line() {
        assert_eq!(visual_position_for_byte("ab\ncd", 2, 1, 10), (0, 3));
    }

    #[test]
    fn display_truncation_never_exceeds_budget_or_splits_utf8() {
        let truncated = truncate_display_width("queued: 中中abc", 10);
        assert!(display_width(&truncated) <= 10);
        assert!(truncated.ends_with('…'));
        assert!(truncated.is_char_boundary(truncated.len()));
    }

    fn feed(c: &mut Composer, s: &str) {
        for ch in s.chars() {
            c.handle_vim_key(key(KeyCode::Char(ch)));
        }
    }

    #[test]
    fn handle_vim_key_insert_and_normal_motions() {
        let mut c = Composer::new(true);
        // Normal mode at start; `i` enters Insert, type, Esc back to Normal.
        assert_eq!(c.vim_mode(), VimMode::Normal);
        c.handle_vim_key(key(KeyCode::Char('i')));
        assert_eq!(c.vim_mode(), VimMode::Insert);
        feed(&mut c, "hello world");
        c.handle_vim_key(key(KeyCode::Esc));
        assert_eq!(c.vim_mode(), VimMode::Normal);
        assert_eq!(c.text(), "hello world");
        // `0` to start, `dw` deletes the first word.
        c.handle_vim_key(key(KeyCode::Char('0')));
        feed(&mut c, "dw");
        assert_eq!(c.text(), "world");
    }

    #[test]
    fn handle_vim_key_text_object_operator() {
        // `ci"` changes inside quotes, leaving the editor in Insert.
        let mut c = at("say \"hi\" now", 5);
        feed(&mut c, "ci\"");
        assert_eq!(c.text(), "say \"\" now");
        assert_eq!(c.vim_mode(), VimMode::Insert);
    }

    #[test]
    fn handle_vim_key_visual_yank_into_register() {
        let mut c = at("abcdef", 0);
        // v + l l selects "abc", y yanks it.
        c.handle_vim_key(key(KeyCode::Char('v')));
        c.handle_vim_key(key(KeyCode::Char('l')));
        c.handle_vim_key(key(KeyCode::Char('l')));
        c.handle_vim_key(key(KeyCode::Char('y')));
        assert_eq!(c.vim_mode(), VimMode::Normal);
        assert_eq!(c.register().text, "abc");
    }

    #[test]
    fn handle_vim_key_plain_when_vim_off() {
        let mut c = Composer::new(false);
        feed(&mut c, "iabc"); // every char is literal — no vim modes
        assert_eq!(c.text(), "iabc");
        // Esc is not a mode switch (vim off) and is not consumed.
        assert!(!c.handle_vim_key(key(KeyCode::Esc)));
    }

    #[test]
    fn dw_deletes_word_and_trailing_space() {
        let mut c = at("hello world", 0);
        c.delete_word_forward(false);
        assert_eq!(c.text(), "world");
        assert_eq!(c.cursor, 0);
    }

    #[test]
    fn db_deletes_back_to_prev_word() {
        let mut c = at("hello world", 11);
        c.delete_word_backward(false);
        assert_eq!(c.text(), "hello ");
        assert_eq!(c.cursor, 6);
    }

    #[test]
    fn dd_deletes_full_line_and_its_newline() {
        let mut c = at("a\nb\nc", 2); // cursor on 'b'
        c.delete_current_line();
        assert_eq!(c.text(), "a\nc");
        // Cursor should land at start of the (now-)current line.
        let (line, col) = c.cursor_line_col();
        assert_eq!((line, col), (1, 0));
    }

    #[test]
    fn dd_on_last_line_removes_preceding_newline() {
        let mut c = at("a\nb\nc", 4); // cursor on 'c'
        c.delete_current_line();
        assert_eq!(c.text(), "a\nb");
        // Cursor lands at the start of "b" (the new last line).
        let (line, col) = c.cursor_line_col();
        assert_eq!((line, col), (1, 0));
    }

    #[test]
    fn dd_on_trailing_empty_line_drops_dangling_newline() {
        // "a\nb\n" with cursor at byte 4 = after the final \n (the
        // empty position vim would place you on if you'd just typed
        // `<CR>` at the end). dd removes the empty trailing line by
        // dropping the dangling newline.
        let mut c = at("a\nb\n", 4);
        c.delete_current_line();
        assert_eq!(c.text(), "a\nb");
    }

    #[test]
    fn dd_on_only_line_clears_buffer() {
        let mut c = at("just one", 4);
        c.delete_current_line();
        assert_eq!(c.text(), "");
        assert_eq!(c.cursor, 0);
    }

    #[test]
    fn d_dollar_deletes_to_eol() {
        let mut c = at("hello world", 5); // cursor after "hello"
        c.delete_to_line_end();
        assert_eq!(c.text(), "hello");
        assert_eq!(c.cursor, 5);
    }

    #[test]
    fn d_zero_deletes_to_line_start() {
        let mut c = at("hello", 5);
        c.delete_to_line_start();
        assert_eq!(c.text(), "");
        assert_eq!(c.cursor, 0);
    }

    #[test]
    fn open_below_inserts_newline_and_lands_on_it() {
        let mut c = at("hello\nworld", 2); // mid-"hello"
        c.open_below();
        assert_eq!(c.text(), "hello\n\nworld");
        // Cursor on the new empty line.
        let (line, col) = c.cursor_line_col();
        assert_eq!((line, col), (1, 0));
    }

    #[test]
    fn open_above_inserts_newline_above_and_lands_on_it() {
        let mut c = at("hello\nworld", 6); // start of "world"
        c.open_above();
        assert_eq!(c.text(), "hello\n\nworld");
        // Cursor on the new empty middle line.
        let (line, col) = c.cursor_line_col();
        assert_eq!((line, col), (1, 0));
    }

    #[test]
    fn word_forward_stops_on_punctuation() {
        let mut c = at("foo.bar baz", 0);
        c.move_word_forward(false);
        // small-w lands on the punctuation transition.
        assert_eq!(c.cursor, 3);
    }

    #[test]
    fn big_word_forward_skips_punctuation() {
        let mut c = at("foo.bar baz", 0);
        c.move_word_forward(true);
        // big-W treats `foo.bar` as one WORD; lands on `baz`.
        assert_eq!(c.cursor, 8);
    }

    #[test]
    fn gg_jumps_to_buffer_start() {
        let mut c = at("a\nb\nc", 4);
        c.move_buffer_start();
        assert_eq!(c.cursor, 0);
    }

    #[test]
    fn at_query_returns_partial_after_at_sign() {
        let c = at("see @src/fo", 11);
        assert_eq!(c.at_query(), Some("src/fo"));
    }

    #[test]
    fn at_query_none_when_email_like() {
        let c = at("ping user@example.com", 21);
        assert_eq!(c.at_query(), None);
    }

    #[test]
    fn at_query_none_when_whitespace_between_at_and_cursor() {
        let c = at("@foo bar", 8);
        assert_eq!(c.at_query(), None);
    }

    #[test]
    fn at_query_quoted_keeps_narrowing_across_spaces() {
        // `@"src/my ` — open quote, cursor after the space.
        let c = at("@\"src/my ", 9);
        assert_eq!(c.at_query(), Some("src/my "));
    }

    #[test]
    fn at_query_quoted_closed_is_not_active() {
        // `@"src/my file.rs"` — closing quote present → tag finished.
        let s = "@\"src/my file.rs\"";
        let c = at(s, s.len());
        assert_eq!(c.at_query(), None);
    }

    #[test]
    fn replace_at_token_swaps_partial_for_full_path() {
        let mut c = at("see @src/fo", 11);
        c.replace_at_token("src/foo.rs");
        assert_eq!(c.text(), "see @src/foo.rs");
        assert_eq!(c.cursor(), c.text().len());
    }

    #[test]
    fn capital_g_lands_on_last_line_start() {
        let mut c = at("a\nb\nccc", 0);
        c.move_buffer_end();
        // Start of "ccc".
        assert_eq!(c.cursor, 4);
    }

    #[test]
    fn find_forward_lands_on_next_occurrence() {
        let mut c = at("hello world", 0);
        c.find_char_forward('o');
        assert_eq!(c.cursor, 4);
    }

    #[test]
    fn find_forward_advances_past_current_char() {
        // Cursor sits on the 'o' in "hello"; repeating `f o` should
        // skip to the second occurrence (in "world").
        let mut c = at("hello world", 4);
        c.find_char_forward('o');
        assert_eq!(c.cursor, 7);
    }

    #[test]
    fn find_forward_stops_at_newline() {
        let mut c = at("hello\nworld", 0);
        c.find_char_forward('w');
        // 'w' is on the next line — `f` must not cross newlines.
        assert_eq!(c.cursor, 0);
    }

    #[test]
    fn find_backward_lands_on_prev_occurrence() {
        let mut c = at("hello world", 10);
        c.find_char_backward('o');
        assert_eq!(c.cursor, 7);
    }

    #[test]
    fn find_backward_stops_at_newline() {
        let mut c = at("foo\nbar", 6);
        c.find_char_backward('f');
        // 'f' lives on the previous line.
        assert_eq!(c.cursor, 6);
    }

    #[test]
    fn ghost_short_converts_to_real_on_first_tab() {
        // A short (single-line) prediction shows fully and the first Tab
        // fills the composer with real text.
        let mut g = PredictionGhost::new("add a test".to_string(), false);
        assert_eq!(g.display_text(), "add a test");
        assert!(!g.box_expanded());
        assert_eq!(g.accept(), GhostAccept::Fill("add a test".to_string()));
    }

    #[test]
    fn ghost_single_line_long_is_one_tab() {
        // `long` mode but a single-line prediction behaves like short:
        // one Tab → real text, no expansion stage.
        let mut g = PredictionGhost::new("just one line".to_string(), true);
        assert_eq!(g.display_text(), "just one line");
        assert!(!g.box_expanded());
        assert_eq!(g.accept(), GhostAccept::Fill("just one line".to_string()));
    }

    #[test]
    fn ghost_multiline_long_is_two_tab_expand_then_fill() {
        // `long` + multi-line: collapsed first line, first Tab expands to
        // full ghost, second Tab converts to real text.
        let full = "first line\nsecond line\nthird line".to_string();
        let mut g = PredictionGhost::new(full.clone(), true);
        // Collapsed: only the first line shows; box not yet expanded.
        assert_eq!(g.display_text(), "first line");
        assert!(!g.box_expanded());
        // First Tab → expand (still ghost, full text now).
        assert_eq!(g.accept(), GhostAccept::Expand);
        assert_eq!(g.display_text(), full);
        assert!(g.box_expanded());
        // Second Tab → fill with the full text as real editable content.
        assert_eq!(g.accept(), GhostAccept::Fill(full));
    }

    // ---- new motions: e / ge / t / T / ; / , / % --------------------

    #[test]
    fn word_end_lands_on_last_char() {
        let mut c = at("hello world", 0);
        c.move_word_end(false);
        // 'o' of "hello" (index 4).
        assert_eq!(c.cursor, 4);
        c.move_word_end(false);
        // 'd' of "world" (index 10).
        assert_eq!(c.cursor, 10);
    }

    #[test]
    fn word_end_stops_on_punctuation_run() {
        let mut c = at("foo.bar", 0);
        c.move_word_end(false);
        // small-e: end of "foo" is index 2.
        assert_eq!(c.cursor, 2);
    }

    #[test]
    fn ge_lands_on_prev_word_end() {
        let mut c = at("hello world", 8); // inside "world"
        c.move_word_end_backward(false);
        // end of "hello" is index 4.
        assert_eq!(c.cursor, 4);
    }

    #[test]
    fn till_forward_stops_before_target() {
        let mut c = at("hello world", 0);
        c.apply_find(
            FindSpec {
                target: 'w',
                till: true,
                forward: true,
            },
            true,
        );
        // `tw` lands one char before 'w' (the space at index 5).
        assert_eq!(c.cursor, 5);
    }

    #[test]
    fn till_backward_stops_after_target() {
        let mut c = at("hello world", 10); // on 'd'
        c.apply_find(
            FindSpec {
                target: 'o',
                till: true,
                forward: false,
            },
            true,
        );
        // backward 'o' is index 7 ("wOrld"); `T` lands one after → 8.
        assert_eq!(c.cursor, 8);
    }

    #[test]
    fn semicolon_repeats_last_find() {
        let mut c = at("a.b.c.d", 0);
        c.find_char_forward('.'); // index 1
        assert_eq!(c.cursor, 1);
        assert!(c.repeat_find(false)); // next '.' index 3
        assert_eq!(c.cursor, 3);
        assert!(c.repeat_find(false)); // next '.' index 5
        assert_eq!(c.cursor, 5);
    }

    #[test]
    fn semicolon_repeats_till_without_sticking() {
        // `t.` lands before the first '.'; `;` must advance to before the
        // next one rather than re-finding the same target.
        let mut c = at("a.b.c.d", 0);
        c.apply_find(
            FindSpec {
                target: '.',
                till: true,
                forward: true,
            },
            true,
        );
        assert_eq!(c.cursor, 0); // just before '.' at index 1
        assert!(c.repeat_find(false));
        assert_eq!(c.cursor, 2); // before '.' at index 3
    }

    #[test]
    fn comma_reverses_last_find() {
        let mut c = at("a.b.c.d", 0);
        c.find_char_forward('.'); // index 1
        c.repeat_find(false); // index 3
        assert!(c.repeat_find(true)); // `,` reverses → back to index 1
        assert_eq!(c.cursor, 1);
    }

    #[test]
    fn match_bracket_jumps_to_pair() {
        let mut c = at("foo(bar)baz", 0);
        c.match_bracket();
        // First bracket ahead is '(' at index 3; match ')' at index 7.
        assert_eq!(c.cursor, 7);
        // From the ')', `%` jumps back to '('.
        c.match_bracket();
        assert_eq!(c.cursor, 3);
    }

    #[test]
    fn match_bracket_handles_nesting() {
        let mut c = at("(a(b)c)", 0);
        c.match_bracket();
        // Outer '(' at 0 matches outer ')' at 6, skipping the inner pair.
        assert_eq!(c.cursor, 6);
    }

    #[test]
    fn match_bracket_no_match_is_noop() {
        let mut c = at("foo(bar", 0);
        c.match_bracket();
        // Unbalanced — cursor stays put.
        assert_eq!(c.cursor, 0);
    }

    // ---- text objects ------------------------------------------------

    #[test]
    fn iw_selects_word_only() {
        let c = at("hello world", 2); // inside "hello"
        assert_eq!(c.text_object_range('w', false), Some((0, 5)));
    }

    #[test]
    fn aw_includes_trailing_whitespace() {
        let c = at("hello world", 2);
        assert_eq!(c.text_object_range('w', true), Some((0, 6)));
    }

    #[test]
    fn inner_quote_excludes_delimiters() {
        let c = at("say \"hi there\" now", 7); // inside the quotes
        // inner: between the quotes.
        let (s, e) = c.text_object_range('"', false).unwrap();
        assert_eq!(&c.text()[s..e], "hi there");
    }

    #[test]
    fn around_quote_includes_delimiters() {
        let c = at("say \"hi there\" now", 7);
        let (s, e) = c.text_object_range('"', true).unwrap();
        assert_eq!(&c.text()[s..e], "\"hi there\"");
    }

    #[test]
    fn inner_paren_excludes_brackets() {
        let c = at("foo(a, b)bar", 5); // inside parens
        let (s, e) = c.text_object_range('(', false).unwrap();
        assert_eq!(&c.text()[s..e], "a, b");
    }

    #[test]
    fn around_paren_includes_brackets() {
        let c = at("foo(a, b)bar", 5);
        let (s, e) = c.text_object_range(')', true).unwrap();
        assert_eq!(&c.text()[s..e], "(a, b)");
    }

    #[test]
    fn nested_brackets_pick_inner() {
        let c = at("a(b(c)d)e", 4); // on 'c' inside inner ()
        let (s, e) = c.text_object_range('(', false).unwrap();
        assert_eq!(&c.text()[s..e], "c");
    }

    #[test]
    fn unmatched_bracket_object_is_none() {
        let c = at("foo(bar", 5);
        assert_eq!(c.text_object_range('(', false), None);
    }

    // ---- register: charwise vs linewise paste -----------------------

    #[test]
    fn yank_word_then_paste_after_duplicates_charwise() {
        // yiw on "foo" yanks "foo"; p after cursor inserts after the cell.
        let mut c = at("foo bar", 0);
        let (s, e) = c.text_object_range('w', false).unwrap();
        c.yank_range(s, e, false);
        assert_eq!(c.register().text, "foo");
        assert!(!c.register().linewise);
        // cursor on 'f' (index 0); paste_after inserts after 'f'.
        c.paste_after();
        assert_eq!(c.text(), "ffoooo bar");
    }

    #[test]
    fn paste_before_charwise_inserts_at_cursor() {
        let mut c = at("xy", 1); // on 'y'
        c.set_register(Register {
            text: "AB".to_string(),
            linewise: false,
        });
        c.paste_before();
        assert_eq!(c.text(), "xABy");
        // Cursor lands on the last pasted char ('B', index 2).
        assert_eq!(c.cursor, 2);
    }

    #[test]
    fn yy_then_p_pastes_line_below() {
        let mut c = at("alpha\nbeta", 0); // on "alpha"
        c.yank_current_line();
        assert_eq!(c.register().text, "alpha\n");
        assert!(c.register().linewise);
        c.paste_after();
        assert_eq!(c.text(), "alpha\nalpha\nbeta");
        // Cursor at the start of the pasted line.
        assert_eq!(c.cursor, 6);
    }

    #[test]
    fn linewise_paste_before_inserts_line_above() {
        let mut c = at("one\ntwo", 4); // on "two"
        c.set_register(Register {
            text: "zero\n".to_string(),
            linewise: true,
        });
        c.paste_before();
        assert_eq!(c.text(), "one\nzero\ntwo");
        assert_eq!(c.cursor, 4);
    }

    #[test]
    fn linewise_paste_after_on_last_line_no_dangling_newline() {
        let mut c = at("one\ntwo", 4); // last line "two"
        c.yank_current_line(); // "two\n"
        c.paste_after();
        // No trailing empty line introduced.
        assert_eq!(c.text(), "one\ntwo\ntwo");
    }

    #[test]
    fn cut_range_populates_register() {
        let mut c = at("hello world", 0);
        let (s, e) = c.text_object_range('w', false).unwrap(); // "hello"
        c.cut_range(s, e, false);
        assert_eq!(c.text(), " world");
        assert_eq!(c.register().text, "hello");
        assert!(!c.register().linewise);
    }

    #[test]
    fn paste_is_multibyte_safe() {
        // Yank a multibyte word and paste it — must not panic on byte
        // boundaries and must land on the right char.
        let mut c = at("héllo café", 0);
        // iw over "héllo" (é is 2 bytes).
        let (s, e) = c.text_object_range('w', false).unwrap();
        assert_eq!(&c.text()[s..e], "héllo");
        c.yank_range(s, e, false);
        c.set_cursor(0);
        c.paste_after();
        assert!(c.text().starts_with("hhélloéllo"));
    }

    // ---- visual mode -------------------------------------------------

    #[test]
    fn charwise_visual_range_is_inclusive_of_cursor_cell() {
        let mut c = at("abcdef", 0);
        c.begin_visual(VimMode::Visual);
        c.cursor = 2; // moved right to 'c'
        // Inclusive of the cursor cell → [0, 3) = "abc".
        let (s, e) = c.visual_range().unwrap();
        assert_eq!(&c.text()[s..e], "abc");
    }

    #[test]
    fn linewise_visual_range_spans_whole_lines() {
        let mut c = at("one\ntwo\nthree", 5); // on "two"
        c.begin_visual(VimMode::VisualLine);
        c.cursor = 9; // on "three"
        let (s, e) = c.visual_range().unwrap();
        // From start of "two" through the end (incl. trailing of "three").
        assert_eq!(&c.text()[s..e], "two\nthree");
    }

    #[test]
    fn linewise_visual_range_includes_trailing_newline_when_present() {
        let mut c = at("one\ntwo\nthree", 0); // on "one"
        c.begin_visual(VimMode::VisualLine);
        // cursor stays on line 0; range covers "one\n".
        let (s, e) = c.visual_range().unwrap();
        assert_eq!(&c.text()[s..e], "one\n");
    }

    #[test]
    fn visual_yank_charwise_into_register() {
        let mut c = at("abcdef", 1);
        c.begin_visual(VimMode::Visual);
        c.cursor = 3; // selecting "bcd"
        let (s, e) = c.visual_range().unwrap();
        c.yank_range(s, e, false);
        assert_eq!(c.register().text, "bcd");
        assert!(!c.register().linewise);
    }

    #[test]
    fn visual_delete_linewise_removes_lines() {
        let mut c = at("one\ntwo\nthree", 5); // on "two"
        c.begin_visual(VimMode::VisualLine);
        let (s, e) = c.visual_range().unwrap();
        c.cut_range(s, e, true);
        assert_eq!(c.text(), "one\nthree");
        assert!(c.register().linewise);
    }

    #[test]
    fn empty_buffer_visual_range_is_zero_width() {
        let mut c = at("", 0);
        c.begin_visual(VimMode::Visual);
        let r = c.visual_range();
        // [0, 0) — a zero-width selection (clean no-op for the caller).
        assert_eq!(r, Some((0, 0)));
    }

    #[test]
    fn set_visual_selection_spans_object() {
        let mut c = at("foo bar baz", 0);
        // Select "bar" (bytes 4..7); cursor on last char 'r' (index 6).
        c.set_visual_selection(4, 6);
        assert_eq!(c.vim_mode(), VimMode::Visual);
        let (s, e) = c.visual_range().unwrap();
        assert_eq!(&c.text()[s..e], "bar");
    }
}
