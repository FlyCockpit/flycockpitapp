//! Atomic owner for the application composer and its paste-block authority.
//!
//! The main [`App`](crate::tui::app::App) never owns or mutably borrows a raw
//! [`Composer`](super::Composer) or [`PasteRegistry`]. Every edit that can
//! change byte offsets crosses this type, which updates both values before
//! returning. Immutable composer reads remain ergonomic through [`Deref`].

use std::ops::Deref;

use super::{Composer, EditOutcome, FindSpec, Operator, Register, VimMode};
use crate::tui::paste::{
    EditorPasteRebuild, EditorPasteSnapshot, ImageIngressDraftAuthority, PasteBlock, PasteKind,
    PasteRegistry,
};

/// A closed inventory of cursor motions accepted by [`RegisteredComposer`].
///
/// Keeping motions as values avoids lending a mutable raw [`Composer`] to
/// callers while still sharing the exact vim motion implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ComposerMotion {
    Up,
    Down,
    LineStart,
    LineEnd,
    BufferStart,
    BufferEnd,
    WordForward { big: bool },
    WordBackward { big: bool },
    WordEnd { big: bool },
    WordEndBackward { big: bool },
    MatchBracket,
    RepeatFind { reverse: bool },
    Absolute(usize),
}

impl ComposerMotion {
    fn forward(self) -> Option<bool> {
        match self {
            Self::WordBackward { .. }
            | Self::WordEndBackward { .. }
            | Self::LineStart
            | Self::BufferStart => Some(false),
            Self::WordForward { .. } | Self::WordEnd { .. } | Self::LineEnd | Self::BufferEnd => {
                Some(true)
            }
            Self::Up
            | Self::Down
            | Self::MatchBracket
            | Self::RepeatFind { .. }
            | Self::Absolute(_) => None,
        }
    }
}

/// The sole application-level owner of editable composer state.
pub(crate) struct RegisteredComposer {
    composer: Composer,
    paste_registry: PasteRegistry,
}

impl Deref for RegisteredComposer {
    type Target = Composer;

    fn deref(&self) -> &Self::Target {
        &self.composer
    }
}

impl RegisteredComposer {
    pub(crate) fn new(vim_enabled: bool) -> Self {
        Self {
            composer: Composer::new(vim_enabled),
            paste_registry: PasteRegistry::new(),
        }
    }

    /// Replace the document and retire every paste authority from the old
    /// byte space as one operation.
    pub(crate) fn replace_buffer(&mut self, text: impl Into<String>) {
        self.paste_registry.clear();
        self.composer.set_unregistered(text);
    }

    pub(crate) fn clear_buffer(&mut self) {
        self.paste_registry.clear();
        self.composer.clear_unregistered();
    }

    fn rebuild_buffer(&mut self, rebuilt: EditorPasteRebuild) {
        self.composer.set_unregistered(rebuilt.buffer);
        self.paste_registry = rebuilt.registry;
        self.reconcile();
    }

    pub(crate) fn rebuild_from_editor(
        &mut self,
        editor_text: &str,
        snapshot: &EditorPasteSnapshot,
    ) {
        let rebuilt = PasteRegistry::rebuild_from_editor_snapshot(
            editor_text,
            snapshot,
            cockpit_core::tokens::count,
        );
        self.rebuild_buffer(rebuilt);
    }

    #[cfg(test)]
    pub(crate) fn set(&mut self, text: impl Into<String>) {
        self.replace_buffer(text);
    }

    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        self.clear_buffer();
    }

    pub(crate) fn paste_is_empty(&self) -> bool {
        self.paste_registry.is_empty()
    }

    pub(crate) fn paste_blocks(&self) -> &[PasteBlock] {
        self.paste_registry.blocks()
    }

    pub(crate) fn display_text(&self) -> String {
        self.paste_registry.expand_display(self.composer.text())
    }

    pub(crate) fn plain_payload(&self) -> Option<String> {
        self.paste_registry
            .expand_plain_payload(self.composer.text())
    }

    pub(crate) fn wire_parts(
        &self,
        vision: bool,
    ) -> (String, Vec<cockpit_core::engine::message::SubmissionImage>) {
        self.paste_registry.build_wire(self.composer.text(), vision)
    }

    pub(crate) fn image_ingress_drafts(&self) -> Vec<ImageIngressDraftAuthority> {
        self.paste_registry.image_ingress_drafts()
    }

    pub(crate) fn wire_image_ingress_drafts(
        &self,
        vision: bool,
    ) -> Vec<ImageIngressDraftAuthority> {
        self.paste_registry.wire_image_ingress_drafts(vision)
    }

    pub(crate) fn editor_text(&self) -> String {
        self.paste_registry.expand_editor(self.composer.text())
    }

    pub(crate) fn editor_snapshot(&self) -> EditorPasteSnapshot {
        self.paste_registry.editor_snapshot()
    }

    pub(crate) fn set_vim_enabled(&mut self, enabled: bool) {
        self.composer.set_vim_enabled(enabled);
    }

    pub(crate) fn set_vim_mode(&mut self, mode: VimMode) {
        self.composer.set_vim_mode(mode);
    }

    pub(crate) fn set_pending_g(&mut self, pending: bool) {
        self.composer.set_pending_g(pending);
    }

    pub(crate) fn set_pending_find(&mut self, spec: Option<FindSpec>) {
        self.composer.set_pending_find(spec);
    }

    pub(crate) fn set_last_find(&mut self, spec: FindSpec) {
        self.composer.set_last_find(spec);
    }

    pub(crate) fn set_register(&mut self, register: Register) {
        self.composer.set_register(register);
    }

    pub(crate) fn set_cursor(&mut self, position: usize) {
        self.composer.set_cursor(position);
        let snapped = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        self.composer.set_cursor(snapped);
    }

    pub(crate) fn set_cursor_from_visual_position(
        &mut self,
        row: usize,
        col: usize,
        prefix: usize,
        inner_width: usize,
    ) {
        self.composer
            .set_cursor_from_visual_position(row, col, prefix, inner_width);
        let snapped = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        self.composer.set_cursor(snapped);
    }

    pub(crate) fn begin_visual(&mut self, mode: VimMode) {
        self.composer.begin_visual(mode);
    }

    pub(crate) fn end_visual(&mut self) {
        self.composer.end_visual();
    }

    pub(crate) fn set_visual_selection(&mut self, anchor: usize, cursor: usize) {
        let forward = cursor >= anchor;
        let anchor = self.paste_registry.skip_cursor(anchor, !forward);
        let cursor = self.paste_registry.skip_cursor(cursor, forward);
        self.composer.set_visual_selection(anchor, cursor);
    }

    pub(crate) fn apply_find(&mut self, spec: FindSpec, record: bool) -> bool {
        let moved = self.composer.apply_find(spec, record);
        self.snap_off_block(spec.forward);
        moved
    }

    pub(crate) fn repeat_find(&mut self, reverse: bool) -> bool {
        let forward = self
            .composer
            .last_find()
            .map_or(!reverse, |spec| spec.forward != reverse);
        let moved = self.composer.repeat_find(reverse);
        self.snap_off_block(forward);
        moved
    }

    pub(crate) fn move_cursor(&mut self, motion: ComposerMotion) {
        let before = self.composer.cursor();
        Self::apply_motion(&mut self.composer, motion);
        let forward = motion.forward().unwrap_or(self.composer.cursor() >= before);
        self.snap_off_block(forward);
    }

    pub(crate) fn move_left(&mut self) {
        let cursor = self.composer.cursor();
        if let Some(block) = self.paste_registry.block_ending_at(cursor) {
            self.composer.set_cursor(block.start);
            return;
        }
        self.composer.move_left();
        self.snap_off_block(false);
    }

    pub(crate) fn move_right(&mut self) {
        let cursor = self.composer.cursor();
        if let Some(block) = self.paste_registry.block_starting_at(cursor) {
            self.composer.set_cursor(block.end);
            return;
        }
        self.composer.move_right();
        self.snap_off_block(true);
    }

    pub(crate) fn move_up(&mut self) {
        self.move_cursor(ComposerMotion::Up);
    }

    pub(crate) fn move_down(&mut self) {
        self.move_cursor(ComposerMotion::Down);
    }

    pub(crate) fn move_line_start(&mut self) {
        self.move_cursor(ComposerMotion::LineStart);
    }

    pub(crate) fn move_line_end(&mut self) {
        self.move_cursor(ComposerMotion::LineEnd);
    }

    pub(crate) fn move_buffer_start(&mut self) {
        self.move_cursor(ComposerMotion::BufferStart);
    }

    pub(crate) fn move_buffer_end(&mut self) {
        self.move_cursor(ComposerMotion::BufferEnd);
    }

    pub(crate) fn insert_str(&mut self, text: &str) {
        let at = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        self.composer.set_cursor(at);
        self.composer.insert_str(text);
        self.paste_registry.shift_for_edit(at, text.len() as isize);
        self.reconcile();
    }

    pub(crate) fn insert_char(&mut self, ch: char) {
        let at = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        self.composer.set_cursor(at);
        self.composer.insert_char(ch);
        self.paste_registry
            .shift_for_edit(at, ch.len_utf8() as isize);
        self.reconcile();
    }

    pub(crate) fn delete_left(&mut self) -> Option<std::ops::Range<usize>> {
        let cursor = self
            .paste_registry
            .skip_cursor(self.composer.cursor(), false);
        self.composer.set_cursor(cursor);
        let removed = self.composer.delete_left()?;
        self.paste_registry
            .shift_for_edit(removed.start, -(removed.len() as isize));
        self.reconcile();
        Some(removed)
    }

    pub(crate) fn delete_right(&mut self) -> Option<std::ops::Range<usize>> {
        let cursor = self
            .paste_registry
            .skip_cursor(self.composer.cursor(), true);
        self.composer.set_cursor(cursor);
        let removed = self.composer.delete_right()?;
        self.paste_registry
            .shift_for_edit(removed.start, -(removed.len() as isize));
        self.reconcile();
        Some(removed)
    }

    pub(crate) fn delete_range(
        &mut self,
        mut start: usize,
        mut end: usize,
    ) -> Option<std::ops::Range<usize>> {
        if let Some((block_start, block_end)) = self.paste_registry.block_crossed_by(start, end) {
            start = start.min(block_start);
            end = end.max(block_end);
        }
        let removed = self.composer.delete_range(start, end)?;
        self.paste_registry
            .shift_for_edit(removed.start, -(removed.len() as isize));
        self.reconcile();
        Some(removed)
    }

    fn cut_range(
        &mut self,
        mut start: usize,
        mut end: usize,
        linewise: bool,
    ) -> Option<std::ops::Range<usize>> {
        if let Some((block_start, block_end)) = self.paste_registry.block_crossed_by(start, end) {
            start = start.min(block_start);
            end = end.max(block_end);
        }
        let removed = self.composer.cut_range(start, end, linewise)?;
        self.paste_registry
            .shift_for_edit(removed.start, -(removed.len() as isize));
        self.reconcile();
        Some(removed)
    }

    fn yank_range(&mut self, mut start: usize, mut end: usize, linewise: bool) {
        if let Some((block_start, block_end)) = self.paste_registry.block_crossed_by(start, end) {
            start = start.min(block_start);
            end = end.max(block_end);
        }
        self.composer.yank_range(start, end, linewise);
    }

    pub(crate) fn yank_current_line(&mut self) {
        self.composer.yank_current_line();
    }

    pub(crate) fn delete_current_line(&mut self) {
        if self.paste_registry.is_empty() {
            self.composer.delete_current_line();
            return;
        }
        let before = self.composer.len();
        let cursor = self.composer.cursor();
        let line_start = self.composer.text()[..cursor]
            .rfind('\n')
            .map(|index| index + 1)
            .unwrap_or(0);
        self.composer.delete_current_line();
        let removed = before - self.composer.len();
        if removed > 0 {
            let anchor = line_start.min(self.composer.cursor());
            self.paste_registry
                .shift_for_edit(anchor, -(removed as isize));
        }
        self.reconcile();
    }

    pub(crate) fn delete_to_line_end(&mut self) {
        let from = self.composer.cursor();
        let to = self.probe_motion(ComposerMotion::LineEnd);
        if from != to {
            let _ = self.delete_range(from.min(to), from.max(to));
        }
    }

    pub(crate) fn open_below(&mut self) {
        if self.paste_registry.is_empty() {
            self.composer.open_below();
            return;
        }
        self.composer.move_line_end();
        self.insert_char('\n');
    }

    pub(crate) fn open_above(&mut self) {
        if self.paste_registry.is_empty() {
            self.composer.open_above();
            return;
        }
        self.composer.move_line_start();
        self.insert_char('\n');
        self.composer
            .set_cursor(self.composer.cursor().saturating_sub(1));
    }

    pub(crate) fn paste_after(&mut self) {
        self.paste_register(true);
    }

    pub(crate) fn paste_before(&mut self) {
        self.paste_register(false);
    }

    pub(crate) fn replace_at_token(&mut self, replacement: &str) -> Option<EditOutcome> {
        let edit = self.composer.replace_at_token(replacement)?;
        self.paste_registry.shift_for_edit(
            edit.removed_range.start,
            -(edit.removed_range.len() as isize),
        );
        self.paste_registry.shift_for_edit(
            edit.inserted_range.start,
            edit.inserted_range.len() as isize,
        );
        self.reconcile();
        Some(edit)
    }

    pub(crate) fn paste_block_left(&self) -> Option<(usize, usize)> {
        self.paste_registry
            .block_ending_at(self.composer.cursor())
            .map(|block| (block.start, block.end))
    }

    pub(crate) fn paste_block_right(&self) -> Option<(usize, usize)> {
        self.paste_registry
            .block_starting_at(self.composer.cursor())
            .map(|block| (block.start, block.end))
    }

    pub(crate) fn delete_paste_block(&mut self, start: usize, end: usize) {
        let _ = self.delete_range(start, end);
    }

    /// Insert a terminal text paste. A returned tuple requests asynchronous
    /// token counting for the newly-condensed block.
    pub(crate) fn insert_pasted_text(&mut self, data: String) -> Option<(u64, String)> {
        let cursor = self.composer.cursor();
        if let Some((start, end, full)) = self.paste_registry.expandable_text_at(cursor, &data) {
            let _ = self.delete_range(start, end);
            self.insert_str(&full);
            return None;
        }
        if !crate::tui::paste::should_condense(&data) {
            self.insert_str(&data);
            return None;
        }
        let at = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        self.composer.set_cursor(at);
        let (block_id, placeholder) = self.paste_registry.register_text_pending(at, data.clone());
        self.composer.insert_str(&placeholder);
        self.paste_registry
            .shift_other_blocks_after_insert(block_id, at, placeholder.len());
        self.reconcile();
        Some((block_id, data))
    }

    pub(crate) fn apply_paste_token_count(&mut self, block_id: u64, tokens: usize) -> bool {
        let Some(replacement) = self.paste_registry.apply_text_token_count(block_id, tokens) else {
            return false;
        };
        let cursor = self.composer.cursor();
        let new_len = replacement.replacement.len();
        let Some(removed) = self
            .composer
            .delete_range(replacement.start, replacement.end)
        else {
            self.reconcile();
            return false;
        };
        let insertion_start = removed.start;
        let old_len = removed.len();
        self.composer.set_cursor(insertion_start);
        self.composer.insert_str(&replacement.replacement);
        let new_end = insertion_start + new_len;
        let new_cursor = if cursor <= removed.start {
            cursor
        } else if cursor >= removed.end {
            if new_len >= old_len {
                cursor + (new_len - old_len)
            } else {
                cursor.saturating_sub(old_len - new_len)
            }
        } else {
            new_end
        };
        self.composer.set_cursor(new_cursor);
        self.reconcile();
        true
    }

    fn can_insert_image(&self, byte_length: u64) -> bool {
        let retained = self.paste_registry.image_payloads_by_number();
        let total = retained.values().try_fold(byte_length, |sum, image| {
            sum.checked_add(image.normalized_byte_length())
        });
        byte_length <= cockpit_proto::MAX_SINGLE_IMAGE_BYTES as u64
            && total.is_some_and(|total| total <= cockpit_proto::MAX_TOTAL_IMAGE_BYTES as u64)
            && retained.len() < cockpit_proto::MAX_IMAGES_PER_USER_MESSAGE
    }

    fn can_insert_image_handle(&self, normalized_byte_length: u64) -> bool {
        let retained = self.paste_registry.image_payloads_by_number();
        let retained_bytes = retained
            .values()
            .try_fold(normalized_byte_length, |sum, image| {
                sum.checked_add(image.normalized_byte_length())
            });
        let image_count = self
            .paste_registry
            .blocks()
            .iter()
            .filter(|block| {
                matches!(
                    block.kind,
                    PasteKind::Image { .. } | PasteKind::ImageHandle { .. }
                )
            })
            .count();
        normalized_byte_length > 0
            && normalized_byte_length <= cockpit_proto::MAX_SINGLE_IMAGE_BYTES as u64
            && retained_bytes
                .is_some_and(|total| total <= cockpit_proto::MAX_TOTAL_IMAGE_BYTES as u64)
            && image_count < cockpit_proto::MAX_IMAGES_PER_USER_MESSAGE
    }

    pub(crate) fn try_insert_image(&mut self, png: Vec<u8>) -> bool {
        if !self.can_insert_image(png.len() as u64) {
            return false;
        }
        let at = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        self.composer.set_cursor(at);
        let (block_id, placeholder) = self.paste_registry.register_image_with_id(at, png);
        self.composer.insert_str(&placeholder);
        self.paste_registry
            .shift_other_blocks_after_insert(block_id, at, placeholder.len());
        self.reconcile();
        true
    }

    pub(crate) fn try_insert_image_handle(
        &mut self,
        draft: ImageIngressDraftAuthority,
        image_ref: cockpit_proto::ImageAttachmentRef,
        normalized_byte_length: u64,
        sha256: String,
    ) -> bool {
        if !self.can_insert_image_handle(normalized_byte_length) {
            return false;
        }
        let at = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        self.composer.set_cursor(at);
        let (block_id, placeholder) = self.paste_registry.register_image_handle_with_id(
            at,
            draft,
            image_ref,
            normalized_byte_length,
            sha256,
        );
        self.composer.insert_str(&placeholder);
        self.paste_registry
            .shift_other_blocks_after_insert(block_id, at, placeholder.len());
        self.reconcile();
        true
    }

    pub(crate) fn probe_motion(&mut self, motion: ComposerMotion) -> usize {
        self.composer
            .probe_motion(|composer| Self::apply_motion(composer, motion))
    }

    pub(crate) fn apply_operator_motion(
        &mut self,
        operator: Operator,
        motion: ComposerMotion,
        inclusive: bool,
    ) -> bool {
        let from = self.composer.cursor();
        let to = self.probe_motion(motion);
        if from == to {
            return false;
        }
        let (lo, hi) = if from <= to {
            let hi = if inclusive {
                self.composer
                    .text()
                    .get(to..)
                    .and_then(|text| text.chars().next())
                    .map_or(to, |ch| to + ch.len_utf8())
            } else {
                to
            };
            (from, hi)
        } else {
            (to, from)
        };
        self.apply_operator_range(operator, lo, hi);
        true
    }

    pub(crate) fn apply_operator_range(
        &mut self,
        operator: Operator,
        mut lo: usize,
        mut hi: usize,
    ) {
        if let Some((block_start, block_end)) = self.paste_registry.block_crossed_by(lo, hi) {
            lo = lo.min(block_start);
            hi = hi.max(block_end);
        }
        match operator {
            Operator::Yank => {
                self.composer.yank_range(lo, hi, false);
                self.composer.set_cursor(lo);
            }
            Operator::Delete | Operator::Change => {
                let _ = self.cut_range(lo, hi, false);
            }
        }
    }

    pub(crate) fn visual_operate(&mut self, operator: Operator) {
        let linewise = self.composer.vim_mode() == VimMode::VisualLine;
        let Some((mut lo, mut hi)) = self.composer.visual_range() else {
            self.composer.end_visual();
            return;
        };
        if lo >= hi {
            self.composer.end_visual();
            return;
        }
        if let Some((block_start, block_end)) = self.paste_registry.block_crossed_by(lo, hi) {
            lo = lo.min(block_start);
            hi = hi.max(block_end);
        }
        match operator {
            Operator::Yank => {
                self.yank_range(lo, hi, linewise);
                self.composer.set_cursor(lo);
                self.composer.set_vim_mode(VimMode::Normal);
            }
            Operator::Delete | Operator::Change => {
                let _ = self.cut_range(lo, hi, linewise);
                self.composer
                    .set_vim_mode(if matches!(operator, Operator::Change) {
                        VimMode::Insert
                    } else {
                        VimMode::Normal
                    });
            }
        }
        self.composer.clear_visual_anchor();
    }

    pub(crate) fn cut_char_forward(&mut self) -> bool {
        let from = self.composer.cursor();
        let Some(ch) = self.composer.text()[from..].chars().next() else {
            return false;
        };
        if ch == '\n' {
            return false;
        }
        self.cut_range(from, from + ch.len_utf8(), false).is_some()
    }

    #[cfg(test)]
    pub(crate) fn insert_registered_text(&mut self, full: String, tokens: usize) -> u64 {
        let at = self
            .paste_registry
            .resolve_insertion(self.composer.cursor());
        let placeholder = self.paste_registry.register_text(at, full.clone(), tokens);
        let block_id = self
            .paste_registry
            .blocks()
            .iter()
            .rev()
            .find(|block| {
                block.start == at
                    && block.end == at + placeholder.len()
                    && matches!(&block.kind, PasteKind::Text { full: stored, .. } if stored == &full)
            })
            .expect("registered text block exists")
            .id;
        self.composer.set_cursor(at);
        self.composer.insert_str(&placeholder);
        self.paste_registry
            .shift_other_blocks_after_insert(block_id, at, placeholder.len());
        self.reconcile();
        block_id
    }

    #[cfg(test)]
    pub(crate) fn insert_registered_image(&mut self, png: Vec<u8>) -> u64 {
        assert!(self.try_insert_image(png), "test image is admissible");
        self.paste_registry
            .block_ending_at(self.composer.cursor())
            .expect("registered image block exists")
            .id
    }

    fn paste_register(&mut self, after: bool) {
        if self.composer.register().text.is_empty() {
            return;
        }
        let before_len = self.composer.len();
        let before_cursor = self.composer.cursor();
        let snapped = self.paste_registry.skip_cursor(before_cursor, after);
        self.composer.set_cursor(snapped);
        let cursor = self.composer.cursor();
        let register = self.composer.register().clone();
        let anchor = if register.linewise {
            if after {
                self.composer.text()[cursor..]
                    .find('\n')
                    .map(|index| cursor + index + 1)
                    .unwrap_or(self.composer.len())
            } else {
                self.composer.text()[..cursor]
                    .rfind('\n')
                    .map(|index| index + 1)
                    .unwrap_or(0)
            }
        } else if after {
            self.composer.semantic_boundary_after_cursor()
        } else {
            cursor
        };
        if after {
            self.composer.paste_after();
        } else {
            self.composer.paste_before();
        }
        let inserted = self.composer.len() as isize - before_len as isize;
        if inserted > 0 {
            self.paste_registry.shift_for_edit(anchor, inserted);
        }
        self.reconcile();
    }

    fn snap_off_block(&mut self, forward: bool) {
        let landed = self
            .paste_registry
            .skip_cursor(self.composer.cursor(), forward);
        self.composer.set_cursor(landed);
    }

    fn reconcile(&mut self) {
        self.paste_registry.reconcile_buffer(self.composer.text());
    }

    fn apply_motion(composer: &mut Composer, motion: ComposerMotion) {
        match motion {
            ComposerMotion::Up => composer.move_up(),
            ComposerMotion::Down => composer.move_down(),
            ComposerMotion::LineStart => composer.move_line_start(),
            ComposerMotion::LineEnd => composer.move_line_end(),
            ComposerMotion::BufferStart => composer.move_buffer_start(),
            ComposerMotion::BufferEnd => composer.move_buffer_end(),
            ComposerMotion::WordForward { big } => composer.move_word_forward(big),
            ComposerMotion::WordBackward { big } => composer.move_word_backward(big),
            ComposerMotion::WordEnd { big } => composer.move_word_end(big),
            ComposerMotion::WordEndBackward { big } => composer.move_word_end_backward(big),
            ComposerMotion::MatchBracket => composer.match_bracket(),
            ComposerMotion::RepeatFind { reverse } => {
                composer.repeat_find(reverse);
            }
            ComposerMotion::Absolute(position) => composer.set_cursor(position),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RegisteredComposer;
    use crate::tui::paste::PasteRegistry;

    #[test]
    fn adversarial_cursor_and_insert_cannot_split_registered_placeholder() {
        let mut owner = RegisteredComposer::new(false);
        owner.insert_registered_text("full payload".to_string(), 2);
        let original = owner.paste_blocks()[0].clone();

        owner.set_cursor(original.start + 3);
        owner.insert_char('>');

        let block = &owner.paste_blocks()[0];
        assert_eq!(
            &owner.text()[block.start..block.end],
            PasteRegistry::text_placeholder(1, 2)
        );
        assert!(owner.cursor() <= block.start || owner.cursor() >= block.end);
    }

    #[test]
    fn semantic_grapheme_cursor_survives_registered_edit_routes() {
        let mut owner = RegisteredComposer::new(false);
        owner.insert_str("a👨‍👩‍👧‍👦b");
        let inside_family = "a👨".len();

        owner.set_cursor(inside_family);
        owner.insert_char('!');

        assert!(owner.text().contains("👨‍👩‍👧‍👦"));
        assert!(
            crate::tui::markdown::semantic_graphemes(owner.text())
                .iter()
                .scan(0usize, |offset, grapheme| {
                    *offset += grapheme.len();
                    Some(*offset)
                })
                .any(|boundary| boundary == owner.cursor())
        );
    }

    #[test]
    fn whole_buffer_replacement_retires_paste_authority() {
        let mut owner = RegisteredComposer::new(false);
        owner.insert_registered_image(vec![1, 2, 3]);

        owner.replace_buffer("plain replacement");

        assert_eq!(owner.text(), "plain replacement");
        assert!(owner.paste_is_empty());
    }

    #[test]
    fn editor_snapshot_rebuild_installs_buffer_and_registry_together() {
        let mut owner = RegisteredComposer::new(false);
        owner.insert_registered_text("expanded editor payload".to_string(), 3);
        let editor = owner.editor_text();
        let snapshot = owner.editor_snapshot();
        owner.rebuild_from_editor(&editor, &snapshot);

        assert_eq!(owner.paste_blocks().len(), 1);
        assert_eq!(
            owner.plain_payload().as_deref(),
            Some("expanded editor payload")
        );
    }
}
