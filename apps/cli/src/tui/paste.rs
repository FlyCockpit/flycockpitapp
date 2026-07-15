//! Composer paste blocks: condensed text + pasted images
//! (composer-paste-handling).
//!
//! Large text pastes collapse into a compact atomic placeholder; pasted
//! images become atomic placeholder blocks. Both behave like the `@`-tag
//! spans: indivisible, cursor-skipped, deleted as a unit.
//!
//! **Span registry, not re-detection.** Unlike `@`-tags — which are
//! re-derived from buffer text on every keystroke (`completed_tag_span`
//! in `app/input.rs`) — paste placeholders are *not* uniquely recoverable
//! from the visible string, and the real payload (full text / image
//! bytes) lives outside it. So we keep an explicit [`PasteRegistry`] of
//! blocks keyed to byte ranges in the composer buffer and shift those
//! ranges whenever an edit before/after a block moves its offsets.
//!
//! The registry never owns the buffer; the [`super::composer::Composer`]
//! does. Every composer mutation that the app makes routes its byte
//! offset + delta through [`PasteRegistry::shift_for_edit`] so the two
//! stay in lockstep.

use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const USER_PASTE_TAG: &str = "user_paste";
const DISPLAY_PASTE_RULE: &str = "---";
const USER_PASTE_OPEN_PREFIX: &str = "<user_paste id=\"";
const PASTED_IMAGE_PREFIX: &str = "[Pasted image #";

/// Text paste collapses into a condensed block only when it exceeds this
/// many lines **or** [`CONDENSE_CHAR_THRESHOLD`] characters. Smaller
/// pastes insert as raw text (settled UX decision).
pub const CONDENSE_LINE_THRESHOLD: usize = 2;
/// See [`CONDENSE_LINE_THRESHOLD`].
pub const CONDENSE_CHAR_THRESHOLD: usize = 320;

/// Whether a paste of `content` should collapse into a condensed text
/// block. Rule (settled): more than 2 lines OR more than 320 chars.
pub fn should_condense(content: &str) -> bool {
    let lines = content.split('\n').count();
    lines > CONDENSE_LINE_THRESHOLD || content.chars().count() > CONDENSE_CHAR_THRESHOLD
}

/// Content hash of decoded image bytes, used to dedup repeat pastes of
/// the same image so the second one is sent as a `[reference image #N]`
/// rather than re-transmitting the bytes.
fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// The payload behind a paste block. Text blocks carry the full expanded
/// text (sent inline to the model); image blocks carry PNG bytes + a
/// content hash + whether this occurrence is a duplicate reference.
#[derive(Debug, Clone)]
pub enum PasteKind {
    /// Condensed text. `full` is the verbatim pasted text the model
    /// receives inline at this block's position (display-only
    /// condensation — the placeholder is never sent for text).
    /// `tokens` is display metadata only; `None` means the exact count is
    /// still being computed off the input path.
    Text {
        full: String,
        tokens: Option<usize>,
        nonce: String,
    },
    /// Pasted image. `png` is the PNG-encoded bytes; `hash` dedups
    /// repeats; `reference` is true when this is a duplicate paste of an
    /// image already in the buffer (sent as `[reference image #N]`, bytes
    /// carried only by the first occurrence).
    Image {
        png: Vec<u8>,
        hash: u64,
        reference: bool,
    },
}

/// One registered paste block. The byte range `[start, end)` indexes into
/// the composer buffer and is the placeholder's exact extent; the app
/// keeps it in sync via [`PasteRegistry::shift_for_edit`].
#[derive(Debug, Clone)]
pub struct PasteBlock {
    pub id: u64,
    pub start: usize,
    pub end: usize,
    /// 1-based display number (`#N`): per-composer running index over
    /// condensed text pastes for [`PasteKind::Text`], over *distinct*
    /// images for [`PasteKind::Image`]. The visible placeholder text
    /// lives in the composer buffer at `[start, end)` — the registry
    /// tracks only the range, number, and payload.
    pub number: u32,
    pub kind: PasteKind,
}

/// The per-composer block registry. Blocks are kept sorted by `start`.
#[derive(Debug)]
pub struct PasteRegistry {
    blocks: Vec<PasteBlock>,
    next_block_id: u64,
}

#[derive(Debug)]
pub struct EditorPasteRebuild {
    pub buffer: String,
    pub registry: PasteRegistry,
}

impl Default for PasteRegistry {
    fn default() -> Self {
        Self {
            blocks: Vec::new(),
            next_block_id: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasteTextCountReplacement {
    pub start: usize,
    pub end: usize,
    pub replacement: String,
}

impl PasteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn blocks(&self) -> &[PasteBlock] {
        &self.blocks
    }

    /// Mutable access to the block list, for the app's post-insert offset
    /// fix-up (the only caller that adjusts ranges outside
    /// [`Self::shift_for_edit`]).
    pub fn blocks_mut(&mut self) -> &mut [PasteBlock] {
        &mut self.blocks
    }

    /// Clear all blocks (after submit / composer clear).
    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    /// Next 1-based number for a fresh condensed text block.
    fn next_text_number(&self) -> u32 {
        self.blocks
            .iter()
            .filter(|b| matches!(b.kind, PasteKind::Text { .. }))
            .count() as u32
            + 1
    }

    /// The display number to use for an image with this content hash. A
    /// prior occurrence of the same image reuses its number (and the new
    /// block becomes a `reference`); otherwise it's the next distinct
    /// image index. Returns `(number, is_duplicate)`.
    fn image_number_for(&self, hash: u64) -> (u32, bool) {
        if let Some(existing) = self.blocks.iter().find_map(|b| match &b.kind {
            PasteKind::Image { hash: h, .. } if *h == hash => Some(b.number),
            _ => None,
        }) {
            return (existing, true);
        }
        let distinct = self
            .blocks
            .iter()
            .filter_map(|b| match &b.kind {
                PasteKind::Image { hash, .. } => Some(*hash),
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>()
            .len() as u32;
        (distinct + 1, false)
    }

    fn next_block_id(&mut self) -> u64 {
        let id = self.next_block_id;
        self.next_block_id = self.next_block_id.saturating_add(1);
        id
    }

    /// Format a condensed text placeholder with an exact count:
    /// `[Pasted text #N, X tokens]`.
    pub fn text_placeholder(number: u32, tokens: usize) -> String {
        format!("[Pasted text #{number}, {tokens} tokens]")
    }

    /// Format a condensed text placeholder whose exact count is pending.
    pub fn pending_text_placeholder(number: u32) -> String {
        format!("[Pasted text #{number}, counting tokens]")
    }

    /// Format an image placeholder: `[Pasted image #N]`.
    pub fn image_placeholder(number: u32) -> String {
        format!("[Pasted image #{number}]")
    }

    /// Insert a block record for a condensed text paste with a known exact
    /// token count. Mostly used by tests and any caller that has already
    /// counted off the input path.
    #[cfg(test)]
    pub fn register_text(&mut self, at: usize, full: String, tokens: usize) -> String {
        let (_id, placeholder) = self.register_text_with_state(at, full, Some(tokens));
        placeholder
    }

    /// Insert a block record for a condensed text paste whose exact token
    /// count will arrive later. Returns the stable block id plus the
    /// pending placeholder the caller must insert into the composer buffer.
    pub fn register_text_pending(&mut self, at: usize, full: String) -> (u64, String) {
        self.register_text_with_state(at, full, None)
    }

    fn register_text_with_state(
        &mut self,
        at: usize,
        full: String,
        tokens: Option<usize>,
    ) -> (u64, String) {
        let nonce = Self::text_nonce(&full);
        self.register_text_with_state_and_nonce(at, full, tokens, nonce)
    }

    fn register_text_with_state_and_nonce(
        &mut self,
        at: usize,
        full: String,
        tokens: Option<usize>,
        nonce: String,
    ) -> (u64, String) {
        let id = self.next_block_id();
        let number = self.next_text_number();
        let placeholder = match tokens {
            Some(tokens) => Self::text_placeholder(number, tokens),
            None => Self::pending_text_placeholder(number),
        };
        let end = at + placeholder.len();
        self.insert_sorted(PasteBlock {
            id,
            start: at,
            end,
            number,
            kind: PasteKind::Text {
                full,
                tokens,
                nonce,
            },
        });
        (id, placeholder)
    }

    /// Insert a block record for a pasted image at byte `at`. Dedups by
    /// content hash: a repeat paste reuses the original's `#N` and is
    /// flagged a `reference` (sent as text at send time). Returns the
    /// placeholder string the caller must insert into the buffer.
    pub fn register_image(&mut self, at: usize, png: Vec<u8>) -> String {
        let hash = hash_bytes(&png);
        let (number, reference) = self.image_number_for(hash);
        let placeholder = Self::image_placeholder(number);
        let end = at + placeholder.len();
        let id = self.next_block_id();
        self.insert_sorted(PasteBlock {
            id,
            start: at,
            end,
            number,
            kind: PasteKind::Image {
                png,
                hash,
                reference,
            },
        });
        placeholder
    }

    pub fn apply_text_token_count(
        &mut self,
        block_id: u64,
        tokens: usize,
    ) -> Option<PasteTextCountReplacement> {
        let idx = self.blocks.iter().position(|b| b.id == block_id)?;
        let (number, start, old_end) = {
            let block = &self.blocks[idx];
            match &block.kind {
                PasteKind::Text { tokens: None, .. } => (block.number, block.start, block.end),
                _ => return None,
            }
        };
        let replacement = Self::text_placeholder(number, tokens);
        let new_end = start + replacement.len();
        let delta = replacement.len() as isize - (old_end - start) as isize;
        if let PasteKind::Text { tokens: slot, .. } = &mut self.blocks[idx].kind {
            *slot = Some(tokens);
        }
        self.blocks[idx].end = new_end;
        if delta != 0 {
            if delta > 0 {
                let d = delta as usize;
                for block in self.blocks.iter_mut().skip(idx + 1) {
                    block.start += d;
                    block.end += d;
                }
            } else {
                let d = (-delta) as usize;
                for block in self.blocks.iter_mut().skip(idx + 1) {
                    block.start = block.start.saturating_sub(d);
                    block.end = block.end.saturating_sub(d);
                }
            }
        }
        Some(PasteTextCountReplacement {
            start,
            end: old_end,
            replacement,
        })
    }

    fn text_nonce(full: &str) -> String {
        loop {
            let nonce = uuid::Uuid::new_v4().simple().to_string();
            if !full.contains(&Self::user_paste_close_tag(&nonce)) {
                return nonce;
            }
        }
    }

    fn user_paste_open_tag(nonce: &str) -> String {
        format!("<{USER_PASTE_TAG} id=\"{nonce}\">")
    }

    fn user_paste_close_tag(nonce: &str) -> String {
        format!("</{USER_PASTE_TAG} id=\"{nonce}\">")
    }

    fn append_user_paste_wire(out: &mut String, full: &str, nonce: &str) {
        out.push_str(&Self::user_paste_open_tag(nonce));
        out.push_str(full);
        out.push_str(&Self::user_paste_close_tag(nonce));
    }

    fn parse_user_paste_open(text: &str) -> Option<(&str, usize)> {
        let rest = text.strip_prefix(USER_PASTE_OPEN_PREFIX)?;
        let end_quote = rest.find("\">")?;
        let nonce = &rest[..end_quote];
        if nonce.is_empty() {
            return None;
        }
        Some((nonce, USER_PASTE_OPEN_PREFIX.len() + end_quote + 2))
    }

    fn parse_image_placeholder_at(text: &str) -> Option<(u32, usize)> {
        let rest = text.strip_prefix(PASTED_IMAGE_PREFIX)?;
        let digit_len = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digit_len == 0 || rest.as_bytes().get(digit_len) != Some(&b']') {
            return None;
        }
        let number = rest[..digit_len].parse::<u32>().ok()?;
        Some((number, PASTED_IMAGE_PREFIX.len() + digit_len + 1))
    }

    fn next_image_placeholder(text: &str) -> Option<(usize, u32, usize)> {
        let mut search_start = 0usize;
        while search_start < text.len() {
            let rel = text[search_start..].find(PASTED_IMAGE_PREFIX)?;
            let start = search_start + rel;
            if let Some((number, len)) = Self::parse_image_placeholder_at(&text[start..]) {
                return Some((start, number, len));
            }
            search_start = start + 1;
        }
        None
    }

    fn display_paste_boundary(number: u32, edge: &str) -> String {
        format!("{DISPLAY_PASTE_RULE} paste #{number} {edge} {DISPLAY_PASTE_RULE}")
    }

    fn append_display_paste(out: &mut String, full: &str, number: u32) {
        out.push_str(&Self::display_paste_boundary(number, "start"));
        out.push('\n');
        out.push_str(full);
        if !full.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&Self::display_paste_boundary(number, "end"));
    }

    fn insert_sorted(&mut self, block: PasteBlock) {
        let pos = self
            .blocks
            .iter()
            .position(|b| b.start > block.start)
            .unwrap_or(self.blocks.len());
        self.blocks.insert(pos, block);
    }

    /// Keep block byte-ranges in sync after an edit of magnitude `delta`
    /// (positive = insertion, negative = deletion) applied at byte `at`.
    ///
    /// - Insertion at `at`: every block whose `start >= at` shifts right
    ///   by `delta`. A block straddling `at` cannot happen because
    ///   insertion points always resolve to a boundary (the app enforces
    ///   this via [`Self::resolve_insertion`]).
    /// - Deletion of `[at, at-delta)`: handled by the caller's
    ///   whole-block delete path for block-spanning deletes; for ordinary
    ///   edits outside any block, blocks entirely after the deleted range
    ///   shift left, and the deleted range never overlaps a block
    ///   interior.
    pub fn shift_for_edit(&mut self, at: usize, delta: isize) {
        if delta == 0 {
            return;
        }
        if delta > 0 {
            let d = delta as usize;
            for b in &mut self.blocks {
                if b.start >= at {
                    b.start += d;
                    b.end += d;
                }
            }
        } else {
            let d = (-delta) as usize;
            let removed_end = at + d;
            // Drop any block fully inside the removed range (whole-block
            // delete already chose to remove it), and shift blocks that
            // start at/after the removal's end.
            self.blocks
                .retain(|b| !(b.start >= at && b.end <= removed_end));
            for b in &mut self.blocks {
                if b.start >= removed_end {
                    b.start -= d;
                    b.end -= d;
                } else if b.start >= at {
                    // Defensive: a partial overlap should never occur
                    // because edits never land inside a block interior.
                    // Clamp rather than corrupt.
                    b.start = at;
                    b.end = b.end.saturating_sub(d);
                }
            }
        }
    }

    /// The block whose closing boundary (`end`) is exactly at `cursor` —
    /// i.e. the cursor sits immediately right of `]`. Used by Backspace
    /// to delete the whole block.
    pub fn block_ending_at(&self, cursor: usize) -> Option<&PasteBlock> {
        self.blocks.iter().find(|b| b.end == cursor)
    }

    /// The block whose opening boundary (`start`) is exactly at `cursor` —
    /// i.e. the cursor sits immediately left of `[`. Used by
    /// forward-`Delete`.
    pub fn block_starting_at(&self, cursor: usize) -> Option<&PasteBlock> {
        self.blocks.iter().find(|b| b.start == cursor)
    }

    /// The block strictly containing `pos` in its interior
    /// (`start < pos < end`). Used to forbid the cursor landing inside a
    /// block and to resolve insertion points to a boundary.
    pub fn block_containing(&self, pos: usize) -> Option<&PasteBlock> {
        self.blocks.iter().find(|b| pos > b.start && pos < b.end)
    }

    /// Resolve an insertion point so it never lands inside a block. A
    /// position strictly inside a block snaps to that block's nearer
    /// boundary (ties favor the right edge, matching `@`-tag feel).
    pub fn resolve_insertion(&self, pos: usize) -> usize {
        match self.block_containing(pos) {
            Some(b) => {
                if pos - b.start < b.end - pos {
                    b.start
                } else {
                    b.end
                }
            }
            None => pos,
        }
    }

    /// Adjust a cursor position so it never sits in a block interior,
    /// snapping toward the direction of travel: when moving right
    /// (`forward = true`) land on the far (`end`) boundary; when moving
    /// left land on the near (`start`) boundary. This is what makes arrow
    /// keys and vim motions treat a block as one unit.
    pub fn skip_cursor(&self, pos: usize, forward: bool) -> usize {
        match self.block_containing(pos) {
            Some(b) => {
                if forward {
                    b.end
                } else {
                    b.start
                }
            }
            None => pos,
        }
    }

    /// The block fully covered by a motion/operator that moved the cursor
    /// from `from` to `to` (in either direction) such that the range
    /// `[lo, hi)` overlaps the block — so a vim delete/change crossing it
    /// should remove the whole block. Returns the block's full span so the
    /// caller can widen the delete range to a block boundary.
    pub fn block_crossed_by(&self, from: usize, to: usize) -> Option<(usize, usize)> {
        let (lo, hi) = if from <= to { (from, to) } else { (to, from) };
        self.blocks
            .iter()
            .find(|b| b.start < hi && b.end > lo)
            .map(|b| (b.start, b.end))
    }

    /// If `cursor` is at the right edge (`end`) of a condensed *text*
    /// block whose stored content equals `pasted`, return that block's
    /// span — the caller replaces `[start, end)` with the raw text and
    /// drops the block (re-paste-to-expand). `None` otherwise.
    pub fn expandable_text_at(
        &self,
        cursor: usize,
        pasted: &str,
    ) -> Option<(usize, usize, String)> {
        self.blocks.iter().find_map(|b| match &b.kind {
            PasteKind::Text { full, .. } if b.end == cursor && full == pasted => {
                Some((b.start, b.end, full.clone()))
            }
            _ => None,
        })
    }

    /// Drop the block whose range is exactly `[start, end)` (used after a
    /// whole-block delete the caller performed on the buffer). Also
    /// shifts the trailing blocks left by the removed length.
    pub fn remove_range(&mut self, start: usize, end: usize) {
        self.shift_for_edit(start, -((end - start) as isize));
    }

    fn expand_blocks(
        &self,
        buffer: &str,
        mut render_block: impl FnMut(&mut String, &PasteBlock),
    ) -> String {
        let mut out = String::with_capacity(buffer.len());
        let mut prev = 0usize;
        for block in &self.blocks {
            out.push_str(&buffer[prev..block.start]);
            render_block(&mut out, block);
            prev = block.end;
        }
        out.push_str(&buffer[prev..]);
        out
    }

    /// Build the per-occurrence wire pieces for send time. Walks the
    /// buffer text left→right, replacing each block placeholder with the
    /// appropriate wire form and emitting image parts in order:
    ///
    /// - Text block → its full expanded text inlined at the placeholder's
    ///   position (display-only condensation).
    /// - Image block, `vision = true`, first occurrence → keep a sentinel
    ///   marker in the text and push the PNG into `images` (the caller
    ///   threads it into a `UserContent::Image` part). A duplicate
    ///   (`reference`) → the literal text `[reference image #N]`, no bytes.
    /// - Image block, `vision = false` → a terse text note
    ///   `[Pasted image #N: not sent — current model has no image support]`.
    ///
    /// Returns `(wire_text, images)` where `images` is the ordered list of
    /// PNG payloads to attach as real image parts. The wire text carries
    /// [`IMAGE_PART_SENTINEL`] markers at the positions where each attached
    /// image part should appear; the caller splits on them to interleave
    /// text and image content parts. (For non-vision and reference cases
    /// no sentinel is emitted — those are pure text.)
    pub fn build_wire(&self, buffer: &str, vision: bool) -> (String, Vec<Vec<u8>>) {
        let mut images = Vec::new();
        let out = self.expand_blocks(buffer, |out, block| match &block.kind {
            PasteKind::Text { full, nonce, .. } => {
                Self::append_user_paste_wire(out, full, nonce);
            }
            PasteKind::Image { png, reference, .. } => {
                if !vision {
                    out.push_str(&format!(
                        "[Pasted image #{}: not sent — current model has no image support]",
                        block.number
                    ));
                } else if *reference {
                    out.push_str(&format!("[reference image #{}]", block.number));
                } else {
                    out.push_str(IMAGE_PART_SENTINEL);
                    images.push(png.clone());
                }
            }
        });
        (out, images)
    }

    /// Build the marker-free transcript display for send time. Text
    /// blocks expand to their full pasted content inside display-only
    /// boundaries; image placeholders remain literal.
    pub fn expand_display(&self, buffer: &str) -> String {
        self.expand_blocks(buffer, |out, block| match &block.kind {
            PasteKind::Text { full, .. } => {
                Self::append_display_paste(out, full, block.number);
            }
            PasteKind::Image { .. } => out.push_str(&buffer[block.start..block.end]),
        })
    }

    /// Build the text handed to `$EDITOR`. Text paste blocks are expanded
    /// with stable nonce tags so they can be rebuilt on return; images stay
    /// as visible placeholders because their bytes cannot live in the file.
    pub fn expand_editor(&self, buffer: &str) -> String {
        self.expand_blocks(buffer, |out, block| match &block.kind {
            PasteKind::Text { full, nonce, .. } => {
                Self::append_user_paste_wire(out, full, nonce);
            }
            PasteKind::Image { .. } => out.push_str(&buffer[block.start..block.end]),
        })
    }

    /// Retain one payload for each visible image number before an external
    /// editor round-trip. Returned text maps `[Pasted image #N]` back through
    /// this table; missing placeholders are dropped.
    pub fn image_payloads_by_number(&self) -> BTreeMap<u32, Vec<u8>> {
        let mut images = BTreeMap::new();
        for block in &self.blocks {
            if let PasteKind::Image { png, .. } = &block.kind {
                images.entry(block.number).or_insert_with(|| png.clone());
            }
        }
        images
    }

    /// Parse editor-returned text into a normal composer buffer plus a fresh
    /// registry. Well-formed `<user_paste id="...">...</user_paste id="...">`
    /// regions become condensed text blocks. Surviving image placeholders
    /// are rebuilt from `retained_images`; unknown image numbers remain text.
    pub fn rebuild_from_editor(
        editor_text: &str,
        retained_images: &BTreeMap<u32, Vec<u8>>,
        mut count_text: impl FnMut(&str) -> usize,
    ) -> EditorPasteRebuild {
        let mut buffer = String::with_capacity(editor_text.len());
        let mut registry = PasteRegistry::new();
        let mut pos = 0usize;

        while pos < editor_text.len() {
            let rest = &editor_text[pos..];
            let next_text = rest.find(USER_PASTE_OPEN_PREFIX);
            let next_image = Self::next_image_placeholder(rest);

            let use_text = match (next_text, next_image) {
                (Some(text_start), Some((image_start, _, _))) => text_start <= image_start,
                (Some(_), None) => true,
                _ => false,
            };

            if use_text {
                let start = next_text.expect("text event exists");
                buffer.push_str(&rest[..start]);
                let absolute_start = pos + start;
                let tag_text = &editor_text[absolute_start..];
                let Some((nonce, open_len)) = Self::parse_user_paste_open(tag_text) else {
                    buffer.push_str(tag_text);
                    break;
                };
                let close_tag = Self::user_paste_close_tag(nonce);
                let content_start = absolute_start + open_len;
                let Some(close_rel) = editor_text[content_start..].find(&close_tag) else {
                    buffer.push_str(tag_text);
                    break;
                };
                let close_start = content_start + close_rel;
                let full = editor_text[content_start..close_start].to_string();
                let at = buffer.len();
                let tokens = count_text(&full);
                let (_id, placeholder) = registry.register_text_with_state_and_nonce(
                    at,
                    full,
                    Some(tokens),
                    nonce.into(),
                );
                buffer.push_str(&placeholder);
                pos = close_start + close_tag.len();
                continue;
            }

            let Some((image_start, image_number, image_len)) = next_image else {
                buffer.push_str(rest);
                break;
            };
            buffer.push_str(&rest[..image_start]);
            let image_text_start = pos + image_start;
            let image_text = &editor_text[image_text_start..image_text_start + image_len];
            if let Some(png) = retained_images.get(&image_number) {
                let placeholder = registry.register_image(buffer.len(), png.clone());
                buffer.push_str(&placeholder);
            } else {
                buffer.push_str(image_text);
            }
            pos = image_text_start + image_len;
        }

        EditorPasteRebuild { buffer, registry }
    }
}

/// Marker inserted into the wire text at each real-image-part position so
/// the caller can interleave text and image content parts in order. Chosen
/// to be vanishingly unlikely in user text and inert if it somehow leaks
/// through (it reads as a tagged placeholder).
pub use crate::daemon::proto::IMAGE_PART_SENTINEL;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condense_rule_lines_or_chars() {
        // Under both thresholds → raw.
        assert!(!should_condense("one line"));
        assert!(!should_condense("line1\nline2")); // exactly 2 lines
        // Over the line threshold.
        assert!(should_condense("a\nb\nc")); // 3 lines
        // Over the char threshold (one line, 321 chars).
        let long = "x".repeat(321);
        assert!(should_condense(&long));
        // Exactly at the char threshold is not over.
        let at = "y".repeat(320);
        assert!(!should_condense(&at));
    }

    #[test]
    fn text_numbering_is_running_and_one_based() {
        let mut r = PasteRegistry::new();
        let p1 = r.register_text(0, "full one".into(), 5);
        assert_eq!(p1, "[Pasted text #1, 5 tokens]");
        let at = p1.len();
        let p2 = r.register_text(at, "full two".into(), 9);
        assert_eq!(p2, "[Pasted text #2, 9 tokens]");
    }

    #[test]
    fn pending_text_placeholder_can_be_completed_by_block_id() {
        let mut r = PasteRegistry::new();
        let (id, pending) = r.register_text_pending(0, "full one".into());
        assert_eq!(pending, "[Pasted text #1, counting tokens]");
        let replacement = r
            .apply_text_token_count(id, 5)
            .expect("pending block accepts count");
        assert_eq!(
            replacement,
            PasteTextCountReplacement {
                start: 0,
                end: pending.len(),
                replacement: "[Pasted text #1, 5 tokens]".to_string(),
            }
        );
        assert!(r.apply_text_token_count(id, 6).is_none());
    }

    #[test]
    fn completing_pending_text_count_shifts_later_blocks() {
        let mut r = PasteRegistry::new();
        let (id, pending) = r.register_text_pending(0, "full one".into());
        let ready = r.register_text(pending.len(), "full two".into(), 9);

        let replacement = r.apply_text_token_count(id, 5).unwrap();

        let first = &r.blocks()[0];
        let second = &r.blocks()[1];
        assert_eq!(first.end, replacement.replacement.len());
        assert_eq!(
            (second.start, second.end),
            (
                replacement.replacement.len(),
                replacement.replacement.len() + ready.len()
            )
        );
    }

    #[test]
    fn image_numbering_distinct_and_duplicate_reuses() {
        let mut r = PasteRegistry::new();
        let a = vec![1u8, 2, 3, 4];
        let b = vec![9u8, 8, 7];
        let p1 = r.register_image(0, a.clone());
        assert_eq!(p1, "[Pasted image #1]");
        let p2 = r.register_image(p1.len(), b.clone());
        assert_eq!(p2, "[Pasted image #2]");
        // Duplicate of the first image reuses #1 and is a reference.
        let p3 = r.register_image(p1.len() + p2.len(), a.clone());
        assert_eq!(p3, "[Pasted image #1]");
        let dup = r.blocks().last().unwrap();
        assert!(matches!(
            dup.kind,
            PasteKind::Image {
                reference: true,
                ..
            }
        ));
    }

    #[test]
    fn backspace_right_of_close_finds_whole_block() {
        let mut r = PasteRegistry::new();
        let p = r.register_text(3, "body".into(), 2); // buffer: "abc[...]"
        let end = 3 + p.len();
        assert!(r.block_ending_at(end).is_some());
        assert!(r.block_ending_at(end - 1).is_none()); // mid-block
    }

    #[test]
    fn forward_delete_left_of_open_finds_whole_block() {
        let mut r = PasteRegistry::new();
        r.register_text(3, "body".into(), 2);
        assert!(r.block_starting_at(3).is_some());
        assert!(r.block_starting_at(4).is_none());
    }

    #[test]
    fn cursor_never_lands_inside_a_block() {
        let mut r = PasteRegistry::new();
        let p = r.register_text(2, "body".into(), 2);
        let mid = 2 + p.len() / 2;
        assert!(r.block_containing(mid).is_some());
        // Insertion resolves to a boundary.
        let resolved = r.resolve_insertion(mid);
        assert!(resolved == 2 || resolved == 2 + p.len());
    }

    #[test]
    fn motion_lands_on_far_boundary() {
        let mut r = PasteRegistry::new();
        let p = r.register_text(2, "body".into(), 2);
        let mid = 2 + 3;
        // Moving right out of the interior lands on `end`.
        assert_eq!(r.skip_cursor(mid, true), 2 + p.len());
        // Moving left lands on `start`.
        assert_eq!(r.skip_cursor(mid, false), 2);
    }

    #[test]
    fn offset_sync_when_editing_before_a_block() {
        let mut r = PasteRegistry::new();
        let p = r.register_text(5, "body".into(), 2);
        let (s0, e0) = {
            let b = &r.blocks()[0];
            (b.start, b.end)
        };
        assert_eq!((s0, e0), (5, 5 + p.len()));
        // Insert 3 chars before the block.
        r.shift_for_edit(2, 3);
        let b = &r.blocks()[0];
        assert_eq!((b.start, b.end), (8, 8 + p.len()));
        // Delete 4 chars before the block.
        r.shift_for_edit(0, -4);
        let b = &r.blocks()[0];
        assert_eq!((b.start, b.end), (4, 4 + p.len()));
    }

    #[test]
    fn offset_sync_ignores_edits_after_a_block() {
        let mut r = PasteRegistry::new();
        let p = r.register_text(0, "body".into(), 2);
        let after = p.len() + 1;
        r.shift_for_edit(after, 5);
        let b = &r.blocks()[0];
        assert_eq!((b.start, b.end), (0, p.len()));
    }

    #[test]
    fn whole_block_delete_drops_record_and_shifts_trailing() {
        let mut r = PasteRegistry::new();
        let p1 = r.register_text(0, "one".into(), 2);
        let p2len = {
            let p2 = r.register_text(p1.len(), "two".into(), 3);
            p2.len()
        };
        // Remove the first block's range.
        r.remove_range(0, p1.len());
        assert_eq!(r.blocks().len(), 1);
        let b = &r.blocks()[0];
        // Second block shifted left to the front.
        assert_eq!((b.start, b.end), (0, p2len));
    }

    #[test]
    fn vim_delete_crossing_a_block_returns_full_span() {
        let mut r = PasteRegistry::new();
        let p = r.register_text(4, "body".into(), 2); // "word[...]"
        let end = 4 + p.len();
        // A `dw`-style motion from cursor 0 that lands at mid-block.
        let mid = 4 + 2;
        let span = r.block_crossed_by(0, mid);
        assert_eq!(span, Some((4, end)));
        // A motion entirely before the block crosses nothing.
        assert_eq!(r.block_crossed_by(0, 3), None);
    }

    #[test]
    fn re_paste_to_expand_matches_only_at_right_edge_and_identical() {
        let mut r = PasteRegistry::new();
        let full = "the original pasted body";
        let p = r.register_text(0, full.into(), 4);
        let end = p.len();
        // At right edge + identical → expandable.
        assert_eq!(
            r.expandable_text_at(end, full),
            Some((0, end, full.to_string()))
        );
        // Different content → not expandable.
        assert_eq!(r.expandable_text_at(end, "something else"), None);
        // Right content but cursor not at the right edge → not expandable.
        assert_eq!(r.expandable_text_at(end - 1, full), None);
    }

    #[test]
    fn build_wire_text_block_wraps_full_text_with_nonce_tags() {
        let mut r = PasteRegistry::new();
        let buffer = String::from("see ");
        let full = "VERY LONG TEXT".to_string();
        let p = r.register_text(buffer.len(), full.clone(), 4);
        let nonce = match &r.blocks()[0].kind {
            PasteKind::Text { nonce, .. } => nonce.clone(),
            _ => panic!("expected text block"),
        };
        let buffer = format!("{buffer}{p}");
        let (wire, images) = r.build_wire(&buffer, true);
        assert_eq!(
            wire,
            format!("see <user_paste id=\"{nonce}\">VERY LONG TEXT</user_paste id=\"{nonce}\">")
        );
        assert!(!wire.contains(DISPLAY_PASTE_RULE));
        assert!(images.is_empty());
    }

    #[test]
    fn text_blocks_get_distinct_stable_nonces() {
        let mut r = PasteRegistry::new();
        let first = r.register_text(0, "first".into(), 1);
        r.register_text(first.len(), "second".into(), 2);

        let nonces = r
            .blocks()
            .iter()
            .map(|b| match &b.kind {
                PasteKind::Text { nonce, .. } => nonce.as_str(),
                _ => panic!("expected text block"),
            })
            .collect::<Vec<_>>();
        assert_eq!(nonces.len(), 2);
        assert_ne!(nonces[0], nonces[1]);
    }

    #[test]
    fn expand_display_inlines_text_without_wire_markers_and_keeps_image_placeholder() {
        let mut r = PasteRegistry::new();
        let mut buffer = String::from("see ");
        let text = r.register_text(buffer.len(), "VERY LONG TEXT".into(), 4);
        buffer.push_str(&text);
        buffer.push(' ');
        let image = r.register_image(buffer.len(), vec![1, 2, 3]);
        buffer.push_str(&image);

        let display = r.expand_display(&buffer);

        assert_eq!(
            display,
            "see --- paste #1 start ---
VERY LONG TEXT
--- paste #1 end --- [Pasted image #1]"
        );
        assert!(!display.contains("<user_paste"));
        assert!(!display.contains("[Pasted text #"));
    }

    #[test]
    fn build_wire_vision_attaches_image_and_dedups_reference() {
        let mut r = PasteRegistry::new();
        let png = vec![1u8, 2, 3];
        let mut buffer = String::new();
        let p1 = r.register_image(0, png.clone());
        buffer.push_str(&p1);
        buffer.push(' ');
        let p2 = r.register_image(buffer.len(), png.clone()); // duplicate
        buffer.push_str(&p2);
        let (wire, images) = r.build_wire(&buffer, true);
        // First image → one real part (sentinel); duplicate → text ref.
        assert_eq!(images.len(), 1);
        assert_eq!(images[0], png);
        assert!(wire.contains(IMAGE_PART_SENTINEL));
        assert!(wire.contains("[reference image #1]"));
    }

    #[test]
    fn build_wire_non_vision_converts_images_to_text_note() {
        let mut r = PasteRegistry::new();
        let png = vec![1u8, 2, 3];
        let p = r.register_image(0, png);
        let (wire, images) = r.build_wire(&p, false);
        assert!(images.is_empty());
        assert_eq!(
            wire,
            "[Pasted image #1: not sent — current model has no image support]"
        );
    }

    // ---- Integration: registry + real Composer buffer ----------------
    //
    // These prove the byte-range sync holds against actual buffer
    // mutations (the App wrappers are thin glue over exactly these two
    // structs), without a live terminal.

    use crate::tui::composer::Composer;

    /// Mirror the app's condensed-text insertion: snap to a boundary,
    /// register, drop the placeholder into the buffer.
    fn insert_text_block(c: &mut Composer, r: &mut PasteRegistry, full: &str, tokens: usize) {
        let at = r.resolve_insertion(c.cursor());
        c.set_cursor(at);
        let placeholder = r.register_text(at, full.to_string(), tokens);
        c.insert_str(&placeholder);
        for b in r.blocks_mut() {
            if b.start > at {
                b.start += placeholder.len();
                b.end += placeholder.len();
            }
        }
    }

    /// Mirror a raw insertion through the app's registry shift path.
    fn insert_raw(c: &mut Composer, r: &mut PasteRegistry, text: &str) {
        let at = r.resolve_insertion(c.cursor());
        c.set_cursor(at);
        c.insert_str(text);
        r.shift_for_edit(at, text.len() as isize);
    }

    /// Mirror the app's image insertion: register, insert placeholder, shift
    /// later blocks while preserving the newly inserted range.
    fn insert_image_block(c: &mut Composer, r: &mut PasteRegistry, png: Vec<u8>) -> String {
        let at = r.resolve_insertion(c.cursor());
        c.set_cursor(at);
        let placeholder = r.register_image(at, png);
        c.insert_str(&placeholder);
        for b in r.blocks_mut() {
            if b.start > at {
                b.start += placeholder.len();
                b.end += placeholder.len();
            }
        }
        placeholder
    }

    #[test]
    fn editor_round_trip_expands_text_tags_and_keeps_images() {
        let mut c = Composer::new(false);
        let mut r = PasteRegistry::new();
        let full = "alpha
beta
gamma";
        let png = vec![9u8, 8, 7];

        insert_raw(&mut c, &mut r, "before ");
        insert_text_block(&mut c, &mut r, full, 3);
        let nonce = match &r.blocks()[0].kind {
            PasteKind::Text { nonce, .. } => nonce.clone(),
            _ => panic!("expected text block"),
        };
        insert_raw(&mut c, &mut r, " after ");
        insert_image_block(&mut c, &mut r, png.clone());
        insert_raw(&mut c, &mut r, " done");

        let editor = r.expand_editor(c.text());
        assert_eq!(
            editor,
            format!(
                "before <user_paste id=\"{nonce}\">{full}</user_paste id=\"{nonce}\"> after [Pasted image #1] done"
            )
        );
        assert!(!editor.contains("[Pasted text #"));

        let retained = r.image_payloads_by_number();
        let rebuilt = PasteRegistry::rebuild_from_editor(&editor, &retained, |_| 11);

        assert_eq!(
            rebuilt.buffer,
            format!(
                "before {} after {} done",
                PasteRegistry::text_placeholder(1, 11),
                PasteRegistry::image_placeholder(1)
            )
        );
        assert_eq!(rebuilt.registry.blocks().len(), 2);
        match &rebuilt.registry.blocks()[0].kind {
            PasteKind::Text {
                full: stored,
                nonce: rebuilt_nonce,
                ..
            } => {
                assert_eq!(stored, full);
                assert_eq!(rebuilt_nonce, &nonce);
            }
            _ => panic!("expected rebuilt text block"),
        }
        let (wire, images) = rebuilt.registry.build_wire(&rebuilt.buffer, true);
        assert_eq!(images, vec![png]);
        assert!(wire.contains(&format!(
            "<user_paste id=\"{nonce}\">{full}</user_paste id=\"{nonce}\">"
        )));
    }

    #[test]
    fn editor_round_trip_uses_edited_user_paste_body() {
        let mut c = Composer::new(false);
        let mut r = PasteRegistry::new();
        insert_text_block(
            &mut c,
            &mut r,
            "original
body
text",
            3,
        );
        let nonce = match &r.blocks()[0].kind {
            PasteKind::Text { nonce, .. } => nonce.clone(),
            _ => panic!("expected text block"),
        };
        let edited = r.expand_editor(c.text()).replace(
            "original
body
text",
            "edited
body
text",
        );

        let rebuilt =
            PasteRegistry::rebuild_from_editor(&edited, &r.image_payloads_by_number(), |_| 7);

        assert_eq!(rebuilt.buffer, PasteRegistry::text_placeholder(1, 7));
        match &rebuilt.registry.blocks()[0].kind {
            PasteKind::Text {
                full,
                nonce: rebuilt_nonce,
                ..
            } => {
                assert_eq!(
                    full,
                    "edited
body
text"
                );
                assert_eq!(rebuilt_nonce, &nonce);
            }
            _ => panic!("expected rebuilt text block"),
        }
    }

    #[test]
    fn editor_round_trip_malformed_user_paste_stays_raw() {
        let mut c = Composer::new(false);
        let mut r = PasteRegistry::new();
        insert_text_block(
            &mut c,
            &mut r,
            "alpha
beta
gamma",
            3,
        );
        let nonce = match &r.blocks()[0].kind {
            PasteKind::Text { nonce, .. } => nonce.clone(),
            _ => panic!("expected text block"),
        };
        let malformed = r
            .expand_editor(c.text())
            .replace(&format!("</user_paste id=\"{nonce}\">"), "");

        let rebuilt =
            PasteRegistry::rebuild_from_editor(&malformed, &r.image_payloads_by_number(), |_| 1);

        assert_eq!(rebuilt.buffer, malformed);
        assert!(rebuilt.registry.is_empty());
    }

    #[test]
    fn editor_round_trip_deleted_image_placeholder_drops_image() {
        let mut c = Composer::new(false);
        let mut r = PasteRegistry::new();
        let first = vec![1u8, 1, 1];
        let second = vec![2u8, 2, 2];
        insert_image_block(&mut c, &mut r, first);
        insert_raw(&mut c, &mut r, " ");
        insert_image_block(&mut c, &mut r, second.clone());
        let retained = r.image_payloads_by_number();

        let rebuilt =
            PasteRegistry::rebuild_from_editor("keep [Pasted image #2]", &retained, |_| 1);

        assert_eq!(rebuilt.buffer, "keep [Pasted image #1]");
        let (wire, images) = rebuilt.registry.build_wire(&rebuilt.buffer, true);
        assert_eq!(images, vec![second]);
        assert!(wire.contains(IMAGE_PART_SENTINEL));
    }

    #[test]
    fn typing_before_a_block_keeps_buffer_and_registry_in_sync() {
        let mut c = Composer::new(false);
        let mut r = PasteRegistry::new();
        // Seed "hi " then a condensed block.
        c.insert_str("hi ");
        insert_text_block(&mut c, &mut r, "L".repeat(400).as_str(), 100);
        let block_start = r.blocks()[0].start;
        assert_eq!(block_start, 3);

        // Type a char at buffer start (before the block).
        c.set_cursor(0);
        c.insert_char('X');
        r.shift_for_edit(0, 1);
        // Block shifted right by one; its range still indexes the
        // placeholder text in the buffer.
        let b = &r.blocks()[0];
        assert_eq!(b.start, 4);
        assert_eq!(&c.text()[b.start..b.end], "[Pasted text #1, 100 tokens]");
    }

    #[test]
    fn backspace_right_of_block_removes_whole_placeholder_from_buffer() {
        let mut c = Composer::new(false);
        let mut r = PasteRegistry::new();
        insert_text_block(&mut c, &mut r, "a\nb\nc\nd", 7);
        // Cursor is just past `]`.
        let cursor = c.cursor();
        let (s, e) = {
            let b = r.block_ending_at(cursor).expect("block ends at cursor");
            (b.start, b.end)
        };
        c.delete_range(s, e);
        r.remove_range(s, e);
        assert_eq!(c.text(), "");
        assert!(r.is_empty());
    }

    /// One block-aware `dw`: delete the motion range, widened to a full
    /// block boundary if it crosses a block. Mirrors `App::block_aware_delete`.
    fn block_dw(c: &mut Composer, r: &mut PasteRegistry) {
        let from = c.cursor();
        let to = c.probe_motion(|c| c.move_word_forward(false));
        if from == to {
            return;
        }
        let (mut lo, mut hi) = if from <= to { (from, to) } else { (to, from) };
        if let Some((bs, be)) = r.block_crossed_by(lo, hi) {
            lo = lo.min(bs);
            hi = hi.max(be);
        }
        c.delete_range(lo, hi);
        r.shift_for_edit(lo, -((hi - lo) as isize));
    }

    #[test]
    fn vim_dw_across_a_block_removes_it_whole() {
        let mut c = Composer::new(true);
        let mut r = PasteRegistry::new();
        c.insert_str("word ");
        insert_text_block(&mut c, &mut r, "x".repeat(400).as_str(), 90);
        c.set_cursor(0);
        // First `dw` removes the word "word " up to the block's left edge
        // (vim word boundary) — the block stays.
        block_dw(&mut c, &mut r);
        assert!(c.text().starts_with("[Pasted text #1"));
        assert_eq!(r.blocks().len(), 1);
        // Cursor now sits at the block's left edge; a second `dw` crosses
        // the block and removes it whole.
        block_dw(&mut c, &mut r);
        assert!(!c.text().contains("[Pasted text"));
        assert!(r.is_empty());
    }

    #[test]
    fn re_paste_to_expand_replaces_placeholder_with_full_text_in_buffer() {
        let mut c = Composer::new(false);
        let mut r = PasteRegistry::new();
        let full = "alpha\nbeta\ngamma\ndelta";
        insert_text_block(&mut c, &mut r, full, 8);
        let cursor = c.cursor();
        let (s, e, stored) = r
            .expandable_text_at(cursor, full)
            .expect("cursor at right edge + identical content");
        c.delete_range(s, e);
        r.remove_range(s, e);
        c.set_cursor(s);
        c.insert_str(&stored);
        r.shift_for_edit(s, stored.len() as isize);
        assert_eq!(c.text(), full);
        assert!(r.is_empty());
    }

    #[test]
    fn model_switch_round_trip_same_blocks_send_differently() {
        // Same registry + buffer, two send-time evaluations: vision vs
        // not. No re-paste required — the bytes are retained either way.
        let mut r = PasteRegistry::new();
        let png = vec![7u8, 7, 7];
        let p = r.register_image(0, png.clone());
        let buffer = p;
        let (non_vision, no_imgs) = r.build_wire(&buffer, false);
        assert!(no_imgs.is_empty());
        assert!(non_vision.contains("not sent"));
        let (vision, imgs) = r.build_wire(&buffer, true);
        assert_eq!(imgs, vec![png]);
        assert!(vision.contains(IMAGE_PART_SENTINEL));
    }
}
