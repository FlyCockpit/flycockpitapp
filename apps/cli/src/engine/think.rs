//! Single source of truth for `<think>…</think>` tag parsing
//! (implementation note).
//!
//! Some openai-compatible models (MiniMax-M2, DeepSeek-R1, Qwen) emit
//! their reasoning as literal `<think>…</think>` tags inside the regular
//! `content` stream instead of the `reasoning_content` channel. Both the
//! live TUI streaming split and the engine's finalization split route
//! that inline reasoning onto a separate channel — they MUST agree
//! byte-for-byte on what is body and what is reasoning, or the displayed
//! body, the stored text, and the rebuilt model history diverge.
//!
//! This module is that one parser. The streaming path
//! ([`ThinkSplitter::feed`]) and the one-shot finalization path
//! ([`split_think`]) drive the **same** state machine — the one-shot form
//! is "feed the whole string, then finish," so there is exactly one set of
//! tag semantics (`route_text_delta` and the old `strip_think_blocks` are
//! both collapsed onto this).
//!
//! Semantics — `<think>` is recognized **only at the start of a message**
//! (implementation note):
//! - A `<think>…</think>` block is reasoning only while no real
//!   (non-whitespace) body text has yet been emitted **and** it has a
//!   matching closing `</think>`. Leading whitespace before the opening
//!   `<think>` is allowed and is not "real body text".
//! - The first time non-whitespace body text is emitted the parser enters
//!   a **permanent literal mode** for the rest of the message: every later
//!   `<think>` / `</think>` is plain body text, never a tag. This protects
//!   messages that legitimately contain `<think>` as content (code, docs).
//! - Consecutive leading blocks separated only by whitespace are all
//!   recognized; the first non-whitespace body text after a close locks out
//!   further tag recognition.
//! - A single `\n` immediately after an opening `<think>` or a closing
//!   `</think>` is dropped so neither the reasoning nor the resumed body
//!   starts with a stray blank line.
//! - Partial tags at a chunk boundary are buffered and resolved on the
//!   next chunk; at end-of-stream a still-buffered partial is flushed to
//!   whichever side we're currently on.
//! - An **unterminated** leading `<think>` (open block, no close) is NOT
//!   reasoning: the entire content — including the literal `<think>` tag —
//!   stays as body text, unstripped. A `<think>` is only split off when its
//!   matching `</think>` is actually seen, so a model that omits the close
//!   tag can never have its real answer or action-driving text swallowed
//!   into the reasoning channel (priority #1 — defend against weak models).
//!   To keep this streaming-safe, content after an opening `<think>` is
//!   *buffered* (in `tag_partial`, verbatim, including the open tag) until
//!   the close arrives; on close it is committed to reasoning with the tags
//!   removed, and at end-of-stream an unclosed buffer is flushed verbatim to
//!   the body.
//!
//! The literal-mode decision depends only on `(inside_think, body_started,
//! buffered partial)`, so the streaming ([`ThinkSplitter::feed`]) and
//! one-shot ([`split_think`]) paths still agree byte-for-byte.

const OPEN: &str = "<think>";
const CLOSE: &str = "</think>";

/// Streaming `<think>`-tag router state. Outside think tags content goes
/// to the body sink; inside, to the reasoning sink. Partial tags at a
/// chunk boundary are buffered in `tag_partial` and resolved on the next
/// [`feed`](Self::feed); [`finish`](Self::finish) flushes any leftover.
#[derive(Debug, Default, Clone)]
pub struct ThinkSplitter {
    /// True while inside a `<think>…</think>` block straddling chunks. While
    /// set, the block's content (and the literal open tag) is held verbatim
    /// in `tag_partial` rather than emitted to reasoning — the commit to
    /// reasoning happens only when the closing `</think>` arrives, so an
    /// unterminated block can be flushed back to the body intact.
    inside_think: bool,
    /// True once real (non-whitespace) body text has been emitted. Latches
    /// permanently: thereafter every `<think>` / `</think>` is literal body
    /// text — tag recognition is only active at the start of the message.
    body_started: bool,
    /// Buffered text held until it can be classified. Two roles, disjoint by
    /// `inside_think`: when outside a block it is the latest chunk's tail
    /// that *might* be the start of a `<think>` / `</think>` tag; when inside
    /// a block (`inside_think`) it is the whole pending block — the literal
    /// `<think>` open tag plus accumulated content — withheld from reasoning
    /// until the close is seen so an unterminated block flushes to the body.
    tag_partial: String,
}

impl ThinkSplitter {
    /// Reconstruct a splitter from its persisted fields. The TUI's
    /// `PendingMsg` stores these separately (they predate this type); this
    /// lets `route_text_delta` adapt them to the shared state machine
    /// without changing that struct.
    pub fn from_parts(inside_think: bool, body_started: bool, tag_partial: String) -> Self {
        Self {
            inside_think,
            body_started,
            tag_partial,
        }
    }

    /// Decompose into the persisted fields, written back onto `PendingMsg`.
    pub fn into_parts(self) -> (bool, bool, String) {
        (self.inside_think, self.body_started, self.tag_partial)
    }

    /// Route one chunk into `text` (outside tags) and `reasoning` (inside
    /// tags). Returns `true` if any non-think body text was appended —
    /// callers use this as the "real answer text has started" signal.
    pub fn feed(&mut self, chunk: &str, text: &mut String, reasoning: &mut String) -> bool {
        let mut buf = std::mem::take(&mut self.tag_partial);
        buf.push_str(chunk);
        let mut wrote_text = false;
        let mut remaining = buf.as_str();
        while !remaining.is_empty() {
            // Literal mode: real body text has started, so tag recognition
            // is permanently off — everything left is plain body text.
            if self.body_started {
                text.push_str(remaining);
                return true;
            }
            if self.inside_think {
                // `remaining` is the whole pending block: the literal `<think>`
                // open tag plus everything seen since. We commit to reasoning
                // ONLY when the matching close is found — otherwise we keep
                // buffering so an unterminated block can flush verbatim to the
                // body at `finish` (a missing close never swallows body text).
                if let Some(idx) = remaining.find(CLOSE) {
                    // Confirmed block: strip the leading `<think>` open tag and
                    // a single `\n` after it, then commit the content as
                    // reasoning. `remaining` always starts with `<think>` here
                    // (we buffered it on open), so the strip is exact.
                    let inner = remaining[..idx]
                        .strip_prefix(OPEN)
                        .unwrap_or(&remaining[..idx]);
                    let inner = inner.strip_prefix('\n').unwrap_or(inner);
                    reasoning.push_str(inner);
                    remaining = &remaining[idx + CLOSE.len()..];
                    self.inside_think = false;
                    // Drop a single `\n` directly after `</think>` so the
                    // answer doesn't render with a leading blank line.
                    if let Some(rest) = remaining.strip_prefix('\n') {
                        remaining = rest;
                    }
                } else {
                    // No close yet: hold the entire pending block (open tag +
                    // content) verbatim. If the stream ends here, `finish`
                    // flushes it to the body unchanged; if a close arrives in a
                    // later chunk, the branch above commits it to reasoning.
                    self.tag_partial = remaining.to_string();
                    return wrote_text;
                }
            } else if let Some(idx) = remaining.find(OPEN) {
                // Text before a leading `<think>` is only allowed if it is
                // pure whitespace; any non-whitespace is real body text and
                // latches literal mode (the `<think>` is then content).
                if idx > 0 {
                    let pre = &remaining[..idx];
                    if pre.trim().is_empty() {
                        // Pure leading whitespace before the block — drop it
                        // so the answer has no leading blank.
                    } else {
                        text.push_str(pre);
                        self.body_started = true;
                        wrote_text = true;
                        // Re-enter the loop in literal mode; the `<think>`
                        // at `remaining[idx..]` stays as body content.
                        remaining = &remaining[idx..];
                        continue;
                    }
                }
                // Enter the block but KEEP the literal `<think>` open tag in
                // the buffer (don't advance past it). It is committed-and-
                // stripped only once the close is seen; until then it must be
                // recoverable as body text. Re-enter the loop in `inside_think`.
                self.inside_think = true;
                remaining = &remaining[idx..];
                continue;
            } else if let Some(idx) = trailing_partial_match(remaining, OPEN) {
                // Text before a partial `<think...` boundary: same rule —
                // non-whitespace latches literal mode and the partial then
                // becomes literal body content rather than a buffered tag.
                if idx > 0 {
                    let pre = &remaining[..idx];
                    if !pre.trim().is_empty() {
                        text.push_str(pre);
                        self.body_started = true;
                        wrote_text = true;
                        remaining = &remaining[idx..];
                        continue;
                    }
                    // Pure leading whitespace before a partial tag: buffer it
                    // together with the partial so the next chunk decides. If
                    // the tag resolves we drop the whitespace (leading-blank
                    // trim); if it doesn't, the whitespace reappears as body —
                    // either way streamed == one-shot.
                    self.tag_partial = remaining.to_string();
                    return wrote_text;
                }
                self.tag_partial = remaining[idx..].to_string();
                return wrote_text;
            } else if remaining.trim().is_empty() {
                // Pure leading whitespace with no tag in sight: buffer it
                // rather than emit it, so a following leading `<think>` can
                // still be recognized (and its leading whitespace dropped)
                // and so streamed == one-shot regardless of chunk boundary.
                // `finish` flushes it to the body if the stream ends here.
                self.tag_partial = remaining.to_string();
                return wrote_text;
            } else {
                // Real (non-whitespace) body text with no leading tag: this
                // latches literal mode for the rest of the message.
                text.push_str(remaining);
                self.body_started = true;
                wrote_text = true;
                return wrote_text;
            }
        }
        wrote_text
    }

    /// Flush any buffered text at end of stream. An unterminated block
    /// (`inside_think`) never found its `</think>`, so it is NOT reasoning:
    /// the whole buffer — the literal `<think>` open tag plus its content —
    /// flushes verbatim to the **body**, so a missing close tag can never
    /// swallow the model's answer or action-driving text. Outside a block the
    /// buffer is a leftover partial tag that likewise lands in the body.
    /// `reasoning` is left untouched (the `_reasoning` arg is kept for the
    /// symmetric `(text, reasoning)` call shape the TUI/`split_think` use).
    pub fn finish(&mut self, text: &mut String, _reasoning: &mut String) {
        if self.tag_partial.is_empty() {
            return;
        }
        let buf = std::mem::take(&mut self.tag_partial);
        text.push_str(&buf);
        if self.inside_think {
            // Unterminated block resolved as body: clear the flag so a reused
            // splitter doesn't think it's still mid-block.
            self.inside_think = false;
            self.body_started = true;
        }
    }
}

/// One-shot split of a complete assistant message into `(body, reasoning)`
/// using the same state machine as the streaming router. A leading
/// `<think>…</think>` block is removed from `body` and its content placed in
/// `reasoning` — but ONLY when its closing `</think>` is present. An
/// unterminated `<think>` (open tag, no close) is left entirely in `body`,
/// open tag and all, so a missing close never swallows the answer. Leading
/// blank lines left in the body by a stripped opening block are trimmed.
///
/// This is the finalization path's parser; it is intentionally identical
/// in semantics to [`ThinkSplitter::feed`] driven over the whole string,
/// so the stored/body text equals the streamed body byte-for-byte.
pub fn split_think(text: &str) -> (String, String) {
    let mut splitter = ThinkSplitter::default();
    let mut body = String::with_capacity(text.len());
    let mut reasoning = String::new();
    splitter.feed(text, &mut body, &mut reasoning);
    splitter.finish(&mut body, &mut reasoning);
    // Trim leading blank lines left when the message opened with a think
    // block (the body then begins after the close, possibly past the one
    // `\n` we already dropped — handle multiple).
    let trimmed = body.trim_start_matches(['\n', '\r']);
    if trimmed.len() != body.len() {
        body = trimmed.to_string();
    }
    (body, reasoning)
}

/// Return `Some(idx)` if the *tail* of `s` is a strict prefix of `tag` —
/// meaning we should buffer everything from `idx` onward because it might
/// be the start of `tag`. Length-1 matches (a trailing `<`) count: we
/// buffer them so the next chunk can finish the tag.
fn trailing_partial_match(s: &str, tag: &str) -> Option<usize> {
    // n is the partial-tag length: 1..=min(s.len(), tag.len()-1). It must
    // be a strict prefix (n < tag.len()) — a full match is handled by the
    // caller's `find`. The upper bound is INCLUSIVE so a lone trailing `<`
    // (s == "<", n == 1) is buffered, not emitted as literal text.
    let max = s.len().min(tag.len() - 1);
    for n in (1..=max).rev() {
        let suffix_start = s.len() - n;
        if s.is_char_boundary(suffix_start) && tag.is_char_boundary(n) && s.ends_with(&tag[..n]) {
            return Some(suffix_start);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the splitter over a slice of chunks (simulating streaming)
    /// and return the accumulated `(body, reasoning)` after `finish`.
    fn stream(chunks: &[&str]) -> (String, String) {
        let mut s = ThinkSplitter::default();
        let mut text = String::new();
        let mut reasoning = String::new();
        for c in chunks {
            s.feed(c, &mut text, &mut reasoning);
        }
        s.finish(&mut text, &mut reasoning);
        (text, reasoning)
    }

    /// The core invariant: streaming the input one delta at a time yields
    /// the *same* `(body, reasoning)` as the one-shot `split_think`, for
    /// every chunk boundary. This is what guarantees displayed body ==
    /// stored body == model history.
    fn assert_stream_matches_oneshot(full: &str) {
        let one = split_think(full);
        // Whole string as a single delta.
        assert_eq!(stream(&[full]), one, "single-delta stream != one-shot");
        // Split at every byte boundary that is a char boundary.
        for i in 1..full.len() {
            if !full.is_char_boundary(i) {
                continue;
            }
            let (a, b) = full.split_at(i);
            let streamed = stream(&[a, b]);
            // The one-shot trims leading blank lines; the streamed body
            // does not, so compare after the same trim for parity.
            let streamed_trimmed = (
                streamed.0.trim_start_matches(['\n', '\r']).to_string(),
                streamed.1.clone(),
            );
            assert_eq!(
                streamed_trimmed, one,
                "stream split at {i} ({a:?}|{b:?}) != one-shot"
            );
        }
    }

    #[test]
    fn partial_think_tag_after_multibyte_char_stays_buffered() {
        assert_stream_matches_oneshot("日<think>reason</think>answer");
        assert_eq!(trailing_partial_match("日<", OPEN), Some("日".len()));
    }

    #[test]
    fn text_only_no_tags() {
        let (t, r) = split_think("just an answer");
        assert_eq!(t, "just an answer");
        assert_eq!(r, "");
        assert_stream_matches_oneshot("just an answer");
    }

    #[test]
    fn single_block_extracted() {
        let (t, r) = split_think("<think>reasoning here</think>\nthe answer");
        assert_eq!(t, "the answer");
        assert_eq!(r, "reasoning here");
        assert_stream_matches_oneshot("<think>reasoning here</think>\nthe answer");
    }

    #[test]
    fn text_before_block_keeps_it_literal() {
        // Real body text precedes the `<think>`, so the block is content and
        // the whole string is body, reasoning empty (leading-only rule).
        let (t, r) = split_think("before <think>mid</think> after");
        assert_eq!(t, "before <think>mid</think> after");
        assert_eq!(r, "");
        assert_stream_matches_oneshot("before <think>mid</think> after");
    }

    #[test]
    fn mid_message_block_after_body_stays_literal() {
        // The leading block is stripped; once `x` (real body) is emitted,
        // the second `<think>` is literal content, not reasoning.
        let (t, r) = split_think("<think>a</think>x<think>b</think>y");
        assert_eq!(t, "x<think>b</think>y");
        assert_eq!(r, "a");
        assert_stream_matches_oneshot("<think>a</think>x<think>b</think>y");
    }

    #[test]
    fn unterminated_block_after_body_is_literal() {
        // Real body text precedes the tag, so an unterminated `<think>` is
        // literal: the whole string is body, reasoning empty.
        let (t, r) = split_think("answer <think>still thinking no close");
        assert_eq!(t, "answer <think>still thinking no close");
        assert_eq!(r, "");
        assert_stream_matches_oneshot("answer <think>still thinking no close");
    }

    #[test]
    fn leading_unterminated_block_stays_body() {
        // A leading `<think>` with NO matching `</think>` is NOT reasoning:
        // the entire content, open tag included, stays as body — a missing
        // close tag can never swallow the model's answer (priority #1).
        let (t, r) = split_think("<think>still thinking no close");
        assert_eq!(t, "<think>still thinking no close");
        assert_eq!(r, "");
        assert_stream_matches_oneshot("<think>still thinking no close");
    }

    #[test]
    fn leading_unterminated_block_preserves_trailing_answer() {
        // Action-driving / answer text after an unterminated open tag must
        // survive verbatim (it would have been lost under the old rule).
        let input = "<think>let me see\nI will now answer: ship it";
        let (t, r) = split_think(input);
        assert_eq!(t, input);
        assert_eq!(r, "");
        assert_stream_matches_oneshot(input);
    }

    #[test]
    fn multiple_leading_blocks_all_stripped() {
        // Consecutive leading blocks separated only by whitespace are all
        // recognized; their reasoning concatenates, the answer is clean.
        let (t, r) = split_think("<think>a</think>\n<think>b</think>\nanswer");
        assert_eq!(t, "answer");
        assert_eq!(r, "ab");
        assert_stream_matches_oneshot("<think>a</think>\n<think>b</think>\nanswer");
    }

    #[test]
    fn leading_whitespace_before_block_dropped() {
        // Leading whitespace before the opening `<think>` is allowed and
        // dropped; the block is recognized and the answer has no leading gap.
        let (t, r) = split_think("  \n<think>r</think>ans");
        assert_eq!(t, "ans");
        assert_eq!(r, "r");
        assert_stream_matches_oneshot("  \n<think>r</think>ans");
    }

    #[test]
    fn nested_tags_first_open_to_first_close() {
        // Malformed/nested: first-open to first-close. The inner `<think>`
        // is reasoning content; the text after the first `</think>` is body
        // and the trailing `</think>` stays as literal body text (matching
        // the streaming state machine — no separate finalization handling).
        let (t, r) = split_think("<think>outer <think>inner</think>tail</think>");
        assert_eq!(r, "outer <think>inner");
        assert_eq!(t, "tail</think>");
        assert_stream_matches_oneshot("<think>outer <think>inner</think>tail</think>");
    }

    #[test]
    fn think_only_message_yields_empty_body() {
        let (t, r) = split_think("<think>only reasoning, no answer</think>");
        assert_eq!(t, "");
        assert_eq!(r, "only reasoning, no answer");
        assert_stream_matches_oneshot("<think>only reasoning, no answer</think>");
    }

    #[test]
    fn leading_blank_after_block_trimmed() {
        // Two newlines after the close: the router drops one, the one-shot
        // trims the rest so the body has no leading blank line.
        let (t, _) = split_think("<think>r</think>\n\nanswer");
        assert_eq!(t, "answer");
    }

    #[test]
    fn partial_tag_across_boundary_is_buffered() {
        // `<th` at the end of one chunk, `ink>` at the start of the next —
        // a leading block split across the boundary is still recognized.
        let (t, r) = stream(&["<th", "ink>reasoning</think>answer"]);
        assert_eq!(t, "answer");
        assert_eq!(r, "reasoning");
        assert_stream_matches_oneshot("<think>reasoning</think>answer");
    }

    #[test]
    fn partial_tag_after_body_is_literal() {
        // Once real body text has been emitted, a `<think>` split across a
        // chunk boundary is literal content, not a tag.
        let (t, r) = stream(&["before <th", "ink>reasoning</think>after"]);
        assert_eq!(t, "before <think>reasoning</think>after");
        assert_eq!(r, "");
    }
}
