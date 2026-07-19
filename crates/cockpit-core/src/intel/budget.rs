//! Token-budgeted output writer for the codebase-intelligence tools.
//!
//! Every intel tool's output crosses to the model, so it must respect
//! the §10 token economy. [`BudgetedWriter`] accumulates whole records
//! (lines, entries, JSON blobs) and stops the moment the next record
//! would push the running cl100k_base count past the cap. Writes are
//! **atomic**: a record that wouldn't fit is dropped entirely rather
//! than split mid-way, so the accumulated buffer is always a valid
//! UTF-8 prefix and never a half-written record. This mirrors the
//! proven kcl behaviour (the deleted-file/truncation regression set).

use crate::tokens;

/// Maximum retained pre-truncation body stored for later retrieval.
///
/// This is intentionally much larger than the intel tools' 3k/4k token
/// model-facing caps, so ordinary over-cap structural/search results are
/// recoverable, but still bounded so a pathological repository cannot balloon
/// the session database with unbounded tool output.
pub const RETAINED_TRUNCATED_OUTPUT_BYTE_CAP: usize = 256 * 1024;

pub fn retained_truncated_body(body: &str) -> crate::engine::tool::RetainedTruncatedOutput {
    let split = capped_prefix_len(body, RETAINED_TRUNCATED_OUTPUT_BYTE_CAP);
    crate::engine::tool::RetainedTruncatedOutput {
        content: body[..split].to_string(),
        original_byte_len: body.len(),
        partial: split < body.len(),
    }
}

/// Accumulates output records under a cl100k token cap, dropping whole
/// records once the cap is reached.
pub struct BudgetedWriter {
    buf: String,
    retained: String,
    retained_original_byte_len: usize,
    retained_partial: bool,
    /// Token cap; `None` means unbounded (only used in tests).
    cap: usize,
    /// Running cl100k count of `buf`. Recomputed incrementally: the cost
    /// of a candidate record is counted in isolation and added. This is
    /// an estimate (token boundaries can shift across a join) but it is
    /// a conservative-enough budget enforcer per the "≈" contract in
    /// `tokens.rs`.
    tokens: usize,
    /// Set once a write was refused. Sticky: no later write succeeds, so
    /// the buffer keeps a clean prefix.
    truncated: bool,
}

impl BudgetedWriter {
    /// New writer capped at `cap` cl100k tokens.
    pub fn new(cap: usize) -> Self {
        Self {
            buf: String::new(),
            retained: String::new(),
            retained_original_byte_len: 0,
            retained_partial: false,
            cap,
            tokens: 0,
            truncated: false,
        }
    }

    /// Attempt to append `record`. Returns `true` if it was written,
    /// `false` if it was dropped (cap reached). Once any write is
    /// dropped, every subsequent write is dropped too.
    pub fn write(&mut self, record: &str) -> bool {
        self.retain(record);
        if self.truncated {
            return false;
        }
        let cost = tokens::count(record);
        if self.tokens + cost > self.cap {
            self.truncated = true;
            return false;
        }
        self.buf.push_str(record);
        self.tokens += cost;
        true
    }

    /// Append `record` followed by a newline. See [`write`].
    pub fn writeln(&mut self, record: &str) -> bool {
        let mut owned = String::with_capacity(record.len() + 1);
        owned.push_str(record);
        owned.push('\n');
        self.write(&owned)
    }

    /// Whether any write has been dropped.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// `true` when no record has been written yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn retained_truncated_output(
        &self,
    ) -> Option<crate::engine::tool::RetainedTruncatedOutput> {
        if !self.truncated || self.retained.is_empty() {
            return None;
        }
        Some(crate::engine::tool::RetainedTruncatedOutput {
            content: self.retained.clone(),
            original_byte_len: self.retained_original_byte_len,
            partial: self.retained_partial,
        })
    }

    /// Whether retained retrieval content is already a capped prefix.
    ///
    /// Producers may keep feeding records after the model-facing token cap trips;
    /// once this turns true, no more retrievable bytes can be stored.
    pub fn retention_is_partial(&self) -> bool {
        self.retained_partial
    }

    /// Consume the writer, returning the accumulated buffer. The caller
    /// is responsible for appending any truncation note it wants — the
    /// writer never injects one so the tools can phrase their own hint.
    pub fn into_string(self) -> String {
        self.buf
    }

    fn retain(&mut self, record: &str) {
        self.retained_original_byte_len += record.len();
        let remaining = RETAINED_TRUNCATED_OUTPUT_BYTE_CAP.saturating_sub(self.retained.len());
        if remaining == 0 {
            self.retained_partial = true;
            return;
        }
        if record.len() <= remaining {
            self.retained.push_str(record);
            return;
        }

        let split = capped_prefix_len(record, remaining);
        self.retained.push_str(&record[..split]);
        self.retained_partial = true;
    }
}

fn capped_prefix_len(text: &str, byte_cap: usize) -> usize {
    if text.len() <= byte_cap {
        return text.len();
    }
    text.char_indices()
        .map(|(idx, _)| idx)
        .take_while(|idx| *idx <= byte_cap)
        .last()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_until_cap_then_drops_whole_records() {
        // Each line counts as a couple of tokens; a tiny cap forces an
        // early drop.
        let mut w = BudgetedWriter::new(5);
        assert!(w.writeln("alpha beta"));
        // Eventually a write is refused; once refused it stays refused.
        let mut refused = false;
        for _ in 0..50 {
            if !w.writeln("gamma delta epsilon zeta") {
                refused = true;
                break;
            }
        }
        assert!(refused, "expected the cap to refuse a write");
        assert!(w.is_truncated());
        // A later small write is still refused (sticky).
        assert!(!w.writeln("x"));
        assert!(!w.is_empty());
        // The buffer is a valid prefix ending on a record boundary.
        assert!(w.into_string().ends_with('\n'));
    }

    #[test]
    fn pre_truncation_body_is_captured_and_stored() {
        let mut w = BudgetedWriter::new(5);
        assert!(w.writeln("alpha beta"));
        assert!(!w.writeln("gamma delta epsilon zeta"));

        let retained = w
            .retained_truncated_output()
            .expect("retained pre-truncation body");
        assert!(retained.content.contains("alpha beta\n"));
        assert!(retained.content.contains("gamma delta epsilon zeta\n"));
        assert!(retained.original_byte_len > w.into_string().len());
        assert!(!retained.partial);
    }

    #[test]
    fn writes_after_model_cap_still_extend_retention() {
        let mut w = BudgetedWriter::new(5);
        assert!(w.writeln("alpha beta"));
        assert!(!w.writeln("gamma delta epsilon zeta"));
        assert!(!w.writeln("later hidden record"));

        let retained = w
            .retained_truncated_output()
            .expect("retained pre-truncation body");
        assert!(retained.content.contains("alpha beta\n"));
        assert!(retained.content.contains("gamma delta epsilon zeta\n"));
        assert!(retained.content.contains("later hidden record\n"));
        assert!(!retained.partial);
    }

    #[test]
    fn pre_truncation_body_over_cap_is_marked_partial() {
        let mut w = BudgetedWriter::new(1);
        assert!(!w.write(&"x".repeat(RETAINED_TRUNCATED_OUTPUT_BYTE_CAP + 10)));

        let retained = w
            .retained_truncated_output()
            .expect("retained pre-truncation body");
        assert_eq!(retained.content.len(), RETAINED_TRUNCATED_OUTPUT_BYTE_CAP);
        assert_eq!(
            retained.original_byte_len,
            RETAINED_TRUNCATED_OUTPUT_BYTE_CAP + 10
        );
        assert!(retained.partial);
    }

    #[test]
    fn original_len_keeps_counting_after_retention_cap() {
        let mut w = BudgetedWriter::new(1);
        assert!(!w.write(&"x".repeat(RETAINED_TRUNCATED_OUTPUT_BYTE_CAP + 10)));
        assert!(!w.write("tail bytes"));

        let retained = w
            .retained_truncated_output()
            .expect("retained pre-truncation body");
        assert_eq!(retained.content.len(), RETAINED_TRUNCATED_OUTPUT_BYTE_CAP);
        assert_eq!(
            retained.original_byte_len,
            RETAINED_TRUNCATED_OUTPUT_BYTE_CAP + 10 + "tail bytes".len()
        );
        assert!(retained.partial);
    }

    #[test]
    fn unbounded_enough_cap_keeps_everything() {
        let mut w = BudgetedWriter::new(100_000);
        for i in 0..100 {
            assert!(w.writeln(&format!("line {i}")));
        }
        assert!(!w.is_truncated());
        assert_eq!(w.into_string().lines().count(), 100);
    }
}
