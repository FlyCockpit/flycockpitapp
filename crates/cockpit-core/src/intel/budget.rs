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

/// Accumulates output records under a cl100k token cap, dropping whole
/// records once the cap is reached.
pub struct BudgetedWriter {
    buf: String,
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
            cap,
            tokens: 0,
            truncated: false,
        }
    }

    /// Attempt to append `record`. Returns `true` if it was written,
    /// `false` if it was dropped (cap reached). Once any write is
    /// dropped, every subsequent write is dropped too.
    pub fn write(&mut self, record: &str) -> bool {
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
        if self.truncated {
            return false;
        }
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

    /// Consume the writer, returning the accumulated buffer. The caller
    /// is responsible for appending any truncation note it wants — the
    /// writer never injects one so the tools can phrase their own hint.
    pub fn into_string(self) -> String {
        self.buf
    }
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
    fn unbounded_enough_cap_keeps_everything() {
        let mut w = BudgetedWriter::new(100_000);
        for i in 0..100 {
            assert!(w.writeln(&format!("line {i}")));
        }
        assert!(!w.is_truncated());
        assert_eq!(w.into_string().lines().count(), 100);
    }
}
