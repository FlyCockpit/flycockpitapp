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

/// Maximum source capture retained for a text artifact.  This is a host
/// resource bound, deliberately aligned with the durable artifact limit.
pub const TEXT_ARTIFACT_CAPTURE_BYTE_CAP: usize = 8 * 1024 * 1024;

pub fn capture_text_artifact_body(body: &str) -> crate::engine::tool::TextArtifactCapture {
    let split = capped_prefix_len(body, TEXT_ARTIFACT_CAPTURE_BYTE_CAP);
    crate::engine::tool::TextArtifactCapture {
        content: body[..split].to_string(),
        host_captured_bytes: split,
        host_original_bytes: body.len(),
        host_dropped_bytes: body.len().saturating_sub(split),
        stored_source_bytes: split,
    }
}

/// Accumulates output records under a cl100k token cap, dropping whole
/// records once the cap is reached.
pub struct BudgetedWriter {
    buf: String,
    captured: String,
    captured_original_byte_len: usize,
    captured_dropped: bool,
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
            captured: String::new(),
            captured_original_byte_len: 0,
            captured_dropped: false,
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

    pub fn text_artifact_capture(&self) -> Option<crate::engine::tool::TextArtifactCapture> {
        if !self.truncated || self.captured.is_empty() {
            return None;
        }
        Some(crate::engine::tool::TextArtifactCapture {
            content: self.captured.clone(),
            host_captured_bytes: self.captured.len(),
            host_original_bytes: self.captured_original_byte_len,
            host_dropped_bytes: self
                .captured_original_byte_len
                .saturating_sub(self.captured.len()),
            stored_source_bytes: self.captured.len(),
        })
    }

    /// Whether the bounded host capture dropped source bytes.
    ///
    /// Producers may keep feeding records after the model-facing token cap trips;
    /// once this turns true, no more retrievable bytes can be stored.
    pub fn capture_has_host_drops(&self) -> bool {
        self.captured_dropped
    }

    /// Consume the writer, returning the accumulated buffer. The caller
    /// is responsible for appending any truncation note it wants — the
    /// writer never injects one so the tools can phrase their own hint.
    ///
    /// Raw variant: no boundary elision. Production output paths must route
    /// through [`Self::into_string_redacted`] (issue #294).
    pub fn into_string(self) -> String {
        self.buf
    }

    /// Consume the writer with the redaction-aware boundary treatment
    /// (issue #294). When records were dropped at the cap, the retained
    /// buffer's END abuts the omitted records: a registered secret
    /// straddling that boundary — a multi-line literal spanning several
    /// trailing records included, since the buffer is the joined contiguous
    /// retained span — leaves only its PREFIX, which the downstream §7
    /// whole-value scrub cannot match. Elide the unsafe back margin under
    /// the CURRENT session table so only WHOLE secrets — which §7 scrubs
    /// normally — remain in the emitted text.
    pub fn into_string_redacted(self, redact: &crate::redact::RedactionTable) -> String {
        if !self.truncated || self.buf.is_empty() {
            return self.buf;
        }
        crate::tools::common::drop_back_margin(redact, &self.buf).to_string()
    }

    /// Redaction-aware [`Self::text_artifact_capture`]: the retained host
    /// capture is a prefix cut of the source records, and when the capture
    /// cap cut a record (`captured_dropped`) the stored content's END abuts
    /// omitted bytes — a straddling secret's PARTIAL would survive the
    /// admission/export whole-value scrubs. Elide the unsafe back margin.
    pub fn text_artifact_capture_redacted(
        &self,
        redact: &crate::redact::RedactionTable,
    ) -> Option<crate::engine::tool::TextArtifactCapture> {
        let mut capture = self.text_artifact_capture();
        if let Some(capture) = capture.as_mut()
            && self.captured_dropped
        {
            let safe = crate::tools::common::drop_back_margin(redact, &capture.content);
            capture.content = safe.to_string();
            capture.stored_source_bytes = capture.content.len();
        }
        capture
    }

    fn retain(&mut self, record: &str) {
        self.captured_original_byte_len += record.len();
        let remaining = TEXT_ARTIFACT_CAPTURE_BYTE_CAP.saturating_sub(self.captured.len());
        if remaining == 0 {
            self.captured_dropped = true;
            return;
        }
        if record.len() <= remaining {
            self.captured.push_str(record);
            return;
        }

        let split = capped_prefix_len(record, remaining);
        self.captured.push_str(&record[..split]);
        self.captured_dropped = true;
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

        let capture = w.text_artifact_capture().expect("captured source body");
        assert!(capture.content.contains("alpha beta\n"));
        assert!(capture.content.contains("gamma delta epsilon zeta\n"));
        assert!(capture.host_original_bytes > w.into_string().len());
        assert_eq!(capture.host_dropped_bytes, 0);
    }

    #[test]
    fn writes_after_model_cap_still_extend_capture() {
        let mut w = BudgetedWriter::new(5);
        assert!(w.writeln("alpha beta"));
        assert!(!w.writeln("gamma delta epsilon zeta"));
        assert!(!w.writeln("later hidden record"));

        let capture = w.text_artifact_capture().expect("captured source body");
        assert!(capture.content.contains("alpha beta\n"));
        assert!(capture.content.contains("gamma delta epsilon zeta\n"));
        assert!(capture.content.contains("later hidden record\n"));
        assert_eq!(capture.host_dropped_bytes, 0);
    }

    #[test]
    fn pre_truncation_body_over_cap_is_marked_partial() {
        let mut w = BudgetedWriter::new(1);
        assert!(!w.write(&"x".repeat(TEXT_ARTIFACT_CAPTURE_BYTE_CAP + 10)));

        let capture = w.text_artifact_capture().expect("captured source body");
        assert_eq!(capture.content.len(), TEXT_ARTIFACT_CAPTURE_BYTE_CAP);
        assert_eq!(
            capture.host_original_bytes,
            TEXT_ARTIFACT_CAPTURE_BYTE_CAP + 10
        );
        assert_eq!(capture.host_dropped_bytes, 10);
    }

    #[test]
    fn host_original_len_keeps_counting_after_capture_cap() {
        let mut w = BudgetedWriter::new(1);
        assert!(!w.write(&"x".repeat(TEXT_ARTIFACT_CAPTURE_BYTE_CAP + 10)));
        assert!(!w.write("tail bytes"));

        let capture = w.text_artifact_capture().expect("captured source body");
        assert_eq!(capture.content.len(), TEXT_ARTIFACT_CAPTURE_BYTE_CAP);
        assert_eq!(
            capture.host_original_bytes,
            TEXT_ARTIFACT_CAPTURE_BYTE_CAP + 10 + "tail bytes".len()
        );
        assert_eq!(capture.host_dropped_bytes, 10 + "tail bytes".len());
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
