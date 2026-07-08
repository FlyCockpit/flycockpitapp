//! Per-subagent **deferred-log** buffer (`plan.md §3d`).
//!
//! When a subagent under a primary hits work outside its assigned scope it
//! calls `defer_to_orchestrator(message)` ([`crate::tools::defer`]) rather
//! than silently expanding. The message is appended here — a buffer scoped
//! to the subagent's driver frame — and control returns to the subagent so
//! it keeps doing its assigned work. On the subagent's return the parent
//! ingests `{ report, deferred_log }`: the report is the subagent's final
//! text, the deferred-log is this buffer's contents, drained and appended
//! to the tool result the parent sees.
//!
//! Token economy (GOALS §10): the verbose interview/work lives in the
//! subagent's own context and is discarded on return; only the short capped
//! report plus this terse deferred-log re-enter the parent's context.
//!
//! General, not Plan-specific: any subagent under a primary may defer.

use std::sync::{Arc, Mutex};

/// A thread-safe, frame-scoped append buffer of deferred messages. Cloning
/// shares the same backing buffer (it's an `Arc`), so the copy threaded into
/// a `turn`'s [`crate::engine::tool::ToolCtx`] and the copy held on the
/// driver frame observe the same appends. `Default` yields an empty buffer,
/// which is what the root frame and every test ctx use.
#[derive(Clone, Default)]
pub struct DeferredLog {
    items: Arc<Mutex<Vec<String>>>,
}

impl DeferredLog {
    /// A fresh, empty deferred-log. One is created per pushed subagent frame.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one deferred message. Trims surrounding whitespace and drops
    /// an empty message so the parent never ingests a blank line.
    pub fn push(&self, message: &str) {
        let m = message.trim();
        if m.is_empty() {
            return;
        }
        if let Ok(mut items) = self.items.lock() {
            items.push(m.to_string());
        }
    }

    /// How many messages have been deferred. Used to word the tool result.
    pub fn len(&self) -> usize {
        self.items.lock().map(|i| i.len()).unwrap_or(0)
    }

    /// Whether nothing has been deferred.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Take the accumulated messages, leaving the buffer empty. Called once
    /// by the driver when the subagent frame pops, so the parent ingests
    /// each deferred item exactly once.
    pub fn drain(&self) -> Vec<String> {
        self.items
            .lock()
            .map(|mut items| std::mem::take(&mut *items))
            .unwrap_or_default()
    }
}

/// Render a drained deferred-log as the trailing section appended to a
/// subagent's report (the parent's tool result). Empty input yields the
/// empty string so a subagent that deferred nothing adds no framing. The
/// heading is terse (token economy) and machine-stable so the parent's
/// prompt can instruct the model to address each item.
pub fn format_section(items: &[String]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let mut out = String::from("\n\n[deferred to orchestrator — address each]\n");
    for item in items {
        out.push_str("- ");
        out.push_str(item);
        out.push('\n');
    }
    out.truncate(out.trim_end().len());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_drain_round_trips_and_empties() {
        let log = DeferredLog::new();
        assert!(log.is_empty());
        log.push("  add a config knob  ");
        log.push("");
        log.push("rename the module");
        assert_eq!(log.len(), 2);
        let drained = log.drain();
        assert_eq!(drained, vec!["add a config knob", "rename the module"]);
        // Drained buffer is empty — a second drain yields nothing.
        assert!(log.is_empty());
        assert!(log.drain().is_empty());
    }

    #[test]
    fn clone_shares_backing_buffer() {
        let a = DeferredLog::new();
        let b = a.clone();
        b.push("from the clone");
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn format_section_empty_is_blank() {
        assert_eq!(format_section(&[]), "");
    }

    #[test]
    fn format_section_lists_items() {
        let s = format_section(&["one".into(), "two".into()]);
        assert!(s.contains("[deferred to orchestrator"));
        assert!(s.contains("- one"));
        assert!(s.contains("- two"));
    }
}
