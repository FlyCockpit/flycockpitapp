//! Per-subagent **seed collector** (GOALS §3c).
//!
//! A re-queryable read-only noninteractive subagent (today `explore`) may,
//! beside its prose report, attach a small set of read-only results for the
//! caller. It does so by calling the `seed` tool ([`crate::tools::seed`]),
//! which appends a `{tool, args}` entry here — a buffer scoped to the
//! subagent's driver frame. On the subagent's return the driver drains this
//! buffer and **re-executes** each entry in the caller's cwd, injecting the
//! results into the caller's transcript as native tool-call/result pairs
//! (reusing the `/compact` seed-replay machinery). Re-execution (not replay
//! of the subagent's snapshot) keeps the caller's context honest and
//! cache-stable.
//!
//! Mirrors [`crate::engine::deferred::DeferredLog`]: cloning shares one
//! backing buffer, so the copy threaded into a `turn`'s
//! [`crate::engine::tool::ToolCtx`] and the copy held by the driver observe
//! the same appends. `Default` yields an empty buffer (root frame + tests).

use std::sync::{Arc, Mutex};

use crate::db::seed_tools::SeedTool;

/// A thread-safe, frame-scoped append buffer of seed entries.
#[derive(Clone, Default)]
pub struct SeedCollector {
    items: Arc<Mutex<Vec<SeedTool>>>,
}

impl SeedCollector {
    /// A fresh, empty collector. One is created per re-queryable subagent
    /// frame.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one seed entry.
    pub fn push(&self, seed: SeedTool) {
        if let Ok(mut items) = self.items.lock() {
            items.push(seed);
        }
    }

    /// How many seeds have been queued. Used to word the tool result and to
    /// tell whether anything was seeded.
    pub fn len(&self) -> usize {
        self.items.lock().map(|i| i.len()).unwrap_or(0)
    }

    /// Whether the collector currently has no queued seeds.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Take the accumulated seeds, leaving the buffer empty. Called once by
    /// the driver when the subagent returns, so each seed is injected exactly
    /// once.
    pub fn drain(&self) -> Vec<SeedTool> {
        self.items
            .lock()
            .map(|mut items| std::mem::take(&mut *items))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn push_drain_round_trips_and_empties() {
        let c = SeedCollector::new();
        assert_eq!(c.len(), 0);
        c.push(SeedTool {
            tool: "read".into(),
            args: json!({"path": "/a.rs"}),
        });
        assert_eq!(c.len(), 1);
        let drained = c.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].tool, "read");
        assert_eq!(c.len(), 0);
        assert!(c.drain().is_empty());
    }

    #[test]
    fn clone_shares_backing_buffer() {
        let a = SeedCollector::new();
        let b = a.clone();
        b.push(SeedTool {
            tool: "read".into(),
            args: json!({}),
        });
        assert_eq!(a.len(), 1);
    }
}
