//! Compact-after-delegation — hide a cold parent cache across a sub-agent
//! run (implementation note, GOALS §10).
//!
//! When the main (parent) agent delegates to a sub-agent, the wait can
//! outlast the provider's prompt-cache TTL, so the *parent* prefix goes
//! cold. This module prepares a smaller version of the parent context so
//! that on the sub-agent's return the parent resumes from the cheapest
//! correct context:
//!
//! - **Cache still hot** → resume on the FULL (un-shrunk) context. No
//!   quality loss; the cache is paid for.
//! - **Cache cold** → resume on the SHRUNK context. The cold re-read is
//!   of a smaller prefix.
//!
//! ## The staleness trap (correctness #1)
//!
//! The parent's prefix staleness is measured from **delegation start**
//! (the parent's last inference — the turn that emitted the `task` call),
//! NOT from [`Session::seconds_since_last_send`]. The sub-agent shares the
//! parent's [`Session`] and calls `note_send()` on every one of its turns,
//! which would reset the session-global timer and make the parent's cold
//! prefix look hot. So we capture an [`Instant`] when delegation begins
//! and compute the cold decision from
//! [`DelegationShrink::elapsed_secs`]. The parent and child have distinct
//! provider-side cache entries (different prefixes/system prompts), so the
//! child's sends never refresh the parent's cache.
//!
//! ## Eager vs lazy
//!
//! - **No-cache provider** (`cache.mode == none`): EAGER — shrink
//!   immediately at delegation start. No cache to protect; the shrink
//!   latency hides under the delegation.
//! - **Cache-capable provider**: LAZY — only if the sub-agent is still
//!   running at `ttl_secs - margin_secs` do we kick the shrink off in
//!   parallel. A fast delegation (returns before that) wastes no shrink.
//!
//! ## Wire-only (GOALS §14)
//!
//! Like prune, the shrink touches the model-bound `Vec<Message>` history
//! only. The on-disk transcript + TUI scrollback keep full fidelity.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::providers::{CacheConfig, ShrinkConfig, ShrinkStrategy};
use crate::engine::agent::Agent;
use crate::engine::message::Message;
use crate::engine::prune;

/// When the parallel parent-context shrink should be kicked off, decided
/// once at delegation start from the resolved cache + shrink config. Pure
/// over its inputs (trivially testable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShrinkTiming {
    /// No prompt cache to protect — shrink immediately at delegation
    /// start (its latency hides under the delegation).
    Eager,
    /// Cache-capable — wait, and only kick the shrink off in parallel if
    /// the sub-agent is still running this long after delegation start
    /// (`ttl_secs - margin_secs`, floored at zero). A delegation that
    /// returns before this wastes no shrink.
    LazyAt(Duration),
}

/// Decide the shrink timing for a delegation. EAGER when the provider has
/// no cache (`cache_state` would report `NoCacheProvider`); otherwise
/// LAZY at `ttl - margin`. The margin is clamped to the TTL so the trigger
/// never lands before delegation start.
pub fn decide_timing(cache: &CacheConfig, shrink: &ShrinkConfig) -> ShrinkTiming {
    use crate::config::providers::CacheMode;
    if cache.mode == CacheMode::None {
        return ShrinkTiming::Eager;
    }
    let margin = shrink.margin_secs.min(cache.ttl_secs);
    ShrinkTiming::LazyAt(Duration::from_secs(cache.ttl_secs - margin))
}

/// Per-delegation bookkeeping: when delegation started, the resolved
/// cache config (for the cold-at-return decision), and the shrunk version
/// of the parent history once it has been computed.
///
/// The parent's FULL history stays on its [`AgentSession`] frame
/// untouched; this struct only carries the *alternative* shrunk copy and
/// the timing metadata. On return [`Self::resolve`] picks which to keep.
pub struct DelegationShrink {
    /// Captured at delegation start (the parent's last inference). The
    /// cold decision measures elapsed time from HERE, never from the
    /// session-global send timer (the trap).
    start: Instant,
    cache: CacheConfig,
    strategy: ShrinkStrategy,
    /// The shrunk parent history once computed (eager or lazy). `None`
    /// until a shrink has actually run.
    shrunk: Option<Vec<Message>>,
}

impl DelegationShrink {
    /// Begin tracking a delegation. The start instant is "now" (the
    /// parent's last inference / the turn that emitted the `task` call).
    pub fn new(cache: CacheConfig, shrink: &ShrinkConfig) -> Self {
        Self::new_at(Instant::now(), cache, shrink)
    }

    /// Begin tracking with an explicit start instant. Lets tests pin a
    /// known elapsed-since-delegation deterministically (the `std::Instant`
    /// timer is unaffected by `tokio::time::advance`).
    pub fn new_at(start: Instant, cache: CacheConfig, shrink: &ShrinkConfig) -> Self {
        Self {
            start,
            cache,
            strategy: shrink.strategy,
            shrunk: None,
        }
    }

    /// Seconds elapsed since delegation start — the parent's true prefix
    /// idle time, immune to the child's `note_send()` resets.
    pub fn elapsed_secs(&self) -> u64 {
        self.start.elapsed().as_secs()
    }

    /// The configured shrink strategy for this delegation.
    pub fn strategy(&self) -> ShrinkStrategy {
        self.strategy
    }

    /// Store the computed shrunk history (from an eager or lazy shrink).
    pub fn set_shrunk(&mut self, shrunk: Vec<Message>) {
        self.shrunk = Some(shrunk);
    }

    /// Was the parent's prefix cache cold at return? Reuses the single
    /// cache-cold predicate ([`prune::cache_state`]) — NOT a second
    /// heuristic — fed `elapsed_since_delegation` (the trap-safe figure)
    /// as `secs_since_last_send`. `upstream_bust = false`: a delegation
    /// return injects the child's report as a tool-result *after* the
    /// parent's cache breakpoint, so it doesn't bust the anchor.
    pub fn cache_cold_at_return(&self) -> bool {
        prune::cache_state(&self.cache, Some(self.elapsed_secs()), false).is_cold()
    }

    /// Pick the parent history to resume on. Cache hot → keep the FULL
    /// history (returned unchanged); cache cold → swap in the SHRUNK copy
    /// if one was computed. Returns `Some(shrunk)` when the caller should
    /// replace the parent frame's history; `None` to keep the full one
    /// (either hot, or cold but no shrink ran).
    pub fn resolve(self) -> Option<Vec<Message>> {
        if self.cache_cold_at_return() {
            self.shrunk
        } else {
            None
        }
    }
}

/// Produce the shrunk version of a parent history with the `prune`
/// strategy: lossless snapshot-dedup via [`prune::prune_history`]. Runs on
/// a clone so the parent's full history is untouched; cheap + synchronous.
pub fn prune_shrink(full_history: &[Message]) -> Vec<Message> {
    let mut copy = full_history.to_vec();
    prune::prune_history(&mut copy);
    copy
}

/// Drafts a dense brief of a parent context for the `compact` shrink
/// strategy. Abstracted behind a trait so the delegation-shrink decision
/// logic is testable without a real model round-trip (the network call is
/// environment-dependent). The production impl
/// ([`ModelBriefDrafter`]) calls the active model; tests inject a stub.
#[async_trait::async_trait]
pub trait BriefDrafter: Send + Sync {
    /// Summarize `history` into a single dense brief string. Returns the
    /// brief text; on failure the caller falls back to leaving the full
    /// history (no shrink), so an error here is non-fatal.
    async fn draft(&self, history: &[Message]) -> anyhow::Result<String>;
}

/// Production [`BriefDrafter`]: one model round-trip over the parent
/// history asking for a self-contained brief, reusing `compact.rs`'s
/// brief prompt. Distinct from `/compact`'s new-session handoff — here we
/// want a shrunk *in-place* parent history, so we reuse only the
/// brief-generation piece.
pub struct ModelBriefDrafter {
    pub agent: Arc<Agent>,
    pub cancel: tokio_util::sync::CancellationToken,
    /// The user's `extended.compact_prompt` override (already resolved from
    /// the config chain). Threaded through so delegation-shrink honors the
    /// same brief-prompt override as `/compact`
    /// (implementation note).
    pub compact_prompt: Option<String>,
}

#[async_trait::async_trait]
impl BriefDrafter for ModelBriefDrafter {
    async fn draft(&self, history: &[Message]) -> anyhow::Result<String> {
        let prompt = Message::user(crate::engine::compact::brief_prompt(
            self.compact_prompt.as_deref(),
        ));
        // Throwaway event channel: only the final brief text matters.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::engine::TurnEvent>(64);
        let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let result = self
            .agent
            .model
            .complete_captured(
                &self.agent.system,
                history,
                prompt,
                &[],
                self.agent.params.clone(),
                &self.agent.name,
                Some(&tx),
                &self.cancel,
                None,
            )
            .await;
        drop(tx);
        let _ = drain.await;
        let ((_, choice, _), _captured, _timing) = result?;
        let text = crate::engine::message::extract_text(&choice);
        if text.trim().is_empty() {
            anyhow::bail!("model produced an empty delegation-shrink brief");
        }
        Ok(text)
    }
}

/// Produce the shrunk version of a parent history with the `compact`
/// strategy: prune first (lossless, denser input), then replace the whole
/// pruned history with a single synthetic user message carrying the
/// model-drafted brief. Heavier and lossier than `prune` but saves the
/// most tokens. Falls back to the prune-only result if the drafter fails,
/// so the path never yields a worse-than-prune history.
pub async fn compact_shrink(full_history: &[Message], drafter: &dyn BriefDrafter) -> Vec<Message> {
    // Prune-first (fixed ordering, mirrors `/compact`): a denser input
    // yields a tighter brief.
    let pruned = prune_shrink(full_history);
    match drafter.draft(&pruned).await {
        Ok(brief) => vec![Message::user(format!(
            "[delegation-shrink — parent context summarized while a sub-agent ran]\n\n{brief}"
        ))],
        Err(e) => {
            tracing::warn!(error = %e, "delegation compact-shrink brief failed; falling back to prune-only");
            pruned
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::CacheMode;
    use rig::OneOrMany;
    use rig::message::{AssistantContent, ToolResult, ToolResultContent, UserContent};

    fn ephemeral(ttl: u64) -> CacheConfig {
        CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: ttl,
        }
    }

    fn none_cache() -> CacheConfig {
        CacheConfig {
            mode: CacheMode::None,
            ttl_secs: 300,
        }
    }

    /// Two identical `read` snapshots — one elidable by prune. Used to
    /// prove the prune-strategy shrink actually shrinks.
    fn dup_read_history() -> Vec<Message> {
        let call = |id: &str| Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(
                crate::engine::message::ToolCall {
                    id: id.to_string(),
                    call_id: None,
                    function: rig::message::ToolFunction {
                        name: "read".into(),
                        arguments: serde_json::json!({ "path": "/abs/foo.rs" }),
                    },
                    signature: None,
                    additional_params: None,
                },
            )),
        };
        let result = |id: &str| Message::User {
            content: OneOrMany::one(UserContent::ToolResult(ToolResult {
                id: id.to_string(),
                call_id: None,
                content: OneOrMany::one(ToolResultContent::text(
                    "FULL SNAPSHOT BODY with enough tokens to matter here",
                )),
            })),
        };
        vec![call("c1"), result("c1"), call("c2"), result("c2")]
    }

    /// No-cache provider → EAGER (shrink immediately at delegation start).
    #[test]
    fn no_cache_is_eager() {
        assert_eq!(
            decide_timing(&none_cache(), &ShrinkConfig::default()),
            ShrinkTiming::Eager
        );
    }

    /// Cache-capable provider → LAZY, kicked off at `ttl - margin`.
    #[test]
    fn cache_capable_is_lazy_at_ttl_minus_margin() {
        let shrink = ShrinkConfig {
            strategy: ShrinkStrategy::Prune,
            margin_secs: 30,
        };
        assert_eq!(
            decide_timing(&ephemeral(300), &shrink),
            ShrinkTiming::LazyAt(Duration::from_secs(270))
        );
    }

    /// A margin larger than the TTL clamps to TTL (trigger at t=0, never
    /// negative).
    #[test]
    fn margin_larger_than_ttl_clamps() {
        let shrink = ShrinkConfig {
            strategy: ShrinkStrategy::Prune,
            margin_secs: 9999,
        };
        assert_eq!(
            decide_timing(&ephemeral(60), &shrink),
            ShrinkTiming::LazyAt(Duration::from_secs(0))
        );
    }

    /// The prune-strategy shrink runs `prune_history`: the older duplicate
    /// read body is elided; the full history is left untouched (clone).
    #[test]
    fn prune_shrink_elides_and_preserves_full() {
        let full = dup_read_history();
        let shrunk = prune_shrink(&full);
        // The shrunk copy has an elided older body...
        assert!(
            prune::dedup_plan(&shrunk).is_empty(),
            "shrunk is fully pruned"
        );
        // ...but the original full history is unchanged (still elidable).
        assert!(
            !prune::dedup_plan(&full).is_empty(),
            "full history must not be mutated"
        );
    }

    /// resolve(): cache HOT at return → keep full (returns None even when a
    /// shrink was computed).
    #[test]
    fn resolve_hot_keeps_full() {
        let mut d = DelegationShrink::new(ephemeral(300), &ShrinkConfig::default());
        d.set_shrunk(vec![Message::user("shrunk")]);
        // elapsed ≈ 0 < ttl 300 → hot.
        assert!(!d.cache_cold_at_return());
        assert!(d.resolve().is_none(), "hot resume keeps the full context");
    }

    /// resolve(): cache COLD at return (no-cache provider) → swap in the
    /// shrunk copy.
    #[test]
    fn resolve_cold_swaps_shrunk() {
        let mut d = DelegationShrink::new(none_cache(), &ShrinkConfig::default());
        d.set_shrunk(vec![Message::user("shrunk")]);
        assert!(d.cache_cold_at_return(), "no-cache provider is always cold");
        let picked = d.resolve().expect("cold resume swaps in the shrunk copy");
        assert_eq!(picked.len(), 1);
    }

    /// resolve(): cache cold but NO shrink ran → keep full (can't swap in
    /// what doesn't exist).
    #[test]
    fn resolve_cold_without_shrink_keeps_full() {
        let d = DelegationShrink::new(none_cache(), &ShrinkConfig::default());
        assert!(d.cache_cold_at_return());
        assert!(d.resolve().is_none(), "no shrunk copy → keep full");
    }

    /// THE TRAP: a child's `note_send()` (which resets the session-global
    /// timer to ~0) must NOT make the parent's cold prefix look hot. We
    /// pin the delegation start 200s in the past (deterministic, immune to
    /// the timer) and prove that touching the SHARED session's send timer
    /// afterwards does not change the parent's verdict — because the
    /// tracker measures elapsed-since-delegation, never the session timer.
    #[test]
    fn child_note_send_does_not_mask_parent_cold() {
        use crate::session::Session;
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create(db, std::path::PathBuf::from("/tmp"), "builder").unwrap();

        // Parent delegated 200s ago with a 100s TTL → its prefix is cold.
        let start = Instant::now() - Duration::from_secs(200);
        let d = DelegationShrink::new_at(start, ephemeral(100), &ShrinkConfig::default());

        // The child does several turns, each stamping the SHARED session's
        // send timer to "now" — exactly what would fool a naive
        // `seconds_since_last_send`-based check into seeing a warm prefix.
        session.note_send();
        assert!(
            session.seconds_since_last_send().unwrap() < 100,
            "session-global timer was just reset by the child's send (looks hot)"
        );

        // The parent's verdict is COLD regardless: the tracker measures
        // elapsed-since-delegation (≈200s > 100s TTL), not the session
        // timer the child clobbered.
        assert!(d.elapsed_secs() >= 200);
        assert!(
            d.cache_cold_at_return(),
            "parent prefix is cold; the child's note_send must not mask it"
        );
        // The shrunk copy (if computed) would be used on resume.
        let mut d = d;
        d.set_shrunk(vec![Message::user("shrunk")]);
        assert!(
            d.resolve().is_some(),
            "cold parent resumes on shrunk context"
        );
    }

    /// A fast delegation: elapsed stays below the TTL, so the parent is
    /// HOT at return and resolve keeps the full context — the
    /// no-wasted-shrink acceptance criterion at the decision layer.
    #[test]
    fn fast_delegation_resumes_full() {
        // Delegated 5s ago with a 300s TTL → still hot.
        let start = Instant::now() - Duration::from_secs(5);
        let d = DelegationShrink::new_at(start, ephemeral(300), &ShrinkConfig::default());
        assert!(!d.cache_cold_at_return(), "5s < 300s TTL → hot");
        assert!(d.resolve().is_none());
    }

    /// The compact-shrink falls back to the prune-only result when the
    /// drafter fails — never yields a worse-than-prune history.
    #[tokio::test]
    async fn compact_shrink_falls_back_to_prune_on_drafter_error() {
        struct Failing;
        #[async_trait::async_trait]
        impl BriefDrafter for Failing {
            async fn draft(&self, _h: &[Message]) -> anyhow::Result<String> {
                anyhow::bail!("no model in test")
            }
        }
        let full = dup_read_history();
        let shrunk = compact_shrink(&full, &Failing).await;
        // Fallback == prune-only: same length as the pruned history (4),
        // and fully pruned.
        assert_eq!(shrunk.len(), full.len());
        assert!(prune::dedup_plan(&shrunk).is_empty());
    }

    /// The compact-shrink with a working drafter collapses history to a
    /// single brief message.
    #[tokio::test]
    async fn compact_shrink_collapses_to_brief() {
        struct Ok;
        #[async_trait::async_trait]
        impl BriefDrafter for Ok {
            async fn draft(&self, _h: &[Message]) -> anyhow::Result<String> {
                Result::Ok("dense brief of the parent context".into())
            }
        }
        let full = dup_read_history();
        let shrunk = compact_shrink(&full, &Ok).await;
        assert_eq!(shrunk.len(), 1, "collapsed to one brief message");
    }
}
