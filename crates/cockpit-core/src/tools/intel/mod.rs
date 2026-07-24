//! Codebase-intelligence tools (GOALS §21, Phase 1).
//!
//! Five tools backed by the on-demand [`crate::intel::Index`]: `code`,
//! `graph`, `search`, `change_impact`, and `context_pack`. Each
//! index-backed tool calls
//! [`crate::intel::Index::ensure_fresh`] first so it never answers from stale data.
//! `graph {kind:"recent"}` is pure-FS (no index). `search` uses the shared in-process text
//! walker, honors gitignore, searches hidden files that gitignore permits, and
//! prunes `.git/` directories. `search` and `code {kind:"symbol_find"}` additionally
//! apply call-graph centrality ranking (additive, default-on,
//! config-gated via `extended.intelCentralityRanking`); `graph {kind:"callers"|"calls"}`
//! reports a symbol's high-precision-resolved callers and calls.
//! `search` emits `path:line[:column]: text` matches and `path:line- text`
//! context lines, then budget-caps its output via
//! [`crate::intel::budget::BudgetedWriter`].
//!
//! Output never self-scrubs: `engine::agent::turn` runs every tool
//! result through `redact::scrub` before it reaches the model.

mod change_impact;
mod circular;
mod code;
mod common;
mod context_pack;
mod deps;
mod graph;
mod hot;
mod impact;
mod outline;
mod search;
mod symbol_find;
mod tree;
mod word;

pub use change_impact::ChangeImpactTool;
pub use code::CodeTool;
pub use context_pack::ContextPackTool;
pub use graph::GraphTool;
pub use search::SearchTool;

#[cfg(test)]
use common::bfs;
#[cfg(test)]
use common::bytecount;
#[cfg(test)]
use common::tarjan_scc;

#[cfg(test)]
mod tests;
