//! Codebase-intelligence tools (GOALS §21, Phase 1).
//!
//! Eleven tools backed by the on-demand [`crate::intel::Index`]: `tree`,
//! `outline`, `symbol_find`, `word`, `deps`, `hot`, `circular`,
//! `search`, `impact`, `change_impact`, and `context_pack`. Each index-backed tool calls
//! [`crate::intel::Index::ensure_fresh`] first so it never answers from stale data.
//! `hot` is pure-FS (no index). `search` uses the shared in-process text
//! walker, honors gitignore, searches hidden files that gitignore permits, and
//! prunes `.git/` directories. `search` and `symbol_find` additionally
//! apply call-graph centrality ranking (additive, default-on,
//! config-gated via `extended.intelCentralityRanking`); `impact` reports
//! a symbol's high-precision-resolved callers and calls.
//! `search` emits `path:line[:column]: text` matches and `path:line- text`
//! context lines, then budget-caps its output via
//! [`crate::intel::budget::BudgetedWriter`].
//!
//! Output never self-scrubs: `engine::agent::turn` runs every tool
//! result through `redact::scrub` before it reaches the model.

mod change_impact;
mod circular;
mod common;
mod context_pack;
mod deps;
mod hot;
mod impact;
mod outline;
mod search;
mod symbol_find;
mod tree;
mod word;

pub use change_impact::ChangeImpactTool;
pub use circular::CircularTool;
pub use context_pack::ContextPackTool;
pub use deps::DepsTool;
pub use hot::HotTool;
pub use impact::ImpactTool;
pub use outline::OutlineTool;
pub use search::SearchTool;
pub use symbol_find::SymbolFindTool;
pub use tree::TreeTool;
pub use word::WordTool;

#[cfg(test)]
use common::bfs;
#[cfg(test)]
use common::bytecount;
#[cfg(test)]
use common::tarjan_scc;

#[cfg(test)]
mod tests;
