//! Hierarchical delegation budget ledger (issue #313).
//!
//! One mechanism: a shared remaining pool plus a per-node local cap. Children
//! charge the same ledger as their parent so a subtree cannot exceed the root
//! allotment; swarm fan-out shares one pool so K children cannot each spend
//! the parent's full budget. Remint rebinds the live ceiling in place and
//! never forgives spend or the wall-clock origin while any handle still
//! charges that ledger. Unpriced token usage is not free: a finite cost
//! ceiling rejects it. Round admission is a reservation: production turn
//! loops must [`BudgetPool::charge_round`] before dispatching a provider
//! turn. [`BudgetPool::preflight`] peeks whether the next round would be
//! admitted; it is not a reservation on a shared ledger.
//!
//! Unlimited is a budget *value* (`ResolvedDelegationBudget` with every
//! dimension `None`), not a bypass. The compact progress guard and retry
//! pacing live on the same handle and are never lifted.

use std::ops::AddAssign;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cockpit_config::config::delegation_budget::{
    BudgetSpend, DEFAULT_COMPACT_NO_PROGRESS_LIMIT, DEFAULT_MAX_RETRIES_PER_TURN,
    ResolvedDelegationBudget,
};

use crate::sync::lock_or_recover;
use crate::tokens::TokenUsage;

/// Which spend dimension rejected a charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetDimension {
    Rounds,
    InputTokens,
    OutputTokens,
    Cost,
    WallClock,
}

impl BudgetDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rounds => "rounds",
            Self::InputTokens => "input_tokens",
            Self::OutputTokens => "output_tokens",
            Self::Cost => "cost",
            Self::WallClock => "wall_clock",
        }
    }
}

/// Terminal exhaustion. Callers return the best partial result; they never
/// continue or hang.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetExhaustion {
    pub dimension: BudgetDimension,
    pub snapshot: BudgetSnapshot,
}

impl BudgetExhaustion {
    pub fn message(&self) -> String {
        format!("budget exhausted ({})", self.dimension.as_str())
    }
}

/// One charge against the pool.
///
/// Token usage without a catalog price is **unpriced**, not free. [`Self::from_usage`]
/// marks any non-zero token mix unpriced until [`Self::with_cost`] records a
/// known amount (including a legitimate `$0` row). A finite cost ceiling
/// rejects unpriced charges; unlimited cost admits them without accumulating
/// cost spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BudgetCharge {
    pub rounds: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
    unpriced_cost: bool,
}

impl BudgetCharge {
    pub fn round() -> Self {
        Self {
            rounds: 1,
            ..Self::default()
        }
    }

    pub fn from_usage(usage: TokenUsage) -> Self {
        let input_tokens = usage
            .input_tokens
            .saturating_add(usage.cache_creation_input_tokens);
        let output_tokens = usage.output_tokens;
        Self {
            rounds: 0,
            // `input_tokens` already includes cached reads. Cache-creation
            // tokens are billed in addition (Anthropic cache writes).
            input_tokens,
            output_tokens,
            cost_microusd: 0,
            unpriced_cost: input_tokens > 0 || output_tokens > 0,
        }
    }

    pub fn with_cost(mut self, cost_microusd: u64) -> Self {
        self.cost_microusd = cost_microusd;
        self.unpriced_cost = false;
        self
    }

    pub fn is_unpriced(self) -> bool {
        self.unpriced_cost
    }

    pub fn is_empty(self) -> bool {
        self == Self::default()
    }
}

impl AddAssign for BudgetCharge {
    fn add_assign(&mut self, rhs: Self) {
        self.rounds = self.rounds.saturating_add(rhs.rounds);
        self.input_tokens = self.input_tokens.saturating_add(rhs.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(rhs.output_tokens);
        self.cost_microusd = self.cost_microusd.saturating_add(rhs.cost_microusd);
        self.unpriced_cost |= rhs.unpriced_cost;
    }
}

/// Point-in-time view of remaining vs ceiling. Always available, including
/// under an unlimited budget, so unlimited is never invisible spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetSnapshot {
    pub ceiling: ResolvedDelegationBudget,
    pub local_ceiling: ResolvedDelegationBudget,
    pub spent: BudgetSpend,
    pub local_spent: BudgetSpend,
    pub unlimited: bool,
}

impl BudgetSnapshot {
    pub fn remaining(&self) -> ResolvedDelegationBudget {
        self.ceiling
            .remaining_after(self.spent)
            .intersect(self.local_ceiling.remaining_after(self.local_spent))
    }

    pub fn render(&self) -> String {
        fn dim<T: std::fmt::Display>(spent: T, ceiling: Option<T>) -> String {
            match ceiling {
                None => format!("{spent}/unlimited"),
                Some(max) => format!("{spent}/{max}"),
            }
        }
        let remaining = self.remaining();
        format!(
            "budget rounds {}  in {}  out {}  cost_µ$ {}  wall {}{}",
            dim(
                self.spent.rounds,
                remaining
                    .max_rounds
                    .map(u64::from)
                    .or(self.ceiling.max_rounds.map(u64::from))
            ),
            dim(self.spent.input_tokens, self.ceiling.max_input_tokens),
            dim(self.spent.output_tokens, self.ceiling.max_output_tokens),
            dim(self.spent.cost_microusd, self.ceiling.max_cost_microusd),
            dim(
                self.spent.elapsed.as_secs(),
                self.ceiling.max_wall_clock.map(|d| d.as_secs())
            ),
            if self.unlimited {
                " (unlimited spend)"
            } else {
                ""
            }
        )
    }
}

/// Consecutive no-progress compact-and-continue bound. Always enforced.
/// Token-count reduction alone is not forward progress.
#[derive(Debug, Clone)]
pub struct CompactProgressGuard {
    consecutive_no_progress: u32,
    max_consecutive: u32,
}

impl Default for CompactProgressGuard {
    fn default() -> Self {
        Self::new(DEFAULT_COMPACT_NO_PROGRESS_LIMIT)
    }
}

impl CompactProgressGuard {
    pub fn new(max_consecutive: u32) -> Self {
        Self {
            consecutive_no_progress: 0,
            max_consecutive: max_consecutive.max(1),
        }
    }

    pub fn consecutive_no_progress(&self) -> u32 {
        self.consecutive_no_progress
    }

    /// Record a compaction. `tokens_after` is the post-compact token count
    /// (informational; shrinking context is not forward progress).
    /// `forward_progress` is true when the agent produced new tool results or
    /// assistant work since the previous compaction.
    pub fn record(
        &mut self,
        _tokens_after: u64,
        forward_progress: bool,
    ) -> Result<(), CompactLoopExhausted> {
        if forward_progress {
            self.consecutive_no_progress = 0;
            return Ok(());
        }
        self.consecutive_no_progress = self.consecutive_no_progress.saturating_add(1);
        if self.consecutive_no_progress >= self.max_consecutive {
            Err(CompactLoopExhausted {
                consecutive: self.consecutive_no_progress,
                max_consecutive: self.max_consecutive,
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactLoopExhausted {
    pub consecutive: u32,
    pub max_consecutive: u32,
}

impl CompactLoopExhausted {
    pub fn message(self) -> String {
        format!(
            "compact-and-continue blocked after {} consecutive compaction(s) with no token/forward progress",
            self.consecutive
        )
    }
}

/// Per-turn retry bound. Always enforced, including under unlimited spend.
#[derive(Debug, Clone)]
pub struct RetryPacingGuard {
    retries_this_turn: u32,
    max_retries_per_turn: u32,
}

impl Default for RetryPacingGuard {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_RETRIES_PER_TURN)
    }
}

impl RetryPacingGuard {
    pub fn new(max_retries_per_turn: u32) -> Self {
        Self {
            retries_this_turn: 0,
            max_retries_per_turn: max_retries_per_turn.max(1),
        }
    }

    pub fn retries_this_turn(&self) -> u32 {
        self.retries_this_turn
    }

    pub fn allow_retry(&mut self) -> bool {
        if self.retries_this_turn >= self.max_retries_per_turn {
            return false;
        }
        self.retries_this_turn = self.retries_this_turn.saturating_add(1);
        true
    }

    pub fn reset_turn(&mut self) {
        self.retries_this_turn = 0;
    }
}

/// Cheap cloneable handle to the per-turn retry bound. Inference retry
/// consults this so a 429 cannot storm across tool rounds, including on
/// dispatch paths that do not hold a [`BudgetPool`].
#[derive(Clone)]
pub struct TurnRetryBudget {
    inner: Arc<Mutex<RetryPacingGuard>>,
}

impl TurnRetryBudget {
    pub fn new(max_retries_per_turn: u32) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RetryPacingGuard::new(max_retries_per_turn))),
        }
    }

    pub fn allow_retry(&self) -> bool {
        lock_or_recover(&self.inner).allow_retry()
    }

    pub fn reset_turn(&self) {
        lock_or_recover(&self.inner).reset_turn();
    }

    pub fn retries_this_turn(&self) -> u32 {
        lock_or_recover(&self.inner).retries_this_turn()
    }
}

impl Default for TurnRetryBudget {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_RETRIES_PER_TURN)
    }
}

impl std::fmt::Debug for TurnRetryBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnRetryBudget")
            .field("retries_this_turn", &self.retries_this_turn())
            .finish()
    }
}

struct SharedLedger {
    ceiling: ResolvedDelegationBudget,
    spent_rounds: u64,
    spent_input_tokens: u64,
    spent_output_tokens: u64,
    spent_cost_microusd: u64,
    started_at: Instant,
}

struct LocalState {
    ceiling: ResolvedDelegationBudget,
    spent_rounds: u64,
    spent_input_tokens: u64,
    spent_output_tokens: u64,
    spent_cost_microusd: u64,
    started_at: Instant,
    compact_guard: CompactProgressGuard,
}

/// Hierarchical spend pool. Clone is cheap (shared ledger + per-node local
/// cap). Swarm children should [`BudgetPool::share`] so they spend one pool.
/// Liveness guards (compact progress, retry pacing) live beside the spend
/// ledger: reminting the ceiling does not reset them, and retry pacing is
/// exposable to inference without a pool handle. Spend on a live ledger is
/// monotonic — remint never forgives it.
#[derive(Clone)]
pub struct BudgetPool {
    ledger: Arc<Mutex<SharedLedger>>,
    local: Arc<Mutex<LocalState>>,
    retry_guard: TurnRetryBudget,
}

impl BudgetPool {
    pub fn new(ceiling: ResolvedDelegationBudget) -> Self {
        let now = Instant::now();
        Self {
            ledger: Arc::new(Mutex::new(SharedLedger {
                ceiling,
                spent_rounds: 0,
                spent_input_tokens: 0,
                spent_output_tokens: 0,
                spent_cost_microusd: 0,
                started_at: now,
            })),
            local: Arc::new(Mutex::new(LocalState {
                ceiling,
                spent_rounds: 0,
                spent_input_tokens: 0,
                spent_output_tokens: 0,
                spent_cost_microusd: 0,
                started_at: now,
                compact_guard: CompactProgressGuard::default(),
            })),
            retry_guard: TurnRetryBudget::default(),
        }
    }

    pub fn defaults() -> Self {
        Self::new(ResolvedDelegationBudget::defaults())
    }

    pub fn unlimited() -> Self {
        Self::new(ResolvedDelegationBudget::unlimited())
    }

    pub fn schedule_run_defaults() -> Self {
        Self::new(ResolvedDelegationBudget::schedule_run_defaults())
    }

    /// Reconfigure the shared ledger and this handle's local ceiling in place.
    ///
    /// Turn install must never allocate a new shared ledger: clones held by
    /// in-flight swarm, background `task`, and schedule runners would keep
    /// charging the orphaned pool, and foreground + stale descendants could
    /// each consume a full root cap. Lock order matches [`Self::charge`]:
    /// ledger, then local.
    ///
    /// Spend and the wall-clock origin are monotonic on a live ledger. A new
    /// user turn may raise or lower the ceiling; it must not forgive charges
    /// already made by descendants that survived the turn boundary. Allotted
    /// children's local caps are untouched (they keep the overlay baked in at
    /// spawn). Compact progress and retry pacing are liveness guards and are
    /// not reset here.
    pub fn remint_root(&self, ceiling: ResolvedDelegationBudget) {
        let mut ledger = lock_or_recover(&self.ledger);
        let mut local = lock_or_recover(&self.local);
        ledger.ceiling = ceiling;
        local.ceiling = ceiling;
    }

    /// Shared view of this pool (swarm fan-out). Children charge the same
    /// remaining budget; they also share the local cap so K children cannot
    /// each spend the full allotment.
    pub fn share(&self) -> Self {
        Self {
            ledger: Arc::clone(&self.ledger),
            local: Arc::clone(&self.local),
            retry_guard: self.retry_guard.clone(),
        }
    }

    /// True when `other` charges the same remaining parent ledger.
    pub fn shares_ledger_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.ledger, &other.ledger)
    }

    /// Turn-scoped retry handle for inference. Always enforced, including
    /// under unlimited spend.
    pub fn retry_handle(&self) -> TurnRetryBudget {
        self.retry_guard.clone()
    }

    /// Allot a child slice of the parent's remaining pool. Charges still hit
    /// the parent ledger (sum of descendants is bounded). The child's local
    /// cap is `remaining ∩ child_ceiling`.
    pub fn allot(&self, child_ceiling: ResolvedDelegationBudget) -> Self {
        let snapshot = self.snapshot();
        let remaining = snapshot.remaining();
        let local_ceiling = remaining.intersect(child_ceiling);
        let now = Instant::now();
        Self {
            ledger: Arc::clone(&self.ledger),
            local: Arc::new(Mutex::new(LocalState {
                ceiling: local_ceiling,
                spent_rounds: 0,
                spent_input_tokens: 0,
                spent_output_tokens: 0,
                spent_cost_microusd: 0,
                started_at: now,
                compact_guard: CompactProgressGuard::default(),
            })),
            retry_guard: TurnRetryBudget::default(),
        }
    }

    pub fn ceiling(&self) -> ResolvedDelegationBudget {
        lock_or_recover(&self.ledger).ceiling
    }

    pub fn snapshot(&self) -> BudgetSnapshot {
        let ledger = lock_or_recover(&self.ledger);
        let local = lock_or_recover(&self.local);
        let elapsed = ledger.started_at.elapsed();
        let local_elapsed = local.started_at.elapsed();
        BudgetSnapshot {
            ceiling: ledger.ceiling,
            local_ceiling: local.ceiling,
            spent: BudgetSpend {
                rounds: ledger.spent_rounds,
                input_tokens: ledger.spent_input_tokens,
                output_tokens: ledger.spent_output_tokens,
                cost_microusd: ledger.spent_cost_microusd,
                elapsed,
            },
            local_spent: BudgetSpend {
                rounds: local.spent_rounds,
                input_tokens: local.spent_input_tokens,
                output_tokens: local.spent_output_tokens,
                cost_microusd: local.spent_cost_microusd,
                elapsed: local_elapsed,
            },
            unlimited: ledger.ceiling.is_unlimited() && local.ceiling.is_unlimited(),
        }
    }

    /// Peek whether the next provider round would be admitted, without
    /// recording spend. Production turn loops must still
    /// [`Self::charge_round`] before dispatch: this is not a reservation,
    /// and descendants sharing the ledger can spend between peek and
    /// dispatch.
    pub fn preflight(&self) -> Result<(), BudgetExhaustion> {
        let ledger = lock_or_recover(&self.ledger);
        let local = lock_or_recover(&self.local);
        if let Some(dimension) = reject_charge(&ledger, &local, BudgetCharge::round()) {
            drop(local);
            drop(ledger);
            return Err(BudgetExhaustion {
                dimension,
                snapshot: self.snapshot(),
            });
        }
        Ok(())
    }

    /// Reserve one provider round on the live ledger. Call this before
    /// dispatching inference so an already-met ceiling cannot spend
    /// tokens or cost on the shared pool.
    pub fn charge_round(&self) -> Result<(), BudgetExhaustion> {
        self.charge(BudgetCharge::round())
    }

    /// Charge provider-reported tokens. Cost is unpriced until the caller
    /// applies [`BudgetCharge::with_cost`]; a finite cost ceiling rejects
    /// that as exhaustion rather than treating unknown cost as free.
    pub fn charge_usage(&self, usage: TokenUsage) -> Result<(), BudgetExhaustion> {
        self.charge(BudgetCharge::from_usage(usage))
    }

    /// Admit `charge` against both the shared ledger and this handle's local
    /// cap. Unpriced token usage (`BudgetCharge::is_unpriced`) is exhaustion
    /// on any finite cost ceiling; it is not recorded as free.
    pub fn charge(&self, charge: BudgetCharge) -> Result<(), BudgetExhaustion> {
        let mut ledger = lock_or_recover(&self.ledger);
        let mut local = lock_or_recover(&self.local);
        if let Some(dimension) = reject_charge(&ledger, &local, charge) {
            drop(local);
            drop(ledger);
            return Err(BudgetExhaustion {
                dimension,
                snapshot: self.snapshot(),
            });
        }

        ledger.spent_rounds = ledger.spent_rounds.saturating_add(charge.rounds);
        ledger.spent_input_tokens = ledger
            .spent_input_tokens
            .saturating_add(charge.input_tokens);
        ledger.spent_output_tokens = ledger
            .spent_output_tokens
            .saturating_add(charge.output_tokens);
        ledger.spent_cost_microusd = ledger
            .spent_cost_microusd
            .saturating_add(charge.cost_microusd);

        local.spent_rounds = local.spent_rounds.saturating_add(charge.rounds);
        local.spent_input_tokens = local.spent_input_tokens.saturating_add(charge.input_tokens);
        local.spent_output_tokens = local
            .spent_output_tokens
            .saturating_add(charge.output_tokens);
        local.spent_cost_microusd = local
            .spent_cost_microusd
            .saturating_add(charge.cost_microusd);
        Ok(())
    }

    /// Compact-and-continue progress guard for this node. Always enforced.
    pub fn record_compaction(
        &self,
        tokens_after: u64,
        forward_progress: bool,
    ) -> Result<(), CompactLoopExhausted> {
        lock_or_recover(&self.local)
            .compact_guard
            .record(tokens_after, forward_progress)
    }

    pub fn compact_guard_consecutive(&self) -> u32 {
        lock_or_recover(&self.local)
            .compact_guard
            .consecutive_no_progress()
    }

    pub fn allow_retry(&self) -> bool {
        self.retry_guard.allow_retry()
    }

    pub fn reset_retry_turn(&self) {
        self.retry_guard.reset_turn();
    }

    pub fn retries_this_turn(&self) -> u32 {
        self.retry_guard.retries_this_turn()
    }

    /// Interactive grant: raise the rounds ceiling by `extra` so the user can
    /// continue after a round-cap pause. Unlimited ceilings stay unlimited.
    pub fn extend_rounds(&self, extra: u32) {
        let extra = u64::from(extra);
        let mut ledger = lock_or_recover(&self.ledger);
        if let Some(max) = &mut ledger.ceiling.max_rounds {
            *max = (*max as u64).saturating_add(extra).min(u64::from(u32::MAX)) as u32;
        }
        drop(ledger);
        let mut local = lock_or_recover(&self.local);
        if let Some(max) = &mut local.ceiling.max_rounds {
            *max = (*max as u64).saturating_add(extra).min(u64::from(u32::MAX)) as u32;
        }
    }
}

fn projected_spend(
    spent_rounds: u64,
    spent_input_tokens: u64,
    spent_output_tokens: u64,
    spent_cost_microusd: u64,
    elapsed: Duration,
    charge: BudgetCharge,
) -> BudgetSpend {
    BudgetSpend {
        rounds: spent_rounds.saturating_add(charge.rounds),
        input_tokens: spent_input_tokens.saturating_add(charge.input_tokens),
        output_tokens: spent_output_tokens.saturating_add(charge.output_tokens),
        cost_microusd: spent_cost_microusd.saturating_add(charge.cost_microusd),
        elapsed,
    }
}

fn reject_charge(
    ledger: &SharedLedger,
    local: &LocalState,
    charge: BudgetCharge,
) -> Option<BudgetDimension> {
    if let Some(dimension) = would_exceed(
        ledger.ceiling,
        projected_spend(
            ledger.spent_rounds,
            ledger.spent_input_tokens,
            ledger.spent_output_tokens,
            ledger.spent_cost_microusd,
            ledger.started_at.elapsed(),
            charge,
        ),
    ) {
        return Some(dimension);
    }
    if let Some(dimension) = would_exceed(
        local.ceiling,
        projected_spend(
            local.spent_rounds,
            local.spent_input_tokens,
            local.spent_output_tokens,
            local.spent_cost_microusd,
            local.started_at.elapsed(),
            charge,
        ),
    ) {
        return Some(dimension);
    }
    if charge.unpriced_cost
        && (unpriced_cost_blocked(ledger.ceiling) || unpriced_cost_blocked(local.ceiling))
    {
        return Some(BudgetDimension::Cost);
    }
    None
}

fn would_exceed(ceiling: ResolvedDelegationBudget, spent: BudgetSpend) -> Option<BudgetDimension> {
    if ceiling
        .max_rounds
        .is_some_and(|max| spent.rounds > u64::from(max))
    {
        return Some(BudgetDimension::Rounds);
    }
    if ceiling
        .max_input_tokens
        .is_some_and(|max| spent.input_tokens > max)
    {
        return Some(BudgetDimension::InputTokens);
    }
    if ceiling
        .max_output_tokens
        .is_some_and(|max| spent.output_tokens > max)
    {
        return Some(BudgetDimension::OutputTokens);
    }
    if ceiling
        .max_cost_microusd
        .is_some_and(|max| spent.cost_microusd > max)
    {
        return Some(BudgetDimension::Cost);
    }
    if ceiling
        .max_wall_clock
        .is_some_and(|max| spent.elapsed > max)
    {
        return Some(BudgetDimension::WallClock);
    }
    None
}

fn unpriced_cost_blocked(ceiling: ResolvedDelegationBudget) -> bool {
    ceiling.max_cost_microusd.is_some()
}

/// Partial-result prefix used at every exhaustion seam.
pub fn budget_exhausted_report(partial: &str, exhaustion: &BudgetExhaustion) -> String {
    let partial = partial.trim();
    if partial.is_empty() {
        exhaustion.message()
    } else {
        format!("{}\n\n{partial}", exhaustion.message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_fan_out_cannot_each_spend_the_parent_full_budget() {
        let root = BudgetPool::new(ResolvedDelegationBudget {
            max_rounds: Some(4),
            ..ResolvedDelegationBudget::unlimited()
        });
        let swarm = root.allot(ResolvedDelegationBudget {
            max_rounds: Some(4),
            ..ResolvedDelegationBudget::unlimited()
        });
        let child_a = swarm.share();
        let child_b = swarm.share();
        for _ in 0..2 {
            child_a.charge_round().unwrap();
        }
        for _ in 0..2 {
            child_b.charge_round().unwrap();
        }
        assert!(child_a.charge_round().is_err());
        assert!(child_b.charge_round().is_err());
        assert_eq!(root.snapshot().spent.rounds, 4);
    }

    #[test]
    fn sequential_children_sum_to_parent_remaining() {
        let root = BudgetPool::new(ResolvedDelegationBudget {
            max_rounds: Some(3),
            ..ResolvedDelegationBudget::unlimited()
        });
        let child_a = root.allot(ResolvedDelegationBudget::unlimited());
        child_a.charge_round().unwrap();
        child_a.charge_round().unwrap();
        let child_b = root.allot(ResolvedDelegationBudget::unlimited());
        child_b.charge_round().unwrap();
        assert!(child_b.charge_round().is_err());
        assert_eq!(root.snapshot().spent.rounds, 3);
    }

    #[test]
    fn parent_can_allot_bounded_slice_under_unlimited_root() {
        let root = BudgetPool::unlimited();
        let child = root.allot(ResolvedDelegationBudget {
            max_rounds: Some(2),
            ..ResolvedDelegationBudget::unlimited()
        });
        child.charge_round().unwrap();
        child.charge_round().unwrap();
        assert!(child.charge_round().is_err());
        // Parent remaining is still unlimited; another child can run.
        let sibling = root.allot(ResolvedDelegationBudget {
            max_rounds: Some(1),
            ..ResolvedDelegationBudget::unlimited()
        });
        sibling.charge_round().unwrap();
        assert_eq!(root.snapshot().spent.rounds, 3);
        assert!(root.snapshot().unlimited);
    }

    #[test]
    fn token_charge_exhausts_and_returns_partial_surface() {
        let pool = BudgetPool::new(ResolvedDelegationBudget {
            max_input_tokens: Some(10),
            ..ResolvedDelegationBudget::unlimited()
        });
        pool.charge(BudgetCharge {
            input_tokens: 10,
            ..BudgetCharge::default()
        })
        .unwrap();
        let err = pool
            .charge(BudgetCharge {
                input_tokens: 1,
                ..BudgetCharge::default()
            })
            .unwrap_err();
        assert_eq!(err.dimension, BudgetDimension::InputTokens);
        assert_eq!(
            budget_exhausted_report("partial answer", &err),
            "budget exhausted (input_tokens)\n\npartial answer"
        );
    }

    #[test]
    fn unlimited_budget_still_trips_progress_guard() {
        let pool = BudgetPool::unlimited();
        assert!(pool.snapshot().unlimited);
        pool.record_compaction(100, false).unwrap();
        pool.record_compaction(100, false).unwrap();
        let err = pool.record_compaction(100, false).unwrap_err();
        assert_eq!(err.consecutive, 3);
        // Forward progress (new assistant/tool work) resets the counter.
        let pool = BudgetPool::unlimited();
        pool.record_compaction(100, false).unwrap();
        pool.record_compaction(90, true).unwrap();
        pool.record_compaction(90, false).unwrap();
        pool.record_compaction(90, false).unwrap();
        let err = pool.record_compaction(90, false).unwrap_err();
        assert_eq!(err.consecutive, 3);
    }

    #[test]
    fn token_reduction_alone_is_not_forward_progress() {
        let pool = BudgetPool::unlimited();
        pool.record_compaction(100, false).unwrap();
        pool.record_compaction(50, false).unwrap();
        let err = pool.record_compaction(10, false).unwrap_err();
        assert_eq!(err.consecutive, 3);
    }

    #[test]
    fn from_usage_includes_cache_creation_and_cost() {
        let usage = TokenUsage {
            input_tokens: 10,
            output_tokens: 3,
            cached_input_tokens: 4,
            cache_creation_input_tokens: 7,
        };
        let unpriced = BudgetCharge::from_usage(usage);
        assert!(unpriced.is_unpriced());
        assert_eq!(unpriced.cost_microusd, 0);
        let charge = unpriced.with_cost(42);
        assert_eq!(charge.input_tokens, 17);
        assert_eq!(charge.output_tokens, 3);
        assert_eq!(charge.cost_microusd, 42);
        assert!(!charge.is_unpriced());
    }

    #[test]
    fn share_and_allot_keep_one_parent_ledger() {
        let root = BudgetPool::new(ResolvedDelegationBudget {
            max_rounds: Some(2),
            ..ResolvedDelegationBudget::unlimited()
        });
        let child_a = root.allot(ResolvedDelegationBudget::unlimited());
        let child_b = root.allot(ResolvedDelegationBudget::unlimited());
        assert!(root.shares_ledger_with(&child_a));
        assert!(root.shares_ledger_with(&child_b));
        child_a.charge_round().unwrap();
        child_b.charge_round().unwrap();
        assert!(child_a.charge_round().is_err());
        assert_eq!(root.snapshot().spent.rounds, 2);
    }

    #[test]
    fn cost_ceiling_is_enforced() {
        let pool = BudgetPool::new(ResolvedDelegationBudget {
            max_cost_microusd: Some(10),
            ..ResolvedDelegationBudget::unlimited()
        });
        pool.charge(BudgetCharge {
            cost_microusd: 10,
            ..BudgetCharge::default()
        })
        .unwrap();
        let err = pool
            .charge(BudgetCharge {
                cost_microusd: 1,
                ..BudgetCharge::default()
            })
            .unwrap_err();
        assert_eq!(err.dimension, BudgetDimension::Cost);
    }

    #[test]
    fn unlimited_budget_still_bounds_retries_per_turn() {
        let pool = BudgetPool::unlimited();
        for _ in 0..DEFAULT_MAX_RETRIES_PER_TURN {
            assert!(pool.allow_retry());
        }
        assert!(!pool.allow_retry());
        pool.reset_retry_turn();
        assert!(pool.allow_retry());
    }

    #[test]
    fn preflight_fails_when_already_exhausted() {
        let pool = BudgetPool::new(ResolvedDelegationBudget {
            max_rounds: Some(0),
            ..ResolvedDelegationBudget::unlimited()
        });
        // A zero-round ceiling rejects the first round: spent.rounds == 0 is
        // allowed as current spend, but the next round (spent+1) is not.
        let err = pool.preflight().unwrap_err();
        assert_eq!(err.dimension, BudgetDimension::Rounds);
        assert_eq!(pool.snapshot().spent.rounds, 0);
        let err = pool.charge_round().unwrap_err();
        assert_eq!(err.dimension, BudgetDimension::Rounds);
        assert_eq!(pool.snapshot().spent.rounds, 0);
    }

    #[test]
    fn preflight_rejects_the_next_round_at_the_ceiling() {
        let pool = BudgetPool::new(ResolvedDelegationBudget {
            max_rounds: Some(1),
            ..ResolvedDelegationBudget::unlimited()
        });
        pool.charge_round().unwrap();
        assert_eq!(pool.snapshot().spent.rounds, 1);
        let err = pool.preflight().unwrap_err();
        assert_eq!(err.dimension, BudgetDimension::Rounds);
        assert_eq!(
            pool.snapshot().spent.rounds,
            1,
            "preflight must not record the peeked round"
        );
        assert!(pool.charge_round().is_err());
        assert_eq!(pool.snapshot().spent.rounds, 1);
    }

    #[test]
    fn snapshot_render_surfaces_unlimited() {
        let pool = BudgetPool::unlimited();
        pool.charge_round().unwrap();
        let text = pool.snapshot().render();
        assert!(text.contains("unlimited"), "{text}");
        assert!(text.contains("unlimited spend"), "{text}");
    }

    #[test]
    fn remint_root_keeps_ledger_identity_and_spend() {
        let root = BudgetPool::new(ResolvedDelegationBudget {
            max_rounds: Some(2),
            ..ResolvedDelegationBudget::unlimited()
        });
        let in_flight = root.share();
        in_flight.charge_round().unwrap();
        assert_eq!(root.snapshot().spent.rounds, 1);
        root.remint_root(ResolvedDelegationBudget {
            max_rounds: Some(2),
            ..ResolvedDelegationBudget::unlimited()
        });
        assert!(root.shares_ledger_with(&in_flight));
        assert_eq!(
            in_flight.snapshot().spent.rounds,
            1,
            "remint must not forgive in-flight spend on the live ledger"
        );
        assert_eq!(
            in_flight.snapshot().local_spent.rounds,
            1,
            "remint must not rewind the reminted handle's local spend"
        );
        in_flight.charge_round().unwrap();
        assert!(in_flight.charge_round().is_err());
        assert_eq!(root.snapshot().spent.rounds, 2);
    }

    #[test]
    fn remint_root_lowering_ceiling_below_spent_exhausts() {
        let root = BudgetPool::new(ResolvedDelegationBudget {
            max_rounds: Some(4),
            ..ResolvedDelegationBudget::unlimited()
        });
        root.charge_round().unwrap();
        root.charge_round().unwrap();
        root.remint_root(ResolvedDelegationBudget {
            max_rounds: Some(1),
            ..ResolvedDelegationBudget::unlimited()
        });
        let err = root.charge_round().unwrap_err();
        assert_eq!(err.dimension, BudgetDimension::Rounds);
        assert_eq!(root.snapshot().spent.rounds, 2);
    }

    #[test]
    fn remint_root_does_not_widen_allotted_child_overlay() {
        let root = BudgetPool::new(ResolvedDelegationBudget {
            max_rounds: Some(8),
            ..ResolvedDelegationBudget::unlimited()
        });
        let child = root.allot(ResolvedDelegationBudget {
            max_rounds: Some(1),
            ..ResolvedDelegationBudget::unlimited()
        });
        root.remint_root(ResolvedDelegationBudget {
            max_rounds: Some(8),
            ..ResolvedDelegationBudget::unlimited()
        });
        assert!(root.shares_ledger_with(&child));
        child.charge_round().unwrap();
        assert!(
            child.charge_round().is_err(),
            "child overlay must survive a parent remint"
        );
        root.charge_round().unwrap();
        assert_eq!(root.snapshot().spent.rounds, 2);
    }

    #[test]
    fn remint_root_does_not_reset_allotted_child_local_spent() {
        let root = BudgetPool::new(ResolvedDelegationBudget {
            max_rounds: Some(8),
            ..ResolvedDelegationBudget::unlimited()
        });
        let child = root.allot(ResolvedDelegationBudget {
            max_rounds: Some(3),
            ..ResolvedDelegationBudget::unlimited()
        });
        child.charge_round().unwrap();
        child.charge_round().unwrap();
        root.remint_root(ResolvedDelegationBudget {
            max_rounds: Some(8),
            ..ResolvedDelegationBudget::unlimited()
        });
        assert_eq!(child.snapshot().local_spent.rounds, 2);
        child.charge_round().unwrap();
        assert!(child.charge_round().is_err());
        assert_eq!(root.snapshot().spent.rounds, 3);
        for _ in 0..5 {
            root.charge_round().unwrap();
        }
        assert!(root.charge_round().is_err());
        assert_eq!(root.snapshot().spent.rounds, 8);
    }

    #[test]
    fn unpriced_token_usage_exhausts_finite_cost_ceiling() {
        let pool = BudgetPool::new(ResolvedDelegationBudget {
            max_cost_microusd: Some(10_000_000),
            ..ResolvedDelegationBudget::unlimited()
        });
        let err = pool
            .charge_usage(TokenUsage {
                input_tokens: 8,
                output_tokens: 2,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            })
            .unwrap_err();
        assert_eq!(err.dimension, BudgetDimension::Cost);
        assert_eq!(pool.snapshot().spent.cost_microusd, 0);
        assert_eq!(pool.snapshot().spent.input_tokens, 0);
    }

    #[test]
    fn unpriced_usage_allowed_when_cost_is_unlimited() {
        let pool = BudgetPool::unlimited();
        pool.charge_usage(TokenUsage {
            input_tokens: 8,
            output_tokens: 2,
            cached_input_tokens: 0,
            cache_creation_input_tokens: 0,
        })
        .unwrap();
        assert_eq!(pool.snapshot().spent.cost_microusd, 0);
        assert_eq!(pool.snapshot().spent.input_tokens, 8);
        assert_eq!(pool.snapshot().spent.output_tokens, 2);
    }

    #[test]
    fn priced_zero_cost_does_not_exhaust_finite_cap() {
        let pool = BudgetPool::new(ResolvedDelegationBudget {
            max_cost_microusd: Some(10),
            ..ResolvedDelegationBudget::unlimited()
        });
        pool.charge(
            BudgetCharge::from_usage(TokenUsage {
                input_tokens: 4,
                ..TokenUsage::default()
            })
            .with_cost(0),
        )
        .unwrap();
        assert_eq!(pool.snapshot().spent.cost_microusd, 0);
        assert_eq!(pool.snapshot().spent.input_tokens, 4);
    }

    #[test]
    fn mixed_priced_and_unpriced_usage_fails_closed() {
        let pool = BudgetPool::new(ResolvedDelegationBudget {
            max_cost_microusd: Some(10_000_000),
            ..ResolvedDelegationBudget::unlimited()
        });
        let mut charge = BudgetCharge::from_usage(TokenUsage {
            input_tokens: 3,
            ..TokenUsage::default()
        })
        .with_cost(5);
        charge += BudgetCharge::from_usage(TokenUsage {
            input_tokens: 2,
            ..TokenUsage::default()
        });
        let err = pool.charge(charge).unwrap_err();
        assert_eq!(err.dimension, BudgetDimension::Cost);
        assert_eq!(pool.snapshot().spent.cost_microusd, 0);
        assert_eq!(pool.snapshot().spent.input_tokens, 0);
    }
}
