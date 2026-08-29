//! Single conversion between [`crate::agents::VerificationBudget`] and the
//! verification ledger's operation columns. The two layers share no type;
//! every production path must go through these helpers so the columns cannot
//! drift from the policy budget.

use crate::agents::VerificationBudget;

/// Ledger-column view of a [`VerificationBudget`]. Counts and ceilings are
/// stored as `i64` (SQLite) and saturating-clamped from the policy `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerVerificationBudget {
    pub candidate_count: i64,
    pub total_token_ceiling: i64,
    pub estimated_cost_ceiling_microunits: i64,
    pub collection_duration_ms: i64,
}

pub fn budget_to_ledger(budget: VerificationBudget) -> LedgerVerificationBudget {
    LedgerVerificationBudget {
        candidate_count: i64::from(budget.max_candidates),
        total_token_ceiling: u64_to_ledger_i64(budget.max_total_tokens),
        estimated_cost_ceiling_microunits: u64_to_ledger_i64(budget.max_estimated_cost_microusd),
        collection_duration_ms: u64_to_ledger_i64(budget.max_collection_millis),
    }
}

pub fn ledger_to_budget(ledger: LedgerVerificationBudget) -> VerificationBudget {
    VerificationBudget {
        max_candidates: u16::try_from(ledger.candidate_count.max(0)).unwrap_or(u16::MAX),
        max_total_tokens: ledger.total_token_ceiling.max(0) as u64,
        max_estimated_cost_microusd: ledger.estimated_cost_ceiling_microunits.max(0) as u64,
        max_collection_millis: ledger.collection_duration_ms.max(0) as u64,
    }
}

pub(crate) fn u64_to_ledger_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_ledger_round_trip_preserves_finite_values() {
        let budget = VerificationBudget {
            max_candidates: 3,
            max_total_tokens: 12_000,
            max_estimated_cost_microusd: 4_000,
            max_collection_millis: 1_500,
        };
        assert_eq!(ledger_to_budget(budget_to_ledger(budget)), budget);
    }

    #[test]
    fn reduce_is_monotonic_and_rejects_widening() {
        let host = VerificationBudget {
            max_candidates: 5,
            max_total_tokens: 10_000,
            max_estimated_cost_microusd: 8_000,
            max_collection_millis: 2_000,
        };
        let session = VerificationBudget {
            max_candidates: 2,
            max_total_tokens: 1_000,
            max_estimated_cost_microusd: 500,
            max_collection_millis: 250,
        };
        let reduced = host.reduce(session).expect("reduction is allowed");
        assert_eq!(reduced, session);
        assert!(host.contains(reduced));
        let widened = VerificationBudget {
            max_candidates: 6,
            ..session
        };
        assert!(host.reduce(widened).is_err());
    }
}
