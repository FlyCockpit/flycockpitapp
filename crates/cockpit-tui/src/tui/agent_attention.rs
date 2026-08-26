//! Deterministic ordering for the agent-tree attention surface (modes AC4/AC5).
//!
//! The daemon owns each decision's class/state; the TUI only *orders* the
//! `AgentDecisionAttention` rows it is given, and does so deterministically so
//! a re-fetch on `AgentTreeChanged` never reshuffles the list. Pending rows
//! sort above answered ones: critical (host) approvals are pinned at the top,
//! then timed questions by ascending deadline, then the remaining non-auto
//! questions; resolved rows sink to the bottom, newest-resolved first.

use std::cmp::Ordering;

use cockpit_proto::AgentDecisionAttention;

/// Daemon `DecisionClass::HostApproval` wire spelling. Host approvals are the
/// critical, always-manual class pinned at the top of the pending list.
const DECISION_CLASS_HOST_APPROVAL: &str = "host_approval";

/// Attention tiers, most urgent first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    /// Pending critical (host) approval — pinned above everything else.
    CriticalApproval,
    /// Pending question with a decision deadline — sorted soonest-first.
    Timed,
    /// Pending manual question with no deadline.
    Question,
    /// Answered/resolved — sinks below all pending rows.
    Resolved,
}

fn tier_rank(tier: Tier) -> u8 {
    match tier {
        Tier::CriticalApproval => 0,
        Tier::Timed => 1,
        Tier::Question => 2,
        Tier::Resolved => 3,
    }
}

fn tier_of(entry: &AgentDecisionAttention) -> Tier {
    if entry.resolved_at_unix_ms.is_some() {
        Tier::Resolved
    } else if entry.decision_class == DECISION_CLASS_HOST_APPROVAL {
        Tier::CriticalApproval
    } else if entry.deadline_unix_ms.is_some() {
        Tier::Timed
    } else {
        Tier::Question
    }
}

fn within_tier(
    tier: Tier,
    a: &AgentDecisionAttention,
    b: &AgentDecisionAttention,
) -> Ordering {
    match tier {
        // Newest-resolved first.
        Tier::Resolved => b.resolved_at_unix_ms.cmp(&a.resolved_at_unix_ms),
        // Soonest deadline first; a deadline-bearing row precedes a
        // deadline-less one, then fall back to when it was raised.
        Tier::CriticalApproval | Tier::Timed => match (a.deadline_unix_ms, b.deadline_unix_ms) {
            (Some(da), Some(db)) => da.cmp(&db),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => a.raised_at_unix_ms.cmp(&b.raised_at_unix_ms),
        },
        // Oldest-raised first, so the longest-waiting question is answered next.
        Tier::Question => a.raised_at_unix_ms.cmp(&b.raised_at_unix_ms),
    }
}

/// Return `entries` reordered for display. Total and deterministic: equal keys
/// break ties on `attention_id`, so the same input always yields the same
/// order regardless of the daemon's page order.
pub(crate) fn order_attention(entries: &[AgentDecisionAttention]) -> Vec<AgentDecisionAttention> {
    let mut ordered = entries.to_vec();
    ordered.sort_by(|a, b| {
        let (ta, tb) = (tier_of(a), tier_of(b));
        tier_rank(ta)
            .cmp(&tier_rank(tb))
            .then_with(|| within_tier(ta, a, b))
            .then_with(|| a.attention_id.cmp(&b.attention_id))
    });
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn attn(
        id: u128,
        class: &str,
        deadline: Option<i64>,
        raised: i64,
        resolved: Option<i64>,
    ) -> AgentDecisionAttention {
        AgentDecisionAttention {
            attention_id: Uuid::from_u128(id),
            decision_request_id: Uuid::from_u128(id),
            agent_instance_id: Uuid::from_u128(1),
            state: "waiting".to_string(),
            decision_state: if resolved.is_some() { "resolved" } else { "pending" }.to_string(),
            decision_class: class.to_string(),
            task_call_id: None,
            workspace_ref: None,
            options_contract_json: "{}".to_string(),
            free_text_contract_json: None,
            recommendation_json: None,
            deadline_unix_ms: deadline,
            revision: 1,
            raised_at_unix_ms: raised,
            resolved_at_unix_ms: resolved,
        }
    }

    fn order_ids(entries: &[AgentDecisionAttention]) -> Vec<u128> {
        order_attention(entries)
            .into_iter()
            .map(|entry| entry.attention_id.as_u128())
            .collect()
    }

    #[test]
    fn modes_session_setup_attention_pending_above_answered_with_tiering() {
        let entries = vec![
            // resolved (should sink to bottom, newest-resolved first)
            attn(10, "user_question", None, 100, Some(500)),
            attn(11, "user_question", None, 100, Some(900)),
            // non-auto question (no deadline)
            attn(20, "user_question", None, 300, None),
            // timed question
            attn(30, "user_question", Some(2000), 200, None),
            attn(31, "user_question", Some(1000), 250, None),
            // critical approval (pinned top)
            attn(40, "host_approval", None, 400, None),
        ];
        assert_eq!(
            order_ids(&entries),
            vec![
                40, // critical approval pinned
                31, 30, // timed questions, deadline ascending (1000 before 2000)
                20, // non-auto question
                11, 10, // resolved newest-first (900 before 500)
            ]
        );
    }

    #[test]
    fn modes_session_setup_attention_ordering_is_deterministic_regardless_of_input_order() {
        let a = attn(1, "user_question", Some(1000), 10, None);
        let b = attn(2, "host_approval", None, 20, None);
        let c = attn(3, "user_question", None, 30, None);
        let forward = order_ids(&[a.clone(), b.clone(), c.clone()]);
        let reversed = order_ids(&[c, b, a]);
        assert_eq!(forward, reversed, "order must not depend on daemon page order");
        assert_eq!(forward, vec![2, 1, 3]);
    }

    #[test]
    fn modes_session_setup_attention_equal_keys_break_ties_on_id() {
        // Two pending questions raised at the same instant: stable by id.
        let entries = vec![
            attn(7, "user_question", None, 100, None),
            attn(5, "user_question", None, 100, None),
        ];
        assert_eq!(order_ids(&entries), vec![5, 7]);
    }
}
