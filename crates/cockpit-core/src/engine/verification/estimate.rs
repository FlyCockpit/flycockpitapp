//! Conservative pre-collection estimate for a verification candidate set.
//!
//! Token counts come from the in-tree tokenizer when the model's encoding is
//! known, otherwise a chars/4 estimate with a safety margin. Assembled text
//! never yields [`crate::agents::VerificationEstimate::UnknownTokens`].
//! Cost uses the model catalog price when present; otherwise the estimate is
//! [`crate::agents::VerificationEstimate::UnknownPrice`], which still routes
//! to `onBudgetExceeded`.

use crate::agents::{VerificationBudget, VerificationEstimate};
use crate::tokens::{TokenizerStrategy, count_with};

/// Conservative inflation applied after the raw token count so the estimate
/// is at least the tokenizer's actual count on the same text.
const SAFETY_NUM: u64 = 5;
const SAFETY_DEN: u64 = 4;
const FALLBACK_CHARS_PER_TOKEN: u64 = 4;
const CONSERVATIVE_OUTPUT_TOKENS_PER_CANDIDATE: u64 = 512;

#[derive(Debug, Clone)]
pub struct CandidateSetEstimateInput<'a> {
    /// Assembled recipe contexts, one per candidate (or the original call
    /// when generators have not been declared yet).
    pub assembled_texts: &'a [String],
    pub encoding: Option<TokenizerStrategy>,
    /// Dollars per million input tokens from the model catalog.
    pub input_price_per_mtok: Option<f64>,
    /// Dollars per million output tokens from the model catalog.
    pub output_price_per_mtok: Option<f64>,
    pub max_candidates: u16,
    pub max_collection_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreCollectionEstimate {
    pub tokens: u64,
    pub cost_microusd: Option<u64>,
    pub candidates: u16,
    pub collection_millis: u64,
}

impl PreCollectionEstimate {
    pub fn to_verification_estimate(self) -> VerificationEstimate {
        match self.cost_microusd {
            Some(cost) => VerificationEstimate::Known(VerificationBudget {
                max_candidates: self.candidates,
                max_total_tokens: self.tokens,
                max_estimated_cost_microusd: cost,
                max_collection_millis: self.collection_millis,
            }),
            None => VerificationEstimate::UnknownPrice,
        }
    }
}

/// Conservative token count for assembled text. Never returns zero for
/// non-empty input; the safety margin guarantees `estimate >= tokenizer count`
/// when the encoding is known, and `estimate >= ceil(chars/4)` otherwise.
pub fn estimate_tokens(text: &str, encoding: Option<TokenizerStrategy>) -> u64 {
    if text.is_empty() {
        return 0;
    }
    let raw = match encoding {
        Some(strategy) => count_with(text, strategy) as u64,
        None => (text.len() as u64)
            .div_ceil(FALLBACK_CHARS_PER_TOKEN)
            .max(1),
    };
    raw.saturating_mul(SAFETY_NUM).div_ceil(SAFETY_DEN)
}

pub fn estimate_candidate_set(input: CandidateSetEstimateInput<'_>) -> PreCollectionEstimate {
    let mut tokens = 0_u64;
    for text in input.assembled_texts {
        tokens = tokens.saturating_add(estimate_tokens(text, input.encoding));
    }
    tokens = tokens.saturating_add(
        u64::from(input.max_candidates.max(1)) * CONSERVATIVE_OUTPUT_TOKENS_PER_CANDIDATE,
    );
    let cost_microusd = match (input.input_price_per_mtok, input.output_price_per_mtok) {
        (Some(input_price), Some(output_price)) if input_price >= 0.0 && output_price >= 0.0 => {
            let output_tokens =
                u64::from(input.max_candidates.max(1)) * CONSERVATIVE_OUTPUT_TOKENS_PER_CANDIDATE;
            let input_tokens = tokens.saturating_sub(output_tokens);
            Some(cost_microusd(
                input_tokens,
                input_price,
                output_tokens,
                output_price,
            ))
        }
        (Some(input_price), None) if input_price >= 0.0 => {
            Some(cost_microusd(tokens, input_price, 0, 0.0))
        }
        _ => None,
    };
    PreCollectionEstimate {
        tokens,
        cost_microusd,
        candidates: input.max_candidates.max(1),
        collection_millis: input.max_collection_millis,
    }
}

fn cost_microusd(
    input_tokens: u64,
    input_price_per_mtok: f64,
    output_tokens: u64,
    output_price_per_mtok: f64,
) -> u64 {
    // microusd = tokens * dollars_per_mtok, because
    // dollars = tokens / 1e6 * price_per_mtok and microusd = dollars * 1e6.
    let value = (input_tokens as f64) * input_price_per_mtok
        + (output_tokens as f64) * output_price_per_mtok;
    value.ceil().max(0.0) as u64
}

/// Best-effort encoding for a model id. `None` selects the chars/4 fallback.
pub fn encoding_for_model_id(model_id: &str) -> Option<TokenizerStrategy> {
    let id = model_id.to_ascii_lowercase();
    if id.contains("gpt-4o")
        || id.contains("gpt-5")
        || id.contains("o1")
        || id.contains("o3")
        || id.contains("o4")
    {
        Some(TokenizerStrategy::O200k)
    } else if id.contains("gpt")
        || id.contains("claude")
        || id.contains("llama")
        || id.contains("mistral")
        || id.contains("qwen")
    {
        Some(TokenizerStrategy::Cl100k)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{
        ExecutionKind, ModelCapability, ModelLocality, ModelSlot, OnBudgetExceeded,
        SelectorPredicate, ToolClass, VerificationAction, VerificationDispatch, VerificationPolicy,
        VerificationRule, VerificationSelector, VnextAgentDef, VnextHostPolicy,
    };
    use std::collections::BTreeMap;

    #[test]
    fn estimate_is_at_least_tokenizer_count_on_fixtures() {
        let fixtures = [
            "fn main() {}\n",
            "the quick brown fox jumps over the lazy dog",
            &"abcdefghijklmnopqrstuvwxyz\n".repeat(40),
        ];
        for text in fixtures {
            let actual = count_with(text, TokenizerStrategy::Cl100k) as u64;
            let estimated = estimate_tokens(text, Some(TokenizerStrategy::Cl100k));
            assert!(
                estimated >= actual,
                "estimate {estimated} < actual {actual} for {text:?}"
            );
        }
    }

    #[test]
    fn chars_fallback_never_returns_unknown_tokens() {
        let text = "assembled recipe context";
        let estimated = estimate_tokens(text, None);
        assert!(estimated >= (text.len() as u64).div_ceil(4));
        let set = estimate_candidate_set(CandidateSetEstimateInput {
            assembled_texts: &[text.to_string()],
            encoding: None,
            input_price_per_mtok: None,
            output_price_per_mtok: None,
            max_candidates: 1,
            max_collection_millis: 1_000,
        });
        assert!(matches!(
            set.to_verification_estimate(),
            VerificationEstimate::UnknownPrice
        ));
        assert!(set.tokens > 0);
    }

    #[test]
    fn known_price_produces_known_estimate() {
        let text = "fn main() { println!(\"hi\"); }\n";
        let set = estimate_candidate_set(CandidateSetEstimateInput {
            assembled_texts: &[text.to_string()],
            encoding: Some(TokenizerStrategy::Cl100k),
            input_price_per_mtok: Some(3.0),
            output_price_per_mtok: Some(15.0),
            max_candidates: 2,
            max_collection_millis: 800,
        });
        match set.to_verification_estimate() {
            VerificationEstimate::Known(budget) => {
                assert!(budget.max_total_tokens >= set.tokens);
                assert!(budget.max_estimated_cost_microusd > 0);
                assert_eq!(budget.max_candidates, 2);
            }
            other => panic!("expected Known, got {other:?}"),
        }
    }

    fn routing_definition(on_budget: OnBudgetExceeded) -> VnextAgentDef {
        VnextAgentDef {
            schema_version: crate::agents::SCHEMA_VERSION,
            agent_id: "authored/reviewer".to_string(),
            execution_kind: ExecutionKind::Coding,
            model_slots: BTreeMap::from([(
                "primary".to_string(),
                ModelSlot {
                    purpose: "primary".to_string(),
                    min_context_tokens: 1,
                    required_capabilities: vec![ModelCapability::TextGeneration],
                    locality: ModelLocality::Any,
                    allow_default_fallback: false,
                    suggested_models: vec![],
                },
            )]),
            delegation: crate::agents::DelegationPolicy::default(),
            questions: None,
            verification: Some(VerificationPolicy {
                rules: vec![VerificationRule {
                    selector: VerificationSelector {
                        all_of: vec![SelectorPredicate::ToolClass {
                            tool_class: ToolClass::ArtifactWrite,
                        }],
                        any_of: vec![],
                    },
                    action: VerificationAction::Verify,
                    max_candidates: Some(1),
                    max_total_tokens: Some(10),
                    max_estimated_cost_microusd: Some(10),
                    max_collection_millis: Some(10),
                    adjudicator_slot: Some("primary".into()),
                    on_budget_exceeded: Some(on_budget),
                    ..Default::default()
                }],
            }),
        }
    }

    #[test]
    fn refuse_vs_dispatch_original_routing() {
        let host = VnextHostPolicy::for_session_config(
            &crate::config::extended::ExtendedConfig::default(),
        );
        let subject = crate::agents::VerificationSubject {
            tool_class: ToolClass::ArtifactWrite,
            tool_id: "edit",
            namespace: "host",
        };
        let over = VerificationEstimate::Known(VerificationBudget {
            max_candidates: 1,
            max_total_tokens: 11,
            max_estimated_cost_microusd: 1,
            max_collection_millis: 1,
        });
        assert_eq!(
            routing_definition(OnBudgetExceeded::Refuse)
                .resolve_verification(&host, &subject, None, over.clone())
                .unwrap(),
            VerificationDispatch::Refuse
        );
        assert_eq!(
            routing_definition(OnBudgetExceeded::DispatchOriginal)
                .resolve_verification(&host, &subject, None, over)
                .unwrap(),
            VerificationDispatch::DispatchOriginal
        );
        assert_eq!(
            routing_definition(OnBudgetExceeded::Refuse)
                .resolve_verification(&host, &subject, None, VerificationEstimate::UnknownPrice,)
                .unwrap(),
            VerificationDispatch::Refuse
        );
    }
}
