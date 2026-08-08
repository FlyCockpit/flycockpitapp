//! Centralized clipboard feedback classification.
//!
//! Every copy call site (context-menu actions, `/copy`, selection copy,
//! rich-text copy) independently needed to answer the same question from a
//! [`DeliveryResult`]: was it confirmed, unverified, failed, and did a rich
//! request quietly downgrade to plain? Before this module each call site
//! re-derived that from `result.confidence`/`result.downgrade` inline;
//! [`classify`] is the one place that decision is made, so a future new
//! outcome (or a bug in reading `confidence`/`downgrade`) has exactly one
//! call site to fix instead of four.

use super::types::{Confidence, DeliveryResult};

/// The confirmed/unverified/failed/rich-downgrade classification of one
/// [`DeliveryResult`], for callers building user-facing feedback. Exact
/// wording stays with the caller (it is inherently contextual — "last
/// response" vs. a message title vs. a character count) — this centralizes
/// only the classification every call site needs to agree on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedbackOutcome {
    pub confidence: Confidence,
    /// `true` when a rich request explicitly downgraded to plain text
    /// (`Downgrade::RichToPlain`) — independent of `confidence`: the
    /// downgraded plain delivery can itself be Confirmed, Unverified, or
    /// (rarely, if every plain route also failed) Failed.
    pub downgraded: bool,
}

impl FeedbackOutcome {
    pub fn is_confirmed(self) -> bool {
        matches!(self.confidence, Confidence::Confirmed)
    }

    pub fn is_unverified(self) -> bool {
        matches!(self.confidence, Confidence::Unverified)
    }

    pub fn is_failed(self) -> bool {
        matches!(self.confidence, Confidence::Failed)
    }
}

/// Classify a delivery result for feedback purposes.
pub fn classify(result: &DeliveryResult) -> FeedbackOutcome {
    FeedbackOutcome {
        confidence: result.confidence,
        downgraded: result.downgrade.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::types::{AttemptRecord, Downgrade, Representation};

    fn result(confidence: Confidence, downgrade: Option<Downgrade>) -> DeliveryResult {
        DeliveryResult {
            attempts: Vec::<AttemptRecord>::new(),
            requested_representation: Representation::Plain,
            delivered_representation: Representation::Plain,
            downgrade,
            confidence,
        }
    }

    #[test]
    fn confirmed_without_downgrade() {
        let outcome = classify(&result(Confidence::Confirmed, None));
        assert!(outcome.is_confirmed());
        assert!(!outcome.downgraded);
    }

    #[test]
    fn confirmed_with_rich_to_plain_downgrade() {
        let outcome = classify(&result(Confidence::Confirmed, Some(Downgrade::RichToPlain)));
        assert!(outcome.is_confirmed());
        assert!(outcome.downgraded);
    }

    #[test]
    fn unverified_without_downgrade() {
        let outcome = classify(&result(Confidence::Unverified, None));
        assert!(outcome.is_unverified());
        assert!(!outcome.downgraded);
    }

    #[test]
    fn unverified_with_rich_to_plain_downgrade() {
        let outcome = classify(&result(
            Confidence::Unverified,
            Some(Downgrade::RichToPlain),
        ));
        assert!(outcome.is_unverified());
        assert!(outcome.downgraded);
    }

    #[test]
    fn failed_without_downgrade() {
        let outcome = classify(&result(Confidence::Failed, None));
        assert!(outcome.is_failed());
        assert!(!outcome.downgraded);
    }

    #[test]
    fn failed_after_a_downgrade_whose_plain_chain_also_failed() {
        let outcome = classify(&result(Confidence::Failed, Some(Downgrade::RichToPlain)));
        assert!(outcome.is_failed());
        assert!(outcome.downgraded);
    }
}
