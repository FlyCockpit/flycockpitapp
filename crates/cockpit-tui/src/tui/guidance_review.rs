//! Computer-use guidance proposal review dialog for the TUI (issue #59, AC8).
//!
//! Renders a pending proposal's typed rule kinds and the optional rationale as
//! **inert plain text** (`textContent` semantics: no HTML, no Markdown, no URL
//! auto-link, no rich text), and dispatches the three review actions: reject,
//! accept session, accept persistent.
//!
//! ## Scope boundary
//!
//! The typed rules are displayed as code-owned kind labels only — never the
//! raw rationale bytes are interpreted as markup. Accepting/rejecting crosses
//! a daemon RPC (the [`GuidanceProposalService`] owns the durable CAS + audit
//! + rule install). The production dispatcher wiring over the daemon wire
//! protocol is transport work deferred past the local launch scope; until it
//! lands the action handlers are stubbed with `TODO` and the review surface is
//! inert. The pure presentation + action-routing logic here is unit-tested so
//! the UI contract (text-only rationale; three action paths) is locked in.
//!
//! [`GuidanceProposalService`]: cockpit_core::computer::guidance::service::GuidanceProposalService

use cockpit_core::computer::guidance::{ComputerGuidanceRuleV1, RuleKind};

/// A pending proposal presented to the reviewer. The rationale is the already
/// normalized inert plaintext (see
/// `cockpit_core::computer::guidance::normalize_rationale`); it is rendered
/// verbatim with no markup interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuidanceReviewProposal {
    pub proposal_id: [u8; 16],
    pub rules: Vec<ComputerGuidanceRuleV1>,
    pub rationale: Option<String>,
}

/// The three review actions (AC8). `AcceptPersistent` is offered only when
/// enablement and authority allow it (the caller gates availability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuidanceReviewAction {
    Reject,
    AcceptSession,
    AcceptPersistent,
}

impl GuidanceReviewAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Reject => "Reject",
            Self::AcceptSession => "Accept (session)",
            Self::AcceptPersistent => "Accept (persistent)",
        }
    }
}

/// The outcome of applying a review action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewOutcome {
    Rejected,
    AcceptedSession { installed: Vec<ComputerGuidanceRuleV1> },
    AcceptedPersistent { installed: Vec<ComputerGuidanceRuleV1> },
    /// The dispatcher was unavailable (stub/transport not yet wired).
    Unavailable(String),
}

/// Dispatches review actions to the daemon's `GuidanceProposalService`.
///
/// The production implementation crosses a daemon RPC (deferred transport
/// work); tests inject a recording implementation.
pub trait GuidanceReviewDispatcher {
    fn reject(&self, proposal_id: &[u8; 16]) -> anyhow::Result<()>;
    fn accept_session(
        &self,
        proposal_id: &[u8; 16],
    ) -> anyhow::Result<Vec<ComputerGuidanceRuleV1>>;
    fn accept_persistent(
        &self,
        proposal_id: &[u8; 16],
    ) -> anyhow::Result<Vec<ComputerGuidanceRuleV1>>;
}

/// A code-owned label for a rule kind, for display only.
pub fn rule_kind_label(kind: RuleKind) -> &'static str {
    match kind {
        RuleKind::ObservationCadence => "observation cadence",
        RuleKind::PointerVerification => "pointer verification",
        RuleKind::FreshDossier => "fresh dossier",
        RuleKind::UnexpectedStateStop => "unexpected state stop",
        RuleKind::MaxReversibleBatch => "max reversible batch",
        RuleKind::ProviderWorkaround => "provider workaround",
    }
}

/// Render the review dialog as plain display lines. The rationale is rendered
/// verbatim with `textContent` semantics — no HTML/Markdown/URL auto-link/rich
/// text. Rule kinds appear as code-owned labels only.
pub fn render_review_lines(proposal: &GuidanceReviewProposal) -> Vec<String> {
    let mut out = Vec::new();
    out.push("Computer-use guidance proposal for review".to_string());
    out.push(String::new());
    out.push("Proposed rules:".to_string());
    for rule in &proposal.rules {
        out.push(format!("  - {}", rule_kind_label(rule.kind())));
    }
    out.push(String::new());
    match &proposal.rationale {
        Some(text) => {
            out.push("Rationale (plain text):".to_string());
            // Verbatim plaintext — no markup interpretation. Each line is
            // rendered as-is so no HTML/Markdown/URL auto-link can activate.
            for line in text.split('\n') {
                out.push(format!("  {line}"));
            }
        }
        None => out.push("Rationale: (none)".to_string()),
    }
    out.push(String::new());
    out.push("Actions: [r] reject  [s] accept session  [p] accept persistent".to_string());
    out
}

/// Apply a review action via the dispatcher, returning the routed outcome.
/// `AcceptPersistent` is only offered when the caller has already confirmed
/// enablement + authority allow it.
pub fn apply_review_action(
    proposal: &GuidanceReviewProposal,
    action: GuidanceReviewAction,
    dispatcher: &dyn GuidanceReviewDispatcher,
) -> ReviewOutcome {
    match action {
        GuidanceReviewAction::Reject => match dispatcher.reject(&proposal.proposal_id) {
            Ok(()) => ReviewOutcome::Rejected,
            Err(e) => ReviewOutcome::Unavailable(e.to_string()),
        },
        GuidanceReviewAction::AcceptSession => {
            match dispatcher.accept_session(&proposal.proposal_id) {
                Ok(installed) => ReviewOutcome::AcceptedSession { installed },
                Err(e) => ReviewOutcome::Unavailable(e.to_string()),
            }
        }
        GuidanceReviewAction::AcceptPersistent => {
            match dispatcher.accept_persistent(&proposal.proposal_id) {
                Ok(installed) => ReviewOutcome::AcceptedPersistent { installed },
                Err(e) => ReviewOutcome::Unavailable(e.to_string()),
            }
        }
    }
}

/// TODO(daemon-rpc): production dispatcher over the daemon wire protocol.
/// Until the proposal-review RPCs land (deferred transport work past the local
/// launch scope), the review surface is inert. This stub returns an
/// unavailable outcome so the UI never silently mutates durable state.
#[derive(Debug, Default)]
pub struct StubGuidanceReviewDispatcher;

impl GuidanceReviewDispatcher for StubGuidanceReviewDispatcher {
    fn reject(&self, _proposal_id: &[u8; 16]) -> anyhow::Result<()> {
        Err(anyhow::anyhow!(
            "guidance proposal review RPC not yet wired (deferred transport work)"
        ))
    }
    fn accept_session(
        &self,
        _proposal_id: &[u8; 16],
    ) -> anyhow::Result<Vec<ComputerGuidanceRuleV1>> {
        Err(anyhow::anyhow!(
            "guidance proposal review RPC not yet wired (deferred transport work)"
        ))
    }
    fn accept_persistent(
        &self,
        _proposal_id: &[u8; 16],
    ) -> anyhow::Result<Vec<ComputerGuidanceRuleV1>> {
        Err(anyhow::anyhow!(
            "guidance proposal review RPC not yet wired (deferred transport work)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_core::computer::guidance::{ObservationCadence, PointerVerification};
    use std::sync::Mutex;

    fn proposal(rationale: Option<&str>) -> GuidanceReviewProposal {
        GuidanceReviewProposal {
            proposal_id: [9; 16],
            rules: vec![
                ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction),
                ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 2 },
            ],
            rationale: rationale.map(|s| s.to_string()),
        }
    }

    /// AC8: rationale is rendered as inert plain text — HTML/Markdown/URL
    /// markers appear verbatim and are NEVER interpreted as markup.
    #[test]
    fn rationale_is_text_only_with_no_markup_interpretation() {
        let rationale = "See <script>alert(1)</script> and [link](https://x) and https://y";
        let p = proposal(Some(rationale));
        let lines = render_review_lines(&p);
        let rendered = lines.join("\n");
        // The raw markup bytes appear verbatim — no stripping, no auto-link,
        // no rich-text rendering. textContent semantics: the string is data.
        assert!(rendered.contains("<script>alert(1)</script>"));
        assert!(rendered.contains("[link](https://x)"));
        assert!(rendered.contains("https://y"));
        // No markdown rendering artifacts (e.g. rendered link text only).
        assert!(!rendered.contains("alert(1)\u{200b}"));
    }

    #[test]
    fn rationale_none_renders_placeholder() {
        let p = proposal(None);
        let lines = render_review_lines(&p);
        assert!(lines.iter().any(|l| l.contains("(none)")));
    }

    /// AC8: rule kinds appear as code-owned labels.
    #[test]
    fn rule_kinds_render_as_code_owned_labels() {
        let p = proposal(None);
        let lines = render_review_lines(&p);
        assert!(lines.iter().any(|l| l.contains("observation cadence")));
        assert!(lines.iter().any(|l| l.contains("max reversible batch")));
    }

    /// A recording dispatcher for the three action-path tests.
    struct Recording {
        rejects: Mutex<Vec<[u8; 16]>>,
        sessions: Mutex<Vec<[u8; 16]>>,
        persistents: Mutex<Vec<[u8; 16]>>,
    }
    impl GuidanceReviewDispatcher for Recording {
        fn reject(&self, id: &[u8; 16]) -> anyhow::Result<()> {
            self.rejects.lock().unwrap().push(*id);
            Ok(())
        }
        fn accept_session(
            &self,
            id: &[u8; 16],
        ) -> anyhow::Result<Vec<ComputerGuidanceRuleV1>> {
            self.sessions.lock().unwrap().push(*id);
            Ok(vec![ComputerGuidanceRuleV1::PointerVerification(
                PointerVerification::BeforeEveryPointerAction,
            )])
        }
        fn accept_persistent(
            &self,
            id: &[u8; 16],
        ) -> anyhow::Result<Vec<ComputerGuidanceRuleV1>> {
            self.persistents.lock().unwrap().push(*id);
            Ok(vec![ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 4 }])
        }
    }

    fn recording() -> Recording {
        Recording {
            rejects: Mutex::new(vec![]),
            sessions: Mutex::new(vec![]),
            persistents: Mutex::new(vec![]),
        }
    }

    #[test]
    fn reject_path_dispatches_reject() {
        let p = proposal(None);
        let d = recording();
        let outcome = apply_review_action(&p, GuidanceReviewAction::Reject, &d);
        assert_eq!(outcome, ReviewOutcome::Rejected);
        assert_eq!(d.rejects.lock().unwrap().len(), 1);
        assert!(d.sessions.lock().unwrap().is_empty());
        assert!(d.persistents.lock().unwrap().is_empty());
    }

    #[test]
    fn accept_session_path_returns_installed_rules() {
        let p = proposal(None);
        let d = recording();
        let outcome = apply_review_action(&p, GuidanceReviewAction::AcceptSession, &d);
        match outcome {
            ReviewOutcome::AcceptedSession { installed } => {
                assert_eq!(installed.len(), 1);
                assert_eq!(
                    installed[0],
                    ComputerGuidanceRuleV1::PointerVerification(
                        PointerVerification::BeforeEveryPointerAction
                    )
                );
            }
            other => panic!("expected AcceptedSession, got {other:?}"),
        }
        assert_eq!(d.sessions.lock().unwrap().len(), 1);
    }

    #[test]
    fn accept_persistent_path_returns_installed_rules() {
        let p = proposal(None);
        let d = recording();
        let outcome = apply_review_action(&p, GuidanceReviewAction::AcceptPersistent, &d);
        match outcome {
            ReviewOutcome::AcceptedPersistent { installed } => {
                assert_eq!(installed.len(), 1);
                assert_eq!(
                    installed[0],
                    ComputerGuidanceRuleV1::MaxReversibleBatch { max_actions: 4 }
                );
            }
            other => panic!("expected AcceptedPersistent, got {other:?}"),
        }
        assert_eq!(d.persistents.lock().unwrap().len(), 1);
    }

    #[test]
    fn stub_dispatcher_is_inert() {
        let p = proposal(None);
        let stub = StubGuidanceReviewDispatcher;
        let outcome = apply_review_action(&p, GuidanceReviewAction::Reject, &stub);
        assert!(matches!(outcome, ReviewOutcome::Unavailable(_)));
    }
}
