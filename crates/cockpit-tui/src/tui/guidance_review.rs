//! Computer-use guidance proposal review dialog for the TUI (issue #59, AC8).
//!
//! Renders a pending proposal's typed rule kinds and the optional rationale as
//! **inert plain text** (`textContent` semantics: no HTML, no Markdown, no URL
//! auto-link, no rich text), and dispatches the three review actions: reject,
//! accept session, accept persistent.
//!
//! The typed rules are displayed as code-owned kind labels only. Review crosses
//! the owner-only daemon RPC; a successful list response is therefore also the
//! UI's authority proof for exposing mutation keys.
//!
//! [`GuidanceProposalService`]: cockpit_core::computer::guidance::service::GuidanceProposalService

use cockpit_core::computer::guidance::{ComputerGuidanceRuleV1, RuleKind};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use std::sync::{Arc, Mutex};

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
    AcceptedSession {
        installed: Vec<ComputerGuidanceRuleV1>,
    },
    AcceptedPersistent {
        installed: Vec<ComputerGuidanceRuleV1>,
    },
    /// The dispatcher was unavailable (stub/transport not yet wired).
    Unavailable(String),
}

/// Dispatches review actions to the daemon's `GuidanceProposalService`.
///
/// The production implementation crosses a daemon RPC (deferred transport
/// work); tests inject a recording implementation.
pub trait GuidanceReviewDispatcher {
    fn reject(&self, proposal_id: &[u8; 16]) -> anyhow::Result<()>;
    fn accept_session(&self, proposal_id: &[u8; 16])
    -> anyhow::Result<Vec<ComputerGuidanceRuleV1>>;
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

pub struct DaemonGuidanceReviewDispatcher {
    client: cockpit_client::DaemonClient,
}

type LoadResult = Result<Vec<GuidanceReviewProposal>, String>;

/// Reachable `/guidance` review overlay. Network work is performed off the
/// reducer thread and each successful mutation refreshes the authoritative
/// daemon list before another action can be taken.
pub struct GuidanceReviewPane {
    lifecycle: cockpit_client::LifecycleClient,
    proposals: Vec<GuidanceReviewProposal>,
    selected: usize,
    owner_authorized: bool,
    status: String,
    pending: Arc<Mutex<Option<LoadResult>>>,
    busy: bool,
    redraw: Arc<tokio::sync::Notify>,
}

impl GuidanceReviewPane {
    pub fn open(
        lifecycle: cockpit_client::LifecycleClient,
        redraw: Arc<tokio::sync::Notify>,
    ) -> Self {
        let mut pane = Self {
            lifecycle,
            proposals: Vec::new(),
            selected: 0,
            owner_authorized: false,
            status: "Loading pending proposals…".into(),
            pending: Arc::new(Mutex::new(None)),
            busy: false,
            redraw,
        };
        pane.refresh();
        pane
    }

    fn refresh(&mut self) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.owner_authorized = false;
        self.status = "Loading pending proposals…".into();
        let lifecycle = self.lifecycle.clone();
        let slot = self.pending.clone();
        let redraw = self.redraw.clone();
        tokio::spawn(async move {
            let result = async {
                let client = crate::tui::settings::settings_daemon_client(&lifecycle).await?;
                DaemonGuidanceReviewDispatcher::new(client).list().await
            }
            .await
            .map_err(|error| error.to_string());
            *slot.lock().expect("guidance result lock") = Some(result);
            redraw.notify_one();
        });
    }

    fn review(&mut self, decision: cockpit_proto::GuidanceProposalDecision) {
        if self.busy || !self.owner_authorized {
            return;
        }
        let Some(proposal) = self.proposals.get(self.selected) else {
            return;
        };
        self.busy = true;
        self.owner_authorized = false;
        self.status = "Applying review decision…".into();
        let proposal_id = proposal.proposal_id;
        let lifecycle = self.lifecycle.clone();
        let slot = self.pending.clone();
        let redraw = self.redraw.clone();
        tokio::spawn(async move {
            let result = async {
                let client = crate::tui::settings::settings_daemon_client(&lifecycle).await?;
                let dispatcher = DaemonGuidanceReviewDispatcher::new(client);
                dispatcher.review(proposal_id, decision).await?;
                dispatcher.list().await
            }
            .await
            .map_err(|error| error.to_string());
            *slot.lock().expect("guidance result lock") = Some(result);
            redraw.notify_one();
        });
    }

    fn poll(&mut self) {
        let result = self.pending.lock().expect("guidance result lock").take();
        let Some(result) = result else {
            return;
        };
        self.busy = false;
        match result {
            Ok(proposals) => {
                self.proposals = proposals;
                self.selected = self.selected.min(self.proposals.len().saturating_sub(1));
                self.owner_authorized = true;
                self.status = if self.proposals.is_empty() {
                    "No pending guidance proposals. [g] refresh  [Esc/q] close".into()
                } else {
                    format!("Proposal {} of {}", self.selected + 1, self.proposals.len())
                };
            }
            Err(error) => {
                self.owner_authorized = false;
                self.status =
                    format!("Unable to load/review proposals: {error}. [g] retry  [Esc/q] close");
            }
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        self.poll();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => true,
            KeyCode::Char('g') => {
                self.refresh();
                false
            }
            KeyCode::Up | KeyCode::Char('k') if !self.busy => {
                self.selected = self.selected.saturating_sub(1);
                false
            }
            KeyCode::Down | KeyCode::Char('j') if !self.busy => {
                self.selected = (self.selected + 1).min(self.proposals.len().saturating_sub(1));
                false
            }
            KeyCode::Char('r') => {
                self.review(cockpit_proto::GuidanceProposalDecision::Reject);
                false
            }
            KeyCode::Char('s') => {
                self.review(cockpit_proto::GuidanceProposalDecision::AcceptSession);
                false
            }
            KeyCode::Char('p') => {
                self.review(cockpit_proto::GuidanceProposalDecision::AcceptPersistent);
                false
            }
            _ => false,
        }
    }

    pub fn render(&mut self, frame: &mut Frame<'_>, area: Rect) {
        self.poll();
        let width = area.width.saturating_sub(8).min(88);
        let height = area.height.saturating_sub(4).min(30);
        let popup = Rect::new(
            area.x + (area.width - width) / 2,
            area.y + (area.height - height) / 2,
            width,
            height,
        );
        frame.render_widget(Clear, popup);
        let mut lines = vec![self.status.clone(), String::new()];
        if let Some(proposal) = self.proposals.get(self.selected) {
            lines.extend(render_review_lines(proposal));
        }
        frame.render_widget(
            Paragraph::new(lines.join("\n"))
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .title(" Guidance review ")
                        .borders(Borders::ALL),
                ),
            popup,
        );
    }
}

impl DaemonGuidanceReviewDispatcher {
    pub fn new(client: cockpit_client::DaemonClient) -> Self {
        Self { client }
    }

    pub async fn list(&self) -> anyhow::Result<Vec<GuidanceReviewProposal>> {
        let response = self
            .client
            .request(cockpit_proto::Request::ListGuidanceProposals)
            .await??;
        let cockpit_proto::Response::GuidanceProposals { proposals } = response else {
            anyhow::bail!("unexpected guidance proposal list response")
        };
        proposals
            .into_iter()
            .map(|proposal| {
                Ok(GuidanceReviewProposal {
                    proposal_id: *proposal.proposal_id.as_bytes(),
                    rules: proposal
                        .rules
                        .iter()
                        .map(|rule| ComputerGuidanceRuleV1::decode(rule))
                        .collect::<Result<Vec<_>, _>>()?,
                    rationale: proposal.rationale,
                })
            })
            .collect()
    }

    pub async fn review(
        &self,
        proposal_id: [u8; 16],
        decision: cockpit_proto::GuidanceProposalDecision,
    ) -> anyhow::Result<Vec<ComputerGuidanceRuleV1>> {
        let response = self
            .client
            .request(cockpit_proto::Request::ReviewGuidanceProposal {
                proposal_id: uuid::Uuid::from_bytes(proposal_id),
                decision,
            })
            .await??;
        let cockpit_proto::Response::GuidanceProposalReviewed { installed_rules } = response else {
            anyhow::bail!("unexpected guidance proposal review response")
        };
        installed_rules
            .iter()
            .map(|rule| ComputerGuidanceRuleV1::decode(rule).map_err(Into::into))
            .collect()
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
        fn accept_session(&self, id: &[u8; 16]) -> anyhow::Result<Vec<ComputerGuidanceRuleV1>> {
            self.sessions.lock().unwrap().push(*id);
            Ok(vec![ComputerGuidanceRuleV1::PointerVerification(
                PointerVerification::BeforeEveryPointerAction,
            )])
        }
        fn accept_persistent(&self, id: &[u8; 16]) -> anyhow::Result<Vec<ComputerGuidanceRuleV1>> {
            self.persistents.lock().unwrap().push(*id);
            Ok(vec![ComputerGuidanceRuleV1::MaxReversibleBatch {
                max_actions: 4,
            }])
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
}
