//! Nested onboarding agent authoring editor.
//!
//! Stack-based phases mirror the reference onboarding agent wizard while
//! consuming the daemon [`AgentAuthoringProjection`] and emitting canonical
//! preview/apply intents for the app to route onto daemon RPCs.

#[cfg(test)]
mod tests;

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_core::agents::{GoalSkepticsPolicy, ToolTier, tool_surface_catalog};
use cockpit_core::authoring_draft::{
    AgentAuthoringDraft, ChildAuthoringDraft, RouteGrantDraft, SourceSelection,
    build_package_draft, default_child_draft,
};
use cockpit_proto::{
    AgentAuthoringProjection, ApplyAuthoredAgentPackageOutcome, ApplyAuthoredAgentPackageReceipt,
    AuthoredAgentPackageDraft, AuthoredAgentReceiptStatus, AuthoredAgentReview,
    AuthoredAgentReviewChild,
};

/// Daemon intents produced by the agent authoring reducer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentAuthoringAction {
    PreviewPackage(AuthoredAgentPackageDraft),
    ApplyPackage {
        client_operation_id: String,
        package: AuthoredAgentPackageDraft,
    },
    RefreshProjection,
}

/// Shell-level wrapper for agent authoring intents.
pub type AgentAuthoringShellAction = AgentAuthoringAction;

/// Ordered editor phases. Subagent editing reuses a subset via [`SubagentPhase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    SourceIdentity,
    ThirdPartyLocator,
    ThirdPartyTrust,
    ModelGrants,
    ModelTrust,
    SidecarEgress,
    Optimizations,
    ToolTiers,
    SubagentsList,
    SubagentEdit(SubagentPhase),
    Review,
    Create,
    Pending,
    Conflict,
    Unknown,
    Success,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubagentPhase {
    Identity,
    ModelGrants,
    ModelTrust,
    ToolTiers,
    SubagentsList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubagentsFocus {
    List,
    Add,
    Edit,
}

/// Saved parent context while a nested subagent draft is on the stack.
#[derive(Debug, Clone)]
struct SubagentStackFrame {
    parent: AgentAuthoringDraft,
    child_path: Vec<usize>,
    phase: SubagentPhase,
}

/// The nested agent authoring reducer.
pub struct AgentAuthoringScreen {
    projection: AgentAuthoringProjection,
    draft: AgentAuthoringDraft,
    phase: Phase,
    subagent_stack: Vec<SubagentStackFrame>,
    subagents_focus: SubagentsFocus,
    editing_child: Option<ChildAuthoringDraft>,
    review: Option<AuthoredAgentReview>,
    review_policy_revision: Option<String>,
    pending_action: Option<AgentAuthoringAction>,
    client_operation_id: String,
    receipt: Option<ApplyAuthoredAgentPackageReceipt>,
    status: Option<String>,
    cursor: usize,
    scroll_offset: usize,
    name_field: TextField,
    third_party_field: TextField,
    list_row_rects: Vec<Rect>,
}

impl std::fmt::Debug for AgentAuthoringScreen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentAuthoringScreen")
            .field("phase", &self.phase)
            .field("client_operation_id", &self.client_operation_id)
            .finish_non_exhaustive()
    }
}

impl AgentAuthoringScreen {
    pub fn new(projection: AgentAuthoringProjection, client_operation_id: String) -> Self {
        let draft = AgentAuthoringDraft::from_projection(&projection);
        let name = draft.name.clone();
        Self {
            projection,
            draft,
            phase: Phase::SourceIdentity,
            subagent_stack: Vec::new(),
            subagents_focus: SubagentsFocus::List,
            editing_child: None,
            review: None,
            review_policy_revision: None,
            pending_action: None,
            client_operation_id,
            receipt: None,
            status: None,
            cursor: 0,
            scroll_offset: 0,
            name_field: TextField::new(&name),
            third_party_field: TextField::new(""),
            list_row_rects: Vec::new(),
        }
    }

    pub fn projection(&self) -> &AgentAuthoringProjection {
        &self.projection
    }

    pub fn client_operation_id(&self) -> &str {
        &self.client_operation_id
    }

    pub fn review(&self) -> Option<&AuthoredAgentReview> {
        self.review.as_ref()
    }

    pub fn take_pending_action(&mut self) -> Option<AgentAuthoringAction> {
        self.pending_action.take()
    }

    /// True when the authored package is committed and onboarding may advance.
    pub fn ready_for_stage_advance(&self) -> bool {
        matches!(self.phase, Phase::Success)
            && self
                .receipt
                .as_ref()
                .is_some_and(|receipt| receipt.status == AuthoredAgentReceiptStatus::Committed)
    }

    pub fn stage_settlement(
        &self,
        run_id: uuid::Uuid,
        attempt_id: uuid::Uuid,
        stage_revision: u64,
        config_generation: u64,
    ) -> Option<cockpit_proto::OnboardingStageSettlement> {
        if !self.ready_for_stage_advance() {
            return None;
        }
        Some(cockpit_proto::OnboardingStageSettlement {
            run_id,
            attempt_id,
            stage_revision,
            settlement_operation_id: self.client_operation_id.clone(),
            provider_id: None,
            mutation_intent_hash: None,
            wizard_id: None,
            config_generation,
        })
    }

    pub fn replace_projection(&mut self, projection: AgentAuthoringProjection) {
        let stale_review = self
            .review_policy_revision
            .as_deref()
            .is_some_and(|revision| revision != projection.policy.policy_revision);
        self.projection = projection;
        self.draft = AgentAuthoringDraft::from_projection(&self.projection);
        if stale_review {
            self.review = None;
            self.review_policy_revision = None;
            self.phase = Phase::Review;
            self.status =
                Some("Provider policy changed; review is stale — refresh the preview.".into());
        }
        self.resize_route_state();
    }

    pub fn apply_outcome(&mut self, outcome: ApplyAuthoredAgentPackageOutcome) {
        match outcome {
            ApplyAuthoredAgentPackageOutcome::Review(review) => {
                self.review = Some(review);
                self.review_policy_revision = Some(self.projection.policy.policy_revision.clone());
                self.phase = Phase::Review;
                self.status = None;
            }
            ApplyAuthoredAgentPackageOutcome::Receipt(receipt) => {
                let status = receipt.status;
                self.review = Some(receipt.review.clone());
                self.receipt = Some(receipt);
                self.phase = match status {
                    AuthoredAgentReceiptStatus::Committed => Phase::Success,
                    AuthoredAgentReceiptStatus::Pending => Phase::Pending,
                    AuthoredAgentReceiptStatus::Unknown => Phase::Unknown,
                    AuthoredAgentReceiptStatus::Rejected => Phase::Create,
                };
                if status == AuthoredAgentReceiptStatus::Rejected {
                    self.status = Some("Create was rejected; adjust the draft and retry.".into());
                } else {
                    self.status = None;
                }
            }
            ApplyAuthoredAgentPackageOutcome::PolicyRevisionConflict { projection } => {
                self.replace_projection(projection);
                self.phase = Phase::Conflict;
                self.status =
                    Some("Policy revision conflict — projection refreshed; review again.".into());
            }
            ApplyAuthoredAgentPackageOutcome::Rejected {
                message,
                projection,
                ..
            } => {
                if let Some(projection) = projection {
                    self.replace_projection(projection);
                }
                self.phase = Phase::Create;
                self.status = Some(message);
            }
        }
    }

    fn resize_route_state(&mut self) {
        let count = self.projection.policy.routes.len();
        self.draft
            .route_grants
            .resize(count, RouteGrantDraft { enabled: false });
        self.draft.trust_confirmations.resize(count, false);
        if self.draft.default_route_index >= count && count > 0 {
            self.draft.default_route_index = 0;
        }
        if let Some(child) = self.editing_child.as_mut() {
            Self::resize_child_route_state(child, count);
        }
    }

    fn resize_child_route_state(child: &mut ChildAuthoringDraft, count: usize) {
        child
            .route_grants
            .resize(count, RouteGrantDraft { enabled: false });
        child.trust_confirmations.resize(count, false);
        if child.default_route_index >= count && count > 0 {
            child.default_route_index = 0;
        }
    }

    fn editing_root(&self) -> bool {
        self.subagent_stack.is_empty()
    }

    fn current_child(&self) -> Option<&ChildAuthoringDraft> {
        self.editing_child.as_ref()
    }

    fn current_child_mut(&mut self) -> Option<&mut ChildAuthoringDraft> {
        self.editing_child.as_mut()
    }

    fn phase_title(&self) -> &'static str {
        match self.phase {
            Phase::SourceIdentity => "Agent source and name",
            Phase::ThirdPartyLocator => "Third-party source locator",
            Phase::ThirdPartyTrust => "Third-party publisher trust",
            Phase::ModelGrants => "Model grants and default",
            Phase::ModelTrust => "Model trust confirmation",
            Phase::SidecarEgress => "Remote sidecar egress",
            Phase::Optimizations => "Optimizations and verification",
            Phase::ToolTiers => "Tool tiers",
            Phase::SubagentsList => "Subagents",
            Phase::SubagentEdit(SubagentPhase::Identity) => "Subagent name",
            Phase::SubagentEdit(SubagentPhase::ModelGrants) => "Subagent models",
            Phase::SubagentEdit(SubagentPhase::ModelTrust) => "Subagent model trust",
            Phase::SubagentEdit(SubagentPhase::ToolTiers) => "Subagent tools",
            Phase::SubagentEdit(SubagentPhase::SubagentsList) => "Subagent children",
            Phase::Review => "Review agent package",
            Phase::Create => "Create agent",
            Phase::Pending => "Create pending",
            Phase::Conflict => "Policy conflict",
            Phase::Unknown => "Create status unknown",
            Phase::Success => "Agent created",
        }
    }

    #[cfg(test)]
    pub(crate) fn test_phase(&self) -> Phase {
        self.phase
    }

    #[cfg(test)]
    pub(crate) fn test_status(&self) -> Option<&str> {
        self.status.as_deref()
    }

    pub fn help_text(&self) -> &'static str {
        match self.phase {
            Phase::SourceIdentity
            | Phase::ThirdPartyLocator
            | Phase::SubagentEdit(SubagentPhase::Identity) => {
                "type text  enter: continue  esc: back"
            }
            Phase::ThirdPartyTrust | Phase::SidecarEgress => {
                "space: confirm  enter: continue  esc: back"
            }
            Phase::SubagentsList => "↑/↓ select  d: delete  enter: continue  esc: back",
            Phase::Review => "enter: create  r: refresh preview  esc: edit",
            Phase::Create | Phase::Pending | Phase::Unknown => "enter: submit create  esc: review",
            Phase::Success => "enter: continue setup",
            _ => "↑/↓ toggle  space: select  enter: continue  esc: back",
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<AgentAuthoringAction> {
        if let Some(action) = self.pending_action.take() {
            return Some(action);
        }
        match key.code {
            KeyCode::Esc => self.handle_back(),
            KeyCode::Enter => self.handle_advance(),
            KeyCode::Up => {
                self.move_cursor(-1);
                None
            }
            KeyCode::Down => {
                self.move_cursor(1);
                None
            }
            KeyCode::Char(' ') => {
                self.toggle_selection();
                None
            }
            KeyCode::Char('r') if self.phase == Phase::Review => self.request_preview(),
            KeyCode::Char('d') if self.phase == Phase::SubagentsList => {
                self.delete_selected_subagent();
                None
            }
            KeyCode::Char(ch)
                if matches!(
                    self.phase,
                    Phase::SourceIdentity | Phase::SubagentEdit(SubagentPhase::Identity)
                ) =>
            {
                let ch = crate::tui::textfield::normalize_shift_char(&key, ch);
                let mut encoded = [0u8; 4];
                self.name_field.paste(ch.encode_utf8(&mut encoded));
                None
            }
            KeyCode::Char(ch) if self.phase == Phase::ThirdPartyLocator => {
                let ch = crate::tui::textfield::normalize_shift_char(&key, ch);
                let mut encoded = [0u8; 4];
                self.third_party_field.paste(ch.encode_utf8(&mut encoded));
                None
            }
            KeyCode::Backspace
                if matches!(
                    self.phase,
                    Phase::SourceIdentity | Phase::SubagentEdit(SubagentPhase::Identity)
                ) =>
            {
                self.name_field
                    .handle_key(KeyEvent::new(KeyCode::Backspace, key.modifiers));
                None
            }
            KeyCode::Backspace if self.phase == Phase::ThirdPartyLocator => {
                self.third_party_field
                    .handle_key(KeyEvent::new(KeyCode::Backspace, key.modifiers));
                None
            }
            _ => None,
        }
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> bool {
        if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            return matches!(
                mouse.kind,
                MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
            );
        }
        let index = self
            .list_row_rects
            .iter()
            .position(|rect| rect.contains((mouse.column, mouse.row).into()));
        if let Some(index) = index {
            self.cursor = index;
            self.toggle_selection();
            return true;
        }
        false
    }

    pub fn paste(&mut self, text: &str) {
        match self.phase {
            Phase::SourceIdentity | Phase::SubagentEdit(SubagentPhase::Identity) => {
                self.name_field.paste(text);
            }
            Phase::ThirdPartyLocator => {
                self.third_party_field.paste(text);
            }
            _ => {}
        }
    }

    fn delete_selected_subagent(&mut self) {
        if self.cursor == 0 || self.cursor > self.draft.children.len() {
            return;
        }
        self.draft.children.remove(self.cursor - 1);
        self.cursor = self.cursor.saturating_sub(1);
        self.review = None;
        self.review_policy_revision = None;
    }

    fn sidecar_egress_required(&self) -> bool {
        self.draft
            .sidecar_route_index
            .and_then(|index| self.projection.policy.routes.get(index))
            .is_some_and(|route| route.remote_sidecar_egress_required)
    }

    fn move_cursor(&mut self, delta: isize) {
        let len = self.visible_row_count();
        if len == 0 {
            self.cursor = 0;
            return;
        }
        let next = (self.cursor as isize + delta).clamp(0, len as isize - 1);
        self.cursor = next as usize;
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        }
        let viewport = 12;
        if self.cursor >= self.scroll_offset + viewport {
            self.scroll_offset = self.cursor.saturating_sub(viewport - 1);
        }
    }

    fn visible_row_count(&self) -> usize {
        match self.phase {
            Phase::SourceIdentity => self.projection.sources.len().max(1) + 2,
            Phase::ThirdPartyLocator | Phase::ThirdPartyTrust | Phase::SidecarEgress => 1,
            Phase::ModelGrants | Phase::SubagentEdit(SubagentPhase::ModelGrants) => {
                self.projection.policy.routes.len()
            }
            Phase::ModelTrust => self
                .draft
                .pending_trust_route_indices(&self.projection)
                .len(),
            Phase::SubagentEdit(SubagentPhase::ModelTrust) => self
                .current_child()
                .map(|child| child.pending_trust_route_indices(&self.projection).len())
                .unwrap_or(0),
            Phase::Optimizations => 4,
            Phase::ToolTiers | Phase::SubagentEdit(SubagentPhase::ToolTiers) => {
                tool_surface_catalog().len()
            }
            Phase::SubagentsList => self.draft.children.len() + 2,
            Phase::Review => self.review_lines().len(),
            Phase::Create => 1,
            Phase::Success => 1,
            _ => 1,
        }
    }

    fn toggle_selection(&mut self) {
        match self.phase {
            Phase::SourceIdentity if self.cursor < self.projection.sources.len() => {
                self.draft.source_selection = SourceSelection::Catalog;
                self.draft.source_index = self.cursor;
                if let Some(source) = self.projection.sources.get(self.cursor) {
                    if let Some(slug) = &source.slug {
                        self.draft.name = slug.clone();
                        self.name_field.set(&self.draft.name);
                    }
                }
            }
            Phase::SourceIdentity if self.cursor == self.projection.sources.len() + 1 => {
                self.draft.source_selection = SourceSelection::ThirdParty;
            }
            Phase::SourceIdentity => {
                self.draft.source_selection = SourceSelection::Authored;
            }
            Phase::ThirdPartyTrust => {
                self.draft.third_party_trust_confirmed = !self.draft.third_party_trust_confirmed;
            }
            Phase::SidecarEgress => {
                self.draft.sidecar_egress_confirmed = !self.draft.sidecar_egress_confirmed;
            }
            Phase::ModelGrants => {
                let cursor = self.cursor;
                toggle_route_grant(
                    &mut self.draft.route_grants,
                    cursor,
                    &mut self.draft.default_route_index,
                );
            }
            Phase::SubagentEdit(SubagentPhase::ModelGrants) => {
                let cursor = self.cursor;
                if let Some(child) = self.current_child_mut() {
                    toggle_route_grant(
                        &mut child.route_grants,
                        cursor,
                        &mut child.default_route_index,
                    );
                }
            }
            Phase::SubagentEdit(SubagentPhase::ModelTrust) => {
                let cursor = self.cursor;
                let pending = self
                    .editing_child
                    .as_ref()
                    .map(|child| child.pending_trust_route_indices(&self.projection))
                    .unwrap_or_default();
                if let Some(child) = self.current_child_mut() {
                    if let Some(index) = pending.get(cursor) {
                        child.trust_confirmations[*index] = !child.trust_confirmations[*index];
                    }
                }
            }
            Phase::ModelTrust => {
                let pending = self.draft.pending_trust_route_indices(&self.projection);
                if let Some(index) = pending.get(self.cursor) {
                    self.draft.trust_confirmations[*index] =
                        !self.draft.trust_confirmations[*index];
                }
            }
            Phase::Create => {
                self.draft.make_default = !self.draft.make_default;
            }
            Phase::Optimizations => match self.cursor {
                0 => {
                    self.draft.interactive_subagents = !self.draft.interactive_subagents;
                }
                1 => {
                    self.draft.verification_enabled = !self.draft.verification_enabled;
                }
                2 => self.cycle_goal_skeptics(),
                3 => self.draft.make_default = !self.draft.make_default,
                _ => {}
            },
            Phase::ToolTiers => {
                let cursor = self.cursor;
                cycle_tool_tier(&mut self.draft.tool_tiers, cursor);
            }
            Phase::SubagentEdit(SubagentPhase::ToolTiers) => {
                let cursor = self.cursor;
                if let Some(child) = self.current_child_mut() {
                    cycle_tool_tier(&mut child.tool_tiers, cursor);
                }
            }
            Phase::SubagentEdit(SubagentPhase::SubagentsList) => {
                if self.cursor == 0 {
                    self.begin_add_nested_subagent();
                } else if let Some(child) = self.editing_child.as_ref()
                    && self.cursor <= child.children.len()
                {
                    self.begin_edit_nested_subagent(self.cursor - 1);
                }
            }
            Phase::SubagentsList => {
                if self.cursor == 0 {
                    self.begin_add_subagent();
                } else if self.cursor <= self.draft.children.len() {
                    let index = self.cursor - 1;
                    self.begin_edit_subagent(index);
                }
            }
            _ => {}
        }
    }

    fn cycle_goal_skeptics(&mut self) {
        self.draft.goal_skeptics = match self.draft.goal_skeptics {
            GoalSkepticsPolicy::Off => GoalSkepticsPolicy::Count { count: 1 },
            GoalSkepticsPolicy::Count { count } if count < GoalSkepticsPolicy::MAX_COUNT => {
                GoalSkepticsPolicy::Count { count: count + 1 }
            }
            GoalSkepticsPolicy::Count { .. } => GoalSkepticsPolicy::Off,
        };
    }

    fn handle_back(&mut self) -> Option<AgentAuthoringAction> {
        self.status = None;
        match self.phase {
            Phase::SourceIdentity if self.editing_root() => None,
            Phase::ThirdPartyLocator => {
                self.phase = Phase::SourceIdentity;
                None
            }
            Phase::ThirdPartyTrust => {
                self.phase = Phase::ThirdPartyLocator;
                None
            }
            Phase::SidecarEgress => {
                self.phase = Phase::ModelTrust;
                None
            }
            Phase::SourceIdentity => {
                self.cancel_subagent_edit();
                None
            }
            Phase::ModelGrants if self.editing_root() => {
                self.phase = match self.draft.source_selection {
                    SourceSelection::ThirdParty => Phase::ThirdPartyTrust,
                    _ => Phase::SourceIdentity,
                };
                None
            }
            Phase::ModelGrants => {
                self.phase = Phase::SubagentEdit(SubagentPhase::Identity);
                None
            }
            Phase::ModelTrust => {
                self.phase = Phase::ModelGrants;
                None
            }
            Phase::Optimizations => {
                self.phase = if self.sidecar_egress_required() {
                    Phase::SidecarEgress
                } else if self
                    .draft
                    .pending_trust_route_indices(&self.projection)
                    .is_empty()
                {
                    Phase::ModelGrants
                } else {
                    Phase::ModelTrust
                };
                None
            }
            Phase::ToolTiers if self.editing_root() => {
                self.phase = Phase::Optimizations;
                None
            }
            Phase::ToolTiers => {
                self.phase = Phase::SubagentEdit(SubagentPhase::ModelGrants);
                None
            }
            Phase::SubagentsList => {
                self.phase = Phase::ToolTiers;
                None
            }
            Phase::SubagentEdit(SubagentPhase::Identity) => {
                self.cancel_subagent_edit();
                None
            }
            Phase::SubagentEdit(SubagentPhase::ModelGrants) => {
                self.phase = Phase::SubagentEdit(SubagentPhase::Identity);
                None
            }
            Phase::SubagentEdit(SubagentPhase::ModelTrust) => {
                self.phase = Phase::SubagentEdit(SubagentPhase::ModelGrants);
                None
            }
            Phase::SubagentEdit(SubagentPhase::ToolTiers) => {
                if let Some(child) = self.current_child()
                    && !child
                        .pending_trust_route_indices(&self.projection)
                        .is_empty()
                {
                    self.phase = Phase::SubagentEdit(SubagentPhase::ModelTrust);
                } else {
                    self.phase = Phase::SubagentEdit(SubagentPhase::ModelGrants);
                }
                None
            }
            Phase::SubagentEdit(SubagentPhase::SubagentsList) => {
                self.phase = Phase::SubagentEdit(SubagentPhase::ToolTiers);
                None
            }
            Phase::Review => {
                self.phase = Phase::SubagentsList;
                None
            }
            Phase::Create | Phase::Conflict => {
                self.phase = Phase::Review;
                None
            }
            Phase::Pending | Phase::Unknown => {
                self.phase = Phase::Create;
                None
            }
            Phase::Success => None,
        }
    }

    fn handle_advance(&mut self) -> Option<AgentAuthoringAction> {
        match self.phase {
            Phase::SourceIdentity => {
                self.draft.name = self.name_field.text().trim().to_string();
                if self.draft.source_selection == SourceSelection::ThirdParty {
                    self.third_party_field.set(&self.draft.third_party_locator);
                    self.phase = Phase::ThirdPartyLocator;
                } else if self.editing_root() {
                    self.phase = Phase::ModelGrants;
                } else {
                    self.phase = Phase::SubagentEdit(SubagentPhase::ModelGrants);
                }
                None
            }
            Phase::ThirdPartyLocator => {
                self.draft.third_party_locator = self.third_party_field.text().trim().to_string();
                self.phase = Phase::ThirdPartyTrust;
                None
            }
            Phase::ThirdPartyTrust => {
                if !self.draft.third_party_trust_confirmed {
                    self.status =
                        Some("Confirm third-party publisher trust before continuing.".into());
                    return None;
                }
                self.phase = Phase::ModelGrants;
                None
            }
            Phase::ModelGrants => {
                if self.draft.enabled_route_count() == 0 && self.editing_root() {
                    self.status = Some("Enable at least one model grant.".into());
                    return None;
                }
                if let Some(child) = self.current_child_mut() {
                    let enabled = child.route_grants.iter().filter(|g| g.enabled).count();
                    if enabled == 0 {
                        self.status = Some("Enable at least one model grant.".into());
                        return None;
                    }
                }
                if self.editing_root() {
                    self.phase = if self
                        .draft
                        .pending_trust_route_indices(&self.projection)
                        .is_empty()
                    {
                        Phase::Optimizations
                    } else {
                        Phase::ModelTrust
                    };
                } else if let Some(child) = self.current_child() {
                    self.phase = if child
                        .pending_trust_route_indices(&self.projection)
                        .is_empty()
                    {
                        Phase::SubagentEdit(SubagentPhase::ToolTiers)
                    } else {
                        Phase::SubagentEdit(SubagentPhase::ModelTrust)
                    };
                } else {
                    self.phase = Phase::SubagentEdit(SubagentPhase::ToolTiers);
                }
                None
            }
            Phase::SubagentEdit(SubagentPhase::ModelTrust) => {
                if let Some(child) = self.current_child()
                    && !child
                        .pending_trust_route_indices(&self.projection)
                        .is_empty()
                {
                    self.status = Some("Confirm trust for every enabled unset model.".into());
                    return None;
                }
                self.phase = Phase::SubagentEdit(SubagentPhase::ToolTiers);
                None
            }
            Phase::ModelTrust => {
                if !self
                    .draft
                    .pending_trust_route_indices(&self.projection)
                    .is_empty()
                {
                    self.status = Some("Confirm trust for every enabled unset model.".into());
                    return None;
                }
                self.phase = if self.editing_root() && self.sidecar_egress_required() {
                    Phase::SidecarEgress
                } else {
                    Phase::Optimizations
                };
                None
            }
            Phase::SidecarEgress => {
                if !self.draft.sidecar_egress_confirmed {
                    self.status = Some("Confirm remote sidecar egress before continuing.".into());
                    return None;
                }
                self.phase = Phase::Optimizations;
                None
            }
            Phase::Optimizations => {
                self.phase = if self.editing_root() {
                    Phase::ToolTiers
                } else {
                    Phase::SubagentEdit(SubagentPhase::ToolTiers)
                };
                None
            }
            Phase::ToolTiers if self.editing_root() => {
                self.phase = Phase::SubagentsList;
                None
            }
            Phase::ToolTiers => {
                self.commit_subagent_edit();
                None
            }
            Phase::SubagentsList => {
                if self.cursor == 0 {
                    self.begin_add_subagent();
                    None
                } else if self.cursor <= self.draft.children.len() {
                    self.begin_edit_subagent(self.cursor - 1);
                    None
                } else {
                    self.request_preview()
                }
            }
            Phase::SubagentEdit(SubagentPhase::Identity) => {
                let name = self.name_field.text().trim().to_string();
                if let Some(child) = self.current_child_mut() {
                    child.name = name;
                }
                self.phase = Phase::SubagentEdit(SubagentPhase::ModelGrants);
                None
            }
            Phase::SubagentEdit(SubagentPhase::ModelGrants) => {
                let next_phase = if let Some(child) = self.editing_child.as_ref() {
                    let enabled = child.route_grants.iter().filter(|g| g.enabled).count();
                    if enabled == 0 {
                        self.status = Some("Enable at least one model grant.".into());
                        return None;
                    }
                    if child
                        .pending_trust_route_indices(&self.projection)
                        .is_empty()
                    {
                        Phase::SubagentEdit(SubagentPhase::ToolTiers)
                    } else {
                        Phase::SubagentEdit(SubagentPhase::ModelTrust)
                    }
                } else {
                    Phase::SubagentEdit(SubagentPhase::ToolTiers)
                };
                self.phase = next_phase;
                None
            }
            Phase::SubagentEdit(SubagentPhase::ToolTiers) => {
                self.phase = Phase::SubagentEdit(SubagentPhase::SubagentsList);
                self.cursor = 0;
                None
            }
            Phase::SubagentEdit(SubagentPhase::SubagentsList) => {
                self.commit_subagent_edit();
                None
            }
            Phase::Review => {
                self.phase = Phase::Create;
                None
            }
            Phase::Create => self.request_apply(),
            Phase::Success => None,
            Phase::Pending | Phase::Unknown | Phase::Conflict => None,
        }
    }

    fn request_preview(&mut self) -> Option<AgentAuthoringAction> {
        match build_package_draft(&self.projection, &self.draft) {
            Ok(package) => {
                let action = AgentAuthoringAction::PreviewPackage(package);
                self.pending_action = Some(action.clone());
                self.status = Some("Requesting canonical review preview…".into());
                Some(action)
            }
            Err(error) => {
                self.status = Some(error.to_string());
                None
            }
        }
    }

    fn request_apply(&mut self) -> Option<AgentAuthoringAction> {
        match build_package_draft(&self.projection, &self.draft) {
            Ok(package) => {
                let action = AgentAuthoringAction::ApplyPackage {
                    client_operation_id: self.client_operation_id.clone(),
                    package,
                };
                self.phase = Phase::Pending;
                self.status = Some("Creating agent package…".into());
                Some(action)
            }
            Err(error) => {
                self.status = Some(error.to_string());
                None
            }
        }
    }

    fn child_at_path<'a>(
        draft: &'a AgentAuthoringDraft,
        path: &[usize],
    ) -> Option<&'a ChildAuthoringDraft> {
        let mut current = draft.children.get(*path.first()?)?;
        for index in path.iter().skip(1) {
            current = current.children.get(*index)?;
        }
        Some(current)
    }

    fn child_slot_at_path<'a>(
        draft: &'a mut AgentAuthoringDraft,
        path: &[usize],
    ) -> Option<&'a mut ChildAuthoringDraft> {
        let mut current = draft.children.get_mut(*path.first()?)?;
        for index in path.iter().skip(1) {
            current = current.children.get_mut(*index)?;
        }
        Some(current)
    }

    fn begin_add_nested_subagent(&mut self) {
        let Some(parent_path) = self
            .subagent_stack
            .last()
            .map(|frame| frame.child_path.clone())
        else {
            return;
        };
        let child = default_child_draft(&self.projection);
        if let Some(parent) = Self::child_slot_at_path(&mut self.draft, &parent_path) {
            let child_path = parent_path
                .iter()
                .chain([&parent.children.len()])
                .copied()
                .collect::<Vec<usize>>();
            if let Some(parent) = Self::child_slot_at_path(&mut self.draft, &parent_path) {
                parent.children.push(child);
            }
            self.subagent_stack.push(SubagentStackFrame {
                parent: self.draft.clone(),
                child_path: child_path.clone(),
                phase: SubagentPhase::Identity,
            });
            self.editing_child = Self::child_at_path(&self.draft, &child_path).cloned();
            self.subagents_focus = SubagentsFocus::Add;
            self.phase = Phase::SubagentEdit(SubagentPhase::Identity);
            self.cursor = 0;
            self.name_field.set("helper");
        }
    }

    fn begin_edit_nested_subagent(&mut self, index: usize) {
        let Some(parent_path) = self
            .subagent_stack
            .last()
            .map(|frame| frame.child_path.clone())
        else {
            return;
        };
        let child_path = parent_path
            .iter()
            .chain([&index])
            .copied()
            .collect::<Vec<usize>>();
        let child = Self::child_at_path(&self.draft, &child_path).cloned();
        if child.is_none() {
            return;
        }
        self.subagent_stack.push(SubagentStackFrame {
            parent: self.draft.clone(),
            child_path,
            phase: SubagentPhase::Identity,
        });
        self.editing_child = child;
        self.subagents_focus = SubagentsFocus::Edit;
        self.phase = Phase::SubagentEdit(SubagentPhase::Identity);
        self.cursor = 0;
        if let Some(child) = &self.editing_child {
            self.name_field.set(&child.name);
        }
    }

    fn begin_add_subagent(&mut self) {
        let child = default_child_draft(&self.projection);
        let child_path = vec![self.draft.children.len()];
        self.subagent_stack.push(SubagentStackFrame {
            parent: self.draft.clone(),
            child_path,
            phase: SubagentPhase::Identity,
        });
        self.draft.children.push(child);
        self.editing_child = self.draft.children.last().cloned();
        self.subagents_focus = SubagentsFocus::Add;
        self.phase = Phase::SubagentEdit(SubagentPhase::Identity);
        self.cursor = 0;
        self.name_field.set("runner");
    }

    fn begin_edit_subagent(&mut self, index: usize) {
        let mut child = self.draft.children.get(index).cloned();
        if child.is_none() {
            return;
        }
        Self::resize_child_route_state(
            child.as_mut().expect("child"),
            self.projection.policy.routes.len(),
        );
        self.subagent_stack.push(SubagentStackFrame {
            parent: self.draft.clone(),
            child_path: vec![index],
            phase: SubagentPhase::Identity,
        });
        self.editing_child = child;
        self.subagents_focus = SubagentsFocus::Edit;
        self.phase = Phase::SubagentEdit(SubagentPhase::Identity);
        self.cursor = 0;
        if let Some(child) = &self.editing_child {
            self.name_field.set(&child.name);
        }
    }

    fn commit_subagent_edit(&mut self) {
        if let Some(mut child) = self.editing_child.take() {
            child.name = self.name_field.text().trim().to_string();
            if let Some(frame) = self.subagent_stack.pop() {
                self.draft = frame.parent;
                if let Some(slot) = Self::child_slot_at_path(&mut self.draft, &frame.child_path) {
                    *slot = child;
                }
                if frame.child_path.len() == 1 {
                    self.phase = Phase::SubagentsList;
                    self.subagents_focus = SubagentsFocus::List;
                } else {
                    let parent_path = frame
                        .child_path
                        .split_last()
                        .map(|(last, prefix)| (prefix.to_vec(), *last))
                        .unwrap_or((Vec::new(), 0));
                    self.editing_child = Self::child_at_path(&self.draft, &parent_path.0).cloned();
                    self.phase = Phase::SubagentEdit(SubagentPhase::SubagentsList);
                }
            }
        }
        self.review = None;
        self.review_policy_revision = None;
    }

    fn cancel_subagent_edit(&mut self) {
        if let Some(frame) = self.subagent_stack.pop() {
            // The stacked parent snapshot never includes an uncommitted child;
            // restoring it is sufficient for both add and edit cancellation.
            self.draft = frame.parent;
        }
        self.editing_child = None;
        self.phase = Phase::SubagentsList;
        self.subagents_focus = SubagentsFocus::List;
    }

    fn review_lines(&self) -> Vec<Line<'static>> {
        let review = self.review.as_ref();
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut lines = vec![Line::from(self.phase_title()), Line::default()];
        if let Some(review) = review {
            lines.push(Line::from(format!("Agent: {}", review.agent_name)));
            for grant in &review.grants {
                let mark = if grant.is_default { "*" } else { " " };
                lines.push(Line::from(format!(
                    "{mark} {}/{} · {}",
                    grant.provider_id,
                    grant.model_id,
                    trust_label(grant.trust)
                )));
            }
            if !review.tool_tier_preferences.is_empty() {
                lines.push(Line::default());
                lines.push(Line::from("Tool tiers:"));
                for (tool, tier) in &review.tool_tier_preferences {
                    lines.push(Line::from(format!("  {tool}: {tier}")));
                }
            }
            lines.push(Line::default());
            lines.push(Line::from(format!(
                "Verification: {}",
                review.verification_label.as_deref().unwrap_or("off")
            )));
            lines.push(Line::from(format!(
                "Goal skeptics: {}",
                review.goal_skeptics_label
            )));
            lines.push(Line::from(format!(
                "Interactive subagents: {}",
                if review.interactive_subagents {
                    "on"
                } else {
                    "off"
                }
            )));
            lines.push(Line::from(format!("Source: {}", review.source)));
            if !review.sidecars.is_empty() {
                lines.push(Line::from(format!(
                    "Sidecars: {}",
                    review.sidecars.join(", ")
                )));
            }
            if !review.children.is_empty() {
                lines.push(Line::from("Children:"));
                for child in &review.children {
                    lines.extend(review_child_lines(child, 1));
                }
            }
            lines.push(Line::from(format!(
                "Make default: {}",
                if review.make_default { "yes" } else { "no" }
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                review.trust_disclosure.clone(),
                muted,
            )));
        } else if let Some(status) = &self.status {
            lines.push(Line::from(Span::styled(status.clone(), Color::Yellow)));
        } else {
            lines.push(Line::from(Span::styled(
                "No review yet — press Enter to request preview.",
                muted,
            )));
        }
        lines
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        self.list_row_rects.clear();
        let mut lines = self.review_lines();
        if !matches!(self.phase, Phase::Review) {
            lines = self.phase_lines();
        }
        let capacity = area.height.saturating_sub(2) as usize;
        self.scroll_offset = self.scroll_offset.min(lines.len().saturating_sub(capacity));
        let mut y = area.y;
        for (index, line) in lines
            .iter()
            .skip(self.scroll_offset)
            .take(capacity)
            .enumerate()
        {
            if y >= area.bottom() {
                break;
            }
            frame.render_widget(
                Paragraph::new(line.clone()).wrap(Wrap { trim: false }),
                Rect {
                    x: area.x,
                    y,
                    width: area.width,
                    height: 1,
                },
            );
            self.list_row_rects.push(Rect {
                x: area.x,
                y,
                width: area.width,
                height: 1,
            });
            if index + self.scroll_offset == self.cursor {
                // cursor row already styled in phase_lines when needed
            }
            y += 1;
        }
        if let Some(status) = &self.status {
            let y = area.bottom().saturating_sub(1);
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(status.clone(), Color::Yellow))),
                Rect {
                    x: area.x,
                    y,
                    width: area.width,
                    height: 1,
                },
            );
        }
    }

    fn phase_lines(&self) -> Vec<Line<'static>> {
        let selected = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut lines = vec![Line::from(self.phase_title()), Line::default()];
        match self.phase {
            Phase::SourceIdentity => {
                lines.push(Line::from(format!("Name: {}", self.name_field.text())));
                for (index, source) in self.projection.sources.iter().enumerate() {
                    let mark = if self.draft.source_selection == SourceSelection::Catalog
                        && self.draft.source_index == index
                    {
                        "▸"
                    } else {
                        " "
                    };
                    lines.push(Line::from(vec![
                        Span::raw(format!("{mark} ")),
                        Span::styled(source.display_name.clone(), selected),
                    ]));
                }
                lines.push(Line::from(vec![
                    Span::raw(
                        if self.draft.source_selection == SourceSelection::Authored {
                            "▸"
                        } else {
                            " "
                        },
                    ),
                    Span::styled("Custom authored agent", selected),
                ]));
                lines.push(Line::from(vec![
                    Span::raw(
                        if self.draft.source_selection == SourceSelection::ThirdParty {
                            "▸"
                        } else {
                            " "
                        },
                    ),
                    Span::styled("Third-party pinned source", selected),
                ]));
            }
            Phase::ThirdPartyLocator => {
                lines.push(Line::from(format!(
                    "Locator: {}",
                    self.third_party_field.text()
                )));
            }
            Phase::ThirdPartyTrust => {
                lines.push(Line::from(format!(
                    "{} Confirm third-party publisher trust",
                    if self.draft.third_party_trust_confirmed {
                        "✓"
                    } else {
                        " "
                    }
                )));
            }
            Phase::SidecarEgress => {
                if let Some(index) = self.draft.sidecar_route_index {
                    let route = &self.projection.policy.routes[index];
                    lines.push(Line::from(format!(
                        "Remote sidecar: {}/{}",
                        route.provider_id, route.model_id
                    )));
                }
                lines.push(Line::from(format!(
                    "{} Confirm remote sidecar egress",
                    if self.draft.sidecar_egress_confirmed {
                        "✓"
                    } else {
                        " "
                    }
                )));
            }
            Phase::ModelGrants | Phase::SubagentEdit(SubagentPhase::ModelGrants) => {
                let grants = if let Some(child) = self.current_child() {
                    &child.route_grants
                } else {
                    &self.draft.route_grants
                };
                let default_index = if let Some(child) = self.current_child() {
                    child.default_route_index
                } else {
                    self.draft.default_route_index
                };
                for (index, (grant, route)) in grants
                    .iter()
                    .zip(self.projection.policy.routes.iter())
                    .enumerate()
                {
                    let mark = if grant.enabled {
                        if index == default_index { "★" } else { "✓" }
                    } else {
                        " "
                    };
                    lines.push(Line::from(format!(
                        "{mark} {}/{}",
                        route.provider_id, route.model_id
                    )));
                }
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "Space toggles grants; disabling the default selects another enabled route.",
                    muted,
                )));
            }
            Phase::ModelTrust => {
                for index in self.draft.pending_trust_route_indices(&self.projection) {
                    let route = &self.projection.policy.routes[index];
                    let confirmed = self.draft.trust_confirmations[index];
                    lines.push(Line::from(format!(
                        "{} Confirm {}/{} as {}",
                        if confirmed { "✓" } else { " " },
                        route.provider_id,
                        route.model_id,
                        trust_label(route.trust)
                    )));
                }
            }
            Phase::SubagentEdit(SubagentPhase::ModelTrust) => {
                if let Some(child) = self.current_child() {
                    for index in child.pending_trust_route_indices(&self.projection) {
                        let route = &self.projection.policy.routes[index];
                        let confirmed = child.trust_confirmations[index];
                        lines.push(Line::from(format!(
                            "{} Confirm {}/{} as {}",
                            if confirmed { "✓" } else { " " },
                            route.provider_id,
                            route.model_id,
                            trust_label(route.trust)
                        )));
                    }
                }
            }
            Phase::Optimizations => {
                lines.push(opt_line(
                    0,
                    self.cursor,
                    &format!(
                        "Interactive subagents: {}",
                        on_off(self.draft.interactive_subagents)
                    ),
                ));
                lines.push(opt_line(
                    1,
                    self.cursor,
                    &format!(
                        "Self-verification: {}",
                        on_off(self.draft.verification_enabled)
                    ),
                ));
                lines.push(opt_line(
                    2,
                    self.cursor,
                    &format!("Goal skeptics: {}", self.draft.goal_skeptics.review_label()),
                ));
                lines.push(opt_line(
                    3,
                    self.cursor,
                    &format!("Make default agent: {}", on_off(self.draft.make_default)),
                ));
            }
            Phase::ToolTiers | Phase::SubagentEdit(SubagentPhase::ToolTiers) => {
                let tiers = if let Some(child) = self.current_child() {
                    &child.tool_tiers
                } else {
                    &self.draft.tool_tiers
                };
                for (index, item) in tool_surface_catalog().iter().enumerate() {
                    let tier = tiers.get(item.name).copied().unwrap_or(ToolTier::Disabled);
                    let mark = if index == self.cursor { "▸" } else { " " };
                    lines.push(Line::from(format!(
                        "{mark} {} · {}",
                        item.name,
                        tier.label()
                    )));
                }
            }
            Phase::SubagentsList => {
                lines.push(opt_line(0, self.cursor, "Add subagent"));
                for (index, child) in self.draft.children.iter().enumerate() {
                    lines.push(opt_line(
                        index + 1,
                        self.cursor,
                        &format!("Edit {}", child.name),
                    ));
                }
                lines.push(opt_line(
                    self.draft.children.len() + 1,
                    self.cursor,
                    "Review agent package",
                ));
            }
            Phase::SubagentEdit(SubagentPhase::SubagentsList) => {
                lines.push(opt_line(0, self.cursor, "Add nested subagent"));
                if let Some(child) = &self.editing_child {
                    for (index, nested) in child.children.iter().enumerate() {
                        lines.push(opt_line(
                            index + 1,
                            self.cursor,
                            &format!("Edit {}", nested.name),
                        ));
                    }
                }
            }
            Phase::SubagentEdit(SubagentPhase::Identity) => {
                lines.push(Line::from(format!("Name: {}", self.name_field.text())));
            }
            Phase::Create => {
                let make_default = self
                    .review
                    .as_ref()
                    .map(|review| review.make_default)
                    .unwrap_or(self.draft.make_default);
                lines.push(Line::from(format!(
                    "Make default agent: {}",
                    on_off(make_default)
                )));
                lines.push(Line::from("Enter submits the stable create operation."));
            }
            Phase::Pending => {
                lines.push(Line::from("Waiting for the authoritative create receipt…"));
            }
            Phase::Unknown => {
                lines.push(Line::from(
                    "Create outcome unknown — query the receipt before retrying.",
                ));
            }
            Phase::Conflict => {
                lines.push(Line::from(
                    "Policy revision conflict — projection refreshed; review again.",
                ));
            }
            Phase::Success => {
                lines.push(Line::from("Agent package committed successfully."));
            }
            Phase::Review => {}
        }
        lines
    }
}

fn opt_line(index: usize, cursor: usize, label: &str) -> Line<'static> {
    let style = if index == cursor {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(Span::styled(
        format!("{} {}", if index == cursor { "▸" } else { " " }, label),
        style,
    ))
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn toggle_route_grant(
    grants: &mut [RouteGrantDraft],
    cursor: usize,
    default_route_index: &mut usize,
) {
    if let Some(grant) = grants.get_mut(cursor) {
        let was_default = cursor == *default_route_index;
        grant.enabled = !grant.enabled;
        if !grant.enabled && was_default {
            if let Some(next_default) = grants.iter().position(|entry| entry.enabled) {
                *default_route_index = next_default;
            }
        } else if grant.enabled && grants.iter().filter(|entry| entry.enabled).count() == 1 {
            *default_route_index = cursor;
        }
    }
}

fn cycle_tool_tier(tiers: &mut std::collections::BTreeMap<String, ToolTier>, cursor: usize) {
    let catalog = tool_surface_catalog();
    if let Some(item) = catalog.get(cursor) {
        let current = tiers.get(item.name).copied().unwrap_or(ToolTier::Disabled);
        let legal = item.tiers;
        let next = legal
            .iter()
            .cycle()
            .skip_while(|tier| **tier != current)
            .nth(1)
            .copied()
            .unwrap_or(legal[0]);
        tiers.insert(item.name.to_string(), next);
    }
}

fn review_child_lines(child: &AuthoredAgentReviewChild, indent: usize) -> Vec<Line<'static>> {
    let prefix = "  ".repeat(indent);
    let mut lines = vec![Line::from(format!("{prefix}{}", child.path))];
    for grant in &child.grants {
        let mark = if grant.is_default { "*" } else { " " };
        lines.push(Line::from(format!(
            "{prefix}  {mark} {}/{} · {}",
            grant.provider_id,
            grant.model_id,
            trust_label(grant.trust)
        )));
    }
    for (tool, tier) in &child.tool_tier_preferences {
        lines.push(Line::from(format!("{prefix}  {tool}: {tier}")));
    }
    lines.push(Line::from(format!(
        "{prefix}  interactive subagents: {}",
        if child.interactive_subagents {
            "on"
        } else {
            "off"
        }
    )));
    lines.push(Line::from(format!(
        "{prefix}  goal skeptics: {}",
        child.goal_skeptics_label
    )));
    if !child.children.is_empty() {
        lines.push(Line::from(format!("{prefix}  delegation children:")));
        for nested in &child.children {
            lines.extend(review_child_lines(nested, indent + 1));
        }
    }
    lines
}

fn trust_label(trust: cockpit_proto::AgentPolicyTrustClassification) -> &'static str {
    match trust {
        cockpit_proto::AgentPolicyTrustClassification::Trusted => "trusted",
        cockpit_proto::AgentPolicyTrustClassification::Untrusted => "untrusted",
        cockpit_proto::AgentPolicyTrustClassification::Unset => "unset",
    }
}
