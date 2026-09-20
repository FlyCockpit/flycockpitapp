//! Nested onboarding agent authoring editor.
//!
//! Stack-based phases mirror the reference onboarding agent wizard while
//! consuming the daemon [`AgentAuthoringProjection`] and emitting canonical
//! preview/apply intents for the app to route onto daemon RPCs.

#[cfg(test)]
mod tests;

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Padding, Paragraph};

use super::{chrome, theme, ui};
use crate::tui::textfield::TextField;
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
    list_row_indices: Vec<usize>,
    model_picker_row_rects: Vec<Rect>,
    list_nav: ui::ListNav,
    actions: chrome::ActionBar,
    mouse_selected: Option<usize>,
    tool_model_picker: Option<usize>,
    tool_model_cursor: usize,
    tool_models: std::collections::BTreeMap<String, usize>,
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
        let draft = fresh_authoring_draft(&projection);
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
            list_row_indices: Vec::new(),
            model_picker_row_rects: Vec::new(),
            list_nav: ui::ListNav::new(),
            actions: chrome::ActionBar::default(),
            mouse_selected: None,
            tool_model_picker: None,
            tool_model_cursor: 0,
            tool_models: std::collections::BTreeMap::new(),
        }
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
            provider_mutation_config_generation: None,
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
        self.draft = fresh_authoring_draft(&self.projection);
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
        cockpit_core::authoring_draft::reconcile_route_grant_default(
            &self.draft.route_grants,
            &mut self.draft.default_route_index,
        );
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
        cockpit_core::authoring_draft::reconcile_route_grant_default(
            &child.route_grants,
            &mut child.default_route_index,
        );
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

    pub(super) fn phase_title(&self) -> &'static str {
        match self.phase {
            Phase::SourceIdentity => "Create your first agent",
            Phase::ThirdPartyLocator => "Pin a third-party agent",
            Phase::ThirdPartyTrust => "Trust this publisher?",
            Phase::ModelGrants => "Choose the agent's models",
            Phase::ModelTrust => "How much does this agent see?",
            Phase::SidecarEgress => "Let the sidecar reach the network?",
            Phase::Optimizations => "Tune the agent",
            Phase::ToolTiers => "Grant tools",
            Phase::SubagentsList => "Define subagents",
            Phase::SubagentEdit(SubagentPhase::Identity) => "Subagent",
            Phase::SubagentEdit(SubagentPhase::ModelGrants) => "Subagent models",
            Phase::SubagentEdit(SubagentPhase::ModelTrust) => "How much does this subagent see?",
            Phase::SubagentEdit(SubagentPhase::ToolTiers) => "Subagent tools",
            Phase::SubagentEdit(SubagentPhase::SubagentsList) => "Subagent helpers",
            Phase::Review => "Ready to create",
            Phase::Create => "Create your agent",
            Phase::Pending => "Creating your agent",
            Phase::Conflict => "The model policy changed",
            Phase::Unknown => "Let's check what happened",
            Phase::Success => "Your agent is ready",
        }
    }

    pub(super) fn phase_subtitle(&self) -> String {
        let subtitle = match self.phase {
            Phase::SourceIdentity => {
                "An agent is a saved configuration you can fly again and again.".into()
            }
            Phase::ThirdPartyLocator => {
                "Paste the immutable source locator you want Cockpit to pin.".into()
            }
            Phase::ThirdPartyTrust => {
                "Confirm who published this pinned definition before it can run.".into()
            }
            Phase::ModelGrants => {
                "Tick every model this agent may use. Star one as the default.".into()
            }
            Phase::ModelTrust => {
                "Untrusted models keep secrets and sealed values out of context.".into()
            }
            Phase::SidecarEgress => {
                "This remote sidecar needs explicit permission to leave the machine.".into()
            }
            Phase::Optimizations => {
                "These settings are independent; the defaults are a sane starting point.".into()
            }
            Phase::ToolTiers => "Required tools are always on. Toggle the rest.".into(),
            Phase::SubagentsList => {
                "Helpers this agent can delegate to. The runner is ready to keep or edit.".into()
            }
            Phase::SubagentEdit(SubagentPhase::Identity) => {
                "Name it, then choose its models, trust, tools, and helpers.".into()
            }
            Phase::SubagentEdit(SubagentPhase::ModelGrants) => {
                "Tick every model this subagent may use. Star one as the default.".into()
            }
            Phase::SubagentEdit(SubagentPhase::ModelTrust) => {
                "Confirm the shared trust classification for every unset model.".into()
            }
            Phase::SubagentEdit(SubagentPhase::ToolTiers) => {
                "Required tools are always on. Toggle the rest.".into()
            }
            Phase::SubagentEdit(SubagentPhase::SubagentsList) => {
                "Add a bounded helper beneath this subagent, or save it as-is.".into()
            }
            Phase::Review => "Read the package back once before Cockpit creates it.".into(),
            Phase::Create => self
                .status
                .clone()
                .unwrap_or_else(|| "Everything is ready for the stable create operation.".into()),
            Phase::Pending => self
                .status
                .clone()
                .unwrap_or_else(|| "Waiting for the authoritative create receipt…".into()),
            Phase::Conflict => self.status.clone().unwrap_or_else(|| {
                "The catalog was refreshed. Review the updated package before retrying.".into()
            }),
            Phase::Unknown => self.status.clone().unwrap_or_else(|| {
                "The outcome is unknown. Review the receipt before retrying.".into()
            }),
            Phase::Success => "The agent package was committed successfully.".into(),
        };
        if !matches!(
            self.phase,
            Phase::Create | Phase::Pending | Phase::Conflict | Phase::Unknown
        ) && let Some(status) = &self.status
        {
            format!("{subtitle}  {status}")
        } else {
            subtitle
        }
    }

    #[cfg(test)]
    pub(crate) fn test_phase(&self) -> Phase {
        self.phase
    }

    pub fn help_text(&self) -> &'static str {
        match self.phase {
            Phase::SourceIdentity => "type name   enter continue   esc back   ^c quit",
            Phase::ThirdPartyLocator | Phase::SubagentEdit(SubagentPhase::Identity) => {
                "type text   enter continue   esc back"
            }
            Phase::ThirdPartyTrust
            | Phase::ModelTrust
            | Phase::SidecarEgress
            | Phase::SubagentEdit(SubagentPhase::ModelTrust) => {
                "↑↓ choose   space confirm   enter continue   esc back"
            }
            Phase::ModelGrants | Phase::SubagentEdit(SubagentPhase::ModelGrants) => {
                "↑↓ move   space toggle   d default   enter continue   esc back"
            }
            Phase::ToolTiers | Phase::SubagentEdit(SubagentPhase::ToolTiers) => {
                "↑↓ move   space cycle grant   m set model   enter continue   esc back"
            }
            Phase::Optimizations => "↑↓ move   space toggle   enter continue   esc back",
            Phase::SubagentsList => {
                "a add   e edit   d delete   ↑↓ move   enter continue   esc back"
            }
            Phase::SubagentEdit(SubagentPhase::SubagentsList) => {
                "↑↓ move   space add/edit   enter save   esc cancel"
            }
            Phase::Review => "r refresh   enter create   esc edit",
            Phase::Create => "enter create   esc review",
            Phase::Pending => "waiting for receipt   esc review",
            Phase::Conflict | Phase::Unknown => "enter retry   esc review",
            Phase::Success => "enter continue setup",
        }
    }

    fn handle_tool_model_key(&mut self, key: KeyEvent) -> Option<AgentAuthoringAction> {
        let count = self.projection.policy.routes.len();
        match key.code {
            KeyCode::Esc => self.tool_model_picker = None,
            KeyCode::Enter => self.choose_tool_model(),
            KeyCode::Up if count > 0 => {
                self.tool_model_cursor = (self.tool_model_cursor + count - 1) % count;
            }
            KeyCode::Down if count > 0 => {
                self.tool_model_cursor = (self.tool_model_cursor + 1) % count;
            }
            _ => {}
        }
        None
    }

    fn focused_tool_index(&self) -> Option<usize> {
        tool_presentation_order().get(self.cursor).copied()
    }

    fn open_tool_model_picker(&mut self) {
        let Some(index) = self.focused_tool_index() else {
            return;
        };
        let catalog = tool_surface_catalog();
        if !tool_requires_model(catalog[index].name) {
            self.status = Some("This tool does not need a separate model.".into());
            return;
        }
        if self.projection.policy.routes.is_empty() {
            self.status = Some("Add a verified model before enabling this tool.".into());
            return;
        }
        self.tool_model_picker = Some(index);
        self.tool_model_cursor = self
            .tool_models
            .get(catalog[index].name)
            .copied()
            .unwrap_or(0)
            .min(self.projection.policy.routes.len() - 1);
        self.status = None;
    }

    fn choose_tool_model(&mut self) {
        let Some(index) = self.tool_model_picker.take() else {
            return;
        };
        let catalog = tool_surface_catalog();
        let Some(item) = catalog.get(index) else {
            return;
        };
        if self
            .projection
            .policy
            .routes
            .get(self.tool_model_cursor)
            .is_none()
        {
            self.status = Some("Choose a model for this tool.".into());
            return;
        }
        self.tool_models
            .insert(item.name.to_string(), self.tool_model_cursor);
        let tiers = if let Some(child) = self.current_child_mut() {
            &mut child.tool_tiers
        } else {
            &mut self.draft.tool_tiers
        };
        tiers.insert(item.name.to_string(), ToolTier::Enabled);
        self.status = None;
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<AgentAuthoringAction> {
        if let Some(action) = self.pending_action.take() {
            return Some(action);
        }
        if self.tool_model_picker.is_some() {
            return self.handle_tool_model_key(key);
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
            KeyCode::Char('d')
                if matches!(
                    self.phase,
                    Phase::ModelGrants | Phase::SubagentEdit(SubagentPhase::ModelGrants)
                ) =>
            {
                self.set_default_model();
                None
            }
            KeyCode::Char('a') if self.phase == Phase::SubagentsList => {
                self.begin_add_subagent();
                None
            }
            KeyCode::Char('e') if self.phase == Phase::SubagentsList => {
                if self.cursor < self.draft.children.len() {
                    self.begin_edit_subagent(self.cursor);
                }
                None
            }
            KeyCode::Char('m')
                if matches!(
                    self.phase,
                    Phase::ToolTiers | Phase::SubagentEdit(SubagentPhase::ToolTiers)
                ) =>
            {
                self.open_tool_model_picker();
                None
            }
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
        let pos = Position::new(mouse.column, mouse.row);
        if matches!(mouse.kind, MouseEventKind::Moved | MouseEventKind::Drag(_)) {
            self.actions.track(pos);
            return true;
        }
        if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            if matches!(
                mouse.kind,
                MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
            ) {
                let delta = if matches!(mouse.kind, MouseEventKind::ScrollUp) {
                    -1
                } else {
                    1
                };
                self.list_nav.scroll_by(delta, self.visible_row_count());
                self.scroll_offset = self.list_nav.offset;
                return true;
            }
            return false;
        }
        if let Some(button) = self.actions.clicked(pos) {
            if let Some(action) = self.action_bar_click(button) {
                self.pending_action = Some(action);
            }
            return true;
        }
        if self.tool_model_picker.is_some()
            && let Some(index) = self
                .model_picker_row_rects
                .iter()
                .position(|rect| rect.contains(pos))
        {
            self.tool_model_cursor = index;
            self.choose_tool_model();
            return true;
        }
        let index = self
            .list_row_rects
            .iter()
            .position(|rect| rect.contains(pos));
        if let Some(index) = index {
            let logical = self.list_row_indices.get(index).copied().unwrap_or(index);
            if matches!(
                self.phase,
                Phase::ModelTrust
                    | Phase::ThirdPartyTrust
                    | Phase::SidecarEgress
                    | Phase::SubagentEdit(SubagentPhase::ModelTrust)
            ) {
                if self.mouse_selected == Some(logical) {
                    self.cursor = logical;
                    self.toggle_selection();
                    self.mouse_selected = None;
                } else {
                    self.cursor = logical;
                    self.mouse_selected = Some(logical);
                }
            } else {
                self.cursor = logical;
                self.toggle_selection();
            }
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

    fn set_default_model(&mut self) {
        let index = self.cursor;
        if let Some(child) = self.current_child_mut() {
            if let Some(grant) = child.route_grants.get_mut(index) {
                grant.enabled = true;
                child.default_route_index = index;
            }
        } else if let Some(grant) = self.draft.route_grants.get_mut(index) {
            grant.enabled = true;
            self.draft.default_route_index = index;
        }
    }

    fn delete_selected_subagent(&mut self) {
        if self.cursor >= self.draft.children.len() {
            return;
        }
        self.draft.children.remove(self.cursor);
        self.cursor = self.cursor.min(self.draft.children.len().saturating_sub(1));
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
            Phase::SubagentsList => self.draft.children.len() + 1,
            Phase::Review => self.phase_rows().len(),
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
                cockpit_core::authoring_draft::toggle_route_grant_draft(
                    &mut self.draft.route_grants,
                    cursor,
                    &mut self.draft.default_route_index,
                );
            }
            Phase::SubagentEdit(SubagentPhase::ModelGrants) => {
                let cursor = self.cursor;
                if let Some(child) = self.current_child_mut() {
                    cockpit_core::authoring_draft::toggle_route_grant_draft(
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
                let Some(index) = self.focused_tool_index() else {
                    return;
                };
                let catalog = tool_surface_catalog();
                let item = &catalog[index];
                let current = self
                    .draft
                    .tool_tiers
                    .get(item.name)
                    .copied()
                    .unwrap_or(ToolTier::Disabled);
                if tool_section(item) == REQUIRED_TOOL_SECTION {
                    self.draft
                        .tool_tiers
                        .insert(item.name.to_string(), ToolTier::Enabled);
                    self.status = Some("Required tools stay enabled.".into());
                } else if current == ToolTier::Disabled
                    && tool_requires_model(item.name)
                    && !self.tool_models.contains_key(item.name)
                {
                    self.open_tool_model_picker();
                } else {
                    cycle_tool_tier_at(&mut self.draft.tool_tiers, index);
                    self.status = None;
                }
            }
            Phase::SubagentEdit(SubagentPhase::ToolTiers) => {
                let Some(index) = self.focused_tool_index() else {
                    return;
                };
                let catalog = tool_surface_catalog();
                let item = &catalog[index];
                let current = self
                    .current_child()
                    .and_then(|child| child.tool_tiers.get(item.name))
                    .copied()
                    .unwrap_or(ToolTier::Disabled);
                if tool_section(item) == REQUIRED_TOOL_SECTION {
                    if let Some(child) = self.current_child_mut() {
                        child
                            .tool_tiers
                            .insert(item.name.to_string(), ToolTier::Enabled);
                    }
                    self.status = Some("Required tools stay enabled.".into());
                    return;
                } else if current == ToolTier::Disabled
                    && tool_requires_model(item.name)
                    && !self.tool_models.contains_key(item.name)
                {
                    self.open_tool_model_picker();
                    return;
                }
                if let Some(child) = self.current_child_mut() {
                    cycle_tool_tier_at(&mut child.tool_tiers, index);
                    self.status = None;
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
            Phase::SubagentsList if self.cursor < self.draft.children.len() => {
                self.begin_edit_subagent(self.cursor);
            }
            Phase::SubagentsList => {
                self.pending_action = self.request_preview();
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
        self.status = None;
        match self.phase {
            Phase::SourceIdentity => {
                self.draft.name = match self.name_field.text().trim() {
                    "" => "pilot".to_string(),
                    name => name.to_string(),
                };
                self.name_field.set(&self.draft.name);
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
            Phase::SubagentsList => self.request_preview(),
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
            Phase::Conflict => self.request_preview(),
            Phase::Unknown => Some(AgentAuthoringAction::RefreshProjection),
            Phase::Pending => None,
        }
    }

    fn request_preview(&mut self) -> Option<AgentAuthoringAction> {
        match build_package_draft(&self.projection, &self.draft) {
            Ok(package) => {
                let action = AgentAuthoringAction::PreviewPackage(package);
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
        let child = prepared_child_draft(&self.projection);
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
        let child = prepared_child_draft(&self.projection);
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

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        self.list_row_rects.clear();
        self.list_row_indices.clear();
        self.model_picker_row_rects.clear();
        match self.phase {
            Phase::SourceIdentity => self.render_source_identity(frame, area),
            Phase::ThirdPartyLocator => self.render_third_party_locator(frame, area),
            Phase::SubagentEdit(SubagentPhase::Identity) => {
                self.render_subagent_identity(frame, area);
            }
            _ if self.tool_model_picker.is_some() => {
                let split =
                    Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)])
                        .split(area);
                let phase_rows = self.phase_rows();
                self.render_rows_block(frame, split[0], " Tools ", phase_rows);
                self.render_tool_model_picker(frame, split[1]);
            }
            _ => {
                let title = self.block_title();
                let phase_rows = self.phase_rows();
                self.render_rows_block(frame, area, &title, phase_rows);
            }
        }
    }

    fn render_source_identity(&mut self, frame: &mut Frame, area: Rect) {
        let rows = Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).split(area);
        if let Some(caret) =
            ui::render_field(frame, rows[0], "Name", &self.name_field, true, "e.g. pilot")
        {
            frame.set_cursor_position(caret);
        }
        let source_rows = self.source_selection_rows();
        self.render_rows_block(frame, rows[1], " Agent ", source_rows);
    }

    fn render_third_party_locator(&mut self, frame: &mut Frame, area: Rect) {
        if let Some(caret) = ui::render_field(
            frame,
            area,
            "Locator",
            &self.third_party_field,
            true,
            "pinned source locator",
        ) {
            frame.set_cursor_position(caret);
        }
    }

    fn render_subagent_identity(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(theme::NIGHT))
            .title(Span::styled(" Subagent ", Style::new().fg(theme::INK)))
            .padding(Padding::horizontal(1));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if let Some(caret) = ui::render_field(
            frame,
            inner,
            "Name",
            &self.name_field,
            true,
            "subagent name",
        ) {
            frame.set_cursor_position(caret);
        }
    }

    fn block_title(&self) -> String {
        match self.phase {
            Phase::SourceIdentity => " Agent ".into(),
            Phase::ModelGrants | Phase::SubagentEdit(SubagentPhase::ModelGrants) => {
                let grants = self
                    .current_child()
                    .map(|child| child.route_grants.as_slice())
                    .unwrap_or(&self.draft.route_grants);
                let enabled = grants.iter().filter(|grant| grant.enabled).count();
                format!(" Models  ·  {enabled} of {} ", grants.len())
            }
            Phase::ModelTrust
            | Phase::ThirdPartyTrust
            | Phase::SidecarEgress
            | Phase::SubagentEdit(SubagentPhase::ModelTrust) => " Trust ".into(),
            Phase::Optimizations => " Optimizations ".into(),
            Phase::ToolTiers | Phase::SubagentEdit(SubagentPhase::ToolTiers) => {
                let tiers = self
                    .current_child()
                    .map(|child| &child.tool_tiers)
                    .unwrap_or(&self.draft.tool_tiers);
                let catalog = tool_surface_catalog();
                let enabled = catalog
                    .iter()
                    .filter(|item| {
                        tool_section(item) == REQUIRED_TOOL_SECTION
                            || tiers.get(item.name) == Some(&ToolTier::Enabled)
                    })
                    .count();
                format!(" Tools  ·  {enabled} of {} enabled ", catalog.len())
            }
            Phase::SubagentsList | Phase::SubagentEdit(SubagentPhase::SubagentsList) => {
                format!(" Subagents  ·  {} ", self.draft.children.len())
            }
            Phase::Review => " Summary ".into(),
            Phase::ThirdPartyLocator => " Source ".into(),
            Phase::SubagentEdit(SubagentPhase::Identity) => " Subagent ".into(),
            Phase::Create | Phase::Pending | Phase::Conflict | Phase::Unknown | Phase::Success => {
                " Status ".into()
            }
        }
    }

    pub(super) fn buttons(&self) -> Vec<chrome::Button<'static>> {
        match self.phase {
            Phase::Review => vec![chrome::Button::primary("Create agent")],
            Phase::Create if self.status.is_some() => vec![
                chrome::Button::secondary("Review"),
                chrome::Button::primary("Retry"),
            ],
            Phase::Create => vec![chrome::Button::primary("Create agent")],
            Phase::Pending => vec![chrome::Button::secondary("Review")],
            Phase::Conflict | Phase::Unknown => vec![
                chrome::Button::secondary("Review"),
                chrome::Button::primary("Retry"),
            ],
            Phase::Success => vec![chrome::Button::primary("Done")],
            Phase::SubagentsList => vec![
                chrome::Button::secondary("Add subagent"),
                chrome::Button::primary("Continue"),
            ],
            Phase::SubagentEdit(SubagentPhase::SubagentsList) => {
                vec![chrome::Button::primary("Save")]
            }
            _ => vec![chrome::Button::primary("Continue")],
        }
    }

    pub(crate) fn action_bar_click(&mut self, button: usize) -> Option<AgentAuthoringAction> {
        match self.phase {
            Phase::SubagentsList if button == 0 => {
                self.begin_add_subagent();
                None
            }
            Phase::SubagentsList => self.request_preview(),
            Phase::Create if self.status.is_some() && button == 0 => {
                self.phase = Phase::Review;
                None
            }
            Phase::Pending if button == 0 => {
                self.phase = Phase::Review;
                None
            }
            Phase::Conflict | Phase::Unknown if button == 0 => {
                self.phase = Phase::Review;
                None
            }
            Phase::Conflict if button == 1 => self.request_preview(),
            Phase::Unknown if button == 1 => Some(AgentAuthoringAction::RefreshProjection),
            _ => self.handle_advance(),
        }
    }

    fn render_rows_block(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        title: &str,
        rows: Vec<(Option<usize>, Line<'static>)>,
    ) {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(if matches!(self.phase, Phase::Review) {
                theme::GOOD
            } else {
                theme::NIGHT
            }))
            .title(Span::styled(
                title.to_string(),
                Style::new().fg(if matches!(self.phase, Phase::Review) {
                    theme::GOOD
                } else {
                    theme::INK
                }),
            ))
            .padding(Padding::horizontal(1));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let total = rows.len();
        self.list_nav.set_view_h(usize::from(inner.height));
        if let Some(display_cursor) = rows
            .iter()
            .position(|(logical, _)| *logical == Some(self.cursor))
        {
            self.list_nav.cursor = display_cursor;
        }
        self.list_nav.clamp(total);
        self.scroll_offset = self.list_nav.offset;
        let overflow = total > usize::from(inner.height);
        let (content, scrollbar) = if overflow && inner.width > 1 {
            let split =
                Layout::horizontal([Constraint::Min(0), Constraint::Length(1)]).split(inner);
            (split[0], Some(split[1]))
        } else {
            (inner, None)
        };
        for (visible, (logical, line)) in rows
            .into_iter()
            .skip(self.scroll_offset)
            .take(usize::from(content.height))
            .enumerate()
        {
            let rect = Rect {
                x: content.x,
                y: content.y + visible as u16,
                width: content.width,
                height: 1,
            };
            frame.render_widget(Paragraph::new(line), rect);
            if let Some(logical) = logical {
                self.list_row_rects.push(rect);
                self.list_row_indices.push(logical);
            }
        }
        if let Some(scrollbar) = scrollbar {
            ui::render_scrollbar(
                frame,
                scrollbar,
                total,
                usize::from(content.height),
                self.scroll_offset,
                false,
            );
        }
    }

    fn render_tool_model_picker(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(theme::BRASS))
            .title(Span::styled(" Models ", Style::new().fg(theme::BRASS)));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Choose a model for this tool",
                Style::new().fg(theme::FOG).add_modifier(Modifier::ITALIC),
            )),
            Rect { height: 1, ..inner },
        );
        self.model_picker_row_rects.clear();
        for (index, route) in self
            .projection
            .policy
            .routes
            .iter()
            .enumerate()
            .take(usize::from(inner.height.saturating_sub(1)))
        {
            let rect = Rect {
                x: inner.x,
                y: inner.y + 1 + index as u16,
                width: inner.width,
                height: 1,
            };
            self.model_picker_row_rects.push(rect);
            let focused = index == self.tool_model_cursor;
            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    ui::radio_mark(focused, focused),
                    Span::styled(
                        format!("{}/{}", route.provider_id, route.model_id),
                        if focused {
                            Style::new().fg(theme::BRASS).add_modifier(Modifier::BOLD)
                        } else {
                            Style::new().fg(theme::INK)
                        },
                    ),
                ])),
                rect,
            );
        }
    }

    fn source_selection_rows(&self) -> Vec<(Option<usize>, Line<'static>)> {
        let selected = Style::new().fg(theme::BRASS).add_modifier(Modifier::BOLD);
        let mut lines = Vec::new();
        lines.push((None, Line::default()));
        for (index, source) in self.projection.sources.iter().enumerate() {
            let chosen = self.draft.source_selection == SourceSelection::Catalog
                && self.draft.source_index == index;
            lines.push((
                Some(index),
                Line::from(vec![
                    ui::radio_mark(chosen, self.cursor == index),
                    Span::styled(
                        source.display_name.clone(),
                        if self.cursor == index {
                            selected
                        } else {
                            Style::new().fg(theme::INK)
                        },
                    ),
                ]),
            ));
        }
        let authored = self.projection.sources.len();
        lines.push((
            Some(authored),
            Line::from(vec![
                ui::radio_mark(
                    self.draft.source_selection == SourceSelection::Authored,
                    self.cursor == authored,
                ),
                Span::styled(
                    "Custom authored agent",
                    if self.cursor == authored {
                        selected
                    } else {
                        Style::new().fg(theme::INK)
                    },
                ),
            ]),
        ));
        let third_party = authored + 1;
        lines.push((
            Some(third_party),
            Line::from(vec![
                ui::radio_mark(
                    self.draft.source_selection == SourceSelection::ThirdParty,
                    self.cursor == third_party,
                ),
                Span::styled(
                    "Third-party pinned source",
                    if self.cursor == third_party {
                        selected
                    } else {
                        Style::new().fg(theme::INK)
                    },
                ),
            ]),
        ));
        lines
    }

    fn phase_rows(&self) -> Vec<(Option<usize>, Line<'static>)> {
        let muted = Style::new().fg(theme::FOG);
        let selected = Style::new().fg(theme::BRASS).add_modifier(Modifier::BOLD);
        let mut lines = Vec::new();
        match self.phase {
            Phase::SourceIdentity
            | Phase::ThirdPartyLocator
            | Phase::SubagentEdit(SubagentPhase::Identity) => {
                return lines;
            }
            Phase::ThirdPartyTrust => {
                lines.push((
                    Some(0),
                    Line::from(vec![
                        ui::radio_mark(self.draft.third_party_trust_confirmed, true),
                        Span::styled("I trust this publisher and pinned source", selected),
                    ]),
                ));
                lines.push((
                    None,
                    Line::from(Span::styled(
                        "Click once to select; click the selected row again to confirm.",
                        muted,
                    )),
                ));
            }
            Phase::SidecarEgress => {
                if let Some(index) = self.draft.sidecar_route_index {
                    let route = &self.projection.policy.routes[index];
                    lines.push((
                        None,
                        Line::from(format!(
                            "Remote sidecar  {}/{}",
                            route.provider_id, route.model_id
                        )),
                    ));
                }
                lines.push((
                    Some(0),
                    Line::from(vec![
                        ui::radio_mark(self.draft.sidecar_egress_confirmed, true),
                        Span::styled("Allow remote sidecar egress", selected),
                    ]),
                ));
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
                    lines.push((
                        Some(index),
                        Line::from(vec![
                            ui::check_mark(grant.enabled, self.cursor == index),
                            Span::styled(
                                if grant.enabled && index == default_index {
                                    "★ "
                                } else {
                                    "  "
                                },
                                Style::new().fg(theme::BRASS),
                            ),
                            Span::styled(
                                format!("{}/{}", route.provider_id, route.model_id),
                                if self.cursor == index {
                                    selected
                                } else if grant.enabled {
                                    Style::new().fg(theme::INK)
                                } else {
                                    muted
                                },
                            ),
                        ]),
                    ));
                }
                lines.push((None, Line::default()));
                lines.push((None, Line::from(Span::styled(
                    "Space toggles grants; disabling the default selects another enabled route.",
                    muted,
                ))));
            }
            Phase::ModelTrust => {
                for (row, index) in self
                    .draft
                    .pending_trust_route_indices(&self.projection)
                    .into_iter()
                    .enumerate()
                {
                    let route = &self.projection.policy.routes[index];
                    let confirmed = self
                        .draft
                        .trust_confirmations
                        .get(index)
                        .copied()
                        .unwrap_or(false);
                    let marked = confirmed || self.mouse_selected == Some(row);
                    lines.push((
                        Some(row),
                        Line::from(vec![
                            ui::radio_mark(marked, self.cursor == row),
                            Span::styled(
                                format!(
                                    "Confirm {}/{} as {}",
                                    route.provider_id,
                                    route.model_id,
                                    trust_label(route.trust)
                                ),
                                if self.cursor == row {
                                    selected
                                } else {
                                    Style::new().fg(theme::INK)
                                },
                            ),
                        ]),
                    ));
                }
                lines.push((
                    None,
                    Line::from(Span::styled(
                        "Click a row twice to confirm its shared trust classification.",
                        muted,
                    )),
                ));
            }
            Phase::SubagentEdit(SubagentPhase::ModelTrust) => {
                if let Some(child) = self.current_child() {
                    for (row, index) in child
                        .pending_trust_route_indices(&self.projection)
                        .into_iter()
                        .enumerate()
                    {
                        let route = &self.projection.policy.routes[index];
                        let confirmed = child
                            .trust_confirmations
                            .get(index)
                            .copied()
                            .unwrap_or(false);
                        let marked = confirmed || self.mouse_selected == Some(row);
                        lines.push((
                            Some(row),
                            Line::from(vec![
                                ui::radio_mark(marked, self.cursor == row),
                                Span::styled(
                                    format!(
                                        "Confirm {}/{} as {}",
                                        route.provider_id,
                                        route.model_id,
                                        trust_label(route.trust)
                                    ),
                                    if self.cursor == row {
                                        selected
                                    } else {
                                        Style::new().fg(theme::INK)
                                    },
                                ),
                            ]),
                        ));
                    }
                }
            }
            Phase::Optimizations => {
                lines.push((
                    Some(0),
                    opt_line(
                        0,
                        self.cursor,
                        &format!(
                            "Interactive subagents: {}",
                            on_off(self.draft.interactive_subagents)
                        ),
                    ),
                ));
                lines.push((
                    Some(1),
                    opt_line(
                        1,
                        self.cursor,
                        &format!(
                            "Self-verification: {}",
                            on_off(self.draft.verification_enabled)
                        ),
                    ),
                ));
                lines.push((
                    Some(2),
                    opt_line(
                        2,
                        self.cursor,
                        &format!("Goal skeptics: {}", self.draft.goal_skeptics.review_label()),
                    ),
                ));
                lines.push((
                    Some(3),
                    opt_line(
                        3,
                        self.cursor,
                        &format!("Make default agent: {}", on_off(self.draft.make_default)),
                    ),
                ));
            }
            Phase::ToolTiers | Phase::SubagentEdit(SubagentPhase::ToolTiers) => {
                let tiers = if let Some(child) = self.current_child() {
                    &child.tool_tiers
                } else {
                    &self.draft.tool_tiers
                };
                let catalog = tool_surface_catalog();
                let mut previous = None;
                for (logical, index) in tool_presentation_order().into_iter().enumerate() {
                    let item = &catalog[index];
                    let group = tool_section(item);
                    if previous != Some(group) {
                        lines.push((
                            None,
                            Line::from(Span::styled(
                                tool_section_heading(group),
                                Style::new().fg(theme::BRASS).add_modifier(Modifier::BOLD),
                            )),
                        ));
                        previous = Some(group);
                    }
                    let tier = tiers.get(item.name).copied().unwrap_or(ToolTier::Disabled);
                    let required = group == REQUIRED_TOOL_SECTION;
                    let effective = if required { ToolTier::Enabled } else { tier };
                    let mut tail = if required {
                        "required".to_string()
                    } else {
                        effective.label().to_string()
                    };
                    if let Some(model) = self
                        .tool_models
                        .get(item.name)
                        .and_then(|index| self.projection.policy.routes.get(*index))
                    {
                        tail.push_str(&format!(" · {}/{}", model.provider_id, model.model_id));
                    } else if tool_requires_model(item.name) {
                        tail.push_str(" · choose model");
                    }
                    lines.push((
                        Some(logical),
                        Line::from(vec![
                            ui::check_mark(effective == ToolTier::Enabled, self.cursor == logical),
                            Span::styled(
                                tool_display_name(item.name).to_string(),
                                if self.cursor == logical {
                                    selected
                                } else if effective == ToolTier::Disabled {
                                    muted
                                } else {
                                    Style::new().fg(theme::INK)
                                },
                            ),
                            Span::styled(
                                format!("  —  {tail}"),
                                if required {
                                    Style::new().fg(theme::DISABLED)
                                } else {
                                    muted
                                },
                            ),
                        ]),
                    ));
                }
            }
            Phase::SubagentsList => {
                for (index, child) in self.draft.children.iter().enumerate() {
                    lines.push((
                        Some(index),
                        opt_line(index, self.cursor, &format!("{}  ·  untrusted", child.name)),
                    ));
                }
                lines.push((
                    Some(self.draft.children.len()),
                    opt_line(
                        self.draft.children.len(),
                        self.cursor,
                        "Review agent package",
                    ),
                ));
            }
            Phase::SubagentEdit(SubagentPhase::SubagentsList) => {
                lines.push((Some(0), opt_line(0, self.cursor, "Add nested subagent")));
                if let Some(child) = &self.editing_child {
                    for (index, nested) in child.children.iter().enumerate() {
                        lines.push((
                            Some(index + 1),
                            opt_line(index + 1, self.cursor, &format!("Edit {}", nested.name)),
                        ));
                    }
                }
            }
            Phase::Review => {
                if let Some(review) = &self.review {
                    lines.push((
                        None,
                        Line::from(Span::styled(
                            format!("Agent  {}", review.agent_name),
                            Style::new().fg(theme::GOOD).add_modifier(Modifier::BOLD),
                        )),
                    ));
                    for grant in &review.grants {
                        lines.push((
                            None,
                            Line::from(format!(
                                "{} {}/{} · {}",
                                if grant.is_default { "★" } else { "▣" },
                                grant.provider_id,
                                grant.model_id,
                                trust_label(grant.trust)
                            )),
                        ));
                    }
                    lines.push((
                        None,
                        Line::from(format!("Tools  {}", review.tool_tier_preferences.len())),
                    ));
                    lines.push((
                        None,
                        Line::from(format!(
                            "Verification  {}",
                            review.verification_label.as_deref().unwrap_or("off")
                        )),
                    ));
                    lines.push((
                        None,
                        Line::from(format!("Goal skeptics  {}", review.goal_skeptics_label)),
                    ));
                    lines.push((
                        None,
                        Line::from(format!(
                            "Interactive subagents  {}",
                            on_off(review.interactive_subagents)
                        )),
                    ));
                    for child in &review.children {
                        for line in review_child_lines(child, 1) {
                            lines.push((None, line));
                        }
                    }
                    lines.push((
                        None,
                        Line::from(format!(
                            "Make default  {}",
                            if review.make_default { "yes" } else { "no" }
                        )),
                    ));
                    lines.push((
                        None,
                        Line::from(Span::styled(review.trust_disclosure.clone(), muted)),
                    ));
                } else {
                    lines.push((
                        None,
                        Line::from(Span::styled(
                            "No review yet — press Enter to request the canonical preview.",
                            muted,
                        )),
                    ));
                }
            }
            Phase::Create => {
                let make_default = self
                    .review
                    .as_ref()
                    .map(|review| review.make_default)
                    .unwrap_or(self.draft.make_default);
                lines.push((
                    Some(0),
                    Line::from(vec![
                        ui::check_mark(make_default, true),
                        Span::styled(
                            format!("Make default agent  {}", on_off(make_default)),
                            selected,
                        ),
                    ]),
                ));
                lines.push((
                    None,
                    Line::from("◐  Ready to submit the stable create operation."),
                ));
            }
            Phase::Pending => {
                lines.push((
                    None,
                    Line::from("◐  Waiting for the authoritative create receipt…"),
                ));
            }
            Phase::Unknown => {
                lines.push((
                    None,
                    Line::from("◐  Create outcome unknown — query the receipt before retrying."),
                ));
            }
            Phase::Conflict => {
                lines.push((
                    None,
                    Line::from("◐  Projection refreshed; review the new policy before retrying."),
                ));
            }
            Phase::Success => {
                lines.push((
                    None,
                    Line::from(Span::styled(
                        "◐  Agent package committed successfully.  ✓",
                        Style::new().fg(theme::GOOD).add_modifier(Modifier::BOLD),
                    )),
                ));
            }
        }
        lines
    }
}

fn opt_line(index: usize, cursor: usize, label: &str) -> Line<'static> {
    let style = if index == cursor {
        Style::default()
            .fg(theme::BRASS)
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

const REQUIRED_TOOL_SECTION: u8 = 0;
const SUGGESTED_TOOL_SECTION: u8 = 1;
const OTHER_TOOL_SECTION: u8 = 2;

fn tool_section(item: &cockpit_core::agents::ToolSurfaceItem) -> u8 {
    if matches!(item.name, "read" | "write" | "bash") {
        REQUIRED_TOOL_SECTION
    } else if matches!(
        item.name,
        "escalate" | "computer" | "computer_use" | "transcribe_audio"
    ) {
        OTHER_TOOL_SECTION
    } else {
        SUGGESTED_TOOL_SECTION
    }
}

fn tool_section_heading(section: u8) -> &'static str {
    match section {
        REQUIRED_TOOL_SECTION => "Required",
        SUGGESTED_TOOL_SECTION => "Suggested",
        _ => "Not suggested",
    }
}

fn tool_requires_model(name: &str) -> bool {
    matches!(name, "ask_image" | "transcribe_audio" | "generate_image")
}

fn tool_display_name(name: &str) -> &str {
    if name == "bash" { "shell" } else { name }
}

fn tool_presentation_order() -> Vec<usize> {
    let catalog = tool_surface_catalog();
    let mut order: Vec<usize> = (0..catalog.len()).collect();
    order.sort_by_key(|index| (tool_section(&catalog[*index]), *index));
    order
}

fn enable_required_tools(tiers: &mut std::collections::BTreeMap<String, ToolTier>) {
    for item in tool_surface_catalog()
        .into_iter()
        .filter(|item| tool_section(item) == REQUIRED_TOOL_SECTION)
    {
        tiers.insert(item.name.to_string(), ToolTier::Enabled);
    }
}

fn fresh_authoring_draft(projection: &AgentAuthoringProjection) -> AgentAuthoringDraft {
    let mut draft = AgentAuthoringDraft::from_projection(projection);
    initialize_tool_tiers(&mut draft.tool_tiers);
    if draft.children.is_empty() {
        draft.children.push(prepared_child_draft(projection));
    } else {
        for child in &mut draft.children {
            initialize_child_tool_tiers(child);
        }
    }
    draft
}

fn initialize_tool_tiers(tiers: &mut std::collections::BTreeMap<String, ToolTier>) {
    enable_required_tools(tiers);
    for item in tool_surface_catalog()
        .into_iter()
        .filter(|item| tool_requires_model(item.name))
    {
        tiers.insert(item.name.to_string(), ToolTier::Disabled);
    }
}

fn prepared_child_draft(projection: &AgentAuthoringProjection) -> ChildAuthoringDraft {
    let mut child = default_child_draft(projection);
    initialize_tool_tiers(&mut child.tool_tiers);
    if let Some(index) = projection
        .policy
        .routes
        .iter()
        .position(|route| !route.confirmation_required)
    {
        for grant in &mut child.route_grants {
            grant.enabled = false;
        }
        child.route_grants[index].enabled = true;
        child.default_route_index = index;
    }
    child
}

fn initialize_child_tool_tiers(child: &mut ChildAuthoringDraft) {
    initialize_tool_tiers(&mut child.tool_tiers);
    for nested in &mut child.children {
        initialize_child_tool_tiers(nested);
    }
}

fn cycle_tool_tier_at(tiers: &mut std::collections::BTreeMap<String, ToolTier>, index: usize) {
    let catalog = tool_surface_catalog();
    if let Some(item) = catalog.get(index) {
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
