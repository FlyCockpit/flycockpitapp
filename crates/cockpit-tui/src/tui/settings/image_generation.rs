//! TUI image-generation settings, approvals, and job cards.
//!
//! This module implements the Generation settings node per
//! `prompts/flycockpitapp/ready/image-generation-tui-settings-and-job-ui.md`.
//!
//! It provides:
//! - Endpoint list/editor, target/capability matrix, workflow binding,
//!   health refresh, default target, explicit spend policy (session/project
//!   standing scopes plus plan-bound request scope), explicit project epoch
//!   policy, and destination-grant list/revoke.
//! - Per-capability visibility following the control-plane authorization
//!   matrix. Unauthorized sections render as visible disabled nodes with
//!   stable reason codes.
//! - Immutable authorization review rendered through the standalone
//!   approval-overlay convention (see `dialog/question.rs`).
//! - Durable job/slot progress, cancellation, late-result disposition, and
//!   safe artifact actions.
//! - Sealed `SettingsPage` pointer states registered in the
//!   `SettingsPointerSurface` registry.
//!
//! The TUI consumes only daemon-protocol projections; it adds no
//! `cockpit-db` read path and no local state variant for the canonical
//! job/slot enum.

use std::any::Any;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use super::pointer_actions::{
    ConfirmationChoice, GenerationAction, GenerationNodeId, ImageEndpointId, ImageJobId,
    ImageTargetId, ImageWorkflowId, LateResultId,
};
use super::{Nav, PageBox, SettingsCx, SettingsPage, SettingsPointerSurfaceKind};

// ---------------------------------------------------------------------------
// Stable reason codes (exhaustive per the prompt)
// ---------------------------------------------------------------------------

/// Config sections (endpoints, workflows, budget, grants) are readable only
/// by local Owner or an exact-project admin.
pub(super) const REASON_FORBIDDEN_IMAGE_ADMIN: &str = "forbidden_requires_image_admin";
/// Targets/health projections need exact-project `project_read=1`.
pub(super) const REASON_FORBIDDEN_PROJECT_READ: &str = "forbidden_requires_project_read";
/// Job/plan sections need current-session `session_read=7`.
pub(super) const REASON_FORBIDDEN_SESSION_MEMBERSHIP: &str = "forbidden_requires_session_membership";
/// Request-scope budget row is editable only with a live plan context.
pub(super) const REASON_REQUEST_SCOPE_REQUIRES_PLAN: &str = "request_scope_requires_plan";

/// The exhaustive set of section-level disabled reason codes.
pub(super) const SECTION_REASON_CODES: &[&str] = &[
    REASON_FORBIDDEN_IMAGE_ADMIN,
    REASON_FORBIDDEN_PROJECT_READ,
    REASON_FORBIDDEN_SESSION_MEMBERSHIP,
];

// ---------------------------------------------------------------------------
// Viewport breakpoints (exact per prompt decisions)
// ---------------------------------------------------------------------------

/// Layout breakpoint outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum GenerationViewportMode {
    /// width >= 100 and height >= 30.
    Full,
    /// width >= 80 and height >= 24.
    Compact,
    /// width >= 60 and height >= 16.
    Reduced,
    /// Below 60 columns or 16 rows: resize blocker + global quit/help.
    Blocked,
}

/// Resolve the highest viewport mode for which both dimensions qualify.
pub(crate) fn generation_viewport_mode(width: u16, height: u16) -> GenerationViewportMode {
    if width >= 100 && height >= 30 {
        GenerationViewportMode::Full
    } else if width >= 80 && height >= 24 {
        GenerationViewportMode::Compact
    } else if width >= 60 && height >= 16 {
        GenerationViewportMode::Reduced
    } else {
        GenerationViewportMode::Blocked
    }
}

// ---------------------------------------------------------------------------
// Principal capability model (mirrors the control-plane matrix)
// ---------------------------------------------------------------------------

/// The principal's resolved capability ceiling for image-generation
/// visibility/gating decisions. The TUI never fabricates a read-only
/// projection of data the control plane returns `forbidden` for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct GenerationPrincipal {
    /// True for local Owner.
    pub local_owner: bool,
    /// True when the current attempt ceiling carries exact-project
    /// `image_generation_admin=15` with an ACTIVE exact-project
    /// `ImageGenerationAdmin` grant.
    pub exact_project_admin: bool,
    /// True when the principal has exact-project `project_read=1`.
    pub project_read: bool,
    /// True when the principal has current-session `session_read=7`.
    pub session_read: bool,
    /// True when the principal has current-session `session_write=8`.
    pub session_write: bool,
    /// Whether the admin grant was for the exact project (vs wrong project).
    pub admin_exact_project: bool,
}

impl GenerationPrincipal {
    /// A local Owner principal: all reads, all mutations.
    pub(crate) fn local_owner() -> Self {
        Self {
            local_owner: true,
            exact_project_admin: true,
            admin_exact_project: true,
            project_read: true,
            session_read: true,
            session_write: true,
        }
    }

    /// Whether this principal may mutate generation configuration
    /// (endpoints, targets, workflows, budget, grants, health refresh).
    pub(crate) fn can_mutate_config(&self) -> bool {
        self.local_owner || (self.exact_project_admin && self.admin_exact_project)
    }

    /// Whether config sections (endpoints, workflows, budget, grants) are
    /// readable.
    pub(crate) fn can_read_config(&self) -> bool {
        self.local_owner || (self.exact_project_admin && self.admin_exact_project)
    }

    /// Whether targets/health projections are readable.
    pub(crate) fn can_read_targets(&self) -> bool {
        self.project_read
    }

    /// Whether job/plan sections are readable.
    pub(crate) fn can_read_jobs(&self) -> bool {
        self.session_read
    }

    /// Whether this principal may cancel jobs of its current session.
    pub(crate) fn can_cancel_job(&self) -> bool {
        self.session_write || self.can_mutate_config()
    }

    /// Section-level disabled reason for config sections, or `None` if
    /// readable.
    pub(crate) fn config_section_reason(&self) -> Option<&'static str> {
        if self.can_read_config() {
            None
        } else {
            Some(REASON_FORBIDDEN_IMAGE_ADMIN)
        }
    }

    /// Section-level disabled reason for targets/health, or `None` if
    /// readable.
    pub(crate) fn targets_section_reason(&self) -> Option<&'static str> {
        if self.can_read_targets() {
            None
        } else {
            Some(REASON_FORBIDDEN_PROJECT_READ)
        }
    }

    /// Section-level disabled reason for job/plan sections, or `None` if
    /// readable.
    pub(crate) fn jobs_section_reason(&self) -> Option<&'static str> {
        if self.can_read_jobs() {
            None
        } else {
            Some(REASON_FORBIDDEN_SESSION_MEMBERSHIP)
        }
    }
}

// ---------------------------------------------------------------------------
// Budget editor state
// ---------------------------------------------------------------------------

/// The spend policy scope kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum BudgetScopeKind {
    Request,
    Session,
    Project,
}

/// The budget editor row state. Each scope is `(Unconfigured, null)` or
/// `(Finite|Unlimited, positive-generation)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BudgetScopeRow {
    pub policy: cockpit_core::image_generation_control_plane::BudgetPolicy,
    pub generation: Option<String>,
    /// Editable USD micros suggestion (non-authoritative until confirmed).
    pub suggestion_usd_micros: Option<u64>,
}

impl BudgetScopeRow {
    pub(crate) fn unconfigured() -> Self {
        Self {
            policy: cockpit_core::image_generation_control_plane::BudgetPolicy::Unconfigured,
            generation: None,
            suggestion_usd_micros: None,
        }
    }
}

/// Whether the budget editor has a live plan context (for request-scope
/// editing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanContext {
    pub plan_id: String,
    pub plan_digest: String,
    pub owning_session: String,
}

impl PlanContext {
    pub(crate) fn is_live(&self) -> bool {
        !self.plan_id.is_empty() && !self.plan_digest.is_empty() && !self.owning_session.is_empty()
    }
}

/// The budget editor state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BudgetEditorState {
    pub session: BudgetScopeRow,
    pub project: BudgetScopeRow,
    pub request: BudgetScopeRow,
    pub plan_context: Option<PlanContext>,
    /// True when budget controls block paid generation (Unconfigured).
    pub blocks_paid_generation: bool,
}

impl BudgetEditorState {
    pub(crate) fn unconfigured() -> Self {
        let session = BudgetScopeRow::unconfigured();
        let project = BudgetScopeRow::unconfigured();
        let request = BudgetScopeRow::unconfigured();
        Self {
            blocks_paid_generation: true,
            session,
            project,
            request,
            plan_context: None,
        }
    }

    /// The request-scope row is editable only with a live plan context.
    pub(crate) fn request_scope_editable(&self) -> bool {
        self.plan_context.as_ref().map(|c| c.is_live()).unwrap_or(false)
    }

    /// Apply explicit finite USD micros to a scope (non-authoritative until
    /// save/confirm).
    pub(crate) fn set_finite(&mut self, scope: BudgetScopeKind, usd_micros: u64) {
        let row = match scope {
            BudgetScopeKind::Request => &mut self.request,
            BudgetScopeKind::Session => &mut self.session,
            BudgetScopeKind::Project => &mut self.project,
        };
        row.policy = cockpit_core::image_generation_control_plane::BudgetPolicy::Finite;
        row.generation = Some("1".to_string());
        row.suggestion_usd_micros = Some(usd_micros);
        self.blocks_paid_generation = false;
    }

    /// Apply explicit Unlimited to a scope.
    pub(crate) fn set_unlimited(&mut self, scope: BudgetScopeKind) {
        let row = match scope {
            BudgetScopeKind::Request => &mut self.request,
            BudgetScopeKind::Session => &mut self.session,
            BudgetScopeKind::Project => &mut self.project,
        };
        row.policy = cockpit_core::image_generation_control_plane::BudgetPolicy::Unlimited;
        row.generation = Some("1".to_string());
        self.blocks_paid_generation = false;
    }

    /// Suggestion values: USD 1/request, USD 10/session, USD 100/project-month.
    /// These are editable suggestions only; none is selected/saved until
    /// confirmation.
    pub(crate) fn suggestion_for(scope: BudgetScopeKind) -> u64 {
        match scope {
            BudgetScopeKind::Request => 1_000_000,        // USD 1 in micros
            BudgetScopeKind::Session => 10_000_000,       // USD 10
            BudgetScopeKind::Project => 100_000_000,      // USD 100
        }
    }
}

// ---------------------------------------------------------------------------
// Job reducer state (consumes ImageJobSafeV1 projection only)
// ---------------------------------------------------------------------------

/// Canonical job state as projected by the control plane's safe wire
/// projection. The TUI adds no local state variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ImageJobState {
    Pending,
    Running,
    Succeeded,
    PartialFailure,
    Failed,
    Cancelling,
    Cancelled,
    Unknown,
}

impl ImageJobState {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Running => "Running",
            Self::Succeeded => "Succeeded",
            Self::PartialFailure => "Partial failure",
            Self::Failed => "Failed",
            Self::Cancelling => "Cancellation requested",
            Self::Cancelled => "Cancelled",
            Self::Unknown => "Unknown",
        }
    }
}

/// A target/sample slot within a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JobSlot {
    pub target_id: String,
    pub state: ImageJobState,
    pub published_artifacts: u32,
    pub quarantined_late_results: u32,
}

/// A job card rendered by stable job ID/version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JobCard {
    pub job_id: String,
    pub version: u64,
    pub state: ImageJobState,
    pub slots: Vec<JobSlot>,
    pub quarantined_late_result_count: u32,
    pub stale: bool,
}

impl JobCard {
    pub(crate) fn has_partial_failure(&self) -> bool {
        self.state == ImageJobState::PartialFailure
            || self.slots.iter().any(|s| {
                s.state == ImageJobState::Failed || s.state == ImageJobState::PartialFailure
            })
    }

    /// Cancellation is requestable only for non-terminal jobs.
    pub(crate) fn cancellable(&self) -> bool {
        matches!(
            self.state,
            ImageJobState::Pending | ImageJobState::Running
        )
    }
}

/// The job reducer, keyed by daemon/project/session/job/version.
/// Health/config/job events commit only when daemon instance, project/session,
/// entity ID, config generation, and monotonic version match current view
/// state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JobReducer {
    pub daemon_instance: String,
    pub project_id: String,
    pub session_id: String,
    pub jobs: Vec<JobCard>,
    pub selected_job_id: Option<String>,
    pub config_generation: String,
    pub monotonic_version: u64,
}

impl JobReducer {
    pub(crate) fn new(daemon_instance: String, project_id: String, session_id: String) -> Self {
        Self {
            daemon_instance,
            project_id,
            session_id,
            jobs: Vec::new(),
            selected_job_id: None,
            config_generation: String::new(),
            monotonic_version: 0,
        }
    }

    /// Apply a job event. Commits only when the view-state key matches.
    /// Gaps force snapshot reload; late results from a prior selection are
    /// discarded.
    pub(crate) fn apply_job_event(
        &mut self,
        daemon_instance: &str,
        project_id: &str,
        session_id: &str,
        job: JobCard,
        config_generation: &str,
        version: u64,
    ) -> bool {
        if self.daemon_instance != daemon_instance
            || self.project_id != project_id
            || self.session_id != session_id
            || self.config_generation != config_generation
            || version < self.monotonic_version
        {
            return false;
        }
        // Gap detection: if version jumps, force reload.
        if version > self.monotonic_version + 1 && self.monotonic_version > 0 {
            return false;
        }
        self.monotonic_version = version;
        // Upsert by job_id + version.
        if let Some(existing) = self.jobs.iter_mut().find(|j| j.job_id == job.job_id) {
            if existing.version <= job.version {
                *existing = job;
            }
        } else {
            self.jobs.push(job);
        }
        // Discard late results from a prior selection.
        if let Some(selected) = self.selected_job_id.clone() {
            if !self.jobs.iter().any(|j| j.job_id == selected) {
                self.selected_job_id = None;
            }
        }
        true
    }

    /// Mark all data stale on connection loss.
    pub(crate) fn mark_stale(&mut self) {
        for job in &mut self.jobs {
            job.stale = true;
        }
    }

    /// Rehydrate on reconnect before enabling mutation/cancel.
    pub(crate) fn rehydrate(&mut self, jobs: Vec<JobCard>) {
        self.jobs = jobs;
        for job in &mut self.jobs {
            job.stale = false;
        }
    }

    /// Request cancellation. Changes the local label to "Cancellation
    /// requested" only after authoritative acknowledgement; never displays
    /// "Cancelled" until the daemon reports terminal `cancelled`.
    pub(crate) fn request_cancel(&mut self, job_id: &str) -> bool {
        if let Some(job) = self.jobs.iter_mut().find(|j| j.job_id == job_id) {
            if job.cancellable() {
                job.state = ImageJobState::Cancelling;
                return true;
            }
        }
        false
    }

    /// Apply authoritative cancellation from the daemon.
    pub(crate) fn apply_cancelled(&mut self, job_id: &str) -> bool {
        if let Some(job) = self.jobs.iter_mut().find(|j| j.job_id == job_id) {
            job.state = ImageJobState::Cancelled;
            return true;
        }
        false
    }

    /// Select a job for detail view.
    pub(crate) fn select_job(&mut self, job_id: &str) {
        if self.jobs.iter().any(|j| j.job_id == job_id) {
            self.selected_job_id = Some(job_id.to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Destination grant list (renders ImageDestinationGrantSafeV1 only)
// ---------------------------------------------------------------------------

/// The settled `ImageDestinationGrantSafeV1` wire projection. The TUI shows
/// no destination tuple detail, reference-egress bit, maxima, scope kind, or
/// creation/use times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DestinationGrantRow {
    pub grant_id: String,
    pub generation: String,
    pub project_id: String,
    pub destination_identity_digest: String,
    pub state: GrantState,
    pub expiry: Option<String>,
}

/// The access-grant status (subset of the control-plane enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum GrantState {
    Pending,
    Active,
    Revoking,
    Revoked,
    Expired,
    Declined,
}

impl GrantState {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Active => "Active",
            Self::Revoking => "Revoking",
            Self::Revoked => "Revoked",
            Self::Expired => "Expired",
            Self::Declined => "Declined",
        }
    }
}

// ---------------------------------------------------------------------------
// Late result disposition
// ---------------------------------------------------------------------------

/// The explicit late-result disposition action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LateResultAction {
    Publish,
    Discard,
}

impl LateResultAction {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Publish => "Publish late result?",
            Self::Discard => "Discard late result?",
        }
    }

    pub(crate) fn confirm_label(self) -> &'static str {
        match self {
            Self::Publish => "Publish",
            Self::Discard => "Discard",
        }
    }
}

/// The confirmation text for a destructive action.
pub(crate) fn confirmation_text(action: GenerationAction) -> Option<&'static str> {
    match action {
        GenerationAction::CancelJob(_) => Some("Cancel job?"),
        GenerationAction::RevokeGrant(_) => Some("Revoke grant?"),
        GenerationAction::PublishLateResult(_) => Some("Publish late result?"),
        GenerationAction::DiscardLateResult(_) => Some("Discard late result?"),
        _ => None,
    }
}

/// The confirmation button labels `[confirm] [Cancel]`.
pub(crate) fn confirmation_buttons(action: GenerationAction) -> Option<(&'static str, &'static str)> {
    match action {
        GenerationAction::CancelJob(_) => Some(("Cancel job", "Cancel")),
        GenerationAction::RevokeGrant(_) => Some(("Revoke grant", "Cancel")),
        GenerationAction::PublishLateResult(_) => Some(("Publish", "Cancel")),
        GenerationAction::DiscardLateResult(_) => Some(("Discard", "Cancel")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Settings pointer surface states (sealed)
// ---------------------------------------------------------------------------

/// The Generation settings node list page.
pub(super) struct GenerationListPage {
    pub(super) cursor: usize,
    pub(super) principal: GenerationPrincipal,
    pub(super) viewport: GenerationViewportMode,
}

/// Endpoint editor page.
pub(super) struct EndpointEditorPage {
    pub(super) cursor: usize,
    pub(super) principal: GenerationPrincipal,
    pub(super) endpoint_id: Option<String>,
    pub(super) viewport: GenerationViewportMode,
}

/// Target editor page.
pub(super) struct TargetEditorPage {
    pub(super) cursor: usize,
    pub(super) principal: GenerationPrincipal,
    pub(super) target_id: Option<String>,
    pub(super) viewport: GenerationViewportMode,
}

/// Workflow editor page.
pub(super) struct WorkflowEditorPage {
    pub(super) cursor: usize,
    pub(super) principal: GenerationPrincipal,
    pub(super) workflow_id: Option<String>,
    pub(super) viewport: GenerationViewportMode,
}

/// Budget editor page.
pub(super) struct BudgetEditorPage {
    pub(super) cursor: usize,
    pub(super) principal: GenerationPrincipal,
    pub(super) state: BudgetEditorState,
    pub(super) viewport: GenerationViewportMode,
}

/// Grant list page (list + revoke only; no GrantEditor).
pub(super) struct GrantListPage {
    pub(super) cursor: usize,
    pub(super) principal: GenerationPrincipal,
    pub(super) grants: Vec<DestinationGrantRow>,
    pub(super) confirm: Option<(GenerationAction, ConfirmationChoice)>,
    pub(super) viewport: GenerationViewportMode,
}

/// Job list page.
pub(super) struct JobListPage {
    pub(super) cursor: usize,
    pub(super) principal: GenerationPrincipal,
    pub(super) reducer: JobReducer,
    pub(super) viewport: GenerationViewportMode,
}

/// Job detail page.
pub(super) struct JobDetailPage {
    pub(super) cursor: usize,
    pub(super) principal: GenerationPrincipal,
    pub(super) job_id: String,
    pub(super) reducer: JobReducer,
    pub(super) confirm: Option<(GenerationAction, ConfirmationChoice)>,
    pub(super) viewport: GenerationViewportMode,
}

/// Late result action confirmation page (entered from JobDetail).
pub(super) struct LateResultActionPage {
    pub(super) cursor: usize,
    pub(super) principal: GenerationPrincipal,
    pub(super) late_result_id: String,
    pub(super) action: LateResultAction,
    pub(super) confirm: Option<ConfirmationChoice>,
    pub(super) viewport: GenerationViewportMode,
}

// ---------------------------------------------------------------------------
// Page constructors
// ---------------------------------------------------------------------------

pub(super) fn generation_list_page(principal: GenerationPrincipal) -> PageBox {
    let viewport = GenerationViewportMode::Full;
    boxed(GenerationListPage {
        cursor: 0,
        principal,
        viewport,
    })
}

pub(super) fn endpoint_editor_page(principal: GenerationPrincipal) -> PageBox {
    boxed(EndpointEditorPage {
        cursor: 0,
        principal,
        endpoint_id: None,
        viewport: GenerationViewportMode::Full,
    })
}

pub(super) fn target_editor_page(principal: GenerationPrincipal) -> PageBox {
    boxed(TargetEditorPage {
        cursor: 0,
        principal,
        target_id: None,
        viewport: GenerationViewportMode::Full,
    })
}

pub(super) fn workflow_editor_page(principal: GenerationPrincipal) -> PageBox {
    boxed(WorkflowEditorPage {
        cursor: 0,
        principal,
        workflow_id: None,
        viewport: GenerationViewportMode::Full,
    })
}

pub(super) fn budget_editor_page(principal: GenerationPrincipal) -> PageBox {
    boxed(BudgetEditorPage {
        cursor: 0,
        principal,
        state: BudgetEditorState::unconfigured(),
        viewport: GenerationViewportMode::Full,
    })
}

pub(super) fn grant_list_page(principal: GenerationPrincipal) -> PageBox {
    boxed(GrantListPage {
        cursor: 0,
        principal,
        grants: Vec::new(),
        confirm: None,
        viewport: GenerationViewportMode::Full,
    })
}

pub(super) fn job_list_page(principal: GenerationPrincipal) -> PageBox {
    boxed(JobListPage {
        cursor: 0,
        principal,
        reducer: JobReducer::new(String::new(), String::new(), String::new()),
        viewport: GenerationViewportMode::Full,
    })
}

fn boxed<P: SettingsPage + 'static>(page: P) -> PageBox {
    Box::new(page)
}

/// The Generation settings node list items.
pub(super) const GENERATION_NODE_TITLES: &[&str] = &[
    "Endpoints",
    "Targets",
    "Workflows",
    "Budget",
    "Destination grants",
    "Jobs",
];

/// Map a cursor index to a Generation sub-page.
pub(super) fn open_generation_node(
    cursor: usize,
    principal: GenerationPrincipal,
) -> Option<PageBox> {
    let idx = cursor.min(GENERATION_NODE_TITLES.len() - 1);
    Some(match idx {
        0 => endpoint_editor_page(principal),
        1 => target_editor_page(principal),
        2 => workflow_editor_page(principal),
        3 => budget_editor_page(principal),
        4 => grant_list_page(principal),
        5 => job_list_page(principal),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// SettingsPage implementations
// ---------------------------------------------------------------------------

impl GenerationListPage {
    fn handle_node_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
            KeyCode::Up | KeyCode::Char('k') => {
                self.cursor = self.cursor.saturating_sub(1);
                Nav::Stay
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.cursor + 1 < GENERATION_NODE_TITLES.len() {
                    self.cursor += 1;
                }
                Nav::Stay
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if let Some(page) = open_generation_node(self.cursor, self.principal) {
                    Nav::Push(page)
                } else {
                    Nav::Stay
                }
            }
            _ => Nav::Stay,
        }
    }
}

impl SettingsPage for GenerationListPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::GenerationList
    }
    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        self.handle_node_key(cx, key)
    }
    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut lines = Vec::new();
        for (i, title) in GENERATION_NODE_TITLES.iter().enumerate() {
            let marker = if i == self.cursor { "▸ " } else { "  " };
            lines.push(Line::from(format!("{marker}{title}")));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" Generation "))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
    fn title(&self, _cx: &SettingsCx) -> String {
        "Generation".to_owned()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "↑/↓: navigate  enter: open  h/esc: back"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "GenerationList"
    }
}

impl SettingsPage for EndpointEditorPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::EndpointEditor
    }
    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
            _ => Nav::Stay,
        }
    }
    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut lines = Vec::new();
        if let Some(reason) = self.principal.config_section_reason() {
            lines.push(Line::from(format!("Disabled: {reason}")));
            lines.push(Line::from("No endpoint data visible."));
        } else {
            lines.push(Line::from("Endpoints (config section, admin-gated)"));
            lines.push(Line::from("  [create endpoint]"));
            lines.push(Line::from("  [edit endpoint]"));
            lines.push(Line::from("  [delete endpoint]"));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" Endpoints "))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
    fn title(&self, _cx: &SettingsCx) -> String {
        "Endpoints".to_owned()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "↑/↓: navigate  ctrl+s: save  h/esc: back"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "EndpointEditor"
    }
}

impl SettingsPage for TargetEditorPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::TargetEditor
    }
    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
            _ => Nav::Stay,
        }
    }
    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut lines = Vec::new();
        if let Some(reason) = self.principal.targets_section_reason() {
            lines.push(Line::from(format!("Disabled: {reason}")));
            lines.push(Line::from("No target data visible."));
        } else {
            lines.push(Line::from("Targets (project_read=1)"));
            lines.push(Line::from("  [create target]"));
            lines.push(Line::from("  [set default]"));
            lines.push(Line::from("  [refresh health]"));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" Targets "))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
    fn title(&self, _cx: &SettingsCx) -> String {
        "Targets".to_owned()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "↑/↓: navigate  ctrl+s: save  h/esc: back"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "TargetEditor"
    }
}

impl SettingsPage for WorkflowEditorPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::WorkflowEditor
    }
    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
            _ => Nav::Stay,
        }
    }
    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut lines = Vec::new();
        if let Some(reason) = self.principal.config_section_reason() {
            lines.push(Line::from(format!("Disabled: {reason}")));
            lines.push(Line::from("No workflow data visible."));
        } else {
            lines.push(Line::from("Workflows (config section, admin-gated)"));
            lines.push(Line::from("  [upload workflow]"));
            lines.push(Line::from("  [bind workflow]"));
            lines.push(Line::from("  [delete workflow]"));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" Workflows "))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
    fn title(&self, _cx: &SettingsCx) -> String {
        "Workflows".to_owned()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "↑/↓: navigate  ctrl+s: save  h/esc: back"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "WorkflowEditor"
    }
}

impl SettingsPage for BudgetEditorPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::BudgetEditor
    }
    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
            KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => Nav::Stay,
            _ => Nav::Stay,
        }
    }
    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut lines = Vec::new();
        if let Some(reason) = self.principal.config_section_reason() {
            lines.push(Line::from(format!("Disabled: {reason}")));
            lines.push(Line::from("No budget data visible."));
        } else {
            let session_label = match self.state.session.policy {
                cockpit_core::image_generation_control_plane::BudgetPolicy::Unconfigured => {
                    "Unconfigured"
                }
                cockpit_core::image_generation_control_plane::BudgetPolicy::Finite => "Finite",
                cockpit_core::image_generation_control_plane::BudgetPolicy::Unlimited => {
                    "Unlimited"
                }
            };
            let project_label = match self.state.project.policy {
                cockpit_core::image_generation_control_plane::BudgetPolicy::Unconfigured => {
                    "Unconfigured"
                }
                cockpit_core::image_generation_control_plane::BudgetPolicy::Finite => "Finite",
                cockpit_core::image_generation_control_plane::BudgetPolicy::Unlimited => {
                    "Unlimited"
                }
            };
            lines.push(Line::from(format!("Session scope: {session_label}")));
            lines.push(Line::from(format!("Project scope: {project_label}")));
            if self.state.request_scope_editable() {
                lines.push(Line::from("Request scope: editable (live plan)"));
            } else {
                lines.push(Line::from(format!(
                    "Request scope: disabled ({REASON_REQUEST_SCOPE_REQUIRES_PLAN})"
                )));
            }
            if self.state.blocks_paid_generation {
                lines.push(Line::from("Status: Unconfigured — paid generation blocked"));
            }
            lines.push(Line::from(""));
            lines.push(Line::from("Suggestions (editable, non-authoritative):"));
            lines.push(Line::from(format!(
                "  USD 1/request, USD 10/session, USD 100/project-month"
            )));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" Budget "))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
    fn title(&self, _cx: &SettingsCx) -> String {
        "Budget".to_owned()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "↑/↓: navigate  ctrl+s: save  h/esc: back"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "BudgetEditor"
    }
}

impl SettingsPage for GrantListPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::GrantList
    }
    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
            KeyCode::Up | KeyCode::Char('k') => {
                self.cursor = self.cursor.saturating_sub(1);
                Nav::Stay
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.cursor = self.cursor.saturating_add(1);
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }
    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut lines = Vec::new();
        if let Some(reason) = self.principal.config_section_reason() {
            lines.push(Line::from(format!("Disabled: {reason}")));
            lines.push(Line::from("No grant data visible."));
        } else if self.grants.is_empty() {
            lines.push(Line::from("No destination grants."));
        } else {
            for grant in &self.grants {
                lines.push(Line::from(format!(
                    "  {} | {} | {} | {} | {}{}",
                    grant.grant_id,
                    grant.generation,
                    grant.project_id,
                    grant.destination_identity_digest,
                    grant.state.label(),
                    grant
                        .expiry
                        .as_ref()
                        .map(|e| format!(" | expires {e}"))
                        .unwrap_or_default(),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from("  [revoke grant]"));
        }
        // Never offer global. No GrantEditor/create-grant surface.
        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Destination grants "),
                )
                .wrap(Wrap { trim: false }),
            area,
        );
    }
    fn title(&self, _cx: &SettingsCx) -> String {
        "Destination grants".to_owned()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "↑/↓: navigate  enter: revoke  h/esc: back"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "GrantList"
    }
}

impl SettingsPage for JobListPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::JobList
    }
    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
            KeyCode::Up | KeyCode::Char('k') => {
                self.cursor = self.cursor.saturating_sub(1);
                Nav::Stay
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.cursor = self.cursor.saturating_add(1);
                Nav::Stay
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if let Some(job) = self.reducer.jobs.get(self.cursor) {
                    Nav::Push(boxed(JobDetailPage {
                        cursor: 0,
                        principal: self.principal,
                        job_id: job.job_id.clone(),
                        reducer: self.reducer.clone(),
                        confirm: None,
                        viewport: self.viewport,
                    }))
                } else {
                    Nav::Stay
                }
            }
            _ => Nav::Stay,
        }
    }
    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut lines = Vec::new();
        if let Some(reason) = self.principal.jobs_section_reason() {
            lines.push(Line::from(format!("Disabled: {reason}")));
            lines.push(Line::from("No job data visible."));
        } else if self.reducer.jobs.is_empty() {
            lines.push(Line::from("No jobs."));
        } else {
            for (i, job) in self.reducer.jobs.iter().enumerate() {
                let marker = if i == self.cursor { "▸ " } else { "  " };
                let stale = if job.stale { " (stale)" } else { "" };
                lines.push(Line::from(format!(
                    "{marker}{} v{} {} [{} slots]{}",
                    job.job_id,
                    job.version,
                    job.state.label(),
                    job.slots.len(),
                    stale,
                )));
            }
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" Jobs "))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
    fn title(&self, _cx: &SettingsCx) -> String {
        "Jobs".to_owned()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "↑/↓: navigate  enter: detail  c: cancel  h/esc: back"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "JobList"
    }
}

impl SettingsPage for JobDetailPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::JobDetail
    }
    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
            KeyCode::Char('c') => {
                if let Some(job) = self.reducer.jobs.iter().find(|j| j.job_id == self.job_id) {
                    if job.cancellable() && self.principal.can_cancel_job() {
                        self.confirm =
                            Some((GenerationAction::CancelJob(ImageJobId(self.job_id.clone())), ConfirmationChoice::Confirm));
                    }
                }
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }
    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut lines = Vec::new();
        if let Some(reason) = self.principal.jobs_section_reason() {
            lines.push(Line::from(format!("Disabled: {reason}")));
            lines.push(Line::from("No job data visible."));
        } else if let Some(job) = self.reducer.jobs.iter().find(|j| j.job_id == self.job_id) {
            let stale = if job.stale { " (stale)" } else { "" };
            lines.push(Line::from(format!(
                "Job {} v{} {}{}",
                job.job_id,
                job.version,
                job.state.label(),
                stale,
            )));
            for slot in &job.slots {
                lines.push(Line::from(format!(
                    "  target {} | {} | {} published, {} quarantined",
                    slot.target_id,
                    slot.state.label(),
                    slot.published_artifacts,
                    slot.quarantined_late_results,
                )));
            }
            if job.quarantined_late_result_count > 0 {
                lines.push(Line::from(format!(
                    "  Quarantined late results: {}",
                    job.quarantined_late_result_count
                )));
                lines.push(Line::from("  [publish late result]"));
                lines.push(Line::from("  [discard late result]"));
            }
            if job.cancellable() && self.principal.can_cancel_job() {
                lines.push(Line::from("  [cancel job]  (press c)"));
            }
        } else {
            lines.push(Line::from("Job not found."));
        }
        if let Some((action, choice)) = &self.confirm {
            if let Some(text) = confirmation_text(*action) {
                let (confirm_label, _) = confirmation_buttons(*action).unwrap();
                lines.push(Line::from(""));
                lines.push(Line::from(format!(
                    "{text} [{confirm_label}] [Cancel]"
                )));
                let _ = choice;
            }
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" Job detail "))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
    fn title(&self, _cx: &SettingsCx) -> String {
        "Job detail".to_owned()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "c: cancel job  h/esc: back"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "JobDetail"
    }
}

impl SettingsPage for LateResultActionPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::LateResultAction
    }
    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
            KeyCode::Enter => {
                self.confirm = Some(ConfirmationChoice::Confirm);
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }
    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let text = self.action.label();
        let confirm_label = self.action.confirm_label();
        let mut lines = Vec::new();
        if let Some(reason) = self.principal.config_section_reason() {
            lines.push(Line::from(format!("Disabled: {reason}")));
        } else {
            lines.push(Line::from(format!("{text} [{confirm_label}] [Cancel]")));
            lines.push(Line::from(""));
            lines.push(Line::from("Late result bytes are never exposed."));
            lines.push(Line::from("Artifact actions use only opaque handles."));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Late result action "),
                )
                .wrap(Wrap { trim: false }),
            area,
        );
    }
    fn title(&self, _cx: &SettingsCx) -> String {
        "Late result action".to_owned()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "enter: confirm  h/esc: cancel"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "LateResultAction"
    }
}

/// Render the resize blocker (below 60×16): only quit/help keys.
fn render_resize_blocker(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from("Terminal too small for Generation settings."),
        Line::from("Minimum: 60 columns × 16 rows."),
        Line::from(""),
        Line::from("q: quit  ?: help"),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" Resize "))
            .wrap(Wrap { trim: false }),
        area,
    );
}
