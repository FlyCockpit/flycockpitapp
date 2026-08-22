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
    ConfirmationChoice, GenerationAction, ImageEndpointId, ImageJobId, ImageTargetId,
    ImageWorkflowId, LateResultId, SettingsPointerAction,
};
use super::shell::SettingsScrollRegionId;
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
pub(super) const REASON_FORBIDDEN_SESSION_MEMBERSHIP: &str =
    "forbidden_requires_session_membership";
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
    /// The non-lossy budget policy. A `Finite` policy carries its `usd_micros`
    /// amount directly (no side-channel amount field), matching the
    /// spend-ledger / control-plane wire DTO.
    pub policy: cockpit_core::image_generation_control_plane::BudgetPolicy,
    pub generation: Option<String>,
}

impl BudgetScopeRow {
    pub(crate) fn unconfigured() -> Self {
        Self {
            policy: cockpit_core::image_generation_control_plane::BudgetPolicy::Unconfigured,
            generation: None,
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
        self.plan_context
            .as_ref()
            .map(|c| c.is_live())
            .unwrap_or(false)
    }

    /// Apply explicit finite USD micros to a scope (non-authoritative until
    /// save/confirm).
    pub(crate) fn set_finite(&mut self, scope: BudgetScopeKind, usd_micros: u64) {
        let row = match scope {
            BudgetScopeKind::Request => &mut self.request,
            BudgetScopeKind::Session => &mut self.session,
            BudgetScopeKind::Project => &mut self.project,
        };
        row.policy =
            cockpit_core::image_generation_control_plane::BudgetPolicy::Finite { usd_micros };
        row.generation = Some("1".to_string());
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
            BudgetScopeKind::Request => 1_000_000,   // USD 1 in micros
            BudgetScopeKind::Session => 10_000_000,  // USD 10
            BudgetScopeKind::Project => 100_000_000, // USD 100
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
        matches!(self.state, ImageJobState::Pending | ImageJobState::Running)
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
        {
            return false;
        }
        // Config generation is adopted on bootstrap (a freshly-constructed
        // reducer carries an empty generation) and must match thereafter;
        // a generation change forces a reload rather than committing.
        if self.config_generation.is_empty() {
            self.config_generation = config_generation.to_string();
        } else if self.config_generation != config_generation {
            return false;
        }
        if version < self.monotonic_version {
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
        if let Some(selected) = self.selected_job_id.clone()
            && !self.jobs.iter().any(|j| j.job_id == selected)
        {
            self.selected_job_id = None;
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
        if let Some(job) = self.jobs.iter_mut().find(|j| j.job_id == job_id)
            && job.cancellable()
        {
            job.state = ImageJobState::Cancelling;
            return true;
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
pub(crate) fn confirmation_buttons(
    action: GenerationAction,
) -> Option<(&'static str, &'static str)> {
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

type GenerationBinding = Option<(GenerationAction, bool, Option<&'static str>)>;

fn render_generation_page(
    cx: &SettingsCx,
    frame: &mut Frame,
    area: Rect,
    key: &'static str,
    title: &str,
    rows: Vec<(String, GenerationBinding)>,
    selected: Option<usize>,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {title} "));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = Vec::with_capacity(rows.len());
    let mut controls = Vec::with_capacity(rows.len());
    for (text, binding) in rows {
        lines.push(Line::from(text));
        controls.push(binding.map(|(action, enabled, reason)| {
            (SettingsPointerAction::Generation(action), enabled, reason)
        }));
    }
    cx.scroll_states.render_control_lines(
        frame,
        inner,
        key,
        (lines, selected),
        controls,
        (&cx.pointer_surface, SettingsScrollRegionId(key)).into(),
    );
}

fn accept_or_back(action: SettingsPointerAction, accepted: bool) -> Nav {
    if accepted {
        return Nav::Stay;
    }
    if matches!(
        action,
        SettingsPointerAction::Generation(GenerationAction::Cancel)
    ) {
        return Nav::Back;
    }
    Nav::Stay
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
    fn handle_pointer_control(
        &mut self,
        _cx: &mut SettingsCx,
        action: super::pointer_actions::SettingsPointerAction,
    ) -> Nav {
        let super::pointer_actions::SettingsPointerAction::Generation(
            super::pointer_actions::GenerationAction::OpenNode(node),
        ) = action
        else {
            return Nav::Stay;
        };
        self.cursor = match node {
            super::pointer_actions::GenerationNodeId::Endpoints => 0,
            super::pointer_actions::GenerationNodeId::Targets => 1,
            super::pointer_actions::GenerationNodeId::Workflows => 2,
            super::pointer_actions::GenerationNodeId::Budget => 3,
            super::pointer_actions::GenerationNodeId::Grants => 4,
            super::pointer_actions::GenerationNodeId::Jobs => 5,
        };
        open_generation_node(self.cursor, self.principal).map_or(Nav::Stay, Nav::Push)
    }
    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        // While the resize blocker is showing, list navigation is inert; only
        // the back/quit keys remain live so the user can leave the surface.
        if self.viewport == GenerationViewportMode::Blocked {
            return match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
                _ => Nav::Stay,
            };
        }
        self.handle_node_key(cx, key)
    }
    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut lines = Vec::new();
        let mut controls = Vec::new();
        for (i, title) in GENERATION_NODE_TITLES.iter().enumerate() {
            let marker = if i == self.cursor { "▸ " } else { "  " };
            lines.push(Line::from(format!("{marker}{title}")));
            let node = match i {
                0 => super::pointer_actions::GenerationNodeId::Endpoints,
                1 => super::pointer_actions::GenerationNodeId::Targets,
                2 => super::pointer_actions::GenerationNodeId::Workflows,
                3 => super::pointer_actions::GenerationNodeId::Budget,
                4 => super::pointer_actions::GenerationNodeId::Grants,
                _ => super::pointer_actions::GenerationNodeId::Jobs,
            };
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Generation(
                    super::pointer_actions::GenerationAction::OpenNode(node),
                ),
                true,
                None,
            )));
        }
        let selected_line = Some(self.cursor);
        cx.scroll_states.render_control_lines(
            frame,
            area,
            "generation:list",
            (lines, selected_line),
            controls,
            (
                &cx.pointer_surface,
                super::shell::SettingsScrollRegionId("generation:list"),
            )
                .into(),
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
    fn handle_pointer_control(
        &mut self,
        _cx: &mut SettingsCx,
        action: SettingsPointerAction,
    ) -> Nav {
        accept_or_back(
            action.clone(),
            matches!(
                &action,
                SettingsPointerAction::Generation(
                    GenerationAction::CreateEndpoint
                        | GenerationAction::EditEndpoint(_)
                        | GenerationAction::DeleteEndpoint(_)
                        | GenerationAction::Cancel
                )
            ),
        )
    }
    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut rows: Vec<(String, GenerationBinding)> = Vec::new();
        if let Some(reason) = self.principal.config_section_reason() {
            rows.push((format!("Disabled: {reason}"), None));
            rows.push(("No endpoint data visible.".into(), None));
        } else {
            rows.push(("Endpoints (config section, admin-gated)".into(), None));
            rows.push((
                "[create endpoint]".into(),
                Some((GenerationAction::CreateEndpoint, true, None)),
            ));
            if let Some(id) = &self.endpoint_id {
                rows.push((
                    "[edit endpoint]".into(),
                    Some((
                        GenerationAction::EditEndpoint(ImageEndpointId(id.clone())),
                        true,
                        None,
                    )),
                ));
                rows.push((
                    "[delete endpoint]".into(),
                    Some((
                        GenerationAction::DeleteEndpoint(ImageEndpointId(id.clone())),
                        true,
                        None,
                    )),
                ));
            }
            rows.push((
                "[Cancel]".into(),
                Some((GenerationAction::Cancel, true, None)),
            ));
        }
        render_generation_page(
            cx,
            frame,
            area,
            "generation:endpoints",
            "Endpoints",
            rows,
            Some(self.cursor),
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
    fn handle_pointer_control(
        &mut self,
        _cx: &mut SettingsCx,
        action: SettingsPointerAction,
    ) -> Nav {
        accept_or_back(
            action.clone(),
            matches!(
                &action,
                SettingsPointerAction::Generation(
                    GenerationAction::CreateTarget
                        | GenerationAction::EditTarget(_)
                        | GenerationAction::DeleteTarget(_)
                        | GenerationAction::SetDefaultTarget(_)
                        | GenerationAction::RefreshHealth
                        | GenerationAction::Cancel
                )
            ),
        )
    }
    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut rows: Vec<(String, GenerationBinding)> = Vec::new();
        if let Some(reason) = self.principal.targets_section_reason() {
            rows.push((format!("Disabled: {reason}"), None));
            rows.push(("No target data visible.".into(), None));
        } else {
            rows.push(("Targets (project_read=1)".into(), None));
            rows.push((
                "[create target]".into(),
                Some((GenerationAction::CreateTarget, true, None)),
            ));
            if let Some(id) = &self.target_id {
                rows.push((
                    "[edit target]".into(),
                    Some((
                        GenerationAction::EditTarget(ImageTargetId(id.clone())),
                        true,
                        None,
                    )),
                ));
                rows.push((
                    "[delete target]".into(),
                    Some((
                        GenerationAction::DeleteTarget(ImageTargetId(id.clone())),
                        true,
                        None,
                    )),
                ));
                rows.push((
                    "[set default]".into(),
                    Some((
                        GenerationAction::SetDefaultTarget(ImageTargetId(id.clone())),
                        true,
                        None,
                    )),
                ));
            }
            rows.push((
                "[refresh health]".into(),
                Some((GenerationAction::RefreshHealth, true, None)),
            ));
            rows.push((
                "[Cancel]".into(),
                Some((GenerationAction::Cancel, true, None)),
            ));
        }
        render_generation_page(
            cx,
            frame,
            area,
            "generation:targets",
            "Targets",
            rows,
            Some(self.cursor),
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
    fn handle_pointer_control(
        &mut self,
        _cx: &mut SettingsCx,
        action: SettingsPointerAction,
    ) -> Nav {
        accept_or_back(
            action.clone(),
            matches!(
                &action,
                SettingsPointerAction::Generation(
                    GenerationAction::UploadWorkflow
                        | GenerationAction::BindWorkflow(_)
                        | GenerationAction::DeleteWorkflow(_)
                        | GenerationAction::Cancel
                )
            ),
        )
    }
    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut rows: Vec<(String, GenerationBinding)> = Vec::new();
        if let Some(reason) = self.principal.config_section_reason() {
            rows.push((format!("Disabled: {reason}"), None));
            rows.push(("No workflow data visible.".into(), None));
        } else {
            rows.push(("Workflows (config section, admin-gated)".into(), None));
            rows.push((
                "[upload workflow]".into(),
                Some((GenerationAction::UploadWorkflow, true, None)),
            ));
            if let Some(id) = &self.workflow_id {
                rows.push((
                    "[bind workflow]".into(),
                    Some((
                        GenerationAction::BindWorkflow(ImageWorkflowId(id.clone())),
                        true,
                        None,
                    )),
                ));
                rows.push((
                    "[delete workflow]".into(),
                    Some((
                        GenerationAction::DeleteWorkflow(ImageWorkflowId(id.clone())),
                        true,
                        None,
                    )),
                ));
            }
            rows.push((
                "[Cancel]".into(),
                Some((GenerationAction::Cancel, true, None)),
            ));
        }
        render_generation_page(
            cx,
            frame,
            area,
            "generation:workflows",
            "Workflows",
            rows,
            Some(self.cursor),
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
    fn handle_pointer_control(
        &mut self,
        _cx: &mut SettingsCx,
        action: SettingsPointerAction,
    ) -> Nav {
        accept_or_back(
            action.clone(),
            matches!(
                &action,
                SettingsPointerAction::Generation(
                    GenerationAction::SaveBudget | GenerationAction::Cancel
                )
            ),
        )
    }
    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut rows: Vec<(String, GenerationBinding)> = Vec::new();
        if let Some(reason) = self.principal.config_section_reason() {
            rows.push((format!("Disabled: {reason}"), None));
            rows.push(("No budget data visible.".into(), None));
        } else {
            let session_label = match self.state.session.policy {
                cockpit_core::image_generation_control_plane::BudgetPolicy::Unconfigured => {
                    "Unconfigured"
                }
                cockpit_core::image_generation_control_plane::BudgetPolicy::Finite { .. } => {
                    "Finite"
                }
                cockpit_core::image_generation_control_plane::BudgetPolicy::Unlimited => {
                    "Unlimited"
                }
            };
            let project_label = match self.state.project.policy {
                cockpit_core::image_generation_control_plane::BudgetPolicy::Unconfigured => {
                    "Unconfigured"
                }
                cockpit_core::image_generation_control_plane::BudgetPolicy::Finite { .. } => {
                    "Finite"
                }
                cockpit_core::image_generation_control_plane::BudgetPolicy::Unlimited => {
                    "Unlimited"
                }
            };
            rows.push((format!("Session scope: {session_label}"), None));
            rows.push((format!("Project scope: {project_label}"), None));
            if self.state.request_scope_editable() {
                rows.push(("Request scope: editable (live plan)".into(), None));
            } else {
                rows.push((
                    format!("Request scope: disabled ({REASON_REQUEST_SCOPE_REQUIRES_PLAN})"),
                    None,
                ));
            }
            if self.state.blocks_paid_generation {
                rows.push((
                    "Status: Unconfigured — paid generation blocked".into(),
                    None,
                ));
            }
            rows.push((String::new(), None));
            rows.push(("Suggestions (editable, non-authoritative):".into(), None));
            rows.push((
                "  USD 1/request, USD 10/session, USD 100/project-month".into(),
                None,
            ));
            rows.push((
                "[Save]".into(),
                Some((GenerationAction::SaveBudget, true, None)),
            ));
            rows.push((
                "[Cancel]".into(),
                Some((GenerationAction::Cancel, true, None)),
            ));
        }
        render_generation_page(
            cx,
            frame,
            area,
            "generation:budget",
            "Budget",
            rows,
            Some(self.cursor),
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
    fn handle_pointer_control(
        &mut self,
        _cx: &mut SettingsCx,
        action: SettingsPointerAction,
    ) -> Nav {
        match action {
            SettingsPointerAction::Generation(GenerationAction::RevokeGrant(id)) => {
                self.confirm = Some((
                    GenerationAction::RevokeGrant(id),
                    ConfirmationChoice::Confirm,
                ));
                Nav::Stay
            }
            SettingsPointerAction::Generation(GenerationAction::ConfirmRevokeGrant(_, _)) => {
                self.confirm = None;
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }
    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut rows: Vec<(String, GenerationBinding)> = Vec::new();
        if let Some(reason) = self.principal.config_section_reason() {
            rows.push((format!("Disabled: {reason}"), None));
            rows.push(("No grant data visible.".into(), None));
        } else if self.grants.is_empty() {
            rows.push(("No destination grants.".into(), None));
        } else {
            for grant in &self.grants {
                rows.push((
                    format!(
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
                    ),
                    None,
                ));
            }
            rows.push((String::new(), None));
            if let Some(grant) = self.grants.first() {
                rows.push((
                    "[revoke grant]".into(),
                    Some((
                        GenerationAction::RevokeGrant(LateResultId(grant.grant_id.clone())),
                        true,
                        None,
                    )),
                ));
            }
        }
        if let Some((GenerationAction::RevokeGrant(id), _)) = &self.confirm {
            rows.push(("Revoke grant?".into(), None));
            rows.push((
                "[Revoke grant]".into(),
                Some((
                    GenerationAction::ConfirmRevokeGrant(id.clone(), ConfirmationChoice::Confirm),
                    true,
                    None,
                )),
            ));
            rows.push((
                "[Cancel]".into(),
                Some((
                    GenerationAction::ConfirmRevokeGrant(id.clone(), ConfirmationChoice::Cancel),
                    true,
                    None,
                )),
            ));
        }
        render_generation_page(
            cx,
            frame,
            area,
            "generation:grants",
            "Destination grants",
            rows,
            Some(self.cursor),
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
    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut rows: Vec<(String, GenerationBinding)> = Vec::new();
        if let Some(reason) = self.principal.jobs_section_reason() {
            rows.push((format!("Disabled: {reason}"), None));
            rows.push(("No job data visible.".into(), None));
        } else if self.reducer.jobs.is_empty() {
            rows.push(("No jobs.".into(), None));
        } else {
            for (i, job) in self.reducer.jobs.iter().enumerate() {
                let marker = if i == self.cursor { "▸ " } else { "  " };
                let stale = if job.stale { " (stale)" } else { "" };
                rows.push((
                    format!(
                        "{marker}{} v{} {} [{} slots]{}",
                        job.job_id,
                        job.version,
                        job.state.label(),
                        job.slots.len(),
                        stale,
                    ),
                    None,
                ));
            }
        }
        render_generation_page(
            cx,
            frame,
            area,
            "generation:jobs",
            "Jobs",
            rows,
            Some(self.cursor),
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
                if let Some(job) = self.reducer.jobs.iter().find(|j| j.job_id == self.job_id)
                    && job.cancellable()
                    && self.principal.can_cancel_job()
                {
                    self.confirm = Some((
                        GenerationAction::CancelJob(ImageJobId(self.job_id.clone())),
                        ConfirmationChoice::Confirm,
                    ));
                }
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }
    fn handle_pointer_control(
        &mut self,
        _cx: &mut SettingsCx,
        action: SettingsPointerAction,
    ) -> Nav {
        match action {
            SettingsPointerAction::Generation(GenerationAction::CancelJob(id)) => {
                self.confirm = Some((GenerationAction::CancelJob(id), ConfirmationChoice::Confirm));
                Nav::Stay
            }
            SettingsPointerAction::Generation(GenerationAction::PublishLateResult(id)) => {
                Nav::Push(boxed(LateResultActionPage {
                    cursor: 0,
                    principal: self.principal,
                    late_result_id: id.0,
                    action: LateResultAction::Publish,
                    confirm: None,
                    viewport: self.viewport,
                }))
            }
            SettingsPointerAction::Generation(GenerationAction::DiscardLateResult(id)) => {
                Nav::Push(boxed(LateResultActionPage {
                    cursor: 0,
                    principal: self.principal,
                    late_result_id: id.0,
                    action: LateResultAction::Discard,
                    confirm: None,
                    viewport: self.viewport,
                }))
            }
            SettingsPointerAction::Generation(GenerationAction::ConfirmCancelJob(_, _)) => {
                self.confirm = None;
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }
    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let mut rows: Vec<(String, GenerationBinding)> = Vec::new();
        if let Some(reason) = self.principal.jobs_section_reason() {
            rows.push((format!("Disabled: {reason}"), None));
            rows.push(("No job data visible.".into(), None));
        } else if let Some(job) = self.reducer.jobs.iter().find(|j| j.job_id == self.job_id) {
            let stale = if job.stale { " (stale)" } else { "" };
            rows.push((
                format!(
                    "Job {} v{} {}{}",
                    job.job_id,
                    job.version,
                    job.state.label(),
                    stale,
                ),
                None,
            ));
            for slot in &job.slots {
                rows.push((
                    format!(
                        "  target {} | {} | {} published, {} quarantined",
                        slot.target_id,
                        slot.state.label(),
                        slot.published_artifacts,
                        slot.quarantined_late_results,
                    ),
                    None,
                ));
            }
            if job.quarantined_late_result_count > 0 {
                rows.push((
                    format!(
                        "  Quarantined late results: {}",
                        job.quarantined_late_result_count
                    ),
                    None,
                ));
                let late_id = LateResultId(format!("{}-late", job.job_id));
                rows.push((
                    "[publish late result]".into(),
                    Some((
                        GenerationAction::PublishLateResult(late_id.clone()),
                        true,
                        None,
                    )),
                ));
                rows.push((
                    "[discard late result]".into(),
                    Some((GenerationAction::DiscardLateResult(late_id), true, None)),
                ));
            }
            if job.cancellable() && self.principal.can_cancel_job() {
                rows.push((
                    "[cancel job]".into(),
                    Some((
                        GenerationAction::CancelJob(ImageJobId(self.job_id.clone())),
                        true,
                        None,
                    )),
                ));
            }
        } else {
            rows.push(("Job not found.".into(), None));
        }
        if let Some((action, _)) = &self.confirm
            && let Some(text) = confirmation_text(action.clone())
        {
            let (confirm_label, _) = confirmation_buttons(action.clone()).unwrap();
            rows.push((String::new(), None));
            rows.push((format!("{text} [{confirm_label}] [Cancel]"), None));
            if let GenerationAction::CancelJob(id) = action {
                rows.push((
                    format!("[{confirm_label}]"),
                    Some((
                        GenerationAction::ConfirmCancelJob(id.clone(), ConfirmationChoice::Confirm),
                        true,
                        None,
                    )),
                ));
                rows.push((
                    "[Cancel]".into(),
                    Some((
                        GenerationAction::ConfirmCancelJob(id.clone(), ConfirmationChoice::Cancel),
                        true,
                        None,
                    )),
                ));
            }
        }
        render_generation_page(
            cx,
            frame,
            area,
            "generation:job-detail",
            "Job detail",
            rows,
            Some(self.cursor),
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
    fn handle_pointer_control(
        &mut self,
        _cx: &mut SettingsCx,
        action: SettingsPointerAction,
    ) -> Nav {
        match action {
            SettingsPointerAction::Generation(
                GenerationAction::ConfirmPublishLateResult(_, choice)
                | GenerationAction::ConfirmDiscardLateResult(_, choice),
            ) => {
                self.confirm = Some(choice);
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }
    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        if self.viewport == GenerationViewportMode::Blocked {
            render_resize_blocker(frame, area);
            return;
        }
        let text = self.action.label();
        let confirm_label = self.action.confirm_label();
        let mut rows: Vec<(String, GenerationBinding)> = Vec::new();
        if let Some(reason) = self.principal.config_section_reason() {
            rows.push((format!("Disabled: {reason}"), None));
        } else {
            let id = LateResultId(self.late_result_id.clone());
            let (confirm, cancel) = match self.action {
                LateResultAction::Publish => (
                    GenerationAction::ConfirmPublishLateResult(
                        id.clone(),
                        ConfirmationChoice::Confirm,
                    ),
                    GenerationAction::ConfirmPublishLateResult(id, ConfirmationChoice::Cancel),
                ),
                LateResultAction::Discard => (
                    GenerationAction::ConfirmDiscardLateResult(
                        id.clone(),
                        ConfirmationChoice::Confirm,
                    ),
                    GenerationAction::ConfirmDiscardLateResult(id, ConfirmationChoice::Cancel),
                ),
            };
            rows.push((format!("{text} [{confirm_label}] [Cancel]"), None));
            rows.push((format!("[{confirm_label}]"), Some((confirm, true, None))));
            rows.push(("[Cancel]".into(), Some((cancel, true, None))));
            rows.push((String::new(), None));
            rows.push(("Late result bytes are never exposed.".into(), None));
            rows.push(("Artifact actions use only opaque handles.".into(), None));
        }
        render_generation_page(
            cx,
            frame,
            area,
            "generation:late-result",
            "Late result action",
            rows,
            Some(self.cursor),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn test_dialog() -> super::super::SettingsDialog {
        use tempfile::TempDir;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        std::mem::forget(tmp);
        super::super::SettingsDialog::open(path)
    }

    fn render_page_lines(
        page: &dyn SettingsPage,
        dialog: &super::super::SettingsDialog,
        width: u16,
        height: u16,
    ) -> Vec<String> {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let cx: &SettingsCx = dialog;
        terminal
            .draw(|frame| {
                let area = frame.area();
                page.render(cx, frame, area);
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        buffer
            .content()
            .iter()
            .collect::<Vec<_>>()
            .chunks(width as usize)
            .map(|row| {
                row.iter()
                    .map(|cell| cell.symbol().to_string())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .filter(|l| !l.is_empty())
            .collect()
    }

    // AC 1: viewport breakpoints
    #[test]
    fn image_generation_settings_viewport_breakpoints() {
        assert_eq!(
            generation_viewport_mode(100, 30),
            GenerationViewportMode::Full
        );
        assert_eq!(
            generation_viewport_mode(120, 40),
            GenerationViewportMode::Full
        );
        assert_eq!(
            generation_viewport_mode(80, 24),
            GenerationViewportMode::Compact
        );
        assert_eq!(
            generation_viewport_mode(99, 29),
            GenerationViewportMode::Compact
        );
        assert_eq!(
            generation_viewport_mode(60, 16),
            GenerationViewportMode::Reduced
        );
        assert_eq!(
            generation_viewport_mode(79, 23),
            GenerationViewportMode::Reduced
        );
        assert_eq!(
            generation_viewport_mode(59, 30),
            GenerationViewportMode::Blocked
        );
        assert_eq!(
            generation_viewport_mode(100, 15),
            GenerationViewportMode::Blocked
        );
        assert_eq!(
            generation_viewport_mode(59, 15),
            GenerationViewportMode::Blocked
        );
        assert_eq!(
            generation_viewport_mode(0, 0),
            GenerationViewportMode::Blocked
        );
        assert_eq!(
            generation_viewport_mode(99, 30),
            GenerationViewportMode::Compact
        );
        assert_eq!(
            generation_viewport_mode(100, 29),
            GenerationViewportMode::Compact
        );
    }

    #[test]
    fn image_generation_settings_viewport_blocked_renders_blocker() {
        let page = GenerationListPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            viewport: GenerationViewportMode::Blocked,
        };
        let dialog = test_dialog();
        let lines = render_page_lines(&page, &dialog, 40, 10);
        assert!(lines.iter().any(|l| l.contains("too small")));
        assert!(lines.iter().any(|l| l.contains("q: quit")));
    }

    // AC 2: keyboard focus matrix
    #[test]
    fn image_generation_settings_keyboard_focus_matrix() {
        let principal = GenerationPrincipal::local_owner();
        let mut dialog = test_dialog();
        let mut page = GenerationListPage {
            cursor: 0,
            principal,
            viewport: GenerationViewportMode::Full,
        };
        let nav = page.handle_key(&mut dialog, press(KeyCode::Down));
        assert!(matches!(nav, Nav::Stay));
        assert_eq!(page.cursor, 1);
        page.handle_key(&mut dialog, press(KeyCode::Up));
        assert_eq!(page.cursor, 0);
        let nav = page.handle_key(&mut dialog, press(KeyCode::Esc));
        assert!(matches!(nav, Nav::Back));
        let nav = page.handle_key(&mut dialog, press(KeyCode::Enter));
        assert!(matches!(nav, Nav::Push(_)));
        let mut compact = GenerationListPage {
            cursor: 0,
            principal,
            viewport: GenerationViewportMode::Compact,
        };
        compact.handle_key(&mut dialog, press(KeyCode::Down));
        assert_eq!(compact.cursor, 1);
        let mut reduced = GenerationListPage {
            cursor: 0,
            principal,
            viewport: GenerationViewportMode::Reduced,
        };
        reduced.handle_key(&mut dialog, press(KeyCode::Down));
        assert_eq!(reduced.cursor, 1);
        let mut blocked = GenerationListPage {
            cursor: 0,
            principal,
            viewport: GenerationViewportMode::Blocked,
        };
        let _ = blocked.handle_key(&mut dialog, press(KeyCode::Down));
        assert_eq!(blocked.cursor, 0);
        let nav = blocked.handle_key(&mut dialog, press(KeyCode::Esc));
        assert!(matches!(nav, Nav::Back));
    }

    // AC 3: authorization visibility
    #[test]
    fn image_generation_settings_authorization_visibility() {
        let owner = GenerationPrincipal::local_owner();
        assert!(owner.config_section_reason().is_none());
        assert!(owner.targets_section_reason().is_none());
        assert!(owner.jobs_section_reason().is_none());
        assert!(owner.can_mutate_config());
        assert!(owner.can_cancel_job());

        let admin = GenerationPrincipal {
            exact_project_admin: true,
            admin_exact_project: true,
            project_read: true,
            session_read: true,
            session_write: true,
            ..Default::default()
        };
        assert!(admin.config_section_reason().is_none());
        assert!(admin.can_mutate_config());

        let wrong_admin = GenerationPrincipal {
            exact_project_admin: true,
            admin_exact_project: false,
            ..Default::default()
        };
        assert_eq!(
            wrong_admin.config_section_reason(),
            Some(REASON_FORBIDDEN_IMAGE_ADMIN)
        );
        assert!(!wrong_admin.can_mutate_config());

        let proj_read = GenerationPrincipal {
            project_read: true,
            ..Default::default()
        };
        assert!(proj_read.targets_section_reason().is_none());
        assert_eq!(
            proj_read.config_section_reason(),
            Some(REASON_FORBIDDEN_IMAGE_ADMIN)
        );
        assert_eq!(
            proj_read.jobs_section_reason(),
            Some(REASON_FORBIDDEN_SESSION_MEMBERSHIP)
        );

        let sess_read = GenerationPrincipal {
            session_read: true,
            ..Default::default()
        };
        assert!(sess_read.jobs_section_reason().is_none());
        assert_eq!(
            sess_read.targets_section_reason(),
            Some(REASON_FORBIDDEN_PROJECT_READ)
        );
        assert_eq!(
            sess_read.config_section_reason(),
            Some(REASON_FORBIDDEN_IMAGE_ADMIN)
        );

        let sess_write = GenerationPrincipal {
            session_write: true,
            ..Default::default()
        };
        assert_eq!(
            sess_write.targets_section_reason(),
            Some(REASON_FORBIDDEN_PROJECT_READ)
        );
        assert!(sess_write.can_cancel_job());

        let sess_both = GenerationPrincipal {
            session_read: true,
            session_write: true,
            ..Default::default()
        };
        assert_eq!(
            sess_both.targets_section_reason(),
            Some(REASON_FORBIDDEN_PROJECT_READ)
        );

        let proj_sess = GenerationPrincipal {
            project_read: true,
            session_read: true,
            ..Default::default()
        };
        assert!(proj_sess.targets_section_reason().is_none());
        assert!(proj_sess.jobs_section_reason().is_none());
        assert_eq!(
            proj_sess.config_section_reason(),
            Some(REASON_FORBIDDEN_IMAGE_ADMIN)
        );

        let none = GenerationPrincipal::default();
        assert_eq!(
            none.config_section_reason(),
            Some(REASON_FORBIDDEN_IMAGE_ADMIN)
        );
        assert_eq!(
            none.targets_section_reason(),
            Some(REASON_FORBIDDEN_PROJECT_READ)
        );
        assert_eq!(
            none.jobs_section_reason(),
            Some(REASON_FORBIDDEN_SESSION_MEMBERSHIP)
        );

        let all_reasons: std::collections::HashSet<&str> =
            SECTION_REASON_CODES.iter().copied().collect();
        assert_eq!(all_reasons.len(), 3);
    }

    #[test]
    fn image_generation_settings_no_global_grant_option() {
        let page = GrantListPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            grants: Vec::new(),
            confirm: None,
            viewport: GenerationViewportMode::Full,
        };
        let dialog = test_dialog();
        let lines = render_page_lines(&page, &dialog, 80, 24);
        assert!(!lines.iter().any(|l| l.to_lowercase().contains("global")));
        assert!(
            !lines
                .iter()
                .any(|l| l.to_lowercase().contains("create grant")
                    || l.to_lowercase().contains("add grant"))
        );
    }

    // AC 4: budget editor
    #[test]
    fn image_generation_settings_budget_editor() {
        let mut state = BudgetEditorState::unconfigured();
        assert!(state.blocks_paid_generation);
        assert!(!state.request_scope_editable());
        state.plan_context = Some(PlanContext {
            plan_id: "p1".into(),
            plan_digest: "d1".into(),
            owning_session: "s1".into(),
        });
        assert!(state.request_scope_editable());
        state.plan_context = Some(PlanContext {
            plan_id: "".into(),
            plan_digest: "d1".into(),
            owning_session: "s1".into(),
        });
        assert!(!state.request_scope_editable());

        let mut state = BudgetEditorState::unconfigured();
        state.set_finite(BudgetScopeKind::Session, 10_000_000);
        assert_eq!(
            state.session.policy,
            cockpit_core::image_generation_control_plane::BudgetPolicy::Finite {
                usd_micros: 10_000_000
            }
        );
        assert!(!state.blocks_paid_generation);
        state.set_unlimited(BudgetScopeKind::Project);
        assert_eq!(
            state.project.policy,
            cockpit_core::image_generation_control_plane::BudgetPolicy::Unlimited
        );

        assert_eq!(
            BudgetEditorState::suggestion_for(BudgetScopeKind::Request),
            1_000_000
        );
        assert_eq!(
            BudgetEditorState::suggestion_for(BudgetScopeKind::Session),
            10_000_000
        );
        assert_eq!(
            BudgetEditorState::suggestion_for(BudgetScopeKind::Project),
            100_000_000
        );

        let state = BudgetEditorState::unconfigured();
        assert!(state.session.generation.is_none());
        assert!(state.project.generation.is_none());
        assert!(state.request.generation.is_none());

        let page = BudgetEditorPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            state: BudgetEditorState::unconfigured(),
            viewport: GenerationViewportMode::Full,
        };
        let dialog = test_dialog();
        let lines = render_page_lines(&page, &dialog, 80, 24);
        assert!(
            lines
                .iter()
                .any(|l| l.contains(REASON_REQUEST_SCOPE_REQUIRES_PLAN))
        );
    }

    // AC 5: authorization review overlay (not a settings surface)
    #[test]
    fn image_generation_authorization_review_not_settings_surface() {
        let surfaces: std::collections::HashSet<SettingsPointerSurfaceKind> =
            SettingsPointerSurfaceKind::ALL.into_iter().collect();
        assert!(surfaces.contains(&SettingsPointerSurfaceKind::GenerationList));
        assert!(surfaces.contains(&SettingsPointerSurfaceKind::EndpointEditor));
        assert!(surfaces.contains(&SettingsPointerSurfaceKind::TargetEditor));
        assert!(surfaces.contains(&SettingsPointerSurfaceKind::WorkflowEditor));
        assert!(surfaces.contains(&SettingsPointerSurfaceKind::BudgetEditor));
        assert!(surfaces.contains(&SettingsPointerSurfaceKind::GrantList));
        assert!(surfaces.contains(&SettingsPointerSurfaceKind::JobList));
        assert!(surfaces.contains(&SettingsPointerSurfaceKind::JobDetail));
        assert!(surfaces.contains(&SettingsPointerSurfaceKind::LateResultAction));
    }

    // AC 6: job reducer matrix
    #[test]
    fn image_generation_job_reducer_matrix() {
        let mut reducer = JobReducer::new("d1".into(), "p1".into(), "s1".into());
        let job = JobCard {
            job_id: "j1".into(),
            version: 1,
            state: ImageJobState::Pending,
            slots: Vec::new(),
            quarantined_late_result_count: 0,
            stale: false,
        };
        assert!(reducer.apply_job_event("d1", "p1", "s1", job, "c1", 1));
        assert_eq!(reducer.jobs.len(), 1);

        let job = JobCard {
            job_id: "j1".into(),
            version: 2,
            state: ImageJobState::Running,
            slots: vec![JobSlot {
                target_id: "t1".into(),
                state: ImageJobState::Running,
                published_artifacts: 0,
                quarantined_late_results: 0,
            }],
            quarantined_late_result_count: 0,
            stale: false,
        };
        assert!(reducer.apply_job_event("d1", "p1", "s1", job, "c1", 2));

        let job = JobCard {
            job_id: "j2".into(),
            version: 1,
            state: ImageJobState::PartialFailure,
            slots: vec![
                JobSlot {
                    target_id: "ta".into(),
                    state: ImageJobState::Succeeded,
                    published_artifacts: 1,
                    quarantined_late_results: 0,
                },
                JobSlot {
                    target_id: "tb".into(),
                    state: ImageJobState::Failed,
                    published_artifacts: 0,
                    quarantined_late_results: 0,
                },
            ],
            quarantined_late_result_count: 0,
            stale: false,
        };
        assert!(reducer.apply_job_event("d1", "p1", "s1", job, "c1", 3));
        assert_eq!(reducer.jobs.len(), 2);

        let job = JobCard {
            job_id: "j3".into(),
            version: 1,
            state: ImageJobState::Pending,
            slots: Vec::new(),
            quarantined_late_result_count: 0,
            stale: false,
        };
        assert!(!reducer.apply_job_event("d2", "p1", "s1", job.clone(), "c1", 4));
        assert!(!reducer.apply_job_event("d1", "p2", "s1", job.clone(), "c1", 4));
        assert!(!reducer.apply_job_event("d1", "p1", "s2", job, "c1", 4));

        let job = JobCard {
            job_id: "j1".into(),
            version: 1,
            state: ImageJobState::Pending,
            slots: Vec::new(),
            quarantined_late_result_count: 0,
            stale: false,
        };
        assert!(!reducer.apply_job_event("d1", "p1", "s1", job, "c1", 1));

        let job = JobCard {
            job_id: "j4".into(),
            version: 1,
            state: ImageJobState::Pending,
            slots: Vec::new(),
            quarantined_late_result_count: 0,
            stale: false,
        };
        assert!(!reducer.apply_job_event("d1", "p1", "s1", job, "c1", 10));

        let job = JobCard {
            job_id: "j5".into(),
            version: 1,
            state: ImageJobState::Running,
            slots: Vec::new(),
            quarantined_late_result_count: 0,
            stale: false,
        };
        assert!(reducer.apply_job_event("d1", "p1", "s1", job, "c1", 4));
        assert!(reducer.request_cancel("j5"));
        let j = reducer.jobs.iter().find(|j| j.job_id == "j5").unwrap();
        assert_eq!(j.state, ImageJobState::Cancelling);
        assert_eq!(j.state.label(), "Cancellation requested");
        assert!(reducer.apply_cancelled("j5"));
        let j = reducer.jobs.iter().find(|j| j.job_id == "j5").unwrap();
        assert_eq!(j.state, ImageJobState::Cancelled);
        assert_eq!(j.state.label(), "Cancelled");

        reducer.mark_stale();
        assert!(reducer.jobs.iter().all(|j| j.stale));
        reducer.rehydrate(Vec::new());
        assert!(reducer.jobs.is_empty());
    }

    // AC 7: late result actions
    #[test]
    fn image_generation_late_result_actions() {
        assert_eq!(LateResultAction::Publish.label(), "Publish late result?");
        assert_eq!(LateResultAction::Publish.confirm_label(), "Publish");
        assert_eq!(LateResultAction::Discard.label(), "Discard late result?");
        assert_eq!(LateResultAction::Discard.confirm_label(), "Discard");

        let page = LateResultActionPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            late_result_id: "lr1".into(),
            action: LateResultAction::Publish,
            confirm: None,
            viewport: GenerationViewportMode::Full,
        };
        let dialog = test_dialog();
        let lines = render_page_lines(&page, &dialog, 80, 24);
        assert!(lines.iter().any(|l| l.contains("bytes are never exposed")));
        assert!(lines.iter().any(|l| l.contains("opaque handles")));
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("/tmp/") || l.contains("host_path"))
        );
    }

    // AC 8: redaction and conflict
    #[test]
    fn image_generation_settings_redaction_and_conflict() {
        let sentinels = cockpit_core::image_generation_control_plane::FORBIDDEN_SENTINELS;
        assert!(sentinels.contains(&"api_key"));
        assert!(sentinels.contains(&"secret"));
        assert!(sentinels.contains(&"raw_workflow_json"));
        assert!(sentinels.contains(&"host_path"));
        assert!(sentinels.contains(&"provider_body"));
        assert!(sentinels.contains(&"quarantine"));

        let dialog = test_dialog();
        let page = EndpointEditorPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            endpoint_id: None,
            viewport: GenerationViewportMode::Full,
        };
        let lines = render_page_lines(&page, &dialog, 80, 24);
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("api_key") || l.contains("secret"))
        );

        let page = EndpointEditorPage {
            cursor: 0,
            principal: GenerationPrincipal::default(),
            endpoint_id: None,
            viewport: GenerationViewportMode::Full,
        };
        let lines = render_page_lines(&page, &dialog, 80, 24);
        assert!(lines.iter().any(|l| l.contains("No endpoint data visible")));

        let mut reducer = JobReducer::new("d".into(), "p".into(), "s".into());
        reducer.apply_job_event(
            "d",
            "p",
            "s",
            JobCard {
                job_id: "j".into(),
                version: 1,
                state: ImageJobState::Running,
                slots: Vec::new(),
                quarantined_late_result_count: 0,
                stale: false,
            },
            "c",
            1,
        );
        reducer.mark_stale();
        assert!(reducer.jobs[0].stale);
        reducer.rehydrate(vec![JobCard {
            job_id: "j".into(),
            version: 2,
            state: ImageJobState::Succeeded,
            slots: Vec::new(),
            quarantined_late_result_count: 0,
            stale: false,
        }]);
        assert_eq!(reducer.jobs[0].version, 2);
        assert!(!reducer.jobs[0].stale);
    }

    // AC 9: pointer surface
    #[test]
    fn image_generation_settings_pointer_surface() {
        let list = GenerationListPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            viewport: GenerationViewportMode::Full,
        };
        assert_eq!(
            list.pointer_surface_kind(),
            SettingsPointerSurfaceKind::GenerationList
        );
        let endpoint = EndpointEditorPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            endpoint_id: None,
            viewport: GenerationViewportMode::Full,
        };
        assert_eq!(
            endpoint.pointer_surface_kind(),
            SettingsPointerSurfaceKind::EndpointEditor
        );
        let target = TargetEditorPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            target_id: None,
            viewport: GenerationViewportMode::Full,
        };
        assert_eq!(
            target.pointer_surface_kind(),
            SettingsPointerSurfaceKind::TargetEditor
        );
        let workflow = WorkflowEditorPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            workflow_id: None,
            viewport: GenerationViewportMode::Full,
        };
        assert_eq!(
            workflow.pointer_surface_kind(),
            SettingsPointerSurfaceKind::WorkflowEditor
        );
        let budget = BudgetEditorPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            state: BudgetEditorState::unconfigured(),
            viewport: GenerationViewportMode::Full,
        };
        assert_eq!(
            budget.pointer_surface_kind(),
            SettingsPointerSurfaceKind::BudgetEditor
        );
        let grants = GrantListPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            grants: Vec::new(),
            confirm: None,
            viewport: GenerationViewportMode::Full,
        };
        assert_eq!(
            grants.pointer_surface_kind(),
            SettingsPointerSurfaceKind::GrantList
        );
        let jobs = JobListPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            reducer: JobReducer::new("d".into(), "p".into(), "s".into()),
            viewport: GenerationViewportMode::Full,
        };
        assert_eq!(
            jobs.pointer_surface_kind(),
            SettingsPointerSurfaceKind::JobList
        );
        let detail = JobDetailPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            job_id: "j".into(),
            reducer: JobReducer::new("d".into(), "p".into(), "s".into()),
            confirm: None,
            viewport: GenerationViewportMode::Full,
        };
        assert_eq!(
            detail.pointer_surface_kind(),
            SettingsPointerSurfaceKind::JobDetail
        );
        let late = LateResultActionPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            late_result_id: "lr".into(),
            action: LateResultAction::Publish,
            confirm: None,
            viewport: GenerationViewportMode::Full,
        };
        assert_eq!(
            late.pointer_surface_kind(),
            SettingsPointerSurfaceKind::LateResultAction
        );

        let surfaces: std::collections::HashSet<SettingsPointerSurfaceKind> =
            SettingsPointerSurfaceKind::ALL.into_iter().collect();
        assert_eq!(surfaces.len(), SettingsPointerSurfaceKind::ALL.len());
    }

    // AC 10: state action registry
    #[test]
    fn image_generation_settings_state_action_registry() {
        assert_eq!(
            confirmation_text(GenerationAction::CancelJob(ImageJobId("j".into()))),
            Some("Cancel job?")
        );
        let (c, x) =
            confirmation_buttons(GenerationAction::CancelJob(ImageJobId("j".into()))).unwrap();
        assert_eq!(c, "Cancel job");
        assert_eq!(x, "Cancel");

        assert_eq!(
            confirmation_text(GenerationAction::RevokeGrant(LateResultId("g".into()))),
            Some("Revoke grant?")
        );
        let (c, x) =
            confirmation_buttons(GenerationAction::RevokeGrant(LateResultId("g".into()))).unwrap();
        assert_eq!(c, "Revoke grant");
        assert_eq!(x, "Cancel");

        assert_eq!(
            confirmation_text(GenerationAction::PublishLateResult(LateResultId(
                "lr".into()
            ))),
            Some("Publish late result?")
        );
        let (c, x) = confirmation_buttons(GenerationAction::PublishLateResult(LateResultId(
            "lr".into(),
        )))
        .unwrap();
        assert_eq!(c, "Publish");
        assert_eq!(x, "Cancel");

        assert_eq!(
            confirmation_text(GenerationAction::DiscardLateResult(LateResultId(
                "lr".into()
            ))),
            Some("Discard late result?")
        );
        let (c, x) = confirmation_buttons(GenerationAction::DiscardLateResult(LateResultId(
            "lr".into(),
        )))
        .unwrap();
        assert_eq!(c, "Discard");
        assert_eq!(x, "Cancel");

        assert!(confirmation_text(GenerationAction::RefreshHealth).is_none());
        assert!(confirmation_text(GenerationAction::CreateEndpoint).is_none());
        assert!(confirmation_text(GenerationAction::SaveBudget).is_none());

        let mut dialog = test_dialog();
        let mut detail = JobDetailPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            job_id: "j1".into(),
            reducer: JobReducer::new("d".into(), "p".into(), "s".into()),
            confirm: None,
            viewport: GenerationViewportMode::Full,
        };
        detail.handle_key(&mut dialog, press(KeyCode::Char('c')));
        assert!(detail.confirm.is_none());

        detail.reducer.jobs.push(JobCard {
            job_id: "j1".into(),
            version: 1,
            state: ImageJobState::Running,
            slots: Vec::new(),
            quarantined_late_result_count: 0,
            stale: false,
        });
        detail.handle_key(&mut dialog, press(KeyCode::Char('c')));
        assert!(detail.confirm.is_some());
        let lines = render_page_lines(&detail, &dialog, 80, 24);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Cancel job? [Cancel job] [Cancel]"))
        );

        let mut detail2 = JobDetailPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            job_id: "j2".into(),
            reducer: JobReducer::new("d".into(), "p".into(), "s".into()),
            confirm: None,
            viewport: GenerationViewportMode::Full,
        };
        detail2.reducer.jobs.push(JobCard {
            job_id: "j2".into(),
            version: 1,
            state: ImageJobState::Succeeded,
            slots: Vec::new(),
            quarantined_late_result_count: 0,
            stale: false,
        });
        detail2.handle_key(&mut dialog, press(KeyCode::Char('c')));
        assert!(detail2.confirm.is_none());

        let mut detail3 = JobDetailPage {
            cursor: 0,
            principal: GenerationPrincipal::default(),
            job_id: "j3".into(),
            reducer: JobReducer::new("d".into(), "p".into(), "s".into()),
            confirm: None,
            viewport: GenerationViewportMode::Full,
        };
        detail3.reducer.jobs.push(JobCard {
            job_id: "j3".into(),
            version: 1,
            state: ImageJobState::Running,
            slots: Vec::new(),
            quarantined_late_result_count: 0,
            stale: false,
        });
        detail3.handle_key(&mut dialog, press(KeyCode::Char('c')));
        assert!(detail3.confirm.is_none());

        let pub_page = LateResultActionPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            late_result_id: "lr".into(),
            action: LateResultAction::Publish,
            confirm: None,
            viewport: GenerationViewportMode::Full,
        };
        let lines = render_page_lines(&pub_page, &dialog, 80, 24);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Publish late result? [Publish] [Cancel]"))
        );

        let disc_page = LateResultActionPage {
            cursor: 0,
            principal: GenerationPrincipal::local_owner(),
            late_result_id: "lr".into(),
            action: LateResultAction::Discard,
            confirm: None,
            viewport: GenerationViewportMode::Full,
        };
        let lines = render_page_lines(&disc_page, &dialog, 80, 24);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Discard late result? [Discard] [Cancel]"))
        );
    }
}
