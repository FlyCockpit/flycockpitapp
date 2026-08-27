//! TUI image-sidecar selection, egress-grant, and accounting settings.
//!
//! This module is presentation-only. It consumes typed projections and
//! constructs typed save/grant requests. It does not run selection, grant
//! matching, dispatch, or journal internals.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use cockpit_config::config::media_budget::MediaResourceLimits;
use cockpit_core::image_sidecar::{
    ApprovalMode, GrantScope, InvocationDisposition, InvocationState, MediaClass, Purpose,
    SidecarInvocationCapProvenance, SidecarProviderModel, SidecarSelectionConfig,
};

use super::pointer_actions::{
    ConfirmationChoice, SettingsPointerAction, SidecarAction, SidecarGrantId, SidecarInvocationId,
    SidecarModeChoice, SidecarModelRef, SidecarNodeId,
};
use super::shell::SettingsScrollRegionId;
use super::{Nav, PageBox, SettingsCx, SettingsPage, SettingsPointerSurfaceKind};

#[cfg(test)]
mod tests;

const PROJECT_GRANT_WARNING: &str = "Each use still requires this session's current project authorization and is audited separately.";

const REASON_STALE_CAPABILITY: &str = "stale_capability";
const REASON_MISSING_SELECTION: &str = "missing_selection";
const REASON_INVALID_OVERRIDE: &str = "invalid_override";
const REASON_CAP_EXHAUSTED: &str = "cap_exhausted";
const REASON_DESTINATION_DENIED: &str = "destination_denied";
const REASON_PROJECT_SESSION_MISMATCH: &str = "project_session_mismatch";
const REASON_REVOKED_GRANT: &str = "revoked_grant";
const REASON_MISSING_CREDENTIAL: &str = "missing_credential";
const REASON_PROVIDER_FAILURE: &str = "provider_failure";
const REASON_REVOKE_REQUIRES_AUTHORIZATION: &str = "revoke_requires_current_authorization";
const REASON_REVOKE_CONFIRMATION_STALE: &str = "revoke_confirmation_stale";
const REASON_YOLO_NO_GRANT: &str = "yolo_no_standing_grant";
const REASON_SAVE_PENDING: &str = "save_pending";
const REASON_FORBIDDEN_SIDECAR_ADMIN: &str = "forbidden_requires_sidecar_admin";
const REASON_AUTHORITATIVE_UNAVAILABLE: &str = "authoritative_sidecar_operation_unavailable";
const REASON_INVOCATION_NOT_FOUND: &str = "invocation_not_found";

const SIDECAR_NODE_TITLES: &[&str] = &[
    "Mode",
    "Trusted / untrusted defaults",
    "Per-primary override",
    "Central invocation policy",
    "Resolver trace",
    "Health",
    "Destination grants",
    "Invocation history",
];

// ---------------------------------------------------------------------------
// Viewport
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SidecarViewportMode {
    Full,
    Compact,
    Reduced,
    Blocked,
}

pub(crate) fn sidecar_viewport_mode(width: u16, height: u16) -> SidecarViewportMode {
    if width >= 100 && height >= 30 {
        SidecarViewportMode::Full
    } else if width >= 80 && height >= 24 {
        SidecarViewportMode::Compact
    } else if width >= 60 && height >= 16 {
        SidecarViewportMode::Reduced
    } else {
        SidecarViewportMode::Blocked
    }
}

// ---------------------------------------------------------------------------
// Principal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SidecarPrincipal {
    pub local_owner: bool,
    pub project_read: bool,
    pub session_read: bool,
    pub session_write: bool,
}

impl SidecarPrincipal {
    pub(crate) fn from_session(
        snapshot: &super::image_generation::SessionCapabilitySnapshot,
    ) -> Self {
        Self {
            local_owner: snapshot.local_owner,
            project_read: snapshot.local_owner || snapshot.project_read,
            session_read: snapshot.local_owner || snapshot.session_read,
            session_write: snapshot.local_owner || snapshot.session_write,
        }
    }

    #[cfg(test)]
    pub(crate) fn local_owner() -> Self {
        Self {
            local_owner: true,
            project_read: true,
            session_read: true,
            session_write: true,
        }
    }

    pub(crate) fn can_mutate(&self) -> bool {
        self.local_owner
    }

    pub(crate) fn can_revoke(&self) -> bool {
        self.local_owner || self.session_write
    }

    pub(crate) fn config_reason(&self) -> Option<&'static str> {
        if self.can_mutate() {
            None
        } else {
            Some(REASON_FORBIDDEN_SIDECAR_ADMIN)
        }
    }
}

// ---------------------------------------------------------------------------
// View models (typed projections the UI consumes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SidecarModelOption {
    pub provider: String,
    pub model: String,
    /// Only the daemon's explicit configured-model projection may be offered
    /// as a sidecar destination. Catalog discovery is not authorization.
    pub configured: bool,
    pub image_capable: bool,
    pub fresh: bool,
}

impl SidecarModelOption {
    pub(crate) fn is_selectable(&self) -> bool {
        self.configured && self.image_capable && self.fresh
    }
}

pub(crate) fn filter_selectable_sidecar_models(
    catalog: &[SidecarModelOption],
) -> Vec<&SidecarModelOption> {
    catalog.iter().filter(|m| m.is_selectable()).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SidecarEffectiveTrace {
    pub primary_provider: String,
    pub primary_model: String,
    pub primary_trust: String,
    pub matched_source: String,
    pub sidecar_provider: Option<String>,
    pub sidecar_model: Option<String>,
    pub origin: String,
    pub location: String,
    pub credential_fingerprint: String,
    pub capability_source: String,
    pub capability_freshness: String,
    pub config_generation: u64,
    pub mode: SidecarModeChoice,
    pub available: bool,
    pub fallback_outcome: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CentralPolicyView {
    pub value: u64,
    pub source: SidecarInvocationCapProvenance,
    pub hard_ceiling: u64,
}

impl CentralPolicyView {
    pub(crate) fn source_label(&self) -> &'static str {
        match self.source {
            SidecarInvocationCapProvenance::CompiledCeiling => "compiled_ceiling",
            SidecarInvocationCapProvenance::Configured => "configured",
            SidecarInvocationCapProvenance::Profile => "profile",
            SidecarInvocationCapProvenance::Adapter => "adapter",
            SidecarInvocationCapProvenance::Request => "request",
        }
    }

    pub(crate) fn render_line(&self) -> String {
        format!(
            "Effective: {} source={} hard_ceiling={}",
            self.value,
            self.source_label(),
            self.hard_ceiling
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HealthView {
    pub available: bool,
    pub capability_source: String,
    pub freshness: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantView {
    pub grant_id: String,
    pub version: u64,
    pub project: String,
    pub destination: String,
    pub media_class: String,
    pub purpose: String,
    pub scope: GrantScope,
    pub session_binding: Option<String>,
    pub invocation_binding: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked: bool,
    pub consumed: bool,
}

impl GrantView {
    pub(crate) fn project_warning(&self) -> Option<&'static str> {
        if self.scope == GrantScope::Project {
            Some(PROJECT_GRANT_WARNING)
        } else {
            None
        }
    }

    pub(crate) fn row_text(&self) -> String {
        format!(
            "{} | project={} dest={} media={} purpose={} scope={}{}{} created={} used={} revoked={} consumed={}",
            self.grant_id,
            self.project,
            sanitized_display_origin(&self.destination),
            self.media_class,
            self.purpose,
            self.scope.as_str(),
            self.session_binding
                .as_deref()
                .map(|s| format!(" session={s}"))
                .unwrap_or_default(),
            self.invocation_binding
                .as_deref()
                .map(|s| format!(" invocation={s}"))
                .unwrap_or_default(),
            self.created_at,
            self.last_used_at.as_deref().unwrap_or("-"),
            self.revoked,
            self.consumed,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnerTechnicalDetail {
    pub purpose: String,
    pub instruction_version: u8,
    pub body_digest_hex: String,
    pub unicode_scalar_len: usize,
    pub utf8_byte_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InvocationView {
    pub invocation_id: String,
    pub parent_operation: String,
    pub session: String,
    pub purpose_label: String,
    pub provider: String,
    pub model: String,
    pub location: String,
    pub state: InvocationState,
    pub created_at: String,
    pub dispatched_at: Option<String>,
    pub terminal_at: Option<String>,
    pub grant_id: Option<String>,
    pub disposition: InvocationDisposition,
    pub usage_input_tokens: Option<u64>,
    pub usage_output_tokens: Option<u64>,
    pub usage_cost_micro_usd: Option<u64>,
    pub sidecar_invocation_charged: bool,
    pub media_reservation_id: Option<String>,
    pub provider_concurrency_slot: Option<String>,
    pub safe_error: Option<String>,
    pub owner_detail: Option<OwnerTechnicalDetail>,
}

impl InvocationView {
    pub(crate) fn row_text(&self) -> String {
        format!(
            "{} | purpose={} parent={} session={} {}:{} loc={} state={} grant={} disposition={} charged={}",
            self.invocation_id,
            self.purpose_label,
            self.parent_operation,
            self.session,
            self.provider,
            self.model,
            self.location,
            self.state.as_str(),
            self.grant_id.as_deref().unwrap_or("-"),
            self.disposition.as_str(),
            self.sidecar_invocation_charged,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustDisclosure {
    pub trust_class: &'static str,
    pub redaction: String,
}

impl TrustDisclosure {
    pub(crate) fn for_trust(trusted: bool) -> Self {
        if trusted {
            Self {
                trust_class: "trusted",
                redaction: "Standard redaction. Trust does not grant egress.".into(),
            }
        } else {
            Self {
                trust_class: "untrusted",
                redaction: "Additional redaction applies. Trust does not grant egress.".into(),
            }
        }
    }

    pub(crate) fn lines(&self) -> Vec<String> {
        vec![
            format!("Trust class: {}", self.trust_class),
            self.redaction.clone(),
            "Egress authority is independent of trust class.".into(),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EgressAuthorityView {
    pub grant_required: bool,
    pub destination: String,
    pub scopes: Vec<GrantScope>,
}

impl EgressAuthorityView {
    pub(crate) fn shared(destination: impl Into<String>) -> Self {
        Self {
            grant_required: true,
            destination: destination.into(),
            scopes: vec![GrantScope::Once, GrantScope::Session, GrantScope::Project],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirstUseView {
    pub mode: ApprovalMode,
    pub grant_choices: Vec<GrantScope>,
    pub yolo_label: Option<&'static str>,
    pub standing_grant: bool,
    pub prompt: bool,
}

impl FirstUseView {
    pub(crate) fn for_mode(mode: ApprovalMode) -> Self {
        match mode {
            ApprovalMode::Ask => Self {
                mode,
                grant_choices: vec![GrantScope::Once, GrantScope::Session, GrantScope::Project],
                yolo_label: None,
                standing_grant: false,
                prompt: true,
            },
            ApprovalMode::Yolo => Self {
                mode,
                grant_choices: Vec::new(),
                yolo_label: Some("agent_discretion"),
                standing_grant: false,
                prompt: false,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SidecarRowView {
    pub label: String,
    pub value: String,
    pub state: String,
    pub destination: Option<String>,
    pub scope: Option<String>,
    pub error: Option<String>,
    pub project_grant_warning: Option<String>,
    pub busy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SidecarA11yProjection {
    pub focused_label: String,
    pub focused_value: String,
    pub effective_policy: String,
    pub effective_value: String,
    pub effective_source: String,
    pub destination: String,
    pub scope: String,
    pub non_color_state: String,
    pub busy: bool,
    pub error: Option<String>,
    pub project_grant_warning: Option<String>,
}

/// One source of truth for a rendered line, its control contract, and the
/// accessibility facts exposed for that exact line.  Keeping these together
/// prevents keyboard focus, pointer targets, and the bounded linearized
/// projection from drifting apart as a page gains headings or status rows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SidecarRenderedRow {
    text: String,
    binding: SidecarBinding,
    view: SidecarRowView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SidecarRemediation {
    MissingSelection,
    InvalidOverride,
    StaleCapability,
    CapExhausted,
    DestinationDenied,
    ProjectSessionMismatch,
    RevokedGrant,
    MissingCredential,
    ProviderFailure,
}

impl SidecarRemediation {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::MissingSelection => REASON_MISSING_SELECTION,
            Self::InvalidOverride => REASON_INVALID_OVERRIDE,
            Self::StaleCapability => REASON_STALE_CAPABILITY,
            Self::CapExhausted => REASON_CAP_EXHAUSTED,
            Self::DestinationDenied => REASON_DESTINATION_DENIED,
            Self::ProjectSessionMismatch => REASON_PROJECT_SESSION_MISMATCH,
            Self::RevokedGrant => REASON_REVOKED_GRANT,
            Self::MissingCredential => REASON_MISSING_CREDENTIAL,
            Self::ProviderFailure => REASON_PROVIDER_FAILURE,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::MissingSelection => "Missing selection — choose a sidecar model.",
            Self::InvalidOverride => "Invalid override — pick a freshly image-capable model.",
            Self::StaleCapability => "Stale capability — refresh health, then retry.",
            Self::CapExhausted => "Cap exhausted — wait for the session or raise the central cap.",
            Self::DestinationDenied => {
                "Destination denied — review grants or destination identity."
            }
            Self::ProjectSessionMismatch => {
                "Project/session mismatch — rebind to the current session."
            }
            Self::RevokedGrant => "Grant revoked — create a new grant to continue.",
            Self::MissingCredential => "Missing credential — configure provider credentials.",
            Self::ProviderFailure => "Provider failure — retry after the provider recovers.",
        }
    }
}

pub(crate) fn strip_query_and_fragment(origin: &str) -> String {
    sanitized_display_origin(origin)
}

fn sanitized_display_origin(origin: &str) -> String {
    let without_query = origin
        .split(['?', '#'])
        .next()
        .unwrap_or(origin)
        .to_string();
    let Some(scheme_end) = without_query.find("://") else {
        return without_query;
    };
    let authority_start = scheme_end + 3;
    let authority_end = without_query[authority_start..]
        .find('/')
        .map_or(without_query.len(), |offset| authority_start + offset);
    let authority = &without_query[authority_start..authority_end];
    let Some(userinfo_end) = authority.rfind('@') else {
        return without_query;
    };
    format!(
        "{}{}",
        &without_query[..authority_start],
        &without_query[authority_start + userinfo_end + 1..]
    )
}

pub(crate) fn offered_grant_scopes() -> [GrantScope; 3] {
    [GrantScope::Once, GrantScope::Session, GrantScope::Project]
}

// ---------------------------------------------------------------------------
// Form + reducer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SidecarFormState {
    pub mode: SidecarModeChoice,
    pub trusted_default: Option<SidecarModelRef>,
    pub untrusted_default: Option<SidecarModelRef>,
    pub override_pair: Option<SidecarModelRef>,
    pub central_cap: u64,
    pub models: Vec<SidecarModelOption>,
    pub draft_scope: GrantScope,
    pub local_edits_preserved: bool,
}

impl Default for SidecarFormState {
    fn default() -> Self {
        Self {
            mode: SidecarModeChoice::Automatic,
            trusted_default: None,
            untrusted_default: None,
            override_pair: None,
            central_cap: MediaResourceLimits::defaults().sidecar_invocations_per_session,
            models: Vec::new(),
            draft_scope: GrantScope::Once,
            local_edits_preserved: false,
        }
    }
}

impl SidecarFormState {
    pub(crate) fn to_selection_config(&self) -> SidecarSelectionConfig {
        let to_pair = |r: &SidecarModelRef| SidecarProviderModel {
            provider: r.provider.clone(),
            model: r.model.clone(),
        };
        let selected = |candidate: &Option<SidecarModelRef>| {
            candidate.as_ref().filter(|candidate| {
                self.selectable_models().iter().any(|model| {
                    model.provider == candidate.provider && model.model == candidate.model
                })
            })
        };
        SidecarSelectionConfig {
            mode: self.mode.to_core(),
            trusted_primary_default: selected(&self.trusted_default).map(to_pair),
            untrusted_primary_default: selected(&self.untrusted_default).map(to_pair),
            per_primary_override: selected(&self.override_pair).map(to_pair),
        }
    }

    pub(crate) fn selectable_models(&self) -> Vec<&SidecarModelOption> {
        filter_selectable_sidecar_models(&self.models)
    }

    pub(crate) fn set_central_cap(&mut self, value: u64) {
        let ceiling = MediaResourceLimits::hard_ceilings().sidecar_invocations_per_session;
        self.central_cap = value.min(ceiling).max(1);
        self.local_edits_preserved = true;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SidecarEventOutcome {
    Applied,
    Discarded,
    RehydrateRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SidecarEventPayload {
    Health(HealthView),
    Grant(GrantView),
    Invocation(InvocationView),
    Resolution(SidecarEffectiveTrace),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SidecarEvent {
    pub daemon_instance: String,
    pub project_id: String,
    pub session_id: String,
    pub selection_id: String,
    pub config_generation: u64,
    pub entity_version: u64,
    pub payload: SidecarEventPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SidecarReducer {
    pub daemon_instance: String,
    pub project_id: String,
    pub session_id: String,
    pub selection_id: String,
    pub config_generation: u64,
    pub entity_version: u64,
    pub grants: Vec<GrantView>,
    pub invocations: Vec<InvocationView>,
    pub health: Option<HealthView>,
    pub resolution: Option<SidecarEffectiveTrace>,
    pub charged_invocation_ids: BTreeSet<String>,
    pub charged_count: u64,
    pub stale: bool,
}

impl SidecarReducer {
    pub(crate) fn new(
        daemon_instance: String,
        project_id: String,
        session_id: String,
        selection_id: String,
        config_generation: u64,
    ) -> Self {
        Self {
            daemon_instance,
            project_id,
            session_id,
            selection_id,
            config_generation,
            entity_version: 0,
            grants: Vec::new(),
            invocations: Vec::new(),
            health: None,
            resolution: None,
            charged_invocation_ids: BTreeSet::new(),
            charged_count: 0,
            stale: false,
        }
    }

    pub(crate) fn apply(&mut self, event: SidecarEvent) -> SidecarEventOutcome {
        if self.stale {
            return SidecarEventOutcome::RehydrateRequired;
        }
        if self.daemon_instance != event.daemon_instance
            || self.project_id != event.project_id
            || self.session_id != event.session_id
            || self.selection_id != event.selection_id
        {
            return SidecarEventOutcome::Discarded;
        }
        if self.config_generation == 0 || self.config_generation != event.config_generation {
            self.stale = true;
            self.invalidate_projections();
            return SidecarEventOutcome::RehydrateRequired;
        }
        if event.entity_version < self.entity_version {
            return SidecarEventOutcome::Discarded;
        }
        if event.entity_version == self.entity_version && self.entity_version > 0 {
            return SidecarEventOutcome::Discarded;
        }
        if event.entity_version != self.entity_version.saturating_add(1) {
            self.stale = true;
            self.invalidate_projections();
            return SidecarEventOutcome::RehydrateRequired;
        }
        match event.payload {
            SidecarEventPayload::Health(health) => self.health = Some(health),
            SidecarEventPayload::Grant(grant) => {
                if let Some(existing) = self
                    .grants
                    .iter_mut()
                    .find(|g| g.grant_id == grant.grant_id)
                {
                    if existing.version <= grant.version {
                        *existing = grant;
                    }
                } else {
                    self.grants.push(grant);
                }
            }
            SidecarEventPayload::Invocation(inv) => {
                if !self.commit_invocation(inv) {
                    // The envelope sequence is authoritative even when its
                    // per-invocation transition is stale. Consuming it avoids
                    // turning the next valid envelope into a false gap.
                    self.entity_version = event.entity_version;
                    return SidecarEventOutcome::Discarded;
                }
            }
            SidecarEventPayload::Resolution(trace) => self.resolution = Some(trace),
        }
        self.entity_version = event.entity_version;
        SidecarEventOutcome::Applied
    }

    fn commit_invocation(&mut self, inv: InvocationView) -> bool {
        if let Some(existing) = self
            .invocations
            .iter()
            .find(|i| i.invocation_id == inv.invocation_id)
        {
            if is_terminal(existing.state)
                || invocation_rank(existing.state) > invocation_rank(inv.state)
            {
                return false;
            }
        }
        if inv.sidecar_invocation_charged
            && self
                .charged_invocation_ids
                .insert(inv.invocation_id.clone())
        {
            self.charged_count = self.charged_count.saturating_add(1);
        }
        if let Some(existing) = self
            .invocations
            .iter_mut()
            .find(|i| i.invocation_id == inv.invocation_id)
        {
            *existing = inv;
        } else {
            self.invocations.push(inv);
        }
        true
    }

    pub(crate) fn mark_stale(&mut self) {
        self.stale = true;
        self.invalidate_projections();
    }

    fn invalidate_projections(&mut self) {
        self.health = None;
        self.resolution = None;
        self.grants.clear();
        self.invocations.clear();
        self.charged_invocation_ids.clear();
        self.charged_count = 0;
    }

    pub(crate) fn rebind(
        &mut self,
        daemon_instance: String,
        project_id: String,
        session_id: String,
        selection_id: String,
    ) {
        *self = Self::new(daemon_instance, project_id, session_id, selection_id, 0);
    }

    pub(crate) fn revoke_grant(&mut self, grant_id: &str, expected_version: u64) -> bool {
        if let Some(grant) = self.grants.iter_mut().find(|g| g.grant_id == grant_id)
            && grant.version == expected_version
            && !grant.revoked
        {
            grant.revoked = true;
            grant.version = grant.version.saturating_add(1);
            return true;
        }
        false
    }
}

fn is_terminal(state: InvocationState) -> bool {
    matches!(
        state,
        InvocationState::Completed
            | InvocationState::Failed
            | InvocationState::Cancelled
            | InvocationState::Ambiguous
    )
}

fn invocation_rank(state: InvocationState) -> u8 {
    match state {
        InvocationState::Pending => 0,
        InvocationState::Authorized => 1,
        InvocationState::Dispatched => 2,
        InvocationState::Accepted => 3,
        InvocationState::Completed
        | InvocationState::Failed
        | InvocationState::Cancelled
        | InvocationState::Ambiguous => 4,
    }
}

// ---------------------------------------------------------------------------
// Session + page
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SidecarPageKind {
    Overview,
    ModeEditor,
    DefaultEditor,
    OverrideEditor,
    CentralPolicyEditor,
    ResolverDetail,
    HealthDetail,
    GrantList,
    GrantEditor,
    InvocationList,
    InvocationDetail,
}

impl SidecarPageKind {
    pub(crate) fn surface(self) -> SettingsPointerSurfaceKind {
        match self {
            Self::Overview => SettingsPointerSurfaceKind::SidecarOverview,
            Self::ModeEditor => SettingsPointerSurfaceKind::SidecarModeEditor,
            Self::DefaultEditor => SettingsPointerSurfaceKind::SidecarDefaultEditor,
            Self::OverrideEditor => SettingsPointerSurfaceKind::SidecarOverrideEditor,
            Self::CentralPolicyEditor => SettingsPointerSurfaceKind::SidecarCentralPolicyEditor,
            Self::ResolverDetail => SettingsPointerSurfaceKind::SidecarResolverDetail,
            Self::HealthDetail => SettingsPointerSurfaceKind::SidecarHealthDetail,
            Self::GrantList => SettingsPointerSurfaceKind::SidecarGrantList,
            Self::GrantEditor => SettingsPointerSurfaceKind::SidecarGrantEditor,
            Self::InvocationList => SettingsPointerSurfaceKind::SidecarInvocationList,
            Self::InvocationDetail => SettingsPointerSurfaceKind::SidecarInvocationDetail,
        }
    }

    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::Overview => "Image Sidecar",
            Self::ModeEditor => "Sidecar mode",
            Self::DefaultEditor => "Sidecar defaults",
            Self::OverrideEditor => "Sidecar override",
            Self::CentralPolicyEditor => "Central invocation policy",
            Self::ResolverDetail => "Resolver trace",
            Self::HealthDetail => "Sidecar health",
            Self::GrantList => "Destination grants",
            Self::GrantEditor => "Grant editor",
            Self::InvocationList => "Invocation history",
            Self::InvocationDetail => "Invocation detail",
        }
    }

    pub(crate) const ALL: [Self; 11] = [
        Self::Overview,
        Self::ModeEditor,
        Self::DefaultEditor,
        Self::OverrideEditor,
        Self::CentralPolicyEditor,
        Self::ResolverDetail,
        Self::HealthDetail,
        Self::GrantList,
        Self::GrantEditor,
        Self::InvocationList,
        Self::InvocationDetail,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingRevoke {
    pub grant_id: String,
    pub version: u64,
    /// The exact presentation geometry that showed this irreversible action.
    /// A confirmation is valid only while that target remains stable.
    pub(super) layout: Option<SidecarLayoutIdentity>,
}

/// The geometry that determines the visible confirmation controls. Terminal
/// coordinates are included as a settings dialog can be embedded in a rect
/// whose origin changes without its dimensions changing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SidecarLayoutIdentity {
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    viewport: SidecarViewportMode,
}

impl SidecarLayoutIdentity {
    fn from_area(area: Rect, viewport: SidecarViewportMode) -> Self {
        Self {
            x: area.x,
            y: area.y,
            width: area.width,
            height: area.height,
            viewport,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SidecarSession {
    pub principal: SidecarPrincipal,
    pub viewport: Cell<SidecarViewportMode>,
    pub form: SidecarFormState,
    pub reducer: SidecarReducer,
    pub approval_mode: ApprovalMode,
    pub policy: CentralPolicyView,
    pub confirm_revoke: RefCell<Option<PendingRevoke>>,
    /// Most recent render identity. A confirmation opened after a render
    /// captures this rather than trusting a stale pointer target.
    layout_identity: Cell<Option<SidecarLayoutIdentity>>,
    pub selected_invocation: Option<String>,
    pub cursor: Cell<usize>,
    /// The line range actually rendered in the last frame. The accessibility
    /// projection is bounded to this same viewport rather than a parallel,
    /// un-clipped interpretation of page data.
    pub a11y_viewport: Cell<(usize, usize)>,
    pub busy: bool,
    pub error: Option<String>,
    pub conflict: Option<String>,
    pub save_pending: bool,
    pub health_refresh_pending: bool,
    pub remediation: Option<SidecarRemediation>,
    /// Test seams can exercise reducer transitions, but production remains
    /// fail-closed until the daemon exposes authoritative sidecar mutations.
    pub authoritative_mutations: bool,
    pub authoritative_snapshot: bool,
}

impl SidecarSession {
    pub(crate) fn new(principal: SidecarPrincipal) -> Self {
        Self {
            principal,
            viewport: Cell::new(SidecarViewportMode::Full),
            form: SidecarFormState::default(),
            reducer: SidecarReducer::new(
                "local".into(),
                "project".into(),
                "session".into(),
                "selection".into(),
                0,
            ),
            approval_mode: ApprovalMode::Ask,
            policy: CentralPolicyView {
                value: MediaResourceLimits::defaults().sidecar_invocations_per_session,
                source: SidecarInvocationCapProvenance::Configured,
                hard_ceiling: MediaResourceLimits::hard_ceilings().sidecar_invocations_per_session,
            },
            confirm_revoke: RefCell::new(None),
            layout_identity: Cell::new(None),
            selected_invocation: None,
            cursor: Cell::new(0),
            a11y_viewport: Cell::new((0, usize::MAX)),
            busy: false,
            error: None,
            conflict: None,
            save_pending: false,
            health_refresh_pending: false,
            remediation: None,
            authoritative_mutations: false,
            authoritative_snapshot: false,
        }
    }

    pub(crate) fn first_use(&self) -> FirstUseView {
        FirstUseView::for_mode(self.approval_mode)
    }

    fn effective_policy_line(&self) -> String {
        if self.authoritative_snapshot {
            self.policy.render_line()
        } else {
            format!("Effective: unavailable source={REASON_AUTHORITATIVE_UNAVAILABLE}")
        }
    }

    pub(crate) fn cancel_confirm(&self) {
        *self.confirm_revoke.borrow_mut() = None;
    }

    fn has_confirm_revoke(&self) -> bool {
        self.confirm_revoke.borrow().is_some()
    }

    fn set_confirm_revoke(&self, grant_id: String, version: u64) {
        *self.confirm_revoke.borrow_mut() = Some(PendingRevoke {
            grant_id,
            version,
            layout: self.layout_identity.get(),
        });
    }

    /// Synchronize the confirmation with the actual rendered layout. This is
    /// intentionally called even for the blocked layout: losing the surface
    /// that presented an irreversible action invalidates its confirmation.
    fn sync_layout_identity(&self, identity: SidecarLayoutIdentity) {
        self.layout_identity.set(Some(identity));
        let mut confirmation = self.confirm_revoke.borrow_mut();
        let changed = confirmation
            .as_ref()
            .and_then(|pending| pending.layout)
            .is_some_and(|expected| expected != identity);
        let unrendered_on_blocked_layout = confirmation
            .as_ref()
            .is_some_and(|pending| pending.layout.is_none())
            && identity.viewport == SidecarViewportMode::Blocked;
        if changed || unrendered_on_blocked_layout {
            *confirmation = None;
        } else if let Some(pending) = confirmation.as_mut()
            && pending.layout.is_none()
        {
            pending.layout = Some(identity);
        }
    }

    pub(crate) fn rebind_identity(
        &mut self,
        daemon_instance: String,
        project_id: String,
        session_id: String,
        selection_id: String,
    ) {
        self.reducer
            .rebind(daemon_instance, project_id, session_id, selection_id);
        // An identity transition invalidates every daemon-owned projection and
        // mutation authority. Do not carry policy, principal, or model/form
        // state into the new identity: a fresh authoritative snapshot must
        // rehydrate them before this screen can act again.
        self.principal = SidecarPrincipal::default();
        self.form = SidecarFormState::default();
        self.approval_mode = ApprovalMode::Ask;
        self.policy = CentralPolicyView {
            value: MediaResourceLimits::defaults().sidecar_invocations_per_session,
            source: SidecarInvocationCapProvenance::Configured,
            hard_ceiling: MediaResourceLimits::hard_ceilings().sidecar_invocations_per_session,
        };
        self.authoritative_mutations = false;
        self.authoritative_snapshot = false;
        *self.confirm_revoke.borrow_mut() = None;
        self.layout_identity.set(None);
        self.selected_invocation = None;
        self.cursor.set(0);
        self.a11y_viewport.set((0, usize::MAX));
        self.error = None;
        self.conflict = None;
        self.busy = false;
        self.save_pending = false;
        self.health_refresh_pending = false;
        self.remediation = None;
    }

    /// Returns the exact destination that a local grant construction may use.
    /// Keeping this check in the session makes the state registry and the
    /// action handler fail closed on the same prerequisites.
    fn grant_creation_destination(&self) -> Result<String, &'static str> {
        if self.approval_mode == ApprovalMode::Yolo {
            return Err(REASON_YOLO_NO_GRANT);
        }
        if !self.authoritative_mutations {
            return Err(REASON_AUTHORITATIVE_UNAVAILABLE);
        }
        if let Some(reason) = self.principal.config_reason() {
            return Err(reason);
        }
        let Some(resolution) = self.reducer.resolution.as_ref() else {
            return Err(REASON_MISSING_SELECTION);
        };
        let destination = sanitized_display_origin(&resolution.origin);
        if !resolution.available || destination.trim().is_empty() {
            return Err(REASON_DESTINATION_DENIED);
        }
        if self.form.draft_scope == GrantScope::Once
            && !self.selected_invocation.as_deref().is_some_and(|selected| {
                !selected.is_empty()
                    && self
                        .reducer
                        .invocations
                        .iter()
                        .any(|invocation| invocation.invocation_id == selected)
            })
        {
            return Err(REASON_INVOCATION_NOT_FOUND);
        }
        Ok(destination)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SidecarPage {
    pub(super) kind: SidecarPageKind,
    pub(super) session: SidecarSession,
}

fn boxed(page: SidecarPage) -> PageBox {
    Box::new(page)
}

pub(super) fn sidecar_overview_page(principal: SidecarPrincipal) -> PageBox {
    boxed(SidecarPage {
        kind: SidecarPageKind::Overview,
        session: SidecarSession::new(principal),
    })
}

pub(super) fn sidecar_page(kind: SidecarPageKind, session: SidecarSession) -> PageBox {
    boxed(SidecarPage { kind, session })
}

fn open_node(node: SidecarNodeId, session: SidecarSession) -> PageBox {
    let kind = match node {
        SidecarNodeId::Mode => SidecarPageKind::ModeEditor,
        SidecarNodeId::Defaults => SidecarPageKind::DefaultEditor,
        SidecarNodeId::Override => SidecarPageKind::OverrideEditor,
        SidecarNodeId::CentralPolicy => SidecarPageKind::CentralPolicyEditor,
        SidecarNodeId::Resolver => SidecarPageKind::ResolverDetail,
        SidecarNodeId::Health => SidecarPageKind::HealthDetail,
        SidecarNodeId::Grants => SidecarPageKind::GrantList,
        SidecarNodeId::Invocations => SidecarPageKind::InvocationList,
    };
    sidecar_page(kind, session)
}

type SidecarBinding = Option<(SidecarAction, bool, Option<&'static str>)>;

fn sidecar_layout(frame: &mut Frame, area: Rect, mode: SidecarViewportMode) -> Rect {
    match mode {
        SidecarViewportMode::Full => {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Min(0), Constraint::Length(26)])
                .split(area);
            let info = Paragraph::new(vec![
                Line::from("Layout: Full"),
                Line::from(""),
                Line::from("Trust is not consent."),
                Line::from("Grants: once/session/project."),
                Line::from("No global option."),
            ])
            .block(Block::default().borders(Borders::ALL).title(" Context "))
            .wrap(Wrap { trim: false });
            frame.render_widget(info, cols[1]);
            cols[0]
        }
        SidecarViewportMode::Compact => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(1), Constraint::Min(0)])
                .split(area);
            frame.render_widget(
                Paragraph::new(Line::from("Layout: Compact — trust is not consent")),
                rows[0],
            );
            rows[1]
        }
        SidecarViewportMode::Reduced | SidecarViewportMode::Blocked => area,
    }
}

fn render_resize_blocker(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from("Terminal too small for Image Sidecar settings."),
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

fn render_sidecar_page(
    cx: &SettingsCx,
    frame: &mut Frame,
    area: Rect,
    key: &'static str,
    title: &str,
    rows: &[SidecarRenderedRow],
    selected: Option<usize>,
) {
    let mode = sidecar_viewport_mode(area.width, area.height);
    if mode == SidecarViewportMode::Blocked {
        render_resize_blocker(frame, area);
        return;
    }
    let content = sidecar_layout(frame, area, mode);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {title} "));
    let inner = block.inner(content);
    frame.render_widget(block, content);
    let mut lines = Vec::with_capacity(rows.len());
    let mut controls = Vec::with_capacity(rows.len());
    for row in rows {
        lines.push(Line::from(row.text.clone()));
        controls.push(row.binding.clone().map(|(action, enabled, reason)| {
            (SettingsPointerAction::Sidecar(action), enabled, reason)
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

fn accept_or_back(action: &SettingsPointerAction, accepted: bool) -> Nav {
    if accepted {
        return Nav::Stay;
    }
    if matches!(
        action,
        SettingsPointerAction::Sidecar(SidecarAction::Cancel)
    ) {
        return Nav::Back;
    }
    Nav::Stay
}

impl SidecarPage {
    fn max_cursor(&self) -> usize {
        self.rendered_rows().len().saturating_sub(1)
    }

    fn normalized_cursor_for_rows(&self, rows: &[SidecarRenderedRow]) -> usize {
        self.session.cursor.get().min(rows.len().saturating_sub(1))
    }

    fn normalized_cursor(&self) -> usize {
        self.normalized_cursor_for_rows(&self.rendered_rows())
    }

    /// A reducer or session transition can remove rows (for example after a
    /// rehydrate). Clamp before further input so a stale index cannot select a
    /// different control than the one rendered.
    fn normalize_cursor(&self) {
        self.session.cursor.set(self.normalized_cursor());
    }

    fn focused_keyboard_action(&self) -> Option<SidecarAction> {
        self.normalize_cursor();
        self.rendered_rows()
            .get(self.normalized_cursor())
            .and_then(|row| row.binding.as_ref())
            .and_then(|(action, enabled, _)| enabled.then(|| action.clone()))
    }

    pub(crate) fn visible_rows(&self) -> Vec<SidecarRowView> {
        self.viewport_rows()
            .into_iter()
            .map(|row| row.view)
            .collect()
    }

    pub(crate) fn a11y(&self) -> SidecarA11yProjection {
        self.normalize_cursor();
        let rows = self.viewport_rows();
        let viewport_start = self.session.a11y_viewport.get().0;
        let focused_index = self.normalized_cursor().saturating_sub(viewport_start);
        let focused = rows.get(focused_index).or_else(|| rows.first());
        // Row-local failures take precedence over a page-level status so the
        // projection describes the focused rendered row. The latter remains a
        // deliberate fallback for pages and controls that have no row error.
        let focused_error = focused
            .and_then(|row| row.view.error.clone())
            .or_else(|| self.session.error.clone());
        SidecarA11yProjection {
            focused_label: focused
                .map(|row| row.view.label.clone())
                .unwrap_or_default(),
            focused_value: focused
                .map(|row| row.view.value.clone())
                .unwrap_or_default(),
            effective_policy: "sidecar_invocations_per_session".into(),
            effective_value: if self.session.authoritative_snapshot {
                self.session.policy.value.to_string()
            } else {
                "unavailable".into()
            },
            effective_source: if self.session.authoritative_snapshot {
                self.session.policy.source_label().into()
            } else {
                REASON_AUTHORITATIVE_UNAVAILABLE.into()
            },
            destination: focused
                .and_then(|row| row.view.destination.clone())
                .unwrap_or_default(),
            scope: focused
                .and_then(|row| row.view.scope.clone())
                .unwrap_or_default(),
            non_color_state: focused
                .map(|row| row.view.state.clone())
                .unwrap_or_else(|| "idle".into()),
            busy: self.session.busy,
            error: focused_error,
            project_grant_warning: focused.and_then(|row| row.view.project_grant_warning.clone()),
        }
    }

    pub(crate) fn named_actions(&self) -> Vec<(SidecarAction, bool, Option<&'static str>)> {
        self.rendered_rows()
            .into_iter()
            .filter_map(|row| row.binding)
            .collect()
    }

    fn rendered_rows(&self) -> Vec<SidecarRenderedRow> {
        build_rows(self)
            .into_iter()
            .map(|(text, binding)| SidecarRenderedRow {
                view: self.row_view(&text, binding.as_ref()),
                text,
                binding,
            })
            .collect()
    }

    fn viewport_rows(&self) -> Vec<SidecarRenderedRow> {
        let (start, count) = self.session.a11y_viewport.get();
        self.rendered_rows()
            .into_iter()
            .skip(start)
            .take(count)
            .collect()
    }

    fn row_view(
        &self,
        text: &str,
        binding: Option<&(SidecarAction, bool, Option<&'static str>)>,
    ) -> SidecarRowView {
        let text_without_marker = text.trim_start_matches(['▸', ' ']);
        if let Some(grant) = self
            .session
            .reducer
            .grants
            .iter()
            .find(|grant| grant.row_text() == text_without_marker)
        {
            return SidecarRowView {
                label: grant.grant_id.clone(),
                value: grant.row_text(),
                state: if grant.revoked { "revoked" } else { "active" }.into(),
                destination: Some(sanitized_display_origin(&grant.destination)),
                scope: Some(grant.scope.as_str().into()),
                error: None,
                project_grant_warning: grant.project_warning().map(str::to_string),
                busy: self.session.busy,
            };
        }
        if let Some(invocation) = self
            .session
            .reducer
            .invocations
            .iter()
            .find(|invocation| invocation.row_text() == text_without_marker)
        {
            return SidecarRowView {
                label: invocation.invocation_id.clone(),
                value: invocation.row_text(),
                state: invocation.state.as_str().into(),
                destination: Some(format!("{}:{}", invocation.provider, invocation.model)),
                scope: invocation.grant_id.clone(),
                error: invocation.safe_error.clone(),
                project_grant_warning: None,
                busy: self.session.busy,
            };
        }
        let (label, state, error) = if let Some(remediation) = self.session.remediation
            && text.contains(remediation.code())
        {
            (
                "remediation".into(),
                remediation.code().into(),
                Some(remediation.code().into()),
            )
        } else if let Some((_, enabled, reason)) = binding {
            (
                text.into(),
                if *enabled { "action" } else { "disabled" }.into(),
                reason.map(str::to_string),
            )
        } else {
            (text.into(), "information".into(), None)
        };
        SidecarRowView {
            label,
            value: text.into(),
            state,
            destination: None,
            scope: None,
            error,
            project_grant_warning: None,
            busy: self.session.busy,
        }
    }

    fn push_kind(&self, kind: SidecarPageKind) -> Nav {
        // A new settings page has a different control layout, so it cannot
        // inherit a confirmation that was presented by the grant list.
        self.session.cancel_confirm();
        Nav::Push(sidecar_page(kind, self.session.clone()))
    }
}

fn build_rows(page: &SidecarPage) -> Vec<(String, SidecarBinding)> {
    let mut rows: Vec<(String, SidecarBinding)> = Vec::new();
    if page.kind != SidecarPageKind::Overview && !page.session.authoritative_snapshot {
        rows.push((
            format!("Sidecar data unavailable: {REASON_AUTHORITATIVE_UNAVAILABLE}"),
            None,
        ));
        rows.push(("[Cancel]".into(), Some((SidecarAction::Cancel, true, None))));
        return rows;
    }
    let can_mutate = page.session.principal.can_mutate() && page.session.authoritative_mutations;
    let mutate_reason = if !page.session.authoritative_mutations {
        Some(REASON_AUTHORITATIVE_UNAVAILABLE)
    } else {
        page.session.principal.config_reason()
    };
    match page.kind {
        SidecarPageKind::Overview => {
            for (i, title) in SIDECAR_NODE_TITLES.iter().enumerate() {
                let marker = if i == page.session.cursor.get() {
                    "▸ "
                } else {
                    "  "
                };
                let node = match i {
                    0 => SidecarNodeId::Mode,
                    1 => SidecarNodeId::Defaults,
                    2 => SidecarNodeId::Override,
                    3 => SidecarNodeId::CentralPolicy,
                    4 => SidecarNodeId::Resolver,
                    5 => SidecarNodeId::Health,
                    6 => SidecarNodeId::Grants,
                    _ => SidecarNodeId::Invocations,
                };
                rows.push((
                    format!("{marker}{title}"),
                    Some((SidecarAction::OpenNode(node), true, None)),
                ));
            }
            rows.push((String::new(), None));
            rows.push((
                "[open resolver detail]".into(),
                Some((SidecarAction::OpenResolverDetail, true, None)),
            ));
            rows.push((
                "[open health detail]".into(),
                Some((SidecarAction::OpenHealthDetail, true, None)),
            ));
            rows.push((page.session.effective_policy_line(), None));
        }
        SidecarPageKind::ModeEditor => {
            rows.push((
                format!("Current mode: {}", page.session.form.mode.as_str()),
                None,
            ));
            for choice in [
                SidecarModeChoice::Automatic,
                SidecarModeChoice::Always,
                SidecarModeChoice::Never,
            ] {
                rows.push((
                    format!("[{}]", choice.as_str()),
                    Some((SidecarAction::SetMode(choice), can_mutate, mutate_reason)),
                ));
            }
            rows.push(("[Cancel]".into(), Some((SidecarAction::Cancel, true, None))));
        }
        SidecarPageKind::DefaultEditor => {
            let models = page.session.form.selectable_models();
            rows.push(("Trusted-primary default".into(), None));
            for m in &models {
                let model = SidecarModelRef {
                    provider: m.provider.clone(),
                    model: m.model.clone(),
                };
                rows.push((
                    format!("[set trusted default {}:{}]", model.provider, model.model),
                    Some((
                        SidecarAction::SetTrustedDefault(model),
                        can_mutate,
                        mutate_reason,
                    )),
                ));
            }
            if models.is_empty() {
                rows.push((
                    "set trusted default [disabled: missing_selection]".into(),
                    None,
                ));
            }
            rows.push(("Untrusted-primary default".into(), None));
            for m in &models {
                let model = SidecarModelRef {
                    provider: m.provider.clone(),
                    model: m.model.clone(),
                };
                rows.push((
                    format!("[set untrusted default {}:{}]", model.provider, model.model),
                    Some((
                        SidecarAction::SetUntrustedDefault(model),
                        can_mutate,
                        mutate_reason,
                    )),
                ));
            }
            if models.is_empty() {
                rows.push((
                    "set untrusted default [disabled: missing_selection]".into(),
                    None,
                ));
            }
            rows.push(("[Cancel]".into(), Some((SidecarAction::Cancel, true, None))));
        }
        SidecarPageKind::OverrideEditor => {
            let models = page.session.form.selectable_models();
            rows.push(("Optional per-primary override".into(), None));
            for m in &models {
                let model = SidecarModelRef {
                    provider: m.provider.clone(),
                    model: m.model.clone(),
                };
                rows.push((
                    format!("[set override {}:{}]", model.provider, model.model),
                    Some((SidecarAction::SetOverride(model), can_mutate, mutate_reason)),
                ));
            }
            if models.is_empty() {
                rows.push(("set override [disabled: missing_selection]".into(), None));
            }
            rows.push((
                "[clear override]".into(),
                Some((SidecarAction::ClearOverride, can_mutate, mutate_reason)),
            ));
            rows.push(("[Cancel]".into(), Some((SidecarAction::Cancel, true, None))));
        }
        SidecarPageKind::CentralPolicyEditor => {
            rows.push((page.session.effective_policy_line(), None));
            rows.push((
                format!(
                    "Draft sidecar_invocations_per_session={}",
                    page.session.form.central_cap
                ),
                None,
            ));
            rows.push(("No sidecar-local cap is stored.".into(), None));
            let lower = page.session.form.central_cap.saturating_sub(1).max(1);
            let upper = page
                .session
                .form
                .central_cap
                .saturating_add(1)
                .min(MediaResourceLimits::hard_ceilings().sidecar_invocations_per_session);
            rows.push((
                "[decrease central cap]".into(),
                Some((
                    SidecarAction::SetCentralCap(lower),
                    can_mutate,
                    mutate_reason,
                )),
            ));
            rows.push((
                "[increase central cap]".into(),
                Some((
                    SidecarAction::SetCentralCap(upper),
                    can_mutate,
                    mutate_reason,
                )),
            ));
            let save_reason = if !can_mutate {
                mutate_reason
            } else if page.session.save_pending {
                Some(REASON_SAVE_PENDING)
            } else {
                None
            };
            rows.push((
                "[Save]".into(),
                Some((
                    SidecarAction::SaveCentralPolicy,
                    can_mutate && !page.session.save_pending,
                    save_reason,
                )),
            ));
            rows.push(("[Cancel]".into(), Some((SidecarAction::Cancel, true, None))));
        }
        SidecarPageKind::ResolverDetail => {
            if let Some(trace) = &page.session.reducer.resolution {
                rows.push((
                    format!(
                        "primary={}:{} trust={}",
                        trace.primary_provider, trace.primary_model, trace.primary_trust
                    ),
                    None,
                ));
                for line in TrustDisclosure::for_trust(trace.primary_trust == "trusted").lines() {
                    rows.push((line, None));
                }
                rows.push((
                    format!(
                        "Egress authority: destination={} scopes=once/session/project",
                        sanitized_display_origin(&trace.origin)
                    ),
                    None,
                ));
                rows.push((format!("matched={}", trace.matched_source), None));
                rows.push((
                    format!(
                        "sidecar={}:{}",
                        trace.sidecar_provider.as_deref().unwrap_or("-"),
                        trace.sidecar_model.as_deref().unwrap_or("-")
                    ),
                    None,
                ));
                rows.push((
                    format!("origin={}", sanitized_display_origin(&trace.origin)),
                    None,
                ));
                rows.push((format!("location={}", trace.location), None));
                rows.push((
                    format!("credential_fingerprint={}", trace.credential_fingerprint),
                    None,
                ));
                rows.push((
                    format!(
                        "capability source={} freshness={}",
                        trace.capability_source, trace.capability_freshness
                    ),
                    None,
                ));
                rows.push((
                    format!(
                        "config_generation={} mode={} available={} reason={}",
                        trace.config_generation,
                        trace.mode.as_str(),
                        trace.available,
                        trace.reason
                    ),
                    None,
                ));
                if let Some(fb) = &trace.fallback_outcome {
                    rows.push((format!("fallback={fb}"), None));
                }
            } else {
                rows.push(("No resolver projection.".into(), None));
            }
            rows.push((page.session.effective_policy_line(), None));
            rows.push((
                "[refresh health]".into(),
                Some((
                    SidecarAction::RefreshHealth,
                    can_mutate && !page.session.health_refresh_pending,
                    if page.session.health_refresh_pending {
                        Some("health_refresh_pending")
                    } else {
                        mutate_reason
                    },
                )),
            ));
            rows.push(("[Cancel]".into(), Some((SidecarAction::Cancel, true, None))));
        }
        SidecarPageKind::HealthDetail => {
            if let Some(health) = &page.session.reducer.health {
                let state = if health.available {
                    "available"
                } else {
                    "unavailable"
                };
                rows.push((format!("Health: {state} (non-color)"), None));
                rows.push((
                    format!(
                        "source={} freshness={} reason={}",
                        health.capability_source, health.freshness, health.reason
                    ),
                    None,
                ));
            } else {
                rows.push(("No health projection.".into(), None));
            }
            rows.push((
                "[refresh health]".into(),
                Some((
                    SidecarAction::RefreshHealth,
                    can_mutate && !page.session.health_refresh_pending,
                    if page.session.health_refresh_pending {
                        Some("health_refresh_pending")
                    } else {
                        mutate_reason
                    },
                )),
            ));
            rows.push(("[Cancel]".into(), Some((SidecarAction::Cancel, true, None))));
        }
        SidecarPageKind::GrantList => {
            let first_use = page.session.first_use();
            if page.session.approval_mode == ApprovalMode::Yolo {
                rows.push((
                    format!(
                        "Yolo: {}",
                        first_use.yolo_label.unwrap_or("agent_discretion")
                    ),
                    None,
                ));
                rows.push(("No standing grant is created automatically.".into(), None));
            }
            if page.session.reducer.grants.is_empty() {
                rows.push(("No destination grants.".into(), None));
            } else {
                for grant in &page.session.reducer.grants {
                    rows.push((grant.row_text(), None));
                    if let Some(warning) = grant.project_warning() {
                        rows.push((warning.into(), None));
                    }
                }
            }
            let create = page.session.grant_creation_destination();
            rows.push((
                "[create grant]".into(),
                Some((SidecarAction::CreateGrant, create.is_ok(), create.err())),
            ));
            rows.push((
                "[open grant editor]".into(),
                Some((SidecarAction::OpenGrantEditor, true, None)),
            ));
            for grant in &page.session.reducer.grants {
                let revoke_ok = page.session.principal.can_revoke()
                    && page.session.authoritative_mutations
                    && !grant.revoked;
                rows.push((
                    format!("[revoke grant {}]", grant.grant_id),
                    Some((
                        SidecarAction::RevokeGrant(SidecarGrantId(grant.grant_id.clone())),
                        revoke_ok,
                        if revoke_ok {
                            None
                        } else if !page.session.authoritative_mutations {
                            Some(REASON_AUTHORITATIVE_UNAVAILABLE)
                        } else {
                            Some(REASON_REVOKE_REQUIRES_AUTHORIZATION)
                        },
                    )),
                ));
            }
            if let Some(pending) = page.session.confirm_revoke.borrow().as_ref() {
                rows.push(("Revoke grant? [Revoke grant] [Cancel]".into(), None));
                rows.push((
                    "[Revoke grant]".into(),
                    Some((
                        SidecarAction::ConfirmRevokeGrant(
                            SidecarGrantId(pending.grant_id.clone()),
                            ConfirmationChoice::Confirm,
                        ),
                        true,
                        None,
                    )),
                ));
                rows.push((
                    "[Cancel]".into(),
                    Some((
                        SidecarAction::ConfirmRevokeGrant(
                            SidecarGrantId(pending.grant_id.clone()),
                            ConfirmationChoice::Cancel,
                        ),
                        true,
                        None,
                    )),
                ));
            }
            rows.push((page.session.effective_policy_line(), None));
        }
        SidecarPageKind::GrantEditor => {
            let first_use = page.session.first_use();
            if first_use.prompt {
                rows.push(("First use — choose a grant scope.".into(), None));
                for scope in first_use.grant_choices {
                    rows.push((
                        format!("[{}]", scope.as_str()),
                        Some((SidecarAction::SelectGrantScope(scope), true, None)),
                    ));
                }
            } else {
                rows.push((
                    format!(
                        "Yolo: {}",
                        first_use.yolo_label.unwrap_or("agent_discretion")
                    ),
                    None,
                ));
                rows.push(("No approval prompt. No standing grant.".into(), None));
            }
            let create = page.session.grant_creation_destination();
            rows.push((
                "[create grant]".into(),
                Some((SidecarAction::CreateGrant, create.is_ok(), create.err())),
            ));
            rows.push(("[Cancel]".into(), Some((SidecarAction::Cancel, true, None))));
        }
        SidecarPageKind::InvocationList => {
            if page.session.reducer.invocations.is_empty() {
                rows.push(("No invocations.".into(), None));
            } else {
                for inv in &page.session.reducer.invocations {
                    rows.push((inv.row_text(), None));
                    rows.push((
                        format!("[open invocation detail {}]", inv.invocation_id),
                        Some((
                            SidecarAction::OpenInvocationDetail(SidecarInvocationId(
                                inv.invocation_id.clone(),
                            )),
                            true,
                            None,
                        )),
                    ));
                }
            }
            rows.push(("[Cancel]".into(), Some((SidecarAction::Cancel, true, None))));
        }
        SidecarPageKind::InvocationDetail => {
            if let Some(inv) = page.session.selected_invocation.as_ref().and_then(|id| {
                page.session
                    .reducer
                    .invocations
                    .iter()
                    .find(|i| i.invocation_id == *id)
            }) {
                rows.push((inv.row_text(), None));
                rows.push((
                    format!(
                        "timestamps created={} dispatched={} terminal={}",
                        inv.created_at,
                        inv.dispatched_at.as_deref().unwrap_or("-"),
                        inv.terminal_at.as_deref().unwrap_or("-")
                    ),
                    None,
                ));
                rows.push((
                    format!(
                        "usage in={} out={} cost_us={}",
                        inv.usage_input_tokens.unwrap_or(0),
                        inv.usage_output_tokens.unwrap_or(0),
                        inv.usage_cost_micro_usd.unwrap_or(0)
                    ),
                    None,
                ));
                rows.push((
                    format!(
                        "resource charged={} reservation={} slot={}",
                        inv.sidecar_invocation_charged,
                        inv.media_reservation_id.as_deref().unwrap_or("-"),
                        inv.provider_concurrency_slot.as_deref().unwrap_or("-")
                    ),
                    None,
                ));
                if let Some(err) = &inv.safe_error {
                    rows.push((format!("error={err}"), None));
                }
                if page.session.principal.local_owner
                    && let Some(detail) = &inv.owner_detail
                {
                    rows.push((
                        format!(
                            "owner purpose={} version={} digest={} scalars={} bytes={}",
                            detail.purpose,
                            detail.instruction_version,
                            detail.body_digest_hex,
                            detail.unicode_scalar_len,
                            detail.utf8_byte_len
                        ),
                        None,
                    ));
                }
            } else {
                rows.push(("Invocation not found.".into(), None));
            }
            rows.push(("[Cancel]".into(), Some((SidecarAction::Cancel, true, None))));
        }
    }
    if let Some(conflict) = &page.session.conflict {
        rows.push((format!("Conflict: {conflict} Reload or reapply."), None));
    }
    if let Some(r) = page.session.remediation {
        rows.push((format!("{} ({})", r.label(), r.code()), None));
    }
    rows
}

impl SettingsPage for SidecarPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        self.kind.surface()
    }

    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        if self.session.viewport.get() == SidecarViewportMode::Blocked {
            return match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
                _ => Nav::Stay,
            };
        }
        self.normalize_cursor();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => {
                if self.session.has_confirm_revoke() {
                    self.session.cancel_confirm();
                    self.normalize_cursor();
                    Nav::Stay
                } else {
                    Nav::Back
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.session.has_confirm_revoke() {
                    self.session.cancel_confirm();
                    self.normalize_cursor();
                    return Nav::Stay;
                }
                self.session
                    .cursor
                    .set(self.session.cursor.get().saturating_sub(1));
                Nav::Stay
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.session.has_confirm_revoke() {
                    self.session.cancel_confirm();
                    self.normalize_cursor();
                    return Nav::Stay;
                }
                self.session.cursor.set(
                    self.session
                        .cursor
                        .get()
                        .saturating_add(1)
                        .min(self.max_cursor()),
                );
                Nav::Stay
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if let Some(action) = self.focused_keyboard_action() {
                    return self
                        .handle_pointer_control(_cx, SettingsPointerAction::Sidecar(action));
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
        let SettingsPointerAction::Sidecar(action) = action else {
            return Nav::Stay;
        };
        self.normalize_cursor();
        match action {
            SidecarAction::OpenNode(node) => Nav::Push(open_node(node, self.session.clone())),
            SidecarAction::OpenResolverDetail => self.push_kind(SidecarPageKind::ResolverDetail),
            SidecarAction::OpenHealthDetail => self.push_kind(SidecarPageKind::HealthDetail),
            SidecarAction::OpenGrantEditor => self.push_kind(SidecarPageKind::GrantEditor),
            SidecarAction::OpenInvocationDetail(id) => {
                if self.session.authoritative_snapshot
                    && self
                        .session
                        .reducer
                        .invocations
                        .iter()
                        .any(|invocation| invocation.invocation_id == id.0)
                {
                    self.session.selected_invocation = Some(id.0);
                    self.push_kind(SidecarPageKind::InvocationDetail)
                } else {
                    self.session.selected_invocation = None;
                    self.session.error = Some(REASON_INVOCATION_NOT_FOUND.into());
                    Nav::Stay
                }
            }
            SidecarAction::SetMode(mode) => {
                if !self.session.authoritative_mutations {
                    self.session.error = Some(REASON_AUTHORITATIVE_UNAVAILABLE.into());
                    return Nav::Stay;
                }
                self.session.form.mode = mode;
                Nav::Stay
            }
            SidecarAction::SetTrustedDefault(model) => {
                if self.session.authoritative_mutations
                    && self
                        .session
                        .form
                        .selectable_models()
                        .iter()
                        .any(|m| m.provider == model.provider && m.model == model.model)
                {
                    self.session.form.trusted_default = Some(model);
                } else {
                    self.session.remediation = Some(SidecarRemediation::MissingSelection);
                }
                Nav::Stay
            }
            SidecarAction::SetUntrustedDefault(model) => {
                if self.session.authoritative_mutations
                    && self
                        .session
                        .form
                        .selectable_models()
                        .iter()
                        .any(|m| m.provider == model.provider && m.model == model.model)
                {
                    self.session.form.untrusted_default = Some(model);
                } else {
                    self.session.remediation = Some(SidecarRemediation::MissingSelection);
                }
                Nav::Stay
            }
            SidecarAction::SetOverride(model) => {
                if self
                    .session
                    .form
                    .selectable_models()
                    .iter()
                    .any(|m| m.provider == model.provider && m.model == model.model)
                    && self.session.authoritative_mutations
                {
                    self.session.form.override_pair = Some(model);
                    self.session.remediation = None;
                } else {
                    self.session.remediation = Some(SidecarRemediation::InvalidOverride);
                }
                Nav::Stay
            }
            SidecarAction::ClearOverride => {
                if self.session.authoritative_mutations {
                    self.session.form.override_pair = None;
                } else {
                    self.session.error = Some(REASON_AUTHORITATIVE_UNAVAILABLE.into());
                }
                Nav::Stay
            }
            SidecarAction::SetCentralCap(value) => {
                if self.session.authoritative_mutations {
                    self.session.form.set_central_cap(value);
                } else {
                    self.session.error = Some(REASON_AUTHORITATIVE_UNAVAILABLE.into());
                }
                Nav::Stay
            }
            SidecarAction::SaveCentralPolicy => {
                if self.session.authoritative_mutations
                    && self.session.principal.can_mutate()
                    && !self.session.save_pending
                {
                    self.session.policy.value = self.session.form.central_cap;
                    self.session.policy.source = SidecarInvocationCapProvenance::Configured;
                    self.session.save_pending = false;
                } else {
                    self.session.error = Some(REASON_AUTHORITATIVE_UNAVAILABLE.into());
                }
                Nav::Stay
            }
            SidecarAction::RefreshHealth => {
                if self.session.authoritative_mutations {
                    self.session.health_refresh_pending = true;
                } else {
                    self.session.error = Some(REASON_AUTHORITATIVE_UNAVAILABLE.into());
                }
                Nav::Stay
            }
            SidecarAction::SelectGrantScope(scope) => {
                self.session.form.draft_scope = scope;
                Nav::Stay
            }
            SidecarAction::CreateGrant => {
                let destination = match self.session.grant_creation_destination() {
                    Ok(destination) => destination,
                    Err(REASON_DESTINATION_DENIED) => {
                        self.session.remediation = Some(SidecarRemediation::DestinationDenied);
                        return Nav::Stay;
                    }
                    Err(_) => {
                        self.session.remediation = Some(SidecarRemediation::MissingSelection);
                        return Nav::Stay;
                    }
                };
                if self.kind == SidecarPageKind::GrantList {
                    return self.push_kind(SidecarPageKind::GrantEditor);
                }
                let grant = GrantView {
                    grant_id: format!("grant-{}", self.session.reducer.grants.len() + 1),
                    version: 1,
                    project: self.session.reducer.project_id.clone(),
                    destination,
                    media_class: MediaClass::Image.as_str().into(),
                    purpose: Purpose::AskImage.as_str().into(),
                    scope: self.session.form.draft_scope,
                    session_binding: (self.session.form.draft_scope == GrantScope::Session)
                        .then(|| self.session.reducer.session_id.clone()),
                    invocation_binding: (self.session.form.draft_scope == GrantScope::Once)
                        .then(|| self.session.selected_invocation.clone())
                        .flatten(),
                    created_at: "0".into(),
                    last_used_at: None,
                    revoked: false,
                    consumed: false,
                };
                self.session.reducer.grants.push(grant);
                Nav::Stay
            }
            SidecarAction::RevokeGrant(id) => {
                if !self.session.principal.can_revoke() || !self.session.authoritative_mutations {
                    return Nav::Stay;
                }
                if let Some(grant) = self
                    .session
                    .reducer
                    .grants
                    .iter()
                    .find(|g| g.grant_id == id.0)
                {
                    self.session
                        .set_confirm_revoke(grant.grant_id.clone(), grant.version);
                }
                Nav::Stay
            }
            SidecarAction::ConfirmRevokeGrant(id, ConfirmationChoice::Confirm) => {
                if !self.session.authoritative_mutations {
                    self.session.cancel_confirm();
                    self.session.error = Some(REASON_AUTHORITATIVE_UNAVAILABLE.into());
                    self.normalize_cursor();
                    return Nav::Stay;
                }
                if !self.session.principal.can_revoke() {
                    self.session.cancel_confirm();
                    self.session.error = Some(REASON_REVOKE_REQUIRES_AUTHORIZATION.into());
                    self.normalize_cursor();
                    return Nav::Stay;
                }
                let Some(pending) = self.session.confirm_revoke.borrow_mut().take() else {
                    return Nav::Stay;
                };
                if pending.grant_id != id.0 {
                    self.session.error = Some(REASON_REVOKE_CONFIRMATION_STALE.into());
                    self.normalize_cursor();
                    return Nav::Stay;
                }
                let current_grant_matches = self.session.reducer.grants.iter().any(|grant| {
                    grant.grant_id == pending.grant_id
                        && grant.version == pending.version
                        && !grant.revoked
                });
                if !current_grant_matches {
                    self.session.error = Some(REASON_REVOKE_CONFIRMATION_STALE.into());
                    self.normalize_cursor();
                    return Nav::Stay;
                }
                if !self
                    .session
                    .reducer
                    .revoke_grant(&pending.grant_id, pending.version)
                {
                    self.session.error = Some(REASON_REVOKE_CONFIRMATION_STALE.into());
                }
                self.normalize_cursor();
                Nav::Stay
            }
            SidecarAction::ConfirmRevokeGrant(_, ConfirmationChoice::Cancel) => {
                self.session.cancel_confirm();
                self.normalize_cursor();
                Nav::Stay
            }
            SidecarAction::Cancel => Nav::Back,
        }
    }

    fn handle_pointer_scroll(
        &mut self,
        cx: &mut SettingsCx,
        _region: SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        if self.session.has_confirm_revoke() {
            self.session.cancel_confirm();
            self.normalize_cursor();
            return Nav::Stay;
        }
        let key = if delta < 0 {
            KeyCode::Up
        } else {
            KeyCode::Down
        };
        for _ in 0..delta.unsigned_abs() {
            let nav = self.handle_key(cx, KeyEvent::new(key, crossterm::event::KeyModifiers::NONE));
            if !matches!(nav, Nav::Stay) {
                return nav;
            }
        }
        Nav::Stay
    }

    fn cancel_pointer_transients(&mut self) {
        self.session.cancel_confirm();
        self.normalize_cursor();
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        self.normalize_cursor();
        let mode = sidecar_viewport_mode(area.width, area.height);
        self.session.viewport.set(mode);
        self.session
            .sync_layout_identity(SidecarLayoutIdentity::from_area(area, mode));
        if mode == SidecarViewportMode::Blocked {
            self.session.a11y_viewport.set((0, 0));
        } else {
            let content_height = if mode == SidecarViewportMode::Compact {
                area.height.saturating_sub(1)
            } else {
                area.height
            };
            let inner_height = content_height.saturating_sub(2);
            self.session.a11y_viewport.set((
                cx.scroll_states.offset_for("sidecar"),
                usize::from(inner_height),
            ));
        }
        let rows = self.rendered_rows();
        let selected = self.normalized_cursor_for_rows(&rows);
        render_sidecar_page(
            cx,
            frame,
            area,
            "sidecar",
            self.kind.title(),
            &rows,
            Some(selected),
        );
        if mode != SidecarViewportMode::Blocked {
            let (_, count) = self.session.a11y_viewport.get();
            self.session
                .a11y_viewport
                .set((cx.scroll_states.offset_for("sidecar"), count));
        }
    }

    fn title(&self, _cx: &SettingsCx) -> String {
        self.kind.title().to_owned()
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
        self.kind.title()
    }
}
