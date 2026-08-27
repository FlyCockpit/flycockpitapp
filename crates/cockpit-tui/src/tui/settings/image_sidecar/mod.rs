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
    ApprovalMode, GrantScope, InvocationDisposition, InvocationState,
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
const REASON_NO_PENDING_CHANGES: &str = "no_pending_changes";
const REASON_RELOAD_REQUIRED: &str = "reload_required_before_reapply";
const REASON_FORBIDDEN_SIDECAR_ADMIN: &str = "forbidden_requires_sidecar_admin";
const REASON_AUTHORITATIVE_UNAVAILABLE: &str = "authoritative_sidecar_operation_unavailable";
const REASON_INVOCATION_NOT_FOUND: &str = "invocation_not_found";
const PIPELINE_UNAVAILABLE_REASON: &str = "provider_transport_unavailable";

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
pub(crate) struct SidecarPrimaryTrace {
    pub provider: String,
    pub model: String,
    pub trust: String,
    pub location: String,
    pub credential_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SidecarEffectiveTrace {
    /// Missing means the daemon resolver did not produce a primary identity.
    /// It is deliberately not rendered as an untrusted primary.
    pub primary: Option<SidecarPrimaryTrace>,
    pub matched_source: String,
    pub sidecar_provider: Option<String>,
    pub sidecar_model: Option<String>,
    pub origin: Option<String>,
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
    pub(crate) fn from_authoritative_config(config: &SidecarSelectionConfig) -> Self {
        let as_ref = |candidate: &SidecarProviderModel| SidecarModelRef {
            provider: candidate.provider.clone(),
            model: candidate.model.clone(),
        };
        Self {
            mode: match config.mode {
                cockpit_config::config::image_sidecar::SidecarMode::Automatic => {
                    SidecarModeChoice::Automatic
                }
                cockpit_config::config::image_sidecar::SidecarMode::Always => {
                    SidecarModeChoice::Always
                }
                cockpit_config::config::image_sidecar::SidecarMode::Never => {
                    SidecarModeChoice::Never
                }
            },
            trusted_default: config.trusted_primary_default.as_ref().map(as_ref),
            untrusted_default: config.untrusted_primary_default.as_ref().map(as_ref),
            override_pair: config.per_primary_override.as_ref().map(as_ref),
            ..Self::default()
        }
    }

    pub(crate) fn to_selection_config(&self) -> SidecarSelectionConfig {
        let to_pair = |r: &SidecarModelRef| SidecarProviderModel {
            provider: r.provider.clone(),
            model: r.model.clone(),
        };
        // Existing values are preserved verbatim. A discovered (not manually
        // configured) catalog row may no longer be offered by the editor, but
        // an unrelated cap/mode save must never silently delete it. New values
        // can enter this form only through the selectable-model handlers.
        let selected = |candidate: &Option<SidecarModelRef>| candidate.as_ref();
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
    pub grant_candidate_id: Option<String>,
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
            grant_candidate_id: None,
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
        self.grant_candidate_id = None;
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
        config_generation: u64,
    ) {
        *self = Self::new(
            daemon_instance,
            project_id,
            session_id,
            selection_id,
            config_generation,
        );
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
    /// Exact client operation id for the config CAS. A terminal rejection is
    /// correlated to this id rather than guessed from a revision transition.
    pub save_operation_id: Option<String>,
    /// Opaque revision consumed by the queued config mutation. Completion
    /// accepts only a different daemon-issued revision; a stale or failed
    /// request never clears the local authority fence.
    pub save_base_revision: Option<String>,
    /// A rejected CAS draft may be preserved, but cannot be resubmitted until
    /// the settings layer has been reloaded at a different daemon revision.
    pub reload_required_base_revision: Option<String>,
    pub reload_required_before_reapply: bool,
    pub health_refresh_pending: bool,
    pub remediation: Option<SidecarRemediation>,
    /// The daemon-issued settings snapshot enables only the config CAS path.
    /// Runtime health, grants, and accounting remain fail-closed until their
    /// own daemon-owned projections exist.
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
                String::new(),
                String::new(),
                String::new(),
                String::new(),
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
            save_operation_id: None,
            save_base_revision: None,
            reload_required_base_revision: None,
            reload_required_before_reapply: false,
            health_refresh_pending: false,
            remediation: None,
            authoritative_mutations: false,
            authoritative_snapshot: false,
        }
    }

    fn with_authoritative_config(
        principal: SidecarPrincipal,
        config: &SidecarSelectionConfig,
        central_cap: u64,
        snapshot_available: bool,
        project_id: String,
        selection_id: String,
        config_generation: u64,
    ) -> Self {
        let mut session = Self::new(principal);
        session.form = SidecarFormState::from_authoritative_config(config);
        session.form.central_cap = central_cap;
        session.policy.value = central_cap;
        // The settings snapshot is an opaque daemon-issued capability.  A
        // local owner cannot mutate until it exists; no client-side config
        // read is used as a fallback.
        session.authoritative_snapshot = snapshot_available;
        session.authoritative_mutations = snapshot_available && session.principal.can_mutate();
        session.reducer = SidecarReducer::new(
            String::new(),
            project_id,
            String::new(),
            selection_id,
            config_generation,
        );
        session
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
        config_generation: u64,
    ) {
        self.reducer.rebind(
            daemon_instance,
            project_id,
            session_id,
            selection_id,
            config_generation,
        );
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
        self.save_operation_id = None;
        self.save_base_revision = None;
        self.reload_required_base_revision = None;
        self.reload_required_before_reapply = false;
        self.health_refresh_pending = false;
        self.remediation = None;
    }

    fn complete_config_save(
        &mut self,
        revision: Option<&str>,
        config_generation: Option<u64>,
    ) -> bool {
        let Some(expected) = self.save_base_revision.as_deref() else {
            return false;
        };
        let Some(revision) = revision else {
            return false;
        };
        if revision == expected {
            return false;
        }
        self.save_pending = false;
        self.save_operation_id = None;
        self.save_base_revision = None;
        self.busy = false;
        self.policy.value = self.form.central_cap;
        self.policy.source = SidecarInvocationCapProvenance::Configured;
        self.form.local_edits_preserved = false;
        // A config write advances daemon generation. The prior sidecar
        // snapshot is no longer mutation authority, even if its selection id
        // is unchanged; rehydrate before any grant operation.
        self.reducer.config_generation = config_generation.unwrap_or(0);
        self.reducer.mark_stale();
        self.authoritative_snapshot = false;
        self.authoritative_mutations = false;
        true
    }

    fn complete_config_rejection(&mut self, operation_id: &str, message: &str) -> bool {
        if !self.save_pending || self.save_operation_id.as_deref() != Some(operation_id) {
            return false;
        }
        self.save_pending = false;
        self.save_operation_id = None;
        self.reload_required_base_revision = self.save_base_revision.take();
        self.reload_required_before_reapply = true;
        self.busy = false;
        self.conflict = Some(message.into());
        self.error = Some(message.into());
        true
    }

    fn reconcile_reloaded_revision(&mut self, revision: Option<&str>) {
        if !self.reload_required_before_reapply {
            return;
        }
        let reloaded = match self.reload_required_base_revision.as_deref() {
            Some(rejected_base) => revision.is_some_and(|revision| revision != rejected_base),
            None => revision.is_some(),
        };
        if reloaded {
            self.reload_required_base_revision = None;
            self.reload_required_before_reapply = false;
            self.conflict = None;
            self.error = None;
        }
    }

    fn requires_reload_before_reapply(&self) -> bool {
        self.reload_required_before_reapply
    }

    fn authority_request_identity(&self) -> (Option<String>, Option<String>) {
        (
            (!self.reducer.daemon_instance.is_empty())
                .then(|| self.reducer.daemon_instance.clone()),
            (!self.reducer.session_id.is_empty()).then(|| self.reducer.session_id.clone()),
        )
    }

    /// Returns only a daemon-issued candidate identity. The UI never submits a
    /// destination URL, so bearer paths/query strings cannot cross this path.
    fn grant_creation_candidate(&self) -> Result<String, &'static str> {
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
        if !resolution.available {
            return Err(match resolution.reason.as_str() {
                "provider_transport_unavailable" => PIPELINE_UNAVAILABLE_REASON,
                _ => REASON_DESTINATION_DENIED,
            });
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
        self.reducer
            .grant_candidate_id
            .clone()
            .ok_or(REASON_DESTINATION_DENIED)
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

#[cfg(test)]
pub(super) fn sidecar_overview_page(principal: SidecarPrincipal) -> PageBox {
    boxed(SidecarPage {
        kind: SidecarPageKind::Overview,
        session: SidecarSession::new(principal),
    })
}

pub(super) fn sidecar_overview_page_from_snapshot(
    principal: SidecarPrincipal,
    config: &SidecarSelectionConfig,
    central_cap: u64,
    snapshot_available: bool,
    project_id: String,
    selection_id: String,
    config_generation: u64,
) -> PageBox {
    boxed(SidecarPage {
        kind: SidecarPageKind::Overview,
        session: SidecarSession::with_authoritative_config(
            principal,
            config,
            central_cap,
            snapshot_available,
            project_id,
            selection_id,
            config_generation,
        ),
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

    fn queue_authority_request(&mut self, cx: &mut SettingsCx, request: cockpit_proto::Request) {
        if self.session.reducer.config_generation == 0
            || self.session.reducer.project_id.is_empty()
            || self.session.reducer.selection_id.is_empty()
        {
            self.session.error = Some(REASON_AUTHORITATIVE_UNAVAILABLE.into());
            return;
        }
        self.session.busy = true;
        self.session.error = None;
        cx.queue_image_sidecar_authority(
            request,
            self.session.reducer.project_id.clone(),
            self.session.reducer.selection_id.clone(),
        );
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
    if matches!(
        page.kind,
        SidecarPageKind::ModeEditor
            | SidecarPageKind::DefaultEditor
            | SidecarPageKind::OverrideEditor
            | SidecarPageKind::CentralPolicyEditor
    ) && page.session.conflict.is_some()
    {
        rows.push((
            format!(
                "Save rejected: {}. Reload current settings, then reapply this draft.",
                page.session
                    .conflict
                    .as_deref()
                    .unwrap_or("authority changed")
            ),
            None,
        ));
        rows.push((
            "[Reload current settings]".into(),
            Some((
                SidecarAction::ReloadSelection,
                !page.session.busy,
                Some("reload_current_settings"),
            )),
        ));
    }
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
            rows.push(selection_save_row(page, can_mutate, mutate_reason));
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
            rows.push(selection_save_row(page, can_mutate, mutate_reason));
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
            rows.push(selection_save_row(page, can_mutate, mutate_reason));
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
            } else if page.session.requires_reload_before_reapply() {
                Some(REASON_RELOAD_REQUIRED)
            } else if page.session.save_pending || page.session.busy {
                Some(REASON_SAVE_PENDING)
            } else if !page.session.form.local_edits_preserved {
                Some(REASON_NO_PENDING_CHANGES)
            } else {
                None
            };
            rows.push((
                "[Save]".into(),
                Some((
                    SidecarAction::SaveCentralPolicy,
                    can_mutate
                        && !page.session.requires_reload_before_reapply()
                        && !page.session.save_pending
                        && !page.session.busy
                        && page.session.form.local_edits_preserved,
                    save_reason,
                )),
            ));
            rows.push(("[Cancel]".into(), Some((SidecarAction::Cancel, true, None))));
        }
        SidecarPageKind::ResolverDetail => {
            if let Some(trace) = &page.session.reducer.resolution {
                if let Some(primary) = &trace.primary {
                    rows.push((
                        format!(
                            "primary={}:{} trust={}",
                            primary.provider, primary.model, primary.trust
                        ),
                        None,
                    ));
                    for line in TrustDisclosure::for_trust(primary.trust == "trusted").lines() {
                        rows.push((line, None));
                    }
                    rows.push((format!("location={}", primary.location), None));
                    rows.push((
                        format!("credential_fingerprint={}", primary.credential_fingerprint),
                        None,
                    ));
                } else {
                    rows.push(("Primary resolver details unavailable.".into(), None));
                }
                rows.push((
                    format!(
                        "Egress authority: destination={} scopes=once/session/project",
                        trace
                            .origin
                            .as_deref()
                            .map(sanitized_display_origin)
                            .unwrap_or_else(|| "unavailable".into())
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
                    format!(
                        "origin={}",
                        trace
                            .origin
                            .as_deref()
                            .map(sanitized_display_origin)
                            .unwrap_or_else(|| "unavailable".into())
                    ),
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
            let create = page.session.grant_creation_candidate();
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
            let create = page.session.grant_creation_candidate();
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

fn selection_save_row(
    page: &SidecarPage,
    can_mutate: bool,
    mutate_reason: Option<&'static str>,
) -> (String, SidecarBinding) {
    let reason = if !can_mutate {
        mutate_reason
    } else if page.session.requires_reload_before_reapply() {
        Some(REASON_RELOAD_REQUIRED)
    } else if page.session.save_pending || page.session.busy {
        Some(REASON_SAVE_PENDING)
    } else if !page.session.form.local_edits_preserved {
        Some(REASON_NO_PENDING_CHANGES)
    } else {
        None
    };
    (
        "[Save changes]".into(),
        Some((SidecarAction::SaveSelection, reason.is_none(), reason)),
    )
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
        cx: &mut SettingsCx,
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
                self.session.form.local_edits_preserved = true;
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
                    self.session.form.local_edits_preserved = true;
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
                    self.session.form.local_edits_preserved = true;
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
                    self.session.form.local_edits_preserved = true;
                    self.session.remediation = None;
                } else {
                    self.session.remediation = Some(SidecarRemediation::InvalidOverride);
                }
                Nav::Stay
            }
            SidecarAction::ClearOverride => {
                if self.session.authoritative_mutations {
                    self.session.form.override_pair = None;
                    self.session.form.local_edits_preserved = true;
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
            SidecarAction::SaveSelection | SidecarAction::SaveCentralPolicy => {
                if self.session.authoritative_mutations
                    && self.session.principal.can_mutate()
                    && !self.session.requires_reload_before_reapply()
                    && !self.session.save_pending
                    && self.session.form.local_edits_preserved
                {
                    let selection = self.session.form.to_selection_config();
                    let mut limits = cx.extended.media_resources.limits().clone();
                    limits.sidecar_invocations_per_session = self.session.form.central_cap;
                    let policy =
                        match cockpit_config::config::media_budget::MediaResourcePolicy::new(
                            cx.extended.media_resources.version(),
                            limits,
                            cx.extended.media_resources.profiles().clone(),
                        ) {
                            Ok(policy) => policy,
                            Err(_) => {
                                self.session.error = Some(REASON_AUTHORITATIVE_UNAVAILABLE.into());
                                return Nav::Stay;
                            }
                        };
                    cx.extended.image_sidecar = selection;
                    cx.extended.media_resources = Box::new(policy);
                    match cx.save_extended() {
                        Ok(_) => {
                            self.session.save_pending = true;
                            self.session.save_operation_id =
                                cx.last_extended_save_operation_id().map(str::to_owned);
                            self.session.save_base_revision = cx.extended_revision.clone();
                            self.session.busy = true;
                            self.session.error = None;
                        }
                        Err(error) => self.session.error = Some(error),
                    }
                } else {
                    self.session.error = Some(
                        if self.session.save_pending || self.session.busy {
                            REASON_SAVE_PENDING
                        } else if self.session.requires_reload_before_reapply() {
                            REASON_RELOAD_REQUIRED
                        } else if !self.session.form.local_edits_preserved {
                            REASON_NO_PENDING_CHANGES
                        } else {
                            REASON_AUTHORITATIVE_UNAVAILABLE
                        }
                        .into(),
                    );
                }
                Nav::Stay
            }
            SidecarAction::ReloadSelection => {
                if self.session.busy {
                    self.session.error = Some(REASON_SAVE_PENDING.into());
                } else {
                    // Keep the non-secret sidecar form draft in this page.
                    // The reload changes only the CAS base/revision in
                    // SettingsCx; the user can then explicitly reapply it.
                    cx.reload_extended();
                }
                Nav::Stay
            }
            SidecarAction::RefreshHealth => {
                let (expected_daemon_instance_id, expected_session_id) =
                    self.session.authority_request_identity();
                self.queue_authority_request(
                    cx,
                    cockpit_proto::Request::GetImageSidecarAuthoritySnapshot {
                        project_root: self.session.reducer.project_id.clone(),
                        config_generation: self.session.reducer.config_generation,
                        selection_id: self.session.reducer.selection_id.clone(),
                        expected_daemon_instance_id,
                        expected_session_id,
                    },
                );
                Nav::Stay
            }
            SidecarAction::SelectGrantScope(scope) => {
                self.session.form.draft_scope = scope;
                Nav::Stay
            }
            SidecarAction::CreateGrant => {
                if self.kind == SidecarPageKind::GrantList {
                    return self.push_kind(SidecarPageKind::GrantEditor);
                }
                let grant_candidate_id = match self.session.grant_creation_candidate() {
                    Ok(candidate) => candidate,
                    Err(reason) => {
                        self.session.error = Some(reason.into());
                        return Nav::Stay;
                    }
                };
                let (scope, session_id, invocation_id) = match self.session.form.draft_scope {
                    GrantScope::Once => {
                        let Some(invocation_id) = self.session.selected_invocation.clone() else {
                            self.session.error = Some(REASON_INVOCATION_NOT_FOUND.into());
                            return Nav::Stay;
                        };
                        (
                            cockpit_proto::image_sidecar_authority::ImageSidecarGrantScopeV1::Once,
                            Some(self.session.reducer.session_id.clone()),
                            Some(invocation_id),
                        )
                    }
                    GrantScope::Session => (
                        cockpit_proto::image_sidecar_authority::ImageSidecarGrantScopeV1::Session,
                        Some(self.session.reducer.session_id.clone()),
                        None,
                    ),
                    GrantScope::Project => (
                        cockpit_proto::image_sidecar_authority::ImageSidecarGrantScopeV1::Project,
                        None,
                        None,
                    ),
                };
                self.queue_authority_request(
                    cx,
                    cockpit_proto::Request::CreateImageSidecarGrant {
                        project_root: self.session.reducer.project_id.clone(),
                        config_generation: self.session.reducer.config_generation,
                        selection_id: self.session.reducer.selection_id.clone(),
                        expected_daemon_instance_id: self.session.authority_request_identity().0,
                        expected_session_id: self.session.authority_request_identity().1,
                        grant_candidate_id,
                        purpose: "ask_image".into(),
                        scope,
                        session_id,
                        invocation_id,
                    },
                );
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
                self.queue_authority_request(
                    cx,
                    cockpit_proto::Request::RevokeImageSidecarGrant {
                        project_root: self.session.reducer.project_id.clone(),
                        config_generation: self.session.reducer.config_generation,
                        selection_id: self.session.reducer.selection_id.clone(),
                        expected_daemon_instance_id: self.session.authority_request_identity().0,
                        expected_session_id: self.session.authority_request_identity().1,
                        grant_id: pending.grant_id,
                        expected_version: pending.version,
                    },
                );
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

impl SidecarPage {
    pub(super) fn apply_authoritative_settings_completion(
        &mut self,
        cx: &mut SettingsCx,
        completion: Option<Result<cockpit_proto::Response, String>>,
    ) {
        self.session
            .reconcile_reloaded_revision(cx.extended_revision.as_deref());
        if let Some(operation_id) = self.session.save_operation_id.as_deref()
            && let Some(error) = cx.extended_save_rejection(operation_id)
        {
            self.session.complete_config_rejection(operation_id, error);
        }
        let saved = self.session.complete_config_save(
            cx.extended_revision.as_deref(),
            cx.image_sidecar_config_generation(),
        );
        if saved && self.session.reducer.config_generation > 0 {
            let (expected_daemon_instance_id, expected_session_id) =
                self.session.authority_request_identity();
            self.queue_authority_request(
                cx,
                cockpit_proto::Request::GetImageSidecarAuthoritySnapshot {
                    project_root: self.session.reducer.project_id.clone(),
                    config_generation: self.session.reducer.config_generation,
                    selection_id: self.session.reducer.selection_id.clone(),
                    expected_daemon_instance_id,
                    expected_session_id,
                },
            );
        }
        let Some(completion) = completion else {
            return;
        };
        match completion {
            Ok(cockpit_proto::Response::ImageSidecarAuthoritySnapshot(snapshot)) => {
                let identity_changed = self.session.reducer.daemon_instance
                    != snapshot.daemon_instance_id
                    || self.session.reducer.session_id != snapshot.session_id
                    || self.session.reducer.project_id != snapshot.project_id;
                if identity_changed {
                    // The daemon owns the canonical project spelling and the
                    // connection/session identity. Rebinding clears every
                    // old projection before this response is allowed to
                    // hydrate the new authority domain.
                    self.session.rebind_identity(
                        snapshot.daemon_instance_id.clone(),
                        snapshot.project_id.clone(),
                        snapshot.session_id.clone(),
                        snapshot.selection_id.clone(),
                        snapshot.config_generation,
                    );
                    self.session.principal =
                        SidecarPrincipal::from_session(&cx.image_generation_session_snapshot());
                    self.session.form =
                        SidecarFormState::from_authoritative_config(&cx.extended.image_sidecar);
                }
                if snapshot.entity_version < self.session.reducer.entity_version {
                    // A concurrent snapshot for this same page completed after
                    // a newer grant mutation. It has no authority to rewind
                    // the current reducer and must not mark the page stale.
                    return;
                }
                if snapshot.schema_version != 1
                    || (!identity_changed
                        && snapshot.config_generation != self.session.reducer.config_generation)
                    || snapshot.selection_id != self.session.reducer.selection_id
                    || snapshot.project_id != self.session.reducer.project_id
                    || snapshot.daemon_instance_id != self.session.reducer.daemon_instance
                    || snapshot.session_id != self.session.reducer.session_id
                {
                    self.session.reducer.mark_stale();
                    self.session.authoritative_mutations = false;
                    self.session.error = Some(REASON_AUTHORITATIVE_UNAVAILABLE.into());
                    return;
                }
                self.session.reducer.entity_version = snapshot.entity_version;
                // Snapshot policy is daemon authority. In particular, a
                // rebind must not retain the reducer's zero generation or a
                // local default policy before mutation authority is enabled.
                self.session.reducer.config_generation = snapshot.config_generation;
                self.session.approval_mode = match snapshot.approval_mode {
                    cockpit_proto::image_sidecar_authority::ImageSidecarApprovalModeV1::Ask => {
                        ApprovalMode::Ask
                    }
                    cockpit_proto::image_sidecar_authority::ImageSidecarApprovalModeV1::Yolo => {
                        ApprovalMode::Yolo
                    }
                };
                self.session.policy = CentralPolicyView {
                    value: snapshot.central_invocation_cap,
                    source: match snapshot.central_invocation_cap_source {
                        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::CompiledCeiling => SidecarInvocationCapProvenance::CompiledCeiling,
                        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Configured => SidecarInvocationCapProvenance::Configured,
                        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Profile => SidecarInvocationCapProvenance::Profile,
                        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Adapter => SidecarInvocationCapProvenance::Adapter,
                        cockpit_proto::image_sidecar_authority::ImageSidecarInvocationCapSourceV1::Request => SidecarInvocationCapProvenance::Request,
                    },
                    hard_ceiling: snapshot.central_invocation_cap_hard_ceiling,
                };
                if identity_changed || !self.session.form.local_edits_preserved {
                    self.session.form.central_cap = snapshot.central_invocation_cap;
                }
                self.session.form.models = snapshot
                    .models
                    .into_iter()
                    .map(|model| SidecarModelOption {
                        provider: model.provider,
                        model: model.model,
                        configured: model.configured,
                        image_capable: model.image_capable,
                        fresh: model.fresh,
                    })
                    .collect();
                self.session.reducer.grant_candidate_id = snapshot.resolution.grant_candidate_id;
                self.session.reducer.resolution = Some(SidecarEffectiveTrace {
                    primary: None,
                    matched_source: "daemon".into(),
                    sidecar_provider: snapshot.resolution.provider,
                    sidecar_model: snapshot.resolution.model,
                    origin: snapshot.resolution.origin,
                    capability_source: "daemon".into(),
                    capability_freshness: "current".into(),
                    config_generation: snapshot.config_generation,
                    mode: self.session.form.mode,
                    available: snapshot.resolution.available,
                    fallback_outcome: None,
                    reason: snapshot.resolution.reason,
                });
                self.session.reducer.grants = snapshot
                    .grants
                    .into_iter()
                    .map(grant_view_from_authority)
                    .collect();
                self.session.reducer.invocations.clear();
                self.session.reducer.health = Some(HealthView {
                    available: false,
                    capability_source: "daemon".into(),
                    freshness: "current".into(),
                    reason: snapshot.health_reason,
                });
                self.session.reducer.stale = false;
                self.session.authoritative_snapshot = true;
                self.session.authoritative_mutations = self.session.principal.can_mutate();
                self.session.busy = false;
                self.session.error = None;
            }
            Ok(cockpit_proto::Response::ImageSidecarGrantMutated(mutation)) => {
                if mutation.schema_version != 1
                    || mutation.daemon_instance_id != self.session.reducer.daemon_instance
                    || mutation.session_id != self.session.reducer.session_id
                    || mutation.config_generation != self.session.reducer.config_generation
                    || mutation.selection_id != self.session.reducer.selection_id
                    || mutation.entity_version
                        != self.session.reducer.entity_version.saturating_add(1)
                {
                    self.session.reducer.mark_stale();
                    self.session.authoritative_mutations = false;
                    self.session.error = Some(REASON_AUTHORITATIVE_UNAVAILABLE.into());
                    let (expected_daemon_instance_id, expected_session_id) =
                        self.session.authority_request_identity();
                    self.queue_authority_request(
                        cx,
                        cockpit_proto::Request::GetImageSidecarAuthoritySnapshot {
                            project_root: self.session.reducer.project_id.clone(),
                            config_generation: self.session.reducer.config_generation,
                            selection_id: self.session.reducer.selection_id.clone(),
                            expected_daemon_instance_id,
                            expected_session_id,
                        },
                    );
                    return;
                }
                let grant = grant_view_from_authority(mutation.grant);
                if let Some(existing) = self
                    .session
                    .reducer
                    .grants
                    .iter_mut()
                    .find(|existing| existing.grant_id == grant.grant_id)
                {
                    *existing = grant;
                } else {
                    self.session.reducer.grants.push(grant);
                }
                self.session.reducer.entity_version = mutation.entity_version;
                self.session.busy = false;
                self.session.error = None;
            }
            Ok(other) => {
                self.session.busy = false;
                self.session.error =
                    Some(format!("unexpected sidecar authority response: {other:?}"));
            }
            Err(error) => {
                self.session.busy = false;
                self.session.error = Some(error);
            }
        }
    }
}

fn grant_view_from_authority(
    grant: cockpit_proto::image_sidecar_authority::ImageSidecarGrantV1,
) -> GrantView {
    let scope = match grant.scope {
        cockpit_proto::image_sidecar_authority::ImageSidecarGrantScopeV1::Once => GrantScope::Once,
        cockpit_proto::image_sidecar_authority::ImageSidecarGrantScopeV1::Session => {
            GrantScope::Session
        }
        cockpit_proto::image_sidecar_authority::ImageSidecarGrantScopeV1::Project => {
            GrantScope::Project
        }
    };
    GrantView {
        grant_id: grant.grant_id,
        version: grant.version,
        project: grant.project_id,
        destination: grant.destination,
        media_class: "image".into(),
        purpose: grant.purpose,
        scope,
        session_binding: grant.session_id,
        invocation_binding: grant.invocation_id,
        created_at: grant.created_at_unix_ms.to_string(),
        last_used_at: grant
            .last_used_at_unix_ms
            .map(|timestamp| timestamp.to_string()),
        revoked: grant.revoked_at_unix_ms.is_some(),
        consumed: grant.consumed_at_unix_ms.is_some(),
    }
}
