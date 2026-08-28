//! Durable, daemon-local vNext agent installation and model-slot bindings.
//!
//! This module is intentionally an opaque persistence boundary.  It neither
//! loads definition files nor parses provider configuration, and its payloads
//! are already-resolved, canonical, redacted bytes supplied by the daemon.

use std::collections::HashSet;
use std::fmt;

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentInstallationScope {
    Global,
    WorkspacePrivate,
    WorkspaceShared,
}

impl AgentInstallationScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::WorkspacePrivate => "workspace_private",
            Self::WorkspaceShared => "workspace_shared",
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "global" => Ok(Self::Global),
            "workspace_private" => Ok(Self::WorkspacePrivate),
            "workspace_shared" => Ok(Self::WorkspaceShared),
            _ => bail!("unknown agent installation scope `{value}`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInstallationInput {
    pub installation_id: Uuid,
    pub scope: AgentInstallationScope,
    /// Canonical daemon-supplied workspace identity.  It is required for both
    /// workspace scopes and forbidden for global installations; DB does no
    /// filesystem canonicalization.
    pub canonical_workspace_id: Option<String>,
    pub source_agent_id: String,
    /// Opaque source/path/publisher identity, never definition Markdown.
    pub source_identity: String,
    pub source_revision: Option<String>,
    pub source_digest: String,
    pub fetched_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInstallationRow {
    pub installation_id: Uuid,
    pub scope: AgentInstallationScope,
    pub canonical_workspace_id: Option<String>,
    pub source_agent_id: String,
    pub source_identity: String,
    pub source_revision: Option<String>,
    pub source_digest: String,
    pub fetched_at_unix_ms: i64,
    pub installation_revision: u64,
    pub deleted_at_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallAgentOutcome {
    Installed(AgentInstallationRow),
    AlreadyInstalled(AgentInstallationRow),
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentObservationRow {
    pub installation_id: Uuid,
    pub observed_digest: String,
    pub observation_revision: u64,
    pub reviewed: bool,
    pub observed_at_unix_ms: i64,
}

/// Exact pre-replacement state kept by the daemon operation journal.  It is
/// deliberately limited to mutable installation/observation/binding state:
/// immutable profile snapshots and their historical receipts are never
/// modified by replacement compensation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentReplacementCompensationReceipt {
    /// The durable daemon installation-operation that owns this replacement.
    /// It is distinct from the pre-existing installation id and lets recovery
    /// reject a receipt copied from a different operation without comparing a
    /// retry's wall clock to the original mutation time.
    pub replacement_operation_id: Uuid,
    pub installation_id: Uuid,
    pub prior_source_identity: String,
    pub prior_source_revision: Option<String>,
    pub prior_source_digest: String,
    pub prior_fetched_at_unix_ms: i64,
    pub prior_installation_revision: u64,
    pub prior_deleted_at_unix_ms: Option<i64>,
    pub prior_observed_digest: String,
    pub prior_observation_revision: u64,
    pub prior_reviewed: bool,
    pub prior_observed_at_unix_ms: i64,
    /// Only bindings that were current before this replacement may be
    /// unretired. This prevents compensation from reviving a later bind.
    pub prior_current_binding_ids: Vec<Uuid>,
    pub replacement_source_identity: String,
    pub replacement_source_revision: Option<String>,
    pub replacement_source_digest: String,
    pub replacement_fetched_at_unix_ms: i64,
    pub replacement_retired_at_unix_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompensateAgentReplacementOutcome {
    Restored,
    AlreadyRestored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserveAgentOutcome {
    Current(AgentObservationRow),
    RebindRequired(AgentObservationRow),
    Deleted,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingInput {
    pub slot_id: String,
    /// Opaque daemon-local handle only; credentials remain outside SQLite.
    pub provider_profile_handle: String,
    pub model_id: String,
    /// Canonical redacted recommendation/capability/alias provenance bytes.
    pub provenance_payload: Vec<u8>,
    pub provenance_digest: String,
    /// Core has already established that the model is hard-compatible.  The
    /// database refuses an unverified binding rather than persisting a later
    /// usable-looking invalid record.
    pub hard_capability_verified: bool,
    /// Exactly one live binding per slot may be the default.
    pub is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingRow {
    pub binding_id: Uuid,
    pub installation_id: Uuid,
    pub definition_digest: String,
    pub slot_id: String,
    pub provider_profile_handle: String,
    pub model_id: String,
    pub provenance_payload: Vec<u8>,
    pub provenance_digest: String,
    /// Persisted evidence that the daemon rejected failed/unknown hard
    /// capabilities before this binding became selectable.
    pub hard_capability_verified: bool,
    pub binding_revision: u64,
    pub is_default: bool,
    pub retired_at_unix_ms: Option<i64>,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindAgentOutcome {
    Bound(AgentBindingRow),
    AlreadyBound(AgentBindingRow),
    RebindRequired,
    Conflict,
    Deleted,
    NotFound,
    Incompatible,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRebindInput {
    pub installation_id: Uuid,
    pub expected_observation_revision: u64,
    pub expected_observed_digest: String,
    pub new_observed_digest: String,
    pub bindings: Vec<AgentBindingInput>,
    pub now_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindSlotSetInput {
    pub installation_id: Uuid,
    pub expected_observation_revision: u64,
    pub expected_definition_digest: String,
    pub expected_binding_revision: Option<u64>,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub bindings: Vec<AgentBindingInput>,
    pub now_unix_ms: i64,
}

/// One package-private child's complete daemon-derived binding material. The
/// database fills in the child installation/observation generations inside
/// the same transaction that validates the owning parent generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageChildSlotBindingInput {
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub bindings: Vec<AgentBindingInput>,
}

/// Atomic package-child materialization guarded by the reviewed whole-tree
/// generation of its parent. A stale or unreviewed parent aborts before any
/// child installation, observation, or binding row can change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializePackageChildInput {
    pub parent_installation_id: Uuid,
    pub expected_parent_installation_revision: u64,
    pub expected_parent_observation_revision: u64,
    pub expected_parent_definition_digest: String,
    /// Daemon-authenticated namespace marker tying both a prior child row and
    /// its replacement to this exact parent installation. Storage treats it
    /// as opaque and never derives package authority from source names.
    pub child_source_identity_guard: String,
    pub child: AgentInstallationInput,
    pub slot_bindings: Vec<PackageChildSlotBindingInput>,
    pub now_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebindAgentOutcome {
    Rebound(AgentObservationRow),
    RebindRequired,
    Conflict,
    Deleted,
    NotFound,
    Incompatible,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBindingExpectation {
    pub slot_id: String,
    pub provider_profile_handle: String,
    pub model_id: String,
    pub expected_binding_revision: u64,
}

/// Complete child-generation evidence folded into the same transaction as the
/// root session preparation. The expected binding set includes every live row
/// for the child definition generation; the persisted snapshot may retain only
/// the hard-compatible primary routes, but every retained route must belong to
/// this atomically validated set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentChildBindingSetExpectation {
    pub installation_id: Uuid,
    pub expected_installation_revision: u64,
    pub expected_observation_revision: u64,
    pub expected_definition_digest: String,
    pub expected_bindings: Vec<AgentBindingExpectation>,
}

/// The daemon-owned minimum needed to create the ordinary `sessions` row in
/// the same transaction as an agent-profile preparation.  The sessions table
/// deliberately owns its other fields and defaults; this type prevents the
/// agent-installation boundary from guessing at or duplicating them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSessionCreateInput {
    pub project_id: String,
    pub project_root: String,
    pub active_agent: String,
    /// Daemon-observed wall-clock time in signed Unix milliseconds.
    pub started_at_unix_ms: i64,
    pub last_active_at_unix_ms: i64,
}

/// Canonical, redacted evidence for one locally selected model slot.  This is
/// deliberately owned by `cockpit-db`: the DB validates persistence
/// invariants without importing a resolver, provider configuration, or any
/// credential-bearing type from a higher crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedBindingEvidence {
    pub slot_id: String,
    pub binding_revision: u64,
    pub provider_profile_handle: String,
    pub model_id: String,
    /// The exact provider/model identity selected by the resolver.  This is
    /// provenance only; the opaque profile handle remains the sole local
    /// credential-bearing indirection and no credential enters this value.
    pub selected_provider_alias: ProviderAlias,
    pub provenance_digest: String,
    pub hard_capability_verified: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_default: bool,
}

/// Immutable hard requirements for one prepared child slot. String-valued
/// capabilities/locality keep the storage crate policy-free while allowing the
/// core resolver to re-check a focused private-child route against the current
/// provider generation without reopening mutable definition files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedModelSlotRequirements {
    pub min_context_tokens: u64,
    pub required_capabilities: Vec<String>,
    pub locality: String,
    pub allowed_models: Vec<ProviderAlias>,
}

/// Session-pinned binding evidence for one authorized child installation.
/// Child routes are separate from the root slot set so a same-named slot can
/// never borrow the root's provider/model default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedChildBindingEvidence {
    pub installation_id: Uuid,
    pub installation_revision: u64,
    pub observation_revision: u64,
    pub definition_digest: String,
    pub binding: RedactedBindingEvidence,
    pub slot_requirements: RedactedModelSlotRequirements,
}

/// A provider/model pair is an identity, not a free-form display alias.  The
/// canonical snapshot keeps these pairs sorted and unique so a reload cannot
/// silently pick a different model for the same provider spelling.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAlias {
    pub provider_id: String,
    pub model_id: String,
}

/// A stable author recommendation record.  Its order is semantic: callers
/// must not sort or re-resolve it when a snapshot is reloaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedRecommendation {
    pub recommendation_id: String,
    /// The selected local slot this recommendation describes.  A snapshot
    /// cannot leave a recommendation floating between bindings.
    pub slot_id: String,
    pub canonical_upstream_identity: String,
    /// Author prose is optional, but a present value must be meaningful.
    pub author_label: Option<String>,
    pub rationale: Option<String>,
    /// Author-declared aliases in canonical provider/model order.  They are
    /// not a provider routing table and contain no credential-bearing route
    /// data.
    pub provider_aliases: Vec<ProviderAlias>,
    pub exact_provider_alias: Option<ProviderAlias>,
    pub author_suggested: bool,
    pub alias_collision_rank: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactedQuestionPolicy {
    /// Questions are durably disabled for this session.  Reload must not
    /// consult mutable defaults and turn this into an enabled policy.
    Off,
    /// Fully resolved active question policy.  Its resolver is pinned to a
    /// snapshot binding, its resource ceiling is explicit, and prohibited
    /// classes are the already-unioned effective set.
    Active {
        auto_answer_disabled: bool,
        prohibited_classes: Vec<String>,
        required_decision_timeout_ms: u64,
        host_resource_ceiling_ms: u64,
        resolver_order: QuestionResolverOrder,
        resolver_slot: String,
    },
}

/// Closed snapshot counterpart of the core question resolver order.  Keeping
/// this enum in cockpit-db avoids an upward dependency on cockpit-core while
/// ensuring corrupt/unrecognized values cannot broaden a persisted policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionResolverOrder {
    WarmParentThenUtility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentExecutionKind {
    Assistant,
    Coding,
    Computer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationTarget {
    SameRoot,
    Subdirectory,
    ManagedWorktree,
}

/// Closed, resolved child identity retained by an effective delegation
/// snapshot.  A daemon-local installation and a portable definition reference
/// are deliberately not interchangeable: collapsing either to a string would
/// let reload lose the authority boundary that core already resolved.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactedAllowedChild {
    LocalInstallation {
        installation_id: Uuid,
        /// The child execution kind was checked against the parent and host
        /// grant before the snapshot was written.  Reload uses this durable
        /// fact instead of rediscovering the child's editable definition.
        execution_kind: AgentExecutionKind,
    },
    /// Explicit recursion into the already-CAS-pinned root installation.
    /// This is not a second child generation: representing it separately
    /// prevents duplicate root/child CAS evidence while retaining the
    /// authored self route in the immutable delegation grant.
    SelfInvocation {
        execution_kind: AgentExecutionKind,
    },
    PortableRef {
        canonical_agent_ref: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedEffectiveDelegation {
    /// Fully resolved daemon-local child identities, sorted and deduplicated.
    /// Canonical persisted snapshots reject portable references: profile
    /// resolution must convert each of those to one local installation first.
    pub allowed_children: Vec<RedactedAllowedChild>,
    pub max_descendant_depth: u16,
    pub max_concurrent_children: u16,
    pub targets: Vec<DelegationTarget>,
    /// Effective host-policy decision for computer children.  This is not
    /// authored definition metadata; it is the fail-closed result that was
    /// actually granted to this session and must not be recomputed on reload.
    pub computer_delegation_enabled: bool,
}

impl RedactedEffectiveDelegation {
    /// Determine whether this already-resolved snapshot authorizes a child of
    /// the requested execution kind. Computer children additionally require
    /// the immutable host-policy result captured above.
    pub fn permits_child_kind(
        &self,
        child: &RedactedAllowedChild,
        child_kind: AgentExecutionKind,
    ) -> bool {
        match child {
            RedactedAllowedChild::LocalInstallation { execution_kind, .. } => {
                self.allowed_children.contains(child)
                    && *execution_kind == child_kind
                    && (child_kind != AgentExecutionKind::Computer
                        || self.computer_delegation_enabled)
            }
            RedactedAllowedChild::SelfInvocation { execution_kind } => {
                self.allowed_children.contains(child)
                    && *execution_kind == child_kind
                    && child_kind != AgentExecutionKind::Computer
            }
            // Portable references must have been resolved to a concrete local
            // installation before a session snapshot is used for delegation.
            RedactedAllowedChild::PortableRef { .. } => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationEffectiveAction {
    Off,
    Verify,
}

/// A closed, durable selector representation.  It retains boolean structure
/// instead of flattening predicates into display strings, so reload can apply
/// first-match exclusions without consulting mutable definitions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RedactedVerificationPredicate {
    ToolClass { tool_class: String },
    ToolId { tool_id: String },
    Namespace { namespace: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RedactedVerificationSelector {
    pub all_of: Vec<RedactedVerificationPredicate>,
    pub any_of: Vec<RedactedVerificationPredicate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedactedVerificationSubject {
    pub tool_class: Option<String>,
    pub tool_id: Option<String>,
    pub namespace: Option<String>,
}

impl RedactedVerificationSelector {
    pub fn matches(&self, subject: &RedactedVerificationSubject) -> bool {
        self.all_of
            .iter()
            .all(|predicate| predicate.matches(subject))
            && (self.any_of.is_empty()
                || self
                    .any_of
                    .iter()
                    .any(|predicate| predicate.matches(subject)))
    }
}

impl RedactedVerificationPredicate {
    fn matches(&self, subject: &RedactedVerificationSubject) -> bool {
        match self {
            Self::ToolClass { tool_class } => subject.tool_class.as_deref() == Some(tool_class),
            Self::ToolId { tool_id } => subject.tool_id.as_deref() == Some(tool_id),
            Self::Namespace { namespace } => subject.namespace.as_deref() == Some(namespace),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedVerificationGenerator {
    pub slot: String,
    pub recipe: RedactedVerificationRecipe,
    pub max_turns: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactedVerificationRecipe {
    Inherit,
    CleanRoom {
        include_linked_files: bool,
        last_n_reads: u8,
    },
}

/// Complete non-secret execution policy for one enabled verification region.
/// Keeping recipes, turn bounds, and failure policies in the immutable profile
/// snapshot prevents a changed or missing authored definition from changing a
/// live session's behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedVerificationExecutionPlan {
    pub mode: String,
    pub generators: Vec<RedactedVerificationGenerator>,
    pub on_budget_exceeded: String,
    pub on_adjudication_failure: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedVerificationRegion {
    pub source_rule_id: String,
    /// The source rule selector before first-match subtraction.
    pub source_selector: RedactedVerificationSelector,
    /// Every earlier source selector.  An effective region matches only when
    /// none of these match, preserving `rule - earlier_rules` exactly.
    pub excluded_prior_selectors: Vec<RedactedVerificationSelector>,
    /// Optional session reduction, evaluated as a further intersection with
    /// the source selector. `None` means no session selector reduction.
    pub session_selector: Option<RedactedVerificationSelector>,
    /// The already-resolved intersection which remains enabled for this
    /// source rule.  Reload must consume it, not re-run first-match rules.
    pub enabled_intersection_mask: Vec<String>,
    pub enabled: bool,
    /// Explicit exclusions from a partially enabled source-rule region.
    pub explicit_off_remainder_mask: Vec<String>,
    /// An explicit whole-region exclusion is distinct from an empty
    /// remainder mask, which means no remainder was excluded.
    pub whole_region_off: bool,
    /// Canonical selector identities for a full-region exclusion.  This must
    /// be present exactly when `whole_region_off` is true, so reload cannot
    /// turn an excluded region into a later-rule fall-through.
    pub whole_region_off_mask: Vec<String>,
    pub effective_action: VerificationEffectiveAction,
    /// An enabled verification region is dispatched through this exact
    /// session-pinned binding.  Off regions deliberately carry no executor.
    pub adjudicator_slot: Option<String>,
    pub count_ceiling: Option<u64>,
    pub token_ceiling: Option<u64>,
    pub cost_ceiling_micros: Option<u64>,
    /// A bounded collection duration, not an absolute deadline.  The
    /// resolver has no clock input, so persisting this as a Unix timestamp
    /// would misrepresent its semantics on reload.
    pub max_collection_duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_plan: Option<RedactedVerificationExecutionPlan>,
}

impl RedactedVerificationRegion {
    pub fn matches(&self, subject: &RedactedVerificationSubject) -> bool {
        self.source_selector.matches(subject)
            && !self
                .excluded_prior_selectors
                .iter()
                .any(|selector| selector.matches(subject))
            && self
                .session_selector
                .as_ref()
                .is_none_or(|selector| selector.matches(subject))
    }
}

/// The complete canonical non-secret payload pinned to a session.  These
/// records are intentionally data-only: DB does not interpret actions or
/// recompute rule precedence on reload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedAgentProfileSnapshot {
    pub agent_id: String,
    pub execution_kind: AgentExecutionKind,
    /// `None` means the resolved grant is a leaf.  This is an effective
    /// authority snapshot, never an authored declaration to re-evaluate.
    pub effective_delegation: Option<RedactedEffectiveDelegation>,
    pub recommendations: Vec<RedactedRecommendation>,
    pub question_policy: RedactedQuestionPolicy,
    pub verification_regions: Vec<RedactedVerificationRegion>,
    pub bindings: Vec<RedactedBindingEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub child_bindings: Vec<RedactedChildBindingEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBindingRevisionMap {
    pub bindings: Vec<AgentBindingRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBindingRevision {
    pub slot_id: String,
    pub provider_profile_handle: String,
    pub model_id: String,
    pub binding_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareAgentSessionInput {
    pub session_id: Uuid,
    /// Values used only if `session_id` has not been persisted yet. Supplying
    /// them on every call makes a retry safe whether it races creation or a
    /// separately registered existing-session claim.
    pub session_create: AgentSessionCreateInput,
    /// Required only when claiming a previously registered idle session.  A
    /// missing session is created by this transaction and must not supply one.
    pub existing_session_claim_token: Option<Uuid>,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub installation_id: Uuid,
    pub expected_installation_revision: u64,
    pub expected_observation_revision: u64,
    pub expected_definition_digest: String,
    pub expected_bindings: Vec<AgentBindingExpectation>,
    pub expected_children: Vec<AgentChildBindingSetExpectation>,
    pub snapshot_schema_version: u64,
    /// Canonical redacted profile including resolved recommendations,
    /// question policy, and effective verification regions.  The storage
    /// layer never recomputes it.
    pub canonical_snapshot_payload: Vec<u8>,
    pub canonical_snapshot_digest: String,
    pub binding_revision_map_payload: Vec<u8>,
    pub binding_revision_map_digest: String,
    pub now_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProfileSnapshotRow {
    pub snapshot_id: Uuid,
    pub session_id: Uuid,
    pub installation_id: Uuid,
    pub schema_version: u64,
    pub canonical_payload: Vec<u8>,
    pub canonical_payload_digest: String,
    pub definition_digest: String,
    pub binding_revision_map_payload: Vec<u8>,
    pub binding_revision_map_digest: String,
    pub created_at_unix_ms: i64,
}

/// One coherent, read-only input record for daemon session-setup projection.
/// It is assembled on one SQLite connection so a caller never combines an
/// installation row from one revision with bindings or selection from another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupInstallationSnapshotRow {
    pub installation: AgentInstallationRow,
    pub observation: Option<AgentObservationRow>,
    pub bindings: Vec<AgentBindingRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupDbSnapshot {
    pub selected_installation_id: Option<Uuid>,
    pub installations: Vec<SessionSetupInstallationSnapshotRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareAgentSessionOutcome {
    Prepared(AgentProfileSnapshotRow),
    AlreadyPrepared(AgentProfileSnapshotRow),
    AlreadyStarted(AgentProfileSnapshotRow),
    Terminal(AgentProfileSnapshotRow),
    RebindRequired,
    Conflict,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartAgentSessionOutcome {
    Started(AgentProfileSnapshotRow),
    AlreadyStarted(AgentProfileSnapshotRow),
    Terminal(AgentProfileSnapshotRow),
    NotPrepared,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterAgentSessionPreparationOutcome {
    Eligible,
    AlreadyEligible,
    Conflict,
    Terminal,
    Deleted,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteAgentInstallationOutcome {
    Tombstoned,
    Deleted,
    AlreadyDeleted,
    NotFound,
}

impl fmt::Display for AgentInstallationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Db {
    /// Capture the exact mutable state that a replacement is allowed to
    /// compensate. The caller persists this receipt before invoking
    /// [`Self::replace_agent`], so a crash after the DB transaction retains
    /// enough information to make recovery idempotent.
    pub async fn agent_replacement_compensation_receipt(
        &self,
        installation_id: Uuid,
        replacement: AgentInstallationInput,
        replacement_retired_at_unix_ms: i64,
    ) -> Result<AgentReplacementCompensationReceipt> {
        self.read(move |conn| {
            replacement_compensation_receipt_conn(
                conn,
                installation_id,
                &replacement,
                replacement_retired_at_unix_ms,
            )
        })
        .await
    }

    /// Restore a replacement only when the installation still exactly equals
    /// the replacement captured by its receipt. The check makes retry after a
    /// crash safe and refuses to overwrite any subsequent mutation.
    pub async fn compensate_agent_replacement(
        &self,
        receipt: AgentReplacementCompensationReceipt,
    ) -> Result<CompensateAgentReplacementOutcome> {
        self.transaction(move |conn| compensate_agent_replacement_conn(conn, &receipt))
            .await
    }

    /// True only after a prior compensation transaction has restored every
    /// mutable installation and observation field captured by the receipt.
    pub async fn agent_replacement_is_compensated(
        &self,
        receipt: AgentReplacementCompensationReceipt,
    ) -> Result<bool> {
        self.read(move |conn| {
            let Some(installation) = installation_by_id(conn, receipt.installation_id)? else {
                return Ok(false);
            };
            let Some(observation) = observation_by_id(conn, receipt.installation_id)? else {
                return Ok(false);
            };
            Ok(compensation_is_already_restored(
                &installation,
                &observation,
                &receipt,
            ))
        })
        .await
    }

    /// Replace the bytes/provenance of an existing installation in the owning
    /// installation transaction. Existing bindings are retired atomically so
    /// a new definition can never inherit an unchecked provider route.
    pub async fn replace_agent(
        &self,
        input: AgentInstallationInput,
        now_unix_ms: i64,
    ) -> Result<InstallAgentOutcome> {
        self.transaction(move |conn| replace_agent_conn(conn, &input, now_unix_ms))
            .await
    }

    /// Replace one explicit daemon-owned installation. Unlike
    /// [`Self::replace_agent`], this never resolves the target from a source
    /// identity: callers that already selected an installation (notably
    /// `agent update INSTALLATION_ID`) must not be able to redirect a replace
    /// merely by fetching an AgentDef with a different identity.
    pub async fn replace_agent_at(
        &self,
        installation_id: Uuid,
        input: AgentInstallationInput,
        now_unix_ms: i64,
    ) -> Result<InstallAgentOutcome> {
        self.transaction(move |conn| {
            replace_agent_at_conn(conn, installation_id, &input, now_unix_ms)
        })
        .await
    }
    pub async fn agent_installation(
        &self,
        installation_id: Uuid,
    ) -> Result<Option<AgentInstallationRow>> {
        self.read(move |conn| installation_by_id(conn, installation_id))
            .await
    }

    pub async fn install_agent(
        &self,
        input: AgentInstallationInput,
    ) -> Result<InstallAgentOutcome> {
        self.transaction(move |conn| install_agent_conn(conn, &input))
            .await
    }

    pub async fn observe_agent_definition(
        &self,
        installation_id: Uuid,
        observed_digest: String,
        now_unix_ms: i64,
    ) -> Result<ObserveAgentOutcome> {
        self.transaction(move |conn| {
            observe_agent_definition_conn(conn, installation_id, &observed_digest, now_unix_ms)
        })
        .await
    }

    // The durable bind CAS deliberately carries identity, definition, prior
    // binding generation, idempotency identity, binding payload and clock as
    // separate values. Collapsing them into a public request object would
    // obscure the database boundary while adding no validation ownership.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind_agent_model(
        &self,
        installation_id: Uuid,
        definition_digest: String,
        expected_binding_revision: Option<u64>,
        idempotency_key: String,
        request_fingerprint: String,
        binding: AgentBindingInput,
        now_unix_ms: i64,
    ) -> Result<BindAgentOutcome> {
        self.transaction(move |conn| {
            bind_agent_model_conn(
                conn,
                installation_id,
                &definition_digest,
                expected_binding_revision,
                &idempotency_key,
                &request_fingerprint,
                &binding,
                now_unix_ms,
            )
        })
        .await
    }

    pub async fn bind_agent_slot_set(
        &self,
        input: AgentBindSlotSetInput,
    ) -> Result<BindAgentOutcome> {
        self.transaction(move |conn| bind_agent_slot_set_conn(conn, &input))
            .await
    }

    pub async fn materialize_package_child(
        &self,
        input: MaterializePackageChildInput,
    ) -> Result<AgentInstallationRow> {
        self.transaction(move |conn| materialize_package_child_conn(conn, &input))
            .await
    }

    /// Materialize every private child derived from one reviewed package in a
    /// single parent-CAS transaction. A malformed or stale later child rolls
    /// back earlier children instead of publishing a partial package tree.
    pub async fn materialize_package_children(
        &self,
        inputs: Vec<MaterializePackageChildInput>,
    ) -> Result<Vec<AgentInstallationRow>> {
        self.transaction(move |conn| materialize_package_children_conn(conn, &inputs))
            .await
    }

    pub async fn rebind_agent(&self, input: AgentRebindInput) -> Result<RebindAgentOutcome> {
        self.transaction(move |conn| rebind_agent_conn(conn, &input))
            .await
    }

    pub async fn prepare_agent_session(
        &self,
        input: PrepareAgentSessionInput,
    ) -> Result<PrepareAgentSessionOutcome> {
        self.transaction(move |conn| prepare_agent_session_conn(conn, &input))
            .await
    }

    /// Record the only durable authorization for a pre-existing session to be
    /// adopted by `prepare_agent_session`.  Callers create ordinary sessions
    /// however they normally do, then explicitly mark an idle one with a
    /// fresh token; preparation consumes that token with a CAS.
    pub async fn register_agent_session_preparation(
        &self,
        session_id: Uuid,
        claim_token: Uuid,
        now_unix_ms: i64,
    ) -> Result<RegisterAgentSessionPreparationOutcome> {
        self.transaction(move |conn| {
            register_agent_session_preparation_conn(conn, session_id, claim_token, now_unix_ms)
        })
        .await
    }

    pub async fn start_prepared_agent_session(
        &self,
        session_id: Uuid,
        idempotency_key: String,
        now_unix_ms: i64,
    ) -> Result<StartAgentSessionOutcome> {
        self.transaction(move |conn| {
            start_prepared_agent_session_conn(conn, session_id, &idempotency_key, now_unix_ms)
        })
        .await
    }

    pub async fn terminal_agent_session(
        &self,
        session_id: Uuid,
        idempotency_key: String,
        now_unix_ms: i64,
    ) -> Result<StartAgentSessionOutcome> {
        self.transaction(move |conn| {
            terminal_agent_session_conn(conn, session_id, &idempotency_key, now_unix_ms)
        })
        .await
    }

    pub async fn delete_agent_installation(
        &self,
        installation_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<DeleteAgentInstallationOutcome> {
        self.transaction(move |conn| {
            delete_agent_installation_conn(conn, installation_id, now_unix_ms)
        })
        .await
    }

    pub async fn agent_profile_snapshot(
        &self,
        session_id: Uuid,
    ) -> Result<Option<AgentProfileSnapshotRow>> {
        self.read(move |conn| snapshot_for_session(conn, session_id))
            .await
    }

    /// Loads the immutable snapshot selected for an agent instance. The
    /// session predicate prevents an instance ID from becoming a cross-session
    /// profile oracle and callers must reconstruct it before routing.
    pub async fn agent_profile_snapshot_by_id(
        &self,
        session_id: Uuid,
        snapshot_id: Uuid,
    ) -> Result<Option<AgentProfileSnapshotRow>> {
        self.read(move |conn| {
            let snapshot = snapshot_by_id(conn, snapshot_id)?;
            Ok(snapshot.filter(|snapshot| snapshot.session_id == session_id))
        })
        .await
    }

    pub async fn current_agent_binding(
        &self,
        installation_id: Uuid,
        definition_digest: String,
        slot_id: String,
    ) -> Result<Option<AgentBindingRow>> {
        self.read(move |conn| {
            current_usable_binding(conn, installation_id, &definition_digest, &slot_id)
        })
        .await
    }

    /// Current hard-verified bindings for a definition digest. Returned rows
    /// remain daemon-local; callers must redact profile handles before wire use.
    pub async fn current_agent_bindings(
        &self,
        installation_id: Uuid,
        definition_digest: String,
    ) -> Result<Vec<AgentBindingRow>> {
        self.read(move |conn| {
            current_bindings_for_digest(conn, installation_id, &definition_digest)
        })
        .await
    }

    /// Look up one installation by its daemon-owned source identity.  The
    /// caller must supply the same canonical workspace identity used during
    /// installation; this layer never inspects a filesystem path.
    pub async fn agent_installation_by_source(
        &self,
        scope: AgentInstallationScope,
        canonical_workspace_id: Option<String>,
        source_agent_id: String,
    ) -> Result<Option<AgentInstallationRow>> {
        let key = scope_key(scope, canonical_workspace_id.as_deref())?;
        self.read(move |conn| installation_by_identity(conn, scope, &key, &source_agent_id))
            .await
    }

    pub async fn agent_observation(
        &self,
        installation_id: Uuid,
    ) -> Result<Option<AgentObservationRow>> {
        self.read(move |conn| observation_by_id(conn, installation_id))
            .await
    }

    /// List installations in exactly one scope/workspace namespace.  This is
    /// intentionally not a fuzzy same-name resolver: global and workspace
    /// records remain independently selectable.
    pub async fn list_agent_installations(
        &self,
        scope: AgentInstallationScope,
        canonical_workspace_id: Option<String>,
    ) -> Result<Vec<AgentInstallationRow>> {
        let key = scope_key(scope, canonical_workspace_id.as_deref())?;
        self.read(move |conn| installations_by_scope(conn, scope, &key))
            .await
    }

    /// Read the selected immutable profile reference, all visible installation
    /// rows, observations, and matching current bindings through one SQLite
    /// read snapshot.  Definition files and provider config are intentionally
    /// outside this DB boundary and must be revalidated by the daemon before
    /// publishing a composite response.
    pub async fn session_setup_snapshot(
        &self,
        session_id: Uuid,
        canonical_workspace_id: String,
    ) -> Result<SessionSetupDbSnapshot> {
        self.read(move |conn| {
            // A pooled SQLite connection does not by itself make consecutive
            // SELECTs one snapshot under WAL. Hold an explicit read
            // transaction so the selected profile, candidates, observations,
            // and bindings are one durable authority view.
            conn.execute_batch("BEGIN DEFERRED TRANSACTION")?;
            let projection = (|| {
                let selected_installation_id = snapshot_for_session(conn, session_id)?
                    .map(|snapshot| snapshot.installation_id);
                let mut installations =
                    installations_by_scope(conn, AgentInstallationScope::Global, "")?;
                installations.extend(installations_by_scope(
                    conn,
                    AgentInstallationScope::WorkspacePrivate,
                    &canonical_workspace_id,
                )?);
                installations.extend(installations_by_scope(
                    conn,
                    AgentInstallationScope::WorkspaceShared,
                    &canonical_workspace_id,
                )?);
                let mut rows = Vec::with_capacity(installations.len());
                for installation in installations {
                    let observation = observation_by_id(conn, installation.installation_id)?;
                    let bindings = current_bindings_for_digest(
                        conn,
                        installation.installation_id,
                        &installation.source_digest,
                    )?;
                    rows.push(SessionSetupInstallationSnapshotRow {
                        installation,
                        observation,
                        bindings,
                    });
                }
                if let Some(selected_installation_id) = selected_installation_id {
                    ensure!(
                        rows.iter().any(|row| {
                            row.installation.installation_id == selected_installation_id
                        }),
                        "session profile references an installation outside its authorized workspace snapshot"
                    );
                }
                Ok(SessionSetupDbSnapshot {
                    selected_installation_id,
                    installations: rows,
                })
            })();
            match projection {
                Ok(snapshot) => {
                    conn.execute_batch("COMMIT")?;
                    Ok(snapshot)
                }
                Err(error) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    Err(error)
                }
            }
        })
        .await
    }
}

impl AgentProfileSnapshotRow {
    /// Validate the stored digest and reconstruct the fully typed canonical
    /// profile.  Callers must use this instead of parsing the opaque bytes so
    /// a deleted definition can never cause a live-default re-resolution.
    pub fn reconstruct(&self) -> Result<RedactedAgentProfileSnapshot> {
        validate_payload(
            &self.canonical_payload,
            &self.canonical_payload_digest,
            "stored canonical agent profile snapshot",
        )?;
        decode_canonical_snapshot(
            &self.canonical_payload,
            "stored canonical agent profile snapshot",
        )
    }

    pub fn reconstruct_binding_revision_map(&self) -> Result<AgentBindingRevisionMap> {
        validate_payload(
            &self.binding_revision_map_payload,
            &self.binding_revision_map_digest,
            "stored binding revision map",
        )?;
        decode_canonical_binding_revision_map(
            &self.binding_revision_map_payload,
            "stored binding revision map",
        )
    }
}

/// Decode a caller-supplied canonical payload using the same fail-closed
/// invariants as persisted snapshots.  It is public so daemon protocol code
/// can reconstruct a receipt without importing SQLite internals.
pub fn decode_agent_profile_snapshot_payload(
    payload: &[u8],
) -> Result<RedactedAgentProfileSnapshot> {
    decode_canonical_snapshot(payload, "canonical agent profile snapshot")
}

/// Decode the accompanying canonical binding-revision receipt without
/// consulting mutable installation state.
pub fn decode_agent_binding_revision_map_payload(
    payload: &[u8],
) -> Result<AgentBindingRevisionMap> {
    decode_canonical_binding_revision_map(payload, "binding revision map")
}

/// Install a new source identity.  This function is transaction-safe when
/// called from an outer [`Db::transaction`] (all public mutation APIs do so).
pub fn install_agent_conn(
    conn: &Connection,
    input: &AgentInstallationInput,
) -> Result<InstallAgentOutcome> {
    validate_installation(input)?;
    let scope_key = scope_key(input.scope, input.canonical_workspace_id.as_deref())?;
    if let Some(existing) =
        installation_by_identity(conn, input.scope, &scope_key, &input.source_agent_id)?
    {
        if existing.installation_id == input.installation_id
            && existing.source_identity == input.source_identity
            && existing.source_digest == input.source_digest
            && existing.source_revision == input.source_revision
            && existing.deleted_at_unix_ms.is_none()
        {
            return Ok(InstallAgentOutcome::AlreadyInstalled(existing));
        }
        return Ok(InstallAgentOutcome::Conflict);
    }
    conn.execute(
        "INSERT INTO agent_installations(installation_id,scope,scope_workspace_key,canonical_workspace_id,source_agent_id,source_identity,source_revision,source_digest,fetched_at_unix_ms)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![input.installation_id.to_string(), input.scope.as_str(), scope_key, input.canonical_workspace_id, input.source_agent_id, input.source_identity, input.source_revision, input.source_digest, input.fetched_at_unix_ms],
    ).context("inserting agent installation")?;
    conn.execute(
        "INSERT INTO installation_observations(installation_id,observed_digest,observation_revision,review_state,observed_at_unix_ms) VALUES(?1,?2,1,'reviewed',?3)",
        params![input.installation_id.to_string(), input.source_digest, input.fetched_at_unix_ms],
    ).context("creating agent installation observation")?;
    Ok(InstallAgentOutcome::Installed(
        installation_by_id(conn, input.installation_id)?.expect("inserted installation"),
    ))
}

fn replacement_compensation_receipt_conn(
    conn: &Connection,
    installation_id: Uuid,
    replacement: &AgentInstallationInput,
    replacement_retired_at_unix_ms: i64,
) -> Result<AgentReplacementCompensationReceipt> {
    validate_installation(replacement)?;
    let installation = installation_by_id(conn, installation_id)?
        .context("replacement target installation is missing")?;
    ensure!(
        installation.scope == replacement.scope
            && installation.canonical_workspace_id == replacement.canonical_workspace_id
            && installation.source_agent_id == replacement.source_agent_id,
        "replacement target does not match installation namespace"
    );
    let observation = observation_by_id(conn, installation_id)?
        .context("replacement target installation is missing observation")?;
    let mut statement = conn
        .prepare(
            "SELECT binding_id FROM agent_model_bindings WHERE installation_id=?1 AND retired_at_unix_ms IS NULL ORDER BY slot_id ASC,is_default DESC,binding_id ASC",
        )
        .context("preparing replacement binding receipt")?;
    let prior_current_binding_ids = statement
        .query_map([installation_id.to_string()], |row| {
            parse_uuid(row.get::<_, String>(0)?)
        })
        .context("reading replacement binding receipt")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("decoding replacement binding receipt")?;
    Ok(AgentReplacementCompensationReceipt {
        replacement_operation_id: replacement.installation_id,
        installation_id,
        prior_source_identity: installation.source_identity,
        prior_source_revision: installation.source_revision,
        prior_source_digest: installation.source_digest,
        prior_fetched_at_unix_ms: installation.fetched_at_unix_ms,
        prior_installation_revision: installation.installation_revision,
        prior_deleted_at_unix_ms: installation.deleted_at_unix_ms,
        prior_observed_digest: observation.observed_digest,
        prior_observation_revision: observation.observation_revision,
        prior_reviewed: observation.reviewed,
        prior_observed_at_unix_ms: observation.observed_at_unix_ms,
        prior_current_binding_ids,
        replacement_source_identity: replacement.source_identity.clone(),
        replacement_source_revision: replacement.source_revision.clone(),
        replacement_source_digest: replacement.source_digest.clone(),
        replacement_fetched_at_unix_ms: replacement.fetched_at_unix_ms,
        replacement_retired_at_unix_ms,
    })
}

fn compensation_is_already_restored(
    installation: &AgentInstallationRow,
    observation: &AgentObservationRow,
    receipt: &AgentReplacementCompensationReceipt,
) -> bool {
    installation.installation_id == receipt.installation_id
        && installation.source_identity == receipt.prior_source_identity
        && installation.source_revision == receipt.prior_source_revision
        && installation.source_digest == receipt.prior_source_digest
        && installation.fetched_at_unix_ms == receipt.prior_fetched_at_unix_ms
        && installation.installation_revision == receipt.prior_installation_revision
        && installation.deleted_at_unix_ms == receipt.prior_deleted_at_unix_ms
        && observation.observed_digest == receipt.prior_observed_digest
        && observation.observation_revision == receipt.prior_observation_revision
        && observation.reviewed == receipt.prior_reviewed
        && observation.observed_at_unix_ms == receipt.prior_observed_at_unix_ms
}

fn compensation_matches_replacement(
    installation: &AgentInstallationRow,
    receipt: &AgentReplacementCompensationReceipt,
) -> bool {
    installation.installation_id == receipt.installation_id
        && installation.source_identity == receipt.replacement_source_identity
        && installation.source_revision == receipt.replacement_source_revision
        && installation.source_digest == receipt.replacement_source_digest
        && installation.fetched_at_unix_ms == receipt.replacement_fetched_at_unix_ms
        && installation.installation_revision == receipt.prior_installation_revision + 1
        && installation.deleted_at_unix_ms.is_none()
}

fn compensate_agent_replacement_conn(
    conn: &Connection,
    receipt: &AgentReplacementCompensationReceipt,
) -> Result<CompensateAgentReplacementOutcome> {
    let installation = installation_by_id(conn, receipt.installation_id)?
        .context("replacement compensation installation is missing")?;
    let observation = observation_by_id(conn, receipt.installation_id)?
        .context("replacement compensation observation is missing")?;
    if compensation_is_already_restored(&installation, &observation, receipt) {
        return Ok(CompensateAgentReplacementOutcome::AlreadyRestored);
    }
    ensure!(
        compensation_matches_replacement(&installation, receipt),
        "replacement compensation refused because installation changed after replacement"
    );
    conn.execute(
        "UPDATE agent_installations SET source_identity=?2,source_revision=?3,source_digest=?4,fetched_at_unix_ms=?5,installation_revision=?6,deleted_at_unix_ms=?7 WHERE installation_id=?1",
        params![receipt.installation_id.to_string(), receipt.prior_source_identity, receipt.prior_source_revision, receipt.prior_source_digest, receipt.prior_fetched_at_unix_ms, i64::try_from(receipt.prior_installation_revision)?, receipt.prior_deleted_at_unix_ms],
    )
    .context("restoring replaced agent installation provenance")?;
    conn.execute(
        "UPDATE installation_observations SET observed_digest=?2,observation_revision=?3,review_state=?4,observed_at_unix_ms=?5 WHERE installation_id=?1",
        params![receipt.installation_id.to_string(), receipt.prior_observed_digest, i64::try_from(receipt.prior_observation_revision)?, if receipt.prior_reviewed { "reviewed" } else { "rebind_required" }, receipt.prior_observed_at_unix_ms],
    )
    .context("restoring replaced agent observation")?;
    for binding_id in &receipt.prior_current_binding_ids {
        conn.execute(
            "UPDATE agent_model_bindings SET retired_at_unix_ms=NULL WHERE binding_id=?1 AND installation_id=?2 AND retired_at_unix_ms=?3",
            params![binding_id.to_string(), receipt.installation_id.to_string(), receipt.replacement_retired_at_unix_ms],
        )
        .context("restoring retired agent binding")?;
    }
    Ok(CompensateAgentReplacementOutcome::Restored)
}

pub fn replace_agent_conn(
    conn: &Connection,
    input: &AgentInstallationInput,
    now_unix_ms: i64,
) -> Result<InstallAgentOutcome> {
    validate_installation(input)?;
    let scope_key = scope_key(input.scope, input.canonical_workspace_id.as_deref())?;
    let Some(existing) =
        installation_by_identity(conn, input.scope, &scope_key, &input.source_agent_id)?
    else {
        return install_agent_conn(conn, input);
    };
    if existing.source_identity == input.source_identity
        && existing.source_revision == input.source_revision
        && existing.source_digest == input.source_digest
        && existing.deleted_at_unix_ms.is_none()
    {
        return Ok(InstallAgentOutcome::AlreadyInstalled(existing));
    }
    conn.execute(
        "UPDATE agent_model_bindings SET retired_at_unix_ms=?2 WHERE installation_id=?1 AND retired_at_unix_ms IS NULL AND is_default=0",
        params![existing.installation_id.to_string(), now_unix_ms],
    )
    .context("retiring binding alternates before agent replacement")?;
    conn.execute(
        "UPDATE agent_model_bindings SET retired_at_unix_ms=?2 WHERE installation_id=?1 AND retired_at_unix_ms IS NULL AND is_default=1",
        params![existing.installation_id.to_string(), now_unix_ms],
    )
    .context("retiring binding defaults before agent replacement")?;
    conn.execute(
        "UPDATE agent_installations SET source_identity=?2,source_revision=?3,source_digest=?4,fetched_at_unix_ms=?5,installation_revision=installation_revision+1,deleted_at_unix_ms=NULL WHERE installation_id=?1",
        params![existing.installation_id.to_string(), input.source_identity, input.source_revision, input.source_digest, input.fetched_at_unix_ms],
    )
    .context("replacing agent installation provenance")?;
    conn.execute(
        "UPDATE installation_observations SET observed_digest=?2,observation_revision=observation_revision+1,review_state='reviewed',observed_at_unix_ms=?3 WHERE installation_id=?1",
        params![existing.installation_id.to_string(), input.source_digest, now_unix_ms],
    )
    .context("refreshing replaced installation observation")?;
    Ok(InstallAgentOutcome::Installed(
        installation_by_id(conn, existing.installation_id)?.expect("updated installation"),
    ))
}

/// Targeted form of [`replace_agent_conn`]. This is deliberately separate
/// from the source-identity resolver above: an update has already authorized
/// a concrete installation id, and changing a fetched AgentDef's id must not
/// select another record in the same namespace.
pub fn replace_agent_at_conn(
    conn: &Connection,
    installation_id: Uuid,
    input: &AgentInstallationInput,
    now_unix_ms: i64,
) -> Result<InstallAgentOutcome> {
    validate_installation(input)?;
    let Some(existing) = installation_by_id(conn, installation_id)? else {
        return Ok(InstallAgentOutcome::Conflict);
    };
    ensure!(
        existing.scope == input.scope
            && existing.canonical_workspace_id == input.canonical_workspace_id
            && existing.source_agent_id == input.source_agent_id,
        "targeted replacement identity does not match installation"
    );
    if existing.source_identity == input.source_identity
        && existing.source_revision == input.source_revision
        && existing.source_digest == input.source_digest
        && existing.deleted_at_unix_ms.is_none()
    {
        return Ok(InstallAgentOutcome::AlreadyInstalled(existing));
    }
    conn.execute(
        "UPDATE agent_model_bindings SET retired_at_unix_ms=?2 WHERE installation_id=?1 AND retired_at_unix_ms IS NULL AND is_default=0",
        params![existing.installation_id.to_string(), now_unix_ms],
    )
    .context("retiring binding alternates before targeted agent replacement")?;
    conn.execute(
        "UPDATE agent_model_bindings SET retired_at_unix_ms=?2 WHERE installation_id=?1 AND retired_at_unix_ms IS NULL AND is_default=1",
        params![existing.installation_id.to_string(), now_unix_ms],
    )
    .context("retiring binding defaults before targeted agent replacement")?;
    conn.execute(
        "UPDATE agent_installations SET source_identity=?2,source_revision=?3,source_digest=?4,fetched_at_unix_ms=?5,installation_revision=installation_revision+1,deleted_at_unix_ms=NULL WHERE installation_id=?1",
        params![existing.installation_id.to_string(), input.source_identity, input.source_revision, input.source_digest, input.fetched_at_unix_ms],
    )
    .context("replacing targeted agent installation provenance")?;
    conn.execute(
        "UPDATE installation_observations SET observed_digest=?2,observation_revision=observation_revision+1,review_state='reviewed',observed_at_unix_ms=?3 WHERE installation_id=?1",
        params![existing.installation_id.to_string(), input.source_digest, now_unix_ms],
    )
    .context("refreshing targeted installation observation")?;
    Ok(InstallAgentOutcome::Installed(
        installation_by_id(conn, existing.installation_id)?.expect("updated installation"),
    ))
}

fn materialize_package_child_conn(
    conn: &Connection,
    input: &MaterializePackageChildInput,
) -> Result<AgentInstallationRow> {
    validate_materialize_package_child_input(input)?;
    validate_package_child_parent_generation(conn, input)?;

    materialize_validated_package_child_conn(conn, input)
}

fn materialize_package_children_conn(
    conn: &Connection,
    inputs: &[MaterializePackageChildInput],
) -> Result<Vec<AgentInstallationRow>> {
    let Some(first) = inputs.first() else {
        return Ok(Vec::new());
    };
    let mut child_ids = HashSet::new();
    let mut child_sources = HashSet::new();
    for input in inputs {
        ensure!(
            input.parent_installation_id == first.parent_installation_id
                && input.expected_parent_installation_revision
                    == first.expected_parent_installation_revision
                && input.expected_parent_observation_revision
                    == first.expected_parent_observation_revision
                && input.expected_parent_definition_digest
                    == first.expected_parent_definition_digest
                && input.child_source_identity_guard == first.child_source_identity_guard
                && input.now_unix_ms == first.now_unix_ms,
            "package-child batch mixes parent generations"
        );
        validate_materialize_package_child_input(input)?;
        ensure!(
            child_ids.insert(input.child.installation_id)
                && child_sources.insert(input.child.source_agent_id.as_str()),
            "package-child batch contains a duplicate child identity"
        );
    }
    validate_package_child_parent_generation(conn, first)?;

    inputs
        .iter()
        .map(|input| materialize_validated_package_child_conn(conn, input))
        .collect()
}

fn validate_materialize_package_child_input(input: &MaterializePackageChildInput) -> Result<()> {
    validate_digest(
        &input.expected_parent_definition_digest,
        "expected parent package definition digest",
    )?;
    validate_installation(&input.child)?;
    ensure!(
        input.child.installation_id != input.parent_installation_id,
        "package child installation must differ from its parent"
    );
    ensure!(
        !input.child_source_identity_guard.is_empty()
            && input
                .child
                .source_identity
                .contains(&input.child_source_identity_guard),
        "package child source identity lacks its authenticated parent guard"
    );
    let mut slots = HashSet::new();
    for slot in &input.slot_bindings {
        ensure!(
            !slot.idempotency_key.is_empty() && !slot.request_fingerprint.is_empty(),
            "package child binding identity is required"
        );
        let slot_id = slot
            .bindings
            .first()
            .map(|binding| binding.slot_id.as_str())
            .context("package child binding set is empty")?;
        ensure!(
            slots.insert(slot_id.to_string()),
            "package child binding request duplicates slot `{slot_id}`"
        );
        let mut routes = HashSet::new();
        ensure!(
            slot.bindings.iter().all(|binding| {
                binding.slot_id == slot_id
                    && validate_binding(binding).is_ok()
                    && routes.insert((
                        binding.provider_profile_handle.as_str(),
                        binding.model_id.as_str(),
                    ))
            }),
            "package child binding set contains mixed, duplicate, or invalid routes"
        );
        ensure!(
            slot.bindings
                .iter()
                .filter(|binding| binding.is_default)
                .count()
                == 1,
            "package child binding set must retain exactly one default route"
        );
    }
    ensure!(
        slots.contains("primary"),
        "package child materialization requires a primary slot"
    );
    Ok(())
}

fn validate_package_child_parent_generation(
    conn: &Connection,
    input: &MaterializePackageChildInput,
) -> Result<()> {
    let parent = installation_by_id(conn, input.parent_installation_id)?
        .context("package child parent installation is missing")?;
    let parent_observation = observation_by_id(conn, input.parent_installation_id)?
        .context("package child parent observation is missing")?;
    ensure!(
        parent.deleted_at_unix_ms.is_none()
            && parent.installation_revision == input.expected_parent_installation_revision
            && parent.source_digest == input.expected_parent_definition_digest
            && parent_observation.reviewed
            && parent_observation.observation_revision
                == input.expected_parent_observation_revision
            && parent_observation.observed_digest == input.expected_parent_definition_digest,
        "package child parent generation is stale or unreviewed"
    );
    Ok(())
}

fn materialize_validated_package_child_conn(
    conn: &Connection,
    input: &MaterializePackageChildInput,
) -> Result<AgentInstallationRow> {
    let row = match install_agent_conn(conn, &input.child)? {
        InstallAgentOutcome::Installed(row) | InstallAgentOutcome::AlreadyInstalled(row) => row,
        InstallAgentOutcome::Conflict => {
            let scope = scope_key(
                input.child.scope,
                input.child.canonical_workspace_id.as_deref(),
            )?;
            let existing = installation_by_identity(
                conn,
                input.child.scope,
                &scope,
                &input.child.source_agent_id,
            )?
            .context("package child identity collided without an installation")?;
            ensure!(
                existing.installation_id == input.child.installation_id
                    && existing
                        .source_identity
                        .contains(&input.child_source_identity_guard),
                "package child identity collides with a different installation"
            );
            match replace_agent_at_conn(
                conn,
                existing.installation_id,
                &input.child,
                input.now_unix_ms,
            )? {
                InstallAgentOutcome::Installed(row)
                | InstallAgentOutcome::AlreadyInstalled(row) => row,
                InstallAgentOutcome::Conflict => bail!("package child replacement conflicted"),
            }
        }
    };

    let mut observation = observation_by_id(conn, row.installation_id)?
        .context("materialized package child is missing its observation")?;
    if !observation.reviewed || observation.observed_digest != input.child.source_digest {
        conn.execute(
            "UPDATE installation_observations SET observed_digest=?2,observation_revision=observation_revision+1,review_state='reviewed',observed_at_unix_ms=?3 WHERE installation_id=?1",
            params![
                row.installation_id.to_string(),
                input.child.source_digest,
                input.now_unix_ms
            ],
        )
        .context("refreshing parent-authorized package child observation")?;
        observation = observation_by_id(conn, row.installation_id)?
            .context("materialized package child observation disappeared")?;
    }

    let mut slots = std::collections::BTreeSet::new();
    for slot in &input.slot_bindings {
        let slot_id = slot
            .bindings
            .first()
            .map(|binding| binding.slot_id.as_str())
            .context("package child binding set is empty")?;
        ensure!(
            slot.bindings
                .iter()
                .all(|binding| binding.slot_id == slot_id),
            "package child binding set mixes slots"
        );
        ensure!(
            slots.insert(slot_id.to_string()),
            "package child binding request duplicates slot `{slot_id}`"
        );
        let expected_binding_revision = current_binding(
            conn,
            row.installation_id,
            &input.child.source_digest,
            slot_id,
        )?
        .map(|binding| binding.binding_revision);
        let outcome = bind_agent_slot_set_conn(
            conn,
            &AgentBindSlotSetInput {
                installation_id: row.installation_id,
                expected_observation_revision: observation.observation_revision,
                expected_definition_digest: input.child.source_digest.clone(),
                expected_binding_revision,
                idempotency_key: slot.idempotency_key.clone(),
                request_fingerprint: slot.request_fingerprint.clone(),
                bindings: slot.bindings.clone(),
                now_unix_ms: input.now_unix_ms,
            },
        )?;
        ensure!(
            matches!(
                outcome,
                BindAgentOutcome::Bound(_) | BindAgentOutcome::AlreadyBound(_)
            ),
            "package child slot `{slot_id}` binding was refused: {outcome:?}"
        );
    }
    debug_assert!(slots.contains("primary"));
    Ok(row)
}

pub fn observe_agent_definition_conn(
    conn: &Connection,
    installation_id: Uuid,
    observed_digest: &str,
    now_unix_ms: i64,
) -> Result<ObserveAgentOutcome> {
    validate_digest(observed_digest, "observed definition digest")?;
    let Some(installation) = installation_by_id(conn, installation_id)? else {
        return Ok(ObserveAgentOutcome::NotFound);
    };
    if installation.deleted_at_unix_ms.is_some() {
        return Ok(ObserveAgentOutcome::Deleted);
    }
    let observation =
        observation_by_id(conn, installation_id)?.context("installation missing observation")?;
    if observation.observed_digest == observed_digest {
        return Ok(if observation.reviewed {
            ObserveAgentOutcome::Current(observation)
        } else {
            ObserveAgentOutcome::RebindRequired(observation)
        });
    }
    conn.execute(
        "UPDATE installation_observations SET observed_digest=?2,observation_revision=observation_revision+1,review_state='rebind_required',observed_at_unix_ms=?3 WHERE installation_id=?1",
        params![installation_id.to_string(), observed_digest, now_unix_ms],
    ).context("recording changed agent definition observation")?;
    Ok(ObserveAgentOutcome::RebindRequired(
        observation_by_id(conn, installation_id)?.expect("updated observation"),
    ))
}

// See `Db::bind_agent_model`: this conn helper mirrors the public atomic CAS
// boundary so both callers preserve the same independent durable predicates.
#[allow(clippy::too_many_arguments)]
pub fn bind_agent_model_conn(
    conn: &Connection,
    installation_id: Uuid,
    definition_digest: &str,
    expected_binding_revision: Option<u64>,
    idempotency_key: &str,
    request_fingerprint: &str,
    binding: &AgentBindingInput,
    now_unix_ms: i64,
) -> Result<BindAgentOutcome> {
    if !binding.hard_capability_verified {
        return Ok(BindAgentOutcome::Incompatible);
    }
    // This legacy single-choice mutation can only replace a slot with its
    // default. Alternate models are installed atomically through rebind so a
    // slot is never left live without a default.
    if !binding.is_default {
        return Ok(BindAgentOutcome::Incompatible);
    }
    validate_binding(binding)?;
    ensure!(
        !idempotency_key.is_empty(),
        "binding idempotency key is required"
    );
    ensure!(
        !request_fingerprint.is_empty(),
        "binding request fingerprint is required"
    );
    if let Some((stored_fingerprint, receipt)) = binding_receipt_by_key(
        conn,
        installation_id,
        definition_digest,
        &binding.slot_id,
        idempotency_key,
    )? {
        return Ok(if stored_fingerprint == request_fingerprint {
            BindAgentOutcome::AlreadyBound(receipt)
        } else {
            BindAgentOutcome::Conflict
        });
    }
    let Some(installation) = installation_by_id(conn, installation_id)? else {
        return Ok(BindAgentOutcome::NotFound);
    };
    if installation.deleted_at_unix_ms.is_some() {
        return Ok(BindAgentOutcome::Deleted);
    }
    let observation =
        observation_by_id(conn, installation_id)?.context("installation missing observation")?;
    if !observation.reviewed || observation.observed_digest != definition_digest {
        return Ok(BindAgentOutcome::RebindRequired);
    }
    let current = current_binding(conn, installation_id, definition_digest, &binding.slot_id)?;
    if let Some(current) = &current {
        if current.provenance_digest == binding.provenance_digest
            && current.provider_profile_handle == binding.provider_profile_handle
            && current.model_id == binding.model_id
        {
            if expected_binding_revision != Some(current.binding_revision) {
                return Ok(BindAgentOutcome::Conflict);
            }
            conn.execute(
                "INSERT INTO agent_binding_receipts(installation_id,definition_digest,slot_id,idempotency_key,request_fingerprint,binding_id,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![installation_id.to_string(), definition_digest, binding.slot_id, idempotency_key, request_fingerprint, current.binding_id.to_string(), now_unix_ms],
            )
            .context("recording existing agent model binding receipt")?;
            return Ok(BindAgentOutcome::AlreadyBound(current.clone()));
        }
        if expected_binding_revision != Some(current.binding_revision) {
            return Ok(BindAgentOutcome::Conflict);
        }
    } else if expected_binding_revision.is_some() {
        return Ok(BindAgentOutcome::Conflict);
    }
    let next_revision = next_binding_revision(conn, installation_id, &binding.slot_id)?;
    conn.execute(
        "UPDATE agent_model_bindings SET retired_at_unix_ms=?1 WHERE installation_id=?2 AND definition_digest=?3 AND slot_id=?4 AND retired_at_unix_ms IS NULL AND is_default=0",
        params![now_unix_ms, installation_id.to_string(), definition_digest, binding.slot_id],
    )
    .context("retiring replaced agent binding alternates")?;
    let id = if let Some(current) = current {
        conn.execute(
            "UPDATE agent_model_bindings SET provider_profile_handle=?1,model_id=?2,provenance_payload=?3,provenance_digest=?4,hard_capability_verified=1,binding_revision=?5,created_at_unix_ms=?6 WHERE binding_id=?7 AND retired_at_unix_ms IS NULL AND is_default=1",
            params![binding.provider_profile_handle,binding.model_id,binding.provenance_payload,binding.provenance_digest,i64::try_from(next_revision)?,now_unix_ms,current.binding_id.to_string()],
        )
        .context("atomically replacing the live agent binding default")?;
        current.binding_id
    } else {
        let id = Uuid::now_v7();
        conn.execute(
            "INSERT INTO agent_model_bindings(binding_id,installation_id,definition_digest,slot_id,provider_profile_handle,model_id,provenance_payload,provenance_digest,hard_capability_verified,binding_revision,is_default,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,?9,1,?10)",
            params![id.to_string(),installation_id.to_string(),definition_digest,binding.slot_id,binding.provider_profile_handle,binding.model_id,binding.provenance_payload,binding.provenance_digest,i64::try_from(next_revision)?,now_unix_ms],
        ).context("inserting initial agent model binding default")?;
        id
    };
    conn.execute(
        "INSERT INTO agent_binding_receipts(installation_id,definition_digest,slot_id,idempotency_key,request_fingerprint,binding_id,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![installation_id.to_string(), definition_digest, binding.slot_id, idempotency_key, request_fingerprint, id.to_string(), now_unix_ms],
    )
    .context("creating agent model binding receipt")?;
    Ok(BindAgentOutcome::Bound(
        binding_by_id(conn, id)?.expect("inserted binding"),
    ))
}

pub fn bind_agent_slot_set_conn(
    conn: &Connection,
    input: &AgentBindSlotSetInput,
) -> Result<BindAgentOutcome> {
    validate_digest(
        &input.expected_definition_digest,
        "expected definition digest",
    )?;
    ensure!(
        !input.idempotency_key.is_empty(),
        "binding idempotency key is required"
    );
    ensure!(
        !input.request_fingerprint.is_empty(),
        "binding request fingerprint is required"
    );
    if input
        .bindings
        .iter()
        .any(|binding| !binding.hard_capability_verified)
    {
        return Ok(BindAgentOutcome::Incompatible);
    }
    let slot_id = input
        .bindings
        .first()
        .map(|binding| binding.slot_id.clone())
        .context("slot binding set is required")?;
    ensure!(
        input
            .bindings
            .iter()
            .all(|binding| binding.slot_id == slot_id),
        "slot binding set must target exactly one slot"
    );
    let mut keys = HashSet::new();
    let default_count = input
        .bindings
        .iter()
        .filter(|binding| binding.is_default)
        .count();
    ensure!(
        input.bindings.iter().all(|binding| {
            validate_binding(binding).is_ok()
                && keys.insert((
                    binding.provider_profile_handle.as_str(),
                    binding.model_id.as_str(),
                ))
        }),
        "slot binding set contains duplicate or invalid routes"
    );
    ensure!(
        default_count == 1,
        "slot binding set must retain exactly one default route"
    );
    if let Some((stored_fingerprint, receipt)) = binding_receipt_by_key(
        conn,
        input.installation_id,
        &input.expected_definition_digest,
        &slot_id,
        &input.idempotency_key,
    )? {
        return Ok(if stored_fingerprint == input.request_fingerprint {
            BindAgentOutcome::AlreadyBound(receipt)
        } else {
            BindAgentOutcome::Conflict
        });
    }
    let Some(installation) = installation_by_id(conn, input.installation_id)? else {
        return Ok(BindAgentOutcome::NotFound);
    };
    if installation.deleted_at_unix_ms.is_some() {
        return Ok(BindAgentOutcome::Deleted);
    }
    let observation = observation_by_id(conn, input.installation_id)?
        .context("installation missing observation")?;
    if !observation.reviewed || observation.observed_digest != input.expected_definition_digest {
        return Ok(BindAgentOutcome::RebindRequired);
    }
    if observation.observation_revision != input.expected_observation_revision {
        return Ok(BindAgentOutcome::Conflict);
    }
    let current_slot_bindings = current_bindings_for_digest(
        conn,
        input.installation_id,
        &input.expected_definition_digest,
    )?
    .into_iter()
    .filter(|binding| binding.slot_id == slot_id)
    .collect::<Vec<_>>();
    let current_revision = current_slot_binding_revision(&current_slot_bindings)?;
    if current_revision != input.expected_binding_revision {
        return Ok(BindAgentOutcome::Conflict);
    }
    if slot_binding_set_matches_current(&input.bindings, &current_slot_bindings) {
        let current_default = current_slot_bindings
            .iter()
            .find(|binding| binding.is_default)
            .context("current slot binding set lost its default")?;
        conn.execute(
            "INSERT INTO agent_binding_receipts(installation_id,definition_digest,slot_id,idempotency_key,request_fingerprint,binding_id,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                input.installation_id.to_string(),
                input.expected_definition_digest,
                slot_id,
                input.idempotency_key,
                input.request_fingerprint,
                current_default.binding_id.to_string(),
                input.now_unix_ms
            ],
        )
        .context("recording existing slot binding set receipt")?;
        return Ok(BindAgentOutcome::AlreadyBound(current_default.clone()));
    }

    conn.execute(
        "UPDATE agent_model_bindings SET retired_at_unix_ms=?1 WHERE installation_id=?2 AND definition_digest=?3 AND slot_id=?4 AND retired_at_unix_ms IS NULL AND is_default=0",
        params![
            input.now_unix_ms,
            input.installation_id.to_string(),
            input.expected_definition_digest,
            slot_id
        ],
    )
    .context("retiring prior slot binding alternates")?;
    conn.execute(
        "UPDATE agent_model_bindings SET retired_at_unix_ms=?1 WHERE installation_id=?2 AND definition_digest=?3 AND slot_id=?4 AND retired_at_unix_ms IS NULL AND is_default=1",
        params![
            input.now_unix_ms,
            input.installation_id.to_string(),
            input.expected_definition_digest,
            slot_id
        ],
    )
    .context("retiring prior slot binding default")?;

    let next_revision = next_binding_revision(conn, input.installation_id, &slot_id)?;
    let mut default_binding_id = None;
    for binding in input
        .bindings
        .iter()
        .filter(|binding| binding.is_default)
        .chain(input.bindings.iter().filter(|binding| !binding.is_default))
    {
        let id = Uuid::now_v7();
        conn.execute(
            "INSERT INTO agent_model_bindings(binding_id,installation_id,definition_digest,slot_id,provider_profile_handle,model_id,provenance_payload,provenance_digest,hard_capability_verified,binding_revision,is_default,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,?9,?10,?11)",
            params![
                id.to_string(),
                input.installation_id.to_string(),
                input.expected_definition_digest,
                binding.slot_id,
                binding.provider_profile_handle,
                binding.model_id,
                binding.provenance_payload,
                binding.provenance_digest,
                i64::try_from(next_revision)?,
                i64::from(binding.is_default),
                input.now_unix_ms
            ],
        )
        .context("inserting rebound slot binding route")?;
        if binding.is_default {
            default_binding_id = Some(id);
        }
    }
    let default_binding_id =
        default_binding_id.context("slot binding set inserted no default route")?;
    conn.execute(
        "INSERT INTO agent_binding_receipts(installation_id,definition_digest,slot_id,idempotency_key,request_fingerprint,binding_id,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            input.installation_id.to_string(),
            input.expected_definition_digest,
            slot_id,
            input.idempotency_key,
            input.request_fingerprint,
            default_binding_id.to_string(),
            input.now_unix_ms
        ],
    )
    .context("recording slot binding set receipt")?;
    Ok(BindAgentOutcome::Bound(
        binding_by_id(conn, default_binding_id)?.expect("inserted default slot binding"),
    ))
}

pub fn rebind_agent_conn(
    conn: &Connection,
    input: &AgentRebindInput,
) -> Result<RebindAgentOutcome> {
    validate_digest(&input.expected_observed_digest, "expected observed digest")?;
    validate_digest(&input.new_observed_digest, "new observed digest")?;
    if input
        .bindings
        .iter()
        .any(|binding| !binding.hard_capability_verified)
    {
        return Ok(RebindAgentOutcome::Incompatible);
    }
    let Some(installation) = installation_by_id(conn, input.installation_id)? else {
        return Ok(RebindAgentOutcome::NotFound);
    };
    if installation.deleted_at_unix_ms.is_some() {
        return Ok(RebindAgentOutcome::Deleted);
    }
    let observation = observation_by_id(conn, input.installation_id)?
        .context("installation missing observation")?;
    if observation.observation_revision != input.expected_observation_revision
        || observation.observed_digest != input.expected_observed_digest
    {
        return Ok(RebindAgentOutcome::Conflict);
    }
    for binding in &input.bindings {
        validate_binding(binding)?;
    }
    let mut keys: HashSet<(String, String, String)> = HashSet::new();
    ensure!(
        input.bindings.iter().all(|binding| keys.insert((
            binding.slot_id.clone(),
            binding.provider_profile_handle.clone(),
            binding.model_id.clone(),
        ))),
        "rebind request contains duplicate (slot, provider, model) ids"
    );
    ensure!(
        keys.iter().any(|(slot, _, _)| slot == "primary"),
        "rebind request must provide the primary model slot"
    );
    let mut defaults_by_slot: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    for binding in &input.bindings {
        let count = defaults_by_slot.entry(&binding.slot_id).or_default();
        if binding.is_default {
            *count += 1;
        }
    }
    ensure!(
        defaults_by_slot.values().all(|count| *count == 1),
        "rebind request must provide exactly one default model per slot"
    );
    conn.execute(
        "UPDATE agent_model_bindings SET retired_at_unix_ms=?1 WHERE installation_id=?2 AND retired_at_unix_ms IS NULL AND is_default=0",
        params![input.now_unix_ms, input.installation_id.to_string()],
    )
    .context("retiring prior agent binding alternates")?;
    conn.execute(
        "UPDATE agent_model_bindings SET retired_at_unix_ms=?1 WHERE installation_id=?2 AND retired_at_unix_ms IS NULL AND is_default=1",
        params![input.now_unix_ms, input.installation_id.to_string()],
    )
    .context("retiring prior agent binding defaults")?;
    let mut slot_revisions: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    for binding in input
        .bindings
        .iter()
        .filter(|binding| binding.is_default)
        .chain(input.bindings.iter().filter(|binding| !binding.is_default))
    {
        if !slot_revisions.contains_key(&binding.slot_id) {
            slot_revisions.insert(
                binding.slot_id.clone(),
                next_binding_revision(conn, input.installation_id, &binding.slot_id)?,
            );
        }
    }
    for binding in input
        .bindings
        .iter()
        .filter(|binding| binding.is_default)
        .chain(input.bindings.iter().filter(|binding| !binding.is_default))
    {
        let id = Uuid::now_v7();
        let revision = *slot_revisions
            .get(&binding.slot_id)
            .expect("slot revision assigned");
        conn.execute("INSERT INTO agent_model_bindings(binding_id,installation_id,definition_digest,slot_id,provider_profile_handle,model_id,provenance_payload,provenance_digest,hard_capability_verified,binding_revision,is_default,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,?9,?10,?11)",params![id.to_string(),input.installation_id.to_string(),input.new_observed_digest,binding.slot_id,binding.provider_profile_handle,binding.model_id,binding.provenance_payload,binding.provenance_digest,i64::try_from(revision)?,i64::from(binding.is_default),input.now_unix_ms]).context("inserting rebound agent model slot")?;
    }
    conn.execute("UPDATE installation_observations SET observed_digest=?2,observation_revision=observation_revision+1,review_state='reviewed',observed_at_unix_ms=?3 WHERE installation_id=?1",params![input.installation_id.to_string(),input.new_observed_digest,input.now_unix_ms]).context("promoting rebound agent observation")?;
    Ok(RebindAgentOutcome::Rebound(
        observation_by_id(conn, input.installation_id)?.expect("rebound observation"),
    ))
}

pub fn prepare_agent_session_conn(
    conn: &Connection,
    input: &PrepareAgentSessionInput,
) -> Result<PrepareAgentSessionOutcome> {
    validate_prepare(input)?;
    if let Some((fingerprint, state, snapshot)) =
        preparation_by_key(conn, input.session_id, &input.idempotency_key)?
    {
        if fingerprint != input.request_fingerprint {
            return Ok(PrepareAgentSessionOutcome::Conflict);
        }
        return Ok(match state.as_str() {
            "prepared" => PrepareAgentSessionOutcome::AlreadyPrepared(snapshot),
            "running" => PrepareAgentSessionOutcome::AlreadyStarted(snapshot),
            "terminal" => PrepareAgentSessionOutcome::Terminal(snapshot),
            _ => bail!("invalid stored agent preparation lifecycle state `{state}`"),
        });
    }
    let preparation_target = match session_preparation_eligibility(conn, input.session_id)? {
        SessionPreparationEligibility::Terminal => return Ok(PrepareAgentSessionOutcome::Conflict),
        SessionPreparationEligibility::Deleted => return Ok(PrepareAgentSessionOutcome::Deleted),
        // The profile receipt and the normal session row are one durable
        // transaction.  A retry can therefore never observe a prepared
        // snapshot whose session has not been claimed, and callers never
        // have to split session creation from the compare-and-insert CAS.
        SessionPreparationEligibility::Missing => {
            if input.existing_session_claim_token.is_some() {
                return Ok(PrepareAgentSessionOutcome::Conflict);
            }
            PreparationTarget::CreateMissing
        }
        // An active session becomes claimable only through the separate,
        // durable marker registered by its owner.  This is deliberately not
        // inferred from `lifecycle = active`, which describes every normal
        // live session including ones that are already running work.
        SessionPreparationEligibility::OrdinaryActive => {
            let Some(token) = input.existing_session_claim_token else {
                return Ok(PrepareAgentSessionOutcome::Conflict);
            };
            match preparation_claim_state(conn, input.session_id, token)? {
                Some(PreparationClaimState::Eligible) => PreparationTarget::ClaimExisting(token),
                Some(
                    PreparationClaimState::Claimed
                    | PreparationClaimState::Running
                    | PreparationClaimState::Terminal,
                )
                | None => {
                    return Ok(PrepareAgentSessionOutcome::Conflict);
                }
            }
        }
    };
    // A second key must never create a different snapshot for the same session.
    if snapshot_for_session(conn, input.session_id)?.is_some() {
        return Ok(PrepareAgentSessionOutcome::Conflict);
    }
    let Some(installation) = installation_by_id(conn, input.installation_id)? else {
        return Ok(PrepareAgentSessionOutcome::Conflict);
    };
    if installation.deleted_at_unix_ms.is_some() {
        return Ok(PrepareAgentSessionOutcome::Deleted);
    }
    if installation.installation_revision != input.expected_installation_revision {
        return Ok(PrepareAgentSessionOutcome::Conflict);
    }
    let observation = observation_by_id(conn, input.installation_id)?
        .context("installation missing observation")?;
    if !observation.reviewed || observation.observed_digest != input.expected_definition_digest {
        return Ok(PrepareAgentSessionOutcome::RebindRequired);
    }
    if observation.observation_revision != input.expected_observation_revision {
        return Ok(PrepareAgentSessionOutcome::Conflict);
    }
    let revision_map = decode_canonical_binding_revision_map(
        &input.binding_revision_map_payload,
        "binding revision map",
    )?;
    let snapshot = decode_canonical_snapshot(
        &input.canonical_snapshot_payload,
        "canonical agent profile snapshot",
    )?;
    if !binding_map_matches_expectations(&revision_map, &input.expected_bindings)? {
        return Ok(PrepareAgentSessionOutcome::Conflict);
    }
    let actual_bindings = current_bindings_for_digest(
        conn,
        input.installation_id,
        &input.expected_definition_digest,
    )?;
    if actual_bindings.is_empty() {
        return Ok(PrepareAgentSessionOutcome::RebindRequired);
    }
    if !binding_map_matches_current(&revision_map, &actual_bindings)
        || !snapshot_evidence_matches_current(&snapshot, &actual_bindings)
    {
        return Ok(PrepareAgentSessionOutcome::Conflict);
    }
    let authorized_child_ids = snapshot
        .effective_delegation
        .iter()
        .flat_map(|delegation| &delegation.allowed_children)
        .filter_map(|child| match child {
            RedactedAllowedChild::LocalInstallation {
                installation_id, ..
            } => Some(*installation_id),
            RedactedAllowedChild::SelfInvocation { .. } => None,
            RedactedAllowedChild::PortableRef { .. } => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let expected_child_ids = input
        .expected_children
        .iter()
        .map(|child| child.installation_id)
        .collect::<std::collections::BTreeSet<_>>();
    if authorized_child_ids != expected_child_ids {
        return Ok(PrepareAgentSessionOutcome::Conflict);
    }
    for child in &input.expected_children {
        if !snapshot.child_bindings.iter().any(|evidence| {
            evidence.installation_id == child.installation_id
                && evidence.installation_revision == child.expected_installation_revision
                && evidence.observation_revision == child.expected_observation_revision
                && evidence.definition_digest == child.expected_definition_digest
        }) || snapshot.child_bindings.iter().any(|evidence| {
            evidence.installation_id == child.installation_id
                && (evidence.installation_revision != child.expected_installation_revision
                    || evidence.observation_revision != child.expected_observation_revision
                    || evidence.definition_digest != child.expected_definition_digest)
        }) {
            return Ok(PrepareAgentSessionOutcome::Conflict);
        }
        let Some(installation) = installation_by_id(conn, child.installation_id)? else {
            return Ok(PrepareAgentSessionOutcome::Conflict);
        };
        if installation.deleted_at_unix_ms.is_some()
            || installation.installation_revision != child.expected_installation_revision
            || installation.source_digest != child.expected_definition_digest
        {
            return Ok(PrepareAgentSessionOutcome::Conflict);
        }
        let Some(observation) = observation_by_id(conn, child.installation_id)? else {
            return Ok(PrepareAgentSessionOutcome::Conflict);
        };
        if !observation.reviewed
            || observation.observed_digest != child.expected_definition_digest
            || observation.observation_revision != child.expected_observation_revision
        {
            return Ok(PrepareAgentSessionOutcome::Conflict);
        }
        let current = current_bindings_for_digest(
            conn,
            child.installation_id,
            &child.expected_definition_digest,
        )?;
        if !binding_expectations_match_current(&child.expected_bindings, &current)
            || !child_snapshot_evidence_matches_current(&snapshot, child.installation_id, &current)
        {
            return Ok(PrepareAgentSessionOutcome::Conflict);
        }
    }
    let created_session = match preparation_target {
        PreparationTarget::CreateMissing => {
            create_agent_session_conn(conn, input.session_id, &input.session_create, &snapshot)?;
            true
        }
        PreparationTarget::ClaimExisting(token) => {
            let claimed = conn
                .execute(
                    "UPDATE agent_session_preparation_claims SET claim_state='claimed',claimed_at_unix_ms=?3 WHERE session_id=?1 AND claim_token=?2 AND claim_state='eligible'",
                    params![input.session_id.to_string(), token.to_string(), input.now_unix_ms],
                )
                .context("claiming registered existing agent session preparation")?;
            if claimed != 1 {
                return Ok(PrepareAgentSessionOutcome::Conflict);
            }
            set_prepared_session_primary_model_conn(conn, input.session_id, &snapshot)?;
            false
        }
    };
    let snapshot_id = Uuid::now_v7();
    conn.execute("INSERT INTO agent_profile_snapshots(snapshot_id,session_id,installation_id,schema_version,canonical_payload,canonical_payload_digest,definition_digest,binding_revision_map_payload,binding_revision_map_digest,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![snapshot_id.to_string(),input.session_id.to_string(),input.installation_id.to_string(),i64::try_from(input.snapshot_schema_version)?,input.canonical_snapshot_payload,input.canonical_snapshot_digest,input.expected_definition_digest,input.binding_revision_map_payload,input.binding_revision_map_digest,input.now_unix_ms]).context("inserting immutable agent profile snapshot")?;
    let created_session = if created_session { 1_i64 } else { 0_i64 };
    conn.execute("INSERT INTO agent_session_preparations(session_id,idempotency_key,request_fingerprint,snapshot_id,created_session,lifecycle_state,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,'prepared',?6)",params![input.session_id.to_string(),input.idempotency_key,input.request_fingerprint,snapshot_id.to_string(),created_session,input.now_unix_ms]).context("creating agent session preparation receipt")?;
    Ok(PrepareAgentSessionOutcome::Prepared(
        snapshot_by_id(conn, snapshot_id)?.expect("inserted snapshot"),
    ))
}

pub fn start_prepared_agent_session_conn(
    conn: &Connection,
    session_id: Uuid,
    idempotency_key: &str,
    now_unix_ms: i64,
) -> Result<StartAgentSessionOutcome> {
    let Some((_, state, snapshot)) = preparation_by_key(conn, session_id, idempotency_key)? else {
        return Ok(StartAgentSessionOutcome::NotPrepared);
    };
    match state.as_str() {
        "running" => Ok(StartAgentSessionOutcome::AlreadyStarted(snapshot)),
        "terminal" => Ok(StartAgentSessionOutcome::Terminal(snapshot)),
        "prepared" => {
            match session_preparation_eligibility(conn, session_id)? {
                SessionPreparationEligibility::OrdinaryActive => {}
                SessionPreparationEligibility::Missing
                | SessionPreparationEligibility::Terminal
                | SessionPreparationEligibility::Deleted => {
                    // The only route that creates a receipt creates its
                    // session atomically, so this is a terminal lifecycle
                    // race rather than permission to attach elsewhere.
                    conn.execute(
                        "UPDATE agent_session_preparations SET lifecycle_state='terminal',terminal_at_unix_ms=?2 WHERE session_id=?1 AND idempotency_key=?3 AND lifecycle_state='prepared'",
                        params![session_id.to_string(), now_unix_ms, idempotency_key],
                    )
                    .context("terminalizing unavailable prepared agent session")?;
                    terminalize_preparation_claim(conn, session_id, now_unix_ms)?;
                    return Ok(StartAgentSessionOutcome::Terminal(snapshot));
                }
            }
            let changed=conn.execute("UPDATE agent_session_preparations SET lifecycle_state='running',started_at_unix_ms=?3 WHERE session_id=?1 AND idempotency_key=?2 AND lifecycle_state='prepared'",params![session_id.to_string(),idempotency_key,now_unix_ms]).context("claiming prepared agent session launch")?;
            if changed == 1 {
                conn.execute(
                    "UPDATE agent_session_preparation_claims SET claim_state='running' WHERE session_id=?1 AND claim_state='claimed'",
                    [session_id.to_string()],
                )
                .context("opening claimed existing agent session for dispatch")?;
                Ok(StartAgentSessionOutcome::Started(snapshot))
            } else {
                let (_, state, snapshot) =
                    preparation_by_key(conn, session_id, idempotency_key)?
                        .context("agent session preparation disappeared during launch claim")?;
                Ok(match state.as_str() {
                    "running" => StartAgentSessionOutcome::AlreadyStarted(snapshot),
                    "terminal" => StartAgentSessionOutcome::Terminal(snapshot),
                    _ => bail!("invalid post-claim agent preparation state `{state}`"),
                })
            }
        }
        _ => bail!("invalid stored agent preparation lifecycle state `{state}`"),
    }
}

pub fn terminal_agent_session_conn(
    conn: &Connection,
    session_id: Uuid,
    idempotency_key: &str,
    now_unix_ms: i64,
) -> Result<StartAgentSessionOutcome> {
    let Some((_, state, snapshot)) = preparation_by_key(conn, session_id, idempotency_key)? else {
        return Ok(StartAgentSessionOutcome::NotPrepared);
    };
    match state.as_str() {
        "terminal" => Ok(StartAgentSessionOutcome::Terminal(snapshot)),
        "running" | "prepared" => {
            conn.execute("UPDATE agent_session_preparations SET lifecycle_state='terminal',terminal_at_unix_ms=?3 WHERE session_id=?1 AND idempotency_key=?2 AND lifecycle_state IN ('prepared','running')",params![session_id.to_string(),idempotency_key,now_unix_ms]).context("terminalizing agent session")?;
            terminalize_preparation_claim(conn, session_id, now_unix_ms)?;
            Ok(StartAgentSessionOutcome::Terminal(snapshot))
        }
        _ => bail!("invalid stored agent preparation lifecycle state `{state}`"),
    }
}

pub fn delete_agent_installation_conn(
    conn: &Connection,
    installation_id: Uuid,
    now_unix_ms: i64,
) -> Result<DeleteAgentInstallationOutcome> {
    let Some(installation) = installation_by_id(conn, installation_id)? else {
        return Ok(DeleteAgentInstallationOutcome::NotFound);
    };
    let snapshot_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_profile_snapshots WHERE installation_id=?1",
            [installation_id.to_string()],
            |row| row.get(0),
        )
        .context("counting installation snapshots")?;
    if snapshot_count > 0 {
        if installation.deleted_at_unix_ms.is_some() {
            return Ok(DeleteAgentInstallationOutcome::AlreadyDeleted);
        }
        conn.execute("UPDATE agent_installations SET deleted_at_unix_ms=?2,installation_revision=installation_revision+1 WHERE installation_id=?1",params![installation_id.to_string(),now_unix_ms]).context("tombstoning snapshotted agent installation")?;
        return Ok(DeleteAgentInstallationOutcome::Tombstoned);
    }
    conn.execute(
        "DELETE FROM agent_binding_receipts WHERE installation_id=?1",
        [installation_id.to_string()],
    )
    .context("deleting unreferenced agent binding receipts")?;
    conn.execute(
        "UPDATE agent_model_bindings SET retired_at_unix_ms=?2 WHERE installation_id=?1 AND retired_at_unix_ms IS NULL AND is_default=0",
        params![installation_id.to_string(), now_unix_ms],
    )
    .context("retiring unreferenced agent binding alternates")?;
    conn.execute(
        "UPDATE agent_model_bindings SET retired_at_unix_ms=?2 WHERE installation_id=?1 AND retired_at_unix_ms IS NULL AND is_default=1",
        params![installation_id.to_string(), now_unix_ms],
    )
    .context("retiring unreferenced agent binding defaults")?;
    conn.execute(
        "DELETE FROM agent_model_bindings WHERE installation_id=?1",
        [installation_id.to_string()],
    )
    .context("deleting unreferenced agent bindings")?;
    conn.execute(
        "DELETE FROM installation_observations WHERE installation_id=?1",
        [installation_id.to_string()],
    )
    .context("deleting unreferenced agent observation")?;
    conn.execute(
        "DELETE FROM agent_installations WHERE installation_id=?1",
        [installation_id.to_string()],
    )
    .context("hard-deleting unreferenced agent installation")?;
    Ok(DeleteAgentInstallationOutcome::Deleted)
}

fn validate_installation(input: &AgentInstallationInput) -> Result<()> {
    ensure!(
        !input.source_agent_id.is_empty(),
        "source agent id is required"
    );
    ensure!(
        !input.source_identity.is_empty(),
        "source identity is required"
    );
    validate_digest(&input.source_digest, "source digest")?;
    scope_key(input.scope, input.canonical_workspace_id.as_deref())?;
    Ok(())
}
fn validate_binding(binding: &AgentBindingInput) -> Result<()> {
    ensure!(
        binding.hard_capability_verified,
        "hard capability compatibility must be verified before binding"
    );
    ensure!(!binding.slot_id.is_empty(), "model slot id is required");
    ensure!(
        !binding.provider_profile_handle.is_empty(),
        "provider profile handle is required"
    );
    ensure!(!binding.model_id.is_empty(), "model id is required");
    validate_payload(
        &binding.provenance_payload,
        &binding.provenance_digest,
        "binding provenance",
    )
}
fn validate_prepare(input: &PrepareAgentSessionInput) -> Result<()> {
    ensure!(
        !input.session_create.project_id.is_empty(),
        "agent session project id is required"
    );
    ensure!(
        !input.session_create.project_root.is_empty(),
        "agent session project root is required"
    );
    ensure!(
        !input.session_create.active_agent.is_empty(),
        "agent session active agent is required"
    );
    ensure!(
        input.session_create.started_at_unix_ms >= 0
            && input.session_create.last_active_at_unix_ms
                >= input.session_create.started_at_unix_ms,
        "agent session timestamps must be ordered non-negative Unix milliseconds"
    );
    ensure!(
        !input.idempotency_key.is_empty(),
        "prepare idempotency key is required"
    );
    ensure!(
        !input.request_fingerprint.is_empty(),
        "prepare request fingerprint is required"
    );
    ensure!(
        input.snapshot_schema_version > 0,
        "snapshot schema version must be positive"
    );
    validate_digest(
        &input.expected_definition_digest,
        "expected definition digest",
    )?;
    validate_payload(
        &input.canonical_snapshot_payload,
        &input.canonical_snapshot_digest,
        "canonical agent profile snapshot",
    )?;
    validate_payload(
        &input.binding_revision_map_payload,
        &input.binding_revision_map_digest,
        "binding revision map",
    )?;
    // Both payloads are canonical typed DB wire values.  Parsing here makes
    // malformed values fail before the transaction touches any lifecycle row;
    // exact canonical-byte checking happens in the decoders as well.
    decode_canonical_snapshot(
        &input.canonical_snapshot_payload,
        "canonical agent profile snapshot",
    )?;
    decode_canonical_binding_revision_map(
        &input.binding_revision_map_payload,
        "binding revision map",
    )?;
    let mut child_ids = HashSet::new();
    ensure!(
        input.expected_children.iter().all(|child| {
            child.installation_id != input.installation_id
                && child.expected_installation_revision > 0
                && child.expected_observation_revision > 0
                && child_ids.insert(child.installation_id)
        }),
        "child preparation expectations must name distinct non-root generations"
    );
    for child in &input.expected_children {
        validate_digest(
            &child.expected_definition_digest,
            "expected child definition digest",
        )?;
    }
    Ok(())
}
fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|b| matches!(b,b'0'..=b'9'|b'a'..=b'f')),
        "{label} must be 64 lowercase hexadecimal characters"
    );
    Ok(())
}
fn validate_payload(payload: &[u8], digest: &str, label: &str) -> Result<()> {
    ensure!(!payload.is_empty(), "{label} payload is required");
    validate_digest(digest, &format!("{label} digest"))?;
    let actual = hex_digest(payload);
    ensure!(
        actual == digest,
        "{label} digest does not match canonical payload"
    );
    Ok(())
}
fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn scope_key(scope: AgentInstallationScope, workspace: Option<&str>) -> Result<String> {
    match (scope, workspace) {
        (AgentInstallationScope::Global, None) => Ok(String::new()),
        (AgentInstallationScope::Global, Some(_)) => {
            bail!("global installation must not have a workspace identity")
        }
        (_, Some(value)) if !value.is_empty() => Ok(value.to_string()),
        _ => bail!("workspace installation requires a canonical workspace identity"),
    }
}

fn installation_by_identity(
    conn: &Connection,
    scope: AgentInstallationScope,
    scope_key: &str,
    source_agent_id: &str,
) -> Result<Option<AgentInstallationRow>> {
    conn.query_row("SELECT installation_id,scope,canonical_workspace_id,source_agent_id,source_identity,source_revision,source_digest,fetched_at_unix_ms,installation_revision,deleted_at_unix_ms FROM agent_installations WHERE scope=?1 AND scope_workspace_key=?2 AND source_agent_id=?3",params![scope.as_str(),scope_key,source_agent_id],decode_installation).optional().context("looking up agent installation identity")
}

fn installations_by_scope(
    conn: &Connection,
    scope: AgentInstallationScope,
    scope_workspace_key: &str,
) -> Result<Vec<AgentInstallationRow>> {
    let mut statement = conn
        .prepare(
            "SELECT installation_id,scope,canonical_workspace_id,source_agent_id,source_identity,source_revision,source_digest,fetched_at_unix_ms,installation_revision,deleted_at_unix_ms FROM agent_installations WHERE scope=?1 AND scope_workspace_key=?2 ORDER BY source_agent_id ASC",
        )
        .context("preparing scoped agent installation list")?;
    statement
        .query_map(
            params![scope.as_str(), scope_workspace_key],
            decode_installation,
        )
        .context("querying scoped agent installation list")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("decoding scoped agent installation list")
}

enum SessionPreparationEligibility {
    /// An ordinary `sessions` active row.  It is deliberately not evidence
    /// that this module prepared it; only `agent_session_preparations` is.
    OrdinaryActive,
    Terminal,
    Deleted,
    Missing,
}

enum PreparationTarget {
    CreateMissing,
    ClaimExisting(Uuid),
}

#[derive(Clone, Copy)]
enum PreparationClaimState {
    Eligible,
    Claimed,
    Running,
    Terminal,
}

fn register_agent_session_preparation_conn(
    conn: &Connection,
    session_id: Uuid,
    claim_token: Uuid,
    now_unix_ms: i64,
) -> Result<RegisterAgentSessionPreparationOutcome> {
    match session_preparation_eligibility(conn, session_id)? {
        SessionPreparationEligibility::Missing => {
            return Ok(RegisterAgentSessionPreparationOutcome::NotFound);
        }
        SessionPreparationEligibility::Terminal => {
            return Ok(RegisterAgentSessionPreparationOutcome::Terminal);
        }
        SessionPreparationEligibility::Deleted => {
            return Ok(RegisterAgentSessionPreparationOutcome::Deleted);
        }
        SessionPreparationEligibility::OrdinaryActive => {}
    }
    if snapshot_for_session(conn, session_id)?.is_some() {
        return Ok(RegisterAgentSessionPreparationOutcome::Conflict);
    }
    let idle: bool = conn
        .query_row(
            "SELECT started_at_unix_ms = last_active_at_unix_ms AND NOT EXISTS(SELECT 1 FROM session_events WHERE session_id=?1) FROM sessions WHERE session_id=?1",
            [session_id.to_string()],
            |row| row.get(0),
        )
        .context("checking whether an existing agent session is idle")?;
    if !idle {
        return Ok(RegisterAgentSessionPreparationOutcome::Conflict);
    }
    let existing = conn
        .query_row(
            "SELECT claim_token,claim_state FROM agent_session_preparation_claims WHERE session_id=?1",
            [session_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .context("looking up existing agent session preparation marker")?;
    if let Some((stored_token, state)) = existing {
        return Ok(
            if stored_token == claim_token.to_string() && state == "eligible" {
                RegisterAgentSessionPreparationOutcome::AlreadyEligible
            } else {
                RegisterAgentSessionPreparationOutcome::Conflict
            },
        );
    }
    conn.execute(
        "INSERT INTO agent_session_preparation_claims(session_id,claim_token,claim_state,created_at_unix_ms) VALUES(?1,?2,'eligible',?3)",
        params![session_id.to_string(), claim_token.to_string(), now_unix_ms],
    )
    .context("recording eligible existing agent session preparation marker")?;
    Ok(RegisterAgentSessionPreparationOutcome::Eligible)
}

fn preparation_claim_state(
    conn: &Connection,
    session_id: Uuid,
    token: Uuid,
) -> Result<Option<PreparationClaimState>> {
    conn.query_row(
        "SELECT claim_state FROM agent_session_preparation_claims WHERE session_id=?1 AND claim_token=?2",
        params![session_id.to_string(), token.to_string()],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .context("looking up eligible existing agent session preparation marker")?
    .map(|state| match state.as_str() {
        "eligible" => Ok(PreparationClaimState::Eligible),
        "claimed" => Ok(PreparationClaimState::Claimed),
        "running" => Ok(PreparationClaimState::Running),
        "terminal" => Ok(PreparationClaimState::Terminal),
        _ => bail!("invalid agent session preparation marker state `{state}`"),
    })
    .transpose()
}

fn terminalize_preparation_claim(
    conn: &Connection,
    session_id: Uuid,
    now_unix_ms: i64,
) -> Result<()> {
    conn.execute(
        // schema-hot-query: local.agent-preparation.terminalize
        "UPDATE agent_session_preparation_claims SET claim_state='terminal',terminal_at_unix_ms=?2 WHERE session_id=?1 AND claim_state IN ('claimed', 'running')",
        params![session_id.to_string(), now_unix_ms],
    )
    .context("terminalizing agent session preparation marker")?;
    Ok(())
}

/// Insert exactly the mandatory normal-session fields, letting the canonical
/// `sessions` schema supply every owned default.  This is intentionally local
/// instead of going through `Db::create_session`: callers are already inside
/// the writer transaction that will install the immutable snapshot.
fn create_agent_session_conn(
    conn: &Connection,
    session_id: Uuid,
    create: &AgentSessionCreateInput,
    snapshot: &RedactedAgentProfileSnapshot,
) -> Result<()> {
    let primary = snapshot
        .bindings
        .iter()
        .find(|binding| binding.slot_id == "primary" && binding.is_default)
        .context("prepared profile has no primary-slot default binding")?;
    let selection_json = serde_json::json!({
        "provider": primary.provider_profile_handle,
        "model": primary.model_id,
    })
    .to_string();
    conn.execute(
        "INSERT INTO sessions(session_id,project_id,project_root,started_at_unix_ms,last_active_at_unix_ms,active_agent,provider,model,model_selection_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            session_id.to_string(),
            create.project_id,
            create.project_root,
            create.started_at_unix_ms,
            create.last_active_at_unix_ms,
            create.active_agent,
            primary.provider_profile_handle,
            primary.model_id,
            selection_json,
        ],
    )
    .context("atomically creating session for agent preparation")?;
    Ok(())
}

fn set_prepared_session_primary_model_conn(
    conn: &Connection,
    session_id: Uuid,
    snapshot: &RedactedAgentProfileSnapshot,
) -> Result<()> {
    let primary = snapshot
        .bindings
        .iter()
        .find(|binding| binding.slot_id == "primary" && binding.is_default)
        .context("prepared profile has no primary-slot default binding")?;
    let selection_json = serde_json::json!({
        "provider": primary.provider_profile_handle,
        "model": primary.model_id,
    })
    .to_string();
    let changed = conn
        .execute(
            "UPDATE sessions SET provider=?1,model=?2,model_selection_json=?3,active_model_revision=active_model_revision+1 WHERE session_id=?4",
            params![
                primary.provider_profile_handle,
                primary.model_id,
                selection_json,
                session_id.to_string()
            ],
        )
        .context("persisting prepared primary model on existing session")?;
    ensure!(
        changed == 1,
        "prepared session disappeared while selecting its primary model"
    );
    Ok(())
}

fn session_preparation_eligibility(
    conn: &Connection,
    session_id: Uuid,
) -> Result<SessionPreparationEligibility> {
    let state = conn
        .query_row(
            "SELECT ended_at_unix_ms,lifecycle FROM sessions WHERE session_id=?1",
            [session_id.to_string()],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .context("checking session preparation lifecycle")?;
    Ok(match state {
        None => SessionPreparationEligibility::Missing,
        Some((Some(_), _)) => SessionPreparationEligibility::Terminal,
        Some((None, lifecycle)) if lifecycle == "active" => {
            SessionPreparationEligibility::OrdinaryActive
        }
        // `deleting` is a live tombstone barrier: do not attach a new durable
        // snapshot to a row that is in the process of disappearing.
        Some((None, lifecycle)) if lifecycle == "deleting" => {
            SessionPreparationEligibility::Deleted
        }
        Some((_, lifecycle)) => bail!("invalid stored session lifecycle `{lifecycle}`"),
    })
}

fn installation_by_id(conn: &Connection, id: Uuid) -> Result<Option<AgentInstallationRow>> {
    conn.query_row("SELECT installation_id,scope,canonical_workspace_id,source_agent_id,source_identity,source_revision,source_digest,fetched_at_unix_ms,installation_revision,deleted_at_unix_ms FROM agent_installations WHERE installation_id=?1",[id.to_string()],decode_installation).optional().context("looking up agent installation")
}
fn decode_installation(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentInstallationRow> {
    Ok(AgentInstallationRow {
        installation_id: parse_uuid(row.get::<_, String>(0)?)?,
        scope: decode_scope(&row.get::<_, String>(1)?)?,
        canonical_workspace_id: row.get(2)?,
        source_agent_id: row.get(3)?,
        source_identity: row.get(4)?,
        source_revision: row.get(5)?,
        source_digest: row.get(6)?,
        fetched_at_unix_ms: row.get(7)?,
        installation_revision: as_u64(row.get(8)?)?,
        deleted_at_unix_ms: row.get(9)?,
    })
}
fn observation_by_id(conn: &Connection, id: Uuid) -> Result<Option<AgentObservationRow>> {
    conn.query_row("SELECT installation_id,observed_digest,observation_revision,review_state,observed_at_unix_ms FROM installation_observations WHERE installation_id=?1",[id.to_string()],decode_observation).optional().context("looking up agent installation observation")
}
fn decode_observation(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentObservationRow> {
    let review: String = row.get(3)?;
    let reviewed = match review.as_str() {
        "reviewed" => true,
        "rebind_required" => false,
        _ => {
            return Err(rusqlite::Error::InvalidColumnType(
                3,
                "review_state".into(),
                rusqlite::types::Type::Text,
            ));
        }
    };
    Ok(AgentObservationRow {
        installation_id: parse_uuid(row.get::<_, String>(0)?)?,
        observed_digest: row.get(1)?,
        observation_revision: as_u64(row.get(2)?)?,
        reviewed,
        observed_at_unix_ms: row.get(4)?,
    })
}
fn current_binding(
    conn: &Connection,
    installation_id: Uuid,
    definition_digest: &str,
    slot_id: &str,
) -> Result<Option<AgentBindingRow>> {
    conn.query_row("SELECT binding_id,installation_id,definition_digest,slot_id,provider_profile_handle,model_id,provenance_payload,provenance_digest,hard_capability_verified,binding_revision,is_default,retired_at_unix_ms,created_at_unix_ms FROM agent_model_bindings WHERE installation_id=?1 AND definition_digest=?2 AND slot_id=?3 AND retired_at_unix_ms IS NULL AND is_default=1",params![installation_id.to_string(),definition_digest,slot_id],decode_binding).optional().context("looking up current agent model binding")
}

/// Public reads fail closed when the installation is tombstoned or its source
/// observation is stale/unreviewed.  Historical snapshots use
/// `binding_by_id`/their stored payload and are intentionally unaffected.
fn current_usable_binding(
    conn: &Connection,
    installation_id: Uuid,
    definition_digest: &str,
    slot_id: &str,
) -> Result<Option<AgentBindingRow>> {
    let Some(installation) = installation_by_id(conn, installation_id)? else {
        return Ok(None);
    };
    if installation.deleted_at_unix_ms.is_some() {
        return Ok(None);
    }
    let Some(observation) = observation_by_id(conn, installation_id)? else {
        return Ok(None);
    };
    if !observation.reviewed || observation.observed_digest != definition_digest {
        return Ok(None);
    }
    current_binding(conn, installation_id, definition_digest, slot_id)
}

fn current_bindings_for_digest(
    conn: &Connection,
    installation_id: Uuid,
    definition_digest: &str,
) -> Result<Vec<AgentBindingRow>> {
    let mut statement = conn
        .prepare(
            "SELECT binding_id,installation_id,definition_digest,slot_id,provider_profile_handle,model_id,provenance_payload,provenance_digest,hard_capability_verified,binding_revision,is_default,retired_at_unix_ms,created_at_unix_ms FROM agent_model_bindings WHERE installation_id=?1 AND definition_digest=?2 AND retired_at_unix_ms IS NULL ORDER BY slot_id ASC",
        )
        .context("preparing current agent binding set lookup")?;
    statement
        .query_map(
            params![installation_id.to_string(), definition_digest],
            decode_binding,
        )
        .context("querying current agent binding set")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("decoding current agent binding set")
}

fn current_slot_binding_revision(current: &[AgentBindingRow]) -> Result<Option<u64>> {
    let mut revisions = current
        .iter()
        .map(|binding| binding.binding_revision)
        .collect::<HashSet<_>>();
    match revisions.len() {
        0 => Ok(None),
        1 => Ok(revisions.drain().next()),
        _ => bail!("current live slot binding set has inconsistent revisions"),
    }
}

fn slot_binding_set_matches_current(
    requested: &[AgentBindingInput],
    current: &[AgentBindingRow],
) -> bool {
    let requested_by_key = requested
        .iter()
        .map(|binding| {
            (
                (
                    binding.slot_id.as_str(),
                    binding.provider_profile_handle.as_str(),
                    binding.model_id.as_str(),
                ),
                (
                    binding.provenance_digest.as_str(),
                    binding.hard_capability_verified,
                    binding.is_default,
                ),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let current_by_key = current
        .iter()
        .map(|binding| {
            (
                (
                    binding.slot_id.as_str(),
                    binding.provider_profile_handle.as_str(),
                    binding.model_id.as_str(),
                ),
                (
                    binding.provenance_digest.as_str(),
                    binding.hard_capability_verified,
                    binding.is_default,
                ),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    requested_by_key == current_by_key
}

fn decode_canonical_snapshot(payload: &[u8], label: &str) -> Result<RedactedAgentProfileSnapshot> {
    let value: RedactedAgentProfileSnapshot =
        serde_json::from_slice(payload).with_context(|| format!("decoding {label}"))?;
    let canonical = serde_json::to_vec(&value).with_context(|| format!("encoding {label}"))?;
    ensure!(
        canonical == payload,
        "{label} must use canonical JSON encoding"
    );
    ensure!(!value.agent_id.is_empty(), "snapshot agent id is required");
    if let Some(delegation) = &value.effective_delegation {
        ensure!(
            delegation.max_descendant_depth > 0 && delegation.max_concurrent_children > 0,
            "effective delegation depth and concurrency must be positive"
        );
        ensure!(
            !delegation.allowed_children.is_empty() && !delegation.targets.is_empty(),
            "effective delegation requires children and targets"
        );
        ensure!(
            delegation.allowed_children.iter().all(|child| {
                matches!(
                    child,
                    RedactedAllowedChild::LocalInstallation { .. }
                        | RedactedAllowedChild::SelfInvocation { .. }
                )
            }) && sorted_unique(&delegation.allowed_children),
            "effective delegation must contain only resolved local children or self invocation"
        );
        ensure!(
            delegation
                .allowed_children
                .iter()
                .filter(|child| matches!(child, RedactedAllowedChild::SelfInvocation { .. }))
                .count()
                <= 1
                && delegation.allowed_children.iter().all(|child| match child {
                    RedactedAllowedChild::SelfInvocation { execution_kind } => {
                        *execution_kind == value.execution_kind
                            && *execution_kind != AgentExecutionKind::Computer
                    }
                    _ => true,
                }),
            "effective delegation self invocation must uniquely match the root execution kind"
        );
        ensure!(
            sorted_unique(&delegation.targets),
            "effective delegation targets must be sorted and unique"
        );
    }
    let mut keys: HashSet<(String, String, String)> = HashSet::new();
    let mut defaults: HashSet<String> = HashSet::new();
    ensure!(
        value.bindings.iter().all(|binding| {
            let distinct = keys.insert((
                binding.slot_id.clone(),
                binding.provider_profile_handle.clone(),
                binding.model_id.clone(),
            ));
            let default_ok = !binding.is_default || defaults.insert(binding.slot_id.clone());
            !binding.slot_id.is_empty()
                && !binding.provider_profile_handle.is_empty()
                && !binding.model_id.is_empty()
                && !binding.selected_provider_alias.provider_id.is_empty()
                && !binding.selected_provider_alias.model_id.is_empty()
                && binding.selected_provider_alias.model_id == binding.model_id
                && binding.hard_capability_verified
                && distinct
                && default_ok
        }),
        "snapshot binding evidence must have distinct hard-compatible (slot, provider, model) rows and exactly one default per live slot"
    );
    let bound_slots = value
        .bindings
        .iter()
        .map(|binding| binding.slot_id.clone())
        .collect::<HashSet<_>>();
    ensure!(
        bound_slots == defaults,
        "snapshot binding evidence must contain exactly one default for every live slot"
    );
    validate_child_binding_evidence(&value)?;
    validate_question_policy(&value.question_policy, &value.bindings)?;
    ensure!(
        value
            .verification_regions
            .iter()
            .all(validate_verification_region),
        "verification regions violate effective action/mask/budget invariants"
    );
    ensure!(
        verification_region_precedence_is_canonical(&value.verification_regions),
        "verification regions do not preserve canonical first-match precedence"
    );
    ensure!(
        value.verification_regions.iter().all(|region| {
            region.adjudicator_slot.iter().all(|slot| {
                value
                    .bindings
                    .iter()
                    .any(|binding| binding.slot_id == *slot && binding.is_default)
            }) && region
                .execution_plan
                .iter()
                .flat_map(|plan| plan.generators.iter().map(|generator| &generator.slot))
                .all(|slot| {
                    value
                        .bindings
                        .iter()
                        .any(|binding| binding.slot_id == *slot)
                })
        }),
        "verification executor slots must reference snapshot bindings"
    );
    validate_recommendations(&value.recommendations)?;
    ensure!(
        value.recommendations.iter().all(|recommendation| {
            let Some(binding) = value
                .bindings
                .iter()
                .find(|binding| binding.slot_id == recommendation.slot_id)
            else {
                return false;
            };
            recommendation
                .exact_provider_alias
                .as_ref()
                .is_none_or(|selected| selected == &binding.selected_provider_alias)
        }),
        "recommendations must reference a snapshot slot and exact aliases must match that slot binding"
    );
    let mut region_ids = HashSet::new();
    ensure!(
        value
            .verification_regions
            .iter()
            .all(|region| region_ids.insert(&region.source_rule_id)),
        "verification regions must retain distinct source-rule identities"
    );
    Ok(value)
}

fn validate_child_binding_evidence(snapshot: &RedactedAgentProfileSnapshot) -> Result<()> {
    let authorized = snapshot
        .effective_delegation
        .iter()
        .flat_map(|delegation| &delegation.allowed_children)
        .filter_map(|child| match child {
            RedactedAllowedChild::LocalInstallation {
                installation_id, ..
            } => Some(*installation_id),
            RedactedAllowedChild::SelfInvocation { .. } => None,
            RedactedAllowedChild::PortableRef { .. } => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let evidenced = snapshot
        .child_bindings
        .iter()
        .map(|evidence| evidence.installation_id)
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        authorized == evidenced,
        "snapshot child binding evidence must exactly cover authorized children"
    );
    let mut routes = HashSet::new();
    let mut generations = std::collections::BTreeMap::new();
    let mut primary_counts = std::collections::BTreeMap::<Uuid, (usize, usize)>::new();
    for evidence in &snapshot.child_bindings {
        validate_digest(&evidence.definition_digest, "child definition digest")?;
        ensure!(
            evidence.installation_revision > 0
                && evidence.observation_revision > 0
                && evidence.binding.hard_capability_verified
                && !evidence.binding.slot_id.is_empty()
                && !evidence.binding.provider_profile_handle.is_empty()
                && !evidence.binding.model_id.is_empty()
                && evidence.binding.selected_provider_alias.model_id == evidence.binding.model_id
                && !evidence
                    .binding
                    .selected_provider_alias
                    .provider_id
                    .is_empty(),
            "snapshot child binding route or generation is invalid"
        );
        ensure!(
            generations.entry(evidence.installation_id).or_insert((
                evidence.installation_revision,
                evidence.observation_revision,
                evidence.definition_digest.as_str(),
            )) == &(
                evidence.installation_revision,
                evidence.observation_revision,
                evidence.definition_digest.as_str(),
            ),
            "snapshot mixes child installation generations"
        );
        ensure!(
            routes.insert((
                evidence.installation_id,
                evidence.binding.slot_id.as_str(),
                evidence.binding.provider_profile_handle.as_str(),
                evidence.binding.model_id.as_str(),
            )),
            "snapshot duplicates a child binding route"
        );
        let requirements = &evidence.slot_requirements;
        let allowed_models = requirements
            .allowed_models
            .iter()
            .map(|model| (model.provider_id.as_str(), model.model_id.as_str()))
            .collect::<HashSet<_>>();
        ensure!(
            requirements.min_context_tokens > 0
                && matches!(requirements.locality.as_str(), "any" | "local" | "remote")
                && !requirements.required_capabilities.is_empty()
                && sorted_unique(&requirements.required_capabilities)
                && requirements
                    .required_capabilities
                    .iter()
                    .all(|capability| matches!(
                        capability.as_str(),
                        "text_generation"
                            | "tool_calling"
                            | "vision"
                            | "computer_use"
                            | "json_schema"
                    ))
                && requirements
                    .allowed_models
                    .iter()
                    .all(|model| { !model.provider_id.is_empty() && !model.model_id.is_empty() })
                && allowed_models.len() == requirements.allowed_models.len(),
            "snapshot child slot requirements are invalid"
        );
        if evidence.binding.slot_id == "primary" {
            let counts = primary_counts.entry(evidence.installation_id).or_default();
            counts.0 += 1;
            counts.1 += usize::from(evidence.binding.is_default);
        }
    }
    ensure!(
        authorized.iter().all(|installation_id| primary_counts
            .get(installation_id)
            .is_some_and(|counts| counts.0 > 0 && counts.1 == 1)),
        "snapshot authorized children require exactly one primary default"
    );
    Ok(())
}

fn sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

/// Recommendations belong to a model slot.  Their stable identifiers and
/// collision ranks are therefore scoped to that slot rather than to the
/// flattened snapshot list.  The flattened representation is still canonical:
/// slot groups are ordered lexicographically, and each group is ordered by its
/// contiguous author collision rank.
fn validate_recommendations(recommendations: &[RedactedRecommendation]) -> Result<()> {
    let mut ids = HashSet::new();
    let mut previous_slot: Option<&str> = None;
    let mut expected_rank = 0_u64;

    for recommendation in recommendations {
        ensure!(
            !recommendation.recommendation_id.is_empty()
                && !recommendation.slot_id.is_empty()
                && !recommendation.canonical_upstream_identity.is_empty()
                && recommendation
                    .author_label
                    .as_ref()
                    .is_none_or(|label| !label.is_empty())
                && recommendation
                    .rationale
                    .as_ref()
                    .is_none_or(|rationale| !rationale.is_empty())
                && recommendation
                    .provider_aliases
                    .iter()
                    .all(|alias| !alias.provider_id.is_empty() && !alias.model_id.is_empty())
                && sorted_unique(&recommendation.provider_aliases)
                && recommendation
                    .exact_provider_alias
                    .as_ref()
                    .is_none_or(|alias| {
                        recommendation.provider_aliases.binary_search(alias).is_ok()
                    })
                && ids.insert((
                    recommendation.slot_id.as_str(),
                    recommendation.recommendation_id.as_str()
                ))
                && (recommendation.author_suggested
                    == recommendation.exact_provider_alias.is_some()),
            "recommendations require slot-scoped distinct stable ids and upstream identities"
        );

        match previous_slot {
            None => expected_rank = 0,
            Some(slot) if slot == recommendation.slot_id.as_str() => {}
            Some(slot) => {
                ensure!(
                    slot < recommendation.slot_id.as_str(),
                    "recommendations must use canonical slot grouping"
                );
                expected_rank = 0;
            }
        }
        ensure!(
            recommendation.alias_collision_rank == expected_rank,
            "recommendation alias collision ranks must be contiguous within each slot"
        );
        expected_rank = expected_rank
            .checked_add(1)
            .context("recommendation alias collision rank overflow")?;
        previous_slot = Some(&recommendation.slot_id);
    }
    Ok(())
}

fn validate_verification_region(region: &RedactedVerificationRegion) -> bool {
    if region.source_rule_id.is_empty()
        || !valid_verification_selector(&region.source_selector)
        || region
            .excluded_prior_selectors
            .iter()
            .any(|selector| !valid_verification_selector(selector))
        || region
            .session_selector
            .as_ref()
            .is_some_and(|selector| !valid_verification_selector(selector))
        || !sorted_unique(&region.enabled_intersection_mask)
        || !sorted_unique(&region.explicit_off_remainder_mask)
        || !sorted_unique(&region.whole_region_off_mask)
        || region
            .explicit_off_remainder_mask
            .iter()
            .any(String::is_empty)
        || region.whole_region_off_mask.iter().any(String::is_empty)
        || region.enabled_intersection_mask.iter().any(|mask| {
            mask.is_empty()
                || region
                    .explicit_off_remainder_mask
                    .binary_search(mask)
                    .is_ok()
        })
    {
        return false;
    }
    let budget_complete_and_positive = [
        region.count_ceiling,
        region.token_ceiling,
        region.cost_ceiling_micros,
        region.max_collection_duration_ms,
    ]
    .into_iter()
    .all(|value| value.is_some_and(|value| value > 0));
    let source_mask = verification_selector_mask(&region.source_selector);
    let enabled_and_disabled = sorted_union(
        &region.enabled_intersection_mask,
        &region.explicit_off_remainder_mask,
    );
    let selector_and_mask_agree = match &region.session_selector {
        Some(selector) => verification_selector_mask(selector) == region.enabled_intersection_mask,
        None => region.enabled_intersection_mask == source_mask,
    };
    let execution_plan_valid = region.execution_plan.as_ref().is_some_and(|plan| {
        matches!(plan.mode.as_str(), "gate" | "revise")
            && matches!(
                plan.on_budget_exceeded.as_str(),
                "refuse" | "dispatch_original"
            )
            && matches!(
                plan.on_adjudication_failure.as_str(),
                "refuse" | "dispatch_original"
            )
            && plan.generators.len() <= 64
            && plan.generators.iter().all(|generator| {
                !generator.slot.is_empty()
                    && (1..=4).contains(&generator.max_turns)
                    && match &generator.recipe {
                        RedactedVerificationRecipe::Inherit => true,
                        RedactedVerificationRecipe::CleanRoom { last_n_reads, .. } => {
                            *last_n_reads > 0
                        }
                    }
            })
    });
    match (
        region.enabled,
        region.whole_region_off,
        region.effective_action,
    ) {
        (true, false, VerificationEffectiveAction::Verify) => {
            region.whole_region_off_mask.is_empty()
                && !region.enabled_intersection_mask.is_empty()
                && enabled_and_disabled == source_mask
                && selector_and_mask_agree
                && budget_complete_and_positive
                && region
                    .adjudicator_slot
                    .as_deref()
                    .is_some_and(|slot| !slot.is_empty())
                && execution_plan_valid
        }
        (false, true, VerificationEffectiveAction::Off) => {
            region.whole_region_off_mask == source_mask
                && region.enabled_intersection_mask.is_empty()
                && region.count_ceiling.is_none()
                && region.token_ceiling.is_none()
                && region.cost_ceiling_micros.is_none()
                && region.max_collection_duration_ms.is_none()
                && region.adjudicator_slot.is_none()
                && region.execution_plan.is_none()
        }
        _ => false,
    }
}

/// The array order is the source-rule order. Every region must retain the
/// complete ordered prefix of earlier source selectors, not merely a set of
/// selectors which happens to be locally well formed. Otherwise a forged
/// snapshot could omit an earlier off rule and allow later-rule fallthrough
/// after reload.
fn verification_region_precedence_is_canonical(regions: &[RedactedVerificationRegion]) -> bool {
    let mut earlier = Vec::with_capacity(regions.len());
    for region in regions {
        if region.excluded_prior_selectors != earlier {
            return false;
        }
        earlier.push(region.source_selector.clone());
    }
    true
}

fn sorted_union(left: &[String], right: &[String]) -> Vec<String> {
    let mut values = left.iter().chain(right).cloned().collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn verification_selector_mask(selector: &RedactedVerificationSelector) -> Vec<String> {
    let mut masks = selector
        .all_of
        .iter()
        .map(|predicate| format!("all:{}", verification_predicate_label(predicate)))
        .chain(
            selector
                .any_of
                .iter()
                .map(|predicate| format!("any:{}", verification_predicate_label(predicate))),
        )
        .collect::<Vec<_>>();
    masks.sort();
    masks
}

fn verification_predicate_label(predicate: &RedactedVerificationPredicate) -> String {
    match predicate {
        RedactedVerificationPredicate::ToolClass { tool_class } => {
            format!("tool_class:{tool_class}")
        }
        RedactedVerificationPredicate::ToolId { tool_id } => format!("tool_id:{tool_id}"),
        RedactedVerificationPredicate::Namespace { namespace } => format!("namespace:{namespace}"),
    }
}

fn valid_verification_selector(selector: &RedactedVerificationSelector) -> bool {
    let predicate_valid = |predicate: &RedactedVerificationPredicate| match predicate {
        RedactedVerificationPredicate::ToolClass { tool_class } => !tool_class.is_empty(),
        RedactedVerificationPredicate::ToolId { tool_id } => !tool_id.is_empty(),
        RedactedVerificationPredicate::Namespace { namespace } => !namespace.is_empty(),
    };
    (!selector.all_of.is_empty() || !selector.any_of.is_empty())
        && sorted_unique(&selector.all_of)
        && sorted_unique(&selector.any_of)
        && selector.all_of.iter().all(predicate_valid)
        && selector.any_of.iter().all(predicate_valid)
}

fn validate_question_policy(
    policy: &RedactedQuestionPolicy,
    bindings: &[RedactedBindingEvidence],
) -> Result<()> {
    let RedactedQuestionPolicy::Active {
        prohibited_classes,
        required_decision_timeout_ms,
        host_resource_ceiling_ms,
        resolver_slot,
        ..
    } = policy
    else {
        return Ok(());
    };
    ensure!(
        *required_decision_timeout_ms > 0 && *host_resource_ceiling_ms > 0,
        "active question policy timeouts must be positive"
    );
    ensure!(
        required_decision_timeout_ms <= host_resource_ceiling_ms,
        "active question policy exceeds its host resource ceiling"
    );
    ensure!(
        !resolver_slot.is_empty()
            && bindings
                .iter()
                .any(|binding| binding.slot_id.as_str() == resolver_slot.as_str()
                    && binding.is_default),
        "active question policy resolver slot must have a default snapshot binding"
    );
    ensure!(
        prohibited_classes.iter().all(|class| !class.is_empty())
            && sorted_unique(prohibited_classes),
        "active question policy prohibited classes must be non-empty, sorted, and unique"
    );
    Ok(())
}

fn decode_canonical_binding_revision_map(
    payload: &[u8],
    label: &str,
) -> Result<AgentBindingRevisionMap> {
    let value: AgentBindingRevisionMap =
        serde_json::from_slice(payload).with_context(|| format!("decoding {label}"))?;
    let canonical = serde_json::to_vec(&value).with_context(|| format!("encoding {label}"))?;
    ensure!(
        canonical == payload,
        "{label} must use canonical JSON encoding"
    );
    let mut keys: HashSet<(String, String, String)> = HashSet::new();
    ensure!(
        value.bindings.iter().all(|binding| {
            !binding.slot_id.is_empty()
                && !binding.model_id.is_empty()
                && binding.binding_revision > 0
                && !binding.provider_profile_handle.is_empty()
                && keys.insert((
                    binding.slot_id.clone(),
                    binding.provider_profile_handle.clone(),
                    binding.model_id.clone(),
                ))
        }),
        "binding revision map must contain distinct non-zero (slot, provider, model) revisions"
    );
    ensure!(
        keys.iter().any(|(slot, _, _)| slot == "primary"),
        "binding revision map must include the primary slot"
    );
    Ok(value)
}

fn binding_map_matches_expectations(
    map: &AgentBindingRevisionMap,
    expected: &[AgentBindingExpectation],
) -> Result<bool> {
    let mut expected_by_key = std::collections::BTreeMap::new();
    for item in expected {
        // Multiple providers may expose the same model id in one slot; the
        // durable conflict key is the complete (slot, provider, model) route.
        expected_by_key.insert(
            (
                item.slot_id.as_str(),
                item.provider_profile_handle.as_str(),
                item.model_id.as_str(),
            ),
            item.expected_binding_revision,
        );
    }
    let map_by_key = map
        .bindings
        .iter()
        .map(|item| {
            (
                (
                    item.slot_id.as_str(),
                    item.provider_profile_handle.as_str(),
                    item.model_id.as_str(),
                ),
                item.binding_revision,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    Ok(map_by_key == expected_by_key)
}

fn binding_map_matches_current(map: &AgentBindingRevisionMap, current: &[AgentBindingRow]) -> bool {
    let current_by_key = current
        .iter()
        .map(|binding| {
            (
                (
                    binding.slot_id.as_str(),
                    binding.provider_profile_handle.as_str(),
                    binding.model_id.as_str(),
                ),
                binding.binding_revision,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let map_by_key = map
        .bindings
        .iter()
        .map(|binding| {
            (
                (
                    binding.slot_id.as_str(),
                    binding.provider_profile_handle.as_str(),
                    binding.model_id.as_str(),
                ),
                binding.binding_revision,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    map_by_key == current_by_key
}

fn binding_expectations_match_current(
    expected: &[AgentBindingExpectation],
    current: &[AgentBindingRow],
) -> bool {
    let expected_by_key = expected
        .iter()
        .map(|binding| {
            (
                (
                    binding.slot_id.as_str(),
                    binding.provider_profile_handle.as_str(),
                    binding.model_id.as_str(),
                ),
                binding.expected_binding_revision,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let current_by_key = current
        .iter()
        .map(|binding| {
            (
                (
                    binding.slot_id.as_str(),
                    binding.provider_profile_handle.as_str(),
                    binding.model_id.as_str(),
                ),
                binding.binding_revision,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    expected_by_key.len() == expected.len()
        && current_by_key.len() == current.len()
        && expected_by_key == current_by_key
}

fn snapshot_evidence_matches_current(
    snapshot: &RedactedAgentProfileSnapshot,
    current: &[AgentBindingRow],
) -> bool {
    let evidence = snapshot
        .bindings
        .iter()
        .map(|binding| {
            (
                (
                    binding.slot_id.as_str(),
                    binding.provider_profile_handle.as_str(),
                    binding.model_id.as_str(),
                ),
                binding,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    if evidence.len() != current.len() {
        return false;
    }
    current.iter().all(|binding| {
        evidence
            .get(&(
                binding.slot_id.as_str(),
                binding.provider_profile_handle.as_str(),
                binding.model_id.as_str(),
            ))
            .is_some_and(|actual| {
                actual.binding_revision == binding.binding_revision
                    && actual.provider_profile_handle == binding.provider_profile_handle
                    && actual.model_id == binding.model_id
                    && actual.provenance_digest == binding.provenance_digest
                    && actual.hard_capability_verified
                    && binding.hard_capability_verified
                    && actual.is_default == binding.is_default
            })
    })
}

fn child_snapshot_evidence_matches_current(
    snapshot: &RedactedAgentProfileSnapshot,
    installation_id: Uuid,
    current: &[AgentBindingRow],
) -> bool {
    let current_by_key = current
        .iter()
        .map(|binding| {
            (
                (
                    binding.slot_id.as_str(),
                    binding.provider_profile_handle.as_str(),
                    binding.model_id.as_str(),
                ),
                binding,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let evidence = snapshot
        .child_bindings
        .iter()
        .filter(|binding| binding.installation_id == installation_id)
        .collect::<Vec<_>>();
    !evidence.is_empty()
        && evidence.iter().all(|evidence| {
            if evidence.installation_revision == 0
                || evidence.observation_revision == 0
                || validate_digest(&evidence.definition_digest, "child definition digest").is_err()
            {
                return false;
            }
            current_by_key
                .get(&(
                    evidence.binding.slot_id.as_str(),
                    evidence.binding.provider_profile_handle.as_str(),
                    evidence.binding.model_id.as_str(),
                ))
                .is_some_and(|actual| {
                    actual.binding_revision == evidence.binding.binding_revision
                        && actual.provenance_digest == evidence.binding.provenance_digest
                        && actual.hard_capability_verified
                        && evidence.binding.hard_capability_verified
                        && actual.is_default == evidence.binding.is_default
                })
        })
}
fn next_binding_revision(conn: &Connection, installation_id: Uuid, slot_id: &str) -> Result<u64> {
    let last: Option<i64> = conn
        .query_row(
            "SELECT MAX(binding_revision) FROM agent_model_bindings WHERE installation_id=?1 AND slot_id=?2",
            params![installation_id.to_string(), slot_id],
            |row| row.get(0),
        )
        .context("looking up next agent binding revision")?;
    match last {
        None => Ok(1),
        Some(value) => u64::try_from(value)
            .context("stored agent binding revision is negative")?
            .checked_add(1)
            .context("agent binding revision overflow"),
    }
}
fn binding_by_id(conn: &Connection, id: Uuid) -> Result<Option<AgentBindingRow>> {
    conn.query_row("SELECT binding_id,installation_id,definition_digest,slot_id,provider_profile_handle,model_id,provenance_payload,provenance_digest,hard_capability_verified,binding_revision,is_default,retired_at_unix_ms,created_at_unix_ms FROM agent_model_bindings WHERE binding_id=?1",[id.to_string()],decode_binding).optional().context("looking up agent model binding")
}
fn binding_receipt_by_key(
    conn: &Connection,
    installation_id: Uuid,
    definition_digest: &str,
    slot_id: &str,
    idempotency_key: &str,
) -> Result<Option<(String, AgentBindingRow)>> {
    conn.query_row(
        "SELECT r.request_fingerprint,b.binding_id,b.installation_id,b.definition_digest,b.slot_id,b.provider_profile_handle,b.model_id,b.provenance_payload,b.provenance_digest,b.hard_capability_verified,b.binding_revision,b.is_default,b.retired_at_unix_ms,b.created_at_unix_ms FROM agent_binding_receipts r JOIN agent_model_bindings b ON b.binding_id=r.binding_id WHERE r.installation_id=?1 AND r.definition_digest=?2 AND r.slot_id=?3 AND r.idempotency_key=?4",
        params![installation_id.to_string(), definition_digest, slot_id, idempotency_key],
        |row| Ok((row.get(0)?, decode_binding_offset(row, 1)?)),
    )
    .optional()
    .context("looking up agent binding receipt")
}
fn decode_binding(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentBindingRow> {
    decode_binding_offset(row, 0)
}
fn decode_binding_offset(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<AgentBindingRow> {
    Ok(AgentBindingRow {
        binding_id: parse_uuid(row.get::<_, String>(offset)?)?,
        installation_id: parse_uuid(row.get::<_, String>(offset + 1)?)?,
        definition_digest: row.get(offset + 2)?,
        slot_id: row.get(offset + 3)?,
        provider_profile_handle: row.get(offset + 4)?,
        model_id: row.get(offset + 5)?,
        provenance_payload: row.get(offset + 6)?,
        provenance_digest: row.get(offset + 7)?,
        hard_capability_verified: row.get::<_, i64>(offset + 8)? != 0,
        binding_revision: as_u64(row.get(offset + 9)?)?,
        is_default: row.get::<_, i64>(offset + 10)? != 0,
        retired_at_unix_ms: row.get(offset + 11)?,
        created_at_unix_ms: row.get(offset + 12)?,
    })
}
fn snapshot_for_session(
    conn: &Connection,
    session_id: Uuid,
) -> Result<Option<AgentProfileSnapshotRow>> {
    // Session-level callers mean the prepared/root profile, not an arbitrary
    // delegated child's immutable snapshot. Child executors always route via
    // `snapshot_by_id` and their durable `resolved_profile_snapshot_id`.
    // Prefer the preparation receipt when one exists; the stable fallback
    // preserves the root choice for ordinary/test sessions which predate that
    // receipt while allowing a session to contain distinct child profiles.
    conn.query_row(
        "SELECT s.snapshot_id, s.session_id, s.installation_id, s.schema_version,
                s.canonical_payload, s.canonical_payload_digest, s.definition_digest,
                s.binding_revision_map_payload, s.binding_revision_map_digest,
                s.created_at_unix_ms
           FROM agent_profile_snapshots s
           LEFT JOIN agent_session_preparations p
             ON p.snapshot_id = s.snapshot_id AND p.session_id = s.session_id
          WHERE s.session_id = ?1
          ORDER BY (p.snapshot_id IS NOT NULL) DESC, s.created_at_unix_ms ASC, s.snapshot_id ASC
          LIMIT 1",
        [session_id.to_string()],
        decode_snapshot,
    )
    .optional()
    .context("looking up root agent profile snapshot")
}
fn snapshot_by_id(conn: &Connection, id: Uuid) -> Result<Option<AgentProfileSnapshotRow>> {
    conn.query_row("SELECT snapshot_id,session_id,installation_id,schema_version,canonical_payload,canonical_payload_digest,definition_digest,binding_revision_map_payload,binding_revision_map_digest,created_at_unix_ms FROM agent_profile_snapshots WHERE snapshot_id=?1",[id.to_string()],decode_snapshot).optional().context("looking up agent profile snapshot")
}
fn decode_snapshot(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentProfileSnapshotRow> {
    Ok(AgentProfileSnapshotRow {
        snapshot_id: parse_uuid(row.get::<_, String>(0)?)?,
        session_id: parse_uuid(row.get::<_, String>(1)?)?,
        installation_id: parse_uuid(row.get::<_, String>(2)?)?,
        schema_version: as_u64(row.get(3)?)?,
        canonical_payload: row.get(4)?,
        canonical_payload_digest: row.get(5)?,
        definition_digest: row.get(6)?,
        binding_revision_map_payload: row.get(7)?,
        binding_revision_map_digest: row.get(8)?,
        created_at_unix_ms: row.get(9)?,
    })
}
fn preparation_by_key(
    conn: &Connection,
    session_id: Uuid,
    key: &str,
) -> Result<Option<(String, String, AgentProfileSnapshotRow)>> {
    conn.query_row("SELECT p.request_fingerprint,p.lifecycle_state,s.snapshot_id,s.session_id,s.installation_id,s.schema_version,s.canonical_payload,s.canonical_payload_digest,s.definition_digest,s.binding_revision_map_payload,s.binding_revision_map_digest,s.created_at_unix_ms FROM agent_session_preparations p JOIN agent_profile_snapshots s ON s.snapshot_id=p.snapshot_id WHERE p.session_id=?1 AND p.idempotency_key=?2",params![session_id.to_string(),key],|row|Ok((row.get(0)?,row.get(1)?,decode_snapshot_offset(row,2)?))).optional().context("looking up agent session preparation receipt")
}
fn decode_snapshot_offset(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<AgentProfileSnapshotRow> {
    Ok(AgentProfileSnapshotRow {
        snapshot_id: parse_uuid(row.get::<_, String>(offset)?)?,
        session_id: parse_uuid(row.get::<_, String>(offset + 1)?)?,
        installation_id: parse_uuid(row.get::<_, String>(offset + 2)?)?,
        schema_version: as_u64(row.get(offset + 3)?)?,
        canonical_payload: row.get(offset + 4)?,
        canonical_payload_digest: row.get(offset + 5)?,
        definition_digest: row.get(offset + 6)?,
        binding_revision_map_payload: row.get(offset + 7)?,
        binding_revision_map_digest: row.get(offset + 8)?,
        created_at_unix_ms: row.get(offset + 9)?,
    })
}
fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}
fn as_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}
fn decode_scope(value: &str) -> rusqlite::Result<AgentInstallationScope> {
    AgentInstallationScope::from_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            )),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> String {
        hex_digest(label.as_bytes())
    }

    fn installation(
        scope: AgentInstallationScope,
        workspace: Option<&str>,
    ) -> AgentInstallationInput {
        AgentInstallationInput {
            installation_id: Uuid::now_v7(),
            scope,
            canonical_workspace_id: workspace.map(str::to_string),
            source_agent_id: "builder".into(),
            source_identity: "daemon-local:builder".into(),
            source_revision: Some("v1".into()),
            source_digest: digest("definition-v1"),
            fetched_at_unix_ms: 10,
        }
    }

    fn binding(slot: &str, model: &str) -> AgentBindingInput {
        let payload = format!("canonical-provenance:{slot}:{model}").into_bytes();
        AgentBindingInput {
            slot_id: slot.into(),
            provider_profile_handle: "local-profile-opaque".into(),
            model_id: model.into(),
            provenance_digest: hex_digest(&payload),
            provenance_payload: payload,
            hard_capability_verified: true,
            is_default: true,
        }
    }

    fn alias(model: &str) -> ProviderAlias {
        ProviderAlias {
            provider_id: "provider".into(),
            model_id: model.into(),
        }
    }

    fn verification_selector() -> RedactedVerificationSelector {
        RedactedVerificationSelector {
            all_of: vec![RedactedVerificationPredicate::ToolId {
                tool_id: "read".into(),
            }],
            any_of: Vec::new(),
        }
    }

    fn verification_execution_plan() -> RedactedVerificationExecutionPlan {
        RedactedVerificationExecutionPlan {
            mode: "gate".into(),
            generators: vec![RedactedVerificationGenerator {
                slot: "primary".into(),
                recipe: RedactedVerificationRecipe::Inherit,
                max_turns: 1,
            }],
            on_budget_exceeded: "refuse".into(),
            on_adjudication_failure: "dispatch_original".into(),
        }
    }

    async fn prepared_fixture(db: &Db) -> (Uuid, Uuid, String) {
        let install = installation(AgentInstallationScope::Global, None);
        let installation_id = install.installation_id;
        let definition_digest = install.source_digest.clone();
        assert!(matches!(
            db.install_agent(install).await.unwrap(),
            InstallAgentOutcome::Installed(_)
        ));
        assert!(matches!(
            db.bind_agent_model(
                installation_id,
                definition_digest.clone(),
                None,
                "bind-key".into(),
                "bind-fingerprint".into(),
                binding("primary", "model-a"),
                11,
            )
            .await
            .unwrap(),
            BindAgentOutcome::Bound(_)
        ));
        // The preparation transaction owns creation of its session.  An
        // ordinary active session is intentionally not attachable.
        (Uuid::now_v7(), installation_id, definition_digest)
    }

    async fn installed_and_bound_fixture(db: &Db) -> (Uuid, String) {
        installed_and_bound_named_fixture(db, "builder").await
    }

    async fn installed_and_bound_named_fixture(db: &Db, name: &str) -> (Uuid, String) {
        let mut install = installation(AgentInstallationScope::Global, None);
        install.source_agent_id = name.to_string();
        install.source_identity = format!("daemon-local:{name}");
        let installation_id = install.installation_id;
        let definition_digest = install.source_digest.clone();
        assert!(matches!(
            db.install_agent(install).await.unwrap(),
            InstallAgentOutcome::Installed(_)
        ));
        assert!(matches!(
            db.bind_agent_model(
                installation_id,
                definition_digest.clone(),
                None,
                "initial-bind".into(),
                "initial-fingerprint".into(),
                binding("primary", "model-a"),
                11,
            )
            .await
            .unwrap(),
            BindAgentOutcome::Bound(_)
        ));
        (installation_id, definition_digest)
    }

    fn prepare_input(
        session_id: Uuid,
        installation_id: Uuid,
        definition_digest: String,
    ) -> PrepareAgentSessionInput {
        let snapshot = serde_json::to_vec(&RedactedAgentProfileSnapshot {
            agent_id: "authored/builder".into(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: vec![RedactedRecommendation {
                recommendation_id: "stable".into(),
                slot_id: "primary".into(),
                canonical_upstream_identity: "provider/model-a".into(),
                author_label: Some("Preferred builder".into()),
                rationale: Some("Selected by the author".into()),
                provider_aliases: vec![alias("model-a")],
                exact_provider_alias: Some(alias("model-a")),
                author_suggested: true,
                alias_collision_rank: 0,
            }],
            question_policy: RedactedQuestionPolicy::Active {
                auto_answer_disabled: true,
                prohibited_classes: vec!["destructive".into()],
                required_decision_timeout_ms: 1,
                host_resource_ceiling_ms: 1,
                resolver_order: QuestionResolverOrder::WarmParentThenUtility,
                resolver_slot: "primary".into(),
            },
            verification_regions: vec![RedactedVerificationRegion {
                source_rule_id: "r1".into(),
                source_selector: verification_selector(),
                excluded_prior_selectors: Vec::new(),
                session_selector: None,
                enabled_intersection_mask: vec!["all:tool_id:read".into()],
                enabled: true,
                explicit_off_remainder_mask: vec![],
                whole_region_off: false,
                whole_region_off_mask: vec![],
                effective_action: VerificationEffectiveAction::Verify,
                adjudicator_slot: Some("primary".into()),
                count_ceiling: Some(1),
                token_ceiling: Some(1),
                cost_ceiling_micros: Some(1),
                max_collection_duration_ms: Some(12),
                execution_plan: Some(verification_execution_plan()),
            }],
            bindings: vec![RedactedBindingEvidence {
                slot_id: "primary".into(),
                binding_revision: 1,
                provider_profile_handle: "local-profile-opaque".into(),
                model_id: "model-a".into(),
                selected_provider_alias: alias("model-a"),
                provenance_digest: hex_digest(b"canonical-provenance:primary:model-a"),
                hard_capability_verified: true,
                is_default: true,
            }],
            child_bindings: Vec::new(),
        })
        .unwrap();
        let revision_map = serde_json::to_vec(&AgentBindingRevisionMap {
            bindings: vec![AgentBindingRevision {
                slot_id: "primary".into(),
                provider_profile_handle: "local-profile-opaque".into(),
                model_id: "test-model".into(),
                binding_revision: 1,
            }],
        })
        .unwrap();
        PrepareAgentSessionInput {
            session_id,
            session_create: AgentSessionCreateInput {
                project_id: "project".into(),
                project_root: "/workspace".into(),
                active_agent: "builder".into(),
                started_at_unix_ms: 12_000,
                last_active_at_unix_ms: 12_000,
            },
            existing_session_claim_token: None,
            idempotency_key: "prepare-key".into(),
            request_fingerprint: "prepare-fingerprint".into(),
            installation_id,
            expected_installation_revision: 1,
            expected_observation_revision: 1,
            expected_definition_digest: definition_digest,
            expected_bindings: vec![AgentBindingExpectation {
                slot_id: "primary".into(),
                provider_profile_handle: "local-profile-opaque".into(),
                model_id: "test-model".into(),
                expected_binding_revision: 1,
            }],
            expected_children: Vec::new(),
            snapshot_schema_version: 1,
            canonical_snapshot_digest: hex_digest(&snapshot),
            canonical_snapshot_payload: snapshot,
            binding_revision_map_digest: hex_digest(&revision_map),
            binding_revision_map_payload: revision_map,
            now_unix_ms: 12,
        }
    }

    fn package_child_input(
        parent: &AgentInstallationRow,
        parent_observation: &AgentObservationRow,
        child: AgentInstallationInput,
        model: &str,
    ) -> MaterializePackageChildInput {
        MaterializePackageChildInput {
            parent_installation_id: parent.installation_id,
            expected_parent_installation_revision: parent.installation_revision,
            expected_parent_observation_revision: parent_observation.observation_revision,
            expected_parent_definition_digest: parent.source_digest.clone(),
            child_source_identity_guard: parent.installation_id.to_string(),
            child,
            slot_bindings: vec![PackageChildSlotBindingInput {
                idempotency_key: format!("package-child-{model}"),
                request_fingerprint: format!("package-child-{model}"),
                bindings: vec![binding("primary", model)],
            }],
            now_unix_ms: 20,
        }
    }

    #[tokio::test]
    async fn package_child_materialization_cas_precedes_all_child_mutations() {
        let db = Db::open_in_memory().unwrap();
        let parent_input = installation(AgentInstallationScope::Global, None);
        let parent = match db.install_agent(parent_input).await.unwrap() {
            InstallAgentOutcome::Installed(row) => row,
            outcome => panic!("expected parent install, got {outcome:?}"),
        };
        let parent_observation = db
            .agent_observation(parent.installation_id)
            .await
            .unwrap()
            .unwrap();
        let mut child = installation(AgentInstallationScope::Global, None);
        child.installation_id = Uuid::now_v7();
        child.source_agent_id = "builder/helper".into();
        child.source_identity = format!("package-child:{}:helper", parent.installation_id);
        child.source_digest = digest("child-v1");
        let installed = db
            .materialize_package_child(package_child_input(
                &parent,
                &parent_observation,
                child.clone(),
                "model-a",
            ))
            .await
            .unwrap();
        assert_eq!(installed.source_digest, digest("child-v1"));

        assert!(matches!(
            db.observe_agent_definition(
                parent.installation_id,
                digest("changed-whole-package"),
                21,
            )
            .await
            .unwrap(),
            ObserveAgentOutcome::RebindRequired(_)
        ));
        child.source_digest = digest("child-v2");
        assert!(
            db.materialize_package_child(package_child_input(
                &parent,
                &parent_observation,
                child,
                "model-b",
            ))
            .await
            .is_err(),
            "a changed parent package must fail before replacing or rebinding its child"
        );
        let unchanged = db
            .agent_installation(installed.installation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.source_digest, digest("child-v1"));
        let binding = db
            .current_agent_binding(
                installed.installation_id,
                digest("child-v1"),
                "primary".into(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(binding.model_id, "model-a");
    }

    #[tokio::test]
    async fn package_child_batch_rejects_later_invalid_child_without_partial_state() {
        let db = Db::open_in_memory().unwrap();
        let parent_input = installation(AgentInstallationScope::Global, None);
        let parent = match db.install_agent(parent_input).await.unwrap() {
            InstallAgentOutcome::Installed(row) => row,
            outcome => panic!("expected parent install, got {outcome:?}"),
        };
        let parent_observation = db
            .agent_observation(parent.installation_id)
            .await
            .unwrap()
            .unwrap();

        let mut first = installation(AgentInstallationScope::Global, None);
        first.installation_id = Uuid::now_v7();
        first.source_agent_id = "builder/first".into();
        first.source_identity = format!("package-child:{}:first", parent.installation_id);
        first.source_digest = digest("first");
        let first_id = first.installation_id;

        let mut second = installation(AgentInstallationScope::Global, None);
        second.installation_id = Uuid::now_v7();
        second.source_agent_id = "builder/second".into();
        second.source_identity = format!("package-child:{}:second", parent.installation_id);
        second.source_digest = digest("second");
        let mut second_input = package_child_input(&parent, &parent_observation, second, "model-b");
        second_input.slot_bindings.clear();

        let result = db
            .materialize_package_children(vec![
                package_child_input(&parent, &parent_observation, first, "model-a"),
                second_input,
            ])
            .await;
        assert!(
            result.is_err(),
            "an invalid later child must reject the complete package batch"
        );
        assert!(
            db.agent_installation(first_id).await.unwrap().is_none(),
            "the earlier valid child must not persist from a rejected batch"
        );
    }

    #[tokio::test]
    async fn agent_installation_db_scope_isolation_and_no_credential_columns() {
        let db = Db::open_in_memory().unwrap();
        let global = installation(AgentInstallationScope::Global, None);
        let private = installation(
            AgentInstallationScope::WorkspacePrivate,
            Some("workspace:a"),
        );
        let shared = installation(AgentInstallationScope::WorkspaceShared, Some("workspace:a"));
        let global_id = global.installation_id;
        let private_id = private.installation_id;
        let shared_id = shared.installation_id;
        assert!(matches!(
            db.install_agent(global).await.unwrap(),
            InstallAgentOutcome::Installed(_)
        ));
        assert!(matches!(
            db.install_agent(private).await.unwrap(),
            InstallAgentOutcome::Installed(_)
        ));
        assert!(matches!(
            db.install_agent(shared).await.unwrap(),
            InstallAgentOutcome::Installed(_)
        ));
        assert_ne!(global_id, private_id);
        assert_ne!(private_id, shared_id);
        assert_eq!(
            db.agent_installation_by_source(
                AgentInstallationScope::Global,
                None,
                "builder".into(),
            )
            .await
            .unwrap()
            .map(|row| row.installation_id),
            Some(global_id)
        );
        assert_eq!(
            db.list_agent_installations(
                AgentInstallationScope::WorkspacePrivate,
                Some("workspace:a".into()),
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.installation_id)
            .collect::<Vec<_>>(),
            vec![private_id]
        );
        assert!(matches!(
            db.install_agent(installation(
                AgentInstallationScope::WorkspacePrivate,
                Some("workspace:b"),
            ))
            .await
            .unwrap(),
            InstallAgentOutcome::Installed(_)
        ));
        assert!(
            db.install_agent(AgentInstallationInput {
                canonical_workspace_id: Some("workspace:a".into()),
                ..installation(AgentInstallationScope::Global, None)
            })
            .await
            .is_err()
        );
        let schema = include_str!("migrations/0001_initial.sql");
        let section = schema
            .split("-- ---- versioned agent installations")
            .nth(1)
            .unwrap();
        assert!(!section.contains("api_key"));
        assert!(!section.contains("secret_bytes"));
    }

    #[tokio::test]
    async fn agent_installation_daemon_replacement_compensation_restores_exact_prior_state_once() {
        let db = Db::open_in_memory().unwrap();
        let original = installation(AgentInstallationScope::Global, None);
        let installation_id = original.installation_id;
        let original_digest = original.source_digest.clone();
        assert!(matches!(
            db.install_agent(original.clone()).await.unwrap(),
            InstallAgentOutcome::Installed(_)
        ));
        let original_binding = match db
            .bind_agent_model(
                installation_id,
                original_digest.clone(),
                None,
                "initial-binding".into(),
                "initial-fingerprint".into(),
                binding("primary", "model-a"),
                11,
            )
            .await
            .unwrap()
        {
            BindAgentOutcome::Bound(binding) => binding,
            outcome => panic!("expected initial binding, got {outcome:?}"),
        };
        let replacement = AgentInstallationInput {
            installation_id: Uuid::now_v7(),
            source_identity: "daemon-local:builder-v2".into(),
            source_revision: Some("v2".into()),
            source_digest: digest("definition-v2"),
            fetched_at_unix_ms: 22,
            ..original.clone()
        };
        let receipt = db
            .agent_replacement_compensation_receipt(installation_id, replacement.clone(), 22)
            .await
            .unwrap();
        assert!(matches!(
            db.replace_agent(replacement, 22).await.unwrap(),
            InstallAgentOutcome::Installed(_)
        ));
        assert!(
            db.current_agent_binding(installation_id, original_digest.clone(), "primary".into())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db.compensate_agent_replacement(receipt.clone())
                .await
                .unwrap(),
            CompensateAgentReplacementOutcome::Restored
        );
        assert_eq!(
            db.compensate_agent_replacement(receipt.clone())
                .await
                .unwrap(),
            CompensateAgentReplacementOutcome::AlreadyRestored
        );
        assert!(db.agent_replacement_is_compensated(receipt).await.unwrap());
        let restored = db
            .agent_installation(installation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.source_identity, original.source_identity);
        assert_eq!(restored.source_revision, original.source_revision);
        assert_eq!(restored.source_digest, original_digest);
        let restored_binding = db
            .current_agent_binding(installation_id, original.source_digest, "primary".into())
            .await
            .unwrap()
            .expect("prior binding must be restored");
        assert_eq!(restored_binding.binding_id, original_binding.binding_id);
    }

    #[tokio::test]
    async fn agent_installation_db_prepare_atomically_creates_and_claims_missing_session() {
        let db = Db::open_in_memory().unwrap();
        let (installation_id, definition_digest) = installed_and_bound_fixture(&db).await;
        let session_id = Uuid::now_v7();
        let input = prepare_input(session_id, installation_id, definition_digest);
        let prepared = match db.prepare_agent_session(input.clone()).await.unwrap() {
            PrepareAgentSessionOutcome::Prepared(snapshot) => snapshot,
            outcome => panic!("expected prepared missing-session claim, got {outcome:?}"),
        };
        assert_eq!(prepared.session_id, session_id);
        let session = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT project_id,project_root,active_agent,lifecycle,ended_at_unix_ms FROM sessions WHERE session_id=?1",
                    [session_id.to_string()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, Option<i64>>(4)?)),
                )
                .optional()
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(
            session,
            Some((
                "project".to_string(),
                "/workspace".to_string(),
                "builder".to_string(),
                "active".to_string(),
                None,
            ))
        );
        assert!(matches!(
            db.prepare_agent_session(input).await.unwrap(),
            PrepareAgentSessionOutcome::AlreadyPrepared(snapshot) if snapshot == prepared
        ));
    }

    #[tokio::test]
    async fn agent_installation_db_digest_change_blocks_prepare_until_rebind() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, installation_id, definition_digest) = prepared_fixture(&db).await;
        let changed = digest("definition-v2");
        assert!(matches!(
            db.observe_agent_definition(installation_id, changed.clone(), 20)
                .await
                .unwrap(),
            ObserveAgentOutcome::RebindRequired(_)
        ));
        let mut input = prepare_input(session_id, installation_id, definition_digest);
        input.idempotency_key = "changed-key".into();
        assert!(matches!(
            db.prepare_agent_session(input).await.unwrap(),
            PrepareAgentSessionOutcome::RebindRequired
        ));
        assert!(matches!(
            db.rebind_agent(AgentRebindInput {
                installation_id,
                expected_observation_revision: 2,
                expected_observed_digest: changed.clone(),
                new_observed_digest: changed,
                bindings: vec![binding("primary", "model-b")],
                now_unix_ms: 21,
            })
            .await
            .unwrap(),
            RebindAgentOutcome::Rebound(_)
        ));
    }

    #[tokio::test]
    async fn agent_installation_db_prepare_replay_fingerprint_and_single_start_claim() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, installation_id, definition_digest) = prepared_fixture(&db).await;
        let input = prepare_input(session_id, installation_id, definition_digest);
        assert!(matches!(
            db.prepare_agent_session(input.clone()).await.unwrap(),
            PrepareAgentSessionOutcome::Prepared(_)
        ));
        assert!(matches!(
            db.prepare_agent_session(input.clone()).await.unwrap(),
            PrepareAgentSessionOutcome::AlreadyPrepared(_)
        ));
        let mut cross = input;
        cross.request_fingerprint = "other".into();
        assert!(matches!(
            db.prepare_agent_session(cross).await.unwrap(),
            PrepareAgentSessionOutcome::Conflict
        ));
        let (first, second) = tokio::join!(
            db.start_prepared_agent_session(session_id, "prepare-key".into(), 30),
            db.start_prepared_agent_session(session_id, "prepare-key".into(), 30),
        );
        let outcomes = [first.unwrap(), second.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, StartAgentSessionOutcome::Started(_)))
                .count(),
            1
        );
        assert!(outcomes.iter().all(|outcome| matches!(
            outcome,
            StartAgentSessionOutcome::Started(_) | StartAgentSessionOutcome::AlreadyStarted(_)
        )));
    }

    #[tokio::test]
    async fn agent_installation_db_prepare_cross_fingerprint_race_is_atomic() {
        let db = Db::open_in_memory().unwrap();
        let (installation_id, definition_digest) = installed_and_bound_fixture(&db).await;
        let session_id = Uuid::now_v7();
        let first = prepare_input(session_id, installation_id, definition_digest.clone());
        let mut second = prepare_input(session_id, installation_id, definition_digest);
        second.request_fingerprint = "cross-fingerprint".into();
        let (left, right) = tokio::join!(
            db.prepare_agent_session(first),
            db.prepare_agent_session(second),
        );
        let outcomes = [left.unwrap(), right.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PrepareAgentSessionOutcome::Prepared(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PrepareAgentSessionOutcome::Conflict))
                .count(),
            1
        );
        assert!(
            db.agent_profile_snapshot(session_id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn agent_installation_db_prepare_never_attaches_to_an_ordinary_active_session() {
        let db = Db::open_in_memory().unwrap();
        let (installation_id, definition_digest) = installed_and_bound_fixture(&db).await;
        let ordinary = db
            .create_session("project", "/workspace", "builder")
            .await
            .unwrap();
        let input = prepare_input(ordinary.session_id, installation_id, definition_digest);
        assert!(matches!(
            db.prepare_agent_session(input).await.unwrap(),
            PrepareAgentSessionOutcome::Conflict
        ));
        assert!(
            db.agent_profile_snapshot(ordinary.session_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn agent_installation_db_prepare_claims_only_marked_idle_existing_session() {
        let db = Db::open_in_memory().unwrap();
        let (installation_id, definition_digest) = installed_and_bound_fixture(&db).await;
        let existing = db
            .create_session("project", "/workspace", "builder")
            .await
            .unwrap();
        let claim_token = Uuid::now_v7();
        assert!(matches!(
            db.register_agent_session_preparation(existing.session_id, claim_token, 20)
                .await
                .unwrap(),
            RegisterAgentSessionPreparationOutcome::Eligible
        ));
        assert!(matches!(
            db.register_agent_session_preparation(existing.session_id, claim_token, 21)
                .await
                .unwrap(),
            RegisterAgentSessionPreparationOutcome::AlreadyEligible
        ));
        let mut input = prepare_input(existing.session_id, installation_id, definition_digest);
        input.existing_session_claim_token = Some(claim_token);
        assert!(matches!(
            db.prepare_agent_session(input.clone()).await.unwrap(),
            PrepareAgentSessionOutcome::Prepared(_)
        ));
        let prepared_model: (Option<String>, Option<String>) = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT provider,model FROM sessions WHERE session_id=?1",
                    [existing.session_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(
            prepared_model,
            (Some("local-profile-opaque".into()), Some("model-a".into()))
        );
        db.transaction(move |conn| {
            conn.execute(
                "UPDATE sessions SET provider='resume-provider',model='resume-model' WHERE session_id=?1",
                [existing.session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(matches!(
            db.prepare_agent_session(input).await.unwrap(),
            PrepareAgentSessionOutcome::AlreadyPrepared(_)
        ));
        let resumed_model: (Option<String>, Option<String>) = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT provider,model FROM sessions WHERE session_id=?1",
                    [existing.session_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(
            resumed_model,
            (Some("resume-provider".into()), Some("resume-model".into()))
        );
        let created_session: i64 = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT created_session FROM agent_session_preparations WHERE session_id=?1",
                    [existing.session_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(created_session, 0);
        let mut wrong_token = prepare_input(existing.session_id, installation_id, digest("unused"));
        wrong_token.existing_session_claim_token = Some(Uuid::now_v7());
        wrong_token.idempotency_key = "other-key".into();
        assert!(matches!(
            db.prepare_agent_session(wrong_token).await.unwrap(),
            PrepareAgentSessionOutcome::Conflict
        ));

        let busy = db
            .create_session("project", "/workspace", "builder")
            .await
            .unwrap();
        db.transaction(move |conn| {
            conn.execute(
                "UPDATE sessions SET last_active_at_unix_ms=started_at_unix_ms+1 WHERE session_id=?1",
                [busy.session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(matches!(
            db.register_agent_session_preparation(busy.session_id, Uuid::now_v7(), 22)
                .await
                .unwrap(),
            RegisterAgentSessionPreparationOutcome::Conflict
        ));
    }

    #[tokio::test]
    async fn agent_installation_db_prepare_lifecycle_and_staleness_outcomes() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, installation_id, definition_digest) = prepared_fixture(&db).await;
        let input = prepare_input(session_id, installation_id, definition_digest.clone());
        assert!(matches!(
            db.prepare_agent_session(input.clone()).await.unwrap(),
            PrepareAgentSessionOutcome::Prepared(_)
        ));
        assert!(matches!(
            db.start_prepared_agent_session(session_id, "prepare-key".into(), 30)
                .await
                .unwrap(),
            StartAgentSessionOutcome::Started(_)
        ));
        assert!(matches!(
            db.prepare_agent_session(input.clone()).await.unwrap(),
            PrepareAgentSessionOutcome::AlreadyStarted(_)
        ));
        assert!(matches!(
            db.terminal_agent_session(session_id, "prepare-key".into(), 31)
                .await
                .unwrap(),
            StartAgentSessionOutcome::Terminal(_)
        ));
        assert!(matches!(
            db.prepare_agent_session(input).await.unwrap(),
            PrepareAgentSessionOutcome::Terminal(_)
        ));

        let stale_session = Uuid::now_v7();
        let stale = prepare_input(stale_session, installation_id, definition_digest.clone());
        assert!(matches!(
            db.observe_agent_definition(installation_id, digest("changed-definition"), 40)
                .await
                .unwrap(),
            ObserveAgentOutcome::RebindRequired(_)
        ));
        assert!(matches!(
            db.prepare_agent_session(stale).await.unwrap(),
            PrepareAgentSessionOutcome::RebindRequired
        ));

        assert!(matches!(
            db.rebind_agent(AgentRebindInput {
                installation_id,
                expected_observation_revision: 2,
                expected_observed_digest: digest("changed-definition"),
                new_observed_digest: digest("changed-definition"),
                bindings: vec![binding("primary", "model-b")],
                now_unix_ms: 41,
            })
            .await
            .unwrap(),
            RebindAgentOutcome::Rebound(_)
        ));
        let conflict_session = Uuid::now_v7();
        let mut conflict = prepare_input(
            conflict_session,
            installation_id,
            digest("changed-definition"),
        );
        conflict.expected_observation_revision = 99;
        conflict.expected_bindings[0].expected_binding_revision = 2;
        let map = AgentBindingRevisionMap {
            bindings: vec![AgentBindingRevision {
                slot_id: "primary".into(),
                provider_profile_handle: "profile".into(),
                model_id: "test-model".into(),
                binding_revision: 2,
            }],
        };
        conflict.binding_revision_map_payload = serde_json::to_vec(&map).unwrap();
        conflict.binding_revision_map_digest = hex_digest(&conflict.binding_revision_map_payload);
        let snapshot = RedactedAgentProfileSnapshot {
            agent_id: "authored/builder".into(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: vec![RedactedRecommendation {
                recommendation_id: "stable".into(),
                slot_id: "primary".into(),
                canonical_upstream_identity: "provider/model-b".into(),
                author_label: Some("Preferred builder".into()),
                rationale: Some("Selected by the author".into()),
                provider_aliases: vec![alias("model-b")],
                exact_provider_alias: Some(alias("model-b")),
                author_suggested: true,
                alias_collision_rank: 0,
            }],
            question_policy: RedactedQuestionPolicy::Active {
                auto_answer_disabled: true,
                prohibited_classes: vec![],
                required_decision_timeout_ms: 1,
                host_resource_ceiling_ms: 1,
                resolver_order: QuestionResolverOrder::WarmParentThenUtility,
                resolver_slot: "primary".into(),
            },
            verification_regions: vec![RedactedVerificationRegion {
                source_rule_id: "rule".into(),
                source_selector: verification_selector(),
                excluded_prior_selectors: Vec::new(),
                session_selector: None,
                enabled_intersection_mask: vec!["all:tool_id:read".into()],
                enabled: true,
                explicit_off_remainder_mask: vec![],
                whole_region_off: false,
                whole_region_off_mask: vec![],
                effective_action: VerificationEffectiveAction::Verify,
                adjudicator_slot: Some("primary".into()),
                count_ceiling: Some(1),
                token_ceiling: Some(1),
                cost_ceiling_micros: Some(1),
                max_collection_duration_ms: Some(1),
                execution_plan: Some(verification_execution_plan()),
            }],
            bindings: vec![RedactedBindingEvidence {
                slot_id: "primary".into(),
                binding_revision: 2,
                provider_profile_handle: "local-profile-opaque".into(),
                model_id: "model-b".into(),
                selected_provider_alias: alias("model-b"),
                provenance_digest: hex_digest(b"canonical-provenance:primary:model-b"),
                hard_capability_verified: true,
                is_default: true,
            }],
            child_bindings: Vec::new(),
        };
        conflict.canonical_snapshot_payload = serde_json::to_vec(&snapshot).unwrap();
        conflict.canonical_snapshot_digest = hex_digest(&conflict.canonical_snapshot_payload);
        assert!(matches!(
            db.prepare_agent_session(conflict).await.unwrap(),
            PrepareAgentSessionOutcome::Conflict
        ));
    }

    #[tokio::test]
    async fn agent_installation_db_prepare_conflict_and_deleted_outcomes() {
        let db = Db::open_in_memory().unwrap();
        let (installation_id, definition_digest) = installed_and_bound_fixture(&db).await;
        let session_id = Uuid::now_v7();
        let mut conflict = prepare_input(session_id, installation_id, definition_digest.clone());
        conflict.expected_installation_revision = 2;
        assert!(matches!(
            db.prepare_agent_session(conflict).await.unwrap(),
            PrepareAgentSessionOutcome::Conflict
        ));
        assert!(
            db.agent_profile_snapshot(session_id)
                .await
                .unwrap()
                .is_none()
        );

        let source_session = Uuid::now_v7();
        assert!(matches!(
            db.prepare_agent_session(prepare_input(
                source_session,
                installation_id,
                definition_digest.clone(),
            ))
            .await
            .unwrap(),
            PrepareAgentSessionOutcome::Prepared(_)
        ));
        assert!(matches!(
            db.delete_agent_installation(installation_id, 50)
                .await
                .unwrap(),
            DeleteAgentInstallationOutcome::Tombstoned
        ));
        assert!(matches!(
            db.prepare_agent_session(prepare_input(
                Uuid::now_v7(),
                installation_id,
                definition_digest,
            ))
            .await
            .unwrap(),
            PrepareAgentSessionOutcome::Deleted
        ));
    }

    #[tokio::test]
    async fn agent_installation_db_bind_rebind_prepare_race_never_mixes_snapshot() {
        let db = Db::open_in_memory().unwrap();
        let (installation_id, definition_digest) = installed_and_bound_fixture(&db).await;
        let session_id = Uuid::now_v7();
        let prepare = prepare_input(session_id, installation_id, definition_digest.clone());
        let (bind_result, prepare_result) = tokio::join!(
            db.bind_agent_model(
                installation_id,
                definition_digest.clone(),
                Some(1),
                "replacement-bind".into(),
                "replacement-fingerprint".into(),
                binding("primary", "model-b"),
                30,
            ),
            db.prepare_agent_session(prepare),
        );
        assert!(matches!(
            bind_result.unwrap(),
            BindAgentOutcome::Bound(_) | BindAgentOutcome::Conflict
        ));
        match prepare_result.unwrap() {
            PrepareAgentSessionOutcome::Prepared(snapshot) => {
                let decoded =
                    decode_canonical_snapshot(&snapshot.canonical_payload, "snapshot").unwrap();
                assert_eq!(decoded.bindings.len(), 1);
                assert_eq!(decoded.bindings[0].model_id, "model-a");
                assert_eq!(decoded.bindings[0].binding_revision, 1);
            }
            PrepareAgentSessionOutcome::Conflict => {
                assert!(
                    db.agent_profile_snapshot(session_id)
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            unexpected => panic!("unexpected prepare/bind race result {unexpected:?}"),
        }

        assert!(matches!(
            db.observe_agent_definition(installation_id, digest("definition-v2"), 40)
                .await
                .unwrap(),
            ObserveAgentOutcome::RebindRequired(_)
        ));
        let rebind = AgentRebindInput {
            installation_id,
            expected_observation_revision: 2,
            expected_observed_digest: digest("definition-v2"),
            new_observed_digest: digest("definition-v2"),
            bindings: vec![binding("primary", "model-c")],
            now_unix_ms: 41,
        };
        let stale_prepare = prepare_input(Uuid::now_v7(), installation_id, definition_digest);
        let (rebind_result, stale_prepare_result) = tokio::join!(
            db.rebind_agent(rebind),
            db.prepare_agent_session(stale_prepare)
        );
        assert!(matches!(
            rebind_result.unwrap(),
            RebindAgentOutcome::Rebound(_) | RebindAgentOutcome::Conflict
        ));
        assert!(matches!(
            stale_prepare_result.unwrap(),
            PrepareAgentSessionOutcome::RebindRequired | PrepareAgentSessionOutcome::Conflict
        ));
    }

    #[tokio::test]
    async fn agent_session_prepare_rejects_child_binding_generation_changed_before_cas() {
        let db = Db::open_in_memory().unwrap();
        let (root_id, root_digest) = installed_and_bound_fixture(&db).await;
        let (child_id, child_digest) = installed_and_bound_named_fixture(&db, "child-cas").await;
        let child_installation = db.agent_installation(child_id).await.unwrap().unwrap();
        let child_observation = db.agent_observation(child_id).await.unwrap().unwrap();
        let child_binding = db
            .current_agent_bindings(child_id, child_digest.clone())
            .await
            .unwrap()
            .pop()
            .unwrap();
        let mut input = prepare_input(Uuid::now_v7(), root_id, root_digest);
        input.expected_children = vec![AgentChildBindingSetExpectation {
            installation_id: child_id,
            expected_installation_revision: child_installation.installation_revision,
            expected_observation_revision: child_observation.observation_revision,
            expected_definition_digest: child_digest.clone(),
            expected_bindings: vec![AgentBindingExpectation {
                slot_id: child_binding.slot_id.clone(),
                provider_profile_handle: child_binding.provider_profile_handle.clone(),
                model_id: child_binding.model_id.clone(),
                expected_binding_revision: child_binding.binding_revision,
            }],
        }];
        let mut snapshot = decode_canonical_snapshot(
            &input.canonical_snapshot_payload,
            "child CAS fixture snapshot",
        )
        .unwrap();
        snapshot.effective_delegation = Some(RedactedEffectiveDelegation {
            allowed_children: vec![RedactedAllowedChild::LocalInstallation {
                installation_id: child_id,
                execution_kind: AgentExecutionKind::Coding,
            }],
            max_descendant_depth: 1,
            max_concurrent_children: 1,
            targets: vec![DelegationTarget::SameRoot],
            computer_delegation_enabled: false,
        });
        snapshot.child_bindings = vec![RedactedChildBindingEvidence {
            installation_id: child_id,
            installation_revision: child_installation.installation_revision,
            observation_revision: child_observation.observation_revision,
            definition_digest: child_digest.clone(),
            binding: RedactedBindingEvidence {
                slot_id: child_binding.slot_id,
                binding_revision: child_binding.binding_revision,
                provider_profile_handle: child_binding.provider_profile_handle,
                model_id: child_binding.model_id.clone(),
                selected_provider_alias: alias(&child_binding.model_id),
                provenance_digest: child_binding.provenance_digest,
                hard_capability_verified: child_binding.hard_capability_verified,
                is_default: child_binding.is_default,
            },
            slot_requirements: RedactedModelSlotRequirements {
                min_context_tokens: 1,
                required_capabilities: vec!["text_generation".into()],
                locality: "any".into(),
                allowed_models: Vec::new(),
            },
        }];
        input.canonical_snapshot_payload = serde_json::to_vec(&snapshot).unwrap();
        input.canonical_snapshot_digest = hex_digest(&input.canonical_snapshot_payload);

        assert!(matches!(
            db.bind_agent_model(
                child_id,
                child_digest,
                Some(1),
                "advance-child".into(),
                "advance-child-fingerprint".into(),
                binding("primary", "model-b"),
                13,
            )
            .await
            .unwrap(),
            BindAgentOutcome::Bound(_)
        ));
        assert!(matches!(
            db.prepare_agent_session(input).await.unwrap(),
            PrepareAgentSessionOutcome::Conflict
        ));
    }

    #[tokio::test]
    async fn agent_installation_db_snapshot_round_trips_profile_semantics_exactly() {
        let db = Db::open_in_memory().unwrap();
        let (installation_id, definition_digest) = installed_and_bound_fixture(&db).await;
        let (local_child_installation_id, child_definition_digest) =
            installed_and_bound_named_fixture(&db, "child").await;
        let child_installation = db
            .agent_installation(local_child_installation_id)
            .await
            .unwrap()
            .unwrap();
        let child_observation = db
            .agent_observation(local_child_installation_id)
            .await
            .unwrap()
            .unwrap();
        let child_binding = db
            .current_agent_bindings(local_child_installation_id, child_definition_digest.clone())
            .await
            .unwrap()
            .pop()
            .unwrap();
        let child_expectation = AgentChildBindingSetExpectation {
            installation_id: local_child_installation_id,
            expected_installation_revision: child_installation.installation_revision,
            expected_observation_revision: child_observation.observation_revision,
            expected_definition_digest: child_definition_digest,
            expected_bindings: vec![AgentBindingExpectation {
                slot_id: child_binding.slot_id.clone(),
                provider_profile_handle: child_binding.provider_profile_handle.clone(),
                model_id: child_binding.model_id.clone(),
                expected_binding_revision: child_binding.binding_revision,
            }],
        };
        let session_id = Uuid::now_v7();
        let mut input = prepare_input(session_id, installation_id, definition_digest);
        input.expected_children = vec![child_expectation.clone()];
        let local_child = RedactedAllowedChild::LocalInstallation {
            installation_id: local_child_installation_id,
            execution_kind: AgentExecutionKind::Coding,
        };
        let profile = RedactedAgentProfileSnapshot {
            agent_id: "authored/builder".into(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: Some(RedactedEffectiveDelegation {
                allowed_children: vec![local_child.clone()],
                max_descendant_depth: 1,
                max_concurrent_children: 1,
                targets: vec![DelegationTarget::SameRoot],
                computer_delegation_enabled: false,
            }),
            recommendations: vec![
                RedactedRecommendation {
                    recommendation_id: "author-primary".into(),
                    slot_id: "primary".into(),
                    canonical_upstream_identity: "upstream/openai:gpt-5".into(),
                    author_label: Some("Primary".into()),
                    rationale: Some("Author preferred primary model".into()),
                    provider_aliases: vec![alias("fast"), alias("model-a")],
                    exact_provider_alias: Some(alias("model-a")),
                    author_suggested: true,
                    alias_collision_rank: 0,
                },
                RedactedRecommendation {
                    recommendation_id: "unsuggested-compatible".into(),
                    slot_id: "primary".into(),
                    canonical_upstream_identity: "upstream/other:exact".into(),
                    author_label: Some("Compatible alternative".into()),
                    rationale: Some(
                        "Hard-capability compatible without an author suggestion".into(),
                    ),
                    provider_aliases: vec![alias("exact")],
                    exact_provider_alias: None,
                    author_suggested: false,
                    alias_collision_rank: 1,
                },
            ],
            question_policy: RedactedQuestionPolicy::Active {
                auto_answer_disabled: true,
                prohibited_classes: vec!["network".into(), "secrets".into()],
                required_decision_timeout_ms: 50,
                host_resource_ceiling_ms: 60,
                resolver_order: QuestionResolverOrder::WarmParentThenUtility,
                resolver_slot: "primary".into(),
            },
            verification_regions: vec![
                RedactedVerificationRegion {
                    source_rule_id: "source-allow".into(),
                    source_selector: verification_selector(),
                    excluded_prior_selectors: Vec::new(),
                    session_selector: None,
                    enabled_intersection_mask: vec!["all:tool_id:read".into()],
                    enabled: true,
                    explicit_off_remainder_mask: vec![],
                    whole_region_off: false,
                    whole_region_off_mask: vec![],
                    effective_action: VerificationEffectiveAction::Verify,
                    adjudicator_slot: Some("primary".into()),
                    count_ceiling: Some(2),
                    token_ceiling: Some(100),
                    cost_ceiling_micros: Some(42),
                    max_collection_duration_ms: Some(999),
                    execution_plan: Some(verification_execution_plan()),
                },
                RedactedVerificationRegion {
                    source_rule_id: "source-deny".into(),
                    source_selector: verification_selector(),
                    excluded_prior_selectors: vec![verification_selector()],
                    session_selector: None,
                    enabled_intersection_mask: vec![],
                    enabled: false,
                    explicit_off_remainder_mask: vec![],
                    whole_region_off: true,
                    whole_region_off_mask: vec!["all:tool_id:read".into()],
                    effective_action: VerificationEffectiveAction::Off,
                    adjudicator_slot: None,
                    count_ceiling: None,
                    token_ceiling: None,
                    cost_ceiling_micros: None,
                    max_collection_duration_ms: None,
                    execution_plan: None,
                },
            ],
            bindings: vec![RedactedBindingEvidence {
                slot_id: "primary".into(),
                binding_revision: 1,
                provider_profile_handle: "local-profile-opaque".into(),
                model_id: "model-a".into(),
                selected_provider_alias: alias("model-a"),
                provenance_digest: hex_digest(b"canonical-provenance:primary:model-a"),
                hard_capability_verified: true,
                is_default: true,
            }],
            child_bindings: vec![RedactedChildBindingEvidence {
                installation_id: local_child_installation_id,
                installation_revision: child_installation.installation_revision,
                observation_revision: child_observation.observation_revision,
                definition_digest: child_expectation.expected_definition_digest.clone(),
                binding: RedactedBindingEvidence {
                    slot_id: child_binding.slot_id,
                    binding_revision: child_binding.binding_revision,
                    provider_profile_handle: child_binding.provider_profile_handle,
                    model_id: child_binding.model_id.clone(),
                    selected_provider_alias: alias(&child_binding.model_id),
                    provenance_digest: child_binding.provenance_digest,
                    hard_capability_verified: child_binding.hard_capability_verified,
                    is_default: child_binding.is_default,
                },
                slot_requirements: RedactedModelSlotRequirements {
                    min_context_tokens: 1,
                    required_capabilities: vec!["text_generation".into()],
                    locality: "any".into(),
                    allowed_models: Vec::new(),
                },
            }],
        };
        input.canonical_snapshot_payload = serde_json::to_vec(&profile).unwrap();
        input.canonical_snapshot_digest = hex_digest(&input.canonical_snapshot_payload);
        let snapshot = match db.prepare_agent_session(input).await.unwrap() {
            PrepareAgentSessionOutcome::Prepared(snapshot) => snapshot,
            outcome => panic!("expected prepared semantic snapshot, got {outcome:?}"),
        };
        let reconstructed = snapshot.reconstruct().unwrap();
        assert_eq!(reconstructed, profile);
        let delegation = reconstructed.effective_delegation.as_ref().unwrap();
        assert!(delegation.permits_child_kind(&local_child, AgentExecutionKind::Coding));
        assert!(!delegation.permits_child_kind(&local_child, AgentExecutionKind::Computer));
        let unmatched = reconstructed
            .recommendations
            .iter()
            .find(|recommendation| recommendation.recommendation_id == "unsuggested-compatible")
            .unwrap();
        assert_eq!(unmatched.slot_id, "primary");
        assert_eq!(unmatched.exact_provider_alias, None);

        // The host-policy decision is persisted separately from the child
        // identity and definition execution kind.  The same tagged child is
        // therefore still present, but only the explicitly granted snapshot
        // authorizes a computer child after reload.
        let mut computer_enabled_profile = profile;
        computer_enabled_profile
            .effective_delegation
            .as_mut()
            .unwrap()
            .computer_delegation_enabled = true;
        let mut computer_enabled_input = prepare_input(
            Uuid::now_v7(),
            installation_id,
            snapshot.definition_digest.clone(),
        );
        computer_enabled_input.expected_children = vec![child_expectation];
        computer_enabled_input.canonical_snapshot_payload =
            serde_json::to_vec(&computer_enabled_profile).unwrap();
        computer_enabled_input.canonical_snapshot_digest =
            hex_digest(&computer_enabled_input.canonical_snapshot_payload);
        let computer_enabled_snapshot = match db
            .prepare_agent_session(computer_enabled_input)
            .await
            .unwrap()
        {
            PrepareAgentSessionOutcome::Prepared(snapshot) => snapshot,
            outcome => panic!("expected prepared computer snapshot, got {outcome:?}"),
        };
        assert!(
            !computer_enabled_snapshot
                .reconstruct()
                .unwrap()
                .effective_delegation
                .as_ref()
                .unwrap()
                .permits_child_kind(&local_child, AgentExecutionKind::Computer),
            "a host computer grant cannot change the durable coding child kind"
        );
    }

    #[test]
    fn agent_installation_db_snapshot_policy_and_slot_contract_is_closed_and_fail_closed() {
        let (_, installation_id, definition_digest) = (Uuid::now_v7(), Uuid::now_v7(), digest("d"));
        let input = prepare_input(Uuid::now_v7(), installation_id, definition_digest);
        let mut profile =
            decode_canonical_snapshot(&input.canonical_snapshot_payload, "test canonical snapshot")
                .unwrap();
        let mut unresolved_portable_child = profile.clone();
        unresolved_portable_child.effective_delegation = Some(RedactedEffectiveDelegation {
            allowed_children: vec![RedactedAllowedChild::PortableRef {
                canonical_agent_ref: "authored/reviewer".into(),
            }],
            max_descendant_depth: 1,
            max_concurrent_children: 1,
            targets: vec![DelegationTarget::SameRoot],
            computer_delegation_enabled: false,
        });
        let unresolved_portable_child = serde_json::to_vec(&unresolved_portable_child).unwrap();
        assert!(
            decode_canonical_snapshot(&unresolved_portable_child, "unresolved portable child")
                .is_err()
        );
        let mut forged_precedence = profile.clone();
        let mut later_region = forged_precedence.verification_regions[0].clone();
        later_region.source_rule_id = "r2".into();
        later_region.excluded_prior_selectors.clear();
        forged_precedence.verification_regions.push(later_region);
        let forged_precedence = serde_json::to_vec(&forged_precedence).unwrap();
        assert!(
            decode_canonical_snapshot(&forged_precedence, "forged first-match precedence").is_err()
        );
        profile.question_policy = RedactedQuestionPolicy::Off;
        let off = serde_json::to_vec(&profile).unwrap();
        assert!(decode_canonical_snapshot(&off, "off policy").is_ok());

        profile.question_policy = RedactedQuestionPolicy::Active {
            auto_answer_disabled: true,
            prohibited_classes: vec![],
            required_decision_timeout_ms: 2,
            host_resource_ceiling_ms: 1,
            resolver_order: QuestionResolverOrder::WarmParentThenUtility,
            resolver_slot: "primary".into(),
        };
        let over_ceiling = serde_json::to_vec(&profile).unwrap();
        assert!(decode_canonical_snapshot(&over_ceiling, "over ceiling policy").is_err());

        profile.question_policy = RedactedQuestionPolicy::Off;
        profile.verification_regions[0].adjudicator_slot = None;
        let missing_adjudicator = serde_json::to_vec(&profile).unwrap();
        assert!(decode_canonical_snapshot(&missing_adjudicator, "missing adjudicator").is_err());

        profile.verification_regions[0].adjudicator_slot = Some("primary".into());
        profile.verification_regions[0].enabled_intersection_mask =
            vec!["all:tool_id:forged".into()];
        let forged_selector_mask = serde_json::to_vec(&profile).unwrap();
        assert!(decode_canonical_snapshot(&forged_selector_mask, "forged selector mask").is_err());
        profile.verification_regions[0].enabled_intersection_mask = vec!["all:tool_id:read".into()];

        profile.verification_regions[0].effective_action = VerificationEffectiveAction::Off;
        profile.verification_regions[0].enabled = false;
        profile.verification_regions[0].whole_region_off = true;
        profile.verification_regions[0].whole_region_off_mask = vec!["all:tool_id:read".into()];
        profile.verification_regions[0]
            .enabled_intersection_mask
            .clear();
        profile.verification_regions[0].count_ceiling = None;
        profile.verification_regions[0].token_ceiling = None;
        profile.verification_regions[0].cost_ceiling_micros = None;
        profile.verification_regions[0].max_collection_duration_ms = None;
        profile.verification_regions[0].adjudicator_slot = Some("primary".into());
        let off_with_slot = serde_json::to_vec(&profile).unwrap();
        assert!(decode_canonical_snapshot(&off_with_slot, "off region with slot").is_err());

        profile.verification_regions[0].adjudicator_slot = None;
        profile.recommendations[0].author_label = None;
        profile.recommendations[0].rationale = None;
        profile.recommendations[0].slot_id = "missing".into();
        let unbound_recommendation = serde_json::to_vec(&profile).unwrap();
        assert!(
            decode_canonical_snapshot(&unbound_recommendation, "unbound recommendation").is_err()
        );
    }

    #[test]
    fn agent_installation_db_snapshot_recommendations_are_slot_scoped_and_canonically_ordered() {
        let input = prepare_input(Uuid::now_v7(), Uuid::now_v7(), digest("d"));
        let mut profile =
            decode_canonical_snapshot(&input.canonical_snapshot_payload, "test canonical snapshot")
                .unwrap();
        profile.bindings.push(RedactedBindingEvidence {
            slot_id: "utility".into(),
            binding_revision: 1,
            provider_profile_handle: "utility-profile-opaque".into(),
            model_id: "model-b".into(),
            selected_provider_alias: alias("model-b"),
            provenance_digest: hex_digest(b"canonical-provenance:utility:model-b"),
            hard_capability_verified: true,
            is_default: true,
        });
        profile.recommendations = vec![
            RedactedRecommendation {
                recommendation_id: "author-default".into(),
                slot_id: "primary".into(),
                canonical_upstream_identity: "upstream/author-default-primary".into(),
                author_label: Some("Default primary".into()),
                rationale: None,
                provider_aliases: vec![alias("model-a")],
                exact_provider_alias: Some(alias("model-a")),
                author_suggested: true,
                alias_collision_rank: 0,
            },
            RedactedRecommendation {
                recommendation_id: "author-fallback".into(),
                slot_id: "primary".into(),
                canonical_upstream_identity: "upstream/author-fallback-primary".into(),
                author_label: Some("Fallback primary".into()),
                rationale: None,
                provider_aliases: vec![alias("model-a")],
                exact_provider_alias: Some(alias("model-a")),
                author_suggested: true,
                alias_collision_rank: 1,
            },
            RedactedRecommendation {
                // Stable recommendation ids are only meaningful inside their
                // declared slot, so this rank-zero utility record may reuse
                // the primary record's id.
                recommendation_id: "author-default".into(),
                slot_id: "utility".into(),
                canonical_upstream_identity: "upstream/author-default-utility".into(),
                author_label: Some("Default utility".into()),
                rationale: None,
                provider_aliases: vec![alias("model-b")],
                exact_provider_alias: Some(alias("model-b")),
                author_suggested: true,
                alias_collision_rank: 0,
            },
            RedactedRecommendation {
                recommendation_id: "author-fallback".into(),
                slot_id: "utility".into(),
                canonical_upstream_identity: "upstream/author-fallback-utility".into(),
                author_label: Some("Fallback utility".into()),
                rationale: None,
                provider_aliases: vec![alias("model-b")],
                exact_provider_alias: Some(alias("model-b")),
                author_suggested: true,
                alias_collision_rank: 1,
            },
        ];
        let canonical = serde_json::to_vec(&profile).unwrap();
        assert!(decode_canonical_snapshot(&canonical, "slot-scoped recommendations").is_ok());

        let mut non_contiguous_rank = profile.clone();
        non_contiguous_rank.recommendations[3].alias_collision_rank = 2;
        assert!(
            decode_canonical_snapshot(
                &serde_json::to_vec(&non_contiguous_rank).unwrap(),
                "non-contiguous slot collision rank"
            )
            .is_err()
        );

        let mut noncanonical_flattening = profile;
        noncanonical_flattening.recommendations.swap(1, 2);
        assert!(
            decode_canonical_snapshot(
                &serde_json::to_vec(&noncanonical_flattening).unwrap(),
                "noncanonical flattened recommendation ordering"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn agent_installation_slot_set_is_atomic_provider_aware_and_preserves_other_slots() {
        let db = Db::open_in_memory().unwrap();
        let (installation_id, definition_digest) = installed_and_bound_fixture(&db).await;
        assert!(matches!(
            db.bind_agent_model(
                installation_id,
                definition_digest.clone(),
                None,
                "utility-bind".into(),
                "utility-fingerprint".into(),
                binding("utility", "utility-model"),
                12,
            )
            .await
            .unwrap(),
            BindAgentOutcome::Bound(_)
        ));

        let default = binding("primary", "shared-model");
        let mut alternate = binding("primary", "shared-model");
        alternate.provider_profile_handle = "second-profile-opaque".into();
        alternate.is_default = false;
        alternate.provenance_payload = b"canonical-provenance:primary:second/shared-model".to_vec();
        alternate.provenance_digest = hex_digest(&alternate.provenance_payload);
        assert!(matches!(
            db.bind_agent_slot_set(AgentBindSlotSetInput {
                installation_id,
                expected_observation_revision: 1,
                expected_definition_digest: definition_digest.clone(),
                expected_binding_revision: Some(1),
                idempotency_key: "slot-set".into(),
                request_fingerprint: "slot-set-fingerprint".into(),
                bindings: vec![default, alternate],
                now_unix_ms: 13,
            })
            .await
            .unwrap(),
            BindAgentOutcome::Bound(_)
        ));

        let live = db
            .current_agent_bindings(installation_id, definition_digest.clone())
            .await
            .unwrap();
        assert_eq!(
            live.iter().filter(|row| row.slot_id == "primary").count(),
            2
        );
        assert!(live.iter().any(|row| {
            row.slot_id == "primary"
                && row.provider_profile_handle == "local-profile-opaque"
                && row.model_id == "shared-model"
                && row.is_default
        }));
        assert!(live.iter().any(|row| {
            row.slot_id == "primary"
                && row.provider_profile_handle == "second-profile-opaque"
                && row.model_id == "shared-model"
                && !row.is_default
        }));
        assert!(live.iter().any(|row| row.slot_id == "utility"));

        let default_id = live
            .iter()
            .find(|row| row.slot_id == "utility" && row.is_default)
            .unwrap()
            .binding_id;
        let invariant_error = db
            .transaction(move |conn| {
                conn.execute(
                    "UPDATE agent_model_bindings SET is_default=0 WHERE binding_id=?1",
                    [default_id.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(format!("{invariant_error:#}").contains("requires exactly one default"));

        let primary_default_id = live
            .iter()
            .find(|row| row.slot_id == "primary" && row.is_default)
            .unwrap()
            .binding_id;
        let move_default_error = db
            .transaction(move |conn| {
                conn.execute(
                    "UPDATE agent_model_bindings SET slot_id='orphan' WHERE binding_id=?1",
                    [primary_default_id.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(format!("{move_default_error:#}").contains("default cannot leave a nonempty slot"));

        let primary_alternate_id = live
            .iter()
            .find(|row| row.slot_id == "primary" && !row.is_default)
            .unwrap()
            .binding_id;
        let move_alternate_error = db
            .transaction(move |conn| {
                conn.execute(
                    "UPDATE agent_model_bindings SET slot_id='orphan' WHERE binding_id=?1",
                    [primary_alternate_id.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(format!("{move_alternate_error:#}").contains("requires exactly one default"));
    }

    #[tokio::test]
    async fn agent_installation_db_binding_receipt_rejects_cross_fingerprint_retry() {
        let db = Db::open_in_memory().unwrap();
        let install = installation(AgentInstallationScope::Global, None);
        let id = install.installation_id;
        let definition_digest = install.source_digest.clone();
        db.install_agent(install).await.unwrap();
        assert!(matches!(
            db.bind_agent_model(
                id,
                definition_digest.clone(),
                None,
                "key".into(),
                "fingerprint".into(),
                binding("primary", "model-a"),
                1
            )
            .await
            .unwrap(),
            BindAgentOutcome::Bound(_)
        ));
        assert!(matches!(
            db.bind_agent_model(
                id,
                definition_digest,
                None,
                "key".into(),
                "other".into(),
                binding("primary", "model-a"),
                2
            )
            .await
            .unwrap(),
            BindAgentOutcome::Conflict
        ));
    }

    #[tokio::test]
    async fn agent_installation_db_rejects_unverified_hard_capabilities() {
        let db = Db::open_in_memory().unwrap();
        let install = installation(AgentInstallationScope::Global, None);
        let installation_id = install.installation_id;
        let definition_digest = install.source_digest.clone();
        db.install_agent(install).await.unwrap();
        let mut incompatible = binding("primary", "unknown-model");
        incompatible.hard_capability_verified = false;
        assert!(matches!(
            db.bind_agent_model(
                installation_id,
                definition_digest.clone(),
                None,
                "unverified".into(),
                "unverified-fingerprint".into(),
                incompatible,
                12,
            )
            .await
            .unwrap(),
            BindAgentOutcome::Incompatible
        ));
        assert!(
            db.current_agent_binding(installation_id, definition_digest, "primary".into())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn agent_installation_db_snapshots_are_immutable_and_tombstone_installations() {
        let db = Db::open_in_memory().unwrap();
        let (session_id, installation_id, definition_digest) = prepared_fixture(&db).await;
        let input = prepare_input(session_id, installation_id, definition_digest);
        let snapshot = match db.prepare_agent_session(input).await.unwrap() {
            PrepareAgentSessionOutcome::Prepared(snapshot) => snapshot,
            other => panic!("expected Prepared, got {other:?}"),
        };
        assert_eq!(
            db.agent_profile_snapshot(session_id).await.unwrap(),
            Some(snapshot)
        );
        assert!(matches!(
            db.delete_agent_installation(installation_id, 40)
                .await
                .unwrap(),
            DeleteAgentInstallationOutcome::Tombstoned
        ));
        db.transaction(move |conn| {
            conn.execute(
                "DELETE FROM sessions WHERE session_id=?1",
                [session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(matches!(
            db.delete_agent_installation(installation_id, 41)
                .await
                .unwrap(),
            DeleteAgentInstallationOutcome::Deleted
        ));
    }
}
