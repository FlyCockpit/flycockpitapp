//! Closed, declarative v2 agent-definition schema.
//!
//! This module deliberately contains no provider, credential, tool-grant, or
//! sandbox binding.  Those are host-owned inputs to a later effective-grant
//! calculation; an authored markdown definition can only request a bounded
//! shape here.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const SCHEMA_VERSION: u8 = 2;
pub const DEFAULT_MAX_CANDIDATES: u16 = 5;

/// Provenance assigned by the trusted definition loader, never read from an
/// authored frontmatter key.  The `local` publisher is a daemon-local
/// identity namespace, so accepting it from a workspace path would let an
/// untrusted checkout name opaque installation UUIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefinitionScope {
    Workspace,
    DaemonLocal,
    /// An override selected by the binary for one of its own embedded
    /// definitions.  This is deliberately distinct from a normal workspace
    /// file: it may retain the binary-owned `cockpit/` publisher, but only
    /// after the resolver has proved that the path overrides that exact
    /// built-in name.
    BuiltinOverride,
    /// A rendered snapshot served by the daemon over the wire.  The daemon is
    /// a trusted source for all publisher provenances (`cockpit`, `authored`,
    /// and `local`), so this scope accepts any publisher without re-checking
    /// the loader boundary.  It is only used by
    /// [`parse_daemon_agent_snapshot`][super::parse_daemon_agent_snapshot].
    DaemonSnapshot,
}

/// The immutable identity recorded by the daemon for a private installation.
/// A display name is deliberately absent: names are editable presentation
/// metadata, whereas a child reference must continue to identify the exact
/// definition revision that was installed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocalInstallationIdentity {
    /// The daemon-owned local launch target. This is deliberately separate
    /// from `agent_id`: the latter identifies the definition contract while
    /// the former selects the installed row/factory path that may launch it.
    /// Markdown never supplies either value for a local child reference.
    pub launch_target: String,
    pub agent_id: String,
    pub definition_digest: String,
}

impl LocalInstallationIdentity {
    pub fn from_definition(definition: &crate::agents::AgentDef) -> Result<Self> {
        let vnext = definition.vnext.as_ref().ok_or_else(|| {
            anyhow::anyhow!("local installation binding requires a vNext definition")
        })?;
        if !vnext.is_local() {
            bail!("local installation binding requires a daemon-local agentId");
        }
        let digest = Sha256::digest(definition.vnext_digest_bytes()?);
        Ok(Self {
            // This constructor derives immutable definition identity only.
            // The daemon binding supplies the trusted launch target later.
            launch_target: definition.name.clone(),
            agent_id: vnext.agent_id.clone(),
            definition_digest: crate::intel::hex_lower(&digest),
        })
    }
}

/// Daemon-owned exact installation binding lookup.  Markdown can name an
/// opaque local installation UUID, but it cannot turn that UUID into a display
/// name: the session owner injects the one-to-one binding it has already
/// authenticated.  Keeping this seam typed makes a missing or ambiguous
/// binding a refusal instead of a legacy-name fallback.
#[derive(Clone)]
pub struct LocalInstallationResolver {
    bindings: std::sync::Arc<BTreeMap<Uuid, LocalInstallationIdentity>>,
    /// The authenticated, daemon-owned definition snapshot for each local
    /// installation.  A UUID reference selects this snapshot directly; it is
    /// never re-resolved by a user-controlled display name or checkout path.
    definitions: std::sync::Arc<BTreeMap<Uuid, crate::agents::AgentDef>>,
}

impl LocalInstallationResolver {
    /// Explicitly state that the daemon has no installed local definitions.
    /// This is different from a permissive fallback: any authored local UUID
    /// still fails at resolution. Production session construction uses this
    /// only until the installation/binding persistence owner injects its
    /// complete one-to-one mapping.
    pub fn no_installations() -> Self {
        Self {
            bindings: std::sync::Arc::new(BTreeMap::new()),
            definitions: std::sync::Arc::new(BTreeMap::new()),
        }
    }

    pub fn from_bindings(bindings: BTreeMap<Uuid, LocalInstallationIdentity>) -> Result<Self> {
        if bindings.values().any(|identity| {
            identity.launch_target.trim().is_empty()
                || identity.agent_id.trim().is_empty()
                || identity.definition_digest.trim().is_empty()
        }) {
            bail!(
                "local installation bindings must contain a launch target plus immutable agentId and definition digest"
            );
        }
        Ok(Self {
            bindings: std::sync::Arc::new(bindings),
            definitions: std::sync::Arc::new(BTreeMap::new()),
        })
    }

    /// Construct the complete daemon snapshot used by production sessions.
    /// Each definition has already crossed the daemon-local loader boundary.
    pub fn from_bound_definitions(
        definitions: BTreeMap<Uuid, crate::agents::AgentDef>,
    ) -> Result<Self> {
        let mut bindings = BTreeMap::new();
        for (installation_id, definition) in &definitions {
            let identity = LocalInstallationIdentity::from_definition(definition)?;
            if bindings.insert(*installation_id, identity).is_some() {
                bail!("duplicate daemon-local installation UUID `{installation_id}`");
            }
        }
        let mut resolver = Self::from_bindings(bindings)?;
        resolver.definitions = std::sync::Arc::new(definitions);
        Ok(resolver)
    }

    pub fn resolve(&self, installation_id: Uuid) -> Result<&LocalInstallationIdentity> {
        self.bindings.get(&installation_id).ok_or_else(|| {
            anyhow::anyhow!(
                "no exact daemon-local installation binding exists for `{installation_id}`"
            )
        })
    }

    pub fn definition(&self, installation_id: Uuid) -> Result<&crate::agents::AgentDef> {
        self.definitions.get(&installation_id).ok_or_else(|| {
            anyhow::anyhow!(
                "no authenticated daemon-local definition snapshot exists for `{installation_id}`"
            )
        })
    }

    /// Resolve the exact local definition selected by the live parent's UUID
    /// allow-list.  This is deliberately a combined lookup: callers cannot
    /// turn the resulting launch target back into a workspace name lookup.
    pub fn definition_for_parent_launch_target(
        &self,
        parent: &EffectiveVnextGrant,
        launch_target: &str,
    ) -> Result<Option<(Uuid, crate::agents::AgentDef)>> {
        let Some(installation_id) =
            self.local_reference_for_launch_target(parent, launch_target)?
        else {
            return Ok(None);
        };
        Ok(Some((
            installation_id,
            self.definition(installation_id)?.clone(),
        )))
    }

    /// Root private-assistant construction has no parent grant, but the
    /// session's identity prefix proves it was selected from the daemon-owned
    /// assistant session record.  Refuse ambiguity rather than letting a
    /// checkout definition shadow it.
    pub fn root_definition_for_launch_target(
        &self,
        launch_target: &str,
    ) -> Result<Option<crate::agents::AgentDef>> {
        let matches: Vec<_> = self
            .bindings
            .iter()
            .filter_map(|(id, identity)| (identity.launch_target == launch_target).then_some(*id))
            .collect();
        match matches.as_slice() {
            [] => Ok(None),
            [installation_id] => Ok(Some(self.definition(*installation_id)?.clone())),
            _ => bail!(
                "multiple daemon-local installation UUIDs resolve to launch target `{launch_target}`"
            ),
        }
    }

    /// Resolve the sole UUID in a parent's live allow-list that names this
    /// daemon-owned launch target. The target comes from trusted installation
    /// state, not the manifest; two UUIDs claiming one target are refused
    /// rather than allowing a name lookup to select one arbitrarily.
    pub fn local_reference_for_launch_target(
        &self,
        parent: &EffectiveVnextGrant,
        launch_target: &str,
    ) -> Result<Option<Uuid>> {
        let Some(delegation) = &parent.delegation else {
            return Ok(None);
        };
        let references: Vec<Uuid> = delegation
            .allowed_children
            .iter()
            .filter_map(|child| match child {
                AllowedChild::LocalInstallation { installation_id }
                    if self
                        .bindings
                        .get(installation_id)
                        .is_some_and(|binding| binding.launch_target == launch_target) =>
                {
                    Some(*installation_id)
                }
                _ => None,
            })
            .collect();
        match references.as_slice() {
            [] => Ok(None),
            [installation_id] => Ok(Some(*installation_id)),
            _ => bail!(
                "multiple daemon-local installation UUIDs resolve to launch target `{launch_target}`"
            ),
        }
    }

    pub fn matches_definition(
        &self,
        installation_id: Uuid,
        launch_target: &str,
        definition: &crate::agents::AgentDef,
    ) -> bool {
        let Ok(identity) = LocalInstallationIdentity::from_definition(definition) else {
            return false;
        };
        self.bindings.get(&installation_id).is_some_and(|bound| {
            bound.launch_target == launch_target
                && bound.agent_id == identity.agent_id
                && bound.definition_digest == identity.definition_digest
        })
    }
}

/// Deliberately bounded operational defaults for the daemon-owned vNext host
/// profile. `VnextHostPolicy::default()` remains the deny-all value for
/// callers that have not entered a session; production session construction
/// must use [`VnextHostPolicy::for_session_config`] instead.
const SESSION_MAX_DESCENDANT_DEPTH: u16 = 8;
const SESSION_MAX_QUESTION_TIMEOUT_SECONDS: u32 = 60 * 60;

/// Host-owned ceilings for a vNext definition.  These values are deliberately
/// separate from the markdown schema: an author requests a bounded shape, but
/// only the host turns that request into a live grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VnextHostPolicy {
    pub max_descendant_depth: u16,
    pub max_concurrent_children: u16,
    pub allowed_targets: BTreeSet<DelegationTarget>,
    pub computer_delegation_enabled: bool,
    pub non_auto_resolvable: BTreeSet<ProhibitedQuestionClass>,
    pub max_question_timeout_seconds: u32,
    pub verification_ceiling: VerificationBudget,
}

impl Default for VnextHostPolicy {
    fn default() -> Self {
        // A missing host profile is never an implicit authority grant.
        Self {
            max_descendant_depth: 0,
            max_concurrent_children: 0,
            allowed_targets: BTreeSet::new(),
            computer_delegation_enabled: false,
            non_auto_resolvable: BTreeSet::new(),
            max_question_timeout_seconds: 0,
            verification_ceiling: VerificationBudget::zero(),
        }
    }
}

impl VnextHostPolicy {
    /// Construct the daemon's session-owned policy snapshot. This is the
    /// single core seam that turns ordinary session configuration into vNext
    /// ceilings; markdown never supplies these values. It intentionally does
    /// not reuse the legacy per-agent recursion map: v2 tree admission is
    /// governed exclusively by [`EffectiveVnextGrant`].
    pub fn for_session_config(config: &crate::config::extended::ExtendedConfig) -> Self {
        let max_concurrent_children = u16::try_from(config.delegation.max_parallel)
            .unwrap_or(u16::MAX)
            .max(1);
        Self {
            max_descendant_depth: SESSION_MAX_DESCENDANT_DEPTH,
            max_concurrent_children,
            allowed_targets: BTreeSet::from([
                DelegationTarget::SameRoot,
                DelegationTarget::Subdirectory,
            ]),
            computer_delegation_enabled: matches!(
                config.computer_use,
                Some(crate::config::extended::ComputerUseMode::Ask)
                    | Some(crate::config::extended::ComputerUseMode::Yolo)
            ),
            non_auto_resolvable: BTreeSet::from([
                ProhibitedQuestionClass::Credential,
                ProhibitedQuestionClass::Authorization,
                ProhibitedQuestionClass::Destructive,
                ProhibitedQuestionClass::ExternalAction,
                ProhibitedQuestionClass::Publish,
                ProhibitedQuestionClass::Purchase,
                ProhibitedQuestionClass::Production,
            ]),
            max_question_timeout_seconds: SESSION_MAX_QUESTION_TIMEOUT_SECONDS,
            verification_ceiling: VerificationBudget {
                max_candidates: DEFAULT_MAX_CANDIDATES,
                max_total_tokens: u64::MAX,
                max_estimated_cost_microusd: u64::MAX,
                max_collection_millis: u64::MAX,
            },
        }
    }
}

/// The four independent verification resource dimensions.  `None` denotes an
/// unavailable estimate, not an unlimited one; callers must take the selected
/// pre-candidate action before dispatching in that case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationBudget {
    pub max_candidates: u16,
    pub max_total_tokens: u64,
    pub max_estimated_cost_microusd: u64,
    pub max_collection_millis: u64,
}

impl VerificationBudget {
    pub const fn zero() -> Self {
        Self {
            max_candidates: 0,
            max_total_tokens: 0,
            max_estimated_cost_microusd: 0,
            max_collection_millis: 0,
        }
    }

    pub fn contains(self, request: Self) -> bool {
        request.max_candidates <= self.max_candidates
            && request.max_total_tokens <= self.max_total_tokens
            && request.max_estimated_cost_microusd <= self.max_estimated_cost_microusd
            && request.max_collection_millis <= self.max_collection_millis
    }

    pub fn reduce(self, session: Self) -> Result<Self> {
        if !self.contains(session) {
            bail!(
                "session verification budget may only reduce the resolved host/definition budget"
            );
        }
        Ok(session)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationEstimate {
    Known(VerificationBudget),
    UnknownTokens,
    UnknownPrice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationDispatch {
    Verify {
        budget: VerificationBudget,
        adjudicator_slot: String,
    },
    Off,
    Refuse,
    DispatchOriginal,
}

/// A persisted monotonic session reduction.  A session can turn verification
/// off, or intersect an already-disjoint definition region with a stricter
/// selector and lower budget; it cannot introduce a new verify region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationSessionReduction {
    Inherit,
    Off,
    Restrict {
        selector: VerificationSelector,
        budget: Option<VerificationBudget>,
    },
}

/// A definition rule compiled into `rule_match - earlier_rule_matches`.
/// `excluded_by` is an explicit off mask: a request excluded from this region
/// never falls through to a later authored rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledVerificationRegion {
    pub rule: VerificationRule,
    pub excluded_by: Vec<VerificationSelector>,
}

impl CompiledVerificationRegion {
    pub fn matches(&self, subject: &VerificationSubject<'_>) -> bool {
        self.rule.selector.matches(subject)
            && !self
                .excluded_by
                .iter()
                .any(|selector| selector.matches(subject))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledVerificationPolicy {
    pub regions: Vec<CompiledVerificationRegion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VnextAgentDef {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    #[serde(rename = "executionKind")]
    pub execution_kind: ExecutionKind,
    #[serde(rename = "modelSlots")]
    pub model_slots: BTreeMap<String, ModelSlot>,
    #[serde(default, skip_serializing_if = "DelegationPolicy::is_off")]
    pub delegation: DelegationPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub questions: Option<QuestionPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationPolicy>,
}

impl VnextAgentDef {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!("schemaVersion must be exactly {SCHEMA_VERSION}");
        }
        validate_agent_id(&self.agent_id)?;
        if !self.model_slots.contains_key("primary") {
            bail!("modelSlots must contain required `primary` slot");
        }
        for (slot_id, slot) in &self.model_slots {
            validate_ascii_identifier(slot_id, "model slot ID")?;
            slot.validate(slot_id)?;
        }
        self.delegation
            .validate(&self.agent_id, self.execution_kind)?;
        if let Some(questions) = &self.questions {
            questions.validate(&self.model_slots)?;
        }
        if let Some(verification) = &self.verification {
            verification.validate(&self.model_slots)?;
        }
        Ok(())
    }

    /// Apply the trusted loader's origin boundary after structural schema
    /// validation.  Scope is intentionally not serializable: a markdown file
    /// cannot self-attest that it was loaded from daemon-owned storage.
    pub(crate) fn validate_for_scope(&self, scope: DefinitionScope) -> Result<()> {
        self.validate()?;
        // The daemon is a trusted source for all publisher provenances — it
        // rendered the snapshot from its own agent store, so the loader
        // boundary does not apply.
        if scope == DefinitionScope::DaemonSnapshot {
            return Ok(());
        }
        if self.is_local() != (scope == DefinitionScope::DaemonLocal) {
            bail!(
                "agentId publisher provenance does not match its trusted loader: `local` is reserved for daemon-local definitions and portable publishers are workspace-authored"
            );
        }
        if self.publisher() == "cockpit" && scope != DefinitionScope::BuiltinOverride {
            bail!("agentId publisher `cockpit` is reserved for binary-owned internal definitions");
        }
        if scope == DefinitionScope::Workspace && self.publisher() != "authored" {
            bail!("workspace-authored vNext definitions must use the `authored/` publisher");
        }
        Ok(())
    }

    pub fn publisher(&self) -> &str {
        self.agent_id
            .split_once('/')
            .map_or("", |(publisher, _)| publisher)
    }

    pub fn is_local(&self) -> bool {
        self.publisher() == "local"
    }

    /// Resolve an authored declaration under a concrete host profile.  This is
    /// intentionally a rejecting operation: values over a ceiling are not
    /// silently clamped, because clamping would make the persisted definition
    /// claim a different authority than the running child received.
    pub fn resolve_grant(&self, host: &VnextHostPolicy) -> Result<EffectiveVnextGrant> {
        self.validate()?;
        let delegation = if self.delegation.is_off() {
            None
        } else {
            let depth = self.delegation.max_descendant_depth.expect("validated");
            let concurrent = self.delegation.max_concurrent_children.expect("validated");
            if depth > host.max_descendant_depth {
                bail!("delegation.maxDescendantDepth exceeds the host ceiling");
            }
            if concurrent > host.max_concurrent_children {
                bail!("delegation.maxConcurrentChildren exceeds the host ceiling");
            }
            let targets: BTreeSet<_> = self.delegation.targets.iter().copied().collect();
            if !targets.is_subset(&host.allowed_targets) {
                bail!("delegation.targets exceed the host policy");
            }
            Some(EffectiveDelegationGrant {
                allowed_children: self.delegation.allowed_children.clone(),
                max_descendant_depth: depth,
                max_concurrent_children: concurrent,
                targets,
            })
        };
        let questions =
            resolve_question_policy(self.questions.as_ref(), host, QuestionOverride::Inherit)?;
        // Compile once at the definition/profile boundary. Verification
        // execution is intentionally owned by its follow-up prompt, but any
        // future executor must consume this immutable snapshot rather than
        // re-read mutable authored YAML mid-session.
        let verification = self
            .verification
            .as_ref()
            .map(|policy| policy.compile_with_slots(&self.model_slots));
        Ok(EffectiveVnextGrant {
            agent_id: self.agent_id.clone(),
            execution_kind: self.execution_kind,
            delegation,
            questions,
            verification,
            computer_delegation_enabled: host.computer_delegation_enabled,
            host_policy: host.clone(),
        })
    }

    /// Resolve a child under its parent's already-snapshotted live grant.
    /// This is the sole vNext child-launch calculation: the child request is
    /// intersected with the host snapshot and the parent cannot hand a depth
    /// or target it did not itself receive. `parent_ref` is resolved before
    /// this call (portable ID or daemon-local installation ID), never guessed.
    pub fn resolve_child_grant(
        &self,
        host: &VnextHostPolicy,
        parent: &EffectiveVnextGrant,
        parent_ref: &AllowedChild,
    ) -> Result<EffectiveVnextGrant> {
        if !parent.permits_child(parent_ref, self.execution_kind) {
            bail!("parent effective vNext grant does not permit this child");
        }
        let mut child = self.resolve_grant(host)?;
        let Some(parent_delegation) = &parent.delegation else {
            bail!("parent effective vNext grant has no delegation authority");
        };
        // Parent depth counts edges from its own root. The direct child uses
        // one edge; a zero remaining budget means it remains a leaf even when
        // its declaration asks for children.
        let remaining_depth = parent_delegation.max_descendant_depth.saturating_sub(1);
        if let Some(child_delegation) = &mut child.delegation {
            child_delegation.max_descendant_depth =
                child_delegation.max_descendant_depth.min(remaining_depth);
            // A live child has no more direct parallelism than either the
            // declared child request, the parent grant, or the host ceiling
            // captured in both resolved grants. Keeping this intersection in
            // the immutable child snapshot makes the admission semaphore
            // enforce the same authority calculation as launch.
            child_delegation.max_concurrent_children = child_delegation
                .max_concurrent_children
                .min(parent_delegation.max_concurrent_children)
                .min(host.max_concurrent_children);
            child_delegation.targets = child_delegation
                .targets
                .intersection(&parent_delegation.targets)
                .copied()
                .collect();
            if child_delegation.max_descendant_depth == 0 || child_delegation.targets.is_empty() {
                child.delegation = None;
            }
        }
        Ok(child)
    }

    /// Resolve the first matching verification rule.  The definition's
    /// requested limits and a session's optional limits are both reductions
    /// under the snapshotted host ceiling.  Unknown estimates are typed so the
    /// caller cannot accidentally treat them as free.
    pub fn resolve_verification(
        &self,
        host: &VnextHostPolicy,
        subject: &VerificationSubject<'_>,
        session_budget: Option<VerificationBudget>,
        estimate: VerificationEstimate,
    ) -> Result<VerificationDispatch> {
        self.resolve_verification_with_session(
            host,
            subject,
            VerificationSessionReduction::Inherit,
            session_budget,
            estimate,
        )
    }

    pub fn resolve_verification_with_session(
        &self,
        host: &VnextHostPolicy,
        subject: &VerificationSubject<'_>,
        session: VerificationSessionReduction,
        session_budget: Option<VerificationBudget>,
        estimate: VerificationEstimate,
    ) -> Result<VerificationDispatch> {
        let Some(policy) = &self.verification else {
            return Ok(VerificationDispatch::Off);
        };
        resolve_compiled_verification(
            &policy.compile(),
            host,
            subject,
            session,
            session_budget,
            estimate,
        )
    }
}

fn resolve_compiled_verification(
    compiled: &CompiledVerificationPolicy,
    host: &VnextHostPolicy,
    subject: &VerificationSubject<'_>,
    session: VerificationSessionReduction,
    session_budget: Option<VerificationBudget>,
    estimate: VerificationEstimate,
) -> Result<VerificationDispatch> {
    let Some(rule) = compiled.select(subject) else {
        return Ok(VerificationDispatch::Off);
    };
    if rule.action == VerificationAction::Off {
        return Ok(VerificationDispatch::Off);
    }
    let reduction_budget = match session {
        VerificationSessionReduction::Inherit => None,
        VerificationSessionReduction::Off => return Ok(VerificationDispatch::Off),
        VerificationSessionReduction::Restrict { selector, budget } => {
            selector.validate()?;
            if !selector.matches(subject) {
                return Ok(VerificationDispatch::Off);
            }
            budget
        }
    };
    let requested = rule.requested_budget(host.verification_ceiling)?;
    let requested_session_budget = match (reduction_budget, session_budget) {
        (Some(reduction), Some(legacy)) => {
            // Both seams may be present during the breaking migration;
            // their intersection is the stricter budget, never a choice
            // of one reduction that accidentally widens the other.
            Some(reduction.reduce(legacy)?)
        }
        (Some(reduction), None) => Some(reduction),
        (None, budget) => budget,
    };
    let resolved = match requested_session_budget {
        Some(session) => requested.reduce(session)?,
        None => requested,
    };
    let estimate_exceeds = match estimate {
        VerificationEstimate::Known(estimated) => !resolved.contains(estimated),
        VerificationEstimate::UnknownTokens | VerificationEstimate::UnknownPrice => true,
    };
    if estimate_exceeds {
        return Ok(
            match rule.on_budget_exceeded.unwrap_or(OnBudgetExceeded::Refuse) {
                OnBudgetExceeded::Refuse => VerificationDispatch::Refuse,
                OnBudgetExceeded::DispatchOriginal => VerificationDispatch::DispatchOriginal,
            },
        );
    }
    Ok(VerificationDispatch::Verify {
        budget: resolved,
        adjudicator_slot: rule
            .adjudicator_slot
            .clone()
            .expect("validated verify rule"),
    })
}

/// The authority actually delivered to a running vNext agent.  Runtime code
/// must carry this value, not re-read the definition, so a parent can never
/// regain a capability rejected by its host profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveVnextGrant {
    /// Canonical definition identity this snapshot was resolved from. This
    /// prevents a same-kind grant from one vNext definition being replayed
    /// against another selected definition.
    pub agent_id: String,
    pub execution_kind: ExecutionKind,
    pub delegation: Option<EffectiveDelegationGrant>,
    pub questions: Option<EffectiveQuestionPolicy>,
    /// Ordered, disjoint verification regions fixed when this profile was
    /// resolved. Runtime dispatch consumes this snapshot via
    /// [`Self::resolve_verification`] rather than re-reading authored markdown.
    pub verification: Option<CompiledVerificationPolicy>,
    computer_delegation_enabled: bool,
    /// Original host ceiling snapshot retained for child intersection. It is
    /// not authored metadata and remains immutable for the running tree.
    pub host_policy: VnextHostPolicy,
}

impl EffectiveVnextGrant {
    pub fn computer_delegation_enabled(&self) -> bool {
        self.computer_delegation_enabled
    }

    pub fn permits_child(&self, child_ref: &AllowedChild, child_kind: ExecutionKind) -> bool {
        self.delegation.as_ref().is_some_and(|delegation| {
            delegation.allowed_children.contains(child_ref)
                && delegation_kind_permitted(
                    self.execution_kind,
                    child_kind,
                    self.computer_delegation_enabled,
                )
        })
    }

    /// Resolve verification against this grant's snapshotted compiled policy
    /// and host ceiling. Runtime dispatch must use this, not re-compile the
    /// authored markdown.
    pub fn resolve_verification(
        &self,
        subject: &VerificationSubject<'_>,
        session: VerificationSessionReduction,
        session_budget: Option<VerificationBudget>,
        estimate: VerificationEstimate,
    ) -> Result<VerificationDispatch> {
        let Some(compiled) = &self.verification else {
            return Ok(VerificationDispatch::Off);
        };
        resolve_compiled_verification(
            compiled,
            &self.host_policy,
            subject,
            session,
            session_budget,
            estimate,
        )
    }

    pub fn permits_target(
        &self,
        parent_cwd: &std::path::Path,
        child_cwd: &std::path::Path,
    ) -> bool {
        let Some(delegation) = &self.delegation else {
            return false;
        };
        // Every path arrives here from a driver confinement object, but this
        // public grant helper is also used by factory/preflight seams. Never
        // let a lexical `starts_with` turn a symlinked or `..` spelling into
        // an authority decision.
        let (Ok(parent_cwd), Ok(child_cwd)) = (parent_cwd.canonicalize(), child_cwd.canonicalize())
        else {
            return false;
        };
        delegation.targets.iter().any(|target| match target {
            DelegationTarget::SameRoot => child_cwd == parent_cwd,
            DelegationTarget::Subdirectory => {
                child_cwd != parent_cwd && child_cwd.starts_with(&parent_cwd)
            }
            // A path in a different git worktree is not itself a managed
            // worktree grant. Creation/lease ownership is supplied by the
            // dedicated worktree lifecycle owner, which has not yet threaded
            // a typed authority token into this vNext preflight seam. Refuse
            // rather than infer management from raw paths.
            DelegationTarget::ManagedWorktree => false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveDelegationGrant {
    pub allowed_children: Vec<AllowedChild>,
    pub max_descendant_depth: u16,
    pub max_concurrent_children: u16,
    pub targets: BTreeSet<DelegationTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveQuestionPolicy {
    pub decision_timeout_seconds: u32,
    pub resolver_order: ResolverOrder,
    pub resolver_slot: Option<String>,
    pub never_auto_resolve: BTreeSet<ProhibitedQuestionClass>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuestionOverride {
    /// Preserve the host/definition result.
    Inherit,
    /// Turn auto-answer off. This is the strictest valid override state.
    Disable,
    /// Retain auto-answer but reduce it under the monotonic order.
    Reduce(QuestionPolicy),
}

/// Apply a persisted/profile/session question override using the one monotonic
/// partial order. `None` means disabled, which is the strictest state.
pub fn resolve_question_policy(
    definition: Option<&QuestionPolicy>,
    host: &VnextHostPolicy,
    override_policy: QuestionOverride,
) -> Result<Option<EffectiveQuestionPolicy>> {
    let Some(base) = definition else {
        if !matches!(
            override_policy,
            QuestionOverride::Inherit | QuestionOverride::Disable
        ) {
            bail!("a question override cannot enable an omitted/off definition policy");
        }
        return Ok(None);
    };
    if matches!(override_policy, QuestionOverride::Disable) {
        return Ok(None);
    }
    if base.decision_timeout_seconds > host.max_question_timeout_seconds {
        bail!("questions.decisionTimeoutSeconds exceeds the host resource ceiling");
    }
    let chosen = match override_policy {
        QuestionOverride::Inherit => base,
        QuestionOverride::Disable => unreachable!("handled above"),
        QuestionOverride::Reduce(ref policy) => policy,
    };
    if chosen.resolver_order != base.resolver_order || chosen.resolver_slot != base.resolver_slot {
        bail!("a question override cannot broaden resolverOrder or resolverSlot");
    }
    // More waiting is a reduction because it gives the user more time.  It is
    // still bounded by the host snapshot; no clamping is allowed.
    if chosen.decision_timeout_seconds < base.decision_timeout_seconds {
        bail!("a question override cannot shorten decisionTimeoutSeconds");
    }
    if chosen.decision_timeout_seconds > host.max_question_timeout_seconds {
        bail!("questions.decisionTimeoutSeconds exceeds the host resource ceiling");
    }
    let mut prohibited = host.non_auto_resolvable.clone();
    prohibited.extend(base.never_auto_resolve.iter().copied());
    prohibited.extend(chosen.never_auto_resolve.iter().copied());
    Ok(Some(EffectiveQuestionPolicy {
        decision_timeout_seconds: chosen.decision_timeout_seconds,
        resolver_order: chosen.resolver_order,
        resolver_slot: chosen.resolver_slot.clone(),
        never_auto_resolve: prohibited,
    }))
}

/// Closed caller/child capability matrix.  Allow-list resolution remains a
/// separate installation lookup, so this function answers only the kind
/// dimension and never turns a manifest request into authority.
pub fn delegation_kind_permitted(
    caller: ExecutionKind,
    child: ExecutionKind,
    host_enables_computer: bool,
) -> bool {
    match caller {
        ExecutionKind::Assistant => {
            child == ExecutionKind::Coding
                || (child == ExecutionKind::Computer && host_enables_computer)
        }
        ExecutionKind::Coding => {
            child == ExecutionKind::Coding
                || (child == ExecutionKind::Computer && host_enables_computer)
        }
        ExecutionKind::Computer => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionKind {
    Assistant,
    Coding,
    Computer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSlot {
    pub purpose: String,
    #[serde(rename = "minContextTokens")]
    pub min_context_tokens: u64,
    #[serde(rename = "requiredCapabilities")]
    pub required_capabilities: Vec<ModelCapability>,
    pub locality: ModelLocality,
    #[serde(rename = "allowDefaultFallback")]
    pub allow_default_fallback: bool,
    #[serde(
        rename = "suggestedModels",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub suggested_models: Vec<ModelRecommendation>,
}

impl ModelSlot {
    fn validate(&self, slot_id: &str) -> Result<()> {
        if self.purpose.trim().is_empty() {
            bail!("modelSlots.{slot_id}.purpose must be non-empty");
        }
        if self.min_context_tokens == 0 {
            bail!("modelSlots.{slot_id}.minContextTokens must be positive");
        }
        if self.required_capabilities.is_empty() {
            bail!("modelSlots.{slot_id}.requiredCapabilities must be non-empty");
        }
        let rendered: Vec<&str> = self
            .required_capabilities
            .iter()
            .map(|capability| capability.as_str())
            .collect();
        let mut canonical = rendered.clone();
        canonical.sort_unstable();
        canonical.dedup();
        if canonical.len() != rendered.len() || canonical != rendered {
            bail!("modelSlots.{slot_id}.requiredCapabilities must be sorted and unique");
        }
        let mut recommendation_ids = BTreeSet::new();
        for recommendation in &self.suggested_models {
            recommendation.validate(slot_id)?;
            if !recommendation_ids.insert(&recommendation.recommendation_id) {
                bail!(
                    "modelSlots.{slot_id}.suggestedModels has duplicate recommendationId `{}`",
                    recommendation.recommendation_id
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapability {
    TextGeneration,
    ToolCalling,
    Vision,
    ComputerUse,
    JsonSchema,
}

impl ModelCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TextGeneration => "text_generation",
            Self::ToolCalling => "tool_calling",
            Self::Vision => "vision",
            Self::ComputerUse => "computer_use",
            Self::JsonSchema => "json_schema",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelLocality {
    Any,
    Local,
    Remote,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRecommendation {
    #[serde(rename = "recommendationId")]
    pub recommendation_id: String,
    #[serde(rename = "upstreamIdentity")]
    pub upstream_identity: String,
    #[serde(
        rename = "providerAliases",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub provider_aliases: Vec<ProviderAlias>,
    #[serde(
        rename = "authorLabel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub author_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

impl ModelRecommendation {
    fn validate(&self, slot_id: &str) -> Result<()> {
        validate_ascii_identifier(&self.recommendation_id, "recommendationId")?;
        validate_upstream_identity(&self.upstream_identity)?;
        let pairs: Vec<(&str, &str)> = self
            .provider_aliases
            .iter()
            .map(|alias| (alias.provider_id.as_str(), alias.model_id.as_str()))
            .collect();
        let mut canonical = pairs.clone();
        canonical.sort_unstable();
        canonical.dedup();
        if canonical.len() != pairs.len() || canonical != pairs {
            bail!(
                "modelSlots.{slot_id}.suggestedModels providerAliases must be canonical sorted unique pairs"
            );
        }
        for alias in &self.provider_aliases {
            if alias.provider_id.trim() != alias.provider_id || alias.provider_id.is_empty() {
                bail!("providerAliases.providerId must be trimmed and non-empty");
            }
            if alias.model_id.trim() != alias.model_id || alias.model_id.is_empty() {
                bail!("providerAliases.modelId must be trimmed and non-empty");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAlias {
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DelegationPolicy {
    #[serde(
        rename = "allowedChildren",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allowed_children: Vec<AllowedChild>,
    #[serde(
        rename = "maxDescendantDepth",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_descendant_depth: Option<u16>,
    #[serde(
        rename = "maxConcurrentChildren",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_concurrent_children: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<DelegationTarget>,
}

impl DelegationPolicy {
    pub fn is_off(&self) -> bool {
        self.allowed_children.is_empty()
            && self.max_descendant_depth.is_none()
            && self.max_concurrent_children.is_none()
            && self.targets.is_empty()
    }

    pub fn validate(&self, agent_id: &str, kind: ExecutionKind) -> Result<()> {
        if self.is_off() {
            return Ok(());
        }
        if kind == ExecutionKind::Computer {
            bail!("computer agents cannot declare delegation");
        }
        if self.allowed_children.is_empty() {
            bail!("delegation.allowedChildren must be non-empty when delegation is declared");
        }
        if self.max_descendant_depth.is_none_or(|depth| depth == 0) {
            bail!("delegation.maxDescendantDepth must be positive");
        }
        if self.max_concurrent_children.is_none_or(|count| count == 0) {
            bail!("delegation.maxConcurrentChildren must be positive");
        }
        if self.targets.is_empty() {
            bail!("delegation.targets must be non-empty when delegation is declared");
        }
        let local = agent_id.starts_with("local/");
        let mut children = BTreeSet::new();
        for child in &self.allowed_children {
            if !children.insert(child) {
                bail!("delegation.allowedChildren must not contain duplicates");
            }
            match (local, child) {
                (true, AllowedChild::LocalInstallation { .. }) => {}
                (false, AllowedChild::PortableRef { portable_agent_ref }) => {
                    validate_agent_id(portable_agent_ref)?;
                    if portable_agent_ref.starts_with("local/") {
                        bail!("portableAgentRef cannot use daemon-local publisher `local`");
                    }
                }
                (true, AllowedChild::PortableRef { .. }) => bail!(
                    "daemon-local definitions may only use localInstallationId child references"
                ),
                (false, AllowedChild::LocalInstallation { .. }) => bail!(
                    "workspace-shared definitions may only use portableAgentRef child references"
                ),
            }
        }
        let target_set: BTreeSet<DelegationTarget> = self.targets.iter().copied().collect();
        if target_set.len() != self.targets.len() {
            bail!("delegation.targets must not contain duplicates");
        }
        if target_set.contains(&DelegationTarget::ManagedWorktree)
            && target_set.contains(&DelegationTarget::SameRoot)
        {
            bail!("managed_worktree is exclusive from same_root");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AllowedChild {
    #[serde(rename = "local_installation")]
    LocalInstallation {
        #[serde(rename = "installationId")]
        installation_id: Uuid,
    },
    #[serde(rename = "portable_ref")]
    PortableRef {
        #[serde(rename = "ref")]
        portable_agent_ref: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationTarget {
    SameRoot,
    Subdirectory,
    ManagedWorktree,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionPolicy {
    #[serde(rename = "autoAnswer")]
    pub auto_answer: AutoAnswer,
    #[serde(rename = "decisionTimeoutSeconds")]
    pub decision_timeout_seconds: u32,
    #[serde(rename = "resolverOrder")]
    pub resolver_order: ResolverOrder,
    #[serde(
        rename = "resolverSlot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resolver_slot: Option<String>,
    #[serde(
        rename = "neverAutoResolve",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub never_auto_resolve: Vec<ProhibitedQuestionClass>,
}

impl QuestionPolicy {
    fn validate(&self, slots: &BTreeMap<String, ModelSlot>) -> Result<()> {
        if self.decision_timeout_seconds == 0 {
            bail!("questions.decisionTimeoutSeconds must be positive when auto-answer is enabled");
        }
        if let Some(slot) = &self.resolver_slot
            && !slots.contains_key(slot)
        {
            bail!("questions.resolverSlot `{slot}` does not name a model slot");
        }
        let rendered: Vec<&str> = self
            .never_auto_resolve
            .iter()
            .map(|class| class.as_str())
            .collect();
        let mut canonical = rendered.clone();
        canonical.sort_unstable();
        canonical.dedup();
        if canonical.len() != rendered.len() || canonical != rendered {
            bail!("questions.neverAutoResolve must be sorted and unique");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoAnswer {
    RecommendedLowRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverOrder {
    WarmParentThenUtility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProhibitedQuestionClass {
    Credential,
    Authorization,
    Destructive,
    ExternalAction,
    Publish,
    Purchase,
    Production,
}

impl ProhibitedQuestionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Authorization => "authorization",
            Self::Destructive => "destructive",
            Self::ExternalAction => "external_action",
            Self::Publish => "publish",
            Self::Purchase => "purchase",
            Self::Production => "production",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationPolicy {
    pub rules: Vec<VerificationRule>,
}

impl VerificationPolicy {
    fn validate(&self, slots: &BTreeMap<String, ModelSlot>) -> Result<()> {
        if self.rules.is_empty() {
            bail!("verification.rules must be non-empty when verification is declared");
        }
        for rule in &self.rules {
            rule.validate(slots)?;
        }
        Ok(())
    }

    /// Deterministic first-match selection. `off` is deliberately a result,
    /// rather than a fallthrough, so explicit exclusions stay exclusions.
    pub fn select(&self, subject: &VerificationSubject<'_>) -> Option<&VerificationRule> {
        self.rules
            .iter()
            .find(|rule| rule.selector.matches(subject))
    }

    pub fn compile(&self) -> CompiledVerificationPolicy {
        self.compile_with_slots(&BTreeMap::new())
    }

    pub fn compile_with_slots(
        &self,
        slots: &BTreeMap<String, ModelSlot>,
    ) -> CompiledVerificationPolicy {
        let mut earlier = Vec::new();
        let mut regions = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            let mut rule = rule.clone();
            let _ = rule.expand_profile(slots);
            let selector = rule.selector.clone();
            regions.push(CompiledVerificationRegion {
                rule,
                excluded_by: earlier.clone(),
            });
            earlier.push(selector);
        }
        CompiledVerificationPolicy { regions }
    }
}

impl CompiledVerificationPolicy {
    pub fn select(&self, subject: &VerificationSubject<'_>) -> Option<&VerificationRule> {
        self.regions
            .iter()
            .find(|region| region.matches(subject))
            .map(|region| &region.rule)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRule {
    pub selector: VerificationSelector,
    pub action: VerificationAction,
    #[serde(
        rename = "maxCandidates",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_candidates: Option<u16>,
    #[serde(
        rename = "maxTotalTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_total_tokens: Option<u64>,
    #[serde(
        rename = "maxEstimatedCostMicrousd",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_estimated_cost_microusd: Option<u64>,
    #[serde(
        rename = "maxCollectionMillis",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_collection_millis: Option<u64>,
    #[serde(
        rename = "adjudicatorSlot",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub adjudicator_slot: Option<String>,
    #[serde(
        rename = "onBudgetExceeded",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub on_budget_exceeded: Option<OnBudgetExceeded>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<VerificationMode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generators: Vec<GeneratorSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(
        rename = "onAdjudicationFailure",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub on_adjudication_failure: Option<OnAdjudicationFailure>,
}

impl Default for VerificationRule {
    fn default() -> Self {
        Self {
            selector: VerificationSelector {
                all_of: Vec::new(),
                any_of: Vec::new(),
            },
            action: VerificationAction::Off,
            max_candidates: None,
            max_total_tokens: None,
            max_estimated_cost_microusd: None,
            max_collection_millis: None,
            adjudicator_slot: None,
            on_budget_exceeded: None,
            mode: None,
            generators: Vec::new(),
            profile: None,
            on_adjudication_failure: None,
        }
    }
}

/// Gate (default): approve the original or block with feedback. Revise:
/// apply an adjudicated variant through the ordinary write/edit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum VerificationMode {
    #[default]
    Gate,
    Revise,
}

/// What to do when the adjudicator fails or times out. Never hang the turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnAdjudicationFailure {
    #[default]
    DispatchOriginal,
    Refuse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratorSpec {
    pub slot: String,
    #[serde(default)]
    pub recipe: VerificationRecipe,
    #[serde(default = "default_max_turns", rename = "maxTurns")]
    pub max_turns: u8,
}

fn default_max_turns() -> u8 {
    1
}

impl Default for GeneratorSpec {
    fn default() -> Self {
        Self {
            slot: String::new(),
            recipe: VerificationRecipe::Inherit,
            max_turns: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerificationRecipe {
    Inherit,
    CleanRoom {
        #[serde(default, rename = "includeLinkedFiles")]
        include_linked_files: bool,
        #[serde(default = "default_last_n_reads", rename = "lastNReads")]
        last_n_reads: u8,
    },
}

fn default_last_n_reads() -> u8 {
    3
}

impl Default for VerificationRecipe {
    fn default() -> Self {
        Self::Inherit
    }
}

impl VerificationRecipe {
    pub fn inherit() -> Self {
        Self::Inherit
    }

    pub fn clean_room_default() -> Self {
        Self::CleanRoom {
            include_linked_files: false,
            last_n_reads: default_last_n_reads(),
        }
    }
}

/// Builtin profile names. Explicit rule fields win over these defaults.
pub const PROFILE_SELF_CHECK: &str = "self-check";
pub const PROFILE_CLEAN_ROOM: &str = "clean-room";
pub const PROFILE_PANEL: &str = "panel";
pub const MAX_GENERATOR_TURNS: u8 = 4;

struct ExpandedProfile {
    mode: VerificationMode,
    generators: Vec<GeneratorSpec>,
    adjudicator_slot: Option<String>,
}

fn author_slot(slots: &BTreeMap<String, ModelSlot>) -> String {
    if slots.contains_key("primary") {
        "primary".to_string()
    } else {
        slots.keys().next().cloned().unwrap_or_else(|| "primary".to_string())
    }
}

fn expand_builtin_profile(
    name: &str,
    rule: &VerificationRule,
    slots: &BTreeMap<String, ModelSlot>,
) -> Result<ExpandedProfile> {
    let author = author_slot(slots);
    let adjudicator = rule
        .adjudicator_slot
        .clone()
        .unwrap_or_else(|| author.clone());
    match name {
        PROFILE_SELF_CHECK => Ok(ExpandedProfile {
            mode: VerificationMode::Gate,
            generators: vec![GeneratorSpec {
                slot: author,
                recipe: VerificationRecipe::Inherit,
                max_turns: 1,
            }],
            adjudicator_slot: Some(adjudicator),
        }),
        PROFILE_CLEAN_ROOM => Ok(ExpandedProfile {
            mode: VerificationMode::Gate,
            generators: vec![GeneratorSpec {
                slot: adjudicator.clone(),
                recipe: VerificationRecipe::clean_room_default(),
                max_turns: 1,
            }],
            adjudicator_slot: Some(adjudicator),
        }),
        PROFILE_PANEL => {
            let n = rule.resolved_max_candidates().max(1);
            let mut generators = Vec::with_capacity(n as usize);
            generators.push(GeneratorSpec {
                slot: author,
                recipe: VerificationRecipe::Inherit,
                max_turns: 1,
            });
            while generators.len() < n as usize {
                generators.push(GeneratorSpec {
                    slot: adjudicator.clone(),
                    recipe: VerificationRecipe::clean_room_default(),
                    max_turns: 1,
                });
            }
            Ok(ExpandedProfile {
                mode: VerificationMode::Revise,
                generators,
                adjudicator_slot: Some(adjudicator),
            })
        }
        other => bail!("unknown verification profile `{other}`"),
    }
}

impl VerificationRule {
    /// Expand a builtin `profile` into field defaults. Explicit fields win.
    pub fn expand_profile(&mut self, slots: &BTreeMap<String, ModelSlot>) -> Result<()> {
        let Some(profile) = self.profile.as_deref() else {
            return Ok(());
        };
        let expanded = expand_builtin_profile(profile, self, slots)?;
        if self.mode.is_none() {
            self.mode = Some(expanded.mode);
        }
        if self.generators.is_empty() {
            self.generators = expanded.generators;
        }
        if self.action == VerificationAction::Verify && self.adjudicator_slot.is_none() {
            self.adjudicator_slot = expanded.adjudicator_slot;
        }
        Ok(())
    }

    pub fn resolved_mode(&self) -> VerificationMode {
        self.mode.unwrap_or(VerificationMode::Gate)
    }

    pub fn resolved_on_adjudication_failure(&self) -> OnAdjudicationFailure {
        self.on_adjudication_failure
            .unwrap_or(OnAdjudicationFailure::DispatchOriginal)
    }

    /// Custody note: inherit generators on untrusted slots see a redacted
    /// transcript and produce placeholder-bearing (invalid) candidates.
    pub fn inherit_untrusted_slot_warnings(&self, untrusted_slots: &BTreeSet<String>) -> Vec<String> {
        self.generators
            .iter()
            .filter(|generator| {
                matches!(generator.recipe, VerificationRecipe::Inherit)
                    && untrusted_slots.contains(&generator.slot)
            })
            .map(|generator| {
                format!(
                    "verification inherit generator on untrusted slot `{}` will receive a redacted transcript; placeholder-bearing candidates are invalid and never selectable",
                    generator.slot
                )
            })
            .collect()
    }

    fn validate(&self, slots: &BTreeMap<String, ModelSlot>) -> Result<()> {
        let mut rule = self.clone();
        rule.expand_profile(slots)?;
        rule.selector.validate()?;
        let bounded = [
            ("maxCandidates", rule.max_candidates.map(u64::from)),
            ("maxTotalTokens", rule.max_total_tokens),
            ("maxEstimatedCostMicrousd", rule.max_estimated_cost_microusd),
            ("maxCollectionMillis", rule.max_collection_millis),
        ];
        for (name, value) in bounded {
            if value == Some(0) {
                bail!("verification.{name} must be positive");
            }
        }
        match rule.action {
            VerificationAction::Off => {
                if rule.max_candidates.is_some()
                    || rule.max_total_tokens.is_some()
                    || rule.max_estimated_cost_microusd.is_some()
                    || rule.max_collection_millis.is_some()
                    || rule.adjudicator_slot.is_some()
                    || rule.on_budget_exceeded.is_some()
                    || rule.mode.is_some()
                    || !rule.generators.is_empty()
                    || rule.profile.is_some()
                    || rule.on_adjudication_failure.is_some()
                {
                    bail!("verification action `off` only permits selector");
                }
            }
            VerificationAction::Verify => {
                let Some(slot) = &rule.adjudicator_slot else {
                    bail!("verification action `verify` requires adjudicatorSlot");
                };
                if !slots.contains_key(slot) {
                    bail!("verification.adjudicatorSlot `{slot}` does not name a model slot");
                }
                for generator in &rule.generators {
                    if generator.slot.is_empty() || !slots.contains_key(&generator.slot) {
                        bail!(
                            "verification generator slot `{}` does not name a model slot",
                            generator.slot
                        );
                    }
                    if generator.max_turns == 0 {
                        bail!("verification generator maxTurns must be positive");
                    }
                    if generator.max_turns > MAX_GENERATOR_TURNS {
                        bail!(
                            "verification generator maxTurns must be <= {MAX_GENERATOR_TURNS}"
                        );
                    }
                    if let VerificationRecipe::CleanRoom { last_n_reads, .. } = generator.recipe
                        && last_n_reads == 0
                    {
                        bail!("verification cleanRoom.lastNReads must be positive");
                    }
                }
            }
        }
        Ok(())
    }

    pub fn resolved_max_candidates(&self) -> u16 {
        self.max_candidates.unwrap_or(DEFAULT_MAX_CANDIDATES)
    }

    pub fn requested_budget(&self, ceiling: VerificationBudget) -> Result<VerificationBudget> {
        let requested = VerificationBudget {
            max_candidates: self.resolved_max_candidates(),
            max_total_tokens: self.max_total_tokens.unwrap_or(ceiling.max_total_tokens),
            max_estimated_cost_microusd: self
                .max_estimated_cost_microusd
                .unwrap_or(ceiling.max_estimated_cost_microusd),
            max_collection_millis: self
                .max_collection_millis
                .unwrap_or(ceiling.max_collection_millis),
        };
        if !ceiling.contains(requested) {
            bail!("verification budget exceeds the host ceiling");
        }
        Ok(requested)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationAction {
    Off,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnBudgetExceeded {
    Refuse,
    DispatchOriginal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSelector {
    #[serde(rename = "allOf", default, skip_serializing_if = "Vec::is_empty")]
    pub all_of: Vec<SelectorPredicate>,
    #[serde(rename = "anyOf", default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<SelectorPredicate>,
}

impl VerificationSelector {
    fn validate(&self) -> Result<()> {
        if self.all_of.is_empty() && self.any_of.is_empty() {
            bail!("verification selector requires allOf and/or anyOf");
        }
        validate_predicates(&self.all_of, "allOf")?;
        validate_predicates(&self.any_of, "anyOf")?;
        Ok(())
    }

    pub fn matches(&self, subject: &VerificationSubject<'_>) -> bool {
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(untagged)]
pub enum SelectorPredicate {
    ToolClass {
        #[serde(rename = "toolClass")]
        tool_class: ToolClass,
    },
    ToolId {
        #[serde(rename = "toolId")]
        tool_id: String,
    },
    Namespace {
        namespace: String,
    },
}

impl<'de> Deserialize<'de> for SelectorPredicate {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let mut fields = BTreeMap::<String, String>::deserialize(deserializer)?;
        if fields.len() != 1 {
            return Err(serde::de::Error::custom(
                "selector predicate must contain exactly one closed tag",
            ));
        }
        let (field, value) = fields.pop_first().expect("checked one predicate field");
        match field.as_str() {
            "toolClass" => match value.as_str() {
                "evidence" => Ok(Self::ToolClass {
                    tool_class: ToolClass::Evidence,
                }),
                "artifact_write" => Ok(Self::ToolClass {
                    tool_class: ToolClass::ArtifactWrite,
                }),
                "shell" => Ok(Self::ToolClass {
                    tool_class: ToolClass::Shell,
                }),
                "computer" => Ok(Self::ToolClass {
                    tool_class: ToolClass::Computer,
                }),
                _ => Err(serde::de::Error::custom(format!(
                    "unknown toolClass `{value}`"
                ))),
            },
            "toolId" => Ok(Self::ToolId { tool_id: value }),
            "namespace" => Ok(Self::Namespace { namespace: value }),
            _ => Err(serde::de::Error::custom(format!(
                "unknown selector predicate `{field}`"
            ))),
        }
    }
}

impl SelectorPredicate {
    fn matches(&self, subject: &VerificationSubject<'_>) -> bool {
        match self {
            Self::ToolClass { tool_class } => *tool_class == subject.tool_class,
            Self::ToolId { tool_id } => *tool_id == subject.tool_id,
            Self::Namespace { namespace } => *namespace == subject.namespace,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolClass {
    Evidence,
    ArtifactWrite,
    Shell,
    Computer,
}

pub struct VerificationSubject<'a> {
    pub tool_class: ToolClass,
    pub tool_id: &'a str,
    pub namespace: &'a str,
}

fn validate_predicates(predicates: &[SelectorPredicate], field: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for predicate in predicates {
        match predicate {
            SelectorPredicate::ToolId { tool_id } => {
                validate_canonical_tool_identifier(tool_id, "toolId")?;
                if !crate::agents::invariants::known_tool_names().contains(&tool_id.as_str()) {
                    bail!(
                        "verification selector toolId `{tool_id}` is not in the canonical ordinary-tool registry"
                    );
                }
            }
            SelectorPredicate::Namespace { namespace } => {
                validate_canonical_tool_identifier(namespace, "namespace")?
            }
            SelectorPredicate::ToolClass { .. } => {}
        }
        if !seen.insert(predicate) {
            bail!("verification selector {field} contains a duplicate predicate");
        }
    }
    Ok(())
}

fn validate_agent_id(value: &str) -> Result<()> {
    let Some((publisher, slug)) = value.split_once('/') else {
        bail!("agentId must be ASCII `publisher/slug`");
    };
    if value.matches('/').count() != 1 {
        bail!("agentId must be ASCII `publisher/slug`");
    }
    validate_agent_segment(publisher, "agentId publisher")?;
    validate_agent_segment(slug, "agentId slug")?;
    if publisher == "local" && Uuid::parse_str(slug).is_err() {
        bail!("daemon-local agentId must be exactly `local/<UUID>`");
    }
    Ok(())
}

fn validate_upstream_identity(value: &str) -> Result<()> {
    let Some((publisher, family)) = value.split_once('/') else {
        bail!("upstreamIdentity must be lowercase ASCII `publisher/model-family`");
    };
    if value.matches('/').count() != 1 {
        bail!("upstreamIdentity must be lowercase ASCII `publisher/model-family`");
    }
    validate_agent_segment(publisher, "upstreamIdentity publisher")?;
    validate_agent_segment(family, "upstreamIdentity model-family")
}

fn validate_agent_segment(value: &str, field: &str) -> Result<()> {
    let mut chars = value.bytes();
    let Some(first) = chars.next() else {
        bail!("{field} must be non-empty");
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        bail!("{field} must be lowercase ASCII and begin with alphanumeric");
    }
    if !chars.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        bail!("{field} must be lowercase ASCII `[a-z0-9][a-z0-9._-]*`");
    }
    Ok(())
}

fn validate_ascii_identifier(value: &str, field: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        bail!("{field} must be non-empty ASCII identifier");
    };
    if !first.is_ascii_alphabetic() && !first.is_ascii_digit() {
        bail!("{field} must begin with ASCII alphanumeric");
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')) {
        bail!("{field} must be ASCII identifier");
    }
    Ok(())
}

fn validate_canonical_tool_identifier(value: &str, field: &str) -> Result<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        bail!("verification selector {field} must be an exact canonical identifier");
    };
    if !first.is_ascii_lowercase()
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b'/')
        })
    {
        bail!("verification selector {field} must be an exact canonical identifier");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> VnextAgentDef {
        VnextAgentDef {
            schema_version: 2,
            agent_id: "acme/reviewer".to_string(),
            execution_kind: ExecutionKind::Coding,
            model_slots: BTreeMap::from([(
                "primary".to_string(),
                ModelSlot {
                    purpose: "review source".to_string(),
                    min_context_tokens: 1,
                    required_capabilities: vec![ModelCapability::TextGeneration],
                    locality: ModelLocality::Any,
                    allow_default_fallback: false,
                    suggested_models: vec![],
                },
            )]),
            delegation: DelegationPolicy::default(),
            questions: None,
            verification: None,
        }
    }

    #[test]
    fn agent_vnext_verification_first_match_keeps_off_exclusion() {
        let mut definition = valid();
        definition.verification = Some(VerificationPolicy {
            rules: vec![
                VerificationRule {
                    selector: VerificationSelector {
                        all_of: vec![SelectorPredicate::ToolId {
                            tool_id: "write".into(),
                        }],
                        any_of: vec![],
                    },
                    action: VerificationAction::Off,
                    max_candidates: None,
                    max_total_tokens: None,
                    max_estimated_cost_microusd: None,
                    max_collection_millis: None,
                    adjudicator_slot: None,
                    on_budget_exceeded: None,
                    ..Default::default()
                },
                VerificationRule {
                    selector: VerificationSelector {
                        all_of: vec![],
                        any_of: vec![SelectorPredicate::ToolClass {
                            tool_class: ToolClass::ArtifactWrite,
                        }],
                    },
                    action: VerificationAction::Verify,
                    max_candidates: None,
                    max_total_tokens: None,
                    max_estimated_cost_microusd: None,
                    max_collection_millis: None,
                    adjudicator_slot: Some("primary".into()),
                    on_budget_exceeded: Some(OnBudgetExceeded::Refuse),
                    ..Default::default()
                },
            ],
        });
        definition.validate().unwrap();
        let policy = definition.verification.unwrap();
        assert_eq!(
            policy
                .select(&VerificationSubject {
                    tool_class: ToolClass::ArtifactWrite,
                    tool_id: "write",
                    namespace: "host"
                })
                .unwrap()
                .action,
            VerificationAction::Off
        );
    }

    #[test]
    fn agent_vnext_compiled_regions_keep_later_matches_off_after_an_exclusion() {
        let policy = VerificationPolicy {
            rules: vec![
                VerificationRule {
                    selector: VerificationSelector {
                        all_of: vec![SelectorPredicate::ToolId {
                            tool_id: "write".into(),
                        }],
                        any_of: vec![],
                    },
                    action: VerificationAction::Off,
                    max_candidates: None,
                    max_total_tokens: None,
                    max_estimated_cost_microusd: None,
                    max_collection_millis: None,
                    adjudicator_slot: None,
                    on_budget_exceeded: None,
                    ..Default::default()
                },
                VerificationRule {
                    selector: VerificationSelector {
                        all_of: vec![],
                        any_of: vec![SelectorPredicate::ToolClass {
                            tool_class: ToolClass::ArtifactWrite,
                        }],
                    },
                    action: VerificationAction::Verify,
                    max_candidates: None,
                    max_total_tokens: None,
                    max_estimated_cost_microusd: None,
                    max_collection_millis: None,
                    adjudicator_slot: Some("primary".into()),
                    on_budget_exceeded: None,
                    ..Default::default()
                },
            ],
        };
        let compiled = policy.compile();
        assert_eq!(compiled.regions.len(), 2);
        assert_eq!(compiled.regions[1].excluded_by.len(), 1);
        assert!(
            compiled
                .select(&VerificationSubject {
                    tool_class: ToolClass::ArtifactWrite,
                    tool_id: "write",
                    namespace: "host",
                })
                .is_some_and(|rule| rule.action == VerificationAction::Off)
        );
    }

    #[test]
    fn agent_vnext_delegation_kind_matrix_rejects_assistant_children_and_computer_fanout() {
        assert!(delegation_kind_permitted(
            ExecutionKind::Assistant,
            ExecutionKind::Coding,
            false
        ));
        assert!(!delegation_kind_permitted(
            ExecutionKind::Coding,
            ExecutionKind::Assistant,
            true
        ));
        assert!(!delegation_kind_permitted(
            ExecutionKind::Computer,
            ExecutionKind::Coding,
            true
        ));
        assert!(delegation_kind_permitted(
            ExecutionKind::Assistant,
            ExecutionKind::Computer,
            true
        ));
        assert!(delegation_kind_permitted(
            ExecutionKind::Coding,
            ExecutionKind::Computer,
            true
        ));
        assert!(!delegation_kind_permitted(
            ExecutionKind::Coding,
            ExecutionKind::Computer,
            false
        ));
        for caller in [
            ExecutionKind::Assistant,
            ExecutionKind::Coding,
            ExecutionKind::Computer,
        ] {
            assert!(
                !delegation_kind_permitted(caller, ExecutionKind::Assistant, true),
                "{caller:?} must not delegate to an assistant"
            );
        }
        for child in [
            ExecutionKind::Assistant,
            ExecutionKind::Coding,
            ExecutionKind::Computer,
        ] {
            assert!(
                !delegation_kind_permitted(ExecutionKind::Computer, child, true),
                "computer must remain a leaf for {child:?}"
            );
        }
    }

    #[test]
    fn agent_vnext_delegation_rejects_duplicate_children() {
        let mut definition = valid();
        definition.delegation = DelegationPolicy {
            allowed_children: vec![
                AllowedChild::PortableRef {
                    portable_agent_ref: "acme/child".into(),
                },
                AllowedChild::PortableRef {
                    portable_agent_ref: "acme/child".into(),
                },
            ],
            max_descendant_depth: Some(1),
            max_concurrent_children: Some(1),
            targets: vec![DelegationTarget::SameRoot],
        };
        assert!(definition.validate().is_err());
    }

    #[test]
    fn agent_vnext_child_grant_intersects_parent_depth_and_targets() {
        let mut parent = valid();
        parent.delegation = DelegationPolicy {
            allowed_children: vec![AllowedChild::PortableRef {
                portable_agent_ref: "acme/child".into(),
            }],
            max_descendant_depth: Some(1),
            max_concurrent_children: Some(1),
            targets: vec![DelegationTarget::SameRoot],
        };
        let mut child = valid();
        child.agent_id = "acme/child".into();
        child.delegation = DelegationPolicy {
            allowed_children: vec![AllowedChild::PortableRef {
                portable_agent_ref: "acme/grandchild".into(),
            }],
            max_descendant_depth: Some(2),
            max_concurrent_children: Some(1),
            targets: vec![DelegationTarget::SameRoot],
        };
        let parent_grant = parent.resolve_grant(&host()).unwrap();
        let child_grant = child
            .resolve_child_grant(
                &host(),
                &parent_grant,
                &AllowedChild::PortableRef {
                    portable_agent_ref: "acme/child".into(),
                },
            )
            .unwrap();
        assert!(child_grant.delegation.is_none());
    }

    #[test]
    fn agent_vnext_runtime_grant_defaults_to_leaf_and_bounds_a_declared_tree() {
        let host = host();
        let mut minimal = valid();
        minimal.agent_id = "local/00000000-0000-0000-0000-000000000001".into();
        assert!(minimal.resolve_grant(&host).unwrap().delegation.is_none());

        let mut root = valid();
        root.agent_id = "acme/root".into();
        root.delegation = DelegationPolicy {
            allowed_children: vec![AllowedChild::PortableRef {
                portable_agent_ref: "acme/child".into(),
            }],
            max_descendant_depth: Some(2),
            max_concurrent_children: Some(1),
            targets: vec![DelegationTarget::SameRoot],
        };
        let mut child = valid();
        child.agent_id = "acme/child".into();
        child.delegation = DelegationPolicy {
            allowed_children: vec![AllowedChild::PortableRef {
                portable_agent_ref: "acme/grandchild".into(),
            }],
            max_descendant_depth: Some(2),
            max_concurrent_children: Some(1),
            targets: vec![DelegationTarget::SameRoot],
        };
        let mut grandchild = valid();
        grandchild.agent_id = "acme/grandchild".into();
        grandchild.delegation = DelegationPolicy {
            allowed_children: vec![AllowedChild::PortableRef {
                portable_agent_ref: "acme/too-deep".into(),
            }],
            max_descendant_depth: Some(1),
            max_concurrent_children: Some(1),
            targets: vec![DelegationTarget::SameRoot],
        };
        let root_grant = root.resolve_grant(&host).unwrap();
        let child_ref = root_grant.delegation.as_ref().unwrap().allowed_children[0].clone();
        assert!(root_grant.permits_child(&child_ref, child.execution_kind));
        let child_grant = child
            .resolve_child_grant(&host, &root_grant, &child_ref)
            .unwrap();
        let grandchild_ref = child_grant.delegation.as_ref().unwrap().allowed_children[0].clone();
        let grandchild_grant = grandchild
            .resolve_child_grant(&host, &child_grant, &grandchild_ref)
            .unwrap();
        assert!(grandchild_grant.delegation.is_none());
    }

    #[test]
    fn agent_vnext_local_installation_resolver_keeps_exact_uuid_launch_targets() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let first_identity = LocalInstallationIdentity {
            launch_target: "reviewer-a".to_string(),
            agent_id: "local/00000000-0000-0000-0000-000000000001".to_string(),
            definition_digest: "a".repeat(64),
        };
        let resolver = LocalInstallationResolver::from_bindings(BTreeMap::from([(
            first,
            first_identity.clone(),
        )]))
        .unwrap();
        assert_eq!(resolver.resolve(first).unwrap(), &first_identity);
        assert!(resolver.resolve(second).is_err());
        // Distinct daemon-local installations may intentionally be copies of
        // the same definition. UUID identity, not content de-duplication,
        // is the authorization key.
        let copied = LocalInstallationIdentity {
            launch_target: "reviewer-b".to_string(),
            ..first_identity.clone()
        };
        assert!(
            LocalInstallationResolver::from_bindings(BTreeMap::from([
                (first, first_identity),
                (second, copied),
            ]))
            .is_ok()
        );
    }

    #[test]
    fn agent_vnext_local_installation_factory_check_rejects_name_shadowing() {
        let installation_id = Uuid::new_v4();
        let mut selected = valid();
        let selected_name = "trusted-helper";
        selected.agent_id = format!("local/{installation_id}");
        let identity = LocalInstallationIdentity::from_definition(&crate::agents::AgentDef {
            name: selected_name.into(),
            description: "trusted".into(),
            mode: crate::agents::AgentMode::Primary,
            model: None,
            temperature: None,
            tools: None,
            tool_tiers: BTreeMap::new(),
            tool_descriptions: BTreeMap::new(),
            scan_tool_results: None,
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: Some(selected.clone()),
            prompt: "body".into(),
            prompt_overrides: std::collections::BTreeMap::new(),
            source: std::path::PathBuf::new(),
        })
        .unwrap();
        let resolver = LocalInstallationResolver::from_bindings(BTreeMap::from([(
            installation_id,
            LocalInstallationIdentity {
                launch_target: "trusted-helper".into(),
                ..identity
            },
        )]))
        .unwrap();
        let definition = crate::agents::AgentDef {
            name: selected_name.into(),
            description: "trusted".into(),
            mode: crate::agents::AgentMode::Primary,
            model: None,
            temperature: None,
            tools: None,
            tool_tiers: BTreeMap::new(),
            tool_descriptions: BTreeMap::new(),
            scan_tool_results: None,
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: Some(selected),
            prompt: "body".into(),
            prompt_overrides: std::collections::BTreeMap::new(),
            source: std::path::PathBuf::new(),
        };
        assert!(resolver.matches_definition(installation_id, "trusted-helper", &definition));

        let mut shadow = definition.clone();
        shadow.name = "shadow-helper".into();
        assert!(!resolver.matches_definition(installation_id, "shadow-helper", &shadow));
    }

    #[test]
    fn agent_vnext_child_grant_intersects_parent_child_and_host_concurrency() {
        let mut parent = valid();
        parent.delegation = DelegationPolicy {
            allowed_children: vec![AllowedChild::PortableRef {
                portable_agent_ref: "acme/child".into(),
            }],
            max_descendant_depth: Some(2),
            max_concurrent_children: Some(1),
            targets: vec![DelegationTarget::SameRoot],
        };
        let mut child = valid();
        child.agent_id = "acme/child".into();
        child.delegation = DelegationPolicy {
            allowed_children: vec![AllowedChild::PortableRef {
                portable_agent_ref: "acme/grandchild".into(),
            }],
            max_descendant_depth: Some(1),
            max_concurrent_children: Some(2),
            targets: vec![DelegationTarget::SameRoot],
        };
        let mut host = host();
        host.max_concurrent_children = 2;
        let parent_grant = parent.resolve_grant(&host).unwrap();
        let child_grant = child
            .resolve_child_grant(
                &host,
                &parent_grant,
                &AllowedChild::PortableRef {
                    portable_agent_ref: "acme/child".into(),
                },
            )
            .unwrap();
        assert_eq!(
            child_grant
                .delegation
                .as_ref()
                .expect("child retains one descendant edge")
                .max_concurrent_children,
            1
        );
    }

    #[test]
    fn agent_vnext_effective_target_checks_actual_child_cwd() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let child = root.join("child");
        std::fs::create_dir(&child).unwrap();
        let mut definition = valid();
        definition.delegation = DelegationPolicy {
            allowed_children: vec![AllowedChild::PortableRef {
                portable_agent_ref: "acme/child".into(),
            }],
            max_descendant_depth: Some(1),
            max_concurrent_children: Some(1),
            targets: vec![DelegationTarget::Subdirectory],
        };
        let mut policy = host();
        policy
            .allowed_targets
            .insert(DelegationTarget::Subdirectory);
        let grant = definition.resolve_grant(&policy).unwrap();
        assert!(grant.permits_target(root, &child));
        assert!(!grant.permits_target(root, root));
    }

    fn host() -> VnextHostPolicy {
        VnextHostPolicy {
            max_descendant_depth: 3,
            max_concurrent_children: 2,
            allowed_targets: BTreeSet::from([DelegationTarget::SameRoot]),
            computer_delegation_enabled: false,
            non_auto_resolvable: BTreeSet::from([ProhibitedQuestionClass::Credential]),
            max_question_timeout_seconds: 60,
            verification_ceiling: VerificationBudget {
                max_candidates: 5,
                max_total_tokens: 1_000,
                max_estimated_cost_microusd: 2_000,
                max_collection_millis: 3_000,
            },
        }
    }

    fn questions(timeout: u32, prohibited: Vec<ProhibitedQuestionClass>) -> QuestionPolicy {
        QuestionPolicy {
            auto_answer: AutoAnswer::RecommendedLowRisk,
            decision_timeout_seconds: timeout,
            resolver_order: ResolverOrder::WarmParentThenUtility,
            resolver_slot: Some("primary".into()),
            never_auto_resolve: prohibited,
        }
    }

    #[test]
    fn agent_vnext_question_override_monotonic_off_cannot_be_enabled() {
        assert!(
            resolve_question_policy(
                None,
                &host(),
                QuestionOverride::Reduce(questions(30, vec![])),
            )
            .is_err()
        );
    }

    #[test]
    fn agent_vnext_question_override_monotonic_disable_is_strictest() {
        assert_eq!(
            resolve_question_policy(
                Some(&questions(30, vec![])),
                &host(),
                QuestionOverride::Disable,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn agent_vnext_question_override_monotonic_longer_timeout_and_union() {
        let resolved = resolve_question_policy(
            Some(&questions(30, vec![ProhibitedQuestionClass::Authorization])),
            &host(),
            QuestionOverride::Reduce(questions(45, vec![ProhibitedQuestionClass::Production])),
        )
        .unwrap()
        .unwrap();
        assert_eq!(resolved.decision_timeout_seconds, 45);
        assert!(
            resolved
                .never_auto_resolve
                .contains(&ProhibitedQuestionClass::Credential)
        );
        assert!(
            resolved
                .never_auto_resolve
                .contains(&ProhibitedQuestionClass::Authorization)
        );
        assert!(
            resolved
                .never_auto_resolve
                .contains(&ProhibitedQuestionClass::Production)
        );
    }

    #[test]
    fn agent_vnext_question_override_monotonic_shorter_or_above_ceiling_rejected() {
        assert!(
            resolve_question_policy(
                Some(&questions(30, vec![])),
                &host(),
                QuestionOverride::Reduce(questions(29, vec![])),
            )
            .is_err()
        );
        assert!(
            resolve_question_policy(
                Some(&questions(30, vec![])),
                &host(),
                QuestionOverride::Reduce(questions(61, vec![])),
            )
            .is_err()
        );
    }

    #[test]
    fn agent_vnext_verification_budget_reduces_or_uses_selected_fallback() {
        let mut definition = valid();
        definition.verification = Some(VerificationPolicy {
            rules: vec![VerificationRule {
                selector: VerificationSelector {
                    all_of: vec![SelectorPredicate::ToolId {
                        tool_id: "write".into(),
                    }],
                    any_of: vec![],
                },
                action: VerificationAction::Verify,
                max_candidates: Some(2),
                max_total_tokens: Some(100),
                max_estimated_cost_microusd: Some(200),
                max_collection_millis: Some(300),
                adjudicator_slot: Some("primary".into()),
                on_budget_exceeded: Some(OnBudgetExceeded::DispatchOriginal),
                ..Default::default()
            }],
        });
        let subject = VerificationSubject {
            tool_class: ToolClass::ArtifactWrite,
            tool_id: "write",
            namespace: "host",
        };
        assert_eq!(
            definition
                .resolve_verification(
                    &host(),
                    &subject,
                    Some(VerificationBudget {
                        max_candidates: 1,
                        max_total_tokens: 90,
                        max_estimated_cost_microusd: 190,
                        max_collection_millis: 290,
                    }),
                    VerificationEstimate::Known(VerificationBudget {
                        max_candidates: 1,
                        max_total_tokens: 80,
                        max_estimated_cost_microusd: 180,
                        max_collection_millis: 280,
                    }),
                )
                .unwrap(),
            VerificationDispatch::Verify {
                budget: VerificationBudget {
                    max_candidates: 1,
                    max_total_tokens: 90,
                    max_estimated_cost_microusd: 190,
                    max_collection_millis: 290,
                },
                adjudicator_slot: "primary".into(),
            }
        );
        assert_eq!(
            definition
                .resolve_verification(&host(), &subject, None, VerificationEstimate::UnknownPrice,)
                .unwrap(),
            VerificationDispatch::DispatchOriginal
        );
        assert_eq!(
            definition
                .resolve_verification(&host(), &subject, None, VerificationEstimate::UnknownTokens,)
                .unwrap(),
            VerificationDispatch::DispatchOriginal
        );
    }

    #[test]
    fn agent_vnext_verification_no_match_is_off_and_default_budget_failure_refuses() {
        let mut definition = valid();
        definition.verification = Some(VerificationPolicy {
            rules: vec![VerificationRule {
                selector: VerificationSelector {
                    all_of: vec![SelectorPredicate::ToolClass {
                        tool_class: ToolClass::ArtifactWrite,
                    }],
                    any_of: vec![SelectorPredicate::ToolId {
                        tool_id: "write".into(),
                    }],
                },
                action: VerificationAction::Verify,
                max_candidates: Some(1),
                max_total_tokens: Some(10),
                max_estimated_cost_microusd: Some(10),
                max_collection_millis: Some(10),
                adjudicator_slot: Some("primary".into()),
                // Omission is the closed-schema default: refuse before a
                // candidate can run when any estimate exceeds a dimension.
                on_budget_exceeded: None,
                ..Default::default()
            }],
        });
        let no_match = VerificationSubject {
            tool_class: ToolClass::Shell,
            tool_id: "bash",
            namespace: "host",
        };
        assert_eq!(
            definition
                .resolve_verification(
                    &host(),
                    &no_match,
                    None,
                    VerificationEstimate::Known(VerificationBudget {
                        max_candidates: 1,
                        max_total_tokens: 1,
                        max_estimated_cost_microusd: 1,
                        max_collection_millis: 1,
                    }),
                )
                .unwrap(),
            VerificationDispatch::Off
        );
        let subject = VerificationSubject {
            tool_class: ToolClass::ArtifactWrite,
            tool_id: "write",
            namespace: "host",
        };
        for estimate in [
            VerificationBudget {
                max_candidates: 2,
                max_total_tokens: 1,
                max_estimated_cost_microusd: 1,
                max_collection_millis: 1,
            },
            VerificationBudget {
                max_candidates: 1,
                max_total_tokens: 11,
                max_estimated_cost_microusd: 1,
                max_collection_millis: 1,
            },
            VerificationBudget {
                max_candidates: 1,
                max_total_tokens: 1,
                max_estimated_cost_microusd: 11,
                max_collection_millis: 1,
            },
            VerificationBudget {
                max_candidates: 1,
                max_total_tokens: 1,
                max_estimated_cost_microusd: 1,
                max_collection_millis: 11,
            },
        ] {
            assert_eq!(
                definition
                    .resolve_verification(
                        &host(),
                        &subject,
                        None,
                        VerificationEstimate::Known(estimate),
                    )
                    .unwrap(),
                VerificationDispatch::Refuse
            );
        }
    }

    #[test]
    fn agent_vnext_verification_rejects_ceiling_widening_and_off_fields() {
        let mut definition = valid();
        definition.verification = Some(VerificationPolicy {
            rules: vec![VerificationRule {
                selector: VerificationSelector {
                    all_of: vec![SelectorPredicate::ToolId {
                        tool_id: "write".into(),
                    }],
                    any_of: vec![],
                },
                action: VerificationAction::Verify,
                max_candidates: Some(6),
                max_total_tokens: Some(1),
                max_estimated_cost_microusd: Some(1),
                max_collection_millis: Some(1),
                adjudicator_slot: Some("primary".into()),
                on_budget_exceeded: None,
                ..Default::default()
            }],
        });
        let subject = VerificationSubject {
            tool_class: ToolClass::ArtifactWrite,
            tool_id: "write",
            namespace: "host",
        };
        assert!(
            definition
                .resolve_verification(
                    &host(),
                    &subject,
                    None,
                    VerificationEstimate::Known(VerificationBudget {
                        max_candidates: 1,
                        max_total_tokens: 1,
                        max_estimated_cost_microusd: 1,
                        max_collection_millis: 1,
                    }),
                )
                .is_err()
        );

        definition.verification.as_mut().unwrap().rules[0].action = VerificationAction::Off;
        assert!(definition.validate().is_err());
    }

    #[test]
    fn agent_vnext_session_verification_restriction_is_an_explicit_off_mask() {
        let mut definition = valid();
        definition.verification = Some(VerificationPolicy {
            rules: vec![VerificationRule {
                selector: VerificationSelector {
                    all_of: vec![SelectorPredicate::ToolClass {
                        tool_class: ToolClass::ArtifactWrite,
                    }],
                    any_of: vec![],
                },
                action: VerificationAction::Verify,
                max_candidates: Some(1),
                max_total_tokens: Some(10),
                max_estimated_cost_microusd: Some(10),
                max_collection_millis: Some(10),
                adjudicator_slot: Some("primary".into()),
                on_budget_exceeded: None,
                ..Default::default()
            }],
        });
        let dispatch = definition
            .resolve_verification_with_session(
                &host(),
                &VerificationSubject {
                    tool_class: ToolClass::ArtifactWrite,
                    tool_id: "write",
                    namespace: "host",
                },
                VerificationSessionReduction::Restrict {
                    selector: VerificationSelector {
                        all_of: vec![SelectorPredicate::Namespace {
                            namespace: "mcp/server".into(),
                        }],
                        any_of: vec![],
                    },
                    budget: None,
                },
                None,
                VerificationEstimate::Known(VerificationBudget {
                    max_candidates: 1,
                    max_total_tokens: 1,
                    max_estimated_cost_microusd: 1,
                    max_collection_millis: 1,
                }),
            )
            .unwrap();
        assert_eq!(dispatch, VerificationDispatch::Off);
    }

    #[test]
    fn verification_profile_self_check_expands_to_inherit_gate() {
        let mut definition = valid();
        definition.verification = Some(VerificationPolicy {
            rules: vec![VerificationRule {
                selector: VerificationSelector {
                    all_of: vec![SelectorPredicate::ToolClass {
                        tool_class: ToolClass::ArtifactWrite,
                    }],
                    any_of: vec![],
                },
                action: VerificationAction::Verify,
                adjudicator_slot: Some("primary".into()),
                profile: Some(PROFILE_SELF_CHECK.into()),
                ..Default::default()
            }],
        });
        definition.validate().unwrap();
        let compiled = definition.verification.as_ref().unwrap().compile();
        let rule = &compiled.regions[0].rule;
        assert_eq!(rule.resolved_mode(), VerificationMode::Gate);
        assert_eq!(rule.generators.len(), 1);
        assert_eq!(rule.generators[0].slot, "primary");
        assert_eq!(rule.generators[0].recipe, VerificationRecipe::Inherit);
        assert_eq!(rule.generators[0].max_turns, 1);
    }

    #[test]
    fn verification_profile_clean_room_and_panel_expand() {
        let mut definition = valid();
        definition.verification = Some(VerificationPolicy {
            rules: vec![VerificationRule {
                selector: VerificationSelector {
                    all_of: vec![SelectorPredicate::ToolId {
                        tool_id: "edit".into(),
                    }],
                    any_of: vec![],
                },
                action: VerificationAction::Verify,
                adjudicator_slot: Some("primary".into()),
                max_candidates: Some(3),
                profile: Some(PROFILE_PANEL.into()),
                ..Default::default()
            }],
        });
        definition.validate().unwrap();
        let compiled = definition.verification.as_ref().unwrap().compile();
        let rule = &compiled.regions[0].rule;
        assert_eq!(rule.resolved_mode(), VerificationMode::Revise);
        assert_eq!(rule.generators.len(), 3);
        assert_eq!(rule.generators[0].recipe, VerificationRecipe::Inherit);
        assert!(matches!(
            rule.generators[1].recipe,
            VerificationRecipe::CleanRoom { .. }
        ));

        let mut clean = valid();
        clean.verification = Some(VerificationPolicy {
            rules: vec![VerificationRule {
                selector: VerificationSelector {
                    all_of: vec![SelectorPredicate::ToolId {
                        tool_id: "write".into(),
                    }],
                    any_of: vec![],
                },
                action: VerificationAction::Verify,
                adjudicator_slot: Some("primary".into()),
                profile: Some(PROFILE_CLEAN_ROOM.into()),
                mode: Some(VerificationMode::Gate),
                ..Default::default()
            }],
        });
        clean.validate().unwrap();
        let compiled = clean.verification.unwrap().compile();
        assert_eq!(compiled.regions[0].rule.generators.len(), 1);
        assert!(matches!(
            compiled.regions[0].rule.generators[0].recipe,
            VerificationRecipe::CleanRoom {
                include_linked_files: false,
                last_n_reads: 3
            }
        ));
    }

    #[test]
    fn verification_explicit_fields_win_over_profile_and_empty_generators_are_valid() {
        let mut definition = valid();
        definition.verification = Some(VerificationPolicy {
            rules: vec![VerificationRule {
                selector: VerificationSelector {
                    all_of: vec![SelectorPredicate::ToolId {
                        tool_id: "write".into(),
                    }],
                    any_of: vec![],
                },
                action: VerificationAction::Verify,
                adjudicator_slot: Some("primary".into()),
                profile: Some(PROFILE_PANEL.into()),
                mode: Some(VerificationMode::Gate),
                generators: vec![GeneratorSpec {
                    slot: "primary".into(),
                    recipe: VerificationRecipe::Inherit,
                    max_turns: 1,
                }],
                ..Default::default()
            }],
        });
        definition.validate().unwrap();
        let compiled = definition.verification.unwrap().compile();
        assert_eq!(compiled.regions[0].rule.resolved_mode(), VerificationMode::Gate);
        assert_eq!(compiled.regions[0].rule.generators.len(), 1);

        let mut adjudicator_only = valid();
        adjudicator_only.verification = Some(VerificationPolicy {
            rules: vec![VerificationRule {
                selector: VerificationSelector {
                    all_of: vec![SelectorPredicate::ToolId {
                        tool_id: "write".into(),
                    }],
                    any_of: vec![],
                },
                action: VerificationAction::Verify,
                adjudicator_slot: Some("primary".into()),
                ..Default::default()
            }],
        });
        adjudicator_only.validate().unwrap();
    }

    #[test]
    fn verification_rejects_unknown_slot_and_excessive_turns() {
        let mut definition = valid();
        definition.verification = Some(VerificationPolicy {
            rules: vec![VerificationRule {
                selector: VerificationSelector {
                    all_of: vec![SelectorPredicate::ToolId {
                        tool_id: "write".into(),
                    }],
                    any_of: vec![],
                },
                action: VerificationAction::Verify,
                adjudicator_slot: Some("primary".into()),
                generators: vec![GeneratorSpec {
                    slot: "missing".into(),
                    recipe: VerificationRecipe::Inherit,
                    max_turns: 1,
                }],
                ..Default::default()
            }],
        });
        assert!(definition.validate().is_err());

        definition.verification.as_mut().unwrap().rules[0].generators[0].slot = "primary".into();
        definition.verification.as_mut().unwrap().rules[0].generators[0].max_turns = 5;
        assert!(definition.validate().is_err());
    }

    #[test]
    fn verification_inherit_untrusted_slot_emits_custody_warning() {
        let rule = VerificationRule {
            selector: VerificationSelector {
                all_of: vec![SelectorPredicate::ToolId {
                    tool_id: "write".into(),
                }],
                any_of: vec![],
            },
            action: VerificationAction::Verify,
            adjudicator_slot: Some("primary".into()),
            generators: vec![GeneratorSpec {
                slot: "untrusted".into(),
                recipe: VerificationRecipe::Inherit,
                max_turns: 1,
            }],
            ..Default::default()
        };
        let warnings = rule.inherit_untrusted_slot_warnings(&BTreeSet::from(["untrusted".into()]));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("untrusted"));
        assert!(rule
            .inherit_untrusted_slot_warnings(&BTreeSet::new())
            .is_empty());
    }

    #[test]
    fn verification_rule_yaml_round_trip_includes_mode_and_recipe() {
        let yaml = r#"
selector:
  allOf:
    - toolClass: artifact_write
action: verify
adjudicatorSlot: primary
mode: revise
onAdjudicationFailure: refuse
generators:
  - slot: primary
    recipe: inherit
    maxTurns: 2
  - slot: primary
    recipe:
      cleanRoom:
        includeLinkedFiles: true
        lastNReads: 4
"#;
        let rule: VerificationRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.mode, Some(VerificationMode::Revise));
        assert_eq!(
            rule.on_adjudication_failure,
            Some(OnAdjudicationFailure::Refuse)
        );
        assert_eq!(rule.generators.len(), 2);
        assert_eq!(rule.generators[0].recipe, VerificationRecipe::Inherit);
        assert_eq!(
            rule.generators[1].recipe,
            VerificationRecipe::CleanRoom {
                include_linked_files: true,
                last_n_reads: 4
            }
        );
        let encoded = serde_yaml::to_string(&rule).unwrap();
        let decoded: VerificationRule = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(decoded, rule);
    }
}
