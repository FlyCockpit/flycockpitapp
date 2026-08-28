//! Immutable installed-agent profile resolution.
//!
//! This is intentionally a core-only adapter over the daemon-owned installation
//! and provider snapshots.  It does not read a path, consult a provider default,
//! or turn authored names into an installation lookup.  Those operations happen
//! before this module is called and their selected identities are retained in the
//! returned profile/snapshot.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use cockpit_config::config::model_policy::EffectiveModelCapabilities;
use cockpit_config::config::providers::{CapabilityStatus, ModelLocation, ProvidersConfig};
use cockpit_db::db::agent_installations::{
    AgentBindingExpectation, AgentBindingRevision, AgentBindingRevisionMap, AgentBindingRow,
    AgentExecutionKind, AgentInstallationRow, AgentInstallationScope, AgentObservationRow,
    AgentProfileSnapshotRow, AgentSessionCreateInput, PrepareAgentSessionInput,
    PrepareAgentSessionOutcome, ProviderAlias as SnapshotProviderAlias, QuestionResolverOrder,
    RedactedAgentProfileSnapshot, RedactedAllowedChild, RedactedBindingEvidence,
    RedactedEffectiveDelegation, RedactedQuestionPolicy, RedactedRecommendation,
    RedactedVerificationExecutionPlan, RedactedVerificationGenerator,
    RedactedVerificationPredicate, RedactedVerificationRecipe, RedactedVerificationRegion,
    RedactedVerificationSelector, VerificationEffectiveAction,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    AgentDef, AllowedChild, EffectiveQuestionPolicy, ExecutionKind, ModelCapability, ModelLocality,
    ModelRecommendation, ProhibitedQuestionClass, QuestionOverride, QuestionPolicy, ResolverOrder,
    SelectorPredicate, VerificationAction, VerificationBudget, VnextHostPolicy,
    resolve_question_policy,
};

/// Trusted classification of the installation source.  A definition never
/// self-selects one of these values from its frontmatter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentProfileInstallationSource {
    Global,
    WorkspacePrivate,
    WorkspaceShared,
    Builtin,
}

impl AgentProfileInstallationSource {
    fn accepts(self, scope: AgentInstallationScope) -> bool {
        matches!(
            (self, scope),
            (Self::Global, AgentInstallationScope::Global)
                | (Self::WorkspacePrivate, AgentInstallationScope::WorkspacePrivate)
                | (Self::WorkspaceShared, AgentInstallationScope::WorkspaceShared)
                // Builtins have a daemon-owned global installation record.
                | (Self::Builtin, AgentInstallationScope::Global)
        )
    }

    fn accepts_definition(self, definition: &AgentDef) -> Result<()> {
        let vnext = definition
            .vnext
            .as_ref()
            .context("profile installation is not a vNext AgentDef")?;
        let publisher = vnext.publisher();
        let valid = match self {
            Self::Global | Self::WorkspacePrivate => publisher == "local",
            Self::WorkspaceShared => publisher == "authored",
            Self::Builtin => {
                publisher == "cockpit"
                    && vnext.agent_id == format!("cockpit/{}", definition.name.to_ascii_lowercase())
                    && super::is_builtin_agent(&definition.name)
            }
        };
        ensure!(
            valid,
            "definition publisher does not match its trusted installation source"
        );
        Ok(())
    }
}

/// An already-loaded definition associated with exactly one installation ID.
/// `source_digest` is checked against the canonical definition bytes below;
/// a same-name candidate can never substitute for this record.
#[derive(Debug, Clone)]
pub struct AgentProfileDefinition {
    pub installation: AgentInstallationRow,
    /// The observation read atomically with the installation and its owned
    /// path.  Keeping the whole row here prevents the resolver from treating
    /// an arbitrary revision as proof that the observed bytes were reviewed.
    pub observation: AgentObservationRow,
    pub source: AgentProfileInstallationSource,
    pub definition: AgentDef,
}

/// The daemon's observed installation namespace.  It deliberately indexes by
/// UUID only.  Display names are not part of profile selection.
#[derive(Debug, Clone, Default)]
pub struct AgentProfileInstallationCatalog {
    definitions: BTreeMap<Uuid, AgentProfileDefinition>,
}

impl AgentProfileInstallationCatalog {
    pub fn new(definitions: impl IntoIterator<Item = AgentProfileDefinition>) -> Result<Self> {
        let mut by_id = BTreeMap::new();
        for definition in definitions {
            let id = definition.installation.installation_id;
            ensure!(
                definition.source.accepts(definition.installation.scope),
                "profile installation source does not match its scope"
            );
            definition
                .source
                .accepts_definition(&definition.definition)?;
            ensure!(
                definition.observation.installation_id == id,
                "profile observation belongs to a different installation"
            );
            ensure!(
                by_id.insert(id, definition).is_none(),
                "duplicate agent profile installation ID `{id}`"
            );
        }
        Ok(Self { definitions: by_id })
    }

    pub fn selected(&self, installation_id: Uuid) -> Result<&AgentProfileDefinition> {
        self.definitions.get(&installation_id).ok_or_else(|| {
            anyhow::anyhow!("selected agent installation `{installation_id}` was not observed")
        })
    }

    /// Resolve a portable child reference only when the daemon observed one
    /// exact, scope-compatible installed definition.  Ambiguity is a refusal,
    /// never a display-name or source-order fallback.
    fn portable_child(&self, parent: &AgentProfileDefinition, reference: &str) -> Result<Uuid> {
        let matches: Vec<_> = self
            .definitions
            .values()
            .filter(|candidate| {
                candidate.installation.deleted_at_unix_ms.is_none()
                    && candidate
                        .definition
                        .vnext
                        .as_ref()
                        .is_some_and(|vnext| vnext.agent_id == reference)
                    && portable_scope_compatible(parent, candidate)
            })
            .map(|candidate| candidate.installation.installation_id)
            .collect();
        match matches.as_slice() {
            [id] => Ok(*id),
            [] => {
                bail!("portable child `{reference}` has no observed scope-compatible installation")
            }
            _ => bail!("portable child `{reference}` maps to multiple observed installations"),
        }
    }
}

fn portable_scope_compatible(
    parent: &AgentProfileDefinition,
    child: &AgentProfileDefinition,
) -> bool {
    match parent.installation.scope {
        AgentInstallationScope::Global => {
            child.installation.scope == AgentInstallationScope::Global
        }
        // A private parent may use same-workspace private or shared children.
        AgentInstallationScope::WorkspacePrivate => {
            child.installation.scope == AgentInstallationScope::Global
                || (child.installation.canonical_workspace_id
                    == parent.installation.canonical_workspace_id
                    && matches!(
                        child.installation.scope,
                        AgentInstallationScope::WorkspacePrivate
                            | AgentInstallationScope::WorkspaceShared
                    ))
        }
        // A shared parent must not gain a workspace-private child merely
        // because both records name the same workspace.
        AgentInstallationScope::WorkspaceShared => {
            child.installation.scope == AgentInstallationScope::Global
                || (child.installation.scope == AgentInstallationScope::WorkspaceShared
                    && child.installation.canonical_workspace_id
                        == parent.installation.canonical_workspace_id)
        }
    }
}

/// A daemon-local provider profile route.  The opaque profile handle is the
/// credential owner; neither a manifest nor this resolver has credential data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProfileModelOffering {
    /// Stable daemon-owned offering identity for deterministic tie breaking.
    pub offering_id: String,
    pub provider_profile_handle: String,
    pub provider_id: String,
    pub model_id: String,
}

/// A host-selected default route.  It is deliberately supplied as an exact
/// installation binding plus offering, never synthesized from a provider
/// name or `ProvidersConfig.active_model`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProfileFallbackRoute {
    pub offering: AgentProfileModelOffering,
    pub binding: AgentBindingRow,
}

/// Request-local narrowing.  `Disable` is strictest.  `Reduce` reuses the
/// schema policy so the resolver/order fields are checked by the vNext
/// monotonic resolver rather than being copied by an ad-hoc second policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileQuestionOverride {
    Inherit,
    Disable,
    Reduce(QuestionPolicy),
}

/// Per-source-rule session narrowing. It can only remove selector atoms or
/// reduce a resolved resource budget; it cannot route an excluded call to a
/// later definition rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileVerificationReduction {
    Inherit,
    Off,
    Restrict {
        enabled_intersection_mask: Vec<String>,
        budget: VerificationBudget,
    },
}

impl From<ProfileQuestionOverride> for QuestionOverride {
    fn from(value: ProfileQuestionOverride) -> Self {
        match value {
            ProfileQuestionOverride::Inherit => Self::Inherit,
            ProfileQuestionOverride::Disable => Self::Disable,
            ProfileQuestionOverride::Reduce(policy) => Self::Reduce(policy),
        }
    }
}

/// All mutable daemon inputs are collected before resolution.  In particular,
/// callers must supply the bindings read from the installation API; a live
/// provider default is not an implicit binding.
#[derive(Debug, Clone)]
pub struct AgentProfileResolutionInput<'a> {
    pub installation_id: Uuid,
    pub catalog: &'a AgentProfileInstallationCatalog,
    pub bindings: Vec<AgentBindingRow>,
    pub offerings: Vec<AgentProfileModelOffering>,
    /// Defaults are opt-in on both sides: this map is host-owned and a slot
    /// may consume one only when its definition explicitly allows fallback.
    pub utility_fallbacks: BTreeMap<String, AgentProfileFallbackRoute>,
    pub providers: &'a ProvidersConfig,
    pub host_policy: VnextHostPolicy,
    pub question_override: ProfileQuestionOverride,
    pub verification_reductions: BTreeMap<String, ProfileVerificationReduction>,
}

/// A resolved choice retains both the selected installed route and the
/// advisory result.  `author_suggested` never gates a compatible route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedModelSlotChoice {
    pub offering: AgentProfileModelOffering,
    pub binding: AgentBindingRow,
    pub author_suggested: bool,
    pub exact_recommendation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedModelSlot {
    pub slot_id: String,
    /// Every live, currently hard-compatible binding in this slot. The
    /// default is also present here and is identified by `is_default`.
    pub choices: Vec<ResolvedModelSlotChoice>,
    pub choice: ResolvedModelSlotChoice,
    /// Matching recommendations stay in author order, then alias order;
    /// unmatched records remain visible in their original author order.
    pub recommendations: Vec<RedactedRecommendation>,
    pub remaining_compatible_offerings: Vec<String>,
}

/// The immutable result passed to `prepare_agent_session`.  It contains no
/// trust, sandbox, approval, credential, or live-default authority.
///
/// ```compile_fail
/// let _ = cockpit_core::agents::ResolvedAgentProfile {
///     installation_id: unimplemented!(),
///     installation_revision: unimplemented!(),
///     observation_revision: unimplemented!(),
///     definition_digest: unimplemented!(),
///     source: unimplemented!(),
///     slots: unimplemented!(),
///     child_installation_ids: unimplemented!(),
///     child_execution_kinds: unimplemented!(),
///     effective_questions: unimplemented!(),
///     snapshot: unimplemented!(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAgentProfile {
    installation_id: Uuid,
    installation_revision: u64,
    observation_revision: u64,
    definition_digest: String,
    source: AgentProfileInstallationSource,
    slots: BTreeMap<String, ResolvedModelSlot>,
    child_installation_ids: Vec<Uuid>,
    child_execution_kinds: BTreeMap<Uuid, AgentExecutionKind>,
    effective_questions: Option<EffectiveQuestionPolicy>,
    snapshot: RedactedAgentProfileSnapshot,
}

/// A session reload representation intentionally restricted to durable,
/// redacted facts. It has no `AgentDef`, provider configuration, credential,
/// or editable binding row to accidentally re-resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadedAgentProfile {
    pub installation_id: Uuid,
    pub installation_revision: u64,
    pub observation_revision: u64,
    pub definition_digest: String,
    pub child_installation_ids: Vec<Uuid>,
    pub child_execution_kinds: BTreeMap<Uuid, AgentExecutionKind>,
    pub effective_questions: Option<EffectiveQuestionPolicy>,
    pub bindings: Vec<RedactedBindingEvidence>,
    pub snapshot: RedactedAgentProfileSnapshot,
}

/// The caller-owned session fields for the DB prepare transaction.  The
/// resolved fields are purposefully absent: they are derived only from the
/// immutable profile, preventing callers from mixing a new digest/binding
/// receipt with an older snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProfilePrepareRequest {
    pub session_id: Uuid,
    pub session_create: AgentSessionCreateInput,
    pub existing_session_claim_token: Option<Uuid>,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub snapshot_schema_version: u64,
    pub now_unix_ms: i64,
}

impl ResolvedAgentProfile {
    pub fn installation_id(&self) -> Uuid {
        self.installation_id
    }

    pub fn installation_revision(&self) -> u64 {
        self.installation_revision
    }

    pub fn observation_revision(&self) -> u64 {
        self.observation_revision
    }

    pub fn definition_digest(&self) -> &str {
        &self.definition_digest
    }

    pub fn source(&self) -> AgentProfileInstallationSource {
        self.source
    }

    pub fn slots(&self) -> &BTreeMap<String, ResolvedModelSlot> {
        &self.slots
    }

    pub fn child_installation_ids(&self) -> &[Uuid] {
        &self.child_installation_ids
    }

    pub fn child_execution_kinds(&self) -> &BTreeMap<Uuid, AgentExecutionKind> {
        &self.child_execution_kinds
    }

    pub fn effective_questions(&self) -> Option<&EffectiveQuestionPolicy> {
        self.effective_questions.as_ref()
    }

    pub fn snapshot(&self) -> &RedactedAgentProfileSnapshot {
        &self.snapshot
    }

    pub fn canonical_snapshot_payload(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.snapshot)?)
    }

    pub fn canonical_snapshot_digest(&self) -> Result<String> {
        Ok(hex_digest(&self.canonical_snapshot_payload()?))
    }

    /// Atomically compare the definition digest and every bound revision
    /// before persisting this canonical snapshot.  A `Conflict` is returned
    /// to the daemon to reread/re-resolve; no running session ever observes a
    /// live definition or provider default after this transaction succeeds.
    ///
    /// This is the composition seam for the daemon installation/session
    /// service: it must load one `installation_id`-selected catalog entry,
    /// call [`resolve_agent_profile`], invoke this method, and on `Conflict`
    /// reread the installation, observation, bindings, and provider evidence
    /// before resolving again.  Core deliberately does not launch a session
    /// here; lifecycle ownership remains with that daemon service.
    pub async fn prepare_session(
        &self,
        db: &cockpit_db::Db,
        request: AgentProfilePrepareRequest,
    ) -> Result<PrepareAgentSessionOutcome> {
        let payload = self.canonical_snapshot_payload()?;
        let revision_map = AgentBindingRevisionMap {
            bindings: self
                .slots
                .values()
                .flat_map(|slot| slot.choices.iter())
                .map(|choice| AgentBindingRevision {
                    slot_id: choice.binding.slot_id.clone(),
                    provider_profile_handle: choice.binding.provider_profile_handle.clone(),
                    model_id: choice.binding.model_id.clone(),
                    binding_revision: choice.binding.binding_revision,
                })
                .collect(),
        };
        let binding_revision_map_payload = serde_json::to_vec(&revision_map)?;
        let expected_bindings = self
            .slots
            .values()
            .flat_map(|slot| slot.choices.iter())
            .map(|choice| AgentBindingExpectation {
                slot_id: choice.binding.slot_id.clone(),
                provider_profile_handle: choice.binding.provider_profile_handle.clone(),
                model_id: choice.binding.model_id.clone(),
                expected_binding_revision: choice.binding.binding_revision,
            })
            .collect();
        db.prepare_agent_session(PrepareAgentSessionInput {
            session_id: request.session_id,
            session_create: request.session_create,
            existing_session_claim_token: request.existing_session_claim_token,
            idempotency_key: request.idempotency_key,
            request_fingerprint: request.request_fingerprint,
            installation_id: self.installation_id,
            expected_installation_revision: self.installation_revision,
            expected_observation_revision: self.observation_revision,
            expected_definition_digest: self.definition_digest.clone(),
            expected_bindings,
            snapshot_schema_version: request.snapshot_schema_version,
            canonical_snapshot_digest: hex_digest(&payload),
            canonical_snapshot_payload: payload,
            binding_revision_map_digest: hex_digest(&binding_revision_map_payload),
            binding_revision_map_payload,
            now_unix_ms: request.now_unix_ms,
        })
        .await
    }

    /// Reload fetches the immutable snapshot through the DB boundary and
    /// revalidates its canonical payload and binding revision map. It
    /// deliberately cannot accept an `AgentDef`, provider configuration, or
    /// caller-constructed snapshot row, so changed disk/config state cannot
    /// influence a running session.
    pub async fn reload(
        db: &cockpit_db::Db,
        session_id: Uuid,
        installation_revision: u64,
        observation_revision: u64,
    ) -> Result<ReloadedAgentProfile> {
        let persisted = db
            .agent_profile_snapshot(session_id)
            .await?
            .context("session has no persisted agent profile snapshot")?;
        Self::reload_persisted(&persisted, installation_revision, observation_revision)
    }

    fn reload_persisted(
        persisted: &AgentProfileSnapshotRow,
        installation_revision: u64,
        observation_revision: u64,
    ) -> Result<ReloadedAgentProfile> {
        let snapshot = persisted.reconstruct()?;
        let revision_map = persisted.reconstruct_binding_revision_map()?;
        validate_snapshot_self_contained(&snapshot)?;
        let snapshot_revisions = snapshot
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
            .collect::<BTreeMap<_, _>>();
        let persisted_revisions = revision_map
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
            .collect::<BTreeMap<_, _>>();
        ensure!(
            snapshot_revisions == persisted_revisions,
            "persisted profile snapshot and binding revision map disagree"
        );
        let mut child_execution_kinds = BTreeMap::new();
        if let Some(delegation) = &snapshot.effective_delegation {
            for child in &delegation.allowed_children {
                if let RedactedAllowedChild::LocalInstallation {
                    installation_id,
                    execution_kind,
                } = child
                {
                    ensure!(
                        child_execution_kinds
                            .insert(*installation_id, *execution_kind)
                            .is_none(),
                        "snapshot duplicates a resolved child installation"
                    );
                }
            }
        }
        let child_installation_ids = child_execution_kinds.keys().copied().collect();
        let effective_questions = questions_from_snapshot(&snapshot.question_policy)?;
        Ok(ReloadedAgentProfile {
            installation_id: persisted.installation_id,
            installation_revision,
            observation_revision,
            definition_digest: persisted.definition_digest.clone(),
            child_installation_ids,
            child_execution_kinds,
            effective_questions,
            bindings: snapshot.bindings.clone(),
            snapshot,
        })
    }
}

/// Resolve one selected installation into a canonical immutable profile.
pub fn resolve_agent_profile(
    input: AgentProfileResolutionInput<'_>,
) -> Result<ResolvedAgentProfile> {
    let selected = input.catalog.selected(input.installation_id)?;
    ensure!(
        selected.installation.deleted_at_unix_ms.is_none(),
        "selected installation was deleted"
    );
    ensure!(
        selected.source.accepts(selected.installation.scope),
        "selected installation scope does not match trusted definition source"
    );
    selected.source.accepts_definition(&selected.definition)?;
    ensure!(
        selected.observation.installation_id == selected.installation.installation_id,
        "selected installation observation belongs to a different installation"
    );
    ensure!(
        selected.observation.reviewed,
        "selected definition observation is unreviewed; review and rebind are required"
    );
    let vnext = selected
        .definition
        .vnext
        .as_ref()
        .context("selected installation is not a vNext AgentDef")?;
    vnext.validate()?;
    ensure!(
        selected.installation.source_agent_id == vnext.agent_id,
        "installation source agent ID does not match selected vNext definition"
    );
    let definition_digest = hex_digest(&selected.definition.vnext_digest_bytes()?);
    ensure!(
        definition_digest == selected.installation.source_digest,
        "selected definition digest changed; review and rebind are required"
    );
    ensure!(
        definition_digest == selected.observation.observed_digest,
        "selected definition differs from its reviewed observation; review and rebind are required"
    );

    let bindings = bindings_by_slot(&input.bindings, input.installation_id, &definition_digest)?;
    let offerings = offerings_by_route(&input.offerings)?;
    let mut slots = BTreeMap::new();
    for (slot_id, slot) in &vnext.model_slots {
        let explicit_bindings = bindings.get(slot_id).cloned().unwrap_or_default();
        let explicit_binding = explicit_bindings
            .iter()
            .find(|binding| binding.is_default)
            .cloned();
        // A durable user binding always wins. The host default is only a
        // missing-slot recovery path for an opt-in utility slot.
        let fallback = explicit_binding
            .is_none()
            .then(|| input.utility_fallbacks.get(slot_id))
            .flatten();
        let binding = match explicit_binding {
            Some(binding) => binding,
            None => fallback
                .map(|fallback| fallback.binding.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "selected installation has no binding for required slot `{slot_id}`"
                    )
                })?,
        };
        if let Some(fallback) = fallback {
            ensure!(
                slot_id != "primary" && slot.allow_default_fallback,
                "slot `{slot_id}` does not permit a utility default fallback"
            );
            ensure!(
                fallback.binding.binding_id == binding.binding_id
                    && binding.installation_id == input.installation_id
                    && fallback.binding.definition_digest == definition_digest
                    && binding.definition_digest == definition_digest
                    && binding.slot_id == *slot_id
                    && binding.retired_at_unix_ms.is_none(),
                "utility fallback must be an installation-local durable binding for its exact slot"
            );
            ensure!(
                fallback.offering.provider_profile_handle == binding.provider_profile_handle
                    && fallback.offering.model_id == binding.model_id,
                "utility fallback offering does not match its durable binding"
            );
        };
        ensure!(
            binding.hard_capability_verified,
            "slot `{slot_id}` lacks hard-capability verification"
        );
        let offering = if let Some(fallback) = fallback {
            fallback.offering.clone()
        } else {
            offerings
                .get(&(
                    binding.provider_profile_handle.clone(),
                    binding.model_id.clone(),
                ))
                .ok_or_else(|| {
                    anyhow::anyhow!("slot `{slot_id}` references an unavailable provider profile")
                })?
                .clone()
        };
        ensure!(
            offering.model_id == binding.model_id,
            "slot `{slot_id}` binding model does not match its selected provider offering"
        );
        let mut choices = Vec::new();
        for live_binding in if explicit_bindings.is_empty() {
            vec![binding.clone()]
        } else {
            explicit_bindings
        } {
            ensure!(
                live_binding.hard_capability_verified,
                "slot `{slot_id}` has an unverified live binding"
            );
            let live_offering = offerings
                .get(&(
                    live_binding.provider_profile_handle.clone(),
                    live_binding.model_id.clone(),
                ))
                .cloned()
                .or_else(|| {
                    fallback
                        .filter(|fallback| fallback.binding.binding_id == live_binding.binding_id)
                        .map(|fallback| fallback.offering.clone())
                })
                .ok_or_else(|| {
                    anyhow::anyhow!("slot `{slot_id}` references an unavailable provider profile")
                })?;
            ensure!(
                offering_is_compatible(slot, &live_offering, input.providers),
                "slot `{slot_id}` binding no longer satisfies hard model requirements"
            );
            if !slot.models.is_empty() {
                ensure!(
                    slot.models
                        .iter()
                        .any(|allowed| allowed.provider_id == live_offering.provider_id
                            && allowed.model_id == live_offering.model_id),
                    "slot `{slot_id}` contains a binding outside its authored allowed model set"
                );
            }
            let live_recommendations =
                resolve_recommendations(slot_id, &slot.suggested_models, &live_offering);
            let exact_recommendation_id = live_recommendations
                .iter()
                .find(|recommendation| recommendation.author_suggested)
                .map(|recommendation| recommendation.recommendation_id.clone());
            choices.push(ResolvedModelSlotChoice {
                offering: live_offering,
                binding: live_binding,
                author_suggested: exact_recommendation_id.is_some(),
                exact_recommendation_id,
            });
        }
        let choice = choices
            .iter()
            .find(|choice| choice.binding.is_default)
            .cloned()
            .context("resolved slot lost its default binding")?;
        ensure!(
            offering_is_compatible(slot, &offering, input.providers),
            "slot `{slot_id}` binding no longer satisfies hard model requirements"
        );
        let recommendations = resolve_recommendations(slot_id, &slot.suggested_models, &offering);
        let remaining_compatible_offerings =
            ranked_compatible_offerings(slot, &input.offerings, input.providers)
                .into_iter()
                .filter(|candidate| candidate.offering_id != offering.offering_id)
                .map(|candidate| candidate.offering_id)
                .collect();
        slots.insert(
            slot_id.clone(),
            ResolvedModelSlot {
                slot_id: slot_id.clone(),
                choices,
                choice,
                recommendations,
                remaining_compatible_offerings,
            },
        );
    }
    ensure!(
        bindings.keys().all(|slot_id| slots.contains_key(slot_id)),
        "selected installation has a binding for an unknown vNext slot"
    );

    // Binding resolution is the first validation boundary that knows the
    // actual provider/model trust of every slot. Surface the custody warning
    // through the same advisory tracing channel as other definition-load
    // warnings; it never mutates or rejects the resolved grant.
    let untrusted_slots = slots
        .iter()
        .filter(|(_, slot)| {
            !input
                .providers
                .resolve_trust(
                    &slot.choice.offering.provider_id,
                    &slot.choice.offering.model_id,
                )
                .is_trusted()
        })
        .map(|(slot_id, _)| slot_id.clone())
        .collect::<BTreeSet<_>>();
    if let Some(policy) = &vnext.verification {
        for region in policy.compile_with_slots(&vnext.model_slots).regions {
            for warning in region
                .rule
                .inherit_untrusted_slot_warnings(&untrusted_slots)
            {
                tracing::warn!(agent = %vnext.agent_id, %warning, "agent definition loaded with warning");
            }
        }
    }

    let resolved_children = resolve_children(selected, input.catalog, &input.host_policy)?;
    let child_installation_ids = resolved_children
        .iter()
        .map(|(installation_id, _)| *installation_id)
        .collect();
    let child_execution_kinds = resolved_children
        .iter()
        .map(|(installation_id, kind)| (*installation_id, execution_kind(*kind)))
        .collect();
    let effective_questions = resolve_question_policy(
        vnext.questions.as_ref(),
        &input.host_policy,
        input.question_override.into(),
    )?;
    let snapshot = snapshot_for(
        selected,
        &slots,
        &resolved_children,
        &input.host_policy,
        effective_questions.as_ref(),
        &input.verification_reductions,
    )?;
    validate_snapshot_self_contained(&snapshot)?;
    Ok(ResolvedAgentProfile {
        installation_id: input.installation_id,
        installation_revision: selected.installation.installation_revision,
        observation_revision: selected.observation.observation_revision,
        definition_digest,
        source: selected.source,
        slots,
        child_installation_ids,
        child_execution_kinds,
        effective_questions,
        snapshot,
    })
}

fn bindings_by_slot(
    bindings: &[AgentBindingRow],
    installation_id: Uuid,
    definition_digest: &str,
) -> Result<BTreeMap<String, Vec<AgentBindingRow>>> {
    let mut grouped: BTreeMap<String, Vec<AgentBindingRow>> = BTreeMap::new();
    for binding in bindings {
        ensure!(
            binding.installation_id == installation_id,
            "binding belongs to a different installation"
        );
        ensure!(
            binding.definition_digest == definition_digest,
            "binding digest is stale; rebind is required"
        );
        ensure!(
            binding.retired_at_unix_ms.is_none(),
            "retired binding cannot select a model slot"
        );
        grouped
            .entry(binding.slot_id.clone())
            .or_default()
            .push(binding.clone());
    }
    for (slot_id, rows) in &grouped {
        let defaults: Vec<_> = rows.iter().filter(|row| row.is_default).collect();
        ensure!(
            defaults.len() == 1,
            "slot `{slot_id}` must have exactly one default live binding"
        );
    }
    Ok(grouped)
}

fn offerings_by_route(
    offerings: &[AgentProfileModelOffering],
) -> Result<BTreeMap<(String, String), AgentProfileModelOffering>> {
    let mut by_route = BTreeMap::new();
    for offering in offerings {
        ensure!(
            !offering.offering_id.is_empty() && !offering.provider_profile_handle.is_empty(),
            "provider offering identities must be non-empty"
        );
        ensure!(
            !offering.provider_id.is_empty() && !offering.model_id.is_empty(),
            "provider offering route must be non-empty"
        );
        ensure!(
            by_route
                .insert(
                    (
                        offering.provider_profile_handle.clone(),
                        offering.model_id.clone(),
                    ),
                    offering.clone(),
                )
                .is_none(),
            "provider profile/model route maps to multiple offerings"
        );
    }
    Ok(by_route)
}

fn offering_is_compatible(
    slot: &super::ModelSlot,
    offering: &AgentProfileModelOffering,
    providers: &ProvidersConfig,
) -> bool {
    // Older catalog callers carry a provider-id key only, while daemon-owned
    // installation choices carry a credential-owning profile handle as well.
    // Prefer the latter when it is an installed local route; falling back to
    // the provider id keeps portable profile resolution independent of the
    // daemon's local handle spelling.
    let capability_key = if providers
        .providers
        .contains_key(&offering.provider_profile_handle)
    {
        &offering.provider_profile_handle
    } else {
        &offering.provider_id
    };
    let capabilities = providers.resolve_effective_model_capabilities(
        capability_key,
        &offering.model_id,
        providers.resolution_generation,
    );
    hard_requirements_satisfied(
        slot,
        providers.resolve_location(capability_key, &offering.model_id),
        &capabilities,
    )
}

fn hard_requirements_satisfied(
    slot: &super::ModelSlot,
    location: Option<ModelLocation>,
    capabilities: &EffectiveModelCapabilities,
) -> bool {
    if capabilities
        .context_tokens
        .is_none_or(|actual| actual < slot.min_context_tokens.try_into().unwrap_or(u32::MAX))
    {
        return false;
    }
    let locality_ok = match slot.locality {
        ModelLocality::Any => true,
        ModelLocality::Local => location == Some(ModelLocation::Local),
        ModelLocality::Remote => matches!(
            location,
            Some(ModelLocation::Remote | ModelLocation::PrivateRemote)
        ),
    };
    locality_ok
        && slot
            .required_capabilities
            .iter()
            .all(|required| match required {
                // A configured concrete offering is positive host evidence for text generation;
                // no authored string can create such an offering.
                ModelCapability::TextGeneration => true,
                ModelCapability::ToolCalling => {
                    capabilities.tool_calling == CapabilityStatus::Supported
                }
                ModelCapability::Vision => {
                    capabilities.image_input.status == CapabilityStatus::Supported
                }
                // Presence of a capability record is not evidence of an
                // executable computer-use contract.  The route must carry a
                // concrete host-issued contract before an authored hard
                // requirement can select it.
                ModelCapability::ComputerUse => capabilities
                    .computer_use
                    .as_ref()
                    .is_some_and(|computer_use| computer_use.contract.is_some()),
                ModelCapability::JsonSchema => {
                    capabilities.structured_outputs == CapabilityStatus::Supported
                }
            })
}

/// Return only hard-compatible offerings in the documented stable order:
/// author recommendation order, exact alias order, then daemon-owned local
/// offering id.  Upstream identities are advisory and never become aliases.
pub fn ranked_compatible_offerings(
    slot: &super::ModelSlot,
    offerings: &[AgentProfileModelOffering],
    providers: &ProvidersConfig,
) -> Vec<AgentProfileModelOffering> {
    let mut compatible: Vec<_> = offerings
        .iter()
        .filter(|offering| {
            offering_is_compatible(slot, offering, providers)
                && (slot.models.is_empty()
                    || slot.models.iter().any(|allowed| {
                        allowed.provider_id == offering.provider_id
                            && allowed.model_id == offering.model_id
                    }))
        })
        .cloned()
        .collect();
    compatible.sort_by(|left, right| {
        recommendation_rank(slot, left)
            .cmp(&recommendation_rank(slot, right))
            .then_with(|| left.offering_id.cmp(&right.offering_id))
    });
    compatible
}

/// Rank only exact aliases.  The tuple is semantic: author recommendation
/// order, alias order, then the daemon-owned stable offering ID.  An
/// unmatched offering sorts after every exact author recommendation.
fn recommendation_rank(
    slot: &super::ModelSlot,
    offering: &AgentProfileModelOffering,
) -> (usize, usize) {
    slot.suggested_models
        .iter()
        .enumerate()
        .find_map(|(author_order, recommendation)| {
            recommendation
                .provider_aliases
                .iter()
                .position(|alias| {
                    alias.provider_id == offering.provider_id && alias.model_id == offering.model_id
                })
                .map(|alias_order| (author_order, alias_order))
        })
        .unwrap_or((usize::MAX, usize::MAX))
}

fn resolve_recommendations(
    slot_id: &str,
    recommendations: &[ModelRecommendation],
    selected: &AgentProfileModelOffering,
) -> Vec<RedactedRecommendation> {
    let selected_alias = SnapshotProviderAlias {
        provider_id: selected.provider_id.clone(),
        model_id: selected.model_id.clone(),
    };
    recommendations
        .iter()
        .enumerate()
        .map(|(author_order, recommendation)| {
            let exact_alias = recommendation
                .provider_aliases
                .iter()
                .find(|alias| {
                    alias.provider_id == selected.provider_id && alias.model_id == selected.model_id
                })
                .map(|alias| SnapshotProviderAlias {
                    provider_id: alias.provider_id.clone(),
                    model_id: alias.model_id.clone(),
                });
            RedactedRecommendation {
                recommendation_id: recommendation.recommendation_id.clone(),
                slot_id: slot_id.to_string(),
                canonical_upstream_identity: recommendation.upstream_identity.clone(),
                author_label: recommendation.author_label.clone(),
                rationale: recommendation.rationale.clone(),
                provider_aliases: recommendation
                    .provider_aliases
                    .iter()
                    .map(|alias| SnapshotProviderAlias {
                        provider_id: alias.provider_id.clone(),
                        model_id: alias.model_id.clone(),
                    })
                    .collect(),
                exact_provider_alias: exact_alias,
                author_suggested: recommendation.provider_aliases.iter().any(|alias| {
                    alias.provider_id == selected_alias.provider_id
                        && alias.model_id == selected_alias.model_id
                }),
                // Snapshot collision ranks identify the author-order record;
                // alias order is retained by the canonical alias vector and
                // used only while ranking a local offering.
                alias_collision_rank: author_order as u64,
            }
        })
        .collect()
}

fn resolve_children(
    selected: &AgentProfileDefinition,
    catalog: &AgentProfileInstallationCatalog,
    host: &VnextHostPolicy,
) -> Result<Vec<(Uuid, ExecutionKind)>> {
    let Some(vnext) = &selected.definition.vnext else {
        return Ok(Vec::new());
    };
    let mut children = BTreeSet::new();
    for child in &vnext.delegation.allowed_children {
        let installation_id = match child {
            AllowedChild::LocalInstallation { installation_id } => {
                validate_child(selected, catalog.selected(*installation_id)?, host)?;
                *installation_id
            }
            AllowedChild::PortableRef { portable_agent_ref } => {
                if portable_agent_ref == super::SELF_CHILD_REF {
                    selected.installation.installation_id
                } else {
                    let installation_id = catalog.portable_child(selected, portable_agent_ref)?;
                    validate_child(selected, catalog.selected(installation_id)?, host)?;
                    installation_id
                }
            }
        };
        ensure!(
            children.insert(installation_id),
            "multiple child references resolve to one installation"
        );
    }
    children
        .into_iter()
        .map(|installation_id| {
            let kind = catalog
                .selected(installation_id)?
                .definition
                .vnext
                .as_ref()
                .expect("children were validated as vNext")
                .execution_kind;
            Ok((installation_id, kind))
        })
        .collect()
}

fn validate_child(
    parent: &AgentProfileDefinition,
    child: &AgentProfileDefinition,
    host: &VnextHostPolicy,
) -> Result<()> {
    ensure!(
        child.installation.deleted_at_unix_ms.is_none(),
        "child installation was deleted"
    );
    ensure!(
        child.source.accepts(child.installation.scope),
        "child source does not match its trusted installation scope"
    );
    child.source.accepts_definition(&child.definition)?;
    ensure!(
        child.observation.reviewed
            && child.observation.installation_id == child.installation.installation_id
            && child.observation.observed_digest == child.installation.source_digest,
        "child installation is unreviewed or no longer current"
    );
    ensure!(
        portable_scope_compatible(parent, child),
        "child installation is scope-incompatible with its parent"
    );
    let parent_vnext = parent
        .definition
        .vnext
        .as_ref()
        .expect("parent was validated as vNext");
    let child_vnext = child
        .definition
        .vnext
        .as_ref()
        .context("child installation is not a vNext AgentDef")?;
    child_vnext.validate()?;
    ensure!(
        child.installation.source_agent_id == child_vnext.agent_id,
        "child installation source identity does not match its definition"
    );
    let child_digest = hex_digest(&child.definition.vnext_digest_bytes()?);
    ensure!(
        child_digest == child.installation.source_digest
            && child_digest == child.observation.observed_digest,
        "child definition changed since its reviewed observation"
    );
    ensure!(
        super::delegation_kind_permitted(
            parent_vnext.execution_kind,
            child_vnext.execution_kind,
            host.computer_delegation_enabled,
        ),
        "child execution kind is not permitted by the parent/host grant"
    );
    Ok(())
}

fn snapshot_for(
    selected: &AgentProfileDefinition,
    slots: &BTreeMap<String, ResolvedModelSlot>,
    resolved_children: &[(Uuid, ExecutionKind)],
    host: &VnextHostPolicy,
    questions: Option<&EffectiveQuestionPolicy>,
    verification_reductions: &BTreeMap<String, ProfileVerificationReduction>,
) -> Result<RedactedAgentProfileSnapshot> {
    let vnext = selected
        .definition
        .vnext
        .as_ref()
        .expect("checked by caller");
    let grant = vnext.resolve_grant(host)?;
    let effective_delegation =
        grant
            .delegation
            .as_ref()
            .map(|delegation| RedactedEffectiveDelegation {
                allowed_children: resolved_children
                    .iter()
                    .copied()
                    .map(redacted_child)
                    .collect(),
                max_descendant_depth: delegation.max_descendant_depth,
                max_concurrent_children: delegation.max_concurrent_children,
                targets: delegation
                    .targets
                    .iter()
                    .map(|target| match target {
                        super::DelegationTarget::SameRoot => {
                            cockpit_db::db::agent_installations::DelegationTarget::SameRoot
                        }
                        super::DelegationTarget::Subdirectory => {
                            cockpit_db::db::agent_installations::DelegationTarget::Subdirectory
                        }
                        super::DelegationTarget::ManagedWorktree => {
                            cockpit_db::db::agent_installations::DelegationTarget::ManagedWorktree
                        }
                    })
                    .collect(),
                computer_delegation_enabled: grant.computer_delegation_enabled(),
            });
    let recommendations = slots
        .values()
        .flat_map(|slot| slot.recommendations.clone())
        .collect();
    let bindings = slots
        .values()
        .flat_map(|slot| {
            slot.choices.iter().map(|choice| RedactedBindingEvidence {
                slot_id: slot.slot_id.clone(),
                binding_revision: choice.binding.binding_revision,
                provider_profile_handle: choice.offering.provider_profile_handle.clone(),
                model_id: choice.offering.model_id.clone(),
                selected_provider_alias: SnapshotProviderAlias {
                    provider_id: choice.offering.provider_id.clone(),
                    model_id: choice.offering.model_id.clone(),
                },
                provenance_digest: choice.binding.provenance_digest.clone(),
                hard_capability_verified: true,
                is_default: choice.binding.is_default,
            })
        })
        .collect();
    Ok(RedactedAgentProfileSnapshot {
        agent_id: vnext.agent_id.clone(),
        execution_kind: execution_kind(vnext.execution_kind),
        effective_delegation,
        recommendations,
        question_policy: snapshot_question_policy(questions, host)?,
        verification_regions: snapshot_verification_regions(
            &grant,
            slots,
            host,
            verification_reductions,
        )?,
        bindings,
    })
}

fn redacted_child((installation_id, kind): (Uuid, ExecutionKind)) -> RedactedAllowedChild {
    RedactedAllowedChild::LocalInstallation {
        installation_id,
        execution_kind: execution_kind(kind),
    }
}

fn execution_kind(kind: ExecutionKind) -> AgentExecutionKind {
    match kind {
        ExecutionKind::Assistant => AgentExecutionKind::Assistant,
        ExecutionKind::Coding => AgentExecutionKind::Coding,
        ExecutionKind::Computer => AgentExecutionKind::Computer,
    }
}

fn snapshot_question_policy(
    questions: Option<&EffectiveQuestionPolicy>,
    host: &VnextHostPolicy,
) -> Result<RedactedQuestionPolicy> {
    let Some(questions) = questions else {
        return Ok(RedactedQuestionPolicy::Off);
    };
    let resolver_slot = questions
        .resolver_slot
        .clone()
        .ok_or_else(|| anyhow::anyhow!("enabled question policy must resolve a utility slot"))?;
    Ok(RedactedQuestionPolicy::Active {
        auto_answer_disabled: false,
        prohibited_classes: questions
            .never_auto_resolve
            .iter()
            .map(|class| class.as_str().to_string())
            .collect(),
        required_decision_timeout_ms: u64::from(questions.decision_timeout_seconds) * 1_000,
        host_resource_ceiling_ms: u64::from(host.max_question_timeout_seconds) * 1_000,
        resolver_order: match questions.resolver_order {
            ResolverOrder::WarmParentThenUtility => QuestionResolverOrder::WarmParentThenUtility,
        },
        resolver_slot,
    })
}

fn questions_from_snapshot(
    policy: &RedactedQuestionPolicy,
) -> Result<Option<EffectiveQuestionPolicy>> {
    let RedactedQuestionPolicy::Active {
        auto_answer_disabled,
        prohibited_classes,
        required_decision_timeout_ms,
        resolver_order,
        resolver_slot,
        ..
    } = policy
    else {
        return Ok(None);
    };
    // A persisted disabled state is strictest and cannot be turned back on by
    // reload. The current writer always stores `false` for active policies,
    // but treating a legacy/corrupt `true` as disabled is fail closed.
    if *auto_answer_disabled {
        return Ok(None);
    }
    ensure!(
        required_decision_timeout_ms % 1_000 == 0 && *required_decision_timeout_ms > 0,
        "snapshot question timeout must be a positive whole number of seconds"
    );
    let mut never_auto_resolve = BTreeSet::new();
    for class in prohibited_classes {
        let class = match class.as_str() {
            "credential" => ProhibitedQuestionClass::Credential,
            "authorization" => ProhibitedQuestionClass::Authorization,
            "destructive" => ProhibitedQuestionClass::Destructive,
            "external_action" => ProhibitedQuestionClass::ExternalAction,
            "publish" => ProhibitedQuestionClass::Publish,
            "purchase" => ProhibitedQuestionClass::Purchase,
            "production" => ProhibitedQuestionClass::Production,
            _ => bail!("snapshot contains unknown prohibited question class `{class}`"),
        };
        ensure!(
            never_auto_resolve.insert(class),
            "snapshot duplicates prohibited question class"
        );
    }
    Ok(Some(EffectiveQuestionPolicy {
        decision_timeout_seconds: u32::try_from(*required_decision_timeout_ms / 1_000)
            .context("snapshot question timeout exceeds u32 seconds")?,
        resolver_order: match resolver_order {
            QuestionResolverOrder::WarmParentThenUtility => ResolverOrder::WarmParentThenUtility,
        },
        resolver_slot: Some(resolver_slot.clone()),
        never_auto_resolve,
    }))
}

fn snapshot_verification_regions(
    grant: &super::EffectiveVnextGrant,
    slots: &BTreeMap<String, ResolvedModelSlot>,
    host: &VnextHostPolicy,
    reductions: &BTreeMap<String, ProfileVerificationReduction>,
) -> Result<Vec<RedactedVerificationRegion>> {
    let Some(compiled) = &grant.verification else {
        return Ok(Vec::new());
    };
    compiled
        .regions
        .iter()
        .enumerate()
        .map(|(index, region)| {
            let source_rule_id = format!("rule-{index}");
            let selector = redacted_selector(&region.rule.selector);
            let source_mask = selector_mask(&region.rule.selector)?;
            let prior = region
                .excluded_by
                .iter()
                .map(redacted_selector)
                .collect::<Vec<_>>();
            let requested_budget = if region.rule.action == VerificationAction::Off {
                None
            } else {
                Some(region.rule.requested_budget(host.verification_ceiling)?)
            };
            let reduction = reductions
                .get(&source_rule_id)
                .cloned()
                .unwrap_or(ProfileVerificationReduction::Inherit);
            let (
                off,
                session_selector,
                enabled_intersection_mask,
                explicit_off_remainder_mask,
                budget,
            ) = match (requested_budget, reduction) {
                (
                    None,
                    ProfileVerificationReduction::Inherit | ProfileVerificationReduction::Off,
                ) => (true, None, Vec::new(), Vec::new(), None),
                (None, ProfileVerificationReduction::Restrict { .. }) => {
                    bail!("session verification reduction cannot enable an off definition region")
                }
                (Some(_), ProfileVerificationReduction::Off) => {
                    (true, None, Vec::new(), source_mask.clone(), None)
                }
                (Some(budget), ProfileVerificationReduction::Inherit) => {
                    (false, None, source_mask.clone(), Vec::new(), Some(budget))
                }
                (
                    Some(budget),
                    ProfileVerificationReduction::Restrict {
                        mut enabled_intersection_mask,
                        budget: session_budget,
                    },
                ) => {
                    enabled_intersection_mask.sort();
                    enabled_intersection_mask.dedup();
                    ensure!(
                        !enabled_intersection_mask.is_empty()
                            && enabled_intersection_mask
                                .iter()
                                .all(|mask| source_mask.binary_search(mask).is_ok())
                            && source_mask
                                .iter()
                                .filter(|mask| mask.starts_with("all:"))
                                .all(|mask| {
                                    enabled_intersection_mask.binary_search(mask).is_ok()
                                }),
                        "session verification intersection may only narrow its source region"
                    );
                    ensure!(
                        verification_budget_contains(budget, session_budget),
                        "session verification budget may only reduce its source region"
                    );
                    let explicit_off_remainder_mask = source_mask
                        .iter()
                        .filter(|mask| enabled_intersection_mask.binary_search(mask).is_err())
                        .cloned()
                        .collect();
                    (
                        false,
                        Some(selector_from_mask(
                            &region.rule.selector,
                            &enabled_intersection_mask,
                        )?),
                        enabled_intersection_mask,
                        explicit_off_remainder_mask,
                        Some(session_budget),
                    )
                }
            };
            let adjudicator_slot = region.rule.adjudicator_slot.clone();
            if let Some(slot) = &adjudicator_slot {
                ensure!(
                    slots.contains_key(slot),
                    "verification adjudicator slot has no installed binding"
                )
            }
            for generator in &region.rule.generators {
                ensure!(
                    slots.contains_key(&generator.slot),
                    "verification generator slot has no installed binding"
                )
            }
            Ok(RedactedVerificationRegion {
                source_rule_id,
                source_selector: selector.clone(),
                excluded_prior_selectors: prior,
                session_selector,
                enabled_intersection_mask,
                enabled: !off,
                explicit_off_remainder_mask,
                whole_region_off: off,
                whole_region_off_mask: if off { source_mask } else { Vec::new() },
                effective_action: if off {
                    VerificationEffectiveAction::Off
                } else {
                    VerificationEffectiveAction::Verify
                },
                adjudicator_slot: if off { None } else { adjudicator_slot },
                count_ceiling: budget.map(|budget| u64::from(budget.max_candidates)),
                token_ceiling: budget.map(|budget| budget.max_total_tokens),
                cost_ceiling_micros: budget.map(|budget| budget.max_estimated_cost_microusd),
                max_collection_duration_ms: budget.map(|budget| budget.max_collection_millis),
                execution_plan: (!off).then(|| RedactedVerificationExecutionPlan {
                    mode: match region.rule.resolved_mode() {
                        crate::agents::VerificationMode::Gate => "gate".to_string(),
                        crate::agents::VerificationMode::Revise => "revise".to_string(),
                    },
                    generators: region
                        .rule
                        .generators
                        .iter()
                        .map(|generator| RedactedVerificationGenerator {
                            slot: generator.slot.clone(),
                            recipe: match &generator.recipe {
                                crate::agents::VerificationRecipe::Inherit => {
                                    RedactedVerificationRecipe::Inherit
                                }
                                crate::agents::VerificationRecipe::CleanRoom {
                                    include_linked_files,
                                    last_n_reads,
                                } => RedactedVerificationRecipe::CleanRoom {
                                    include_linked_files: *include_linked_files,
                                    last_n_reads: *last_n_reads,
                                },
                            },
                            max_turns: generator.max_turns,
                        })
                        .collect(),
                    on_budget_exceeded: match region
                        .rule
                        .on_budget_exceeded
                        .unwrap_or(crate::agents::OnBudgetExceeded::DispatchOriginal)
                    {
                        crate::agents::OnBudgetExceeded::Refuse => "refuse".to_string(),
                        crate::agents::OnBudgetExceeded::DispatchOriginal => {
                            "dispatch_original".to_string()
                        }
                    },
                    on_adjudication_failure: match region.rule.resolved_on_adjudication_failure() {
                        crate::agents::OnAdjudicationFailure::Refuse => "refuse".to_string(),
                        crate::agents::OnAdjudicationFailure::DispatchOriginal => {
                            "dispatch_original".to_string()
                        }
                    },
                }),
            })
        })
        .collect()
}

fn selector_mask(selector: &super::VerificationSelector) -> Result<Vec<String>> {
    let mut mask = Vec::new();
    for predicate in &selector.all_of {
        mask.push(format!("all:{}", predicate_label(predicate)));
    }
    for predicate in &selector.any_of {
        mask.push(format!("any:{}", predicate_label(predicate)));
    }
    mask.sort();
    mask.dedup();
    ensure!(!mask.is_empty(), "verification selector cannot be empty");
    Ok(mask)
}

fn redacted_selector(selector: &super::VerificationSelector) -> RedactedVerificationSelector {
    RedactedVerificationSelector {
        all_of: selector.all_of.iter().map(redacted_predicate).collect(),
        any_of: selector.any_of.iter().map(redacted_predicate).collect(),
    }
}

fn redacted_predicate(predicate: &SelectorPredicate) -> RedactedVerificationPredicate {
    match predicate {
        SelectorPredicate::ToolClass { tool_class } => RedactedVerificationPredicate::ToolClass {
            tool_class: predicate_label(&SelectorPredicate::ToolClass {
                tool_class: *tool_class,
            })
            .trim_start_matches("tool_class:")
            .to_string(),
        },
        SelectorPredicate::ToolId { tool_id } => RedactedVerificationPredicate::ToolId {
            tool_id: tool_id.clone(),
        },
        SelectorPredicate::Namespace { namespace } => RedactedVerificationPredicate::Namespace {
            namespace: namespace.clone(),
        },
    }
}

fn selector_from_mask(
    source: &super::VerificationSelector,
    enabled_mask: &[String],
) -> Result<RedactedVerificationSelector> {
    let source_mask = selector_mask(source)?;
    ensure!(
        enabled_mask
            .iter()
            .all(|mask| source_mask.binary_search(mask).is_ok()),
        "session verification intersection contains an unknown selector predicate"
    );
    Ok(RedactedVerificationSelector {
        all_of: source
            .all_of
            .iter()
            .filter(|predicate| {
                enabled_mask
                    .binary_search(&format!("all:{}", predicate_label(predicate)))
                    .is_ok()
            })
            .map(redacted_predicate)
            .collect(),
        any_of: source
            .any_of
            .iter()
            .filter(|predicate| {
                enabled_mask
                    .binary_search(&format!("any:{}", predicate_label(predicate)))
                    .is_ok()
            })
            .map(redacted_predicate)
            .collect(),
    })
}

fn verification_budget_contains(ceiling: VerificationBudget, request: VerificationBudget) -> bool {
    request.max_candidates <= ceiling.max_candidates
        && request.max_total_tokens <= ceiling.max_total_tokens
        && request.max_estimated_cost_microusd <= ceiling.max_estimated_cost_microusd
        && request.max_collection_millis <= ceiling.max_collection_millis
}

fn predicate_label(predicate: &SelectorPredicate) -> String {
    match predicate {
        SelectorPredicate::ToolClass { tool_class } => format!(
            "tool_class:{}",
            match tool_class {
                super::ToolClass::Evidence => "evidence",
                super::ToolClass::ArtifactWrite => "artifact_write",
                super::ToolClass::Shell => "shell",
                super::ToolClass::Computer => "computer",
            }
        ),
        SelectorPredicate::ToolId { tool_id } => format!("tool_id:{tool_id}"),
        SelectorPredicate::Namespace { namespace } => format!("namespace:{namespace}"),
    }
}

fn validate_snapshot_self_contained(snapshot: &RedactedAgentProfileSnapshot) -> Result<()> {
    ensure!(
        !snapshot.agent_id.is_empty(),
        "profile snapshot lacks agent identity"
    );
    let slots: BTreeSet<_> = snapshot
        .bindings
        .iter()
        .map(|binding| binding.slot_id.as_str())
        .collect();
    match &snapshot.question_policy {
        RedactedQuestionPolicy::Off => {}
        RedactedQuestionPolicy::Active {
            resolver_slot,
            required_decision_timeout_ms,
            host_resource_ceiling_ms,
            ..
        } => {
            ensure!(
                slots.contains(resolver_slot.as_str()),
                "question policy must reference a snapshot binding"
            );
            ensure!(
                required_decision_timeout_ms <= host_resource_ceiling_ms,
                "question timeout exceeds host ceiling"
            );
        }
    }
    for region in &snapshot.verification_regions {
        if region.enabled {
            let slot = region
                .adjudicator_slot
                .as_deref()
                .context("enabled verification region lacks adjudicator slot")?;
            ensure!(
                slots.contains(slot),
                "verification region must reference a snapshot binding"
            );
            ensure!(
                region
                    .execution_plan
                    .as_ref()
                    .context("enabled verification region lacks an execution plan")?
                    .generators
                    .iter()
                    .all(|generator| slots.contains(generator.slot.as_str())),
                "verification generator region must reference snapshot bindings"
            );
        }
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    crate::intel::hex_lower(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_config::config::providers::{
        ComputerUseCapability, ComputerUseContract, ModelEntry, ProviderEntry,
    };
    use cockpit_db::db::agent_installations::{
        AgentBindingInput, AgentInstallationInput, BindAgentOutcome, InstallAgentOutcome,
        ObserveAgentOutcome,
    };

    fn definition(extra: &str) -> AgentDef {
        super::super::parse_agent(
            &format!(
                "---\ndescription: Profile test\nschemaVersion: 2\nagentId: authored/profile-test\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Primary\n    minContextTokens: 8\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n{extra}---\nbody\n"
            ),
            "profile-test",
            "profile-test.md".into(),
        )
        .expect("test definition parses")
    }

    fn providers() -> ProvidersConfig {
        let mut config = ProvidersConfig::default();
        let mut provider = ProviderEntry::default();
        provider.models.push(ModelEntry {
            id: "model-a".into(),
            context_length: Some(64),
            ..ModelEntry::default()
        });
        provider.models.push(ModelEntry {
            id: "model-b".into(),
            context_length: Some(64),
            ..ModelEntry::default()
        });
        provider.models.push(ModelEntry {
            id: "model-a-latest".into(),
            context_length: Some(64),
            ..ModelEntry::default()
        });
        config.providers.insert("provider".into(), provider);
        config
    }

    fn catalog(definition: AgentDef) -> (AgentProfileInstallationCatalog, Uuid, String) {
        let installation_id = Uuid::now_v7();
        let digest = hex_digest(&definition.vnext_digest_bytes().expect("digest"));
        let catalog = AgentProfileInstallationCatalog::new([AgentProfileDefinition {
            installation: AgentInstallationRow {
                installation_id,
                scope: AgentInstallationScope::WorkspaceShared,
                canonical_workspace_id: Some("workspace".into()),
                source_agent_id: "authored/profile-test".into(),
                source_identity: "workspace-agent".into(),
                source_revision: None,
                source_digest: digest.clone(),
                fetched_at_unix_ms: 0,
                installation_revision: 1,
                deleted_at_unix_ms: None,
            },
            observation: AgentObservationRow {
                installation_id,
                observed_digest: digest.clone(),
                observation_revision: 1,
                reviewed: true,
                observed_at_unix_ms: 0,
            },
            source: AgentProfileInstallationSource::WorkspaceShared,
            definition,
        }])
        .expect("catalog");
        (catalog, installation_id, digest)
    }

    fn binding(installation_id: Uuid, digest: String, model_id: &str) -> AgentBindingRow {
        AgentBindingRow {
            binding_id: Uuid::now_v7(),
            installation_id,
            definition_digest: digest,
            slot_id: "primary".into(),
            provider_profile_handle: "profile".into(),
            model_id: model_id.into(),
            provenance_payload: Vec::new(),
            provenance_digest: hex_digest(b"provenance"),
            hard_capability_verified: true,
            is_default: true,
            binding_revision: 1,
            retired_at_unix_ms: None,
            created_at_unix_ms: 0,
        }
    }

    fn offering(model_id: &str) -> AgentProfileModelOffering {
        AgentProfileModelOffering {
            offering_id: model_id.into(),
            provider_profile_handle: "profile".into(),
            provider_id: "provider".into(),
            model_id: model_id.into(),
        }
    }

    fn persisted_snapshot_row(profile: &ResolvedAgentProfile) -> AgentProfileSnapshotRow {
        let canonical_payload = profile
            .canonical_snapshot_payload()
            .expect("canonical resolved snapshot");
        let revision_map = AgentBindingRevisionMap {
            bindings: profile
                .slots
                .values()
                .map(|slot| AgentBindingRevision {
                    slot_id: slot.slot_id.clone(),
                    provider_profile_handle: slot.choice.binding.provider_profile_handle.clone(),
                    model_id: slot.choice.binding.model_id.clone(),
                    binding_revision: slot.choice.binding.binding_revision,
                })
                .collect(),
        };
        let binding_revision_map_payload =
            serde_json::to_vec(&revision_map).expect("canonical binding revision map");
        AgentProfileSnapshotRow {
            snapshot_id: Uuid::now_v7(),
            session_id: Uuid::now_v7(),
            installation_id: profile.installation_id,
            schema_version: 1,
            canonical_payload_digest: hex_digest(&canonical_payload),
            canonical_payload,
            definition_digest: profile.definition_digest.clone(),
            binding_revision_map_digest: hex_digest(&binding_revision_map_payload),
            binding_revision_map_payload,
            created_at_unix_ms: 0,
        }
    }

    #[test]
    fn agent_profile_resolution_exact_alias_order_and_fuzzy_non_equivalence() {
        let definition = definition(
            "    suggestedModels:\n      - recommendationId: b\n        upstreamIdentity: upstream/model-b\n        providerAliases:\n          - providerId: provider\n            modelId: model-b\n      - recommendationId: a\n        upstreamIdentity: upstream/model-a\n        providerAliases:\n          - providerId: provider\n            modelId: model-a\n",
        );
        let (catalog, installation_id, digest) = catalog(definition);
        let providers = providers();
        let profile = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            bindings: vec![binding(installation_id, digest, "model-a")],
            offerings: vec![offering("model-a"), offering("model-b")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: VnextHostPolicy::default(),
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect("exact alias resolves");
        let primary = &profile.slots["primary"];
        assert_eq!(primary.choice.exact_recommendation_id.as_deref(), Some("a"));
        assert_eq!(
            primary.remaining_compatible_offerings,
            vec!["model-b".to_string()]
        );
        assert!(
            primary
                .recommendations
                .iter()
                .find(|recommendation| recommendation.recommendation_id == "b")
                .is_some_and(|recommendation| !recommendation.author_suggested)
        );
    }

    #[test]
    fn agent_profile_resolution_unsuggested_route_is_allowed_but_never_fuzzy_matched() {
        let definition = definition(
            "    suggestedModels:\n      - recommendationId: exact-a\n        upstreamIdentity: upstream/a\n        providerAliases:\n          - providerId: provider\n            modelId: model-a\n",
        );
        let (catalog, installation_id, digest) = catalog(definition);
        let providers = providers();
        let profile = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            bindings: vec![binding(installation_id, digest, "model-a-latest")],
            offerings: vec![offering("model-a"), offering("model-a-latest")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: VnextHostPolicy::default(),
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect("compatible but unsuggested local route resolves");
        let primary = &profile.slots["primary"];
        assert!(!primary.choice.author_suggested);
        assert_eq!(primary.choice.exact_recommendation_id, None);
        assert!(
            primary
                .recommendations
                .iter()
                .all(|recommendation| !recommendation.author_suggested)
        );
    }

    #[test]
    fn agent_profile_resolution_digest_change_and_missing_binding_fail_closed() {
        let definition = definition("");
        let (catalog, installation_id, _) = catalog(definition);
        let providers = providers();
        let error = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            bindings: Vec::new(),
            offerings: vec![offering("model-a")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: VnextHostPolicy::default(),
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect_err("missing binding fails closed");
        assert!(error.to_string().contains("no binding"));
    }

    #[test]
    fn agent_profile_resolution_manifest_cannot_influence_host_authority() {
        for injected_field in [
            "    trust: trusted\n",
            "    credentials: inherited\n",
            "    sandbox: unrestricted\n",
            "    approvals: automatic\n",
        ] {
            let text = format!(
                "---\ndescription: authority test\nschemaVersion: 2\nagentId: authored/authority-test\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 8\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n{injected_field}---\nbody\n"
            );
            assert!(
                super::super::parse_agent(&text, "authority-test", "authority-test.md".into())
                    .is_err(),
                "manifest field must not create host authority: {injected_field:?}"
            );
        }
    }

    #[test]
    fn agent_profile_resolution_question_override_monotonic_missing_timeout_is_rejected() {
        let text = "---\ndescription: question test\nschemaVersion: 2\nagentId: authored/question-test\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 8\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\nquestions:\n  autoAnswer: recommended_low_risk\n  resolverOrder: warm_parent_then_utility\n  resolverSlot: primary\n---\nbody\n";
        assert!(
            super::super::parse_agent(text, "question-test", "question-test.md".into()).is_err()
        );
    }

    #[test]
    fn agent_profile_resolution_rejects_an_unreviewed_or_noncurrent_observation() {
        let definition = definition("");
        let (mut catalog, installation_id, digest) = catalog(definition);
        let providers = providers();
        catalog
            .definitions
            .get_mut(&installation_id)
            .expect("selected definition")
            .observation
            .reviewed = false;
        let error = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            bindings: vec![binding(installation_id, digest, "model-a")],
            offerings: vec![offering("model-a")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: VnextHostPolicy::default(),
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect_err("unreviewed observation must fail before binding selection");
        assert!(error.to_string().contains("unreviewed"));
    }

    #[test]
    fn agent_profile_resolution_catalog_retains_same_display_name_in_every_scope() {
        let definition = definition("");
        let (base, selected_id, _) = catalog(definition);
        let selected = base
            .selected(selected_id)
            .expect("fixture definition")
            .clone();
        let mut global = selected.clone();
        global.installation.installation_id = Uuid::now_v7();
        global.installation.scope = AgentInstallationScope::Global;
        global.installation.canonical_workspace_id = None;
        global.installation.source_agent_id = "local/00000000-0000-0000-0000-000000000001".into();
        global
            .definition
            .vnext
            .as_mut()
            .expect("global vNext")
            .agent_id = "local/00000000-0000-0000-0000-000000000001".into();
        global.installation.source_digest = hex_digest(
            &global
                .definition
                .vnext_digest_bytes()
                .expect("global digest"),
        );
        global.observation.installation_id = global.installation.installation_id;
        global.observation.observed_digest = global.installation.source_digest.clone();
        global.source = AgentProfileInstallationSource::Global;
        let mut private = selected.clone();
        private.installation.installation_id = Uuid::now_v7();
        private.installation.scope = AgentInstallationScope::WorkspacePrivate;
        private.installation.source_agent_id = "local/00000000-0000-0000-0000-000000000001".into();
        private
            .definition
            .vnext
            .as_mut()
            .expect("private vNext")
            .agent_id = "local/00000000-0000-0000-0000-000000000001".into();
        private.installation.source_digest = hex_digest(
            &private
                .definition
                .vnext_digest_bytes()
                .expect("private digest"),
        );
        private.observation.installation_id = private.installation.installation_id;
        private.observation.observed_digest = private.installation.source_digest.clone();
        private.source = AgentProfileInstallationSource::WorkspacePrivate;
        let catalog =
            AgentProfileInstallationCatalog::new([global.clone(), private.clone(), selected])
                .expect("same display names are distinct installation records");
        assert_eq!(
            catalog
                .selected(global.installation.installation_id)
                .expect("global selection")
                .source,
            AgentProfileInstallationSource::Global
        );
        assert_eq!(
            catalog
                .selected(private.installation.installation_id)
                .expect("private selection")
                .source,
            AgentProfileInstallationSource::WorkspacePrivate
        );
        assert_eq!(
            catalog
                .selected(selected_id)
                .expect("shared selection")
                .source,
            AgentProfileInstallationSource::WorkspaceShared
        );
    }

    #[test]
    fn agent_profile_resolution_utility_fallback_requires_a_durable_local_binding() {
        let definition = definition(
            "  utility:\n    purpose: Utility\n    minContextTokens: 8\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: true\n",
        );
        let (catalog, installation_id, digest) = catalog(definition);
        let providers = providers();
        let primary = binding(installation_id, digest.clone(), "model-a");
        let mut utility = binding(installation_id, digest, "model-b");
        utility.slot_id = "utility".into();
        utility.binding_id = Uuid::now_v7();
        let mut fallbacks = BTreeMap::new();
        fallbacks.insert(
            "utility".into(),
            AgentProfileFallbackRoute {
                offering: offering("model-b"),
                binding: utility.clone(),
            },
        );
        let profile = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            // The fallback itself carries the durable installation binding;
            // it need not also be an explicit user-selected slot binding.
            bindings: vec![primary],
            offerings: vec![offering("model-a"), offering("model-b")],
            utility_fallbacks: fallbacks.clone(),
            providers: &providers,
            host_policy: VnextHostPolicy::default(),
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect("durable installation-local fallback resolves");
        assert_eq!(
            profile.slots["utility"].choice.binding.binding_id,
            utility.binding_id
        );

        let mut explicit_utility = utility.clone();
        explicit_utility.binding_id = Uuid::now_v7();
        explicit_utility.model_id = "model-a".into();
        let explicit_profile = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            bindings: vec![
                profile.slots["primary"].choice.binding.clone(),
                explicit_utility.clone(),
            ],
            offerings: vec![offering("model-a"), offering("model-b")],
            utility_fallbacks: fallbacks,
            providers: &providers,
            host_policy: VnextHostPolicy::default(),
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect("explicit utility binding wins over an available fallback");
        assert_eq!(
            explicit_profile.slots["utility"].choice.binding.binding_id,
            explicit_utility.binding_id
        );
        assert_eq!(
            explicit_profile.slots["utility"].choice.offering.model_id,
            "model-a"
        );

        let mut non_durable = profile.slots["utility"].choice.binding.clone();
        non_durable.installation_id = Uuid::now_v7();
        let error = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            bindings: vec![profile.slots["primary"].choice.binding.clone()],
            offerings: vec![offering("model-a"), offering("model-b")],
            utility_fallbacks: BTreeMap::from([(
                "utility".into(),
                AgentProfileFallbackRoute {
                    offering: offering("model-b"),
                    binding: non_durable,
                },
            )]),
            providers: &providers,
            host_policy: VnextHostPolicy::default(),
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect_err("foreign fallback binding must fail");
        assert!(
            error
                .to_string()
                .contains("installation-local durable binding")
        );
    }

    #[test]
    fn agent_profile_resolution_question_override_monotonic_disable_is_strictest() {
        let definition = definition(
            "questions:\n  autoAnswer: recommended_low_risk\n  decisionTimeoutSeconds: 10\n  resolverOrder: warm_parent_then_utility\n  resolverSlot: primary\n  neverAutoResolve: [credential]\n",
        );
        let (catalog, installation_id, digest) = catalog(definition);
        let providers = providers();
        let profile = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            bindings: vec![binding(installation_id, digest, "model-a")],
            offerings: vec![offering("model-a")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: VnextHostPolicy {
                max_question_timeout_seconds: 60,
                ..VnextHostPolicy::default()
            },
            question_override: ProfileQuestionOverride::Disable,
            verification_reductions: BTreeMap::new(),
        })
        .expect("disable is valid");
        assert!(matches!(
            profile.snapshot.question_policy,
            RedactedQuestionPolicy::Off
        ));
        let persisted = persisted_snapshot_row(&profile);
        assert!(
            ResolvedAgentProfile::reload_persisted(
                &persisted,
                profile.installation_revision,
                profile.observation_revision,
            )
            .expect("snapshot reload")
            .effective_questions
            .is_none()
        );
    }

    #[test]
    fn agent_profile_resolution_question_override_monotonic_rejects_enable_shorten_and_over_ceiling()
     {
        let definition = definition(
            "questions:\n  autoAnswer: recommended_low_risk\n  decisionTimeoutSeconds: 10\n  resolverOrder: warm_parent_then_utility\n  resolverSlot: primary\n  neverAutoResolve: [credential]\n",
        );
        let policy = definition
            .vnext
            .as_ref()
            .and_then(|definition| definition.questions.as_ref())
            .expect("question fixture")
            .clone();
        let host = VnextHostPolicy {
            max_question_timeout_seconds: 60,
            non_auto_resolvable: BTreeSet::from([ProhibitedQuestionClass::Publish]),
            ..VnextHostPolicy::default()
        };
        let mut shortened = policy.clone();
        shortened.decision_timeout_seconds = 9;
        assert!(
            resolve_question_policy(Some(&policy), &host, QuestionOverride::Reduce(shortened))
                .is_err()
        );
        let mut over_ceiling = policy.clone();
        over_ceiling.decision_timeout_seconds = 61;
        assert!(
            resolve_question_policy(Some(&policy), &host, QuestionOverride::Reduce(over_ceiling))
                .is_err()
        );
        assert!(
            resolve_question_policy(None, &host, QuestionOverride::Reduce(policy.clone())).is_err()
        );
        let mut different_slot = policy.clone();
        different_slot.resolver_slot = Some("other".into());
        assert!(
            resolve_question_policy(
                Some(&policy),
                &host,
                QuestionOverride::Reduce(different_slot)
            )
            .is_err()
        );
        let mut longer = policy;
        longer.decision_timeout_seconds = 20;
        let resolved = resolve_question_policy(
            definition
                .vnext
                .as_ref()
                .and_then(|definition| definition.questions.as_ref()),
            &host,
            QuestionOverride::Reduce(longer),
        )
        .expect("longer timeout is monotonic")
        .expect("questions stay enabled");
        assert!(
            resolved
                .never_auto_resolve
                .contains(&ProhibitedQuestionClass::Credential)
        );
        assert!(
            resolved
                .never_auto_resolve
                .contains(&ProhibitedQuestionClass::Publish)
        );
        assert_eq!(resolved.decision_timeout_seconds, 20);
    }

    #[test]
    fn agent_profile_resolution_question_override_monotonic_active_snapshot_preserves_route_union_and_ceiling()
     {
        let definition = definition(
            "questions:\n  autoAnswer: recommended_low_risk\n  decisionTimeoutSeconds: 10\n  resolverOrder: warm_parent_then_utility\n  resolverSlot: primary\n  neverAutoResolve: [credential]\n",
        );
        let (catalog, installation_id, digest) = catalog(definition);
        let providers = providers();
        let host = VnextHostPolicy {
            max_question_timeout_seconds: 60,
            non_auto_resolvable: BTreeSet::from([ProhibitedQuestionClass::Publish]),
            ..VnextHostPolicy::default()
        };
        let profile = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            bindings: vec![binding(installation_id, digest, "model-a")],
            offerings: vec![offering("model-a")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: host,
            question_override: ProfileQuestionOverride::Reduce(QuestionPolicy {
                auto_answer: super::super::AutoAnswer::RecommendedLowRisk,
                decision_timeout_seconds: 20,
                resolver_order: ResolverOrder::WarmParentThenUtility,
                resolver_slot: Some("primary".into()),
                never_auto_resolve: Vec::new(),
            }),
            verification_reductions: BTreeMap::new(),
        })
        .expect("monotonic active policy resolves");
        let persisted = persisted_snapshot_row(&profile);
        let reloaded = ResolvedAgentProfile::reload_persisted(
            &persisted,
            profile.installation_revision,
            profile.observation_revision,
        )
        .expect("active question snapshot reload");
        let questions = reloaded.effective_questions.expect("active questions");
        assert_eq!(questions.decision_timeout_seconds, 20);
        assert_eq!(questions.resolver_slot.as_deref(), Some("primary"));
        assert!(
            questions
                .never_auto_resolve
                .contains(&ProhibitedQuestionClass::Credential)
        );
        assert!(
            questions
                .never_auto_resolve
                .contains(&ProhibitedQuestionClass::Publish)
        );
    }

    #[test]
    fn agent_profile_resolution_hard_capability_and_locality_unknown_fail_closed() {
        let tool_slot = super::super::ModelSlot {
            purpose: "tools".into(),
            min_context_tokens: 8,
            required_capabilities: vec![ModelCapability::ToolCalling],
            locality: ModelLocality::Local,
            allow_default_fallback: false,
            suggested_models: Vec::new(),
            models: Vec::new(),
        };
        let caps = EffectiveModelCapabilities {
            context_tokens: Some(64),
            ..EffectiveModelCapabilities::default()
        };
        assert!(
            !hard_requirements_satisfied(&tool_slot, None, &caps),
            "unknown locality and capability evidence must not satisfy a hard requirement"
        );
    }

    #[test]
    fn agent_profile_resolution_computer_use_requires_a_concrete_contract() {
        let computer_slot = super::super::ModelSlot {
            purpose: "computer".into(),
            min_context_tokens: 8,
            required_capabilities: vec![ModelCapability::ComputerUse],
            locality: ModelLocality::Any,
            allow_default_fallback: false,
            suggested_models: Vec::new(),
            models: Vec::new(),
        };
        let mut caps = EffectiveModelCapabilities {
            context_tokens: Some(64),
            computer_use: Some(ComputerUseCapability::default()),
            ..EffectiveModelCapabilities::default()
        };
        assert!(!hard_requirements_satisfied(&computer_slot, None, &caps));
        caps.computer_use = Some(ComputerUseCapability {
            contract: Some(ComputerUseContract::OpenAiResponses),
            source: None,
        });
        assert!(hard_requirements_satisfied(&computer_slot, None, &caps));
    }

    #[test]
    fn agent_profile_resolution_portable_child_missing_fails_closed() {
        let definition = definition(
            "delegation:\n  allowedChildren:\n    - kind: portable_ref\n      ref: authored/child\n  maxDescendantDepth: 1\n  maxConcurrentChildren: 1\n  targets: [same_root]\n",
        );
        let (catalog, installation_id, digest) = catalog(definition);
        let providers = providers();
        let error = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            bindings: vec![binding(installation_id, digest, "model-a")],
            offerings: vec![offering("model-a")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: VnextHostPolicy {
                max_descendant_depth: 1,
                max_concurrent_children: 1,
                allowed_targets: BTreeSet::from([super::super::DelegationTarget::SameRoot]),
                ..VnextHostPolicy::default()
            },
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect_err("unmapped portable child fails closed");
        assert!(
            error
                .to_string()
                .contains("no observed scope-compatible installation")
        );
    }

    #[test]
    fn agent_profile_resolution_portable_child_ambiguous_and_private_scope_fail_closed() {
        let parent_definition = definition(
            "delegation:\n  allowedChildren:\n    - kind: portable_ref\n      ref: authored/child\n  maxDescendantDepth: 1\n  maxConcurrentChildren: 1\n  targets: [same_root]\n",
        );
        let (parent_catalog, parent_id, parent_digest) = catalog(parent_definition);
        let parent = parent_catalog
            .selected(parent_id)
            .expect("parent fixture")
            .clone();
        let child = |installation_id: Uuid,
                     scope: AgentInstallationScope,
                     workspace: Option<&str>,
                     source: AgentProfileInstallationSource| {
            let mut child = parent.clone();
            child.installation.installation_id = installation_id;
            child.installation.scope = scope;
            child.installation.canonical_workspace_id = workspace.map(str::to_owned);
            child.source = source;
            let agent_id = match source {
                AgentProfileInstallationSource::Global
                | AgentProfileInstallationSource::WorkspacePrivate => {
                    "local/00000000-0000-0000-0000-000000000002"
                }
                AgentProfileInstallationSource::WorkspaceShared => "authored/child",
                AgentProfileInstallationSource::Builtin => "cockpit/child",
            };
            child.installation.source_agent_id = agent_id.into();
            let vnext = child.definition.vnext.as_mut().expect("child vNext");
            vnext.agent_id = agent_id.into();
            // This fixture is a leaf child definition.  The parent owns the
            // portable/local selection being exercised below; copying its
            // portable child declaration into a daemon-local child would be
            // invalid by design.
            if matches!(
                source,
                AgentProfileInstallationSource::Global
                    | AgentProfileInstallationSource::WorkspacePrivate
            ) {
                vnext.delegation = Default::default();
            }
            let digest = hex_digest(&child.definition.vnext_digest_bytes().expect("child digest"));
            child.installation.source_digest = digest.clone();
            child.observation = AgentObservationRow {
                installation_id,
                observed_digest: digest,
                observation_revision: 1,
                reviewed: true,
                observed_at_unix_ms: 0,
            };
            child
        };
        let first = child(
            Uuid::now_v7(),
            AgentInstallationScope::WorkspaceShared,
            Some("workspace"),
            AgentProfileInstallationSource::WorkspaceShared,
        );
        let second = child(
            Uuid::now_v7(),
            AgentInstallationScope::WorkspaceShared,
            Some("workspace"),
            AgentProfileInstallationSource::WorkspaceShared,
        );
        let providers = providers();
        let host = VnextHostPolicy {
            max_descendant_depth: 1,
            max_concurrent_children: 1,
            allowed_targets: BTreeSet::from([super::super::DelegationTarget::SameRoot]),
            ..VnextHostPolicy::default()
        };
        let ambiguous = AgentProfileInstallationCatalog::new([parent.clone(), first, second])
            .expect("ambiguous catalog is representable");
        let error = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id: parent_id,
            catalog: &ambiguous,
            bindings: vec![binding(parent_id, parent_digest.clone(), "model-a")],
            offerings: vec![offering("model-a")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: host.clone(),
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect_err("two exact portable children are ambiguous");
        assert!(
            error
                .to_string()
                .contains("multiple observed installations")
        );

        let private = child(
            Uuid::now_v7(),
            AgentInstallationScope::WorkspacePrivate,
            Some("workspace"),
            AgentProfileInstallationSource::WorkspacePrivate,
        );
        let private_id = private.installation.installation_id;
        let mut local_parent = parent.clone();
        // Local-installation references are valid only on daemon-local
        // definitions. Place the parent in another private workspace so this
        // still exercises the required private-scope fail-closed branch.
        local_parent.installation.scope = AgentInstallationScope::WorkspacePrivate;
        local_parent.installation.canonical_workspace_id = Some("other-workspace".into());
        local_parent.installation.source_agent_id =
            "local/00000000-0000-0000-0000-000000000003".into();
        local_parent.source = AgentProfileInstallationSource::WorkspacePrivate;
        let local_parent_id = local_parent.installation.installation_id;
        let parent_vnext = local_parent
            .definition
            .vnext
            .as_mut()
            .expect("local parent vNext");
        parent_vnext.agent_id = "local/00000000-0000-0000-0000-000000000003".into();
        parent_vnext.delegation.allowed_children =
            vec![super::super::AllowedChild::LocalInstallation {
                installation_id: private_id,
            }];
        let local_parent_digest = hex_digest(
            &local_parent
                .definition
                .vnext_digest_bytes()
                .expect("parent digest"),
        );
        local_parent.installation.source_digest = local_parent_digest.clone();
        local_parent.observation.installation_id = local_parent_id;
        local_parent.observation.observed_digest = local_parent_digest.clone();
        let scope_mismatch = AgentProfileInstallationCatalog::new([local_parent, private])
            .expect("source-valid private child catalog");
        let error = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id: local_parent_id,
            catalog: &scope_mismatch,
            bindings: vec![binding(local_parent_id, local_parent_digest, "model-a")],
            offerings: vec![offering("model-a")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: host,
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect_err("shared parent cannot select private child");
        assert!(error.to_string().contains("scope-incompatible"));
    }

    #[test]
    fn agent_profile_resolution_child_kind_and_identity_survive_snapshot_reload() {
        let parent_definition = definition(
            "delegation:\n  allowedChildren:\n    - kind: portable_ref\n      ref: authored/child\n  maxDescendantDepth: 1\n  maxConcurrentChildren: 1\n  targets: [same_root]\n",
        );
        let (parent_catalog, parent_id, parent_digest) = catalog(parent_definition);
        let parent = parent_catalog
            .selected(parent_id)
            .expect("parent fixture")
            .clone();
        let mut child = parent.clone();
        child.installation.installation_id = Uuid::now_v7();
        child.installation.scope = AgentInstallationScope::WorkspaceShared;
        child.installation.canonical_workspace_id = Some("workspace".into());
        child.installation.source_agent_id = "authored/child".into();
        child.source = AgentProfileInstallationSource::WorkspaceShared;
        child
            .definition
            .vnext
            .as_mut()
            .expect("child vNext")
            .agent_id = "authored/child".into();
        let child_digest =
            hex_digest(&child.definition.vnext_digest_bytes().expect("child digest"));
        child.installation.source_digest = child_digest.clone();
        child.observation = AgentObservationRow {
            installation_id: child.installation.installation_id,
            observed_digest: child_digest,
            observation_revision: 1,
            reviewed: true,
            observed_at_unix_ms: 0,
        };
        let catalog = AgentProfileInstallationCatalog::new([parent, child.clone()])
            .expect("catalog with exact portable child");
        let providers = providers();
        let profile = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id: parent_id,
            catalog: &catalog,
            bindings: vec![binding(parent_id, parent_digest, "model-a")],
            offerings: vec![offering("model-a")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: VnextHostPolicy {
                max_descendant_depth: 1,
                max_concurrent_children: 1,
                allowed_targets: BTreeSet::from([super::super::DelegationTarget::SameRoot]),
                ..VnextHostPolicy::default()
            },
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect("scope-compatible coding child resolves");
        assert_eq!(
            profile.child_execution_kinds[&child.installation.installation_id],
            AgentExecutionKind::Coding
        );
        let persisted = persisted_snapshot_row(&profile);
        let reloaded = ResolvedAgentProfile::reload_persisted(
            &persisted,
            profile.installation_revision,
            profile.observation_revision,
        )
        .expect("reload uses child snapshot only");
        assert_eq!(
            reloaded.child_execution_kinds[&child.installation.installation_id],
            AgentExecutionKind::Coding
        );
    }

    #[test]
    fn agent_profile_resolution_verification_first_match_off_and_narrowing_are_pinned_on_reload() {
        let definition = definition(
            "verification:\n  rules:\n    - selector:\n        allOf: [{ toolClass: shell }]\n      action: off\n    - selector:\n        allOf: [{ toolClass: shell }]\n        anyOf: [{ toolId: bash }, { namespace: terminal }]\n      action: verify\n      adjudicatorSlot: primary\n      maxCandidates: 1\n      maxTotalTokens: 20\n      maxEstimatedCostMicrousd: 30\n      maxCollectionMillis: 40\n      mode: revise\n      onBudgetExceeded: dispatch_original\n      onAdjudicationFailure: refuse\n      generators:\n        - slot: primary\n          recipe:\n            cleanRoom:\n              includeLinkedFiles: true\n              lastNReads: 4\n          maxTurns: 3\n",
        );
        let (catalog, installation_id, digest) = catalog(definition);
        let providers = providers();
        let host = VnextHostPolicy {
            verification_ceiling: VerificationBudget {
                max_candidates: 2,
                max_total_tokens: 100,
                max_estimated_cost_microusd: 100,
                max_collection_millis: 100,
            },
            ..VnextHostPolicy::default()
        };
        let profile = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            bindings: vec![binding(installation_id, digest, "model-a")],
            offerings: vec![offering("model-a")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: host,
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::from([(
                "rule-1".into(),
                ProfileVerificationReduction::Restrict {
                    enabled_intersection_mask: vec![
                        "all:tool_class:shell".into(),
                        "any:tool_id:bash".into(),
                    ],
                    budget: VerificationBudget {
                        max_candidates: 1,
                        max_total_tokens: 10,
                        max_estimated_cost_microusd: 20,
                        max_collection_millis: 30,
                    },
                },
            )]),
        })
        .expect("first-match policy resolves");
        assert!(profile.snapshot.verification_regions[0].whole_region_off);
        assert_eq!(
            profile.snapshot.verification_regions[1]
                .excluded_prior_selectors
                .len(),
            1
        );
        assert_eq!(
            profile.snapshot.verification_regions[1].enabled_intersection_mask,
            vec!["all:tool_class:shell", "any:tool_id:bash"]
        );
        assert_eq!(
            profile.snapshot.verification_regions[1].explicit_off_remainder_mask,
            vec!["any:namespace:terminal"]
        );
        let shell = cockpit_db::db::agent_installations::RedactedVerificationSubject {
            tool_class: Some("shell".into()),
            ..Default::default()
        };
        assert!(
            profile.snapshot.verification_regions[0].matches(&shell),
            "the first matching off region remains an evaluated terminal region"
        );
        assert!(
            !profile.snapshot.verification_regions[1].matches(&shell),
            "an earlier off rule prevents later verification fallthrough"
        );
        assert_eq!(
            profile.snapshot.verification_regions[1].token_ceiling,
            Some(10)
        );
        let execution = profile.snapshot.verification_regions[1]
            .execution_plan
            .as_ref()
            .expect("enabled region pins its complete execution plan");
        assert_eq!(execution.mode, "revise");
        assert_eq!(execution.on_budget_exceeded, "dispatch_original");
        assert_eq!(execution.on_adjudication_failure, "refuse");
        assert_eq!(execution.generators.len(), 1);
        assert_eq!(execution.generators[0].slot, "primary");
        assert_eq!(execution.generators[0].max_turns, 3);
        assert_eq!(
            execution.generators[0].recipe,
            RedactedVerificationRecipe::CleanRoom {
                include_linked_files: true,
                last_n_reads: 4,
            }
        );
        let persisted = persisted_snapshot_row(&profile);
        let reloaded = ResolvedAgentProfile::reload_persisted(
            &persisted,
            profile.installation_revision,
            profile.observation_revision,
        )
        .expect("reload keeps explicit first-match exclusions");
        assert!(reloaded.snapshot.verification_regions[0].whole_region_off);
        assert_eq!(
            reloaded.snapshot.verification_regions[1]
                .excluded_prior_selectors
                .len(),
            1
        );
        assert_eq!(
            reloaded.snapshot.verification_regions[1].enabled_intersection_mask,
            vec!["all:tool_class:shell", "any:tool_id:bash"]
        );
        assert_eq!(
            reloaded.snapshot.verification_regions[1].execution_plan,
            profile.snapshot.verification_regions[1].execution_plan
        );
        assert_eq!(
            reloaded.snapshot.verification_regions[1].explicit_off_remainder_mask,
            vec!["any:namespace:terminal"]
        );
        assert!(reloaded.snapshot.verification_regions[0].matches(&shell));
        assert!(!reloaded.snapshot.verification_regions[1].matches(&shell));
    }

    #[tokio::test]
    async fn agent_profile_resolution_prepare_session_persists_and_reloads_only_durable_profile() {
        let initial_definition = definition("");
        let (catalog, installation_id, definition_digest) = catalog(initial_definition);
        let selected = catalog
            .selected(installation_id)
            .expect("selected catalog installation")
            .clone();
        let db = cockpit_db::Db::open_in_memory().expect("in-memory DB");
        let installed = match db
            .install_agent(AgentInstallationInput {
                installation_id,
                scope: selected.installation.scope,
                canonical_workspace_id: selected.installation.canonical_workspace_id.clone(),
                source_agent_id: selected.installation.source_agent_id.clone(),
                source_identity: selected.installation.source_identity.clone(),
                source_revision: selected.installation.source_revision.clone(),
                source_digest: definition_digest.clone(),
                fetched_at_unix_ms: 10,
            })
            .await
            .expect("install selected definition")
        {
            InstallAgentOutcome::Installed(row) => row,
            outcome => panic!("expected installed definition, got {outcome:?}"),
        };
        let provenance_payload = b"profile-resolution-durable-provenance".to_vec();
        let db_binding = match db
            .bind_agent_model(
                installation_id,
                definition_digest.clone(),
                None,
                "profile-resolution-bind".into(),
                "profile-resolution-bind-fingerprint".into(),
                AgentBindingInput {
                    slot_id: "primary".into(),
                    provider_profile_handle: "profile".into(),
                    model_id: "model-a".into(),
                    provenance_digest: hex_digest(&provenance_payload),
                    provenance_payload,
                    hard_capability_verified: true,
                    is_default: true,
                },
                11,
            )
            .await
            .expect("bind selected local route")
        {
            BindAgentOutcome::Bound(row) => row,
            outcome => panic!("expected durable binding, got {outcome:?}"),
        };
        let providers = providers();
        let profile = resolve_agent_profile(AgentProfileResolutionInput {
            installation_id,
            catalog: &catalog,
            bindings: vec![db_binding.clone()],
            offerings: vec![offering("model-a")],
            utility_fallbacks: BTreeMap::new(),
            providers: &providers,
            host_policy: VnextHostPolicy::default(),
            question_override: ProfileQuestionOverride::Inherit,
            verification_reductions: BTreeMap::new(),
        })
        .expect("resolve selected installation with DB binding");
        let canonical_before_prepare = profile
            .canonical_snapshot_payload()
            .expect("canonical resolved snapshot");
        let session_id = Uuid::now_v7();
        let persisted_at_prepare = match profile
            .prepare_session(
                &db,
                AgentProfilePrepareRequest {
                    session_id,
                    session_create: AgentSessionCreateInput {
                        project_id: "project".into(),
                        project_root: "/workspace".into(),
                        active_agent: "profile-test".into(),
                        started_at_unix_ms: 12_000,
                        last_active_at_unix_ms: 12_000,
                    },
                    existing_session_claim_token: None,
                    idempotency_key: "profile-resolution-prepare".into(),
                    request_fingerprint: "profile-resolution-prepare-fingerprint".into(),
                    snapshot_schema_version: 1,
                    now_unix_ms: 12,
                },
            )
            .await
            .expect("prepare immutable profile")
        {
            PrepareAgentSessionOutcome::Prepared(row) => row,
            outcome => panic!("expected prepared profile, got {outcome:?}"),
        };
        let persisted = db
            .agent_profile_snapshot(session_id)
            .await
            .expect("read persisted profile")
            .expect("prepared session has a profile snapshot");
        assert_eq!(persisted, persisted_at_prepare);
        assert_eq!(persisted.canonical_payload, canonical_before_prepare);
        assert_eq!(persisted.installation_id, installation_id);
        assert_eq!(persisted.definition_digest, definition_digest);
        assert_eq!(
            persisted
                .reconstruct_binding_revision_map()
                .expect("persisted binding revision map"),
            AgentBindingRevisionMap {
                bindings: vec![AgentBindingRevision {
                    slot_id: "primary".into(),
                    provider_profile_handle: db_binding.provider_profile_handle.clone(),
                    model_id: "test-model".into(),
                    binding_revision: db_binding.binding_revision,
                }],
            }
        );
        drop(profile);
        drop(catalog);

        // These are deliberately changed after preparation.  Reload below
        // receives neither a live AgentDef nor provider configuration and uses
        // only the DB row fetched above.
        let changed_definition = definition(
            "    suggestedModels:\n      - recommendationId: changed\n        upstreamIdentity: upstream/changed\n        providerAliases:\n          - providerId: provider\n            modelId: changed-model\n",
        );
        let changed_digest = hex_digest(
            &changed_definition
                .vnext_digest_bytes()
                .expect("changed definition digest"),
        );
        assert_ne!(changed_digest, definition_digest);
        assert!(matches!(
            db.observe_agent_definition(installation_id, changed_digest, 13)
                .await
                .expect("record changed disk observation"),
            ObserveAgentOutcome::RebindRequired(_)
        ));
        let mut changed_providers = providers;
        changed_providers
            .providers
            .get_mut("provider")
            .expect("provider fixture")
            .models
            .clear();
        assert!(
            changed_providers
                .providers
                .get("provider")
                .expect("changed provider fixture")
                .models
                .is_empty(),
            "the live provider no longer offers the prepared route"
        );

        let reloaded =
            ResolvedAgentProfile::reload(&db, session_id, installed.installation_revision, 1)
                .await
                .expect("reload needs no changed definition or provider data");
        assert_eq!(reloaded.definition_digest, definition_digest);
        assert_eq!(reloaded.bindings.len(), 1);
        assert_eq!(reloaded.bindings[0].model_id, "model-a");
        assert_eq!(
            reloaded.snapshot.bindings[0].binding_revision,
            db_binding.binding_revision
        );

        let mut fabricated = persisted;
        let forged_revision_map = AgentBindingRevisionMap {
            bindings: vec![AgentBindingRevision {
                slot_id: "primary".into(),
                provider_profile_handle: db_binding.provider_profile_handle.clone(),
                model_id: "test-model".into(),
                binding_revision: db_binding.binding_revision + 1,
            }],
        };
        fabricated.binding_revision_map_payload =
            serde_json::to_vec(&forged_revision_map).expect("forged revision map");
        fabricated.binding_revision_map_digest =
            hex_digest(&fabricated.binding_revision_map_payload);
        assert!(
            ResolvedAgentProfile::reload_persisted(&fabricated, installed.installation_revision, 1)
                .is_err(),
            "a tampered persisted revision map must not reload a profile"
        );
    }
}
