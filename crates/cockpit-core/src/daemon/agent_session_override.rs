//! Daemon-owned authority for per-agent-node session overrides (modes AC5/6/7).
//!
//! This module holds the pure, unit-tested policy: it projects a node's
//! effective sandbox/mode/verification/question settings into the wire DTO, and
//! it validates a requested override is **non-escalating** before any field is
//! persisted. A session override may only preserve or reduce the immutable
//! profile/host authority envelope; it never raises authority.
//!
//! Two authorities meet here:
//!   * Verification and question effective settings and their reductions come
//!     from the vNext profile/host machinery — the node's resolved profile
//!     snapshot (`RedactedAgentProfileSnapshot`) already carries the compiled,
//!     disjoint verification regions and the redacted question policy with its
//!     host ceiling.
//!   * Sandbox posture has **no profile envelope**; it is a session config
//!     value. Non-escalation for that axis is defined against the current
//!     effective value via an explicit restrictiveness ordering, so an override
//!     can only make a node stricter, never looser.
//!
//! The model axis is resolved against the session-setup snapshot for the
//! focused node's own installation. Dispatch loads that snapshot; the policy
//! below scopes the `(slot_id, choice_id)` to that node and maps the opaque
//! route key back to the credential-owning provider handle.

use cockpit_config::config::providers::ProvidersConfig;
use cockpit_config::config::sandbox_mode::SandboxMode;
use cockpit_proto::{
    AGENT_EFFECTIVE_SETTINGS_DTO_VERSION, AgentControlLockedReasonV1, AgentEffectiveSettingsV1,
    AgentQuestionControlV1, AgentQuestionEffectiveV1, AgentQuestionOverrideV1,
    AgentSandboxControlV1, AgentSessionOverrideFieldV1, AgentSessionOverrideStatusV1,
    AgentVerificationControlV1, AgentVerificationReductionV1, AgentVerificationRegionV1,
    SessionSetupSnapshotV1,
};
use uuid::Uuid;

use crate::db::agent_installations::{
    RedactedAgentProfileSnapshot, RedactedBindingEvidence, RedactedChildBindingEvidence,
    RedactedQuestionPolicy, RedactedVerificationRegion, VerificationEffectiveAction,
};
use crate::db::agent_tree_decisions::{
    AgentInstanceState, StoredModelBinding, StoredOverrideField, StoredQuestionOverride,
    StoredSessionOverride, StoredVerificationReduction,
};

/// All loaded facts needed to project effective settings and authorize a
/// non-model override for one node. The dispatch layer loads these; the policy
/// below is a pure function of them.
#[derive(Debug, Clone)]
pub struct NodeOverrideContext {
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    /// Installation this node is bound to, when a profile snapshot exists.
    /// Model-slot overrides are validated only against this installation's
    /// session-setup candidate — never against a sibling or the session's
    /// selected candidate.
    pub installation_id: Option<String>,
    pub state: AgentInstanceState,
    pub override_revision: i64,
    pub pending: Option<StoredSessionOverride>,
    pub effective: Option<StoredSessionOverride>,
    /// Session config sandbox default (the baseline when no consumed override).
    pub session_sandbox_default: SandboxMode,
    /// The node's resolved profile snapshot, when one is bound. Absent for a
    /// node with no persisted profile (e.g. a bare utility node).
    pub profile: Option<RedactedAgentProfileSnapshot>,
    /// Binding evidence for this exact installation. Delegated nodes select
    /// their entry from the enclosing profile's immutable child evidence.
    pub model_bindings: Vec<RedactedBindingEvidence>,
    /// Full prepared evidence for a focused delegated child, including the
    /// pinned hard slot requirements used for current-generation revalidation.
    pub child_model_bindings: Vec<RedactedChildBindingEvidence>,
}

// --- restrictiveness / permissiveness orderings ---------------------------

/// Sandbox restrictiveness rank: higher = stricter = *less* authority. A
/// non-escalating override may only keep or raise the rank.
fn sandbox_rank(mode: SandboxMode) -> u8 {
    match mode {
        SandboxMode::Off => 0,
        SandboxMode::Sandbox => 1,
        SandboxMode::Container => 2,
        SandboxMode::ContainerReadonly => 3,
    }
}

const SANDBOX_ORDER: [SandboxMode; 4] = [
    SandboxMode::Off,
    SandboxMode::Sandbox,
    SandboxMode::Container,
    SandboxMode::ContainerReadonly,
];

fn sandbox_label(mode: SandboxMode) -> &'static str {
    match mode {
        SandboxMode::Off => "off",
        SandboxMode::Sandbox => "sandbox",
        SandboxMode::Container => "container",
        SandboxMode::ContainerReadonly => "container_readonly",
    }
}

pub(crate) fn sandbox_from_label(label: &str) -> Option<SandboxMode> {
    match label {
        "off" => Some(SandboxMode::Off),
        "sandbox" => Some(SandboxMode::Sandbox),
        "container" => Some(SandboxMode::Container),
        "container_readonly" => Some(SandboxMode::ContainerReadonly),
        _ => None,
    }
}

impl NodeOverrideContext {
    fn effective_sandbox(&self) -> SandboxMode {
        self.effective
            .as_ref()
            .and_then(|o| o.sandbox.as_deref())
            .and_then(sandbox_from_label)
            .unwrap_or(self.session_sandbox_default)
    }

    fn pending_sandbox(&self) -> Option<SandboxMode> {
        self.pending
            .as_ref()
            .and_then(|o| o.sandbox.as_deref())
            .and_then(sandbox_from_label)
    }

    fn pending_region(&self, region_id: &str) -> bool {
        self.pending
            .as_ref()
            .map(|o| o.verification.iter().any(|r| r.region_id == region_id))
            .unwrap_or(false)
    }

    fn pending_question(&self) -> Option<AgentQuestionOverrideV1> {
        self.pending.as_ref().and_then(|o| {
            o.question.as_ref().map(|q| match q {
                StoredQuestionOverride::Disable => AgentQuestionOverrideV1::Disable,
                StoredQuestionOverride::Reduce {
                    required_decision_timeout_seconds,
                } => AgentQuestionOverrideV1::Reduce {
                    required_decision_timeout_seconds: *required_decision_timeout_seconds,
                },
            })
        })
    }
}

fn ms_to_secs(ms: u64) -> u32 {
    u32::try_from(ms / 1000).unwrap_or(u32::MAX)
}

/// Project the node's effective settings, allowed transitions, and locked
/// reasons into the wire DTO.
pub fn build_effective_settings(ctx: &NodeOverrideContext) -> AgentEffectiveSettingsV1 {
    let terminal = ctx.state.is_terminal();
    let terminal_lock = terminal.then_some(AgentControlLockedReasonV1::Terminal);

    // Sandbox: allowed = keep or raise restrictiveness (never loosen). `off`
    // appears only when the effective value is already `off`.
    let eff_sandbox = ctx.effective_sandbox();
    let sandbox_allowed: Vec<SandboxMode> = if terminal {
        Vec::new()
    } else {
        SANDBOX_ORDER
            .into_iter()
            .filter(|candidate| sandbox_rank(*candidate) >= sandbox_rank(eff_sandbox))
            .collect()
    };
    let sandbox = AgentSandboxControlV1 {
        effective: eff_sandbox,
        allowed: sandbox_allowed,
        locked_reason: terminal_lock,
        pending: ctx.pending_sandbox(),
    };

    // Verification: one control per daemon-resolved disjoint region.
    let regions = ctx
        .profile
        .as_ref()
        .map(|profile| {
            profile
                .verification_regions
                .iter()
                .map(|region| verification_region_dto(ctx, region, terminal))
                .collect()
        })
        .unwrap_or_default();
    let verification = AgentVerificationControlV1 { regions };

    // Question: from the redacted policy, if any.
    let question = build_question_control(ctx, terminal_lock);

    AgentEffectiveSettingsV1 {
        dto_version: AGENT_EFFECTIVE_SETTINGS_DTO_VERSION,
        session_id: ctx.session_id.to_string(),
        agent_instance_id: ctx.agent_instance_id.to_string(),
        installation_id: ctx.installation_id.clone(),
        override_revision: ctx.override_revision.max(0) as u64,
        terminal,
        sandbox,
        verification,
        question,
        model: {
            let allowed = ctx
                .model_bindings
                .iter()
                .filter(|binding| binding.slot_id == "primary")
                .map(|binding| cockpit_proto::AgentModelRefV1 {
                    choice_id: cockpit_proto::focused_model_binding_choice_id(
                        &binding.provider_profile_handle,
                        &binding.selected_provider_alias.provider_id,
                        &binding.model_id,
                    ),
                    provider_id: binding.selected_provider_alias.provider_id.clone(),
                    model_id: binding.model_id.clone(),
                    is_default: binding.is_default,
                })
                .collect::<Vec<_>>();
            let effective = ctx
                .effective
                .as_ref()
                .and_then(|o| o.model.as_ref())
                .map(|binding| {
                    ctx.model_bindings
                        .iter()
                        .find(|candidate| {
                            candidate.provider_profile_handle == binding.provider
                                && candidate.model_id == binding.model
                        })
                        .map(|candidate| cockpit_proto::AgentModelRefV1 {
                            choice_id: cockpit_proto::focused_model_binding_choice_id(
                                &candidate.provider_profile_handle,
                                &candidate.selected_provider_alias.provider_id,
                                &candidate.model_id,
                            ),
                            provider_id: candidate.selected_provider_alias.provider_id.clone(),
                            model_id: candidate.model_id.clone(),
                            is_default: candidate.is_default,
                        })
                        .unwrap_or(cockpit_proto::AgentModelRefV1 {
                            choice_id: cockpit_proto::focused_model_binding_choice_id(
                                &binding.provider,
                                &binding.provider,
                                &binding.model,
                            ),
                            provider_id: binding.provider.clone(),
                            model_id: binding.model.clone(),
                            is_default: false,
                        })
                })
                .or_else(|| {
                    allowed
                        .iter()
                        .find(|candidate| candidate.is_default)
                        .cloned()
                });
            cockpit_proto::AgentModelControlV1 {
                effective,
                allowed,
                pending: ctx
                    .pending
                    .as_ref()
                    .and_then(|o| o.model.as_ref())
                    .map(|binding| {
                        ctx.model_bindings
                            .iter()
                            .find(|candidate| {
                                candidate.slot_id == "primary"
                                    && candidate.provider_profile_handle == binding.provider
                                    && candidate.model_id == binding.model
                            })
                            .map(|candidate| cockpit_proto::AgentModelRefV1 {
                                choice_id: cockpit_proto::focused_model_binding_choice_id(
                                    &candidate.provider_profile_handle,
                                    &candidate.selected_provider_alias.provider_id,
                                    &candidate.model_id,
                                ),
                                provider_id: candidate.selected_provider_alias.provider_id.clone(),
                                model_id: candidate.model_id.clone(),
                                is_default: candidate.is_default,
                            })
                            .unwrap_or(cockpit_proto::AgentModelRefV1 {
                                choice_id: cockpit_proto::focused_model_binding_choice_id(
                                    &binding.provider,
                                    "unavailable",
                                    &binding.model,
                                ),
                                provider_id: "unavailable".to_string(),
                                model_id: binding.model.clone(),
                                is_default: false,
                            })
                    }),
                locked_reason: terminal_lock,
            }
        },
    }
}

/// Resolve a model-slot override against the focused node's own installation
/// candidate. The client names a `(slot_id, choice_id)`; this re-validates the
/// choice is present and hard-compatible on **that node** only, then stores the
/// credential-owning provider handle (never the wire display token).
///
/// A choice in `slot.choices` but not in the live binding set is the root-only
/// derived-definition path: persist the route's credential-owning handle so
/// consume pins it as `model_override`. Delegated / non-root nodes still
/// reject unbound picks.
pub fn resolve_node_model_override(
    snapshot: &SessionSetupSnapshotV1,
    installation_id: Option<&str>,
    model_bindings: &[RedactedBindingEvidence],
    child_model_bindings: &[RedactedChildBindingEvidence],
    slot_id: &str,
    choice_id: &str,
    providers: &ProvidersConfig,
) -> Result<StoredModelBinding, AgentSessionOverrideStatusV1> {
    if slot_id != "primary" {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    }
    let Some(installation_id) = installation_id.filter(|id| !id.is_empty()) else {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    };
    // Private package children never appear in the generic session-setup
    // candidate list. Their focused picker names immutable binding evidence
    // with a separate opaque choice namespace; re-resolve that evidence
    // against the current provider inventory before accepting it.
    if let Some(evidence) = child_model_bindings.iter().find(|evidence| {
        let binding = &evidence.binding;
        evidence.installation_id.to_string() == installation_id
            && binding.slot_id == slot_id
            && cockpit_proto::focused_model_binding_choice_id(
                &binding.provider_profile_handle,
                &binding.selected_provider_alias.provider_id,
                &binding.model_id,
            ) == choice_id
            && crate::daemon::agent_installation::wire_provider_id_for_profile_route(
                providers,
                &binding.provider_profile_handle,
                &binding.model_id,
            )
            .as_deref()
                == Some(binding.selected_provider_alias.provider_id.as_str())
            && crate::agents::redacted_child_route_is_compatible(evidence, providers)
    }) {
        let binding = &evidence.binding;
        return Ok(StoredModelBinding {
            slot_id: slot_id.to_string(),
            provider: binding.provider_profile_handle.clone(),
            model: binding.model_id.clone(),
        });
    }
    let Some(candidate) = snapshot
        .candidates
        .iter()
        .find(|candidate| candidate.installation.installation_id == installation_id)
    else {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    };
    let Some(slot) = candidate.slots.iter().find(|slot| slot.slot_id == slot_id) else {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    };
    if slot.unavailable_reason.is_some() {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    }
    let Some(choice) = slot
        .choices
        .iter()
        .find(|choice| choice.choice_id == choice_id)
    else {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    };
    if let Some(route) = slot
        .choice_routes
        .iter()
        .find(|route| route.choice_id == choice.choice_id)
    {
        if let Some(binding) = model_bindings.iter().find(|binding| {
            binding.slot_id == slot_id
                && binding.model_id == choice.model_id
                && binding.selected_provider_alias.provider_id == choice.provider_id
                && cockpit_proto::focused_model_binding_choice_id(
                    &binding.provider_profile_handle,
                    &binding.selected_provider_alias.provider_id,
                    &binding.model_id,
                ) == route.route_choice_id
                && crate::daemon::agent_installation::wire_provider_id_for_profile_route(
                    providers,
                    &binding.provider_profile_handle,
                    &binding.model_id,
                )
                .as_deref()
                    == Some(choice.provider_id.as_str())
        }) {
            return Ok(StoredModelBinding {
                slot_id: slot_id.to_string(),
                provider: binding.provider_profile_handle.clone(),
                model: binding.model_id.clone(),
            });
        }
        // Slot-compatible but not a live binding: root-only derived-def.
        // Delegated nodes stay bound-only.
        return derived_def_binding_from_route(
            snapshot,
            installation_id,
            slot_id,
            choice,
            route,
            providers,
        );
    }
    // Compatibility for setup snapshots produced before opaque choice-route
    // mappings were added. Current snapshots always take the exact branch
    // above; display-only ambiguity fails closed here.
    let Some(provider) =
        crate::daemon::agent_installation::resolvable_provider_handle_for_choice(providers, choice)
    else {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    };
    if model_bindings.iter().any(|binding| {
        binding.slot_id == slot_id
            && binding.model_id == choice.model_id
            && binding.provider_profile_handle == provider
    }) {
        return Ok(StoredModelBinding {
            slot_id: slot_id.to_string(),
            provider,
            model: choice.model_id.clone(),
        });
    }
    if is_root_setup_installation(snapshot, installation_id) {
        return Ok(StoredModelBinding {
            slot_id: slot_id.to_string(),
            provider,
            model: choice.model_id.clone(),
        });
    }
    Err(AgentSessionOverrideStatusV1::RejectedIncompatible)
}

fn is_root_setup_installation(snapshot: &SessionSetupSnapshotV1, installation_id: &str) -> bool {
    snapshot.selected_installation_id.as_deref() == Some(installation_id)
        || snapshot.candidates.iter().any(|candidate| {
            candidate.selected && candidate.installation.installation_id == installation_id
        })
}

/// Persist a credential-owning handle for a root out-of-set pick so consume
/// pins it as `model_override` and `resolve_vnext_slot_model` takes the
/// derived-definition path. The opaque route's config index is the handle;
/// a stale index or display-token mismatch fails closed.
fn derived_def_binding_from_route(
    snapshot: &SessionSetupSnapshotV1,
    installation_id: &str,
    slot_id: &str,
    choice: &cockpit_proto::AgentInstallationChoiceV1,
    route: &cockpit_proto::SessionSetupModelChoiceRouteV1,
    providers: &ProvidersConfig,
) -> Result<StoredModelBinding, AgentSessionOverrideStatusV1> {
    if !is_root_setup_installation(snapshot, installation_id) {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    }
    let Ok(index) = usize::try_from(route.config_provider_index) else {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    };
    let Some((provider, entry)) = providers.providers.iter().nth(index) else {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    };
    if !entry.models.iter().any(|model| model.id == choice.model_id) {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    }
    let expected = cockpit_proto::focused_model_binding_choice_id(
        provider,
        &choice.provider_id,
        &choice.model_id,
    );
    if expected != route.route_choice_id {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    }
    Ok(StoredModelBinding {
        slot_id: slot_id.to_string(),
        provider: provider.clone(),
        model: choice.model_id.clone(),
    })
}

fn verification_region_dto(
    ctx: &NodeOverrideContext,
    region: &RedactedVerificationRegion,
    terminal: bool,
) -> AgentVerificationRegionV1 {
    let verifying = matches!(region.effective_action, VerificationEffectiveAction::Verify);
    let enabled = verifying && !region.whole_region_off;
    // A reduction is offerable only for a still-verifying, not-yet-off region,
    // and never on a terminal node.
    let reducible = enabled && !terminal;
    AgentVerificationRegionV1 {
        region_id: region.source_rule_id.clone(),
        label: region.source_rule_id.clone(),
        enabled,
        can_disable: reducible,
        can_restrict: reducible,
        pending: ctx.pending_region(&region.source_rule_id),
    }
}

fn build_question_control(
    ctx: &NodeOverrideContext,
    terminal_lock: Option<AgentControlLockedReasonV1>,
) -> AgentQuestionControlV1 {
    let policy = ctx.profile.as_ref().map(|p| &p.question_policy);
    match policy {
        Some(RedactedQuestionPolicy::Active {
            auto_answer_disabled,
            required_decision_timeout_ms,
            host_resource_ceiling_ms,
            ..
        }) => {
            let ceiling = ms_to_secs(*host_resource_ceiling_ms);
            let auto_answer_enabled = !auto_answer_disabled;
            let effective = AgentQuestionEffectiveV1 {
                auto_answer_enabled,
                required_decision_timeout_seconds: ms_to_secs(*required_decision_timeout_ms),
                host_ceiling_seconds: ceiling,
                // Disabling auto-answer is offerable only while it is enabled
                // and the node is live.
                can_disable_auto_answer: auto_answer_enabled && terminal_lock.is_none(),
                max_required_decision_timeout_seconds: ceiling,
            };
            AgentQuestionControlV1 {
                effective: Some(effective),
                locked_reason: terminal_lock,
                pending: ctx.pending_question(),
            }
        }
        // Off or absent policy can never be enabled by a session override.
        Some(RedactedQuestionPolicy::Off) => AgentQuestionControlV1 {
            effective: None,
            locked_reason: Some(
                terminal_lock.unwrap_or(AgentControlLockedReasonV1::InheritedFromProfile),
            ),
            pending: None,
        },
        None => AgentQuestionControlV1 {
            effective: None,
            locked_reason: terminal_lock,
            pending: None,
        },
    }
}

/// Validate that a non-model override field is non-escalating for this node and
/// convert it into the storable, authorized form. Returns the rejecting status
/// otherwise. The model axis is handled by the dispatch layer.
pub fn authorize_non_model_field(
    field: &AgentSessionOverrideFieldV1,
    ctx: &NodeOverrideContext,
) -> Result<StoredOverrideField, AgentSessionOverrideStatusV1> {
    match field {
        AgentSessionOverrideFieldV1::Model { .. } => {
            // Handled by the dispatch layer against the setup snapshot.
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible)
        }
        AgentSessionOverrideFieldV1::Sandbox { mode } => {
            if sandbox_rank(*mode) >= sandbox_rank(ctx.effective_sandbox()) {
                Ok(StoredOverrideField::Sandbox(
                    sandbox_label(*mode).to_string(),
                ))
            } else {
                Err(AgentSessionOverrideStatusV1::RejectedEscalation)
            }
        }
        AgentSessionOverrideFieldV1::Verification { reduction } => {
            authorize_verification(reduction, ctx)
        }
        AgentSessionOverrideFieldV1::Question { policy } => authorize_question(policy, ctx),
    }
}

fn find_region<'a>(
    ctx: &'a NodeOverrideContext,
    region_id: &str,
) -> Option<&'a RedactedVerificationRegion> {
    ctx.profile
        .as_ref()?
        .verification_regions
        .iter()
        .find(|region| region.source_rule_id == region_id)
}

fn authorize_verification(
    reduction: &AgentVerificationReductionV1,
    ctx: &NodeOverrideContext,
) -> Result<StoredOverrideField, AgentSessionOverrideStatusV1> {
    let region_id = match reduction {
        AgentVerificationReductionV1::Off { region_id } => region_id,
        AgentVerificationReductionV1::Restrict { region_id, .. } => region_id,
    };
    let region =
        find_region(ctx, region_id).ok_or(AgentSessionOverrideStatusV1::RejectedIncompatible)?;
    // Only a still-verifying, not-yet-off region can be reduced.
    let verifying = matches!(region.effective_action, VerificationEffectiveAction::Verify);
    if !verifying || region.whole_region_off {
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    }
    match reduction {
        AgentVerificationReductionV1::Off { region_id } => Ok(StoredOverrideField::Verification(
            StoredVerificationReduction {
                region_id: region_id.clone(),
                off: true,
                selector_intersection: Vec::new(),
                max_candidates: None,
                max_total_tokens: None,
                max_estimated_cost_microusd: None,
                max_collection_millis: None,
            },
        )),
        AgentVerificationReductionV1::Restrict {
            region_id,
            selector_intersection,
            max_candidates,
            max_total_tokens,
            max_estimated_cost_microusd,
            max_collection_millis,
        } => {
            // A restriction must narrow: at least one selector token or one
            // lowered budget, and no budget may exceed the region ceiling.
            let has_narrowing = !selector_intersection.is_empty()
                || max_candidates.is_some()
                || max_total_tokens.is_some()
                || max_estimated_cost_microusd.is_some()
                || max_collection_millis.is_some();
            if !has_narrowing {
                return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
            }
            if exceeds_ceiling(max_candidates.map(u64::from), region.count_ceiling)
                || exceeds_ceiling(*max_total_tokens, region.token_ceiling)
                || exceeds_ceiling(*max_estimated_cost_microusd, region.cost_ceiling_micros)
                || exceeds_ceiling(*max_collection_millis, region.max_collection_duration_ms)
            {
                return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
            }
            Ok(StoredOverrideField::Verification(
                StoredVerificationReduction {
                    region_id: region_id.clone(),
                    off: false,
                    selector_intersection: selector_intersection.clone(),
                    max_candidates: *max_candidates,
                    max_total_tokens: *max_total_tokens,
                    max_estimated_cost_microusd: *max_estimated_cost_microusd,
                    max_collection_millis: *max_collection_millis,
                },
            ))
        }
    }
}

/// A requested budget exceeds the region ceiling when the ceiling is present and
/// the request is above it. A missing ceiling means unbounded (never exceeded).
fn exceeds_ceiling(requested: Option<u64>, ceiling: Option<u64>) -> bool {
    match (requested, ceiling) {
        (Some(value), Some(limit)) => value > limit,
        _ => false,
    }
}

fn authorize_question(
    policy: &AgentQuestionOverrideV1,
    ctx: &NodeOverrideContext,
) -> Result<StoredOverrideField, AgentSessionOverrideStatusV1> {
    let question = ctx
        .profile
        .as_ref()
        .map(|p| &p.question_policy)
        .ok_or(AgentSessionOverrideStatusV1::RejectedIncompatible)?;
    let RedactedQuestionPolicy::Active {
        required_decision_timeout_ms,
        host_resource_ceiling_ms,
        ..
    } = question
    else {
        // An off/absent policy cannot be enabled or modified.
        return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
    };
    match policy {
        AgentQuestionOverrideV1::Disable => Ok(StoredOverrideField::Question(
            StoredQuestionOverride::Disable,
        )),
        AgentQuestionOverrideV1::Reduce {
            required_decision_timeout_seconds,
        } => {
            let requested_ms = u64::from(*required_decision_timeout_seconds) * 1000;
            // Lengthening the wait up to the host ceiling is the reduction;
            // shortening is forbidden and over-ceiling is rejected, not clamped.
            if requested_ms < *required_decision_timeout_ms
                || requested_ms > *host_resource_ceiling_ms
            {
                return Err(AgentSessionOverrideStatusV1::RejectedIncompatible);
            }
            Ok(StoredOverrideField::Question(
                StoredQuestionOverride::Reduce {
                    required_decision_timeout_seconds: *required_decision_timeout_seconds,
                },
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::agent_installations::{AgentExecutionKind, QuestionResolverOrder};

    fn base_ctx() -> NodeOverrideContext {
        NodeOverrideContext {
            session_id: Uuid::from_u128(1),
            agent_instance_id: Uuid::from_u128(2),
            installation_id: None,
            state: AgentInstanceState::Running,
            override_revision: 0,
            pending: None,
            effective: None,
            session_sandbox_default: SandboxMode::Sandbox,
            profile: None,
            model_bindings: Vec::new(),
            child_model_bindings: Vec::new(),
        }
    }

    fn active_question(
        timeout_ms: u64,
        ceiling_ms: u64,
        auto_disabled: bool,
    ) -> RedactedQuestionPolicy {
        RedactedQuestionPolicy::Active {
            auto_answer_disabled: auto_disabled,
            prohibited_classes: Vec::new(),
            required_decision_timeout_ms: timeout_ms,
            host_resource_ceiling_ms: ceiling_ms,
            resolver_order: QuestionResolverOrder::WarmParentThenUtility,
            resolver_slot: String::new(),
        }
    }

    fn verifying_region(id: &str, token_ceiling: Option<u64>) -> RedactedVerificationRegion {
        RedactedVerificationRegion {
            source_rule_id: id.to_string(),
            source_selector: Default::default(),
            excluded_prior_selectors: Vec::new(),
            session_selector: None,
            enabled_intersection_mask: Vec::new(),
            enabled: true,
            explicit_off_remainder_mask: Vec::new(),
            whole_region_off: false,
            whole_region_off_mask: Vec::new(),
            effective_action: VerificationEffectiveAction::Verify,
            adjudicator_slot: None,
            count_ceiling: None,
            token_ceiling,
            cost_ceiling_micros: None,
            max_collection_duration_ms: None,
            execution_plan: None,
        }
    }

    #[test]
    fn modes_session_setup_sandbox_allowed_never_loosens_and_off_gated() {
        let mut ctx = base_ctx();
        // Effective sandbox = Sandbox: allowed is Sandbox and stricter; never Off.
        ctx.session_sandbox_default = SandboxMode::Sandbox;
        let dto = build_effective_settings(&ctx);
        assert_eq!(
            dto.sandbox.allowed,
            vec![
                SandboxMode::Sandbox,
                SandboxMode::Container,
                SandboxMode::ContainerReadonly
            ]
        );
        assert!(!dto.sandbox.allowed.contains(&SandboxMode::Off));

        // Loosening (Sandbox -> Off) is an escalation.
        assert_eq!(
            authorize_non_model_field(
                &AgentSessionOverrideFieldV1::Sandbox {
                    mode: SandboxMode::Off
                },
                &ctx
            ),
            Err(AgentSessionOverrideStatusV1::RejectedEscalation)
        );
        // Tightening (Sandbox -> Container) is allowed.
        assert!(
            authorize_non_model_field(
                &AgentSessionOverrideFieldV1::Sandbox {
                    mode: SandboxMode::Container
                },
                &ctx
            )
            .is_ok()
        );
    }

    #[test]
    fn modes_session_setup_question_override_monotonic_timeout_rules() {
        let mut ctx = base_ctx();
        ctx.profile = Some(RedactedAgentProfileSnapshot {
            agent_id: "a".to_string(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: Vec::new(),
            question_policy: active_question(30_000, 60_000, false),
            verification_regions: Vec::new(),
            bindings: Vec::new(),
            child_bindings: Vec::new(),
        });

        // Shorter than the required timeout is widening -> rejected.
        assert_eq!(
            authorize_question(
                &AgentQuestionOverrideV1::Reduce {
                    required_decision_timeout_seconds: 20
                },
                &ctx
            ),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible)
        );
        // Over the host ceiling is rejected, not clamped.
        assert_eq!(
            authorize_question(
                &AgentQuestionOverrideV1::Reduce {
                    required_decision_timeout_seconds: 120
                },
                &ctx
            ),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible)
        );
        // Lengthening within the ceiling is a valid reduction.
        assert!(
            authorize_question(
                &AgentQuestionOverrideV1::Reduce {
                    required_decision_timeout_seconds: 45
                },
                &ctx
            )
            .is_ok()
        );
        // Disable is always the strictest valid state.
        assert!(authorize_question(&AgentQuestionOverrideV1::Disable, &ctx).is_ok());
    }

    #[test]
    fn modes_session_setup_question_off_policy_cannot_be_enabled() {
        let mut ctx = base_ctx();
        ctx.profile = Some(RedactedAgentProfileSnapshot {
            agent_id: "a".to_string(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: Vec::new(),
            question_policy: RedactedQuestionPolicy::Off,
            verification_regions: Vec::new(),
            bindings: Vec::new(),
            child_bindings: Vec::new(),
        });
        assert_eq!(
            authorize_question(&AgentQuestionOverrideV1::Disable, &ctx),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible)
        );
        let dto = build_effective_settings(&ctx);
        assert!(dto.question.effective.is_none());
        assert_eq!(
            dto.question.locked_reason,
            Some(AgentControlLockedReasonV1::InheritedFromProfile)
        );
    }

    #[test]
    fn modes_session_setup_verification_off_and_ceiling_enforced() {
        let mut ctx = base_ctx();
        ctx.profile = Some(RedactedAgentProfileSnapshot {
            agent_id: "a".to_string(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: Vec::new(),
            question_policy: RedactedQuestionPolicy::Off,
            verification_regions: vec![verifying_region("rule-1", Some(1000))],
            bindings: Vec::new(),
            child_bindings: Vec::new(),
        });
        // Off is a valid reduction for a verifying region.
        assert!(
            authorize_verification(
                &AgentVerificationReductionV1::Off {
                    region_id: "rule-1".to_string()
                },
                &ctx
            )
            .is_ok()
        );
        // A restrict above the token ceiling is rejected (cannot raise budget).
        assert_eq!(
            authorize_verification(
                &AgentVerificationReductionV1::Restrict {
                    region_id: "rule-1".to_string(),
                    selector_intersection: Vec::new(),
                    max_candidates: None,
                    max_total_tokens: Some(5000),
                    max_estimated_cost_microusd: None,
                    max_collection_millis: None,
                },
                &ctx
            ),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible)
        );
        // An unknown region is rejected.
        assert_eq!(
            authorize_verification(
                &AgentVerificationReductionV1::Off {
                    region_id: "nope".to_string()
                },
                &ctx
            ),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible)
        );
    }

    #[test]
    fn modes_session_setup_terminal_node_has_no_allowed_transitions() {
        let mut ctx = base_ctx();
        ctx.state = AgentInstanceState::Cancelled;
        let dto = build_effective_settings(&ctx);
        assert!(dto.terminal);
        assert!(dto.sandbox.allowed.is_empty());
        assert_eq!(
            dto.sandbox.locked_reason,
            Some(AgentControlLockedReasonV1::Terminal)
        );
    }

    #[test]
    fn modes_session_setup_sandbox_ordering_endpoints() {
        // From the strictest posture nothing is loosenable: allowed is a
        // singleton; from `off` every posture is allowed (off included).
        let mut ctx = base_ctx();
        ctx.session_sandbox_default = SandboxMode::ContainerReadonly;
        assert_eq!(
            build_effective_settings(&ctx).sandbox.allowed,
            vec![SandboxMode::ContainerReadonly]
        );
        ctx.session_sandbox_default = SandboxMode::Off;
        assert_eq!(
            build_effective_settings(&ctx).sandbox.allowed,
            vec![
                SandboxMode::Off,
                SandboxMode::Sandbox,
                SandboxMode::Container,
                SandboxMode::ContainerReadonly
            ]
        );
    }

    #[test]
    fn modes_session_setup_question_override_monotonic_every_transition() {
        let mut ctx = base_ctx();
        ctx.profile = Some(RedactedAgentProfileSnapshot {
            agent_id: "a".to_string(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: Vec::new(),
            question_policy: active_question(30_000, 60_000, false),
            verification_regions: Vec::new(),
            bindings: Vec::new(),
            child_bindings: Vec::new(),
        });
        // Equal to the current required timeout is a no-op reduction (allowed).
        assert!(
            authorize_question(
                &AgentQuestionOverrideV1::Reduce {
                    required_decision_timeout_seconds: 30
                },
                &ctx
            )
            .is_ok()
        );
        // Effective rendering: auto-answer enabled, ceiling reflected, disable
        // offerable while live.
        let effective = build_effective_settings(&ctx).question.effective.unwrap();
        assert!(effective.auto_answer_enabled);
        assert_eq!(effective.required_decision_timeout_seconds, 30);
        assert_eq!(effective.host_ceiling_seconds, 60);
        assert_eq!(effective.max_required_decision_timeout_seconds, 60);
        assert!(effective.can_disable_auto_answer);
    }

    #[test]
    fn modes_session_setup_question_auto_answer_already_disabled_cannot_redisable() {
        let mut ctx = base_ctx();
        ctx.profile = Some(RedactedAgentProfileSnapshot {
            agent_id: "a".to_string(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: Vec::new(),
            // auto-answer already disabled.
            question_policy: active_question(30_000, 60_000, true),
            verification_regions: Vec::new(),
            bindings: Vec::new(),
            child_bindings: Vec::new(),
        });
        let effective = build_effective_settings(&ctx).question.effective.unwrap();
        assert!(!effective.auto_answer_enabled);
        // Disabling is not offered again once auto-answer is already off.
        assert!(!effective.can_disable_auto_answer);
    }

    #[test]
    fn modes_session_setup_question_terminal_node_is_read_only() {
        let mut ctx = base_ctx();
        ctx.state = AgentInstanceState::Completed;
        ctx.profile = Some(RedactedAgentProfileSnapshot {
            agent_id: "a".to_string(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: Vec::new(),
            question_policy: active_question(30_000, 60_000, false),
            verification_regions: Vec::new(),
            bindings: Vec::new(),
            child_bindings: Vec::new(),
        });
        let question = build_effective_settings(&ctx).question;
        assert_eq!(
            question.locked_reason,
            Some(AgentControlLockedReasonV1::Terminal)
        );
        assert!(!question.effective.unwrap().can_disable_auto_answer);
    }

    #[test]
    fn modes_session_setup_verification_restrict_requires_real_narrowing() {
        let mut ctx = base_ctx();
        ctx.profile = Some(RedactedAgentProfileSnapshot {
            agent_id: "a".to_string(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: Vec::new(),
            question_policy: RedactedQuestionPolicy::Off,
            verification_regions: vec![verifying_region("rule-1", Some(1000))],
            bindings: Vec::new(),
            child_bindings: Vec::new(),
        });
        // A Restrict with neither a selector nor a lowered budget narrows
        // nothing and is refused.
        assert_eq!(
            authorize_verification(
                &AgentVerificationReductionV1::Restrict {
                    region_id: "rule-1".to_string(),
                    selector_intersection: Vec::new(),
                    max_candidates: None,
                    max_total_tokens: None,
                    max_estimated_cost_microusd: None,
                    max_collection_millis: None,
                },
                &ctx
            ),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible)
        );
        // A selector intersection within the ceiling is a valid narrowing.
        assert!(
            authorize_verification(
                &AgentVerificationReductionV1::Restrict {
                    region_id: "rule-1".to_string(),
                    selector_intersection: vec!["tool_class:write".to_string()],
                    max_candidates: None,
                    max_total_tokens: Some(500),
                    max_estimated_cost_microusd: None,
                    max_collection_millis: None,
                },
                &ctx
            )
            .is_ok()
        );
    }

    #[test]
    fn modes_session_setup_verification_region_projected_with_flags() {
        let mut ctx = base_ctx();
        let mut off_region = verifying_region("rule-off", None);
        off_region.whole_region_off = true;
        ctx.profile = Some(RedactedAgentProfileSnapshot {
            agent_id: "a".to_string(),
            execution_kind: AgentExecutionKind::Coding,
            effective_delegation: None,
            recommendations: Vec::new(),
            question_policy: RedactedQuestionPolicy::Off,
            verification_regions: vec![verifying_region("rule-on", None), off_region],
            bindings: Vec::new(),
            child_bindings: Vec::new(),
        });
        let regions = build_effective_settings(&ctx).verification.regions;
        assert_eq!(regions.len(), 2);
        let on = regions.iter().find(|r| r.region_id == "rule-on").unwrap();
        assert!(on.enabled && on.can_disable && on.can_restrict);
        // A region already turned off is not enabled and offers no reduction.
        let off = regions.iter().find(|r| r.region_id == "rule-off").unwrap();
        assert!(!off.enabled && !off.can_disable && !off.can_restrict);
    }

    fn custom_providers(handle: &str, model: &str) -> ProvidersConfig {
        use cockpit_config::config::providers::{ModelEntry, ProviderEntry};
        let mut providers = ProvidersConfig::default();
        providers.providers.insert(
            handle.to_string(),
            ProviderEntry {
                template: None,
                models: vec![ModelEntry {
                    id: model.to_string(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        providers
    }

    fn named_providers(entries: &[(&str, Option<&str>, &str)]) -> ProvidersConfig {
        use cockpit_config::config::providers::{ModelEntry, ProviderEntry};
        let mut providers = ProvidersConfig::default();
        for (handle, template, model) in entries {
            providers.providers.insert(
                (*handle).to_string(),
                ProviderEntry {
                    template: template.map(str::to_string),
                    models: vec![ModelEntry {
                        id: (*model).to_string(),
                        ..ModelEntry::default()
                    }],
                    ..ProviderEntry::default()
                },
            );
        }
        providers
    }

    fn model_choice(
        choice_id: &str,
        slot_id: &str,
        provider_id: &str,
        model_id: &str,
    ) -> cockpit_proto::AgentInstallationChoiceV1 {
        cockpit_proto::AgentInstallationChoiceV1 {
            choice_id: choice_id.to_string(),
            slot_id: slot_id.to_string(),
            offering_id: format!("offering-{choice_id}"),
            provider_id: provider_id.to_string(),
            model_id: model_id.to_string(),
            recommendation_id: None,
            canonical_upstream_identity: None,
            author_label: None,
            rationale: None,
            author_suggested: false,
            exact_alias_match: false,
        }
    }

    fn candidate(
        installation_id: &str,
        selected: bool,
        slots: Vec<cockpit_proto::SessionSetupModelSlotV1>,
    ) -> cockpit_proto::SessionSetupAgentCandidateV1 {
        cockpit_proto::SessionSetupAgentCandidateV1 {
            installation: cockpit_proto::AgentInstallationRecordV1 {
                installation_id: installation_id.to_string(),
                scope: cockpit_proto::AgentInstallationScopeWire::Global,
                source_agent_id: installation_id.to_string(),
                source_identity: "identity".to_string(),
                source_revision: None,
                source_digest: "digest".to_string(),
                installation_revision: 1,
                bindings: Vec::new(),
            },
            selected,
            slots,
            locked_reason: None,
        }
    }

    fn slot(
        slot_id: &str,
        choices: Vec<cockpit_proto::AgentInstallationChoiceV1>,
        unavailable: Option<cockpit_proto::SessionSetupUnavailableReasonV1>,
    ) -> cockpit_proto::SessionSetupModelSlotV1 {
        cockpit_proto::SessionSetupModelSlotV1 {
            slot_id: slot_id.to_string(),
            choices,
            choice_routes: Vec::new(),
            allowed_choice_ids: Vec::new(),
            unmatched_recommendations: Vec::new(),
            default_choice_id: None,
            unavailable_reason: unavailable,
        }
    }

    fn setup_snapshot(
        selected: &str,
        candidates: Vec<cockpit_proto::SessionSetupAgentCandidateV1>,
    ) -> SessionSetupSnapshotV1 {
        SessionSetupSnapshotV1 {
            dto_version: 1,
            session_id: Uuid::from_u128(1).to_string(),
            config_generation: 1,
            revision: 0,
            selected_installation_id: Some(selected.to_string()),
            resolved_agent: None,
            last_used_agent: None,
            available_agents: Vec::new(),
            root_agent_instance_id: None,
            override_revision: 0,
            root_foreground: true,
            model: Default::default(),
            tools: Vec::new(),
            mcps: Vec::new(),
            candidates,
        }
    }

    fn binding_evidence(
        provider_handle: &str,
        provider_id: &str,
        model_id: &str,
    ) -> RedactedBindingEvidence {
        RedactedBindingEvidence {
            slot_id: "primary".to_string(),
            binding_revision: 1,
            provider_profile_handle: provider_handle.to_string(),
            model_id: model_id.to_string(),
            selected_provider_alias: crate::db::agent_installations::ProviderAlias {
                provider_id: provider_id.to_string(),
                model_id: model_id.to_string(),
            },
            provenance_digest: "digest".to_string(),
            hard_capability_verified: true,
            is_default: true,
        }
    }

    fn child_binding_evidence(
        installation_id: Uuid,
        provider_handle: &str,
        provider_id: &str,
        model_id: &str,
    ) -> RedactedChildBindingEvidence {
        RedactedChildBindingEvidence {
            installation_id,
            installation_revision: 1,
            observation_revision: 1,
            definition_digest: "d".repeat(64),
            binding: binding_evidence(provider_handle, provider_id, model_id),
            slot_requirements: crate::db::agent_installations::RedactedModelSlotRequirements {
                min_context_tokens: 1,
                required_capabilities: vec!["text_generation".to_string()],
                locality: "any".to_string(),
                allowed_models: vec![crate::db::agent_installations::ProviderAlias {
                    provider_id: provider_id.to_string(),
                    model_id: model_id.to_string(),
                }],
            },
        }
    }

    #[test]
    fn model_override_stores_custom_provider_handle_not_display_token() {
        let providers = custom_providers("profile-secret", "glm");
        let snapshot = setup_snapshot(
            "inst-a",
            vec![candidate(
                "inst-a",
                true,
                vec![slot(
                    "primary",
                    vec![model_choice(
                        "choice-local-offering-0",
                        "primary",
                        "configured-provider-0",
                        "glm",
                    )],
                    None,
                )],
            )],
        );
        let binding = resolve_node_model_override(
            &snapshot,
            Some("inst-a"),
            &[binding_evidence(
                "profile-secret",
                "configured-provider-0",
                "glm",
            )],
            &[],
            "primary",
            "choice-local-offering-0",
            &providers,
        )
        .expect("custom-provider choice must resolve");
        assert_eq!(binding.provider, "profile-secret");
        assert_eq!(binding.model, "glm");
        assert_ne!(
            binding.provider, "configured-provider-0",
            "display token must never be persisted as the live provider route"
        );
    }

    #[test]
    fn setup_choice_route_selects_exact_same_display_profile() {
        let providers = named_providers(&[
            ("profile-a", Some("openai"), "gpt"),
            ("profile-b", Some("openai"), "gpt"),
        ]);
        let mut primary = slot(
            "primary",
            vec![
                model_choice("choice-a", "primary", "openai", "gpt"),
                model_choice("choice-b", "primary", "openai", "gpt"),
            ],
            None,
        );
        primary.choice_routes = vec![
            cockpit_proto::SessionSetupModelChoiceRouteV1 {
                choice_id: "choice-a".to_string(),
                route_choice_id: cockpit_proto::focused_model_binding_choice_id(
                    "profile-a",
                    "openai",
                    "gpt",
                ),
                config_provider_index: 0,
            },
            cockpit_proto::SessionSetupModelChoiceRouteV1 {
                choice_id: "choice-b".to_string(),
                route_choice_id: cockpit_proto::focused_model_binding_choice_id(
                    "profile-b",
                    "openai",
                    "gpt",
                ),
                config_provider_index: 1,
            },
        ];
        let snapshot = setup_snapshot("inst-a", vec![candidate("inst-a", true, vec![primary])]);

        let selected = resolve_node_model_override(
            &snapshot,
            Some("inst-a"),
            &[
                binding_evidence("profile-a", "openai", "gpt"),
                binding_evidence("profile-b", "openai", "gpt"),
            ],
            &[],
            "primary",
            "choice-b",
            &providers,
        )
        .expect("opaque setup route must distinguish same-display profiles");
        assert_eq!(selected.provider, "profile-b");
    }

    #[test]
    fn root_out_of_set_choice_stores_derived_def_handle() {
        let providers = named_providers(&[
            ("profile-a", Some("openai"), "gpt"),
            ("profile-b", Some("openai"), "other"),
        ]);
        let mut primary = slot(
            "primary",
            vec![
                model_choice("choice-a", "primary", "openai", "gpt"),
                model_choice("choice-b", "primary", "openai", "other"),
            ],
            None,
        );
        primary.choice_routes = vec![
            cockpit_proto::SessionSetupModelChoiceRouteV1 {
                choice_id: "choice-a".to_string(),
                route_choice_id: cockpit_proto::focused_model_binding_choice_id(
                    "profile-a",
                    "openai",
                    "gpt",
                ),
                config_provider_index: 0,
            },
            cockpit_proto::SessionSetupModelChoiceRouteV1 {
                choice_id: "choice-b".to_string(),
                route_choice_id: cockpit_proto::focused_model_binding_choice_id(
                    "profile-b",
                    "openai",
                    "other",
                ),
                config_provider_index: 1,
            },
        ];
        let snapshot = setup_snapshot("inst-a", vec![candidate("inst-a", true, vec![primary])]);

        let selected = resolve_node_model_override(
            &snapshot,
            Some("inst-a"),
            &[binding_evidence("profile-a", "openai", "gpt")],
            &[],
            "primary",
            "choice-b",
            &providers,
        )
        .expect("root out-of-set compatible choice is the derived-def path");
        assert_eq!(selected.provider, "profile-b");
        assert_eq!(selected.model, "other");
    }

    #[test]
    fn child_out_of_set_choice_is_rejected() {
        let providers = named_providers(&[
            ("profile-a", Some("openai"), "gpt"),
            ("profile-b", Some("openai"), "other"),
        ]);
        let mut primary = slot(
            "primary",
            vec![
                model_choice("choice-a", "primary", "openai", "gpt"),
                model_choice("choice-b", "primary", "openai", "other"),
            ],
            None,
        );
        primary.choice_routes = vec![
            cockpit_proto::SessionSetupModelChoiceRouteV1 {
                choice_id: "choice-a".to_string(),
                route_choice_id: cockpit_proto::focused_model_binding_choice_id(
                    "profile-a",
                    "openai",
                    "gpt",
                ),
                config_provider_index: 0,
            },
            cockpit_proto::SessionSetupModelChoiceRouteV1 {
                choice_id: "choice-b".to_string(),
                route_choice_id: cockpit_proto::focused_model_binding_choice_id(
                    "profile-b",
                    "openai",
                    "other",
                ),
                config_provider_index: 1,
            },
        ];
        let snapshot = setup_snapshot(
            "inst-root",
            vec![
                candidate("inst-root", true, vec![]),
                candidate("inst-child", false, vec![primary]),
            ],
        );

        assert_eq!(
            resolve_node_model_override(
                &snapshot,
                Some("inst-child"),
                &[binding_evidence("profile-a", "openai", "gpt")],
                &[],
                "primary",
                "choice-b",
                &providers,
            ),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible),
            "derived-def is root-only; a delegated node cannot pick an unbound compatible model"
        );
    }

    #[test]
    fn model_override_is_scoped_to_focused_node_installation() {
        let providers = named_providers(&[
            ("anthropic", Some("anthropic"), "opus"),
            ("openai", Some("openai"), "gpt"),
        ]);
        let snapshot = setup_snapshot(
            "inst-root",
            vec![
                candidate(
                    "inst-root",
                    true,
                    vec![slot(
                        "primary",
                        vec![model_choice("root-choice", "primary", "anthropic", "opus")],
                        None,
                    )],
                ),
                candidate(
                    "inst-child",
                    false,
                    vec![slot(
                        "primary",
                        vec![model_choice("child-choice", "primary", "openai", "gpt")],
                        None,
                    )],
                ),
            ],
        );

        let child = resolve_node_model_override(
            &snapshot,
            Some("inst-child"),
            &[binding_evidence("openai", "openai", "gpt")],
            &[],
            "primary",
            "child-choice",
            &providers,
        )
        .expect("child node may pick its own slot choice");
        assert_eq!(child.provider, "openai");
        assert_eq!(child.model, "gpt");

        assert_eq!(
            resolve_node_model_override(
                &snapshot,
                Some("inst-child"),
                &[binding_evidence("anthropic", "anthropic", "opus")],
                &[],
                "primary",
                "child-choice",
                &providers,
            ),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible),
            "a delegated node must validate against its child binding evidence, not the root profile binding"
        );

        assert_eq!(
            resolve_node_model_override(
                &snapshot,
                Some("inst-child"),
                &[],
                &[],
                "primary",
                "root-choice",
                &providers,
            ),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible),
            "a parent choice_id must not apply to a child node sharing slot_id primary"
        );
        assert_eq!(
            resolve_node_model_override(
                &snapshot,
                Some("inst-root"),
                &[],
                &[],
                "primary",
                "child-choice",
                &providers,
            ),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible),
            "a child choice_id must not apply to the root node sharing slot_id primary"
        );
    }

    #[test]
    fn private_child_model_override_uses_immutable_focused_binding_choice() {
        let providers = named_providers(&[("openai", Some("openai"), "gpt")]);
        let snapshot = setup_snapshot("inst-root", Vec::new());
        let evidence = child_binding_evidence(Uuid::from_u128(99), "openai", "openai", "gpt");
        let installation_id = evidence.installation_id.to_string();
        let choice_id = cockpit_proto::focused_model_binding_choice_id("openai", "openai", "gpt");

        let binding = resolve_node_model_override(
            &snapshot,
            Some(&installation_id),
            &[evidence.binding.clone()],
            &[evidence],
            "primary",
            &choice_id,
            &providers,
        )
        .expect("focused private child binding must not require a public setup candidate");
        assert_eq!(binding.provider, "openai");
        assert_eq!(binding.model, "gpt");
    }

    #[test]
    fn private_child_same_display_routes_keep_distinct_opaque_choices() {
        let providers = named_providers(&[
            ("profile-a", Some("openai"), "gpt"),
            ("profile-b", Some("openai"), "gpt"),
        ]);
        let snapshot = setup_snapshot("inst-root", Vec::new());
        let installation_id = Uuid::from_u128(99);
        let first = child_binding_evidence(installation_id, "profile-a", "openai", "gpt");
        let mut second = child_binding_evidence(installation_id, "profile-b", "openai", "gpt");
        second.binding.is_default = false;
        let first_choice =
            cockpit_proto::focused_model_binding_choice_id("profile-a", "openai", "gpt");
        let second_choice =
            cockpit_proto::focused_model_binding_choice_id("profile-b", "openai", "gpt");
        assert_ne!(first_choice, second_choice);

        let selected = resolve_node_model_override(
            &snapshot,
            Some(&installation_id.to_string()),
            &[],
            &[first, second],
            "primary",
            &second_choice,
            &providers,
        )
        .expect("opaque route key must select the exact same-display profile");
        assert_eq!(selected.provider, "profile-b");
    }

    #[test]
    fn private_child_model_override_rejects_route_stale_for_pinned_slot_requirements() {
        let providers = named_providers(&[("openai", Some("openai"), "gpt")]);
        let snapshot = setup_snapshot("inst-root", Vec::new());
        let mut evidence = child_binding_evidence(Uuid::from_u128(99), "openai", "openai", "gpt");
        let installation_id = evidence.installation_id.to_string();
        evidence.slot_requirements.min_context_tokens = u64::MAX;
        let binding = evidence.binding.clone();
        let choice_id = cockpit_proto::focused_model_binding_choice_id("openai", "openai", "gpt");

        assert_eq!(
            resolve_node_model_override(
                &snapshot,
                Some(&installation_id),
                &[binding],
                &[evidence],
                "primary",
                &choice_id,
                &providers,
            ),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible),
            "a route compatible with an older provider generation must not bypass the focused child's pinned hard requirements"
        );
    }

    #[test]
    fn model_override_ignores_sibling_unavailable_same_named_slot() {
        let providers = named_providers(&[("openai", Some("openai"), "gpt")]);
        let snapshot = setup_snapshot(
            "inst-b",
            vec![
                candidate(
                    "inst-b",
                    true,
                    vec![slot(
                        "primary",
                        vec![model_choice("b-choice", "primary", "anthropic", "opus")],
                        Some(
                            cockpit_proto::SessionSetupUnavailableReasonV1::NoHardCompatibleLocalModel,
                        ),
                    )],
                ),
                candidate(
                    "inst-a",
                    false,
                    vec![slot(
                        "primary",
                        vec![model_choice("a-choice", "primary", "openai", "gpt")],
                        None,
                    )],
                ),
            ],
        );
        let binding = resolve_node_model_override(
            &snapshot,
            Some("inst-a"),
            &[binding_evidence("openai", "openai", "gpt")],
            &[],
            "primary",
            "a-choice",
            &providers,
        )
        .expect("sibling unavailable same-named slot must not reject this node's choice");
        assert_eq!(binding.provider, "openai");
        assert_eq!(binding.model, "gpt");
    }

    #[test]
    fn model_override_without_installation_link_is_incompatible() {
        let providers = custom_providers("profile-secret", "glm");
        let snapshot = setup_snapshot(
            "inst-a",
            vec![candidate(
                "inst-a",
                true,
                vec![slot(
                    "primary",
                    vec![model_choice(
                        "choice-local-offering-0",
                        "primary",
                        "configured-provider-0",
                        "glm",
                    )],
                    None,
                )],
            )],
        );
        assert_eq!(
            resolve_node_model_override(
                &snapshot,
                None,
                &[],
                &[],
                "primary",
                "choice-local-offering-0",
                &providers,
            ),
            Err(AgentSessionOverrideStatusV1::RejectedIncompatible)
        );
    }
}
