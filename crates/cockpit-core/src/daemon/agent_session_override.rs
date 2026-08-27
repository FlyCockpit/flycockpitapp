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
//! The model axis is validated in the dispatch layer against the session-setup
//! snapshot (hard-compatibility is daemon-owned there) and is not handled here.

use cockpit_config::config::sandbox_mode::SandboxMode;
use cockpit_proto::{
    AGENT_EFFECTIVE_SETTINGS_DTO_VERSION, AgentControlLockedReasonV1, AgentEffectiveSettingsV1,
    AgentQuestionControlV1, AgentQuestionEffectiveV1, AgentQuestionOverrideV1,
    AgentSandboxControlV1, AgentSessionOverrideFieldV1, AgentSessionOverrideStatusV1,
    AgentVerificationControlV1, AgentVerificationReductionV1, AgentVerificationRegionV1,
};
use uuid::Uuid;

use crate::db::agent_installations::{
    RedactedAgentProfileSnapshot, RedactedQuestionPolicy, RedactedVerificationRegion,
    VerificationEffectiveAction,
};
use crate::db::agent_tree_decisions::{
    AgentInstanceState, StoredOverrideField, StoredQuestionOverride, StoredSessionOverride,
    StoredVerificationReduction,
};

/// All loaded facts needed to project effective settings and authorize a
/// non-model override for one node. The dispatch layer loads these; the policy
/// below is a pure function of them.
#[derive(Debug, Clone)]
pub struct NodeOverrideContext {
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub state: AgentInstanceState,
    pub override_revision: i64,
    pub pending: Option<StoredSessionOverride>,
    pub effective: Option<StoredSessionOverride>,
    /// Session config sandbox default (the baseline when no consumed override).
    pub session_sandbox_default: SandboxMode,
    /// The node's resolved profile snapshot, when one is bound. Absent for a
    /// node with no persisted profile (e.g. a bare utility node).
    pub profile: Option<RedactedAgentProfileSnapshot>,
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
        override_revision: ctx.override_revision.max(0) as u64,
        terminal,
        sandbox,
        verification,
        question,
    }
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
            state: AgentInstanceState::Running,
            override_revision: 0,
            pending: None,
            effective: None,
            session_sandbox_default: SandboxMode::Sandbox,
            profile: None,
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
        });
        let regions = build_effective_settings(&ctx).verification.regions;
        assert_eq!(regions.len(), 2);
        let on = regions.iter().find(|r| r.region_id == "rule-on").unwrap();
        assert!(on.enabled && on.can_disable && on.can_restrict);
        // A region already turned off is not enabled and offers no reduction.
        let off = regions.iter().find(|r| r.region_id == "rule-off").unwrap();
        assert!(!off.enabled && !off.can_disable && !off.can_restrict);
    }
}
