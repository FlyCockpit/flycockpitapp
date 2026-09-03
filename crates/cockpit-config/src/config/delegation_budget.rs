//! Hierarchical delegation spend budget (issue #313).
//!
//! Typed spend ceilings for rounds, tokens, cost, and wall-clock. `None` on a
//! spec field means "inherit"; `"unlimited"` is an explicit opt-in and is
//! never the compiled default. Resolution is global → per-agent →
//! per-delegation, then intersected at runtime with the parent's remaining
//! pool so a subtree cannot exceed its root allotment.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Default per-agent round ceiling. Replaces the previous
/// `maxPrimaryRounds = 0` (unlimited) default.
pub const DEFAULT_MAX_ROUNDS: u32 = 32;
/// Default input-token ceiling for one delegation subtree.
pub const DEFAULT_MAX_INPUT_TOKENS: u64 = 1_000_000;
/// Default output-token ceiling for one delegation subtree.
pub const DEFAULT_MAX_OUTPUT_TOKENS: u64 = 250_000;
/// Default cost ceiling in micro-USD ($10.00).
pub const DEFAULT_MAX_COST_MICROUSD: u64 = 10_000_000;
/// Default wall-clock ceiling for one delegation subtree (30 minutes).
pub const DEFAULT_MAX_WALL_CLOCK_SECS: u64 = 30 * 60;
/// Default per-run round ceiling for schedule/goal loop iterations.
pub const DEFAULT_SCHEDULE_RUN_MAX_ROUNDS: u32 = 8;
/// Consecutive no-progress compact-and-continue bound. Liveness, not spend:
/// an unlimited budget cannot lift this.
pub const DEFAULT_COMPACT_NO_PROGRESS_LIMIT: u32 = 3;
/// Per-turn retry-attempt bound. Liveness, not spend.
pub const DEFAULT_MAX_RETRIES_PER_TURN: u32 = 8;

/// One spend dimension. `"unlimited"` is explicit opt-in; a JSON number is a
/// finite ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendLimit {
    Unlimited,
    Finite(u64),
}

impl SpendLimit {
    pub fn finite_u32(self) -> Option<u32> {
        match self {
            Self::Unlimited => None,
            Self::Finite(n) => Some(u32::try_from(n).unwrap_or(u32::MAX)),
        }
    }

    pub fn finite_u64(self) -> Option<u64> {
        match self {
            Self::Unlimited => None,
            Self::Finite(n) => Some(n),
        }
    }
}

impl Serialize for SpendLimit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Unlimited => serializer.serialize_str("unlimited"),
            Self::Finite(n) => serializer.serialize_u64(*n),
        }
    }
}

impl<'de> Deserialize<'de> for SpendLimit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(SpendLimitVisitor)
    }
}

struct SpendLimitVisitor;

impl<'de> Visitor<'de> for SpendLimitVisitor {
    type Value = SpendLimit;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("\"unlimited\" or a non-negative integer")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.eq_ignore_ascii_case("unlimited") {
            Ok(SpendLimit::Unlimited)
        } else {
            Err(E::custom(
                "expected \"unlimited\" or a non-negative integer",
            ))
        }
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(SpendLimit::Finite(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        if value < 0 {
            Err(E::custom("spend limit cannot be negative"))
        } else {
            Ok(SpendLimit::Finite(value as u64))
        }
    }
}

/// Overlay for a single budget. Omitted fields inherit the previous layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DelegationBudgetSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rounds: Option<SpendLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_tokens: Option<SpendLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<SpendLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_microusd: Option<SpendLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wall_clock_secs: Option<SpendLimit>,
}

impl DelegationBudgetSpec {
    pub fn is_empty(&self) -> bool {
        self.max_rounds.is_none()
            && self.max_input_tokens.is_none()
            && self.max_output_tokens.is_none()
            && self.max_cost_microusd.is_none()
            && self.max_wall_clock_secs.is_none()
    }

    pub fn unlimited() -> Self {
        Self {
            max_rounds: Some(SpendLimit::Unlimited),
            max_input_tokens: Some(SpendLimit::Unlimited),
            max_output_tokens: Some(SpendLimit::Unlimited),
            max_cost_microusd: Some(SpendLimit::Unlimited),
            max_wall_clock_secs: Some(SpendLimit::Unlimited),
        }
    }

    pub fn is_unlimited(&self) -> bool {
        matches!(self.max_rounds, Some(SpendLimit::Unlimited))
            && matches!(self.max_input_tokens, Some(SpendLimit::Unlimited))
            && matches!(self.max_output_tokens, Some(SpendLimit::Unlimited))
            && matches!(self.max_cost_microusd, Some(SpendLimit::Unlimited))
            && matches!(self.max_wall_clock_secs, Some(SpendLimit::Unlimited))
    }

    pub fn overlay(&self, base: ResolvedDelegationBudget) -> ResolvedDelegationBudget {
        ResolvedDelegationBudget {
            max_rounds: overlay_u32(self.max_rounds, base.max_rounds),
            max_input_tokens: overlay_u64(self.max_input_tokens, base.max_input_tokens),
            max_output_tokens: overlay_u64(self.max_output_tokens, base.max_output_tokens),
            max_cost_microusd: overlay_u64(self.max_cost_microusd, base.max_cost_microusd),
            max_wall_clock: overlay_duration(self.max_wall_clock_secs, base.max_wall_clock),
        }
    }
}

/// Global budget configuration: compiled-default overlay, per-agent overlays,
/// and the per-run overlay applied to each schedule/goal loop iteration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DelegationBudgetConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rounds: Option<SpendLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_tokens: Option<SpendLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<SpendLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_microusd: Option<SpendLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wall_clock_secs: Option<SpendLimit>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub agents: BTreeMap<String, DelegationBudgetSpec>,
    #[serde(default, skip_serializing_if = "DelegationBudgetSpec::is_empty")]
    pub schedule_per_run: DelegationBudgetSpec,
}

impl DelegationBudgetConfig {
    pub fn is_empty(&self) -> bool {
        self.max_rounds.is_none()
            && self.max_input_tokens.is_none()
            && self.max_output_tokens.is_none()
            && self.max_cost_microusd.is_none()
            && self.max_wall_clock_secs.is_none()
            && self.agents.is_empty()
            && self.schedule_per_run.is_empty()
    }

    pub fn global_spec(&self) -> DelegationBudgetSpec {
        DelegationBudgetSpec {
            max_rounds: self.max_rounds,
            max_input_tokens: self.max_input_tokens,
            max_output_tokens: self.max_output_tokens,
            max_cost_microusd: self.max_cost_microusd,
            max_wall_clock_secs: self.max_wall_clock_secs,
        }
    }

    pub fn set_global_spec(&mut self, spec: DelegationBudgetSpec) {
        self.max_rounds = spec.max_rounds;
        self.max_input_tokens = spec.max_input_tokens;
        self.max_output_tokens = spec.max_output_tokens;
        self.max_cost_microusd = spec.max_cost_microusd;
        self.max_wall_clock_secs = spec.max_wall_clock_secs;
    }
}

/// Runtime spend ceiling. `None` on a field is unlimited for that dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedDelegationBudget {
    pub max_rounds: Option<u32>,
    pub max_input_tokens: Option<u64>,
    pub max_output_tokens: Option<u64>,
    pub max_cost_microusd: Option<u64>,
    pub max_wall_clock: Option<Duration>,
}

impl ResolvedDelegationBudget {
    /// Compiled sane defaults: every spend dimension is finite.
    pub const fn defaults() -> Self {
        Self {
            max_rounds: Some(DEFAULT_MAX_ROUNDS),
            max_input_tokens: Some(DEFAULT_MAX_INPUT_TOKENS),
            max_output_tokens: Some(DEFAULT_MAX_OUTPUT_TOKENS),
            max_cost_microusd: Some(DEFAULT_MAX_COST_MICROUSD),
            max_wall_clock: Some(Duration::from_secs(DEFAULT_MAX_WALL_CLOCK_SECS)),
        }
    }

    /// Default per-run ceiling for schedule/goal loop iterations.
    pub const fn schedule_run_defaults() -> Self {
        Self {
            max_rounds: Some(DEFAULT_SCHEDULE_RUN_MAX_ROUNDS),
            max_input_tokens: Some(DEFAULT_MAX_INPUT_TOKENS),
            max_output_tokens: Some(DEFAULT_MAX_OUTPUT_TOKENS),
            max_cost_microusd: Some(DEFAULT_MAX_COST_MICROUSD),
            max_wall_clock: Some(Duration::from_secs(DEFAULT_MAX_WALL_CLOCK_SECS)),
        }
    }

    /// Unlimited spend. Liveness guards (progress, retry pacing, cancel,
    /// oversized-request) are still enforced by the runtime.
    pub const fn unlimited() -> Self {
        Self {
            max_rounds: None,
            max_input_tokens: None,
            max_output_tokens: None,
            max_cost_microusd: None,
            max_wall_clock: None,
        }
    }

    pub fn is_unlimited(self) -> bool {
        self.max_rounds.is_none()
            && self.max_input_tokens.is_none()
            && self.max_output_tokens.is_none()
            && self.max_cost_microusd.is_none()
            && self.max_wall_clock.is_none()
    }

    /// Tightest ceiling of `self` and `other`. Unlimited ∩ finite = finite.
    pub fn intersect(self, other: Self) -> Self {
        Self {
            max_rounds: min_opt(self.max_rounds, other.max_rounds),
            max_input_tokens: min_opt(self.max_input_tokens, other.max_input_tokens),
            max_output_tokens: min_opt(self.max_output_tokens, other.max_output_tokens),
            max_cost_microusd: min_opt(self.max_cost_microusd, other.max_cost_microusd),
            max_wall_clock: min_opt(self.max_wall_clock, other.max_wall_clock),
        }
    }

    /// Remaining ceiling after `spent`. Saturating; a dimension that is
    /// already exhausted becomes `Some(0)`.
    pub fn remaining_after(self, spent: BudgetSpend) -> Self {
        Self {
            max_rounds: remaining_u32(self.max_rounds, spent.rounds),
            max_input_tokens: remaining_u64(self.max_input_tokens, spent.input_tokens),
            max_output_tokens: remaining_u64(self.max_output_tokens, spent.output_tokens),
            max_cost_microusd: remaining_u64(self.max_cost_microusd, spent.cost_microusd),
            max_wall_clock: remaining_duration(self.max_wall_clock, spent.elapsed),
        }
    }
}

/// Spent amounts used when computing a remaining ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BudgetSpend {
    pub rounds: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_microusd: u64,
    pub elapsed: Duration,
}

fn overlay_u32(overlay: Option<SpendLimit>, base: Option<u32>) -> Option<u32> {
    match overlay {
        None => base,
        Some(SpendLimit::Unlimited) => None,
        Some(SpendLimit::Finite(n)) => Some(u32::try_from(n).unwrap_or(u32::MAX)),
    }
}

fn overlay_u64(overlay: Option<SpendLimit>, base: Option<u64>) -> Option<u64> {
    match overlay {
        None => base,
        Some(SpendLimit::Unlimited) => None,
        Some(SpendLimit::Finite(n)) => Some(n),
    }
}

fn overlay_duration(overlay: Option<SpendLimit>, base: Option<Duration>) -> Option<Duration> {
    match overlay {
        None => base,
        Some(SpendLimit::Unlimited) => None,
        Some(SpendLimit::Finite(n)) => Some(Duration::from_secs(n)),
    }
}

fn min_opt<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (None, None) => None,
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

fn remaining_u32(ceiling: Option<u32>, spent: u64) -> Option<u32> {
    ceiling.map(|max| {
        let max = u64::from(max);
        u32::try_from(max.saturating_sub(spent)).unwrap_or(u32::MAX)
    })
}

fn remaining_u64(ceiling: Option<u64>, spent: u64) -> Option<u64> {
    ceiling.map(|max| max.saturating_sub(spent))
}

fn remaining_duration(ceiling: Option<Duration>, spent: Duration) -> Option<Duration> {
    ceiling.map(|max| max.saturating_sub(spent))
}

/// Resolve the effective budget for `agent_name`.
///
/// Cascade: compiled defaults → global config → `max_primary_rounds` overlay
/// (legacy rounds-only field; `0` now means inherit, not unlimited) →
/// per-agent map → host `AgentRuntimeDefaults` → per-delegation spec.
pub fn resolve_delegation_budget(
    config: &DelegationBudgetConfig,
    agent_name: &str,
    agent_runtime: Option<&DelegationBudgetSpec>,
    per_delegation: Option<&DelegationBudgetSpec>,
    max_primary_rounds_overlay: u32,
) -> ResolvedDelegationBudget {
    let mut resolved = ResolvedDelegationBudget::defaults();
    resolved = config.global_spec().overlay(resolved);
    if config.max_rounds.is_none() && max_primary_rounds_overlay > 0 {
        resolved.max_rounds = Some(max_primary_rounds_overlay);
    }
    if let Some(agent_spec) = config.agents.get(agent_name) {
        resolved = agent_spec.overlay(resolved);
    }
    if let Some(runtime) = agent_runtime {
        resolved = runtime.overlay(resolved);
    }
    if let Some(delegation) = per_delegation {
        resolved = delegation.overlay(resolved);
    }
    resolved
}

/// Resolve the per-run budget for one schedule/goal loop iteration.
///
/// Starts from [`ResolvedDelegationBudget::schedule_run_defaults`], overlays
/// the global config (so an unlimited root can still be inherited), then the
/// dedicated `schedulePerRun` spec. The result is later intersected with the
/// parent's remaining pool at allotment time.
pub fn resolve_schedule_run_budget(config: &DelegationBudgetConfig) -> ResolvedDelegationBudget {
    let mut resolved = ResolvedDelegationBudget::schedule_run_defaults();
    resolved = config.global_spec().overlay(resolved);
    config.schedule_per_run.overlay(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spend_limit_round_trips_unlimited_and_finite() {
        let unlimited: SpendLimit = serde_json::from_str("\"unlimited\"").unwrap();
        assert_eq!(unlimited, SpendLimit::Unlimited);
        assert_eq!(
            serde_json::to_string(&SpendLimit::Unlimited).unwrap(),
            "\"unlimited\""
        );
        let finite: SpendLimit = serde_json::from_str("32").unwrap();
        assert_eq!(finite, SpendLimit::Finite(32));
        assert_eq!(
            serde_json::to_string(&SpendLimit::Finite(32)).unwrap(),
            "32"
        );
    }

    #[test]
    fn spend_limit_rejects_negative() {
        assert!(serde_json::from_str::<SpendLimit>("-1").is_err());
    }

    #[test]
    fn defaults_are_finite() {
        let d = ResolvedDelegationBudget::defaults();
        assert!(!d.is_unlimited());
        assert_eq!(d.max_rounds, Some(DEFAULT_MAX_ROUNDS));
        assert_eq!(d.max_input_tokens, Some(DEFAULT_MAX_INPUT_TOKENS));
        assert_eq!(d.max_output_tokens, Some(DEFAULT_MAX_OUTPUT_TOKENS));
        assert_eq!(d.max_cost_microusd, Some(DEFAULT_MAX_COST_MICROUSD));
        assert_eq!(
            d.max_wall_clock,
            Some(Duration::from_secs(DEFAULT_MAX_WALL_CLOCK_SECS))
        );
    }

    #[test]
    fn unlimited_is_all_none() {
        assert!(ResolvedDelegationBudget::unlimited().is_unlimited());
    }

    #[test]
    fn intersect_takes_the_tighter_finite_value() {
        let parent = ResolvedDelegationBudget {
            max_rounds: Some(32),
            max_input_tokens: None,
            max_output_tokens: Some(100),
            max_cost_microusd: Some(50),
            max_wall_clock: None,
        };
        let child = ResolvedDelegationBudget {
            max_rounds: Some(8),
            max_input_tokens: Some(10),
            max_output_tokens: None,
            max_cost_microusd: Some(80),
            max_wall_clock: Some(Duration::from_secs(5)),
        };
        let got = parent.intersect(child);
        assert_eq!(got.max_rounds, Some(8));
        assert_eq!(got.max_input_tokens, Some(10));
        assert_eq!(got.max_output_tokens, Some(100));
        assert_eq!(got.max_cost_microusd, Some(50));
        assert_eq!(got.max_wall_clock, Some(Duration::from_secs(5)));
    }

    #[test]
    fn resolve_cascade_global_agent_delegation() {
        let mut config = DelegationBudgetConfig::default();
        config.max_rounds = Some(SpendLimit::Finite(20));
        config.agents.insert(
            "explore".into(),
            DelegationBudgetSpec {
                max_rounds: Some(SpendLimit::Finite(6)),
                ..DelegationBudgetSpec::default()
            },
        );
        let per_delegation = DelegationBudgetSpec {
            max_input_tokens: Some(SpendLimit::Finite(100)),
            ..DelegationBudgetSpec::default()
        };
        let resolved =
            resolve_delegation_budget(&config, "explore", None, Some(&per_delegation), 0);
        assert_eq!(resolved.max_rounds, Some(6));
        assert_eq!(resolved.max_input_tokens, Some(100));
        assert_eq!(resolved.max_output_tokens, Some(DEFAULT_MAX_OUTPUT_TOKENS));
    }

    #[test]
    fn max_primary_rounds_overlays_only_when_budget_rounds_inherit() {
        let config = DelegationBudgetConfig::default();
        let resolved = resolve_delegation_budget(&config, "Build", None, None, 4);
        assert_eq!(resolved.max_rounds, Some(4));

        let mut unlimited_rounds = DelegationBudgetConfig::default();
        unlimited_rounds.max_rounds = Some(SpendLimit::Unlimited);
        let resolved = resolve_delegation_budget(&unlimited_rounds, "Build", None, None, 4);
        assert_eq!(resolved.max_rounds, None);
    }

    #[test]
    fn parent_can_allot_finite_slice_under_unlimited_root() {
        let unlimited = ResolvedDelegationBudget::unlimited();
        let child = ResolvedDelegationBudget {
            max_rounds: Some(3),
            ..ResolvedDelegationBudget::unlimited()
        };
        let allotted = unlimited.intersect(child);
        assert_eq!(allotted.max_rounds, Some(3));
        assert!(allotted.max_input_tokens.is_none());
    }

    #[test]
    fn schedule_per_run_defaults_to_eight_rounds() {
        let config = DelegationBudgetConfig::default();
        let resolved = resolve_schedule_run_budget(&config);
        assert_eq!(resolved.max_rounds, Some(DEFAULT_SCHEDULE_RUN_MAX_ROUNDS));
    }

    #[test]
    fn config_round_trips_through_json() {
        let raw = r#"{
            "maxRounds": "unlimited",
            "maxInputTokens": 1000,
            "agents": { "explore": { "maxRounds": 4 } },
            "schedulePerRun": { "maxRounds": 2 }
        }"#;
        let cfg: DelegationBudgetConfig = serde_json::from_str(raw).unwrap();
        assert_eq!(cfg.max_rounds, Some(SpendLimit::Unlimited));
        assert_eq!(cfg.max_input_tokens, Some(SpendLimit::Finite(1000)));
        assert_eq!(
            cfg.agents["explore"].max_rounds,
            Some(SpendLimit::Finite(4))
        );
        assert_eq!(cfg.schedule_per_run.max_rounds, Some(SpendLimit::Finite(2)));
    }
}
