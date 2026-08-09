//! Persisted session goals.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{Db, sql::placeholders};

/// Host-owned disposition of an explicit goal. Running goals additionally carry
/// a phase; every other disposition stores the phase to resume separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalDisposition {
    Running,
    UserPaused,
    InfraPaused,
    Blocked,
    NoProgressPaused,
    BudgetLimited,
    Complete,
    Cleared,
}

impl GoalDisposition {
    pub const ALL: [Self; 8] = [
        Self::Running,
        Self::UserPaused,
        Self::InfraPaused,
        Self::Blocked,
        Self::NoProgressPaused,
        Self::BudgetLimited,
        Self::Complete,
        Self::Cleared,
    ];

    pub const fn is_open(self) -> bool {
        !matches!(self, Self::Complete | Self::Cleared)
    }

    pub const fn is_terminal(self) -> bool {
        !self.is_open()
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::UserPaused => "user_paused",
            Self::InfraPaused => "infra_paused",
            Self::Blocked => "blocked",
            Self::NoProgressPaused => "no_progress_paused",
            Self::BudgetLimited => "budget_limited",
            Self::Complete => "complete",
            Self::Cleared => "cleared",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "running" => Ok(Self::Running),
            "user_paused" => Ok(Self::UserPaused),
            "infra_paused" => Ok(Self::InfraPaused),
            "blocked" => Ok(Self::Blocked),
            "no_progress_paused" => Ok(Self::NoProgressPaused),
            "budget_limited" => Ok(Self::BudgetLimited),
            "complete" => Ok(Self::Complete),
            "cleared" => Ok(Self::Cleared),
            _ => anyhow::bail!("invalid goal disposition `{value}`"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalPhase {
    Planning,
    Executing,
    Evaluating,
    Verifying,
}

impl GoalPhase {
    pub const ALL: [Self; 4] = [
        Self::Planning,
        Self::Executing,
        Self::Evaluating,
        Self::Verifying,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planning => "planning",
            Self::Executing => "executing",
            Self::Evaluating => "evaluating",
            Self::Verifying => "verifying",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "planning" => Ok(Self::Planning),
            "executing" => Ok(Self::Executing),
            "evaluating" => Ok(Self::Evaluating),
            "verifying" => Ok(Self::Verifying),
            _ => anyhow::bail!("invalid goal phase `{value}`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum GoalPauseReason {
    User,
    OperatorDisabled,
    Restart,
    PlannerFailure,
    EvaluatorFailure,
    RootTurnFailure,
    ProviderUsageLimit,
    RepeatedGapSet,
    VerificationAttemptCap,
}

impl GoalPauseReason {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::OperatorDisabled => "operator_disabled",
            Self::Restart => "restart",
            Self::PlannerFailure => "planner_failure",
            Self::EvaluatorFailure => "evaluator_failure",
            Self::RootTurnFailure => "root_turn_failure",
            Self::ProviderUsageLimit => "provider_usage_limit",
            Self::RepeatedGapSet => "repeated_gap_set",
            Self::VerificationAttemptCap => "verification_attempt_cap",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "user" => Ok(Self::User),
            "operator_disabled" => Ok(Self::OperatorDisabled),
            "restart" => Ok(Self::Restart),
            "planner_failure" => Ok(Self::PlannerFailure),
            "evaluator_failure" => Ok(Self::EvaluatorFailure),
            "root_turn_failure" => Ok(Self::RootTurnFailure),
            "provider_usage_limit" => Ok(Self::ProviderUsageLimit),
            "repeated_gap_set" => Ok(Self::RepeatedGapSet),
            "verification_attempt_cap" => Ok(Self::VerificationAttemptCap),
            _ => anyhow::bail!("invalid goal pause reason `{value}`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalContract {
    pub kind: String,
    pub acceptance: Vec<String>,
    pub verification_gates: Vec<String>,
    pub evidence_collection: Vec<String>,
    pub non_goals: Vec<String>,
    pub assumed_scope: Vec<String>,
    pub implementation_checklist: Vec<String>,
}

impl GoalContract {
    pub fn validate(&self) -> Result<()> {
        const MAX_KIND_CHARS: usize = 128;
        const MAX_ITEMS_PER_SECTION: usize = 32;
        const MAX_ITEM_CHARS: usize = 4_096;
        const MAX_SERIALIZED_BYTES: usize = 65_536;
        if self.kind.trim().is_empty()
            || self.kind.chars().count() > MAX_KIND_CHARS
            || self.acceptance.is_empty()
            || self.verification_gates.is_empty()
        {
            anyhow::bail!("goal contract requires kind, acceptance, and verification gates");
        }
        if self
            .acceptance
            .iter()
            .chain(&self.verification_gates)
            .any(|v| v.trim().is_empty())
        {
            anyhow::bail!("goal contract criteria must not be empty");
        }
        let sections = [
            &self.acceptance,
            &self.verification_gates,
            &self.evidence_collection,
            &self.non_goals,
            &self.assumed_scope,
            &self.implementation_checklist,
        ];
        if sections.iter().any(|section| {
            section.len() > MAX_ITEMS_PER_SECTION
                || section
                    .iter()
                    .any(|item| item.trim().is_empty() || item.chars().count() > MAX_ITEM_CHARS)
        }) || serde_json::to_vec(self)?.len() > MAX_SERIALIZED_BYTES
        {
            anyhow::bail!("goal contract exceeds bounded result limits");
        }
        Ok(())
    }

    /// Acceptance and verification are frozen completion authority. Only the
    /// guidance portions may evolve after the baseline is accepted.
    pub fn with_guidance_from(&self, advice: &Self) -> Result<Self> {
        if self.kind != advice.kind
            || self.acceptance != advice.acceptance
            || self.verification_gates != advice.verification_gates
            || self.evidence_collection != advice.evidence_collection
        {
            anyhow::bail!("goal contract baseline cannot be weakened or replaced");
        }
        let mut updated = self.clone();
        updated.non_goals = advice.non_goals.clone();
        updated.assumed_scope = advice.assumed_scope.clone();
        updated.implementation_checklist = advice.implementation_checklist.clone();
        Ok(updated)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoalLifecycle {
    pub disposition: GoalDisposition,
    pub phase: Option<GoalPhase>,
    pub resume_phase: Option<GoalPhase>,
    pub attempt_generation: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoalLifecycleEvent {
    PlannerAccepted,
    PlannerFailed,
    RootSucceeded,
    RootFailed,
    ApprovalPending,
    EvaluatorContinue,
    EvaluatorCandidateComplete,
    EvaluatorBlocked { streak: u8 },
    EvaluatorFailed,
    VerificationApproved,
    VerificationRefuted,
    RepeatedGapSet,
    VerificationCap,
    UserPause,
    OperatorDisabled,
    Restart,
    BudgetExhausted,
    UserResume,
    UserClear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoalTransition {
    pub lifecycle: GoalLifecycle,
    pub cancel_current_jobs: bool,
    pub dispatch_phase: Option<GoalPhase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalControlRole {
    Planner,
    Evaluator,
    Gatekeeper,
    ColdSkeptic,
}

impl GoalControlRole {
    pub const ALL: [Self; 4] = [
        Self::Planner,
        Self::Evaluator,
        Self::Gatekeeper,
        Self::ColdSkeptic,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planner => "planner",
            Self::Evaluator => "evaluator",
            Self::Gatekeeper => "gatekeeper",
            Self::ColdSkeptic => "cold_skeptic",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "planner" => Ok(Self::Planner),
            "evaluator" => Ok(Self::Evaluator),
            "gatekeeper" => Ok(Self::Gatekeeper),
            "cold_skeptic" => Ok(Self::ColdSkeptic),
            _ => anyhow::bail!("invalid goal control role `{value}`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalControlJob {
    pub job_id: Uuid,
    pub goal_id: Uuid,
    pub attempt_generation: i64,
    pub role: GoalControlRole,
    pub slot: i64,
    pub request_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum GoalEvaluatorDecision {
    Continue {
        next_step: String,
    },
    CandidateComplete {
        evidence: String,
    },
    Blocked {
        blocker_key: String,
        explanation: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum GoalSkepticVerdict {
    Approve { evidence: String },
    Refute { findings: Vec<String> },
}

const MAX_GOAL_CONTROL_FIELD_CHARS: usize = 4_096;
const MAX_GOAL_FINDINGS: usize = 32;

impl GoalEvaluatorDecision {
    fn validate(&self) -> Result<()> {
        let valid = |value: &str| {
            let len = value.chars().count();
            !value.trim().is_empty() && len <= MAX_GOAL_CONTROL_FIELD_CHARS
        };
        match self {
            Self::Continue { next_step } => valid(next_step),
            Self::CandidateComplete { evidence } => valid(evidence),
            Self::Blocked {
                blocker_key,
                explanation,
            } => valid(blocker_key) && valid(explanation),
        }
        .then_some(())
        .ok_or_else(|| anyhow::anyhow!("invalid evaluator decision fields"))
    }
}

impl GoalSkepticVerdict {
    fn validate(&self) -> Result<()> {
        let valid = |value: &str| {
            let len = value.chars().count();
            !value.trim().is_empty() && len <= MAX_GOAL_CONTROL_FIELD_CHARS
        };
        match self {
            Self::Approve { evidence } => valid(evidence),
            Self::Refute { findings } => {
                !findings.is_empty()
                    && findings.len() <= MAX_GOAL_FINDINGS
                    && findings.iter().all(|finding| valid(finding))
            }
        }
        .then_some(())
        .ok_or_else(|| anyhow::anyhow!("invalid skeptic verdict fields"))
    }
}

pub fn sanitize_goal_finding(value: &str) -> String {
    let mut cleaned = value
        .replace("<tool", "&lt;tool")
        .replace("</tool", "&lt;/tool")
        .replace("<assistant", "&lt;assistant")
        .replace("<system", "&lt;system");
    cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    cleaned.truncate(floor_char_boundary(&cleaned, 512));
    cleaned
}

fn sanitize_goal_evidence(value: &str) -> String {
    let mut cleaned = value
        .replace("<tool", "&lt;tool")
        .replace("</tool", "&lt;/tool")
        .replace("<assistant", "&lt;assistant")
        .replace("<system", "&lt;system");
    cleaned.truncate(floor_char_boundary(&cleaned, 16_384));
    cleaned
}

pub fn goal_gap_fingerprint(value: &str) -> String {
    let normalized = sanitize_goal_finding(value).to_lowercase();
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in normalized.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

impl GoalLifecycle {
    pub fn new() -> Self {
        Self {
            disposition: GoalDisposition::Running,
            phase: Some(GoalPhase::Planning),
            resume_phase: None,
            attempt_generation: 1,
        }
    }

    pub fn apply(self, event: GoalLifecycleEvent) -> Result<GoalTransition> {
        use GoalDisposition as D;
        use GoalLifecycleEvent as E;
        use GoalPhase as P;
        if self.disposition.is_terminal() {
            anyhow::bail!("terminal goal cannot transition");
        }
        let (disposition, phase, resume_phase, cancel, dispatch) =
            match (self.disposition, self.phase, event) {
                (_, _, E::UserClear) => (D::Cleared, None, None, true, None),
                (D::Running, Some(phase), E::UserPause) => {
                    (D::UserPaused, None, Some(phase), true, None)
                }
                (D::Running, Some(phase), E::OperatorDisabled | E::Restart) => {
                    (D::UserPaused, None, Some(phase), true, None)
                }
                (D::Running, Some(phase), E::BudgetExhausted) => {
                    (D::BudgetLimited, None, Some(phase), true, None)
                }
                (D::Running, Some(P::Planning), E::PlannerAccepted) => (
                    D::Running,
                    Some(P::Executing),
                    None,
                    false,
                    Some(P::Executing),
                ),
                (D::Running, Some(P::Planning), E::PlannerFailed) => {
                    (D::InfraPaused, None, Some(P::Planning), true, None)
                }
                (D::Running, Some(P::Executing), E::RootSucceeded) => (
                    D::Running,
                    Some(P::Evaluating),
                    None,
                    false,
                    Some(P::Evaluating),
                ),
                (D::Running, Some(P::Executing), E::RootFailed) => {
                    (D::InfraPaused, None, Some(P::Executing), true, None)
                }
                (D::Running, Some(P::Executing), E::ApprovalPending) => {
                    (D::Running, Some(P::Executing), None, false, None)
                }
                (
                    D::Running,
                    Some(P::Evaluating),
                    E::EvaluatorContinue | E::EvaluatorBlocked { streak: 0..=2 },
                ) => (
                    D::Running,
                    Some(P::Executing),
                    None,
                    false,
                    Some(P::Executing),
                ),
                (D::Running, Some(P::Evaluating), E::EvaluatorBlocked { streak: 3.. }) => {
                    (D::Blocked, None, Some(P::Executing), true, None)
                }
                (D::Running, Some(P::Evaluating), E::EvaluatorCandidateComplete) => (
                    D::Running,
                    Some(P::Verifying),
                    None,
                    false,
                    Some(P::Verifying),
                ),
                (D::Running, Some(P::Evaluating), E::EvaluatorFailed) => {
                    (D::InfraPaused, None, Some(P::Evaluating), true, None)
                }
                (D::Running, Some(P::Verifying), E::VerificationApproved) => {
                    (D::Complete, None, None, true, None)
                }
                (D::Running, Some(P::Verifying), E::VerificationRefuted) => (
                    D::Running,
                    Some(P::Executing),
                    None,
                    true,
                    Some(P::Executing),
                ),
                (D::Running, Some(P::Verifying), E::RepeatedGapSet) => {
                    (D::NoProgressPaused, None, Some(P::Executing), true, None)
                }
                (D::Running, Some(P::Verifying), E::VerificationCap) => {
                    (D::NoProgressPaused, None, Some(P::Executing), true, None)
                }
                (
                    D::UserPaused
                    | D::InfraPaused
                    | D::Blocked
                    | D::NoProgressPaused
                    | D::BudgetLimited,
                    None,
                    E::UserResume,
                ) => {
                    let phase = self
                        .resume_phase
                        .ok_or_else(|| anyhow::anyhow!("paused goal lacks resume phase"))?;
                    (D::Running, Some(phase), None, false, Some(phase))
                }
                _ => anyhow::bail!("illegal goal lifecycle transition"),
            };
        let starts_work = dispatch.is_some();
        Ok(GoalTransition {
            lifecycle: GoalLifecycle {
                disposition,
                phase,
                resume_phase,
                attempt_generation: self.attempt_generation + i64::from(starts_work),
            },
            cancel_current_jobs: cancel,
            dispatch_phase: dispatch,
        })
    }
}

impl Default for GoalLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionGoal {
    pub id: Uuid,
    pub session_id: Uuid,
    pub project_id: String,
    pub objective: String,
    pub context: Option<String>,
    pub disposition: GoalDisposition,
    pub phase: Option<GoalPhase>,
    pub resume_phase: Option<GoalPhase>,
    pub pause_reason: Option<GoalPauseReason>,
    pub attempt_generation: i64,
    pub contract: Option<GoalContract>,
    pub resolved_policy_json: String,
    pub evaluator_outcome_json: Option<String>,
    pub verifier_outcome_json: Option<String>,
    pub unresolved_gaps: Vec<String>,
    pub gap_fingerprints: Vec<String>,
    pub blocker_key: Option<String>,
    pub blocker_key_streak: i64,
    pub token_budget: i64,
    pub tokens_used: i64,
    /// Persisted active time plus the live interval beginning at `active_since`.
    pub elapsed_active_ms: i64,
    pub active_since: Option<i64>,
    pub lifecycle_history: Vec<GoalLifecycleHistoryEntry>,
    pub blocked_attempts: i64,
    pub completion_evidence: Option<String>,
    pub verification_rounds: i64,
    pub last_read_at: Option<i64>,
    pub cleared_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalLifecycleHistoryEntry {
    pub at: i64,
    pub disposition: GoalDisposition,
    pub phase: Option<GoalPhase>,
    pub reason: Option<GoalPauseReason>,
}

const MAX_GOAL_LIFECYCLE_HISTORY: usize = 32;

fn append_lifecycle_history(encoded: &str, entry: GoalLifecycleHistoryEntry) -> Result<String> {
    let mut history: Vec<GoalLifecycleHistoryEntry> =
        serde_json::from_str(encoded).context("decoding goal lifecycle history")?;
    history.push(entry);
    if history.len() > MAX_GOAL_LIFECYCLE_HISTORY {
        history.drain(..history.len() - MAX_GOAL_LIFECYCLE_HISTORY);
    }
    Ok(serde_json::to_string(&history)?)
}

fn record_lifecycle_history(
    conn: &rusqlite::Connection,
    goal_id: Uuid,
    entry: GoalLifecycleHistoryEntry,
) -> Result<()> {
    let encoded: String = conn.query_row(
        "SELECT lifecycle_history_json FROM session_goals WHERE id = ?1",
        params![goal_id.to_string()],
        |row| row.get(0),
    )?;
    conn.execute(
        "UPDATE session_goals SET lifecycle_history_json = ?1 WHERE id = ?2",
        params![
            append_lifecycle_history(&encoded, entry)?,
            goal_id.to_string()
        ],
    )?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalCompactionSnapshot {
    pub objective: String,
    pub disposition: GoalDisposition,
    pub phase: Option<GoalPhase>,
    pub token_budget: i64,
    pub tokens_used: i64,
    pub contract_reference: Option<Uuid>,
    pub latest_gap_or_blocker: Option<String>,
}

impl SessionGoal {
    fn transition(&self, event: GoalLifecycleEvent) -> Result<GoalTransition> {
        GoalLifecycle {
            disposition: self.disposition,
            phase: self.phase,
            resume_phase: self.resume_phase,
            attempt_generation: self.attempt_generation,
        }
        .apply(event)
    }

    pub fn compaction_snapshot(&self) -> GoalCompactionSnapshot {
        let mut objective = sanitize_goal_finding(&self.objective);
        objective.truncate(floor_char_boundary(&objective, 512));
        GoalCompactionSnapshot {
            objective,
            disposition: self.disposition,
            phase: self.phase,
            token_budget: self.token_budget,
            tokens_used: self.tokens_used,
            contract_reference: self.contract.as_ref().map(|_| self.id),
            latest_gap_or_blocker: self
                .unresolved_gaps
                .first()
                .or(self.blocker_key.as_ref())
                .map(|value| sanitize_goal_finding(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoalUpdateOutcome {
    Updated(SessionGoal),
    BlockAttempt { attempts: i64, required: i64 },
}

pub const BLOCK_ATTEMPTS_REQUIRED: i64 = 3;
const OPEN_DISPOSITION_VALUES: [&str; 6] = [
    "running",
    "user_paused",
    "infra_paused",
    "blocked",
    "no_progress_paused",
    "budget_limited",
];
const GOAL_SELECT: &str = "id, session_id, project_id, objective, context,
    disposition, phase, resume_phase, pause_reason, attempt_generation,
    contract_json, resolved_policy_json, evaluator_outcome_json, verifier_outcome_json,
    unresolved_gaps_json, gap_fingerprints_json, blocker_key, blocker_key_streak,
    token_budget, tokens_used, elapsed_active_ms, active_since, lifecycle_history_json,
    blocked_attempts, completion_evidence, verification_rounds,
    last_read_at, cleared_at, created_at, updated_at";

impl Db {
    pub async fn create_session_goal(
        &self,
        session_id: Uuid,
        project_id: &str,
        objective: &str,
        context: Option<&str>,
        token_budget: Option<i64>,
    ) -> Result<SessionGoal> {
        self.create_session_goal_with_policy(
            session_id,
            project_id,
            objective,
            context,
            token_budget,
            "{}",
        )
        .await
    }

    pub async fn create_session_goal_with_policy(
        &self,
        session_id: Uuid,
        project_id: &str,
        objective: &str,
        context: Option<&str>,
        token_budget: Option<i64>,
        policy_json: &str,
    ) -> Result<SessionGoal> {
        let objective = objective.trim();
        if objective.is_empty() {
            anyhow::bail!("goal objective must not be empty");
        }
        let token_budget = token_budget.unwrap_or(200_000);
        if token_budget <= 0 {
            anyhow::bail!("token_budget must be positive");
        }
        let id = Uuid::new_v4();
        let now = Utc::now().timestamp();
        let project_id = project_id.to_owned();
        let objective = objective.to_owned();
        let context = context.map(str::to_owned);
        serde_json::from_str::<serde_json::Value>(policy_json)
            .context("validating resolved goal policy")?;
        let policy_json = policy_json.to_owned();
        self.write(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let conn = &tx;
            let open_dispositiones = open_disposition_placeholders(2);
            let existing_params = bind_session_and_open_dispositiones(session_id.to_string());
            let existing_param_refs = param_refs(&existing_params);
            let existing: Option<String> = conn
                .query_row(
                    &format!(
                        "SELECT id FROM session_goals
                     WHERE session_id = ?1
                       AND disposition IN ({open_dispositiones})
                     LIMIT 1"
                    ),
                    existing_param_refs.as_slice(),
                    |row| row.get(0),
                )
                .optional()
                .context("checking existing session goal")?;
            if existing.is_some() {
                anyhow::bail!("session already has an open goal");
            }
            let token_baseline: i64 = conn.query_row(
                "SELECT COALESCE(SUM(input_tokens + output_tokens), 0) FROM inference_calls WHERE session_id = ?1",
                params![session_id.to_string()], |row| row.get(0),
            )?;
            conn.execute(
                "INSERT INTO session_goals
                    (id, session_id, project_id, objective, context, disposition, phase,
                     attempt_generation, resolved_policy_json, token_budget, token_accounting_baseline,
                     active_since, lifecycle_history_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'running', 'planning', 1, ?6, ?7, ?8, ?9, ?10, ?9, ?9)",
                params![
                    id.to_string(),
                    session_id.to_string(),
                    project_id,
                    objective,
                    clean_opt(context.as_deref()),
                    policy_json,
                    token_budget,
                    token_baseline,
                    now,
                    serde_json::to_string(&vec![GoalLifecycleHistoryEntry {
                        at: now,
                        disposition: GoalDisposition::Running,
                        phase: Some(GoalPhase::Planning),
                        reason: None,
                    }])?,
                ],
            )
            .context("inserting session_goal")?;
            let job_id = Uuid::new_v4();
            let planner_request = serde_json::json!({
                "goal_id": id,
                "attempt_generation": 1,
                "role": "planner",
                "objective": objective,
                "tool_policy": "read_only_workspace",
                "instructions": "Investigate read-only. Return only one JSON object matching response_schema.",
                "response_schema": {
                    "kind": "non-empty string",
                    "acceptance": ["small numbered observable outcomes"],
                    "verification_gates": ["required pass/fail gates"],
                    "evidence_collection": ["evidence to collect"],
                    "non_goals": ["explicit exclusions"],
                    "assumed_scope": ["scope assumptions"],
                    "implementation_checklist": ["guidance-only steps"]
                }
            });
            conn.execute(
                "INSERT INTO goal_control_jobs
                    (job_id, goal_id, attempt_generation, role, slot, request_json, state, created_at, updated_at)
                 VALUES (?1, ?2, 1, 'planner', 0, ?3, 'pending', ?4, ?4)",
                params![job_id.to_string(), id.to_string(), planner_request.to_string(), now],
            )
            .context("registering initial goal planner")?;
            let goal = load_goal(conn, session_id, id)?;
            tx.commit()?;
            Ok(goal)
        })
        .await
    }

    pub async fn current_session_goal(
        &self,
        session_id: Uuid,
        mark_read: bool,
    ) -> Result<Option<SessionGoal>> {
        self.write(move |conn| Db::current_session_goal_conn(conn, session_id, mark_read))
            .await
    }

    pub async fn update_session_goal(
        &self,
        session_id: Uuid,
        disposition: GoalDisposition,
        evidence: Option<&str>,
        blocker: Option<&str>,
        context_delta: Option<&str>,
    ) -> Result<GoalUpdateOutcome> {
        let now = Utc::now().timestamp();
        let evidence = evidence.map(str::to_owned);
        let blocker = blocker.map(str::to_owned);
        let context_delta = context_delta.map(str::to_owned);
        self.transaction(move |conn| {
            let mut goal = current_goal_required(conn, session_id)?;
            if disposition == GoalDisposition::Running {
                return Ok(GoalUpdateOutcome::Updated(Db::set_session_goal_status_conn(
                    conn,
                    session_id,
                    GoalDisposition::Running,
                )?));
            }
            match disposition {
                GoalDisposition::Complete => {
                    if clean_opt(evidence.as_deref()).is_none() {
                        anyhow::bail!("complete requires evidence");
                    }
                    if goal.disposition != GoalDisposition::Running
                        || goal.phase != Some(GoalPhase::Verifying)
                    {
                        anyhow::bail!("only verified goals may complete");
                    }
                }
                GoalDisposition::Blocked => {
                    if clean_opt(blocker.as_deref()).is_none() {
                        anyhow::bail!("blocked requires blocker");
                    }
                    let attempts = goal.blocked_attempts + 1;
                    if attempts < BLOCK_ATTEMPTS_REQUIRED {
                        conn.execute(
                            "UPDATE session_goals
                                SET blocked_attempts = ?1, updated_at = ?2
                              WHERE id = ?3",
                            params![attempts, now, goal.id.to_string()],
                        )
                        .context("recording blocked attempt")?;
                        return Ok(GoalUpdateOutcome::BlockAttempt {
                            attempts,
                            required: BLOCK_ATTEMPTS_REQUIRED,
                        });
                    }
                    goal.blocked_attempts = attempts;
                }
                GoalDisposition::Running
                | GoalDisposition::UserPaused
                | GoalDisposition::BudgetLimited
                | GoalDisposition::InfraPaused
                | GoalDisposition::NoProgressPaused => {}
                GoalDisposition::Cleared => anyhow::bail!("use clear_session_goal"),
            }

            let context = append_context(goal.context.as_deref(), context_delta.as_deref());
            let pause_reason = if disposition == GoalDisposition::InfraPaused
                && context_delta.as_deref().is_some_and(|value| value.contains("usage or rate limit"))
            { Some("provider_usage_limit") } else { None };
            if disposition != GoalDisposition::Running {
                conn.execute("UPDATE goal_control_jobs SET state = 'cancelled', cancel_reason = COALESCE(?1, 'lifecycle_transition'), updated_at = ?2 WHERE goal_id = ?3 AND attempt_generation = ?4 AND state IN ('pending', 'leased')", params![pause_reason, now, goal.id.to_string(), goal.attempt_generation])?;
                conn.execute("UPDATE goal_root_turns SET state = 'cancelled', updated_at = ?1 WHERE goal_id = ?2 AND attempt_generation = ?3 AND state IN ('pending', 'leased')", params![now, goal.id.to_string(), goal.attempt_generation])?;
            }
            conn.execute(
                "UPDATE session_goals
                    SET disposition = ?1,
                        phase = CASE WHEN ?1 = 'running' THEN phase ELSE NULL END,
                        resume_phase = CASE WHEN ?1 IN ('complete', 'cleared') THEN NULL ELSE phase END,
                        pause_reason = ?4,
                        context = COALESCE(?2, context),
                        blocked_attempts = CASE WHEN ?1 = 'blocked' THEN ?3 ELSE 0 END,
                        elapsed_active_ms = elapsed_active_ms + CASE WHEN active_since IS NULL THEN 0 ELSE MAX(0, ?5 - active_since) * 1000 END,
                        active_since = NULL,
                        updated_at = ?5
                  WHERE id = ?6 AND session_id = ?7",
                params![
                    disposition.as_str(),
                    context,
                    goal.blocked_attempts,
                    pause_reason,
                    now,
                    goal.id.to_string(),
                    session_id.to_string()
                ],
            )
            .context("updating session_goal")?;
            record_lifecycle_history(
                conn,
                goal.id,
                GoalLifecycleHistoryEntry {
                    at: now,
                    disposition,
                    phase: None,
                    reason: pause_reason
                        .map(GoalPauseReason::parse)
                        .transpose()?,
                },
            )?;
            Ok(GoalUpdateOutcome::Updated(load_goal(
                conn, session_id, goal.id,
            )?))
        })
        .await
    }

    pub async fn clear_session_goal(&self, session_id: Uuid) -> Result<bool> {
        self.transaction(move |conn| Db::clear_session_goal_conn(conn, session_id))
            .await
    }

    pub async fn set_session_goal_status(
        &self,
        session_id: Uuid,
        disposition: GoalDisposition,
    ) -> Result<SessionGoal> {
        if !matches!(
            disposition,
            GoalDisposition::Running | GoalDisposition::UserPaused
        ) {
            anyhow::bail!("set_session_goal_status supports active or paused");
        }
        self.transaction(move |conn| {
            Db::set_session_goal_status_conn(conn, session_id, disposition)
        })
        .await
    }

    pub async fn refresh_session_goal_usage(&self, session_id: Uuid) -> Result<()> {
        self.write(move |conn| Db::refresh_session_goal_usage_conn(conn, session_id))
            .await
    }

    pub async fn lease_goal_control_job(
        &self,
        goal_id: Uuid,
        attempt_generation: i64,
        now: i64,
        lease_seconds: i64,
    ) -> Result<Option<GoalControlJob>> {
        self.write(move |conn| {
            let row = conn.query_row(
                "SELECT job_id, role, slot, request_json FROM goal_control_jobs
                 WHERE goal_id = ?1 AND attempt_generation = ?2
                   AND (state = 'pending' OR (state = 'leased' AND lease_expires_at <= ?3))
                 ORDER BY role, slot LIMIT 1",
                params![goal_id.to_string(), attempt_generation, now],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, String>(3)?)),
            ).optional()?;
            let Some((job_id, role, slot, request_json)) = row else { return Ok(None); };
            let changed = conn.execute(
                "UPDATE goal_control_jobs SET state = 'leased', lease_expires_at = ?1, updated_at = ?2
                 WHERE job_id = ?3 AND (state = 'pending' OR (state = 'leased' AND lease_expires_at <= ?2))",
                params![now.saturating_add(lease_seconds.max(1)), now, job_id],
            )?;
            if changed == 0 { return Ok(None); }
            Ok(Some(GoalControlJob {
                job_id: Uuid::parse_str(&job_id)?,
                goal_id,
                attempt_generation,
                role: GoalControlRole::parse(&role)?,
                slot,
                request_json,
            }))
        }).await
    }

    pub async fn begin_goal_root_turn(
        &self,
        goal_id: Uuid,
        attempt_generation: i64,
    ) -> Result<Uuid> {
        let turn_id = Uuid::new_v4();
        self.write(move |conn| {
            let now = Utc::now().timestamp();
            let changed = conn.execute(
                "INSERT INTO goal_root_turns (goal_id, attempt_generation, turn_id, state, created_at, updated_at)
                 SELECT id, ?2, ?3, 'leased', ?4, ?4 FROM session_goals
                 WHERE id = ?1 AND attempt_generation = ?2 AND disposition = 'running' AND phase = 'executing'",
                params![goal_id.to_string(), attempt_generation, turn_id.to_string(), now],
            )?;
            if changed != 1 { anyhow::bail!("stale or non-executing goal root turn"); }
            Ok(turn_id)
        }).await
    }

    pub async fn finish_goal_root_turn(
        &self,
        goal_id: Uuid,
        attempt_generation: i64,
        turn_id: Uuid,
    ) -> Result<Option<SessionGoal>> {
        self.finish_goal_root_turn_with_evidence(
            goal_id,
            attempt_generation,
            turn_id,
            "host-observed successful root turn",
        )
        .await
    }

    pub async fn finish_goal_root_turn_with_evidence(
        &self,
        goal_id: Uuid,
        attempt_generation: i64,
        turn_id: Uuid,
        worker_evidence: &str,
    ) -> Result<Option<SessionGoal>> {
        let worker_evidence = sanitize_goal_evidence(worker_evidence);
        self.write(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let conn = &tx;
            let now = Utc::now().timestamp();
            let changed = conn.execute(
                "UPDATE goal_root_turns SET state = 'finished', audit_excerpt = ?1, updated_at = ?2
                 WHERE goal_id = ?3 AND attempt_generation = ?4 AND turn_id = ?5 AND state = 'leased'
                   AND EXISTS (SELECT 1 FROM session_goals WHERE id = ?3 AND disposition = 'running'
                               AND phase = 'executing' AND attempt_generation = ?4)",
                params![worker_evidence.as_str(), now, goal_id.to_string(), attempt_generation, turn_id.to_string()],
            )?;
            if changed != 1 { return Ok(None); }
            let session_id: String = conn.query_row("SELECT session_id FROM session_goals WHERE id = ?1", params![goal_id.to_string()], |row| row.get(0))?;
            let current = load_goal(conn, Uuid::parse_str(&session_id)?, goal_id)?;
            let transition = current.transition(GoalLifecycleEvent::RootSucceeded)?;
            let next_generation = transition.lifecycle.attempt_generation;
            let job_id = Uuid::new_v4();
            let request = evaluator_request(&current, next_generation, turn_id, &worker_evidence);
            conn.execute(
                "INSERT INTO goal_control_jobs (job_id, goal_id, attempt_generation, role, slot, request_json, state, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'evaluator', 0, ?4, 'pending', ?5, ?5)",
                params![job_id.to_string(), goal_id.to_string(), next_generation, request.to_string(), now],
            )?;
            conn.execute(
                "UPDATE session_goals SET phase = 'evaluating', attempt_generation = ?3, updated_at = ?1
                 WHERE id = ?2 AND disposition = 'running' AND phase = 'executing' AND attempt_generation = ?4",
                params![now, goal_id.to_string(), next_generation, attempt_generation],
            )?;
            record_lifecycle_history(conn, goal_id, GoalLifecycleHistoryEntry {
                at: now,
                disposition: GoalDisposition::Running,
                phase: Some(GoalPhase::Evaluating),
                reason: None,
            })?;
            let goal = load_goal(conn, Uuid::parse_str(&session_id)?, goal_id)?;
            tx.commit()?;
            Ok(Some(goal))
        }).await
    }

    pub async fn fail_goal_root_turn(
        &self,
        goal_id: Uuid,
        attempt_generation: i64,
        turn_id: Uuid,
    ) -> Result<bool> {
        self.write(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let goal: SessionGoal = tx.query_row(
                &format!("SELECT {GOAL_SELECT} FROM session_goals WHERE id = ?1"),
                params![goal_id.to_string()],
                decode_goal,
            )?;
            if goal.disposition != GoalDisposition::Running
                || goal.phase != Some(GoalPhase::Executing)
                || goal.attempt_generation != attempt_generation
            {
                return Ok(false);
            }
            goal.transition(GoalLifecycleEvent::RootFailed)?;
            let now = Utc::now().timestamp();
            let changed = tx.execute(
                "UPDATE goal_root_turns SET state = 'cancelled', audit_excerpt = 'root turn failed before evaluation', updated_at = ?1
                 WHERE goal_id = ?2 AND attempt_generation = ?3 AND turn_id = ?4 AND state = 'leased'",
                params![now, goal_id.to_string(), attempt_generation, turn_id.to_string()],
            )?;
            if changed == 1 {
                tx.execute(
                    "UPDATE session_goals SET disposition = 'infra_paused', resume_phase = 'executing',
                            phase = NULL, pause_reason = 'root_turn_failure',
                            elapsed_active_ms = elapsed_active_ms + MAX(0, ?1 - COALESCE(active_since, ?1)) * 1000,
                            active_since = NULL, updated_at = ?1
                     WHERE id = ?2 AND attempt_generation = ?3 AND disposition = 'running' AND phase = 'executing'",
                    params![now, goal_id.to_string(), attempt_generation],
                )?;
                record_lifecycle_history(
                    &tx,
                    goal_id,
                    GoalLifecycleHistoryEntry {
                        at: now,
                        disposition: GoalDisposition::InfraPaused,
                        phase: None,
                        reason: Some(GoalPauseReason::RootTurnFailure),
                    },
                )?;
            }
            tx.commit()?;
            Ok(changed == 1)
        }).await
    }

    pub async fn cancel_goal_root_turn_for_user(
        &self,
        goal_id: Uuid,
        attempt_generation: i64,
        turn_id: Uuid,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let now = Utc::now().timestamp();
            let goal: SessionGoal = conn.query_row(
                &format!("SELECT {GOAL_SELECT} FROM session_goals WHERE id = ?1"),
                params![goal_id.to_string()],
                decode_goal,
            )?;
            if goal.disposition != GoalDisposition::Running
                || goal.phase != Some(GoalPhase::Executing)
                || goal.attempt_generation != attempt_generation
            {
                return Ok(false);
            }
            goal.transition(GoalLifecycleEvent::UserPause)?;
            let changed = conn.execute(
                "UPDATE goal_root_turns SET state = 'cancelled', audit_excerpt = 'cancelled by user', updated_at = ?1
                 WHERE goal_id = ?2 AND attempt_generation = ?3 AND turn_id = ?4 AND state = 'leased'",
                params![now, goal_id.to_string(), attempt_generation, turn_id.to_string()],
            )?;
            if changed == 1 {
                conn.execute(
                    "UPDATE session_goals SET disposition = 'user_paused', resume_phase = 'executing',
                            phase = NULL, pause_reason = 'user',
                            elapsed_active_ms = elapsed_active_ms + MAX(0, ?1 - COALESCE(active_since, ?1)) * 1000,
                            active_since = NULL, updated_at = ?1
                     WHERE id = ?2 AND attempt_generation = ?3 AND disposition = 'running' AND phase = 'executing'",
                    params![now, goal_id.to_string(), attempt_generation],
                )?;
                record_lifecycle_history(
                    conn,
                    goal_id,
                    GoalLifecycleHistoryEntry {
                        at: now,
                        disposition: GoalDisposition::UserPaused,
                        phase: None,
                        reason: Some(GoalPauseReason::User),
                    },
                )?;
            }
            Ok(changed == 1)
        }).await
    }

    pub async fn defer_goal_root_turn_for_approval(
        &self,
        goal_id: Uuid,
        attempt_generation: i64,
        turn_id: Uuid,
    ) -> Result<bool> {
        self.write(move |conn| {
            let goal: SessionGoal = conn.query_row(
                &format!("SELECT {GOAL_SELECT} FROM session_goals WHERE id = ?1"),
                params![goal_id.to_string()],
                decode_goal,
            )?;
            if goal.disposition != GoalDisposition::Running
                || goal.phase != Some(GoalPhase::Executing)
                || goal.attempt_generation != attempt_generation
            {
                return Ok(false);
            }
            goal.transition(GoalLifecycleEvent::ApprovalPending)?;
            Ok(conn.execute(
                "UPDATE goal_root_turns SET state = 'cancelled', audit_excerpt = 'deferred for approval', updated_at = ?1
                 WHERE goal_id = ?2 AND attempt_generation = ?3 AND turn_id = ?4 AND state = 'leased'
                   AND EXISTS (SELECT 1 FROM session_goals WHERE id = ?2 AND disposition = 'running'
                               AND phase = 'executing' AND attempt_generation = ?3)",
                params![Utc::now().timestamp(), goal_id.to_string(), attempt_generation, turn_id.to_string()],
            )? == 1)
        }).await
    }

    /// Crash recovery is intentionally fail-closed: pre-crash work is never
    /// redispatched, and the interrupted phase is retained for explicit resume.
    pub async fn restore_supervised_goals(&self, session_id: Uuid) -> Result<Option<SessionGoal>> {
        self.transaction(move |conn| {
            let Some(goal) = Db::current_session_goal_conn(conn, session_id, false)? else { return Ok(None); };
            if goal.disposition != GoalDisposition::Running { return Ok(Some(goal)); }
            goal.transition(GoalLifecycleEvent::Restart)?;
            let now = Utc::now().timestamp();
            conn.execute(
                "UPDATE goal_control_jobs SET state = 'cancelled', cancel_reason = 'restart', updated_at = ?1
                 WHERE goal_id = ?2 AND state IN ('pending', 'leased')",
                params![now, goal.id.to_string()],
            )?;
            conn.execute(
                "UPDATE goal_root_turns SET state = 'cancelled', updated_at = ?1
                 WHERE goal_id = ?2 AND state IN ('pending', 'leased')",
                params![now, goal.id.to_string()],
            )?;
            conn.execute(
                "UPDATE session_goals SET disposition = 'user_paused', resume_phase = phase,
                        phase = NULL, pause_reason = 'restart',
                        elapsed_active_ms = elapsed_active_ms + MAX(0, ?1 - COALESCE(active_since, ?1)) * 1000,
                        active_since = NULL, updated_at = ?1 WHERE id = ?2",
                params![now, goal.id.to_string()],
            )?;
            record_lifecycle_history(conn, goal.id, GoalLifecycleHistoryEntry {
                at: now,
                disposition: GoalDisposition::UserPaused,
                phase: None,
                reason: Some(GoalPauseReason::Restart),
            })?;
            Ok(Some(load_goal(conn, session_id, goal.id)?))
        }).await
    }

    pub async fn pause_open_goal_for_operator_disable(
        &self,
        session_id: Uuid,
    ) -> Result<Option<SessionGoal>> {
        self.transaction(move |conn| {
            let Some(goal) = Db::current_session_goal_conn(conn, session_id, false)? else { return Ok(None); };
            if goal.disposition != GoalDisposition::Running { return Ok(Some(goal)); }
            goal.transition(GoalLifecycleEvent::OperatorDisabled)?;
            let now = Utc::now().timestamp();
            conn.execute("UPDATE goal_control_jobs SET state = 'cancelled', cancel_reason = 'operator_disabled', updated_at = ?1 WHERE goal_id = ?2 AND state IN ('pending', 'leased')", params![now, goal.id.to_string()])?;
            conn.execute("UPDATE goal_root_turns SET state = 'cancelled', updated_at = ?1 WHERE goal_id = ?2 AND state IN ('pending', 'leased')", params![now, goal.id.to_string()])?;
            conn.execute("UPDATE session_goals SET disposition = 'user_paused', resume_phase = phase, phase = NULL, pause_reason = 'operator_disabled', elapsed_active_ms = elapsed_active_ms + MAX(0, ?1 - COALESCE(active_since, ?1)) * 1000, active_since = NULL, updated_at = ?1 WHERE id = ?2", params![now, goal.id.to_string()])?;
            record_lifecycle_history(conn, goal.id, GoalLifecycleHistoryEntry { at: now, disposition: GoalDisposition::UserPaused, phase: None, reason: Some(GoalPauseReason::OperatorDisabled) })?;
            Ok(Some(load_goal(conn, session_id, goal.id)?))
        }).await
    }

    /// Atomically parks every running supervised goal, including detached
    /// sessions that have no worker to receive a config-refresh message.
    pub async fn pause_all_goals_for_operator_disable(&self) -> Result<usize> {
        self.transaction(move |conn| {
            let now = Utc::now().timestamp();
            conn.execute(
                "UPDATE goal_control_jobs SET state = 'cancelled', cancel_reason = 'operator_disabled', updated_at = ?1
                 WHERE state IN ('pending', 'leased') AND goal_id IN
                   (SELECT id FROM session_goals WHERE disposition = 'running')",
                params![now],
            )?;
            conn.execute(
                "UPDATE goal_root_turns SET state = 'cancelled', updated_at = ?1
                 WHERE state IN ('pending', 'leased') AND goal_id IN
                   (SELECT id FROM session_goals WHERE disposition = 'running')",
                params![now],
            )?;
            let mut rows = conn.prepare(
                "SELECT id, phase, lifecycle_history_json FROM session_goals WHERE disposition = 'running'",
            )?;
            let goals = rows
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(rows);
            for (id, phase, history) in &goals {
                let history = append_lifecycle_history(
                    history,
                    GoalLifecycleHistoryEntry {
                        at: now,
                        disposition: GoalDisposition::UserPaused,
                        phase: None,
                        reason: Some(GoalPauseReason::OperatorDisabled),
                    },
                )?;
                conn.execute(
                    "UPDATE session_goals SET disposition = 'user_paused', resume_phase = ?1,
                         phase = NULL, pause_reason = 'operator_disabled',
                         elapsed_active_ms = elapsed_active_ms + MAX(0, ?2 - COALESCE(active_since, ?2)) * 1000,
                         active_since = NULL, lifecycle_history_json = ?3, updated_at = ?2
                     WHERE id = ?4 AND disposition = 'running'",
                    params![phase, now, history, id],
                )?;
            }
            Ok(goals.len())
        })
        .await
    }

    pub async fn purge_cleared_goal_tombstones(&self, now: i64) -> Result<usize> {
        const RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;
        self.transaction(move |conn| {
            let cutoff = now.saturating_sub(RETENTION_SECONDS);
            let mut statement = conn.prepare(
                "SELECT id FROM session_goals g WHERE disposition = 'cleared' AND cleared_at <= ?1
                 AND NOT EXISTS (SELECT 1 FROM goal_control_jobs j WHERE j.goal_id = g.id AND j.state IN ('pending', 'leased'))",
            )?;
            let ids = statement.query_map(params![cutoff], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(statement);
            let mut purged = 0;
            for id in ids {
                conn.execute("DELETE FROM goal_control_jobs WHERE goal_id = ?1", params![id])?;
                conn.execute("DELETE FROM goal_root_turns WHERE goal_id = ?1", params![id])?;
                purged += conn.execute("DELETE FROM session_goals WHERE id = ?1 AND disposition = 'cleared'", params![id])?;
            }
            Ok(purged)
        }).await
    }

    pub async fn finish_goal_control_job(
        &self,
        job: GoalControlJob,
        output: Result<&str, &str>,
    ) -> Result<Option<SessionGoal>> {
        let output = output.map(str::to_owned).map_err(str::to_owned);
        self.transaction(move |conn| {
            let Some(goal) = conn.query_row(
                &format!("SELECT {GOAL_SELECT} FROM session_goals WHERE id = ?1"),
                params![job.goal_id.to_string()], decode_goal,
            ).optional()? else { return Ok(None); };
            if goal.disposition != GoalDisposition::Running
                || goal.attempt_generation != job.attempt_generation
            {
                return Ok(None);
            }
            let now = Utc::now().timestamp();
            let state: Option<String> = conn.query_row(
                "SELECT state FROM goal_control_jobs WHERE job_id = ?1",
                params![job.job_id.to_string()], |row| row.get(0),
            ).optional()?;
            if state.as_deref() != Some("leased") { return Ok(None); }

            match job.role {
                GoalControlRole::Planner => {
                    let contract = output.as_ref().ok().and_then(|raw| serde_json::from_str::<GoalContract>(raw).ok()).filter(|contract| contract.validate().is_ok());
                    let Some(contract) = contract else {
                        goal.transition(GoalLifecycleEvent::PlannerFailed)?;
                        finish_control_row(conn, &job, output.as_ref().ok().map(String::as_str), now)?;
                        pause_goal_for_failure(conn, &goal, GoalPhase::Planning, "planner_failure", now)?;
                        return Ok(Some(load_goal(conn, goal.session_id, goal.id)?));
                    };
                    let transition = goal.transition(GoalLifecycleEvent::PlannerAccepted)?;
                    finish_control_row(conn, &job, output.as_ref().ok().map(String::as_str), now)?;
                    conn.execute(
                        "UPDATE session_goals SET contract_json = ?1, phase = 'executing', attempt_generation = ?2, updated_at = ?3
                         WHERE id = ?4 AND disposition = 'running' AND phase = 'planning' AND attempt_generation = ?5",
                        params![serde_json::to_string(&contract)?, transition.lifecycle.attempt_generation, now, goal.id.to_string(), job.attempt_generation],
                    )?;
                    record_lifecycle_history(conn, goal.id, GoalLifecycleHistoryEntry {
                        at: now,
                        disposition: GoalDisposition::Running,
                        phase: Some(GoalPhase::Executing),
                        reason: None,
                    })?;
                }
                GoalControlRole::Evaluator => {
                    let decision = output.as_ref().ok().and_then(|raw| serde_json::from_str::<GoalEvaluatorDecision>(raw).ok()).filter(|decision| decision.validate().is_ok());
                    let Some(decision) = decision else {
                        goal.transition(GoalLifecycleEvent::EvaluatorFailed)?;
                        finish_control_row(conn, &job, output.as_ref().ok().map(String::as_str), now)?;
                        pause_goal_for_failure(conn, &goal, GoalPhase::Evaluating, "evaluator_failure", now)?;
                        return Ok(Some(load_goal(conn, goal.session_id, goal.id)?));
                    };
                    finish_control_row(conn, &job, output.as_ref().ok().map(String::as_str), now)?;
                    let decision_json = serde_json::to_string(&decision)?;
                    match decision {
                        GoalEvaluatorDecision::Continue { .. } => {
                            let transition = goal.transition(GoalLifecycleEvent::EvaluatorContinue)?;
                            conn.execute("UPDATE session_goals SET phase = 'executing', attempt_generation = ?1, evaluator_outcome_json = ?2, blocker_key = NULL, blocker_key_streak = 0, updated_at = ?3 WHERE id = ?4 AND attempt_generation = ?5", params![transition.lifecycle.attempt_generation, decision_json, now, goal.id.to_string(), job.attempt_generation])?;
                            record_lifecycle_history(conn, goal.id, GoalLifecycleHistoryEntry { at: now, disposition: GoalDisposition::Running, phase: Some(GoalPhase::Executing), reason: None })?;
                        }
                        GoalEvaluatorDecision::Blocked { blocker_key, .. } => {
                            let key = sanitize_goal_finding(&blocker_key);
                            let streak = if goal.blocker_key.as_deref() == Some(key.as_str()) { goal.blocker_key_streak + 1 } else { 1 };
                            let transition = goal.transition(GoalLifecycleEvent::EvaluatorBlocked {
                                streak: u8::try_from(streak).unwrap_or(u8::MAX),
                            })?;
                            if streak >= 3 {
                                conn.execute("UPDATE session_goals SET disposition = 'blocked', phase = NULL, resume_phase = 'executing', evaluator_outcome_json = ?1, blocker_key = ?2, blocker_key_streak = ?3, elapsed_active_ms = elapsed_active_ms + MAX(0, ?4 - COALESCE(active_since, ?4)) * 1000, active_since = NULL, updated_at = ?4 WHERE id = ?5 AND attempt_generation = ?6", params![decision_json, key, streak, now, goal.id.to_string(), job.attempt_generation])?;
                                record_lifecycle_history(conn, goal.id, GoalLifecycleHistoryEntry { at: now, disposition: GoalDisposition::Blocked, phase: None, reason: None })?;
                            } else {
                                conn.execute("UPDATE session_goals SET phase = 'executing', attempt_generation = ?1, evaluator_outcome_json = ?2, blocker_key = ?3, blocker_key_streak = ?4, updated_at = ?5 WHERE id = ?6 AND attempt_generation = ?7", params![transition.lifecycle.attempt_generation, decision_json, key, streak, now, goal.id.to_string(), job.attempt_generation])?;
                                record_lifecycle_history(conn, goal.id, GoalLifecycleHistoryEntry { at: now, disposition: GoalDisposition::Running, phase: Some(GoalPhase::Executing), reason: None })?;
                            }
                        }
                        GoalEvaluatorDecision::CandidateComplete { .. } => {
                            let transition = goal.transition(GoalLifecycleEvent::EvaluatorCandidateComplete)?;
                            conn.execute("UPDATE session_goals SET phase = 'verifying', attempt_generation = ?1, evaluator_outcome_json = ?2, verification_rounds = verification_rounds + 1, blocker_key = NULL, blocker_key_streak = 0, updated_at = ?3 WHERE id = ?4 AND attempt_generation = ?5", params![transition.lifecycle.attempt_generation, decision_json, now, goal.id.to_string(), job.attempt_generation])?;
                            record_lifecycle_history(conn, goal.id, GoalLifecycleHistoryEntry { at: now, disposition: GoalDisposition::Running, phase: Some(GoalPhase::Verifying), reason: None })?;
                            let verifying = load_goal(conn, goal.session_id, goal.id)?;
                            register_verification_jobs(conn, &verifying, &decision_json, now)?;
                        }
                    }
                }
                GoalControlRole::Gatekeeper | GoalControlRole::ColdSkeptic => {
                    let verdict = output.as_ref().ok().and_then(|raw| serde_json::from_str::<GoalSkepticVerdict>(raw).ok()).filter(|verdict| verdict.validate().is_ok()).unwrap_or_else(|| GoalSkepticVerdict::Refute { findings: vec!["skeptic result unavailable or malformed".into()] });
                    let normalized = serde_json::to_string(&verdict)?;
                    finish_control_row(conn, &job, Some(&normalized), now)?;
                    apply_verification_if_terminal(conn, &goal, now)?;
                }
            }
            Ok(Some(load_goal(conn, goal.session_id, goal.id)?))
        }).await
    }

    pub fn current_session_goal_conn(
        conn: &rusqlite::Connection,
        session_id: Uuid,
        mark_read: bool,
    ) -> Result<Option<SessionGoal>> {
        let now = Utc::now().timestamp();
        let open_dispositiones = open_disposition_placeholders(2);
        let goal_params = bind_session_and_open_dispositiones(session_id.to_string());
        let goal_param_refs = param_refs(&goal_params);
        let goal = conn
            .query_row(
                &format!(
                    "SELECT {GOAL_SELECT}
                 FROM session_goals
                 WHERE session_id = ?1
                   AND disposition IN ({open_dispositiones})
                 ORDER BY updated_at DESC
                 LIMIT 1"
                ),
                goal_param_refs.as_slice(),
                decode_goal,
            )
            .optional()
            .context("loading current session goal")?;
        if mark_read && let Some(goal) = &goal {
            conn.execute(
                "UPDATE session_goals SET last_read_at = ?1 WHERE id = ?2",
                params![now, goal.id.to_string()],
            )
            .context("marking goal read")?;
            let mut goal = goal.clone();
            goal.last_read_at = Some(now);
            return Ok(Some(goal));
        }
        Ok(goal)
    }

    pub fn clear_session_goal_conn(conn: &rusqlite::Connection, session_id: Uuid) -> Result<bool> {
        let now = Utc::now().timestamp();
        let Some(goal) = Db::current_session_goal_conn(conn, session_id, false)? else {
            return Ok(false);
        };
        goal.transition(GoalLifecycleEvent::UserClear)?;
        conn.execute(
            "UPDATE goal_control_jobs SET state = 'cancelled', cancel_reason = 'cleared', updated_at = ?1
             WHERE goal_id = ?2 AND state IN ('pending', 'leased')",
            params![now, goal.id.to_string()],
        )?;
        conn.execute(
            "UPDATE goal_root_turns SET state = 'cancelled', updated_at = ?1
             WHERE goal_id = ?2 AND state IN ('pending', 'leased')",
            params![now, goal.id.to_string()],
        )?;
        let changed = conn.execute(
            "UPDATE session_goals SET disposition = 'cleared', phase = NULL, resume_phase = NULL,
                    elapsed_active_ms = elapsed_active_ms + CASE WHEN active_since IS NULL THEN 0 ELSE MAX(0, ?1 - active_since) * 1000 END,
                    active_since = NULL, cleared_at = ?1, updated_at = ?1 WHERE id = ?2",
            params![now, goal.id.to_string()],
        ).context("clearing session goal")?;
        record_lifecycle_history(
            conn,
            goal.id,
            GoalLifecycleHistoryEntry {
                at: now,
                disposition: GoalDisposition::Cleared,
                phase: None,
                reason: None,
            },
        )?;
        Ok(changed > 0)
    }

    pub fn set_session_goal_status_conn(
        conn: &rusqlite::Connection,
        session_id: Uuid,
        disposition: GoalDisposition,
    ) -> Result<SessionGoal> {
        if !matches!(
            disposition,
            GoalDisposition::Running | GoalDisposition::UserPaused
        ) {
            anyhow::bail!("set_session_goal_status supports active or paused");
        }
        let now = Utc::now().timestamp();
        let goal = current_goal_required(conn, session_id)?;
        if goal.disposition == disposition {
            return Ok(goal);
        }
        let lifecycle = GoalLifecycle {
            disposition: goal.disposition,
            phase: goal.phase,
            resume_phase: goal.resume_phase,
            attempt_generation: goal.attempt_generation,
        }
        .apply(if disposition == GoalDisposition::UserPaused {
            GoalLifecycleEvent::UserPause
        } else {
            GoalLifecycleEvent::UserResume
        })?
        .lifecycle;
        if disposition == GoalDisposition::UserPaused {
            conn.execute(
                "UPDATE goal_control_jobs SET state = 'cancelled', cancel_reason = 'user', updated_at = ?1
                 WHERE goal_id = ?2 AND attempt_generation = ?3 AND state IN ('pending', 'leased')",
                params![now, goal.id.to_string(), goal.attempt_generation],
            )?;
            conn.execute(
                "UPDATE goal_root_turns SET state = 'cancelled', updated_at = ?1
                 WHERE goal_id = ?2 AND attempt_generation = ?3 AND state IN ('pending', 'leased')",
                params![now, goal.id.to_string(), goal.attempt_generation],
            )?;
        }
        conn.execute(
            "UPDATE session_goals SET disposition = ?1, phase = ?2, resume_phase = ?3,
                    pause_reason = CASE WHEN ?1 = 'user_paused' THEN 'user' ELSE NULL END,
                    attempt_generation = ?4,
                    elapsed_active_ms = elapsed_active_ms + CASE WHEN ?1 = 'user_paused' AND active_since IS NOT NULL THEN MAX(0, ?5 - active_since) * 1000 ELSE 0 END,
                    active_since = CASE WHEN ?1 = 'running' THEN ?5 ELSE NULL END,
                    updated_at = ?5 WHERE id = ?6",
            params![
                disposition.as_str(),
                lifecycle.phase.map(GoalPhase::as_str),
                lifecycle.resume_phase.map(GoalPhase::as_str),
                lifecycle.attempt_generation,
                now,
                goal.id.to_string()
            ],
        )
        .context("setting session goal disposition")?;
        record_lifecycle_history(
            conn,
            goal.id,
            GoalLifecycleHistoryEntry {
                at: now,
                disposition,
                phase: lifecycle.phase,
                reason: (disposition == GoalDisposition::UserPaused)
                    .then_some(GoalPauseReason::User),
            },
        )?;
        let updated = load_goal(conn, session_id, goal.id)?;
        if disposition == GoalDisposition::Running {
            match updated.phase {
                Some(GoalPhase::Planning) | Some(GoalPhase::Evaluating) => {
                    let (role, request) = if updated.phase == Some(GoalPhase::Planning) {
                        (
                            GoalControlRole::Planner,
                            serde_json::json!({
                                "goal_id": updated.id,
                                "attempt_generation": updated.attempt_generation,
                                "role": "planner",
                                "objective": updated.objective,
                                "tool_policy": "read_only_workspace",
                                "instructions": "Investigate read-only. Return only one JSON object matching response_schema.",
                                "response_schema": {
                                    "kind": "non-empty string",
                                    "acceptance": ["small numbered observable outcomes"],
                                    "verification_gates": ["required pass/fail gates"],
                                    "evidence_collection": ["evidence to collect"],
                                    "non_goals": ["explicit exclusions"],
                                    "assumed_scope": ["scope assumptions"],
                                    "implementation_checklist": ["guidance-only steps"]
                                }
                            }),
                        )
                    } else {
                        let (turn_id, evidence) = conn
                            .query_row(
                                "SELECT turn_id, audit_excerpt FROM goal_root_turns
                             WHERE goal_id = ?1 AND state = 'finished'
                             ORDER BY updated_at DESC, rowid DESC LIMIT 1",
                                params![updated.id.to_string()],
                                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                            )
                            .context(
                                "resuming evaluator without durable successful root-turn evidence",
                            )?;
                        (
                            GoalControlRole::Evaluator,
                            evaluator_request(
                                &updated,
                                updated.attempt_generation,
                                Uuid::parse_str(&turn_id)?,
                                &sanitize_goal_evidence(&evidence),
                            ),
                        )
                    };
                    conn.execute("INSERT INTO goal_control_jobs (job_id, goal_id, attempt_generation, role, slot, request_json, state, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, 0, ?5, 'pending', ?6, ?6)", params![Uuid::new_v4().to_string(), updated.id.to_string(), updated.attempt_generation, role.as_str(), request.to_string(), now])?;
                }
                Some(GoalPhase::Verifying) => {
                    let max_attempts = goal_max_verification_attempts(&updated);
                    if u64::try_from(updated.verification_rounds).unwrap_or(u64::MAX)
                        >= max_attempts
                    {
                        conn.execute(
                            "UPDATE session_goals SET disposition = 'no_progress_paused', phase = NULL,
                                    resume_phase = 'executing', pause_reason = 'verification_attempt_cap',
                                    elapsed_active_ms = elapsed_active_ms + MAX(0, ?1 - COALESCE(active_since, ?1)) * 1000,
                                    active_since = NULL, updated_at = ?1 WHERE id = ?2 AND attempt_generation = ?3",
                            params![now, updated.id.to_string(), updated.attempt_generation],
                        )?;
                        record_lifecycle_history(
                            conn,
                            updated.id,
                            GoalLifecycleHistoryEntry {
                                at: now,
                                disposition: GoalDisposition::NoProgressPaused,
                                phase: None,
                                reason: Some(GoalPauseReason::VerificationAttemptCap),
                            },
                        )?;
                    } else {
                        conn.execute(
                            "UPDATE session_goals SET verification_rounds = verification_rounds + 1,
                                    updated_at = ?1 WHERE id = ?2 AND attempt_generation = ?3
                                    AND disposition = 'running' AND phase = 'verifying'",
                            params![now, updated.id.to_string(), updated.attempt_generation],
                        )?;
                        let replacement = load_goal(conn, updated.session_id, updated.id)?;
                        register_verification_jobs(
                            conn,
                            &replacement,
                            replacement
                                .evaluator_outcome_json
                                .as_deref()
                                .unwrap_or("{}"),
                            now,
                        )?;
                    }
                }
                Some(GoalPhase::Executing) | None => {}
            }
        }
        load_goal(conn, session_id, goal.id)
    }

    pub fn refresh_session_goal_usage_conn(
        conn: &rusqlite::Connection,
        session_id: Uuid,
    ) -> Result<()> {
        let open_dispositiones = open_disposition_placeholders(2);
        let bind = bind_session_and_open_dispositiones(session_id.to_string());
        let bind_refs = param_refs(&bind);
        // Usage is charged exactly once by `insert_inference_call_conn`, in the
        // same transaction as the uniquely keyed call row. This refresh keeps
        // the aggregate checkpoint diagnostic current, but never derives usage
        // from a resettable/retention-pruned snapshot.
        conn.execute(
            &format!(
                "UPDATE session_goals
                SET token_accounting_baseline = COALESCE((
                    SELECT SUM(input_tokens + output_tokens)
                    FROM inference_calls
                    WHERE session_id = session_goals.session_id
                ), 0)
              WHERE session_id = ?1
                AND disposition IN ({open_dispositiones})"
            ),
            bind_refs.as_slice(),
        )
        .context("refreshing goal token usage")?;
        Ok(())
    }
}

fn finish_control_row(
    conn: &rusqlite::Connection,
    job: &GoalControlJob,
    result: Option<&str>,
    now: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE goal_control_jobs SET state = 'finished', result_json = ?1,
                lease_expires_at = NULL, updated_at = ?2
         WHERE job_id = ?3 AND state = 'leased'",
        params![result, now, job.job_id.to_string()],
    )?;
    Ok(())
}

fn pause_goal_for_failure(
    conn: &rusqlite::Connection,
    goal: &SessionGoal,
    phase: GoalPhase,
    reason: &str,
    now: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE goal_control_jobs SET state = 'cancelled', cancel_reason = ?1, updated_at = ?2
         WHERE goal_id = ?3 AND attempt_generation = ?4 AND state IN ('pending', 'leased')",
        params![reason, now, goal.id.to_string(), goal.attempt_generation],
    )?;
    conn.execute(
        "UPDATE session_goals SET disposition = 'infra_paused', phase = NULL, resume_phase = ?1,
                pause_reason = ?2,
                elapsed_active_ms = elapsed_active_ms + MAX(0, ?3 - COALESCE(active_since, ?3)) * 1000,
                active_since = NULL, updated_at = ?3 WHERE id = ?4 AND attempt_generation = ?5",
        params![
            phase.as_str(),
            reason,
            now,
            goal.id.to_string(),
            goal.attempt_generation
        ],
    )?;
    record_lifecycle_history(
        conn,
        goal.id,
        GoalLifecycleHistoryEntry {
            at: now,
            disposition: GoalDisposition::InfraPaused,
            phase: None,
            reason: Some(GoalPauseReason::parse(reason)?),
        },
    )?;
    Ok(())
}

fn register_verification_jobs(
    conn: &rusqlite::Connection,
    goal: &SessionGoal,
    evidence: &str,
    now: i64,
) -> Result<()> {
    let count = serde_json::from_str::<serde_json::Value>(&goal.resolved_policy_json)
        .ok()
        .and_then(|value| {
            value
                .get("coldSkepticCount")
                .and_then(serde_json::Value::as_u64)
        })
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(3)
        .clamp(1, 5);
    let gatekeepers = (!goal.unresolved_gaps.is_empty())
        .then_some((GoalControlRole::Gatekeeper, 0_i64))
        .into_iter();
    for (role, slot) in gatekeepers.chain((0..count).map(|slot| {
        (
            GoalControlRole::ColdSkeptic,
            i64::try_from(slot).unwrap_or(0),
        )
    })) {
        let request = serde_json::json!({
            "goal_id": goal.id,
            "attempt_generation": goal.attempt_generation,
            "role": role,
            "contract": goal.contract,
            "evaluator_evidence": evidence,
            "prior_unresolved_gaps": goal.unresolved_gaps,
            "tool_policy": "read_only_workspace",
            "instructions": "Inspect read-only and return only one JSON object. Uncertainty, missing evidence, or failed gates must refute.",
            "response_schema": [
                {"verdict":"approve", "evidence":"non-empty concrete evidence"},
                {"verdict":"refute", "findings":["specific sanitized finding"]}
            ]
        });
        conn.execute(
            "INSERT INTO goal_control_jobs
                (job_id, goal_id, attempt_generation, role, slot, request_json, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?7)",
            params![Uuid::new_v4().to_string(), goal.id.to_string(), goal.attempt_generation, role.as_str(), slot, request.to_string(), now],
        )?;
    }
    Ok(())
}

fn evaluator_request(
    goal: &SessionGoal,
    attempt_generation: i64,
    turn_id: Uuid,
    evidence: &str,
) -> serde_json::Value {
    serde_json::json!({
        "goal_id": goal.id,
        "attempt_generation": attempt_generation,
        "role": "evaluator",
        "tool_policy": "none",
        "objective": goal.objective,
        "immutable_contract": goal.contract,
        "root_turn": {"turn_id": turn_id, "result": "successful", "evidence": evidence},
        "unresolved_gaps": goal.unresolved_gaps,
        "instructions": "Return only one JSON object matching one response variant.",
        "response_schema": [
            {"decision":"continue", "next_step":"non-empty string"},
            {"decision":"candidate_complete", "evidence":"non-empty string"},
            {"decision":"blocked", "blocker_key":"stable non-empty key", "explanation":"non-empty string"}
        ]
    })
}

fn goal_max_verification_attempts(goal: &SessionGoal) -> u64 {
    serde_json::from_str::<serde_json::Value>(&goal.resolved_policy_json)
        .ok()
        .and_then(|value| {
            value
                .get("maxVerificationAttempts")
                .and_then(serde_json::Value::as_u64)
        })
        .unwrap_or(4)
}

fn apply_verification_if_terminal(
    conn: &rusqlite::Connection,
    goal: &SessionGoal,
    now: i64,
) -> Result<()> {
    let pending: i64 = conn.query_row(
        "SELECT COUNT(*) FROM goal_control_jobs WHERE goal_id = ?1 AND attempt_generation = ?2
         AND role IN ('gatekeeper', 'cold_skeptic') AND state IN ('pending', 'leased')",
        params![goal.id.to_string(), goal.attempt_generation],
        |row| row.get(0),
    )?;
    if pending != 0 {
        return Ok(());
    }
    let mut statement = conn.prepare(
        "SELECT role, result_json FROM goal_control_jobs WHERE goal_id = ?1 AND attempt_generation = ?2
         AND role IN ('gatekeeper', 'cold_skeptic') ORDER BY role, slot",
    )?;
    let rows = statement.query_map(
        params![goal.id.to_string(), goal.attempt_generation],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
    )?;
    let mut gatekeeper_refuted = false;
    let mut approvals = 0_usize;
    let mut cold_total = 0_usize;
    let mut findings = Vec::new();
    let prior_gap_fingerprints: std::collections::HashSet<String> = goal
        .unresolved_gaps
        .iter()
        .map(|finding| goal_gap_fingerprint(finding))
        .collect();
    for row in rows {
        let (role, raw) = row?;
        let verdict = raw
            .as_deref()
            .and_then(|raw| serde_json::from_str::<GoalSkepticVerdict>(raw).ok())
            .unwrap_or_else(|| GoalSkepticVerdict::Refute {
                findings: vec!["skeptic result unavailable or malformed".into()],
            });
        if role == "cold_skeptic" {
            cold_total += 1;
        }
        match verdict {
            GoalSkepticVerdict::Approve { .. } if role == "cold_skeptic" => approvals += 1,
            GoalSkepticVerdict::Refute {
                findings: row_findings,
            } => {
                if role == "gatekeeper" {
                    let replayed: Vec<String> = row_findings
                        .into_iter()
                        .map(|finding| sanitize_goal_finding(&finding))
                        .filter(|finding| {
                            finding == "skeptic result unavailable or malformed"
                                || prior_gap_fingerprints.contains(&goal_gap_fingerprint(finding))
                        })
                        .collect();
                    gatekeeper_refuted = !replayed.is_empty();
                    findings.extend(replayed);
                    continue;
                }
                findings.extend(
                    row_findings
                        .into_iter()
                        .map(|finding| sanitize_goal_finding(&finding)),
                );
            }
            _ => {}
        }
    }
    if !gatekeeper_refuted && approvals > cold_total / 2 {
        goal.transition(GoalLifecycleEvent::VerificationApproved)?;
        conn.execute(
            "UPDATE session_goals SET disposition = 'complete', phase = NULL, resume_phase = NULL,
                    verifier_outcome_json = ?1,
                    elapsed_active_ms = elapsed_active_ms + MAX(0, ?2 - COALESCE(active_since, ?2)) * 1000,
                    active_since = NULL, updated_at = ?2
             WHERE id = ?3 AND disposition = 'running' AND phase = 'verifying' AND attempt_generation = ?4",
            params![serde_json::json!({"approved": true, "cold_approvals": approvals, "cold_total": cold_total}).to_string(), now, goal.id.to_string(), goal.attempt_generation],
        )?;
        record_lifecycle_history(
            conn,
            goal.id,
            GoalLifecycleHistoryEntry {
                at: now,
                disposition: GoalDisposition::Complete,
                phase: None,
                reason: None,
            },
        )?;
        return Ok(());
    }
    findings.sort();
    findings.dedup();
    let mut fingerprints: Vec<String> = findings
        .iter()
        .map(|finding| goal_gap_fingerprint(finding))
        .collect();
    fingerprints.sort();
    let set_hash = goal_gap_fingerprint(&fingerprints.join("\n"));
    let repeated = !goal.gap_fingerprints.is_empty() && goal.gap_fingerprints == fingerprints;
    let max_attempts = goal_max_verification_attempts(goal);
    let pause_reason = if repeated {
        Some("repeated_gap_set")
    } else if u64::try_from(goal.verification_rounds).unwrap_or(u64::MAX) >= max_attempts {
        Some("verification_attempt_cap")
    } else {
        None
    };
    let findings_json = serde_json::to_string(&findings)?;
    let fingerprints_json = serde_json::to_string(&fingerprints)?;
    if let Some(reason) = pause_reason {
        goal.transition(if repeated {
            GoalLifecycleEvent::RepeatedGapSet
        } else {
            GoalLifecycleEvent::VerificationCap
        })?;
        conn.execute(
            "UPDATE session_goals SET disposition = 'no_progress_paused', phase = NULL,
                    resume_phase = 'executing', pause_reason = ?1, unresolved_gaps_json = ?2,
                    gap_fingerprints_json = ?3, previous_gap_set_hash = ?4, verifier_outcome_json = ?5,
                    elapsed_active_ms = elapsed_active_ms + MAX(0, ?6 - COALESCE(active_since, ?6)) * 1000,
                    active_since = NULL, updated_at = ?6 WHERE id = ?7 AND attempt_generation = ?8",
            params![reason, findings_json, fingerprints_json, set_hash, serde_json::json!({"approved": false}).to_string(), now, goal.id.to_string(), goal.attempt_generation],
        )?;
        record_lifecycle_history(
            conn,
            goal.id,
            GoalLifecycleHistoryEntry {
                at: now,
                disposition: GoalDisposition::NoProgressPaused,
                phase: None,
                reason: Some(GoalPauseReason::parse(reason)?),
            },
        )?;
    } else {
        let transition = goal.transition(GoalLifecycleEvent::VerificationRefuted)?;
        conn.execute(
            "UPDATE session_goals SET phase = 'executing', attempt_generation = ?1,
                    unresolved_gaps_json = ?2, gap_fingerprints_json = ?3,
                    previous_gap_set_hash = ?4, verifier_outcome_json = ?5,
                    updated_at = ?6 WHERE id = ?7 AND attempt_generation = ?8",
            params![
                transition.lifecycle.attempt_generation,
                findings_json,
                fingerprints_json,
                set_hash,
                serde_json::json!({"approved": false}).to_string(),
                now,
                goal.id.to_string(),
                goal.attempt_generation
            ],
        )?;
        record_lifecycle_history(
            conn,
            goal.id,
            GoalLifecycleHistoryEntry {
                at: now,
                disposition: GoalDisposition::Running,
                phase: Some(GoalPhase::Executing),
                reason: None,
            },
        )?;
    }
    Ok(())
}

fn clean_opt(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn floor_char_boundary(value: &str, mut index: usize) -> usize {
    index = index.min(value.len());
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn append_context(existing: Option<&str>, delta: Option<&str>) -> Option<String> {
    let delta = clean_opt(delta)?;
    match existing.map(str::trim).filter(|s| !s.is_empty()) {
        Some(existing) => Some(format!("{existing}\n\nUpdate:\n{delta}")),
        None => Some(delta),
    }
}

fn current_goal_required(conn: &rusqlite::Connection, session_id: Uuid) -> Result<SessionGoal> {
    let open_dispositiones = open_disposition_placeholders(2);
    let goal_params = bind_session_and_open_dispositiones(session_id.to_string());
    let goal_param_refs = param_refs(&goal_params);
    conn.query_row(
        &format!(
            "SELECT {GOAL_SELECT}
         FROM session_goals
         WHERE session_id = ?1
           AND disposition IN ({open_dispositiones})
         ORDER BY updated_at DESC
         LIMIT 1"
        ),
        goal_param_refs.as_slice(),
        decode_goal,
    )
    .optional()
    .context("loading open session goal")?
    .ok_or_else(|| anyhow::anyhow!("no open goal for this session"))
}

fn open_disposition_placeholders(start: usize) -> String {
    placeholders(start, OPEN_DISPOSITION_VALUES.len())
}

fn bind_session_and_open_dispositiones(session_id: String) -> Vec<Box<dyn rusqlite::ToSql>> {
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(session_id)];
    for disposition in OPEN_DISPOSITION_VALUES.iter() {
        params.push(Box::new(*disposition));
    }
    params
}

fn param_refs(params: &[Box<dyn rusqlite::ToSql>]) -> Vec<&dyn rusqlite::ToSql> {
    params.iter().map(|param| param.as_ref()).collect()
}

fn load_goal(conn: &rusqlite::Connection, session_id: Uuid, id: Uuid) -> Result<SessionGoal> {
    conn.query_row(
        &format!(
            "SELECT {GOAL_SELECT}
         FROM session_goals
         WHERE session_id = ?1 AND id = ?2"
        ),
        params![session_id.to_string(), id.to_string()],
        decode_goal,
    )
    .context("loading session goal")
}

fn decode_goal(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionGoal> {
    let id: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let disposition: String = row.get(5)?;
    let phase: Option<String> = row.get(6)?;
    let resume_phase: Option<String> = row.get(7)?;
    let pause_reason: Option<String> = row.get(8)?;
    let contract: Option<String> = row.get(10)?;
    let unresolved_gaps: String = row.get(14)?;
    let gap_fingerprints: String = row.get(15)?;
    let lifecycle_history: String = row.get(22)?;
    let disposition_value = GoalDisposition::parse(&disposition).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, e.into())
    })?;
    let active_since: Option<i64> = row.get(21)?;
    let persisted_elapsed: i64 = row.get(20)?;
    let elapsed_active_ms = if disposition_value == GoalDisposition::Running {
        persisted_elapsed.saturating_add(
            Utc::now()
                .timestamp()
                .saturating_sub(active_since.unwrap_or_else(|| row.get(29).unwrap_or_default()))
                .saturating_mul(1_000),
        )
    } else {
        persisted_elapsed
    };
    Ok(SessionGoal {
        id: Uuid::parse_str(&id).map_err(decode_err)?,
        session_id: Uuid::parse_str(&session_id).map_err(decode_err)?,
        project_id: row.get(2)?,
        objective: row.get(3)?,
        context: row.get(4)?,
        disposition: disposition_value,
        phase: phase
            .map(|value| GoalPhase::parse(&value).map_err(decode_anyhow_err))
            .transpose()?,
        resume_phase: resume_phase
            .map(|value| GoalPhase::parse(&value).map_err(decode_anyhow_err))
            .transpose()?,
        pause_reason: pause_reason
            .map(|value| GoalPauseReason::parse(&value).map_err(decode_anyhow_err))
            .transpose()?,
        attempt_generation: row.get(9)?,
        contract: contract
            .map(|value| serde_json::from_str(&value).map_err(decode_err))
            .transpose()?,
        resolved_policy_json: row.get(11)?,
        evaluator_outcome_json: row.get(12)?,
        verifier_outcome_json: row.get(13)?,
        unresolved_gaps: serde_json::from_str(&unresolved_gaps).map_err(decode_err)?,
        gap_fingerprints: serde_json::from_str(&gap_fingerprints).map_err(decode_err)?,
        blocker_key: row.get(16)?,
        blocker_key_streak: row.get(17)?,
        token_budget: row.get(18)?,
        tokens_used: row.get(19)?,
        elapsed_active_ms,
        active_since,
        lifecycle_history: serde_json::from_str(&lifecycle_history).map_err(decode_err)?,
        blocked_attempts: row.get(23)?,
        completion_evidence: row.get(24)?,
        verification_rounds: row.get(25)?,
        last_read_at: row.get(26)?,
        cleared_at: row.get(27)?,
        created_at: row.get(28)?,
        updated_at: row.get(29)?,
    })
}

fn decode_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
}

fn decode_anyhow_err(error: anyhow::Error) -> rusqlite::Error {
    decode_err(std::io::Error::other(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> GoalContract {
        GoalContract {
            kind: "implementation".into(),
            acceptance: vec!["observable outcome".into()],
            verification_gates: vec!["tests pass".into()],
            evidence_collection: vec!["inspect diff".into()],
            non_goals: vec!["unrelated work".into()],
            assumed_scope: vec!["workspace".into()],
            implementation_checklist: vec!["implement".into()],
        }
    }

    #[test]
    fn goal_contract_baseline_rejects_criterion_weakening() {
        let baseline = contract();
        let mut weakened = baseline.clone();
        weakened.acceptance.clear();
        assert!(baseline.with_guidance_from(&weakened).is_err());
    }

    #[test]
    fn goal_contract_checklist_is_non_authoritative() {
        let baseline = contract();
        let mut advice = baseline.clone();
        advice.implementation_checklist = vec!["different strategy".into()];
        assert_eq!(
            baseline
                .with_guidance_from(&advice)
                .unwrap()
                .implementation_checklist,
            advice.implementation_checklist
        );
    }

    #[test]
    fn goal_contract_rejects_unbounded_planner_output() {
        let mut oversized = contract();
        oversized.acceptance = vec!["x".repeat(4_097)];
        assert!(oversized.validate().is_err());

        let mut too_many = contract();
        too_many.non_goals = (0..33).map(|index| format!("non-goal {index}")).collect();
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn goal_control_results_require_bounded_nonempty_semantics() {
        assert!(
            GoalEvaluatorDecision::CandidateComplete {
                evidence: String::new(),
            }
            .validate()
            .is_err()
        );
        assert!(
            GoalEvaluatorDecision::Blocked {
                blocker_key: "key".into(),
                explanation: " ".into(),
            }
            .validate()
            .is_err()
        );
        assert!(
            GoalSkepticVerdict::Approve {
                evidence: String::new(),
            }
            .validate()
            .is_err()
        );
        assert!(
            GoalSkepticVerdict::Refute {
                findings: vec!["x".repeat(MAX_GOAL_CONTROL_FIELD_CHARS + 1)],
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn goal_lifecycle_transition_table_is_exhaustive() {
        let planning = GoalLifecycle::new();
        let executing = planning
            .apply(GoalLifecycleEvent::PlannerAccepted)
            .unwrap()
            .lifecycle;
        assert_eq!(executing.phase, Some(GoalPhase::Executing));
        let evaluating = executing
            .apply(GoalLifecycleEvent::RootSucceeded)
            .unwrap()
            .lifecycle;
        let verifying = evaluating
            .apply(GoalLifecycleEvent::EvaluatorCandidateComplete)
            .unwrap()
            .lifecycle;
        let complete = verifying
            .apply(GoalLifecycleEvent::VerificationApproved)
            .unwrap()
            .lifecycle;
        assert_eq!(complete.disposition, GoalDisposition::Complete);
        assert!(complete.apply(GoalLifecycleEvent::UserResume).is_err());

        for disposition in GoalDisposition::ALL {
            assert_eq!(disposition.is_open(), !disposition.is_terminal());
        }
        for phase in GoalPhase::ALL {
            let running = GoalLifecycle {
                disposition: GoalDisposition::Running,
                phase: Some(phase),
                resume_phase: None,
                attempt_generation: 7,
            };
            let paused = running
                .apply(GoalLifecycleEvent::UserPause)
                .unwrap()
                .lifecycle;
            assert_eq!(paused.resume_phase, Some(phase));
            let resumed = paused
                .apply(GoalLifecycleEvent::UserResume)
                .unwrap()
                .lifecycle;
            assert_eq!(resumed.phase, Some(phase));
            assert_eq!(resumed.attempt_generation, 8);
        }
    }

    #[tokio::test]
    async fn goal_status_parse_rejects_draft() {
        assert!(GoalDisposition::parse("draft").is_err());
    }

    #[tokio::test]
    async fn db_async_delegation_goals_roundtrip_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("p", "/tmp/goal-test", "Build")
            .await
            .unwrap();
        let goal = db
            .create_session_goal(
                session.session_id,
                &session.project_id,
                "ship async goals",
                None,
                Some(100),
            )
            .await
            .unwrap();
        assert_eq!(goal.disposition, GoalDisposition::Running);

        db.set_session_goal_status(session.session_id, GoalDisposition::UserPaused)
            .await
            .unwrap();
        let current = db
            .current_session_goal(session.session_id, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.objective, "ship async goals");
        assert_eq!(current.disposition, GoalDisposition::UserPaused);
        assert!(current.last_read_at.is_some());
    }

    #[tokio::test]
    async fn blocked_requires_three_attempts() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("p", "/tmp/goal-test", "Build")
            .await
            .unwrap();
        db.create_session_goal(
            session.session_id,
            &session.project_id,
            "ship feature",
            None,
            None,
        )
        .await
        .unwrap();
        for expected in 1..BLOCK_ATTEMPTS_REQUIRED {
            let out = db
                .update_session_goal(
                    session.session_id,
                    GoalDisposition::Blocked,
                    None,
                    Some("waiting"),
                    None,
                )
                .await
                .unwrap();
            assert!(
                matches!(out, GoalUpdateOutcome::BlockAttempt { attempts, .. } if attempts == expected)
            );
        }
        let out = db
            .update_session_goal(
                session.session_id,
                GoalDisposition::Blocked,
                None,
                Some("waiting"),
                None,
            )
            .await
            .unwrap();
        let GoalUpdateOutcome::Updated(blocked) = out else {
            panic!("third blocker update must transition the goal")
        };
        assert_eq!(blocked.disposition, GoalDisposition::Blocked);
        assert!(blocked.active_since.is_none());
        assert_eq!(
            blocked
                .lifecycle_history
                .last()
                .map(|entry| entry.disposition),
            Some(GoalDisposition::Blocked)
        );
    }

    #[tokio::test]
    async fn second_open_goal_is_rejected() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("p", "/tmp/goal-test", "Build")
            .await
            .unwrap();
        db.create_session_goal(
            session.session_id,
            &session.project_id,
            "first goal",
            None,
            None,
        )
        .await
        .unwrap();

        let err = db
            .create_session_goal(
                session.session_id,
                &session.project_id,
                "second goal",
                None,
                None,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("open goal"));
    }

    async fn planning_fixture() -> (Db, SessionGoal, GoalControlJob) {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("p", "/tmp/goal-supervision", "Build")
            .await
            .unwrap();
        let goal = db
            .create_session_goal(
                session.session_id,
                &session.project_id,
                "ship",
                None,
                Some(1000),
            )
            .await
            .unwrap();
        let job = db
            .lease_goal_control_job(goal.id, goal.attempt_generation, Utc::now().timestamp(), 60)
            .await
            .unwrap()
            .unwrap();
        (db, goal, job)
    }

    fn inference_row(
        goal: &SessionGoal,
        tokens: i64,
    ) -> crate::db::inference_calls::InferenceCallRow {
        crate::db::inference_calls::InferenceCallRow {
            call_id: Uuid::new_v4(),
            session_id: goal.session_id,
            project_id: goal.project_id.clone(),
            project_root: "/tmp/goal-supervision".into(),
            model: "test".into(),
            provider: "test".into(),
            timestamp: Utc::now().timestamp(),
            input_tokens: tokens,
            output_tokens: 0,
            cached_input_tokens: 0,
            cache_creation_input_tokens: 0,
            cost_usd_micros: None,
            is_utility: false,
        }
    }

    #[tokio::test]
    async fn goal_usage_detects_counter_reset_with_new_tokens_before_next_refresh() {
        let (db, goal, _) = planning_fixture().await;
        db.insert_inference_call(&inference_row(&goal, 10))
            .await
            .unwrap();
        db.refresh_session_goal_usage(goal.session_id)
            .await
            .unwrap();
        assert_eq!(
            db.current_session_goal(goal.session_id, false)
                .await
                .unwrap()
                .unwrap()
                .tokens_used,
            10
        );

        let session_id = goal.session_id;
        db.write(move |conn| {
            conn.execute(
                "DELETE FROM inference_calls WHERE session_id = ?1",
                params![session_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        db.insert_inference_call(&inference_row(&goal, 4))
            .await
            .unwrap();
        // The append itself is the durable accounting boundary; no refresh
        // occurs between the reset and this assertion.
        assert_eq!(
            db.current_session_goal(goal.session_id, false)
                .await
                .unwrap()
                .unwrap()
                .tokens_used,
            14
        );
        db.refresh_session_goal_usage(goal.session_id)
            .await
            .unwrap();
        assert_eq!(
            db.current_session_goal(goal.session_id, false)
                .await
                .unwrap()
                .unwrap()
                .tokens_used,
            14
        );
    }

    #[tokio::test]
    async fn operator_disable_sweep_is_transactional_and_includes_detached_sessions() {
        let db = Db::open_in_memory().unwrap();
        let first = db.create_session("p", "/tmp/a", "Build").await.unwrap();
        let second = db.create_session("p", "/tmp/b", "Build").await.unwrap();
        let first_goal = db
            .create_session_goal(first.session_id, "p", "a", None, Some(10))
            .await
            .unwrap();
        let second_goal = db
            .create_session_goal(second.session_id, "p", "b", None, Some(10))
            .await
            .unwrap();
        assert_eq!(db.pause_all_goals_for_operator_disable().await.unwrap(), 2);
        for goal in [first_goal, second_goal] {
            let paused = db
                .current_session_goal(goal.session_id, false)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(paused.disposition, GoalDisposition::UserPaused);
            assert_eq!(paused.pause_reason, Some(GoalPauseReason::OperatorDisabled));
            assert!(paused.active_since.is_none());
        }
    }

    #[tokio::test]
    async fn lifecycle_history_is_bounded_and_elapsed_survives_pause_resume() {
        let (db, goal, _) = planning_fixture().await;
        for _ in 0..20 {
            db.set_session_goal_status(goal.session_id, GoalDisposition::UserPaused)
                .await
                .unwrap();
            db.set_session_goal_status(goal.session_id, GoalDisposition::Running)
                .await
                .unwrap();
        }
        let current = db
            .current_session_goal(goal.session_id, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.lifecycle_history.len(), MAX_GOAL_LIFECYCLE_HISTORY);
        assert!(current.active_since.is_some());
        assert!(current.elapsed_active_ms >= 0);
    }

    #[tokio::test]
    async fn goal_planning_requires_valid_contract() {
        let (db, goal, job) = planning_fixture().await;
        let raw = serde_json::to_string(&contract()).unwrap();
        let updated = db
            .finish_goal_control_job(job, Ok(&raw))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (updated.disposition, updated.phase),
            (GoalDisposition::Running, Some(GoalPhase::Executing))
        );
        assert_eq!(updated.contract, Some(contract()));
        assert_eq!(updated.id, goal.id);
    }

    #[tokio::test]
    async fn goal_planner_failure_pauses_resumably() {
        let (db, _, job) = planning_fixture().await;
        let updated = db
            .finish_goal_control_job(job, Ok("not json"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.disposition, GoalDisposition::InfraPaused);
        assert_eq!(updated.resume_phase, Some(GoalPhase::Planning));
        assert_eq!(updated.pause_reason, Some(GoalPauseReason::PlannerFailure));
    }

    #[test]
    fn goal_control_job_enforces_closed_role_rosters() {
        assert_eq!(GoalControlRole::ALL.len(), 4);
        assert!(GoalControlRole::parse("scout").is_err());
    }

    #[test]
    fn goal_compaction_snapshot_is_bounded_and_side_effect_free() {
        let goal = SessionGoal {
            id: Uuid::nil(),
            session_id: Uuid::nil(),
            project_id: "p".into(),
            objective: "x".repeat(1000),
            context: None,
            disposition: GoalDisposition::Running,
            phase: Some(GoalPhase::Executing),
            resume_phase: None,
            pause_reason: None,
            attempt_generation: 1,
            contract: None,
            resolved_policy_json: "{}".into(),
            evaluator_outcome_json: None,
            verifier_outcome_json: None,
            unresolved_gaps: vec!["gap".into()],
            gap_fingerprints: vec![],
            blocker_key: None,
            blocker_key_streak: 0,
            token_budget: 100,
            tokens_used: 1,
            elapsed_active_ms: 0,
            active_since: Some(0),
            lifecycle_history: vec![],
            blocked_attempts: 0,
            completion_evidence: None,
            verification_rounds: 0,
            last_read_at: None,
            cleared_at: None,
            created_at: 0,
            updated_at: 0,
        };
        let before = goal.clone();
        let snapshot = goal.compaction_snapshot();
        assert!(snapshot.objective.len() <= 512);
        assert_eq!(goal, before);
    }

    async fn evaluator_fixture() -> (Db, SessionGoal, GoalControlJob) {
        let (db, _, planner) = planning_fixture().await;
        let raw = serde_json::to_string(&contract()).unwrap();
        let executing = db
            .finish_goal_control_job(planner, Ok(&raw))
            .await
            .unwrap()
            .unwrap();
        let turn = db
            .begin_goal_root_turn(executing.id, executing.attempt_generation)
            .await
            .unwrap();
        let evaluating = db
            .finish_goal_root_turn(executing.id, executing.attempt_generation, turn)
            .await
            .unwrap()
            .unwrap();
        let job = db
            .lease_goal_control_job(
                evaluating.id,
                evaluating.attempt_generation,
                Utc::now().timestamp(),
                60,
            )
            .await
            .unwrap()
            .unwrap();
        (db, evaluating, job)
    }

    #[tokio::test]
    async fn goal_evaluator_drives_turn_outcomes() {
        let (db, _, job) = evaluator_fixture().await;
        let updated = db
            .finish_goal_control_job(
                job,
                Ok(r#"{"decision":"continue","next_step":"inspect output"}"#),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.phase, Some(GoalPhase::Executing));
        assert!(
            updated
                .evaluator_outcome_json
                .as_deref()
                .is_some_and(|json| json.contains("inspect output"))
        );
    }

    #[tokio::test]
    async fn resumed_evaluator_replays_durable_root_turn_evidence() {
        let (db, evaluating, _) = evaluator_fixture().await;
        db.set_session_goal_status(evaluating.session_id, GoalDisposition::UserPaused)
            .await
            .unwrap();
        let resumed = db
            .set_session_goal_status(evaluating.session_id, GoalDisposition::Running)
            .await
            .unwrap();
        let job = db
            .lease_goal_control_job(
                resumed.id,
                resumed.attempt_generation,
                Utc::now().timestamp(),
                60,
            )
            .await
            .unwrap()
            .unwrap();
        let request: serde_json::Value = serde_json::from_str(&job.request_json).unwrap();
        assert_eq!(request["root_turn"]["result"], "successful");
        assert_eq!(
            request["root_turn"]["evidence"],
            "host-observed successful root turn"
        );
        assert!(request["root_turn"]["turn_id"].as_str().is_some());
    }

    #[tokio::test]
    async fn resumed_verification_replacement_counts_as_a_started_panel() {
        let (db, verifying, _) = verification_fixture().await;
        assert_eq!(verifying.verification_rounds, 1);
        db.set_session_goal_status(verifying.session_id, GoalDisposition::UserPaused)
            .await
            .unwrap();
        let resumed = db
            .set_session_goal_status(verifying.session_id, GoalDisposition::Running)
            .await
            .unwrap();
        assert_eq!(resumed.phase, Some(GoalPhase::Verifying));
        assert_eq!(resumed.verification_rounds, 2);
        assert!(
            db.lease_goal_control_job(
                resumed.id,
                resumed.attempt_generation,
                Utc::now().timestamp(),
                60,
            )
            .await
            .unwrap()
            .is_some()
        );
    }

    #[tokio::test]
    async fn resumed_verification_does_not_start_a_panel_past_the_inclusive_cap() {
        let (db, verifying, _) = verification_fixture().await;
        let goal_id = verifying.id;
        db.write(move |conn| {
            conn.execute(
                "UPDATE session_goals SET verification_rounds = 4 WHERE id = ?1",
                params![goal_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        db.set_session_goal_status(verifying.session_id, GoalDisposition::UserPaused)
            .await
            .unwrap();
        let capped = db
            .set_session_goal_status(verifying.session_id, GoalDisposition::Running)
            .await
            .unwrap();
        assert_eq!(capped.disposition, GoalDisposition::NoProgressPaused);
        assert_eq!(capped.verification_rounds, 4);
        assert_eq!(
            capped.pause_reason,
            Some(GoalPauseReason::VerificationAttemptCap)
        );
        assert!(
            db.lease_goal_control_job(
                capped.id,
                capped.attempt_generation,
                Utc::now().timestamp(),
                60,
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    #[tokio::test]
    async fn goal_evaluator_failure_never_falls_back_to_model_completion() {
        let (db, _, job) = evaluator_fixture().await;
        let updated = db
            .finish_goal_control_job(job, Ok("malformed"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.disposition, GoalDisposition::InfraPaused);
        assert_eq!(
            updated.pause_reason,
            Some(GoalPauseReason::EvaluatorFailure)
        );
        assert_eq!(updated.resume_phase, Some(GoalPhase::Evaluating));
    }

    #[tokio::test]
    async fn goal_late_control_result_is_ignored_for_non_running_goal() {
        let (db, evaluating, job) = evaluator_fixture().await;
        db.set_session_goal_status(evaluating.session_id, GoalDisposition::UserPaused)
            .await
            .unwrap();
        assert!(
            db.finish_goal_control_job(
                job,
                Ok(r#"{"decision":"candidate_complete","evidence":"stale"}"#),
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    #[tokio::test]
    async fn goal_root_failure_infra_pauses_without_continuation() {
        let (db, _, planner) = planning_fixture().await;
        let raw = serde_json::to_string(&contract()).unwrap();
        let executing = db
            .finish_goal_control_job(planner, Ok(&raw))
            .await
            .unwrap()
            .unwrap();
        let turn = db
            .begin_goal_root_turn(executing.id, executing.attempt_generation)
            .await
            .unwrap();
        assert!(
            db.fail_goal_root_turn(executing.id, executing.attempt_generation, turn)
                .await
                .unwrap()
        );
        let paused = db
            .current_session_goal(executing.session_id, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(paused.disposition, GoalDisposition::InfraPaused);
        assert_eq!(paused.pause_reason, Some(GoalPauseReason::RootTurnFailure));
        assert!(paused.active_since.is_none());
        assert_eq!(
            paused.lifecycle_history.last(),
            Some(&GoalLifecycleHistoryEntry {
                at: paused.updated_at,
                disposition: GoalDisposition::InfraPaused,
                phase: None,
                reason: Some(GoalPauseReason::RootTurnFailure),
            })
        );
    }

    #[tokio::test]
    async fn goal_cleared_tombstone_retains_for_30_days_then_purges_without_jobs() {
        let (db, goal, _) = planning_fixture().await;
        assert!(db.clear_session_goal(goal.session_id).await.unwrap());
        let now = Utc::now().timestamp();
        db.write(move |conn| {
            conn.execute(
                "UPDATE session_goals SET cleared_at = ?1 WHERE id = ?2",
                params![now - 31 * 86_400, goal.id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(db.purge_cleared_goal_tombstones(now).await.unwrap(), 1);
    }

    async fn verification_fixture() -> (Db, SessionGoal, Vec<GoalControlJob>) {
        let (db, _, evaluator) = evaluator_fixture().await;
        let verifying = db
            .finish_goal_control_job(
                evaluator,
                Ok(r#"{"decision":"candidate_complete","evidence":"tests pass"}"#),
            )
            .await
            .unwrap()
            .unwrap();
        let mut jobs = Vec::new();
        while let Some(job) = db
            .lease_goal_control_job(
                verifying.id,
                verifying.attempt_generation,
                Utc::now().timestamp(),
                60,
            )
            .await
            .unwrap()
        {
            jobs.push(job);
        }
        (db, verifying, jobs)
    }

    #[tokio::test]
    async fn goal_cold_panel_is_completion_authority() {
        let (db, verifying, jobs) = verification_fixture().await;
        assert!(!jobs.is_empty());
        assert_eq!(
            jobs.iter()
                .filter(|job| job.role == GoalControlRole::Gatekeeper)
                .count(),
            0,
            "an initial candidate has no unresolved gaps for the resumed-gap gatekeeper"
        );
        assert!(
            jobs.iter()
                .any(|job| job.role == GoalControlRole::ColdSkeptic)
        );
        let mut last = None;
        for job in jobs {
            last = db
                .finish_goal_control_job(job, Ok(r#"{"verdict":"approve","evidence":"verified"}"#))
                .await
                .unwrap();
        }
        let complete = last.unwrap();
        assert_eq!(complete.id, verifying.id);
        assert_eq!(complete.disposition, GoalDisposition::Complete);
    }

    #[tokio::test]
    async fn goal_malformed_skeptic_verdict_refutes() {
        let (db, verifying, jobs) = verification_fixture().await;
        for (index, job) in jobs.into_iter().enumerate() {
            db.finish_goal_control_job(
                job,
                if index < 2 {
                    Ok("malformed")
                } else {
                    Ok(r#"{"verdict":"approve","evidence":"verified"}"#)
                },
            )
            .await
            .unwrap();
        }
        let goal = db
            .current_session_goal(verifying.session_id, false)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(goal.disposition, GoalDisposition::Complete);
        assert!(!goal.unresolved_gaps.is_empty());
    }

    #[tokio::test]
    async fn goal_supervision_resolution_and_reload_pauses_open_goals() {
        let (db, goal, _) = planning_fixture().await;
        let paused = db
            .pause_open_goal_for_operator_disable(goal.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(paused.disposition, GoalDisposition::UserPaused);
        assert_eq!(paused.resume_phase, Some(GoalPhase::Planning));
        assert_eq!(paused.pause_reason, Some(GoalPauseReason::OperatorDisabled));
    }

    #[tokio::test]
    async fn goal_supervision_reenable_does_not_resume_existing_goal() {
        let (db, goal, _) = planning_fixture().await;
        db.pause_open_goal_for_operator_disable(goal.session_id)
            .await
            .unwrap();
        let still_paused = db
            .current_session_goal(goal.session_id, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(still_paused.disposition, GoalDisposition::UserPaused);
        assert_eq!(
            still_paused.pause_reason,
            Some(GoalPauseReason::OperatorDisabled)
        );
    }

    #[tokio::test]
    async fn goal_evaluator_blocker_key_requires_three_consecutive_matches() {
        let (db, _, mut evaluator) = evaluator_fixture().await;
        for expected in 1..=3 {
            let updated = db
                .finish_goal_control_job(
                    evaluator.clone(),
                    Ok(r#"{"decision":"blocked","blocker_key":"same","explanation":"waiting"}"#),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(updated.blocker_key_streak, expected);
            if expected < 3 {
                assert_eq!(updated.disposition, GoalDisposition::Running);
                let turn = db
                    .begin_goal_root_turn(updated.id, updated.attempt_generation)
                    .await
                    .unwrap();
                let evaluating = db
                    .finish_goal_root_turn(updated.id, updated.attempt_generation, turn)
                    .await
                    .unwrap()
                    .unwrap();
                evaluator = db
                    .lease_goal_control_job(
                        evaluating.id,
                        evaluating.attempt_generation,
                        Utc::now().timestamp(),
                        60,
                    )
                    .await
                    .unwrap()
                    .unwrap();
            } else {
                assert_eq!(updated.disposition, GoalDisposition::Blocked);
                assert!(updated.active_since.is_none());
                assert_eq!(
                    updated
                        .lifecycle_history
                        .last()
                        .map(|entry| entry.disposition),
                    Some(GoalDisposition::Blocked)
                );
            }
        }
    }

    #[tokio::test]
    async fn goal_root_turn_result_is_ignored_after_non_running_transition() {
        let (db, _, planner) = planning_fixture().await;
        let raw = serde_json::to_string(&contract()).unwrap();
        let executing = db
            .finish_goal_control_job(planner, Ok(&raw))
            .await
            .unwrap()
            .unwrap();
        let turn = db
            .begin_goal_root_turn(executing.id, executing.attempt_generation)
            .await
            .unwrap();
        db.set_session_goal_status(executing.session_id, GoalDisposition::UserPaused)
            .await
            .unwrap();
        assert!(
            db.finish_goal_root_turn(executing.id, executing.attempt_generation, turn)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn goal_restore_demotes_inflight_phase_to_user_paused() {
        let (db, goal, _) = planning_fixture().await;
        let restored = db
            .restore_supervised_goals(goal.session_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.disposition, GoalDisposition::UserPaused);
        assert_eq!(restored.resume_phase, Some(GoalPhase::Planning));
        assert_eq!(restored.pause_reason, Some(GoalPauseReason::Restart));
    }

    async fn finish_verification_with_refutation(
        db: &Db,
        jobs: Vec<GoalControlJob>,
        finding: &str,
    ) -> SessionGoal {
        let refutation = serde_json::json!({"verdict":"refute", "findings":[finding]}).to_string();
        let mut last = None;
        for job in jobs {
            last = db
                .finish_goal_control_job(job, Ok(&refutation))
                .await
                .unwrap();
        }
        last.unwrap()
    }

    async fn start_next_verification(
        db: &Db,
        executing: &SessionGoal,
    ) -> (SessionGoal, Vec<GoalControlJob>) {
        let turn = db
            .begin_goal_root_turn(executing.id, executing.attempt_generation)
            .await
            .unwrap();
        let evaluating = db
            .finish_goal_root_turn(executing.id, executing.attempt_generation, turn)
            .await
            .unwrap()
            .unwrap();
        let evaluator = db
            .lease_goal_control_job(
                evaluating.id,
                evaluating.attempt_generation,
                Utc::now().timestamp(),
                60,
            )
            .await
            .unwrap()
            .unwrap();
        let verifying = db
            .finish_goal_control_job(
                evaluator,
                Ok(r#"{"decision":"candidate_complete","evidence":"retry"}"#),
            )
            .await
            .unwrap()
            .unwrap();
        let mut jobs = Vec::new();
        while let Some(job) = db
            .lease_goal_control_job(
                verifying.id,
                verifying.attempt_generation,
                Utc::now().timestamp(),
                60,
            )
            .await
            .unwrap()
        {
            jobs.push(job);
        }
        (verifying, jobs)
    }

    #[tokio::test]
    async fn goal_verification_replays_unresolved_gaps() {
        let (db, _, jobs) = verification_fixture().await;
        let executing = finish_verification_with_refutation(&db, jobs, "missing evidence").await;
        let (_, next_jobs) = start_next_verification(&db, &executing).await;
        assert!(next_jobs.iter().any(|job| {
            job.role == GoalControlRole::Gatekeeper && job.request_json.contains("missing evidence")
        }));
    }

    #[tokio::test]
    async fn goal_repeated_gap_set_pauses_on_second_occurrence() {
        let (db, _, jobs) = verification_fixture().await;
        let executing = finish_verification_with_refutation(&db, jobs, "same gap").await;
        let (_, jobs) = start_next_verification(&db, &executing).await;
        let paused = finish_verification_with_refutation(&db, jobs, "same gap").await;
        assert_eq!(paused.disposition, GoalDisposition::NoProgressPaused);
        assert_eq!(paused.pause_reason, Some(GoalPauseReason::RepeatedGapSet));
    }

    #[tokio::test]
    async fn goal_identical_gap_set_pauses_before_verification_cap() {
        let (db, _, jobs) = verification_fixture().await;
        let executing = finish_verification_with_refutation(&db, jobs, "same gap").await;
        let (_, jobs) = start_next_verification(&db, &executing).await;
        let paused = finish_verification_with_refutation(&db, jobs, "same gap").await;
        assert_eq!(paused.pause_reason, Some(GoalPauseReason::RepeatedGapSet));
        assert!(paused.verification_rounds < 4);
    }

    #[tokio::test]
    async fn goal_new_gap_set_resets_stall_counter() {
        let (db, _, jobs) = verification_fixture().await;
        let executing = finish_verification_with_refutation(&db, jobs, "first gap").await;
        let (_, jobs) = start_next_verification(&db, &executing).await;
        let executing = finish_verification_with_refutation(&db, jobs, "different gap").await;
        assert_eq!(executing.disposition, GoalDisposition::Running);
        assert_eq!(executing.phase, Some(GoalPhase::Executing));
    }

    #[tokio::test]
    async fn goal_gatekeeper_cannot_approve_completion() {
        let (db, _, jobs) = verification_fixture().await;
        let executing = finish_verification_with_refutation(&db, jobs, "first gap").await;
        let (_, jobs) = start_next_verification(&db, &executing).await;
        let mut last = None;
        for job in jobs {
            let verdict = if job.role == GoalControlRole::Gatekeeper {
                r#"{"verdict":"approve","evidence":"gap resolved"}"#
            } else {
                r#"{"verdict":"refute","findings":["cold refutation"]}"#
            };
            last = db.finish_goal_control_job(job, Ok(verdict)).await.unwrap();
        }
        assert_ne!(last.unwrap().disposition, GoalDisposition::Complete);
    }

    #[tokio::test]
    async fn goal_verification_attempt_cap_is_inclusive_and_pauses() {
        let (db, _, jobs) = verification_fixture().await;
        let mut goal = finish_verification_with_refutation(&db, jobs, "gap one").await;
        for finding in ["gap two", "gap three", "gap four"] {
            let (_, jobs) = start_next_verification(&db, &goal).await;
            goal = finish_verification_with_refutation(&db, jobs, finding).await;
        }
        assert_eq!(goal.verification_rounds, 4);
        assert_eq!(goal.disposition, GoalDisposition::NoProgressPaused);
        assert_eq!(
            goal.pause_reason,
            Some(GoalPauseReason::VerificationAttemptCap)
        );
    }

    async fn control_job_state(db: &Db, goal_id: Uuid) -> String {
        db.read(move |conn| {
            conn.query_row(
                "SELECT state FROM goal_control_jobs WHERE goal_id = ?1 LIMIT 1",
                params![goal_id.to_string()],
                |row| row.get(0),
            )
            .map_err(Into::into)
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn goal_control_outbox_recovers_prelease_crash() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("p", "/tmp/goal-supervision", "Build")
            .await
            .unwrap();
        let goal = db
            .create_session_goal(
                session.session_id,
                &session.project_id,
                "ship",
                None,
                Some(1000),
            )
            .await
            .unwrap();
        db.restore_supervised_goals(goal.session_id).await.unwrap();
        assert_eq!(control_job_state(&db, goal.id).await, "cancelled");
    }

    #[tokio::test]
    async fn goal_control_outbox_recovers_postlease_crash() {
        let (db, goal, _leased) = planning_fixture().await;
        db.restore_supervised_goals(goal.session_id).await.unwrap();
        assert_eq!(control_job_state(&db, goal.id).await, "cancelled");
    }

    #[tokio::test]
    async fn goal_tombstone_cleanup_waits_for_registered_job_and_retires_terminal_audit_rows() {
        let (db, goal, _) = planning_fixture().await;
        db.clear_session_goal(goal.session_id).await.unwrap();
        let now = Utc::now().timestamp();
        let id = goal.id;
        db.write(move |conn| {
            conn.execute(
                "UPDATE session_goals SET cleared_at = ?1 WHERE id = ?2",
                params![now - 31 * 86_400, id.to_string()],
            )?;
            conn.execute(
                "UPDATE goal_control_jobs SET state = 'pending' WHERE goal_id = ?1",
                params![id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(db.purge_cleared_goal_tombstones(now).await.unwrap(), 0);
        db.write(move |conn| {
            conn.execute(
                "UPDATE goal_control_jobs SET state = 'cancelled' WHERE goal_id = ?1",
                params![id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(db.purge_cleared_goal_tombstones(now).await.unwrap(), 1);
        assert!(
            db.read(move |conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM goal_control_jobs WHERE goal_id = ?1",
                    params![id.to_string()],
                    |row| row.get(0),
                )?;
                Ok(count == 0)
            })
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn goal_late_result_for_expired_or_deleted_id_is_rejected() {
        let (db, goal, job) = planning_fixture().await;
        db.clear_session_goal(goal.session_id).await.unwrap();
        let now = Utc::now().timestamp();
        let id = goal.id;
        db.write(move |conn| {
            conn.execute(
                "UPDATE session_goals SET cleared_at = ?1 WHERE id = ?2",
                params![now - 31 * 86_400, id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            db.finish_goal_control_job(job.clone(), Ok("{}"))
                .await
                .unwrap()
                .is_none()
        );
        db.purge_cleared_goal_tombstones(now).await.unwrap();
        assert!(
            db.finish_goal_control_job(job, Ok("{}"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn goal_user_cancel_pauses_without_evaluation() {
        let (db, _, planner) = planning_fixture().await;
        let raw = serde_json::to_string(&contract()).unwrap();
        let executing = db
            .finish_goal_control_job(planner, Ok(&raw))
            .await
            .unwrap()
            .unwrap();
        let turn = db
            .begin_goal_root_turn(executing.id, executing.attempt_generation)
            .await
            .unwrap();
        db.cancel_goal_root_turn_for_user(executing.id, executing.attempt_generation, turn)
            .await
            .unwrap();
        let paused = db
            .current_session_goal(executing.session_id, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(paused.disposition, GoalDisposition::UserPaused);
        assert_eq!(paused.pause_reason, Some(GoalPauseReason::User));
        assert!(paused.active_since.is_none());
        assert_eq!(
            paused
                .lifecycle_history
                .last()
                .map(|entry| (entry.disposition, entry.reason.clone())),
            Some((GoalDisposition::UserPaused, Some(GoalPauseReason::User)))
        );
    }

    #[tokio::test]
    async fn goal_approval_blocked_turn_skips_evaluation_and_continuation() {
        let (db, _, planner) = planning_fixture().await;
        let raw = serde_json::to_string(&contract()).unwrap();
        let executing = db
            .finish_goal_control_job(planner, Ok(&raw))
            .await
            .unwrap()
            .unwrap();
        let turn = db
            .begin_goal_root_turn(executing.id, executing.attempt_generation)
            .await
            .unwrap();
        db.defer_goal_root_turn_for_approval(executing.id, executing.attempt_generation, turn)
            .await
            .unwrap();
        let current = db
            .current_session_goal(executing.session_id, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.phase, Some(GoalPhase::Executing));
        assert!(
            db.lease_goal_control_job(
                current.id,
                current.attempt_generation,
                Utc::now().timestamp(),
                60
            )
            .await
            .unwrap()
            .is_none()
        );
    }
}
