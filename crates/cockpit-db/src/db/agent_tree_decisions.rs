//! Durable recursive-agent and user-decision control state.
//!
//! This module is deliberately a daemon boundary: callers supply the owning
//! session on every read and mutation, and it persists only redacted summaries
//! of decision contracts and receipts. Live prompts, credentials, provider
//! handles, and resolver context never cross this boundary.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::Db;

/// Test-only deterministic fault points immediately after a control event has
/// been inserted.  They exercise the real transaction boundary rather than a
/// mock: the following error must roll back the event and every prior state
/// change in the operation.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlEventFailurePoint {
    AgentTransition = 1,
    CreateDecision = 2,
    TerminalDecision = 3,
    AgentReceipt = 4,
    DecisionReceipt = 5,
}

#[cfg(test)]
static CONTROL_EVENT_FAILURE: std::sync::OnceLock<std::sync::Mutex<Option<(u8, Uuid)>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn inject_control_event_failure(point: ControlEventFailurePoint, subject_id: Uuid) {
    let failure = CONTROL_EVENT_FAILURE.get_or_init(|| std::sync::Mutex::new(None));
    *failure.lock().expect("control-event failure lock poisoned") = Some((point as u8, subject_id));
}

fn fail_after_control_event(point: u8, subject_id: Uuid) -> Result<()> {
    #[cfg(test)]
    let should_fail = CONTROL_EVENT_FAILURE
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("control-event failure lock poisoned")
        .as_ref()
        .is_some_and(|(configured_point, configured_subject)| {
            *configured_point == point && *configured_subject == subject_id
        });
    #[cfg(test)]
    if should_fail {
        *CONTROL_EVENT_FAILURE
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("control-event failure lock poisoned") = None;
        bail!("injected failure after control event");
    }
    #[cfg(not(test))]
    let _ = (point, subject_id);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentInstanceState {
    Created,
    Running,
    WaitingForUser,
    WaitingForApproval,
    Completed,
    Failed,
    Cancelled,
}

impl AgentInstanceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::WaitingForUser => "waiting_for_user",
            Self::WaitingForApproval => "waiting_for_approval",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "created" => Ok(Self::Created),
            "running" => Ok(Self::Running),
            "waiting_for_user" => Ok(Self::WaitingForUser),
            "waiting_for_approval" => Ok(Self::WaitingForApproval),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(invalid_persisted_value("agent instance state")),
        }
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    fn legal_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Running)
                | (
                    Self::Running,
                    Self::WaitingForUser | Self::WaitingForApproval
                )
                | (
                    Self::Running,
                    Self::Completed | Self::Failed | Self::Cancelled
                )
                | (
                    Self::WaitingForUser | Self::WaitingForApproval,
                    Self::Running | Self::Completed | Self::Failed | Self::Cancelled
                )
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionState {
    Pending,
    Resolving,
    Answered,
    AutoResolved,
    TimedOut,
    Cancelled,
}

impl DecisionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Resolving => "resolving",
            Self::Answered => "answered",
            Self::AutoResolved => "auto_resolved",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "resolving" => Ok(Self::Resolving),
            "answered" => Ok(Self::Answered),
            "auto_resolved" => Ok(Self::AutoResolved),
            "timed_out" => Ok(Self::TimedOut),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(invalid_persisted_value("decision state")),
        }
    }

    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Answered | Self::AutoResolved | Self::TimedOut | Self::Cancelled
        )
    }

    fn legal_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Pending,
                Self::Resolving | Self::Answered | Self::Cancelled | Self::TimedOut
            ) | (
                Self::Resolving,
                Self::Answered | Self::AutoResolved | Self::Cancelled | Self::TimedOut
            )
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInstanceRow {
    pub agent_instance_id: Uuid,
    pub session_id: Uuid,
    pub parent_agent_instance_id: Option<Uuid>,
    pub task_delegation_job_id: Option<String>,
    pub task_delegation_child_uuid: Option<Uuid>,
    pub resolved_profile_snapshot_id: Option<Uuid>,
    pub state: AgentInstanceState,
    pub revision: i64,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRequestRow {
    pub decision_request_id: Uuid,
    pub agent_instance_id: Uuid,
    pub session_id: Uuid,
    pub options_contract_json: String,
    pub free_text_contract_json: Option<String>,
    pub recommendation_json: Option<String>,
    pub rationale_redaction_class: String,
    pub deadline_unix_ms: Option<i64>,
    pub policy_receipt_json: String,
    pub resolver_route: Option<String>,
    pub state: DecisionState,
    pub revision: i64,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalReceipt {
    pub subject_id: Uuid,
    pub session_id: Uuid,
    pub terminal_state: String,
    pub terminal_revision: i64,
    pub receipt_json: String,
    pub session_event_seq: Option<i64>,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentTransitionOutcome {
    Transitioned(AgentInstanceRow),
    AlreadyTerminal(TerminalReceipt),
    RevisionConflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionTransitionOutcome {
    Transitioned(DecisionRequestRow),
    AlreadyTerminal(TerminalReceipt),
    RevisionConflict,
}

#[derive(Debug, Clone)]
pub struct NewAgentInstance {
    pub session_id: Uuid,
    pub parent_agent_instance_id: Option<Uuid>,
    pub task_delegation_job_id: Option<String>,
    pub task_delegation_child_uuid: Option<Uuid>,
    pub resolved_profile_snapshot_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct NewDecisionRequest {
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub expected_agent_revision: i64,
    pub waiting_state: AgentInstanceState,
    pub options_contract_json: String,
    pub free_text_contract_json: Option<String>,
    pub recommendation_json: Option<String>,
    pub rationale_redaction_class: String,
    pub deadline_unix_ms: Option<i64>,
    pub policy_receipt_json: String,
    pub resolver_route: Option<String>,
}

impl Db {
    /// Creates an agent node after validating every lineage edge belongs to the
    /// authorized session. `now_unix_ms` is supplied by the daemon so tests and
    /// recovery receipts remain deterministic.
    pub async fn create_agent_instance(
        &self,
        input: NewAgentInstance,
        now_unix_ms: i64,
    ) -> Result<AgentInstanceRow> {
        let agent_instance_id = Uuid::new_v4();
        self.transaction(move |conn| {
            validate_agent_lineage(conn, &input, agent_instance_id)?;
            conn.execute(
                "INSERT INTO agent_instances (
                    agent_instance_id, session_id, parent_agent_instance_id,
                    task_delegation_job_id, task_delegation_child_uuid,
                    resolved_profile_snapshot_id, state, revision,
                    created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'created', 0, ?7, ?7)",
                params![
                    agent_instance_id.to_string(),
                    input.session_id.to_string(),
                    input.parent_agent_instance_id.map(|id| id.to_string()),
                    input.task_delegation_job_id,
                    input.task_delegation_child_uuid.map(|id| id.to_string()),
                    input.resolved_profile_snapshot_id.map(|id| id.to_string()),
                    now_unix_ms,
                ],
            )
            .context("creating agent instance")?;
            load_agent(conn, input.session_id, agent_instance_id)?.context("created agent missing")
        })
        .await
    }

    pub async fn agent_instance(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
    ) -> Result<Option<AgentInstanceRow>> {
        self.read(move |conn| load_agent(conn, session_id, agent_instance_id))
            .await
    }

    /// Lists only direct, session-authorized descendants. The caller cannot
    /// use an instance UUID from another session as an existence oracle.
    pub async fn agent_instance_children(
        &self,
        session_id: Uuid,
        parent_agent_instance_id: Uuid,
    ) -> Result<Vec<AgentInstanceRow>> {
        self.read(move |conn| {
            if load_agent(conn, session_id, parent_agent_instance_id)?.is_none() {
                return Ok(Vec::new());
            }
            let mut statement = conn.prepare(
                "SELECT agent_instance_id FROM agent_instances
                 WHERE session_id = ?1 AND parent_agent_instance_id = ?2
                 ORDER BY created_at_unix_ms, agent_instance_id",
            )?;
            let ids = statement
                .query_map(
                    params![session_id.to_string(), parent_agent_instance_id.to_string()],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut children = Vec::with_capacity(ids.len());
            for id in ids {
                children
                    .push(load_agent(conn, session_id, parse_uuid(id)?)?.context("child missing")?);
            }
            Ok(children)
        })
        .await
    }

    /// Resolves a stable legacy task-child mapping only within its owner
    /// session. The UUID is never derived from a mutable label or agent name.
    pub async fn agent_instance_for_task_delegation_child(
        &self,
        session_id: Uuid,
        child_uuid: Uuid,
    ) -> Result<Option<AgentInstanceRow>> {
        self.read(move |conn| {
            let agent_id: Option<String> = conn
                .query_row(
                    "SELECT agent_instance_id FROM agent_instances
                     WHERE session_id = ?1 AND task_delegation_child_uuid = ?2",
                    params![session_id.to_string(), child_uuid.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            agent_id
                .map(|id| {
                    load_agent(conn, session_id, parse_uuid(id)?)?.context("mapped agent missing")
                })
                .transpose()
        })
        .await
    }

    pub async fn agent_terminal_receipt(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
    ) -> Result<Option<TerminalReceipt>> {
        self.read(move |conn| {
            let Some(agent) = load_agent(conn, session_id, agent_instance_id)? else {
                return Ok(None);
            };
            if !agent.state.is_terminal() {
                return Ok(None);
            }
            Ok(Some(load_agent_receipt(
                conn,
                session_id,
                agent_instance_id,
                agent.state,
            )?))
        })
        .await
    }

    /// Compares the agent revision, performs a legal transition, and records a
    /// terminal receipt plus redacted notice atomically. A terminal winner is
    /// replayed regardless of a stale retry's requested next state.
    pub async fn transition_agent_instance(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        expected_revision: i64,
        next_state: AgentInstanceState,
        receipt_json: &str,
        now_unix_ms: i64,
    ) -> Result<AgentTransitionOutcome> {
        let receipt_json = redact_receipt_json(receipt_json)?;
        self.transaction(move |conn| {
            let Some(current) = load_agent(conn, session_id, agent_instance_id)? else {
                return Ok(AgentTransitionOutcome::RevisionConflict);
            };
            if current.state.is_terminal() {
                return Ok(AgentTransitionOutcome::AlreadyTerminal(load_agent_receipt(
                    conn,
                    session_id,
                    agent_instance_id,
                    current.state,
                )?));
            }
            if current.revision != expected_revision {
                return Ok(AgentTransitionOutcome::RevisionConflict);
            }
            ensure!(
                current.state.legal_transition(next_state),
                "illegal agent state transition"
            );

            if matches!(
                next_state,
                AgentInstanceState::Completed | AgentInstanceState::Failed
            ) {
                ensure!(
                    !has_live_descendant(conn, session_id, agent_instance_id)?,
                    "cannot complete or fail agent while a descendant remains live"
                );
                ensure!(
                    !has_live_owned_decision(conn, session_id, agent_instance_id)?,
                    "cannot complete or fail agent while an owned decision remains live"
                );
            }
            if next_state == AgentInstanceState::Cancelled {
                cancel_owned_decisions_for_subtree(
                    conn,
                    session_id,
                    agent_instance_id,
                    now_unix_ms,
                )?;
                cancel_live_descendants(conn, session_id, agent_instance_id, now_unix_ms)?;
            }

            let next_revision = current.revision + 1;
            let event_seq = insert_control_event(
                conn,
                session_id,
                "agent_transition",
                agent_instance_id,
                next_state.as_str(),
                now_unix_ms,
            )?;
            fail_after_control_event(1, agent_instance_id)?;
            let changed = conn.execute(
                "UPDATE agent_instances
                 SET state = ?1, revision = ?2, updated_at_unix_ms = ?3
                 WHERE agent_instance_id = ?4 AND session_id = ?5 AND revision = ?6",
                params![
                    next_state.as_str(),
                    next_revision,
                    now_unix_ms,
                    agent_instance_id.to_string(),
                    session_id.to_string(),
                    expected_revision,
                ],
            )?;
            if changed != 1 {
                return Ok(AgentTransitionOutcome::RevisionConflict);
            }
            if next_state.is_terminal() {
                conn.execute(
                    "INSERT INTO agent_transition_receipts (
                         agent_instance_id, terminal_state, session_id, terminal_revision,
                         receipt_json, session_event_seq, created_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        agent_instance_id.to_string(),
                        next_state.as_str(),
                        session_id.to_string(),
                        next_revision,
                        receipt_json,
                        Some(event_seq),
                        now_unix_ms,
                    ],
                )?;
                fail_after_control_event(4, agent_instance_id)?;
            }
            Ok(AgentTransitionOutcome::Transitioned(
                load_agent(conn, session_id, agent_instance_id)?
                    .context("transitioned agent missing")?,
            ))
        })
        .await
    }

    /// Creates a pending decision, atomically moves its agent to the requested
    /// wait state, creates the sole typed attention row, and emits one notice.
    pub async fn create_decision_request(
        &self,
        input: NewDecisionRequest,
        now_unix_ms: i64,
    ) -> Result<DecisionRequestRow> {
        ensure!(
            matches!(
                input.waiting_state,
                AgentInstanceState::WaitingForUser | AgentInstanceState::WaitingForApproval
            ),
            "decision request must put its agent into a waiting state"
        );
        validate_redaction_class(&input.rationale_redaction_class)?;
        let resolver_route = input.resolver_route.clone();
        if let Some(route) = resolver_route.as_deref() {
            validate_resolver_route(route)?;
        }
        let options = redact_options_contract(&input.options_contract_json)?;
        let free_text = input
            .free_text_contract_json
            .as_deref()
            .map(redact_free_text_contract)
            .transpose()?;
        let recommendation = input
            .recommendation_json
            .as_deref()
            .map(redact_recommendation)
            .transpose()?;
        if let Some(recommendation) = recommendation.as_deref() {
            validate_recommendation_is_offered(&options, recommendation)?;
        }
        let policy_receipt = redact_policy_receipt(&input.policy_receipt_json)?;
        let decision_request_id = Uuid::new_v4();
        let attention_id = Uuid::new_v4();
        self.transaction(move |conn| {
            let Some(agent) = load_agent(conn, input.session_id, input.agent_instance_id)? else {
                bail!("agent instance is not authorized for this session");
            };
            ensure!(agent.state == AgentInstanceState::Running, "decision owner is not running");
            ensure!(agent.revision == input.expected_agent_revision, "agent revision conflict");
            let changed = conn.execute(
                "UPDATE agent_instances SET state = ?1, revision = revision + 1, updated_at_unix_ms = ?2
                 WHERE agent_instance_id = ?3 AND session_id = ?4 AND revision = ?5 AND state = 'running'",
                params![
                    input.waiting_state.as_str(), now_unix_ms, input.agent_instance_id.to_string(),
                    input.session_id.to_string(), input.expected_agent_revision,
                ],
            )?;
            ensure!(changed == 1, "agent revision conflict");
            insert_control_event(
                conn,
                input.session_id,
                "agent_transition",
                input.agent_instance_id,
                input.waiting_state.as_str(),
                now_unix_ms,
            )?;
            conn.execute(
                "INSERT INTO decision_requests (
                     decision_request_id, agent_instance_id, session_id,
                     options_contract_json, free_text_contract_json, recommendation_json,
                     rationale_redaction_class, deadline_unix_ms, policy_receipt_json,
                     resolver_route, state, revision, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending', 0, ?11, ?11)",
                params![
                    decision_request_id.to_string(), input.agent_instance_id.to_string(), input.session_id.to_string(),
                    options, free_text, recommendation, input.rationale_redaction_class,
                    input.deadline_unix_ms, policy_receipt, resolver_route, now_unix_ms,
                ],
            )?;
            conn.execute(
                "INSERT INTO needs_attention (
                     interrupt_id, session_id, agent_id, description, state, raised_at,
                     decision_request_id
                 ) VALUES (?1, ?2, ?3, 'agent decision pending', 'open', ?4, ?5)",
                params![
                    attention_id.to_string(), input.session_id.to_string(), input.agent_instance_id.to_string(),
                    now_unix_ms, decision_request_id.to_string(),
                ],
            )?;
            insert_control_event(
                conn, input.session_id, "decision_pending", decision_request_id, "pending", now_unix_ms,
            )?;
            // The owner ID is known before this API allocates the durable
            // decision ID, allowing deterministic fault injection without
            // exposing an ID-generation seam to production callers.
            fail_after_control_event(2, input.agent_instance_id)?;
            load_decision(conn, input.session_id, decision_request_id)?.context("created decision missing")
        })
        .await
    }

    pub async fn decision_request(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
    ) -> Result<Option<DecisionRequestRow>> {
        self.read(move |conn| load_decision(conn, session_id, decision_request_id))
            .await
    }

    pub async fn decision_terminal_receipt(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
    ) -> Result<Option<TerminalReceipt>> {
        self.read(move |conn| {
            let Some(decision) = load_decision(conn, session_id, decision_request_id)? else {
                return Ok(None);
            };
            if !decision.state.is_terminal() {
                return Ok(None);
            }
            Ok(Some(load_decision_receipt(
                conn,
                session_id,
                decision_request_id,
            )?))
        })
        .await
    }

    pub async fn claim_decision_request(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        expected_revision: i64,
        now_unix_ms: i64,
    ) -> Result<DecisionTransitionOutcome> {
        self.transition_decision_request(
            session_id,
            decision_request_id,
            expected_revision,
            DecisionState::Resolving,
            "{}",
            now_unix_ms,
        )
        .await
    }

    /// Resolves, cancels, or times out a decision with a terminal receipt. A
    /// direct user answer from pending is legal; automatic resolution requires
    /// the prior `resolving` claim.
    pub async fn resolve_decision_request(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        expected_revision: i64,
        terminal_state: DecisionState,
        receipt_json: &str,
        now_unix_ms: i64,
    ) -> Result<DecisionTransitionOutcome> {
        ensure!(
            terminal_state.is_terminal(),
            "decision resolution must be terminal"
        );
        self.transition_decision_request(
            session_id,
            decision_request_id,
            expected_revision,
            terminal_state,
            receipt_json,
            now_unix_ms,
        )
        .await
    }

    async fn transition_decision_request(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        expected_revision: i64,
        next_state: DecisionState,
        receipt_json: &str,
        now_unix_ms: i64,
    ) -> Result<DecisionTransitionOutcome> {
        let receipt_json = redact_receipt_json(receipt_json)?;
        self.transaction(move |conn| {
            let Some(current) = load_decision(conn, session_id, decision_request_id)? else {
                return Ok(DecisionTransitionOutcome::RevisionConflict);
            };
            if current.state.is_terminal() {
                return Ok(DecisionTransitionOutcome::AlreadyTerminal(
                    load_decision_receipt(conn, session_id, decision_request_id)?,
                ));
            }
            let Some(owner) = load_agent(conn, session_id, current.agent_instance_id)? else {
                return Ok(DecisionTransitionOutcome::RevisionConflict);
            };
            if owner.state.is_terminal() {
                return Ok(DecisionTransitionOutcome::RevisionConflict);
            }
            if current.revision != expected_revision {
                return Ok(DecisionTransitionOutcome::RevisionConflict);
            }
            ensure!(
                current.state.legal_transition(next_state),
                "illegal decision state transition"
            );
            let next_revision = current.revision + 1;
            let terminal = next_state.is_terminal();
            let event_seq = insert_control_event(
                conn,
                session_id,
                "decision_transition",
                decision_request_id,
                next_state.as_str(),
                now_unix_ms,
            )?;
            if terminal {
                fail_after_control_event(3, decision_request_id)?;
            }
            let changed = conn.execute(
                "UPDATE decision_requests
                 SET state = ?1, revision = ?2, updated_at_unix_ms = ?3
                 WHERE decision_request_id = ?4 AND session_id = ?5 AND revision = ?6",
                params![
                    next_state.as_str(),
                    next_revision,
                    now_unix_ms,
                    decision_request_id.to_string(),
                    session_id.to_string(),
                    expected_revision,
                ],
            )?;
            if changed != 1 {
                return Ok(DecisionTransitionOutcome::RevisionConflict);
            }
            if terminal {
                conn.execute(
                    "INSERT INTO decision_receipts (
                         decision_request_id, session_id, terminal_state, terminal_revision,
                         receipt_json, session_event_seq, created_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        decision_request_id.to_string(),
                        session_id.to_string(),
                        next_state.as_str(),
                        next_revision,
                        receipt_json,
                        Some(event_seq),
                        now_unix_ms,
                    ],
                )?;
                fail_after_control_event(5, decision_request_id)?;
                resolve_owned_decision_attention(
                    conn,
                    session_id,
                    decision_request_id,
                    &receipt_json,
                    now_unix_ms,
                )?;
            }
            Ok(DecisionTransitionOutcome::Transitioned(
                load_decision(conn, session_id, decision_request_id)?
                    .context("transitioned decision missing")?,
            ))
        })
        .await
    }
}

fn validate_agent_lineage(
    conn: &Connection,
    input: &NewAgentInstance,
    agent_instance_id: Uuid,
) -> Result<()> {
    if let Some(parent_id) = input.parent_agent_instance_id {
        ensure!(parent_id != agent_instance_id, "agent cannot parent itself");
        let parent = load_agent(conn, input.session_id, parent_id)?
            .context("parent agent is not authorized for this session")?;
        ensure!(
            !parent.state.is_terminal(),
            "cannot create a child for a terminal parent agent"
        );
    }
    if let Some(job_id) = input.task_delegation_job_id.as_deref() {
        let owner: Option<String> = conn
            .query_row(
                "SELECT parent_session_id FROM task_delegation_jobs WHERE task_call_id = ?1",
                [job_id],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            owner.as_deref() == Some(&input.session_id.to_string()),
            "task delegation job is not authorized for this session"
        );
    }
    if let Some(child_id) = input.task_delegation_child_uuid {
        let child_job: Option<(String, String)> = conn
            .query_row(
                "SELECT c.task_call_id, j.parent_session_id
                 FROM task_delegation_children c
                 JOIN task_delegation_jobs j ON j.task_call_id = c.task_call_id
                 WHERE c.child_uuid = ?1",
                [child_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((child_job, child_session)) = child_job else {
            bail!("task delegation child mapping is unknown");
        };
        ensure!(
            child_session == input.session_id.to_string(),
            "task delegation child is not authorized for this session"
        );
        if let Some(job_id) = input.task_delegation_job_id.as_deref() {
            ensure!(
                child_job == job_id,
                "task delegation child belongs to another job"
            );
        }
    }
    if let Some(snapshot_id) = input.resolved_profile_snapshot_id {
        let owner: Option<String> = conn
            .query_row(
                "SELECT session_id FROM agent_profile_snapshots WHERE snapshot_id = ?1",
                [snapshot_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            owner.as_deref() == Some(&input.session_id.to_string()),
            "profile snapshot is not authorized for this session"
        );
    }
    Ok(())
}

fn load_agent(
    conn: &Connection,
    session_id: Uuid,
    agent_id: Uuid,
) -> Result<Option<AgentInstanceRow>> {
    conn.query_row(
        "SELECT agent_instance_id, session_id, parent_agent_instance_id, task_delegation_job_id,
                task_delegation_child_uuid, resolved_profile_snapshot_id, state, revision,
                created_at_unix_ms, updated_at_unix_ms
         FROM agent_instances WHERE agent_instance_id = ?1 AND session_id = ?2",
        params![agent_id.to_string(), session_id.to_string()],
        |row| {
            Ok(AgentInstanceRow {
                agent_instance_id: parse_uuid(row.get::<_, String>(0)?)?,
                session_id: parse_uuid(row.get::<_, String>(1)?)?,
                parent_agent_instance_id: row
                    .get::<_, Option<String>>(2)?
                    .map(parse_uuid)
                    .transpose()?,
                task_delegation_job_id: row.get(3)?,
                task_delegation_child_uuid: row
                    .get::<_, Option<String>>(4)?
                    .map(parse_uuid)
                    .transpose()?,
                resolved_profile_snapshot_id: row
                    .get::<_, Option<String>>(5)?
                    .map(parse_uuid)
                    .transpose()?,
                state: AgentInstanceState::parse(&row.get::<_, String>(6)?)?,
                revision: row.get(7)?,
                created_at_unix_ms: row.get(8)?,
                updated_at_unix_ms: row.get(9)?,
            })
        },
    )
    .optional()
    .context("loading authorized agent instance")
}

fn load_decision(
    conn: &Connection,
    session_id: Uuid,
    decision_id: Uuid,
) -> Result<Option<DecisionRequestRow>> {
    conn.query_row(
        "SELECT decision_request_id, agent_instance_id, session_id, options_contract_json,
                free_text_contract_json, recommendation_json, rationale_redaction_class,
                deadline_unix_ms, policy_receipt_json, resolver_route, state, revision,
                created_at_unix_ms, updated_at_unix_ms
         FROM decision_requests WHERE decision_request_id = ?1 AND session_id = ?2",
        params![decision_id.to_string(), session_id.to_string()],
        |row| {
            Ok(DecisionRequestRow {
                decision_request_id: parse_uuid(row.get::<_, String>(0)?)?,
                agent_instance_id: parse_uuid(row.get::<_, String>(1)?)?,
                session_id: parse_uuid(row.get::<_, String>(2)?)?,
                options_contract_json: row.get(3)?,
                free_text_contract_json: row.get(4)?,
                recommendation_json: row.get(5)?,
                rationale_redaction_class: row.get(6)?,
                deadline_unix_ms: row.get(7)?,
                policy_receipt_json: row.get(8)?,
                resolver_route: row.get(9)?,
                state: DecisionState::parse(&row.get::<_, String>(10)?)?,
                revision: row.get(11)?,
                created_at_unix_ms: row.get(12)?,
                updated_at_unix_ms: row.get(13)?,
            })
        },
    )
    .optional()
    .context("loading authorized decision request")
}

fn load_agent_receipt(
    conn: &Connection,
    session_id: Uuid,
    agent_id: Uuid,
    terminal_state: AgentInstanceState,
) -> Result<TerminalReceipt> {
    conn.query_row(
        "SELECT agent_instance_id, session_id, terminal_state, terminal_revision,
                receipt_json, session_event_seq, created_at_unix_ms
         FROM agent_transition_receipts
         WHERE agent_instance_id = ?1 AND session_id = ?2 AND terminal_state = ?3",
        params![
            agent_id.to_string(),
            session_id.to_string(),
            terminal_state.as_str()
        ],
        |row| {
            Ok(TerminalReceipt {
                subject_id: parse_uuid(row.get::<_, String>(0)?)?,
                session_id: parse_uuid(row.get::<_, String>(1)?)?,
                terminal_state: row.get(2)?,
                terminal_revision: row.get(3)?,
                receipt_json: row.get(4)?,
                session_event_seq: row.get(5)?,
                created_at_unix_ms: row.get(6)?,
            })
        },
    )
    .context("terminal agent is missing its durable receipt")
}

fn load_decision_receipt(
    conn: &Connection,
    session_id: Uuid,
    decision_id: Uuid,
) -> Result<TerminalReceipt> {
    conn.query_row(
        "SELECT decision_request_id, session_id, terminal_state, terminal_revision,
                receipt_json, session_event_seq, created_at_unix_ms
         FROM decision_receipts WHERE decision_request_id = ?1 AND session_id = ?2",
        params![decision_id.to_string(), session_id.to_string()],
        |row| {
            Ok(TerminalReceipt {
                subject_id: parse_uuid(row.get::<_, String>(0)?)?,
                session_id: parse_uuid(row.get::<_, String>(1)?)?,
                terminal_state: row.get(2)?,
                terminal_revision: row.get(3)?,
                receipt_json: row.get(4)?,
                session_event_seq: row.get(5)?,
                created_at_unix_ms: row.get(6)?,
            })
        },
    )
    .context("terminal decision is missing its durable receipt")
}

fn has_live_descendant(conn: &Connection, session_id: Uuid, root_id: Uuid) -> Result<bool> {
    let count: i64 = conn.query_row(
        "WITH RECURSIVE descendants(agent_instance_id) AS (
             SELECT agent_instance_id FROM agent_instances
             WHERE parent_agent_instance_id = ?1 AND session_id = ?2
             UNION ALL
             SELECT a.agent_instance_id FROM agent_instances a
             JOIN descendants d ON a.parent_agent_instance_id = d.agent_instance_id
             WHERE a.session_id = ?2
         )
         SELECT COUNT(*) FROM agent_instances
         WHERE agent_instance_id IN descendants
           AND state NOT IN ('completed', 'failed', 'cancelled')",
        params![root_id.to_string(), session_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(count != 0)
}

/// Completion and failure must not strand a request in a pending decision
/// projection. Cancellation has its own atomic terminalization path below;
/// the other terminal transitions fail closed until their owner has resolved
/// every live decision.
fn has_live_owned_decision(conn: &Connection, session_id: Uuid, agent_id: Uuid) -> Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM decision_requests
         WHERE session_id = ?1 AND agent_instance_id = ?2
           AND state IN ('pending', 'resolving')",
        params![session_id.to_string(), agent_id.to_string()],
        |row| row.get(0),
    )?;
    Ok(count != 0)
}

fn cancel_live_descendants(
    conn: &Connection,
    session_id: Uuid,
    root_id: Uuid,
    now_unix_ms: i64,
) -> Result<()> {
    let mut statement = conn.prepare(
        "WITH RECURSIVE descendants(agent_instance_id) AS (
             SELECT agent_instance_id FROM agent_instances
             WHERE parent_agent_instance_id = ?1 AND session_id = ?2
             UNION ALL
             SELECT a.agent_instance_id FROM agent_instances a
             JOIN descendants d ON a.parent_agent_instance_id = d.agent_instance_id
             WHERE a.session_id = ?2
         )
         SELECT agent_instance_id, revision FROM agent_instances
         WHERE agent_instance_id IN descendants
           AND state NOT IN ('completed', 'failed', 'cancelled')
         ORDER BY agent_instance_id",
    )?;
    let live = statement
        .query_map(
            params![root_id.to_string(), session_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (agent_id, revision) in live {
        let id = parse_uuid(agent_id)?;
        let event_seq = insert_control_event(
            conn,
            session_id,
            "agent_transition",
            id,
            AgentInstanceState::Cancelled.as_str(),
            now_unix_ms,
        )?;
        let changed = conn.execute(
            "UPDATE agent_instances SET state = 'cancelled', revision = revision + 1,
             updated_at_unix_ms = ?1
             WHERE agent_instance_id = ?2 AND session_id = ?3 AND revision = ?4
               AND state NOT IN ('completed', 'failed', 'cancelled')",
            params![
                now_unix_ms,
                id.to_string(),
                session_id.to_string(),
                revision
            ],
        )?;
        ensure!(
            changed == 1,
            "descendant cancellation lost its compare-and-set"
        );
        conn.execute(
            "INSERT INTO agent_transition_receipts (
                 agent_instance_id, terminal_state, session_id, terminal_revision,
                 receipt_json, session_event_seq, created_at_unix_ms
             ) VALUES (?1, 'cancelled', ?2, ?3, ?4, ?5, ?6)",
            params![
                id.to_string(),
                session_id.to_string(),
                revision + 1,
                redacted_marker("cascade cancellation"),
                event_seq,
                now_unix_ms,
            ],
        )?;
    }
    Ok(())
}

/// Cancelling an agent is also the terminal winner for every still-live
/// decision owned by that agent or its descendants. This runs in the same DB
/// transaction as the descendant and parent agent receipts, so a late user or
/// utility result cannot revive a cancelled tree after a daemon restart.
fn cancel_owned_decisions_for_subtree(
    conn: &Connection,
    session_id: Uuid,
    root_id: Uuid,
    now_unix_ms: i64,
) -> Result<()> {
    let mut statement = conn.prepare(
        "WITH RECURSIVE tree(agent_instance_id) AS (
             SELECT agent_instance_id FROM agent_instances
             WHERE agent_instance_id = ?1 AND session_id = ?2
             UNION ALL
             SELECT a.agent_instance_id FROM agent_instances a
             JOIN tree t ON a.parent_agent_instance_id = t.agent_instance_id
             WHERE a.session_id = ?2
         )
         SELECT d.decision_request_id, d.revision
         FROM decision_requests d
         WHERE d.session_id = ?2
           AND d.agent_instance_id IN tree
           AND d.state IN ('pending', 'resolving')
         ORDER BY d.decision_request_id",
    )?;
    let decisions = statement
        .query_map(
            params![root_id.to_string(), session_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (decision_id, revision) in decisions {
        let decision_id = parse_uuid(decision_id)?;
        let receipt_json = redacted_marker("agent tree cancellation");
        let event_seq = insert_control_event(
            conn,
            session_id,
            "decision_transition",
            decision_id,
            DecisionState::Cancelled.as_str(),
            now_unix_ms,
        )?;
        let changed = conn.execute(
            "UPDATE decision_requests
             SET state = 'cancelled', revision = revision + 1, updated_at_unix_ms = ?1
             WHERE decision_request_id = ?2 AND session_id = ?3 AND revision = ?4
               AND state IN ('pending', 'resolving')",
            params![
                now_unix_ms,
                decision_id.to_string(),
                session_id.to_string(),
                revision,
            ],
        )?;
        ensure!(
            changed == 1,
            "decision cancellation lost its compare-and-set"
        );
        conn.execute(
            "INSERT INTO decision_receipts (
                 decision_request_id, session_id, terminal_state, terminal_revision,
                 receipt_json, session_event_seq, created_at_unix_ms
             ) VALUES (?1, ?2, 'cancelled', ?3, ?4, ?5, ?6)",
            params![
                decision_id.to_string(),
                session_id.to_string(),
                revision + 1,
                receipt_json,
                event_seq,
                now_unix_ms,
            ],
        )?;
        resolve_owned_decision_attention(
            conn,
            session_id,
            decision_id,
            &redacted_marker("agent tree cancellation"),
            now_unix_ms,
        )?;
    }
    Ok(())
}

/// Resolves the attention projection only while the decision state machine is
/// in the same transaction.  The schema trigger requires this short-lived
/// guard and a monotonic projection revision, which makes legacy interrupt
/// APIs fail closed for decision-owned rows instead of racing the decision
/// CAS/receipt path.
fn resolve_owned_decision_attention(
    conn: &Connection,
    session_id: Uuid,
    decision_request_id: Uuid,
    receipt_json: &str,
    now_unix_ms: i64,
) -> Result<()> {
    let current_revision: Option<i64> = conn
        .query_row(
            "SELECT revision FROM needs_attention
             WHERE decision_request_id = ?1 AND session_id = ?2 AND state <> 'resolved'",
            params![decision_request_id.to_string(), session_id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(current_revision) = current_revision else {
        bail!("decision is missing its owned attention row");
    };
    conn.execute(
        "INSERT INTO decision_attention_mutation_guards (decision_request_id, session_id)
         VALUES (?1, ?2)",
        params![decision_request_id.to_string(), session_id.to_string()],
    )?;
    let changed = conn.execute(
        "UPDATE needs_attention
         SET state = 'resolved', resolved_at = ?1, response_json = ?2, revision = ?3
         WHERE decision_request_id = ?4 AND session_id = ?5 AND revision = ?6
           AND state <> 'resolved'",
        params![
            now_unix_ms,
            receipt_json,
            current_revision + 1,
            decision_request_id.to_string(),
            session_id.to_string(),
            current_revision,
        ],
    )?;
    ensure!(changed == 1, "decision-owned attention CAS lost");
    let removed = conn.execute(
        "DELETE FROM decision_attention_mutation_guards WHERE decision_request_id = ?1 AND session_id = ?2",
        params![decision_request_id.to_string(), session_id.to_string()],
    )?;
    ensure!(removed == 1, "decision attention guard disappeared");
    Ok(())
}

fn insert_control_event(
    conn: &Connection,
    session_id: Uuid,
    kind: &str,
    subject_id: Uuid,
    state: &str,
    now_unix_ms: i64,
) -> Result<i64> {
    let data_json = serde_json::to_string(&json!({
        "kind": kind,
        "subject_id": subject_id,
        "state": state,
        "redacted": true,
    }))?;
    conn.execute(
        "INSERT INTO session_events (session_id, ts_ms, type, data_json)
         VALUES (?1, ?2, 'notice', ?3)",
        params![session_id.to_string(), now_unix_ms, data_json],
    )?;
    Ok(conn.last_insert_rowid())
}

fn validate_redaction_class(value: &str) -> Result<()> {
    ensure!(
        matches!(value, "public" | "sensitive" | "secret"),
        "invalid rationale redaction class"
    );
    Ok(())
}

fn validate_resolver_route(value: &str) -> Result<()> {
    ensure!(
        matches!(
            value,
            "user" | "policy" | "utility" | "timeout" | "cancellation"
        ),
        "invalid decision resolver route"
    );
    Ok(())
}

/// Receipts may carry a user answer or a resolver's raw context, so the DB
/// stores only a non-reversible marker. Decision *contracts* use the typed
/// allowlisted projections below instead: they retain only what a restart may
/// safely render or resolve.
fn redact_receipt_json(raw: &str) -> Result<String> {
    let _: serde_json::Value =
        serde_json::from_str(raw).context("decision payload must be valid JSON")?;
    Ok(redacted_marker(raw))
}

fn redact_options_contract(raw: &str) -> Result<String> {
    let values: Vec<serde_json::Value> =
        serde_json::from_str(raw).context("decision options contract must be a JSON array")?;
    ensure!(
        values.len() <= 64,
        "decision options contract has too many options"
    );
    let mut options = Vec::with_capacity(values.len());
    for value in values {
        let object = value
            .as_object()
            .context("each decision option must be an object")?;
        ensure!(
            object.keys().all(|key| key == "id" || key == "label"),
            "decision option contains an unapproved field"
        );
        let id = object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .context("decision option is missing its id")?;
        validate_safe_identifier(id, "decision option id")?;
        let label = object
            .get("label")
            .and_then(serde_json::Value::as_str)
            .context("decision option is missing its label")?;
        validate_safe_display(label, "decision option label")?;
        options.push(json!({ "id": id, "label": label }));
    }
    let unique = options
        .iter()
        .filter_map(|value| value.get("id").and_then(serde_json::Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        unique.len() == options.len(),
        "decision option ids must be unique"
    );
    serde_json::to_string(&json!({ "options": options, "redacted": true }))
        .context("serializing redacted decision options")
}

fn redact_free_text_contract(raw: &str) -> Result<String> {
    let object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(raw).context("free-text contract must be a JSON object")?;
    ensure!(
        object
            .keys()
            .all(|key| key == "allowed" || key == "max_chars"),
        "free-text contract contains an unapproved field"
    );
    let allowed = object
        .get("allowed")
        .and_then(serde_json::Value::as_bool)
        .context("free-text contract is missing allowed")?;
    let max_chars = object
        .get("max_chars")
        .map(|value| {
            value
                .as_u64()
                .context("free-text contract max_chars must be an unsigned integer")
        })
        .transpose()?;
    ensure!(
        max_chars.is_none_or(|value| value <= 10_000),
        "free-text contract max_chars is too large"
    );
    serde_json::to_string(&json!({
        "allowed": allowed,
        "max_chars": max_chars,
        "redacted": true,
    }))
    .context("serializing redacted free-text contract")
}

fn redact_recommendation(raw: &str) -> Result<String> {
    let object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(raw).context("decision recommendation must be a JSON object")?;
    ensure!(
        object.keys().all(|key| key == "option_id"),
        "decision recommendation contains an unapproved field"
    );
    let option_id = object
        .get("option_id")
        .map(|value| {
            value
                .as_str()
                .context("decision recommendation option_id must be a string")
        })
        .transpose()?;
    if let Some(option_id) = option_id {
        validate_safe_identifier(option_id, "decision recommendation option_id")?;
    }
    serde_json::to_string(&json!({ "option_id": option_id, "redacted": true }))
        .context("serializing redacted decision recommendation")
}

fn redact_policy_receipt(raw: &str) -> Result<String> {
    let object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(raw).context("decision policy receipt must be a JSON object")?;
    ensure!(
        object
            .keys()
            .all(|key| key == "policy" || key == "receipt_id"),
        "decision policy receipt contains an unapproved field"
    );
    let policy = object
        .get("policy")
        .map(|value| {
            value
                .as_str()
                .context("decision policy receipt policy must be a string")
        })
        .transpose()?;
    if let Some(policy) = policy {
        ensure!(
            matches!(
                policy,
                "manual" | "automatic" | "utility" | "timeout" | "cancellation"
            ),
            "decision policy receipt policy is unsupported"
        );
    }
    let receipt_id = object
        .get("receipt_id")
        .map(|value| {
            value
                .as_str()
                .context("decision policy receipt receipt_id must be a string")
        })
        .transpose()?;
    if let Some(receipt_id) = receipt_id {
        validate_safe_identifier(receipt_id, "decision policy receipt id")?;
    }
    serde_json::to_string(&json!({
        "policy": policy,
        "receipt_id": receipt_id,
        "redacted": true,
    }))
    .context("serializing redacted decision policy receipt")
}

fn validate_recommendation_is_offered(options: &str, recommendation: &str) -> Result<()> {
    let options: serde_json::Value = serde_json::from_str(options)
        .context("loading redacted options contract for recommendation validation")?;
    let recommendation: serde_json::Value = serde_json::from_str(recommendation)
        .context("loading redacted recommendation for validation")?;
    let Some(option_id) = recommendation
        .get("option_id")
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(());
    };
    ensure!(
        options["options"].as_array().is_some_and(|options| {
            options.iter().any(|option| {
                option.get("id").and_then(serde_json::Value::as_str) == Some(option_id)
            })
        }),
        "decision recommendation must name an offered option"
    );
    Ok(())
}

fn validate_safe_identifier(value: &str, field: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'-' | b':')),
        "{field} is not a safe opaque identifier"
    );
    Ok(())
}

fn validate_safe_display(value: &str, field: &str) -> Result<()> {
    let lower = value.to_ascii_lowercase();
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && !value
                .chars()
                .any(|character| matches!(character, '\n' | '\r' | '`' | '[' | ']' | '<' | '>'))
            && !lower.contains("credential")
            && !lower.contains("password")
            && !lower.contains("secret")
            && !lower.contains("token")
            && !lower.contains("api_key")
            && !lower.contains("api key")
            && !lower.contains("private key")
            && !lower.contains("bearer")
            && !lower.contains("github_pat")
            && !lower.contains("sk-")
            && !lower.contains("handle"),
        "{field} contains unsafe or markdown-like content"
    );
    Ok(())
}

fn redacted_marker(raw: &str) -> String {
    serde_json::to_string(&json!({
        "redacted": true,
        "sha256": Sha256::digest(raw.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "byte_len": raw.len(),
    }))
    .expect("fixed redaction marker is serializable")
}

fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })
}

fn invalid_persisted_value(field: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid persisted {field}"),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::task_delegation_payloads::NewTaskDelegationPayload;
    use crate::db::task_delegations::{DelegationChildInit, TaskDelegationJobUpsert};
    use crate::db::wire::ResolveResponse;

    fn standard_decision(
        session_id: Uuid,
        agent_instance_id: Uuid,
        expected_agent_revision: i64,
    ) -> NewDecisionRequest {
        NewDecisionRequest {
            session_id,
            agent_instance_id,
            expected_agent_revision,
            waiting_state: AgentInstanceState::WaitingForUser,
            options_contract_json: r#"[{"id":"continue","label":"Continue"}]"#.into(),
            free_text_contract_json: None,
            recommendation_json: Some(r#"{"option_id":"continue"}"#.into()),
            rationale_redaction_class: "public".into(),
            deadline_unix_ms: None,
            policy_receipt_json: r#"{"policy":"manual"}"#.into(),
            resolver_route: Some("user".into()),
        }
    }

    async fn subject_notice_count(db: &Db, session_id: Uuid, subject_id: Uuid) -> i64 {
        db.read(move |conn| {
            let count = conn.query_row(
                "SELECT COUNT(*) FROM session_events
                 WHERE session_id = ?1 AND type = 'notice'
                   AND json_extract(data_json, '$.subject_id') = ?2",
                params![session_id.to_string(), subject_id.to_string()],
                |row| row.get(0),
            )?;
            Ok(count)
        })
        .await
        .unwrap()
    }

    async fn running_agent(db: &Db, session_id: Uuid, now: i64) -> AgentInstanceRow {
        let agent = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                },
                now,
            )
            .await
            .unwrap();
        match db
            .transition_agent_instance(
                session_id,
                agent.agent_instance_id,
                agent.revision,
                AgentInstanceState::Running,
                "{}",
                now + 1,
            )
            .await
            .unwrap()
        {
            AgentTransitionOutcome::Transitioned(agent) => agent,
            outcome => panic!("unexpected running transition: {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn agent_tree_control_event_failures_rollback_state_receipts_and_attention() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 10).await;

        // A nonterminal agent event is rolled back with its attempted CAS.
        let notices_before =
            subject_notice_count(&db, session.session_id, agent.agent_instance_id).await;
        inject_control_event_failure(
            ControlEventFailurePoint::AgentTransition,
            agent.agent_instance_id,
        );
        let failed = db
            .transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                agent.revision,
                AgentInstanceState::WaitingForApproval,
                "{}",
                12,
            )
            .await;
        assert!(failed.unwrap_err().to_string().contains("injected failure"));
        let unchanged = db
            .agent_instance(session.session_id, agent.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (unchanged.state, unchanged.revision),
            (agent.state, agent.revision)
        );
        assert_eq!(
            subject_notice_count(&db, session.session_id, agent.agent_instance_id).await,
            notices_before
        );

        // Failure after the wait event, decision insert, attention projection,
        // and pending event leaves none of that composite operation behind.
        inject_control_event_failure(
            ControlEventFailurePoint::CreateDecision,
            agent.agent_instance_id,
        );
        let failed = db
            .create_decision_request(
                standard_decision(session.session_id, agent.agent_instance_id, agent.revision),
                13,
            )
            .await;
        assert!(failed.unwrap_err().to_string().contains("injected failure"));
        let unchanged = db
            .agent_instance(session.session_id, agent.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (unchanged.state, unchanged.revision),
            (agent.state, agent.revision)
        );
        let (decisions, attention) = db
            .read(move |conn| {
                Ok((
                    conn.query_row("SELECT COUNT(*) FROM decision_requests WHERE session_id = ?1", [session.session_id.to_string()], |row| row.get::<_, i64>(0))?,
                    conn.query_row("SELECT COUNT(*) FROM needs_attention WHERE session_id = ?1 AND decision_request_id IS NOT NULL", [session.session_id.to_string()], |row| row.get::<_, i64>(0))?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((decisions, attention), (0, 0));
        assert_eq!(
            subject_notice_count(&db, session.session_id, agent.agent_instance_id).await,
            notices_before
        );

        let decision = db
            .create_decision_request(
                standard_decision(session.session_id, agent.agent_instance_id, agent.revision),
                14,
            )
            .await
            .unwrap();
        let decision_notices =
            subject_notice_count(&db, session.session_id, decision.decision_request_id).await;
        inject_control_event_failure(
            ControlEventFailurePoint::TerminalDecision,
            decision.decision_request_id,
        );
        let failed = db
            .resolve_decision_request(
                session.session_id,
                decision.decision_request_id,
                decision.revision,
                DecisionState::Answered,
                r#"{"answer":"private"}"#,
                15,
            )
            .await;
        assert!(failed.unwrap_err().to_string().contains("injected failure"));
        let pending = db
            .decision_request(session.session_id, decision.decision_request_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (pending.state, pending.revision),
            (DecisionState::Pending, 0)
        );
        assert!(
            db.decision_terminal_receipt(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            subject_notice_count(&db, session.session_id, decision.decision_request_id).await,
            decision_notices
        );
        let attention_after_terminal_failure: (String, i64, Option<i64>) = db
            .read(move |conn| {
                let row = conn.query_row(
                    "SELECT state, revision, resolved_at FROM needs_attention WHERE decision_request_id = ?1",
                    [decision.decision_request_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                Ok(row)
            })
            .await
            .unwrap();
        assert_eq!(attention_after_terminal_failure, ("open".into(), 0, None));

        // This reaches the receipt insert, then fails before resolving its
        // attention projection; every terminal artifact must roll back.
        inject_control_event_failure(
            ControlEventFailurePoint::DecisionReceipt,
            decision.decision_request_id,
        );
        let failed = db
            .resolve_decision_request(
                session.session_id,
                decision.decision_request_id,
                decision.revision,
                DecisionState::Answered,
                r#"{"answer":"private"}"#,
                16,
            )
            .await;
        assert!(failed.unwrap_err().to_string().contains("injected failure"));
        let pending = db
            .decision_request(session.session_id, decision.decision_request_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (pending.state, pending.revision),
            (DecisionState::Pending, 0)
        );
        assert!(
            db.decision_terminal_receipt(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            subject_notice_count(&db, session.session_id, decision.decision_request_id).await,
            decision_notices
        );
        let attention_after_receipt_failure: (String, i64, Option<i64>) = db
            .read(move |conn| {
                let row = conn.query_row(
                    "SELECT state, revision, resolved_at FROM needs_attention WHERE decision_request_id = ?1",
                    [decision.decision_request_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                Ok(row)
            })
            .await
            .unwrap();
        assert_eq!(attention_after_receipt_failure, ("open".into(), 0, None));

        // A terminal agent receipt and its receipt-linked event share the
        // same rollback boundary too.
        let terminal_agent = running_agent(&db, session.session_id, 20).await;
        let notices_before =
            subject_notice_count(&db, session.session_id, terminal_agent.agent_instance_id).await;
        inject_control_event_failure(
            ControlEventFailurePoint::AgentTransition,
            terminal_agent.agent_instance_id,
        );
        let failed = db
            .transition_agent_instance(
                session.session_id,
                terminal_agent.agent_instance_id,
                terminal_agent.revision,
                AgentInstanceState::Completed,
                "{}",
                22,
            )
            .await;
        assert!(failed.unwrap_err().to_string().contains("injected failure"));
        assert!(
            db.agent_terminal_receipt(session.session_id, terminal_agent.agent_instance_id)
                .await
                .unwrap()
                .is_none()
        );
        let unchanged = db
            .agent_instance(session.session_id, terminal_agent.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (unchanged.state, unchanged.revision),
            (terminal_agent.state, terminal_agent.revision)
        );
        assert_eq!(
            subject_notice_count(&db, session.session_id, terminal_agent.agent_instance_id).await,
            notices_before
        );

        // The terminal event and receipt have both been inserted before this
        // fault; rollback must nevertheless leave neither durable.
        inject_control_event_failure(
            ControlEventFailurePoint::AgentReceipt,
            terminal_agent.agent_instance_id,
        );
        let failed = db
            .transition_agent_instance(
                session.session_id,
                terminal_agent.agent_instance_id,
                terminal_agent.revision,
                AgentInstanceState::Completed,
                "{}",
                23,
            )
            .await;
        assert!(failed.unwrap_err().to_string().contains("injected failure"));
        assert!(
            db.agent_terminal_receipt(session.session_id, terminal_agent.agent_instance_id)
                .await
                .unwrap()
                .is_none()
        );
        let unchanged = db
            .agent_instance(session.session_id, terminal_agent.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (unchanged.state, unchanged.revision),
            (terminal_agent.state, terminal_agent.revision)
        );
        assert_eq!(
            subject_notice_count(&db, session.session_id, terminal_agent.agent_instance_id).await,
            notices_before
        );
    }

    #[tokio::test]
    async fn agent_tree_decision_owned_attention_refuses_legacy_mutation_and_uses_monotonic_cas() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 30).await;
        let decision = db
            .create_decision_request(
                standard_decision(session.session_id, agent.agent_instance_id, agent.revision),
                32,
            )
            .await
            .unwrap();
        let attention_id: Uuid = db
            .read(move |conn| {
                let raw: String = conn.query_row(
                    "SELECT interrupt_id FROM needs_attention WHERE decision_request_id = ?1",
                    [decision.decision_request_id.to_string()],
                    |row| row.get(0),
                )?;
                Ok(Uuid::parse_str(&raw)?)
            })
            .await
            .unwrap();
        let legacy = db
            .resolve_interrupt(
                attention_id,
                &ResolveResponse::Single {
                    selected_id: "continue".into(),
                },
            )
            .await;
        assert!(
            legacy
                .unwrap_err()
                .to_string()
                .contains("not found or not open")
        );
        // A direct legacy writer racing the terminal decision cannot sneak a
        // projection transition through between the decision CAS and receipt.
        let legacy_attention_id = attention_id.to_string();
        let legacy_writer = db.write(move |conn| {
            conn.execute(
                "UPDATE needs_attention
                 SET state = 'resolved', resolved_at = 33, revision = revision + 1
                 WHERE interrupt_id = ?1",
                [legacy_attention_id],
            )?;
            Ok(())
        });
        let decision_writer = db.resolve_decision_request(
            session.session_id,
            decision.decision_request_id,
            decision.revision,
            DecisionState::Answered,
            "{}",
            33,
        );
        let (legacy_writer, resolved) = tokio::join!(legacy_writer, decision_writer);
        assert!(
            legacy_writer
                .unwrap_err()
                .to_string()
                .contains("decision-owned")
        );
        let resolved = resolved.unwrap();
        assert!(matches!(
            resolved,
            DecisionTransitionOutcome::Transitioned(_)
        ));
        let (state, revision): (String, i64) = db
            .read(move |conn| {
                let row = conn.query_row(
                    "SELECT state, revision FROM needs_attention WHERE interrupt_id = ?1",
                    [attention_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                Ok(row)
            })
            .await
            .unwrap();
        assert_eq!((state.as_str(), revision), ("resolved", 1));
    }

    #[tokio::test]
    async fn agent_tree_decision_attention_is_invisible_to_legacy_interrupt_apis() {
        let db = Db::open_in_memory().unwrap();
        let owner_session = db.create_session("owner", "/owner", "root").await.unwrap();
        let other_session = db.create_session("other", "/other", "root").await.unwrap();
        let owner = running_agent(&db, owner_session.session_id, 40).await;
        let decision = db
            .create_decision_request(
                standard_decision(
                    owner_session.session_id,
                    owner.agent_instance_id,
                    owner.revision,
                ),
                42,
            )
            .await
            .unwrap();
        let attention_id: Uuid = db
            .read(move |conn| {
                let raw: String = conn.query_row(
                    "SELECT interrupt_id FROM needs_attention WHERE decision_request_id = ?1",
                    [decision.decision_request_id.to_string()],
                    |row| row.get(0),
                )?;
                Ok(Uuid::parse_str(&raw)?)
            })
            .await
            .unwrap();

        // `get_interrupt` has no session authority. It must never become an
        // oracle for a decision projection, even when a different session has
        // the opaque UUID. Lists and every legacy mutation use the same
        // decision_request_id IS NULL boundary.
        assert!(db.get_interrupt(attention_id).await.unwrap().is_none());
        assert!(
            db.list_open_interrupts(owner_session.session_id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.list_open_interrupts(other_session.session_id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.resolve_interrupt(
                attention_id,
                &ResolveResponse::Single {
                    selected_id: "continue".into(),
                },
            )
            .await
            .is_err()
        );
        assert!(!db.park_interrupt(attention_id).await.unwrap());
        assert!(!db.mark_interrupt_interrupted(attention_id).await.unwrap());
        assert!(
            db.interrupt_question_occurrence(attention_id)
                .await
                .is_err()
        );

        // The authorized, session-scoped decision API remains the only path
        // that can resolve its owned projection.
        let resolved = db
            .resolve_decision_request(
                owner_session.session_id,
                decision.decision_request_id,
                decision.revision,
                DecisionState::Answered,
                "{}",
                43,
            )
            .await
            .unwrap();
        assert!(matches!(
            resolved,
            DecisionTransitionOutcome::Transitioned(_)
        ));
        assert!(
            db.decision_terminal_receipt(owner_session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .is_some()
        );

        // Legacy rows retain their previous lookup, list, and resolution
        // behavior; the new boundary does not turn the existing interrupt
        // queue into a decision-only API.
        let legacy_id = db
            .raise_interrupt(other_session.session_id, "root", "legacy", None)
            .await
            .unwrap();
        assert_eq!(
            db.get_interrupt(legacy_id)
                .await
                .unwrap()
                .unwrap()
                .session_id,
            other_session.session_id
        );
        assert_eq!(
            db.list_open_interrupts(other_session.session_id)
                .await
                .unwrap()
                .len(),
            1
        );
        db.resolve_interrupt(legacy_id, &ResolveResponse::Freetext { text: "ok".into() })
            .await
            .unwrap();
        assert_eq!(
            db.get_interrupt(legacy_id).await.unwrap().unwrap().state,
            crate::db::needs_attention::InterruptState::Resolved
        );
    }

    #[tokio::test]
    async fn agent_tree_complete_and_fail_refuse_live_owned_decisions_without_orphaning_attention()
    {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        for (offset, waiting_state, terminal_state) in [
            (
                0_i64,
                AgentInstanceState::WaitingForUser,
                AgentInstanceState::Completed,
            ),
            (
                20_i64,
                AgentInstanceState::WaitingForApproval,
                AgentInstanceState::Failed,
            ),
        ] {
            let agent = running_agent(&db, session.session_id, 100 + offset).await;
            let mut input =
                standard_decision(session.session_id, agent.agent_instance_id, agent.revision);
            input.waiting_state = waiting_state;
            let decision = db
                .create_decision_request(input, 102 + offset)
                .await
                .unwrap();
            let waiting_agent = db
                .agent_instance(session.session_id, agent.agent_instance_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(waiting_agent.state, waiting_state);

            let refused = db
                .transition_agent_instance(
                    session.session_id,
                    agent.agent_instance_id,
                    waiting_agent.revision,
                    terminal_state,
                    "{}",
                    103 + offset,
                )
                .await;
            assert!(
                refused
                    .unwrap_err()
                    .to_string()
                    .contains("owned decision remains live")
            );
            let still_waiting = db
                .agent_instance(session.session_id, agent.agent_instance_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                (still_waiting.state, still_waiting.revision),
                (waiting_state, waiting_agent.revision)
            );
            let decision_id = decision.decision_request_id;
            let (decision_state, attention_state): (String, String) = db
                .read(move |conn| {
                    let decision_state = conn.query_row(
                        "SELECT state FROM decision_requests WHERE decision_request_id = ?1",
                        [decision_id.to_string()],
                        |row| row.get(0),
                    )?;
                    let attention_state = conn.query_row(
                        "SELECT state FROM needs_attention WHERE decision_request_id = ?1",
                        [decision_id.to_string()],
                        |row| row.get(0),
                    )?;
                    Ok((decision_state, attention_state))
                })
                .await
                .unwrap();
            assert_eq!(
                (decision_state.as_str(), attention_state.as_str()),
                ("pending", "open")
            );

            // A resolver still owns the live request because the rejected
            // terminal transition left its owner and projection untouched.
            let late = db
                .resolve_decision_request(
                    session.session_id,
                    decision.decision_request_id,
                    decision.revision,
                    DecisionState::Answered,
                    "{}",
                    104 + offset,
                )
                .await
                .unwrap();
            assert!(matches!(late, DecisionTransitionOutcome::Transitioned(_)));
            let terminal = db
                .transition_agent_instance(
                    session.session_id,
                    agent.agent_instance_id,
                    waiting_agent.revision,
                    terminal_state,
                    "{}",
                    105 + offset,
                )
                .await
                .unwrap();
            assert!(matches!(terminal, AgentTransitionOutcome::Transitioned(_)));
        }
    }

    #[tokio::test]
    async fn agent_tree_rejects_children_for_every_terminal_parent_without_mutation() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        for (offset, terminal_state) in [
            (0_i64, AgentInstanceState::Completed),
            (10_i64, AgentInstanceState::Failed),
            (20_i64, AgentInstanceState::Cancelled),
        ] {
            let parent = running_agent(&db, session.session_id, 200 + offset).await;
            let parent = match db
                .transition_agent_instance(
                    session.session_id,
                    parent.agent_instance_id,
                    parent.revision,
                    terminal_state,
                    "{}",
                    202 + offset,
                )
                .await
                .unwrap()
            {
                AgentTransitionOutcome::Transitioned(row) => row,
                outcome => panic!("unexpected parent terminal outcome: {outcome:?}"),
            };
            let (instances_before, notices_before): (i64, i64) = db
                .read(move |conn| {
                    Ok((
                        conn.query_row(
                            "SELECT COUNT(*) FROM agent_instances WHERE session_id = ?1",
                            [session.session_id.to_string()],
                            |row| row.get(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM session_events WHERE session_id = ?1 AND type = 'notice'",
                            [session.session_id.to_string()],
                            |row| row.get(0),
                        )?,
                    ))
                })
                .await
                .unwrap();
            let refused = db
                .create_agent_instance(
                    NewAgentInstance {
                        session_id: session.session_id,
                        parent_agent_instance_id: Some(parent.agent_instance_id),
                        task_delegation_job_id: None,
                        task_delegation_child_uuid: None,
                        resolved_profile_snapshot_id: None,
                    },
                    203 + offset,
                )
                .await;
            assert!(refused.unwrap_err().to_string().contains("terminal parent"));
            let (instances_after, notices_after): (i64, i64) = db
                .read(move |conn| {
                    Ok((
                        conn.query_row(
                            "SELECT COUNT(*) FROM agent_instances WHERE session_id = ?1",
                            [session.session_id.to_string()],
                            |row| row.get(0),
                        )?,
                        conn.query_row(
                            "SELECT COUNT(*) FROM session_events WHERE session_id = ?1 AND type = 'notice'",
                            [session.session_id.to_string()],
                            |row| row.get(0),
                        )?,
                    ))
                })
                .await
                .unwrap();
            assert_eq!(
                (instances_after, notices_after),
                (instances_before, notices_before)
            );
            assert!(
                db.agent_instance_children(session.session_id, parent.agent_instance_id)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[tokio::test]
    async fn agent_tree_attention_requires_the_decision_owner_agent_on_insert_and_update() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let session_id = session.session_id;
        let owner = running_agent(&db, session.session_id, 300).await;
        let other = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                },
                302,
            )
            .await
            .unwrap();
        let decision = db
            .create_decision_request(
                standard_decision(session.session_id, owner.agent_instance_id, owner.revision),
                303,
            )
            .await
            .unwrap();
        let decision_id = decision.decision_request_id;
        let normal_owner: String = db
            .read(move |conn| {
                let agent_id = conn.query_row(
                    "SELECT agent_id FROM needs_attention WHERE decision_request_id = ?1",
                    [decision_id.to_string()],
                    |row| row.get(0),
                )?;
                Ok(agent_id)
            })
            .await
            .unwrap();
        assert_eq!(normal_owner, owner.agent_instance_id.to_string());

        let insert_id = Uuid::new_v4().to_string();
        let decision_id = decision_id.to_string();
        let other_id = other.agent_instance_id.to_string();
        let cross_agent_insert = db
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO needs_attention (
                         interrupt_id, session_id, agent_id, description, state, raised_at,
                         decision_request_id
                     ) VALUES (?1, ?2, ?3, 'wrong owner', 'open', 304, ?4)",
                    params![insert_id, session_id.to_string(), other_id, decision_id],
                )?;
                Ok(())
            })
            .await;
        assert!(
            cross_agent_insert
                .unwrap_err()
                .to_string()
                .contains("session mismatch")
        );

        let legacy_id = Uuid::new_v4().to_string();
        let legacy_id_for_insert = legacy_id.clone();
        let other_id = other.agent_instance_id.to_string();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO needs_attention (
                     interrupt_id, session_id, agent_id, description, state, raised_at
                 ) VALUES (?1, ?2, ?3, 'legacy', 'open', 305)",
                params![legacy_id_for_insert, session_id.to_string(), other_id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let update_id = legacy_id;
        let decision_id = decision.decision_request_id.to_string();
        let cross_agent_update = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE needs_attention SET decision_request_id = ?1 WHERE interrupt_id = ?2",
                    params![decision_id, update_id],
                )?;
                Ok(())
            })
            .await;
        assert!(
            cross_agent_update
                .unwrap_err()
                .to_string()
                .contains("session mismatch")
        );
    }

    #[test]
    fn agent_tree_state_graphs_are_closed_and_exhaustive() {
        let agent_states = [
            AgentInstanceState::Created,
            AgentInstanceState::Running,
            AgentInstanceState::WaitingForUser,
            AgentInstanceState::WaitingForApproval,
            AgentInstanceState::Completed,
            AgentInstanceState::Failed,
            AgentInstanceState::Cancelled,
        ];
        for current in agent_states {
            for next in agent_states {
                let expected = matches!(
                    (current, next),
                    (AgentInstanceState::Created, AgentInstanceState::Running)
                        | (
                            AgentInstanceState::Running,
                            AgentInstanceState::WaitingForUser
                                | AgentInstanceState::WaitingForApproval
                                | AgentInstanceState::Completed
                                | AgentInstanceState::Failed
                                | AgentInstanceState::Cancelled
                        )
                        | (
                            AgentInstanceState::WaitingForUser
                                | AgentInstanceState::WaitingForApproval,
                            AgentInstanceState::Running
                                | AgentInstanceState::Completed
                                | AgentInstanceState::Failed
                                | AgentInstanceState::Cancelled
                        )
                );
                assert_eq!(
                    current.legal_transition(next),
                    expected,
                    "{current:?} -> {next:?}"
                );
            }
        }
        let decision_states = [
            DecisionState::Pending,
            DecisionState::Resolving,
            DecisionState::Answered,
            DecisionState::AutoResolved,
            DecisionState::TimedOut,
            DecisionState::Cancelled,
        ];
        for current in decision_states {
            for next in decision_states {
                let expected = matches!(
                    (current, next),
                    (
                        DecisionState::Pending,
                        DecisionState::Resolving
                            | DecisionState::Answered
                            | DecisionState::Cancelled
                            | DecisionState::TimedOut
                    ) | (
                        DecisionState::Resolving,
                        DecisionState::Answered
                            | DecisionState::AutoResolved
                            | DecisionState::Cancelled
                            | DecisionState::TimedOut
                    )
                );
                assert_eq!(
                    current.legal_transition(next),
                    expected,
                    "{current:?} -> {next:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn agent_tree_decisions_redact_contracts_and_atomically_own_attention() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 100).await;
        let secret = "credential: should-never-persist";
        let decision = db
            .create_decision_request(
                NewDecisionRequest {
                    session_id: session.session_id,
                    agent_instance_id: agent.agent_instance_id,
                    expected_agent_revision: agent.revision,
                    waiting_state: AgentInstanceState::WaitingForUser,
                    options_contract_json: r#"[{"id":"approve","label":"Approve"}]"#.into(),
                    free_text_contract_json: Some(r#"{"allowed":true,"max_chars":240}"#.into()),
                    recommendation_json: Some(r#"{"option_id":"approve"}"#.into()),
                    rationale_redaction_class: "secret".into(),
                    deadline_unix_ms: Some(999),
                    policy_receipt_json: r#"{"policy":"manual","receipt_id":"policy-1"}"#.into(),
                    resolver_route: Some("user".into()),
                },
                102,
            )
            .await
            .unwrap();
        assert_eq!(decision.state, DecisionState::Pending);
        assert!(!format!("{decision:?}").contains(secret));
        assert!(decision.options_contract_json.contains("approve"));
        assert!(
            decision
                .free_text_contract_json
                .as_deref()
                .unwrap()
                .contains("max_chars")
        );
        assert!(
            decision
                .recommendation_json
                .as_deref()
                .unwrap()
                .contains("approve")
        );
        assert!(decision.policy_receipt_json.contains("policy-1"));
        let decision_id = decision.decision_request_id;
        let (attention_count, legacy_count, event_count): (i64, i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM needs_attention WHERE decision_request_id = ?1",
                        [decision_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM needs_attention
                         WHERE decision_request_id = ?1 AND (
                           question_json IS NOT NULL OR questions_json IS NOT NULL OR
                           parked_tool IS NOT NULL OR parked_args_json IS NOT NULL OR
                           parked_call_id IS NOT NULL OR parked_resume_json IS NOT NULL OR
                           parked_gate_json IS NOT NULL
                         )",
                        [decision_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM session_events WHERE session_id = ?1 AND type = 'notice'",
                        [session.session_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((attention_count, legacy_count, event_count), (1, 0, 3));

        let answer_payload = format!(r#"{{"answer":"{secret}"}}"#);
        let answer = db
            .resolve_decision_request(
                session.session_id,
                decision_id,
                decision.revision,
                DecisionState::Answered,
                &answer_payload,
                103,
            )
            .await
            .unwrap();
        let resolved = match answer {
            DecisionTransitionOutcome::Transitioned(row) => row,
            outcome => panic!("unexpected resolution: {outcome:?}"),
        };
        assert_eq!(resolved.state, DecisionState::Answered);
        let replay = db
            .resolve_decision_request(
                session.session_id,
                decision_id,
                0,
                DecisionState::Cancelled,
                "{}",
                104,
            )
            .await
            .unwrap();
        match replay {
            DecisionTransitionOutcome::AlreadyTerminal(receipt) => {
                assert_eq!(receipt.terminal_state, "answered");
                assert!(!receipt.receipt_json.contains(secret));
                assert!(receipt.session_event_seq.is_some());
            }
            outcome => panic!("terminal receipt must win: {outcome:?}"),
        }
        let immutable_id = decision_id.to_string();
        let immutable = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE decision_receipts SET receipt_json = '{}' WHERE decision_request_id = ?1",
                    [immutable_id],
                )?;
                Ok(())
        })
        .await;
        assert!(immutable.unwrap_err().to_string().contains("immutable"));
        let other_session = db.create_session("other", "/other", "root").await.unwrap();
        let mismatch_decision = decision_id.to_string();
        let mismatch = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE needs_attention SET session_id = ?1 WHERE decision_request_id = ?2",
                    params![other_session.session_id.to_string(), mismatch_decision],
                )?;
                Ok(())
            })
            .await;
        let error = mismatch.unwrap_err().to_string();
        assert!(
            error.contains("session mismatch") || error.contains("decision-owned"),
            "decision ownership and same-session checks must both reject mutation: {error}"
        );
    }

    #[tokio::test]
    async fn agent_tree_parent_terminal_rules_cas_and_cancellation_cascade() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let parent = running_agent(&db, session.session_id, 100).await;
        let child = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: Some(parent.agent_instance_id),
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                },
                102,
            )
            .await
            .unwrap();
        let complete = db
            .transition_agent_instance(
                session.session_id,
                parent.agent_instance_id,
                parent.revision,
                AgentInstanceState::Completed,
                "{}",
                103,
            )
            .await;
        assert!(complete.unwrap_err().to_string().contains("descendant"));
        let cancelled = db
            .transition_agent_instance(
                session.session_id,
                parent.agent_instance_id,
                parent.revision,
                AgentInstanceState::Cancelled,
                "{}",
                104,
            )
            .await
            .unwrap();
        assert!(matches!(cancelled, AgentTransitionOutcome::Transitioned(_)));
        let child = db
            .agent_instance(session.session_id, child.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(child.state, AgentInstanceState::Cancelled);
        assert_eq!(child.revision, 1);
        let replay = db
            .transition_agent_instance(
                session.session_id,
                parent.agent_instance_id,
                0,
                AgentInstanceState::Running,
                "{}",
                105,
            )
            .await
            .unwrap();
        assert!(matches!(replay, AgentTransitionOutcome::AlreadyTerminal(_)));
    }

    #[tokio::test]
    async fn agent_tree_cancellation_terminalizes_root_and_descendant_decisions_before_agent_receipts()
     {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let root = running_agent(&db, session.session_id, 10).await;
        let child = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: Some(root.agent_instance_id),
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                },
                12,
            )
            .await
            .unwrap();
        let child = match db
            .transition_agent_instance(
                session.session_id,
                child.agent_instance_id,
                child.revision,
                AgentInstanceState::Running,
                "{}",
                13,
            )
            .await
            .unwrap()
        {
            AgentTransitionOutcome::Transitioned(row) => row,
            outcome => panic!("unexpected child start: {outcome:?}"),
        };
        let child_decision = db
            .create_decision_request(
                NewDecisionRequest {
                    session_id: session.session_id,
                    agent_instance_id: child.agent_instance_id,
                    expected_agent_revision: child.revision,
                    waiting_state: AgentInstanceState::WaitingForUser,
                    options_contract_json: "[]".into(),
                    free_text_contract_json: None,
                    recommendation_json: None,
                    rationale_redaction_class: "public".into(),
                    deadline_unix_ms: None,
                    policy_receipt_json: "{}".into(),
                    resolver_route: Some("user".into()),
                },
                14,
            )
            .await
            .unwrap();
        let root_decision = db
            .create_decision_request(
                NewDecisionRequest {
                    session_id: session.session_id,
                    agent_instance_id: root.agent_instance_id,
                    expected_agent_revision: root.revision,
                    waiting_state: AgentInstanceState::WaitingForApproval,
                    options_contract_json: "[]".into(),
                    free_text_contract_json: None,
                    recommendation_json: None,
                    rationale_redaction_class: "public".into(),
                    deadline_unix_ms: None,
                    policy_receipt_json: "{}".into(),
                    resolver_route: Some("utility".into()),
                },
                15,
            )
            .await
            .unwrap();
        let cancelled = db
            .transition_agent_instance(
                session.session_id,
                root.agent_instance_id,
                root.revision + 1,
                AgentInstanceState::Cancelled,
                "{}",
                16,
            )
            .await
            .unwrap();
        assert!(matches!(cancelled, AgentTransitionOutcome::Transitioned(_)));
        for decision_id in [
            root_decision.decision_request_id,
            child_decision.decision_request_id,
        ] {
            let decision = db
                .decision_request(session.session_id, decision_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(decision.state, DecisionState::Cancelled);
            let receipt = db
                .decision_terminal_receipt(session.session_id, decision_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(receipt.terminal_state, "cancelled");
            let late = db
                .resolve_decision_request(
                    session.session_id,
                    decision_id,
                    0,
                    DecisionState::Answered,
                    "{}",
                    17,
                )
                .await
                .unwrap();
            assert!(matches!(
                late,
                DecisionTransitionOutcome::AlreadyTerminal(_)
            ));
        }
        let (receipts, resolved_attention): (i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM decision_receipts WHERE session_id = ?1",
                        [session.session_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM needs_attention
                         WHERE session_id = ?1 AND decision_request_id IS NOT NULL AND state = 'resolved'",
                        [session.session_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((receipts, resolved_attention), (2, 2));
    }

    #[tokio::test]
    async fn agent_tree_separate_connections_have_one_mapping_and_decision_cas_winner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-tree-race.sqlite");
        let (
            session_id,
            other_session_id,
            child_uuid,
            decision_id,
            terminal_agent_id,
            terminal_agent_revision,
        ) = {
            let db = Db::open(&path).unwrap();
            let session = db.create_session("p", "/workspace", "root").await.unwrap();
            let other = db.create_session("other", "/other", "root").await.unwrap();
            let children = [DelegationChildInit {
                label: "worker",
                child_agent: "worker",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            }];
            db.upsert_task_delegation_job(
                session.session_id,
                "task-race",
                None,
                "root",
                None,
                &children,
            )
            .await
            .unwrap();
            let child_uuid: String = db
                .read(|conn| {
                    let child_uuid = conn.query_row(
                        "SELECT child_uuid FROM task_delegation_children
                         WHERE task_call_id = 'task-race' AND label = 'worker'",
                        [],
                        |row| row.get(0),
                    )?;
                    Ok(child_uuid)
                })
                .await
                .unwrap();
            let agent = running_agent(&db, session.session_id, 10).await;
            let decision = db
                .create_decision_request(
                    NewDecisionRequest {
                        session_id: session.session_id,
                        agent_instance_id: agent.agent_instance_id,
                        expected_agent_revision: agent.revision,
                        waiting_state: AgentInstanceState::WaitingForUser,
                        options_contract_json: "[]".into(),
                        free_text_contract_json: None,
                        recommendation_json: None,
                        rationale_redaction_class: "public".into(),
                        deadline_unix_ms: None,
                        policy_receipt_json: "{}".into(),
                        resolver_route: Some("user".into()),
                    },
                    12,
                )
                .await
                .unwrap();
            let terminal_agent = running_agent(&db, session.session_id, 14).await;
            (
                session.session_id,
                other.session_id,
                Uuid::parse_str(&child_uuid).unwrap(),
                decision.decision_request_id,
                terminal_agent.agent_instance_id,
                terminal_agent.revision,
            )
        };
        let first = Db::open(&path).unwrap();
        let second = Db::open(&path).unwrap();
        let left = first.create_agent_instance(
            NewAgentInstance {
                session_id,
                parent_agent_instance_id: None,
                task_delegation_job_id: Some("task-race".into()),
                task_delegation_child_uuid: Some(child_uuid),
                resolved_profile_snapshot_id: None,
            },
            20,
        );
        let right = second.create_agent_instance(
            NewAgentInstance {
                session_id,
                parent_agent_instance_id: None,
                task_delegation_job_id: Some("task-race".into()),
                task_delegation_child_uuid: Some(child_uuid),
                resolved_profile_snapshot_id: None,
            },
            20,
        );
        let (left, right) = tokio::join!(left, right);
        assert_eq!(
            [left.is_ok(), right.is_ok()]
                .into_iter()
                .filter(|success| *success)
                .count(),
            1
        );
        let first = Db::open(&path).unwrap();
        let second = Db::open(&path).unwrap();
        let (session_left, session_right) = tokio::join!(
            first.create_session("concurrent-a", "/concurrent-a", "root"),
            second.create_session("concurrent-b", "/concurrent-b", "root"),
        );
        assert_ne!(
            session_left.unwrap().session_id,
            session_right.unwrap().session_id,
            "independent daemon connections must not collapse concurrent session starts"
        );
        let first = Db::open(&path).unwrap();
        let second = Db::open(&path).unwrap();
        let complete = first.transition_agent_instance(
            session_id,
            terminal_agent_id,
            terminal_agent_revision,
            AgentInstanceState::Completed,
            "{}",
            20,
        );
        let fail = second.transition_agent_instance(
            session_id,
            terminal_agent_id,
            terminal_agent_revision,
            AgentInstanceState::Failed,
            "{}",
            20,
        );
        let (complete, fail) = tokio::join!(complete, fail);
        let agent_outcomes = [complete.unwrap(), fail.unwrap()];
        assert_eq!(
            agent_outcomes
                .iter()
                .filter(|outcome| matches!(outcome, AgentTransitionOutcome::Transitioned(_)))
                .count(),
            1
        );
        assert!(agent_outcomes.iter().any(|outcome| matches!(
            outcome,
            AgentTransitionOutcome::AlreadyTerminal(_) | AgentTransitionOutcome::RevisionConflict
        )));
        let verify_agent = Db::open(&path).unwrap();
        let terminal_agent = verify_agent
            .agent_instance(session_id, terminal_agent_id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            terminal_agent.state,
            AgentInstanceState::Completed | AgentInstanceState::Failed
        ));
        assert_eq!(terminal_agent.revision, terminal_agent_revision + 1);
        let (agent_receipts, terminal_events): (i64, i64) = verify_agent
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM agent_transition_receipts
                         WHERE agent_instance_id = ?1 AND session_id = ?2",
                        params![terminal_agent_id.to_string(), session_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM session_events
                         WHERE session_id = ?1 AND type = 'notice'
                           AND json_extract(data_json, '$.subject_id') = ?2
                           AND json_extract(data_json, '$.state') IN ('completed', 'failed')",
                        params![session_id.to_string(), terminal_agent_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((agent_receipts, terminal_events), (1, 1));
        assert!(
            verify_agent
                .agent_instance(other_session_id, terminal_agent_id)
                .await
                .unwrap()
                .is_none()
        );
        let first = Db::open(&path).unwrap();
        let second = Db::open(&path).unwrap();
        let answer = first.resolve_decision_request(
            session_id,
            decision_id,
            0,
            DecisionState::Answered,
            "{}",
            21,
        );
        let timeout = second.resolve_decision_request(
            session_id,
            decision_id,
            0,
            DecisionState::TimedOut,
            "{}",
            21,
        );
        let (answer, timeout) = tokio::join!(answer, timeout);
        let outcomes = [answer.unwrap(), timeout.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, DecisionTransitionOutcome::Transitioned(_)))
                .count(),
            1
        );
        let verify = Db::open(&path).unwrap();
        let (receipts, events): (i64, i64) = verify
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM decision_receipts WHERE decision_request_id = ?1",
                        [decision_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM session_events
                         WHERE session_id = ?1 AND type = 'notice' AND json_extract(data_json, '$.subject_id') = ?2",
                        params![session_id.to_string(), decision_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((receipts, events), (1, 2)); // pending notice + exactly one terminal notice
        assert!(
            verify
                .decision_request(other_session_id, decision_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn agent_tree_decision_terminal_cas_has_one_winner_for_user_timeout_cancel_and_utility() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        for (offset, terminal) in [
            DecisionState::Answered,
            DecisionState::TimedOut,
            DecisionState::Cancelled,
        ]
        .into_iter()
        .enumerate()
        {
            let agent = running_agent(&db, session.session_id, 100 + offset as i64 * 10).await;
            let decision = db
                .create_decision_request(
                    NewDecisionRequest {
                        session_id: session.session_id,
                        agent_instance_id: agent.agent_instance_id,
                        expected_agent_revision: agent.revision,
                        waiting_state: AgentInstanceState::WaitingForUser,
                        options_contract_json: "[]".into(),
                        free_text_contract_json: None,
                        recommendation_json: None,
                        rationale_redaction_class: "public".into(),
                        deadline_unix_ms: None,
                        policy_receipt_json: "{}".into(),
                        resolver_route: Some("user".into()),
                    },
                    102 + offset as i64 * 10,
                )
                .await
                .unwrap();
            let won = db
                .resolve_decision_request(
                    session.session_id,
                    decision.decision_request_id,
                    0,
                    terminal,
                    "{}",
                    103 + offset as i64 * 10,
                )
                .await
                .unwrap();
            assert!(matches!(won, DecisionTransitionOutcome::Transitioned(_)));
            let late = db
                .resolve_decision_request(
                    session.session_id,
                    decision.decision_request_id,
                    0,
                    DecisionState::Answered,
                    "{}",
                    104 + offset as i64 * 10,
                )
                .await
                .unwrap();
            assert!(matches!(
                late,
                DecisionTransitionOutcome::AlreadyTerminal(_)
            ));
        }
        let agent = running_agent(&db, session.session_id, 200).await;
        let decision = db
            .create_decision_request(
                NewDecisionRequest {
                    session_id: session.session_id,
                    agent_instance_id: agent.agent_instance_id,
                    expected_agent_revision: agent.revision,
                    waiting_state: AgentInstanceState::WaitingForApproval,
                    options_contract_json: "[]".into(),
                    free_text_contract_json: None,
                    recommendation_json: None,
                    rationale_redaction_class: "public".into(),
                    deadline_unix_ms: None,
                    policy_receipt_json: "{}".into(),
                    resolver_route: Some("utility".into()),
                },
                202,
            )
            .await
            .unwrap();
        let claim = db
            .claim_decision_request(session.session_id, decision.decision_request_id, 0, 203)
            .await
            .unwrap();
        assert!(matches!(claim, DecisionTransitionOutcome::Transitioned(_)));
        let utility = db
            .resolve_decision_request(
                session.session_id,
                decision.decision_request_id,
                1,
                DecisionState::AutoResolved,
                "{}",
                204,
            )
            .await
            .unwrap();
        assert!(matches!(
            utility,
            DecisionTransitionOutcome::Transitioned(_)
        ));
        let late_user = db
            .resolve_decision_request(
                session.session_id,
                decision.decision_request_id,
                1,
                DecisionState::Answered,
                "{}",
                205,
            )
            .await
            .unwrap();
        assert!(matches!(
            late_user,
            DecisionTransitionOutcome::AlreadyTerminal(_)
        ));
    }

    #[tokio::test]
    async fn agent_tree_lineage_rejects_cross_session_child_mapping_and_keeps_child_uuid_stable() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_session("a", "/a", "root").await.unwrap();
        let b = db.create_session("b", "/b", "root").await.unwrap();
        let children = [DelegationChildInit {
            label: "worker",
            child_agent: "worker",
            model: None,
            output_dir: None,
            requested_cwd: None,
            resolved_cwd: None,
            todo_ids_json: None,
        }];
        db.upsert_task_delegation_job(a.session_id, "task-1", None, "root", None, &children)
            .await
            .unwrap();
        let child_uuid: String = db
            .read(|conn| {
                let child_uuid = conn.query_row(
                    "SELECT child_uuid FROM task_delegation_children WHERE task_call_id = 'task-1' AND label = 'worker'",
                    [],
                    |row| row.get(0),
                )?;
                Ok(child_uuid)
            })
            .await
            .unwrap();
        db.upsert_task_delegation_job(a.session_id, "task-1", None, "root", None, &children)
            .await
            .unwrap();
        let repeated_uuid: String = db
            .read(|conn| {
                let child_uuid = conn.query_row(
                    "SELECT child_uuid FROM task_delegation_children WHERE task_call_id = 'task-1' AND label = 'worker'",
                    [],
                    |row| row.get(0),
                )?;
                Ok(child_uuid)
            })
            .await
            .unwrap();
        assert_eq!(child_uuid, repeated_uuid);
        let child_uuid = Uuid::parse_str(&child_uuid).unwrap();
        let error = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: b.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: Some("task-1".into()),
                    task_delegation_child_uuid: Some(child_uuid),
                    resolved_profile_snapshot_id: None,
                },
                10,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not authorized"));
        let allowed = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: a.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: Some("task-1".into()),
                    task_delegation_child_uuid: Some(child_uuid),
                    resolved_profile_snapshot_id: None,
                },
                11,
            )
            .await
            .unwrap();
        assert_eq!(allowed.task_delegation_child_uuid, Some(child_uuid));
        let before_cross_session_upsert: (String, String, String) = db
            .read(|conn| {
                let row = conn.query_row(
                    "SELECT j.parent_session_id, c.child_uuid, c.child_agent
                     FROM task_delegation_jobs j
                     JOIN task_delegation_children c ON c.task_call_id = j.task_call_id
                     WHERE j.task_call_id = 'task-1' AND c.label = 'worker'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                Ok(row)
            })
            .await
            .unwrap();
        let hostile_children = [DelegationChildInit {
            label: "worker",
            child_agent: "other-agent",
            model: None,
            output_dir: None,
            requested_cwd: None,
            resolved_cwd: None,
            todo_ids_json: None,
        }];
        let refused = db
            .upsert_task_delegation_job(
                b.session_id,
                "task-1",
                None,
                "other",
                None,
                &hostile_children,
            )
            .await;
        assert!(
            refused
                .unwrap_err()
                .to_string()
                .contains("belongs to another session")
        );
        let after_cross_session_upsert: (String, String, String) = db
            .read(|conn| {
                let row = conn.query_row(
                    "SELECT j.parent_session_id, c.child_uuid, c.child_agent
                     FROM task_delegation_jobs j
                     JOIN task_delegation_children c ON c.task_call_id = j.task_call_id
                     WHERE j.task_call_id = 'task-1' AND c.label = 'worker'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                Ok(row)
            })
            .await
            .unwrap();
        assert_eq!(after_cross_session_upsert, before_cross_session_upsert);
        assert_eq!(
            db.agent_instance(a.session_id, allowed.agent_instance_id)
                .await
                .unwrap()
                .unwrap()
                .task_delegation_child_uuid,
            Some(child_uuid)
        );
    }

    #[tokio::test]
    async fn agent_tree_cross_session_task_upsert_race_has_one_exact_owner_and_payload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("delegation-owner-race.sqlite");
        let (session_a, session_b) = {
            let db = Db::open(&path).unwrap();
            let a = db.create_session("a", "/a", "root-a").await.unwrap();
            let b = db.create_session("b", "/b", "root-b").await.unwrap();
            (a.session_id, b.session_id)
        };

        let first = Db::open(&path).unwrap();
        let second = Db::open(&path).unwrap();
        let children_a = [DelegationChildInit {
            label: "worker",
            child_agent: "winner-a-child",
            model: Some("model-a"),
            output_dir: None,
            requested_cwd: None,
            resolved_cwd: None,
            todo_ids_json: None,
        }];
        let children_b = [DelegationChildInit {
            label: "worker",
            child_agent: "winner-b-child",
            model: Some("model-b"),
            output_dir: None,
            requested_cwd: None,
            resolved_cwd: None,
            todo_ids_json: None,
        }];
        let left = first.upsert_task_delegation_job_and_payload(
            TaskDelegationJobUpsert {
                session_id: session_a,
                task_call_id: "same-task",
                function_call_id: Some("call-a"),
                parent_agent: "winner-a-parent",
                original_args_json: Some(r#"{"winner":"a"}"#),
                children: &children_a,
            },
            NewTaskDelegationPayload {
                task_call_id: "same-task",
                function_call_id: Some("call-a"),
                parent_session_id: session_a,
                parent_agent: "winner-a-parent",
                label: "worker",
                child_agent: "winner-a-child",
                prompt: "winner a payload",
            },
        );
        let right = second.upsert_task_delegation_job_and_payload(
            TaskDelegationJobUpsert {
                session_id: session_b,
                task_call_id: "same-task",
                function_call_id: Some("call-b"),
                parent_agent: "winner-b-parent",
                original_args_json: Some(r#"{"winner":"b"}"#),
                children: &children_b,
            },
            NewTaskDelegationPayload {
                task_call_id: "same-task",
                function_call_id: Some("call-b"),
                parent_session_id: session_b,
                parent_agent: "winner-b-parent",
                label: "worker",
                child_agent: "winner-b-child",
                prompt: "winner b payload",
            },
        );
        let (left, right) = tokio::join!(left, right);
        assert_eq!(
            [left.is_ok(), right.is_ok()]
                .into_iter()
                .filter(|success| *success)
                .count(),
            1,
            "only one session may create a task-call-id owner"
        );
        let winning = if left.is_ok() {
            (
                session_a,
                session_b,
                "winner-a-parent",
                "winner-a-child",
                "model-a",
                "winner a payload",
            )
        } else {
            assert!(right.is_ok());
            (
                session_b,
                session_a,
                "winner-b-parent",
                "winner-b-child",
                "model-b",
                "winner b payload",
            )
        };
        let losing_error = match (left, right) {
            (Err(error), _) | (_, Err(error)) => error,
            (Ok(_), Ok(_)) => panic!("one concurrent insert must lose"),
        };
        assert!(
            losing_error
                .to_string()
                .contains("belongs to another session")
        );

        let verify = Db::open(&path).unwrap();
        let (owner, parent, child, model, child_count, payload_count): (
            String,
            String,
            String,
            Option<String>,
            i64,
            i64,
        ) = verify
            .read(|conn| {
                let (owner, parent) = conn.query_row(
                    "SELECT parent_session_id, parent_agent
                     FROM task_delegation_jobs WHERE task_call_id = 'same-task'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                let (child, model) = conn.query_row(
                    "SELECT child_agent, model FROM task_delegation_children
                     WHERE task_call_id = 'same-task' AND label = 'worker'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                Ok((
                    owner,
                    parent,
                    child,
                    model,
                    conn.query_row(
                        "SELECT COUNT(*) FROM task_delegation_children
                         WHERE task_call_id = 'same-task'",
                        [],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM task_delegation_payloads
                         WHERE task_call_id = 'same-task'",
                        [],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(owner, winning.0.to_string());
        assert_eq!(parent, winning.2);
        assert_eq!(child, winning.3);
        assert_eq!(model.as_deref(), Some(winning.4));
        assert_eq!((child_count, payload_count), (1, 1));
        let payload_row = verify
            .task_delegation_payload("same-task", "worker")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload_row.parent_session_id, winning.0);
        assert_eq!(payload_row.parent_agent, winning.2);
        assert_eq!(payload_row.child_agent, winning.3);
        let payload = verify
            .load_task_delegation_payload("same-task", "worker")
            .await
            .unwrap();
        assert_eq!(payload.body, winning.5);
        assert!(
            verify
                .list_task_delegation_children(winning.1)
                .await
                .unwrap()
                .is_empty(),
            "the losing session must have no visible job or child mutation"
        );
    }

    #[tokio::test]
    async fn agent_tree_decision_rejects_invalid_redaction_input_before_mutation() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 1).await;
        let error = db
            .create_decision_request(
                NewDecisionRequest {
                    session_id: session.session_id,
                    agent_instance_id: agent.agent_instance_id,
                    expected_agent_revision: agent.revision,
                    waiting_state: AgentInstanceState::WaitingForUser,
                    options_contract_json:
                        r#"[{"id":"approve","label":"Approve","credential":"never-store"}]"#.into(),
                    free_text_contract_json: None,
                    recommendation_json: None,
                    rationale_redaction_class: "secret".into(),
                    deadline_unix_ms: None,
                    policy_receipt_json: "{}".into(),
                    resolver_route: Some("user".into()),
                },
                2,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unapproved"));
        let after = db
            .agent_instance(session.session_id, agent.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.state, AgentInstanceState::Running);
        assert_eq!(after.revision, agent.revision);
    }

    #[tokio::test]
    async fn agent_tree_nonterminal_events_are_once_ordered_and_conflicts_are_silent() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 1).await;
        let conflict = db
            .transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                0,
                AgentInstanceState::WaitingForUser,
                "{}",
                2,
            )
            .await
            .unwrap();
        assert!(matches!(conflict, AgentTransitionOutcome::RevisionConflict));
        let decision = db
            .create_decision_request(
                NewDecisionRequest {
                    session_id: session.session_id,
                    agent_instance_id: agent.agent_instance_id,
                    expected_agent_revision: agent.revision,
                    waiting_state: AgentInstanceState::WaitingForUser,
                    options_contract_json: r#"[{"id":"approve","label":"Approve"}]"#.into(),
                    free_text_contract_json: None,
                    recommendation_json: None,
                    rationale_redaction_class: "public".into(),
                    deadline_unix_ms: None,
                    policy_receipt_json: "{}".into(),
                    resolver_route: Some("user".into()),
                },
                3,
            )
            .await
            .unwrap();
        let claim = db
            .claim_decision_request(session.session_id, decision.decision_request_id, 0, 4)
            .await
            .unwrap();
        assert!(matches!(claim, DecisionTransitionOutcome::Transitioned(_)));
        let events: Vec<(String, String)> = db
            .read(move |conn| {
                let mut statement = conn.prepare(
                    "SELECT json_extract(data_json, '$.kind'), json_extract(data_json, '$.state')
                     FROM session_events WHERE session_id = ?1 AND type = 'notice' ORDER BY seq",
                )?;
                let events = statement
                    .query_map([session.session_id.to_string()], |row| {
                        Ok((row.get(0)?, row.get(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(events)
            })
            .await
            .unwrap();
        assert_eq!(
            events,
            vec![
                ("agent_transition".into(), "running".into()),
                ("agent_transition".into(), "waiting_for_user".into()),
                ("decision_pending".into(), "pending".into()),
                ("decision_transition".into(), "resolving".into()),
            ]
        );
    }

    #[tokio::test]
    async fn agent_tree_redacted_contracts_survive_restart_without_raw_context() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-tree-contract.sqlite");
        let (session_id, decision_id) = {
            let db = Db::open(&path).unwrap();
            let session = db.create_session("p", "/workspace", "root").await.unwrap();
            let agent = running_agent(&db, session.session_id, 1).await;
            let decision = db
                .create_decision_request(
                    NewDecisionRequest {
                        session_id: session.session_id,
                        agent_instance_id: agent.agent_instance_id,
                        expected_agent_revision: agent.revision,
                        waiting_state: AgentInstanceState::WaitingForUser,
                        options_contract_json: r#"[{"id":"approve","label":"Approve"}]"#.into(),
                        free_text_contract_json: Some(r#"{"allowed":true,"max_chars":120}"#.into()),
                        recommendation_json: Some(r#"{"option_id":"approve"}"#.into()),
                        rationale_redaction_class: "sensitive".into(),
                        deadline_unix_ms: Some(99),
                        policy_receipt_json: r#"{"policy":"manual","receipt_id":"receipt-1"}"#
                            .into(),
                        resolver_route: Some("user".into()),
                    },
                    3,
                )
                .await
                .unwrap();
            (session.session_id, decision.decision_request_id)
        };
        let reopened = Db::open(&path).unwrap();
        let decision = reopened
            .decision_request(session_id, decision_id)
            .await
            .unwrap()
            .unwrap();
        let options: serde_json::Value =
            serde_json::from_str(&decision.options_contract_json).unwrap();
        assert_eq!(options["options"][0]["id"], "approve");
        assert_eq!(options["options"][0]["label"], "Approve");
        assert_eq!(options["redacted"], true);
        assert!(
            decision
                .free_text_contract_json
                .as_deref()
                .unwrap()
                .contains("max_chars")
        );
        let recommendation: serde_json::Value =
            serde_json::from_str(decision.recommendation_json.as_deref().unwrap()).unwrap();
        assert_eq!(recommendation["option_id"], "approve");
        assert!(decision.policy_receipt_json.contains("receipt-1"));
        assert!(!format!("{decision:?}").contains("credential"));
    }

    #[tokio::test]
    async fn agent_tree_transaction_rollback_and_restart_keep_only_committed_terminal_receipts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent-tree.sqlite");
        let (session_id, agent_instance_id) = {
            let db = Db::open(&path).unwrap();
            let session = db.create_session("p", "/workspace", "root").await.unwrap();
            let agent = db
                .create_agent_instance(
                    NewAgentInstance {
                        session_id: session.session_id,
                        parent_agent_instance_id: None,
                        task_delegation_job_id: None,
                        task_delegation_child_uuid: None,
                        resolved_profile_snapshot_id: None,
                    },
                    1,
                )
                .await
                .unwrap();
            let rollback_session = session.session_id.to_string();
            let rollback_agent = agent.agent_instance_id.to_string();
            let rolled_back = db
                .transaction(move |conn| -> Result<()> {
                    conn.execute(
                        "UPDATE agent_instances SET state = 'running', revision = 1
                         WHERE session_id = ?1 AND agent_instance_id = ?2",
                        params![rollback_session, rollback_agent],
                    )?;
                    Err(anyhow::anyhow!("forced rollback"))
                })
                .await;
            assert!(rolled_back.is_err());
            let unchanged = db
                .agent_instance(session.session_id, agent.agent_instance_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(unchanged.state, AgentInstanceState::Created);
            let terminal = db
                .transition_agent_instance(
                    session.session_id,
                    agent.agent_instance_id,
                    0,
                    AgentInstanceState::Running,
                    "{}",
                    2,
                )
                .await
                .unwrap();
            let terminal = match terminal {
                AgentTransitionOutcome::Transitioned(row) => row,
                outcome => panic!("unexpected transition: {outcome:?}"),
            };
            db.transition_agent_instance(
                session.session_id,
                terminal.agent_instance_id,
                terminal.revision,
                AgentInstanceState::Completed,
                "{}",
                3,
            )
            .await
            .unwrap();
            (session.session_id, agent.agent_instance_id)
        };
        let reopened = Db::open(&path).unwrap();
        let receipt = reopened
            .agent_terminal_receipt(session_id, agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.terminal_state, "completed");
        assert!(receipt.session_event_seq.is_some());
    }
}
