//! Durable recursive-agent and user-decision control state.
//!
//! This module is deliberately a daemon boundary: callers supply the owning
//! session on every read and mutation, and it persists only redacted summaries
//! of decision contracts and receipts. Live prompts, credentials, provider
//! handles, and resolver context never cross this boundary.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::Db;
use crate::db::agent_installations::{RedactedAgentProfileSnapshot, RedactedQuestionPolicy};
use crate::db::wire::{InterruptQuestion, InterruptQuestionSet};

/// Opaque authority required to terminalize a host-approval decision.
///
/// There is deliberately no safe constructor.  The daemon composition layer
/// owns the one internal bridge for this zero-sized marker; ordinary storage
/// callers cannot manufacture it merely by holding a [`Db`] handle.  The
/// marker is only a call-graph capability — the transaction below remains the
/// enforcement boundary and validates the persisted interrupt offer and
/// private option mapping before it writes an approval.
#[cfg(feature = "host-approval-composition")]
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostApprovalAuthority(u8);

#[cfg(feature = "host-approval-composition")]
impl HostApprovalAuthority {
    /// Explicitly test-only authority for unit fixtures that isolate a
    /// cancellation/Drop handoff from the full daemon QuestionTool stack.
    /// This constructor is unavailable to normal dependency graphs: only
    /// cockpit-core's dev-dependency enables `host-approval-test-support`.
    #[cfg(feature = "host-approval-test-support")]
    pub fn test_only() -> Self {
        Self(1)
    }

    #[cfg(feature = "host-approval-test-support")]
    fn is_test_only(self) -> bool {
        self.0 == 1
    }
}

/// Opaque authority for the daemon-owned host-capability refresh control
/// plane, including its automatic decision ingress, enumeration, leases, and
/// terminal/publication mutations.
///
/// There is deliberately no safe constructor.  The typed creation API below
/// still proves the complete persisted refresh operation / interrupt /
/// decision binding in its transaction, so this marker cannot turn a generic
/// `Db` caller into a refresh-control authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCapabilityRefreshAuthority(());

/// Versioned workspace identity supplied only by the daemon's authoritative
/// session-workspace composition point. Generic callers cannot safely turn
/// arbitrary text (or even a correctly-shaped digest) into this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostWorkspaceRef(String);

impl HostWorkspaceRef {
    /// Construct the root workspace identity after deriving it from the live,
    /// authoritative daemon session workspace path.
    ///
    /// # Safety
    ///
    /// `value` must have been derived directly from the daemon-owned session
    /// workspace, never from a protocol field, agent/tool input, presentation
    /// packet, or storage value. The exact format is still checked here.
    pub unsafe fn from_daemon_derived(value: String) -> Result<Self> {
        ensure!(
            is_host_workspace_ref(&value),
            "session root requires a validated host-owned workspace reference"
        );
        Ok(Self(value))
    }

    fn into_inner(self) -> String {
        self.0
    }
}

/// Result of fencing one opaque host-approval handoff at a concrete effect
/// boundary. `DifferentCandidate` is deliberately distinct from a stale
/// capability so the boundary can fail closed on an exact-candidate mismatch,
/// rather than mistaking a live but unrelated approval for authority.
#[cfg(feature = "host-approval-composition")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostApprovalEffectFence {
    /// The concrete boundary atomically claimed the exact selected candidate.
    /// Crossing an external boundary is now permitted exactly once.
    Claimed,
    DifferentCandidate,
    NotLive,
}

/// Durable phase of the daemon-owned host-capability refresh operation.  This
/// is intentionally distinct from an AgentTree decision state: the decision
/// answers whether the host may probe, while this row records whether the
/// host actually crossed and completed that probe boundary. Its only forward
/// edges are `pending -> allowed|failed|cancelled`, `allowed ->
/// executing|failed|cancelled`, and `executing -> completed|failed|cancelled`.
/// `completed`, `failed`, and `cancelled` are terminal; executing cancellation
/// is the subtree/root authority that fences a result already in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCapabilityRefreshOperationState {
    Pending,
    Allowed,
    Executing,
    Completed,
    Failed,
    Cancelled,
}

/// Result of attempting to close the pre-bind half of one daemon-owned
/// host-capability refresh. The immutable `(operation_id, request_id, child)`
/// tuple is deliberately part of this boundary: an aborted attempt must never
/// cancel a later operation which happens to share a session or parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCapabilityRefreshInitializationAbort {
    /// The still-initializing descriptor, its child, and any raw unbound
    /// QuestionTool attention were terminalized in one transaction.
    Aborted,
    /// The descriptor has already crossed the atomic interrupt/decision/
    /// operation bind. Its exactly-once operation state machine remains the
    /// sole authority for subsequent finalization.
    AlreadyBound,
    /// A previous abort/recovery already terminalized this exact descriptor.
    AlreadyTerminal,
    /// No descriptor exists for this exact immutable initialization identity.
    Missing,
}

impl HostCapabilityRefreshOperationState {
    fn parse(raw: &str) -> rusqlite::Result<Self> {
        match raw {
            "pending" => Ok(Self::Pending),
            "allowed" => Ok(Self::Allowed),
            "executing" => Ok(Self::Executing),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(invalid_persisted_value("host capability refresh operation state")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilityRefreshOperationRow {
    pub operation_id: Uuid,
    pub request_id: Uuid,
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub interrupt_id: Uuid,
    pub decision_request_id: Option<Uuid>,
    pub state: HostCapabilityRefreshOperationState,
    /// Reserved atomically with the local probe execution claim. A completed
    /// receipt must use this exact daemon-global generation.
    pub reserved_snapshot_generation: Option<u64>,
    pub result_snapshot_json: Option<String>,
    /// Canonical parsed receipt identity. These values are intentionally
    /// separate from the JSON body and are used by the outbox acknowledgement
    /// CAS after the body has been parsed and installed in memory.
    pub result_snapshot_generation: Option<u64>,
    pub result_snapshot_digest: Option<String>,
    /// `None` is a durable completion outbox entry. A successor worker must
    /// make the same committed generation visible, never start another probe.
    pub published_at_unix_ms: Option<i64>,
    pub error_text: Option<String>,
    /// Stable creation ordering for the allowed-operation maintenance page.
    pub created_at_unix_ms: i64,
    /// Stable secondary ordering for the global completed-publication outbox.
    pub completed_at_unix_ms: Option<i64>,
}

/// Keyset cursor for the daemon-global completed refresh publication outbox.
/// All three fields participate in the authoritative SQL ordering, so a
/// restart/retry never skips equal-generation or equal-timestamp entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilityRefreshOutboxCursor {
    pub result_snapshot_generation: u64,
    pub completed_at_unix_ms: i64,
    pub operation_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilityRefreshOutboxPage {
    pub entries: Vec<HostCapabilityRefreshOperationRow>,
    pub next_cursor: Option<HostCapabilityRefreshOutboxCursor>,
}

/// The latest completed daemon-global capability receipt. Startup uses this
/// to seed an otherwise empty in-memory store before it accepts any new
/// generation reservation. It is deliberately a receipt, not a session view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilityRefreshSnapshotReceipt {
    pub result_snapshot_json: String,
    pub generation: u64,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCapabilityRefreshExecutionClaim {
    Claimed {
        /// Opaque, one-executor capability. Every renewal and terminal write
        /// must carry this exact lease alongside the operation id.
        lease: HostCapabilityRefreshExecutionLease,
    },
    Completed {
        receipt: HostCapabilityRefreshSnapshotReceipt,
    },
    /// This operation, or an earlier operation in the same durable session
    /// stream (including a completed receipt awaiting outbox publication),
    /// owns the one probe boundary. A live requester may wait for that
    /// receipt; it must never issue a second local probe merely because the
    /// execution claim was already taken.
    InFlight,
    Failed { error_text: String },
    Cancelled { error_text: String },
    NotReady,
}

/// The durable identity of one local host-capability probe execution.
///
/// An execution cannot be resumed after a process loss, but its lease must
/// still distinguish the task that crossed the boundary from a stale timer or
/// a cancellation/recovery path. The database only accepts renewal and
/// terminal writes when the operation id, monotonic execution epoch, opaque
/// owner token, and owner agent revision all agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCapabilityRefreshExecutionLease {
    execution_epoch: i64,
    owner_token: Uuid,
    owner_agent_revision: i64,
    snapshot_generation: u64,
}

impl HostCapabilityRefreshExecutionLease {
    /// The durable global generation reserved in the same transaction as this
    /// exact execution claim. The host probe must stage this generation and
    /// no other value.
    pub fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
    }
}

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

/// The one terminal outcome shared by the legacy task-delegation ledger and
/// its bound AgentTree executor.  Keeping this small enum at the persistence
/// boundary prevents callers from terminalizing the compatibility row and the
/// durable executor in separate transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskDelegationTerminalState {
    Completed,
    Failed,
    Cancelled,
}

impl TaskDelegationTerminalState {
    fn delegation_status(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn agent_state(self) -> AgentInstanceState {
        match self {
            Self::Completed => AgentInstanceState::Completed,
            Self::Failed => AgentInstanceState::Failed,
            Self::Cancelled => AgentInstanceState::Cancelled,
        }
    }
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

    /// Whether this persisted lifecycle state has no executable continuation.
    ///
    /// Recovery must inspect this predicate before it can claim a child for
    /// reconciliation; keeping the transition rules themselves private still
    /// prevents callers outside this module from changing lifecycle policy.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    fn legal_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Running | Self::Cancelled)
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
    /// Opaque host-owned reference to the workspace authority held by this
    /// node. It is never a resolver-context transport.
    pub workspace_ref: Option<String>,
    /// Legacy migration field retained for existing rows. Production resolver
    /// routing ignores it and derives authority from the immutable profile.
    pub auto_answer_enabled: bool,
    pub state: AgentInstanceState,
    pub revision: i64,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

/// Immutable launch record plus the latest durable continuation snapshot for
/// a task-backed executor. It is intentionally keyed by the agent UUID: a
/// recovery caller may not substitute a same-named task child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskDelegationRecoveryDescriptor {
    pub agent_instance_id: Uuid,
    pub parent_agent_instance_id: Uuid,
    pub task_call_id: String,
    pub label: String,
    pub child_agent: String,
    pub original_args_json: String,
    pub snapshot_json: String,
    /// The durable task-child status controls completion delivery after a
    /// restart.  A detached/backgrounded executor must never be reattached
    /// as a foreground task merely because its live handle was lost.
    pub was_backgrounded: bool,
}

/// Immutable recursive executor launch plus its latest precise continuation.
/// Unlike task delegation rows this has no display label or compatibility
/// result queue; the durable agent UUID is the sole recovery identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveNoninteractiveRecoveryDescriptor {
    pub agent_instance_id: Uuid,
    pub parent_agent_instance_id: Uuid,
    pub launch: ValidatedRecursiveNoninteractiveLaunch,
    pub snapshot: ValidatedRecursiveNoninteractiveSnapshot,
}

/// A canonical, versioned recursive-executor launch descriptor.  This type is
/// the only way the DB mutation APIs accept a launch record: raw JSON cannot
/// advance a child lifecycle to `running` and cannot enter recovery storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRecursiveNoninteractiveLaunch(String);

impl ValidatedRecursiveNoninteractiveLaunch {
    pub fn parse_and_canonicalize(raw: impl AsRef<str>) -> Result<Self> {
        let canonical = validate_recursive_noninteractive_launch_json(raw.as_ref())?;
        Ok(Self(canonical))
    }

    pub fn as_json(&self) -> &str {
        &self.0
    }

    pub fn into_json(self) -> String {
        self.0
    }
}

/// A canonical, versioned recursive-executor continuation snapshot.  The DB
/// validates its outer shape independently of core's `Message` types, while
/// the core parser validates the full continuation before rehydrating it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRecursiveNoninteractiveSnapshot(String);

impl ValidatedRecursiveNoninteractiveSnapshot {
    pub fn parse_and_canonicalize(raw: impl AsRef<str>) -> Result<Self> {
        let canonical = validate_recursive_noninteractive_snapshot_json(raw.as_ref())?;
        Ok(Self(canonical))
    }

    pub fn as_json(&self) -> &str {
        &self.0
    }

    pub fn into_json(self) -> String {
        self.0
    }
}

/// The root's private continuation. Unlike child frames, the root has no task
/// delegation descriptor; this record is the durable recovery source for an
/// accepted late steer that later parked at a question or approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAgentContinuationDescriptor {
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub continuation_id: Option<Uuid>,
    pub snapshot_json: String,
}

/// Durable terminal material for one recursive executor.  This is deliberately
/// separate from the executor snapshot: snapshots are resumable state for a
/// live child, whereas this row is the parent-visible exactly-once result of a
/// child that may already have been removed from recovery scheduling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveNoninteractiveOutcome {
    pub agent_instance_id: Uuid,
    pub parent_agent_instance_id: Uuid,
    pub label: String,
    pub child_agent: String,
    pub report: String,
    pub failed: bool,
    pub completed_at_unix_ms: i64,
}

/// One recursive child and its immutable launch/initial-continuation pair.
/// The caller allocates both UUIDs before the transaction so the parent
/// checkpoint can name the exact set of children it is waiting to receive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRecursiveNoninteractiveExecutor {
    pub agent_instance_id: Uuid,
    pub recovery_anchor: Uuid,
    pub launch: ValidatedRecursiveNoninteractiveLaunch,
    pub snapshot: ValidatedRecursiveNoninteractiveSnapshot,
}

/// The first durable continuation of one legacy task child.  A task child is
/// not recoverable until this snapshot and its AgentTree identity have been
/// published in the same transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTaskDelegationAgent {
    pub label: String,
    pub snapshot_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRequestRow {
    pub decision_request_id: Uuid,
    pub agent_instance_id: Uuid,
    pub session_id: Uuid,
    /// Bounded daemon-owned task lineage derived from the exact owner at
    /// creation. It is never taken from a presentation selector.
    pub task_call_id: Option<String>,
    /// Opaque daemon-owned workspace identity copied from the exact owner.
    pub workspace_ref: Option<String>,
    pub options_contract_json: String,
    pub free_text_contract_json: Option<String>,
    pub recommendation_json: Option<String>,
    pub rationale_redaction_class: String,
    /// A closed host-classified risk category. This is persisted so recovery
    /// cannot reinterpret a formerly prohibited request as low risk.
    pub decision_class: String,
    /// The final operation identity that a host approval authorizes. This is
    /// intentionally absent from resolver packets and public Attention rows.
    pub host_approval_operation_id: Option<Uuid>,
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
    /// Internal continuation input for a settled user decision. Agent
    /// receipts leave this `None`; this value is never projected publicly.
    pub resume_payload_json: Option<String>,
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
    pub workspace_ref: Option<String>,
    pub auto_answer_enabled: bool,
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
    pub decision_class: String,
    /// Only the daemon's host-approval composition point supplies this. A
    /// request with the host-approval class must bind one real operation; all
    /// other classes must leave it absent.
    pub host_approval_operation_id: Option<Uuid>,
    pub deadline_unix_ms: Option<i64>,
    pub policy_receipt_json: String,
    pub resolver_route: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum DecisionCreationKind {
    Generic,
    /// Reserved host approvals are not a generic decision class.  Both the
    /// reservation and its one atomic interrupt/decision bind carry this
    /// daemon composition capability, so a caller holding only `Db` cannot
    /// turn a string-shaped `host_approval` request into an effect authority.
    #[cfg(feature = "host-approval-composition")]
    HostApproval { authority: HostApprovalAuthority },
    #[cfg(feature = "host-capability-refresh-composition")]
    HostCapabilityRefresh {
        operation_id: Uuid,
        request_id: Uuid,
        /// The direct daemon RPC creates a durable child before it can mint
        /// the real QuestionTool interrupt.  That path must consume its
        /// matching initialization descriptor atomically with the bind.
        /// Isolated decision fixtures deliberately have no such child.
        requires_dedicated_child_initialization: bool,
        authority: HostCapabilityRefreshAuthority,
    },
}

/// Stable, opaque pagination cursor for ordered agent/attention snapshots.
/// The pair is part of the ordering key, so equal timestamps never cause an
/// entry to be skipped or replayed across a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTreePageCursor {
    pub created_at_unix_ms: i64,
    pub id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTreePage<T> {
    pub entries: Vec<T>,
    pub next_cursor: Option<AgentTreePageCursor>,
}

/// The only daemon DTO for a decision-owned attention row.  It deliberately
/// omits legacy parked-call data and the resolved receipt body: those values
/// are not resolver context and must never cross the attention boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionAttentionRow {
    pub attention_id: Uuid,
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub state: String,
    pub raised_at_unix_ms: i64,
    pub resolved_at_unix_ms: Option<i64>,
    pub decision: DecisionRequestRow,
}

/// Private continuation-only mapping for daemon-minted public decision
/// tokens. It must never be projected through an Attention or resolver DTO.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionPrivateOptionMapping {
    pub opaque_option_id: String,
    pub continuation_option_id: String,
}

/// Private durable continuation message created only when a user answers an
/// already-auto-resolved decision. It intentionally keeps the original
/// receipt immutable. `requesting_agent_instance_id` preserves the decision
/// owner even when a daemon-only host-operation child reroutes the new
/// user-authored steer to its model-owning direct parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateUserDecisionSteerExecutionState {
    Pending,
    Accepted,
    Completed,
    Rejected,
}

impl LateUserDecisionSteerExecutionState {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "pending" => Ok(Self::Pending),
            "accepted" => Ok(Self::Accepted),
            "completed" => Ok(Self::Completed),
            "rejected" => Ok(Self::Rejected),
            _ => bail!("unknown late user steer execution state `{raw}`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LateUserDecisionSteer {
    pub steer_id: Uuid,
    /// Immutable idempotency identity of the continuation consuming this
    /// steer. It is never replaced by a recovery epoch.
    pub continuation_id: Uuid,
    pub session_id: Uuid,
    /// Immutable source owner of the auto-resolved decision.
    pub requesting_agent_instance_id: Uuid,
    /// Exact executor that must consume this user-authored continuation.
    /// This is normally equal to `requesting_agent_instance_id`; the only
    /// exception is a daemon-owned host operation with no model mailbox.
    pub agent_instance_id: Uuid,
    pub decision_request_id: Uuid,
    pub payload_json: String,
    /// The exact auto-result parked continuation that must be durably
    /// acknowledged before this post-auto instruction is eligible.
    pub predecessor_interrupt_id: Option<Uuid>,
    pub created_at_unix_ms: i64,
    pub claimed_recovery_epoch: Option<Uuid>,
    pub execution_state: LateUserDecisionSteerExecutionState,
    /// The recovery epoch whose exact executor accepted this continuation.
    /// This is private delivery state, never an Attention or wire projection.
    pub accepted_recovery_epoch: Option<Uuid>,
    /// Immutable exact owner revision observed when this continuation crossed
    /// the no-redelivery acceptance boundary.
    pub accepted_agent_revision: Option<i64>,
    /// Byte length (not Unicode scalar count) of the canonical payload row.
    pub payload_bytes: Option<i64>,
    /// Durable, private replay checkpoint minted at acceptance. It binds the
    /// continuation identity to the exact owner revision and payload digest.
    /// It must never cross an Attention or protocol boundary.
    pub continuation_checkpoint_json: Option<String>,
    /// Completion is durable before the worker receipt.  A later boot can
    /// therefore acknowledge this row without invoking the continuation again.
    pub completed_at_unix_ms: Option<i64>,
    pub rejected_at_unix_ms: Option<i64>,
    pub rejection_reason: Option<String>,
}

/// One committed, session-ordered invalidation.  The daemon event relay reads
/// these rows after commit and broadcasts them without writing another session
/// event, so every durable lifecycle edge has exactly one public invalidation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTreeEventRow {
    pub session_id: Uuid,
    pub session_event_seq: i64,
    pub kind: String,
    /// The event body is deliberately state-free. A relay must never reload a
    /// later mutable row and pretend it was the state at this ordered edge.
    pub subject_kind: String,
    pub subject_id: Uuid,
}

pub const MAX_AGENT_TREE_PAGE_SIZE: usize = 100;

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
            // Workspace identity belongs to the daemon's root and is carried
            // down the lineage, never selected by a child/task caller.  The
            // validation returns the value that must be persisted so the
            // parent lookup and child insertion are one transaction.
            let workspace_ref = validate_agent_lineage(conn, &input, agent_instance_id)?;
            conn.execute(
                "INSERT INTO agent_instances (
                    agent_instance_id, session_id, parent_agent_instance_id,
                    task_delegation_job_id, task_delegation_child_uuid,
                    resolved_profile_snapshot_id, workspace_ref, auto_answer_enabled,
                    state, revision, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 'created', 0, ?8, ?8)",
                params![
                    agent_instance_id.to_string(),
                    input.session_id.to_string(),
                    input.parent_agent_instance_id.map(|id| id.to_string()),
                    input.task_delegation_job_id,
                    input.task_delegation_child_uuid.map(|id| id.to_string()),
                    input.resolved_profile_snapshot_id.map(|id| id.to_string()),
                    workspace_ref,
                    now_unix_ms,
                ],
            )
            .context("creating agent instance")?;
            insert_control_event(
                conn,
                input.session_id,
                "agent_created",
                agent_instance_id,
                AgentInstanceState::Created.as_str(),
                now_unix_ms,
            )?;
            load_agent(conn, input.session_id, agent_instance_id)?.context("created agent missing")
        })
        .await
    }

    /// Create the daemon-owned host-capability refresh child together with a
    /// durable pre-bind descriptor.  The real QuestionTool interrupt and
    /// decision are intentionally not manufactured here: their later
    /// transaction binds the same immutable `(operation, request, child)`
    /// tuple all at once.  If a process stops anywhere between these two
    /// transactions, startup sees `initializing` and terminalizes this child
    /// instead of treating it as an ordinary unattached recursive executor.
    #[cfg(feature = "host-capability-refresh-composition")]
    pub async fn create_host_capability_refresh_initialization(
        &self,
        input: NewAgentInstance,
        operation_id: Uuid,
        request_id: Uuid,
        authority: HostCapabilityRefreshAuthority,
        now_unix_ms: i64,
    ) -> Result<AgentInstanceRow> {
        ensure!(
            !operation_id.is_nil() && !request_id.is_nil(),
            "host capability refresh initialization identities must not be nil"
        );
        let parent_agent_instance_id = input
            .parent_agent_instance_id
            .context("host capability refresh child requires a direct requesting parent")?;
        // Retain the opaque call-graph capability across the storage
        // transaction. The database still proves all tuple/session/lineage
        // facts before publishing the descriptor.
        let _ = authority;
        let agent_instance_id = Uuid::new_v4();
        self.transaction(move |conn| {
            let workspace_ref = validate_agent_lineage(conn, &input, agent_instance_id)?;
            conn.execute(
                "INSERT INTO agent_instances (
                    agent_instance_id, session_id, parent_agent_instance_id,
                    task_delegation_job_id, task_delegation_child_uuid,
                    resolved_profile_snapshot_id, workspace_ref, auto_answer_enabled,
                    state, revision, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'created', 0, ?9, ?9)",
                params![
                    agent_instance_id.to_string(),
                    input.session_id.to_string(),
                    Some(parent_agent_instance_id.to_string()),
                    input.task_delegation_job_id,
                    input.task_delegation_child_uuid.map(|id| id.to_string()),
                    input.resolved_profile_snapshot_id.map(|id| id.to_string()),
                    workspace_ref,
                    if input.auto_answer_enabled { 1_i64 } else { 0_i64 },
                    now_unix_ms,
                ],
            )
            .context("creating host capability refresh child")?;
            conn.execute(
                "INSERT INTO host_capability_refresh_initializations (
                    operation_id, request_id, session_id, agent_instance_id,
                    parent_agent_instance_id, state, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'initializing', ?6, ?6)",
                params![
                    operation_id.to_string(),
                    request_id.to_string(),
                    input.session_id.to_string(),
                    agent_instance_id.to_string(),
                    parent_agent_instance_id.to_string(),
                    now_unix_ms,
                ],
            )
            .context("recording host capability refresh initialization")?;
            insert_control_event(
                conn,
                input.session_id,
                "agent_created",
                agent_instance_id,
                AgentInstanceState::Created.as_str(),
                now_unix_ms,
            )?;
            load_agent(conn, input.session_id, agent_instance_id)?
                .context("created host capability refresh child missing")
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

    /// Returns the one daemon-owned root node for a session, creating it only
    /// once. Legacy task children use their own durable child UUID mapping;
    /// this key is reserved for the live root continuation and is never a
    /// caller-provided authority token.
    pub async fn ensure_session_root_agent(
        &self,
        session_id: Uuid,
        resolved_profile_snapshot_id: Option<Uuid>,
        workspace_ref: HostWorkspaceRef,
        now_unix_ms: i64,
    ) -> Result<AgentInstanceRow> {
        let workspace_ref = workspace_ref.into_inner();
        self.transaction(move |conn| {
            let session_id_text = session_id.to_string();
            let existing: Option<String> = conn
                .query_row(
                    "SELECT agent_instance_id FROM agent_instances
                     WHERE session_id = ?1 AND runtime_key = 'session-root'",
                    [&session_id_text],
                    |row| row.get(0),
            )
            .optional()?;
            if let Some(existing) = existing {
                let root = load_agent(conn, session_id, parse_uuid(existing)?)?
                    .context("session root agent disappeared")?;
                // A database created before root workspace ownership was
                // persisted can be repaired only by the daemon that owns the
                // canonical workspace. Never accept a caller-selected value
                // here, and never replace an established identity.
                if root.workspace_ref.is_none() {
                    conn.execute(
                        "UPDATE agent_instances
                         SET workspace_ref = ?1, revision = revision + 1,
                             updated_at_unix_ms = ?2
                         WHERE session_id = ?3 AND agent_instance_id = ?4
                           AND workspace_ref IS NULL",
                        params![
                            workspace_ref,
                            now_unix_ms,
                            session_id.to_string(),
                            root.agent_instance_id.to_string(),
                        ],
                    )?;
                    return load_agent(conn, session_id, root.agent_instance_id)?
                        .context("repaired session root agent disappeared");
                }
                ensure!(
                    root.workspace_ref.as_deref().is_some_and(is_host_workspace_ref),
                    "session root carries an invalid workspace reference"
                );
                return Ok(root);
            }
            if let Some(snapshot_id) = resolved_profile_snapshot_id {
                let snapshot_session: Option<String> = conn
                    .query_row(
                        "SELECT session_id FROM agent_profile_snapshots WHERE snapshot_id = ?1",
                        [snapshot_id.to_string()],
                        |row| row.get(0),
                    )
                    .optional()?;
                ensure!(
                    snapshot_session.as_deref() == Some(session_id_text.as_str()),
                    "root profile snapshot is not authorized for this session"
                );
            }
            let agent_instance_id = Uuid::new_v4();
            conn.execute(
                "INSERT INTO agent_instances (
                     agent_instance_id, session_id, runtime_key,
                     resolved_profile_snapshot_id, workspace_ref,
                     auto_answer_enabled, state, revision, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, 'session-root', ?3, ?4, 0, 'created', 0, ?5, ?5)",
                params![
                    agent_instance_id.to_string(),
                    session_id.to_string(),
                    resolved_profile_snapshot_id.map(|id| id.to_string()),
                    workspace_ref,
                    now_unix_ms,
                ],
            )?;
            insert_control_event(
                conn,
                session_id,
                "agent_created",
                agent_instance_id,
                AgentInstanceState::Created.as_str(),
                now_unix_ms,
            )?;
            load_agent(conn, session_id, agent_instance_id)?.context("created root agent missing")
        })
        .await
    }

    /// Explicitly applies an already-resolved profile reduction to one agent.
    /// Creation is always disabled. This API derives the reduction solely from
    /// the exact immutable profile snapshot bound to the agent; callers supply
    /// no enable boolean, and `Off`/prohibited policies fail closed.
    pub async fn set_agent_auto_answer_from_resolved_profile(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        resolved_profile_snapshot_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let Some(agent) = load_agent(conn, session_id, agent_instance_id)? else {
                return Ok(false);
            };
            ensure!(
                agent.resolved_profile_snapshot_id == Some(resolved_profile_snapshot_id),
                "automatic-answer policy must use the agent's resolved profile snapshot"
            );
            let profile_payload: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT canonical_payload FROM agent_profile_snapshots
                     WHERE session_id = ?1 AND snapshot_id = ?2",
                    params![session_id.to_string(), resolved_profile_snapshot_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            let profile_payload = profile_payload
                .context("resolved profile snapshot is not authorized for this session")?;
            let profile: RedactedAgentProfileSnapshot = serde_json::from_slice(&profile_payload)
                .context("resolved profile snapshot is malformed")?;
            // This reduction is intentionally computed inside the same
            // database transaction as the state change. Callers never supply
            // an enable boolean: `Off`, a persisted disabled reduction, and a
            // malformed snapshot all fail closed to disabled.
            let enabled = matches!(
                profile.question_policy,
                RedactedQuestionPolicy::Active {
                    auto_answer_disabled: false,
                    ..
                }
            );
            let changed = conn.execute(
                "UPDATE agent_instances
                 SET auto_answer_enabled = ?1, updated_at_unix_ms = ?2
                 WHERE session_id = ?3 AND agent_instance_id = ?4
                   AND resolved_profile_snapshot_id = ?5",
                params![
                    if enabled { 1_i64 } else { 0_i64 },
                    now_unix_ms,
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    resolved_profile_snapshot_id.to_string(),
                ],
            )?;
            if changed == 1 {
                insert_control_event(
                    conn,
                    session_id,
                    "agent_auto_answer_policy",
                    agent_instance_id,
                    agent.state.as_str(),
                    now_unix_ms,
                )?;
            }
            Ok(changed == 1)
        })
        .await
    }

    /// Returns the daemon-owned root when the session worker has already
    /// established it.  Unlike `ensure_session_root_agent`, this read never
    /// creates an unprofiled fallback during a tool call.
    pub async fn session_root_agent(&self, session_id: Uuid) -> Result<Option<AgentInstanceRow>> {
        self.read(move |conn| {
            let id: Option<String> = conn
                .query_row(
                    "SELECT agent_instance_id FROM agent_instances
                     WHERE session_id = ?1 AND runtime_key = 'session-root'",
                    [session_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            match id {
                Some(id) => load_agent(conn, session_id, parse_uuid(id)?),
                None => Ok(None),
            }
        })
        .await
    }

    /// Persist the root's exact next model/tool message before any provider
    /// handoff. A `continuation_id` is present only when this is the currently
    /// accepted late-steer continuation. The update deliberately replaces
    /// older root checkpoints as the frame enters each later parked phase;
    /// recovery always receives the newest exact state, while the accepted
    /// steer row remains the immutable no-redelivery authority.
    pub async fn persist_session_root_agent_continuation(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        continuation_id: Option<Uuid>,
        snapshot_json: String,
        now_unix_ms: i64,
    ) -> Result<()> {
        let _: Value = serde_json::from_str(&snapshot_json)
            .context("root continuation snapshot is not JSON")?;
        self.transaction(move |conn| {
            let owner = load_agent(conn, session_id, agent_instance_id)?
                .context("root continuation owner is not authorized for this session")?;
            ensure!(
                owner.parent_agent_instance_id.is_none()
                    && owner.task_delegation_job_id.is_none()
                    && owner.task_delegation_child_uuid.is_none(),
                "root continuation owner is not the session root"
            );
            let runtime_key: Option<String> = conn
                .query_row(
                    "SELECT runtime_key FROM agent_instances
                      WHERE session_id = ?1 AND agent_instance_id = ?2",
                    params![session_id.to_string(), agent_instance_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            ensure!(
                runtime_key.as_deref() == Some("session-root"),
                "root continuation owner does not carry the daemon root identity"
            );
            ensure!(
                !owner.state.is_terminal(),
                "terminal root cannot publish a resumable continuation"
            );
            conn.execute(
                "INSERT INTO root_agent_continuations (
                     session_id, agent_instance_id, continuation_id,
                     snapshot_json, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(session_id) DO UPDATE SET
                     agent_instance_id = excluded.agent_instance_id,
                     continuation_id = excluded.continuation_id,
                     snapshot_json = excluded.snapshot_json,
                     updated_at_unix_ms = excluded.updated_at_unix_ms",
                params![
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    continuation_id.map(|id| id.to_string()),
                    snapshot_json,
                    now_unix_ms,
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// Load only the exact root snapshot bound to one accepted continuation.
    /// An old ordinary root checkpoint is never a substitute for a missing
    /// accepted steer snapshot.
    pub async fn session_root_agent_continuation_for_steer(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        continuation_id: Uuid,
    ) -> Result<Option<RootAgentContinuationDescriptor>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT session_id, agent_instance_id, continuation_id, snapshot_json
                   FROM root_agent_continuations
                  WHERE session_id = ?1 AND agent_instance_id = ?2
                    AND continuation_id = ?3",
                params![
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    continuation_id.to_string(),
                ],
                |row| {
                    Ok(RootAgentContinuationDescriptor {
                        session_id: parse_uuid(row.get::<_, String>(0)?)?,
                        agent_instance_id: parse_uuid(row.get::<_, String>(1)?)?,
                        continuation_id: row
                            .get::<_, Option<String>>(2)?
                            .map(parse_uuid)
                            .transpose()?,
                        snapshot_json: row.get(3)?,
                    })
                },
            )
            .optional()
            .context("loading exact root continuation for accepted late steer")
        })
        .await
    }

    /// Atomically publishes every first task-child continuation together with
    /// the exact AgentTree node that owns it.  This replaces the former
    /// activate-then-bind sequence: a crash between those transactions made a
    /// `running` task child visible to recovery with no lineage identity.
    ///
    /// Batch callers provide the complete label set.  The transaction either
    /// publishes every sibling snapshot and mapping or none; retries verify
    /// already-published entries without replacing a newer continuation.
    pub async fn publish_task_delegation_children_and_agents(
        &self,
        session_id: Uuid,
        parent_agent_instance_id: Uuid,
        task_call_id: String,
        children: Vec<NewTaskDelegationAgent>,
        now_unix_ms: i64,
    ) -> Result<Vec<AgentInstanceRow>> {
        ensure!(
            !children.is_empty(),
            "task delegation publication requires at least one child"
        );
        let mut labels = std::collections::HashSet::with_capacity(children.len());
        for child in &children {
            ensure!(
                labels.insert(child.label.as_str()),
                "task delegation publication contains duplicate label `{}`",
                child.label
            );
            ensure!(
                !child.snapshot_json.trim().is_empty(),
                "task delegation publication snapshot is empty"
            );
        }
        let rows = self.transaction(move |conn| {
            let parent = load_agent(conn, session_id, parent_agent_instance_id)?
                .context("task delegation parent agent is not authorized for this session")?;
            ensure!(
                !parent.state.is_terminal(),
                "cannot publish a task child below a terminal parent"
            );
            let mut rows = Vec::with_capacity(children.len());
            for child in children {
                let updated = conn.execute(
                    "UPDATE task_delegation_children
                        SET status = 'running', snapshot_json = ?3,
                            started_at = COALESCE(started_at, ?4), updated_at = ?4
                      WHERE task_call_id = ?1 AND label = ?2 AND status = 'created'",
                    params![
                        &task_call_id,
                        &child.label,
                        &child.snapshot_json,
                        now_unix_ms / 1_000,
                    ],
                )?;
                let (child_uuid_text, status, snapshot_json): (String, String, Option<String>) = conn
                    .query_row(
                        "SELECT c.child_uuid, c.status, c.snapshot_json
                           FROM task_delegation_children c
                           JOIN task_delegation_jobs j ON j.task_call_id = c.task_call_id
                          WHERE c.task_call_id = ?1 AND c.label = ?2
                            AND j.parent_session_id = ?3",
                        params![&task_call_id, &child.label, session_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .context("task delegation child publication is not authorized for this session")?;
                ensure!(
                    updated == 1
                        || (matches!(status.as_str(), "running" | "backgrounded" | "paused_pending_tool")
                            && snapshot_json.is_some()),
                    "task delegation child is not safely published"
                );
                let child_uuid = parse_uuid(child_uuid_text)?;
                let existing: Option<String> = conn
                    .query_row(
                        "SELECT agent_instance_id FROM agent_instances
                          WHERE session_id = ?1 AND task_delegation_child_uuid = ?2",
                        params![session_id.to_string(), child_uuid.to_string()],
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(existing) = existing {
                    let existing = load_agent(conn, session_id, parse_uuid(existing)?)?
                        .context("task delegation agent mapping disappeared")?;
                    ensure!(
                        existing.parent_agent_instance_id == Some(parent_agent_instance_id)
                            && existing.task_delegation_job_id.as_deref() == Some(task_call_id.as_str()),
                        "task delegation child mapping has incompatible lineage"
                    );
                    rows.push(existing);
                    continue;
                }
                let agent_instance_id = Uuid::new_v4();
                conn.execute(
                    "INSERT INTO agent_instances (
                         agent_instance_id, session_id, parent_agent_instance_id,
                         task_delegation_job_id, task_delegation_child_uuid,
                         resolved_profile_snapshot_id, workspace_ref, auto_answer_enabled,
                         state, revision, created_at_unix_ms, updated_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 'created', 0, ?8, ?8)",
                    params![
                        agent_instance_id.to_string(),
                        session_id.to_string(),
                        parent_agent_instance_id.to_string(),
                        &task_call_id,
                        child_uuid.to_string(),
                        parent.resolved_profile_snapshot_id.map(|id| id.to_string()),
                        parent.workspace_ref.clone(),
                        now_unix_ms,
                    ],
                )?;
                insert_control_event(
                    conn,
                    session_id,
                    "agent_created",
                    agent_instance_id,
                    AgentInstanceState::Created.as_str(),
                    now_unix_ms,
                )?;
                let started = conn.execute(
                    "UPDATE agent_instances
                        SET state = 'running', revision = 1, updated_at_unix_ms = ?1
                      WHERE session_id = ?2 AND agent_instance_id = ?3 AND state = 'created'",
                    params![now_unix_ms, session_id.to_string(), agent_instance_id.to_string()],
                )?;
                ensure!(started == 1, "task delegation child lifecycle start CAS lost");
                insert_control_event(
                    conn,
                    session_id,
                    "agent_transition",
                    agent_instance_id,
                    AgentInstanceState::Running.as_str(),
                    now_unix_ms,
                )?;
                rows.push(
                    load_agent(conn, session_id, agent_instance_id)?
                        .context("published task delegation agent missing")?,
                );
            }
            Ok(rows)
        }).await?;
        for row in &rows {
            if let Some(snapshot_id) = row.resolved_profile_snapshot_id {
                self.set_agent_auto_answer_from_resolved_profile(
                    session_id,
                    row.agent_instance_id,
                    snapshot_id,
                    now_unix_ms,
                )
                .await?;
            }
        }
        Ok(rows)
    }

    /// Allocate a distinct durable node for a recursive vNext executor. The
    /// caller supplies a fresh recovery anchor; it is stored only in the
    /// daemon-owned runtime key and is never derived from an agent name or
    /// task label. Unlike legacy task children this node has no compatibility
    /// queue binding, but it still inherits the exact parent lineage, profile,
    /// and workspace authority.
    pub async fn create_recursive_noninteractive_child_agent(
        &self,
        session_id: Uuid,
        parent_agent_instance_id: Uuid,
        recovery_anchor: Uuid,
        now_unix_ms: i64,
    ) -> Result<AgentInstanceRow> {
        ensure!(!recovery_anchor.is_nil(), "recursive child recovery anchor must not be nil");
        let runtime_key = format!("recursive-noninteractive:{parent_agent_instance_id}:{recovery_anchor}");
        let child = self.transaction(move |conn| {
            let parent = load_agent(conn, session_id, parent_agent_instance_id)?
                .context("recursive child parent is not authorized for this session")?;
            ensure!(
                !parent.state.is_terminal(),
                "cannot bind a recursive child to a terminal parent"
            );
            let agent_instance_id = Uuid::new_v4();
            conn.execute(
                "INSERT INTO agent_instances (
                     agent_instance_id, session_id, parent_agent_instance_id, runtime_key,
                     resolved_profile_snapshot_id, workspace_ref, auto_answer_enabled,
                     state, revision, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 'created', 0, ?7, ?7)",
                params![
                    agent_instance_id.to_string(),
                    session_id.to_string(),
                    parent_agent_instance_id.to_string(),
                    runtime_key,
                    parent.resolved_profile_snapshot_id.map(|id| id.to_string()),
                    parent.workspace_ref,
                    now_unix_ms,
                ],
            )?;
            insert_control_event(
                conn,
                session_id,
                "agent_created",
                agent_instance_id,
                AgentInstanceState::Created.as_str(),
                now_unix_ms,
            )?;
            let changed = conn.execute(
                "UPDATE agent_instances
                 SET state = 'running', revision = 1, updated_at_unix_ms = ?1
                 WHERE session_id = ?2 AND agent_instance_id = ?3 AND state = 'created'",
                params![now_unix_ms, session_id.to_string(), agent_instance_id.to_string()],
            )?;
            ensure!(changed == 1, "recursive child lifecycle start CAS lost");
            insert_control_event(
                conn,
                session_id,
                "agent_transition",
                agent_instance_id,
                AgentInstanceState::Running.as_str(),
                now_unix_ms,
            )?;
            load_agent(conn, session_id, agent_instance_id)?
                .context("created recursive child agent missing")
        })
        .await?;
        if let Some(snapshot_id) = child.resolved_profile_snapshot_id {
            self.set_agent_auto_answer_from_resolved_profile(
                session_id,
                child.agent_instance_id,
                snapshot_id,
                now_unix_ms,
            )
            .await?;
        }
        self.agent_instance(session_id, child.agent_instance_id)
            .await?
            .context("recursive child agent disappeared after profile reduction")
    }

    /// Atomically records a parent continuation that is waiting on a fixed
    /// recursive child set and creates the corresponding child executors.
    ///
    /// This is intentionally one transaction.  A parent checkpoint without
    /// all of the named children would be unrecoverable, while children without
    /// the parent's waiting checkpoint could be replayed as an orphaned second
    /// delegation after a crash.  Parent executors are either task-backed or
    /// recursive; a root/interactive node is not a valid caller for this
    /// noninteractive continuation seam.
    pub async fn create_recursive_noninteractive_executors_and_checkpoint_parent(
        &self,
        session_id: Uuid,
        parent_agent_instance_id: Uuid,
        parent_snapshot: ValidatedRecursiveNoninteractiveSnapshot,
        children: Vec<NewRecursiveNoninteractiveExecutor>,
        now_unix_ms: i64,
    ) -> Result<Vec<AgentInstanceRow>> {
        ensure!(!children.is_empty(), "recursive executor checkpoint requires at least one child");
        let mut seen_agent_ids = std::collections::HashSet::new();
        let mut seen_anchors = std::collections::HashSet::new();
        for child in &children {
            ensure!(!child.agent_instance_id.is_nil(), "recursive child agent id must not be nil");
            ensure!(!child.recovery_anchor.is_nil(), "recursive child recovery anchor must not be nil");
            ensure!(seen_agent_ids.insert(child.agent_instance_id), "recursive checkpoint has duplicate child agent id");
            ensure!(seen_anchors.insert(child.recovery_anchor), "recursive checkpoint has duplicate recovery anchor");
        }
        let parent_snapshot_json = parent_snapshot.into_json();
        let created = self.transaction(move |conn| {
            let parent = load_agent(conn, session_id, parent_agent_instance_id)?
                .context("recursive executor parent is not authorized for this session")?;
            ensure!(
                !parent.state.is_terminal(),
                "cannot checkpoint recursive children under a terminal parent"
            );
            let parent_updated = if let Some(task_child_uuid) = parent.task_delegation_child_uuid {
                conn.execute(
                    "UPDATE task_delegation_children
                        SET snapshot_json = ?1, updated_at = ?2
                      WHERE child_uuid = ?3
                        AND status IN ('running', 'backgrounded', 'paused_pending_tool')",
                    params![parent_snapshot_json, now_unix_ms / 1000, task_child_uuid.to_string()],
                )?
            } else {
                conn.execute(
                    "UPDATE recursive_noninteractive_executors
                        SET snapshot_json = ?1, updated_at_unix_ms = ?2
                      WHERE session_id = ?3 AND agent_instance_id = ?4",
                    params![parent_snapshot_json, now_unix_ms, session_id.to_string(), parent_agent_instance_id.to_string()],
                )?
            };
            ensure!(parent_updated == 1, "recursive parent has no live durable continuation descriptor");

            let mut rows = Vec::with_capacity(children.len());
            for child in children {
                let runtime_key = format!(
                    "recursive-noninteractive:{parent_agent_instance_id}:{}",
                    child.recovery_anchor
                );
                conn.execute(
                    "INSERT INTO agent_instances (
                         agent_instance_id, session_id, parent_agent_instance_id, runtime_key,
                         resolved_profile_snapshot_id, workspace_ref, auto_answer_enabled,
                         state, revision, created_at_unix_ms, updated_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 'created', 0, ?7, ?7)",
                    params![
                        child.agent_instance_id.to_string(),
                        session_id.to_string(),
                        parent_agent_instance_id.to_string(),
                        runtime_key,
                        parent.resolved_profile_snapshot_id.map(|id| id.to_string()),
                        parent.workspace_ref.clone(),
                        now_unix_ms,
                    ],
                )?;
                insert_control_event(
                    conn,
                    session_id,
                    "agent_created",
                    child.agent_instance_id,
                    AgentInstanceState::Created.as_str(),
                    now_unix_ms,
                )?;
                let changed = conn.execute(
                    "UPDATE agent_instances
                     SET state = 'running', revision = 1, updated_at_unix_ms = ?1
                     WHERE agent_instance_id = ?2 AND session_id = ?3 AND state = 'created'",
                    params![now_unix_ms, child.agent_instance_id.to_string(), session_id.to_string()],
                )?;
                ensure!(changed == 1, "recursive child lifecycle start CAS lost");
                insert_control_event(
                    conn,
                    session_id,
                    "agent_transition",
                    child.agent_instance_id,
                    AgentInstanceState::Running.as_str(),
                    now_unix_ms,
                )?;
                conn.execute(
                    "INSERT INTO recursive_noninteractive_executors (
                         agent_instance_id, session_id, parent_agent_instance_id,
                         launch_json, snapshot_json, created_at_unix_ms, updated_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    params![
                        child.agent_instance_id.to_string(),
                        session_id.to_string(),
                        parent_agent_instance_id.to_string(),
                        child.launch.into_json(),
                        child.snapshot.into_json(),
                        now_unix_ms,
                    ],
                )?;
                rows.push(
                    load_agent(conn, session_id, child.agent_instance_id)?
                        .context("created recursive child agent missing")?,
                );
            }
            Ok(rows)
        }).await?;
        for child in &created {
            if let Some(snapshot_id) = child.resolved_profile_snapshot_id {
                self.set_agent_auto_answer_from_resolved_profile(
                    session_id,
                    child.agent_instance_id,
                    snapshot_id,
                    now_unix_ms,
                )
                .await?;
            }
        }
        Ok(created)
    }

    pub async fn insert_recursive_noninteractive_executor(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        parent_agent_instance_id: Uuid,
        launch: ValidatedRecursiveNoninteractiveLaunch,
        snapshot: ValidatedRecursiveNoninteractiveSnapshot,
        now_unix_ms: i64,
    ) -> Result<()> {
        self.transaction(move |conn| {
            let child = load_agent(conn, session_id, agent_instance_id)?
                .context("recursive executor child is not authorized for this session")?;
            ensure!(child.parent_agent_instance_id == Some(parent_agent_instance_id), "recursive executor parent does not match durable lineage");
            conn.execute(
                "INSERT INTO recursive_noninteractive_executors (
                     agent_instance_id, session_id, parent_agent_instance_id,
                     launch_json, snapshot_json, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![agent_instance_id.to_string(), session_id.to_string(), parent_agent_instance_id.to_string(), launch.into_json(), snapshot.into_json(), now_unix_ms],
            )?;
            Ok(())
        }).await
    }

    pub async fn persist_recursive_noninteractive_snapshot(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        snapshot: ValidatedRecursiveNoninteractiveSnapshot,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            Ok(conn.execute(
                "UPDATE recursive_noninteractive_executors
                    SET snapshot_json = ?1, updated_at_unix_ms = ?2
                  WHERE session_id = ?3 AND agent_instance_id = ?4",
                params![snapshot.into_json(), now_unix_ms, session_id.to_string(), agent_instance_id.to_string()],
            )? == 1)
        }).await
    }

    /// Atomically records one recursive child's authored outcome and its
    /// AgentTree terminal receipt.  Recursive batch dependency gates release
    /// only after this returns; recovery reads this row instead of attempting
    /// to reconstruct the terminal child from a live continuation descriptor.
    pub async fn settle_recursive_noninteractive_child_outcome(
        &self,
        session_id: Uuid,
        parent_agent_instance_id: Uuid,
        child_agent_instance_id: Uuid,
        label: String,
        child_agent: String,
        report: String,
        failed: bool,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let parent = load_agent(conn, session_id, parent_agent_instance_id)?
                .context("recursive outcome parent is not authorized for this session")?;
            ensure!(
                !parent.state.is_terminal(),
                "cannot record recursive child outcome below terminal parent"
            );
            let child = load_agent(conn, session_id, child_agent_instance_id)?
                .context("recursive outcome child is not authorized for this session")?;
            ensure!(
                child.parent_agent_instance_id == Some(parent_agent_instance_id),
                "recursive outcome child is not owned by parent"
            );
            let existing: Option<(String, String, String, i64)> = conn
                .query_row(
                    "SELECT label, child_agent, report, failed FROM recursive_noninteractive_outcomes
                      WHERE session_id = ?1 AND agent_instance_id = ?2
                        AND parent_agent_instance_id = ?3",
                    params![
                        session_id.to_string(),
                        child_agent_instance_id.to_string(),
                        parent_agent_instance_id.to_string(),
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            if let Some((existing_label, existing_child_agent, existing_report, existing_failed)) = existing {
                ensure!(
                    existing_label == label
                        && existing_child_agent == child_agent
                        && existing_report == report
                        && (existing_failed != 0) == failed,
                    "recursive child already has a different durable outcome"
                );
                ensure!(child.state.is_terminal(), "recursive outcome exists without terminal child");
                return Ok(false);
            }
            ensure!(
                !child.state.is_terminal(),
                "terminal recursive child is missing its durable outcome"
            );
            let next_state = if failed {
                AgentInstanceState::Failed
            } else {
                AgentInstanceState::Completed
            };
            ensure!(
                child.state.legal_transition(next_state),
                "recursive outcome attempted an illegal child lifecycle transition"
            );
            ensure!(
                !has_live_descendant(conn, session_id, child_agent_instance_id)?,
                "cannot settle recursive child while a descendant remains live"
            );
            ensure!(
                !has_live_owned_decision(conn, session_id, child_agent_instance_id)?,
                "cannot settle recursive child while an owned decision remains live"
            );
            reject_undelivered_late_user_steers_for_tree(
                conn,
                session_id,
                child_agent_instance_id,
                terminal_late_steer_rejection_reason(next_state),
                now_unix_ms,
            )?;
            let event_seq = insert_control_event(
                conn,
                session_id,
                "agent_transition",
                child_agent_instance_id,
                next_state.as_str(),
                now_unix_ms,
            )?;
            let changed = conn.execute(
                "UPDATE agent_instances
                    SET state = ?1, revision = ?2, updated_at_unix_ms = ?3
                  WHERE session_id = ?4 AND agent_instance_id = ?5 AND revision = ?6
                    AND state NOT IN ('completed', 'failed', 'cancelled')",
                params![
                    next_state.as_str(),
                    child.revision + 1,
                    now_unix_ms,
                    session_id.to_string(),
                    child_agent_instance_id.to_string(),
                    child.revision,
                ],
            )?;
            ensure!(changed == 1, "recursive child outcome terminal CAS lost");
            conn.execute(
                "INSERT INTO agent_transition_receipts (
                     agent_instance_id, terminal_state, session_id, terminal_revision,
                     receipt_json, session_event_seq, created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    child_agent_instance_id.to_string(),
                    next_state.as_str(),
                    session_id.to_string(),
                    child.revision + 1,
                    redacted_marker("recursive noninteractive child outcome"),
                    event_seq,
                    now_unix_ms,
                ],
            )?;
            conn.execute(
                "INSERT INTO recursive_noninteractive_outcomes (
                     agent_instance_id, session_id, parent_agent_instance_id,
                     label, child_agent, report, failed, completed_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    child_agent_instance_id.to_string(),
                    session_id.to_string(),
                    parent_agent_instance_id.to_string(),
                    label,
                    child_agent,
                    report,
                    if failed { 1_i64 } else { 0_i64 },
                    now_unix_ms,
                ],
            )?;
            Ok(true)
        })
        .await
    }

    /// Loads one committed recursive result, including the terminal child
    /// identity that produced it. This is recovery-only state and is never
    /// exposed through Attention or a resolver packet.
    pub async fn recursive_noninteractive_outcome(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
    ) -> Result<Option<RecursiveNoninteractiveOutcome>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT agent_instance_id, parent_agent_instance_id, label, child_agent, report, failed, completed_at_unix_ms
                   FROM recursive_noninteractive_outcomes
                  WHERE session_id = ?1 AND agent_instance_id = ?2",
                params![session_id.to_string(), agent_instance_id.to_string()],
                |row| {
                    Ok(RecursiveNoninteractiveOutcome {
                        agent_instance_id: parse_uuid(row.get::<_, String>(0)?)?,
                        parent_agent_instance_id: parse_uuid(row.get::<_, String>(1)?)?,
                        label: row.get(2)?,
                        child_agent: row.get(3)?,
                        report: row.get(4)?,
                        failed: row.get::<_, i64>(5)? != 0,
                        completed_at_unix_ms: row.get(6)?,
                    })
                },
            )
            .optional()
            .context("loading recursive noninteractive outcome")
        })
        .await
    }

    /// Commits the parent-visible synthetic result together with terminalizing
    /// the exact recursive children that produced it.  Recovery therefore sees
    /// either a durable waiting checkpoint and live children, or a durable
    /// ready parent continuation and terminal children—never the lossy middle
    /// state where a completed child report can be re-run after a crash.
    pub async fn complete_recursive_noninteractive_children_and_checkpoint_parent(
        &self,
        session_id: Uuid,
        parent_agent_instance_id: Uuid,
        parent_snapshot: ValidatedRecursiveNoninteractiveSnapshot,
        children: Vec<(Uuid, bool)>,
        now_unix_ms: i64,
    ) -> Result<()> {
        ensure!(!children.is_empty(), "recursive completion requires at least one child");
        let parent_snapshot_json = parent_snapshot.into_json();
        self.transaction(move |conn| {
            let parent = load_agent(conn, session_id, parent_agent_instance_id)?
                .context("recursive completion parent is not authorized for this session")?;
            ensure!(!parent.state.is_terminal(), "cannot resume a terminal recursive parent");
            let parent_updated = if let Some(task_child_uuid) = parent.task_delegation_child_uuid {
                conn.execute(
                    "UPDATE task_delegation_children
                        SET snapshot_json = ?1, updated_at = ?2
                      WHERE child_uuid = ?3
                        AND status IN ('running', 'backgrounded', 'paused_pending_tool')",
                    params![parent_snapshot_json, now_unix_ms / 1000, task_child_uuid.to_string()],
                )?
            } else {
                conn.execute(
                    "UPDATE recursive_noninteractive_executors
                        SET snapshot_json = ?1, updated_at_unix_ms = ?2
                      WHERE session_id = ?3 AND agent_instance_id = ?4",
                    params![parent_snapshot_json, now_unix_ms, session_id.to_string(), parent_agent_instance_id.to_string()],
                )?
            };
            ensure!(parent_updated == 1, "recursive completion parent has no live continuation descriptor");
            // Do not use a raw state update here.  A child can be parked on an
            // Attention record while its runner is reporting a sibling result,
            // and the normal lifecycle transition is the only place that
            // proves a terminal child has no live descendants or owned
            // decisions and records its terminal receipt.  Keeping those
            // checks in this same transaction gives recovery an all-or-nothing
            // view: the ready parent checkpoint is never committed beside a
            // child that can still resume its own continuation.
            for (child_agent_instance_id, failed) in children {
                let child = load_agent(conn, session_id, child_agent_instance_id)?
                    .context("recursive completion child is not authorized for this session")?;
                ensure!(child.parent_agent_instance_id == Some(parent_agent_instance_id), "recursive completion child is not owned by parent");
                if child.state.is_terminal() {
                    continue;
                }
                let next_state = if failed {
                    AgentInstanceState::Failed
                } else {
                    AgentInstanceState::Completed
                };
                ensure!(
                    child.state.legal_transition(next_state),
                    "recursive completion attempted an illegal child lifecycle transition"
                );
                ensure!(
                    !has_live_descendant(conn, session_id, child_agent_instance_id)?,
                    "cannot complete recursive child while a descendant remains live"
                );
                ensure!(
                    !has_live_owned_decision(conn, session_id, child_agent_instance_id)?,
                    "cannot complete recursive child while an owned decision remains live"
                );
                reject_undelivered_late_user_steers_for_tree(
                    conn,
                    session_id,
                    child_agent_instance_id,
                    terminal_late_steer_rejection_reason(next_state),
                    now_unix_ms,
                )?;
                let receipt_json = redacted_marker("recursive noninteractive child completion");
                let event_seq = insert_control_event(
                    conn,
                    session_id,
                    "agent_transition",
                    child_agent_instance_id,
                    next_state.as_str(),
                    now_unix_ms,
                )?;
                fail_after_control_event(1, child_agent_instance_id)?;
                let changed = conn.execute(
                    "UPDATE agent_instances
                        SET state = ?1, revision = ?2, updated_at_unix_ms = ?3
                      WHERE session_id = ?4 AND agent_instance_id = ?5 AND revision = ?6
                        AND state NOT IN ('completed', 'failed', 'cancelled')",
                    params![
                        next_state.as_str(),
                        child.revision + 1,
                        now_unix_ms,
                        session_id.to_string(),
                        child_agent_instance_id.to_string(),
                        child.revision,
                    ],
                )?;
                ensure!(
                    changed == 1,
                    "recursive child completion lost its exact lifecycle compare-and-set"
                );
                conn.execute(
                    "INSERT INTO agent_transition_receipts (
                         agent_instance_id, terminal_state, session_id, terminal_revision,
                         receipt_json, session_event_seq, created_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        child_agent_instance_id.to_string(),
                        next_state.as_str(),
                        session_id.to_string(),
                        child.revision + 1,
                        receipt_json,
                        Some(event_seq),
                        now_unix_ms,
                    ],
                )?;
                fail_after_control_event(4, child_agent_instance_id)?;
            }
            Ok(())
        }).await
    }

    pub async fn recursive_noninteractive_recovery_descriptor(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
    ) -> Result<Option<RecursiveNoninteractiveRecoveryDescriptor>> {
        self.read(move |conn| conn.query_row(
            "SELECT e.agent_instance_id, e.parent_agent_instance_id, e.launch_json, e.snapshot_json
               FROM recursive_noninteractive_executors e
               JOIN agent_instances a
                 ON a.agent_instance_id = e.agent_instance_id
                AND a.session_id = e.session_id
              WHERE e.session_id = ?1
                AND e.agent_instance_id = ?2
                AND a.state NOT IN ('completed', 'failed', 'cancelled')",
            params![session_id.to_string(), agent_instance_id.to_string()],
            |row| {
                let launch_json: String = row.get(2)?;
                let snapshot_json: String = row.get(3)?;
                let launch = ValidatedRecursiveNoninteractiveLaunch::parse_and_canonicalize(&launch_json)
                    .map_err(|error| invalid_persisted_value_with_error("recursive noninteractive launch descriptor", error))?;
                let snapshot = ValidatedRecursiveNoninteractiveSnapshot::parse_and_canonicalize(&snapshot_json)
                    .map_err(|error| invalid_persisted_value_with_error("recursive noninteractive snapshot", error))?;
                Ok(RecursiveNoninteractiveRecoveryDescriptor {
                    agent_instance_id: parse_uuid(row.get::<_, String>(0)?)?,
                    parent_agent_instance_id: parse_uuid(row.get::<_, String>(1)?)?,
                    launch,
                    snapshot,
                })
            },
        ).optional().context("loading recursive noninteractive recovery descriptor")).await
    }

    /// Looks up the lifecycle identity that was bound to a persisted task
    /// child. Executors use this read when they are reconstructed from the
    /// legacy delegation payload after a worker restart; it never mints a
    /// replacement child.
    pub async fn task_delegation_child_agent(
        &self,
        session_id: Uuid,
        task_call_id: String,
        label: String,
    ) -> Result<Option<AgentInstanceRow>> {
        self.read(move |conn| {
            let child_uuid: Option<String> = conn
                .query_row(
                    "SELECT c.child_uuid
                     FROM task_delegation_children c
                     JOIN task_delegation_jobs j ON j.task_call_id = c.task_call_id
                     WHERE c.task_call_id = ?1 AND c.label = ?2
                       AND j.parent_session_id = ?3",
                    params![task_call_id, label, session_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(child_uuid) = child_uuid else {
                return Ok(None);
            };
            let agent_id: Option<String> = conn
                .query_row(
                    "SELECT agent_instance_id FROM agent_instances
                     WHERE session_id = ?1 AND task_delegation_child_uuid = ?2",
                    params![session_id.to_string(), child_uuid],
                    |row| row.get(0),
                )
                .optional()?;
            match agent_id {
                Some(agent_id) => load_agent(conn, session_id, parse_uuid(agent_id)?),
                None => Ok(None),
            }
        })
        .await
    }

    /// Resolves the immutable legacy task identity for a recovered AgentTree
    /// child. Recovery uses this to reconcile the actual task executor record
    /// before it terminalizes the mapped node; it never derives identity from
    /// an agent name or a mutable display label.
    pub async fn task_delegation_binding_for_agent(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
    ) -> Result<Option<(String, String)>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT c.task_call_id, c.label
                   FROM agent_instances a
                   JOIN task_delegation_children c
                     ON c.child_uuid = a.task_delegation_child_uuid
                   JOIN task_delegation_jobs j
                     ON j.task_call_id = c.task_call_id
                  WHERE a.session_id = ?1
                    AND a.agent_instance_id = ?2
                    AND j.parent_session_id = ?1",
                params![session_id.to_string(), agent_instance_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context("resolving recovered task delegation child binding")
        })
        .await
    }

    /// Whether this exact lifecycle child is owned by a noninteractive task
    /// executor.  The task's immutable launch descriptor records the mode;
    /// absent/legacy descriptors deliberately default to `false` so they keep
    /// the foreground-compatible delivery path instead of silently dropping a
    /// steer into an executor that has not proved it owns one.
    pub async fn task_delegation_is_noninteractive_for_agent(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
    ) -> Result<bool> {
        self.read(move |conn| {
            let original_args_json: Option<String> = conn
                .query_row(
                    "SELECT j.original_args_json
                       FROM agent_instances a
                       JOIN task_delegation_children c
                         ON c.child_uuid = a.task_delegation_child_uuid
                       JOIN task_delegation_jobs j
                         ON j.task_call_id = c.task_call_id
                      WHERE a.session_id = ?1
                        AND a.agent_instance_id = ?2
                        AND j.parent_session_id = ?1",
                    params![session_id.to_string(), agent_instance_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(original_args_json
                .as_deref()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                .and_then(|value| value.get("interactive").and_then(serde_json::Value::as_bool))
                == Some(false))
        })
        .await
    }

    /// Load the exact persisted launch descriptor needed to reattach one
    /// task-backed executor after a worker crash. Missing fields are an error:
    /// recovery must leave the durable claim intact rather than inventing a
    /// replacement continuation from UI text or a display name.
    pub async fn task_delegation_recovery_descriptor(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
    ) -> Result<Option<TaskDelegationRecoveryDescriptor>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT a.agent_instance_id, a.parent_agent_instance_id,
                        c.task_call_id, c.label, c.child_agent,
                        j.original_args_json, c.snapshot_json, j.status, c.status
                   FROM agent_instances a
                   JOIN task_delegation_children c
                     ON c.child_uuid = a.task_delegation_child_uuid
                   JOIN task_delegation_jobs j
                     ON j.task_call_id = c.task_call_id
                  WHERE a.session_id = ?1
                    AND a.agent_instance_id = ?2
                    AND j.parent_session_id = ?1
                    AND c.status IN ('running', 'backgrounded', 'paused_pending_tool')",
                params![session_id.to_string(), agent_instance_id.to_string()],
                |row| {
                    let parent_agent_instance_id = row
                        .get::<_, Option<String>>(1)?
                        .map(parse_uuid)
                        .transpose()?
                        .ok_or_else(|| rusqlite::Error::InvalidQuery)?;
                    Ok(TaskDelegationRecoveryDescriptor {
                        agent_instance_id: parse_uuid(row.get::<_, String>(0)?)?,
                        parent_agent_instance_id,
                        task_call_id: row.get(2)?,
                        label: row.get(3)?,
                        child_agent: row.get(4)?,
                        original_args_json: row
                            .get::<_, Option<String>>(5)?
                            .ok_or_else(|| rusqlite::Error::InvalidQuery)?,
                        snapshot_json: row
                            .get::<_, Option<String>>(6)?
                            .ok_or_else(|| rusqlite::Error::InvalidQuery)?,
                        was_backgrounded: row.get::<_, String>(7)? == "backgrounded"
                            || row.get::<_, String>(8)? == "backgrounded",
                    })
                },
            )
            .optional()
            .context("loading task delegation recovery descriptor")
        })
        .await
    }

    /// Returns every still-live member of one exact task job. Recovery uses
    /// this for batch jobs so it can rebuild the declared dependency
    /// coordinator once, rather than launching independently claimed labels.
    pub async fn task_delegation_recovery_descriptors_for_job(
        &self,
        session_id: Uuid,
        task_call_id: String,
    ) -> Result<Vec<TaskDelegationRecoveryDescriptor>> {
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT a.agent_instance_id, a.parent_agent_instance_id,
                        c.task_call_id, c.label, c.child_agent,
                        j.original_args_json, c.snapshot_json, j.status, c.status
                   FROM agent_instances a
                   JOIN task_delegation_children c
                     ON c.child_uuid = a.task_delegation_child_uuid
                   JOIN task_delegation_jobs j
                     ON j.task_call_id = c.task_call_id
                  WHERE a.session_id = ?1
                    AND j.parent_session_id = ?1
                    AND c.task_call_id = ?2
                    AND c.status IN ('running', 'backgrounded', 'paused_pending_tool')
                  ORDER BY c.label ASC",
            )?;
            statement
                .query_map(params![session_id.to_string(), task_call_id], |row| {
                    let parent_agent_instance_id = row
                        .get::<_, Option<String>>(1)?
                        .map(parse_uuid)
                        .transpose()?
                        .ok_or_else(|| rusqlite::Error::InvalidQuery)?;
                    Ok(TaskDelegationRecoveryDescriptor {
                        agent_instance_id: parse_uuid(row.get::<_, String>(0)?)?,
                        parent_agent_instance_id,
                        task_call_id: row.get(2)?,
                        label: row.get(3)?,
                        child_agent: row.get(4)?,
                        original_args_json: row
                            .get::<_, Option<String>>(5)?
                            .ok_or_else(|| rusqlite::Error::InvalidQuery)?,
                        snapshot_json: row
                            .get::<_, Option<String>>(6)?
                            .ok_or_else(|| rusqlite::Error::InvalidQuery)?,
                        was_backgrounded: row.get::<_, String>(7)? == "backgrounded"
                            || row.get::<_, String>(8)? == "backgrounded",
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("loading task delegation recovery descriptors for job")
        })
        .await
    }

    /// Terminalizes the one lifecycle node already bound to a legacy task
    /// child. This deliberately performs no creation: completion, cancellation
    /// and restart reconciliation may only settle an executor that was
    /// attached when the task was launched.
    pub async fn terminalize_task_delegation_child_agent(
        &self,
        session_id: Uuid,
        task_call_id: String,
        label: String,
        next_state: AgentInstanceState,
        now_unix_ms: i64,
    ) -> Result<bool> {
        ensure!(next_state.is_terminal(), "task child lifecycle target must be terminal");
        let receipt_json = json!({
            "source": "task_delegation",
            "task_call_id": task_call_id.as_str(),
            "label": label.as_str(),
            "state": next_state.as_str(),
        })
        .to_string();
        for _ in 0..4 {
            let Some(agent) = self
                .task_delegation_child_agent(
                    session_id,
                    task_call_id.clone(),
                    label.clone(),
                )
                .await?
            else {
                return Ok(false);
            };
            match self
                .transition_agent_instance(
                    session_id,
                    agent.agent_instance_id,
                    agent.revision,
                    next_state,
                    &receipt_json,
                    now_unix_ms,
                )
                .await?
            {
                AgentTransitionOutcome::Transitioned(_) => return Ok(true),
                AgentTransitionOutcome::AlreadyTerminal(_) => return Ok(false),
                AgentTransitionOutcome::RevisionConflict => continue,
            }
        }
        bail!("task child lifecycle terminalization lost repeated revision races")
    }

    /// Linearizes a legacy task child's durable result with the terminal
    /// transition and receipt of its exact AgentTree node.
    ///
    /// A batch dependency is permitted to observe its predecessor only after
    /// this method returns.  In particular, callers must not first complete
    /// `task_delegation_children` and signal an in-memory watch, then try to
    /// terminalize `agent_instances`: a crash in that gap lets recovery run
    /// the predecessor again after a dependent has started.  The reverse gap
    /// is equally invalid because recovery would retain a live task claim for
    /// an already-terminal executor.
    ///
    /// The method also repairs the old split-write shape conservatively: if a
    /// prior daemon wrote the task terminal row but crashed before the agent
    /// receipt, it writes only the missing matching agent terminal transition.
    /// It never retargets a mismatched terminal result.
    pub async fn settle_task_delegation_child_and_agent(
        &self,
        session_id: Uuid,
        task_call_id: String,
        label: String,
        outcome: TaskDelegationTerminalState,
        report: Option<String>,
        snapshot_json: Option<String>,
        receipt_json: String,
        now_unix_ms: i64,
        /// A successful interactive child can be the exact owner of an
        /// already-accepted late user steer.  Its continuation receipt and
        /// the child/task terminal receipt must share this transaction: the
        /// ordinary terminalization path otherwise rejects the accepted steer
        /// while popping the very child that completed it.
        late_user_steer_completion: Option<(Uuid, Uuid)>,
    ) -> Result<bool> {
        let receipt_json = redact_receipt_json(&receipt_json)?;
        self.transaction(move |conn| {
            let target_task_state = outcome.delegation_status();
            let target_agent_state = outcome.agent_state();
            let (child_uuid, child_state): (Uuid, String) = conn
                .query_row(
                    "SELECT child_uuid, status
                       FROM task_delegation_children AS child
                       JOIN task_delegation_jobs AS job
                         ON job.task_call_id = child.task_call_id
                      WHERE child.task_call_id = ?1 AND child.label = ?2
                        AND job.parent_session_id = ?3",
                    params![task_call_id, label, session_id.to_string()],
                    |row| Ok((parse_uuid(row.get::<_, String>(0)?)?, row.get(1)?)),
                )
                .context("task delegation child is not authorized for this session")?;
            let agent_id: Uuid = conn
                .query_row(
                    "SELECT agent_instance_id FROM agent_instances
                      WHERE session_id = ?1 AND task_delegation_child_uuid = ?2",
                    params![session_id.to_string(), child_uuid.to_string()],
                    |row| parse_uuid(row.get::<_, String>(0)?),
                )
                .context("live task delegation child has no AgentTree executor")?;

            if let Some((steer_id, recovery_epoch)) = late_user_steer_completion {
                // This uses the same immutable epoch fence as the normal
                // executor completion CAS, but is deliberately co-located
                // with the task/AgentTree terminalization below.  A parent
                // continuation therefore can never inherit the child's
                // provider permit, and the generic terminal rejector observes
                // this exact row as completed rather than undelivered.
                let completed = conn.execute(
                    "UPDATE agent_decision_steers
                     SET execution_state = 'completed', completed_at_unix_ms = ?1
                     WHERE steer_id = ?2 AND session_id = ?3
                       AND agent_instance_id = ?4
                       AND delivered_at_unix_ms IS NULL
                       AND claimed_recovery_epoch = ?5
                       AND execution_state = 'accepted'
                       AND completed_at_unix_ms IS NULL
                       AND EXISTS (
                           SELECT 1 FROM agent_instances a
                            WHERE a.session_id = agent_decision_steers.session_id
                              AND a.agent_instance_id = agent_decision_steers.agent_instance_id
                              AND a.state = 'running'
                       )",
                    params![
                        now_unix_ms,
                        steer_id.to_string(),
                        session_id.to_string(),
                        agent_id.to_string(),
                        recovery_epoch.to_string(),
                    ],
                )?;
                if completed != 1 {
                    let already_completed: i64 = conn.query_row(
                        "SELECT EXISTS (
                             SELECT 1 FROM agent_decision_steers
                              WHERE steer_id = ?1 AND session_id = ?2
                                AND agent_instance_id = ?3
                                AND delivered_at_unix_ms IS NULL
                                AND claimed_recovery_epoch = ?4
                                AND execution_state = 'completed'
                                AND completed_at_unix_ms IS NOT NULL
                         )",
                        params![
                            steer_id.to_string(),
                            session_id.to_string(),
                            agent_id.to_string(),
                            recovery_epoch.to_string(),
                        ],
                        |row| row.get(0),
                    )?;
                    ensure!(
                        already_completed != 0,
                        "interactive task terminalization lost its exact late-steer completion claim"
                    );
                }
            }

            let mut changed = false;
            if matches!(child_state.as_str(), "running" | "backgrounded" | "paused_pending_tool") {
                let default_report = if outcome == TaskDelegationTerminalState::Cancelled {
                    Some("cancelled".to_owned())
                } else {
                    None
                };
                let report = report.or(default_report);
                let child_changed = conn.execute(
                    "UPDATE task_delegation_children
                        SET status = ?1,
                            report = COALESCE(?2, report),
                            snapshot_json = COALESCE(?3, snapshot_json),
                            finished_at = COALESCE(finished_at, ?4),
                            updated_at = ?4
                      WHERE task_call_id = ?5 AND label = ?6
                        AND status IN ('running', 'backgrounded', 'paused_pending_tool')",
                    params![
                        target_task_state,
                        report,
                        snapshot_json,
                        now_unix_ms / 1_000,
                        task_call_id,
                        label,
                    ],
                )?;
                ensure!(child_changed == 1, "task delegation terminalization lost its child CAS");
                changed = true;

                // A job cannot become terminal while a sibling is merely
                // created.  This matters for a crash between publication and
                // launch as much as it does for a dependency-gated batch.
                let (remaining, failed, cancelled): (i64, i64, i64) = conn.query_row(
                    "SELECT
                         COALESCE(SUM(status IN ('created', 'running', 'backgrounded', 'paused_pending_tool')), 0),
                         COALESCE(SUM(status IN ('failed', 'lost')), 0),
                         COALESCE(SUM(status = 'cancelled'), 0)
                       FROM task_delegation_children WHERE task_call_id = ?1",
                    params![task_call_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                if remaining == 0 {
                    let job_state = if failed > 0 {
                        "failed"
                    } else if cancelled > 0 {
                        "cancelled"
                    } else {
                        "completed"
                    };
                    conn.execute(
                        "UPDATE task_delegation_jobs SET status = ?1, updated_at = ?2
                          WHERE task_call_id = ?3",
                        params![job_state, now_unix_ms / 1_000, task_call_id],
                    )?;
                }
            } else if child_state != target_task_state {
                bail!(
                    "task delegation child already has incompatible terminal state `{child_state}` (wanted `{target_task_state}`)"
                );
            }

            let current = load_agent(conn, session_id, agent_id)?
                .context("task delegation AgentTree executor disappeared")?;
            if current.state.is_terminal() {
                ensure!(
                    current.state == target_agent_state,
                    "task delegation executor already has incompatible terminal state `{}`",
                    current.state.as_str()
                );
                return Ok(changed);
            }
            ensure!(
                current.state.legal_transition(target_agent_state),
                "illegal task delegation AgentTree terminal transition"
            );
            match target_agent_state {
                AgentInstanceState::Completed | AgentInstanceState::Failed => {
                    ensure!(
                        !has_live_descendant(conn, session_id, agent_id)?,
                        "cannot terminalize task executor while a descendant remains live"
                    );
                    ensure!(
                        !has_live_owned_decision(conn, session_id, agent_id)?,
                        "cannot terminalize task executor while an owned decision remains live"
                    );
                    reject_undelivered_late_user_steers_for_tree(
                        conn,
                        session_id,
                        agent_id,
                        terminal_late_steer_rejection_reason(target_agent_state),
                        now_unix_ms,
                    )?;
                }
                AgentInstanceState::Cancelled => {
                    cancel_owned_decisions_for_subtree(conn, session_id, agent_id, now_unix_ms)?;
                    cancel_live_descendants(conn, session_id, agent_id, now_unix_ms)?;
                }
                AgentInstanceState::Created
                | AgentInstanceState::Running
                | AgentInstanceState::WaitingForUser
                | AgentInstanceState::WaitingForApproval => unreachable!("terminal outcome maps to a terminal agent state"),
            }
            let next_revision = current.revision + 1;
            let event_seq = insert_control_event(
                conn,
                session_id,
                "agent_transition",
                agent_id,
                target_agent_state.as_str(),
                now_unix_ms,
            )?;
            let agent_changed = conn.execute(
                "UPDATE agent_instances
                    SET state = ?1, revision = ?2, updated_at_unix_ms = ?3
                  WHERE agent_instance_id = ?4 AND session_id = ?5 AND revision = ?6",
                params![
                    target_agent_state.as_str(),
                    next_revision,
                    now_unix_ms,
                    agent_id.to_string(),
                    session_id.to_string(),
                    current.revision,
                ],
            )?;
            ensure!(agent_changed == 1, "task delegation AgentTree terminal CAS lost");
            conn.execute(
                "INSERT INTO agent_transition_receipts (
                     agent_instance_id, terminal_state, session_id, terminal_revision,
                     receipt_json, session_event_seq, created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    agent_id.to_string(),
                    target_agent_state.as_str(),
                    session_id.to_string(),
                    next_revision,
                    receipt_json,
                    event_seq,
                    now_unix_ms,
                ],
            )?;
            Ok(true)
        })
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

    /// Returns a stable, paginated snapshot of a session's durable lineage in
    /// durable creation order. `root_agent_instance_id = None` lists the entire forest;
    /// callers cannot use a foreign root as an existence oracle.
    pub async fn agent_lineage_page(
        &self,
        session_id: Uuid,
        root_agent_instance_id: Option<Uuid>,
        after: Option<AgentTreePageCursor>,
        limit: usize,
    ) -> Result<AgentTreePage<AgentInstanceRow>> {
        ensure!(
            (1..=MAX_AGENT_TREE_PAGE_SIZE).contains(&limit),
            "agent lineage page limit is out of range"
        );
        self.read(move |conn| {
            let ids = list_lineage_ids_conn(conn, session_id, root_agent_instance_id, after.as_ref(), limit + 1)?;
            let has_more = ids.len() > limit;
            let ids = ids.into_iter().take(limit).collect::<Vec<_>>();
            let mut entries = Vec::with_capacity(ids.len());
            for id in ids {
                entries.push(load_agent(conn, session_id, id)?.context("lineage agent missing")?);
            }
            let next_cursor = has_more.then(|| {
                let last = entries.last().expect("nonempty paginated lineage");
                AgentTreePageCursor {
                    created_at_unix_ms: last.created_at_unix_ms,
                    id: last.agent_instance_id,
                }
            });
            Ok(AgentTreePage { entries, next_cursor })
        })
        .await
    }

    /// Lists typed attention projections in the same deterministic order as
    /// their durable creation. Legacy interrupt rows never enter this API.
    pub async fn decision_attention_page(
        &self,
        session_id: Uuid,
        after: Option<AgentTreePageCursor>,
        limit: usize,
    ) -> Result<AgentTreePage<DecisionAttentionRow>> {
        ensure!(
            (1..=MAX_AGENT_TREE_PAGE_SIZE).contains(&limit),
            "decision attention page limit is out of range"
        );
        self.read(move |conn| {
            let (where_clause, args): (&str, Vec<rusqlite::types::Value>) = match after {
                Some(cursor) => (
                    "AND (n.raised_at > ?2 OR (n.raised_at = ?2 AND n.interrupt_id > ?3))",
                    vec![session_id.to_string().into(), cursor.created_at_unix_ms.into(), cursor.id.to_string().into()],
                ),
                None => ("", vec![session_id.to_string().into()]),
            };
            let sql = format!(
                "SELECT n.interrupt_id, n.agent_instance_id, n.state, n.raised_at, n.resolved_at, n.decision_request_id
                 FROM needs_attention n
                 WHERE n.session_id = ?1 AND n.decision_request_id IS NOT NULL {where_clause}
                 ORDER BY n.raised_at, n.interrupt_id LIMIT ?{}",
                args.len() + 1
            );
            let mut args = args;
            args.push(((limit + 1) as i64).into());
            let mut statement = conn.prepare(&sql)?;
            let rows = statement.query_map(rusqlite::params_from_iter(args), |row| {
                Ok((
                    parse_uuid(row.get::<_, String>(0)?)?,
                    parse_uuid(row.get::<_, String>(1)?)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    parse_uuid(row.get::<_, String>(5)?)?,
                ))
            })?.collect::<rusqlite::Result<Vec<_>>>()?;
            let has_more = rows.len() > limit;
            let mut entries = Vec::with_capacity(rows.len().min(limit));
            for (attention_id, agent_instance_id, state, raised_at_unix_ms, resolved_at_unix_ms, decision_id) in rows.into_iter().take(limit) {
                entries.push(DecisionAttentionRow {
                    attention_id,
                    session_id,
                    agent_instance_id,
                    state,
                    raised_at_unix_ms,
                    resolved_at_unix_ms,
                    decision: load_decision(conn, session_id, decision_id)?.context("attention decision missing")?,
                });
            }
            let next_cursor = has_more.then(|| {
                let last = entries.last().expect("nonempty paginated attention");
                AgentTreePageCursor { created_at_unix_ms: last.raised_at_unix_ms, id: last.attention_id }
            });
            Ok(AgentTreePage { entries, next_cursor })
        }).await
    }

    /// Read one bounded, keyset-paginated recovery slice.  This is the
    /// maintenance API: callers must carry `next_cursor` forward rather than
    /// materializing an unbounded session backlog merely to choose a small
    /// round-robin slice.  The cursor exactly matches the durable order.
    pub async fn recoverable_decision_requests_page(
        &self,
        session_id: Uuid,
        after: Option<AgentTreePageCursor>,
        limit: usize,
    ) -> Result<AgentTreePage<DecisionRequestRow>> {
        ensure!(
            (1..=MAX_AGENT_TREE_PAGE_SIZE).contains(&limit),
            "recoverable decision page limit is out of range"
        );
        self.read(move |conn| {
            let (where_clause, mut args): (&str, Vec<rusqlite::types::Value>) = match after {
                Some(cursor) => (
                    "AND (created_at_unix_ms > ?2 OR (created_at_unix_ms = ?2 AND decision_request_id > ?3))",
                    vec![
                        session_id.to_string().into(),
                        cursor.created_at_unix_ms.into(),
                        cursor.id.to_string().into(),
                    ],
                ),
                None => ("", vec![session_id.to_string().into()]),
            };
            let sql = format!(
                "SELECT decision_request_id, created_at_unix_ms FROM decision_requests
                 WHERE session_id = ?1 AND state IN ('pending', 'resolving') {where_clause}
                 ORDER BY created_at_unix_ms, decision_request_id LIMIT ?{}",
                args.len() + 1,
            );
            args.push(((limit + 1) as i64).into());
            let mut statement = conn.prepare(&sql)?;
            let rows = statement
                .query_map(rusqlite::params_from_iter(args), |row| {
                    Ok((
                        parse_uuid(row.get::<_, String>(0)?)?,
                        row.get::<_, i64>(1)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let has_more = rows.len() > limit;
            let rows = rows.into_iter().take(limit).collect::<Vec<_>>();
            let mut entries = Vec::with_capacity(rows.len());
            for (decision_request_id, _) in &rows {
                entries.push(
                    load_decision(conn, session_id, *decision_request_id)?
                        .context("recoverable decision missing")?,
                );
            }
            let next_cursor = has_more.then(|| {
                let (id, created_at_unix_ms) = rows.last().expect("nonempty paginated decision");
                AgentTreePageCursor {
                    created_at_unix_ms: *created_at_unix_ms,
                    id: *id,
                }
            });
            Ok(AgentTreePage { entries, next_cursor })
        })
        .await
    }

    /// Returns the newest ordered lifecycle event for this session only. It
    /// is used solely to annotate a session-scoped invalidation after the
    /// transaction has committed; callers cannot query a foreign session.
    pub async fn latest_agent_tree_event_seq(&self, session_id: Uuid) -> Result<Option<i64>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT MAX(seq) FROM session_events
                 WHERE session_id = ?1 AND type = 'agent_tree'",
                [session_id.to_string()],
                |row| row.get(0),
            )
            .context("loading latest agent-tree event sequence")
        })
        .await
    }

    /// Read committed control events after an exclusive session sequence. This
    /// is intentionally a read-only relay API: callers must not synthesize
    /// lifecycle broadcasts or write a second audit event for an already
    /// committed transition.
    pub async fn agent_tree_events_after(
        &self,
        session_id: Uuid,
        after_session_event_seq: i64,
        limit: usize,
    ) -> Result<Vec<AgentTreeEventRow>> {
        ensure!(limit > 0 && limit <= 1_000, "agent tree event page limit is out of range");
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT seq, data_json FROM session_events
                 WHERE session_id = ?1 AND type = 'agent_tree' AND seq > ?2
                 ORDER BY seq ASC LIMIT ?3",
            )?;
            let rows = statement
                .query_map(
                    params![session_id.to_string(), after_session_event_seq, limit as i64],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows.into_iter()
                .map(|(session_event_seq, data_json)| {
                    let value: serde_json::Value = serde_json::from_str(&data_json)
                        .context("decoding persisted agent-tree event")?;
                    let kind = value
                        .get("kind")
                        .and_then(serde_json::Value::as_str)
                        .context("agent-tree event is missing kind")?
                        .to_owned();
                    let subject_id = value
                        .get("subject_id")
                        .and_then(serde_json::Value::as_str)
                        .context("agent-tree event is missing subject id")?;
                    let subject_kind = value
                        .get("subject_kind")
                        .and_then(serde_json::Value::as_str)
                        .context("agent-tree event is missing subject kind")?
                        .to_owned();
                    Ok(AgentTreeEventRow {
                        session_id,
                        session_event_seq,
                        kind,
                        subject_kind,
                        subject_id: parse_uuid(subject_id.to_owned())?,
                    })
                })
                .collect()
        })
        .await
    }

    /// Claims the current nonterminal agent revision for one daemon recovery
    /// epoch. The epoch is daemon-owned and fresh per boot; repeated scans in
    /// that boot get `false`, while a later restart may legitimately resume a
    /// still-nonterminal node once again.
    pub async fn claim_agent_resume(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        expected_revision: i64,
        recovery_epoch: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let Some(agent) = load_agent(conn, session_id, agent_instance_id)? else {
                return Ok(false);
            };
            if agent.state.is_terminal() || agent.revision != expected_revision {
                return Ok(false);
            }
            let inserted = conn.execute(
                "INSERT INTO agent_resume_claims (
                     agent_instance_id, session_id, agent_revision, recovery_epoch, claimed_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(agent_instance_id, agent_revision, recovery_epoch) DO NOTHING",
                params![
                    agent_instance_id.to_string(),
                    session_id.to_string(),
                    expected_revision,
                    recovery_epoch.to_string(),
                    now_unix_ms,
                ],
            )?;
            if inserted == 1 {
                insert_control_event(
                    conn,
                    session_id,
                    "recovery_claimed",
                    agent_instance_id,
                    // Recovery attaches a real executor before it redelivers
                    // a parked decision.  A child waiting on that decision is
                    // still a valid executor attachment candidate; rendering
                    // this event as `running` used to hide that distinction
                    // from the ordered ledger.
                    agent.state.as_str(),
                    now_unix_ms,
                )?;
            }
            Ok(inserted == 1)
        }).await
    }

    /// A claim remains observable until a fresh continuation accepts it. The
    /// compare-and-set makes repeated recovery delivery attempts a no-op.
    pub async fn consume_agent_resume_claim(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        agent_revision: i64,
        recovery_epoch: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE agent_resume_claims SET consumed_at_unix_ms = ?1
                 WHERE agent_instance_id = ?2 AND session_id = ?3
                   AND agent_revision = ?4 AND recovery_epoch = ?5
                   AND consumed_at_unix_ms IS NULL
                   AND EXISTS (
                       SELECT 1 FROM agent_instances a
                        WHERE a.agent_instance_id = agent_resume_claims.agent_instance_id
                          AND a.session_id = agent_resume_claims.session_id
                          AND a.revision = agent_resume_claims.agent_revision
                          AND a.state NOT IN ('completed', 'failed', 'cancelled')
                   )",
                params![
                    now_unix_ms,
                    agent_instance_id.to_string(),
                    session_id.to_string(),
                    agent_revision,
                    recovery_epoch.to_string(),
                ],
            )?;
            if changed == 1 {
                let agent = load_agent(conn, session_id, agent_instance_id)?
                    .context("recovery-attached agent disappeared after exact attachment CAS")?;
                insert_control_event(
                    conn,
                    session_id,
                    "recovery_attached",
                    agent_instance_id,
                    agent.state.as_str(),
                    now_unix_ms,
                )?;
            }
            Ok(changed == 1)
        })
        .await
    }

    /// Consume an entire recovered executor set as one durable attachment
    /// acknowledgement.
    /// A recursive/batch reattach may expose several resolver mailboxes before
    /// it can acknowledge any of them.  Consuming them one at a time permits a
    /// late conflict to strand an earlier sibling as attached even though the
    /// batch as a whole must be retried.  The database transaction begins
    /// `IMMEDIATE`, so the all-unconsumed preflight and the subsequent writes
    /// are one linearizable decision.
    pub async fn consume_agent_resume_claims_atomically(
        &self,
        session_id: Uuid,
        claims: Vec<(Uuid, i64)>,
        recovery_epoch: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        anyhow::ensure!(
            !claims.is_empty(),
            "atomic recovery consumption requires at least one claim"
        );
        self.transaction(move |conn| {
            let mut identities = std::collections::HashSet::with_capacity(claims.len());
            for (agent_instance_id, agent_revision) in &claims {
                anyhow::ensure!(
                    identities.insert((*agent_instance_id, *agent_revision)),
                    "atomic recovery consumption contains a duplicate agent revision"
                );
                let consumed_at: Option<Option<i64>> = conn
                    .query_row(
                        "SELECT consumed_at_unix_ms FROM agent_resume_claims
                          WHERE agent_instance_id = ?1 AND session_id = ?2
                            AND agent_revision = ?3 AND recovery_epoch = ?4",
                        params![
                            agent_instance_id.to_string(),
                            session_id.to_string(),
                            agent_revision,
                            recovery_epoch.to_string(),
                        ],
                        |row| row.get(0),
                    )
                    .optional()?;
                // Do the complete read preflight before the first write. The
                // writer transaction owns the immediate lock, therefore a
                // failed set has made no visible acknowledgement and a retry
                // can reuse every exact claim.
                if consumed_at != Some(None) {
                    return Ok(false);
                }
                let Some(agent) = load_agent(conn, session_id, *agent_instance_id)? else {
                    return Ok(false);
                };
                // This is an executor-attachment CAS, not the provider
                // dispatch permit. Cancellation or any newer lifecycle
                // transition wins before a reconstructed mailbox can be
                // released through this acknowledgement, but a child that is
                // waiting on an already-durable QuestionTool/approval still
                // needs its exact mailbox attached before that decision may be
                // replayed. The later provider handoff has its own
                // `running`-only late-steer permit.
                if agent.revision != *agent_revision || agent.state.is_terminal() {
                    return Ok(false);
                }
            }
            for (agent_instance_id, agent_revision) in &claims {
                let changed = conn.execute(
                    "UPDATE agent_resume_claims SET consumed_at_unix_ms = ?1
                     WHERE agent_instance_id = ?2 AND session_id = ?3
                       AND agent_revision = ?4 AND recovery_epoch = ?5
                       AND consumed_at_unix_ms IS NULL
                       AND EXISTS (
                           SELECT 1 FROM agent_instances a
                            WHERE a.agent_instance_id = agent_resume_claims.agent_instance_id
                              AND a.session_id = agent_resume_claims.session_id
                              AND a.revision = agent_resume_claims.agent_revision
                              -- This acknowledgement proves that an exact
                              -- executor mailbox has attached. It deliberately
                              -- accepts every current nonterminal lifecycle
                              -- state: a WaitingForUser/WaitingForApproval
                              -- child must attach before its durable decision
                              -- can replay. The later external-provider
                              -- permit remains independently `running` only.
                              AND a.state NOT IN ('completed', 'failed', 'cancelled')
                       )",
                    params![
                        now_unix_ms,
                        agent_instance_id.to_string(),
                        session_id.to_string(),
                        agent_revision,
                        recovery_epoch.to_string(),
                    ],
                )?;
                anyhow::ensure!(
                    changed == 1,
                    "atomic recovery consumption changed after its exact preflight"
                );
            }
            for (agent_instance_id, agent_revision) in claims {
                let agent = load_agent(conn, session_id, agent_instance_id)?
                    .context("recovery-attached agent disappeared after exact attachment CAS")?;
                anyhow::ensure!(
                    agent.revision == agent_revision && !agent.state.is_terminal(),
                    "recovery-attached agent changed after exact attachment CAS"
                );
                insert_control_event(
                    conn,
                    session_id,
                    "recovery_attached",
                    agent_instance_id,
                    agent.state.as_str(),
                    now_unix_ms,
                )?;
            }
            Ok(true)
        })
        .await
    }

    /// Releases a recovery claim which could not be attached to a real
    /// executor.  This is deliberately a compare-and-delete on the exact
    /// recovery epoch and agent revision: a newer daemon must never release
    /// work claimed by its successor.  Releasing is observable so clients do
    /// not see a permanently-running node with no executable owner.
    pub async fn release_agent_resume_claim(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        agent_revision: i64,
        recovery_epoch: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let changed = conn.execute(
                "DELETE FROM agent_resume_claims
                 WHERE agent_instance_id = ?1 AND session_id = ?2
                   AND agent_revision = ?3 AND recovery_epoch = ?4
                   AND consumed_at_unix_ms IS NULL",
                params![
                    agent_instance_id.to_string(),
                    session_id.to_string(),
                    agent_revision,
                    recovery_epoch.to_string(),
                ],
            )?;
            if changed == 1 {
                insert_control_event(
                    conn,
                    session_id,
                    "recovery_released",
                    agent_instance_id,
                    AgentInstanceState::Running.as_str(),
                    now_unix_ms,
                )?;
            }
            Ok(changed == 1)
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
            } else if next_state.is_terminal() {
                // A terminal executor has no successor continuation for an
                // accepted late user steer.  Unlike a completed steer (which
                // remains receipt-only acknowledgeable), pending/accepted
                // rows must receive their own durable terminal receipt in the
                // same transaction as the lifecycle state.  Otherwise a
                // recursive child that failed after acceptance would be
                // permanently unrecoverable but still look resumable.
                reject_undelivered_late_user_steers_for_tree(
                    conn,
                    session_id,
                    agent_instance_id,
                    terminal_late_steer_rejection_reason(next_state),
                    now_unix_ms,
                )?;
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
        self.create_decision_request_with_attention(
            input,
            None,
            DecisionCreationKind::Generic,
            now_unix_ms,
        )
            .await
    }

    /// Attach a durable decision to an already-persisted interactive question
    /// row.  This is the compatibility seam for `QuestionTool`: it retains the
    /// real interrupt/wakeup path while making the single existing Attention
    /// record and its continuation receipt authoritative.
    pub async fn create_decision_request_for_interrupt(
        &self,
        input: NewDecisionRequest,
        interrupt_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<DecisionRequestRow> {
        self.create_decision_request_with_attention(
            input,
            Some(interrupt_id),
            DecisionCreationKind::Generic,
            now_unix_ms,
        )
            .await
    }

    /// Create the sole automatically-resolvable decision class through the
    /// daemon-owned host-capability refresh composition boundary. The opaque
    /// authority has no safe constructor, and this single transaction binds
    /// the concrete operation, its real QuestionTool interrupt, and the new
    /// decision before any resolver can observe the row.
    #[cfg(feature = "host-capability-refresh-composition")]
    pub async fn create_host_capability_refresh_decision_for_interrupt(
        &self,
        input: NewDecisionRequest,
        operation_id: Uuid,
        request_id: Uuid,
        requires_dedicated_child_initialization: bool,
        interrupt_id: Uuid,
        authority: HostCapabilityRefreshAuthority,
        now_unix_ms: i64,
    ) -> Result<DecisionRequestRow> {
        ensure!(
            !operation_id.is_nil() && !request_id.is_nil(),
            "host capability refresh operation identities must not be nil"
        );
        self.create_decision_request_with_attention(
            input,
            Some(interrupt_id),
            DecisionCreationKind::HostCapabilityRefresh {
                operation_id,
                request_id,
                requires_dedicated_child_initialization,
                authority,
            },
            now_unix_ms,
        )
        .await
    }

    /// Bind a previously reserved final host operation to its real
    /// QuestionTool interrupt and approval decision in one transaction.  The
    /// generic creation APIs categorically reject `host_approval`; there is
    /// intentionally no reserve-then-generic-bind escape hatch.
    #[cfg(feature = "host-approval-composition")]
    pub async fn create_host_approval_decision_for_interrupt(
        &self,
        input: NewDecisionRequest,
        interrupt_id: Uuid,
        authority: HostApprovalAuthority,
        now_unix_ms: i64,
    ) -> Result<DecisionRequestRow> {
        self.create_decision_request_with_attention(
            input,
            Some(interrupt_id),
            DecisionCreationKind::HostApproval { authority },
            now_unix_ms,
        )
        .await
    }

    /// Read one bounded keyset page of decisions that have already allowed
    /// the exact host probe but have not crossed its boundary.  The cursor is
    /// the precise `(created_at_unix_ms, operation_id)` SQL order; callers
    /// advance it between maintenance turns rather than materializing every
    /// allowed operation in one worker tick.
    pub async fn ready_host_capability_refresh_operations_page(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        after: Option<AgentTreePageCursor>,
        limit: usize,
    ) -> Result<AgentTreePage<HostCapabilityRefreshOperationRow>> {
        ensure!(
            (1..=MAX_AGENT_TREE_PAGE_SIZE).contains(&limit),
            "ready host capability refresh page limit is out of range"
        );
        self.read(move |conn| {
            let (where_clause, mut args): (&str, Vec<rusqlite::types::Value>) = match after {
                Some(cursor) => (
                    "AND (created_at_unix_ms > ?2 OR (created_at_unix_ms = ?2 AND operation_id > ?3))",
                    vec![
                        session_id.to_string().into(),
                        cursor.created_at_unix_ms.into(),
                        cursor.id.to_string().into(),
                    ],
                ),
                None => ("", vec![session_id.to_string().into()]),
            };
            let sql = format!(
                "SELECT operation_id, request_id, session_id, agent_instance_id,
                        interrupt_id, decision_request_id, state,
                        reserved_snapshot_generation, result_snapshot_json,
                        result_snapshot_generation, result_snapshot_digest,
                        published_at_unix_ms, error_text, created_at_unix_ms,
                        completed_at_unix_ms
                   FROM host_capability_refresh_operations
                  WHERE session_id = ?1 AND state = 'allowed' {where_clause}
                  ORDER BY created_at_unix_ms, operation_id LIMIT ?{}",
                args.len() + 1,
            );
            args.push(((limit + 1) as i64).into());
            let mut statement = conn.prepare(&sql)?;
            let rows = statement
                .query_map(rusqlite::params_from_iter(args), host_capability_refresh_operation_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let has_more = rows.len() > limit;
            let entries = rows.into_iter().take(limit).collect::<Vec<_>>();
            let next_cursor = has_more.then(|| {
                let last = entries.last().expect("nonempty paginated allowed refresh");
                AgentTreePageCursor {
                    created_at_unix_ms: last.created_at_unix_ms,
                    id: last.operation_id,
                }
            });
            Ok(AgentTreePage { entries, next_cursor })
        })
        .await
    }

    /// Read the daemon-global reservation high-water. The allocator exists
    /// even when no operation has completed, because a crash after claim must
    /// still prevent a later process from recycling that generation.
    pub async fn host_capability_refresh_generation_high_water(
        &self,
        _authority: HostCapabilityRefreshAuthority,
    ) -> Result<u64> {
        self.read(|conn| {
            let value: i64 = conn.query_row(
                "SELECT high_water_generation
                   FROM host_capability_refresh_generation_allocator
                  WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?;
            u64::try_from(value)
                .context("host capability refresh generation high-water is invalid")
        })
        .await
    }

    /// Reserve the generation used by the daemon's initial in-memory host
    /// snapshot. Boot is not an AgentTree operation, but it is visible in the
    /// same generation namespace; recording it prevents the first approved
    /// refresh from reusing generation one in that live store.
    pub async fn reserve_host_capability_boot_snapshot_generation(
        &self,
        _authority: HostCapabilityRefreshAuthority,
    ) -> Result<u64> {
        self.transaction(|conn| {
            let changed = conn.execute(
                "UPDATE host_capability_refresh_generation_allocator
                    SET high_water_generation = high_water_generation + 1
                  WHERE singleton = 1",
                [],
            )?;
            ensure!(changed == 1, "host capability refresh generation allocator is missing");
            let generation: i64 = conn.query_row(
                "SELECT high_water_generation
                   FROM host_capability_refresh_generation_allocator
                  WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?;
            u64::try_from(generation)
                .context("reserved host capability boot snapshot generation is invalid")
        })
        .await
    }

    /// The greatest completed durable receipt, including an already-published
    /// one. A new daemon seeds its store from this exact serialized fact rather
    /// than resetting an in-memory counter to one after a prior acknowledgement.
    pub async fn latest_completed_host_capability_refresh_snapshot_receipt(
        &self,
        _authority: HostCapabilityRefreshAuthority,
    ) -> Result<Option<HostCapabilityRefreshSnapshotReceipt>> {
        self.read(|conn| {
            conn.query_row(
                "SELECT result_snapshot_json, result_snapshot_generation, result_snapshot_digest
                   FROM host_capability_refresh_operations
                  WHERE state = 'completed'
                  ORDER BY result_snapshot_generation DESC, completed_at_unix_ms DESC, operation_id DESC
                  LIMIT 1",
                [],
                |row| {
                    let generation: i64 = row.get(1)?;
                    Ok((row.get::<_, String>(0)?, generation, row.get::<_, String>(2)?))
                },
            )
            .optional()?
            .map(|(result_snapshot_json, generation, digest)| {
                let generation = u64::try_from(generation)
                    .context("host capability refresh completed receipt generation is invalid")?;
                validate_host_capability_refresh_snapshot_receipt(
                    result_snapshot_json.clone(),
                    generation,
                    &digest,
                )?;
                Ok(HostCapabilityRefreshSnapshotReceipt {
                    result_snapshot_json,
                    generation,
                    digest,
                })
            })
            .transpose()
        })
        .await
    }

    /// The newest receipt which has already crossed the durable publication
    /// acknowledgement. Boot may seed its in-memory store from this fact, but
    /// it must replay every unacknowledged completed receipt in generation
    /// order before it reserves or publishes a newer boot generation. Using
    /// `latest_completed_*` for that seed would incorrectly install a newer
    /// outbox entry first and make an older pending acknowledgement
    /// unpublishable on the same boot.
    pub async fn latest_published_host_capability_refresh_snapshot_receipt(
        &self,
        _authority: HostCapabilityRefreshAuthority,
    ) -> Result<Option<HostCapabilityRefreshSnapshotReceipt>> {
        self.read(|conn| {
            conn.query_row(
                "SELECT result_snapshot_json, result_snapshot_generation, result_snapshot_digest
                   FROM host_capability_refresh_operations
                  WHERE state = 'completed' AND published_at_unix_ms IS NOT NULL
                  ORDER BY result_snapshot_generation DESC, completed_at_unix_ms DESC, operation_id DESC
                  LIMIT 1",
                [],
                |row| {
                    let generation: i64 = row.get(1)?;
                    Ok((row.get::<_, String>(0)?, generation, row.get::<_, String>(2)?))
                },
            )
            .optional()?
            .map(|(result_snapshot_json, generation, digest)| {
                let generation = u64::try_from(generation)
                    .context("host capability refresh published receipt generation is invalid")?;
                validate_host_capability_refresh_snapshot_receipt(
                    result_snapshot_json.clone(),
                    generation,
                    &digest,
                )?;
                Ok(HostCapabilityRefreshSnapshotReceipt {
                    result_snapshot_json,
                    generation,
                    digest,
                })
            })
            .transpose()
        })
        .await
    }

    /// Durable completion outbox entries for the *whole daemon* capability
    /// store. Their probe has already crossed the exactly-once boundary;
    /// recovery must publish this recorded snapshot rather than rerun the
    /// probe.  The store is daemon-global rather than session-local, so a
    /// per-session outbox scan is incorrect: an unpublished generation from
    /// session A must be made visible before session B can probe or publish a
    /// newer generation.
    ///
    /// The durable snapshot generation is the primary ordering key. The
    /// completion timestamp and operation id make rows with equal/malformed
    /// generations deterministic, which is important when a recovery worker
    /// restarts halfway through a drain. Valid completion receipts are always
    /// full `HostCapabilitySnapshot`s, but retaining a stable fallback order
    /// lets the dispatcher fail closed on the first invalid receipt rather
    /// than nondeterministically overtaking it.
    pub async fn completed_unpublished_host_capability_refresh_operations_page(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        after: Option<HostCapabilityRefreshOutboxCursor>,
        limit: usize,
    ) -> Result<HostCapabilityRefreshOutboxPage> {
        ensure!(
            (1..=MAX_AGENT_TREE_PAGE_SIZE).contains(&limit),
            "completed host capability refresh outbox page limit is out of range"
        );
        self.read(move |conn| {
            let (where_clause, mut args): (&str, Vec<rusqlite::types::Value>) = match after {
                Some(cursor) => (
                    "AND (result_snapshot_generation > ?1
                         OR (result_snapshot_generation = ?1 AND completed_at_unix_ms > ?2)
                         OR (result_snapshot_generation = ?1 AND completed_at_unix_ms = ?2 AND operation_id > ?3))",
                    vec![
                        i64::try_from(cursor.result_snapshot_generation)
                            .context("host capability refresh outbox cursor generation exceeds SQLite range")?
                            .into(),
                        cursor.completed_at_unix_ms.into(),
                        cursor.operation_id.to_string().into(),
                    ],
                ),
                None => ("", Vec::new()),
            };
            let sql = format!(
                "SELECT operation_id, request_id, session_id, agent_instance_id,
                        interrupt_id, decision_request_id, state,
                        reserved_snapshot_generation, result_snapshot_json,
                        result_snapshot_generation, result_snapshot_digest,
                        published_at_unix_ms, error_text, created_at_unix_ms,
                        completed_at_unix_ms
                   FROM host_capability_refresh_operations
                  WHERE state = 'completed'
                    AND published_at_unix_ms IS NULL
                    {where_clause}
                  ORDER BY result_snapshot_generation, completed_at_unix_ms, operation_id
                  LIMIT ?{}",
                args.len() + 1,
            );
            args.push(((limit + 1) as i64).into());
            let mut statement = conn.prepare(&sql)?;
            let rows = statement
                .query_map(rusqlite::params_from_iter(args), host_capability_refresh_operation_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let has_more = rows.len() > limit;
            let entries = rows.into_iter().take(limit).collect::<Vec<_>>();
            let next_cursor = has_more.then(|| {
                let last = entries.last().expect("nonempty paginated refresh outbox");
                HostCapabilityRefreshOutboxCursor {
                    result_snapshot_generation: last
                        .result_snapshot_generation
                        .expect("completed refresh has a snapshot generation"),
                    completed_at_unix_ms: last
                        .completed_at_unix_ms
                        .expect("completed refresh has a completion timestamp"),
                    operation_id: last.operation_id,
                }
            });
            Ok(HostCapabilityRefreshOutboxPage { entries, next_cursor })
        })
        .await
    }

    /// Acknowledge the durable completion outbox only after the exact stored
    /// snapshot was handed to the idempotent generation store. This is a
    /// no-op for a prior winner, which lets a crash after the in-memory swap
    /// retry safely without another probe or duplicate lifecycle state.
    pub async fn mark_host_capability_refresh_published(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        operation_id: Uuid,
        result_snapshot_generation: u64,
        result_snapshot_digest: String,
        now_unix_ms: i64,
    ) -> Result<bool> {
        validate_host_capability_refresh_snapshot_identity(
            result_snapshot_generation,
            &result_snapshot_digest,
        )?;
        self.transaction(move |conn| {
            Ok(conn.execute(
                "UPDATE host_capability_refresh_operations
                    SET published_at_unix_ms = ?1, updated_at_unix_ms = ?1
                  WHERE operation_id = ?2 AND session_id = ?3
                    AND state = 'completed'
                    AND result_snapshot_json IS NOT NULL
                    AND result_snapshot_generation = ?4
                    AND result_snapshot_digest = ?5
                    AND reserved_snapshot_generation = ?4
                    AND published_at_unix_ms IS NULL",
                params![
                    now_unix_ms,
                    operation_id.to_string(),
                    session_id.to_string(),
                    i64::try_from(result_snapshot_generation)
                        .context("host capability refresh generation exceeds SQLite range")?,
                    result_snapshot_digest,
                ],
            )? == 1)
        })
        .await
    }

    /// A refresh RPC owns an attention row but not a parked tool replay. On
    /// restart that open row must remain answerable: marking it interrupted
    /// would discard the only route from its durable decision to the pending
    /// host operation. The caller uses this only to exempt the dedicated
    /// operation from generic parked-continuation reconciliation.
    pub async fn has_pending_host_capability_refresh_interrupt(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        interrupt_id: Uuid,
    ) -> Result<bool> {
        self.read(move |conn| {
            let exists: i64 = conn.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM host_capability_refresh_operations
                      WHERE session_id = ?1 AND interrupt_id = ?2
                        AND state = 'pending'
                        AND EXISTS (
                            SELECT 1 FROM needs_attention n
                             WHERE n.interrupt_id = host_capability_refresh_operations.interrupt_id
                               AND n.session_id = host_capability_refresh_operations.session_id
                               AND n.decision_request_id IS NOT NULL
                        )
                 )",
                params![session_id.to_string(), interrupt_id.to_string()],
                |row| row.get(0),
            )?;
            Ok(exists != 0)
        })
        .await
    }

    /// Every durable refresh operation whose dedicated child still needs an
    /// executor/lifecycle reconciliation.  This deliberately includes every
    /// operation state, not merely `pending`: a process can die after a
    /// terminal operation CAS but before its child lifecycle/Attention
    /// acknowledgement, and a completed publication can be either published
    /// or still waiting in the outbox. The caller must attach the typed host
    /// endpoint before it consumes the child's recovery claim, then use the
    /// row state to dispatch or terminalize it.
    pub async fn nonterminal_host_capability_refresh_operations(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
    ) -> Result<Vec<HostCapabilityRefreshOperationRow>> {
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT operation.operation_id, operation.request_id, operation.session_id,
                        operation.agent_instance_id, operation.interrupt_id,
                        operation.decision_request_id, operation.state,
                        operation.reserved_snapshot_generation,
                        operation.result_snapshot_json,
                        operation.result_snapshot_generation,
                        operation.result_snapshot_digest,
                        operation.published_at_unix_ms, operation.error_text,
                        operation.created_at_unix_ms, operation.completed_at_unix_ms
                   FROM host_capability_refresh_operations operation
                   JOIN agent_instances child
                     ON child.agent_instance_id = operation.agent_instance_id
                    AND child.session_id = operation.session_id
                  WHERE operation.session_id = ?1
                    AND child.state NOT IN ('completed', 'failed', 'cancelled')
                  ORDER BY operation.created_at_unix_ms, operation.operation_id",
            )?;
            statement
                .query_map([session_id.to_string()], host_capability_refresh_operation_from_row)?
                .collect()
        })
        .await
    }

    /// A terminal operation can outlive the worker that terminalized its
    /// child but crashed before acknowledging the linked executing Attention
    /// row. This scan is intentionally independent of the child lifecycle:
    /// once the child is terminal it no longer appears in the nonterminal
    /// recovery inventory, but its exact Attention acknowledgement still
    /// needs the common terminal finalizer on the next boot.
    pub async fn terminal_host_capability_refresh_interrupts_requiring_finalization(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT operation.interrupt_id
                   FROM host_capability_refresh_operations operation
                   JOIN needs_attention attention
                     ON attention.interrupt_id = operation.interrupt_id
                    AND attention.session_id = operation.session_id
                  WHERE operation.session_id = ?1
                    AND operation.state IN ('completed', 'failed', 'cancelled')
                    AND attention.state = 'executing'
                  ORDER BY operation.created_at_unix_ms, operation.operation_id",
            )?;
            statement
                .query_map([session_id.to_string()], |row| {
                    parse_uuid(row.get::<_, String>(0)?)
                })?
                .collect()
        })
        .await
    }

    /// Look up the one daemon-owned refresh operation bound to a real
    /// QuestionTool interrupt.  Recovery uses this to distinguish a typed
    /// host-operation continuation from a model/driver continuation: the
    /// former must acknowledge its executing Attention claim directly and
    /// must never be replayed through a foreground driver.
    pub async fn host_capability_refresh_operation_for_interrupt(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        interrupt_id: Uuid,
    ) -> Result<Option<HostCapabilityRefreshOperationRow>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT operation_id, request_id, session_id, agent_instance_id,
                        interrupt_id, decision_request_id, state,
                        reserved_snapshot_generation, result_snapshot_json,
                        result_snapshot_generation, result_snapshot_digest,
                        published_at_unix_ms, error_text, created_at_unix_ms,
                        completed_at_unix_ms
                   FROM host_capability_refresh_operations
                  WHERE session_id = ?1 AND interrupt_id = ?2",
                params![session_id.to_string(), interrupt_id.to_string()],
                host_capability_refresh_operation_from_row,
            )
            .optional()
            .map_err(Into::into)
        })
        .await
    }

    /// Load the exact daemon-owned refresh operation after its direct waiter
    /// has returned. The caller has the daemon-minted operation id, never a
    /// protocol-supplied selector; this is used to hand the final Attention
    /// acknowledgement to the shared typed terminalizer.
    pub async fn host_capability_refresh_operation_by_id(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Option<HostCapabilityRefreshOperationRow>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT operation_id, request_id, session_id, agent_instance_id,
                        interrupt_id, decision_request_id, state,
                        reserved_snapshot_generation, result_snapshot_json,
                        result_snapshot_generation, result_snapshot_digest,
                        published_at_unix_ms, error_text, created_at_unix_ms,
                        completed_at_unix_ms
                   FROM host_capability_refresh_operations
                  WHERE session_id = ?1 AND operation_id = ?2",
                params![session_id.to_string(), operation_id.to_string()],
                host_capability_refresh_operation_from_row,
            )
            .optional()
            .map_err(Into::into)
        })
        .await
    }

    /// Claim the real local-probe boundary exactly once. A completed result is
    /// returned for an idempotent live retry; all other states fail closed.
    ///
    /// `owner_token` is allocated by the actual worker task, not inferred from
    /// process identity. This makes every subsequent renewal and terminal
    /// write an exact capability rather than an update by operation id alone.
    pub async fn claim_host_capability_refresh_execution(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        operation_id: Uuid,
        owner_token: Uuid,
        lease_expires_at_unix_ms: i64,
        now_unix_ms: i64,
    ) -> Result<HostCapabilityRefreshExecutionClaim> {
        ensure!(!owner_token.is_nil(), "host capability refresh lease owner token must not be nil");
        ensure!(
            lease_expires_at_unix_ms > now_unix_ms,
            "host capability refresh execution lease must expire in the future"
        );
        self.transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE host_capability_refresh_operations
                    SET state = 'executing',
                        execution_agent_revision = (
                            SELECT a.revision FROM agent_instances a
                             WHERE a.session_id = host_capability_refresh_operations.session_id
                               AND a.agent_instance_id = host_capability_refresh_operations.agent_instance_id
                        ),
                        execution_epoch = execution_epoch + 1,
                        execution_lease_owner_token = ?1,
                        execution_lease_expires_at_unix_ms = ?2,
                        reserved_snapshot_generation = (
                            SELECT high_water_generation + 1
                              FROM host_capability_refresh_generation_allocator
                             WHERE singleton = 1
                        ),
                        updated_at_unix_ms = ?3
                  WHERE operation_id = ?4 AND session_id = ?5
                    AND state = 'allowed'
                    AND decision_request_id IS NOT NULL
                    AND EXISTS (
                        SELECT 1 FROM decision_requests d
                         WHERE d.decision_request_id = host_capability_refresh_operations.decision_request_id
                           AND d.session_id = host_capability_refresh_operations.session_id
                           AND d.state IN ('answered', 'auto_resolved')
                    )
                    AND EXISTS (
                        SELECT 1 FROM agent_instances a
                         WHERE a.session_id = host_capability_refresh_operations.session_id
                           AND a.agent_instance_id = host_capability_refresh_operations.agent_instance_id
                           AND a.state NOT IN ('completed', 'failed', 'cancelled')
                    )
                    -- This is a durable second fence behind the daemon's
                    -- shared-store mutex. A stale/second process can never
                    -- start a newer probe while *any session* sharing this
                    -- daemon-global store owns an execution receipt or a
                    -- completed receipt still needs publication.  The latter
                    -- matters after a crash: a later generation from another
                    -- session must not make the older durable receipt
                    -- permanently unpublishable.
                    AND NOT EXISTS (
                    SELECT 1 FROM host_capability_refresh_operations active
                         WHERE (
                                active.state = 'executing'
                                OR (
                                    active.state = 'completed'
                                    AND active.result_snapshot_json IS NOT NULL
                                    AND active.published_at_unix_ms IS NULL
                                )
                           )
                    )",
                params![
                    owner_token.to_string(),
                    lease_expires_at_unix_ms,
                    now_unix_ms,
                    operation_id.to_string(),
                    session_id.to_string(),
                ],
            )?;
            if changed == 1 {
                // Reserve this exact generation only after the allowed →
                // executing CAS won. Both updates are inside the same
                // IMMEDIATE transaction, so no other daemon process can see
                // a claim without its global generation reservation.
                let allocated = conn.execute(
                    "UPDATE host_capability_refresh_generation_allocator
                        SET high_water_generation = high_water_generation + 1
                      WHERE singleton = 1",
                    [],
                )?;
                ensure!(allocated == 1, "host capability refresh generation allocator is missing");
                let (execution_epoch, owner_agent_revision, snapshot_generation): (i64, i64, i64) = conn.query_row(
                    "SELECT execution_epoch, execution_agent_revision, reserved_snapshot_generation
                       FROM host_capability_refresh_operations
                      WHERE operation_id = ?1 AND session_id = ?2
                        AND state = 'executing' AND execution_lease_owner_token = ?3",
                    params![
                        operation_id.to_string(),
                        session_id.to_string(),
                        owner_token.to_string(),
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                ensure!(
                    execution_epoch > 0 && owner_agent_revision >= 0 && snapshot_generation >= 1,
                    "host capability refresh claim did not persist a valid execution fence"
                );
                return Ok(HostCapabilityRefreshExecutionClaim::Claimed {
                    lease: HostCapabilityRefreshExecutionLease {
                        execution_epoch,
                        owner_token,
                        owner_agent_revision,
                        snapshot_generation: u64::try_from(snapshot_generation)
                            .context("host capability refresh reserved generation is invalid")?,
                    },
                });
            }
            let operation: Option<(String, Option<String>, Option<i64>, Option<String>, Option<String>)> = conn
                .query_row(
                    "SELECT state, result_snapshot_json, result_snapshot_generation,
                            result_snapshot_digest, error_text
                       FROM host_capability_refresh_operations
                      WHERE operation_id = ?1 AND session_id = ?2",
                    params![operation_id.to_string(), session_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .optional()?;
            let another_refresh_blocks_execution: i64 = conn.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM host_capability_refresh_operations
                      WHERE operation_id <> ?1
                        AND (
                            state = 'executing'
                            OR (
                                state = 'completed'
                                AND result_snapshot_json IS NOT NULL
                                AND published_at_unix_ms IS NULL
                            )
                        )
                 )",
                params![operation_id.to_string()],
                |row| row.get(0),
            )?;
            Ok(match operation {
                Some((state, Some(result_snapshot_json), Some(generation), Some(digest), _))
                    if state == "completed" =>
                {
                    let generation = u64::try_from(generation)
                        .context("completed host capability refresh generation is invalid")?;
                    validate_host_capability_refresh_snapshot_receipt(
                        result_snapshot_json.clone(),
                        generation,
                        &digest,
                    )?;
                    HostCapabilityRefreshExecutionClaim::Completed {
                        receipt: HostCapabilityRefreshSnapshotReceipt {
                            result_snapshot_json,
                            generation,
                            digest,
                        },
                    }
                }
                Some((state, _, _, _, _))
                    if state == "executing"
                        || (state == "allowed" && another_refresh_blocks_execution != 0) =>
                {
                    HostCapabilityRefreshExecutionClaim::InFlight
                }
                Some((state, _, _, _, error_text)) if state == "failed" => {
                    HostCapabilityRefreshExecutionClaim::Failed {
                        error_text: error_text.unwrap_or_else(|| {
                            "host capability refresh failed without a durable error".to_string()
                        }),
                    }
                }
                Some((state, _, _, _, error_text)) if state == "cancelled" => {
                    HostCapabilityRefreshExecutionClaim::Cancelled {
                        error_text: error_text.unwrap_or_else(|| {
                            "host capability refresh was cancelled without a durable reason".to_string()
                        }),
                    }
                }
                _ => HostCapabilityRefreshExecutionClaim::NotReady,
            })
        })
        .await
    }

    /// Commit the staged probe result only if the exact owner revision which
    /// claimed the probe is still live and still holds its execution lease.
    /// The caller publishes the staged snapshot only after this transaction
    /// succeeds, making cancellation, renewal loss, and revision changes a
    /// durable fence rather than a late observable result.
    pub async fn complete_host_capability_refresh_execution(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        operation_id: Uuid,
        lease: &HostCapabilityRefreshExecutionLease,
        result_snapshot_json: String,
        result_snapshot_generation: u64,
        result_snapshot_digest: String,
        now_unix_ms: i64,
    ) -> Result<bool> {
        let result_snapshot_json = validate_host_capability_refresh_snapshot_receipt(
            result_snapshot_json,
            result_snapshot_generation,
            &result_snapshot_digest,
        )?;
        let result_snapshot_generation = i64::try_from(result_snapshot_generation)
            .context("host capability refresh generation exceeds SQLite range")?;
        let lease = lease.clone();
        self.transaction(move |conn| {
            Ok(conn.execute(
                "UPDATE host_capability_refresh_operations
                    SET state = 'completed', result_snapshot_json = ?1,
                        result_snapshot_generation = ?2,
                        result_snapshot_digest = ?3,
                        updated_at_unix_ms = ?4, completed_at_unix_ms = ?4
                  WHERE operation_id = ?5 AND session_id = ?6
                    AND state = 'executing'
                    AND execution_epoch = ?7
                    AND execution_lease_owner_token = ?8
                    AND execution_agent_revision = ?9
                    AND reserved_snapshot_generation = ?2
                    AND execution_lease_expires_at_unix_ms > ?4
                    AND EXISTS (
                        SELECT 1 FROM agent_instances a
                         WHERE a.session_id = host_capability_refresh_operations.session_id
                           AND a.agent_instance_id = host_capability_refresh_operations.agent_instance_id
                           AND a.revision = host_capability_refresh_operations.execution_agent_revision
                           AND a.state NOT IN ('completed', 'failed', 'cancelled')
                    )",
                params![
                    result_snapshot_json,
                    result_snapshot_generation,
                    result_snapshot_digest,
                    now_unix_ms,
                    operation_id.to_string(),
                    session_id.to_string(),
                    lease.execution_epoch,
                    lease.owner_token.to_string(),
                    lease.owner_agent_revision,
                ],
            )? == 1)
        })
        .await
    }

    /// Renew a live probe's durable execution lease. This does not change the
    /// operation state or owner identity. A false result means cancellation,
    /// reaping, or an owner/revision fence won and the caller must drop any
    /// staged probe result without publishing it.
    pub async fn renew_host_capability_refresh_execution_lease(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        operation_id: Uuid,
        lease: &HostCapabilityRefreshExecutionLease,
        lease_expires_at_unix_ms: i64,
        now_unix_ms: i64,
    ) -> Result<bool> {
        ensure!(
            lease_expires_at_unix_ms > now_unix_ms,
            "host capability refresh renewal lease must expire in the future"
        );
        let lease = lease.clone();
        self.transaction(move |conn| {
            Ok(conn.execute(
                "UPDATE host_capability_refresh_operations
                    SET execution_lease_expires_at_unix_ms = ?1,
                        updated_at_unix_ms = ?2
                  WHERE operation_id = ?3 AND session_id = ?4
                    AND state = 'executing'
                    AND execution_epoch = ?5
                    AND execution_lease_owner_token = ?6
                    AND execution_agent_revision = ?7
                    AND execution_lease_expires_at_unix_ms > ?2
                    AND EXISTS (
                        SELECT 1 FROM agent_instances a
                         WHERE a.session_id = host_capability_refresh_operations.session_id
                           AND a.agent_instance_id = host_capability_refresh_operations.agent_instance_id
                           AND a.revision = host_capability_refresh_operations.execution_agent_revision
                           AND a.state NOT IN ('completed', 'failed', 'cancelled')
                    )",
                params![
                    lease_expires_at_unix_ms,
                    now_unix_ms,
                    operation_id.to_string(),
                    session_id.to_string(),
                    lease.execution_epoch,
                    lease.owner_token.to_string(),
                    lease.owner_agent_revision,
                ],
            )? == 1)
        })
        .await
    }

    pub async fn fail_host_capability_refresh_execution(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        operation_id: Uuid,
        lease: &HostCapabilityRefreshExecutionLease,
        error_text: String,
        now_unix_ms: i64,
    ) -> Result<bool> {
        ensure!(
            !error_text.trim().is_empty() && error_text.len() <= 8 * 1024,
            "host capability refresh failure text is invalid"
        );
        let lease = lease.clone();
        self.transaction(move |conn| {
            Ok(conn.execute(
                "UPDATE host_capability_refresh_operations
                    SET state = 'failed', error_text = ?1,
                        updated_at_unix_ms = ?2, completed_at_unix_ms = ?2
                  WHERE operation_id = ?3 AND session_id = ?4
                    AND state = 'executing'
                    AND execution_epoch = ?5
                    AND execution_lease_owner_token = ?6
                    AND execution_agent_revision = ?7",
                params![
                    error_text,
                    now_unix_ms,
                    operation_id.to_string(),
                    session_id.to_string(),
                    lease.execution_epoch,
                    lease.owner_token.to_string(),
                    lease.owner_agent_revision,
                ],
            )? == 1)
        })
        .await
    }

    /// Cancel a refresh before it crosses the local probe boundary. An
    /// executing refresh is cancelled only by `cancel_owned_decisions_for_subtree`,
    /// which atomically cancels its dedicated child and operation together;
    /// this standalone API must not create half of that lifecycle outcome.
    pub async fn cancel_host_capability_refresh_operation(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        operation_id: Uuid,
        error_text: String,
        now_unix_ms: i64,
    ) -> Result<bool> {
        ensure!(
            !error_text.trim().is_empty() && error_text.len() <= 8 * 1024,
            "host capability refresh cancellation text is invalid"
        );
        self.transaction(move |conn| {
            Ok(conn.execute(
                "UPDATE host_capability_refresh_operations
                    SET state = 'cancelled', error_text = ?1,
                        updated_at_unix_ms = ?2, completed_at_unix_ms = ?2
                  WHERE operation_id = ?3 AND session_id = ?4
                    AND state IN ('pending', 'allowed')",
                params![
                    error_text,
                    now_unix_ms,
                    operation_id.to_string(),
                    session_id.to_string(),
                ],
            )? == 1)
        })
        .await
    }

    /// Abort the daemon-owned pre-bind half of one refresh attempt while the
    /// worker is still alive. This is distinct from cancelling a bound refresh
    /// operation: before the atomic bind there is no executable operation to
    /// cancel, only an initializing child and, possibly, its raw QuestionTool
    /// attention row. Keeping every mutation in one transaction prevents
    /// ordinary runtime errors from leaving a descriptor that only boot could
    /// repair.
    #[cfg(feature = "host-capability-refresh-composition")]
    pub async fn abort_host_capability_refresh_initialization(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        operation_id: Uuid,
        request_id: Uuid,
        agent_instance_id: Uuid,
        raw_interrupt_id: Option<Uuid>,
        now_unix_ms: i64,
    ) -> Result<HostCapabilityRefreshInitializationAbort> {
        ensure!(
            !operation_id.is_nil() && !request_id.is_nil(),
            "host capability refresh initialization identities must not be nil"
        );
        self.transaction(move |conn| {
            abort_host_capability_refresh_initialization_conn(
                conn,
                session_id,
                operation_id,
                request_id,
                agent_instance_id,
                raw_interrupt_id,
                "host capability refresh runtime failed before its real interrupt, decision, and operation were bound",
                now_unix_ms,
            )
        })
        .await
    }

    /// Close an operation whose execution boundary was crossed by the prior
    /// process. A local probe is read-only, but silently issuing it again
    /// would still violate this request's exactly-once state machine; callers
    /// receive a durable failed outcome and may make a new refresh request.
    pub async fn reconcile_host_capability_refresh_operations(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<usize> {
        self.transaction(move |conn| {
            // The direct daemon refresh path publishes a child plus this
            // descriptor before it can acquire the real QuestionTool
            // interrupt.  A still-initializing descriptor therefore means no
            // decision, interrupt bind, or executable operation was ever
            // committed as one tuple.  Terminalize its child *before* generic
            // tree recovery sees it, rather than guessing how an otherwise
            // ordinary nonterminal child should resume.
            let initializing = {
                let mut statement = conn.prepare(
                    "SELECT operation_id, request_id, agent_instance_id
                       FROM host_capability_refresh_initializations
                      WHERE session_id = ?1 AND state = 'initializing'
                      ORDER BY created_at_unix_ms, operation_id",
                )?;
                statement
                    .query_map(params![session_id.to_string()], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            for (operation_id_raw, request_id_raw, child_id_raw) in &initializing {
                let operation_id = parse_uuid(operation_id_raw.clone())?;
                let request_id = parse_uuid(request_id_raw.clone())?;
                let child_id = parse_uuid(child_id_raw.clone())?;
                let outcome = abort_host_capability_refresh_initialization_conn(
                    conn,
                    session_id,
                    operation_id,
                    request_id,
                    child_id,
                    None,
                    "daemon stopped before host capability refresh child was bound to its real interrupt, decision, and operation",
                    now_unix_ms,
                )?;
                ensure!(
                    outcome == HostCapabilityRefreshInitializationAbort::Aborted,
                    "startup initialization scan lost its exact initializing descriptor"
                );
            }
            // The current squashed schema has no split operation/decision
            // state: the typed composition boundary binds both in one
            // transaction. A pending operation whose real interrupt is
            // already decision-owned is therefore corrupt imported durable
            // state, not a recoverable earlier release shape. Do not infer or
            // rewrite authority at startup.
            let split_binding: Option<String> = conn
                .query_row(
                    "SELECT operation_id
                       FROM host_capability_refresh_operations
                      WHERE session_id = ?1 AND state = 'pending'
                        AND decision_request_id IS NULL
                        AND EXISTS (
                            SELECT 1 FROM needs_attention n
                             WHERE n.interrupt_id = host_capability_refresh_operations.interrupt_id
                               AND n.session_id = host_capability_refresh_operations.session_id
                               AND n.decision_request_id IS NOT NULL
                        )
                      LIMIT 1",
                    params![session_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            ensure!(
                split_binding.is_none(),
                "host capability refresh operation has a malformed split decision binding"
            );
            // There is no persisted decision contract before the decision
            // creation transaction. A process death in the earlier
            // reserve-only window therefore cannot be reconstructed safely;
            // close that operation rather than retaining an executable row
            // whose option contract was never committed. A row whose
            // Attention already owns a decision is rejected above rather than
            // repaired.
            conn.execute(
                "UPDATE host_capability_refresh_operations
                    SET state = 'cancelled',
                        error_text = 'daemon stopped before host capability refresh decision was created',
                        updated_at_unix_ms = ?1, completed_at_unix_ms = ?1
                  WHERE session_id = ?2 AND state = 'pending'
                    AND decision_request_id IS NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM needs_attention n
                         WHERE n.interrupt_id = host_capability_refresh_operations.interrupt_id
                           AND n.session_id = host_capability_refresh_operations.session_id
                           AND n.decision_request_id IS NOT NULL
                    )",
                params![now_unix_ms, session_id.to_string()],
            )?;
            conn.execute(
                "UPDATE host_capability_refresh_operations
                    SET state = 'failed',
                        error_text = 'daemon stopped after host capability refresh probe began',
                        updated_at_unix_ms = ?1, completed_at_unix_ms = ?1
                  WHERE session_id = ?2 AND state = 'executing'",
                params![now_unix_ms, session_id.to_string()],
            )?;
            Ok(initializing.len())
        })
        .await
    }

    /// Periodically reap only genuinely expired, unrenewed execution claims.
    /// Startup may reconcile every `executing` row because no old executor is
    /// live then; an active worker renews its token-fenced lease while a probe
    /// runs, so elapsed wall time alone cannot fail a healthy execution.
    pub async fn reap_stale_host_capability_refresh_operations(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        session_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<usize> {
        self.transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE host_capability_refresh_operations
                    SET state = 'failed',
                        error_text = 'host capability refresh execution lease expired before a durable completion receipt',
                        updated_at_unix_ms = ?1,
                        completed_at_unix_ms = ?1
                  WHERE session_id = ?2
                    AND state = 'executing'
                    AND execution_epoch > 0
                    AND execution_lease_owner_token IS NOT NULL
                    AND execution_lease_expires_at_unix_ms IS NOT NULL
                    AND execution_lease_expires_at_unix_ms <= ?1",
                params![now_unix_ms, session_id.to_string()],
            )?;
            Ok(changed)
        })
        .await
    }

    /// Reap expired execution leases across every session sharing the
    /// daemon-global capability snapshot store. A live refresh in session B
    /// must not wait forever behind an abandoned execution from a session A
    /// whose worker did not restart or receive another tick. The exact
    /// token-fenced lease predicate remains the authority, so this never
    /// terminates a healthy probe before its published expiry.
    pub async fn reap_stale_host_capability_refresh_operations_globally(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        now_unix_ms: i64,
    ) -> Result<usize> {
        self.transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE host_capability_refresh_operations
                    SET state = 'failed',
                        error_text = 'host capability refresh execution lease expired before a durable completion receipt',
                        updated_at_unix_ms = ?1,
                        completed_at_unix_ms = ?1
                  WHERE state = 'executing'
                    AND execution_epoch > 0
                    AND execution_lease_owner_token IS NOT NULL
                    AND execution_lease_expires_at_unix_ms IS NOT NULL
                    AND execution_lease_expires_at_unix_ms <= ?1",
                [now_unix_ms],
            )?;
            Ok(changed)
        })
        .await
    }

    /// Daemon boot owns a new process epoch. No previous process lease can be
    /// live across that boundary, so every globally executing probe must be
    /// terminalized before boot reserves or publishes a later capability
    /// generation. This is intentionally stronger than the periodic expiry
    /// reaper, which must preserve a healthy current-process heartbeat.
    pub async fn reconcile_host_capability_refresh_execution_leases_at_boot(
        &self,
        _authority: HostCapabilityRefreshAuthority,
        now_unix_ms: i64,
    ) -> Result<usize> {
        self.transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE host_capability_refresh_operations
                    SET state = 'failed',
                        error_text = 'daemon boot fenced a prior-process host capability refresh execution lease',
                        updated_at_unix_ms = ?1,
                        completed_at_unix_ms = ?1
                  WHERE state = 'executing'",
                [now_unix_ms],
            )?;
            Ok(changed)
        })
        .await
    }

    /// A global generation must never be reserved while an execution claim is
    /// still live. Boot calls this after fencing the previous process so an
    /// unexpected partial repair is a hard failure rather than a generation
    /// overtake.
    pub async fn has_executing_host_capability_refresh_operations(
        &self,
        _authority: HostCapabilityRefreshAuthority,
    ) -> Result<bool> {
        self.read(|conn| {
            let exists: i64 = conn.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM host_capability_refresh_operations
                      WHERE state = 'executing'
                 )",
                [],
                |row| row.get(0),
            )?;
            Ok(exists != 0)
        })
        .await
    }

    /// Reserve the concrete final operation at the host composition boundary.
    /// A later decision can only bind this already-existing row; the generic
    /// decision creation path never manufactures a host approval operation.
    #[cfg(feature = "host-approval-composition")]
    pub async fn reserve_host_approval_final_operation(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        operation_id: Uuid,
        operation_kind: String,
        canonical_input_json: String,
        input_digest: String,
        _authority: HostApprovalAuthority,
        now_unix_ms: i64,
    ) -> Result<()> {
        ensure!(!operation_id.is_nil(), "host approval operation id must not be nil");
        validate_host_operation_binding(&operation_kind, &input_digest)?;
        validate_host_operation_canonical_input(&canonical_input_json, &input_digest)?;
        self.transaction(move |conn| {
            ensure!(
                load_agent(conn, session_id, agent_instance_id)?.is_some(),
                "host approval operation owner is not authorized for this session"
            );
            conn.execute(
                "INSERT INTO agent_host_approval_operations (
                     operation_id, session_id, agent_instance_id, operation_kind, canonical_input_json, input_digest,
                     decision_request_id, state, created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'pending', ?7)",
                params![
                    operation_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    operation_kind,
                    canonical_input_json,
                    input_digest,
                    now_unix_ms,
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// Materialize the one durable, *unclaimed* handoff for a host-approved
    /// operation.
    ///
    /// Approval and effect submission are intentionally separate.  This
    /// method may run when the QuestionTool continuation wakes, which is
    /// often well before a command, MCP request, grant mutation, or other
    /// concrete host boundary.  It only creates an opaque pending capability;
    /// [`Self::claim_host_approval_effect_handoff`] performs the irreversible
    /// transition immediately at the real effect boundary.  In particular, a
    /// restart between these calls is safe to reject/re-prompt, while a restart
    /// after a successful claim is always `submission_unknown` and never
    /// replayed.
    #[cfg(feature = "host-approval-composition")]
    pub async fn consume_host_approval_final_operation(
        &self,
        authority: HostApprovalAuthority,
        interrupt_id: Uuid,
        session_id: Uuid,
        agent_instance_id: Uuid,
        operation_id: Uuid,
        operation_kind: String,
        canonical_input_json: String,
        input_digest: String,
        now_unix_ms: i64,
    ) -> Result<bool> {
        validate_host_operation_binding(&operation_kind, &input_digest)?;
        validate_host_operation_canonical_input(&canonical_input_json, &input_digest)?;
        self.transaction(move |conn| {
            ensure!(
                host_approval_operation_has_exact_interrupt(
                    conn,
                    authority,
                    session_id,
                    agent_instance_id,
                    operation_id,
                    interrupt_id,
                )?,
                "host approval effect handoff is not bound to its exact interrupt"
            );
            let approved: Option<i64> = conn
                .query_row(
                    "SELECT 1
                       FROM agent_host_approval_operations AS operation
                       JOIN agent_instances AS agent
                         ON agent.agent_instance_id = operation.agent_instance_id
                        AND agent.session_id = operation.session_id
                      WHERE operation.operation_id = ?1 AND operation.session_id = ?2
                        AND operation.agent_instance_id = ?3 AND operation.operation_kind = ?4
                        AND operation.canonical_input_json = ?5 AND operation.input_digest = ?6
                        AND operation.selected_response_json IS NOT NULL
                        AND operation.selected_candidate_json IS NOT NULL
                        AND operation.state = 'approved'
                        AND operation.approved_agent_revision = agent.revision
                        AND agent.state = 'running'",
                    params![
                        operation_id.to_string(),
                        session_id.to_string(),
                        agent_instance_id.to_string(),
                        operation_kind,
                        canonical_input_json.clone(),
                        input_digest,
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            if approved.is_none() {
                return Ok(false);
            }
            // The stable operation UUID is the only permissible idempotency
            // identity. A prompt ID or UI path is not an effect identity.  A
            // `ready` row is not an external handoff: it is still cancellable
            // and cannot be replayed as an effect until the exact boundary
            // claims it below.
            let inserted = conn.execute(
                "INSERT INTO agent_host_approval_effect_handoffs (
                     operation_id, session_id, agent_instance_id, operation_kind, canonical_input_json, input_digest,
                     selected_candidate_json, idempotency_key, state, dispatch_started_at_unix_ms
                 ) SELECT ?1, ?2, ?3, ?4, ?5, ?6, selected_candidate_json, ?7, 'ready', ?8
                   FROM agent_host_approval_operations
                  WHERE operation_id = ?1 AND session_id = ?2 AND agent_instance_id = ?3
                    AND state = 'approved' AND selected_candidate_json IS NOT NULL",
                params![
                    operation_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    operation_kind,
                    canonical_input_json,
                    input_digest,
                    operation_id.to_string(),
                    now_unix_ms,
                ],
            )?;
            ensure!(
                inserted == 1,
                "host approval operation lost its selected candidate while creating the effect handoff"
            );
            Ok(true)
        })
        .await
    }

    /// Atomically claim an approved host capability at its exact concrete
    /// effect boundary.  This is the one linearization point for host
    /// dispatch: before it commits, a cancellation/revision transition wins;
    /// after it commits, recovery records `submission_unknown` rather than
    /// allowing a second external submission.
    #[cfg(feature = "host-approval-composition")]
    pub async fn claim_host_approval_effect_handoff(
        &self,
        authority: HostApprovalAuthority,
        interrupt_id: Uuid,
        session_id: Uuid,
        agent_instance_id: Uuid,
        operation_id: Uuid,
        operation_kind: String,
        canonical_input_json: String,
        input_digest: String,
        concrete_effects_json: String,
        now_unix_ms: i64,
    ) -> Result<HostApprovalEffectFence> {
        validate_host_operation_binding(&operation_kind, &input_digest)?;
        validate_host_operation_canonical_input(&canonical_input_json, &input_digest)?;
        let concrete_effects = validate_host_operation_concrete_effects(&concrete_effects_json)?;
        self.transaction(move |conn| {
            ensure!(
                host_approval_operation_has_exact_interrupt(
                    conn,
                    authority,
                    session_id,
                    agent_instance_id,
                    operation_id,
                    interrupt_id,
                )?,
                "host approval effect handoff is not bound to its exact interrupt"
            );
            let selected_candidate: Option<String> = conn
                .query_row(
                    "SELECT operation.selected_candidate_json
                       FROM agent_host_approval_operations AS operation
                       JOIN agent_host_approval_effect_handoffs AS handoff
                         ON handoff.operation_id = operation.operation_id
                       JOIN agent_instances AS agent
                         ON agent.agent_instance_id = operation.agent_instance_id
                        AND agent.session_id = operation.session_id
                      WHERE operation.operation_id = ?1
                        AND operation.session_id = ?2
                        AND operation.agent_instance_id = ?3
                        AND operation.operation_kind = ?4
                        AND operation.canonical_input_json = ?5
                        AND operation.input_digest = ?6
                        AND operation.selected_response_json IS NOT NULL
                        AND operation.selected_candidate_json IS NOT NULL
                        AND operation.state = 'approved'
                        AND handoff.state = 'ready'
                        AND handoff.canonical_input_json = operation.canonical_input_json
                        AND handoff.selected_candidate_json = operation.selected_candidate_json
                        AND handoff.idempotency_key = operation.operation_id
                        AND operation.approved_agent_revision = agent.revision
                        AND agent.state = 'running'",
                    params![
                        operation_id.to_string(),
                        session_id.to_string(),
                        agent_instance_id.to_string(),
                        operation_kind,
                        canonical_input_json,
                        input_digest,
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(selected_candidate) = selected_candidate else {
                return Ok(HostApprovalEffectFence::NotLive);
            };
            let selected_candidate: Value = serde_json::from_str(&selected_candidate)
                .context("persisted host approval candidate is malformed")?;
            if !host_operation_candidate_matches_any_concrete_effect(
                &selected_candidate,
                &concrete_effects,
            ) {
                return Ok(HostApprovalEffectFence::DifferentCandidate);
            }
            // Recheck the live owner in the same write transaction that
            // changes the irreversible handoff state. A cancellation that has
            // already reached the durable agent state wins this compare and
            // leaves the capability ready/unsubmitted.
            let operation_changed = conn.execute(
                "UPDATE agent_host_approval_operations AS operation
                    SET state = 'dispatching'
                  WHERE operation.operation_id = ?1 AND operation.session_id = ?2
                    AND operation.agent_instance_id = ?3 AND operation.state = 'approved'
                    AND operation.approved_agent_revision = (
                        SELECT agent.revision FROM agent_instances AS agent
                         WHERE agent.agent_instance_id = operation.agent_instance_id
                           AND agent.session_id = operation.session_id
                           AND agent.state = 'running'
                    )",
                params![
                    operation_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                ],
            )?;
            if operation_changed != 1 {
                return Ok(HostApprovalEffectFence::NotLive);
            }
            let handoff_changed = conn.execute(
                "UPDATE agent_host_approval_effect_handoffs
                    SET state = 'dispatching', dispatch_started_at_unix_ms = ?1
                  WHERE operation_id = ?2 AND session_id = ?3 AND agent_instance_id = ?4
                    AND operation_kind = ?5 AND canonical_input_json = ?6 AND input_digest = ?7
                    AND idempotency_key = ?8 AND state = 'ready'",
                params![
                    now_unix_ms,
                    operation_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    operation_kind,
                    canonical_input_json,
                    input_digest,
                    operation_id.to_string(),
                ],
            )?;
            ensure!(
                handoff_changed == 1,
                "host approval effect handoff lost its final dispatch claim"
            );
            Ok(HostApprovalEffectFence::Claimed)
        })
        .await
    }

    /// Recheck a capability which was already irrevocably claimed by an
    /// earlier concrete sub-boundary of the same selected operation. This is
    /// not an authorization claim (the one-way `dispatching` transition has
    /// already happened); it prevents a claimed persistence subeffect from
    /// being reused to run an unrelated command/MCP/filesystem operation in
    /// the same task-local scope.
    #[cfg(feature = "host-approval-composition")]
    pub async fn claimed_host_approval_effect_handoff_matches_candidate(
        &self,
        authority: HostApprovalAuthority,
        interrupt_id: Uuid,
        session_id: Uuid,
        agent_instance_id: Uuid,
        operation_id: Uuid,
        operation_kind: String,
        canonical_input_json: String,
        input_digest: String,
        concrete_effects_json: String,
    ) -> Result<bool> {
        validate_host_operation_binding(&operation_kind, &input_digest)?;
        validate_host_operation_canonical_input(&canonical_input_json, &input_digest)?;
        let concrete_effects = validate_host_operation_concrete_effects(&concrete_effects_json)?;
        self.read(move |conn| {
            ensure!(
                host_approval_operation_has_exact_interrupt(
                    conn,
                    authority,
                    session_id,
                    agent_instance_id,
                    operation_id,
                    interrupt_id,
                )?,
                "host approval effect handoff is not bound to its exact interrupt"
            );
            let selected_candidate: Option<String> = conn
                .query_row(
                    "SELECT operation.selected_candidate_json
                       FROM agent_host_approval_operations AS operation
                       JOIN agent_host_approval_effect_handoffs AS handoff
                         ON handoff.operation_id = operation.operation_id
                      WHERE operation.operation_id = ?1 AND operation.session_id = ?2
                        AND operation.agent_instance_id = ?3 AND operation.operation_kind = ?4
                        AND operation.canonical_input_json = ?5 AND operation.input_digest = ?6
                        AND operation.state = 'dispatching' AND handoff.state = 'dispatching'
                        AND handoff.canonical_input_json = operation.canonical_input_json
                        AND handoff.selected_candidate_json = operation.selected_candidate_json
                        AND handoff.idempotency_key = operation.operation_id",
                    params![
                        operation_id.to_string(),
                        session_id.to_string(),
                        agent_instance_id.to_string(),
                        operation_kind,
                        canonical_input_json,
                        input_digest,
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(selected_candidate) = selected_candidate else {
                return Ok(false);
            };
            let selected_candidate: Value = serde_json::from_str(&selected_candidate)
                .context("persisted claimed host approval candidate is malformed")?;
            Ok(host_operation_candidate_matches_any_concrete_effect(
                &selected_candidate,
                &concrete_effects,
            ))
        })
        .await
    }

    /// Reject a materialized capability which never reached a concrete host
    /// boundary (for example, a prompt continuation escaped its effect scope).
    /// This is intentionally distinct from `submission_unknown`: no host
    /// dispatch claim happened, so it is truthful and safe to record a known
    /// rejection rather than pretending an external effect may have run.
    #[cfg(feature = "host-approval-composition")]
    pub async fn reject_unclaimed_host_approval_final_operation(
        &self,
        authority: HostApprovalAuthority,
        interrupt_id: Uuid,
        session_id: Uuid,
        agent_instance_id: Uuid,
        operation_id: Uuid,
        operation_kind: String,
        canonical_input_json: String,
        input_digest: String,
        now_unix_ms: i64,
    ) -> Result<bool> {
        validate_host_operation_binding(&operation_kind, &input_digest)?;
        validate_host_operation_canonical_input(&canonical_input_json, &input_digest)?;
        self.transaction(move |conn| {
            ensure!(
                host_approval_operation_has_exact_interrupt(
                    conn,
                    authority,
                    session_id,
                    agent_instance_id,
                    operation_id,
                    interrupt_id,
                )?,
                "host approval effect handoff is not bound to its exact interrupt"
            );
            let changed = conn.execute(
                "UPDATE agent_host_approval_effect_handoffs
                    SET state = 'rejected', completed_at_unix_ms = ?1,
                        completion_receipt_json = '{\"outcome\":\"not_submitted\"}'
                  WHERE operation_id = ?2 AND session_id = ?3 AND agent_instance_id = ?4
                    AND operation_kind = ?5 AND canonical_input_json = ?6 AND input_digest = ?7
                    AND idempotency_key = ?8 AND state = 'ready'",
                params![
                    now_unix_ms,
                    operation_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    operation_kind,
                    canonical_input_json,
                    input_digest,
                    operation_id.to_string(),
                ],
            )?;
            if changed != 1 {
                // A subtree cancellation closes `ready` as known-not-
                // submitted and changes the operation to `cancelled` in its
                // own atomic transaction.  The normal effect-scope cleanup
                // must accept that terminal winner instead of attempting an
                // invalid approved -> rejected CAS which would roll back the
                // already-correct handoff terminalization.
                let already_cancelled: bool = conn.query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM agent_host_approval_effect_handoffs handoff
                         JOIN agent_host_approval_operations operation
                           ON operation.operation_id = handoff.operation_id
                        WHERE handoff.operation_id = ?1 AND handoff.session_id = ?2
                          AND handoff.agent_instance_id = ?3 AND handoff.operation_kind = ?4
                          AND handoff.canonical_input_json = ?5 AND handoff.input_digest = ?6
                          AND handoff.idempotency_key = ?7 AND handoff.state = 'rejected'
                          AND handoff.completion_receipt_json LIKE '%not_submitted%'
                          AND operation.state = 'cancelled'
                     )",
                    params![
                        operation_id.to_string(),
                        session_id.to_string(),
                        agent_instance_id.to_string(),
                        operation_kind,
                        canonical_input_json,
                        input_digest,
                        operation_id.to_string(),
                    ],
                    |row| row.get(0),
                )?;
                return Ok(already_cancelled);
            }
            let changed = conn.execute(
                "UPDATE agent_host_approval_operations
                    SET state = 'rejected'
                  WHERE operation_id = ?1 AND session_id = ?2 AND agent_instance_id = ?3
                    AND state = 'approved'",
                params![
                    operation_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                ],
            )?;
            ensure!(changed == 1, "unclaimed host approval operation lost its rejection CAS");
            Ok(true)
        })
        .await
    }

    /// Record a known completion of an already-dispatched host effect. The
    /// caller must hold the same complete canonical binding that began the
    /// handoff. This method is deliberately separate from approval: only a
    /// concrete effect boundary may call it after it has definitive outcome
    /// evidence.
    #[cfg(feature = "host-approval-composition")]
    pub async fn complete_host_approval_final_operation(
        &self,
        authority: HostApprovalAuthority,
        interrupt_id: Uuid,
        session_id: Uuid,
        agent_instance_id: Uuid,
        operation_id: Uuid,
        operation_kind: String,
        canonical_input_json: String,
        input_digest: String,
        succeeded: bool,
        completion_receipt_json: String,
        now_unix_ms: i64,
    ) -> Result<bool> {
        validate_host_operation_binding(&operation_kind, &input_digest)?;
        validate_host_operation_canonical_input(&canonical_input_json, &input_digest)?;
        let completion_receipt_json = redact_receipt_json(&completion_receipt_json)?;
        self.transaction(move |conn| {
            ensure!(
                host_approval_operation_has_exact_interrupt(
                    conn,
                    authority,
                    session_id,
                    agent_instance_id,
                    operation_id,
                    interrupt_id,
                )?,
                "host approval effect handoff is not bound to its exact interrupt"
            );
            let handoff_state = if succeeded { "succeeded" } else { "rejected" };
            let operation_state = if succeeded { "completed" } else { "rejected" };
            let changed = conn.execute(
                "UPDATE agent_host_approval_effect_handoffs
                    SET state = ?1, completed_at_unix_ms = ?2, completion_receipt_json = ?3
                  WHERE operation_id = ?4 AND session_id = ?5 AND agent_instance_id = ?6
                    AND operation_kind = ?7 AND canonical_input_json = ?8 AND input_digest = ?9 AND idempotency_key = ?10
                    AND state = 'dispatching'
                    AND EXISTS (
                        SELECT 1 FROM agent_host_approval_operations operation
                        JOIN agent_instances agent
                          ON agent.agent_instance_id = operation.agent_instance_id
                         AND agent.session_id = operation.session_id
                         WHERE operation.operation_id = ?4
                           AND operation.session_id = ?5
                           AND operation.agent_instance_id = ?6
                           AND operation.state = 'dispatching'
                           AND agent.state = 'running'
                           AND agent.revision = operation.approved_agent_revision
                    )",
                params![
                    handoff_state,
                    now_unix_ms,
                    completion_receipt_json,
                    operation_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    operation_kind,
                    canonical_input_json,
                    input_digest,
                    operation_id.to_string(),
                ],
            )?;
            if changed != 1 {
                return Ok(false);
            }
            let changed = conn.execute(
                "UPDATE agent_host_approval_operations
                    SET state = ?1
                  WHERE operation_id = ?2 AND session_id = ?3 AND agent_instance_id = ?4
                    AND state = 'dispatching'",
                params![
                    operation_state,
                    operation_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                ],
            )?;
            ensure!(changed == 1, "host approval operation lost its dispatch completion CAS");
            Ok(true)
        })
        .await
    }

    /// Convert a dispatching operation into an explicit submission-unknown
    /// record only when a concrete effect boundary knows it cannot obtain a
    /// definitive completion result. Recovery uses this state for repair and
    /// audit; it never turns it back into an executable approval.
    #[cfg(feature = "host-approval-composition")]
    pub async fn mark_host_approval_final_operation_submission_unknown(
        &self,
        authority: HostApprovalAuthority,
        interrupt_id: Uuid,
        session_id: Uuid,
        agent_instance_id: Uuid,
        operation_id: Uuid,
        operation_kind: String,
        canonical_input_json: String,
        input_digest: String,
        now_unix_ms: i64,
    ) -> Result<bool> {
        validate_host_operation_binding(&operation_kind, &input_digest)?;
        validate_host_operation_canonical_input(&canonical_input_json, &input_digest)?;
        self.transaction(move |conn| {
            ensure!(
                host_approval_operation_has_exact_interrupt(
                    conn,
                    authority,
                    session_id,
                    agent_instance_id,
                    operation_id,
                    interrupt_id,
                )?,
                "host approval effect handoff is not bound to its exact interrupt"
            );
            let changed = conn.execute(
                "UPDATE agent_host_approval_effect_handoffs
                    SET state = 'submission_unknown', completed_at_unix_ms = ?1
                  WHERE operation_id = ?2 AND session_id = ?3 AND agent_instance_id = ?4
                    AND operation_kind = ?5 AND canonical_input_json = ?6 AND input_digest = ?7 AND idempotency_key = ?8
                    AND state = 'dispatching'",
                params![
                    now_unix_ms,
                    operation_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    operation_kind,
                    canonical_input_json,
                    input_digest,
                    operation_id.to_string(),
                ],
            )?;
            if changed != 1 {
                return Ok(false);
            }
            let changed = conn.execute(
                "UPDATE agent_host_approval_operations SET state = 'submission_unknown'
                  WHERE operation_id = ?1 AND session_id = ?2 AND agent_instance_id = ?3
                    AND state = 'dispatching'",
                params![
                    operation_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                ],
            )?;
            ensure!(changed == 1, "host approval operation lost its submission-unknown CAS");
            Ok(true)
        })
        .await
    }

    /// Startup reconciliation for host-approval effect handoffs.
    ///
    /// An `approved` operation or `ready` handoff did not cross a concrete
    /// effect boundary, so it is known not submitted and is closed as a
    /// rejection. A `dispatching` row is the opposite: the exact boundary had
    /// accepted the durable capability but the daemon did not record a final
    /// receipt, so it becomes `submission_unknown` and is never replayed.
    #[cfg(feature = "host-approval-composition")]
    pub async fn reconcile_host_approval_dispatches(
        &self,
        session_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<usize> {
        self.transaction(move |conn| {
            // Approval is deliberately not ambient across a worker crash.
            // This also covers the tiny safe interval after the decision
            // transaction has recorded its selected candidate but before the
            // continuation materializes a ready handoff.
            conn.execute(
                "UPDATE agent_host_approval_operations
                    SET state = 'rejected'
                  WHERE session_id = ?1 AND state = 'approved'",
                params![session_id.to_string()],
            )?;
            conn.execute(
                "UPDATE agent_host_approval_effect_handoffs
                    SET state = 'rejected', completed_at_unix_ms = ?1,
                        completion_receipt_json = '{\"outcome\":\"not_submitted\",\"recovery\":true}'
                  WHERE session_id = ?2 AND state = 'ready'",
                params![now_unix_ms, session_id.to_string()],
            )?;
            let dispatching_handoffs = conn.execute(
                "UPDATE agent_host_approval_effect_handoffs
                    SET state = 'submission_unknown', completed_at_unix_ms = ?1
                  WHERE session_id = ?2 AND state = 'dispatching'",
                params![now_unix_ms, session_id.to_string()],
            )?;
            let dispatching_operations = conn.execute(
                "UPDATE agent_host_approval_operations
                    SET state = 'submission_unknown'
                  WHERE session_id = ?1 AND state = 'dispatching'",
                params![session_id.to_string()],
            )?;
            ensure!(
                dispatching_operations == dispatching_handoffs,
                "host approval handoff and operation reconciliation diverged"
            );
            Ok(dispatching_handoffs)
        })
        .await
    }

    /// Close an unbound reservation when the real interrupt cannot be bound
    /// to a decision. This prevents a failed prompt attempt from becoming a
    /// future approval capability.
    #[cfg(feature = "host-approval-composition")]
    pub async fn cancel_unbound_host_approval_final_operation(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        operation_id: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            Ok(conn.execute(
                "UPDATE agent_host_approval_operations
                 SET state = 'cancelled', resolved_at_unix_ms = ?1
                 WHERE operation_id = ?2 AND session_id = ?3 AND agent_instance_id = ?4
                   AND decision_request_id IS NULL AND state = 'pending'",
                params![
                    now_unix_ms,
                    operation_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                ],
            )? == 1)
        })
        .await
    }

    async fn create_decision_request_with_attention(
        &self,
        input: NewDecisionRequest,
        existing_interrupt_id: Option<Uuid>,
        creation_kind: DecisionCreationKind,
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
        validate_decision_class(&input.decision_class)?;
        let host_approval = match creation_kind {
            #[cfg(feature = "host-approval-composition")]
            DecisionCreationKind::HostApproval { authority } => {
                // Keep the opaque capability live through the complete
                // transaction.  The private-field marker has no safe
                // constructor outside the daemon composition layer.
                let _ = authority;
                true
            }
            _ => false,
        };
        let host_capability_refresh = match creation_kind {
            DecisionCreationKind::Generic => None,
            #[cfg(feature = "host-approval-composition")]
            DecisionCreationKind::HostApproval { .. } => None,
            #[cfg(feature = "host-capability-refresh-composition")]
            DecisionCreationKind::HostCapabilityRefresh {
                operation_id,
                request_id,
                requires_dedicated_child_initialization,
                authority,
            } => {
                // Keep the opaque capability live through the DB transaction.
                // It cannot be constructed safely outside daemon composition;
                // the persisted operation/interrupt/decision checks below are
                // the authoritative storage boundary.
                let _ = authority;
                Some((
                    operation_id,
                    request_id,
                    requires_dedicated_child_initialization,
                ))
            }
        };
        if is_automatically_resolvable_decision_class(&input.decision_class) {
            ensure!(
                host_capability_refresh.is_some(),
                "automatically resolvable decision classes require the host capability refresh composition authority"
            );
        } else {
            ensure!(
                host_capability_refresh.is_none(),
                "host capability refresh composition may create only the low_risk decision class"
            );
        }
        match (&input.decision_class[..], input.host_approval_operation_id) {
            ("host_approval", Some(operation_id)) => {
                ensure!(
                    host_approval,
                    "host approval decisions require the daemon host approval composition authority"
                );
                ensure!(
                    !operation_id.is_nil(),
                    "host approval operation id must not be nil"
                );
            }
            ("host_approval", None) => {
                bail!("host approval decision must bind a final host operation")
            }
            (_, Some(_)) => bail!("only host approval decisions may bind a host operation"),
            (_, None) => {}
        }
        ensure!(
            input.decision_class != "host_approval" || existing_interrupt_id.is_some(),
            "host approval must be composed through an existing final interrupt"
        );
        ensure!(
            host_approval || input.decision_class != "host_approval",
            "generic decision creation cannot create a host approval"
        );
        ensure!(
            host_capability_refresh.is_none() || existing_interrupt_id.is_some(),
            "host capability refresh must be composed through an existing final interrupt"
        );
        let resolver_route = input.resolver_route.clone();
        if let Some(route) = resolver_route.as_deref() {
            validate_resolver_route(route)?;
        }
        let RedactedOptionsContract {
            public_json: options_json,
            private_option_mappings,
        } = redact_options_contract(&input.options_contract_json)?;
        let attention_description = decision_attention_description(&options_json)?;
        let free_text = input
            .free_text_contract_json
            .as_deref()
            .map(redact_free_text_contract)
            .transpose()?;
        // Storage owns the final persisted shape. A generic decision must
        // remain answerable after an import or restart: cancellation only
        // terminates an existing question and is never an answer channel.
        // QuestionTool retains its distinct typed response contract, whose
        // nonempty/answerable shape is revalidated here as well.
        let public_option_ids =
            validate_durable_decision_answer_contract(&options_json, free_text.as_deref())?;
        let is_question_tool_contract = durable_decision_has_question_tool_contract(&options_json)?;
        ensure!(
            existing_interrupt_id.is_some() == is_question_tool_contract,
            "QuestionTool durable contracts and existing question interrupts must be bound together"
        );
        let recommendation = input
            .recommendation_json
            .as_deref()
            .map(|raw| {
                redact_recommendation(
                    raw,
                    &private_option_mappings,
                    &input.decision_class,
                    &input.rationale_redaction_class,
                )
            })
            .transpose()?;
        if let Some(recommendation) = recommendation.as_deref() {
            validate_durable_recommendation(
                recommendation,
                &input.decision_class,
                &input.rationale_redaction_class,
                &public_option_ids,
                private_option_mappings.iter().map(|mapping| {
                    (
                        mapping.opaque_option_id.as_str(),
                        mapping.continuation_option_id.as_str(),
                    )
                }),
            )?;
        }
        let policy_receipt = redact_policy_receipt(&input.policy_receipt_json)?;
        let decision_request_id = Uuid::new_v4();
        let host_approval_operation_id = input.host_approval_operation_id;
        let attention_id = existing_interrupt_id.unwrap_or_else(Uuid::new_v4);
        self.transaction(move |conn| {
            let Some(agent) = load_agent(conn, input.session_id, input.agent_instance_id)? else {
                bail!("agent instance is not authorized for this session");
            };
            if let Some((operation_id, request_id, true)) = host_capability_refresh {
                // A refresh child may only leave its pre-bind descriptor by
                // committing this exact real QuestionTool/decision/operation
                // tuple. This prevents a same-session child or a stale UUID
                // from borrowing another initialization record.
                let initializing: i64 = conn.query_row(
                    "SELECT EXISTS (
                         SELECT 1 FROM host_capability_refresh_initializations
                          WHERE operation_id = ?1 AND request_id = ?2
                            AND session_id = ?3 AND agent_instance_id = ?4
                            AND state = 'initializing'
                     )",
                    params![
                        operation_id.to_string(),
                        request_id.to_string(),
                        input.session_id.to_string(),
                        input.agent_instance_id.to_string(),
                    ],
                    |row| row.get(0),
                )?;
                ensure!(
                    initializing != 0,
                    "host capability refresh child lacks its exact durable initialization descriptor"
                );
            }
            ensure!(agent.state == AgentInstanceState::Running, "decision owner is not running");
            ensure!(agent.revision == input.expected_agent_revision, "agent revision conflict");
            // Decision metadata is selected here from the durable owner only.
            // Never consult the presentation object: its task/workspace
            // fields are display inputs and must not become routing authority.
            if let Some(task_call_id) = agent.task_delegation_job_id.as_deref() {
                validate_daemon_opaque_reference(task_call_id, "agent task call id")?;
            }
            if let Some(workspace_ref) = agent.workspace_ref.as_deref() {
                validate_daemon_opaque_reference(workspace_ref, "agent workspace reference")?;
            }
            if existing_interrupt_id.is_some() {
                let (owner, question_json, questions_json): (
                    Option<String>,
                    Option<String>,
                    Option<String>,
                ) = conn
                    .query_row(
                        "SELECT agent_instance_id, question_json, questions_json
                           FROM needs_attention
                          WHERE interrupt_id = ?1 AND session_id = ?2
                            AND state = 'open' AND decision_request_id IS NULL",
                        params![attention_id.to_string(), input.session_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?
                    .context("question interrupt is not an open unbound attention row")?;
                let expected_owner = input.agent_instance_id.to_string();
                ensure!(
                    owner.as_deref() == Some(expected_owner.as_str()),
                    "question interrupt owner does not match its decision agent"
                );
                validate_question_tool_contract_matches_interrupt(
                    &options_json,
                    private_option_mappings.iter().map(|mapping| {
                        (
                            mapping.opaque_option_id.as_str(),
                            mapping.continuation_option_id.as_str(),
                        )
                    }),
                    question_json.as_deref(),
                    questions_json.as_deref(),
                )?;
                validate_raw_interrupt_approval_binding(
                    &input.decision_class,
                    input.host_approval_operation_id,
                    question_json.as_deref(),
                    questions_json.as_deref(),
                )?;
            }
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
                     task_call_id_ref, workspace_ref,
                     options_contract_json, free_text_contract_json, recommendation_json,
                     rationale_redaction_class, decision_class, host_approval_operation_id,
                     deadline_unix_ms, policy_receipt_json,
                     resolver_route, state, revision, created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 'pending', 0, ?15, ?15)",
                params![
                    decision_request_id.to_string(), input.agent_instance_id.to_string(), input.session_id.to_string(),
                    agent.task_delegation_job_id, agent.workspace_ref,
                    options_json, free_text, recommendation, input.rationale_redaction_class,
                    input.decision_class,
                    host_approval_operation_id.map(|id| id.to_string()),
                    input.deadline_unix_ms, policy_receipt, resolver_route,
                    now_unix_ms,
                ],
            )?;
            for mapping in &private_option_mappings {
                conn.execute(
                    "INSERT INTO decision_private_option_mappings (
                         decision_request_id, session_id, opaque_option_id, continuation_option_id
                     ) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        decision_request_id.to_string(),
                        input.session_id.to_string(),
                        &mapping.opaque_option_id,
                        &mapping.continuation_option_id,
                    ],
                )?;
            }
            if input.decision_class == "host_approval" {
                // The host composition point already reserved the final
                // operation before this decision existed. Bind exactly that
                // pending row; a generic decision request cannot mint an
                // approval capability as a side effect of creation.
                let bound = conn.execute(
                    "UPDATE agent_host_approval_operations
                     SET decision_request_id = ?1
                     WHERE operation_id = ?2 AND session_id = ?3 AND agent_instance_id = ?4
                       AND decision_request_id IS NULL AND state = 'pending'",
                    params![
                        decision_request_id.to_string(),
                        host_approval_operation_id
                            .expect("validated host operation id")
                            .to_string(),
                        input.session_id.to_string(),
                        input.agent_instance_id.to_string(),
                    ],
                )?;
                ensure!(bound == 1, "host approval final operation was not reserved by the host");
            }
            if existing_interrupt_id.is_some() {
                // The legacy QuestionTool row already contains the real
                // questions and wake-up anchor. Claim exactly that row before
                // it is advertised to clients; a retry cannot rebind another
                // interrupt or create a second Attention entry.
                let changed = conn.execute(
                    "UPDATE needs_attention
                     SET decision_request_id = ?1
                     WHERE interrupt_id = ?2 AND session_id = ?3
                       AND agent_instance_id = ?4
                       AND state = 'open' AND decision_request_id IS NULL
                       AND (question_json IS NOT NULL OR questions_json IS NOT NULL)",
                    params![
                        decision_request_id.to_string(),
                        attention_id.to_string(),
                        input.session_id.to_string(),
                        input.agent_instance_id.to_string(),
                    ],
                )?;
                ensure!(changed == 1, "question interrupt is not an open unbound attention row");

            } else {
                conn.execute(
                    "INSERT INTO needs_attention (
                         interrupt_id, session_id, agent_id, agent_instance_id, description, state, raised_at,
                         decision_request_id
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'open', ?6, ?7)",
                    params![
                        attention_id.to_string(), input.session_id.to_string(), "agent-tree",
                        input.agent_instance_id.to_string(), attention_description, now_unix_ms,
                        decision_request_id.to_string(),
                    ],
                )?;
            }
            if let Some((operation_id, request_id, requires_dedicated_child_initialization)) = host_capability_refresh {
                // The same transaction that makes an automatically-resolvable
                // request visible inserts its exact durable host operation.
                // A generic caller cannot pre-bind a `low_risk` decision, and
                // no reserve/bind crash window exists for recovery to infer.
                let inserted = conn.execute(
                    "INSERT INTO host_capability_refresh_operations (
                         operation_id, request_id, session_id, agent_instance_id,
                         interrupt_id, decision_request_id, state,
                         created_at_unix_ms, updated_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?7)",
                    params![
                        operation_id.to_string(),
                        request_id.to_string(),
                        input.session_id.to_string(),
                        input.agent_instance_id.to_string(),
                        attention_id.to_string(),
                        decision_request_id.to_string(),
                        now_unix_ms,
                    ],
                )?;
                ensure!(
                    inserted == 1,
                    "host capability refresh operation was not durably bound to its exact decision and interrupt"
                );
                if requires_dedicated_child_initialization {
                    let initialization_bound = conn.execute(
                        "UPDATE host_capability_refresh_initializations
                            SET interrupt_id = ?1, decision_request_id = ?2,
                                state = 'bound', updated_at_unix_ms = ?3
                          WHERE operation_id = ?4 AND request_id = ?5
                            AND session_id = ?6 AND agent_instance_id = ?7
                            AND state = 'initializing'",
                        params![
                            attention_id.to_string(),
                            decision_request_id.to_string(),
                            now_unix_ms,
                            operation_id.to_string(),
                            request_id.to_string(),
                            input.session_id.to_string(),
                            input.agent_instance_id.to_string(),
                        ],
                    )?;
                    ensure!(
                        initialization_bound == 1,
                        "host capability refresh initialization was not atomically bound"
                    );
                }
                let exact_binding: i64 = conn.query_row(
                    "SELECT EXISTS (
                         SELECT 1
                           FROM host_capability_refresh_operations operation
                           JOIN needs_attention attention
                             ON attention.interrupt_id = operation.interrupt_id
                            AND attention.session_id = operation.session_id
                            AND attention.agent_instance_id = operation.agent_instance_id
                          WHERE operation.operation_id = ?1
                            AND operation.request_id = ?2
                            AND operation.session_id = ?3
                            AND operation.agent_instance_id = ?4
                            AND operation.interrupt_id = ?5
                            AND operation.decision_request_id = ?6
                            AND operation.state = 'pending'
                            AND attention.decision_request_id = operation.decision_request_id
                     )",
                    params![
                        operation_id.to_string(),
                        request_id.to_string(),
                        input.session_id.to_string(),
                        input.agent_instance_id.to_string(),
                        attention_id.to_string(),
                        decision_request_id.to_string(),
                    ],
                    |row| row.get(0),
                )?;
                ensure!(
                    exact_binding != 0,
                    "host capability refresh operation did not retain its exact interrupt/decision binding"
                );
                if requires_dedicated_child_initialization {
                    let initialization_binding: i64 = conn.query_row(
                        "SELECT EXISTS (
                             SELECT 1 FROM host_capability_refresh_initializations initialization
                              WHERE initialization.operation_id = ?1
                                AND initialization.request_id = ?2
                                AND initialization.session_id = ?3
                                AND initialization.agent_instance_id = ?4
                                AND initialization.interrupt_id = ?5
                                AND initialization.decision_request_id = ?6
                                AND initialization.state = 'bound'
                         )",
                        params![
                            operation_id.to_string(),
                            request_id.to_string(),
                            input.session_id.to_string(),
                            input.agent_instance_id.to_string(),
                            attention_id.to_string(),
                            decision_request_id.to_string(),
                        ],
                        |row| row.get(0),
                    )?;
                    ensure!(
                        initialization_binding != 0,
                        "host capability refresh initialization did not retain its exact interrupt/decision binding"
                    );
                }
            }
            // A root has no task-child descriptor to carry the next parked
            // phase. If this QuestionTool *or approval* belongs to an
            // accepted root late steer, advance its existing root-owned
            // snapshot in this same lifecycle transaction. The marker binds
            // recovery to the actual interrupt row (whose parked payload
            // remains the precise tool replay authority), rather than merely
            // observing that some root attention happened to be open after a
            // crash. Ordinary root decisions may have a null continuation id
            // and are checkpointed the same way for uniform restart
            // observability.
            let root_checkpoint_updated = conn.execute(
                "UPDATE root_agent_continuations
                    SET snapshot_json = json_set(
                            snapshot_json,
                            '$.parked_interrupt_id', ?1,
                            '$.parked_at_unix_ms', ?2
                        ),
                        updated_at_unix_ms = ?2
                  WHERE session_id = ?3 AND agent_instance_id = ?4
                    AND EXISTS (
                        SELECT 1 FROM agent_instances root
                         WHERE root.session_id = root_agent_continuations.session_id
                           AND root.agent_instance_id = root_agent_continuations.agent_instance_id
                           AND root.runtime_key = 'session-root'
                    )",
                params![
                    attention_id.to_string(),
                    now_unix_ms,
                    input.session_id.to_string(),
                    input.agent_instance_id.to_string(),
                ],
            )?;
            let accepted_root_checkpoint_exists: i64 = conn.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM root_agent_continuations checkpoint
                      WHERE checkpoint.session_id = ?1
                        AND checkpoint.agent_instance_id = ?2
                        AND checkpoint.continuation_id IS NOT NULL
                   )",
                params![input.session_id.to_string(), input.agent_instance_id.to_string()],
                |row| row.get(0),
            )?;
            ensure!(
                accepted_root_checkpoint_exists == 0 || root_checkpoint_updated == 1,
                "accepted root late-steer parked continuation checkpoint is unavailable"
            );
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

    /// Loads the exact private mapping for one decision continuation. This is
    /// intentionally a daemon-only recovery input; public readers receive
    /// only `options_contract_json` with the opaque side of each pair.
    #[doc(hidden)]
    pub async fn private_decision_option_mappings(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
    ) -> Result<Vec<DecisionPrivateOptionMapping>> {
        self.read(move |conn| {
            // `load_decision` proves the complete public contract and its
            // exact private counterpart before this daemon-only API returns
            // a continuation mapping.  Never turn a syntactically-safe row
            // into a recovery input merely because the mapping query itself
            // happened to succeed.
            let _ = load_decision(conn, session_id, decision_request_id)?
                .context("decision request is not authorized for this session")?;
            load_private_decision_option_mappings_conn(conn, session_id, decision_request_id)
        })
        .await
    }

    /// Resolves the durable decision attached to a real interrupt row.  The
    /// interrupt id remains the continuation rendezvous key, while the
    /// decision id is the authorization and exactly-once settlement key.
    pub async fn decision_request_for_interrupt(
        &self,
        session_id: Uuid,
        interrupt_id: Uuid,
    ) -> Result<Option<DecisionRequestRow>> {
        self.read(move |conn| {
            let decision_id: Option<String> = conn
                .query_row(
                    "SELECT decision_request_id FROM needs_attention
                     WHERE session_id = ?1 AND interrupt_id = ?2",
                    params![session_id.to_string(), interrupt_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            match decision_id {
                Some(decision_id) => load_decision(conn, session_id, parse_uuid(decision_id)?),
                None => Ok(None),
            }
        })
        .await
    }

    /// Returns the concrete QuestionTool interrupt only when this decision is
    /// bound to its real waiter/replay payload.  Typed AgentTree resolution is
    /// intentionally not allowed to terminalize that row: the existing
    /// `ResolveInterrupt` path owns its response schema and wake-up ACK.
    pub async fn interrupt_for_decision_request(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
    ) -> Result<Option<Uuid>> {
        self.read(move |conn| {
            let interrupt_id: Option<String> = conn
                .query_row(
                    "SELECT interrupt_id FROM needs_attention
                     WHERE session_id = ?1 AND decision_request_id = ?2
                       AND (question_json IS NOT NULL OR questions_json IS NOT NULL)",
                    params![session_id.to_string(), decision_request_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            interrupt_id.map(parse_uuid).transpose()
        })
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

    /// Creates the single idempotent user-authored steer for a decision that
    /// had already been auto-resolved. A conflicting retry cannot replace the
    /// first durable user instruction.
    pub async fn record_late_user_decision_steer(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        payload_json: String,
        now_unix_ms: i64,
    ) -> Result<LateUserDecisionSteer> {
        let payload_json = validate_resume_payload_json(&payload_json)?;
        self.transaction(move |conn| {
            let decision = load_decision(conn, session_id, decision_request_id)?
                .context("decision request is not authorized for this session")?;
            ensure!(
                decision.state == DecisionState::AutoResolved,
                "late user steer requires an auto-resolved decision"
            );
            // An existing user-authored steer is already the durable receipt.
            // Check it before proving that the target is currently runnable:
            // a parent may have terminalized after accepting the first reply,
            // but an idempotent retry must still return that exact immutable
            // receipt rather than attempting to create or reroute another
            // instruction.
            let existing: Option<String> = conn
                .query_row(
                    "SELECT steer_id FROM agent_decision_steers
                     WHERE session_id = ?1 AND decision_request_id = ?2",
                    params![session_id.to_string(), decision_request_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(id) = existing {
                let steer_id = parse_uuid(id)?;
                let existing = load_late_user_steer(conn, session_id, steer_id)?
                    .context("late user steer disappeared")?;
                ensure!(
                    existing.payload_json == payload_json,
                    "a late user steer already exists with a different payload"
                );
                return Ok(existing);
            }
            let requesting_owner = load_agent(conn, session_id, decision.agent_instance_id)?
                .context("late user steer owner is not authorized for this session")?;
            // A host-capability refresh is deliberately represented by a
            // daemon-owned child so the root remains runnable while the host
            // effect waits. That child has no model control mailbox. A human
            // reply after its automatic result is therefore a *new* user
            // steer for the direct parent which requested that operation. The
            // immutable source is recorded alongside the target so restart
            // cannot later reinterpret the reroute as a root fallback.
            let host_operation_parent: Option<Option<String>> = conn
                .query_row(
                    "SELECT child.parent_agent_instance_id
                       FROM host_capability_refresh_operations operation
                       JOIN agent_instances child
                         ON child.agent_instance_id = operation.agent_instance_id
                        AND child.session_id = operation.session_id
                      WHERE operation.session_id = ?1
                        AND operation.decision_request_id = ?2
                        AND operation.agent_instance_id = ?3",
                    params![
                        session_id.to_string(),
                        decision_request_id.to_string(),
                        decision.agent_instance_id.to_string(),
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            let target_agent_instance_id = match host_operation_parent {
                Some(Some(parent_raw)) => {
                    let parent_agent_instance_id = parse_uuid(parent_raw)?;
                    let parent = load_agent(conn, session_id, parent_agent_instance_id)?
                        .context("host capability refresh has no requesting parent agent")?;
                    ensure!(
                        !parent.state.is_terminal(),
                        "host capability refresh requesting parent is terminal and cannot receive a late user steer"
                    );
                    parent_agent_instance_id
                }
                Some(None) => bail!(
                    "host capability refresh child has no requesting parent for a late user steer"
                ),
                None => {
                    // Creating the one idempotent steer and proving that its
                    // exact owner still has a continuation are one
                    // transaction. Returning `Steered` for a terminal node
                    // would leave an irrevocable user instruction that no
                    // executor can ever accept.
                    ensure!(
                        !requesting_owner.state.is_terminal(),
                        "late user steer owner is terminal and has no successor route"
                    );
                    requesting_owner.agent_instance_id
                }
            };
            let steer_id = Uuid::new_v4();
            // The continuation identity is allocated with the immutable user
            // instruction, not with a delivery worker.  It consequently
            // survives every recovery epoch and can be used by the execution
            // layer as its idempotency/checkpoint identity.
            let continuation_id = Uuid::new_v4();
            // A late reply must remain ordered after the exact parked
            // continuation that consumed the automatic answer. Persist its
            // interrupt identity now; claims below use this dependency rather
            // than a best-effort worker timing assumption.
            let predecessor_interrupt_id: Option<String> = conn
                .query_row(
                    "SELECT interrupt_id FROM needs_attention
                      WHERE session_id = ?1 AND decision_request_id = ?2
                        AND (question_json IS NOT NULL OR questions_json IS NOT NULL)
                        AND state <> 'resolved'",
                    params![session_id.to_string(), decision_request_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            let inserted = conn.execute(
                "INSERT INTO agent_decision_steers (
                     steer_id, continuation_id, session_id, requesting_agent_instance_id,
                     agent_instance_id, decision_request_id,
                     origin_principal, payload_json, predecessor_interrupt_id, created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'user', ?7, ?8, ?9)
                 ON CONFLICT(decision_request_id) DO NOTHING",
                params![
                    steer_id.to_string(),
                    continuation_id.to_string(),
                    session_id.to_string(),
                    requesting_owner.agent_instance_id.to_string(),
                    target_agent_instance_id.to_string(),
                    decision_request_id.to_string(),
                    payload_json,
                    predecessor_interrupt_id,
                    now_unix_ms,
                ],
            )?;
            if inserted == 0 {
                // A second client/worker can race between its initial
                // receipt lookup and this insert. The unique decision edge
                // is the exactly-once fence; reread the winner and never
                // append a second event or delivery identity.
                let existing: Option<String> = conn
                    .query_row(
                        "SELECT steer_id FROM agent_decision_steers
                         WHERE session_id = ?1 AND decision_request_id = ?2",
                        params![session_id.to_string(), decision_request_id.to_string()],
                        |row| row.get(0),
                    )
                    .optional()?;
                let existing_id = parse_uuid(
                    existing.context("late user steer conflict winner has no receipt")?,
                )?;
                let existing = load_late_user_steer(conn, session_id, existing_id)?
                    .context("late user steer conflict winner disappeared")?;
                ensure!(
                    existing.payload_json == payload_json,
                    "a late user steer already exists with a different payload"
                );
                return Ok(existing);
            }
            // The AgentTree steer itself is the authoritative delivery
            // receipt. A noninteractive child claims it from its own
            // UUID-scoped turn boundary and acknowledges after that turn
            // completes; do not mirror it into `task_delegation_steers`, whose
            // legacy drain marks a row delivered before inference has accepted
            // the continuation. Ordinary user task steers keep using that
            // independent compatibility queue.
            insert_control_event(
                conn,
                session_id,
                "decision_user_steer",
                decision_request_id,
                "steered",
                now_unix_ms,
            )?;
            load_late_user_steer(conn, session_id, steer_id)?.context("created late user steer missing")
        })
        .await
    }

    /// Read the canonical durable steer after a state-transition CAS. Runtime
    /// delivery must not retain a pre-acceptance copy because the immutable
    /// owner revision and payload-byte checkpoint are minted by acceptance.
    pub async fn late_user_decision_steer(
        &self,
        session_id: Uuid,
        steer_id: Uuid,
    ) -> Result<Option<LateUserDecisionSteer>> {
        self.read(move |conn| load_late_user_steer(conn, session_id, steer_id))
            .await
    }

    /// Starts a new daemon recovery epoch for the session's private decision
    /// steers. This runs only after the daemon has fenced the prior worker for
    /// the session; retaining an old claim across a crash would otherwise
    /// strand a still-pending user steer forever. An accepted row is *not*
    /// released here: that would let a fresh epoch re-accept and re-run an
    /// already-dispatched continuation.
    pub async fn begin_late_user_decision_steer_recovery(
        &self,
        session_id: Uuid,
        recovery_epoch: Uuid,
    ) -> Result<()> {
        self.transaction(move |conn| {
            conn.execute(
                "UPDATE agent_decision_steers
                 SET claimed_recovery_epoch = NULL
                 WHERE session_id = ?1 AND execution_state = 'pending'
                   AND delivered_at_unix_ms IS NULL
                   AND claimed_recovery_epoch IS NOT NULL
                   AND claimed_recovery_epoch <> ?2",
                params![session_id.to_string(), recovery_epoch.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    /// Atomically claims only executable (pending) or receipt-only
    /// (completed) late steers for one exact, live requesting agent and one
    /// recovery epoch. An accepted-incomplete row is deliberately absent: its
    /// immutable checkpoint has to be resumed via
    /// [`Self::accepted_late_user_decision_steers_for_recovery`], never
    /// delivered as a new user message.
    pub async fn claim_late_user_decision_steers(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        recovery_epoch: Uuid,
    ) -> Result<Vec<LateUserDecisionSteer>> {
        self.transaction(move |conn| {
            conn.execute(
                "UPDATE agent_decision_steers
                 SET claimed_recovery_epoch = ?1
                 WHERE session_id = ?2 AND agent_instance_id = ?3
                   AND delivered_at_unix_ms IS NULL
                   AND execution_state IN ('pending', 'completed')
                   AND claimed_recovery_epoch IS NULL
                   AND steer_id = (
                       SELECT candidate.steer_id
                        FROM agent_decision_steers candidate
                        WHERE candidate.session_id = ?2
                          AND candidate.agent_instance_id = ?3
                          AND candidate.delivered_at_unix_ms IS NULL
                          AND candidate.execution_state IN ('pending', 'completed')
                          AND candidate.claimed_recovery_epoch IS NULL
                          -- A blocked post-auto steer must not head-of-line
                          -- block an unrelated decision owned by the same
                          -- executor.  The outer predicate repeats this CAS
                          -- guard for the selected row; it also belongs here
                          -- so the deterministic candidate selection skips
                          -- rows whose exact parked replay is still live.
                          AND NOT EXISTS (
                              SELECT 1 FROM needs_attention predecessor
                               WHERE predecessor.interrupt_id = candidate.predecessor_interrupt_id
                                 AND predecessor.session_id = candidate.session_id
                                 AND predecessor.state <> 'resolved'
                          )
                        ORDER BY candidate.created_at_unix_ms, candidate.steer_id
                        LIMIT 1
                   )
                   AND (
                       -- A completed continuation is receipt-only work. It
                       -- remains acknowledgeable even if the owner reached a
                       -- terminal lifecycle state between provider success
                       -- and the worker receipt; requiring a live mailbox
                       -- here would strand the durable completion forever.
                       agent_decision_steers.execution_state = 'completed'
                       OR EXISTS (
                           SELECT 1 FROM agent_instances a
                            WHERE a.session_id = agent_decision_steers.session_id
                              AND a.agent_instance_id = agent_decision_steers.agent_instance_id
                              AND a.agent_instance_id = ?3
                              -- A pending steer is only deliverable to a
                              -- runnable continuation. A waiting owner keeps
                              -- the row durable and unclaimed behind its
                              -- current question/approval; the worker's
                              -- lifecycle-transition scheduler retries it
                              -- after the exact owner returns to running.
                              AND a.state = 'running'
                       )
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM needs_attention predecessor
                        WHERE predecessor.interrupt_id = agent_decision_steers.predecessor_interrupt_id
                          AND predecessor.session_id = agent_decision_steers.session_id
                          AND predecessor.state <> 'resolved'
                   )",
                // The exact agent-row predicate closes the cancel-vs-claim
                // race in the same SQLite transaction. A label, a stale
                // executor, or a terminal descendant cannot claim an input.
                params![
                    recovery_epoch.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                ],
            )?;
            let mut statement = conn.prepare(
                "SELECT steer_id FROM agent_decision_steers
                 WHERE session_id = ?1 AND agent_instance_id = ?2
                   AND delivered_at_unix_ms IS NULL
                   AND execution_state IN ('pending', 'completed')
                   AND claimed_recovery_epoch = ?3
                 ORDER BY created_at_unix_ms, steer_id",
            )?;
            let ids = statement
                .query_map(
                    params![
                        session_id.to_string(),
                        agent_instance_id.to_string(),
                        recovery_epoch.to_string(),
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ids.into_iter()
                .map(|id| load_late_user_steer(conn, session_id, parse_uuid(id)?)?.context("pending steer missing"))
                .collect()
        })
        .await
    }

    /// Claims accepted-but-incomplete continuations for a *successor* daemon
    /// after the prior executor has been fenced. This does not make the rows
    /// deliverable: it merely attaches the new recovery epoch to the same
    /// immutable continuation checkpoint so the executor recovery path can
    /// reconcile/resume it without replaying its user instruction.
    ///
    /// The checkpoint's accepted owner revision is immutable proof of the
    /// original provider handoff, not a lease on every later model round. An
    /// accepted continuation can legitimately park on its own QuestionTool or
    /// approval and resume the same agent at a newer revision. A successor
    /// must therefore attach this immutable checkpoint even while the owner
    /// is waiting: the parked QuestionTool/approval replay restores the
    /// permit later. The actual provider-dispatch permit remains separately
    /// `running`-only at the final handoff.
    pub async fn accepted_late_user_decision_steers_for_recovery(
        &self,
        session_id: Uuid,
        agent_instance_id: Uuid,
        recovery_epoch: Uuid,
    ) -> Result<Vec<LateUserDecisionSteer>> {
        self.transaction(move |conn| {
            conn.execute(
                "UPDATE agent_decision_steers
                 SET claimed_recovery_epoch = ?1
                 WHERE session_id = ?2 AND agent_instance_id = ?3
                   AND delivered_at_unix_ms IS NULL
                   AND execution_state = 'accepted'
                   AND completed_at_unix_ms IS NULL
                   AND steer_id = (
                       SELECT candidate.steer_id
                        FROM agent_decision_steers candidate
                        WHERE candidate.session_id = ?2
                          AND candidate.agent_instance_id = ?3
                          AND candidate.delivered_at_unix_ms IS NULL
                          AND candidate.execution_state = 'accepted'
                          AND candidate.completed_at_unix_ms IS NULL
                          AND NOT EXISTS (
                              SELECT 1 FROM needs_attention predecessor
                               WHERE predecessor.interrupt_id = candidate.predecessor_interrupt_id
                                 AND predecessor.session_id = candidate.session_id
                                 AND predecessor.state <> 'resolved'
                          )
                        ORDER BY candidate.accepted_at_unix_ms, candidate.steer_id
                        LIMIT 1
                   )
                   AND EXISTS (
                       SELECT 1 FROM agent_instances a
                        WHERE a.session_id = agent_decision_steers.session_id
                          AND a.agent_instance_id = agent_decision_steers.agent_instance_id
                          AND a.agent_instance_id = ?3
                          AND a.state NOT IN ('completed', 'failed', 'cancelled')
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM needs_attention predecessor
                        WHERE predecessor.interrupt_id = agent_decision_steers.predecessor_interrupt_id
                          AND predecessor.session_id = agent_decision_steers.session_id
                          AND predecessor.state <> 'resolved'
                   )",
                params![
                    recovery_epoch.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                ],
            )?;
            let mut statement = conn.prepare(
                "SELECT steer_id FROM agent_decision_steers
                 WHERE session_id = ?1 AND agent_instance_id = ?2
                   AND delivered_at_unix_ms IS NULL
                   AND execution_state = 'accepted'
                   AND completed_at_unix_ms IS NULL
                   AND claimed_recovery_epoch = ?3
                 ORDER BY accepted_at_unix_ms, steer_id",
            )?;
            let ids = statement
                .query_map(
                    params![
                        session_id.to_string(),
                        agent_instance_id.to_string(),
                        recovery_epoch.to_string(),
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            ids.into_iter()
                .map(|id| {
                    load_late_user_steer(conn, session_id, parse_uuid(id)?)?
                        .context("accepted late steer disappeared during recovery")
                })
                .collect()
        })
        .await
    }

    /// Acknowledges delivery only after the existing requesting continuation
    /// accepts this steer. The recovery epoch is part of the CAS, preventing a
    /// superseded worker from acknowledging a newer worker's claim.
    pub async fn ack_late_user_decision_steer_delivery(
        &self,
        session_id: Uuid,
        steer_id: Uuid,
        recovery_epoch: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            Ok(conn.execute(
                "UPDATE agent_decision_steers SET delivered_at_unix_ms = ?1
                 WHERE steer_id = ?2 AND session_id = ?3 AND delivered_at_unix_ms IS NULL
                   AND claimed_recovery_epoch = ?4
                   AND execution_state = 'completed'
                   AND completed_at_unix_ms IS NOT NULL",
                params![
                    now_unix_ms,
                    steer_id.to_string(),
                    session_id.to_string(),
                    recovery_epoch.to_string(),
                ],
            )? == 1)
        })
        .await
    }

    /// Persist that the exact runnable executor for this recovery epoch has
    /// accepted a late steer at its provider-handoff boundary. Acceptance is
    /// an irreversible no-redelivery fence, coupled to an immutable checkpoint
    /// containing the exact *running* owner revision. A completed invocation
    /// is deliberately not accepted again: callers must retry its
    /// acknowledgement instead of running user-directed work twice.
    pub async fn accept_late_user_decision_steer_execution(
        &self,
        session_id: Uuid,
        steer_id: Uuid,
        recovery_epoch: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            Ok(conn.execute(
                "UPDATE agent_decision_steers
                 SET execution_state = 'accepted',
                     accepted_recovery_epoch = ?1,
                     accepted_at_unix_ms = ?2,
                     accepted_agent_revision = (
                         SELECT a.revision FROM agent_instances a
                          WHERE a.session_id = agent_decision_steers.session_id
                            AND a.agent_instance_id = agent_decision_steers.agent_instance_id
                     ),
                     payload_bytes = length(CAST(payload_json AS BLOB)),
                     continuation_checkpoint_json = json_object(
                         'version', 1,
                         'steer_id', steer_id,
                         'continuation_id', continuation_id,
                         'agent_instance_id', agent_instance_id,
                         'decision_request_id', decision_request_id,
                         'agent_revision', (
                             SELECT a.revision FROM agent_instances a
                              WHERE a.session_id = agent_decision_steers.session_id
                                AND a.agent_instance_id = agent_decision_steers.agent_instance_id
                         ),
                         -- The authoritative payload remains in this row;
                         -- checkpointing its exact byte length prevents a
                         -- recovery from mistaking a structurally unrelated
                         -- body for the same continuation without duplicating
                         -- private user text into a second persistence field.
                         'payload_bytes', length(CAST(payload_json AS BLOB))
                     )
                 WHERE steer_id = ?3 AND session_id = ?4
                   AND delivered_at_unix_ms IS NULL
                   AND execution_state = 'pending'
                   AND claimed_recovery_epoch = ?1
                   AND EXISTS (
                       SELECT 1 FROM agent_instances a
                        WHERE a.session_id = agent_decision_steers.session_id
                          AND a.agent_instance_id = agent_decision_steers.agent_instance_id
                            AND a.state = 'running'
                   )
                   AND (
                       -- Child continuations carry their own task/recursive
                       -- snapshot. The daemon root has no such descriptor,
                       -- so it may cross acceptance only after its exact
                       -- root-owned snapshot was durably checkpointed.
                       NOT EXISTS (
                           SELECT 1 FROM agent_instances root
                            WHERE root.session_id = agent_decision_steers.session_id
                              AND root.agent_instance_id = agent_decision_steers.agent_instance_id
                              AND root.runtime_key = 'session-root'
                       )
                       OR EXISTS (
                           SELECT 1 FROM root_agent_continuations root_checkpoint
                            WHERE root_checkpoint.session_id = agent_decision_steers.session_id
                              AND root_checkpoint.agent_instance_id = agent_decision_steers.agent_instance_id
                              AND root_checkpoint.continuation_id = agent_decision_steers.continuation_id
                       )
                   )",
                params![
                    recovery_epoch.to_string(),
                    now_unix_ms,
                    steer_id.to_string(),
                    session_id.to_string(),
                ],
            )? == 1)
        })
        .await
    }

    /// Activate or revalidate the revocable executor permit at the final
    /// provider handoff. Queue/mailbox delivery leaves a steer `pending`; only
    /// this transaction may turn it into the immutable no-redelivery
    /// checkpoint, and only while the exact owner is `running`. Therefore a
    /// competing transition to `waiting_for_user`/`waiting_for_approval`
    /// leaves the row pending and releasable rather than stranding an accepted
    /// checkpoint against an obsolete revision.
    ///
    /// For an already accepted row (including restart recovery), this never
    /// rewrites the checkpoint. Its recorded revision proves the original
    /// handoff, while a current `running` owner permits a later round of that
    /// same continuation after it resumed from a newer decision revision.
    /// The caller supplies every immutable identity instead of trusting an
    /// in-memory steer body.
    pub async fn late_user_decision_steer_dispatch_permit_is_current(
        &self,
        session_id: Uuid,
        steer_id: Uuid,
        continuation_id: Uuid,
        agent_instance_id: Uuid,
        recovery_epoch: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let accepted = conn.execute(
                "UPDATE agent_decision_steers
                 SET execution_state = 'accepted',
                     accepted_recovery_epoch = ?1,
                     accepted_at_unix_ms = ?2,
                     accepted_agent_revision = (
                         SELECT a.revision FROM agent_instances a
                          WHERE a.session_id = agent_decision_steers.session_id
                            AND a.agent_instance_id = agent_decision_steers.agent_instance_id
                     ),
                     payload_bytes = length(CAST(payload_json AS BLOB)),
                     continuation_checkpoint_json = json_object(
                         'version', 1,
                         'steer_id', steer_id,
                         'continuation_id', continuation_id,
                         'agent_instance_id', agent_instance_id,
                         'decision_request_id', decision_request_id,
                         'agent_revision', (
                             SELECT a.revision FROM agent_instances a
                              WHERE a.session_id = agent_decision_steers.session_id
                                AND a.agent_instance_id = agent_decision_steers.agent_instance_id
                         ),
                         'payload_bytes', length(CAST(payload_json AS BLOB))
                     )
                 WHERE steer_id = ?2 AND session_id = ?3
                   AND continuation_id = ?4 AND agent_instance_id = ?5
                   AND delivered_at_unix_ms IS NULL
                   AND execution_state = 'pending'
                   AND claimed_recovery_epoch = ?1
                   AND EXISTS (
                       SELECT 1 FROM agent_instances a
                        WHERE a.session_id = agent_decision_steers.session_id
                          AND a.agent_instance_id = agent_decision_steers.agent_instance_id
                          AND a.state = 'running'
                   )
                   AND (
                       NOT EXISTS (
                           SELECT 1 FROM agent_instances root
                            WHERE root.session_id = agent_decision_steers.session_id
                              AND root.agent_instance_id = agent_decision_steers.agent_instance_id
                              AND root.runtime_key = 'session-root'
                       )
                       OR EXISTS (
                           SELECT 1 FROM root_agent_continuations root_checkpoint
                            WHERE root_checkpoint.session_id = agent_decision_steers.session_id
                              AND root_checkpoint.agent_instance_id = agent_decision_steers.agent_instance_id
                              AND root_checkpoint.continuation_id = agent_decision_steers.continuation_id
                       )
                   )",
                params![
                    recovery_epoch.to_string(),
                    now_unix_ms,
                    steer_id.to_string(),
                    session_id.to_string(),
                    continuation_id.to_string(),
                    agent_instance_id.to_string(),
                ],
            )?;
            if accepted == 1 {
                return Ok(true);
            }
            let exists: i64 = conn.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM agent_decision_steers s
                      WHERE s.steer_id = ?1
                        AND s.session_id = ?2
                        AND s.continuation_id = ?3
                        AND s.agent_instance_id = ?4
                        AND s.execution_state = 'accepted'
                        AND s.delivered_at_unix_ms IS NULL
                        AND s.claimed_recovery_epoch = ?5
                        AND EXISTS (
                            SELECT 1 FROM agent_instances a
                             WHERE a.session_id = s.session_id
                               AND a.agent_instance_id = s.agent_instance_id
                               AND a.state = 'running'
                        )
                 )",
                params![
                    steer_id.to_string(),
                    session_id.to_string(),
                    continuation_id.to_string(),
                    agent_instance_id.to_string(),
                    recovery_epoch.to_string(),
                ],
                |row| row.get(0),
            )?;
            Ok(exists != 0)
        })
        .await
    }

    /// The executor calls this after its continuation has completed, before it
    /// reports success to the worker.  It is intentionally idempotent for the
    /// same recovery epoch so a response-channel failure can be recovered by a
    /// receipt-only retry.
    pub async fn complete_late_user_decision_steer_execution(
        &self,
        session_id: Uuid,
        steer_id: Uuid,
        recovery_epoch: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE agent_decision_steers
                 SET execution_state = 'completed', completed_at_unix_ms = ?1
                 WHERE steer_id = ?2 AND session_id = ?3
                   AND delivered_at_unix_ms IS NULL
                   AND claimed_recovery_epoch = ?4
                   AND execution_state = 'accepted'
                   AND completed_at_unix_ms IS NULL
                   AND EXISTS (
                       SELECT 1 FROM agent_instances a
                        WHERE a.session_id = agent_decision_steers.session_id
                          AND a.agent_instance_id = agent_decision_steers.agent_instance_id
                          AND a.state = 'running'
                   )",
                params![
                    now_unix_ms,
                    steer_id.to_string(),
                    session_id.to_string(),
                    recovery_epoch.to_string(),
                ],
            )?;
            if changed == 1 {
                return Ok(true);
            }
            let completed: Option<i64> = conn
                .query_row(
                    "SELECT completed_at_unix_ms FROM agent_decision_steers
                     WHERE steer_id = ?1 AND session_id = ?2
                       AND delivered_at_unix_ms IS NULL
                       AND claimed_recovery_epoch = ?3",
                    params![steer_id.to_string(), session_id.to_string(), recovery_epoch.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(completed.is_some())
        })
        .await
    }

    /// Give an unaccepted steer back when its claimed executor could not be
    /// reconstructed. The exact recovery epoch fences a superseded worker;
    /// the next real executor may claim it without manufacturing a second
    /// user instruction. An accepted row intentionally cannot be released:
    /// recovery has to resume its checkpoint, not redeliver its body.
    pub async fn release_late_user_decision_steer_claim(
        &self,
        session_id: Uuid,
        steer_id: Uuid,
        recovery_epoch: Uuid,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let decision_id: Option<String> = conn
                .query_row(
                    "SELECT decision_request_id FROM agent_decision_steers
                     WHERE session_id = ?1 AND steer_id = ?2
                       AND delivered_at_unix_ms IS NULL
                       AND execution_state = 'pending'
                       AND claimed_recovery_epoch = ?3",
                    params![
                        session_id.to_string(),
                        steer_id.to_string(),
                        recovery_epoch.to_string(),
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(decision_id) = decision_id else {
                return Ok(false);
            };
            let changed = conn.execute(
                "UPDATE agent_decision_steers SET claimed_recovery_epoch = NULL
                 WHERE session_id = ?1 AND steer_id = ?2
                   AND delivered_at_unix_ms IS NULL
                   AND execution_state = 'pending'
                   AND claimed_recovery_epoch = ?3",
                params![
                    session_id.to_string(),
                    steer_id.to_string(),
                    recovery_epoch.to_string(),
                ],
            )?;
            if changed == 1 {
                insert_control_event(
                    conn,
                    session_id,
                    "decision_steer_released",
                    parse_uuid(decision_id)?,
                    "pending_delivery",
                    now_unix_ms,
                )?;
            }
            Ok(changed == 1)
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
            None,
            "{}",
            None,
            None,
            false,
            None,
            now_unix_ms,
        )
        .await
    }

    /// Claims an automatic resolver and records its host-selected route in
    /// the same CAS. Recovery can distinguish a warm parent claim from a
    /// utility fallback without trusting transient cache state.
    pub async fn claim_decision_request_with_route(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        expected_revision: i64,
        resolver_route: String,
        now_unix_ms: i64,
    ) -> Result<DecisionTransitionOutcome> {
        validate_resolver_route(&resolver_route)?;
        self.transition_decision_request(
            session_id,
            decision_request_id,
            expected_revision,
            DecisionState::Resolving,
            Some(resolver_route),
            "{}",
            None,
            None,
            false,
            None,
            now_unix_ms,
        )
        .await
    }

    /// Releases a resolver claim only when its delivery boundary rejected the
    /// packet before accepting it. This is not a terminal transition: the
    /// request returns to user-visible pending state and may be retried by a
    /// later verified resolver. A result from the abandoned route loses the
    /// normal resolving-state CAS.
    pub async fn abandon_decision_resolver_claim(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        expected_revision: i64,
        now_unix_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE decision_requests
                 SET state = 'pending', revision = revision + 1,
                     resolver_route = NULL, updated_at_unix_ms = ?1
                 WHERE decision_request_id = ?2 AND session_id = ?3
                   AND revision = ?4 AND state = 'resolving'",
                params![
                    now_unix_ms,
                    decision_request_id.to_string(),
                    session_id.to_string(),
                    expected_revision,
                ],
            )?;
            if changed == 1 {
                insert_control_event(
                    conn,
                    session_id,
                    "decision_resolver_released",
                    decision_request_id,
                    DecisionState::Pending.as_str(),
                    now_unix_ms,
                )?;
            }
            Ok(changed == 1)
        })
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
            None,
            receipt_json,
            None,
            None,
            false,
            None,
            now_unix_ms,
        )
        .await
    }

    /// Same terminal CAS as `resolve_decision_request`, with a private durable
    /// continuation envelope. The envelope is written only after caller-side
    /// contract validation and never appears in Attention or event rows.
    pub async fn resolve_decision_request_with_resume_payload(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        expected_revision: i64,
        terminal_state: DecisionState,
        receipt_json: &str,
        resume_payload_json: &str,
        now_unix_ms: i64,
    ) -> Result<DecisionTransitionOutcome> {
        ensure!(terminal_state.is_terminal(), "decision resolution must be terminal");
        let resume_payload_json = validate_resume_payload_json(resume_payload_json)?;
        self.transition_decision_request(
            session_id,
            decision_request_id,
            expected_revision,
            terminal_state,
            None,
            receipt_json,
            Some(resume_payload_json),
            None,
            false,
            None,
            now_unix_ms,
        )
        .await
    }

    /// Trusted-host-only approval terminalization. The operation identity is
    /// looked up from the durable decision rather than accepted from a caller,
    /// and operation approval and decision settlement share one transaction.
    #[cfg(feature = "host-approval-composition")]
    pub async fn resolve_host_approval_decision(
        &self,
        session_id: Uuid,
        decision_request_id: Uuid,
        interrupt_id: Uuid,
        _authority: HostApprovalAuthority,
        expected_revision: i64,
        receipt_json: &str,
        resume_payload_json: &str,
        now_unix_ms: i64,
    ) -> Result<DecisionTransitionOutcome> {
        let resume_payload_json = validate_resume_payload_json(resume_payload_json)?;
        let selected_response_json = interrupt_response_from_resume_payload(Some(&resume_payload_json))
            .context("host approval resume payload is missing its selected response")?;
        let selected_response: serde_json::Value = serde_json::from_str(&selected_response_json)
            .context("host approval selected response is not valid JSON")?;
        let selected_response_json = String::from_utf8(canonical_json_bytes(&selected_response)?)
            .context("canonical host approval selected response was not UTF-8")?;
        self.transition_decision_request(
            session_id,
            decision_request_id,
            expected_revision,
            DecisionState::Answered,
            None,
            receipt_json,
            Some(resume_payload_json),
            Some(selected_response_json),
            true,
            Some(interrupt_id),
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
        resolver_route: Option<String>,
        receipt_json: &str,
        resume_payload_json: Option<String>,
        host_selected_response_json: Option<String>,
        trusted_host_approval: bool,
        host_interrupt_id: Option<Uuid>,
        now_unix_ms: i64,
    ) -> Result<DecisionTransitionOutcome> {
        let receipt_json = redact_receipt_json(receipt_json)?;
        let host_capability_refresh_allowed = host_capability_refresh_response_allows(
            resume_payload_json.as_deref(),
        );
        if trusted_host_approval {
            ensure!(
                host_selected_response_json.is_some(),
                "trusted host approval requires its exact selected response"
            );
        } else {
            ensure!(
                host_selected_response_json.is_none(),
                "only trusted host approval may bind a selected response"
            );
        }
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
            if current.decision_class == "host_approval" {
                ensure!(
                    trusted_host_approval
                        || matches!(next_state, DecisionState::Cancelled | DecisionState::TimedOut),
                    "host approval may only be approved by trusted host authority"
                );
            } else {
                ensure!(
                    !trusted_host_approval,
                    "trusted host approval operation is bound to a host approval decision"
                );
            }
            let host_selected_candidate_json = if trusted_host_approval {
                let interrupt_id = host_interrupt_id
                    .context("trusted host settlement requires its final interrupt")?;
                let real_interrupt: Option<(Option<String>, Option<String>)> = conn
                    .query_row(
                        "SELECT question_json, questions_json
                           FROM needs_attention
                          WHERE interrupt_id = ?1
                            AND session_id = ?2
                            AND decision_request_id = ?3
                            AND (question_json IS NOT NULL OR questions_json IS NOT NULL)",
                        params![
                            interrupt_id.to_string(),
                            session_id.to_string(),
                            decision_request_id.to_string(),
                        ],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let (question_json, questions_json) = real_interrupt
                    .context("host approval is not bound to its existing final interrupt")?;
                validate_host_approval_response_against_offered_interrupt(
                    conn,
                    session_id,
                    decision_request_id,
                    question_json.as_deref(),
                    questions_json.as_deref(),
                    host_selected_response_json
                        .as_deref()
                        .expect("trusted host approval requires selected response"),
                )?;
                let operation_id = current
                    .host_approval_operation_id
                    .context("host approval decision is missing its final operation binding")?;
                let canonical_input_json: String = conn.query_row(
                    "SELECT canonical_input_json
                       FROM agent_host_approval_operations
                      WHERE operation_id = ?1 AND session_id = ?2
                        AND agent_instance_id = ?3 AND state = 'pending'",
                    params![
                        operation_id.to_string(),
                        session_id.to_string(),
                        current.agent_instance_id.to_string(),
                    ],
                    |row| row.get(0),
                )?;
                let selected_candidate_json = validate_host_operation_selected_response(
                    &canonical_input_json,
                    host_selected_response_json
                        .as_deref()
                        .expect("trusted host approval requires selected response"),
                )?;
                Some(selected_candidate_json)
            } else {
                ensure!(
                    host_interrupt_id.is_none(),
                    "only trusted host settlement may supply a final interrupt"
                );
                None
            }
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
                 SET state = ?1, revision = ?2, updated_at_unix_ms = ?3,
                     resolver_route = COALESCE(?4, resolver_route)
                 WHERE decision_request_id = ?5 AND session_id = ?6 AND revision = ?7",
                params![
                    next_state.as_str(),
                    next_revision,
                    now_unix_ms,
                    resolver_route,
                    decision_request_id.to_string(),
                    session_id.to_string(),
                    expected_revision,
                ],
            )?;
            if changed != 1 {
                return Ok(DecisionTransitionOutcome::RevisionConflict);
            }
            if terminal {
                // This operation is deliberately *not* a generic low-risk
                // decision side effect.  Its operation row was reserved from
                // the real interrupt before this decision was published, and
                // terminal decision state plus the exact allow/cancel outcome
                // become visible atomically to restart recovery.
                let refresh_operation_id: Option<String> = conn
                    .query_row(
                        "SELECT operation_id FROM host_capability_refresh_operations
                          WHERE session_id = ?1 AND decision_request_id = ?2
                            AND agent_instance_id = ?3 AND state = 'pending'",
                        params![
                            session_id.to_string(),
                            decision_request_id.to_string(),
                            current.agent_instance_id.to_string(),
                        ],
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(operation_id) = refresh_operation_id {
                    let (state, error_text) = if host_capability_refresh_allowed {
                        ("allowed", None)
                    } else {
                        (
                            "cancelled",
                            Some("host capability refresh was declined, cancelled, or timed out"),
                        )
                    };
                    let changed = conn.execute(
                        "UPDATE host_capability_refresh_operations
                            SET state = ?1, error_text = ?2,
                                updated_at_unix_ms = ?3,
                                completed_at_unix_ms = CASE WHEN ?1 = 'cancelled' THEN ?3 ELSE NULL END
                          WHERE operation_id = ?4 AND session_id = ?5
                            AND decision_request_id = ?6 AND agent_instance_id = ?7
                            AND state = 'pending'",
                        params![
                            state,
                            error_text,
                            now_unix_ms,
                            operation_id,
                            session_id.to_string(),
                            decision_request_id.to_string(),
                            current.agent_instance_id.to_string(),
                        ],
                    )?;
                    ensure!(
                        changed == 1,
                        "host capability refresh operation terminalization lost its decision binding"
                    );
                }
                if trusted_host_approval {
                    let operation_id = current
                        .host_approval_operation_id
                        .context("host approval decision is missing its final operation binding")?;
                    let changed = conn.execute(
                        "UPDATE agent_host_approval_operations
                         SET state = 'approved', resolved_at_unix_ms = ?1,
                             approved_agent_revision = ?2, selected_response_json = ?3,
                             selected_candidate_json = ?4
                         WHERE operation_id = ?5 AND decision_request_id = ?6
                           AND session_id = ?7 AND agent_instance_id = ?8
                           AND state = 'pending'",
                        params![
                            now_unix_ms,
                            owner.revision + 1,
                            host_selected_response_json.as_deref(),
                            host_selected_candidate_json.as_deref(),
                            operation_id.to_string(),
                            decision_request_id.to_string(),
                            session_id.to_string(),
                            current.agent_instance_id.to_string(),
                        ],
                    )?;
                    ensure!(changed == 1, "host approval operation is not pending for this decision");
                } else if current.decision_class == "host_approval" {
                    // A decline/cancel is the only non-host terminal path for
                    // an approval decision. Close the exact pre-bound final
                    // operation in the same transaction; leaving it pending
                    // would let a later caller mistake a declined prompt for
                    // authority to execute.
                    let operation_id = current
                        .host_approval_operation_id
                        .context("host approval decision is missing its final operation binding")?;
                    let changed = conn.execute(
                        "UPDATE agent_host_approval_operations
                         SET state = 'cancelled', resolved_at_unix_ms = ?1
                         WHERE operation_id = ?2 AND decision_request_id = ?3
                           AND session_id = ?4 AND agent_instance_id = ?5
                           AND state = 'pending'",
                        params![
                            now_unix_ms,
                            operation_id.to_string(),
                            decision_request_id.to_string(),
                            session_id.to_string(),
                            current.agent_instance_id.to_string(),
                        ],
                    )?;
                    ensure!(changed == 1, "host approval operation is not pending for this decision");
                }
                conn.execute(
                    "INSERT INTO decision_receipts (
                         decision_request_id, session_id, terminal_state, terminal_revision,
                         receipt_json, resume_payload_json, session_event_seq, created_at_unix_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        decision_request_id.to_string(),
                        session_id.to_string(),
                        next_state.as_str(),
                        next_revision,
                        receipt_json,
                        resume_payload_json.as_deref(),
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
                    resume_payload_json.as_deref(),
                    now_unix_ms,
                )?;
                // A terminal decision is the sole durable resume gate for a
                // waiting owner.  Put the owner back into `running` inside
                // the same transaction so a restart observes either both
                // facts or neither; terminal CAS losers cannot enqueue a
                // second resume.
                if matches!(
                    owner.state,
                    AgentInstanceState::WaitingForUser | AgentInstanceState::WaitingForApproval
                ) {
                    let resumed_revision = owner.revision + 1;
                    let resumed = conn.execute(
                        "UPDATE agent_instances
                         SET state = 'running', revision = ?1, updated_at_unix_ms = ?2
                         WHERE agent_instance_id = ?3 AND session_id = ?4
                           AND revision = ?5
                           AND state IN ('waiting_for_user', 'waiting_for_approval')",
                        params![
                            resumed_revision,
                            now_unix_ms,
                            owner.agent_instance_id.to_string(),
                            session_id.to_string(),
                            owner.revision,
                        ],
                    )?;
                    ensure!(resumed == 1, "decision owner resume CAS lost");
                    insert_control_event(
                        conn,
                        session_id,
                        "agent_transition",
                        owner.agent_instance_id,
                        AgentInstanceState::Running.as_str(),
                        now_unix_ms,
                    )?;
                }
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
) -> Result<Option<String>> {
    let workspace_ref = match input.parent_agent_instance_id {
        Some(parent_id) => {
            let parent = load_agent(conn, input.session_id, parent_id)?
                .context("parent agent is not authorized for this session")?;
            ensure!(parent_id != agent_instance_id, "agent cannot parent itself");
            ensure!(
                !parent.state.is_terminal(),
                "cannot create a child for a terminal parent agent"
            );
            match parent.workspace_ref {
                Some(parent_workspace_ref) => {
                    ensure!(
                        is_host_workspace_ref(&parent_workspace_ref),
                        "parent agent carries an invalid workspace reference"
                    );
                    if let Some(requested_workspace_ref) = input.workspace_ref.as_deref() {
                        ensure!(
                            requested_workspace_ref == parent_workspace_ref,
                            "child workspace reference must inherit its exact parent workspace reference"
                        );
                    }
                    Some(parent_workspace_ref)
                }
                None => {
                    // Legacy/test-only daemonless roots deliberately have no
                    // workspace identity. They may only produce another
                    // absent identity; a child still cannot inject text.
                    ensure!(
                        input.workspace_ref.is_none(),
                        "child cannot supply a workspace reference when its parent has none"
                    );
                    None
                }
            }
        }
        None => {
            // `ensure_session_root_agent` is the only root creation API that
            // accepts a workspace identity; it receives the daemon-derived
            // path digest and persists the stable `session-root` binding.
            // Generic agent creation remains useful for daemonless fixtures
            // and non-root recovery scaffolding, but cannot inject a root
            // workspace selector into packets.
            ensure!(
                input.workspace_ref.is_none(),
                "generic root creation cannot choose a workspace reference; use the daemon-owned session root"
            );
            None
        }
    };
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
    Ok(workspace_ref)
}

fn is_host_workspace_ref(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("workspace:v1:") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f'))
}

/// Decision packets may expose only bounded opaque identifiers copied from
/// daemon-owned agent/task/session rows. This deliberately validates shape
/// without attempting to interpret a task id or grant authority from it.
fn validate_daemon_opaque_reference(value: &str, field: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 512
            && !value.contains('\0')
            && value.chars().all(|character| !character.is_control()),
        "{field} is not a bounded opaque reference"
    );
    Ok(())
}

/// Prove that an effect handoff still belongs to the exact real
/// QuestionTool interrupt that produced its host authority.  Every concrete
/// consume/claim/terminal boundary calls this inside its own DB closure; a
/// forged operation-shaped row cannot be attached to an unrelated attention
/// record merely by matching UUID-looking inputs.
fn host_approval_operation_has_exact_interrupt(
    conn: &Connection,
    authority: HostApprovalAuthority,
    session_id: Uuid,
    agent_instance_id: Uuid,
    operation_id: Uuid,
    interrupt_id: Uuid,
) -> Result<bool> {
    // A typed production host approval is inseparable from the real
    // QuestionTool continuation that offered it. The only nil exception is a
    // separately feature-gated dev-test marker; normal/release dependency
    // graphs cannot construct that marker.
    #[cfg(not(feature = "host-approval-test-support"))]
    let _ = authority;
    if interrupt_id.is_nil() {
        #[cfg(feature = "host-approval-test-support")]
        if authority.is_test_only() {
            return Ok(true);
        }
        bail!("host approval effect handoff requires a non-nil registered interrupt");
    }
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(
             SELECT 1
               FROM agent_host_approval_operations operation
               JOIN decision_requests decision
                 ON decision.decision_request_id = operation.decision_request_id
                AND decision.session_id = operation.session_id
               JOIN needs_attention interrupt
                 ON interrupt.decision_request_id = decision.decision_request_id
                AND interrupt.session_id = decision.session_id
              WHERE operation.operation_id = ?1
                AND operation.session_id = ?2
                AND operation.agent_instance_id = ?3
                AND decision.host_approval_operation_id = operation.operation_id
                AND interrupt.interrupt_id = ?4
           )",
        params![
            operation_id.to_string(),
            session_id.to_string(),
            agent_instance_id.to_string(),
            interrupt_id.to_string(),
        ],
        |row| row.get(0),
    )?;
    Ok(exists != 0)
}

fn load_agent(
    conn: &Connection,
    session_id: Uuid,
    agent_id: Uuid,
) -> Result<Option<AgentInstanceRow>> {
    conn.query_row(
        "SELECT agent_instance_id, session_id, parent_agent_instance_id, task_delegation_job_id,
                task_delegation_child_uuid, resolved_profile_snapshot_id, workspace_ref,
                auto_answer_enabled, state, revision,
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
                workspace_ref: row.get(6)?,
                auto_answer_enabled: row.get::<_, i64>(7)? != 0,
                state: AgentInstanceState::parse(&row.get::<_, String>(8)?)?,
                revision: row.get(9)?,
                created_at_unix_ms: row.get(10)?,
                updated_at_unix_ms: row.get(11)?,
            })
        },
    )
    .optional()
    .context("loading authorized agent instance")
}

fn list_lineage_ids_conn(
    conn: &Connection,
    session_id: Uuid,
    root_agent_instance_id: Option<Uuid>,
    after: Option<&AgentTreePageCursor>,
    limit: usize,
) -> Result<Vec<Uuid>> {
    let (root_clause, cursor_clause, mut values): (&str, &str, Vec<rusqlite::types::Value>) =
        match (root_agent_instance_id, after) {
            (Some(root), Some(cursor)) => (
                "AND agent_instance_id IN (SELECT agent_instance_id FROM tree)",
                "AND (created_at_unix_ms > ?3 OR (created_at_unix_ms = ?3 AND agent_instance_id > ?4))",
                vec![session_id.to_string().into(), root.to_string().into(), cursor.created_at_unix_ms.into(), cursor.id.to_string().into()],
            ),
            (Some(root), None) => (
                "AND agent_instance_id IN (SELECT agent_instance_id FROM tree)",
                "",
                vec![session_id.to_string().into(), root.to_string().into()],
            ),
            (None, Some(cursor)) => (
                "",
                "AND (created_at_unix_ms > ?2 OR (created_at_unix_ms = ?2 AND agent_instance_id > ?3))",
                vec![session_id.to_string().into(), cursor.created_at_unix_ms.into(), cursor.id.to_string().into()],
            ),
            (None, None) => ("", "", vec![session_id.to_string().into()]),
        };
    if let Some(root) = root_agent_instance_id {
        ensure!(
            load_agent(conn, session_id, root)?.is_some(),
            "agent lineage root is not authorized for this session"
        );
    }
    let limit_parameter = values.len() + 1;
    values.push((limit as i64).into());
    let sql = format!(
        "WITH RECURSIVE tree(agent_instance_id) AS (
             SELECT agent_instance_id FROM agent_instances
              WHERE agent_instance_id = ?2 AND session_id = ?1
             UNION ALL
             SELECT child.agent_instance_id FROM agent_instances child
             JOIN tree parent ON child.parent_agent_instance_id = parent.agent_instance_id
              WHERE child.session_id = ?1
         )
         SELECT agent_instance_id FROM agent_instances
          WHERE session_id = ?1 {root_clause} {cursor_clause}
          ORDER BY created_at_unix_ms, agent_instance_id LIMIT ?{limit_parameter}"
    );
    // SQLite accepts an unused recursive CTE when listing the whole forest;
    // its root parameter is absent in that branch, so use a branch-local query
    // instead of binding a meaningless NULL and risking an accidental root.
    let sql = if root_agent_instance_id.is_none() {
        format!(
            "SELECT agent_instance_id FROM agent_instances
              WHERE session_id = ?1 {cursor_clause}
              ORDER BY created_at_unix_ms, agent_instance_id LIMIT ?{limit_parameter}"
        )
    } else {
        sql
    };
    let mut statement = conn.prepare(&sql)?;
    statement
        .query_map(rusqlite::params_from_iter(values), |row| {
            parse_uuid(row.get::<_, String>(0)?)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("listing agent lineage")
}

fn load_decision(
    conn: &Connection,
    session_id: Uuid,
    decision_id: Uuid,
) -> Result<Option<DecisionRequestRow>> {
    let decision = conn.query_row(
        "SELECT decision_request_id, agent_instance_id, session_id, task_call_id_ref, workspace_ref,
                options_contract_json,
                free_text_contract_json, recommendation_json, rationale_redaction_class,
                decision_class, host_approval_operation_id, deadline_unix_ms,
                policy_receipt_json, resolver_route, state, revision,
                created_at_unix_ms, updated_at_unix_ms
         FROM decision_requests WHERE decision_request_id = ?1 AND session_id = ?2",
        params![decision_id.to_string(), session_id.to_string()],
        |row| {
            let decision = DecisionRequestRow {
                decision_request_id: parse_uuid(row.get::<_, String>(0)?)?,
                agent_instance_id: parse_uuid(row.get::<_, String>(1)?)?,
                session_id: parse_uuid(row.get::<_, String>(2)?)?,
                task_call_id: row.get(3)?,
                workspace_ref: row.get(4)?,
                options_contract_json: row.get(5)?,
                free_text_contract_json: row.get(6)?,
                recommendation_json: row.get(7)?,
                rationale_redaction_class: row.get(8)?,
                decision_class: row.get(9)?,
                host_approval_operation_id: row
                    .get::<_, Option<String>>(10)?
                    .map(parse_uuid)
                    .transpose()?,
                deadline_unix_ms: row.get(11)?,
                policy_receipt_json: row.get(12)?,
                resolver_route: row.get(13)?,
                state: DecisionState::parse(&row.get::<_, String>(14)?)?,
                revision: row.get(15)?,
                created_at_unix_ms: row.get(16)?,
                updated_at_unix_ms: row.get(17)?,
            };
            Ok(decision)
        },
    )
    .optional()
    .context("loading authorized decision request")?;
    let Some(decision) = decision else {
        return Ok(None);
    };
    validate_redaction_class(&decision.rationale_redaction_class)
        .context("persisted decision rationale class is invalid")?;
    validate_decision_class(&decision.decision_class).context("persisted decision class is invalid")?;
    let public_option_ids = validate_durable_decision_answer_contract(
        &decision.options_contract_json,
        decision.free_text_contract_json.as_deref(),
    )
    .context("persisted decision answer contract is invalid")?;
    let has_question_tool_contract = durable_decision_has_question_tool_contract(
        &decision.options_contract_json,
    )
    .context("persisted decision QuestionTool binding is invalid")?;
    let mappings = load_private_decision_option_mappings_conn(
        conn,
        decision.session_id,
        decision.decision_request_id,
    )
    .context("persisted decision private option mappings are invalid")?;
    validate_durable_private_option_mappings(
        &public_option_ids,
        mappings.iter().map(|mapping| {
            (
                mapping.opaque_option_id.as_str(),
                mapping.continuation_option_id.as_str(),
            )
        }),
    )
    .context("persisted decision private option mappings are invalid")?;
    let attention: Option<(Option<String>, Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT agent_instance_id, question_json, questions_json
               FROM needs_attention
              WHERE session_id = ?1 AND decision_request_id = ?2",
            params![decision.session_id.to_string(), decision.decision_request_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (attention_owner, question_json, questions_json) = attention.context(
        "persisted decision is missing its sole durable Attention projection",
    )?;
    let expected_owner = decision.agent_instance_id.to_string();
    ensure!(
        attention_owner.as_deref() == Some(expected_owner.as_str()),
        "persisted decision Attention owner does not match its decision agent"
    );
    if has_question_tool_contract {
        validate_question_tool_contract_matches_interrupt(
            &decision.options_contract_json,
            mappings.iter().map(|mapping| {
                (
                    mapping.opaque_option_id.as_str(),
                    mapping.continuation_option_id.as_str(),
                )
            }),
            question_json.as_deref(),
            questions_json.as_deref(),
        )
        .context("persisted QuestionTool durable contract does not match its real interrupt")?;
        validate_raw_interrupt_approval_binding(
            &decision.decision_class,
            decision.host_approval_operation_id,
            question_json.as_deref(),
            questions_json.as_deref(),
        )
        .context("persisted QuestionTool approval metadata does not match its decision class")?;
    } else {
        ensure!(
            question_json.is_none() && questions_json.is_none(),
            "persisted generic decision must not bind a real QuestionTool interrupt"
        );
    }
    validate_persisted_host_approval_operation_binding(
        conn,
        &decision,
        has_question_tool_contract,
    )?;
    match decision.recommendation_json.as_deref() {
        Some(recommendation) => validate_durable_recommendation(
            recommendation,
            &decision.decision_class,
            &decision.rationale_redaction_class,
            &public_option_ids,
            mappings.iter().map(|mapping| {
                (
                    mapping.opaque_option_id.as_str(),
                    mapping.continuation_option_id.as_str(),
                )
            }),
        )
        .context("persisted decision recommendation is invalid")?,
        None if decision.decision_class == "low_risk" => bail!(
            "persisted low-risk durable decision is missing the approved host recommendation"
        ),
        None => {}
    }
    Ok(Some(decision))
}

fn load_private_decision_option_mappings_conn(
    conn: &Connection,
    session_id: Uuid,
    decision_request_id: Uuid,
) -> Result<Vec<DecisionPrivateOptionMapping>> {
    let mut statement = conn.prepare(
        "SELECT opaque_option_id, continuation_option_id
         FROM decision_private_option_mappings
         WHERE decision_request_id = ?1 AND session_id = ?2
         ORDER BY opaque_option_id",
    )?;
    statement
        .query_map(
            params![decision_request_id.to_string(), session_id.to_string()],
            |row| {
                Ok(DecisionPrivateOptionMapping {
                    opaque_option_id: row.get(0)?,
                    continuation_option_id: row.get(1)?,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn validate_durable_private_option_mappings<'a>(
    public_option_ids: &std::collections::BTreeSet<String>,
    mappings: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<()> {
    let mappings = mappings.into_iter().collect::<Vec<_>>();
    ensure!(
        mappings.len() == public_option_ids.len(),
        "durable public option tokens and private continuation mappings have different cardinality"
    );
    let mut opaque_option_ids = std::collections::BTreeSet::new();
    let mut continuation_option_ids = std::collections::BTreeSet::new();
    for (opaque_option_id, continuation_option_id) in mappings {
        validate_daemon_minted_public_option_id(opaque_option_id)?;
        validate_safe_identifier(continuation_option_id, "private continuation option id")?;
        ensure!(
            opaque_option_ids.insert(opaque_option_id),
            "durable private option mappings contain a duplicate public token"
        );
        ensure!(
            continuation_option_ids.insert(continuation_option_id),
            "durable private option mappings contain a duplicate continuation token"
        );
    }
    ensure!(
        opaque_option_ids == public_option_ids.iter().map(String::as_str).collect(),
        "durable public option tokens do not have exact private continuation mappings"
    );
    Ok(())
}

fn load_late_user_steer(
    conn: &Connection,
    session_id: Uuid,
    steer_id: Uuid,
) -> Result<Option<LateUserDecisionSteer>> {
    conn.query_row(
        "SELECT steer_id, continuation_id, session_id, requesting_agent_instance_id,
                agent_instance_id, decision_request_id,
                payload_json, predecessor_interrupt_id, created_at_unix_ms, claimed_recovery_epoch,
                execution_state, accepted_recovery_epoch, accepted_agent_revision,
                payload_bytes, continuation_checkpoint_json, completed_at_unix_ms,
                rejected_at_unix_ms, rejection_reason
         FROM agent_decision_steers WHERE steer_id = ?1 AND session_id = ?2",
        params![steer_id.to_string(), session_id.to_string()],
        |row| {
            Ok(LateUserDecisionSteer {
                steer_id: parse_uuid(row.get::<_, String>(0)?)?,
                continuation_id: parse_uuid(row.get::<_, String>(1)?)?,
                session_id: parse_uuid(row.get::<_, String>(2)?)?,
                requesting_agent_instance_id: parse_uuid(row.get::<_, String>(3)?)?,
                agent_instance_id: parse_uuid(row.get::<_, String>(4)?)?,
                decision_request_id: parse_uuid(row.get::<_, String>(5)?)?,
                payload_json: row.get(6)?,
                predecessor_interrupt_id: row
                    .get::<_, Option<String>>(7)?
                    .map(parse_uuid)
                    .transpose()?,
                created_at_unix_ms: row.get(8)?,
                claimed_recovery_epoch: row
                    .get::<_, Option<String>>(9)?
                    .map(parse_uuid)
                    .transpose()?,
                execution_state: LateUserDecisionSteerExecutionState::parse(&row.get::<_, String>(10)?)?,
                accepted_recovery_epoch: row
                    .get::<_, Option<String>>(11)?
                    .map(parse_uuid)
                    .transpose()?,
                accepted_agent_revision: row.get(12)?,
                payload_bytes: row.get(13)?,
                continuation_checkpoint_json: row.get(14)?,
                completed_at_unix_ms: row.get(15)?,
                rejected_at_unix_ms: row.get(16)?,
                rejection_reason: row.get(17)?,
            })
        },
    )
    .optional()
    .context("loading late user decision steer")
}

/// The runtime and boot-recovery paths share this exact pre-bind cleanup
/// transaction. A caller must name the immutable initialization tuple rather
/// than merely a session/child, so a stale failure cannot touch a later
/// refresh attempt. `raw_interrupt_id` narrows the live path to the concrete
/// QuestionTool row it just raised; boot passes `None` to close every raw,
/// unbound row that the still-initializing child could have produced.
fn abort_host_capability_refresh_initialization_conn(
    conn: &Connection,
    session_id: Uuid,
    operation_id: Uuid,
    request_id: Uuid,
    agent_instance_id: Uuid,
    raw_interrupt_id: Option<Uuid>,
    terminal_reason: &'static str,
    now_unix_ms: i64,
) -> Result<HostCapabilityRefreshInitializationAbort> {
    let descriptor: Option<(String, String)> = conn
        .query_row(
            "SELECT state, parent_agent_instance_id
               FROM host_capability_refresh_initializations
              WHERE operation_id = ?1 AND request_id = ?2
                AND session_id = ?3 AND agent_instance_id = ?4",
            params![
                operation_id.to_string(),
                request_id.to_string(),
                session_id.to_string(),
                agent_instance_id.to_string(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((descriptor_state, parent_id_raw)) = descriptor else {
        return Ok(HostCapabilityRefreshInitializationAbort::Missing);
    };
    match descriptor_state.as_str() {
        "cancelled" => return Ok(HostCapabilityRefreshInitializationAbort::AlreadyTerminal),
        "bound" => {
            // A bound descriptor has crossed the atomic creation boundary.
            // Do not let a stale caller cancel it; prove that it still names
            // the same operation/interrupt/decision tuple and leave the
            // exactly-once operation state machine in charge.
            let exact_binding: i64 = conn.query_row(
                "SELECT EXISTS (
                     SELECT 1
                       FROM host_capability_refresh_operations operation
                       JOIN host_capability_refresh_initializations initialization
                         ON initialization.operation_id = operation.operation_id
                        AND initialization.request_id = operation.request_id
                        AND initialization.session_id = operation.session_id
                        AND initialization.agent_instance_id = operation.agent_instance_id
                        AND initialization.interrupt_id = operation.interrupt_id
                        AND initialization.decision_request_id = operation.decision_request_id
                      WHERE operation.operation_id = ?1 AND operation.request_id = ?2
                        AND operation.session_id = ?3 AND operation.agent_instance_id = ?4
                        AND initialization.state = 'bound'
                 )",
                params![
                    operation_id.to_string(),
                    request_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                ],
                |row| row.get(0),
            )?;
            ensure!(
                exact_binding != 0,
                "bound host capability refresh initialization lost its exact operation binding"
            );
            return Ok(HostCapabilityRefreshInitializationAbort::AlreadyBound);
        }
        "initializing" => {}
        _ => bail!("invalid host capability refresh initialization state"),
    }

    let parent_agent_instance_id = parse_uuid(parent_id_raw)?;
    let child = load_agent(conn, session_id, agent_instance_id)?
        .context("host capability refresh initialization child is missing")?;
    ensure!(
        child.parent_agent_instance_id == Some(parent_agent_instance_id),
        "host capability refresh initialization child lineage changed"
    );
    let bound_operation_exists: i64 = conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM host_capability_refresh_operations
              WHERE operation_id = ?1 AND request_id = ?2
                AND session_id = ?3 AND agent_instance_id = ?4
         )",
        params![
            operation_id.to_string(),
            request_id.to_string(),
            session_id.to_string(),
            agent_instance_id.to_string(),
        ],
        |row| row.get(0),
    )?;
    ensure!(
        bound_operation_exists == 0,
        "initializing host capability refresh child already has a bound operation"
    );

    // A normal failure can occur after QuestionTool durably raised its real
    // interrupt but before the later transaction attaches the decision and
    // operation. When the live caller knows that raw interrupt, first prove
    // that it did not cross the bind. Then resolve every raw unbound row for
    // this dedicated child: there should be only the named row, but retaining
    // a second malformed/stale one would still make the cancelled descriptor
    // replayable through generic interrupt recovery.
    if let Some(raw_interrupt_id) = raw_interrupt_id {
        let raw_decision_request_id: Option<Option<String>> = conn
            .query_row(
                "SELECT decision_request_id
                   FROM needs_attention
                  WHERE interrupt_id = ?1 AND session_id = ?2
                    AND agent_instance_id = ?3",
                params![
                    raw_interrupt_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                ],
                |row| row.get(0),
            )
            .optional()?;
        ensure!(
            raw_decision_request_id.flatten().is_none(),
            "pre-bind host capability refresh abort found a decision-bound interrupt"
        );
    }
    conn.execute(
        "UPDATE needs_attention
            SET state = 'resolved', resolved_at = ?1, revision = revision + 1
          WHERE session_id = ?2 AND agent_instance_id = ?3
            AND decision_request_id IS NULL
            AND state IN ('open', 'parked', 'executing', 'interrupted')",
        params![now_unix_ms, session_id.to_string(), agent_instance_id.to_string()],
    )?;

    if !child.state.is_terminal() {
        // This is equivalent to the cancellation branch of the public
        // lifecycle transition, but stays in this transaction so the child,
        // raw attention, and descriptor cannot be observed disagreeing.
        cancel_owned_decisions_for_subtree(conn, session_id, agent_instance_id, now_unix_ms)?;
        cancel_live_descendants(conn, session_id, agent_instance_id, now_unix_ms)?;
        let next_revision = child.revision + 1;
        let event_seq = insert_control_event(
            conn,
            session_id,
            "agent_transition",
            agent_instance_id,
            AgentInstanceState::Cancelled.as_str(),
            now_unix_ms,
        )?;
        let changed = conn.execute(
            "UPDATE agent_instances
                SET state = 'cancelled', revision = ?1, updated_at_unix_ms = ?2
              WHERE agent_instance_id = ?3 AND session_id = ?4 AND revision = ?5
                AND state NOT IN ('completed', 'failed', 'cancelled')",
            params![
                next_revision,
                now_unix_ms,
                agent_instance_id.to_string(),
                session_id.to_string(),
                child.revision,
            ],
        )?;
        ensure!(
            changed == 1,
            "host capability refresh initialization cancellation lost its compare-and-set"
        );
        conn.execute(
            "INSERT INTO agent_transition_receipts (
                 agent_instance_id, terminal_state, session_id, terminal_revision,
                 receipt_json, session_event_seq, created_at_unix_ms
             ) VALUES (?1, 'cancelled', ?2, ?3, ?4, ?5, ?6)",
            params![
                agent_instance_id.to_string(),
                session_id.to_string(),
                next_revision,
                redacted_marker(
                    "host capability refresh initialization aborted before durable decision bind",
                ),
                event_seq,
                now_unix_ms,
            ],
        )?;
    }
    let descriptor_cancelled = conn.execute(
        "UPDATE host_capability_refresh_initializations
            SET state = 'cancelled', terminal_reason = ?1,
                updated_at_unix_ms = ?2, completed_at_unix_ms = ?2
          WHERE operation_id = ?3 AND request_id = ?4
            AND session_id = ?5 AND agent_instance_id = ?6
            AND state = 'initializing'",
        params![
            terminal_reason,
            now_unix_ms,
            operation_id.to_string(),
            request_id.to_string(),
            session_id.to_string(),
            agent_instance_id.to_string(),
        ],
    )?;
    ensure!(
        descriptor_cancelled == 1,
        "host capability refresh initialization cancellation lost its exact descriptor"
    );
    Ok(HostCapabilityRefreshInitializationAbort::Aborted)
}

fn host_capability_refresh_operation_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<HostCapabilityRefreshOperationRow> {
    Ok(HostCapabilityRefreshOperationRow {
        operation_id: parse_uuid(row.get::<_, String>(0)?)?,
        request_id: parse_uuid(row.get::<_, String>(1)?)?,
        session_id: parse_uuid(row.get::<_, String>(2)?)?,
        agent_instance_id: parse_uuid(row.get::<_, String>(3)?)?,
        interrupt_id: parse_uuid(row.get::<_, String>(4)?)?,
        decision_request_id: row
            .get::<_, Option<String>>(5)?
            .map(parse_uuid)
            .transpose()?,
        state: HostCapabilityRefreshOperationState::parse(&row.get::<_, String>(6)?)?,
        reserved_snapshot_generation: row
            .get::<_, Option<i64>>(7)?
            .map(|generation| {
                u64::try_from(generation).map_err(|_| {
                    invalid_persisted_value("host capability refresh reserved snapshot generation")
                })
            })
            .transpose()?,
        result_snapshot_json: row.get(8)?,
        result_snapshot_generation: row
            .get::<_, Option<i64>>(9)?
            .map(|generation| {
                u64::try_from(generation).map_err(|_| {
                    invalid_persisted_value("host capability refresh result snapshot generation")
                })
            })
            .transpose()?,
        result_snapshot_digest: row.get(10)?,
        published_at_unix_ms: row.get(11)?,
        error_text: row.get(12)?,
        created_at_unix_ms: row.get(13)?,
        completed_at_unix_ms: row.get(14)?,
    })
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
                resume_payload_json: None,
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
                receipt_json, resume_payload_json, session_event_seq, created_at_unix_ms
         FROM decision_receipts WHERE decision_request_id = ?1 AND session_id = ?2",
        params![decision_id.to_string(), session_id.to_string()],
        |row| {
            Ok(TerminalReceipt {
                subject_id: parse_uuid(row.get::<_, String>(0)?)?,
                session_id: parse_uuid(row.get::<_, String>(1)?)?,
                terminal_state: row.get(2)?,
                terminal_revision: row.get(3)?,
                receipt_json: row.get(4)?,
                resume_payload_json: row.get(5)?,
                session_event_seq: row.get(6)?,
                created_at_unix_ms: row.get(7)?,
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
         SELECT child.agent_instance_id, child.revision, child.state, operation.state
           FROM agent_instances child
      LEFT JOIN host_capability_refresh_operations operation
             ON operation.session_id = child.session_id
            AND operation.agent_instance_id = child.agent_instance_id
          WHERE child.agent_instance_id IN descendants
            AND child.state NOT IN ('completed', 'failed', 'cancelled')
          ORDER BY child.agent_instance_id",
    )?;
    let live = statement
        .query_map(
            params![root_id.to_string(), session_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (agent_id, revision, current_state, operation_state) in live {
        let id = parse_uuid(agent_id)?;
        let current_state = AgentInstanceState::parse(&current_state)?;
        // The durable host operation is the only authority that may override
        // a generic subtree-cancellation child state.  If it already reached
        // a terminal outcome, preserve that exact outcome on its dedicated
        // child instead of manufacturing a mismatched cancellation receipt.
        // Any nonterminal operation here is a cancellation-ordering bug: the
        // caller must first terminalize every operation in this subtree.
        let target_state = match operation_state.as_deref() {
            None => AgentInstanceState::Cancelled,
            Some("completed") => AgentInstanceState::Completed,
            Some("failed") => AgentInstanceState::Failed,
            Some("cancelled") => AgentInstanceState::Cancelled,
            Some(_) => bail!("subtree cancellation found a nonterminal host capability refresh operation"),
        };
        ensure!(
            current_state.legal_transition(target_state),
            "subtree cancellation cannot apply the host capability refresh terminal outcome to its child"
        );
        let event_seq = insert_control_event(
            conn,
            session_id,
            "agent_transition",
            id,
            target_state.as_str(),
            now_unix_ms,
        )?;
        let changed = conn.execute(
            "UPDATE agent_instances SET state = ?1, revision = revision + 1,
             updated_at_unix_ms = ?2
             WHERE agent_instance_id = ?3 AND session_id = ?4 AND revision = ?5
               AND state NOT IN ('completed', 'failed', 'cancelled')",
            params![
                target_state.as_str(),
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
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id.to_string(),
                target_state.as_str(),
                session_id.to_string(),
                revision + 1,
                redacted_marker("cascade cancellation with durable host-operation terminal outcome"),
                event_seq,
                now_unix_ms,
            ],
        )?;
    }
    Ok(())
}

/// An accepted late steer is a no-redelivery continuation only while its
/// exact owner has a live successor.  Every terminal lifecycle path owns the
/// complementary terminal receipt: pending/accepted rows become rejected,
/// while completed rows remain receipt-only acknowledgeable.  The caller is
/// already inside the lifecycle transaction, so a terminal owner can never
/// race a recovery epoch into stranding an accepted continuation.
fn reject_undelivered_late_user_steers_for_tree(
    conn: &Connection,
    session_id: Uuid,
    root_id: Uuid,
    reason: &'static str,
    now_unix_ms: i64,
) -> Result<()> {
    conn.execute(
        "WITH RECURSIVE tree(agent_instance_id) AS (
             SELECT agent_instance_id FROM agent_instances
              WHERE agent_instance_id = ?1 AND session_id = ?2
             UNION ALL
             SELECT child.agent_instance_id FROM agent_instances child
              JOIN tree parent ON child.parent_agent_instance_id = parent.agent_instance_id
              WHERE child.session_id = ?2
         )
         UPDATE agent_decision_steers
            SET execution_state = 'rejected',
                claimed_recovery_epoch = NULL,
                rejected_at_unix_ms = ?3,
                rejection_reason = ?4
          WHERE session_id = ?2
            AND agent_instance_id IN tree
            AND delivered_at_unix_ms IS NULL
            AND execution_state IN ('pending', 'accepted')",
        params![
            root_id.to_string(),
            session_id.to_string(),
            now_unix_ms,
            reason,
        ],
    )?;
    Ok(())
}

fn terminal_late_steer_rejection_reason(state: AgentInstanceState) -> &'static str {
    match state {
        AgentInstanceState::Completed => "owner_terminal_completed",
        AgentInstanceState::Failed => "owner_terminal_failed",
        AgentInstanceState::Cancelled => "owner_subtree_cancelled",
        AgentInstanceState::Created
        | AgentInstanceState::Running
        | AgentInstanceState::WaitingForUser
        | AgentInstanceState::WaitingForApproval => {
            unreachable!("only terminal lifecycle states can reject a late steer")
        }
    }
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
    // A late steer is a durable continuation, not an informational event. A
    // subtree cancellation is therefore its terminal winner too. Do this
    // before any agent receipt is written and in the same IMMEDIATE
    // transaction as decision/descendant cancellation: a claim or acceptance
    // that loses this transaction can observe no live exact owner and cannot
    // start a post-cancel model turn. A completed row already crossed the
    // exact continuation handoff, so retain its immutable receipt for
    // acknowledgement rather than moving a terminal state backward.
    reject_undelivered_late_user_steers_for_tree(
        conn,
        session_id,
        root_id,
        terminal_late_steer_rejection_reason(AgentInstanceState::Cancelled),
        now_unix_ms,
    )?;
    // An approval is deliberately not an executor lease.  If cancellation
    // wins while an operation is approved but has not crossed its durable
    // dispatch handoff, close it in the same transaction as the tree
    // terminalization.  `dispatching` is intentionally excluded: that state
    // is the linearized external boundary and must become submission-unknown
    // on recovery instead of being silently relabelled cancelled.
    // Close the pre-dispatch capability before cancelling its matching
    // approved operation. This is one transaction with the tree cancellation,
    // so scope cleanup can never observe a `ready` handoff whose operation has
    // already become cancelled. `dispatching` is deliberately excluded: it is
    // the irrevocable external boundary and must reconcile as unknown.
    conn.execute(
        "WITH RECURSIVE tree(agent_instance_id) AS (
             SELECT agent_instance_id FROM agent_instances
              WHERE agent_instance_id = ?1 AND session_id = ?2
             UNION ALL
             SELECT child.agent_instance_id FROM agent_instances child
             JOIN tree parent ON child.parent_agent_instance_id = parent.agent_instance_id
              WHERE child.session_id = ?2
         )
         UPDATE agent_host_approval_effect_handoffs
            SET state = 'rejected', completed_at_unix_ms = ?3,
                completion_receipt_json = '{\"outcome\":\"not_submitted\",\"reason\":\"tree_cancelled\"}'
          WHERE session_id = ?2 AND agent_instance_id IN tree AND state = 'ready'
            AND operation_id IN (
                SELECT operation_id FROM agent_host_approval_operations
                 WHERE session_id = ?2 AND agent_instance_id IN tree AND state = 'approved'
            )",
        params![root_id.to_string(), session_id.to_string(), now_unix_ms],
    )?;
    conn.execute(
        "WITH RECURSIVE tree(agent_instance_id) AS (
             SELECT agent_instance_id FROM agent_instances
              WHERE agent_instance_id = ?1 AND session_id = ?2
             UNION ALL
             SELECT child.agent_instance_id FROM agent_instances child
             JOIN tree parent ON child.parent_agent_instance_id = parent.agent_instance_id
              WHERE child.session_id = ?2
         )
         UPDATE agent_host_approval_operations
            SET state = 'cancelled', resolved_at_unix_ms = ?3
          WHERE session_id = ?2
            AND agent_instance_id IN tree
            AND state = 'approved'",
        params![root_id.to_string(), session_id.to_string(), now_unix_ms],
    )?;
    // A host-capability refresh has no successor continuation once its owner
    // subtree is cancelled. Close it in this same lifecycle transaction so a
    // later worker start cannot claim a probe for a tree that has already
    // produced its terminal receipts. `executing` has crossed the local probe
    // boundary, but a subtree cancellation is still the terminal authority
    // for this daemon-local, result-suppressed operation: fence the in-flight
    // completion and give the operation and its child one coherent cancelled
    // outcome rather than creating an unrecoverable failed/cancelled pair.
    conn.execute(
        "WITH RECURSIVE tree(agent_instance_id) AS (
             SELECT agent_instance_id FROM agent_instances
              WHERE agent_instance_id = ?1 AND session_id = ?2
             UNION ALL
             SELECT child.agent_instance_id FROM agent_instances child
              JOIN tree parent ON child.parent_agent_instance_id = parent.agent_instance_id
              WHERE child.session_id = ?2
         )
         UPDATE host_capability_refresh_operations
            SET state = 'cancelled',
                error_text = 'host capability refresh owner subtree was cancelled',
                updated_at_unix_ms = ?3,
                completed_at_unix_ms = ?3
          WHERE session_id = ?2 AND agent_instance_id IN tree
            AND state IN ('pending', 'allowed')",
        params![root_id.to_string(), session_id.to_string(), now_unix_ms],
    )?;
    conn.execute(
        "WITH RECURSIVE tree(agent_instance_id) AS (
             SELECT agent_instance_id FROM agent_instances
              WHERE agent_instance_id = ?1 AND session_id = ?2
             UNION ALL
             SELECT child.agent_instance_id FROM agent_instances child
              JOIN tree parent ON child.parent_agent_instance_id = parent.agent_instance_id
              WHERE child.session_id = ?2
         )
         UPDATE host_capability_refresh_operations
            SET state = 'cancelled',
                error_text = 'host capability refresh owner subtree was cancelled after probe began',
                updated_at_unix_ms = ?3,
                completed_at_unix_ms = ?3
          WHERE session_id = ?2 AND agent_instance_id IN tree
            AND state = 'executing'",
        params![root_id.to_string(), session_id.to_string(), now_unix_ms],
    )?;
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
        conn.execute(
            "UPDATE agent_host_approval_operations
             SET state = 'cancelled', resolved_at_unix_ms = ?1
             WHERE decision_request_id = ?2 AND session_id = ?3 AND state = 'pending'",
            params![now_unix_ms, decision_id.to_string(), session_id.to_string()],
        )?;
        resolve_owned_decision_attention(
            conn,
            session_id,
            decision_id,
            &redacted_marker("agent tree cancellation"),
            None,
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
    resume_payload_json: Option<&str>,
    now_unix_ms: i64,
) -> Result<()> {
    let attention: Option<(i64, String, bool)> = conn
        .query_row(
            "SELECT revision, state,
                    question_json IS NOT NULL OR questions_json IS NOT NULL
             FROM needs_attention
             WHERE decision_request_id = ?1 AND session_id = ?2 AND state <> 'resolved'",
            params![decision_request_id.to_string(), session_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((current_revision, current_state, is_real_interrupt)) = attention else {
        bail!("decision is missing its owned attention row");
    };
    // A QuestionTool/approval row is the existing durable continuation
    // rendezvous, not a synthetic AgentTree queue entry. Preserve its exact
    // protocol response and claim a parked continuation as `executing`; the
    // worker will then wake/replay that original continuation exactly once.
    let (next_state, response_json, resolved_at) = if is_real_interrupt {
        let response_json = interrupt_response_from_resume_payload(resume_payload_json)
            .unwrap_or_else(|| r#"{"kind":"cancel"}"#.to_string());
        match current_state.as_str() {
            "open" => ("resolved", response_json, Some(now_unix_ms)),
            "parked" => ("executing", response_json, None),
            "executing" => ("executing", response_json, None),
            _ => bail!("decision-owned interrupt is not in a resumable state"),
        }
    } else {
        ("resolved", receipt_json.to_string(), Some(now_unix_ms))
    };
    conn.execute(
        "INSERT INTO decision_attention_mutation_guards (decision_request_id, session_id)
         VALUES (?1, ?2)",
        params![decision_request_id.to_string(), session_id.to_string()],
    )?;
    let changed = conn.execute(
        "UPDATE needs_attention
         SET state = ?1, resolved_at = ?2, response_json = ?3, revision = ?4
         WHERE decision_request_id = ?5 AND session_id = ?6 AND revision = ?7
           AND state <> 'resolved'",
        params![
            next_state,
            resolved_at,
            response_json,
            current_revision + 1,
            decision_request_id.to_string(),
            session_id.to_string(),
            current_revision,
        ],
    )?;
    ensure!(changed == 1, "decision-owned attention CAS lost");
    insert_control_event(
        conn,
        session_id,
        "attention_transition",
        decision_request_id,
        next_state,
        now_unix_ms,
    )?;
    let removed = conn.execute(
        "DELETE FROM decision_attention_mutation_guards WHERE decision_request_id = ?1 AND session_id = ?2",
        params![decision_request_id.to_string(), session_id.to_string()],
    )?;
    ensure!(removed == 1, "decision attention guard disappeared");
    Ok(())
}

/// The private resume payload for an interactive question contains the exact
/// daemon-wire response under `answer`. It is intentionally extracted only at
/// the DB-owned continuation projection; public receipts stay redacted.
fn interrupt_response_from_resume_payload(resume_payload_json: Option<&str>) -> Option<String> {
    let payload: serde_json::Value = serde_json::from_str(resume_payload_json?).ok()?;
    match payload.get("answer_kind")?.as_str()? {
        "interrupt_response" => {
            let response = payload.get("answer")?.clone();
            // Parsing the precise wire type rejects JSON that happens to be
            // syntactically valid but cannot wake a parked QuestionTool call.
            serde_json::from_value::<crate::db::wire::ResolveResponse>(response.clone()).ok()?;
            serde_json::to_string(&response).ok()
        }
        _ => None,
    }
}

fn host_capability_refresh_response_allows(resume_payload_json: Option<&str>) -> bool {
    matches!(
        interrupt_response_from_resume_payload(resume_payload_json)
            .as_deref()
            .and_then(|raw| serde_json::from_str::<crate::db::wire::ResolveResponse>(raw).ok()),
        Some(crate::db::wire::ResolveResponse::Single { selected_id }) if selected_id == "refresh"
    )
}

pub(crate) fn insert_control_event(
    conn: &Connection,
    session_id: Uuid,
    kind: &str,
    subject_id: Uuid,
    _state: &str,
    now_unix_ms: i64,
) -> Result<i64> {
    let subject_kind = if kind.starts_with("decision_") || kind == "attention_transition" {
        "decision"
    } else {
        "agent"
    };
    let data_json = serde_json::to_string(&json!({
        "kind": kind,
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        // `state` is intentionally only an internal write-site assertion. It
        // is not serialized: consumers must re-read a page for current state,
        // rather than receiving a later mutable row relabeled as this event.
        "state_free": true,
        "redacted": true,
    }))?;
    conn.execute(
        "INSERT INTO session_events (session_id, ts_ms, type, data_json)
         VALUES (?1, ?2, 'agent_tree', ?3)",
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

fn validate_decision_class(value: &str) -> Result<()> {
    ensure!(
        matches!(
            value,
            "user_question"
                | "low_risk"
                | "credential"
                | "authorization"
                | "destructive"
                | "external_action"
                | "publish"
                | "purchase"
                | "production"
                | "host_approval"
        ),
        "invalid host decision class"
    );
    Ok(())
}

/// The storage boundary keeps this closed set next to the durable class
/// allowlist. Adding another automatically-resolvable class requires an
/// explicit typed composition path; it can never silently become available
/// through the generic `NewDecisionRequest` APIs.
fn is_automatically_resolvable_decision_class(value: &str) -> bool {
    matches!(value, "low_risk")
}

fn validate_host_operation_binding(operation_kind: &str, input_digest: &str) -> Result<()> {
    ensure!(
        !operation_kind.is_empty()
            && operation_kind.len() <= 128
            && operation_kind
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'),
        "host approval operation kind is invalid"
    );
    ensure!(
        input_digest.len() == 64 && input_digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "host approval operation digest is invalid"
    );
    Ok(())
}

/// Verify the opaque operation capability against the exact canonical facts
/// that the composition point persisted. A digest by itself is not enough at
/// a concrete effect boundary: accepting alternate JSON spellings would make
/// it impossible to prove which candidate set was actually approved.
fn validate_host_operation_canonical_input(canonical_input_json: &str, input_digest: &str) -> Result<()> {
    ensure!(
        canonical_input_json.len() <= 512 * 1024,
        "host approval canonical input exceeds durable limit"
    );
    let value: serde_json::Value = serde_json::from_str(canonical_input_json)
        .context("host approval canonical input must be valid JSON")?;
    validate_host_operation_candidate_set(&value)?;
    let canonical = canonical_json_bytes(&value)?;
    let canonical = std::str::from_utf8(&canonical)
        .context("canonical host approval input was not UTF-8")?;
    ensure!(
        canonical == canonical_input_json,
        "host approval input is not canonical JSON"
    );
    let mut digest = Sha256::new();
    digest.update(b"flycockpit.host-approval-input.v1\0");
    digest.update(canonical.as_bytes());
    ensure!(
        format!("{:x}", digest.finalize()) == input_digest,
        "host approval canonical input does not match its digest"
    );
    Ok(())
}

/// Validate the concrete effects re-derived at a host boundary before they
/// are compared with durable selected candidates. A single host boundary can
/// legitimately require two capabilities (for example an out-of-workspace
/// existing-file write has both a path-access and an exact-content approval),
/// so every handoff must match one member of this finite set.
fn validate_host_operation_concrete_effects(concrete_effects_json: &str) -> Result<Vec<Value>> {
    ensure!(
        concrete_effects_json.len() <= 512 * 1024,
        "host approval concrete effects are too large"
    );
    let effects: Vec<Value> = serde_json::from_str(concrete_effects_json)
        .context("host approval concrete effects are not JSON")?;
    ensure!(
        !effects.is_empty() && effects.len() <= 16,
        "host approval concrete effect set is empty or exceeds durable limit"
    );
    for effect in &effects {
        ensure!(
            effect.as_object().is_some_and(|object| object.len() == 1),
            "host approval concrete effect must contain exactly one effect field"
        );
    }
    Ok(effects)
}

/// Compare the effect reconstructed at the actual host boundary with the
/// selected durable candidate. A candidate's selection id and persistence
/// mutation are not caller authority; the exact effect field must match
/// structurally, so a stale approval cannot be redirected to another command,
/// request, connection, or filesystem mutation.
fn host_operation_candidate_matches_any_concrete_effect(
    candidate: &Value,
    concrete_effects: &[Value],
) -> bool {
    let Some(candidate) = candidate.as_object() else {
        return false;
    };
    concrete_effects.iter().any(|effect| {
        let Some(effect) = effect.as_object() else {
            return false;
        };
        let Some((effect_name, effect_value)) = effect.iter().next() else {
            return false;
        };
        matches!(
            effect_name.as_str(),
            "execute"
                | "connect"
                | "write"
                | "access"
                | "effect"
                | "persist_grant"
                | "persist_rule"
                | "persist_reject"
        )
            && candidate.get(effect_name) == Some(effect_value)
    })
}

/// Host approval is meaningful only for a finite, unambiguous candidate set.
/// The selected response is an option ID, so duplicate IDs would make the
/// terminal effect depend on producer ordering rather than the durable choice.
fn validate_host_operation_candidate_set(input: &serde_json::Value) -> Result<()> {
    let candidates = input
        .get("candidate_effects")
        .and_then(serde_json::Value::as_array)
        .context("host approval operation has no candidate effects")?;
    ensure!(
        !candidates.is_empty() && candidates.len() <= 64,
        "host approval candidate set is empty or exceeds durable limit"
    );
    let mut selections = std::collections::BTreeSet::new();
    for candidate in candidates {
        let candidate = candidate
            .as_object()
            .context("host approval candidate effect must be an object")?;
        let selection = candidate
            .get("selection")
            .and_then(serde_json::Value::as_str)
            .context("host approval candidate is missing its selection id")?;
        ensure!(
            !selection.is_empty()
                && selection.len() <= 128
                && selection.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-')
                }),
            "host approval candidate selection id is invalid"
        );
        ensure!(
            candidate.len() > 1,
            "host approval candidate has no effect or mutation binding"
        );
        ensure!(
            selections.insert(selection),
            "host approval candidate selections must be unique"
        );
    }
    Ok(())
}

/// A durable host approval names a finite candidate set before the UI renders.
/// Its terminal response must choose one of those exact candidates; merely
/// being an option in the presentation is insufficient because grant writes
/// and effect scopes are different authority changes.
fn validate_host_operation_selected_response(
    canonical_input_json: &str,
    selected_response_json: &str,
) -> Result<String> {
    let input: serde_json::Value = serde_json::from_str(canonical_input_json)
        .context("host approval canonical input must be valid JSON")?;
    let selected: serde_json::Value = serde_json::from_str(selected_response_json)
        .context("host approval selected response must be valid JSON")?;
    let selected_id = selected
        .get("data")
        .and_then(|data| data.get("selected_id"))
        .and_then(serde_json::Value::as_str)
        .context("host approval selected response is not a single option")?;
    let candidates = input
        .get("candidate_effects")
        .and_then(serde_json::Value::as_array)
        .context("host approval operation has no candidate effects")?;
    let candidate = candidates
        .iter()
        .find(|candidate| {
            candidate
                .get("selection")
                .and_then(serde_json::Value::as_str)
                == Some(selected_id)
        })
        .context("host approval response does not select a persisted candidate effect")?;
    String::from_utf8(canonical_json_bytes(candidate)?)
        .context("canonical selected host approval candidate was not UTF-8")
}

/// The host-approval decision transition is privileged, but the final
/// response still arrives through an interrupt. Validate that response against
/// the exact persisted question *inside the same transaction* which writes the
/// selected candidate.  Core performs the same check for good diagnostics;
/// this storage-side guard prevents a stale/malicious caller from selecting a
/// candidate merely by fabricating a response envelope.
fn validate_host_approval_response_against_offered_interrupt(
    conn: &Connection,
    session_id: Uuid,
    decision_request_id: Uuid,
    question_json: Option<&str>,
    questions_json: Option<&str>,
    selected_response_json: &str,
) -> Result<()> {
    use crate::db::wire::{InterruptQuestion, InterruptQuestionSet, ResolveResponse};

    ensure!(
        question_json.is_some() ^ questions_json.is_some(),
        "host approval interrupt has an invalid offered-question shape"
    );
    let questions = match (question_json, questions_json) {
        (Some(raw), None) => vec![
            serde_json::from_str::<InterruptQuestion>(raw)
                .context("host approval interrupt question is malformed")?,
        ],
        (None, Some(raw)) => serde_json::from_str::<InterruptQuestionSet>(raw)
            .context("host approval interrupt question set is malformed")?
            .questions,
        (None, None) | (Some(_), Some(_)) => unreachable!("validated exclusive question shape"),
    };
    ensure!(
        questions.len() == 1,
        "host approval interrupt must offer exactly one single-select question"
    );
    let response: ResolveResponse = serde_json::from_str(selected_response_json)
        .context("host approval selected response is not a valid response envelope")?;
    let (InterruptQuestion::Single { options, allow_freetext, .. }, ResolveResponse::Single { selected_id }) =
        (&questions[0], response)
    else {
        bail!("host approval response is not the exact offered single-select answer");
    };
    ensure!(
        !*allow_freetext,
        "host approval interrupt must not permit free-text selection"
    );
    ensure!(
        options.iter().any(|option| option.id == selected_id),
        "host approval response selects an option not offered by its persisted interrupt"
    );
    let mapped: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM decision_private_option_mappings
              WHERE decision_request_id = ?1 AND session_id = ?2
                AND continuation_option_id = ?3",
            params![
                decision_request_id.to_string(),
                session_id.to_string(),
                selected_id,
            ],
            |row| row.get(0),
        )
        .optional()?;
    ensure!(
        mapped.is_some(),
        "host approval response is not backed by this decision's immutable private option mapping"
    );
    Ok(())
}

/// Stable recursively sorted JSON encoding used by durable operation receipts.
/// Callers that persist a cross-process identity must use these exact bytes
/// before computing a digest; `serde_json::to_string` alone preserves input
/// map order and is not a canonical receipt format.
pub fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    fn write(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
        match value {
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
                out.extend(serde_json::to_vec(value)?);
            }
            serde_json::Value::String(_) => out.extend(serde_json::to_vec(value)?),
            serde_json::Value::Array(values) => {
                out.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    write(value, out)?;
                }
                out.push(b']');
            }
            serde_json::Value::Object(values) => {
                out.push(b'{');
                let mut entries = values.iter().collect::<Vec<_>>();
                entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(key)?);
                    out.push(b':');
                    write(value, out)?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }

    let mut canonical = Vec::new();
    write(value, &mut canonical)?;
    Ok(canonical)
}

/// The durable decision boundary stores canonical JSON, not merely equivalent
/// JSON.  This makes imports and SQLite corruption fail before a later reader
/// can reinterpret a differently-shaped public projection.
fn canonical_json_string(value: &serde_json::Value) -> Result<String> {
    String::from_utf8(canonical_json_bytes(value)?)
        .context("canonical JSON encoding is not valid UTF-8")
}

fn validate_resolver_route(value: &str) -> Result<()> {
    ensure!(
        matches!(
            value,
            "user" | "warm_parent" | "policy" | "utility" | "timeout" | "cancellation"
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

fn validate_resume_payload_json(raw: &str) -> Result<String> {
    ensure!(raw.len() <= 32 * 1024, "decision resume payload exceeds durable limit");
    let value: serde_json::Value =
        serde_json::from_str(raw).context("decision resume payload must be valid JSON")?;
    ensure!(value.is_object(), "decision resume payload must be an object");
    Ok(raw.to_owned())
}

/// The public contract and its private continuation-side option mapping are
/// deliberately produced together.  No caller gets to choose a public option
/// token, so an arbitrary option identifier cannot become a resolver/Attention
/// side channel.
struct RedactedOptionsContract {
    public_json: String,
    private_option_mappings: Vec<PrivateOptionMapping>,
}

struct PrivateOptionMapping {
    opaque_option_id: String,
    continuation_option_id: String,
}

fn redact_options_contract(raw: &str) -> Result<RedactedOptionsContract> {
    let raw: serde_json::Value =
        serde_json::from_str(raw).context("decision options contract must be valid JSON")?;
    // One ingress object means one codec.  There is no bare-array legacy
    // representation in the prerelease durable boundary: callers must name
    // `options`, and the codec owns every persisted public marker.
    let mut object = raw
        .as_object()
        .cloned()
        .context("decision options contract must be a JSON object")?;
    ensure!(
        object.keys().all(|key| {
            matches!(
                key.as_str(),
                "options" | "question" | "description" | "task_call_id" | "workspace_ref"
                    | "interrupt_response_contract"
            )
        }) && object.contains_key("options"),
        "decision options contract contains an unapproved field"
    );
    let values = object
        .remove("options")
        .and_then(|value| value.as_array().cloned())
        .context("decision options contract options must be a JSON array")?;
    // `question`, `description`, and option labels are private
    // continuation/UI material. They are accepted only at trusted ingress,
    // then discarded at the one durable Attention boundary. A keyword
    // deny-list is not a redaction system: arbitrary model text must never
    // become a resolver or daemon-wire projection.
    if let Some(question) = object.remove("question") {
        ensure!(question.is_string(), "decision question must be a string");
    }
    if let Some(description) = object.remove("description") {
        ensure!(description.is_string(), "decision description must be a string");
    }
    if let Some(task_call_id) = object.remove("task_call_id") {
        ensure!(
            task_call_id.is_null() || task_call_id.is_string(),
            "decision task id must be a string"
        );
    }
    if let Some(workspace_ref) = object.remove("workspace_ref") {
        ensure!(
            workspace_ref.is_null() || workspace_ref.is_string(),
            "decision workspace reference must be a string"
        );
    }
    // A generic lifecycle ingress may carry a `null` marker. `null` is not a
    // QuestionTool contract; normalize it as absent before the typed
    // redactor rather than treating key presence alone as the discriminator.
    let interrupt_response_contract = object
        .remove("interrupt_response_contract")
        .filter(|value| !value.is_null());
    ensure!(
        values.len() <= 64,
        "decision options contract has too many options"
    );
    let mut options = Vec::with_capacity(values.len());
    let mut private_option_mappings = Vec::with_capacity(values.len());
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
        if let Some(label) = object.get("label") {
            ensure!(label.is_string(), "decision option label must be a string");
        }
        // Caller-provided option identifiers are continuation material, not
        // public metadata: a model can put arbitrary user text in an
        // otherwise syntactically safe identifier. Mint an unpredictable
        // opaque token for Attention and resolver packets, and retain the
        // original ID only in the private continuation mapping table.
        let opaque_option_id = private_or_new_opaque_option_id(&mut private_option_mappings, id);
        options.push(json!({ "id": opaque_option_id }));
    }
    let unique = options
        .iter()
        .filter_map(|value| value.get("id").and_then(serde_json::Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        unique.len() == options.len(),
        "daemon-minted decision option tokens must be unique"
    );
    ensure!(
        private_option_mappings
            .iter()
            .map(|mapping| mapping.continuation_option_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == private_option_mappings.len(),
        "decision continuation option ids must be unique"
    );
    let interrupt_response_contract = interrupt_response_contract
        .as_ref()
        .map(|raw| redact_interrupt_response_contract(raw, &mut private_option_mappings))
        .transpose()?;
    let public_json = canonical_json_string(&json!({
        "options": options,
        "question": "Decision required",
        "description": "An agent decision is waiting",
        // Task/workspace selectors can be caller-derived even when they have
        // a superficially safe identifier shape. The owner tree already
        // carries host-owned lineage; decision Attention needs no extra
        // caller-controlled metadata.
        "task_call_id": serde_json::Value::Null,
        "workspace_ref": serde_json::Value::Null,
        "interrupt_response_contract": interrupt_response_contract,
        "redacted": true,
    }))?;
    Ok(RedactedOptionsContract {
        public_json,
        private_option_mappings,
    })
}

fn private_or_new_opaque_option_id(
    private_option_mappings: &mut Vec<PrivateOptionMapping>,
    continuation_option_id: &str,
) -> String {
    if let Some(mapping) = private_option_mappings
        .iter()
        .find(|mapping| mapping.continuation_option_id == continuation_option_id)
    {
        return mapping.opaque_option_id.clone();
    }
    let opaque_option_id = format!("option:{}", Uuid::now_v7());
    private_option_mappings.push(PrivateOptionMapping {
        opaque_option_id: opaque_option_id.clone(),
        continuation_option_id: continuation_option_id.to_owned(),
    });
    opaque_option_id
}

/// The only QuestionTool data duplicated into a decision contract. Prompt
/// text, labels, and parked-call context stay in needs_attention; this
/// projection lets a resolver validate a response without receiving them.
fn redact_interrupt_response_contract(
    raw: &serde_json::Value,
    private_option_mappings: &mut Vec<PrivateOptionMapping>,
) -> Result<serde_json::Value> {
    let object = raw
        .as_object()
        .context("QuestionTool continuation contract must be an object")?;
    ensure!(
        object.keys().all(|key| key == "schema" || key == "questions"),
        "QuestionTool continuation contract contains an unapproved field"
    );
    ensure!(
        object.get("schema").and_then(serde_json::Value::as_str)
            == Some("interrupt_question_set_v1"),
        "QuestionTool continuation contract has an unknown schema"
    );
    let questions = object
        .get("questions")
        .and_then(serde_json::Value::as_array)
        .context("QuestionTool continuation questions must be an array")?;
    ensure!(
        !questions.is_empty() && questions.len() <= 16,
        "QuestionTool continuation has an invalid question count"
    );
    let mut redacted_questions = Vec::with_capacity(questions.len());
    for question in questions {
        let question = question
            .as_object()
            .context("QuestionTool continuation question must be an object")?;
        let kind = question
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .context("QuestionTool continuation question is missing kind")?;
        match kind {
            "single" | "multi" => {
                ensure!(
                    question
                        .keys()
                        .all(|key| key == "kind" || key == "option_ids" || key == "allow_freetext"),
                    "QuestionTool choice contract contains an unapproved field"
                );
                let option_ids = question
                    .get("option_ids")
                    .and_then(serde_json::Value::as_array)
                    .context("QuestionTool choice contract is missing option ids")?;
                ensure!(
                    option_ids.len() <= 64,
                    "QuestionTool choice contract has too many options"
                );
                let option_ids = option_ids
                    .iter()
                    .map(|value| {
                        let id = value
                            .as_str()
                            .context("QuestionTool option id must be a string")?;
                        validate_safe_identifier(id, "QuestionTool option id")?;
                        Ok(private_or_new_opaque_option_id(private_option_mappings, id))
                    })
                    .collect::<Result<Vec<_>>>()?;
                ensure!(
                    option_ids.iter().collect::<std::collections::BTreeSet<_>>().len()
                        == option_ids.len(),
                    "QuestionTool option ids must be unique"
                );
                let allow_freetext = question
                    .get("allow_freetext")
                    .and_then(serde_json::Value::as_bool)
                    .context("QuestionTool choice contract is missing allow_freetext")?;
                // Cancel is an interruption outcome, not an answer channel.
                // A durable QuestionTool choice must therefore retain at
                // least one selectable option or explicitly permit bounded
                // free text after restart.
                ensure!(
                    !option_ids.is_empty() || allow_freetext,
                    "QuestionTool choice contract must offer an option or allow free-text"
                );
                redacted_questions.push(json!({
                    "kind": kind,
                    "option_ids": option_ids,
                    "allow_freetext": allow_freetext,
                }));
            }
            "freetext" => {
                ensure!(
                    question.keys().all(|key| key == "kind"),
                    "QuestionTool free-text contract contains an unapproved field"
                );
                redacted_questions.push(json!({ "kind": "freetext" }));
            }
            _ => bail!("QuestionTool continuation question kind is invalid"),
        }
    }
    Ok(json!({
        "schema": "interrupt_question_set_v1",
        "questions": redacted_questions,
    }))
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
    match (allowed, max_chars) {
        (true, Some(1..=10_000)) => {}
        (true, Some(_)) => bail!("free-text contract max_chars must be between 1 and 10000"),
        (true, None) => bail!("allowed free-text contract requires a bounded max_chars"),
        (false, None) => {}
        (false, Some(_)) => bail!("disallowed free-text contract must not carry max_chars"),
    }
    canonical_json_string(&json!({
        "allowed": allowed,
        "max_chars": max_chars,
        "redacted": true,
    }))
}

/// Validate the exact redacted contract stored in `decision_requests`.
/// Creation invokes this before mutation and `load_decision` invokes it again
/// before a row can reach recovery, replay, Attention, or an importer-backed
/// read. That gives persisted data the same answerability invariant as the
/// typed core ingress: a generic decision needs an option or bounded free
/// text, while a QuestionTool owns a separately validated typed response set.
fn validate_durable_decision_answer_contract(
    options_contract_json: &str,
    free_text_contract_json: Option<&str>,
) -> Result<std::collections::BTreeSet<String>> {
    let raw: serde_json::Value = serde_json::from_str(options_contract_json)
        .context("durable decision options contract must be a JSON object")?;
    let contract = raw
        .as_object()
        .context("durable decision options contract must be a JSON object")?;
    const REQUIRED: [&str; 7] = [
        "options",
        "question",
        "description",
        "task_call_id",
        "workspace_ref",
        "interrupt_response_contract",
        "redacted",
    ];
    ensure!(
        contract.len() == REQUIRED.len() && REQUIRED.iter().all(|key| contract.contains_key(*key)),
        "durable decision options contract does not have the exact canonical public shape"
    );
    ensure!(
        contract.get("question").and_then(serde_json::Value::as_str) == Some("Decision required")
            && contract.get("description").and_then(serde_json::Value::as_str)
                == Some("An agent decision is waiting")
            && contract.get("task_call_id") == Some(&serde_json::Value::Null)
            && contract.get("workspace_ref") == Some(&serde_json::Value::Null)
            && contract.get("redacted").and_then(serde_json::Value::as_bool) == Some(true),
        "durable decision options contract is not the canonical redacted projection"
    );
    let options = contract
        .get("options")
        .and_then(serde_json::Value::as_array)
        .context("durable decision options contract is missing its options array")?;
    ensure!(options.len() <= 64, "durable decision options contract has too many options");
    let mut option_ids = std::collections::BTreeSet::new();
    for option in options {
        let option = option
            .as_object()
            .context("durable decision option must be an object")?;
        ensure!(
            option.len() == 1 && option.contains_key("id"),
            "durable decision option does not have the exact canonical public shape"
        );
        let id = option
            .get("id")
            .and_then(serde_json::Value::as_str)
            .context("durable decision option is missing its id")?;
        validate_daemon_minted_public_option_id(id)?;
        ensure!(option_ids.insert(id.to_owned()), "durable decision option ids must be unique");
    }
    let interrupt_response_contract = contract
        .get("interrupt_response_contract")
        .expect("required canonical interrupt response field");
    let question_tool_option_ids = if interrupt_response_contract.is_null() {
        std::collections::BTreeSet::new()
    } else {
        ensure!(
            options.is_empty(),
            "QuestionTool durable contract must not expose generic public options"
        );
        ensure!(
            free_text_contract_json.is_none(),
            "QuestionTool durable contract must not carry a generic free-text contract"
        );
        validate_durable_interrupt_response_contract(interrupt_response_contract)?
    };
    let public_option_ids = if interrupt_response_contract.is_null() {
        let allows_free_text = match free_text_contract_json {
            Some(raw) => validate_durable_free_text_contract(raw)?,
            None => false,
        };
        ensure!(
            !options.is_empty() || allows_free_text,
            "generic decision must offer an option or allow bounded free-text"
        );
        option_ids
    } else {
        question_tool_option_ids
    };
    let canonical = canonical_json_string(&raw)?;
    ensure!(
        canonical == options_contract_json,
        "durable decision options contract is not canonically encoded"
    );
    Ok(public_option_ids)
}

/// Returns whether a fully validated redacted decision contract carries the
/// distinct QuestionTool answer shape.  The companion Attention row is the
/// only durable proof of the real parked QuestionTool continuation, so both
/// creation and loading require this discriminator to agree with that row.
fn durable_decision_has_question_tool_contract(options_contract_json: &str) -> Result<bool> {
    let contract: serde_json::Value = serde_json::from_str(options_contract_json)
        .context("durable decision options contract must be JSON")?;
    Ok(contract
        .get("interrupt_response_contract")
        .is_some_and(|value| !value.is_null()))
}

/// Prove that a redacted QuestionTool contract is the exact response-shaped
/// projection of its real `needs_attention` row.  Prompt text and labels do
/// not cross the decision boundary, but question kind, offered option IDs,
/// free-text permission, cancellation behavior, and the private/public token
/// correspondence are all continuation authority and must survive reload.
fn validate_question_tool_contract_matches_interrupt<'a>(
    options_contract_json: &str,
    mappings: impl IntoIterator<Item = (&'a str, &'a str)>,
    question_json: Option<&str>,
    questions_json: Option<&str>,
) -> Result<()> {
    ensure!(
        question_json.is_some() ^ questions_json.is_some(),
        "QuestionTool decision must bind exactly one real interrupt question shape"
    );
    let contract: serde_json::Value = serde_json::from_str(options_contract_json)
        .context("decoding durable QuestionTool decision contract")?;
    let expected = contract
        .get("interrupt_response_contract")
        .filter(|value| !value.is_null())
        .context("QuestionTool decision is missing its typed response contract")?;
    let mappings = mappings.into_iter().collect::<Vec<_>>();
    let questions = match (question_json, questions_json) {
        (Some(raw), None) => vec![
            serde_json::from_str::<InterruptQuestion>(raw)
                .context("QuestionTool interrupt question is malformed")?,
        ],
        (None, Some(raw)) => serde_json::from_str::<InterruptQuestionSet>(raw)
            .context("QuestionTool interrupt question set is malformed")?
            .questions,
        (None, None) | (Some(_), Some(_)) => unreachable!("exclusive shape was validated"),
    };
    ensure!(
        !questions.is_empty() && questions.len() <= 16,
        "QuestionTool interrupt has an invalid question count"
    );
    let mut projected = Vec::with_capacity(questions.len());
    for question in questions {
        match question {
            InterruptQuestion::Single {
                options,
                allow_freetext,
                ..
            } => {
                let option_ids = project_question_tool_option_ids(&options, &mappings)?;
                ensure!(
                    !option_ids.is_empty() || allow_freetext,
                    "QuestionTool interrupt cannot make cancellation its only answer path"
                );
                projected.push(json!({
                    "kind": "single",
                    "option_ids": option_ids,
                    "allow_freetext": allow_freetext,
                }));
            }
            InterruptQuestion::Multi {
                options,
                allow_freetext,
                ..
            } => {
                let option_ids = project_question_tool_option_ids(&options, &mappings)?;
                ensure!(
                    !option_ids.is_empty() || allow_freetext,
                    "QuestionTool interrupt cannot make cancellation its only answer path"
                );
                projected.push(json!({
                    "kind": "multi",
                    "option_ids": option_ids,
                    "allow_freetext": allow_freetext,
                }));
            }
            InterruptQuestion::Freetext { .. } => {
                projected.push(json!({"kind": "freetext"}));
            }
        }
    }
    let actual = json!({
        "schema": "interrupt_question_set_v1",
        "questions": projected,
    });
    ensure!(
        canonical_json_string(expected)? == canonical_json_string(&actual)?,
        "QuestionTool durable response contract does not exactly match its real interrupt"
    );
    Ok(())
}

fn project_question_tool_option_ids(
    options: &[crate::db::wire::InterruptOption],
    mappings: &[(&str, &str)],
) -> Result<Vec<String>> {
    ensure!(
        options.len() <= 64,
        "QuestionTool interrupt has too many options"
    );
    let mut option_ids = Vec::with_capacity(options.len());
    let mut seen = std::collections::BTreeSet::new();
    for option in options {
        ensure!(
            seen.insert(option.id.as_str()),
            "QuestionTool interrupt option ids must be unique"
        );
        let mapped = mappings
            .iter()
            .filter(|(_, continuation_option_id)| *continuation_option_id == option.id.as_str())
            .map(|(opaque_option_id, _)| *opaque_option_id)
            .collect::<Vec<_>>();
        ensure!(
            mapped.len() == 1,
            "QuestionTool interrupt option lacks its exact private/public decision mapping"
        );
        option_ids.push(mapped[0].to_owned());
    }
    Ok(option_ids)
}

/// Approval metadata is authority owned by the real QuestionTool interrupt,
/// not a decoration a generic AgentTree decision may borrow.  The redacted
/// contract deliberately omits these raw host facts; this DB boundary keeps
/// them attached to the final-operation path without projecting them to
/// Attention or utility resolvers.
fn validate_raw_interrupt_approval_binding(
    decision_class: &str,
    host_approval_operation_id: Option<Uuid>,
    question_json: Option<&str>,
    questions_json: Option<&str>,
) -> Result<()> {
    ensure!(
        question_json.is_some() ^ questions_json.is_some(),
        "QuestionTool approval binding requires exactly one raw question shape"
    );
    let questions = match (question_json, questions_json) {
        (Some(raw), None) => vec![
            serde_json::from_str::<InterruptQuestion>(raw)
                .context("QuestionTool approval interrupt question is malformed")?,
        ],
        (None, Some(raw)) => serde_json::from_str::<InterruptQuestionSet>(raw)
            .context("QuestionTool approval interrupt question set is malformed")?
            .questions,
        (None, None) | (Some(_), Some(_)) => unreachable!("exclusive shape was validated"),
    };
    let approval_questions = questions
        .iter()
        .filter_map(|question| match question {
            InterruptQuestion::Single {
                permission,
                approval_class,
                sandbox_escalation,
                allow_freetext,
                options,
                ..
            } if *permission || approval_class.is_some() || sandbox_escalation.is_some() => {
                Some((allow_freetext, options))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if approval_questions.is_empty() {
        ensure!(
            decision_class != "host_approval" && host_approval_operation_id.is_none(),
            "host approval decision must bind a raw approval-shaped QuestionTool interrupt"
        );
        return Ok(());
    }
    ensure!(
        decision_class == "host_approval" && host_approval_operation_id.is_some(),
        "raw approval-shaped QuestionTool interrupt may bind only a host approval final operation"
    );
    ensure!(
        approval_questions.len() == 1 && questions.len() == 1,
        "host approval interrupt must contain exactly one approval-shaped question"
    );
    let (allow_freetext, options) = approval_questions[0];
    ensure!(
        !*allow_freetext && !options.is_empty(),
        "host approval interrupt must offer a nonempty non-free-text choice"
    );
    Ok(())
}

/// A host-approval decision can be recovered only when the exact final
/// operation row still names this decision and its owning session/agent. The
/// creation transaction establishes this edge; this load boundary makes an
/// imported or corrupted row fail closed before recovery can issue a resume
/// or effect handoff.
fn validate_persisted_host_approval_operation_binding(
    conn: &Connection,
    decision: &DecisionRequestRow,
    has_question_tool_contract: bool,
) -> Result<()> {
    match (decision.decision_class.as_str(), decision.host_approval_operation_id) {
        ("host_approval", Some(operation_id)) => {
            ensure!(
                has_question_tool_contract,
                "persisted host approval must bind a real QuestionTool interrupt"
            );
            ensure!(
                !operation_id.is_nil(),
                "persisted host approval operation id must not be nil"
            );
            let exact_binding: i64 = conn.query_row(
                "SELECT EXISTS (
                     SELECT 1
                       FROM agent_host_approval_operations
                      WHERE operation_id = ?1
                        AND decision_request_id = ?2
                        AND session_id = ?3
                        AND agent_instance_id = ?4
                 )",
                params![
                    operation_id.to_string(),
                    decision.decision_request_id.to_string(),
                    decision.session_id.to_string(),
                    decision.agent_instance_id.to_string(),
                ],
                |row| row.get(0),
            )?;
            ensure!(
                exact_binding != 0,
                "persisted host approval final operation is not bound to its exact decision owner"
            );
        }
        ("host_approval", None) => {
            bail!("persisted host approval is missing its final operation binding")
        }
        (_, Some(_)) => bail!("only persisted host approvals may bind a final operation"),
        (_, None) => {}
    }
    Ok(())
}

fn validate_durable_free_text_contract(raw: &str) -> Result<bool> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .context("durable free-text contract must be a JSON object")?;
    let object = value
        .as_object()
        .context("durable free-text contract must be a JSON object")?;
    const REQUIRED: [&str; 3] = ["allowed", "max_chars", "redacted"];
    ensure!(
        object.len() == REQUIRED.len() && REQUIRED.iter().all(|key| object.contains_key(*key)),
        "durable free-text contract does not have the exact canonical public shape"
    );
    ensure!(
        object.get("redacted").and_then(serde_json::Value::as_bool) == Some(true),
        "durable free-text contract is not a redacted projection"
    );
    let allowed = object
        .get("allowed")
        .and_then(serde_json::Value::as_bool)
        .context("durable free-text contract is missing allowed")?;
    let max_chars = object
        .get("max_chars")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_u64()
                .context("durable free-text contract max_chars must be an unsigned integer")
        })
        .transpose()?;
    let allows_free_text = match (allowed, max_chars) {
        (true, Some(1..=10_000)) => true,
        (true, Some(_)) => bail!("durable free-text contract max_chars must be between 1 and 10000"),
        (true, None) => bail!("durable allowed free-text contract requires a bounded max_chars"),
        (false, None) => false,
        (false, Some(_)) => bail!("durable disallowed free-text contract must not carry max_chars"),
    };
    ensure!(
        canonical_json_string(&value)? == raw,
        "durable free-text contract is not canonically encoded"
    );
    Ok(allows_free_text)
}

fn validate_durable_interrupt_response_contract(
    raw: &serde_json::Value,
) -> Result<std::collections::BTreeSet<String>> {
    let object = raw
        .as_object()
        .context("durable QuestionTool continuation contract must be an object")?;
    ensure!(
        object.len() == 2 && object.contains_key("schema") && object.contains_key("questions"),
        "durable QuestionTool continuation contract does not have the exact canonical public shape"
    );
    ensure!(
        object.get("schema").and_then(serde_json::Value::as_str)
            == Some("interrupt_question_set_v1"),
        "durable QuestionTool continuation contract has an unknown schema"
    );
    let questions = object
        .get("questions")
        .and_then(serde_json::Value::as_array)
        .context("durable QuestionTool continuation questions must be an array")?;
    ensure!(
        !questions.is_empty() && questions.len() <= 16,
        "durable QuestionTool continuation has an invalid question count"
    );
    let mut public_option_ids = std::collections::BTreeSet::new();
    for question in questions {
        let question = question
            .as_object()
            .context("durable QuestionTool continuation question must be an object")?;
        let kind = question
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .context("durable QuestionTool continuation question is missing kind")?;
        match kind {
            "single" | "multi" => {
                ensure!(
                    question.len() == 3
                        && question.contains_key("kind")
                        && question.contains_key("option_ids")
                        && question.contains_key("allow_freetext"),
                    "durable QuestionTool choice contract does not have the exact canonical public shape"
                );
                let option_ids = question
                    .get("option_ids")
                    .and_then(serde_json::Value::as_array)
                    .context("durable QuestionTool choice contract is missing option ids")?;
                ensure!(
                    option_ids.len() <= 64,
                    "durable QuestionTool choice contract has too many options"
                );
                let mut unique = std::collections::BTreeSet::new();
                for option_id in option_ids {
                    let option_id = option_id
                        .as_str()
                        .context("durable QuestionTool option id must be a string")?;
                    validate_daemon_minted_public_option_id(option_id)?;
                    ensure!(
                        unique.insert(option_id),
                        "durable QuestionTool option ids must be unique"
                    );
                    // A multi-question QuestionTool may intentionally reuse
                    // one local choice across questions.  It still has one
                    // exact private mapping; the durable mapping validator
                    // compares the set of public tokens to that table.
                    public_option_ids.insert(option_id.to_owned());
                }
                let allow_freetext = question
                    .get("allow_freetext")
                    .and_then(serde_json::Value::as_bool)
                    .context("durable QuestionTool choice contract is missing allow_freetext")?;
                ensure!(
                    !option_ids.is_empty() || allow_freetext,
                    "QuestionTool choice contract must offer an option or allow free-text"
                );
            }
            "freetext" => ensure!(
                question.len() == 1 && question.contains_key("kind"),
                "durable QuestionTool free-text contract does not have the exact canonical public shape"
            ),
            _ => bail!("durable QuestionTool continuation question kind is invalid"),
        }
    }
    Ok(public_option_ids)
}

fn decision_attention_description(options_contract_json: &str) -> Result<String> {
    let contract: serde_json::Value = serde_json::from_str(options_contract_json)
        .context("decoding redacted decision contract for attention description")?;
    let description = contract
        .get("description")
        .and_then(serde_json::Value::as_str)
        .filter(|description| !description.is_empty())
        .unwrap_or("agent decision pending");
    validate_bounded_display(description, "decision attention description", 500, true)?;
    Ok(description.to_owned())
}

fn redact_recommendation(
    raw: &str,
    private_option_mappings: &[PrivateOptionMapping],
    decision_class: &str,
    expected_rationale_redaction_class: &str,
) -> Result<String> {
    let object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(raw).context("decision recommendation must be a JSON object")?;
    ensure!(
        object
            .keys()
            .all(|key| {
                key == "option_id"
                    || key == "rationale"
                    || key == "rationale_redaction_class"
                    || key == "host_action"
            }),
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
    let option_id = option_id
        .map(|option_id| {
            validate_safe_identifier(option_id, "decision recommendation option_id")?;
            private_option_mappings
                .iter()
                .find(|mapping| mapping.continuation_option_id == option_id)
                .map(|mapping| mapping.opaque_option_id.clone())
                .context("decision recommendation must name an offered option")
        })
        .transpose()?;
    let rationale_is_redacted = object
        .get("rationale")
        .map(|value| value.as_str() == Some("redacted"))
        .unwrap_or(false);
    let supplied_rationale_redaction_class = object
        .get("rationale_redaction_class")
        .map(|value| value.as_str().context("decision rationale class must be a string"))
        .transpose()?;
    if let Some(class) = supplied_rationale_redaction_class {
        validate_redaction_class(class)?;
        ensure!(
            class == expected_rationale_redaction_class,
            "decision recommendation rationale class must match its durable decision"
        );
    }
    let host_action = object
        .get("host_action")
        .map(|value| value.as_str().context("host-owned recommendation action must be a string"))
        .transpose()?;
    if let Some(host_action) = host_action {
        // The contract exposes exactly one host-authored, non-sensitive
        // semantic. It is sufficient to distinguish the safe local refresh
        // from cancellation while neither a prompt label nor an opaque private
        // continuation id becomes visible to a resolver.
        ensure!(
            decision_class == "low_risk"
                && host_action == "refresh_local_host_capabilities"
                && option_id.is_some(),
            "host-owned recommendation action is not valid for this durable decision"
        );
    }
    canonical_json_string(&json!({
        "option_id": option_id,
        "host_action": host_action,
        "rationale": rationale_is_redacted.then_some("redacted"),
        "rationale_redaction_class": expected_rationale_redaction_class,
        "redacted": true,
    }))
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

/// Validate the canonical public recommendation against both sides of the
/// durable decision boundary.  A syntactically-safe option token is not
/// enough: it must be offered by this contract *and* have one exact private
/// continuation mapping for this decision/session.
fn validate_durable_recommendation<'a>(
    raw: &str,
    decision_class: &str,
    expected_rationale_redaction_class: &str,
    public_option_ids: &std::collections::BTreeSet<String>,
    mappings: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .context("durable decision recommendation must be a JSON object")?;
    let object = value
        .as_object()
        .context("durable decision recommendation must be a JSON object")?;
    const REQUIRED: [&str; 5] = [
        "option_id",
        "host_action",
        "rationale",
        "rationale_redaction_class",
        "redacted",
    ];
    ensure!(
        object.len() == REQUIRED.len() && REQUIRED.iter().all(|key| object.contains_key(*key)),
        "durable decision recommendation does not have the exact canonical public shape"
    );
    ensure!(
        object.get("redacted").and_then(serde_json::Value::as_bool) == Some(true),
        "durable decision recommendation is not a redacted projection"
    );
    let option_id = object
        .get("option_id")
        .and_then(serde_json::Value::as_str)
        .context("durable decision recommendation must name an offered option")?;
    validate_daemon_minted_public_option_id(option_id)?;
    ensure!(
        public_option_ids.contains(option_id),
        "durable decision recommendation option is not offered by this contract"
    );
    let mappings = mappings.into_iter().collect::<Vec<_>>();
    let mapped = mappings
        .iter()
        .filter(|(opaque_option_id, _)| *opaque_option_id == option_id)
        .count();
    ensure!(
        mapped == 1,
        "durable decision recommendation option lacks its exact private continuation mapping"
    );
    let rationale = object.get("rationale").expect("required canonical rationale field");
    ensure!(
        rationale.is_null() || rationale.as_str() == Some("redacted"),
        "durable decision recommendation rationale is not redacted"
    );
    let rationale_redaction_class = object
        .get("rationale_redaction_class")
        .and_then(serde_json::Value::as_str)
        .context("durable decision recommendation rationale class must be a string")?;
    validate_redaction_class(rationale_redaction_class)?;
    ensure!(
        rationale_redaction_class == expected_rationale_redaction_class,
        "durable decision recommendation rationale class does not match its decision"
    );
    let host_action = object.get("host_action").expect("required canonical host action field");
    match (decision_class, host_action) {
        ("low_risk", serde_json::Value::String(action))
            if action == "refresh_local_host_capabilities" => {}
        ("low_risk", _) => bail!(
            "low-risk durable recommendation must carry the approved host action semantics"
        ),
        (_, serde_json::Value::Null) => {}
        _ => bail!("durable recommendation carries an unapproved host action semantic"),
    }
    ensure!(
        canonical_json_string(&value)? == raw,
        "durable decision recommendation is not canonically encoded"
    );
    Ok(())
}

fn validate_daemon_minted_public_option_id(value: &str) -> Result<()> {
    let Some(uuid_text) = value.strip_prefix("option:") else {
        bail!("durable public option id is not daemon-minted");
    };
    let uuid = Uuid::parse_str(uuid_text).context("durable public option id has an invalid UUID")?;
    ensure!(
        !uuid.is_nil()
            && uuid.get_version_num() == 7
            && uuid.get_variant() == uuid::Variant::RFC4122
            && uuid.to_string() == uuid_text,
        "durable public option id is not a canonical UUIDv7 token"
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

fn validate_bounded_display(value: &str, field: &str, max_chars: usize, required: bool) -> Result<()> {
    let lower = value.to_ascii_lowercase();
    ensure!(
        (!required || !value.trim().is_empty())
            && value.chars().count() <= max_chars
            && !value.contains('\0')
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
        "{field} is not safely bounded"
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

fn sha256_hex(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

const MAX_RECURSIVE_NONINTERACTIVE_DESCRIPTOR_BYTES: usize = 4 * 1024 * 1024;

fn canonical_recursive_noninteractive_json(raw: &str, kind: &str) -> Result<Value> {
    ensure!(
        !raw.trim().is_empty() && raw.len() <= MAX_RECURSIVE_NONINTERACTIVE_DESCRIPTOR_BYTES,
        "recursive noninteractive {kind} is empty or exceeds its byte limit"
    );
    let value: Value = serde_json::from_str(raw)
        .with_context(|| format!("recursive noninteractive {kind} is not JSON"))?;
    ensure!(
        value.is_object(),
        "recursive noninteractive {kind} must be a JSON object"
    );
    Ok(value)
}

fn canonical_recursive_noninteractive_json_string(value: &Value, kind: &str) -> Result<String> {
    String::from_utf8(canonical_json_bytes(value)?)
        .with_context(|| format!("canonical recursive noninteractive {kind} is not UTF-8"))
}

fn required_recursive_noninteractive_string<'a>(
    value: &'a Value,
    field: &str,
    kind: &str,
) -> Result<&'a str> {
    let raw = value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("recursive noninteractive {kind} has no string `{field}`"))?;
    ensure!(
        !raw.trim().is_empty() && raw.len() <= 16 * 1024,
        "recursive noninteractive {kind} `{field}` is empty or too large"
    );
    Ok(raw)
}

fn validate_recursive_noninteractive_launch_json(raw: &str) -> Result<String> {
    let value = canonical_recursive_noninteractive_json(raw, "launch descriptor")?;
    ensure!(
        value.get("version").and_then(Value::as_u64) == Some(2),
        "recursive noninteractive launch descriptor version is unsupported"
    );
    for field in ["task_call_id", "label", "child_agent", "cwd"] {
        required_recursive_noninteractive_string(&value, field, "launch descriptor")?;
    }
    // A null model is the canonical representation of an intentionally
    // inherited delegation model. A non-null model must still be a structured
    // selector; accepting scalars here would let malformed persisted launch
    // records reach the child lifecycle before recovery rejects them.
    let model = value
        .get("model")
        .context("recursive noninteractive launch descriptor has no model snapshot")?;
    ensure!(
        model.is_null() || model.is_object(),
        "recursive noninteractive launch descriptor model is not a structured selector"
    );
    let granted_tools = value
        .get("granted_tools")
        .and_then(Value::as_array)
        .context("recursive noninteractive launch descriptor has no granted-tools snapshot")?;
    ensure!(
        granted_tools.len() <= 4_096,
        "recursive noninteractive launch descriptor has too many granted tools"
    );
    for tool in granted_tools {
        let tool = tool
            .as_str()
            .context("recursive noninteractive launch descriptor granted tool is not a string")?;
        ensure!(
            !tool.trim().is_empty() && tool.len() <= 1024,
            "recursive noninteractive launch descriptor has an invalid granted tool"
        );
    }
    if let Some(write_scope) = value.get("write_scope") {
        ensure!(
            write_scope.is_null()
                || write_scope
                    .as_str()
                    .is_some_and(|scope| !scope.trim().is_empty() && scope.len() <= 16 * 1024),
            "recursive noninteractive launch descriptor has an invalid write scope"
        );
    }
    if let Some(depends_on) = value.get("depends_on") {
        let depends_on = depends_on
            .as_array()
            .context("recursive noninteractive launch descriptor dependencies are not an array")?;
        ensure!(
            depends_on.len() <= 4_096,
            "recursive noninteractive launch descriptor has too many dependencies"
        );
        for dependency in depends_on {
            let dependency = dependency
                .as_str()
                .context("recursive noninteractive launch descriptor dependency is not a string")?;
            ensure!(
                !dependency.trim().is_empty() && dependency.len() <= 16 * 1024,
                "recursive noninteractive launch descriptor has an invalid dependency"
            );
        }
    }
    canonical_recursive_noninteractive_json_string(&value, "launch descriptor")
}

fn validate_recursive_noninteractive_snapshot_json(raw: &str) -> Result<String> {
    let value = canonical_recursive_noninteractive_json(raw, "continuation snapshot")?;
    ensure!(
        value.get("version").and_then(Value::as_u64) == Some(2),
        "recursive noninteractive continuation snapshot version is unsupported"
    );
    ensure!(
        value.get("history").is_some_and(Value::is_array),
        "recursive noninteractive continuation snapshot has no history array"
    );
    if let Some(next_prompt) = value.get("next_prompt") {
        ensure!(
            next_prompt.is_null() || next_prompt.is_object(),
            "recursive noninteractive continuation snapshot has an invalid next prompt"
        );
    }
    if let Some(pending_recursive) = value.get("pending_recursive") {
        ensure!(
            pending_recursive.is_null() || pending_recursive.is_object(),
            "recursive noninteractive continuation snapshot has an invalid pending-recursive frame"
        );
    }
    if let Some(continuation_id) = value.get("late_user_steer_continuation_id") {
        ensure!(
            continuation_id.is_null()
                || continuation_id
                    .as_str()
                    .is_some_and(|id| Uuid::parse_str(id).is_ok()),
            "recursive noninteractive continuation snapshot has an invalid late-steer identity"
        );
    }
    canonical_recursive_noninteractive_json_string(&value, "continuation snapshot")
}

fn validate_host_capability_refresh_snapshot_identity(
    generation: u64,
    digest: &str,
) -> Result<()> {
    ensure!(generation >= 1, "host capability refresh snapshot generation must be positive");
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())),
        "host capability refresh snapshot digest is invalid"
    );
    Ok(())
}

/// Canonicalize the result persisted by a host capability probe. Storage does
/// not depend on `cockpit-proto`, but it still validates the generic envelope
/// and exact digest; the daemon composition layer additionally deserializes it
/// as `HostCapabilitySnapshot` before it reaches this API.
fn validate_host_capability_refresh_snapshot_receipt(
    raw_snapshot_json: String,
    generation: u64,
    digest: &str,
) -> Result<String> {
    validate_host_capability_refresh_snapshot_identity(generation, digest)?;
    ensure!(
        raw_snapshot_json.len() <= 4 * 1024 * 1024,
        "host capability refresh snapshot is too large"
    );
    let value: Value = serde_json::from_str(&raw_snapshot_json)
        .context("host capability refresh result snapshot is not JSON")?;
    let canonical = canonical_json_bytes(&value)?;
    let canonical_json = String::from_utf8(canonical.clone())
        .context("canonical host capability refresh snapshot is not UTF-8")?;
    ensure!(
        raw_snapshot_json == canonical_json,
        "host capability refresh snapshot must use canonical JSON"
    );
    let encoded_generation = value
        .get("generation")
        .and_then(Value::as_u64)
        .context("host capability refresh snapshot has no positive generation")?;
    ensure!(
        encoded_generation == generation,
        "host capability refresh snapshot generation does not match its durable reservation"
    );
    ensure!(
        sha256_hex(&canonical) == digest,
        "host capability refresh snapshot digest does not match canonical bytes"
    );
    Ok(canonical_json)
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

fn invalid_persisted_value_with_error(
    field: &'static str,
    error: anyhow::Error,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid persisted {field}: {error:#}"),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // The production marker has no safe constructor. DB-local tests exercise
    // the storage state machine directly, so they use the private test seam
    // rather than weakening the public composition API.
    fn host_capability_refresh_authority() -> HostCapabilityRefreshAuthority {
        HostCapabilityRefreshAuthority(())
    }

    fn host_workspace_ref() -> HostWorkspaceRef {
        HostWorkspaceRef(format!("workspace:v1:{}", "0".repeat(64)))
    }

    #[test]
    fn host_workspace_ref_requires_the_exact_versioned_lowercase_digest() {
        for malformed in [
            "workspace:v1:abc",
            "workspace:v2:0000000000000000000000000000000000000000000000000000000000000000",
            "workspace:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "workspace:v1:000000000000000000000000000000000000000000000000000000000000000g",
            "workspace:v1:00000000000000000000000000000000000000000000000000000000000000000",
        ] {
            // SAFETY: this test deliberately checks the constructor's format
            // validation; it does not grant the value any production use.
            assert!(unsafe { HostWorkspaceRef::from_daemon_derived(malformed.into()) }.is_err());
        }
        assert!(unsafe {
            HostWorkspaceRef::from_daemon_derived(format!("workspace:v1:{}", "a".repeat(64)))
        }
        .is_ok());
    }

    #[tokio::test]
    async fn child_workspace_identity_is_transactionally_inherited_from_its_root() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let root = db
            .ensure_session_root_agent(session.session_id, None, host_workspace_ref(), 1)
            .await
            .unwrap();
        let child = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: Some(root.agent_instance_id),
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                2,
            )
            .await
            .unwrap();
        assert_eq!(child.workspace_ref, root.workspace_ref);

        let rejected = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: Some(root.agent_instance_id),
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: Some(format!("workspace:v1:{}", "b".repeat(64))),
                    auto_answer_enabled: false,
                },
                3,
            )
            .await
            .unwrap_err();
        assert!(rejected
            .to_string()
            .contains("inherit its exact parent workspace reference"));
    }

    #[test]
    fn recursive_executor_descriptors_are_versioned_canonical_and_fail_closed() {
        let launch = ValidatedRecursiveNoninteractiveLaunch::parse_and_canonicalize(
            r#"{"write_scope":null,"cwd":"/workspace","granted_tools":[],"model":{},"child_agent":"child","label":"label","task_call_id":"task","version":2}"#,
        )
        .unwrap();
        assert_eq!(
            launch.as_json(),
            r#"{"child_agent":"child","cwd":"/workspace","granted_tools":[],"label":"label","model":{},"task_call_id":"task","version":2,"write_scope":null}"#
        );
        assert!(ValidatedRecursiveNoninteractiveLaunch::parse_and_canonicalize(
            r#"{"version":1,"task_call_id":"task","label":"label","child_agent":"child","model":{},"granted_tools":[],"cwd":"/workspace"}"#,
        )
        .is_err());
        assert!(ValidatedRecursiveNoninteractiveSnapshot::parse_and_canonicalize(
            r#"{"version":3,"history":[]}"#,
        )
        .is_err());
        assert!(ValidatedRecursiveNoninteractiveSnapshot::parse_and_canonicalize("not-json")
            .is_err());
    }

    #[tokio::test]
    async fn stale_or_malformed_recursive_descriptors_fail_before_a_child_reaches_running() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let root = running_agent(&db, session.session_id, 10).await;
        let parent = db
            .create_recursive_noninteractive_child_agent(
                session.session_id,
                root.agent_instance_id,
                Uuid::new_v4(),
                11,
            )
            .await
            .unwrap();
        let valid_launch = ValidatedRecursiveNoninteractiveLaunch::parse_and_canonicalize(
            r#"{"version":2,"task_call_id":"parent","label":"parent","child_agent":"agent","model":{},"granted_tools":[],"cwd":"/workspace"}"#,
        )
        .unwrap();
        let valid_snapshot = ValidatedRecursiveNoninteractiveSnapshot::parse_and_canonicalize(
            r#"{"version":2,"history":[],"next_prompt":null,"pending_recursive":null}"#,
        )
        .unwrap();
        db.insert_recursive_noninteractive_executor(
            session.session_id,
            parent.agent_instance_id,
            root.agent_instance_id,
            valid_launch.clone(),
            valid_snapshot.clone(),
            12,
        )
        .await
        .unwrap();

        let child_id = Uuid::new_v4();
        assert!(ValidatedRecursiveNoninteractiveLaunch::parse_and_canonicalize(
            r#"{"version":1,"task_call_id":"child","label":"child","child_agent":"agent","model":{},"granted_tools":[],"cwd":"/workspace"}"#,
        )
        .is_err());
        assert!(ValidatedRecursiveNoninteractiveSnapshot::parse_and_canonicalize("not-json")
            .is_err());
        assert!(
            db.agent_instance(session.session_id, child_id)
                .await
                .unwrap()
                .is_none(),
            "typed descriptor construction fails before the creation transaction can publish a running child"
        );

        let created = db
            .create_recursive_noninteractive_executors_and_checkpoint_parent(
                session.session_id,
                parent.agent_instance_id,
                valid_snapshot.clone(),
                vec![NewRecursiveNoninteractiveExecutor {
                    agent_instance_id: child_id,
                    recovery_anchor: Uuid::new_v4(),
                    launch: valid_launch,
                    snapshot: valid_snapshot,
                }],
                13,
            )
            .await
            .unwrap();
        assert_eq!(created[0].state, AgentInstanceState::Running);
    }

    #[tokio::test]
    async fn agent_tree_event_backlog_is_read_in_bounded_ordered_pages() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        for offset in 0..4 {
            let _ = running_agent(&db, session.session_id, 10 + offset * 10).await;
        }

        let mut after = 0;
        let mut observed = Vec::new();
        loop {
            let page = db
                .agent_tree_events_after(session.session_id, after, 2)
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            assert!(page.len() <= 2, "each maintenance turn has a fixed event budget");
            after = page.last().expect("nonempty event page").session_event_seq;
            observed.extend(page.into_iter().map(|event| event.session_event_seq));
        }
        assert!(observed.len() >= 8, "the fixture creates a multi-page event backlog");
        assert!(
            observed.windows(2).all(|pair| pair[0] < pair[1]),
            "the durable event cursor is stable and never skips or reorders backlog entries"
        );
    }

    #[tokio::test]
    async fn recoverable_decision_backlog_uses_keyset_pages_without_skips() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let mut expected = Vec::new();
        for offset in 0..5 {
            let agent = running_agent(&db, session.session_id, 10 + offset).await;
            let decision = db
                .create_decision_request(
                    standard_decision(
                        session.session_id,
                        agent.agent_instance_id,
                        agent.revision,
                    ),
                    100,
                )
                .await
                .unwrap();
            expected.push((decision.created_at_unix_ms, decision.decision_request_id));
        }
        expected.sort_unstable();

        let mut after = None;
        let mut observed = Vec::new();
        loop {
            let page = db
                .recoverable_decision_requests_page(session.session_id, after.clone(), 2)
                .await
                .unwrap();
            assert!(page.entries.len() <= 2, "one DB maintenance query is bounded");
            observed.extend(
                page
                    .entries
                    .iter()
                    .map(|decision| (decision.created_at_unix_ms, decision.decision_request_id)),
            );
            let Some(cursor) = page.next_cursor else {
                break;
            };
            after = Some(cursor);
        }
        assert_eq!(
            observed, expected,
            "the ordered timestamp/UUID keyset cursor visits an equal-timestamp backlog once without skipping"
        );
    }

    #[tokio::test]
    async fn allowed_refresh_backlog_uses_keyset_pages_without_skips() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let mut expected = Vec::new();
        for _ in 0..5 {
            let agent = running_agent(&db, session.session_id, 10).await;
            let operation =
                allowed_host_capability_refresh(&db, session.session_id, &agent, 20).await;
            expected.push(operation);
        }

        let mut after = None;
        let mut observed = Vec::new();
        loop {
            let page = db
                .ready_host_capability_refresh_operations_page(
                    host_capability_refresh_authority(),
                    session.session_id,
                    after.clone(),
                    2,
                )
                .await
                .unwrap();
            assert!(page.entries.len() <= 2, "one allowed-refresh scan is bounded");
            observed.extend(page.entries.iter().map(|operation| operation.operation_id));
            let Some(cursor) = page.next_cursor else {
                break;
            };
            after = Some(cursor);
        }
        expected.sort_unstable();
        assert_eq!(
            observed, expected,
            "the created-at/operation-id keyset cursor visits every equal-timestamp allowed operation once"
        );
    }

    #[tokio::test]
    async fn completed_refresh_outbox_backlog_uses_keyset_pages_without_skips() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let mut operations = Vec::new();
        for _ in 0..5 {
            let agent = running_agent(&db, session.session_id, 10).await;
            operations.push((
                allowed_host_capability_refresh(&db, session.session_id, &agent, 20).await,
                agent.agent_instance_id,
            ));
        }
        let session_id = session.session_id.to_string();
        db.transaction(move |conn| {
            for (index, (operation_id, agent_instance_id)) in operations.iter().enumerate() {
                let generation = i64::try_from(index + 1).expect("test generation fits i64");
                let completed_at = 100 + generation;
                let (receipt_json, receipt_digest) =
                    test_host_capability_receipt(u64::try_from(generation).unwrap());
                conn.execute(
                    "UPDATE host_capability_refresh_operations
                        SET state = 'executing', execution_agent_revision = 1,
                            execution_epoch = 1, execution_lease_owner_token = ?1,
                            execution_lease_expires_at_unix_ms = 1000,
                            reserved_snapshot_generation = ?2,
                            updated_at_unix_ms = ?3
                      WHERE operation_id = ?4 AND session_id = ?5
                        AND agent_instance_id = ?6 AND state = 'allowed'",
                    params![
                        Uuid::new_v4().to_string(),
                        generation,
                        completed_at - 1,
                        operation_id.to_string(),
                        session_id,
                        agent_instance_id.to_string(),
                    ],
                )?;
                conn.execute(
                    "UPDATE host_capability_refresh_operations
                        SET state = 'completed', result_snapshot_json = ?1,
                            result_snapshot_generation = ?2,
                            result_snapshot_digest = ?3,
                            updated_at_unix_ms = ?4, completed_at_unix_ms = ?4
                      WHERE operation_id = ?5 AND session_id = ?6 AND state = 'executing'",
                    params![
                        receipt_json,
                        generation,
                        receipt_digest,
                        completed_at,
                        operation_id.to_string(),
                        session_id,
                    ],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();

        let mut after = None;
        let mut observed = Vec::new();
        loop {
            let page = db
                .completed_unpublished_host_capability_refresh_operations_page(
                    host_capability_refresh_authority(),
                    after.clone(),
                    2,
                )
                .await
                .unwrap();
            assert!(page.entries.len() <= 2, "one outbox scan is bounded");
            observed.extend(
                page.entries.into_iter().map(|operation| {
                    (
                        operation.result_snapshot_generation.unwrap(),
                        operation.completed_at_unix_ms.unwrap(),
                        operation.operation_id,
                    )
                }),
            );
            let Some(cursor) = page.next_cursor else {
                break;
            };
            after = Some(cursor);
        }
        assert_eq!(
            observed.iter().map(|(generation, _, _)| *generation).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5],
            "the generation/timestamp/operation-id cursor cannot skip a large completed outbox"
        );
    }

    #[test]
    fn concrete_effect_fence_matches_only_the_selected_candidate_effect() {
        let selected = json!({
            "selection": "approve_once",
            "execute": {"command": "safe-command"},
        });
        assert!(host_operation_candidate_matches_any_concrete_effect(
            &selected,
            &[json!({"execute": {"command": "safe-command"}})],
        ));
        assert!(!host_operation_candidate_matches_any_concrete_effect(
            &selected,
            &[json!({"execute": {"command": "different-command"}})],
        ));
    }
    use crate::db::task_delegation_payloads::NewTaskDelegationPayload;
    use crate::db::task_delegations::{DelegationChildInit, TaskDelegationJobUpsert};
    use crate::db::wire::{InterruptOption, InterruptQuestion, ResolveResponse};
    #[cfg(feature = "host-capability-refresh-composition")]
    use crate::db::wire::InterruptQuestionSet;

    fn test_host_capability_receipt(generation: u64) -> (String, String) {
        let value = json!({"generation": generation});
        let canonical = canonical_json_bytes(&value).expect("test receipt is canonicalizable");
        let json = String::from_utf8(canonical.clone()).expect("canonical JSON is UTF-8");
        let digest = sha256_hex(&canonical);
        (json, digest)
    }

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
            options_contract_json: r#"{"options":[{"id":"continue","label":"Continue"}]}"#.into(),
            free_text_contract_json: None,
            recommendation_json: Some(r#"{"option_id":"continue"}"#.into()),
            rationale_redaction_class: "public".into(),
            decision_class: "user_question".into(),
            host_approval_operation_id: None,
            deadline_unix_ms: None,
            policy_receipt_json: r#"{"policy":"manual"}"#.into(),
            resolver_route: Some("user".into()),
        }
    }

    fn standard_question_tool_decision(
        session_id: Uuid,
        agent_instance_id: Uuid,
        expected_agent_revision: i64,
        option_id: &str,
    ) -> NewDecisionRequest {
        let mut input = standard_decision(session_id, agent_instance_id, expected_agent_revision);
        input.options_contract_json = serde_json::to_string(&json!({
            "options": [],
            "interrupt_response_contract": {
                "schema": "interrupt_question_set_v1",
                "questions": [{
                    "kind": "single",
                    "option_ids": [option_id],
                    "allow_freetext": false,
                }],
            },
        }))
        .expect("test QuestionTool contract serializes");
        input.recommendation_json = None;
        input
    }

    #[test]
    fn canonical_question_tool_tokens_require_one_exact_private_mapping() {
        let option_id = format!("option:{}", Uuid::now_v7());
        let contract = canonical_json_string(&json!({
            "options": [],
            "question": "Decision required",
            "description": "An agent decision is waiting",
            "task_call_id": null,
            "workspace_ref": null,
            "interrupt_response_contract": {
                "schema": "interrupt_question_set_v1",
                "questions": [{
                    "kind": "single",
                    "option_ids": [option_id.clone()],
                    "allow_freetext": false,
                }],
            },
            "redacted": true,
        }))
        .unwrap();
        let offered = validate_durable_decision_answer_contract(&contract, None).unwrap();
        assert!(validate_durable_private_option_mappings(
            &offered,
            [(option_id.as_str(), "continue")],
        )
        .is_ok());
        assert!(validate_durable_private_option_mappings(
            &offered,
            std::iter::empty::<(&str, &str)>(),
        )
        .is_err());
        assert!(validate_durable_private_option_mappings(
            &offered,
            [(option_id.as_str(), "continue"), (option_id.as_str(), "other")],
        )
        .is_err());
    }

    #[test]
    fn imported_question_tool_contract_must_exactly_match_its_real_interrupt() {
        let opaque = format!("option:{}", Uuid::now_v7());
        let contract = canonical_json_string(&json!({
            "options": [],
            "question": "Decision required",
            "description": "An agent decision is waiting",
            "task_call_id": null,
            "workspace_ref": null,
            "interrupt_response_contract": {
                "schema": "interrupt_question_set_v1",
                "questions": [{
                    "kind": "single",
                    "option_ids": [opaque.clone()],
                    "allow_freetext": false,
                }],
            },
            "redacted": true,
        }))
        .unwrap();
        let mapping = [(opaque.as_str(), "continue")];
        let valid = InterruptQuestion::Single {
            prompt: "Continue?".into(),
            options: vec![InterruptOption {
                id: "continue".into(),
                label: "Continue".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        };
        let valid_json = serde_json::to_string(&valid).unwrap();
        assert!(validate_question_tool_contract_matches_interrupt(
            &contract,
            mapping,
            Some(&valid_json),
            None,
        )
        .is_ok());

        let shape_mismatch = InterruptQuestion::Multi {
            prompt: "Continue?".into(),
            options: vec![InterruptOption {
                id: "continue".into(),
                label: "Continue".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
        };
        let shape_mismatch_json = serde_json::to_string(&shape_mismatch).unwrap();
        assert!(validate_question_tool_contract_matches_interrupt(
            &contract,
            mapping,
            Some(&shape_mismatch_json),
            None,
        )
        .is_err());

        let offered_option_mismatch = InterruptQuestion::Single {
            prompt: "Continue?".into(),
            options: vec![InterruptOption {
                id: "different".into(),
                label: "Different".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        };
        let offered_option_mismatch_json = serde_json::to_string(&offered_option_mismatch).unwrap();
        assert!(validate_question_tool_contract_matches_interrupt(
            &contract,
            mapping,
            Some(&offered_option_mismatch_json),
            None,
        )
        .is_err());

        let freetext_mismatch = InterruptQuestion::Single {
            prompt: "Continue?".into(),
            options: vec![InterruptOption {
                id: "continue".into(),
                label: "Continue".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: true,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        };
        let freetext_mismatch_json = serde_json::to_string(&freetext_mismatch).unwrap();
        assert!(validate_question_tool_contract_matches_interrupt(
            &contract,
            mapping,
            Some(&freetext_mismatch_json),
            None,
        )
        .is_err());
    }

    async fn subject_notice_count(db: &Db, session_id: Uuid, subject_id: Uuid) -> i64 {
        db.read(move |conn| {
            let count = conn.query_row(
                "SELECT COUNT(*) FROM session_events
                 WHERE session_id = ?1 AND type = 'agent_tree'
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
                    workspace_ref: None,
                    auto_answer_enabled: false,
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

    #[cfg(feature = "host-capability-refresh-composition")]
    #[tokio::test]
    async fn boot_terminalizes_a_crash_left_host_refresh_initialization_before_tree_recovery() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let parent = running_agent(&db, session.session_id, 10).await;
        let operation_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let child = db
            .create_host_capability_refresh_initialization(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: Some(parent.agent_instance_id),
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                operation_id,
                request_id,
                host_capability_refresh_authority(),
                20,
            )
            .await
            .unwrap();

        // The production crash window is after QuestionTool has durably
        // raised its interrupt but before the atomic decision/operation bind.
        // Seed that exact unbound interrupt here; recovery must resolve it as
        // well as cancelling the initialization child.
        let raw_interrupt_id = db
            .raise_interrupt_questions_with_agent_instance_and_payload(
                session.session_id,
                "host-capability-refresh",
                Some(child.agent_instance_id),
                "host capability refresh",
                &InterruptQuestionSet {
                    questions: vec![InterruptQuestion::Single {
                        prompt: "Refresh host capabilities?".into(),
                        options: vec![InterruptOption {
                            id: "refresh".into(),
                            label: "Refresh".into(),
                            description: None,
                            secondary: false,
                        }],
                        allow_freetext: false,
                        command_detail: None,
                        permission: false,
                        approval_class: None,
                        sandbox_escalation: None,
                    }],
                },
                None,
            )
            .await
            .unwrap();

        // This is the deterministic crash point: creation and its immutable
        // descriptor committed, while the later real QuestionTool/decision/
        // operation transaction never began.
        assert_eq!(
            db.reconcile_host_capability_refresh_operations(
                host_capability_refresh_authority(),
                session.session_id,
                30,
            )
            .await
            .unwrap(),
            1
        );
        let child = db
            .agent_instance(session.session_id, child.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(child.state, AgentInstanceState::Cancelled);
        db.read(move |conn| {
            let (state, interrupt_id, decision_request_id, completed_at): (
                String,
                Option<String>,
                Option<String>,
                Option<i64>,
            ) = conn.query_row(
                "SELECT state, interrupt_id, decision_request_id, completed_at_unix_ms
                   FROM host_capability_refresh_initializations
                  WHERE operation_id = ?1 AND request_id = ?2
                    AND session_id = ?3 AND agent_instance_id = ?4",
                params![
                    operation_id.to_string(),
                    request_id.to_string(),
                    session.session_id.to_string(),
                    child.agent_instance_id.to_string(),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
            assert_eq!(state, "cancelled");
            assert!(interrupt_id.is_none() && decision_request_id.is_none());
            assert_eq!(completed_at, Some(30));
            let operation_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM host_capability_refresh_operations WHERE operation_id = ?1",
                params![operation_id.to_string()],
                |row| row.get(0),
            )?;
            assert_eq!(operation_count, 0);
            let (state, resolved_at, decision_request_id): (String, Option<i64>, Option<String>) =
                conn.query_row(
                    "SELECT state, resolved_at, decision_request_id
                       FROM needs_attention
                      WHERE interrupt_id = ?1 AND session_id = ?2
                        AND agent_instance_id = ?3",
                    params![
                        raw_interrupt_id.to_string(),
                        session.session_id.to_string(),
                        child.agent_instance_id.to_string(),
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
            assert_eq!(state, "resolved");
            assert_eq!(resolved_at, Some(30));
            assert!(decision_request_id.is_none());
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn startup_rejects_an_imported_split_host_refresh_operation_without_rebinding_it() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 1).await;
        let question = InterruptQuestion::Single {
            prompt: "Refresh?".into(),
            options: vec![InterruptOption {
                id: "refresh".into(),
                label: "Refresh".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        };
        let interrupt_id = db
            .raise_interrupt_with_agent_instance(
                session.session_id,
                "host-capability-refresh",
                Some(agent.agent_instance_id),
                "imported split refresh operation",
                Some(&question),
            )
            .await
            .unwrap();
        let decision = db
            .create_decision_request_for_interrupt(
                standard_question_tool_decision(
                    session.session_id,
                    agent.agent_instance_id,
                    agent.revision,
                    "refresh",
                ),
                interrupt_id,
                2,
            )
            .await
            .unwrap();
        let operation_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let session_id = session.session_id;
        let agent_instance_id = agent.agent_instance_id;
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO host_capability_refresh_operations (
                     operation_id, request_id, session_id, agent_instance_id,
                     interrupt_id, decision_request_id, state,
                     created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, 'pending', 3, 3)",
                params![
                    operation_id.to_string(),
                    request_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    interrupt_id.to_string(),
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let error = db
            .reconcile_host_capability_refresh_operations(
                host_capability_refresh_authority(),
                session_id,
                4,
            )
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("malformed split decision binding"),
            "startup must reject rather than infer a missing operation-to-decision edge"
        );
        db.read(move |conn| {
            let (state, decision_request_id): (String, Option<String>) = conn.query_row(
                "SELECT state, decision_request_id
                   FROM host_capability_refresh_operations
                  WHERE operation_id = ?1 AND request_id = ?2",
                params![operation_id.to_string(), request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(state, "pending");
            assert!(decision_request_id.is_none());
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            db.decision_request(session_id, decision.decision_request_id)
                .await
                .is_ok(),
            "the malformed operation must not rewrite its separately valid decision"
        );
    }

    async fn allowed_host_capability_refresh(
        db: &Db,
        session_id: Uuid,
        agent: &AgentInstanceRow,
        now: i64,
    ) -> Uuid {
        let agent_instance_id = agent.agent_instance_id;
        let question = InterruptQuestion::Single {
            prompt: "Refresh host capability snapshot?".into(),
            options: vec![InterruptOption {
                id: "refresh".into(),
                label: "Refresh".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        };
        let interrupt_id = db
            .raise_interrupt_with_agent_instance(
                session_id,
                "host-capability-refresh",
                Some(agent.agent_instance_id),
                "host capability refresh",
                Some(&question),
            )
            .await
            .unwrap();
        let decision = db
            .create_decision_request_for_interrupt(
                standard_question_tool_decision(
                    session_id,
                    agent.agent_instance_id,
                    agent.revision,
                    "refresh",
                ),
                interrupt_id,
                now + 1,
            )
            .await
            .unwrap();
        // This test-only helper deliberately seeds a terminal-state-machine
        // fixture with raw SQL. Production has no reserve/bind APIs: the
        // only public creation route is the typed authority entrypoint above.
        // The outbox tests below exercise execution/publication semantics,
        // not the separately-tested composition authority.
        let operation_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        db.transaction(move |conn| {
            conn.execute(
                "INSERT INTO host_capability_refresh_operations (
                     operation_id, request_id, session_id, agent_instance_id,
                     interrupt_id, decision_request_id, state,
                     created_at_unix_ms, updated_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?7)",
                params![
                    operation_id.to_string(),
                    request_id.to_string(),
                    session_id.to_string(),
                    agent_instance_id.to_string(),
                    interrupt_id.to_string(),
                    decision.decision_request_id.to_string(),
                    now + 2,
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let resume_payload_json = serde_json::to_string(&json!({
            "answer_kind": "interrupt_response",
            "answer": ResolveResponse::Single {
                selected_id: "refresh".into(),
            },
        }))
        .unwrap();
        assert!(matches!(
            db.resolve_decision_request_with_resume_payload(
                session_id,
                decision.decision_request_id,
                decision.revision,
                DecisionState::Answered,
                "{\"source\":\"test\"}",
                &resume_payload_json,
                now + 3,
            )
            .await
            .unwrap(),
            DecisionTransitionOutcome::Transitioned(_)
        ));
        operation_id
    }

    #[tokio::test]
    async fn host_capability_refresh_operation_state_graph_allows_executing_cancellation_only_as_new_terminal_edge() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 10).await;

        let cancelled =
            allowed_host_capability_refresh(&db, session.session_id, &agent, 20).await;
        let _cancelled_lease = match db
            .claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                cancelled,
                Uuid::new_v4(),
                100,
                40,
            )
            .await
            .unwrap()
        {
            HostCapabilityRefreshExecutionClaim::Claimed { lease } => lease,
            other => panic!("expected executing cancellation fixture, got {other:?}"),
        };
        let session_id = session.session_id;
        assert_eq!(
            db.transaction(move |conn| {
                Ok(conn.execute(
                    "UPDATE host_capability_refresh_operations
                        SET state = 'cancelled',
                            error_text = 'subtree cancellation won after probe began',
                            updated_at_unix_ms = ?1, completed_at_unix_ms = ?1
                      WHERE operation_id = ?2 AND session_id = ?3 AND state = 'executing'",
                    params![41_i64, cancelled.to_string(), session_id.to_string()],
                )?)
            })
            .await
            .unwrap(),
            1,
            "executing -> cancelled is the one cancellation edge needed to fence an in-flight probe"
        );
        assert_eq!(
            db.host_capability_refresh_operation_by_id(
                host_capability_refresh_authority(),
                session.session_id,
                cancelled,
            )
            .await
            .unwrap()
            .expect("cancelled operation remains durable")
            .state,
            HostCapabilityRefreshOperationState::Cancelled
        );
        let cancelled_to_allowed = db
            .transaction(move |conn| {
                conn.execute(
                    "UPDATE host_capability_refresh_operations
                        SET state = 'allowed'
                      WHERE operation_id = ?1 AND session_id = ?2",
                    params![cancelled.to_string(), session_id.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(
            cancelled_to_allowed
                .to_string()
                .contains("state transition is invalid"),
            "cancelled must remain terminal"
        );

        let invalid = allowed_host_capability_refresh(&db, session.session_id, &agent, 50).await;
        let invalid_allowed_to_completed = db
            .transaction(move |conn| {
                conn.execute(
                    "UPDATE host_capability_refresh_operations
                        SET state = 'completed'
                      WHERE operation_id = ?1 AND session_id = ?2",
                    params![invalid.to_string(), session_id.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(
            invalid_allowed_to_completed
                .to_string()
                .contains("state transition is invalid"),
            "the new executing cancellation edge must not open unrelated forward jumps"
        );
        assert!(db
            .cancel_host_capability_refresh_operation(
                host_capability_refresh_authority(),
                session.session_id,
                invalid,
                "clearing invalid-edge fixture".to_string(),
                51,
            )
            .await
            .unwrap());

        let failed = allowed_host_capability_refresh(&db, session.session_id, &agent, 60).await;
        let failed_lease = match db
            .claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                failed,
                Uuid::new_v4(),
                100,
                61,
            )
            .await
            .unwrap()
        {
            HostCapabilityRefreshExecutionClaim::Claimed { lease } => lease,
            other => panic!("expected failed terminal fixture, got {other:?}"),
        };
        assert!(db
            .fail_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                failed,
                &failed_lease,
                "probe failed".to_string(),
                62,
            )
            .await
            .unwrap());
        let failed_to_cancelled = db
            .transaction(move |conn| {
                conn.execute(
                    "UPDATE host_capability_refresh_operations
                        SET state = 'cancelled'
                      WHERE operation_id = ?1 AND session_id = ?2",
                    params![failed.to_string(), session_id.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(
            failed_to_cancelled
                .to_string()
                .contains("state transition is invalid"),
            "failed must remain terminal"
        );

        let completed =
            allowed_host_capability_refresh(&db, session.session_id, &agent, 70).await;
        let completed_lease = match db
            .claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                completed,
                Uuid::new_v4(),
                100,
                71,
            )
            .await
            .unwrap()
        {
            HostCapabilityRefreshExecutionClaim::Claimed { lease } => lease,
            other => panic!("expected completed terminal fixture, got {other:?}"),
        };
        let (receipt_json, receipt_digest) =
            test_host_capability_receipt(completed_lease.snapshot_generation());
        assert!(db
            .complete_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                completed,
                &completed_lease,
                receipt_json,
                completed_lease.snapshot_generation(),
                receipt_digest,
                72,
            )
            .await
            .unwrap());
        let completed_to_failed = db
            .transaction(move |conn| {
                conn.execute(
                    "UPDATE host_capability_refresh_operations
                        SET state = 'failed'
                      WHERE operation_id = ?1 AND session_id = ?2",
                    params![completed.to_string(), session_id.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(
            completed_to_failed
                .to_string()
                .contains("state transition is invalid"),
            "completed must remain terminal"
        );
    }

    #[tokio::test]
    async fn refresh_execution_lease_renewal_keeps_live_probe_past_original_deadline_and_reaps_abandoned_claim() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 10).await;
        let operation_id =
            allowed_host_capability_refresh(&db, session.session_id, &agent, 20).await;
        let owner = Uuid::new_v4();
        let lease = match db
            .claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                operation_id,
                owner,
                100,
                40,
            )
            .await
            .unwrap()
        {
            HostCapabilityRefreshExecutionClaim::Claimed { lease } => lease,
            other => panic!("expected execution claim, got {other:?}"),
        };

        // The probe remains live beyond its original lease by renewing its
        // exact token-fenced claim. A periodic reaper cannot infer staleness
        // from the original claim timestamp.
        assert!(db
            .renew_host_capability_refresh_execution_lease(
                host_capability_refresh_authority(),
                session.session_id,
                operation_id,
                &lease,
                180,
                99,
            )
            .await
            .unwrap());
        assert_eq!(
            db.reap_stale_host_capability_refresh_operations(
                host_capability_refresh_authority(),
                session.session_id,
                120,
            )
                .await
                .unwrap(),
            0,
            "renewed live probe must survive beyond its original 100ms lease"
        );

        // Once the task stops renewing, the same periodic reaper closes the
        // abandoned execution. A stale owner token cannot complete afterward.
        assert_eq!(
            db.reap_stale_host_capability_refresh_operations(
                host_capability_refresh_authority(),
                session.session_id,
                180,
            )
                .await
                .unwrap(),
            1
        );
        assert!(!db
            .renew_host_capability_refresh_execution_lease(
                host_capability_refresh_authority(),
                session.session_id,
                operation_id,
                &lease,
                260,
                181,
            )
            .await
            .unwrap());
        assert!(matches!(
            db.claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                operation_id,
                Uuid::new_v4(),
                260,
                181,
            )
            .await
            .unwrap(),
            HostCapabilityRefreshExecutionClaim::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn boot_fences_global_executing_refresh_claims_before_advancing_generation() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 10).await;
        let operation =
            allowed_host_capability_refresh(&db, session.session_id, &agent, 20).await;
        let claimed_generation = match db
            .claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                operation,
                Uuid::new_v4(),
                10_000,
                40,
            )
            .await
            .unwrap()
        {
            HostCapabilityRefreshExecutionClaim::Claimed { lease } => lease.snapshot_generation(),
            other => panic!("expected global execution claim, got {other:?}"),
        };
        assert!(db
            .has_executing_host_capability_refresh_operations(
                host_capability_refresh_authority(),
            )
            .await
            .unwrap());

        assert_eq!(
            db.reconcile_host_capability_refresh_execution_leases_at_boot(
                host_capability_refresh_authority(),
                41,
            )
                .await
                .unwrap(),
            1,
            "a new daemon process fences even an unexpired previous-process lease"
        );
        assert!(!db
            .has_executing_host_capability_refresh_operations(
                host_capability_refresh_authority(),
            )
            .await
            .unwrap());
        assert_eq!(
            db.reserve_host_capability_boot_snapshot_generation(
                host_capability_refresh_authority(),
            )
                .await
                .unwrap(),
            claimed_generation + 1,
            "boot cannot overtake a global executing claim without first terminalizing it"
        );
        assert!(matches!(
            db.claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                operation,
                Uuid::new_v4(),
                10_001,
                42,
            )
            .await
            .unwrap(),
            HostCapabilityRefreshExecutionClaim::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn refresh_execution_claims_are_durably_serialized_per_session() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 10).await;
        let first = allowed_host_capability_refresh(&db, session.session_id, &agent, 20).await;
        let agent = db
            .agent_instance(session.session_id, agent.agent_instance_id)
            .await
            .unwrap()
            .expect("first terminal decision leaves the same owner runnable");
        let second = allowed_host_capability_refresh(&db, session.session_id, &agent, 30).await;
        let first_owner = Uuid::new_v4();
        match db
            .claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                first,
                first_owner,
                100,
                40,
            )
            .await
            .unwrap()
        {
            HostCapabilityRefreshExecutionClaim::Claimed { .. } => {}
            other => panic!("first allowed refresh must claim, got {other:?}"),
        }
        assert!(matches!(
            db.claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                second,
                Uuid::new_v4(),
                100,
                41,
            )
            .await
            .unwrap(),
            HostCapabilityRefreshExecutionClaim::InFlight,
        ));
        // A restart cannot reverse completion order: the first operation is
        // terminalized by startup reconciliation before the second allowed
        // operation can ever cross its probe boundary.
        assert_eq!(
            db.reconcile_host_capability_refresh_operations(
                host_capability_refresh_authority(),
                session.session_id,
                42,
            )
                .await
                .unwrap(),
            1
        );
        assert!(matches!(
            db.claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                second,
                Uuid::new_v4(),
                110,
                43,
            )
            .await
            .unwrap(),
            HostCapabilityRefreshExecutionClaim::Claimed { .. },
        ));
    }

    #[tokio::test]
    async fn completed_refresh_outbox_blocks_later_execution_until_recovery_acknowledges_it() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 10).await;
        let first = allowed_host_capability_refresh(&db, session.session_id, &agent, 20).await;
        let agent = db
            .agent_instance(session.session_id, agent.agent_instance_id)
            .await
            .unwrap()
            .expect("first terminal decision leaves the same owner runnable");
        let second = allowed_host_capability_refresh(&db, session.session_id, &agent, 30).await;
        let first_lease = match db
            .claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                first,
                Uuid::new_v4(),
                100,
                40,
            )
            .await
            .unwrap()
        {
            HostCapabilityRefreshExecutionClaim::Claimed { lease } => lease,
            other => panic!("first allowed refresh must claim, got {other:?}"),
        };
        let (first_receipt_json, first_receipt_digest) =
            test_host_capability_receipt(first_lease.snapshot_generation());
        assert!(db
            .complete_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                first,
                &first_lease,
                first_receipt_json,
                first_lease.snapshot_generation(),
                first_receipt_digest.clone(),
                41,
            )
            .await
            .unwrap());
        // Simulate a crash after the durable completion receipt but before
        // the process can make its snapshot live and ack the outbox. A newer
        // approved operation must not probe/publish first, or the old receipt
        // would become permanently unpublishable on restart.
        assert!(matches!(
            db.claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                second,
                Uuid::new_v4(),
                100,
                42,
            )
            .await
            .unwrap(),
            HostCapabilityRefreshExecutionClaim::InFlight,
        ));
        assert!(db
            .mark_host_capability_refresh_published(
                host_capability_refresh_authority(),
                session.session_id,
                first,
                first_lease.snapshot_generation(),
                first_receipt_digest,
                43,
            )
            .await
            .unwrap());
        assert!(matches!(
            db.claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                second,
                Uuid::new_v4(),
                110,
                44,
            )
            .await
            .unwrap(),
            HostCapabilityRefreshExecutionClaim::Claimed { .. },
        ));
    }

    #[tokio::test]
    async fn completed_refresh_outbox_blocks_later_execution_across_sessions_until_global_ack() {
        let db = Db::open_in_memory().unwrap();
        let first_session = db.create_session("p", "/workspace-a", "root").await.unwrap();
        let second_session = db.create_session("p", "/workspace-b", "root").await.unwrap();
        let first_agent = running_agent(&db, first_session.session_id, 10).await;
        let second_agent = running_agent(&db, second_session.session_id, 11).await;
        let first =
            allowed_host_capability_refresh(&db, first_session.session_id, &first_agent, 20).await;
        let second =
            allowed_host_capability_refresh(&db, second_session.session_id, &second_agent, 21)
                .await;
        let first_lease = match db
            .claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                first_session.session_id,
                first,
                Uuid::new_v4(),
                100,
                40,
            )
            .await
            .unwrap()
        {
            HostCapabilityRefreshExecutionClaim::Claimed { lease } => lease,
            other => panic!("first global refresh must claim, got {other:?}"),
        };
        let (first_receipt_json, first_receipt_digest) =
            test_host_capability_receipt(first_lease.snapshot_generation());
        assert!(db
            .complete_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                first_session.session_id,
                first,
                &first_lease,
                first_receipt_json,
                first_lease.snapshot_generation(),
                first_receipt_digest.clone(),
                41,
            )
            .await
            .unwrap());

        // A second session shares the same daemon-local snapshot store. It
        // cannot issue generation 2 while session A's durable generation 1
        // receipt still awaits publication after a crash/restart.
        assert!(matches!(
            db.claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                second_session.session_id,
                second,
                Uuid::new_v4(),
                100,
                42,
            )
            .await
            .unwrap(),
            HostCapabilityRefreshExecutionClaim::InFlight,
        ));
        assert!(db
            .mark_host_capability_refresh_published(
                host_capability_refresh_authority(),
                first_session.session_id,
                first,
                first_lease.snapshot_generation(),
                first_receipt_digest,
                43,
            )
            .await
            .unwrap());
        assert!(matches!(
            db.claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                second_session.session_id,
                second,
                Uuid::new_v4(),
                110,
                44,
            )
            .await
            .unwrap(),
            HostCapabilityRefreshExecutionClaim::Claimed { .. },
        ));
    }

    #[tokio::test]
    async fn completed_refresh_receipt_is_immutable_and_publication_ack_is_exact() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 10).await;
        let operation = allowed_host_capability_refresh(&db, session.session_id, &agent, 20).await;
        let lease = match db
            .claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                operation,
                Uuid::new_v4(),
                100,
                40,
            )
            .await
            .unwrap()
        {
            HostCapabilityRefreshExecutionClaim::Claimed { lease } => lease,
            other => panic!("expected exact refresh execution claim, got {other:?}"),
        };
        let (receipt_json, receipt_digest) =
            test_host_capability_receipt(lease.snapshot_generation());
        assert!(db
            .complete_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                operation,
                &lease,
                receipt_json,
                lease.snapshot_generation(),
                receipt_digest.clone(),
                41,
            )
            .await
            .unwrap());

        // This simulates an unsafe raw concurrent writer after the dispatcher
        // has loaded the completed row. The SQL trigger is a second fence;
        // the acknowledgement method independently matches generation/digest.
        let operation_id = operation.to_string();
        let session_id = session.session_id.to_string();
        assert!(db
            .transaction(move |conn| {
                let error = conn
                    .execute(
                        "UPDATE host_capability_refresh_operations
                            SET result_snapshot_json = '{\"generation\":999}'
                          WHERE operation_id = ?1 AND session_id = ?2",
                        params![operation_id, session_id],
                    )
                    .expect_err("completed receipt mutation must be rejected");
                assert!(error.to_string().contains("immutable"));
                Ok(())
            })
            .await
            .is_ok());
        assert!(!db
            .mark_host_capability_refresh_published(
                host_capability_refresh_authority(),
                session.session_id,
                operation,
                lease.snapshot_generation(),
                "0".repeat(64),
                42,
            )
            .await
            .unwrap());
        assert!(db
            .mark_host_capability_refresh_published(
                host_capability_refresh_authority(),
                session.session_id,
                operation,
                lease.snapshot_generation(),
                receipt_digest,
                43,
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn global_refresh_generation_reservations_never_reuse_a_crashed_claim() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let first_agent = running_agent(&db, session.session_id, 10).await;
        let first = allowed_host_capability_refresh(&db, session.session_id, &first_agent, 20).await;
        let second_agent = db
            .agent_instance(session.session_id, first_agent.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        let second = allowed_host_capability_refresh(&db, session.session_id, &second_agent, 30).await;
        let first_generation = match db
            .claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                first,
                Uuid::new_v4(),
                100,
                40,
            )
            .await
            .unwrap()
        {
            HostCapabilityRefreshExecutionClaim::Claimed { lease } => lease.snapshot_generation(),
            other => panic!("first refresh must claim, got {other:?}"),
        };
        assert_eq!(first_generation, 1);
        assert_eq!(
            db.host_capability_refresh_generation_high_water(
                host_capability_refresh_authority(),
            )
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            db.reconcile_host_capability_refresh_operations(
                host_capability_refresh_authority(),
                session.session_id,
                41,
            )
                .await
                .unwrap(),
            0,
            "startup reconciliation only reports repaired pre-bind operations"
        );
        let second_generation = match db
            .claim_host_capability_refresh_execution(
                host_capability_refresh_authority(),
                session.session_id,
                second,
                Uuid::new_v4(),
                200,
                42,
            )
            .await
            .unwrap()
        {
            HostCapabilityRefreshExecutionClaim::Claimed { lease } => lease.snapshot_generation(),
            other => panic!("recovered second refresh must claim, got {other:?}"),
        };
        assert_eq!(second_generation, 2);
        assert_eq!(
            db.host_capability_refresh_generation_high_water(
                host_capability_refresh_authority(),
            )
            .await
            .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn global_completed_refresh_outbox_replays_reverse_cross_session_receipts_by_generation() {
        let db = Db::open_in_memory().unwrap();
        let first_session = db.create_session("p", "/workspace-a", "root").await.unwrap();
        let second_session = db.create_session("p", "/workspace-b", "root").await.unwrap();
        let first_agent = running_agent(&db, first_session.session_id, 10).await;
        let second_agent = running_agent(&db, second_session.session_id, 11).await;
        let first =
            allowed_host_capability_refresh(&db, first_session.session_id, &first_agent, 20).await;
        let second =
            allowed_host_capability_refresh(&db, second_session.session_id, &second_agent, 21)
                .await;

        // Model a pre-dispatch crash/restart where old independent session
        // workers durably completed the newer receipt first. The global
        // runtime fence prevents this for new work; recovery still has to
        // replay historical rows in generation order rather than completion
        // timestamp or whichever session starts first.
        let first_agent_id = first_agent.agent_instance_id.to_string();
        let second_agent_id = second_agent.agent_instance_id.to_string();
        let first_session_id = first_session.session_id.to_string();
        let second_session_id = second_session.session_id.to_string();
        let first_operation = first.to_string();
        let second_operation = second.to_string();
        db.transaction(move |conn| {
            for (operation_id, session_id, agent_id, generation, completed_at, lease_token) in [
                (
                    second_operation.as_str(),
                    second_session_id.as_str(),
                    second_agent_id.as_str(),
                    2_i64,
                    30_i64,
                    Uuid::new_v4().to_string(),
                ),
                (
                    first_operation.as_str(),
                    first_session_id.as_str(),
                    first_agent_id.as_str(),
                    1_i64,
                    40_i64,
                    Uuid::new_v4().to_string(),
                ),
            ] {
                let (receipt_json, receipt_digest) =
                    test_host_capability_receipt(u64::try_from(generation).unwrap());
                conn.execute(
                    "UPDATE host_capability_refresh_operations
                        SET state = 'executing', execution_agent_revision = 1,
                            execution_epoch = 1, execution_lease_owner_token = ?1,
                            execution_lease_expires_at_unix_ms = 1000,
                            reserved_snapshot_generation = ?2,
                            updated_at_unix_ms = ?3
                      WHERE operation_id = ?4 AND session_id = ?5
                        AND agent_instance_id = ?6 AND state = 'allowed'",
                    params![lease_token, generation, completed_at - 1, operation_id, session_id, agent_id],
                )?;
                conn.execute(
                    "UPDATE host_capability_refresh_operations
                        SET state = 'completed', result_snapshot_json = ?1,
                            result_snapshot_generation = ?2,
                            result_snapshot_digest = ?3,
                            updated_at_unix_ms = ?4, completed_at_unix_ms = ?4
                      WHERE operation_id = ?5 AND session_id = ?6 AND state = 'executing'",
                    params![receipt_json, generation, receipt_digest, completed_at, operation_id, session_id],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();

        let global = db
            .completed_unpublished_host_capability_refresh_operations_page(
                host_capability_refresh_authority(),
                None,
                10,
            )
            .await
            .unwrap()
            .entries;
        assert_eq!(
            global
                .iter()
                .map(|operation| operation.operation_id)
                .collect::<Vec<_>>(),
            vec![first, second],
            "a reverse-session restart must publish generation 1 before generation 2"
        );
        assert_eq!(global[0].session_id, first_session.session_id);
        assert_eq!(global[1].session_id, second_session.session_id);
        assert!(
            db.latest_published_host_capability_refresh_snapshot_receipt(
                host_capability_refresh_authority(),
            )
                .await
                .unwrap()
                .is_none(),
            "boot must not seed from an unpublished later receipt before this ordered outbox drains"
        );
        assert_eq!(
            db.latest_completed_host_capability_refresh_snapshot_receipt(
                host_capability_refresh_authority(),
            )
                .await
                .unwrap()
                .expect("newest completed receipt")
                .generation,
            2,
            "the completed high-water alone is intentionally not a boot seed"
        );
    }

    async fn auto_resolved_late_steer(
        db: &Db,
        session_id: Uuid,
        agent: &AgentInstanceRow,
        now: i64,
    ) -> LateUserDecisionSteer {
        let decision = db
            .create_decision_request(
                standard_decision(session_id, agent.agent_instance_id, agent.revision),
                now,
            )
            .await
            .unwrap();
        assert!(matches!(
            db.resolve_decision_request(
                session_id,
                decision.decision_request_id,
                decision.revision,
                DecisionState::AutoResolved,
                r#"{"source":"test-auto"}"#,
                now + 1,
            )
            .await
            .unwrap(),
            DecisionTransitionOutcome::Transitioned(_)
        ));
        db.record_late_user_decision_steer(
            session_id,
            decision.decision_request_id,
            r#"{"kind":"option","id":"continue"}"#.to_string(),
            now + 2,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn accepted_late_steer_recovers_only_its_checkpoint_and_never_reaccepts() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 10).await;
        let steer = auto_resolved_late_steer(&db, session.session_id, &agent, 20).await;
        let first_epoch = Uuid::new_v4();
        let claimed = db
            .claim_late_user_decision_steers(
                session.session_id,
                agent.agent_instance_id,
                first_epoch,
            )
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(db
            .accept_late_user_decision_steer_execution(
                session.session_id,
                steer.steer_id,
                first_epoch,
                30,
            )
            .await
            .unwrap());

        // Crash window: the provider/model side effect began after acceptance
        // but the continuation completion record was not written. A successor
        // may own the *same* checkpoint, but it cannot put the user body back
        // through the ordinary claim/accept path.
        let model_side_effects = std::sync::atomic::AtomicUsize::new(0);
        model_side_effects.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let successor_epoch = Uuid::new_v4();
        db.begin_late_user_decision_steer_recovery(session.session_id, successor_epoch)
            .await
            .unwrap();
        assert!(db
            .claim_late_user_decision_steers(
                session.session_id,
                agent.agent_instance_id,
                successor_epoch,
            )
            .await
            .unwrap()
            .is_empty());
        let resumed = db
            .accepted_late_user_decision_steers_for_recovery(
                session.session_id,
                agent.agent_instance_id,
                successor_epoch,
            )
            .await
            .unwrap();
        let [resumed] = resumed.as_slice() else {
            panic!("accepted steer must recover as exactly one checkpoint");
        };
        assert_eq!(resumed.steer_id, steer.steer_id);
        assert_eq!(resumed.continuation_id, steer.continuation_id);
        assert_eq!(
            resumed.execution_state,
            LateUserDecisionSteerExecutionState::Accepted
        );
        assert!(resumed.continuation_checkpoint_json.is_some());
        assert_eq!(
            model_side_effects.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "recovery owns the accepted checkpoint, not another model handoff"
        );
        assert!(
            !db.accept_late_user_decision_steer_execution(
                session.session_id,
                steer.steer_id,
                successor_epoch,
                31,
            )
            .await
            .unwrap(),
            "a successor resumes the original continuation identity; it cannot accept a second one"
        );
        assert!(db
            .complete_late_user_decision_steer_execution(
                session.session_id,
                steer.steer_id,
                successor_epoch,
                32,
            )
            .await
            .unwrap());
        assert_eq!(
            model_side_effects.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "completion/recovery must not execute the accepted side effect twice"
        );
        assert!(db
            .ack_late_user_decision_steer_delivery(
                session.session_id,
                steer.steer_id,
                successor_epoch,
                33,
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn root_late_steer_requires_and_recovers_its_exact_durable_continuation() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let created = db
            .ensure_session_root_agent(session.session_id, None, host_workspace_ref(), 10)
            .await
            .unwrap();
        let root = match db
            .transition_agent_instance(
                session.session_id,
                created.agent_instance_id,
                created.revision,
                AgentInstanceState::Running,
                "{}",
                11,
            )
            .await
            .unwrap()
        {
            AgentTransitionOutcome::Transitioned(root) => root,
            other => panic!("root running transition lost: {other:?}"),
        };
        let steer = auto_resolved_late_steer(&db, session.session_id, &root, 20).await;
        let epoch = Uuid::new_v4();
        assert_eq!(
            db.claim_late_user_decision_steers(
                session.session_id,
                root.agent_instance_id,
                epoch,
            )
            .await
            .unwrap()
            .len(),
            1
        );
        assert!(
            !db.accept_late_user_decision_steer_execution(
                session.session_id,
                steer.steer_id,
                epoch,
                21,
            )
            .await
            .unwrap(),
            "the root must not accept before its exact continuation is durable"
        );
        let first_snapshot = serde_json::json!({
            "version": 1,
            "agent_instance_id": root.agent_instance_id,
            "history": [],
            "next_prompt": {"role":"user","content":"first"},
            "late_user_steer_continuation_id": steer.continuation_id,
        })
        .to_string();
        db.persist_session_root_agent_continuation(
            session.session_id,
            root.agent_instance_id,
            Some(steer.continuation_id),
            first_snapshot,
            22,
        )
        .await
        .unwrap();
        assert!(
            db.accept_late_user_decision_steer_execution(
                session.session_id,
                steer.steer_id,
                epoch,
                23,
            )
            .await
            .unwrap(),
            "the persisted root snapshot is an acceptance prerequisite"
        );
        let later_snapshot = serde_json::json!({
            "version": 1,
            "agent_instance_id": root.agent_instance_id,
            "history": ["later parked phase"],
            "next_prompt": {"role":"user","content":"after-question"},
            "late_user_steer_continuation_id": steer.continuation_id,
        })
        .to_string();
        db.persist_session_root_agent_continuation(
            session.session_id,
            root.agent_instance_id,
            Some(steer.continuation_id),
            later_snapshot.clone(),
            24,
        )
        .await
        .unwrap();
        let successor_epoch = Uuid::new_v4();
        db.begin_late_user_decision_steer_recovery(session.session_id, successor_epoch)
            .await
            .unwrap();
        let accepted = db
            .accepted_late_user_decision_steers_for_recovery(
                session.session_id,
                root.agent_instance_id,
                successor_epoch,
            )
            .await
            .unwrap();
        assert_eq!(accepted.len(), 1);
        let descriptor = db
            .session_root_agent_continuation_for_steer(
                session.session_id,
                root.agent_instance_id,
                steer.continuation_id,
            )
            .await
            .unwrap()
            .expect("accepted root steer must recover its exact continuation");
        assert_eq!(descriptor.snapshot_json, later_snapshot);
        assert!(
            db.session_root_agent_continuation_for_steer(
                session.session_id,
                root.agent_instance_id,
                Uuid::new_v4(),
            )
            .await
            .unwrap()
            .is_none(),
            "a same-root earlier snapshot cannot be substituted for this steer"
        );
    }

    #[tokio::test]
    async fn pending_late_steer_acceptance_loses_to_a_new_decision_then_retries_after_recovery() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let initial_agent = running_agent(&db, session.session_id, 34).await;
        let steer = auto_resolved_late_steer(&db, session.session_id, &initial_agent, 35).await;
        let owner = db
            .agent_instance(session.session_id, initial_agent.agent_instance_id)
            .await
            .unwrap()
            .expect("auto-resolved decision owner must remain present");
        assert_eq!(owner.state, AgentInstanceState::Running);

        // Model the narrow race: the executor has claimed the pending steer,
        // but a different continuation parks the exact owner before the
        // final provider-handoff transaction can accept it.
        let first_epoch = Uuid::new_v4();
        let claimed = db
            .claim_late_user_decision_steers(
                session.session_id,
                owner.agent_instance_id,
                first_epoch,
            )
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1);
        let parking_decision = db
            .create_decision_request(
                standard_decision(
                    session.session_id,
                    owner.agent_instance_id,
                    owner.revision,
                ),
                40,
            )
            .await
            .unwrap();
        let waiting_owner = db
            .agent_instance(session.session_id, owner.agent_instance_id)
            .await
            .unwrap()
            .expect("parked decision owner must remain present");
        assert_eq!(waiting_owner.state, AgentInstanceState::WaitingForUser);
        assert!(
            !db.late_user_decision_steer_dispatch_permit_is_current(
                session.session_id,
                steer.steer_id,
                steer.continuation_id,
                steer.agent_instance_id,
                first_epoch,
                41,
            )
            .await
            .unwrap(),
            "a parked owner must lose the pre-provider acceptance race"
        );
        let pending = db
            .late_user_decision_steer(session.session_id, steer.steer_id)
            .await
            .unwrap()
            .expect("lost acceptance race must retain its durable row");
        assert_eq!(
            pending.execution_state,
            LateUserDecisionSteerExecutionState::Pending
        );
        assert_eq!(pending.claimed_recovery_epoch, Some(first_epoch));
        assert!(pending.accepted_agent_revision.is_none());
        assert!(pending.continuation_checkpoint_json.is_none());

        // The executor's negative acknowledgement releases only the pending
        // claim. A recovery while the new decision is still waiting must not
        // redeliver or manufacture an accepted checkpoint.
        assert!(db
            .release_late_user_decision_steer_claim(
                session.session_id,
                steer.steer_id,
                first_epoch,
                42,
            )
            .await
            .unwrap());
        let waiting_epoch = Uuid::new_v4();
        db.begin_late_user_decision_steer_recovery(session.session_id, waiting_epoch)
            .await
            .unwrap();
        assert!(db
            .claim_late_user_decision_steers(
                session.session_id,
                owner.agent_instance_id,
                waiting_epoch,
            )
            .await
            .unwrap()
            .is_empty());
        assert!(db
            .accepted_late_user_decision_steers_for_recovery(
                session.session_id,
                owner.agent_instance_id,
                waiting_epoch,
            )
            .await
            .unwrap()
            .is_empty());

        // Resolving the newer decision atomically resumes the owner. Only
        // now can a new exact-revision executor claim and accept the same
        // immutable steer identity.
        assert!(matches!(
            db.resolve_decision_request(
                session.session_id,
                parking_decision.decision_request_id,
                parking_decision.revision,
                DecisionState::Answered,
                r#"{"source":"test-user"}"#,
                43,
            )
            .await
            .unwrap(),
            DecisionTransitionOutcome::Transitioned(_)
        ));
        let resumed_owner = db
            .agent_instance(session.session_id, owner.agent_instance_id)
            .await
            .unwrap()
            .expect("resolved decision owner must remain present");
        assert_eq!(resumed_owner.state, AgentInstanceState::Running);
        assert!(resumed_owner.revision > waiting_owner.revision);

        let retry_epoch = Uuid::new_v4();
        let retried = db
            .claim_late_user_decision_steers(
                session.session_id,
                owner.agent_instance_id,
                retry_epoch,
            )
            .await
            .unwrap();
        assert_eq!(retried.len(), 1);
        assert_eq!(retried[0].steer_id, steer.steer_id);
        assert!(db
            .late_user_decision_steer_dispatch_permit_is_current(
                session.session_id,
                steer.steer_id,
                steer.continuation_id,
                steer.agent_instance_id,
                retry_epoch,
                44,
            )
            .await
            .unwrap());
        let accepted = db
            .late_user_decision_steer(session.session_id, steer.steer_id)
            .await
            .unwrap()
            .expect("retry must retain its original durable steer");
        assert_eq!(
            accepted.execution_state,
            LateUserDecisionSteerExecutionState::Accepted
        );
        assert_eq!(
            accepted.accepted_agent_revision,
            Some(resumed_owner.revision),
            "acceptance must bind the revision that was runnable at the real provider handoff"
        );
        assert!(accepted.continuation_checkpoint_json.is_some());

        // The accepted continuation can itself park on a later decision after
        // its first provider handoff. Its checkpoint revision remains frozen,
        // but recovery must wait while the owner is parked and then resume
        // that exact checkpoint (not redeliver the user body) after the newer
        // decision returns the owner to running.
        let post_handoff_decision = db
            .create_decision_request(
                standard_decision(
                    session.session_id,
                    resumed_owner.agent_instance_id,
                    resumed_owner.revision,
                ),
                45,
            )
            .await
            .unwrap();
        let post_handoff_waiting_owner = db
            .agent_instance(session.session_id, resumed_owner.agent_instance_id)
            .await
            .unwrap()
            .expect("post-handoff parked owner must remain present");
        assert_eq!(
            post_handoff_waiting_owner.state,
            AgentInstanceState::WaitingForUser
        );
        let waiting_recovery_epoch = Uuid::new_v4();
        db.begin_late_user_decision_steer_recovery(session.session_id, waiting_recovery_epoch)
            .await
            .unwrap();
        assert!(db
            .accepted_late_user_decision_steers_for_recovery(
                session.session_id,
                resumed_owner.agent_instance_id,
                waiting_recovery_epoch,
            )
            .await
            .unwrap()
            .is_empty());
        assert!(matches!(
            db.resolve_decision_request(
                session.session_id,
                post_handoff_decision.decision_request_id,
                post_handoff_decision.revision,
                DecisionState::Answered,
                r#"{"source":"test-user"}"#,
                46,
            )
            .await
            .unwrap(),
            DecisionTransitionOutcome::Transitioned(_)
        ));
        let post_handoff_resumed_owner = db
            .agent_instance(session.session_id, resumed_owner.agent_instance_id)
            .await
            .unwrap()
            .expect("post-handoff resolved owner must remain present");
        assert_eq!(
            post_handoff_resumed_owner.state,
            AgentInstanceState::Running
        );
        assert!(
            post_handoff_resumed_owner.revision > resumed_owner.revision,
            "the resumed continuation must use a fresh owner revision"
        );

        // A subsequent crash/recovery resumes the accepted checkpoint; it
        // cannot put the user message through the pending delivery path or
        // rewrite the original handoff identity to the newer revision.
        let successor_epoch = Uuid::new_v4();
        db.begin_late_user_decision_steer_recovery(session.session_id, successor_epoch)
            .await
            .unwrap();
        assert!(db
            .claim_late_user_decision_steers(
                session.session_id,
                owner.agent_instance_id,
                successor_epoch,
            )
            .await
            .unwrap()
            .is_empty());
        let recovered = db
            .accepted_late_user_decision_steers_for_recovery(
                session.session_id,
                owner.agent_instance_id,
                successor_epoch,
            )
            .await
            .unwrap();
        let [recovered] = recovered.as_slice() else {
            panic!("accepted retry must recover exactly one immutable checkpoint");
        };
        assert_eq!(recovered.steer_id, steer.steer_id);
        assert_eq!(recovered.continuation_id, steer.continuation_id);
        assert_eq!(
            recovered.accepted_agent_revision,
            Some(resumed_owner.revision),
            "recovery keeps the immutable original handoff revision"
        );
        assert!(db
            .late_user_decision_steer_dispatch_permit_is_current(
                session.session_id,
                recovered.steer_id,
                recovered.continuation_id,
                recovered.agent_instance_id,
                successor_epoch,
                47,
            )
            .await
            .unwrap(),
            "the accepted continuation may continue after its own decision resumed the owner"
        );
    }

    #[tokio::test]
    async fn cancellation_wins_late_steer_claim_race_before_a_model_turn_can_begin() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 40).await;
        let steer = auto_resolved_late_steer(&db, session.session_id, &agent, 50).await;
        let claim_epoch = Uuid::new_v4();
        let claim = db.claim_late_user_decision_steers(
            session.session_id,
            agent.agent_instance_id,
            claim_epoch,
        );
        let cancel = db.transition_agent_instance(
            session.session_id,
            agent.agent_instance_id,
            agent.revision + 2,
            AgentInstanceState::Cancelled,
            "{}",
            60,
        );
        let (claim, cancelled) = tokio::join!(claim, cancel);
        let _ = claim.unwrap();
        assert!(matches!(cancelled.unwrap(), AgentTransitionOutcome::Transitioned(_)));

        // An executor must always perform the accepting CAS immediately before
        // it can start a model turn. Whichever transaction won the first race,
        // cancellation atomically leaves this final gate closed.
        let model_turn_started = std::sync::atomic::AtomicBool::new(false);
        if db
            .accept_late_user_decision_steer_execution(
                session.session_id,
                steer.steer_id,
                claim_epoch,
                61,
            )
            .await
            .unwrap()
        {
            model_turn_started.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        assert!(
            !model_turn_started.load(std::sync::atomic::Ordering::SeqCst),
            "cancellation must prevent every post-cancel late-steer model turn"
        );
        let rejected = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT execution_state, rejection_reason, claimed_recovery_epoch
                     FROM agent_decision_steers WHERE steer_id = ?1",
                    [steer.steer_id.to_string()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?)),
                )
            })
            .await
            .unwrap();
        assert_eq!(rejected.0, "rejected");
        assert_eq!(rejected.1, "owner_subtree_cancelled");
        assert!(rejected.2.is_none());
    }

    #[tokio::test]
    async fn cancellation_revokes_an_already_accepted_late_steer_dispatch_permit() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let initial_agent = running_agent(&db, session.session_id, 70).await;
        let steer = auto_resolved_late_steer(&db, session.session_id, &initial_agent, 80).await;
        let epoch = Uuid::new_v4();
        assert_eq!(
            db.claim_late_user_decision_steers(
                session.session_id,
                initial_agent.agent_instance_id,
                epoch,
            )
            .await
            .unwrap()
            .len(),
            1
        );
        assert!(db
            .accept_late_user_decision_steer_execution(
                session.session_id,
                steer.steer_id,
                epoch,
                90,
            )
            .await
            .unwrap());
        let accepted = db
            .late_user_decision_steer(session.session_id, steer.steer_id)
            .await
            .unwrap()
            .unwrap();
        assert!(db
            .late_user_decision_steer_dispatch_permit_is_current(
                session.session_id,
                accepted.steer_id,
                accepted.continuation_id,
                accepted.agent_instance_id,
                epoch,
                90,
            )
            .await
            .unwrap());

        let owner = db
            .agent_instance(session.session_id, accepted.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            db.transition_agent_instance(
                session.session_id,
                owner.agent_instance_id,
                owner.revision,
                AgentInstanceState::Cancelled,
                "{}",
                91,
            )
            .await
            .unwrap(),
            AgentTransitionOutcome::Transitioned(_)
        ));
        assert!(
            !db.late_user_decision_steer_dispatch_permit_is_current(
                session.session_id,
                accepted.steer_id,
                accepted.continuation_id,
                accepted.agent_instance_id,
                epoch,
                92,
            )
            .await
            .unwrap(),
            "cancellation must revoke an accepted executor permit before provider dispatch"
        );
    }

    #[tokio::test]
    async fn failed_recursive_child_terminalizes_its_accepted_late_steer() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let parent = running_agent(&db, session.session_id, 100).await;
        let child = db
            .create_recursive_noninteractive_child_agent(
                session.session_id,
                parent.agent_instance_id,
                Uuid::new_v4(),
                102,
            )
            .await
            .unwrap();
        let steer = auto_resolved_late_steer(&db, session.session_id, &child, 104).await;
        let epoch = Uuid::new_v4();
        assert_eq!(
            db.claim_late_user_decision_steers(session.session_id, child.agent_instance_id, epoch)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(db
            .accept_late_user_decision_steer_execution(
                session.session_id,
                steer.steer_id,
                epoch,
                105,
            )
            .await
            .unwrap());

        assert!(db
            .settle_recursive_noninteractive_child_outcome(
                session.session_id,
                parent.agent_instance_id,
                child.agent_instance_id,
                "child".to_string(),
                "explore".to_string(),
                "Error: provider failed".to_string(),
                true,
                106,
            )
            .await
            .unwrap());

        let terminal = db
            .late_user_decision_steer(session.session_id, steer.steer_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            terminal.execution_state,
            LateUserDecisionSteerExecutionState::Rejected
        );
        assert_eq!(
            terminal.rejection_reason.as_deref(),
            Some("owner_terminal_failed")
        );
        assert!(db
            .accepted_late_user_decision_steers_for_recovery(
                session.session_id,
                child.agent_instance_id,
                Uuid::new_v4(),
            )
            .await
            .unwrap()
            .is_empty(),
            "a terminal recursive child cannot retain an accepted continuation"
        );
    }

    #[tokio::test]
    async fn late_steer_identity_checkpoint_and_state_machine_are_tamper_proof() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 100).await;
        let steer = auto_resolved_late_steer(&db, session.session_id, &agent, 110).await;
        let epoch = Uuid::new_v4();
        assert_eq!(
            db.claim_late_user_decision_steers(session.session_id, agent.agent_instance_id, epoch)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(db
            .accept_late_user_decision_steer_execution(
                session.session_id,
                steer.steer_id,
                epoch,
                120,
            )
            .await
            .unwrap());
        let steer_id = steer.steer_id.to_string();
        let immutable_identity = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE agent_decision_steers SET continuation_id = ?1 WHERE steer_id = ?2",
                    params![Uuid::new_v4().to_string(), steer_id],
                )?;
                Ok(())
            })
            .await;
        assert!(immutable_identity.unwrap_err().to_string().contains("immutable"));

        let steer_id = steer.steer_id.to_string();
        let stale_state = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE agent_decision_steers SET execution_state = 'pending' WHERE steer_id = ?1",
                    params![steer_id],
                )?;
                Ok(())
            })
            .await;
        assert!(stale_state.unwrap_err().to_string().contains("forward-only"));

        let steer_id = steer.steer_id.to_string();
        let checkpoint_rewrite = db
            .write(move |conn| {
                conn.execute(
                    "UPDATE agent_decision_steers SET payload_bytes = 0 WHERE steer_id = ?1",
                    params![steer_id],
                )?;
                Ok(())
            })
            .await;
        assert!(checkpoint_rewrite
            .unwrap_err()
            .to_string()
            .contains("checkpoint is immutable"));
    }

    #[tokio::test]
    async fn cancelled_or_revised_owner_cannot_consume_a_recovery_claim() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 130).await;
        let epoch = Uuid::new_v4();
        assert!(db
            .claim_agent_resume(
                session.session_id,
                agent.agent_instance_id,
                agent.revision,
                epoch,
                140,
            )
            .await
            .unwrap());
        assert!(matches!(
            db.transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                agent.revision,
                AgentInstanceState::Cancelled,
                "{}",
                141,
            )
            .await
            .unwrap(),
            AgentTransitionOutcome::Transitioned(_)
        ));
        assert!(
            !db.consume_agent_resume_claim(
                session.session_id,
                agent.agent_instance_id,
                agent.revision,
                epoch,
                142,
            )
            .await
            .unwrap(),
            "a stale recovery gate must remain closed after cancellation"
        );
    }

    #[tokio::test]
    async fn waiting_child_executor_attachment_claims_are_independent_from_running_provider_permits() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let parent = running_agent(&db, session.session_id, 150).await;

        for (offset, state) in [
            (0_i64, AgentInstanceState::WaitingForUser),
            (10_i64, AgentInstanceState::WaitingForApproval),
        ] {
            let child = db
                .create_recursive_noninteractive_child_agent(
                    session.session_id,
                    parent.agent_instance_id,
                    Uuid::new_v4(),
                    151 + offset,
                )
                .await
                .unwrap();
            let waiting = match db
                .transition_agent_instance(
                    session.session_id,
                    child.agent_instance_id,
                    child.revision,
                    state,
                    r#"{"source":"restart_waiting_child_fixture"}"#.to_string(),
                    152 + offset,
                )
                .await
                .unwrap()
            {
                AgentTransitionOutcome::Transitioned(row) => row,
                other => panic!("waiting child transition must succeed, got {other:?}"),
            };
            let epoch = Uuid::new_v4();
            assert!(db
                .claim_agent_resume(
                    session.session_id,
                    waiting.agent_instance_id,
                    waiting.revision,
                    epoch,
                    153 + offset,
                )
                .await
                .unwrap());
            assert!(db
                .consume_agent_resume_claims_atomically(
                    session.session_id,
                    vec![(waiting.agent_instance_id, waiting.revision)],
                    epoch,
                    154 + offset,
                )
                .await
                .unwrap(),
                "a waiting child must attach its exact executor before the pending decision replay"
            );
        }
    }

    #[tokio::test]
    async fn accepted_late_steer_checkpoint_recovers_while_its_owner_waits_for_a_later_question() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 170).await;
        let steer = auto_resolved_late_steer(&db, session.session_id, &agent, 171).await;
        let accepted_epoch = Uuid::new_v4();
        assert_eq!(
            db.claim_late_user_decision_steers(
                session.session_id,
                agent.agent_instance_id,
                accepted_epoch,
            )
            .await
            .unwrap()
            .len(),
            1
        );
        assert!(db
            .accept_late_user_decision_steer_execution(
                session.session_id,
                steer.steer_id,
                accepted_epoch,
                172,
            )
            .await
            .unwrap());
        let running = db
            .agent_instance(session.session_id, agent.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            db.transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                running.revision,
                AgentInstanceState::WaitingForUser,
                r#"{"source":"later_question_after_accepted_steer"}"#.to_string(),
                173,
            )
            .await
            .unwrap(),
            AgentTransitionOutcome::Transitioned(_)
        ));
        let recovered = db
            .accepted_late_user_decision_steers_for_recovery(
                session.session_id,
                agent.agent_instance_id,
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        assert_eq!(
            recovered.iter().map(|row| row.steer_id).collect::<Vec<_>>(),
            vec![steer.steer_id],
            "recovery must retain an accepted checkpoint for parked replay without treating it as a new provider permit"
        );
    }

    #[tokio::test]
    async fn mixed_recursive_restart_state_uses_terminal_outcome_and_keeps_live_sibling() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let parent = running_agent(&db, session.session_id, 10).await;

        let terminal_child = db
            .create_recursive_noninteractive_child_agent(
                session.session_id,
                parent.agent_instance_id,
                Uuid::new_v4(),
                12,
            )
            .await
            .unwrap();
        let live_child = db
            .create_recursive_noninteractive_child_agent(
                session.session_id,
                parent.agent_instance_id,
                Uuid::new_v4(),
                13,
            )
            .await
            .unwrap();
        for child in [terminal_child.agent_instance_id, live_child.agent_instance_id] {
            db.insert_recursive_noninteractive_executor(
                session.session_id,
                child,
                parent.agent_instance_id,
                ValidatedRecursiveNoninteractiveLaunch::parse_and_canonicalize(
                    r#"{"version":2,"task_call_id":"task","label":"child","child_agent":"agent","model":{},"granted_tools":[],"cwd":"/workspace"}"#,
                )
                .unwrap(),
                ValidatedRecursiveNoninteractiveSnapshot::parse_and_canonicalize(
                    r#"{"version":2,"history":[],"next_prompt":null,"pending_recursive":null}"#,
                )
                .unwrap(),
                14,
            )
            .await
            .unwrap();
        }

        assert!(db
            .settle_recursive_noninteractive_child_outcome(
                session.session_id,
                parent.agent_instance_id,
                terminal_child.agent_instance_id,
                "completed-child".to_string(),
                "child".to_string(),
                "durable terminal report".to_string(),
                false,
                15,
            )
            .await
            .unwrap());

        let terminal_outcome = db
            .recursive_noninteractive_outcome(session.session_id, terminal_child.agent_instance_id)
            .await
            .unwrap()
            .expect("terminal recursive child retains its durable dependency receipt");
        assert_eq!(terminal_outcome.parent_agent_instance_id, parent.agent_instance_id);
        assert!(db
            .recursive_noninteractive_recovery_descriptor(
                session.session_id,
                terminal_child.agent_instance_id,
            )
            .await
            .unwrap()
            .is_none());

        let live_descriptor = db
            .recursive_noninteractive_recovery_descriptor(
                session.session_id,
                live_child.agent_instance_id,
            )
            .await
            .unwrap()
            .expect("live recursive sibling remains recoverable after a mixed restart");
        assert_eq!(live_descriptor.parent_agent_instance_id, parent.agent_instance_id);
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
                            "SELECT COUNT(*) FROM session_events WHERE session_id = ?1 AND type = 'agent_tree'",
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
                        workspace_ref: None,
                        auto_answer_enabled: false,
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
                            "SELECT COUNT(*) FROM session_events WHERE session_id = ?1 AND type = 'agent_tree'",
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
                    workspace_ref: None,
                    auto_answer_enabled: false,
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
                let agent_instance_id = conn.query_row(
                    "SELECT agent_instance_id FROM needs_attention WHERE decision_request_id = ?1",
                    [decision_id.to_string()],
                    |row| row.get(0),
                )?;
                Ok(agent_instance_id)
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
                         interrupt_id, session_id, agent_id, agent_instance_id, description, state, raised_at,
                         decision_request_id
                     ) VALUES (?1, ?2, 'wrong owner', ?3, 'wrong owner', 'open', 304, ?4)",
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
                     interrupt_id, session_id, agent_id, agent_instance_id, description, state, raised_at
                 ) VALUES (?1, ?2, 'legacy', ?3, 'legacy', 'open', 305)",
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
                    (
                        AgentInstanceState::Created,
                        AgentInstanceState::Running | AgentInstanceState::Cancelled
                    )
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
                    options_contract_json: r#"{
                        "options":[{"id":"model-origin-987654","label":"Label with arbitrary user material"}],
                        "question":"Question with arbitrary user material",
                        "description":"Description with arbitrary user material",
                        "task_call_id":"caller-task-987654",
                        "workspace_ref":"caller-workspace-987654"
                    }"#.into(),
                    free_text_contract_json: Some(r#"{"allowed":true,"max_chars":240}"#.into()),
                    recommendation_json: Some(r#"{"option_id":"model-origin-987654"}"#.into()),
                    rationale_redaction_class: "secret".into(),
                    decision_class: "user_question".into(),
                    host_approval_operation_id: None,
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
        let public_contract: serde_json::Value =
            serde_json::from_str(&decision.options_contract_json).unwrap();
        let opaque_option_id = public_contract["options"][0]["id"]
            .as_str()
            .expect("public option token")
            .to_owned();
        assert!(opaque_option_id.starts_with("option:"));
        for leaked in [
            "model-origin-987654",
            "Label with arbitrary user material",
            "Question with arbitrary user material",
            "Description with arbitrary user material",
            "caller-task-987654",
            "caller-workspace-987654",
        ] {
            assert!(
                !decision.options_contract_json.contains(leaked),
                "public decision contract leaked caller-controlled material: {leaked}"
            );
        }
        assert!(
            decision
                .free_text_contract_json
                .as_deref()
                .unwrap()
                .contains("max_chars")
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                decision.recommendation_json.as_deref().unwrap()
            )
            .unwrap()["option_id"]
                .as_str(),
            Some(opaque_option_id.as_str())
        );
        assert!(
            db.private_decision_option_mappings(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .iter()
                .any(|mapping| {
                    mapping.opaque_option_id == opaque_option_id
                        && mapping.continuation_option_id == "model-origin-987654"
                })
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
                        "SELECT COUNT(*) FROM session_events WHERE session_id = ?1 AND type = 'agent_tree'",
                        [session.session_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((attention_count, legacy_count, event_count), (1, 0, 4));

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
                    workspace_ref: None,
                    auto_answer_enabled: false,
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
                    workspace_ref: None,
                    auto_answer_enabled: false,
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
                    options_contract_json: r#"{"options":[{"id":"continue","label":"Continue"}]}"#.into(),
                    free_text_contract_json: None,
                    recommendation_json: None,
                    rationale_redaction_class: "public".into(),
                    decision_class: "user_question".into(),
                    host_approval_operation_id: None,
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
                    options_contract_json: r#"{"options":[{"id":"continue","label":"Continue"}]}"#.into(),
                    free_text_contract_json: None,
                    recommendation_json: None,
                    rationale_redaction_class: "public".into(),
                    decision_class: "authorization".into(),
                    host_approval_operation_id: None,
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
                        options_contract_json: r#"{"options":[{"id":"continue","label":"Continue"}]}"#.into(),
                        free_text_contract_json: None,
                        recommendation_json: None,
                        rationale_redaction_class: "public".into(),
                        decision_class: "user_question".into(),
                        host_approval_operation_id: None,
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
                workspace_ref: None,
                auto_answer_enabled: false,
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
                workspace_ref: None,
                auto_answer_enabled: false,
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
                        "SELECT COUNT(*) FROM session_events event
                         JOIN agent_transition_receipts receipt
                           ON receipt.session_event_seq = event.seq
                         WHERE event.session_id = ?1 AND event.type = 'agent_tree'
                           AND json_extract(event.data_json, '$.kind') = 'agent_transition'
                           AND json_extract(event.data_json, '$.subject_kind') = 'agent'
                           AND json_extract(event.data_json, '$.subject_id') = ?2
                           AND receipt.terminal_state IN ('completed', 'failed')",
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
                         WHERE session_id = ?1 AND type = 'agent_tree'
                           AND json_extract(data_json, '$.subject_id') = ?2",
                        params![session_id.to_string(), decision_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((receipts, events), (1, 2)); // pending + exactly one terminal tree event
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
                        options_contract_json: r#"{"options":[{"id":"continue","label":"Continue"}]}"#.into(),
                        free_text_contract_json: None,
                        recommendation_json: None,
                        rationale_redaction_class: "public".into(),
                        decision_class: "user_question".into(),
                        host_approval_operation_id: None,
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
        let rejected = db
            .create_decision_request(
                NewDecisionRequest {
                    session_id: session.session_id,
                    agent_instance_id: agent.agent_instance_id,
                    expected_agent_revision: agent.revision,
                    waiting_state: AgentInstanceState::WaitingForApproval,
                        options_contract_json: r#"{"options":[{"id":"continue","label":"Continue"}]}"#.into(),
                    free_text_contract_json: None,
                    recommendation_json: None,
                    rationale_redaction_class: "public".into(),
                    decision_class: "host_approval".into(),
                    host_approval_operation_id: Some(Uuid::new_v4()),
                    deadline_unix_ms: None,
                    policy_receipt_json: "{}".into(),
                    resolver_route: Some("utility".into()),
                },
                202,
            )
            .await
            .unwrap_err();
        assert!(
            rejected
                .to_string()
                .contains("host approval composition authority"),
            "a public DB caller cannot mint a standalone host approval"
        );
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
                workspace_ref: None,
                auto_answer_enabled: false,
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
                workspace_ref: None,
                auto_answer_enabled: false,
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
    async fn task_recovery_descriptor_keeps_exact_child_snapshot_and_lineage() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/p", "root").await.unwrap();
        let children = [DelegationChildInit {
            label: "default",
            child_agent: "builder",
            model: None,
            output_dir: None,
            requested_cwd: None,
            resolved_cwd: None,
            todo_ids_json: None,
        }];
        db.upsert_task_delegation_job(
            session.session_id,
            "task-recover",
            None,
            "root",
            Some(r#"{"interactive":true,"child_agent":"builder"}"#),
            &children,
        )
        .await
        .unwrap();
        let root = db
            .ensure_session_root_agent(
                session.session_id,
                None,
                host_workspace_ref(),
                1,
            )
            .await
            .unwrap();
        let children = db
            .publish_task_delegation_children_and_agents(
                session.session_id,
                root.agent_instance_id,
                "task-recover".to_string(),
                vec![NewTaskDelegationAgent {
                    label: "default".to_string(),
                    snapshot_json: r#"{"version":1,"history":[]}"#.to_string(),
                }],
                2,
            )
            .await
            .unwrap();
        assert_eq!(children.len(), 1);
        let child = children.into_iter().next().unwrap();
        let descriptor = db
            .task_delegation_recovery_descriptor(session.session_id, child.agent_instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(descriptor.agent_instance_id, child.agent_instance_id);
        assert_eq!(descriptor.parent_agent_instance_id, root.agent_instance_id);
        assert_eq!(descriptor.task_call_id, "task-recover");
        assert_eq!(descriptor.snapshot_json, r#"{"version":1,"history":[]}"#);
        assert!(!descriptor.was_backgrounded);
        db.transaction({
            let task_call_id = descriptor.task_call_id.clone();
            move |conn| {
                conn.execute(
                    "UPDATE task_delegation_jobs
                        SET status = 'backgrounded'
                      WHERE task_call_id = ?1",
                    [task_call_id],
                )?;
                Ok(())
            }
        })
        .await
        .unwrap();
        assert!(
            db.task_delegation_recovery_descriptor(session.session_id, child.agent_instance_id)
                .await
                .unwrap()
                .expect("backgrounded durable child descriptor")
                .was_backgrounded,
            "a backgrounded durable job must not recover as a foreground child"
        );
    }

    #[tokio::test]
    async fn task_batch_publication_commits_snapshots_and_agent_tree_mappings_together() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/p", "root").await.unwrap();
        let children = [
            DelegationChildInit {
                label: "left",
                child_agent: "builder",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            },
            DelegationChildInit {
                label: "right",
                child_agent: "reviewer",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            },
        ];
        db.upsert_task_delegation_job(
            session.session_id,
            "task-batch-atomic",
            None,
            "root",
            Some(r#"{"entries":[]}"#),
            &children,
        )
        .await
        .unwrap();
        let root = db
            .ensure_session_root_agent(
                session.session_id,
                None,
                host_workspace_ref(),
                1,
            )
            .await
            .unwrap();
        let rows = db
            .publish_task_delegation_children_and_agents(
                session.session_id,
                root.agent_instance_id,
                "task-batch-atomic".to_string(),
                vec![
                    NewTaskDelegationAgent {
                        label: "left".to_string(),
                        snapshot_json: r#"{"version":1,"history":["left"]}"#.to_string(),
                    },
                    NewTaskDelegationAgent {
                        label: "right".to_string(),
                        snapshot_json: r#"{"version":1,"history":["right"]}"#.to_string(),
                    },
                ],
                2,
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        let (published_children, mapped_agents): (i64, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM task_delegation_children
                          WHERE task_call_id = 'task-batch-atomic'
                            AND status = 'running' AND snapshot_json IS NOT NULL",
                        [],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM agent_instances
                          WHERE session_id = ?1 AND task_delegation_job_id = 'task-batch-atomic'
                            AND state = 'running' AND task_delegation_child_uuid IS NOT NULL",
                        [session.session_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((published_children, mapped_agents), (2, 2));
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
        let mut cancellation_only =
            standard_decision(session.session_id, agent.agent_instance_id, agent.revision);
        cancellation_only.options_contract_json = r#"{"options":[]}"#.into();
        cancellation_only.free_text_contract_json = None;
        let error = db
            .create_decision_request(cancellation_only, 2)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("generic decision must offer an option or allow bounded free-text"),
            "a direct DB caller cannot persist a cancellation-only generic decision"
        );
        let mut cancellation_only_question_tool =
            standard_decision(session.session_id, agent.agent_instance_id, agent.revision);
        cancellation_only_question_tool.options_contract_json = r#"{
            "options": [],
            "interrupt_response_contract": {
                "schema": "interrupt_question_set_v1",
                "questions": [{"kind":"single","option_ids":[],"allow_freetext":false}]
            }
        }"#
        .into();
        let error = db
            .create_decision_request(cancellation_only_question_tool, 2)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("QuestionTool choice contract must offer an option or allow free-text"),
            "the direct DB boundary preserves QuestionTool's distinct nonempty response contract"
        );
        let mut forged_auto_resolvable =
            standard_decision(session.session_id, agent.agent_instance_id, agent.revision);
        forged_auto_resolvable.decision_class = "low_risk".into();
        let error = db
            .create_decision_request(forged_auto_resolvable, 2)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("automatically resolvable decision classes require"),
            "holding Db must not let a generic caller manufacture a low-risk resolver input"
        );
        let interrupt_id = db
            .raise_interrupt(
                session.session_id,
                &agent.agent_instance_id.to_string(),
                "ordinary user question",
                None,
            )
            .await
            .unwrap();
        let mut forged_interrupt_bound =
            standard_decision(session.session_id, agent.agent_instance_id, agent.revision);
        forged_interrupt_bound.decision_class = "low_risk".into();
        let error = db
            .create_decision_request_for_interrupt(forged_interrupt_bound, interrupt_id, 2)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("automatically resolvable decision classes require"),
            "the generic interrupt-bound creation API cannot mint a low-risk decision either"
        );
        let question_interrupt_id = db
            .raise_interrupt_with_agent_instance(
                session.session_id,
                "agent-tree",
                Some(agent.agent_instance_id),
                "ordinary QuestionTool continuation",
                Some(&InterruptQuestion::Single {
                    prompt: "Continue?".into(),
                    options: vec![InterruptOption {
                        id: "continue".into(),
                        label: "Continue".into(),
                        description: None,
                        secondary: false,
                    }],
                    allow_freetext: false,
                    command_detail: None,
                    permission: false,
                    approval_class: None,
                    sandbox_escalation: None,
                }),
            )
            .await
            .unwrap();
        let error = db
            .create_decision_request_for_interrupt(
                standard_decision(session.session_id, agent.agent_instance_id, agent.revision),
                question_interrupt_id,
                2,
            )
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("QuestionTool durable contracts and existing question interrupts must be bound together"),
            "a generic decision can never claim a real QuestionTool interrupt"
        );
        assert!(
            db.decision_request_for_interrupt(session.session_id, question_interrupt_id)
                .await
                .unwrap()
                .is_none(),
            "the rejected generic bind leaves the real QuestionTool continuation unclaimed"
        );
        let error = db
            .create_decision_request(
                NewDecisionRequest {
                    session_id: session.session_id,
                    agent_instance_id: agent.agent_instance_id,
                    expected_agent_revision: agent.revision,
                    waiting_state: AgentInstanceState::WaitingForUser,
                    options_contract_json:
                        r#"{"options":[{"id":"approve","label":"Approve","credential":"never-store"}]}"#.into(),
                    free_text_contract_json: None,
                    recommendation_json: None,
                    rationale_redaction_class: "secret".into(),
                    decision_class: "credential".into(),
                    host_approval_operation_id: None,
                    deadline_unix_ms: None,
                    policy_receipt_json: "{}".into(),
                    resolver_route: Some("user".into()),
                },
                2,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unapproved"));
        let error = db
            .create_decision_request(
                NewDecisionRequest {
                    session_id: session.session_id,
                    agent_instance_id: agent.agent_instance_id,
                    expected_agent_revision: agent.revision,
                    waiting_state: AgentInstanceState::WaitingForUser,
                    options_contract_json: r#"{"options":[{"id":"approve","label":"Approve"}]}"#.into(),
                    free_text_contract_json: Some(r#"{"allowed":true}"#.into()),
                    recommendation_json: None,
                    rationale_redaction_class: "public".into(),
                    decision_class: "user_question".into(),
                    host_approval_operation_id: None,
                    deadline_unix_ms: None,
                    policy_receipt_json: "{}".into(),
                    resolver_route: None,
                },
                2,
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("requires a bounded max_chars"),
            "an allowed free-text decision may not persist an unbounded contract"
        );
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
                    options_contract_json: r#"{"options":[{"id":"approve","label":"Approve"}]}"#.into(),
                    free_text_contract_json: None,
                    recommendation_json: None,
                    rationale_redaction_class: "public".into(),
                    decision_class: "user_question".into(),
                    host_approval_operation_id: None,
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
        let events: Vec<(String, String, String)> = db
            .read(move |conn| {
                let mut statement = conn.prepare(
                    "SELECT json_extract(data_json, '$.kind'),
                            json_extract(data_json, '$.subject_kind'),
                            json_extract(data_json, '$.subject_id')
                     FROM session_events WHERE session_id = ?1 AND type = 'agent_tree' ORDER BY seq",
                )?;
                let events = statement
                    .query_map([session.session_id.to_string()], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(events)
            })
            .await
            .unwrap();
        assert_eq!(
            events,
            vec![
                ("agent_created".into(), "agent".into(), agent.agent_instance_id.to_string()),
                ("agent_transition".into(), "agent".into(), agent.agent_instance_id.to_string()),
                ("agent_transition".into(), "agent".into(), agent.agent_instance_id.to_string()),
                ("decision_pending".into(), "decision".into(), decision.decision_request_id.to_string()),
                ("decision_transition".into(), "decision".into(), decision.decision_request_id.to_string()),
            ]
        );
        assert_eq!(
            db.agent_instance(session.session_id, agent.agent_instance_id)
                .await
                .unwrap()
                .expect("event subject agent")
                .state,
            AgentInstanceState::WaitingForUser,
            "the authoritative agent row, not an invalidation payload, owns current state"
        );
        assert_eq!(
            db.decision_request(session.session_id, decision.decision_request_id)
                .await
                .unwrap()
                .expect("event subject decision")
                .state,
            DecisionState::Resolving,
            "the authoritative decision row, not an invalidation payload, owns current state"
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
                        options_contract_json: r#"{"options":[{"id":"approve","label":"Approve"}]}"#.into(),
                        free_text_contract_json: Some(r#"{"allowed":true,"max_chars":120}"#.into()),
                        recommendation_json: Some(r#"{"option_id":"approve"}"#.into()),
                        rationale_redaction_class: "sensitive".into(),
                        decision_class: "user_question".into(),
                        host_approval_operation_id: None,
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
        let opaque_option_id = options["options"][0]["id"]
            .as_str()
            .expect("opaque option token")
            .to_owned();
        assert!(opaque_option_id.starts_with("option:"));
        assert_ne!(opaque_option_id, "approve");
        assert!(options["options"][0].get("label").is_none());
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
        assert_eq!(
            recommendation["option_id"].as_str(),
            Some(opaque_option_id.as_str())
        );
        assert!(
            reopened
                .private_decision_option_mappings(session_id, decision_id)
                .await
                .unwrap()
                .iter()
                .any(|mapping| {
                    mapping.opaque_option_id == opaque_option_id
                        && mapping.continuation_option_id == "approve"
                })
        );
        assert!(decision.policy_receipt_json.contains("receipt-1"));
        assert!(!format!("{decision:?}").contains("credential"));
    }

    #[tokio::test]
    async fn malformed_persisted_decision_contract_cannot_reach_replay_or_recovery() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 1).await;
        let decision = db
            .create_decision_request(
                standard_decision(
                    session.session_id,
                    agent.agent_instance_id,
                    agent.revision,
                ),
                2,
            )
            .await
            .unwrap();
        let decision_id = decision.decision_request_id;
        db.write(move |conn| {
            conn.execute(
                "UPDATE decision_requests
                 SET options_contract_json = ?1, free_text_contract_json = NULL
                 WHERE decision_request_id = ?2",
                params![
                    r#"{"options":[],"question":"Decision required","description":"An agent decision is waiting","task_call_id":null,"workspace_ref":null,"interrupt_response_contract":null,"redacted":true}"#,
                    decision_id.to_string(),
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let error = db
            .decision_request(session.session_id, decision_id)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("generic decision must offer an option or allow bounded free-text"),
            "an imported/corrupted row must fail closed before normal replay can observe it"
        );
        let error = db
            .recoverable_decision_requests_page(session.session_id, None, 10)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("generic decision must offer an option or allow bounded free-text"),
            "recovery cannot reintroduce an unsatisfiable persisted decision"
        );
    }

    #[tokio::test]
    async fn imported_generic_decision_cannot_claim_a_question_tool_interrupt() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 1).await;
        let decision = db
            .create_decision_request(
                standard_decision(
                    session.session_id,
                    agent.agent_instance_id,
                    agent.revision,
                ),
                2,
            )
            .await
            .unwrap();
        let question_interrupt_id = db
            .raise_interrupt_with_agent_instance(
                session.session_id,
                "agent-tree",
                Some(agent.agent_instance_id),
                "imported QuestionTool continuation",
                Some(&InterruptQuestion::Single {
                    prompt: "Continue?".into(),
                    options: vec![InterruptOption {
                        id: "continue".into(),
                        label: "Continue".into(),
                        description: None,
                        secondary: false,
                    }],
                    allow_freetext: false,
                    command_detail: None,
                    permission: false,
                    approval_class: None,
                    sandbox_escalation: None,
                }),
            )
            .await
            .unwrap();
        let decision_id = decision.decision_request_id;
        db.write(move |conn| {
            conn.execute(
                "DELETE FROM needs_attention WHERE session_id = ?1 AND decision_request_id = ?2",
                params![session.session_id.to_string(), decision_id.to_string()],
            )?;
            conn.execute(
                "UPDATE needs_attention SET decision_request_id = ?1 WHERE interrupt_id = ?2",
                params![decision_id.to_string(), question_interrupt_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let error = db
            .decision_request(session.session_id, decision_id)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("persisted QuestionTool durable contract and existing question interrupt must be bound together"),
            "an imported generic decision must fail closed before it can claim a QuestionTool continuation"
        );
        let error = db
            .recoverable_decision_requests_page(session.session_id, None, 10)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("persisted QuestionTool durable contract and existing question interrupt must be bound together"),
            "recovery must not turn a malformed imported link into a QuestionTool replay"
        );
    }

    #[tokio::test]
    async fn imported_question_tool_approval_metadata_and_final_operation_bindings_fail_closed() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 1).await;
        let ordinary_question = InterruptQuestion::Single {
            prompt: "Continue?".into(),
            options: vec![InterruptOption {
                id: "continue".into(),
                label: "Continue".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        };
        let interrupt_id = db
            .raise_interrupt_with_agent_instance(
                session.session_id,
                "agent-tree",
                Some(agent.agent_instance_id),
                "imported QuestionTool approval metadata",
                Some(&ordinary_question),
            )
            .await
            .unwrap();
        let decision = db
            .create_decision_request_for_interrupt(
                standard_question_tool_decision(
                    session.session_id,
                    agent.agent_instance_id,
                    agent.revision,
                    "continue",
                ),
                interrupt_id,
                2,
            )
            .await
            .unwrap();
        let decision_id = decision.decision_request_id;
        let session_id = session.session_id;
        let approval_question = InterruptQuestion::Single {
            permission: true,
            ..ordinary_question.clone()
        };
        let approval_interrupt_id = db
            .raise_interrupt_with_agent_instance(
                session_id,
                "agent-tree",
                Some(agent.agent_instance_id),
                "imported approval-shaped QuestionTool continuation",
                Some(&approval_question),
            )
            .await
            .unwrap();
        db.write(move |conn| {
            conn.execute(
                "DELETE FROM needs_attention WHERE session_id = ?1 AND decision_request_id = ?2",
                params![session_id.to_string(), decision_id.to_string()],
            )?;
            conn.execute(
                "UPDATE needs_attention SET decision_request_id = ?1 WHERE interrupt_id = ?2",
                params![decision_id.to_string(), approval_interrupt_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let error = db
            .decision_request(session_id, decision_id)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("raw approval-shaped QuestionTool interrupt"),
            "a generic decision must not load after an imported raw approval metadata mutation"
        );
        let error = db
            .recoverable_decision_requests_page(session_id, None, 10)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("raw approval-shaped QuestionTool interrupt"),
            "recovery must not replay an imported generic-to-approval-shaped decision"
        );

        let operation_id = Uuid::new_v4();
        let operation_input = canonical_json_string(&json!({
            "candidate_effects": [{
                "selection": "continue",
                "execute": {"operation": "test"},
            }],
        }))
        .unwrap();
        let mut digest = Sha256::new();
        digest.update(b"flycockpit.host-approval-input.v1\0");
        digest.update(operation_input.as_bytes());
        let input_digest = format!("{:x}", digest.finalize());
        let decision_id_for_bind = decision_id.to_string();
        let session_id_for_bind = session_id.to_string();
        let agent_id_for_bind = agent.agent_instance_id.to_string();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO agent_host_approval_operations (
                     operation_id, session_id, agent_instance_id, operation_kind,
                     canonical_input_json, input_digest, decision_request_id, state,
                     created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, 'test', ?4, ?5, NULL, 'pending', 3)",
                params![
                    operation_id.to_string(),
                    session_id_for_bind,
                    agent_id_for_bind,
                    operation_input.clone(),
                    input_digest.clone(),
                ],
            )?;
            conn.execute(
                "UPDATE decision_requests
                    SET decision_class = 'host_approval', host_approval_operation_id = ?1
                  WHERE decision_request_id = ?2",
                params![operation_id.to_string(), decision_id_for_bind],
            )?;
            conn.execute(
                "UPDATE agent_host_approval_operations
                    SET decision_request_id = ?1
                  WHERE operation_id = ?2",
                params![decision_id.to_string(), operation_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            db.decision_request(session_id, decision_id).await.is_ok(),
            "the fully bound host approval fixture must satisfy the common load boundary"
        );

        let ordinary_interrupt_id = db
            .raise_interrupt_with_agent_instance(
                session_id,
                "agent-tree",
                Some(agent.agent_instance_id),
                "imported ordinary QuestionTool continuation",
                Some(&ordinary_question),
            )
            .await
            .unwrap();
        let mismatched_operation_id = Uuid::new_v4();
        db.write(move |conn| {
            conn.execute(
                "DELETE FROM needs_attention WHERE session_id = ?1 AND decision_request_id = ?2",
                params![session_id.to_string(), decision_id.to_string()],
            )?;
            conn.execute(
                "UPDATE needs_attention SET decision_request_id = ?1 WHERE interrupt_id = ?2",
                params![decision_id.to_string(), ordinary_interrupt_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let error = db
            .decision_request(session_id, decision_id)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("host approval decision must bind a raw approval-shaped"),
            "a host approval must not load after its imported raw interrupt is made ordinary"
        );
        let error = db
            .recoverable_decision_requests_page(session_id, None, 10)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("host approval decision must bind a raw approval-shaped"),
            "recovery must not replay an imported host approval whose raw interrupt was made ordinary"
        );

        let restored_approval_interrupt_id = db
            .raise_interrupt_with_agent_instance(
                session_id,
                "agent-tree",
                Some(agent.agent_instance_id),
                "restored imported approval QuestionTool continuation",
                Some(&approval_question),
            )
            .await
            .unwrap();
        db.write(move |conn| {
            conn.execute(
                "DELETE FROM needs_attention WHERE session_id = ?1 AND decision_request_id = ?2",
                params![session_id.to_string(), decision_id.to_string()],
            )?;
            conn.execute(
                "UPDATE needs_attention SET decision_request_id = ?1 WHERE interrupt_id = ?2",
                params![decision_id.to_string(), restored_approval_interrupt_id.to_string()],
            )?;
            conn.execute(
                "DELETE FROM agent_host_approval_operations WHERE operation_id = ?1",
                params![operation_id.to_string()],
            )?;
            conn.execute(
                "INSERT INTO agent_host_approval_operations (
                     operation_id, session_id, agent_instance_id, operation_kind,
                     canonical_input_json, input_digest, decision_request_id, state,
                     created_at_unix_ms
                 ) VALUES (?1, ?2, ?3, 'test', ?4, ?5, NULL, 'pending', 4)",
                params![
                    mismatched_operation_id.to_string(),
                    session_id.to_string(),
                    agent.agent_instance_id.to_string(),
                    operation_input,
                    input_digest,
                ],
            )?;
            conn.execute(
                "UPDATE decision_requests SET host_approval_operation_id = ?1
                  WHERE decision_request_id = ?2",
                params![mismatched_operation_id.to_string(), decision_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let error = db
            .recoverable_decision_requests_page(session_id, None, 10)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("final operation is not bound to its exact decision owner"),
            "recovery must reject an imported host approval whose final operation belongs to no decision"
        );
    }

    #[tokio::test]
    async fn imported_or_corrupted_decision_fields_and_private_mappings_fail_before_attention() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/workspace", "root").await.unwrap();
        let agent = running_agent(&db, session.session_id, 1).await;
        let decision = db
            .create_decision_request(
                standard_decision(
                    session.session_id,
                    agent.agent_instance_id,
                    agent.revision,
                ),
                2,
            )
            .await
            .unwrap();
        let decision_id = decision.decision_request_id;
        let original_options = decision.options_contract_json.clone();
        let original_recommendation = decision.recommendation_json.clone();
        let original_free_text = decision.free_text_contract_json.clone();
        let original_mappings = db
            .private_decision_option_mappings(session.session_id, decision_id)
            .await
            .unwrap();

        // Each mutation remains valid JSON and canonically encoded.  The
        // load boundary must nevertheless reject every changed public field
        // before an Attention projection or recovery worker can observe it.
        for (field, replacement) in [
            ("question", serde_json::Value::String("forged".into())),
            ("description", serde_json::Value::String("forged".into())),
            ("task_call_id", serde_json::Value::String("forged".into())),
            ("workspace_ref", serde_json::Value::String("forged".into())),
            (
                "interrupt_response_contract",
                json!({
                    "schema": "interrupt_question_set_v1",
                    "questions": [{"kind": "freetext"}],
                }),
            ),
            ("redacted", serde_json::Value::Bool(false)),
        ] {
            let mut options: serde_json::Value = serde_json::from_str(&original_options).unwrap();
            options[field] = replacement;
            let malformed = canonical_json_string(&options).unwrap();
            db.write({
                let decision_id = decision_id;
                move |conn| {
                    conn.execute(
                        "UPDATE decision_requests SET options_contract_json = ?1 WHERE decision_request_id = ?2",
                        params![malformed, decision_id.to_string()],
                    )?;
                    Ok(())
                }
            })
            .await
            .unwrap();
            assert!(
                db.decision_attention_page(session.session_id, None, 10)
                    .await
                    .is_err(),
                "malformed public {field} must not reach Attention"
            );
            db.write({
                let decision_id = decision_id;
                let original_options = original_options.clone();
                move |conn| {
                    conn.execute(
                        "UPDATE decision_requests SET options_contract_json = ?1 WHERE decision_request_id = ?2",
                        params![original_options, decision_id.to_string()],
                    )?;
                    Ok(())
                }
            })
            .await
            .unwrap();
        }

        let mut options: serde_json::Value = serde_json::from_str(&original_options).unwrap();
        options["options"][0]["id"] = serde_json::Value::String(
            "option:00000000-0000-4000-8000-000000000001".into(),
        );
        let malformed_options = canonical_json_string(&options).unwrap();
        db.write({
            let decision_id = decision_id;
            move |conn| {
                conn.execute(
                    "UPDATE decision_requests SET options_contract_json = ?1 WHERE decision_request_id = ?2",
                    params![malformed_options, decision_id.to_string()],
                )?;
                Ok(())
            }
        })
        .await
        .unwrap();
        assert!(db.decision_request(session.session_id, decision_id).await.is_err());
        db.write({
            let decision_id = decision_id;
            let original_options = original_options.clone();
            move |conn| {
                conn.execute(
                    "UPDATE decision_requests SET options_contract_json = ?1 WHERE decision_request_id = ?2",
                    params![original_options, decision_id.to_string()],
                )?;
                Ok(())
            }
        })
        .await
        .unwrap();

        let mut recommendation: serde_json::Value =
            serde_json::from_str(original_recommendation.as_deref().unwrap()).unwrap();
        recommendation["option_id"] = serde_json::Value::String(
            "option:018f47a2-7b3c-7def-8123-000000000001".into(),
        );
        let malformed_recommendation = canonical_json_string(&recommendation).unwrap();
        db.write({
            let decision_id = decision_id;
            move |conn| {
                conn.execute(
                    "UPDATE decision_requests SET recommendation_json = ?1 WHERE decision_request_id = ?2",
                    params![malformed_recommendation, decision_id.to_string()],
                )?;
                Ok(())
            }
        })
        .await
        .unwrap();
        assert!(db.decision_request(session.session_id, decision_id).await.is_err());
        db.write({
            let decision_id = decision_id;
            let original_recommendation = original_recommendation.clone();
            move |conn| {
                conn.execute(
                    "UPDATE decision_requests SET recommendation_json = ?1 WHERE decision_request_id = ?2",
                    params![original_recommendation, decision_id.to_string()],
                )?;
                Ok(())
            }
        })
        .await
        .unwrap();

        db.write({
            let decision_id = decision_id;
            move |conn| {
                conn.execute(
                    "DELETE FROM decision_private_option_mappings WHERE decision_request_id = ?1",
                    params![decision_id.to_string()],
                )?;
                Ok(())
            }
        })
        .await
        .unwrap();
        assert!(db.decision_request(session.session_id, decision_id).await.is_err());

        db.write({
            let decision_id = decision_id;
            let session_id = session.session_id;
            move |conn| {
                for mapping in original_mappings {
                    conn.execute(
                        "INSERT INTO decision_private_option_mappings (
                             decision_request_id, session_id, opaque_option_id, continuation_option_id
                         ) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            decision_id.to_string(),
                            session_id.to_string(),
                            mapping.opaque_option_id,
                            mapping.continuation_option_id,
                        ],
                    )?;
                }
                Ok(())
            }
        })
        .await
        .unwrap();

        // This generic decision has no stored free-text capability. A forged
        // malformed capability must be detected independently of the options
        // and private-token validation above.
        let forged_free_text = canonical_json_string(&json!({
            "allowed": true,
            "max_chars": 120,
            "redacted": true,
            "extra": false,
        }))
        .unwrap();
        assert!(original_free_text.is_none());
        db.write(move |conn| {
            conn.execute(
                "UPDATE decision_requests SET free_text_contract_json = ?1 WHERE decision_request_id = ?2",
                params![forged_free_text, decision_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(db.decision_request(session.session_id, decision_id).await.is_err());
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
                        workspace_ref: None,
                        auto_answer_enabled: false,
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
