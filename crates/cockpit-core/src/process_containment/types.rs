//! Core types for generation-bound process containment.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Whether the platform can prove the descendant set empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentGuarantee {
    /// Adapter empty oracle is authoritative for barriers.
    Proven,
    /// No proven containment; strict workflows fail closed before user code.
    Unsupported,
}

impl ContainmentGuarantee {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Unsupported => "unsupported",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "proven" => Some(Self::Proven),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

/// Durable containment lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentState {
    Creating,
    Active,
    Stopping,
    Empty,
    Uncertain,
}

impl ContainmentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Active => "active",
            Self::Stopping => "stopping",
            Self::Empty => "empty",
            Self::Uncertain => "uncertain",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "creating" => Some(Self::Creating),
            "active" => Some(Self::Active),
            "stopping" => Some(Self::Stopping),
            "empty" => Some(Self::Empty),
            "uncertain" => Some(Self::Uncertain),
            _ => None,
        }
    }

    pub fn is_empty(self) -> bool {
        matches!(self, Self::Empty)
    }

    pub fn is_nonempty(self) -> bool {
        !self.is_empty()
    }
}

/// Platform adapter kind recorded on durable rows (safe label only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    LinuxCgroup,
    WindowsJob,
    MacosUnsupported,
    Docker,
    Podman,
    Fake,
    Unsupported,
}

impl PlatformKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxCgroup => "linux_cgroup",
            Self::WindowsJob => "windows_job",
            Self::MacosUnsupported => "macos_unsupported",
            Self::Docker => "docker",
            Self::Podman => "podman",
            Self::Fake => "fake",
            Self::Unsupported => "unsupported",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "linux_cgroup" => Some(Self::LinuxCgroup),
            "windows_job" => Some(Self::WindowsJob),
            "macos_unsupported" => Some(Self::MacosUnsupported),
            "docker" => Some(Self::Docker),
            "podman" => Some(Self::Podman),
            "fake" => Some(Self::Fake),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

/// Result of await_empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmptyOutcome {
    /// Same-generation adapter oracle reports the group is empty.
    ProvenEmpty { generation: u64 },
    /// No proven empty signal; durable row retained for recovery.
    Uncertain { generation: u64, reason: String },
    /// Platform cannot provide Proven containment.
    Unsupported { reason: String },
}

/// Typed errors from the containment actor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContainmentError {
    #[error("containment actor queue saturated")]
    QueueSaturated,
    #[error("containment actor stopped")]
    ActorStopped,
    #[error("descendant containment unavailable: {reason}")]
    DescendantContainmentUnavailable { reason: String },
    #[error("session is deleting; new containment rejected")]
    SessionDeleting,
    #[error("daemon is shutting down; new containment rejected")]
    ShutdownIntakeClosed,
    #[error("illegal state transition: {from} -> {to}")]
    IllegalTransition { from: String, to: String },
    #[error("generation mismatch: expected {expected}, got {got}")]
    GenerationMismatch { expected: u64, got: u64 },
    #[error("duplicate command for containment {containment_id}")]
    DuplicateCommand { containment_id: Uuid },
    #[error("containment not found: {0}")]
    NotFound(Uuid),
    #[error("session deletion blocked: nonempty containments remain")]
    DeletionBlocked { blockers: Vec<Uuid> },
    #[error("shutdown not clean: nonempty containments remain")]
    ShutdownNotClean { blockers: Vec<Uuid> },
    #[error("internal containment error: {0}")]
    Internal(String),
}

/// Non-serializable lease token. Callers spawn user code only into this
/// lease's process-tree guard when the adapter provides one. Dropping does
/// not terminate the group; cancellation drives Stopping + reconciliation.
#[derive(Clone)]
pub struct ContainmentLease {
    pub(crate) containment_id: Uuid,
    pub(crate) session_id: Uuid,
    pub(crate) generation: u64,
    pub(crate) guarantee: ContainmentGuarantee,
    /// Opaque handle that prevents accidental serde / cross-process reuse.
    pub(crate) token: Arc<LeaseToken>,
}

/// Opaque non-serializable token core.
pub struct LeaseToken {
    pub(crate) alive: AtomicBool,
    #[allow(dead_code)]
    pub(crate) label: Mutex<String>,
}

impl LeaseToken {
    pub(crate) fn new(label: impl Into<String>) -> Self {
        Self {
            alive: AtomicBool::new(true),
            label: Mutex::new(label.into()),
        }
    }

    pub(crate) fn invalidate(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

// Explicitly no Serialize/Deserialize for ContainmentLease.
impl fmt::Debug for ContainmentLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContainmentLease")
            .field("containment_id", &self.containment_id)
            .field("session_id", &self.session_id)
            .field("generation", &self.generation)
            .field("guarantee", &self.guarantee)
            .field("alive", &self.token.is_alive())
            .finish()
    }
}

impl ContainmentLease {
    pub fn containment_id(&self) -> Uuid {
        self.containment_id
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn guarantee(&self) -> ContainmentGuarantee {
        self.guarantee
    }

    pub fn is_alive(&self) -> bool {
        self.token.is_alive()
    }
}

/// Safe doctor/audit metadata — no command, env, path payload, output, PID
/// oracle, container output, endpoint credential, or secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeContainmentMetadata {
    pub platform_kind: PlatformKind,
    pub guarantee: ContainmentGuarantee,
    pub capability_reason: Option<String>,
    pub adapter_name: String,
    pub management_boundary: Option<String>,
}

/// Safe durable locator fields (content-free).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeLocator {
    /// Platform object id digest or opaque locator key (never a command).
    pub locator_key: Option<String>,
    /// Container full-id digest (when container adapter).
    pub full_id_digest: Option<String>,
    /// Runtime kind + binary/endpoint context digest.
    pub runtime_context_digest: Option<String>,
    /// Expected diagnostic name (never authoritative after create).
    pub expected_name: Option<String>,
    /// Generation nonce for recovery matching.
    pub nonce: Option<String>,
    /// Installation identity digest binding.
    pub installation_digest: Option<String>,
}

impl SafeLocator {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }

    pub fn from_json(s: &str) -> Self {
        serde_json::from_str(s).unwrap_or_default()
    }
}

/// Events applied to the pure durable reducer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainmentEvent {
    /// Begin Creating (row written before platform allocation).
    BeginCreate {
        containment_id: Uuid,
        session_id: Uuid,
        operation_id: String,
        generation: u64,
        platform_kind: PlatformKind,
        guarantee: ContainmentGuarantee,
        now_wall_ms: i64,
    },
    /// Platform allocation succeeded; membership not yet proven.
    #[allow(dead_code)]
    PlatformAllocated {
        generation: u64,
        locator: SafeLocator,
        now_wall_ms: i64,
    },
    /// Spawn membership proven → Active.
    MembershipProven {
        generation: u64,
        locator: SafeLocator,
        now_wall_ms: i64,
    },
    /// Allocation/membership failed as Unsupported before user code.
    MarkUnsupported {
        generation: u64,
        reason: String,
        now_wall_ms: i64,
    },
    /// Caller cancel or force terminate → Stopping.
    RequestStop { generation: u64, now_wall_ms: i64 },
    /// Same-generation empty oracle → Empty.
    OracleEmpty { generation: u64, now_wall_ms: i64 },
    /// Ambiguous platform/DB disagreement → Uncertain.
    MarkUncertain {
        generation: u64,
        reason: String,
        now_wall_ms: i64,
    },
    /// Generation replacement for recovery; invalidates prior generation.
    #[allow(dead_code)]
    ReplaceGeneration {
        from_generation: u64,
        to_generation: u64,
        now_wall_ms: i64,
    },
    /// Late callback from an older generation — must be ignored.
    LateCallback {
        callback_generation: u64,
        kind: LateCallbackKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateCallbackKind {
    ProcessExit,
    ClientExit,
    EmptyNotification,
    Cancellation,
    Recovery,
    ImmutableIdReuse,
    NameReuse,
    LocatorReuse,
}

/// Pure in-memory view of one containment's durable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentRecord {
    pub containment_id: Uuid,
    pub session_id: Uuid,
    pub operation_id: String,
    pub generation: u64,
    pub platform_kind: PlatformKind,
    pub state: ContainmentState,
    pub guarantee: ContainmentGuarantee,
    pub locator: SafeLocator,
    pub unsupported_reason: Option<String>,
    pub created_at_wall_ms: i64,
    pub updated_at_wall_ms: i64,
    pub emptied_at_wall_ms: Option<i64>,
    /// Tracks in-flight commands for duplicate detection.
    pub pending_command: Option<String>,
}

/// Reducer outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReduceResult {
    Applied(Box<ContainmentRecord>),
    IgnoredLate {
        current_generation: u64,
        callback_generation: u64,
        kind: LateCallbackKind,
    },
    Illegal {
        from: ContainmentState,
        event: String,
    },
    GenerationMismatch {
        expected: u64,
        got: u64,
    },
    DuplicateCommand {
        command: String,
    },
}
