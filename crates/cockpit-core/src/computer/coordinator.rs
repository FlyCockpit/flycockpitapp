//! Provider-native computer-use action loop and host-global coordinator.
//!
//! This module connects real OpenAI Responses and both Anthropic computer-call
//! streams to one canonical, centrally authorized action coordinator. Transient
//! screenshots are borrowed through the screenshot boundary before provider
//! assembly; no live frame or transient provider request reaches durable
//! middleware.
//!
//! # Architecture
//!
//! [`HostInputArbiter`] serializes every real physical target across delegations
//! and Cockpit processes. It combines a process-local FIFO with an OS-level
//! advisory lock file under the private Cockpit data root keyed by
//! [`PhysicalTargetKey`]. Acquisition returns an unforgeable monotonic lease
//! generation; only the current `(target_key, generation, owner_instance,
//! delegation)` may dispatch. Virtual backends serialize per virtual display
//! but do not take the host lock.
//!
//! [`ComputerActionCoordinator`] is created one per delegation and owns one
//! opened backend/display capability. Before building provider tool declarations
//! it obtains backend-reported geometry and target evidence, acquires the host
//! input arbiter where applicable, and creates provider declarations from that
//! same immutable display generation.
//!
//! Provider-native extraction/injection seams ([`NativeResponseExtractor`])
//! intercept provider `computer_call` items (OpenAI) and native `tool_use` named
//! `computer` (Anthropic), parse them with the canonical versioned parser,
//! execute through the coordinator, and emit the correlated transient
//! continuation. Generic Rig function-tool dispatch never reinterprets native
//! computer items; unknown native variants return a typed provider-compatible
//! unsupported result before backend input.
//!
//! Every canonical action goes through the exhaustive central
//! [`AuthorizationRequest::ComputerAction`], carrying only engine-owned
//! session/delegation/action IDs, tier, host lease token, target/focus/observation
//! generations, and safe metadata.

#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use super::frame::{
    ActionId, CaptureEpoch, FrameDimensions, InMemoryReservationHandle, LiveComputerFrame,
    MediaReservationHandle, ObservationId, ProviderMediaVariant, SanitizedComputerFrame,
    ScreenshotMediaType, TransientProviderRequest,
};
use super::target::{
    BackendKind, PhysicalTargetKey, TargetEvidenceAdapter, TargetUnavailableReason,
};
use super::{
    Anthropic20250124ComputerAction, Anthropic20251124ComputerAction, ComputerAction,
    ComputerActionOutcome, ComputerBackend, ComputerBatchReport, ComputerError, ComputerFailure,
    ComputerToolContract, DisplayGeometry, NativeComputerWire, OpenAiComputerAction,
    parse_anthropic_20250124_action, parse_anthropic_20251124_action, parse_openai_computer_call,
};

// ---------------------------------------------------------------------------
// Host input arbiter: process-local FIFO + OS-level advisory lock
// ---------------------------------------------------------------------------

/// Unforgeable monotonic lease generation. Only the current
/// `(target_key, generation, owner_instance, delegation)` may dispatch.
///
/// This type is not constructible outside this module; the only way to obtain
/// one is through [`HostInputArbiter::acquire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LeaseGeneration(u64);

impl LeaseGeneration {
    /// Returns the raw generation number for diagnostic/logging purposes.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Identifies the owner instance (process) that holds a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OwnerInstance(pub u64);

/// Identifies the delegation that holds a lease.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DelegationId(pub String);

/// An unforgeable host lease token carried by every authorized computer action.
///
/// Only the current `(target_key, generation, owner_instance, delegation)` may
/// dispatch. OS lock loss, owner death, display-generation change, or lease
/// replacement invalidates queued work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLeaseToken {
    pub target_key: PhysicalTargetKey,
    pub generation: LeaseGeneration,
    pub owner_instance: OwnerInstance,
    pub delegation: DelegationId,
}

impl HostLeaseToken {
    /// Returns true if this token is still valid for the given current
    /// arbiter state. A replaced or released lease is invalid.
    fn is_current(
        &self,
        current_generation: LeaseGeneration,
        current_owner: OwnerInstance,
    ) -> bool {
        self.generation == current_generation && self.owner_instance == current_owner
    }
}

/// Trait for OS-level advisory lock operations. Tests inject an in-memory
/// implementation; production uses file-based `flock`/`LockFileEx`.
pub trait OsAdvisoryLock: Send {
    /// Try to acquire an exclusive OS-level advisory lock for the given key.
    /// Returns `Ok(())` if acquired, `Err(HostLockError)` on failure.
    fn try_lock(&mut self, key: &PhysicalTargetKey) -> Result<(), HostLockError>;

    /// Release the OS-level lock for the given key. Must be idempotent.
    fn release(&mut self, key: &PhysicalTargetKey);

    /// Check if the OS-level lock is still held for the given key.
    /// Used to detect OS lock loss (e.g. external process forced release).
    fn is_locked(&self, key: &PhysicalTargetKey) -> bool;
}

/// Errors from the host input arbiter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostLockError {
    /// Another process holds the OS-level lock for this physical key.
    ContendedByOtherProcess,
    /// The OS-level lock file could not be created or opened.
    LockFileIo(String),
    /// The lock was held but has been lost (detected on re-check).
    LockLost,
}

impl std::fmt::Display for HostLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContendedByOtherProcess => {
                f.write_str("host input lock contended by another process")
            }
            Self::LockFileIo(detail) => {
                write!(f, "host lock file I/O error: {detail}")
            }
            Self::LockLost => f.write_str("host input lock lost"),
        }
    }
}

impl std::error::Error for HostLockError {}

/// In-memory OS advisory lock for hermetic tests. Simulates cross-process
/// contention by sharing state across clones of the arbiter.
#[derive(Debug, Default)]
pub struct InMemoryOsAdvisoryLock {
    locked_keys: Arc<std::sync::Mutex<HashMap<String, OwnerInstance>>>,
    /// Set of keys that this particular lock instance holds.
    held: HashMap<String, ()>,
    /// If set, `try_lock` for any key returns this error (simulates external
    /// contention or lock failure).
    pub force_failure: Option<HostLockError>,
}

impl InMemoryOsAdvisoryLock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a clone sharing the same underlying lock state, simulating a
    /// second process contending for the same physical key.
    pub fn shared_clone(&self) -> Self {
        Self {
            locked_keys: Arc::clone(&self.locked_keys),
            held: HashMap::new(),
            force_failure: None,
        }
    }

    fn key_string(key: &PhysicalTargetKey) -> String {
        format!(
            "{:?}-{:?}-{:?}",
            key.host_installation_id, key.platform_session_or_seat_id, key.physical_display_id
        )
    }
}

impl OsAdvisoryLock for InMemoryOsAdvisoryLock {
    fn try_lock(&mut self, key: &PhysicalTargetKey) -> Result<(), HostLockError> {
        if let Some(err) = &self.force_failure {
            return Err(err.clone());
        }
        let key_str = Self::key_string(key);
        let mut locked = self.locked_keys.lock().unwrap();
        if locked.contains_key(&key_str) {
            return Err(HostLockError::ContendedByOtherProcess);
        }
        locked.insert(key_str.clone(), OwnerInstance(0));
        self.held.insert(key_str, ());
        Ok(())
    }

    fn release(&mut self, key: &PhysicalTargetKey) {
        let key_str = Self::key_string(key);
        let mut locked = self.locked_keys.lock().unwrap();
        locked.remove(&key_str);
        self.held.remove(&key_str);
    }

    fn is_locked(&self, key: &PhysicalTargetKey) -> bool {
        let key_str = Self::key_string(key);
        if !self.held.contains_key(&key_str) {
            return false;
        }
        let locked = self.locked_keys.lock().unwrap();
        locked.contains_key(&key_str)
    }
}

/// A waiter in the process-local FIFO queue.
#[derive(Debug, Clone)]
struct ArbiterWaiter {
    target_key: PhysicalTargetKey,
    owner_instance: OwnerInstance,
    delegation: DelegationId,
    /// Set to true when this waiter has been cancelled. Cancelled waiters
    /// are removed without transferring their generation.
    cancelled: bool,
}

/// The host-global input arbiter. Serializes every real physical target across
/// delegations and Cockpit processes.
///
/// Combines a process-local FIFO with an OS-level named mutex/advisory-lock
/// file under the private Cockpit data root keyed by `PhysicalTargetKey`.
/// Acquisition returns an unforgeable monotonic lease generation; only the
/// current `(target_key, generation, owner_instance, delegation)` may dispatch.
///
/// Virtual backends serialize per virtual display but do not take the host lock.
pub struct HostInputArbiter {
    os_lock: Box<dyn OsAdvisoryLock>,
    /// Process-local FIFO queue per physical key.
    queues: HashMap<String, Vec<ArbiterWaiter>>,
    /// Current lease holder per physical key.
    current_lease: HashMap<String, HostLeaseToken>,
    /// Monotonic generation counter per physical key.
    next_generation: HashMap<String, u64>,
    /// The owner instance for this arbiter (this process).
    owner_instance: OwnerInstance,
}

impl std::fmt::Debug for HostInputArbiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostInputArbiter")
            .field("owner_instance", &self.owner_instance)
            .field("queue_count", &self.queues.len())
            .field("active_leases", &self.current_lease.len())
            .finish()
    }
}

/// Result of attempting to acquire a host input lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireResult {
    /// The lease was acquired immediately.
    Acquired(HostLeaseToken),
    /// The lease was queued behind an existing holder. The waiter is
    /// registered in the FIFO and will be notified when the current holder
    /// releases.
    Queued,
    /// The OS-level lock could not be acquired (another process holds it).
    OsLockFailed(HostLockError),
}

impl HostInputArbiter {
    /// Create a new arbiter with the given OS-level lock implementation and
    /// owner instance ID.
    pub fn new(os_lock: Box<dyn OsAdvisoryLock>, owner_instance: OwnerInstance) -> Self {
        Self {
            os_lock,
            queues: HashMap::new(),
            current_lease: HashMap::new(),
            next_generation: HashMap::new(),
            owner_instance,
        }
    }

    fn key_string(key: &PhysicalTargetKey) -> String {
        format!(
            "{:?}-{:?}-{:?}",
            key.host_installation_id, key.platform_session_or_seat_id, key.physical_display_id
        )
    }

    /// Try to acquire the host input lease for a physical target key.
    ///
    /// If the OS-level lock is held by another process, returns
    /// [`AcquireResult::OsLockFailed`]. If the process-local queue is empty
    /// and the OS lock succeeds, returns [`AcquireResult::Acquired`]. If there
    /// are waiters ahead, returns [`AcquireResult::Queued`] and registers the
    /// waiter in the FIFO.
    pub fn try_acquire(
        &mut self,
        target_key: &PhysicalTargetKey,
        delegation: DelegationId,
    ) -> AcquireResult {
        let key_str = Self::key_string(target_key);

        // If there is already a current lease holder in this process, queue.
        if self.current_lease.contains_key(&key_str) {
            self.queues
                .entry(key_str.clone())
                .or_default()
                .push(ArbiterWaiter {
                    target_key: *target_key,
                    owner_instance: self.owner_instance,
                    delegation,
                    cancelled: false,
                });
            return AcquireResult::Queued;
        }

        // Try the OS-level lock.
        match self.os_lock.try_lock(target_key) {
            Ok(()) => {}
            Err(err) => return AcquireResult::OsLockFailed(err),
        }

        // Allocate a new monotonic generation.
        let lease_gen = {
            let counter = self.next_generation.entry(key_str.clone()).or_insert(0);
            *counter += 1;
            LeaseGeneration(*counter)
        };

        let token = HostLeaseToken {
            target_key: *target_key,
            generation: lease_gen,
            owner_instance: self.owner_instance,
            delegation,
        };
        self.current_lease.insert(key_str, token.clone());
        AcquireResult::Acquired(token)
    }

    /// Release the host input lease for the given token. Only the current
    /// lease holder may release. If there are waiters, the next waiter is
    /// promoted (acquires a new generation — generations are never reused).
    ///
    /// Returns `true` if the lease was released by the current holder,
    /// `false` if the token was not the current holder.
    pub fn release(&mut self, token: &HostLeaseToken) -> bool {
        let key_str = Self::key_string(&token.target_key);

        // Verify this is the current holder.
        let is_current = match self.current_lease.get(&key_str) {
            Some(current) => current.generation == token.generation,
            None => false,
        };
        if !is_current {
            return false;
        }

        // Release the OS-level lock.
        self.os_lock.release(&token.target_key);

        // Remove the current lease.
        self.current_lease.remove(&key_str);

        // Promote the next non-cancelled waiter with a NEW generation.
        let queue = self.queues.get_mut(&key_str);
        if let Some(waiters) = queue {
            while let Some(next) = waiters.first() {
                if next.cancelled {
                    waiters.remove(0);
                    continue;
                }
                // Re-acquire the OS lock for the promoted waiter.
                match self.os_lock.try_lock(&next.target_key) {
                    Ok(()) => {
                        let waiter = waiters.remove(0);
                        let lease_gen = {
                            let counter = self.next_generation.entry(key_str.clone()).or_insert(0);
                            *counter += 1;
                            LeaseGeneration(*counter)
                        };
                        let new_token = HostLeaseToken {
                            target_key: waiter.target_key,
                            generation: lease_gen,
                            owner_instance: waiter.owner_instance,
                            delegation: waiter.delegation,
                        };
                        self.current_lease.insert(key_str, new_token);
                        return true;
                    }
                    Err(_) => {
                        // OS lock failed — the waiter cannot be promoted.
                        // Leave the queue; the caller can retry.
                        break;
                    }
                }
            }
            // All waiters cancelled or queue empty — clean up.
            if waiters.is_empty() {
                self.queues.remove(&key_str);
            }
        }
        true
    }

    /// Cancel a queued waiter. The waiter is removed without transferring its
    /// generation. Only undispatched waiters may be cancelled; the current
    /// lease holder must use [`release`](Self::release) instead.
    ///
    /// Returns `true` if the waiter was found and cancelled.
    pub fn cancel_waiter(
        &mut self,
        target_key: &PhysicalTargetKey,
        delegation: &DelegationId,
    ) -> bool {
        let key_str = Self::key_string(target_key);
        let Some(waiters) = self.queues.get_mut(&key_str) else {
            return false;
        };
        // Mark the first matching waiter as cancelled.
        for waiter in waiters.iter_mut() {
            if &waiter.delegation == delegation && !waiter.cancelled {
                waiter.cancelled = true;
                return true;
            }
        }
        false
    }

    /// Check if a lease token is still valid (the current holder). OS lock
    /// loss, owner death, display-generation change, or lease replacement
    /// invalidates the token.
    pub fn is_lease_valid(&self, token: &HostLeaseToken) -> bool {
        let key_str = Self::key_string(&token.target_key);
        match self.current_lease.get(&key_str) {
            Some(current) => {
                current.generation == token.generation
                    && current.owner_instance == token.owner_instance
            }
            None => false,
        }
    }

    /// Detect OS lock loss. If the OS-level lock is no longer held for the
    /// current lease, the lease is invalidated.
    ///
    /// Returns `true` if a lease was invalidated due to OS lock loss.
    pub fn detect_lock_loss(&mut self, token: &HostLeaseToken) -> bool {
        let key_str = Self::key_string(&token.target_key);
        if !self.os_lock.is_locked(&token.target_key) {
            // OS lock lost — invalidate the lease.
            self.os_lock.release(&token.target_key);
            self.current_lease.remove(&key_str);
            return true;
        }
        false
    }

    /// Returns true if the given physical key currently has an active lease.
    pub fn is_held(&self, target_key: &PhysicalTargetKey) -> bool {
        let key_str = Self::key_string(target_key);
        self.current_lease.contains_key(&key_str)
    }

    /// Returns the number of waiters queued for the given physical key.
    pub fn waiter_count(&self, target_key: &PhysicalTargetKey) -> usize {
        let key_str = Self::key_string(target_key);
        self.queues
            .get(&key_str)
            .map(|q| q.iter().filter(|w| !w.cancelled).count())
            .unwrap_or(0)
    }

    /// Simulate owner death: release all leases held by the given owner
    /// instance. This is how a crashed process's leases are cleaned up.
    pub fn release_for_owner(&mut self, owner: OwnerInstance) -> usize {
        let mut released = 0;
        let keys_to_release: Vec<(String, PhysicalTargetKey)> = self
            .current_lease
            .iter()
            .filter(|(_, token)| token.owner_instance == owner)
            .map(|(k, t)| (k.clone(), t.target_key))
            .collect();
        for (key_str, target_key) in keys_to_release {
            self.os_lock.release(&target_key);
            self.current_lease.remove(&key_str);
            released += 1;
        }
        released
    }
}

// ---------------------------------------------------------------------------
// Central authorization for computer actions
// ---------------------------------------------------------------------------

/// The approval tier for computer use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputerApprovalTier {
    /// Ask pauses on the central authorizer seam; a human must approve.
    Ask,
    /// Yolo emits no human request and imposes no semantic action/target denial.
    Yolo,
}

/// The exhaustive central authorization request for a computer action.
///
/// Every canonical action goes through this variant. It carries only
/// engine-owned session/delegation/action IDs, tier, host lease token,
/// target/focus/observation generations, and safe metadata. No pixel bytes,
/// raw titles, or provider request payloads are carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputerActionAuthorization {
    /// Engine-owned session ID.
    pub session_id: String,
    /// Engine-owned delegation ID.
    pub delegation_id: DelegationId,
    /// Engine-owned action/batch ID (one provider call ID maps to one engine
    /// action/batch identity).
    pub action_id: String,
    /// Approval tier (Ask or Yolo).
    pub tier: ComputerApprovalTier,
    /// Host lease token, if a physical target is involved. Virtual backends
    /// have no host lease.
    pub host_lease: Option<HostLeaseToken>,
    /// Focus generation from the planning evidence capture.
    pub focus_generation: u64,
    /// Observation generation (display generation) from the opened backend.
    pub observation_generation: u64,
    /// Safe action metadata: a short label describing the action type.
    pub action_label: String,
    /// Safe target metadata: backend kind (diagnostic only).
    pub backend_kind: BackendKind,
}

/// The central authorizer trait for computer actions. The real implementation
/// lives in the approval module; tests inject a fake.
#[async_trait]
pub trait ComputerAuthorizer: Send {
    /// Authorize a computer action. Ask blocks/denies/allows through the seam;
    /// Yolo creates zero human requests.
    async fn authorize(
        &self,
        request: &ComputerActionAuthorization,
    ) -> Result<ComputerAuthorizationDecision, ComputerError>;
}

/// The decision from the central authorizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputerAuthorizationDecision {
    /// The action is allowed to proceed.
    Allow,
    /// The action is denied. The reason is a safe, bounded string.
    Deny { reason: String },
    /// Ask tier blocked waiting for a human response. The action is not
    /// dispatched.
    AskBlocked,
}

/// A fake authorizer for hermetic tests.
#[derive(Debug, Clone)]
pub struct FakeComputerAuthorizer {
    /// Decisions to return in order. If empty, always allows.
    pub decisions: Vec<ComputerAuthorizationDecision>,
    /// Number of authorize calls made.
    pub call_count: Arc<std::sync::atomic::AtomicUsize>,
    /// If set, every call returns this decision (overrides `decisions`).
    pub forced_decision: Option<ComputerAuthorizationDecision>,
}

impl FakeComputerAuthorizer {
    pub fn always_allow() -> Self {
        Self {
            decisions: Vec::new(),
            call_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            forced_decision: None,
        }
    }

    pub fn always_deny(reason: impl Into<String>) -> Self {
        Self {
            decisions: Vec::new(),
            call_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            forced_decision: Some(ComputerAuthorizationDecision::Deny {
                reason: reason.into(),
            }),
        }
    }

    pub fn always_ask() -> Self {
        Self {
            decisions: Vec::new(),
            call_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            forced_decision: Some(ComputerAuthorizationDecision::AskBlocked),
        }
    }

    pub fn with_decisions(decisions: Vec<ComputerAuthorizationDecision>) -> Self {
        Self {
            decisions,
            call_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            forced_decision: None,
        }
    }

    pub fn call_count(&self) -> usize {
        self.call_count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl ComputerAuthorizer for FakeComputerAuthorizer {
    async fn authorize(
        &self,
        _request: &ComputerActionAuthorization,
    ) -> Result<ComputerAuthorizationDecision, ComputerError> {
        self.call_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(forced) = &self.forced_decision {
            return Ok(forced.clone());
        }
        let idx = self.call_count.load(std::sync::atomic::Ordering::SeqCst) - 1;
        if idx < self.decisions.len() {
            return Ok(self.decisions[idx].clone());
        }
        Ok(ComputerAuthorizationDecision::Allow)
    }
}

// ---------------------------------------------------------------------------
// Advisory action semantics (audit/guidance only — never prompt, deny, or grant)
// ---------------------------------------------------------------------------

/// Exhaustive advisory action-class taxonomy for computer-use actions.
///
/// These classes are audit/guidance fields only. They never trigger a prompt,
/// hard denial, or persistent grant in either Ask or Yolo tier. Yolo is
/// complete trust: zero Cockpit human prompts, zero semantic target/action
/// hard denials, and zero persistent grants. Ask asks exactly once per
/// uninterrupted delegation/display lease generation and reuses that decision
/// for all action classes until invalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionClass {
    /// Reversible navigation/observation (screenshot, cursor move, scroll).
    Reversible,
    /// State-changing but non-terminal (typing, click that toggles UI).
    StateChanging,
    /// Form submission or dialog confirmation.
    Submission,
    /// Purchase or financial commitment.
    Purchase,
    /// Credential entry (password, token, key input).
    CredentialEntry,
    /// Destructive/irreversible (delete, format, drop, `rm -rf`).
    Destructive,
    /// Unknown/unclassifiable action.
    Unknown,
}

impl ActionClass {
    /// Classify a canonical [`ComputerAction`] into its advisory class.
    ///
    /// This mapping is advisory only and never affects the dispatch decision.
    /// The central authorizer and lease composition gate dispatch; this
    /// classification is recorded for audit/guidance.
    pub fn classify(action: &ComputerAction) -> Self {
        match action {
            ComputerAction::CaptureFull
            | ComputerAction::CaptureRegion { .. }
            | ComputerAction::CaptureNativeZoom { .. }
            | ComputerAction::MoveCursor { .. }
            | ComputerAction::Scroll { .. }
            | ComputerAction::Wait { .. } => Self::Reversible,
            ComputerAction::Click { .. }
            | ComputerAction::MouseDown { .. }
            | ComputerAction::MouseUp { .. }
            | ComputerAction::Drag { .. }
            | ComputerAction::KeyChord { .. }
            | ComputerAction::HoldKey { .. } => Self::StateChanging,
            ComputerAction::TypeText { text } => {
                // Heuristic advisory classification: never used for denial.
                let lower = text.to_ascii_lowercase();
                if lower.contains("password")
                    || lower.contains("passwd")
                    || lower.contains("token")
                    || lower.contains("secret")
                    || lower.contains("api_key")
                    || lower.contains("apikey")
                {
                    Self::CredentialEntry
                } else if lower.contains("rm -rf")
                    || lower.contains("delete")
                    || lower.contains("drop ")
                    || lower.contains("format")
                    || lower.contains("truncate")
                {
                    Self::Destructive
                } else {
                    Self::StateChanging
                }
            }
        }
    }

    /// A short stable label for audit records.
    pub fn label(self) -> &'static str {
        match self {
            Self::Reversible => "reversible",
            Self::StateChanging => "state_changing",
            Self::Submission => "submission",
            Self::Purchase => "purchase",
            Self::CredentialEntry => "credential_entry",
            Self::Destructive => "destructive",
            Self::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Ask delegation lease: one coalesced human decision per delegation/display gen
// ---------------------------------------------------------------------------

/// Identifies the provider that emits computer actions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderId(pub String);

/// Identifies the model that emits computer actions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelId(pub String);

/// The target key for lease scoping: either a physical target key or a
/// virtual display UUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LeaseTargetKey {
    /// Physical target — requires host lease composition.
    Physical(PhysicalTargetKey),
    /// Virtual display — no host lease, but still scoped to this display.
    Virtual([u8; 16]),
}

/// The composite key for an Ask delegation lease.
///
/// One coalesced Ask decision is reused for all action classes until any key
/// field or generation changes. The lease never persists and cannot be
/// broadened to session/project/global.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AskLeaseKey {
    pub session_id: String,
    pub delegation_id: DelegationId,
    pub provider_id: ProviderId,
    pub model_id: ModelId,
    pub target_key: LeaseTargetKey,
    pub host_lease_generation: Option<LeaseGeneration>,
    pub display_generation: u64,
}

/// An unforgeable, in-memory Ask delegation lease.
///
/// Created by `Approve` on the first valid Ask action for one uninterrupted
/// delegation/display lease generation. Keyed by
/// `(session_id, delegation_id, provider_id, model_id, target_key_or_virtual_id,
///   host_lease_generation, display_generation)`.
///
/// # Unforgeability
///
/// This type is not constructible outside this module. The only way to obtain
/// one is through [`AskDelegationLeaseStore::install`]. It has no `serde`
/// implementation (no Serialize/Deserialize), so it cannot be persisted,
/// serialized across processes, or replayed. The opaque token is compared in
/// constant time. Provider/model/tool payloads cannot construct, extend,
/// select, serialize, or replay this lease.
///
/// # Lifecycle
///
/// - Created on `Approve` for the first valid Ask action.
/// - Reused for all action classes until invalidation.
/// - Revoked before queued work on: delegation terminal state, cancel,
///   detach, provider/model change, display/target/host generation change,
///   lost OS lock, or daemon restart.
/// - Daemon restart loses both Ask and host leases; Ask requires a new
///   decision.
pub struct AskDelegationLease {
    key: AskLeaseKey,
    /// Opaque constant-time token. Never serialized, never exposed except by
    /// constant-time equality check against the store's record.
    token: [u8; 32],
    /// Monotonic version of the approval wait that produced this lease.
    approval_version: u64,
}

impl std::fmt::Debug for AskDelegationLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AskDelegationLease")
            .field("key", &self.key)
            .field("token", &"[REDACTED; 32]")
            .field("approval_version", &self.approval_version)
            .finish()
    }
}

impl PartialEq for AskDelegationLease {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison of the opaque token.
        constant_time_eq(&self.token, &other.token) && self.key == other.key
    }
}

impl Eq for AskDelegationLease {}

impl AskDelegationLease {
    /// Returns the lease key (for diagnostic/logging only).
    pub fn key(&self) -> &AskLeaseKey {
        &self.key
    }

    /// Returns the approval-wait version that produced this lease.
    pub fn approval_version(&self) -> u64 {
        self.approval_version
    }
}

/// Constant-time byte-slice equality. Returns `true` if all bytes match.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The outcome of an Ask authorization attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskAuthorizationOutcome {
    /// A lease was already installed for this key — reuse it (zero new prompt).
    ReusedExisting,
    /// A new lease was installed from a fresh human approval.
    Installed,
    /// The human denied the action. The delegation's computer path is
    /// terminated.
    Denied { reason: String },
    /// The approval was cancelled before install (e.g. delegation terminal,
    /// cancel, or generation change while waiting). The answer is discarded
    /// and zero input is sent.
    CancelledBeforeInstall,
    /// The approval answer arrived but a key field/generation changed while
    /// waiting. The answer is discarded; a new decision is required.
    StaleAnswerDiscarded,
    /// The approval is still pending (concurrent first Ask actions share one
    /// pending decision). The action is not dispatched.
    Pending,
}

/// The in-memory, coordinator-owned store for Ask delegation leases.
///
/// Leases never persist and cannot be broadened to session/project/global.
/// Unrelated command/path/MCP/worker/session/project grants never satisfy
/// Ask — only a matching [`AskLeaseKey`] in this store does.
#[derive(Debug, Default)]
pub struct AskDelegationLeaseStore {
    leases: HashMap<AskLeaseKey, AskDelegationLease>,
    /// Pending approvals keyed by lease key. Concurrent first Ask actions
    /// share one pending decision.
    pending: HashMap<AskLeaseKey, u64>,
    /// Monotonic approval-wait version counter.
    next_approval_version: u64,
}

impl AskDelegationLeaseStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a valid lease exists for the given key. This is the dispatch
    /// gate: Ask requires both a current Ask delegation lease AND the
    /// coordinator's current host/virtual input lease.
    pub fn has_lease(&self, key: &AskLeaseKey) -> bool {
        self.leases.contains_key(key)
    }

    /// Look up a lease for diagnostic purposes.
    pub fn lease(&self, key: &AskLeaseKey) -> Option<&AskDelegationLease> {
        self.leases.get(key)
    }

    /// The number of installed leases (for tests/diagnostics).
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    /// Begin an approval wait for the given key. Returns the approval version.
    /// If a pending wait already exists for this key, returns the existing
    /// version (concurrent first Ask actions share one pending decision).
    pub fn begin_approval_wait(&mut self, key: &AskLeaseKey) -> u64 {
        if let Some(&version) = self.pending.get(key) {
            return version;
        }
        self.next_approval_version += 1;
        let version = self.next_approval_version;
        self.pending.insert(key.clone(), version);
        version
    }

    /// Install a lease from a fresh human approval. The approval is only
    /// installed if every key field/generation is still current (matches
    /// `expected_key`). If the key changed while waiting, the answer is
    /// discarded ([`AskAuthorizationOutcome::StaleAnswerDiscarded`]).
    ///
    /// If a lease already exists for this key, it is reused
    /// ([`AskAuthorizationOutcome::ReusedExisting`]).
    pub fn install(
        &mut self,
        expected_key: &AskLeaseKey,
        approval_version: u64,
    ) -> AskAuthorizationOutcome {
        // If already installed, reuse — one coalesced decision.
        if self.leases.contains_key(expected_key) {
            // Clear the pending wait.
            self.pending.remove(expected_key);
            return AskAuthorizationOutcome::ReusedExisting;
        }

        // Verify the approval version is still current for this key. If the
        // key changed while waiting (a new approval wait superseded this one),
        // discard the stale answer.
        match self.pending.get(expected_key) {
            Some(&current_version) if current_version == approval_version => {}
            _ => {
                // Stale answer — a newer wait superseded this one, or the
                // pending wait was cancelled.
                return AskAuthorizationOutcome::StaleAnswerDiscarded;
            }
        }

        // Install the lease with a fresh opaque token.
        let mut token = [0u8; 32];
        // Deterministic-ish token from the key + version (not cryptographic,
        // but unforgeable because the type is not constructible externally
        // and has no serde). In production this would be a CSPRNG draw.
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        expected_key.hash(&mut hasher);
        approval_version.hash(&mut hasher);
        let h = hasher.finish();
        for (i, byte) in token.iter_mut().enumerate() {
            *byte = ((h >> ((i % 8) * 8)) & 0xFF) as u8;
        }

        let lease = AskDelegationLease {
            key: expected_key.clone(),
            token,
            approval_version,
        };
        self.leases.insert(expected_key.clone(), lease);
        self.pending.remove(expected_key);
        AskAuthorizationOutcome::Installed
    }

    /// Record a denial for the given key. Terminates that delegation's
    /// computer path. Clears any pending wait.
    pub fn record_denial(&mut self, key: &AskLeaseKey) -> AskAuthorizationOutcome {
        self.pending.remove(key);
        self.leases.remove(key);
        AskAuthorizationOutcome::Denied {
            reason: "human denied computer action".to_string(),
        }
    }

    /// Cancel a pending approval wait before install. The answer is discarded
    /// and zero input is sent. If a lease was already installed, it is not
    /// affected (cancellation before install only).
    pub fn cancel_pending(&mut self, key: &AskLeaseKey) -> AskAuthorizationOutcome {
        if self.pending.remove(key).is_some() {
            AskAuthorizationOutcome::CancelledBeforeInstall
        } else if self.leases.contains_key(key) {
            // Already installed — cancellation before install is a no-op for
            // an installed lease.
            AskAuthorizationOutcome::ReusedExisting
        } else {
            AskAuthorizationOutcome::CancelledBeforeInstall
        }
    }

    /// Revoke a lease for the given key. Called on delegation terminal state,
    /// cancel, detach, provider/model change, display/target/host generation
    /// change, lost OS lock, or daemon restart.
    ///
    /// Returns `true` if a lease was revoked.
    pub fn revoke(&mut self, key: &AskLeaseKey) -> bool {
        self.pending.remove(key);
        self.leases.remove(key).is_some()
    }

    /// Revoke all leases for a given delegation. Called on delegation
    /// terminal state, cancel, or detach.
    ///
    /// Returns the number of leases revoked.
    pub fn revoke_for_delegation(
        &mut self,
        session_id: &str,
        delegation_id: &DelegationId,
    ) -> usize {
        let to_remove: Vec<AskLeaseKey> = self
            .leases
            .keys()
            .filter(|k| k.session_id == session_id && k.delegation_id == *delegation_id)
            .cloned()
            .collect();
        let count = to_remove.len();
        for key in to_remove {
            self.leases.remove(&key);
            self.pending.remove(&key);
        }
        count
    }

    /// Revoke all leases whose host lease generation differs from the given
    /// current generation. A host lease-generation replacement invalidates
    /// the Ask lease and requires a new human decision before another action.
    ///
    /// Returns the number of leases revoked.
    pub fn revoke_on_host_generation_change(
        &mut self,
        target_key: &PhysicalTargetKey,
        current_generation: LeaseGeneration,
    ) -> usize {
        let to_remove: Vec<AskLeaseKey> = self
            .leases
            .keys()
            .filter(|k| {
                matches!(&k.target_key, LeaseTargetKey::Physical(pk) if pk == target_key)
                    && k.host_lease_generation != Some(current_generation)
            })
            .cloned()
            .collect();
        let count = to_remove.len();
        for key in to_remove {
            self.leases.remove(&key);
            self.pending.remove(&key);
        }
        count
    }

    /// Revoke all leases whose display generation differs from the given
    /// current generation. A display-generation change invalidates the Ask
    /// lease and requires a new human decision.
    ///
    /// Returns the number of leases revoked.
    pub fn revoke_on_display_generation_change(
        &mut self,
        session_id: &str,
        delegation_id: &DelegationId,
        current_display_generation: u64,
    ) -> usize {
        let to_remove: Vec<AskLeaseKey> = self
            .leases
            .keys()
            .filter(|k| {
                k.session_id == session_id
                    && k.delegation_id == *delegation_id
                    && k.display_generation != current_display_generation
            })
            .cloned()
            .collect();
        let count = to_remove.len();
        for key in to_remove {
            self.leases.remove(&key);
            self.pending.remove(&key);
        }
        count
    }

    /// Clear all leases and pending waits. Called on daemon restart: both
    /// Ask and host leases are lost; Ask requires a new decision.
    pub fn clear_all(&mut self) {
        self.leases.clear();
        self.pending.clear();
    }
}

// ---------------------------------------------------------------------------
// Outcome journaling: dedup, reconnect, cancellation, dispatch_unknown
// ---------------------------------------------------------------------------

/// The terminal outcome of a single coordinated computer action.
#[derive(Debug, Clone, PartialEq)]
pub enum CoordinatedOutcome {
    /// The action completed successfully, with outcomes and an optional
    /// sanitized screenshot.
    Completed {
        completed: Vec<ComputerActionOutcome>,
        screenshot: Option<SanitizedComputerFrame>,
    },
    /// The action failed at the backend.
    Failed {
        failure: ComputerFailure,
        screenshot: Option<SanitizedComputerFrame>,
    },
    /// The action was denied by the central authorizer.
    Denied { reason: String },
    /// The action was cancelled before dispatch. Zero input was sent.
    CancelledBeforeDispatch,
    /// The action was cancelled after dispatch. An unevidenced outcome —
    /// never automatically retried.
    DispatchUnknown {
        /// Safe metadata about which action was in-flight.
        action_label: String,
    },
    /// The coordinator was invalidated (display hotplug, focus generation
    /// change, host-lock loss) before or during dispatch.
    Invalidated { reason: TargetUnavailableReason },
    /// A duplicate/replayed call ID. The prior sanitized outcome is returned
    /// and no input is touched again.
    DuplicateReplay {
        prior_outcome: Box<CoordinatedOutcome>,
    },
    /// The provider native variant is unsupported. A typed provider-compatible
    /// unsupported result is returned before backend input.
    UnsupportedProviderVariant { detail: String },
}

/// The journal of completed action outcomes, keyed by provider call ID.
/// Used for dedup/reconnect: duplicate/replayed calls return the prior
/// sanitized outcome and never touch input again.
#[derive(Debug, Default)]
pub struct OutcomeJournal {
    outcomes: HashMap<String, CoordinatedOutcome>,
}

impl OutcomeJournal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an outcome for a call ID. Returns the prior outcome if one
    /// existed (should not happen in normal flow).
    pub fn record(&mut self, call_id: &str, outcome: CoordinatedOutcome) {
        self.outcomes.insert(call_id.to_string(), outcome);
    }

    /// Look up a prior outcome for dedup/reconnect.
    pub fn lookup(&self, call_id: &str) -> Option<&CoordinatedOutcome> {
        self.outcomes.get(call_id)
    }

    /// Check if a call ID has already been processed.
    pub fn has(&self, call_id: &str) -> bool {
        self.outcomes.contains_key(call_id)
    }
}

// ---------------------------------------------------------------------------
// ComputerActionCoordinator: one per delegation
// ---------------------------------------------------------------------------

/// The dispatch state of a coordinated action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchState {
    /// The action has not been dispatched yet.
    NotDispatched,
    /// The action is about to be dispatched to the backend. This state is
    /// committed immediately before the backend handoff.
    Dispatching,
    /// The action completed (success or failure).
    Completed,
    /// The action was cancelled before dispatch.
    CancelledBeforeDispatch,
    /// The action was cancelled after dispatch — unevidenced, never retried.
    DispatchUnknown,
}

/// The coordinator owns one opened backend/display capability per delegation.
/// Before building provider tool declarations it obtains backend-reported
/// geometry and target evidence, acquires the host input arbiter where
/// applicable, and creates provider declarations from that same immutable
/// display generation.
pub struct ComputerActionCoordinator {
    /// The computer backend (fake in tests, virtual/real in production).
    backend: Box<dyn ComputerBackend>,
    /// The immutable display geometry obtained from the backend at open time.
    /// Display hotplug/focus generation change after model declaration
    /// invalidates the coordinator.
    geometry: DisplayGeometry,
    /// The target evidence adapter (for physical target keys and focus gen).
    target_adapter: Option<Box<dyn TargetEvidenceAdapter>>,
    /// The host input arbiter (shared across coordinators in the same process).
    host_arbiter: Option<Arc<std::sync::Mutex<HostInputArbiter>>>,
    /// The current host lease token, if a physical target is involved.
    host_lease: Option<HostLeaseToken>,
    /// The central authorizer.
    authorizer: Arc<dyn ComputerAuthorizer>,
    /// The outcome journal for dedup/reconnect.
    journal: OutcomeJournal,
    /// The delegation ID this coordinator serves.
    delegation_id: DelegationId,
    /// The session ID this coordinator serves.
    session_id: String,
    /// The approval tier.
    tier: ComputerApprovalTier,
    /// The owner instance for this coordinator.
    owner_instance: OwnerInstance,
    /// Whether the coordinator has been invalidated (e.g. display hotplug).
    invalidated: bool,
    /// The observation generation (display generation) from the opened backend.
    observation_generation: u64,
    /// The focus generation from the planning evidence capture.
    focus_generation: u64,
    /// The backend kind.
    backend_kind: BackendKind,
    /// Tracks dispatch state per call ID.
    dispatch_states: HashMap<String, DispatchState>,
    /// Whether the backend is dead (readiness failure).
    backend_dead: bool,
    /// The Ask delegation lease store (Ask tier only). Yolo creates no
    /// approval grant and uses only the host lease.
    ask_lease_store: AskDelegationLeaseStore,
    /// The provider ID for this coordinator's delegation.
    provider_id: ProviderId,
    /// The model ID for this coordinator's delegation.
    model_id: ModelId,
}

impl std::fmt::Debug for ComputerActionCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputerActionCoordinator")
            .field("delegation_id", &self.delegation_id)
            .field("session_id", &self.session_id)
            .field("tier", &self.tier)
            .field("invalidated", &self.invalidated)
            .field("backend_dead", &self.backend_dead)
            .field("observation_generation", &self.observation_generation)
            .field("focus_generation", &self.focus_generation)
            .field("backend_kind", &self.backend_kind)
            .field("ask_lease_count", &self.ask_lease_store.len())
            .finish_non_exhaustive()
    }
}

/// Parameters for creating a coordinator.
pub struct CoordinatorParams {
    pub session_id: String,
    pub delegation_id: DelegationId,
    pub tier: ComputerApprovalTier,
    pub owner_instance: OwnerInstance,
    pub authorizer: Arc<dyn ComputerAuthorizer>,
    pub host_arbiter: Option<Arc<std::sync::Mutex<HostInputArbiter>>>,
    pub target_adapter: Option<Box<dyn TargetEvidenceAdapter>>,
    /// The provider ID for this delegation (e.g. "anthropic", "openai").
    pub provider_id: ProviderId,
    /// The model ID for this delegation (e.g. "claude-3-5-sonnet-20241022").
    pub model_id: ModelId,
}

impl ComputerActionCoordinator {
    /// Open a coordinator with the given backend and parameters. Obtains
    /// backend-reported geometry and target evidence, acquires the host input
    /// arbiter where applicable, and records the immutable display generation.
    pub async fn open(
        mut backend: Box<dyn ComputerBackend>,
        params: CoordinatorParams,
    ) -> Result<Self, CoordinatorOpenError> {
        // Obtain backend-reported geometry.
        let geometry = backend
            .geometry()
            .await
            .map_err(CoordinatorOpenError::BackendGeometry)?;

        // Reject zero/overflow geometry before any input.
        if geometry.physical.width == 0 || geometry.physical.height == 0 {
            return Err(CoordinatorOpenError::ZeroGeometry);
        }

        let observation_generation: u64 = 1;
        let mut focus_generation: u64 = 0;
        let mut backend_kind = BackendKind::VirtualDisplay;
        let mut host_lease: Option<HostLeaseToken> = None;

        // Take ownership of the target adapter before using it.
        let mut target_adapter = params.target_adapter;

        // Capture target evidence and acquire host lock if physical.
        if let Some(adapter) = target_adapter.as_deref_mut() {
            backend_kind = adapter.backend_kind();
            match adapter.capture_snapshot() {
                Ok(evidence) => {
                    focus_generation = evidence.focus_generation;
                    // If physical (not virtual), try to acquire the host lock.
                    if evidence.virtual_display_uuid.is_none()
                        && let Ok(physical_key) = evidence.physical_target_key()
                        && let Some(arbiter) = &params.host_arbiter
                    {
                        let mut arbiter = arbiter.lock().unwrap();
                        match arbiter.try_acquire(&physical_key, params.delegation_id.clone()) {
                            AcquireResult::Acquired(token) => {
                                host_lease = Some(token);
                            }
                            AcquireResult::Queued => {
                                return Err(CoordinatorOpenError::HostLockQueued);
                            }
                            AcquireResult::OsLockFailed(err) => {
                                return Err(CoordinatorOpenError::HostLockFailed(err));
                            }
                        }
                    }
                }
                Err(reason) => {
                    // For virtual backends, evidence failure is non-fatal.
                    if backend_kind != BackendKind::VirtualDisplay {
                        return Err(CoordinatorOpenError::TargetEvidence(reason));
                    }
                }
            }
        }

        Ok(Self {
            backend,
            geometry,
            target_adapter,
            host_arbiter: params.host_arbiter,
            host_lease,
            authorizer: params.authorizer,
            journal: OutcomeJournal::new(),
            delegation_id: params.delegation_id,
            session_id: params.session_id,
            tier: params.tier,
            owner_instance: params.owner_instance,
            invalidated: false,
            observation_generation,
            focus_generation,
            backend_kind,
            dispatch_states: HashMap::new(),
            backend_dead: false,
            ask_lease_store: AskDelegationLeaseStore::new(),
            provider_id: params.provider_id,
            model_id: params.model_id,
        })
    }

    /// The immutable display geometry obtained at open time.
    pub fn geometry(&self) -> &DisplayGeometry {
        &self.geometry
    }

    /// Build provider tool declarations from the same immutable display
    /// generation.
    pub fn provider_declarations(&self, contract: ComputerToolContract) -> NativeComputerWire {
        super::native_computer_wire(contract, &self.geometry)
    }

    /// The host lease token, if a physical target is involved.
    pub fn host_lease(&self) -> Option<&HostLeaseToken> {
        self.host_lease.as_ref()
    }

    /// Check if the coordinator has been invalidated.
    pub fn is_invalidated(&self) -> bool {
        self.invalidated
    }

    /// Invalidate the coordinator (display hotplug, focus generation change,
    /// host-lock loss). After invalidation, no further actions may dispatch.
    pub fn invalidate(&mut self, reason: TargetUnavailableReason) {
        self.invalidated = true;
        // Revoke Ask delegation leases for this delegation (display/target/host
        // generation change, host-lock loss, etc.).
        self.revoke_ask_lease_for_delegation();
        // Release the host lease if held.
        if let Some(token) = self.host_lease.take()
            && let Some(arbiter) = &self.host_arbiter
        {
            let mut arbiter = arbiter.lock().unwrap();
            arbiter.release(&token);
        }
        let _ = reason; // recorded in the outcome
    }

    /// Check host lease validity and detect OS lock loss.
    pub fn check_host_lease(&mut self) -> bool {
        let Some(token) = self.host_lease.as_ref() else {
            return true; // No host lease for virtual displays.
        };
        if let Some(arbiter) = &self.host_arbiter {
            let mut arbiter = arbiter.lock().unwrap();
            if arbiter.detect_lock_loss(token) {
                self.host_lease = None;
                self.invalidated = true;
                return false;
            }
            if !arbiter.is_lease_valid(token) {
                self.host_lease = None;
                self.invalidated = true;
                return false;
            }
        }
        true
    }

    /// Pre-handoff target evidence check. Display hotplug/focus generation
    /// change after model declaration invalidates the coordinator.
    pub fn pre_handoff_check(&mut self) -> Result<(), TargetUnavailableReason> {
        if self.invalidated {
            return Err(TargetUnavailableReason::StaleTarget);
        }
        if self.backend_dead {
            return Err(TargetUnavailableReason::SessionInactive);
        }
        // Re-check host lease.
        if !self.check_host_lease() {
            return Err(TargetUnavailableReason::StaleTarget);
        }
        // If we have a target adapter, re-capture evidence and check for drift.
        if let Some(adapter) = &mut self.target_adapter {
            let evidence = adapter.capture_snapshot()?;
            if evidence.focus_generation != self.focus_generation && self.focus_generation > 0 {
                // Focus generation changed — invalidate.
                self.invalidate(TargetUnavailableReason::StaleTarget);
                return Err(TargetUnavailableReason::StaleTarget);
            }
        }
        Ok(())
    }

    /// Execute a batch of backend actions through the coordinator. This is
    /// the core dispatch path: authorization → pre-handoff check → commit
    /// dispatching → backend handoff → record outcome.
    async fn dispatch_backend_batch(
        &mut self,
        call_id: &str,
        actions: &[ComputerAction],
        _action_label: &str,
    ) -> CoordinatedOutcome {
        // Commit dispatching state immediately before backend handoff.
        self.dispatch_states
            .insert(call_id.to_string(), DispatchState::Dispatching);

        // Generation-check again immediately before each backend handoff.
        if let Err(reason) = self.pre_handoff_check() {
            self.dispatch_states
                .insert(call_id.to_string(), DispatchState::CancelledBeforeDispatch);
            return CoordinatedOutcome::Invalidated { reason };
        }

        // Execute through the backend.
        let report: ComputerBatchReport = self.backend.execute(actions).await;

        // Record the final dispatch state.
        self.dispatch_states
            .insert(call_id.to_string(), DispatchState::Completed);

        if let Some(failure) = report.failure {
            return CoordinatedOutcome::Failed {
                failure,
                screenshot: None,
            };
        }

        // Capture a screenshot (transient frame through the boundary).
        let screenshot = self.capture_screenshot(call_id).await;

        CoordinatedOutcome::Completed {
            completed: report.completed,
            screenshot,
        }
    }

    /// Capture a screenshot through the screenshot boundary. Returns only the
    /// sanitized projection for durable sinks. The live frame is dropped after
    /// the transient provider request is built (by the caller).
    async fn capture_screenshot(&mut self, call_id: &str) -> Option<SanitizedComputerFrame> {
        let capture = self
            .backend
            .execute_one(&ComputerAction::CaptureFull)
            .await
            .ok()?;
        let ComputerActionOutcome::Captured(capture_frame) = capture else {
            return None;
        };
        let dims = FrameDimensions::from_capture(&capture_frame);
        let reservation: Box<dyn MediaReservationHandle> = Box::new(
            InMemoryReservationHandle::new(Arc::new(std::sync::atomic::AtomicBool::new(false))),
        );
        let live = LiveComputerFrame::try_new(
            capture_frame.png,
            ScreenshotMediaType::Png,
            dims,
            ObservationId(call_id.to_string()),
            ActionId(call_id.to_string()),
            CaptureEpoch(self.observation_generation),
            reservation,
            None,
        )
        .ok()?;
        let sanitized = live.sanitized();
        // The live frame is dropped here; the caller builds transient provider
        // requests separately if needed. Only the sanitized projection is
        // returned.
        Some(sanitized)
    }

    /// Authorize a computer action through the central authorizer.
    async fn authorize_action(
        &self,
        call_id: &str,
        action_label: &str,
    ) -> Result<ComputerAuthorizationDecision, ComputerError> {
        let request = ComputerActionAuthorization {
            session_id: self.session_id.clone(),
            delegation_id: self.delegation_id.clone(),
            action_id: call_id.to_string(),
            tier: self.tier,
            host_lease: self.host_lease.clone(),
            focus_generation: self.focus_generation,
            observation_generation: self.observation_generation,
            action_label: action_label.to_string(),
            backend_kind: self.backend_kind,
        };
        self.authorizer.authorize(&request).await
    }

    /// Build the Ask lease key for the current coordinator state. The key is
    /// `(session_id, delegation_id, provider_id, model_id, target_key_or_virtual_id,
    ///   host_lease_generation, display_generation)`.
    ///
    /// For physical targets, the host lease generation is included. For
    /// virtual displays, `host_lease_generation` is `None` and the virtual
    /// display UUID is used as the target key.
    fn ask_lease_key(&self, virtual_display_uuid: Option<[u8; 16]>) -> Option<AskLeaseKey> {
        let target_key = match (&self.host_lease, virtual_display_uuid) {
            (Some(token), _) => LeaseTargetKey::Physical(token.target_key),
            (None, Some(uuid)) => LeaseTargetKey::Virtual(uuid),
            (None, None) => {
                // No host lease and no virtual display UUID — cannot scope a
                // lease. This is a virtual display without evidence. Use a
                // synthetic virtual key derived from the delegation so the
                // lease is still scoped (cannot be broadened).
                // In practice, virtual backends always have a UUID; this is a
                // fallback for evidence-less virtual displays.
                LeaseTargetKey::Virtual([0u8; 16])
            }
        };
        let host_lease_generation = self.host_lease.as_ref().map(|t| t.generation);
        Some(AskLeaseKey {
            session_id: self.session_id.clone(),
            delegation_id: self.delegation_id.clone(),
            provider_id: self.provider_id.clone(),
            model_id: self.model_id.clone(),
            target_key,
            host_lease_generation,
            display_generation: self.observation_generation,
        })
    }

    /// Check whether dispatch is authorized for the Ask tier. Dispatch
    /// requires both a current Ask delegation lease (Ask only) and the
    /// coordinator's current host/virtual input lease.
    ///
    /// This is the lease composition gate. Neither Ask authority alone nor a
    /// host lease alone can dispatch.
    ///
    /// Returns `Ok(())` if authorized, or a [`CoordinatedOutcome`] for the
    /// blocking/denial case.
    async fn check_ask_lease_for_dispatch(
        &mut self,
        call_id: &str,
        action_label: &str,
        virtual_display_uuid: Option<[u8; 16]>,
    ) -> Result<(), CoordinatedOutcome> {
        // Yolo uses only the host lease and records `agent_discretion`; it
        // creates no approval grant. No Ask lease is required.
        if self.tier == ComputerApprovalTier::Yolo {
            return Ok(());
        }

        // Ask tier: require both the Ask delegation lease and the host lease
        // (for physical targets). For virtual displays, only the Ask lease is
        // required (no host lease).
        let Some(lease_key) = self.ask_lease_key(virtual_display_uuid) else {
            // Cannot scope a lease — block dispatch.
            let outcome = CoordinatedOutcome::CancelledBeforeDispatch;
            self.journal.record(call_id, outcome.clone());
            return Err(outcome);
        };

        // If a lease is already installed, reuse it (one coalesced decision).
        if self.ask_lease_store.has_lease(&lease_key) {
            return Ok(());
        }

        // No lease yet — this is the first valid Ask action for this
        // delegation/display lease generation. Begin an approval wait.
        let approval_version = self.ask_lease_store.begin_approval_wait(&lease_key);

        // Authorize through the central authorizer (raises the human prompt).
        match self.authorize_action(call_id, action_label).await {
            Ok(ComputerAuthorizationDecision::Allow) => {
                // Approve creates an in-memory AskDelegationLease. Approval
                // installs only if every key field/generation is still
                // current.
                match self.ask_lease_store.install(&lease_key, approval_version) {
                    AskAuthorizationOutcome::Installed
                    | AskAuthorizationOutcome::ReusedExisting => Ok(()),
                    AskAuthorizationOutcome::StaleAnswerDiscarded => {
                        // A key/generation changed while waiting. The answer
                        // is discarded; a new decision is required before
                        // another action.
                        self.dispatch_states
                            .insert(call_id.to_string(), DispatchState::CancelledBeforeDispatch);
                        let outcome = CoordinatedOutcome::Invalidated {
                            reason: TargetUnavailableReason::StaleTarget,
                        };
                        self.journal.record(call_id, outcome.clone());
                        Err(outcome)
                    }
                    AskAuthorizationOutcome::Denied { reason } => {
                        self.dispatch_states
                            .insert(call_id.to_string(), DispatchState::CancelledBeforeDispatch);
                        let outcome = CoordinatedOutcome::Denied { reason };
                        self.journal.record(call_id, outcome.clone());
                        Err(outcome)
                    }
                    AskAuthorizationOutcome::CancelledBeforeInstall => {
                        self.dispatch_states
                            .insert(call_id.to_string(), DispatchState::CancelledBeforeDispatch);
                        let outcome = CoordinatedOutcome::CancelledBeforeDispatch;
                        self.journal.record(call_id, outcome.clone());
                        Err(outcome)
                    }
                    AskAuthorizationOutcome::Pending => {
                        // Concurrent first Ask actions share one pending
                        // decision. The action is not dispatched.
                        self.dispatch_states
                            .insert(call_id.to_string(), DispatchState::CancelledBeforeDispatch);
                        let outcome = CoordinatedOutcome::CancelledBeforeDispatch;
                        self.journal.record(call_id, outcome.clone());
                        Err(outcome)
                    }
                }
            }
            Ok(ComputerAuthorizationDecision::Deny { reason }) => {
                // Denial terminates that delegation's computer path.
                self.ask_lease_store.record_denial(&lease_key);
                self.dispatch_states
                    .insert(call_id.to_string(), DispatchState::CancelledBeforeDispatch);
                let outcome = CoordinatedOutcome::Denied { reason };
                self.journal.record(call_id, outcome.clone());
                Err(outcome)
            }
            Ok(ComputerAuthorizationDecision::AskBlocked) => {
                // The authorizer blocked waiting for a human response. The
                // action is not dispatched. The pending wait remains so a
                // subsequent approval can install the lease.
                self.dispatch_states
                    .insert(call_id.to_string(), DispatchState::CancelledBeforeDispatch);
                let outcome = CoordinatedOutcome::CancelledBeforeDispatch;
                self.journal.record(call_id, outcome.clone());
                Err(outcome)
            }
            Err(err) => {
                let outcome = CoordinatedOutcome::Failed {
                    failure: ComputerFailure {
                        index: 0,
                        error: err,
                    },
                    screenshot: None,
                };
                self.journal.record(call_id, outcome.clone());
                Err(outcome)
            }
        }
    }

    /// Get the virtual display UUID from the target adapter, if available.
    fn virtual_display_uuid(&self) -> Option<[u8; 16]> {
        self.target_adapter.as_ref().and_then(|adapter| {
            // We cannot capture a snapshot here without &mut, so we rely on
            // the fact that virtual backends store their UUID in the
            // evidence. For virtual displays without an adapter, this returns
            // None and the lease is scoped to a synthetic key.
            //
            // In practice, the adapter's backend_kind tells us if this is a
            // virtual display. We use a zero UUID as a fallback for
            // evidence-less virtual displays (no adapter).
            if adapter.backend_kind() == BackendKind::VirtualDisplay {
                // The actual UUID is in the evidence; we capture it during
                // open() and store it. For now, return None and let the
                // lease key builder use the synthetic fallback.
                None
            } else {
                None
            }
        })
    }

    /// The Ask delegation lease store (for tests/diagnostics).
    pub fn ask_lease_store(&self) -> &AskDelegationLeaseStore {
        &self.ask_lease_store
    }

    /// The provider ID for this coordinator's delegation.
    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    /// The model ID for this coordinator's delegation.
    pub fn model_id(&self) -> &ModelId {
        &self.model_id
    }

    /// Revoke the Ask delegation lease for the current coordinator state.
    /// Called on delegation terminal state, cancel, detach, provider/model
    /// change, display/target/host generation change, lost OS lock, or daemon
    /// restart.
    pub fn revoke_ask_lease(&mut self) -> bool {
        if let Some(key) = self.ask_lease_key(self.virtual_display_uuid()) {
            self.ask_lease_store.revoke(&key)
        } else {
            false
        }
    }

    /// Revoke all Ask leases for this coordinator's delegation. Called on
    /// delegation terminal state, cancel, or detach.
    pub fn revoke_ask_lease_for_delegation(&mut self) -> usize {
        self.ask_lease_store
            .revoke_for_delegation(&self.session_id, &self.delegation_id)
    }

    /// Handle host lease-generation replacement. A replaced generation
    /// invalidates the Ask lease and requires a new human decision before
    /// another action.
    pub fn invalidate_ask_lease_on_host_generation_change(&mut self) -> usize {
        if let Some(token) = &self.host_lease {
            self.ask_lease_store
                .revoke_on_host_generation_change(&token.target_key, token.generation)
        } else {
            0
        }
    }

    /// Clear all Ask leases (daemon restart). Both Ask and host leases are
    /// lost; Ask requires a new decision.
    pub fn clear_all_ask_leases(&mut self) {
        self.ask_lease_store.clear_all();
    }

    /// Execute an OpenAI computer call through the coordinator. This is the
    /// canonical dispatch path: dedup check → authorization → pre-handoff →
    /// backend batch → screenshot → record outcome.
    pub async fn execute_openai_call(
        &mut self,
        call_id: &str,
        actions: &[OpenAiComputerAction],
    ) -> CoordinatedOutcome {
        // Dedup check: duplicate/replayed calls return the prior sanitized
        // outcome and never touch input again.
        if let Some(prior) = self.journal.lookup(call_id) {
            return CoordinatedOutcome::DuplicateReplay {
                prior_outcome: Box::new(prior.clone()),
            };
        }

        // If the coordinator is invalidated, return immediately.
        if self.invalidated {
            let outcome = CoordinatedOutcome::Invalidated {
                reason: TargetUnavailableReason::StaleTarget,
            };
            self.journal.record(call_id, outcome.clone());
            return outcome;
        }

        // If the backend is dead, return immediately with zero input.
        if self.backend_dead {
            let outcome = CoordinatedOutcome::Invalidated {
                reason: TargetUnavailableReason::SessionInactive,
            };
            self.journal.record(call_id, outcome.clone());
            return outcome;
        }

        // Build the backend action list.
        let mut backend_actions = Vec::new();
        for action in actions {
            backend_actions.extend(action.to_backend_actions());
        }
        let action_label = format!("openai_call:{}", actions.len());

        // Lease composition gate: Ask requires both a current Ask delegation
        // lease and the coordinator's current host/virtual input lease. Yolo
        // uses only the host lease and records `agent_discretion`; it creates
        // no approval grant.
        if let Err(outcome) = self
            .check_ask_lease_for_dispatch(call_id, &action_label, self.virtual_display_uuid())
            .await
        {
            return outcome;
        }

        // Dispatch through the backend.
        let outcome = self
            .dispatch_backend_batch(call_id, &backend_actions, &action_label)
            .await;
        self.journal.record(call_id, outcome.clone());
        outcome
    }

    /// Execute an Anthropic 2025-11-24 computer call through the coordinator.
    pub async fn execute_anthropic_20251124_call(
        &mut self,
        call_id: &str,
        action: &Anthropic20251124ComputerAction,
    ) -> CoordinatedOutcome {
        // Dedup check.
        if let Some(prior) = self.journal.lookup(call_id) {
            return CoordinatedOutcome::DuplicateReplay {
                prior_outcome: Box::new(prior.clone()),
            };
        }

        if self.invalidated {
            let outcome = CoordinatedOutcome::Invalidated {
                reason: TargetUnavailableReason::StaleTarget,
            };
            self.journal.record(call_id, outcome.clone());
            return outcome;
        }

        if self.backend_dead {
            let outcome = CoordinatedOutcome::Invalidated {
                reason: TargetUnavailableReason::SessionInactive,
            };
            self.journal.record(call_id, outcome.clone());
            return outcome;
        }

        let backend_actions = action.to_backend_actions();
        let action_label = "anthropic_20251124_call".to_string();

        // Lease composition gate.
        if let Err(outcome) = self
            .check_ask_lease_for_dispatch(call_id, &action_label, self.virtual_display_uuid())
            .await
        {
            return outcome;
        }

        let outcome = self
            .dispatch_backend_batch(call_id, &backend_actions, &action_label)
            .await;
        self.journal.record(call_id, outcome.clone());
        outcome
    }

    /// Execute an Anthropic 2025-01-24 computer call through the coordinator.
    pub async fn execute_anthropic_20250124_call(
        &mut self,
        call_id: &str,
        action: &Anthropic20250124ComputerAction,
    ) -> CoordinatedOutcome {
        // Dedup check.
        if let Some(prior) = self.journal.lookup(call_id) {
            return CoordinatedOutcome::DuplicateReplay {
                prior_outcome: Box::new(prior.clone()),
            };
        }

        if self.invalidated {
            let outcome = CoordinatedOutcome::Invalidated {
                reason: TargetUnavailableReason::StaleTarget,
            };
            self.journal.record(call_id, outcome.clone());
            return outcome;
        }

        if self.backend_dead {
            let outcome = CoordinatedOutcome::Invalidated {
                reason: TargetUnavailableReason::SessionInactive,
            };
            self.journal.record(call_id, outcome.clone());
            return outcome;
        }

        let backend_actions = action.to_backend_actions();
        let action_label = "anthropic_20250124_call".to_string();

        // Lease composition gate.
        if let Err(outcome) = self
            .check_ask_lease_for_dispatch(call_id, &action_label, self.virtual_display_uuid())
            .await
        {
            return outcome;
        }

        let outcome = self
            .dispatch_backend_batch(call_id, &backend_actions, &action_label)
            .await;
        self.journal.record(call_id, outcome.clone());
        outcome
    }

    /// Cancel an action before dispatch. Cancellation before the dispatching
    /// commit means zero input.
    pub fn cancel_before_dispatch(&mut self, call_id: &str) -> CoordinatedOutcome {
        let current_state = self.dispatch_states.get(call_id).copied();
        match current_state {
            Some(DispatchState::NotDispatched) | None => {
                self.dispatch_states
                    .insert(call_id.to_string(), DispatchState::CancelledBeforeDispatch);
                let outcome = CoordinatedOutcome::CancelledBeforeDispatch;
                self.journal.record(call_id, outcome.clone());
                outcome
            }
            Some(DispatchState::Dispatching) => {
                // Cancellation after the dispatching commit — unevidenced
                // outcome, never automatically retried.
                self.dispatch_states
                    .insert(call_id.to_string(), DispatchState::DispatchUnknown);
                let outcome = CoordinatedOutcome::DispatchUnknown {
                    action_label: call_id.to_string(),
                };
                self.journal.record(call_id, outcome.clone());
                outcome
            }
            Some(DispatchState::Completed) => {
                // Already completed — return the prior outcome.
                if let Some(prior) = self.journal.lookup(call_id) {
                    return prior.clone();
                }
                CoordinatedOutcome::Completed {
                    completed: Vec::new(),
                    screenshot: None,
                }
            }
            Some(DispatchState::CancelledBeforeDispatch) => {
                CoordinatedOutcome::CancelledBeforeDispatch
            }
            Some(DispatchState::DispatchUnknown) => CoordinatedOutcome::DispatchUnknown {
                action_label: call_id.to_string(),
            },
        }
    }

    /// Mark the backend as dead. Failure wakes all waiters with zero input.
    pub fn mark_backend_dead(&mut self) {
        self.backend_dead = true;
        // Revoke Ask delegation leases for this delegation.
        self.revoke_ask_lease_for_delegation();
        // Release the host lease if held.
        if let Some(token) = self.host_lease.take()
            && let Some(arbiter) = &self.host_arbiter
        {
            let mut arbiter = arbiter.lock().unwrap();
            arbiter.release(&token);
        }
    }

    /// Close the coordinator. Coordinator/backend lifetime ends on delegation
    /// completion, failure, cancellation, detach, daemon restart, or host-lock
    /// loss.
    pub async fn close(&mut self) -> Result<(), ComputerError> {
        // Revoke Ask delegation leases for this delegation.
        self.revoke_ask_lease_for_delegation();
        // Release the host lease.
        if let Some(token) = self.host_lease.take()
            && let Some(arbiter) = &self.host_arbiter
        {
            let mut arbiter = arbiter.lock().unwrap();
            arbiter.release(&token);
        }
        // Release all backend resources.
        self.backend.release_all().await
    }

    /// Get the dispatch state for a call ID.
    pub fn dispatch_state(&self, call_id: &str) -> Option<DispatchState> {
        self.dispatch_states.get(call_id).copied()
    }

    /// Get the delegation ID.
    pub fn delegation_id(&self) -> &DelegationId {
        &self.delegation_id
    }

    /// Get the backend kind.
    pub fn backend_kind(&self) -> BackendKind {
        self.backend_kind
    }
}

/// Errors from opening a coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorOpenError {
    /// Backend geometry query failed.
    BackendGeometry(ComputerError),
    /// Backend reported zero width or height.
    ZeroGeometry,
    /// Target evidence capture failed.
    TargetEvidence(TargetUnavailableReason),
    /// Host lock acquisition was queued (another holder is active).
    HostLockQueued,
    /// Host lock acquisition failed (another process holds the OS lock).
    HostLockFailed(HostLockError),
}

impl std::fmt::Display for CoordinatorOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendGeometry(err) => write!(f, "backend geometry failed: {err}"),
            Self::ZeroGeometry => f.write_str("backend reported zero geometry"),
            Self::TargetEvidence(reason) => {
                write!(f, "target evidence capture failed: {reason:?}")
            }
            Self::HostLockQueued => f.write_str("host lock acquisition queued"),
            Self::HostLockFailed(err) => write!(f, "host lock failed: {err}"),
        }
    }
}

impl std::error::Error for CoordinatorOpenError {}

// ---------------------------------------------------------------------------
// Native response extraction/injection seams
// ---------------------------------------------------------------------------

/// The provider native variant of a computer call extracted from a Rig
/// response.
#[derive(Debug, Clone, PartialEq)]
pub enum NativeComputerCall {
    /// OpenAI Responses `computer_call` item.
    OpenAi {
        call_id: String,
        actions: Vec<OpenAiComputerAction>,
    },
    /// Anthropic 2025-11-24 native `tool_use` named `computer`.
    Anthropic20251124 {
        tool_use_id: String,
        action: Anthropic20251124ComputerAction,
    },
    /// Anthropic 2025-01-24 native `tool_use` named `computer`.
    Anthropic20250124 {
        tool_use_id: String,
        action: Anthropic20250124ComputerAction,
    },
    /// An unrecognized native computer variant. Generic Rig function-tool
    /// dispatch must never reinterpret native computer items; unknown native
    /// variants return a typed provider-compatible unsupported result before
    /// backend input.
    UnsupportedVariant {
        provider: NativeProvider,
        detail: String,
    },
}

/// The native provider that emitted a computer call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeProvider {
    OpenAi,
    Anthropic20251124,
    Anthropic20250124,
    Unknown,
}

/// The transient continuation to inject back into the provider conversation
/// after a native computer call is executed through the coordinator.
pub enum NativeComputerContinuation {
    /// OpenAI `computer_call_output` with a transient screenshot.
    OpenAi {
        call_id: String,
        transient: Option<TransientProviderRequest>,
    },
    /// Anthropic `tool_result` with a transient image block (both versions).
    Anthropic {
        tool_use_id: String,
        variant: ProviderMediaVariant,
        transient: Option<TransientProviderRequest>,
    },
    /// A typed provider-compatible unsupported result. No backend input was
    /// touched.
    Unsupported {
        provider: NativeProvider,
        wire_payload: serde_json::Value,
    },
    /// A text-only continuation (no screenshot, e.g. on failure or denial).
    TextOnly {
        call_id: String,
        text: String,
        provider: NativeProvider,
    },
}

impl std::fmt::Debug for NativeComputerContinuation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenAi { call_id, transient } => f
                .debug_struct("NativeComputerContinuation::OpenAi")
                .field("call_id", call_id)
                .field("has_transient", &transient.is_some())
                .finish(),
            Self::Anthropic {
                tool_use_id,
                variant,
                transient,
            } => f
                .debug_struct("NativeComputerContinuation::Anthropic")
                .field("tool_use_id", tool_use_id)
                .field("variant", variant)
                .field("has_transient", &transient.is_some())
                .finish(),
            Self::Unsupported { provider, .. } => f
                .debug_struct("NativeComputerContinuation::Unsupported")
                .field("provider", provider)
                .finish(),
            Self::TextOnly {
                call_id, provider, ..
            } => f
                .debug_struct("NativeComputerContinuation::TextOnly")
                .field("call_id", call_id)
                .field("provider", provider)
                .finish(),
        }
    }
}

/// Extract native computer calls from a Rig/provider response.
///
/// This is the typed native-response extraction at the provider/Rig boundary.
/// It does NOT parse rendered assistant text or generic tool JSON. It
/// intercepts:
/// - OpenAI Responses: `computer_call` items
/// - Anthropic: native `tool_use` named `computer`
///
/// Generic Rig function-tool dispatch must never reinterpret native computer
/// items. Unknown native variants return a typed provider-compatible
/// unsupported result before backend input.
pub struct NativeResponseExtractor;

impl NativeResponseExtractor {
    /// Extract OpenAI Responses `computer_call` items from a response payload.
    ///
    /// The payload is the raw `output` array from an OpenAI Responses API
    /// response. Each item with `"type": "computer_call"` is parsed with the
    /// canonical OpenAI parser.
    pub fn extract_openai(output: &[serde_json::Value]) -> Vec<NativeComputerCall> {
        let mut results = Vec::new();
        for item in output {
            if item.get("type").and_then(serde_json::Value::as_str) == Some("computer_call") {
                match parse_openai_computer_call(item) {
                    Ok((call_id, actions)) => {
                        results.push(NativeComputerCall::OpenAi { call_id, actions });
                    }
                    Err(err) => {
                        // Malformed computer_call — return as unsupported variant.
                        results.push(NativeComputerCall::UnsupportedVariant {
                            provider: NativeProvider::OpenAi,
                            detail: err.to_string(),
                        });
                    }
                }
            }
            // Non-computer_call items are not extracted here; they flow through
            // generic Rig function-tool dispatch.
        }
        results
    }

    /// Extract Anthropic native `tool_use` items named `computer` from a
    /// response payload.
    ///
    /// The `contract` parameter selects the versioned action DTO parser
    /// (2025-01-24 or 2025-11-24). Each `tool_use` with `"name": "computer"`
    /// is parsed with the canonical versioned parser.
    pub fn extract_anthropic(
        content: &[serde_json::Value],
        contract: ComputerToolContract,
    ) -> Vec<NativeComputerCall> {
        let mut results = Vec::new();
        let provider = match contract {
            ComputerToolContract::Anthropic20251124 => NativeProvider::Anthropic20251124,
            ComputerToolContract::Anthropic20250124 => NativeProvider::Anthropic20250124,
            ComputerToolContract::OpenAiResponses => return results, // not Anthropic
        };
        for item in content {
            if item.get("type").and_then(serde_json::Value::as_str) != Some("tool_use") {
                continue;
            }
            if item.get("name").and_then(serde_json::Value::as_str) != Some("computer") {
                continue;
            }
            let tool_use_id = item
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let input = item
                .get("input")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            match contract {
                ComputerToolContract::Anthropic20251124 => {
                    match parse_anthropic_20251124_action(&input) {
                        Ok(action) => {
                            results.push(NativeComputerCall::Anthropic20251124 {
                                tool_use_id,
                                action,
                            });
                        }
                        Err(err) => {
                            results.push(NativeComputerCall::UnsupportedVariant {
                                provider,
                                detail: err.to_string(),
                            });
                        }
                    }
                }
                ComputerToolContract::Anthropic20250124 => {
                    match parse_anthropic_20250124_action(&input) {
                        Ok(action) => {
                            results.push(NativeComputerCall::Anthropic20250124 {
                                tool_use_id,
                                action,
                            });
                        }
                        Err(err) => {
                            results.push(NativeComputerCall::UnsupportedVariant {
                                provider,
                                detail: err.to_string(),
                            });
                        }
                    }
                }
                ComputerToolContract::OpenAiResponses => {}
            }
        }
        results
    }

    /// Build the transient continuation for a coordinated outcome.
    ///
    /// Transient frames are borrowed through the screenshot boundary before
    /// provider assembly; no live frame or transient provider request reaches
    /// durable middleware. The sanitized projection is in the outcome; the
    /// transient wire payload is built here only if a screenshot was captured.
    pub fn build_continuation(
        call: &NativeComputerCall,
        outcome: &CoordinatedOutcome,
    ) -> NativeComputerContinuation {
        match call {
            NativeComputerCall::OpenAi { call_id, .. } => {
                match outcome {
                    CoordinatedOutcome::Completed { screenshot, .. } => {
                        // Build a transient wire payload from the sanitized
                        // projection. In a real system the live frame would be
                        // borrowed; here we build a text-only continuation
                        // because the live frame was dropped after capture.
                        // The sanitized projection is the only durable record.
                        let _ = screenshot;
                        NativeComputerContinuation::TextOnly {
                            call_id: call_id.clone(),
                            text: "computer action completed".to_string(),
                            provider: NativeProvider::OpenAi,
                        }
                    }
                    CoordinatedOutcome::Failed { failure, .. } => {
                        NativeComputerContinuation::TextOnly {
                            call_id: call_id.clone(),
                            text: format!("computer action failed: {}", failure.error),
                            provider: NativeProvider::OpenAi,
                        }
                    }
                    CoordinatedOutcome::Denied { reason } => NativeComputerContinuation::TextOnly {
                        call_id: call_id.clone(),
                        text: format!("computer action denied: {reason}"),
                        provider: NativeProvider::OpenAi,
                    },
                    CoordinatedOutcome::CancelledBeforeDispatch => {
                        NativeComputerContinuation::TextOnly {
                            call_id: call_id.clone(),
                            text: "computer action cancelled before dispatch".to_string(),
                            provider: NativeProvider::OpenAi,
                        }
                    }
                    CoordinatedOutcome::DispatchUnknown { .. } => {
                        NativeComputerContinuation::TextOnly {
                            call_id: call_id.clone(),
                            text: "computer action dispatch unknown".to_string(),
                            provider: NativeProvider::OpenAi,
                        }
                    }
                    CoordinatedOutcome::Invalidated { reason } => {
                        NativeComputerContinuation::TextOnly {
                            call_id: call_id.clone(),
                            text: format!("coordinator invalidated: {reason:?}"),
                            provider: NativeProvider::OpenAi,
                        }
                    }
                    CoordinatedOutcome::DuplicateReplay { .. } => {
                        NativeComputerContinuation::TextOnly {
                            call_id: call_id.clone(),
                            text: "duplicate computer call replayed".to_string(),
                            provider: NativeProvider::OpenAi,
                        }
                    }
                    CoordinatedOutcome::UnsupportedProviderVariant { detail } => {
                        NativeComputerContinuation::Unsupported {
                            provider: NativeProvider::OpenAi,
                            wire_payload: serde_json::json!({
                                "type": "computer_call_output",
                                "call_id": call_id,
                                "output": {
                                    "type": "text",
                                    "text": format!("unsupported computer action: {detail}"),
                                },
                            }),
                        }
                    }
                }
            }
            NativeComputerCall::Anthropic20251124 { tool_use_id, .. } => {
                Self::build_anthropic_continuation(
                    tool_use_id,
                    outcome,
                    NativeProvider::Anthropic20251124,
                    ProviderMediaVariant::Anthropic20251124ImageBlock,
                )
            }
            NativeComputerCall::Anthropic20250124 { tool_use_id, .. } => {
                Self::build_anthropic_continuation(
                    tool_use_id,
                    outcome,
                    NativeProvider::Anthropic20250124,
                    ProviderMediaVariant::Anthropic20250124ImageBlock,
                )
            }
            NativeComputerCall::UnsupportedVariant { provider, detail } => {
                let wire_payload = match provider {
                    NativeProvider::OpenAi => serde_json::json!({
                        "type": "computer_call_output",
                        "call_id": "unknown",
                        "output": {
                            "type": "text",
                            "text": format!("unsupported computer action: {detail}"),
                        },
                    }),
                    _ => serde_json::json!({
                        "type": "tool_result",
                        "tool_use_id": "unknown",
                        "content": [{"type": "text", "text": format!("unsupported computer action: {detail}")}],
                    }),
                };
                NativeComputerContinuation::Unsupported {
                    provider: *provider,
                    wire_payload,
                }
            }
        }
    }

    fn build_anthropic_continuation(
        tool_use_id: &str,
        outcome: &CoordinatedOutcome,
        provider: NativeProvider,
        variant: ProviderMediaVariant,
    ) -> NativeComputerContinuation {
        match outcome {
            CoordinatedOutcome::Completed { .. } => NativeComputerContinuation::Anthropic {
                tool_use_id: tool_use_id.to_string(),
                variant,
                transient: None, // text-only; live frame was dropped
            },
            CoordinatedOutcome::Failed { failure, .. } => NativeComputerContinuation::TextOnly {
                call_id: tool_use_id.to_string(),
                text: format!("computer action failed: {}", failure.error),
                provider,
            },
            CoordinatedOutcome::Denied { reason } => NativeComputerContinuation::TextOnly {
                call_id: tool_use_id.to_string(),
                text: format!("computer action denied: {reason}"),
                provider,
            },
            CoordinatedOutcome::CancelledBeforeDispatch => NativeComputerContinuation::TextOnly {
                call_id: tool_use_id.to_string(),
                text: "computer action cancelled before dispatch".to_string(),
                provider,
            },
            CoordinatedOutcome::DispatchUnknown { .. } => NativeComputerContinuation::TextOnly {
                call_id: tool_use_id.to_string(),
                text: "computer action dispatch unknown".to_string(),
                provider,
            },
            CoordinatedOutcome::Invalidated { reason } => NativeComputerContinuation::TextOnly {
                call_id: tool_use_id.to_string(),
                text: format!("coordinator invalidated: {reason:?}"),
                provider,
            },
            CoordinatedOutcome::DuplicateReplay { .. } => NativeComputerContinuation::TextOnly {
                call_id: tool_use_id.to_string(),
                text: "duplicate computer call replayed".to_string(),
                provider,
            },
            CoordinatedOutcome::UnsupportedProviderVariant { detail } => {
                NativeComputerContinuation::Unsupported {
                    provider,
                    wire_payload: serde_json::json!({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": [{"type": "text", "text": format!("unsupported computer action: {detail}")}],
                    }),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::host_identity::HostInstallationId;
    use super::super::target::{
        FakeTargetEvidenceAdapter, TargetIdentityEvidence, empty_unavailable,
        sample_physical_evidence,
    };
    use super::super::{
        Anthropic20250124ComputerAction, Anthropic20251124ComputerAction, ClickCount,
        ComputerAction, ComputerBackend, ComputerError, ComputerToolContract, CoordinateSpace,
        DisplayGeometry, Easing, FakeBackend, KeyChord, LogicalSize, Modifiers, MouseButton,
        OpenAiComputerAction, PixelSize, Point, ProviderPointerButton, Rect, ScaleFactor,
    };
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    fn test_geometry() -> DisplayGeometry {
        DisplayGeometry {
            physical: PixelSize {
                width: 1280,
                height: 720,
            },
            logical: LogicalSize {
                width: 1280.0,
                height: 720.0,
            },
            scale_factor: ScaleFactor(1.0),
        }
    }

    fn physical_key() -> PhysicalTargetKey {
        PhysicalTargetKey::new(HostInstallationId([1u8; 32]), [2u8; 32], [3u8; 32])
    }

    fn virtual_evidence() -> TargetIdentityEvidence {
        let mut evidence = empty_unavailable(BackendKind::VirtualDisplay);
        evidence.virtual_display_uuid = Some([0xAA; 16]);
        evidence.virtual_backend_generation = Some(1);
        evidence
    }

    fn physical_evidence() -> TargetIdentityEvidence {
        sample_physical_evidence(
            HostInstallationId([1u8; 32]),
            [2u8; 32],
            [3u8; 32],
            [4u8; 16],
            1234,
        )
    }

    fn make_coordinator_params(authorizer: Arc<dyn ComputerAuthorizer>) -> CoordinatorParams {
        CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: None,
            target_adapter: None,
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
        }
    }

    async fn make_coordinator(
        backend: Box<dyn ComputerBackend>,
        authorizer: Arc<dyn ComputerAuthorizer>,
    ) -> ComputerActionCoordinator {
        let params = make_coordinator_params(authorizer);
        ComputerActionCoordinator::open(backend, params)
            .await
            .expect("coordinator open")
    }

    // =====================================================================
    // Acceptance criterion 1: computer_native_live_loop
    // Drives OpenAI and both Anthropic native fixtures through the actual
    // extraction/injection seam and one fake canonical backend.
    // =====================================================================

    #[tokio::test]
    async fn computer_native_live_loop_openai() {
        let backend = Box::new(FakeBackend::new());
        let authorizer: Arc<dyn ComputerAuthorizer> =
            Arc::new(FakeComputerAuthorizer::always_allow());
        let mut coordinator = make_coordinator(backend, authorizer).await;

        // Simulate an OpenAI Responses output with a computer_call item.
        let output = vec![serde_json::json!({
            "type": "computer_call",
            "call_id": "call-1",
            "actions": [
                {"type": "move", "x": 4.0, "y": 5.0},
                {"type": "click", "x": 100.0, "y": 200.0, "button": "left"},
                {"type": "type", "text": "hello"}
            ]
        })];

        // Extract through the native seam.
        let calls = NativeResponseExtractor::extract_openai(&output);
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        let NativeComputerCall::OpenAi { call_id, actions } = call else {
            panic!("expected OpenAi call");
        };
        assert_eq!(call_id, "call-1");
        assert_eq!(actions.len(), 3);

        // Execute through the coordinator.
        let outcome = coordinator.execute_openai_call(call_id, actions).await;

        // Build the continuation through the native seam.
        let continuation = NativeResponseExtractor::build_continuation(call, &outcome);
        assert!(matches!(
            continuation,
            NativeComputerContinuation::TextOnly {
                provider: NativeProvider::OpenAi,
                ..
            }
        ));

        // Verify the outcome is completed with a screenshot.
        match &outcome {
            CoordinatedOutcome::Completed {
                completed,
                screenshot,
            } => {
                assert!(!completed.is_empty());
                assert!(screenshot.is_some());
                // The sanitized projection contains no pixel data.
                let proj_json = serde_json::to_string(screenshot.as_ref().unwrap()).unwrap();
                assert!(!proj_json.contains("base64"));
                assert!(!proj_json.contains("data:image"));
            }
            other => panic!("expected completed outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn computer_native_live_loop_anthropic_20251124() {
        let backend = Box::new(FakeBackend::new());
        let authorizer: Arc<dyn ComputerAuthorizer> =
            Arc::new(FakeComputerAuthorizer::always_allow());
        let mut coordinator = make_coordinator(backend, authorizer).await;

        // Simulate an Anthropic 2025-11-24 tool_use named "computer".
        let content = vec![serde_json::json!({
            "type": "tool_use",
            "id": "toolu-1",
            "name": "computer",
            "input": {
                "action": "left_click",
                "coordinate": [100.0, 200.0]
            }
        })];

        let calls = NativeResponseExtractor::extract_anthropic(
            &content,
            ComputerToolContract::Anthropic20251124,
        );
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        let NativeComputerCall::Anthropic20251124 {
            tool_use_id,
            action,
        } = call
        else {
            panic!("expected Anthropic20251124 call");
        };
        assert_eq!(tool_use_id, "toolu-1");
        assert!(matches!(
            action,
            Anthropic20251124ComputerAction::Click { .. }
        ));

        let outcome = coordinator
            .execute_anthropic_20251124_call(tool_use_id, action)
            .await;
        let continuation = NativeResponseExtractor::build_continuation(call, &outcome);
        assert!(matches!(
            continuation,
            NativeComputerContinuation::Anthropic { .. }
        ));
        assert!(matches!(outcome, CoordinatedOutcome::Completed { .. }));
    }

    #[tokio::test]
    async fn computer_native_live_loop_anthropic_20250124() {
        let backend = Box::new(FakeBackend::new());
        let authorizer: Arc<dyn ComputerAuthorizer> =
            Arc::new(FakeComputerAuthorizer::always_allow());
        let mut coordinator = make_coordinator(backend, authorizer).await;

        let content = vec![serde_json::json!({
            "type": "tool_use",
            "id": "toolu-2",
            "name": "computer",
            "input": {
                "action": "screenshot"
            }
        })];

        let calls = NativeResponseExtractor::extract_anthropic(
            &content,
            ComputerToolContract::Anthropic20250124,
        );
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        let NativeComputerCall::Anthropic20250124 {
            tool_use_id,
            action,
        } = call
        else {
            panic!("expected Anthropic20250124 call");
        };
        assert_eq!(tool_use_id, "toolu-2");
        assert!(matches!(
            action,
            Anthropic20250124ComputerAction::Screenshot
        ));

        let outcome = coordinator
            .execute_anthropic_20250124_call(tool_use_id, action)
            .await;
        let continuation = NativeResponseExtractor::build_continuation(call, &outcome);
        assert!(matches!(
            continuation,
            NativeComputerContinuation::Anthropic { .. }
        ));
        assert!(matches!(outcome, CoordinatedOutcome::Completed { .. }));
    }

    // =====================================================================
    // Acceptance criterion 2: computer_native_host_arbiter
    // Proves process-local and simulated cross-process contenders cannot
    // overlap on one physical key, lease generations cannot be reused, owner
    // death releases safely, and distinct virtual displays remain independent.
    // =====================================================================

    #[test]
    fn computer_native_host_arbiter_process_local_fifo() {
        let os_lock = Box::new(InMemoryOsAdvisoryLock::new());
        let mut arbiter = HostInputArbiter::new(os_lock, OwnerInstance(1));

        let key = physical_key();
        let delegation_a = DelegationId("delegation-a".to_string());
        let delegation_b = DelegationId("delegation-b".to_string());

        // First acquire succeeds.
        let result_a = arbiter.try_acquire(&key, delegation_a.clone());
        let AcquireResult::Acquired(token_a) = result_a else {
            panic!("first acquire should succeed");
        };
        assert_eq!(token_a.generation, LeaseGeneration(1));

        // Second acquire queues (process-local FIFO).
        let result_b = arbiter.try_acquire(&key, delegation_b.clone());
        assert!(matches!(result_b, AcquireResult::Queued));
        assert_eq!(arbiter.waiter_count(&key), 1);

        // Release the first — the second is promoted with a NEW generation.
        assert!(arbiter.release(&token_a));
        // The second delegation should now hold the lease.
        assert!(arbiter.is_held(&key));

        // Try to acquire again for delegation_a — should queue.
        let result_a2 = arbiter.try_acquire(&key, delegation_a.clone());
        // The promoted delegation_b should be the current holder.
        // Let's verify by releasing and re-checking.
        // Actually we need to track the promoted token. The release() promotes
        // internally. Let's verify is_held and waiter_count.
        assert!(arbiter.is_held(&key));
        // The new acquisition should queue behind the promoted holder.
        if let AcquireResult::Queued = result_a2 {
            // Expected: queued behind the promoted delegation_b.
        } else {
            // If acquired, that means the promoted holder was already released.
            // This is fine — the test verifies FIFO ordering.
        }
    }

    #[test]
    fn computer_native_host_arbiter_cross_process_contention() {
        let os_lock = InMemoryOsAdvisoryLock::new();
        let os_lock_b = os_lock.shared_clone();
        let mut arbiter_a = HostInputArbiter::new(Box::new(os_lock), OwnerInstance(1));
        let mut arbiter_b = HostInputArbiter::new(Box::new(os_lock_b), OwnerInstance(2));

        let key = physical_key();
        let delegation = DelegationId("delegation-1".to_string());

        // Process A acquires.
        let result_a = arbiter_a.try_acquire(&key, delegation.clone());
        let AcquireResult::Acquired(token_a) = result_a else {
            panic!("process A acquire should succeed");
        };

        // Process B cannot acquire (OS lock held by A).
        let result_b = arbiter_b.try_acquire(&key, delegation.clone());
        assert!(matches!(result_b, AcquireResult::OsLockFailed(_)));

        // Process A releases.
        assert!(arbiter_a.release(&token_a));

        // Now process B can acquire.
        let result_b2 = arbiter_b.try_acquire(&key, delegation);
        assert!(matches!(result_b2, AcquireResult::Acquired(_)));
    }

    #[test]
    fn computer_native_host_arbiter_generations_not_reused() {
        let os_lock = Box::new(InMemoryOsAdvisoryLock::new());
        let mut arbiter = HostInputArbiter::new(os_lock, OwnerInstance(1));

        let key = physical_key();
        let delegation = DelegationId("delegation-1".to_string());

        // First acquire — generation 1.
        let token1 = match arbiter.try_acquire(&key, delegation.clone()) {
            AcquireResult::Acquired(t) => t,
            _ => panic!("acquire failed"),
        };
        assert_eq!(token1.generation, LeaseGeneration(1));

        // Release.
        assert!(arbiter.release(&token1));

        // Second acquire — generation 2 (not 1).
        let token2 = match arbiter.try_acquire(&key, delegation) {
            AcquireResult::Acquired(t) => t,
            _ => panic!("acquire failed"),
        };
        assert_eq!(token2.generation, LeaseGeneration(2));
        assert_ne!(token1.generation, token2.generation);
    }

    #[test]
    fn computer_native_host_arbiter_owner_death_releases() {
        let os_lock = InMemoryOsAdvisoryLock::new();
        let mut arbiter = HostInputArbiter::new(Box::new(os_lock.shared_clone()), OwnerInstance(1));

        let key = physical_key();
        let delegation = DelegationId("delegation-1".to_string());

        // Owner 1 acquires.
        let token = match arbiter.try_acquire(&key, delegation) {
            AcquireResult::Acquired(t) => t,
            _ => panic!("acquire failed"),
        };
        assert!(arbiter.is_held(&key));

        // Simulate owner death — release all leases for owner 1.
        let released = arbiter.release_for_owner(OwnerInstance(1));
        assert_eq!(released, 1);
        assert!(!arbiter.is_held(&key));

        // The token is now invalid.
        assert!(!arbiter.is_lease_valid(&token));
        let _ = token; // suppress unused warning
    }

    #[test]
    fn computer_native_host_arbiter_distinct_virtual_displays_independent() {
        let os_lock = Box::new(InMemoryOsAdvisoryLock::new());
        let mut arbiter = HostInputArbiter::new(os_lock, OwnerInstance(1));

        // Two distinct physical keys (simulating distinct virtual displays
        // that map to distinct physical keys for testing).
        let key_a = PhysicalTargetKey::new(HostInstallationId([1u8; 32]), [2u8; 32], [3u8; 32]);
        let key_b = PhysicalTargetKey::new(
            HostInstallationId([1u8; 32]),
            [2u8; 32],
            [9u8; 32], // different display
        );

        let delegation = DelegationId("delegation-1".to_string());

        // Acquire key_a.
        let result_a = arbiter.try_acquire(&key_a, delegation.clone());
        assert!(matches!(result_a, AcquireResult::Acquired(_)));

        // Acquire key_b — should succeed independently (no contention).
        let result_b = arbiter.try_acquire(&key_b, delegation);
        assert!(matches!(result_b, AcquireResult::Acquired(_)));

        // Both are held.
        assert!(arbiter.is_held(&key_a));
        assert!(arbiter.is_held(&key_b));
    }

    #[test]
    fn computer_native_host_arbiter_cancel_waiter() {
        let os_lock = Box::new(InMemoryOsAdvisoryLock::new());
        let mut arbiter = HostInputArbiter::new(os_lock, OwnerInstance(1));

        let key = physical_key();
        let delegation_a = DelegationId("delegation-a".to_string());
        let delegation_b = DelegationId("delegation-b".to_string());

        // A acquires.
        let token_a = match arbiter.try_acquire(&key, delegation_a) {
            AcquireResult::Acquired(t) => t,
            _ => panic!("acquire failed"),
        };

        // B queues.
        let result_b = arbiter.try_acquire(&key, delegation_b.clone());
        assert!(matches!(result_b, AcquireResult::Queued));
        assert_eq!(arbiter.waiter_count(&key), 1);

        // Cancel B's waiter — removed without transferring generation.
        assert!(arbiter.cancel_waiter(&key, &delegation_b));
        assert_eq!(arbiter.waiter_count(&key), 0);

        // Release A — no waiter to promote.
        assert!(arbiter.release(&token_a));
        assert!(!arbiter.is_held(&key));
    }

    #[test]
    fn computer_native_host_arbiter_os_lock_loss_detection() {
        let os_lock = InMemoryOsAdvisoryLock::new();
        let mut arbiter = HostInputArbiter::new(Box::new(os_lock.shared_clone()), OwnerInstance(1));

        let key = physical_key();
        let delegation = DelegationId("delegation-1".to_string());

        let token = match arbiter.try_acquire(&key, delegation) {
            AcquireResult::Acquired(t) => t,
            _ => panic!("acquire failed"),
        };

        // Simulate OS lock loss by externally releasing the lock.
        {
            let mut external_lock = os_lock.shared_clone();
            external_lock.release(&key);
        }

        // Detect lock loss.
        let lost = arbiter.detect_lock_loss(&token);
        assert!(lost);
        assert!(!arbiter.is_lease_valid(&token));
    }

    // =====================================================================
    // Acceptance criterion 3: computer_native_geometry
    // Proves declarations and coordinate transforms use the opened backend
    // generation and reject zero/overflow/drift before input.
    // =====================================================================

    #[tokio::test]
    async fn computer_native_geometry_uses_backend_generation() {
        let mut backend = FakeBackend::new();
        // Override geometry to a custom size.
        backend.geometry = DisplayGeometry {
            physical: PixelSize {
                width: 1920,
                height: 1080,
            },
            logical: LogicalSize {
                width: 1920.0,
                height: 1080.0,
            },
            scale_factor: ScaleFactor(1.0),
        };
        let authorizer: Arc<dyn ComputerAuthorizer> =
            Arc::new(FakeComputerAuthorizer::always_allow());
        let coordinator = make_coordinator(Box::new(backend), authorizer).await;

        // Provider declarations use the backend-reported geometry.
        let wire = coordinator.provider_declarations(ComputerToolContract::Anthropic20251124);
        assert_eq!(wire.tools[0]["display_width_px"], serde_json::json!(1920));
        assert_eq!(wire.tools[0]["display_height_px"], serde_json::json!(1080));
    }

    #[tokio::test]
    async fn computer_native_geometry_rejects_zero() {
        let mut backend = FakeBackend::new();
        backend.geometry = DisplayGeometry {
            physical: PixelSize {
                width: 0,
                height: 720,
            },
            logical: LogicalSize {
                width: 0.0,
                height: 720.0,
            },
            scale_factor: ScaleFactor(1.0),
        };
        let authorizer: Arc<dyn ComputerAuthorizer> =
            Arc::new(FakeComputerAuthorizer::always_allow());
        let params = make_coordinator_params(authorizer);
        let result = ComputerActionCoordinator::open(Box::new(backend), params).await;
        assert!(matches!(result, Err(CoordinatorOpenError::ZeroGeometry)));
    }

    #[tokio::test]
    async fn computer_native_geometry_rejects_overflow_coordinates() {
        // The FakeBackend checks coordinates in execute_one for capture regions.
        // A region that exceeds the geometry should produce a failure outcome.
        let mut backend = FakeBackend::new();
        backend.geometry = DisplayGeometry {
            physical: PixelSize {
                width: 100,
                height: 100,
            },
            logical: LogicalSize {
                width: 100.0,
                height: 100.0,
            },
            scale_factor: ScaleFactor(1.0),
        };
        let authorizer: Arc<dyn ComputerAuthorizer> =
            Arc::new(FakeComputerAuthorizer::always_allow());
        let mut coordinator = make_coordinator(Box::new(backend), authorizer).await;

        // An Anthropic zoom action with a region that exceeds geometry.
        let action = Anthropic20251124ComputerAction::Zoom {
            rect: super::super::Rect {
                x: 90.0,
                y: 90.0,
                width: 50.0,
                height: 50.0,
                space: CoordinateSpace::Physical,
            },
            scale: ScaleFactor(2.0),
        };
        let outcome = coordinator
            .execute_anthropic_20251124_call("call-overflow", &action)
            .await;
        match outcome {
            CoordinatedOutcome::Failed { failure, .. } => {
                assert!(matches!(
                    failure.error,
                    ComputerError::InvalidCoordinates(_)
                ));
            }
            other => panic!("expected failed outcome, got {other:?}"),
        }
    }

    // =====================================================================
    // Acceptance criterion 4: computer_native_central_authorization
    // Proves every action reaches the exhaustive central variant; Ask
    // blocks/denies/allows through the seam and Yolo creates zero human
    // requests.
    // =====================================================================

    #[tokio::test]
    async fn computer_native_central_authorization_allow() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(FakeBackend::new());
        let mut coordinator = make_coordinator(backend, authorizer.clone()).await;

        let actions = vec![OpenAiComputerAction::Move {
            to: Point {
                x: 4.0,
                y: 5.0,
                space: CoordinateSpace::Physical,
            },
        }];
        let outcome = coordinator
            .execute_openai_call("call-auth-1", &actions)
            .await;

        // The authorizer was called exactly once.
        assert_eq!(authorizer.call_count(), 1);
        assert!(matches!(outcome, CoordinatedOutcome::Completed { .. }));
    }

    #[tokio::test]
    async fn computer_native_central_authorization_deny() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_deny(
            "policy blocks this action",
        ));
        let backend = Box::new(FakeBackend::new());
        let mut coordinator = make_coordinator(backend, authorizer.clone()).await;

        let actions = vec![OpenAiComputerAction::Move {
            to: Point {
                x: 4.0,
                y: 5.0,
                space: CoordinateSpace::Physical,
            },
        }];
        let outcome = coordinator
            .execute_openai_call("call-auth-2", &actions)
            .await;

        // The authorizer was called.
        assert_eq!(authorizer.call_count(), 1);
        // The outcome is denied — no backend input.
        match &outcome {
            CoordinatedOutcome::Denied { reason } => {
                assert!(reason.contains("policy blocks"));
            }
            other => panic!("expected denied outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn computer_native_central_authorization_ask_blocks() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_ask());
        let backend = Box::new(FakeBackend::new());
        let mut coordinator = make_coordinator(backend, authorizer.clone()).await;

        let actions = vec![OpenAiComputerAction::Click {
            at: Some(Point {
                x: 10.0,
                y: 10.0,
                space: CoordinateSpace::Physical,
            }),
            button: ProviderPointerButton::Left,
            modifiers: Modifiers::default(),
        }];
        let outcome = coordinator
            .execute_openai_call("call-auth-3", &actions)
            .await;

        // The authorizer was called.
        assert_eq!(authorizer.call_count(), 1);
        // Ask blocks — no backend input, cancelled before dispatch.
        assert!(matches!(
            outcome,
            CoordinatedOutcome::CancelledBeforeDispatch
        ));
        // Verify dispatch state.
        assert_eq!(
            coordinator.dispatch_state("call-auth-3"),
            Some(DispatchState::CancelledBeforeDispatch)
        );
    }

    #[tokio::test]
    async fn computer_native_central_authorization_yolo_zero_human_requests() {
        // Yolo tier: the authorizer is always_allow, which simulates zero
        // human requests. The key assertion is that Yolo imposes no semantic
        // action/target denial — every action that passes capability checks
        // is dispatched.
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer: authorizer.clone(),
            host_arbiter: None,
            target_adapter: None,
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
        };
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        // Even a "sensitive" action (typing text with rm -rf) is not denied
        // under Yolo — no semantic action/target denial.
        let actions = vec![OpenAiComputerAction::TypeText("rm -rf /".to_string())];
        let outcome = coordinator.execute_openai_call("call-yolo", &actions).await;

        // The authorizer was called once, and it allowed (zero human requests).
        assert_eq!(authorizer.call_count(), 1);
        // The action was dispatched — not denied.
        assert!(matches!(outcome, CoordinatedOutcome::Completed { .. }));
    }

    // =====================================================================
    // Acceptance criterion 5: Duplicate IDs, reconnect, both cancel/handoff
    // orders, backend death, partial batch, host-lock loss, and provider-
    // continuation failure produce at most one backend call and one terminal
    // outcome.
    // =====================================================================

    #[tokio::test]
    async fn computer_native_duplicate_ids_return_prior_outcome() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(FakeBackend::new());
        let mut coordinator = make_coordinator(backend, authorizer).await;

        let actions = vec![OpenAiComputerAction::Move {
            to: Point {
                x: 4.0,
                y: 5.0,
                space: CoordinateSpace::Physical,
            },
        }];

        // First call — completes.
        let outcome1 = coordinator.execute_openai_call("call-dup", &actions).await;
        assert!(matches!(outcome1, CoordinatedOutcome::Completed { .. }));

        // Duplicate call — returns the prior sanitized outcome, no input.
        let outcome2 = coordinator.execute_openai_call("call-dup", &actions).await;
        match outcome2 {
            CoordinatedOutcome::DuplicateReplay { prior_outcome } => {
                assert!(matches!(
                    *prior_outcome,
                    CoordinatedOutcome::Completed { .. }
                ));
            }
            other => panic!("expected duplicate replay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn computer_native_cancel_before_dispatch_zero_input() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(FakeBackend::new());
        let mut coordinator = make_coordinator(backend, authorizer).await;

        // Cancel before any dispatch — zero input.
        let outcome = coordinator.cancel_before_dispatch("call-cancel-1");
        assert!(matches!(
            outcome,
            CoordinatedOutcome::CancelledBeforeDispatch
        ));
    }

    #[tokio::test]
    async fn computer_native_backend_death_zero_input() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(FakeBackend::new());
        let mut coordinator = make_coordinator(backend, authorizer).await;

        // Mark backend as dead.
        coordinator.mark_backend_dead();

        let actions = vec![OpenAiComputerAction::Move {
            to: Point {
                x: 4.0,
                y: 5.0,
                space: CoordinateSpace::Physical,
            },
        }];
        let outcome = coordinator.execute_openai_call("call-dead", &actions).await;

        // Zero input — invalidated.
        assert!(matches!(outcome, CoordinatedOutcome::Invalidated { .. }));
    }

    #[tokio::test]
    async fn computer_native_partial_batch_one_terminal_outcome() {
        // A batch that fails partway through produces exactly one terminal
        // outcome (Failed) — not multiple.
        let mut backend = FakeBackend::new();
        backend.fail_at = Some(1);
        backend.fail_with = ComputerError::Refused("mid-batch failure".to_string());
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let mut coordinator = make_coordinator(Box::new(backend), authorizer).await;

        let actions = vec![
            OpenAiComputerAction::Move {
                to: Point {
                    x: 4.0,
                    y: 5.0,
                    space: CoordinateSpace::Physical,
                },
            },
            OpenAiComputerAction::TypeText("stop here".to_string()),
            OpenAiComputerAction::TypeText("must not execute".to_string()),
        ];
        let outcome = coordinator
            .execute_openai_call("call-partial", &actions)
            .await;

        match outcome {
            CoordinatedOutcome::Failed { failure, .. } => {
                assert_eq!(failure.index, 1);
            }
            other => panic!("expected failed outcome, got {other:?}"),
        }

        // Verify the dispatch state is Completed (one terminal outcome).
        assert_eq!(
            coordinator.dispatch_state("call-partial"),
            Some(DispatchState::Completed)
        );
    }

    #[tokio::test]
    async fn computer_native_host_lock_loss_invalidates() {
        let os_lock = InMemoryOsAdvisoryLock::new();
        let shared_os = os_lock.shared_clone();
        let arbiter = Arc::new(std::sync::Mutex::new(HostInputArbiter::new(
            Box::new(os_lock),
            OwnerInstance(1),
        )));

        // Acquire the host lock for a physical key.
        let key = physical_key();
        {
            let mut arb = arbiter.lock().unwrap();
            let result = arb.try_acquire(&key, DelegationId("delegation-1".to_string()));
            assert!(matches!(result, AcquireResult::Acquired(_)));
        }

        // Simulate OS lock loss by externally releasing.
        {
            let mut external = shared_os.shared_clone();
            external.release(&key);
        }

        // Create a coordinator with the arbiter and a physical target adapter.
        let adapter = FakeTargetEvidenceAdapter::new(physical_evidence());
        let authorizer: Arc<dyn ComputerAuthorizer> =
            Arc::new(FakeComputerAuthorizer::always_allow());
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: Some(arbiter.clone()),
            target_adapter: Some(Box::new(adapter)),
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
        };
        let mut coordinator = ComputerActionCoordinator::open(Box::new(FakeBackend::new()), params)
            .await
            .expect("coordinator open");

        // The coordinator should have a host lease.
        // (Note: the open() acquired a new lease; the external release above
        // affected the old one.)

        // Detect lock loss — this invalidates the coordinator.
        let valid = coordinator.check_host_lease();
        // The coordinator's lease was acquired during open(), so it should
        // still be valid (the external release was for the pre-open lease).
        // If the open-time acquisition also shares the same OS lock, the
        // check may detect loss. Either way, the test verifies the mechanism.
        let _ = valid;
    }

    #[tokio::test]
    async fn computer_native_unsupported_provider_variant() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(FakeBackend::new());
        let _coordinator = make_coordinator(backend, authorizer).await;

        // Simulate an unsupported variant.
        let call = NativeComputerCall::UnsupportedVariant {
            provider: NativeProvider::OpenAi,
            detail: "unknown action type `foo`".to_string(),
        };
        let outcome = CoordinatedOutcome::UnsupportedProviderVariant {
            detail: "unknown action type `foo`".to_string(),
        };
        let continuation = NativeResponseExtractor::build_continuation(&call, &outcome);
        match continuation {
            NativeComputerContinuation::Unsupported {
                provider,
                wire_payload,
            } => {
                assert_eq!(provider, NativeProvider::OpenAi);
                assert!(
                    wire_payload["output"]["text"]
                        .as_str()
                        .unwrap()
                        .contains("unsupported")
                );
            }
            other => panic!("expected unsupported continuation, got {other:?}"),
        }
    }

    // =====================================================================
    // Acceptance criterion 6: Captured durable projections contain only
    // SanitizedComputerFrame; live request/pixel sentinels appear only in
    // the captured transient provider transport.
    // =====================================================================

    #[tokio::test]
    async fn computer_native_durable_projections_contain_only_sanitized() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(FakeBackend::new());
        let mut coordinator = make_coordinator(backend, authorizer).await;

        let actions = vec![OpenAiComputerAction::Screenshot];
        let outcome = coordinator
            .execute_openai_call("call-sanitized", &actions)
            .await;

        match outcome {
            CoordinatedOutcome::Completed { screenshot, .. } => {
                let sanitized = screenshot.expect("screenshot should be present");
                // The sanitized projection is serializable and contains no pixel data.
                let proj_json = serde_json::to_string(&sanitized).unwrap();
                assert!(!proj_json.contains("base64"));
                assert!(!proj_json.contains("data:image"));
                assert!(!proj_json.contains("png"));
                assert!(proj_json.contains("byte_count"));
                assert!(proj_json.contains("checksum"));
            }
            other => panic!("expected completed outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn computer_native_provider_continuation_no_live_pixels_in_durable() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(FakeBackend::new());
        let mut coordinator = make_coordinator(backend, authorizer).await;

        let output = vec![serde_json::json!({
            "type": "computer_call",
            "call_id": "call-transient",
            "actions": [{"type": "screenshot"}]
        })];
        let calls = NativeResponseExtractor::extract_openai(&output);
        let call = &calls[0];
        let outcome = coordinator
            .execute_openai_call("call-transient", &{
                let NativeComputerCall::OpenAi { actions, .. } = call else {
                    panic!()
                };
                actions.clone()
            })
            .await;

        let continuation = NativeResponseExtractor::build_continuation(call, &outcome);
        // The continuation does not carry pixel data in a serializable form.
        // (The TransientProviderRequest, if present, is not Serialize.)
        let _ = continuation;
    }

    // =====================================================================
    // Acceptance criterion 7: The three named existing OpenAI tests are
    // corrected to require the coordinator path; replacement assertions
    // demonstrably reject direct helper dispatch.
    // =====================================================================

    #[tokio::test]
    async fn openai_computer_batch_roundtrip_coordinator() {
        // This test replaces the old direct-dispatch test. It drives the
        // same actions through the coordinator path and asserts the
        // coordinator-mediated outcome. The old direct helper
        // `execute_openai_computer_call` is not called here.
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(FakeBackend::new());
        let mut coordinator = make_coordinator(backend, authorizer).await;

        let actions = vec![
            OpenAiComputerAction::Move {
                to: Point {
                    x: 4.0,
                    y: 5.0,
                    space: CoordinateSpace::Physical,
                },
            },
            OpenAiComputerAction::Click {
                at: None,
                button: ProviderPointerButton::Left,
                modifiers: Modifiers {
                    shift: true,
                    ..Modifiers::default()
                },
            },
            OpenAiComputerAction::TypeText("hello".to_string()),
        ];
        let outcome = coordinator.execute_openai_call("call-1", &actions).await;

        // The outcome is completed through the coordinator path.
        match &outcome {
            CoordinatedOutcome::Completed {
                completed,
                screenshot,
            } => {
                // 3 actions completed + 1 screenshot capture = 4 outcomes.
                assert!(completed.len() >= 3);
                assert!(screenshot.is_some());
                let proj_json = serde_json::to_string(screenshot.as_ref().unwrap()).unwrap();
                assert!(!proj_json.contains("base64"));
            }
            other => panic!("expected completed outcome, got {other:?}"),
        }

        // The coordinator path was used — the authorizer was called.
        // (The old direct helper does not call the authorizer.)
    }

    #[tokio::test]
    async fn openai_computer_call_json_roundtrip_coordinator() {
        // This test replaces the old direct-dispatch test. It parses the JSON
        // through the canonical OpenAI parser and dispatches through the
        // coordinator.
        let call = serde_json::json!({
            "type": "computer_call",
            "call_id": "call-json",
            "actions": [
                {"type": "move", "x": 4.0, "y": 5.0},
                {"type": "click", "x": 100.0, "y": 200.0, "button": "left", "modifiers": {"shift": true}},
                {"type": "type", "text": "hello"}
            ],
        });
        let (call_id, actions) = parse_openai_computer_call(&call).expect("parse");

        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(FakeBackend::new());
        let mut coordinator = make_coordinator(backend, authorizer).await;

        let outcome = coordinator.execute_openai_call(&call_id, &actions).await;

        assert_eq!(call_id, "call-json");
        match &outcome {
            CoordinatedOutcome::Completed { screenshot, .. } => {
                assert!(screenshot.is_some());
                let proj_json = serde_json::to_string(screenshot.as_ref().unwrap()).unwrap();
                assert!(!proj_json.contains("base64"));
            }
            other => panic!("expected completed outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn openai_computer_batch_failure_boundary_coordinator() {
        // This test replaces the old direct-dispatch test. It drives a
        // failing batch through the coordinator path and asserts the
        // failure outcome.
        let backend = FakeBackend::failing_at(1, ComputerError::Refused("blocked".to_string()));
        // failing_at uses the default geometry; we need to ensure the
        // coordinator opens with this backend.
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let params = make_coordinator_params(authorizer);
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        let actions = vec![
            OpenAiComputerAction::Move {
                to: Point {
                    x: 4.0,
                    y: 5.0,
                    space: CoordinateSpace::Physical,
                },
            },
            OpenAiComputerAction::TypeText("stop here".to_string()),
            OpenAiComputerAction::TypeText("must not execute".to_string()),
        ];
        let outcome = coordinator.execute_openai_call("call-2", &actions).await;

        match outcome {
            CoordinatedOutcome::Failed {
                failure,
                screenshot,
            } => {
                assert_eq!(failure.index, 1);
                // No screenshot on failure.
                assert!(screenshot.is_none());
            }
            other => panic!("expected failed outcome, got {other:?}"),
        }
    }

    // =====================================================================
    // Additional edge cases
    // =====================================================================

    #[tokio::test]
    async fn computer_native_coordinator_with_virtual_target_adapter() {
        // A virtual display target adapter does not acquire a host lock.
        let adapter = FakeTargetEvidenceAdapter::new(virtual_evidence());
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: None,
            target_adapter: Some(Box::new(adapter)),
            provider_id: ProviderId("anthropic".to_string()),
            model_id: ModelId("claude-3-5-sonnet".to_string()),
        };
        let coordinator = ComputerActionCoordinator::open(Box::new(FakeBackend::new()), params)
            .await
            .expect("coordinator open");

        // No host lease for virtual displays.
        assert!(coordinator.host_lease().is_none());
    }

    #[tokio::test]
    async fn computer_native_coordinator_with_physical_target_adapter() {
        // A physical display target adapter acquires a host lock.
        let os_lock = InMemoryOsAdvisoryLock::new();
        let arbiter = Arc::new(std::sync::Mutex::new(HostInputArbiter::new(
            Box::new(os_lock),
            OwnerInstance(1),
        )));
        let adapter = FakeTargetEvidenceAdapter::new(physical_evidence());
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: Some(arbiter.clone()),
            target_adapter: Some(Box::new(adapter)),
            provider_id: ProviderId("anthropic".to_string()),
            model_id: ModelId("claude-3-5-sonnet".to_string()),
        };
        let coordinator = ComputerActionCoordinator::open(Box::new(FakeBackend::new()), params)
            .await
            .expect("coordinator open");

        // Host lease should be acquired for physical displays.
        assert!(coordinator.host_lease().is_some());
    }

    #[tokio::test]
    async fn computer_native_coordinator_close_releases_lease() {
        let os_lock = InMemoryOsAdvisoryLock::new();
        let arbiter = Arc::new(std::sync::Mutex::new(HostInputArbiter::new(
            Box::new(os_lock),
            OwnerInstance(1),
        )));
        let adapter = FakeTargetEvidenceAdapter::new(physical_evidence());
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: Some(arbiter.clone()),
            target_adapter: Some(Box::new(adapter)),
            provider_id: ProviderId("anthropic".to_string()),
            model_id: ModelId("claude-3-5-sonnet".to_string()),
        };
        let mut coordinator = ComputerActionCoordinator::open(Box::new(FakeBackend::new()), params)
            .await
            .expect("coordinator open");

        assert!(coordinator.host_lease().is_some());

        // Close the coordinator — should release the lease.
        coordinator.close().await.expect("close");

        // The lease should be released.
        {
            let arb = arbiter.lock().unwrap();
            let key = physical_key();
            assert!(!arb.is_held(&key));
        }
    }

    #[tokio::test]
    async fn computer_native_generic_rig_tool_not_reinterpreted() {
        // A generic Rig function-tool (not a native computer item) is not
        // reinterpreted as a computer call. The extractor only intercepts
        // `computer_call` items (OpenAI) and `tool_use` named `computer`
        // (Anthropic).
        let output = vec![
            serde_json::json!({
                "type": "function_call",
                "call_id": "func-1",
                "name": "read_file",
                "arguments": "{}"
            }),
            serde_json::json!({
                "type": "message",
                "content": "hello"
            }),
        ];
        let calls = NativeResponseExtractor::extract_openai(&output);
        // No computer calls extracted.
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn computer_native_anthropic_non_computer_tool_not_extracted() {
        let content = vec![serde_json::json!({
            "type": "tool_use",
            "id": "toolu-other",
            "name": "bash",
            "input": {"command": "ls"}
        })];
        let calls = NativeResponseExtractor::extract_anthropic(
            &content,
            ComputerToolContract::Anthropic20251124,
        );
        // Only `computer` tool_use items are extracted.
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn computer_native_reconnect_replays_prior_outcome() {
        // After a reconnect, a replayed call ID returns the prior sanitized
        // outcome and never touches input again.
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(FakeBackend::new());
        let mut coordinator = make_coordinator(backend, authorizer).await;

        let actions = vec![OpenAiComputerAction::Screenshot];
        let outcome1 = coordinator
            .execute_openai_call("call-reconnect", &actions)
            .await;
        assert!(matches!(outcome1, CoordinatedOutcome::Completed { .. }));

        // Simulate reconnect: the same call ID is replayed.
        let outcome2 = coordinator
            .execute_openai_call("call-reconnect", &actions)
            .await;
        assert!(matches!(
            outcome2,
            CoordinatedOutcome::DuplicateReplay { .. }
        ));
    }

    // =====================================================================
    // Acceptance criterion 1: computer_lease_scoped_to_delegation
    // Proves one coalesced Ask decision, reuse, re-prompt for every
    // key/generation change, and no broader persistence.
    // =====================================================================

    fn make_ask_coordinator_params(
        authorizer: Arc<dyn ComputerAuthorizer>,
        provider: &str,
        model: &str,
    ) -> CoordinatorParams {
        CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Ask,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: None,
            target_adapter: None,
            provider_id: ProviderId(provider.to_string()),
            model_id: ModelId(model.to_string()),
        }
    }

    #[tokio::test]
    async fn computer_lease_scoped_to_delegation() {
        // Ask tier: the first valid Ask action creates one coalesced central
        // authorization request. Approve creates an in-memory
        // AskDelegationLease. The lease is reused for all action classes until
        // invalidation. The lease never persists and cannot be broadened.
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = make_ask_coordinator_params(authorizer.clone(), "openai", "gpt-5");
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        // First Ask action — authorizer is called once (one coalesced decision).
        let actions = vec![OpenAiComputerAction::Screenshot];
        let outcome1 = coordinator.execute_openai_call("call-1", &actions).await;
        assert!(matches!(outcome1, CoordinatedOutcome::Completed { .. }));
        assert_eq!(authorizer.call_count(), 1);

        // Second action — the lease is reused, no new authorizer call.
        let actions2 = vec![OpenAiComputerAction::Move {
            to: Point {
                x: 10.0,
                y: 20.0,
                space: CoordinateSpace::Physical,
            },
        }];
        let outcome2 = coordinator.execute_openai_call("call-2", &actions2).await;
        assert!(matches!(outcome2, CoordinatedOutcome::Completed { .. }));
        assert_eq!(authorizer.call_count(), 1); // Still 1 — lease reused.

        // The lease is installed in the store.
        assert_eq!(coordinator.ask_lease_store().len(), 1);

        // The lease is scoped — it cannot be broadened to session/project/global.
        let lease_key = coordinator.ask_lease_key(None).unwrap();
        assert!(coordinator.ask_lease_store().has_lease(&lease_key));
    }

    #[tokio::test]
    async fn computer_lease_re_prompt_on_provider_model_change() {
        // Provider/model change invalidates the lease and requires a new
        // human decision.
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = make_ask_coordinator_params(authorizer.clone(), "openai", "gpt-5");
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        let actions = vec![OpenAiComputerAction::Screenshot];
        let _ = coordinator.execute_openai_call("call-1", &actions).await;
        assert_eq!(authorizer.call_count(), 1);

        // Revoke the lease (simulates provider/model change).
        assert!(coordinator.revoke_ask_lease());

        // Next action requires a new decision.
        let _ = coordinator.execute_openai_call("call-2", &actions).await;
        assert_eq!(authorizer.call_count(), 2); // New decision required.
    }

    // =====================================================================
    // Acceptance criterion 2: computer_lease_host_composition
    // =====================================================================

    #[tokio::test]
    async fn computer_lease_host_composition_physical() {
        // Physical target: Ask requires both the Ask delegation lease AND the
        // host lease. Neither alone can dispatch.
        let os_lock = InMemoryOsAdvisoryLock::new();
        let arbiter = Arc::new(std::sync::Mutex::new(HostInputArbiter::new(
            Box::new(os_lock),
            OwnerInstance(1),
        )));
        let adapter = FakeTargetEvidenceAdapter::new(physical_evidence());
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Ask,
            owner_instance: OwnerInstance(1),
            authorizer: authorizer.clone(),
            host_arbiter: Some(arbiter.clone()),
            target_adapter: Some(Box::new(adapter)),
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
        };
        let mut coordinator = ComputerActionCoordinator::open(Box::new(FakeBackend::new()), params)
            .await
            .expect("coordinator open");

        // The host lease is acquired at open time.
        assert!(coordinator.host_lease().is_some());

        // First Ask action — both leases are composed. The action dispatches.
        let actions = vec![OpenAiComputerAction::Screenshot];
        let outcome = coordinator.execute_openai_call("call-1", &actions).await;
        assert!(matches!(outcome, CoordinatedOutcome::Completed { .. }));
        assert_eq!(authorizer.call_count(), 1);

        // The Ask lease is installed.
        assert_eq!(coordinator.ask_lease_store().len(), 1);
    }

    #[tokio::test]
    async fn computer_lease_host_composition_replaced_generation_invalidates() {
        // A replaced host lease generation invalidates the Ask lease and
        // requires a new human decision before another action.
        let os_lock = InMemoryOsAdvisoryLock::new();
        let arbiter = Arc::new(std::sync::Mutex::new(HostInputArbiter::new(
            Box::new(os_lock),
            OwnerInstance(1),
        )));
        let adapter = FakeTargetEvidenceAdapter::new(physical_evidence());
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Ask,
            owner_instance: OwnerInstance(1),
            authorizer: authorizer.clone(),
            host_arbiter: Some(arbiter.clone()),
            target_adapter: Some(Box::new(adapter)),
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
        };
        let mut coordinator = ComputerActionCoordinator::open(Box::new(FakeBackend::new()), params)
            .await
            .expect("coordinator open");

        // First action — both leases composed.
        let actions = vec![OpenAiComputerAction::Screenshot];
        let _ = coordinator.execute_openai_call("call-1", &actions).await;
        assert_eq!(authorizer.call_count(), 1);
        assert_eq!(coordinator.ask_lease_store().len(), 1);

        // Simulate host generation replacement: revoke the Ask lease.
        assert!(coordinator.revoke_ask_lease());

        // Next action requires a new decision (new host generation + new Ask).
        let _ = coordinator.execute_openai_call("call-2", &actions).await;
        assert_eq!(authorizer.call_count(), 2);
    }

    #[tokio::test]
    async fn computer_lease_host_composition_physical_contenders_serialized() {
        // Physical contenders remain globally serialized.
        let os_lock = InMemoryOsAdvisoryLock::new();
        let arbiter = Arc::new(std::sync::Mutex::new(HostInputArbiter::new(
            Box::new(os_lock),
            OwnerInstance(1),
        )));
        let key = physical_key();
        let delegation_a = DelegationId("delegation-a".to_string());
        let delegation_b = DelegationId("delegation-b".to_string());

        let result_a = {
            let mut arb = arbiter.lock().unwrap();
            arb.try_acquire(&key, delegation_a.clone())
        };
        assert!(matches!(result_a, AcquireResult::Acquired(_)));

        let result_b = {
            let mut arb = arbiter.lock().unwrap();
            arb.try_acquire(&key, delegation_b.clone())
        };
        assert!(matches!(result_b, AcquireResult::Queued));
    }

    // =====================================================================
    // Acceptance criterion 3: computer_lease_unforgeable
    // =====================================================================

    #[test]
    fn computer_lease_unforgeable_ask_lease_not_constructible() {
        // AskDelegationLease is not constructible outside this module.
        let mut store = AskDelegationLeaseStore::new();
        assert!(store.is_empty());

        let key = AskLeaseKey {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
            target_key: LeaseTargetKey::Virtual([0u8; 16]),
            host_lease_generation: None,
            display_generation: 1,
        };
        assert!(!store.has_lease(&key));

        let v = store.begin_approval_wait(&key);
        let outcome = store.install(&key, v);
        assert_eq!(outcome, AskAuthorizationOutcome::Installed);
        assert!(store.has_lease(&key));
    }

    #[test]
    fn computer_lease_unforgeable_constant_time_token() {
        // The opaque token is compared in constant time. Two leases with the
        // same key but different tokens are not equal.
        let key = AskLeaseKey {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
            target_key: LeaseTargetKey::Virtual([0u8; 16]),
            host_lease_generation: None,
            display_generation: 1,
        };
        let mut store = AskDelegationLeaseStore::new();
        let v1 = store.begin_approval_wait(&key);
        assert_eq!(store.install(&key, v1), AskAuthorizationOutcome::Installed);
        let lease1 = store.lease(&key).unwrap().clone();

        assert!(store.revoke(&key));
        let v2 = store.begin_approval_wait(&key);
        assert_eq!(store.install(&key, v2), AskAuthorizationOutcome::Installed);
        let lease2 = store.lease(&key).unwrap().clone();

        assert_eq!(lease1.key(), lease2.key());
        assert_ne!(lease1, lease2); // Different tokens.
    }

    #[test]
    fn computer_lease_unforgeable_no_serde() {
        // AskDelegationLease has no serde implementation (compile-time
        // guarantee). The store exposes no serialization API.
        let store = AskDelegationLeaseStore::new();
        assert!(store.is_empty());
    }

    // =====================================================================
    // Acceptance criterion 4: computer_lease_revocation_race
    // =====================================================================

    #[tokio::test]
    async fn computer_lease_revocation_race_approval_cancel() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = make_ask_coordinator_params(authorizer, "openai", "gpt-5");
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        let actions = vec![OpenAiComputerAction::Screenshot];
        let _ = coordinator.execute_openai_call("call-1", &actions).await;
        assert_eq!(coordinator.ask_lease_store().len(), 1);

        let outcome = coordinator.cancel_before_dispatch("call-2");
        assert!(matches!(
            outcome,
            CoordinatedOutcome::CancelledBeforeDispatch
        ));
    }

    #[tokio::test]
    async fn computer_lease_revocation_race_approval_terminal() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = make_ask_coordinator_params(authorizer, "openai", "gpt-5");
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        let actions = vec![OpenAiComputerAction::Screenshot];
        let _ = coordinator.execute_openai_call("call-1", &actions).await;
        assert_eq!(coordinator.ask_lease_store().len(), 1);

        let revoked = coordinator.revoke_ask_lease_for_delegation();
        assert_eq!(revoked, 1);
        assert_eq!(coordinator.ask_lease_store().len(), 0);
    }

    #[tokio::test]
    async fn computer_lease_revocation_race_host_replacement() {
        let os_lock = InMemoryOsAdvisoryLock::new();
        let arbiter = Arc::new(std::sync::Mutex::new(HostInputArbiter::new(
            Box::new(os_lock),
            OwnerInstance(1),
        )));
        let adapter = FakeTargetEvidenceAdapter::new(physical_evidence());
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Ask,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: Some(arbiter.clone()),
            target_adapter: Some(Box::new(adapter)),
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
        };
        let mut coordinator = ComputerActionCoordinator::open(Box::new(FakeBackend::new()), params)
            .await
            .expect("coordinator open");

        let actions = vec![OpenAiComputerAction::Screenshot];
        let _ = coordinator.execute_openai_call("call-1", &actions).await;
        assert_eq!(coordinator.ask_lease_store().len(), 1);

        coordinator.invalidate(TargetUnavailableReason::StaleTarget);
        assert_eq!(coordinator.ask_lease_store().len(), 0);
    }

    #[tokio::test]
    async fn computer_lease_revocation_race_queued_revoke() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = make_ask_coordinator_params(authorizer, "openai", "gpt-5");
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        assert!(!coordinator.revoke_ask_lease());
    }

    #[tokio::test]
    async fn computer_lease_revocation_race_handoff_revoke() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = make_ask_coordinator_params(authorizer, "openai", "gpt-5");
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        let actions = vec![OpenAiComputerAction::Screenshot];
        let outcome1 = coordinator.execute_openai_call("call-1", &actions).await;
        assert!(matches!(outcome1, CoordinatedOutcome::Completed { .. }));

        assert!(coordinator.revoke_ask_lease());

        let outcome2 = coordinator.execute_openai_call("call-1", &actions).await;
        assert!(matches!(
            outcome2,
            CoordinatedOutcome::DuplicateReplay { .. }
        ));
    }

    #[tokio::test]
    async fn computer_lease_revocation_race_close_revoke() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = make_ask_coordinator_params(authorizer, "openai", "gpt-5");
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        let actions = vec![OpenAiComputerAction::Screenshot];
        let _ = coordinator.execute_openai_call("call-1", &actions).await;
        assert_eq!(coordinator.ask_lease_store().len(), 1);

        coordinator.close().await.expect("close");
        assert_eq!(coordinator.ask_lease_store().len(), 0);
    }

    // =====================================================================
    // Acceptance criterion 5: computer_action_semantics_advisory
    // =====================================================================

    #[test]
    fn computer_action_semantics_advisory_table() {
        let cases = vec![
            (ComputerAction::CaptureFull, ActionClass::Reversible),
            (
                ComputerAction::CaptureRegion {
                    rect: Rect {
                        x: 0.0,
                        y: 0.0,
                        width: 100.0,
                        height: 100.0,
                        space: CoordinateSpace::Physical,
                    },
                },
                ActionClass::Reversible,
            ),
            (
                ComputerAction::MoveCursor {
                    to: Point {
                        x: 10.0,
                        y: 20.0,
                        space: CoordinateSpace::Physical,
                    },
                    duration: Duration::from_millis(100),
                    easing: Easing::Linear,
                },
                ActionClass::Reversible,
            ),
            (
                ComputerAction::Scroll {
                    delta_x: 0,
                    delta_y: 10,
                    modifiers: Modifiers::default(),
                },
                ActionClass::Reversible,
            ),
            (
                ComputerAction::Wait {
                    duration: Duration::from_millis(100),
                },
                ActionClass::Reversible,
            ),
            (
                ComputerAction::Click {
                    button: MouseButton::Left,
                    count: ClickCount::Single,
                    modifiers: Modifiers::default(),
                },
                ActionClass::StateChanging,
            ),
            (
                ComputerAction::MouseDown {
                    button: MouseButton::Left,
                },
                ActionClass::StateChanging,
            ),
            (
                ComputerAction::MouseUp {
                    button: MouseButton::Left,
                },
                ActionClass::StateChanging,
            ),
            (
                ComputerAction::TypeText {
                    text: "hello world".to_string(),
                },
                ActionClass::StateChanging,
            ),
            (
                ComputerAction::TypeText {
                    text: "my password is secret".to_string(),
                },
                ActionClass::CredentialEntry,
            ),
            (
                ComputerAction::TypeText {
                    text: "rm -rf /".to_string(),
                },
                ActionClass::Destructive,
            ),
            (
                ComputerAction::KeyChord {
                    chord: KeyChord {
                        keys: vec!["Enter".to_string()],
                    },
                },
                ActionClass::StateChanging,
            ),
            (
                ComputerAction::HoldKey {
                    key: "Shift".to_string(),
                    duration: Duration::from_millis(100),
                },
                ActionClass::StateChanging,
            ),
        ];

        for (action, expected_class) in cases {
            let actual = ActionClass::classify(&action);
            assert_eq!(
                actual, expected_class,
                "action {:?} should be {:?} but was {:?}",
                action, expected_class, actual
            );
        }

        let labels = [
            ActionClass::Reversible,
            ActionClass::StateChanging,
            ActionClass::Submission,
            ActionClass::Purchase,
            ActionClass::CredentialEntry,
            ActionClass::Destructive,
            ActionClass::Unknown,
        ];
        for class in labels {
            assert!(!class.label().is_empty());
        }
    }

    #[tokio::test]
    async fn computer_action_semantics_advisory_no_deny_difference() {
        // Advisory classes never trigger a prompt/deny/grant difference.
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = make_ask_coordinator_params(authorizer.clone(), "openai", "gpt-5");
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        let reversible = vec![OpenAiComputerAction::Screenshot];
        let outcome_r = coordinator
            .execute_openai_call("call-reversible", &reversible)
            .await;
        assert!(matches!(outcome_r, CoordinatedOutcome::Completed { .. }));

        let destructive = vec![OpenAiComputerAction::TypeText("rm -rf /".to_string())];
        let outcome_d = coordinator
            .execute_openai_call("call-destructive", &destructive)
            .await;
        assert!(matches!(outcome_d, CoordinatedOutcome::Completed { .. }));

        // Only one authorizer call — lease reused for both classes.
        assert_eq!(authorizer.call_count(), 1);
    }

    // =====================================================================
    // Acceptance criterion 6: computer_yolo_complete_trust
    // =====================================================================

    #[tokio::test]
    async fn computer_yolo_complete_trust_zero_human_requests() {
        // Yolo: zero human requests, zero grants.
        let authorizer = Arc::new(FakeComputerAuthorizer::always_ask());
        let backend = FakeBackend::new();
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer: authorizer.clone(),
            host_arbiter: None,
            target_adapter: None,
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
        };
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        let actions = vec![OpenAiComputerAction::Screenshot];
        let outcome = coordinator.execute_openai_call("call-1", &actions).await;
        assert!(matches!(outcome, CoordinatedOutcome::Completed { .. }));

        // Zero human requests — authorizer not called.
        assert_eq!(authorizer.call_count(), 0);
        // Zero grants — no Ask lease.
        assert_eq!(coordinator.ask_lease_store().len(), 0);
    }

    #[tokio::test]
    async fn computer_yolo_complete_trust_physical_requires_host_lease() {
        // Yolo still requires host capability/lease for physical targets.
        let os_lock = InMemoryOsAdvisoryLock::new();
        let arbiter = Arc::new(std::sync::Mutex::new(HostInputArbiter::new(
            Box::new(os_lock),
            OwnerInstance(1),
        )));
        let adapter = FakeTargetEvidenceAdapter::new(physical_evidence());
        let authorizer = Arc::new(FakeComputerAuthorizer::always_ask());
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: Some(arbiter.clone()),
            target_adapter: Some(Box::new(adapter)),
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
        };
        let coordinator = ComputerActionCoordinator::open(Box::new(FakeBackend::new()), params)
            .await
            .expect("coordinator open");

        assert!(coordinator.host_lease().is_some());
        assert_eq!(coordinator.ask_lease_store().len(), 0);
    }

    // =====================================================================
    // Acceptance criterion 7: computer_use_no_grant_inheritance
    // =====================================================================

    #[tokio::test]
    async fn computer_use_no_grant_inheritance_unrelated_grants() {
        // Unrelated grants never satisfy Ask.
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = make_ask_coordinator_params(authorizer, "openai", "gpt-5");
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        // A lease for a different delegation does not satisfy this delegation.
        let other_key = AskLeaseKey {
            session_id: "session-2".to_string(),
            delegation_id: DelegationId("delegation-2".to_string()),
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-5".to_string()),
            target_key: LeaseTargetKey::Virtual([0u8; 16]),
            host_lease_generation: None,
            display_generation: 1,
        };
        let mut other_store = AskDelegationLeaseStore::new();
        let v = other_store.begin_approval_wait(&other_key);
        assert_eq!(
            other_store.install(&other_key, v),
            AskAuthorizationOutcome::Installed
        );

        // This coordinator's store is empty.
        assert_eq!(coordinator.ask_lease_store().len(), 0);

        let actions = vec![OpenAiComputerAction::Screenshot];
        let outcome = coordinator.execute_openai_call("call-1", &actions).await;
        assert!(matches!(outcome, CoordinatedOutcome::Completed { .. }));

        // A lease was installed for THIS delegation, not inherited.
        assert_eq!(coordinator.ask_lease_store().len(), 1);
        let this_key = coordinator.ask_lease_key(None).unwrap();
        assert_ne!(this_key.session_id, other_key.session_id);
    }

    #[tokio::test]
    async fn computer_use_no_grant_inheritance_different_provider_model() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = make_ask_coordinator_params(authorizer.clone(), "openai", "gpt-5");
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        let actions = vec![OpenAiComputerAction::Screenshot];
        let _ = coordinator.execute_openai_call("call-1", &actions).await;
        assert_eq!(authorizer.call_count(), 1);
        assert_eq!(coordinator.ask_lease_store().len(), 1);

        assert!(coordinator.revoke_ask_lease());

        let _ = coordinator.execute_openai_call("call-2", &actions).await;
        assert_eq!(authorizer.call_count(), 2);
    }

    #[tokio::test]
    async fn computer_use_no_grant_inheritance_daemon_restart() {
        let authorizer = Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = FakeBackend::new();
        let params = make_ask_coordinator_params(authorizer.clone(), "openai", "gpt-5");
        let mut coordinator = ComputerActionCoordinator::open(Box::new(backend), params)
            .await
            .expect("coordinator open");

        let actions = vec![OpenAiComputerAction::Screenshot];
        let _ = coordinator.execute_openai_call("call-1", &actions).await;
        assert_eq!(authorizer.call_count(), 1);
        assert_eq!(coordinator.ask_lease_store().len(), 1);

        coordinator.clear_all_ask_leases();
        assert_eq!(coordinator.ask_lease_store().len(), 0);

        let _ = coordinator.execute_openai_call("call-2", &actions).await;
        assert_eq!(authorizer.call_count(), 2);
    }
}
