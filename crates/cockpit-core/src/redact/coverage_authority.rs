//! Daemon-owned admission for secret-bearing redaction work.
//!
//! This module deliberately keeps source identity, candidate fingerprints and
//! matcher artifacts private.  A caller gets a short-lived, non-cloneable
//! admission and can use it exactly once at its owned sink.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    path::Path,
    sync::{Arc, Mutex, Weak},
};

use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use super::RedactionTable;

pub(crate) const COVERAGE_WORKERS: usize = 2;
pub(crate) const COVERAGE_QUEUE: usize = 32;
pub(crate) const COVERAGE_FLIGHTS: usize = 64;
pub(crate) const COVERAGE_WAITERS_PER_KEY: usize = 16;
pub(crate) const COVERAGE_WAITERS: usize = 256;
pub(crate) const COVERAGE_ADMISSIONS: usize = 256;
pub(crate) const COVERAGE_RESIDENT_GENERATIONS: usize = 64;
pub(crate) const COVERAGE_ARTIFACT_BYTES_PER_GENERATION: usize = 4 * 1024 * 1024;
pub(crate) const COVERAGE_ARTIFACT_BYTES_TOTAL: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoverageOwnerMode {
    Persistent,
    Ephemeral,
    InProcess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoverageLimits {
    pub workers: usize,
    pub queued: usize,
    pub flight_keys: usize,
    pub waiters_per_key: usize,
    pub waiters: usize,
    pub admissions: usize,
    pub resident_generations: usize,
    pub artifact_bytes_per_generation: usize,
    pub artifact_bytes_total: usize,
}

pub(crate) const COVERAGE_LIMITS: CoverageLimits = CoverageLimits {
    workers: COVERAGE_WORKERS,
    queued: COVERAGE_QUEUE,
    flight_keys: COVERAGE_FLIGHTS,
    waiters_per_key: COVERAGE_WAITERS_PER_KEY,
    waiters: COVERAGE_WAITERS,
    admissions: COVERAGE_ADMISSIONS,
    resident_generations: COVERAGE_RESIDENT_GENERATIONS,
    artifact_bytes_per_generation: COVERAGE_ARTIFACT_BYTES_PER_GENERATION,
    artifact_bytes_total: COVERAGE_ARTIFACT_BYTES_TOTAL,
};

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A daemon-derived opaque component of a coverage binding.  It is purposely
/// not printable: source identities must not become a diagnostics channel.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CoverageBinding([u8; 16]);

impl CoverageBinding {
    pub(crate) const fn from_daemon_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Derive a private binding component from daemon-owned identity bytes.
    /// The result never crosses a protocol or diagnostic boundary.
    pub(crate) fn derive(domain: &[u8], identity: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"flycockpit-redaction-coverage-binding-v1\0");
        digest.update(domain);
        digest.update([0]);
        digest.update(identity);
        let digest = digest.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Self(bytes)
    }
}

impl fmt::Debug for CoverageBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoverageBinding(..)")
    }
}

/// The operation purpose is audit metadata on an admission. It is deliberately
/// not part of [`RedactionCoverageKey`]: one accepted source capture must be
/// reusable by submission, driver and inference while every source binding is
/// unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CoverageScope {
    DaemonGlobalBootstrap,
    DaemonGlobalEvent,
    DaemonGlobalRefresh,
    SessionStart,
    SessionSubmission,
    DriverTurn,
    CredentialRetry,
    RedactedExport,
    DocsAsk,
    AutoTitle,
    InputPrediction,
    TagInline,
    McpSandboxProjection,
    ApprovalPreview,
    DebugContext,
    RedactionOverride,
}

/// All members are opaque daemon-derived revisions/identities.  A key cannot
/// be made from a path, a secret, a candidate list, or an exposed fingerprint.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct RedactionCoverageKey {
    principal: CoverageBinding,
    owner_authorization: CoverageBinding,
    session: Option<CoverageBinding>,
    workspace: Option<CoverageBinding>,
    environment: CoverageBinding,
    credential_vault: CoverageBinding,
    policy: CoverageBinding,
    sealed: CoverageBinding,
    override_revision: CoverageBinding,
    machine_sources: CoverageBinding,
}

impl fmt::Debug for RedactionCoverageKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactionCoverageKey")
            .finish_non_exhaustive()
    }
}

impl RedactionCoverageKey {
    fn same_lineage(&self, other: &Self) -> bool {
        self.principal == other.principal
            && self.owner_authorization == other.owner_authorization
            && self.session == other.session
            && self.workspace == other.workspace
    }

    /// Refresh mutable owned-source revisions while retaining the daemon-bound
    /// principal, authorization, session, and workspace identity. Callers
    /// derive `current` from live inputs; they cannot reconstruct the retained
    /// authorization identity from a numeric guess at a later turn.
    pub(crate) fn with_current_owned_revisions(&self, current: &Self) -> Self {
        let mut refreshed = self.clone();
        refreshed.environment = current.environment;
        refreshed.credential_vault = current.credential_vault;
        refreshed.policy = current.policy;
        refreshed.sealed = current.sealed;
        refreshed.override_revision = current.override_revision;
        refreshed.machine_sources = current.machine_sources;
        refreshed
    }

    pub(crate) fn matches_owned_revisions(
        &self,
        revisions: &super::coverage_bindings::OwnedSourceRevisions,
    ) -> bool {
        self.environment == revisions.environment
            && self.credential_vault == revisions.credential_vault
            && self.policy == revisions.policy
            && self.sealed == revisions.sealed
            && self.override_revision == revisions.override_revision
            && self.machine_sources == revisions.machine_sources
    }

    pub(crate) fn for_derived_session(&self, session_id: Uuid) -> Self {
        let mut derived = self.clone();
        derived.principal = CoverageBinding::derive(b"principal", session_id.as_bytes());
        derived.session = Some(CoverageBinding::derive(b"session", session_id.as_bytes()));
        derived
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn session(
        principal: CoverageBinding,
        owner_authorization: CoverageBinding,
        session: CoverageBinding,
        workspace: CoverageBinding,
        environment: CoverageBinding,
        credential_vault: CoverageBinding,
        policy: CoverageBinding,
        sealed: CoverageBinding,
        override_revision: CoverageBinding,
        machine_sources: CoverageBinding,
    ) -> Self {
        Self {
            principal,
            owner_authorization,
            session: Some(session),
            workspace: Some(workspace),
            environment,
            credential_vault,
            policy,
            sealed,
            override_revision,
            machine_sources,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn daemon_global(
        principal: CoverageBinding,
        owner_authorization: CoverageBinding,
        environment: CoverageBinding,
        credential_vault: CoverageBinding,
        policy: CoverageBinding,
        sealed: CoverageBinding,
        override_revision: CoverageBinding,
        machine_sources: CoverageBinding,
    ) -> Self {
        Self {
            principal,
            owner_authorization,
            session: None,
            workspace: None,
            environment,
            credential_vault,
            policy,
            sealed,
            override_revision,
            machine_sources,
        }
    }
}

/// Sanitized fail-closed result.  The variants intentionally carry no source
/// details; callers may turn them into their generic coverage-unavailable UX.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoverageError {
    Unavailable,
    Saturated,
    Invalidated,
    /// Complete capture found an env source that cannot be read within the
    /// daemon's fixed file cap. The category is safe to surface; the source
    /// path and all other capture details remain confined to the worker.
    SourceFileOverLimit,
}

impl fmt::Display for CoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "coverage_unavailable",
            Self::Saturated => "coverage_saturated",
            Self::Invalidated => "coverage_unavailable",
            Self::SourceFileOverLimit => "redaction source exceeds the daemon file size limit",
        })
    }
}

impl std::error::Error for CoverageError {}

struct LiveCurrentBindingGuard {
    generation: Arc<RedactionCoverageGeneration>,
}

impl Drop for LiveCurrentBindingGuard {
    fn drop(&mut self) {
        self.generation
            .live_current_bindings
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Generation-bound egress proof carried on [`RedactionTable`] scrub paths
/// during a one-operation [`CoverageAdmission::use_at_sink`] lease.
pub(crate) struct CoverageTableBinding {
    authority: Weak<Inner>,
    generation_id: Uuid,
    epoch: u64,
    generation_order: u64,
    key_revision: u64,
    key: RedactionCoverageKey,
    live_binding: Option<LiveCurrentBindingGuard>,
}

impl Clone for CoverageTableBinding {
    fn clone(&self) -> Self {
        let live_binding = self.live_binding.as_ref().map(|guard| {
            guard
                .generation
                .live_current_bindings
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            LiveCurrentBindingGuard {
                generation: guard.generation.clone(),
            }
        });
        Self {
            authority: self.authority.clone(),
            generation_id: self.generation_id,
            epoch: self.epoch,
            generation_order: self.generation_order,
            key_revision: self.key_revision,
            key: self.key.clone(),
            live_binding,
        }
    }
}

impl CoverageTableBinding {
    pub(crate) fn same_generation(&self, other: &Self) -> bool {
        self.authority.ptr_eq(&other.authority)
            && self.key == other.key
            && self.generation_id == other.generation_id
            && self.epoch == other.epoch
            && self.generation_order == other.generation_order
            && self.key_revision == other.key_revision
    }

    pub(crate) fn binding_ordering(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // A repeated opaque generation id must describe precisely the same
        // authority, key material, and counters. Anything else is forged or
        // ambiguous and cannot participate in an ordered historical fold.
        if self.generation_id == other.generation_id {
            return self
                .same_generation(other)
                .then_some(std::cmp::Ordering::Equal);
        }
        // Mutable source revisions may legitimately differ across historical
        // generations, but principal/session/workspace authority may not.
        if !self.authority.ptr_eq(&other.authority) || !self.key.same_lineage(&other.key) {
            return None;
        }
        let order = (self.epoch, self.generation_order, self.key_revision).cmp(&(
            other.epoch,
            other.generation_order,
            other.key_revision,
        ));
        if order == std::cmp::Ordering::Equal {
            // Generation order is authority-unique. Equal counters paired
            // with distinct ids cannot be assigned trustworthy provenance.
            None
        } else {
            Some(order)
        }
    }

    pub(crate) fn validate(&self) -> Result<(), CoverageError> {
        let inner = self.authority.upgrade().ok_or(CoverageError::Unavailable)?;
        let state = lock(&inner.state);
        let current = !state.closed
            && state.epoch == self.epoch
            && state.key_revisions.get(&self.key).copied().unwrap_or(0) == self.key_revision
            && state
                .residents
                .get(&self.key)
                .is_some_and(|resident| resident.generation.id == self.generation_id);
        if current {
            Ok(())
        } else {
            Err(CoverageError::Invalidated)
        }
    }
}

/// Rereads owned source revisions at publication time. Runs on the authority's
/// blocking pool so callers may consult live owners that are not async-safe.
/// Any owner reread failure must fail closed and prevent publication.
pub(crate) type CoveragePublishFence =
    Box<dyn Fn(&RedactionTable) -> Result<super::coverage_bindings::OwnedSourceRevisions> + Send>;

/// Complete, in-memory-only result of a source capture. `artifact_bytes` is
/// supplied by the capture owner after measuring private parsed artifacts.
pub(crate) struct CoverageBuild {
    table: Arc<RedactionTable>,
    artifact_bytes: usize,
    boundary_revisions: super::coverage_bindings::OwnedSourceRevisions,
    publish_fence: Option<CoveragePublishFence>,
}

impl CoverageBuild {
    pub(crate) fn from_complete_table(
        table: RedactionTable,
        boundary_revisions: super::coverage_bindings::OwnedSourceRevisions,
    ) -> Self {
        let artifact_bytes = table.measured_immutable_artifact_bytes();
        Self::from_complete_table_and_artifact_bytes(table, artifact_bytes, boundary_revisions)
    }

    /// Construct a build from a table whose complete-capture owner already
    /// measured the immutable candidate and matcher artifacts.
    pub(crate) fn from_complete_table_and_artifact_bytes(
        table: RedactionTable,
        artifact_bytes: usize,
        boundary_revisions: super::coverage_bindings::OwnedSourceRevisions,
    ) -> Self {
        Self {
            table: Arc::new(table),
            artifact_bytes,
            boundary_revisions,
            publish_fence: None,
        }
    }

    pub(crate) fn with_publish_fence(mut self, fence: CoveragePublishFence) -> Self {
        self.publish_fence = Some(fence);
        self
    }

    /// Production-private complete capture funnel. Callers supply immutable
    /// daemon snapshots; discovery and matcher compilation execute only inside
    /// the authority worker closure.
    pub(crate) fn capture(
        config: &crate::config::extended::RedactConfig,
        root: &Path,
        environment: &HashMap<String, String>,
        store: &crate::credentials::CredentialStore,
        sealed: &RedactionTable,
        boundary_inputs: &super::coverage_bindings::SessionCoverageInputs<'_>,
    ) -> Result<Self> {
        let base =
            RedactionTable::build_with_env_and_credential_store(config, root, environment, store)?;
        let table = base.union(sealed)?;
        let boundary_revisions = boundary_inputs.boundary_revisions(&table);
        Ok(Self::from_complete_table(table, boundary_revisions))
    }

    /// Daemon-global capture. It takes no root: the build is scoped to
    /// daemon-global sources and never walks a directory.
    pub(crate) fn capture_without_sealed(
        config: &crate::config::extended::RedactConfig,
        environment: &HashMap<String, String>,
        store: &crate::credentials::CredentialStore,
        boundary_inputs: &super::coverage_bindings::DaemonGlobalCoverageInputs<'_>,
    ) -> Result<Self> {
        let table =
            RedactionTable::build_daemon_global_with_credential_store(config, environment, store)?;
        let boundary_revisions = boundary_inputs.boundary_revisions(&table);
        Ok(Self::from_complete_table(table, boundary_revisions))
    }

    pub(crate) fn capture_session_without_sealed(
        config: &crate::config::extended::RedactConfig,
        root: &Path,
        environment: &HashMap<String, String>,
        store: &crate::credentials::CredentialStore,
        boundary_inputs: &super::coverage_bindings::SessionCoverageInputs<'_>,
    ) -> Result<Self> {
        let table =
            RedactionTable::build_with_env_and_credential_store(config, root, environment, store)?;
        let boundary_revisions = boundary_inputs.boundary_revisions(&table);
        Ok(Self::from_complete_table(table, boundary_revisions))
    }
}

/// Immutable authority generation. Its opaque id is random and cannot act as
/// a candidate/source fingerprint.
pub(crate) struct RedactionCoverageGeneration {
    id: Uuid,
    key: RedactionCoverageKey,
    epoch: u64,
    generation_order: u64,
    key_revision: u64,
    table: Arc<RedactionTable>,
    artifact_bytes: usize,
    active_admissions: std::sync::atomic::AtomicUsize,
    live_current_bindings: std::sync::atomic::AtomicUsize,
}

impl fmt::Debug for RedactionCoverageGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactionCoverageGeneration")
            .field("id", &"opaque")
            .field("artifact_bytes", &self.artifact_bytes)
            .finish()
    }
}

impl RedactionCoverageGeneration {
    fn new(
        key: RedactionCoverageKey,
        epoch: u64,
        generation_order: u64,
        key_revision: u64,
        build: CoverageBuild,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            key,
            epoch,
            generation_order,
            key_revision,
            table: build.table,
            artifact_bytes: build.artifact_bytes,
            active_admissions: std::sync::atomic::AtomicUsize::new(0),
            live_current_bindings: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

/// The sole explicit raw-export disposition. It is intentionally unrelated to
/// a coverage generation and cannot be supplied to generic egress.
#[derive(Debug)]
pub(crate) struct RawExportDisposition(());

impl RawExportDisposition {
    pub(crate) fn after_owner_local_check(owner_local: bool) -> Option<Self> {
        owner_local.then_some(Self(()))
    }
}

struct Flight {
    correlation: Uuid,
    epoch: u64,
    key_revision: u64,
    waiters: std::sync::atomic::AtomicUsize,
    result: Mutex<Option<std::result::Result<Arc<RedactionCoverageGeneration>, CoverageError>>>,
    ready: Notify,
    interest_changed: Notify,
}

struct Resident {
    generation: Arc<RedactionCoverageGeneration>,
}

struct State {
    epoch: u64,
    next_generation_order: u64,
    closed: bool,
    queued: usize,
    allocated_flights: usize,
    waiters: usize,
    admissions: usize,
    artifact_bytes: usize,
    residents: HashMap<RedactionCoverageKey, Resident>,
    lru: VecDeque<RedactionCoverageKey>,
    flights: HashMap<RedactionCoverageKey, Arc<Flight>>,
    diagnostic_notices: HashSet<Uuid>,
    key_revisions: HashMap<RedactionCoverageKey, u64>,
}

struct Inner {
    state: Mutex<State>,
    workers: Arc<Semaphore>,
    flight_completed: Notify,
    owner_mode: CoverageOwnerMode,
}

/// Independent bounded worker facility shared by persistent, ephemeral and
/// in-process daemon composition. It deliberately does not use the optional
/// resource scheduler.
#[derive(Clone)]
pub(crate) struct RedactionCoverageAuthority {
    inner: Arc<Inner>,
}

impl Default for RedactionCoverageAuthority {
    fn default() -> Self {
        Self::new(CoverageOwnerMode::InProcess)
    }
}

impl RedactionCoverageAuthority {
    pub(crate) fn new(owner_mode: CoverageOwnerMode) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    epoch: 1,
                    next_generation_order: 1,
                    closed: false,
                    queued: 0,
                    allocated_flights: 0,
                    waiters: 0,
                    admissions: 0,
                    artifact_bytes: 0,
                    residents: HashMap::new(),
                    lru: VecDeque::new(),
                    flights: HashMap::new(),
                    diagnostic_notices: HashSet::new(),
                    key_revisions: HashMap::new(),
                }),
                workers: Arc::new(Semaphore::new(COVERAGE_WORKERS)),
                flight_completed: Notify::new(),
                owner_mode,
            }),
        }
    }

    pub(crate) fn owner_mode(&self) -> CoverageOwnerMode {
        self.inner.owner_mode
    }

    pub(crate) const fn limits(&self) -> CoverageLimits {
        COVERAGE_LIMITS
    }

    /// Start (or join) one complete capture. Work executes on the authority's
    /// bounded blocking pool; a caller never runs discovery on its event loop.
    pub(crate) async fn acquire<F>(
        &self,
        key: RedactionCoverageKey,
        purpose: CoverageScope,
        capture: F,
    ) -> std::result::Result<CoverageAdmission, CoverageError>
    where
        F: FnOnce() -> Result<CoverageBuild> + Send + 'static,
    {
        let (flight, leader) = {
            let mut state = lock(&self.inner.state);
            if state.closed {
                return Err(CoverageError::Unavailable);
            }
            if let Some(resident) = state.residents.get(&key) {
                let generation = resident.generation.clone();
                if let Some(position) = state.lru.iter().position(|candidate| candidate == &key) {
                    state.lru.remove(position);
                }
                state.lru.push_back(key.clone());
                return self.admit_locked(&mut state, generation, purpose);
            }
            if let Some(flight) = state.flights.get(&key).cloned() {
                if flight.waiters.load(std::sync::atomic::Ordering::Acquire)
                    >= COVERAGE_WAITERS_PER_KEY
                    || state.waiters >= COVERAGE_WAITERS
                {
                    return Err(CoverageError::Saturated);
                }
                flight
                    .waiters
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                state.waiters += 1;
                (flight, None)
            } else {
                if state.allocated_flights >= COVERAGE_FLIGHTS {
                    return Err(CoverageError::Saturated);
                }
                let permit = self.inner.workers.clone().try_acquire_owned().ok();
                if permit.is_none() && state.queued >= COVERAGE_QUEUE {
                    return Err(CoverageError::Saturated);
                }
                let flight = Arc::new(Flight {
                    correlation: Uuid::new_v4(),
                    epoch: state.epoch,
                    key_revision: state.key_revisions.get(&key).copied().unwrap_or(0),
                    waiters: std::sync::atomic::AtomicUsize::new(1),
                    result: Mutex::new(None),
                    ready: Notify::new(),
                    interest_changed: Notify::new(),
                });
                if permit.is_none() {
                    state.queued += 1;
                }
                state.waiters += 1;
                state.allocated_flights += 1;
                state.flights.insert(key.clone(), flight.clone());
                (flight, Some(permit))
            }
        };

        if let Some(permit) = leader {
            let authority = self.clone();
            let flight_key = key.clone();
            let worker_flight = flight.clone();
            tokio::spawn(async move {
                authority
                    .run_flight(flight_key, worker_flight, permit, capture)
                    .await;
            });
        }

        // Keeping this guard across the await is important: cancelling an
        // acquisition is real loss of interest, not a leaked queue slot.
        let waiter = WaiterLease {
            inner: Arc::downgrade(&self.inner),
            flight: Arc::downgrade(&flight),
            released: false,
        };

        let generation = loop {
            // Register the notification future before observing the result so
            // `notify_waiters` cannot land in the check/await gap.
            let notified = flight.ready.notified();
            if let Some(result) = lock(&flight.result).clone() {
                break result?;
            }
            notified.await;
        };
        waiter.release();
        let mut state = lock(&self.inner.state);
        self.admit_locked(&mut state, generation, purpose)
    }

    async fn run_flight<F>(
        &self,
        key: RedactionCoverageKey,
        flight: Arc<Flight>,
        permit: Option<OwnedSemaphorePermit>,
        capture: F,
    ) where
        F: FnOnce() -> Result<CoverageBuild> + Send + 'static,
    {
        let was_queued = permit.is_none();
        let scope_class = if key.session.is_some() {
            "session"
        } else {
            "daemon_global"
        };
        tracing::info!(
            target: crate::startup::TARGET,
            event = "coverage-phase-start",
            scope_class,
            correlation = %flight.correlation,
            "startup"
        );
        let permit = match permit {
            Some(permit) => Some(permit),
            None => loop {
                let interest_changed = flight.interest_changed.notified();
                if flight.waiters.load(std::sync::atomic::Ordering::Acquire) == 0 {
                    break None;
                }
                tokio::select! {
                    biased;
                    _ = interest_changed => continue,
                    permit = self.inner.workers.clone().acquire_owned() => break permit.ok(),
                }
            },
        };
        if was_queued {
            let mut state = lock(&self.inner.state);
            state.queued = state.queued.saturating_sub(1);
        }
        let cancelled = flight.waiters.load(std::sync::atomic::Ordering::Acquire) == 0;
        let result = match permit {
            Some(_permit) if !cancelled => match tokio::task::spawn_blocking(capture).await {
                Ok(Ok(mut build))
                    if flight.waiters.load(std::sync::atomic::Ordering::Acquire) > 0 =>
                {
                    // A blocking capture cannot be force-aborted safely, but
                    // losing its final waiter makes the result inert. Fence
                    // publication again after the completed-capture boundary
                    // so zero-interest running work never enters the cache.
                    let publish_fence = build.publish_fence.take();
                    let publish_revisions = match publish_fence {
                        Some(fence) => {
                            let table = build.table.clone();
                            match tokio::task::spawn_blocking(move || fence(&table)).await {
                                Ok(Ok(revisions)) => Some(revisions),
                                Ok(Err(_)) | Err(_) => None,
                            }
                        }
                        None => Some(build.boundary_revisions.clone()),
                    };
                    match publish_revisions {
                        Some(publish_revisions) => self.publish(
                            key.clone(),
                            flight.epoch,
                            flight.key_revision,
                            build,
                            publish_revisions,
                        ),
                        None => Err(CoverageError::Invalidated),
                    }
                }
                Ok(Ok(_)) => Err(CoverageError::Unavailable),
                Ok(Err(error)) => Err(
                    if error
                        .chain()
                        .any(|cause| cause.is::<super::EnvFileOverLimitError>())
                    {
                        CoverageError::SourceFileOverLimit
                    } else {
                        CoverageError::Unavailable
                    },
                ),
                Err(_) => Err(CoverageError::Unavailable),
            },
            Some(_) | None => Err(CoverageError::Unavailable),
        };
        tracing::info!(
            target: crate::startup::TARGET,
            event = "coverage-phase-complete",
            scope_class,
            correlation = %flight.correlation,
            "startup"
        );
        let mut stored = lock(&flight.result);
        if stored.is_none() {
            *stored = Some(result);
        }
        drop(stored);
        flight.ready.notify_waiters();
        let mut state = lock(&self.inner.state);
        state.allocated_flights = state.allocated_flights.saturating_sub(1);
        if state
            .flights
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, &flight))
        {
            state.flights.remove(&key);
        }
        drop(state);
        self.inner.flight_completed.notify_waiters();
    }

    fn publish(
        &self,
        key: RedactionCoverageKey,
        flight_epoch: u64,
        flight_key_revision: u64,
        build: CoverageBuild,
        publish_revisions: super::coverage_bindings::OwnedSourceRevisions,
    ) -> std::result::Result<Arc<RedactionCoverageGeneration>, CoverageError> {
        if build.artifact_bytes > COVERAGE_ARTIFACT_BYTES_PER_GENERATION {
            return Err(CoverageError::Unavailable);
        }
        let mut state = lock(&self.inner.state);
        if state.closed
            || state.epoch != flight_epoch
            || state.key_revisions.get(&key).copied().unwrap_or(0) != flight_key_revision
            || !key.matches_owned_revisions(&build.boundary_revisions)
            || !key.matches_owned_revisions(&publish_revisions)
        {
            return Err(CoverageError::Invalidated);
        }
        while (state.residents.len() >= COVERAGE_RESIDENT_GENERATIONS
            || state.artifact_bytes.saturating_add(build.artifact_bytes)
                > COVERAGE_ARTIFACT_BYTES_TOTAL)
            && self.evict_one_locked(&mut state)
        {}
        if state.residents.len() >= COVERAGE_RESIDENT_GENERATIONS
            || state.artifact_bytes.saturating_add(build.artifact_bytes)
                > COVERAGE_ARTIFACT_BYTES_TOTAL
        {
            return Err(CoverageError::Saturated);
        }
        let generation_order = state.next_generation_order;
        state.next_generation_order = state
            .next_generation_order
            .checked_add(1)
            .ok_or(CoverageError::Unavailable)?;
        let generation = Arc::new(RedactionCoverageGeneration::new(
            key.clone(),
            state.epoch,
            generation_order,
            flight_key_revision,
            build,
        ));
        state.artifact_bytes += generation.artifact_bytes;
        state.lru.push_back(key.clone());
        state.residents.insert(
            key,
            Resident {
                generation: generation.clone(),
            },
        );
        Ok(generation)
    }

    fn evict_one_locked(&self, state: &mut State) -> bool {
        let attempts = state.lru.len();
        for _ in 0..attempts {
            let Some(key) = state.lru.pop_front() else {
                return false;
            };
            let evictable = state.residents.get(&key).is_some_and(|resident| {
                resident
                    .generation
                    .active_admissions
                    .load(std::sync::atomic::Ordering::Acquire)
                    == 0
                    && resident
                        .generation
                        .live_current_bindings
                        .load(std::sync::atomic::Ordering::Acquire)
                        == 0
            });
            if evictable {
                if let Some(resident) = state.residents.remove(&key) {
                    state.artifact_bytes = state
                        .artifact_bytes
                        .saturating_sub(resident.generation.artifact_bytes);
                    return true;
                }
            } else {
                state.lru.push_back(key);
            }
        }
        false
    }

    fn admit_locked(
        &self,
        state: &mut State,
        generation: Arc<RedactionCoverageGeneration>,
        purpose: CoverageScope,
    ) -> std::result::Result<CoverageAdmission, CoverageError> {
        let resident_matches = state
            .residents
            .get(&generation.key)
            .is_some_and(|resident| resident.generation.id == generation.id);
        if state.closed
            || state.epoch != generation.epoch
            || state
                .key_revisions
                .get(&generation.key)
                .copied()
                .unwrap_or(0)
                != generation.key_revision
            || !resident_matches
            || state.admissions >= COVERAGE_ADMISSIONS
        {
            return Err(if state.admissions >= COVERAGE_ADMISSIONS {
                CoverageError::Saturated
            } else {
                CoverageError::Invalidated
            });
        }
        state.admissions += 1;
        generation
            .active_admissions
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Ok(CoverageAdmission {
            inner: Arc::downgrade(&self.inner),
            generation,
            purpose,
            released: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Revoke current coverage after any known owned mutation. Existing and
    /// late work becomes inert; the next acquisition performs a complete scan.
    pub(crate) fn invalidate(&self) {
        let mut state = lock(&self.inner.state);
        state.epoch = state.epoch.wrapping_add(1).max(1);
        state.residents.clear();
        state.lru.clear();
        state.artifact_bytes = 0;
        // Every outstanding admission is revoked by the epoch bump. Drops
        // from those stale lease objects use saturating subtraction, so the
        // new epoch begins with its full independent admission budget.
        state.admissions = 0;
        state.diagnostic_notices.clear();
        state.key_revisions.clear();
        let flights = state
            .flights
            .drain()
            .map(|(_, flight)| flight)
            .collect::<Vec<_>>();
        for flight in flights {
            *lock(&flight.result) = Some(Err(CoverageError::Invalidated));
            flight.ready.notify_waiters();
        }
    }

    /// Revoke exactly one bound source view without discarding unrelated
    /// session generations. A detached late completion carries the prior
    /// key revision and therefore cannot publish.
    pub(crate) fn invalidate_key(&self, key: &RedactionCoverageKey) {
        let mut state = lock(&self.inner.state);
        let revision = state.key_revisions.entry(key.clone()).or_insert(0);
        *revision = revision.wrapping_add(1).max(1);
        if let Some(resident) = state.residents.remove(key) {
            let revoked_admissions = resident
                .generation
                .active_admissions
                .load(std::sync::atomic::Ordering::Acquire);
            state.admissions = state.admissions.saturating_sub(revoked_admissions);
            state.artifact_bytes = state
                .artifact_bytes
                .saturating_sub(resident.generation.artifact_bytes);
            state.diagnostic_notices.remove(&resident.generation.id);
        }
        state.lru.retain(|candidate| candidate != key);
        if let Some(flight) = state.flights.remove(key) {
            *lock(&flight.result) = Some(Err(CoverageError::Invalidated));
            flight.ready.notify_waiters();
        }
    }

    pub(crate) fn invalidate_workspace(&self, workspace: CoverageBinding) {
        let keys = {
            let state = lock(&self.inner.state);
            state
                .residents
                .keys()
                .chain(state.flights.keys())
                .chain(state.key_revisions.keys())
                .filter(|key| key.workspace == Some(workspace))
                .cloned()
                .collect::<HashSet<_>>()
        };
        for key in keys {
            self.invalidate_key(&key);
        }
    }

    /// Rebind is intentionally stronger than invalidation: old waiters wake
    /// with a sanitized refusal and no old result can publish.
    pub(crate) fn rebind(&self) {
        self.invalidate();
    }

    /// Close acquisition, revoke every future sink check and wake waiters.
    pub(crate) fn shutdown(&self) {
        self.inner.workers.close();
        let mut state = lock(&self.inner.state);
        state.closed = true;
        state.epoch = state.epoch.wrapping_add(1).max(1);
        state.residents.clear();
        state.lru.clear();
        state.artifact_bytes = 0;
        state.admissions = 0;
        state.diagnostic_notices.clear();
        state.key_revisions.clear();
        let flights = state
            .flights
            .drain()
            .map(|(_, flight)| flight)
            .collect::<Vec<_>>();
        for flight in flights {
            *lock(&flight.result) = Some(Err(CoverageError::Unavailable));
            flight.ready.notify_waiters();
        }
    }

    /// Shutdown coordination fence. Acquisition closes immediately; only the
    /// daemon teardown coordinator awaits blocking captures that were already
    /// running. Registering the notification before observing occupancy avoids
    /// a completion/check race without polling or a fixed wait budget.
    pub(crate) async fn shutdown_and_wait(&self) {
        self.shutdown();
        loop {
            let completed = self.inner.flight_completed.notified();
            if lock(&self.inner.state).allocated_flights == 0 {
                return;
            }
            completed.await;
        }
    }
}

struct WaiterLease {
    inner: Weak<Inner>,
    flight: Weak<Flight>,
    released: bool,
}

impl WaiterLease {
    fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        if let Some(inner) = self.inner.upgrade() {
            let mut state = lock(&inner.state);
            state.waiters = state.waiters.saturating_sub(1);
            if let Some(flight) = self.flight.upgrade() {
                let prior = flight
                    .waiters
                    .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                if prior == 1 {
                    flight.interest_changed.notify_waiters();
                }
            }
        }
    }
}

impl Drop for WaiterLease {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// A one-operation lease. It cannot be cloned. [`Self::use_at_sink`],
/// [`Self::consume_at_sink`], and [`Self::consume_at_async_sink`] each validate
/// immediately and consume the lease at one owned sink.
pub(crate) struct CoverageAdmission {
    inner: Weak<Inner>,
    generation: Arc<RedactionCoverageGeneration>,
    purpose: CoverageScope,
    released: std::sync::atomic::AtomicBool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UnsupportedSourceDetailClass {
    UnsupportedFormat,
    Unreadable,
    ChangedDuringCapture,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct OwnerUnsupportedSourceDiagnostic {
    pub display_path: String,
    pub detail: UnsupportedSourceDetailClass,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RedactionCoverageStatusProjection {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_diagnostic: Option<OwnerUnsupportedSourceDiagnostic>,
}

/// Proof that daemon dispatch completed the owner authorization check. The
/// field is private so a generic egress caller cannot forge the disposition.
pub(crate) struct OwnerAuthorization(());

impl OwnerAuthorization {
    pub(crate) fn after_principal_check(is_owner: bool) -> Option<Self> {
        is_owner.then_some(Self(()))
    }
}

impl CoverageAdmission {
    fn validate_current(&self) -> std::result::Result<(), CoverageError> {
        let Some(inner) = self.inner.upgrade() else {
            return Err(CoverageError::Unavailable);
        };
        let state = lock(&inner.state);
        let current = !state.closed
            && state.epoch == self.generation.epoch
            && state
                .key_revisions
                .get(&self.generation.key)
                .copied()
                .unwrap_or(0)
                == self.generation.key_revision
            && state
                .residents
                .get(&self.generation.key)
                .is_some_and(|resident| resident.generation.id == self.generation.id);
        if current {
            Ok(())
        } else {
            Err(CoverageError::Invalidated)
        }
    }

    fn coverage_binding_for_sink(&self) -> CoverageTableBinding {
        CoverageTableBinding {
            authority: self.inner.clone(),
            generation_id: self.generation.id,
            epoch: self.generation.epoch,
            generation_order: self.generation.generation_order,
            key_revision: self.generation.key_revision,
            key: self.generation.key.clone(),
            live_binding: None,
        }
    }

    fn bound_table_for_sink(&self) -> std::result::Result<RedactionTable, CoverageError> {
        self.validate_current()?;
        Ok(self
            .generation
            .table
            .enforced()
            .clone()
            .with_coverage_binding(self.coverage_binding_for_sink()))
    }

    /// Install the admitted generation table with durable provenance binding.
    /// The raw generation [`Arc`] cannot escape; only this bound table may be
    /// persisted or installed for later historical folds.
    pub(crate) fn install_table(self) -> std::result::Result<RedactionTable, CoverageError> {
        self.bound_table_for_sink()
    }

    /// Run one immediate sink against the admitted generation table. The lease
    /// is consumed before the sink returns; the sink receives one owned bound
    /// table and must not perform irreversible side effects before returning.
    pub(crate) fn consume_at_sink<T>(
        self,
        sink: impl FnOnce(RedactionTable) -> Result<T>,
    ) -> std::result::Result<T, CoverageError> {
        let table = self.bound_table_for_sink()?;
        let result = sink(table).map_err(|_| CoverageError::Unavailable)?;
        self.validate_current()?;
        Ok(result)
    }

    /// Async variant of [`Self::consume_at_sink`]. The lease stays active until
    /// the future completes. Callers must defer persistence, swap, and other
    /// irreversible side effects until after this method returns `Ok`.
    pub(crate) async fn consume_at_async_sink<T, F, Fut>(
        self,
        sink: F,
    ) -> std::result::Result<T, CoverageError>
    where
        F: FnOnce(RedactionTable) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let table = self.bound_table_for_sink()?;
        let result = sink(table).await.map_err(|_| CoverageError::Unavailable)?;
        self.validate_current()?;
        Ok(result)
    }

    /// Async sink variant that keeps the sink's domain error distinct from a
    /// coverage invalidation. The lease still spans the entire future and is
    /// revalidated before the caller may act on either domain result.
    pub(crate) async fn consume_at_async_sink_preserving_error<T, E, F, Fut>(
        self,
        sink: F,
    ) -> std::result::Result<std::result::Result<T, E>, CoverageError>
    where
        F: FnOnce(RedactionTable) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, E>>,
    {
        let table = self.bound_table_for_sink()?;
        let result = sink(table).await;
        self.validate_current()?;
        Ok(result)
    }

    pub(crate) fn use_at_sink<T>(
        self,
        sink: impl FnOnce(RedactionTable) -> Result<T>,
    ) -> std::result::Result<T, CoverageError> {
        let table = self.bound_table_for_sink()?;
        let result = sink(table).map_err(|_| CoverageError::Unavailable)?;
        self.validate_current()?;
        Ok(result)
    }

    pub(crate) fn purpose(&self) -> CoverageScope {
        self.purpose
    }

    pub(crate) fn unsupported_source_projection(
        self,
        authorization: Option<OwnerAuthorization>,
        source_path: &Path,
        detail: UnsupportedSourceDetailClass,
    ) -> std::result::Result<RedactionCoverageStatusProjection, CoverageError> {
        let Some(_authorization) = authorization else {
            self.release();
            return Ok(RedactionCoverageStatusProjection {
                state: "unsupported_coverage",
                owner_diagnostic: None,
            });
        };
        let generation_id = self.generation.id;
        let Some(inner) = self.inner.upgrade() else {
            return Err(CoverageError::Unavailable);
        };
        let mut state = lock(&inner.state);
        let current = !state.closed
            && state.epoch == self.generation.epoch
            && state
                .key_revisions
                .get(&self.generation.key)
                .copied()
                .unwrap_or(0)
                == self.generation.key_revision
            && state
                .residents
                .get(&self.generation.key)
                .is_some_and(|resident| resident.generation.id == generation_id);
        if !current {
            return Err(CoverageError::Invalidated);
        }
        let first_notice = state.diagnostic_notices.insert(generation_id);
        let owner_diagnostic = first_notice.then(|| {
            let file_name = source_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unsupported-source");
            OwnerUnsupportedSourceDiagnostic {
                display_path: self.generation.table.enforced().scrub(file_name),
                detail,
            }
        });
        drop(state);
        self.release();
        Ok(RedactionCoverageStatusProjection {
            state: "unsupported_coverage",
            owner_diagnostic,
        })
    }

    fn release(&self) {
        if self
            .released
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
        self.generation
            .active_admissions
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        if let Some(inner) = self.inner.upgrade() {
            let mut state = lock(&inner.state);
            if state.epoch == self.generation.epoch
                && state
                    .key_revisions
                    .get(&self.generation.key)
                    .copied()
                    .unwrap_or(0)
                    == self.generation.key_revision
            {
                state.admissions = state.admissions.saturating_sub(1);
            }
        }
    }
}

impl Drop for CoverageAdmission {
    fn drop(&mut self) {
        self.release();
    }
}
