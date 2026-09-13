//! Daemon-owned admission for secret-bearing redaction work.
//!
//! This module deliberately keeps source identity, candidate fingerprints and
//! matcher artifacts private.  A caller gets a short-lived, non-cloneable
//! admission and can use it exactly once at its owned sink.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::{Arc, Mutex, Weak},
};

use anyhow::Result;
use tokio::sync::{Notify, Semaphore};
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
}

impl fmt::Debug for CoverageBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CoverageBinding(..)")
    }
}

/// The purpose is a binding, rather than an instruction to scan separately.
/// Equal source bindings may therefore share one accepted capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CoverageScope {
    DaemonGlobal,
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
    scope: CoverageScope,
}

impl fmt::Debug for RedactionCoverageKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactionCoverageKey")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl RedactionCoverageKey {
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
        scope: CoverageScope,
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
            scope,
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
        scope: CoverageScope,
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
            scope,
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
}

impl fmt::Display for CoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "coverage_unavailable",
            Self::Saturated => "coverage_saturated",
            Self::Invalidated => "coverage_unavailable",
        })
    }
}

impl std::error::Error for CoverageError {}

/// Complete, in-memory-only result of a source capture. `artifact_bytes` is
/// supplied by the capture owner after measuring private parsed artifacts.
pub(crate) struct CoverageBuild {
    table: Arc<RedactionTable>,
    artifact_bytes: usize,
}

impl CoverageBuild {
    pub(crate) fn from_complete_table(table: RedactionTable, artifact_bytes: usize) -> Self {
        Self {
            table: Arc::new(table),
            artifact_bytes,
        }
    }
}

/// Immutable authority generation. Its opaque id is random and cannot act as
/// a candidate/source fingerprint.
pub(crate) struct RedactionCoverageGeneration {
    id: Uuid,
    key: RedactionCoverageKey,
    epoch: u64,
    table: Arc<RedactionTable>,
    artifact_bytes: usize,
    active_admissions: std::sync::atomic::AtomicUsize,
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
    fn new(key: RedactionCoverageKey, epoch: u64, build: CoverageBuild) -> Self {
        Self {
            id: Uuid::now_v7(),
            key,
            epoch,
            table: build.table,
            artifact_bytes: build.artifact_bytes,
            active_admissions: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

/// The sole explicit raw-export disposition. It is intentionally unrelated to
/// a coverage generation and cannot be supplied to generic egress.
#[derive(Debug)]
pub(crate) enum RawExportDisposition {
    OwnerAuthorized,
}

struct Flight {
    epoch: u64,
    waiters: usize,
    result: Mutex<Option<std::result::Result<Arc<RedactionCoverageGeneration>, CoverageError>>>,
    ready: Notify,
}

struct Resident {
    generation: Arc<RedactionCoverageGeneration>,
}

struct State {
    epoch: u64,
    closed: bool,
    queued: usize,
    waiters: usize,
    admissions: usize,
    artifact_bytes: usize,
    residents: HashMap<RedactionCoverageKey, Resident>,
    lru: VecDeque<RedactionCoverageKey>,
    flights: HashMap<RedactionCoverageKey, Arc<Flight>>,
}

struct Inner {
    state: Mutex<State>,
    workers: Semaphore,
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
        Self::new()
    }
}

impl RedactionCoverageAuthority {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    epoch: 1,
                    closed: false,
                    queued: 0,
                    waiters: 0,
                    admissions: 0,
                    artifact_bytes: 0,
                    residents: HashMap::new(),
                    lru: VecDeque::new(),
                    flights: HashMap::new(),
                }),
                workers: Semaphore::new(COVERAGE_WORKERS),
            }),
        }
    }

    /// Start (or join) one complete capture. Work executes on the authority's
    /// bounded blocking pool; a caller never runs discovery on its event loop.
    pub(crate) async fn acquire<F>(
        &self,
        key: RedactionCoverageKey,
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
                return self.admit_locked(&mut state, generation);
            }
            if let Some(flight) = state.flights.get(&key).cloned() {
                if flight.waiters >= COVERAGE_WAITERS_PER_KEY || state.waiters >= COVERAGE_WAITERS {
                    return Err(CoverageError::Saturated);
                }
                flight.waiters += 1;
                state.waiters += 1;
                (flight, false)
            } else {
                if state.flights.len() >= COVERAGE_FLIGHTS || state.queued >= COVERAGE_QUEUE {
                    return Err(CoverageError::Saturated);
                }
                let flight = Arc::new(Flight {
                    epoch: state.epoch,
                    waiters: 1,
                    result: Mutex::new(None),
                    ready: Notify::new(),
                });
                state.queued += 1;
                state.waiters += 1;
                state.flights.insert(key.clone(), flight.clone());
                (flight, true)
            }
        };

        if leader {
            let authority = self.clone();
            let flight_key = key.clone();
            tokio::spawn(async move {
                authority.run_flight(flight_key, flight, capture).await;
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
            if let Some(result) = lock(&flight.result).clone() {
                break result?;
            }
            flight.ready.notified().await;
        };
        waiter.release();
        let mut state = lock(&self.inner.state);
        self.admit_locked(&mut state, generation)
    }

    async fn run_flight<F>(&self, key: RedactionCoverageKey, flight: Arc<Flight>, capture: F)
    where
        F: FnOnce() -> Result<CoverageBuild> + Send + 'static,
    {
        let permit = self.workers.acquire().await;
        {
            let mut state = lock(&self.inner.state);
            state.queued = state.queued.saturating_sub(1);
        }
        let result = match permit {
            Ok(_permit) => match tokio::task::spawn_blocking(capture).await {
                Ok(Ok(build)) => self.publish(key.clone(), flight.epoch, build),
                Ok(Err(_)) | Err(_) => Err(CoverageError::Unavailable),
            },
            Err(_) => Err(CoverageError::Unavailable),
        };
        *lock(&flight.result) = Some(result);
        flight.ready.notify_waiters();
        let mut state = lock(&self.inner.state);
        state.flights.remove(&key);
    }

    fn publish(
        &self,
        key: RedactionCoverageKey,
        flight_epoch: u64,
        build: CoverageBuild,
    ) -> std::result::Result<Arc<RedactionCoverageGeneration>, CoverageError> {
        if build.artifact_bytes > COVERAGE_ARTIFACT_BYTES_PER_GENERATION {
            return Err(CoverageError::Unavailable);
        }
        let mut state = lock(&self.inner.state);
        if state.closed || state.epoch != flight_epoch {
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
        let generation = Arc::new(RedactionCoverageGeneration::new(
            key.clone(),
            state.epoch,
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
    ) -> std::result::Result<CoverageAdmission, CoverageError> {
        if state.closed
            || state.epoch != generation.epoch
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
    }

    /// Rebind is intentionally stronger than invalidation: old waiters wake
    /// with a sanitized refusal and no old result can publish.
    pub(crate) fn rebind(&self) {
        self.invalidate();
        let state = lock(&self.inner.state);
        for flight in state.flights.values() {
            *lock(&flight.result) = Some(Err(CoverageError::Invalidated));
            flight.ready.notify_waiters();
        }
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
        for flight in state.flights.values() {
            *lock(&flight.result) = Some(Err(CoverageError::Unavailable));
            flight.ready.notify_waiters();
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
                flight.waiters = flight.waiters.saturating_sub(1);
            }
        }
    }
}

impl Drop for WaiterLease {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// A one-operation lease. It cannot be cloned or converted into a table; the
/// sink closure is the single funnel that observes the enforced table.
pub(crate) struct CoverageAdmission {
    inner: Weak<Inner>,
    generation: Arc<RedactionCoverageGeneration>,
    released: std::sync::atomic::AtomicBool,
}

impl CoverageAdmission {
    pub(crate) fn use_at_sink<T>(
        self,
        sink: impl FnOnce(&RedactionTable) -> Result<T>,
    ) -> std::result::Result<T, CoverageError> {
        let Some(inner) = self.inner.upgrade() else {
            return Err(CoverageError::Unavailable);
        };
        let state = lock(&inner.state);
        let current = !state.closed
            && state.epoch == self.generation.epoch
            && state
                .residents
                .get(&self.generation.key)
                .is_some_and(|resident| resident.generation.id == self.generation.id);
        drop(state);
        if !current {
            return Err(CoverageError::Invalidated);
        }
        sink(&self.generation.table.enforced()).map_err(|_| CoverageError::Unavailable)
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
            state.admissions = state.admissions.saturating_sub(1);
        }
    }
}

impl Drop for CoverageAdmission {
    fn drop(&mut self) {
        self.release();
    }
}
