//! Daemon-owned resource permit scheduler.
//!
//! This is a runtime concurrency gate, not an OS resource limiter. Callers
//! declare named permit counts, acquire them atomically, and hold the returned
//! RAII lease for the duration of the work.
#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::extended::ResourceSchedulerConfig;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub pools: BTreeMap<String, u32>,
}

impl ResourceRequirements {
    pub fn new(pools: impl IntoIterator<Item = (impl Into<String>, u32)>) -> Self {
        Self {
            pools: pools
                .into_iter()
                .filter_map(|(name, count)| (count > 0).then(|| (name.into(), count)))
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRequestMetadata {
    pub session_id: Option<Uuid>,
    pub agent_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub command_label: Option<String>,
    pub declared_requirements: ResourceRequirements,
    pub policy_requirements: ResourceRequirements,
    pub reviewer_requirements: ResourceRequirements,
    pub effective_requirements: ResourceRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAcquireRequest {
    pub resources: ResourceRequirements,
    pub metadata: ResourceRequestMetadata,
}

impl ResourceAcquireRequest {
    pub fn new(resources: ResourceRequirements) -> Self {
        Self {
            resources: resources.clone(),
            metadata: ResourceRequestMetadata {
                effective_requirements: resources,
                ..ResourceRequestMetadata::default()
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceAcquireError {
    UnknownPool {
        pool: String,
    },
    OverCapacity {
        pool: String,
        requested: u32,
        capacity: u32,
    },
    QueueFull {
        max_queued: usize,
    },
    Cancelled,
}

impl std::fmt::Display for ResourceAcquireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPool { pool } => write!(f, "unknown resource pool `{pool}`"),
            Self::OverCapacity {
                pool,
                requested,
                capacity,
            } => write!(
                f,
                "resource request for `{pool}` needs {requested} permits but capacity is {capacity}"
            ),
            Self::QueueFull { max_queued } => {
                write!(f, "resource scheduler queue is full (max {max_queued})")
            }
            Self::Cancelled => write!(f, "resource request cancelled"),
        }
    }
}

impl std::error::Error for ResourceAcquireError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourcePromoteError {
    NotFound(Uuid),
    NotQueued(Uuid),
}

impl std::fmt::Display for ResourcePromoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "resource request `{id}` not found"),
            Self::NotQueued(id) => write!(f, "resource request `{id}` is not queued"),
        }
    }
}

impl std::error::Error for ResourcePromoteError {}

#[derive(Clone)]
pub struct ResourceScheduler {
    shared: Arc<Shared>,
}

struct Shared {
    state: Mutex<SchedulerState>,
    notify: Notify,
}

struct SchedulerState {
    enabled: bool,
    pools: BTreeMap<String, PoolState>,
    max_queued: usize,
    next_display_id: u64,
    queued: VecDeque<RequestEntry>,
    running: BTreeMap<Uuid, RunningEntry>,
}

#[derive(Debug, Clone)]
struct PoolState {
    capacity: u32,
    used: u32,
}

#[derive(Debug, Clone)]
struct RequestEntry {
    id: Uuid,
    display_id: String,
    resources: ResourceRequirements,
    metadata: ResourceRequestMetadata,
    queued_at_ms: i64,
    promoted_by: Option<String>,
    promoted_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
struct RunningEntry {
    id: Uuid,
    display_id: String,
    resources: ResourceRequirements,
    metadata: ResourceRequestMetadata,
    queued_at_ms: i64,
    started_at_ms: i64,
    promoted_by: Option<String>,
    promoted_at_ms: Option<i64>,
}

pub struct ResourceTicket {
    scheduler: Option<ResourceScheduler>,
    request_id: Uuid,
    display_id: String,
    consumed: bool,
}

impl std::fmt::Debug for ResourceTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceTicket")
            .field("request_id", &self.request_id)
            .field("display_id", &self.display_id)
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

impl ResourceTicket {
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub fn display_id(&self) -> &str {
        &self.display_id
    }

    pub async fn wait(
        mut self,
        cancel: &CancellationToken,
    ) -> Result<ResourceLease, ResourceAcquireError> {
        let Some(scheduler) = self.scheduler.clone() else {
            self.consumed = true;
            return Ok(ResourceLease::noop(
                self.request_id,
                self.display_id.clone(),
            ));
        };

        loop {
            let notified = scheduler.shared.notify.notified();
            {
                let state = lock_state(&scheduler.shared);
                if state.running.contains_key(&self.request_id) {
                    self.consumed = true;
                    return Ok(ResourceLease::tracked(
                        Arc::downgrade(&scheduler.shared),
                        self.request_id,
                        self.display_id.clone(),
                    ));
                }
                if !state.queued.iter().any(|entry| entry.id == self.request_id) {
                    return Err(ResourceAcquireError::Cancelled);
                }
            }

            tokio::select! {
                _ = notified => {}
                _ = cancel.cancelled() => {
                    scheduler.cancel_or_release(self.request_id);
                    self.consumed = true;
                    return Err(ResourceAcquireError::Cancelled);
                }
            }
        }
    }
}

impl Drop for ResourceTicket {
    fn drop(&mut self) {
        if !self.consumed
            && let Some(scheduler) = &self.scheduler
        {
            scheduler.cancel_or_release(self.request_id);
        }
    }
}

#[derive(Debug)]
pub struct ResourceLease {
    scheduler: Option<Weak<Shared>>,
    request_id: Uuid,
    display_id: String,
    released: bool,
}

impl ResourceLease {
    fn tracked(scheduler: Weak<Shared>, request_id: Uuid, display_id: String) -> Self {
        Self {
            scheduler: Some(scheduler),
            request_id,
            display_id,
            released: false,
        }
    }

    fn noop(request_id: Uuid, display_id: String) -> Self {
        Self {
            scheduler: None,
            request_id,
            display_id,
            released: false,
        }
    }

    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub fn display_id(&self) -> &str {
        &self.display_id
    }

    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let Some(shared) = self.scheduler.as_ref().and_then(Weak::upgrade) else {
            return;
        };
        release_running(&shared, self.request_id);
    }
}

impl Drop for ResourceLease {
    fn drop(&mut self) {
        self.release_inner();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSchedulerSnapshot {
    pub enabled: bool,
    pub pools: Vec<ResourcePoolSnapshot>,
    pub running: Vec<ResourceRunningSnapshot>,
    pub queued: Vec<ResourceQueuedSnapshot>,
    pub max_queued: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePoolSnapshot {
    pub name: String,
    pub capacity: u32,
    pub used: u32,
    pub available: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRunningSnapshot {
    pub id: Uuid,
    pub display_id: String,
    pub resources: ResourceRequirements,
    pub metadata: ResourceRequestMetadata,
    pub queued_at_ms: i64,
    pub started_at_ms: i64,
    pub wait_ms: u64,
    pub promoted_by: Option<String>,
    pub promoted_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceQueuedSnapshot {
    pub id: Uuid,
    pub display_id: String,
    pub resources: ResourceRequirements,
    pub metadata: ResourceRequestMetadata,
    pub queued_at_ms: i64,
    pub wait_ms: u64,
    pub state: ResourceQueuedState,
    pub promoted_by: Option<String>,
    pub promoted_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceQueuedState {
    Queued,
    Promoted,
}

impl ResourceScheduler {
    pub fn new(config: ResourceSchedulerConfig) -> Self {
        let pools = config
            .pools
            .as_map()
            .into_iter()
            .map(|(name, pool)| {
                (
                    name,
                    PoolState {
                        capacity: pool.capacity,
                        used: 0,
                    },
                )
            })
            .collect();
        Self {
            shared: Arc::new(Shared {
                state: Mutex::new(SchedulerState {
                    enabled: config.enabled,
                    pools,
                    max_queued: config.limits.max_queued,
                    next_display_id: 1,
                    queued: VecDeque::new(),
                    running: BTreeMap::new(),
                }),
                notify: Notify::new(),
            }),
        }
    }

    pub fn disabled() -> Self {
        Self::new(ResourceSchedulerConfig {
            enabled: false,
            ..ResourceSchedulerConfig::default()
        })
    }

    pub fn submit(
        &self,
        request: ResourceAcquireRequest,
    ) -> Result<ResourceTicket, ResourceAcquireError> {
        let mut state = lock_state(&self.shared);
        let id = Uuid::new_v4();
        let display_id = next_display_id(&mut state);
        if !state.enabled || request.resources.is_empty() {
            return Ok(ResourceTicket {
                scheduler: None,
                request_id: id,
                display_id,
                consumed: false,
            });
        }

        validate_request(&state, &request.resources)?;
        if state.queued.is_empty() && has_capacity(&state, &request.resources) {
            start_running(
                &mut state,
                RequestEntry {
                    id,
                    display_id: display_id.clone(),
                    resources: request.resources,
                    metadata: request.metadata,
                    queued_at_ms: now_ms(),
                    promoted_by: None,
                    promoted_at_ms: None,
                },
            );
            self.shared.notify.notify_waiters();
            return Ok(ResourceTicket {
                scheduler: Some(self.clone()),
                request_id: id,
                display_id,
                consumed: false,
            });
        }

        if state.queued.len() >= state.max_queued {
            return Err(ResourceAcquireError::QueueFull {
                max_queued: state.max_queued,
            });
        }

        state.queued.push_back(RequestEntry {
            id,
            display_id: display_id.clone(),
            resources: request.resources,
            metadata: request.metadata,
            queued_at_ms: now_ms(),
            promoted_by: None,
            promoted_at_ms: None,
        });
        try_start_queued(&mut state);
        self.shared.notify.notify_waiters();
        Ok(ResourceTicket {
            scheduler: Some(self.clone()),
            request_id: id,
            display_id,
            consumed: false,
        })
    }

    pub async fn acquire(
        &self,
        request: ResourceAcquireRequest,
        cancel: &CancellationToken,
    ) -> Result<ResourceLease, ResourceAcquireError> {
        self.submit(request)?.wait(cancel).await
    }

    pub fn promote(
        &self,
        request_id: Uuid,
        promoted_by: impl Into<String>,
    ) -> Result<(), ResourcePromoteError> {
        let mut state = lock_state(&self.shared);
        if state.running.contains_key(&request_id) {
            return Err(ResourcePromoteError::NotQueued(request_id));
        }
        let Some(pos) = state.queued.iter().position(|entry| entry.id == request_id) else {
            return Err(ResourcePromoteError::NotFound(request_id));
        };
        let Some(mut entry) = state.queued.remove(pos) else {
            return Err(ResourcePromoteError::NotFound(request_id));
        };
        entry.promoted_by = Some(promoted_by.into());
        entry.promoted_at_ms = Some(now_ms());
        state.queued.push_front(entry);
        try_start_queued(&mut state);
        self.shared.notify.notify_waiters();
        Ok(())
    }

    pub fn snapshot(&self) -> ResourceSchedulerSnapshot {
        let state = lock_state(&self.shared);
        let now = now_ms();
        ResourceSchedulerSnapshot {
            enabled: state.enabled,
            pools: state
                .pools
                .iter()
                .map(|(name, pool)| ResourcePoolSnapshot {
                    name: name.clone(),
                    capacity: pool.capacity,
                    used: pool.used,
                    available: pool.capacity.saturating_sub(pool.used),
                })
                .collect(),
            running: state
                .running
                .values()
                .map(|entry| ResourceRunningSnapshot {
                    id: entry.id,
                    display_id: entry.display_id.clone(),
                    resources: entry.resources.clone(),
                    metadata: entry.metadata.clone(),
                    queued_at_ms: entry.queued_at_ms,
                    started_at_ms: entry.started_at_ms,
                    wait_ms: elapsed_ms(entry.queued_at_ms, entry.started_at_ms),
                    promoted_by: entry.promoted_by.clone(),
                    promoted_at_ms: entry.promoted_at_ms,
                })
                .collect(),
            queued: state
                .queued
                .iter()
                .map(|entry| ResourceQueuedSnapshot {
                    id: entry.id,
                    display_id: entry.display_id.clone(),
                    resources: entry.resources.clone(),
                    metadata: entry.metadata.clone(),
                    queued_at_ms: entry.queued_at_ms,
                    wait_ms: elapsed_ms(entry.queued_at_ms, now),
                    state: if entry.promoted_by.is_some() {
                        ResourceQueuedState::Promoted
                    } else {
                        ResourceQueuedState::Queued
                    },
                    promoted_by: entry.promoted_by.clone(),
                    promoted_at_ms: entry.promoted_at_ms,
                })
                .collect(),
            max_queued: state.max_queued,
        }
    }

    fn cancel_or_release(&self, request_id: Uuid) {
        let mut state = lock_state(&self.shared);
        if let Some(pos) = state.queued.iter().position(|entry| entry.id == request_id) {
            state.queued.remove(pos);
            try_start_queued(&mut state);
            self.shared.notify.notify_waiters();
            return;
        }
        if release_running_locked(&mut state, request_id) {
            try_start_queued(&mut state);
            self.shared.notify.notify_waiters();
        }
    }
}

fn lock_state(shared: &Shared) -> std::sync::MutexGuard<'_, SchedulerState> {
    shared.state.lock().unwrap_or_else(|err| err.into_inner())
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn elapsed_ms(start: i64, end: i64) -> u64 {
    end.saturating_sub(start).try_into().unwrap_or(0)
}

fn next_display_id(state: &mut SchedulerState) -> String {
    let n = state.next_display_id;
    state.next_display_id = state.next_display_id.saturating_add(1);
    format!("rs-{n:04}")
}

fn validate_request(
    state: &SchedulerState,
    resources: &ResourceRequirements,
) -> Result<(), ResourceAcquireError> {
    for (name, requested) in &resources.pools {
        let Some(pool) = state.pools.get(name) else {
            return Err(ResourceAcquireError::UnknownPool { pool: name.clone() });
        };
        if *requested > pool.capacity {
            return Err(ResourceAcquireError::OverCapacity {
                pool: name.clone(),
                requested: *requested,
                capacity: pool.capacity,
            });
        }
    }
    Ok(())
}

fn has_capacity(state: &SchedulerState, resources: &ResourceRequirements) -> bool {
    resources.pools.iter().all(|(name, requested)| {
        state
            .pools
            .get(name)
            .map(|pool| pool.used.saturating_add(*requested) <= pool.capacity)
            .unwrap_or(false)
    })
}

fn start_running(state: &mut SchedulerState, entry: RequestEntry) {
    for (name, permits) in &entry.resources.pools {
        if let Some(pool) = state.pools.get_mut(name) {
            pool.used = pool.used.saturating_add(*permits);
        }
    }
    let started_at_ms = now_ms();
    state.running.insert(
        entry.id,
        RunningEntry {
            id: entry.id,
            display_id: entry.display_id,
            resources: entry.resources,
            metadata: entry.metadata,
            queued_at_ms: entry.queued_at_ms,
            started_at_ms,
            promoted_by: entry.promoted_by,
            promoted_at_ms: entry.promoted_at_ms,
        },
    );
}

fn try_start_queued(state: &mut SchedulerState) {
    loop {
        let Some(front) = state.queued.front() else {
            return;
        };
        if !has_capacity(state, &front.resources) {
            return;
        }
        let Some(entry) = state.queued.pop_front() else {
            return;
        };
        start_running(state, entry);
    }
}

fn release_running(shared: &Shared, request_id: Uuid) {
    let mut state = lock_state(shared);
    if release_running_locked(&mut state, request_id) {
        try_start_queued(&mut state);
        shared.notify.notify_waiters();
    }
}

fn release_running_locked(state: &mut SchedulerState, request_id: Uuid) -> bool {
    let Some(entry) = state.running.remove(&request_id) else {
        return false;
    };
    for (name, permits) in &entry.resources.pools {
        if let Some(pool) = state.pools.get_mut(name) {
            pool.used = pool.used.saturating_sub(*permits);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scheduler(cpu: u32, memory: u32, max_queued: usize) -> ResourceScheduler {
        let mut cfg = ResourceSchedulerConfig::default();
        cfg.pools.cpu.capacity = cpu;
        cfg.pools.memory.capacity = memory;
        cfg.limits.max_queued = max_queued;
        ResourceScheduler::new(cfg)
    }

    fn req(cpu: u32, memory: u32) -> ResourceAcquireRequest {
        ResourceAcquireRequest::new(ResourceRequirements::new([
            ("cpu", cpu),
            ("memory", memory),
        ]))
    }

    #[tokio::test]
    async fn acquisition_and_release_start_next_waiter() {
        let scheduler = scheduler(1, 1, 8);
        let cancel = CancellationToken::new();
        let first = scheduler.acquire(req(1, 1), &cancel).await.unwrap();
        let second = scheduler.submit(req(1, 1)).unwrap();
        assert!(second.display_id().starts_with("rs-"));
        assert_eq!(scheduler.snapshot().queued.len(), 1);

        first.release();
        let second = second.wait(&cancel).await.unwrap();
        assert!(second.display_id().starts_with("rs-"));
        let snap = scheduler.snapshot();
        assert_eq!(snap.running.len(), 1);
        assert_eq!(snap.running[0].id, second.request_id());
    }

    #[tokio::test]
    async fn atomic_acquisition_requires_every_pool() {
        let scheduler = scheduler(2, 1, 8);
        let cancel = CancellationToken::new();
        let first = scheduler.acquire(req(1, 1), &cancel).await.unwrap();
        let queued = scheduler.submit(req(1, 1)).unwrap();

        let snap = scheduler.snapshot();
        assert_eq!(snap.queued[0].id, queued.request_id());
        assert_eq!(snap.running[0].id, first.request_id());
    }

    #[test]
    fn over_capacity_requests_fail_immediately() {
        let scheduler = scheduler(1, 1, 8);
        let err = scheduler.submit(req(2, 1)).unwrap_err();
        assert!(matches!(
            err,
            ResourceAcquireError::OverCapacity {
                pool,
                requested: 2,
                capacity: 1,
            } if pool == "cpu"
        ));
        assert!(scheduler.snapshot().queued.is_empty());
    }

    #[tokio::test]
    async fn max_queue_length_is_enforced() {
        let scheduler = scheduler(1, 1, 1);
        let cancel = CancellationToken::new();
        let _running = scheduler.acquire(req(1, 1), &cancel).await.unwrap();
        let _queued = scheduler.submit(req(1, 1)).unwrap();
        let err = scheduler.submit(req(1, 1)).unwrap_err();
        assert_eq!(err, ResourceAcquireError::QueueFull { max_queued: 1 });
    }

    #[tokio::test]
    async fn cancellation_removes_queued_request_and_advances_queue() {
        let scheduler = scheduler(1, 1, 8);
        let cancel = CancellationToken::new();
        let running = scheduler.acquire(req(1, 1), &cancel).await.unwrap();
        let queued = scheduler.submit(req(1, 1)).unwrap();
        let queued_id = queued.request_id();
        let queued_cancel = CancellationToken::new();
        queued_cancel.cancel();
        let err = queued.wait(&queued_cancel).await.unwrap_err();
        assert_eq!(err, ResourceAcquireError::Cancelled);
        assert!(
            scheduler
                .snapshot()
                .queued
                .iter()
                .all(|entry| entry.id != queued_id)
        );
        drop(running);
        assert!(scheduler.snapshot().running.is_empty());
    }

    #[tokio::test]
    async fn strict_fifo_head_of_line_blocks_later_smaller_request() {
        let scheduler = scheduler(6, 6, 8);
        let cancel = CancellationToken::new();
        let blocker = scheduler.acquire(req(4, 4), &cancel).await.unwrap();
        let small_running = scheduler.acquire(req(2, 2), &cancel).await.unwrap();
        let head = scheduler.submit(req(4, 4)).unwrap();
        let later = scheduler.submit(req(2, 2)).unwrap();
        assert_eq!(
            scheduler
                .snapshot()
                .queued
                .iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>(),
            vec![head.request_id(), later.request_id()]
        );

        drop(small_running);
        let snap = scheduler.snapshot();
        assert!(
            snap.queued
                .iter()
                .any(|entry| entry.id == head.request_id())
        );
        assert!(
            snap.queued
                .iter()
                .any(|entry| entry.id == later.request_id())
        );

        drop(blocker);
        let head_lease = head.wait(&cancel).await.unwrap();
        let snap = scheduler.snapshot();
        assert!(
            snap.running
                .iter()
                .any(|entry| entry.id == head_lease.request_id())
        );
        assert!(
            snap.running
                .iter()
                .any(|entry| entry.id == later.request_id())
        );
    }

    #[tokio::test]
    async fn disabled_scheduler_returns_noop_lease_without_tracking() {
        let scheduler = ResourceScheduler::disabled();
        let cancel = CancellationToken::new();
        let lease = scheduler.acquire(req(1, 1), &cancel).await.unwrap();
        assert!(lease.display_id().starts_with("rs-"));
        assert!(scheduler.snapshot().running.is_empty());
        assert!(scheduler.snapshot().queued.is_empty());
    }

    #[tokio::test]
    async fn promotion_moves_queued_request_to_front_without_preempting_running() {
        let scheduler = scheduler(2, 2, 8);
        let cancel = CancellationToken::new();
        let running = scheduler.acquire(req(2, 2), &cancel).await.unwrap();
        let first = scheduler.submit(req(2, 2)).unwrap();
        let second = scheduler.submit(req(1, 1)).unwrap();

        scheduler
            .promote(second.request_id(), "user")
            .expect("promote queued request");
        let snap = scheduler.snapshot();
        assert_eq!(snap.running[0].id, running.request_id());
        assert_eq!(snap.queued[0].id, second.request_id());
        assert_eq!(snap.queued[0].state, ResourceQueuedState::Promoted);
        assert_eq!(snap.queued[1].id, first.request_id());

        let second_id = second.request_id();
        drop(running);
        let promoted = second.wait(&cancel).await.unwrap();
        assert_eq!(promoted.request_id(), second_id);
    }
}
