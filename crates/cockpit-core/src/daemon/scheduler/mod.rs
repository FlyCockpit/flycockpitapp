use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use croner::parser::{CronParser, Seconds};
use serde_json::json;
use tokio::sync::{Semaphore, oneshot, watch};

use crate::daemon::proto::{
    EnvSnapshotSource, MissedRunPolicy, ScheduledJobCreate, ScheduledJobLastResult,
    ScheduledJobPayload, ScheduledJobSchedule, ScheduledJobSummary,
};
use crate::daemon::registry::SessionRegistry;
use crate::daemon::session_worker::SessionWork;
use crate::db::Db;
use crate::db::scheduler::{NewScheduledJobRow, ScheduledJobRow, ScheduledJobRunUpdate};

const MAX_FAILURES: u32 = 5;
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(30);
const RUN_PROMPT_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_CONCURRENT_JOBS: usize = 4;

type CallbackFuture = Pin<Box<dyn Future<Output = Result<String>> + Send>>;
type SchedulerCallback = Arc<dyn Fn(ScheduledJob) -> CallbackFuture + Send + Sync>;

#[derive(Clone, Default)]
pub struct CallbackRegistry {
    callbacks: Arc<RwLock<HashMap<String, SchedulerCallback>>>,
}

impl CallbackRegistry {
    pub fn register<F, Fut>(&self, subsystem: impl Into<String>, callback: F)
    where
        F: Fn(ScheduledJob) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String>> + Send + 'static,
    {
        let callback =
            Arc::new(move |job: ScheduledJob| -> CallbackFuture { Box::pin(callback(job)) });
        self.callbacks
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(subsystem.into(), callback);
    }

    fn get(&self, subsystem: &str) -> Option<SchedulerCallback> {
        self.callbacks
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(subsystem)
            .cloned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledJob {
    pub id: String,
    pub owner: String,
    pub schedule: ScheduledJobSchedule,
    pub payload: ScheduledJobPayload,
    pub enabled: bool,
    pub missed_run_policy: MissedRunPolicy,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_run_at: Option<i64>,
    pub next_run_at: Option<i64>,
    pub last_result: Option<ScheduledJobLastResult>,
    pub failure_count: u32,
    pub backoff_until: Option<i64>,
    pub disabled_notice: Option<String>,
}

pub trait SchedulerClock: Send + Sync {
    fn now(&self) -> i64;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl SchedulerClock for SystemClock {
    fn now(&self) -> i64 {
        Utc::now().timestamp()
    }
}

#[async_trait]
pub trait JobExecutor: Send + Sync {
    async fn execute(&self, job: ScheduledJob) -> Result<String>;
}

#[async_trait]
pub trait SchedulerSleeper: Send + Sync {
    async fn sleep_until(&self, now: i64, wake_at: Option<i64>);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunKind {
    Scheduled,
    Manual,
}

#[derive(Debug, Default)]
pub struct TokioSchedulerSleeper;

#[async_trait]
impl SchedulerSleeper for TokioSchedulerSleeper {
    async fn sleep_until(&self, now: i64, wake_at: Option<i64>) {
        let seconds = wake_at
            .map(|next| next.saturating_sub(now).max(0) as u64)
            .unwrap_or(60 * 60);
        tokio::time::sleep(Duration::from_secs(seconds)).await;
    }
}

#[derive(Clone)]
pub struct DaemonScheduler {
    db: Db,
    clock: Arc<dyn SchedulerClock>,
    executor: Arc<dyn JobExecutor>,
    last_user_activity: Arc<RwLock<i64>>,
    timeline: Arc<RwLock<BinaryHeap<Reverse<i64>>>>,
    in_flight: Arc<std::sync::Mutex<HashSet<String>>>,
    slots: Arc<Semaphore>,
}

#[derive(Clone)]
pub struct DaemonSchedulerHandle {
    scheduler: Arc<DaemonScheduler>,
    wake_tx: watch::Sender<u64>,
    callbacks: Option<CallbackRegistry>,
}

impl DaemonSchedulerHandle {
    pub fn scheduler(&self) -> &Arc<DaemonScheduler> {
        &self.scheduler
    }

    pub fn wake_generation(&self) -> u64 {
        *self.wake_tx.borrow()
    }

    pub fn register_callback<F, Fut>(&self, subsystem: impl Into<String>, callback: F) -> Result<()>
    where
        F: Fn(ScheduledJob) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String>> + Send + 'static,
    {
        let registry = self.callbacks.as_ref().ok_or_else(|| {
            anyhow::anyhow!("scheduler callback registration is unavailable for this executor")
        })?;
        registry.register(subsystem, callback);
        Ok(())
    }

    fn wake(&self) {
        let next = self.wake_generation().saturating_add(1);
        let _ = self.wake_tx.send(next);
    }

    pub fn record_user_activity(&self) {
        if let Err(error) = self.scheduler.record_user_activity() {
            tracing::warn!(error = %error, "scheduler activity recompute failed");
        }
        self.wake();
    }

    pub fn create_job(&self, job: ScheduledJobCreate) -> Result<ScheduledJobSummary> {
        let summary = self.scheduler.create_job(job)?;
        self.wake();
        Ok(summary)
    }

    pub fn list_jobs(&self, owner: Option<&str>) -> Result<Vec<ScheduledJobSummary>> {
        self.scheduler.list_jobs(owner)
    }

    pub fn delete_job(&self, id: &str) -> Result<bool> {
        let deleted = self.scheduler.delete_job(id)?;
        if deleted {
            self.wake();
        }
        Ok(deleted)
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<Option<ScheduledJobSummary>> {
        let job = self.scheduler.set_enabled(id, enabled)?;
        self.wake();
        Ok(job)
    }

    pub fn run_now(&self, id: &str) -> Result<()> {
        self.scheduler.run_job_by_id(id)?;
        self.wake();
        Ok(())
    }
}

impl DaemonScheduler {
    pub fn new(db: Db, clock: Arc<dyn SchedulerClock>, executor: Arc<dyn JobExecutor>) -> Self {
        let now = clock.now();
        Self {
            db,
            clock,
            executor,
            last_user_activity: Arc::new(RwLock::new(now)),
            timeline: Arc::new(RwLock::new(BinaryHeap::new())),
            in_flight: Arc::new(std::sync::Mutex::new(HashSet::new())),
            slots: Arc::new(Semaphore::new(MAX_CONCURRENT_JOBS)),
        }
    }

    pub fn start(
        self: Arc<Self>,
        shutdown: crate::daemon::shutdown::ShutdownSignal,
    ) -> DaemonSchedulerHandle {
        self.start_with_sleeper(shutdown, Arc::new(TokioSchedulerSleeper), None)
    }

    pub fn start_with_callbacks(
        self: Arc<Self>,
        shutdown: crate::daemon::shutdown::ShutdownSignal,
        callbacks: CallbackRegistry,
    ) -> DaemonSchedulerHandle {
        self.start_with_sleeper(shutdown, Arc::new(TokioSchedulerSleeper), Some(callbacks))
    }

    pub fn start_with_sleeper(
        self: Arc<Self>,
        shutdown: crate::daemon::shutdown::ShutdownSignal,
        sleeper: Arc<dyn SchedulerSleeper>,
        callbacks: Option<CallbackRegistry>,
    ) -> DaemonSchedulerHandle {
        let (wake_tx, wake_rx) = watch::channel(0u64);
        let handle = DaemonSchedulerHandle {
            scheduler: self.clone(),
            wake_tx,
            callbacks,
        };
        tokio::spawn(run_scheduler_loop(self, sleeper, wake_rx, shutdown));
        handle
    }

    pub fn record_user_activity(&self) -> Result<()> {
        *self
            .last_user_activity
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = self.clock.now();
        self.rebuild_timeline()
    }

    pub fn create_job(&self, job: ScheduledJobCreate) -> Result<ScheduledJobSummary> {
        validate_job_create_with_db(&job, &self.db)?;
        let now = self.clock.now();
        let next_run_at = compute_next_run(
            &job.schedule,
            now,
            None,
            now,
            self.last_user_activity(),
            job.missed_run_policy,
            None,
        )?;
        let row = self.db.insert_scheduled_job(NewScheduledJobRow {
            id: job.id,
            owner: job.owner,
            schedule_json: serde_json::to_string(&job.schedule)?,
            payload_json: serde_json::to_string(&job.payload)?,
            enabled: job.enabled,
            missed_run_policy: job.missed_run_policy.as_str().to_string(),
            created_at: now,
            updated_at: now,
            next_run_at: job.enabled.then_some(next_run_at).flatten(),
        })?;
        self.rebuild_timeline()?;
        row_to_summary(row)
    }

    pub fn list_jobs(&self, owner: Option<&str>) -> Result<Vec<ScheduledJobSummary>> {
        self.db
            .list_scheduled_jobs(owner)?
            .into_iter()
            .map(row_to_summary)
            .collect()
    }

    pub fn delete_job(&self, id: &str) -> Result<bool> {
        let deleted = self.db.delete_scheduled_job(id)?;
        if deleted {
            self.rebuild_timeline()?;
        }
        Ok(deleted)
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<Option<ScheduledJobSummary>> {
        let Some(job) = self.db.get_scheduled_job(id)? else {
            return Ok(None);
        };
        let job = row_to_job(job)?;
        let now = self.clock.now();
        let next_run_at = enabled
            .then(|| {
                compute_next_run(
                    &job.schedule,
                    now,
                    job.last_run_at,
                    job.created_at,
                    self.last_user_activity(),
                    job.missed_run_policy,
                    job.next_run_at,
                )
            })
            .transpose()?
            .flatten();
        let job = self
            .db
            .set_scheduled_job_enabled(id, enabled, next_run_at, now)?
            .map(row_to_summary)
            .transpose()?;
        self.rebuild_timeline()?;
        Ok(job)
    }

    pub fn recompute_after_start(&self) -> Result<()> {
        let now = self.clock.now();
        for row in self.db.list_scheduled_jobs(None)? {
            let job = row_to_job(row)?;
            if !job.enabled {
                continue;
            }
            let next = compute_next_run(
                &job.schedule,
                now,
                job.last_run_at,
                job.created_at,
                self.last_user_activity(),
                job.missed_run_policy,
                job.next_run_at,
            )?;
            self.db.update_scheduled_job_next_run(&job.id, next, now)?;
        }
        self.rebuild_timeline()
    }

    pub fn next_wake(&self) -> Result<Option<i64>> {
        Ok(self
            .timeline
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .peek()
            .map(|Reverse(at)| *at))
    }

    pub fn timeline_len(&self) -> usize {
        self.timeline
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub async fn run_due_once(&self) -> Result<Vec<ScheduledJobLastResult>> {
        let now = self.clock.now();
        let jobs = self
            .db
            .list_scheduled_jobs(None)?
            .into_iter()
            .map(row_to_job)
            .collect::<Result<Vec<_>>>()?;
        let results = Vec::new();
        for job in jobs {
            if !job.enabled || job.next_run_at.is_none_or(|next| next > now) {
                continue;
            }
            if job.backoff_until.is_some_and(|until| until > now) {
                continue;
            }
            if self.is_in_flight(&job.id) {
                continue;
            }
            if let Some(wait_until) = self.idle_wait_until(&job, now)? {
                self.db
                    .update_scheduled_job_next_run(&job.id, Some(wait_until), now)?;
                continue;
            }
            self.enqueue_job(job, RunKind::Scheduled)?;
        }
        self.rebuild_timeline()?;
        Ok(results)
    }

    pub fn run_job_by_id(&self, id: &str) -> Result<()> {
        let row = self
            .db
            .get_scheduled_job(id)?
            .ok_or_else(|| anyhow::anyhow!("scheduled job `{id}` not found"))?;
        self.enqueue_job(row_to_job(row)?, RunKind::Manual)?;
        self.rebuild_timeline()?;
        Ok(())
    }

    fn enqueue_job(&self, job: ScheduledJob, kind: RunKind) -> Result<()> {
        self.mark_in_flight(&job.id)?;
        let scheduler = self.clone();
        tokio::spawn(async move {
            if let Err(error) = scheduler.execute_and_record(job.clone(), kind).await {
                tracing::warn!(
                    error = %error,
                    job_id = %job.id,
                    "scheduled job execution failed before recording"
                );
            }
            scheduler.clear_in_flight(&job.id);
            if let Err(error) = scheduler.rebuild_timeline() {
                tracing::warn!(error = %error, "scheduler timeline rebuild after job failed");
            }
        });
        Ok(())
    }

    fn mark_in_flight(&self, id: &str) -> Result<()> {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !in_flight.insert(id.to_string()) {
            bail!("scheduled job `{id}` is already running");
        }
        Ok(())
    }

    fn clear_in_flight(&self, id: &str) {
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(id);
    }

    fn is_in_flight(&self, id: &str) -> bool {
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(id)
    }

    async fn execute_and_record(
        &self,
        job: ScheduledJob,
        kind: RunKind,
    ) -> Result<ScheduledJobLastResult> {
        let _slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .context("scheduler concurrency limiter closed")?;
        let execution = self.executor.execute(job.clone()).await;
        let finished_at = self.clock.now();
        let (ok, summary) = match execution {
            Ok(summary) => (true, summary),
            Err(error) => (false, format!("{error:#}")),
        };
        let result = ScheduledJobLastResult {
            ok,
            summary,
            finished_at,
        };
        let Some(current_row) = self.db.get_scheduled_job(&job.id)? else {
            return Ok(result);
        };
        let current = row_to_job(current_row)?;
        let failure_count = if ok {
            0
        } else {
            current.failure_count.saturating_add(1)
        };
        let disabled = failure_count >= MAX_FAILURES;
        let disabled_notice = disabled.then(|| {
            format!(
                "scheduled job `{}` disabled after {failure_count} consecutive failures",
                job.id
            )
        });
        let backoff_until = (!ok && !disabled)
            .then(|| finished_at.saturating_add(backoff_seconds(failure_count, &job.id)));
        let enabled = current.enabled && !disabled;
        let next_run_at = if !enabled {
            None
        } else if kind == RunKind::Scheduled {
            compute_next_run(
                &current.schedule,
                finished_at,
                Some(finished_at),
                finished_at,
                self.last_user_activity(),
                current.missed_run_policy,
                None,
            )?
        } else {
            current.next_run_at
        };
        self.db
            .update_scheduled_job_after_run(ScheduledJobRunUpdate {
                id: job.id,
                last_run_at: finished_at,
                next_run_at,
                last_result_json: serde_json::to_string(&result)?,
                failure_count,
                backoff_until,
                enabled,
                disabled_notice: disabled_notice.or(current.disabled_notice),
            })?;
        Ok(result)
    }

    fn last_user_activity(&self) -> i64 {
        *self
            .last_user_activity
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn idle_wait_until(&self, job: &ScheduledJob, now: i64) -> Result<Option<i64>> {
        let ScheduledJobSchedule::Idle {
            min_idle_seconds,
            max_age_seconds,
        } = &job.schedule
        else {
            return Ok(None);
        };
        let min_idle = i64::try_from(*min_idle_seconds).context("idle min_idle too large")?;
        let max_age = i64::try_from(*max_age_seconds).context("idle max_age too large")?;
        let age_base = job.last_run_at.unwrap_or(job.created_at);
        let max_age_at = age_base.saturating_add(max_age);
        if now >= max_age_at {
            return Ok(None);
        }
        let wait_until = self
            .last_user_activity()
            .saturating_add(min_idle)
            .min(max_age_at);
        Ok((wait_until > now).then_some(wait_until))
    }

    fn rebuild_timeline(&self) -> Result<()> {
        let now = self.clock.now();
        let mut heap = BinaryHeap::new();
        for row in self.db.list_scheduled_jobs(None)? {
            let job = row_to_job(row)?;
            if !job.enabled {
                continue;
            }
            if self.is_in_flight(&job.id) {
                continue;
            }
            let wake_at = if let Some(backoff) = job.backoff_until
                && backoff > now
            {
                Some(backoff)
            } else {
                job.next_run_at
            };
            if let Some(wake_at) = wake_at {
                heap.push(Reverse(wake_at));
            }
        }
        *self
            .timeline
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = heap;
        Ok(())
    }
}

async fn run_scheduler_loop(
    scheduler: Arc<DaemonScheduler>,
    sleeper: Arc<dyn SchedulerSleeper>,
    mut wake_rx: watch::Receiver<u64>,
    shutdown: crate::daemon::shutdown::ShutdownSignal,
) {
    if let Err(error) = scheduler.recompute_after_start() {
        tracing::warn!(error = %error, "scheduler startup recompute failed");
    }
    loop {
        if shutdown.is_draining() {
            return;
        }
        let now = scheduler.clock.now();
        let wake_at = match scheduler.next_wake() {
            Ok(wake_at) => wake_at,
            Err(error) => {
                tracing::warn!(error = %error, "scheduler next wake failed");
                Some(now.saturating_add(60))
            }
        };
        let sleep = sleeper.sleep_until(now, wake_at);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {
                if let Err(error) = scheduler.run_due_once().await {
                    tracing::warn!(error = %error, "scheduler due-job pass failed");
                }
            }
            changed = wake_rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct ProductionJobExecutor {
    db: Db,
    prompt_runner: Arc<dyn ScheduledPromptRunner>,
    callbacks: CallbackRegistry,
}

impl ProductionJobExecutor {
    pub fn new(db: Db, registry: SessionRegistry) -> Self {
        Self {
            db,
            prompt_runner: Arc::new(RegistryPromptRunner { registry }),
            callbacks: CallbackRegistry::default(),
        }
    }

    pub fn with_prompt_runner(db: Db, prompt_runner: Arc<dyn ScheduledPromptRunner>) -> Self {
        Self {
            db,
            prompt_runner,
            callbacks: CallbackRegistry::default(),
        }
    }

    pub fn callback_registry(&self) -> CallbackRegistry {
        self.callbacks.clone()
    }

    pub fn register_callback<F, Fut>(&self, subsystem: impl Into<String>, callback: F)
    where
        F: Fn(ScheduledJob) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String>> + Send + 'static,
    {
        self.callbacks.register(subsystem, callback);
    }
}

#[async_trait]
impl JobExecutor for ProductionJobExecutor {
    async fn execute(&self, job: ScheduledJob) -> Result<String> {
        match job.payload.clone() {
            ScheduledJobPayload::RunPrompt {
                assistant,
                prompt,
                project_root,
            } => self.run_prompt(job, assistant, prompt, project_root).await,
            ScheduledJobPayload::Callback { subsystem } => {
                let callback = self.callbacks.get(&subsystem).ok_or_else(|| {
                    anyhow::anyhow!("scheduler callback `{subsystem}` is not registered")
                })?;
                tokio::time::timeout(CALLBACK_TIMEOUT, callback(job))
                    .await
                    .map_err(|_| anyhow::anyhow!("scheduler callback timed out"))?
            }
        }
    }
}

impl ProductionJobExecutor {
    async fn run_prompt(
        &self,
        job: ScheduledJob,
        assistant: String,
        prompt: String,
        project_root: String,
    ) -> Result<String> {
        let expected_owner = format!("assistant:{assistant}");
        if job.owner != expected_owner {
            bail!(
                "RunPrompt owner/payload mismatch: owner `{}` cannot run assistant `{assistant}`",
                job.owner
            );
        }
        let row = self
            .db
            .get_assistant(&assistant)?
            .ok_or_else(|| anyhow::anyhow!("assistant `{assistant}` not found"))?;
        crate::assistants::load_from_row(&row)
            .with_context(|| format!("validating assistant `{assistant}`"))?;

        let root = PathBuf::from(project_root);
        let project_id = crate::session::project_id_for(&root);
        let root_str = root.to_string_lossy().into_owned();
        let session = self
            .db
            .create_assistant_session(&project_id, &root_str, &assistant, &assistant)
            .context("creating scheduled assistant session")?;
        self.prompt_runner
            .run_prompt_turn(
                &self.db,
                &job,
                session.session_id,
                &assistant,
                prompt,
                crate::env_snapshot::EnvSnapshot::from_process(EnvSnapshotSource::DaemonStart),
            )
            .await
            .inspect_err(|error| {
                let text = format!("scheduled job `{}` refused: {error}", job.id);
                let _ = self.db.insert_session_event(
                    session.session_id,
                    crate::db::session_log::SessionEventKind::Notice,
                    Some(&assistant),
                    None,
                    &json!({ "text": text, "source": "daemon_scheduler" }),
                );
            })
            .with_context(|| format!("running scheduled assistant session {}", session.session_id))
    }
}

#[async_trait]
pub trait ScheduledPromptRunner: Send + Sync {
    async fn run_prompt_turn(
        &self,
        db: &Db,
        job: &ScheduledJob,
        session_id: uuid::Uuid,
        assistant: &str,
        prompt: String,
        env_snapshot: crate::env_snapshot::EnvSnapshot,
    ) -> Result<String>;
}

struct RegistryPromptRunner {
    registry: SessionRegistry,
}

#[async_trait]
impl ScheduledPromptRunner for RegistryPromptRunner {
    async fn run_prompt_turn(
        &self,
        db: &Db,
        job: &ScheduledJob,
        session_id: uuid::Uuid,
        assistant: &str,
        prompt: String,
        env_snapshot: crate::env_snapshot::EnvSnapshot,
    ) -> Result<String> {
        let handle = match self
            .registry
            .attach(Some(session_id), None, false, None, env_snapshot)
            .await
        {
            Ok(handle) => handle,
            Err(error) => {
                if let Err(cleanup_error) = db.delete_session(session_id, true) {
                    tracing::warn!(
                        error = %cleanup_error,
                        %session_id,
                        "failed to clean up refused scheduled session"
                    );
                }
                return Err(error).context("starting scheduled assistant session");
            }
        };
        let mut events = handle.subscribe();
        let (respond_to, response_rx) = oneshot::channel();
        handle
            .send_work(SessionWork::UserMessage {
                submission: Box::new(crate::engine::message::UserSubmission {
                    kind: crate::engine::message::UserSubmissionKind::User,
                    text: prompt,
                    display_text: None,
                    tag_expansions: Vec::new(),
                    images: Vec::new(),
                    forced_skill: None,
                    origin_principal: Some("daemon_scheduler".to_string()),
                    job_id: Some(job.id.clone()),
                    preflight_cleaned: None,
                    queue_item_ids: Vec::new(),
                    queue_target: None,
                }),
                respond_to,
            })
            .await
            .context("dispatching scheduled prompt")?;
        let (queued_item, _) = response_rx
            .await
            .context("scheduled prompt queue ack dropped")?;
        let expected_turn_id = queued_item.id.to_string();
        tokio::time::timeout(RUN_PROMPT_TIMEOUT, async {
            loop {
                match events.recv().await {
                    Ok(envelope)
                        if matches!(
                            &envelope.event,
                            crate::daemon::proto::Event::AgentIdle { session_id, turn_id, .. }
                                if *session_id == handle.session_id
                                    && turn_id.as_deref() == Some(expected_turn_id.as_str())
                        ) =>
                    {
                        return Ok(format!(
                            "assistant `{assistant}` completed scheduled turn in session {}",
                            handle.session_id
                        ));
                    }
                    Ok(envelope)
                        if matches!(
                            &envelope.event,
                            crate::daemon::proto::Event::SessionDriverFailed {
                                session_id,
                                turn_id,
                                ..
                            } if *session_id == handle.session_id
                                && turn_id
                                    .as_deref()
                                    .is_none_or(|turn_id| turn_id == expected_turn_id)
                        ) =>
                    {
                        if let crate::daemon::proto::Event::SessionDriverFailed { error, .. } =
                            envelope.event
                        {
                            bail!("scheduled session driver failed: {error}");
                        }
                    }
                    Ok(_) => {}
                    Err(error) => bail!("scheduled session event stream closed: {error}"),
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("scheduled prompt timed out"))?
    }
}

pub fn validate_job_create(job: &ScheduledJobCreate) -> Result<()> {
    validate_job_id(&job.id)?;
    validate_owner(&job.owner)?;
    validate_schedule(&job.schedule)?;
    match &job.payload {
        ScheduledJobPayload::RunPrompt {
            assistant,
            prompt,
            project_root,
        } => {
            crate::assistants::validate_assistant_name(assistant)?;
            let expected = format!("assistant:{assistant}");
            if job.owner != expected {
                bail!("RunPrompt owner must be `{expected}`");
            }
            if prompt.trim().is_empty() {
                bail!("RunPrompt prompt must not be empty");
            }
            if project_root.trim().is_empty() {
                bail!("RunPrompt project_root must not be empty");
            }
        }
        ScheduledJobPayload::Callback { subsystem } => {
            if subsystem.trim().is_empty() || subsystem.contains(':') {
                bail!("Callback subsystem must be a non-empty subsystem id");
            }
            let expected = format!("system:{subsystem}");
            if job.owner != expected {
                bail!("Callback owner must be `{expected}`");
            }
        }
    }
    Ok(())
}

fn validate_job_create_with_db(job: &ScheduledJobCreate, db: &Db) -> Result<()> {
    validate_job_create(job)?;
    if let ScheduledJobPayload::RunPrompt { assistant, .. } = &job.payload
        && db.get_assistant(assistant)?.is_none()
    {
        bail!("assistant `{assistant}` not found");
    }
    Ok(())
}

fn validate_job_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 96
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        bail!("scheduled job id must use [A-Za-z0-9_.-] and be 1-96 bytes");
    }
    Ok(())
}

fn validate_owner(owner: &str) -> Result<()> {
    let Some((kind, name)) = owner.split_once(':') else {
        bail!("scheduled job owner must be assistant:<name> or system:<subsystem>");
    };
    if !matches!(kind, "assistant" | "system") || name.trim().is_empty() {
        bail!("scheduled job owner must be assistant:<name> or system:<subsystem>");
    }
    Ok(())
}

pub fn validate_schedule(schedule: &ScheduledJobSchedule) -> Result<()> {
    match schedule {
        ScheduledJobSchedule::Cron { expr } => {
            let expr = normalize_cron_expr(expr)?;
            validate_product_cron(&expr)?;
            CronParser::builder()
                .seconds(Seconds::Disallowed)
                .build()
                .parse(&expr)
                .with_context(|| format!("invalid cron expression `{expr}`"))?;
        }
        ScheduledJobSchedule::Every { seconds } => {
            if *seconds == 0 {
                bail!("every schedule duration must be greater than zero");
            }
        }
        ScheduledJobSchedule::Once { .. } => {}
        ScheduledJobSchedule::Idle {
            min_idle_seconds,
            max_age_seconds,
        } => {
            if *min_idle_seconds == 0 || *max_age_seconds == 0 {
                bail!("idle min_idle_seconds and max_age_seconds must be greater than zero");
            }
        }
    }
    Ok(())
}

pub fn compute_next_run(
    schedule: &ScheduledJobSchedule,
    now: i64,
    last_run_at: Option<i64>,
    created_at: i64,
    last_user_activity: i64,
    missed_policy: MissedRunPolicy,
    stored_next: Option<i64>,
) -> Result<Option<i64>> {
    if let Some(next) = stored_next
        && next >= now
    {
        return Ok(Some(next));
    }
    if stored_next.is_some_and(|next| next <= now)
        && missed_policy == MissedRunPolicy::RunOnceOnStart
    {
        return Ok(Some(now));
    }
    match schedule {
        ScheduledJobSchedule::Cron { expr } => {
            let expr = normalize_cron_expr(expr)?;
            validate_product_cron(&expr)?;
            let cron = CronParser::builder()
                .seconds(Seconds::Disallowed)
                .build()
                .parse(&expr)?;
            let start = Utc
                .timestamp_opt(now, 0)
                .single()
                .ok_or_else(|| anyhow::anyhow!("invalid scheduler timestamp {now}"))?;
            Ok(Some(cron.find_next_occurrence(&start, false)?.timestamp()))
        }
        ScheduledJobSchedule::Every { seconds } => {
            let seconds = i64::try_from(*seconds).context("every schedule too large")?;
            let base = last_run_at.unwrap_or(created_at).max(now);
            Ok(Some(base.saturating_add(seconds)))
        }
        ScheduledJobSchedule::Once { at } => {
            if *at > now
                || last_run_at.is_none() && missed_policy == MissedRunPolicy::RunOnceOnStart
            {
                Ok(Some((*at).max(now)))
            } else {
                Ok(None)
            }
        }
        ScheduledJobSchedule::Idle {
            min_idle_seconds,
            max_age_seconds,
        } => {
            let min_idle = i64::try_from(*min_idle_seconds).context("idle min_idle too large")?;
            let max_age = i64::try_from(*max_age_seconds).context("idle max_age too large")?;
            let age_base = last_run_at.unwrap_or(created_at);
            Ok(Some(
                last_user_activity
                    .saturating_add(min_idle)
                    .min(age_base.saturating_add(max_age)),
            ))
        }
    }
}

fn normalize_cron_expr(expr: &str) -> Result<String> {
    let trimmed = expr.trim();
    let expanded = match trimmed {
        "@hourly" => "0 * * * *",
        "@daily" => "0 0 * * *",
        "@weekly" => "0 0 * * 0",
        "@monthly" => "0 0 1 * *",
        other if other.starts_with('@') => bail!("unsupported cron macro `{other}`"),
        other => other,
    };
    Ok(expanded.to_string())
}

fn validate_product_cron(expr: &str) -> Result<()> {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        bail!("cron expression must have exactly five fields");
    }
    validate_cron_field(fields[0], 0, 59, "minute")?;
    validate_cron_field(fields[1], 0, 23, "hour")?;
    validate_cron_field(fields[2], 1, 31, "day-of-month")?;
    validate_cron_field(fields[3], 1, 12, "month")?;
    validate_cron_field(fields[4], 0, 7, "day-of-week")?;
    Ok(())
}

fn validate_cron_field(field: &str, min: u32, max: u32, name: &str) -> Result<()> {
    if field.is_empty() {
        bail!("cron {name} field is empty");
    }
    for part in field.split(',') {
        validate_cron_part(part, min, max, name)?;
    }
    Ok(())
}

fn validate_cron_part(part: &str, min: u32, max: u32, name: &str) -> Result<()> {
    let (range, step) = part
        .split_once('/')
        .map_or((part, None), |(range, step)| (range, Some(step)));
    if let Some(step) = step {
        if range != "*" {
            bail!("cron {name} steps only support */n syntax");
        }
        let step: u32 = step
            .parse()
            .with_context(|| format!("cron {name} step must be numeric"))?;
        if step == 0 {
            bail!("cron {name} step must be greater than zero");
        }
    }
    if range == "*" {
        return Ok(());
    }
    let check_num = |raw: &str| -> Result<()> {
        if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
            bail!("cron {name} field only supports numeric values, ranges, lists, and steps");
        }
        let value: u32 = raw.parse()?;
        if !(min..=max).contains(&value) {
            bail!("cron {name} value {value} is outside {min}-{max}");
        }
        Ok(())
    };
    if let Some((start, end)) = range.split_once('-') {
        check_num(start)?;
        check_num(end)?;
        if start.parse::<u32>()? > end.parse::<u32>()? {
            bail!("cron {name} range start must be <= end");
        }
    } else {
        check_num(range)?;
    }
    Ok(())
}

fn backoff_seconds(failure_count: u32, job_id: &str) -> i64 {
    let exp = failure_count.saturating_sub(1).min(6);
    let base = 60_i64.saturating_mul(1_i64 << exp);
    let jitter = (job_id.bytes().map(u64::from).sum::<u64>() % 30) as i64;
    base.saturating_add(jitter).min(60 * 60)
}

fn row_to_summary(row: ScheduledJobRow) -> Result<ScheduledJobSummary> {
    let job = row_to_job(row)?;
    Ok(ScheduledJobSummary {
        id: job.id,
        owner: job.owner,
        schedule: job.schedule,
        payload: job.payload,
        enabled: job.enabled,
        missed_run_policy: job.missed_run_policy,
        last_run_at: job.last_run_at,
        next_run_at: job.next_run_at,
        last_result: job.last_result,
        failure_count: job.failure_count,
        backoff_until: job.backoff_until,
        disabled_notice: job.disabled_notice,
    })
}

fn row_to_job(row: ScheduledJobRow) -> Result<ScheduledJob> {
    Ok(ScheduledJob {
        id: row.id,
        owner: row.owner,
        schedule: serde_json::from_str(&row.schedule_json).context("parsing job schedule")?,
        payload: serde_json::from_str(&row.payload_json).context("parsing job payload")?,
        enabled: row.enabled,
        missed_run_policy: match row.missed_run_policy.as_str() {
            "skip" => MissedRunPolicy::Skip,
            "run_once_on_start" => MissedRunPolicy::RunOnceOnStart,
            other => bail!("unknown missed-run policy `{other}`"),
        },
        created_at: row.created_at,
        updated_at: row.updated_at,
        last_run_at: row.last_run_at,
        next_run_at: row.next_run_at,
        last_result: row
            .last_result_json
            .map(|raw| serde_json::from_str(&raw))
            .transpose()
            .context("parsing job last_result")?,
        failure_count: row.failure_count,
        backoff_until: row.backoff_until,
        disabled_notice: row.disabled_notice,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::agents::AgentMode;
    use crate::assistants::{CreateAssistantSpec, create_assistant};
    use crate::config::extended::ExtendedConfig;
    use crate::config::providers::ProvidersConfig;
    use crate::daemon::config_source::ConfigSource;
    use crate::daemon::registry::SessionRegistry;
    use crate::daemon::shutdown::ShutdownSignal;
    use crate::db::workspace_trust::WorkspaceTrustMode;
    use crate::locks::LockManager;
    use tokio::sync::Notify;

    #[derive(Debug)]
    struct ManualClock(std::sync::Mutex<i64>);

    impl ManualClock {
        fn new(now: i64) -> Arc<Self> {
            Arc::new(Self(std::sync::Mutex::new(now)))
        }

        fn set(&self, now: i64) {
            *self.0.lock().unwrap() = now;
        }
    }

    impl SchedulerClock for ManualClock {
        fn now(&self) -> i64 {
            *self.0.lock().unwrap()
        }
    }

    struct CountingExecutor {
        runs: AtomicUsize,
        fail: bool,
    }

    #[async_trait]
    impl JobExecutor for CountingExecutor {
        async fn execute(&self, _job: ScheduledJob) -> Result<String> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                bail!("boom");
            }
            Ok("ok".to_string())
        }
    }

    struct BlockingByIdExecutor {
        blocked_id: String,
        started: std::sync::Mutex<Vec<String>>,
        notify: Notify,
    }

    impl BlockingByIdExecutor {
        fn new(blocked_id: impl Into<String>) -> Arc<Self> {
            Arc::new(Self {
                blocked_id: blocked_id.into(),
                started: std::sync::Mutex::new(Vec::new()),
                notify: Notify::new(),
            })
        }

        fn started(&self) -> Vec<String> {
            self.started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    #[async_trait]
    impl JobExecutor for BlockingByIdExecutor {
        async fn execute(&self, job: ScheduledJob) -> Result<String> {
            self.started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(job.id.clone());
            if job.id == self.blocked_id {
                self.notify.notified().await;
            }
            Ok(format!("ok {}", job.id))
        }
    }

    struct AdvancingExecutor {
        runs: AtomicUsize,
        clock: Arc<ManualClock>,
        advance_seconds: i64,
    }

    #[async_trait]
    impl JobExecutor for AdvancingExecutor {
        async fn execute(&self, _job: ScheduledJob) -> Result<String> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            let now = self.clock.now();
            self.clock.set(now.saturating_add(self.advance_seconds));
            Ok("advanced".to_string())
        }
    }

    struct GatedExecutor {
        started: std::sync::Mutex<Vec<String>>,
        active: AtomicUsize,
        max_active: AtomicUsize,
        gate: Notify,
    }

    impl GatedExecutor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                started: std::sync::Mutex::new(Vec::new()),
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
                gate: Notify::new(),
            })
        }

        fn started(&self) -> Vec<String> {
            self.started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    struct ActiveJob<'a>(&'a GatedExecutor);

    impl Drop for ActiveJob<'_> {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl JobExecutor for GatedExecutor {
        async fn execute(&self, job: ScheduledJob) -> Result<String> {
            self.started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(job.id.clone());
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            let _active = ActiveJob(self);
            self.gate.notified().await;
            Ok(format!("ok {}", job.id))
        }
    }

    fn scheduler(
        now: i64,
        fail: bool,
    ) -> (DaemonScheduler, Arc<ManualClock>, Arc<CountingExecutor>) {
        let db = Db::open_in_memory().unwrap();
        scheduler_with_db(db, now, fail)
    }

    fn scheduler_with_db(
        db: Db,
        now: i64,
        fail: bool,
    ) -> (DaemonScheduler, Arc<ManualClock>, Arc<CountingExecutor>) {
        let clock = ManualClock::new(now);
        let executor = Arc::new(CountingExecutor {
            runs: AtomicUsize::new(0),
            fail,
        });
        (
            DaemonScheduler::new(db, clock.clone(), executor.clone()),
            clock,
            executor,
        )
    }

    #[derive(Default)]
    struct FakePromptRunner {
        runs: AtomicUsize,
    }

    #[async_trait]
    impl ScheduledPromptRunner for FakePromptRunner {
        async fn run_prompt_turn(
            &self,
            db: &Db,
            job: &ScheduledJob,
            session_id: uuid::Uuid,
            assistant: &str,
            prompt: String,
            _env_snapshot: crate::env_snapshot::EnvSnapshot,
        ) -> Result<String> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            assert_eq!(job.owner, format!("assistant:{assistant}"));
            assert_eq!(prompt, "summarize the workspace");
            let session = db
                .get_session(session_id)?
                .expect("production executor creates session before running turn");
            assert_eq!(session.assistant_name.as_deref(), Some(assistant));
            assert_eq!(session.active_agent, assistant);
            db.insert_session_event(
                session_id,
                crate::db::session_log::SessionEventKind::Notice,
                Some(assistant),
                None,
                &json!({ "text": "fake scheduled turn completed", "source": "test_prompt_runner" }),
            )?;
            Ok(format!("fake scheduled turn completed for `{assistant}`"))
        }
    }

    #[derive(Default)]
    struct RecordingSleeper {
        calls: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
        wakes: std::sync::Mutex<Vec<Option<i64>>>,
    }

    impl RecordingSleeper {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn max_active(&self) -> usize {
            self.max_active.load(Ordering::SeqCst)
        }

        fn last_wake(&self) -> Option<i64> {
            self.wakes.lock().unwrap().last().copied().flatten()
        }
    }

    struct ActiveSleep<'a>(&'a RecordingSleeper);

    impl Drop for ActiveSleep<'_> {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl SchedulerSleeper for RecordingSleeper {
        async fn sleep_until(&self, _now: i64, wake_at: Option<i64>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            self.wakes.lock().unwrap().push(wake_at);
            let _active = ActiveSleep(self);
            std::future::pending::<()>().await;
        }
    }

    async fn wait_for_sleeper_calls(sleeper: &RecordingSleeper, expected: usize) {
        for _ in 0..100 {
            if sleeper.calls() >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "expected at least {expected} scheduler sleep calls, saw {}",
            sleeper.calls()
        );
    }

    async fn wait_for_executor_runs(executor: &CountingExecutor, expected: usize) {
        for _ in 0..100 {
            if executor.runs.load(Ordering::SeqCst) >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "expected at least {expected} executor runs, saw {}",
            executor.runs.load(Ordering::SeqCst)
        );
    }

    async fn wait_for_started_jobs(executor: &BlockingByIdExecutor, expected: usize) {
        for _ in 0..100 {
            if executor.started().len() >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "expected at least {expected} started jobs, saw {:?}",
            executor.started()
        );
    }

    async fn wait_for_gated_started_jobs(executor: &GatedExecutor, expected: usize) {
        for _ in 0..100 {
            if executor.started().len() >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "expected at least {expected} gated jobs, saw {:?}",
            executor.started()
        );
    }

    async fn wait_for_job_result(scheduler: &DaemonScheduler, id: &str) -> ScheduledJobSummary {
        for _ in 0..100 {
            let jobs = scheduler.list_jobs(None).unwrap();
            if let Some(job) = jobs
                .into_iter()
                .find(|job| job.id == id && job.last_result.is_some())
            {
                return job;
            }
            tokio::task::yield_now().await;
        }
        panic!("expected job `{id}` to record a result");
    }

    async fn wait_for_job_failure_count(
        scheduler: &DaemonScheduler,
        id: &str,
        expected: u32,
    ) -> ScheduledJobSummary {
        for _ in 0..100 {
            let jobs = scheduler.list_jobs(None).unwrap();
            if let Some(job) = jobs
                .into_iter()
                .find(|job| job.id == id && job.failure_count == expected)
            {
                return job;
            }
            tokio::task::yield_now().await;
        }
        panic!("expected job `{id}` failure_count to reach {expected}");
    }

    fn callback_job(id: &str, schedule: ScheduledJobSchedule) -> ScheduledJobCreate {
        ScheduledJobCreate {
            id: id.to_string(),
            owner: "system:test".to_string(),
            schedule,
            payload: ScheduledJobPayload::Callback {
                subsystem: "test".to_string(),
            },
            enabled: true,
            missed_run_policy: MissedRunPolicy::Skip,
        }
    }

    fn run_prompt_job(
        id: &str,
        assistant: &str,
        project_root: &std::path::Path,
    ) -> ScheduledJobCreate {
        ScheduledJobCreate {
            id: id.to_string(),
            owner: format!("assistant:{assistant}"),
            schedule: ScheduledJobSchedule::Once { at: 1_000 },
            payload: ScheduledJobPayload::RunPrompt {
                assistant: assistant.to_string(),
                prompt: "summarize the workspace".to_string(),
                project_root: project_root.to_string_lossy().into_owned(),
            },
            enabled: true,
            missed_run_policy: MissedRunPolicy::Skip,
        }
    }

    fn production_registry(db: Db) -> SessionRegistry {
        let locks = Arc::new(LockManager::from_db(db.clone()).expect("locks"));
        SessionRegistry::new(
            db,
            locks,
            ShutdownSignal::new(),
            None,
            ConfigSource::fixed(ProvidersConfig::default(), ExtendedConfig::default()),
        )
    }

    fn create_helper_assistant(db: &Db, home_dir: std::path::PathBuf) {
        create_assistant(
            db,
            CreateAssistantSpec {
                name: "helper-bot".to_string(),
                description: "Helper bot".to_string(),
                mode: AgentMode::Primary,
                tools: Some(vec!["read".to_string()]),
                tool_tiers: std::collections::BTreeMap::new(),
                model: None,
                prompt: "You help with scheduled workspace maintenance.".to_string(),
                home_dir,
            },
        )
        .unwrap();
    }

    #[test]
    fn scheduler_next_run_matrix() {
        assert_eq!(
            compute_next_run(
                &ScheduledJobSchedule::Every { seconds: 60 },
                1_000,
                None,
                1_000,
                1_000,
                MissedRunPolicy::Skip,
                None,
            )
            .unwrap(),
            Some(1_060)
        );
        assert_eq!(
            compute_next_run(
                &ScheduledJobSchedule::Once { at: 900 },
                1_000,
                None,
                900,
                1_000,
                MissedRunPolicy::RunOnceOnStart,
                Some(900),
            )
            .unwrap(),
            Some(1_000)
        );
        assert_eq!(
            compute_next_run(
                &ScheduledJobSchedule::Once { at: 900 },
                1_000,
                None,
                900,
                1_000,
                MissedRunPolicy::Skip,
                Some(900),
            )
            .unwrap(),
            None
        );
        assert_eq!(
            compute_next_run(
                &ScheduledJobSchedule::Idle {
                    min_idle_seconds: 120,
                    max_age_seconds: 600,
                },
                1_000,
                Some(800),
                0,
                950,
                MissedRunPolicy::Skip,
                None,
            )
            .unwrap(),
            Some(1_070)
        );
        assert_eq!(
            compute_next_run(
                &ScheduledJobSchedule::Cron {
                    expr: "@hourly".to_string()
                },
                1_704_067_230,
                None,
                1_704_067_230,
                1_704_067_230,
                MissedRunPolicy::Skip,
                None,
            )
            .unwrap(),
            Some(1_704_070_800)
        );
    }

    #[test]
    fn cron_product_grammar_rejects_broader_library_syntax() {
        assert!(
            validate_schedule(&ScheduledJobSchedule::Cron {
                expr: "*/5 * * * *".into()
            })
            .is_ok()
        );
        assert!(
            validate_schedule(&ScheduledJobSchedule::Cron {
                expr: "1/5 * * * *".into()
            })
            .is_err()
        );
        assert!(
            validate_schedule(&ScheduledJobSchedule::Cron {
                expr: "1-10/2 * * * *".into()
            })
            .is_err()
        );
        assert!(
            validate_schedule(&ScheduledJobSchedule::Cron {
                expr: "* * * * * *".into()
            })
            .is_err()
        );
        assert!(
            validate_schedule(&ScheduledJobSchedule::Cron {
                expr: "0 0 L * *".into()
            })
            .is_err()
        );
        assert!(
            validate_schedule(&ScheduledJobSchedule::Cron {
                expr: "@reboot".into()
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn scheduler_survives_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("scheduler.db");
        let db = Db::open(&db_path).unwrap();
        let (scheduler, _, _) = scheduler_with_db(db, 1_000, false);
        scheduler
            .create_job(callback_job(
                "job-every",
                ScheduledJobSchedule::Every { seconds: 10 },
            ))
            .unwrap();
        let mut catch_up = callback_job("job-once", ScheduledJobSchedule::Once { at: 1_010 });
        catch_up.missed_run_policy = MissedRunPolicy::RunOnceOnStart;
        scheduler.create_job(catch_up).unwrap();

        drop(scheduler);
        let reopened = Db::open(&db_path).unwrap();
        let (restarted, clock, executor) = scheduler_with_db(reopened.clone(), 1_020, false);
        clock.set(1_020);
        restarted.recompute_after_start().unwrap();
        let jobs = restarted.list_jobs(None).unwrap();
        assert_eq!(jobs.len(), 2);
        assert_eq!(
            jobs.iter()
                .find(|job| job.id == "job-every")
                .and_then(|job| job.next_run_at),
            Some(1_030),
            "skip policy should skip the missed interval while the daemon was down"
        );
        assert_eq!(
            jobs.iter()
                .find(|job| job.id == "job-once")
                .and_then(|job| job.next_run_at),
            Some(1_020),
            "run_once_on_start should catch up one missed one-shot"
        );
        restarted.run_due_once().await.unwrap();
        wait_for_executor_runs(&executor, 1).await;
        assert_eq!(executor.runs.load(Ordering::SeqCst), 1);
        assert!(
            restarted
                .list_jobs(None)
                .unwrap()
                .iter()
                .any(|job| job.id == "job-once" && job.last_run_at == Some(1_020))
        );
        drop(restarted);

        let reopened_again = Db::open(&db_path).unwrap();
        let (restarted_again, clock, executor) = scheduler_with_db(reopened_again, 1_030, false);
        restarted_again.recompute_after_start().unwrap();
        clock.set(1_030);
        restarted_again.run_due_once().await.unwrap();
        wait_for_executor_runs(&executor, 1).await;
        assert_eq!(executor.runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn scheduler_idle_gate() {
        let (scheduler, clock, executor) = scheduler(1_000, false);
        scheduler
            .create_job(callback_job(
                "job-idle",
                ScheduledJobSchedule::Idle {
                    min_idle_seconds: 120,
                    max_age_seconds: 300,
                },
            ))
            .unwrap();
        clock.set(1_250);
        scheduler.record_user_activity().unwrap();
        scheduler.run_due_once().await.unwrap();
        assert_eq!(executor.runs.load(Ordering::SeqCst), 0);
        clock.set(1_370);
        scheduler.recompute_after_start().unwrap();
        scheduler.run_due_once().await.unwrap();
        wait_for_executor_runs(&executor, 1).await;
        assert_eq!(executor.runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn hung_job_does_not_block_other_jobs() {
        let db = Db::open_in_memory().unwrap();
        let clock = ManualClock::new(1_000);
        let executor = BlockingByIdExecutor::new("job-a");
        let scheduler = DaemonScheduler::new(db, clock.clone(), executor.clone());
        scheduler
            .create_job(callback_job(
                "job-a",
                ScheduledJobSchedule::Every { seconds: 1 },
            ))
            .unwrap();
        scheduler
            .create_job(callback_job(
                "job-b",
                ScheduledJobSchedule::Every { seconds: 1 },
            ))
            .unwrap();

        clock.set(1_001);
        scheduler.run_due_once().await.unwrap();
        wait_for_started_jobs(&executor, 2).await;
        assert_eq!(executor.started(), vec!["job-a", "job-b"]);

        scheduler
            .create_job(callback_job(
                "job-c",
                ScheduledJobSchedule::Every { seconds: 10 },
            ))
            .unwrap();
        assert!(
            scheduler
                .list_jobs(None)
                .unwrap()
                .iter()
                .any(|job| job.id == "job-c")
        );
    }

    #[tokio::test]
    async fn concurrency_is_bounded_and_nothing_is_dropped() {
        let db = Db::open_in_memory().unwrap();
        let clock = ManualClock::new(1_000);
        let executor = GatedExecutor::new();
        let scheduler = DaemonScheduler::new(db, clock.clone(), executor.clone());
        let total = MAX_CONCURRENT_JOBS + 2;
        for i in 0..total {
            scheduler
                .create_job(callback_job(
                    &format!("job-{i:02}"),
                    ScheduledJobSchedule::Every { seconds: 1 },
                ))
                .unwrap();
        }

        clock.set(1_001);
        scheduler.run_due_once().await.unwrap();
        wait_for_gated_started_jobs(&executor, MAX_CONCURRENT_JOBS).await;
        assert_eq!(executor.started().len(), MAX_CONCURRENT_JOBS);
        assert_eq!(
            executor.max_active.load(Ordering::SeqCst),
            MAX_CONCURRENT_JOBS
        );

        executor.gate.notify_waiters();
        wait_for_gated_started_jobs(&executor, total).await;
        executor.gate.notify_waiters();
        for i in 0..total {
            let id = format!("job-{i:02}");
            wait_for_job_result(&scheduler, &id).await;
        }
        assert!(executor.max_active.load(Ordering::SeqCst) <= MAX_CONCURRENT_JOBS);
        assert_eq!(
            executor.started(),
            (0..total)
                .map(|i| format!("job-{i:02}"))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn next_run_computed_from_completion_not_start() {
        let db = Db::open_in_memory().unwrap();
        let clock = ManualClock::new(1_000);
        let executor = Arc::new(AdvancingExecutor {
            runs: AtomicUsize::new(0),
            clock: clock.clone(),
            advance_seconds: 90,
        });
        let scheduler = DaemonScheduler::new(db, clock.clone(), executor.clone());
        scheduler
            .create_job(callback_job(
                "job-slow",
                ScheduledJobSchedule::Every { seconds: 60 },
            ))
            .unwrap();

        clock.set(1_060);
        scheduler.run_due_once().await.unwrap();
        let job = wait_for_job_result(&scheduler, "job-slow").await;
        let result = job.last_result.expect("slow result");
        assert_eq!(result.finished_at, 1_150);
        assert_eq!(job.last_run_at, Some(1_150));
        assert_eq!(job.next_run_at, Some(1_210));
    }

    #[tokio::test]
    async fn idle_max_age_overrides_min_idle() {
        let (scheduler, clock, executor) = scheduler(1_000, false);
        scheduler
            .create_job(callback_job(
                "job-idle-max-age",
                ScheduledJobSchedule::Idle {
                    min_idle_seconds: 300,
                    max_age_seconds: 60,
                },
            ))
            .unwrap();

        clock.set(1_059);
        scheduler.record_user_activity().unwrap();
        clock.set(1_060);
        scheduler.run_due_once().await.unwrap();
        wait_for_executor_runs(&executor, 1).await;
        assert_eq!(executor.runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn manual_and_scheduled_runs_are_mutually_exclusive() {
        let db = Db::open_in_memory().unwrap();
        let clock = ManualClock::new(1_000);
        let executor = BlockingByIdExecutor::new("job-blocked");
        let scheduler = DaemonScheduler::new(db, clock.clone(), executor.clone());
        scheduler
            .create_job(callback_job(
                "job-blocked",
                ScheduledJobSchedule::Every { seconds: 1 },
            ))
            .unwrap();

        clock.set(1_001);
        scheduler.run_due_once().await.unwrap();
        wait_for_started_jobs(&executor, 1).await;
        let error = scheduler.run_job_by_id("job-blocked").unwrap_err();
        assert!(error.to_string().contains("already running"), "{error:#}");
    }

    #[tokio::test]
    async fn run_now_does_not_block_the_caller() {
        let db = Db::open_in_memory().unwrap();
        let clock = ManualClock::new(1_000);
        let executor = BlockingByIdExecutor::new("job-blocked");
        let scheduler = DaemonScheduler::new(db, clock, executor.clone());
        scheduler
            .create_job(callback_job(
                "job-blocked",
                ScheduledJobSchedule::Every { seconds: 60 },
            ))
            .unwrap();

        scheduler.run_job_by_id("job-blocked").unwrap();
        wait_for_started_jobs(&executor, 1).await;
        assert!(scheduler.is_in_flight("job-blocked"));
    }

    #[tokio::test]
    async fn manual_failures_count_toward_disable() {
        let (scheduler, _clock, executor) = scheduler(1_000, true);
        scheduler
            .create_job(callback_job(
                "job-manual-fail",
                ScheduledJobSchedule::Every { seconds: 60 },
            ))
            .unwrap();

        let mut job = scheduler.list_jobs(None).unwrap().remove(0);
        for expected in 1..=MAX_FAILURES {
            scheduler.run_job_by_id("job-manual-fail").unwrap();
            job = wait_for_job_failure_count(&scheduler, "job-manual-fail", expected).await;
        }
        assert_eq!(executor.runs.load(Ordering::SeqCst), MAX_FAILURES as usize);
        assert!(!job.enabled);
        assert!(job.disabled_notice.unwrap().contains("disabled"));
    }

    #[tokio::test(start_paused = true)]
    async fn callback_watchdog_times_out_and_records_failure() {
        let db = Db::open_in_memory().unwrap();
        let registry = production_registry(db.clone());
        let executor = Arc::new(ProductionJobExecutor::new(db.clone(), registry));
        let clock = ManualClock::new(1_000);
        let scheduler = DaemonScheduler::new(db, clock.clone(), executor.clone());
        executor.register_callback("test", |_job| async {
            std::future::pending::<Result<String>>().await
        });
        scheduler
            .create_job(callback_job(
                "job-timeout",
                ScheduledJobSchedule::Every { seconds: 1 },
            ))
            .unwrap();

        clock.set(1_001);
        scheduler.run_due_once().await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(CALLBACK_TIMEOUT).await;
        let job = wait_for_job_failure_count(&scheduler, "job-timeout", 1).await;
        let result = job.last_result.expect("timeout result");
        assert!(!result.ok);
        assert!(result.summary.contains("timed out"), "{}", result.summary);
    }

    #[tokio::test]
    async fn inflight_result_does_not_resurrect_deleted_job() {
        let db = Db::open_in_memory().unwrap();
        let clock = ManualClock::new(1_000);
        let executor = BlockingByIdExecutor::new("job-delete");
        let scheduler = DaemonScheduler::new(db, clock, executor.clone());
        scheduler
            .create_job(callback_job(
                "job-delete",
                ScheduledJobSchedule::Every { seconds: 60 },
            ))
            .unwrap();

        scheduler.run_job_by_id("job-delete").unwrap();
        wait_for_started_jobs(&executor, 1).await;
        assert!(scheduler.delete_job("job-delete").unwrap());
        executor.notify.notify_waiters();
        for _ in 0..100 {
            if scheduler.list_jobs(None).unwrap().is_empty() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("deleted in-flight job was resurrected");
    }

    #[tokio::test]
    async fn inflight_result_does_not_reenable_disabled_job() {
        let db = Db::open_in_memory().unwrap();
        let clock = ManualClock::new(1_000);
        let executor = BlockingByIdExecutor::new("job-disable");
        let scheduler = DaemonScheduler::new(db, clock, executor.clone());
        scheduler
            .create_job(callback_job(
                "job-disable",
                ScheduledJobSchedule::Every { seconds: 60 },
            ))
            .unwrap();

        scheduler.run_job_by_id("job-disable").unwrap();
        wait_for_started_jobs(&executor, 1).await;
        scheduler.set_enabled("job-disable", false).unwrap();
        executor.notify.notify_waiters();
        let job = wait_for_job_result(&scheduler, "job-disable").await;
        assert!(!job.enabled);
    }

    #[tokio::test]
    async fn scheduler_failure_backoff_disable() {
        let (scheduler, clock, executor) = scheduler(1_000, true);
        scheduler
            .create_job(callback_job(
                "job-fail",
                ScheduledJobSchedule::Every { seconds: 1 },
            ))
            .unwrap();
        clock.set(1_001);
        scheduler.run_due_once().await.unwrap();
        wait_for_executor_runs(&executor, 1).await;
        let mut job = wait_for_job_result(&scheduler, "job-fail").await;
        assert_eq!(executor.runs.load(Ordering::SeqCst), 1);
        assert_eq!(job.failure_count, 1);
        let mut backoff = job.backoff_until.expect("first failure backs off");
        assert!(backoff > 1_001);

        clock.set(backoff - 1);
        scheduler.run_due_once().await.unwrap();
        assert_eq!(
            executor.runs.load(Ordering::SeqCst),
            1,
            "due jobs must not fire while backoff_until is still in the future"
        );

        for expected_failure in 2..=MAX_FAILURES {
            clock.set(backoff);
            scheduler.run_due_once().await.unwrap();
            wait_for_executor_runs(&executor, expected_failure as usize).await;
            job = wait_for_job_result(&scheduler, "job-fail").await;
            assert_eq!(job.failure_count, expected_failure);
            if expected_failure < MAX_FAILURES {
                let next_backoff = job.backoff_until.expect("failure backs off");
                assert!(next_backoff > backoff);
                assert_eq!(scheduler.next_wake().unwrap(), Some(next_backoff));
                backoff = next_backoff;
            }
        }
        assert_eq!(executor.runs.load(Ordering::SeqCst), MAX_FAILURES as usize);
        assert!(!job.enabled);
        assert!(job.disabled_notice.unwrap().contains("disabled"));
        let job = scheduler.set_enabled("job-fail", true).unwrap().unwrap();
        assert!(job.enabled);
        assert_eq!(job.failure_count, 0);
        assert!(job.backoff_until.is_none());
        assert!(job.disabled_notice.is_none());
    }

    #[tokio::test]
    async fn scheduler_many_jobs_use_single_timer() {
        let (scheduler, _clock, _executor) = scheduler(1_000, false);
        let scheduler = Arc::new(scheduler);
        for i in 0..100 {
            scheduler
                .create_job(callback_job(
                    &format!("job-{i}"),
                    ScheduledJobSchedule::Every {
                        seconds: 60 + i as u64,
                    },
                ))
                .unwrap();
        }
        assert_eq!(scheduler.timeline_len(), 100);
        assert_eq!(scheduler.next_wake().unwrap(), Some(1_060));

        let sleeper = Arc::new(RecordingSleeper::default());
        let shutdown = crate::daemon::shutdown::ShutdownSignal::new();
        let handle = scheduler
            .clone()
            .start_with_sleeper(shutdown.clone(), sleeper.clone(), None);
        wait_for_sleeper_calls(&sleeper, 1).await;
        assert_eq!(sleeper.last_wake(), Some(1_060));
        assert_eq!(sleeper.max_active(), 1);

        handle
            .create_job(callback_job(
                "job-earlier",
                ScheduledJobSchedule::Every { seconds: 5 },
            ))
            .unwrap();
        wait_for_sleeper_calls(&sleeper, 2).await;
        assert_eq!(handle.list_jobs(None).unwrap().len(), 101);
        assert_eq!(handle.wake_generation(), 1);
        assert_eq!(handle.scheduler.next_wake().unwrap(), Some(1_005));
        assert_eq!(sleeper.last_wake(), Some(1_005));
        assert_eq!(sleeper.max_active(), 1);
        shutdown.begin_drain();
    }

    #[tokio::test]
    async fn scheduler_callback_registry_dispatches_registered_hooks() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let registry = production_registry(db.clone());
        let executor = Arc::new(ProductionJobExecutor::new(db.clone(), registry));
        let clock = ManualClock::new(1_000);
        let scheduler = Arc::new(DaemonScheduler::new(db, clock.clone(), executor.clone()));
        let shutdown = crate::daemon::shutdown::ShutdownSignal::new();
        let handle = scheduler.clone().start_with_sleeper(
            shutdown.clone(),
            Arc::new(RecordingSleeper::default()),
            Some(executor.callback_registry()),
        );
        let runs = Arc::new(AtomicUsize::new(0));
        let callback_runs = runs.clone();
        handle
            .register_callback("test", move |job| {
                let callback_runs = callback_runs.clone();
                async move {
                    callback_runs.fetch_add(1, Ordering::SeqCst);
                    Ok(format!("hook ran {}", job.id))
                }
            })
            .unwrap();
        handle
            .create_job(callback_job(
                "job-callback",
                ScheduledJobSchedule::Every { seconds: 1 },
            ))
            .unwrap();
        clock.set(1_001);
        scheduler.run_due_once().await.unwrap();
        let job = wait_for_job_result(&scheduler, "job-callback").await;
        let result = job.last_result.expect("callback result");
        assert!(result.ok);
        assert_eq!(result.summary, "hook ran job-callback");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        shutdown.begin_drain();
        drop(tmp);
    }

    #[tokio::test]
    async fn scheduler_manual_run_preserves_schedule() {
        let (scheduler, clock, executor) = scheduler(1_000, false);
        scheduler
            .create_job(callback_job(
                "job-once",
                ScheduledJobSchedule::Once { at: 2_000 },
            ))
            .unwrap();
        scheduler.run_job_by_id("job-once").unwrap();
        let job = wait_for_job_result(&scheduler, "job-once").await;
        assert!(job.last_result.as_ref().unwrap().ok);
        assert_eq!(executor.runs.load(Ordering::SeqCst), 1);
        assert_eq!(job.last_run_at, Some(1_000));
        assert_eq!(job.next_run_at, Some(2_000));
        assert!(job.enabled);

        clock.set(2_000);
        scheduler.run_due_once().await.unwrap();
        wait_for_executor_runs(&executor, 2).await;
        assert_eq!(executor.runs.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn scheduler_runprompt_owner_validation() {
        let mut job = ScheduledJobCreate {
            id: "job-run".to_string(),
            owner: "assistant:alice".to_string(),
            schedule: ScheduledJobSchedule::Every { seconds: 60 },
            payload: ScheduledJobPayload::RunPrompt {
                assistant: "bob".to_string(),
                prompt: "hi".to_string(),
                project_root: "/tmp/project".to_string(),
            },
            enabled: true,
            missed_run_policy: MissedRunPolicy::Skip,
        };
        assert!(validate_job_create(&job).is_err());
        job.owner = "assistant:bob".to_string();
        assert!(validate_job_create(&job).is_ok());

        let mut callback =
            callback_job("job-callback", ScheduledJobSchedule::Every { seconds: 60 });
        callback.owner = "system:other".to_string();
        assert!(validate_job_create(&callback).is_err());
        callback.owner = "system:test".to_string();
        assert!(validate_job_create(&callback).is_ok());
    }

    #[tokio::test]
    async fn create_rejects_unknown_assistant() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let scheduler = DaemonScheduler::new(
            db.clone(),
            ManualClock::new(1_000),
            Arc::new(CountingExecutor {
                runs: AtomicUsize::new(0),
                fail: false,
            }),
        );
        let project_root = tmp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let error = scheduler
            .create_job(run_prompt_job("job-missing", "helper-bot", &project_root))
            .unwrap_err();
        assert!(error.to_string().contains("helper-bot"), "{error:#}");

        create_helper_assistant(&db, tmp.path().join("assistants/helper-bot"));
        scheduler
            .create_job(run_prompt_job("job-present", "helper-bot", &project_root))
            .unwrap();
    }

    #[tokio::test]
    async fn scheduler_runprompt_creates_owned_session() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let project_root = tmp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        db.set_workspace_trust(&project_root, WorkspaceTrustMode::Trust)
            .unwrap();
        create_helper_assistant(&db, tmp.path().join("assistants/helper-bot"));
        let runner = Arc::new(FakePromptRunner::default());
        let scheduler = DaemonScheduler::new(
            db.clone(),
            ManualClock::new(1_000),
            Arc::new(ProductionJobExecutor::with_prompt_runner(
                db.clone(),
                runner.clone(),
            )),
        );
        scheduler
            .create_job(run_prompt_job("job-run", "helper-bot", &project_root))
            .unwrap();

        scheduler.run_job_by_id("job-run").unwrap();
        let job = wait_for_job_result(&scheduler, "job-run").await;
        let result = job.last_result.expect("scheduled prompt result");

        let sessions = db.list_sessions(false, 10).unwrap();
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(session.assistant_name.as_deref(), Some("helper-bot"));
        assert_eq!(session.active_agent, "helper-bot");
        assert_eq!(session.project_root, project_root.to_string_lossy());
        assert!(result.ok);
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1);
        assert!(
            result
                .summary
                .contains("fake scheduled turn completed for `helper-bot`")
        );
        assert!(
            !db.list_session_events(session.session_id)
                .unwrap()
                .is_empty(),
            "prompt runner should persist session events"
        );
    }

    #[tokio::test]
    async fn scheduler_respects_trust() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let project_root = tmp.path().join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        db.set_workspace_trust(&project_root, WorkspaceTrustMode::Untrusted)
            .unwrap();
        create_helper_assistant(&db, tmp.path().join("assistants/helper-bot"));
        let registry = production_registry(db.clone());
        let scheduler = DaemonScheduler::new(
            db.clone(),
            ManualClock::new(1_000),
            Arc::new(ProductionJobExecutor::new(db.clone(), registry)),
        );
        scheduler
            .create_job(run_prompt_job("job-trust", "helper-bot", &project_root))
            .unwrap();

        scheduler.run_job_by_id("job-trust").unwrap();
        let job = wait_for_job_result(&scheduler, "job-trust").await;
        let result = job.last_result.expect("trust refusal result");

        assert!(!result.ok);
        assert!(result.summary.contains("untrusted"), "{}", result.summary);
        let sessions = db.list_sessions(false, 10).unwrap();
        assert!(
            sessions.is_empty(),
            "trust refusal must not leave an orphan session row"
        );
    }
}
