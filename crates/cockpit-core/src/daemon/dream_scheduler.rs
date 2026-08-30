//! Daemon-owned knowledge dream scheduling.
//!
//! This is intentionally separate from `daemon::scheduler`: that subsystem
//! runs session-scoped, agent-created jobs. A dream schedule belongs to one
//! configured knowledge base on this installation and consumes its complete
//! per-consumer ledger snapshot in one headless Dream turn.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use chrono::{Datelike, Local, TimeZone, Utc};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, oneshot};

use crate::config::extended::{KnowledgeBaseRegistryEntry, KnowledgeBaseSource};
use crate::config::providers::ActiveModelRef;
use crate::daemon::config_source::ConfigSource;
use crate::daemon::proto::{EnvSnapshotSource, QueueDeliveryClass, SessionEntryMode};
use crate::daemon::registry::SessionRegistry;
use crate::daemon::session_worker::{SessionWork, TurnOutcome};
use crate::db::Db;
use crate::db::session_search::HistoryCallerTrust;
use crate::env_snapshot::EnvSnapshot;
use crate::knowledge::dream::{history_caller_trust, resolve_dream_model};

const POLL_INTERVAL: Duration = Duration::from_secs(60);
const DREAM_TURN_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const DEFAULT_JITTER_SECONDS: i64 = 60 * 60;

#[derive(Clone)]
pub(crate) struct DreamScheduler {
    db: Db,
    registry: SessionRegistry,
    config_source: ConfigSource,
    workspace_root: PathBuf,
    in_flight: Arc<Mutex<HashSet<String>>>,
}

impl DreamScheduler {
    pub(crate) fn spawn(
        db: Db,
        registry: SessionRegistry,
        config_source: ConfigSource,
        workspace_root: PathBuf,
        shutdown: crate::daemon::shutdown::ShutdownSignal,
    ) -> tokio::task::JoinHandle<()> {
        let scheduler = Self {
            db,
            registry,
            config_source,
            workspace_root,
            in_flight: Arc::new(Mutex::new(HashSet::new())),
        };
        tokio::spawn(async move { scheduler.run(shutdown).await })
    }

    async fn run(self, shutdown: crate::daemon::shutdown::ShutdownSignal) {
        let mut shutdown_rx = shutdown.subscribe();
        loop {
            if shutdown.is_draining() {
                return;
            }
            if let Err(error) = self.run_due_once().await {
                tracing::warn!(error = %error, "knowledge dream scheduler pass failed");
            }
            tokio::select! {
                _ = tokio::time::sleep(POLL_INTERVAL) => {}
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || shutdown.is_draining() {
                        return;
                    }
                }
            }
        }
    }

    async fn run_due_once(&self) -> Result<()> {
        let trust_policy = crate::config::trust::resolve_workspace_trust_policy_from_db(
            &self.db,
            &self.workspace_root,
        )
        .await?;
        let (providers, extended) = self
            .config_source
            .load_effective_for_daemon(&self.workspace_root, &trust_policy)?;
        let consumer_id = self
            .db
            .ensure_installation_identity()
            .await?
            .as_hex()
            .to_owned();
        let now = Utc::now().timestamp_millis();

        for knowledge_base in &extended.knowledge_bases {
            if !matches!(&knowledge_base.source, KnowledgeBaseSource::Local { .. }) {
                // TODO(hosted dream service): dispatch configured remote KB
                // schedules through the hosted sink once it owns remote writes.
                continue;
            }
            let last_scheduled = self
                .db
                .knowledge_base_last_scheduled_at(&knowledge_base.id, &consumer_id)
                .await?;
            if !is_due(
                knowledge_base.dream_schedule.as_deref(),
                last_scheduled,
                now,
                &knowledge_base.id,
                &consumer_id,
            )? {
                continue;
            }
            if !self.claim_in_flight(&knowledge_base.id).await {
                continue;
            }

            let model = match resolve_dream_model(knowledge_base, &extended, &providers) {
                Ok(model) => model,
                Err(error) => {
                    self.release_in_flight(&knowledge_base.id).await;
                    tracing::warn!(knowledge_base_id = %knowledge_base.id, error = %error, "knowledge dream schedule has no usable model");
                    continue;
                }
            };
            let caller_trust = history_caller_trust(&model, &providers);
            let sources = match self
                .db
                .undreamed_sessions_for_knowledge_base(
                    &knowledge_base.id,
                    &consumer_id,
                    caller_trust,
                )
                .await
            {
                Ok(sources) => sources,
                Err(error) => {
                    self.release_in_flight(&knowledge_base.id).await;
                    tracing::warn!(knowledge_base_id = %knowledge_base.id, error = %error, "loading scheduled knowledge dream sources failed");
                    continue;
                }
            };
            if sources.is_empty() {
                // A scheduled empty pass is still observable, but does not
                // create a model session or invoke the dream agent.
                let record = self
                    .db
                    .record_knowledge_dream_schedule_fire(
                        &knowledge_base.id,
                        &consumer_id,
                        now,
                        Some(now),
                    )
                    .await;
                self.release_in_flight(&knowledge_base.id).await;
                record?;
                continue;
            }

            let scheduler = self.clone();
            let knowledge_base = knowledge_base.clone();
            let consumer_id = consumer_id.clone();
            let model = ActiveModelRef {
                provider: model.provider,
                model: model.model,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            };
            tokio::spawn(async move {
                let result = scheduler
                    .run_dream_turn(&knowledge_base, model, caller_trust)
                    .await;
                if let Err(error) = &result {
                    tracing::warn!(knowledge_base_id = %knowledge_base.id, error = %error, "scheduled knowledge dream failed");
                }
                if let Err(error) = scheduler
                    .db
                    .record_knowledge_dream_schedule_fire(
                        &knowledge_base.id,
                        &consumer_id,
                        now,
                        None,
                    )
                    .await
                {
                    tracing::warn!(knowledge_base_id = %knowledge_base.id, error = %error, "recording scheduled knowledge dream fire failed");
                }
                scheduler.release_in_flight(&knowledge_base.id).await;
            });
        }
        Ok(())
    }

    async fn run_dream_turn(
        &self,
        knowledge_base: &KnowledgeBaseRegistryEntry,
        model: ActiveModelRef,
        caller_trust: HistoryCallerTrust,
    ) -> Result<()> {
        let handle = self
            .registry
            .attach(
                None,
                Some(self.workspace_root.clone()),
                Some(model.clone()),
                false,
                Some(&model),
                EnvSnapshot::from_process(EnvSnapshotSource::DaemonStart),
                SessionEntryMode::Code,
            )
            .await
            .context("starting scheduled Dream session")?;
        let (agent_settled_tx, agent_settled_rx) = oneshot::channel();
        handle
            .send_work(SessionWork::SetAgent {
                name: "Dream".to_string(),
                durable_selection_committed: false,
                respond_to: agent_settled_tx,
            })
            .await
            .context("selecting Dream agent for scheduled knowledge dream")?;
        agent_settled_rx
            .await
            .context("scheduled Dream session dropped agent selection")?
            .map_err(anyhow::Error::msg)?;

        let (respond_to, response_rx) = oneshot::channel();
        handle
            .send_work(SessionWork::UserMessage {
                submission: Box::new(crate::engine::message::UserSubmission {
                    origin: crate::engine::message::SubmissionOrigin::ScheduledJob,
                    expected_model_state_generation: None,
                    expected_model: None,
                    kind: crate::engine::message::UserSubmissionKind::User,
                    text: crate::knowledge::build_dream_prompt(&knowledge_base.id),
                    display_text: None,
                    tag_expansions: Vec::new(),
                    images: Vec::new(),
                    media: Vec::new(),
                    forced_skill: None,
                    origin_principal: Some("daemon_dream_scheduler".to_string()),
                    job_id: Some(format!("knowledge-dream:{}", knowledge_base.id)),
                    preflight_cleaned: None,
                    queue_item_ids: Vec::new(),
                    client_submissions: Vec::new(),
                    queue_target: None,
                    pending_terminal_disposition: None,
                    run_invocation_id: None,
                    delivery_class: QueueDeliveryClass::default(),
                    delivery_class_override: None,
                }),
                #[cfg(feature = "remote")]
                remote_operation: None,
                artifact_admission: None,
                respond_to,
            })
            .await
            .context("dispatching scheduled Dream turn")?;
        let (queued_item, _) = response_rx
            .await
            .context("scheduled Dream session dropped queue acknowledgement")?
            .map_err(|error| anyhow::anyhow!(error.message))?;
        let completion = handle.watch_turn(&queued_item.id.to_string());
        match tokio::time::timeout(DREAM_TURN_TIMEOUT, completion).await {
            Ok(Ok(TurnOutcome::Completed { .. })) => {}
            Ok(Ok(TurnOutcome::Failed { error })) => {
                anyhow::bail!("scheduled Dream session driver failed: {error}");
            }
            Ok(Err(_)) => anyhow::bail!("scheduled Dream session ended before its turn completed"),
            Err(_) => anyhow::bail!("scheduled Dream turn timed out"),
        }

        let consumer = self.db.ensure_installation_identity().await?;
        let remaining = self
            .db
            .undreamed_sessions_for_knowledge_base(
                &knowledge_base.id,
                consumer.as_hex(),
                caller_trust,
            )
            .await?;
        ensure!(
            remaining.is_empty(),
            "scheduled Dream did not apply every attached undreamed session"
        );
        Ok(())
    }

    async fn claim_in_flight(&self, kb_id: &str) -> bool {
        self.in_flight.lock().await.insert(kb_id.to_owned())
    }

    async fn release_in_flight(&self, kb_id: &str) {
        self.in_flight.lock().await.remove(kb_id);
    }
}

fn is_due(
    schedule: Option<&str>,
    last_scheduled_at_unix_ms: Option<i64>,
    now_unix_ms: i64,
    kb_id: &str,
    consumer_id: &str,
) -> Result<bool> {
    let now_seconds = now_unix_ms.div_euclid(1_000);
    let Some(last_scheduled_at_unix_ms) = last_scheduled_at_unix_ms else {
        // No durable cursor means the daemon may have been off for a fire.
        return Ok(true);
    };
    if schedule.is_none_or(|schedule| schedule.trim().is_empty()) {
        return Ok(default_daily_is_due(
            last_scheduled_at_unix_ms.div_euclid(1_000),
            now_seconds,
            kb_id,
            consumer_id,
        ));
    }
    let schedule = crate::daemon::proto::ScheduledJobSchedule::Cron {
        expr: schedule.expect("checked above").to_owned(),
    };
    crate::daemon::scheduler::validate_schedule(&schedule)?;
    let next = crate::daemon::scheduler::compute_next_run(
        &schedule,
        last_scheduled_at_unix_ms.div_euclid(1_000),
        Some(last_scheduled_at_unix_ms.div_euclid(1_000)),
        last_scheduled_at_unix_ms.div_euclid(1_000),
        last_scheduled_at_unix_ms.div_euclid(1_000),
        crate::daemon::proto::MissedRunPolicy::Skip,
        None,
    )?;
    Ok(next.is_some_and(|next| next <= now_seconds))
}

fn default_daily_is_due(last_scheduled_at: i64, now: i64, kb_id: &str, consumer_id: &str) -> bool {
    let Some(now_local) = Local.timestamp_opt(now, 0).single() else {
        return false;
    };
    let Some(midnight) = Local
        .with_ymd_and_hms(
            now_local.year(),
            now_local.month(),
            now_local.day(),
            0,
            0,
            0,
        )
        .earliest()
    else {
        return false;
    };
    let scheduled_today = midnight
        .timestamp()
        .saturating_add(default_jitter_seconds(kb_id, consumer_id));
    last_scheduled_at < scheduled_today && scheduled_today <= now
}

fn default_jitter_seconds(kb_id: &str, consumer_id: &str) -> i64 {
    let mut hash = Sha256::new();
    hash.update(b"flycockpit-knowledge-dream-midnight-jitter-v1\0");
    hash.update(consumer_id.as_bytes());
    hash.update([0]);
    hash.update(kb_id.as_bytes());
    let digest = hash.finalize();
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    i64::from(value % u32::try_from(DEFAULT_JITTER_SECONDS).expect("constant fits u32"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_machine_default_jitter_is_stable_and_kb_specific() {
        let first = default_jitter_seconds("kb-a", "machine-a");
        assert_eq!(first, default_jitter_seconds("kb-a", "machine-a"));
        assert!((0..DEFAULT_JITTER_SECONDS).contains(&first));
        assert!((0..DEFAULT_JITTER_SECONDS).contains(&default_jitter_seconds("kb-b", "machine-a")));
        assert!((0..DEFAULT_JITTER_SECONDS).contains(&default_jitter_seconds("kb-a", "machine-b")));
    }

    #[test]
    fn empty_custom_schedule_is_the_local_midnight_default() {
        assert!(is_due(None, None, 1, "kb", "machine").unwrap());
        assert!(is_due(Some("   "), None, 1, "kb", "machine").unwrap());
    }
}
