use anyhow::Result;
use tokio::sync::oneshot;

use crate::daemon::config_source::ConfigSource;
use crate::daemon::session_worker::{SessionConfigSnapshot, SessionWork, SessionWorkerHandle};
use crate::db::Db;

const CONFIG_REFRESH_FAILURE_PREFIX: &str = "Config refresh failed; keeping the last good snapshot";

#[derive(Debug, Default)]
pub(crate) struct ConfigRefreshFailureDeduper {
    last_notice: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConfigRefreshResult {
    pub applied_generation: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExplicitConfigRefreshError {
    InvalidResponseMetricsTokenizer,
    InvalidConfig(String),
    Internal,
}

pub(crate) async fn refresh_session_config_explicit(
    db: &Db,
    config_source: &ConfigSource,
    handle: &SessionWorkerHandle,
) -> std::result::Result<ConfigRefreshResult, ExplicitConfigRefreshError> {
    let trust_policy =
        crate::config::trust::resolve_workspace_trust_policy_from_db(db, &handle.project_root)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to resolve trust for explicit config refresh");
                ExplicitConfigRefreshError::Internal
            })?;
    let (providers, extended) = config_source
        .load_effective_for_daemon(&handle.project_root, &trust_policy)
        .map_err(|error| {
            if let Some(invalid) = error
                .downcast_ref::<crate::config::extended::InvalidResponseMetricsTokenizer>()
            {
                tracing::warn!(diagnostic = %invalid.diagnostic(), "explicit config refresh rejected");
                ExplicitConfigRefreshError::InvalidResponseMetricsTokenizer
            } else {
                tracing::warn!(error = ?error, "explicit config refresh rejected");
                ExplicitConfigRefreshError::InvalidConfig(format!("{error:#}"))
            }
        })?;
    // Resolve hooks under the same workspace-trust scope and generation as
    // providers/extended config so the hook registry is turn-stable with the
    // rest of the snapshot.
    let hooks = crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
        crate::config::extended::hooks::resolve_hooks_for_cwd(&handle.project_root)
    });
    apply_global_goal_supervision_kill_switch(db, &extended)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to apply global goal-supervision kill switch");
            ExplicitConfigRefreshError::Internal
        })?;
    let (respond_to, response_rx) = oneshot::channel();
    handle
        .send_work(SessionWork::ReplaceConfigSnapshot {
            snapshot: Box::new(SessionConfigSnapshot::with_hooks(
                0, providers, extended, hooks,
            )),
            respond_to,
        })
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to deliver explicit config refresh");
            ExplicitConfigRefreshError::Internal
        })?;
    let replacement = response_rx.await.map_err(|error| {
        tracing::warn!(%error, "explicit config refresh worker response dropped");
        ExplicitConfigRefreshError::Internal
    })?;
    crate::daemon::server::inventory::bump_inventory_generation();
    Ok(ConfigRefreshResult {
        applied_generation: replacement.generation,
        changed: replacement.changed,
    })
}

impl ConfigRefreshFailureDeduper {
    fn should_emit(&mut self, notice: &str) -> bool {
        if self.last_notice.as_deref() == Some(notice) {
            return false;
        }
        self.last_notice = Some(notice.to_string());
        true
    }

    fn record_success(&mut self) {
        self.last_notice = None;
    }
}

pub(crate) async fn refresh_session_config(
    db: &Db,
    config_source: &ConfigSource,
    handle: &SessionWorkerHandle,
    mut failure_deduper: Option<&mut ConfigRefreshFailureDeduper>,
) -> Result<Option<ConfigRefreshResult>> {
    let trust_policy =
        crate::config::trust::resolve_workspace_trust_policy_from_db(db, &handle.project_root)
            .await?;
    let (providers, extended) = match config_source
        .load_effective_for_daemon(&handle.project_root, &trust_policy)
    {
        Ok(configs) => configs,
        Err(error) => {
            let notice = if let Some(invalid) =
                error.downcast_ref::<crate::config::extended::InvalidResponseMetricsTokenizer>()
            {
                tracing::warn!(diagnostic = %invalid.diagnostic(), "background config refresh rejected");
                format!("{CONFIG_REFRESH_FAILURE_PREFIX}: configuration value is invalid")
            } else {
                tracing::warn!(error = ?error, "background config refresh rejected");
                format!("{CONFIG_REFRESH_FAILURE_PREFIX}: {error:#}")
            };
            let emit = failure_deduper
                .as_deref_mut()
                .map(|deduper| deduper.should_emit(&notice))
                .unwrap_or(true);
            if emit {
                handle.broadcast_notice(notice);
            }
            return Ok(None);
        }
    };

    apply_global_goal_supervision_kill_switch(db, &extended).await?;

    // Resolve hooks under the same workspace-trust scope and generation as
    // providers/extended config.
    let hooks = crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
        crate::config::extended::hooks::resolve_hooks_for_cwd(&handle.project_root)
    });

    let (respond_to, response_rx) = oneshot::channel();
    handle
        .send_work(SessionWork::ReplaceConfigSnapshot {
            snapshot: Box::new(SessionConfigSnapshot::with_hooks(
                0, providers, extended, hooks,
            )),
            respond_to,
        })
        .await?;
    let replacement = response_rx.await?;
    crate::daemon::server::inventory::bump_inventory_generation();
    if let Some(deduper) = failure_deduper {
        deduper.record_success();
    }
    Ok(Some(ConfigRefreshResult {
        applied_generation: replacement.generation,
        changed: replacement.changed,
    }))
}

/// A successful daemon config resolution is the ownership boundary for the
/// global supervision master switch. Apply it directly to durable state before
/// delivering any per-worker snapshot so detached sessions and sessions whose
/// workers are not running cannot escape the operator disable.
async fn apply_global_goal_supervision_kill_switch(
    db: &Db,
    extended: &crate::config::extended::ExtendedConfig,
) -> Result<()> {
    if !extended.goal_supervision.enabled {
        db.pause_all_goals_for_operator_disable().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::daemon::proto;
    use crate::locks::LockManager;
    use crate::session::Session;

    #[test]
    fn config_refresh_failure_deduper_reemits_after_change_or_success() {
        let mut deduper = ConfigRefreshFailureDeduper::default();
        assert!(deduper.should_emit("first"));
        assert!(!deduper.should_emit("first"));
        assert!(deduper.should_emit("second"));
        assert!(!deduper.should_emit("second"));
        deduper.record_success();
        assert!(deduper.should_emit("second"));
    }

    #[tokio::test]
    async fn refresh_config_returns_generation_and_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        db.set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .await
        .unwrap();
        let session =
            Arc::new(Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap());
        let locks = Arc::new(LockManager::from_db(db.clone()).await.unwrap());
        let (handle, mut work_rx) = SessionWorkerHandle::test_handle_with_receiver(session, locks);
        let responder = tokio::spawn(async move {
            let SessionWork::ReplaceConfigSnapshot { respond_to, .. } =
                work_rx.recv().await.expect("replacement work")
            else {
                panic!("unexpected work")
            };
            respond_to
                .send(crate::daemon::session_worker::ReplaceConfigSnapshotResult {
                    generation: 7,
                    changed: true,
                })
                .unwrap();
        });
        let result = refresh_session_config_explicit(
            &db,
            &ConfigSource::fixed(
                crate::config::providers::ProvidersConfig::default(),
                crate::config::extended::ExtendedConfig::default(),
            ),
            &handle,
        )
        .await
        .unwrap();
        responder.await.unwrap();
        assert_eq!(result.applied_generation, 7);
        assert!(result.changed);
    }

    #[tokio::test]
    async fn successful_global_refresh_disables_detached_goal_without_its_worker() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        db.set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .await
        .unwrap();
        let detached = db
            .create_session("p", "/tmp/detached", "Build")
            .await
            .unwrap();
        db.create_session_goal(detached.session_id, "p", "detached", None, Some(100))
            .await
            .unwrap();

        let live =
            Arc::new(Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap());
        let locks = Arc::new(LockManager::from_db(db.clone()).await.unwrap());
        let (handle, mut work_rx) = SessionWorkerHandle::test_handle_with_receiver(live, locks);
        let responder = tokio::spawn(async move {
            let SessionWork::ReplaceConfigSnapshot { respond_to, .. } =
                work_rx.recv().await.expect("replacement work")
            else {
                panic!("unexpected work")
            };
            respond_to
                .send(crate::daemon::session_worker::ReplaceConfigSnapshotResult {
                    generation: 1,
                    changed: true,
                })
                .unwrap();
        });
        let mut extended = crate::config::extended::ExtendedConfig::default();
        extended.goal_supervision.enabled = false;
        refresh_session_config_explicit(
            &db,
            &ConfigSource::fixed(
                crate::config::providers::ProvidersConfig::default(),
                extended,
            ),
            &handle,
        )
        .await
        .unwrap();
        responder.await.unwrap();

        let paused = db
            .current_session_goal(detached.session_id, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            paused.disposition,
            crate::db::session_goals::GoalDisposition::UserPaused
        );
        assert_eq!(
            paused.pause_reason,
            Some(crate::db::session_goals::GoalPauseReason::OperatorDisabled)
        );
    }

    #[tokio::test]
    async fn config_refresh_load_failure_keeps_last_good_snapshot_and_notices_once() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        db.set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .await
        .unwrap();
        let session =
            Arc::new(Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap());
        let locks = Arc::new(LockManager::from_db(db.clone()).await.unwrap());
        let (handle, _work_rx) = SessionWorkerHandle::test_handle_with_receiver(session, locks);
        let mut events = handle.subscribe();
        let source = ConfigSource::new(
            |_cwd| Err(anyhow::anyhow!("malformed config layer")),
            |_cwd, _provider_id| None,
            |_cwd| crate::daemon::config_source::ConfigWatchPaths::default(),
        );
        let mut deduper = ConfigRefreshFailureDeduper::default();

        let first = refresh_session_config(&db, &source, &handle, Some(&mut deduper)).await;
        let second = refresh_session_config(&db, &source, &handle, Some(&mut deduper)).await;

        assert!(first.unwrap().is_none());
        assert!(second.unwrap().is_none());
        assert_eq!(handle.config_snapshot().generation, 0);
        let notice_count = std::iter::from_fn(|| events.try_recv().ok())
            .filter(|envelope| {
                matches!(
                    &envelope.event,
                    proto::Event::Notice { text, .. }
                        if text.contains(CONFIG_REFRESH_FAILURE_PREFIX)
                )
            })
            .count();
        assert_eq!(notice_count, 1);
    }

    #[tokio::test]
    async fn invalid_response_metrics_tokenizer_explicit_refresh_fails_and_watcher_keeps_last_good()
    {
        let tmp = tempfile::tempdir().unwrap();
        let _home =
            crate::config::dirs::test_support::IsolatedCockpitHome::new_async(tmp.path()).await;
        let project = tmp.path().join("repo");
        std::fs::create_dir_all(project.join(".cockpit")).unwrap();
        std::fs::write(
            project.join(".cockpit/config.json"),
            r#"{"response_metrics_tokenizer":"raw-secret-invalid"}"#,
        )
        .unwrap();
        let db = Db::open_in_memory().unwrap();
        db.set_workspace_trust(
            &project,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .await
        .unwrap();
        let session = Arc::new(Session::create(db.clone(), project, "Build").unwrap());
        let locks = Arc::new(LockManager::from_db(db.clone()).await.unwrap());
        let (handle, _work_rx) = SessionWorkerHandle::test_handle_with_receiver(session, locks);
        let source = ConfigSource::production();

        assert_eq!(
            refresh_session_config_explicit(&db, &source, &handle).await,
            Err(ExplicitConfigRefreshError::InvalidResponseMetricsTokenizer)
        );
        let mut events = handle.subscribe();
        let mut deduper = ConfigRefreshFailureDeduper::default();
        assert!(
            refresh_session_config(&db, &source, &handle, Some(&mut deduper))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(handle.config_snapshot().generation, 0);
        let notice = std::iter::from_fn(|| events.try_recv().ok())
            .find_map(|envelope| match envelope.event {
                proto::Event::Notice { text, .. } => Some(text),
                _ => None,
            })
            .expect("watcher failure notice");
        assert_eq!(
            notice,
            "Config refresh failed; keeping the last good snapshot: configuration value is invalid"
        );
        assert!(!notice.contains("raw-secret-invalid"));
    }
}
