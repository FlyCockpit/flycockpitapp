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
) -> Result<Option<u64>> {
    let trust_policy =
        crate::config::trust::resolve_workspace_trust_policy_from_db(db, &handle.project_root)?;
    let (providers, extended) =
        match config_source.load_with_trust(&handle.project_root, &trust_policy) {
            Ok(configs) => configs,
            Err(error) => {
                let notice = format!("{CONFIG_REFRESH_FAILURE_PREFIX}: {error:#}");
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

    let (respond_to, response_rx) = oneshot::channel();
    handle
        .send_work(SessionWork::ReplaceConfigSnapshot {
            snapshot: Box::new(SessionConfigSnapshot::new(0, providers, extended)),
            respond_to,
        })
        .await?;
    let generation = response_rx.await?;
    if let Some(deduper) = failure_deduper {
        deduper.record_success();
    }
    Ok(Some(generation))
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
    async fn config_refresh_load_failure_keeps_last_good_snapshot_and_notices_once() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        db.set_workspace_trust(
            tmp.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        )
        .unwrap();
        let session =
            Arc::new(Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap());
        let locks = Arc::new(LockManager::from_db(db.clone()).unwrap());
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
}
