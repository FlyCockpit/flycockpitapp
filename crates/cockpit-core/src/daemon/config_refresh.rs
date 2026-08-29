use anyhow::Result;
use tokio::sync::oneshot;

use crate::daemon::config_source::ConfigSource;
use crate::daemon::session_worker::{SessionConfigSnapshot, SessionWork, SessionWorkerHandle};
use crate::db::Db;

const CONFIG_REFRESH_FAILURE_PREFIX: &str = "Config refresh failed; keeping the last good snapshot";
/// Bound on *publication*: delivering a config-snapshot replacement into the
/// worker queue and receiving its snapshot-CAS acknowledgement. The worker loop
/// never awaits the driver on this path, so exceeding it means the sequential
/// worker loop itself is wedged, not that a turn is long.
const CONFIG_REPLACEMENT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
/// Bound on the *applied* follow-up for a trust transition only. The driver
/// services controls at turn boundaries, so this expiring is an ordinary
/// outcome under a long turn — never a worker failure.
const CONFIG_APPLICATION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Destroy exactly this worker after a *publication* timeout.
///
/// This is only reached when delivery or the snapshot-CAS acknowledgement
/// exceeded [`CONFIG_REPLACEMENT_DEADLINE`]. Since the two-stage receipt landed,
/// the worker loop no longer blocks on the driver for any part of a
/// replacement, so an expired publication deadline genuinely means a wedged
/// worker loop: it cannot dequeue, cannot be cancelled, and cannot be brought
/// back onto the committed authority. Stopping it is the fail-closed answer.
/// A pending *application* never comes here.
async fn stop_exact_worker_after_replacement_timeout(handle: &SessionWorkerHandle) {
    // This handle's channel is the worker identity captured by the refresh;
    // never re-enumerate the registry after a timeout, where a successor may
    // already own the reusable session id.
    let deadline = tokio::time::Instant::now() + CONFIG_REPLACEMENT_DEADLINE;
    let _ = tokio::time::timeout_at(deadline, handle.send_work(SessionWork::Cancel)).await;
    let _ = tokio::time::timeout_at(
        deadline,
        handle.send_work(SessionWork::Shutdown {
            pause_for_resume: false,
        }),
    )
    .await;
}

#[derive(Debug, Default)]
pub(crate) struct ConfigRefreshFailureDeduper {
    last_notice: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConfigRefreshResult {
    pub applied_generation: u64,
    pub changed: bool,
    /// Internal worker-CAS signal. Public refresh callers always consume this
    /// by retrying; it never crosses the daemon protocol boundary.
    stale: bool,
}

/// Internal two-stage receipt: the CAS result plus the still-unresolved
/// driver-application follow-up. Only the trust path observes the follow-up;
/// every other caller drops it.
struct PublishedConfigRefresh {
    result: ConfigRefreshResult,
    applied: Option<oneshot::Receiver<()>>,
}

/// Terminal outcome of publishing one committed trust decision onto one worker.
///
/// Reaching this type at all means the projection is **published**: the
/// worker's live config is the post-transition one. [`Self::application`] says
/// only whether the driver has already rebuilt its config-derived state from
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrustTransitionRefresh {
    pub result: ConfigRefreshResult,
    pub application: TrustTransitionApplication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustTransitionApplication {
    /// The driver acknowledged application. The worker's admission gate has
    /// been (or is about to be) cleared by the worker's own follow-up task.
    Applied,
    /// The driver has not reached a turn boundary within
    /// [`CONFIG_APPLICATION_DEADLINE`]. This is a success, not a failure: the
    /// trust decision is durable, the worker holds the new projection, and the
    /// per-worker pending gate keeps setup/inventory reads fail-closed until
    /// the driver applies it at the next turn boundary. The worker must NOT be
    /// stopped — that would destroy a healthy mid-turn session for being busy.
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExplicitConfigRefreshError {
    InvalidResponseMetricsTokenizer,
    InvalidConfig(String),
    /// A newer publication won while this resolution was in flight. This is
    /// private control flow; callers retry from the retained authority.
    Stale,
    Internal,
}

pub(crate) async fn refresh_session_config_explicit(
    db: &Db,
    config_source: &ConfigSource,
    handle: &SessionWorkerHandle,
) -> std::result::Result<ConfigRefreshResult, ExplicitConfigRefreshError> {
    refresh_session_config_explicit_with_retry(db, config_source, handle).await
}

/// Publish the retained projection for one already-committed trust decision.
/// Unlike the watcher path this never adopts a newer DB value on retry: a
/// superseding transition owns its own convergence pass, and this call must
/// fail stale rather than publish the wrong authority under its caller.
pub(crate) async fn refresh_session_config_for_trust_transition(
    db: &Db,
    config_source: &ConfigSource,
    handle: &SessionWorkerHandle,
    resolved_trust: &crate::config::trust::ResolvedWorkspaceTrustPolicy,
    publication: tokio::sync::OwnedRwLockWriteGuard<()>,
) -> std::result::Result<TrustTransitionRefresh, ExplicitConfigRefreshError> {
    let published = refresh_session_config_explicit_once_with_publication(
        db,
        config_source,
        handle,
        Some(resolved_trust),
        publication,
    )
    .await?;
    let result = published.result;
    let Some(applied) = published.applied else {
        // Nothing for the driver to apply (the projection was byte-identical),
        // so publication alone completed the transition for this worker.
        return Ok(TrustTransitionRefresh {
            result,
            application: TrustTransitionApplication::Applied,
        });
    };
    // This receiver is purely observational. The worker's own follow-up task
    // owns clearing `trust_transition_pending`, so letting this receiver drop
    // on timeout cannot strand the admission gate — it only ends *our*
    // interest in the receipt.
    let application = match tokio::time::timeout(CONFIG_APPLICATION_DEADLINE, applied).await {
        Ok(Ok(())) => TrustTransitionApplication::Applied,
        // Sender dropped: either the driver died (the worker's follow-up task
        // leaves the gate closed, which is exactly the fail-closed state this
        // outcome describes) or a long turn outlived our interest.
        Ok(Err(_)) | Err(_) => TrustTransitionApplication::Pending,
    };
    Ok(TrustTransitionRefresh {
        result,
        application,
    })
}

/// The synchronous reload paired with a retained `SetDefaultModel` write.
/// Unlike ordinary watcher refresh, this must replay the complete layer chain
/// captured at attach so neither an ambient environment change nor a renewed
/// path discovery can make an acknowledged mutation describe another config.
pub(crate) async fn refresh_session_config_after_retained_default_mutation(
    db: &Db,
    config_source: &ConfigSource,
    handle: &SessionWorkerHandle,
) -> std::result::Result<ConfigRefreshResult, ExplicitConfigRefreshError> {
    refresh_session_config_explicit_with_retry(db, config_source, handle).await
}

/// A direct refresh is serialized by the daemon publication coordinator, but
/// its parse/load work necessarily happens outside the worker's short-lived
/// snapshot lock. A concurrent retained mutation can therefore win after the
/// capture. Retry from the same retained authority instead of accepting an
/// older resolved view.
async fn refresh_session_config_explicit_with_retry(
    db: &Db,
    config_source: &ConfigSource,
    handle: &SessionWorkerHandle,
) -> std::result::Result<ConfigRefreshResult, ExplicitConfigRefreshError> {
    for _ in 0..3 {
        match refresh_session_config_explicit_once(db, config_source, handle, None).await {
            Err(ExplicitConfigRefreshError::Stale) => continue,
            result => return result,
        }
    }
    Err(ExplicitConfigRefreshError::Internal)
}

async fn refresh_session_config_explicit_once(
    db: &Db,
    config_source: &ConfigSource,
    handle: &SessionWorkerHandle,
    expected_trust: Option<&crate::config::trust::ResolvedWorkspaceTrustPolicy>,
) -> std::result::Result<ConfigRefreshResult, ExplicitConfigRefreshError> {
    let publication = handle.write_owned_config_publication().await;
    // Explicit (non-transition) refreshes succeed on publication. The applied
    // receiver is dropped deliberately: their caller only needs the new
    // projection to be live, and awaiting the driver would make an ordinary
    // mutation's latency the length of an in-flight turn.
    refresh_session_config_explicit_once_with_publication(
        db,
        config_source,
        handle,
        expected_trust,
        publication,
    )
    .await
    .map(|published| published.result)
}

async fn refresh_session_config_explicit_once_with_publication(
    db: &Db,
    config_source: &ConfigSource,
    handle: &SessionWorkerHandle,
    expected_trust: Option<&crate::config::trust::ResolvedWorkspaceTrustPolicy>,
    _config_publication: tokio::sync::OwnedRwLockWriteGuard<()>,
) -> std::result::Result<PublishedConfigRefresh, ExplicitConfigRefreshError> {
    // Capture before any await or path/config read. The worker performs the
    // matching CAS immediately before it publishes the replacement.
    let expected_generation = handle.config_snapshot().generation;
    let resolved_trust = match expected_trust {
        Some(expected) => expected.clone(),
        None => crate::config::trust::resolve_workspace_trust_policy_with_revision_from_db(
            db,
            &handle.project_root,
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to resolve trust for explicit config refresh");
            ExplicitConfigRefreshError::Internal
        })?,
    };
    let trust_policy = resolved_trust.policy.clone();
    let trust_revision = resolved_trust.revision;
    if !handle.trust_transition_matches(&resolved_trust) {
        return Err(ExplicitConfigRefreshError::Stale);
    }
    let workspace_layer = handle
        .workspace_root_authority
        .capture_retained_config_source_chain(&trust_policy)
        .map_err(|error| {
            tracing::warn!(%error, "explicit config refresh workspace authority rejected");
            ExplicitConfigRefreshError::Internal
        })?;
    let (providers, extended) = config_source
        .load_effective_for_daemon_with_retained_workspace_layer(
            &handle.project_root,
            &trust_policy,
            &workspace_layer,
        )
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
    handle
        .workspace_root_authority
        .verify_retained_config_source_chain_for_policy(&trust_policy)
        .map_err(|error| {
            tracing::warn!(%error, "explicit config refresh authority changed before publication");
            ExplicitConfigRefreshError::Internal
        })?;
    // Resolve hooks from the immutable attach-time source selection so a
    // mutable process override cannot redirect this worker during refresh.
    let hooks = handle
        .workspace_root_authority
        .resolve_hooks_for_policy(&trust_policy)
        .map_err(|error| {
            tracing::warn!(%error, "explicit config refresh hook authority rejected");
            ExplicitConfigRefreshError::Internal
        })?;
    apply_global_goal_supervision_kill_switch(db, &extended)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to apply global goal-supervision kill switch");
            ExplicitConfigRefreshError::Internal
        })?;
    handle
        .workspace_root_authority
        .verify_retained_config_source_chain_for_policy(&trust_policy)
        .map_err(|error| {
            tracing::warn!(%error, "explicit config refresh authority changed at publication");
            ExplicitConfigRefreshError::Internal
        })?;
    let latest_trust = crate::config::trust::resolve_workspace_trust_policy_with_revision_from_db(
        db,
        &handle.project_root,
    )
    .await
    .map_err(|error| {
        tracing::warn!(%error, "failed to re-read trust at explicit config publication");
        ExplicitConfigRefreshError::Internal
    })?;
    if latest_trust != resolved_trust || !handle.trust_transition_matches(&resolved_trust) {
        return Err(ExplicitConfigRefreshError::Stale);
    }
    let snapshot = SessionConfigSnapshot::with_hooks(0, providers, extended, hooks)
        .with_trust_revision(trust_revision)
        .with_retained_provider_model_sources(&workspace_layer)
        .map_err(|error| {
            tracing::warn!(%error, "explicit config refresh provider provenance rejected");
            ExplicitConfigRefreshError::Internal
        })?;
    let (respond_to, response_rx) = oneshot::channel();
    let deadline = tokio::time::Instant::now() + CONFIG_REPLACEMENT_DEADLINE;
    let delivered = tokio::time::timeout_at(
        deadline,
        handle.send_work(SessionWork::ReplaceConfigSnapshot {
            snapshot: Box::new(snapshot),
            expected_generation: Some(expected_generation),
            expected_trust_revision: Some(trust_revision),
            respond_to,
        }),
    )
    .await;
    match delivered {
        Ok(result) => result.map_err(|error| {
            tracing::warn!(%error, "failed to deliver explicit config refresh");
            ExplicitConfigRefreshError::Internal
        })?,
        Err(_) => {
            tracing::warn!(session_id = %handle.session_id, "explicit config refresh delivery timed out");
            stop_exact_worker_after_replacement_timeout(handle).await;
            return Err(ExplicitConfigRefreshError::Internal);
        }
    };
    // The publication acknowledgement, not the driver's application receipt.
    let replacement = match tokio::time::timeout_at(deadline, response_rx).await {
        Ok(result) => result.map_err(|error| {
            tracing::warn!(%error, "explicit config refresh worker response dropped");
            ExplicitConfigRefreshError::Internal
        })?,
        Err(_) => {
            tracing::warn!(session_id = %handle.session_id, "explicit config refresh publication acknowledgement timed out");
            stop_exact_worker_after_replacement_timeout(handle).await;
            return Err(ExplicitConfigRefreshError::Internal);
        }
    };
    if replacement.stale {
        return Err(ExplicitConfigRefreshError::Stale);
    }
    crate::daemon::server::inventory::bump_inventory_generation();
    Ok(PublishedConfigRefresh {
        result: ConfigRefreshResult {
            applied_generation: replacement.generation,
            changed: replacement.changed,
            stale: false,
        },
        applied: replacement.applied,
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
    for _ in 0..3 {
        match refresh_session_config_once(db, config_source, handle, failure_deduper.as_deref_mut())
            .await?
        {
            Some(result) if result.stale => continue,
            Some(result) => return Ok(Some(result)),
            None => return Ok(None),
        }
    }
    Ok(None)
}

async fn refresh_session_config_once(
    db: &Db,
    config_source: &ConfigSource,
    handle: &SessionWorkerHandle,
    mut failure_deduper: Option<&mut ConfigRefreshFailureDeduper>,
) -> Result<Option<ConfigRefreshResult>> {
    let _config_publication = handle.write_config_publication().await;
    let expected_generation = handle.config_snapshot().generation;
    let resolved_trust =
        crate::config::trust::resolve_workspace_trust_policy_with_revision_from_db(
            db,
            &handle.project_root,
        )
        .await?;
    let trust_policy = resolved_trust.policy.clone();
    let trust_revision = resolved_trust.revision;
    if !handle.trust_transition_matches(&resolved_trust) {
        return Ok(Some(ConfigRefreshResult {
            applied_generation: handle.config_snapshot().generation,
            changed: false,
            stale: true,
        }));
    }
    let workspace_layer = match handle
        .workspace_root_authority
        .capture_retained_config_source_chain(&trust_policy)
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let notice = format!("{CONFIG_REFRESH_FAILURE_PREFIX}: workspace authority changed");
            tracing::warn!(%error, "background config refresh workspace authority rejected");
            if failure_deduper
                .as_deref_mut()
                .map(|deduper| deduper.should_emit(&notice))
                .unwrap_or(true)
            {
                handle.broadcast_notice(notice);
            }
            return Ok(None);
        }
    };
    let (providers, extended) = match config_source
        .load_effective_for_daemon_with_retained_workspace_layer(
            &handle.project_root,
            &trust_policy,
            &workspace_layer,
        ) {
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

    if let Err(error) = handle
        .workspace_root_authority
        .verify_retained_config_source_chain_for_policy(&trust_policy)
    {
        let notice = format!("{CONFIG_REFRESH_FAILURE_PREFIX}: workspace authority changed");
        tracing::warn!(%error, "background config refresh authority changed before publication");
        if failure_deduper
            .as_deref_mut()
            .map(|deduper| deduper.should_emit(&notice))
            .unwrap_or(true)
        {
            handle.broadcast_notice(notice);
        }
        return Ok(None);
    }

    apply_global_goal_supervision_kill_switch(db, &extended).await?;

    // Resolve hooks from the immutable attach-time source selection so a
    // mutable process override cannot redirect this worker during refresh.
    let hooks = match handle
        .workspace_root_authority
        .resolve_hooks_for_policy(&trust_policy)
    {
        Ok(hooks) => hooks,
        Err(error) => {
            let notice = format!("{CONFIG_REFRESH_FAILURE_PREFIX}: workspace authority changed");
            tracing::warn!(%error, "background config refresh hook authority rejected");
            if failure_deduper
                .as_deref_mut()
                .map(|deduper| deduper.should_emit(&notice))
                .unwrap_or(true)
            {
                handle.broadcast_notice(notice);
            }
            return Ok(None);
        }
    };

    if let Err(error) = handle
        .workspace_root_authority
        .verify_retained_config_source_chain_for_policy(&trust_policy)
    {
        let notice = format!("{CONFIG_REFRESH_FAILURE_PREFIX}: workspace authority changed");
        tracing::warn!(%error, "background config refresh authority changed at publication");
        if failure_deduper
            .as_deref_mut()
            .map(|deduper| deduper.should_emit(&notice))
            .unwrap_or(true)
        {
            handle.broadcast_notice(notice);
        }
        return Ok(None);
    }

    let latest_trust = crate::config::trust::resolve_workspace_trust_policy_with_revision_from_db(
        db,
        &handle.project_root,
    )
    .await?;
    if latest_trust != resolved_trust || !handle.trust_transition_matches(&resolved_trust) {
        return Ok(Some(ConfigRefreshResult {
            applied_generation: handle.config_snapshot().generation,
            changed: false,
            stale: true,
        }));
    }

    let snapshot = match SessionConfigSnapshot::with_hooks(0, providers, extended, hooks)
        .with_trust_revision(trust_revision)
        .with_retained_provider_model_sources(&workspace_layer)
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let notice =
                format!("{CONFIG_REFRESH_FAILURE_PREFIX}: provider source provenance is invalid");
            tracing::warn!(%error, "background config refresh provider provenance rejected");
            if failure_deduper
                .as_deref_mut()
                .map(|deduper| deduper.should_emit(&notice))
                .unwrap_or(true)
            {
                handle.broadcast_notice(notice);
            }
            return Ok(None);
        }
    };
    let (respond_to, response_rx) = oneshot::channel();
    let deadline = tokio::time::Instant::now() + CONFIG_REPLACEMENT_DEADLINE;
    let delivered = tokio::time::timeout_at(
        deadline,
        handle.send_work(SessionWork::ReplaceConfigSnapshot {
            snapshot: Box::new(snapshot),
            expected_generation: Some(expected_generation),
            expected_trust_revision: Some(trust_revision),
            respond_to,
        }),
    )
    .await;
    match delivered {
        Ok(result) => result?,
        Err(_) => {
            stop_exact_worker_after_replacement_timeout(handle).await;
            anyhow::bail!("config refresh delivery timed out");
        }
    };
    // The watcher succeeds on publication. `replacement.applied` is dropped
    // here on purpose: a filesystem-driven refresh must never block on a turn
    // boundary, and the driver picks the new snapshot up at its next re-pin
    // regardless. The worker's follow-up task owns any gate clearing.
    let replacement = match tokio::time::timeout_at(deadline, response_rx).await {
        Ok(result) => result?,
        Err(_) => {
            stop_exact_worker_after_replacement_timeout(handle).await;
            anyhow::bail!("config refresh publication acknowledgement timed out");
        }
    };
    if replacement.stale {
        // The watcher has already consumed the edge that triggered this
        // refresh. Surface an internal stale signal so the bounded outer loop
        // re-resolves rather than waiting for a second filesystem event.
        return Ok(Some(ConfigRefreshResult {
            applied_generation: replacement.generation,
            changed: false,
            stale: true,
        }));
    }
    crate::daemon::server::inventory::bump_inventory_generation();
    if let Some(deduper) = failure_deduper {
        deduper.record_success();
    }
    Ok(Some(ConfigRefreshResult {
        applied_generation: replacement.generation,
        changed: replacement.changed,
        stale: false,
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
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let locks = Arc::new(LockManager::from_db(db.clone()).await.unwrap());
        let (handle, mut work_rx) = SessionWorkerHandle::test_handle_with_receiver(session, locks);
        let responder = tokio::spawn(async move {
            let SessionWork::ReplaceConfigSnapshot { respond_to, .. } =
                work_rx.recv().await.expect("replacement work")
            else {
                panic!("unexpected work")
            };
            respond_to
                .send(crate::daemon::session_worker::ReplaceConfigSnapshotAck {
                    generation: 7,
                    changed: true,
                    stale: false,
                    applied: None,
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

    async fn trust_transition_fixture(
        tmp: &std::path::Path,
    ) -> (
        Db,
        SessionWorkerHandle,
        tokio::sync::mpsc::Receiver<SessionWork>,
        crate::config::trust::ResolvedWorkspaceTrustPolicy,
    ) {
        let db = Db::open_in_memory().unwrap();
        db.set_workspace_trust(tmp, crate::db::workspace_trust::WorkspaceTrustMode::Trust)
            .await
            .unwrap();
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let locks = Arc::new(LockManager::from_db(db.clone()).await.unwrap());
        let (handle, work_rx) = SessionWorkerHandle::test_handle_with_receiver(session, locks);
        let resolved =
            crate::config::trust::resolve_workspace_trust_policy_with_revision_from_db(&db, tmp)
                .await
                .unwrap();
        (db, handle, work_rx, resolved)
    }

    /// A worker that publishes but whose driver is mid-turn is healthy. The
    /// transition must report application as pending — a success — instead of
    /// timing out into a destructive stop.
    #[tokio::test(start_paused = true)]
    async fn trust_transition_refresh_reports_pending_application_without_failing() {
        let tmp = tempfile::tempdir().unwrap();
        let (db, handle, mut work_rx, resolved) = trust_transition_fixture(tmp.path()).await;
        let (keep_tx, keep_rx) = oneshot::channel::<()>();
        let responder = tokio::spawn(async move {
            let SessionWork::ReplaceConfigSnapshot { respond_to, .. } =
                work_rx.recv().await.expect("replacement work")
            else {
                panic!("unexpected work")
            };
            let (applied_tx, applied_rx) = oneshot::channel();
            respond_to
                .send(crate::daemon::session_worker::ReplaceConfigSnapshotAck {
                    generation: 3,
                    changed: true,
                    stale: false,
                    applied: Some(applied_rx),
                })
                .unwrap();
            // A mid-turn driver: the receipt never arrives, and the sender is
            // deliberately kept alive so the refresh observes a timeout rather
            // than a dropped channel.
            let _ = keep_rx.await;
            drop(applied_tx);
        });

        let publication = handle.write_owned_config_publication().await;
        let outcome = refresh_session_config_for_trust_transition(
            &db,
            &ConfigSource::fixed(
                crate::config::providers::ProvidersConfig::default(),
                crate::config::extended::ExtendedConfig::default(),
            ),
            &handle,
            &resolved,
            publication,
        )
        .await
        .expect("publication succeeded, so the transition succeeded");

        assert_eq!(outcome.application, TrustTransitionApplication::Pending);
        assert_eq!(outcome.result.applied_generation, 3);
        let _ = keep_tx.send(());
        responder.await.unwrap();
    }

    /// When the driver is idle it applies immediately and the transition
    /// reports the fully-applied outcome.
    #[tokio::test]
    async fn trust_transition_refresh_reports_applied_when_the_receipt_lands() {
        let tmp = tempfile::tempdir().unwrap();
        let (db, handle, mut work_rx, resolved) = trust_transition_fixture(tmp.path()).await;
        let responder = tokio::spawn(async move {
            let SessionWork::ReplaceConfigSnapshot { respond_to, .. } =
                work_rx.recv().await.expect("replacement work")
            else {
                panic!("unexpected work")
            };
            let (applied_tx, applied_rx) = oneshot::channel();
            respond_to
                .send(crate::daemon::session_worker::ReplaceConfigSnapshotAck {
                    generation: 4,
                    changed: true,
                    stale: false,
                    applied: Some(applied_rx),
                })
                .unwrap();
            applied_tx.send(()).unwrap();
        });

        let publication = handle.write_owned_config_publication().await;
        let outcome = refresh_session_config_for_trust_transition(
            &db,
            &ConfigSource::fixed(
                crate::config::providers::ProvidersConfig::default(),
                crate::config::extended::ExtendedConfig::default(),
            ),
            &handle,
            &resolved,
            publication,
        )
        .await
        .expect("applied transition succeeds");

        assert_eq!(outcome.application, TrustTransitionApplication::Applied);
        assert_eq!(outcome.result.applied_generation, 4);
        responder.await.unwrap();
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

        let live = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let locks = Arc::new(LockManager::from_db(db.clone()).await.unwrap());
        let (handle, mut work_rx) = SessionWorkerHandle::test_handle_with_receiver(live, locks);
        let responder = tokio::spawn(async move {
            let SessionWork::ReplaceConfigSnapshot { respond_to, .. } =
                work_rx.recv().await.expect("replacement work")
            else {
                panic!("unexpected work")
            };
            respond_to
                .send(crate::daemon::session_worker::ReplaceConfigSnapshotAck {
                    generation: 1,
                    changed: true,
                    stale: false,
                    applied: None,
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
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
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
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                project,
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
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
