//! Daemon-owned serialized guidance-proposal maintenance.
//!
//! Audit-outbox delivery and proposal expiry used to run inside the accept
//! loop, holding [`crate::computer::guidance::service::GuidanceProposalService`]
//! across database awaits. A dedicated worker keeps that whole-pass lock and
//! the one-second recovery cadence without stalling socket acceptance.
//!
//! New passes are admitted only while the daemon is `Running`, under the same
//! mutex as drain. An already-admitted pass may finish during normal drain;
//! `Forced` cancels waiting on the pass promptly.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::MissedTickBehavior;

use crate::daemon::server::DaemonContext;

const GUIDANCE_MAINTENANCE_PERIOD: Duration = Duration::from_secs(1);

/// Spawn the single daemon-owned guidance maintenance worker.
pub(crate) fn spawn_guidance_maintenance(ctx: Arc<DaemonContext>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_guidance_maintenance(ctx))
}

pub(crate) async fn run_guidance_maintenance(ctx: Arc<DaemonContext>) {
    run_guidance_maintenance_loop(ctx, GUIDANCE_MAINTENANCE_PERIOD).await;
}

async fn run_guidance_maintenance_loop(ctx: Arc<DaemonContext>, period: Duration) {
    let shutdown = ctx.shutdown_signal().clone();
    let mut shutdown_rx = shutdown.subscribe();
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval.tick().await;
    if shutdown.is_draining() {
        return;
    }
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || shutdown.is_draining() {
                    break;
                }
            }
            _ = interval.tick() => {
                let Some(_pass) = shutdown.admit_guidance_maintenance() else {
                    break;
                };
                tokio::select! {
                    _ = run_guidance_maintenance_pass(&ctx) => {}
                    _ = shutdown.wait_until_forced() => {}
                }
            }
        }
    }
}

pub(crate) async fn run_guidance_maintenance_pass(ctx: &DaemonContext) {
    #[cfg(test)]
    apply_test_seam(ctx).await;

    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut service = ctx.guidance_proposals.lock().await;
    if let Err(error) = service.flush_audit_outbox(now_ms).await {
        tracing::warn!(%error, "guidance proposal audit outbox delivery deferred");
    }
    let candidates = service.expired_candidates(now_ms);
    for candidate in candidates {
        if let Err(error) = service.expire_candidate(&candidate, now_ms).await {
            tracing::warn!(%error, "guidance proposal expiry delivery deferred");
        }
    }
}

#[cfg(test)]
struct GuidanceMaintenanceTestSeam {
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    pause: Option<tokio::sync::oneshot::Receiver<()>>,
    touch_writer: bool,
}

#[cfg(test)]
static TEST_SEAM: std::sync::Mutex<Option<GuidanceMaintenanceTestSeam>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
pub(crate) struct GuidanceMaintenanceTestGuard;

#[cfg(test)]
impl Drop for GuidanceMaintenanceTestGuard {
    fn drop(&mut self) {
        *TEST_SEAM.lock().expect("guidance maintenance test seam") = None;
    }
}

#[cfg(test)]
fn install_test_seam(
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    pause: Option<tokio::sync::oneshot::Receiver<()>>,
    touch_writer: bool,
) -> GuidanceMaintenanceTestGuard {
    *TEST_SEAM.lock().expect("guidance maintenance test seam") =
        Some(GuidanceMaintenanceTestSeam {
            entered,
            pause,
            touch_writer,
        });
    GuidanceMaintenanceTestGuard
}

#[cfg(test)]
async fn apply_test_seam(ctx: &DaemonContext) {
    let seam = TEST_SEAM
        .lock()
        .expect("guidance maintenance test seam")
        .take();
    let Some(seam) = seam else {
        return;
    };
    if let Some(entered) = seam.entered {
        let _ = entered.send(());
    }
    if let Some(pause) = seam.pause {
        let _ = pause.await;
    }
    if seam.touch_writer {
        let _ = ctx.db.write(|_| Ok(())).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::server::{disk_test_ctx, test_ctx};
    use std::time::{Duration, Instant};
    use tokio::sync::oneshot;

    async fn run_guidance_maintenance_with_period(ctx: Arc<DaemonContext>, period: Duration) {
        run_guidance_maintenance_loop(ctx, period).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accept_loop_does_not_await_guidance_maintenance() {
        let ctx = test_ctx();
        let dir = cockpit_test_support::isolated_tempdir();
        let socket = dir.path().join("guidance-accept.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind test unix socket");
        let _hold = ctx.guidance_proposals.lock().await;
        let accept = tokio::spawn(crate::daemon::server::run_accept_loop(
            ctx.clone(),
            listener,
        ));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(
            ctx.shutdown_signal().begin_drain(),
            "test owns the first drain"
        );
        tokio::time::timeout(Duration::from_millis(400), accept)
            .await
            .expect("accept loop must exit without waiting on the guidance mutex")
            .expect("accept task")
            .expect("accept loop ok");
    }

    #[tokio::test]
    async fn drain_allows_admitted_pass_to_finish() {
        let ctx = test_ctx();
        let (entered_tx, entered_rx) = oneshot::channel();
        let (pause_tx, pause_rx) = oneshot::channel();
        let _guard = install_test_seam(Some(entered_tx), Some(pause_rx), false);
        let worker = tokio::spawn(run_guidance_maintenance_with_period(
            ctx.clone(),
            Duration::from_millis(10),
        ));
        tokio::time::timeout(Duration::from_secs(1), entered_rx)
            .await
            .expect("maintenance pass should admit")
            .expect("entered");
        assert!(ctx.shutdown_signal().begin_drain());
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            !worker.is_finished(),
            "normal drain must not cancel an already-admitted pass"
        );
        pause_tx.send(()).expect("release admitted pass");
        tokio::time::timeout(Duration::from_millis(400), worker)
            .await
            .expect("worker should exit after the admitted pass finishes")
            .expect("worker join");
        assert!(ctx.shutdown_signal().admit_guidance_maintenance().is_none());
    }

    #[tokio::test]
    async fn force_cancels_admitted_pass_promptly() {
        let ctx = test_ctx();
        let (entered_tx, entered_rx) = oneshot::channel();
        let (_pause_tx, pause_rx) = oneshot::channel();
        let _guard = install_test_seam(Some(entered_tx), Some(pause_rx), false);
        let worker = tokio::spawn(run_guidance_maintenance_with_period(
            ctx.clone(),
            Duration::from_millis(10),
        ));
        tokio::time::timeout(Duration::from_secs(1), entered_rx)
            .await
            .expect("maintenance pass should admit")
            .expect("entered");
        ctx.shutdown_signal().begin_drain();
        ctx.shutdown_signal().force();
        let started = Instant::now();
        tokio::time::timeout(Duration::from_millis(300), worker)
            .await
            .expect("forced worker must exit without waiting for the slow pass")
            .expect("worker join");
        assert!(started.elapsed() < Duration::from_millis(300));
    }

    #[tokio::test]
    async fn stalled_writer_does_not_defeat_forced_shutdown() {
        let dir = cockpit_test_support::isolated_tempdir();
        let db_path = dir.path().join("guidance.db");
        let spool = dir.path().join("spool");
        let ctx = disk_test_ctx(&db_path, &spool);
        let stall = ctx.db.stall_writer_for_test().expect("stall writer");
        let (entered_tx, entered_rx) = oneshot::channel();
        let _guard = install_test_seam(Some(entered_tx), None, true);
        let worker = tokio::spawn(run_guidance_maintenance_with_period(
            ctx.clone(),
            Duration::from_millis(10),
        ));
        tokio::time::timeout(Duration::from_secs(1), entered_rx)
            .await
            .expect("maintenance pass should admit")
            .expect("entered");
        tokio::time::sleep(Duration::from_millis(20)).await;
        ctx.shutdown_signal().force();
        let started = Instant::now();
        tokio::time::timeout(Duration::from_millis(400), worker)
            .await
            .expect("forced shutdown must not wait on a stalled sqlite writer")
            .expect("worker join");
        assert!(started.elapsed() < Duration::from_millis(400));
        drop(stall);
    }

    #[tokio::test]
    async fn worker_does_not_admit_after_drain_starts() {
        let ctx = test_ctx();
        assert!(ctx.shutdown_signal().begin_drain());
        let worker = tokio::spawn(run_guidance_maintenance_with_period(
            ctx.clone(),
            Duration::from_millis(10),
        ));
        tokio::time::timeout(Duration::from_millis(200), worker)
            .await
            .expect("worker should exit once drain has already begun")
            .expect("worker join");
        assert!(ctx.shutdown_signal().admit_guidance_maintenance().is_none());
    }
}
