//! Daemon-owned serialized retention maintenance.
//!
//! Session payload expiry and media retention used to run inside the accept
//! loop, holding database and storage handles across long awaits. A dedicated
//! worker keeps that cadence without stalling socket acceptance.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::MissedTickBehavior;

use crate::daemon::server::{DaemonContext, retention_config, run_retention_tick};

#[cfg(test)]
struct RetentionMaintenanceTestSeam {
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    pause: Option<tokio::sync::oneshot::Receiver<()>>,
}

#[cfg(test)]
static TEST_SEAM: std::sync::Mutex<Option<RetentionMaintenanceTestSeam>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
static TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
pub(crate) struct RetentionMaintenanceTestGuard;

#[cfg(test)]
impl Drop for RetentionMaintenanceTestGuard {
    fn drop(&mut self) {
        *TEST_SEAM.lock().expect("retention maintenance test seam") = None;
    }
}

#[cfg(test)]
fn install_test_seam(
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    pause: Option<tokio::sync::oneshot::Receiver<()>>,
) -> RetentionMaintenanceTestGuard {
    *TEST_SEAM.lock().expect("retention maintenance test seam") =
        Some(RetentionMaintenanceTestSeam { entered, pause });
    RetentionMaintenanceTestGuard
}

#[cfg(test)]
async fn apply_test_seam() {
    let seam = TEST_SEAM
        .lock()
        .expect("retention maintenance test seam")
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
}

/// Spawn the single daemon-owned retention maintenance worker.
pub(crate) fn spawn_retention_maintenance(ctx: Arc<DaemonContext>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_retention_maintenance(ctx))
}

pub(crate) async fn run_retention_maintenance(ctx: Arc<DaemonContext>) {
    let cfg = retention_config();
    let period = Duration::from_secs((cfg.sweep_interval_hours.max(1) as u64) * 60 * 60);
    run_retention_maintenance_loop(ctx, period).await;
}

async fn run_retention_maintenance_loop(ctx: Arc<DaemonContext>, period: Duration) {
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
                    _ = run_retention_maintenance_pass(ctx.clone()) => {}
                    _ = shutdown.wait_until_forced() => {}
                }
            }
        }
    }
}

pub(crate) async fn run_retention_maintenance_pass(ctx: Arc<DaemonContext>) {
    #[cfg(test)]
    apply_test_seam().await;

    run_retention_tick(ctx, retention_config()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::server::test_ctx;
    use std::time::{Duration, Instant};
    use tokio::sync::oneshot;

    async fn serial_lock() -> tokio::sync::MutexGuard<'static, ()> {
        TEST_SERIAL.lock().await
    }

    async fn run_retention_maintenance_with_period(ctx: Arc<DaemonContext>, period: Duration) {
        run_retention_maintenance_loop(ctx, period).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accept_loop_accepts_while_retention_maintenance_is_blocked() {
        let _serial = serial_lock().await;
        let ctx = test_ctx();
        let dir = cockpit_test_support::isolated_tempdir();
        let socket = dir.path().join("retention-accept.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind test unix socket");
        let (entered_tx, entered_rx) = oneshot::channel();
        let (pause_tx, pause_rx) = oneshot::channel();
        let _guard = install_test_seam(Some(entered_tx), Some(pause_rx));
        let worker = tokio::spawn(run_retention_maintenance_with_period(
            ctx.clone(),
            Duration::from_millis(10),
        ));
        tokio::time::timeout(Duration::from_secs(1), entered_rx)
            .await
            .expect("retention pass should admit")
            .expect("entered");
        let accept = tokio::spawn(crate::daemon::server::run_accept_loop(
            ctx.clone(),
            listener,
        ));
        let client = tokio::time::timeout(
            Duration::from_secs(5),
            cockpit_client::DaemonClient::connect(&socket),
        )
        .await
        .expect("accept loop must accept while retention maintenance is blocked")
        .expect("daemon handshake while retention maintenance is blocked");
        assert!(client.is_socket_backed());
        drop(client);
        let started = Instant::now();
        assert!(
            ctx.shutdown_signal().begin_drain(),
            "test owns the first drain"
        );
        tokio::time::timeout(Duration::from_secs(5), accept)
            .await
            .expect("accept loop must exit without waiting on retention maintenance")
            .expect("accept task")
            .expect("accept loop ok");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "accept loop took {:?} while retention pass is paused",
            started.elapsed()
        );
        pause_tx.send(()).expect("release admitted pass");
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("worker should exit after the admitted pass finishes")
            .expect("worker join");
    }
}
