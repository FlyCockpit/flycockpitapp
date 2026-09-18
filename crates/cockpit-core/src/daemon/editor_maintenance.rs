//! Daemon-owned serialized editor-lease and OAuth-flow maintenance.
//!
//! These short periodic passes used to run inside the accept loop. A dedicated
//! worker keeps the cadence without stalling socket acceptance.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::MissedTickBehavior;

use crate::daemon::server::DaemonContext;

const EDITOR_MAINTENANCE_PERIOD: Duration = Duration::from_secs(60);

#[cfg(test)]
struct EditorMaintenanceTestSeam {
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    pause: Option<tokio::sync::oneshot::Receiver<()>>,
}

#[cfg(test)]
static TEST_SEAM: std::sync::Mutex<Option<EditorMaintenanceTestSeam>> = std::sync::Mutex::new(None);

#[cfg(test)]
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) struct EditorMaintenanceTestGuard;

#[cfg(test)]
impl Drop for EditorMaintenanceTestGuard {
    fn drop(&mut self) {
        *TEST_SEAM.lock().expect("editor maintenance test seam") = None;
    }
}

#[cfg(test)]
fn install_test_seam(
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    pause: Option<tokio::sync::oneshot::Receiver<()>>,
) -> EditorMaintenanceTestGuard {
    *TEST_SEAM.lock().expect("editor maintenance test seam") =
        Some(EditorMaintenanceTestSeam { entered, pause });
    EditorMaintenanceTestGuard
}

#[cfg(test)]
async fn apply_test_seam() {
    let seam = TEST_SEAM
        .lock()
        .expect("editor maintenance test seam")
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

/// Spawn the single daemon-owned editor/OAuth maintenance worker.
pub(crate) fn spawn_editor_maintenance(ctx: Arc<DaemonContext>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_editor_maintenance(ctx))
}

pub(crate) async fn run_editor_maintenance(ctx: Arc<DaemonContext>) {
    run_editor_maintenance_loop(ctx, EDITOR_MAINTENANCE_PERIOD).await;
}

async fn run_editor_maintenance_loop(ctx: Arc<DaemonContext>, period: Duration) {
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
                    _ = run_editor_maintenance_pass(ctx.clone()) => {}
                    _ = shutdown.wait_until_forced() => {}
                }
            }
        }
    }
}

pub(crate) async fn run_editor_maintenance_pass(ctx: Arc<DaemonContext>) {
    #[cfg(test)]
    apply_test_seam().await;

    if let Err(error) = crate::daemon::agent_management::maintain_editor_leases(&ctx).await {
        tracing::warn!(message = %error.message, "editor lease maintenance failed");
    }
    if let Err(error) = crate::daemon::server::maintain_durable_oauth_flows(&ctx).await {
        tracing::warn!(message = %error.message, "OAuth flow maintenance failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::server::test_ctx;
    use std::time::{Duration, Instant};
    use tokio::sync::oneshot;

    fn serial_lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_SERIAL
            .lock()
            .expect("editor maintenance test serial lock")
    }

    async fn run_editor_maintenance_with_period(ctx: Arc<DaemonContext>, period: Duration) {
        run_editor_maintenance_loop(ctx, period).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accept_loop_does_not_await_editor_maintenance() {
        let _serial = serial_lock();
        let ctx = test_ctx();
        let dir = cockpit_test_support::isolated_tempdir();
        let socket = dir.path().join("editor-accept.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind test unix socket");
        let (entered_tx, entered_rx) = oneshot::channel();
        let (pause_tx, pause_rx) = oneshot::channel();
        let _guard = install_test_seam(Some(entered_tx), Some(pause_rx));
        let worker = tokio::spawn(run_editor_maintenance_with_period(
            ctx.clone(),
            Duration::from_millis(10),
        ));
        tokio::time::timeout(Duration::from_secs(1), entered_rx)
            .await
            .expect("editor maintenance pass should admit")
            .expect("entered");
        let accept = tokio::spawn(crate::daemon::server::run_accept_loop(
            ctx.clone(),
            listener,
        ));
        let started = Instant::now();
        assert!(
            ctx.shutdown_signal().begin_drain(),
            "test owns the first drain"
        );
        tokio::time::timeout(Duration::from_secs(5), accept)
            .await
            .expect("accept loop must exit without waiting on editor maintenance")
            .expect("accept task")
            .expect("accept loop ok");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "accept loop took {:?} while editor maintenance pass is paused",
            started.elapsed()
        );
        pause_tx.send(()).expect("release admitted pass");
        tokio::time::timeout(Duration::from_secs(5), worker)
            .await
            .expect("worker should exit after the admitted pass finishes")
            .expect("worker join");
    }
}
