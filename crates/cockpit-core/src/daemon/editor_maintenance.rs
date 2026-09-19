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
static TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    use crate::daemon::server::{disk_test_ctx, test_ctx};
    use std::time::{Duration, Instant};
    use tokio::sync::oneshot;

    async fn serial_lock() -> tokio::sync::MutexGuard<'static, ()> {
        TEST_SERIAL.lock().await
    }

    async fn run_editor_maintenance_with_period(ctx: Arc<DaemonContext>, period: Duration) {
        run_editor_maintenance_loop(ctx, period).await;
    }

    async fn join_within_wall_time<T>(limit: Duration, handle: tokio::task::JoinHandle<T>) -> T {
        let started = Instant::now();
        loop {
            if handle.is_finished() {
                return handle.await.expect("join handle finished");
            }
            if started.elapsed() >= limit {
                handle.abort();
                panic!("task did not finish within {limit:?} (wall clock)");
            }
            tokio::task::yield_now().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accept_loop_does_not_await_editor_maintenance() {
        let _serial = serial_lock().await;
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

    /// Regression for the pre-worker inline arm: if `run_accept_loop` ever
    /// awaits editor-lease maintenance inline again, the tick fires inside
    /// the test window (paused clock advanced past the 60s cadence) and
    /// parks on the stalled writer — the seeded expired lease forces
    /// `maintain_editor_leases` into `delete_editor_replay_and_row`'s
    /// transaction — so the loop cannot observe drain and this test fails on
    /// the accept-loop timeout.
    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn accept_loop_does_not_run_editor_maintenance_inline() {
        let dir = cockpit_test_support::isolated_tempdir();
        let db_path = dir.path().join("editor-inline.db");
        let spool = dir.path().join("spool");
        let ctx = disk_test_ctx(&db_path, &spool);
        let now_ms = chrono::Utc::now().timestamp_millis();
        ctx.db
            .insert_agent_editor_lease(crate::db::agent_editor_leases::AgentEditorLeaseRow {
                owner_digest: "inline-editor-owner".into(),
                client_operation_id: "inline-editor-op".into(),
                lease_id: "inline-editor-lease".into(),
                project_root: "/inline-editor".into(),
                agent_name: "Build".into(),
                consumed_revision: "r0".into(),
                // Any handle satisfies the open-lease schema check; the
                // delete path that would consume it never gets past the
                // stalled writer.
                snapshot_handle: Some("editor-replay:inline-editor-lease".into()),
                snapshot_identity: [0u8; 32],
                state: "open".into(),
                completion_identity: None,
                completion_handle: None,
                completion_operation_id: None,
                publication_phase: "none".into(),
                consumed_projection_identity: None,
                intended_projection_identity: None,
                publication_result_revision: None,
                consumed_config_generation: None,
                result_config_generation: None,
                terminal_result_json: None,
                terminal_error_json: None,
                expires_at_unix_ms: now_ms - 3_600_000,
                updated_at_unix_ms: now_ms - 3_600_000,
            })
            .await
            .expect("seed one expired open editor lease");
        let stall = ctx.db.stall_writer_for_test().expect("stall writer");
        let socket = dir.path().join("editor-inline.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind test unix socket");
        let accept = tokio::spawn(crate::daemon::server::run_accept_loop(
            ctx.clone(),
            listener,
        ));
        // Advance past the 60s inline cadence without `sleep`: a restored arm
        // that parks on the stalled writer is a non-timer waiter and would
        // stop paused-clock auto-advance during `sleep`.
        tokio::time::advance(EDITOR_MAINTENANCE_PERIOD + Duration::from_secs(1)).await;
        let started = Instant::now();
        assert!(
            ctx.shutdown_signal().begin_drain(),
            "test owns the first drain"
        );
        join_within_wall_time(Duration::from_secs(5), accept)
            .await
            .expect("accept loop ok");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "accept loop took {:?} while the db writer was stalled",
            started.elapsed()
        );
        drop(stall);
    }
}
