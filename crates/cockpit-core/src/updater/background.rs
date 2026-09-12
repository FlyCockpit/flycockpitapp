//! Periodic disabled update checks while the daemon is running.

use std::sync::Arc;
use std::time::Duration;

use crate::daemon::server::DaemonContext;

use super::{effective_update_channel, run_startup_check};

pub const BACKGROUND_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

pub fn spawn_background(ctx: Arc<DaemonContext>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(BACKGROUND_CHECK_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Startup already performed the first check during daemon boot.
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = wait_for_shutdown(ctx.clone()) => break,
            }
            if ctx.shutdown_signal().is_draining() {
                break;
            }
            match effective_update_channel() {
                Ok(channel) => {
                    let _ = run_startup_check(channel).await;
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "skipping background update check due to invalid channel configuration"
                    );
                }
            }
        }
    })
}

async fn wait_for_shutdown(ctx: Arc<DaemonContext>) {
    while !ctx.shutdown_signal().is_draining() {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
