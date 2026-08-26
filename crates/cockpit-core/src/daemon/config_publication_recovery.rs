//! Bounded filesystem publication fencing for pre-socket daemon recovery.
//!
//! Recovery reads and writes authority-bearing config files only inside the
//! blocking closure passed to [`PreSocketConfigPublication::with_target`].
//! The synchronous cross-process guard can therefore never block a Tokio
//! worker and cannot accidentally survive across an async SQLite/network
//! operation. Callers must follow the order:
//!
//! `durable DB claim -> with_target(sync classify/publish) -> durable DB settle`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// One shared deadline for every file-backed recovery pass before the daemon
/// publishes its socket. A single budget prevents a sequence of contended
/// targets from multiplying startup latency.
const PRE_SOCKET_CONFIG_PUBLICATION_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug)]
pub(crate) struct PreSocketConfigPublication {
    deadline: Instant,
}

impl PreSocketConfigPublication {
    pub(crate) fn new() -> Self {
        Self {
            deadline: Instant::now() + PRE_SOCKET_CONFIG_PUBLICATION_TIMEOUT,
        }
    }

    /// Shared absolute deadline for legacy blocking recovery closures that
    /// already own their complete synchronous publication transaction.
    pub(crate) fn deadline(self) -> Instant {
        self.deadline
    }

    /// Acquire the shared cross-process config guard on a blocking worker,
    /// execute only synchronous filesystem work, and drop the guard before the
    /// future completes. `action` must not perform database or network I/O.
    pub(crate) async fn with_target<T, F>(&self, target: &Path, action: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&cockpit_config::config::HeldConfigMutationLock) -> Result<T> + Send + 'static,
    {
        let target = PathBuf::from(target);
        let deadline = self.deadline;
        tokio::task::spawn_blocking(move || {
            let Some(guard) =
                cockpit_config::config::try_hold_config_mutation_lock_until(&target, deadline)
                    .with_context(|| {
                        format!(
                            "acquiring bounded pre-socket config publication lock for {}",
                            target.display()
                        )
                    })?
            else {
                bail!(
                    "pre-socket config publication lock deadline elapsed; durable recovery intent remains pending"
                );
            };
            action(&guard)
        })
        .await
        .context("pre-socket config publication worker failed")?
    }
}
