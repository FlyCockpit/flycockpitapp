//! Daemon-wide graceful-shutdown authority (`daemon-graceful-drain-shutdown.md`).
//!
//! A single [`ShutdownSignal`] lives on the daemon's central authority
//! (the [`crate::daemon::server::DaemonContext`]) and is shared into every
//! per-session [`crate::engine::model::Model`] the registry builds. It is
//! the real chokepoint that gates *new* outbound provider requests once a
//! drain begins — not an advisory per-call-site flag.
//!
//! The single graceful path (SIGINT/SIGTERM, explicit `StopDaemon`, and
//! ephemeral last-client teardown) routes through
//! [`ShutdownSignal::begin_drain`]; a *second* stop request during drain
//! routes through [`ShutdownSignal::force`], which shortens the wait to an
//! immediate force-exit. Both transitions are monotonic and idempotent, so
//! a second signal never starts a second drain, resets the deadline, or
//! deadlocks.
//!
//! Phase transitions and guidance-maintenance admission share one mutex so a
//! pass cannot start after drain has begun. That boundary is the lock, not a
//! racy `is_draining()` check beside the worker.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, watch};

use crate::sync::lock_or_recover;

/// Grace period the daemon waits for in-flight inference + tool calls to
/// drain before it force-exits and aborts whatever is still running. Held
/// while a draining daemon (of either lifetime) waits at most this long for
/// work to finish.
pub const SHUTDOWN_DRAIN_GRACE: Duration = Duration::from_secs(30);

/// The daemon's lifecycle phase. Monotonic: `Running → Draining → Forced`.
/// Never moves backwards, so an observer that has seen `Draining` will
/// never again see `Running`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    /// Normal operation: new provider requests dispatch freely.
    Running,
    /// Drain in progress: new provider requests are gated (refused at the
    /// dispatch chokepoint) and new user work is rejected; in-flight work
    /// runs to completion within the grace window.
    Draining,
    /// Grace deadline hit (or a second stop request arrived during drain):
    /// the daemon is force-exiting and any outstanding work is aborted.
    Forced,
}

impl ShutdownPhase {
    /// Whether new outbound provider requests must be refused in this
    /// phase. True for both `Draining` and `Forced`.
    fn gates_new_requests(self) -> bool {
        !matches!(self, ShutdownPhase::Running)
    }
}

struct GuidanceAdmission {
    phase: ShutdownPhase,
    admitted_guidance_passes: usize,
}

/// Cloneable handle to the daemon-wide shutdown state. Cheap to clone —
/// it's a `watch` sender/receiver pair behind shared ownership.
#[derive(Clone)]
pub struct ShutdownSignal {
    tx: watch::Sender<ShutdownPhase>,
    admission: Arc<Mutex<GuidanceAdmission>>,
    /// Notified whenever an admitted maintenance pass is dropped. Drain
    /// waiters park on this instead of polling the counter.
    maintenance_drained: Arc<Notify>,
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard for one admitted guidance-maintenance pass. Dropping it releases the
/// admission slot. The worker holds this for the whole flush+expire pass.
#[must_use]
pub(crate) struct GuidanceMaintenancePass {
    admission: Arc<Mutex<GuidanceAdmission>>,
    maintenance_drained: Arc<Notify>,
}

impl Drop for GuidanceMaintenancePass {
    fn drop(&mut self) {
        {
            let mut inner = lock_or_recover(&self.admission);
            inner.admitted_guidance_passes = inner.admitted_guidance_passes.saturating_sub(1);
        }
        // Wake drain waiters without holding the admission mutex.
        self.maintenance_drained.notify_one();
    }
}

impl ShutdownSignal {
    /// A fresh signal in the `Running` phase.
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(ShutdownPhase::Running);
        Self {
            tx,
            admission: Arc::new(Mutex::new(GuidanceAdmission {
                phase: ShutdownPhase::Running,
                admitted_guidance_passes: 0,
            })),
            maintenance_drained: Arc::new(Notify::new()),
        }
    }

    /// Current phase.
    ///
    /// Reads `admission.phase` under the admission mutex. Do not hold a
    /// [`watch::Receiver::borrow`] across [`Self::begin_drain`] or
    /// [`Self::force`]: those methods update phase under the same mutex and
    /// call `send_replace`, which would deadlock if a borrow is active.
    pub fn phase(&self) -> ShutdownPhase {
        lock_or_recover(&self.admission).phase
    }

    /// Whether a drain has begun (phase is `Draining` or `Forced`). Used by
    /// the new-user-work gate and the inference-dispatch chokepoint.
    pub fn is_draining(&self) -> bool {
        self.phase().gates_new_requests()
    }

    /// Whether the force deadline has been crossed.
    pub fn is_forced(&self) -> bool {
        matches!(self.phase(), ShutdownPhase::Forced)
    }

    /// Begin draining. Idempotent and monotonic: a no-op if a drain (or a
    /// force) is already in progress, so a second `StopDaemon`/signal can
    /// never start a second drain or reset the deadline. Returns `true`
    /// only on the transition that actually started the drain — the caller
    /// uses that to run the one-and-only teardown.
    ///
    /// Shares the admission mutex with [`Self::admit_guidance_maintenance`],
    /// so a pass cannot be admitted once this returns.
    pub fn begin_drain(&self) -> bool {
        let mut inner = lock_or_recover(&self.admission);
        if inner.phase != ShutdownPhase::Running {
            return false;
        }
        inner.phase = ShutdownPhase::Draining;
        self.tx.send_replace(ShutdownPhase::Draining);
        true
    }

    /// Force-exit now. Monotonic: promotes `Running`/`Draining` to `Forced`
    /// and is a no-op if already forced. Used both by the grace-deadline
    /// timer and by a second stop request arriving mid-drain (which
    /// shortens the wait to an immediate force-exit).
    pub fn force(&self) {
        let mut inner = lock_or_recover(&self.admission);
        if inner.phase == ShutdownPhase::Forced {
            return;
        }
        inner.phase = ShutdownPhase::Forced;
        self.tx.send_replace(ShutdownPhase::Forced);
    }

    /// Admit one guidance-maintenance pass. Succeeds only while phase is
    /// `Running`, under the same mutex [`Self::begin_drain`] takes. After
    /// drain starts this returns `None` and the caller must not start a pass.
    pub(crate) fn admit_guidance_maintenance(&self) -> Option<GuidanceMaintenancePass> {
        let mut inner = lock_or_recover(&self.admission);
        if inner.phase != ShutdownPhase::Running {
            return None;
        }
        inner.admitted_guidance_passes = inner.admitted_guidance_passes.saturating_add(1);
        Some(GuidanceMaintenancePass {
            admission: Arc::clone(&self.admission),
            maintenance_drained: Arc::clone(&self.maintenance_drained),
        })
    }

    /// Subscribe for phase transitions. The inference-dispatch chokepoint
    /// can hold one of these to react the instant a drain begins.
    pub fn subscribe(&self) -> watch::Receiver<ShutdownPhase> {
        self.tx.subscribe()
    }

    /// Number of admitted maintenance passes still running.
    pub(crate) fn admitted_guidance_passes(&self) -> usize {
        lock_or_recover(&self.admission).admitted_guidance_passes
    }

    /// Wait until every admitted maintenance pass has finished, or `deadline`
    /// passes. Returns `true` when all admitted passes finished and `false`
    /// when the deadline expired with passes still admitted — the caller must
    /// surface that (a pass may still own the writer) rather than proceed
    /// silently.
    ///
    /// Event-driven: waiters park on the drop [`Notify`] rather than polling
    /// the counter. Callers share this deadline with the rest of their drain
    /// so a stuck pass consumes the same grace window, not an extra one.
    pub(crate) async fn wait_for_admitted_maintenance_drain(
        &self,
        deadline: tokio::time::Instant,
    ) -> bool {
        loop {
            if lock_or_recover(&self.admission).admitted_guidance_passes == 0 {
                return true;
            }
            tokio::select! {
                _ = self.maintenance_drained.notified() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    return lock_or_recover(&self.admission).admitted_guidance_passes == 0;
                }
            }
        }
    }

    /// Resolves when the signal becomes `Forced` (or the publisher is dropped).
    /// Drain alone does not resolve this — an already-admitted pass may finish
    /// during normal grace.
    pub(crate) async fn wait_until_forced(&self) {
        let mut rx = self.subscribe();
        loop {
            if self.is_forced() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Instant;

    #[test]
    fn begin_drain_is_monotonic_and_idempotent() {
        let sig = ShutdownSignal::new();
        assert_eq!(sig.phase(), ShutdownPhase::Running);
        assert!(!sig.is_draining());

        // First call starts the drain.
        assert!(sig.begin_drain());
        assert_eq!(sig.phase(), ShutdownPhase::Draining);
        assert!(sig.is_draining());

        // Second call (second signal / StopDaemon) does NOT restart it.
        assert!(!sig.begin_drain());
        assert_eq!(sig.phase(), ShutdownPhase::Draining);
    }

    #[test]
    fn force_promotes_and_never_regresses() {
        let sig = ShutdownSignal::new();
        sig.begin_drain();
        sig.force();
        assert_eq!(sig.phase(), ShutdownPhase::Forced);
        assert!(sig.is_forced());
        assert!(sig.is_draining());

        // begin_drain after force is a no-op — no regress to Draining.
        assert!(!sig.begin_drain());
        assert_eq!(sig.phase(), ShutdownPhase::Forced);

        // force again is idempotent.
        sig.force();
        assert_eq!(sig.phase(), ShutdownPhase::Forced);
    }

    #[test]
    fn force_can_skip_straight_from_running() {
        let sig = ShutdownSignal::new();
        sig.force();
        assert_eq!(sig.phase(), ShutdownPhase::Forced);
    }

    #[test]
    fn admit_succeeds_only_while_running() {
        let sig = ShutdownSignal::new();
        let pass = sig
            .admit_guidance_maintenance()
            .expect("running daemon admits one pass");
        drop(pass);

        assert!(sig.begin_drain());
        assert!(
            sig.admit_guidance_maintenance().is_none(),
            "drain must refuse new guidance-maintenance admission"
        );

        sig.force();
        assert!(sig.admit_guidance_maintenance().is_none());
    }

    #[test]
    fn subscribe_notifies_after_mutex_phase_change() {
        let sig = ShutdownSignal::new();
        let rx = sig.subscribe();
        assert!(sig.begin_drain());
        assert_eq!(*rx.borrow(), ShutdownPhase::Draining);
        sig.force();
        assert_eq!(*rx.borrow(), ShutdownPhase::Forced);
    }

    #[test]
    fn concurrent_admits_cannot_succeed_after_drain() {
        let sig = ShutdownSignal::new();
        let stop = AtomicBool::new(false);
        let post_drain_success = AtomicUsize::new(0);

        thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    while !stop.load(Ordering::Acquire) {
                        let _pass = sig.admit_guidance_maintenance();
                        thread::yield_now();
                    }
                    for _ in 0..200 {
                        if sig.admit_guidance_maintenance().is_some() {
                            post_drain_success.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                });
            }
            thread::yield_now();
            assert!(sig.begin_drain());
            stop.store(true, Ordering::Release);
        });

        assert_eq!(
            post_drain_success.load(Ordering::SeqCst),
            0,
            "an admit that ran after begin_drain returned observed Running"
        );
        assert!(sig.admit_guidance_maintenance().is_none());
    }

    #[tokio::test]
    async fn wait_until_forced_ignores_drain_and_returns_on_force() {
        let sig = ShutdownSignal::new();
        let waiting = sig.clone();
        let wait = tokio::spawn(async move { waiting.wait_until_forced().await });
        sig.begin_drain();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !wait.is_finished(),
            "drain must not cancel an admitted wait"
        );
        sig.force();
        let started = Instant::now();
        tokio::time::timeout(Duration::from_millis(200), wait)
            .await
            .expect("forced wait should resolve promptly")
            .expect("wait task");
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn maintenance_drain_wait_wakes_on_pass_drop() {
        let sig = ShutdownSignal::new();
        let pass = sig
            .admit_guidance_maintenance()
            .expect("running daemon admits one pass");
        let waiter = {
            let sig = sig.clone();
            tokio::spawn(async move {
                sig.wait_for_admitted_maintenance_drain(
                    tokio::time::Instant::now() + Duration::from_secs(60),
                )
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !waiter.is_finished(),
            "drain wait must not resolve while a pass is admitted"
        );
        drop(pass);
        let drained = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("pass drop must wake the drain waiter without polling")
            .expect("waiter task");
        assert!(drained);
    }

    #[tokio::test]
    async fn maintenance_drain_wait_reports_deadline_expiry_instead_of_waiting() {
        let sig = ShutdownSignal::new();
        let _pass = sig
            .admit_guidance_maintenance()
            .expect("running daemon admits one pass");
        let started = Instant::now();
        let drained = sig
            .wait_for_admitted_maintenance_drain(
                tokio::time::Instant::now() + Duration::from_millis(50),
            )
            .await;
        assert!(
            !drained,
            "deadline expiry with a live admitted pass must be reported, not silent"
        );
        assert!(started.elapsed() >= Duration::from_millis(50));
        drop(_pass);
        assert!(
            sig.wait_for_admitted_maintenance_drain(
                tokio::time::Instant::now() + Duration::from_millis(50)
            )
            .await
        );
    }
}
