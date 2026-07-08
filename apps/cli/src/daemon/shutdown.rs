//! Daemon-wide graceful-shutdown authority (`daemon-graceful-drain-shutdown.md`).
//!
//! A single [`ShutdownSignal`] lives on the daemon's central authority
//! (the [`crate::daemon::server::DaemonContext`]) and is shared into every
//! per-session [`crate::engine::model::Model`] the registry builds. It is
//! the real chokepoint that gates *new* outbound provider requests once a
//! drain begins — not an advisory per-call-site flag.
//!
//! The single graceful path (SIGINT/SIGTERM, explicit `StopDaemon`, the
//! ephemeral last-client/owner-exit teardown) routes through
//! [`ShutdownSignal::begin_drain`]; a *second* stop request during drain
//! routes through [`ShutdownSignal::force`], which shortens the wait to an
//! immediate force-exit. Both transitions are monotonic and idempotent, so
//! a second signal never starts a second drain, resets the deadline, or
//! deadlocks.

use std::time::Duration;

use tokio::sync::watch;

/// Grace period the daemon waits for in-flight inference + tool calls to
/// drain before it force-exits and aborts whatever is still running. Held
/// at the same 30s as [`crate::daemon::EPHEMERAL_IDLE_GRACE`] per the
/// drain-shutdown spec: an idle ephemeral daemon reaps after 30s of idle;
/// a draining daemon (of either kind) waits at most this long for work to
/// finish.
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

/// Cloneable handle to the daemon-wide shutdown state. Cheap to clone —
/// it's a `watch` sender/receiver pair behind shared ownership.
#[derive(Clone)]
pub struct ShutdownSignal {
    tx: watch::Sender<ShutdownPhase>,
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownSignal {
    /// A fresh signal in the `Running` phase.
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(ShutdownPhase::Running);
        Self { tx }
    }

    /// Current phase.
    pub fn phase(&self) -> ShutdownPhase {
        *self.tx.borrow()
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
    pub fn begin_drain(&self) -> bool {
        let mut started = false;
        self.tx.send_if_modified(|phase| {
            if *phase == ShutdownPhase::Running {
                *phase = ShutdownPhase::Draining;
                started = true;
                true
            } else {
                false
            }
        });
        started
    }

    /// Force-exit now. Monotonic: promotes `Running`/`Draining` to `Forced`
    /// and is a no-op if already forced. Used both by the grace-deadline
    /// timer and by a second stop request arriving mid-drain (which
    /// shortens the wait to an immediate force-exit).
    pub fn force(&self) {
        self.tx.send_if_modified(|phase| {
            if *phase == ShutdownPhase::Forced {
                false
            } else {
                *phase = ShutdownPhase::Forced;
                true
            }
        });
    }

    /// Subscribe for phase transitions. The inference-dispatch chokepoint
    /// can hold one of these to react the instant a drain begins.
    pub fn subscribe(&self) -> watch::Receiver<ShutdownPhase> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
