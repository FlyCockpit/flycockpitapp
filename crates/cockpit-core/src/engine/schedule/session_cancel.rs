//! Session-wide cancellation root for Stop / [`crate::daemon::proto::Request::CancelAllSessionWork`].
//!
//! The foreground turn installs a *child* of this root. Scheduled loops,
//! swarm children, background shells, and background delegates also take
//! children (or clone that turn child). `CancelTurn` cancels only the live
//! child, so TUI Ctrl+C still stops the current turn without tearing down
//! session-owned work. Stop / `CancelAllSessionWork` cancels this root,
//! which cancels every descendant — including work that outlived the
//! originating turn — then rotates so later work is not born cancelled.

use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;

use crate::sync::lock_or_recover;

/// Shared cancellation generation for every unit of session-owned work.
///
/// Cheap to clone: every handle shares the same slot. Survives turn
/// boundaries (`cancel_current` does not).
#[derive(Clone)]
pub struct SessionWorkCancel {
    current: Arc<Mutex<CancellationToken>>,
}

impl SessionWorkCancel {
    pub fn new() -> Self {
        Self {
            current: Arc::new(Mutex::new(CancellationToken::new())),
        }
    }

    /// The live root token. Prefer [`Self::child`] at spawn sites so a
    /// per-job cancel cannot tear down the whole session.
    pub fn token(&self) -> CancellationToken {
        lock_or_recover(&self.current).clone()
    }

    /// A descendant cancelled when Stop fires, independent of other jobs.
    pub fn child(&self) -> CancellationToken {
        lock_or_recover(&self.current).child_token()
    }

    /// Cancel every descendant and install a fresh root so subsequent work
    /// is not pre-cancelled. Idempotent with respect to already-cancelled
    /// descendants: cancelling a cancelled token is a no-op.
    pub fn cancel_and_rotate(&self) {
        let mut slot = lock_or_recover(&self.current);
        slot.cancel();
        *slot = CancellationToken::new();
    }
}

impl Default for SessionWorkCancel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_survives_until_stop() {
        let session = SessionWorkCancel::new();
        let child = session.child();
        assert!(!child.is_cancelled());
        assert!(!session.token().is_cancelled());
        session.cancel_and_rotate();
        assert!(
            child.is_cancelled(),
            "Stop must cancel descendants minted before rotate"
        );
        assert!(
            !session.token().is_cancelled(),
            "the rotated root must be live for later work"
        );
        let later = session.child();
        assert!(
            !later.is_cancelled(),
            "work started after Stop must not be born cancelled"
        );
    }

    #[test]
    fn cancelling_a_child_does_not_cancel_siblings_or_the_root() {
        let session = SessionWorkCancel::new();
        let a = session.child();
        let b = session.child();
        a.cancel();
        assert!(a.is_cancelled());
        assert!(!b.is_cancelled());
        assert!(!session.token().is_cancelled());
    }
}
