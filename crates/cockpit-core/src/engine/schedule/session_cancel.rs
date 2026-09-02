//! Session-wide cancellation root for Stop / [`crate::daemon::proto::Request::CancelAllSessionWork`].
//!
//! The foreground turn installs a *child* of this root. Scheduled loops,
//! swarm children, background shells, and background delegates also take
//! children (or clone that turn child). `CancelTurn` cancels only the live
//! child, so TUI Ctrl+C still stops the current turn without tearing down
//! session-owned work. Stop / `CancelAllSessionWork` cancels this root,
//! which cancels every descendant — including work that outlived the
//! originating turn — then rotates so later work is not born cancelled.
//!
//! Each root has a generation. Work records the generation it was admitted
//! under. A delayed `ScheduleCommand::CancelAll` carries that generation so
//! it cannot sweep jobs registered after the rotate.

use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;

use crate::sync::lock_or_recover;

struct Slot {
    token: CancellationToken,
    generation: u64,
}

/// Shared cancellation generation for every unit of session-owned work.
///
/// Cheap to clone: every handle shares the same slot. Survives turn
/// boundaries (`cancel_current` does not).
#[derive(Clone)]
pub struct SessionWorkCancel {
    current: Arc<Mutex<Slot>>,
}

impl SessionWorkCancel {
    pub fn new() -> Self {
        Self {
            current: Arc::new(Mutex::new(Slot {
                token: CancellationToken::new(),
                generation: 0,
            })),
        }
    }

    /// The live root token. Prefer [`Self::child`] at spawn sites so a
    /// per-job cancel cannot tear down the whole session.
    pub fn token(&self) -> CancellationToken {
        lock_or_recover(&self.current).token.clone()
    }

    /// Generation of the live root. Work registered now is admitted under
    /// this generation and is the set a Stop of this generation may halt.
    pub fn generation(&self) -> u64 {
        lock_or_recover(&self.current).generation
    }

    /// A descendant cancelled when Stop fires, independent of other jobs.
    pub fn child(&self) -> CancellationToken {
        lock_or_recover(&self.current).token.child_token()
    }

    /// Mint a child and return the generation it belongs to, under one lock
    /// so a concurrent rotate cannot split the pair.
    pub fn child_with_generation(&self) -> (CancellationToken, u64) {
        let slot = lock_or_recover(&self.current);
        (slot.token.child_token(), slot.generation)
    }

    /// Mint `n` children of the same generation under one lock. Recovered
    /// batch siblings use this so Stop cannot rotate between siblings.
    pub fn children_with_generation(&self, n: usize) -> (Vec<CancellationToken>, u64) {
        let slot = lock_or_recover(&self.current);
        let children = (0..n).map(|_| slot.token.child_token()).collect();
        (children, slot.generation)
    }

    /// A child of `generation`, or an already-cancelled token if that
    /// generation is no longer current (Stop already rotated past it).
    /// Queued swarm starts use this so work admitted before Stop cannot
    /// be born on the rotated live root.
    pub fn child_for_generation(&self, generation: u64) -> CancellationToken {
        let slot = lock_or_recover(&self.current);
        if slot.generation != generation {
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            return cancelled;
        }
        slot.token.child_token()
    }

    /// Cancel every descendant and install a fresh root so subsequent work
    /// is not pre-cancelled. Returns the generation that was cancelled.
    /// Idempotent with respect to already-cancelled descendants: cancelling
    /// a cancelled token is a no-op.
    pub fn cancel_and_rotate(&self) -> u64 {
        let mut slot = lock_or_recover(&self.current);
        let cancelled = slot.generation;
        slot.token.cancel();
        slot.generation = slot.generation.wrapping_add(1);
        slot.token = CancellationToken::new();
        cancelled
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
        let cancelled = session.cancel_and_rotate();
        assert_eq!(cancelled, 0);
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
        assert_eq!(session.generation(), 1);
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

    #[test]
    fn children_with_generation_share_one_generation() {
        let session = SessionWorkCancel::new();
        let (children, generation) = session.children_with_generation(3);
        assert_eq!(generation, 0);
        assert_eq!(children.len(), 3);
        session.cancel_and_rotate();
        for child in children {
            assert!(
                child.is_cancelled(),
                "every sibling minted under one lock must die with that generation"
            );
        }
        let later = session.child();
        assert!(!later.is_cancelled());
    }

    #[test]
    fn child_for_generation_is_born_cancelled_after_rotate() {
        let session = SessionWorkCancel::new();
        let admitted = session.generation();
        session.cancel_and_rotate();
        let late = session.child_for_generation(admitted);
        assert!(
            late.is_cancelled(),
            "work admitted before Stop must not start on the rotated root"
        );
        let current = session.child_for_generation(session.generation());
        assert!(!current.is_cancelled());
    }

    #[test]
    fn child_with_generation_pairs_token_and_generation() {
        let session = SessionWorkCancel::new();
        let (child, generation) = session.child_with_generation();
        assert_eq!(generation, 0);
        assert!(!child.is_cancelled());
        assert_eq!(session.cancel_and_rotate(), 0);
        assert!(child.is_cancelled());
        let (later, later_gen) = session.child_with_generation();
        assert_eq!(later_gen, 1);
        assert!(!later.is_cancelled());
    }
}
