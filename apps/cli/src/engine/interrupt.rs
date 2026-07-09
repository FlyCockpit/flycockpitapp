//! Interrupt wakeup hub — the bridge that lets a blocked structural
//! tool (`question`, GOALS §3b) wait on a human answer that arrives,
//! out of band, on the daemon's `ResolveInterrupt` path.
//!
//! ## Why this exists
//!
//! The `question` tool runs inside the driver's tool-dispatch loop. It
//! must *block* until the user answers. But the answer round-trips
//! daemon ↔ client over NDJSON and lands in the **session worker's**
//! work loop ([`crate::daemon::session_worker`]) as
//! `SessionWork::ResolveInterrupt` — a different task from the one the
//! tool call is suspended in. The two need a rendezvous.
//!
//! The hub is that rendezvous: a shared registry of
//! `interrupt_id -> oneshot::Sender<ResolveResponse>`. The tool
//! [`register`](InterruptHub::register)s a channel, persists the
//! interrupt, emits the `InterruptRaised` event, and awaits the
//! receiver. The worker, on `ResolveInterrupt`, persists the response
//! and calls [`resolve`](InterruptHub::resolve), which fires the
//! matching sender and wakes the tool.
//!
//! ## Headless / no client
//!
//! Nothing in the hub times out. If no interactive client is attached
//! (headless daemon, scheduled run), the interrupt simply parks in the
//! `needs_attention` table and the tool's `await` blocks indefinitely
//! until *some* client answers — the TUI today, the remote dashboard
//! later (GOALS north star). That is the intended behavior.
//!
//! ## Single authority, like the lock manager
//!
//! One hub per session worker; both the driver (which threads it into
//! every [`crate::engine::tool::ToolCtx`]) and the worker's resolve
//! handler hold an `Arc` to the same instance. The `Mutex` is held only
//! for map insert/remove — never across an `.await`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::sync::lock_or_recover;

use tokio::sync::{broadcast, oneshot};
use uuid::Uuid;

use crate::daemon::proto::{self, InterruptQuestionSet, ResolveResponse};

/// Shared interrupt rendezvous. Cheap to clone via `Arc`.
pub struct InterruptHub {
    /// Pending wakeups keyed by interrupt id. A sender is inserted by
    /// [`Self::register`] and removed when [`Self::resolve`] fires it
    /// (or when the [`PendingInterrupt`] guard drops on cancellation).
    waiters: Mutex<HashMap<Uuid, oneshot::Sender<ResolveResponse>>>,
    /// Outbound event channel to attached clients. `None` in
    /// non-daemon paths (tool unit tests, the standalone run shim) where
    /// no client is listening — raising still works; the event is just
    /// not broadcast. Cloned from the session worker's fan-out sender.
    events: Option<broadcast::Sender<proto::Event>>,
    /// Count of attached *interactive* clients — ones that can answer an
    /// interrupt (the TUI; later the remote dashboard). A `cockpit run`
    /// event pump attaches but cannot answer, so it does not count. The
    /// server bumps this on interactive attach and decrements on detach
    /// via the shared `Arc`. Read by the loop guard (GOALS §1/§12) to
    /// decide headless behavior: 0 means "no human to prompt → don't
    /// block, auto-reject the repeat."
    interactive_clients: Arc<AtomicUsize>,
}

impl InterruptHub {
    /// Build a hub wired to the worker's client event fan-out, sharing an
    /// externally-owned interactive-client counter so the daemon's attach
    /// lifecycle and the hub read the same cell. The session worker owns
    /// the counter and exposes it on its handle for the server to bump as
    /// interactive clients attach/detach; the loop guard reads it via
    /// [`Self::is_interactive_attached`].
    pub fn new(
        events: broadcast::Sender<proto::Event>,
        interactive_clients: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            waiters: Mutex::new(HashMap::new()),
            events: Some(events),
            interactive_clients,
        }
    }

    /// Build a detached hub with no client fan-out. Used where no client
    /// is attached (tests, the standalone shim): wakeups still work via
    /// [`Self::resolve`], but no `InterruptRaised` event is emitted.
    pub fn detached() -> Self {
        Self {
            waiters: Mutex::new(HashMap::new()),
            events: None,
            interactive_clients: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Whether at least one interactive client (one that can answer an
    /// interrupt) is currently attached. `false` means headless: the loop
    /// guard must not block on a prompt and instead auto-rejects the
    /// repeat. A detached hub (tests / standalone shim) is always headless.
    pub fn is_interactive_attached(&self) -> bool {
        self.interactive_clients.load(Ordering::SeqCst) > 0
    }

    /// Register a wakeup for `interrupt_id` and return the guard the
    /// caller awaits. The guard removes its registry entry on drop, so a
    /// tool whose future is cancelled (e.g. the worker shuts down) never
    /// leaves a dangling sender.
    pub fn register(&self, interrupt_id: Uuid) -> PendingInterrupt<'_> {
        let (tx, rx) = oneshot::channel();
        lock_or_recover(&self.waiters).insert(interrupt_id, tx);
        PendingInterrupt {
            hub: self,
            interrupt_id,
            rx: Some(rx),
        }
    }

    /// Emit `InterruptRaised` to attached clients (no-op when detached).
    /// The `question` tool calls this right after persisting the
    /// interrupt and registering the wakeup, so a client can render the
    /// answering dialog.
    pub fn emit_raised(
        &self,
        session_id: Uuid,
        interrupt_id: Uuid,
        agent: &str,
        description: &str,
        questions: InterruptQuestionSet,
    ) {
        if let Some(events) = &self.events {
            // `send` errors only when there are no subscribers — fine,
            // the interrupt still parks in the DB for the next client.
            let _ = events.send(proto::Event::InterruptRaised {
                session_id,
                interrupt_id,
                agent: agent.to_string(),
                description: description.to_string(),
                question: None,
                questions: Some(questions),
            });
        }
    }

    /// Broadcast the session's current gitignore read-allowlist to attached
    /// clients (no-op when detached). Called right after a "Approve for this
    /// session" outcome lands a new glob, so the TUI `@`-tag popup re-includes
    /// the session-approved entry without a restart
    /// (implementation note). Carries the full set
    /// (replace, not delta); only the allow-set is ever sent. Reuses the same
    /// per-session event fan-out the worker uses for `RedactionState`.
    pub fn emit_gitignore_allow(&self, session_id: Uuid, allow: Vec<String>) {
        if let Some(events) = &self.events {
            // `send` errors only when there are no subscribers — fine; an
            // attaching client re-hydrates the set via the attach broadcast.
            let _ = events.send(proto::Event::GitignoreAllow { session_id, allow });
        }
    }

    /// Deliver a resolution to whoever is blocked on `interrupt_id`.
    /// Returns `true` if a waiter was woken. `false` means no tool was
    /// blocked on it locally — e.g. the worker restarted and the
    /// in-flight tool future was dropped, or the resolution targets a
    /// `schedule` needs-attention nudge that nobody awaits. The DB row has
    /// already been updated by the caller regardless.
    pub fn resolve(&self, interrupt_id: Uuid, response: ResolveResponse) -> bool {
        let Some(tx) = lock_or_recover(&self.waiters).remove(&interrupt_id) else {
            return false;
        };
        tx.send(response).is_ok()
    }
}

/// Guard returned by [`InterruptHub::register`]. Awaiting it (via
/// [`Self::wait`]) blocks until [`InterruptHub::resolve`] fires for this
/// id; dropping it without resolving removes the registry entry so no
/// stale sender lingers.
pub struct PendingInterrupt<'a> {
    hub: &'a InterruptHub,
    interrupt_id: Uuid,
    /// `Option` so [`Self::wait`] can take the receiver out of `self`
    /// without fighting the `Drop` guard (a `Drop` type can't be moved
    /// out of field-by-field).
    rx: Option<oneshot::Receiver<ResolveResponse>>,
}

impl PendingInterrupt<'_> {
    /// Block until resolved. Returns the human's resolution, or
    /// [`ResolveResponse::Cancel`] if the wakeup channel closed without
    /// a value (only happens on worker teardown — the agent treats it
    /// as a dismissal, the safe default).
    pub async fn wait(mut self) -> ResolveResponse {
        let rx = self.rx.take().expect("wait called once");
        match rx.await {
            Ok(response) => response,
            Err(_) => ResolveResponse::Cancel,
        }
    }
}

impl Drop for PendingInterrupt<'_> {
    fn drop(&mut self) {
        // Idempotent: `resolve` already removed it on the happy path.
        lock_or_recover(&self.hub.waiters).remove(&self.interrupt_id);
    }
}

/// The selected option id from a resolved single-select interrupt
/// (unwrapping a one-question `Batch`); `Cancel` / other shapes → `None`.
pub fn selected_id_of(resp: &ResolveResponse) -> Option<String> {
    match resp {
        ResolveResponse::Single { selected_id } => Some(selected_id.clone()),
        ResolveResponse::Batch { responses } => match responses.first() {
            Some(ResolveResponse::Single { selected_id }) => Some(selected_id.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// The free-text answer from a resolved free-text interrupt (unwrapping a
/// one-question `Batch`); `Cancel` / other shapes → `None`.
pub fn freetext_of(resp: &ResolveResponse) -> Option<String> {
    match resp {
        ResolveResponse::Freetext { text } => Some(text.clone()),
        ResolveResponse::Batch { responses } => match responses.first() {
            Some(ResolveResponse::Freetext { text }) => Some(text.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Persist → register → emit → wait: raise an interrupt with `set` and
/// block until the user answers (or dismisses). On a DB failure (can't
/// persist) returns [`ResolveResponse::Cancel`] so the caller treats it as
/// a dismissal rather than hanging. `log_label` prefixes the warn on that
/// failure. Shared by the driver and in-turn raise wrappers.
pub async fn raise_and_wait(
    db: &crate::db::Db,
    interrupts: &InterruptHub,
    session_id: Uuid,
    agent: &str,
    description: &str,
    set: InterruptQuestionSet,
    log_label: &str,
) -> ResolveResponse {
    let interrupt_id = match db.raise_interrupt_questions(session_id, agent, description, &set) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, "{log_label}: raising interrupt failed");
            return ResolveResponse::Cancel;
        }
    };
    let pending = interrupts.register(interrupt_id);
    interrupts.emit_raised(session_id, interrupt_id, agent, description, set);
    pending.wait().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_wakes_a_registered_waiter() {
        let hub = InterruptHub::detached();
        let id = Uuid::new_v4();
        let pending = hub.register(id);
        assert!(hub.resolve(
            id,
            ResolveResponse::Single {
                selected_id: "y".into(),
            }
        ));
        let got = pending.wait().await;
        assert!(matches!(got, ResolveResponse::Single { selected_id } if selected_id == "y"));
    }

    #[tokio::test]
    async fn resolve_unknown_id_returns_false() {
        let hub = InterruptHub::detached();
        assert!(!hub.resolve(Uuid::new_v4(), ResolveResponse::Cancel));
    }

    #[tokio::test]
    async fn dropping_pending_clears_the_registry() {
        let hub = InterruptHub::detached();
        let id = Uuid::new_v4();
        let pending = hub.register(id);
        drop(pending);
        // No waiter remains, so a late resolve finds nothing.
        assert!(!hub.resolve(id, ResolveResponse::Cancel));
    }

    #[tokio::test]
    async fn poisoned_waiter_mutex_recovers_without_panicking() {
        let hub = InterruptHub::detached();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = hub.waiters.lock().unwrap();
            panic!("poison waiter mutex");
        }));

        let id = Uuid::new_v4();
        let pending = hub.register(id);
        assert!(hub.resolve(id, ResolveResponse::Cancel));
        assert!(matches!(pending.wait().await, ResolveResponse::Cancel));
    }

    #[tokio::test]
    async fn dropped_sender_resolves_to_cancel() {
        // Worker teardown: the registry is cleared (sender dropped)
        // while a tool is still awaiting. `wait` must yield `Cancel`.
        let hub = InterruptHub::detached();
        let id = Uuid::new_v4();
        let pending = hub.register(id);
        lock_or_recover(&hub.waiters).clear();
        assert!(matches!(pending.wait().await, ResolveResponse::Cancel));
    }
}
