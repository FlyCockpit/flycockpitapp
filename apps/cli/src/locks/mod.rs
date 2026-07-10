//! Daemon-wide file-lock manager.
//!
//! Per plan §4.1 / GOALS §8b the lock manager is one process-wide
//! authority that arbitrates between every agent in every session
//! attached to the daemon. The in-memory `LockState` is mirrored to
//! SQLite (`lock_state` + `lock_reads` tables, see
//! `db/migrations/0001_initial.sql`) so a daemon crash leaves a
//! coherent on-disk view the next process can resume from.
//!
//! Invariants enforced here:
//!
//!   1. At most one agent (in any session) can hold an exclusive lock
//!      on a path at a time.
//!   2. The agent that holds the lock can write to it.
//!   3. Writing a file the agent has never `read[lock]`ed in this
//!      session fails loudly — the §3c write-existing-file guard.
//!   4. Release on `unlock` / `writeunlock` / `editunlock`.
//!
//! Contention + liveness (implementation note):
//!
//!   - [`LockManager::acquire_wait`] is the **async** waiting acquire:
//!     `readlock` blocks on a busy path until the holder releases (by
//!     `*unlock`, subagent-pop release, idle-expiry, or session-detach)
//!     then acquires. Internal callers (`resume_agent`, suspend/resume)
//!     keep the synchronous [`LockManager::acquire`], which skips-on-
//!     conflict. Waiters wake via a single per-manager `tokio::Notify`
//!     (`notify_waiters()` on every release) and re-contend under the
//!     state lock — no busy-poll, no lost wakeup. The `std::sync::Mutex`
//!     is never held across an `.await`.
//!   - Locks **idle-expire** after [`LOCK_IDLE_TIMEOUT`]: every tool
//!     call by a holder refreshes its locks' last-touched timestamp
//!     ([`LockManager::touch_holder`]); the daemon's periodic sweeper
//!     ([`LockManager::sweep_expired`]) reclaims any lock idle past the
//!     threshold, persists the release, invalidates the §3c read-record
//!     (so the former holder must re-read before writing), and wakes
//!     waiters.
//!
//! Deferred to a later milestone:
//!
//!   - File-hash-based opportunistic-reacquire path.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::db::Db;
use crate::engine::validation_hint::ValidationCorrection;

pub type AgentId = String;

/// Idle-timeout after which a lock whose holder has been inactive is
/// reclaimed by the sweeper (implementation note).
/// A *liveness* timeout — every tool call by the holder refreshes the
/// deadline — not an absolute age cap, so an agent legitimately mid-task
/// on a slow file keeps its lock; only a genuinely hung/abandoned holder
/// is reclaimed. Named constant, not user-configurable.
pub const LOCK_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Outcome of [`LockManager::acquire_wait`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireWait {
    /// The lock is now held by the caller (acquired immediately or after
    /// waiting). `readlock` proceeds to read.
    Acquired,
    /// The wait was cancelled (ctrl+C on the per-turn token) before the
    /// lock came free. Nothing was acquired; no waiter is left registered.
    Cancelled,
}

#[derive(Debug)]
pub struct LockManager {
    db: Db,
    inner: Mutex<LockState>,
    /// Single per-manager wakeup hub for [`LockManager::acquire_wait`]
    /// waiters. Every release (`release`/`suspend_agent`/`sweep_expired`/
    /// session-detach) calls `notify_waiters()` so all blocked waiters
    /// re-contend under the state lock. Registering intent (`enable()`)
    /// before dropping the lock + re-checking after each wake is the
    /// no-lost-wakeup contract.
    notify: Arc<Notify>,
}

#[derive(Debug, Default)]
struct LockState {
    /// Canonical path → `(session_id, agent_id)` of the holder.
    held: HashMap<PathBuf, (Uuid, AgentId)>,
    /// Canonical path → unix-seconds the holder last touched this lock.
    /// Seeded on acquire and refreshed by [`LockManager::touch_holder`]
    /// on every tool call; the sweeper reads it to find idle holders.
    /// Kept in lock-step with `held` — every `held` insert/remove has a
    /// matching `touched` insert/remove.
    touched: HashMap<PathBuf, i64>,
    /// `(session_id, agent_id) → set of paths the agent has read this
    /// session`. Required by the §3c pre-write guard.
    read_tracker: HashMap<(Uuid, AgentId), HashSet<PathBuf>>,
    /// Canonical paths whose persisted release failed after the in-memory
    /// lock was force-released. The next acquire may overwrite the stale DB
    /// owner row for these paths only.
    forced_released: HashSet<PathBuf>,
    /// Suspended snapshots: `(session_id, agent_id) → (path → content
    /// hash at suspend time)`. Populated by `suspend_agent` when an
    /// interactive subagent loses its active slot; consulted by
    /// `resume_agent` to reacquire locks for files whose on-disk hash
    /// still matches.
    suspended: HashMap<(Uuid, AgentId), HashMap<PathBuf, u64>>,
    /// Session-scoped release snapshots: `session_id → (path → (agent_id,
    /// content hash at release time))`. Populated by [`LockManager::
    /// suspend_session`] when a session's last interactive client detaches
    /// while the session is idle (implementation note);
    /// consulted by [`LockManager::resume_session`] on reattach to reacquire
    /// locks for files whose on-disk hash still matches and that no one else
    /// took meanwhile. The agent is retained so reacquire restores the same
    /// `(session, agent)` holder the release took the lock from.
    session_released: HashMap<Uuid, HashMap<PathBuf, (AgentId, u64)>>,
    /// `(session_id, agent_id) -> lock wait edge`. Used only while
    /// `acquire_wait` is blocked so unexpected cycles fail fast instead of
    /// waiting for the idle sweeper.
    waiting: HashMap<(Uuid, AgentId), WaitingOn>,
}

#[derive(Debug, Clone)]
struct WaitingOn {
    path: PathBuf,
    holder_session: Uuid,
    holder_agent: AgentId,
}

impl LockManager {
    /// Build a new manager backed by `db`, rebuilding in-memory state
    /// from the persisted mirror. Called once at daemon startup.
    pub fn from_db(db: Db) -> Result<Self> {
        let mut state = LockState::default();

        for row in db.list_held_locks().context("loading held locks")? {
            let path = PathBuf::from(row.path);
            // `acquired_at` doubles as the last-touched field — seed the
            // sweeper's deadline from the persisted timestamp so a lock
            // held by a daemon that crashed isn't reclaimed prematurely
            // (or kept forever): its idle clock resumes where it left off.
            state.touched.insert(path.clone(), row.acquired_at);
            state.held.insert(path, (row.session_id, row.agent_id));
        }

        for (session_id, agent_id, path) in db.list_lock_reads().context("loading lock reads")? {
            state
                .read_tracker
                .entry((session_id, agent_id))
                .or_default()
                .insert(PathBuf::from(path));
        }

        Ok(Self {
            db,
            inner: Mutex::new(state),
            notify: Arc::new(Notify::new()),
        })
    }

    /// In-memory-only manager. Used by tests and the (rare) headless
    /// `cockpit run --ephemeral` path that doesn't persist anything.
    // Retained for the not-yet-wired `cockpit run --ephemeral` path.
    #[allow(dead_code)]
    pub fn in_memory(db: Db) -> Self {
        Self {
            db,
            inner: Mutex::new(LockState::default()),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Acquire the exclusive lock on `path` for `agent` within `session`.
    /// Errors loud if the lock is held by a different `(session,
    /// agent)`. Idempotent for the same holder.
    ///
    /// The **synchronous, skip-on-conflict** variant: internal callers that
    /// must not block (resume/reacquire paths) and the lock-manager test
    /// surface use it; `readlock` uses [`Self::acquire_wait`] instead. Its
    /// conflict-message string is load-bearing for those internal callers —
    /// do not change it (implementation note).
    #[allow(dead_code)]
    pub fn acquire(&self, path: &Path, agent: &str, session: Uuid) -> Result<()> {
        let canon = canonicalize(path);
        let mut state = crate::sync::lock_or_recover(&self.inner);
        match state.held.get(&canon) {
            Some((s, a)) if *s == session && a == agent => return Ok(()),
            Some((s, a)) => bail!(
                "lock on `{}` is held by `{a}` in session {s}",
                canon.display()
            ),
            None => {}
        }
        state
            .held
            .insert(canon.clone(), (session, agent.to_string()));
        state.touched.insert(canon.clone(), now_secs());
        state
            .read_tracker
            .entry((session, agent.to_string()))
            .or_default()
            .insert(canon.clone());
        let was_forced_released = state.forced_released.contains(&canon);

        // Persist before returning so a crash here doesn't leak the
        // lock as "held in memory only."
        drop(state);
        let acquire_result = if was_forced_released {
            self.db
                .lock_force_acquire_with_read(&canon, agent, session)
                .context("persisting forced lock_acquire/read")
        } else {
            self.db
                .lock_acquire_with_read(&canon, agent, session)
                .context("persisting lock_acquire/read")
        };
        if let Err(error) = acquire_result {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            if matches!(state.held.get(&canon), Some((s, a)) if *s == session && a == agent) {
                state.held.remove(&canon);
                state.touched.remove(&canon);
            }
            if let Some(reads) = state.read_tracker.get_mut(&(session, agent.to_string())) {
                reads.remove(&canon);
                if reads.is_empty() {
                    state.read_tracker.remove(&(session, agent.to_string()));
                }
            }
            return Err(error);
        }
        let mut state = crate::sync::lock_or_recover(&self.inner);
        state.forced_released.remove(&canon);
        Ok(())
    }

    /// Try to acquire `path` for `(session, agent)` **without blocking**,
    /// reporting the current holder when busy instead of erroring. Returns
    /// `Ok(None)` when the lock was acquired (free, or already this
    /// holder's), `Ok(Some((s, a)))` when it is held by a different
    /// `(session, agent)` — that holder is the one `acquire_wait` must wait
    /// on. The state lock is dropped before any DB write so it is never held
    /// across an `.await`.
    fn try_acquire(
        &self,
        canon: &Path,
        agent: &str,
        session: Uuid,
    ) -> Result<Option<(Uuid, AgentId)>> {
        let mut state = crate::sync::lock_or_recover(&self.inner);
        match state.held.get(canon) {
            Some((s, a)) if *s == session && a == agent => return Ok(None),
            Some((s, a)) => return Ok(Some((*s, a.clone()))),
            None => {}
        }
        state
            .held
            .insert(canon.to_path_buf(), (session, agent.to_string()));
        state.touched.insert(canon.to_path_buf(), now_secs());
        state
            .read_tracker
            .entry((session, agent.to_string()))
            .or_default()
            .insert(canon.to_path_buf());
        let was_forced_released = state.forced_released.contains(canon);
        drop(state);
        let acquire_result = if was_forced_released {
            self.db
                .lock_force_acquire_with_read(canon, agent, session)
                .context("persisting forced lock_acquire/read")
        } else {
            self.db
                .lock_acquire_with_read(canon, agent, session)
                .context("persisting lock_acquire/read")
        };
        if let Err(error) = acquire_result {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            if matches!(state.held.get(canon), Some((s, a)) if *s == session && a == agent) {
                state.held.remove(canon);
                state.touched.remove(canon);
            }
            if let Some(reads) = state.read_tracker.get_mut(&(session, agent.to_string())) {
                reads.remove(canon);
                if reads.is_empty() {
                    state.read_tracker.remove(&(session, agent.to_string()));
                }
            }
            return Err(error);
        }
        let mut state = crate::sync::lock_or_recover(&self.inner);
        state.forced_released.remove(canon);
        Ok(None)
    }

    /// **Async, waiting** acquire — the variant `readlock` uses. If the
    /// path is free (or already this `(session, agent)`'s) it acquires
    /// immediately, exactly like [`Self::acquire`]. If a *different*
    /// `(session, agent)` holds it, this blocks until the lock is released
    /// (by `*unlock`, subagent-pop release, idle-expiry, or session-detach)
    /// then acquires.
    ///
    /// No busy-poll and no lost wakeup: the per-manager `Notify`'s
    /// `Notified` future is registered (`enable()`) **before** the state
    /// lock is dropped, then awaited; on each wake the holder is re-checked
    /// under the lock. The `std::sync::Mutex` is never held across the
    /// `.await`.
    ///
    /// The wait races `cancel.cancelled()` (the per-turn token): on ctrl+C
    /// the future returns [`AcquireWait::Cancelled`] promptly, acquiring
    /// nothing and leaving no registered waiter (dropping the `Notified`
    /// future deregisters it). `on_wait` fires once when the call first
    /// blocks, carrying the holder it is waiting on, so the caller can
    /// surface the transient TUI indicator; it is **not** called on the
    /// immediate-acquire path.
    pub async fn acquire_wait<F>(
        &self,
        path: &Path,
        agent: &str,
        session: Uuid,
        cancel: &tokio_util::sync::CancellationToken,
        mut on_wait: F,
    ) -> Result<AcquireWait>
    where
        F: FnMut(&(Uuid, AgentId)),
    {
        let canon = canonicalize(path);
        let waiter_key = (session, agent.to_string());
        // Fast path: acquire immediately if free / already ours.
        if self.try_acquire(&canon, agent, session)?.is_none() {
            self.clear_waiter(&waiter_key);
            return Ok(AcquireWait::Acquired);
        }

        let mut waiting = false;
        loop {
            // Register intent to wait BEFORE re-checking the holder so a
            // release that happens between the check and the await can't be
            // missed (no lost wakeup). `enable()` polls the future once,
            // registering this task as a waiter for the next
            // `notify_waiters()`.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            // Re-check under the lock: a release may have landed since the
            // last attempt (or since `enable()`). If acquired, we're done.
            match self.try_acquire(&canon, agent, session)? {
                None => {
                    self.clear_waiter(&waiter_key);
                    return Ok(AcquireWait::Acquired);
                }
                Some(holder) => {
                    self.record_wait_or_cycle(&waiter_key, &canon, holder)?;
                    if !waiting {
                        waiting = true;
                        let state = crate::sync::lock_or_recover(&self.inner);
                        if let Some(edge) = state.waiting.get(&waiter_key) {
                            on_wait(&(edge.holder_session, edge.holder_agent.clone()));
                        }
                    }
                }
            }

            // Block until a release wakes us, the turn is cancelled, or a
            // bounded wait expires fail-closed. Dropping `notified` (on every
            // branch) deregisters this task from Notify.
            tokio::select! {
                _ = cancel.cancelled() => {
                    self.clear_waiter(&waiter_key);
                    return Ok(AcquireWait::Cancelled);
                }
                _ = tokio::time::sleep(LOCK_WAIT_TIMEOUT) => {
                    let context = self.wait_context(&waiter_key);
                    self.clear_waiter(&waiter_key);
                    bail!("lock wait timed out after {}s{context}", LOCK_WAIT_TIMEOUT.as_secs());
                }
                _ = &mut notified => {}
            }
        }
    }

    fn clear_waiter(&self, waiter: &(Uuid, AgentId)) {
        let mut state = crate::sync::lock_or_recover(&self.inner);
        state.waiting.remove(waiter);
    }

    fn wait_context(&self, waiter: &(Uuid, AgentId)) -> String {
        let state = crate::sync::lock_or_recover(&self.inner);
        match state.waiting.get(waiter) {
            Some(edge) => format!(
                " waiting for `{}` held by `{}` in session {}",
                edge.path.display(),
                edge.holder_agent,
                edge.holder_session
            ),
            None => String::new(),
        }
    }

    fn record_wait_or_cycle(
        &self,
        waiter: &(Uuid, AgentId),
        path: &Path,
        holder: (Uuid, AgentId),
    ) -> Result<()> {
        let mut state = crate::sync::lock_or_recover(&self.inner);
        let edge = WaitingOn {
            path: path.to_path_buf(),
            holder_session: holder.0,
            holder_agent: holder.1.clone(),
        };
        state.waiting.insert(waiter.clone(), edge);
        if let Some(cycle) = wait_cycle(&state, waiter) {
            state.waiting.remove(waiter);
            bail!("lock wait cycle detected: {cycle}");
        }
        Ok(())
    }

    #[cfg(test)]
    pub async fn acquire_wait_all_ordered(
        &self,
        paths: &[PathBuf],
        agent: &str,
        session: Uuid,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Result<AcquireWait> {
        let mut ordered: Vec<PathBuf> = paths.iter().map(|p| canonicalize(p)).collect();
        ordered.sort();
        ordered.dedup();
        let mut acquired = Vec::new();
        for path in ordered {
            match self
                .acquire_wait(&path, agent, session, cancel, |_| {})
                .await
            {
                Ok(AcquireWait::Acquired) => acquired.push(path),
                Ok(AcquireWait::Cancelled) => {
                    for path in acquired.into_iter().rev() {
                        let _ = self.release(&path, agent, session);
                    }
                    return Ok(AcquireWait::Cancelled);
                }
                Err(err) => {
                    for path in acquired.into_iter().rev() {
                        let _ = self.release(&path, agent, session);
                    }
                    return Err(err);
                }
            }
        }
        Ok(AcquireWait::Acquired)
    }

    /// Refresh the idle deadline of every lock held by `(session, agent)`.
    /// Called centrally at the engine tool-dispatch site on every tool call
    /// so an agent legitimately mid-task keeps its locks; only a hung /
    /// abandoned holder ages out. Best-effort persistence — the in-memory
    /// `touched` map is what the sweeper reads.
    pub fn touch_holder(&self, agent: &str, session: Uuid) {
        let now = now_secs();
        let touched: Vec<PathBuf> = {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            let paths: Vec<PathBuf> = state
                .held
                .iter()
                .filter(|(_, (s, a))| *s == session && a == agent)
                .map(|(p, _)| p.clone())
                .collect();
            for p in &paths {
                state.touched.insert(p.clone(), now);
            }
            paths
        };
        for p in &touched {
            if let Err(e) = self.db.lock_touch(p, agent, session, now) {
                tracing::warn!(error = %e, path = %p.display(), "persisting lock_touch failed");
            }
        }
    }

    /// Reclaim every lock whose holder has been idle longer than
    /// [`LOCK_IDLE_TIMEOUT`], measured against `now` (unix seconds —
    /// injected so tests can drive the clock without a wall-clock sleep).
    /// For each reclaimed `(session, agent, path)` this: removes the
    /// in-memory hold, **invalidates the §3c read-record** (so the former
    /// holder must re-read before writing — same as a drifted resume),
    /// persists the release, and — once any lock was reclaimed — wakes
    /// blocked `acquire_wait` waiters so they re-contend. Returns the
    /// reclaimed paths (canonical).
    pub fn sweep_expired(&self, now: i64) -> Result<Vec<PathBuf>> {
        self.sweep_expired_with_hook(now, || {})
    }

    fn sweep_expired_with_hook(&self, now: i64, hook: impl FnOnce()) -> Result<Vec<PathBuf>> {
        let cutoff = now - LOCK_IDLE_TIMEOUT.as_secs() as i64;
        // Collect under the state lock, then persist before mutating memory or
        // notifying waiters. A failed DB write leaves the live view unchanged.
        let reclaimed: Vec<(PathBuf, Uuid, AgentId)> = {
            let state = crate::sync::lock_or_recover(&self.inner);
            state
                .held
                .iter()
                .filter(|(p, _)| state.touched.get(*p).copied().unwrap_or(now) <= cutoff)
                .map(|(p, (s, a))| (p.clone(), *s, a.clone()))
                .collect()
        };

        if reclaimed.is_empty() {
            return Ok(Vec::new());
        }

        self.db
            .lock_release_and_delete_reads(&reclaimed)
            .context("persisting idle-expiry release/read cleanup")?;

        hook();

        let actually_reclaimed = {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            let mut actually_reclaimed = Vec::new();
            for (p, s, a) in &reclaimed {
                let still_held_by_snapshot = matches!(
                    state.held.get(p),
                    Some((live_s, live_a)) if live_s == s && live_a == a
                );
                let still_idle = state.touched.get(p).copied().unwrap_or(now) <= cutoff;
                if !still_held_by_snapshot || !still_idle {
                    continue;
                }

                state.held.remove(p);
                state.touched.remove(p);
                // §3c: a reclaimed lock invalidates the read-record so the
                // former holder cannot later write the file it no longer
                // holds without re-reading (mirrors the drifted-resume path).
                if let Some(reads) = state.read_tracker.get_mut(&(*s, a.clone())) {
                    reads.remove(p);
                }
                actually_reclaimed.push(p.clone());
            }
            actually_reclaimed
        };

        if !actually_reclaimed.is_empty() {
            // A blocked `readlock` on a reclaimed path now proceeds.
            self.notify.notify_waiters();
        }
        Ok(actually_reclaimed)
    }

    /// Release the lock on `path` if held by `(session, agent)`. No-op when no
    /// one holds it (idempotent — common with `*unlock` variants).
    pub fn release(&self, path: &Path, agent: &str, session: Uuid) -> Result<()> {
        let canon = canonicalize(path);
        {
            let state = crate::sync::lock_or_recover(&self.inner);
            match state.held.get(&canon) {
                Some((s, a)) if *s == session && a == agent => {}
                Some((s, a)) if a == agent => {
                    bail!(
                        "cannot release `{}` — `{a}` holds it in another session; only the owning session can release it",
                        canon.display()
                    );
                }
                Some((_, a)) => {
                    bail!(
                        "cannot release `{}` — `{a}` holds it, not you; only the holder can release it",
                        canon.display()
                    );
                }
                None => return Ok(()),
            }
        }
        self.db
            .lock_release(&canon, agent, session)
            .context("persisting lock_release")?;
        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            if matches!(state.held.get(&canon), Some((s, a)) if *s == session && a == agent) {
                state.held.remove(&canon);
                state.touched.remove(&canon);
            }
            state.forced_released.remove(&canon);
        }
        // Wake every blocked `acquire_wait` waiter so it re-contends for
        // the freed path (wake-all + re-check under the lock).
        self.notify.notify_waiters();
        Ok(())
    }

    /// Release `path` held by `(session, agent)` and drop its §3c read-record.
    /// Used when a `readlock` acquired the lock but produced no file bytes, so
    /// neither the lock nor the implicit read grant should survive. Idempotent.
    pub fn release_and_drop_read(&self, path: &Path, agent: &str, session: Uuid) -> Result<()> {
        let canon = canonicalize(path);
        self.db
            .lock_release_and_delete_reads(&[(canon.clone(), session, agent.to_string())])
            .context("persisting lock release/read cleanup")?;

        let mut released = false;
        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            if matches!(state.held.get(&canon), Some((s, a)) if *s == session && a == agent) {
                state.held.remove(&canon);
                state.touched.remove(&canon);
                released = true;
            }
            if let Some(reads) = state.read_tracker.get_mut(&(session, agent.to_string())) {
                reads.remove(&canon);
                if reads.is_empty() {
                    state.read_tracker.remove(&(session, agent.to_string()));
                }
            }
            state.forced_released.remove(&canon);
        }

        if released {
            self.notify.notify_waiters();
        }
        Ok(())
    }

    /// Release after a write has already landed on disk, forcing the
    /// in-memory hold to drop even when `lock_release` persistence fails.
    ///
    /// This intentionally does not weaken [`Self::release`]'s persist-first
    /// invariant. It is for `writeunlock`/`editunlock` only, where reporting a
    /// landed write as a plain failure and leaving memory locked would be the
    /// more dangerous inconsistency. Defensive owner surprises are treated as
    /// nothing to release so a landed write is never converted to an error.
    /// Returns `true` when the persistent release committed, `false` when the
    /// release was forced in memory only.
    pub fn release_force_memory(&self, path: &Path, agent: &str, session: Uuid) -> bool {
        let canon = canonicalize(path);
        {
            let state = crate::sync::lock_or_recover(&self.inner);
            match state.held.get(&canon) {
                Some((s, a)) if *s == session && a == agent => {}
                Some(_) | None => return true,
            }
        }

        let persist_ok = match self.db.lock_release(&canon, agent, session) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %canon.display(),
                    "lock_release persist failed after write landed; forcing in-memory release"
                );
                false
            }
        };

        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            if matches!(state.held.get(&canon), Some((s, a)) if *s == session && a == agent) {
                state.held.remove(&canon);
                state.touched.remove(&canon);
            }
            if persist_ok {
                state.forced_released.remove(&canon);
            } else {
                state.forced_released.insert(canon.clone());
            }
        }
        self.notify.notify_waiters();
        persist_ok
    }

    /// Record a successful read by `agent` in `session`. Acquisition
    /// already calls this internally; non-locking reads (the `read`
    /// tool exposed to `Build`) call it explicitly so a
    /// subsequent `writeunlock` is permitted.
    pub fn note_read(&self, path: &Path, agent: &str, session: Uuid) {
        let canon = canonicalize(path);
        if let Err(e) = self.db.lock_note_read(&canon, agent, session) {
            tracing::warn!(error = %e, "persisting note_read failed");
            return;
        }
        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            state
                .read_tracker
                .entry((session, agent.to_string()))
                .or_default()
                .insert(canon.clone());
        }
    }

    /// True if `agent` in `session` has `read`/`readlock`ed `path`.
    /// Used by the write tools to enforce §3c.
    // §3c write-guard query; retained for the lock-manager API surface.
    #[allow(dead_code)]
    pub fn has_read(&self, path: &Path, agent: &str, session: Uuid) -> bool {
        let canon = canonicalize(path);
        let state = crate::sync::lock_or_recover(&self.inner);
        state
            .read_tracker
            .get(&(session, agent.to_string()))
            .map(|s| s.contains(&canon))
            .unwrap_or(false)
    }

    /// The `(session_id, agent_id)` currently holding `path`, if any.
    // Holder-introspection query; retained for the lock-manager API surface.
    #[allow(dead_code)]
    pub fn holder(&self, path: &Path) -> Option<(Uuid, AgentId)> {
        let canon = canonicalize(path);
        let state = crate::sync::lock_or_recover(&self.inner);
        state.held.get(&canon).cloned()
    }

    /// Suspend `agent` in `session`: release every lock it holds and
    /// remember the on-disk hash of each released file so a later
    /// [`Self::resume_agent`] can reacquire the ones that didn't drift
    /// while the agent was inactive.
    ///
    /// Called by the driver when an interactive subagent loses the
    /// active slot (a deeper agent gets pushed onto the stack). The
    /// read-tracker is untouched — the §3c invariant still applies
    /// when the agent is resumed.
    ///
    /// Returns the paths that were released, in canonical form.
    pub fn suspend_agent(&self, agent: &str, session: Uuid) -> Result<Vec<PathBuf>> {
        let key = (session, agent.to_string());
        let to_release: Vec<PathBuf> = {
            let state = crate::sync::lock_or_recover(&self.inner);
            state
                .held
                .iter()
                .filter(|(_, (s, a))| *s == session && a == agent)
                .map(|(p, _)| p.clone())
                .collect()
        };
        if to_release.is_empty() {
            return Ok(Vec::new());
        }

        let mut snapshot: HashMap<PathBuf, u64> = HashMap::new();
        for path in &to_release {
            // Hash before releasing so a concurrent writer between
            // release and snapshot can't fool resume. The lock is still
            // held at this point — this `(session, agent)` is its sole
            // writer (single active writer per delegation tree).
            if let Some(h) = file_hash(path) {
                snapshot.insert(path.clone(), h);
            }
        }

        for path in &to_release {
            self.db
                .lock_release(path, agent, session)
                .with_context(|| format!("persisting suspend release for `{}`", path.display()))?;
        }
        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            for path in &to_release {
                state.held.remove(path);
                state.touched.remove(path);
            }
            state.suspended.insert(key, snapshot);
        }

        // Releasing the parent's locks frees them for cross-tree waiters.
        self.notify.notify_waiters();
        Ok(to_release)
    }

    /// Resume `agent` in `session`: for every file the agent had locked
    /// at suspend time, reacquire the lock iff the on-disk hash still
    /// matches the snapshot. Files whose content changed (or were
    /// deleted) are dropped from the snapshot — the agent must
    /// `readlock` them again before writing.
    ///
    /// Returns the paths that were successfully reacquired.
    pub fn resume_agent(&self, agent: &str, session: Uuid) -> Result<Vec<PathBuf>> {
        let key = (session, agent.to_string());
        let snapshot = {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            match state.suspended.remove(&key) {
                Some(s) => s,
                None => return Ok(Vec::new()),
            }
        };

        let mut reacquired: Vec<PathBuf> = Vec::new();
        let mut to_reacquire: Vec<PathBuf> = Vec::new();
        let mut invalidated: Vec<PathBuf> = Vec::new();
        for (path, expected) in &snapshot {
            match file_hash(path) {
                Some(now) if now == *expected => to_reacquire.push(path.clone()),
                _ => {
                    // File changed while the agent was inactive — drop
                    // the read record so a later write must explicitly
                    // readlock again (no silent re-grant on stale
                    // content).
                    let mut state = crate::sync::lock_or_recover(&self.inner);
                    if let Some(reads) = state.read_tracker.get_mut(&key) {
                        reads.remove(path);
                    }
                    invalidated.push(path.clone());
                }
            }
        }

        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            for path in &to_reacquire {
                // Conflict check: another agent might have grabbed it
                // while we were suspended. If so, skip — that agent
                // wins; on its next release the file is up for grabs.
                if state.held.contains_key(path) {
                    continue;
                }
                state
                    .held
                    .insert(path.clone(), (session, agent.to_string()));
                state.touched.insert(path.clone(), now_secs());
                reacquired.push(path.clone());
            }
        }
        for path in &reacquired {
            self.db
                .lock_acquire(path, agent, session)
                .with_context(|| format!("persisting resume reacquire for `{}`", path.display()))?;
        }
        for path in &invalidated {
            self.db
                .lock_delete_read(path, agent, session)
                .with_context(|| {
                    format!(
                        "persisting resume read invalidation for `{}`",
                        path.display()
                    )
                })?;
        }
        Ok(reacquired)
    }

    /// Transfer every currently-held lock and read guard from one agent name to
    /// another within the same session. Used for primary swaps between
    /// write-capable agents so a re-root does not strand locks under the old
    /// primary name.
    pub fn transfer_agent_locks(
        &self,
        from_agent: &str,
        to_agent: &str,
        session: Uuid,
    ) -> Result<Vec<PathBuf>> {
        if from_agent == to_agent {
            return Ok(Vec::new());
        }
        let transferred: Vec<PathBuf> = {
            let state = crate::sync::lock_or_recover(&self.inner);
            state
                .held
                .iter()
                .filter(|(_, (s, a))| *s == session && a == from_agent)
                .map(|(p, _)| p.clone())
                .collect()
        };
        if transferred.is_empty() {
            return Ok(Vec::new());
        }

        self.db
            .lock_transfer_agent(session, from_agent, to_agent)
            .context("persisting primary lock transfer")?;

        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            for path in &transferred {
                if matches!(state.held.get(path), Some((s, a)) if *s == session && a == from_agent)
                {
                    state
                        .held
                        .insert(path.clone(), (session, to_agent.to_string()));
                }
            }
            let from_key = (session, from_agent.to_string());
            let to_key = (session, to_agent.to_string());
            if let Some(from_reads) = state.read_tracker.remove(&from_key) {
                state
                    .read_tracker
                    .entry(to_key)
                    .or_default()
                    .extend(from_reads);
            }
        }

        Ok(transferred)
    }

    /// Suspend a whole **session**: release every lock held by **any**
    /// agent under `session`, snapshotting each released file's on-disk hash
    /// (alongside the holding agent) so a later [`Self::resume_session`] can
    /// reacquire the ones that didn't drift while the session was unattended.
    ///
    /// Called when a session's last interactive client detaches while the
    /// session is idle (implementation note) — the
    /// session-scoped analogue of [`Self::suspend_agent`]. Read-records are
    /// left intact so the §3c invariant still applies on reacquire. Persists
    /// each release and wakes blocked [`Self::acquire_wait`] waiters so a lock
    /// freed here lets a cross-session `readlock` proceed.
    ///
    /// Returns the paths that were released, in canonical form.
    pub fn suspend_session(&self, session: Uuid) -> Result<Vec<PathBuf>> {
        let to_release: Vec<(PathBuf, AgentId)> = {
            let state = crate::sync::lock_or_recover(&self.inner);
            state
                .held
                .iter()
                .filter(|(_, (s, _))| *s == session)
                .map(|(p, (_, a))| (p.clone(), a.clone()))
                .collect()
        };
        if to_release.is_empty() {
            return Ok(Vec::new());
        }

        let mut snapshot: HashMap<PathBuf, (AgentId, u64)> = HashMap::new();
        for (path, agent) in &to_release {
            // Hash before releasing so a concurrent writer between release and
            // snapshot can't fool resume. The lock is still held at this point.
            if let Some(h) = file_hash(path) {
                snapshot.insert(path.clone(), (agent.clone(), h));
            }
        }

        for (path, agent) in &to_release {
            self.db
                .lock_release(path, agent, session)
                .with_context(|| {
                    format!("persisting session-detach release for `{}`", path.display())
                })?;
        }
        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            for (path, _) in &to_release {
                state.held.remove(path);
                state.touched.remove(path);
            }
            state.session_released.insert(session, snapshot);
        }

        // Releasing the session's locks frees them for cross-session waiters.
        self.notify.notify_waiters();
        Ok(to_release.into_iter().map(|(p, _)| p).collect())
    }

    /// Permanently clear all lock-manager state for an ended session.
    ///
    /// This is distinct from [`Self::suspend_session`]: no resume snapshot is
    /// retained, and every read guard for every agent in the session is purged.
    pub fn end_session(&self, session: Uuid) -> Result<()> {
        self.db
            .lock_cleanup_session(session)
            .context("persisting permanent session lock cleanup")?;

        let released_any = {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            let held_before = state.held.len();
            state.held.retain(|_, (s, _)| *s != session);
            let held_paths: HashSet<PathBuf> = state.held.keys().cloned().collect();
            state.touched.retain(|path, _| held_paths.contains(path));
            state.read_tracker.retain(|(s, _), _| *s != session);
            state.suspended.retain(|(s, _), _| *s != session);
            state.session_released.remove(&session);
            state.held.len() != held_before
        };

        if released_any {
            self.notify.notify_waiters();
        }
        Ok(())
    }

    /// Resume a whole **session**: for every file the session had locked at
    /// release time, reacquire the lock for its original `(session, agent)`
    /// holder iff the on-disk hash still matches the snapshot **and** no other
    /// holder took the path meanwhile. Drifted/taken paths are dropped from the
    /// snapshot and their §3c read-record invalidated, so a later write must
    /// `readlock` again.
    ///
    /// Called from the reattach path (implementation note)
    /// — the session-scoped analogue of [`Self::resume_agent`]. A no-op (empty
    /// vec) when the session has no release snapshot, so a second concurrent
    /// attach to an already-resumed session does nothing.
    ///
    /// Returns the paths that were successfully reacquired.
    pub fn resume_session(&self, session: Uuid) -> Result<Vec<PathBuf>> {
        let snapshot = {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            match state.session_released.remove(&session) {
                Some(s) => s,
                None => return Ok(Vec::new()),
            }
        };

        let mut to_reacquire: Vec<(PathBuf, AgentId)> = Vec::new();
        let mut invalidated: Vec<(PathBuf, AgentId)> = Vec::new();
        for (path, (agent, expected)) in &snapshot {
            match file_hash(path) {
                Some(now) if now == *expected => to_reacquire.push((path.clone(), agent.clone())),
                _ => {
                    // File changed (or was deleted) while detached — drop the
                    // read record so a later write must explicitly readlock
                    // again (no silent re-grant on stale content).
                    let mut state = crate::sync::lock_or_recover(&self.inner);
                    if let Some(reads) = state.read_tracker.get_mut(&(session, agent.clone())) {
                        reads.remove(path);
                    }
                    invalidated.push((path.clone(), agent.clone()));
                }
            }
        }

        let mut reacquired: Vec<PathBuf> = Vec::new();
        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            for (path, agent) in &to_reacquire {
                // Another (session, agent) might have grabbed it while we were
                // detached. If so, skip — that holder wins — and drop this
                // session's read record so its later write must readlock again.
                if state.held.contains_key(path) {
                    if let Some(reads) = state.read_tracker.get_mut(&(session, agent.clone())) {
                        reads.remove(path);
                    }
                    invalidated.push((path.clone(), agent.clone()));
                    continue;
                }
                state.held.insert(path.clone(), (session, agent.clone()));
                state.touched.insert(path.clone(), now_secs());
                reacquired.push(path.clone());
            }
        }
        for path in &reacquired {
            // The agent paired with each reacquired path in the snapshot.
            let agent = &snapshot[path].0;
            self.db
                .lock_acquire(path, agent, session)
                .with_context(|| {
                    format!(
                        "persisting session-resume reacquire for `{}`",
                        path.display()
                    )
                })?;
        }
        for (path, agent) in &invalidated {
            self.db
                .lock_delete_read(path, agent, session)
                .with_context(|| {
                    format!(
                        "persisting session-resume read invalidation for `{}`",
                        path.display()
                    )
                })?;
        }
        Ok(reacquired)
    }

    /// Acquire write authority for `path` and hold it until the returned guard
    /// is either released after a landed write or dropped before writing.
    ///
    /// If the caller already holds the lock, the guard borrows that authority:
    /// a pre-write error leaves the original lock in place, while
    /// `release_after_write` still unlocks after a successful write. If no one
    /// holds the path, a prior read record is required and the guard acquires a
    /// temporary exclusive hold before returning.
    pub fn begin_write<'a>(
        &'a self,
        path: &Path,
        agent: &str,
        session: Uuid,
    ) -> Result<WriteGuard<'a>> {
        let canon = canonicalize(path);
        let agent_id = agent.to_string();
        let mut acquired_by_guard = false;
        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            match state.held.get(&canon) {
                Some((s, a)) if *s == session && a == agent => {}
                Some((s, a)) => bail!(
                    "cannot write `{}` — `{a}` holds the lock in session {s}; wait for it to release or pick a different file",
                    canon.display()
                ),
                None => {
                    let has_read = state
                        .read_tracker
                        .get(&(session, agent_id.clone()))
                        .map(|s| s.contains(&canon))
                        .unwrap_or(false);
                    if !has_read {
                        bail!(
                            "{}",
                            ValidationCorrection::write_requires_readlock(&canon)
                                .model_message(&crate::redact::RedactionTable::empty())
                        );
                    }
                    state
                        .held
                        .insert(canon.clone(), (session, agent_id.clone()));
                    state.touched.insert(canon.clone(), now_secs());
                    acquired_by_guard = true;
                }
            }
        }

        if acquired_by_guard
            && let Err(error) = self
                .db
                .lock_acquire(&canon, agent, session)
                .context("persisting write guard acquire")
        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            if matches!(state.held.get(&canon), Some((s, a)) if *s == session && a == agent) {
                state.held.remove(&canon);
                state.touched.remove(&canon);
            }
            return Err(error);
        }

        Ok(WriteGuard {
            locks: self,
            path: canon,
            agent: agent_id,
            session,
            acquired_by_guard,
            active: true,
        })
    }

    /// Acquire a short-lived, in-memory-only lock for daemon-owned work that
    /// is not tied to an agent session row, such as the remote project file
    /// API. It arbitrates with normal agent locks but intentionally skips DB
    /// persistence because the guard is scoped to one synchronous operation.
    pub fn acquire_transient<'a>(
        &'a self,
        path: &Path,
        agent: &str,
    ) -> Result<TransientLockGuard<'a>> {
        let canon = canonicalize(path);
        let session = Uuid::nil();
        let mut state = crate::sync::lock_or_recover(&self.inner);
        match state.held.get(&canon) {
            Some((s, a)) if *s == session && a == agent => {}
            Some((s, a)) => bail!(
                "lock on `{}` is held by `{a}` in session {s}",
                canon.display()
            ),
            None => {
                state
                    .held
                    .insert(canon.clone(), (session, agent.to_string()));
                state.touched.insert(canon.clone(), now_secs());
            }
        }
        Ok(TransientLockGuard {
            locks: self,
            path: canon,
            agent: agent.to_string(),
            session,
            active: true,
        })
    }

    /// Check the §3c invariant before a write: the caller must hold
    /// the lock, OR (no one holds it AND the caller has read the file
    /// in this session). Returns `Ok(())` if the write is permitted.
    #[allow(dead_code)]
    pub fn check_write_permitted(&self, path: &Path, agent: &str, session: Uuid) -> Result<()> {
        let canon = canonicalize(path);
        let state = crate::sync::lock_or_recover(&self.inner);
        match state.held.get(&canon) {
            Some((s, a)) if *s == session && a == agent => Ok(()),
            Some((_, a)) => bail!(
                "cannot write `{}` — `{a}` holds the lock; wait for it to release or pick a different file",
                canon.display()
            ),
            None => {
                let has_read = state
                    .read_tracker
                    .get(&(session, agent.to_string()))
                    .map(|s| s.contains(&canon))
                    .unwrap_or(false);
                if has_read {
                    Ok(())
                } else {
                    bail!(
                        "{}",
                        ValidationCorrection::write_requires_readlock(&canon)
                            .model_message(&crate::redact::RedactionTable::empty())
                    )
                }
            }
        }
    }
}

fn canonicalize(path: &Path) -> PathBuf {
    crate::tools::sandbox::effective_native_path(path).unwrap_or_else(|_| path.to_path_buf())
}

fn wait_cycle(state: &LockState, start: &(Uuid, AgentId)) -> Option<String> {
    let mut seen = HashSet::new();
    let mut current = start.clone();
    let mut parts = Vec::new();
    while seen.insert(current.clone()) {
        let edge = state.waiting.get(&current)?;
        parts.push(format!(
            "`{}` in session {} waits for `{}` held by `{}` in session {}",
            current.1,
            current.0,
            edge.path.display(),
            edge.holder_agent,
            edge.holder_session
        ));
        current = (edge.holder_session, edge.holder_agent.clone());
        if &current == start {
            return Some(parts.join("; "));
        }
    }
    None
}

#[derive(Debug)]
pub struct TransientLockGuard<'a> {
    locks: &'a LockManager,
    path: PathBuf,
    agent: AgentId,
    session: Uuid,
    active: bool,
}

impl Drop for TransientLockGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = crate::sync::lock_or_recover(&self.locks.inner);
        if matches!(state.held.get(&self.path), Some((s, a)) if *s == self.session && a == &self.agent)
        {
            state.held.remove(&self.path);
            state.touched.remove(&self.path);
        }
        drop(state);
        self.locks.notify.notify_waiters();
        self.active = false;
    }
}

#[derive(Debug)]
pub struct WriteGuard<'a> {
    locks: &'a LockManager,
    path: PathBuf,
    agent: AgentId,
    session: Uuid,
    acquired_by_guard: bool,
    active: bool,
}

impl WriteGuard<'_> {
    pub fn release_after_write(mut self) -> bool {
        self.active = false;
        self.locks
            .release_force_memory(&self.path, &self.agent, self.session)
    }
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        if !self.active || !self.acquired_by_guard {
            return;
        }
        if let Err(error) = self.locks.release(&self.path, &self.agent, self.session) {
            tracing::warn!(
                error = %error,
                path = %self.path.display(),
                "failed to release abandoned write guard"
            );
        }
    }
}

/// Current unix time in seconds — the unit `lock_state.acquired_at` (the
/// last-touched field) is stored in.
fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// 64-bit content hash of `path`'s bytes, or `None` if the file can't
/// be read. Cheap enough to call per file at suspend/resume — these
/// snapshots are taken at primary-handoff boundaries, not in any hot
/// path. Hash quality doesn't need to be cryptographic; we're just
/// detecting external drift, not defending against an adversary.
fn file_hash(path: &Path) -> Option<u64> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::io::Read;

    let file = std::fs::File::open(path).ok()?;
    let mut reader = std::io::BufReader::new(file);
    let mut h = DefaultHasher::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        buf[..n].hash(&mut h);
    }
    Some(h.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup() -> (Db, Uuid) {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        (db, s.session_id)
    }

    fn touch(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, "").unwrap();
        p
    }

    fn fail_lock_reads_inserts(db: &Db) {
        db.write_blocking(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_lock_reads_insert
                 BEFORE INSERT ON lock_reads
                 BEGIN
                     SELECT RAISE(FAIL, 'forced lock_reads insert failure');
                 END;",
            )?;
            Ok(())
        })
        .unwrap();
    }

    fn fail_lock_reads_deletes(db: &Db) {
        db.write_blocking(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_lock_reads_delete
                 BEFORE DELETE ON lock_reads
                 BEGIN
                     SELECT RAISE(FAIL, 'forced lock_reads delete failure');
                 END;",
            )?;
            Ok(())
        })
        .unwrap();
    }

    fn fail_lock_state_deletes(db: &Db) {
        db.write_blocking(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_lock_state_delete
                 BEFORE DELETE ON lock_state
                 BEGIN
                     SELECT RAISE(FAIL, 'forced lock_state delete failure');
                 END;",
            )?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn acquire_and_release_round_trip() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p, "builder", sid).unwrap();
        assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
        // Mirror landed in the DB too.
        assert_eq!(db.list_held_locks().unwrap().len(), 1);
        lm.release(&p, "builder", sid).unwrap();
        assert!(lm.holder(&p).is_none());
        assert!(db.list_held_locks().unwrap().is_empty());
    }

    #[test]
    fn double_acquire_by_same_holder_idempotent() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "builder", sid).unwrap();
        lm.acquire(&p, "builder", sid).unwrap();
    }

    #[test]
    fn acquire_rolls_back_memory_when_read_persist_fails() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        fail_lock_reads_inserts(&db);
        let lm = LockManager::in_memory(db.clone());

        let err = lm.acquire(&p, "builder", sid).unwrap_err().to_string();

        assert!(err.contains("persisting lock_acquire/read"), "{err}");
        assert!(lm.holder(&p).is_none());
        assert!(!lm.has_read(&p, "builder", sid));
        assert!(db.list_held_locks().unwrap().is_empty());
        assert!(db.list_reads_for_session(sid).unwrap().is_empty());
    }

    #[test]
    fn swarm_disjoint_scopes_coexist_same_path_serializes() {
        // The single-writer-per-tree invariant is extended for `Swarm`
        // (GOALS §24): multiple concurrent writers coexist when their write
        // scopes are disjoint (each branch its own dedicated folder), while a
        // same-path write is still serialized/rejected as today. The lock
        // manager is already path-granular and keyed by `(session, agent)`, so
        // two distinct swarm-branch writers on disjoint paths both acquire;
        // a third targeting an already-held path is rejected.
        let tmp = TempDir::new().unwrap();
        let a = touch(tmp.path(), "branch-ca.json");
        let b = touch(tmp.path(), "branch-ny.json");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        // Two swarm branches, distinct agent ids, disjoint dedicated paths:
        // both acquire — disjoint scopes coexist.
        lm.acquire(&a, "swarm-branch-1", sid).unwrap();
        lm.acquire(&b, "swarm-branch-2", sid).unwrap();
        assert_eq!(
            lm.holder(&a).map(|(_, ag)| ag).as_deref(),
            Some("swarm-branch-1")
        );
        assert_eq!(
            lm.holder(&b).map(|(_, ag)| ag).as_deref(),
            Some("swarm-branch-2")
        );
        // A third branch targeting branch-1's path is rejected — same-path
        // contention is still serialized (not silently weakened to a no-op).
        assert!(
            lm.acquire(&a, "swarm-branch-3", sid).is_err(),
            "same-path write by a different branch must still be rejected"
        );
        // And `check_write_permitted` agrees: branch-3 can't write a's path.
        assert!(lm.check_write_permitted(&a, "swarm-branch-3", sid).is_err());
    }

    #[test]
    fn different_session_cannot_acquire_held_lock() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid_a) = setup();
        let s_b = db.create_session("p", "/x", "explore").unwrap();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "builder", sid_a).unwrap();
        assert!(lm.acquire(&p, "builder", s_b.session_id).is_err());
    }

    #[test]
    fn write_requires_prior_read_per_session() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        assert!(lm.check_write_permitted(&p, "builder", sid).is_err());
        lm.note_read(&p, "builder", sid);
        lm.check_write_permitted(&p, "builder", sid).unwrap();
    }

    #[test]
    fn note_read_persistence_failure_does_not_mutate_memory() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        fail_lock_reads_inserts(&db);
        let lm = LockManager::in_memory(db);

        lm.note_read(&p, "builder", sid);

        assert!(!lm.has_read(&p, "builder", sid));
    }

    #[test]
    fn lock_holder_can_write() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "builder", sid).unwrap();
        lm.check_write_permitted(&p, "builder", sid).unwrap();
    }

    #[test]
    fn release_of_unheld_lock_is_noop() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.release(&p, "builder", sid).unwrap();
    }

    #[test]
    fn release_persist_failure_keeps_memory_held() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p, "builder", sid).unwrap();
        fail_lock_state_deletes(&db);

        let err = lm.release(&p, "builder", sid).unwrap_err().to_string();

        assert!(err.contains("persisting lock_release"), "{err}");
        assert_eq!(
            lm.holder(&p).map(|(_, agent)| agent),
            Some("builder".into())
        );
    }

    #[test]
    fn force_memory_release_drops_memory_when_persist_fails() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p, "builder", sid).unwrap();
        fail_lock_state_deletes(&db);

        let persist_ok = lm.release_force_memory(&p, "builder", sid);

        assert!(!persist_ok);
        assert!(lm.holder(&p).is_none(), "held no longer contains canon");
        assert!(
            lm.acquire(&p, "other", sid).is_ok(),
            "another agent can acquire after forced in-memory release"
        );
    }

    #[tokio::test]
    async fn force_memory_release_wakes_waiters_when_persist_fails() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = std::sync::Arc::new(LockManager::in_memory(db.clone()));
        lm.acquire(&p, "builder", sid).unwrap();
        fail_lock_state_deletes(&db);

        let waiter_lm = lm.clone();
        let waiter_path = p.clone();
        let cancel = tokio_util::sync::CancellationToken::new();
        let waiter = tokio::spawn(async move {
            waiter_lm
                .acquire_wait(&waiter_path, "other", sid, &cancel, |_| {})
                .await
        });
        tokio::task::yield_now().await;

        assert!(!lm.release_force_memory(&p, "builder", sid));

        let acquired = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("waiter should be notified")
            .expect("wait task should not panic")
            .expect("waiter acquire should succeed");
        assert_eq!(acquired, AcquireWait::Acquired);
        assert_eq!(lm.holder(&p).map(|(_, agent)| agent), Some("other".into()));
    }

    #[test]
    fn release_by_wrong_agent_errors() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "builder", sid).unwrap();
        assert!(lm.release(&p, "explore", sid).is_err());
    }

    #[test]
    fn same_agent_in_different_session_cannot_release_lock() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid_a) = setup();
        let s_b = db.create_session("p", "/x", "explore").unwrap();
        let lm = LockManager::in_memory(db.clone());

        lm.acquire(&p, "builder", sid_a).unwrap();

        let err = lm.release(&p, "builder", s_b.session_id).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("another session"),
            "wrong-session release should explain ownership scope: {msg}"
        );
        assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(sid_a));
        assert_eq!(db.list_held_locks().unwrap().len(), 1);

        lm.release(&p, "builder", sid_a).unwrap();
        assert!(lm.holder(&p).is_none());
        assert!(db.list_held_locks().unwrap().is_empty());
    }

    #[test]
    fn suspend_releases_locks_and_records_hashes() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        fs::write(&p, "hello").unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "builder", sid).unwrap();
        let released = lm.suspend_agent("builder", sid).unwrap();
        assert_eq!(released.len(), 1);
        assert!(lm.holder(&p).is_none());
    }

    #[test]
    fn suspend_session_preserves_read_state_for_resume() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        fs::write(&p, "hello").unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "builder", sid).unwrap();

        let released = lm.suspend_session(sid).unwrap();

        assert_eq!(released.len(), 1);
        assert!(lm.holder(&p).is_none());
        assert!(lm.has_read(&p, "builder", sid));
        let reacquired = lm.resume_session(sid).unwrap();
        assert_eq!(reacquired.len(), 1);
        assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
        assert!(lm.has_read(&p, "builder", sid));
    }

    #[test]
    fn resume_reacquires_when_hash_matches() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        fs::write(&p, "hello").unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "builder", sid).unwrap();
        lm.suspend_agent("builder", sid).unwrap();
        // No change to the file — resume should reacquire.
        let reacquired = lm.resume_agent("builder", sid).unwrap();
        assert_eq!(reacquired.len(), 1);
        assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
    }

    #[test]
    fn transfer_agent_locks_moves_holder_and_read_guard() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        fs::write(&p, "hello").unwrap();
        let (db, sid) = setup();
        let lm = LockManager::from_db(db.clone()).unwrap();

        lm.acquire(&p, "Build", sid).unwrap();
        let transferred = lm.transfer_agent_locks("Build", "Swarm", sid).unwrap();

        assert_eq!(transferred, vec![canonicalize(&p)]);
        assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("Swarm"));
        assert!(lm.has_read(&p, "Swarm", sid));
        assert!(!lm.has_read(&p, "Build", sid));
        let held = db.list_held_locks().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].agent_id, "Swarm");
        let reads = db.list_lock_reads().unwrap();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].1, "Swarm");
    }

    #[test]
    fn transfer_agent_locks_noop_without_held_locks() {
        let (db, sid) = setup();
        let lm = LockManager::from_db(db).unwrap();
        let transferred = lm.transfer_agent_locks("Build", "Swarm", sid).unwrap();
        assert!(transferred.is_empty());
    }

    #[test]
    fn resume_skips_when_file_changed() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        fs::write(&p, "hello").unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p, "builder", sid).unwrap();
        lm.suspend_agent("builder", sid).unwrap();
        fs::write(&p, "drift").unwrap();
        let reacquired = lm.resume_agent("builder", sid).unwrap();
        assert!(reacquired.is_empty());
        assert!(lm.holder(&p).is_none());
        // §3c: stale content invalidates the read record too.
        assert!(!lm.has_read(&p, "builder", sid));
        assert!(db.list_reads_for_session(sid).unwrap().is_empty());
    }

    #[test]
    fn resume_skips_when_another_agent_grabbed_lock() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        fs::write(&p, "hello").unwrap();
        let (db, sid) = setup();
        let s_b = db.create_session("p", "/x", "builder").unwrap();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "builder", sid).unwrap();
        lm.suspend_agent("builder", sid).unwrap();
        // Another (session, agent) takes the lock while we're suspended.
        lm.acquire(&p, "builder", s_b.session_id).unwrap();
        let reacquired = lm.resume_agent("builder", sid).unwrap();
        assert!(reacquired.is_empty());
        assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(s_b.session_id));
    }

    // ── Multi-writer acceptance (prompt `lock-manager-multi-writer.md`) ──
    //
    // The lock authority is path-granular and keyed by `(session, agent)`, so
    // multiple write-capable agents (no hard-coded `builder` name) coexist on
    // disjoint paths while same-path contention is serialized/rejected and the
    // §3c write-existing-file guard holds per writer. These assert that
    // contract for two arbitrarily-named writers.

    /// Two distinct write-capable agents writing **disjoint** paths both
    /// succeed — disjoint-scope concurrency, no hard-coded writer name.
    #[test]
    fn two_writers_disjoint_paths_both_write() {
        let tmp = TempDir::new().unwrap();
        let a = touch(tmp.path(), "a.rs");
        let b = touch(tmp.path(), "b.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        // Two arbitrarily-named writers, disjoint scopes.
        lm.acquire(&a, "writer-1", sid).unwrap();
        lm.acquire(&b, "writer-2", sid).unwrap();
        // Each may write its own held path; neither blocks the other.
        lm.check_write_permitted(&a, "writer-1", sid).unwrap();
        lm.check_write_permitted(&b, "writer-2", sid).unwrap();
    }

    /// A second writer targeting a path the first holds is rejected with a
    /// clear error — serialized/rejected, **never** silently dropped to a
    /// no-op (the path stays held by the first writer).
    #[test]
    fn two_writers_same_path_is_rejected_not_noop() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "shared.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "writer-1", sid).unwrap();
        // Acquire by the second writer is rejected, not silently accepted.
        let err = lm.acquire(&p, "writer-2", sid).unwrap_err().to_string();
        assert!(err.contains("writer-1"), "{err}");
        // And the write-permission check agrees — writer-2 cannot write it,
        // with a recovery-oriented message naming the holder and the next step.
        let werr = lm
            .check_write_permitted(&p, "writer-2", sid)
            .unwrap_err()
            .to_string();
        assert!(werr.contains("writer-1"), "{werr}");
        assert!(werr.contains("holds the lock"), "{werr}");
        // The lock was NOT weakened to a no-op: writer-1 still holds it.
        assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("writer-1"));
        lm.check_write_permitted(&p, "writer-1", sid).unwrap();
    }

    /// The §3c write-existing-file guard holds for a **second** writer: a
    /// writer that never read the file cannot write it even though another
    /// writer is active on a different path.
    #[test]
    fn write_existing_file_guard_holds_for_second_writer() {
        let tmp = TempDir::new().unwrap();
        let owned = touch(tmp.path(), "owned.rs");
        let other = touch(tmp.path(), "other.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        // Writer-1 reads + holds `owned`. Writer-2 has read nothing.
        lm.acquire(&owned, "writer-1", sid).unwrap();
        // Writer-2 may not write a file it never read (no lock held on it).
        assert!(lm.check_write_permitted(&other, "writer-2", sid).is_err());
        // After an explicit read, writer-2 may write its own disjoint file.
        lm.note_read(&other, "writer-2", sid);
        lm.check_write_permitted(&other, "writer-2", sid).unwrap();
    }

    /// Single-writer-per-tree is preserved across two distinct write-capable
    /// agents via suspend/resume: when the parent writer suspends (a child
    /// writer takes the active slot) the child can acquire the same path; on
    /// resume the parent reacquires it (hash unchanged).
    #[test]
    fn suspend_resume_serializes_two_writers_in_a_tree() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("f.rs");
        fs::write(&p, "v1").unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        // Parent writer holds the path, then suspends (child takes the slot).
        lm.acquire(&p, "parent-writer", sid).unwrap();
        let released = lm.suspend_agent("parent-writer", sid).unwrap();
        assert_eq!(released.len(), 1);
        // The child writer (distinct agent) now acquires the freed path —
        // single active writer at a time, no overlap.
        lm.acquire(&p, "child-writer", sid).unwrap();
        assert_eq!(
            lm.holder(&p).map(|(_, a)| a).as_deref(),
            Some("child-writer")
        );
        // Child releases; parent resumes and reacquires (hash unchanged).
        lm.release(&p, "child-writer", sid).unwrap();
        let reacquired = lm.resume_agent("parent-writer", sid).unwrap();
        assert_eq!(reacquired.len(), 1);
        assert_eq!(
            lm.holder(&p).map(|(_, a)| a).as_deref(),
            Some("parent-writer")
        );
    }

    /// Hash-mismatch on resume forces a re-read before write for an arbitrary
    /// writer: if the file drifted while the writer was suspended, resume does
    /// not reacquire and the §3c read record is dropped, so a later write must
    /// `readlock` again.
    #[test]
    fn hash_mismatch_on_resume_forces_reread_for_any_writer() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("f.rs");
        fs::write(&p, "v1").unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "writer-x", sid).unwrap();
        lm.suspend_agent("writer-x", sid).unwrap();
        // External drift while suspended.
        fs::write(&p, "v2-drift").unwrap();
        let reacquired = lm.resume_agent("writer-x", sid).unwrap();
        assert!(reacquired.is_empty(), "drifted file must not reacquire");
        assert!(lm.holder(&p).is_none());
        // Read record invalidated → write is now refused until a fresh read.
        assert!(!lm.has_read(&p, "writer-x", sid));
        assert!(lm.check_write_permitted(&p, "writer-x", sid).is_err());
    }

    #[test]
    fn from_db_restores_state() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        {
            let lm = LockManager::in_memory(db.clone());
            lm.acquire(&p, "builder", sid).unwrap();
            lm.note_read(&p, "builder", sid);
            // Drop the manager; the DB mirror persists.
        }
        let restored = LockManager::from_db(db).unwrap();
        let canon = std::fs::canonicalize(&p).unwrap();
        assert_eq!(restored.holder(&p), Some((sid, "builder".to_string())));
        assert!(restored.has_read(&canon, "builder", sid));
    }

    #[test]
    fn from_db_restores_read_without_held_lock() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        {
            let lm = LockManager::in_memory(db.clone());
            lm.note_read(&p, "builder", sid);
            assert!(lm.holder(&p).is_none());
        }

        let restored = LockManager::from_db(db).unwrap();
        assert!(restored.holder(&p).is_none());
        restored.check_write_permitted(&p, "builder", sid).unwrap();
    }

    #[test]
    fn write_guard_serializes_two_read_but_unlocked_writers() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "shared.rs");
        let (db, sid_a) = setup();
        let sid_b = db.create_session("p", "/b", "builder").unwrap().session_id;
        let lm = LockManager::in_memory(db);
        lm.note_read(&p, "writer-a", sid_a);
        lm.note_read(&p, "writer-b", sid_b);
        assert!(lm.holder(&p).is_none());

        let guard = lm.begin_write(&p, "writer-a", sid_a).unwrap();
        let err = lm
            .begin_write(&p, "writer-b", sid_b)
            .unwrap_err()
            .to_string();

        assert!(err.contains("writer-a"), "{err}");
        assert!(err.contains("holds the lock"), "{err}");
        assert_eq!(lm.holder(&p), Some((sid_a, "writer-a".to_string())));
        drop(guard);
        assert!(lm.holder(&p).is_none());
    }

    #[test]
    fn missing_path_spellings_normalize_to_existing_parent() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("src");
        fs::create_dir(&dir).unwrap();
        let direct = dir.join("new.rs");
        let dotted = dir.join(".").join("new.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);

        lm.note_read(&direct, "builder", sid);
        let guard = lm.begin_write(&dotted, "builder", sid).unwrap();

        assert_eq!(lm.holder(&direct), Some((sid, "builder".to_string())));
        assert_eq!(lm.holder(&dotted), Some((sid, "builder".to_string())));
        drop(guard);
        assert!(lm.holder(&direct).is_none());
    }

    #[test]
    fn missing_path_canonicalization_matches_boundary_helper_through_symlink_dotdot() {
        let root = TempDir::new().unwrap();
        let outside_parent = TempDir::new().unwrap();
        let outside_child = outside_parent.path().join("child");
        fs::create_dir(&outside_child).unwrap();
        let link = root.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_child, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&outside_child, &link).unwrap();
        let target = link.join("../new.txt");
        let expected = crate::tools::sandbox::effective_native_path(&target).unwrap();

        assert_eq!(canonicalize(&target), expected);
        assert_eq!(expected, outside_parent.path().join("new.txt"));
    }

    // ── Waiter queue + idle-expiry (`readlock-wait-and-lock-expiry.md`) ──

    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    /// A no-op `on_wait` for tests that don't assert on the wait callback.
    fn noop_on_wait(_: &(Uuid, AgentId)) {}

    /// Acquire-immediately fast path: a free lock resolves to `Acquired`
    /// without ever blocking (the `on_wait` callback never fires).
    #[tokio::test]
    async fn acquire_wait_free_path_acquires_immediately() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        let cancel = CancellationToken::new();
        let waited = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let w = waited.clone();
        let out = lm
            .acquire_wait(&p, "builder", sid, &cancel, |_| {
                w.store(true, std::sync::atomic::Ordering::Relaxed);
            })
            .await
            .unwrap();
        assert_eq!(out, AcquireWait::Acquired);
        assert!(
            !waited.load(std::sync::atomic::Ordering::Relaxed),
            "free path must not signal a wait"
        );
        assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
    }

    /// The same `(session, agent)` re-acquiring an already-held lock is
    /// idempotent on the waiting path too (no block).
    #[tokio::test]
    async fn acquire_wait_same_holder_idempotent() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        let cancel = CancellationToken::new();
        lm.acquire(&p, "builder", sid).unwrap();
        let out = lm
            .acquire_wait(&p, "builder", sid, &cancel, noop_on_wait)
            .await
            .unwrap();
        assert_eq!(out, AcquireWait::Acquired);
    }

    /// WAITER QUEUE: agent A (session 1) holds the lock; agent B (session 2)
    /// calls the waiting acquire. B does not error and does not return until A
    /// releases — then B holds it. Ordering is asserted via a controlled
    /// release (a watch channel) + `tokio::time`, never a real sleep on the
    /// acquire path.
    #[tokio::test(start_paused = true)]
    async fn acquire_wait_blocks_until_holder_releases() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid_a) = setup();
        let s_b = db.create_session("p", "/x", "explore").unwrap();
        let lm = Arc::new(LockManager::in_memory(db));

        // A holds the lock.
        lm.acquire(&p, "builder", sid_a).unwrap();

        // B starts waiting in a task.
        let cancel = CancellationToken::new();
        let lm_b = lm.clone();
        let p_b = p.clone();
        let waited_holder = Arc::new(std::sync::Mutex::new(None::<AgentId>));
        let wh = waited_holder.clone();
        let handle = tokio::spawn(async move {
            lm_b.acquire_wait(&p_b, "builder", s_b.session_id, &cancel, move |(_, a)| {
                *crate::sync::lock_or_recover(&wh) = Some(a.clone());
            })
            .await
        });

        // Let B reach its blocked state. The task is still pending: B must NOT
        // have acquired while A holds it.
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(!handle.is_finished(), "B must block while A holds the lock");
        assert_eq!(
            crate::sync::lock_or_recover(&waited_holder).as_deref(),
            Some("builder"),
            "the wait callback names the holder B is waiting on"
        );
        // A still holds it.
        assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(sid_a));

        // Controlled release: A releases → B's waiter wakes, re-contends, wins.
        lm.release(&p, "builder", sid_a).unwrap();
        let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("B's wait resolves promptly after release")
            .expect("join")
            .expect("acquire_wait ok");
        assert_eq!(out, AcquireWait::Acquired);
        // B now holds it (session 2).
        assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(s_b.session_id));
    }

    /// CANCELLED WAIT: a wait cancelled via the per-turn token returns
    /// `Cancelled` promptly, acquires nothing, and leaves no registered
    /// waiter — a subsequent release wakes nobody and the lock stays free for
    /// the original holder's re-acquire.
    #[tokio::test(start_paused = true)]
    async fn acquire_wait_cancelled_leaves_no_waiter() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid_a) = setup();
        let s_b = db.create_session("p", "/x", "explore").unwrap();
        let lm = Arc::new(LockManager::in_memory(db));
        lm.acquire(&p, "builder", sid_a).unwrap();

        let cancel = CancellationToken::new();
        let lm_b = lm.clone();
        let p_b = p.clone();
        let cancel_b = cancel.clone();
        let handle = tokio::spawn(async move {
            lm_b.acquire_wait(&p_b, "builder", s_b.session_id, &cancel_b, noop_on_wait)
                .await
        });

        // B blocks.
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(!handle.is_finished());

        // Cancel the turn → B aborts promptly with `Cancelled`.
        cancel.cancel();
        let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("cancel aborts the wait promptly")
            .expect("join")
            .expect("acquire_wait ok");
        assert_eq!(out, AcquireWait::Cancelled);

        // No phantom waiter: B never acquired (A still holds it), and a
        // subsequent release leaves the lock free with no stranded waiter.
        assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(sid_a));
        lm.release(&p, "builder", sid_a).unwrap();
        assert!(lm.holder(&p).is_none());
    }

    /// IDLE EXPIRY: a lock whose last-touched is backdated past the threshold
    /// is reclaimed by the sweep (called directly with a clock-controlled
    /// `now`), and the §3c read-record for the former holder is invalidated.
    #[test]
    fn sweep_reclaims_idle_lock_and_invalidates_read_record() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let canon = std::fs::canonicalize(&p).unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p, "builder", sid).unwrap();
        assert!(lm.has_read(&canon, "builder", sid));

        // Backdate the stored last-touched well past the threshold, then sweep
        // at "now". (No wall-clock sleep — the timestamp is the clock.)
        let now = now_secs();
        {
            let mut state = crate::sync::lock_or_recover(&lm.inner);
            *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
        }
        let reclaimed = lm.sweep_expired(now).unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert!(lm.holder(&p).is_none(), "idle lock must be reclaimed");
        // §3c read-record invalidated: a later write is refused until re-read.
        assert!(!lm.has_read(&canon, "builder", sid));
        assert!(lm.check_write_permitted(&p, "builder", sid).is_err());
        assert!(db.list_reads_for_session(sid).unwrap().is_empty());
    }

    #[test]
    fn sweep_expired_rolls_back_when_read_delete_fails() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let canon = std::fs::canonicalize(&p).unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p, "builder", sid).unwrap();
        let now = now_secs();
        {
            let mut state = crate::sync::lock_or_recover(&lm.inner);
            *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
        }
        fail_lock_reads_deletes(&db);

        assert!(lm.sweep_expired(now).is_err());

        assert_eq!(lm.holder(&p), Some((sid, "builder".to_string())));
        assert!(lm.has_read(&p, "builder", sid));
        assert_eq!(db.list_held_locks().unwrap().len(), 1);
        assert_eq!(db.list_reads_for_session(sid).unwrap().len(), 1);
    }

    #[test]
    fn sweep_skips_path_reacquired_by_other_holder_between_phases() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let canon = std::fs::canonicalize(&p).unwrap();
        let (db, sid) = setup();
        let other = db
            .create_session("p", "/other", "builder")
            .unwrap()
            .session_id;
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p, "builder", sid).unwrap();
        let now = now_secs();
        {
            let mut state = crate::sync::lock_or_recover(&lm.inner);
            *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
        }

        let reclaimed = lm
            .sweep_expired_with_hook(now, || {
                db.lock_acquire_with_read(&canon, "builder", other).unwrap();
                let mut state = crate::sync::lock_or_recover(&lm.inner);
                state
                    .held
                    .insert(canon.clone(), (other, "builder".to_string()));
                state.touched.insert(canon.clone(), now);
                state
                    .read_tracker
                    .entry((other, "builder".to_string()))
                    .or_default()
                    .insert(canon.clone());
            })
            .unwrap();

        assert!(reclaimed.is_empty());
        assert_eq!(lm.holder(&p), Some((other, "builder".to_string())));
        assert!(lm.has_read(&p, "builder", other));
        let held = db.list_held_locks().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].session_id, other);
    }

    #[test]
    fn sweep_skips_holder_refreshed_between_collect_and_mutate() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let canon = std::fs::canonicalize(&p).unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p, "builder", sid).unwrap();
        let now = now_secs();
        {
            let mut state = crate::sync::lock_or_recover(&lm.inner);
            *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
        }

        let reclaimed = lm
            .sweep_expired_with_hook(now, || {
                db.lock_acquire_with_read(&canon, "builder", sid).unwrap();
                let mut state = crate::sync::lock_or_recover(&lm.inner);
                state.touched.insert(canon.clone(), now);
                state
                    .read_tracker
                    .entry((sid, "builder".to_string()))
                    .or_default()
                    .insert(canon.clone());
            })
            .unwrap();

        assert!(reclaimed.is_empty());
        assert_eq!(lm.holder(&p), Some((sid, "builder".to_string())));
        assert!(lm.has_read(&p, "builder", sid));
        let held = db.list_held_locks().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].session_id, sid);
    }

    #[tokio::test(start_paused = true)]
    async fn sweep_returns_only_actually_evicted_count() {
        let tmp = TempDir::new().unwrap();
        let evicted = touch(tmp.path(), "evicted.rs");
        let survived = touch(tmp.path(), "survived.rs");
        let evicted_canon = std::fs::canonicalize(&evicted).unwrap();
        let survived_canon = std::fs::canonicalize(&survived).unwrap();
        let (db, sid) = setup();
        let other = db
            .create_session("p", "/other", "builder")
            .unwrap()
            .session_id;
        let waiter_session = db.create_session("p", "/waiter", "builder").unwrap();
        let lm = Arc::new(LockManager::in_memory(db.clone()));
        lm.acquire(&evicted, "builder", sid).unwrap();
        lm.acquire(&survived, "builder", sid).unwrap();

        let cancel = CancellationToken::new();
        let evicted_waiter_lm = lm.clone();
        let evicted_waiter_path = evicted.clone();
        let evicted_cancel = cancel.clone();
        let evicted_waiter = tokio::spawn(async move {
            evicted_waiter_lm
                .acquire_wait(
                    &evicted_waiter_path,
                    "builder",
                    waiter_session.session_id,
                    &evicted_cancel,
                    noop_on_wait,
                )
                .await
        });

        let survived_waiter_lm = lm.clone();
        let survived_waiter_path = survived.clone();
        let survived_cancel = cancel.clone();
        let survived_waiter = tokio::spawn(async move {
            survived_waiter_lm
                .acquire_wait(
                    &survived_waiter_path,
                    "builder",
                    waiter_session.session_id,
                    &survived_cancel,
                    noop_on_wait,
                )
                .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(!evicted_waiter.is_finished());
        assert!(!survived_waiter.is_finished());

        let now = now_secs();
        {
            let mut state = crate::sync::lock_or_recover(&lm.inner);
            *state.touched.get_mut(&evicted_canon).unwrap() =
                now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
            *state.touched.get_mut(&survived_canon).unwrap() =
                now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
        }

        let reclaimed = lm
            .sweep_expired_with_hook(now, || {
                db.lock_acquire_with_read(&survived_canon, "builder", other)
                    .unwrap();
                let mut state = crate::sync::lock_or_recover(&lm.inner);
                state
                    .held
                    .insert(survived_canon.clone(), (other, "builder".to_string()));
                state.touched.insert(survived_canon.clone(), now);
                state
                    .read_tracker
                    .entry((other, "builder".to_string()))
                    .or_default()
                    .insert(survived_canon.clone());
            })
            .unwrap();

        assert_eq!(reclaimed, vec![evicted_canon.clone()]);
        let out = tokio::time::timeout(std::time::Duration::from_secs(5), evicted_waiter)
            .await
            .expect("evicted path waiter wakes")
            .expect("join")
            .expect("acquire_wait ok");
        assert_eq!(out, AcquireWait::Acquired);
        tokio::task::yield_now().await;
        assert!(
            !survived_waiter.is_finished(),
            "waiter for a skipped path must remain blocked"
        );
        cancel.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), survived_waiter).await;
        assert_eq!(lm.holder(&survived), Some((other, "builder".to_string())));
    }

    #[test]
    fn permanent_session_end_purges_session_state_only() {
        let tmp = TempDir::new().unwrap();
        let p1 = touch(tmp.path(), "a.rs");
        let p2 = touch(tmp.path(), "b.rs");
        let p3 = touch(tmp.path(), "c.rs");
        let (db, sid) = setup();
        let other = db
            .create_session("p", "/other", "builder")
            .unwrap()
            .session_id;
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p1, "builder", sid).unwrap();
        lm.note_read(&p2, "explore", sid);
        lm.acquire(&p3, "builder", other).unwrap();
        {
            let mut state = crate::sync::lock_or_recover(&lm.inner);
            state
                .suspended
                .insert((sid, "builder".to_string()), HashMap::new());
            state.session_released.insert(sid, HashMap::new());
        }

        lm.end_session(sid).unwrap();

        assert!(lm.holder(&p1).is_none());
        assert_eq!(lm.holder(&p3), Some((other, "builder".to_string())));
        assert!(!lm.has_read(&p2, "explore", sid));
        assert!(lm.has_read(&p3, "builder", other));
        assert!(db.list_reads_for_session(sid).unwrap().is_empty());
        assert_eq!(db.list_reads_for_session(other).unwrap().len(), 1);
        let held = db.list_held_locks().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].session_id, other);
        let state = crate::sync::lock_or_recover(&lm.inner);
        assert!(!state.suspended.keys().any(|(s, _)| *s == sid));
        assert!(!state.session_released.contains_key(&sid));
    }

    /// COMPLEMENT: a lock refreshed within the window is NOT reclaimed.
    #[test]
    fn sweep_spares_recently_touched_lock() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "builder", sid).unwrap();
        // Refresh the deadline (as a tool call would), then sweep at "now".
        lm.touch_holder("builder", sid);
        let now = now_secs();
        let reclaimed = lm.sweep_expired(now).unwrap();
        assert!(
            reclaimed.is_empty(),
            "a freshly-touched lock must not be reclaimed"
        );
        assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
    }

    /// `touch_holder` pushes an about-to-expire lock back outside the window,
    /// so the very next sweep spares it (the liveness-refresh contract).
    #[test]
    fn touch_holder_refreshes_deadline_and_survives_next_sweep() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let canon = std::fs::canonicalize(&p).unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "builder", sid).unwrap();
        let now = now_secs();
        // Drive the lock to the brink of expiry…
        {
            let mut state = crate::sync::lock_or_recover(&lm.inner);
            *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
        }
        // …then a tool call refreshes it.
        lm.touch_holder("builder", sid);
        let reclaimed = lm.sweep_expired(now).unwrap();
        assert!(reclaimed.is_empty(), "refresh must spare the lock");
        assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
    }

    /// WAITER WOKEN ON EXPIRY: a blocked `acquire_wait` proceeds when the
    /// holder's lock idle-expires (the sweeper wakes waiters), with no
    /// `*unlock` ever called.
    #[tokio::test(start_paused = true)]
    async fn waiter_woken_when_holder_lock_expires() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let canon = std::fs::canonicalize(&p).unwrap();
        let (db, sid_a) = setup();
        let s_b = db.create_session("p", "/x", "explore").unwrap();
        let lm = Arc::new(LockManager::in_memory(db));
        lm.acquire(&p, "builder", sid_a).unwrap();

        // B blocks waiting on A's lock.
        let cancel = CancellationToken::new();
        let lm_b = lm.clone();
        let p_b = p.clone();
        let handle = tokio::spawn(async move {
            lm_b.acquire_wait(&p_b, "builder", s_b.session_id, &cancel, noop_on_wait)
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(!handle.is_finished(), "B blocks while A holds the lock");

        // A's lock idle-expires; the sweep reclaims it and wakes B.
        let now = now_secs();
        {
            let mut state = crate::sync::lock_or_recover(&lm.inner);
            *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
        }
        let reclaimed = lm.sweep_expired(now).unwrap();
        assert_eq!(reclaimed.len(), 1);

        let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("expiry wakes the waiter promptly")
            .expect("join")
            .expect("acquire_wait ok");
        assert_eq!(out, AcquireWait::Acquired);
        assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(s_b.session_id));
    }

    #[tokio::test(start_paused = true)]
    async fn acquire_wait_times_out_with_holder_context() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "held.rs");
        let (db, sid_a) = setup();
        let sid_b = db.create_session("p", "/b", "builder").unwrap().session_id;
        let lm = Arc::new(LockManager::in_memory(db));
        lm.acquire(&p, "holder", sid_a).unwrap();

        let cancel = CancellationToken::new();
        let waiter_lm = lm.clone();
        let waiter_path = p.clone();
        let handle = tokio::spawn(async move {
            waiter_lm
                .acquire_wait(&waiter_path, "waiter", sid_b, &cancel, noop_on_wait)
                .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(LOCK_WAIT_TIMEOUT + std::time::Duration::from_secs(1)).await;
        let err = handle.await.expect("join").unwrap_err().to_string();

        assert!(err.contains("timed out"), "{err}");
        assert!(err.contains("held.rs"), "{err}");
        assert!(err.contains("holder"), "{err}");
        assert_eq!(lm.holder(&p), Some((sid_a, "holder".to_string())));
    }

    #[tokio::test(start_paused = true)]
    async fn acquire_wait_reports_wait_for_cycle_with_paths_and_holders() {
        let tmp = TempDir::new().unwrap();
        let a = touch(tmp.path(), "a.rs");
        let b = touch(tmp.path(), "b.rs");
        let (db, sid_a) = setup();
        let sid_b = db.create_session("p", "/b", "builder").unwrap().session_id;
        let lm = Arc::new(LockManager::in_memory(db));
        lm.acquire(&a, "agent-a", sid_a).unwrap();
        lm.acquire(&b, "agent-b", sid_b).unwrap();

        let cancel_a = CancellationToken::new();
        let wait_a_lm = lm.clone();
        let b_for_a = b.clone();
        let cancel_a_task = cancel_a.clone();
        let wait_a = tokio::spawn(async move {
            wait_a_lm
                .acquire_wait(&b_for_a, "agent-a", sid_a, &cancel_a_task, noop_on_wait)
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(!wait_a.is_finished());

        let cancel_b = CancellationToken::new();
        let err = lm
            .acquire_wait(&a, "agent-b", sid_b, &cancel_b, noop_on_wait)
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("cycle"), "{err}");
        assert!(err.contains("agent-a"), "{err}");
        assert!(err.contains("agent-b"), "{err}");
        assert!(err.contains("a.rs"), "{err}");
        assert!(err.contains("b.rs"), "{err}");
        cancel_a.cancel();
        let out = wait_a.await.expect("join").unwrap();
        assert_eq!(out, AcquireWait::Cancelled);
    }

    #[tokio::test(start_paused = true)]
    async fn ordered_multi_lock_acquire_avoids_reversed_path_deadlock() {
        let tmp = TempDir::new().unwrap();
        let a = touch(tmp.path(), "a.rs");
        let b = touch(tmp.path(), "b.rs");
        let (db, sid_a) = setup();
        let sid_b = db.create_session("p", "/b", "builder").unwrap().session_id;
        let lm = Arc::new(LockManager::in_memory(db));

        let cancel_a = CancellationToken::new();
        let first_lm = lm.clone();
        let first_a = a.clone();
        let first_b = b.clone();
        let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let first = tokio::spawn(async move {
            first_lm
                .acquire_wait_all_ordered(
                    &[first_a.clone(), first_b.clone()],
                    "agent-a",
                    sid_a,
                    &cancel_a,
                )
                .await
                .unwrap();
            acquired_tx.send(()).unwrap();
            release_rx.await.unwrap();
            first_lm.release(&first_b, "agent-a", sid_a).unwrap();
            first_lm.release(&first_a, "agent-a", sid_a).unwrap();
        });
        acquired_rx.await.unwrap();

        let cancel_b = CancellationToken::new();
        let second_lm = lm.clone();
        let second_a = a.clone();
        let second_b = b.clone();
        let second = tokio::spawn(async move {
            second_lm
                .acquire_wait_all_ordered(&[second_b, second_a], "agent-b", sid_b, &cancel_b)
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            !second.is_finished(),
            "second requester waits instead of deadlocking"
        );

        release_tx.send(()).unwrap();
        first.await.unwrap();
        let out = tokio::time::timeout(std::time::Duration::from_secs(5), second)
            .await
            .expect("ordered waiter completes after release")
            .expect("join")
            .expect("acquire all ok");
        assert_eq!(out, AcquireWait::Acquired);
        assert_eq!(lm.holder(&a), Some((sid_b, "agent-b".to_string())));
        assert_eq!(lm.holder(&b), Some((sid_b, "agent-b".to_string())));
    }

    // ── Session-scoped suspend/resume (`session-detach-lock-release.md`) ──

    /// `suspend_session` releases every lock held by ANY agent under the
    /// session (not just one), leaving read-records intact, and snapshots each
    /// file's hash so a later `resume_session` can reacquire it.
    #[test]
    fn suspend_session_releases_all_agents_locks() {
        let tmp = TempDir::new().unwrap();
        let a = tmp.path().join("a.rs");
        let b = tmp.path().join("b.rs");
        fs::write(&a, "x").unwrap();
        fs::write(&b, "y").unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        // Two distinct agents under the SAME session each hold a file.
        lm.acquire(&a, "builder", sid).unwrap();
        lm.acquire(&b, "bee", sid).unwrap();
        let released = lm.suspend_session(sid).unwrap();
        assert_eq!(released.len(), 2, "both agents' locks released");
        assert!(lm.holder(&a).is_none());
        assert!(lm.holder(&b).is_none());
        // Read-records left intact (like `suspend_agent`).
        assert!(lm.has_read(&a, "builder", sid));
        assert!(lm.has_read(&b, "bee", sid));
    }

    /// A session-scoped release wakes a blocked cross-session waiter, which then
    /// acquires the freed path — the release/wake hook reuses `notify_waiters`.
    #[tokio::test(start_paused = true)]
    async fn suspend_session_wakes_cross_session_waiter() {
        let tmp = TempDir::new().unwrap();
        let p = touch(tmp.path(), "a.rs");
        let (db, sid_a) = setup();
        let s_b = db.create_session("p", "/x", "explore").unwrap();
        let lm = Arc::new(LockManager::in_memory(db));
        lm.acquire(&p, "builder", sid_a).unwrap();

        // B (a different session) blocks waiting on A's lock.
        let cancel = CancellationToken::new();
        let lm_b = lm.clone();
        let p_b = p.clone();
        let handle = tokio::spawn(async move {
            lm_b.acquire_wait(&p_b, "builder", s_b.session_id, &cancel, noop_on_wait)
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(!handle.is_finished(), "B blocks while A holds the lock");

        // Session A's last client detaches while idle → session-scoped release.
        let released = lm.suspend_session(sid_a).unwrap();
        assert_eq!(released.len(), 1);

        let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("session release wakes the waiter promptly")
            .expect("join")
            .expect("acquire_wait ok");
        assert_eq!(out, AcquireWait::Acquired);
        assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(s_b.session_id));
    }

    /// `resume_session` reacquires the lock for an unchanged file, restoring the
    /// original `(session, agent)` holder.
    #[test]
    fn resume_session_reacquires_unchanged_file() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        fs::write(&p, "hello").unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        lm.acquire(&p, "builder", sid).unwrap();
        lm.suspend_session(sid).unwrap();
        assert!(lm.holder(&p).is_none());
        // No change to the file — reattach reacquires for the same holder.
        let reacquired = lm.resume_session(sid).unwrap();
        assert_eq!(reacquired.len(), 1);
        assert_eq!(lm.holder(&p), Some((sid, "builder".to_string())));
    }

    /// A file changed while the session was detached is NOT reacquired and its
    /// §3c read-record is invalidated (a later write must `readlock` again).
    #[test]
    fn resume_session_skips_changed_file_and_invalidates_read() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        fs::write(&p, "hello").unwrap();
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p, "builder", sid).unwrap();
        lm.suspend_session(sid).unwrap();
        fs::write(&p, "drift").unwrap();
        let reacquired = lm.resume_session(sid).unwrap();
        assert!(reacquired.is_empty(), "drifted file must not reacquire");
        assert!(lm.holder(&p).is_none());
        assert!(!lm.has_read(&p, "builder", sid));
        assert!(lm.check_write_permitted(&p, "builder", sid).is_err());
        assert!(db.list_reads_for_session(sid).unwrap().is_empty());
    }

    /// A path taken by another `(session, agent)` while detached is NOT
    /// reacquired on resume, and the detached session's read-record for it is
    /// dropped so its later write must `readlock` again.
    #[test]
    fn resume_session_skips_taken_file_and_invalidates_read() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        fs::write(&p, "hello").unwrap();
        let (db, sid) = setup();
        let s_b = db.create_session("p", "/x", "builder").unwrap();
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p, "builder", sid).unwrap();
        lm.suspend_session(sid).unwrap();
        // Another session grabs the (unchanged) file while we're detached.
        lm.acquire(&p, "builder", s_b.session_id).unwrap();
        let reacquired = lm.resume_session(sid).unwrap();
        assert!(reacquired.is_empty(), "taken file must not reacquire");
        assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(s_b.session_id));
        // The detached session's read-record is invalidated.
        assert!(!lm.has_read(&p, "builder", sid));
        assert!(db.list_reads_for_session(sid).unwrap().is_empty());
        assert_eq!(db.list_reads_for_session(s_b.session_id).unwrap().len(), 1);
    }

    /// `resume_session` with no release snapshot is a no-op — the path that
    /// makes a second concurrent reattach (multi-attach) trigger nothing.
    #[test]
    fn resume_session_without_snapshot_is_noop() {
        let (db, sid) = setup();
        let lm = LockManager::in_memory(db);
        let reacquired = lm.resume_session(sid).unwrap();
        assert!(reacquired.is_empty());
        // And a second resume after a real one is also a no-op (snapshot is
        // consumed by the first), so only the FIRST reattach reacquires.
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a.rs");
        fs::write(&p, "hello").unwrap();
        lm.acquire(&p, "builder", sid).unwrap();
        lm.suspend_session(sid).unwrap();
        assert_eq!(lm.resume_session(sid).unwrap().len(), 1);
        assert!(
            lm.resume_session(sid).unwrap().is_empty(),
            "snapshot consumed: a second reattach reacquires nothing"
        );
    }
}
