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
                            ValidationCorrection::write_requires_readlock(&canon).model_message()
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
                        ValidationCorrection::write_requires_readlock(&canon).model_message()
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
mod tests;
