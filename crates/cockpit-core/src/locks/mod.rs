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
//!   4. Tool-acquired write locks release when `writeunlock` / `editunlock`
//!      exits; pre-existing holds release on `unlock`.
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
//! Hash-based drift checks:
//!
//!   - Read records carry a best-effort content hash. A write that relies on
//!     a read record rather than a held lock is rejected if the file changed
//!     after the read, or if the recorded hash is unknown.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::db::Db;
use crate::engine::validation_hint::ValidationCorrection;

mod acquire;
mod suspension;
mod waitgraph;

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
    /// `(session_id, agent_id) → path → content hash captured when the agent
    /// read it in this session`. Required by the §3c pre-write guard. `None`
    /// means the record was restored without a known hash and cannot authorize
    /// a write.
    read_tracker: HashMap<(Uuid, AgentId), HashMap<PathBuf, Option<u64>>>,
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
        if self.acquired_by_guard {
            self.locks
                .release_force_memory(&self.path, &self.agent, self.session)
        } else {
            true
        }
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
