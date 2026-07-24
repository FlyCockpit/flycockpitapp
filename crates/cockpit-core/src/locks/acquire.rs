use super::*;

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

        for row in db.list_lock_reads().context("loading lock reads")? {
            state
                .read_tracker
                .entry((row.session_id, row.agent_id))
                .or_default()
                .insert(PathBuf::from(row.path), row.read_hash);
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
        let read_hash = file_hash(&canon);
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
            .insert(canon.clone(), read_hash);
        let was_forced_released = state.forced_released.contains(&canon);

        // Persist before returning so a crash here doesn't leak the
        // lock as "held in memory only."
        drop(state);
        let acquire_result = if was_forced_released {
            self.db
                .lock_force_acquire_with_read(&canon, agent, session, read_hash)
                .context("persisting forced lock_acquire/read")
        } else {
            self.db
                .lock_acquire_with_read(&canon, agent, session, read_hash)
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
        record_read: bool,
    ) -> Result<Option<(Uuid, AgentId)>> {
        let read_hash = record_read.then(|| file_hash(canon));
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
        if record_read {
            state
                .read_tracker
                .entry((session, agent.to_string()))
                .or_default()
                .insert(canon.to_path_buf(), read_hash.flatten());
        }
        let was_forced_released = state.forced_released.contains(canon);
        drop(state);
        let acquire_result = if record_read && was_forced_released {
            self.db
                .lock_force_acquire_with_read(canon, agent, session, read_hash.flatten())
                .context("persisting forced lock_acquire/read")
        } else if was_forced_released {
            self.db
                .lock_force_acquire(canon, agent, session)
                .context("persisting forced lock_acquire")
        } else if record_read {
            self.db
                .lock_acquire_with_read(canon, agent, session, read_hash.flatten())
                .context("persisting lock_acquire/read")
        } else {
            self.db
                .lock_acquire(canon, agent, session)
                .context("persisting lock_acquire")
        };
        if let Err(error) = acquire_result {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            if matches!(state.held.get(canon), Some((s, a)) if *s == session && a == agent) {
                state.held.remove(canon);
                state.touched.remove(canon);
            }
            if record_read
                && let Some(reads) = state.read_tracker.get_mut(&(session, agent.to_string()))
            {
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
        on_wait: F,
    ) -> Result<AcquireWait>
    where
        F: FnMut(&(Uuid, AgentId)),
    {
        self.acquire_wait_inner(path, agent, session, cancel, on_wait, true)
            .await
    }

    /// Waiting acquire for write tools. It uses the same waiter/cancel/timeout
    /// machinery as [`Self::acquire_wait`] but deliberately does not refresh
    /// the caller's read record; the write guard must validate the read hash
    /// captured by an earlier `read`/`readlock`.
    pub async fn acquire_wait_without_read<F>(
        &self,
        path: &Path,
        agent: &str,
        session: Uuid,
        cancel: &tokio_util::sync::CancellationToken,
        on_wait: F,
    ) -> Result<AcquireWait>
    where
        F: FnMut(&(Uuid, AgentId)),
    {
        self.acquire_wait_inner(path, agent, session, cancel, on_wait, false)
            .await
    }

    async fn acquire_wait_inner<F>(
        &self,
        path: &Path,
        agent: &str,
        session: Uuid,
        cancel: &tokio_util::sync::CancellationToken,
        mut on_wait: F,
        record_read: bool,
    ) -> Result<AcquireWait>
    where
        F: FnMut(&(Uuid, AgentId)),
    {
        let canon = canonicalize(path);
        let waiter_key = (session, agent.to_string());
        // Fast path: acquire immediately if free / already ours.
        if self
            .try_acquire(&canon, agent, session, record_read)?
            .is_none()
        {
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
            match self.try_acquire(&canon, agent, session, record_read)? {
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
                    bail!(
                        "lock wait timed out after {}s{context}. Work on something else and retry this path later instead of immediately re-issuing the same readlock.",
                        LOCK_WAIT_TIMEOUT.as_secs()
                    );
                }
                _ = &mut notified => {}
            }
        }
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

    pub(super) fn sweep_expired_with_hook(
        &self,
        now: i64,
        hook: impl FnOnce(),
    ) -> Result<Vec<PathBuf>> {
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
        let read_hash = file_hash(&canon);
        if let Err(e) = self.db.lock_note_read(&canon, agent, session, read_hash) {
            tracing::warn!(error = %e, "persisting note_read failed");
            return;
        }
        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            state
                .read_tracker
                .entry((session, agent.to_string()))
                .or_default()
                .insert(canon.clone(), read_hash);
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
            .map(|s| s.contains_key(&canon))
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
        tool_name: &str,
    ) -> Result<WriteGuard<'a>> {
        let canon = canonicalize(path);
        let agent_id = agent.to_string();
        let mut acquired_by_guard = false;
        {
            let mut state = crate::sync::lock_or_recover(&self.inner);
            match state.held.get(&canon) {
                Some((s, a)) if *s == session && a == agent => {}
                Some((s, a)) => {
                    return Err(crate::engine::tool::invalid_input(format!(
                        "cannot write `{}` — `{a}` holds the lock in session {s}; wait for it to release or pick a different file",
                        canon.display()
                    )));
                }
                None => {
                    let read_hash = state
                        .read_tracker
                        .get(&(session, agent_id.clone()))
                        .and_then(|s| s.get(&canon).copied());
                    match read_hash {
                        None => {
                            return Err(crate::engine::tool::invalid_input(
                                ValidationCorrection::write_requires_readlock(&canon, tool_name)
                                    .model_message(),
                            ));
                        }
                        Some(Some(expected)) if file_hash(&canon) == Some(expected) => {}
                        Some(_) => {
                            return Err(crate::engine::tool::invalid_input(stale_read_message(
                                &canon,
                            )));
                        }
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

    /// Finish write-guard setup after a caller has already acquired the lock
    /// through the waiting path. `acquired_by_wait` means this call owns the
    /// hold and should release it on success/drop; `require_fresh_read` keeps
    /// the §3c stale-content guard load-bearing for existing-file writes.
    pub fn begin_write_after_wait<'a>(
        &'a self,
        path: &Path,
        agent: &str,
        session: Uuid,
        tool_name: &str,
        acquired_by_wait: bool,
        require_fresh_read: bool,
    ) -> Result<WriteGuard<'a>> {
        let canon = canonicalize(path);
        let agent_id = agent.to_string();
        let result = {
            let state = crate::sync::lock_or_recover(&self.inner);
            match state.held.get(&canon) {
                Some((s, a)) if *s == session && a == agent => {
                    if require_fresh_read {
                        let read_hash = state
                            .read_tracker
                            .get(&(session, agent_id.clone()))
                            .and_then(|s| s.get(&canon).copied());
                        match read_hash {
                            None => Err(crate::engine::tool::invalid_input(
                                ValidationCorrection::write_requires_readlock(&canon, tool_name)
                                    .model_message(),
                            )),
                            Some(Some(expected)) if file_hash(&canon) == Some(expected) => Ok(()),
                            Some(_) => Err(crate::engine::tool::invalid_input(stale_read_message(
                                &canon,
                            ))),
                        }
                    } else {
                        Ok(())
                    }
                }
                Some((s, a)) => Err(crate::engine::tool::invalid_input(format!(
                    "cannot write `{}` — `{a}` holds the lock in session {s}; wait for it to release or pick a different file",
                    canon.display()
                ))),
                None => Err(crate::engine::tool::invalid_input(format!(
                    "cannot write `{}` — lock was not acquired for this write; retry the tool call",
                    canon.display()
                ))),
            }
        };

        if let Err(error) = result {
            if acquired_by_wait {
                let _ = self.release_force_memory(&canon, agent, session);
            }
            return Err(error);
        }

        Ok(WriteGuard {
            locks: self,
            path: canon,
            agent: agent_id,
            session,
            acquired_by_guard: acquired_by_wait,
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
        self.check_write_permitted_for_tool(path, agent, session, "writeunlock")
    }

    #[allow(dead_code)]
    pub fn check_write_permitted_for_tool(
        &self,
        path: &Path,
        agent: &str,
        session: Uuid,
        tool_name: &str,
    ) -> Result<()> {
        let canon = canonicalize(path);
        let state = crate::sync::lock_or_recover(&self.inner);
        match state.held.get(&canon) {
            Some((s, a)) if *s == session && a == agent => Ok(()),
            Some((_, a)) => Err(crate::engine::tool::invalid_input(format!(
                "cannot write `{}` — `{a}` holds the lock; wait for it to release or pick a different file",
                canon.display()
            ))),
            None => {
                let read_hash = state
                    .read_tracker
                    .get(&(session, agent.to_string()))
                    .and_then(|s| s.get(&canon).copied());
                match read_hash {
                    None => Err(crate::engine::tool::invalid_input(
                        ValidationCorrection::write_requires_readlock(&canon, tool_name)
                            .model_message(),
                    )),
                    Some(Some(expected)) if file_hash(&canon) == Some(expected) => Ok(()),
                    Some(_) => Err(crate::engine::tool::invalid_input(stale_read_message(
                        &canon,
                    ))),
                }
            }
        }
    }
}

fn stale_read_message(path: &Path) -> String {
    format!(
        "cannot write `{}`: it changed on disk since you read it — readlock it again, re-check the current contents, and redo your edit",
        path.display()
    )
}
