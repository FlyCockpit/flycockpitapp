use super::*;

impl LockManager {
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
}
