use super::*;

fn capture_model_system_prompt_snapshot_json(project_root: &std::path::Path) -> String {
    let (_, providers) = crate::auto_title::load_configs_for(project_root);
    ModelSystemPromptSnapshot::capture(&providers).to_json_string()
}

impl Session {
    /// Create a brand-new session, inserting its row in the DB.
    #[allow(dead_code)]
    pub fn create(db: Db, project_root: PathBuf, active_agent: &str) -> Result<Self> {
        let project_id = project_id_for(&project_root);
        let project_root_str = project_root.to_string_lossy().into_owned();
        let mut row = db
            .new_session_row(&project_id, &project_root_str, active_agent)
            .context("building session row")?;
        row.model_system_prompt_snapshot_json =
            capture_model_system_prompt_snapshot_json(&project_root);
        let row = db
            .insert_session_row(&row)
            .context("creating session row")?;
        Self::from_row(db, project_root, row)
    }

    /// Create a brand-new session held **in memory only** — its `sessions`
    /// row is not written yet (session-id-display-and-lazy-persist). The id
    /// and short_id exist immediately (so the TUI can show the id at
    /// startup), but the row lands in the DB only on the first user message
    /// via [`Self::persist_if_needed`]. A session created this way and never
    /// persisted leaves no DB trace and never appears in `session list`.
    pub fn create_deferred(db: Db, project_root: PathBuf, active_agent: &str) -> Result<Self> {
        let project_id = project_id_for(&project_root);
        let project_root_str = project_root.to_string_lossy().into_owned();
        let mut row = db
            .new_session_row(&project_id, &project_root_str, active_agent)
            .context("building deferred session row")?;
        row.model_system_prompt_snapshot_json =
            capture_model_system_prompt_snapshot_json(&project_root);
        let session = Self::from_row(db, project_root, row.clone())?;
        *session.pending_row.lock().unwrap() = Some(row);
        Ok(session)
    }

    /// Write the deferred `sessions` row if it hasn't been written yet, and
    /// return `true` when this call performed the write
    /// (session-id-display-and-lazy-persist). Idempotent: a no-op (returns
    /// `false`) for an already-persisted session — including every session
    /// created via [`Self::create`] / [`Self::resume`] / [`Self::create_fork`],
    /// which are persisted from the start.
    ///
    /// This is the **only** flush point, and it MUST be called before any
    /// row that references the session (tool_calls, inference_calls, locks,
    /// …) so the FK/ordering invariant holds. The session worker calls it on
    /// the first user message, ahead of dispatching it to the driver. The
    /// stored row carries the latest provider/model so a model picked before
    /// the first message survives the deferred write.
    pub fn persist_if_needed(&self) -> Result<bool> {
        let row = {
            let mut slot = self.pending_row.lock().unwrap();
            match slot.take() {
                Some(mut row) => {
                    row.provider = self.active_provider();
                    row.model = self.active_model();
                    row.redaction_table_json = self.redaction_table_json.lock().unwrap().clone();
                    row
                }
                None => return Ok(false),
            }
        };
        match self.db.insert_session_row(&row) {
            Ok(_) => {}
            Err(e) => {
                // Restore the pending row so a transient failure can retry on
                // the next user message rather than silently losing the session.
                *self.pending_row.lock().unwrap() = Some(row);
                return Err(e).context("persisting deferred session row");
            }
        }
        if row.last_viewed_at.is_some()
            && let Err(e) = self.db.mark_session_viewed(self.id)
        {
            tracing::warn!(error = %e, "persisting deferred session viewed marker failed");
        }
        Ok(true)
    }

    pub(super) fn stage_pending_row(&self, update: impl FnOnce(&mut SessionRow)) -> bool {
        let mut slot = self.pending_row.lock().unwrap();
        if let Some(row) = slot.as_mut() {
            update(row);
            true
        } else {
            false
        }
    }

    /// Whether this session's `sessions` row has been written
    /// (session-id-display-and-lazy-persist). `false` only for a deferred
    /// session that has not yet seen its first user message; `true`
    /// otherwise. Used by the lazy-persistence tests; the TUI's own
    /// exit-print decision tracks the persistence trigger locally (it can't
    /// reach this daemon-owned state synchronously).
    #[cfg(test)]
    pub fn is_persisted(&self) -> bool {
        self.pending_row.lock().unwrap().is_none()
    }

    /// Branch a fork from `parent` at `fork_point_turn_id` (None = tail).
    /// The new session inherits the parent's project, agent, provider,
    /// and model; its conversation history is reconstructed by the
    /// daemon from the parent's transcript up to the fork point.
    pub fn create_fork(
        db: Db,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
    ) -> Result<Self> {
        let row = db
            .create_fork(parent_session_id, fork_point_turn_id)
            .context("creating fork session row")?;
        let project_root = PathBuf::from(&row.project_root);
        Self::from_row(db, project_root, row)
    }

    /// Resume an existing session. Returns `None` if the id is unknown.
    /// Backfills `short_id` if missing (lazy migration from pre-§17 rows).
    pub fn resume(db: Db, session_id: Uuid) -> Result<Option<Self>> {
        let Some(row) = db.get_session(session_id).context("fetching session")? else {
            return Ok(None);
        };
        let project_root = PathBuf::from(&row.project_root);
        Ok(Some(Self::from_row(db, project_root, row)?))
    }

    fn from_row(db: Db, project_root: PathBuf, row: SessionRow) -> Result<Self> {
        let started_at =
            DateTime::<Utc>::from_timestamp(row.started_at, 0).unwrap_or_else(Utc::now);
        let user_content_turns = count_user_turns_for_title(&db, row.session_id);
        let model_system_prompt_snapshot = Arc::new(ModelSystemPromptSnapshot::from_json_str(
            &row.model_system_prompt_snapshot_json,
        ));
        let short_id = match row.short_id {
            Some(s) => s,
            None => db
                .ensure_short_id(row.session_id)
                .context("backfilling short_id")?,
        };
        Ok(Self {
            id: row.session_id,
            project_id: row.project_id,
            project_root,
            started_at,
            db,
            short_id,
            parent_session_id: row.parent_session_id,
            fork_point_turn_id: row.fork_point_turn_id,
            title: Mutex::new(row.title),
            user_renamed: Mutex::new(row.user_renamed),
            model: Mutex::new(row.model),
            provider: Mutex::new(row.provider),
            redaction_table_json: Mutex::new(row.redaction_table_json),
            model_system_prompt_snapshot,
            last_time_prelude: Mutex::new(None),
            user_content_tokens: AtomicUsize::new(row.user_content_tokens.max(0) as usize),
            user_content_turns: AtomicUsize::new(user_content_turns),
            title_stage: AtomicU8::new(normalize_title_slot(row.title_stage)),
            title_failure_noticed: std::sync::atomic::AtomicBool::new(false),
            last_usage: Mutex::new(None),
            last_send_at: Mutex::new(None),
            pinned_messages: Mutex::new(Vec::new()),
            calibrator: Mutex::new(crate::tokens::Calibrator::new()),
            tmp_dir: Mutex::new(None),
            sandbox_mode: AtomicU8::new(sandbox_mode_to_u8(
                crate::tools::sandbox_mode::SandboxMode::Sandbox,
            )),
            container_network_enabled: AtomicBool::new(false),
            sandbox_escalation_enabled: AtomicBool::new(true),
            sandbox_escalation_notice_state: AtomicBool::new(true),
            mcp_reserved_cockpit_notice_sent: AtomicBool::new(false),
            agent_compact_requested: AtomicBool::new(false),
            // Default `manual` until the spawn path applies the config default.
            approval_mode: AtomicU8::new(approval_mode_to_u8(
                crate::config::extended::ApprovalMode::Manual,
            )),
            // Default ON until the spawn path applies the config default.
            shell_compression_enabled: AtomicBool::new(true),
            trusted_only: Arc::new(AtomicBool::new(false)),
            active_tool_names: Mutex::new(std::collections::HashSet::new()),
            active_sandbox_escalate_eligible: AtomicBool::new(false),
            last_tool_call: Mutex::new(None),
            last_recoverable_tool_call: Mutex::new(None),
            // Persisted by default; `create_deferred` overrides this with the
            // pending row right after construction.
            pending_row: Mutex::new(None),
            gitignore_session_allow: Mutex::new(Vec::new()),
            gitignore_session_reject: Mutex::new(std::collections::HashSet::new()),
            adopted_tip_tools: Mutex::new(std::collections::HashSet::new()),
            recent_bash: Mutex::new(std::collections::VecDeque::new()),
        })
    }

    /// The session's private tmp dir (sandboxing part 2), creating it on
    /// first access under `<system temp>/cockpit-session-<id>`. Sandboxed
    /// shells get read+write here, and native-tool path checks treat it
    /// as inside the boundary. Returns `None` only if the directory can't
    /// be created (a degraded but non-fatal state: native checks then
    /// fall back to cwd-only, and the shell sandbox simply omits the tmp
    /// allow entry).
    pub fn tmp_dir(&self) -> Option<PathBuf> {
        let mut slot = self.tmp_dir.lock().unwrap();
        if let Some(dir) = slot.as_ref() {
            return Some(dir.clone());
        }
        let dir = std::env::temp_dir().join(format!("cockpit-session-{}", self.id));
        match std::fs::create_dir_all(&dir) {
            Ok(()) => {
                *slot = Some(dir.clone());
                Some(dir)
            }
            Err(e) => {
                tracing::warn!(error = %e, dir = %dir.display(), "creating session tmp dir failed");
                None
            }
        }
    }

    /// Manually set the session's title. Locks out the auto-titling
    /// pass (GOALS §17d).
    // Manual-rename API (GOALS §17d); retained for the not-yet-wired
    // `/rename` affordance.
    #[allow(dead_code)]
    pub fn rename(&self, new_title: &str) -> Result<()> {
        self.db
            .rename_session(self.id, new_title)
            .context("renaming session")?;
        *self.title.lock().unwrap() = Some(new_title.to_string());
        *self.user_renamed.lock().unwrap() = true;
        Ok(())
    }

    /// Persist the accumulated egress redaction table with the session so raw
    /// history remains covered after resume even if env/dotenv sources change.
    pub fn persist_redaction_table(&self, table: &crate::redact::RedactionTable) -> Result<()> {
        let json = table.to_persisted_json()?;
        *self.redaction_table_json.lock().unwrap() = Some(json.clone());
        if self.stage_pending_row(|row| {
            row.redaction_table_json = Some(json.clone());
        }) {
            return Ok(());
        }
        self.db
            .set_session_redaction_table_json(self.id, Some(json))
            .context("persisting session redaction table")
    }

    pub fn persisted_redaction_table(&self) -> Result<Option<crate::redact::RedactionTable>> {
        let Some(json) = self.redaction_table_json.lock().unwrap().clone() else {
            return Ok(None);
        };
        crate::redact::RedactionTable::from_persisted_json(&json)
            .map(Some)
            .context("loading persisted session redaction table")
    }

    /// Touch `last_active_at`. Called by the daemon on every
    /// interaction so `cockpit -c` lands on the right session.
    pub fn touch(&self) -> Result<()> {
        if self.stage_pending_row(|row| {
            row.last_active_at = Utc::now().timestamp();
        }) {
            return Ok(());
        }
        self.db.touch_session(self.id).context("touching session")
    }

    /// Mark this session viewed by a client. For an unpersisted deferred
    /// session, stage the marker so the first INSERT carries it; otherwise
    /// write through to the existing row.
    pub fn mark_viewed(&self) -> Result<()> {
        if self.stage_pending_row(|row| {
            row.last_viewed_at = Some(Utc::now().timestamp());
        }) {
            return Ok(());
        }
        self.db
            .mark_session_viewed(self.id)
            .context("marking session viewed")
    }

    /// End the session — sets `ended_at` in the DB. Doesn't drop the
    /// row; history stays queryable via `cockpit session list`. Also
    /// removes the per-session tmp dir (sandboxing part 2): a session's
    /// scratch space doesn't outlive it.
    pub fn end(&self) -> Result<()> {
        self.remove_tmp_dir();
        self.db.end_session(self.id).context("ending session")
    }

    /// Remove the per-session tmp dir if one was created. Idempotent.
    /// Best-effort: a removal failure is logged, never propagated — it
    /// must not block session teardown.
    pub(super) fn remove_tmp_dir(&self) {
        if let Some(dir) = self.tmp_dir.lock().unwrap().take()
            && let Err(e) = std::fs::remove_dir_all(&dir)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(error = %e, dir = %dir.display(), "removing session tmp dir failed");
        }
    }
}
