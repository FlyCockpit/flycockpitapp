use super::*;

impl Session {
    /// Apply an auto-generated title. No-ops (and returns false) if the
    /// user has manually renamed this session.
    pub fn set_auto_title(&self, title: &str) -> Result<bool> {
        let updated = self
            .db
            .set_auto_title(self.id, title)
            .context("setting auto title")?;
        if updated {
            *self.title.lock().unwrap() = Some(title.to_string());
        }
        Ok(updated)
    }

    /// Apply an explicitly user-requested generated title (`/rename` with no
    /// argument). Unlike scheduled auto-titles, this clears the manual-title
    /// guard because the user asked the utility model to replace the current
    /// title.
    pub fn set_explicit_auto_title(&self, title: &str) -> Result<bool> {
        let updated = self
            .db
            .set_explicit_auto_title(self.id, title)
            .context("setting explicit auto title")?;
        if updated {
            *self.title.lock().unwrap() = Some(title.to_string());
            *self.user_renamed.lock().unwrap() = false;
        }
        Ok(updated)
    }

    /// Apply an explicitly requested generated title only while the session is
    /// still untitled. The DB update is atomic so competing daemon requests
    /// produce exactly one winner.
    pub fn set_explicit_auto_title_if_untitled(&self, title: &str) -> Result<bool> {
        let updated = self
            .db
            .set_explicit_auto_title_if_untitled(self.id, title)
            .context("setting explicit auto title if untitled")?;
        if updated {
            *self.title.lock().unwrap() = Some(title.to_string());
            *self.user_renamed.lock().unwrap() = false;
        }
        Ok(updated)
    }

    pub fn title(&self) -> Option<String> {
        self.title.lock().unwrap().clone()
    }

    pub fn user_renamed(&self) -> bool {
        *self.user_renamed.lock().unwrap()
    }

    pub(crate) fn agent_rename_session_available(&self, auto_title_configured: bool) -> bool {
        let Ok(Some(row)) = self.db.get_session(self.id) else {
            return false;
        };
        if row.user_renamed || row.ephemeral {
            return false;
        }
        if !auto_title_configured {
            return true;
        }
        row.title.is_none() && self.title_nudge_threshold_reached()
    }

    pub(crate) fn agent_rename_session_invoke_allowed(&self, auto_title_configured: bool) -> bool {
        let Ok(Some(row)) = self.db.get_session(self.id) else {
            return false;
        };
        if row.user_renamed || row.ephemeral {
            return false;
        }
        !auto_title_configured || self.title_nudge_threshold_reached()
    }

    pub(crate) fn unnamed_session_title_nudge(
        &self,
        mcp_present: bool,
        root_agent_frame: bool,
    ) -> Option<String> {
        if !root_agent_frame {
            return None;
        }
        let slot = self.title_nudge_due_slot_this_turn()?;
        if !mcp_present {
            return None;
        }
        let row = self.db.get_session(self.id).ok().flatten()?;
        if row.user_renamed || row.ephemeral || row.title.is_some() {
            return None;
        }
        Some(format!(
            "This session is still unnamed after {slot} user turns. Name it now with mcp.invoke(\"cockpit\", \"rename_session\", {{\"name\": \"short-title\"}})."
        ))
    }

    /// Fold a chunk of RAW typed user content (pre-skill-injection) into the
    /// running estimate and decide the bounded auto-title action.
    ///
    /// Automatic title calls are allowed only at deterministic user-turn slots:
    /// `1`, `2`, `4`, `8`, and `16`. The selected slot is persisted before the
    /// detached utility task is spawned, so a failed task or daemon restart does
    /// not repeat the same unchanged context. The first slot keeps the fast
    /// single-message eager title; later slots regenerate from accumulated
    /// user-authored messages.
    ///
    /// Persistence is best-effort: an erroring write is logged, never
    /// propagated, and never blocks the turn.
    pub fn note_user_content(&self, text: &str) -> TitleAction {
        let increment = crate::auto_title::estimate_tokens(text);
        if increment != 0 {
            self.user_content_tokens
                .fetch_add(increment, Ordering::Relaxed);
        }
        let user_turns = if increment == 0 {
            self.user_content_turns.load(Ordering::Relaxed)
        } else {
            self.user_content_turns.fetch_add(1, Ordering::Relaxed) + 1
        };

        if self.user_renamed() {
            if increment != 0 {
                self.persist_title_progress();
            }
            return TitleAction::None;
        }

        if increment != 0
            && let Some(slot) =
                scheduled_title_slot(user_turns, self.title_stage.load(Ordering::Relaxed))
        {
            self.title_stage.store(slot, Ordering::Relaxed);
            if slot >= 8 {
                self.title_nudge_slot_pending.store(slot, Ordering::Relaxed);
            }
            self.persist_title_progress();
            return if slot == 1 {
                TitleAction::Eager
            } else {
                TitleAction::Refine
            };
        }

        if increment != 0 {
            self.persist_title_progress();
        }
        TitleAction::None
    }

    fn title_nudge_threshold_reached(&self) -> bool {
        let slot = self.title_stage.load(Ordering::Relaxed);
        TITLE_SCHEDULE_SLOTS.contains(&slot) && slot >= 8
    }

    fn title_nudge_due_slot_this_turn(&self) -> Option<u8> {
        let slot = self.title_nudge_slot_pending.swap(0, Ordering::Relaxed);
        (TITLE_SCHEDULE_SLOTS.contains(&slot)
            && slot >= 8
            && self.user_content_turns.load(Ordering::Relaxed) >= usize::from(slot))
        .then_some(slot)
    }

    pub(crate) fn compact_self_nudge(
        &self,
        ctx_pct: Option<f64>,
        nudge_pct: u8,
        forced_pct: u8,
        mcp_present: bool,
        root_agent_frame: bool,
    ) -> Option<String> {
        if !root_agent_frame || !mcp_present {
            return None;
        }
        let ctx_pct = ctx_pct?;
        if !ctx_pct.is_finite() || ctx_pct < f64::from(nudge_pct) {
            return None;
        }
        let stage = self.compact_self_nudge_stage.load(Ordering::Relaxed);
        let next_stage = if stage < 1 {
            1
        } else if stage < 2 && ctx_pct >= f64::from(nudge_pct.saturating_add(10)) {
            2
        } else {
            return None;
        };
        self.compact_self_nudge_stage
            .store(next_stage, Ordering::Relaxed);
        Some(format!(
            "Context is at {}% of this model's window. Compact now to control the handoff: call mcp.invoke(\"cockpit\", \"request_compact\", {{}}). If you don't, the host will auto-compact this session for you at {forced_pct}%.",
            ctx_pct.round() as u64
        ))
    }

    pub(crate) fn reset_compact_self_nudge_latch(&self) {
        self.compact_self_nudge_stage.store(0, Ordering::Relaxed);
    }

    pub(crate) fn compact_self_nudge_has_fired(&self) -> bool {
        self.compact_self_nudge_stage.load(Ordering::Relaxed) > 0
    }

    /// Compatibility hook retained for older call sites/tests. The schedule is
    /// consumed before the detached utility call starts, so a successful eager
    /// write normally has no progress work left to do.
    pub fn mark_eager_titled(&self) {
        if self.title_stage.load(Ordering::Relaxed) == 0 {
            self.title_stage.store(1, Ordering::Relaxed);
        }
        self.persist_title_progress();
    }

    /// Persist the running estimate + last consumed title slot to the
    /// `sessions` row. Best-effort: an erroring write is logged at warn and
    /// dropped — it never blocks or fails a turn.
    fn persist_title_progress(&self) {
        let tokens = self.user_content_tokens.load(Ordering::Relaxed) as i64;
        let stage = self.title_stage.load(Ordering::Relaxed) as i64;
        if let Err(e) = self.db.set_title_progress(self.id, tokens, stage) {
            tracing::warn!(error = %e, "auto_title: persisting title progress failed");
        }
    }

    /// Read-only view of the running user-content token estimate.
    /// Mostly for tests and `/stats`-style introspection.
    // Retained for `/stats`-style introspection.
    #[allow(dead_code)]
    pub fn user_content_tokens(&self) -> usize {
        self.user_content_tokens.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn user_content_turns(&self) -> usize {
        self.user_content_turns.load(Ordering::Relaxed)
    }

    /// Read-only view of the last consumed auto-title schedule slot. For tests
    /// and introspection.
    #[cfg(test)]
    pub fn title_stage(&self) -> u8 {
        self.title_stage.load(Ordering::Relaxed)
    }

    /// Claim the one-per-session right to surface an auto-title failure
    /// `Notice`. Returns `true` exactly once per session (the first
    /// genuine failure); `false` thereafter, so a broken utility model
    /// doesn't spam the transcript every turn.
    pub fn claim_title_failure_notice(&self) -> bool {
        self.title_failure_noticed
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Compute the `[time: <iso8601>]` prelude for the next user
    /// message (GOALS §17g). Returns `Some` when the first message of
    /// the session is about to fire, or when ≥ `interval_minutes` have
    /// elapsed since the last prelude; otherwise `None`. Updating the
    /// per-session "last prelude" stamp is the side-effect of a
    /// `Some` return — call only when actually about to send.
    pub fn take_time_prelude(&self, interval_minutes: u32) -> Option<String> {
        let now = Utc::now();
        let mut last = self.last_time_prelude.lock().unwrap();
        let should_inject = match *last {
            None => true,
            Some(prev) => (now - prev).num_minutes() >= interval_minutes as i64,
        };
        if !should_inject {
            return None;
        }
        *last = Some(now);
        Some(format!("[time: {}]", now.to_rfc3339()))
    }
}
