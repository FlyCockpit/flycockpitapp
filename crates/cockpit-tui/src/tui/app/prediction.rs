use super::*;

impl App {
    /// Assemble the prediction input from the visible transcript: the
    /// trailing turns, each reduced to the user's message + the agent's
    /// final response text. Tool calls, diffs, subagent reports, plain
    /// notices, and reasoning are skipped — only [`HistoryEntry::User`]
    /// and [`HistoryEntry::Agent`] carry into a turn (the latter's `text`
    /// is the final response; `reasoning` is never included).
    ///
    /// A user message opens a turn; the next agent message closes it.
    /// Consecutive user messages (e.g. queued + folded) flatten into the
    /// most recent open turn's user text so the turn count stays faithful.
    /// `engine::predict::last_turns` then keeps only the last 3.
    pub(super) fn prediction_turns(&self) -> Vec<crate::engine::predict::PredictionTurn> {
        turns_from_history(&self.history)
    }

    /// Kick off the eager next-message prediction for the current turn
    /// (implementation note). Short-circuits before any
    /// utility call when the setting is `off`, when there's no agent
    /// response to predict from (fresh session), or when no provider
    /// config can be loaded. The result lands in `prediction_result`
    /// tagged with the turn it belongs to; `drain_prediction` adopts it.
    pub(super) fn spawn_prediction(&mut self) {
        let mode = self.predict_setting;
        if !mode.is_enabled() {
            return;
        }
        if self.daemon_draining {
            return;
        }
        let turns = self.prediction_turns();
        // Nothing to predict yet (no agent final response) → no call.
        if turns.is_empty() || turns.iter().all(|t| t.agent.trim().is_empty()) {
            return;
        }
        let turn_id = self.prediction_state.turn();
        let cwd = self.launch.cwd.clone();
        let slot = Arc::clone(&self.prediction_result);
        tokio::spawn(async move {
            let (extended, providers) = crate::auto_title::load_configs_for(&cwd);
            // Build the same non-bypassable redaction table the driver uses
            // (GOALS §7) so the prediction prompt is scrubbed before send.
            let redactor = match crate::redact::RedactionTable::build(&extended.redact, &cwd) {
                Ok(r) => Arc::new(r),
                Err(e) => {
                    tracing::debug!(error = %e, "predict: redaction table build failed; no ghost");
                    return;
                }
            };
            let trusted_only = Arc::new(std::sync::atomic::AtomicBool::new(extended.trusted_only));
            let text = crate::engine::predict::predict(
                &turns,
                mode,
                &extended,
                &providers,
                redactor,
                trusted_only,
            )
            .await;
            if let Ok(mut guard) = slot.lock() {
                *guard = Some((turn_id, text));
            }
        });
    }

    /// Adopt a completed async prediction. Runs each tick. Discards a
    /// result tagged with a stale turn (a newer turn started) or one that
    /// arrives after the user began typing (box non-empty) —
    /// appear-once-ready, never pop in over active input. On a usable
    /// result for the current empty turn, caches it and builds the ghost.
    pub(super) fn drain_prediction(&mut self) -> bool {
        let drained = match self.prediction_result.lock() {
            Ok(mut slot) => slot.take(),
            Err(_) => return false,
        };
        let Some((turn_id, text)) = drained else {
            return false;
        };
        let long_mode = matches!(
            self.predict_setting,
            crate::config::extended::PredictNextMessage::Long
        );
        self.prediction_state
            .on_result(turn_id, text, long_mode, self.composer.is_empty());
        true
    }

    /// Reconcile the ghost with the composer's empty/non-empty state. Runs
    /// each tick after key handling: a non-empty box hides the ghost; a
    /// box cleared back to empty within the same turn restores the cached
    /// prediction's ghost — **without** a new utility call (the cache is
    /// reused). Never overwrites typed content.
    pub(super) fn sync_prediction_ghost(&mut self) {
        self.prediction_state.reconcile(self.composer.is_empty());
    }
}
