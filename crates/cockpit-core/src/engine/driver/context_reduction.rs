use super::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreparedCompactionCoverage {
    pub history_len: usize,
    pub complete_exchange_count: usize,
    pub history_hash: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PreparedCompaction {
    pub agent_name: String,
    pub source: String,
    pub prepared_at_unix_seconds: i64,
    pub coverage: PreparedCompactionCoverage,
    pub history: Vec<Message>,
    pub brief: String,
    pub handoff: String,
    pub tail_message_positions: Vec<usize>,
    pub turns_summarized: usize,
    pub tail_kept: usize,
    pub tail_trimmed: usize,
    pub tokens_before: u64,
    pub tokens_after: u64,
    pub trigger_ctx_pct: Option<f64>,
    pub seed_tools: Vec<crate::db::seed_tools::SeedTool>,
    pub seed_tool_tokens: u64,
    pub compressed_entries: Vec<crate::db::compressed_results::CompressedToolResultEntry>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DurableCompactionShadow {
    ReadyBrief(DurableShadowBrief),
    PreparedCompaction(Box<PreparedCompaction>),
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DurableShadowBrief {
    pub generation: u64,
    pub snapshot_history: Vec<Message>,
    pub snapshot_turns: usize,
    pub snapshot_tail_turns: usize,
    pub brief: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::engine::driver) enum PreparedCompactionApplyError {
    Stale {
        expected: PreparedCompactionCoverage,
        actual: PreparedCompactionCoverage,
    },
    StoreCompressedResults(String),
}

struct CompactBriefDraft {
    session: Arc<Session>,
    model: Arc<crate::engine::model::Model>,
    system: String,
    history: Vec<Message>,
    params: crate::engine::model::ModelParams,
    agent_name: String,
    prompt_override: Option<String>,
    #[cfg(test)]
    test_calls: Option<Arc<std::sync::Mutex<Vec<TestCompactBriefCall>>>>,
}

fn prepared_compaction_coverage(history: &[Message]) -> PreparedCompactionCoverage {
    use sha2::{Digest, Sha256};

    let serialized = serde_json::to_vec(history).unwrap_or_default();
    let digest = Sha256::digest(&serialized);
    PreparedCompactionCoverage {
        history_len: history.len(),
        complete_exchange_count: crate::engine::compact::complete_exchange_count(history),
        history_hash: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
    }
}

fn normalize_prepared_history_for_serde(history: Vec<Message>) -> Vec<Message> {
    serde_json::to_value(&history)
        .and_then(serde_json::from_value)
        .unwrap_or(history)
}

pub(in crate::engine::driver) fn shadow_stale_after_turns(keep_recent_turns: usize) -> usize {
    std::cmp::max(8, keep_recent_turns.saturating_add(4))
}

impl From<&ShadowBriefReady> for DurableShadowBrief {
    fn from(ready: &ShadowBriefReady) -> Self {
        Self {
            generation: ready.generation,
            snapshot_history: ready.snapshot_history.clone(),
            snapshot_turns: ready.snapshot_turns,
            snapshot_tail_turns: ready.snapshot_tail_turns,
            brief: ready.brief.clone(),
        }
    }
}

impl From<DurableShadowBrief> for ShadowBriefReady {
    fn from(record: DurableShadowBrief) -> Self {
        Self {
            generation: record.generation,
            snapshot_history: record.snapshot_history,
            snapshot_turns: record.snapshot_turns,
            snapshot_tail_turns: record.snapshot_tail_turns,
            brief: record.brief,
        }
    }
}

impl Driver {
    #[cfg(test)]
    fn trace_compaction_apply(&self, step: &'static str) {
        if let Some(trace) = &self.test_compaction_apply_trace {
            trace.lock().unwrap().push(step);
        }
    }

    fn shadow_ready_is_stale(&self, ready: &ShadowBriefReady, keep_recent_turns: usize) -> bool {
        let current = self.compact_brief_history(&self.stack[0].history);
        let current_turns = crate::engine::compact::complete_exchange_count(&current);
        current_turns.saturating_sub(ready.snapshot_turns)
            > shadow_stale_after_turns(keep_recent_turns)
    }

    fn delete_durable_shadow_brief(&self) {
        if let Err(error) = self.session.db.delete_compaction_shadow(self.session.id) {
            tracing::warn!(error = %error, "compact shadow: deleting durable shadow failed");
        }
    }

    fn persist_ready_shadow_brief(&self, ready: &ShadowBriefReady) {
        if !self.resolve_context_config().compact_shadow {
            self.delete_durable_shadow_brief();
            return;
        }
        let payload = DurableCompactionShadow::ReadyBrief(DurableShadowBrief::from(ready));
        let payload_json = match serde_json::to_string(&payload) {
            Ok(payload_json) => payload_json,
            Err(error) => {
                tracing::warn!(error = %error, "compact shadow: serializing durable shadow failed");
                return;
            }
        };
        if let Err(error) = self
            .session
            .db
            .upsert_compaction_shadow(self.session.id, &payload_json)
        {
            tracing::warn!(error = %error, "compact shadow: persisting durable shadow failed");
        }
    }

    pub(in crate::engine::driver) fn load_compaction_shadow_from_store(&mut self) {
        let ctx_cfg = self.resolve_context_config();
        if !ctx_cfg.compact_shadow {
            self.shadow_brief = None;
            self.delete_durable_shadow_brief();
            return;
        }
        let row = match self.session.db.compaction_shadow(self.session.id) {
            Ok(row) => row,
            Err(error) => {
                tracing::warn!(error = %error, "compact shadow: loading durable shadow failed");
                return;
            }
        };
        let Some(row) = row else {
            self.shadow_brief = None;
            return;
        };
        let payload = match serde_json::from_str::<DurableCompactionShadow>(&row.payload_json) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(error = %error, "compact shadow: deserializing durable shadow failed");
                self.shadow_brief = None;
                self.delete_durable_shadow_brief();
                return;
            }
        };
        let DurableCompactionShadow::ReadyBrief(record) = payload else {
            self.shadow_brief = None;
            return;
        };
        if record.generation < self.shadow_brief_generation {
            self.shadow_brief = None;
            self.delete_durable_shadow_brief();
            return;
        }
        self.shadow_brief_generation = record.generation;
        let ready = ShadowBriefReady::from(record);
        if self.shadow_ready_is_stale(&ready, ctx_cfg.compact_keep_recent_turns) {
            self.shadow_brief = None;
            self.delete_durable_shadow_brief();
            return;
        }
        self.shadow_brief = Some(ShadowBriefState::Ready(ready));
    }

    /// `/compact` drafts a new-thread brief from a filtered view of history:
    /// non-steering user-invoked skill pairs are deliberately omitted because
    /// they would be stripped on any primary swap and must not survive inside
    /// the model-written handoff text. The live history is left unchanged until
    /// the normal compaction reset, where stale ledger rows are cleaned up.
    pub(in crate::engine::driver) fn compact_brief_history(
        &self,
        history: &[Message],
    ) -> Vec<Message> {
        let ids: std::collections::HashSet<String> = self
            .skill_pairs
            .iter()
            .filter(|pair| !pair.intentional_steer)
            .map(|pair| pair.call_id.clone())
            .collect();
        if ids.is_empty() {
            return history.to_vec();
        }
        history
            .iter()
            .filter(|msg| !message_references_call_id(msg, &ids))
            .cloned()
            .collect()
    }

    /// Stable daemon timeline ids owning the recent exchanges that survive a
    /// compaction. A prior compaction owns its serialized handoff/tail as one
    /// boundary row, so that boundary's seq represents those messages on a
    /// later compaction instead of inventing ephemeral wire-history indexes.
    pub(in crate::engine::driver) fn compact_tail_message_seqs(
        &self,
        tail_turns: usize,
    ) -> Vec<i64> {
        use crate::daemon::proto::HistoryEntry;

        if tail_turns == 0 {
            return Vec::new();
        }
        let Ok(entries) = crate::engine::rehydrate::history_snapshot(
            &self.session.db,
            self.session.id,
            self.active_agent(),
        ) else {
            return Vec::new();
        };
        let excluded_skill_calls = self
            .skill_pairs
            .iter()
            .filter(|pair| !pair.intentional_steer)
            .map(|pair| pair.call_id.as_str())
            .collect::<std::collections::HashSet<_>>();
        let mut remaining = tail_turns;
        let mut start = 0;
        for (index, entry) in entries.iter().enumerate().rev() {
            let represented_turns = match entry {
                HistoryEntry::User { .. } => 1,
                HistoryEntry::CompactBoundary { tail_kept, .. } => tail_kept.saturating_add(1),
                _ => 0,
            };
            if represented_turns == 0 {
                continue;
            }
            if represented_turns >= remaining {
                start = index;
                break;
            }
            remaining -= represented_turns;
        }
        entries[start..]
            .iter()
            .filter_map(|entry| match entry {
                HistoryEntry::User { seq, .. }
                | HistoryEntry::Assistant { seq, .. }
                | HistoryEntry::CompactBoundary { seq, .. } => (*seq > 0).then_some(*seq),
                HistoryEntry::ToolCall { seq, call_id, .. }
                    if !excluded_skill_calls.contains(call_id.as_str()) =>
                {
                    (*seq > 0).then_some(*seq)
                }
                _ => None,
            })
            .collect()
    }

    /// Snapshot-dedup the foreground agent's history. `auto` distinguishes
    /// the cache-aware auto-fire from a manual `/prune`. Emits `Pruned` +
    /// a refreshed `ContextProjection`. Never breaks a warm cache (the
    /// cache-cold or manual paths), so `cache_break = false`.
    pub(in crate::engine::driver) async fn do_prune(
        &mut self,
        auto: bool,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        self.do_prune_inner(auto, false, None, None, tx).await;
    }

    /// Inner prune: `cache_break` flags a ctx%-threshold auto-prune that ran
    /// against a warm cache (implementation note), so the
    /// client surfaces the shared cache-break warning. Emits `Pruned` + a
    /// refreshed `ContextProjection`.
    pub(in crate::engine::driver) async fn do_prune_inner(
        &mut self,
        auto: bool,
        cache_break: bool,
        trigger_reason: Option<&'static str>,
        precomputed_plan: Option<prune::DedupPlan>,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        // Capture the inputs the escalation telemetry needs before borrowing
        // `top` mutably (last reported usage + the model window).
        let window = self.active_model_context_length();
        let used_before = self.session.last_usage().map(|u| u.input_tokens);

        let depth = self.stack.len();
        let agent_name = self.active_agent().to_string();
        let top = self.stack.last_mut().expect("stack never empty");
        // Snapshot wire-token total + message count before the prune so
        // the timeline event (Part C) can record the before/after delta.
        let messages_before = top.history.len();
        let tokens_before = wire_token_total(&top.history);
        // This prune's targets (the bodies elided *this* call) — the
        // `original_event_id`s describing what was removed — and the
        // classifying reason (overlap-merge vs exact-identity vs mixed).
        let this_prune = precomputed_plan.unwrap_or_else(|| prune::dedup_plan(&top.history));
        let this_elided: Vec<String> = this_prune
            .targets
            .iter()
            .map(|t| t.elision.original_event_id.clone())
            .collect();
        let reason = classify_prune_reason(&this_prune).to_string();

        let applied = this_prune;
        prune::apply_plan(&mut top.history, &applied);
        for candidate in prune::condense_candidates(&top.history) {
            let hash =
                crate::db::compressed_results::compressed_result_hash(&candidate.original_body);
            match self.session.db.insert_compressed_tool_result(
                &hash,
                crate::db::compressed_results::NewCompressedToolResult {
                    session_id: self.session.id,
                    agent_id: &agent_name,
                    tool: &candidate.tool,
                    call_id: &candidate.call_id,
                    original_byte_len: candidate.original_body.len(),
                    compressed_byte_len: Some(candidate.condensed_body.len()),
                    created_at: chrono::Utc::now().timestamp(),
                    kind: "prune-boundary",
                    content: &candidate.original_body,
                },
            ) {
                Ok(()) => {
                    prune::apply_condensed_tool_result(&mut top.history, &candidate, &hash);
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        tool = %candidate.tool,
                        call_id = %candidate.call_id,
                        "prune-boundary compressed tool result store failed"
                    );
                }
            }
        }
        let bodies = applied.targets.len();
        let tokens_saved = applied.tokens_saved() as u64;
        let messages_after = top.history.len();
        let tokens_after = wire_token_total(&top.history);
        // The full live elided set (cumulative across prunes), so the TUI
        // dims every currently-elided body — not just this prune's targets.
        let elided = prune::current_elided_ids(&top.history);
        // Update the watermark so auto-prune short-circuits until the
        // foreground history grows again.
        self.prune_watermark.insert(depth, top.history.len());

        // Remaining context budget after this prune: model window − the
        // post-prune input-token estimate. The last reported usage is the
        // pre-prune prompt size; subtract this prune's wire saving to estimate
        // the post-prune prompt size. `None` when the window / usage is
        // unknown (ctx%-gated figures inert).
        let remaining_budget = match (window, used_before) {
            (Some(w), Some(used)) => {
                let after = used.saturating_sub(tokens_saved);
                Some(u64::from(w).saturating_sub(after))
            }
            _ => None,
        };

        // Record this auto-prune's effectiveness for the escalation policy
        // (root frame only — a subagent frame's prune is transient). Only when
        // the ctx%-gated figures are known.
        if auto
            && depth == 1
            && bodies > 0
            && let (Some(w), Some(used)) = (window, used_before)
        {
            let window_f = f64::from(w);
            self.note_prune_effectiveness(PruneEffectiveness {
                ctx_pct: used as f64 / window_f * 100.0,
                saved_pct: tokens_saved as f64 / window_f * 100.0,
            });
        }

        // Timeline event (Part C): record the prune so the export can
        // audit it. Only when something was actually elided — an empty
        // prune is not a meaningful timeline entry. Ordered immediately
        // before the next `inference_request` event by construction
        // (auto-prune fires right before a `turn`).
        if bodies > 0
            && let Err(e) = self.session.record_context_pruned(
                &agent_name,
                auto,
                messages_before,
                messages_after,
                tokens_before,
                tokens_after,
                &this_elided,
                &reason,
                tokens_saved,
                remaining_budget,
                trigger_reason,
            )
        {
            tracing::warn!(error = %e, "record context_pruned event failed");
        }

        // Persist the prune ledger so a later resume re-derives this exact
        // pruned form (implementation note). Only the
        // root frame's prune is resumable; an interactive subagent frame's
        // prune is transient (its frame is never resumed), so skip the
        // write there to avoid clobbering the root ledger.
        if depth == 1 {
            self.persist_prune_ledger();
            self.drop_stale_owner_ledgers();
        }

        let _ = tx
            .send(TurnEvent::Pruned {
                auto,
                bodies,
                tokens_saved,
                elided,
                trigger_reason: trigger_reason.map(str::to_string),
                cache_break,
            })
            .await;
        self.emit_context_projection(tx).await;
    }

    /// Record one auto-prune's effectiveness onto the rolling ledger, capped
    /// at the window the escalation predicate inspects
    /// (implementation note).
    pub(in crate::engine::driver) fn note_prune_effectiveness(&mut self, e: PruneEffectiveness) {
        self.prune_effectiveness.push_back(e);
        while self.prune_effectiveness.len() > PRUNE_INEFFECTIVE_RUN {
            self.prune_effectiveness.pop_front();
        }
    }

    /// True when recent auto-prunes have been *ineffective* — the last
    /// [`PRUNE_INEFFECTIVE_RUN`] prunes each saved below
    /// [`PRUNE_INEFFECTIVE_SAVING_PCT`] of the window while ctx% rose strictly
    /// across them — so the next boundary should escalate to compaction rather
    /// than continue tiny snapshot prunes (implementation note
    /// Part B). Pure over the ledger so it is unit-testable.
    pub(in crate::engine::driver) fn prune_is_ineffective(&self) -> bool {
        if self.prune_effectiveness.len() < PRUNE_INEFFECTIVE_RUN {
            return false;
        }
        let runs: Vec<&PruneEffectiveness> = self
            .prune_effectiveness
            .iter()
            .rev()
            .take(PRUNE_INEFFECTIVE_RUN)
            .collect();
        // Each of the last N prunes saved below the threshold.
        let all_small = runs
            .iter()
            .all(|e| e.saved_pct < PRUNE_INEFFECTIVE_SAVING_PCT);
        // ctx% climbed strictly across them (oldest → newest). `runs` is
        // newest-first, so compare adjacent pairs in reverse.
        let mut climbing = true;
        for pair in runs.windows(2) {
            // pair[0] is newer, pair[1] is older → newer must exceed older.
            if pair[0].ctx_pct <= pair[1].ctx_pct {
                climbing = false;
                break;
            }
        }
        all_small && climbing
    }

    pub(in crate::engine::driver) fn record_auto_prune_skip(
        &self,
        agent_name: &str,
        trigger_reason: &str,
        plan: &prune::DedupPlan,
        tokens_saved: usize,
        skip_reason: &str,
        watermark_advanced: bool,
    ) {
        let data = serde_json::json!({
            "kind": "auto_prune_skipped",
            "skip_reason": skip_reason,
            "trigger_reason": trigger_reason,
            "tokens_saved": tokens_saved,
            "min_cold_savings_tokens": AUTO_PRUNE_MIN_COLD_SAVINGS_TOKENS,
            "targets": plan.targets.len(),
            "plan_reason": classify_prune_reason(plan),
            "watermark_advanced": watermark_advanced,
        });
        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::AutoPruneDiagnostic,
            Some(agent_name),
            None,
            &data,
        ) {
            tracing::warn!(error = %e, "recording auto-prune diagnostic failed");
        }
    }

    /// Cache-aware auto-prune (GOALS §10 / implementation note):
    /// before an inference call, fire `/prune` with no user prompt when the
    /// foreground history has grown since the last prune, there is something
    /// prunable, and **either**
    ///
    /// - the cache-cold predicate holds (free pruning, unchanged), **or**
    /// - the ctx%-threshold branch holds (`ctx% > auto-prune ctx %` AND
    ///   `prunable% > auto-prune prunable %`), which may prune even on a warm
    ///   cache, accepting the cache bust to reclaim context.
    ///
    /// When the threshold branch fires against a warm cache the same
    /// cache-break warning the manual `/prune` surfaces is emitted via the
    /// `Pruned { cache_break }` flag. Returns `true` if a prune happened.
    pub(in crate::engine::driver) async fn maybe_auto_prune(
        &mut self,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        if !self.at_safe_boundary() {
            return false;
        }
        let depth = self.stack.len();
        let history_len = self.stack.last().expect("stack never empty").history.len();
        // Short-circuit: nothing new since the last prune at this depth.
        // Checked before anything touching the layered config so the common
        // no-growth boundary stays a pure in-memory lookup.
        if self.prune_watermark.get(&depth).copied() == Some(history_len) {
            return false;
        }
        // One layered-config load feeds every resolve below (auto-prune
        // switch, cache config, context config) — `active_providers_config`
        // walks the on-disk config chain, so don't load it three times.
        let providers_cfg = self.active_providers_config();
        // Master switch: auto-prune off for this (provider, model) means no
        // automatic pruning at all — neither the cache-cold branch nor the
        // ctx%-threshold branch. Manual `/prune` is unaffected.
        if !Self::auto_prune_enabled_from(providers_cfg.as_ref()) {
            // Advance the watermark so we don't re-walk the config chain until
            // growth. Flipping auto-prune back on mid-session won't re-evaluate
            // until history grows past the watermark, matching the sibling
            // no-op branches (empty plan / below-min savings).
            self.prune_watermark.insert(depth, history_len);
            return false;
        }
        // Cache-cold? Resolve the active provider/model cache config and
        // evaluate the predicate. `upstream_bust = false` here: v1 has no
        // mid-prefix tool-result edit path that busts the anchor before a
        // send, so cases (a) and (b) carry the predicate.
        let cache = Self::cache_config_from(providers_cfg.as_ref());
        let secs = self.session.seconds_since_last_send();
        let cache_state = prune::cache_state(&cache, secs, false);

        // Is anything actually prunable? Avoid an empty Pruned event.
        let plan = {
            let top = self.stack.last().expect("stack never empty");
            prune::dedup_plan(&top.history)
        };
        if plan.is_empty() {
            // Advance the watermark so we don't re-walk until growth.
            self.prune_watermark.insert(depth, history_len);
            return false;
        }

        // The ctx%-threshold branch (inert when context_length is unknown):
        // prune above the configured ctx% AND prunable% even on a warm cache.
        let ctx_cfg = Self::context_config_from(providers_cfg.as_ref());
        let context_length = self.active_model_context_length();
        let metrics = context_metrics(
            context_length,
            self.context_input_tokens(context_length),
            plan.tokens_saved() as u64,
        );
        let threshold_hit = metrics.is_some_and(|m| {
            m.ctx_pct > f64::from(ctx_cfg.auto_prune_pct)
                && m.prunable_pct > f64::from(ctx_cfg.auto_prune_prunable_pct)
        });

        let Some(trigger_reason) = auto_prune_trigger_reason(cache_state, threshold_hit) else {
            return false;
        };

        let tokens_saved = plan.tokens_saved();
        let cold_branch = !auto_prune_trigger_breaks_cache(trigger_reason);
        if tokens_saved == 0 || (cold_branch && tokens_saved < AUTO_PRUNE_MIN_COLD_SAVINGS_TOKENS) {
            self.prune_watermark.insert(depth, history_len);
            let skip_reason = if tokens_saved == 0 {
                "zero_savings"
            } else {
                "below_min_cold_savings"
            };
            let agent_name = self.active_agent().to_string();
            self.record_auto_prune_skip(
                &agent_name,
                trigger_reason,
                &plan,
                tokens_saved,
                skip_reason,
                true,
            );
            return false;
        }
        // Warm cache + threshold-driven prune → the cache anchor is broken;
        // surface the same warning the manual prune does.
        let cache_break = auto_prune_trigger_breaks_cache(trigger_reason);
        self.do_prune_inner(true, cache_break, Some(trigger_reason), Some(plan), tx)
            .await;
        true
    }

    /// Publish a completed generation-tagged shadow task without ever waiting
    /// for one that is still running.
    pub(in crate::engine::driver) async fn settle_shadow_brief(&mut self) {
        let Some(state) = self.shadow_brief.take() else {
            return;
        };
        let ShadowBriefState::InFlight(mut task) = state else {
            self.shadow_brief = Some(state);
            return;
        };
        if !task.handle.is_finished() {
            self.shadow_brief = Some(ShadowBriefState::InFlight(task));
            return;
        }
        let result = (&mut task.handle).await.ok().flatten();
        if task.generation == self.shadow_brief_generation
            && !task.cancel.is_cancelled()
            && let Some(brief) = result
        {
            let ready = ShadowBriefReady {
                generation: task.generation,
                snapshot_history: task.snapshot_history,
                snapshot_turns: task.snapshot_turns,
                snapshot_tail_turns: task.snapshot_tail_turns,
                brief,
            };
            self.persist_ready_shadow_brief(&ready);
            self.shadow_brief = Some(ShadowBriefState::Ready(ready));
        }
    }

    /// Cancel only unfinished utility work. A ready shadow survives the next
    /// foreground turn and is delta-revised when compaction eventually fires.
    pub(in crate::engine::driver) async fn cancel_shadow_brief_inflight(&mut self) {
        let Some(state) = self.shadow_brief.take() else {
            return;
        };
        match state {
            ShadowBriefState::InFlight(mut task) => {
                task.cancel.cancel();
                task.handle.abort();
                let _ = (&mut task.handle).await;
                self.shadow_brief_generation = self.shadow_brief_generation.wrapping_add(1);
            }
            ready @ ShadowBriefState::Ready(_) => self.shadow_brief = Some(ready),
        }
    }

    /// Foreground preparation priority boundary. Settle first so a draft that
    /// completed before dequeue remains usable; otherwise cancel and join the
    /// unfinished task before any foreground utility inference begins.
    pub(in crate::engine::driver) async fn preempt_shadow_brief_for_foreground(&mut self) {
        self.settle_shadow_brief().await;
        self.cancel_shadow_brief_inflight().await;
    }

    /// At an idle root boundary, pre-draft a full brief once context enters the
    /// configured shadow band. Effective pruning suppresses the early half of
    /// the band; the late half always drafts so the hard line has a head start.
    pub(in crate::engine::driver) async fn maybe_shadow_brief(
        &mut self,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        if !self.at_safe_boundary() || self.stack.len() != 1 || self.auto_compacted {
            return false;
        }
        self.settle_shadow_brief().await;
        let ctx_cfg = self.resolve_context_config();
        if !ctx_cfg.compact_shadow {
            self.cancel_shadow_brief_inflight().await;
            self.shadow_brief = None;
            self.delete_durable_shadow_brief();
            return false;
        }

        let snapshot_history = self.compact_brief_history(&self.stack[0].history);
        let snapshot_turns = crate::engine::compact::complete_exchange_count(&snapshot_history);
        if matches!(
            &self.shadow_brief,
            Some(ShadowBriefState::Ready(ready))
                if snapshot_turns.saturating_sub(ready.snapshot_turns)
                    > shadow_stale_after_turns(ctx_cfg.compact_keep_recent_turns)
        ) {
            self.shadow_brief = None;
            self.delete_durable_shadow_brief();
        }
        if self.shadow_brief.is_some() {
            return false;
        }

        let context_length = self.active_model_context_length();
        let Some(metrics) =
            context_metrics(context_length, self.context_input_tokens(context_length), 0)
        else {
            return false;
        };
        let margin = ctx_cfg.compact_shadow_margin_pct.min(100);
        let start = ctx_cfg.auto_compact_pct.saturating_sub(margin);
        let late_start = ctx_cfg
            .auto_compact_pct
            .saturating_sub(margin.saturating_add(1) / 2);
        if metrics.ctx_pct < f64::from(start)
            || metrics.ctx_pct >= f64::from(ctx_cfg.auto_compact_pct)
            || (!self.prune_is_ineffective() && metrics.ctx_pct < f64::from(late_start))
        {
            return false;
        }

        let snapshot_tail_turns = crate::engine::compact::plan_compacted_history(
            &snapshot_history,
            "",
            ctx_cfg.compact_keep_recent_turns,
            context_length,
            100,
        )
        .map(|plan| plan.tail_kept)
        .unwrap_or(ctx_cfg.compact_keep_recent_turns);
        let tail_message_seqs = self.compact_tail_message_seqs(snapshot_tail_turns);
        let draft = self.compact_brief_draft(tx, snapshot_history.clone()).await;
        let mut prompt_text =
            crate::engine::compact::brief_prompt(draft.prompt_override.as_deref());
        prompt_text.push_str(&crate::engine::compact::tail_anti_duplication_instruction(
            &tail_message_seqs,
        ));
        let cancel = tokio_util::sync::CancellationToken::new();
        let task_cancel = cancel.clone();
        self.shadow_brief_generation = self.shadow_brief_generation.wrapping_add(1);
        let generation = self.shadow_brief_generation;
        let handle = tokio::spawn(async move {
            execute_compact_brief(draft, prompt_text, "compact_shadow_brief", &task_cancel).await
        });
        self.shadow_brief = Some(ShadowBriefState::InFlight(ShadowBriefInFlight {
            generation,
            snapshot_history,
            snapshot_turns,
            snapshot_tail_turns,
            cancel,
            handle,
        }));
        true
    }

    pub(in crate::engine::driver) async fn take_fresh_shadow_brief(
        &mut self,
        keep_recent_turns: usize,
    ) -> Option<ShadowBriefReady> {
        self.settle_shadow_brief().await;
        let state = self.shadow_brief.take()?;
        match state {
            ShadowBriefState::InFlight(mut task) => {
                task.cancel.cancel();
                task.handle.abort();
                let _ = (&mut task.handle).await;
                self.shadow_brief_generation = self.shadow_brief_generation.wrapping_add(1);
                None
            }
            ShadowBriefState::Ready(ready) => {
                if ready.generation == self.shadow_brief_generation
                    && !self.shadow_ready_is_stale(&ready, keep_recent_turns)
                {
                    self.delete_durable_shadow_brief();
                    Some(ready)
                } else {
                    self.delete_durable_shadow_brief();
                    None
                }
            }
        }
    }

    /// Auto-compact trigger (implementation note): at or
    /// above the configured auto-compact ctx% the foreground context is
    /// compacted automatically via the existing `/compact` machinery — no
    /// prune-first step for the compact trigger (the prune threshold handles
    /// the cheaper reclaim below the compact line). Inert when
    /// `context_length` is unknown (ctx% uncomputable). Guarded by the same
    /// `at_safe_boundary` / watermark short-circuit as auto-prune so it can't
    /// loop. Returns `true` if a compaction was started.
    pub(in crate::engine::driver) async fn maybe_auto_compact(
        &mut self,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        if !self.at_safe_boundary() {
            return false;
        }
        // Only the foreground root frame is compactable at the boundary; a
        // deeper interactive subagent frame is never auto-compacted.
        if self.stack.len() != 1 {
            return false;
        }
        if self.session.take_agent_compact_request() {
            self.do_compact_with_source(tx, "agent_requested").await;
            return true;
        }
        // One-shot: `/compact` hands off to a fresh session, so firing again
        // on this (now-abandoned) session would loop. Agent-requested compact
        // above intentionally bypasses this auto-trigger latch, matching manual
        // `/compact` semantics.
        if self.auto_compacted {
            return false;
        }
        let ctx_cfg = self.resolve_context_config();
        let context_length = self.active_model_context_length();
        let Some(metrics) =
            context_metrics(context_length, self.context_input_tokens(context_length), 0)
        else {
            return false;
        };
        // Two triggers reach the same `/compact` machinery:
        //   1. ctx% at/above the configured auto-compact line (the existing
        //      hard ceiling), OR
        //   2. escalation: recent auto-prunes stayed ineffective while ctx%
        //      kept climbing (implementation note Part B) —
        //      tiny snapshot prunes aren't keeping context in budget, so stop
        //      churning them and compact now, below the hard line.
        let over_compact_line = metrics.ctx_pct >= f64::from(ctx_cfg.auto_compact_pct);
        let escalate = self.prune_is_ineffective();
        if !over_compact_line && !escalate {
            return false;
        }
        self.auto_compacted = true;
        self.do_compact_with_source(tx, "auto").await;
        true
    }

    /// Assemble and apply a `/compact` handoff for the foreground agent.
    /// Prune-first (fixed ordering), draft the model brief, append the
    /// deterministic appendix, derive seed-tools, then reset the foreground
    /// context window in this same session.
    pub(in crate::engine::driver) async fn do_compact(&mut self, tx: &mpsc::Sender<TurnEvent>) {
        self.do_compact_with_source(tx, "manual").await;
    }

    pub(in crate::engine::driver) async fn do_compact_with_source(
        &mut self,
        tx: &mpsc::Sender<TurnEvent>,
        source: &'static str,
    ) {
        let prepared = match self.prepare_compaction_with_source(tx, source).await {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: format!("/compact: {error}; history was left unchanged"),
                    })
                    .await;
                return;
            }
        };
        if let Err(error) = self.apply_prepared_compaction(prepared, tx).await {
            let text = match error {
                PreparedCompactionApplyError::Stale { .. } => {
                    "/compact: prepared compaction is stale; history was left unchanged".to_string()
                }
                PreparedCompactionApplyError::StoreCompressedResults(error) => {
                    format!(
                        "/compact: storing recoverable pruned results failed: {error}; history was left unchanged"
                    )
                }
            };
            let _ = tx.send(TurnEvent::Notice { text }).await;
        }
    }

    pub(in crate::engine::driver) async fn prepare_compaction_with_source(
        &mut self,
        tx: &mpsc::Sender<TurnEvent>,
        source: &'static str,
    ) -> Result<PreparedCompaction, crate::engine::compact::CompactBudgetError> {
        use crate::engine::compact;

        let live_history = &self.stack.last().expect("stack never empty").history;
        let coverage = prepared_compaction_coverage(live_history);
        let tokens_before = wire_token_total(live_history);
        let context_window = self.active_model_context_length();
        let ctx_cfg = self.resolve_context_config();
        // Resolve shadow ownership before mutating history with the private
        // prune. An unfinished task is cancelled and falls back to the full
        // synchronous path; a stale ready draft is discarded likewise.
        let shadow = if ctx_cfg.compact_shadow {
            self.take_fresh_shadow_brief(ctx_cfg.compact_keep_recent_turns)
                .await
        } else {
            self.cancel_shadow_brief_inflight().await;
            self.shadow_brief = None;
            self.delete_durable_shadow_brief();
            None
        };
        let trigger_ctx_pct = match (self.context_input_tokens(context_window), context_window) {
            (Some(used), Some(window)) if window > 0 => {
                Some(used as f64 / f64::from(window) * 100.0)
            }
            _ => None,
        };

        // 0. Prune-first (lossless; denser transcript → tighter brief). This
        // intermediate form is deliberately private to compaction: publishing
        // a normal prune event/ledger here would leave a false durable trail if
        // the assembled handoff later proves too large. Keep it as a derived
        // history until the normal compaction reset commits the final plan.
        let compact_prune =
            prune::dedup_plan(&self.stack.last().expect("stack never empty").history);
        let mut pruned_history = prune::apply_plan_to(
            &self.stack.last().expect("stack never empty").history,
            &compact_prune,
        );
        let compact_condense_plan = prune::CondensePlan {
            targets: prune::condense_candidates(&pruned_history)
                .into_iter()
                .map(|candidate| {
                    let hash = crate::db::compressed_results::compressed_result_hash(
                        &candidate.original_body,
                    );
                    prune::CondenseTarget { candidate, hash }
                })
                .collect(),
        };
        pruned_history = prune::apply_condense_plan_to(&pruned_history, &compact_condense_plan);

        // 1. Model brief from the foreground agent's current history.
        let filtered_history = self.compact_brief_history(&pruned_history);
        let candidate_tail = compact::plan_compacted_history(
            &filtered_history,
            "",
            ctx_cfg.compact_keep_recent_turns,
            context_window,
            100,
        )?;
        // 2. Deterministic appendix from the runtime ledger.
        let calls = self
            .session
            .db
            .list_tool_calls_for_session(self.session.id)
            .unwrap_or_default();
        let pins = self.session.pinned_messages();
        let active_goal = self
            .session
            .db
            .current_session_goal(self.session.id, false)
            .ok()
            .flatten()
            .map(|g| {
                format!(
                    "- status: {}\n- objective: {}\n- tokens: {}/{}",
                    g.status.as_str(),
                    g.objective,
                    g.tokens_used,
                    g.token_budget
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "none".to_string())
                )
            });
        let mut appendix = compact::build_appendix(&calls, &self.cwd, &pins, &[], active_goal);
        if let Ok(overview) = self.session.db.task_todo_overview(self.session.id, 24) {
            appendix.task_overview = compact::render_task_todo_overview(&overview);
        }

        // 3. Seed-tools (read-only/idempotent; re-executed, not replayed).
        let seeds = compact::derive_seed_tools(&calls);
        let seed_tool_tokens: u64 = seeds
            .iter()
            .map(|s| crate::tokens::count(&s.args.to_string()) as u64)
            .sum();

        // 4. Draft + assemble against the exact tail that will survive. The
        // 25%-cap candidate normally fits immediately. If the produced handoff
        // forces more oldest-first trimming, redraft with that smaller list so
        // the anti-duplication instruction never promises a removed turn.
        let initial_tail_kept = candidate_tail.tail_kept;
        let initial_tail_trimmed = candidate_tail.tail_trimmed;
        let mut keep = initial_tail_kept;
        let mut tail_positions = candidate_tail.tail_message_positions;
        let (brief, handoff, mut plan) = loop {
            let tail_message_seqs = self.compact_tail_message_seqs(keep);
            let brief = if let Some(ready) = shadow.as_ref() {
                let revision_history = compact::shadow_revision_history(
                    &ready.snapshot_history,
                    &filtered_history,
                    ready.snapshot_tail_turns,
                );
                self.draft_brief_delta(tx, &tail_message_seqs, &ready.brief, revision_history)
                    .await
            } else {
                self.draft_brief(tx, &tail_message_seqs, filtered_history.clone())
                    .await
            };
            let handoff = compact::assemble_handoff(&brief, &appendix);
            let plan = match compact::plan_compacted_history(
                &filtered_history,
                &handoff,
                keep,
                context_window,
                ctx_cfg.auto_compact_pct,
            ) {
                Ok(plan) => plan,
                Err(error) => return Err(error),
            };
            if plan.tail_message_positions == tail_positions {
                break (brief, handoff, plan);
            }
            keep = plan.tail_kept;
            tail_positions = plan.tail_message_positions;
        };
        plan.tail_trimmed = initial_tail_trimmed + initial_tail_kept.saturating_sub(plan.tail_kept);

        // Persist every recoverable original for the private prune transform
        // atomically, but only after the handoff is proven to fit. A storage
        // failure aborts before model history or timeline state changes.
        let compressed_entries = compact_condense_plan
            .targets
            .into_iter()
            .map(
                |target| crate::db::compressed_results::CompressedToolResultEntry {
                    hash: target.hash,
                    session_id: self.session.id,
                    agent_id: self.active_agent().to_string(),
                    tool: target.candidate.tool,
                    call_id: target.candidate.call_id,
                    original_byte_len: target.candidate.original_body.len(),
                    compressed_byte_len: Some(target.candidate.condensed_body.len()),
                    created_at: chrono::Utc::now().timestamp(),
                    kind: "prune-boundary".to_string(),
                    content: target.candidate.original_body,
                },
            )
            .collect();
        let history = normalize_prepared_history_for_serde(plan.history);
        Ok(PreparedCompaction {
            agent_name: self.active_agent().to_string(),
            source: source.to_string(),
            prepared_at_unix_seconds: chrono::Utc::now().timestamp(),
            coverage,
            history,
            brief,
            handoff,
            tail_message_positions: plan.tail_message_positions,
            turns_summarized: plan.turns_summarized,
            tail_kept: plan.tail_kept,
            tail_trimmed: plan.tail_trimmed,
            tokens_before,
            tokens_after: plan.tokens_after,
            trigger_ctx_pct,
            seed_tool_tokens,
            seed_tools: seeds,
            compressed_entries,
        })
    }

    /// Commit a prepared compaction without drafting. This remains a
    /// `Driver` method because seed-tool re-execution needs the live tool
    /// context and `pending_seed_context`; the injected inference test pins
    /// the zero-model-call guarantee for this apply path.
    pub(in crate::engine::driver) async fn apply_prepared_compaction(
        &mut self,
        prepared: PreparedCompaction,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<(), PreparedCompactionApplyError> {
        let actual =
            prepared_compaction_coverage(&self.stack.last().expect("stack never empty").history);
        if actual != prepared.coverage {
            return Err(PreparedCompactionApplyError::Stale {
                expected: prepared.coverage,
                actual,
            });
        }

        if let Err(error) = self
            .session
            .db
            .insert_compressed_tool_results(prepared.compressed_entries.clone())
        {
            return Err(PreparedCompactionApplyError::StoreCompressedResults(
                error.to_string(),
            ));
        }
        #[cfg(test)]
        self.trace_compaction_apply("compressed_results_persisted");

        // 5. Reset the foreground model context in place.
        self.stack.last_mut().expect("stack never empty").history = prepared.history.clone();
        self.drop_stale_owner_ledgers();
        #[cfg(test)]
        self.trace_compaction_apply("live_history_swapped");

        // Persist the seed-tool plan on this session for the follow-up
        // prompt's re-execution kickoff.
        if let Err(e) = self
            .session
            .db
            .set_seed_tools(self.session.id, &prepared.seed_tools)
        {
            tracing::warn!(error = %e, "compact: persisting seed tools failed");
        } else {
            #[cfg(test)]
            self.trace_compaction_apply("seed_tools_persisted");
        }

        // Timeline boundary: `/compact` reset this session in place.
        if let Err(e) = self.session.record_session_compacted_with_source(
            &prepared.agent_name,
            crate::session::SessionCompactionRecord {
                successor_session_id: self.session.id,
                successor_short_id: &self.session.short_id,
                seed_tool_count: prepared.seed_tools.len(),
                brief_text: &prepared.brief,
                handoff_text: &prepared.handoff,
                source: &prepared.source,
                trigger_ctx_pct: prepared.trigger_ctx_pct,
                tokens_before: prepared.tokens_before,
                tokens_after: prepared.tokens_after,
                turns_summarized: prepared.turns_summarized,
                tail_kept: prepared.tail_kept,
                tail_trimmed: prepared.tail_trimmed,
                tail_messages: &prepared.history[1..],
            },
        ) {
            tracing::warn!(error = %e, "record session_compacted event failed");
        } else {
            #[cfg(test)]
            self.trace_compaction_apply("timeline_recorded");
        }

        self.run_seed_tools(&prepared.seed_tools, tx).await;
        #[cfg(test)]
        self.trace_compaction_apply("seed_tools_ran");

        let _ = tx
            .send(TurnEvent::CompactReady {
                new_session_id: self.session.id,
                handoff: prepared.handoff,
                brief: prepared.brief,
                source: prepared.source,
                trigger_ctx_pct: prepared.trigger_ctx_pct,
                tokens_before: prepared.tokens_before,
                tokens_after: prepared.tokens_after,
                turns_summarized: prepared.turns_summarized,
                tail_kept: prepared.tail_kept,
                tail_trimmed: prepared.tail_trimmed,
                seed_tool_count: prepared.seed_tools.len(),
                seed_tool_tokens: prepared.seed_tool_tokens,
            })
            .await;
        #[cfg(test)]
        self.trace_compaction_apply("compact_ready_emitted");
        Ok(())
    }

    async fn compact_brief_draft(
        &self,
        tx: &mpsc::Sender<TurnEvent>,
        history: Vec<Message>,
    ) -> CompactBriefDraft {
        let top = self.stack.last().expect("stack never empty");
        // Resolve the two `extended.*` compaction knobs from the config
        // chain (implementation note):
        // `compact_prompt` (the brief-prompt override) and `compact_model`
        // (the dedicated drafting model).
        #[cfg(test)]
        let (extended, providers) = if let Some((providers, _, _)) = &self.test_providers_override {
            (
                crate::config::extended::ExtendedConfig::default(),
                providers.clone(),
            )
        } else {
            crate::auto_title::load_configs_for(&self.cwd)
        };
        #[cfg(not(test))]
        let (extended, providers) = crate::auto_title::load_configs_for(&self.cwd);
        // Two-level model precedence: a configured `compact_model` (when it
        // resolves) drafts the brief; otherwise the active agent's own model.
        // A configured-but-unresolvable `compact_model` falls back to the
        // agent's model and surfaces a terse one-line notice — losing the
        // handoff is worse than using the wrong model (priority #1).
        let compact_model = match extended.compact_model_ref() {
            Some(model_ref) => match crate::engine::model::Model::from_ref_trusted_only(
                &providers,
                model_ref,
                self.redact.clone(),
                top.agent.model.trusted_only_flag(),
            ) {
                Ok(m) => Some(m.with_shutdown_gate(top.agent.model.shutdown_gate())),
                Err(e) => {
                    tracing::warn!(error = %e, model = %model_ref, "compact: compact_model failed to resolve; using active agent's model");
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: format!(
                                "compact_model `{model_ref}` unavailable; drafting the brief with the active agent's model."
                            ),
                        })
                        .await;
                    None
                }
            },
            None => None,
        };
        let model = compact_model
            .map(Arc::new)
            .unwrap_or_else(|| top.agent.model.clone());
        CompactBriefDraft {
            session: self.session.clone(),
            model,
            system: top.agent.system.clone(),
            history,
            params: top.agent.params.clone(),
            agent_name: top.agent.name.clone(),
            prompt_override: extended.compact_prompt,
            #[cfg(test)]
            test_calls: self.test_compact_brief_calls.clone(),
        }
    }

    async fn draft_brief(
        &self,
        tx: &mpsc::Sender<TurnEvent>,
        tail_message_seqs: &[i64],
        history: Vec<Message>,
    ) -> String {
        let draft = self.compact_brief_draft(tx, history).await;
        let mut prompt_text =
            crate::engine::compact::brief_prompt(draft.prompt_override.as_deref());
        prompt_text.push_str(&crate::engine::compact::tail_anti_duplication_instruction(
            tail_message_seqs,
        ));
        execute_compact_brief(
            draft,
            prompt_text,
            "compact_brief",
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap_or_else(|| {
            "(brief generation failed; rely on the state appendix below)".to_string()
        })
    }

    async fn draft_brief_delta(
        &self,
        tx: &mpsc::Sender<TurnEvent>,
        tail_message_seqs: &[i64],
        shadow_brief: &str,
        new_turns: Vec<Message>,
    ) -> String {
        let draft = self.compact_brief_draft(tx, new_turns).await;
        let prompt_text = crate::engine::compact::shadow_delta_prompt(
            draft.prompt_override.as_deref(),
            shadow_brief,
            tail_message_seqs,
        );
        execute_compact_brief(
            draft,
            prompt_text,
            "compact_brief_delta",
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap_or_else(|| {
            "(brief generation failed; rely on the state appendix below)".to_string()
        })
    }
}

async fn execute_compact_brief(
    draft: CompactBriefDraft,
    prompt_text: String,
    purpose: &'static str,
    cancel: &tokio_util::sync::CancellationToken,
) -> Option<String> {
    #[cfg(test)]
    if let Some(calls) = &draft.test_calls {
        if cancel.is_cancelled() {
            return None;
        }
        crate::sync::lock_or_recover(calls).push(TestCompactBriefCall {
            purpose,
            prompt: prompt_text.clone(),
            history: draft.history.clone(),
        });
        let _ = draft.session.record_event(
            crate::db::session_log::SessionEventKind::InferenceRequest,
            Some(&draft.agent_name),
            None,
            &serde_json::json!({ "usage": null, "purpose": purpose }),
        );
        return Some("test compact brief".to_string());
    }
    let call_id = uuid::Uuid::new_v4();
    match draft
        .model
        .complete_captured(
            &draft.system,
            &draft.history,
            Message::user(prompt_text),
            &[],
            draft.params,
            &draft.agent_name,
            None,
            cancel,
            None,
        )
        .await
    {
        Ok(((_, choice, usage), captured, _timing)) if !cancel.is_cancelled() => {
            if let Err(e) = draft.session.record_inference_request(
                call_id,
                &captured,
                crate::db::session_log::InferenceRequestStatus::Completed,
            ) {
                tracing::warn!(error = %e, "compact brief: record_inference_request failed");
            }
            if let Some(u) = usage
                && let Err(e) = draft.session.record_usage_utility(call_id, u)
            {
                tracing::warn!(error = %e, "compact brief: record_usage_utility failed");
            }
            let usage_json = usage.map(|u| {
                serde_json::json!({
                    "input_tokens": u.input_tokens,
                    "output_tokens": u.output_tokens,
                    "cached_input_tokens": u.cached_input_tokens,
                })
            });
            if let Err(e) = draft.session.record_event(
                crate::db::session_log::SessionEventKind::InferenceRequest,
                Some(&draft.agent_name),
                Some(&call_id.to_string()),
                &serde_json::json!({ "usage": usage_json, "purpose": purpose }),
            ) {
                tracing::warn!(error = %e, "compact brief: record inference_request event failed");
            }
            let text = crate::engine::message::extract_text(&choice);
            Some(if text.trim().is_empty() {
                "(model produced no brief; rely on the state appendix below)".to_string()
            } else {
                text
            })
        }
        Ok(_) => None,
        Err(_) if cancel.is_cancelled() => None,
        Err(e) => {
            tracing::warn!(error = %e, purpose, "compact: brief generation failed");
            Some("(brief generation failed; rely on the state appendix below)".to_string())
        }
    }
}
/// Estimate the wire-side token total of a message history via the
/// cl100k_base fallback counter over each message's serialized form. Used
/// only for the `context_pruned` timeline event's before/after figures
/// (session-log-export Part C) — a faithful proxy, the same basis the
/// tokenizer-calibration sampler uses, not an exact provider count.
pub(in crate::engine::driver) fn wire_token_total(history: &[Message]) -> u64 {
    history
        .iter()
        .map(|m| match serde_json::to_string(m) {
            Ok(s) => crate::tokens::count(&s) as u64,
            Err(_) => 0,
        })
        .sum()
}

/// Context-fill metrics for the auto-prune/auto-compact triggers
/// (implementation note). `ctx_pct` is the last request's
/// prompt size as a percentage of the model's context window; `prunable_pct`
/// is the prunable wire tokens as a percentage of the same window. Returns
/// `None` (ctx%-gated triggers inert) when the window size is unknown/zero or
/// no request has reported its usage yet — exactly the edge case the spec
/// requires the ctx%-gated paths to skip.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(in crate::engine::driver) struct ContextMetrics {
    pub(in crate::engine::driver) ctx_pct: f64,
    pub(in crate::engine::driver) prunable_pct: f64,
}

pub(in crate::engine::driver) fn context_metrics(
    context_length: Option<u32>,
    input_tokens: Option<u64>,
    prunable_tokens: u64,
) -> Option<ContextMetrics> {
    let window = context_length.filter(|n| *n > 0)?;
    let used = input_tokens?;
    let window = f64::from(window);
    Some(ContextMetrics {
        ctx_pct: used as f64 / window * 100.0,
        prunable_pct: prunable_tokens as f64 / window * 100.0,
    })
}

/// One auto-prune boundary's effectiveness, for the escalate-to-compaction
/// policy (implementation note). Both figures are known
/// only when the model window + last usage are (ctx%-gated); a prune at an
/// unknown-window boundary records nothing (the escalation path stays inert,
/// exactly like the other ctx%-gated triggers).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(in crate::engine::driver) struct PruneEffectiveness {
    /// ctx% (input tokens / window) measured just before this prune.
    pub(in crate::engine::driver) ctx_pct: f64,
    /// Tokens this prune saved, as a percentage of the model window.
    pub(in crate::engine::driver) saved_pct: f64,
}

/// Classify a prune plan's targets into the telemetry reason string
/// (implementation note Part D): `overlap-merge` when
/// every elided body was an overlapping-read partial, `exact-identity` when
/// every body was a whole-body snapshot supersession, `mixed` when both
/// kinds fired in one prune. Empty plans never reach here (no event emitted).
pub(in crate::engine::driver) fn classify_prune_reason(
    plan: &crate::engine::prune::DedupPlan,
) -> &'static str {
    let mut overlap = false;
    let mut exact = false;
    for t in &plan.targets {
        if t.elision.reason == crate::engine::prune::OVERLAP_REASON {
            overlap = true;
        } else {
            exact = true;
        }
    }
    match (overlap, exact) {
        (true, true) => "mixed",
        (true, false) => "overlap-merge",
        _ => "exact-identity",
    }
}

pub(in crate::engine::driver) fn auto_prune_trigger_reason(
    cache_state: crate::engine::prune::CacheState,
    threshold_hit: bool,
) -> Option<&'static str> {
    match cache_state {
        crate::engine::prune::CacheState::Cold(
            crate::engine::prune::ColdReason::NoCacheProvider,
        ) => Some(AUTO_PRUNE_TRIGGER_NO_CACHE_PROVIDER),
        crate::engine::prune::CacheState::Cold(crate::engine::prune::ColdReason::TtlElapsed) => {
            Some(AUTO_PRUNE_TRIGGER_CACHE_ALREADY_COLD)
        }
        crate::engine::prune::CacheState::Cold(crate::engine::prune::ColdReason::UpstreamBust) => {
            Some(AUTO_PRUNE_TRIGGER_UPSTREAM_CACHE_BUST)
        }
        crate::engine::prune::CacheState::Hot if threshold_hit => {
            Some(AUTO_PRUNE_TRIGGER_WARM_THRESHOLD)
        }
        crate::engine::prune::CacheState::Hot => None,
    }
}

pub(in crate::engine::driver) fn auto_prune_trigger_breaks_cache(trigger_reason: &str) -> bool {
    trigger_reason == AUTO_PRUNE_TRIGGER_WARM_THRESHOLD
}

#[cfg(test)]
mod tests {
    #[test]
    fn genuinely_compressed_result_has_distinct_byte_lengths() {
        let original = "line 1\nline 2\nline 3\n";
        let condensed = "[compressed tool result: omitted middle]\n";
        let entry = crate::db::compressed_results::NewCompressedToolResult {
            session_id: uuid::Uuid::new_v4(),
            agent_id: "Build",
            tool: "bash",
            call_id: "call-1",
            original_byte_len: original.len(),
            compressed_byte_len: Some(condensed.len()),
            created_at: 123,
            kind: "prune-boundary",
            content: original,
        };

        assert_ne!(
            entry.original_byte_len,
            entry.compressed_byte_len.expect("compressed length")
        );
    }
}
