use super::*;

impl Driver {
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
        let usage = self.session.last_usage();
        let metrics = context_metrics(
            self.active_model_context_length(),
            usage.map(|u| u.input_tokens),
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
        let usage = self.session.last_usage();
        let Some(metrics) = context_metrics(
            self.active_model_context_length(),
            usage.map(|u| u.input_tokens),
            0,
        ) else {
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
        use crate::engine::compact;

        let original_history = self
            .stack
            .last()
            .expect("stack never empty")
            .history
            .clone();
        let tokens_before = wire_token_total(&original_history);
        let context_window = self.active_model_context_length();
        let ctx_cfg = self.resolve_context_config();
        let trigger_ctx_pct = match (
            self.session.last_usage().map(|usage| usage.input_tokens),
            context_window,
        ) {
            (Some(used), Some(window)) if window > 0 => {
                Some(used as f64 / f64::from(window) * 100.0)
            }
            _ => None,
        };

        // 0. Prune-first (lossless; denser transcript → tighter brief). This
        // intermediate form is deliberately private to compaction: publishing
        // a normal prune event/ledger here would leave a false durable trail if
        // the assembled handoff later proves too large and we roll back.
        let compact_prune =
            prune::dedup_plan(&self.stack.last().expect("stack never empty").history);
        prune::apply_plan(
            &mut self.stack.last_mut().expect("stack never empty").history,
            &compact_prune,
        );
        let compact_condensations =
            prune::condense_candidates(&self.stack.last().expect("stack never empty").history)
                .into_iter()
                .map(|candidate| {
                    let hash = crate::db::compressed_results::compressed_result_hash(
                        &candidate.original_body,
                    );
                    prune::apply_condensed_tool_result(
                        &mut self.stack.last_mut().expect("stack never empty").history,
                        &candidate,
                        &hash,
                    );
                    (candidate, hash)
                })
                .collect::<Vec<_>>();

        // 1. Model brief from the foreground agent's current history.
        let filtered_history =
            self.compact_brief_history(&self.stack.last().expect("stack never empty").history);
        let candidate_tail = match compact::plan_compacted_history(
            &filtered_history,
            "",
            ctx_cfg.compact_keep_recent_turns,
            context_window,
            100,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                self.stack.last_mut().expect("stack never empty").history = original_history;
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: format!("/compact: {error}; history was left unchanged"),
                    })
                    .await;
                return;
            }
        };
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
            let brief = self.draft_brief(tx, &tail_message_seqs).await;
            let handoff = compact::assemble_handoff(&brief, &appendix);
            let plan = match compact::plan_compacted_history(
                &filtered_history,
                &handoff,
                keep,
                context_window,
                ctx_cfg.auto_compact_pct,
            ) {
                Ok(plan) => plan,
                Err(error) => {
                    // Prune-first operated only on the live frame, so roll it
                    // back too: an over-budget handoff must not partially
                    // mutate history or its durable/UI trail.
                    self.stack.last_mut().expect("stack never empty").history = original_history;
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: format!("/compact: {error}; history was left unchanged"),
                        })
                        .await;
                    return;
                }
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
        let compressed_entries = compact_condensations
            .into_iter()
            .map(
                |(candidate, hash)| crate::db::compressed_results::CompressedToolResultEntry {
                    hash,
                    session_id: self.session.id,
                    agent_id: self.active_agent().to_string(),
                    tool: candidate.tool,
                    call_id: candidate.call_id,
                    original_byte_len: candidate.original_body.len(),
                    compressed_byte_len: Some(candidate.condensed_body.len()),
                    created_at: chrono::Utc::now().timestamp(),
                    kind: "prune-boundary".to_string(),
                    content: candidate.original_body,
                },
            )
            .collect();
        if let Err(error) = self
            .session
            .db
            .insert_compressed_tool_results(compressed_entries)
        {
            self.stack.last_mut().expect("stack never empty").history = original_history;
            let _ = tx
                .send(TurnEvent::Notice {
                    text: format!(
                        "/compact: storing recoverable pruned results failed: {error}; history was left unchanged"
                    ),
                })
                .await;
            return;
        }

        // 5. Reset the foreground model context in place.
        self.stack.last_mut().expect("stack never empty").history = plan.history.clone();
        self.drop_stale_owner_ledgers();

        // Persist the seed-tool plan on this session for the follow-up
        // prompt's re-execution kickoff.
        if let Err(e) = self.session.db.set_seed_tools(self.session.id, &seeds) {
            tracing::warn!(error = %e, "compact: persisting seed tools failed");
        }

        // Timeline boundary: `/compact` reset this session in place.
        if let Err(e) = self.session.record_session_compacted_with_source(
            self.active_agent(),
            crate::session::SessionCompactionRecord {
                successor_session_id: self.session.id,
                successor_short_id: &self.session.short_id,
                seed_tool_count: seeds.len(),
                brief_text: &brief,
                handoff_text: &handoff,
                source,
                trigger_ctx_pct,
                tokens_before,
                tokens_after: plan.tokens_after,
                turns_summarized: plan.turns_summarized,
                tail_kept: plan.tail_kept,
                tail_trimmed: plan.tail_trimmed,
                tail_messages: &plan.history[1..],
            },
        ) {
            tracing::warn!(error = %e, "record session_compacted event failed");
        }

        self.run_seed_tools(&seeds, tx).await;

        let _ = tx
            .send(TurnEvent::CompactReady {
                new_session_id: self.session.id,
                handoff,
                brief,
                source: source.to_string(),
                trigger_ctx_pct,
                tokens_before,
                tokens_after: plan.tokens_after,
                turns_summarized: plan.turns_summarized,
                tail_kept: plan.tail_kept,
                tail_trimmed: plan.tail_trimmed,
                seed_tool_count: seeds.len(),
                seed_tool_tokens,
            })
            .await;
    }

    /// Run one model round-trip asking the foreground agent to draft the
    /// self-contained handoff brief (T6.e step 1). Falls back to a terse
    /// placeholder if the model call fails so `/compact` always produces
    /// a usable handoff (the deterministic appendix is the real safety
    /// net).
    pub(in crate::engine::driver) async fn draft_brief(
        &self,
        tx: &mpsc::Sender<TurnEvent>,
        tail_message_seqs: &[i64],
    ) -> String {
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
        let mut prompt_text =
            crate::engine::compact::brief_prompt(extended.compact_prompt.as_deref());
        prompt_text.push_str(&crate::engine::compact::tail_anti_duplication_instruction(
            tail_message_seqs,
        ));
        let prompt = Message::user(prompt_text);

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
                Ok(m) => Some(m),
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
        let model = compact_model.as_ref().unwrap_or(&top.agent.model);

        // Always-on capture (Part A): the `/compact` brief is an inference
        // call too, so persist its request body + a timeline event keyed by
        // a fresh round-trip id.
        let call_id = uuid::Uuid::new_v4();
        let brief_history = self.compact_brief_history(&top.history);
        match model
            .complete_captured(
                &top.agent.system,
                &brief_history,
                prompt,
                &[],
                top.agent.params.clone(),
                &top.agent.name,
                None,
                // The `/compact` brief is a short utility round-trip, not a
                // user-message turn; it isn't tied to the run's ctrl+c
                // cancel slot. A fresh never-cancelled token keeps the
                // signature uniform.
                &tokio_util::sync::CancellationToken::new(),
                None,
            )
            .await
        {
            Ok(((_, choice, usage), captured, _timing)) => {
                if let Err(e) = self.session.record_inference_request(
                    call_id,
                    &captured,
                    crate::db::session_log::InferenceRequestStatus::Completed,
                ) {
                    tracing::warn!(error = %e, "compact brief: record_inference_request failed");
                }
                // The `/compact` brief is background machinery, not a
                // foreground user turn: persist a utility-flagged
                // `inference_calls` row so the `/export debug` bundle routes
                // this request body into `inference_requests_utility/`.
                if let Some(u) = usage
                    && let Err(e) = self.session.record_usage_utility(call_id, u)
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
                if let Err(e) = self.session.record_event(
                    crate::db::session_log::SessionEventKind::InferenceRequest,
                    Some(&top.agent.name),
                    Some(&call_id.to_string()),
                    &serde_json::json!({ "usage": usage_json, "purpose": "compact_brief" }),
                ) {
                    tracing::warn!(error = %e, "compact brief: record inference_request event failed");
                }
                let text = crate::engine::message::extract_text(&choice);
                if text.trim().is_empty() {
                    "(model produced no brief; rely on the state appendix below)".to_string()
                } else {
                    text
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "compact: brief generation failed");
                "(brief generation failed; rely on the state appendix below)".to_string()
            }
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
