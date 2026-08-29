use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::engine::driver) struct BoundaryKey {
    activity_epoch: u64,
    coverage: PreparedCompactionCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::engine::driver) enum AutoCompactGate {
    Eligible { activity_epoch: u64 },
    BoundarySuppressed { key: BoundaryKey },
    UntilActivity { activity_epoch: u64, reason: String },
    Committed { activity_epoch: u64 },
}

impl Default for AutoCompactGate {
    fn default() -> Self {
        Self::Eligible { activity_epoch: 0 }
    }
}

impl AutoCompactGate {
    fn activity_epoch(&self) -> u64 {
        match self {
            Self::Eligible { activity_epoch }
            | Self::UntilActivity { activity_epoch, .. }
            | Self::Committed { activity_epoch } => *activity_epoch,
            Self::BoundarySuppressed { key } => key.activity_epoch,
        }
    }

    fn is_committed_current(&self) -> bool {
        matches!(self, Self::Committed { activity_epoch } if *activity_epoch == self.activity_epoch())
    }

    pub(in crate::engine::driver) fn suppresses(
        &self,
        coverage: &PreparedCompactionCoverage,
    ) -> bool {
        match self {
            Self::BoundarySuppressed { key } => {
                key.activity_epoch == self.activity_epoch() && key.coverage == *coverage
            }
            Self::UntilActivity { .. } | Self::Committed { .. } => true,
            Self::Eligible { .. } => false,
        }
    }

    fn mark_committed(&mut self) {
        *self = Self::Committed {
            activity_epoch: self.activity_epoch(),
        };
    }

    pub(in crate::engine::driver) fn external_activity(&mut self) {
        *self = Self::Eligible {
            activity_epoch: self.activity_epoch().wrapping_add(1),
        };
    }

    /// Observe an accepted submission. Only `ExternalRoot` without an
    /// oversized lease advances `activity_epoch`.
    ///
    /// Production consumption is owned by
    /// `Driver::observe_accepted_user_submission` (called from
    /// `run_user_input_with_leading_history_inner` and
    /// `record_queued_user_fold`). Oversized FCM2 phase-two materialization
    /// skips this at turn start and calls [`Self::external_activity`] after
    /// the lease is accepted. Message-only rebuilds cannot move the gate.
    pub(in crate::engine::driver) fn observe_submission(
        &mut self,
        origin: crate::engine::message::SubmissionOrigin,
        has_oversized_artifact_lease: bool,
    ) {
        if origin.advances_activity_epoch() && !has_oversized_artifact_lease {
            self.external_activity();
        }
    }

    pub(in crate::engine::driver) fn record_failure(
        &mut self,
        outcome: &PrepareCompactionError,
        coverage: PreparedCompactionCoverage,
    ) {
        use crate::engine::compact_draft::CompactDraftOutcome as O;
        let epoch = self.activity_epoch();
        *self = match outcome {
            PrepareCompactionError::Draft(O::Cancelled) => Self::Eligible {
                activity_epoch: epoch,
            },
            PrepareCompactionError::Draft(O::TransientExhausted { .. } | O::Degenerate { .. }) => {
                Self::BoundarySuppressed {
                    key: BoundaryKey {
                        activity_epoch: epoch,
                        coverage,
                    },
                }
            }
            _ => Self::UntilActivity {
                activity_epoch: epoch,
                reason: outcome.to_string(),
            },
        };
    }
}

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
    pub seed_tags: Vec<String>,
    pub seed_tool_tokens: u64,
    /// Identity of the model that AUTHORED the brief/handoff text, so the
    /// `session_compacted` record journals through the frame-carrying path
    /// against that model's trust (decision 10.3 / K1). Threaded from the
    /// compaction drafting model (`compact_model` when configured, else the
    /// active agent's model). `#[serde(default)]` keeps a shadow written before
    /// this field loadable; an empty id then resolves no trust frame and
    /// journals nothing (fail-safe).
    #[serde(default)]
    pub authoring_provider_id: String,
    #[serde(default)]
    pub authoring_model_id: String,
}

/// Identity of the model that authored a compaction brief, captured from the
/// drafting model so [`Session::record_session_compacted_with_source`] can build
/// a trust frame for the `session_compacted` record (K1).
#[derive(Clone)]
pub(in crate::engine::driver) struct CompactAuthoringModel {
    pub(in crate::engine::driver) provider_id: String,
    pub(in crate::engine::driver) model_id: String,
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
    pub fit_rung: crate::engine::compact_draft::CompactFitRung,
    pub input_coverage: crate::engine::compact_draft::CompactInputCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::engine::driver) enum PreparedCompactionApplyError {
    Stale {
        expected: PreparedCompactionCoverage,
        actual: PreparedCompactionCoverage,
    },
    #[cfg_attr(not(test), allow(dead_code))]
    StoreTextArtifacts(String),
}

#[derive(Debug)]
pub(in crate::engine::driver) enum PrepareCompactionError {
    Budget(crate::engine::compact::CompactBudgetError),
    Draft(crate::engine::compact_draft::CompactDraftOutcome),
}

impl From<crate::engine::compact::CompactBudgetError> for PrepareCompactionError {
    fn from(value: crate::engine::compact::CompactBudgetError) -> Self {
        Self::Budget(value)
    }
}

impl std::fmt::Display for PrepareCompactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::engine::compact_draft::CompactDraftOutcome as O;
        match self {
            Self::Budget(error) => error.fmt(f),
            Self::Draft(O::Cancelled) => f.write_str("brief generation was cancelled"),
            Self::Draft(O::ContextOverflow { .. }) => {
                f.write_str("brief request did not fit the compact model")
            }
            Self::Draft(O::Deterministic { diagnostic }) => {
                write!(f, "compact model rejected the brief request ({diagnostic})")
            }
            Self::Draft(O::TransientExhausted { diagnostic }) => write!(
                f,
                "compact model remained unavailable after a bounded retry ({diagnostic})"
            ),
            Self::Draft(O::Degenerate { .. }) => {
                f.write_str("compact model returned an unusably short brief twice")
            }
            Self::Draft(O::Success(_)) => f.write_str("unexpected successful draft outcome"),
        }
    }
}

#[derive(Clone)]
pub(in crate::engine::driver) struct CompactBriefDraft {
    session: Arc<Session>,
    pub(in crate::engine::driver) model: Arc<crate::engine::model::Model>,
    system: String,
    history: Vec<Message>,
    params: crate::engine::model::ModelParams,
    agent_name: String,
    prompt_override: Option<String>,
    pub(in crate::engine::driver) context_window: Option<u32>,
    quota: Arc<std::sync::Mutex<CompactPreparationQuota>>,
    #[cfg(test)]
    test_calls: Option<Arc<std::sync::Mutex<Vec<TestCompactBriefCall>>>>,
    #[cfg(test)]
    test_script: Option<Arc<std::sync::Mutex<std::collections::VecDeque<TestCompactSample>>>>,
}

#[derive(Debug, Default)]
pub(in crate::engine::driver) struct CompactPreparationQuota {
    pub(in crate::engine::driver) draft_nodes: usize,
    pub(in crate::engine::driver) wire_samples: usize,
}

impl CompactPreparationQuota {
    pub(in crate::engine::driver) fn ensure_nodes_available(
        &self,
        additional: usize,
    ) -> Result<(), String> {
        if self.draft_nodes.saturating_add(additional)
            > crate::engine::compact_draft::MAX_DRAFT_NODES
        {
            return Err(format!(
                "compaction preparation requires {additional} additional draft nodes after {} already claimed; limit is {}",
                self.draft_nodes,
                crate::engine::compact_draft::MAX_DRAFT_NODES
            ));
        }
        Ok(())
    }

    pub(in crate::engine::driver) fn claim_node(&mut self) -> Result<(), String> {
        self.ensure_nodes_available(1)?;
        self.draft_nodes += 1;
        Ok(())
    }

    pub(in crate::engine::driver) fn claim_wire_sample(&mut self) -> Result<(), String> {
        if self.wire_samples >= crate::engine::compact_draft::MAX_COMPACTION_WIRE_SAMPLES {
            return Err(format!(
                "compaction preparation exhausted {} draft nodes / {} wire samples",
                self.draft_nodes, self.wire_samples
            ));
        }
        self.wire_samples += 1;
        Ok(())
    }
}

pub(in crate::engine::driver) fn prepared_compaction_coverage(
    history: &[Message],
) -> PreparedCompactionCoverage {
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
            fit_rung: ready.fit_rung,
            input_coverage: ready.input_coverage,
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
            fit_rung: record.fit_rung,
            input_coverage: record.input_coverage,
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

    async fn delete_durable_shadow_brief(&self) {
        if let Err(error) = self
            .session
            .db
            .delete_compaction_shadow(self.session.id)
            .await
        {
            tracing::warn!(error = %error, "compact shadow: deleting durable shadow failed");
        }
    }

    async fn persist_ready_shadow_brief(&self, ready: &ShadowBriefReady) {
        if !self.resolve_context_config().compact_shadow {
            self.delete_durable_shadow_brief().await;
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
            .await
        {
            tracing::warn!(error = %error, "compact shadow: persisting durable shadow failed");
        }
    }

    pub(in crate::engine::driver) async fn load_compaction_shadow_from_store(&mut self) {
        let ctx_cfg = self.resolve_context_config();
        if !ctx_cfg.compact_shadow {
            self.shadow_brief = None;
            self.delete_durable_shadow_brief().await;
            return;
        }
        let row = match self.session.db.compaction_shadow(self.session.id).await {
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
                self.delete_durable_shadow_brief().await;
                return;
            }
        };
        let DurableCompactionShadow::ReadyBrief(record) = payload else {
            self.shadow_brief = None;
            return;
        };
        if record.generation < self.shadow_brief_generation {
            self.shadow_brief = None;
            self.delete_durable_shadow_brief().await;
            return;
        }
        self.shadow_brief_generation = record.generation;
        let ready = ShadowBriefReady::from(record);
        if self.shadow_ready_is_stale(&ready, ctx_cfg.compact_keep_recent_turns) {
            self.shadow_brief = None;
            self.delete_durable_shadow_brief().await;
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
    pub(in crate::engine::driver) async fn compact_tail_message_seqs(
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
        )
        .await
        else {
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
        if self.persist_on_reentry_owns_started_unsettled_siblings() {
            // Manual `/prune` is already deferred at the control arm; this
            // closes prune-after-switch and auto-prune, which rewrite bodies
            // without that gate.
            tracing::warn!("prune deferred: persist-on-re-entry owns keep-parked siblings");
            return;
        }
        // Capture the inputs the escalation telemetry needs before borrowing
        // `top` mutably (last reported usage + the model window).
        let window = self.active_model_context_length();
        let used_before = self.session.last_usage().map(|u| u.input_tokens);
        // A frame-looking tool body is untrusted ordinary text. Only the
        // durable owning-event projection state tells us that a call was
        // already retained, including the quota-unavailable branch that has no
        // artifact/ref row. If the state cannot be read, continue ordinary
        // prune work but do not risk a duplicate/forged artifact projection.
        let mut projection_calls = match self
            .session
            .db
            .text_artifact_projection_call_ids(self.session.id)
            .await
        {
            Ok(calls) => Some(calls),
            Err(error) => {
                tracing::warn!(%error, "loading durable text-artifact projection ids before prune failed");
                None
            }
        };

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
        let prune_artifact_candidates = projection_calls
            .as_ref()
            .map(|calls| {
                prune::condense_candidates_with_artifact_calls(
                    &top.history,
                    &calls.model_context_calls,
                )
            })
            .unwrap_or_default();
        let bodies = applied.targets.len();
        let tokens_saved = applied.tokens_saved() as u64;
        let event_messages_after = top.history.len();
        let event_tokens_after = wire_token_total(&top.history);
        // Update the watermark so auto-prune short-circuits until the
        // foreground history grows again.
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
        let effectiveness = if auto
            && depth == 1
            && bodies > 0
            && let (Some(w), Some(used)) = (window, used_before)
        {
            let window_f = f64::from(w);
            Some(PruneEffectiveness {
                ctx_pct: used as f64 / window_f * 100.0,
                saved_pct: tokens_saved as f64 / window_f * 100.0,
            })
        } else {
            None
        };

        // Timeline event (Part C): record the prune so the export can
        // audit it. Only when something was actually elided — an empty
        // prune is not a meaningful timeline entry. Ordered immediately
        // before the next `inference_request` event by construction
        // (auto-prune fires right before a `turn`).
        if bodies > 0 || !prune_artifact_candidates.is_empty() {
            let artifacts = prune_artifact_candidates
                .iter()
                .enumerate()
                .map(
                    |(slot, candidate)| crate::db::text_artifacts::TextArtifactCandidate {
                        relation:
                            crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult,
                        projection_slot: Some(slot as i64),
                        kind: crate::db::text_artifacts::TextArtifactKind::ToolResult,
                        capture_reason: crate::db::text_artifacts::CaptureReason::PruneBoundary,
                        content: candidate.original_body.clone(),
                        host_captured_bytes: candidate.original_body.len(),
                        host_original_bytes: candidate.original_body.len(),
                        host_dropped_bytes: 0,
                        stored_source_bytes: candidate.original_body.len(),
                        provenance_json: serde_json::json!({
                            "agent_id": &agent_name,
                            "tool": &candidate.tool,
                            "call_id": &candidate.call_id,
                        })
                        .to_string(),
                        created_at: chrono::Utc::now().timestamp_millis(),
                    },
                )
                .collect();
            match self
                .session
                .record_context_pruned_with_artifacts(
                    &agent_name,
                    auto,
                    messages_before,
                    event_messages_after,
                    tokens_before,
                    event_tokens_after,
                    &this_elided,
                    &reason,
                    tokens_saved,
                    remaining_budget,
                    trigger_reason,
                    artifacts,
                )
                .await
            {
                Ok(result) => {
                    if let Some(calls) = projection_calls.as_mut() {
                        for candidate in &prune_artifact_candidates {
                            calls.model_context_calls.insert(candidate.call_id.clone());
                            calls.prune_boundary_calls.insert(candidate.call_id.clone());
                        }
                    }
                    let mut admissions = std::collections::BTreeMap::new();
                    let mut malformed = false;
                    for slot in result.slots {
                        let key = (slot.relation.as_str(), slot.projection_slot);
                        if admissions.insert(key, slot.admission).is_some() {
                            malformed = true;
                        }
                    }
                    for (ordinal, candidate) in prune_artifact_candidates.iter().enumerate() {
                        let key = (
                            crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult
                                .as_str(),
                            Some(ordinal as i64),
                        );
                        let admission = admissions.remove(&key);
                        let frame = match admission {
                            Some(crate::db::text_artifacts::TextArtifactAdmission::Stored(
                                artifact,
                            )) => {
                                prune::render_prune_artifact_frame(candidate, Some(&artifact), None)
                            }
                            Some(
                                crate::db::text_artifacts::TextArtifactAdmission::ArtifactLimit,
                            ) => prune::render_prune_artifact_frame_with_agent(
                                candidate,
                                None,
                                Some("artifact_limit"),
                                Some(&agent_name),
                            ),
                            Some(
                                crate::db::text_artifacts::TextArtifactAdmission::SessionQuota,
                            ) => prune::render_prune_artifact_frame_with_agent(
                                candidate,
                                None,
                                Some("session_quota"),
                                Some(&agent_name),
                            ),
                            None => {
                                malformed = true;
                                prune::render_prune_artifact_frame_with_agent(
                                    candidate,
                                    None,
                                    Some("persistence_unavailable"),
                                    Some(&agent_name),
                                )
                            }
                        };
                        let _ =
                            prune::apply_condensed_tool_result(&mut top.history, candidate, &frame);
                    }
                    if malformed || !admissions.is_empty() {
                        tracing::error!(
                            "context prune artifact composition returned malformed owner slots"
                        );
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "record context_pruned artifact composition failed");
                    // `apply_plan` already removed the original bodies above.
                    // A failed persistence composition must therefore render
                    // the same canonical unavailable frame for *every*
                    // candidate, rather than leaving an older ad-hoc elision
                    // with no durable retrieval contract.
                    for candidate in &prune_artifact_candidates {
                        let frame = prune::render_prune_artifact_frame_with_agent(
                            candidate,
                            None,
                            Some("persistence_unavailable"),
                            Some(&agent_name),
                        );
                        let _ =
                            prune::apply_condensed_tool_result(&mut top.history, candidate, &frame);
                    }
                }
            }
        }

        // The full live elided set (cumulative across prunes), so the TUI
        // dims every currently-elided body — not just this prune's targets.
        let elided = projection_calls
            .as_ref()
            .map(|calls| {
                prune::current_elided_ids_with_prune_boundary_calls(
                    &top.history,
                    &calls.prune_boundary_calls,
                )
            })
            .unwrap_or_else(|| prune::current_elided_ids(&top.history));
        self.prune_watermark.insert(depth, top.history.len());
        let _ = top;
        if let Some(effectiveness) = effectiveness {
            self.note_prune_effectiveness(effectiveness);
        }

        // Persist the prune ledger so a later resume re-derives this exact
        // pruned form (implementation note). Only the
        // root frame's prune is resumable; an interactive subagent frame's
        // prune is transient (its frame is never resumed), so skip the
        // write there to avoid clobbering the root ledger.
        if depth == 1 {
            self.persist_prune_ledger().await;
            self.drop_stale_owner_ledgers().await;
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

    pub(in crate::engine::driver) async fn record_auto_prune_skip(
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
        // Host-generated auto-prune telemetry (skip reason, token counts, plan
        // classification) — no model-authored free text, so no session-table
        // literal can appear. Frame-less `record_event` is correct; nothing to
        // journal.
        if let Err(e) = self
            .session
            .record_event(
                crate::db::session_log::SessionEventKind::AutoPruneDiagnostic,
                Some(agent_name),
                None,
                &data,
            )
            .await
        {
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
        if self.persist_on_reentry_owns_started_unsettled_siblings() {
            return false;
        }
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
            )
            .await;
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
        let result = (&mut task.handle).await.ok();
        if task.generation == self.shadow_brief_generation
            && !task.cancel.is_cancelled()
            && let Some(crate::engine::compact_draft::CompactDraftOutcome::Success(success)) =
                result
        {
            let ready = ShadowBriefReady {
                generation: task.generation,
                snapshot_history: task.snapshot_history,
                snapshot_turns: task.snapshot_turns,
                snapshot_tail_turns: task.snapshot_tail_turns,
                brief: success.brief,
                fit_rung: success.fit_rung,
                input_coverage: success.input_coverage,
            };
            self.persist_ready_shadow_brief(&ready).await;
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
        if self.persist_on_reentry_owns_started_unsettled_siblings() {
            return false;
        }
        if !self.at_safe_boundary()
            || self.stack.len() != 1
            || self.auto_compact_gate.is_committed_current()
        {
            return false;
        }
        self.settle_shadow_brief().await;
        let ctx_cfg = self.resolve_context_config();
        if !ctx_cfg.compact_shadow {
            self.cancel_shadow_brief_inflight().await;
            self.shadow_brief = None;
            self.delete_durable_shadow_brief().await;
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
            self.delete_durable_shadow_brief().await;
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
        let auto_compact_pct = self.effective_root_auto_compact_pct(&ctx_cfg);
        let start = auto_compact_pct.saturating_sub(margin);
        let late_start = auto_compact_pct.saturating_sub(margin.saturating_add(1) / 2);
        if metrics.ctx_pct < f64::from(start)
            || metrics.ctx_pct >= f64::from(auto_compact_pct)
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
        let tail_message_seqs = self.compact_tail_message_seqs(snapshot_tail_turns).await;
        let draft = self
            .compact_brief_draft(
                tx,
                snapshot_history.clone(),
                Arc::new(std::sync::Mutex::new(CompactPreparationQuota::default())),
            )
            .await;
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
                    self.delete_durable_shadow_brief().await;
                    Some(ready)
                } else {
                    self.delete_durable_shadow_brief().await;
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
        // Keep-park idle is not a compaction boundary: persist-on-re-entry
        // still owns started-unsettled members, and apply swaps history
        // without settling the plan. Check before `take_agent_compact_request`
        // so a latched agent request survives until after persist CAS-commits.
        if self.persist_on_reentry_owns_started_unsettled_siblings() {
            return false;
        }
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
        let boundary_coverage = prepared_compaction_coverage(&self.stack[0].history);
        if self.auto_compact_gate.suppresses(&boundary_coverage) {
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
        let auto_compact_pct = self.effective_root_auto_compact_pct(&ctx_cfg);
        let over_compact_line = metrics.ctx_pct >= f64::from(auto_compact_pct);
        let escalate = self.prune_is_ineffective();
        if !over_compact_line && !escalate {
            return false;
        }
        if over_compact_line
            && auto_compact_pct == ctx_cfg.compact_nudge_pct
            && self.root_can_self_compact()
            && !self.session.compact_self_nudge_has_fired()
        {
            return false;
        }
        self.do_compact_with_source(tx, "auto").await;
        true
    }

    /// Assemble and apply a `/compact` handoff for the foreground agent.
    /// Prune-first (fixed ordering), draft the model brief, append the
    /// deterministic appendix, derive context tags, then reset the foreground
    /// context window in this same session.
    pub(in crate::engine::driver) async fn do_compact(&mut self, tx: &mpsc::Sender<TurnEvent>) {
        self.do_compact_with_source(tx, "manual").await;
    }

    /// Compaction `preCompact` / `postCompact` hook contract (asymmetric BY
    /// DESIGN, matching Claude-Code semantics):
    /// - **PREPARE failure** (assembly/brief/prune) fires NEITHER `preCompact`
    ///   nor `postCompact` — no compaction was attempted.
    /// - **APPLY failure** (the successor mutation) fires `preCompact` ONLY:
    ///   `preCompact` runs strictly before the destructive apply and cannot be
    ///   retroactively un-fired if the apply then errors; `postCompact` is
    ///   withheld because no durable successor exists.
    /// - **SUCCESS** fires BOTH, `preCompact` strictly before `postCompact`.
    pub(in crate::engine::driver) async fn do_compact_with_source(
        &mut self,
        tx: &mpsc::Sender<TurnEvent>,
        source: &'static str,
    ) {
        if self.persist_on_reentry_owns_started_unsettled_siblings() {
            // Manual `/compact` is already deferred at the control arm; this
            // closes auto-compact, agent-requested compact, and folded
            // compact markers, which replace `stack.last().history`.
            tracing::warn!("compact deferred: persist-on-re-entry owns keep-parked siblings");
            return;
        }
        let prepared = match self.prepare_compaction_with_source(tx, source).await {
            Ok(prepared) => prepared,
            Err(error) => {
                if source == "auto" {
                    let coverage = prepared_compaction_coverage(
                        &self.stack.last().expect("stack never empty").history,
                    );
                    self.auto_compact_gate.record_failure(&error, coverage);
                }
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: format!("/compact: {error}; history was left unchanged"),
                    })
                    .await;
                return;
            }
        };
        // `preCompact` observe hooks: PREPARE succeeded, so a compaction WILL be
        // attempted — fire now, strictly before the destructive apply below.
        // Matcher / `compactSource` is the compaction source (`agent_requested`
        // | `auto` | `manual`). Observe-only / fail-open. (Prepare-failure above
        // returned before reaching here, so it fires neither pre nor post.)
        self.fire_observe_hook(
            crate::config::extended::hooks::HookEvent::PreCompact,
            source,
            None,
            None,
            crate::engine::agent::hooks::ObserveFields {
                compact_source: Some(source),
                ..Default::default()
            },
        )
        .await;
        match self.apply_prepared_compaction(prepared, tx).await {
            Ok(()) => {
                // `postCompact` observe hooks: fire ONLY after the successor is
                // durable (apply returned Ok), strictly after `preCompact`. An
                // apply failure (Err arm below) fires `preCompact` only — never
                // `postCompact` — and never `stop`.
                self.fire_observe_hook(
                    crate::config::extended::hooks::HookEvent::PostCompact,
                    source,
                    None,
                    None,
                    crate::engine::agent::hooks::ObserveFields {
                        compact_source: Some(source),
                        ..Default::default()
                    },
                )
                .await;
            }
            Err(error) => {
                let text = match error {
                    PreparedCompactionApplyError::Stale { .. } => {
                        "/compact: prepared compaction is stale; history was left unchanged"
                            .to_string()
                    }
                    PreparedCompactionApplyError::StoreTextArtifacts(error) => {
                        format!(
                            "/compact: recording prepared artifacts failed: {error}; history was left unchanged"
                        )
                    }
                };
                let _ = tx.send(TurnEvent::Notice { text }).await;
            }
        }
    }

    pub(in crate::engine::driver) async fn prepare_compaction_with_source(
        &mut self,
        tx: &mpsc::Sender<TurnEvent>,
        source: &'static str,
    ) -> Result<PreparedCompaction, PrepareCompactionError> {
        use crate::engine::compact;

        #[cfg(test)]
        if self.test_compact_force_failure == Some(super::CompactForceFailure::Prepare) {
            // Exercise the real prepare-failure branch (an overflowing/cancelled
            // brief is genuinely reachable in production).
            return Err(PrepareCompactionError::Draft(
                crate::engine::compact_draft::CompactDraftOutcome::Cancelled,
            ));
        }

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
            self.delete_durable_shadow_brief().await;
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
        let pruned_history = prune::apply_plan_to(
            &self.stack.last().expect("stack never empty").history,
            &compact_prune,
        );
        // Prune-boundary artifacts are committed only with their real owning
        // `context_pruned` event.  A private compaction draft has no such
        // event, so it deliberately keeps these bodies intact rather than
        // inventing a marker or a second persistence path.

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
            .await
            .unwrap_or_default();
        let pins = self.session.pinned_messages();
        let active_goal = self
            .session
            .db
            .current_session_goal(self.session.id, false)
            .await
            .ok()
            .flatten()
            .map(|g| {
                let snapshot = g.compaction_snapshot();
                format!(
                    "- lifecycle: {} / {:?}\n- objective: {}\n- tokens: {}/{}\n- contract: {}\n- latest gap: {}",
                    snapshot.disposition.as_str(),
                    snapshot.phase,
                    snapshot.objective,
                    snapshot.tokens_used,
                    snapshot.token_budget,
                    snapshot.contract_reference.map(|id| id.to_string()).unwrap_or_else(|| "planning".to_string()),
                    snapshot.latest_gap_or_blocker.as_deref().unwrap_or("none")
                )
            });
        let mut appendix = compact::build_appendix(&calls, &self.cwd, &pins, &[], active_goal);
        if let Ok(overview) = self
            .session
            .db
            .task_todo_overview(self.session.id, 24)
            .await
        {
            appendix.task_overview = compact::render_task_todo_overview(&overview);
        }
        let history_agent_available = self.history_agent_available_for_compaction_nudge().await;

        // 3. Context tags (read-only/idempotent working-set references).
        let seed_tags = compact::derive_seed_tags(&calls);
        let seed_tool_tokens: u64 = seed_tags
            .iter()
            .map(|s| crate::tokens::count(s) as u64)
            .sum();

        // 4. Draft + assemble against the exact tail that will survive. The
        // 25%-cap candidate normally fits immediately. If the produced handoff
        // forces more oldest-first trimming, redraft with that smaller list so
        // the anti-duplication instruction never promises a removed turn.
        let initial_tail_kept = candidate_tail.tail_kept;
        let initial_tail_trimmed = candidate_tail.tail_trimmed;
        let mut keep = initial_tail_kept;
        let mut tail_positions = candidate_tail.tail_message_positions;
        let draft_quota = Arc::new(std::sync::Mutex::new(CompactPreparationQuota::default()));
        let mut authoring_model: Option<CompactAuthoringModel>;
        let (brief, handoff, mut plan) = loop {
            let tail_message_seqs = self.compact_tail_message_seqs(keep).await;
            let (brief, authoring) = if let Some(ready) = shadow.as_ref() {
                // A fitted initial shadow has only partial source coverage.
                // Its brief is useful context for a delta, but cannot stand in
                // for the snapshot prefix that fitting omitted. Feed the
                // delta the entire current source history in that case; a
                // further fitted delta then falls back to full chunked
                // synthesis below rather than promoting omitted history.
                let revision_history = if ready.input_coverage
                    == crate::engine::compact_draft::CompactInputCoverage::Partial
                {
                    filtered_history.clone()
                } else {
                    compact::shadow_revision_history(
                        &ready.snapshot_history,
                        &filtered_history,
                        ready.snapshot_tail_turns,
                    )
                };
                self.draft_brief_delta(
                    tx,
                    &tail_message_seqs,
                    &ready.brief,
                    revision_history,
                    filtered_history.clone(),
                    draft_quota.clone(),
                )
                .await?
            } else {
                self.draft_brief(
                    tx,
                    &tail_message_seqs,
                    filtered_history.clone(),
                    draft_quota.clone(),
                )
                .await?
            };
            authoring_model = Some(authoring);
            let handoff =
                compact::assemble_handoff(&brief, &appendix, &seed_tags, history_agent_available);
            let plan = match compact::plan_compacted_history(
                &filtered_history,
                &handoff,
                keep,
                context_window,
                self.effective_root_auto_compact_pct(&ctx_cfg),
            ) {
                Ok(plan) => plan,
                Err(error) => return Err(error.into()),
            };
            if plan.tail_message_positions == tail_positions {
                break (brief, handoff, plan);
            }
            keep = plan.tail_kept;
            tail_positions = plan.tail_message_positions;
        };
        let authoring_model = authoring_model.expect("draft ran at least one iteration");
        plan.tail_trimmed = initial_tail_trimmed + initial_tail_kept.saturating_sub(plan.tail_kept);

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
            seed_tags,
            authoring_provider_id: authoring_model.provider_id,
            authoring_model_id: authoring_model.model_id,
        })
    }

    async fn history_agent_available_for_compaction_nudge(&self) -> bool {
        crate::agents::resolve_with_assistant_db(&self.cwd, "history", &self.session.db)
            .await
            .ok()
            .flatten()
            .is_some_and(|def| crate::agents::is_builtin_agent("history") && def.mode.is_subagent())
    }

    /// Commit a prepared compaction without drafting. This remains a
    /// `Driver` method because applying compaction mutates live driver state;
    /// the injected inference test pins the zero-model-call guarantee for this
    /// apply path. Production apply is reached only through
    /// `do_compact_with_source`, which refuses while persist-on-re-entry owns
    /// started-unsettled keep-parked siblings.
    pub(in crate::engine::driver) async fn apply_prepared_compaction(
        &mut self,
        prepared: PreparedCompaction,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<(), PreparedCompactionApplyError> {
        #[cfg(test)]
        if self.test_compact_force_failure == Some(super::CompactForceFailure::Apply) {
            // Exercise the real apply-failure branch (a store error /
            // concurrent-history `Stale` is genuinely reachable in production).
            return Err(PreparedCompactionApplyError::StoreTextArtifacts(
                "test-injected compaction apply failure".to_string(),
            ));
        }

        let actual =
            prepared_compaction_coverage(&self.stack.last().expect("stack never empty").history);
        if actual != prepared.coverage {
            return Err(PreparedCompactionApplyError::Stale {
                expected: prepared.coverage,
                actual,
            });
        }

        // 5. Reset the foreground model context in place.
        self.stack.last_mut().expect("stack never empty").history = prepared.history.clone();
        self.drop_stale_owner_ledgers().await;
        #[cfg(test)]
        self.trace_compaction_apply("live_history_swapped");

        // Timeline boundary: `/compact` reset this session in place. The record
        // embeds the drafting model's brief/handoff text and the retained tail,
        // so journal it through the frame-carrying path against the AUTHORING
        // model's trust (K1, decision 10.3): a trusted author's session-table
        // literal journals (or fail-closed scrubs) rather than persisting raw.
        // A shadow written before the authoring id existed leaves both ids empty
        // (`#[serde(default)]`); `resolve_trust` of an empty pair falls to the
        // default (untrusted) so the frame journals nothing — the record still
        // persists. `self.config` is the turn-pinned snapshot; `self.redact` is
        // the session's pre-policy table (same shape the SubagentReport finalizer
        // uses).
        let compaction_frame = (!prepared.authoring_provider_id.is_empty()
            && !prepared.authoring_model_id.is_empty())
        .then_some(crate::session::SessionEventModelFrame {
            provider_id: &prepared.authoring_provider_id,
            model_id: &prepared.authoring_model_id,
            config: &self.config,
            session_table: self.redact.as_ref(),
        });
        if let Err(e) = self
            .session
            .record_session_compacted_with_source(
                &prepared.agent_name,
                crate::session::SessionCompactionRecord {
                    successor_session_id: self.session.id,
                    successor_short_id: &self.session.short_id(),
                    seed_tool_count: prepared.seed_tags.len(),
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
                compaction_frame,
            )
            .await
        {
            tracing::warn!(error = %e, "record session_compacted event failed");
        } else {
            #[cfg(test)]
            self.trace_compaction_apply("timeline_recorded");
        }

        self.session.reset_compact_self_nudge_latch();
        self.auto_compact_gate.mark_committed();
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
                seed_tool_count: prepared.seed_tags.len(),
                seed_tool_tokens: prepared.seed_tool_tokens,
            })
            .await;
        #[cfg(test)]
        self.trace_compaction_apply("compact_ready_emitted");
        Ok(())
    }

    pub(in crate::engine::driver) async fn compact_brief_draft(
        &self,
        tx: &mpsc::Sender<TurnEvent>,
        history: Vec<Message>,
        quota: Arc<std::sync::Mutex<CompactPreparationQuota>>,
    ) -> CompactBriefDraft {
        let top = self.stack.last().expect("stack never empty");
        // Resolve the two `extended.*` compaction knobs from the config
        // chain (implementation note):
        // `compact_prompt` (the brief-prompt override) and `compact_model`
        // (the dedicated drafting model).
        #[cfg(test)]
        let (mut extended, providers) =
            if let Some((providers, _, _)) = &self.test_providers_override {
                (
                    crate::config::extended::ExtendedConfig::default(),
                    providers.clone(),
                )
            } else {
                self.config.configs()
            };
        #[cfg(test)]
        if let Some(model_ref) = &self.test_compact_model_ref {
            extended.compact_model = Some(model_ref.clone());
        }
        #[cfg(not(test))]
        let (extended, providers) = self.config.configs();
        // Two-level model precedence: a configured `compact_model` (when it
        // resolves) drafts the brief; otherwise the active agent's own model.
        // A configured-but-unresolvable `compact_model` falls back to the
        // agent's model and surfaces a terse one-line notice — losing the
        // handoff is worse than using the wrong model (priority #1).
        let compact_model = match extended.compact_model_ref() {
            Some(model_ref) => match crate::engine::model::Model::from_ref(
                &providers,
                model_ref,
                self.redact.clone(),
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
        let context_window = providers
            .resolve_effective_model_capabilities(
                model.provider_id(),
                model.model_id_ref(),
                providers.resolution_generation,
            )
            .context_tokens;
        CompactBriefDraft {
            session: self.session.clone(),
            model,
            system: top.agent.system.clone(),
            history,
            params: top.agent.params.clone(),
            agent_name: top.agent.name.clone(),
            prompt_override: extended.compact_prompt,
            // Model metadata is resolved through the same driver accounting
            // path used by trigger and post-compact planning. Unknown remains
            // unknown: the fitter will allow one verbatim attempt only.
            context_window,
            quota,
            #[cfg(test)]
            test_calls: self.test_compact_brief_calls.clone(),
            #[cfg(test)]
            test_script: self.test_compact_brief_script.clone(),
        }
    }

    async fn draft_brief(
        &self,
        tx: &mpsc::Sender<TurnEvent>,
        tail_message_seqs: &[i64],
        history: Vec<Message>,
        quota: Arc<std::sync::Mutex<CompactPreparationQuota>>,
    ) -> Result<(String, CompactAuthoringModel), PrepareCompactionError> {
        let draft = self.compact_brief_draft(tx, history.clone(), quota).await;
        // The authoring model's identity — the drafting model resolved above —
        // is threaded onto the prepared compaction so the `session_compacted`
        // record journals against its trust (K1).
        let authoring = CompactAuthoringModel {
            provider_id: draft.model.provider_id().to_string(),
            model_id: draft.model.model_id_ref().to_string(),
        };
        let mut prompt_text =
            crate::engine::compact::brief_prompt(draft.prompt_override.as_deref());
        prompt_text.push_str(&crate::engine::compact::tail_anti_duplication_instruction(
            tail_message_seqs,
        ));
        let direct = execute_compact_brief(
            draft.clone(),
            prompt_text.clone(),
            "compact_brief",
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        match direct {
            crate::engine::compact_draft::CompactDraftOutcome::Success(success)
                if success.input_coverage
                    == crate::engine::compact_draft::CompactInputCoverage::Full =>
            {
                return Ok((success.brief, authoring));
            }
            crate::engine::compact_draft::CompactDraftOutcome::Success(_)
            | crate::engine::compact_draft::CompactDraftOutcome::ContextOverflow { .. } => {}
            failure => return Err(PrepareCompactionError::Draft(failure)),
        }

        let Some(window) = draft.context_window else {
            return Err(PrepareCompactionError::Draft(
                crate::engine::compact_draft::CompactDraftOutcome::ContextOverflow {
                    diagnostic: "full history overflowed with no declared context window"
                        .to_string(),
                },
            ));
        };
        let budget = crate::engine::compact_draft::CompactRequestBudget::new(
            window,
            &draft.system,
            &prompt_text,
            &history,
        );
        let plan = crate::engine::compact_draft::plan_chunked_synthesis(
            &history,
            budget.history_allowance(),
        )
        .map_err(|diagnostic| {
            PrepareCompactionError::Draft(
                crate::engine::compact_draft::CompactDraftOutcome::ContextOverflow { diagnostic },
            )
        })?;
        let synthesis_nodes = plan.draft_nodes.saturating_sub(1);
        let quota_check =
            crate::sync::lock_or_recover(&draft.quota).ensure_nodes_available(synthesis_nodes);
        if let Err(diagnostic) = quota_check {
            return Err(PrepareCompactionError::Draft(
                crate::engine::compact_draft::CompactDraftOutcome::ContextOverflow { diagnostic },
            ));
        }
        let cancel = tokio_util::sync::CancellationToken::new();
        let chunk_instruction = "Summarize this chronological source chunk faithfully. Preserve decisions, constraints, tool findings, failures, and the next action. A deterministic appendix will be appended by the host after final synthesis; do not invent or reproduce it.";
        let mut summaries = Vec::with_capacity(plan.chunks.len());
        for chunk in plan.chunks {
            let mut node = draft.clone();
            node.history = chunk;
            let outcome = execute_compact_brief(
                node,
                chunk_instruction.to_string(),
                "compact_chunk_brief",
                &cancel,
            )
            .await;
            match outcome {
                crate::engine::compact_draft::CompactDraftOutcome::Success(success)
                    if success.input_coverage
                        == crate::engine::compact_draft::CompactInputCoverage::Full =>
                {
                    summaries.push(success.brief)
                }
                crate::engine::compact_draft::CompactDraftOutcome::Success(_) => {
                    return Err(PrepareCompactionError::Draft(
                        crate::engine::compact_draft::CompactDraftOutcome::ContextOverflow {
                            diagnostic: "chunk leaf could not retain its complete exchange set"
                                .to_string(),
                        },
                    ));
                }
                failure => return Err(PrepareCompactionError::Draft(failure)),
            }
        }
        let merge_instruction = "Merge these adjacent chronological chunk summaries without dropping information or changing chronology. Preserve decisions, constraints, tool findings, failures, and next actions. A deterministic appendix will be appended later by the host.";
        while summaries.len() > 1 {
            let mut merged = Vec::with_capacity(summaries.len().div_ceil(2));
            let mut iter = summaries.into_iter();
            while let Some(left) = iter.next() {
                let Some(right) = iter.next() else {
                    merged.push(left);
                    break;
                };
                let mut node = draft.clone();
                node.history = vec![
                    Message::user(format!("<earlier_chunk>\n{left}\n</earlier_chunk>")),
                    Message::user(format!("<later_chunk>\n{right}\n</later_chunk>")),
                ];
                let outcome = execute_compact_brief(
                    node,
                    merge_instruction.to_string(),
                    "compact_chunk_merge",
                    &cancel,
                )
                .await;
                match outcome {
                    crate::engine::compact_draft::CompactDraftOutcome::Success(success)
                        if success.input_coverage
                            == crate::engine::compact_draft::CompactInputCoverage::Full =>
                    {
                        merged.push(success.brief)
                    }
                    crate::engine::compact_draft::CompactDraftOutcome::Success(_) => {
                        return Err(PrepareCompactionError::Draft(
                            crate::engine::compact_draft::CompactDraftOutcome::ContextOverflow {
                                diagnostic: "recursive chunk merge could not retain both inputs"
                                    .to_string(),
                            },
                        ));
                    }
                    failure => return Err(PrepareCompactionError::Draft(failure)),
                }
            }
            summaries = merged;
        }
        let mut final_node = draft;
        final_node.history = vec![Message::user(format!(
            "<complete_ordered_chunk_synthesis>\n{}\n</complete_ordered_chunk_synthesis>",
            summaries.pop().expect("chunk plan is non-empty")
        ))];
        if let Some(range) = crate::engine::compact::complete_exchange_ranges(&history).pop() {
            final_node.history.extend_from_slice(&history[range]);
        }
        let final_outcome = execute_compact_brief(
            final_node,
            prompt_text,
            "compact_chunk_final_synthesis",
            &cancel,
        )
        .await;
        match final_outcome {
            crate::engine::compact_draft::CompactDraftOutcome::Success(mut success)
                if success.input_coverage
                    == crate::engine::compact_draft::CompactInputCoverage::Full =>
            {
                success.fit_rung = crate::engine::compact_draft::CompactFitRung::ChunkedSynthesis;
                Ok((success.brief, authoring))
            }
            crate::engine::compact_draft::CompactDraftOutcome::Success(_) => {
                Err(PrepareCompactionError::Draft(
                    crate::engine::compact_draft::CompactDraftOutcome::ContextOverflow {
                        diagnostic: "final chunk synthesis did not fit with full coverage"
                            .to_string(),
                    },
                ))
            }
            failure => Err(PrepareCompactionError::Draft(failure)),
        }
    }

    pub(in crate::engine::driver) async fn draft_brief_delta(
        &self,
        tx: &mpsc::Sender<TurnEvent>,
        tail_message_seqs: &[i64],
        shadow_brief: &str,
        revision_history: Vec<Message>,
        full_history: Vec<Message>,
        quota: Arc<std::sync::Mutex<CompactPreparationQuota>>,
    ) -> Result<(String, CompactAuthoringModel), PrepareCompactionError> {
        let draft = self
            .compact_brief_draft(tx, revision_history.clone(), quota.clone())
            .await;
        let authoring = CompactAuthoringModel {
            provider_id: draft.model.provider_id().to_string(),
            model_id: draft.model.model_id_ref().to_string(),
        };
        let prompt_text = crate::engine::compact::shadow_delta_prompt(
            draft.prompt_override.as_deref(),
            shadow_brief,
            tail_message_seqs,
        );
        let outcome = execute_compact_brief(
            draft,
            prompt_text,
            "compact_brief_delta",
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        match outcome {
            crate::engine::compact_draft::CompactDraftOutcome::Success(success)
                if success.input_coverage
                    == crate::engine::compact_draft::CompactInputCoverage::Full =>
            {
                Ok((success.brief, authoring))
            }
            crate::engine::compact_draft::CompactDraftOutcome::Success(_)
            | crate::engine::compact_draft::CompactDraftOutcome::ContextOverflow { .. } => {
                // A fitted delta is only a partial precursor. Re-run from the
                // complete current source history so the foreground path
                // enters the same full-coverage chunk synthesis as a non-shadow
                // compact instead of promoting the partial shadow. A full
                // shadow's revision history intentionally contains only its
                // prior tail plus newer turns, so it is not a full-coverage
                // fallback source by itself.
                self.draft_brief(tx, tail_message_seqs, full_history, quota)
                    .await
            }
            failure => Err(PrepareCompactionError::Draft(failure)),
        }
    }
}

pub(in crate::engine::driver) async fn execute_compact_brief(
    mut draft: CompactBriefDraft,
    prompt_text: String,
    purpose: &'static str,
    cancel: &tokio_util::sync::CancellationToken,
) -> crate::engine::compact_draft::CompactDraftOutcome {
    use crate::engine::compact_draft::{
        CompactDraftOutcome as O, CompactDraftSuccess, CompactSampleClass,
        MAX_WIRE_SAMPLES_PER_NODE,
    };
    if let Err(diagnostic) = crate::sync::lock_or_recover(&draft.quota).claim_node() {
        return O::ContextOverflow { diagnostic };
    }
    let source_history = draft.history.clone();
    let fitted = match crate::engine::compact_draft::fit_compact_request(
        &draft.history,
        &draft.system,
        &prompt_text,
        draft.context_window,
    ) {
        Ok(fitted) => fitted,
        Err(diagnostic) => return O::ContextOverflow { diagnostic },
    };
    draft.history = fitted.history;
    let mut fit_rung = fitted.rung;
    let mut input_coverage = fitted.coverage;
    #[cfg(test)]
    if let Some(calls) = &draft.test_calls {
        for attempt in 1..=MAX_WIRE_SAMPLES_PER_NODE {
            if let Err(diagnostic) = crate::sync::lock_or_recover(&draft.quota).claim_wire_sample()
            {
                return O::ContextOverflow { diagnostic };
            }
            if cancel.is_cancelled() {
                return O::Cancelled;
            }
            crate::sync::lock_or_recover(calls).push(TestCompactBriefCall {
                purpose,
                prompt: prompt_text.clone(),
                history: draft.history.clone(),
                attempt,
                fit_rung,
            });
            let scripted = draft
                .test_script
                .as_ref()
                .and_then(|script| crate::sync::lock_or_recover(script).pop_front());
            let Some(scripted) = scripted else {
                record_compact_sample_observation(
                    &draft, purpose, attempt, fit_rung, "success", None,
                )
                .await;
                return O::Success(CompactDraftSuccess {
                    brief: "test compact brief".to_string(),
                    fit_rung,
                    input_coverage,
                    attempts: attempt,
                });
            };
            match scripted {
                TestCompactSample::Success(text) => {
                    let chars = crate::engine::compact_draft::cleaned_brief_chars(&text);
                    if crate::engine::compact_draft::is_degenerate_brief(&text) {
                        record_compact_sample_observation(
                            &draft,
                            purpose,
                            attempt,
                            fit_rung,
                            "degenerate",
                            Some(&format!("{chars} non-whitespace characters")),
                        )
                        .await;
                        if attempt < MAX_WIRE_SAMPLES_PER_NODE {
                            continue;
                        }
                        return O::Degenerate {
                            non_whitespace_chars: chars,
                        };
                    }
                    record_compact_sample_observation(
                        &draft, purpose, attempt, fit_rung, "success", None,
                    )
                    .await;
                    return O::Success(CompactDraftSuccess {
                        brief: text,
                        fit_rung,
                        input_coverage,
                        attempts: attempt,
                    });
                }
                TestCompactSample::Cancelled => {
                    record_compact_sample_observation(
                        &draft,
                        purpose,
                        attempt,
                        fit_rung,
                        "cancelled",
                        None,
                    )
                    .await;
                    return O::Cancelled;
                }
                TestCompactSample::Error {
                    message,
                    status,
                    typed_timeout,
                } => {
                    let classification = crate::engine::compact_draft::classify_sample_error(
                        false,
                        &message,
                        status,
                        typed_timeout,
                    );
                    record_compact_sample_observation(
                        &draft,
                        purpose,
                        attempt,
                        fit_rung,
                        match classification {
                            CompactSampleClass::Cancelled => "cancelled",
                            CompactSampleClass::ContextOverflow => "context_overflow",
                            CompactSampleClass::Deterministic => "deterministic",
                            CompactSampleClass::Transient => "transient",
                        },
                        Some(&compact_diagnostic(&draft, &message)),
                    )
                    .await;
                    match classification {
                        CompactSampleClass::Cancelled => return O::Cancelled,
                        CompactSampleClass::ContextOverflow => {
                            if draft.context_window.is_some()
                                && attempt < MAX_WIRE_SAMPLES_PER_NODE
                                && let Some(smaller) =
                                    crate::engine::compact_draft::next_smaller_fit(
                                        &source_history,
                                        &draft.history,
                                        fit_rung,
                                    )
                            {
                                draft.history = smaller.history;
                                fit_rung = smaller.rung;
                                input_coverage = smaller.coverage;
                                continue;
                            }
                            return O::ContextOverflow {
                                diagnostic: compact_diagnostic(&draft, &message),
                            };
                        }
                        CompactSampleClass::Deterministic => {
                            return O::Deterministic {
                                diagnostic: compact_diagnostic(&draft, &message),
                            };
                        }
                        CompactSampleClass::Transient if attempt < MAX_WIRE_SAMPLES_PER_NODE => {}
                        CompactSampleClass::Transient => {
                            return O::TransientExhausted {
                                diagnostic: compact_diagnostic(&draft, &message),
                            };
                        }
                    }
                }
            }
        }
        unreachable!("compact test sampler has a fixed non-zero attempt budget");
    }
    let mut last_transient = String::new();
    for attempt in 1..=MAX_WIRE_SAMPLES_PER_NODE {
        if let Err(diagnostic) = crate::sync::lock_or_recover(&draft.quota).claim_wire_sample() {
            return O::ContextOverflow { diagnostic };
        }
        let call_id = uuid::Uuid::new_v4();
        let sampled = draft
            .model
            .complete_captured_compact_utility(
                &draft.system,
                &draft.history,
                Message::user(prompt_text.clone()),
                &[],
                draft.params.clone(),
                &draft.agent_name,
                cancel,
            )
            .await;
        match sampled {
            Ok(((_, choice, usage), captured, _timing)) if !cancel.is_cancelled() => {
                let compact_session_table = draft.model.session_redact_table();
                if let Err(e) = draft
                    .session
                    .record_inference_request(
                        call_id,
                        &captured,
                        crate::db::session_log::InferenceRequestStatus::Completed,
                        compact_session_table.as_ref(),
                        draft.model.is_trusted(),
                    )
                    .await
                {
                    tracing::warn!(error = %e, "compact brief: record_inference_request failed");
                }
                if let Some(u) = usage
                    && let Err(e) = draft.session.record_usage_utility(call_id, u).await
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
                // Host-generated compact-brief inference metadata (token usage,
                // purpose, attempt, host-computed fit_rung/classification). The
                // model's drafted brief TEXT is not carried here — `choice` is only
                // read to classify degenerate-vs-success — so this InferenceRequest
                // payload holds no model-authored free text and no session-table
                // literal. Frame-less `record_event` is correct; nothing to journal.
                if let Err(e) = draft
                    .session
                    .record_event(
                        crate::db::session_log::SessionEventKind::InferenceRequest,
                        Some(&draft.agent_name),
                        Some(&call_id.to_string()),
                        &serde_json::json!({
                            "usage": usage_json,
                            "purpose": purpose,
                            "attempt": attempt,
                            "fit_rung": format!("{fit_rung:?}"),
                            "classification": if crate::engine::compact_draft::is_degenerate_brief(&crate::engine::message::extract_text(&choice)) { "degenerate" } else { "success" },
                        }),
                    )
                    .await
                {
                    tracing::warn!(error = %e, "compact brief: record inference_request event failed");
                }
                let text = crate::engine::message::extract_text(&choice);
                let cleaned_chars = crate::engine::compact_draft::cleaned_brief_chars(&text);
                if crate::engine::compact_draft::is_degenerate_brief(&text) {
                    record_compact_sample_observation(
                        &draft,
                        purpose,
                        attempt,
                        fit_rung,
                        "degenerate",
                        Some(&format!("{cleaned_chars} non-whitespace characters")),
                    )
                    .await;
                    if attempt < MAX_WIRE_SAMPLES_PER_NODE {
                        continue;
                    }
                    return O::Degenerate {
                        non_whitespace_chars: cleaned_chars,
                    };
                }
                return O::Success(CompactDraftSuccess {
                    brief: text,
                    fit_rung,
                    input_coverage,
                    attempts: attempt,
                });
            }
            Ok(_) => return O::Cancelled,
            Err(_) if cancel.is_cancelled() => return O::Cancelled,
            Err(e) => {
                // Keep the raw completion detail in-process only while the
                // classifier recognizes a context-overflow response. Rig 0.42
                // can render provider request ids in its display error, so the
                // log and durable diagnostic must use the common safe
                // projection instead of formatting a provider error.
                let raw_error = e.to_string();
                let safe = crate::engine::model::safe_inference_error_detail(&e);
                if let Some(safe) = safe {
                    tracing::warn!(
                        purpose,
                        provider_detail = safe.marker,
                        observed_status = ?safe.observed_status,
                        recovery = safe.recovery.as_str(),
                        "compact: brief generation failed"
                    );
                } else {
                    tracing::warn!(
                        purpose,
                        provider_detail = "unavailable",
                        "compact: brief generation failed"
                    );
                }
                let diagnostic_input = safe.map_or(raw_error.as_str(), |safe| safe.marker);
                let diagnostic = compact_diagnostic(&draft, diagnostic_input);
                let completion_error = e.downcast_ref::<rig::completion::CompletionError>();
                let status = safe.and_then(|safe| safe.observed_status).or_else(|| {
                    completion_error.and_then(crate::engine::model::rig_boundary::http_status_of)
                });
                let typed_timeout = completion_error
                    .and_then(crate::engine::model::rig_boundary::stream_timeout_kind)
                    .is_some();
                let classification = crate::engine::compact_draft::classify_sample_error(
                    false,
                    &raw_error,
                    status,
                    typed_timeout,
                );
                record_compact_sample_observation(
                    &draft,
                    purpose,
                    attempt,
                    fit_rung,
                    match classification {
                        CompactSampleClass::Cancelled => "cancelled",
                        CompactSampleClass::ContextOverflow => "context_overflow",
                        CompactSampleClass::Deterministic => "deterministic",
                        CompactSampleClass::Transient => "transient",
                    },
                    Some(&diagnostic),
                )
                .await;
                match classification {
                    CompactSampleClass::Cancelled => return O::Cancelled,
                    CompactSampleClass::ContextOverflow => {
                        // Provider accounting can be stricter than the local
                        // estimator. Spend the node's one remaining wire
                        // sample only on a strictly smaller whole-exchange
                        // suffix; never retry the known-overflowing input.
                        if draft.context_window.is_some()
                            && attempt < MAX_WIRE_SAMPLES_PER_NODE
                            && let Some(smaller) = crate::engine::compact_draft::next_smaller_fit(
                                &source_history,
                                &draft.history,
                                fit_rung,
                            )
                        {
                            draft.history = smaller.history;
                            fit_rung = smaller.rung;
                            input_coverage = smaller.coverage;
                            continue;
                        }
                        return O::ContextOverflow { diagnostic };
                    }
                    CompactSampleClass::Deterministic => return O::Deterministic { diagnostic },
                    CompactSampleClass::Transient if attempt < MAX_WIRE_SAMPLES_PER_NODE => {
                        last_transient = diagnostic;
                    }
                    CompactSampleClass::Transient => {
                        return O::TransientExhausted { diagnostic };
                    }
                }
            }
        }
    }
    O::TransientExhausted {
        diagnostic: last_transient,
    }
}

async fn record_compact_sample_observation(
    draft: &CompactBriefDraft,
    purpose: &'static str,
    attempt: u8,
    fit_rung: crate::engine::compact_draft::CompactFitRung,
    classification: &'static str,
    diagnostic: Option<&str>,
) {
    let diagnostic = diagnostic.map(crate::engine::compact_draft::bounded_diagnostic);
    // Host-generated compact-sample observation: purpose/attempt/fit_rung/
    // classification are host constants and `diagnostic` is a host/provider
    // failure diagnostic (bounded), never the model's drafted brief text — so this
    // InferenceRequest payload carries no model-authored session-table literal.
    // Frame-less `record_event` is correct; nothing to journal.
    if let Err(error) = draft
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::InferenceRequest,
            Some(&draft.agent_name),
            None,
            &serde_json::json!({
                "purpose": purpose,
                "attempt": attempt,
                "fit_rung": format!("{fit_rung:?}"),
                "classification": classification,
                "diagnostic": diagnostic,
            }),
        )
        .await
    {
        tracing::warn!(%error, "compact brief: record sample observation failed");
    }
}

fn compact_diagnostic(draft: &CompactBriefDraft, text: &str) -> String {
    crate::engine::compact_draft::bounded_model_diagnostic(&draft.model, text)
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
    fn artifact_frame_never_claims_a_shorter_stored_body() {
        let original = "line 1\nline 2\nline 3\n";
        let candidate = crate::engine::prune::CondenseCandidate {
            history_index: 0,
            tool: "bash".to_string(),
            call_id: "call-1".to_string(),
            original_body: original.to_string(),
            condensed_body: "summary".to_string(),
        };
        let frame = crate::engine::prune::render_prune_artifact_frame(
            &candidate,
            None,
            Some("artifact_limit"),
        );

        assert!(frame.contains(&format!("\"content_bytes\":{}", original.len())));
        assert!(frame.contains(&format!("\"stored_source_bytes\":{}", original.len())));
    }
}
