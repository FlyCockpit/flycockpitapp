use super::*;

impl Session {
    /// Append one tool-call audit row to the §15b table.
    pub fn record_tool_call(&self, row: ToolCallRow) -> Result<()> {
        let provider = self.active_provider().unwrap_or_default();
        let model = self.active_model().unwrap_or_default();
        let project_root = self.project_root.to_string_lossy().into_owned();
        let event = ToolCallEvent {
            event_id: row.event_id,
            session_id: self.id,
            call_id: row.call_id,
            provider_item_id: row.identity.provider_item_id,
            provider_call_id: row.identity.provider_call_id,
            provider_call_id_source: row.identity.provider_call_id_source,
            wire_api: row.identity.wire_api,
            provider_family: row.identity.provider_family,
            timestamp: row.timestamp.timestamp(),
            model,
            provider,
            project_id: self.project_id.clone(),
            project_root,
            agent: row.agent,
            tool: row.tool,
            path: row.path,
            recovery: row.recovery,
            hard_fail: row.hard_fail,
            exit_code: row.exit_code,
            sandbox_enabled: row.sandbox_enabled,
            sandboxed: row.sandboxed,
            sandbox_unavailable_reason: row.sandbox_unavailable_reason,
            original_input_json: row.original_input_json,
            wire_input_json: row.wire_input_json,
            output: row.output,
            truncated: row.truncated,
            duration_ms: row.duration_ms,
            cockpit_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            llm_mode: Some(row.llm_mode.as_str().to_string()),
            shape_fingerprint: row.shape_fingerprint,
            hint: row.hint,
        };
        self.db
            .insert_tool_call(&event)
            .context("inserting tool_call_event")
    }

    /// Record provider-reported token usage for a round-trip: persist
    /// it to `inference_calls` for `/stats` and store the latest value
    /// on the session so the TUI can show it in the context indicator.
    /// No-op (for the DB write) when the active provider/model isn't set
    /// on the session (background calls during startup).
    ///
    /// `call_id` is the round-trip's id — the SAME value used to key the
    /// captured request body in `inference_requests`
    /// ([`Self::record_inference_request`]) so the metadata row and the
    /// full payload join on `call_id` (session-log-export Part A).
    pub fn record_usage(&self, call_id: Uuid, usage: crate::tokens::TokenUsage) -> Result<()> {
        self.record_usage_inner(call_id, usage, false)
    }

    /// Like [`Self::record_usage`] but flags the persisted `inference_calls`
    /// row as a utility / background call (the `/export debug` bundle routes
    /// it into `inference_requests_utility/`). Used by background round-trips
    /// (the `/compact` handoff brief, etc.) that aren't foreground user turns.
    pub fn record_usage_utility(
        &self,
        call_id: Uuid,
        usage: crate::tokens::TokenUsage,
    ) -> Result<()> {
        self.record_usage_inner(call_id, usage, true)
    }

    fn record_usage_inner(
        &self,
        call_id: Uuid,
        usage: crate::tokens::TokenUsage,
        is_utility: bool,
    ) -> Result<()> {
        *self.last_usage.lock().unwrap() = Some(usage);

        let (Some(provider), Some(model)) = (self.active_provider(), self.active_model()) else {
            return Ok(());
        };
        let row = crate::db::inference_calls::InferenceCallRow {
            call_id,
            session_id: self.id,
            project_id: self.project_id.clone(),
            project_root: self.project_root.to_string_lossy().into_owned(),
            model,
            provider,
            timestamp: Utc::now().timestamp(),
            input_tokens: usage.input_tokens as i64,
            output_tokens: usage.output_tokens as i64,
            cached_input_tokens: usage.cached_input_tokens as i64,
            cache_creation_input_tokens: usage.cache_creation_input_tokens as i64,
            cost_usd_micros: None,
            is_utility,
        };
        self.db
            .insert_inference_call(&row)
            .context("inserting inference_call")
    }

    /// Persist the full assembled (post-redaction) outbound request body
    /// for one inference call, keyed by `call_id` (session-log-export
    /// Part A), with its lifecycle `status`. Always-on — every call, every
    /// session. The payload is the exact as-sent form; no second redaction
    /// pass is applied. Written at DISPATCH with status `pending` and updated
    /// to its terminal value on settle so a hung/failed turn still records an
    /// attempt (implementation note).
    pub fn record_inference_request(
        &self,
        call_id: Uuid,
        payload: &Value,
        status: crate::db::session_log::InferenceRequestStatus,
    ) -> Result<()> {
        self.db
            .insert_inference_request(&call_id.to_string(), self.id, payload, status)
            .context("inserting inference_request")
    }

    /// Async variant for inference dispatch hot paths. It uses the DB writer
    /// actor directly instead of adding another `spawn_blocking` wrapper around
    /// the synchronous convenience method.
    pub async fn record_inference_request_async(
        &self,
        call_id: Uuid,
        payload: Value,
        status: crate::db::session_log::InferenceRequestStatus,
    ) -> Result<()> {
        let payload_json =
            serde_json::to_string(&payload).context("serializing request payload")?;
        let ts_ms = crate::db::session_log::now_ms();
        let call_id = call_id.to_string();
        let session_id = self.id.to_string();
        self.db
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO inference_requests
                       (call_id, session_id, ts_ms, payload_json, status)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(call_id) DO UPDATE SET
                       payload_json = excluded.payload_json,
                       status       = excluded.status",
                    params![call_id, session_id, ts_ms, payload_json, status.as_str()],
                )
                .context("inserting inference_request")?;
                Ok(())
            })
            .await
            .context("inserting inference_request")
    }

    /// Persist (or update) one tandem (shadow) inference record for
    /// model-comparison mode (implementation note),
    /// keyed by the per-row `id`. Unlike [`Self::record_inference_request`]
    /// (request body only), a tandem record additionally stores the full raw
    /// `response` + `usage`, and links back to the main call it shadows via
    /// `parent_call_id` (+ `parent_seq`/`agent` for timeline alignment).
    /// Written at dispatch (`pending`, no response) and again on settle
    /// (terminal status + captured response/usage). The `request` body is
    /// already post-redaction (reused from the main call's assembled body) —
    /// no second redaction pass.
    #[allow(clippy::too_many_arguments)]
    pub fn record_tandem_inference(
        &self,
        id: &str,
        parent_call_id: &str,
        parent_seq: Option<i64>,
        agent: Option<&str>,
        provider: &str,
        model: &str,
        request: &Value,
        response: Option<&Value>,
        usage: Option<&Value>,
        status: crate::db::session_log::InferenceRequestStatus,
    ) -> Result<()> {
        self.db
            .upsert_tandem_inference(
                id,
                self.id,
                parent_call_id,
                parent_seq,
                agent,
                provider,
                model,
                request,
                response,
                usage,
                status,
            )
            .context("inserting tandem_inference")
    }

    /// Snapshot the resolved agent-guidance file body at session start
    /// (live instructions-file diff injection, prompt
    /// `instructions-file-live-diff.md`). Called once when the session's
    /// system prompt is composed (the daemon session-worker spawn): the
    /// frozen system block carries this body, so it becomes the baseline a
    /// later in-place edit is diffed against.
    ///
    /// Resolves the same first-matching guidance file
    /// [`crate::engine::builtin`] bakes into the system block. When one
    /// resolves, stores `(path, hash)` on the session row and the body in
    /// the content-addressed `guidance_contents` table. When none resolves,
    /// clears the baseline (NULL) so the feature stays inert for this
    /// session. Best-effort: a failure here must never break session
    /// startup.
    pub fn snapshot_guidance_baseline(&self, cwd: &std::path::Path) {
        let baseline = match crate::engine::builtin::load_agent_guidance(cwd) {
            Some((path, body)) => {
                let hash = crate::engine::guidance_diff::hash_contents(&body);
                if let Err(e) = self.db.put_guidance_contents(&hash, &body) {
                    tracing::warn!(error = %e, "guidance baseline: storing contents failed");
                    return;
                }
                Some(crate::db::guidance::GuidanceBaseline {
                    path: path.display().to_string(),
                    hash,
                })
            }
            None => None,
        };
        if self.stage_pending_row(|row| {
            row.guidance_baseline_path = baseline.as_ref().map(|b| b.path.clone());
            row.guidance_baseline_hash = baseline.as_ref().map(|b| b.hash.clone());
        }) {
            return;
        }
        if let Err(e) = self.db.set_guidance_baseline(self.id, baseline.as_ref()) {
            tracing::warn!(error = %e, "guidance baseline: setting baseline failed");
        }
    }

    /// Check the resolved guidance file for an in-place edit since the
    /// session's stored baseline, and — when one is found — return the
    /// synthetic system-message body to append at the end of history (live
    /// instructions-file diff injection). The returned string is the
    /// authoritative framing header + unified diff (or full contents); the
    /// caller scrubs it through [`crate::redact`] before appending, exactly
    /// like any other outbound content.
    ///
    /// Returns `None` (no injection) when:
    /// - no baseline was stored (no guidance file at session start), or
    /// - re-resolution finds no guidance file (deleted mid-session), or
    /// - re-resolution finds a *different* file than the baseline path
    ///   (the file switched — out of scope), or
    /// - the resolved file's hash is unchanged (idempotent: already at
    ///   baseline, nothing to inject).
    ///
    /// On a real in-place change it persists the new body into the
    /// content-addressed table and **advances the baseline** to the new
    /// `(path, hash)` so the same change is injected exactly once; the next
    /// request diffs from the just-injected version.
    pub fn guidance_change_injection(&self, cwd: &std::path::Path) -> Option<String> {
        let baseline = match self.db.guidance_baseline(self.id) {
            Ok(Some(b)) => b,
            // No baseline stored → feature inert for this session.
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(error = %e, "guidance diff: reading baseline failed");
                return None;
            }
        };

        // Re-resolve the currently-winning guidance file. Deleted → None;
        // switched → a different path. Both are out of scope.
        let (current_path, current_body) = crate::engine::builtin::load_agent_guidance(cwd)?;
        let current_path = current_path.display().to_string();
        if current_path != baseline.path {
            // File deleted or a different file now wins — no in-place
            // change to track. Leave the baseline as-is; do not inject.
            return None;
        }

        let current_hash = crate::engine::guidance_diff::hash_contents(&current_body);
        if current_hash == baseline.hash {
            // Unchanged since baseline — idempotent no-op.
            return None;
        }

        // A genuine in-place edit. Persist the new body (content-addressed,
        // idempotent) and build the injection from the prior stored body.
        if let Err(e) = self.db.put_guidance_contents(&current_hash, &current_body) {
            tracing::warn!(error = %e, "guidance diff: storing new contents failed");
            return None;
        }
        let prior = self
            .db
            .guidance_contents(&baseline.hash)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "guidance diff: reading prior contents failed");
                None
            });
        let injection =
            crate::engine::guidance_diff::decide_injection(prior.as_deref(), &current_body);
        let message = crate::engine::guidance_diff::injection_message(&current_path, &injection);

        // Advance the baseline so this change injects exactly once.
        let advanced = crate::db::guidance::GuidanceBaseline {
            path: current_path,
            hash: current_hash,
        };
        if let Err(e) = self.db.set_guidance_baseline(self.id, Some(&advanced)) {
            tracing::warn!(error = %e, "guidance diff: advancing baseline failed");
            // Returning the message anyway would risk re-injecting the same
            // change next turn (baseline not advanced). Skip this injection
            // rather than risk a loop.
            return None;
        }
        Some(message)
    }

    /// Append one event to the session timeline (session-log-export Part
    /// B). Always-on, engine/daemon-owned. Returns the assigned monotonic
    /// `seq`. Best-effort callers may ignore the result.
    pub fn record_event(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        data: &Value,
    ) -> Result<i64> {
        self.record_event_with_origin(kind, agent, call_id, None, data)
    }

    pub fn record_event_with_origin(
        &self,
        kind: crate::db::session_log::SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        origin_principal: Option<&str>,
        data: &Value,
    ) -> Result<i64> {
        let lineage = current_session_event_lineage();
        self.db
            .insert_session_event_with_context(
                self.id,
                kind,
                agent,
                call_id,
                crate::db::session_log::SessionEventContext {
                    origin_principal,
                    task_call_id: lineage.as_ref().map(|l| l.task_call_id.as_str()),
                    label: lineage.as_ref().map(|l| l.label.as_str()),
                },
                data,
            )
            .context("inserting session_event")
    }

    /// Record a `context_pruned` timeline event (session-log-export Part
    /// C). Fired by the real `/prune` path (manual + cache-cold auto): a
    /// wire-only snapshot dedup that elided superseded tool-result bodies.
    /// Carries messages-before/after, wire tokens-before/after, the elided
    /// `original_event_id`s, the reason, and the trigger (auto vs manual).
    ///
    /// Because auto-prune fires right before an inference call, this event
    /// lands immediately before the next `inference_request` event in
    /// `seq` order — the two adjacent request payloads then *show* the
    /// elision directly, which is the before/after-prune audit the export
    /// is for. `agent` is the foreground agent the prune targeted.
    #[allow(clippy::too_many_arguments)]
    pub fn record_context_pruned(
        &self,
        agent: &str,
        auto: bool,
        messages_before: usize,
        messages_after: usize,
        tokens_before: u64,
        tokens_after: u64,
        elided: &[String],
        reason: &str,
        tokens_saved: u64,
        remaining_budget: Option<u64>,
        trigger_reason: Option<&str>,
    ) -> Result<i64> {
        self.record_event(
            crate::db::session_log::SessionEventKind::ContextPruned,
            Some(agent),
            None,
            &serde_json::json!({
                "kind": "prune",
                "trigger": if auto { "auto" } else { "manual" },
                "messages_before": messages_before,
                "messages_after": messages_after,
                "tokens_before": tokens_before,
                "tokens_after": tokens_after,
                // The projected cl100k_base wire saving this prune realized,
                // so `analyze-session-logs` can judge effectiveness without
                // re-diffing the adjacent request payloads.
                "tokens_saved": tokens_saved,
                // Remaining context budget (model window − post-prune input
                // tokens) when the window + last usage are known; `null`
                // otherwise (ctx%-gated metrics inert).
                "remaining_budget": remaining_budget,
                "elided": elided,
                // Present for auto-prune so exports show why it fired
                // (cold cache, no-cache provider, upstream bust, or the warm
                // ctx/prunable threshold branch). Manual `/prune` leaves it
                // null because the trigger is the user command.
                "trigger_reason": trigger_reason,
                // The classifying reason: `overlap-merge`, `exact-identity`,
                // or `mixed` — distinct from the escalation-to-compaction
                // path, which records a `session_compacted` boundary instead.
                "reason": reason,
            }),
        )
    }

    /// Record a `session_compacted` timeline boundary (session-log-export
    /// Part C). `/compact` is a fresh-thread handoff, not an in-session
    /// edit: it starts a brand-new successor session and preserves this
    /// one. Modeled as a session boundary (predecessor → successor short
    /// ids) the export follows like the fork tree, so both sessions land
    /// in one unified `events.json`. Not a `context_pruned` event.
    #[allow(dead_code)]
    pub fn record_session_compacted(
        &self,
        agent: &str,
        successor_session_id: Uuid,
        successor_short_id: &str,
        seed_tool_count: usize,
        brief_text: &str,
    ) -> Result<i64> {
        self.record_session_compacted_with_source(
            agent,
            SessionCompactionRecord {
                successor_session_id,
                successor_short_id,
                seed_tool_count,
                brief_text,
                handoff_text: brief_text,
                source: "manual",
                trigger_ctx_pct: None,
                tokens_before: 0,
                tokens_after: 0,
                turns_summarized: 0,
                tail_kept: 0,
                tail_trimmed: 0,
                tail_messages: &[],
            },
        )
    }

    pub fn record_session_compacted_with_source(
        &self,
        agent: &str,
        record: SessionCompactionRecord<'_>,
    ) -> Result<i64> {
        const INLINE_HANDOFF_MAX_BYTES: usize = 16 * 1024;
        let mut data = serde_json::json!({
            "kind": "compaction",
            "predecessor_session_id": self.id.to_string(),
            "predecessor_short_id": self.short_id,
            "successor_session_id": record.successor_session_id.to_string(),
            "successor_short_id": record.successor_short_id,
            "seed_tool_count": record.seed_tool_count,
            "brief_text": record.brief_text,
            "handoff_text": record.handoff_text,
            "source": record.source,
            "trigger_ctx_pct": record.trigger_ctx_pct,
            "tokens_before": record.tokens_before,
            "tokens_after": record.tokens_after,
            "turns_summarized": record.turns_summarized,
            "tail_kept": record.tail_kept,
            "tail_trimmed": record.tail_trimmed,
            "tail_messages": record.tail_messages,
        });
        if data.to_string().len() > INLINE_HANDOFF_MAX_BYTES {
            let handoff_id = Uuid::new_v4();
            self.db
                .store_compaction_payload(handoff_id, self.id, &data.to_string())?;
            data = serde_json::json!({
                "kind": "compaction",
                "predecessor_session_id": self.id.to_string(),
                "predecessor_short_id": self.short_id,
                "successor_session_id": record.successor_session_id.to_string(),
                "successor_short_id": record.successor_short_id,
                "seed_tool_count": record.seed_tool_count,
                "source": record.source,
                "trigger_ctx_pct": record.trigger_ctx_pct,
                "tokens_before": record.tokens_before,
                "tokens_after": record.tokens_after,
                "turns_summarized": record.turns_summarized,
                "tail_kept": record.tail_kept,
                "tail_trimmed": record.tail_trimmed,
                "handoff_ref": handoff_id.to_string(),
            });
        }
        self.record_event(
            crate::db::session_log::SessionEventKind::SessionCompacted,
            Some(agent),
            None,
            &data,
        )
    }

    /// Record a `tool_rejected` timeline event (export-audit fidelity). Fired
    /// from the dispatcher's validate-then-repair path (GOALS §12) when a call
    /// is rejected **before** it becomes a `tool_call` row — a hallucinated
    /// tool name (`not_in_advertised_set`), an unrepairable malformed call
    /// (`schema_invalid_unrepairable`), or a path-field pointing at a
    /// nonexistent file (`path_not_found`, model path-hallucination). Carries
    /// the attempted tool `name`, the `reason`, and optionally a compact
    /// corrected-shape hint when the dispatcher emitted one (token economy,
    /// project guidance priority #2): a hallucinated / unrepairable call becomes a
    /// one-query check instead of prose inference.
    /// The `call_id` is the model's per-tool-call id so the rejection joins the
    /// assistant turn that emitted it.
    pub fn record_tool_rejected(
        &self,
        agent: &str,
        call_id: &str,
        tool: &str,
        reason: &str,
    ) -> Result<i64> {
        self.record_tool_rejected_with_correction(agent, call_id, tool, reason, None)
    }

    pub fn record_tool_rejected_with_correction(
        &self,
        agent: &str,
        call_id: &str,
        tool: &str,
        reason: &str,
        correction: Option<Value>,
    ) -> Result<i64> {
        let mut data = serde_json::json!({
            "tool": tool,
            "reason": reason,
        });
        if let Some(correction) = correction {
            data["validation_correction"] = correction;
        }
        self.record_event(
            crate::db::session_log::SessionEventKind::ToolRejected,
            Some(agent),
            Some(call_id),
            &data,
        )
    }

    /// Record a `primary_swap` timeline event (export-audit fidelity). Fired
    /// whenever the root-frame primary is re-rooted (GOALS §26): an `Auto`→
    /// primary `handoff` (trigger `handoff`) or a `/plan`/`/build`/`/swarm`
    /// slash-command swap (trigger `swap_command`). Preserves the wire-vs-user
    /// split (GOALS §14): `display` is the user-facing row and `kickoff` is the
    /// model-facing wire kickoff. The `handoff` path supplies both; the
    /// slash-command swaps inject no kickoff, so `kickoff` is absent there
    /// (`None`) — never fabricated. Carries only `from`/`to`/`trigger`/`display`
    /// /`kickoff` (token economy, project guidance priority #2).
    pub fn record_primary_swap(
        &self,
        from: &str,
        to: &str,
        trigger: &str,
        display: Option<&str>,
        kickoff: Option<&str>,
    ) -> Result<i64> {
        self.record_event(
            crate::db::session_log::SessionEventKind::PrimarySwap,
            Some(from),
            None,
            &serde_json::json!({
                "from": from,
                "to": to,
                "trigger": trigger,
                "display": display,
                "kickoff": kickoff,
            }),
        )
    }

    /// Most recent provider-reported usage, if we've made any calls
    /// this session. Returns `None` before the first round-trip
    /// finishes — callers fall back to a local tiktoken estimate.
    pub fn last_usage(&self) -> Option<crate::tokens::TokenUsage> {
        *self.last_usage.lock().unwrap()
    }

    /// Seed the in-memory `last_usage` **without** writing an
    /// `inference_calls` row. Used by resume rehydration
    /// (implementation note) to recompute the context
    /// indicator from the reconstructed pruned history before the provider
    /// reports a real count — a local estimate, not a real round-trip, so
    /// it must not pollute `/stats`. The next real `record_usage` overwrites
    /// it with the provider's figure.
    pub fn set_last_usage_estimate(&self, usage: crate::tokens::TokenUsage) {
        *self.last_usage.lock().unwrap() = Some(usage);
    }
}
