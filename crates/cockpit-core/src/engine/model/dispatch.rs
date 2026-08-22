use super::*;
use futures::StreamExt;
use rig::completion::{CompletionModel, CompletionRequestBuilder};

fn configured_completion_request<M: CompletionModel + Clone>(
    model: M,
    system: &str,
    history: &[Message],
    prompt: Message,
    tools: &[ToolDefinition],
    params: &ModelParams,
    additional_params: Option<serde_json::Value>,
) -> CompletionRequestBuilder<M> {
    let mut request = model
        .completion_request(prompt)
        .messages(history.iter().cloned())
        .tools(tools.to_vec())
        .temperature_opt(params.temperature)
        .max_tokens_opt(params.max_tokens)
        .additional_params_opt(additional_params);
    if !system.is_empty() {
        request = request.preamble(system.to_string());
    }
    if params.tools_required && !tools.is_empty() {
        request = request.tool_choice(ToolChoice::Required);
    }
    request
}

fn choice_text(choice: &[AssistantContent]) -> String {
    choice
        .iter()
        .filter_map(|content| match content {
            AssistantContent::Text(text) => Some(text.text.as_str()),
            _ => None,
        })
        .collect()
}

impl Model {
    /// One-shot, non-streaming, no-tools text completion. Used by
    /// background tasks (auto-titling, prompt-injection guard) that
    /// just want a string back without the streaming + tool-dispatch
    /// machinery of [`Self::complete`]. Returns the assistant's full
    /// text response, trimmed.
    #[allow(dead_code)]
    pub async fn text_completion(&self, prompt: &str) -> Result<String> {
        self.text_completion_for(UtilityCallSite::AdHocBackground, prompt)
            .await
    }

    pub async fn text_completion_for(&self, site: UtilityCallSite, prompt: &str) -> Result<String> {
        self.text_completion_with_params(site, ModelParams::default(), prompt)
            .await
    }

    pub async fn text_completion_with_params(
        &self,
        site: UtilityCallSite,
        params: ModelParams,
        prompt: &str,
    ) -> Result<String> {
        let guard = self.outbound_guard();
        // Inference-dispatch chokepoint: refuse a *new* provider request once
        // the daemon has begun draining. Background utility calls are abandoned
        // immediately; turn-blocking utility calls remain owned by the parent
        // turn's park/drain-grace semantics.
        if site.budget_class() == UtilityBudgetClass::Background && self.gate().is_draining() {
            return Err(anyhow::Error::new(InferenceGated));
        }
        // Non-bypassable redaction chokepoint (GOALS §7,
        // `redaction-cover-all-llm-requests.md`): scrub the outbound prompt
        // before any provider work. A disabled/empty table passes it through.
        let prompt = guard.scrub(prompt);
        let prompt = prompt.as_str();
        let params = self.utility_params_for(site, params);
        self.with_utility_timeout(site, async {
            match self {
                Model::OpenAi {
                    client, model_id, ..
                } => {
                    let wire_api = self.resolve_live_wire_api_for_base_url(client.base_url());
                    openai_text_completion(
                        client,
                        model_id,
                        wire_api,
                        &params,
                        None,
                        prompt,
                        "text_completion: prompt failed",
                    )
                    .await
                }
                Model::ChatGpt { model, .. } => {
                    let response = configured_completion_request(
                        build_chatgpt_completion_model(model.clone()),
                        "",
                        &[],
                        Message::user(prompt),
                        &[],
                        &params,
                        chatgpt_additional_params(&params),
                    )
                    .send()
                    .await
                    .context("text_completion: send failed")?;
                    Ok(choice_text(&response.choice).trim().to_string())
                }
                Model::Anthropic { model, .. } => {
                    let response = configured_completion_request(
                        build_anthropic_completion_model(model.clone()),
                        "",
                        &[],
                        Message::user(prompt),
                        &[],
                        &params,
                        anthropic_additional_params(&params),
                    )
                    .send()
                    .await
                    .context("text_completion: send failed")?;
                    Ok(choice_text(&response.choice).trim().to_string())
                }
            }
        })
        .await
    }

    /// One-shot, history-free text completion with a fixed `system`
    /// preamble. Like [`Self::text_completion`] but lets a background
    /// caller (the request-preflight rewrite, implementation note)
    /// set the system contract separately from the user payload. Returns
    /// the trimmed free-text response.
    #[allow(dead_code)]
    pub async fn text_completion_with_system(&self, system: &str, prompt: &str) -> Result<String> {
        self.text_completion_with_system_for(UtilityCallSite::AdHocBackground, system, prompt)
            .await
    }

    pub async fn text_completion_with_system_for(
        &self,
        site: UtilityCallSite,
        system: &str,
        prompt: &str,
    ) -> Result<String> {
        self.text_completion_with_system_with_params(site, ModelParams::default(), system, prompt)
            .await
    }

    pub async fn text_completion_with_system_with_params(
        &self,
        site: UtilityCallSite,
        params: ModelParams,
        system: &str,
        prompt: &str,
    ) -> Result<String> {
        let guard = self.outbound_guard();
        // Inference-dispatch chokepoint: refuse a *new* provider request once
        // the daemon has begun draining. Background utility calls are abandoned
        // immediately; turn-blocking utility calls remain owned by the parent
        // turn's park/drain-grace semantics.
        if site.budget_class() == UtilityBudgetClass::Background && self.gate().is_draining() {
            return Err(anyhow::Error::new(InferenceGated));
        }
        // Non-bypassable redaction chokepoint (GOALS §7): scrub both the
        // system contract and the user payload before any provider work.
        let system = guard.scrub(system);
        let system = system.as_str();
        let prompt = guard.scrub(prompt);
        let prompt = prompt.as_str();
        let params = self.utility_params_for(site, params);
        self.with_utility_timeout(site, async {
            match self {
                Model::OpenAi {
                    client, model_id, ..
                } => {
                    let wire_api = self.resolve_live_wire_api_for_base_url(client.base_url());
                    openai_text_completion(
                        client,
                        model_id,
                        wire_api,
                        &params,
                        Some(system),
                        prompt,
                        "text_completion_with_system: prompt failed",
                    )
                    .await
                }
                Model::ChatGpt { model, .. } => {
                    let response = configured_completion_request(
                        build_chatgpt_completion_model(model.clone()),
                        system,
                        &[],
                        Message::user(prompt),
                        &[],
                        &params,
                        chatgpt_additional_params(&params),
                    )
                    .send()
                    .await
                    .context("text_completion_with_system: send failed")?;
                    Ok(choice_text(&response.choice).trim().to_string())
                }
                Model::Anthropic { model, .. } => {
                    let response = configured_completion_request(
                        build_anthropic_completion_model(model.clone()),
                        system,
                        &[],
                        Message::user(prompt),
                        &[],
                        &params,
                        anthropic_additional_params(&params),
                    )
                    .send()
                    .await
                    .context("text_completion_with_system: send failed")?;
                    Ok(choice_text(&response.choice).trim().to_string())
                }
            }
        })
        .await
    }

    /// One-shot, non-streaming, single-tool completion that **forces** the
    /// model to answer through `tool` (`tool_choice = required`). Used by
    /// background tasks that need a *structured* verdict rather than free
    /// text — the prompt-injection guard's `risk` tool (GOALS §4i). Sends
    /// only `system` + `prompt` (no conversation history), and returns
    /// every [`ToolCall`] the model emitted so the caller can read the
    /// structured arguments. History-free by construction: the untrusted
    /// text the caller wraps into `prompt` is the only content the model
    /// sees.
    #[allow(dead_code)]
    pub async fn tool_completion(
        &self,
        system: &str,
        prompt: &str,
        tool: &ToolDefinition,
    ) -> Result<Vec<crate::engine::message::ToolCall>> {
        self.tool_completion_for(UtilityCallSite::AdHocBackground, system, prompt, tool)
            .await
    }

    pub async fn tool_completion_for(
        &self,
        site: UtilityCallSite,
        system: &str,
        prompt: &str,
        tool: &ToolDefinition,
    ) -> Result<Vec<crate::engine::message::ToolCall>> {
        self.tool_completion_with_params(site, ModelParams::default(), system, prompt, tool)
            .await
    }

    pub async fn tool_completion_with_params(
        &self,
        site: UtilityCallSite,
        params: ModelParams,
        system: &str,
        prompt: &str,
        tool: &ToolDefinition,
    ) -> Result<Vec<crate::engine::message::ToolCall>> {
        let guard = self.outbound_guard();
        // Inference-dispatch chokepoint: refuse a *new* provider request once
        // the daemon has begun draining. Background utility calls are abandoned
        // immediately; turn-blocking utility calls remain owned by the parent
        // turn's park/drain-grace semantics.
        if site.budget_class() == UtilityBudgetClass::Background && self.gate().is_draining() {
            return Err(anyhow::Error::new(InferenceGated));
        }
        // Non-bypassable redaction chokepoint (GOALS §7): scrub the system
        // contract and the (untrusted) prompt before dispatch. Scrubbing
        // secret *values* leaves injection *instructions* intact, so the
        // injection classifier still works on the scrubbed text.
        let system = guard.scrub(system);
        let system = system.as_str();
        let prompt = guard.scrub(prompt);
        let prompt = prompt.as_str();
        let params = self.utility_params_for(site, params);
        self.with_utility_timeout(site, async {
            match self {
                Model::OpenAi {
                    client, model_id, ..
                } => {
                    let wire_api = self.resolve_live_wire_api_for_base_url(client.base_url());
                    openai_tool_completion(
                        client, model_id, wire_api, &params, system, prompt, tool,
                    )
                    .await
                }
                Model::ChatGpt { model, .. } => {
                    let response = configured_completion_request(
                        build_chatgpt_completion_model(model.clone()),
                        system,
                        &[],
                        Message::user(prompt),
                        std::slice::from_ref(tool),
                        &params,
                        chatgpt_additional_params(&params),
                    )
                    .tool_choice(ToolChoice::Required)
                    .send()
                    .await
                    .context("tool_completion: send failed")?;
                    Ok(crate::engine::message::collect_tool_calls(&response.choice))
                }
                Model::Anthropic { model, .. } => {
                    let response = configured_completion_request(
                        build_anthropic_completion_model(model.clone()),
                        system,
                        &[],
                        Message::user(prompt),
                        std::slice::from_ref(tool),
                        &params,
                        anthropic_additional_params(&params),
                    )
                    .tool_choice(ToolChoice::Required)
                    .send()
                    .await
                    .context("tool_completion: send failed")?;
                    Ok(crate::engine::message::collect_tool_calls(&response.choice))
                }
            }
        })
        .await
    }

    async fn with_utility_timeout<T>(
        &self,
        site: UtilityCallSite,
        future: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let started = Instant::now();
        match tokio::time::timeout(site.timeout(), future).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::Error::new(InferenceFailure {
                provider: self.provider_label().to_string(),
                model: self.model_id().to_string(),
                phase: "utility_dispatch".to_string(),
                class: InferenceErrorClass::UtilityTimeout,
                elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                retry_attempts: 1,
                detail: format!(
                    "{site:?} utility request exceeded {}ms {:?} budget",
                    site.timeout().as_millis(),
                    site.budget_class()
                ),
                observed_status: None,
                recovery: crate::engine::model::ProviderRecoverySignal::None,
            })),
        }
    }

    /// Build a streaming completion request and aggregate it.
    ///
    /// Streaming is on for every provider variant — rig's
    /// `StreamingCompletionResponse` aggregates `choice` and
    /// `message_id` internally as the stream advances, so by the time
    /// we exhaust the stream we have the same shape the non-streaming
    /// `send()` path would have produced. We emit a
    /// [`TurnEvent::AssistantTextDelta`] for every `Message(...)`
    /// chunk (and drop `Reasoning`/`ReasoningDelta` — the TUI shows
    /// `Thinking…` instead per user spec).
    ///
    /// **Also returns the full assembled request body** that was handed
    /// to the provider — exactly what hit the wire, after the driver's
    /// upstream redaction (session-log-export Part A). The caller persists
    /// it via
    /// [`crate::session::Session::record_inference_request`] keyed by the
    /// same `call_id` it uses for the `inference_calls` metadata row.
    ///
    /// The body is assembled here, at the engine→provider boundary,
    /// because this is the only place that knows the post-strip-reasoning
    /// history + resolved model id. We do not (cannot) read rig's exact
    /// serialized HTTP body — rig builds and sends it internally without
    /// exposing the bytes — so the faithful capture is the same
    /// `(model, provider, params, system, tools, history, prompt)` tuple
    /// rig receives (verified via kcl `rig-core`).
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_captured(
        &self,
        system: &str,
        history: &[Message],
        prompt: Message,
        tools: &[ToolDefinition],
        params: ModelParams,
        agent_name: &str,
        event_tx: Option<&mpsc::Sender<TurnEvent>>,
        cancel: &CancellationToken,
        endpoint_recovery: Option<EndpointRecoveryContext>,
    ) -> Result<(
        (Option<String>, Vec<AssistantContent>, Option<TokenUsage>),
        serde_json::Value,
        InferenceTiming,
    )> {
        self.complete_captured_with_pre_drain(
            system,
            history,
            prompt,
            tools,
            params,
            agent_name,
            event_tx,
            cancel,
            endpoint_recovery,
            None,
        )
        .await
    }

    /// Compact-utility dispatch: one transport attempt, no probe/backoff or
    /// endpoint swap, and TTFT/idle deadlines are terminal even without a
    /// configured backup. The compaction sampler exclusively owns retries.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn complete_captured_compact_utility(
        &self,
        system: &str,
        history: &[Message],
        prompt: Message,
        tools: &[ToolDefinition],
        params: ModelParams,
        agent_name: &str,
        cancel: &CancellationToken,
    ) -> Result<(
        (Option<String>, Vec<AssistantContent>, Option<TokenUsage>),
        serde_json::Value,
        InferenceTiming,
    )> {
        self.complete_captured_with_pre_drain_mode(
            system, history, prompt, tools, params, agent_name, None, cancel, None, None, true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn complete_captured_with_pre_drain(
        &self,
        system: &str,
        history: &[Message],
        prompt: Message,
        tools: &[ToolDefinition],
        params: ModelParams,
        agent_name: &str,
        event_tx: Option<&mpsc::Sender<TurnEvent>>,
        cancel: &CancellationToken,
        endpoint_recovery: Option<EndpointRecoveryContext>,
        pre_drain: Option<PreDrainFuture>,
    ) -> Result<(
        (Option<String>, Vec<AssistantContent>, Option<TokenUsage>),
        serde_json::Value,
        InferenceTiming,
    )> {
        self.complete_captured_with_pre_drain_mode(
            system,
            history,
            prompt,
            tools,
            params,
            agent_name,
            event_tx,
            cancel,
            endpoint_recovery,
            pre_drain,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn complete_captured_with_pre_drain_mode(
        &self,
        system: &str,
        history: &[Message],
        prompt: Message,
        tools: &[ToolDefinition],
        params: ModelParams,
        agent_name: &str,
        event_tx: Option<&mpsc::Sender<TurnEvent>>,
        cancel: &CancellationToken,
        endpoint_recovery: Option<EndpointRecoveryContext>,
        pre_drain: Option<PreDrainFuture>,
        compact_utility: bool,
    ) -> Result<(
        (Option<String>, Vec<AssistantContent>, Option<TokenUsage>),
        serde_json::Value,
        InferenceTiming,
    )> {
        let params = self.with_resolved_model_params(params);
        let prepared = self.prepare_completion_request(
            system,
            history,
            &prompt,
            tools,
            &params,
            endpoint_recovery.is_some(),
            // This `complete`/`complete_captured` path is not the interactive
            // sealed-marker chokepoint; it renders the model's own effective
            // table (generic). Sealed-marker derivation is done in the turn.
            None,
        )?;
        self.complete_prepared_with_pre_drain(
            prepared,
            tools,
            params,
            agent_name,
            event_tx,
            cancel,
            endpoint_recovery,
            pre_drain,
            compact_utility,
            None,
        )
        .await
    }

    /// `max_tokens` is deliberately not inferred for normal OpenAI-compatible
    /// turns (including Ollama): their capability metadata can be stale or
    /// describe context rather than completion capacity. Callers send an
    /// explicit value only when policy requires it (for example utilities,
    /// whose cap is tested below); omission lets each endpoint apply its own
    /// model-specific default.
    fn with_resolved_model_params(&self, mut params: ModelParams) -> ModelParams {
        if params.max_tokens.is_none()
            && let Model::Anthropic { max_tokens, .. } = self
        {
            params.max_tokens = Some(*max_tokens);
        }
        params
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn complete_prepared_with_pre_drain(
        &self,
        prepared: PreparedCompletionRequest,
        tools: &[ToolDefinition],
        params: ModelParams,
        agent_name: &str,
        event_tx: Option<&mpsc::Sender<TurnEvent>>,
        cancel: &CancellationToken,
        endpoint_recovery: Option<EndpointRecoveryContext>,
        pre_drain: Option<PreDrainFuture>,
        compact_utility: bool,
        display: Option<crate::engine::model::DisplayAttemptSlot>,
    ) -> Result<(
        (Option<String>, Vec<AssistantContent>, Option<TokenUsage>),
        serde_json::Value,
        InferenceTiming,
    )> {
        let params = self.with_resolved_model_params(params);
        let PreparedCompletionRequest {
            system,
            history,
            prompt,
            mut captured,
            single_handoff,
        } = prepared;
        let system = system.as_str();

        if let Some(path) = debug_last_message_path() {
            write_dump(path, &captured);
        }

        let dispatched_at = std::time::Instant::now();

        // Bail before doing any provider work if cancellation already
        // fired (e.g. the user pressed ctrl+c between turns). Cheap and
        // keeps the cancel path from racing a fresh round-trip.
        if cancel.is_cancelled() {
            return Err(anyhow::Error::new(InferenceCancelled {
                phase: InferencePhase::Prep,
            }));
        }

        // Inference-dispatch chokepoint (`daemon-graceful-drain-shutdown.md`):
        // once the daemon begins draining, no *new* provider request goes
        // out. A request already past this gate keeps streaming; this refuses
        // only the ones that would start after the drain began. Checked here,
        // before any client work, so the gate is the single real seam — not
        // an advisory flag each call site must remember.
        if self.gate().is_draining() {
            return Err(anyhow::Error::new(InferenceGated));
        }

        self.ensure_client_side_tools_allowed(tools)?;

        // Build a connectivity probe from the provider base URL so a
        // backoff wait short-circuits the moment the link returns. `None`
        // (unparseable URL) falls back to plain backoff — never fatal. The
        // same base URL names the unreachable target on every reconnect
        // status / headless log line.
        let base_url = match self {
            Model::OpenAi { client, .. } => client.base_url().to_string(),
            Model::ChatGpt { base_url, .. } => base_url.clone(),
            Model::Anthropic { base_url, .. } => base_url.clone(),
        };
        let probe = retry::TcpProbe::from_base_url(&base_url);
        // Names the unreachable provider/model/url on every
        // `TurnEvent::Reconnecting` so a network-class retry loop is
        // visibly distinct from the generic working spinner (TUI) and never
        // silently hung (headless `run`).
        let reconnect_target = retry::ReconnectTarget {
            provider: self.provider_label().to_string(),
            model: self.model_id().to_string(),
            url: base_url,
        };

        let timeout = self.timeout().clone();
        let hard_timeout_on_stall = compact_utility || self.hard_timeout_on_stall();
        // Furthest lifecycle phase reached across (possibly several) retry
        // attempts; seeded at `Prep` (we got past assembly). A typed failure
        // reports the furthest phase, so e.g. a network blip that reached
        // `first_token` once then failed at `dispatched` on retry still
        // records `first_token`.
        let phase = std::sync::atomic::AtomicU8::new(InferencePhase::Prep.rank());
        let retry_attempts = std::sync::atomic::AtomicU32::new(0);
        // Strongest provider-recovery signal (billing > overload > none) observed
        // across the WHOLE retry chain, accumulated by the retry loop so the
        // terminal `InferenceFailure.recovery` reflects an earlier billing/overload
        // signal even if a later attempt failed generically (issue #23).
        let recovery_signal = std::sync::atomic::AtomicU8::new(0);
        // Time-to-first-token (ms from dispatch), recorded by the drain on
        // the attempt that ultimately succeeds; `0` means no token arrived.
        let first_token_ms = std::sync::atomic::AtomicU64::new(0);
        let output_sent = std::sync::atomic::AtomicBool::new(false);
        // Dispatch clock: started during pre-dispatch assembly, so
        // `elapsed_ms` on a failure covers request repair plus provider
        // dispatch — the figure the export + inline error report.

        // Each attempt builds + drains a *fresh* stream: a failed
        // attempt's partial is discarded, never resumed (prompt edge
        // case). `with_retry` re-invokes this closure on a network/
        // transient failure with jittered, capped backoff; a non-
        // transient error fails fast. Persistence in `agent::turn` runs
        // once, after this whole retry unit settles — so a retried call
        // logs exactly one inference outcome.
        //
        // Cancellation: the select arms below short-circuit a ctrl+c
        // *during an attempt* via [`AttemptCancelled`] (classified
        // fail-fast, so `with_retry` returns at once); cancellation
        // *during a backoff wait* is interrupted immediately by
        // `with_retry`'s own select against `cancel`. Either way we map
        // the final state to the `InferenceCancelled` sentinel below.
        //
        // Stream wait thresholds (TTFT + idle) are applied inside
        // `drain_completion_stream`. Without a resolved backup they warn and
        // keep waiting; with a resolved backup they hard-abort the attempt so
        // the outer backup fallback can retry on the backup model.
        //
        // **Wire-API endpoint fallback** (the *inner* retry, layer 3 of
        // implementation note): for the OpenAI-compat
        // arm the whole `with_retry` unit runs once per endpoint. If it fails
        // with the narrow `unsupported_api_for_model` signal **and** no token
        // has reached the user yet, we retry once on the opposite endpoint and,
        // on success, persist the corrected `wire_api`. This swap is strictly
        // *before* the v0.1.128 backup-model fallback (which runs in
        // `agent::turn_with_backup` only on the typed `InferenceFailure` this
        // method finally returns): a wrong endpoint never switches models.
        let mut successful_wire = match self {
            Model::ChatGpt { .. } => Some(crate::config::providers::WireApi::Responses),
            Model::Anthropic { .. } => Some(crate::config::providers::WireApi::Completions),
            Model::OpenAi { .. } => None,
        };
        let out = match self {
            Model::OpenAi {
                client,
                model_id,
                provider_id,
                config_path,
                ..
            } => {
                let base_url = client.base_url().to_string();
                // The endpoint to try first (resolved concrete value), then —
                // on a qualifying miss — its opposite, exactly once.
                let mut endpoint = self.resolve_live_wire_api_for_base_url(&base_url);
                let mut tried_swap = false;
                let mut approved_swap = false;
                loop {
                    let attempt = || async {
                        retry_attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        // Each transport retry is a distinct display attempt.
                        // Keep the overall call clock above for audit timing, but
                        // start TTFT and the display classifier at this handoff.
                        let attempt_dispatched_at = std::time::Instant::now();
                        let wire_tools = wire_schema::definitions_for_wire(endpoint, tools);
                        let wire_tools = wire_tools.as_ref();
                        // Build the OpenAI-compat completion request against
                        // the *current* endpoint: the kept `CompletionsClient`
                        // directly, or a cheap O(1) `.responses_api()` swap of
                        // a clone (only the provider extension changes; base
                        // URL/headers/HTTP are reused). Re-built every attempt
                        // so a transient retry rebuilds a fresh stream.
                        match endpoint {
                            crate::config::providers::WireApi::Responses => {
                                let responses = client.clone().responses_api();
                                let completion =
                                    build_openai_responses_completion_model(responses, model_id);
                                let request = configured_completion_request(
                                    completion,
                                    system,
                                    &history,
                                    prompt.clone(),
                                    wire_tools,
                                    &params,
                                    openai_additional_params(&params),
                                );
                                drain_completion_stream(
                                    request,
                                    agent_name,
                                    provider_id,
                                    model_id,
                                    event_tx,
                                    cancel,
                                    &timeout,
                                    hard_timeout_on_stall,
                                    &phase,
                                    attempt_dispatched_at,
                                    &first_token_ms,
                                    &output_sent,
                                    pre_drain.clone(),
                                    display.as_ref(),
                                )
                                .await
                            }
                            // `Completions` (and the defensive `Auto`, never the
                            // resolved value) use the kept completions client.
                            _ => {
                                let completion = build_completion_model(client, model_id);
                                let request = configured_completion_request(
                                    completion,
                                    system,
                                    &history,
                                    prompt.clone(),
                                    wire_tools,
                                    &params,
                                    openai_additional_params(&params),
                                );
                                drain_completion_stream(
                                    request,
                                    agent_name,
                                    provider_id,
                                    model_id,
                                    event_tx,
                                    cancel,
                                    &timeout,
                                    hard_timeout_on_stall,
                                    &phase,
                                    attempt_dispatched_at,
                                    &first_token_ms,
                                    &output_sent,
                                    pre_drain.clone(),
                                    display.as_ref(),
                                )
                                .await
                            }
                        }
                    };
                    let result = if single_handoff || compact_utility {
                        retry::with_retry_max(
                            agent_name,
                            &reconnect_target,
                            event_tx,
                            cancel,
                            probe.as_ref(),
                            1,
                            Some(&recovery_signal),
                            attempt,
                        )
                        .await
                    } else if tried_swap {
                        retry::with_retry_max(
                            agent_name,
                            &reconnect_target,
                            event_tx,
                            cancel,
                            probe.as_ref(),
                            5,
                            Some(&recovery_signal),
                            attempt,
                        )
                        .await
                    } else {
                        retry::with_retry(
                            agent_name,
                            &reconnect_target,
                            event_tx,
                            cancel,
                            probe.as_ref(),
                            Some(&recovery_signal),
                            attempt,
                        )
                        .await
                    };
                    match result {
                        Ok(value) => {
                            successful_wire = Some(endpoint);
                            // A swap that produced a working turn pins the
                            // corrected endpoint so later turns route directly
                            // with no retry (layer-3 persist). Only after an
                            // actual swap, and only when we know where to write.
                            if approved_swap {
                                self.confirm_wire_api_for_base_url(&base_url, endpoint);
                                record_endpoint_observation(
                                    provider_id,
                                    model_id,
                                    &base_url,
                                    endpoint,
                                    EndpointObservation::Works,
                                );
                                if let Some(path) = config_path {
                                    persist_wire_api(path, provider_id, model_id, endpoint);
                                }
                            }
                            break Ok(value);
                        }
                        Err(err) => {
                            // The endpoint-swap fallback fires only when:
                            //   (a) the error is the narrow
                            //       `unsupported_api_for_model` signal (NOT any
                            //       400 — bad request / context length / auth
                            //       must surface as-is),
                            //   (b) we have not already swapped once, and
                            //   (c) **no user-visible output has been emitted** —
                            //       the 400 arrives as the first stream item, so
                            //       the furthest phase is still `Dispatched`
                            //       (no chunk consumed). If any chunk reached the
                            //       UI we must NOT retry (prompt invariant).
                            let no_output = !output_sent.load(std::sync::atomic::Ordering::SeqCst);
                            if is_endpoint_mismatch_error(&err) {
                                record_endpoint_observation(
                                    provider_id,
                                    model_id,
                                    &base_url,
                                    endpoint,
                                    EndpointObservation::Incompatible,
                                );
                            }
                            let alternate = endpoint.opposite();
                            let alternate_not_incompatible =
                                endpoint_observation(provider_id, model_id, &base_url, alternate)
                                    != EndpointObservation::Incompatible;
                            if !single_handoff
                                && !compact_utility
                                && !tried_swap
                                && no_output
                                && is_endpoint_mismatch_error(&err)
                                && !self.is_live_wire_api_explicit()
                                && !cancel.is_cancelled()
                                && !is_attempt_cancelled(&err)
                                && let Some(confirmed) =
                                    self.confirmed_wire_api_for_base_url(&base_url)
                                && confirmed != endpoint
                                && endpoint_observation(provider_id, model_id, &base_url, confirmed)
                                    != EndpointObservation::Incompatible
                            {
                                tried_swap = true;
                                endpoint = confirmed;
                                continue;
                            }
                            let approved = if !single_handoff
                                && !compact_utility
                                && !tried_swap
                                && no_output
                                && is_endpoint_mismatch_error(&err)
                                && !self.is_live_wire_api_explicit()
                                && alternate_not_incompatible
                                && !cancel.is_cancelled()
                                && !is_attempt_cancelled(&err)
                            {
                                match &endpoint_recovery {
                                    Some(ctx) => {
                                        (ctx.approve)(EndpointRecoveryPrompt {
                                            provider: provider_id.clone(),
                                            model: model_id.clone(),
                                            attempted: endpoint,
                                            alternate,
                                        })
                                        .await
                                    }
                                    None => false,
                                }
                            } else {
                                false
                            };
                            if approved {
                                tried_swap = true;
                                approved_swap = true;
                                endpoint = alternate;
                                continue;
                            }
                            if retry::classify(&err) != retry::RetryDecision::FailFast {
                                record_endpoint_observation(
                                    provider_id,
                                    model_id,
                                    &base_url,
                                    endpoint,
                                    EndpointObservation::TransientFailed,
                                );
                            }
                            break Err(err);
                        }
                    }
                }
            }
            Model::ChatGpt {
                model,
                provider_id,
                model_id,
                ..
            } => {
                // Native ChatGPT/Codex Responses API: no OpenAI-compatible
                // endpoint selector. Rig normalizes system/developer content
                // into top-level `instructions`, posts `/responses`, streams,
                // and aggregates Responses API tool/reasoning/usage chunks.
                let attempt = || async {
                    retry_attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let attempt_dispatched_at = std::time::Instant::now();
                    let wire_tools = wire_schema::definitions_for_wire(
                        crate::config::providers::WireApi::Responses,
                        tools,
                    );
                    let wire_tools = wire_tools.as_ref();
                    let completion = build_chatgpt_completion_model(model.clone());
                    let request = configured_completion_request(
                        completion,
                        system,
                        &history,
                        prompt.clone(),
                        wire_tools,
                        &params,
                        chatgpt_additional_params(&params),
                    );
                    drain_completion_stream(
                        request,
                        agent_name,
                        provider_id,
                        model_id,
                        event_tx,
                        cancel,
                        &timeout,
                        hard_timeout_on_stall,
                        &phase,
                        attempt_dispatched_at,
                        &first_token_ms,
                        &output_sent,
                        pre_drain.clone(),
                        display.as_ref(),
                    )
                    .await
                };
                if single_handoff || compact_utility {
                    retry::with_retry_max(
                        agent_name,
                        &reconnect_target,
                        event_tx,
                        cancel,
                        probe.as_ref(),
                        1,
                        Some(&recovery_signal),
                        attempt,
                    )
                    .await
                } else {
                    retry::with_retry(
                        agent_name,
                        &reconnect_target,
                        event_tx,
                        cancel,
                        probe.as_ref(),
                        Some(&recovery_signal),
                        attempt,
                    )
                    .await
                }
            }
            Model::Anthropic {
                model,
                provider_id,
                model_id,
                ..
            } => {
                // Native Anthropic: no wire-API selector, single retry unit.
                let attempt = || async {
                    retry_attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let attempt_dispatched_at = std::time::Instant::now();
                    let completion = build_anthropic_completion_model(model.clone());
                    let request = configured_completion_request(
                        completion,
                        system,
                        &history,
                        prompt.clone(),
                        tools,
                        &params,
                        anthropic_additional_params(&params),
                    );
                    drain_completion_stream(
                        request,
                        agent_name,
                        provider_id,
                        model_id,
                        event_tx,
                        cancel,
                        &timeout,
                        hard_timeout_on_stall,
                        &phase,
                        attempt_dispatched_at,
                        &first_token_ms,
                        &output_sent,
                        pre_drain.clone(),
                        display.as_ref(),
                    )
                    .await
                };
                if single_handoff || compact_utility {
                    retry::with_retry_max(
                        agent_name,
                        &reconnect_target,
                        event_tx,
                        cancel,
                        probe.as_ref(),
                        1,
                        Some(&recovery_signal),
                        attempt,
                    )
                    .await
                } else {
                    retry::with_retry(
                        agent_name,
                        &reconnect_target,
                        event_tx,
                        cancel,
                        probe.as_ref(),
                        Some(&recovery_signal),
                        attempt,
                    )
                    .await
                }
            }
        };

        match out {
            Ok(value) => {
                if let Some(wire) = successful_wire {
                    let wire_tools = wire_schema::definitions_for_wire(wire, tools);
                    captured["tools"] =
                        serde_json::to_value(wire_tools.as_ref()).unwrap_or_else(|error| {
                            tracing::warn!(%error, "serialize final wire tool definitions failed");
                            serde_json::Value::Array(Vec::new())
                        });
                    if let Some(path) = debug_last_message_path() {
                        write_dump(path, &captured);
                    }
                }
                let ft = first_token_ms.load(std::sync::atomic::Ordering::SeqCst);
                let timing = InferenceTiming {
                    first_token_ms: (ft > 0).then_some(ft),
                    completed_ms: dispatched_at.elapsed().as_millis() as u64,
                    open_display: display.and_then(|slot| slot.take_open_classifier()),
                };
                Ok((value, captured, timing))
            }
            Err(err) => {
                // A ctrl+c (either during an attempt via the
                // `AttemptCancelled` sentinel, or because the token fired
                // during a backoff wait) unwinds the turn cleanly rather
                // than logging a real failure — keep the dedicated
                // sentinels the driver already special-cases.
                if cancel.is_cancelled() || is_attempt_cancelled(&err) {
                    if let Some(slot) = display.as_ref() {
                        slot.finish_as_error(
                            agent_name,
                            crate::engine::response_performance::DisplayErrorKind::Cancelled,
                            "cancelled",
                            event_tx,
                        )
                        .await;
                    }
                    return Err(anyhow::Error::new(InferenceCancelled {
                        phase: InferencePhase::from_rank(
                            phase.load(std::sync::atomic::Ordering::SeqCst),
                        ),
                    }));
                }
                // Every other terminal failure (timeout / network /
                // non-retryable HTTP) is mapped into the well-typed
                // `InferenceFailure` seam a future fallback intercepts.
                let elapsed_ms = dispatched_at.elapsed().as_millis() as u64;
                let phase =
                    InferencePhase::from_rank(phase.load(std::sync::atomic::Ordering::SeqCst));
                // Classify ONCE at the model boundary into (class, observed
                // status, recovery signal). Billing overrides the class to
                // `BillingOrQuotaExhausted` with its observed status (often 429)
                // retained separately; overload keeps its natural class and is
                // distinguished by the recovery signal for the retry/failover
                // policy. The floor carries the strongest signal seen across the
                // whole retry chain so a later generic error cannot mask it.
                let recovery_floor = crate::engine::model::ProviderRecoverySignal::from_rank(
                    recovery_signal.load(std::sync::atomic::Ordering::SeqCst),
                );
                let mut failure = terminal_inference_failure(
                    &err,
                    self.provider_id(),
                    self.model_id(),
                    phase,
                    elapsed_ms,
                    retry_attempts
                        .load(std::sync::atomic::Ordering::SeqCst)
                        .max(1),
                    recovery_floor,
                );
                if !tools.is_empty()
                    && self.xai_multi_agent_tools_entitlement_enabled()
                    && provider_rejected_xai_multi_agent_tools(&failure.detail)
                {
                    failure.detail.push_str(" Disable the xAI beta tools entitlement in provider/model settings or choose a non-multi-agent model if the account lacks beta access.");
                }
                // Keep a visible partial classifier open. The backup wrapper
                // either starts a replacement (which emits Reset) or, after
                // failover is exhausted, emits the single terminal display
                // error. Closing it here would make that decision impossible.
                Err(anyhow::Error::new(failure))
            }
        }
    }
    pub(super) fn model_id(&self) -> &str {
        match self {
            Model::OpenAi { model_id, .. } => model_id,
            Model::ChatGpt { model_id, .. } => model_id,
            Model::Anthropic { model_id, .. } => model_id,
        }
    }

    /// Provider-flavor label for the captured request body. Coarse —
    /// the exact configured provider id lives on the session row; this
    /// is the wire-flavor the model client speaks.
    pub(super) fn provider_label(&self) -> &str {
        match self {
            Model::OpenAi { provider_id, .. }
                if provider_id == "grok" || provider_id == "grok-oauth" =>
            {
                provider_id
            }
            Model::OpenAi { .. } => "openai-compatible",
            Model::ChatGpt { .. } => "codex-oauth",
            Model::Anthropic { .. } => "anthropic",
        }
    }

    fn ensure_client_side_tools_allowed(&self, tools: &[ToolDefinition]) -> Result<()> {
        if tools.is_empty() {
            return Ok(());
        }
        let capability = match self {
            Model::OpenAi {
                client_side_tools, ..
            } => client_side_tools,
            Model::ChatGpt { .. } | Model::Anthropic { .. } => return Ok(()),
        };
        match capability.status {
            CapabilityStatus::RequiresEntitlement => {
                let entitlement = capability
                    .entitlement
                    .as_deref()
                    .unwrap_or("required provider entitlement");
                Err(anyhow::Error::new(InferenceFailure {
                    provider: self.provider_id().to_string(),
                    model: self.model_id().to_string(),
                    phase: "prep".to_string(),
                    class: InferenceErrorClass::MissingToolEntitlement {
                        feature: entitlement.to_string(),
                    },
                    elapsed_ms: 0,
                    retry_attempts: 1,
                    detail: format!(
                        "client-side tools require entitlement `{entitlement}`; primary model was blocked before network dispatch. Enable the entitlement in provider/model settings or choose a non-multi-agent model."
                    ),
                    observed_status: None,
                    recovery: crate::engine::model::ProviderRecoverySignal::None,
                }))
            }
            CapabilityStatus::Unsupported => Err(anyhow::Error::new(InferenceFailure {
                provider: self.provider_id().to_string(),
                model: self.model_id().to_string(),
                phase: "prep".to_string(),
                class: InferenceErrorClass::ClientSideToolsUnsupported,
                elapsed_ms: 0,
                retry_attempts: 1,
                detail: "client-side tools are unsupported for this model; primary model was blocked before network dispatch. Choose a tool-compatible model or configure a compatible backup model."
                    .to_string(),
                observed_status: None,
                recovery: crate::engine::model::ProviderRecoverySignal::None,
            })),
            CapabilityStatus::Supported | CapabilityStatus::Unknown => Ok(()),
        }
    }

    fn xai_multi_agent_tools_entitlement_enabled(&self) -> bool {
        match self {
            Model::OpenAi {
                client_side_tools, ..
            } => {
                client_side_tools.status == CapabilityStatus::Supported
                    && client_side_tools.entitlement.as_deref()
                        == Some(crate::config::providers::XAI_MULTI_AGENT_TOOLS_ENTITLEMENT)
            }
            Model::ChatGpt { .. } | Model::Anthropic { .. } => false,
        }
    }

    fn preserve_reasoning_for_replay(&self) -> bool {
        matches!(self, Model::Anthropic { .. })
    }

    fn definitions_for_initial_wire<'a>(
        &self,
        tools: &'a [ToolDefinition],
    ) -> std::borrow::Cow<'a, [ToolDefinition]> {
        let wire = match self {
            Model::OpenAi { client, .. } => {
                self.resolve_live_wire_api_for_base_url(client.base_url())
            }
            Model::ChatGpt { .. } => crate::config::providers::WireApi::Responses,
            Model::Anthropic { .. } => crate::config::providers::WireApi::Completions,
        };
        wire_schema::definitions_for_wire(wire, tools)
    }

    /// Map a fail-closed [`UnrenderableWireField`] into the typed pre-network
    /// [`InferenceFailure`] (phase `prep`,
    /// [`InferenceErrorClass::UnrenderableWireField`]) the prep entry points
    /// return. The provider is never contacted.
    fn unrenderable_wire_failure(
        &self,
        field: UnrenderableWireField,
        started: std::time::Instant,
    ) -> anyhow::Error {
        anyhow::Error::new(InferenceFailure {
            provider: self.provider_id().to_string(),
            model: self.model_id().to_string(),
            phase: InferencePhase::Prep.as_str().to_string(),
            class: InferenceErrorClass::UnrenderableWireField,
            elapsed_ms: started.elapsed().as_millis() as u64,
            retry_attempts: 1,
            detail: field.detail(),
            observed_status: None,
            recovery: crate::engine::model::ProviderRecoverySignal::None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_completion_request(
        &self,
        system: &str,
        history: &[Message],
        prompt: &Message,
        tools: &[ToolDefinition],
        params: &ModelParams,
        endpoint_recovery_enabled: bool,
        // Optional per-attempt egress table override. The interactive turn
        // derives this by applying `with_sealed_replacements` to the model's own
        // effective table when (and only when) an untrusted, interactive request
        // with a callable `use_sealed_value` holds a live exact sealed grant, so
        // a sealed literal renders the actionable marker instead of the generic
        // placeholder. `None` uses the model's own effective table (the default
        // for every other route). The `Model` never gets a DB handle: the table
        // is derived in the turn and passed here. This override is a *rendering*
        // choice over the same enforced entries — it cannot release raw custody.
        sealed_egress: Option<&RedactionTable>,
    ) -> Result<PreparedCompletionRequest> {
        let prep_started = std::time::Instant::now();
        let params = self.with_resolved_model_params(params.clone());
        let history = self.prepare_history_for_request(history);

        // Non-bypassable redaction chokepoint (GOALS §7,
        // `redaction-cover-all-llm-requests.md`): scrub every dynamic text
        // field of the request — the system contract, every history message
        // (including tool results), and the prompt — before assembling the
        // captured body and before any provider work. Static tool *schemas*
        // carry no user secrets and are left untouched.
        // The effective egress table: the sealed-marker override when the turn
        // derived one, else the model's own effective table. Both carry the same
        // enforced entries; the override differs only in rendering a sealed
        // entry as its actionable marker instead of the generic placeholder, so
        // it can never widen custody.
        let redact = sealed_egress.unwrap_or_else(|| self.redact());
        let system = redact.scrub(system);
        let mut history = history;
        let mut prompt = prompt.clone();
        // Trusted raw custody sends raw bytes and skips the wire walk entirely.
        // Every untrusted route runs the fail-closed walk even when the table
        // has no entries (the string scrub is a byte-stable no-op; the walk
        // still fails closed on any non-renderable media channel), so
        // `redact.is_empty()` can never skip the untrusted policy.
        if !self.is_trusted() {
            history = history
                .iter()
                .map(|m| scrub_message(redact, m))
                .collect::<std::result::Result<Vec<Message>, _>>()
                .map_err(|field| self.unrenderable_wire_failure(field, prep_started))?;
            prompt = scrub_message(redact, &prompt)
                .map_err(|field| self.unrenderable_wire_failure(field, prep_started))?;
        }
        let identity_records =
            if self.needs_responses_tool_identity_normalization(endpoint_recovery_enabled) {
                match normalize_responses_tool_call_identity(&mut history, &mut prompt) {
                    Ok(records) => records,
                    Err(err) => {
                        return Err(anyhow::Error::new(InferenceFailure {
                            provider: self.provider_id().to_string(),
                            model: self.model_id().to_string(),
                            phase: InferencePhase::Prep.as_str().to_string(),
                            class: InferenceErrorClass::ResponsesToolIdentity,
                            elapsed_ms: prep_started.elapsed().as_millis() as u64,
                            retry_attempts: 1,
                            detail: err.to_string(),
                            observed_status: None,
                            recovery: crate::engine::model::ProviderRecoverySignal::None,
                        }));
                    }
                }
            } else {
                Vec::new()
            };

        let wire_tools = self.definitions_for_initial_wire(tools);
        let mut captured = assembled_request(
            self.model_id(),
            self.provider_label(),
            &system,
            &history,
            &prompt,
            wire_tools.as_ref(),
            &params,
        );
        if !identity_records.is_empty() {
            captured["responses_tool_identity"] = serde_json::to_value(&identity_records)
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "serialize responses tool identity records failed");
                    serde_json::Value::Array(Vec::new())
                });
        }

        Ok(PreparedCompletionRequest {
            system,
            history,
            prompt,
            captured,
            single_handoff: false,
        })
    }

    fn prepare_history_for_request(&self, history: &[Message]) -> Vec<Message> {
        #[cfg(test)]
        PREPARE_HISTORY_CALLS.with(|calls| calls.set(calls.get() + 1));
        if self.preserve_reasoning_for_replay() {
            history
                .iter()
                .filter_map(strip_unsigned_reasoning)
                .collect()
        } else {
            history.iter().filter_map(strip_reasoning).collect()
        }
    }

    /// Assemble the as-sent request body for the **dispatch-time** record,
    /// without dispatching (`inference-timeout-and-failure-
    /// observability.md` #4). Builds the identical payload
    /// [`Self::complete_captured`] does — same post-strip-reasoning history,
    /// same model id + params — so the `pending` record written before
    /// dispatch and the terminal record written after settle describe the
    /// same request. Used by [`crate::engine::agent::turn`] to persist the
    /// attempt at dispatch so a hung turn still exports a record.
    pub fn assemble_dispatch_request(
        &self,
        system: &str,
        history: &[Message],
        prompt: &Message,
        tools: &[ToolDefinition],
        params: &ModelParams,
    ) -> Result<serde_json::Value> {
        let prep_started = std::time::Instant::now();
        let params = self.with_resolved_model_params(params.clone());
        // Scrub identically to `complete_captured` so the pre-dispatch
        // `pending` record and the terminal captured record describe
        // byte-identical requests (GOALS §7). A trusted raw-custody route keeps
        // the raw history; an untrusted route runs the fail-closed wire walk
        // and propagates a non-renderable channel as a typed prep failure.
        let redact = self.redact();
        let history = self.prepare_history_for_request(history);
        let system = redact.scrub(system);
        let (mut history, mut prompt): (Vec<Message>, Message) = if self.is_trusted() {
            (history, prompt.clone())
        } else {
            let scrubbed_history = history
                .iter()
                .map(|m| scrub_message(redact, m))
                .collect::<std::result::Result<Vec<Message>, _>>()
                .map_err(|field| self.unrenderable_wire_failure(field, prep_started))?;
            let scrubbed_prompt = scrub_message(redact, prompt)
                .map_err(|field| self.unrenderable_wire_failure(field, prep_started))?;
            (scrubbed_history, scrubbed_prompt)
        };
        let identity_metadata = if self.needs_responses_tool_identity_normalization(false) {
            match normalize_responses_tool_call_identity(&mut history, &mut prompt) {
                Ok(records) if !records.is_empty() => Some((
                    "responses_tool_identity",
                    serde_json::to_value(&records)
                        .unwrap_or_else(|_| serde_json::Value::Array(Vec::new())),
                )),
                Err(err) => err
                    .downcast_ref::<ResponsesToolIdentityError>()
                    .map(|identity| {
                        (
                            "responses_tool_identity_error",
                            serde_json::json!({
                                "kind": identity.kind,
                                "call_id": identity.call_id,
                            }),
                        )
                    }),
                _ => None,
            }
        } else {
            None
        };
        let wire_tools = self.definitions_for_initial_wire(tools);
        let mut captured = assembled_request(
            self.model_id(),
            self.provider_label(),
            &system,
            &history,
            &prompt,
            wire_tools.as_ref(),
            &params,
        );
        if let Some((key, value)) = identity_metadata {
            captured[key] = value;
        }
        Ok(captured)
    }

    /// One-shot **tandem (shadow) completion** for model-comparison mode
    /// (implementation note). Sends the *identical*
    /// assembled request the main model received — same post-strip-reasoning
    /// `system` + `history` + `prompt` + `tools` + `params` — to this (tandem)
    /// model, and captures the outcome verbatim. A pure observer:
    ///
    /// - **Single-shot, no retry** (the spec wants the first outcome recorded).
    /// - **Non-streaming** — no `TurnEvent`s, never touches the UI.
    /// - **Independent, generous timeout** ([`TANDEM_TIMEOUT_SECS`]): a tandem
    ///   model erroring / rate-limiting / timing out is itself comparison
    ///   signal, captured as the record's status, and never affects the main
    ///   loop.
    /// - The returned output is **never executed** and **never enters any
    ///   agent's history** — the caller persists it to the session DB only.
    ///
    /// Redaction safety: the `(system, history, prompt)` handed in are already
    /// the post-`redact::scrub()` canonical forms the main turn built, so this
    /// reuses the already-scrubbed body and never routes around redaction.
    ///
    /// Returns the as-sent `request` body (identical assembly to the main
    /// call), the captured `response` (the full raw choice as JSON, `None` on
    /// failure/timeout), the `usage` (`None` when absent), and the terminal
    /// `status`.
    pub async fn complete_tandem(
        &self,
        system: &str,
        history: &[Message],
        prompt: &Message,
        tools: &[ToolDefinition],
        params: &ModelParams,
    ) -> TandemOutcome {
        let params = self.with_resolved_model_params(params.clone());
        // Identical assembly to `complete_captured` / `assemble_dispatch_request`
        // (strip reasoning, scrub every dynamic text field, then
        // `assembled_request`), so the persisted tandem request body is
        // byte-for-byte the shape the tandem model received and lines up with
        // the main call's captured body. The `(system, history, prompt)` handed
        // in are already the main turn's post-scrub forms; re-scrubbing here is
        // idempotent and keeps the redaction chokepoint authoritative (GOALS §7).
        let redact = self.redact();
        let stripped_raw = self.prepare_history_for_request(history);
        let system_scrubbed = redact.scrub(system);
        let system = system_scrubbed.as_str();
        // Trusted tandem keeps raw custody; an untrusted tandem runs the
        // fail-closed wire walk. A non-renderable channel is recorded as an
        // errored tandem outcome rather than passed unscrubbed to the wire.
        let scrub_result: std::result::Result<(Vec<Message>, Message), UnrenderableWireField> =
            if self.is_trusted() {
                Ok((stripped_raw, prompt.clone()))
            } else {
                (|| {
                    let history = stripped_raw
                        .iter()
                        .map(|m| scrub_message(redact, m))
                        .collect::<std::result::Result<Vec<Message>, _>>()?;
                    let prompt = scrub_message(redact, prompt)?;
                    Ok((history, prompt))
                })()
            };
        let (stripped, prompt_scrubbed) = match scrub_result {
            Ok(pair) => pair,
            Err(field) => {
                return TandemOutcome {
                    request: serde_json::json!({
                        "model": self.model_id(),
                        "provider": self.provider_label(),
                        "prep_error": field.detail(),
                    }),
                    response: Some(tandem_failure_response("error", field.detail())),
                    usage: None,
                    status: InferenceRequestStatus::Errored,
                };
            }
        };
        let prompt = &prompt_scrubbed;
        let wire_tools = self.definitions_for_initial_wire(tools);
        let request = assembled_request(
            self.model_id(),
            self.provider_label(),
            system,
            &stripped,
            prompt,
            wire_tools.as_ref(),
            &params,
        );

        // The daemon drain gate still applies — a tandem request is a *new*
        // provider round-trip, so it must not slip past the shutdown authority.
        if self.gate().is_draining() {
            return TandemOutcome {
                request,
                response: Some(tandem_failure_response("cancelled", "daemon is draining")),
                usage: None,
                status: InferenceRequestStatus::Cancelled,
            };
        }

        let limit = std::time::Duration::from_secs(TANDEM_TIMEOUT_SECS);
        let attempt = self.tandem_send(system, &stripped, prompt, tools, &params);
        match tokio::time::timeout(limit, attempt).await {
            Ok(Ok((choice, usage))) => {
                let response = serde_json::to_value(&choice)
                    .map_err(|e| {
                        tracing::warn!(error = %e, "serialize tandem response choice failed");
                        e
                    })
                    .ok();
                let usage = usage.map(|u| {
                    serde_json::json!({
                        "input_tokens": u.input_tokens,
                        "output_tokens": u.output_tokens,
                        "cached_input_tokens": u.cached_input_tokens,
                        "cache_creation_input_tokens": u.cache_creation_input_tokens,
                    })
                });
                TandemOutcome {
                    request,
                    response,
                    usage,
                    status: InferenceRequestStatus::Completed,
                }
            }
            Ok(Err(e)) => TandemOutcome {
                request,
                // Omit the raw provider error text: route it through the funnel
                // so only the fixed marker + typed metadata is persisted.
                response: Some(tandem_provider_error_response(&e)),
                usage: None,
                status: InferenceRequestStatus::Errored,
            },
            Err(_elapsed) => TandemOutcome {
                request,
                response: Some(tandem_failure_response(
                    "timeout",
                    format!("timed out after {TANDEM_TIMEOUT_SECS} seconds"),
                )),
                usage: None,
                status: InferenceRequestStatus::TimedOut,
            },
        }
    }

    /// Build + send one non-streaming tandem completion, returning the
    /// aggregated choice + usage. Mirrors the completion-request construction of
    /// [`Self::complete_captured`] per provider flavor (so tools + params ride
    /// the request identically), but uses the single-shot `.send()` path: a
    /// tandem call never streams to the UI and never retries.
    async fn tandem_send(
        &self,
        system: &str,
        history: &[Message],
        prompt: &Message,
        tools: &[ToolDefinition],
        params: &ModelParams,
    ) -> Result<(Vec<AssistantContent>, Option<TokenUsage>), rig::completion::CompletionError> {
        match self {
            Model::OpenAi {
                client, model_id, ..
            } => {
                // Use the resolved endpoint the main call would use first.
                let wire_api = self.resolve_live_wire_api_for_base_url(client.base_url());
                match wire_api {
                    crate::config::providers::WireApi::Responses => {
                        let wire_tools = wire_schema::definitions_for_wire(wire_api, tools);
                        let wire_tools = wire_tools.as_ref();
                        let responses = client.clone().responses_api();
                        let r = configured_completion_request(
                            build_openai_responses_completion_model(responses, model_id),
                            system,
                            history,
                            prompt.clone(),
                            wire_tools,
                            params,
                            openai_additional_params(params),
                        )
                        .send()
                        .await?;
                        Ok(tandem_choice_usage(r.choice, r.usage))
                    }
                    _ => {
                        let r = configured_completion_request(
                            build_completion_model(client, model_id),
                            system,
                            history,
                            prompt.clone(),
                            tools,
                            params,
                            openai_additional_params(params),
                        )
                        .send()
                        .await?;
                        Ok(tandem_choice_usage(r.choice, r.usage))
                    }
                }
            }
            Model::ChatGpt { model, .. } => {
                let wire_tools = wire_schema::definitions_for_wire(
                    crate::config::providers::WireApi::Responses,
                    tools,
                );
                let wire_tools = wire_tools.as_ref();
                let r = configured_completion_request(
                    build_chatgpt_completion_model(model.clone()),
                    system,
                    history,
                    prompt.clone(),
                    wire_tools,
                    params,
                    chatgpt_additional_params(params),
                )
                .send()
                .await?;
                Ok(tandem_choice_usage(r.choice, r.usage))
            }
            Model::Anthropic { model, .. } => {
                let r = configured_completion_request(
                    build_anthropic_completion_model(model.clone()),
                    system,
                    history,
                    prompt.clone(),
                    tools,
                    params,
                    anthropic_additional_params(params),
                )
                .send()
                .await?;
                Ok(tandem_choice_usage(r.choice, r.usage))
            }
        }
    }
}

/// Converts the terminal Rig error at the dispatch boundary into the typed
/// failure seam consumed by recording and failover. Keeping this conversion
/// standalone lets regression tests exercise the exact production classifier
/// without constructing an already-sanitized `InferenceFailure`.
pub(crate) fn terminal_inference_failure(
    err: &rig::completion::CompletionError,
    provider: &str,
    model: &str,
    phase: InferencePhase,
    elapsed_ms: u64,
    retry_attempts: u32,
    recovery_floor: ProviderRecoverySignal,
) -> InferenceFailure {
    let rig_boundary::ClassifiedFailure {
        class,
        observed_status,
        recovery,
    } = rig_boundary::classify_terminal_failure_with_floor(err, recovery_floor);
    InferenceFailure {
        provider: provider.to_string(),
        model: model.to_string(),
        phase: phase.as_str().to_string(),
        detail: failure_detail(err, &class),
        class,
        elapsed_ms,
        retry_attempts,
        observed_status,
        recovery,
    }
}

async fn openai_text_completion(
    client: &OpenAiCompatClient,
    model_id: &str,
    wire_api: crate::config::providers::WireApi,
    params: &ModelParams,
    system: Option<&str>,
    prompt: &str,
    context: &'static str,
) -> Result<String> {
    let choice = match wire_api {
        crate::config::providers::WireApi::Responses => {
            let responses = client.clone().responses_api();
            configured_completion_request(
                build_openai_responses_completion_model(responses, model_id),
                system.unwrap_or(""),
                &[],
                Message::user(prompt),
                &[],
                params,
                openai_additional_params(params),
            )
            .send()
            .await
            .context(context)?
            .choice
        }
        crate::config::providers::WireApi::Completions
        | crate::config::providers::WireApi::Auto => {
            configured_completion_request(
                build_completion_model(client, model_id),
                system.unwrap_or(""),
                &[],
                Message::user(prompt),
                &[],
                params,
                openai_additional_params(params),
            )
            .send()
            .await
            .context(context)?
            .choice
        }
    };

    Ok(choice_text(&choice).trim().to_string())
}

async fn openai_tool_completion(
    client: &OpenAiCompatClient,
    model_id: &str,
    wire_api: crate::config::providers::WireApi,
    params: &ModelParams,
    system: &str,
    prompt: &str,
    tool: &ToolDefinition,
) -> Result<Vec<crate::engine::message::ToolCall>> {
    let wire_tool = wire_schema::definitions_for_wire(wire_api, std::slice::from_ref(tool))
        .as_ref()
        .first()
        .cloned()
        .unwrap_or_else(|| tool.clone());
    let choice = match wire_api {
        crate::config::providers::WireApi::Responses => {
            let responses = client.clone().responses_api();
            configured_completion_request(
                build_openai_responses_completion_model(responses, model_id),
                system,
                &[],
                Message::user(prompt),
                std::slice::from_ref(&wire_tool),
                params,
                openai_additional_params(params),
            )
            .tool_choice(ToolChoice::Required)
            .send()
            .await
            .context("tool_completion: send failed")?
            .choice
        }
        crate::config::providers::WireApi::Completions
        | crate::config::providers::WireApi::Auto => {
            configured_completion_request(
                build_completion_model(client, model_id),
                system,
                &[],
                Message::user(prompt),
                std::slice::from_ref(&wire_tool),
                params,
                openai_additional_params(params),
            )
            .tool_choice(ToolChoice::Required)
            .send()
            .await
            .context("tool_completion: send failed")?
            .choice
        }
    };
    Ok(crate::engine::message::collect_tool_calls(&choice))
}

pub(super) fn assembled_request(
    model_id: &str,
    provider: &str,
    system: &str,
    history: &[Message],
    prompt: &Message,
    tools: &[ToolDefinition],
    params: &ModelParams,
) -> serde_json::Value {
    json!({
        "model": model_id,
        "provider": provider,
        "system": system,
        "tools": tools,
        "params": {
            "temperature": params.temperature,
            "max_tokens": params.max_tokens,
            "tools_required": params.tools_required,
        },
        // The exact extra fragment that gets flattened into the wire body —
        // computed the same way the live request computes it, so what's
        // recorded is what's sent:
        // - OpenAI-compat: vendor + native computer tools + prompt cache keys
        // - codex-oauth (native ChatGPT): vendor + native computer tools only
        // - anthropic: vendor + anthropic computer tools (per-block cache)
        // Omitted when there's nothing to add.
        "additional_params": match provider {
            "anthropic" => anthropic_additional_params(params),
            "codex-oauth" => chatgpt_additional_params(params),
            _ => openai_additional_params(params),
        },
        "native_computer_beta_headers": native_computer_beta_headers(params),
        "history": history,
        "prompt": prompt,
    })
}

/// Write a pre-assembled request body to `path` for `--debug-last-message`.
/// Best-effort — any error is traced but never propagated, because losing
/// a debug dump must not break a live turn.
fn write_dump(path: &Path, body: &serde_json::Value) {
    let pretty = match serde_json::to_string_pretty(body) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "debug-last-message: serialization failed");
            return;
        }
    };
    if let Err(e) = std::fs::write(path, format!("{pretty}\n")) {
        tracing::warn!(path = %path.display(), error = %e, "debug-last-message: write failed");
    }
}

pub(super) const TANDEM_TIMEOUT_SECS: u64 = 300;

/// Normalize a non-streaming completion response's `(choice, usage)` for a
/// tandem call: map rig's direct `Usage` into [`TokenUsage`], dropping an
/// all-zero usage (some providers omit it). Shared by the per-flavor arms of
/// [`Model::tandem_send`] so each provider's distinct `CompletionResponse<T>`
/// is reduced to the same shape.
pub(super) fn tandem_choice_usage(
    choice: Vec<AssistantContent>,
    usage: rig::completion::Usage,
) -> (Vec<AssistantContent>, Option<TokenUsage>) {
    let usage = Some(TokenUsage::from(usage)).filter(|u| !u.is_empty());
    (choice, usage)
}

pub(super) fn tandem_failure_response(
    kind: impl Into<String>,
    detail: impl Into<String>,
) -> serde_json::Value {
    serde_json::json!({
        "error": {
            "kind": kind.into(),
            "detail": detail.into(),
        }
    })
}

/// Content-safe tandem failure response for a raw provider
/// [`rig::completion::CompletionError`]. The attacker-controllable
/// `err.to_string()` provider body is OMITTED — routed through the same funnel
/// as every other provider-failure sink — so it never lands in the persisted
/// tandem session record (`schedule/tandem.rs` writes `outcome.response`
/// verbatim, and export redaction does not cover provider error text). The
/// stored `detail` is the fixed `provider_detail_omitted` marker; the typed
/// observed-status class and recovery kind remain queryable.
pub(super) fn tandem_provider_error_response(
    err: &rig::completion::CompletionError,
) -> serde_json::Value {
    let safe = crate::engine::model::safe_completion_error_detail(err);
    serde_json::json!({
        "error": {
            "kind": "error",
            "detail": safe.marker,
            "observed_status": safe.observed_status,
            "recovery": safe.recovery.as_str(),
        }
    })
}

/// The captured outcome of one tandem (shadow) completion
/// (implementation note). The caller persists every
/// field to the session DB; nothing here ever enters an agent's history.
#[derive(Clone)]
pub struct TandemOutcome {
    /// The exact post-redaction request body sent (identical assembly to the
    /// main call's captured body).
    pub request: serde_json::Value,
    /// The full raw completion (assistant text and/or tool calls) as JSON, or
    /// `None` on failure/timeout.
    pub response: Option<serde_json::Value>,
    /// Provider-reported token usage, or `None` when absent.
    pub usage: Option<serde_json::Value>,
    /// Terminal lifecycle status.
    pub status: InferenceRequestStatus,
}

/// Structural, content-free redaction descriptor for a trusted-body JSON
/// [`serde_json::Value`]. Emits the JSON kind plus a coarse size — never a key
/// name or value — behind the shared `[REDACTED; …]` marker, so a `{:?}` /
/// `tracing` / panic over a [`TandemOutcome`] never prints the verbatim body.
fn redacted_json_debug(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "[REDACTED; null]".to_string(),
        serde_json::Value::Bool(_) => "[REDACTED; bool]".to_string(),
        serde_json::Value::Number(_) => "[REDACTED; number]".to_string(),
        serde_json::Value::String(s) => format!("[REDACTED; string; len {}]", s.len()),
        serde_json::Value::Array(a) => format!("[REDACTED; array; {} items]", a.len()),
        serde_json::Value::Object(o) => format!("[REDACTED; object; {} keys]", o.len()),
    }
}

impl std::fmt::Debug for TandemOutcome {
    /// `request` / `response` (and `usage`) are the raw trusted tandem bodies;
    /// never print them verbatim. Show each field's structural descriptor plus
    /// the (non-body) terminal status.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TandemOutcome")
            .field(
                "request",
                &format_args!("{}", redacted_json_debug(&self.request)),
            )
            .field(
                "response",
                &format_args!(
                    "{}",
                    self.response
                        .as_ref()
                        .map_or_else(|| "None".to_string(), redacted_json_debug)
                ),
            )
            .field(
                "usage",
                &format_args!(
                    "{}",
                    self.usage
                        .as_ref()
                        .map_or_else(|| "None".to_string(), redacted_json_debug)
                ),
            )
            .field("status", &self.status)
            .finish()
    }
}

/// Drain one streaming completion attempt from a configured raw Rig request,
/// emitting text/reasoning deltas and aggregating the final choice + usage.
/// Generic over the model flavor so both the OpenAI-compat and native
/// Anthropic arms of [`Model::complete_captured`] share one body — the only
/// per-provider difference is how the `CompletionRequestBuilder` is built.
///
/// rig's `StreamingCompletionResponse` aggregates `choice` / `message_id`
/// internally as the stream advances; the post-loop reads pick them up. The
/// build and each chunk are raced against `cancel` so a ctrl+c aborts the
/// in-flight stream (dropping it closes the HTTP body) via the
/// [`AttemptCancelled`] sentinel (classified fail-fast by the retry layer).
///
/// **Stream wait thresholds**:
/// the first chunk after dispatch is watched with `timeout.ttft()` (TTFT) and
/// every subsequent chunk with `timeout.idle()` (inter-token), each as an
/// independent per-`next()` threshold — there is **no** overall wall-clock cap.
/// On expiry a warning is emitted; the same live read keeps waiting unless
/// `hard_timeout_on_stall` is true, in which case the attempt returns a
/// timeout sentinel for backup fallback. `phase` is bumped to the furthest
/// lifecycle stage reached so cancellation or a terminal provider error still
/// records exactly where it stopped.
#[allow(clippy::too_many_arguments)]
pub(super) async fn drain_completion_stream<M>(
    request: CompletionRequestBuilder<M>,
    agent_name: &str,
    provider_id: &str,
    model_id: &str,
    event_tx: Option<&mpsc::Sender<TurnEvent>>,
    cancel: &CancellationToken,
    timeout: &crate::config::providers::TimeoutConfig,
    hard_timeout_on_stall: bool,
    phase: &std::sync::atomic::AtomicU8,
    dispatched_at: std::time::Instant,
    first_token_ms: &std::sync::atomic::AtomicU64,
    output_sent: &std::sync::atomic::AtomicBool,
    pre_drain: Option<PreDrainFuture>,
    display: Option<&crate::engine::model::DisplayAttemptSlot>,
) -> Result<CompleteOut, rig::completion::CompletionError>
where
    M: rig::completion::CompletionModel,
{
    // Build the stream, racing the request dispatch against cancellation so a ctrl+c
    // during the initial round-trip aborts promptly. The request is now on
    // the wire: record `Dispatched` so a stall before the first token is
    // attributed to the dispatched (not prep) phase.
    // Polling `request.stream()` can put bytes on the wire before it resolves,
    // including when it resolves with an error. Advance first so every error
    // or cancellation from that poll is conservatively post-handoff.
    if cancel.is_cancelled() {
        return Err(attempt_cancelled());
    }
    bump_phase(phase, InferencePhase::Dispatched);
    let mut stream = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(attempt_cancelled()),
        built = request.stream() => built?,
    };
    await_pre_drain_record(pre_drain).await?;
    // Successful-attempt dispatch boundary: construct the display classifier
    // now that the stream is live, before any chunk is drained.
    if let Some(slot) = display {
        slot.begin_successful_attempt(agent_name, event_tx, dispatched_at)
            .await;
    }
    // Drive the chunk loop with TTFT + idle timeouts. The post-loop reads
    // below pick up the aggregated `choice` / `message_id` / `response` rig
    // accumulated as the stream advanced (the loop borrows `&mut stream`).
    // On error, leave any open visible classifier in place:
    // - a replacement attempt's `begin_successful_attempt` emits Reset
    // - a terminal Err arm calls `finish_as_error` for AssistantDisplayError
    drain_items(
        &mut stream,
        timeout,
        hard_timeout_on_stall,
        phase,
        dispatched_at,
        first_token_ms,
        agent_name,
        provider_id,
        model_id,
        event_tx,
        cancel,
        output_sent,
        display,
    )
    .await?;
    // rig requests `stream_options.include_usage = true` on every stream;
    // providers that omit it now surface as an empty default usage value.
    let usage = TokenUsage::from(stream.usage());
    let usage = (!usage.is_empty()).then_some(usage);
    Ok((stream.message_id.clone(), stream.choice.clone(), usage))
}

pub(super) async fn await_pre_drain_record(
    pre_drain: Option<PreDrainFuture>,
) -> Result<(), rig::completion::CompletionError> {
    if let Some(pre_drain) = pre_drain {
        pre_drain.await.map_err(|err| {
            rig::completion::CompletionError::ResponseError(format!(
                "record_inference_request failed before response processing: {err}"
            ))
        })?;
    }
    Ok(())
}

/// Drive the chunk loop of a streaming completion with the TTFT + idle
/// wait thresholds and cancellation (`inference-timeout-and-failure-
/// observability.md`). Generic over the chunk stream `S` so it is unit-
/// testable with a `futures` fake (a real `StreamingCompletionResponse` is
/// not constructible in a test). Drives the per-chunk side effects (text /
/// reasoning deltas) and the phase/first-token tracking; the caller reads the
/// rig-aggregated `choice` / `message_id` / `response` after this returns.
///
/// The first chunk is watched by `timeout.ttft()` (TTFT); every later chunk by
/// `timeout.idle()` (inter-token). Each `next()` gets its own independent
/// warning threshold — there is no overall wall-clock cap, so an actively
/// streaming response is never killed. On expiry a warning is emitted; if a
/// backup is configured the current attempt hard-aborts with a timeout
/// sentinel so backup fallback can engage. A ctrl+c returns [`AttemptCancelled`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn drain_items<S>(
    stream: &mut S,
    timeout: &crate::config::providers::TimeoutConfig,
    hard_timeout_on_stall: bool,
    phase: &std::sync::atomic::AtomicU8,
    dispatched_at: std::time::Instant,
    first_token_ms: &std::sync::atomic::AtomicU64,
    agent_name: &str,
    provider_id: &str,
    model_id: &str,
    event_tx: Option<&mpsc::Sender<TurnEvent>>,
    cancel: &CancellationToken,
    output_sent: &std::sync::atomic::AtomicBool,
    display: Option<&crate::engine::model::DisplayAttemptSlot>,
) -> Result<(), rig::completion::CompletionError>
where
    S: futures::Stream<Item = Result<StreamedAssistantContent, rig::completion::CompletionError>>
        + Unpin,
{
    // The first chunk is watched by TTFT; every later chunk by the idle
    // threshold. `first_token` flips after the first chunk so the warning phase
    // switches from TTFT to idle.
    let mut first_token = true;
    let mut ttft_warning_sent = false;
    let mut idle_warning_sent_for_boundary = false;
    loop {
        let limit = if first_token {
            timeout.ttft()
        } else {
            timeout.idle()
        };
        let mut next = Box::pin(stream.next());
        let mut warned_for_current_wait = false;
        let item = loop {
            let warning_sleep = tokio::time::sleep(limit);
            tokio::pin!(warning_sleep);
            let phase_warning_already_sent = if first_token {
                ttft_warning_sent
            } else {
                idle_warning_sent_for_boundary
            };
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(attempt_cancelled()),
                next = &mut next => match next {
                    Some(item) => break item,
                    None => return Ok(()),
                },
                _ = &mut warning_sleep, if !warned_for_current_wait && !phase_warning_already_sent => {
                    let is_ttft = first_token;
                    if let Some(event_tx) = event_tx {
                        let _ = event_tx
                            .send(TurnEvent::InferenceWarning {
                            agent: agent_name.to_string(),
                            provider: provider_id.to_string(),
                            model: model_id.to_string(),
                            phase: if is_ttft { "ttft" } else { "idle" }.to_string(),
                            waited_secs: limit.as_secs(),
                        })
                            .await;
                    }
                    warned_for_current_wait = true;
                    if is_ttft {
                        ttft_warning_sent = true;
                    } else {
                        idle_warning_sent_for_boundary = true;
                    }
                    if hard_timeout_on_stall {
                        return Err(if is_ttft { ttft_timeout() } else { idle_timeout() });
                    }
                }
            }
        };
        if first_token {
            first_token = false;
            bump_phase(phase, InferencePhase::FirstToken);
            // Record time-to-first-token (from dispatch) for the phase-
            // timestamp export. `store` rather than `fetch_max` because each
            // fresh attempt's first token is the meaningful one for the
            // attempt that ultimately succeeds (the last write wins, and only
            // the Ok attempt's value is read back).
            first_token_ms.store(
                dispatched_at.elapsed().as_millis() as u64,
                std::sync::atomic::Ordering::SeqCst,
            );
        } else {
            bump_phase(phase, InferencePhase::Streaming);
        }
        idle_warning_sent_for_boundary = false;
        match item? {
            StreamedAssistantContent::Text(text) if !text.text.is_empty() => {
                output_sent.store(true, std::sync::atomic::Ordering::SeqCst);
                if let Some(slot) = display {
                    slot.feed_text(agent_name, &text.text, event_tx).await;
                } else if let Some(event_tx) = event_tx {
                    let _ = event_tx
                        .send(TurnEvent::AssistantTextDelta {
                            agent: agent_name.to_string(),
                            delta: text.text,
                        })
                        .await;
                }
            }
            StreamedAssistantContent::ReasoningDelta { reasoning, .. } => {
                // Capture for the "expand thinking block" feature; the TUI
                // hides this by default.
                if !reasoning.is_empty() {
                    output_sent.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                if let Some(slot) = display {
                    slot.feed_reasoning(agent_name, &reasoning, event_tx).await;
                } else if let Some(event_tx) = event_tx {
                    let _ = event_tx
                        .send(TurnEvent::ReasoningDelta {
                            agent: agent_name.to_string(),
                            delta: reasoning,
                        })
                        .await;
                }
            }
            StreamedAssistantContent::Reasoning { reasoning, .. } => {
                let combined = collect_reasoning_text(&reasoning);
                if !combined.is_empty() {
                    output_sent.store(true, std::sync::atomic::Ordering::SeqCst);
                    if let Some(slot) = display {
                        slot.feed_reasoning(agent_name, &combined, event_tx).await;
                    } else if let Some(event_tx) = event_tx {
                        let _ = event_tx
                            .send(TurnEvent::ReasoningDelta {
                                agent: agent_name.to_string(),
                                delta: combined,
                            })
                            .await;
                    }
                }
            }
            // ToolCallDelta / ToolCall / Final are aggregated into
            // `stream.choice` / `stream.message_id` internally; the
            // post-loop reads pick them up.
            _ => {}
        }
    }
}

#[cfg(test)]
mod redact_debug_tests {
    use super::*;

    #[test]
    fn tandem_outcome_debug_redacts_request_and_response() {
        let req_secret = "TRUSTED-OUTCOME-REQUEST-SECRET-aaa";
        let resp_secret = "TRUSTED-OUTCOME-RESPONSE-SECRET-bbb";
        let outcome = TandemOutcome {
            request: serde_json::json!({ "prompt": req_secret }),
            response: Some(serde_json::json!({ "text": resp_secret })),
            usage: Some(serde_json::json!({ "input_tokens": 10 })),
            status: InferenceRequestStatus::Completed,
        };
        let rendered = format!("{outcome:?}");
        assert!(!rendered.contains(req_secret), "leaked request: {rendered}");
        assert!(
            !rendered.contains(resp_secret),
            "leaked response: {rendered}"
        );
        assert!(rendered.contains("REDACTED"), "missing marker: {rendered}");
        // The non-body terminal status stays visible for diagnostics.
        assert!(rendered.contains("Completed"), "dropped status: {rendered}");
    }
}
