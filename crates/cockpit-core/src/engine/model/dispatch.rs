use super::*;
use futures::StreamExt;

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
        use rig::completion::Prompt;
        let guard = self.outbound_guard();
        guard.ensure_dispatch_allowed()?;
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
                    let agent = build_chatgpt_agent(model.clone(), "", &[], &params);
                    let response = agent
                        .prompt(prompt)
                        .await
                        .context("text_completion: prompt failed")?;
                    Ok(response.trim().to_string())
                }
                Model::Anthropic { model, .. } => {
                    let agent = build_anthropic_agent(model.clone(), "", &[], &params);
                    let response = agent
                        .prompt(prompt)
                        .await
                        .context("text_completion: prompt failed")?;
                    Ok(response.trim().to_string())
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
        use rig::completion::Prompt;
        let guard = self.outbound_guard();
        guard.ensure_dispatch_allowed()?;
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
                    let agent = build_chatgpt_agent(model.clone(), system, &[], &params);
                    let response = agent
                        .prompt(prompt)
                        .await
                        .context("text_completion_with_system: prompt failed")?;
                    Ok(response.trim().to_string())
                }
                Model::Anthropic { model, .. } => {
                    let agent = build_anthropic_agent(model.clone(), system, &[], &params);
                    let response = agent
                        .prompt(prompt)
                        .await
                        .context("text_completion_with_system: prompt failed")?;
                    Ok(response.trim().to_string())
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
        use rig::completion::Completion;
        let guard = self.outbound_guard();
        guard.ensure_dispatch_allowed()?;
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
                    let agent = build_chatgpt_agent(model.clone(), system, &[], &params);
                    let response = agent
                        .completion(Message::user(prompt), Vec::<Message>::new())
                        .await?
                        .tool(tool.clone())
                        .tool_choice(ToolChoice::Required)
                        .send()
                        .await
                        .context("tool_completion: send failed")?;
                    Ok(crate::engine::message::collect_tool_calls(&response.choice))
                }
                Model::Anthropic { model, .. } => {
                    let agent = build_anthropic_agent(model.clone(), system, &[], &params);
                    let response = agent
                        .completion(Message::user(prompt), Vec::<Message>::new())
                        .await?
                        .tool(tool.clone())
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
                class: "utility_timeout".to_string(),
                elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                detail: format!(
                    "{site:?} utility request exceeded {}ms {:?} budget",
                    site.timeout().as_millis(),
                    site.budget_class()
                ),
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
        (
            Option<String>,
            OneOrMany<AssistantContent>,
            Option<TokenUsage>,
        ),
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
        (
            Option<String>,
            OneOrMany<AssistantContent>,
            Option<TokenUsage>,
        ),
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
        )
        .await
    }

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
    ) -> Result<(
        (
            Option<String>,
            OneOrMany<AssistantContent>,
            Option<TokenUsage>,
        ),
        serde_json::Value,
        InferenceTiming,
    )> {
        let params = self.with_resolved_model_params(params);
        self.outbound_guard().ensure_dispatch_allowed()?;
        let PreparedCompletionRequest {
            system,
            history,
            prompt,
            mut captured,
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
            return Err(anyhow::Error::new(InferenceCancelled));
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
        let hard_timeout_on_stall = self.hard_timeout_on_stall();
        // Furthest lifecycle phase reached across (possibly several) retry
        // attempts; seeded at `Prep` (we got past assembly). A typed failure
        // reports the furthest phase, so e.g. a network blip that reached
        // `first_token` once then failed at `dispatched` on retry still
        // records `first_token`.
        let phase = std::sync::atomic::AtomicU8::new(InferencePhase::Prep.rank());
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
                        let wire_tools = wire_schema::definitions_for_wire(endpoint, tools);
                        let wire_tools = wire_tools.as_ref();
                        // Build the OpenAI-compat agent against the *current*
                        // endpoint: the kept `CompletionsClient` directly, or a
                        // cheap O(1) `.responses_api()` swap of a clone (only the
                        // provider extension changes; base URL/headers/HTTP are
                        // reused). Re-built every attempt so a transient retry
                        // rebuilds a fresh stream.
                        match endpoint {
                            crate::config::providers::WireApi::Responses => {
                                let responses = client.clone().responses_api();
                                let agent =
                                    build_agent(&responses, model_id, system, wire_tools, &params);
                                drain_completion_stream(
                                    agent,
                                    &prompt,
                                    &history,
                                    &params,
                                    wire_tools,
                                    agent_name,
                                    provider_id,
                                    model_id,
                                    event_tx,
                                    cancel,
                                    &timeout,
                                    hard_timeout_on_stall,
                                    &phase,
                                    dispatched_at,
                                    &first_token_ms,
                                    &output_sent,
                                    pre_drain.clone(),
                                )
                                .await
                            }
                            // `Completions` (and the defensive `Auto`, never the
                            // resolved value) use the kept completions client.
                            _ => {
                                let agent =
                                    build_agent(client, model_id, system, wire_tools, &params);
                                drain_completion_stream(
                                    agent,
                                    &prompt,
                                    &history,
                                    &params,
                                    wire_tools,
                                    agent_name,
                                    provider_id,
                                    model_id,
                                    event_tx,
                                    cancel,
                                    &timeout,
                                    hard_timeout_on_stall,
                                    &phase,
                                    dispatched_at,
                                    &first_token_ms,
                                    &output_sent,
                                    pre_drain.clone(),
                                )
                                .await
                            }
                        }
                    };
                    let result = if tried_swap {
                        retry::with_retry_max(
                            agent_name,
                            &reconnect_target,
                            event_tx,
                            cancel,
                            probe.as_ref(),
                            5,
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
                            if !tried_swap
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
                            let approved = if !tried_swap
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
                    let wire_tools = wire_schema::definitions_for_wire(
                        crate::config::providers::WireApi::Responses,
                        tools,
                    );
                    let wire_tools = wire_tools.as_ref();
                    let agent = build_chatgpt_agent(model.clone(), system, wire_tools, &params);
                    drain_completion_stream(
                        agent,
                        &prompt,
                        &history,
                        &params,
                        wire_tools,
                        agent_name,
                        provider_id,
                        model_id,
                        event_tx,
                        cancel,
                        &timeout,
                        hard_timeout_on_stall,
                        &phase,
                        dispatched_at,
                        &first_token_ms,
                        &output_sent,
                        pre_drain.clone(),
                    )
                    .await
                };
                retry::with_retry(
                    agent_name,
                    &reconnect_target,
                    event_tx,
                    cancel,
                    probe.as_ref(),
                    attempt,
                )
                .await
            }
            Model::Anthropic {
                model,
                provider_id,
                model_id,
                ..
            } => {
                // Native Anthropic: no wire-API selector, single retry unit.
                let attempt = || async {
                    let agent = build_anthropic_agent(model.clone(), system, tools, &params);
                    drain_completion_stream(
                        agent,
                        &prompt,
                        &history,
                        &params,
                        tools,
                        agent_name,
                        provider_id,
                        model_id,
                        event_tx,
                        cancel,
                        &timeout,
                        hard_timeout_on_stall,
                        &phase,
                        dispatched_at,
                        &first_token_ms,
                        &output_sent,
                        pre_drain.clone(),
                    )
                    .await
                };
                retry::with_retry(
                    agent_name,
                    &reconnect_target,
                    event_tx,
                    cancel,
                    probe.as_ref(),
                    attempt,
                )
                .await
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
                    return Err(anyhow::Error::new(InferenceCancelled));
                }
                // Every other terminal failure (timeout / network /
                // non-retryable HTTP) is mapped into the well-typed
                // `InferenceFailure` seam a future fallback intercepts.
                let elapsed_ms = dispatched_at.elapsed().as_millis() as u64;
                let phase =
                    InferencePhase::from_rank(phase.load(std::sync::atomic::Ordering::SeqCst));
                let class = classify_inference_failure(&err);
                let mut detail = failure_detail(&err, &class);
                if !tools.is_empty()
                    && self.xai_multi_agent_tools_entitlement_enabled()
                    && provider_rejected_xai_multi_agent_tools(&detail)
                {
                    detail.push_str(" Disable the xAI beta tools entitlement in provider/model settings or choose a non-multi-agent model if the account lacks beta access.");
                }
                Err(anyhow::Error::new(InferenceFailure {
                    provider: self.provider_id().to_string(),
                    model: self.model_id().to_string(),
                    phase: phase.as_str().to_string(),
                    class: class.as_str(),
                    elapsed_ms,
                    detail,
                }))
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
                    class: "missing_tool_entitlement".to_string(),
                    elapsed_ms: 0,
                    detail: format!(
                        "client-side tools require entitlement `{entitlement}`; primary model was blocked before network dispatch. Enable the entitlement in provider/model settings or choose a non-multi-agent model."
                    ),
                }))
            }
            CapabilityStatus::Unsupported => Err(anyhow::Error::new(InferenceFailure {
                provider: self.provider_id().to_string(),
                model: self.model_id().to_string(),
                phase: "prep".to_string(),
                class: "client_side_tools_unsupported".to_string(),
                elapsed_ms: 0,
                detail: "client-side tools are unsupported for this model; primary model was blocked before network dispatch. Choose a tool-compatible model or configure a compatible backup model."
                    .to_string(),
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

    pub(crate) fn prepare_completion_request(
        &self,
        system: &str,
        history: &[Message],
        prompt: &Message,
        tools: &[ToolDefinition],
        params: &ModelParams,
        endpoint_recovery_enabled: bool,
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
        let redact = self.redact();
        let system = redact.scrub(system);
        let mut history = history;
        let mut prompt = prompt.clone();
        if !redact.is_empty() {
            history = history.iter().map(|m| scrub_message(redact, m)).collect();
            prompt = scrub_message(redact, &prompt);
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
                            class: "responses_tool_identity".to_string(),
                            elapsed_ms: prep_started.elapsed().as_millis() as u64,
                            detail: err.to_string(),
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
    ) -> serde_json::Value {
        let params = self.with_resolved_model_params(params.clone());
        // Scrub identically to `complete_captured` so the pre-dispatch
        // `pending` record and the terminal captured record describe
        // byte-identical requests (GOALS §7).
        let redact = self.redact();
        let history = self.prepare_history_for_request(history);
        let mut history: Vec<Message> = history.iter().map(|m| scrub_message(redact, m)).collect();
        let system = redact.scrub(system);
        let mut prompt = scrub_message(redact, prompt);
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
        captured
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
        let stripped = self.prepare_history_for_request(history);
        let stripped: Vec<Message> = stripped.iter().map(|m| scrub_message(redact, m)).collect();
        let system_scrubbed = redact.scrub(system);
        let system = system_scrubbed.as_str();
        let prompt_scrubbed = scrub_message(redact, prompt);
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
                response: Some(tandem_failure_response("error", e.to_string())),
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
    /// aggregated choice + usage. Mirrors the agent-build of
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
    ) -> Result<(OneOrMany<AssistantContent>, Option<TokenUsage>), rig::completion::CompletionError>
    {
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
                        let agent = build_agent(&responses, model_id, system, wire_tools, params);
                        let mut req = agent.completion(prompt.clone(), history.to_vec()).await?;
                        if params.tools_required && !wire_tools.is_empty() {
                            req = req.tool_choice(ToolChoice::Required);
                        }
                        let r = req.send().await?;
                        Ok(tandem_choice_usage(r.choice, r.usage))
                    }
                    _ => {
                        let agent = build_agent(client, model_id, system, tools, params);
                        let mut req = agent.completion(prompt.clone(), history.to_vec()).await?;
                        if params.tools_required && !tools.is_empty() {
                            req = req.tool_choice(ToolChoice::Required);
                        }
                        let r = req.send().await?;
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
                let agent = build_chatgpt_agent(model.clone(), system, wire_tools, params);
                let mut req = agent.completion(prompt.clone(), history.to_vec()).await?;
                if params.tools_required && !wire_tools.is_empty() {
                    req = req.tool_choice(ToolChoice::Required);
                }
                let r = req.send().await?;
                Ok(tandem_choice_usage(r.choice, r.usage))
            }
            Model::Anthropic { model, .. } => {
                let agent = build_anthropic_agent(model.clone(), system, tools, params);
                let mut req = agent.completion(prompt.clone(), history.to_vec()).await?;
                if params.tools_required && !tools.is_empty() {
                    req = req.tool_choice(ToolChoice::Required);
                }
                let r = req.send().await?;
                Ok(tandem_choice_usage(r.choice, r.usage))
            }
        }
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
    use rig::completion::Prompt;

    let response = match wire_api {
        crate::config::providers::WireApi::Responses => {
            let responses = client.clone().responses_api();
            build_agent(&responses, model_id, system.unwrap_or(""), &[], params)
                .prompt(prompt)
                .await
        }
        crate::config::providers::WireApi::Completions
        | crate::config::providers::WireApi::Auto => {
            build_agent(client, model_id, system.unwrap_or(""), &[], params)
                .prompt(prompt)
                .await
        }
    }
    .context(context)?;

    Ok(response.trim().to_string())
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
    use rig::completion::Completion;

    let wire_tool = wire_schema::definitions_for_wire(wire_api, std::slice::from_ref(tool))
        .as_ref()
        .first()
        .cloned()
        .unwrap_or_else(|| tool.clone());
    match wire_api {
        crate::config::providers::WireApi::Responses => {
            let responses = client.clone().responses_api();
            let response = build_agent(&responses, model_id, system, &[], params)
                .completion(Message::user(prompt), Vec::<Message>::new())
                .await?
                .tool(wire_tool)
                .tool_choice(ToolChoice::Required)
                .send()
                .await
                .context("tool_completion: send failed")?;
            Ok(crate::engine::message::collect_tool_calls(&response.choice))
        }
        crate::config::providers::WireApi::Completions
        | crate::config::providers::WireApi::Auto => {
            let response = build_agent(client, model_id, system, &[], params)
                .completion(Message::user(prompt), Vec::<Message>::new())
                .await?
                .tool(wire_tool)
                .tool_choice(ToolChoice::Required)
                .send()
                .await
                .context("tool_completion: send failed")?;
            Ok(crate::engine::message::collect_tool_calls(&response.choice))
        }
    }
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
        // recorded is what's sent. The native Anthropic arm flattens only the
        // sanitized vendor fragment (it caches per-block, no `prompt_cache_key`);
        // every OpenAI-compat arm also injects the top-level `prompt_cache_key`
        // (`prompt-caching-strategy.md` decision 3). Omitted when there's
        // nothing to add, so existing providers' captured bodies are unchanged.
        "additional_params": if provider == "anthropic" {
            anthropic_additional_params(params)
        } else {
            openai_additional_params(params)
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
    choice: OneOrMany<AssistantContent>,
    usage: rig::completion::Usage,
) -> (OneOrMany<AssistantContent>, Option<TokenUsage>) {
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

/// The captured outcome of one tandem (shadow) completion
/// (implementation note). The caller persists every
/// field to the session DB; nothing here ever enters an agent's history.
#[derive(Debug, Clone)]
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

/// Drain one streaming completion attempt over a built `rig::agent::Agent`,
/// emitting text/reasoning deltas and aggregating the final choice + usage.
/// Generic over the model flavor so both the OpenAI-compat and native
/// Anthropic arms of [`Model::complete_captured`] share one body — the only
/// per-provider difference is how the agent is built.
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
    agent: rig::agent::Agent<M>,
    prompt: &Message,
    history: &[Message],
    params: &ModelParams,
    tools: &[ToolDefinition],
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
) -> Result<CompleteOut, rig::completion::CompletionError>
where
    M: rig::completion::CompletionModel,
{
    let mut req = agent.completion(prompt.clone(), history.to_vec()).await?;
    if params.tools_required && !tools.is_empty() {
        req = req.tool_choice(ToolChoice::Required);
    }
    // Build the stream, racing the build against cancellation so a ctrl+c
    // during the initial round-trip aborts promptly. The request is now on
    // the wire: record `Dispatched` so a stall before the first token is
    // attributed to the dispatched (not prep) phase.
    let mut stream = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(attempt_cancelled()),
        built = req.stream() => built?,
    };
    bump_phase(phase, InferencePhase::Dispatched);
    await_pre_drain_record(pre_drain).await?;
    // Drive the chunk loop with TTFT + idle timeouts. The post-loop reads
    // below pick up the aggregated `choice` / `message_id` / `response` rig
    // accumulated as the stream advanced (the loop borrows `&mut stream`).
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
    )
    .await?;
    // rig requests `stream_options.include_usage = true` on every stream;
    // the final usage chunk lands on `stream.response` (Option, because some
    // providers omit it).
    let usage = stream
        .response
        .token_usage()
        .map(TokenUsage::from)
        .filter(|u| !u.is_empty());
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
pub(super) async fn drain_items<S, R>(
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
) -> Result<(), rig::completion::CompletionError>
where
    S: futures::Stream<
            Item = Result<StreamedAssistantContent<R>, rig::completion::CompletionError>,
        > + Unpin,
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
                if let Some(event_tx) = event_tx {
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
                if let Some(event_tx) = event_tx {
                    let _ = event_tx
                        .send(TurnEvent::ReasoningDelta {
                            agent: agent_name.to_string(),
                            delta: reasoning,
                        })
                        .await;
                }
            }
            StreamedAssistantContent::Reasoning(r) => {
                let combined = collect_reasoning_text(&r);
                if !combined.is_empty() {
                    output_sent.store(true, std::sync::atomic::Ordering::SeqCst);
                    if let Some(event_tx) = event_tx {
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
