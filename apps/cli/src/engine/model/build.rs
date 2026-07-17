use super::*;

impl Model {
    /// Resolve the active model from the user's config + credentials and
    /// build a concrete `Model`. Returns a descriptive error when nothing
    /// is configured or the env var that holds the key isn't set.
    ///
    /// `redact` is the session's effective redaction table — required, so
    /// the model carries its non-bypassable scrub chokepoint by construction
    /// (GOALS §7, `redaction-cover-all-llm-requests.md`).
    #[allow(dead_code)]
    pub fn from_config(cfg: &ProvidersConfig, redact: Arc<RedactionTable>) -> Result<Self> {
        Self::from_config_with_env(cfg, redact, |name| std::env::var(name).ok())
    }

    #[allow(dead_code)]
    pub fn from_config_trusted_only(
        cfg: &ProvidersConfig,
        redact: Arc<RedactionTable>,
        trusted_only: Arc<AtomicBool>,
    ) -> Result<Self> {
        Self::from_config_with_env_trusted_only(cfg, redact, trusted_only, |name| {
            std::env::var(name).ok()
        })
    }

    pub fn from_config_with_env<F>(
        cfg: &ProvidersConfig,
        redact: Arc<RedactionTable>,
        lookup: F,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        Self::from_config_with_env_trusted_only(
            cfg,
            redact,
            Arc::new(AtomicBool::new(false)),
            lookup,
        )
    }

    pub fn from_config_with_env_trusted_only<F>(
        cfg: &ProvidersConfig,
        redact: Arc<RedactionTable>,
        trusted_only: Arc<AtomicBool>,
        lookup: F,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let active: &ActiveModelRef = cfg.active_model.as_ref().context(
            "no active model selected — run /model or set COCKPIT_PROVIDER/COCKPIT_MODEL",
        )?;
        let entry = cfg
            .providers
            .get(&active.provider)
            .with_context(|| format!("provider `{}` is not configured", active.provider))?;
        let trusted = Self::ensure_trusted_only_build_allowed(
            cfg,
            &active.provider,
            &active.model,
            &trusted_only,
        )?;
        let cache = cfg.resolve_cache(&active.provider, &active.model);
        let timeout = cfg.resolve_timeout(&active.provider, &active.model);
        let hard_timeout_on_stall = cfg
            .resolve_backup(&active.provider, &active.model)
            .is_some();
        let wire_api = cfg.resolve_wire_api(&active.provider, &active.model);
        let wire_api_explicit = cfg.is_wire_api_explicit(&active.provider, &active.model);
        let client_side_tools =
            cfg.resolve_effective_client_side_tools(&active.provider, &active.model);
        let location = cfg.resolve_location(&active.provider, &active.model);
        let quality_rank = cfg.resolve_quality_rank(&active.provider, &active.model);
        let cost_rank = cfg.resolve_cost_rank(&active.provider, &active.model);
        let subagent_invokable = cfg.resolve_subagent_invokable(&active.provider, &active.model);
        let effective_redact =
            Self::effective_redact_table_for(cfg, &active.provider, &active.model, redact.clone());
        build_model(
            &active.provider,
            entry,
            &active.model,
            &cache,
            &timeout,
            hard_timeout_on_stall,
            client_side_tools,
            wire_api,
            wire_api_explicit,
            trusted,
            location,
            quality_rank,
            cost_rank,
            subagent_invokable,
            trusted_only,
            redact,
            effective_redact,
            lookup,
        )
    }
    /// Build a `Model` from a `"provider:model-id"` reference, erroring on
    /// a missing colon. Thin wrapper over [`Self::for_provider`] for the
    /// utility-model call sites. `redact` is the caller's effective
    /// redaction table (the session's table for in-session utility calls;
    /// a `RedactConfig`+cwd-built table for out-of-session ones).
    #[allow(dead_code)]
    pub fn from_ref(
        cfg: &ProvidersConfig,
        model_ref: &str,
        redact: Arc<RedactionTable>,
    ) -> Result<Self> {
        let (provider_id, model_id) = model_ref
            .split_once(':')
            .with_context(|| format!("model ref `{model_ref}` must be provider:model-id"))?;
        Self::for_provider(cfg, provider_id, model_id, redact)
    }

    pub fn from_ref_trusted_only(
        cfg: &ProvidersConfig,
        model_ref: &str,
        redact: Arc<RedactionTable>,
        trusted_only: Arc<AtomicBool>,
    ) -> Result<Self> {
        let (provider_id, model_id) = model_ref
            .split_once(':')
            .with_context(|| format!("model ref `{model_ref}` must be provider:model-id"))?;
        Self::for_provider_trusted_only(cfg, provider_id, model_id, redact, trusted_only)
    }

    /// Build a `Model` for an arbitrary `(provider, model_id)` pair,
    /// re-using the same auth-header / env-resolve pipeline as
    /// [`Self::from_config`] but bypassing the active-model selection.
    /// Used by background-only flows (auto-titling §17d, prompt-
    /// injection guard §4i) that target the utility model rather than
    /// whatever the user has selected for the foreground turn. `redact` is
    /// the required effective redaction table (see [`Self::from_config`]).
    pub fn for_provider(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        redact: Arc<RedactionTable>,
    ) -> Result<Self> {
        Self::for_provider_with_env(cfg, provider_id, model_id, redact, |name| {
            std::env::var(name).ok()
        })
    }

    pub fn for_provider_trusted_only(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        redact: Arc<RedactionTable>,
        trusted_only: Arc<AtomicBool>,
    ) -> Result<Self> {
        Self::for_provider_with_env_trusted_only(
            cfg,
            provider_id,
            model_id,
            redact,
            trusted_only,
            |name| std::env::var(name).ok(),
        )
    }

    pub fn for_provider_with_env<F>(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        redact: Arc<RedactionTable>,
        lookup: F,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        Self::for_provider_with_env_trusted_only(
            cfg,
            provider_id,
            model_id,
            redact,
            Arc::new(AtomicBool::new(false)),
            lookup,
        )
    }

    pub fn for_provider_with_env_trusted_only<F>(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        redact: Arc<RedactionTable>,
        trusted_only: Arc<AtomicBool>,
        lookup: F,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let entry = cfg
            .providers
            .get(provider_id)
            .with_context(|| format!("provider `{provider_id}` is not configured"))?;
        let trusted =
            Self::ensure_trusted_only_build_allowed(cfg, provider_id, model_id, &trusted_only)?;
        let cache = cfg.resolve_cache(provider_id, model_id);
        let timeout = cfg.resolve_timeout(provider_id, model_id);
        let hard_timeout_on_stall = cfg.resolve_backup(provider_id, model_id).is_some();
        let wire_api = cfg.resolve_wire_api(provider_id, model_id);
        let wire_api_explicit = cfg.is_wire_api_explicit(provider_id, model_id);
        let client_side_tools = cfg.resolve_effective_client_side_tools(provider_id, model_id);
        let location = cfg.resolve_location(provider_id, model_id);
        let quality_rank = cfg.resolve_quality_rank(provider_id, model_id);
        let cost_rank = cfg.resolve_cost_rank(provider_id, model_id);
        let subagent_invokable = cfg.resolve_subagent_invokable(provider_id, model_id);
        let effective_redact =
            Self::effective_redact_table_for(cfg, provider_id, model_id, redact.clone());
        build_model(
            provider_id,
            entry,
            model_id,
            &cache,
            &timeout,
            hard_timeout_on_stall,
            client_side_tools,
            wire_api,
            wire_api_explicit,
            trusted,
            location,
            quality_rank,
            cost_rank,
            subagent_invokable,
            trusted_only,
            redact,
            effective_redact,
            lookup,
        )
    }
}

pub(super) fn is_anthropic_native(base_url: &str) -> bool {
    crate::config::providers::is_anthropic_native_base_url(base_url)
}

/// Route a `(provider, model)` build to the native Anthropic path or the
/// OpenAI-compat path based on the resolved base-URL host
/// ([`is_anthropic_native`]). The `cache` config drives the Anthropic TTL
/// mode (5-min vs 1h) and is unused on the OpenAI-compat path (which relies
/// on prefix stability + `prompt_cache_key`, set later via `ModelParams`).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_model(
    provider_id: &str,
    entry: &ProviderEntry,
    model_id: &str,
    cache: &crate::config::providers::CacheConfig,
    timeout: &crate::config::providers::TimeoutConfig,
    hard_timeout_on_stall: bool,
    client_side_tools: ClientSideToolsCapability,
    wire_api: crate::config::providers::WireApi,
    wire_api_explicit: bool,
    trusted: bool,
    location: Option<ModelLocation>,
    quality_rank: i64,
    cost_rank: i64,
    subagent_invokable: bool,
    trusted_only: Arc<AtomicBool>,
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Model> {
    let registry = crate::providers::ProviderRegistry::standard();
    let is_codex_oauth =
        registry.provider_for(provider_id, entry).id() == crate::auth::codex_oauth::CREDENTIAL_KEY;
    if is_codex_oauth && provider_id.eq_ignore_ascii_case("openai-compatible") {
        anyhow::bail!(
            "Codex OAuth cannot be used through the generic `openai-compatible` provider; remove the stale provider entry and select `codex-oauth` in /settings -> Providers."
        );
    }

    let resolved =
        models_fetch::resolve_provider_request_blocking_with_env(provider_id, entry, lookup)?;
    if is_codex_oauth {
        build_chatgpt_model(
            provider_id,
            &resolved,
            model_id,
            timeout,
            hard_timeout_on_stall,
            trusted,
            location,
            quality_rank,
            cost_rank,
            subagent_invokable,
            trusted_only,
            session_redact,
            redact,
        )
    } else if is_anthropic_native(&resolved.base_url) {
        let max_tokens =
            crate::config::providers::validate_anthropic_model_configuration(entry, model_id)?;
        build_anthropic_model(
            provider_id,
            &resolved,
            model_id,
            max_tokens,
            cache,
            timeout,
            hard_timeout_on_stall,
            trusted,
            location,
            quality_rank,
            cost_rank,
            subagent_invokable,
            trusted_only,
            session_redact,
            redact,
        )
    } else {
        build_openai_model_from_resolved(
            provider_id,
            &resolved,
            model_id,
            timeout,
            hard_timeout_on_stall,
            client_side_tools,
            wire_api,
            wire_api_explicit,
            trusted,
            location,
            quality_rank,
            cost_rank,
            subagent_invokable,
            trusted_only,
            session_redact,
            redact,
        )
    }
}

/// Build the native Anthropic [`Model::Anthropic`] from an already-resolved
/// request (api key from the `x-api-key` header, base URL from the resolver).
///
/// **TTL mapping (prompt `prompt-caching-strategy.md`, decisions 2 & 4):**
/// the existing `cache.ttl_secs` lever selects the TTL mode — `>= 3600`
/// (`CacheConfig::wants_one_hour_ttl`) builds the client with the
/// `extended-cache-ttl-2025-04-11` beta header and enables top-level
/// `with_automatic_caching_1h()` (rig 0.37's only 1-hour mechanism; honors
/// the no-serialization-fork rule); anything below enables per-block
/// `with_prompt_caching()` (system prompt + last content block of the last
/// message, 5-min ephemeral). No new config field — `ttl_secs` is the lever.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_anthropic_model(
    provider_id: &str,
    resolved: &models_fetch::ResolvedRequest,
    model_id: &str,
    max_tokens: u64,
    cache: &crate::config::providers::CacheConfig,
    timeout: &crate::config::providers::TimeoutConfig,
    hard_timeout_on_stall: bool,
    trusted: bool,
    location: Option<ModelLocation>,
    quality_rank: i64,
    cost_rank: i64,
    subagent_invokable: bool,
    trusted_only: Arc<AtomicBool>,
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
) -> Result<Model> {
    // The anthropic template carries the key in `x-api-key`
    // (`x-api-key: $ANTHROPIC_API_KEY`), not an `Authorization: Bearer`.
    let api_key = resolved
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("x-api-key"))
        .map(|h| h.value.trim().to_string())
        .filter(|value| !value.is_empty())
        .with_context(|| {
            format!("native Anthropic provider `{provider_id}` is missing required `x-api-key` header/API key")
        })?;

    let one_hour = cache.wants_one_hour_ttl();
    let mut builder = anthropic::Client::builder()
        .api_key(api_key)
        .base_url(&resolved.base_url);
    if one_hour {
        // The 1h extended cache requires the beta header on the client.
        builder = builder.anthropic_beta("extended-cache-ttl-2025-04-11");
    }
    let client = builder
        .build()
        .with_context(|| format!("building anthropic client for `{provider_id}`"))?;

    let completion = client.completion_model(model_id);
    let completion = if one_hour {
        // 1h opt-in: top-level automatic caching (decision 4).
        completion.with_automatic_caching_1h()
    } else {
        // 5-min default: per-block caching (decision 2).
        completion.with_prompt_caching()
    };

    Ok(Model::Anthropic {
        model: completion,
        model_id: model_id.to_string(),
        provider_id: provider_id.to_string(),
        max_tokens,
        base_url: resolved.base_url.clone(),
        timeout: timeout.clone(),
        hard_timeout_on_stall,
        trusted,
        location,
        quality_rank,
        cost_rank,
        subagent_invokable,
        trusted_only,
        // Default never-draining gate; the registry swaps in the daemon's
        // shared gate via `Model::with_shutdown_gate` for worker models.
        gate: crate::daemon::shutdown::ShutdownSignal::new(),
        session_redact,
        redact,
    })
}

/// Build the native ChatGPT/Codex [`Model::ChatGpt`] from Cockpit-resolved
/// OAuth request inputs. This deliberately uses `ChatGPTAuth::AccessToken` so
/// rig never launches its own device flow or reads its auth file; Cockpit's
/// `models_fetch` resolver owns credential refresh and account-id discovery.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_chatgpt_model(
    provider_id: &str,
    resolved: &models_fetch::ResolvedRequest,
    model_id: &str,
    timeout: &crate::config::providers::TimeoutConfig,
    hard_timeout_on_stall: bool,
    trusted: bool,
    location: Option<ModelLocation>,
    quality_rank: i64,
    cost_rank: i64,
    subagent_invokable: bool,
    trusted_only: Arc<AtomicBool>,
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
) -> Result<Model> {
    let access_token = resolved
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("authorization"))
        .and_then(|auth| {
            auth.value
                .strip_prefix("Bearer ")
                .or_else(|| auth.value.strip_prefix("bearer "))
                .map(str::trim)
        })
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .context("Codex OAuth resolved request is missing Authorization bearer token")?;

    let account_id = resolved
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("chatgpt-account-id"))
        .map(|h| h.value.trim().to_string())
        .filter(|value| !value.is_empty())
        .context("Codex OAuth resolved request is missing chatgpt-account-id")?;

    // Rig's ChatGPT provider supplies Authorization, ChatGPT-Account-Id,
    // originator, Accept, Content-Type, and its own per-request session_id.
    // Preserve resolver-owned compatibility headers that rig does not know
    // about, especially the Codex Responses beta opt-in.
    let extra_headers = resolved
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("OpenAI-Beta"))
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();

    let client = chatgpt::Client::builder()
        .api_key(chatgpt::ChatGPTAuth::AccessToken {
            access_token,
            account_id: Some(account_id),
        })
        .base_url(&resolved.base_url)
        .originator("codex_cli_rs")
        // Avoid rig's built-in "You are ChatGPT..." default so Cockpit's
        // system prompt is the only instruction source. An empty default is
        // a no-op when a real preamble is present.
        .default_instructions("")
        .http_client(UsageAliasHttpClient::new(extra_headers))
        .build()
        .with_context(|| format!("building native ChatGPT client for `{provider_id}`"))?;

    Ok(Model::ChatGpt {
        model: chatgpt::ResponsesCompletionModel::new(client, model_id),
        model_id: model_id.to_string(),
        provider_id: provider_id.to_string(),
        base_url: resolved.base_url.clone(),
        timeout: timeout.clone(),
        hard_timeout_on_stall,
        trusted,
        location,
        quality_rank,
        cost_rank,
        subagent_invokable,
        trusted_only,
        gate: crate::daemon::shutdown::ShutdownSignal::new(),
        session_redact,
        redact,
    })
}

/// Resolve `(provider, model)` and build the OpenAI-compat [`Model::OpenAi`]
/// directly, bypassing the [`build_model`] router. Test-only convenience for
/// the keyless / draining-gate tests, which want an OpenAI-compat model
/// without threading a `CacheConfig`. Production code routes through
/// [`build_model`] so native-Anthropic endpoints take the concrete path.
#[cfg(test)]
pub(super) fn build_openai_model(
    provider_id: &str,
    entry: &ProviderEntry,
    model_id: &str,
    redact: Arc<RedactionTable>,
) -> Result<Model> {
    let resolved = models_fetch::resolve_provider_request(provider_id, entry)?;
    build_openai_model_from_resolved(
        provider_id,
        &resolved,
        model_id,
        &crate::config::providers::TimeoutConfig::default(),
        false,
        ClientSideToolsCapability::default(),
        crate::config::providers::WireApi::Auto,
        false,
        false,
        None,
        0,
        0,
        false,
        Arc::new(AtomicBool::new(false)),
        redact.clone(),
        redact,
    )
}

/// Build [`Model::OpenAi`] from an already-resolved request. The router
/// ([`build_model`]) resolves once and dispatches here without re-resolving.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_openai_model_from_resolved(
    provider_id: &str,
    resolved: &models_fetch::ResolvedRequest,
    model_id: &str,
    timeout: &crate::config::providers::TimeoutConfig,
    hard_timeout_on_stall: bool,
    client_side_tools: ClientSideToolsCapability,
    wire_api: crate::config::providers::WireApi,
    wire_api_explicit: bool,
    trusted: bool,
    location: Option<ModelLocation>,
    quality_rank: i64,
    cost_rank: i64,
    subagent_invokable: bool,
    trusted_only: Arc<AtomicBool>,
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
) -> Result<Model> {
    let resolved_wire_api = if !wire_api.is_auto() {
        wire_api
    } else if let Some(learned) =
        learned_working_endpoint(provider_id, model_id, &resolved.base_url)
    {
        learned
    } else {
        crate::config::providers::WireApi::detect_for_provider(provider_id, model_id)
    };
    // A missing Authorization header means the provider is keyless — a
    // fully-local OpenAI-compatible endpoint (e.g. LM Studio at
    // `http://localhost:1234/v1`). That is not an error: the resolver
    // already errors for an Authorization ref whose env var is unset
    // (`models_fetch::resolve_provider_request`), so here absence means
    // "send no auth". Build the client with an empty api key — rig's
    // OpenAI-compat `CompletionsClient` has no dedicated no-key
    // constructor; an empty string is the documented no-auth form (the
    // local endpoint ignores the empty bearer). A remote endpoint that
    // truly needs a key but got none will surface its own 401.
    let token = resolved
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("authorization"))
        .map(|auth| {
            auth.value
                .strip_prefix("Bearer ")
                .or_else(|| auth.value.strip_prefix("bearer "))
                .unwrap_or(&auth.value)
                .trim()
                .to_string()
        })
        .unwrap_or_default();

    // rig appends `/chat/completions` to the base URL (see
    // `OpenAICompletionsExt`'s build_uri). The user's templates put the
    // version segment in the base URL already (e.g. `https://api.minimax.io/v1`),
    // giving the right final URL `https://api.minimax.io/v1/chat/completions`.
    let extra_headers = resolved
        .headers
        .iter()
        .filter(|h| !h.name.eq_ignore_ascii_case("authorization"))
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();

    let client = openai::CompletionsClient::builder()
        .api_key(token)
        .base_url(&resolved.base_url)
        .http_client(UsageAliasHttpClient::new(extra_headers))
        .build()
        .with_context(|| format!("building openai-compatible client for `{provider_id}`"))?;
    Ok(Model::OpenAi {
        client,
        model_id: model_id.to_string(),
        provider_id: provider_id.to_string(),
        wire_api: resolved_wire_api,
        // Set by production build sites via `Model::with_config_path`; absent
        // here so the endpoint fallback's persist is best-effort/skipped for
        // tests + utility models.
        config_path: None,
        wire_api_explicit,
        timeout: timeout.clone(),
        hard_timeout_on_stall,
        client_side_tools,
        trusted,
        location,
        quality_rank,
        cost_rank,
        subagent_invokable,
        trusted_only,
        // Default never-draining gate; the registry swaps in the daemon's
        // shared gate via `Model::with_shutdown_gate` for worker models.
        gate: crate::daemon::shutdown::ShutdownSignal::new(),
        session_redact,
        redact,
    })
}

/// Per-turn knobs the agent loop hands to the model.
#[derive(Debug, Clone, Default)]
pub struct ModelParams {
    pub temperature: Option<f64>,
    pub max_tokens: Option<u64>,
    /// When true, on the first turn force `tool_choice = required` so
    /// the model has to call a tool rather than answer from priors. We
    /// don't use this in v0 (agents may legitimately reply text-only),
    /// but the knob is wired for the future.
    pub tools_required: bool,
    /// Vendor-specific extra-request-body fragment merged into the
    /// outbound chat/completions body in addition to the params cockpit
    /// already sets (implementation note). Resolved
    /// upstream from the active model's typed reasoning capability or legacy
    /// thinking mode — this field is the already-resolved JSON, so the request
    /// builder is fully provider-agnostic. `None` means "send no extra keys"
    /// (every existing provider's request is unchanged). The fragment supplies
    /// vendor keys only; cockpit's own keys are stripped from it before the
    /// merge so it can never clobber them.
    pub additional_params: Option<serde_json::Value>,
    /// Top-level `prompt_cache_key` for OpenAI-compatible backends
    /// (prompt `prompt-caching-strategy.md`, decision 3) — the session id,
    /// held constant for the session so the backend's per-key prefix cache
    /// (OpenAI Responses, GitHub Copilot, …) keeps hitting. Ignored by
    /// backends that don't honor it; zero risk. Set **only** on the main
    /// session worker's foreground model; background/utility models leave it
    /// `None`. The native Anthropic arm ignores it entirely (it uses
    /// provider-concrete per-block caching instead).
    pub prompt_cache_key: Option<String>,
}

/// Build a `rig::agent::Agent` (we only use its `.completion()` builder,
/// not its `.prompt()` convenience layer). The construction is identical
/// across providers; only the client type differs, so this lives here
/// rather than in each variant.
///
/// `AgentBuilder` is type-stated — `.tool()` transitions from
/// `NoToolConfig` to `WithBuilderTools`, which is why we use the plural
/// `.tools()` (accepts `Vec<Box<dyn ToolDyn>>`) so the transition is one
/// step and we don't have to reassign across types.
pub(super) fn build_agent<C: CompletionClient>(
    client: &C,
    model_id: &str,
    system: &str,
    tools: &[ToolDefinition],
    params: &ModelParams,
) -> rig::agent::Agent<C::CompletionModel> {
    let boxed: Vec<Box<dyn rig::tool::ToolDyn>> = tools
        .iter()
        .map(|def| Box::new(StaticTool(def.clone())) as Box<dyn rig::tool::ToolDyn>)
        .collect();
    let mut b = client.agent(model_id).preamble(system).tools(boxed);
    if let Some(t) = params.temperature {
        b = b.temperature(t);
    }
    if let Some(m) = params.max_tokens {
        b = b.max_tokens(m);
    }
    // Vendor reasoning controls (and any other config-driven extra body
    // params) ride through rig's `additional_params`, which serializes
    // `#[serde(flatten)]` into the chat/completions body — so the fragment's
    // keys land flat alongside `model`/`messages`/`temperature`, exactly the
    // shape the vendor expects. We strip cockpit-owned keys first so the
    // fragment can only ever add vendor keys, never override the
    // temperature/max_tokens/messages/tools cockpit already set. The
    // `prompt_cache_key` (decision 3) is injected on top for the OpenAI arm
    // so the session id rides the body as a top-level key.
    if let Some(extra) = openai_additional_params(params) {
        b = b.additional_params(extra);
    }
    b.build()
}

/// Compose the OpenAI-compat outbound `additional_params` object: the
/// sanitized vendor reasoning fragment plus, when set, the top-level
/// `prompt_cache_key` (= session id, prompt `prompt-caching-strategy.md`
/// decision 3). `prompt_cache_key` is not a cockpit-owned request key, so it
/// survives sanitization, but we inject it explicitly rather than relying on
/// the user's fragment. Returns `None` when there is nothing to add, so
/// providers with no extra params and no cache key stay byte-for-byte
/// unchanged.
pub(super) fn openai_additional_params(params: &ModelParams) -> Option<serde_json::Value> {
    let vendor = sanitized_extra_params(params.additional_params.as_ref());
    let Some(key) = params.prompt_cache_key.as_ref().filter(|k| !k.is_empty()) else {
        return vendor;
    };
    // Merge the cache key into the vendor object (or start a fresh object).
    let mut map = match vendor {
        Some(serde_json::Value::Object(m)) => m,
        // A non-object vendor fragment is a shape the config author chose; we
        // don't silently rewrite it, so the cache key can't be merged in —
        // keep the vendor fragment as-is (the cache key is best-effort).
        Some(other) => return Some(other),
        None => serde_json::Map::new(),
    };
    map.insert(
        "prompt_cache_key".to_string(),
        serde_json::Value::String(key.clone()),
    );
    Some(serde_json::Value::Object(map))
}

/// Build a native-Anthropic `rig::agent::Agent` from the pre-built,
/// caching-enabled [`anthropic::completion::CompletionModel`]. Mirrors
/// [`build_agent`]
/// but wraps the concrete model with `AgentBuilder::new` so the model's
/// `with_prompt_caching` / `with_automatic_caching_1h` flags are preserved.
/// Re-built every attempt, so the per-block last-message cache marker
/// re-applies over the grown history each turn. The `prompt_cache_key`
/// (OpenAI-only) is intentionally **not** forwarded here — Anthropic uses
/// provider-concrete per-block caching, not a top-level key.
pub(super) fn build_anthropic_agent(
    model: anthropic::completion::CompletionModel,
    system: &str,
    tools: &[ToolDefinition],
    params: &ModelParams,
) -> rig::agent::Agent<anthropic::completion::CompletionModel> {
    let boxed: Vec<Box<dyn rig::tool::ToolDyn>> = tools
        .iter()
        .map(|def| Box::new(StaticTool(def.clone())) as Box<dyn rig::tool::ToolDyn>)
        .collect();
    let mut b = rig::agent::AgentBuilder::new(model)
        .preamble(system)
        .tools(boxed);
    if let Some(t) = params.temperature {
        b = b.temperature(t);
    }
    if let Some(m) = params.max_tokens {
        b = b.max_tokens(m);
    }
    if let Some(extra) = sanitized_extra_params(params.additional_params.as_ref()) {
        b = b.additional_params(extra);
    }
    b.build()
}

/// Build a native ChatGPT/Codex `rig::agent::Agent` from the pre-built
/// [`ChatGptResponsesModel`]. This mirrors [`build_anthropic_agent`] because
/// the native model is already constructed with Cockpit-resolved OAuth
/// credentials and must not go back through a client/model-id factory.
pub(super) fn build_chatgpt_agent(
    model: ChatGptResponsesModel,
    system: &str,
    tools: &[ToolDefinition],
    params: &ModelParams,
) -> rig::agent::Agent<ChatGptResponsesModel> {
    let boxed: Vec<Box<dyn rig::tool::ToolDyn>> = tools
        .iter()
        .map(|def| Box::new(StaticTool(def.clone())) as Box<dyn rig::tool::ToolDyn>)
        .collect();
    let mut b = rig::agent::AgentBuilder::new(model)
        .preamble(system)
        .tools(boxed);
    if let Some(t) = params.temperature {
        b = b.temperature(t);
    }
    if let Some(m) = params.max_tokens {
        b = b.max_tokens(m);
    }
    if let Some(extra) = sanitized_extra_params(params.additional_params.as_ref()) {
        b = b.additional_params(extra);
    }
    b.build()
}

struct StaticTool(ToolDefinition);

#[derive(Debug, thiserror::Error)]
#[error("StaticTool::call should never be invoked — cockpit dispatches through ToolBox")]
struct StaticToolError;

impl rig::tool::Tool for StaticTool {
    const NAME: &'static str = "static-cockpit-tool";

    type Error = StaticToolError;
    type Args = serde_json::Value;
    type Output = String;

    fn name(&self) -> String {
        self.0.name.clone()
    }

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        self.0.clone()
    }

    async fn call(&self, _args: Self::Args) -> Result<Self::Output, Self::Error> {
        Err(StaticToolError)
    }
}
