use super::*;
use rig::providers::{anthropic, chatgpt, openai};

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

    pub fn from_config_with_env<F>(
        cfg: &ProvidersConfig,
        redact: Arc<RedactionTable>,
        lookup: F,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String> + Send + Sync,
    {
        Self::from_config_with_sources(cfg, redact, lookup, |_| None, None)
    }

    pub fn from_config_with_store<F>(
        cfg: &ProvidersConfig,
        redact: Arc<RedactionTable>,
        lookup: F,
        store: crate::credentials::CredentialStore,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String> + Send + Sync,
    {
        let secret_lookup = {
            let store = store.clone();
            move |name: &str| store.named_secret(name).map(str::to_string)
        };
        Self::from_config_with_sources(cfg, redact, lookup, secret_lookup, Some(store))
    }

    pub fn from_config_with_sources<F, S>(
        cfg: &ProvidersConfig,
        redact: Arc<RedactionTable>,
        lookup: F,
        secret_lookup: S,
        store: Option<crate::credentials::CredentialStore>,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String> + Send + Sync,
        S: Fn(&str) -> Option<String>,
    {
        let active: &ActiveModelRef = cfg.active_model.as_ref().context(
            "no active model selected — run /model or set COCKPIT_PROVIDER/COCKPIT_MODEL",
        )?;
        let entry = cfg
            .providers
            .get(&active.provider)
            .with_context(|| format!("provider `{}` is not configured", active.provider))?;
        // Route through the typed policy API before constructing the model.
        // The route supplies an enforced egress table for every trust level;
        // trust itself remains model metadata for capture/write policy.
        let custody_route =
            Self::configured_custody_route(cfg, &active.provider, &active.model, &redact).map_err(
                |error| {
                    anyhow::anyhow!(
                        "cannot route custody for active model `{}:{}`: {error}",
                        active.provider,
                        active.model
                    )
                },
            )?;
        let trusted = cfg
            .resolve_trust(&active.provider, &active.model)
            .is_trusted();
        let cache = cfg.resolve_cache(&active.provider, &active.model);
        let timeout = cfg.resolve_timeout(&active.provider, &active.model);
        let hard_timeout_on_stall = true;
        let wire_api = cfg.resolve_wire_api(&active.provider, &active.model);
        let wire_api_explicit = cfg.is_wire_api_explicit(&active.provider, &active.model);
        let client_side_tools =
            cfg.resolve_effective_client_side_tools(&active.provider, &active.model);
        let location = cfg.resolve_location(&active.provider, &active.model);
        let quality_rank = cfg.resolve_quality_rank(&active.provider, &active.model);
        let cost_rank = cfg.resolve_cost_rank(&active.provider, &active.model);
        let subagent_invokable = cfg.resolve_subagent_invokable(&active.provider, &active.model);
        let can_delegate = cfg.resolve_can_delegate(&active.provider, &active.model);
        let computer_use = cfg
            .resolve_effective_model_capabilities(
                &active.provider,
                &active.model,
                cfg.resolution_generation,
            )
            .computer_use;
        let effective_redact = Self::effective_redact_table_for(
            &custody_route,
            &active.provider,
            &active.model,
            redact.clone(),
        );
        build_model_with_can_delegate(
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
            can_delegate,
            computer_use,
            redact,
            effective_redact,
            lookup,
            secret_lookup,
            store,
        )
    }
    /// Build a `Model` from a `"provider:model-id"` reference, erroring on
    /// a missing colon. Thin wrapper over [`Self::for_provider`] for the
    /// utility-model call sites. `redact` is the caller's effective
    /// redaction table (the session's table for in-session utility calls;
    /// a `RedactConfig`+cwd-built table for out-of-session ones).
    #[allow(dead_code)]
    /// LIMITATION (command-backed-secret-refs-daemon inc2): this utility-model
    /// constructor resolves through [`Self::for_provider`] →
    /// [`Self::for_provider_with_env`], which supplies NO credential store and a
    /// `|_| None` secret lookup. The provider entry and its headers are still
    /// consumed, but any `$secret:` header reference — LITERAL or COMMAND-backed
    /// — simply fails to expand, because there is no store to resolve it against.
    /// This is an UNSUPPORTED path for secret-bearing headers, not an enforced
    /// invariant: callers that build a utility model this way (auto-title,
    /// prompt-injection guard, predict/preflight/translate, safety-gate, harness
    /// summarization, skill auto-select) get an unexpanded header rather than a
    /// resolved one. Command-backed secrets share exactly the pre-existing
    /// behavior of literal named secrets here, so this is out of inc2's scope,
    /// not a regression. Foreground/session and DocsAsk models (which DO expand
    /// headers) go through the store-bearing `from_config_with_store` /
    /// `for_provider_with_store` paths, where the `Session` store funnel injects
    /// resolved command outputs.
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

    pub fn for_provider_optional_store(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        redact: Arc<RedactionTable>,
        store: Option<crate::credentials::CredentialStore>,
    ) -> Result<Self> {
        match store {
            Some(store) => Self::for_provider_with_store(
                cfg,
                provider_id,
                model_id,
                redact,
                |name| std::env::var(name).ok(),
                store,
            ),
            None => Self::for_provider(cfg, provider_id, model_id, redact),
        }
    }

    pub fn for_provider_with_env<F>(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        redact: Arc<RedactionTable>,
        lookup: F,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String> + Send + Sync,
    {
        Self::for_provider_with_sources(cfg, provider_id, model_id, redact, lookup, |_| None, None)
    }

    pub fn for_provider_with_store<F>(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        redact: Arc<RedactionTable>,
        lookup: F,
        store: crate::credentials::CredentialStore,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String> + Send + Sync,
    {
        let secret_lookup = {
            let store = store.clone();
            move |name: &str| store.named_secret(name).map(str::to_string)
        };
        Self::for_provider_with_sources(
            cfg,
            provider_id,
            model_id,
            redact,
            lookup,
            secret_lookup,
            Some(store),
        )
    }

    pub fn for_provider_with_sources<F, S>(
        cfg: &ProvidersConfig,
        provider_id: &str,
        model_id: &str,
        redact: Arc<RedactionTable>,
        lookup: F,
        secret_lookup: S,
        store: Option<crate::credentials::CredentialStore>,
    ) -> Result<Self>
    where
        F: Fn(&str) -> Option<String> + Send + Sync,
        S: Fn(&str) -> Option<String>,
    {
        let entry = cfg
            .providers
            .get(provider_id)
            .with_context(|| format!("provider `{provider_id}` is not configured"))?;
        // Utility/background targets use the same typed route and enforced
        // egress table as foreground completions.
        let custody_route = Self::configured_custody_route(cfg, provider_id, model_id, &redact)
            .map_err(|error| {
                anyhow::anyhow!("cannot route custody for `{provider_id}:{model_id}`: {error}")
            })?;
        let trusted = cfg.resolve_trust(provider_id, model_id).is_trusted();
        let cache = cfg.resolve_cache(provider_id, model_id);
        let timeout = cfg.resolve_timeout(provider_id, model_id);
        let hard_timeout_on_stall = true;
        let wire_api = cfg.resolve_wire_api(provider_id, model_id);
        let wire_api_explicit = cfg.is_wire_api_explicit(provider_id, model_id);
        let client_side_tools = cfg.resolve_effective_client_side_tools(provider_id, model_id);
        let location = cfg.resolve_location(provider_id, model_id);
        let quality_rank = cfg.resolve_quality_rank(provider_id, model_id);
        let cost_rank = cfg.resolve_cost_rank(provider_id, model_id);
        let subagent_invokable = cfg.resolve_subagent_invokable(provider_id, model_id);
        let can_delegate = cfg.resolve_can_delegate(provider_id, model_id);
        let computer_use = cfg
            .resolve_effective_model_capabilities(provider_id, model_id, cfg.resolution_generation)
            .computer_use;
        let effective_redact =
            Self::effective_redact_table_for(&custody_route, provider_id, model_id, redact.clone());
        build_model_with_can_delegate(
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
            can_delegate,
            computer_use,
            redact,
            effective_redact,
            lookup,
            secret_lookup,
            store,
        )
    }
}

/// Route a `(provider, model)` build solely from its resolved `wire_api`.
/// When the provider enables Anthropic prompt caching, the `cache` config
/// drives its TTL mode (5-min vs 1h). It is unused on the OpenAI-compatible
/// path, which relies on prefix stability plus `prompt_cache_key`, set later
/// via `ModelParams`.
#[cfg(test)]
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
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
    lookup: impl Fn(&str) -> Option<String> + Send + Sync,
) -> Result<Model> {
    build_model_with_can_delegate(
        provider_id,
        entry,
        model_id,
        cache,
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
        true,
        None,
        session_redact,
        redact,
        lookup,
        |_| None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_model_with_can_delegate(
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
    can_delegate: bool,
    computer_use: Option<crate::config::providers::ComputerUseCapability>,
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
    lookup: impl Fn(&str) -> Option<String> + Send + Sync,
    secret_lookup: impl Fn(&str) -> Option<String>,
    store: Option<crate::credentials::CredentialStore>,
) -> Result<Model> {
    let resolved = match store {
        Some(store) => models_fetch::resolve_provider_request_blocking_with_store(
            provider_id,
            entry,
            lookup,
            store,
        )?,
        None => models_fetch::resolve_provider_request_blocking_with_sources(
            provider_id,
            entry,
            lookup,
            secret_lookup,
        )?,
    };
    let utility_token_limit = resolve_utility_token_limit(entry, model_id);
    match wire_api {
        crate::config::providers::WireApi::Responses if resolved.is_codex_credential => {
            build_chatgpt_model_with_utility_limit(
                provider_id,
                &resolved,
                true,
                model_id,
                utility_token_limit,
                timeout,
                hard_timeout_on_stall,
                trusted,
                location,
                quality_rank,
                cost_rank,
                subagent_invokable,
                can_delegate,
                session_redact,
                redact,
            )
        }
        // Responses is a wire choice, not a Codex credential. Third-party
        // Bearer providers use the generic OpenAI client and its `/responses`
        // serializer; only the Codex credential may select `Model::ChatGpt`.
        crate::config::providers::WireApi::Responses => {
            build_openai_model_from_resolved_with_utility_limit_and_can_delegate(
                provider_id,
                &resolved,
                model_id,
                utility_token_limit,
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
                can_delegate,
                session_redact,
                redact,
            )
        }
        crate::config::providers::WireApi::Anthropic => {
            let max_tokens =
                crate::config::providers::validate_anthropic_model_configuration(entry, model_id)?;
            let anthropic_features = entry.effective_anthropic_features();
            build_anthropic_model_with_can_delegate(
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
                can_delegate,
                computer_use.as_ref(),
                &anthropic_features,
                session_redact,
                redact,
            )
        }
        crate::config::providers::WireApi::Completions => {
            build_openai_model_from_resolved_with_utility_limit_and_can_delegate(
                provider_id,
                &resolved,
                model_id,
                utility_token_limit,
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
                can_delegate,
                session_redact,
                redact,
            )
        }
        crate::config::providers::WireApi::Auto => {
            anyhow::bail!("effective wire_api must not be auto")
        }
    }
}

fn resolve_utility_token_limit(entry: &ProviderEntry, model_id: &str) -> Option<u64> {
    let model = entry.models.iter().find(|model| model.id == model_id);
    let caps = model.map(|model| &model.capabilities);
    let overrides = model.map(|model| &model.capability_overrides);
    let max_output = overrides
        .and_then(|caps| caps.max_output_tokens)
        .or_else(|| caps.and_then(|caps| caps.max_output_tokens))
        .or(entry.capabilities.max_output_tokens);
    let context = overrides
        .and_then(|caps| caps.context_tokens)
        .or_else(|| caps.and_then(|caps| caps.context_tokens))
        .or(entry.capabilities.context_tokens)
        .or_else(|| model.and_then(|model| model.context_length));
    [max_output, context]
        .into_iter()
        .flatten()
        .filter(|value| *value > 0)
        .map(u64::from)
        .min()
}

/// Build the native Anthropic [`Model::Anthropic`] from an already-resolved
/// request. Provider configuration may supply either `x-api-key` or
/// `Authorization: Bearer` authentication.
///
/// **TTL mapping (prompt `prompt-caching-strategy.md`, decisions 2 & 4):**
/// the existing `cache.ttl_secs` lever selects the TTL mode — `>= 3600`
/// (`CacheConfig::wants_one_hour_ttl`) builds the client with the
/// `extended-cache-ttl-2025-04-11` beta header and enables top-level
/// `with_automatic_caching_1h()` (rig's 1-hour mechanism; honors the
/// no-serialization-fork rule); anything below enables per-block
/// `with_prompt_caching()` (system prompt + last content block of the last
/// message, 5-min ephemeral). The provider's explicit Anthropic feature gate
/// controls whether either form, and the required beta header, is emitted.
#[cfg(test)]
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
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
) -> Result<Model> {
    build_anthropic_model_with_can_delegate(
        provider_id,
        resolved,
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
        true,
        None,
        &crate::config::providers::AnthropicFeatures::first_party(),
        session_redact,
        redact,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_anthropic_model_with_can_delegate(
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
    can_delegate: bool,
    computer_use: Option<&crate::config::providers::ComputerUseCapability>,
    anthropic_features: &crate::config::providers::AnthropicFeatures,
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
) -> Result<Model> {
    let x_api_key = resolved
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("x-api-key"))
        .map(|h| h.value.trim().to_string())
        .filter(|value| !value.is_empty());
    let bearer_auth = resolved
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("authorization"))
        .map(|h| h.value.trim())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let (api_key, uses_bearer_auth) = match (x_api_key, bearer_auth) {
        // Preserve the first-party x-api-key behavior when both headers are
        // present on an existing provider.
        (Some(api_key), _) => (api_key, false),
        // Rig requires an API key even though it is removed at the custom
        // HTTP-client boundary before this request reaches the gateway.
        (None, Some(_)) => ("flycockpit-anthropic-bearer-placeholder".to_string(), true),
        (None, None) => anyhow::bail!(
            "native Anthropic provider `{provider_id}` requires `x-api-key` or `Authorization: Bearer <token>`"
        ),
    };

    let prompt_caching = anthropic_features.prompt_caching;
    // Rig's 1-hour cache-control form requires the extended-cache beta. A
    // provider may opt into portable 5-minute caching without beta support.
    let one_hour = prompt_caching && anthropic_features.betas && cache.wants_one_hour_ttl();
    let mut builder = anthropic::Client::builder()
        .api_key(api_key)
        .base_url(&resolved.base_url);
    if one_hour {
        // The 1h extended cache requires the beta header on the client.
        builder = builder.anthropic_beta("extended-cache-ttl-2025-04-11");
    }
    if anthropic_features.betas {
        if let Some(contract) = computer_use.and_then(|capability| capability.contract) {
            builder = match contract {
                crate::config::providers::ComputerUseContract::Anthropic20251124 => {
                    builder.anthropic_beta("computer-use-2025-11-24")
                }
                crate::config::providers::ComputerUseContract::Anthropic20250124 => {
                    builder.anthropic_beta("computer-use-2025-01-24")
                }
                crate::config::providers::ComputerUseContract::OpenAiResponses => builder,
            };
        }
    }
    let extra_headers = resolved
        .headers
        .iter()
        // Rig owns the x-api-key it builds from above. All other headers,
        // including Bearer Authorization, go through the custom HTTP client,
        // which removes Rig's synthetic x-api-key for the Bearer path.
        // `anthropic-beta` is a native Anthropic extension, so configured
        // headers must obey the same explicit provider gate as headers Rig
        // generates for caching and computer-use.
        .filter(|h| {
            !h.name.eq_ignore_ascii_case("x-api-key")
                && (anthropic_features.betas || !h.name.eq_ignore_ascii_case("anthropic-beta"))
        })
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();
    let http_client = if uses_bearer_auth {
        UsageAliasHttpClient::for_anthropic_bearer(extra_headers)?
    } else {
        UsageAliasHttpClient::new(extra_headers)?
    };
    let client = builder
        .http_client(http_client)
        .build()
        .with_context(|| format!("building anthropic client for `{provider_id}`"))?;

    let completion = client.completion_model(model_id);
    let completion = if !prompt_caching {
        completion
    } else if one_hour {
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
        #[cfg(not(test))]
        command_credential_generation: resolved.command_credential_generation,
        max_tokens,
        base_url: resolved.base_url.clone(),
        timeout: timeout.clone(),
        hard_timeout_on_stall,
        trusted,
        location,
        quality_rank,
        cost_rank,
        subagent_invokable,
        can_delegate,
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
#[cfg(test)]
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
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
) -> Result<Model> {
    build_chatgpt_model_with_utility_limit(
        provider_id,
        resolved,
        resolved.is_codex_credential,
        model_id,
        None,
        timeout,
        hard_timeout_on_stall,
        trusted,
        location,
        quality_rank,
        cost_rank,
        subagent_invokable,
        true,
        session_redact,
        redact,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_chatgpt_model_with_utility_limit(
    provider_id: &str,
    resolved: &models_fetch::ResolvedRequest,
    is_codex_credential: bool,
    model_id: &str,
    utility_token_limit: Option<u64>,
    timeout: &crate::config::providers::TimeoutConfig,
    hard_timeout_on_stall: bool,
    trusted: bool,
    location: Option<ModelLocation>,
    quality_rank: i64,
    cost_rank: i64,
    subagent_invokable: bool,
    can_delegate: bool,
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
        .context("Responses provider resolved request is missing Authorization bearer token")?;

    let account_id = if is_codex_credential {
        Some(
            resolved
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("chatgpt-account-id"))
                .map(|h| h.value.trim().to_string())
                .filter(|value| !value.is_empty())
                .context("Codex OAuth resolved request is missing chatgpt-account-id")?,
        )
    } else {
        None
    };

    // Rig's ChatGPT provider supplies Responses serialization. Codex
    // credential resolution adds its account and compatibility headers; a
    // non-Codex Responses provider keeps only its configured request headers.
    let extra_headers = resolved
        .headers
        .iter()
        // `session_id` is deliberately left to Rig, which generates a new
        // request identifier for every request. A resolver-owned value would
        // otherwise overwrite that per-request identifier.
        .filter(|h| {
            !h.name.eq_ignore_ascii_case("authorization")
                && !h.name.eq_ignore_ascii_case("session_id")
        })
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();

    let client = chatgpt::Client::builder()
        .api_key(chatgpt::ChatGPTAuth::AccessToken {
            access_token,
            account_id,
        })
        .base_url(&resolved.base_url)
        .originator("cockpit")
        // Avoid rig's built-in "You are ChatGPT..." default so Cockpit's
        // system prompt is the only instruction source. An empty default is
        // a no-op when a real preamble is present.
        .default_instructions("")
        .http_client(if is_codex_credential {
            UsageAliasHttpClient::new(extra_headers)?
        } else {
            UsageAliasHttpClient::without_codex_headers(extra_headers)?
        })
        .build()
        .with_context(|| format!("building Responses client for `{provider_id}`"))?;

    Ok(Model::ChatGpt {
        model: chatgpt::ResponsesCompletionModel::new(client, model_id).with_strict_tools(),
        model_id: model_id.to_string(),
        provider_id: provider_id.to_string(),
        #[cfg(not(test))]
        command_credential_generation: resolved.command_credential_generation,
        utility_token_limit,
        base_url: resolved.base_url.clone(),
        timeout: timeout.clone(),
        hard_timeout_on_stall,
        trusted,
        location,
        quality_rank,
        cost_rank,
        subagent_invokable,
        can_delegate,
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
    build_openai_model_from_resolved_with_utility_limit(
        provider_id,
        &resolved,
        model_id,
        resolve_utility_token_limit(entry, model_id),
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
        redact.clone(),
        redact,
    )
}

/// Build [`Model::OpenAi`] from an already-resolved request. The router
/// ([`build_model`]) resolves once and dispatches here without re-resolving.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
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
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
) -> Result<Model> {
    build_openai_model_from_resolved_with_utility_limit_and_can_delegate(
        provider_id,
        resolved,
        model_id,
        None,
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
        true,
        session_redact,
        redact,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(super) fn build_openai_model_from_resolved_with_utility_limit(
    provider_id: &str,
    resolved: &models_fetch::ResolvedRequest,
    model_id: &str,
    utility_token_limit: Option<u64>,
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
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
) -> Result<Model> {
    build_openai_model_from_resolved_with_utility_limit_and_can_delegate(
        provider_id,
        resolved,
        model_id,
        utility_token_limit,
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
        true,
        session_redact,
        redact,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_openai_model_from_resolved_with_utility_limit_and_can_delegate(
    provider_id: &str,
    resolved: &models_fetch::ResolvedRequest,
    model_id: &str,
    utility_token_limit: Option<u64>,
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
    can_delegate: bool,
    session_redact: Arc<RedactionTable>,
    redact: Arc<RedactionTable>,
) -> Result<Model> {
    let resolved_wire_api = if wire_api.is_auto() {
        crate::config::providers::WireApi::Completions
    } else {
        wire_api
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

    // A `CompletionsClient` can recover between the Chat Completions and
    // Responses endpoints without being rebuilt. Keep the generic client
    // fenced for its whole lifetime instead of tying the header policy to its
    // initially resolved endpoint. The policy filters Codex subscription
    // headers whenever this generic client selects `/responses`.
    let http_client = UsageAliasHttpClient::without_codex_headers(extra_headers)?;
    let client = openai::CompletionsClient::builder()
        .api_key(token)
        .base_url(&resolved.base_url)
        .http_client(http_client)
        .build()
        .with_context(|| format!("building openai-compatible client for `{provider_id}`"))?;
    Ok(Model::OpenAi {
        client,
        model_id: model_id.to_string(),
        provider_id: provider_id.to_string(),
        #[cfg(not(test))]
        command_credential_generation: resolved.command_credential_generation,
        utility_token_limit,
        wire_api: resolved_wire_api,
        // Set by production build sites via `Model::with_config_path`; absent
        // here so the endpoint fallback's persist is best-effort/skipped for
        // tests + utility models.
        config_path: None,
        live_wire_api: Arc::new(Mutex::new(LiveWireApiState::new(wire_api_explicit))),
        timeout: timeout.clone(),
        hard_timeout_on_stall,
        client_side_tools,
        trusted,
        location,
        quality_rank,
        cost_rank,
        subagent_invokable,
        can_delegate,
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
    /// Optional completion length bound. On Anthropic native, a missing value
    /// is filled from the model's resolved limit before dispatch. On OpenAI-
    /// compatible endpoints (including Ollama), `None` is left as omission so
    /// the provider applies its own default: rig 0.42 maps a present
    /// `max_tokens` to Ollama `options.num_predict` and enforces it. Utility
    /// paths always set an explicit cap via [`UTILITY_MAX_TOKENS_CAP`].
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
    /// The alternate vendor fragment for OpenAI endpoint routing. This is
    /// populated alongside catalog-derived reasoning controls so an
    /// endpoint-scoped Responses mapping is omitted on Chat Completions both
    /// during recovery and on later turns after that endpoint is persisted.
    /// Endpoint-agnostic mappings supply the same value for both routes.
    /// Hand-authored `additional_params` leave this unset and are retained on
    /// either endpoint.
    pub endpoint_recovery_additional_params: Option<EndpointRecoveryAdditionalParams>,
    /// Top-level `prompt_cache_key` for OpenAI-compatible backends
    /// (prompt `prompt-caching-strategy.md`, decision 3) — the session id,
    /// held constant for the session so the backend's per-key prefix cache
    /// (OpenAI Responses, GitHub Copilot, …) keeps hitting. Ignored by
    /// backends that don't honor it; zero risk. Set **only** on the main
    /// session worker's foreground model; background/utility models leave it
    /// `None`. The Anthropic Messages-wire arm ignores it entirely because
    /// that wire has no top-level cache-key field.
    pub prompt_cache_key: Option<String>,
    /// Opaque provider-defined prompt-cache retention policy for
    /// OpenAI-compatible backends, such as OpenAI's `"24h"`. `None` is the
    /// default and sends no retention key, so existing request bodies are
    /// unchanged. When set to a non-empty value, the OpenAI-compatible
    /// additional-params composition passes it through verbatim; native
    /// Anthropic ignores it because its Messages wire has no top-level cache
    /// key, whether or not provider-configured prompt caching is enabled.
    pub prompt_cache_retention: Option<String>,
    /// Provider-native computer-use tool overlay. This stays `None` by default;
    /// the gating prompt is responsible for attaching it only to approved
    /// computer-use subagent turns.
    pub native_computer: Option<crate::computer::NativeComputerToolConfig>,
}

impl ModelParams {
    /// Drop an inherited native-computer advertisement. Scheduled-loop forks,
    /// caged background reviews, and other paths that do not own a coordinator
    /// must not re-advertise a parent/root's opened geometry — that is the
    /// advertised-but-inert failure open-before-advertise exists to prevent.
    pub(crate) fn detach_inherited_native_computer(&mut self) {
        self.native_computer = None;
    }

    /// Select the catalog-derived vendor fragment for the endpoint that will
    /// actually receive this request. Endpoint recovery is persisted on the
    /// model, while a session's [`ModelParams`] are intentionally long-lived,
    /// so this selection must happen at dispatch time rather than only on the
    /// one recovery retry.
    pub fn additional_params_for_wire(
        &self,
        wire_api: crate::config::providers::WireApi,
    ) -> Option<serde_json::Value> {
        match &self.endpoint_recovery_additional_params {
            Some(recovery) if wire_api != recovery.primary_wire_api => recovery.alternate.clone(),
            Some(_) | None => self.additional_params.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EndpointRecoveryAdditionalParams {
    /// Endpoint for which [`ModelParams::additional_params`] was resolved.
    /// The alternate fragment is selected whenever dispatch uses its opposite,
    /// including turns after a successful endpoint recovery was persisted.
    pub primary_wire_api: crate::config::providers::WireApi,
    pub alternate: Option<serde_json::Value>,
}

/// Utility/non-streaming model dispatch budget and override seam.
///
/// The enum deliberately names each production utility purpose instead of
/// letting call sites pick raw durations or params. Compatibility wrappers use
/// `AdHocBackground`; new production call sites should use a concrete variant.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtilityCallSite {
    AutoTitle,
    Predict,
    Translate,
    SkillAutoSelect,
    HarnessSummary,
    SafetyGate,
    InjectionCheck,
    PreflightRewrite,
    CompactionBrief,
    DelegationShrink,
    /// A redacted low-risk AgentTree decision routed through the daemon's
    /// installed resolver model. This is deliberately separate from ad-hoc
    /// background work so its timeout/custody boundary remains auditable.
    AgentTreeDecision,
    /// One observed-hit-gated, non-mutating prompt-cache refresh during a
    /// user's idle window.
    KeepWarm,
    /// The leak-report trusted-child acquisition child turn (2c-3b). A
    /// non-persisting utility completion: the sensitive acquisition dispatch
    /// runs here rather than through the turn runner so the child's raw output
    /// never reaches a durable session event or stream.
    TrustedChildAcquisition,
    /// ArtifactWrite variant generator (verification profiles). Turn-blocking.
    VerificationVariant,
    /// ArtifactWrite adjudicator (verification profiles). Turn-blocking;
    /// temperature is pinned to 0.
    VerificationAdjudication,
    AdHocBackground,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtilityBudgetClass {
    TurnBlocking,
    Background,
}

/// Generous enough for the largest legitimate utility output (the compaction
/// handoff brief) while bounding runaway utility completions.
pub const UTILITY_MAX_TOKENS_CAP: u64 = 4_096;
pub const UTILITY_TURN_BLOCKING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
pub const UTILITY_BACKGROUND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl UtilityCallSite {
    pub fn budget_class(self) -> UtilityBudgetClass {
        match self {
            Self::SafetyGate
            | Self::InjectionCheck
            | Self::PreflightRewrite
            | Self::CompactionBrief
            | Self::DelegationShrink
            | Self::VerificationVariant
            | Self::VerificationAdjudication => UtilityBudgetClass::TurnBlocking,
            Self::AutoTitle
            | Self::Predict
            | Self::Translate
            | Self::SkillAutoSelect
            | Self::HarnessSummary
            | Self::TrustedChildAcquisition
            | Self::AgentTreeDecision
            | Self::KeepWarm
            | Self::AdHocBackground => UtilityBudgetClass::Background,
        }
    }

    pub fn timeout(self) -> std::time::Duration {
        match self.budget_class() {
            UtilityBudgetClass::TurnBlocking => UTILITY_TURN_BLOCKING_TIMEOUT,
            UtilityBudgetClass::Background => UTILITY_BACKGROUND_TIMEOUT,
        }
    }

    pub fn pins_temperature_zero(self) -> bool {
        matches!(
            self,
            Self::SafetyGate | Self::InjectionCheck | Self::VerificationAdjudication
        )
    }
}

/// The raw Rig request builder owns provider transport serialization; Cockpit
/// owns the conversation transcript, tool definitions, and completion-request
/// assembly. No Rig agent APIs participate in this path.
pub(super) fn build_completion_model<C: CompletionClient>(
    client: &C,
    model_id: &str,
) -> C::CompletionModel {
    client.completion_model(model_id)
}

/// Build a raw OpenAI Responses completion model with strict tool schemas.
/// Request-level system messages, tools, parameters, and additional parameters
/// belong on its `completion_request` builder.
pub(super) fn build_openai_responses_completion_model(
    client: openai::Client<UsageAliasHttpClient>,
    model_id: &str,
) -> openai::responses_api::ResponsesCompletionModel<UsageAliasHttpClient> {
    openai::responses_api::ResponsesCompletionModel::new(client, model_id).with_strict_tools()
}

/// Return the pre-built Anthropic Messages-wire completion model. Its optional
/// caching mode is selected while constructing the provider client above;
/// request-specific system messages, tools, and parameters are configured through
/// `CompletionModel::completion_request`.
pub(super) fn build_anthropic_completion_model(
    model: AnthropicCompletionModel,
) -> AnthropicCompletionModel {
    model
}

/// Return the pre-built native ChatGPT/Codex Responses model with strict tool
/// schemas. Request-specific system messages, tools, and parameters are
/// configured through `CompletionModel::completion_request`.
pub(super) fn build_chatgpt_completion_model(
    model: ChatGptResponsesModel,
) -> ChatGptResponsesModel {
    model.with_strict_tools()
}

/// Compose the OpenAI-compat outbound `additional_params` object. rig >=0.40
/// deserializes this JSON fragment into its typed Responses
/// `AdditionalParameters` (PR #1830), so this is rig's native channel for
/// prompt-cache params rather than a side path.
///
/// The composed fragment is the sanitized vendor reasoning fragment plus, when
/// set, the top-level `prompt_cache_key` (= session id, prompt
/// `prompt-caching-strategy.md` decision 3) and opaque
/// `prompt_cache_retention`. These keys are not cockpit-owned request keys, so
/// they survive sanitization, but we inject them explicitly rather than relying
/// on the user's fragment. Returns `None` when there is nothing to add, so
/// providers with no extra params and no cache params stay byte-for-byte
/// unchanged.
pub(super) fn openai_additional_params(params: &ModelParams) -> Option<serde_json::Value> {
    openai_additional_params_with_vendor(chatgpt_additional_params(params), params)
}

/// Add generic OpenAI cache parameters to a wire-specific sanitized provider
/// fragment. Responses passes its statefulness-aware sanitizer here while
/// Chat Completions keeps its vendor fragment untouched beyond universal
/// request-key collision protection.
fn openai_additional_params_with_vendor(
    vendor: Option<serde_json::Value>,
    params: &ModelParams,
) -> Option<serde_json::Value> {
    let cache_key = params
        .prompt_cache_key
        .as_ref()
        .filter(|key| !key.is_empty());
    let cache_retention = params
        .prompt_cache_retention
        .as_ref()
        .filter(|retention| !retention.is_empty());
    if cache_key.is_none() && cache_retention.is_none() {
        return vendor;
    }
    // Merge cache params into the vendor object (or start a fresh object).
    let mut map = match vendor {
        Some(serde_json::Value::Object(m)) => m,
        // A non-object vendor fragment is a shape the config author chose; we
        // don't silently rewrite it, so cache params can't be merged in; keep
        // the vendor fragment as-is (cache params are best-effort).
        Some(other) => return Some(other),
        None => serde_json::Map::new(),
    };
    if let Some(key) = cache_key {
        map.insert(
            "prompt_cache_key".to_string(),
            serde_json::Value::String(key.clone()),
        );
    }
    if let Some(retention) = cache_retention {
        map.insert(
            "prompt_cache_retention".to_string(),
            serde_json::Value::String(retention.clone()),
        );
    }
    Some(serde_json::Value::Object(map))
}

/// Compose the generic OpenAI **Responses**-wire extras.
///
/// Responses calls are deliberately stateless: Cockpit replays the complete
/// conversation as `input`, always sends `store: false`, and does not permit a
/// provider fragment to select `previous_response_id` or `background` (those
/// fields are removed by [`sanitized_openai_responses_extra_params`]). Rig's
/// Responses serializer models reasoning effort as `reasoning.effort`, whereas the
/// generic catalog's OpenAI-compatible mapping supplies `reasoning_effort`.
/// Translate that mapping at the wire boundary instead of silently letting
/// Rig discard it as an unknown additional parameter.
pub(super) fn openai_responses_additional_params(params: &ModelParams) -> serde_json::Value {
    let vendor = merge_native_computer_tools(
        sanitized_openai_responses_extra_params(params.additional_params.as_ref()),
        params,
        |contract| contract == crate::computer::ComputerToolContract::OpenAiResponses,
    );
    let mut map = match openai_additional_params_with_vendor(vendor, params) {
        Some(serde_json::Value::Object(map)) => map,
        // A scalar cannot be represented in Rig's typed Responses parameters.
        // Place it in the typed `reasoning` slot so Rig rejects the malformed
        // config instead of silently sending an unconstrained request body.
        Some(other) => serde_json::Map::from_iter([("reasoning".into(), other)]),
        None => serde_json::Map::new(),
    };

    if let Some(effort) = map.remove("reasoning_effort") {
        match map.entry("reasoning".to_string()) {
            serde_json::map::Entry::Vacant(entry) => {
                entry.insert(serde_json::json!({ "effort": effort }));
            }
            serde_json::map::Entry::Occupied(mut entry) => match entry.get_mut() {
                serde_json::Value::Object(reasoning) => {
                    reasoning.insert("effort".to_string(), effort);
                }
                // The catalog mapping is authoritative for this request. A
                // malformed hand-authored `reasoning` shape cannot cause its
                // selected effort to be silently dropped.
                other => *other = serde_json::json!({ "effort": effort }),
            },
        }
    }

    // This is intentionally injected after vendor composition. The provider
    // fragment cannot override it, and the typed Rig serializer therefore
    // emits the key rather than applying a provider default by omission.
    map.insert("store".to_string(), serde_json::Value::Bool(false));
    serde_json::Value::Object(map)
}

/// Native ChatGPT/Codex subscription backend extras: sanitized vendor fragment
/// plus OpenAI-Responses native computer tools. **Does not** inject
/// `prompt_cache_key` / `prompt_cache_retention` — those are OpenAI-compatible
/// body keys only. The ChatGPT path hits `chatgpt.com/backend-api/codex`, a
/// distinct API that must not receive OpenAI cache fields (pre-0.41
/// `build_chatgpt_agent` used this same composition).
pub(super) fn chatgpt_additional_params(params: &ModelParams) -> Option<serde_json::Value> {
    let vendor = sanitized_extra_params(params.additional_params.as_ref());
    merge_native_computer_tools(vendor, params, |contract| {
        contract == crate::computer::ComputerToolContract::OpenAiResponses
    })
}

pub(super) fn anthropic_additional_params(params: &ModelParams) -> Option<serde_json::Value> {
    let vendor = sanitized_extra_params(params.additional_params.as_ref());
    merge_native_computer_tools(vendor, params, |contract| {
        matches!(
            contract,
            crate::computer::ComputerToolContract::Anthropic20251124
                | crate::computer::ComputerToolContract::Anthropic20250124
        )
    })
}

pub(super) fn native_computer_beta_headers(params: &ModelParams) -> Vec<&'static str> {
    native_computer_wire_config(params)
        .map(|computer| computer.wire().beta_headers)
        .unwrap_or_default()
}

/// Native computer tools belong on the wire only for a coordinator-backed
/// live-loop request. Opened geometry on long-lived [`ModelParams`] is not a
/// sufficient gate: compact, shrink, and warm-resolver clones reuse those
/// params with empty Rig tools and no live-loop injection path.
fn native_computer_wire_config(
    params: &ModelParams,
) -> Option<&crate::computer::NativeComputerToolConfig> {
    params
        .native_computer
        .as_ref()
        .filter(|computer| computer.geometry.is_some() && super::native_computer_live_turn_active())
}

fn merge_native_computer_tools(
    vendor: Option<serde_json::Value>,
    params: &ModelParams,
    accepts_contract: impl Fn(crate::computer::ComputerToolContract) -> bool,
) -> Option<serde_json::Value> {
    let Some(native_computer) =
        native_computer_wire_config(params).filter(|computer| accepts_contract(computer.contract))
    else {
        return vendor;
    };
    let mut map = match vendor {
        Some(serde_json::Value::Object(map)) => map,
        Some(other) => return Some(other),
        None => serde_json::Map::new(),
    };
    let native_tools = native_computer.wire().tools;
    match map.get_mut("tools") {
        Some(serde_json::Value::Array(tools)) => tools.extend(native_tools),
        _ => {
            map.insert("tools".to_string(), serde_json::Value::Array(native_tools));
        }
    }
    Some(serde_json::Value::Object(map))
}
