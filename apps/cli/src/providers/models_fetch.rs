//! `GET {url}/models` against an OpenAI-compatible endpoint.
//!
//! Returns either:
//!   - `Ok(Some(entries))` — a parsed list (envelope or bare-array).
//!   - `Ok(None)` — the endpoint replied 404, so the provider doesn't
//!     ship one. The caller treats this as a no-op (the `/fetch-models`
//!     workflow leaves the configured model list alone).
//!   - `Err(...)` — any other failure surfaces, including 401 with a
//!     hint to fix the credential.
//!
//! The body parser is tolerant: it accepts the canonical
//! `{"data": [...]}` envelope, Codex's `{"models": [...]}` envelope, and the
//! bare-array shape some compat gateways emit. Entries missing an `id` are
//! dropped rather than erroring (matches mixer-rs's behavior; see
//! `mixer-rs/src/providers/common/models_list.rs`).

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::{StatusCode, Url};
use serde_json::{Map, Value};

use crate::config::providers::{
    CapabilitySource, CapabilityStatus, CapabilityValue, ClientSideToolsCapability, HeaderSpec,
    ModelCapabilities, ModelEntry, ProviderEntry, ProviderModelCatalog, ReasoningEffortCapability,
    ReasoningEffortRequestMapping, ThinkingMode, validate_anthropic_model_configuration,
};
use crate::envref;
use crate::providers::registry::{
    OAuthCredential, ProviderCredentialKind, ProviderRegistry, ProviderRequestKind,
};

const COPILOT_TOKEN_ENV_VARS: [&str; 3] = ["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"];
const COPILOT_DIRECT_API_TOKEN_ENV: &str = "GITHUB_COPILOT_API_TOKEN";
const COPILOT_API_URL_ENV: &str = "COPILOT_API_URL";
const ERROR_BODY_SNIPPET_CHARS: usize = 256;
const MAX_MODELS_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const CODEX_MODEL_LIST_CLIENT_VERSION: &str = "0.0.0";

pub(crate) fn codex_model_list_client_version() -> &'static str {
    // This value is the Codex backend model-list compatibility contract,
    // not Cockpit's package version. Current Codex source resolves the
    // model-list client version to 0.0.0.
    CODEX_MODEL_LIST_CLIENT_VERSION
}

/// Resolved view of a `HeaderSpec` after envref expansion.
#[derive(Clone)]
pub struct ResolvedHeader {
    pub name: String,
    pub value: String,
}

impl fmt::Debug for ResolvedHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedHeader")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Fully resolved provider request inputs after applying envref
/// expansion plus GitHub Copilot's documented token fallbacks.
#[derive(Clone)]
pub struct ResolvedRequest {
    pub base_url: String,
    pub headers: Vec<ResolvedHeader>,
}

impl fmt::Debug for ResolvedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedRequest")
            .field("base_url", &self.base_url)
            .field("headers", &self.headers)
            .finish()
    }
}

/// Resolve environment and named-secret references in every header, collecting
/// missing references into one list. Caller decides whether to abort or warn.
pub fn resolve_headers(headers: &[HeaderSpec]) -> (Vec<ResolvedHeader>, Vec<String>) {
    let store = crate::credentials::CredentialStore::open_default_readonly().ok();
    resolve_headers_with_sources(
        headers,
        |name| std::env::var(name).ok(),
        |name| {
            store
                .as_ref()
                .and_then(|store| store.named_secret(name))
                .map(str::to_string)
        },
    )
}

pub fn resolve_headers_with_env<F>(
    headers: &[HeaderSpec],
    lookup: F,
) -> (Vec<ResolvedHeader>, Vec<String>)
where
    F: Fn(&str) -> Option<String>,
{
    resolve_headers_with_sources(headers, lookup, |_| None)
}

pub fn resolve_headers_with_sources<F, S>(
    headers: &[HeaderSpec],
    env_lookup: F,
    secret_lookup: S,
) -> (Vec<ResolvedHeader>, Vec<String>)
where
    F: Fn(&str) -> Option<String>,
    S: Fn(&str) -> Option<String>,
{
    let mut out = Vec::with_capacity(headers.len());
    let mut missing: Vec<String> = Vec::new();
    for h in headers {
        let r = envref::resolve_with_sources(&h.value, &env_lookup, &secret_lookup);
        push_missing(&mut missing, &r.missing);
        push_missing(&mut missing, &r.errors);
        out.push(ResolvedHeader {
            name: h.name.clone(),
            value: r.value,
        });
    }
    (out, missing)
}

/// Resolve a provider entry into concrete request inputs. For most
/// providers this is just `$VAR` expansion over `headers`; GitHub
/// Copilot also accepts documented token sources in the same priority
/// order as GitHub's SDK docs.
pub fn resolve_provider_request(
    provider_id: &str,
    entry: &ProviderEntry,
) -> Result<ResolvedRequest> {
    let registry = ProviderRegistry::standard();
    let provider = registry.provider_for(provider_id, entry);
    if let Some(message) = provider.sync_auth_error() {
        anyhow::bail!(message);
    }
    provider.request(provider_id, entry, None, &|name| std::env::var(name).ok())
}

pub fn resolve_provider_request_with_env<F>(
    provider_id: &str,
    entry: &ProviderEntry,
    lookup: F,
) -> Result<ResolvedRequest>
where
    F: Fn(&str) -> Option<String>,
{
    resolve_provider_request_with_sources(provider_id, entry, lookup, |_| None)
}

pub fn resolve_provider_request_with_sources<F, S>(
    provider_id: &str,
    entry: &ProviderEntry,
    env_lookup: F,
    secret_lookup: S,
) -> Result<ResolvedRequest>
where
    F: Fn(&str) -> Option<String>,
    S: Fn(&str) -> Option<String>,
{
    let registry = ProviderRegistry::standard();
    let provider = registry.provider_for(provider_id, entry);
    if let Some(message) = provider.sync_auth_error() {
        anyhow::bail!(message);
    }
    resolve_provider_request_inner_with_sources(
        provider_id,
        entry,
        None,
        provider.request_kind(),
        &env_lookup,
        &secret_lookup,
    )
}

pub async fn resolve_provider_request_async(
    provider_id: &str,
    entry: &ProviderEntry,
) -> Result<ResolvedRequest> {
    let registry = ProviderRegistry::standard();
    let credential_kind = registry.provider_for(provider_id, entry).credential_kind();
    let credential = match credential_kind {
        Some(ProviderCredentialKind::CodexOAuth) => Some(OAuthCredential::Codex(
            crate::auth::codex_oauth::credential().await?,
        )),
        Some(ProviderCredentialKind::XaiOAuth) => Some(OAuthCredential::Bearer(
            crate::auth::xai_oauth::bearer_token().await?,
        )),
        None => None,
    };
    registry
        .provider_for(provider_id, entry)
        .request(provider_id, entry, credential, &|name| {
            std::env::var(name).ok()
        })
}

async fn resolve_model_list_request_async(
    provider_id: &str,
    entry: &ProviderEntry,
    resolved: &ResolvedRequest,
) -> Result<ResolvedRequest> {
    let registry = ProviderRegistry::standard();
    let credential_kind = registry.provider_for(provider_id, entry).credential_kind();
    let credential = match credential_kind {
        Some(ProviderCredentialKind::CodexOAuth) => Some(OAuthCredential::Codex(
            crate::auth::codex_oauth::credential().await?,
        )),
        Some(ProviderCredentialKind::XaiOAuth) => Some(OAuthCredential::Bearer(
            crate::auth::xai_oauth::bearer_token().await?,
        )),
        None => None,
    };
    registry
        .provider_for(provider_id, entry)
        .model_list_request(provider_id, entry, resolved, credential, &|name| {
            std::env::var(name).ok()
        })
}

pub fn resolve_provider_request_blocking(
    provider_id: &str,
    entry: &ProviderEntry,
) -> Result<ResolvedRequest> {
    let registry = ProviderRegistry::standard();
    if registry
        .provider_for(provider_id, entry)
        .credential_kind()
        .is_none()
    {
        return resolve_provider_request(provider_id, entry);
    }
    let handle = tokio::runtime::Handle::try_current()
        .context("subscription auth requires an async runtime")?;
    tokio::task::block_in_place(|| {
        handle.block_on(resolve_provider_request_async(provider_id, entry))
    })
}

pub fn resolve_provider_request_blocking_with_env<F>(
    provider_id: &str,
    entry: &ProviderEntry,
    lookup: F,
) -> Result<ResolvedRequest>
where
    F: Fn(&str) -> Option<String>,
{
    let registry = ProviderRegistry::standard();
    if registry
        .provider_for(provider_id, entry)
        .credential_kind()
        .is_none()
    {
        return resolve_provider_request_with_env(provider_id, entry, lookup);
    }
    resolve_provider_request_blocking(provider_id, entry)
}

pub(crate) fn resolve_provider_request_inner(
    provider_id: &str,
    entry: &ProviderEntry,
    oauth_credential: Option<OAuthCredential>,
    request_kind: ProviderRequestKind,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<ResolvedRequest> {
    let secret_store = crate::credentials::CredentialStore::open_default_readonly().ok();
    resolve_provider_request_inner_with_sources(
        provider_id,
        entry,
        oauth_credential,
        request_kind,
        lookup,
        &|name| {
            secret_store
                .as_ref()
                .and_then(|store| store.named_secret(name))
                .map(str::to_string)
        },
    )
}

fn resolve_provider_request_inner_with_sources(
    provider_id: &str,
    entry: &ProviderEntry,
    oauth_credential: Option<OAuthCredential>,
    request_kind: ProviderRequestKind,
    env_lookup: &dyn Fn(&str) -> Option<String>,
    secret_lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<ResolvedRequest> {
    let is_copilot = request_kind == ProviderRequestKind::Copilot;
    let mut headers: Vec<ResolvedHeader> = Vec::with_capacity(entry.headers.len() + 1);
    let mut missing_other: Vec<String> = Vec::new();
    let mut errors_other: Vec<String> = Vec::new();
    let mut auth_header: Option<ResolvedHeader> = None;
    let mut auth_missing: Vec<String> = Vec::new();
    let mut auth_errors: Vec<String> = Vec::new();

    for h in &entry.headers {
        let resolved = envref::resolve_with_sources(&h.value, env_lookup, secret_lookup);
        if h.name.eq_ignore_ascii_case("authorization") {
            if resolved.has_errors() {
                push_missing(&mut auth_errors, &resolved.errors);
            } else if resolved.has_missing() {
                push_missing(&mut auth_missing, &resolved.missing);
            } else {
                auth_header = Some(ResolvedHeader {
                    name: h.name.clone(),
                    value: resolved.value,
                });
            }
            continue;
        }

        push_missing(&mut missing_other, &resolved.missing);
        if resolved.has_errors() {
            push_missing(&mut errors_other, &resolved.errors);
            continue;
        }
        headers.push(ResolvedHeader {
            name: h.name.clone(),
            value: resolved.value,
        });
    }

    if !missing_other.is_empty() {
        anyhow::bail!(
            "provider `{provider_id}` references missing environment variable(s) or named secret(s): {}",
            missing_other.join(", ")
        );
    }
    if !errors_other.is_empty() {
        anyhow::bail!(
            "provider `{provider_id}` has invalid environment or named-secret reference(s): {}",
            errors_other.join(", ")
        );
    }
    if !auth_errors.is_empty() {
        anyhow::bail!(
            "Authorization for provider `{provider_id}` has invalid environment or named-secret reference(s): {}",
            auth_errors.join(", ")
        );
    }

    if let Some(credential) = oauth_credential {
        let token = credential.access_token().to_string();
        headers.push(ResolvedHeader {
            name: "Authorization".to_string(),
            value: format!("Bearer {token}"),
        });
        if let OAuthCredential::Codex(tokens) = credential {
            let account_id = tokens.account_id.ok_or_else(|| {
                anyhow!(
                    "Codex subscription auth is missing chatgpt-account-id; set up OAuth in /settings → Providers."
                )
            })?;
            headers.push(ResolvedHeader {
                name: "chatgpt-account-id".to_string(),
                value: account_id,
            });
            headers.push(ResolvedHeader {
                name: "originator".to_string(),
                value: "cockpit".to_string(),
            });
            headers.push(ResolvedHeader {
                name: "OpenAI-Beta".to_string(),
                value: "responses=experimental".to_string(),
            });
            headers.push(ResolvedHeader {
                name: "session_id".to_string(),
                value: uuid::Uuid::new_v4().to_string(),
            });
        }
    } else if let Some(auth) = auth_header {
        headers.push(auth);
    } else if is_copilot {
        match resolve_copilot_token_with_env(env_lookup)? {
            Some(token) => headers.push(ResolvedHeader {
                name: "Authorization".to_string(),
                value: format!("Bearer {token}"),
            }),
            None => {
                let configured = if auth_missing.is_empty() {
                    String::new()
                } else {
                    format!(
                        " Configured Authorization refs were unset: {}.",
                        auth_missing.join(", ")
                    )
                };
                anyhow::bail!(
                    "GitHub Copilot requires an official GitHub token. \
                     Export one of COPILOT_GITHUB_TOKEN, GH_TOKEN, or GITHUB_TOKEN; \
                     or use the documented direct API pair \
                     GITHUB_COPILOT_API_TOKEN + COPILOT_API_URL.{configured}"
                );
            }
        }
    } else if !auth_missing.is_empty() {
        anyhow::bail!(
            "Authorization for provider `{provider_id}` references missing environment variable(s) or named secret(s): {}",
            auth_missing.join(", ")
        );
    }
    // No Authorization header at all (and not Copilot): fetch
    // unauthenticated. Fully-local endpoints like LM Studio don't
    // require auth; a provider that actually needs it surfaces a clear
    // 401 from `fetch_models`.

    Ok(ResolvedRequest {
        base_url: resolve_provider_base_url_with_env(provider_id, entry, is_copilot, env_lookup)?,
        headers,
    })
}

pub(crate) fn resolve_codex_model_list_request(
    provider_id: &str,
    entry: &ProviderEntry,
    tokens: crate::auth::codex_oauth::StoredTokens,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<ResolvedRequest> {
    let mut headers: Vec<ResolvedHeader> = Vec::with_capacity(2);

    let account_id = tokens.account_id.ok_or_else(|| {
        anyhow!(
            "Codex subscription auth is missing chatgpt-account-id; set up OAuth in /settings → Providers."
        )
    })?;
    headers.push(ResolvedHeader {
        name: "Authorization".to_string(),
        value: format!("Bearer {}", tokens.access_token),
    });
    headers.push(ResolvedHeader {
        name: "ChatGPT-Account-ID".to_string(),
        value: account_id,
    });

    Ok(ResolvedRequest {
        base_url: resolve_provider_base_url_with_env(provider_id, entry, false, lookup)?,
        headers,
    })
}

/// Outcome of [`fetch_models`].
#[derive(Debug)]
pub enum FetchOutcome {
    /// The endpoint returned a model list.
    Models {
        models: Vec<ModelEntry>,
        catalog: ProviderModelCatalog,
    },
    /// Live discovery failed, but this provider has a built-in fallback
    /// catalog the caller may explicitly activate.
    FallbackAvailable {
        models: Vec<ModelEntry>,
        catalog: ProviderModelCatalog,
        reason: String,
    },
    /// The provider doesn't expose `/models` (404).
    Unsupported,
}

pub async fn fetch_models(
    base_url: &str,
    headers: &[ResolvedHeader],
    timeout: Duration,
) -> Result<FetchOutcome> {
    let url = format!("{}/models", base_url.trim_end_matches('/'));
    fetch_models_at(&url, headers, timeout).await
}

fn models_url_for_provider(provider_id: &str, entry: &ProviderEntry, base_url: &str) -> String {
    ProviderRegistry::standard()
        .provider_for(provider_id, entry)
        .models_url(entry, base_url)
}

async fn fetch_models_at(
    url: &str,
    headers: &[ResolvedHeader],
    timeout: Duration,
) -> Result<FetchOutcome> {
    fetch_models_at_detailed(url, headers, timeout)
        .await
        .map(|result| result.outcome)
}

struct FetchModelsAtResult {
    outcome: FetchOutcome,
    status: Option<StatusCode>,
    body_nonempty: bool,
}

async fn fetch_models_at_detailed(
    url: &str,
    headers: &[ResolvedHeader],
    timeout: Duration,
) -> Result<FetchModelsAtResult> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .context("building reqwest client")?;

    let resp = send_models_request_with_retries(&client, url, headers).await?;
    let status = resp.status();
    if status == StatusCode::NOT_FOUND {
        return Ok(FetchModelsAtResult {
            outcome: FetchOutcome::Unsupported,
            status: Some(status),
            body_nonempty: false,
        });
    }
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        anyhow::bail!(
            "{url} returned {status} — credentials rejected. Verify the API key, OAuth login, and headers."
        );
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("{url} returned {status}: {}", response_body_snippet(&body));
    }

    let body = read_success_body_limited(resp).await?;
    let body_nonempty = !body.trim().is_empty();
    let models = parse_models_body(&body)?;
    Ok(FetchModelsAtResult {
        outcome: FetchOutcome::Models {
            models,
            catalog: ProviderModelCatalog::Live,
        },
        status: Some(status),
        body_nonempty,
    })
}

async fn send_models_request_with_retries(
    client: &reqwest::Client,
    url: &str,
    headers: &[ResolvedHeader],
) -> Result<reqwest::Response> {
    let mut attempt = 0;
    loop {
        let user_agent = headers
            .iter()
            .find(|h| {
                h.name
                    .eq_ignore_ascii_case(reqwest::header::USER_AGENT.as_str())
            })
            .map(|h| h.value.clone())
            .unwrap_or_else(|| crate::user_agent::user_agent().to_string());
        let mut req = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::USER_AGENT, user_agent);
        for h in headers {
            if h.name
                .eq_ignore_ascii_case(reqwest::header::USER_AGENT.as_str())
            {
                continue;
            }
            req = req.header(&h.name, &h.value);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if crate::providers::http_retry::is_retryable_status(status)
                    && attempt < crate::providers::http_retry::MAX_RETRIES
                {
                    let delay = crate::providers::http_retry::delay_for(resp.headers(), attempt);
                    attempt += 1;
                    tokio::time::sleep(delay).await;
                    continue;
                }
                return Ok(resp);
            }
            Err(error)
                if crate::providers::http_retry::is_retryable_error(&error)
                    && attempt < crate::providers::http_retry::MAX_RETRIES =>
            {
                let delay = crate::providers::http_retry::fallback_delay_for(attempt);
                attempt += 1;
                tokio::time::sleep(delay).await;
                continue;
            }
            Err(error) => return Err(error).with_context(|| format!("GET {url}")),
        }
    }
}

pub async fn fetch_models_for_provider(
    provider_id: &str,
    entry: &ProviderEntry,
    resolved: &ResolvedRequest,
    timeout: Duration,
) -> Result<FetchOutcome> {
    let request = resolve_model_list_request_async(provider_id, entry, resolved).await?;
    let registry = ProviderRegistry::standard();
    let provider = registry.provider_for(provider_id, entry);
    let url = provider.models_url(entry, &request.base_url);
    let fallback_models = provider.fallback_models();
    let fallback_catalog = provider.fallback_catalog();
    let outcome = fetch_models_at_detailed(&url, &request.headers, timeout)
        .await
        .and_then(|result| validate_anthropic_fetch_result(entry, &request.base_url, result));
    if fallback_models.is_empty() {
        return outcome.map(|result| result.outcome);
    }
    match outcome {
        Ok(FetchModelsAtResult {
            outcome: FetchOutcome::Unsupported,
            ..
        }) => {
            tracing::warn!(
                provider_id,
                url,
                "provider /models unavailable; fallback catalog available"
            );
            Ok(FetchOutcome::FallbackAvailable {
                models: fallback_models,
                catalog: fallback_catalog,
                reason: format!("{url} returned 404"),
            })
        }
        Ok(FetchModelsAtResult {
            outcome: FetchOutcome::Models { models, catalog: _ },
            status: Some(status),
            body_nonempty: true,
        }) if models.is_empty() && status.is_success() => {
            tracing::warn!(
                provider_id,
                url,
                %status,
                "provider /models returned an empty model list; fallback catalog available"
            );
            Ok(FetchOutcome::FallbackAvailable {
                models: fallback_models,
                catalog: fallback_catalog,
                reason: format!("{url} returned an empty model list (status {status})"),
            })
        }
        Err(error) => {
            let reason = error.to_string();
            if reason.contains("returned 401") || reason.contains("returned 403") {
                return Err(error);
            }
            tracing::warn!(provider_id, url, error = %reason, "provider /models fetch failed; fallback catalog available");
            Ok(FetchOutcome::FallbackAvailable {
                models: fallback_models,
                catalog: fallback_catalog,
                reason,
            })
        }
        Ok(result) => Ok(result.outcome),
    }
}

fn validate_anthropic_fetch_result(
    entry: &ProviderEntry,
    base_url: &str,
    result: FetchModelsAtResult,
) -> Result<FetchModelsAtResult> {
    if !crate::config::providers::is_anthropic_native_base_url(base_url) {
        return Ok(result);
    }
    if let FetchOutcome::Models { models, .. } = &result.outcome {
        for fetched in models {
            let mut candidate_model = fetched.clone();
            if let Some(existing) = entry.models.iter().find(|model| model.id == fetched.id) {
                candidate_model.capability_overrides = existing.capability_overrides.clone();
            }
            let mut candidate_provider = entry.clone();
            candidate_provider.models = vec![candidate_model];
            if let Err(error) =
                validate_anthropic_model_configuration(&candidate_provider, &fetched.id)
            {
                anyhow::bail!(
                    "rejecting invalid Anthropic catalog entry `{}`: {error:#}",
                    fetched.id
                );
            }
        }
    }
    Ok(result)
}

async fn read_success_body_limited(mut resp: reqwest::Response) -> Result<String> {
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .context("reading /models response body")?
    {
        if body.len().saturating_add(chunk.len()) > MAX_MODELS_RESPONSE_BYTES {
            anyhow::bail!(
                "/models response body exceeded {} byte limit",
                MAX_MODELS_RESPONSE_BYTES
            );
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).context("/models response body was not valid UTF-8")
}

pub fn parse_models_body(body: &str) -> Result<Vec<ModelEntry>> {
    let parsed: Value = serde_json::from_str(body)
        .with_context(|| format!("parsing /models response: {}", response_body_snippet(body)))?;
    let entries: Vec<Value> = match parsed {
        Value::Array(xs) => xs,
        Value::Object(mut m) => match (m.remove("data"), m.remove("models")) {
            (Some(Value::Array(xs)), _) | (_, Some(Value::Array(xs))) => xs,
            _ => return Err(anyhow!("models response lacks a `data` or `models` array")),
        },
        _ => return Err(anyhow!("unexpected models response root")),
    };

    entries
        .into_iter()
        .filter_map(|raw| {
            let obj = raw.as_object()?;
            let id = obj
                .get("id")
                .or_else(|| obj.get("slug"))
                .and_then(Value::as_str)?
                .to_string();

            let name = obj
                .get("display_name")
                .or_else(|| obj.get("name"))
                .and_then(Value::as_str)
                .map(str::to_string);

            let thinking_modes = obj
                .get("thinking_modes")
                .and_then(Value::as_array)
                .map(|xs| {
                    xs.iter()
                        .filter_map(|v| match v.as_str()? {
                            "off" => Some(ThinkingMode::Off),
                            "low" => Some(ThinkingMode::Low),
                            "medium" => Some(ThinkingMode::Medium),
                            "high" => Some(ThinkingMode::High),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();

            let inputs = obj.get("inputs").and_then(|v| {
                serde_json::from_value::<crate::config::providers::Inputs>(v.clone()).ok()
            });

            let capabilities = match model_capabilities_from_metadata(obj) {
                Ok(capabilities) => capabilities,
                Err(error) => return Some(Err(anyhow!("model `{id}` capabilities: {error}"))),
            };

            // Stash every remaining field into `extra` so re-saving
            // doesn't lose provider-specific metadata.
            let mut extra = Map::new();
            for (k, v) in obj {
                if matches!(
                    k.as_str(),
                    "id" | "name"
                        | "display_name"
                        | "thinking_modes"
                        | "inputs"
                        | "context_length"
                        | "max_tokens"
                ) {
                    continue;
                }
                extra.insert(k.clone(), v.clone());
            }

            // Several providers include a request context window under
            // different names. Keep `context_length` in sync with the typed
            // capability projection so legacy context consumers still work.
            let context_length = context_tokens_from_metadata(obj);

            Some(Ok(ModelEntry {
                id,
                name,
                thinking_modes,
                inputs,
                context_length,
                favorite: false,
                manual: false,
                trust: None,
                location: None,
                quality_rank: None,
                cost_rank: None,
                subagent_invokable: None,
                embeddings: None,
                embedding_dimensions: None,
                availability: Default::default(),
                cache: None,
                shrink: None,
                context: None,
                auto_prune: None,
                timeout: None,
                backup: None,
                mode: None,
                system_prompt: None,
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                thinking_params: Default::default(),
                // Fetched entries are always `auto`; a user/fallback pin is
                // carried over by `merge_fetched_models`
                // (implementation note).
                wire_api: Default::default(),
                extra: extra.clone(),
                capabilities,
                capability_overrides: Default::default(),
                provider_metadata: extra,
            }))
        })
        .collect()
}

fn model_capabilities_from_metadata(obj: &Map<String, Value>) -> Result<ModelCapabilities> {
    let context_tokens = context_tokens_from_metadata(obj);
    let max_output_tokens = max_output_tokens_from_metadata(obj);
    Ok(ModelCapabilities {
        tool_calling: capability_status_from_metadata(
            obj,
            "tool_calling",
            &["tools", "tool_choice", "functions", "function_calling"],
        ),
        images: images_from_metadata(obj),
        embeddings: embeddings_from_metadata(obj),
        embedding_dimensions: embedding_dimensions_from_metadata(obj),
        context_tokens,
        context_tokens_source: context_tokens.map(|_| CapabilitySource::Live),
        max_output_tokens,
        max_output_tokens_source: max_output_tokens.map(|_| CapabilitySource::Live),
        reasoning: capability_status_from_metadata(
            obj,
            "reasoning",
            &["reasoning", "reasoning_effort", "include_reasoning"],
        ),
        structured_outputs: capability_status_from_metadata(
            obj,
            "structured_outputs",
            &[
                "structured_outputs",
                "response_format",
                "json_schema",
                "json_schema_response_format",
            ],
        ),
        reasoning_effort: reasoning_effort_capability_from_metadata(obj)?,
        client_side_tools: client_side_tools_capability_from_metadata(obj).unwrap_or_default(),
        computer_use: Default::default(),
    })
}

fn context_tokens_from_metadata(obj: &Map<String, Value>) -> Option<u32> {
    numeric_field(obj, "max_input_tokens")
        .or_else(|| numeric_field(obj, "context_length"))
        .or_else(|| nested_numeric_field(obj, &["top_provider", "context_length"]))
        .or_else(|| nested_numeric_field(obj, &["limit", "context"]))
        .or_else(|| numeric_field(obj, "max_context_tokens"))
        .or_else(|| numeric_field(obj, "max_tokens"))
}

fn max_output_tokens_from_metadata(obj: &Map<String, Value>) -> Option<u32> {
    numeric_field(obj, "max_output_tokens")
        .or_else(|| numeric_field(obj, "output_token_limit"))
        .or_else(|| numeric_field(obj, "max_tokens"))
}

fn numeric_field(obj: &Map<String, Value>, key: &str) -> Option<u32> {
    u32_from_value(obj.get(key)?)
}

fn nested_numeric_field(obj: &Map<String, Value>, path: &[&str]) -> Option<u32> {
    let mut current = obj.get(*path.first()?)?;
    for key in &path[1..] {
        current = current.as_object()?.get(*key)?;
    }
    u32_from_value(current)
}

fn u32_from_value(value: &Value) -> Option<u32> {
    match value {
        Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        Value::String(s) => s.trim().parse::<u32>().ok(),
        _ => None,
    }
}

fn embeddings_from_metadata(obj: &Map<String, Value>) -> Option<bool> {
    obj.get("embeddings")
        .and_then(Value::as_bool)
        .or_else(|| obj.get("embedding").and_then(Value::as_bool))
        .or_else(|| {
            obj.get("capabilities")
                .and_then(Value::as_object)
                .and_then(|capabilities| capabilities.get("embeddings"))
                .and_then(Value::as_bool)
        })
}

fn embedding_dimensions_from_metadata(obj: &Map<String, Value>) -> Option<u32> {
    numeric_field(obj, "embedding_dimensions")
        .or_else(|| numeric_field(obj, "embedding_dimension"))
        .or_else(|| numeric_field(obj, "dimensions"))
        .or_else(|| {
            obj.get("capabilities")
                .and_then(Value::as_object)
                .and_then(|capabilities| {
                    capabilities
                        .get("embedding_dimensions")
                        .or_else(|| capabilities.get("embedding_dimension"))
                        .or_else(|| capabilities.get("dimensions"))
                })
                .and_then(u32_from_value)
        })
}

fn images_from_metadata(obj: &Map<String, Value>) -> Option<bool> {
    if let Some(images) = obj
        .get("inputs")
        .and_then(Value::as_object)
        .and_then(|inputs| inputs.get("images"))
        .and_then(Value::as_bool)
    {
        return Some(images);
    }
    let input_modalities = obj
        .get("architecture")
        .and_then(Value::as_object)
        .and_then(|architecture| architecture.get("input_modalities"))
        .or_else(|| obj.get("input_modalities"))
        .or_else(|| obj.get("inputModalities"));
    modality_list_contains(input_modalities, "image").then_some(true)
}

fn modality_list_contains(value: Option<&Value>, needle: &str) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| string_value_eq(value, needle)))
}

fn capability_status_from_metadata(
    obj: &Map<String, Value>,
    key: &str,
    supported_parameters: &[&str],
) -> CapabilityStatus {
    let camel = snake_to_camel(key);
    let raw = obj.get(key).or_else(|| obj.get(&camel)).or_else(|| {
        obj.get("capabilities")
            .and_then(Value::as_object)
            .and_then(|capabilities| capabilities.get(key).or_else(|| capabilities.get(&camel)))
    });
    let parsed = raw
        .map(capability_status_from_value)
        .unwrap_or(CapabilityStatus::Unknown);
    if !parsed.is_unknown() {
        return parsed;
    }
    supported_parameters_status(obj, supported_parameters)
}

fn capability_status_from_value(raw: &Value) -> CapabilityStatus {
    match raw {
        Value::Bool(true) => CapabilityStatus::Supported,
        Value::Bool(false) => CapabilityStatus::Unsupported,
        Value::String(s) => capability_status_from_str(s),
        Value::Object(obj) => obj
            .get("supported")
            .and_then(Value::as_bool)
            .map(|supported| {
                if supported {
                    CapabilityStatus::Supported
                } else {
                    CapabilityStatus::Unsupported
                }
            })
            .or_else(|| {
                obj.get("status")
                    .or_else(|| obj.get("state"))
                    .or_else(|| obj.get("support"))
                    .and_then(Value::as_str)
                    .map(capability_status_from_str)
            })
            .unwrap_or(CapabilityStatus::Unknown),
        _ => CapabilityStatus::Unknown,
    }
}

fn capability_status_from_str(raw: &str) -> CapabilityStatus {
    match raw.trim().to_ascii_lowercase().as_str() {
        "supported" | "support" | "available" | "enabled" | "true" | "yes" => {
            CapabilityStatus::Supported
        }
        "unsupported" | "not_supported" | "unavailable" | "disabled" | "false" | "no" => {
            CapabilityStatus::Unsupported
        }
        "requires_entitlement"
        | "requires entitlement"
        | "entitlement"
        | "entitlement_required" => CapabilityStatus::RequiresEntitlement,
        _ => CapabilityStatus::Unknown,
    }
}

fn supported_parameters_status(obj: &Map<String, Value>, keys: &[&str]) -> CapabilityStatus {
    let Some(raw) = obj.get("supported_parameters") else {
        return CapabilityStatus::Unknown;
    };
    let supported = match raw {
        Value::Array(values) => values
            .iter()
            .any(|value| keys.iter().any(|key| string_value_eq(value, key))),
        Value::Object(map) => keys.iter().any(|key| map.contains_key(*key)),
        _ => false,
    };
    if supported {
        CapabilityStatus::Supported
    } else {
        CapabilityStatus::Unknown
    }
}

fn string_value_eq(value: &Value, expected: &str) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.eq_ignore_ascii_case(expected))
}

fn snake_to_camel(key: &str) -> String {
    let mut out = String::new();
    let mut upper_next = false;
    for ch in key.chars() {
        if ch == '_' {
            upper_next = true;
        } else if upper_next {
            out.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

fn client_side_tools_capability_from_metadata(
    obj: &Map<String, Value>,
) -> Option<ClientSideToolsCapability> {
    let raw = obj
        .get("client_side_tools")
        .or_else(|| obj.get("clientSideTools"))
        .or_else(|| {
            obj.get("capabilities")
                .and_then(Value::as_object)
                .and_then(|capabilities| {
                    capabilities
                        .get("client_side_tools")
                        .or_else(|| capabilities.get("clientSideTools"))
                })
        })?;
    match raw {
        Value::Bool(true) => Some(ClientSideToolsCapability {
            status: CapabilityStatus::Supported,
            source: Some(CapabilitySource::Live),
            ..Default::default()
        }),
        Value::Bool(false) => Some(ClientSideToolsCapability {
            status: CapabilityStatus::Unsupported,
            source: Some(CapabilitySource::Live),
            ..Default::default()
        }),
        Value::String(status) => {
            client_side_tools_status(status).map(|status| ClientSideToolsCapability {
                status,
                source: Some(CapabilitySource::Live),
                ..Default::default()
            })
        }
        Value::Object(obj) => {
            let status = obj
                .get("status")
                .or_else(|| obj.get("state"))
                .or_else(|| obj.get("support"))
                .and_then(Value::as_str)
                .and_then(client_side_tools_status)?;
            let entitlement = obj
                .get("entitlement")
                .or_else(|| obj.get("requires_entitlement"))
                .or_else(|| obj.get("requiresEntitlement"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string);
            Some(ClientSideToolsCapability {
                status,
                entitlement,
                source: Some(CapabilitySource::Live),
            })
        }
        _ => None,
    }
}

fn client_side_tools_status(raw: &str) -> Option<CapabilityStatus> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "supported" | "support" | "available" | "enabled" | "true" => {
            Some(CapabilityStatus::Supported)
        }
        "unsupported" | "not_supported" | "unavailable" | "disabled" | "false" => {
            Some(CapabilityStatus::Unsupported)
        }
        "requires_entitlement" | "requires entitlement" | "entitlement_required" => {
            Some(CapabilityStatus::RequiresEntitlement)
        }
        "unknown" => Some(CapabilityStatus::Unknown),
        _ => None,
    }
}

fn reasoning_effort_capability_from_metadata(
    obj: &Map<String, Value>,
) -> Result<Option<ReasoningEffortCapability>> {
    if let Some(raw) = obj
        .get("capabilities")
        .and_then(Value::as_object)
        .and_then(|capabilities| capabilities.get("reasoning_effort"))
    {
        let mut capability = serde_json::from_value::<ReasoningEffortCapability>(raw.clone())
            .context("invalid explicit reasoning_effort capability")?;
        capability.source.get_or_insert(CapabilitySource::Live);
        return Ok(Some(capability));
    }

    let mut values = Vec::new();
    if let Some(raw_values) = obj
        .get("supported_reasoning_levels")
        .and_then(Value::as_array)
    {
        for raw in raw_values {
            let Some(value) = reasoning_level_value(raw) else {
                continue;
            };
            if values
                .iter()
                .any(|existing: &CapabilityValue| existing.value == value.value)
            {
                continue;
            }
            values.push(value);
        }
    }

    let default = obj
        .get("default_reasoning_level")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);

    if values.is_empty() && default.is_none() {
        return Ok(None);
    }

    let request_mapping = if values.is_empty() {
        None
    } else {
        Some(ReasoningEffortRequestMapping::JsonField {
            field: "reasoning_effort".to_string(),
            values: values
                .iter()
                .map(|value| (value.value.clone(), Value::String(value.value.clone())))
                .collect::<BTreeMap<_, _>>(),
        })
    };

    Ok(Some(ReasoningEffortCapability {
        values,
        default,
        request_mapping,
        source: Some(CapabilitySource::Live),
    }))
}

fn reasoning_level_value(raw: &Value) -> Option<CapabilityValue> {
    match raw {
        Value::String(value) => nonempty_reasoning_level(value).map(|value| CapabilityValue {
            value,
            ..Default::default()
        }),
        Value::Object(obj) => {
            let value = obj
                .get("value")
                .or_else(|| obj.get("id"))
                .or_else(|| obj.get("name"))
                .or_else(|| obj.get("effort"))
                .and_then(Value::as_str)
                .and_then(nonempty_reasoning_level)?;
            Some(CapabilityValue {
                value,
                label: obj
                    .get("label")
                    .or_else(|| obj.get("display_name"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                description: obj
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            })
        }
        _ => None,
    }
}

fn nonempty_reasoning_level(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

pub(crate) fn response_body_snippet(body: &str) -> String {
    let mut snippet: String = body.chars().take(ERROR_BODY_SNIPPET_CHARS).collect();
    let truncated = body.chars().count() > ERROR_BODY_SNIPPET_CHARS;
    if truncated {
        snippet.push_str("...");
    }
    format!("body_bytes={}, body_prefix={snippet:?}", body.len())
}

fn resolve_provider_base_url(provider_id: &str, entry: &ProviderEntry) -> Result<String> {
    let registry = ProviderRegistry::standard();
    let is_copilot =
        registry.provider_for(provider_id, entry).request_kind() == ProviderRequestKind::Copilot;
    resolve_provider_base_url_with_env(provider_id, entry, is_copilot, &|name| {
        std::env::var(name).ok()
    })
}

fn resolve_provider_base_url_with_env(
    provider_id: &str,
    entry: &ProviderEntry,
    is_copilot: bool,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<String> {
    let url = if is_copilot && let Some(url) = env_var_nonempty_with(COPILOT_API_URL_ENV, lookup) {
        url.trim_end_matches('/').to_string()
    } else {
        entry.url.trim_end_matches('/').to_string()
    };
    validate_provider_base_url(provider_id, &url, entry.allow_insecure_http)?;
    Ok(url)
}

fn validate_provider_base_url(
    provider_id: &str,
    base_url: &str,
    allow_insecure_http: bool,
) -> Result<()> {
    let parsed = Url::parse(base_url)
        .with_context(|| format!("Provider `{provider_id}` has invalid base URL `{base_url}`"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if allow_insecure_http || is_loopback_or_local_url(&parsed) => Ok(()),
        "http" => anyhow::bail!(
            "Provider `{provider_id}` uses unsafe non-HTTPS base URL `{base_url}`. \
             Use HTTPS, a loopback/local HTTP URL, or enable this provider's insecure HTTP opt-in."
        ),
        scheme => anyhow::bail!(
            "Provider `{provider_id}` uses unsupported base URL scheme `{scheme}` in `{base_url}`. \
             Provider base URLs must use HTTPS, or HTTP only for loopback/local development or with the provider's insecure HTTP opt-in."
        ),
    }
}

fn is_loopback_or_local_url(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|addr| addr.is_loopback())
}

fn resolve_copilot_token() -> Result<Option<String>> {
    resolve_copilot_token_with_env(|name| std::env::var(name).ok())
}

fn resolve_copilot_token_with_env<F>(lookup: F) -> Result<Option<String>>
where
    F: Fn(&str) -> Option<String>,
{
    for name in COPILOT_TOKEN_ENV_VARS {
        if let Some(token) = env_var_nonempty_with(name, &lookup) {
            validate_copilot_token(name, &token)?;
            return Ok(Some(token));
        }
    }

    if let Some(token) = env_var_nonempty_with(COPILOT_DIRECT_API_TOKEN_ENV, &lookup) {
        validate_copilot_token(COPILOT_DIRECT_API_TOKEN_ENV, &token)?;
        return Ok(Some(token));
    }

    Ok(None)
}

fn validate_copilot_token(source: &str, token: &str) -> Result<()> {
    if token.starts_with("ghp_") {
        anyhow::bail!(
            "{source} looks like a classic GitHub PAT (`ghp_...`). \
             GitHub Copilot expects a GitHub OAuth token (`gho_`/`ghu_`), \
             a GitHub App installation token, or a fine-grained PAT \
             (`github_pat_...`) issued to an account with Copilot access."
        );
    }
    Ok(())
}

fn env_var_nonempty(name: &str) -> Option<String> {
    env_var_nonempty_with(name, |key| std::env::var(key).ok())
}

fn env_var_nonempty_with<F>(name: &str, lookup: F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(name)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn push_missing(dst: &mut Vec<String>, src: &[String]) {
    for name in src {
        if !dst.iter().any(|existing| existing == name) {
            dst.push(name.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::AuthKind;

    /// Cargo runs tests in parallel by default. Several tests below
    /// mutate process-wide env vars (`COPILOT_GITHUB_TOKEN`,
    /// `XDG_STATE_HOME`, and friends) to exercise resolver fallbacks, so
    /// they must serialize against every other test that touches those vars.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env::lock()
    }

    fn clear_copilot_env() {
        unsafe {
            std::env::remove_var("COPILOT_GITHUB_TOKEN");
            std::env::remove_var("GH_TOKEN");
            std::env::remove_var("GITHUB_TOKEN");
            std::env::remove_var("GITHUB_COPILOT_API_TOKEN");
            std::env::remove_var("COPILOT_API_URL");
        }
    }

    #[test]
    fn parses_canonical_envelope() {
        let body = r#"{
            "object":"list",
            "data":[
                {"id":"gpt-5.2","object":"model","created":1},
                {"id":"gpt-5.2-mini","object":"model","created":2}
            ]
        }"#;
        let entries = parse_models_body(body).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "gpt-5.2");
        assert!(entries[0].extra.contains_key("created"));
    }

    #[test]
    fn parses_bare_array() {
        let body = r#"[{"id":"foo"},{"id":"bar"}]"#;
        let entries = parse_models_body(body).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn parses_codex_models_envelope_empty() {
        let entries = parse_models_body(r#"{"models":[]}"#).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parses_codex_models_envelope_with_reasoning_capabilities() {
        let body = r#"{
            "models": [{
                "slug": "gpt-5.2-codex",
                "display_name": "GPT-5.2 Codex",
                "default_reasoning_level": "minimal",
                "supported_reasoning_levels": [
                    {"effort": "minimal", "label": "Minimal"},
                    {"effort": "low"},
                    {"effort": "medium"},
                    {"effort": "high"},
                    {"effort": "xhigh"}
                ],
                "family": "gpt-5"
            }]
        }"#;

        let entries = parse_models_body(body).unwrap();
        assert_eq!(entries.len(), 1);
        let model = &entries[0];
        assert_eq!(model.id, "gpt-5.2-codex");
        assert_eq!(model.name.as_deref(), Some("GPT-5.2 Codex"));
        assert_eq!(
            model.provider_metadata.get("slug").and_then(Value::as_str),
            Some("gpt-5.2-codex")
        );
        assert_eq!(
            model
                .provider_metadata
                .get("default_reasoning_level")
                .and_then(Value::as_str),
            Some("minimal")
        );
        assert_eq!(
            model
                .provider_metadata
                .get("family")
                .and_then(Value::as_str),
            Some("gpt-5")
        );

        let reasoning = model
            .capabilities
            .reasoning_effort
            .as_ref()
            .expect("reasoning capability");
        assert_eq!(reasoning.default.as_deref(), Some("minimal"));
        assert_eq!(reasoning.source, Some(CapabilitySource::Live));
        let values: Vec<_> = reasoning.values.iter().map(|v| v.value.as_str()).collect();
        assert_eq!(values, vec!["minimal", "low", "medium", "high", "xhigh"]);
        let ReasoningEffortRequestMapping::JsonField { field, values } =
            reasoning.request_mapping.as_ref().unwrap()
        else {
            panic!("Codex catalog must retain the OpenAI JSON-field mapping");
        };
        assert_eq!(field, "reasoning_effort");
        assert_eq!(values.get("xhigh"), Some(&serde_json::json!("xhigh")));
        assert!(model.thinking_modes.is_empty());
    }

    #[test]
    fn parses_live_client_side_tools_capability_metadata() {
        let body = r#"{
            "data": [{
                "id": "grok-4.20-multi-agent-0309",
                "capabilities": {
                    "client_side_tools": {
                        "status": "supported"
                    }
                }
            }]
        }"#;

        let entries = parse_models_body(body).unwrap();
        assert_eq!(entries.len(), 1);
        let capability = &entries[0].capabilities.client_side_tools;
        assert_eq!(capability.status, CapabilityStatus::Supported);
        assert_eq!(capability.source, Some(CapabilitySource::Live));
    }

    #[test]
    fn skips_entries_without_id() {
        let body = r#"{"data":[{"id":"ok"},{"object":"model"}]}"#;
        let entries = parse_models_body(body).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "ok");
    }

    #[test]
    fn captures_thinking_modes_and_inputs() {
        let body = r#"{"data":[{
            "id":"x",
            "thinking_modes":["off","high"],
            "inputs":{"images":true},
            "owned_by":"provider"
        }]}"#;
        let entries = parse_models_body(body).unwrap();
        assert_eq!(entries[0].thinking_modes.len(), 2);
        assert_eq!(entries[0].inputs.as_ref().unwrap().images, Some(true));
        assert_eq!(
            entries[0]
                .provider_metadata
                .get("owned_by")
                .and_then(serde_json::Value::as_str),
            Some("provider")
        );
        assert_eq!(
            entries[0]
                .extra
                .get("owned_by")
                .and_then(serde_json::Value::as_str),
            Some("provider")
        );
    }

    #[test]
    fn parses_openrouter_architecture_and_supported_parameters() {
        let body = r#"{"data":[{
            "id":"openai/gpt-4.1",
            "architecture":{"input_modalities":["text","image"],"output_modalities":["text"]},
            "supported_parameters":["tools","reasoning","response_format"],
            "top_provider":{"context_length":1048576}
        }]}"#;

        let entries = parse_models_body(body).unwrap();
        let model = &entries[0];
        assert_eq!(model.context_length, Some(1_048_576));
        assert_eq!(model.capabilities.context_tokens, Some(1_048_576));
        assert_eq!(model.capabilities.images, Some(true));
        assert_eq!(model.capabilities.tool_calling, CapabilityStatus::Supported);
        assert_eq!(model.capabilities.reasoning, CapabilityStatus::Supported);
        assert_eq!(
            model.capabilities.structured_outputs,
            CapabilityStatus::Supported
        );
    }

    #[test]
    fn output_only_image_modality_does_not_enable_image_input() {
        let body = r#"{"data":[{
            "id":"image-generator",
            "architecture":{"input_modalities":["text"],"output_modalities":["image"]},
            "limit":{"context":32768}
        }]}"#;

        let entries = parse_models_body(body).unwrap();
        let model = &entries[0];
        assert_eq!(model.capabilities.images, None);
        assert_eq!(model.capabilities.context_tokens, Some(32_768));
    }

    #[test]
    fn parses_anthropic_token_fields_and_object_capabilities() {
        let body = r#"{"data":[{
            "id":"claude-sonnet-4-7-20260701",
            "max_input_tokens":200000,
            "max_tokens":64000,
            "capabilities":{
                "tool_calling":{"supported":true},
                "reasoning":{"supported":true},
                "structured_outputs":{"supported":false}
            }
        }]}"#;

        let entries = parse_models_body(body).unwrap();
        let model = &entries[0];
        assert_eq!(model.context_length, Some(200_000));
        assert_eq!(model.capabilities.context_tokens, Some(200_000));
        assert_eq!(model.capabilities.max_output_tokens, Some(64_000));
        assert_eq!(model.capabilities.tool_calling, CapabilityStatus::Supported);
        assert_eq!(model.capabilities.reasoning, CapabilityStatus::Supported);
        assert_eq!(
            model.capabilities.structured_outputs,
            CapabilityStatus::Unsupported
        );
    }

    #[test]
    fn ingest_validates_anthropic_mapping() {
        let openai_shaped = parse_models_body(
            r#"{"data":[{
                "id":"claude-invalid",
                "max_output_tokens":8192,
                "capabilities":{"reasoning_effort":{
                    "values":[{"value":"high"}],
                    "default":"high",
                    "request_mapping":{"type":"json_field","field":"reasoning_effort"}
                }}
            }]}"#,
        )
        .unwrap();
        let result = FetchModelsAtResult {
            outcome: FetchOutcome::Models {
                models: openai_shaped,
                catalog: ProviderModelCatalog::Live,
            },
            status: Some(StatusCode::OK),
            body_nonempty: true,
        };
        let error = match validate_anthropic_fetch_result(
            &ProviderEntry::default(),
            "https://api.anthropic.com/v1",
            result,
        ) {
            Ok(_) => panic!("OpenAI-shaped native Anthropic mapping must be rejected"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains("rejecting invalid Anthropic catalog entry"));

        let inconsistent = parse_models_body(
            r#"{"data":[{
                "id":"claude-invalid-adaptive",
                "max_output_tokens":8192,
                "capabilities":{"reasoning_effort":{
                    "values":[{"value":"high"}],
                    "request_mapping":{"type":"anthropic_adaptive","budget_tokens":2048}
                }}
            }]}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            inconsistent.contains("invalid explicit reasoning_effort capability"),
            "{inconsistent}"
        );

        let unknown_adaptive_target = parse_models_body(
            r#"{"data":[{
                "id":"claude-invalid-effort",
                "max_output_tokens":8192,
                "capabilities":{"reasoning_effort":{
                    "values":[{"value":"xhigh"}],
                    "request_mapping":{"type":"anthropic_adaptive"}
                }}
            }]}"#,
        )
        .unwrap();
        let result = FetchModelsAtResult {
            outcome: FetchOutcome::Models {
                models: unknown_adaptive_target,
                catalog: ProviderModelCatalog::Live,
            },
            status: Some(StatusCode::OK),
            body_nonempty: true,
        };
        let error = match validate_anthropic_fetch_result(
            &ProviderEntry::default(),
            "https://api.anthropic.com/v1",
            result,
        ) {
            Ok(_) => panic!("unknown adaptive Anthropic targets must be rejected"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains("unsupported target `xhigh`"), "{error}");

        let manual_without_limit = parse_models_body(
            r#"{"data":[{
                "id":"claude-manual",
                "capabilities":{"reasoning_effort":{
                    "values":[{"value":"low"}],
                    "request_mapping":{"type":"anthropic_manual"}
                }}
            }]}"#,
        )
        .unwrap();
        let result = FetchModelsAtResult {
            outcome: FetchOutcome::Models {
                models: manual_without_limit,
                catalog: ProviderModelCatalog::Live,
            },
            status: Some(StatusCode::OK),
            body_nonempty: true,
        };
        let error = match validate_anthropic_fetch_result(
            &ProviderEntry::default(),
            "https://api.anthropic.com/v1",
            result,
        ) {
            Ok(_) => panic!("manual Anthropic mapping without an output limit must be rejected"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains("no output limit"), "{error}");

        let valid = parse_models_body(
            r#"{"data":[{
                "id":"claude-adaptive",
                "max_output_tokens":8192,
                "capabilities":{"reasoning_effort":{
                    "values":[{"value":"high"}],
                    "default":"high",
                    "request_mapping":{"type":"anthropic_adaptive"}
                }}
            }]}"#,
        )
        .unwrap();
        let result = FetchModelsAtResult {
            outcome: FetchOutcome::Models {
                models: valid,
                catalog: ProviderModelCatalog::Live,
            },
            status: Some(StatusCode::OK),
            body_nonempty: true,
        };
        validate_anthropic_fetch_result(
            &ProviderEntry::default(),
            "https://api.anthropic.com/v1",
            result,
        )
        .unwrap();
    }

    #[test]
    fn malformed_huge_models_body_error_is_capped() {
        let body = format!("{{\"data\":{}", "x".repeat(10_000));
        let err = parse_models_body(&body).unwrap_err().to_string();

        assert!(err.contains("parsing /models response"));
        assert!(err.contains("body_bytes=10008"));
        assert!(err.contains("body_prefix="));
        assert!(err.contains("..."));
        assert!(!err.contains(&"x".repeat(300)));
    }

    #[test]
    fn response_body_snippet_preserves_char_boundaries_and_marks_truncation() {
        let body = format!("{}tail", "é".repeat(ERROR_BODY_SNIPPET_CHARS));
        let snippet = response_body_snippet(&body);

        assert!(snippet.contains(&format!("body_bytes={}", body.len())));
        assert!(snippet.contains("..."));
        assert!(!snippet.contains("tail"));
    }

    #[test]
    fn resolve_headers_collects_missing_once() {
        let h = vec![
            HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $NONEXISTENT_VAR_123".into(),
            },
            HeaderSpec {
                name: "x-second".into(),
                value: "$NONEXISTENT_VAR_123".into(),
            },
        ];
        let (resolved, missing) = resolve_headers(&h);
        assert_eq!(resolved.len(), 2);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], "NONEXISTENT_VAR_123");
    }

    #[test]
    fn resolve_headers_expands_injected_secret_refs() {
        let headers = vec![HeaderSpec {
            name: "Authorization".into(),
            value: "Bearer $secret:openai".into(),
        }];
        let (resolved, missing) = resolve_headers_with_sources(
            &headers,
            |_| None,
            |name| (name == "openai").then(|| "sk-request-secret".to_string()),
        );

        assert!(missing.is_empty());
        assert_eq!(resolved[0].value, "Bearer sk-request-secret");
    }

    #[test]
    fn resolved_request_expands_injected_secret_refs() {
        let entry = ProviderEntry {
            url: "https://api.example.test/v1".into(),
            headers: vec![HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $secret:openai".into(),
            }],
            ..Default::default()
        };
        let request = resolve_provider_request_with_sources(
            "custom",
            &entry,
            |_| None,
            |name| (name == "openai").then(|| "sk-request-secret".to_string()),
        )
        .unwrap();

        assert_eq!(
            header_pairs(&request),
            vec![("Authorization", "Bearer sk-request-secret")]
        );
    }

    fn header_pairs(request: &ResolvedRequest) -> Vec<(&str, &str)> {
        request
            .headers
            .iter()
            .map(|header| (header.name.as_str(), header.value.as_str()))
            .collect()
    }

    #[test]
    fn resolved_request_debug_redacts_header_values() {
        let resolved = ResolvedRequest {
            base_url: "https://api.example.com/v1".into(),
            headers: vec![ResolvedHeader {
                name: "Authorization".into(),
                value: "Bearer fixture-secret-token".into(),
            }],
        };

        let rendered = format!("{resolved:?}");

        assert!(rendered.contains("Authorization"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("fixture-secret-token"), "{rendered}");
    }

    #[test]
    fn copilot_falls_back_to_gh_token_when_default_header_var_is_missing() {
        let _g = env_lock();
        clear_copilot_env();
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $COPILOT_GITHUB_TOKEN".into(),
            }],
            ..ProviderEntry::default()
        };
        unsafe {
            std::env::set_var("GH_TOKEN", "ghu_test");
        }
        let resolved = resolve_provider_request("copilot", &entry).unwrap();
        let auth = resolved
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.value, "Bearer ghu_test");
        clear_copilot_env();
    }

    #[test]
    fn copilot_uses_direct_api_url_override() {
        let _g = env_lock();
        clear_copilot_env();
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![],
            ..ProviderEntry::default()
        };
        unsafe {
            std::env::set_var("GITHUB_COPILOT_API_TOKEN", "token");
            std::env::set_var("COPILOT_API_URL", "https://copilot-proxy.example/v1/");
        }
        let resolved = resolve_provider_request("copilot", &entry).unwrap();
        assert_eq!(resolved.base_url, "https://copilot-proxy.example/v1");
        clear_copilot_env();
    }

    #[test]
    fn copilot_rejects_classic_pat() {
        let _g = env_lock();
        clear_copilot_env();
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![],
            ..ProviderEntry::default()
        };
        unsafe {
            std::env::set_var("COPILOT_GITHUB_TOKEN", "ghp_legacy");
        }
        let err = resolve_provider_request("copilot", &entry).unwrap_err();
        assert!(err.to_string().contains("classic GitHub PAT"));
        clear_copilot_env();
    }

    #[test]
    fn copilot_detected_via_url_when_provider_id_differs() {
        // A user might add a Copilot endpoint under a custom id; the
        // resolver still picks up the documented env-var fallbacks.
        let _g = env_lock();
        clear_copilot_env();
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![],
            ..ProviderEntry::default()
        };
        unsafe {
            std::env::set_var("COPILOT_GITHUB_TOKEN", "gho_via_url");
        }
        let resolved = resolve_provider_request("my-copilot", &entry).unwrap();
        let auth = resolved
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.value, "Bearer gho_via_url");
        clear_copilot_env();
    }

    #[test]
    fn copilot_priority_prefers_copilot_github_token_over_gh_token() {
        // With both vars set the highest-priority source wins.
        let _g = env_lock();
        clear_copilot_env();
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![],
            ..ProviderEntry::default()
        };
        unsafe {
            std::env::set_var("COPILOT_GITHUB_TOKEN", "gho_primary");
            std::env::set_var("GH_TOKEN", "gho_secondary");
            std::env::set_var("GITHUB_TOKEN", "gho_tertiary");
        }
        let resolved = resolve_provider_request("copilot", &entry).unwrap();
        let auth = resolved
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.value, "Bearer gho_primary");
        clear_copilot_env();
    }

    #[test]
    fn copilot_errors_when_no_env_var_set() {
        // Sanity check: with no headers and no env vars, the resolver
        // emits the documented-token guidance instead of falling back
        // to the legacy device-code path.
        let _g = env_lock();
        clear_copilot_env();
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![],
            ..ProviderEntry::default()
        };
        let err = resolve_provider_request("copilot", &entry).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("COPILOT_GITHUB_TOKEN"));
        assert!(msg.contains("GH_TOKEN"));
        assert!(msg.contains("GITHUB_TOKEN"));
        // Critically, the message must not point users at the old
        // device-code login path.
        assert!(!msg.contains("device-code"));
        assert!(!msg.contains("copilot_internal"));
    }

    #[test]
    fn non_copilot_provider_with_missing_auth_env_errors() {
        // A non-Copilot provider whose `Authorization` references an
        // unset var must NOT silently fall back to Copilot env vars.
        let _g = env_lock();
        clear_copilot_env();
        let entry = ProviderEntry {
            url: "https://api.example.com/v1".into(),
            headers: vec![HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $TOTALLY_UNSET_VAR_PROBE".into(),
            }],
            ..ProviderEntry::default()
        };
        unsafe {
            std::env::remove_var("TOTALLY_UNSET_VAR_PROBE");
            // Even if a Copilot fallback is set, a non-Copilot
            // provider must not pick it up.
            std::env::set_var("COPILOT_GITHUB_TOKEN", "gho_should_not_leak");
        }
        let err = resolve_provider_request("some-vendor", &entry).unwrap_err();
        assert!(err.to_string().contains("TOTALLY_UNSET_VAR_PROBE"));
        clear_copilot_env();
    }

    #[test]
    fn non_copilot_provider_without_auth_resolves_unauthenticated() {
        // A fully-local endpoint (e.g. LM Studio) has no Authorization
        // header. That must resolve cleanly so /models can be fetched
        // unauthenticated rather than erroring out.
        let _g = env_lock();
        clear_copilot_env();
        let entry = ProviderEntry {
            url: "http://localhost:1234/v1".into(),
            headers: vec![],
            ..ProviderEntry::default()
        };
        let resolved = resolve_provider_request("lmstudio", &entry).unwrap();
        assert!(
            !resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("authorization"))
        );
    }

    #[test]
    fn grok_oauth_sync_resolver_requires_login() {
        let entry = ProviderEntry {
            url: "https://api.x.ai/v1".into(),
            credential_ref: Some(crate::auth::xai_oauth::CREDENTIAL_KEY.to_string()),
            ..ProviderEntry::default()
        };
        assert_eq!(
            ProviderRegistry::standard()
                .provider_for("custom-grok", &entry)
                .id(),
            crate::auth::xai_oauth::CREDENTIAL_KEY
        );
        let err = resolve_provider_request("custom-grok", &entry).unwrap_err();
        assert!(err.to_string().contains("Grok subscription auth required"));
    }

    #[tokio::test]
    async fn grok_oauth_async_resolver_injects_stored_bearer() {
        let _g = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("XDG_STATE_HOME", tmp.path());
        }
        let mut store = crate::credentials::CredentialStore::open_default().unwrap();
        store.set(
            crate::auth::xai_oauth::CREDENTIAL_KEY,
            serde_json::json!({
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "expires_at": i64::MAX
            }),
        );
        store.save().unwrap();

        let entry = ProviderEntry {
            url: "https://api.x.ai/v1".into(),
            credential_ref: Some(crate::auth::xai_oauth::CREDENTIAL_KEY.to_string()),
            ..ProviderEntry::default()
        };
        let resolved = resolve_provider_request_async("grok-oauth", &entry)
            .await
            .unwrap();
        let auth = resolved
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.value, "Bearer access-1");
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
        }
    }

    #[test]
    fn codex_oauth_sync_resolver_requires_login() {
        let entry = ProviderEntry {
            url: crate::auth::codex_oauth::DEFAULT_BASE_URL.into(),
            auth: Some(AuthKind::OAuth),
            ..ProviderEntry::default()
        };
        assert_eq!(
            ProviderRegistry::standard()
                .provider_for("custom-codex", &entry)
                .id(),
            crate::auth::codex_oauth::CREDENTIAL_KEY
        );
        let err = resolve_provider_request("custom-codex", &entry).unwrap_err();
        assert!(err.to_string().contains("Codex subscription auth required"));
    }

    #[tokio::test]
    async fn codex_oauth_async_resolver_injects_stored_bearer_and_codex_headers() {
        let _g = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("XDG_STATE_HOME", tmp.path());
        }
        let mut store = crate::credentials::CredentialStore::open_default().unwrap();
        store.set(
            crate::auth::codex_oauth::CREDENTIAL_KEY,
            serde_json::json!({
                "access_token": "codex-access-1",
                "refresh_token": "codex-refresh-1",
                "id_token": "id-token-1",
                "account_id": "acc_123",
                "expires_at": i64::MAX
            }),
        );
        store.save().unwrap();

        let entry = ProviderEntry {
            url: crate::auth::codex_oauth::DEFAULT_BASE_URL.into(),
            credential_ref: Some(crate::auth::codex_oauth::CREDENTIAL_KEY.to_string()),
            ..ProviderEntry::default()
        };
        let resolved = resolve_provider_request_async("codex-oauth", &entry)
            .await
            .unwrap();
        let auth = resolved
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.value, "Bearer codex-access-1");
        assert!(
            resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("chatgpt-account-id") && h.value == "acc_123")
        );
        assert!(
            resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("originator") && h.value == "cockpit")
        );
        assert!(
            resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("OpenAI-Beta")
                    && h.value == "responses=experimental")
        );
        assert!(
            resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("session_id") && !h.value.is_empty())
        );
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
        }
    }

    fn codex_tokens(account_id: Option<&str>) -> crate::auth::codex_oauth::StoredTokens {
        crate::auth::codex_oauth::StoredTokens {
            access_token: "codex-access-1".to_string(),
            refresh_token: "codex-refresh-1".to_string(),
            id_token: Some("id-token-1".to_string()),
            account_id: account_id.map(str::to_string),
            expires_at: i64::MAX,
        }
    }

    fn install_codex_tokens(tmp: &tempfile::TempDir) {
        unsafe {
            std::env::set_var("XDG_STATE_HOME", tmp.path());
        }
        let mut store = crate::credentials::CredentialStore::open_default().unwrap();
        store.set(
            crate::auth::codex_oauth::CREDENTIAL_KEY,
            serde_json::json!({
                "access_token": "codex-access-1",
                "refresh_token": "codex-refresh-1",
                "id_token": "id-token-1",
                "account_id": "acc_123",
                "expires_at": i64::MAX
            }),
        );
        store.save().unwrap();
    }

    struct TestModelResponse {
        status: u16,
        headers: Vec<(&'static str, &'static str)>,
        body: &'static str,
    }

    impl TestModelResponse {
        fn ok(body: &'static str) -> Self {
            Self {
                status: 200,
                headers: Vec::new(),
                body,
            }
        }

        fn status(status: u16, body: &'static str) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body,
            }
        }

        fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
            self.headers.push((name, value));
            self
        }
    }

    async fn serve_model_responses(
        responses: Vec<TestModelResponse>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut requests = Vec::new();
            for response in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0_u8; 1024];
                loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                requests.push(String::from_utf8_lossy(&request).into_owned());

                let status_text = if response.status == 200 {
                    "OK"
                } else {
                    "ERROR"
                };
                let mut raw = format!(
                    "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
                    response.status,
                    status_text,
                    response.body.len()
                );
                for (name, value) in response.headers {
                    raw.push_str(name);
                    raw.push_str(": ");
                    raw.push_str(value);
                    raw.push_str("\r\n");
                }
                raw.push_str("\r\n");
                raw.push_str(response.body);
                socket.write_all(raw.as_bytes()).await.unwrap();
            }
            requests
        });
        tokio::task::yield_now().await;
        (format!("http://{addr}/v1"), handle)
    }

    async fn serve_models_once(body: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let (base, handle) = serve_model_responses(vec![TestModelResponse::ok(body)]).await;
        let handle =
            tokio::spawn(
                async move { handle.await.unwrap().into_iter().next().unwrap_or_default() },
            );
        (base, handle)
    }

    fn request_header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
        let needle = format!("{}:", name.to_ascii_lowercase());
        request.lines().find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .starts_with(&needle)
                .then(|| line.split_once(':').map(|(_, value)| value.trim()))?
        })
    }

    fn codex_entry(base_url: String) -> ProviderEntry {
        ProviderEntry {
            url: base_url,
            credential_ref: Some(crate::auth::codex_oauth::CREDENTIAL_KEY.to_string()),
            allow_insecure_http: true,
            ..ProviderEntry::default()
        }
    }

    #[test]
    fn codex_oauth_model_list_request_uses_codex_shape() {
        let entry = ProviderEntry {
            url: crate::auth::codex_oauth::DEFAULT_BASE_URL.into(),
            credential_ref: Some(crate::auth::codex_oauth::CREDENTIAL_KEY.to_string()),
            ..ProviderEntry::default()
        };

        let resolved = resolve_codex_model_list_request(
            "codex-oauth",
            &entry,
            codex_tokens(Some("acc_123")),
            &|_| None,
        )
        .unwrap();
        let url = models_url_for_provider("codex-oauth", &entry, &resolved.base_url);

        let parsed = Url::parse(&url).unwrap();
        let client_versions: Vec<_> = parsed
            .query_pairs()
            .filter(|(key, _)| key == "client_version")
            .map(|(_, value)| value.into_owned())
            .collect();
        assert_eq!(
            client_versions,
            vec![codex_model_list_client_version().to_string()]
        );
        if env!("CARGO_PKG_VERSION") != codex_model_list_client_version() {
            assert_ne!(client_versions, vec![env!("CARGO_PKG_VERSION").to_string()]);
        }

        assert!(
            resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("authorization")
                    && h.value == "Bearer codex-access-1")
        );
        assert!(
            resolved
                .headers
                .iter()
                .any(|h| h.name == "ChatGPT-Account-ID" && h.value == "acc_123")
        );
        assert!(
            !resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("originator"))
        );
        assert!(
            !resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("user-agent"))
        );
        assert!(
            !resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("version"))
        );
        assert!(
            !resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("OpenAI-Beta"))
        );
        assert!(
            !resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("session_id"))
        );
    }

    #[tokio::test]
    async fn codex_empty_success_responses_offer_fallback_catalog() {
        let _g = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        install_codex_tokens(&tmp);

        for body in [r#"{"data":[]}"#, r#"{"models":[]}"#, "[]"] {
            let (base_url, request_handle) = serve_models_once(body).await;
            let entry = codex_entry(base_url.clone());
            let resolved = ResolvedRequest {
                base_url,
                headers: Vec::new(),
            };

            let outcome =
                fetch_models_for_provider("codex-oauth", &entry, &resolved, Duration::from_secs(5))
                    .await
                    .unwrap();

            let request = request_handle.await.unwrap();
            assert!(request.starts_with("GET /v1/models?client_version=0.0.0 "));
            assert_eq!(
                request_header_value(&request, "authorization"),
                Some("Bearer codex-access-1")
            );
            assert_eq!(
                request_header_value(&request, "chatgpt-account-id"),
                Some("acc_123")
            );
            assert_eq!(
                request_header_value(&request, "accept"),
                Some("application/json")
            );
            assert!(request_header_value(&request, "openai-beta").is_none());
            assert!(request_header_value(&request, "originator").is_none());
            assert!(request_header_value(&request, "session_id").is_none());
            assert!(request_header_value(&request, "version").is_none());
            assert_eq!(
                request_header_value(&request, "user-agent"),
                Some(crate::user_agent::user_agent())
            );

            match outcome {
                FetchOutcome::FallbackAvailable {
                    models,
                    catalog,
                    reason,
                } => {
                    assert_eq!(catalog, ProviderModelCatalog::CodexFallback);
                    assert_eq!(models.len(), 3);
                    assert!(reason.contains("empty model list"));
                    assert!(reason.contains("status 200 OK"));
                }
                other => panic!("expected fallback for empty Codex response, got {other:?}"),
            }
        }

        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
        }
    }

    #[tokio::test]
    async fn non_codex_empty_success_response_remains_live_empty_catalog() {
        let (base_url, request_handle) = serve_models_once(r#"{"data":[]}"#).await;
        let entry = ProviderEntry {
            url: base_url.clone(),
            allow_insecure_http: true,
            ..ProviderEntry::default()
        };
        let resolved = ResolvedRequest {
            base_url,
            headers: Vec::new(),
        };

        let outcome = fetch_models_for_provider("local", &entry, &resolved, Duration::from_secs(5))
            .await
            .unwrap();
        let request = request_handle.await.unwrap();
        assert_eq!(
            request_header_value(&request, "user-agent"),
            Some(crate::user_agent::user_agent())
        );

        match outcome {
            FetchOutcome::Models { models, catalog } => {
                assert!(models.is_empty());
                assert_eq!(catalog, ProviderModelCatalog::Live);
            }
            other => panic!("expected live empty catalog for non-Codex, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn codex_nonempty_slug_response_remains_live_catalog() {
        let _g = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        install_codex_tokens(&tmp);
        let (base_url, request_handle) =
            serve_models_once(r#"{"models":[{"slug":"gpt-5.5","display_name":"GPT-5.5"}]}"#).await;
        let entry = codex_entry(base_url.clone());
        let resolved = ResolvedRequest {
            base_url,
            headers: Vec::new(),
        };

        let outcome =
            fetch_models_for_provider("codex-oauth", &entry, &resolved, Duration::from_secs(5))
                .await
                .unwrap();
        let _ = request_handle.await.unwrap();

        match outcome {
            FetchOutcome::Models { models, catalog } => {
                assert_eq!(catalog, ProviderModelCatalog::Live);
                assert_eq!(models.len(), 1);
                assert_eq!(models[0].id, "gpt-5.5");
                assert_eq!(models[0].name.as_deref(), Some("GPT-5.5"));
            }
            other => panic!("expected live Codex catalog, got {other:?}"),
        }

        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
        }
    }

    #[tokio::test]
    async fn codex_auth_failures_do_not_offer_fallback_catalog() {
        let _g = env_lock();
        let tmp = tempfile::tempdir().unwrap();
        install_codex_tokens(&tmp);

        for status in [401, 403] {
            let (base_url, request_handle) =
                serve_model_responses(vec![TestModelResponse::status(
                    status,
                    r#"{"error":"denied"}"#,
                )])
                .await;
            let entry = codex_entry(base_url.clone());
            let resolved = ResolvedRequest {
                base_url,
                headers: Vec::new(),
            };

            let err =
                fetch_models_for_provider("codex-oauth", &entry, &resolved, Duration::from_secs(5))
                    .await
                    .unwrap_err();
            assert!(err.to_string().contains(&format!("returned {status}")));
            assert_eq!(request_handle.await.unwrap().len(), 1);
        }

        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
        }
    }

    #[tokio::test]
    async fn oversized_success_response_body_errors_before_parse() {
        let mut body = String::from(r#"{"data":[]}"#);
        body.push_str(&" ".repeat(MAX_MODELS_RESPONSE_BYTES));
        let body: &'static str = Box::leak(body.into_boxed_str());
        let (base_url, request_handle) = serve_models_once(body).await;
        let entry = ProviderEntry {
            url: base_url.clone(),
            allow_insecure_http: true,
            ..ProviderEntry::default()
        };
        let resolved = ResolvedRequest {
            base_url,
            headers: Vec::new(),
        };

        let err = fetch_models_for_provider("local", &entry, &resolved, Duration::from_secs(5))
            .await
            .unwrap_err();
        let _ = request_handle.await.unwrap();

        let message = err.to_string();
        assert!(
            message.contains("/models response body exceeded"),
            "{message}"
        );
        assert!(
            message.contains(&MAX_MODELS_RESPONSE_BYTES.to_string()),
            "{message}"
        );
    }

    #[tokio::test]
    async fn model_fetch_retries_retry_after_rate_limit_then_succeeds() {
        let (base_url, request_handle) = serve_model_responses(vec![
            TestModelResponse::status(429, r#"{"error":"slow"}"#).with_header("Retry-After", "0"),
            TestModelResponse::ok(r#"{"data":[{"id":"ok"}]}"#),
        ])
        .await;
        let entry = ProviderEntry {
            url: base_url.clone(),
            allow_insecure_http: true,
            ..ProviderEntry::default()
        };
        let resolved = ResolvedRequest {
            base_url,
            headers: Vec::new(),
        };

        let outcome = fetch_models_for_provider("local", &entry, &resolved, Duration::from_secs(5))
            .await
            .unwrap();
        let requests = request_handle.await.unwrap();
        assert_eq!(requests.len(), 2);
        match outcome {
            FetchOutcome::Models { models, catalog } => {
                assert_eq!(catalog, ProviderModelCatalog::Live);
                assert_eq!(models[0].id, "ok");
            }
            other => panic!("expected retry to live catalog, got {other:?}"),
        }
    }

    #[test]
    fn codex_oauth_model_list_missing_account_id_keeps_error_message() {
        let entry = ProviderEntry {
            url: crate::auth::codex_oauth::DEFAULT_BASE_URL.into(),
            credential_ref: Some(crate::auth::codex_oauth::CREDENTIAL_KEY.to_string()),
            ..ProviderEntry::default()
        };

        let err =
            resolve_codex_model_list_request("codex-oauth", &entry, codex_tokens(None), &|_| None)
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Codex subscription auth is missing chatgpt-account-id; set up OAuth in /settings → Providers."
        );
    }

    #[test]
    fn non_codex_model_list_url_has_no_codex_query() {
        let entry = ProviderEntry {
            url: "https://api.example.com/v1".into(),
            headers: vec![HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $TOKEN".into(),
            }],
            ..ProviderEntry::default()
        };
        let resolved = resolve_provider_request_with_env("openai-compatible", &entry, |name| {
            (name == "TOKEN").then(|| "key-1".to_string())
        })
        .unwrap();

        assert_eq!(
            models_url_for_provider("openai-compatible", &entry, &resolved.base_url),
            "https://api.example.com/v1/models"
        );
        assert!(
            !resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("originator"))
        );
        assert!(
            !resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("OpenAI-Beta"))
        );
        assert!(
            !resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("session_id"))
        );
    }

    #[test]
    fn synthetic_openai_compatible_template_uses_template_provider_fallback() {
        let template = crate::providers::ProviderTemplate {
            id: "synthetic-openai-compatible",
            display: "Synthetic OpenAI-compatible",
            url: "https://synthetic.example/v1",
            auth: AuthKind::ApiKey,
            default_env_var: Some("SYNTHETIC_API_KEY"),
            env_var_candidates: &[],
            default_headers: &[("Authorization", "Bearer $SYNTHETIC_API_KEY")],
            supports_models_endpoint: true,
            hint: None,
            use_id_as_default: true,
            default_wire_api: crate::config::providers::WireApi::Auto,
            api_key: Some(crate::providers::ApiKeyTemplate {
                header_name: "Authorization",
                value_template: "Bearer {key}",
                format_hint: "synthetic key",
                console_url: "https://synthetic.example/keys",
            }),
            auth_check: crate::providers::AuthCheckKind::ModelsEndpoint,
        };
        let entry = ProviderEntry {
            url: template.url.to_string(),
            headers: crate::providers::default_headers_for(&template),
            ..ProviderEntry::default()
        };
        let lookup = |name: &str| (name == "SYNTHETIC_API_KEY").then(|| "key-1".to_string());
        let registry = ProviderRegistry::standard();
        let provider = registry.provider_for(template.id, &entry);

        assert_eq!(provider.id(), "template");

        let via_registry = provider
            .request(template.id, &entry, None, &lookup)
            .unwrap();
        let via_public = resolve_provider_request_with_env(template.id, &entry, lookup).unwrap();
        assert_eq!(via_registry.base_url, via_public.base_url);
        assert_eq!(header_pairs(&via_registry), header_pairs(&via_public));
        assert_eq!(
            provider.models_url(&entry, &via_registry.base_url),
            models_url_for_provider(template.id, &entry, &via_public.base_url)
        );
    }

    #[test]
    fn standard_special_provider_matches_are_mutually_exclusive() {
        let registry = ProviderRegistry::standard();
        let cases = [
            (
                "codex-oauth",
                ProviderEntry {
                    url: crate::auth::codex_oauth::DEFAULT_BASE_URL.into(),
                    auth: Some(AuthKind::OAuth),
                    ..ProviderEntry::default()
                },
                crate::auth::codex_oauth::CREDENTIAL_KEY,
            ),
            (
                "grok-oauth",
                ProviderEntry {
                    url: "https://api.x.ai/v1".into(),
                    auth: Some(AuthKind::OAuth),
                    ..ProviderEntry::default()
                },
                crate::auth::xai_oauth::CREDENTIAL_KEY,
            ),
            (
                "copilot",
                ProviderEntry {
                    url: "https://api.githubcopilot.com".into(),
                    ..ProviderEntry::default()
                },
                "copilot",
            ),
        ];

        for (provider_id, entry, expected) in cases {
            let matches = registry.special_match_ids(provider_id, &entry);
            assert_eq!(
                matches,
                vec![expected],
                "unexpected matches for {provider_id}"
            );
        }
    }

    #[test]
    fn codex_model_list_fallback_catalog_is_hardcoded_and_effort_free() {
        let entry = ProviderEntry {
            url: crate::auth::codex_oauth::DEFAULT_BASE_URL.into(),
            credential_ref: Some(crate::auth::codex_oauth::CREDENTIAL_KEY.to_string()),
            ..ProviderEntry::default()
        };
        let models = ProviderRegistry::standard()
            .provider_for("codex-oauth", &entry)
            .fallback_models();
        let ids: Vec<_> = models.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["gpt-5.5", "gpt-5.4", "gpt-5.4-mini"]);
        assert!(models.iter().all(|m| m.thinking_modes.is_empty()));
        assert!(models.iter().all(|m| m.capabilities.is_empty()));
        assert!(models.iter().all(|m| m.inputs.is_none()));
    }

    #[test]
    fn provider_base_url_policy_accepts_https() {
        let entry = ProviderEntry {
            url: "https://api.example.com/v1/".into(),
            ..ProviderEntry::default()
        };
        let resolved = resolve_provider_request("safe", &entry).unwrap();
        assert_eq!(resolved.base_url, "https://api.example.com/v1");
    }

    #[test]
    fn provider_base_url_policy_accepts_http_loopback_hosts() {
        for url in [
            "http://localhost:1234/v1",
            "http://127.0.0.1:1234/v1",
            "http://[::1]:1234/v1",
        ] {
            let entry = ProviderEntry {
                url: url.into(),
                ..ProviderEntry::default()
            };
            let resolved = resolve_provider_request("local", &entry).unwrap();
            assert_eq!(resolved.base_url, url);
        }
    }

    #[test]
    fn provider_base_url_policy_rejects_http_non_loopback_by_default() {
        let entry = ProviderEntry {
            url: "http://api.example.com/v1".into(),
            ..ProviderEntry::default()
        };
        let err = resolve_provider_request("plain", &entry).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("plain"));
        assert!(msg.contains("http://api.example.com/v1"));
        assert!(msg.contains("unsafe non-HTTPS"));
    }

    #[test]
    fn provider_base_url_policy_allows_http_non_loopback_with_provider_opt_in() {
        let entry = ProviderEntry {
            url: "http://api.example.com/v1".into(),
            allow_insecure_http: true,
            ..ProviderEntry::default()
        };
        let resolved = resolve_provider_request("plain", &entry).unwrap();
        assert_eq!(resolved.base_url, "http://api.example.com/v1");
    }

    #[test]
    fn copilot_template_is_apikey_with_documented_default_env() {
        // The Add-Provider wizard should no longer offer a device-code
        // flow for Copilot. Pin the template's shape so it can't
        // regress.
        let t = crate::providers::template_by_id("copilot").expect("copilot template");
        assert!(matches!(t.auth, crate::config::providers::AuthKind::ApiKey));
        assert_eq!(t.default_env_var, Some("COPILOT_GITHUB_TOKEN"));
        assert_eq!(t.default_headers.len(), 1);
        assert_eq!(t.default_headers[0].0, "Authorization");
        assert_eq!(t.default_headers[0].1, "Bearer $COPILOT_GITHUB_TOKEN");
    }
}
