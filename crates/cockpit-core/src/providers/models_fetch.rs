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
    CapabilitySource, CapabilityStatus, CapabilityValue, ClientSideToolsCapability,
    EndpointReasoningEffortRequestMapping, HeaderSpec, ModelCapabilities, ModelEntry,
    ProviderEntry, ProviderModelCatalog, ReasoningEffortCapability, ReasoningEffortRequestMapping,
    ThinkingMode, WireApi, validate_anthropic_model_configuration,
};
use crate::envref;
#[cfg(not(test))]
use crate::providers::registry::ResolvedProviderOrigin;
use crate::providers::registry::{
    OAuthCredential, ProviderCredentialKind, ProviderRegistry, ProviderRequestKind,
};

const COPILOT_TOKEN_ENV_VARS: [&str; 3] = ["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"];
const COPILOT_DIRECT_API_TOKEN_ENV: &str = "GITHUB_COPILOT_API_TOKEN";
pub const COPILOT_TOKEN_CREDENTIAL_KEY: &str = "copilot-github-token";
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
    /// True only when Cockpit resolved a Codex OAuth credential for this
    /// request. Header names are request data and must not be used to infer
    /// credential ownership.
    pub(crate) is_codex_credential: bool,
    /// Generation of the command credential that authenticated this exact
    /// request. A 401/403 retry must present this value to the refresh path so
    /// a late rejection can reuse a concurrent winner instead of re-running
    /// the user's command.
    #[cfg(not(test))]
    pub(crate) command_credential_generation: Option<u64>,
    #[cfg(not(test))]
    pub(crate) origin: ResolvedProviderOrigin,
}

impl fmt::Debug for ResolvedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("ResolvedRequest");
        debug
            .field("base_url", &self.base_url)
            .field("headers", &self.headers)
            .field("is_codex_credential", &self.is_codex_credential);
        #[cfg(not(test))]
        debug.field("origin", &self.origin);
        debug.finish()
    }
}

impl ResolvedRequest {
    /// Returns the command-credential generation bound to this request. Unit
    /// test literals intentionally omit production-only request provenance.
    pub(crate) fn command_credential_generation(&self) -> Option<u64> {
        #[cfg(not(test))]
        {
            self.command_credential_generation
        }
        #[cfg(test)]
        {
            None
        }
    }
}

/// Resolve environment and named-secret references in every header, collecting
/// missing references into one list. Caller decides whether to abort or warn.
pub fn resolve_headers(headers: &[HeaderSpec]) -> (Vec<ResolvedHeader>, Vec<String>) {
    resolve_headers_with_sources(headers, |name| std::env::var(name).ok(), |_| None)
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
    if entry.auth_command.is_some() {
        anyhow::bail!(
            "provider `{provider_id}` auth_command requires an injected credential store"
        );
    }
    let registry = ProviderRegistry::standard();
    if registry
        .provider_for(provider_id, entry)
        .credential_kind()
        .is_some()
    {
        anyhow::bail!("Codex/Grok OAuth requires an injected credential store");
    }
    registry
        .provider_for(provider_id, entry)
        .request(provider_id, entry, None, &|name| std::env::var(name).ok())
}

pub async fn resolve_provider_request_async_with_store(
    provider_id: &str,
    entry: &ProviderEntry,
    store: crate::credentials::CredentialStore,
    env_lookup: impl Fn(&str) -> Option<String> + Sync,
) -> Result<ResolvedRequest> {
    resolve_provider_request_async_with_store_refresh(
        provider_id,
        entry,
        store,
        &env_lookup,
        false,
        None,
    )
    .await
}

/// Re-resolve a command-authenticated request after an explicit provider
/// rejection.  The environment lookup is deliberately supplied by the caller:
/// it is part of the resolved command argv and therefore part of the command
/// credential's configuration identity.  Do not replace it with the daemon's
/// ambient environment on refresh.
pub async fn refresh_provider_request_async_with_store(
    provider_id: &str,
    entry: &ProviderEntry,
    store: crate::credentials::CredentialStore,
    env_lookup: impl Fn(&str) -> Option<String> + Sync,
    rejected_refresh_generation: Option<u64>,
) -> Result<Option<ResolvedRequest>> {
    if entry.auth_command.is_none() {
        return Ok(None);
    }
    let rejected_refresh_generation = rejected_refresh_generation.context(
        "command-authenticated request is missing the credential generation used for its rejection",
    )?;
    resolve_provider_request_async_with_store_refresh(
        provider_id,
        entry,
        store,
        &env_lookup,
        true,
        Some(rejected_refresh_generation),
    )
    .await
    .map(Some)
}

/// Re-resolve a long-lived command-authenticated request using the provider
/// entry authorized after this refresh owns the serialized execution turn.
///
/// A live client supplies `authorize_entry` instead of a cloned entry because
/// config can reload while the refresh waits behind another request.
pub(crate) async fn refresh_provider_request_async_with_store_authorized<F>(
    provider_id: &str,
    store: crate::credentials::CredentialStore,
    env_lookup: impl Fn(&str) -> Option<String> + Sync,
    rejected_refresh_generation: Option<u64>,
    authorize_entry: F,
) -> Result<ResolvedRequest>
where
    F: FnOnce() -> Result<ProviderEntry>,
{
    let (entry, command_credential) = crate::auth::command::resolve_authorized(
        provider_id,
        store.clone(),
        &env_lookup,
        true,
        rejected_refresh_generation,
        authorize_entry,
    )
    .await?;
    #[cfg(not(test))]
    let command_credential_generation = command_credential.refresh_generation;
    let registry = ProviderRegistry::standard();
    let credential = Some(OAuthCredential::Command(command_credential));
    let secret_lookup = |name: &str| store.named_secret(name).map(str::to_string);
    let request = resolve_provider_request_inner_with_sources(
        provider_id,
        &entry,
        credential,
        registry.provider_for(provider_id, &entry).request_kind(),
        &env_lookup,
        &secret_lookup,
    )?;
    #[cfg(not(test))]
    {
        let mut request = request;
        request.command_credential_generation = Some(command_credential_generation);
        return Ok(request);
    }
    #[cfg(test)]
    Ok(request)
}

async fn resolve_provider_request_async_with_store_refresh(
    provider_id: &str,
    entry: &ProviderEntry,
    store: crate::credentials::CredentialStore,
    env_lookup: &(dyn Fn(&str) -> Option<String> + Sync),
    force_refresh: bool,
    rejected_refresh_generation: Option<u64>,
) -> Result<ResolvedRequest> {
    let registry = ProviderRegistry::standard();
    let command_credential = match entry.auth_command.as_deref() {
        Some(_) => Some(
            crate::auth::command::resolve(
                provider_id,
                entry,
                store.clone(),
                env_lookup,
                force_refresh,
                rejected_refresh_generation,
            )
            .await?,
        ),
        None => None,
    };
    #[cfg(not(test))]
    let command_credential_generation = command_credential
        .as_ref()
        .map(|credential| credential.refresh_generation);
    let credential_kind = registry.provider_for(provider_id, entry).credential_kind();
    let credential = if let Some(credential) = command_credential {
        Some(OAuthCredential::Command(credential))
    } else {
        match credential_kind {
            Some(ProviderCredentialKind::CodexOAuth) => Some(OAuthCredential::Codex(
                crate::auth::codex_oauth::credential_from_store(store.clone()).await?,
            )),
            Some(ProviderCredentialKind::XaiOAuth) => Some(OAuthCredential::Bearer(
                crate::auth::xai_oauth::bearer_token_from_store(store.clone()).await?,
            )),
            None => None,
        }
    };
    let secret_lookup = |name: &str| store.named_secret(name).map(str::to_string);
    let mut request = resolve_provider_request_inner_with_sources(
        provider_id,
        entry,
        credential,
        registry.provider_for(provider_id, entry).request_kind(),
        env_lookup,
        &secret_lookup,
    )?;
    #[cfg(not(test))]
    {
        request.command_credential_generation = command_credential_generation;
    }
    Ok(request)
}

async fn resolve_model_list_request_async(
    provider_id: &str,
    entry: &ProviderEntry,
    resolved: &ResolvedRequest,
) -> Result<ResolvedRequest> {
    resolve_model_list_request_async_with_store(provider_id, entry, resolved, None, &|name| {
        std::env::var(name).ok()
    })
    .await
}

async fn resolve_model_list_request_async_with_store(
    provider_id: &str,
    entry: &ProviderEntry,
    resolved: &ResolvedRequest,
    store: Option<crate::credentials::CredentialStore>,
    env_lookup: &(dyn Fn(&str) -> Option<String> + Sync),
) -> Result<ResolvedRequest> {
    let registry = ProviderRegistry::standard();
    let command_credential = match (entry.auth_command.as_deref(), store.as_ref()) {
        (Some(_), Some(store)) => Some(
            crate::auth::command::resolve(
                provider_id,
                entry,
                store.clone(),
                env_lookup,
                false,
                None,
            )
            .await?,
        ),
        (Some(_), None) => {
            anyhow::bail!(
                "provider `{provider_id}` auth_command requires an injected credential store"
            )
        }
        (None, _) => None,
    };
    #[cfg(not(test))]
    let command_credential_generation = command_credential
        .as_ref()
        .map(|credential| credential.refresh_generation);
    let credential_kind = registry.provider_for(provider_id, entry).credential_kind();
    let credential = if let Some(credential) = command_credential {
        Some(OAuthCredential::Command(credential))
    } else {
        match (credential_kind, store) {
            (Some(ProviderCredentialKind::CodexOAuth), Some(store)) => {
                Some(OAuthCredential::Codex(
                    crate::auth::codex_oauth::credential_from_store(store).await?,
                ))
            }
            (Some(ProviderCredentialKind::XaiOAuth), Some(store)) => Some(OAuthCredential::Bearer(
                crate::auth::xai_oauth::bearer_token_from_store(store).await?,
            )),
            (Some(ProviderCredentialKind::CodexOAuth), None) => {
                anyhow::bail!("Codex OAuth requires an injected credential store")
            }
            (Some(ProviderCredentialKind::XaiOAuth), None) => {
                anyhow::bail!("Grok OAuth requires an injected credential store")
            }
            (None, _) => None,
        }
    };
    let mut request = registry
        .provider_for(provider_id, entry)
        .model_list_request(provider_id, entry, resolved, credential, env_lookup)?;
    #[cfg(not(test))]
    {
        request.command_credential_generation = command_credential_generation;
    }
    Ok(request)
}

pub fn resolve_provider_request_blocking(
    provider_id: &str,
    entry: &ProviderEntry,
) -> Result<ResolvedRequest> {
    let registry = ProviderRegistry::standard();
    if entry.auth_command.is_none()
        && registry
            .provider_for(provider_id, entry)
            .credential_kind()
            .is_none()
    {
        return resolve_provider_request(provider_id, entry);
    }
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| {
                handle.block_on(resolve_provider_request_async(provider_id, entry))
            })
        }
        Ok(_) => {
            // `block_in_place` panics on Tokios current-thread runtime. The
            // model builder is intentionally synchronous, so bridge OAuth on
            // a dedicated thread instead of making every caller runtime-flavor
            // dependent.
            let provider_id = provider_id.to_owned();
            let entry = entry.clone();
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("build subscription-auth runtime")?
                    .block_on(resolve_provider_request_async(&provider_id, &entry))
            })
            .join()
            .map_err(|_| anyhow!("subscription-auth worker panicked"))?
        }
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build subscription-auth runtime")?
            .block_on(resolve_provider_request_async(provider_id, entry)),
    }
}

pub fn resolve_provider_request_blocking_with_env<F>(
    provider_id: &str,
    entry: &ProviderEntry,
    lookup: F,
) -> Result<ResolvedRequest>
where
    F: Fn(&str) -> Option<String>,
{
    resolve_provider_request_blocking_with_sources(provider_id, entry, lookup, |_| None)
}

pub fn resolve_provider_request_blocking_with_sources<F, S>(
    provider_id: &str,
    entry: &ProviderEntry,
    lookup: F,
    secret_lookup: S,
) -> Result<ResolvedRequest>
where
    F: Fn(&str) -> Option<String>,
    S: Fn(&str) -> Option<String>,
{
    let registry = ProviderRegistry::standard();
    if entry.auth_command.is_none()
        && registry
            .provider_for(provider_id, entry)
            .credential_kind()
            .is_none()
    {
        return resolve_provider_request_with_sources(provider_id, entry, lookup, secret_lookup);
    }
    resolve_provider_request_blocking(provider_id, entry)
}

pub fn resolve_provider_request_blocking_with_store<F>(
    provider_id: &str,
    entry: &ProviderEntry,
    lookup: F,
    store: crate::credentials::CredentialStore,
) -> Result<ResolvedRequest>
where
    F: Fn(&str) -> Option<String> + Send + Sync,
{
    let registry = ProviderRegistry::standard();
    if entry.auth_command.is_none()
        && registry
            .provider_for(provider_id, entry)
            .credential_kind()
            .is_none()
    {
        let secret_lookup = |name: &str| store.named_secret(name).map(str::to_string);
        return resolve_provider_request_with_sources(provider_id, entry, lookup, secret_lookup);
    }
    let provider_id_owned = provider_id.to_owned();
    let entry = entry.clone();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| {
                handle.block_on(resolve_provider_request_async_with_store(
                    &provider_id_owned,
                    &entry,
                    store,
                    |name| lookup(name),
                ))
            })
        }
        Ok(_) => std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .context("build subscription-auth runtime")?
                        .block_on(resolve_provider_request_async_with_store(
                            &provider_id_owned,
                            &entry,
                            store,
                            |name| lookup(name),
                        ))
                })
                .join()
                .map_err(|_| anyhow!("subscription-auth worker panicked"))?
        }),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build subscription-auth runtime")?
            .block_on(resolve_provider_request_async_with_store(
                &provider_id_owned,
                &entry,
                store,
                |name| lookup(name),
            )),
    }
}

pub(crate) fn resolve_provider_request_inner(
    provider_id: &str,
    entry: &ProviderEntry,
    oauth_credential: Option<OAuthCredential>,
    request_kind: ProviderRequestKind,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<ResolvedRequest> {
    resolve_provider_request_inner_with_sources(
        provider_id,
        entry,
        oauth_credential,
        request_kind,
        lookup,
        &|_| None,
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
    if matches!(
        entry.auth,
        Some(crate::config::providers::AuthKind::Command)
    ) && entry.auth_command.is_none()
    {
        anyhow::bail!(
            "provider `{provider_id}` uses command authentication but no global auth_command is configured"
        );
    }
    crate::config::providers::validate_provider_headers(provider_id, &entry.headers)?;
    let origin = ProviderRegistry::standard().resolve_origin(provider_id, entry)?;
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

    let is_codex_credential = matches!(&oauth_credential, Some(OAuthCredential::Codex(_)));
    if let Some(credential) = oauth_credential {
        let token = credential.access_token().to_string();
        headers.push(ResolvedHeader {
            name: "Authorization".to_string(),
            value: format!("Bearer {token}"),
        });
        match credential {
            OAuthCredential::Codex(mut tokens) => {
                let account_id = tokens.account_id.take().ok_or_else(|| {
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
            }
            OAuthCredential::Command(command) => {
                for (name, value) in command.headers.unwrap_or_default() {
                    merge_header_override(&mut headers, ResolvedHeader { name, value });
                }
            }
            OAuthCredential::Bearer(_) => {}
        }
    } else if let Some(auth) = auth_header {
        headers.push(auth);
    } else if is_copilot {
        match resolve_copilot_token_with_sources(env_lookup, secret_lookup)? {
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

    validate_resolved_provider_headers(provider_id, &headers)?;
    if origin.is_template("openrouter") {
        crate::providers::openrouter_attribution::merge_openrouter_attribution(&mut headers);
    }

    Ok(ResolvedRequest {
        base_url: resolve_provider_base_url_with_env(provider_id, entry, is_copilot, env_lookup)?,
        headers,
        is_codex_credential,
        #[cfg(not(test))]
        command_credential_generation: None,
        #[cfg(not(test))]
        origin,
    })
}

fn merge_header_override(headers: &mut Vec<ResolvedHeader>, replacement: ResolvedHeader) {
    if let Some(existing) = headers
        .iter_mut()
        .find(|header| header.name.eq_ignore_ascii_case(&replacement.name))
    {
        *existing = replacement;
    } else {
        headers.push(replacement);
    }
}

fn validate_resolved_provider_headers(provider_id: &str, headers: &[ResolvedHeader]) -> Result<()> {
    let mut names = std::collections::BTreeSet::new();
    for header in headers {
        if !names.insert(header.name.to_ascii_lowercase())
            || reqwest::header::HeaderName::from_bytes(header.name.as_bytes()).is_err()
            || reqwest::header::HeaderValue::from_str(&header.value).is_err()
        {
            return Err(
                crate::config::providers::ProviderHeaderConfigError::new(provider_id).into(),
            );
        }
    }
    Ok(())
}

pub(crate) fn resolve_codex_model_list_request(
    provider_id: &str,
    entry: &ProviderEntry,
    mut tokens: crate::auth::codex_oauth::StoredTokens,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<ResolvedRequest> {
    let mut headers: Vec<ResolvedHeader> = Vec::with_capacity(2);

    let account_id = tokens.account_id.take().ok_or_else(|| {
        anyhow!(
            "Codex subscription auth is missing chatgpt-account-id; set up OAuth in /settings → Providers."
        )
    })?;
    headers.push(ResolvedHeader {
        name: "Authorization".to_string(),
        value: format!("Bearer {}", std::mem::take(&mut tokens.access_token)),
    });
    headers.push(ResolvedHeader {
        name: "ChatGPT-Account-ID".to_string(),
        value: account_id,
    });

    Ok(ResolvedRequest {
        base_url: resolve_provider_base_url_with_env(provider_id, entry, false, lookup)?,
        headers,
        is_codex_credential: true,
        #[cfg(not(test))]
        command_credential_generation: None,
        #[cfg(not(test))]
        origin: ProviderRegistry::standard().resolve_origin(provider_id, entry)?,
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
    fetch_models_at_detailed(url, headers, timeout, ModelCatalogAbi::Generic)
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
    catalog_abi: ModelCatalogAbi,
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
    let models = parse_models_body_with_abi(&body, catalog_abi)?;
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
    fetch_models_for_provider_with_store(provider_id, entry, resolved, timeout, None, |name| {
        std::env::var(name).ok()
    })
    .await
}

pub async fn fetch_models_for_provider_with_store(
    provider_id: &str,
    entry: &ProviderEntry,
    resolved: &ResolvedRequest,
    timeout: Duration,
    store: Option<crate::credentials::CredentialStore>,
    env_lookup: impl Fn(&str) -> Option<String> + Sync,
) -> Result<FetchOutcome> {
    let auth_store = store.clone();
    let request = resolve_model_list_request_async_with_store(
        provider_id,
        entry,
        resolved,
        store,
        &env_lookup,
    )
    .await?;
    let registry = ProviderRegistry::standard();
    let provider = registry.provider_for(provider_id, entry);
    let url = provider.models_url(entry, &request.base_url);
    let fallback_models = provider.fallback_models();
    let fallback_catalog = provider.fallback_catalog();
    let mut outcome = fetch_models_at_detailed(
        &url,
        &request.headers,
        timeout,
        ModelCatalogAbi::from(provider.request_kind()),
    )
    .await
    .and_then(|result| validate_anthropic_fetch_result(entry, &request.base_url, result));
    if outcome
        .as_ref()
        .is_err_and(|error| auth_rejection_error(error))
        && let (Some(_), Some(store)) = (entry.auth_command.as_deref(), auth_store)
    {
        let rejected_generation = request.command_credential_generation().context(
            "command-authenticated model-list request is missing its credential generation",
        )?;
        let credential = crate::auth::command::resolve(
            provider_id,
            entry,
            store.clone(),
            &env_lookup,
            true,
            Some(rejected_generation),
        )
        .await?;
        let secret_lookup = |name: &str| store.named_secret(name).map(str::to_string);
        let refreshed = resolve_provider_request_inner_with_sources(
            provider_id,
            entry,
            Some(OAuthCredential::Command(credential)),
            ProviderRequestKind::Template,
            &env_lookup,
            &secret_lookup,
        )?;
        let refreshed_url = provider.models_url(entry, &refreshed.base_url);
        outcome = fetch_models_at_detailed(
            &refreshed_url,
            &refreshed.headers,
            timeout,
            ModelCatalogAbi::from(provider.request_kind()),
        )
        .await
        .and_then(|result| validate_anthropic_fetch_result(entry, &refreshed.base_url, result));
    }
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

fn auth_rejection_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message.contains("returned 401") || message.contains("returned 403")
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
    parse_models_body_with_abi(body, ModelCatalogAbi::Generic)
}

/// Request-body ABI whose metadata projections are understood for a fetched
/// model catalog. Endpoint availability is provider-neutral, but a capability
/// list alone does not establish how to encode that capability on a request.
/// Keep provider-specific encodings opt-in here rather than inferring them
/// from fields that an OpenAI-compatible gateway might happen to share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelCatalogAbi {
    Generic,
    Copilot,
}

impl From<ProviderRequestKind> for ModelCatalogAbi {
    fn from(request_kind: ProviderRequestKind) -> Self {
        match request_kind {
            ProviderRequestKind::Template => Self::Generic,
            ProviderRequestKind::Copilot => Self::Copilot,
        }
    }
}

fn parse_models_body_with_abi(body: &str, catalog_abi: ModelCatalogAbi) -> Result<Vec<ModelEntry>> {
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

            let capabilities = match model_capabilities_from_metadata(obj, catalog_abi) {
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
                can_delegate: None,
                computer_use: None,
                allow_computer_guidance_proposals: None,
                default_thinking_mode: None,
                embeddings: None,
                embedding_dimensions: None,
                availability: Default::default(),
                cache: None,
                shrink: None,
                context: None,
                auto_prune: None,
                timeout: None,
                backup: None,
                system_prompt: None,
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                thinking_params: Default::default(),
                // Fetched entries are always `auto`; a user/fallback pin is
                // carried over by `merge_fetched_models`
                // (implementation note).
                wire_api: Default::default(),
                wire_api_provenance: Default::default(),
                extra: extra.clone(),
                capabilities,
                capability_overrides: Default::default(),
                provider_metadata: extra,
            }))
        })
        .collect()
}

fn model_capabilities_from_metadata(
    obj: &Map<String, Value>,
    catalog_abi: ModelCatalogAbi,
) -> Result<ModelCapabilities> {
    let context_tokens = context_tokens_from_metadata(obj);
    let max_output_tokens = max_output_tokens_from_metadata(obj);
    let input_modalities = input_modalities_from_metadata(obj);
    Ok(ModelCapabilities {
        tool_calling: capability_status_from_metadata(
            obj,
            "tool_calling",
            &["tools", "tool_choice", "functions", "function_calling"],
        ),
        image_input: input_capability_from_metadata(
            obj,
            "image_input",
            "images",
            "image",
            input_modalities,
        ),
        audio_input: input_capability_from_metadata(
            obj,
            "audio_input",
            "audio",
            "audio",
            input_modalities,
        ),
        video_input: input_capability_from_metadata(
            obj,
            "video_input",
            "video",
            "video",
            input_modalities,
        ),
        transcription: capability_status_from_metadata(
            obj,
            "transcription",
            &[
                "audio_transcriptions",
                "audio_transcription",
                "transcriptions",
            ],
        ),
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
        prompt_cache_retention: Default::default(),
        reasoning_effort: reasoning_effort_capability_from_metadata(obj, catalog_abi)?,
        supported_wire_apis: supported_wire_apis_from_metadata(obj),
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

/// Project one input modality into typed model metadata.
///
/// Reads explicit capability fields first, then legacy `inputs.<key>` boolean
/// membership, then architecture input-modality lists. Output-only modalities
/// never enable input. Legacy projection here feeds detection only — runtime
/// consumers must call `resolve_effective_model_capabilities`.
fn input_capability_from_metadata(
    obj: &Map<String, Value>,
    capability_key: &str,
    legacy_inputs_key: &str,
    modality_name: &str,
    input_modalities: Option<&Value>,
) -> CapabilityStatus {
    let camel = snake_to_camel(capability_key);
    let raw = obj
        .get(capability_key)
        .or_else(|| obj.get(&camel))
        .or_else(|| {
            obj.get("capabilities")
                .and_then(Value::as_object)
                .and_then(|capabilities| {
                    capabilities
                        .get(capability_key)
                        .or_else(|| capabilities.get(&camel))
                        .or_else(|| capabilities.get(legacy_inputs_key))
                })
        });
    if let Some(raw) = raw {
        let parsed = capability_status_from_value(raw);
        if !parsed.is_unknown() {
            return parsed;
        }
    }
    if let Some(listed) = obj
        .get("inputs")
        .and_then(Value::as_object)
        .and_then(|inputs| inputs.get(legacy_inputs_key))
        .and_then(Value::as_bool)
    {
        // Detection projection: true → Supported. Explicit false/absence both
        // stay Unknown under the legacy membership contract (not Unsupported).
        return if listed {
            CapabilityStatus::Supported
        } else {
            CapabilityStatus::Unknown
        };
    }
    if modality_list_contains(input_modalities, modality_name) {
        return CapabilityStatus::Supported;
    }
    CapabilityStatus::Unknown
}

fn input_modalities_from_metadata(obj: &Map<String, Value>) -> Option<&Value> {
    obj.get("architecture")
        .and_then(Value::as_object)
        .and_then(|architecture| architecture.get("input_modalities"))
        .or_else(|| obj.get("input_modalities"))
        .or_else(|| obj.get("inputModalities"))
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
    catalog_abi: ModelCatalogAbi,
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
    // `supported_reasoning_levels` is our established generic catalog
    // contract and maps to OpenAI's top-level `reasoning_effort` parameter.
    // Copilot's similarly-shaped nested metadata instead describes its
    // Responses-only `reasoning.effort` ABI. Do not turn a lookalike field
    // from an arbitrary gateway into a request parameter.
    let raw_values = obj
        .get("supported_reasoning_levels")
        .and_then(Value::as_array)
        .or_else(|| {
            (catalog_abi == ModelCatalogAbi::Copilot)
                .then(|| {
                    obj.get("capabilities")
                        .and_then(Value::as_object)
                        .and_then(|capabilities| capabilities.get("supports"))
                        .and_then(Value::as_object)
                        .and_then(|supports| supports.get("reasoning_effort"))
                        .and_then(Value::as_array)
                })
                .flatten()
        });
    if let Some(raw_values) = raw_values {
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

    // Codex-style catalogs use `default_reasoning_level`; Copilot's model
    // catalog calls the same concept `default_reasoning_effort`. Prefer the
    // former when both are present for backwards-compatible precedence.
    let default = obj
        .get("default_reasoning_level")
        .or_else(|| obj.get("default_reasoning_effort"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string);

    // A default without selectable values cannot establish either a valid UI
    // choice or an outbound request encoding. Treat it as informational
    // provider metadata only (it remains in `provider_metadata`).
    if values.is_empty() {
        return Ok(None);
    }

    let (request_mapping, endpoint_request_mappings) = if catalog_abi == ModelCatalogAbi::Copilot
        && has_responses_reasoning_effort_metadata(obj)
    {
        (
            None,
            vec![EndpointReasoningEffortRequestMapping {
                wire_api: WireApi::Responses,
                request_mapping: ReasoningEffortRequestMapping::JsonPath {
                    path: vec!["reasoning".to_string(), "effort".to_string()],
                    values: values
                        .iter()
                        .map(|value| (value.value.clone(), Value::String(value.value.clone())))
                        .collect::<BTreeMap<_, _>>(),
                },
            }],
        )
    } else {
        (
            Some(ReasoningEffortRequestMapping::JsonField {
                field: "reasoning_effort".to_string(),
                values: values
                    .iter()
                    .map(|value| (value.value.clone(), Value::String(value.value.clone())))
                    .collect::<BTreeMap<_, _>>(),
            }),
            Vec::new(),
        )
    };

    Ok(Some(ReasoningEffortCapability {
        values,
        default,
        request_mapping,
        endpoint_request_mappings,
        source: Some(CapabilitySource::Live),
    }))
}

fn has_responses_reasoning_effort_metadata(obj: &Map<String, Value>) -> bool {
    supported_wire_apis_from_metadata(obj).contains(&WireApi::Responses)
        && obj
            .get("capabilities")
            .and_then(Value::as_object)
            .and_then(|capabilities| capabilities.get("supports"))
            .and_then(Value::as_object)
            .and_then(|supports| supports.get("reasoning_effort"))
            .is_some_and(Value::is_array)
}

fn supported_wire_apis_from_metadata(obj: &Map<String, Value>) -> Vec<WireApi> {
    let Some(endpoints) = obj.get("supported_endpoints").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut wire_apis = Vec::new();
    for endpoint in endpoints.iter().filter_map(Value::as_str) {
        let endpoint = endpoint.trim().trim_end_matches('/');
        let wire_api = match endpoint {
            "/responses" | "responses" => WireApi::Responses,
            "/chat/completions" | "chat/completions" => WireApi::Completions,
            _ => continue,
        };
        if !wire_apis.contains(&wire_api) {
            wire_apis.push(wire_api);
        }
    }
    wire_apis
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
    resolve_copilot_token_with_sources(|name| std::env::var(name).ok(), |_| None)
}

fn resolve_copilot_token_with_env<F>(lookup: F) -> Result<Option<String>>
where
    F: Fn(&str) -> Option<String>,
{
    resolve_copilot_token_with_sources(&lookup, |_| None)
}

fn resolve_copilot_token_with_sources<F, S>(lookup: F, secret_lookup: S) -> Result<Option<String>>
where
    F: Fn(&str) -> Option<String>,
    S: Fn(&str) -> Option<String>,
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

    if let Some(token) =
        secret_lookup(COPILOT_TOKEN_CREDENTIAL_KEY).filter(|token| !token.trim().is_empty())
    {
        validate_copilot_token(COPILOT_TOKEN_CREDENTIAL_KEY, &token)?;
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

/// Write a fetched model list back to the most specific writable config
/// layer for `provider_id`. The terminating step of every `/fetch-models`
/// flow, shared by the `cockpit fetch-models` subcommand and the TUI's
/// background model refresh.
pub fn persist_provider(
    cwd: &std::path::Path,
    provider_id: &str,
    entry: ProviderEntry,
) -> Result<()> {
    let path = crate::config::dirs::config_write_target_for_provider(cwd, provider_id).ok_or_else(
        || anyhow!("no cockpit config found — run `/settings` inside the TUI to create one"),
    )?;
    let mut doc = crate::config::providers::ConfigDoc::load(&path)?;
    doc.write_provider_models(
        provider_id,
        &entry.models,
        entry.models_fetched_at,
        entry.model_catalog,
        entry.last_model_fetch,
    )
    .context("writing config.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::AuthKind;

    fn clear_copilot_env(env: &crate::test_env::TestEnvGuard) {
        env.remove_var("COPILOT_GITHUB_TOKEN");
        env.remove_var("GH_TOKEN");
        env.remove_var("GITHUB_TOKEN");
        env.remove_var("GITHUB_COPILOT_API_TOKEN");
        env.remove_var("COPILOT_API_URL");
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
    fn parses_copilot_responses_capabilities_without_static_effort_levels() {
        let body = r#"{
            "data": [{
                "id": "gpt-5.6-terra",
                "default_reasoning_effort": "high",
                "supported_endpoints": ["/chat/completions", "/responses"],
                "capabilities": {
                    "supports": {
                        "reasoning_effort": ["low", "medium", "high", "xhigh", "max", "ultra"]
                    }
                }
            }]
        }"#;

        let entries = parse_models_body_with_abi(body, ModelCatalogAbi::Copilot).unwrap();
        let model = entries.first().expect("Copilot model");
        assert_eq!(
            model.capabilities.supported_wire_apis,
            vec![WireApi::Completions, WireApi::Responses]
        );
        let reasoning = model
            .capabilities
            .reasoning_effort
            .as_ref()
            .expect("Copilot reasoning capability");
        assert_eq!(
            reasoning
                .values
                .iter()
                .map(|value| value.value.as_str())
                .collect::<Vec<_>>(),
            vec!["low", "medium", "high", "xhigh", "max", "ultra"]
        );
        assert_eq!(reasoning.default.as_deref(), Some("high"));
        let mapping = reasoning
            .endpoint_request_mappings
            .iter()
            .find(|mapping| mapping.wire_api == WireApi::Responses)
            .expect("Responses mapping");
        let ReasoningEffortRequestMapping::JsonPath { path, values } = &mapping.request_mapping
        else {
            panic!("Responses-capable catalog must use nested reasoning.effort");
        };
        assert_eq!(path, &["reasoning", "effort"]);
        assert_eq!(values.get("ultra"), Some(&serde_json::json!("ultra")));
    }

    #[test]
    fn renamed_copilot_template_uses_copilot_request_kind_and_catalog_abi() {
        let entry = ProviderEntry {
            template: Some("CoPiLoT".into()),
            // The persisted template, rather than a mutable key, credential,
            // or URL spelling, establishes this provider's special identity.
            url: "https://custom-proxy.example/v1".into(),
            ..ProviderEntry::default()
        };
        let registry = ProviderRegistry::standard();
        let provider = registry.provider_for("work-copilot", &entry);

        assert_eq!(provider.request_kind(), ProviderRequestKind::Copilot);

        let body = r#"{
            "data": [{
                "id": "gpt-5.6-terra",
                "default_reasoning_effort": "high",
                "supported_endpoints": ["/responses"],
                "capabilities": {
                    "supports": { "reasoning_effort": ["low", "high", "ultra"] }
                }
            }]
        }"#;
        let entries = parse_models_body_with_abi(body, provider.request_kind().into()).unwrap();
        let reasoning = entries[0]
            .capabilities
            .reasoning_effort
            .as_ref()
            .expect("Copilot catalog exposes reasoning effort");
        let mapping = reasoning
            .endpoint_request_mappings
            .iter()
            .find(|mapping| mapping.wire_api == WireApi::Responses)
            .expect("Copilot Responses ABI mapping");
        let ReasoningEffortRequestMapping::JsonPath { path, values } = &mapping.request_mapping
        else {
            panic!("Copilot Responses ABI must use nested reasoning.effort");
        };
        assert_eq!(path, &["reasoning", "effort"]);
        assert_eq!(values.get("ultra"), Some(&serde_json::json!("ultra")));
    }

    #[test]
    fn mixed_case_copilot_url_uses_copilot_request_kind() {
        let entry = ProviderEntry {
            url: "https://API.GitHubCopilot.COM".into(),
            ..ProviderEntry::default()
        };
        let registry = ProviderRegistry::standard();
        let provider = registry.provider_for("work-copilot", &entry);

        assert_eq!(provider.id(), "copilot");
        assert_eq!(provider.request_kind(), ProviderRequestKind::Copilot);
    }

    #[test]
    fn generic_catalog_does_not_infer_copilot_responses_request_abi() {
        let body = r#"{
            "data": [{
                "id": "gateway-model",
                "default_reasoning_effort": "high",
                "supported_endpoints": ["/chat/completions", "/responses"],
                "capabilities": {
                    "supports": {
                        "reasoning_effort": ["low", "medium", "high"]
                    }
                }
            }]
        }"#;

        let entries = parse_models_body(body).unwrap();
        let model = entries.first().expect("generic catalog model");
        assert_eq!(
            model.capabilities.supported_wire_apis,
            vec![WireApi::Completions, WireApi::Responses]
        );
        assert!(
            model.capabilities.reasoning_effort.is_none(),
            "an unknown catalog's capability list does not establish a request ABI"
        );
    }

    #[test]
    fn generic_catalog_retains_established_top_level_reasoning_contract() {
        let body = r#"{
            "data": [{
                "id": "generic-reasoning-model",
                "supported_endpoints": ["/responses"],
                "supported_reasoning_levels": ["low", "high"]
            }]
        }"#;

        let entries = parse_models_body(body).unwrap();
        let reasoning = entries[0]
            .capabilities
            .reasoning_effort
            .as_ref()
            .expect("established generic capability");
        let ReasoningEffortRequestMapping::JsonField { field, .. } = reasoning
            .request_mapping
            .as_ref()
            .expect("generic request mapping")
        else {
            panic!("top-level generic capability must retain its known ABI");
        };
        assert_eq!(field, "reasoning_effort");
        assert!(reasoning.endpoint_request_mappings.is_empty());
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
        assert_eq!(model.capabilities.image_input, CapabilityStatus::Supported);
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
        assert!(model.capabilities.image_input.is_unknown());
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
    fn command_headers_override_static_and_bearer_headers() {
        let entry = ProviderEntry {
            url: "https://api.example.test/v1".into(),
            auth: Some(AuthKind::Command),
            auth_command: Some(vec!["auth-helper".into()]),
            headers: vec![
                HeaderSpec {
                    name: "X-Tenant".into(),
                    value: "static".into(),
                },
                HeaderSpec {
                    name: "X-Static".into(),
                    value: "kept".into(),
                },
            ],
            ..ProviderEntry::default()
        };
        let credential = OAuthCredential::Command(crate::auth::command::CommandCredential {
            token: "default-token".into(),
            expires_at: None,
            headers: Some(BTreeMap::from([
                ("authorization".into(), "Token override".into()),
                ("x-tenant".into(), "returned".into()),
            ])),
            refresh_generation: 0,
        });
        let request = resolve_provider_request_inner_with_sources(
            "custom",
            &entry,
            Some(credential),
            ProviderRequestKind::Template,
            &|_| None,
            &|_| None,
        )
        .unwrap();

        assert_eq!(
            resolved_header_value(&request, "Authorization"),
            Some("Token override")
        );
        assert_eq!(
            resolved_header_value(&request, "X-Tenant"),
            Some("returned")
        );
        assert_eq!(resolved_header_value(&request, "X-Static"), Some("kept"));
    }

    #[test]
    fn command_auth_always_uses_template_provider_fallback() {
        let entry = ProviderEntry {
            url: crate::auth::codex_oauth::DEFAULT_BASE_URL.into(),
            auth: Some(AuthKind::Command),
            auth_command: Some(vec!["auth-helper".into()]),
            ..ProviderEntry::default()
        };

        assert_eq!(
            ProviderRegistry::standard().provider_id_for("codex-oauth", &entry),
            "template"
        );
    }

    #[test]
    fn openrouter_rust_provider_header_override() {
        let entry = ProviderEntry {
            template: Some("openrouter".into()),
            url: "https://openrouter.ai/api/v1".into(),
            headers: vec![
                HeaderSpec {
                    name: "http-referer".into(),
                    value: "https://override.test".into(),
                },
                HeaderSpec {
                    name: "X-OpenRouter-Title".into(),
                    value: String::new(),
                },
                HeaderSpec {
                    name: "X-Title".into(),
                    value: "unrelated".into(),
                },
            ],
            ..ProviderEntry::default()
        };
        let request =
            resolve_provider_request_with_sources("renamed", &entry, |_| None, |_| None).unwrap();
        assert_eq!(
            resolved_header_value(&request, "HTTP-Referer"),
            Some("https://override.test")
        );
        assert_eq!(resolved_header_value(&request, "X-OpenRouter-Title"), None);
        assert_eq!(
            resolved_header_value(&request, "X-Title"),
            Some("unrelated")
        );

        let stock = ProviderEntry {
            template: Some("openrouter".into()),
            url: "https://openrouter.ai/api/v1".into(),
            ..ProviderEntry::default()
        };
        let request =
            resolve_provider_request_with_sources("work", &stock, |_| None, |_| None).unwrap();
        assert_eq!(
            resolved_header_value(&request, "HTTP-Referer"),
            Some("https://flycockpit.dev")
        );
        assert_eq!(
            resolved_header_value(&request, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );
    }

    #[test]
    fn openrouter_identity_uses_registry_origin() {
        let custom = ProviderEntry {
            url: "https://openrouter.ai/api/v1".into(),
            ..ProviderEntry::default()
        };
        let request =
            resolve_provider_request_with_sources("openrouter", &custom, |_| None, |_| None)
                .unwrap();
        assert_eq!(resolved_header_value(&request, "HTTP-Referer"), None);

        let unknown = ProviderEntry {
            template: Some("openrouter-lookalike".into()),
            url: "https://openrouter.ai/api/v1".into(),
            ..ProviderEntry::default()
        };
        assert!(
            resolve_provider_request_with_sources("custom", &unknown, |_| None, |_| None).is_err()
        );

        let conflicting_special = ProviderEntry {
            template: Some("openrouter".into()),
            url: "https://api.githubcopilot.com".into(),
            credential_ref: Some("copilot".into()),
            ..ProviderEntry::default()
        };
        let error = resolve_provider_request_with_sources(
            "renamed-openrouter",
            &conflicting_special,
            |_| None,
            |_| None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("conflicting template"));
    }

    #[test]
    fn provider_header_normalization_rejects_invalid_or_duplicate() {
        for headers in [
            vec![
                HeaderSpec {
                    name: "X-Test".into(),
                    value: "one".into(),
                },
                HeaderSpec {
                    name: "x-test".into(),
                    value: "two".into(),
                },
            ],
            vec![HeaderSpec {
                name: "bad name".into(),
                value: "secret-value".into(),
            }],
            vec![HeaderSpec {
                name: "X-Test".into(),
                value: "bad\r\nvalue".into(),
            }],
        ] {
            let entry = ProviderEntry {
                url: "https://example.test/v1".into(),
                headers,
                ..ProviderEntry::default()
            };
            let error =
                resolve_provider_request_with_sources("safe-id", &entry, |_| None, |_| None)
                    .unwrap_err();
            let typed = error
                .downcast_ref::<crate::config::providers::ProviderHeaderConfigError>()
                .unwrap();
            assert_eq!(typed.code(), "provider_header_invalid");
            assert_eq!(
                typed.to_string(),
                "Provider 'safe-id' has invalid or duplicate HTTP header configuration; edit provider headers before retrying."
            );
            assert!(!format!("{error:#}").contains("secret-value"));
        }

        let dynamic = ProviderEntry {
            headers: vec![HeaderSpec {
                name: "X-Dynamic".into(),
                value: "$secret:header-value".into(),
            }],
            ..ProviderEntry::default()
        };
        let error = resolve_provider_request_with_sources(
            "safe-id",
            &dynamic,
            |_| None,
            |name| (name == "header-value").then(|| "secret\nvalue".into()),
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<crate::config::providers::ProviderHeaderConfigError>()
                .unwrap()
                .code(),
            "provider_header_invalid"
        );
        assert!(!format!("{error:#}").contains("secret"));
    }

    /// Finding 5: do not call `merge_openrouter_attribution` directly here.
    /// Test through the resolved OpenRouter-template request path and assert
    /// the resulting headers, so the test exercises the same identity gate
    /// (`origin.is_template("openrouter")`) that production uses.
    #[test]
    fn openrouter_attribution_merge_fixture() {
        let entry = ProviderEntry {
            template: Some("openrouter".into()),
            url: "https://openrouter.ai/api/v1".into(),
            ..ProviderEntry::default()
        };
        let resolved =
            resolve_provider_request_with_sources("renamed-openrouter", &entry, |_| None, |_| None)
                .unwrap();
        assert_eq!(
            resolved_header_value(&resolved, "HTTP-Referer"),
            Some("https://flycockpit.dev")
        );
        assert_eq!(
            resolved_header_value(&resolved, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );
        // No auth header is configured, so the only headers are the
        // attribution pair.
        assert_eq!(resolved.headers.len(), 2);
    }

    #[tokio::test]
    async fn openrouter_attribution_cross_adapter_fixture() {
        let (base_url, request_handle) = serve_models_once(r#"{"data":[]}"#).await;
        let entry = ProviderEntry {
            template: Some("openrouter".into()),
            url: base_url,
            allow_insecure_http: true,
            ..ProviderEntry::default()
        };
        let resolved =
            resolve_provider_request_with_sources("renamed", &entry, |_| None, |_| None).unwrap();

        assert_eq!(
            resolved_header_value(&resolved, "HTTP-Referer"),
            Some("https://flycockpit.dev")
        );
        assert_eq!(
            resolved_header_value(&resolved, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );

        fetch_models_for_provider("renamed", &entry, &resolved, Duration::from_secs(5))
            .await
            .unwrap();
        let request = request_handle.await.unwrap();
        assert_eq!(
            request_header_value(&request, "HTTP-Referer"),
            Some("https://flycockpit.dev")
        );
        assert_eq!(
            request_header_value(&request, "X-OpenRouter-Title"),
            Some("FlyCockpit")
        );
        assert!(request_header_value(&request, "X-Title").is_none());
    }

    #[test]
    fn openrouter_origin_cannot_be_forged_downstream() {
        for (id, url, credential_ref) in [
            ("openrouter", "https://example.test/v1", None),
            ("custom", "https://openrouter.ai/api/v1", None),
            ("custom", "https://example.test/v1", Some("openrouter")),
        ] {
            let entry = ProviderEntry {
                url: url.into(),
                credential_ref: credential_ref.map(str::to_string),
                ..ProviderEntry::default()
            };
            let request =
                resolve_provider_request_with_sources(id, &entry, |_| None, |_| None).unwrap();
            assert_eq!(resolved_header_value(&request, "HTTP-Referer"), None);
        }
    }

    #[test]
    fn non_openrouter_requests_byte_identical() {
        let entry = ProviderEntry {
            url: "https://example.test/v1".into(),
            headers: vec![
                HeaderSpec {
                    name: "Authorization".into(),
                    value: "Bearer unchanged".into(),
                },
                HeaderSpec {
                    name: "X-Title".into(),
                    value: "Unrelated".into(),
                },
            ],
            ..ProviderEntry::default()
        };
        let resolved =
            resolve_provider_request_with_sources("openrouter", &entry, |_| None, |_| None)
                .unwrap();
        assert_eq!(resolved.base_url, entry.url);
        assert_eq!(
            header_pairs(&resolved),
            vec![
                ("X-Title", "Unrelated"),
                ("Authorization", "Bearer unchanged"),
            ]
        );
        assert_eq!(resolved_header_value(&resolved, "HTTP-Referer"), None);
        assert_eq!(resolved_header_value(&resolved, "X-OpenRouter-Title"), None);
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

    fn resolved_header_value<'a>(request: &'a ResolvedRequest, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    #[test]
    fn resolved_request_debug_redacts_header_values() {
        let resolved = ResolvedRequest {
            base_url: "https://api.example.com/v1".into(),
            headers: vec![ResolvedHeader {
                name: "Authorization".into(),
                value: "Bearer fixture-secret-token".into(),
            }],
            is_codex_credential: false,
        };

        let rendered = format!("{resolved:?}");

        assert!(rendered.contains("Authorization"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("fixture-secret-token"), "{rendered}");
    }

    #[test]
    fn github_token_from_environment_still_supported() {
        let env = crate::test_env::lock();
        clear_copilot_env(&env);
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $COPILOT_GITHUB_TOKEN".into(),
            }],
            ..ProviderEntry::default()
        };
        env.set_var("GH_TOKEN", "ghu_test");
        let resolved = resolve_provider_request("copilot", &entry).unwrap();
        let auth = resolved
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.value, "Bearer ghu_test");
    }

    #[test]
    fn copilot_uses_stored_github_token_when_environment_is_unset() {
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![],
            ..ProviderEntry::default()
        };
        let resolved = resolve_provider_request_with_sources(
            "copilot",
            &entry,
            |_| None,
            |name| (name == COPILOT_TOKEN_CREDENTIAL_KEY).then(|| "ghu_stored".to_string()),
        )
        .unwrap();
        let auth = resolved
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.value, "Bearer ghu_stored");
    }

    #[test]
    fn copilot_uses_direct_api_url_override() {
        let env = crate::test_env::lock();
        clear_copilot_env(&env);
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![],
            ..ProviderEntry::default()
        };
        env.set_var("GITHUB_COPILOT_API_TOKEN", "token");
        env.set_var("COPILOT_API_URL", "https://copilot-proxy.example/v1/");
        let resolved = resolve_provider_request("copilot", &entry).unwrap();
        assert_eq!(resolved.base_url, "https://copilot-proxy.example/v1");
    }

    #[test]
    fn copilot_rejects_classic_pat() {
        let env = crate::test_env::lock();
        clear_copilot_env(&env);
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![],
            ..ProviderEntry::default()
        };
        env.set_var("COPILOT_GITHUB_TOKEN", "ghp_legacy");
        let err = resolve_provider_request("copilot", &entry).unwrap_err();
        assert!(err.to_string().contains("classic GitHub PAT"));
    }

    #[test]
    fn copilot_detected_via_url_when_provider_id_differs() {
        // A user might add a Copilot endpoint under a custom id; the
        // resolver still picks up the documented env-var fallbacks.
        let env = crate::test_env::lock();
        clear_copilot_env(&env);
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![],
            ..ProviderEntry::default()
        };
        env.set_var("COPILOT_GITHUB_TOKEN", "gho_via_url");
        let resolved = resolve_provider_request("my-copilot", &entry).unwrap();
        let auth = resolved
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.value, "Bearer gho_via_url");
    }

    #[test]
    fn copilot_priority_prefers_copilot_github_token_over_gh_token() {
        // With both vars set the highest-priority source wins.
        let env = crate::test_env::lock();
        clear_copilot_env(&env);
        let entry = ProviderEntry {
            url: "https://api.githubcopilot.com".into(),
            headers: vec![],
            ..ProviderEntry::default()
        };
        env.set_var("COPILOT_GITHUB_TOKEN", "gho_primary");
        env.set_var("GH_TOKEN", "gho_secondary");
        env.set_var("GITHUB_TOKEN", "gho_tertiary");
        let resolved = resolve_provider_request("copilot", &entry).unwrap();
        let auth = resolved
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.value, "Bearer gho_primary");
    }

    #[test]
    fn copilot_errors_when_no_env_var_set() {
        // Sanity check: with no headers and no env vars, the resolver
        // emits the documented-token guidance instead of falling back
        // to the legacy device-code path.
        let env = crate::test_env::lock();
        clear_copilot_env(&env);
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
        let env = crate::test_env::lock();
        clear_copilot_env(&env);
        let entry = ProviderEntry {
            url: "https://api.example.com/v1".into(),
            headers: vec![HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $TOTALLY_UNSET_VAR_PROBE".into(),
            }],
            ..ProviderEntry::default()
        };
        env.remove_var("TOTALLY_UNSET_VAR_PROBE");
        // Even if a Copilot fallback is set, a non-Copilot provider must not pick it up.
        env.set_var("COPILOT_GITHUB_TOKEN", "gho_should_not_leak");
        let err = resolve_provider_request("some-vendor", &entry).unwrap_err();
        assert!(err.to_string().contains("TOTALLY_UNSET_VAR_PROBE"));
    }

    #[test]
    fn non_copilot_provider_without_auth_resolves_unauthenticated() {
        // A fully-local endpoint (e.g. LM Studio) has no Authorization
        // header. That must resolve cleanly so /models can be fetched
        // unauthenticated rather than erroring out.
        let env = crate::test_env::lock();
        clear_copilot_env(&env);
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
        let env = crate::test_env::lock_async().await;
        let tmp = tempfile::tempdir().unwrap();
        env.set_var("XDG_STATE_HOME", tmp.path());
        env.set_var("XDG_DATA_HOME", tmp.path().join("data"));
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
        let resolved =
            resolve_provider_request_async_with_store("grok-oauth", &entry, store, |name| {
                std::env::var(name).ok()
            })
            .await
            .unwrap();
        let auth = resolved
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.value, "Bearer access-1");
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
    async fn codex_oauth_async_resolver_marks_credential_and_injects_codex_headers() {
        let env = crate::test_env::lock_async().await;
        let tmp = tempfile::tempdir().unwrap();
        env.set_var("XDG_STATE_HOME", tmp.path());
        env.set_var("XDG_DATA_HOME", tmp.path().join("data"));
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
        let resolved =
            resolve_provider_request_async_with_store("codex-oauth", &entry, store, |name| {
                std::env::var(name).ok()
            })
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
        assert!(resolved.is_codex_credential);
        assert!(
            !resolved
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("session_id")),
            "Rig owns the per-request session_id"
        );
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

    fn install_codex_tokens(env: &crate::test_env::TestEnvGuard, tmp: &tempfile::TempDir) {
        env.set_var("XDG_STATE_HOME", tmp.path());
        env.set_var("XDG_DATA_HOME", tmp.path().join("data"));
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

    #[test]
    fn provider_headers_use_injected_vault() {
        let env = crate::test_env::lock();
        let tmp = tempfile::tempdir().unwrap();
        env.set_var("XDG_STATE_HOME", tmp.path());
        env.set_var("XDG_DATA_HOME", tmp.path().join("data"));
        let mut store = crate::credentials::CredentialStore::open_default().unwrap();
        store.set_named_secret("hdr", "sk-models-fetch-header-secret");
        store.save().unwrap();
        let (headers, missing) = resolve_headers_with_sources(
            &[crate::config::providers::HeaderSpec {
                name: "Authorization".into(),
                value: "$secret:hdr".into(),
            }],
            |_| None,
            |name| store.named_secret(name).map(str::to_string),
        );
        assert!(missing.is_empty());
        assert_eq!(headers[0].value, "sk-models-fetch-header-secret");
        assert!(
            !crate::credentials::default_path().unwrap().exists(),
            "models_fetch must read named secrets from the vault"
        );
    }

    #[tokio::test]
    async fn async_with_store_resolves_named_secret_headers() {
        let env = crate::test_env::lock_async().await;
        let tmp = tempfile::tempdir().unwrap();
        env.set_var("XDG_STATE_HOME", tmp.path());
        env.set_var("XDG_DATA_HOME", tmp.path().join("data"));
        let mut store = crate::credentials::CredentialStore::open_default().unwrap();
        store.set_named_secret("hdr", "sk-async-store-header-secret");
        store.save().unwrap();
        let entry = crate::config::providers::ProviderEntry {
            url: "https://example.test/v1".into(),
            headers: vec![crate::config::providers::HeaderSpec {
                name: "Authorization".into(),
                value: "$secret:hdr".into(),
            }],
            ..crate::config::providers::ProviderEntry::default()
        };
        let resolved = resolve_provider_request_async_with_store("openai", &entry, store, |_| None)
            .await
            .unwrap();
        let auth = resolved
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.value, "sk-async-store-header-secret");
        assert!(
            !crate::credentials::default_path().unwrap().exists(),
            "models_fetch must read named secrets from the vault"
        );
    }

    struct TestModelResponse {
        status: u16,
        headers: Vec<(&'static str, &'static str)>,
        body: String,
    }

    impl TestModelResponse {
        fn ok(body: impl Into<String>) -> Self {
            Self {
                status: 200,
                headers: Vec::new(),
                body: body.into(),
            }
        }

        fn status(status: u16, body: impl Into<String>) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: body.into(),
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
                raw.push_str(&response.body);
                socket.write_all(raw.as_bytes()).await.unwrap();
            }
            requests
        });
        tokio::task::yield_now().await;
        (format!("http://{addr}/v1"), handle)
    }

    async fn serve_models_once(
        body: impl Into<String>,
    ) -> (String, tokio::task::JoinHandle<String>) {
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
        let env = crate::test_env::lock_async().await;
        let tmp = tempfile::tempdir().unwrap();
        install_codex_tokens(&env, &tmp);

        for body in [r#"{"data":[]}"#, r#"{"models":[]}"#, "[]"] {
            let (base_url, request_handle) = serve_models_once(body).await;
            let entry = codex_entry(base_url.clone());
            let resolved = ResolvedRequest {
                base_url,
                headers: Vec::new(),
                is_codex_credential: false,
            };

            let outcome = fetch_models_for_provider_with_store(
                "codex-oauth",
                &entry,
                &resolved,
                Duration::from_secs(5),
                Some(crate::credentials::CredentialStore::open_default().unwrap()),
                |_| None,
            )
            .await
            .unwrap();

            let request = request_handle.await.unwrap();
            assert!(
                request.starts_with("GET /v1/models?client_version=0.0.0 "),
                "unexpected Codex model-list request: {request}"
            );
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
            is_codex_credential: false,
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
        let env = crate::test_env::lock_async().await;
        let tmp = tempfile::tempdir().unwrap();
        install_codex_tokens(&env, &tmp);
        let (base_url, request_handle) =
            serve_models_once(r#"{"models":[{"slug":"gpt-5.5","display_name":"GPT-5.5"}]}"#).await;
        let entry = codex_entry(base_url.clone());
        let resolved = ResolvedRequest {
            base_url,
            headers: Vec::new(),
            is_codex_credential: false,
        };

        let outcome = fetch_models_for_provider_with_store(
            "codex-oauth",
            &entry,
            &resolved,
            Duration::from_secs(5),
            Some(crate::credentials::CredentialStore::open_default().unwrap()),
            |_| None,
        )
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
    }

    #[tokio::test]
    async fn codex_auth_failures_do_not_offer_fallback_catalog() {
        let env = crate::test_env::lock_async().await;
        let tmp = tempfile::tempdir().unwrap();
        install_codex_tokens(&env, &tmp);

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
                is_codex_credential: false,
            };

            let err = fetch_models_for_provider_with_store(
                "codex-oauth",
                &entry,
                &resolved,
                Duration::from_secs(5),
                Some(crate::credentials::CredentialStore::open_default().unwrap()),
                |_| None,
            )
            .await
            .unwrap_err();
            assert!(err.to_string().contains(&format!("returned {status}")));
            assert_eq!(request_handle.await.unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn oversized_success_response_body_errors_before_parse() {
        let mut body = String::from(r#"{"data":[]}"#);
        body.push_str(&" ".repeat(MAX_MODELS_RESPONSE_BYTES));
        let (base_url, request_handle) = serve_models_once(body).await;
        let entry = ProviderEntry {
            url: base_url.clone(),
            allow_insecure_http: true,
            ..ProviderEntry::default()
        };
        let resolved = ResolvedRequest {
            base_url,
            headers: Vec::new(),
            is_codex_credential: false,
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
            is_codex_credential: false,
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

    #[tokio::test]
    async fn baseten_models_fetches_v1_models() {
        let (base_url, request_handle) =
            serve_models_once(r#"{"data":[{"id":"moonshotai/Kimi-K2.5","object":"model"}]}"#).await;
        let mut entry = ProviderEntry {
            url: base_url.clone(),
            template: Some("baseten".into()),
            allow_insecure_http: true,
            headers: vec![crate::config::providers::HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer bt-test".into(),
            }],
            models: vec![
                crate::config::providers::ModelEntry {
                    id: "manual-keep".into(),
                    manual: true,
                    favorite: true,
                    name: Some("kept-name".into()),
                    ..Default::default()
                },
                crate::config::providers::ModelEntry {
                    id: "moonshotai/Kimi-K2.5".into(),
                    favorite: true,
                    quality_rank: Some(3),
                    ..Default::default()
                },
            ],
            ..ProviderEntry::default()
        };
        let resolved = ResolvedRequest {
            base_url: base_url.clone(),
            headers: vec![ResolvedHeader {
                name: "Authorization".into(),
                value: "Bearer bt-test".into(),
            }],
            is_codex_credential: false,
        };

        let outcome =
            fetch_models_for_provider("baseten", &entry, &resolved, Duration::from_secs(5))
                .await
                .unwrap();
        let request = request_handle.await.unwrap();
        let request_line = request.lines().next().unwrap_or_default();
        assert_eq!(
            request_line, "GET /v1/models HTTP/1.1",
            "exact models route required, got {request_line}"
        );
        assert!(!request.contains("model-"), "{request}");
        assert_eq!(
            request_header_value(&request, "authorization"),
            Some("Bearer bt-test")
        );
        match outcome {
            FetchOutcome::Models { models, catalog } => {
                assert_eq!(catalog, ProviderModelCatalog::Live);
                assert!(models.iter().any(|m| m.id == "moonshotai/Kimi-K2.5"));
                let before = entry.models.clone();
                entry.models = crate::config::providers::merge_fetched_models_with_policy(
                    entry.effective_template("baseten"),
                    &before,
                    models,
                    crate::config::providers::ModelMergePolicy::KeepUnlisted,
                );
                entry.models_fetched_at = Some(chrono::Utc::now());
                entry.model_catalog = catalog;
                entry.mark_model_fetch_success(catalog);
                assert!(
                    entry
                        .models
                        .iter()
                        .any(|m| m.id == "manual-keep" && m.manual && m.favorite),
                    "manual model must survive keep-policy merge: {:?}",
                    entry.models
                );
                let refreshed = entry
                    .models
                    .iter()
                    .find(|m| m.id == "moonshotai/Kimi-K2.5")
                    .expect("fetched model");
                assert!(refreshed.favorite, "user favorite override must survive");
                assert_eq!(refreshed.quality_rank, Some(3));
                assert!(entry.models_fetched_at.is_some());
                assert_eq!(entry.model_catalog, ProviderModelCatalog::Live);
                let status = entry.last_model_fetch.expect("fetch status");
                assert_eq!(
                    status.status,
                    crate::config::providers::ModelFetchStatusKind::Live
                );
            }
            other => panic!("expected models, got {other:?}"),
        }

        // Bounded success body: oversized payloads error before parse/merge.
        {
            let mut body = String::from(r#"{"data":[{"id":"too-big"}]}"#);
            body.push_str(&" ".repeat(MAX_MODELS_RESPONSE_BYTES));
            let (base_url, _) = serve_models_once(body).await;
            let mut entry = ProviderEntry {
                url: base_url.clone(),
                template: Some("baseten".into()),
                allow_insecure_http: true,
                models: vec![crate::config::providers::ModelEntry {
                    id: "manual-keep".into(),
                    manual: true,
                    ..Default::default()
                }],
                ..ProviderEntry::default()
            };
            let resolved = ResolvedRequest {
                base_url,
                headers: Vec::new(),
                is_codex_credential: false,
            };
            let err =
                fetch_models_for_provider("baseten", &entry, &resolved, Duration::from_secs(5))
                    .await
                    .unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("response body exceeded"), "{msg}");
            entry.mark_model_fetch_failed_kept_existing(msg);
            assert_eq!(entry.models[0].id, "manual-keep");
            assert_eq!(entry.models.len(), 1);
        }
    }

    #[test]
    fn baseten_models_preserve_unknown_catalog_metadata() {
        // Table-driven unrecognised field shapes: absent key, object, array,
        // number, boolean, null, and malformed (non-object) top-level data entry.
        let cases: &[(&str, &str, serde_json::Value)] = &[
            (
                "object",
                r#"{"data":[{"id":"m-obj","pricing":{"prompt":0.1,"completion":0.2}}]}"#,
                serde_json::json!({"prompt": 0.1, "completion": 0.2}),
            ),
            (
                "array",
                r#"{"data":[{"id":"m-arr","tags":["chat","tools"]}]}"#,
                serde_json::json!(["chat", "tools"]),
            ),
            (
                "number",
                r#"{"data":[{"id":"m-num","rank":7}]}"#,
                serde_json::json!(7),
            ),
            (
                "boolean",
                r#"{"data":[{"id":"m-bool","supports_vision":true}]}"#,
                serde_json::json!(true),
            ),
            (
                "null",
                r#"{"data":[{"id":"m-null","weird":null}]}"#,
                serde_json::Value::Null,
            ),
        ];
        for (label, body, expected) in cases {
            let entries = parse_models_body(body).expect(label);
            assert_eq!(entries.len(), 1, "{label}");
            let m = &entries[0];
            assert!(m.cost_rank.is_none(), "{label}");
            assert!(m.quality_rank.is_none(), "{label}");
            let key = match *label {
                "object" => "pricing",
                "array" => "tags",
                "number" => "rank",
                "boolean" => "supports_vision",
                "null" => "weird",
                _ => unreachable!(),
            };
            for bag in [&m.extra, &m.provider_metadata] {
                assert_eq!(bag.get(key), Some(expected), "{label}");
            }
            let cfg = crate::config::providers::ProvidersConfig {
                providers: std::collections::BTreeMap::from([(
                    "baseten".into(),
                    ProviderEntry {
                        models: vec![m.clone()],
                        ..ProviderEntry::default()
                    },
                )]),
                ..Default::default()
            };
            let caps = cfg.resolve_effective_model_capabilities("baseten", &m.id, 0);
            assert!(
                caps.image_input.status.is_unknown()
                    && caps.audio_input.status.is_unknown()
                    && caps.video_input.status.is_unknown(),
                "{label}"
            );
        }

        // Absent: bare id has no opaque capability/price keys and stays Unknown.
        let bare = parse_models_body(r#"{"data":[{"id":"m-absent"}]}"#).unwrap();
        assert!(bare[0].extra.is_empty() || bare[0].extra.get("id").is_none());
        assert!(bare[0].cost_rank.is_none());
        let cfg = crate::config::providers::ProvidersConfig {
            providers: std::collections::BTreeMap::from([(
                "baseten".into(),
                ProviderEntry {
                    models: bare.clone(),
                    ..ProviderEntry::default()
                },
            )]),
            ..Default::default()
        };
        let caps = cfg.resolve_effective_model_capabilities("baseten", "m-absent", 0);
        assert!(caps.image_input.status.is_unknown());

        // Malformed: non-object entries are skipped; parser still succeeds.
        let mixed =
            parse_models_body(r#"{"data":[null,"skip",{"id":"kept","nested":{"a":[1,2]}}]}"#)
                .expect("malformed siblings");
        assert_eq!(mixed.len(), 1);
        assert_eq!(mixed[0].id, "kept");
        assert_eq!(
            mixed[0]
                .provider_metadata
                .get("nested")
                .and_then(|v| v.get("a")),
            Some(&serde_json::json!([1, 2]))
        );

        // Malformed field values remain opaque without widening capabilities.
        let malformed_field = parse_models_body(
            r#"{"data":[{"id":"m-mal","pricing":"not-an-object","capabilities":"nope"}]}"#,
        )
        .expect("malformed field values");
        assert_eq!(malformed_field.len(), 1);
        assert!(malformed_field[0].cost_rank.is_none());
        assert_eq!(
            malformed_field[0].extra.get("pricing"),
            Some(&serde_json::json!("not-an-object"))
        );
        assert_eq!(
            malformed_field[0].provider_metadata.get("capabilities"),
            Some(&serde_json::json!("nope"))
        );
        let cfg = crate::config::providers::ProvidersConfig {
            providers: std::collections::BTreeMap::from([(
                "baseten".into(),
                ProviderEntry {
                    models: malformed_field.clone(),
                    ..ProviderEntry::default()
                },
            )]),
            ..Default::default()
        };
        let caps = cfg.resolve_effective_model_capabilities("baseten", "m-mal", 0);
        assert!(caps.image_input.status.is_unknown());
        assert!(caps.audio_input.status.is_unknown());
    }

    #[tokio::test]
    async fn baseten_models_fetch_failures_keep_existing_catalog() {
        let existing = vec![crate::config::providers::ModelEntry {
            id: "manual".into(),
            manual: true,
            favorite: true,
            ..Default::default()
        }];

        let assert_kept = |entry: &ProviderEntry, msg: &str, auth_failed: bool| {
            assert_eq!(entry.models.len(), 1);
            assert_eq!(entry.models[0].id, "manual");
            assert!(entry.models[0].manual);
            assert!(entry.models[0].favorite);
            assert!(!msg.contains("SECRETKEY"), "auth secret leaked: {msg}");
            let status = entry.last_model_fetch.as_ref().expect("status recorded");
            if auth_failed {
                assert_eq!(
                    status.status,
                    crate::config::providers::ModelFetchStatusKind::AuthFailed
                );
            } else {
                assert_eq!(
                    status.status,
                    crate::config::providers::ModelFetchStatusKind::FailedKeptExisting
                );
            }
            let reason = status.reason.as_deref().unwrap_or_default();
            assert!(!reason.contains("SECRETKEY"), "redacted reason: {reason}");
            // Failure must not invent capabilities on retained models.
            assert!(entry.models[0].capabilities.image_input.is_unknown());
            assert!(entry.models[0].capabilities.audio_input.is_unknown());
            assert!(entry.models[0].capabilities.video_input.is_unknown());
        };

        for status in [401, 403] {
            let (base_url, request_handle) =
                serve_model_responses(vec![TestModelResponse::status(
                    status,
                    r#"{"error":"denied"}"#,
                )])
                .await;
            let mut entry = ProviderEntry {
                url: base_url.clone(),
                template: Some("baseten".into()),
                allow_insecure_http: true,
                models: existing.clone(),
                model_catalog: ProviderModelCatalog::Live,
                ..ProviderEntry::default()
            };
            let resolved = ResolvedRequest {
                base_url,
                headers: vec![ResolvedHeader {
                    name: "Authorization".into(),
                    value: "Bearer SECRETKEY".into(),
                }],
                is_codex_credential: false,
            };
            let err =
                fetch_models_for_provider("baseten", &entry, &resolved, Duration::from_secs(5))
                    .await
                    .unwrap_err();
            let _ = request_handle.await;
            let msg = err.to_string();
            assert!(msg.contains(&format!("returned {status}")), "{msg}");
            entry.mark_model_fetch_failed_kept_existing(msg.clone());
            assert_kept(&entry, &msg, true);
        }

        // 429 is retryable (MAX_RETRIES=2 → three attempts); exhaust retries with
        // Retry-After:0 so the final error keeps the existing catalog intact.
        {
            let responses = (0..=crate::providers::http_retry::MAX_RETRIES)
                .map(|_| {
                    TestModelResponse::status(429, r#"{"error":"slow"}"#)
                        .with_header("Retry-After", "0")
                })
                .collect();
            let (base_url, request_handle) = serve_model_responses(responses).await;
            let mut entry = ProviderEntry {
                url: base_url.clone(),
                template: Some("baseten".into()),
                allow_insecure_http: true,
                models: existing.clone(),
                model_catalog: ProviderModelCatalog::Live,
                ..ProviderEntry::default()
            };
            let resolved = ResolvedRequest {
                base_url,
                headers: vec![ResolvedHeader {
                    name: "Authorization".into(),
                    value: "Bearer SECRETKEY".into(),
                }],
                is_codex_credential: false,
            };
            let err =
                fetch_models_for_provider("baseten", &entry, &resolved, Duration::from_secs(5))
                    .await
                    .unwrap_err();
            let requests = request_handle.await.unwrap();
            assert_eq!(
                requests.len(),
                crate::providers::http_retry::MAX_RETRIES + 1
            );
            let msg = err.to_string();
            assert!(msg.contains("429"), "{msg}");
            entry.mark_model_fetch_failed_kept_existing(msg.clone());
            assert_kept(&entry, &msg, false);
        }

        // Malformed JSON does not erase entry.models
        {
            let (base_url, _) = serve_models_once("not-json").await;
            let mut entry = ProviderEntry {
                url: base_url.clone(),
                template: Some("baseten".into()),
                allow_insecure_http: true,
                models: existing.clone(),
                model_catalog: ProviderModelCatalog::Live,
                ..ProviderEntry::default()
            };
            let resolved = ResolvedRequest {
                base_url,
                headers: Vec::new(),
                is_codex_credential: false,
            };
            let err =
                fetch_models_for_provider("baseten", &entry, &resolved, Duration::from_secs(5))
                    .await
                    .unwrap_err();
            let msg = err.to_string();
            entry.mark_model_fetch_failed_kept_existing(msg.clone());
            assert_kept(&entry, &msg, false);
        }

        // Timeout: short client deadline against a hanging peer (no response body).
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let _hold = tokio::spawn(async move {
                let (_socket, _) = listener.accept().await.unwrap();
                std::future::pending::<()>().await;
            });
            tokio::task::yield_now().await;
            let base_url = format!("http://{addr}/v1");
            let mut entry = ProviderEntry {
                url: base_url.clone(),
                template: Some("baseten".into()),
                allow_insecure_http: true,
                models: existing.clone(),
                model_catalog: ProviderModelCatalog::Live,
                ..ProviderEntry::default()
            };
            let resolved = ResolvedRequest {
                base_url,
                headers: Vec::new(),
                is_codex_credential: false,
            };
            let err =
                fetch_models_for_provider("baseten", &entry, &resolved, Duration::from_millis(50))
                    .await
                    .unwrap_err();
            let msg = err.to_string();
            entry.mark_model_fetch_failed_kept_existing(msg.clone());
            assert_kept(&entry, &msg, false);
        }

        // Transport failure: bind then drop an ephemeral listener so the port is closed.
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);
            let base_url = format!("http://{addr}/v1");
            let mut entry = ProviderEntry {
                url: base_url.clone(),
                template: Some("baseten".into()),
                allow_insecure_http: true,
                models: existing.clone(),
                model_catalog: ProviderModelCatalog::Live,
                ..ProviderEntry::default()
            };
            let resolved = ResolvedRequest {
                base_url,
                headers: Vec::new(),
                is_codex_credential: false,
            };
            let err =
                fetch_models_for_provider("baseten", &entry, &resolved, Duration::from_secs(2))
                    .await
                    .unwrap_err();
            let msg = err.to_string();
            entry.mark_model_fetch_failed_kept_existing(msg.clone());
            assert_kept(&entry, &msg, false);
        }
    }
}
