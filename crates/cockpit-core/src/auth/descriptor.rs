//! Config-driven OAuth for custom providers.
//!
//! The provider descriptor is the authority for endpoints and header mapping;
//! credential records contain only the resulting token document plus cache
//! metadata. No provider-supplied code is executed.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cockpit_config::config::providers::{OAuthDescriptor, OAuthFlowKind};
use futures::StreamExt;
use rand::Rng;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::credentials::CredentialStore;

const REFRESH_SKEW_SECS: i64 = 120;
const DEFAULT_DEVICE_INTERVAL_SECS: u64 = 5;
const MIN_DEVICE_INTERVAL_SECS: u64 = 1;
const MAX_DEVICE_POLL_SECS: u64 = 15 * 60;
const OAUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OAUTH_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
/// OAuth endpoints are configured data, not a trusted daemon service.  Keep
/// their error and token documents comfortably below the RPC payload ceiling.
const MAX_OAUTH_RESPONSE_BYTES: usize = 64 * 1024;

/// Reserved vault-record namespace owned exclusively by declarative OAuth.
///
/// Provider ids are user-facing configuration names and are also used by
/// unrelated credential owners. They must never be used as the durable
/// identity of a descriptor token record.
pub(crate) const CREDENTIAL_RECORD_PREFIX: &str =
    cockpit_proto::RESERVED_DESCRIPTOR_OAUTH_PROVIDER_ID_PREFIX;

pub(crate) fn credential_record_id(provider_id: &str) -> String {
    format!("{CREDENTIAL_RECORD_PREFIX}{provider_id}")
}

pub(crate) fn is_credential_record_id(record_id: &str) -> bool {
    record_id.starts_with(CREDENTIAL_RECORD_PREFIX)
}

pub(crate) fn ensure_public_credential_record_id(record_id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !is_credential_record_id(record_id),
        "provider credential reference `{record_id}` uses a reserved namespace"
    );
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredCredential {
    configuration_identity: String,
    refresh_generation: u64,
    token: Map<String, Value>,
    expires_at: Option<i64>,
}

#[derive(Clone)]
pub(crate) struct DescriptorCredential {
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) refresh_generation: u64,
}

impl std::fmt::Debug for DescriptorCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DescriptorCredential")
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("refresh_generation", &self.refresh_generation)
            .finish()
    }
}

/// Serializable state returned while a device-code authorization is pending.
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceCodeLogin {
    pub verification_uri: String,
    pub user_code: String,
    device_code: String,
    interval_secs: u64,
    expires_in_secs: u64,
    configuration_identity: String,
}

impl std::fmt::Debug for DeviceCodeLogin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceCodeLogin")
            .field("verification_uri", &self.verification_uri)
            .field("user_code", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for DeviceCodeLogin {
    fn drop(&mut self) {
        self.user_code.zeroize();
        self.device_code.zeroize();
        self.configuration_identity.zeroize();
    }
}

/// Serializable state returned while a PKCE browser authorization is pending.
#[derive(Clone, Serialize, Deserialize)]
pub struct PkceBrowserLogin {
    pub authorize_url: String,
    state: String,
    verifier: String,
    configuration_identity: String,
}

impl std::fmt::Debug for PkceBrowserLogin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PkceBrowserLogin")
            .field("authorize_url", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Drop for PkceBrowserLogin {
    fn drop(&mut self) {
        self.authorize_url.zeroize();
        self.state.zeroize();
        self.verifier.zeroize();
        self.configuration_identity.zeroize();
    }
}

#[derive(Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    #[serde(default)]
    verification_uri: Option<String>,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default)]
    interval: Option<u64>,
    #[serde(default)]
    expires_in: Option<u64>,
}

pub async fn begin_device_code_login(descriptor: &OAuthDescriptor) -> Result<DeviceCodeLogin> {
    validate_descriptor(descriptor, OAuthFlowKind::DeviceCode)?;
    let endpoint = descriptor.device_endpoint.as_deref().unwrap();
    let mut params = vec![("client_id", descriptor.client_id.as_str())];
    let scopes = descriptor.scopes.join(" ");
    if !scopes.is_empty() {
        params.push(("scope", scopes.as_str()));
    }
    let response = oauth_client()?
        .post(endpoint)
        .form(&params)
        .send()
        .await
        .context("requesting OAuth device code")?
        .error_for_status()
        .context("OAuth device-code request failed")?;
    let body = bounded_response_body(response).await?;
    let parsed: DeviceAuthorizationResponse =
        serde_json::from_str(&body).context("OAuth device-code response is malformed")?;
    ensure_nonempty(&parsed.device_code, "device_code")?;
    ensure_nonempty(&parsed.user_code, "user_code")?;
    let verification_uri = parsed
        .verification_uri_complete
        .or(parsed.verification_uri)
        .or_else(|| descriptor.authorize_endpoint.clone())
        .filter(|value| !value.is_empty())
        .context("OAuth device-code response is missing verification_uri")?;
    validate_endpoint(&verification_uri, true)?;
    Ok(DeviceCodeLogin {
        verification_uri,
        user_code: parsed.user_code,
        device_code: parsed.device_code,
        interval_secs: parsed
            .interval
            .unwrap_or(DEFAULT_DEVICE_INTERVAL_SECS)
            .clamp(MIN_DEVICE_INTERVAL_SECS, MAX_DEVICE_POLL_SECS),
        expires_in_secs: parsed.expires_in.unwrap_or(MAX_DEVICE_POLL_SECS),
        configuration_identity: configuration_identity(descriptor)?,
    })
}

pub async fn complete_device_code_login_in(
    provider_id: &str,
    descriptor: &OAuthDescriptor,
    login: DeviceCodeLogin,
    store: CredentialStore,
) -> Result<()> {
    let token = complete_device_code_login_unpersisted(descriptor, &login).await?;
    persist_initial(provider_id, descriptor, store, token).await
}

/// Poll a descriptor device-code flow without persisting its token document.
/// The daemon uses this so the one-shot OAuth-flow fence and credential write
/// can commit atomically in its vault transaction.
pub(crate) async fn complete_device_code_login_unpersisted(
    descriptor: &OAuthDescriptor,
    login: &DeviceCodeLogin,
) -> Result<Map<String, Value>> {
    complete_device_code_login_unpersisted_for(
        descriptor,
        login,
        Duration::from_secs(login.expires_in_secs.min(MAX_DEVICE_POLL_SECS)),
        None,
    )
    .await
}

/// Poll a descriptor device-code flow for no longer than `maximum_wait`.
///
/// The daemon passes the remaining lifetime of its durable OAuth flow here so
/// a client-side response timeout cannot leave provider polling alive beyond
/// that flow's advertised completion deadline.
pub(crate) async fn complete_device_code_login_unpersisted_for(
    descriptor: &OAuthDescriptor,
    login: &DeviceCodeLogin,
    maximum_wait: Duration,
    cancellation_fence: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Map<String, Value>> {
    validate_descriptor(descriptor, OAuthFlowKind::DeviceCode)?;
    validate_login_identity(descriptor, &login.configuration_identity)?;
    let deadline = std::time::Instant::now()
        + maximum_wait.min(Duration::from_secs(
            login.expires_in_secs.min(MAX_DEVICE_POLL_SECS),
        ));
    let mut interval = login.interval_secs;
    loop {
        if cancellation_fence.is_some_and(|fence| fence.load(std::sync::atomic::Ordering::SeqCst)) {
            anyhow::bail!("OAuth device-code login was cancelled");
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("OAuth device-code login timed out; try again");
        }
        let response = token_post(
            &descriptor.token_endpoint,
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", login.device_code.as_str()),
                ("client_id", descriptor.client_id.as_str()),
            ],
        )
        .await?;
        let status = response.status();
        let body = bounded_response_body(response).await?;
        if cancellation_fence.is_some_and(|fence| fence.load(std::sync::atomic::Ordering::SeqCst)) {
            anyhow::bail!("OAuth device-code login was cancelled");
        }
        if status.is_success() {
            anyhow::ensure!(
                !deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .is_zero(),
                "OAuth device-code login timed out; try again"
            );
            return parse_token_response(&body);
        }
        let error = oauth_error_code(&body);
        match error.as_deref() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval = interval.saturating_add(5).min(30),
            _ => return Err(token_endpoint_error(status, &body)),
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("OAuth device-code login timed out; try again");
        }
        if cancellation_fence.is_some_and(|fence| fence.load(std::sync::atomic::Ordering::SeqCst)) {
            anyhow::bail!("OAuth device-code login was cancelled");
        }
        tokio::time::sleep(Duration::from_secs(interval).min(remaining)).await;
    }
}

pub fn begin_pkce_browser_login(descriptor: &OAuthDescriptor) -> Result<PkceBrowserLogin> {
    validate_descriptor(descriptor, OAuthFlowKind::PkceBrowser)?;
    let verifier = random_urlsafe(32);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_urlsafe(32);
    let mut url = Url::parse(descriptor.authorize_endpoint.as_deref().unwrap())
        .context("OAuth authorize_endpoint is not a URL")?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &descriptor.client_id)
            .append_pair("redirect_uri", descriptor.redirect_uri.as_deref().unwrap())
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        if !descriptor.scopes.is_empty() {
            query.append_pair("scope", &descriptor.scopes.join(" "));
        }
    }
    Ok(PkceBrowserLogin {
        authorize_url: url.to_string(),
        state,
        verifier,
        configuration_identity: configuration_identity(descriptor)?,
    })
}

pub async fn complete_pkce_browser_login_in(
    provider_id: &str,
    descriptor: &OAuthDescriptor,
    login: PkceBrowserLogin,
    callback_or_code: &str,
    store: CredentialStore,
) -> Result<()> {
    let token =
        complete_pkce_browser_login_unpersisted(descriptor, &login, callback_or_code).await?;
    persist_initial(provider_id, descriptor, store, token).await
}

/// Exchange a descriptor PKCE flow without persisting its token document.
/// See [`complete_device_code_login_unpersisted`] for why daemon callers use
/// this lower-level primitive.
pub(crate) async fn complete_pkce_browser_login_unpersisted(
    descriptor: &OAuthDescriptor,
    login: &PkceBrowserLogin,
    callback_or_code: &str,
) -> Result<Map<String, Value>> {
    validate_descriptor(descriptor, OAuthFlowKind::PkceBrowser)?;
    validate_login_identity(descriptor, &login.configuration_identity)?;
    let code = parse_callback(callback_or_code, &login.state)?;
    let response = token_post(
        &descriptor.token_endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", descriptor.client_id.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", descriptor.redirect_uri.as_deref().unwrap()),
            ("code_verifier", login.verifier.as_str()),
        ],
    )
    .await?;
    let status = response.status();
    let body = bounded_response_body(response).await?;
    if !status.is_success() {
        return Err(token_endpoint_error(status, &body));
    }
    parse_token_response(&body)
}

pub(crate) async fn resolve(
    provider_id: &str,
    descriptor: &OAuthDescriptor,
    store: CredentialStore,
    force_refresh: bool,
    rejected_refresh_generation: Option<u64>,
) -> Result<DescriptorCredential> {
    validate_descriptor(descriptor, descriptor.flow)?;
    let identity = configuration_identity(descriptor)?;
    let refresh_key = format!("oauth:{provider_id}");
    let descriptor_record_id = credential_record_id(provider_id);
    crate::auth::refresh_guard::serialized_refresh(&refresh_key, || async move {
        let cached = load_cached(&store, provider_id, &identity)?
            .with_context(|| format!("provider `{provider_id}` requires OAuth login"))?;
        let another_waiter_refreshed = force_refresh
            && rejected_refresh_generation
                .is_some_and(|rejected| rejected != cached.refresh_generation);
        if another_waiter_refreshed || (!force_refresh && !needs_refresh(&cached)) {
            return render_credential(descriptor, cached);
        }
        let refresh_token = cached
            .token
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .context("stored OAuth credential cannot refresh: refresh_token is missing")?;
        let refresh_endpoint = descriptor
            .refresh_endpoint
            .as_deref()
            .unwrap_or(&descriptor.token_endpoint);
        let response = token_post(
            refresh_endpoint,
            &[
                ("grant_type", "refresh_token"),
                ("client_id", descriptor.client_id.as_str()),
                ("refresh_token", refresh_token),
            ],
        )
        .await?;
        let status = response.status();
        let body = bounded_response_body(response).await?;
        if !status.is_success() {
            let error = token_endpoint_error(status, &body);
            if is_terminal_refresh_error(status, &body) {
                // The same provider lock covers login and refresh persistence.
                // A concurrent descriptor writer can therefore only have
                // changed this record before our re-open, never during this
                // decision.  Still compare the token: a non-descriptor owner
                // may have replaced the record externally.
                if load_cached_record(&store, &descriptor_record_id, &identity)?.is_some_and(
                    |latest| {
                        latest.token.get("refresh_token").and_then(Value::as_str)
                            == Some(refresh_token)
                    },
                ) {
                    store.remove_record_merged(&descriptor_record_id)?;
                }
            }
            return Err(error);
        }
        let mut merged = cached.token;
        // Expiry metadata describes the access token returned alongside it.
        // Never carry an already-expired absolute timestamp onto a rotated
        // token when the refresh response omits fresh lifetime metadata.
        merged.remove("expires_at");
        merged.remove("expires_in");
        merged.extend(parse_token_response(&body)?);
        validate_token_mapping(descriptor, &merged)?;
        let refreshed = StoredCredential {
            configuration_identity: identity,
            refresh_generation: cached.refresh_generation.saturating_add(1),
            expires_at: token_expiry(&merged),
            token: merged,
        };
        store.save_record_merged(
            &descriptor_record_id,
            serde_json::json!({ "oauth": refreshed }),
        )?;
        render_credential(descriptor, refreshed)
    })
    .await
}

async fn persist_initial(
    provider_id: &str,
    descriptor: &OAuthDescriptor,
    store: CredentialStore,
    token: Map<String, Value>,
) -> Result<()> {
    let provider_id = provider_id.to_owned();
    let lock_provider_id = provider_id.clone();
    let descriptor = descriptor.clone();
    serialized_credential_mutation(&lock_provider_id, move || async move {
        let record = initial_record(&provider_id, &descriptor, &store, token)?;
        store.save_record_merged(&credential_record_id(&provider_id), record)
    })
    .await
}

/// Serialize every descriptor-owned credential mutation for one provider.
/// Refresh holds this lock across reload, exchange, and save; initial login
/// callers use it around their durable persistence transaction as well.
pub(crate) async fn serialized_credential_mutation<T, F, Fut>(provider_id: &str, mutation: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    crate::auth::refresh_guard::serialized_refresh(&format!("oauth:{provider_id}"), mutation).await
}

pub(crate) async fn credential_mutation_lock(
    provider_id: &str,
) -> tokio::sync::OwnedMutexGuard<()> {
    crate::auth::refresh_guard::serialized_refresh_lock(&format!("oauth:{provider_id}")).await
}

/// Build the persisted descriptor record while the caller owns
/// [`serialized_credential_mutation`].  The daemon uses this to keep OAuth
/// flow fencing and credential persistence in one SQLite transaction.
pub(crate) fn initial_record(
    provider_id: &str,
    descriptor: &OAuthDescriptor,
    store: &CredentialStore,
    token: Map<String, Value>,
) -> Result<Value> {
    validate_token_mapping(descriptor, &token)?;
    let configuration_identity = configuration_identity(descriptor)?;
    let refresh_generation = load_cached(store, provider_id, &configuration_identity)?
        .map_or(1, |cached| cached.refresh_generation.saturating_add(1));
    let cached = StoredCredential {
        configuration_identity,
        refresh_generation,
        expires_at: token_expiry(&token),
        token,
    };
    Ok(serde_json::json!({ "oauth": cached }))
}

fn load_cached(
    store: &CredentialStore,
    provider_id: &str,
    identity: &str,
) -> Result<Option<StoredCredential>> {
    load_cached_record(store, &credential_record_id(provider_id), identity)
}

fn load_cached_record(
    store: &CredentialStore,
    record_id: &str,
    identity: &str,
) -> Result<Option<StoredCredential>> {
    store
        .get_owned(record_id)?
        .and_then(|record| record.get("oauth").cloned())
        .map(serde_json::from_value::<StoredCredential>)
        .transpose()
        .with_context(|| format!("stored OAuth credential `{record_id}` is malformed"))
        .map(|cached| cached.filter(|cached| cached.configuration_identity == identity))
}

fn render_credential(
    descriptor: &OAuthDescriptor,
    cached: StoredCredential,
) -> Result<DescriptorCredential> {
    let headers = render_headers(descriptor, &cached.token)?;
    Ok(DescriptorCredential {
        headers,
        refresh_generation: cached.refresh_generation,
    })
}

/// Render and validate the full HTTP projection before a token document can
/// become durable. Token-response fields are untrusted endpoint data, so
/// placeholder expansion alone is not sufficient validation.
fn render_headers(
    descriptor: &OAuthDescriptor,
    token: &Map<String, Value>,
) -> Result<BTreeMap<String, String>> {
    let mut headers = BTreeMap::new();
    let mut normalized_names = std::collections::BTreeSet::new();
    for mapping in &descriptor.headers {
        let value = render_template(&mapping.value, token)?;
        anyhow::ensure!(
            reqwest::header::HeaderName::from_bytes(mapping.name.as_bytes()).is_ok()
                && reqwest::header::HeaderValue::from_str(&value).is_ok(),
            "OAuth header mapping produced an invalid header"
        );
        anyhow::ensure!(
            normalized_names.insert(mapping.name.to_ascii_lowercase()),
            "OAuth header mapping contains duplicate header names"
        );
        headers.insert(mapping.name.clone(), value);
    }
    Ok(headers)
}

fn validate_token_mapping(descriptor: &OAuthDescriptor, token: &Map<String, Value>) -> Result<()> {
    render_headers(descriptor, token).map(|_| ())
}

fn render_template(template: &str, token: &Map<String, Value>) -> Result<String> {
    let mut rendered = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        rendered.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let close = after_open
            .find('}')
            .context("OAuth header mapping contains an unclosed placeholder")?;
        let field = &after_open[..close];
        anyhow::ensure!(
            !field.is_empty() && !field.contains('{'),
            "OAuth header mapping contains an invalid placeholder"
        );
        let value = token
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .with_context(|| format!("OAuth token response is missing string field `{field}`"))?;
        rendered.push_str(value);
        rest = &after_open[close + 1..];
    }
    anyhow::ensure!(
        !rest.contains('}'),
        "OAuth header mapping contains an unmatched closing brace"
    );
    rendered.push_str(rest);
    Ok(rendered)
}

fn validate_descriptor(descriptor: &OAuthDescriptor, expected: OAuthFlowKind) -> Result<()> {
    descriptor.validate().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        descriptor.flow == expected,
        "OAuth flow kind does not match operation"
    );
    validate_endpoint(&descriptor.token_endpoint, false)?;
    if let Some(endpoint) = descriptor.refresh_endpoint.as_deref() {
        validate_endpoint(endpoint, false)?;
    }
    if let Some(endpoint) = descriptor.device_endpoint.as_deref() {
        validate_endpoint(endpoint, false)?;
    }
    if let Some(endpoint) = descriptor.authorize_endpoint.as_deref() {
        validate_endpoint(endpoint, true)?;
    }
    if let Some(redirect_uri) = descriptor.redirect_uri.as_deref() {
        validate_endpoint(redirect_uri, true)?;
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str, browser_facing: bool) -> Result<()> {
    let url = Url::parse(endpoint).context("OAuth endpoint is not a URL")?;
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    anyhow::ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "OAuth endpoints must use HTTPS (HTTP is allowed only on loopback)"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
        "OAuth endpoint contains forbidden URL components"
    );
    if !browser_facing {
        anyhow::ensure!(
            url.query().is_none(),
            "OAuth POST endpoint must not contain a query"
        );
    }
    Ok(())
}

async fn token_post(endpoint: &str, params: &[(&str, &str)]) -> Result<reqwest::Response> {
    oauth_client()?
        .post(endpoint)
        .form(params)
        .send()
        .await
        .with_context(|| format!("POST OAuth token endpoint {endpoint}"))
}

async fn bounded_response_body(response: reqwest::Response) -> Result<String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_OAUTH_RESPONSE_BYTES as u64)
    {
        anyhow::bail!("OAuth endpoint response exceeds {MAX_OAUTH_RESPONSE_BYTES} bytes");
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading OAuth endpoint response")?;
        let remaining = MAX_OAUTH_RESPONSE_BYTES.saturating_sub(body.len());
        if chunk.len() > remaining {
            anyhow::bail!("OAuth endpoint response exceeds {MAX_OAUTH_RESPONSE_BYTES} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).context("OAuth endpoint response is not UTF-8")
}

fn oauth_client() -> Result<reqwest::Client> {
    crate::providers::provider_http::client_builder()
        .connect_timeout(OAUTH_CONNECT_TIMEOUT)
        .timeout(OAUTH_TOTAL_TIMEOUT)
        .build()
        .context("building OAuth HTTP client")
}

fn parse_token_response(body: &str) -> Result<Map<String, Value>> {
    let Value::Object(token) =
        serde_json::from_str(body).context("OAuth token response is malformed")?
    else {
        anyhow::bail!("OAuth token response must be a JSON object");
    };
    Ok(token)
}

fn token_expiry(token: &Map<String, Value>) -> Option<i64> {
    token.get("expires_at").and_then(Value::as_i64).or_else(|| {
        token
            .get("expires_in")
            .and_then(Value::as_i64)
            .map(|ttl| unix_now().saturating_add(ttl))
    })
}

fn needs_refresh(cached: &StoredCredential) -> bool {
    cached
        .expires_at
        .is_some_and(|expires_at| expires_at.saturating_sub(unix_now()) <= REFRESH_SKEW_SECS)
}

fn parse_callback(input: &str, expected_state: &str) -> Result<String> {
    let trimmed = input.trim();
    if !trimmed.contains('?') && !trimmed.contains('=') {
        anyhow::ensure!(!trimmed.is_empty(), "OAuth callback is missing `code`");
        return Ok(trimmed.to_string());
    }
    let query = trimmed
        .split_once('?')
        .map_or(trimmed, |(_, query)| query)
        .split('#')
        .next()
        .unwrap_or_default();
    let values: BTreeMap<_, _> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    anyhow::ensure!(!values.contains_key("error"), "OAuth authorization failed");
    let state = values
        .get("state")
        .context("OAuth callback is missing `state` (possible CSRF)")?;
    anyhow::ensure!(
        state == expected_state,
        "OAuth state mismatch (possible CSRF)"
    );
    values
        .get("code")
        .filter(|code| !code.is_empty())
        .cloned()
        .context("OAuth callback is missing `code`")
}

fn configuration_identity(descriptor: &OAuthDescriptor) -> Result<String> {
    let bytes = serde_json::to_vec(descriptor).context("serializing OAuth descriptor")?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn validate_login_identity(descriptor: &OAuthDescriptor, identity: &str) -> Result<()> {
    anyhow::ensure!(
        configuration_identity(descriptor)? == identity,
        "OAuth provider configuration changed while login was pending"
    );
    Ok(())
}

fn oauth_error_code(body: &str) -> Option<String> {
    serde_json::from_str::<Value>(body).ok().and_then(|value| {
        value
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

fn token_endpoint_error(status: StatusCode, _body: &str) -> anyhow::Error {
    anyhow!("OAuth token endpoint rejected the request ({status})")
}

fn is_terminal_refresh_error(status: StatusCode, body: &str) -> bool {
    matches!(
        oauth_error_code(body).as_deref(),
        Some("invalid_grant" | "invalid_client" | "unauthorized_client" | "invalid_token")
    ) || (status == StatusCode::UNAUTHORIZED && oauth_error_code(body).is_none())
}

fn ensure_nonempty(value: &str, field: &str) -> Result<()> {
    anyhow::ensure!(!value.is_empty(), "OAuth response field `{field}` is empty");
    Ok(())
}

fn random_urlsafe(bytes: usize) -> String {
    let mut raw = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_config::config::providers::{OAuthHeaderMapping, ProviderEntry};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn descriptor(base: &str, flow: OAuthFlowKind) -> OAuthDescriptor {
        OAuthDescriptor {
            flow,
            authorize_endpoint: (flow == OAuthFlowKind::PkceBrowser)
                .then(|| format!("{base}/authorize")),
            device_endpoint: (flow == OAuthFlowKind::DeviceCode).then(|| format!("{base}/device")),
            token_endpoint: format!("{base}/token"),
            refresh_endpoint: Some(format!("{base}/refresh")),
            client_id: "test-client".to_string(),
            scopes: vec!["openid".to_string(), "offline_access".to_string()],
            redirect_uri: (flow == OAuthFlowKind::PkceBrowser)
                .then(|| "http://127.0.0.1:8765/callback".to_string()),
            headers: vec![
                OAuthHeaderMapping {
                    name: "Authorization".to_string(),
                    value: "Bearer {access_token}".to_string(),
                },
                OAuthHeaderMapping {
                    name: "X-Account".to_string(),
                    value: "{account_id}".to_string(),
                },
            ],
        }
    }

    fn store() -> (tempfile::TempDir, CredentialStore) {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::open(temp.path().join("credentials.json")).unwrap();
        (temp, store)
    }

    async fn response_server(
        responses: Vec<&'static str>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for body in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..read]);
                    if let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n")
                    {
                        let headers = String::from_utf8_lossy(&bytes[..header_end]);
                        let content_length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|value| value.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= header_end + 4 + content_length {
                            break;
                        }
                    }
                }
                requests.push(String::from_utf8_lossy(&bytes).into_owned());
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(reply.as_bytes()).await.unwrap();
            }
            requests
        });
        (format!("http://{address}"), task)
    }

    async fn error_response_server(body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let reply = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn device_code_happy_path_persists_and_maps_headers() {
        let (base, server) = response_server(vec![
            r#"{"device_code":"device","user_code":"ABCD","verification_uri":"https://example.test/verify","interval":1}"#,
            r#"{"access_token":"device-access","refresh_token":"refresh","expires_in":3600,"account_id":"acct-1"}"#,
        ])
        .await;
        let descriptor = descriptor(&base, OAuthFlowKind::DeviceCode);
        let login = begin_device_code_login(&descriptor).await.unwrap();
        assert_eq!(login.user_code, "ABCD");
        let (_temp, mut store) = store();
        store.set_api_key("custom", "unrelated-api-key");
        store.save().unwrap();
        complete_device_code_login_in("custom", &descriptor, login, store.clone())
            .await
            .unwrap();

        let entry = ProviderEntry {
            url: "https://api.example.test/v1".to_string(),
            oauth: Some(descriptor),
            ..ProviderEntry::default()
        };
        let resolved = crate::providers::models_fetch::resolve_provider_request_async_with_store(
            "custom",
            &entry,
            store.clone(),
            |_| None,
        )
        .await
        .unwrap();
        assert!(
            resolved
                .headers
                .iter()
                .any(|header| header.name == "Authorization"
                    && header.value == "Bearer device-access")
        );
        assert!(
            resolved
                .headers
                .iter()
                .any(|header| header.name == "X-Account" && header.value == "acct-1")
        );
        assert_eq!(
            store.reopen().unwrap().api_key("custom").as_deref(),
            Some("unrelated-api-key")
        );
        let requests = server.await.unwrap();
        assert!(requests[0].contains("client_id=test-client"));
        assert!(requests[1].contains("device_code=device"));
    }

    #[tokio::test]
    async fn pkce_happy_path_binds_state_and_exchanges_code() {
        let (base, server) = response_server(vec![
            r#"{"access_token":"pkce-access","refresh_token":"refresh","expires_in":3600,"account_id":"acct-2"}"#,
        ])
        .await;
        let descriptor = descriptor(&base, OAuthFlowKind::PkceBrowser);
        let login = begin_pkce_browser_login(&descriptor).unwrap();
        assert!(login.authorize_url.contains("code_challenge_method=S256"));
        let callback = format!(
            "http://127.0.0.1:8765/callback?code=approved&state={}",
            login.state
        );
        let (_temp, mut store) = store();
        store.set_api_key("custom", "unrelated-api-key");
        store.save().unwrap();
        complete_pkce_browser_login_in("custom", &descriptor, login, &callback, store.clone())
            .await
            .unwrap();
        let credential = resolve("custom", &descriptor, store.clone(), false, None)
            .await
            .unwrap();
        assert_eq!(credential.headers["Authorization"], "Bearer pkce-access");
        assert_eq!(
            store.reopen().unwrap().api_key("custom").as_deref(),
            Some("unrelated-api-key")
        );
        let requests = server.await.unwrap();
        assert!(requests[0].contains("code=approved"));
        assert!(requests[0].contains("code_verifier="));
    }

    #[tokio::test]
    async fn expired_credential_refreshes_and_preserves_omitted_fields() {
        let (base, server) =
            response_server(vec![r#"{"access_token":"fresh-access","expires_in":3600}"#]).await;
        let descriptor = descriptor(&base, OAuthFlowKind::DeviceCode);
        let (_temp, mut store) = store();
        store.set_api_key("custom", "unrelated-api-key");
        store.save().unwrap();
        persist_initial(
            "custom",
            &descriptor,
            store.clone(),
            serde_json::from_value(serde_json::json!({
                "access_token": "expired-access",
                "refresh_token": "rotate-me",
                "expires_in": 0,
                "account_id": "preserved-account"
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let credential = resolve("custom", &descriptor, store.clone(), false, None)
            .await
            .unwrap();
        assert_eq!(credential.headers["Authorization"], "Bearer fresh-access");
        assert_eq!(credential.headers["X-Account"], "preserved-account");
        assert_eq!(credential.refresh_generation, 2);
        assert_eq!(
            store.reopen().unwrap().api_key("custom").as_deref(),
            Some("unrelated-api-key")
        );
        let requests = server.await.unwrap();
        assert!(requests[0].contains("refresh_token=rotate-me"));
    }

    #[tokio::test]
    async fn malformed_token_response_fails_closed_without_persisting() {
        let (base, server) = response_server(vec![
            r#"{"device_code":"device","user_code":"ABCD","verification_uri":"https://example.test/verify"}"#,
            "{ malformed JSON",
        ])
        .await;
        let descriptor = descriptor(&base, OAuthFlowKind::DeviceCode);
        let (_temp, store) = store();
        let login = begin_device_code_login(&descriptor).await.unwrap();
        let error = complete_device_code_login_in("custom", &descriptor, login, store.clone())
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("OAuth token response is malformed")
        );
        assert!(
            store
                .reopen()
                .unwrap()
                .get(&credential_record_id("custom"))
                .is_none()
        );
        assert_eq!(server.await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn rendered_invalid_header_fails_closed_before_initial_persistence() {
        let descriptor = descriptor("https://example.test", OAuthFlowKind::DeviceCode);
        let (_temp, mut store) = store();
        store.set_api_key("custom", "unrelated-api-key");
        store.save().unwrap();
        let error = persist_initial(
            "custom",
            &descriptor,
            store.clone(),
            serde_json::from_value(serde_json::json!({
                "access_token": "valid\r\ninjected: value",
                "account_id": "account"
            }))
            .unwrap(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("invalid header"));
        assert!(
            store
                .reopen()
                .unwrap()
                .get(&credential_record_id("custom"))
                .is_none()
        );
        assert_eq!(
            store.reopen().unwrap().api_key("custom").as_deref(),
            Some("unrelated-api-key")
        );
    }

    #[tokio::test]
    async fn rendered_invalid_header_does_not_replace_working_credential_on_refresh() {
        let (base, server) = response_server(vec![
            r#"{"access_token":"fresh\r\ninjected: value","expires_in":3600}"#,
        ])
        .await;
        let descriptor = descriptor(&base, OAuthFlowKind::DeviceCode);
        let (_temp, mut store) = store();
        store.set_api_key("custom", "unrelated-api-key");
        store.save().unwrap();
        persist_initial(
            "custom",
            &descriptor,
            store.clone(),
            serde_json::from_value(serde_json::json!({
                "access_token": "working-access",
                "refresh_token": "refresh",
                "expires_in": 0,
                "account_id": "account"
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let error = resolve("custom", &descriptor, store.clone(), false, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("invalid header"));
        let stored = store
            .reopen()
            .unwrap()
            .get(&credential_record_id("custom"))
            .cloned()
            .unwrap();
        assert_eq!(
            stored["oauth"]["token"]["access_token"],
            serde_json::json!("working-access")
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn terminal_refresh_failure_removes_revoked_credential() {
        let base = error_response_server(r#"{"error":"invalid_grant"}"#).await;
        let descriptor = descriptor(&base, OAuthFlowKind::DeviceCode);
        let (_temp, mut store) = store();
        store.set_api_key("custom", "unrelated-api-key");
        store.save().unwrap();
        persist_initial(
            "custom",
            &descriptor,
            store.clone(),
            serde_json::from_value(serde_json::json!({
                "access_token": "expired-access",
                "refresh_token": "revoked-refresh",
                "expires_in": 0,
                "account_id": "account"
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let error = resolve("custom", &descriptor, store.clone(), false, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("rejected"));
        assert!(
            store
                .reopen()
                .unwrap()
                .get(&credential_record_id("custom"))
                .is_none()
        );
        assert_eq!(
            store.reopen().unwrap().api_key("custom").as_deref(),
            Some("unrelated-api-key")
        );
    }

    #[tokio::test]
    async fn scoped_provider_store_resolves_descriptor_request_without_reading_other_reserved_records()
     {
        let descriptor = descriptor("https://example.test", OAuthFlowKind::DeviceCode);
        let entry = ProviderEntry {
            url: "https://api.example.test/v1".to_string(),
            oauth: Some(descriptor.clone()),
            ..ProviderEntry::default()
        };
        let providers = cockpit_config::config::providers::ProvidersConfig {
            providers: std::collections::BTreeMap::from([("custom".to_string(), entry.clone())]),
            ..Default::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = crate::session::Session::create_for_test(
            db,
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        let valid_record_id = credential_record_id("custom");
        let victim_record_id = credential_record_id("victim");
        let full_store = session.credential_store().unwrap();
        full_store
            .save_record_merged(
                &valid_record_id,
                serde_json::json!({
                    "oauth": StoredCredential {
                        configuration_identity: configuration_identity(&descriptor).unwrap(),
                        refresh_generation: 7,
                        expires_at: Some(i64::MAX),
                        token: serde_json::from_value(serde_json::json!({
                            "access_token": "descriptor-access",
                            "account_id": "acct-7"
                        }))
                        .unwrap(),
                    }
                }),
            )
            .unwrap();
        session
            .secret_vault()
            .put_item(
                cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                &victim_record_id,
                b"{not-json-reserved-victim",
            )
            .unwrap();

        let store = session.provider_credential_store(&providers).unwrap();
        assert!(store.get_loaded_owned(&valid_record_id).is_none());
        assert!(store.get_loaded_owned(&victim_record_id).is_none());

        let resolved = crate::providers::models_fetch::resolve_provider_request_async_with_store(
            "custom",
            &entry,
            store,
            |_| None,
        )
        .await
        .unwrap();

        assert!(
            resolved
                .headers
                .iter()
                .any(|header| header.name == "Authorization"
                    && header.value == "Bearer descriptor-access")
        );
        assert!(
            resolved
                .headers
                .iter()
                .any(|header| header.name == "X-Account" && header.value == "acct-7")
        );
    }

    #[tokio::test]
    async fn descriptor_records_are_isolated_from_raw_provider_credentials() {
        let descriptor = descriptor("https://example.test", OAuthFlowKind::DeviceCode);
        let (_temp, mut store) = store();
        store.set_api_key("firecrawl", "web-key");
        store.save().unwrap();

        persist_initial(
            "firecrawl",
            &descriptor,
            store.clone(),
            serde_json::from_value(serde_json::json!({
                "access_token": "oauth-access",
                "account_id": "account"
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let reloaded = store.reopen().unwrap();
        assert_eq!(reloaded.api_key("firecrawl").as_deref(), Some("web-key"));
        assert!(reloaded.get(&credential_record_id("firecrawl")).is_some());
    }
}
