//! Per-server MCP authentication (GOALS §18a).
//!
//! Four kinds (`oauth` / `header` / `env` / `none`):
//!
//! - **header** — a static / custom header (value may carry `$VAR`,
//!   resolved through [`crate::envref`] at launch). Becomes a request
//!   header on remote transports.
//! - **env** — env-var injection (esp. stdio); each value `$VAR`-resolved
//!   at launch. Becomes extra child env.
//! - **oauth** — OAuth 2.1 authorization-code + PKCE (RFC 7636). The
//!   interactive flow opens the browser to a loopback redirect, exchanges
//!   the code, and stores the `{access,refresh}` tokens in the vault's
//!   named-secret compartment under `mcp:<server>`. At call time the stored
//!   token is refreshed if expired and sent as `Authorization: Bearer …`.
//! - **none** — public; no header, no env. Warned at add-time.
//!
//! Tokens never enter model context; they live only in the request layer.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::config::{Auth, DEFAULT_PROFILE, OauthAuth, ServerConfig};

const OAUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OAUTH_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// The credential-store key for a server's OAuth tokens.
pub fn cred_key(server: &str) -> String {
    cred_key_for(server, crate::mcp::config::DEFAULT_PROFILE)
}

pub fn cred_key_for(server: &str, profile: &str) -> String {
    if profile == crate::mcp::config::DEFAULT_PROFILE {
        format!("mcp:{server}")
    } else {
        format!("mcp:{server}:{profile}")
    }
}

/// Every named-secret id this server's auth references: header/env credential
/// refs plus the flow-managed OAuth token key. Used to scope owner-scoped
/// resolution (`owner_kind = mcp`) so legacy backfill only ever claims names the
/// MCP server config actually uses. All such names are `mcp:`-prefixed.
pub fn named_secret_references(
    server: &str,
    cfg: &ServerConfig,
) -> std::collections::BTreeSet<String> {
    named_secret_references_for(server, cfg, crate::mcp::config::DEFAULT_PROFILE)
}

pub fn named_secret_references_for(
    server: &str,
    cfg: &ServerConfig,
    profile: &str,
) -> std::collections::BTreeSet<String> {
    let mut refs: std::collections::BTreeSet<String> =
        cfg.env_credential_refs.values().cloned().collect();
    collect_auth_secret_refs(&mut refs, server, profile, &cfg.auth);
    for (name, auth) in &cfg.profiles {
        collect_auth_secret_refs(&mut refs, server, name, auth);
    }
    if let Ok(selected) = cfg.auth_for_profile_named(server, profile) {
        collect_auth_secret_refs(&mut refs, server, profile, selected);
    }
    refs
}

fn collect_auth_secret_refs(
    refs: &mut std::collections::BTreeSet<String>,
    server: &str,
    profile: &str,
    auth: &Auth,
) {
    match auth {
        Auth::Header(header) => {
            if let Some(name) = &header.credential_ref {
                refs.insert(name.clone());
            }
            refs.insert(header_cred_key_for(server, profile));
        }
        Auth::Env(env) => {
            refs.extend(env.credential_refs.values().cloned());
            for env_name in env.vars.keys().chain(env.credential_refs.keys()) {
                refs.insert(auth_env_cred_key_for(server, profile, env_name));
            }
        }
        Auth::Oauth(_) => {
            refs.insert(cred_key_for(server, profile));
            if profile == crate::mcp::config::DEFAULT_PROFILE {
                refs.insert(format!("mcp:{server}"));
            }
        }
        Auth::None => {}
    }
}

pub fn header_cred_key(server: &str) -> String {
    header_cred_key_for(server, crate::mcp::config::DEFAULT_PROFILE)
}

pub fn header_cred_key_for(server: &str, profile: &str) -> String {
    if profile == crate::mcp::config::DEFAULT_PROFILE {
        format!("mcp:{server}:header")
    } else {
        format!("mcp:{server}:{profile}:header")
    }
}

pub fn auth_env_cred_key(server: &str, env_name: &str) -> String {
    auth_env_cred_key_for(server, crate::mcp::config::DEFAULT_PROFILE, env_name)
}

pub fn auth_env_cred_key_for(server: &str, profile: &str, env_name: &str) -> String {
    if profile == crate::mcp::config::DEFAULT_PROFILE {
        format!("mcp:{server}:auth-env:{env_name}")
    } else {
        format!("mcp:{server}:{profile}:auth-env:{env_name}")
    }
}

pub fn base_env_cred_key(server: &str, env_name: &str) -> String {
    format!("mcp:{server}:base-env:{env_name}")
}

/// Stored OAuth tokens for an MCP server.
// Clone is intentionally retained because refresh replacement must preserve
// the previous set until the provider response has been validated.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredTokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Unix seconds at which `access_token` expires (0 = unknown/never).
    #[serde(default)]
    pub expires_at: i64,
}

impl std::fmt::Debug for StoredTokens {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredTokens")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Drop for StoredTokens {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

impl StoredTokens {
    /// Whether the access token is expired (30s safety buffer), given the
    /// current unix time. Tokens with `expires_at == 0` never expire here.
    pub fn is_expired(&self, now_unix: i64) -> bool {
        self.expires_at != 0 && now_unix >= self.expires_at - 30
    }
}

/// Resolved auth artifacts for a single client construction: request
/// headers (remote transports) and extra subprocess env (stdio).
#[derive(Debug, Clone, Default)]
pub struct ResolvedAuth {
    pub headers: BTreeMap<String, String>,
    pub env: BTreeMap<String, String>,
    /// Env references that were referenced but not present in non-header env
    /// config, for surfacing a warning. Header-auth misses are fatal for
    /// remote transports and are reported through `header_errors`.
    pub missing_env: Vec<String>,
    pub header_errors: Vec<String>,
}

/// Resolve the non-OAuth parts of a server's auth into headers + env.
/// OAuth bearer headers are attached separately by [`oauth_bearer`] so
/// the (async, possibly-refreshing) token fetch isn't on this sync path.
#[allow(dead_code)]
pub fn resolve_static(cfg: &ServerConfig) -> ResolvedAuth {
    resolve_static_inner(None, "", cfg)
}

pub fn resolve_static_for_server(server: &str, cfg: &ServerConfig) -> ResolvedAuth {
    resolve_static_for_server_with_store(server, cfg, None)
}

pub fn resolve_static_for_server_with_store(
    server: &str,
    cfg: &ServerConfig,
    store: Option<&crate::credentials::CredentialStore>,
) -> ResolvedAuth {
    resolve_static_inner(store, server, cfg)
}

fn resolve_static_inner(
    store: Option<&crate::credentials::CredentialStore>,
    _server: &str,
    cfg: &ServerConfig,
) -> ResolvedAuth {
    let mut out = ResolvedAuth::default();
    if let Some(store) = store {
        for (k, credential_ref) in &cfg.env_credential_refs {
            if let Some(value) = credential_value(store, credential_ref) {
                out.env.insert(k.clone(), value);
            } else {
                out.missing_env.push(format!("credential:{credential_ref}"));
            }
        }
    }
    // Base subprocess env (stdio) with $VAR / `$secret:` resolution.
    for (k, v) in &cfg.env {
        let r = crate::envref::resolve_with_store(v, store);
        out.env.insert(k.clone(), r.value);
        out.missing_env.extend(r.missing);
        out.missing_env.extend(r.errors);
    }
    match &cfg.auth {
        Auth::Header(h) => {
            if let Some(credential_ref) = h.credential_ref.as_deref()
                && let Some(store) = store
            {
                if let Some(value) = credential_value(store, credential_ref) {
                    out.headers.insert(h.header.clone(), value);
                } else {
                    out.missing_env.push(format!("credential:{credential_ref}"));
                }
            } else {
                let r = crate::envref::resolve_with_store(&h.value, store);
                if r.has_missing() || r.has_errors() {
                    out.missing_env.extend(r.missing.iter().cloned());
                    for missing in &r.missing {
                        out.header_errors.push(format!(
                            "MCP auth header `{}` references unset environment variable `{missing}`",
                            h.header
                        ));
                    }
                    for error in &r.errors {
                        out.header_errors.push(format!(
                            "MCP auth header `{}` has invalid environment reference: {error}",
                            h.header
                        ));
                    }
                } else {
                    out.headers.insert(h.header.clone(), r.value);
                }
            }
        }
        Auth::Env(e) => {
            if let Some(store) = store {
                for (k, credential_ref) in &e.credential_refs {
                    if let Some(value) = credential_value(store, credential_ref) {
                        out.env.insert(k.clone(), value);
                    } else {
                        out.missing_env.push(format!("credential:{credential_ref}"));
                    }
                }
            }
            for (k, v) in &e.vars {
                let r = crate::envref::resolve_with_store(v, store);
                out.env.insert(k.clone(), r.value);
                out.missing_env.extend(r.missing);
                out.missing_env.extend(r.errors);
            }
        }
        // OAuth bearer is attached by the caller via `oauth_bearer`; None
        // contributes nothing.
        Auth::Oauth(_) | Auth::None => {}
    }
    out
}

fn credential_value(
    store: &crate::credentials::CredentialStore,
    credential_ref: &str,
) -> Option<String> {
    // MCP header and env values are written by the daemon's named-secret
    // owner RPCs. Keep the older credential-record lookup as a read-only
    // compatibility path for existing installations, but never make a new
    // MCP setup depend on that separate compartment.
    if let Some(value) = store.named_secret(credential_ref) {
        return Some(value.to_string());
    }
    let value = store.get(credential_ref)?;
    if let Some(s) = value.as_str() {
        return Some(s.to_string());
    }
    for key in ["secret", "api_key", "value"] {
        if let Some(s) = value.get(key).and_then(|v| v.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

/// Fetch a valid OAuth bearer header value (`Bearer <token>`) for a
/// server, refreshing if the stored access token is expired. Returns
/// `Ok(None)` when the server's auth isn't OAuth. Errors when OAuth is
/// configured but no token is stored (the user must authenticate first).
pub async fn oauth_bearer(server: &str, cfg: &ServerConfig) -> Result<Option<String>> {
    oauth_bearer_with_store(server, cfg, None, None).await
}

pub async fn oauth_bearer_with_store(
    server: &str,
    cfg: &ServerConfig,
    store: Option<&mut crate::credentials::CredentialStore>,
    project_root: Option<&str>,
) -> Result<Option<String>> {
    oauth_bearer_with_store_for(
        server,
        crate::mcp::config::DEFAULT_PROFILE,
        cfg,
        store,
        project_root,
    )
    .await
}

pub async fn oauth_bearer_with_store_for(
    server: &str,
    profile: &str,
    cfg: &ServerConfig,
    store: Option<&mut crate::credentials::CredentialStore>,
    project_root: Option<&str>,
) -> Result<Option<String>> {
    let Auth::Oauth(oauth) = &cfg.auth else {
        return Ok(None);
    };
    let store = match store {
        Some(store) => store,
        None => anyhow::bail!("MCP server `{server}` requires an injected credential store"),
    };
    let key = cred_key_for(server, profile);
    let mut tokens = stored_tokens_from_store(store, &key)?.ok_or_else(|| {
        anyhow::anyhow!(
            "MCP server `{server}` requires OAuth — run `authenticate` in /settings → MCP first"
        )
    })?;
    if tokens.is_expired(now_unix()) {
        let refresh = tokens
            .refresh_token
            .clone()
            .context("stored MCP token expired and no refresh token is available")?;
        tokens = refresh_token(oauth, &refresh).await?;
        let serialized = serde_json::to_string(&tokens)?;
        // A refresh MUST own the name it rotates: route the write through the
        // in-transaction ownership guard so a refresh can never mutate a
        // foreign-owned `mcp:<server>` token. The daemon always supplies the
        // owning project root; without it (non-daemon callers) fall back to the
        // ungated publish, which cannot reach a foreign vault here anyway.
        match project_root {
            Some(project_root) => store.set_named_secret_owned_and_save_published(
                &key,
                serialized,
                crate::secret_ownership::OWNER_KIND_MCP,
                project_root,
            )?,
            None => store.set_named_secret_and_save_published(&key, serialized)?,
        }
    }
    Ok(Some(format!("Bearer {}", tokens.access_token)))
}

fn stored_tokens_from_store(
    store: &crate::credentials::CredentialStore,
    key: &str,
) -> Result<Option<StoredTokens>> {
    if let Some(raw) = store.named_secret(key) {
        return serde_json::from_str(raw)
            .with_context(|| format!("parsing stored MCP OAuth tokens for {key}"))
            .map(Some);
    }
    store
        .get(key)
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .with_context(|| format!("parsing legacy MCP OAuth credential record for {key}"))
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// PKCE verifier + S256 challenge (RFC 7636).
struct Pkce {
    verifier: String,
    challenge: String,
}

impl Drop for Pkce {
    fn drop(&mut self) {
        self.verifier.zeroize();
        self.challenge.zeroize();
    }
}

/// Fixed loopback redirect used for the REMOTE begin path, where the daemon
/// binds no listener. The remote client is responsible for capturing the
/// provider's redirect and returning the callback code over `CompleteMcpOAuth`;
/// the token exchange re-sends this exact value, so it stays consistent between
/// the authorize request and the code exchange (PKCE + `state` carry the
/// binding security, not the redirect liveness).
const REMOTE_LOOPBACK_REDIRECT_URI: &str = "http://127.0.0.1/callback";

/// Daemon-owned state for one MCP OAuth browser flow. The listener, PKCE
/// verifier, and CSRF state never cross the daemon protocol boundary.
///
/// `listener` is `None` for a remote-owner flow: the daemon binds no host
/// loopback listener and the callback code arrives over the RPC instead.
#[derive(Serialize, Deserialize)]
pub struct McpOAuthFlow {
    oauth: OauthAuth,
    verifier: String,
    state: String,
    redirect_uri: String,
    #[serde(skip)]
    listener: Option<tokio::net::TcpListener>,
}

impl Drop for McpOAuthFlow {
    fn drop(&mut self) {
        self.verifier.zeroize();
        self.state.zeroize();
        self.redirect_uri.zeroize();
    }
}

#[cfg(test)]
impl McpOAuthFlow {
    /// Whether this flow bound a local loopback listener (local-owner path).
    pub fn has_local_listener(&self) -> bool {
        self.listener.is_some()
    }
}

fn generate_pkce() -> Pkce {
    let mut bytes = [0u8; 64];
    rand::rng().fill_bytes(&mut bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    Pkce {
        verifier,
        challenge,
    }
}

/// Start an MCP OAuth flow and return only the daemon-held flow plus the
/// display-safe authorization URL.
///
/// `local_display` gates the two LOCAL-HOST side effects: only a local owner
/// gets a host loopback listener bound and the host browser opened. For a
/// remote caller the daemon binds no listener and opens no browser — it returns
/// the authorize URL only, and the callback code arrives over `CompleteMcpOAuth`
/// (a remote caller could otherwise drive unsolicited host browser launches and
/// attacker-controlled local browser navigation).
pub async fn begin_oauth_flow(
    server: &str,
    cfg: &ServerConfig,
    local_display: bool,
) -> Result<(McpOAuthFlow, String)> {
    let Auth::Oauth(oauth) = &cfg.auth else {
        bail!("MCP server `{server}` is not configured for OAuth");
    };
    let mut pkce = generate_pkce();
    let mut state_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut state_bytes);
    let mut state = zeroize::Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(state_bytes),
    );
    let (listener, redirect_uri) = if local_display {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let redirect_uri = format!("http://127.0.0.1:{port}/callback");
        (Some(listener), redirect_uri)
    } else {
        (None, REMOTE_LOOPBACK_REDIRECT_URI.to_string())
    };
    let url = build_authorize_url(oauth, &redirect_uri, &pkce.challenge, &state)?;
    // Do NOT log the authorize URL. It carries flow parameters (`state`,
    // `code_challenge`) and spewing it to daemon/CLI logs is unnecessary: the
    // URL is returned to the owner-only caller for display. Open the host
    // browser ONLY for a local owner; a remote caller presents the URL itself.
    if local_display {
        let _ = crate::browser::open(&url);
    }
    Ok((
        McpOAuthFlow {
            oauth: oauth.clone(),
            verifier: std::mem::take(&mut pkce.verifier),
            state: std::mem::take(&mut *state),
            redirect_uri,
            listener,
        },
        url,
    ))
}

/// Complete a daemon-owned MCP OAuth flow. The optional callback is a
/// display-layer convenience; it carries only an authorization code and CSRF
/// state, never an access or refresh token.
pub async fn complete_oauth_flow(
    mut flow: McpOAuthFlow,
    callback: Option<&str>,
) -> Result<StoredTokens> {
    let (code, got_state) = match (callback, flow.listener.take()) {
        // Explicit callback (the remote-owner path, and a local convenience):
        // parse the code + CSRF state the client returned over the RPC.
        (Some(callback), _) => parse_callback_target(callback)?,
        // No callback + a bound listener: the local-owner browser flow waits on
        // the host loopback listener for the provider's redirect.
        (None, Some(listener)) => wait_for_callback(listener).await?,
        // No callback + no listener: a remote-owner flow was started URL-only,
        // so it can only complete with the callback code supplied over the RPC.
        (None, None) => bail!(
            "this MCP OAuth flow was started for a remote client; complete it with the callback code"
        ),
    };
    let code = zeroize::Zeroizing::new(code);
    let got_state = zeroize::Zeroizing::new(got_state);
    if got_state.as_str() != flow.state {
        bail!("OAuth state mismatch (possible CSRF)");
    }
    exchange_code(&flow.oauth, &code, &flow.verifier, &flow.redirect_uri).await
}

/// Build the authorization URL for the loopback PKCE flow.
pub fn build_authorize_url(
    oauth: &OauthAuth,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
) -> Result<String> {
    let base = oauth
        .authorize_url
        .as_deref()
        .context("OAuth server has no `authorize_url`")?;
    let client_id = oauth.client_id.as_deref().unwrap_or("");
    let scope = oauth.scopes.join(" ");
    let mut url = format!(
        "{base}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}",
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(challenge),
        urlencoding::encode(state),
    );
    if !scope.is_empty() {
        url.push_str("&scope=");
        url.push_str(&urlencoding::encode(&scope));
    }
    Ok(url)
}

/// Encode an `application/x-www-form-urlencoded` body (reqwest is built
/// without the `urlencoded` feature, so we encode manually like the rest
/// of `auth/`).
fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[derive(Deserialize)]
struct TokenResp {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

impl Drop for TokenResp {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

fn into_stored(mut resp: TokenResp) -> StoredTokens {
    let expires_at = resp.expires_in.map(|s| now_unix() + s).unwrap_or(0);
    StoredTokens {
        access_token: std::mem::take(&mut resp.access_token),
        refresh_token: std::mem::take(&mut resp.refresh_token),
        expires_at,
    }
}

/// Exchange an authorization code + PKCE verifier for tokens.
async fn exchange_code(
    oauth: &OauthAuth,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<StoredTokens> {
    let token_url = oauth
        .token_url
        .as_deref()
        .context("OAuth server has no `token_url`")?;
    let client_id = oauth.client_id.as_deref().unwrap_or("");
    let body = zeroize::Zeroizing::new(form_body(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ]));
    let resp = oauth_http_client()?
        .post(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.as_bytes().to_vec())
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(oauth_token_endpoint_error("exchange", status));
    }
    let response_body = zeroize::Zeroizing::new(resp.bytes().await?.to_vec());
    let parsed: TokenResp = serde_json::from_slice(&response_body)?;
    Ok(into_stored(parsed))
}

/// Refresh an access token using a stored refresh token.
async fn refresh_token(oauth: &OauthAuth, refresh: &str) -> Result<StoredTokens> {
    let token_url = oauth
        .token_url
        .as_deref()
        .context("OAuth server has no `token_url`")?;
    let client_id = oauth.client_id.as_deref().unwrap_or("");
    let body = zeroize::Zeroizing::new(form_body(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("client_id", client_id),
    ]));
    let resp = oauth_http_client()?
        .post(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.as_bytes().to_vec())
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(oauth_token_endpoint_error("refresh", status));
    }
    let response_body = zeroize::Zeroizing::new(resp.bytes().await?.to_vec());
    let parsed: TokenResp = serde_json::from_slice(&response_body)?;
    let mut tokens = into_stored(parsed);
    // Some servers omit the refresh token on refresh — keep the old one.
    if tokens.refresh_token.is_none() {
        tokens.refresh_token = Some(refresh.to_string());
    }
    Ok(tokens)
}

fn oauth_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(OAUTH_CONNECT_TIMEOUT)
        .timeout(OAUTH_TOTAL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building MCP OAuth HTTP client")
}

fn oauth_token_endpoint_error(operation: &str, status: reqwest::StatusCode) -> anyhow::Error {
    anyhow::anyhow!("MCP OAuth token {operation} failed ({status})")
}

/// Run the interactive OAuth 2.1 + PKCE flow for a server: spin a
/// loopback redirect listener, open the browser to the authorize URL,
/// capture the code, exchange it, and persist the tokens under
/// `mcp:<server>`. Returns the stored access token's summary.
pub async fn run_oauth_flow(
    server: &str,
    cfg: &ServerConfig,
    store: &mut crate::credentials::CredentialStore,
) -> Result<StoredTokens> {
    // The interactive local flow: bind the host loopback listener and open the
    // host browser (`local_display = true`), then block on the listener.
    let (flow, _) = begin_oauth_flow(server, cfg, true).await?;
    let tokens = complete_oauth_flow(flow, None).await?;
    store.set_named_secret_and_save_published(cred_key(server), serde_json::to_string(&tokens)?)?;
    Ok(tokens)
}

/// Block on the loopback listener until the OAuth provider redirects back
/// with `?code=…&state=…`, then reply with a small success page.
async fn wait_for_callback(listener: tokio::net::TcpListener) -> Result<(String, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut stream, _) = listener.accept().await?;
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next().unwrap_or("");
    // `GET /callback?code=…&state=… HTTP/1.1`
    let target = first.split_whitespace().nth(1).unwrap_or("");
    let (code, state) = parse_callback_target(target)?;
    let body = "<html><body>Authentication complete. You can close this tab.</body></html>";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
    Ok((code, state))
}

fn parse_callback_target(target: &str) -> Result<(String, String)> {
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or(target);
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let mut val = zeroize::Zeroizing::new(
                urlencoding::decode(v)
                    .map(|c| c.into_owned())
                    .unwrap_or_default(),
            );
            match k {
                "code" => code = Some(std::mem::take(&mut *val)),
                "state" => state = Some(std::mem::take(&mut *val)),
                _ => {}
            }
        }
    }
    let code = code.context("OAuth callback missing `code`")?;
    let state = state.unwrap_or_default();
    Ok((code, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::config::{HeaderAuth, ServerConfig, Transport};
    use std::collections::BTreeMap;

    fn base_server() -> ServerConfig {
        ServerConfig {
            transport: Transport::Streamable,
            endpoint: Some("https://x/mcp".into()),
            command: None,
            args: vec![],
            env: BTreeMap::new(),
            env_credential_refs: BTreeMap::new(),
            auth: Auth::None,
            mode: Default::default(),
            enabled: true,
            cache_ttl_secs: 3600,
            connect_timeout_secs: None,
            timeout_secs: None,
            profiles: BTreeMap::new(),
        }
    }

    #[test]
    fn cred_key_namespaces_server() {
        assert_eq!(cred_key("github"), "mcp:github");
        assert_eq!(cred_key_for("github", DEFAULT_PROFILE), "mcp:github");
        assert_eq!(cred_key_for("github", "admin"), "mcp:github:admin");
        assert_eq!(
            header_cred_key_for("github", "admin"),
            "mcp:github:admin:header"
        );
    }

    #[test]
    fn header_secret_refs_are_reported_missing_without_store() {
        let mut cfg = base_server();
        cfg.auth = Auth::Header(crate::mcp::config::HeaderAuth {
            header: "Authorization".into(),
            value: "Bearer $secret:foo".into(),
            credential_ref: None,
        });
        let resolved = resolve_static_for_server("svc", &cfg);
        assert!(
            resolved
                .missing_env
                .iter()
                .any(|m| m.contains("secret:foo")),
            "store-backed resolver must see $secret: refs, got {:?}",
            resolved.missing_env
        );
    }

    #[test]
    fn named_secret_references_include_profile_keys() {
        let mut cfg = base_server();
        cfg.auth = Auth::Header(crate::mcp::config::HeaderAuth {
            header: "Authorization".into(),
            value: "Bearer $secret:foo".into(),
            credential_ref: None,
        });
        cfg.profiles.insert(
            "admin".into(),
            Auth::Oauth(crate::mcp::config::OauthAuth::default()),
        );
        let refs = named_secret_references_for("svc", &cfg, "admin");
        assert!(refs.contains("mcp:svc:admin"), "{refs:?}");
        assert!(refs.contains("mcp:svc:header"), "{refs:?}");
    }

    #[test]
    fn token_expiry_uses_buffer() {
        let t = StoredTokens {
            access_token: "a".into(),
            refresh_token: None,
            expires_at: 1000,
        };
        assert!(!t.is_expired(900));
        assert!(t.is_expired(980), "30s buffer trips early");
        let never = StoredTokens {
            access_token: "a".into(),
            refresh_token: None,
            expires_at: 0,
        };
        assert!(!never.is_expired(i64::MAX), "0 means never expires");
    }

    #[test]
    fn oauth_token_endpoint_errors_never_include_response_body() {
        let error = oauth_token_endpoint_error("refresh", reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(
            error.to_string(),
            "MCP OAuth token refresh failed (400 Bad Request)"
        );
        assert!(!error.to_string().contains("access_token"));
    }

    #[test]
    fn oauth_http_client_has_bounded_timeout_and_no_redirects() {
        let _ = oauth_http_client().expect("MCP OAuth HTTP client builds");
        assert_eq!(OAUTH_CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(OAUTH_TOTAL_TIMEOUT, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn oauth_exchange_mock_error_body_is_not_returned() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock token endpoint");
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let secret_body = "provider-secret-access-token-body";
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept token request");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                secret_body.len(),
                secret_body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write mock token error");
        });

        let oauth = OauthAuth {
            token_url: Some(endpoint),
            ..OauthAuth::default()
        };
        let error = exchange_code(&oauth, "code", "verifier", "http://127.0.0.1/callback")
            .await
            .expect_err("mock token endpoint must fail");
        server.await.expect("mock token endpoint task");
        assert!(!error.to_string().contains(secret_body));
    }

    #[tokio::test]
    async fn begin_oauth_flow_remote_owner_binds_no_local_listener_or_browser() {
        // A remote-owner begin (`local_display = false`) must NOT bind a host
        // loopback listener (and, in the same gated branch, must NOT open the
        // host browser). It returns the authorize URL, carrying the fixed remote
        // loopback redirect the client is contracted to capture.
        let mut cfg = base_server();
        cfg.auth = Auth::Oauth(OauthAuth {
            authorize_url: Some("https://provider.example/authorize".into()),
            token_url: Some("https://provider.example/token".into()),
            client_id: Some("client".into()),
            scopes: vec!["read".into()],
        });
        let (flow, url) = begin_oauth_flow("srv", &cfg, false)
            .await
            .expect("remote begin must succeed URL-only");
        assert!(
            !flow.has_local_listener(),
            "a remote-owner flow must not bind a host loopback listener"
        );
        assert!(url.starts_with("https://provider.example/authorize?"));
        assert!(url.contains("code_challenge="));
        let encoded_redirect = urlencoding::encode(REMOTE_LOOPBACK_REDIRECT_URI).into_owned();
        assert!(
            url.contains(encoded_redirect.as_str()),
            "remote authorize URL must carry the fixed remote loopback redirect: {url}"
        );

        // A remote-started flow (no listener) cannot complete by waiting on a
        // host listener; it must be given the callback code over the RPC.
        let err = complete_oauth_flow(flow, None)
            .await
            .expect_err("a listener-less remote flow cannot self-complete");
        assert!(err.to_string().contains("remote client"), "{err}");
    }

    #[test]
    fn static_header_auth_resolves_to_header() {
        let mut cfg = base_server();
        cfg.auth = Auth::Header(HeaderAuth {
            header: "X-Key".into(),
            value: "literal-token".into(),
            credential_ref: None,
        });
        let r = resolve_static(&cfg);
        assert_eq!(r.headers.get("X-Key").unwrap(), "literal-token");
        assert!(r.env.is_empty());
    }

    #[test]
    fn env_auth_resolves_into_env() {
        let mut cfg = base_server();
        let mut vars = BTreeMap::new();
        vars.insert("TOKEN".to_string(), "static".to_string());
        cfg.auth = Auth::Env(super::super::config::EnvAuth {
            vars,
            credential_refs: Default::default(),
        });
        let r = resolve_static(&cfg);
        assert_eq!(r.env.get("TOKEN").unwrap(), "static");
        assert!(r.headers.is_empty());
    }

    #[test]
    fn none_auth_yields_nothing() {
        let r = resolve_static(&base_server());
        assert!(r.headers.is_empty());
        assert!(r.env.is_empty());
    }

    #[test]
    fn authorize_url_includes_pkce_and_scope() {
        let oauth = OauthAuth {
            authorize_url: Some("https://auth.example.com/authorize".into()),
            token_url: Some("https://auth.example.com/token".into()),
            client_id: Some("cid".into()),
            scopes: vec!["read".into(), "write".into()],
        };
        let url =
            build_authorize_url(&oauth, "http://127.0.0.1:1234/callback", "chal", "st").unwrap();
        assert!(url.contains("code_challenge=chal"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("client_id=cid"));
        assert!(url.contains("scope=read%20write"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn mcp_secrets_use_injected_vault() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let mut store = crate::credentials::CredentialStore::open_default().unwrap();
        store.set_named_secret("mcp-header-secret", "header-secret-value");
        store.save().unwrap();
        assert!(
            !crate::credentials::default_path().unwrap().exists(),
            "MCP secrets must not recreate credentials.json"
        );

        let mut cfg = base_server();
        cfg.auth = Auth::Header(HeaderAuth {
            header: "X-Key".into(),
            value: String::new(),
            credential_ref: Some("mcp-header-secret".into()),
        });
        let resolved = resolve_static_for_server_with_store("example", &cfg, Some(&store));
        assert_eq!(
            resolved.headers.get("X-Key").map(String::as_str),
            Some("header-secret-value")
        );
    }

    #[test]
    fn mcp_oauth_tokens_use_named_secret_compartment() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let mut store = crate::credentials::CredentialStore::open_default().unwrap();
        let tokens = StoredTokens {
            access_token: "access-token".into(),
            refresh_token: Some("refresh-token".into()),
            expires_at: 0,
        };
        let key = cred_key("example");
        store.set_named_secret(&key, serde_json::to_string(&tokens).unwrap());
        store.save().unwrap();

        let resolved = stored_tokens_from_store(&store, &key).unwrap().unwrap();
        assert_eq!(resolved.access_token, "access-token");
        assert_eq!(resolved.refresh_token.as_deref(), Some("refresh-token"));
        assert!(
            store.get(&key).is_none(),
            "OAuth must not require credential_record"
        );
    }
}
