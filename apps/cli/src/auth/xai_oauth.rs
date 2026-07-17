//! xAI SuperGrok OAuth for the `grok-oauth` inference provider.
//!
//! This flow is provider auth, not harness auth: tokens are stored under the
//! provider credential key and read by the daemon before each request.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::credentials::CredentialStore;

pub const CREDENTIAL_KEY: &str = "grok-oauth";
pub const DISCOVERY_URL: &str = "https://auth.x.ai/.well-known/openid-configuration";
pub const CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
pub const SCOPES: &str = "openid profile email offline_access grok-cli:access api:access";
pub const CALLBACK_PORT: u16 = 56121;
pub const CALLBACK_PATH: &str = "/callback";
pub const REDIRECT_URI: &str = "http://127.0.0.1:56121/callback";
pub const REFRESH_SKEW_SECS: i64 = 120;
const OAUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OAUTH_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const CALLBACK_OVERALL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CALLBACK_REQUEST_LINE_LIMIT: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackSource {
    /// Arrived on loopback, where any local process could have sent it. State
    /// is therefore load-bearing and must be present and equal.
    LocalListener,
    /// Pasted by the user into this pending login and also bound by PKCE. An
    /// absent state is allowed, but an affirmatively different state is not.
    ManualPaste,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

impl StoredTokens {
    fn needs_refresh(&self, now: i64) -> bool {
        self.expires_at.saturating_sub(now) <= REFRESH_SKEW_SECS
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Debug, Clone)]
pub struct ManualLogin {
    pub authorize_url: String,
    state: String,
    verifier: String,
    token_endpoint: String,
}

#[cfg(test)]
impl ManualLogin {
    pub(crate) fn for_test(authorize_url: &str) -> Self {
        Self {
            authorize_url: authorize_url.to_string(),
            state: "state".to_string(),
            verifier: "verifier".to_string(),
            token_endpoint: "https://auth.x.ai/oauth/token".to_string(),
        }
    }

    pub(crate) fn state_for_test(&self) -> &str {
        &self.state
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

pub async fn begin_manual_login() -> Result<ManualLogin> {
    let discovery = fetch_discovery().await?;
    let (verifier, challenge) = generate_pkce();
    let state = random_urlsafe(32);
    let authorize_url = build_authorize_url(&discovery.authorization_endpoint, &state, &challenge);
    Ok(ManualLogin {
        authorize_url,
        state,
        verifier,
        token_endpoint: discovery.token_endpoint,
    })
}

pub async fn complete_manual_login(login: ManualLogin, input: &str) -> Result<StoredTokens> {
    complete_login(login, input, CallbackSource::ManualPaste).await
}

async fn complete_login(
    login: ManualLogin,
    input: &str,
    source: CallbackSource,
) -> Result<StoredTokens> {
    let code = parse_callback_input(input, &login.state, source)?;
    let tokens = exchange_code(&login.token_endpoint, &code, &login.verifier).await?;
    store_tokens(&tokens)?;
    Ok(tokens)
}

pub async fn bearer_token() -> Result<String> {
    let tokens = crate::auth::refresh_guard::credential_with_refresh(
        CREDENTIAL_KEY,
        "parsing stored xAI OAuth tokens",
        missing_auth_error,
        StoredTokens::needs_refresh,
        StoredTokens::refresh_token,
        replace_refresh_tokens,
        |tokens| async move {
            let discovery = fetch_discovery().await?;
            refresh_tokens(&discovery.token_endpoint, &tokens.refresh_token).await
        },
        is_terminal_refresh_error,
        xai_terminal_refresh_error,
    )
    .await?;
    Ok(tokens.access_token)
}

pub fn is_logged_in() -> bool {
    is_logged_in_at(None)
}

pub(crate) fn is_logged_in_at(store_path: Option<&Path>) -> bool {
    open_store(store_path)
        .ok()
        .and_then(|store| {
            store
                .get(CREDENTIAL_KEY)
                .and_then(|raw| serde_json::from_value::<StoredTokens>(raw.clone()).ok())
        })
        .is_some()
}

pub fn logout() -> Result<()> {
    logout_at(None)
}

pub(crate) fn logout_at(store_path: Option<&Path>) -> Result<()> {
    let mut store = open_store(store_path)?;
    store.remove(CREDENTIAL_KEY);
    store.save()
}

fn open_store(store_path: Option<&Path>) -> Result<CredentialStore> {
    match store_path {
        Some(path) => CredentialStore::open(path.to_path_buf()),
        None => CredentialStore::open_default(),
    }
}

fn missing_auth_error() -> anyhow::Error {
    anyhow!("Grok subscription auth required — set up OAuth in /settings → Providers.")
}

fn xai_terminal_refresh_error(e: anyhow::Error) -> anyhow::Error {
    anyhow!(
        "{e}; Grok subscription auth expired or was revoked — set up OAuth in /settings → Providers"
    )
}

async fn fetch_discovery() -> Result<Discovery> {
    let doc: Discovery = oauth_http_client()?
        .get(DISCOVERY_URL)
        .send()
        .await
        .context("fetching xAI OAuth discovery document")?
        .error_for_status()
        .context("xAI OAuth discovery failed")?
        .json()
        .await
        .context("parsing xAI OAuth discovery document")?;
    Ok(doc)
}

fn build_authorize_url(authorize_endpoint: &str, state: &str, challenge: &str) -> String {
    format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        authorize_endpoint,
        urlencoding::encode(CLIENT_ID),
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(SCOPES),
        urlencoding::encode(state),
        urlencoding::encode(challenge)
    )
}

async fn exchange_code(token_endpoint: &str, code: &str, verifier: &str) -> Result<StoredTokens> {
    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT_ID),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("code_verifier", verifier),
    ];
    token_request(token_endpoint, &params, None).await
}

async fn refresh_tokens(token_endpoint: &str, refresh_token: &str) -> Result<StoredTokens> {
    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", CLIENT_ID),
        ("refresh_token", refresh_token),
    ];
    token_request(token_endpoint, &params, Some(refresh_token)).await
}

async fn token_request(
    token_endpoint: &str,
    params: &[(&str, &str)],
    fallback_refresh: Option<&str>,
) -> Result<StoredTokens> {
    let resp = oauth_http_client()?
        .post(token_endpoint)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(params))
        .send()
        .await
        .with_context(|| format!("POST {token_endpoint}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(classify_token_error(status, &body));
    }
    let parsed: TokenResponse =
        serde_json::from_str(&body).context("parsing xAI OAuth token response")?;
    let refresh_token = parsed
        .refresh_token
        .or_else(|| fallback_refresh.map(str::to_string))
        .context("xAI OAuth token response missing refresh_token")?;
    Ok(StoredTokens {
        access_token: parsed.access_token,
        refresh_token,
        expires_at: unix_now() + parsed.expires_in.unwrap_or(3600),
    })
}

fn oauth_http_client() -> Result<reqwest::Client> {
    oauth_http_client_builder()
        .build()
        .context("building xAI OAuth HTTP client")
}

fn oauth_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(OAUTH_CONNECT_TIMEOUT)
        .timeout(OAUTH_TOTAL_TIMEOUT)
}

#[cfg(test)]
fn oauth_timeout_config() -> (Duration, Duration) {
    (OAUTH_CONNECT_TIMEOUT, OAUTH_TOTAL_TIMEOUT)
}

fn classify_token_error(status: StatusCode, body: &str) -> anyhow::Error {
    let lower = body.to_ascii_lowercase();
    if status == StatusCode::FORBIDDEN {
        return anyhow!(
            "xAI OAuth returned 403 — this account may not have SuperGrok/API access for the OAuth API surface; use SuperGrok/API-key access or try again after upgrading"
        );
    }
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return anyhow!("xAI OAuth token endpoint transient failure ({status}): {body}");
    }
    if status == StatusCode::BAD_REQUEST
        || status == StatusCode::UNAUTHORIZED
        || lower.contains("invalid_grant")
        || lower.contains("revoked")
    {
        return anyhow!("xAI OAuth refresh rejected ({status}): invalid_grant or revoked token");
    }
    anyhow!("xAI OAuth token endpoint failed ({status}): {body}")
}

fn is_terminal_refresh_error(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("invalid_grant") || msg.contains("revoked token")
}

fn replace_refresh_tokens(_previous: &StoredTokens, fresh: StoredTokens) -> StoredTokens {
    fresh
}

impl StoredTokens {
    fn refresh_token(&self) -> &str {
        &self.refresh_token
    }
}

fn store_tokens(tokens: &StoredTokens) -> Result<()> {
    let mut store = CredentialStore::open_default()?;
    store.set(CREDENTIAL_KEY, serde_json::to_value(tokens)?);
    store.save()
}

pub fn bind_callback_listener(port: u16) -> Result<tokio::net::TcpListener> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).with_context(|| {
        format!(
            "binding xAI OAuth callback on 127.0.0.1:{port}; use manual paste if the port is busy"
        )
    })?;
    listener
        .set_nonblocking(true)
        .context("configuring xAI OAuth callback listener")?;
    tokio::net::TcpListener::from_std(listener).context("registering xAI OAuth callback listener")
}

pub async fn wait_for_callback_async(listener: &tokio::net::TcpListener) -> Result<String> {
    tokio::time::timeout(CALLBACK_OVERALL_TIMEOUT, wait_for_callback_loop(listener))
        .await
        .context("timed out waiting for xAI OAuth callback")?
}

async fn wait_for_callback_loop(listener: &tokio::net::TcpListener) -> Result<String> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .context("waiting for xAI OAuth callback")?;
        match read_callback_request_line(&mut stream).await {
            CallbackRequest::Callback(path) => {
                write_callback_response(&mut stream, 200, success_page()).await;
                return Ok(path);
            }
            CallbackRequest::Noise => {
                write_callback_response(&mut stream, 404, not_found_page()).await;
            }
            CallbackRequest::Malformed => {
                write_callback_response(&mut stream, 400, bad_request_page()).await;
            }
        }
    }
}

enum CallbackRequest {
    Callback(String),
    Noise,
    Malformed,
}

async fn read_callback_request_line(stream: &mut tokio::net::TcpStream) -> CallbackRequest {
    use tokio::io::AsyncReadExt;

    let mut line = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = match stream.read(&mut chunk).await {
            Ok(read) => read,
            Err(_) => return CallbackRequest::Malformed,
        };
        if read == 0 {
            break;
        }
        line.extend_from_slice(&chunk[..read]);
        if line.len() > CALLBACK_REQUEST_LINE_LIMIT {
            return CallbackRequest::Malformed;
        }
        if !b"GET ".starts_with(&line[..line.len().min(4)]) && !line.starts_with(b"GET ") {
            return CallbackRequest::Malformed;
        }
        if let Some(newline) = line.iter().position(|byte| *byte == b'\n') {
            line.truncate(newline + 1);
            break;
        }
    }
    let Ok(line) = std::str::from_utf8(&line) else {
        return CallbackRequest::Malformed;
    };
    let mut parts = line.split_whitespace();
    if parts.next() != Some("GET") {
        return CallbackRequest::Malformed;
    }
    let Some(path) = parts.next() else {
        return CallbackRequest::Malformed;
    };
    let (request_path, query) = path.split_once('?').unwrap_or((path, ""));
    if request_path != CALLBACK_PATH {
        return CallbackRequest::Noise;
    }
    if query.split('&').any(|pair| {
        matches!(
            pair.split_once('=').map(|(name, _)| name),
            Some("code" | "error")
        )
    }) {
        CallbackRequest::Callback(path.to_string())
    } else {
        CallbackRequest::Noise
    }
}

async fn write_callback_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &'static str,
) {
    use tokio::io::AsyncWriteExt;

    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn success_page() -> &'static str {
    "<!doctype html><meta charset=\"utf-8\"><title>OAuth complete</title><p>xAI OAuth complete. You can close this tab.</p>"
}

fn not_found_page() -> &'static str {
    "<!doctype html><meta charset=\"utf-8\"><title>Not found</title><p>Not found.</p>"
}

fn bad_request_page() -> &'static str {
    "<!doctype html><meta charset=\"utf-8\"><title>Bad request</title><p>Bad request.</p>"
}

pub async fn complete_local_callback_login(
    login: ManualLogin,
    listener: tokio::net::TcpListener,
) -> Result<StoredTokens> {
    let callback = wait_for_callback_async(&listener).await?;
    complete_login(login, &callback, CallbackSource::LocalListener).await
}

fn parse_callback_input(
    input: &str,
    expected_state: &str,
    source: CallbackSource,
) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("OAuth callback/code is empty");
    }
    if !trimmed.contains('=') && !trimmed.contains('?') && !trimmed.contains('/') {
        if source == CallbackSource::LocalListener {
            bail!("OAuth callback missing `state` (paste the full callback URL for this login)");
        }
        return Ok(trimmed.to_string());
    }
    let query = if let Some(idx) = trimmed.find('?') {
        &trimmed[idx + 1..]
    } else if let Some(stripped) = trimmed.strip_prefix("/callback?") {
        stripped
    } else {
        trimmed
    };
    let query = query.split('#').next().unwrap_or(query);
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let Some(name) = parts.next() else {
            continue;
        };
        let value = parts.next().unwrap_or_default();
        let value = urlencoding::decode(value)
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| value.to_string());
        match name {
            "code" => code = Some(value),
            "state" => state = Some(value),
            "error" => error = Some(value),
            "error_description" => error_description = Some(value),
            _ => {}
        }
    }
    match state.as_deref() {
        Some(actual) if actual != expected_state => {
            bail!("OAuth state mismatch (possible CSRF)");
        }
        None if source == CallbackSource::LocalListener => {
            bail!("OAuth callback missing `state` (possible CSRF)");
        }
        _ => {}
    }
    if let Some(error) = error {
        if let Some(description) = error_description.filter(|text| !text.is_empty()) {
            bail!("xAI OAuth returned `{error}`: {description}");
        }
        bail!("xAI OAuth returned `{error}`");
    }
    code.context("OAuth callback missing `code`")
}

fn generate_pkce() -> (String, String) {
    let verifier = random_urlsafe(32);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    (verifier, challenge)
}

fn random_urlsafe(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

fn form_body(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn parse_callback_bare_code_manual_paste_accepted() {
        assert_eq!(
            parse_callback_input("abc123", "state-1", CallbackSource::ManualPaste).unwrap(),
            "abc123"
        );
    }

    #[test]
    fn parse_callback_bare_code_listener_rejected() {
        let err =
            parse_callback_input("abc123", "state-1", CallbackSource::LocalListener).unwrap_err();
        assert!(err.to_string().contains("missing `state`"));
    }

    #[test]
    fn parse_callback_matching_state_manual_paste_accepted() {
        assert_eq!(
            parse_callback_input(
                "/callback?code=abc&state=state-1",
                "state-1",
                CallbackSource::ManualPaste,
            )
            .unwrap(),
            "abc"
        );
    }

    #[test]
    fn parse_callback_matching_state_listener_accepted() {
        assert_eq!(
            parse_callback_input(
                "http://127.0.0.1:56121/callback?code=abc&state=state-1",
                "state-1",
                CallbackSource::LocalListener,
            )
            .unwrap(),
            "abc"
        );
    }

    #[test]
    fn parse_callback_mismatched_state_manual_paste_rejected() {
        let err = parse_callback_input(
            "/callback?code=abc&state=wrong",
            "state-1",
            CallbackSource::ManualPaste,
        )
        .unwrap_err();
        assert!(err.to_string().contains("state mismatch"));
    }

    #[test]
    fn parse_callback_mismatched_state_listener_rejected() {
        let err = parse_callback_input(
            "/callback?code=abc&state=wrong",
            "state-1",
            CallbackSource::LocalListener,
        )
        .unwrap_err();
        assert!(err.to_string().contains("state mismatch"));
    }

    #[test]
    fn parse_callback_absent_state_manual_paste_accepted() {
        assert_eq!(
            parse_callback_input("/callback?code=abc", "state-1", CallbackSource::ManualPaste,)
                .unwrap(),
            "abc"
        );
    }

    #[test]
    fn parse_callback_absent_state_listener_rejected() {
        let err = parse_callback_input(
            "/callback?code=abc",
            "state-1",
            CallbackSource::LocalListener,
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing `state`"));
    }

    #[test]
    fn parse_callback_error_param_manual_paste_reports_denial() {
        let err = parse_callback_input(
            "/callback?error=access_denied&error_description=You%20denied%20access",
            "state-1",
            CallbackSource::ManualPaste,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("access_denied"), "{err}");
        assert!(err.contains("You denied access"), "{err}");
    }

    #[test]
    fn parse_callback_error_param_listener_reports_denial() {
        let err = parse_callback_input(
            "/callback?error=access_denied&error_description=You%20denied%20access&state=state-1",
            "state-1",
            CallbackSource::LocalListener,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("access_denied"), "{err}");
        assert!(err.contains("You denied access"), "{err}");
    }

    #[test]
    fn parse_callback_no_code_no_error_manual_paste_rejected() {
        let err = parse_callback_input(
            "/callback?state=state-1",
            "state-1",
            CallbackSource::ManualPaste,
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing `code`"));
    }

    #[test]
    fn parse_callback_no_code_no_error_listener_rejected() {
        let err = parse_callback_input(
            "/callback?state=state-1",
            "state-1",
            CallbackSource::LocalListener,
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing `code`"));
    }

    #[test]
    fn redirect_uri_matches_callback_port_and_path() {
        assert_eq!(
            REDIRECT_URI,
            format!("http://127.0.0.1:{CALLBACK_PORT}{CALLBACK_PATH}")
        );
    }

    async fn callback_server() -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<Result<String>>,
    ) {
        let listener = bind_callback_listener(0).unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { wait_for_callback_async(&listener).await });
        (addr, task)
    }

    async fn request(addr: std::net::SocketAddr, bytes: &[u8]) -> Vec<u8> {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn callback_server_ignores_favicon_then_returns_callback() {
        let (addr, task) = callback_server().await;
        let response = request(
            addr,
            b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 404"));
        assert!(!task.is_finished());
        request(
            addr,
            b"GET /callback?code=abc&state=s HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert_eq!(task.await.unwrap().unwrap(), "/callback?code=abc&state=s");
    }

    #[tokio::test]
    async fn callback_server_ignores_non_http_payload_then_returns_callback() {
        let (addr, task) = callback_server().await;
        let response = request(addr, &[0x16, 0x03, 0x01, 0x00, 0x2f]).await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"));
        assert!(!task.is_finished());
        request(
            addr,
            b"GET /callback?code=abc&state=s HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert_eq!(task.await.unwrap().unwrap(), "/callback?code=abc&state=s");
    }

    #[tokio::test]
    async fn callback_server_returns_full_callback_path() {
        let (addr, task) = callback_server().await;
        request(
            addr,
            b"GET /callback?code=abc%20123&state=state-1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert_eq!(
            task.await.unwrap().unwrap(),
            "/callback?code=abc%20123&state=state-1"
        );
    }

    #[tokio::test]
    async fn callback_server_response_content_length_matches_body_and_closes() {
        let (addr, task) = callback_server().await;
        let response = request(
            addr,
            b"GET /callback?code=abc&state=s HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        task.await.unwrap().unwrap();
        let response = String::from_utf8(response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        let declared = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(declared, body.len());
        assert!(headers.lines().any(|line| line == "connection: close"));
    }

    #[tokio::test]
    async fn callback_server_caps_oversized_request_line() {
        let (addr, task) = callback_server().await;
        let oversized = format!("GET /{} HTTP/1.1\r\n\r\n", "x".repeat(9 * 1024));
        let response = request(addr, oversized.as_bytes()).await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"));
        assert!(!task.is_finished());
        request(
            addr,
            b"GET /callback?code=abc&state=s HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        assert_eq!(task.await.unwrap().unwrap(), "/callback?code=abc&state=s");
    }

    #[tokio::test(start_paused = true)]
    async fn oauth_grok_callback_overall_timeout() {
        let listener = bind_callback_listener(0).unwrap();
        let task = tokio::spawn(async move { wait_for_callback_async(&listener).await });
        tokio::task::yield_now().await;
        tokio::time::advance(CALLBACK_OVERALL_TIMEOUT - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        let error = task.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("timed out"), "{error}");
    }

    #[test]
    fn oauth_client_timeout_config_is_explicit() {
        assert_eq!(
            oauth_timeout_config(),
            (Duration::from_secs(5), Duration::from_secs(30))
        );
        let _ = oauth_http_client().unwrap();
    }

    #[test]
    fn expiring_token_refreshes_inside_skew() {
        let tokens = StoredTokens {
            access_token: "a".into(),
            refresh_token: "r".into(),
            expires_at: 1_000,
        };
        assert!(tokens.needs_refresh(881));
        assert!(!tokens.needs_refresh(879));
    }

    #[test]
    fn invalid_grant_is_terminal_refresh_error() {
        let err = classify_token_error(StatusCode::BAD_REQUEST, r#"{"error":"invalid_grant"}"#);
        assert!(is_terminal_refresh_error(&err));
    }

    #[test]
    fn forbidden_is_tier_denied_not_terminal_refresh_error() {
        let err = classify_token_error(StatusCode::FORBIDDEN, "tier denied");
        assert!(err.to_string().contains("SuperGrok"));
        assert!(!is_terminal_refresh_error(&err));
    }
}
