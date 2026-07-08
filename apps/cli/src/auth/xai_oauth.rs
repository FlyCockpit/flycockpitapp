//! xAI SuperGrok OAuth for the `grok-oauth` inference provider.
//!
//! This flow is provider auth, not harness auth: tokens are stored under the
//! provider credential key and read by the daemon before each request.

use std::io::{BufRead, Write};
use std::net::TcpListener;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::credentials::CredentialStore;

pub const CREDENTIAL_KEY: &str = "grok-oauth";
#[allow(dead_code)]
pub const ISSUER: &str = "https://auth.x.ai";
pub const DISCOVERY_URL: &str = "https://auth.x.ai/.well-known/openid-configuration";
pub const CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
pub const SCOPES: &str = "openid profile email offline_access grok-cli:access api:access";
pub const REDIRECT_URI: &str = "http://127.0.0.1:56121/callback";
pub const REFRESH_SKEW_SECS: i64 = 120;
const OAUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OAUTH_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

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

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

#[allow(dead_code)]
pub async fn run_login_flow(manual_paste: bool) -> Result<StoredTokens> {
    let login = begin_manual_login().await?;
    if manual_paste {
        eprintln!("Open this xAI OAuth URL, then paste the callback URL or code:");
        eprintln!("{}", login.authorize_url);
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("reading OAuth callback/code from stdin")?;
        return complete_manual_login(login, line.trim()).await;
    }

    let listener = TcpListener::bind("127.0.0.1:56121").context(
        "binding xAI OAuth callback on 127.0.0.1:56121; use manual paste if the port is busy",
    )?;
    eprintln!("Opening browser for xAI Grok subscription OAuth...");
    if let Err(e) = webbrowser_open(&login.authorize_url) {
        eprintln!("Could not open browser ({e}). Open this URL manually:");
        eprintln!("{}", login.authorize_url);
    }
    let callback = wait_for_callback(listener)?;
    complete_manual_login(login, &callback).await
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
    let code = parse_callback_input(input, Some(&login.state))?;
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
    CredentialStore::open_default()
        .ok()
        .and_then(|store| {
            store
                .get(CREDENTIAL_KEY)
                .and_then(|raw| serde_json::from_value::<StoredTokens>(raw.clone()).ok())
        })
        .is_some()
}

#[allow(dead_code)]
pub fn logout() -> Result<()> {
    let mut store = CredentialStore::open_default()?;
    store.remove(CREDENTIAL_KEY);
    store.save()
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

#[allow(dead_code)]
fn wait_for_callback(listener: TcpListener) -> Result<String> {
    let (mut stream, _) = listener
        .accept()
        .context("waiting for xAI OAuth callback")?;
    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("reading xAI OAuth callback request")?;
    let path = line
        .split_whitespace()
        .nth(1)
        .context("malformed xAI OAuth callback request")?
        .to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 41\r\n\r\nxAI OAuth complete. You can close this tab."
    );
    Ok(path)
}

pub async fn wait_for_callback_async() -> Result<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:56121")
        .await
        .context(
            "binding xAI OAuth callback on 127.0.0.1:56121; use manual paste if the port is busy",
        )?;
    let (mut stream, _) = listener
        .accept()
        .await
        .context("waiting for xAI OAuth callback")?;
    let mut reader = tokio::io::BufReader::new(&mut stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("reading xAI OAuth callback request")?;
    let path = line
        .split_whitespace()
        .nth(1)
        .context("malformed xAI OAuth callback request")?
        .to_string();
    let _ = stream
        .write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 41\r\n\r\nxAI OAuth complete. You can close this tab.",
        )
        .await;
    Ok(path)
}

pub async fn complete_local_callback_login(login: ManualLogin) -> Result<StoredTokens> {
    let callback = wait_for_callback_async().await?;
    complete_manual_login(login, &callback).await
}

fn parse_callback_input(input: &str, expected_state: Option<&str>) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("OAuth callback/code is empty");
    }
    if !trimmed.contains('=') && !trimmed.contains('?') && !trimmed.contains('/') {
        if expected_state.is_some() {
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
            _ => {}
        }
    }
    if let Some(expected) = expected_state {
        let actual = state
            .as_deref()
            .context("OAuth callback missing `state` (possible CSRF)")?;
        if actual != expected {
            bail!("OAuth state mismatch (possible CSRF)");
        }
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

pub(crate) fn webbrowser_open(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.spawn().context("launching browser")?;
    Ok(())
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

    #[test]
    fn parse_callback_url_checks_state() {
        let code = parse_callback_input(
            "http://127.0.0.1:56121/callback?code=abc&state=state-1",
            Some("state-1"),
        )
        .unwrap();
        assert_eq!(code, "abc");
    }

    #[test]
    fn parse_callback_rejects_bare_code_when_state_expected() {
        let err = parse_callback_input("abc123", Some("state-1")).unwrap_err();
        assert!(err.to_string().contains("missing `state`"));
    }

    #[test]
    fn parse_callback_accepts_bare_code_without_stateful_flow() {
        assert_eq!(parse_callback_input("abc123", None).unwrap(), "abc123");
    }

    #[test]
    fn parse_callback_rejects_missing_state_when_expected() {
        let err = parse_callback_input("/callback?code=abc", Some("state-1")).unwrap_err();
        assert!(err.to_string().contains("missing `state`"));
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
    fn parse_callback_rejects_state_mismatch() {
        let err = parse_callback_input("/callback?code=abc&state=bad", Some("good")).unwrap_err();
        assert!(err.to_string().contains("state mismatch"));
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
