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
//!   the code, and stores the `{access,refresh}` tokens via
//!   [`crate::credentials`] under `mcp:<server>`. At call time the stored
//!   token is refreshed if expired and sent as `Authorization: Bearer …`.
//! - **none** — public; no header, no env. Warned at add-time.
//!
//! Tokens never enter model context; they live only in the request layer.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::config::{Auth, OauthAuth, ServerConfig};

/// The credential-store key for a server's OAuth tokens.
pub fn cred_key(server: &str) -> String {
    format!("mcp:{server}")
}

pub fn header_cred_key(server: &str) -> String {
    format!("mcp:{server}:header")
}

pub fn auth_env_cred_key(server: &str, env_name: &str) -> String {
    format!("mcp:{server}:auth-env:{env_name}")
}

pub fn base_env_cred_key(server: &str, env_name: &str) -> String {
    format!("mcp:{server}:base-env:{env_name}")
}

/// Stored OAuth tokens for an MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTokens {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Unix seconds at which `access_token` expires (0 = unknown/never).
    #[serde(default)]
    pub expires_at: i64,
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
    resolve_static_inner(None, cfg)
}

pub fn resolve_static_for_server(server: &str, cfg: &ServerConfig) -> ResolvedAuth {
    let store = crate::credentials::CredentialStore::open_default().ok();
    resolve_static_inner(Some((&store, server)), cfg)
}

fn resolve_static_inner(
    credential_context: Option<(&Option<crate::credentials::CredentialStore>, &str)>,
    cfg: &ServerConfig,
) -> ResolvedAuth {
    let mut out = ResolvedAuth::default();
    if let Some((store, _server)) = credential_context {
        for (k, credential_ref) in &cfg.env_credential_refs {
            if let Some(value) = credential_value(store, credential_ref) {
                out.env.insert(k.clone(), value);
            } else {
                out.missing_env.push(format!("credential:{credential_ref}"));
            }
        }
    }
    // Base subprocess env (stdio) with $VAR resolution.
    for (k, v) in &cfg.env {
        let r = crate::envref::resolve(v);
        out.env.insert(k.clone(), r.value);
        out.missing_env.extend(r.missing);
        out.missing_env.extend(r.errors);
    }
    match &cfg.auth {
        Auth::Header(h) => {
            if let Some(credential_ref) = h.credential_ref.as_deref()
                && let Some((store, _server)) = credential_context
            {
                if let Some(value) = credential_value(store, credential_ref) {
                    out.headers.insert(h.header.clone(), value);
                } else {
                    out.missing_env.push(format!("credential:{credential_ref}"));
                }
            } else {
                let r = crate::envref::resolve(&h.value);
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
            if let Some((store, _server)) = credential_context {
                for (k, credential_ref) in &e.credential_refs {
                    if let Some(value) = credential_value(store, credential_ref) {
                        out.env.insert(k.clone(), value);
                    } else {
                        out.missing_env.push(format!("credential:{credential_ref}"));
                    }
                }
            }
            for (k, v) in &e.vars {
                let r = crate::envref::resolve(v);
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
    store: &Option<crate::credentials::CredentialStore>,
    credential_ref: &str,
) -> Option<String> {
    let value = store.as_ref()?.get(credential_ref)?;
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
    let Auth::Oauth(oauth) = &cfg.auth else {
        return Ok(None);
    };
    let mut store = crate::credentials::CredentialStore::open_default()?;
    let key = cred_key(server);
    let Some(raw) = store.get(&key).cloned() else {
        bail!("MCP server `{server}` requires OAuth — run `authenticate` in /settings → MCP first");
    };
    let mut tokens: StoredTokens =
        serde_json::from_value(raw).context("parsing stored MCP OAuth tokens")?;
    if tokens.is_expired(now_unix()) {
        let refresh = tokens
            .refresh_token
            .clone()
            .context("stored MCP token expired and no refresh token is available")?;
        tokens = refresh_token(oauth, &refresh).await?;
        store.set(&key, serde_json::to_value(&tokens)?);
        store.save()?;
    }
    Ok(Some(format!("Bearer {}", tokens.access_token)))
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// PKCE verifier + S256 challenge (RFC 7636).
struct Pkce {
    verifier: String,
    challenge: String,
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

fn into_stored(resp: TokenResp) -> StoredTokens {
    let expires_at = resp.expires_in.map(|s| now_unix() + s).unwrap_or(0);
    StoredTokens {
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
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
    let body = form_body(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ]);
    let resp = reqwest::Client::new()
        .post(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("OAuth token exchange failed ({status}): {body}");
    }
    Ok(into_stored(resp.json::<TokenResp>().await?))
}

/// Refresh an access token using a stored refresh token.
async fn refresh_token(oauth: &OauthAuth, refresh: &str) -> Result<StoredTokens> {
    let token_url = oauth
        .token_url
        .as_deref()
        .context("OAuth server has no `token_url`")?;
    let client_id = oauth.client_id.as_deref().unwrap_or("");
    let body = form_body(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("client_id", client_id),
    ]);
    let resp = reqwest::Client::new()
        .post(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("OAuth token refresh failed ({status}): {body}");
    }
    let mut tokens = into_stored(resp.json::<TokenResp>().await?);
    // Some servers omit the refresh token on refresh — keep the old one.
    if tokens.refresh_token.is_none() {
        tokens.refresh_token = Some(refresh.to_string());
    }
    Ok(tokens)
}

/// Run the interactive OAuth 2.1 + PKCE flow for a server: spin a
/// loopback redirect listener, open the browser to the authorize URL,
/// capture the code, exchange it, and persist the tokens under
/// `mcp:<server>`. Returns the stored access token's summary.
pub async fn run_oauth_flow(server: &str, cfg: &ServerConfig) -> Result<StoredTokens> {
    let Auth::Oauth(oauth) = &cfg.auth else {
        bail!("MCP server `{server}` is not configured for OAuth");
    };
    let pkce = generate_pkce();
    let state = {
        let mut b = [0u8; 16];
        rand::rng().fill_bytes(&mut b);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let url = build_authorize_url(oauth, &redirect_uri, &pkce.challenge, &state)?;

    eprintln!("Opening browser for MCP server `{server}` OAuth…");
    eprintln!("If it doesn't open, visit:\n  {url}");
    let _ = webbrowser_open(&url);

    let (code, got_state) = wait_for_callback(listener).await?;
    if got_state != state {
        bail!("OAuth state mismatch (possible CSRF)");
    }
    let tokens = exchange_code(oauth, &code, &pkce.verifier, &redirect_uri).await?;

    let mut store = crate::credentials::CredentialStore::open_default()?;
    store.set(cred_key(server), serde_json::to_value(&tokens)?);
    store.save()?;
    Ok(tokens)
}

/// Best-effort browser open without pulling a dependency: shell out to the
/// platform opener. Failure is non-fatal (the URL is also printed).
fn webbrowser_open(url: &str) -> Result<()> {
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
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let val = urlencoding::decode(v)
                .map(|c| c.into_owned())
                .unwrap_or_default();
            match k {
                "code" => code = Some(val),
                "state" => state = Some(val),
                _ => {}
            }
        }
    }
    let body = "<html><body>Authentication complete. You can close this tab.</body></html>";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
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
        }
    }

    #[test]
    fn cred_key_namespaces_server() {
        assert_eq!(cred_key("github"), "mcp:github");
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
}
