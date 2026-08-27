//! RFC 8628 device-authorization grant for MCP OAuth.
//!
//! The in-tree Codex provider flow is the pattern: poll in the daemon, keep
//! the Completing{cancelled} fence, and store tokens through the ownership-
//! guarded vault write. Poll ceiling is strictly below the OAuth flow-store
//! TTL so a flow cannot outlive its store entry.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use zeroize::Zeroize;

use super::auth::{StoredTokens, form_body, oauth_http_client};
use super::config::OauthAuth;

/// Must stay below the daemon OAuth flow-store TTL (600s).
pub const DEVICE_MAX_POLL_SECS: u64 = 9 * 60;
pub const DEVICE_SLOW_DOWN_INCREMENT_SECS: u64 = 5;
const DEFAULT_INTERVAL_SECS: u64 = 5;
const MIN_INTERVAL_SECS: u64 = 1;

/// RFC 8628 device-authorization response (the subset we persist).
#[derive(Clone)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub interval_secs: u64,
    pub expires_in_secs: u64,
}

impl std::fmt::Debug for DeviceAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .field("interval_secs", &self.interval_secs)
            .field("expires_in_secs", &self.expires_in_secs)
            .finish()
    }
}

impl Drop for DeviceAuthorization {
    fn drop(&mut self) {
        self.device_code.zeroize();
        self.user_code.zeroize();
    }
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
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

impl Drop for DeviceCodeResponse {
    fn drop(&mut self) {
        self.device_code.zeroize();
        self.user_code.zeroize();
    }
}

/// `user_code` is `[A-Za-z0-9-]` only (RFC 8628 / grok-build display rule).
pub fn validate_user_code(user_code: &str) -> Result<()> {
    if user_code.is_empty()
        || !user_code
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        bail!("MCP device-flow user_code is not displayable");
    }
    Ok(())
}

/// `verification_uri` must be https or loopback, with no control characters.
pub fn validate_verification_uri(uri: &str) -> Result<()> {
    if uri.chars().any(char::is_control) {
        bail!("MCP device-flow verification_uri contains control characters");
    }
    let lower = uri.to_ascii_lowercase();
    let ok = lower.starts_with("https://")
        || lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://localhost")
        || lower.starts_with("http://[::1]");
    if !ok {
        bail!("MCP device-flow verification_uri must be https or loopback");
    }
    Ok(())
}

pub fn synthesize_verification_uri_complete(verification_uri: &str, user_code: &str) -> String {
    let sep = if verification_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    format!("{verification_uri}{sep}user_code={user_code}")
}

pub fn display_device_prompt(auth: &DeviceAuthorization) -> String {
    format!(
        "Open {} and confirm this code: {}",
        auth.verification_uri_complete, auth.user_code
    )
}

pub async fn request_device_authorization(oauth: &OauthAuth) -> Result<DeviceAuthorization> {
    let endpoint = oauth
        .device_authorization_endpoint
        .as_deref()
        .context("OAuth server has no device_authorization_endpoint")?;
    let client_id = oauth.client_id.as_deref().unwrap_or("");
    let mut pairs = vec![("client_id", client_id)];
    let scope = oauth.scopes.join(" ");
    if !scope.is_empty() {
        pairs.push(("scope", &scope));
    }
    let body = zeroize::Zeroizing::new(form_body(&pairs));
    let resp = oauth_http_client()?
        .post(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.as_bytes().to_vec())
        .send()
        .await
        .context("requesting MCP device authorization")?;
    if !resp.status().is_success() {
        bail!(
            "MCP device-authorization request failed ({})",
            resp.status()
        );
    }
    let body = zeroize::Zeroizing::new(resp.text().await.unwrap_or_default());
    let mut parsed: DeviceCodeResponse =
        serde_json::from_str(&body).context("parsing MCP device-authorization response")?;
    validate_user_code(&parsed.user_code)?;
    let verification_uri = parsed
        .verification_uri
        .take()
        .context("device-authorization response omitted verification_uri")?;
    validate_verification_uri(&verification_uri)?;
    let verification_uri_complete = parsed
        .verification_uri_complete
        .take()
        .filter(|uri| validate_verification_uri(uri).is_ok())
        .unwrap_or_else(|| {
            synthesize_verification_uri_complete(&verification_uri, &parsed.user_code)
        });
    Ok(DeviceAuthorization {
        device_code: std::mem::take(&mut parsed.device_code),
        user_code: std::mem::take(&mut parsed.user_code),
        verification_uri,
        verification_uri_complete,
        interval_secs: parsed
            .interval
            .unwrap_or(DEFAULT_INTERVAL_SECS)
            .max(MIN_INTERVAL_SECS),
        expires_in_secs: parsed.expires_in.unwrap_or(DEVICE_MAX_POLL_SECS),
    })
}

pub enum DevicePollOutcome {
    Pending,
    SlowDown,
    Success(StoredTokens),
    Denied(String),
}

pub async fn poll_device_token(oauth: &OauthAuth, device_code: &str) -> Result<DevicePollOutcome> {
    let token_url = oauth
        .token_url
        .as_deref()
        .context("OAuth server has no token_url")?;
    let client_id = oauth.client_id.as_deref().unwrap_or("");
    let body = zeroize::Zeroizing::new(form_body(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", device_code),
        ("client_id", client_id),
    ]));
    let resp = oauth_http_client()?
        .post(token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.as_bytes().to_vec())
        .send()
        .await
        .context("polling MCP device token")?;
    let status = resp.status();
    let body = zeroize::Zeroizing::new(resp.text().await.unwrap_or_default());
    if status.is_success() {
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
        let mut parsed: TokenResp =
            serde_json::from_str(&body).context("parsing MCP device token response")?;
        let expires_at = parsed
            .expires_in
            .map(|secs| chrono::Utc::now().timestamp() + secs)
            .unwrap_or(0);
        return Ok(DevicePollOutcome::Success(StoredTokens {
            access_token: std::mem::take(&mut parsed.access_token),
            refresh_token: std::mem::take(&mut parsed.refresh_token),
            expires_at,
        }));
    }
    let error = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_default();
    match error.as_str() {
        "authorization_pending" => Ok(DevicePollOutcome::Pending),
        "slow_down" => Ok(DevicePollOutcome::SlowDown),
        other => Ok(DevicePollOutcome::Denied(if other.is_empty() {
            format!("device token poll failed ({status})")
        } else {
            other.to_string()
        })),
    }
}

pub async fn run_device_poll_loop<F, Fut>(
    mut interval_secs: u64,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mut poll: F,
) -> Result<StoredTokens>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<DevicePollOutcome>>,
{
    let started = std::time::Instant::now();
    // RFC 8628: wait one interval before the first poll.
    tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    loop {
        if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            bail!("MCP device-flow cancelled");
        }
        if started.elapsed() > Duration::from_secs(DEVICE_MAX_POLL_SECS) {
            bail!("MCP device-flow timed out; try again");
        }
        match poll().await? {
            DevicePollOutcome::Success(tokens) => return Ok(tokens),
            DevicePollOutcome::Pending => {
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            }
            DevicePollOutcome::SlowDown => {
                interval_secs = interval_secs.saturating_add(DEVICE_SLOW_DOWN_INCREMENT_SECS);
                tokio::time::sleep(Duration::from_secs(interval_secs)).await;
            }
            DevicePollOutcome::Denied(error) => bail!("MCP device-flow failed: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_ceiling_is_below_flow_store_ttl() {
        const FLOW_STORE_TTL_SECS: u64 = 10 * 60;
        assert!(
            DEVICE_MAX_POLL_SECS < FLOW_STORE_TTL_SECS,
            "device poll ceiling ({DEVICE_MAX_POLL_SECS}) must be < store TTL ({FLOW_STORE_TTL_SECS})"
        );
    }

    #[test]
    fn user_code_and_uri_validation() {
        validate_user_code("ABCD-EFGH").unwrap();
        validate_user_code("abc").unwrap();
        validate_user_code("bad code").unwrap_err();
        validate_user_code("bad\ncode").unwrap_err();
        validate_verification_uri("https://example.test/device").unwrap();
        validate_verification_uri("http://127.0.0.1:8080/device").unwrap();
        validate_verification_uri("http://evil.test/device").unwrap_err();
        validate_verification_uri("https://example.test/\n").unwrap_err();
        assert_eq!(
            synthesize_verification_uri_complete("https://example.test/device", "ABCD"),
            "https://example.test/device?user_code=ABCD"
        );
        assert_eq!(
            synthesize_verification_uri_complete("https://example.test/device?x=1", "ABCD"),
            "https://example.test/device?x=1&user_code=ABCD"
        );
    }

    #[tokio::test]
    async fn poll_loop_pending_slow_down_success_and_cancel() {
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ticks_clone = ticks.clone();
        let tokens = run_device_poll_loop(0, cancelled.clone(), move || {
            let n = ticks_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                Ok(match n {
                    0 => DevicePollOutcome::Pending,
                    1 => DevicePollOutcome::SlowDown,
                    _ => DevicePollOutcome::Success(StoredTokens {
                        access_token: "tok".into(),
                        refresh_token: None,
                        expires_at: 0,
                    }),
                })
            }
        })
        .await
        .unwrap();
        assert_eq!(tokens.access_token, "tok");
        assert!(ticks.load(std::sync::atomic::Ordering::SeqCst) >= 3);

        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let err = run_device_poll_loop(0, cancelled, || async { Ok(DevicePollOutcome::Pending) })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cancelled"), "{err}");
    }
}
