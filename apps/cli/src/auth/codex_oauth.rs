//! OpenAI Codex subscription OAuth for the `codex-oauth` inference provider.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::StatusCode;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::credentials::CredentialStore;

pub const CREDENTIAL_KEY: &str = "codex-oauth";
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const DEVICE_CODE_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/usercode";
pub const DEVICE_TOKEN_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
pub const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const VERIFY_URL: &str = "https://auth.openai.com/codex/device";
pub const REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";
pub const DEFAULT_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
pub const REFRESH_SKEW_SECS: i64 = 120;
const DEFAULT_EXPIRES_IN_SECS: i64 = 3600;
const MAX_POLL_SECS: u64 = 15 * 60;
const MIN_POLL_INTERVAL_SECS: u64 = 3;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
const OAUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OAUTH_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredTokens {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    pub expires_at: i64,
}

impl StoredTokens {
    fn needs_refresh(&self, now: i64) -> bool {
        self.expires_at.saturating_sub(now) <= REFRESH_SKEW_SECS
    }
}

#[derive(Debug, Clone)]
pub struct DeviceLogin {
    pub verification_uri: String,
    pub user_code: String,
    device_auth_id: String,
    interval_secs: u64,
}

#[cfg(test)]
impl DeviceLogin {
    pub(crate) fn for_test(verification_uri: &str, user_code: &str) -> Self {
        Self {
            verification_uri: verification_uri.to_string(),
            user_code: user_code.to_string(),
            device_auth_id: "test-device-auth-id".to_string(),
            interval_secs: 1,
        }
    }
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    #[serde(alias = "usercode")]
    user_code: String,
    device_auth_id: String,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenResponse {
    authorization_code: String,
    code_verifier: String,
    #[serde(default)]
    code_challenge: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

#[allow(dead_code)]
pub async fn run_device_code_login() -> Result<StoredTokens> {
    let login = begin_device_code_login().await?;
    eprintln!("Open this URL to authorize Codex subscription access:");
    eprintln!("{}", login.verification_uri);
    eprintln!(
        "Enter this one-time code in any browser: {}",
        login.user_code
    );
    complete_device_code_login(login).await
}

pub async fn begin_device_code_login() -> Result<DeviceLogin> {
    let body = oauth_http_client()?
        .post(DEVICE_CODE_URL)
        .json(&json!({ "client_id": CLIENT_ID }))
        .send()
        .await
        .context("requesting OpenAI Codex device code")?
        .error_for_status()
        .context("OpenAI Codex device-code request failed")?
        .text()
        .await
        .context("reading OpenAI Codex device-code response")?;
    let resp: DeviceCodeResponse = serde_json::from_str(&body).with_context(|| {
        format!(
            "parsing OpenAI Codex device-code response: {}",
            response_shape_hint(&body)
        )
    })?;
    Ok(DeviceLogin {
        verification_uri: VERIFY_URL.to_string(),
        user_code: resp.user_code,
        device_auth_id: resp.device_auth_id,
        interval_secs: resp
            .interval
            .unwrap_or(DEFAULT_POLL_INTERVAL_SECS)
            .max(MIN_POLL_INTERVAL_SECS),
    })
}

pub async fn complete_device_code_login(login: DeviceLogin) -> Result<StoredTokens> {
    let started = std::time::Instant::now();
    let mut interval = login.interval_secs;
    loop {
        if started.elapsed() > Duration::from_secs(MAX_POLL_SECS) {
            anyhow::bail!("OpenAI Codex device-code login timed out; try again");
        }
        let resp = oauth_http_client()?
            .post(DEVICE_TOKEN_URL)
            .json(&json!({
                "device_auth_id": login.device_auth_id,
                "user_code": login.user_code,
            }))
            .send()
            .await
            .context("polling OpenAI Codex device-code approval")?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            let approved: DeviceTokenResponse =
                serde_json::from_str(&body).context("parsing Codex device approval response")?;
            let _ = approved.code_challenge.as_deref();
            let tokens =
                exchange_authorization_code(&approved.authorization_code, &approved.code_verifier)
                    .await?;
            store_tokens(&tokens)?;
            return Ok(tokens);
        }
        let error_code = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
            .unwrap_or_default();
        if device_poll_is_pending(status, &error_code) {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            continue;
        }
        if error_code == "slow_down" {
            interval = (interval + 1).min(30);
            tokio::time::sleep(Duration::from_secs(interval)).await;
            continue;
        }
        return Err(classify_token_error(status, &body));
    }
}

pub async fn credential() -> Result<StoredTokens> {
    crate::auth::refresh_guard::credential_with_refresh(
        CREDENTIAL_KEY,
        "parsing stored Codex OAuth tokens",
        missing_auth_error,
        StoredTokens::needs_refresh,
        StoredTokens::refresh_token,
        merge_refresh_tokens,
        |tokens| async move { refresh_tokens(&tokens.refresh_token).await },
        is_terminal_refresh_error,
        codex_terminal_refresh_error,
    )
    .await
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
    anyhow!("Codex subscription auth required — set up OAuth in /settings → Providers.")
}

fn codex_terminal_refresh_error(e: anyhow::Error) -> anyhow::Error {
    anyhow!(
        "{e}; Codex subscription auth expired or was reused — set up OAuth in /settings → Providers"
    )
}

async fn exchange_authorization_code(code: &str, verifier: &str) -> Result<StoredTokens> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
        ("code_verifier", verifier),
    ];
    token_request(&params, None).await
}

async fn refresh_tokens(refresh_token: &str) -> Result<StoredTokens> {
    let previous = load_tokens()?;
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", CLIENT_ID),
    ];
    token_request(&params, Some(&previous)).await
}

async fn token_request(
    params: &[(&str, &str)],
    previous: Option<&StoredTokens>,
) -> Result<StoredTokens> {
    let resp = oauth_http_client()?
        .post(TOKEN_URL)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_body(params))
        .send()
        .await
        .context("POST OpenAI Codex OAuth token endpoint")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(classify_token_error(status, &body));
    }
    let parsed: TokenResponse = serde_json::from_str(&body).with_context(|| {
        format!(
            "parsing Codex OAuth token response: {}",
            response_shape_hint(&body)
        )
    })?;
    let access_token = parsed
        .access_token
        .or_else(|| previous.map(|tokens| tokens.access_token.clone()))
        .ok_or_else(|| anyhow!("Codex OAuth token response missing access_token"))?;
    let refresh_token = parsed
        .refresh_token
        .or_else(|| previous.map(|tokens| tokens.refresh_token.clone()))
        .ok_or_else(|| anyhow!("Codex OAuth token response missing refresh_token"))?;
    let expires_at = jwt_exp(&access_token)
        .or(parsed.expires_in.map(|secs| unix_now() + secs))
        .unwrap_or_else(|| unix_now() + DEFAULT_EXPIRES_IN_SECS);
    let id_token = parsed
        .id_token
        .or_else(|| previous.and_then(|tokens| tokens.id_token.clone()));
    let account_id = id_token
        .as_deref()
        .and_then(jwt_chatgpt_account_id)
        .or_else(|| previous.and_then(|tokens| tokens.account_id.clone()));
    Ok(StoredTokens {
        access_token,
        refresh_token,
        id_token,
        account_id,
        expires_at,
    })
}

fn oauth_http_client() -> Result<reqwest::Client> {
    oauth_http_client_builder()
        .build()
        .context("building OpenAI Codex OAuth HTTP client")
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

fn merge_refresh_tokens(previous: &StoredTokens, fresh: StoredTokens) -> StoredTokens {
    StoredTokens {
        id_token: fresh.id_token.or_else(|| previous.id_token.clone()),
        account_id: fresh.account_id.or_else(|| previous.account_id.clone()),
        ..fresh
    }
}

impl StoredTokens {
    fn refresh_token(&self) -> &str {
        &self.refresh_token
    }
}

fn classify_token_error(status: StatusCode, body: &str) -> anyhow::Error {
    let lower = body.to_ascii_lowercase();
    if status == StatusCode::TOO_MANY_REQUESTS {
        return anyhow!("OpenAI Codex OAuth token endpoint rate limited ({status}): {body}");
    }
    if status == StatusCode::UNAUTHORIZED
        || status == StatusCode::FORBIDDEN
        || lower.contains("invalid_grant")
        || lower.contains("invalid_token")
        || lower.contains("refresh_token_reused")
    {
        return anyhow!(
            "OpenAI Codex OAuth refresh rejected ({status}): invalid_grant, invalid_token, or refresh_token_reused"
        );
    }
    anyhow!("OpenAI Codex OAuth endpoint failed ({status}): {body}")
}

fn is_terminal_refresh_error(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("invalid_grant")
        || msg.contains("invalid_token")
        || msg.contains("refresh_token_reused")
}

fn device_poll_is_pending(status: StatusCode, error_code: &str) -> bool {
    status == StatusCode::FORBIDDEN
        || status == StatusCode::NOT_FOUND
        || error_code == "authorization_pending"
}

fn store_tokens(tokens: &StoredTokens) -> Result<()> {
    let mut store = CredentialStore::open_default()?;
    store.set(CREDENTIAL_KEY, serde_json::to_value(tokens)?);
    store.save()
}

fn load_tokens() -> Result<StoredTokens> {
    let store = CredentialStore::open_default()?;
    let raw = store.get(CREDENTIAL_KEY).ok_or_else(missing_auth_error)?;
    serde_json::from_value(raw.clone()).context("parsing stored Codex OAuth tokens")
}

fn jwt_exp(token: &str) -> Option<i64> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.as_bytes()).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("exp")?.as_i64()
}

fn jwt_chatgpt_account_id(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.as_bytes()).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("https://api.openai.com/auth")
        .and_then(|auth| auth.get("chatgpt_account_id"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn deserialize_optional_u64<'de, D>(deserializer: D) -> std::result::Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| de::Error::custom("expected unsigned integer interval")),
        Some(serde_json::Value::String(s)) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|_| de::Error::custom("expected numeric string interval")),
        Some(_) => Err(de::Error::custom("expected numeric interval")),
    }
}

fn response_shape_hint(body: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return "response was not valid JSON".to_string();
    };
    let Some(obj) = value.as_object() else {
        return format!("response root was {}", json_kind(&value));
    };
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    format!("JSON object with keys: {}", keys.join(", "))
}

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
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

    fn fake_jwt(exp: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#));
        format!("{header}.{payload}.sig")
    }

    fn fake_id_token(account_id: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"https://api.openai.com/auth":{{"chatgpt_account_id":"{account_id}"}}}}"#
        ));
        format!("{header}.{payload}.sig")
    }

    #[test]
    fn jwt_exp_reads_exp_claim() {
        assert_eq!(jwt_exp(&fake_jwt(1234)), Some(1234));
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
            id_token: None,
            account_id: None,
            expires_at: 1_000,
        };
        assert!(tokens.needs_refresh(881));
        assert!(!tokens.needs_refresh(879));
    }

    #[test]
    fn terminal_refresh_errors_are_classified() {
        for body in [
            r#"{"error":"invalid_grant"}"#,
            r#"{"error":"invalid_token"}"#,
            r#"{"error":"refresh_token_reused"}"#,
        ] {
            let err = classify_token_error(StatusCode::BAD_REQUEST, body);
            assert!(is_terminal_refresh_error(&err));
        }
    }

    #[test]
    fn rate_limit_is_transient_not_terminal() {
        let err = classify_token_error(StatusCode::TOO_MANY_REQUESTS, "slow");
        assert!(!is_terminal_refresh_error(&err));
    }

    #[test]
    fn device_code_response_accepts_string_interval_and_user_code_aliases() {
        let snake: DeviceCodeResponse = serde_json::from_str(
            r#"{"device_auth_id":"device-auth-123","user_code":"CODE-12345","interval":"0"}"#,
        )
        .unwrap();
        assert_eq!(snake.user_code, "CODE-12345");
        assert_eq!(snake.interval, Some(0));

        let compact: DeviceCodeResponse = serde_json::from_str(
            r#"{"device_auth_id":"device-auth-123","usercode":"CODE-67890","interval":7}"#,
        )
        .unwrap();
        assert_eq!(compact.user_code, "CODE-67890");
        assert_eq!(compact.interval, Some(7));
    }

    #[test]
    fn device_code_response_missing_interval_uses_default_later() {
        let parsed: DeviceCodeResponse =
            serde_json::from_str(r#"{"device_auth_id":"device-auth-123","usercode":"CODE"}"#)
                .unwrap();
        assert_eq!(parsed.interval, None);
    }

    #[test]
    fn account_id_is_extracted_from_id_token_claim() {
        assert_eq!(
            jwt_chatgpt_account_id(&fake_id_token("acc_123")).as_deref(),
            Some("acc_123")
        );
    }

    #[test]
    fn response_shape_hint_lists_keys_without_values() {
        let hint = response_shape_hint(r#"{"access_token":"secret","refresh_token":"secret2"}"#);
        assert_eq!(hint, "JSON object with keys: access_token, refresh_token");
        assert!(!hint.contains("secret"));
    }

    #[test]
    fn device_poll_pending_matches_codex_statuses_and_json_error() {
        assert!(device_poll_is_pending(StatusCode::FORBIDDEN, ""));
        assert!(device_poll_is_pending(StatusCode::NOT_FOUND, ""));
        assert!(device_poll_is_pending(
            StatusCode::BAD_REQUEST,
            "authorization_pending"
        ));
        assert!(!device_poll_is_pending(
            StatusCode::BAD_REQUEST,
            "invalid_grant"
        ));
    }

    #[test]
    fn token_response_accepts_id_token_and_extracts_account_metadata() {
        let id_token = fake_id_token("acc_abc");
        let body = format!(
            r#"{{
                "access_token":"{}",
                "refresh_token":"refresh-1",
                "id_token":"{}",
                "expires_in":3600
            }}"#,
            fake_jwt(9999),
            id_token
        );
        let parsed: TokenResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.id_token.as_deref(), Some(id_token.as_str()));
        assert_eq!(
            jwt_chatgpt_account_id(parsed.id_token.as_deref().unwrap()).as_deref(),
            Some("acc_abc")
        );
    }
}
