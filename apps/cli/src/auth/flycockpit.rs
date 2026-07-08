//! Flycockpit account device authorization and instance credentials.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use reqwest::{StatusCode, Url};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::credentials::CredentialStore;

pub const CREDENTIAL_KEY: &str = "flycockpit";
pub const CLIENT_ID: &str = "cockpit-cli";
pub const DEVICE_SCOPE: &str = "account:instance";
pub const DEFAULT_SERVER_URL: &str = "https://app.flycockpit.dev";
const MAX_POLL_SECS: u64 = 30 * 60;
const MIN_POLL_INTERVAL_SECS: u64 = 1;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
const MAX_POLL_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountInfo {
    pub user_id: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredFlycockpitCredential {
    pub server_url: String,
    pub instance_id: String,
    pub instance_token: String,
    pub account: AccountInfo,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLogin {
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub user_code: String,
    device_code: String,
    interval_secs: u64,
    expires_in_secs: Option<u64>,
}

impl DeviceLogin {
    pub fn open_url(&self) -> &str {
        self.verification_uri_complete
            .as_deref()
            .unwrap_or(&self.verification_uri)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DeviceCodeResponse {
    #[serde(alias = "deviceCode")]
    device_code: String,
    #[serde(alias = "userCode")]
    user_code: String,
    #[serde(alias = "verificationUri")]
    verification_uri: String,
    #[serde(default, alias = "verificationUriComplete")]
    verification_uri_complete: Option<String>,
    #[serde(
        default,
        alias = "expiresIn",
        deserialize_with = "deserialize_optional_u64"
    )]
    expires_in: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    interval: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
struct DeviceTokenResponse {
    #[serde(default, alias = "accessToken")]
    access_token: Option<String>,
    #[serde(default, alias = "tokenType")]
    token_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RegisterResponse {
    #[serde(alias = "instanceId")]
    instance_id: String,
    #[serde(alias = "instanceToken")]
    instance_token: String,
    account: AccountResponse,
}

#[derive(Debug, Clone, Deserialize)]
struct AccountResponse {
    #[serde(alias = "userId")]
    user_id: String,
    email: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ConnectorTokenResponse {
    token: String,
    #[serde(default, alias = "expiresAt")]
    expires_at: Option<String>,
    #[serde(default, alias = "relayUrl")]
    relay_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorToken {
    pub token: String,
    pub expires_at: Option<String>,
    pub relay_url: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OrpcEnvelope<T> {
    json: T,
}

#[derive(Debug, Clone, Deserialize)]
struct OAuthErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default, alias = "errorDescription")]
    error_description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OrpcErrorBody {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PollErrorAction {
    Pending,
    SlowDown,
    Expired,
    Denied,
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    Unknown,
    Online { relay_url: Option<String> },
    Revoked,
    Unauthorized,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct FlycockpitClient {
    http: reqwest::Client,
    server_url: String,
}

impl FlycockpitClient {
    pub fn new(server_url: impl AsRef<str>) -> Result<Self> {
        let server_url = normalize_server_url(server_url.as_ref())?;
        Ok(Self {
            http: reqwest::Client::new(),
            server_url,
        })
    }

    pub async fn begin_device_code_login(&self) -> Result<DeviceLogin> {
        let url = endpoint(&self.server_url, "/api/auth/device/code")?;
        let body = self
            .http
            .post(url)
            .json(&json!({ "client_id": CLIENT_ID, "scope": DEVICE_SCOPE }))
            .send()
            .await
            .context("requesting Flycockpit device code")?
            .error_for_status()
            .context("Flycockpit device-code request failed")?
            .text()
            .await
            .context("reading Flycockpit device-code response")?;
        let resp: DeviceCodeResponse = serde_json::from_str(&body).with_context(|| {
            format!(
                "parsing Flycockpit device-code response: {}",
                response_shape_hint(&body)
            )
        })?;
        Ok(DeviceLogin {
            verification_uri: resp.verification_uri,
            verification_uri_complete: resp.verification_uri_complete,
            user_code: resp.user_code,
            device_code: resp.device_code,
            interval_secs: resp
                .interval
                .unwrap_or(DEFAULT_POLL_INTERVAL_SECS)
                .max(MIN_POLL_INTERVAL_SECS),
            expires_in_secs: resp.expires_in,
        })
    }

    pub async fn complete_device_code_login(
        &self,
        login: DeviceLogin,
        display_name: Option<String>,
        existing_instance_id: Option<String>,
    ) -> Result<StoredFlycockpitCredential> {
        let access_token = self.poll_device_token(login).await?;
        let registered = self
            .register_instance(&access_token, display_name.clone(), existing_instance_id)
            .await?;
        let stored = StoredFlycockpitCredential {
            server_url: self.server_url.clone(),
            instance_id: registered.instance_id,
            instance_token: registered.instance_token,
            account: AccountInfo {
                user_id: registered.account.user_id,
                email: registered.account.email,
            },
            display_name: display_name.or_else(|| Some(default_display_name())),
        };
        store_credential(&stored)?;
        Ok(stored)
    }

    async fn poll_device_token(&self, login: DeviceLogin) -> Result<String> {
        let started = Instant::now();
        let max_secs = login
            .expires_in_secs
            .unwrap_or(MAX_POLL_SECS)
            .min(MAX_POLL_SECS);
        let mut interval = login.interval_secs.max(MIN_POLL_INTERVAL_SECS);
        let url = endpoint(&self.server_url, "/api/auth/device/token")?;
        loop {
            if started.elapsed() > Duration::from_secs(max_secs) {
                anyhow::bail!("Flycockpit device-code login expired; run `cockpit login` again");
            }
            let resp = self
                .http
                .post(url.clone())
                .json(&json!({
                    "client_id": CLIENT_ID,
                    "device_code": login.device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                }))
                .send()
                .await
                .context("polling Flycockpit device-code approval")?;
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if status.is_success() {
                let token: DeviceTokenResponse =
                    parse_orpc_json(&body).context("parsing Flycockpit device token response")?;
                let _ = token.token_type.as_deref();
                if let Some(access_token) = token.access_token.filter(|s| !s.trim().is_empty()) {
                    return Ok(access_token);
                }
                anyhow::bail!(
                    "Flycockpit device token response did not include an access token: {}",
                    response_shape_hint(&body)
                );
            }

            match classify_poll_error(status, &body) {
                PollErrorAction::Pending => {
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                }
                PollErrorAction::SlowDown => {
                    interval = (interval + 1).min(MAX_POLL_INTERVAL_SECS);
                    tokio::time::sleep(Duration::from_secs(interval)).await;
                }
                PollErrorAction::Expired => {
                    anyhow::bail!(
                        "Flycockpit device-code login expired; run `cockpit login` again"
                    );
                }
                PollErrorAction::Denied => {
                    anyhow::bail!("Flycockpit device-code login was denied in the browser");
                }
                PollErrorAction::Fatal => {
                    return Err(classify_http_error("device token", status, &body));
                }
            }
        }
    }

    async fn register_instance(
        &self,
        access_token: &str,
        display_name: Option<String>,
        existing_instance_id: Option<String>,
    ) -> Result<RegisterResponse> {
        let url = endpoint(&self.server_url, "/rpc/instances/register")?;
        let mut payload = json!({
            "hostname": hostname(),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cliVersion": env!("CARGO_PKG_VERSION"),
        });
        if let Some(name) = display_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            payload["displayName"] = Value::String(name.to_string());
        }
        if let Some(instance_id) = existing_instance_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            payload["instanceId"] = Value::String(instance_id.to_string());
        }
        let resp = self
            .http
            .post(url)
            .bearer_auth(access_token)
            .header("x-csrf-token", "cockpit-cli")
            .json(&json!({ "json": payload }))
            .send()
            .await
            .context("registering Flycockpit instance")?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            return parse_orpc_json(&body).context("parsing Flycockpit instance.register response");
        }
        Err(classify_http_error("instance.register", status, &body))
    }

    pub async fn revoke_instance(&self, credential: &StoredFlycockpitCredential) -> Result<()> {
        let url = endpoint(&self.server_url, "/rpc/instances/revoke")?;
        let resp = self
            .http
            .post(url)
            .header("x-csrf-token", "cockpit-cli")
            .json(&json!({ "json": { "instanceId": credential.instance_id } }))
            .send()
            .await
            .context("revoking Flycockpit instance")?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            return Ok(());
        }
        Err(classify_http_error("instance.revoke", status, &body))
    }

    pub async fn mint_connector_token(
        &self,
        credential: &StoredFlycockpitCredential,
    ) -> Result<ConnectorToken> {
        let url = endpoint(&self.server_url, "/rpc/instances/mintConnectorToken")?;
        let resp = self
            .http
            .post(url)
            .header("x-csrf-token", "cockpit-cli")
            .json(&json!({
                "json": {
                    "instanceId": credential.instance_id,
                    "instanceToken": credential.instance_token,
                }
            }))
            .send()
            .await
            .context("minting Flycockpit connector token")?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            let parsed: ConnectorTokenResponse =
                parse_orpc_json(&body).context("parsing Flycockpit connector token response")?;
            let relay_url = parsed
                .relay_url
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| {
                    anyhow!("Flycockpit connector token response did not include relayUrl")
                })?;
            return Ok(ConnectorToken {
                token: parsed.token,
                expires_at: parsed.expires_at,
                relay_url,
            });
        }
        if is_revoked_error(&body) {
            let _ = clear_credential();
        }
        Err(classify_http_error("connector token", status, &body))
    }

    pub async fn connection_status(
        &self,
        credential: &StoredFlycockpitCredential,
    ) -> ConnectionStatus {
        match self.mint_connector_token(credential).await {
            Ok(token) => ConnectionStatus::Online {
                relay_url: Some(token.relay_url),
            },
            Err(error) => {
                let message = error.to_string();
                if message.to_ascii_lowercase().contains("revoked") {
                    ConnectionStatus::Revoked
                } else if message.contains("401") || message.contains("403") {
                    ConnectionStatus::Unauthorized
                } else if message.contains("request") || message.contains("network") {
                    ConnectionStatus::Unknown
                } else {
                    ConnectionStatus::Error(message)
                }
            }
        }
    }
}

pub fn load_credential() -> Result<StoredFlycockpitCredential> {
    let store = CredentialStore::open_default()?;
    let raw = store
        .get(CREDENTIAL_KEY)
        .ok_or_else(|| anyhow!("not logged in to Flycockpit; run `cockpit login`"))?;
    serde_json::from_value(raw.clone()).context("parsing stored Flycockpit account credential")
}

pub fn maybe_load_credential() -> Option<StoredFlycockpitCredential> {
    CredentialStore::open_default()
        .ok()
        .and_then(|store| store.get(CREDENTIAL_KEY).cloned())
        .and_then(|raw| serde_json::from_value(raw).ok())
}

pub fn store_credential(credential: &StoredFlycockpitCredential) -> Result<()> {
    let mut store = CredentialStore::open_default()?;
    store.set(CREDENTIAL_KEY, serde_json::to_value(credential)?);
    store.save()
}

pub fn clear_credential() -> Result<()> {
    let mut store = CredentialStore::open_default()?;
    store.remove(CREDENTIAL_KEY);
    store.save()
}

pub fn stored_instance_token_for_redaction() -> Option<String> {
    #[cfg(test)]
    {
        return TEST_REDACTION_TOKEN.with(|token| token.borrow().clone());
    }

    #[cfg(not(test))]
    {
        maybe_load_credential().map(|credential| credential.instance_token)
    }
}

#[cfg(test)]
thread_local! {
    static TEST_REDACTION_TOKEN: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_redaction_token_override<T>(
    token: impl Into<String>,
    f: impl FnOnce() -> T,
) -> T {
    struct Reset(Option<String>);

    impl Drop for Reset {
        fn drop(&mut self) {
            let previous = self.0.take();
            TEST_REDACTION_TOKEN.with(|token| *token.borrow_mut() = previous);
        }
    }

    let previous = TEST_REDACTION_TOKEN.with(|slot| slot.borrow_mut().replace(token.into()));
    let _reset = Reset(previous);
    f()
}

pub fn default_display_name() -> String {
    hostname()
}

pub fn normalize_server_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        anyhow::bail!("server URL cannot be empty");
    }
    let url = Url::parse(trimmed).context("server URL must be an absolute URL")?;
    if url.username() != "" || url.password().is_some() {
        anyhow::bail!("server URL must not include credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("server URL must not include a query string or fragment");
    }
    if url.path() != "/" && !url.path().is_empty() {
        anyhow::bail!("server URL must be an origin, not a path");
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(url.host_str()) => {}
        "http" => anyhow::bail!("server URL must use HTTPS except for localhost development"),
        scheme => anyhow::bail!("unsupported server URL scheme `{scheme}`"),
    }
    let mut origin = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

fn endpoint(server_url: &str, path: &str) -> Result<Url> {
    let base = Url::parse(server_url).context("parsing Flycockpit server URL")?;
    base.join(path.trim_start_matches('/'))
        .with_context(|| format!("building Flycockpit endpoint {path}"))
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(
        host,
        Some("localhost") | Some("127.0.0.1") | Some("::1") | Some("[::1]")
    )
}

fn parse_orpc_json<T: for<'de> Deserialize<'de>>(body: &str) -> Result<T> {
    if let Ok(envelope) = serde_json::from_str::<OrpcEnvelope<T>>(body) {
        return Ok(envelope.json);
    }
    serde_json::from_str::<T>(body).with_context(|| response_shape_hint(body))
}

fn classify_poll_error(status: StatusCode, body: &str) -> PollErrorAction {
    let oauth = serde_json::from_str::<OAuthErrorBody>(body).ok();
    let orpc = serde_json::from_str::<OrpcEnvelope<OrpcErrorBody>>(body).ok();
    let code = oauth
        .as_ref()
        .and_then(|e| e.error.as_deref())
        .or_else(|| orpc.as_ref().and_then(|e| e.json.code.as_deref()))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let message = oauth
        .as_ref()
        .and_then(|e| e.error_description.as_deref())
        .or_else(|| orpc.as_ref().and_then(|e| e.json.message.as_deref()))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if code == "authorization_pending" || message.contains("pending") {
        return PollErrorAction::Pending;
    }
    if code == "slow_down" || message.contains("slow") || message.contains("too fast") {
        return PollErrorAction::SlowDown;
    }
    if code == "expired_token" || message.contains("expired") {
        return PollErrorAction::Expired;
    }
    if code == "access_denied" || message.contains("denied") || message.contains("rejected") {
        return PollErrorAction::Denied;
    }
    if status == StatusCode::BAD_REQUEST && message.contains("device authorization is pending") {
        return PollErrorAction::Pending;
    }
    PollErrorAction::Fatal
}

fn is_revoked_error(body: &str) -> bool {
    let message = serde_json::from_str::<OrpcEnvelope<OrpcErrorBody>>(body)
        .ok()
        .and_then(|e| e.json.message)
        .unwrap_or_default()
        .to_ascii_lowercase();
    message.contains("revoked")
}

fn classify_http_error(context: &str, status: StatusCode, body: &str) -> anyhow::Error {
    let message = serde_json::from_str::<OrpcEnvelope<OrpcErrorBody>>(body)
        .ok()
        .and_then(|e| e.json.message)
        .filter(|m| !m.trim().is_empty());
    if let Some(message) = message {
        return anyhow!("Flycockpit {context} failed ({status}): {message}");
    }
    let oauth = serde_json::from_str::<OAuthErrorBody>(body).ok();
    if let Some(code) = oauth.and_then(|e| e.error).filter(|m| !m.trim().is_empty()) {
        return anyhow!("Flycockpit {context} failed ({status}): {code}");
    }
    anyhow!(
        "Flycockpit {context} failed ({status}): {}",
        response_shape_hint(body)
    )
}

fn response_shape_hint(body: &str) -> String {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return "response was not valid JSON".to_string();
    };
    let Some(obj) = value.as_object() else {
        return format!("response root was {}", json_kind(&value));
    };
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    format!("JSON object with keys: {}", keys.join(", "))
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn deserialize_optional_u64<'de, D>(deserializer: D) -> std::result::Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| de::Error::custom("expected unsigned integer")),
        Some(Value::String(s)) => s
            .parse::<u64>()
            .map(Some)
            .map_err(|_| de::Error::custom("expected numeric string")),
        Some(_) => Err(de::Error::custom("expected numeric value")),
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "cockpit-cli".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    #[test]
    fn device_code_response_accepts_snake_and_camel_case() {
        let snake: DeviceCodeResponse = serde_json::from_str(
            r#"{"device_code":"dev-1","user_code":"ABCD-1234","verification_uri":"https://app.test/device","verification_uri_complete":"https://app.test/device?user_code=ABCD-1234","expires_in":"1800","interval":"1"}"#,
        )
        .unwrap();
        assert_eq!(snake.device_code, "dev-1");
        assert_eq!(snake.user_code, "ABCD-1234");
        assert_eq!(snake.expires_in, Some(1800));

        let camel: DeviceCodeResponse = serde_json::from_str(
            r#"{"deviceCode":"dev-2","userCode":"WXYZ-9876","verificationUri":"https://app.test/device","verificationUriComplete":"https://app.test/device?user_code=WXYZ-9876","expiresIn":1800,"interval":2}"#,
        )
        .unwrap();
        assert_eq!(camel.device_code, "dev-2");
        assert_eq!(
            camel.verification_uri_complete.as_deref(),
            Some("https://app.test/device?user_code=WXYZ-9876")
        );
    }

    #[test]
    fn orpc_register_response_accepts_camel_and_snake_case() {
        let parsed: RegisterResponse = parse_orpc_json(
            r#"{"json":{"instanceId":"i1","instanceToken":"fci_secret","account":{"userId":"u1","email":"u@example.test"}}}"#,
        )
        .unwrap();
        assert_eq!(parsed.instance_id, "i1");
        assert_eq!(parsed.account.user_id, "u1");

        let parsed: RegisterResponse = parse_orpc_json(
            r#"{"json":{"instance_id":"i2","instance_token":"fci_secret","account":{"user_id":"u2","email":"u2@example.test"}}}"#,
        )
        .unwrap();
        assert_eq!(parsed.instance_id, "i2");
        assert_eq!(parsed.account.user_id, "u2");
    }

    #[test]
    fn pending_slow_down_expired_and_denied_errors_are_classified() {
        assert_eq!(
            classify_poll_error(
                StatusCode::BAD_REQUEST,
                r#"{"error":"authorization_pending"}"#
            ),
            PollErrorAction::Pending
        );
        assert_eq!(
            classify_poll_error(
                StatusCode::BAD_REQUEST,
                r#"{"json":{"code":"BAD_REQUEST","message":"Device authorization is pending."}}"#
            ),
            PollErrorAction::Pending
        );
        assert_eq!(
            classify_poll_error(StatusCode::BAD_REQUEST, r#"{"error":"slow_down"}"#),
            PollErrorAction::SlowDown
        );
        assert_eq!(
            classify_poll_error(StatusCode::BAD_REQUEST, r#"{"error":"expired_token"}"#),
            PollErrorAction::Expired
        );
        assert_eq!(
            classify_poll_error(StatusCode::BAD_REQUEST, r#"{"error":"access_denied"}"#),
            PollErrorAction::Denied
        );
    }

    #[test]
    fn response_shape_hint_does_not_leak_tokens() {
        let hint =
            response_shape_hint(r#"{"instanceToken":"fci_super_secret","access_token":"secret"}"#);
        assert_eq!(hint, "JSON object with keys: access_token, instanceToken");
        assert!(!hint.contains("fci_super_secret"));
        assert!(!hint.contains("secret"));
    }

    #[test]
    fn server_url_validation_requires_https_except_loopback() {
        assert_eq!(
            normalize_server_url("https://app.example.test/").unwrap(),
            "https://app.example.test"
        );
        assert_eq!(
            normalize_server_url("http://localhost:3000").unwrap(),
            "http://localhost:3000"
        );
        assert!(normalize_server_url("http://example.test").is_err());
        assert!(normalize_server_url("https://example.test/path").is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn device_login_polls_pending_then_registers_and_stores_credentials() {
        let (server, requests) = start_test_server(vec![
            response(200, r#"{"device_code":"dev-1","user_code":"ABCD-1234","verification_uri":"http://localhost/device","interval":1}"#),
            response(400, r#"{"json":{"code":"BAD_REQUEST","message":"Device authorization is pending."}}"#),
            response(200, r#"{"access_token":"session-token"}"#),
            response(200, r#"{"json":{"instanceId":"inst-1","instanceToken":"fci_instance_secret","account":{"userId":"user-1","email":"user@example.test"}}}"#),
        ]).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());

        let client = FlycockpitClient::new(&server).unwrap();
        let login = client.begin_device_code_login().await.unwrap();
        assert_eq!(login.user_code, "ABCD-1234");
        let completed = client
            .complete_device_code_login(login, Some("Devbox".into()), None)
            .await
            .unwrap();
        assert_eq!(completed.instance_id, "inst-1");
        assert_eq!(completed.instance_token, "fci_instance_secret");

        let stored = load_credential().unwrap();
        assert_eq!(stored.account.email, "user@example.test");
        assert_eq!(stored.display_name.as_deref(), Some("Devbox"));

        let seen = requests.lock().await;
        assert_eq!(seen.len(), 4);
        assert!(seen[0].starts_with("POST /api/auth/device/code "));
        assert!(seen[1].contains("/api/auth/device/token"));
        assert!(seen[2].contains("/api/auth/device/token"));
        assert!(seen[3].contains("POST /rpc/instances/register "));
        let register_request = seen[3].to_ascii_lowercase();
        assert!(register_request.contains("authorization: bearer session-token"));
        assert!(seen[3].contains("\"displayName\":\"Devbox\""));
    }

    #[tokio::test]
    async fn logout_clear_preserves_unrelated_credentials() {
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
        let mut store = CredentialStore::open_default().unwrap();
        store.set_api_key("other", "keep");
        store.set(
            CREDENTIAL_KEY,
            json!({
                "server_url":"http://localhost:3000",
                "instance_id":"inst",
                "instance_token":"fci_secret",
                "account":{"user_id":"u","email":"u@example.test"}
            }),
        );
        store.save().unwrap();

        clear_credential().unwrap();
        let store = CredentialStore::open_default().unwrap();
        assert!(store.get(CREDENTIAL_KEY).is_none());
        assert_eq!(store.api_key("other").as_deref(), Some("keep"));
    }

    async fn start_test_server(
        responses: Vec<(u16, &'static str)>,
    ) -> (String, std::sync::Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let request_log = requests.clone();
        let responses = std::sync::Arc::new(Mutex::new(VecDeque::from(responses)));
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let request_log = request_log.clone();
                let responses = responses.clone();
                tokio::spawn(async move {
                    let request = read_request(&mut stream).await;
                    request_log.lock().await.push(request);
                    let (status, body) = responses
                        .lock()
                        .await
                        .pop_front()
                        .unwrap_or_else(|| response(500, r#"{"error":"unexpected"}"#));
                    let status_text = if status == 200 { "OK" } else { "ERROR" };
                    let raw = format!(
                        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(raw.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        (format!("http://{addr}"), requests)
    }

    fn response(status: u16, body: &'static str) -> (u16, &'static str) {
        (status, body)
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut tmp = [0_u8; 1024];
        loop {
            let n = stream.read(&mut tmp).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(header_end) = find_subsequence(&buf, b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&buf[..header_end + 4]).to_string();
                let content_len = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .or_else(|| line.strip_prefix("Content-Length:"))
                            .and_then(|s| s.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + 4 + content_len {
                    let n = stream.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                break;
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }
}
