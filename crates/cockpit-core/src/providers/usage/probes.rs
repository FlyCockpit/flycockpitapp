use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Url;
use serde_json::Value;

use crate::config::providers::{
    ProviderEntry, ProvidersConfig, UsageProbeFieldKind, UsageProbeMethod, UsageProbeSpec,
};
use crate::providers::ProviderRegistry;
use crate::providers::models_fetch;

use super::{ProviderUsageSnapshot, UsageAvailability, UsageWindow};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const GROK_USAGE_HINT: &str = "https://grok.com/?_s=usage";
const GROK_USAGE_REASON: &str = "xAI does not expose a subscription usage API. Standalone SuperGrok accounts may use OAuth inference; X Premium+ does not include xAI API access. Check usage in the Grok portal.";

#[async_trait]
pub trait ProviderUsageProbe: Send + Sync {
    async fn fetch(&self, provider_id: &str, entry: &ProviderEntry) -> ProviderUsageSnapshot;
}

pub async fn fetch_all_provider_usage(
    config: &ProvidersConfig,
    provider_filter: Option<&str>,
) -> Result<Vec<ProviderUsageSnapshot>> {
    fetch_all_provider_usage_with_store(config, provider_filter, None, std::env::vars().collect())
        .await
}

pub async fn fetch_all_provider_usage_with_store(
    config: &ProvidersConfig,
    provider_filter: Option<&str>,
    store: Option<crate::credentials::CredentialStore>,
    env: std::collections::HashMap<String, String>,
) -> Result<Vec<ProviderUsageSnapshot>> {
    fetch_all_provider_usage_with_registry_and_store(
        config,
        provider_filter,
        ProviderRegistry::standard(),
        store,
        env,
    )
    .await
}

pub async fn fetch_all_provider_usage_with_registry(
    config: &ProvidersConfig,
    provider_filter: Option<&str>,
    registry: ProviderRegistry,
) -> Result<Vec<ProviderUsageSnapshot>> {
    fetch_all_provider_usage_with_registry_and_store(
        config,
        provider_filter,
        registry,
        None,
        std::env::vars().collect(),
    )
    .await
}

async fn fetch_all_provider_usage_with_registry_and_store(
    config: &ProvidersConfig,
    provider_filter: Option<&str>,
    registry: ProviderRegistry,
    store: Option<crate::credentials::CredentialStore>,
    env: std::collections::HashMap<String, String>,
) -> Result<Vec<ProviderUsageSnapshot>> {
    let providers: Vec<(String, ProviderEntry)> = if let Some(filter) = provider_filter {
        let Some((id, entry)) = config.providers.get_key_value(filter) else {
            let known = config
                .providers
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let suffix = if known.is_empty() {
                "no providers are configured".to_string()
            } else {
                format!("configured providers: {known}")
            };
            anyhow::bail!("no configured provider with id `{filter}` ({suffix})");
        };
        vec![(id.clone(), entry.clone())]
    } else {
        config
            .providers
            .iter()
            .map(|(id, entry)| (id.clone(), entry.clone()))
            .collect()
    };

    let mut pending = FuturesUnordered::new();
    for (provider_id, entry) in providers {
        let registry = registry.clone();
        let store = store.clone();
        let env = env.clone();
        pending.push(async move {
            let usage = async {
                if let Some(spec) = resolved_usage_probe_spec(&entry) {
                    DeclarativeUsageProbe::new(spec)
                        .fetch_with_store(&provider_id, &entry, store, env)
                        .await
                } else if registry.provider_for(&provider_id, &entry).id()
                    == crate::auth::codex_oauth::CREDENTIAL_KEY
                {
                    match fetch_codex_usage_with_store(&provider_id, &entry, store, env).await {
                        Ok((plan, windows, details)) => fetched_snapshot(
                            &provider_id,
                            &entry,
                            "oauth_usage_api",
                            plan,
                            windows,
                            details,
                        ),
                        Err(e) => error_snapshot(
                            &provider_id,
                            &entry,
                            &format!(
                                "{} Run Codex subscription login in `/settings` -> Providers.",
                                e
                            ),
                        ),
                    }
                } else if let Some(probe) =
                    registry.provider_for(&provider_id, &entry).usage_probe()
                {
                    probe.fetch(&provider_id, &entry).await
                } else {
                    unsupported_snapshot(&provider_id, &entry)
                }
            };
            match tokio::time::timeout(DEFAULT_TIMEOUT, usage).await {
                Ok(snapshot) => snapshot,
                Err(_) => error_snapshot(&provider_id, &entry, "usage probe timed out after 10s"),
            }
        });
    }

    let mut out = Vec::new();
    while let Some(snapshot) = pending.next().await {
        out.push(snapshot);
    }
    out.sort_by(|a, b| a.provider_id.cmp(&b.provider_id));
    Ok(out)
}

/// Resolve an entry-level usage probe first, then inherit the built-in
/// template default. Template identity is persisted separately from the
/// editable provider id, so renamed built-in providers retain their probe.
fn resolved_usage_probe_spec(entry: &ProviderEntry) -> Option<UsageProbeSpec> {
    entry.usage_probe.clone().or_else(|| {
        entry
            .template
            .as_deref()
            .and_then(crate::providers::template_by_id)
            .and_then(|template| template.usage_probe.cloned())
    })
}

/// Generic JSON usage endpoint probe for API-key and simple OAuth-backed
/// providers. It deliberately reuses the fully resolved inference headers,
/// avoiding a second credential configuration surface.
pub struct DeclarativeUsageProbe {
    spec: UsageProbeSpec,
}

impl DeclarativeUsageProbe {
    pub fn new(spec: UsageProbeSpec) -> Self {
        Self { spec }
    }

    async fn fetch_with_store(
        &self,
        provider_id: &str,
        entry: &ProviderEntry,
        store: Option<crate::credentials::CredentialStore>,
        env: std::collections::HashMap<String, String>,
    ) -> ProviderUsageSnapshot {
        match self
            .fetch_result_with_store(provider_id, entry, store, env)
            .await
        {
            Ok((windows, details)) => fetched_snapshot(
                provider_id,
                entry,
                "declarative_usage_api",
                None,
                windows,
                details,
            ),
            Err(error) => error_snapshot(provider_id, entry, &error.to_string()),
        }
    }

    async fn fetch_result_with_store(
        &self,
        provider_id: &str,
        entry: &ProviderEntry,
        store: Option<crate::credentials::CredentialStore>,
        env: std::collections::HashMap<String, String>,
    ) -> Result<(Vec<UsageWindow>, Vec<String>)> {
        let resolved = match store {
            Some(store) => {
                models_fetch::resolve_provider_request_async_with_store(
                    provider_id,
                    entry,
                    store,
                    |name| env.get(name).cloned(),
                )
                .await?
            }
            None => models_fetch::resolve_provider_request_async(provider_id, entry).await?,
        };
        let url = resolve_usage_endpoint(&self.spec.endpoint, &resolved.base_url)?;
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()?;
        let mut request = (match self.spec.method {
            UsageProbeMethod::Get => client.get(&url),
        })
        .header(reqwest::header::ACCEPT, "application/json");
        for header in &resolved.headers {
            request = request.header(&header.name, &header.value);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("fetching declarative usage endpoint {url}"))?;
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("usage API returned {status}");
        }
        let body = response
            .json::<Value>()
            .await
            .context("parsing declarative usage JSON")?;
        extract_usage_fields(&body, &self.spec)
    }
}

#[async_trait]
impl ProviderUsageProbe for DeclarativeUsageProbe {
    async fn fetch(&self, provider_id: &str, entry: &ProviderEntry) -> ProviderUsageSnapshot {
        self.fetch_with_store(provider_id, entry, None, std::env::vars().collect())
            .await
    }
}

fn resolve_usage_endpoint(endpoint: &str, provider_base_url: &str) -> Result<String> {
    let endpoint = endpoint.trim();
    let url = if endpoint.starts_with('/') {
        if endpoint.starts_with("//") {
            anyhow::bail!("usage probe endpoint path must not replace the provider origin");
        }
        let provider_url = Url::parse(provider_base_url)
            .with_context(|| format!("parsing provider URL {provider_base_url}"))?;
        let origin = provider_url.origin().ascii_serialization();
        if origin == "null" {
            anyhow::bail!("provider URL has no HTTP origin for usage probe");
        }
        Url::parse(&origin)?.join(endpoint)?
    } else {
        Url::parse(endpoint).with_context(|| {
            format!("usage probe endpoint must be an absolute URL or root path: {endpoint}")
        })?
    };
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("usage probe endpoint must use HTTP or HTTPS");
    }
    Ok(url.to_string())
}

fn extract_usage_fields(
    body: &Value,
    spec: &UsageProbeSpec,
) -> Result<(Vec<UsageWindow>, Vec<String>)> {
    let mut windows = Vec::new();
    let mut details = Vec::new();
    for field in spec.fields.iter() {
        let value = body.pointer(&field.pointer).ok_or_else(|| {
            anyhow::anyhow!(
                "usage response missing field at JSON Pointer `{}`",
                field.pointer
            )
        })?;
        match field.kind {
            UsageProbeFieldKind::Credits => {
                details.push(format!("{}: {}", field.label, compact_json(value)));
            }
            UsageProbeFieldKind::RequestsRemaining => {
                let rendered = if value.is_null() {
                    "pay-as-you-go".to_string()
                } else {
                    compact_json(value)
                };
                details.push(format!("{}: {rendered}", field.label));
            }
            UsageProbeFieldKind::Percent => {
                let used_percent = value.as_f64().ok_or_else(|| {
                    anyhow::anyhow!(
                        "usage response field `{}` must be a numeric percent",
                        field.pointer
                    )
                })?;
                windows.push(UsageWindow {
                    label: field.label.to_string(),
                    used_percent: Some(used_percent),
                    reset_at: None,
                    detail: None,
                });
            }
            UsageProbeFieldKind::Text => {
                details.push(format!("{}: {}", field.label, compact_json(value)));
            }
        }
    }
    Ok((windows, details))
}

pub struct CodexOAuthUsageProbe;

#[async_trait]
impl ProviderUsageProbe for CodexOAuthUsageProbe {
    async fn fetch(&self, provider_id: &str, entry: &ProviderEntry) -> ProviderUsageSnapshot {
        match fetch_codex_usage(provider_id, entry).await {
            Ok((plan, windows, details)) => fetched_snapshot(
                provider_id,
                entry,
                "oauth_usage_api",
                plan,
                windows,
                details,
            ),
            Err(e) => error_snapshot(
                provider_id,
                entry,
                &format!(
                    "{} Run Codex subscription login in `/settings` -> Providers.",
                    e
                ),
            ),
        }
    }
}

async fn fetch_codex_usage(
    provider_id: &str,
    entry: &ProviderEntry,
) -> Result<(Option<String>, Vec<UsageWindow>, Vec<String>)> {
    fetch_codex_usage_with_store(provider_id, entry, None, std::env::vars().collect()).await
}

async fn fetch_codex_usage_with_store(
    provider_id: &str,
    entry: &ProviderEntry,
    store: Option<crate::credentials::CredentialStore>,
    env: std::collections::HashMap<String, String>,
) -> Result<(Option<String>, Vec<UsageWindow>, Vec<String>)> {
    let resolved = match store {
        Some(store) => {
            models_fetch::resolve_provider_request_async_with_store(
                provider_id,
                entry,
                store,
                |name| env.get(name).cloned(),
            )
            .await?
        }
        None => models_fetch::resolve_provider_request_async(provider_id, entry).await?,
    };
    let url = resolve_codex_usage_url(&resolved.base_url);
    let client = reqwest::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .build()?;
    let resp = send_codex_usage_request_with_retries(&client, &url, &resolved.headers).await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Codex usage API returned {status}: {}",
            crate::providers::models_fetch::response_body_snippet(&body)
        );
    }
    let body = resp
        .json::<Value>()
        .await
        .context("parsing Codex usage JSON")?;
    Ok(parse_codex_usage(&body))
}

async fn send_codex_usage_request_with_retries(
    client: &reqwest::Client,
    url: &str,
    headers: &[models_fetch::ResolvedHeader],
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
        for header in headers {
            if header
                .name
                .eq_ignore_ascii_case(reqwest::header::USER_AGENT.as_str())
            {
                continue;
            }
            req = req.header(&header.name, &header.value);
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
            Err(error) => return Err(error).context("fetching Codex usage"),
        }
    }
}

fn resolve_codex_usage_url(base_url: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    if let Some(prefix) = trimmed.strip_suffix("/codex") {
        format!("{prefix}/wham/usage")
    } else {
        format!("{trimmed}/wham/usage")
    }
}

pub fn parse_codex_usage(body: &Value) -> (Option<String>, Vec<UsageWindow>, Vec<String>) {
    let plan = body
        .get("plan_type")
        .or_else(|| body.get("plan"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let mut windows = Vec::new();
    if let Some(rate_limit) = body.get("rate_limit") {
        if let Some(window) = rate_limit.get("primary_window") {
            windows.push(parse_window("Session", window));
        }
        if let Some(window) = rate_limit.get("secondary_window") {
            windows.push(parse_window("Weekly", window));
        }
    }
    let mut details = Vec::new();
    if let Some(credits) = body.get("credits") {
        details.push(format!("credits: {}", compact_json(credits)));
    }
    (plan, windows, details)
}

fn parse_window(label: &str, value: &Value) -> UsageWindow {
    UsageWindow {
        label: value
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or(label)
            .to_string(),
        used_percent: value
            .get("used_percent")
            .or_else(|| value.get("percent_used"))
            .or_else(|| value.get("usage_percent"))
            .and_then(Value::as_f64),
        reset_at: value
            .get("reset_at")
            .or_else(|| value.get("resets_at"))
            .and_then(Value::as_str)
            .and_then(parse_datetime),
        detail: value
            .get("detail")
            .or_else(|| value.get("details"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
    }
}

fn parse_datetime(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn compact_json(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| value.to_string()),
    }
}

pub struct GrokOAuthUsageProbe;

#[async_trait]
impl ProviderUsageProbe for GrokOAuthUsageProbe {
    async fn fetch(&self, provider_id: &str, entry: &ProviderEntry) -> ProviderUsageSnapshot {
        ProviderUsageSnapshot {
            provider_id: provider_id.to_string(),
            display_name: display_name(provider_id, entry),
            fetched_at: Utc::now(),
            availability: UsageAvailability::Unavailable {
                reason: GROK_USAGE_REASON.to_string(),
                hint_url: Some(GROK_USAGE_HINT.to_string()),
            },
        }
    }
}

fn fetched_snapshot(
    provider_id: &str,
    entry: &ProviderEntry,
    source: &'static str,
    plan: Option<String>,
    windows: Vec<UsageWindow>,
    details: Vec<String>,
) -> ProviderUsageSnapshot {
    ProviderUsageSnapshot {
        provider_id: provider_id.to_string(),
        display_name: display_name(provider_id, entry),
        fetched_at: Utc::now(),
        availability: UsageAvailability::Fetched {
            source,
            plan,
            windows,
            details,
        },
    }
}

fn unsupported_snapshot(provider_id: &str, entry: &ProviderEntry) -> ProviderUsageSnapshot {
    ProviderUsageSnapshot {
        provider_id: provider_id.to_string(),
        display_name: display_name(provider_id, entry),
        fetched_at: Utc::now(),
        availability: UsageAvailability::Unsupported {
            reason: "This provider does not expose usage limits via API.",
        },
    }
}

fn error_snapshot(
    provider_id: &str,
    entry: &ProviderEntry,
    message: &str,
) -> ProviderUsageSnapshot {
    ProviderUsageSnapshot {
        provider_id: provider_id.to_string(),
        display_name: display_name(provider_id, entry),
        fetched_at: Utc::now(),
        availability: UsageAvailability::Error {
            message: message.to_string(),
        },
    }
}

fn display_name(provider_id: &str, entry: &ProviderEntry) -> String {
    entry
        .name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(provider_id)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{
        HeaderSpec, ProvidersConfig, UsageProbeField, UsageProbeFieldKind, UsageProbeSpec,
    };
    use crate::providers::registry::Provider;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestUsageResponse {
        status: u16,
        headers: Vec<(&'static str, &'static str)>,
        body: &'static str,
    }

    impl TestUsageResponse {
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

    async fn serve_usage_responses(
        responses: Vec<TestUsageResponse>,
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
        (format!("http://{addr}/usage"), handle)
    }

    fn request_header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
        request.lines().skip(1).find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header
                .trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim())
        })
    }

    fn entry(name: &str) -> ProviderEntry {
        ProviderEntry {
            name: Some(name.to_string()),
            url: "https://example.com/v1".to_string(),
            ..ProviderEntry::default()
        }
    }

    fn declarative_spec(endpoint: &str) -> UsageProbeSpec {
        UsageProbeSpec {
            endpoint: endpoint.to_string().into(),
            method: UsageProbeMethod::Get,
            fields: vec![
                UsageProbeField {
                    pointer: "/credits".into(),
                    label: "credits".into(),
                    kind: UsageProbeFieldKind::Credits,
                },
                UsageProbeField {
                    pointer: "/usable_requests".into(),
                    label: "requests left today".into(),
                    kind: UsageProbeFieldKind::RequestsRemaining,
                },
            ]
            .into(),
        }
    }

    fn declarative_entry(name: &str, usage_url: &str, spec: UsageProbeSpec) -> ProviderEntry {
        let origin = Url::parse(usage_url)
            .unwrap()
            .origin()
            .ascii_serialization();
        ProviderEntry {
            name: Some(name.to_string()),
            url: format!("{origin}/v1"),
            allow_insecure_http: true,
            headers: vec![HeaderSpec {
                name: "Authorization".to_string(),
                value: "Bearer usage-test-key".to_string(),
            }],
            usage_probe: Some(spec),
            ..ProviderEntry::default()
        }
    }

    #[test]
    fn parses_codex_usage_fixture() {
        let body: Value = serde_json::json!({
            "plan_type": "plus",
            "rate_limit": {
                "primary_window": {
                    "used_percent": 40.0,
                    "reset_at": "2026-06-12T00:00:00Z",
                    "detail": "session cap"
                },
                "secondary_window": {
                    "percent_used": 10.0,
                    "resets_at": "2026-06-18T00:00:00Z"
                }
            },
            "credits": {"remaining": 12}
        });
        let (plan, windows, details) = parse_codex_usage(&body);
        assert_eq!(plan.as_deref(), Some("plus"));
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].label, "Session");
        assert_eq!(windows[0].used_percent, Some(40.0));
        assert_eq!(windows[1].label, "Weekly");
        assert_eq!(windows[1].used_percent, Some(10.0));
        assert_eq!(details, vec!["credits: {\"remaining\":12}"]);
    }

    #[tokio::test]
    async fn grok_oauth_returns_unavailable_without_http() {
        let probe = GrokOAuthUsageProbe;
        let snap = probe.fetch("grok-oauth", &entry("Grok")).await;
        match snap.availability {
            UsageAvailability::Unavailable { reason, hint_url } => {
                assert!(reason.contains("xAI does not expose"));
                assert_eq!(hint_url.as_deref(), Some(GROK_USAGE_HINT));
            }
            other => panic!("unexpected availability: {other:?}"),
        }
    }

    #[tokio::test]
    async fn usage_probe_retries_retry_after_rate_limit_then_succeeds() {
        let (url, handle) = serve_usage_responses(vec![
            TestUsageResponse::status(429, r#"{"error":"slow"}"#).with_header("Retry-After", "0"),
            TestUsageResponse::ok(r#"{"plan_type":"plus"}"#),
        ])
        .await;
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .unwrap();
        let resp = send_codex_usage_request_with_retries(&client, &url, &[])
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(handle.await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn usage_probe_retries_bounded_5xx_then_returns_final_response() {
        let (url, handle) = serve_usage_responses(vec![
            TestUsageResponse::status(502, r#"{"error":"bad gateway 1"}"#)
                .with_header("Retry-After", "0"),
            TestUsageResponse::status(503, r#"{"error":"bad gateway 2"}"#)
                .with_header("Retry-After", "0"),
            TestUsageResponse::status(504, r#"{"error":"bad gateway 3"}"#),
        ])
        .await;
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .unwrap();
        let resp = send_codex_usage_request_with_retries(&client, &url, &[])
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(handle.await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn declarative_probe_fetches_subscription_credits_and_requests_from_origin_path() {
        let (usage_url, handle) = serve_usage_responses(vec![TestUsageResponse::ok(
            r#"{"credits":12.5,"usable_requests":42}"#,
        )])
        .await;
        let entry = declarative_entry("Custom usage", &usage_url, declarative_spec("/usage"));
        let mut providers = BTreeMap::new();
        providers.insert("custom-usage".to_string(), entry);
        let config = ProvidersConfig {
            providers,
            ..ProvidersConfig::default()
        };

        let snapshots = fetch_all_provider_usage_with_registry(
            &config,
            None,
            ProviderRegistry::new(Vec::new()),
        )
        .await
        .unwrap();

        match &snapshots[0].availability {
            UsageAvailability::Fetched {
                source, details, ..
            } => {
                assert_eq!(*source, "declarative_usage_api");
                assert_eq!(
                    details,
                    &vec![
                        "credits: 12.5".to_string(),
                        "requests left today: 42".to_string()
                    ]
                );
            }
            other => panic!("unexpected availability: {other:?}"),
        }
        let requests = handle.await.unwrap();
        assert!(requests[0].starts_with("GET /usage HTTP/1.1"));
        assert_eq!(
            request_header_value(&requests[0], "authorization"),
            Some("Bearer usage-test-key")
        );
    }

    #[tokio::test]
    async fn declarative_probe_renders_null_requests_as_pay_as_you_go() {
        let (usage_url, _handle) = serve_usage_responses(vec![TestUsageResponse::ok(
            r#"{"credits":3,"usable_requests":null}"#,
        )])
        .await;
        let entry = declarative_entry("PAYG", &usage_url, declarative_spec("/usage"));
        let snapshot = DeclarativeUsageProbe::new(declarative_spec("/usage"))
            .fetch("payg", &entry)
            .await;

        match snapshot.availability {
            UsageAvailability::Fetched { details, .. } => {
                assert_eq!(
                    details,
                    vec!["credits: 3", "requests left today: pay-as-you-go"]
                );
            }
            other => panic!("unexpected availability: {other:?}"),
        }
    }

    #[tokio::test]
    async fn declarative_probe_surfaces_http_errors() {
        let (usage_url, _handle) = serve_usage_responses(vec![TestUsageResponse::status(
            401,
            r#"{"error":"unauthorized"}"#,
        )])
        .await;
        let entry = declarative_entry("Unauthorized", &usage_url, declarative_spec("/usage"));
        let snapshot = DeclarativeUsageProbe::new(declarative_spec("/usage"))
            .fetch("unauthorized", &entry)
            .await;

        match snapshot.availability {
            UsageAvailability::Error { message } => {
                assert!(message.contains("usage API returned 401"));
            }
            other => panic!("unexpected availability: {other:?}"),
        }
    }

    #[test]
    fn template_usage_probe_is_inherited_when_the_entry_has_no_override() {
        let entry = ProviderEntry {
            template: Some("crofai".to_string()),
            ..ProviderEntry::default()
        };
        let spec = resolved_usage_probe_spec(&entry).expect("CrofAI usage probe");
        assert_eq!(spec.endpoint, "/usage_api/");
        assert_eq!(spec.fields.len(), 2);
    }

    #[tokio::test]
    async fn default_unknown_provider_is_unsupported() {
        let registry = ProviderRegistry::new(Vec::new());
        let entry = entry("Anthropic");
        let snap = if let Some(probe) = registry.provider_for("anthropic", &entry).usage_probe() {
            probe.fetch("anthropic", &entry).await
        } else {
            unsupported_snapshot("anthropic", &entry)
        };
        assert!(matches!(
            snap.availability,
            UsageAvailability::Unsupported { .. }
        ));
    }

    struct CountingProvider {
        id: &'static str,
        probe: CountingProbe,
    }

    impl Provider for CountingProvider {
        fn id(&self) -> &'static str {
            self.id
        }

        fn matches(&self, provider_id: &str, _entry: &ProviderEntry) -> bool {
            provider_id == self.id
        }

        fn usage_probe(&self) -> Option<&dyn ProviderUsageProbe> {
            Some(&self.probe)
        }
    }

    struct CountingProbe {
        label: &'static str,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ProviderUsageProbe for CountingProbe {
        async fn fetch(&self, provider_id: &str, entry: &ProviderEntry) -> ProviderUsageSnapshot {
            self.calls.fetch_add(1, Ordering::SeqCst);
            fetched_snapshot(provider_id, entry, self.label, None, Vec::new(), Vec::new())
        }
    }

    #[tokio::test]
    async fn registry_matching_provider_exposes_usage_probe() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = ProviderRegistry::new(vec![Arc::new(CountingProvider {
            id: "p",
            probe: CountingProbe {
                label: "usage",
                calls: calls.clone(),
            },
        })]);
        let entry = entry("P");
        let snap = registry
            .provider_for("p", &entry)
            .usage_probe()
            .unwrap()
            .fetch("p", &entry)
            .await;
        assert!(matches!(
            snap.availability,
            UsageAvailability::Fetched {
                source: "usage",
                ..
            }
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    struct SlowProvider;

    impl Provider for SlowProvider {
        fn id(&self) -> &'static str {
            "slow"
        }

        fn matches(&self, provider_id: &str, _entry: &ProviderEntry) -> bool {
            provider_id == "slow"
        }

        fn usage_probe(&self) -> Option<&dyn ProviderUsageProbe> {
            Some(self)
        }
    }

    #[async_trait]
    impl ProviderUsageProbe for SlowProvider {
        async fn fetch(&self, provider_id: &str, entry: &ProviderEntry) -> ProviderUsageSnapshot {
            tokio::time::sleep(Duration::from_secs(11)).await;
            unsupported_snapshot(provider_id, entry)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_turns_one_provider_into_error_while_others_complete() {
        let mut providers = BTreeMap::new();
        providers.insert("slow".to_string(), entry("Slow"));
        providers.insert("other".to_string(), entry("Other"));
        let cfg = ProvidersConfig {
            providers,
            ..ProvidersConfig::default()
        };
        let registry = ProviderRegistry::new(vec![Arc::new(SlowProvider)]);
        let rows = fetch_all_provider_usage_with_registry(&cfg, None, registry)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|row| matches!(
            row.availability,
            UsageAvailability::Error { ref message } if message.contains("timed out")
        )));
        assert!(
            rows.iter()
                .any(|row| matches!(row.availability, UsageAvailability::Unsupported { .. }))
        );
    }
}
