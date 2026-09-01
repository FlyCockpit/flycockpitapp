//! Governed general egress for Monty.
//!
//! This policy is intentionally separate from `tools::web`: web search/fetch
//! has fixed vendor destinations, while this is a deny-by-default general
//! network capability. Every dispatch re-reads the durable agent policy,
//! unions it with process-local session grants, scrubs every outbound field,
//! and crosses both generation fences immediately before transport egress.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use futures::StreamExt as _;
use serde_json::Value;

use super::builtin::HostContext;

pub const SAFE_STDLIB_PACKAGES: &[&str] = &[
    "json",
    "csv",
    "re",
    "datetime",
    "math",
    "statistics",
    "textwrap",
    "base64",
    "hashlib",
];

const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionNetworkMutation {
    GrantHost(String),
    RevokeHost(String),
    RevokeAllHosts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionNetworkGrantSnapshot {
    pub generation: u64,
    pub hosts: BTreeSet<String>,
}

#[derive(Debug, Default)]
pub struct SessionNetworkGrants {
    generation: u64,
    hosts: BTreeSet<String>,
}

impl SessionNetworkGrants {
    pub fn apply(
        &mut self,
        mutation: SessionNetworkMutation,
    ) -> Result<SessionNetworkGrantSnapshot> {
        match mutation {
            SessionNetworkMutation::GrantHost(host) => {
                validate_canonical_host(&host)?;
                self.hosts.insert(host);
            }
            SessionNetworkMutation::RevokeHost(host) => {
                validate_canonical_host(&host)?;
                self.hosts.remove(&host);
            }
            SessionNetworkMutation::RevokeAllHosts => self.hosts.clear(),
        }
        self.generation = self
            .generation
            .checked_add(1)
            .context("Monty session network generation overflow")?;
        Ok(self.snapshot())
    }

    pub fn snapshot(&self) -> SessionNetworkGrantSnapshot {
        SessionNetworkGrantSnapshot {
            generation: self.generation,
            hosts: self.hosts.clone(),
        }
    }

    pub fn fence_allows(&self, expected_generation: u64, host: &str) -> bool {
        self.generation == expected_generation && self.hosts.contains(host)
    }
}

#[derive(Debug, Clone)]
pub struct EffectiveNetworkPolicy {
    agent_generation: u64,
    session_generation: u64,
    agent_hosts: BTreeSet<String>,
    session_hosts: BTreeSet<String>,
    pub requests_enabled: bool,
    pub approval_required: bool,
}

impl EffectiveNetworkPolicy {
    pub fn permits(&self, host: &str) -> bool {
        self.requests_enabled
            && (self.agent_hosts.contains(host) || self.session_hosts.contains(host))
    }
}

pub async fn effective_policy(host: &HostContext) -> Result<EffectiveNetworkPolicy> {
    if let Some(denial) = host.builtin_registry.monty_network_denial() {
        bail!("{}", denial["message"].as_str().unwrap_or("fork network capability denied"));
    }
    let ctx = host
        .native_tool_ctx
        .as_ref()
        .context("governed network requires a live agent context")?;
    let agent = ctx
        .session
        .db
        .monty_network_agent_policy(&ctx.agent_id)
        .await?;
    let session = ctx.session.monty_session_network_grant_snapshot();
    Ok(EffectiveNetworkPolicy {
        agent_generation: agent.generation,
        session_generation: session.generation,
        agent_hosts: agent.hosts,
        session_hosts: session.hosts,
        requests_enabled: agent.requests_enabled,
        approval_required: agent.approval_required,
    })
}

#[derive(Debug, Clone)]
pub struct GovernedRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug)]
struct VisitedRequest {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: Option<String>,
    visited_fields: usize,
    expected_fields: usize,
}

impl GovernedRequest {
    fn redact_fully(&self, table: &crate::redact::RedactionTable) -> Result<VisitedRequest> {
        let table = table
            .enforced_checked()
            .context("constructing fail-closed Monty egress redaction view")?;
        let expected_fields = 2 + self.headers.len() * 2 + usize::from(self.body.is_some());
        let mut visited_fields = 0;
        let mut visit = |value: &str| {
            visited_fields += 1;
            table.scrub(value)
        };
        let method = visit(&self.method);
        let url = visit(&self.url);
        let headers = self
            .headers
            .iter()
            .map(|(name, value)| (visit(name), visit(value)))
            .collect();
        let body = self.body.as_deref().map(&mut visit);
        ensure!(
            visited_fields == expected_fields,
            "Monty egress redaction visitor did not prove complete coverage"
        );
        Ok(VisitedRequest {
            method,
            url,
            headers,
            body,
            visited_fields,
            expected_fields,
        })
    }
}

pub async fn dispatch(host: &HostContext, request: GovernedRequest) -> Result<Value> {
    let policy = effective_policy(host).await?;
    ensure!(policy.requests_enabled, "requests is disabled for this agent");
    ensure!(
        request.body.as_ref().is_none_or(|body| body.len() <= MAX_REQUEST_BODY_BYTES),
        "governed request body exceeds {MAX_REQUEST_BODY_BYTES} bytes"
    );
    let ctx = host
        .native_tool_ctx
        .as_ref()
        .context("governed network requires a live agent context")?;
    let request = request.redact_fully(&ctx.redact)?;
    ensure!(
        request.visited_fields == request.expected_fields,
        "governed request redaction proof is incomplete"
    );
    let url = reqwest::Url::parse(&request.url).context("invalid governed request URL")?;
    ensure!(matches!(url.scheme(), "http" | "https"), "only http and https are allowed");
    ensure!(url.username().is_empty() && url.password().is_none(), "URL userinfo is forbidden");
    let destination = url
        .host_str()
        .context("governed request URL has no host")?
        .to_ascii_lowercase();
    ensure!(policy.permits(&destination), "network host `{destination}` is not user-granted");

    if policy.approval_required {
        let approver = ctx
            .approver
            .as_ref()
            .context("network policy requires approval but no approver is attached")?;
        let label = format!("Monty {} request to {destination}", request.method);
        ensure!(
            approver.approve_tool_call(&label).await?.is_accept(),
            "network request was not approved"
        );
    }

    let agent_fence = ctx
        .session
        .db
        .monty_network_agent_fence_is_current(&ctx.agent_id, policy.agent_generation)
        .await?;
    let session_fence = ctx
        .session
        .monty_session_network_fence_allows(policy.session_generation, &destination);
    ensure!(
        agent_fence && (policy.agent_hosts.contains(&destination) || session_fence),
        "network grant changed before dispatch; request refused"
    );

    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .context("invalid governed request method")?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut builder = client.request(method, url);
    for (name, value) in request.headers {
        builder = builder.header(
            reqwest::header::HeaderName::from_bytes(name.as_bytes())?,
            reqwest::header::HeaderValue::from_str(&value)?,
        );
    }
    if let Some(body) = request.body {
        builder = builder.body(body);
    }
    let response = builder.send().await.context("governed network request failed")?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("[non-UTF-8]").to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= MAX_RESPONSE_BODY_BYTES as u64),
        "network response exceeds {MAX_RESPONSE_BODY_BYTES} bytes"
    );
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_RESPONSE_BODY_BYTES,
            "network response exceeds {MAX_RESPONSE_BODY_BYTES} bytes"
        );
        bytes.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok(serde_json::json!({
        "status_code": status,
        "ok": (200..400).contains(&status),
        "headers": headers,
        "text": text,
    }))
}

fn validate_canonical_host(host: &str) -> Result<()> {
    if host.is_empty()
        || host.len() > 253
        || host != host.to_ascii_lowercase()
        || host
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '/' | '?' | '#' | '@'))
    {
        bail!("network grant host is not canonical");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_grants_are_deny_by_default_and_generation_fenced() {
        let mut grants = SessionNetworkGrants::default();
        let initial = grants.snapshot();
        assert!(initial.hosts.is_empty());
        assert!(!grants.fence_allows(initial.generation, "api.example.test"));

        let granted = grants
            .apply(SessionNetworkMutation::GrantHost(
                "api.example.test".to_string(),
            ))
            .unwrap();
        assert!(grants.fence_allows(granted.generation, "api.example.test"));

        let revoked = grants
            .apply(SessionNetworkMutation::RevokeHost(
                "api.example.test".to_string(),
            ))
            .unwrap();
        assert!(!grants.fence_allows(granted.generation, "api.example.test"));
        assert!(!grants.fence_allows(revoked.generation, "api.example.test"));
    }

    #[test]
    fn outbound_redaction_visits_url_headers_and_body() {
        let cfg = crate::config::extended::RedactConfig {
            enabled: false,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 4,
            placeholder: "[redacted]".to_string(),
            ..Default::default()
        };
        let table = crate::redact::RedactionTable::build_with_env_and_secrets(
            &cfg,
            std::path::Path::new("."),
            &std::collections::HashMap::from([(
                "API_TOKEN".to_string(),
                "network-secret".to_string(),
            )]),
            Vec::<(String, String)>::new(),
        )
        .unwrap();
        let request = GovernedRequest {
            method: "POST".to_string(),
            url: "https://api.example.test/path?q=network-secret".to_string(),
            headers: BTreeMap::from([(
                "authorization".to_string(),
                "Bearer network-secret".to_string(),
            )]),
            body: Some("{\"token\":\"network-secret\"}".to_string()),
        };
        let visited = request.redact_fully(&table).unwrap();
        assert_eq!(visited.visited_fields, visited.expected_fields);
        assert!(!visited.url.contains("network-secret"));
        assert!(
            visited
                .headers
                .values()
                .all(|value| !value.contains("network-secret"))
        );
        assert!(!visited.body.unwrap().contains("network-secret"));
    }

    #[test]
    fn canonical_host_validation_rejects_url_shaped_grants() {
        assert!(validate_canonical_host("api.example.test").is_ok());
        assert!(validate_canonical_host("https://api.example.test").is_err());
        assert!(validate_canonical_host("API.example.test").is_err());
    }
}
