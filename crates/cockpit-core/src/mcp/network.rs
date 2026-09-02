//! Governed general egress for Monty.
//!
//! This policy is intentionally separate from `tools::web`: web search/fetch
//! has fixed vendor destinations, while this is a deny-by-default general
//! network capability. Every dispatch re-reads the durable agent policy,
//! unions it with process-local session grants, scrubs every outbound field,
//! and crosses both generation fences immediately before transport egress.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use futures::StreamExt as _;
use serde_json::Value;

use super::builtin::HostContext;
use crate::db::monty_network::CanonicalNetworkHost;

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
    GrantHost(CanonicalNetworkHost),
    RevokeHost(CanonicalNetworkHost),
    RevokeAllHosts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionNetworkGrantSnapshot {
    pub generation: u64,
    pub hosts: BTreeSet<CanonicalNetworkHost>,
}

#[derive(Debug, Default)]
pub struct SessionNetworkGrants {
    generation: u64,
    hosts: BTreeSet<CanonicalNetworkHost>,
}

impl SessionNetworkGrants {
    pub fn apply(
        &mut self,
        mutation: SessionNetworkMutation,
    ) -> Result<SessionNetworkGrantSnapshot> {
        match mutation {
            SessionNetworkMutation::GrantHost(host) => {
                self.hosts.insert(host);
            }
            SessionNetworkMutation::RevokeHost(host) => {
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

    pub fn fence_allows(&self, expected_generation: u64, host: &CanonicalNetworkHost) -> bool {
        self.generation == expected_generation && self.hosts.contains(host)
    }
}

#[derive(Debug, Clone)]
pub struct EffectiveNetworkPolicy {
    agent_generation: u64,
    session_generation: u64,
    agent_hosts: BTreeSet<CanonicalNetworkHost>,
    session_hosts: BTreeSet<CanonicalNetworkHost>,
    pub requests_enabled: bool,
    pub approval_required: bool,
}

impl EffectiveNetworkPolicy {
    pub fn permits(&self, host: &CanonicalNetworkHost) -> bool {
        self.requests_enabled
            && (self.agent_hosts.contains(host) || self.session_hosts.contains(host))
    }
}

pub async fn effective_policy(host: &HostContext) -> Result<EffectiveNetworkPolicy> {
    let capability = host.effective_network_capability().await?;
    let requests_enabled = capability.requests_enabled();
    let agent = capability.agent_policy;
    let session = capability.session_policy;
    Ok(EffectiveNetworkPolicy {
        agent_generation: agent.generation,
        session_generation: session.generation,
        agent_hosts: agent.hosts,
        session_hosts: session.hosts,
        requests_enabled,
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

fn has_caller_supplied_host_header(headers: &BTreeMap<String, String>) -> bool {
    headers.keys().any(|name| name.eq_ignore_ascii_case("host"))
}

pub async fn dispatch(host: &HostContext, request: GovernedRequest) -> Result<Value> {
    let policy = effective_policy(host).await?;
    ensure!(
        policy.requests_enabled,
        "requests is disabled for this agent"
    );
    // The URL host is the sole destination authority. `reqwest` permits a
    // caller-supplied Host header, which would otherwise route the request to
    // a different virtual host while this policy authorizes only the URL.
    ensure!(
        !has_caller_supplied_host_header(&request.headers),
        "caller-supplied Host header is forbidden for governed requests"
    );
    ensure!(
        request
            .body
            .as_ref()
            .is_none_or(|body| body.len() <= MAX_REQUEST_BODY_BYTES),
        "governed request body exceeds {MAX_REQUEST_BODY_BYTES} bytes"
    );
    let ctx = host
        .native_tool_ctx
        .as_ref()
        .context("governed network requires a live agent context")?;
    // `effective_policy` resolves the execution instance to an immutable
    // installed-agent identity for its preflight. Re-resolve under the final
    // durable fence so a profile rebinding cannot carry a prior installation's
    // grant across the actual transport boundary.
    let agent_instance_id = ctx
        .agent_instance_id
        .context("governed network requires a daemon-owned agent instance")?;
    let mut request = request.redact_fully(&ctx.redact)?;
    ensure!(
        request.visited_fields == request.expected_fields,
        "governed request redaction proof is incomplete"
    );
    ensure!(
        !has_caller_supplied_host_header(&request.headers),
        "redacted governed request contains a forbidden Host header"
    );
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .context("invalid governed request method")?;
    request.method = method.as_str().to_string();
    let url = reqwest::Url::parse(&request.url).context("invalid governed request URL")?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "only http and https are allowed"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "URL userinfo is forbidden"
    );
    request.url = url.to_string();
    let mut canonical_headers = BTreeMap::new();
    for (name, value) in &request.headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())?;
        let value = reqwest::header::HeaderValue::from_str(value)?;
        ensure!(
            canonical_headers
                .insert(name.as_str().to_string(), value.to_str()?.to_string())
                .is_none(),
            "duplicate governed request header after canonicalization"
        );
    }
    request.headers = canonical_headers;
    let destination =
        CanonicalNetworkHost::parse(url.host_str().context("governed request URL has no host")?)?;
    ensure!(
        policy.permits(&destination),
        "network host `{destination}` is not user-granted"
    );

    let approval_input = serde_json::json!({
        "method": &request.method,
        "url": &request.url,
        "headers": &request.headers,
        "body": &request.body,
        "destination": &destination,
    });
    if policy.approval_required {
        let approver = ctx
            .approver
            .as_ref()
            .context("network policy requires approval but no approver is attached")?;
        let label = format!("Monty {} request to {destination}", request.method);
        ensure!(
            approver
                .approve_monty_network_egress(&label, &approval_input)
                .await?
                .is_allowed(),
            "network request was not approved"
        );
    }

    let client = reqwest::Client::builder()
        .no_proxy()
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
    // Acquire fences in a single global order: durable policy first, then
    // session policy. Durable mutations take the Db write side before their
    // SQLite transaction; session mutations take the Session write side
    // before touching the grant mutex. Retain both permits through `send` so
    // a completed revocation is ordered after this actual egress, never just
    // after a preflight check.
    let response = {
        let _durable_egress_permit = ctx.session.db.monty_network_egress_permit().await;
        let current_installation_id = ctx
            .session
            .db
            .monty_network_installation_id_for_agent_instance(ctx.session.id, agent_instance_id)
            .await?;
        let current_agent_policy = ctx
            .session
            .db
            .monty_network_installation_policy(current_installation_id)
            .await?;
        let _session_egress_permit = ctx.session.monty_network_egress_permit().await;
        let current_session_policy = ctx.session.monty_session_network_grant_snapshot();
        ensure!(
            current_installation_id == policy.installation_id
                && current_agent_policy.generation == policy.agent_generation
                && current_session_policy.generation == policy.session_generation
                && current_agent_policy.requests_enabled
                && (current_agent_policy.hosts.contains(&destination)
                    || current_session_policy.hosts.contains(&destination)),
            "network grant changed before dispatch; request refused"
        );
        crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
            "monty_network_egress",
            &[serde_json::json!({"execute": {"wire_input": approval_input}})],
        )
        .await
        .context("network request approval became stale")?;
        builder
            .send()
            .await
            .context("governed network request failed")?
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_grants_are_deny_by_default_and_generation_fenced() {
        let mut grants = SessionNetworkGrants::default();
        let host = CanonicalNetworkHost::parse("api.example.test").unwrap();
        let initial = grants.snapshot();
        assert!(initial.hosts.is_empty());
        assert!(!grants.fence_allows(initial.generation, &host));

        let granted = grants
            .apply(SessionNetworkMutation::GrantHost(host.clone()))
            .unwrap();
        assert!(grants.fence_allows(granted.generation, &host));

        let revoked = grants
            .apply(SessionNetworkMutation::RevokeHost(host.clone()))
            .unwrap();
        assert!(!grants.fence_allows(granted.generation, &host));
        assert!(!grants.fence_allows(revoked.generation, &host));
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
        .unwrap()
        .with_forced_sealed_literal(
            "sealed-network-secret".to_string(),
            crate::sealed::identity::SealedRedactionIdentity {
                scope: crate::sealed::identity::SealedScopeKind::Session,
                record_id: None,
                name: crate::sealed::identity::SealedName::canonical("network_token").unwrap(),
                version: 0,
            },
        )
        .unwrap();
        let request = GovernedRequest {
            method: "POST".to_string(),
            url: "https://api.example.test/path?q=network-secret".to_string(),
            headers: BTreeMap::from([(
                "authorization".to_string(),
                "Bearer network-secret".to_string(),
            )]),
            body: Some(
                "{\"token\":\"network-secret\",\"sealed\":\"sealed-network-secret\"}".to_string(),
            ),
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
        let body = visited.body.unwrap();
        assert!(!body.contains("network-secret"));
        assert!(!body.contains("sealed-network-secret"));
    }

    #[test]
    fn caller_host_header_is_rejected_case_insensitively() {
        for name in ["Host", "host", "HOST", "hOsT"] {
            let headers = BTreeMap::from([(name.to_string(), "other.example.test".to_string())]);
            assert!(
                has_caller_supplied_host_header(&headers),
                "{name} must not override the URL-authorized destination"
            );
        }
        let headers = BTreeMap::from([("x-forwarded-host".to_string(), "opaque".to_string())]);
        assert!(!has_caller_supplied_host_header(&headers));
    }

    #[test]
    fn outbound_redaction_fails_closed_when_enforced_view_cannot_be_built() {
        let table = crate::redact::RedactionTable::empty().with_forced_enforced_view_failure();
        let request = GovernedRequest {
            method: "POST".to_string(),
            url: "https://api.example.test/path".to_string(),
            headers: BTreeMap::new(),
            body: Some("must-not-leave".to_string()),
        };

        let error = request.redact_fully(&table).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("constructing fail-closed Monty egress redaction view"),
            "{error:#}"
        );
    }

    #[test]
    fn canonical_host_validation_rejects_url_shaped_grants() {
        assert!(CanonicalNetworkHost::parse("api.example.test").is_ok());
        assert!(CanonicalNetworkHost::parse("https://api.example.test").is_err());
        assert!(CanonicalNetworkHost::parse("API.example.test").is_err());
        assert!(CanonicalNetworkHost::parse("api.example.test:443").is_err());
    }
}
