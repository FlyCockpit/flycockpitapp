//! The HTTPS sealed-action executor.
//!
//! An [`HttpsSealedAction`] is compiled from a persisted [`SealedActionSnapshot`]
//! and an injected [`HttpsTransport`]. Its [`SealedHostAction::invoke`] performs
//! exactly one outbound HTTPS request built ONLY from the compiled snapshot:
//!
//! * the origin comes from the snapshot's validated allowlist (never a caller
//!   projection or origin rewrite — AC10), and is re-parsed through
//!   [`HttpsOrigin::parse`] on every call so an `http`, wildcard, IP-literal, or
//!   scheme-relative (`//host`) origin fails closed BEFORE the transport is
//!   invoked (findings 4/5, AC6);
//! * the request path is the snapshot's fixed template (no scheme, absolute,
//!   never `//`);
//! * only the snapshot's DECLARED parameters are serialized, pulled from the
//!   already-bound [`SealedParams`] — a stray caller value can never reach the
//!   wire (finding 4, AC10);
//! * the credential (the resolved literal) is placed in the fixed header or whole
//!   body the snapshot declares and NOWHERE else — never logged, never in an
//!   error, never returned (AC8); [`invoke`](SealedHostAction::invoke)'s return
//!   value (including its error) is discarded by the runtime, so nothing about
//!   the request or response can encode a bit of the literal;
//! * redirects are DENIED: the transport must not follow them, and a `3xx`
//!   status fails closed (AC6);
//! * the fixed [`HTTPS_TIMEOUT_MS`] deadline and [`HTTPS_MAX_RESPONSE_BYTES`]
//!   body bound are handed to the transport and re-checked (AC7).
//!
//! Tests inject a fake [`HttpsTransport`] and never touch the network (AC9); the
//! production [`ReqwestHttpsTransport`] performs the real request with redirects
//! disabled at the client level and a bounded body read.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;

use super::super::action::{
    SealedActionDescriptor, SealedHostAction, SealedParamValue, SealedParams,
};
use super::super::compartment::SealedLiteralHandle;
use super::{
    HTTPS_MAX_RESPONSE_BYTES, HTTPS_TIMEOUT_MS, HttpsCredentialPlacement, HttpsOrigin,
    SealedActionKind, SealedActionSnapshot,
};

/// One outbound HTTPS request the executor asks the transport to perform.
///
/// The headers or body may carry the credential (the snapshot's declared
/// placement); a transport MUST NOT log request fields. `timeout` and `max_response_bytes`
/// are hard bounds the transport must enforce.
pub struct HttpsRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

impl std::fmt::Debug for HttpsRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the URL or headers: either may carry the credential.
        f.debug_struct("HttpsRequest")
            .field("url", &"<redacted>")
            .field(
                "headers",
                &format_args!("[{} redacted]", self.headers.len()),
            )
            .field("body", &self.body.as_ref().map(|_| "<redacted>"))
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// The bounded, non-oracular outcome of a transport send. It carries no body
/// bytes — only the status (for redirect denial) and the observed length (for
/// the size bound). Nothing here is returned to the action's caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpsResponse {
    pub status: u16,
    pub body_len: usize,
}

/// The injected HTTPS transport seam. Production uses [`ReqwestHttpsTransport`];
/// tests use a fake so required tests perform no real network I/O (AC9).
#[async_trait]
pub trait HttpsTransport: Send + Sync + std::fmt::Debug {
    /// Perform exactly one HTTPS request. The implementation MUST NOT follow
    /// redirects and MUST NOT read beyond `request.max_response_bytes`.
    async fn send(&self, request: HttpsRequest) -> Result<HttpsResponse>;
}

/// An executable HTTPS action compiled from a persisted snapshot.
#[derive(Debug)]
pub struct HttpsSealedAction {
    descriptor: SealedActionDescriptor,
    origin: HttpsOrigin,
    credential_placement: HttpsCredentialPlacement,
    path_template: String,
    /// Declared parameter names, in the snapshot's order. The executor serializes
    /// ONLY these, pulling values from the already-bound `SealedParams`.
    declared_params: Vec<String>,
    transport: Arc<dyn HttpsTransport>,
}

impl HttpsSealedAction {
    /// Compile an executable from a persisted snapshot + injected transport.
    ///
    /// The snapshot is the ONLY source of the origin, path, credential placement,
    /// and declared parameters; nothing caller-supplied is consulted (AC10). The
    /// origin is re-parsed through the validating constructor here so a corrupt
    /// persisted origin fails closed at compile time as well as per call.
    pub fn from_snapshot(
        snapshot: &SealedActionSnapshot,
        transport: Arc<dyn HttpsTransport>,
    ) -> Result<Self> {
        let descriptor = snapshot.kind.compile_descriptor(
            &snapshot.action_id,
            snapshot.revision,
            &snapshot.description,
        )?;
        let (origins, credential_placement, path_template, parameters) = match &snapshot.kind {
            SealedActionKind::Https {
                origins,
                credential_placement,
                path_template,
                parameters,
                ..
            } => (origins, credential_placement, path_template, parameters),
            _ => bail!("non-HTTPS actions do not have an HTTPS executor"),
        };
        let origin = origins
            .iter()
            .next()
            .context("sealed HTTPS action snapshot has no origin")?
            .clone();
        // Defense in depth: the persisted origin must still validate.
        HttpsOrigin::parse(&origin.as_str())
            .context("persisted sealed HTTPS origin fails origin validation")?;
        validate_path_template(path_template)?;
        Ok(Self {
            descriptor,
            origin,
            credential_placement: credential_placement.clone(),
            path_template: path_template.clone(),
            declared_params: parameters.keys().cloned().collect(),
            transport,
        })
    }

    /// Render the absolute request URL from the snapshot origin + fixed path +
    /// the declared query parameters. Rejects any result that is not a plain
    /// `https://` URL (finding 5).
    fn render_url(&self, query: &[(String, String)]) -> Result<String> {
        // The origin is `https://host[:port]`; re-parse it every call.
        let origin = HttpsOrigin::parse(&self.origin.as_str())
            .context("origin recheck failed before request")?;
        validate_path_template(&self.path_template)?;
        let mut url = format!("{}{}", origin.as_str(), self.path_template);
        if !query.is_empty() {
            let encoded = query
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&encoded);
        }
        // Final scheme guard: a rendered URL that is not `https://` (e.g. a
        // scheme-relative `//host` that a URL-joining transport would read as
        // authority-relative) fails closed.
        if !url.starts_with("https://") {
            bail!("rendered sealed HTTPS URL is not https");
        }
        Ok(url)
    }
}

#[async_trait]
impl SealedHostAction for HttpsSealedAction {
    fn descriptor(&self) -> &SealedActionDescriptor {
        &self.descriptor
    }

    fn sink_kind(&self) -> &'static str {
        match &self.credential_placement {
            HttpsCredentialPlacement::Header { .. } => "http_header",
            HttpsCredentialPlacement::Body { .. } => "http_body",
        }
    }

    async fn invoke(&self, literal: SealedLiteralHandle<'_>, params: &SealedParams) -> Result<()> {
        // Re-bind the supplied parameters against this action's own descriptor
        // before use. `SealedParams::from_map` is publicly constructible and does
        // no validation, so a caller that bypassed the runtime's binding could
        // present a wrong-typed or out-of-choice value for a declared parameter;
        // re-binding here makes the executor enforce the declared bounds itself
        // (defense in depth — the declared boundary holds even off the runtime
        // path). It also guarantees only declared names reach the wire.
        let supplied: BTreeMap<String, SealedParamValue> = params
            .names()
            .filter_map(|name| {
                params
                    .get(name)
                    .map(|value| (name.to_string(), value.clone()))
            })
            .collect();
        let bound = self
            .descriptor
            .bind_parameters(&supplied)
            .context("sealed HTTPS action parameters failed re-binding")?;
        // Serialize ONLY the snapshot's declared parameters, in declared order.
        let mut query: Vec<(String, String)> = Vec::new();
        for name in &self.declared_params {
            if let Some(value) = bound.get(name) {
                query.push((name.clone(), render_param(value)));
            }
        }
        // Place the credential in the snapshot's fixed location — and nowhere
        // else. It is never added to a log line or an error string.
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut body = None;
        match &self.credential_placement {
            HttpsCredentialPlacement::Header { header_name } => {
                headers.push((header_name.clone(), literal.expose().to_string()));
            }
            HttpsCredentialPlacement::Body { content_type } => {
                headers.push(("Content-Type".to_string(), content_type.clone()));
                body = Some(literal.expose().to_string());
            }
        }
        let url = self.render_url(&query)?;
        let response = self
            .transport
            .send(HttpsRequest {
                url,
                headers,
                body,
                timeout: Duration::from_millis(HTTPS_TIMEOUT_MS),
                max_response_bytes: HTTPS_MAX_RESPONSE_BYTES,
            })
            .await
            .context("sealed HTTPS action transport error")?;
        // Deny redirects: a 3xx is a failure even if the transport did not follow
        // it (an allowlisted origin must not bounce us elsewhere).
        if (300..400).contains(&response.status) {
            bail!(
                "sealed HTTPS action received a redirect ({}); redirects are denied",
                response.status
            );
        }
        // Re-check the body bound the transport was asked to enforce.
        if response.body_len > HTTPS_MAX_RESPONSE_BYTES {
            bail!("sealed HTTPS action response exceeds the {HTTPS_MAX_RESPONSE_BYTES}-byte limit");
        }
        Ok(())
    }
}

/// Render a bound parameter value as its wire string. Choice values are
/// Owner-predeclared constants; integers and flags are canonical.
fn render_param(value: &SealedParamValue) -> String {
    match value {
        SealedParamValue::Text(text) => text.clone(),
        SealedParamValue::Integer(n) => n.to_string(),
        SealedParamValue::Flag(b) => b.to_string(),
    }
}

/// A request path template must be an absolute path with no scheme and no
/// scheme-relative `//` prefix (which a URL-joining transport could read as a
/// replacement authority — finding 5).
fn validate_path_template(path_template: &str) -> Result<()> {
    if !path_template.starts_with('/') {
        bail!("sealed HTTPS path template must be absolute");
    }
    if path_template.starts_with("//") {
        bail!("sealed HTTPS path template must not be scheme-relative");
    }
    if path_template.contains("://") {
        bail!("sealed HTTPS path template must not contain a scheme");
    }
    Ok(())
}

/// The production transport: a `reqwest` client with redirects disabled and a
/// bounded body read. Constructed once; safe to share across actions.
#[derive(Debug)]
pub struct ReqwestHttpsTransport {
    client: reqwest::Client,
}

impl ReqwestHttpsTransport {
    /// Build a client that never follows redirects and ignores ambient proxy
    /// configuration. Per-request timeout and body bound are enforced in
    /// [`HttpsTransport::send`].
    ///
    /// `no_proxy()` matters for egress control: without it a `HTTPS_PROXY` in the
    /// daemon's environment would route the outbound connection to a host outside
    /// the snapshot's origin allowlist.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .context("building sealed HTTPS transport client")?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HttpsTransport for ReqwestHttpsTransport {
    async fn send(&self, request: HttpsRequest) -> Result<HttpsResponse> {
        // Re-assert https at the transport boundary.
        if !request.url.starts_with("https://") {
            bail!("refusing a non-https sealed action request");
        }
        let mut builder = self.client.post(&request.url).timeout(request.timeout);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        // Discard the reqwest source error: it may retain request metadata. Only a fixed, credential-
        // free message survives, so `{err:#}` / `{err:?}` cannot disclose it.
        let response = builder
            .send()
            .await
            .map_err(|_| anyhow!("sealed HTTPS request failed"))?;
        let status = response.status().as_u16();
        // Reject an over-limit declared body up front, before streaming.
        if let Some(len) = response.content_length()
            && len > request.max_response_bytes as u64
        {
            bail!("sealed HTTPS response exceeds the size limit");
        }
        // Bound the streamed body by total bytes. A single chunk may momentarily
        // carry more than the remaining budget before the check trips, but the
        // total is bounded and the connection is dropped on the first overflow;
        // combined with the Content-Length pre-check, an honest or lying oversized
        // response is rejected.
        use futures::StreamExt;
        let mut stream = response.bytes_stream();
        let mut body_len = 0usize;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| anyhow!("reading sealed HTTPS response body failed"))?;
            body_len += chunk.len();
            if body_len > request.max_response_bytes {
                bail!("sealed HTTPS response exceeds the size limit");
            }
        }
        Ok(HttpsResponse { status, body_len })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::super::{
        HttpsOrigin, HttpsOriginAllowlist, SealedActionKind, SealedActionSnapshot,
        SealedParamSpecJson, SealedProjectionId,
    };
    use super::*;
    use crate::sealed::action::{SealedParamValue, SealedParams};
    use crate::sealed::compartment::SealedLiteral;

    type Captured = (
        String,
        Vec<(String, String)>,
        Option<String>,
        Duration,
        usize,
    );

    #[derive(Debug)]
    struct FakeTransport {
        captured: Mutex<Vec<Captured>>,
        status: u16,
        body_len: usize,
    }

    impl FakeTransport {
        fn new(status: u16, body_len: usize) -> Arc<Self> {
            Arc::new(Self {
                captured: Mutex::new(Vec::new()),
                status,
                body_len,
            })
        }
        fn last(&self) -> Captured {
            self.captured.lock().unwrap().last().unwrap().clone()
        }
    }

    #[async_trait]
    impl HttpsTransport for FakeTransport {
        async fn send(&self, request: HttpsRequest) -> Result<HttpsResponse> {
            self.captured.lock().unwrap().push((
                request.url.clone(),
                request.headers.clone(),
                request.body.clone(),
                request.timeout,
                request.max_response_bytes,
            ));
            Ok(HttpsResponse {
                status: self.status,
                body_len: self.body_len,
            })
        }
    }

    /// A transport that must never be reached.
    #[derive(Debug)]
    struct NeverTransport;

    #[async_trait]
    impl HttpsTransport for NeverTransport {
        async fn send(&self, _request: HttpsRequest) -> Result<HttpsResponse> {
            panic!("transport must not be invoked");
        }
    }

    fn https_snapshot(
        origin: &str,
        placement: HttpsCredentialPlacement,
        path: &str,
        params: BTreeMap<String, SealedParamSpecJson>,
    ) -> SealedActionSnapshot {
        let origins = HttpsOriginAllowlist::from_raw(&[origin]).unwrap();
        let kind = SealedActionKind::Https {
            origins,
            credential_placement: placement,
            path_template: path.to_string(),
            projection: SealedProjectionId::None,
            parameters: params,
        };
        SealedActionSnapshot {
            action_id: uuid::Uuid::new_v4().to_string(),
            revision: 1,
            kind,
            description: "notify deploy".into(),
            project_key: "proj".into(),
            enabled: true,
            created_at_ms: 1_000,
            retired_at_ms: None,
        }
    }

    #[tokio::test]
    async fn header_credential_stays_out_of_url_and_uses_snapshot_origin() {
        // AC8 + AC10 + AC9 (fake transport): the credential is placed in the
        // declared header and never in the URL; the URL host is the snapshot
        // origin; the fixed timeout + body bound are handed to the transport.
        let transport = FakeTransport::new(200, 10);
        let snapshot = https_snapshot(
            "https://api.deploy.example.com",
            HttpsCredentialPlacement::Header {
                header_name: "X-Deploy-Key".into(),
            },
            "/v1/notify",
            BTreeMap::new(),
        );
        let action = HttpsSealedAction::from_snapshot(&snapshot, transport.clone()).unwrap();
        let secret = SealedLiteral::new("sk-live-credential-abc123");
        action
            .invoke(secret.handle(), &SealedParams::default())
            .await
            .unwrap();
        let (url, headers, body, timeout, max_bytes) = transport.last();
        assert_eq!(url, "https://api.deploy.example.com/v1/notify");
        assert!(
            !url.contains("sk-live-credential-abc123"),
            "credential must never appear in the URL"
        );
        assert!(body.is_none());
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "X-Deploy-Key" && v == "sk-live-credential-abc123")
        );
        assert_eq!(timeout, Duration::from_millis(HTTPS_TIMEOUT_MS));
        assert_eq!(max_bytes, HTTPS_MAX_RESPONSE_BYTES);
    }

    #[tokio::test]
    async fn request_debug_never_reveals_credential() {
        // AC8: even a debug render of the outbound request redacts the URL and
        // headers, so an accidental log cannot leak the credential.
        let request = HttpsRequest {
            url: "https://api.example.com/v1/notify?api_key=sk-live-secret".into(),
            headers: vec![("X-Key".into(), "sk-live-secret".into())],
            body: Some("sk-live-secret".into()),
            timeout: Duration::from_millis(HTTPS_TIMEOUT_MS),
            max_response_bytes: HTTPS_MAX_RESPONSE_BYTES,
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("sk-live-secret"), "{rendered}");
    }

    #[tokio::test]
    async fn redirect_status_is_denied() {
        // AC6: a 3xx status fails closed (redirects are not followed).
        let transport = FakeTransport::new(302, 0);
        let snapshot = https_snapshot(
            "https://api.deploy.example.com",
            HttpsCredentialPlacement::Header {
                header_name: "X-Key".into(),
            },
            "/v1/notify",
            BTreeMap::new(),
        );
        let action = HttpsSealedAction::from_snapshot(&snapshot, transport).unwrap();
        let secret = SealedLiteral::new("cred");
        let err = action
            .invoke(secret.handle(), &SealedParams::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("redirect"), "{err}");
    }

    #[tokio::test]
    async fn over_limit_body_is_rejected() {
        // AC7: a response body over the size bound fails closed.
        let transport = FakeTransport::new(200, HTTPS_MAX_RESPONSE_BYTES + 1);
        let snapshot = https_snapshot(
            "https://api.deploy.example.com",
            HttpsCredentialPlacement::Header {
                header_name: "X-Key".into(),
            },
            "/v1/notify",
            BTreeMap::new(),
        );
        let action = HttpsSealedAction::from_snapshot(&snapshot, transport).unwrap();
        let secret = SealedLiteral::new("cred");
        let err = action
            .invoke(secret.handle(), &SealedParams::default())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("limit") || err.to_string().contains("exceeds"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn ip_literal_origin_rejected_before_transport() {
        // AC6 / finding 5: an IP-literal origin (built via raw fields to bypass
        // the validating parse) fails closed at compile; the transport is never
        // reached.
        let bad_origins = HttpsOriginAllowlist {
            origins: vec![HttpsOrigin {
                host: "169.254.169.254".into(),
                port: None,
            }],
        };
        let kind = SealedActionKind::Https {
            origins: bad_origins,
            credential_placement: HttpsCredentialPlacement::Header {
                header_name: "X-Key".into(),
            },
            path_template: "/v1/notify".into(),
            projection: SealedProjectionId::None,
            parameters: BTreeMap::new(),
        };
        let snapshot = SealedActionSnapshot {
            action_id: uuid::Uuid::new_v4().to_string(),
            revision: 1,
            kind,
            description: "x".into(),
            project_key: "proj".into(),
            enabled: true,
            created_at_ms: 1_000,
            retired_at_ms: None,
        };
        assert!(HttpsSealedAction::from_snapshot(&snapshot, Arc::new(NeverTransport)).is_err());
    }

    #[tokio::test]
    async fn scheme_relative_path_rejected_before_transport() {
        // finding 5: a `//host` path template (a scheme-relative authority a URL
        // joiner would honor) fails closed; the transport is never reached.
        let snapshot = https_snapshot(
            "https://api.deploy.example.com",
            HttpsCredentialPlacement::Header {
                header_name: "X-Key".into(),
            },
            "//evil.example.com/x",
            BTreeMap::new(),
        );
        assert!(HttpsSealedAction::from_snapshot(&snapshot, Arc::new(NeverTransport)).is_err());
    }

    #[tokio::test]
    async fn serializes_only_declared_params_and_body_credential() {
        // Only declared parameters reach the query. Body placement keeps the
        // literal out of the URL and sets the fixed content type.
        let spec = BTreeMap::from([(
            "channel".to_string(),
            SealedParamSpecJson::Choice {
                allowed: vec!["primary".to_string()],
            },
        )]);
        let snapshot = https_snapshot(
            "https://api.deploy.example.com",
            HttpsCredentialPlacement::Body {
                content_type: "text/plain".into(),
            },
            "/v1/notify",
            spec,
        );
        let transport = FakeTransport::new(200, 0);
        let action = HttpsSealedAction::from_snapshot(&snapshot, transport.clone()).unwrap();
        let bound = SealedParams::from_map(BTreeMap::from([(
            "channel".to_string(),
            SealedParamValue::Text("primary".to_string()),
        )]));
        let secret = SealedLiteral::new("cred-xyz");
        action.invoke(secret.handle(), &bound).await.unwrap();
        let (url, headers, body, _, _) = transport.last();
        assert!(
            url.starts_with("https://api.deploy.example.com/v1/notify?"),
            "{url}"
        );
        assert!(url.contains("channel=primary"), "{url}");
        assert!(
            headers.iter().any(|(name, value)| name == "Content-Type" && value == "text/plain")
        );
        assert_eq!(body.as_deref(), Some("cred-xyz"));
    }

    #[tokio::test]
    async fn forged_out_of_choice_param_is_rejected_before_transport() {
        // Finding 5: `SealedParams::from_map` is publicly constructible and
        // unvalidated. A forged value outside a declared Choice set must be
        // rejected by the executor's re-binding, before the transport is reached.
        let spec = BTreeMap::from([(
            "channel".to_string(),
            SealedParamSpecJson::Choice {
                allowed: vec!["primary".to_string()],
            },
        )]);
        let snapshot = https_snapshot(
            "https://api.deploy.example.com",
            HttpsCredentialPlacement::Header {
                header_name: "X-Key".into(),
            },
            "/v1/notify",
            spec,
        );
        let action = HttpsSealedAction::from_snapshot(&snapshot, Arc::new(NeverTransport)).unwrap();
        let forged = SealedParams::from_map(BTreeMap::from([(
            "channel".to_string(),
            SealedParamValue::Text("attacker-controlled".to_string()),
        )]));
        let secret = SealedLiteral::new("cred");
        let err = action
            .invoke(secret.handle(), &forged)
            .await
            .expect_err("a forged out-of-choice parameter must be rejected");
        assert!(
            err.to_string().contains("re-binding") || err.to_string().contains("choice"),
            "{err}"
        );
    }
}
