//! Production [`super::dispatch::TranscriptionEgressTransport`] over the
//! shared pinned/vetted provider HTTP client.
//!
//! Live transcription egress is `POST {origin}/v1/audio/transcriptions` with a
//! `multipart/form-data` body. Every request byte leaves through
//! [`crate::image_generation::http_transport::VettedHttpClient`] — the same
//! chokepoint image generation and other provider HTTP uses — so DNS is
//! vetted as a whole, redirects and proxies are refused, the response body is
//! bounded while it is read, and failures map onto a billing-safe vocabulary.
//! Credential material is a sensitive header and never appears in `Debug`,
//! logs, or error text.

use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use async_trait::async_trait;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Url};

use super::dispatch::{
    TranscriptionEgressError, TranscriptionEgressTransport, TranscriptionHttpResponse,
};
use super::response::MAX_RESPONSE_BODY_BYTES;
use crate::image_generation::http_transport::{
    ProviderTransportConfigError, VettedHttpClient, validate_https_origin,
};
use crate::image_generation::transport::ProviderTransportError;
use crate::image_generation_runtime::{AddressClass, DnsResolver};

/// Resolve and bind the complete live transcription route. Absence is the
/// fail-closed result for missing capability or a route that is not the
/// supported public OpenAI-compatible HTTPS endpoint shape. Authentication
/// resolution errors deliberately remain errors so a failed auth command is
/// surfaced as authentication failure instead of disappearing as capability
/// absence.
pub(crate) async fn resolve_vetted_egress(
    session: &crate::session::Session,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    provider_id: &str,
    model_id: &str,
    env: &std::collections::HashMap<String, String>,
) -> anyhow::Result<Option<VettedTranscriptionEgress>> {
    use crate::config::providers::CapabilityStatus;

    let providers = config.providers();
    let config_generation = providers.resolution_generation;
    let capabilities =
        providers.resolve_effective_model_capabilities(provider_id, model_id, config_generation);
    if capabilities.transcription != CapabilityStatus::Supported {
        return Ok(None);
    }
    let Some(entry) = providers.providers.get(provider_id) else {
        return Ok(None);
    };
    let store = session
        .provider_credential_store(&providers)
        .context("resolving transcription provider credentials")?;
    let request = crate::providers::models_fetch::resolve_provider_request_async_with_store(
        provider_id,
        entry,
        store.clone(),
        |name| env.get(name).cloned().or_else(|| std::env::var(name).ok()),
    )
    .await
    .context("resolving transcription provider authentication")?;
    let Some(header) = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("authorization"))
    else {
        return Ok(None);
    };
    let authorization = header.value.as_str();
    if authorization.is_empty() {
        return Ok(None);
    }
    let Ok(mut origin) = reqwest::Url::parse(&request.base_url) else {
        return Ok(None);
    };
    if origin.path().trim_end_matches('/') == "/v1" {
        origin.set_path("/");
    }
    if origin.path() != "/" {
        return Ok(None);
    }
    let fingerprint = crate::image_sidecar::CredentialFingerprint::from_identity(authorization);
    let command_refresh = entry.auth_command.as_ref().map(|_| CommandRefresh {
        provider_id: provider_id.to_string(),
        config: config.live(),
        configured_generation: config_generation,
        store,
        env: env.clone(),
        state: Arc::new(Mutex::new(CommandRequestState {
            headers: HeaderMap::new(),
            rejected_refresh_generation: request.command_credential_generation(),
        })),
    });
    VettedTranscriptionEgress::new_with_headers_and_refresh(
        provider_id.to_string(),
        origin.as_str(),
        "public_network".to_string(),
        &request.headers,
        super::authorization::CredentialFingerprintDigest::from_fingerprint(&fingerprint),
        config_generation,
        Arc::new(crate::image_generation_runtime::TokioDnsResolver),
        command_refresh,
    )
    .map(Some)
    .context("binding transcription provider authentication")
}

/// Production HTTPS transport for OpenAI-compatible `/v1/audio/transcriptions`.
pub struct TranscriptionHttpTransport {
    origin: Url,
    headers: Mutex<HeaderMap>,
    command_refresh: Option<CommandRefresh>,
    dns: Arc<dyn DnsResolver>,
    body_limit: usize,
    required_location: AddressClass,
    path: &'static str,
}

#[derive(Clone)]
struct CommandRefresh {
    provider_id: String,
    config: crate::daemon::session_worker::SessionConfigHandle,
    configured_generation: u64,
    store: crate::credentials::CredentialStore,
    env: std::collections::HashMap<String, String>,
    state: Arc<Mutex<CommandRequestState>>,
}

impl CommandRefresh {
    /// Resolve the command entry from the current config snapshot immediately
    /// before a rejection-triggered refresh. A removed command fails closed;
    /// a replacement is the only executable allowed to run.
    fn current_entry(&self) -> anyhow::Result<crate::config::providers::ProviderEntry> {
        let snapshot = self.config.snapshot();
        if snapshot.generation != self.configured_generation {
            tracing::debug!(
                provider_id = %self.provider_id,
                configured_generation = self.configured_generation,
                current_generation = snapshot.generation,
                "transcription auth-command refresh re-authorized against reloaded provider config"
            );
        }
        snapshot
            .providers
            .providers
            .get(&self.provider_id)
            .filter(|entry| entry.auth_command.is_some())
            .cloned()
            .with_context(|| {
                format!(
                    "provider `{}` no longer has a global auth_command authorized for transcription refresh",
                    self.provider_id
                )
            })
    }
}

/// The exact command-authenticated headers and generation attached to a
/// request. They must be read and replaced under one lock: a delayed 401 from
/// generation N must never be attributed to concurrently published N+1.
#[derive(Clone)]
struct CommandRequestState {
    headers: HeaderMap,
    rejected_refresh_generation: Option<u64>,
}

/// A fully vetted provider route.  Keeping the transport and its audit
/// identity in one opaque value prevents callers from authorizing one
/// provider/location/fingerprint while sending with another bearer/origin.
pub struct VettedTranscriptionEgress {
    transport: TranscriptionHttpTransport,
    identity: super::journal::TranscriptionDestinationIdentity,
}

impl VettedTranscriptionEgress {
    pub fn new(
        provider_id: String,
        origin: &str,
        resolved_location: String,
        bearer_token: &str,
        credential_fingerprint: super::authorization::CredentialFingerprintDigest,
        endpoint_config_generation: u64,
        dns: Arc<dyn DnsResolver>,
    ) -> Result<Self, ProviderTransportConfigError> {
        let transport =
            TranscriptionHttpTransport::vetted_default_limit(origin, bearer_token, dns)?;
        Self::from_transport(
            provider_id,
            transport,
            resolved_location,
            credential_fingerprint,
            endpoint_config_generation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_headers_and_refresh(
        provider_id: String,
        origin: &str,
        resolved_location: String,
        headers: &[crate::providers::models_fetch::ResolvedHeader],
        credential_fingerprint: super::authorization::CredentialFingerprintDigest,
        endpoint_config_generation: u64,
        dns: Arc<dyn DnsResolver>,
        command_refresh: Option<CommandRefresh>,
    ) -> Result<Self, ProviderTransportConfigError> {
        let transport = TranscriptionHttpTransport::vetted_headers_default_limit_with_refresh(
            origin,
            headers,
            dns,
            command_refresh,
        )?;
        Self::from_transport(
            provider_id,
            transport,
            resolved_location,
            credential_fingerprint,
            endpoint_config_generation,
        )
    }

    fn from_transport(
        provider_id: String,
        transport: TranscriptionHttpTransport,
        resolved_location: String,
        credential_fingerprint: super::authorization::CredentialFingerprintDigest,
        endpoint_config_generation: u64,
    ) -> Result<Self, ProviderTransportConfigError> {
        let identity = super::journal::TranscriptionDestinationIdentity {
            provider_id,
            origin: transport.origin().to_string(),
            resolved_location,
            credential_fingerprint,
            endpoint_config_generation,
        };
        Ok(Self {
            transport,
            identity,
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        TranscriptionHttpTransport,
        super::journal::TranscriptionDestinationIdentity,
    ) {
        (self.transport, self.identity)
    }
}

impl fmt::Debug for TranscriptionHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TranscriptionHttpTransport")
            .field("origin", &self.origin.as_str())
            .field("headers", &"<redacted>")
            .field("body_limit", &self.body_limit)
            .field("required_location", &self.required_location)
            .field("path", &self.path)
            .finish()
    }
}

impl TranscriptionHttpTransport {
    /// The OpenAI Audio transcriptions path. Joined onto a validated origin.
    pub const TRANSCRIPTIONS_PATH: &'static str = "/v1/audio/transcriptions";

    pub fn origin(&self) -> &str {
        self.origin.as_str()
    }

    /// Bind a vetted HTTPS origin, a caller-supplied bearer credential, and
    /// the public-internet address class. Fails closed on a malformed origin
    /// or credential; never hardcodes a secret.
    pub fn vetted(
        origin: &str,
        bearer_token: &str,
        dns: Arc<dyn DnsResolver>,
        body_limit: usize,
    ) -> Result<Self, ProviderTransportConfigError> {
        let mut authorization = HeaderValue::from_str(&format!("Bearer {bearer_token}"))
            .map_err(|_| ProviderTransportConfigError::InvalidCredential)?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        Self::vetted_header_map(origin, headers, dns, body_limit, None)
    }

    pub(crate) fn vetted_headers_default_limit(
        origin: &str,
        headers: &[crate::providers::models_fetch::ResolvedHeader],
        dns: Arc<dyn DnsResolver>,
    ) -> Result<Self, ProviderTransportConfigError> {
        let mut resolved = HeaderMap::new();
        for header in headers {
            let name = HeaderName::from_bytes(header.name.as_bytes())
                .map_err(|_| ProviderTransportConfigError::InvalidCredential)?;
            let mut value = HeaderValue::from_str(&header.value)
                .map_err(|_| ProviderTransportConfigError::InvalidCredential)?;
            value.set_sensitive(true);
            resolved.insert(name, value);
        }
        Self::vetted_header_map(origin, resolved, dns, MAX_RESPONSE_BODY_BYTES, None)
    }

    fn vetted_headers_default_limit_with_refresh(
        origin: &str,
        headers: &[crate::providers::models_fetch::ResolvedHeader],
        dns: Arc<dyn DnsResolver>,
        command_refresh: Option<CommandRefresh>,
    ) -> Result<Self, ProviderTransportConfigError> {
        let mut resolved = HeaderMap::new();
        for header in headers {
            let name = HeaderName::from_bytes(header.name.as_bytes())
                .map_err(|_| ProviderTransportConfigError::InvalidCredential)?;
            let mut value = HeaderValue::from_str(&header.value)
                .map_err(|_| ProviderTransportConfigError::InvalidCredential)?;
            value.set_sensitive(true);
            resolved.insert(name, value);
        }
        Self::vetted_header_map(
            origin,
            resolved,
            dns,
            MAX_RESPONSE_BODY_BYTES,
            command_refresh,
        )
    }

    fn vetted_header_map(
        origin: &str,
        headers: HeaderMap,
        dns: Arc<dyn DnsResolver>,
        body_limit: usize,
        command_refresh: Option<CommandRefresh>,
    ) -> Result<Self, ProviderTransportConfigError> {
        if body_limit == 0 {
            return Err(ProviderTransportConfigError::EmptyBodyLimit);
        }
        let origin = validate_https_origin(origin)?;
        if origin.path() != "/" {
            return Err(ProviderTransportConfigError::ForbiddenOriginComponent);
        }
        if let Some(refresh) = &command_refresh {
            refresh
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .headers = headers.clone();
        }
        Ok(Self {
            origin,
            headers: Mutex::new(headers),
            command_refresh,
            dns,
            body_limit,
            required_location: AddressClass::PublicNetwork,
            path: Self::TRANSCRIPTIONS_PATH,
        })
    }

    /// Convenience constructor using the transcription response body cap.
    pub fn vetted_default_limit(
        origin: &str,
        bearer_token: &str,
        dns: Arc<dyn DnsResolver>,
    ) -> Result<Self, ProviderTransportConfigError> {
        Self::vetted(origin, bearer_token, dns, MAX_RESPONSE_BODY_BYTES)
    }

    fn map_error(error: ProviderTransportError) -> TranscriptionEgressError {
        match error {
            ProviderTransportError::Connect | ProviderTransportError::Tls => {
                TranscriptionEgressError::Connect
            }
            ProviderTransportError::Timeout | ProviderTransportError::AmbiguousAcceptance => {
                TranscriptionEgressError::AmbiguousAcceptance
            }
            ProviderTransportError::Status { status, .. } => {
                TranscriptionEgressError::Status { status }
            }
            ProviderTransportError::BodyLimit => TranscriptionEgressError::BodyLimit,
            ProviderTransportError::Malformed => TranscriptionEgressError::Malformed,
        }
    }
}

#[async_trait]
impl TranscriptionEgressTransport for TranscriptionHttpTransport {
    async fn post_multipart(
        &self,
        boundary: &str,
        body: Vec<u8>,
    ) -> std::result::Result<TranscriptionHttpResponse, TranscriptionEgressError> {
        let url = self
            .origin
            .join(self.path.trim_start_matches('/'))
            .map_err(|_| TranscriptionEgressError::Connect)?;
        let content_type = format!("multipart/form-data; boundary={boundary}");
        let content_type_value =
            HeaderValue::from_str(&content_type).map_err(|_| TranscriptionEgressError::Connect)?;
        let (mut headers, rejected_refresh_generation) = self
            .command_refresh
            .as_ref()
            .map(|refresh| {
                let state = refresh
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                (state.headers.clone(), state.rejected_refresh_generation)
            })
            .unwrap_or_else(|| {
                (
                    self.headers
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone(),
                    None,
                )
            });
        headers.insert(CONTENT_TYPE, content_type_value.clone());

        let outcome = VettedHttpClient::new(self.dns.clone(), self.required_location)
            .execute(
                Method::POST,
                &url,
                headers,
                Some(body.clone()),
                self.body_limit,
            )
            .await
            .map_err(Self::map_error)?;
        if matches!(outcome.status, 401 | 403)
            && let Some(refresh) = &self.command_refresh
        {
            let refreshed = crate::providers::models_fetch::refresh_provider_request_async_with_store_authorized(
                &refresh.provider_id,
                refresh.store.clone(),
                |name| {
                    refresh
                        .env
                        .get(name)
                        .cloned()
                        .or_else(|| std::env::var(name).ok())
                },
                rejected_refresh_generation,
                || refresh.current_entry(),
            )
                .await
                .map_err(|_| TranscriptionEgressError::Authentication)?;
            let mut refreshed_headers = HeaderMap::new();
            for header in &refreshed.headers {
                let name = HeaderName::from_bytes(header.name.as_bytes())
                    .map_err(|_| TranscriptionEgressError::Authentication)?;
                let mut value = HeaderValue::from_str(&header.value)
                    .map_err(|_| TranscriptionEgressError::Authentication)?;
                value.set_sensitive(true);
                refreshed_headers.insert(name, value);
            }
            let mut request_headers = refreshed_headers.clone();
            request_headers.insert(CONTENT_TYPE, content_type_value);
            // Publish the refreshed request state before retrying. The next
            // long-lived dispatch must reject generation N+1 (not the
            // construction-time N) if this retry is rejected too.
            *self
                .headers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = refreshed_headers.clone();
            *refresh
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = CommandRequestState {
                headers: refreshed_headers.clone(),
                rejected_refresh_generation: refreshed.command_credential_generation(),
            };
            let retry = VettedHttpClient::new(self.dns.clone(), self.required_location)
                .execute(
                    Method::POST,
                    &url,
                    request_headers,
                    Some(body),
                    self.body_limit,
                )
                .await
                .map_err(Self::map_error)?;
            return Ok(TranscriptionHttpResponse {
                status: retry.status,
                body: retry.body,
            });
        }
        Ok(TranscriptionHttpResponse {
            status: outcome.status,
            body: outcome.body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_generation_runtime::RuntimeError;
    use std::future::Future;
    use std::net::IpAddr;
    use std::pin::Pin;

    struct RejectingDns;

    impl DnsResolver for RejectingDns {
        fn resolve<'a>(
            &'a self,
            _hostname: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, RuntimeError>> + Send + 'a>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[test]
    fn vetted_rejects_non_https_origin() {
        let err = TranscriptionHttpTransport::vetted(
            "http://api.openai.com",
            "sk-test",
            Arc::new(RejectingDns),
            MAX_RESPONSE_BODY_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, ProviderTransportConfigError::NotHttps);
    }

    #[test]
    fn vetted_rejects_userinfo_query_fragment() {
        let err = TranscriptionHttpTransport::vetted(
            "https://api.openai.com/v1?x=1",
            "sk-test",
            Arc::new(RejectingDns),
            MAX_RESPONSE_BODY_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, ProviderTransportConfigError::ForbiddenOriginComponent);
    }

    #[test]
    fn vetted_rejects_empty_body_limit() {
        let err = TranscriptionHttpTransport::vetted(
            "https://api.openai.com",
            "sk-test",
            Arc::new(RejectingDns),
            0,
        )
        .unwrap_err();
        assert_eq!(err, ProviderTransportConfigError::EmptyBodyLimit);
    }

    #[test]
    fn vetted_rejects_invalid_credential_header() {
        let err = TranscriptionHttpTransport::vetted(
            "https://api.openai.com",
            "sk-\n-newline",
            Arc::new(RejectingDns),
            MAX_RESPONSE_BODY_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, ProviderTransportConfigError::InvalidCredential);
    }

    #[test]
    fn vetted_debug_redacts_authorization() {
        let transport = TranscriptionHttpTransport::vetted(
            "https://api.openai.com",
            "sk-secret-token",
            Arc::new(RejectingDns),
            MAX_RESPONSE_BODY_BYTES,
        )
        .unwrap();
        let rendered = format!("{transport:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("sk-secret-token"));
        assert!(rendered.contains("https://api.openai.com"));
    }

    #[test]
    fn transcriptions_path_is_openai_audio() {
        assert_eq!(
            TranscriptionHttpTransport::TRANSCRIPTIONS_PATH,
            "/v1/audio/transcriptions"
        );
    }
}
