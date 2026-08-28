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
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
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
/// fail-closed result for missing capability, journal-independent provider
/// configuration, credentials, or a route that is not the supported public
/// OpenAI-compatible HTTPS endpoint shape.
pub(crate) async fn resolve_vetted_egress(
    session: &crate::session::Session,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    provider_id: &str,
    model_id: &str,
    env: &std::collections::HashMap<String, String>,
) -> Option<VettedTranscriptionEgress> {
    use crate::config::providers::CapabilityStatus;

    let providers = config.providers();
    let capabilities =
        providers.resolve_effective_model_capabilities(provider_id, model_id, config.generation());
    if capabilities.transcription != CapabilityStatus::Supported {
        return None;
    }
    let entry = providers.providers.get(provider_id)?;
    let store = session.provider_credential_store(&providers).ok()?;
    let request = crate::providers::models_fetch::resolve_provider_request_async_with_store(
        provider_id,
        entry,
        store,
        |name| env.get(name).cloned().or_else(|| std::env::var(name).ok()),
    )
    .await
    .ok()?;
    let authorization = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("authorization"))?
        .value
        .strip_prefix("Bearer ")?;
    if authorization.is_empty() {
        return None;
    }
    let mut origin = reqwest::Url::parse(&request.base_url).ok()?;
    if origin.path().trim_end_matches('/') == "/v1" {
        origin.set_path("/");
    }
    if origin.path() != "/" {
        return None;
    }
    let fingerprint = crate::image_sidecar::CredentialFingerprint::from_identity(authorization);
    VettedTranscriptionEgress::new(
        provider_id.to_string(),
        origin.as_str(),
        "public_network".to_string(),
        authorization,
        super::authorization::CredentialFingerprintDigest::from_fingerprint(&fingerprint),
        config.generation(),
        Arc::new(crate::image_generation_runtime::TokioDnsResolver),
    )
    .ok()
}

/// Production HTTPS transport for OpenAI-compatible `/v1/audio/transcriptions`.
pub struct TranscriptionHttpTransport {
    origin: Url,
    authorization: HeaderValue,
    dns: Arc<dyn DnsResolver>,
    body_limit: usize,
    required_location: AddressClass,
    path: &'static str,
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
            .field("authorization", &"<redacted>")
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
        if body_limit == 0 {
            return Err(ProviderTransportConfigError::EmptyBodyLimit);
        }
        let origin = validate_https_origin(origin)?;
        if origin.path() != "/" {
            return Err(ProviderTransportConfigError::ForbiddenOriginComponent);
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {bearer_token}"))
            .map_err(|_| ProviderTransportConfigError::InvalidCredential)?;
        authorization.set_sensitive(true);
        Ok(Self {
            origin,
            authorization,
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
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, self.authorization.clone());
        headers.insert(CONTENT_TYPE, content_type_value);

        match VettedHttpClient::new(self.dns.clone(), self.required_location)
            .execute(Method::POST, &url, headers, Some(body), self.body_limit)
            .await
        {
            Ok(outcome) => Ok(TranscriptionHttpResponse {
                status: outcome.status,
                body: outcome.body,
            }),
            Err(error) => Err(Self::map_error(error)),
        }
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
