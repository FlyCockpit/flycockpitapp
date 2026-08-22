//! Production pinned HTTPS transport for the OpenAI Images adapter.
//!
//! This is the only place an OpenAI Images request byte leaves the process. It
//! reuses the runtime probe client's egress posture (`image_generation_runtime`
//! `BoundConnector` / `media_https`): the socket is pinned to a DNS answer set
//! that is vetted to the required location class before any byte is sent,
//! automatic redirects are disabled so no credential-bearing request ever
//! crosses an origin, an environment/system proxy is refused, the process-global
//! rustls provider is pinned before any TLS client is built, and the response
//! body is bounded **while it is read** rather than after buffering an
//! unbounded response.
//!
//! The type has private fields and is constructible only through
//! [`OpenaiImagesHttpTransport::vetted`], so no caller can assemble one that
//! skips the vetted posture. Credential material is supplied by the caller,
//! never hardcoded, and is held in a sensitive header value that is kept off
//! every log, error, and `Debug` rendering.

use std::fmt;
use std::sync::Arc;

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Method, Url};

use super::{OpenaiImagesRoute, OpenaiImagesTransport, openai_images_adapter_sealed};
use crate::image_generation::http_transport::VettedHttpClient;
use crate::image_generation::transport::{ProviderTransportError, ProviderTransportOutcome};
use crate::image_generation_runtime::{AddressClass, DnsResolver};

/// A production pinned HTTPS transport bound to one OpenAI Images origin.
pub struct OpenaiImagesHttpTransport {
    /// Validated `https` origin (no userinfo, query, or fragment).
    origin: Url,
    /// `Authorization: Bearer …` value, marked sensitive so reqwest never logs
    /// it. Its `Debug` is redacted below.
    authorization: HeaderValue,
    /// Vetted DNS resolver (shared with the runtime probe client).
    dns: Arc<dyn DnsResolver>,
    /// Per-adapter response body limit, enforced while reading.
    body_limit: usize,
    /// The only address class the socket peer may belong to.
    required_location: AddressClass,
}

impl fmt::Debug for OpenaiImagesHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenaiImagesHttpTransport")
            .field("origin", &self.origin.as_str())
            .field("authorization", &"<redacted>")
            .field("body_limit", &self.body_limit)
            .field("required_location", &self.required_location)
            .finish()
    }
}

/// Why a transport could not be constructed. Carries no credential material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenaiImagesTransportConfigError {
    /// The origin was not a parseable absolute URL.
    InvalidOrigin,
    /// The origin scheme was not `https`.
    NotHttps,
    /// The origin had no host.
    MissingHost,
    /// The origin carried userinfo, a query, or a fragment.
    ForbiddenOriginComponent,
    /// The supplied credential could not form a valid header value.
    InvalidCredential,
    /// The body limit was zero.
    EmptyBodyLimit,
}

impl fmt::Display for OpenaiImagesTransportConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidOrigin => "origin is not a valid absolute URL",
            Self::NotHttps => "origin scheme must be https",
            Self::MissingHost => "origin has no host",
            Self::ForbiddenOriginComponent => "origin must not carry userinfo, query, or fragment",
            Self::InvalidCredential => "credential is not a valid header value",
            Self::EmptyBodyLimit => "body limit must be positive",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OpenaiImagesTransportConfigError {}

impl OpenaiImagesHttpTransport {
    /// The single vetted constructor. Validates the origin, binds the
    /// caller-supplied bearer credential as a sensitive header, and fixes the
    /// required peer location class to the public internet. Fails closed on any
    /// malformed input; never hardcodes a credential.
    pub fn vetted(
        origin: &str,
        bearer_token: &str,
        dns: Arc<dyn DnsResolver>,
        body_limit: usize,
    ) -> Result<Self, OpenaiImagesTransportConfigError> {
        let origin =
            Url::parse(origin).map_err(|_| OpenaiImagesTransportConfigError::InvalidOrigin)?;
        if origin.scheme() != "https" {
            return Err(OpenaiImagesTransportConfigError::NotHttps);
        }
        if origin.host_str().is_none() {
            return Err(OpenaiImagesTransportConfigError::MissingHost);
        }
        if !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(OpenaiImagesTransportConfigError::ForbiddenOriginComponent);
        }
        if body_limit == 0 {
            return Err(OpenaiImagesTransportConfigError::EmptyBodyLimit);
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {bearer_token}"))
            .map_err(|_| OpenaiImagesTransportConfigError::InvalidCredential)?;
        authorization.set_sensitive(true);
        Ok(Self {
            origin,
            authorization,
            dns,
            body_limit,
            required_location: AddressClass::PublicRemote,
        })
    }

    async fn submit_inner(
        &self,
        route: OpenaiImagesRoute,
        content_type: &str,
        body: &[u8],
    ) -> Result<ProviderTransportOutcome, ProviderTransportError> {
        // A fixed route path joined onto a validated origin: a failure here is a
        // build error with no byte sent, hence the safe pre-handoff class.
        let url = self
            .origin
            .join(route.path().trim_start_matches('/'))
            .map_err(|_| ProviderTransportError::Connect)?;

        // The credential is kept in a sensitive header value; a malformed
        // content-type is a build error with no byte sent.
        let content_type_value =
            HeaderValue::from_str(content_type).map_err(|_| ProviderTransportError::Connect)?;
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, self.authorization.clone());
        headers.insert(CONTENT_TYPE, content_type_value);

        // Every byte leaves through the single pinned/vetted client, which vets
        // the full DNS answer set to the required class before sending, refuses
        // proxies and credential-bearing redirects, verifies the response peer,
        // reads the body bounded, and maps failures onto the billing-safe
        // transport vocabulary.
        VettedHttpClient::new(self.dns.clone(), self.required_location)
            .execute(
                Method::POST,
                &url,
                headers,
                Some(body.to_vec()),
                self.body_limit,
            )
            .await
    }
}

impl openai_images_adapter_sealed::Sealed for OpenaiImagesHttpTransport {}

#[async_trait::async_trait]
impl OpenaiImagesTransport for OpenaiImagesHttpTransport {
    async fn submit(
        &self,
        route: OpenaiImagesRoute,
        content_type: &str,
        body: &[u8],
    ) -> Result<ProviderTransportOutcome, ProviderTransportError> {
        self.submit_inner(route, content_type, body).await
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::IpAddr;
    use std::pin::Pin;
    use std::sync::Arc;

    use super::*;
    use crate::image_generation_runtime::RuntimeError;

    struct FixedDnsResolver {
        answers: Vec<IpAddr>,
    }

    impl DnsResolver for FixedDnsResolver {
        fn resolve<'a>(
            &'a self,
            _hostname: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, RuntimeError>> + Send + 'a>> {
            let answers = self.answers.clone();
            Box::pin(async move { Ok(answers) })
        }
    }

    fn dns(answers: &[&str]) -> Arc<dyn DnsResolver> {
        Arc::new(FixedDnsResolver {
            answers: answers.iter().map(|ip| ip.parse().unwrap()).collect(),
        })
    }

    #[test]
    fn vetted_builder_rejects_non_https_and_userinfo_origins() {
        let resolver = dns(&["93.184.216.34"]);
        assert_eq!(
            OpenaiImagesHttpTransport::vetted(
                "http://api.example.test",
                "k",
                resolver.clone(),
                1024
            )
            .unwrap_err(),
            OpenaiImagesTransportConfigError::NotHttps
        );
        assert_eq!(
            OpenaiImagesHttpTransport::vetted(
                "https://user:pass@api.example.test",
                "k",
                resolver.clone(),
                1024
            )
            .unwrap_err(),
            OpenaiImagesTransportConfigError::ForbiddenOriginComponent
        );
        assert_eq!(
            OpenaiImagesHttpTransport::vetted("not a url", "k", resolver.clone(), 1024)
                .unwrap_err(),
            OpenaiImagesTransportConfigError::InvalidOrigin
        );
        assert_eq!(
            OpenaiImagesHttpTransport::vetted("https://api.example.test", "k", resolver, 0)
                .unwrap_err(),
            OpenaiImagesTransportConfigError::EmptyBodyLimit
        );
    }

    #[test]
    fn vetted_builder_accepts_https_public_origin() {
        let transport = OpenaiImagesHttpTransport::vetted(
            "https://api.openai.com",
            "sk-secret",
            dns(&["93.184.216.34"]),
            1024,
        )
        .expect("vetted builder should accept a clean https origin");
        // Credential material must not appear in Debug output.
        let rendered = format!("{transport:?}");
        assert!(
            !rendered.contains("sk-secret"),
            "credential leaked in Debug: {rendered}"
        );
        assert!(rendered.contains("<redacted>"));
    }

    #[tokio::test]
    async fn submit_refuses_non_public_dns_answer_before_sending() {
        // A loopback answer is rejected during vetting, before any socket is
        // opened, so this needs no network. A byte is never sent, so the class
        // is the safe pre-handoff `Connect`.
        let transport = OpenaiImagesHttpTransport::vetted(
            "https://api.openai.com",
            "sk-secret",
            dns(&["127.0.0.1"]),
            1024,
        )
        .unwrap();
        let outcome = transport
            .submit(OpenaiImagesRoute::Generations, "application/json", b"{}")
            .await;
        assert_eq!(outcome, Err(ProviderTransportError::Connect));
    }

    #[tokio::test]
    async fn submit_refuses_mixed_answer_set_when_any_member_is_forbidden() {
        // Even one non-public answer poisons the whole set (no public-member
        // cherry-picking), so DNS order cannot become an SSRF bypass.
        let transport = OpenaiImagesHttpTransport::vetted(
            "https://api.openai.com",
            "sk-secret",
            dns(&["93.184.216.34", "169.254.169.254"]),
            1024,
        )
        .unwrap();
        let outcome = transport
            .submit(OpenaiImagesRoute::Generations, "application/json", b"{}")
            .await;
        assert_eq!(outcome, Err(ProviderTransportError::Connect));
    }
}
