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
use std::net::SocketAddr;
use std::sync::Arc;

use futures::StreamExt as _;
use reqwest::Url;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};

use super::{OpenaiImagesRoute, OpenaiImagesTransport, openai_images_adapter_sealed};
use crate::image_generation::transport::{ProviderTransportError, ProviderTransportOutcome};
use crate::image_generation_runtime::{
    AddressClass, BODY_TIMEOUT, CONNECT_TIMEOUT, DnsResolver, HEADER_TIMEOUT, classify_address,
};

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
        let host = url
            .host_str()
            .ok_or(ProviderTransportError::Connect)?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or(ProviderTransportError::Connect)?;

        // Resolve and vet the full answer set BEFORE any byte is sent. Reject
        // the whole set if even one answer is outside the required class, so DNS
        // ordering / rebinding cannot become an SSRF bypass.
        let addresses = self
            .dns
            .resolve(&host)
            .await
            .map_err(|_| ProviderTransportError::Connect)?;
        if addresses.is_empty()
            || addresses
                .iter()
                .any(|ip| classify_address(*ip) != self.required_location)
        {
            return Err(ProviderTransportError::Connect);
        }
        let socket_addrs: Vec<SocketAddr> = addresses
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();

        // Pin the process-global rustls provider before building any TLS client
        // so production never initializes rustls under a foreign default. A
        // conflict fails closed as a pre-handoff (no byte sent) TLS failure.
        if crate::tls_crypto_provider::install_process_default().is_err() {
            return Err(ProviderTransportError::Tls);
        }

        let client = reqwest::Client::builder()
            // An environment/system proxy would bypass the vetted peer set and
            // could receive URL or credential material.
            .no_proxy()
            // No automatic redirects: every 3xx is a stable failure, so a
            // credential-bearing request can never cross an origin boundary.
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .connect_timeout(CONNECT_TIMEOUT)
            // Keep the URL host for Host/SNI/cert checks while dialing only the
            // vetted socket addresses.
            .resolve_to_addrs(&host, &socket_addrs)
            .build()
            .map_err(|_| ProviderTransportError::Tls)?;

        let content_type_value =
            HeaderValue::from_str(content_type).map_err(|_| ProviderTransportError::Connect)?;

        let send = client
            .post(url.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .header(CONTENT_TYPE, content_type_value)
            .body(body.to_vec())
            .send();
        let response = match tokio::time::timeout(HEADER_TIMEOUT, send).await {
            // Deadline after the request was written: ambiguous, must reconcile.
            Err(_elapsed) => return Err(ProviderTransportError::Timeout),
            Ok(Err(error)) => {
                if error.is_connect() {
                    // The connection was never established: no byte accepted.
                    return Err(ProviderTransportError::Tls);
                }
                if error.is_timeout() {
                    return Err(ProviderTransportError::Timeout);
                }
                // The request was written and then failed: ambiguous.
                return Err(ProviderTransportError::AmbiguousAcceptance);
            }
            Ok(Ok(response)) => response,
        };

        // Defense in depth: the socket peer must still be a vetted, in-class
        // address. A missing peer address is unverifiable and — since request
        // bytes may already have been written — fails closed as ambiguous
        // rather than trusting the response (mirroring the runtime probe
        // client, which rejects a `None` peer instead of proceeding).
        verify_response_peer(
            response.remote_addr(),
            self.required_location,
            &socket_addrs,
        )?;

        let status = response.status();
        let stream = response.bytes_stream();
        let body_bytes =
            match tokio::time::timeout(BODY_TIMEOUT, read_body_bounded(stream, self.body_limit))
                .await
            {
                // Body deadline after a status was received: reconcile.
                Err(_elapsed) => return Err(ProviderTransportError::Timeout),
                Ok(Ok(bytes)) => bytes,
                // A body-read failure after a status line is a definitive,
                // safe-to-resubmit non-acceptance only for a 3xx/4xx. On a 2xx
                // (accepted, likely charged) or 5xx (ambiguous) it must widen to
                // ambiguous, never collapse into the safe pre-handoff class.
                Ok(Err(read_error)) => {
                    return Err(classify_body_read_failure(status, read_error));
                }
            };

        let code = status.as_u16();
        if status.is_success() {
            Ok(ProviderTransportOutcome {
                status: code,
                body: body_bytes,
            })
        } else if status.is_server_error() {
            // 5xx: the provider received the request but its disposition is
            // unclear; reconcile rather than assume a definitive rejection.
            Err(ProviderTransportError::AmbiguousAcceptance)
        } else {
            // 3xx (never followed) and 4xx: a definitive non-acceptance with no
            // paid submission.
            Err(ProviderTransportError::Status {
                status: code,
                body: body_bytes,
            })
        }
    }
}

/// Classify a bounded-body read failure that occurred *after* a status line was
/// received, preserving billing safety. A body-read failure is a definitive,
/// safe-to-resubmit non-acceptance only for a 3xx/4xx (no paid submission). For
/// a 2xx (accepted, likely charged) or a 5xx (ambiguous provider disposition),
/// widening it to `BodyLimit`/`Malformed` — which the adapter maps to
/// `DefinitivelyRejected` — would let the dispatcher resubmit a paid
/// generation, so it fails closed to `AmbiguousAcceptance`.
fn classify_body_read_failure(
    status: reqwest::StatusCode,
    error: ReadBodyError,
) -> ProviderTransportError {
    if status.is_success() || status.is_server_error() {
        return ProviderTransportError::AmbiguousAcceptance;
    }
    match error {
        ReadBodyError::Limit => ProviderTransportError::BodyLimit,
        ReadBodyError::Chunk => ProviderTransportError::Malformed,
    }
}

/// Verify the response's socket peer is still a vetted, in-class address. A
/// missing peer address is unverifiable; since request bytes may already have
/// been written, it fails closed as ambiguous rather than trusting the response
/// (the runtime probe client rejects a `None` peer likewise). An out-of-set or
/// out-of-class peer is treated the same way.
fn verify_response_peer(
    peer: Option<SocketAddr>,
    required_location: AddressClass,
    socket_addrs: &[SocketAddr],
) -> Result<(), ProviderTransportError> {
    let Some(peer) = peer else {
        return Err(ProviderTransportError::AmbiguousAcceptance);
    };
    if classify_address(peer.ip()) != required_location
        || !socket_addrs.iter().any(|addr| addr.ip() == peer.ip())
    {
        return Err(ProviderTransportError::AmbiguousAcceptance);
    }
    Ok(())
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

/// Why a bounded body read stopped short of success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadBodyError {
    /// The cumulative body size exceeded the limit.
    Limit,
    /// A chunk could not be read.
    Chunk,
}

/// Reads a chunked body into a `Vec`, enforcing `limit` **while reading**: the
/// stream is stopped and rejected the moment the cumulative size would exceed
/// `limit`, before the offending chunk is buffered and before any further chunk
/// is pulled. This is the single production body-reading funnel; unit tests
/// drive it directly with a synthetic stream.
async fn read_body_bounded<S, B, E>(mut stream: S, limit: usize) -> Result<Vec<u8>, ReadBodyError>
where
    S: futures::Stream<Item = Result<B, E>> + Unpin,
    B: AsRef<[u8]>,
{
    let mut body = Vec::new();
    let mut total = 0usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ReadBodyError::Chunk)?;
        let chunk = chunk.as_ref();
        total = total.checked_add(chunk.len()).ok_or(ReadBodyError::Limit)?;
        if total > limit {
            return Err(ReadBodyError::Limit);
        }
        body.extend_from_slice(chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::IpAddr;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    fn counting_stream(
        chunks: Vec<Vec<u8>>,
        counter: Arc<AtomicUsize>,
    ) -> impl futures::Stream<Item = Result<Vec<u8>, ()>> + Unpin {
        futures::stream::iter(chunks.into_iter().map(Ok)).map(move |item| {
            counter.fetch_add(1, Ordering::SeqCst);
            item
        })
    }

    #[tokio::test]
    async fn read_body_bounded_rejects_oversize_while_reading() {
        // 1000 chunks of 1 KiB each = ~1 MiB available, but the limit is 4 KiB.
        // A correct implementation stops the moment cumulative size crosses the
        // limit, having pulled only a handful of chunks — not all 1000. A
        // buffer-then-check implementation would pull every chunk.
        let counter = Arc::new(AtomicUsize::new(0));
        let chunks: Vec<Vec<u8>> = (0..1000).map(|_| vec![7u8; 1024]).collect();
        let stream = counting_stream(chunks, counter.clone());
        let result = read_body_bounded(stream, 4 * 1024).await;
        assert_eq!(result, Err(ReadBodyError::Limit));
        let pulled = counter.load(Ordering::SeqCst);
        assert!(
            pulled <= 6,
            "expected the read to short-circuit within a few chunks, pulled {pulled}"
        );
    }

    #[tokio::test]
    async fn read_body_bounded_accepts_exactly_at_limit() {
        let counter = Arc::new(AtomicUsize::new(0));
        let chunks = vec![vec![1u8; 512], vec![2u8; 512]];
        let stream = counting_stream(chunks, counter.clone());
        let body = read_body_bounded(stream, 1024).await.unwrap();
        assert_eq!(body.len(), 1024);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn read_body_bounded_rejects_one_byte_over_limit() {
        let counter = Arc::new(AtomicUsize::new(0));
        let chunks = vec![vec![1u8; 1024], vec![2u8; 1]];
        let stream = counting_stream(chunks, counter.clone());
        let result = read_body_bounded(stream, 1024).await;
        assert_eq!(result, Err(ReadBodyError::Limit));
    }

    // --- billing-safety: post-status body-read failure classification ---

    #[test]
    fn body_read_failure_on_2xx_is_ambiguous_not_definitive_reject() {
        // A 2xx means the provider accepted (and likely charged); a body-read
        // failure must NOT collapse into a safe-to-resubmit rejection, or the
        // dispatcher could duplicate a paid generation.
        assert_eq!(
            classify_body_read_failure(reqwest::StatusCode::OK, ReadBodyError::Limit),
            ProviderTransportError::AmbiguousAcceptance
        );
        assert_eq!(
            classify_body_read_failure(reqwest::StatusCode::CREATED, ReadBodyError::Chunk),
            ProviderTransportError::AmbiguousAcceptance
        );
    }

    #[test]
    fn body_read_failure_on_5xx_is_ambiguous() {
        assert_eq!(
            classify_body_read_failure(
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                ReadBodyError::Limit
            ),
            ProviderTransportError::AmbiguousAcceptance
        );
        assert_eq!(
            classify_body_read_failure(reqwest::StatusCode::BAD_GATEWAY, ReadBodyError::Chunk),
            ProviderTransportError::AmbiguousAcceptance
        );
    }

    #[test]
    fn body_read_failure_on_3xx_4xx_is_definitive_non_acceptance() {
        // 3xx (never followed) and 4xx are definitive non-acceptances with no
        // paid submission: preserving BodyLimit/Malformed (→ DefinitivelyRejected)
        // is billing-safe.
        assert_eq!(
            classify_body_read_failure(reqwest::StatusCode::BAD_REQUEST, ReadBodyError::Limit),
            ProviderTransportError::BodyLimit
        );
        assert_eq!(
            classify_body_read_failure(reqwest::StatusCode::FOUND, ReadBodyError::Chunk),
            ProviderTransportError::Malformed
        );
    }

    // --- fail-closed response-peer verification ---

    #[test]
    fn response_peer_missing_addr_fails_closed_ambiguous() {
        let vetted: Vec<SocketAddr> = vec!["93.184.216.34:443".parse().unwrap()];
        assert_eq!(
            verify_response_peer(None, AddressClass::PublicRemote, &vetted),
            Err(ProviderTransportError::AmbiguousAcceptance)
        );
    }

    #[test]
    fn response_peer_outside_vetted_set_is_ambiguous() {
        // In-class but not a dialed address: still fail closed.
        let vetted: Vec<SocketAddr> = vec!["93.184.216.34:443".parse().unwrap()];
        let rogue: SocketAddr = "1.1.1.1:443".parse().unwrap();
        assert_eq!(classify_address(rogue.ip()), AddressClass::PublicRemote);
        assert_eq!(
            verify_response_peer(Some(rogue), AddressClass::PublicRemote, &vetted),
            Err(ProviderTransportError::AmbiguousAcceptance)
        );
    }

    #[test]
    fn response_peer_in_vetted_public_set_is_accepted() {
        let good: SocketAddr = "93.184.216.34:443".parse().unwrap();
        assert_eq!(classify_address(good.ip()), AddressClass::PublicRemote);
        let vetted = vec![good];
        assert_eq!(
            verify_response_peer(Some(good), AddressClass::PublicRemote, &vetted),
            Ok(())
        );
    }
}
