//! Shared pinned/vetted HTTPS egress for the image-generation adapters.
//!
//! Every production provider transport (OpenAI Images, OpenRouter, ComfyUI, and
//! Gemini generation) sends its request bytes through the single
//! [`VettedHttpClient`] here so the pinned-connector posture and the billing-safe
//! outcome mapping live in exactly one place rather than being re-derived (and
//! subtly diverging) per provider:
//!
//! * the socket is pinned to a DNS answer set that is vetted **as a whole** to the
//!   required [`AddressClass`] before any byte is sent (one forbidden answer
//!   rejects the whole set, so DNS ordering / rebinding cannot become an SSRF
//!   bypass);
//! * automatic redirects are disabled so no credential-bearing request ever
//!   crosses an origin (every 3xx is a definitive [`ProviderTransportError::Status`]);
//! * an environment/system proxy is refused (`.no_proxy()`);
//! * the process-global rustls provider is pinned before any TLS client is built;
//! * the response body is bounded **while it is read** (see [`read_body_bounded`]),
//!   never after buffering an unbounded response;
//! * the failure classification never widens a post-handoff ambiguity into a safe
//!   pre-handoff class (see [`classify_body_read_failure`] / [`verify_response_peer`]).
//!
//! The credential material a caller passes lives in the [`reqwest::header::HeaderMap`]
//! it hands to [`VettedHttpClient::execute`]; callers mark the credential header
//! sensitive so reqwest keeps it off its own logs. This module never logs, stores,
//! or renders any header value.

use std::net::SocketAddr;
use std::sync::Arc;

use futures::StreamExt as _;
use reqwest::header::HeaderMap;
use reqwest::{Method, Url};

use crate::image_generation::transport::{ProviderTransportError, ProviderTransportOutcome};
use crate::image_generation_runtime::{
    AddressClass, BODY_TIMEOUT, CONNECT_TIMEOUT, DnsResolver, HEADER_TIMEOUT, classify_address,
};

/// Why a provider transport could not be constructed from its endpoint origin.
/// Carries no credential material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderTransportConfigError {
    /// The origin was not a parseable absolute URL.
    InvalidOrigin,
    /// The origin scheme was not `https`.
    NotHttps,
    /// The origin scheme was neither `https` nor (for a local endpoint) `http`.
    UnsupportedScheme,
    /// The origin had no host.
    MissingHost,
    /// The origin carried userinfo, a query, or a fragment.
    ForbiddenOriginComponent,
    /// The supplied credential could not form a valid header value.
    InvalidCredential,
    /// A configured byte bound was zero.
    EmptyBodyLimit,
}

impl std::fmt::Display for ProviderTransportConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidOrigin => "origin is not a valid absolute URL",
            Self::NotHttps => "origin scheme must be https",
            Self::UnsupportedScheme => "origin scheme must be http or https",
            Self::MissingHost => "origin has no host",
            Self::ForbiddenOriginComponent => "origin must not carry userinfo, query, or fragment",
            Self::InvalidCredential => "credential is not a valid header value",
            Self::EmptyBodyLimit => "body limit must be positive",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProviderTransportConfigError {}

/// Reject userinfo, query, and fragment on an origin. Shared by the origin
/// validators of every provider transport.
fn reject_forbidden_origin_components(url: &Url) -> Result<(), ProviderTransportConfigError> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderTransportConfigError::ForbiddenOriginComponent);
    }
    Ok(())
}

/// Validate an `https` public-internet origin: absolute URL, `https` scheme, a
/// host, and no userinfo/query/fragment. Used by the OpenAI, OpenRouter, and
/// Gemini transports (all public-cloud).
pub(crate) fn validate_https_origin(origin: &str) -> Result<Url, ProviderTransportConfigError> {
    let url = Url::parse(origin).map_err(|_| ProviderTransportConfigError::InvalidOrigin)?;
    if url.scheme() != "https" {
        return Err(ProviderTransportConfigError::NotHttps);
    }
    if url.host_str().is_none() {
        return Err(ProviderTransportConfigError::MissingHost);
    }
    reject_forbidden_origin_components(&url)?;
    Ok(url)
}

/// Validate a possibly-local origin: absolute URL, `http` or `https` scheme, a
/// host, and no userinfo/query/fragment. Used by the ComfyUI transport, whose
/// endpoints may be a loopback/LAN server reached over plain `http`. The peer
/// address class is still vetted by [`VettedHttpClient`] against the endpoint's
/// declared location, so allowing `http` here does not widen the egress target
/// set.
pub(crate) fn validate_http_or_https_origin(
    origin: &str,
) -> Result<Url, ProviderTransportConfigError> {
    let url = Url::parse(origin).map_err(|_| ProviderTransportConfigError::InvalidOrigin)?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(ProviderTransportConfigError::UnsupportedScheme);
    }
    if url.host_str().is_none() {
        return Err(ProviderTransportConfigError::MissingHost);
    }
    reject_forbidden_origin_components(&url)?;
    Ok(url)
}

/// A pinned/vetted HTTP client bound to a single required peer location class.
///
/// The client is constructed fresh per request (matching the OpenAI reference
/// and the runtime probe client) so the vetted DNS answer set can be pinned via
/// `resolve_to_addrs` for exactly this request.
pub(crate) struct VettedHttpClient {
    /// Vetted DNS resolver (shared with the runtime probe client).
    dns: Arc<dyn DnsResolver>,
    /// The only address class the socket peer may belong to.
    required_location: AddressClass,
}

impl VettedHttpClient {
    pub(crate) fn new(dns: Arc<dyn DnsResolver>, required_location: AddressClass) -> Self {
        Self {
            dns,
            required_location,
        }
    }

    /// Send one request through the pinned/vetted connector and return the
    /// bounded outcome or a billing-safe [`ProviderTransportError`].
    ///
    /// `url` is the fully-built request URL (origin + path + query). `headers`
    /// carries every request header, including any (sensitive) credential. `body`
    /// is the request body for methods that carry one. `body_limit` bounds the
    /// response body **while it is read**.
    pub(crate) async fn execute(
        &self,
        method: Method,
        url: &Url,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
        body_limit: usize,
    ) -> Result<ProviderTransportOutcome, ProviderTransportError> {
        let host = url
            .host_str()
            .ok_or(ProviderTransportError::Connect)?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or(ProviderTransportError::Connect)?;

        // Resolve and vet the full answer set BEFORE any byte is sent. Reject the
        // whole set if even one answer is outside the required class.
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
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .connect_timeout(CONNECT_TIMEOUT)
            .resolve_to_addrs(&host, &socket_addrs)
            .build()
            .map_err(|_| ProviderTransportError::Tls)?;

        let mut request = client.request(method, url.clone()).headers(headers);
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = match tokio::time::timeout(HEADER_TIMEOUT, request.send()).await {
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
        // bytes may already have been written — fails closed as ambiguous.
        verify_response_peer(
            response.remote_addr(),
            self.required_location,
            &socket_addrs,
        )?;

        let status = response.status();
        let stream = response.bytes_stream();
        let body_bytes =
            match tokio::time::timeout(BODY_TIMEOUT, read_body_bounded(stream, body_limit)).await {
                // Body deadline after a status was received: reconcile.
                Err(_elapsed) => return Err(ProviderTransportError::Timeout),
                Ok(Ok(bytes)) => bytes,
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
            // 3xx (never followed) and 4xx: a definitive non-acceptance.
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
/// widening it to `BodyLimit`/`Malformed` — which an adapter maps to
/// `DefinitivelyRejected` — would let the dispatcher resubmit a paid
/// generation, so it fails closed to `AmbiguousAcceptance`.
pub(crate) fn classify_body_read_failure(
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
/// been written, it fails closed as ambiguous rather than trusting the response.
/// An out-of-set or out-of-class peer is treated the same way.
pub(crate) fn verify_response_peer(
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

/// Why a bounded body read stopped short of success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadBodyError {
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
pub(crate) async fn read_body_bounded<S, B, E>(
    mut stream: S,
    limit: usize,
) -> Result<Vec<u8>, ReadBodyError>
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

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
        // limit, having pulled only a handful of chunks — not all 1000.
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

    #[test]
    fn validate_https_origin_rejects_non_https_and_userinfo() {
        assert_eq!(
            validate_https_origin("http://api.example.test").unwrap_err(),
            ProviderTransportConfigError::NotHttps
        );
        assert_eq!(
            validate_https_origin("https://user:pass@api.example.test").unwrap_err(),
            ProviderTransportConfigError::ForbiddenOriginComponent
        );
        assert_eq!(
            validate_https_origin("not a url").unwrap_err(),
            ProviderTransportConfigError::InvalidOrigin
        );
        assert!(validate_https_origin("https://api.example.test").is_ok());
    }

    #[test]
    fn validate_http_or_https_origin_allows_local_http_but_not_userinfo() {
        assert!(validate_http_or_https_origin("http://127.0.0.1:8188").is_ok());
        assert!(validate_http_or_https_origin("https://comfy.example.test").is_ok());
        assert_eq!(
            validate_http_or_https_origin("ftp://comfy.example.test").unwrap_err(),
            ProviderTransportConfigError::UnsupportedScheme
        );
        assert_eq!(
            validate_http_or_https_origin("http://user:pass@127.0.0.1:8188").unwrap_err(),
            ProviderTransportConfigError::ForbiddenOriginComponent
        );
    }
}
