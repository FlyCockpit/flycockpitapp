//! HTTPS retained-media ingress policy.
//!
//! Resolution and connection planning deliberately share this private module:
//! callers cannot turn a checked host back into a hostname-only request which
//! the HTTP stack could resolve a second time.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use futures::StreamExt as _;
use reqwest::Url;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncWrite, AsyncWriteExt as _};

const MAX_REDIRECTS: u8 = 5;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETAINED_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HttpsFetchLimits {
    pub(crate) timeout: Duration,
    pub(crate) max_bytes: u64,
}

impl Default for HttpsFetchLimits {
    fn default() -> Self {
        Self {
            timeout: FETCH_TIMEOUT,
            max_bytes: MAX_RETAINED_BYTES,
        }
    }
}

/// A single HTTP hop whose socket peer is one of the answers checked below.
/// Fields are private so no hostname-only request can be constructed from it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VettedHttpsHop {
    url: Url,
    socket_addrs: Vec<SocketAddr>,
    redirect_depth: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) enum RedirectLocationClass {
    SameOrigin,
    CrossOrigin,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct RedactedHttpsProvenance {
    pub(crate) redirect_classes: Vec<RedirectLocationClass>,
    pub(crate) path_segment_count: u32,
    pub(crate) safe_basename: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedHttpsFetchEvidence {
    pub(crate) byte_length: u64,
    pub(crate) sha256: String,
    pub(crate) provenance: RedactedHttpsProvenance,
}

#[async_trait]
pub(crate) trait HttpsDnsResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>>;
}

pub(crate) struct SystemHttpsDnsResolver;

#[async_trait]
impl HttpsDnsResolver for SystemHttpsDnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let mut answers = tokio::net::lookup_host((host, port))
            .await
            .context("resolve retained-media HTTPS host")?
            .map(|address| address.ip())
            .collect::<Vec<_>>();
        answers.sort_unstable();
        answers.dedup();
        Ok(answers)
    }
}

#[async_trait]
pub(crate) trait HttpsMediaFetcher: Send + Sync {
    async fn fetch(
        &self,
        raw_url: &str,
        sink: &mut (dyn AsyncWrite + Unpin + Send),
        limits: &HttpsFetchLimits,
    ) -> Result<RetainedHttpsFetchEvidence>;
}

/// In-memory HTTPS body sink. Tool admission fetches here first so a DNS,
/// redirect, timeout, or non-success denial cannot reserve private storage.
#[derive(Default)]
pub(crate) struct MemoryHttpsSink(Vec<u8>);

impl MemoryHttpsSink {
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsyncWrite for MemoryHttpsSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().0.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct SystemHttpsMediaFetcher;

#[async_trait]
trait HttpsHopExecutor: Send + Sync {
    async fn execute(
        &self,
        hop: &VettedHttpsHop,
        limits: &HttpsFetchLimits,
    ) -> Result<reqwest::Response>;
}

struct ReqwestHttpsHopExecutor;

#[async_trait]
impl HttpsHopExecutor for ReqwestHttpsHopExecutor {
    async fn execute(
        &self,
        hop: &VettedHttpsHop,
        limits: &HttpsFetchLimits,
    ) -> Result<reqwest::Response> {
        hop.bound_client(limits)?
            .get(hop.url().clone())
            .send()
            .await
            .context("execute retained-media HTTPS request")
    }
}

#[async_trait]
impl HttpsMediaFetcher for SystemHttpsMediaFetcher {
    async fn fetch(
        &self,
        raw_url: &str,
        sink: &mut (dyn AsyncWrite + Unpin + Send),
        limits: &HttpsFetchLimits,
    ) -> Result<RetainedHttpsFetchEvidence> {
        fetch_retained_https(raw_url, &SystemHttpsDnsResolver, sink, limits).await
    }
}

/// Fetch a retained object into a caller-owned held sink. The caller must fsync,
/// reopen, and verify its storage identity before publication; this function
/// supplies only the network byte proof.
pub(crate) async fn fetch_retained_https<W: AsyncWrite + Unpin + ?Sized>(
    raw_url: &str,
    resolver: &dyn HttpsDnsResolver,
    sink: &mut W,
    limits: &HttpsFetchLimits,
) -> Result<RetainedHttpsFetchEvidence> {
    tokio::time::timeout(
        limits.timeout,
        fetch_retained_https_before_deadline(raw_url, resolver, sink, limits),
    )
    .await
    .context("retained-media HTTPS fetch timed out")?
}

async fn fetch_retained_https_before_deadline<W: AsyncWrite + Unpin + ?Sized>(
    raw_url: &str,
    resolver: &dyn HttpsDnsResolver,
    sink: &mut W,
    limits: &HttpsFetchLimits,
) -> Result<RetainedHttpsFetchEvidence> {
    fetch_retained_https_with_executor(raw_url, resolver, sink, limits, &ReqwestHttpsHopExecutor)
        .await
}

async fn fetch_retained_https_with_executor<W: AsyncWrite + Unpin + ?Sized>(
    raw_url: &str,
    resolver: &dyn HttpsDnsResolver,
    sink: &mut W,
    limits: &HttpsFetchLimits,
    executor: &dyn HttpsHopExecutor,
) -> Result<RetainedHttpsFetchEvidence> {
    let initial_url = parse_fetch_url(raw_url)?;
    let answers = resolve_url(resolver, &initial_url).await?;
    let mut hop = vetted_hop(initial_url, &answers, 0)?;
    let mut provenance = RedactedHttpsProvenance::initial(&hop)?;

    loop {
        let response = executor.execute(&hop, limits).await?;
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .context("HTTPS redirect is missing Location")?
                .to_str()
                .context("HTTPS redirect Location is not text")?;
            let next_url = hop
                .url
                .join(location)
                .context("invalid HTTPS redirect location")?;
            validate_url(&next_url)?;
            let answers = resolve_url(resolver, &next_url).await?;
            let next = redirected_https_hop(&hop, location, &answers)?;
            provenance.record_redirect(&hop, &next)?;
            hop = next;
            continue;
        }
        ensure!(
            response.status().is_success(),
            "HTTPS media source returned a non-success status"
        );
        checked_content_length(response.content_length(), limits)?;
        let mut length = 0_u64;
        let mut hasher = Sha256::new();
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.context("read retained-media HTTPS body")?;
            length = checked_body_progress(length, chunk.len(), limits)?;
            hasher.update(&chunk);
            sink.write_all(&chunk)
                .await
                .context("write retained-media quarantine")?;
        }
        ensure!(length > 0, "empty retained media is forbidden");
        sink.flush()
            .await
            .context("flush retained-media quarantine")?;
        return Ok(RetainedHttpsFetchEvidence {
            byte_length: length,
            sha256: crate::intel::hex_lower(&hasher.finalize()),
            provenance,
        });
    }
}

async fn resolve_url(resolver: &dyn HttpsDnsResolver, url: &Url) -> Result<Vec<IpAddr>> {
    let host = url.host_str().context("HTTPS URL has no host")?;
    let port = url
        .port_or_known_default()
        .context("HTTPS URL has no port")?;
    resolver.resolve(host, port).await
}

impl RedactedHttpsProvenance {
    pub(crate) fn initial(hop: &VettedHttpsHop) -> Result<Self> {
        let (path_segment_count, safe_basename) = redacted_path_shape(&hop.url)?;
        Ok(Self {
            redirect_classes: Vec::new(),
            path_segment_count,
            safe_basename,
        })
    }

    pub(crate) fn record_redirect(
        &mut self,
        previous: &VettedHttpsHop,
        next: &VettedHttpsHop,
    ) -> Result<()> {
        ensure!(
            self.redirect_classes.len() < usize::from(MAX_REDIRECTS),
            "too many redirects"
        );
        self.redirect_classes
            .push(if origin(&previous.url) == origin(&next.url) {
                RedirectLocationClass::SameOrigin
            } else {
                RedirectLocationClass::CrossOrigin
            });
        let (path_segment_count, safe_basename) = redacted_path_shape(&next.url)?;
        self.path_segment_count = path_segment_count;
        self.safe_basename = safe_basename;
        Ok(())
    }
}

impl VettedHttpsHop {
    pub(crate) fn url(&self) -> &Url {
        &self.url
    }

    #[cfg(test)]
    pub(crate) fn socket_addrs(&self) -> &[SocketAddr] {
        &self.socket_addrs
    }

    /// Build the only HTTP client permitted to execute this hop. Redirects are
    /// disabled because each Location must return through `redirected_https_hop`.
    /// Reqwest keeps the URL hostname for Host and TLS SNI while dialing only
    /// the supplied socket addresses.
    pub(crate) fn bound_client(&self, limits: &HttpsFetchLimits) -> Result<reqwest::Client> {
        // Pin the process-global rustls provider to `aws_lc_rs` before building
        // any rustls-backed client, so production retained-media HTTPS never
        // initializes rustls under an implicitly-selected or foreign
        // process-default provider. Fail closed on a provider conflict.
        crate::tls_crypto_provider::install_process_default()
            .context("install aws_lc_rs rustls crypto provider for retained-media HTTPS")?;
        let host = self.url.host_str().context("vetted HTTPS hop lost host")?;
        self.bound_client_builder(limits)
            .resolve_to_addrs(host, &self.socket_addrs)
            .build()
            .context("build connection-bound HTTPS media client")
    }

    fn bound_client_builder(&self, limits: &HttpsFetchLimits) -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            // An environment/system proxy would bypass the vetted peer set
            // and could also receive URL or credential material.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .timeout(limits.timeout)
    }

    #[cfg(test)]
    fn bound_client_with_test_root(
        &self,
        limits: &HttpsFetchLimits,
        certificate_der: &[u8],
    ) -> Result<reqwest::Client> {
        let host = self.url.host_str().context("vetted HTTPS hop lost host")?;
        self.bound_client_builder(limits)
            .add_root_certificate(reqwest::Certificate::from_der(certificate_der)?)
            .resolve_to_addrs(host, &self.socket_addrs)
            .build()
            .context("build connection-bound HTTPS media client")
    }
}

#[cfg(test)]
pub(crate) fn initial_https_hop(url: &str, answers: &[IpAddr]) -> Result<VettedHttpsHop> {
    let url = parse_fetch_url(url)?;
    vetted_hop(url, answers, 0)
}

pub(crate) fn redirected_https_hop(
    previous: &VettedHttpsHop,
    location: &str,
    answers: &[IpAddr],
) -> Result<VettedHttpsHop> {
    ensure!(
        previous.redirect_depth < MAX_REDIRECTS,
        "too many redirects"
    );
    let url = previous
        .url
        .join(location)
        .context("invalid HTTPS redirect location")?;
    validate_url(&url)?;
    vetted_hop(url, answers, previous.redirect_depth + 1)
}

/// Policy admission for a retained-HTTPS URL.
///
/// Validates scheme, host, and userinfo/fragment bans, and applies the SSRF
/// destination check when the host is already an IP literal. This is
/// metadata-only: no DNS, fetch, content open, or storage reservation.
/// Hostname DNS, redirect hops, timeouts, and non-success are enforced inside
/// the subsequent fetch, which tool admission runs against an in-memory sink
/// before any private storage reservation.
pub(crate) fn preflight_retained_https_url(raw_url: &str) -> Result<()> {
    let url = parse_fetch_url(raw_url)?;
    if let Some(host) = url.host_str()
        && let Ok(ip) = host.parse::<IpAddr>()
    {
        let _ = vetted_hop(url, &[ip], 0)?;
    }
    Ok(())
}

fn parse_fetch_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("invalid retained-media URL")?;
    validate_url(&url)?;
    Ok(url)
}

fn validate_url(url: &Url) -> Result<()> {
    ensure!(url.scheme() == "https", "retained media requires HTTPS");
    ensure!(url.host_str().is_some(), "HTTPS URL has no host");
    ensure!(url.username().is_empty(), "URL userinfo is forbidden");
    ensure!(url.password().is_none(), "URL userinfo is forbidden");
    ensure!(url.fragment().is_none(), "URL fragments are forbidden");
    Ok(())
}

fn vetted_hop(url: Url, answers: &[IpAddr], redirect_depth: u8) -> Result<VettedHttpsHop> {
    ensure!(!answers.is_empty(), "HTTPS host has no addresses");
    // Reject the complete answer set when even one answer is unsafe. Choosing
    // only a public member would leave DNS-order/retry behavior as an SSRF
    // bypass and would make rebinding behavior client-dependent.
    ensure!(
        answers.iter().all(|ip| is_public_destination(*ip)),
        "HTTPS host resolved to a forbidden destination"
    );
    let port = url
        .port_or_known_default()
        .context("HTTPS URL has no port")?;
    let socket_addrs = answers
        .iter()
        .copied()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    Ok(VettedHttpsHop {
        url,
        socket_addrs,
        redirect_depth,
    })
}

fn origin(url: &Url) -> (&str, &str, u16) {
    (
        url.scheme(),
        url.host_str().expect("validated URL has host"),
        url.port_or_known_default()
            .expect("validated HTTPS has port"),
    )
}

fn redacted_path_shape(url: &Url) -> Result<(u32, Option<String>)> {
    let segments = url
        .path_segments()
        .context("HTTPS URL cannot carry path segments")?;
    let segments = segments
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let count = u32::try_from(segments.len()).context("HTTPS URL has too many path segments")?;
    let basename = segments.last().and_then(|segment| {
        let safe = segment
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
            .take(128)
            .collect::<String>();
        (!safe.is_empty()).then_some(safe)
    });
    Ok((count, basename))
}

fn is_public_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    !is_forbidden_v4(ip)
}

fn is_forbidden_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let octets = ip.octets();
    if let Some(v4) = ip.to_ipv4() {
        return is_public_v4(v4);
    }
    // Ordinary 2000::/3 global unicast only. Translation, ULA, link/site-local,
    // discard-only and multicast prefixes consequently never reach a socket.
    if octets[0] & 0xe0 != 0x20 {
        return false;
    }
    !is_forbidden_v6_segments(ip.segments())
}

fn is_forbidden_v6_segments(segments: [u16; 8]) -> bool {
    (segments[1] < 0x0200 || segments[1] == 0x0db8) && segments[0] == 0x2001 // IETF special assignments /23 and documentation /32
        || segments[0] == 0x2002 // 6to4 embeds an unchecked IPv4 destination
        || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0) // documentation /20
}

pub(crate) fn checked_content_length(value: Option<u64>, limits: &HttpsFetchLimits) -> Result<()> {
    if let Some(value) = value {
        ensure!(value > 0, "empty retained media is forbidden");
        ensure!(
            value <= limits.max_bytes,
            "retained media exceeds byte limit"
        );
    }
    Ok(())
}

pub(crate) fn checked_body_progress(
    total: u64,
    chunk: usize,
    limits: &HttpsFetchLimits,
) -> Result<u64> {
    let chunk = u64::try_from(chunk).context("body chunk length overflow")?;
    let next = total.checked_add(chunk).context("body length overflow")?;
    if next > limits.max_bytes {
        bail!("retained media exceeds byte limit");
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_test_crypto_provider() {
        // Process-global rustls provider is `aws_lc_rs` (USER-SETTLED); share
        // the one install helper so media HTTPS tests never claim `ring`.
        crate::tls_crypto_provider::install_for_tests();
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn preflight_rejects_non_https_and_userinfo_without_dns() {
        assert!(preflight_retained_https_url("http://example.com/x").is_err());
        assert!(preflight_retained_https_url("https://user@example.com/x").is_err());
        assert!(preflight_retained_https_url("https://example.com/x#frag").is_err());
        assert!(preflight_retained_https_url("https://127.0.0.1/private").is_err());
        assert!(preflight_retained_https_url("https://example.com/ok").is_ok());
    }

    struct LoopbackDns;

    #[async_trait]
    impl HttpsDnsResolver for LoopbackDns {
        async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>> {
            Ok(vec![ip("127.0.0.1")])
        }
    }

    #[tokio::test]
    async fn hostname_resolving_to_loopback_writes_no_body() {
        assert!(preflight_retained_https_url("https://example.com/ok").is_ok());
        let mut sink = MemoryHttpsSink::default();
        let error = fetch_retained_https(
            "https://example.com/ok",
            &LoopbackDns,
            &mut sink,
            &HttpsFetchLimits::default(),
        )
        .await
        .expect_err("hostname SSRF must fail closed after DNS");
        assert!(
            error.to_string().contains("forbidden destination"),
            "{error:#}"
        );
        assert!(
            sink.as_slice().is_empty(),
            "hostname SSRF must not write a body before reservation"
        );
    }

    fn request_header_values<'a>(request: &'a str, name: &str) -> Vec<&'a str> {
        request
            .split("\r\n")
            .skip(1)
            .take_while(|line| !line.is_empty())
            .filter_map(|line| line.split_once(':'))
            .filter_map(|(header_name, value)| {
                header_name
                    .eq_ignore_ascii_case(name)
                    .then_some(value.trim())
            })
            .collect()
    }

    // Non-vacuous under nextest's process-per-test isolation: this test does
    // NOT pre-install a provider (it must not call `install_test_crypto_provider`)
    // and reqwest's own config build does not install a process default, so a
    // provider becomes the process default ONLY because `bound_client` installs
    // it. Removing the `install_process_default()` call from `bound_client`
    // leaves `get_default() == None` and fails this test.
    #[test]
    fn bound_client_installs_process_crypto_provider() {
        let hop = initial_https_hop("https://media.example.test/a", &[ip("93.184.216.34")])
            .expect("vetted hop");
        let _client = hop
            .bound_client(&HttpsFetchLimits::default())
            .expect("bound_client builds");
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "bound_client() must install the process-global rustls crypto provider"
        );
    }

    #[test]
    fn https_media_ingest_binds_every_vetted_dns_answer_to_socket_plan() {
        let hop = initial_https_hop(
            "https://media.example.test/a",
            &[
                ip("93.184.216.34"),
                ip("2606:2800:220:1:248:1893:25c8:1946"),
            ],
        )
        .unwrap();
        assert_eq!(
            hop.socket_addrs(),
            &[
                "93.184.216.34:443".parse::<std::net::SocketAddr>().unwrap(),
                "[2606:2800:220:1:248:1893:25c8:1946]:443"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
            ]
        );
        assert_eq!(hop.url().host_str(), Some("media.example.test"));
    }

    #[test]
    fn https_media_ingest_rejects_mixed_or_rebound_answers() {
        assert!(
            initial_https_hop(
                "https://media.example.test/a",
                &[ip("93.184.216.34"), ip("127.0.0.1")]
            )
            .is_err()
        );
        let first =
            initial_https_hop("https://media.example.test/a", &[ip("93.184.216.34")]).unwrap();
        assert!(redirected_https_hop(&first, "/b", &[ip("169.254.169.254")]).is_err());
    }

    #[test]
    fn https_media_ingest_redirect_revalidates_scheme_without_credentials() {
        let first =
            initial_https_hop("https://media.example.test/a", &[ip("93.184.216.34")]).unwrap();
        let same = redirected_https_hop(&first, "/b", &[ip("93.184.216.34")]).unwrap();
        let other =
            redirected_https_hop(&same, "https://cdn.example.test/c", &[ip("93.184.216.35")])
                .unwrap();
        assert_eq!(other.url().host_str(), Some("cdn.example.test"));
        let request = other
            .bound_client(&HttpsFetchLimits::default())
            .unwrap()
            .get(other.url().clone())
            .build()
            .unwrap();
        assert!(
            !request
                .headers()
                .contains_key(reqwest::header::AUTHORIZATION)
        );
        assert!(!request.headers().contains_key(reqwest::header::COOKIE));
        assert!(
            redirected_https_hop(
                &first,
                "http://media.example.test/b",
                &[ip("93.184.216.34")]
            )
            .is_err()
        );
    }

    #[test]
    fn https_media_ingest_timeout_and_size_limits_are_closed_without_network() {
        let limits = HttpsFetchLimits {
            timeout: Duration::from_millis(1),
            max_bytes: 4,
        };
        assert_eq!(limits.timeout, Duration::from_millis(1));
        checked_content_length(Some(4), &limits).unwrap();
        assert!(checked_content_length(Some(5), &limits).is_err());
        assert_eq!(checked_body_progress(2, 2, &limits).unwrap(), 4);
        assert!(checked_body_progress(4, 1, &limits).is_err());
    }

    #[test]
    fn https_media_ingest_rejects_url_credentials_fragments_and_reserved_ranges() {
        for url in [
            "http://example.test/a",
            "https://user@example.test/a",
            "https://example.test/a#secret",
        ] {
            assert!(
                initial_https_hop(url, &[ip("93.184.216.34")]).is_err(),
                "{url}"
            );
        }
        for address in [
            "10.0.0.1",
            "100.64.0.1",
            "192.168.0.1",
            "192.88.99.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::7f00:1",
            "fec0::1",
            "2001::1",
            "2001:2::1",
            "2002:7f00:1::1",
            "3fff::1",
        ] {
            assert!(
                initial_https_hop("https://example.test/a", &[ip(address)]).is_err(),
                "{address}"
            );
        }
        initial_https_hop("https://example.test/a", &[ip("2606:4700:4700::1111")]).unwrap();
    }

    #[test]
    fn https_media_ingest_provenance_never_retains_origin_query_or_fragment() {
        let first = initial_https_hop(
            "https://secret.example.test/private/a.png?token=signed",
            &[ip("93.184.216.34")],
        )
        .unwrap();
        let mut provenance = RedactedHttpsProvenance::initial(&first).unwrap();
        let next = redirected_https_hop(
            &first,
            "https://cdn.example.test/final/b.webp?other=secret",
            &[ip("93.184.216.35")],
        )
        .unwrap();
        provenance.record_redirect(&first, &next).unwrap();
        assert_eq!(
            provenance.redirect_classes,
            vec![RedirectLocationClass::CrossOrigin]
        );
        assert_eq!(provenance.path_segment_count, 2);
        assert_eq!(provenance.safe_basename.as_deref(), Some("b.webp"));
        let debug = format!("{provenance:?}");
        for forbidden in [
            "secret.example",
            "cdn.example",
            "token",
            "signed",
            "other=",
            "private/",
        ] {
            assert!(!debug.contains(forbidden));
        }
    }

    #[tokio::test]
    async fn https_media_ingest_tls_socket_uses_pinned_peer_and_original_host_sni() {
        install_test_crypto_provider();
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio_rustls::TlsAcceptor;

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["pinned.example.test".into()]).unwrap();
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, observed_peer) = listener.accept().await.unwrap();
            assert_eq!(observed_peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            let mut tls = TlsAcceptor::from(Arc::new(server))
                .accept(socket)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.server_name(), Some("pinned.example.test"));
            let mut request = vec![0; 4096];
            let length = tls.read(&mut request).await.unwrap();
            let request = String::from_utf8(request[..length].to_vec()).unwrap();
            assert_eq!(
                request_header_values(&request, "host"),
                [format!("pinned.example.test:{}", peer.port())]
            );
            assert!(request_header_values(&request, "authorization").is_empty());
            assert!(request_header_values(&request, "cookie").is_empty());
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        // Construction is normally possible only through vetted_hop. The
        // loopback peer here is a hermetic stand-in proving that its exact
        // SocketAddr is dialed while URL authority remains Host/TLS SNI.
        let hop = VettedHttpsHop {
            url: Url::parse(&format!(
                "https://pinned.example.test:{}/media",
                peer.port()
            ))
            .unwrap(),
            socket_addrs: vec![peer],
            redirect_depth: 0,
        };
        let response = hop
            .bound_client_with_test_root(&HttpsFetchLimits::default(), cert.der().as_ref())
            .unwrap()
            .get(hop.url().clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn https_media_ingest_tls_redirect_reresolves_and_dials_each_vetted_set() {
        install_test_crypto_provider();
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use std::{
            collections::HashMap,
            sync::{Arc, Mutex},
        };
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio_rustls::TlsAcceptor;
        struct Resolver(Mutex<Vec<String>>);
        #[async_trait]
        impl HttpsDnsResolver for Resolver {
            async fn resolve(&self, host: &str, _: u16) -> Result<Vec<IpAddr>> {
                self.0.lock().unwrap().push(host.into());
                Ok(vec![if host == "a.example.test" {
                    ip("93.184.216.34")
                } else {
                    ip("93.184.216.35")
                }])
            }
        }
        struct Executor {
            roots: Vec<u8>,
            peers: HashMap<String, SocketAddr>,
            vetted: Mutex<Vec<Vec<SocketAddr>>>,
        }
        #[async_trait]
        impl HttpsHopExecutor for Executor {
            async fn execute(
                &self,
                hop: &VettedHttpsHop,
                limits: &HttpsFetchLimits,
            ) -> Result<reqwest::Response> {
                self.vetted.lock().unwrap().push(hop.socket_addrs.clone());
                let host = hop.url.host_str().unwrap();
                let peer = *self.peers.get(host).unwrap();
                self.bound(hop, limits, peer)?
                    .get(hop.url.clone())
                    .send()
                    .await
                    .map_err(Into::into)
            }
        }
        impl Executor {
            fn bound(
                &self,
                hop: &VettedHttpsHop,
                limits: &HttpsFetchLimits,
                peer: SocketAddr,
            ) -> Result<reqwest::Client> {
                let host = hop.url.host_str().unwrap();
                hop.bound_client_builder(limits)
                    .add_root_certificate(reqwest::Certificate::from_der(&self.roots)?)
                    .resolve_to_addrs(host, &[peer])
                    .build()
                    .map_err(Into::into)
            }
        }
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["a.example.test".into(), "b.example.test".into()])
                .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
        let a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ap = a.local_addr().unwrap();
        let b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bp = b.local_addr().unwrap();
        let serve = |listener: tokio::net::TcpListener,
                     config: rustls::ServerConfig,
                     name: &'static str,
                     response: String| {
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut tls = TlsAcceptor::from(Arc::new(config))
                    .accept(socket)
                    .await
                    .unwrap();
                assert_eq!(tls.get_ref().1.server_name(), Some(name));
                let mut bytes = vec![0; 4096];
                let n = tls.read(&mut bytes).await.unwrap();
                let text = String::from_utf8(bytes[..n].to_vec()).unwrap();
                assert_eq!(
                    request_header_values(&text, "host"),
                    [format!("{name}:{port}")]
                );
                assert!(request_header_values(&text, "authorization").is_empty());
                assert!(request_header_values(&text, "cookie").is_empty());
                tls.write_all(response.as_bytes()).await.unwrap()
            })
        };
        let sa = serve(
            a,
            config.clone(),
            "a.example.test",
            format!(
                "HTTP/1.1 302 Found\r\nLocation: https://b.example.test:{}/final\r\nContent-Length: 0\r\n\r\n",
                bp.port()
            ),
        );
        let sb = serve(
            b,
            config,
            "b.example.test",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into(),
        );
        let resolver = Resolver(Mutex::new(Vec::new()));
        let executor = Executor {
            roots: cert.der().as_ref().to_vec(),
            peers: HashMap::from([("a.example.test".into(), ap), ("b.example.test".into(), bp)]),
            vetted: Mutex::new(Vec::new()),
        };
        let (mut sink, mut source) = tokio::io::duplex(16);
        let drain = tokio::spawn(async move {
            let mut body = Vec::new();
            source.read_to_end(&mut body).await.unwrap();
            body
        });
        let evidence = fetch_retained_https_with_executor(
            &format!("https://a.example.test:{}/start", ap.port()),
            &resolver,
            &mut sink,
            &HttpsFetchLimits::default(),
            &executor,
        )
        .await
        .unwrap();
        drop(sink);
        assert_eq!(drain.await.unwrap(), b"ok");
        assert_eq!(evidence.byte_length, 2);
        assert_eq!(
            *resolver.0.lock().unwrap(),
            vec!["a.example.test", "b.example.test"]
        );
        assert_eq!(
            *executor.vetted.lock().unwrap(),
            vec![
                vec![
                    format!("93.184.216.34:{}", ap.port())
                        .parse::<std::net::SocketAddr>()
                        .unwrap()
                ],
                vec![
                    format!("93.184.216.35:{}", bp.port())
                        .parse::<std::net::SocketAddr>()
                        .unwrap()
                ]
            ]
        );
        sa.await.unwrap();
        sb.await.unwrap();
    }
}
