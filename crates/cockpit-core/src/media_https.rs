//! HTTPS retained-media ingress policy.
//!
//! Resolution and connection planning deliberately share this private module:
//! callers cannot turn a checked host back into a hostname-only request which
//! the HTTP stack could resolve a second time.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
        sink: &mut tokio::fs::File,
        limits: &HttpsFetchLimits,
    ) -> Result<RetainedHttpsFetchEvidence>;
}

pub(crate) struct SystemHttpsMediaFetcher;

#[async_trait]
impl HttpsMediaFetcher for SystemHttpsMediaFetcher {
    async fn fetch(
        &self,
        raw_url: &str,
        sink: &mut tokio::fs::File,
        limits: &HttpsFetchLimits,
    ) -> Result<RetainedHttpsFetchEvidence> {
        fetch_retained_https(raw_url, &SystemHttpsDnsResolver, sink, limits).await
    }
}

/// Fetch a retained object into a caller-owned held sink. The caller must fsync,
/// reopen, and verify its storage identity before publication; this function
/// supplies only the network byte proof.
pub(crate) async fn fetch_retained_https<W: AsyncWrite + Unpin>(
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

async fn fetch_retained_https_before_deadline<W: AsyncWrite + Unpin>(
    raw_url: &str,
    resolver: &dyn HttpsDnsResolver,
    sink: &mut W,
    limits: &HttpsFetchLimits,
) -> Result<RetainedHttpsFetchEvidence> {
    let initial_url = parse_fetch_url(raw_url)?;
    let answers = resolve_url(resolver, &initial_url).await?;
    let mut hop = vetted_hop(initial_url, &answers, 0)?;
    let mut provenance = RedactedHttpsProvenance::initial(&hop)?;

    loop {
        let response = hop
            .bound_client(limits)?
            .get(hop.url().clone())
            .send()
            .await
            .context("execute retained-media HTTPS request")?;
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

    pub(crate) fn socket_addrs(&self) -> &[SocketAddr] {
        &self.socket_addrs
    }

    /// Build the only HTTP client permitted to execute this hop. Redirects are
    /// disabled because each Location must return through `redirected_https_hop`.
    /// Reqwest keeps the URL hostname for Host and TLS SNI while dialing only
    /// the supplied socket addresses.
    pub(crate) fn bound_client(&self, limits: &HttpsFetchLimits) -> Result<reqwest::Client> {
        let host = self.url.host_str().context("vetted HTTPS hop lost host")?;
        reqwest::Client::builder()
            // An environment/system proxy would bypass the vetted peer set
            // and could also receive URL or credential material.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .timeout(limits.timeout)
            .resolve_to_addrs(host, &self.socket_addrs)
            .build()
            .context("build connection-bound HTTPS media client")
    }
}

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
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
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
    let segments = ip.segments();
    !(segments[0] == 0x2001 && segments[1] < 0x0200 // IETF special assignments /23
        || segments[0] == 0x2002 // 6to4 embeds an unchecked IPv4 destination
        || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0)) // documentation /20
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

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
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
                "93.184.216.34:443".parse().unwrap(),
                "[2606:2800:220:1:248:1893:25c8:1946]:443".parse().unwrap()
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
}
