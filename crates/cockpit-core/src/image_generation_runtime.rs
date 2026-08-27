//! Runtime-only registry, discovery and destination health for image targets.
//! Configuration remains pure; all I/O is behind injected read-only seams.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fmt::Write as _;
use std::future::Future;
use std::net::IpAddr;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use cockpit_config::config::image_generation::{
    ImageAdapterKind, ImageEndpoint, ImageGenerationConfig, ImageLocationClass, ImageTargetIdentity,
};
use futures::{FutureExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialIdentityDigest([u8; 32]);

impl CredentialIdentityDigest {
    pub const fn from_sha256(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn plan_identity_hex(&self) -> String {
        crate::intel::hex_lower(&self.0)
    }
}

impl fmt::Debug for CredentialIdentityDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialIdentityDigest(<redacted>)")
    }
}

pub const SUCCESS_TTL: Duration = Duration::from_secs(30);
pub const FAILURE_TTL: Duration = Duration::from_secs(5);
pub const CAPABILITY_DISPATCH_TTL: Duration = Duration::from_secs(15 * 60);
pub const DISPLAY_STALE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
pub const BODY_TIMEOUT: Duration = Duration::from_secs(15);
pub const DISCOVERY_BODY_LIMIT: usize = 1024 * 1024;
pub const HEALTH_BODY_LIMIT: usize = 256 * 1024;
pub const REDIRECT_LIMIT: usize = 3;

pub trait RuntimeClock: Send + Sync {
    fn now_millis(&self) -> u64;
}

/// Process-monotonic production clock. Wall-clock adjustments cannot make a
/// stale capability appear fresh again.
pub struct SystemRuntimeClock {
    started: Instant,
}

impl Default for SystemRuntimeClock {
    fn default() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl RuntimeClock for SystemRuntimeClock {
    fn now_millis(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefreshKind {
    Health,
    Capabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotProvenance {
    Live,
    Cache,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageHealthState {
    Checking,
    Healthy,
    Stale,
    Unreachable,
    DnsDenied,
    TlsFailed,
    AuthFailed,
    Incompatible,
    WorkflowInvalid,
    Busy,
    Disabled,
    Unknown,
}

impl ImageHealthState {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Checking => "checking",
            Self::Healthy => "healthy",
            Self::Stale => "stale",
            Self::Unreachable => "unreachable",
            Self::DnsDenied => "dns_denied",
            Self::TlsFailed => "tls_failed",
            Self::AuthFailed => "auth_failed",
            Self::Incompatible => "incompatible",
            Self::WorkflowInvalid => "workflow_invalid",
            Self::Busy => "busy",
            Self::Disabled => "disabled",
            Self::Unknown => "unknown",
        }
    }
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::Checking => "Wait for the current check to finish.",
            Self::Healthy => "No action is required.",
            Self::Stale => "Refresh the target before dispatch.",
            Self::Unreachable => "Check the endpoint address and service availability.",
            Self::DnsDenied => {
                "Choose an endpoint whose resolved network location matches its policy."
            }
            Self::TlsFailed => "Check the endpoint certificate and configured hostname.",
            Self::AuthFailed => "Check the configured credential reference.",
            Self::Incompatible => "Choose a compatible provider endpoint.",
            Self::WorkflowInvalid => "Update the registered workflow and its bindings.",
            Self::Busy => "Retry after the provider is less busy.",
            Self::Disabled => "Enable the endpoint and target before dispatch.",
            Self::Unknown => "Run a target health check.",
        }
    }
    const fn successful(self) -> bool {
        matches!(self, Self::Healthy)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeErrorCode {
    AdapterMissing,
    Dns,
    DnsDenied,
    ConnectTimeout,
    HeaderTimeout,
    BodyLimit,
    RedirectLimit,
    Tls,
    Authentication,
    MalformedResponse,
    Incompatible,
    WorkflowInvalid,
    Busy,
    Disabled,
    Obsolete,
}
impl RuntimeErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdapterMissing => "adapter_missing",
            Self::Dns => "dns_failed",
            Self::DnsDenied => "dns_denied",
            Self::ConnectTimeout => "connect_timeout",
            Self::HeaderTimeout => "header_timeout",
            Self::BodyLimit => "body_limit",
            Self::RedirectLimit => "redirect_limit",
            Self::Tls => "tls_failed",
            Self::Authentication => "auth_failed",
            Self::MalformedResponse => "malformed_response",
            Self::Incompatible => "incompatible",
            Self::WorkflowInvalid => "workflow_invalid",
            Self::Busy => "busy",
            Self::Disabled => "disabled",
            Self::Obsolete => "obsolete",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RuntimeError {
    pub code: RuntimeErrorCode,
    pub remediation: &'static str,
}
impl RuntimeError {
    pub const fn new(code: RuntimeErrorCode, remediation: &'static str) -> Self {
        Self { code, remediation }
    }
}
impl fmt::Debug for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeError")
            .field("code", &self.code)
            .field("remediation", &self.remediation)
            .finish()
    }
}
impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.remediation)
    }
}
impl std::error::Error for RuntimeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    Loopback,
    PrivateLan,
    PublicNetwork,
    Forbidden,
}
impl AddressClass {
    /// Stable, storage-facing spelling used for the persisted dispatch proof's
    /// `location_class`. Must stay in lockstep with the CHECK constraint on
    /// `image_generation_attempts.dispatch_proof_location_class`.
    pub fn as_canonical_str(self) -> &'static str {
        match self {
            AddressClass::Loopback => "loopback",
            AddressClass::PrivateLan => "private_lan",
            AddressClass::PublicNetwork => "public_network",
            AddressClass::Forbidden => "forbidden",
        }
    }
}
pub fn classify_address(ip: IpAddr) -> AddressClass {
    if let IpAddr::V6(v6) = ip {
        let octets = v6.octets();
        let embedded = v6.to_ipv4_mapped().or_else(|| {
            // IPv4-compatible, well-known NAT64, and 6to4 addresses must inherit
            // the policy of their embedded IPv4 destination.
            if (octets[..12] == [0; 12]
                && octets[12..] != [0, 0, 0, 0]
                && octets[12..] != [0, 0, 0, 1])
                || octets[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]
            {
                Some(std::net::Ipv4Addr::new(
                    octets[12], octets[13], octets[14], octets[15],
                ))
            } else if octets[0] == 0x20 && octets[1] == 0x02 {
                Some(std::net::Ipv4Addr::new(
                    octets[2], octets[3], octets[4], octets[5],
                ))
            } else {
                None
            }
        });
        if let Some(v4) = embedded {
            return classify_address(IpAddr::V4(v4));
        }
    }
    if ip.is_loopback() {
        AddressClass::Loopback
    } else if match ip {
        IpAddr::V4(v) => {
            v.is_broadcast()
                || v.is_unspecified()
                || v.is_link_local()
                || v.is_documentation()
                || v.is_multicast()
                || (v.octets()[0] == 100 && (64..=127).contains(&v.octets()[1]))
                || (v.octets()[0] == 192 && v.octets()[1] == 0 && v.octets()[2] == 0)
        }
        IpAddr::V6(v) => v.is_unspecified() || v.is_multicast() || v.is_unicast_link_local(),
    } {
        AddressClass::Forbidden
    } else if match ip {
        IpAddr::V4(v) => v.is_private(),
        IpAddr::V6(v) => v.is_unique_local(),
    } {
        AddressClass::PrivateLan
    } else {
        AddressClass::PublicNetwork
    }
}
pub(crate) fn declared_class(class: ImageLocationClass) -> AddressClass {
    match class {
        ImageLocationClass::Local => AddressClass::Loopback,
        ImageLocationClass::PrivateNetwork => AddressClass::PrivateLan,
        ImageLocationClass::PublicCloud => AddressClass::PublicNetwork,
    }
}
fn origin_authority(url: &reqwest::Url, hostname: &str) -> String {
    let bare = hostname
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(hostname);
    let host = if bare.contains(':') {
        format!("[{bare}]")
    } else {
        bare.to_owned()
    };
    format!(
        "{host}:{}",
        url.port_or_known_default()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 })
    )
}
fn unbracketed_hostname(hostname: &str) -> &str {
    hostname
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(hostname)
}
fn health_state_for_error(code: RuntimeErrorCode) -> ImageHealthState {
    match code {
        RuntimeErrorCode::DnsDenied => ImageHealthState::DnsDenied,
        RuntimeErrorCode::Tls => ImageHealthState::TlsFailed,
        RuntimeErrorCode::Authentication => ImageHealthState::AuthFailed,
        RuntimeErrorCode::Incompatible => ImageHealthState::Incompatible,
        RuntimeErrorCode::WorkflowInvalid => ImageHealthState::WorkflowInvalid,
        RuntimeErrorCode::Busy => ImageHealthState::Busy,
        RuntimeErrorCode::Disabled => ImageHealthState::Disabled,
        _ => ImageHealthState::Unreachable,
    }
}

pub trait DnsResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        hostname: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, RuntimeError>> + Send + 'a>>;
}

pub struct TokioDnsResolver;

impl DnsResolver for TokioDnsResolver {
    fn resolve<'a>(
        &'a self,
        hostname: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            let resolved = tokio::net::lookup_host((hostname, 0)).await.map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::Dns,
                    "Check the endpoint hostname and DNS availability.",
                )
            })?;
            let mut addresses = resolved.map(|address| address.ip()).collect::<Vec<_>>();
            addresses.sort_unstable();
            addresses.dedup();
            if addresses.is_empty() {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::Dns,
                    "Check the endpoint hostname and DNS availability.",
                ));
            }
            Ok(addresses)
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionHop {
    pub authority: String,
    pub hostname: String,
    pub connected_ip: IpAddr,
    pub location: AddressClass,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionProof {
    pub authority: String,
    pub connected_ip: IpAddr,
    pub location: AddressClass,
    pub established_at: u64,
    /// Initial connection followed by every redirect connection, in order.
    pub hops: Vec<ConnectionHop>,
}
pub struct BoundProbeResponse {
    pub status: reqwest::StatusCode,
    pub body: Vec<u8>,
    pub connection: ConnectionProof,
}

/// The durable binding a successful dispatch revalidation produces. It ties the
/// attempt to the exact `(endpoint_id, config_generation, refresh_epoch,
/// connected_ip, location_class, hops_digest)` observed at prepare time. A proof
/// captured under one location class or configuration generation cannot satisfy a
/// later prepare under a different one -- the tuple would differ, and revalidation
/// re-derives it from scratch every time (it is never read back from storage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchProofBinding {
    pub endpoint_id: String,
    pub config_generation: u64,
    pub refresh_epoch: u64,
    pub connected_ip: IpAddr,
    pub location_class: AddressClass,
    /// Lowercase-hex SHA-256 over the ordered connection hops (initial connection
    /// followed by every redirect), so a proof observed across a different path is
    /// distinguishable from one observed on the direct route.
    pub hops_digest: String,
}

/// Canonical digest of the ordered connection hops in a `ConnectionProof`. Encodes
/// each hop's authority, hostname, connected IP, and location class in order with
/// unambiguous field/record separators so no two distinct hop chains collide.
pub fn connection_hops_digest(proof: &ConnectionProof) -> String {
    let mut hasher = Sha256::new();
    for hop in &proof.hops {
        hasher.update(hop.authority.as_bytes());
        hasher.update([0x1f]);
        hasher.update(hop.hostname.as_bytes());
        hasher.update([0x1f]);
        hasher.update(hop.connected_ip.to_string().as_bytes());
        hasher.update([0x1f]);
        hasher.update(hop.location.as_canonical_str().as_bytes());
        hasher.update([0x1e]);
    }
    crate::intel::hex_lower(&hasher.finalize())
}

impl fmt::Debug for BoundProbeResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundProbeResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .field("connection", &self.connection)
            .finish()
    }
}

pub struct ReadOnlyProbeRequest {
    pub url: reqwest::Url,
    headers: reqwest::header::HeaderMap,
}

impl ReadOnlyProbeRequest {
    pub fn new(url: reqwest::Url, headers: reqwest::header::HeaderMap) -> Self {
        Self { url, headers }
    }
}

impl fmt::Debug for ReadOnlyProbeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadOnlyProbeRequest")
            .field("url", &self.url)
            .field("header_count", &self.headers.len())
            .finish()
    }
}
/// Establishes sockets only to `candidates`, retaining `authority` for Host,
/// TLS SNI and certificate checks. Redirects must be resolved independently,
/// constrained to `required_location`, and returned in `ConnectionProof::hops`.
pub trait BoundConnector: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: ReadOnlyProbeRequest,
        candidates: &'a [IpAddr],
        required_location: AddressClass,
        limits: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<BoundProbeResponse, RuntimeError>> + Send + 'a>>;
}

pub struct ReqwestPinnedConnector {
    dns: Arc<dyn DnsResolver>,
}

struct PinnedResponse {
    status: reqwest::StatusCode,
    location: Option<String>,
    connected_ip: IpAddr,
    body: Vec<u8>,
    body_bytes: usize,
}

struct PinnedReadContext<'a> {
    url: &'a reqwest::Url,
    ip: IpAddr,
    limits: ProbeLimits,
    headers: &'a reqwest::header::HeaderMap,
    connect_deadline: tokio::time::Instant,
    header_deadline: tokio::time::Instant,
    body_deadline: tokio::time::Instant,
}

impl ReqwestPinnedConnector {
    pub fn new(dns: Arc<dyn DnsResolver>) -> Self {
        Self { dns }
    }

    async fn pinned_read_only(
        &self,
        context: PinnedReadContext<'_>,
    ) -> Result<PinnedResponse, RuntimeError> {
        let PinnedReadContext {
            url,
            ip,
            limits,
            headers,
            connect_deadline,
            header_deadline,
            body_deadline,
        } = context;
        let hostname = url.host_str().ok_or(RuntimeError::new(
            RuntimeErrorCode::Dns,
            "Correct the endpoint hostname.",
        ))?;
        let port = url.port_or_known_default().ok_or(RuntimeError::new(
            RuntimeErrorCode::Dns,
            "Correct the endpoint port.",
        ))?;
        let connect_timeout = connect_deadline
            .checked_duration_since(tokio::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(RuntimeError::new(
                RuntimeErrorCode::ConnectTimeout,
                "The provider connection did not complete in time.",
            ))?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(connect_timeout)
            .resolve(hostname, std::net::SocketAddr::new(ip, port))
            .build()
            .map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::Tls,
                    "Check the endpoint certificate and configured hostname.",
                )
            })?;
        let response = tokio::time::timeout_at(
            header_deadline,
            client.get(url.clone()).headers(headers.clone()).send(),
        )
        .await
        .map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::HeaderTimeout,
                "The provider did not return response headers in time.",
            )
        })?
        .map_err(|error| {
            let code = if error.is_connect() && url.scheme() == "https" {
                RuntimeErrorCode::Tls
            } else {
                RuntimeErrorCode::ConnectTimeout
            };
            RuntimeError::new(code, health_state_for_error(code).remediation())
        })?;
        let connected_ip =
            response
                .remote_addr()
                .map(|address| address.ip())
                .ok_or(RuntimeError::new(
                    RuntimeErrorCode::DnsDenied,
                    ImageHealthState::DnsDenied.remediation(),
                ))?;
        let status = response.status();
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body_bytes = 0usize;
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = tokio::time::timeout_at(body_deadline, stream.next())
            .await
            .map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::HeaderTimeout,
                    "The provider response body did not complete in time.",
                )
            })?
        {
            let chunk = chunk.map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::MalformedResponse,
                    "The provider returned a malformed inspection response.",
                )
            })?;
            body_bytes = body_bytes
                .checked_add(chunk.len())
                .ok_or(RuntimeError::new(
                    RuntimeErrorCode::BodyLimit,
                    "The provider response exceeded the inspection limit.",
                ))?;
            if body_bytes > limits.body_limit {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::BodyLimit,
                    "The provider response exceeded the inspection limit.",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(PinnedResponse {
            status,
            location,
            connected_ip,
            body,
            body_bytes,
        })
    }
}

impl BoundConnector for ReqwestPinnedConnector {
    fn execute<'a>(
        &'a self,
        request: ReadOnlyProbeRequest,
        candidates: &'a [IpAddr],
        required_location: AddressClass,
        limits: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<BoundProbeResponse, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            let connect_deadline = tokio::time::Instant::now() + limits.connect_timeout;
            let header_deadline = tokio::time::Instant::now() + limits.header_timeout;
            let body_deadline = tokio::time::Instant::now() + limits.body_timeout;
            let mut url = request.url;
            let initial_headers = request.headers;
            let mut candidates = candidates.to_vec();
            let mut hops = Vec::new();
            let mut total_body_bytes = 0usize;
            for redirect_count in 0..=limits.redirect_limit {
                let ip = *candidates.first().ok_or(RuntimeError::new(
                    RuntimeErrorCode::DnsDenied,
                    ImageHealthState::DnsDenied.remediation(),
                ))?;
                let hostname = url.host_str().ok_or(RuntimeError::new(
                    RuntimeErrorCode::Dns,
                    "Correct the endpoint hostname.",
                ))?;
                let authority = origin_authority(&url, hostname);
                let headers = if redirect_count == 0 {
                    &initial_headers
                } else {
                    // Credentials and attribution are never forwarded across
                    // a redirect boundary.
                    static EMPTY: std::sync::LazyLock<reqwest::header::HeaderMap> =
                        std::sync::LazyLock::new(reqwest::header::HeaderMap::new);
                    &EMPTY
                };
                let response = self
                    .pinned_read_only(PinnedReadContext {
                        url: &url,
                        ip,
                        limits: ProbeLimits {
                            body_limit: limits.body_limit.saturating_sub(total_body_bytes),
                            ..limits
                        },
                        headers,
                        connect_deadline,
                        header_deadline,
                        body_deadline,
                    })
                    .await?;
                total_body_bytes = total_body_bytes
                    .checked_add(response.body_bytes)
                    .filter(|total| *total <= limits.body_limit)
                    .ok_or(RuntimeError::new(
                        RuntimeErrorCode::BodyLimit,
                        "The provider response exceeded the inspection limit.",
                    ))?;
                let connected_ip = response.connected_ip;
                if !candidates.contains(&connected_ip)
                    || classify_address(connected_ip) != required_location
                {
                    return Err(RuntimeError::new(
                        RuntimeErrorCode::DnsDenied,
                        ImageHealthState::DnsDenied.remediation(),
                    ));
                }
                hops.push(ConnectionHop {
                    authority: authority.clone(),
                    hostname: hostname.to_owned(),
                    connected_ip,
                    location: required_location,
                });
                if !response.status.is_redirection() {
                    let first = &hops[0];
                    return Ok(BoundProbeResponse {
                        status: response.status,
                        body: response.body,
                        connection: ConnectionProof {
                            authority: first.authority.clone(),
                            connected_ip: first.connected_ip,
                            location: required_location,
                            established_at: 0,
                            hops,
                        },
                    });
                }
                if redirect_count == limits.redirect_limit {
                    return Err(RuntimeError::new(
                        RuntimeErrorCode::RedirectLimit,
                        "Use an endpoint with at most three redirects.",
                    ));
                }
                let location = response.location.ok_or(RuntimeError::new(
                    RuntimeErrorCode::MalformedResponse,
                    "Correct the provider redirect response.",
                ))?;
                url = url.join(&location).map_err(|_| {
                    RuntimeError::new(
                        RuntimeErrorCode::MalformedResponse,
                        "Correct the provider redirect location.",
                    )
                })?;
                let redirect_host = url.host_str().ok_or(RuntimeError::new(
                    RuntimeErrorCode::Dns,
                    "Correct the redirect hostname.",
                ))?;
                candidates =
                    tokio::time::timeout_at(header_deadline, self.dns.resolve(redirect_host))
                        .await
                        .map_err(|_| {
                            RuntimeError::new(
                                RuntimeErrorCode::HeaderTimeout,
                                "Redirect validation exceeded the probe deadline.",
                            )
                        })??;
                if candidates.is_empty()
                    || candidates
                        .iter()
                        .any(|ip| classify_address(*ip) != required_location)
                {
                    return Err(RuntimeError::new(
                        RuntimeErrorCode::DnsDenied,
                        ImageHealthState::DnsDenied.remediation(),
                    ));
                }
            }
            Err(RuntimeError::new(
                RuntimeErrorCode::RedirectLimit,
                "Use an endpoint with at most three redirects.",
            ))
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeLimits {
    pub connect_timeout: Duration,
    pub header_timeout: Duration,
    pub body_timeout: Duration,
    pub body_limit: usize,
    pub redirect_limit: usize,
}
impl ProbeLimits {
    pub const fn health() -> Self {
        Self {
            connect_timeout: CONNECT_TIMEOUT,
            header_timeout: HEADER_TIMEOUT,
            body_timeout: BODY_TIMEOUT,
            body_limit: HEALTH_BODY_LIMIT,
            redirect_limit: REDIRECT_LIMIT,
        }
    }
    pub const fn discovery() -> Self {
        Self {
            body_limit: DISCOVERY_BODY_LIMIT,
            ..Self::health()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySnapshot {
    pub target_id: String,
    pub model_or_workflow_digest: String,
    pub retrieved_at: u64,
    pub expires_at: u64,
    pub provenance: SnapshotProvenance,
    pub constraints: BTreeMap<String, String>,
}
impl CapabilitySnapshot {
    pub fn dispatchable_at(&self, now: u64) -> bool {
        now <= self.expires_at
            && now.saturating_sub(self.retrieved_at) <= CAPABILITY_DISPATCH_TTL.as_millis() as u64
            && self.provenance != SnapshotProvenance::Stale
    }
    pub fn visible_at(&self, now: u64) -> bool {
        now.saturating_sub(self.retrieved_at) <= DISPLAY_STALE_TTL.as_millis() as u64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageHealthSnapshot {
    pub endpoint_id: String,
    pub adapter_kind: ImageAdapterKind,
    pub target_id: String,
    pub target_immutable_identity: String,
    pub config_generation: u64,
    pub refresh_epoch: u64,
    pub request_id: u64,
    pub state: ImageHealthState,
    pub provenance: SnapshotProvenance,
    pub retrieved_at: u64,
    pub expires_at: u64,
    pub endpoint_origin: String,
    pub connection: Option<ConnectionProof>,
    pub model_or_workflow_digest: Option<String>,
    pub capability: Option<CapabilitySnapshot>,
    pub unavailable_reason: Option<RuntimeErrorCode>,
    pub credential_identity_digest: Option<CredentialIdentityDigest>,
}
impl ImageHealthSnapshot {
    pub fn reusable_at(&self, now: u64) -> bool {
        now <= self.expires_at
    }
    pub fn dispatchable_at(&self, now: u64) -> bool {
        self.state == ImageHealthState::Healthy
            && self.reusable_at(now)
            && self.connection.is_some()
            && self
                .capability
                .as_ref()
                .is_some_and(|c| c.dispatchable_at(now))
    }
}

#[derive(Clone)]
pub struct ProbeRequest {
    pub endpoint: ImageEndpoint,
    pub target_id: String,
    pub config_generation: u64,
    pub refresh_epoch: u64,
    pub request_id: u64,
    pub kind: RefreshKind,
    pub credential_identity_digest: CredentialIdentityDigest,
    resolved_headers: reqwest::header::HeaderMap,
    pub limits: ProbeLimits,
}
impl fmt::Debug for ProbeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProbeRequest")
            .field("endpoint_id", &self.endpoint.id)
            .field("target_id", &self.target_id)
            .field("adapter", &self.endpoint.adapter)
            .field("config_generation", &self.config_generation)
            .field("refresh_epoch", &self.refresh_epoch)
            .field("request_id", &self.request_id)
            .field("kind", &self.kind)
            .field("credential_identity_digest", &"<redacted>")
            .field("resolved_header_count", &self.resolved_headers.len())
            .field("limits", &self.limits)
            .finish()
    }
}
impl ProbeRequest {
    pub fn read_only_request(&self, url: reqwest::Url) -> ReadOnlyProbeRequest {
        ReadOnlyProbeRequest::new(url, self.resolved_headers.clone())
    }
}
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub state: ImageHealthState,
    pub capability: Option<CapabilitySnapshot>,
    pub model_or_workflow_digest: Option<String>,
    pub unavailable_reason: Option<RuntimeErrorCode>,
}
mod adapter_sealed {
    pub trait Sealed {}
}

pub mod comfyui;
pub mod gemini;
pub mod openai;
pub mod openrouter;

pub trait ImageRuntimeAdapter: adapter_sealed::Sealed + Send + Sync {
    fn kind(&self) -> ImageAdapterKind;
    /// Purely describes a read-only request. Header values remain ephemeral in
    /// the registry-owned transport and are never returned in snapshots.
    fn request(&self, request: &ProbeRequest) -> Result<ReadOnlyProbeRequest, RuntimeError>;
    /// Purely parses an already bounded response. This synchronous sealed hook
    /// has no transport capability and cannot follow redirects or open sockets.
    fn parse(
        &self,
        request: &ProbeRequest,
        response: &BoundProbeResponse,
    ) -> Result<ProbeResult, RuntimeError>;
}

/// Exhaustive production registration: adding an adapter kind to config makes
/// this struct fail to compile until the runtime wiring supplies it exactly
/// once. Tests that exercise missing-adapter behavior may still use [`ImageRuntimeRegistry::new`].
pub struct StandardImageRuntimeAdapters {
    pub openai_images: Arc<dyn ImageRuntimeAdapter>,
    pub openrouter_images: Arc<dyn ImageRuntimeAdapter>,
    pub gemini_images: Arc<dyn ImageRuntimeAdapter>,
    pub comfyui: Arc<dyn ImageRuntimeAdapter>,
}

impl StandardImageRuntimeAdapters {
    fn into_checked(self) -> Result<Vec<Arc<dyn ImageRuntimeAdapter>>, RuntimeError> {
        let adapters = vec![
            (ImageAdapterKind::OpenaiImages, self.openai_images),
            (ImageAdapterKind::OpenrouterImages, self.openrouter_images),
            (ImageAdapterKind::GeminiImages, self.gemini_images),
            (ImageAdapterKind::Comfyui, self.comfyui),
        ];
        for (expected, adapter) in &adapters {
            if adapter.kind() != *expected {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::Incompatible,
                    "Register each image adapter in its exact standard slot.",
                ));
            }
        }
        Ok(adapters.into_iter().map(|(_, adapter)| adapter).collect())
    }
}

/// Construct the production standard image runtime adapter set: one health /
/// capability probe adapter per [`ImageAdapterKind`], each backed by the pinned
/// / vetted connector the registry owns. This is the single production
/// construction point for the four standard adapters; it is not test-only.
///
/// The daemon image-generation worker
/// (`image-generation-job-daemon-integration`) installs the runtime registry
/// through [`crate::daemon::image_runtime::install_standard_image_runtime_registry`],
/// which threads this set into [`ImageRuntimeRegistry::production_standard`].
pub fn production_standard_image_runtime_adapters() -> StandardImageRuntimeAdapters {
    StandardImageRuntimeAdapters {
        openai_images: openai::standard_adapter(),
        openrouter_images: openrouter::standard_adapter(),
        gemini_images: gemini::standard_adapter(),
        comfyui: comfyui::standard_adapter(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RefreshKey {
    endpoint: String,
    target: String,
    generation: u64,
    epoch: u64,
    kind: RefreshKind,
    credential_identity_digest: CredentialIdentityDigest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigRevision {
    generation: u64,
    epoch: u64,
}
impl ConfigRevision {
    pub const fn new(generation: u64, epoch: u64) -> Self {
        Self { generation, epoch }
    }
}

struct RefreshWork {
    endpoint: ImageEndpoint,
    target_id: String,
    revision: ConfigRevision,
    request_id: u64,
    kind: RefreshKind,
    credential_identity_digest: CredentialIdentityDigest,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    endpoint: String,
    target: String,
}
#[derive(Clone)]
struct CurrentIdentity {
    generation: u64,
    epoch: u64,
    immutable: String,
    location: ImageLocationClass,
    adapter_kind: ImageAdapterKind,
    allow_insecure_transport: bool,
    enabled: bool,
    refresh_authority: Option<RefreshAuthority>,
}
#[derive(Clone)]
struct RefreshAuthority {
    request_id: u64,
    credential_identity_digest: CredentialIdentityDigest,
}
#[derive(Clone)]
struct CurrentTargetIdentity {
    endpoint: String,
    generation: u64,
    epoch: u64,
    immutable: String,
    model_or_workflow_digest: String,
    enabled: bool,
    is_default: bool,
    reference_support: cockpit_config::config::image_generation::ReferenceImageSupport,
    max_reference_images: u64,
}
struct Flight {
    notify: Notify,
    completed: AtomicBool,
    result: Mutex<Option<Result<ImageHealthSnapshot, RuntimeError>>>,
    waiters: AtomicUsize,
    cancelled: AtomicBool,
    cancel_notify: Notify,
}
struct WaiterGuard {
    flight: Arc<Flight>,
}
impl Drop for WaiterGuard {
    fn drop(&mut self) {
        if self.flight.waiters.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.flight.cancelled.store(true, Ordering::Release);
            self.flight.cancel_notify.notify_waiters();
        }
    }
}
struct Inner {
    adapters: Vec<Arc<dyn ImageRuntimeAdapter>>,
    cache: Mutex<HashMap<CacheKey, ImageHealthSnapshot>>,
    current: Mutex<HashMap<String, CurrentIdentity>>,
    current_targets: Mutex<HashMap<String, CurrentTargetIdentity>>,
    inflight: Mutex<HashMap<RefreshKey, Arc<Flight>>>,
}
#[derive(Clone)]
pub struct ImageRuntimeRegistry {
    inner: Arc<Inner>,
    clock: Arc<dyn RuntimeClock>,
    dns: Arc<dyn DnsResolver>,
    connector: Arc<dyn BoundConnector>,
    store: Option<crate::credentials::CredentialStore>,
}

/// Stable, redacted string label for an [`ImageAdapterKind`], mirroring the
/// `destination.adapter_kind` field produced by the dispatch authority. Used
/// for discovery projections so the model sees the same adapter vocabulary it
/// passes to `generate_image`.
fn adapter_kind_str(kind: ImageAdapterKind) -> &'static str {
    match kind {
        ImageAdapterKind::OpenaiImages => "openai_images",
        ImageAdapterKind::OpenrouterImages => "openrouter_images",
        ImageAdapterKind::GeminiImages => "gemini_images",
        ImageAdapterKind::Comfyui => "comfyui",
    }
}

impl ImageRuntimeRegistry {
    /// Build an isolated registry for a candidate configuration.  Reload uses
    /// this to refresh capabilities and construct adapters before replacing the
    /// live registry, so a failed candidate can never leave new target facts
    /// paired with old adapters/credentials.
    pub fn staged_for_config(
        &self,
        config: &ImageGenerationConfig,
        generation: u64,
        epoch: u64,
    ) -> Result<Self, RuntimeError> {
        let staged = Self {
            inner: Arc::new(Inner {
                adapters: self.inner.adapters.clone(),
                cache: Mutex::new(HashMap::new()),
                current: Mutex::new(HashMap::new()),
                current_targets: Mutex::new(HashMap::new()),
                inflight: Mutex::new(HashMap::new()),
            }),
            clock: self.clock.clone(),
            dns: self.dns.clone(),
            connector: self.connector.clone(),
            store: self.store.clone(),
        };
        staged.apply_config(config, generation, epoch)?;
        Ok(staged)
    }

    fn secret_lookup(&self, name: &str) -> Option<String> {
        let store = self.store.as_ref()?;
        if let Some(value) = store.named_secret(name) {
            return Some(value.to_string());
        }
        if let Some(value) = store.api_key(name) {
            return Some(value);
        }
        let record = store.get(name)?;
        if let Some(value) = record.as_str() {
            return Some(value.to_string());
        }
        for field in ["instance_token", "access_token", "token", "api_key"] {
            if let Some(value) = record.get(field).and_then(|value| value.as_str()) {
                return Some(value.to_string());
            }
        }
        None
    }

    /// Refresh every enabled configured target against the exact registry
    /// revision. Individual target failures are retained as health snapshots;
    /// they do not prevent other targets from becoming discoverable.
    pub async fn refresh_configured_targets(
        &self,
        config: &ImageGenerationConfig,
        generation: u64,
        epoch: u64,
    ) {
        let endpoints: HashMap<&str, &ImageEndpoint> = config
            .endpoints()
            .iter()
            .map(|endpoint| (endpoint.id.as_str(), endpoint))
            .collect();
        for (index, target) in config.targets().iter().enumerate() {
            let Some(endpoint) = endpoints.get(target.endpoint_id.as_str()) else {
                continue;
            };
            if !target.enabled || !endpoint.enabled {
                continue;
            }
            // The dispatch credential binding is the *effective* auth/header
            // material, not merely the credential_ref label. A credential can
            // be supplied by a configured secret header (and an Authorization
            // header can override credential_ref), so hashing only the ref
            // would let a rotated effective header reuse a health/approval
            // binding. This helper hashes canonical header names and bytes
            // without storing or exposing any raw value.
            let credential_identity_digest = match self.effective_credential_identity(endpoint) {
                Ok(digest) => digest,
                Err(error) => {
                    tracing::warn!(target_id = %target.id, %error, "image generation target credential resolution failed");
                    continue;
                }
            };
            let request_id = u64::try_from(index + 1).unwrap_or(u64::MAX);
            if let Err(error) = self
                .refresh(
                    (*endpoint).clone(),
                    target.id.clone(),
                    ConfigRevision::new(generation, epoch),
                    request_id,
                    RefreshKind::Capabilities,
                    credential_identity_digest,
                )
                .await
            {
                tracing::warn!(target_id = %target.id, %error, "image generation target refresh failed");
            }
        }
    }

    pub(crate) fn resolve_ephemeral_headers(
        &self,
        endpoint: &ImageEndpoint,
    ) -> Result<reqwest::header::HeaderMap, RuntimeError> {
        let (headers, missing) = crate::providers::models_fetch::resolve_headers_with_sources(
            &endpoint.headers,
            |name| std::env::var(name).ok(),
            |name| self.secret_lookup(name),
        );
        if !missing.is_empty() {
            return Err(RuntimeError::new(
                RuntimeErrorCode::Authentication,
                "Check the configured credential reference.",
            ));
        }
        let mut resolved = reqwest::header::HeaderMap::new();
        for header in headers {
            let name =
                reqwest::header::HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| {
                    RuntimeError::new(
                        RuntimeErrorCode::Authentication,
                        "Correct the configured probe headers.",
                    )
                })?;
            let value = reqwest::header::HeaderValue::from_str(&header.value).map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::Authentication,
                    "Correct the configured probe headers.",
                )
            })?;
            if resolved.insert(name, value).is_some() {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::Authentication,
                    "Correct duplicate configured probe headers.",
                ));
            }
        }
        if let Some(credential_ref) = endpoint.credential_ref.as_deref() {
            let Some(token) = self.secret_lookup(credential_ref) else {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::Authentication,
                    "Check the configured credential reference.",
                ));
            };
            if !resolved.contains_key(reqwest::header::AUTHORIZATION) {
                let value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| {
                        RuntimeError::new(
                            RuntimeErrorCode::Authentication,
                            "Correct the configured credential reference.",
                        )
                    })?;
                resolved.insert(reqwest::header::AUTHORIZATION, value);
            }
        }
        Ok(resolved)
    }

    /// Secret-free identity of the exact credential-bearing request headers.
    /// Header bytes are used only as input to this one-way digest and are never
    /// copied into a health snapshot, plan, grant, or log.
    pub(crate) fn effective_credential_identity(
        &self,
        endpoint: &ImageEndpoint,
    ) -> Result<CredentialIdentityDigest, RuntimeError> {
        let headers = self.resolve_ephemeral_headers(endpoint)?;
        let mut entries = headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_ascii_lowercase(),
                    value.as_bytes().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let mut digest = Sha256::new();
        digest.update(b"flycockpit:image-generation-effective-credential:v1\0");
        for (name, value) in entries {
            digest.update((name.len() as u64).to_be_bytes());
            digest.update(name.as_bytes());
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        Ok(CredentialIdentityDigest::from_sha256(
            digest.finalize().into(),
        ))
    }
    fn invalidate_target_cache(&self, endpoint_id: &str, target_id: &str) {
        self.inner.cache.lock().unwrap().remove(&CacheKey {
            endpoint: endpoint_id.to_owned(),
            target: target_id.to_owned(),
        });
    }
    pub fn new(
        clock: Arc<dyn RuntimeClock>,
        dns: Arc<dyn DnsResolver>,
        connector: Arc<dyn BoundConnector>,
        adapters: Vec<Arc<dyn ImageRuntimeAdapter>>,
    ) -> Result<Self, RuntimeError> {
        for (index, adapter) in adapters.iter().enumerate() {
            if adapters[..index]
                .iter()
                .any(|registered| registered.kind() == adapter.kind())
            {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::Incompatible,
                    "Register each image adapter kind exactly once.",
                ));
            }
        }
        Ok(Self {
            inner: Arc::new(Inner {
                adapters,
                cache: Mutex::new(HashMap::new()),
                current: Mutex::new(HashMap::new()),
                current_targets: Mutex::new(HashMap::new()),
                inflight: Mutex::new(HashMap::new()),
            }),
            clock,
            dns,
            connector,
            store: None,
        })
    }

    pub fn with_store(mut self, store: crate::credentials::CredentialStore) -> Self {
        self.store = Some(store);
        self
    }
    pub fn standard(adapters: StandardImageRuntimeAdapters) -> Result<Self, RuntimeError> {
        Self::standard_with_clock(Arc::new(SystemRuntimeClock::default()), adapters)
    }

    /// Construct the standard registry against a caller-owned monotonic clock.
    /// The daemon passes its image-generation clock here so health TTLs and
    /// sealed job deadlines share one origin across every session and worker.
    pub fn standard_with_clock(
        clock: Arc<dyn RuntimeClock>,
        adapters: StandardImageRuntimeAdapters,
    ) -> Result<Self, RuntimeError> {
        let dns: Arc<dyn DnsResolver> = Arc::new(TokioDnsResolver);
        let connector: Arc<dyn BoundConnector> = Arc::new(ReqwestPinnedConnector::new(dns.clone()));
        Self::new(clock, dns, connector, adapters.into_checked()?)
    }
    /// Construct the production registry with the four standard health /
    /// capability probe adapters (OpenAI Images, OpenRouter Images, Gemini
    /// Images, ComfyUI) over the pinned/vetted connector. This is the
    /// production factory referenced from the daemon install seam; it is not
    /// test-only. Attach a [`crate::credentials::CredentialStore`] with
    /// [`Self::with_store`] and apply the loaded configuration with
    /// [`Self::apply_config`] before dispatch.
    pub fn production_standard() -> Result<Self, RuntimeError> {
        Self::standard(production_standard_image_runtime_adapters())
    }

    /// Production factory variant for the daemon's shared image-generation
    /// timeline. See [`Self::standard_with_clock`].
    pub fn production_standard_with_clock(
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, RuntimeError> {
        Self::standard_with_clock(clock, production_standard_image_runtime_adapters())
    }
    pub fn adapter(
        &self,
        kind: ImageAdapterKind,
    ) -> Result<Arc<dyn ImageRuntimeAdapter>, RuntimeError> {
        self.inner
            .adapters
            .iter()
            .find(|adapter| adapter.kind() == kind)
            .cloned()
            .ok_or(RuntimeError::new(
                RuntimeErrorCode::AdapterMissing,
                "Install or enable the adapter for this target kind.",
            ))
    }
    pub fn apply_endpoint(&self, endpoint: &ImageEndpoint, generation: u64, epoch: u64) {
        let mut identity = CurrentIdentity {
            generation,
            epoch,
            immutable: endpoint.immutable_identity(),
            location: endpoint.location,
            adapter_kind: endpoint.adapter,
            allow_insecure_transport: endpoint.allow_insecure_transport,
            enabled: endpoint.enabled,
            refresh_authority: None,
        };
        let mut current = self.inner.current.lock().unwrap();
        if let Some(old) = current.get(&endpoint.id)
            && old.immutable == identity.immutable
            && old.generation == identity.generation
            && old.epoch == identity.epoch
        {
            identity.refresh_authority = old.refresh_authority.clone();
        }
        let invalidate = current.get(&endpoint.id).is_some_and(|old| {
            old.immutable != identity.immutable
                || old.location != identity.location
                || !identity.enabled
        });
        current.insert(endpoint.id.clone(), identity);
        drop(current);
        if invalidate {
            self.inner
                .cache
                .lock()
                .unwrap()
                .retain(|key, _| key.endpoint != endpoint.id);
        }
    }
    pub fn remove_endpoint(&self, endpoint_id: &str) {
        self.inner.current.lock().unwrap().remove(endpoint_id);
        self.inner
            .cache
            .lock()
            .unwrap()
            .retain(|key, _| key.endpoint != endpoint_id);
        self.inner
            .inflight
            .lock()
            .unwrap()
            .retain(|key, _| key.endpoint != endpoint_id);
        self.inner
            .current_targets
            .lock()
            .unwrap()
            .retain(|_, target| target.endpoint != endpoint_id);
    }
    pub fn apply_config(
        &self,
        config: &ImageGenerationConfig,
        generation: u64,
        epoch: u64,
    ) -> Result<(), RuntimeError> {
        let endpoint_ids = config
            .endpoints()
            .iter()
            .map(|endpoint| endpoint.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let existing = self
            .inner
            .current
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for removed in existing
            .into_iter()
            .filter(|endpoint| !endpoint_ids.contains(endpoint))
        {
            self.remove_endpoint(&removed);
        }
        for endpoint in config.endpoints() {
            self.apply_endpoint(endpoint, generation, epoch);
        }
        let mut targets = HashMap::new();
        for target in config.targets() {
            let immutable = config.target_immutable_identity(&target.id).map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::Incompatible,
                    "Correct the configured image target identity.",
                )
            })?;
            let model_or_workflow_digest = match &target.identity {
                ImageTargetIdentity::HostedModel { model } => {
                    let mut encoded = String::with_capacity(64);
                    for byte in Sha256::digest(model.as_bytes()) {
                        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
                    }
                    encoded
                }
                ImageTargetIdentity::Workflow {
                    workflow_digest, ..
                } => workflow_digest.clone(),
            };
            targets.insert(
                target.id.clone(),
                CurrentTargetIdentity {
                    endpoint: target.endpoint_id.clone(),
                    generation,
                    epoch,
                    immutable,
                    model_or_workflow_digest,
                    enabled: target.enabled,
                    is_default: target.is_default,
                    reference_support: target.reference_support,
                    max_reference_images: target.max_reference_images,
                },
            );
        }
        *self.inner.current_targets.lock().unwrap() = targets;
        self.inner.cache.lock().unwrap().retain(|key, snapshot| {
            self.inner
                .current_targets
                .lock()
                .unwrap()
                .get(&key.target)
                .is_some_and(|target| {
                    target.endpoint == key.endpoint
                        && target.generation == snapshot.config_generation
                        && target.epoch == snapshot.refresh_epoch
                        && target.enabled
                })
        });
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn apply_test_target(
        &self,
        target_id: &str,
        endpoint_id: &str,
        generation: u64,
        epoch: u64,
        model_or_workflow_digest: &str,
    ) {
        self.inner.current_targets.lock().unwrap().insert(
            target_id.to_owned(),
            CurrentTargetIdentity {
                endpoint: endpoint_id.to_owned(),
                generation,
                epoch,
                immutable: "test-target-identity".into(),
                model_or_workflow_digest: model_or_workflow_digest.into(),
                enabled: true,
                is_default: false,
                reference_support:
                    cockpit_config::config::image_generation::ReferenceImageSupport::Unsupported,
                max_reference_images: 0,
            },
        );
    }
    pub fn snapshot(&self, endpoint_id: &str, target_id: &str) -> Option<ImageHealthSnapshot> {
        let now = self.clock.now_millis();
        self.inner
            .cache
            .lock()
            .unwrap()
            .get(&CacheKey {
                endpoint: endpoint_id.to_owned(),
                target: target_id.to_owned(),
            })
            .cloned()
            .and_then(|mut value| {
                let age = now.saturating_sub(value.retrieved_at);
                if age > DISPLAY_STALE_TTL.as_millis() as u64 {
                    return None;
                }
                if !value.reusable_at(now) {
                    value.state = ImageHealthState::Stale;
                    value.provenance = SnapshotProvenance::Stale;
                }
                Some(value)
            })
    }

    /// Safe, redacted, model-facing discovery projections for every configured
    /// target, mirroring the redaction contract of [`ProjectionDestination`]
    /// and the `generate_image`/`get_image_generation_job` outcomes.
    ///
    /// By default disabled targets are excluded; `include_disabled` lists them
    /// too (still without secrets, headers, raw workflow JSON, endpoint
    /// origins, connected IPs, credential digests, or target immutable
    /// identities). A target is `enabled` only when both the target and its
    /// bound endpoint are enabled. Health and capability facts come from the
    /// cached [`ImageHealthSnapshot`] when one is available; otherwise the
    /// health state is `unknown` and the capability fields are empty. An empty
    /// configuration yields an empty list (not an error).
    pub fn list_target_projections(
        &self,
        include_disabled: bool,
    ) -> Vec<crate::image_generation_agent_tools::ImageGenerationTargetProjection> {
        use crate::image_generation_agent_tools::{ImageGenerationTargetProjection, LocationClass};

        let now = self.clock.now_millis();
        // Snapshot the current target/endpoint identities under one short lock
        // each, then read cached health per target outside the identity locks.
        let targets: Vec<(String, CurrentTargetIdentity)> = {
            self.inner
                .current_targets
                .lock()
                .unwrap()
                .iter()
                .map(|(id, identity)| (id.clone(), identity.clone()))
                .collect()
        };
        let endpoints: HashMap<String, CurrentIdentity> =
            self.inner.current.lock().unwrap().clone();

        let mut out = Vec::new();
        for (target_id, target) in targets {
            let Some(endpoint) = endpoints.get(&target.endpoint) else {
                // Target references an endpoint that is no longer current; skip
                // it rather than emit a half-resolved projection.
                continue;
            };
            let enabled = target.enabled && endpoint.enabled;
            if !enabled && !include_disabled {
                continue;
            }

            // Prefer the cached snapshot for adapter kind / health / capability;
            // fall back to the endpoint identity for adapter kind when no
            // snapshot has been taken yet.
            let snapshot = self.snapshot(&target.endpoint, &target_id);
            let adapter_kind = snapshot
                .as_ref()
                .map(|s| adapter_kind_str(s.adapter_kind))
                .unwrap_or_else(|| adapter_kind_str(endpoint.adapter_kind));
            let location_class = match endpoint.location {
                ImageLocationClass::Local => LocationClass::Local,
                ImageLocationClass::PrivateNetwork => LocationClass::PrivateNetwork,
                ImageLocationClass::PublicCloud => LocationClass::PublicCloud,
            };

            let (
                health_state,
                supported_formats,
                maximum_width,
                maximum_height,
                allowed_parameters,
                capability_fresh,
            ) = match snapshot.as_ref() {
                Some(s) => {
                    let fresh = s
                        .capability
                        .as_ref()
                        .is_some_and(|c| c.dispatchable_at(now));
                    let (formats, max_w, max_h, params) = s
                        .capability
                        .as_ref()
                        .map(|c| {
                            let formats = c
                                .constraints
                                .get("formats")
                                .map(|v| {
                                    v.split(',')
                                        .filter(|f| !f.is_empty())
                                        .map(str::to_owned)
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default();
                            let max_w = c
                                .constraints
                                .get("max_width")
                                .and_then(|v| v.parse::<u32>().ok());
                            let max_h = c
                                .constraints
                                .get("max_height")
                                .and_then(|v| v.parse::<u32>().ok());
                            let params = c
                                .constraints
                                .get("parameters")
                                .map(|v| {
                                    v.split(',')
                                        .filter(|p| {
                                            let name = p.split(':').next().unwrap_or("");
                                            !name.is_empty()
                                        })
                                        .map(|p| p.split(':').next().unwrap_or("").to_owned())
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default();
                            (formats, max_w, max_h, params)
                        })
                        .unwrap_or_default();
                    (
                        s.state.code().to_owned(),
                        formats,
                        max_w,
                        max_h,
                        params,
                        fresh,
                    )
                }
                None => (
                    "unknown".to_owned(),
                    Vec::new(),
                    None,
                    None,
                    Vec::new(),
                    false,
                ),
            };

            out.push(ImageGenerationTargetProjection {
                target_id,
                adapter_kind: adapter_kind.to_owned(),
                location_class,
                enabled,
                health_state,
                supported_formats,
                maximum_width,
                maximum_height,
                allowed_parameters,
                capability_fresh,
            });
        }
        // Stable ordering by target_id so discovery output is deterministic.
        out.sort_by(|a, b| a.target_id.cmp(&b.target_id));
        out
    }

    /// Digest the current sealed authority identity for a resolved destination
    /// set. This binds standing approvals to the endpoint origin, credential,
    /// target configuration, and discovered model/workflow identities without
    /// exposing any of those values to the approval prompt or grant table.
    pub fn destination_grant_binding_digest(&self, target_ids: &[String]) -> Option<String> {
        let now = self.clock.now_millis();
        let mut target_ids = target_ids.to_vec();
        target_ids.sort();
        target_ids.dedup();
        let mut digest = Sha256::new();
        for target_id in target_ids {
            let target = self
                .inner
                .current_targets
                .lock()
                .unwrap()
                .get(&target_id)
                .cloned()?;
            let snapshot = self.snapshot(&target.endpoint, &target_id)?;
            if !snapshot.dispatchable_at(now)
                || snapshot.target_immutable_identity != target.immutable
                || snapshot.config_generation != target.generation
                || snapshot.refresh_epoch != target.epoch
            {
                return None;
            }
            let credential = snapshot.credential_identity_digest.as_ref()?;
            let workflow = snapshot.model_or_workflow_digest.as_deref()?;
            let credential_digest = credential.plan_identity_hex();
            for field in [
                target_id.as_str(),
                snapshot.endpoint_origin.as_str(),
                snapshot.target_immutable_identity.as_str(),
                workflow,
                credential_digest.as_str(),
            ] {
                digest.update((field.len() as u64).to_be_bytes());
                digest.update(field.as_bytes());
            }
        }
        Some(crate::intel::hex_lower(&digest.finalize()))
    }

    /// Resolve a configured target into the redacted authorization projection
    /// and hard-gate facts backed by its current sealed health snapshot.
    pub fn resolve_dispatch_target(
        &self,
        target_id: &str,
    ) -> Option<(
        crate::image_generation_agent_tools::ProjectionDestination,
        bool,
        bool,
        bool,
    )> {
        use crate::image_generation_agent_tools::{LocationClass, ProjectionDestination};
        let target = self
            .inner
            .current_targets
            .lock()
            .unwrap()
            .get(target_id)
            .cloned()?;
        let endpoint = self
            .inner
            .current
            .lock()
            .unwrap()
            .get(&target.endpoint)
            .cloned()?;
        let snapshot = self.snapshot(&target.endpoint, target_id);
        let current_snapshot = snapshot.as_ref().is_some_and(|snapshot| {
            snapshot.target_immutable_identity == target.immutable
                && snapshot.config_generation == target.generation
                && snapshot.refresh_epoch == target.epoch
        });
        let capability_fresh = current_snapshot
            && snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.dispatchable_at(self.clock.now_millis()));
        let location_class = match endpoint.location {
            ImageLocationClass::Local => LocationClass::Local,
            ImageLocationClass::PrivateNetwork => LocationClass::PrivateNetwork,
            ImageLocationClass::PublicCloud => LocationClass::PublicCloud,
        };
        let secure_transport = snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.endpoint_origin.starts_with("https://"));
        Some((
            ProjectionDestination {
                target_id: target_id.to_owned(),
                location_class,
                adapter_kind: adapter_kind_str(endpoint.adapter_kind).to_owned(),
            },
            target.enabled && endpoint.enabled,
            capability_fresh,
            secure_transport || endpoint.allow_insecure_transport,
        ))
    }

    /// Return the current sealed health snapshot for a configured target. The
    /// endpoint association and config/refresh generation are checked under
    /// the registry's live maps so callers cannot turn an old cache entry into
    /// a preflight authority after a config replacement.
    pub fn current_target_snapshot(&self, target_id: &str) -> Option<ImageHealthSnapshot> {
        let target = self
            .inner
            .current_targets
            .lock()
            .unwrap()
            .get(target_id)
            .cloned()?;
        let snapshot = self.snapshot(&target.endpoint, target_id)?;
        (snapshot.target_immutable_identity == target.immutable
            && snapshot.config_generation == target.generation
            && snapshot.refresh_epoch == target.epoch
            && target.enabled)
            .then_some(snapshot)
    }

    /// Resolve the sole enabled configured default target. Configuration
    /// validation guarantees there is exactly one whenever an enabled target
    /// exists; retaining the check here makes an in-memory partial refresh fail
    /// closed rather than selecting an arbitrary target.
    pub fn configured_default_target_id(&self) -> Option<String> {
        let targets = self.inner.current_targets.lock().unwrap();
        let endpoints = self.inner.current.lock().unwrap();
        let mut defaults = targets
            .iter()
            .filter(|(_, target)| {
                target.is_default
                    && target.enabled
                    && endpoints
                        .get(&target.endpoint)
                        .is_some_and(|endpoint| endpoint.enabled)
            })
            .map(|(target_id, _)| target_id.clone());
        let target_id = defaults.next()?;
        defaults.next().is_none().then_some(target_id)
    }
    pub async fn refresh(
        &self,
        endpoint: ImageEndpoint,
        target_id: String,
        revision: ConfigRevision,
        request_id: u64,
        kind: RefreshKind,
        credential_identity_digest: CredentialIdentityDigest,
    ) -> Result<ImageHealthSnapshot, RuntimeError> {
        let ConfigRevision { generation, epoch } = revision;
        if !endpoint.enabled {
            return Err(RuntimeError::new(
                RuntimeErrorCode::Disabled,
                ImageHealthState::Disabled.remediation(),
            ));
        }
        self.inner
            .current_targets
            .lock()
            .unwrap()
            .get(&target_id)
            .cloned()
            .filter(|target| {
                target.endpoint == endpoint.id
                    && target.generation == generation
                    && target.epoch == epoch
                    && target.enabled
            })
            .ok_or(RuntimeError::new(
                RuntimeErrorCode::Obsolete,
                "Refresh after target configuration changes.",
            ))?;
        let credential_rotated = {
            let mut current = self.inner.current.lock().unwrap();
            let identity = current.get_mut(&endpoint.id).ok_or(RuntimeError::new(
                RuntimeErrorCode::Obsolete,
                "Refresh after endpoint configuration changes.",
            ))?;
            let rotated = identity
                .refresh_authority
                .as_ref()
                .is_some_and(|authority| {
                    authority.credential_identity_digest != credential_identity_digest
                });
            if identity.refresh_authority.is_none()
                || identity
                    .refresh_authority
                    .as_ref()
                    .is_some_and(|authority| request_id > authority.request_id)
            {
                identity.refresh_authority = Some(RefreshAuthority {
                    request_id,
                    credential_identity_digest: credential_identity_digest.clone(),
                });
            } else if rotated {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::Obsolete,
                    "Refresh after credential rotation.",
                ));
            }
            rotated
        };
        if credential_rotated {
            self.inner
                .cache
                .lock()
                .unwrap()
                .retain(|key, _| key.endpoint != endpoint.id);
        }
        let key = RefreshKey {
            endpoint: endpoint.id.clone(),
            target: target_id.clone(),
            generation,
            epoch,
            kind,
            credential_identity_digest: credential_identity_digest.clone(),
        };
        if let Some(cached) = self.snapshot(&key.endpoint, &key.target)
            && cached.config_generation == generation
            && cached.refresh_epoch == epoch
            && cached.credential_identity_digest.as_ref() == Some(&credential_identity_digest)
            && ((kind == RefreshKind::Health && cached.reusable_at(self.clock.now_millis()))
                || (kind == RefreshKind::Capabilities
                    && cached.capability.as_ref().is_some_and(|capability| {
                        capability.dispatchable_at(self.clock.now_millis())
                    })))
        {
            let mut cached = cached;
            cached.provenance = SnapshotProvenance::Cache;
            if let Some(capability) = &mut cached.capability {
                capability.provenance = SnapshotProvenance::Cache;
            }
            cached.request_id = request_id;
            return Ok(cached);
        }
        let (flight, leader) = {
            let mut flights = self.inner.inflight.lock().unwrap();
            match flights.get(&key) {
                Some(n) if !n.cancelled.load(Ordering::Acquire) => (n.clone(), false),
                Some(_) | None => {
                    let n = Arc::new(Flight {
                        notify: Notify::new(),
                        completed: AtomicBool::new(false),
                        result: Mutex::new(None),
                        waiters: AtomicUsize::new(0),
                        cancelled: AtomicBool::new(false),
                        cancel_notify: Notify::new(),
                    });
                    flights.insert(key.clone(), n.clone());
                    (n, true)
                }
            }
        };
        flight.waiters.fetch_add(1, Ordering::AcqRel);
        let _waiter = WaiterGuard {
            flight: flight.clone(),
        };
        let mut notified = Box::pin(flight.notify.notified());
        notified.as_mut().enable();
        if leader {
            let registry = self.clone();
            let key2 = key.clone();
            let flight2 = flight.clone();
            tokio::spawn(async move {
                let work = AssertUnwindSafe(registry.run_refresh(RefreshWork {
                    endpoint,
                    target_id,
                    revision,
                    request_id,
                    kind,
                    credential_identity_digest,
                }))
                .catch_unwind();
                let mut cancelled = Box::pin(flight2.cancel_notify.notified());
                cancelled.as_mut().enable();
                tokio::pin!(work);
                let outcome = if flight2.cancelled.load(Ordering::Acquire) {
                    Err(RuntimeError::new(
                        RuntimeErrorCode::Obsolete,
                        "The refresh has no current waiters.",
                    ))
                } else {
                    tokio::select! {
                        result = &mut work => result
                            .map_err(|_| RuntimeError::new(
                                RuntimeErrorCode::Obsolete,
                                "The refresh ended before producing a result.",
                            ))
                            .and_then(|result| result),
                        () = cancelled.as_mut() => Err(RuntimeError::new(
                            RuntimeErrorCode::Obsolete,
                            "The refresh has no current waiters.",
                        )),
                    }
                };
                *flight2.result.lock().unwrap() = Some(outcome);
                flight2.completed.store(true, Ordering::Release);
                flight2.notify.notify_waiters();
                let mut inflight = registry.inner.inflight.lock().unwrap();
                if inflight
                    .get(&key2)
                    .is_some_and(|current| Arc::ptr_eq(current, &flight2))
                {
                    inflight.remove(&key2);
                }
            });
        }
        if !flight.completed.load(Ordering::Acquire) {
            notified.await;
        }
        let mut result =
            flight
                .result
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(Err(RuntimeError::new(
                    RuntimeErrorCode::Obsolete,
                    "The refresh did not produce a current result.",
                )))?;
        result.request_id = request_id;
        Ok(result)
    }
    async fn run_refresh(&self, work: RefreshWork) -> Result<ImageHealthSnapshot, RuntimeError> {
        let RefreshWork {
            endpoint,
            target_id,
            revision: ConfigRevision { generation, epoch },
            request_id,
            kind,
            credential_identity_digest,
        } = work;
        let target_current = self
            .inner
            .current_targets
            .lock()
            .unwrap()
            .get(&target_id)
            .cloned()
            .filter(|target| {
                target.endpoint == endpoint.id
                    && target.generation == generation
                    && target.epoch == epoch
                    && target.enabled
            })
            .ok_or(RuntimeError::new(
                RuntimeErrorCode::Obsolete,
                "Refresh after target configuration changes.",
            ))?;
        let adapter = self.adapter(endpoint.adapter)?;
        let url = reqwest::Url::parse(&endpoint.origin).map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::MalformedResponse,
                "Correct the endpoint origin.",
            )
        })?;
        let hostname = url
            .host_str()
            .map(unbracketed_hostname)
            .ok_or(RuntimeError::new(
                RuntimeErrorCode::MalformedResponse,
                "Correct the endpoint origin.",
            ))?
            .to_owned();
        let authority = origin_authority(&url, &hostname);
        let resolved = match tokio::time::timeout(HEADER_TIMEOUT, self.dns.resolve(&hostname))
            .await
            .map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::HeaderTimeout,
                    "The provider did not return response headers in time.",
                )
            })
            .and_then(|result| result)
        {
            Ok(value) => value,
            Err(error) => {
                let state = health_state_for_error(error.code);
                self.commit_failure(
                    &endpoint,
                    &target_id,
                    generation,
                    epoch,
                    request_id,
                    state,
                    error.code,
                    &credential_identity_digest,
                )?;
                return Err(error);
            }
        };
        let wanted = declared_class(endpoint.location);
        if resolved.is_empty() || resolved.iter().any(|ip| classify_address(*ip) != wanted) {
            self.commit_failure(
                &endpoint,
                &target_id,
                generation,
                epoch,
                request_id,
                ImageHealthState::DnsDenied,
                RuntimeErrorCode::DnsDenied,
                &credential_identity_digest,
            )?;
            return Err(RuntimeError::new(
                RuntimeErrorCode::DnsDenied,
                ImageHealthState::DnsDenied.remediation(),
            ));
        }
        let allowed = resolved;
        let limits = if kind == RefreshKind::Capabilities {
            ProbeLimits::discovery()
        } else {
            ProbeLimits::health()
        };
        let probe = ProbeRequest {
            endpoint: endpoint.clone(),
            target_id: target_id.clone(),
            config_generation: generation,
            refresh_epoch: epoch,
            request_id,
            kind,
            credential_identity_digest: credential_identity_digest.clone(),
            resolved_headers: self.resolve_ephemeral_headers(&endpoint)?,
            limits,
        };
        let request = adapter.request(&probe)?;
        if request.url.origin() != url.origin() {
            return Err(RuntimeError::new(
                RuntimeErrorCode::DnsDenied,
                "Keep runtime probes within the configured endpoint origin.",
            ));
        }
        // DNS and request construction do not consume the connector's one-shot
        // header/body phase budgets.
        let connector_deadline = tokio::time::Instant::now() + HEADER_TIMEOUT + BODY_TIMEOUT;
        let response = match tokio::time::timeout_at(
            connector_deadline,
            self.connector.execute(request, &allowed, wanted, limits),
        )
        .await
        .map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::HeaderTimeout,
                "The provider probe exceeded its total deadline.",
            )
        })
        .and_then(|result| result)
        {
            Ok(value) => value,
            Err(error) => {
                let state = health_state_for_error(error.code);
                self.commit_failure(
                    &endpoint,
                    &target_id,
                    generation,
                    epoch,
                    request_id,
                    state,
                    error.code,
                    &credential_identity_digest,
                )?;
                return Err(error);
            }
        };
        let connection = &response.connection;
        if !allowed.contains(&connection.connected_ip)
            || connection.authority != authority
            || connection.location != wanted
        {
            self.commit_failure(
                &endpoint,
                &target_id,
                generation,
                epoch,
                request_id,
                ImageHealthState::DnsDenied,
                RuntimeErrorCode::DnsDenied,
                &credential_identity_digest,
            )?;
            return Err(RuntimeError::new(
                RuntimeErrorCode::DnsDenied,
                ImageHealthState::DnsDenied.remediation(),
            ));
        }
        if let Err(error) = Self::validate_connection_hops(connection, wanted, &allowed) {
            self.commit_failure(
                &endpoint,
                &target_id,
                generation,
                epoch,
                request_id,
                health_state_for_error(error.code),
                error.code,
                &credential_identity_digest,
            )?;
            return Err(error);
        }
        let result = match adapter.parse(&probe, &response) {
            Ok(value) => value,
            Err(error) => {
                let state = health_state_for_error(error.code);
                self.commit_failure(
                    &endpoint,
                    &target_id,
                    generation,
                    epoch,
                    request_id,
                    state,
                    error.code,
                    &credential_identity_digest,
                )?;
                return Err(error);
            }
        };
        let now = self.clock.now_millis();
        let ttl = if result.state.successful() {
            SUCCESS_TTL
        } else {
            FAILURE_TTL
        };
        let mut capability = if kind == RefreshKind::Capabilities {
            result.capability
        } else {
            None
        };
        if let Some(value) = &mut capability {
            let adapter_expiry = value.expires_at;
            value.retrieved_at = now;
            value.expires_at =
                adapter_expiry.min(now.saturating_add(CAPABILITY_DISPATCH_TTL.as_millis() as u64));
            value.provenance = SnapshotProvenance::Live;
            // Reference egress is a sealed capability, not an adapter's
            // late-only concern. Carry the configured support and bound into
            // the runtime snapshot so preflight rejects unsupported/fanout
            // requests before authorization or reservations.
            value.constraints.insert(
                "reference_support".to_string(),
                match target_current.reference_support {
                    cockpit_config::config::image_generation::ReferenceImageSupport::Unsupported => "unsupported",
                    cockpit_config::config::image_generation::ReferenceImageSupport::Optional => "optional",
                    cockpit_config::config::image_generation::ReferenceImageSupport::Required => "required",
                }
                .to_string(),
            );
            value.constraints.insert(
                "max_reference_images".to_string(),
                target_current.max_reference_images.to_string(),
            );
        }
        if capability.is_none() && kind == RefreshKind::Health {
            capability = self
                .inner
                .cache
                .lock()
                .unwrap()
                .get(&CacheKey {
                    endpoint: endpoint.id.clone(),
                    target: target_id.clone(),
                })
                .and_then(|snapshot| {
                    (snapshot.credential_identity_digest.as_ref()
                        == Some(&credential_identity_digest)
                        && snapshot.capability.as_ref().is_some_and(|capability| {
                            result.model_or_workflow_digest.as_deref()
                                == Some(capability.model_or_workflow_digest.as_str())
                        }))
                    .then(|| snapshot.capability.clone())
                    .flatten()
                });
            if let Some(capability) = &mut capability {
                capability.provenance = SnapshotProvenance::Cache;
            }
        }
        if capability.is_none() && kind == RefreshKind::Capabilities && result.state.successful() {
            let error = RuntimeError::new(
                RuntimeErrorCode::Incompatible,
                "Choose a provider target with discoverable capabilities.",
            );
            self.commit_failure(
                &endpoint,
                &target_id,
                generation,
                epoch,
                request_id,
                ImageHealthState::Incompatible,
                error.code,
                &credential_identity_digest,
            )?;
            return Err(error);
        }
        if capability.as_ref().is_some_and(|capability| {
            capability.target_id != target_id
                || capability.model_or_workflow_digest != target_current.model_or_workflow_digest
        }) {
            let error = RuntimeError::new(
                RuntimeErrorCode::Incompatible,
                "Refresh capabilities for the configured target identity.",
            );
            self.commit_failure(
                &endpoint,
                &target_id,
                generation,
                epoch,
                request_id,
                ImageHealthState::Incompatible,
                error.code,
                &credential_identity_digest,
            )?;
            return Err(error);
        }
        let snapshot = ImageHealthSnapshot {
            endpoint_id: endpoint.id.clone(),
            adapter_kind: endpoint.adapter,
            target_id,
            target_immutable_identity: target_current.immutable,
            config_generation: generation,
            refresh_epoch: epoch,
            request_id,
            state: result.state,
            provenance: SnapshotProvenance::Live,
            retrieved_at: now,
            expires_at: now.saturating_add(ttl.as_millis() as u64),
            endpoint_origin: endpoint.origin.clone(),
            connection: Some(response.connection),
            model_or_workflow_digest: result.model_or_workflow_digest,
            capability,
            unavailable_reason: result.unavailable_reason,
            credential_identity_digest: Some(credential_identity_digest),
        };
        let immutable_identity = endpoint.immutable_identity();
        self.commit(
            endpoint.id,
            snapshot,
            generation,
            epoch,
            &immutable_identity,
        )
    }
    fn validate_connection_hops(
        proof: &ConnectionProof,
        wanted: AddressClass,
        initial_candidates: &[IpAddr],
    ) -> Result<(), RuntimeError> {
        if proof.hops.is_empty() || proof.hops.len() > REDIRECT_LIMIT + 1 {
            return Err(RuntimeError::new(
                RuntimeErrorCode::RedirectLimit,
                "Use an endpoint with at most three redirects.",
            ));
        }
        let first = &proof.hops[0];
        if first.authority != proof.authority
            || first.connected_ip != proof.connected_ip
            || first.location != proof.location
        {
            return Err(RuntimeError::new(
                RuntimeErrorCode::DnsDenied,
                ImageHealthState::DnsDenied.remediation(),
            ));
        }
        for (index, hop) in proof.hops.iter().enumerate() {
            if (index == 0 && !initial_candidates.contains(&hop.connected_ip))
                || classify_address(hop.connected_ip) != wanted
                || hop.location != wanted
            {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::DnsDenied,
                    ImageHealthState::DnsDenied.remediation(),
                ));
            }
            let parsed =
                reqwest::Url::parse(&format!("https://{}", hop.authority)).map_err(|_| {
                    RuntimeError::new(
                        RuntimeErrorCode::MalformedResponse,
                        "Correct the redirect authority.",
                    )
                })?;
            if parsed.host_str().is_none_or(|host| {
                host.trim_matches(&['[', ']'][..]) != hop.hostname.trim_matches(&['[', ']'][..])
            }) {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::MalformedResponse,
                    "Correct the redirect authority.",
                ));
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn commit_failure(
        &self,
        endpoint: &ImageEndpoint,
        target_id: &str,
        generation: u64,
        epoch: u64,
        request_id: u64,
        state: ImageHealthState,
        code: RuntimeErrorCode,
        credential_identity_digest: &CredentialIdentityDigest,
    ) -> Result<(), RuntimeError> {
        let now = self.clock.now_millis();
        self.commit(
            endpoint.id.clone(),
            ImageHealthSnapshot {
                endpoint_id: endpoint.id.clone(),
                adapter_kind: endpoint.adapter,
                target_id: target_id.to_owned(),
                target_immutable_identity: self
                    .inner
                    .current_targets
                    .lock()
                    .unwrap()
                    .get(target_id)
                    .map(|target| target.immutable.clone())
                    .unwrap_or_default(),
                config_generation: generation,
                refresh_epoch: epoch,
                request_id,
                state,
                provenance: SnapshotProvenance::Live,
                retrieved_at: now,
                expires_at: now.saturating_add(FAILURE_TTL.as_millis() as u64),
                endpoint_origin: endpoint.origin.clone(),
                connection: None,
                model_or_workflow_digest: None,
                capability: None,
                unavailable_reason: Some(code),
                credential_identity_digest: Some(credential_identity_digest.clone()),
            },
            generation,
            epoch,
            &endpoint.immutable_identity(),
        )
        .map(|_| ())
    }
    fn commit(
        &self,
        id: String,
        snapshot: ImageHealthSnapshot,
        generation: u64,
        epoch: u64,
        immutable_identity: &str,
    ) -> Result<ImageHealthSnapshot, RuntimeError> {
        let current = self.inner.current.lock().unwrap();
        let authority = current
            .get(&id)
            .and_then(|value| value.refresh_authority.clone());
        let valid = current.get(&id).is_some_and(|v| {
            v.generation == generation
                && v.epoch == epoch
                && v.immutable == immutable_identity
                && v.enabled
                && v.refresh_authority.as_ref().is_some_and(|authority| {
                    snapshot.credential_identity_digest.as_ref()
                        == Some(&authority.credential_identity_digest)
                        && authority.request_id >= snapshot.request_id
                })
        });
        if !valid {
            return Err(RuntimeError::new(
                RuntimeErrorCode::Obsolete,
                "The refresh was superseded by newer configuration.",
            ));
        }
        let mut cache = self.inner.cache.lock().unwrap();
        let cache_key = CacheKey {
            endpoint: id,
            target: snapshot.target_id.clone(),
        };
        let mut snapshot = snapshot;
        if let Some(authority) = authority {
            snapshot.request_id = authority.request_id;
        }
        if let Some(newer_capability) = cache
            .get(&cache_key)
            .filter(|current| {
                snapshot.state == ImageHealthState::Healthy
                    && current.credential_identity_digest == snapshot.credential_identity_digest
                    && current.config_generation == snapshot.config_generation
                    && current.refresh_epoch == snapshot.refresh_epoch
                    && current.capability.as_ref().is_some_and(|capability| {
                        snapshot.model_or_workflow_digest.as_deref()
                            == Some(capability.model_or_workflow_digest.as_str())
                    })
            })
            .and_then(|current| current.capability.as_ref())
            .filter(|current| {
                snapshot
                    .capability
                    .as_ref()
                    .is_none_or(|incoming| current.retrieved_at > incoming.retrieved_at)
            })
            .cloned()
        {
            snapshot.capability = Some(newer_capability);
        }
        cache.insert(cache_key, snapshot.clone());
        drop(current);
        Ok(snapshot)
    }
    pub async fn revalidate_dispatch(
        &self,
        endpoint: &ImageEndpoint,
        target_id: &str,
        credential_identity_digest: &CredentialIdentityDigest,
    ) -> Result<ConnectionProof, RuntimeError> {
        self.revalidate_dispatch_inner(endpoint, target_id, credential_identity_digest)
            .await
            .map(|(_, proof)| proof)
    }

    /// Revalidate dispatchability and return the durable proof binding pinned to
    /// the single health snapshot the check validated. Used by the dispatcher's
    /// prepare transaction: the `config_generation`/`refresh_epoch` are read from
    /// the very snapshot that passed revalidation (no second, racy read), and the
    /// connection facts come from the freshly established probe. The registry's own
    /// injected clock supplies "now" -- callers never pass `retrieved_at`.
    ///
    /// `config_generation` is the snapshot's generation. Revalidation rejects a
    /// substantive endpoint/target/credential change (immutable-identity, location,
    /// origin, or credential mismatch); config reconciliation also evicts cache
    /// entries whose generation no longer matches the live target, so a pure
    /// generation bump cannot reuse an old health proof. The caller additionally
    /// binds this generation to the sealed plan's generation.
    pub async fn revalidate_dispatch_binding(
        &self,
        endpoint: &ImageEndpoint,
        target_id: &str,
        credential_identity_digest: &CredentialIdentityDigest,
    ) -> Result<DispatchProofBinding, RuntimeError> {
        let (snap, proof) = self
            .revalidate_dispatch_inner(endpoint, target_id, credential_identity_digest)
            .await?;
        Ok(DispatchProofBinding {
            endpoint_id: endpoint.id.clone(),
            config_generation: snap.config_generation,
            refresh_epoch: snap.refresh_epoch,
            connected_ip: proof.connected_ip,
            location_class: proof.location,
            hops_digest: connection_hops_digest(&proof),
        })
    }

    async fn revalidate_dispatch_inner(
        &self,
        endpoint: &ImageEndpoint,
        target_id: &str,
        credential_identity_digest: &CredentialIdentityDigest,
    ) -> Result<(ImageHealthSnapshot, ConnectionProof), RuntimeError> {
        let snap = self
            .snapshot(&endpoint.id, target_id)
            .ok_or(RuntimeError::new(
                RuntimeErrorCode::Obsolete,
                "Refresh health before dispatch.",
            ))?;
        let identity_current = self
            .inner
            .current
            .lock()
            .unwrap()
            .get(&endpoint.id)
            .is_some_and(|identity| {
                identity.enabled
                    && identity.immutable == endpoint.immutable_identity()
                    && identity.location == endpoint.location
            });
        let target_identity_current = self
            .inner
            .current_targets
            .lock()
            .unwrap()
            .get(target_id)
            .is_some_and(|target| {
                target.enabled
                    && target.endpoint == endpoint.id
                    && target.immutable == snap.target_immutable_identity
            });
        if !identity_current || !target_identity_current || snap.endpoint_origin != endpoint.origin
        {
            self.invalidate_target_cache(&endpoint.id, target_id);
            return Err(RuntimeError::new(
                RuntimeErrorCode::Obsolete,
                "Refresh after endpoint configuration changes.",
            ));
        }
        if !snap.dispatchable_at(self.clock.now_millis()) {
            return Err(RuntimeError::new(
                RuntimeErrorCode::Obsolete,
                "Refresh health and capabilities before dispatch.",
            ));
        }
        if snap.credential_identity_digest.as_ref() != Some(credential_identity_digest) {
            self.invalidate_target_cache(&endpoint.id, target_id);
            return Err(RuntimeError::new(
                RuntimeErrorCode::Obsolete,
                "Refresh after credential rotation.",
            ));
        }
        let url = reqwest::Url::parse(&endpoint.origin).map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::MalformedResponse,
                "Correct the endpoint origin.",
            )
        })?;
        let hostname = url
            .host_str()
            .map(unbracketed_hostname)
            .ok_or(RuntimeError::new(
                RuntimeErrorCode::MalformedResponse,
                "Correct the endpoint origin.",
            ))?;
        let authority = origin_authority(&url, hostname);
        let ips = self.dns.resolve(hostname).await?;
        let class = declared_class(endpoint.location);
        if snap
            .connection
            .as_ref()
            .is_none_or(|proof| proof.location != class)
        {
            self.invalidate_target_cache(&endpoint.id, target_id);
            return Err(RuntimeError::new(
                RuntimeErrorCode::DnsDenied,
                ImageHealthState::DnsDenied.remediation(),
            ));
        }
        if ips.is_empty() || ips.iter().any(|ip| classify_address(*ip) != class) {
            self.invalidate_target_cache(&endpoint.id, target_id);
            return Err(RuntimeError::new(
                RuntimeErrorCode::DnsDenied,
                ImageHealthState::DnsDenied.remediation(),
            ));
        }
        let allowed = ips;
        let deadline = tokio::time::Instant::now() + HEADER_TIMEOUT + BODY_TIMEOUT;
        let proof = tokio::time::timeout_at(
            deadline,
            self.connector.execute(
                ReadOnlyProbeRequest::new(url.clone(), self.resolve_ephemeral_headers(endpoint)?),
                &allowed,
                class,
                ProbeLimits::health(),
            ),
        )
        .await
        .map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::HeaderTimeout,
                "The dispatch revalidation exceeded its total deadline.",
            )
        })??;
        let proof = proof.connection;
        if !allowed.contains(&proof.connected_ip)
            || proof.location != class
            || proof.authority != authority
        {
            self.invalidate_target_cache(&endpoint.id, target_id);
            return Err(RuntimeError::new(
                RuntimeErrorCode::DnsDenied,
                ImageHealthState::DnsDenied.remediation(),
            ));
        }
        if let Err(error) = Self::validate_connection_hops(&proof, class, &allowed) {
            self.invalidate_target_cache(&endpoint.id, target_id);
            return Err(error);
        }
        Ok((snap, proof))
    }
}

/// Test-only scaffolding shared with the dispatcher's prepare-time proof tests
/// (`image_generation_job`). It lives here because `ImageRuntimeAdapter` is a
/// sealed trait -- a fake adapter can only be implemented inside this module.
#[cfg(test)]
pub(crate) mod dispatch_proof_support {
    use super::*;
    use cockpit_config::config::image_generation::ImageLocationClass;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A settable clock so tests can drive dispatchability past the capability TTL.
    pub(crate) struct FixedClock(pub AtomicU64);
    impl RuntimeClock for FixedClock {
        fn now_millis(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct FixedDns(IpAddr);
    impl DnsResolver for FixedDns {
        fn resolve<'a>(
            &'a self,
            _: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, RuntimeError>> + Send + 'a>> {
            let ip = self.0;
            Box::pin(async move { Ok(vec![ip]) })
        }
    }

    /// Reports the connection it was told to establish, so the observed proof's
    /// location class equals the class of the resolved IP.
    struct EchoConnector;
    impl BoundConnector for EchoConnector {
        fn execute<'a>(
            &'a self,
            request: ReadOnlyProbeRequest,
            candidates: &'a [IpAddr],
            _: AddressClass,
            _: ProbeLimits,
        ) -> Pin<Box<dyn Future<Output = Result<BoundProbeResponse, RuntimeError>> + Send + 'a>>
        {
            Box::pin(async move {
                let hostname = request.url.host_str().unwrap();
                let authority = origin_authority(&request.url, hostname);
                Ok(BoundProbeResponse {
                    status: reqwest::StatusCode::OK,
                    body: Vec::new(),
                    connection: ConnectionProof {
                        authority: authority.clone(),
                        connected_ip: candidates[0],
                        location: classify_address(candidates[0]),
                        established_at: 0,
                        hops: vec![ConnectionHop {
                            authority,
                            hostname: hostname.into(),
                            connected_ip: candidates[0],
                            location: classify_address(candidates[0]),
                        }],
                    },
                })
            })
        }
    }

    struct HealthyAdapter;
    impl adapter_sealed::Sealed for HealthyAdapter {}
    impl ImageRuntimeAdapter for HealthyAdapter {
        fn kind(&self) -> ImageAdapterKind {
            ImageAdapterKind::OpenaiImages
        }
        fn request(&self, request: &ProbeRequest) -> Result<ReadOnlyProbeRequest, RuntimeError> {
            let url = reqwest::Url::parse(&request.endpoint.origin).unwrap();
            Ok(request.read_only_request(url))
        }
        fn parse(
            &self,
            request: &ProbeRequest,
            _response: &BoundProbeResponse,
        ) -> Result<ProbeResult, RuntimeError> {
            Ok(ProbeResult {
                state: ImageHealthState::Healthy,
                // The capability must describe the configured target identity, or
                // `refresh` rejects it as Incompatible.
                capability: Some(CapabilitySnapshot {
                    target_id: request.target_id.clone(),
                    model_or_workflow_digest: "digest".into(),
                    retrieved_at: 0,
                    expires_at: CAPABILITY_DISPATCH_TTL.as_millis() as u64,
                    provenance: SnapshotProvenance::Live,
                    constraints: BTreeMap::from([
                        ("formats".to_string(), "png".to_string()),
                        ("max_width".to_string(), "512".to_string()),
                        ("max_height".to_string(), "512".to_string()),
                        ("max_attempts".to_string(), "1".to_string()),
                        ("required_grant".to_string(), "image_generation".to_string()),
                        ("reference_support".to_string(), "unsupported".to_string()),
                        ("max_reference_images".to_string(), "0".to_string()),
                    ]),
                }),
                model_or_workflow_digest: Some("digest".into()),
                unavailable_reason: None,
            })
        }
    }

    /// A loopback (`ImageLocationClass::Local`) endpoint whose connection resolves
    /// to `127.0.0.1`.
    pub(crate) fn loopback_endpoint() -> ImageEndpoint {
        ImageEndpoint {
            id: "endpoint-loopback".into(),
            adapter: ImageAdapterKind::OpenaiImages,
            origin: "https://loopback.test".into(),
            path_prefix: None,
            credential_ref: None,
            headers: vec![],
            allow_insecure_transport: false,
            location: ImageLocationClass::Local,
            enabled: true,
            route_profile_version: 1,
            exclusive_server: false,
        }
    }

    /// Build a registry whose single `endpoint`/`target_id` is refreshed to a
    /// dispatchable snapshot at `generation`/`epoch`, bound to `credential` and
    /// connecting to `127.0.0.1`. `clock` (start it at 0) drives dispatchability.
    pub(crate) async fn dispatchable_registry(
        clock: Arc<FixedClock>,
        endpoint: &ImageEndpoint,
        target_id: &str,
        generation: u64,
        epoch: u64,
        credential: CredentialIdentityDigest,
    ) -> ImageRuntimeRegistry {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let registry = ImageRuntimeRegistry::new(
            clock,
            Arc::new(FixedDns(ip)),
            Arc::new(EchoConnector),
            vec![Arc::new(HealthyAdapter)],
        )
        .unwrap();
        registry.apply_endpoint(endpoint, generation, epoch);
        registry.apply_test_target(target_id, &endpoint.id, generation, epoch, "digest");
        registry
            .refresh(
                endpoint.clone(),
                target_id.to_owned(),
                ConfigRevision::new(generation, epoch),
                1,
                RefreshKind::Capabilities,
                credential,
            )
            .await
            .unwrap();
        registry
    }
}

#[cfg(test)]
mod tests;
