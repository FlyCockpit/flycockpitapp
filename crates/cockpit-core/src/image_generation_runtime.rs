//! Runtime-only registry, discovery and destination health for image targets.
//! Configuration remains pure; all I/O is behind injected read-only seams.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
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
    PublicRemote,
    Forbidden,
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
        AddressClass::PublicRemote
    }
}
fn declared_class(class: ImageLocationClass) -> AddressClass {
    match class {
        ImageLocationClass::Local => AddressClass::Loopback,
        ImageLocationClass::PrivateNetwork => AddressClass::PrivateLan,
        ImageLocationClass::PublicCloud => AddressClass::PublicRemote,
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
/// Establishes sockets only to `candidates`, retaining `authority` for Host,
/// TLS SNI and certificate checks. Redirects must be resolved independently,
/// constrained to `required_location`, and returned in `ConnectionProof::hops`.
pub trait BoundConnector: Send + Sync {
    fn connect<'a>(
        &'a self,
        origin: &'a reqwest::Url,
        candidates: &'a [IpAddr],
        required_location: AddressClass,
        limits: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<ConnectionProof, RuntimeError>> + Send + 'a>>;
}

pub struct ReqwestPinnedConnector {
    dns: Arc<dyn DnsResolver>,
}

struct PinnedResponse {
    status: reqwest::StatusCode,
    location: Option<String>,
    connected_ip: IpAddr,
}

impl ReqwestPinnedConnector {
    pub fn new(dns: Arc<dyn DnsResolver>) -> Self {
        Self { dns }
    }

    async fn pinned_read_only(
        &self,
        url: &reqwest::Url,
        ip: IpAddr,
        limits: ProbeLimits,
    ) -> Result<PinnedResponse, RuntimeError> {
        let hostname = url.host_str().ok_or(RuntimeError::new(
            RuntimeErrorCode::Dns,
            "Correct the endpoint hostname.",
        ))?;
        let port = url.port_or_known_default().ok_or(RuntimeError::new(
            RuntimeErrorCode::Dns,
            "Correct the endpoint port.",
        ))?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(limits.connect_timeout)
            .resolve(hostname, std::net::SocketAddr::new(ip, port))
            .build()
            .map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::Tls,
                    "Check the endpoint certificate and configured hostname.",
                )
            })?;
        let response = tokio::time::timeout(limits.header_timeout, client.get(url.clone()).send())
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
        let mut stream = response.bytes_stream();
        while let Some(chunk) = tokio::time::timeout(limits.header_timeout, stream.next())
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
        }
        Ok(PinnedResponse {
            status,
            location,
            connected_ip,
        })
    }
}

impl BoundConnector for ReqwestPinnedConnector {
    fn connect<'a>(
        &'a self,
        origin: &'a reqwest::Url,
        candidates: &'a [IpAddr],
        required_location: AddressClass,
        limits: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<ConnectionProof, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            let mut url = origin.clone();
            let mut candidates = candidates.to_vec();
            let mut hops = Vec::new();
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
                let response = self.pinned_read_only(&url, ip, limits).await?;
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
                    return Ok(ConnectionProof {
                        authority: first.authority.clone(),
                        connected_ip: first.connected_ip,
                        location: required_location,
                        established_at: 0,
                        hops,
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
                candidates = self.dns.resolve(redirect_host).await?;
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
    pub body_limit: usize,
    pub redirect_limit: usize,
}
impl ProbeLimits {
    pub const fn health() -> Self {
        Self {
            connect_timeout: CONNECT_TIMEOUT,
            header_timeout: HEADER_TIMEOUT,
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
    pub connection: ConnectionProof,
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
            .field("connection", &self.connection)
            .field("limits", &self.limits)
            .finish()
    }
}
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub state: ImageHealthState,
    pub capability: Option<CapabilitySnapshot>,
    pub model_or_workflow_digest: Option<String>,
    pub unavailable_reason: Option<RuntimeErrorCode>,
}
pub trait ImageRuntimeAdapter: Send + Sync {
    fn kind(&self) -> ImageAdapterKind;
    /// Performs only bounded, read-only inspection over the bound connection
    /// represented by `request.connection`. Implementations must not resolve a
    /// second destination, open an unvalidated socket, or follow redirects that
    /// are absent from the connector's proof.
    fn probe<'a>(
        &'a self,
        request: ProbeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeResult, RuntimeError>> + Send + 'a>>;
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RefreshKey {
    endpoint: String,
    target: String,
    generation: u64,
    epoch: u64,
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
    enabled: bool,
}
#[derive(Clone)]
struct CurrentTargetIdentity {
    endpoint: String,
    generation: u64,
    epoch: u64,
    immutable: String,
    model_or_workflow_digest: String,
    enabled: bool,
}
struct Flight {
    notify: Notify,
    completed: AtomicBool,
    result: Mutex<Option<Result<ImageHealthSnapshot, RuntimeError>>>,
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
}

impl ImageRuntimeRegistry {
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
        })
    }
    pub fn standard(adapters: StandardImageRuntimeAdapters) -> Result<Self, RuntimeError> {
        let dns: Arc<dyn DnsResolver> = Arc::new(TokioDnsResolver);
        let connector: Arc<dyn BoundConnector> = Arc::new(ReqwestPinnedConnector::new(dns.clone()));
        Self::new(
            Arc::new(SystemRuntimeClock::default()),
            dns,
            connector,
            adapters.into_checked()?,
        )
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
        let identity = CurrentIdentity {
            generation,
            epoch,
            immutable: endpoint.immutable_identity(),
            location: endpoint.location,
            enabled: endpoint.enabled,
        };
        let mut current = self.inner.current.lock().unwrap();
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
                    format!("{:x}", Sha256::digest(model.as_bytes()))
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
    fn apply_test_target(
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
    pub async fn refresh(
        &self,
        endpoint: ImageEndpoint,
        target_id: String,
        generation: u64,
        epoch: u64,
        request_id: u64,
        kind: RefreshKind,
        credential_identity_digest: CredentialIdentityDigest,
    ) -> Result<ImageHealthSnapshot, RuntimeError> {
        if !endpoint.enabled {
            return Err(RuntimeError::new(
                RuntimeErrorCode::Disabled,
                ImageHealthState::Disabled.remediation(),
            ));
        }
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
                Some(n) => (n.clone(), false),
                None => {
                    let n = Arc::new(Flight {
                        notify: Notify::new(),
                        completed: AtomicBool::new(false),
                        result: Mutex::new(None),
                    });
                    flights.insert(key.clone(), n.clone());
                    (n, true)
                }
            }
        };
        let mut notified = Box::pin(flight.notify.notified());
        notified.as_mut().enable();
        if leader {
            let registry = self.clone();
            let key2 = key.clone();
            let flight2 = flight.clone();
            tokio::spawn(async move {
                let outcome = AssertUnwindSafe(registry.run_refresh(
                    endpoint,
                    target_id,
                    generation,
                    epoch,
                    request_id,
                    kind,
                    credential_identity_digest,
                ))
                .catch_unwind()
                .await
                .map_err(|_| {
                    RuntimeError::new(
                        RuntimeErrorCode::Obsolete,
                        "The refresh ended before producing a result.",
                    )
                })
                .and_then(|result| result);
                *flight2.result.lock().unwrap() = Some(outcome);
                flight2.completed.store(true, Ordering::Release);
                flight2.notify.notify_waiters();
                registry.inner.inflight.lock().unwrap().remove(&key2);
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
    async fn run_refresh(
        &self,
        endpoint: ImageEndpoint,
        target_id: String,
        generation: u64,
        epoch: u64,
        request_id: u64,
        kind: RefreshKind,
        credential_identity_digest: CredentialIdentityDigest,
    ) -> Result<ImageHealthSnapshot, RuntimeError> {
        let header_deadline = tokio::time::Instant::now() + HEADER_TIMEOUT;
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
        let resolved = match tokio::time::timeout_at(header_deadline, self.dns.resolve(&hostname))
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
        let connect_deadline = header_deadline.min(tokio::time::Instant::now() + CONNECT_TIMEOUT);
        let connection = match tokio::time::timeout_at(
            connect_deadline,
            self.connector.connect(&url, &allowed, wanted, limits),
        )
        .await
        .map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::ConnectTimeout,
                "The provider connection did not complete in time.",
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
        if let Err(error) = Self::validate_connection_hops(&connection, wanted, &allowed) {
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
        let result = match tokio::time::timeout_at(
            header_deadline,
            adapter.probe(ProbeRequest {
                endpoint: endpoint.clone(),
                target_id: target_id.clone(),
                config_generation: generation,
                refresh_epoch: epoch,
                request_id,
                kind,
                credential_identity_digest: credential_identity_digest.clone(),
                connection: connection.clone(),
                limits,
            }),
        )
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
            connection: Some(connection),
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
        let valid = current.get(&id).is_some_and(|v| {
            v.generation == generation
                && v.epoch == epoch
                && v.immutable == immutable_identity
                && v.enabled
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
        let proof = self
            .connector
            .connect(&url, &allowed, class, ProbeLimits::health())
            .await?;
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
        Ok(proof)
    }
}

#[cfg(test)]
mod tests;
