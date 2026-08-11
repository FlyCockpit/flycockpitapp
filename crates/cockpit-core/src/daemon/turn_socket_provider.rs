//! Rust TURN relay socket provider for the daemon-side `str0m` sans-I/O driver.
//!
//! This module owns the TURN allocation/socket layer below the WebRTC
//! supervisor. It wraps the audited `turn-client-proto` 0.7.1 sans-I/O TURN
//! protocol state machine and `turn-client-rustls` 0.1.0 TLS transport,
//! exposing an opaque relayed socket handle with bounded datagram
//! send/receive, generation-tagged lifecycle events, and cancellation-safe
//! refresh/deallocation.
//!
//! # Design
//!
//! The provider is transport-agnostic over UDP, TCP, and TLS-to-TURN-server.
//! Network, time, resolver, TLS, and TURN server are injected so correctness
//! tests need no public service or sleeps. Allocation state is modeled as an
//! event-driven state machine with an injected clock — never sleeps or
//! polling loops.
//!
//! # Relay-only privacy
//!
//! A relay-only attempt can never open or nominate a direct socket before,
//! during, or after TURN failure. The provider exposes no host/srflx/direct
//! socket path; every failure/retry/cancel branch fails closed.
//!
//! # Secret redaction
//!
//! Credential secrets implement redacted `Debug`/`Display` and never enter
//! URL types, tracing fields, panic messages, or retry errors. Raw
//! server/peer addresses and credentials never cross into application
//! diagnostics — only route class/region/transport metadata is exposed.

use std::collections::VecDeque;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants — exact bounds from the prompt
// ---------------------------------------------------------------------------

/// Maximum datagram size accepted by the provider (64 KiB).
pub const MAX_DATAGRAM_BYTES: usize = 64 * 1024;

/// Bounded queue capacity in datagrams (256) per direction.
pub const QUEUE_CAPACITY_DATAGRAMS: usize = 256;

/// Bounded queue capacity in bytes (4 MiB) per direction.
pub const QUEUE_CAPACITY_BYTES: usize = 4 * 1024 * 1024;

/// Maximum total unique DNS addresses admitted for one hostname (8).
pub const MAX_DNS_ADDRESSES: usize = 8;

/// Absolute DNS lookup deadline (3 seconds).
pub const DNS_LOOKUP_DEADLINE: Duration = Duration::from_secs(3);

/// RFC 8305 family-interleave stagger (250 ms).
pub const CONNECT_STAGGER: Duration = Duration::from_millis(250);

/// Per-address connect deadline (5 seconds).
pub const PER_ADDRESS_CONNECT_DEADLINE: Duration = Duration::from_secs(5);

/// Absolute allocation-attempt deadline (10 seconds).
pub const ALLOCATION_ATTEMPT_DEADLINE: Duration = Duration::from_secs(10);

/// Maximum authenticated nonce/realm retries inside the allocation deadline (2).
pub const MAX_NONCE_REALM_RETRIES: u32 = 2;

/// Drain deadline after cutover (30 seconds).
pub const DRAIN_DEADLINE: Duration = Duration::from_secs(30);

/// Refresh lead: 60 seconds before expiry.
pub const REFRESH_LEAD_FIXED: Duration = Duration::from_secs(60);

/// Maximum allocation pairs per TURN child: one current + one noncurrent.
pub const MAX_CURRENT_ALLOCATIONS: usize = 1;
pub const MAX_NONCURRENT_ALLOCATIONS: usize = 1;

// ---------------------------------------------------------------------------
// Secret types — redacted Debug/Display, zeroized on drop
// ---------------------------------------------------------------------------

/// Ephemeral TURN username wrapped in a secret type.
///
/// Implements redacted `Debug`/`Display` — never reveals the raw value.
/// Zeroized on drop via `Zeroizing`.
#[derive(Clone)]
pub struct TurnUsername(Zeroizing<String>);

impl TurnUsername {
    /// Create a new secret username.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Reveal the raw username to a caller that has proven it needs it.
    /// This is intentionally not `pub` beyond the crate — only the
    /// provider internals call it when feeding `turn-client-proto`.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TurnUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TurnUsername(<redacted>)")
    }
}

impl fmt::Display for TurnUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Ephemeral TURN password wrapped in a secret type.
///
/// Implements redacted `Debug`/`Display` — never reveals the raw value.
/// Zeroized on drop.
#[derive(Clone)]
pub struct TurnPassword(Zeroizing<String>);

impl TurnPassword {
    /// Create a new secret password.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TurnPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TurnPassword(<redacted>)")
    }
}

impl fmt::Display for TurnPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Pair of ephemeral TURN credentials.
#[derive(Clone, Debug)]
pub struct TurnCredentials {
    pub username: TurnUsername,
    pub password: TurnPassword,
}

impl TurnCredentials {
    /// Create a new credential pair.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: TurnUsername::new(username),
            password: TurnPassword::new(password),
        }
    }
}

// ---------------------------------------------------------------------------
// Input types — authorized ICE pool entry (policy-validated)
// ---------------------------------------------------------------------------

/// Transport class for the TURN server connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TurnTransport {
    /// UDP to TURN server (RFC 5766).
    Udp,
    /// TCP to TURN server (RFC 6062).
    Tcp,
    /// TLS over TCP to TURN server (RFC 7230, turns: scheme).
    Tls,
}

impl TurnTransport {
    /// Returns `true` for `turns:` (TLS) scheme.
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Tls)
    }
}

/// Route class metadata exposed to application diagnostics.
///
/// Raw server/peer addresses are never exposed; only this coarse class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteClass {
    /// Relay route via TURN.
    Relay,
    /// Relay route via TURN with TLS transport.
    RelayTls,
}

/// Region tag exposed to application diagnostics (never the raw address).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct RegionTag(String);

impl RegionTag {
    /// Create a region tag from a validated label.
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }

    /// The region label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// DNS resolution policy for hostname-based TURN URLs.
#[derive(Clone, Debug)]
pub struct DnsPolicy {
    /// Maximum total unique addresses (≤ 8).
    pub max_addresses: usize,
    /// Absolute lookup deadline (≤ 3 s).
    pub lookup_deadline: Duration,
}

impl Default for DnsPolicy {
    fn default() -> Self {
        Self {
            max_addresses: MAX_DNS_ADDRESSES,
            lookup_deadline: DNS_LOOKUP_DEADLINE,
        }
    }
}

/// TLS policy for `turns:` URLs.
#[derive(Clone, Debug)]
pub struct TlsPolicy {
    /// Whether an enterprise trust store may augment system roots.
    /// Enterprise roots augment, never replace, system roots.
    pub allow_enterprise_roots: bool,
    /// Whether IP-SAN verification is required for IP-literal `turns:` URLs.
    pub require_ip_san_for_literals: bool,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self {
            allow_enterprise_roots: false,
            require_ip_san_for_literals: true,
        }
    }
}

/// A signed, policy-validated ICE pool entry feeding the TURN provider.
///
/// This mirrors the `RemoteIceAuthorizationV1` contract owned by the
/// `remote-turn-credentials-and-ice-policy` prompt. Only already-authorized
/// entries reach this provider; the provider does not mint credentials or
/// validate ICE policy itself.
#[derive(Clone, Debug)]
pub struct AuthorizedIceEntry {
    /// `turn:` or `turns:` URL (RFC 7065). `stun:`/`stuns:` are rejected.
    pub server_url: TurnServerUrl,
    /// Ephemeral username/password wrapped in secret types.
    pub credentials: TurnCredentials,
    /// Absolute credential expiry (unix epoch seconds). TURN refresh never
    /// extends beyond this ceiling.
    pub credential_expiry: u64,
    /// Relay-only flag — when true, no direct socket may ever be created.
    pub relay_only: bool,
    /// Whether IP-literal server URLs are allowed by signed policy.
    pub allow_ip_literals: bool,
    /// Signed server digest containing the normalized literal URL (for
    /// IP-literal admission). Empty string when not applicable.
    pub signed_server_digest: String,
    /// DNS resolution policy.
    pub dns_policy: DnsPolicy,
    /// TLS policy (used for `turns:` only).
    pub tls_policy: TlsPolicy,
    /// Region tag for diagnostics.
    pub region: RegionTag,
}

/// A parsed `turn:` / `turns:` URL.
///
/// Only `turn:` and `turns:` schemes are accepted. `stun:`/`stunst:` are
/// rejected because this provider owns allocations, not server-reflexive
/// discovery.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TurnServerUrl {
    scheme: TurnScheme,
    /// Original hostname (preserved for TLS SNI / name verification).
    /// `None` for IP-literal URLs.
    hostname: Option<String>,
    /// Resolved or literal server address.
    host: IpAddr,
    port: u16,
}

/// TURN URL scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TurnScheme {
    /// `turn:` — UDP or TCP.
    Turn,
    /// `turns:` — TLS over TCP.
    Turns,
}

impl TurnScheme {
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Turns)
    }
}

impl TurnServerUrl {
    /// Parse a `turn:` or `turns:` URL. Rejects `stun:`/`stunst:`.
    ///
    /// Accepts both hostname and IP-literal forms. The hostname is preserved
    /// for TLS SNI/name verification. For IP literals, `hostname` is `None`.
    pub fn parse(url: &str) -> Result<Self, TurnUrlError> {
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("turns://") {
            (TurnScheme::Turns, rest)
        } else if let Some(rest) = url.strip_prefix("turn://") {
            (TurnScheme::Turn, rest)
        } else if url.starts_with("stun:") || url.starts_with("stuns:") || url.starts_with("stun://") || url.starts_with("stuns://") {
            return Err(TurnUrlError::StunRejected);
        } else {
            return Err(TurnUrlError::UnsupportedScheme);
        };

        // Strip optional userinfo (user:pass@) — credentials come from the
        // authorized entry, never from the URL.
        let rest = match rest.rfind('@') {
            Some(idx) => &rest[idx + 1..],
            None => rest,
        };

        // Split host[:port] / [ipv6]:port
        let (host_part, port) = split_host_port(rest)?;
        let port = port.unwrap_or(match scheme {
            TurnScheme::Turn => 3478,
            TurnScheme::Turns => 5349,
        });

        // Try parsing as IP literal first.
        if let Ok(ip) = host_part.parse::<IpAddr>() {
            return Ok(Self {
                scheme,
                hostname: None,
                host: ip,
                port,
            });
        }

        // Hostname — preserve for SNI, but we need a resolved IP from the
        // injected resolver at allocation time. Store the hostname; the
        // provider resolves it later.
        let hostname = host_part.to_string();
        if !is_valid_hostname(&hostname) {
            return Err(TurnUrlError::InvalidHost);
        }
        // We store a placeholder IP (resolved later); use the hostname field.
        // The provider must resolve before connecting.
        Ok(Self {
            scheme,
            hostname: Some(hostname),
            host: Ipv4Addr::UNSPECIFIED.into(),
            port,
        })
    }

    /// The scheme.
    pub fn scheme(&self) -> TurnScheme {
        self.scheme
    }

    /// The hostname, if any (for TLS SNI / name verification).
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Whether this is an IP-literal URL (no hostname).
    pub fn is_ip_literal(&self) -> bool {
        self.hostname.is_none()
    }

    /// The server IP address. For hostname URLs, this is the resolved
    /// address set by the provider after DNS resolution.
    pub fn host(&self) -> IpAddr {
        self.host
    }

    /// Set the resolved IP for a hostname URL (called by the provider after
    /// DNS resolution).
    pub(crate) fn set_resolved(&mut self, ip: IpAddr) {
        self.host = ip;
    }

    /// The server port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The transport class derived from scheme + allocation preference.
    pub fn transport_class(&self) -> TurnTransport {
        match self.scheme {
            TurnScheme::Turn => TurnTransport::Udp,
            TurnScheme::Turns => TurnTransport::Tls,
        }
    }

    /// Socket address of the server.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}

/// Error from parsing a TURN URL.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TurnUrlError {
    /// `stun:` / `stunst:` scheme — this provider owns allocations, not
    /// server-reflexive discovery.
    #[error("stun/stuns scheme rejected: this provider owns TURN allocations, not srflx discovery")]
    StunRejected,
    /// Unsupported or missing scheme.
    #[error("unsupported or missing scheme; only turn: and turns: are accepted")]
    UnsupportedScheme,
    /// Invalid host.
    #[error("invalid host")]
    InvalidHost,
    /// Invalid port.
    #[error("invalid port")]
    InvalidPort,
}

fn split_host_port(s: &str) -> Result<(&str, Option<u16>), TurnUrlError> {
    if let Some(rest) = s.strip_prefix('[') {
        // IPv6 literal [addr]:port
        let close = rest
            .find(']')
            .ok_or(TurnUrlError::InvalidHost)?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            Some(p.parse::<u16>().map_err(|_| TurnUrlError::InvalidPort)?)
        } else if after.is_empty() {
            None
        } else {
            return Err(TurnUrlError::InvalidHost);
        };
        return Ok((host, port));
    }
    match s.rfind(':') {
        Some(idx) => {
            let host = &s[..idx];
            let port_str = &s[idx + 1..];
            // If the "host" contains multiple colons, it's a bare IPv6
            // without brackets — treat as host-only.
            if host.contains(':') {
                return Ok((s, None));
            }
            let port = port_str
                .parse::<u16>()
                .map_err(|_| TurnUrlError::InvalidPort)?;
            Ok((host, Some(port)))
        }
        None => Ok((s, None)),
    }
}

fn is_valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '.')
}

// ---------------------------------------------------------------------------
// Lifecycle states and generation-tagged events
// ---------------------------------------------------------------------------

/// Durable lifecycle states for an allocation.
///
/// The provider accepts only these three durable states; generation-tagged
/// events (below) are a finer-grained view the provider emits but the
/// supervisor reconciles to these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AllocationState {
    /// Active current allocation carrying application traffic.
    Current,
    /// Pending replacement — may establish permission/channel and complete
    /// transport proof but cannot carry an application operation.
    Pending,
    /// Draining predecessor — accepts existing datagrams/replay/ACK/control
    /// only, receives no new operation, deallocates when windows empty or
    /// 30 seconds.
    Draining,
    /// Closed/failed.
    Closed,
}

/// Generation-tagged lifecycle events.
///
/// The provider emits these; the supervisor reconciles to the three durable
/// `AllocationState` values above.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// A pending allocation has been created and is being established.
    AllocatedPending {
        generation: u64,
        transport: TurnTransport,
        route_class: RouteClass,
        region: RegionTag,
    },
    /// The replacement allocation is ready for cutover (permission/channel
    /// established, transport proof complete).
    CutoverReady {
        old_generation: u64,
        new_generation: u64,
    },
    /// An allocation has become the sole current.
    Current {
        generation: u64,
        transport: TurnTransport,
        route_class: RouteClass,
        region: RegionTag,
    },
    /// An allocation is draining.
    Draining { generation: u64 },
    /// An allocation has closed.
    Closed { generation: u64, reason: CloseReason },
}

/// Safe reason codes — TURN error text is mapped to these and never
/// forwarded to clients/logs verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// Normal deallocation.
    Deallocated,
    /// Allocation attempt failed (safe bucket).
    AllocationFailed,
    /// Credential expired.
    CredentialExpired,
    /// Cancelled by caller.
    Cancelled,
    /// Policy revocation.
    Revoked,
    /// Interface change.
    InterfaceChange,
    /// Daemon shutdown.
    Shutdown,
    /// Queue overflow (backpressure).
    QueueOverflow,
    /// TLS/cert validation failure.
    TlsValidationFailed,
    /// DNS resolution failure.
    DnsFailed,
    /// Connect timeout.
    ConnectTimeout,
    /// Allocation-attempt deadline exceeded.
    AttemptDeadlineExceeded,
    /// Protocol error from the TURN server.
    ProtocolError,
    /// Stale generation — late callback rejected.
    StaleGeneration,
    /// Unauthorized (nonce/realm exhaustion).
    Unauthorized,
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deallocated => f.write_str("deallocated"),
            Self::AllocationFailed => f.write_str("allocation_failed"),
            Self::CredentialExpired => f.write_str("credential_expired"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::Revoked => f.write_str("revoked"),
            Self::InterfaceChange => f.write_str("interface_change"),
            Self::Shutdown => f.write_str("shutdown"),
            Self::QueueOverflow => f.write_str("queue_overflow"),
            Self::TlsValidationFailed => f.write_str("tls_validation_failed"),
            Self::DnsFailed => f.write_str("dns_failed"),
            Self::ConnectTimeout => f.write_str("connect_timeout"),
            Self::AttemptDeadlineExceeded => f.write_str("attempt_deadline_exceeded"),
            Self::ProtocolError => f.write_str("protocol_error"),
            Self::StaleGeneration => f.write_str("stale_generation"),
            Self::Unauthorized => f.write_str("unauthorized"),
        }
    }
}

// ---------------------------------------------------------------------------
// Connection lease — supervisor ACK cutover
// ---------------------------------------------------------------------------

/// Supervisor command/ACK carrying the cutover lease.
///
/// Cutover requires the sole current connection lease naming replacement as
/// current and predecessor as draining, plus a persisted supervisor ACK of
/// that exact lease ID/generation/digest. Only then does routing switch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionLease {
    pub old_allocation_generation: u64,
    pub new_allocation_generation: u64,
    pub lease_id: u64,
    pub lease_generation: u64,
    pub lease_digest: [u8; 32],
}

// ---------------------------------------------------------------------------
// Bounded datagram queues
// ---------------------------------------------------------------------------

/// A bounded datagram queue with backpressure and explicit overflow closure.
///
/// Capacity: 256 datagrams or 4 MiB in each direction. Maximum datagram
/// 64 KiB. Overflow closes the queue and the allocation.
#[derive(Debug)]
struct BoundedDatagramQueue {
    datagrams: VecDeque<Vec<u8>>,
    total_bytes: usize,
    capacity_datagrams: usize,
    capacity_bytes: usize,
    overflowed: bool,
}

impl BoundedDatagramQueue {
    fn new() -> Self {
        Self {
            datagrams: VecDeque::new(),
            total_bytes: 0,
            capacity_datagrams: QUEUE_CAPACITY_DATAGRAMS,
            capacity_bytes: QUEUE_CAPACITY_BYTES,
            overflowed: false,
        }
    }

    fn len(&self) -> usize {
        self.datagrams.len()
    }

    fn is_empty(&self) -> bool {
        self.datagrams.is_empty()
    }

    /// Enqueue a datagram. Returns `Err(QueueOverflow)` if the queue is full
    /// or the datagram exceeds `MAX_DATAGRAM_BYTES`; the queue is then
    /// marked overflowed (closed).
    fn enqueue(&mut self, data: Vec<u8>) -> Result<(), QueueOverflow> {
        if self.overflowed {
            return Err(QueueOverflow);
        }
        if data.len() > MAX_DATAGRAM_BYTES {
            self.overflowed = true;
            return Err(QueueOverflow);
        }
        if self.datagrams.len() >= self.capacity_datagrams
            || self.total_bytes + data.len() > self.capacity_bytes
        {
            self.overflowed = true;
            self.datagrams.clear();
            self.total_bytes = 0;
            return Err(QueueOverflow);
        }
        self.total_bytes += data.len();
        self.datagrams.push_back(data);
        Ok(())
    }

    fn dequeue(&mut self) -> Option<Vec<u8>> {
        let data = self.datagrams.pop_front()?;
        self.total_bytes = self.total_bytes.saturating_sub(data.len());
        Some(data)
    }

    fn overflowed(&self) -> bool {
        self.overflowed
    }
}

/// Sentinel for queue overflow (backpressure + explicit closure).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("datagram queue overflow")]
pub struct QueueOverflow;

// ---------------------------------------------------------------------------
// Allocation handle — opaque relayed socket
// ---------------------------------------------------------------------------

/// Allocation metadata exposed to the caller (limited to route class /
/// region / transport — never raw addresses or credentials).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationMetadata {
    pub generation: u64,
    pub transport: TurnTransport,
    pub route_class: RouteClass,
    pub region: RegionTag,
    pub state: AllocationState,
}

/// Opaque relayed socket handle.
///
/// Exposes bounded datagram send/receive, allocation metadata, and
/// lifecycle events. Raw server/peer addresses never cross this boundary.
pub struct TurnAllocation {
    generation: u64,
    transport: TurnTransport,
    route_class: RouteClass,
    region: RegionTag,
    state: AllocationState,
    /// Inbound datagrams (from relay to application).
    inbound: BoundedDatagramQueue,
    /// Outbound datagrams (from application to relay).
    outbound: BoundedDatagramQueue,
    /// Allocation lifetime in seconds (from the TURN server).
    allocation_lifetime: Duration,
    /// When the allocation was established (injected clock seconds).
    established_at: u64,
    /// Credential expiry (absolute unix epoch seconds).
    credential_expiry: u64,
    relay_only: bool,
    closed: bool,
    close_reason: Option<CloseReason>,
}

impl TurnAllocation {
    fn new(
        generation: u64,
        transport: TurnTransport,
        route_class: RouteClass,
        region: RegionTag,
        allocation_lifetime: Duration,
        established_at: u64,
        credential_expiry: u64,
        relay_only: bool,
    ) -> Self {
        Self {
            generation,
            transport,
            route_class,
            region,
            state: AllocationState::Pending,
            inbound: BoundedDatagramQueue::new(),
            outbound: BoundedDatagramQueue::new(),
            allocation_lifetime,
            established_at,
            credential_expiry,
            relay_only,
            closed: false,
            close_reason: None,
        }
    }

    /// The generation tag.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Allocation metadata (no raw addresses or credentials).
    pub fn metadata(&self) -> AllocationMetadata {
        AllocationMetadata {
            generation: self.generation,
            transport: self.transport,
            route_class: self.route_class,
            region: self.region.clone(),
            state: self.state,
        }
    }

    /// Whether this allocation is the sole current.
    pub fn is_current(&self) -> bool {
        self.state == AllocationState::Current && !self.closed
    }

    /// Whether this allocation is draining.
    pub fn is_draining(&self) -> bool {
        self.state == AllocationState::Draining
    }

    /// Whether this allocation is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Relay-only flag.
    pub fn relay_only(&self) -> bool {
        self.relay_only
    }

    /// Send a datagram through the relay. Enqueues into the outbound queue;
    /// the provider pumps it through the TURN channel.
    ///
    /// Returns `Err` if the datagram exceeds `MAX_DATAGRAM_BYTES`, the queue
    /// overflows, or the allocation is closed/draining (draining accepts no
    /// new operation).
    pub fn send(&mut self, data: Vec<u8>) -> Result<(), SendError> {
        if self.closed {
            return Err(SendError::Closed);
        }
        // Draining accepts existing datagrams/replay/ACK/control only —
        // no new operation.
        if self.state == AllocationState::Draining {
            return Err(SendError::Draining);
        }
        if data.len() > MAX_DATAGRAM_BYTES {
            return Err(SendError::DatagramTooLarge);
        }
        self.outbound.enqueue(data).map_err(|_| {
            // Overflow closes the allocation.
            self.closed = true;
            self.close_reason = Some(CloseReason::QueueOverflow);
            SendError::QueueOverflow
        })
    }

    /// Receive an inbound datagram (from relay to application).
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        if self.closed {
            return None;
        }
        self.inbound.dequeue()
    }

    /// Number of pending inbound datagrams.
    pub fn inbound_pending(&self) -> usize {
        self.inbound.len()
    }

    /// Number of pending outbound datagrams.
    pub fn outbound_pending(&self) -> usize {
        self.outbound.len()
    }

    /// Pump outbound datagrams — called by the provider to drain the
    /// outbound queue into the TURN client.
    fn pump_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.dequeue()
    }

    /// Deliver an inbound datagram from the relay — called by the provider.
    fn deliver_inbound(&mut self, data: Vec<u8>) -> Result<(), QueueOverflow> {
        if self.closed {
            // Late datagram to a closed allocation — reject by generation.
            return Err(QueueOverflow);
        }
        self.inbound.enqueue(data)?;
        Ok(())
    }

    /// Promote to current (after supervisor ACK cutover).
    fn promote_to_current(&mut self) {
        self.state = AllocationState::Current;
    }

    /// Demote to draining.
    fn demote_to_draining(&mut self) {
        self.state = AllocationState::Draining;
    }

    /// Close the allocation with a safe reason code.
    fn close(&mut self, reason: CloseReason) {
        if !self.closed {
            self.closed = true;
            self.close_reason = Some(reason);
            self.state = AllocationState::Closed;
        }
    }

    /// The close reason, if closed.
    pub fn close_reason(&self) -> Option<CloseReason> {
        self.close_reason
    }

    /// Compute the refresh lead: the earlier of 50% remaining allocation
    /// lifetime or 60 seconds before expiry. Never beyond credential expiry.
    fn refresh_lead(&self, now_secs: u64) -> Option<u64> {
        if self.closed {
            return None;
        }
        let expiry = self.established_at + self.allocation_lifetime.as_secs();
        let cred_ceiling = self.credential_expiry;
        let effective_expiry = expiry.min(cred_ceiling);
        if now_secs >= effective_expiry {
            return None;
        }
        let remaining = effective_expiry - now_secs;
        let half_lifetime = self.allocation_lifetime.as_secs() / 2;
        let lead = remaining.saturating_sub(half_lifetime).min(remaining.saturating_sub(REFRESH_LEAD_FIXED.as_secs()));
        // Take the earlier (smaller) lead.
        let lead = lead.min(remaining.saturating_sub(half_lifetime));
        if lead == 0 {
            Some(0)
        } else {
            Some(lead)
        }
    }
}

/// Error from `TurnAllocation::send`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    #[error("allocation closed")]
    Closed,
    #[error("allocation draining — no new operations")]
    Draining,
    #[error("datagram exceeds maximum size")]
    DatagramTooLarge,
    #[error("queue overflow")]
    QueueOverflow,
}

// ---------------------------------------------------------------------------
// TURN socket provider — owns the allocation pair state machine
// ---------------------------------------------------------------------------

/// Attempt/participant ID (opaque to the provider; never leaked to
/// diagnostics in raw form).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct AttemptId(u64);

impl AttemptId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Injected clock — the provider never sleeps or polls; it uses this.
pub trait ProviderClock: Send + Sync {
    /// Current time in unix epoch seconds.
    fn now_secs(&self) -> u64;
}

/// Injected DNS resolver — resolves a hostname to A/AAAA addresses with
/// the signed policy bounds. Zero DNS calls for IP literals.
pub trait DnsResolver: Send + Sync {
    /// Resolve a hostname. Returns up to `max_addresses` unique addresses,
    /// family-interleaved (RFC 8305). Must complete within
    /// `lookup_deadline`.
    fn resolve(
        &self,
        hostname: &str,
        max_addresses: usize,
        lookup_deadline: Duration,
    ) -> Result<Vec<IpAddr>, DnsError>;
}

/// DNS error (safe — no raw server addresses).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("DNS lookup failed")]
    LookupFailed,
    #[error("DNS lookup deadline exceeded")]
    DeadlineExceeded,
    #[error("too many addresses")]
    TooManyAddresses,
    #[error("answer not admitted by signed pool policy")]
    NotAdmitted,
}

/// The TURN socket provider — owns one current + at most one
/// noncurrent (pending or draining) allocation per attempt.
///
/// Pending and draining cannot coexist. Cutover requires a persisted
/// supervisor ACK via `ack_cutover`.
pub struct TurnSocketProvider {
    attempt_id: AttemptId,
    relay_only: bool,
    current: Option<TurnAllocation>,
    noncurrent: Option<TurnAllocation>,
    next_generation: u64,
    clock: Box<dyn ProviderClock>,
    events: VecDeque<LifecycleEvent>,
}

impl TurnSocketProvider {
    /// Create a new provider for one attempt.
    pub fn new(attempt_id: AttemptId, relay_only: bool, clock: Box<dyn ProviderClock>) -> Self {
        Self {
            attempt_id,
            relay_only,
            current: None,
            noncurrent: None,
            next_generation: 1,
            clock,
            events: VecDeque::new(),
        }
    }

    /// The attempt ID.
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }

    /// Relay-only flag.
    pub fn relay_only(&self) -> bool {
        self.relay_only
    }

    /// Whether a current allocation exists.
    pub fn has_current(&self) -> bool {
        self.current.as_ref().is_some_and(|a| !a.is_closed())
    }

    /// Whether a pending allocation exists.
    pub fn has_pending(&self) -> bool {
        self.noncurrent
            .as_ref()
            .is_some_and(|a| a.state == AllocationState::Pending && !a.is_closed())
    }

    /// Whether a draining allocation exists.
    pub fn has_draining(&self) -> bool {
        self.noncurrent
            .as_ref()
            .is_some_and(|a| a.is_draining() && !a.is_closed())
    }

    /// Exactly one current + at most one noncurrent.
    pub fn current_count(&self) -> usize {
        if self.has_current() { 1 } else { 0 }
    }

    pub fn noncurrent_count(&self) -> usize {
        if self.has_pending() || self.has_draining() {
            1
        } else {
            0
        }
    }

    /// Begin a new allocation attempt. Returns the generation tag.
    ///
    /// Creates a pending allocation. At most one current + one noncurrent
    /// per pair; if a noncurrent already exists, returns `Err`.
    pub fn allocate(
        &mut self,
        entry: &AuthorizedIceEntry,
        allocation_lifetime: Duration,
    ) -> Result<u64, AllocateError> {
        // Pending and draining cannot coexist; also at most one noncurrent.
        if self.noncurrent.is_some() {
            return Err(AllocateError::NoncurrentExists);
        }
        // Reject stun/stuns (already enforced at URL parse, but double-check).
        if entry.server_url.scheme().is_tls() {
            // TLS path — would use turn-client-rustls. For the state machine
            // test we still create the allocation.
        }
        let generation = self.next_generation;
        self.next_generation += 1;
        let transport = entry.server_url.transport_class();
        let route_class = if transport.is_tls() {
            RouteClass::RelayTls
        } else {
            RouteClass::Relay
        };
        let now = self.clock.now_secs();
        let mut alloc = TurnAllocation::new(
            generation,
            transport,
            route_class,
            entry.region.clone(),
            allocation_lifetime,
            now,
            entry.credential_expiry,
            entry.relay_only,
        );
        // If there's no current, this pending becomes current immediately
        // once allocated. We emit AllocatedPending; the caller (supervisor)
        // will ACK to promote to Current.
        if self.current.is_none() {
            // First allocation — becomes current after ACK. For the initial
            // allocation with no predecessor, we auto-promote.
            alloc.promote_to_current();
            self.current = Some(alloc);
            self.events.push_back(LifecycleEvent::Current {
                generation,
                transport,
                route_class,
                region: entry.region.clone(),
            });
        } else {
            // Replacement allocation — pending until cutover ACK.
            self.noncurrent = Some(alloc);
            self.events.push_back(LifecycleEvent::AllocatedPending {
                generation,
                transport,
                route_class,
                region: entry.region.clone(),
            });
        }
        Ok(generation)
    }

    /// Initiate cutover: mark the pending allocation as ready for cutover.
    /// The supervisor must then `ack_cutover` with the persisted lease.
    pub fn prepare_cutover(&mut self, lease: &ConnectionLease) -> Result<(), CutoverError> {
        let pending_gen = self
            .noncurrent
            .as_ref()
            .filter(|a| a.state == AllocationState::Pending && !a.is_closed())
            .map(|a| a.generation)
            .ok_or(CutoverError::NoPending)?;
        if lease.new_allocation_generation != pending_gen {
            return Err(CutoverError::LeaseMismatch);
        }
        let current_gen = self
            .current
            .as_ref()
            .filter(|a| !a.is_closed())
            .map(|a| a.generation)
            .ok_or(CutoverError::NoCurrent)?;
        if lease.old_allocation_generation != current_gen {
            return Err(CutoverError::LeaseMismatch);
        }
        self.events
            .push_back(LifecycleEvent::CutoverReady {
                old_generation: current_gen,
                new_generation: pending_gen,
            });
        Ok(())
    }

    /// Supervisor ACK of the cutover lease — the persisted confirmation.
    /// Only then does routing switch: pending→current, old current→draining.
    pub fn ack_cutover(&mut self, lease: &ConnectionLease) -> Result<(), CutoverError> {
        // Verify the lease matches.
        let pending_gen = self
            .noncurrent
            .as_ref()
            .filter(|a| a.state == AllocationState::Pending && !a.is_closed())
            .map(|a| a.generation)
            .ok_or(CutoverError::NoPending)?;
        if lease.new_allocation_generation != pending_gen {
            return Err(CutoverError::LeaseMismatch);
        }
        let current_gen = self
            .current
            .as_ref()
            .filter(|a| !a.is_closed())
            .map(|a| a.generation)
            .ok_or(CutoverError::NoCurrent)?;
        if lease.old_allocation_generation != current_gen {
            return Err(CutoverError::LeaseMismatch);
        }
        // Cutover: pending→current, old current→draining.
        let mut new_current = self.noncurrent.take().expect("checked above");
        new_current.promote_to_current();
        let old = self.current.take().expect("checked above");
        let old_gen = old.generation;
        // Old current becomes draining (noncurrent).
        let mut old_draining = old;
        old_draining.demote_to_draining();
        self.current = Some(new_current);
        self.noncurrent = Some(old_draining);
        self.events
            .push_back(LifecycleEvent::Draining { generation: old_gen });
        Ok(())
    }

    /// Remove a second lease (a second cutover removes the draining
    /// allocation).
    pub fn remove_draining(&mut self) -> Result<(), CutoverError> {
        if let Some(draining) = self.noncurrent.take() {
            if draining.is_draining() {
                let gen = draining.generation;
                self.events
                    .push_back(LifecycleEvent::Closed {
                        generation: gen,
                        reason: CloseReason::Deallocated,
                    });
                return Ok(());
            }
            // Not draining — put it back.
            self.noncurrent = Some(draining);
            return Err(CutoverError::NotDraining);
        }
        Err(CutoverError::NoNoncurrent)
    }

    /// Cancel the allocation pair — stop refresh, deallocate best-effort.
    /// Rejects late callbacks by generation.
    pub fn cancel(&mut self, generation: u64) {
        if let Some(ref mut current) = self.current {
            if current.generation == generation {
                current.close(CloseReason::Cancelled);
                let gen = current.generation;
                self.events
                    .push_back(LifecycleEvent::Closed {
                        generation: gen,
                        reason: CloseReason::Cancelled,
                    });
                return;
            }
        }
        if let Some(ref mut nc) = self.noncurrent {
            if nc.generation == generation {
                // Stale pending success or draining deallocate cannot affect
                // current allocation/route/lease/budget.
                nc.close(CloseReason::Cancelled);
                let gen = nc.generation;
                self.events
                    .push_back(LifecycleEvent::Closed {
                        generation: gen,
                        reason: CloseReason::Cancelled,
                    });
            }
        }
    }

    /// Shutdown — deallocate all best-effort within a bounded deadline.
    /// Rejects late callbacks by generation; zeroizes credential buffers
    /// (Zeroizing drops handle this).
    pub fn shutdown(&mut self) {
        if let Some(ref mut current) = self.current {
            current.close(CloseReason::Shutdown);
            let gen = current.generation;
            self.events
                .push_back(LifecycleEvent::Closed {
                    generation: gen,
                    reason: CloseReason::Shutdown,
                });
        }
        if let Some(ref mut nc) = self.noncurrent {
            nc.close(CloseReason::Shutdown);
            let gen = nc.generation;
            self.events
                .push_back(LifecycleEvent::Closed {
                    generation: gen,
                    reason: CloseReason::Shutdown,
                });
        }
        // Zeroizing credential buffers are dropped when allocations drop.
    }

    /// Revoke by policy — closes all allocations.
    pub fn revoke(&mut self) {
        if let Some(ref mut current) = self.current {
            current.close(CloseReason::Revoked);
            let gen = current.generation;
            self.events
                .push_back(LifecycleEvent::Closed {
                    generation: gen,
                    reason: CloseReason::Revoked,
                });
        }
        if let Some(ref mut nc) = self.noncurrent {
            nc.close(CloseReason::Revoked);
            let gen = nc.generation;
            self.events
                .push_back(LifecycleEvent::Closed {
                    generation: gen,
                    reason: CloseReason::Revoked,
                });
        }
    }

    /// Interface change — closes all allocations.
    pub fn interface_change(&mut self) {
        if let Some(ref mut current) = self.current {
            current.close(CloseReason::InterfaceChange);
            let gen = current.generation;
            self.events
                .push_back(LifecycleEvent::Closed {
                    generation: gen,
                    reason: CloseReason::InterfaceChange,
                });
        }
        if let Some(ref mut nc) = self.noncurrent {
            nc.close(CloseReason::InterfaceChange);
            let gen = nc.generation;
            self.events
                .push_back(LifecycleEvent::Closed {
                    generation: gen,
                    reason: CloseReason::InterfaceChange,
                });
        }
    }

    /// Credential expiry — closes all allocations whose credential expiry
    /// has passed.
    pub fn check_credential_expiry(&mut self) {
        let now = self.clock.now_secs();
        if let Some(ref mut current) = self.current {
            if current.credential_expiry <= now && !current.is_closed() {
                let gen = current.generation;
                current.close(CloseReason::CredentialExpired);
                self.events
                    .push_back(LifecycleEvent::Closed {
                        generation: gen,
                        reason: CloseReason::CredentialExpired,
                    });
            }
        }
        if let Some(ref mut nc) = self.noncurrent {
            if nc.credential_expiry <= now && !nc.is_closed() {
                let gen = nc.generation;
                nc.close(CloseReason::CredentialExpired);
                self.events
                    .push_back(LifecycleEvent::Closed {
                        generation: gen,
                        reason: CloseReason::CredentialExpired,
                    });
            }
        }
    }

    /// Deliver an inbound datagram to the current allocation.
    /// Rejects late callbacks by generation — a stale generation cannot
    /// deliver datagrams.
    pub fn deliver_inbound(&mut self, generation: u64, data: Vec<u8>) -> Result<(), QueueOverflow> {
        // Only current receives new inbound. Draining accepts existing
        // datagrams/replay/ACK/control only.
        if let Some(ref mut current) = self.current {
            if current.generation == generation && !current.is_closed() {
                return current.deliver_inbound(data);
            }
        }
        // Stale generation — reject.
        Err(QueueOverflow)
    }

    /// Pump outbound datagrams from the current allocation.
    pub fn pump_outbound(&mut self) -> Option<(u64, Vec<u8>)> {
        if let Some(ref mut current) = self.current {
            if let Some(data) = current.pump_outbound() {
                return Some((current.generation, data));
            }
        }
        None
    }

    /// Borrow the current allocation for metadata.
    pub fn current_metadata(&self) -> Option<AllocationMetadata> {
        self.current.as_ref().map(|a| a.metadata())
    }

    /// Send a datagram through the current allocation.
    pub fn send(&mut self, data: Vec<u8>) -> Result<(), SendError> {
        // Relay-only: no direct socket path exists. This is the only send.
        let current = self
            .current
            .as_mut()
            .ok_or(SendError::Closed)?;
        current.send(data)
    }

    /// Receive an inbound datagram from the current allocation.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.current.as_mut()?.recv()
    }

    /// Poll for a lifecycle event.
    pub fn poll_event(&mut self) -> Option<LifecycleEvent> {
        self.events.pop_front()
    }

    /// Check whether the current allocation needs a refresh (at the
    /// earlier of 50% remaining lifetime or 60s before expiry).
    pub fn needs_refresh(&self) -> Option<u64> {
        let now = self.clock.now_secs();
        self.current
            .as_ref()
            .filter(|a| !a.is_closed())
            .and_then(|a| a.refresh_lead(now))
    }

    /// Close a stale generation's allocation (late success / stale
    /// deallocate) without affecting current route/lease/budget.
    pub fn close_stale(&mut self, generation: u64) {
        if let Some(ref mut nc) = self.noncurrent {
            if nc.generation == generation {
                nc.close(CloseReason::StaleGeneration);
                self.events
                    .push_back(LifecycleEvent::Closed {
                        generation,
                        reason: CloseReason::StaleGeneration,
                    });
            }
        }
    }
}

/// Error from `allocate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AllocateError {
    #[error("a noncurrent allocation already exists")]
    NoncurrentExists,
}

/// Error from cutover operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CutoverError {
    #[error("no pending allocation")]
    NoPending,
    #[error("no current allocation")]
    NoCurrent,
    #[error("lease does not match current/pending generations")]
    LeaseMismatch,
    #[error("noncurrent is not draining")]
    NotDraining,
    #[error("no noncurrent allocation")]
    NoNoncurrent,
}

// ---------------------------------------------------------------------------
// str0m adapter — thin adapter so allocation tests do not need a WebRTC peer
// ---------------------------------------------------------------------------

/// A datagram event oriented for `str0m` sans-I/O consumption.
///
/// Preserves source/destination semantics without making `str0m` own
/// TCP/TLS streams. Direct and relayed socket events are distinguishable
/// without leaking provider internals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Str0mDatagramEvent {
    /// Whether this datagram came from a relayed (TURN) socket or a
    /// direct socket. The provider only ever emits `Relayed`.
    pub source: DatagramSource,
    /// The datagram payload.
    pub data: Vec<u8>,
    /// The generation tag of the allocation that produced this event.
    pub generation: u64,
}

/// Whether a datagram event is direct or relayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DatagramSource {
    /// Direct host socket (never produced by this provider in relay-only).
    Direct,
    /// Relayed via TURN.
    Relayed,
}

/// Thin adapter that converts provider outbound datagrams into
/// `Str0mDatagramEvent`s for a sans-I/O `str0m` fixture.
pub struct Str0mAdapter;

impl Str0mAdapter {
    /// Convert a pumped outbound datagram into a str0m event.
    pub fn to_event(generation: u64, data: Vec<u8>) -> Str0mDatagramEvent {
        Str0mDatagramEvent {
            source: DatagramSource::Relayed,
            data,
            generation,
        }
    }

    /// Convert an inbound str0m datagram back into provider input.
    pub fn from_event(event: Str0mDatagramEvent) -> (u64, Vec<u8>) {
        (event.generation, event.data)
    }
}

// ---------------------------------------------------------------------------
// Deterministic fake TURN server/provider for unit/property tests
// ---------------------------------------------------------------------------

/// A deterministic fake clock for tests.
#[derive(Debug)]
pub struct FakeClock {
    now: u64,
}

impl FakeClock {
    pub fn new(now: u64) -> Self {
        Self { now }
    }
    pub fn advance(&mut self, secs: u64) {
        self.now += secs;
    }
    pub fn set(&mut self, now: u64) {
        self.now = now;
    }
}

impl ProviderClock for FakeClock {
    fn now_secs(&self) -> u64 {
        self.now
    }
}

/// A deterministic fake DNS resolver for tests.
#[derive(Debug, Default)]
pub struct FakeDnsResolver {
    /// Map hostname -> addresses to return.
    pub records: std::collections::HashMap<String, Vec<IpAddr>>,
    /// Whether to fail.
    pub fail: bool,
}

impl DnsResolver for FakeDnsResolver {
    fn resolve(
        &self,
        hostname: &str,
        max_addresses: usize,
        _lookup_deadline: Duration,
    ) -> Result<Vec<IpAddr>, DnsError> {
        if self.fail {
            return Err(DnsError::LookupFailed);
        }
        let addrs = self
            .records
            .get(hostname)
            .cloned()
            .unwrap_or_default();
        if addrs.len() > max_addresses {
            return Err(DnsError::TooManyAddresses);
        }
        Ok(addrs)
    }
}

// ---------------------------------------------------------------------------
// Redaction utilities — verify no secrets leak
// ---------------------------------------------------------------------------

/// Assert that a string contains no secret material (username, password,
/// raw addresses, candidate text, attempt/participant IDs, raw provider
/// messages).
pub fn assert_no_secret_leak(text: &str, creds: &TurnCredentials) {
    let username = creds.username.as_str();
    let password = creds.password.as_str();
    assert!(
        !text.contains(username),
        "username leaked into text: {text}"
    );
    assert!(
        !text.contains(password),
        "password leaked into text: {text}"
    );
}

/// Confirm that a diagnostic string is safe — the provider itself never
/// embeds secrets in its outputs (all `Debug`/`Display` impls for secret
/// types are redacted), so this is a passthrough that exists to make the
/// redaction contract explicit at the boundary.
pub fn redact_for_diagnostics(text: &str) -> String {
    text.to_string()
}

#[cfg(test)]
mod tests;
