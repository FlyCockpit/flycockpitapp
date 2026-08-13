//! Rust TURN relay socket provider for the daemon-side `str0m` sans-I/O driver.
//!
//! This module owns the TURN allocation/socket layer below the WebRTC
//! supervisor. It exposes:
//!
//! - a single RFC 7065 URL grammar shared with the ICE policy authority in
//!   `cockpit-proto` (see [`TurnServerUrl::parse`], which delegates to
//!   [`cockpit_proto::remote_turn_ice_policy::validate_turn_url`]),
//! - the generation-tagged allocation-pair lifecycle state machine (current +
//!   at most one noncurrent, lease/ACK cutover, 30 s drain, stale-generation
//!   rejection), driven by an injected [`ProviderClock`],
//! - a production admission/DNS plan enforced on the [`TurnSocketProvider::allocate`]
//!   path via an injected [`DnsResolver`]: hostnames resolve under
//!   [`MAX_DNS_ADDRESSES`] / [`DNS_LOOKUP_DEADLINE`] with RFC 8305 family
//!   interleave; signed IP-literal URLs skip DNS entirely and are admitted only
//!   by the entry's signed digest,
//! - a relay-only [`TurnTransportConnector`] seam: the ONLY socket-opening path,
//!   so no host/srflx/direct socket can ever be created on any failure, retry,
//!   or cancel branch,
//! - bounded datagram send/receive with explicit overflow closure,
//! - redacted secret types that never enter URL types, tracing fields, panic
//!   messages, retry errors, or diagnostics.
//!
//! # Real transport I/O
//!
//! The production connector that drives the audited `turn-client-proto` 0.7.1
//! sans-I/O state machine and `turn-client-rustls` 0.1.0 TLS transport over
//! Tokio UDP/TCP/TLS sockets lives in the `io` submodule and is compiled only
//! under the off-by-default `turn-coturn-conformance` feature. That real wire
//! path is exercised against a pinned coturn instance on the Linux CI leg
//! (`remote_turn_socket_provider_coturn_conformance`); it needs live network
//! infrastructure and is therefore not part of the default serialized gate.
//! When the feature is off, the production connector fails closed with an
//! explicit "live infrastructure required" reason and never fabricates an
//! allocation. Deterministic in-process tests drive the real admission/DNS/
//! relay-only/generation/queue paths through an injected recording connector.
//!
//! # Rustls crypto provider
//!
//! Every rustls user in this process (TURN TLS via `turn-client-rustls`, media
//! HTTPS test servers, future direct rustls clients) shares one process-global
//! `aws_lc_rs` `CryptoProvider`, installed once via
//! [`crate::tls_crypto_provider`]. `ring` is never installed as the process
//! default.
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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use zeroize::Zeroizing;

#[cfg(feature = "turn-coturn-conformance")]
pub mod io;

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
    /// Signed enterprise root certificates (DER), if any, that may **augment**
    /// (never replace) the system trust store — but only when
    /// `tls_policy.allow_enterprise_roots` is set. Empty for the common case.
    pub enterprise_root_ders: Vec<Vec<u8>>,
    /// Region tag for diagnostics.
    pub region: RegionTag,
}

impl AuthorizedIceEntry {
    /// Whether the entry's signed digest admits the given normalized
    /// (canonical RFC 7065) IP-literal URL.
    ///
    /// The signed digest is the newline-separated set of normalized server
    /// URLs the signer admitted for this entry; a literal is admitted only if
    /// it appears verbatim. Full cryptographic verification of the digest
    /// against the pool signature is owned by the ICE-authorization prompt;
    /// this provider consumes the already-admitted set and never mints or
    /// re-signs it.
    pub fn admits_literal(&self, canonical_url: &str) -> bool {
        !self.signed_server_digest.is_empty()
            && self
                .signed_server_digest
                .split('\n')
                .any(|admitted| admitted == canonical_url)
    }
}

/// Interleave resolved addresses by family (RFC 8305 "Happy Eyeballs"):
/// alternate IPv6 / IPv4 starting with the first-seen family, preserving
/// intra-family order.
fn interleave_families(addrs: &[IpAddr]) -> Vec<IpAddr> {
    let v6: Vec<IpAddr> = addrs.iter().copied().filter(|a| a.is_ipv6()).collect();
    let v4: Vec<IpAddr> = addrs.iter().copied().filter(|a| a.is_ipv4()).collect();
    // Lead with whichever family appears first in the resolver's answer.
    let (first, second) = if addrs.first().is_some_and(IpAddr::is_ipv6) {
        (v6, v4)
    } else {
        (v4, v6)
    };
    let mut fi = first.into_iter();
    let mut si = second.into_iter();
    let mut out = Vec::with_capacity(addrs.len());
    loop {
        match (fi.next(), si.next()) {
            (Some(a), Some(b)) => {
                out.push(a);
                out.push(b);
            }
            (Some(a), None) => out.push(a),
            (None, Some(b)) => out.push(b),
            (None, None) => break,
        }
    }
    out
}

/// A parsed `turn:` / `turns:` URL.
///
/// The single canonical grammar is RFC 7065, shared with the ICE policy
/// authority: [`TurnServerUrl::parse`] delegates to
/// [`cockpit_proto::remote_turn_ice_policy::validate_turn_url`], so a URL
/// emitted by policy (`turn:host[:port]`, `turn:host?transport=tcp`,
/// `turns:host:443`) parses here and nowhere else. `stun:`/`stuns:` are
/// rejected because this provider owns allocations, not server-reflexive
/// discovery; the legacy `turn://` double-slash form is no longer accepted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TurnServerUrl {
    scheme: TurnScheme,
    /// Transport derived from scheme + `?transport=` per product policy:
    /// `turn` → UDP, `turn?transport=tcp` → TCP, `turns:host:443` → TLS.
    transport: TurnTransport,
    /// Original hostname (preserved for TLS SNI / name verification).
    /// `None` for IP-literal URLs.
    hostname: Option<String>,
    /// Resolved or literal server address.
    host: IpAddr,
    port: u16,
    /// Canonical RFC 7065 string (from `TurnUrl::to_url_string`) used for
    /// signed IP-literal admission. Never contains credentials.
    canonical: String,
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
    /// Parse a `turn:` or `turns:` URL against the single RFC 7065 grammar
    /// shared with ICE policy. Rejects `stun:`/`stuns:`, the legacy `turn://`
    /// double-slash form, userinfo/path/fragment, unknown query keys,
    /// `turns` on a non-443 port, and `turn` UDP with an explicit
    /// `?transport=udp`.
    ///
    /// The hostname is preserved for TLS SNI / name verification. For IP
    /// literals, `hostname` is `None` and no DNS resolution occurs.
    pub fn parse(url: &str) -> Result<Self, TurnUrlError> {
        // Reject srflx discovery schemes with a specific reason before
        // delegating; this provider owns TURN allocations only.
        let scheme_str = url.split(':').next().unwrap_or("");
        if scheme_str == "stun" || scheme_str == "stuns" {
            return Err(TurnUrlError::StunRejected);
        }
        // The provider admits IP literals only when the signed entry allows
        // it; grammar-level parsing accepts literals and defers admission to
        // `TurnSocketProvider::allocate`. Pass `allow_ip_literals = true` so
        // the shared grammar does not reject literals here.
        // Any grammar/policy rejection collapses to a single safe reason so no
        // server detail leaks into diagnostics.
        let parsed = cockpit_proto::remote_turn_ice_policy::validate_turn_url(url, true)
            .map_err(|_| TurnUrlError::MalformedUrl)?;

        use cockpit_proto::remote_turn_ice_policy::{
            TurnScheme as PScheme, TurnTransport as PTransport,
        };
        let scheme = match parsed.scheme {
            PScheme::Turn => TurnScheme::Turn,
            PScheme::Turns => TurnScheme::Turns,
        };
        // Map scheme + policy transport to the provider's transport class.
        // `turns` is always TLS-over-TCP; `turn` is UDP or TCP.
        let transport = match (parsed.scheme, parsed.transport) {
            (PScheme::Turns, _) => TurnTransport::Tls,
            (PScheme::Turn, PTransport::Udp) => TurnTransport::Udp,
            (PScheme::Turn, PTransport::Tcp) => TurnTransport::Tcp,
        };
        let canonical = parsed.to_url_string();
        let port = parsed.port.unwrap_or(match scheme {
            TurnScheme::Turn => 3478,
            // `turns` on a non-443 port is already rejected by the grammar, so
            // a missing port cannot occur here; keep 443 for completeness.
            TurnScheme::Turns => 443,
        });

        // `parsed.host` is normalized: lowercase hostname, or an IP literal
        // (IPv6 bracketed as `[..]`).
        if parsed.is_ip_literal {
            let literal = parsed.host.trim_start_matches('[').trim_end_matches(']');
            let ip = literal
                .parse::<IpAddr>()
                .map_err(|_| TurnUrlError::MalformedUrl)?;
            return Ok(Self {
                scheme,
                transport,
                hostname: None,
                host: ip,
                port,
                canonical,
            });
        }

        Ok(Self {
            scheme,
            transport,
            hostname: Some(parsed.host),
            host: Ipv4Addr::UNSPECIFIED.into(),
            port,
            canonical,
        })
    }

    /// The canonical RFC 7065 URL string (no credentials). Used for signed
    /// IP-literal admission on the production allocate path.
    pub fn canonical(&self) -> &str {
        &self.canonical
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

    /// The literal server IP address for IP-literal URLs. For hostname URLs
    /// this is an unspecified placeholder — hostnames are resolved on the
    /// production allocate path into a [`ConnectionPlan`], never stored here.
    pub fn host(&self) -> IpAddr {
        self.host
    }

    /// The server port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The transport class derived from scheme + `?transport=` query per
    /// product policy.
    pub fn transport_class(&self) -> TurnTransport {
        self.transport
    }

    /// Socket address of the server.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}

/// Error from parsing a TURN URL.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TurnUrlError {
    /// `stun:` / `stuns:` scheme — this provider owns allocations, not
    /// server-reflexive discovery.
    #[error("stun/stuns scheme rejected: this provider owns TURN allocations, not srflx discovery")]
    StunRejected,
    /// The URL is not a valid RFC 7065 `turn:`/`turns:` URL under product
    /// policy (bad scheme, `turn://` double-slash form, userinfo/path/
    /// fragment, unknown query, `turns` non-443, invalid host/port). The
    /// specific reason is deliberately collapsed so no server detail leaks.
    #[error("malformed turn url")]
    MalformedUrl,
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
    Closed {
        generation: u64,
        reason: CloseReason,
    },
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
        let lead = remaining
            .saturating_sub(half_lifetime)
            .min(remaining.saturating_sub(REFRESH_LEAD_FIXED.as_secs()));
        // Take the earlier (smaller) lead.
        let lead = lead.min(remaining.saturating_sub(half_lifetime));
        if lead == 0 { Some(0) } else { Some(lead) }
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

/// The resolved, admitted connection plan for one allocation attempt.
///
/// Produced by [`TurnSocketProvider::plan_connection`] on the production
/// allocate path. Carries only the relay server target(s) and transport —
/// never credentials. The list of candidate addresses is family-interleaved
/// per RFC 8305 for the connect loop; for IP literals it holds exactly the one
/// literal and involved zero DNS calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionPlan {
    /// Transport to the TURN server.
    pub transport: TurnTransport,
    /// Server name for TLS SNI / name verification. `None` for a signed IP
    /// literal, where TLS verification is by IP-SAN against the literal
    /// address instead of a DNS name.
    pub server_name: Option<String>,
    /// Ordered, family-interleaved candidate server socket addresses. The
    /// connect loop MUST try them in this order (RFC 8305).
    pub addresses: Vec<SocketAddr>,
    /// Whether the server URL was an IP literal (⇒ zero DNS calls).
    pub is_ip_literal: bool,
    /// Whether an IP-literal `turns:` connection requires the presented
    /// certificate to carry an IP-SAN for the literal address
    /// (`TlsPolicy::require_ip_san_for_literals`).
    pub require_ip_san_for_literals: bool,
    /// Whether enterprise roots may **augment** (never replace) the system
    /// trust store for this connection (`TlsPolicy::allow_enterprise_roots`).
    pub allow_enterprise_roots: bool,
    /// Signed enterprise root certificates (DER) to augment system roots with,
    /// present only when `allow_enterprise_roots` is set. Empty otherwise, so a
    /// connection can never augment roots it was not signed into.
    pub enterprise_root_ders: Vec<Vec<u8>>,
}

/// Error building the connection plan (safe reason codes only).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// IP-literal URL not admitted (either `allow_ip_literals` is false or the
    /// signed digest does not admit the normalized URL).
    #[error("ip literal not admitted by signed policy")]
    IpLiteralNotAdmitted,
    /// DNS resolution failed / exceeded bounds. Carries the safe DNS reason.
    #[error("dns resolution failed")]
    Dns(DnsError),
}

/// Injected transport connector — the ONE and ONLY socket-opening seam.
///
/// This is a relay-only boundary by construction: the provider exposes no
/// direct/host/srflx socket path, so no failure, retry, or cancel branch can
/// open a direct socket. The production implementation drives
/// `turn-client-proto` / `turn-client-rustls` over Tokio sockets (in the
/// `io` submodule, compiled only under the `turn-coturn-conformance`
/// feature). Tests inject a recording connector that drives the real admission
/// / DNS / generation path without a live TURN server.
pub trait TurnTransportConnector: Send + Sync {
    /// Open a relay socket for the plan and drive the TURN Allocate exchange
    /// to completion. Returns the established relay on success. Implementations
    /// MUST NOT open any host/srflx/direct socket.
    fn connect_and_allocate(
        &self,
        plan: &ConnectionPlan,
        credentials: &TurnCredentials,
    ) -> Result<EstablishedRelay, ConnectError>;
}

/// A successfully established relay allocation (metadata only — no addresses,
/// no credentials cross this boundary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EstablishedRelay {
    /// The allocation lifetime granted by the TURN server.
    pub allocation_lifetime: Duration,
    /// The transport actually used.
    pub transport: TurnTransport,
}

/// Error from the transport connector (safe reason codes only — raw TURN
/// server text is never forwarded).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    /// No candidate address accepted a connection within the deadline.
    #[error("connect timeout")]
    ConnectTimeout,
    /// TLS/cert validation failed.
    #[error("tls validation failed")]
    TlsValidationFailed,
    /// Authentication failed after nonce/realm retries were exhausted.
    #[error("unauthorized")]
    Unauthorized,
    /// The TURN server rejected the allocation (mapped, never raw text).
    #[error("allocation failed")]
    AllocationFailed,
    /// The real wire path needs live TURN infrastructure not available in this
    /// build/environment (default build with the `turn-coturn-conformance`
    /// feature off). Fail closed rather than fabricate an allocation.
    #[error("live turn infrastructure required")]
    LiveInfrastructureRequired,
}

impl ConnectError {
    /// Map to a safe lifecycle close reason.
    pub fn close_reason(self) -> CloseReason {
        match self {
            Self::ConnectTimeout => CloseReason::ConnectTimeout,
            Self::TlsValidationFailed => CloseReason::TlsValidationFailed,
            Self::Unauthorized => CloseReason::Unauthorized,
            Self::AllocationFailed | Self::LiveInfrastructureRequired => {
                CloseReason::AllocationFailed
            }
        }
    }
}

/// The default production connector when the live Tokio TURN driver is not
/// compiled in (the `turn-coturn-conformance` feature is off) or the live
/// infrastructure is unavailable.
///
/// It fails closed with [`ConnectError::LiveInfrastructureRequired`] — it never
/// fabricates an allocation, and (like every connector) opens no socket of any
/// kind. The real wire path is `io::drive_allocation`, compiled under the
/// feature and verified against pinned coturn on Linux CI.
///
/// TODO(turn-coturn-conformance): bridge `io::drive_allocation` into a
/// blocking connector once the WebRTC endpoint owns a Tokio runtime handle
/// (`webrtc-endpoint-tokio-driver`); until then production allocation over the
/// real wire runs only on the coturn CI leg.
#[derive(Debug, Default, Clone, Copy)]
pub struct FailClosedConnector;

impl TurnTransportConnector for FailClosedConnector {
    fn connect_and_allocate(
        &self,
        _plan: &ConnectionPlan,
        _credentials: &TurnCredentials,
    ) -> Result<EstablishedRelay, ConnectError> {
        Err(ConnectError::LiveInfrastructureRequired)
    }
}

/// The TURN socket provider — owns one current + at most one
/// noncurrent (pending or draining) allocation per attempt.
///
/// Pending and draining cannot coexist. Cutover requires a persisted
/// supervisor ACK via `ack_cutover`.
///
/// DNS resolution, IP-literal admission, and the relay-only socket boundary
/// are enforced on the production [`allocate`](Self::allocate) path via the
/// injected [`DnsResolver`] and [`TurnTransportConnector`].
pub struct TurnSocketProvider {
    attempt_id: AttemptId,
    relay_only: bool,
    current: Option<TurnAllocation>,
    noncurrent: Option<TurnAllocation>,
    next_generation: u64,
    clock: Box<dyn ProviderClock>,
    resolver: Box<dyn DnsResolver>,
    connector: Box<dyn TurnTransportConnector>,
    events: VecDeque<LifecycleEvent>,
}

impl TurnSocketProvider {
    /// Create a new provider for one attempt.
    ///
    /// The `resolver` enforces DNS bounds on the production allocate path and
    /// the `connector` is the sole socket-opening seam (relay-only by
    /// construction). Production wiring passes a real system resolver and the
    /// Tokio `turn-client-*` connector; tests inject deterministic fakes.
    pub fn new(
        attempt_id: AttemptId,
        relay_only: bool,
        clock: Box<dyn ProviderClock>,
        resolver: Box<dyn DnsResolver>,
        connector: Box<dyn TurnTransportConnector>,
    ) -> Self {
        Self {
            attempt_id,
            relay_only,
            current: None,
            noncurrent: None,
            next_generation: 1,
            clock,
            resolver,
            connector,
            events: VecDeque::new(),
        }
    }

    /// Build the resolved, admitted connection plan for an authorized entry.
    ///
    /// This is the production admission/DNS path. IP literals are admitted
    /// only when `allow_ip_literals` is set AND the entry's signed digest
    /// admits the normalized URL — and involve **zero** DNS calls. Hostnames
    /// are resolved via the injected resolver under the signed policy's
    /// `max_addresses` (≤ [`MAX_DNS_ADDRESSES`]) and `lookup_deadline`
    /// (≤ [`DNS_LOOKUP_DEADLINE`]) bounds, then family-interleaved per
    /// RFC 8305.
    pub fn plan_connection(
        &self,
        entry: &AuthorizedIceEntry,
    ) -> Result<ConnectionPlan, PlanError> {
        let url = &entry.server_url;
        let transport = url.transport_class();
        let port = url.port();
        // Enterprise roots may augment system roots only when signed into the
        // entry; otherwise the augmentation set is empty (never augment roots a
        // connection was not signed into).
        let enterprise_root_ders = if entry.tls_policy.allow_enterprise_roots {
            entry.enterprise_root_ders.clone()
        } else {
            Vec::new()
        };
        if url.is_ip_literal() {
            // Signed admission for IP literals: the entry must allow literals
            // and its signed digest must admit the normalized URL. No DNS.
            if !entry.allow_ip_literals || !entry.admits_literal(url.canonical()) {
                return Err(PlanError::IpLiteralNotAdmitted);
            }
            return Ok(ConnectionPlan {
                transport,
                server_name: None,
                addresses: vec![SocketAddr::new(url.host(), port)],
                is_ip_literal: true,
                require_ip_san_for_literals: entry.tls_policy.require_ip_san_for_literals,
                allow_enterprise_roots: entry.tls_policy.allow_enterprise_roots,
                enterprise_root_ders,
            });
        }
        // Hostname: resolve under the signed policy bounds.
        let hostname = url.hostname().expect("non-literal url has a hostname");
        let max = entry.dns_policy.max_addresses.min(MAX_DNS_ADDRESSES);
        let deadline = entry.dns_policy.lookup_deadline.min(DNS_LOOKUP_DEADLINE);
        let raw = self
            .resolver
            .resolve(hostname, max, deadline)
            .map_err(PlanError::Dns)?;
        // Enforce uniqueness + the answer cap on the production path (not just
        // in the fake resolver). Stable order is preserved for RFC 8305.
        let mut seen = std::collections::HashSet::new();
        let answers: Vec<IpAddr> = raw.into_iter().filter(|a| seen.insert(*a)).collect();
        if answers.is_empty() {
            return Err(PlanError::Dns(DnsError::LookupFailed));
        }
        if answers.len() > max {
            return Err(PlanError::Dns(DnsError::TooManyAddresses));
        }
        let addresses = interleave_families(&answers)
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        Ok(ConnectionPlan {
            transport,
            server_name: Some(hostname.to_string()),
            addresses,
            is_ip_literal: false,
            require_ip_san_for_literals: entry.tls_policy.require_ip_san_for_literals,
            allow_enterprise_roots: entry.tls_policy.allow_enterprise_roots,
            enterprise_root_ders,
        })
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

    /// Drop any closed allocation from the `current`/`noncurrent` slots so a
    /// fresh allocation can be admitted (and later cut over) after a cancel,
    /// credential expiry, revoke, or interface change closed the prior
    /// generation. Idempotent; leaves live allocations untouched.
    fn retire_closed(&mut self) {
        if self.current.as_ref().is_some_and(TurnAllocation::is_closed) {
            self.current = None;
        }
        if self.noncurrent.as_ref().is_some_and(TurnAllocation::is_closed) {
            self.noncurrent = None;
        }
    }

    /// Close a still-live noncurrent (pending replacement or draining
    /// predecessor) with the given reason and emit its `Closed` event. Used
    /// when the current generation is torn down, which orphans the noncurrent
    /// (a pending cannot be promoted without ACK cutover, and cutover needs a
    /// live current). No-op if the noncurrent is absent or already closed.
    fn close_noncurrent_if_live(&mut self, reason: CloseReason) {
        if let Some(ref mut nc) = self.noncurrent {
            if !nc.is_closed() {
                let alloc_gen = nc.generation;
                nc.close(reason);
                self.events.push_back(LifecycleEvent::Closed {
                    generation: alloc_gen,
                    reason,
                });
            }
        }
    }

    /// Begin a new allocation attempt. Returns the generation tag.
    ///
    /// Drives the real production path: build the admitted DNS/IP-literal plan
    /// (enforcing bounds and signed admission), then open the relay via the
    /// injected connector (the sole socket-opening seam — relay-only by
    /// construction). Only on a successful Allocate does a pending/current
    /// allocation come into existence. At most one current + one noncurrent per
    /// pair; if a noncurrent already exists, returns `Err`.
    ///
    /// The requested `allocation_lifetime` is a ceiling; the effective lifetime
    /// is whatever the TURN server grants (from the connector), never longer
    /// than requested.
    pub fn allocate(
        &mut self,
        entry: &AuthorizedIceEntry,
        allocation_lifetime: Duration,
    ) -> Result<u64, AllocateError> {
        // Recover from a prior closed generation: retire closed slots so a
        // fresh attempt after cancel/expiry/revoke/interface-change is admitted
        // and (when a current already exists) can still cut over.
        self.retire_closed();
        // Pending and draining cannot coexist; also at most one noncurrent.
        if self.noncurrent.is_some() {
            return Err(AllocateError::NoncurrentExists);
        }
        // Build the admitted DNS / IP-literal plan on the production path.
        let plan = self
            .plan_connection(entry)
            .map_err(AllocateError::Plan)?;
        // Open the relay through the sole socket-opening seam. No direct/host/
        // srflx socket is reachable from here; a failure fails closed and
        // creates no allocation.
        let established = self
            .connector
            .connect_and_allocate(&plan, &entry.credentials)
            .map_err(AllocateError::Connect)?;
        // Never exceed the requested lifetime ceiling.
        let allocation_lifetime = established.allocation_lifetime.min(allocation_lifetime);

        let generation = self.next_generation;
        self.next_generation += 1;
        let transport = established.transport;
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
        self.events.push_back(LifecycleEvent::CutoverReady {
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
        self.events.push_back(LifecycleEvent::Draining {
            generation: old_gen,
        });
        Ok(())
    }

    /// Remove a second lease (a second cutover removes the draining
    /// allocation).
    pub fn remove_draining(&mut self) -> Result<(), CutoverError> {
        if let Some(draining) = self.noncurrent.take() {
            if draining.is_draining() {
                let alloc_gen = draining.generation;
                self.events.push_back(LifecycleEvent::Closed {
                    generation: alloc_gen,
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
        let mut hit_current = false;
        if let Some(ref mut current) = self.current {
            if current.generation == generation {
                current.close(CloseReason::Cancelled);
                let alloc_gen = current.generation;
                self.events.push_back(LifecycleEvent::Closed {
                    generation: alloc_gen,
                    reason: CloseReason::Cancelled,
                });
                hit_current = true;
            }
        }
        if hit_current {
            // Cancelling the current orphans any noncurrent: an unacked pending
            // replacement can no longer cut over (there is no current to cut
            // over FROM, and we must not silently promote it), and a draining
            // predecessor has nothing left to hand off to. Close it too so the
            // pair recovers via a fresh allocate.
            self.close_noncurrent_if_live(CloseReason::Cancelled);
        } else if let Some(ref mut nc) = self.noncurrent {
            if nc.generation == generation {
                // Stale pending success or draining deallocate cannot affect
                // current allocation/route/lease/budget.
                nc.close(CloseReason::Cancelled);
                let alloc_gen = nc.generation;
                self.events.push_back(LifecycleEvent::Closed {
                    generation: alloc_gen,
                    reason: CloseReason::Cancelled,
                });
            }
        }
        // Free any slot this cancel closed so a fresh allocation can be admitted.
        self.retire_closed();
    }

    /// Shutdown — deallocate all best-effort within a bounded deadline.
    /// Rejects late callbacks by generation; zeroizes credential buffers
    /// (Zeroizing drops handle this).
    pub fn shutdown(&mut self) {
        if let Some(ref mut current) = self.current {
            current.close(CloseReason::Shutdown);
            let alloc_gen = current.generation;
            self.events.push_back(LifecycleEvent::Closed {
                generation: alloc_gen,
                reason: CloseReason::Shutdown,
            });
        }
        if let Some(ref mut nc) = self.noncurrent {
            nc.close(CloseReason::Shutdown);
            let alloc_gen = nc.generation;
            self.events.push_back(LifecycleEvent::Closed {
                generation: alloc_gen,
                reason: CloseReason::Shutdown,
            });
        }
        // Retiring the slots drops (and zeroizes) the credential buffers.
        self.retire_closed();
    }

    /// Revoke by policy — closes all allocations.
    pub fn revoke(&mut self) {
        if let Some(ref mut current) = self.current {
            current.close(CloseReason::Revoked);
            let alloc_gen = current.generation;
            self.events.push_back(LifecycleEvent::Closed {
                generation: alloc_gen,
                reason: CloseReason::Revoked,
            });
        }
        if let Some(ref mut nc) = self.noncurrent {
            nc.close(CloseReason::Revoked);
            let alloc_gen = nc.generation;
            self.events.push_back(LifecycleEvent::Closed {
                generation: alloc_gen,
                reason: CloseReason::Revoked,
            });
        }
        self.retire_closed();
    }

    /// Interface change — closes all allocations.
    pub fn interface_change(&mut self) {
        if let Some(ref mut current) = self.current {
            current.close(CloseReason::InterfaceChange);
            let alloc_gen = current.generation;
            self.events.push_back(LifecycleEvent::Closed {
                generation: alloc_gen,
                reason: CloseReason::InterfaceChange,
            });
        }
        if let Some(ref mut nc) = self.noncurrent {
            nc.close(CloseReason::InterfaceChange);
            let alloc_gen = nc.generation;
            self.events.push_back(LifecycleEvent::Closed {
                generation: alloc_gen,
                reason: CloseReason::InterfaceChange,
            });
        }
        self.retire_closed();
    }

    /// Credential expiry — closes all allocations whose credential expiry
    /// has passed.
    pub fn check_credential_expiry(&mut self) {
        let now = self.clock.now_secs();
        let mut closed_current = false;
        if let Some(ref mut current) = self.current {
            if current.credential_expiry <= now && !current.is_closed() {
                let alloc_gen = current.generation;
                current.close(CloseReason::CredentialExpired);
                self.events.push_back(LifecycleEvent::Closed {
                    generation: alloc_gen,
                    reason: CloseReason::CredentialExpired,
                });
                closed_current = true;
            }
        }
        if let Some(ref mut nc) = self.noncurrent {
            // Close the noncurrent if its OWN credential expired, or if the
            // current just expired — an orphaned pending (even one with a newer
            // credential) cannot cut over without a live current, and we never
            // silently promote an unacked pending. Recovery is a fresh allocate.
            if !nc.is_closed() && (nc.credential_expiry <= now || closed_current) {
                let alloc_gen = nc.generation;
                nc.close(CloseReason::CredentialExpired);
                self.events.push_back(LifecycleEvent::Closed {
                    generation: alloc_gen,
                    reason: CloseReason::CredentialExpired,
                });
            }
        }
        self.retire_closed();
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
        let current = self.current.as_mut().ok_or(SendError::Closed)?;
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
                self.events.push_back(LifecycleEvent::Closed {
                    generation,
                    reason: CloseReason::StaleGeneration,
                });
            }
        }
        self.retire_closed();
    }
}

/// Error from `allocate` (safe reason codes only — no server text or
/// credentials).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AllocateError {
    #[error("a noncurrent allocation already exists")]
    NoncurrentExists,
    /// DNS / IP-literal admission failed before any socket was opened.
    #[error("connection plan rejected")]
    Plan(PlanError),
    /// The relay could not be established (fail closed; no allocation created).
    #[error("relay connect failed")]
    Connect(ConnectError),
}

impl AllocateError {
    /// The safe lifecycle close reason for a failed allocation, or `None` for
    /// `NoncurrentExists` (no allocation was attempted).
    pub fn close_reason(&self) -> Option<CloseReason> {
        match self {
            Self::NoncurrentExists => None,
            Self::Plan(PlanError::IpLiteralNotAdmitted) => Some(CloseReason::AllocationFailed),
            Self::Plan(PlanError::Dns(_)) => Some(CloseReason::DnsFailed),
            Self::Connect(e) => Some(e.close_reason()),
        }
    }
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
// Deterministic test-only fakes (NOT public release API — `#[cfg(test)]`).
//
// `FakeClock`, `FakeDnsResolver`, `RecordingConnector`, and
// `assert_no_secret_leak` exist only in test builds so they never appear on
// the release library surface. The former identity-function
// `redact_for_diagnostics` has been deleted (it never redacted anything and
// was a leak trap): secret redaction lives in the `Debug`/`Display` impls of
// the secret types themselves.
// ---------------------------------------------------------------------------

/// A deterministic fake clock for tests.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct FakeClock {
    now: u64,
}

#[cfg(test)]
impl FakeClock {
    pub(crate) fn new(now: u64) -> Self {
        Self { now }
    }
}

#[cfg(test)]
impl ProviderClock for FakeClock {
    fn now_secs(&self) -> u64 {
        self.now
    }
}

/// A deterministic fake DNS resolver for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct FakeDnsResolver {
    /// Map hostname -> addresses to return.
    pub(crate) records: std::collections::HashMap<String, Vec<IpAddr>>,
    /// Whether to fail.
    pub(crate) fail: bool,
    /// Optional forced error (takes precedence over `fail`/records).
    pub(crate) force: Option<DnsError>,
    /// When true, return the recorded answers WITHOUT applying the cap — so a
    /// test can prove the *production* allocate path (not the fake) enforces
    /// `MAX_DNS_ADDRESSES`.
    pub(crate) ignore_cap: bool,
}

#[cfg(test)]
impl DnsResolver for FakeDnsResolver {
    fn resolve(
        &self,
        hostname: &str,
        max_addresses: usize,
        _lookup_deadline: Duration,
    ) -> Result<Vec<IpAddr>, DnsError> {
        if let Some(e) = self.force.clone() {
            return Err(e);
        }
        if self.fail {
            return Err(DnsError::LookupFailed);
        }
        let addrs = self.records.get(hostname).cloned().unwrap_or_default();
        if !self.ignore_cap && addrs.len() > max_addresses {
            return Err(DnsError::TooManyAddresses);
        }
        Ok(addrs)
    }
}

/// A recording transport connector for tests — the ONLY socket-opening seam.
///
/// It records every `connect_and_allocate` call (proving the provider opens a
/// relay socket exactly once per successful allocation and NEVER any other
/// kind of socket), and can be scripted to succeed with a given lifetime or
/// fail with a specific [`ConnectError`]. Because it is the provider's sole
/// socket path, a passing relay-only test proves no direct/host/srflx socket
/// is ever created on any branch.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct RecordingConnector {
    /// Every plan the provider attempted to connect (in order).
    pub(crate) attempts: std::sync::Mutex<Vec<ConnectionPlan>>,
    /// Forced outcome; `None` ⇒ succeed with `granted_lifetime`.
    pub(crate) outcome: Option<ConnectError>,
    /// Lifetime the fake TURN server "grants" on success.
    pub(crate) granted_lifetime: Duration,
}

#[cfg(test)]
impl RecordingConnector {
    pub(crate) fn success(granted_lifetime: Duration) -> Self {
        Self {
            attempts: std::sync::Mutex::new(Vec::new()),
            outcome: None,
            granted_lifetime,
        }
    }

    pub(crate) fn failing(err: ConnectError) -> Self {
        Self {
            attempts: std::sync::Mutex::new(Vec::new()),
            outcome: Some(err),
            granted_lifetime: Duration::from_secs(600),
        }
    }

    pub(crate) fn attempt_count(&self) -> usize {
        self.attempts.lock().unwrap().len()
    }

    pub(crate) fn last_plan(&self) -> Option<ConnectionPlan> {
        self.attempts.lock().unwrap().last().cloned()
    }
}

#[cfg(test)]
impl TurnTransportConnector for RecordingConnector {
    fn connect_and_allocate(
        &self,
        plan: &ConnectionPlan,
        _credentials: &TurnCredentials,
    ) -> Result<EstablishedRelay, ConnectError> {
        self.attempts.lock().unwrap().push(plan.clone());
        if let Some(err) = self.outcome {
            return Err(err);
        }
        Ok(EstablishedRelay {
            allocation_lifetime: self.granted_lifetime,
            transport: plan.transport,
        })
    }
}

// Allow a test to keep a shared handle to the recording connector after moving
// a `Box<dyn TurnTransportConnector>` into the provider, so it can assert the
// recorded socket-open attempts.
#[cfg(test)]
impl TurnTransportConnector for std::sync::Arc<RecordingConnector> {
    fn connect_and_allocate(
        &self,
        plan: &ConnectionPlan,
        credentials: &TurnCredentials,
    ) -> Result<EstablishedRelay, ConnectError> {
        (**self).connect_and_allocate(plan, credentials)
    }
}

/// Assert that a string contains no secret material (username, password).
#[cfg(test)]
pub(crate) fn assert_no_secret_leak(text: &str, creds: &TurnCredentials) {
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

#[cfg(test)]
mod tests;
