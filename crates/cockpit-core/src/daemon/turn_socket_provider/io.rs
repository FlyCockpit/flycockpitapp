//! Real Tokio TURN allocation driver over `turn-client-proto` /
//! `turn-client-rustls`.
//!
//! Compiled only under the `turn-coturn-conformance` feature. This is the live
//! wire path: it drives the audited sans-I/O TURN state machine over real
//! Tokio UDP / TCP / TLS sockets and is exercised against a pinned coturn
//! instance on the Linux CI leg (`remote_turn_socket_provider_coturn_conformance`).
//! It needs live TURN infrastructure and is therefore never part of the default
//! serialized gate; the default build fails closed via
//! [`super::FailClosedConnector`].
//!
//! The driver never opens a host/srflx/direct socket — it only connects the one
//! relay socket for the plan, preserving the relay-only guarantee end to end.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant as TokioInstant;

use turn_client_rustls::proto::api::{
    TurnClientApi, TurnConfig, TurnEvent, TurnPollRet, TurnRecvRet,
};
use turn_client_rustls::proto::types::{Instant as TurnInstant, TransportType, TurnCredentials};
use turn_client_rustls::proto::udp::TurnClientUdp;
use turn_client_rustls::proto::{stun::agent::Transmit, tcp::TurnClientTcp};

use super::{
    CONNECT_STAGGER, ConnectError, ConnectionPlan, EstablishedRelay, PER_ADDRESS_CONNECT_DEADLINE,
    TurnTransport,
};

/// A monotonic clock adapter for the sans-I/O state machine: the crate's
/// `Instant` has no `now()`, so pin a base `std::time::Instant` and advance
/// from it.
struct DriverClock {
    base: std::time::Instant,
    zero: TurnInstant,
}

impl DriverClock {
    fn new() -> Self {
        Self {
            base: std::time::Instant::now(),
            zero: TurnInstant::from_nanos(0),
        }
    }

    fn now(&self) -> TurnInstant {
        self.zero
            .checked_add(self.base.elapsed())
            .unwrap_or(self.zero)
    }
}

const RECV_BUF: usize = 64 * 1024;
const POLL_TICK: Duration = Duration::from_millis(250);

/// Drive one TURN allocation to completion, trying EVERY candidate address in
/// the plan's RFC 8305-interleaved order: a per-address deadline
/// ([`PER_ADDRESS_CONNECT_DEADLINE`]) bounds each attempt, [`CONNECT_STAGGER`]
/// separates them, and a failed/unreachable address falls through to the next.
/// The whole attempt is bounded by ONE absolute deadline (`deadline` from now),
/// so per-address timeouts can never sum past the caller's allocation-attempt
/// budget.
///
/// On any failure no allocation is fabricated and no host/srflx socket is
/// opened. Credentials are taken as raw `&str` so callers (and the conformance
/// test) never need to name the `turn-client-*` types.
pub async fn drive_allocation(
    plan: &ConnectionPlan,
    username: &str,
    password: &str,
    deadline: Duration,
) -> Result<EstablishedRelay, ConnectError> {
    let credentials = TurnCredentials::new(username, password);
    // One absolute deadline threaded through connect + drive for every address.
    let overall_at = TokioInstant::now() + deadline;
    if plan.addresses.is_empty() {
        return Err(ConnectError::ConnectTimeout);
    }

    let mut last_err = ConnectError::ConnectTimeout;
    for (i, &server) in plan.addresses.iter().enumerate() {
        if i > 0 {
            // RFC 8305 stagger between attempts, never past the overall budget.
            let stagger_until = (TokioInstant::now() + CONNECT_STAGGER).min(overall_at);
            tokio::time::sleep_until(stagger_until).await;
        }
        let now = TokioInstant::now();
        if now >= overall_at {
            break;
        }
        // Per-address deadline, clamped to the remaining overall budget.
        let per_addr_at = (now + PER_ADDRESS_CONNECT_DEADLINE).min(overall_at);
        let result = match plan.transport {
            TurnTransport::Udp => drive_udp(server, &credentials, per_addr_at).await,
            TurnTransport::Tcp => drive_tcp(server, &credentials, per_addr_at).await,
            TurnTransport::Tls => drive_tls(plan, server, &credentials, per_addr_at).await,
        };
        match result {
            Ok(relay) => return Ok(relay),
            // Fall through to the next candidate address.
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

async fn drive_udp(
    server: SocketAddr,
    credentials: &TurnCredentials,
    deadline_at: TokioInstant,
) -> Result<EstablishedRelay, ConnectError> {
    let bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|_| ConnectError::ConnectTimeout)?;
    socket
        .connect(server)
        .await
        .map_err(|_| ConnectError::ConnectTimeout)?;
    let local = socket
        .local_addr()
        .map_err(|_| ConnectError::ConnectTimeout)?;

    let config = TurnConfig::new(credentials.clone());
    let mut client = TurnClientUdp::allocate(local, server, config);
    let clock = DriverClock::new();
    let mut buf = vec![0u8; RECV_BUF];

    let overall = tokio::time::sleep_until(deadline_at);
    tokio::pin!(overall);

    loop {
        // Drain outbound STUN/TURN datagrams to the server. Every send is bound
        // by the SAME absolute deadline so a stuck send buffer cannot exceed the
        // allocation-attempt budget.
        while let Some(t) = client.poll_transmit(clock.now()) {
            match tokio::time::timeout_at(deadline_at, socket.send(t.data.as_ref())).await {
                Ok(Ok(_)) => {}
                _ => return Err(ConnectError::ConnectTimeout),
            }
        }
        if let Some(relay) = drain_events(&mut client)? {
            return Ok(relay);
        }

        let wait_until = match client.poll(clock.now()) {
            TurnPollRet::Closed => return Err(ConnectError::AllocationFailed),
            TurnPollRet::WaitUntil(t) => t,
            // No TCP relay sockets on the client-to-server UDP path.
            TurnPollRet::AllocateTcpSocket { .. } | TurnPollRet::TcpClose { .. } => clock.now(),
        };
        let sleep_for = wait_until
            .saturating_duration_since(clock.now())
            .min(POLL_TICK);

        tokio::select! {
            _ = &mut overall => return Err(ConnectError::ConnectTimeout),
            _ = tokio::time::sleep(sleep_for) => {}
            r = socket.recv(&mut buf) => {
                let n = r.map_err(|_| ConnectError::ConnectTimeout)?;
                let rx = Transmit::new(&buf[..n], TransportType::Udp, server, local);
                if let TurnRecvRet::PeerData(_) = client.recv(rx, clock.now()) {
                    // Peer data during allocation is unexpected; ignore.
                }
            }
        }
    }
}

async fn drive_tcp(
    server: SocketAddr,
    credentials: &TurnCredentials,
    deadline_at: TokioInstant,
) -> Result<EstablishedRelay, ConnectError> {
    let stream = connect_tcp(server, deadline_at).await?;
    let local = stream
        .local_addr()
        .map_err(|_| ConnectError::ConnectTimeout)?;
    let mut config = TurnConfig::new(credentials.clone());
    config.set_allocation_transport(TransportType::Udp);
    let client = TurnClientTcp::allocate(local, server, config);
    drive_stream(client, stream, server, local, deadline_at, None).await
}

async fn drive_tls(
    plan: &ConnectionPlan,
    server: SocketAddr,
    credentials: &TurnCredentials,
    deadline_at: TokioInstant,
) -> Result<EstablishedRelay, ConnectError> {
    // aws_lc_rs must be installed before we build any rustls client config.
    crate::tls_crypto_provider::install_process_default()
        .map_err(|_| ConnectError::TlsValidationFailed)?;
    let mut roots = RootCertStore::empty();
    // System roots are best-effort per repo policy: individually malformed OS
    // roots are skipped, but an empty resulting store fails closed below.
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    // Enterprise roots AUGMENT (never replace) system roots, and only when the
    // signed entry allowed it (the plan carries the DERs only in that case). A
    // caller-supplied signed root that will not parse/add is a HARD failure —
    // never silently skipped — so a malformed enterprise root can't be ignored.
    if plan.allow_enterprise_roots {
        for der in &plan.enterprise_root_ders {
            roots
                .add(CertificateDer::from(der.as_slice()))
                .map_err(|_| ConnectError::TlsValidationFailed)?;
        }
    }
    if roots.is_empty() {
        return Err(ConnectError::TlsValidationFailed);
    }
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    // SNI: preserved hostname for DNS names; IP-SAN against the literal address
    // for a signed IP literal (`server_name == None`). rustls verifies the
    // certificate's IP-SAN when the ServerName is an IpAddress.
    let sni: ServerName<'static> = match &plan.server_name {
        Some(name) => {
            ServerName::try_from(name.clone()).map_err(|_| ConnectError::TlsValidationFailed)?
        }
        None => {
            if !plan.require_ip_san_for_literals {
                // The only literal-TLS verification path we support is IP-SAN;
                // a policy that disables it has no safe fallback here.
                return Err(ConnectError::TlsValidationFailed);
            }
            ServerName::IpAddress(server.ip().into())
        }
    };

    let stream = connect_tcp(server, deadline_at).await?;
    let local = stream
        .local_addr()
        .map_err(|_| ConnectError::ConnectTimeout)?;
    let config = TurnConfig::new(credentials.clone());
    let client =
        turn_client_rustls::TurnClientRustls::allocate(local, server, config, sni, tls_config);
    drive_stream(
        client,
        stream,
        server,
        local,
        deadline_at,
        Some(TurnTransport::Tls),
    )
    .await
}

async fn connect_tcp(
    server: SocketAddr,
    deadline_at: TokioInstant,
) -> Result<TcpStream, ConnectError> {
    match tokio::time::timeout_at(deadline_at, TcpStream::connect(server)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(_)) | Err(_) => Err(ConnectError::ConnectTimeout),
    }
}

/// Drive a stream-based (TCP or TLS) TURN client to allocation completion.
async fn drive_stream<C: TurnClientApi>(
    mut client: C,
    stream: TcpStream,
    server: SocketAddr,
    local: SocketAddr,
    deadline_at: TokioInstant,
    tls: Option<TurnTransport>,
) -> Result<EstablishedRelay, ConnectError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut rd, mut wr) = stream.into_split();
    let clock = DriverClock::new();
    let mut buf = vec![0u8; RECV_BUF];

    let overall = tokio::time::sleep_until(deadline_at);
    tokio::pin!(overall);

    loop {
        // Every write is bound by the SAME absolute deadline: a peer that
        // accepts then stops reading fills the send buffer, and without this the
        // write would block past the allocation-attempt budget.
        while let Some(t) = client.poll_transmit(clock.now()) {
            match tokio::time::timeout_at(deadline_at, wr.write_all(t.data.as_ref())).await {
                Ok(Ok(())) => {}
                _ => return Err(ConnectError::ConnectTimeout),
            }
        }
        if let Some(mut relay) = drain_events(&mut client)? {
            if let Some(t) = tls {
                relay.transport = t;
            }
            return Ok(relay);
        }

        let wait_until = match client.poll(clock.now()) {
            TurnPollRet::Closed => return Err(ConnectError::AllocationFailed),
            TurnPollRet::WaitUntil(t) => t,
            TurnPollRet::AllocateTcpSocket { .. } | TurnPollRet::TcpClose { .. } => clock.now(),
        };
        let sleep_for = wait_until
            .saturating_duration_since(clock.now())
            .min(POLL_TICK);

        tokio::select! {
            _ = &mut overall => return Err(ConnectError::ConnectTimeout),
            _ = tokio::time::sleep(sleep_for) => {}
            r = rd.read(&mut buf) => {
                let n = r.map_err(|_| ConnectError::ConnectTimeout)?;
                if n == 0 {
                    return Err(ConnectError::AllocationFailed); // half-close mid-allocation
                }
                let rx = Transmit::new(&buf[..n], TransportType::Tcp, server, local);
                let _ = client.recv(rx, clock.now());
            }
        }
    }
}

/// Poll events; return `Ok(Some(relay))` once an allocation is created,
/// `Err(..)` on an allocation failure (mapped to a safe reason, never raw
/// server text), or `Ok(None)` to keep driving.
fn drain_events<C: TurnClientApi>(
    client: &mut C,
) -> Result<Option<EstablishedRelay>, ConnectError> {
    while let Some(ev) = client.poll_event() {
        match ev {
            TurnEvent::AllocationCreated(_, _) => {
                return Ok(Some(EstablishedRelay {
                    // The concrete granted lifetime is refined by the caller /
                    // refresh loop; report the RFC 5766 default here.
                    allocation_lifetime: Duration::from_secs(600),
                    transport: TurnTransport::Udp,
                }));
            }
            TurnEvent::AllocationCreateFailed(_) => return Err(ConnectError::AllocationFailed),
            _ => {}
        }
    }
    Ok(None)
}
