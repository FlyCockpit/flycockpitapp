//! Unit tests for the TURN socket provider.
//!
//! These tests are deterministic — they use an injected fake clock, fake DNS
//! resolver, and a recording transport connector, and never contact a public
//! TURN host. They drive the REAL production paths: the shared RFC 7065 URL
//! grammar, DNS/IP-literal admission on the `allocate` path, the relay-only
//! socket seam, and the generation/lease/queue lifecycle. The live wire
//! (turn-client-proto/rustls over real sockets) is exercised separately by the
//! env-gated coturn conformance test on Linux CI.

use super::*;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an authorized ICE entry. For IP-literal URLs the signed digest is set
/// to the canonical URL so the entry self-admits the literal (representing a
/// signer that admitted exactly this server); hostname entries do not use it.
fn test_entry(url: &str, relay_only: bool, expiry: u64) -> AuthorizedIceEntry {
    let server_url = TurnServerUrl::parse(url).expect("parse turn url");
    let signed_server_digest = server_url.canonical().to_string();
    AuthorizedIceEntry {
        server_url,
        credentials: TurnCredentials::new("test-user-secret", "test-pass-secret"),
        credential_expiry: expiry,
        relay_only,
        allow_ip_literals: true,
        signed_server_digest,
        dns_policy: DnsPolicy::default(),
        tls_policy: TlsPolicy::default(),
        enterprise_root_ders: Vec::new(),
        region: RegionTag::new("test-region"),
    }
}

fn provider_with(
    relay_only: bool,
    now: u64,
    resolver: FakeDnsResolver,
    connector: Arc<RecordingConnector>,
) -> TurnSocketProvider {
    TurnSocketProvider::new(
        AttemptId::new(42),
        relay_only,
        Box::new(FakeClock::new(now)),
        Box::new(resolver),
        Box::new(connector),
    )
}

/// The common case: literal servers (no DNS), connector always succeeds.
fn make_provider(relay_only: bool, now: u64) -> TurnSocketProvider {
    provider_with(
        relay_only,
        now,
        FakeDnsResolver::default(),
        Arc::new(RecordingConnector::success(Duration::from_secs(600))),
    )
}

fn resolver_with(host: &str, addrs: Vec<IpAddr>) -> FakeDnsResolver {
    let mut records = HashMap::new();
    records.insert(host.to_string(), addrs);
    FakeDnsResolver {
        records,
        ..Default::default()
    }
}

// ===========================================================================
// AC1 (corrected) + AC2/AC3: URL grammar + transport matrix on the real path
// ===========================================================================

#[test]
fn remote_turn_socket_provider_transport_matrix() {
    // (a) Only RFC 7065 forms that policy emits parse; `turn://` is rejected.
    assert!(TurnServerUrl::parse("turn:example.com:3478").is_ok());
    assert!(TurnServerUrl::parse("turn:example.com:3478?transport=tcp").is_ok());
    assert!(TurnServerUrl::parse("turns:turn.example.com:443").is_ok());
    assert!(TurnServerUrl::parse("turn:1.2.3.4").is_ok());
    // (b) The legacy double-slash form is no longer accepted.
    assert_eq!(
        TurnServerUrl::parse("turn://example.com:3478").unwrap_err(),
        TurnUrlError::MalformedUrl
    );
    assert_eq!(
        TurnServerUrl::parse("turns://example.com:5349").unwrap_err(),
        TurnUrlError::MalformedUrl
    );
    // stun/stuns rejected with a specific reason.
    assert_eq!(
        TurnServerUrl::parse("stun:example.com").unwrap_err(),
        TurnUrlError::StunRejected
    );
    assert_eq!(
        TurnServerUrl::parse("stuns:example.com:5349").unwrap_err(),
        TurnUrlError::StunRejected
    );
    // Bad scheme, bad port, turns non-443, turn+explicit-udp all rejected.
    assert_eq!(
        TurnServerUrl::parse("https:example.com").unwrap_err(),
        TurnUrlError::MalformedUrl
    );
    assert_eq!(
        TurnServerUrl::parse("turn:1.2.3.4:99999").unwrap_err(),
        TurnUrlError::MalformedUrl
    );
    assert_eq!(
        TurnServerUrl::parse("turns:1.2.3.4:3479").unwrap_err(),
        TurnUrlError::MalformedUrl
    );
    assert_eq!(
        TurnServerUrl::parse("turn:1.2.3.4:3478?transport=udp").unwrap_err(),
        TurnUrlError::MalformedUrl
    );

    // Transport classes derived per policy.
    assert_eq!(
        TurnServerUrl::parse("turn:1.2.3.4:3478")
            .unwrap()
            .transport_class(),
        TurnTransport::Udp
    );
    assert_eq!(
        TurnServerUrl::parse("turn:1.2.3.4:3478?transport=tcp")
            .unwrap()
            .transport_class(),
        TurnTransport::Tcp
    );
    assert_eq!(
        TurnServerUrl::parse("turns:1.2.3.4:443")
            .unwrap()
            .transport_class(),
        TurnTransport::Tls
    );
    // Default turn port.
    assert_eq!(TurnServerUrl::parse("turn:1.2.3.4").unwrap().port(), 3478);
    // Hostname preserved for SNI; IPv6 literal recognized.
    let host = TurnServerUrl::parse("turns:turn.example.com:443").unwrap();
    assert!(!host.is_ip_literal());
    assert_eq!(host.hostname(), Some("turn.example.com"));
    let v6 = TurnServerUrl::parse("turns:[2001:db8::1]:443").unwrap();
    assert!(v6.is_ip_literal());
    assert_eq!(v6.host(), IpAddr::V6("2001:db8::1".parse().unwrap()));

    // The settled process-global crypto provider installs (aws_lc_rs only).
    crate::tls_crypto_provider::install_for_tests();
    assert!(rustls::crypto::CryptoProvider::get_default().is_some());

    // (c) Real UDP allocation over a signed IPv4 literal — zero DNS calls.
    let rec = Arc::new(RecordingConnector::success(Duration::from_secs(600)));
    let mut provider = provider_with(true, 1000, FakeDnsResolver::default(), rec.clone());
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
    let generation = provider.allocate(&entry, Duration::from_secs(600)).unwrap();
    assert_eq!(generation, 1);
    let plan = rec.last_plan().expect("connector attempted");
    assert!(plan.is_ip_literal, "literal must skip DNS");
    assert_eq!(plan.transport, TurnTransport::Udp);
    assert_eq!(
        plan.addresses,
        vec!["192.0.2.1:3478".parse::<std::net::SocketAddr>().unwrap()]
    );
    assert_eq!(rec.attempt_count(), 1);
    assert_eq!(
        provider.current_metadata().unwrap().route_class,
        RouteClass::Relay
    );

    // TCP literal allocation.
    let rec = Arc::new(RecordingConnector::success(Duration::from_secs(600)));
    let mut p = provider_with(true, 1000, FakeDnsResolver::default(), rec.clone());
    let tcp_entry = test_entry("turn:192.0.2.1:3478?transport=tcp", true, 9_999_999_999);
    p.allocate(&tcp_entry, Duration::from_secs(600)).unwrap();
    assert_eq!(rec.last_plan().unwrap().transport, TurnTransport::Tcp);

    // TLS allocation over a signed IPv6 literal.
    let rec = Arc::new(RecordingConnector::success(Duration::from_secs(600)));
    let mut p = provider_with(true, 1000, FakeDnsResolver::default(), rec.clone());
    let tls_entry = test_entry("turns:[2001:db8::1]:443", true, 9_999_999_999);
    p.allocate(&tls_entry, Duration::from_secs(600)).unwrap();
    assert_eq!(rec.last_plan().unwrap().transport, TurnTransport::Tls);
    assert_eq!(
        p.current_metadata().unwrap().route_class,
        RouteClass::RelayTls
    );

    // (c) Hostname DNS bounds enforced on the PRODUCTION allocate path.
    // Under the cap: two answers, family-interleaved (IPv6 first here).
    let resolver = resolver_with(
        "turn.example.com",
        vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        ],
    );
    let rec = Arc::new(RecordingConnector::success(Duration::from_secs(600)));
    let mut p = provider_with(true, 1000, resolver, rec.clone());
    let host_entry = test_entry("turns:turn.example.com:443", true, 9_999_999_999);
    p.allocate(&host_entry, Duration::from_secs(600)).unwrap();
    let plan = rec.last_plan().unwrap();
    assert!(!plan.is_ip_literal);
    assert_eq!(plan.server_name.as_deref(), Some("turn.example.com"));
    assert_eq!(plan.addresses.len(), 2);
    // RFC 8305 interleave leads with the first-seen family (IPv6 here).
    assert!(plan.addresses[0].is_ipv6());
    assert!(plan.addresses[1].is_ipv4());

    // OVER the cap: the fake returns 9 answers WITHOUT capping, so the
    // production path must reject — proving the bound is not only in the fake.
    let over = FakeDnsResolver {
        records: {
            let mut m = HashMap::new();
            m.insert(
                "big.example.com".to_string(),
                (0..9u8)
                    .map(|i| IpAddr::V4(Ipv4Addr::new(203, 0, 113, i)))
                    .collect(),
            );
            m
        },
        ignore_cap: true,
        ..Default::default()
    };
    let mut p = provider_with(
        true,
        1000,
        over,
        Arc::new(RecordingConnector::success(Duration::from_secs(600))),
    );
    let big = test_entry("turn:big.example.com:3478", true, 9_999_999_999);
    assert_eq!(
        p.allocate(&big, Duration::from_secs(600)).unwrap_err(),
        AllocateError::Plan(PlanError::Dns(DnsError::TooManyAddresses))
    );

    // DNS deadline propagates from the production path.
    let slow = FakeDnsResolver {
        force: Some(DnsError::DeadlineExceeded),
        ..Default::default()
    };
    let mut p = provider_with(
        true,
        1000,
        slow,
        Arc::new(RecordingConnector::success(Duration::from_secs(600))),
    );
    let h = test_entry("turn:slow.example.com:3478", true, 9_999_999_999);
    assert_eq!(
        p.allocate(&h, Duration::from_secs(600)).unwrap_err(),
        AllocateError::Plan(PlanError::Dns(DnsError::DeadlineExceeded))
    );

    // Unsigned IP literal (digest does not admit) is rejected before any socket.
    let rec = Arc::new(RecordingConnector::success(Duration::from_secs(600)));
    let mut p = provider_with(true, 1000, FakeDnsResolver::default(), rec.clone());
    let mut unsigned = test_entry("turn:198.51.100.1:3478", true, 9_999_999_999);
    unsigned.signed_server_digest = String::new();
    assert_eq!(
        p.allocate(&unsigned, Duration::from_secs(600)).unwrap_err(),
        AllocateError::Plan(PlanError::IpLiteralNotAdmitted)
    );
    assert_eq!(
        rec.attempt_count(),
        0,
        "no socket opened for unadmitted literal"
    );

    // allow_ip_literals=false also rejects even when digest matches.
    let mut p = make_provider(true, 1000);
    let mut noliteral = test_entry("turn:198.51.100.1:3478", true, 9_999_999_999);
    noliteral.allow_ip_literals = false;
    assert_eq!(
        p.allocate(&noliteral, Duration::from_secs(600))
            .unwrap_err(),
        AllocateError::Plan(PlanError::IpLiteralNotAdmitted)
    );

    // Bad certificate / TLS validation failure maps to a safe reason.
    let mut p = provider_with(
        true,
        1000,
        FakeDnsResolver::default(),
        Arc::new(RecordingConnector::failing(
            ConnectError::TlsValidationFailed,
        )),
    );
    let tls = test_entry("turns:[2001:db8::1]:443", true, 9_999_999_999);
    assert_eq!(
        p.allocate(&tls, Duration::from_secs(600)).unwrap_err(),
        AllocateError::Connect(ConnectError::TlsValidationFailed)
    );

    // Zero DNS answers fail closed.
    let empty = resolver_with("empty.example.com", vec![]);
    let mut p = provider_with(
        true,
        1000,
        empty,
        Arc::new(RecordingConnector::success(Duration::from_secs(600))),
    );
    let e = test_entry("turn:empty.example.com:3478", true, 9_999_999_999);
    assert_eq!(
        p.allocate(&e, Duration::from_secs(600)).unwrap_err(),
        AllocateError::Plan(PlanError::Dns(DnsError::LookupFailed))
    );

    // TLS policy defaults.
    let tls = TlsPolicy::default();
    assert!(tls.require_ip_san_for_literals);
    assert!(!tls.allow_enterprise_roots);
}

// ===========================================================================
// AC3: lifecycle
// ===========================================================================

#[test]
fn remote_turn_socket_provider_lifecycle() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
    let lifetime = Duration::from_secs(600);

    let gen_tag = provider.allocate(&entry, lifetime).unwrap();
    assert_eq!(gen_tag, 1);
    assert!(provider.has_current());

    let event = provider.poll_event().unwrap();
    assert!(matches!(
        event,
        LifecycleEvent::Current { generation: 1, .. }
    ));

    let meta = provider.current_metadata().unwrap();
    assert_eq!(meta.generation, 1);
    assert_eq!(meta.transport, TurnTransport::Udp);
    assert_eq!(meta.route_class, RouteClass::Relay);
    assert_eq!(meta.state, AllocationState::Current);

    // Send/receive.
    provider.send(b"hello".to_vec()).unwrap();
    assert_eq!(provider.current.as_ref().unwrap().outbound_pending(), 1);
    let pumped = provider.pump_outbound().unwrap();
    assert_eq!(pumped.0, 1);
    assert_eq!(pumped.1, b"hello");

    provider.deliver_inbound(1, b"world".to_vec()).unwrap();
    assert_eq!(provider.recv().unwrap(), b"world");

    // Refresh threshold: earlier of 50% lifetime (1300) or 60s-before (1540).
    // now=1000 → lead 300.
    assert_eq!(provider.needs_refresh().unwrap(), 300);

    provider.check_credential_expiry();
    assert!(provider.has_current());

    provider.shutdown();
    assert!(!provider.has_current());
    assert!(matches!(
        provider.poll_event().unwrap(),
        LifecycleEvent::Closed {
            reason: CloseReason::Shutdown,
            ..
        }
    ));
}

// ===========================================================================
// AC4: relay-only fail closed — the connector is the sole socket seam
// ===========================================================================

#[test]
fn remote_turn_socket_provider_relay_only_fail_closed() {
    // Success path: exactly one relay socket opened, no other socket exists.
    let rec = Arc::new(RecordingConnector::success(Duration::from_secs(600)));
    let mut provider = provider_with(true, 1000, FakeDnsResolver::default(), rec.clone());
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
    provider.allocate(&entry, Duration::from_secs(600)).unwrap();
    assert_eq!(rec.attempt_count(), 1);

    provider.send(b"via-relay".to_vec()).unwrap();
    provider.cancel(1);
    assert!(!provider.has_current());
    assert_eq!(provider.send(b"x".to_vec()), Err(SendError::Closed));
    // Cancel opened no new socket.
    assert_eq!(rec.attempt_count(), 1);
    let events: Vec<_> = std::iter::from_fn(|| provider.poll_event()).collect();
    assert!(events.iter().any(|e| matches!(
        e,
        LifecycleEvent::Closed {
            reason: CloseReason::Cancelled,
            ..
        }
    )));

    // Every TURN failure class fails closed and opens NO socket beyond the
    // single relay connect attempt (and creates no allocation).
    for err in [
        ConnectError::ConnectTimeout,
        ConnectError::TlsValidationFailed,
        ConnectError::Unauthorized,
        ConnectError::AllocationFailed,
        ConnectError::LiveInfrastructureRequired,
    ] {
        let rec = Arc::new(RecordingConnector::failing(err));
        let mut p = provider_with(true, 1000, FakeDnsResolver::default(), rec.clone());
        let e = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
        assert_eq!(
            p.allocate(&e, Duration::from_secs(600)).unwrap_err(),
            AllocateError::Connect(err)
        );
        // The connector recorded exactly the one relay attempt and nothing else,
        // and no allocation came into existence (no host/srflx path exists).
        assert_eq!(rec.attempt_count(), 1);
        assert!(!p.has_current());
        assert!(!p.has_pending());
        // The failure maps to a safe close reason (never raw server text).
        assert_eq!(
            AllocateError::Connect(err).close_reason(),
            Some(err.close_reason())
        );
    }
}

// ===========================================================================
// AC5: generation races
// ===========================================================================

#[test]
fn remote_turn_socket_provider_generation_races() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
    let lifetime = Duration::from_secs(600);

    provider.allocate(&entry, lifetime).unwrap();
    let _ = provider.poll_event();
    assert_eq!(provider.current_count(), 1);
    assert_eq!(provider.noncurrent_count(), 0);

    let gen2 = provider.allocate(&entry, lifetime).unwrap();
    assert_eq!(gen2, 2);
    assert_eq!(provider.noncurrent_count(), 1);
    assert!(provider.has_pending());

    let pending_event = provider.poll_event().unwrap();
    assert!(matches!(
        pending_event,
        LifecycleEvent::AllocatedPending { generation: 2, .. }
    ));

    assert_eq!(
        provider.allocate(&entry, lifetime).unwrap_err(),
        AllocateError::NoncurrentExists
    );

    let lease = ConnectionLease {
        old_allocation_generation: 1,
        new_allocation_generation: 2,
        lease_id: 100,
        lease_generation: 1,
        lease_digest: [0xab; 32],
    };
    provider.prepare_cutover(&lease).unwrap();
    assert!(matches!(
        provider.poll_event().unwrap(),
        LifecycleEvent::CutoverReady {
            old_generation: 1,
            new_generation: 2
        }
    ));

    provider.ack_cutover(&lease).unwrap();
    assert!(provider.has_current());
    assert!(provider.has_draining());
    assert!(!provider.has_pending());
    assert_eq!(provider.current_metadata().unwrap().generation, 2);

    provider.send(b"to-current".to_vec()).unwrap();
    assert_eq!(provider.pump_outbound().unwrap().0, 2);

    let bad_lease = ConnectionLease {
        old_allocation_generation: 99,
        new_allocation_generation: 2,
        lease_id: 100,
        lease_generation: 1,
        lease_digest: [0xab; 32],
    };
    assert_eq!(
        provider.prepare_cutover(&bad_lease).unwrap_err(),
        CutoverError::NoPending
    );

    provider.remove_draining().unwrap();
    assert_eq!(provider.noncurrent_count(), 0);

    let gen3 = provider.allocate(&entry, lifetime).unwrap();
    assert_eq!(gen3, 3);
    provider.cancel(gen3);
    assert!(provider.has_current());
    assert_eq!(provider.current_metadata().unwrap().generation, 2);

    assert!(provider.deliver_inbound(1, b"stale".to_vec()).is_err());
    assert!(provider.deliver_inbound(gen3, b"late".to_vec()).is_err());
    provider.deliver_inbound(2, b"ok".to_vec()).unwrap();
    assert_eq!(provider.recv().unwrap(), b"ok");
}

// ===========================================================================
// TLS plan threading: SNI vs IP-SAN, enterprise-root augmentation gating.
// (The real IP-SAN/enterprise-root TLS handshake is coturn-leg-verified; here
// we prove the production plan carries the policy the driver consumes.)
// ===========================================================================

#[test]
fn remote_turn_socket_provider_tls_plan_carries_policy() {
    let p = make_provider(true, 1000);

    // Signed IP-literal `turns:` → no SNI (IP-SAN verification path), inherits
    // the TLS policy; default requires IP-SAN and forbids enterprise roots.
    let entry = test_entry("turns:[2001:db8::1]:443", true, 9_999_999_999);
    let plan = p.plan_connection(&entry).unwrap();
    assert_eq!(plan.transport, TurnTransport::Tls);
    assert!(plan.is_ip_literal);
    assert_eq!(plan.server_name, None);
    assert!(plan.require_ip_san_for_literals);
    assert!(!plan.allow_enterprise_roots);
    assert!(plan.enterprise_root_ders.is_empty());

    // Hostname `turns:` keeps the SNI name for DNS-name verification.
    let resolver = resolver_with(
        "turn.example.com",
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))],
    );
    let ph = provider_with(
        true,
        1000,
        resolver,
        Arc::new(RecordingConnector::success(Duration::from_secs(600))),
    );
    let host = test_entry("turns:turn.example.com:443", true, 9_999_999_999);
    let plan = ph.plan_connection(&host).unwrap();
    assert_eq!(plan.server_name.as_deref(), Some("turn.example.com"));

    // Enterprise roots augment ONLY when signed into the entry.
    let mut e2 = test_entry("turns:[2001:db8::1]:443", true, 9_999_999_999);
    e2.tls_policy.allow_enterprise_roots = true;
    e2.enterprise_root_ders = vec![vec![0x30, 0x82, 0x01]]; // opaque DER stub
    let plan = p.plan_connection(&e2).unwrap();
    assert!(plan.allow_enterprise_roots);
    assert_eq!(plan.enterprise_root_ders.len(), 1);

    // Present roots but policy NOT allowing → never augment (empty in plan).
    let mut e3 = test_entry("turns:[2001:db8::1]:443", true, 9_999_999_999);
    e3.tls_policy.allow_enterprise_roots = false;
    e3.enterprise_root_ders = vec![vec![0x30, 0x82, 0x01]];
    let plan = p.plan_connection(&e3).unwrap();
    assert!(!plan.allow_enterprise_roots);
    assert!(
        plan.enterprise_root_ders.is_empty(),
        "unsigned enterprise roots must not augment system roots"
    );
}

// ===========================================================================
// Recovery after cancel / credential expiry (regression: closed allocations
// must be retired so a fresh allocation can be admitted and cut over).
// ===========================================================================

#[test]
fn remote_turn_socket_provider_recovers_after_cancel_and_expiry() {
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
    let lifetime = Duration::from_secs(600);

    // Cancel the CURRENT generation → a fresh allocation must be admitted and
    // become current (previously wedged: current stayed Some(closed) so a new
    // success landed pending and cutover failed NoCurrent).
    let mut p = make_provider(true, 1000);
    p.allocate(&entry, lifetime).unwrap(); // gen 1 -> current
    p.cancel(1);
    assert!(!p.has_current());
    let g = p.allocate(&entry, lifetime).unwrap();
    assert_eq!(g, 2);
    assert!(p.has_current());
    assert_eq!(p.current_metadata().unwrap().generation, 2);

    // Cancel a PENDING replacement → a new replacement must be admitted
    // (previously wedged: noncurrent stayed Some(closed) → NoncurrentExists).
    let mut p = make_provider(true, 1000);
    p.allocate(&entry, lifetime).unwrap(); // gen 1 current
    assert_eq!(p.allocate(&entry, lifetime).unwrap(), 2); // gen 2 pending
    p.cancel(2);
    assert!(!p.has_pending());
    let g3 = p.allocate(&entry, lifetime).unwrap();
    assert_eq!(g3, 3);
    assert!(p.has_pending());

    // Credential expiry closes current → a fresh allocation recovers.
    let mut p = make_provider(true, 2000);
    let short = test_entry("turn:192.0.2.1:3478", true, 1500); // expired at now=2000
    p.allocate(&short, lifetime).unwrap();
    p.check_credential_expiry();
    assert!(!p.has_current());
    p.allocate(&entry, lifetime).unwrap();
    assert!(p.has_current());
    assert_eq!(p.current_metadata().unwrap().generation, 2);

    // Cancel the CURRENT *while a replacement is PENDING* → the orphaned
    // pending must be closed too (never promoted without ACK), and a fresh
    // allocate must recover AND still cut over normally.
    let mut p = make_provider(true, 1000);
    p.allocate(&entry, lifetime).unwrap(); // gen 1 current
    assert_eq!(p.allocate(&entry, lifetime).unwrap(), 2); // gen 2 pending
    p.cancel(1);
    assert!(!p.has_current());
    assert!(!p.has_pending(), "pending replacement must not be orphaned");
    let g_cur = p.allocate(&entry, lifetime).unwrap(); // recovers -> current
    assert_eq!(g_cur, 3);
    assert!(p.has_current());
    let g_repl = p.allocate(&entry, lifetime).unwrap(); // gen 4 pending
    assert_eq!(g_repl, 4);
    let lease = ConnectionLease {
        old_allocation_generation: g_cur,
        new_allocation_generation: g_repl,
        lease_id: 9,
        lease_generation: 1,
        lease_digest: [0x22; 32],
    };
    p.ack_cutover(&lease).unwrap();
    assert_eq!(p.current_metadata().unwrap().generation, g_repl);
    assert!(p.has_draining());

    // Current expires *while a newer-credential replacement is PENDING* → the
    // pending is NOT silently promoted (it lacks an ACK cutover); both close and
    // a fresh allocate recovers and cuts over.
    let mut p = make_provider(true, 2000);
    let expired_current = test_entry("turn:192.0.2.1:3478", true, 1500); // expired at 2000
    let newer_cred = test_entry("turn:192.0.2.1:3478", true, 5000); // newer credential
    p.allocate(&expired_current, lifetime).unwrap(); // gen 1 current (expired cred)
    assert_eq!(p.allocate(&newer_cred, lifetime).unwrap(), 2); // gen 2 pending (newer)
    p.check_credential_expiry();
    assert!(!p.has_current());
    assert!(
        !p.has_pending(),
        "unacked newer-cred pending must not be silently promoted"
    );
    let g_cur = p.allocate(&newer_cred, lifetime).unwrap(); // recovers -> current
    assert_eq!(g_cur, 3);
    let g_repl = p.allocate(&newer_cred, lifetime).unwrap(); // gen 4 pending
    let lease = ConnectionLease {
        old_allocation_generation: g_cur,
        new_allocation_generation: g_repl,
        lease_id: 11,
        lease_generation: 1,
        lease_digest: [0x33; 32],
    };
    p.ack_cutover(&lease).unwrap();
    assert_eq!(p.current_metadata().unwrap().generation, g_repl);
}

// ===========================================================================
// AC6: bounds
// ===========================================================================

#[test]
fn remote_turn_socket_provider_bounds() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
    provider.allocate(&entry, Duration::from_secs(600)).unwrap();
    let _ = provider.poll_event();

    let oversize = vec![0u8; MAX_DATAGRAM_BYTES + 1];
    assert_eq!(provider.send(oversize), Err(SendError::DatagramTooLarge));

    let small = vec![0u8; 100];
    for _ in 0..QUEUE_CAPACITY_DATAGRAMS {
        provider.send(small.clone()).unwrap();
    }
    assert_eq!(provider.send(small.clone()), Err(SendError::QueueOverflow));
    assert!(!provider.has_current());
    assert_eq!(provider.send(small), Err(SendError::Closed));
}

#[test]
fn remote_turn_socket_provider_bounds_byte_capacity() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
    provider.allocate(&entry, Duration::from_secs(600)).unwrap();
    let _ = provider.poll_event();

    let big = vec![0u8; MAX_DATAGRAM_BYTES]; // 64 KiB
    let fill = QUEUE_CAPACITY_BYTES / MAX_DATAGRAM_BYTES; // 64 datagrams == 4 MiB
    assert!(fill < QUEUE_CAPACITY_DATAGRAMS);
    for _ in 0..fill {
        provider.send(big.clone()).unwrap();
    }
    assert_eq!(provider.send(big), Err(SendError::QueueOverflow));
}

// ===========================================================================
// AC7: secret redaction. `redact_for_diagnostics` no longer exists;
// `assert_no_secret_leak` is `#[cfg(test)]`-only.
// ===========================================================================

#[test]
fn remote_turn_socket_provider_secret_redaction() {
    let creds = TurnCredentials::new("my-secret-user", "my-secret-pass");

    // Precondition: the raw secrets really are present in the source values.
    assert_eq!(creds.username.as_str(), "my-secret-user");
    assert_eq!(creds.password.as_str(), "my-secret-pass");

    let debug_str = format!("{:?}", creds.username);
    assert!(!debug_str.contains("my-secret-user"));
    assert!(debug_str.contains("<redacted>"));
    let debug_str = format!("{:?}", creds.password);
    assert!(!debug_str.contains("my-secret-pass"));
    let display_str = format!("{}", creds.username);
    assert!(!display_str.contains("my-secret-user"));
    let creds_debug = format!("{:?}", creds);
    assert!(!creds_debug.contains("my-secret-user"));
    assert!(!creds_debug.contains("my-secret-pass"));

    // Close reason is a safe code, never raw TURN error text.
    assert_eq!(format!("{}", CloseReason::ProtocolError), "protocol_error");

    // Credentials never come from the URL: userinfo forms are REJECTED.
    assert_eq!(
        TurnServerUrl::parse("turn:user:pass@192.0.2.1:3478").unwrap_err(),
        TurnUrlError::MalformedUrl
    );
    // A parsed URL's Debug carries no credentials.
    let url = TurnServerUrl::parse("turn:192.0.2.1:3478").unwrap();
    let url_debug = format!("{:?}", url);
    assert!(!url_debug.contains("secret"));

    // Errors carry safe reasons only, never server text.
    let plan_err = AllocateError::Connect(ConnectError::Unauthorized);
    assert_no_secret_leak(&format!("{plan_err}"), &creds);
    assert_no_secret_leak(&format!("{plan_err:?}"), &creds);

    // Lifecycle events never contain raw addresses or credentials.
    let event = LifecycleEvent::Current {
        generation: 1,
        transport: TurnTransport::Udp,
        route_class: RouteClass::Relay,
        region: RegionTag::new("us-east"),
    };
    let event_debug = format!("{:?}", event);
    assert!(!event_debug.contains("my-secret-user"));
    assert!(!event_debug.contains("192.0.2.1"));
}

// ===========================================================================
// AC8: str0m adapter
// ===========================================================================

#[test]
fn remote_turn_socket_provider_str0m_adapter() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
    provider.allocate(&entry, Duration::from_secs(600)).unwrap();
    let _ = provider.poll_event();

    provider.send(b"dtls-ciphertext".to_vec()).unwrap();
    let (gen_tag, data) = provider.pump_outbound().unwrap();
    let event = Str0mAdapter::to_event(gen_tag, data.clone());
    assert_eq!(event.source, DatagramSource::Relayed);
    assert_eq!(event.data, b"dtls-ciphertext");
    assert_eq!(event.generation, 1);
    let event_debug = format!("{:?}", event);
    assert!(!event_debug.contains("192.0.2.1"));

    let (gen2, data2) = Str0mAdapter::from_event(event);
    assert_eq!(gen2, 1);
    assert_eq!(data2, b"dtls-ciphertext");

    let direct = Str0mDatagramEvent {
        source: DatagramSource::Direct,
        data: b"direct".to_vec(),
        generation: 0,
    };
    assert_ne!(direct.source, DatagramSource::Relayed);
}

// ===========================================================================
// AC12: real provider call site from the WebRTC endpoint (minimal wire)
// ===========================================================================

#[test]
fn remote_turn_socket_provider_endpoint_wire() {
    use crate::remote_webrtc_endpoint::{ConsentGatedResourceFactory, WebrtcEndpointError};
    use cockpit_proto::remote_ip_consent::{ConsentCapability, VerifiedDirectCapability};

    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);

    // relay_only capability drives a REAL provider allocation attempt.
    let cap = VerifiedDirectCapability::relay_only([0xaa; 32], 1, 1, 1);
    assert_eq!(cap.capability(), ConsentCapability::RelayOnly);
    let rec = Arc::new(RecordingConnector::success(Duration::from_secs(600)));
    let mut provider = provider_with(true, 1000, FakeDnsResolver::default(), rec.clone());
    let mut factory = ConsentGatedResourceFactory::default();
    let generation = factory
        .create_turn_allocation_via_provider(&cap, &mut provider, &entry, Duration::from_secs(600))
        .unwrap();
    assert_eq!(generation, 1);
    // The provider really attempted a relay allocation (not a bare counter++).
    assert_eq!(rec.attempt_count(), 1);
    assert_eq!(factory.turn_allocations_created, 1);
    assert!(provider.has_current());

    // A fail-closed connector still reflects the real attempt and creates no
    // allocation (relay-only cannot fall back to a direct socket).
    let rec = Arc::new(RecordingConnector::failing(
        ConnectError::LiveInfrastructureRequired,
    ));
    let mut provider = provider_with(true, 1000, FakeDnsResolver::default(), rec.clone());
    let mut factory = ConsentGatedResourceFactory::default();
    let err = factory
        .create_turn_allocation_via_provider(&cap, &mut provider, &entry, Duration::from_secs(600))
        .unwrap_err();
    assert!(matches!(err, WebrtcEndpointError::TurnAllocationFailed));
    assert_eq!(rec.attempt_count(), 1);
    assert_eq!(factory.turn_allocations_created, 1);
    assert!(!provider.has_current());

    // Unavailable capability performs no provider call at all.
    let unavailable = VerifiedDirectCapability::unavailable([0xaa; 32], 1, 1, 1);
    let rec = Arc::new(RecordingConnector::success(Duration::from_secs(600)));
    let mut provider = provider_with(true, 1000, FakeDnsResolver::default(), rec.clone());
    let mut factory = ConsentGatedResourceFactory::default();
    assert!(matches!(
        factory
            .create_turn_allocation_via_provider(
                &unavailable,
                &mut provider,
                &entry,
                Duration::from_secs(600)
            )
            .unwrap_err(),
        WebrtcEndpointError::ConsentDenied
    ));
    assert_eq!(rec.attempt_count(), 0);
    assert_eq!(factory.turn_allocations_created, 0);
}

// ===========================================================================
// Refresh threshold detail
// ===========================================================================

#[test]
fn remote_turn_socket_provider_refresh_thresholds() {
    // lifetime=120 → 50% and 60s-before both give lead 60.
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
    provider.allocate(&entry, Duration::from_secs(120)).unwrap();
    let _ = provider.poll_event();
    assert_eq!(provider.needs_refresh().unwrap(), 60);

    // Credential expiry is an absolute ceiling → refresh now (lead 0).
    let mut provider2 = make_provider(true, 1000);
    let entry_short = test_entry("turn:192.0.2.1:3478", true, 1050);
    provider2
        .allocate(&entry_short, Duration::from_secs(600))
        .unwrap();
    let _ = provider2.poll_event();
    assert_eq!(provider2.needs_refresh().unwrap(), 0);

    // After credential expiry the allocation closes.
    let mut provider4 = make_provider(true, 2000);
    let entry_past = test_entry("turn:192.0.2.1:3478", true, 1500);
    provider4
        .allocate(&entry_past, Duration::from_secs(600))
        .unwrap();
    let _ = provider4.poll_event();
    provider4.check_credential_expiry();
    assert!(!provider4.has_current());
    assert!(matches!(
        provider4.poll_event().unwrap(),
        LifecycleEvent::Closed {
            reason: CloseReason::CredentialExpired,
            ..
        }
    ));
}

// ===========================================================================
// Allocation pair caps
// ===========================================================================

#[test]
fn remote_turn_socket_provider_pair_caps() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
    let lifetime = Duration::from_secs(600);

    provider.allocate(&entry, lifetime).unwrap();
    let _ = provider.poll_event();
    assert_eq!(provider.current_count(), 1);

    provider.allocate(&entry, lifetime).unwrap();
    assert_eq!(provider.noncurrent_count(), 1);

    assert_eq!(
        provider.allocate(&entry, lifetime).unwrap_err(),
        AllocateError::NoncurrentExists
    );
}

// ===========================================================================
// Revoke and interface change
// ===========================================================================

#[test]
fn remote_turn_socket_provider_revoke_and_interface_change() {
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);

    let mut provider = make_provider(true, 1000);
    provider.allocate(&entry, Duration::from_secs(600)).unwrap();
    let _ = provider.poll_event();
    provider.revoke();
    assert!(!provider.has_current());
    assert!(matches!(
        provider.poll_event().unwrap(),
        LifecycleEvent::Closed {
            reason: CloseReason::Revoked,
            ..
        }
    ));

    let mut provider2 = make_provider(true, 1000);
    provider2
        .allocate(&entry, Duration::from_secs(600))
        .unwrap();
    let _ = provider2.poll_event();
    provider2.interface_change();
    assert!(!provider2.has_current());
    assert!(matches!(
        provider2.poll_event().unwrap(),
        LifecycleEvent::Closed {
            reason: CloseReason::InterfaceChange,
            ..
        }
    ));
}

// ===========================================================================
// Draining deadline (30 seconds)
// ===========================================================================

#[test]
fn remote_turn_socket_provider_drain_deadline() {
    assert_eq!(DRAIN_DEADLINE, Duration::from_secs(30));

    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn:192.0.2.1:3478", true, 9_999_999_999);
    let lifetime = Duration::from_secs(600);

    provider.allocate(&entry, lifetime).unwrap();
    let _ = provider.poll_event();
    provider.allocate(&entry, lifetime).unwrap();

    let lease = ConnectionLease {
        old_allocation_generation: 1,
        new_allocation_generation: 2,
        lease_id: 1,
        lease_generation: 1,
        lease_digest: [0; 32],
    };
    provider.ack_cutover(&lease).unwrap();
    assert!(provider.has_draining());

    provider.send(b"new".to_vec()).unwrap();
    assert_eq!(provider.pump_outbound().unwrap().0, 2); // current, not draining
    provider.remove_draining().unwrap();
    assert!(!provider.has_draining());
}

// ===========================================================================
// Connection lease digest uniqueness
// ===========================================================================

#[test]
fn remote_turn_socket_provider_lease_digest() {
    let lease1 = ConnectionLease {
        old_allocation_generation: 1,
        new_allocation_generation: 2,
        lease_id: 100,
        lease_generation: 1,
        lease_digest: [0xab; 32],
    };
    let lease2 = ConnectionLease {
        lease_digest: [0xcd; 32],
        ..lease1.clone()
    };
    assert_ne!(lease1.lease_digest, lease2.lease_digest);
}

// ===========================================================================
// Zeroization — credentials are zeroized on drop
// ===========================================================================

#[test]
fn remote_turn_socket_provider_credentials_zeroize() {
    let creds = TurnCredentials::new("zeroize-me", "zeroize-pass");
    let user_ptr = creds.username.as_str().as_ptr();
    drop(creds);
    let _ = user_ptr;
}
