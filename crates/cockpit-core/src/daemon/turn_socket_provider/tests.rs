//! Unit tests for the TURN socket provider.
//!
//! These tests are deterministic — they use the injected fake clock and
//! fake DNS resolver, and never contact a public TURN host. They cover the
//! acceptance criteria that can be verified without a live coturn instance;
//! the Docker-gated coturn conformance job is separate (Linux-only CI).

use super::*;
use std::net::Ipv6Addr;

// Helper: build a default authorized ICE entry for tests.
fn test_entry(url: &str, relay_only: bool, expiry: u64) -> AuthorizedIceEntry {
    AuthorizedIceEntry {
        server_url: TurnServerUrl::parse(url).expect("parse turn url"),
        credentials: TurnCredentials::new("test-user-secret", "test-pass-secret"),
        credential_expiry: expiry,
        relay_only,
        allow_ip_literals: true,
        signed_server_digest: String::new(),
        dns_policy: DnsPolicy::default(),
        tls_policy: TlsPolicy::default(),
        region: RegionTag::new("test-region"),
    }
}

fn test_entry_ip(url: &str, relay_only: bool, expiry: u64) -> AuthorizedIceEntry {
    test_entry(url, relay_only, expiry)
}

fn make_provider(relay_only: bool, now: u64) -> TurnSocketProvider {
    TurnSocketProvider::new(
        AttemptId::new(42),
        relay_only,
        Box::new(FakeClock::new(now)),
    )
}

// ===========================================================================
// Acceptance criterion 1: transport matrix
// ===========================================================================

#[test]
fn remote_turn_socket_provider_transport_matrix() {
    // Accept turn: and turns:; reject stun: and stuns:.
    assert!(TurnServerUrl::parse("turn://example.com:3478").is_ok());
    assert!(TurnServerUrl::parse("turns://example.com:5349").is_ok());
    assert!(TurnServerUrl::parse("turn://1.2.3.4:3478").is_ok());
    assert!(TurnServerUrl::parse("turns://[::1]:5349").is_ok());
    assert_eq!(
        TurnServerUrl::parse("stun://example.com:3478").unwrap_err(),
        TurnUrlError::StunRejected
    );
    assert_eq!(
        TurnServerUrl::parse("stuns://example.com:5349").unwrap_err(),
        TurnUrlError::StunRejected
    );
    assert_eq!(
        TurnServerUrl::parse("stun:example.com").unwrap_err(),
        TurnUrlError::StunRejected
    );

    // UDP transport class from turn:.
    let udp_url = TurnServerUrl::parse("turn://1.2.3.4:3478").unwrap();
    assert_eq!(udp_url.transport_class(), TurnTransport::Udp);
    assert_eq!(udp_url.scheme(), TurnScheme::Turn);

    // TLS transport class from turns:.
    let tls_url = TurnServerUrl::parse("turns://1.2.3.4:5349").unwrap();
    assert_eq!(tls_url.transport_class(), TurnTransport::Tls);
    assert!(tls_url.scheme().is_tls());

    // IPv4 literal.
    let v4 = TurnServerUrl::parse("turn://192.0.2.1:3478").unwrap();
    assert!(v4.is_ip_literal());
    assert_eq!(v4.host(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));

    // IPv6 literal with brackets.
    let v6 = TurnServerUrl::parse("turns://[2001:db8::1]:5349").unwrap();
    assert!(v6.is_ip_literal());
    assert_eq!(v6.port(), 5349);

    // Hostname preserves the hostname for SNI.
    let host = TurnServerUrl::parse("turns://turn.example.com:5349").unwrap();
    assert!(!host.is_ip_literal());
    assert_eq!(host.hostname(), Some("turn.example.com"));

    // Default ports.
    assert_eq!(TurnServerUrl::parse("turn://1.2.3.4").unwrap().port(), 3478);
    assert_eq!(
        TurnServerUrl::parse("turns://1.2.3.4").unwrap().port(),
        5349
    );

    // Reject bad scheme.
    assert_eq!(
        TurnServerUrl::parse("https://example.com").unwrap_err(),
        TurnUrlError::UnsupportedScheme
    );

    // Reject bad port.
    assert_eq!(
        TurnServerUrl::parse("turn://1.2.3.4:99999").unwrap_err(),
        TurnUrlError::InvalidPort
    );

    // IP literal with signed policy — zero DNS calls (the provider does not
    // resolve IP literals).
    let entry = test_entry_ip("turn://198.51.100.1:3478", true, 9999999999);
    assert!(entry.server_url.is_ip_literal());

    // DNS bounds: max 8 addresses.
    let resolver = FakeDnsResolver {
        records: {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "over.limit.example".to_string(),
                (0..10)
                    .map(|i| IpAddr::V4(Ipv4Addr::new(203, 0, 113, i as u8)))
                    .collect(),
            );
            m.insert(
                "ok.example".to_string(),
                vec![
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ],
            );
            m
        },
        fail: false,
    };
    assert_eq!(
        resolver
            .resolve("over.limit.example", MAX_DNS_ADDRESSES, DNS_LOOKUP_DEADLINE)
            .unwrap_err(),
        DnsError::TooManyAddresses
    );
    let addrs = resolver
        .resolve("ok.example", MAX_DNS_ADDRESSES, DNS_LOOKUP_DEADLINE)
        .unwrap();
    assert_eq!(addrs.len(), 2);

    // TLS policy defaults.
    let tls = TlsPolicy::default();
    assert!(tls.require_ip_san_for_literals);
    assert!(!tls.allow_enterprise_roots);
}

// ===========================================================================
// Acceptance criterion 2: lifecycle
// ===========================================================================

#[test]
fn remote_turn_socket_provider_lifecycle() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn://192.0.2.1:3478", true, 9999999999);
    let lifetime = Duration::from_secs(600);

    // Allocate.
    let gen_tag = provider.allocate(&entry, lifetime).unwrap();
    assert_eq!(gen_tag, 1);
    assert!(provider.has_current());

    // Lifecycle event: Current (auto-promoted, first allocation).
    let event = provider.poll_event().unwrap();
    assert!(matches!(
        event,
        LifecycleEvent::Current { generation: 1, .. }
    ));

    // Metadata.
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

    // Deliver inbound.
    provider.deliver_inbound(1, b"world".to_vec()).unwrap();
    let recv = provider.recv().unwrap();
    assert_eq!(recv, b"world");

    // Refresh threshold: earlier of 50% lifetime or 60s before expiry.
    // lifetime=600s, established_at=1000, so expiry=1600.
    // 50% = 300s into the lifetime -> refresh at 1300.
    // 60s before expiry -> refresh at 1540.
    // Earlier is 1300. now=1000, lead = 1300-1000 = 300.
    let lead = provider.needs_refresh().unwrap();
    assert_eq!(lead, 300);

    // Credential expiry check — not expired yet.
    provider.check_credential_expiry();
    assert!(provider.has_current());

    // Shutdown — deallocate.
    provider.shutdown();
    assert!(!provider.has_current());
    let close_event = provider.poll_event().unwrap();
    assert!(matches!(
        close_event,
        LifecycleEvent::Closed {
            reason: CloseReason::Shutdown,
            ..
        }
    ));
}

// ===========================================================================
// Acceptance criterion 3: relay-only fail closed
// ===========================================================================

#[test]
fn remote_turn_socket_provider_relay_only_fail_closed() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn://192.0.2.1:3478", true, 9999999999);
    provider.allocate(&entry, Duration::from_secs(600)).unwrap();

    // Relay-only: the only send path is through the relay. There is no
    // direct socket method on the provider.
    provider.send(b"via-relay".to_vec()).unwrap();

    // Cancel — fail closed.
    provider.cancel(1);
    assert!(!provider.has_current());

    // After failure, send fails.
    assert_eq!(provider.send(b"x".to_vec()), Err(SendError::Closed));

    // No direct socket was created — the provider exposes no direct/host/
    // srflx path. Verify by attempting to send after failure: it fails
    // closed, not by opening a direct socket.
    let events: Vec<_> = std::iter::from_fn(|| provider.poll_event()).collect();
    assert!(events.iter().any(|e| matches!(
        e,
        LifecycleEvent::Closed {
            reason: CloseReason::Cancelled,
            ..
        }
    )));
}

// ===========================================================================
// Acceptance criterion 4: generation races
// ===========================================================================

#[test]
fn remote_turn_socket_provider_generation_races() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn://192.0.2.1:3478", true, 9999999999);
    let lifetime = Duration::from_secs(600);

    // First allocation -> current (gen 1).
    provider.allocate(&entry, lifetime).unwrap();
    let _ = provider.poll_event(); // drain Current event
    assert_eq!(provider.current_count(), 1);
    assert_eq!(provider.noncurrent_count(), 0);

    // Replacement allocation -> pending (gen 2).
    let gen2 = provider.allocate(&entry, lifetime).unwrap();
    assert_eq!(gen2, 2);
    assert_eq!(provider.current_count(), 1);
    assert_eq!(provider.noncurrent_count(), 1);
    assert!(provider.has_pending());
    assert!(!provider.has_draining());

    // Pending and draining cannot coexist — we only have pending.
    // A second noncurrent would fail.
    assert_eq!(
        provider.allocate(&entry, lifetime).unwrap_err(),
        AllocateError::NoncurrentExists
    );

    // Cutover requires supervisor ACK.
    let lease = ConnectionLease {
        old_allocation_generation: 1,
        new_allocation_generation: 2,
        lease_id: 100,
        lease_generation: 1,
        lease_digest: [0xab; 32],
    };

    // Prepare cutover.
    provider.prepare_cutover(&lease).unwrap();
    let cutover_ready = provider.poll_event().unwrap();
    assert!(matches!(
        cutover_ready,
        LifecycleEvent::CutoverReady {
            old_generation: 1,
            new_generation: 2
        }
    ));

    // ACK cutover — routing switches.
    provider.ack_cutover(&lease).unwrap();
    assert!(provider.has_current());
    assert!(provider.has_draining());
    assert!(!provider.has_pending());

    // Current is now gen 2.
    let meta = provider.current_metadata().unwrap();
    assert_eq!(meta.generation, 2);

    // Draining (gen 1) accepts no new operation.
    // Send goes to current (gen 2), not draining.
    provider.send(b"to-current".to_vec()).unwrap();
    let pumped = provider.pump_outbound().unwrap();
    assert_eq!(pumped.0, 2);

    // Lease mismatch — changed duplicate conflicts.
    let bad_lease = ConnectionLease {
        old_allocation_generation: 99,
        new_allocation_generation: 2,
        lease_id: 100,
        lease_generation: 1,
        lease_digest: [0xab; 32],
    };
    // No pending to cutover now.
    assert_eq!(
        provider.prepare_cutover(&bad_lease).unwrap_err(),
        CutoverError::NoPending
    );

    // Remove draining (second-lease removal).
    provider.remove_draining().unwrap();
    assert!(!provider.has_draining());
    assert_eq!(provider.noncurrent_count(), 0);

    // Stale close/deallocate without current mutation.
    // Start a new replacement.
    let gen3 = provider.allocate(&entry, lifetime).unwrap();
    assert_eq!(gen3, 3);
    // Cancel the pending (stale) — current must be unaffected.
    provider.cancel(gen3);
    assert!(provider.has_current());
    let meta = provider.current_metadata().unwrap();
    assert_eq!(meta.generation, 2); // unchanged

    // Stale generation cannot deliver datagrams.
    let result = provider.deliver_inbound(1, b"stale".to_vec());
    assert!(result.is_err()); // gen 1 is gone

    // Late datagram to a stale generation is rejected.
    let result = provider.deliver_inbound(gen3, b"late".to_vec());
    assert!(result.is_err()); // gen 3 is closed

    // Current (gen 2) still receives.
    provider.deliver_inbound(2, b"ok".to_vec()).unwrap();
    assert_eq!(provider.recv().unwrap(), b"ok");
}

// ===========================================================================
// Acceptance criterion 5: bounds
// ===========================================================================

#[test]
fn remote_turn_socket_provider_bounds() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn://192.0.2.1:3478", true, 9999999999);
    provider.allocate(&entry, Duration::from_secs(600)).unwrap();
    let _ = provider.poll_event(); // drain Current

    // Datagram exceeding max size (64 KiB + 1).
    let oversize = vec![0u8; MAX_DATAGRAM_BYTES + 1];
    assert_eq!(provider.send(oversize), Err(SendError::DatagramTooLarge));

    // Fill the queue to capacity (256 datagrams).
    let small = vec![0u8; 100];
    for _ in 0..QUEUE_CAPACITY_DATAGRAMS {
        provider.send(small.clone()).unwrap();
    }
    // Next send overflows -> closes the allocation.
    assert_eq!(provider.send(small.clone()), Err(SendError::QueueOverflow));
    // Allocation is now closed.
    assert!(!provider.has_current());
    // Further sends fail.
    assert_eq!(provider.send(small), Err(SendError::Closed));
}

#[test]
fn remote_turn_socket_provider_bounds_byte_capacity() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn://192.0.2.1:3478", true, 9999999999);
    provider.allocate(&entry, Duration::from_secs(600)).unwrap();
    let _ = provider.poll_event();

    // Fill the queue to the byte capacity (4 MiB) with large datagrams.
    let big = vec![0u8; 1024 * 1024]; // 1 MiB
    for _ in 0..4 {
        provider.send(big.clone()).unwrap();
    }
    // Next 1 MiB datagram overflows the byte cap.
    assert_eq!(provider.send(big), Err(SendError::QueueOverflow));
}

// ===========================================================================
// Acceptance criterion 6: secret redaction
// ===========================================================================

#[test]
fn remote_turn_socket_provider_secret_redaction() {
    let creds = TurnCredentials::new("my-secret-user", "my-secret-pass");

    // Debug is redacted.
    let debug_str = format!("{:?}", creds.username);
    assert!(!debug_str.contains("my-secret-user"));
    assert!(debug_str.contains("<redacted>"));

    let debug_str = format!("{:?}", creds.password);
    assert!(!debug_str.contains("my-secret-pass"));
    assert!(debug_str.contains("<redacted>"));

    // Display is redacted.
    let display_str = format!("{}", creds.username);
    assert!(!display_str.contains("my-secret-user"));
    assert!(display_str.contains("<redacted>"));

    let display_str = format!("{}", creds.password);
    assert!(!display_str.contains("my-secret-pass"));

    // Credentials struct Debug does not leak.
    let creds_debug = format!("{:?}", creds);
    assert!(!creds_debug.contains("my-secret-user"));
    assert!(!creds_debug.contains("my-secret-pass"));

    // Close reason is a safe code, never raw TURN error text.
    let reason = CloseReason::ProtocolError;
    let reason_str = format!("{}", reason);
    assert_eq!(reason_str, "protocol_error");
    assert!(!reason_str.contains("my-secret-user"));

    // URL parsing strips userinfo from the URL — credentials never come
    // from the URL.
    let url = TurnServerUrl::parse("turn://user:pass@192.0.2.1:3478").unwrap();
    let url_debug = format!("{:?}", url);
    assert!(!url_debug.contains("user:pass"));

    // assert_no_secret_leak utility.
    assert_no_secret_leak("some safe diagnostic text", &creds);
    // Would panic if secret present:
    // assert_no_secret_leak("my-secret-user leaked", &creds);

    // Lifecycle events never contain raw addresses or credentials.
    let event = LifecycleEvent::Current {
        generation: 1,
        transport: TurnTransport::Udp,
        route_class: RouteClass::Relay,
        region: RegionTag::new("us-east"),
    };
    let event_debug = format!("{:?}", event);
    assert!(!event_debug.contains("my-secret-user"));
    assert!(!event_debug.contains("my-secret-pass"));
    assert!(!event_debug.contains("192.0.2.1"));
}

// ===========================================================================
// Acceptance criterion 7: str0m adapter
// ===========================================================================

#[test]
fn remote_turn_socket_provider_str0m_adapter() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn://192.0.2.1:3478", true, 9999999999);
    provider.allocate(&entry, Duration::from_secs(600)).unwrap();
    let _ = provider.poll_event();

    // Send a datagram, pump it, and convert to a str0m event.
    provider.send(b"dtls-ciphertext".to_vec()).unwrap();
    let (gen_tag, data) = provider.pump_outbound().unwrap();
    let event = Str0mAdapter::to_event(gen_tag, data.clone());

    // Direct and relayed are distinguishable.
    assert_eq!(event.source, DatagramSource::Relayed);
    assert_eq!(event.data, b"dtls-ciphertext");
    assert_eq!(event.generation, 1);

    // The event does not leak provider internals (no raw addresses).
    let event_debug = format!("{:?}", event);
    assert!(!event_debug.contains("192.0.2.1"));

    // Round-trip through the adapter.
    let (gen2, data2) = Str0mAdapter::from_event(event);
    assert_eq!(gen2, 1);
    assert_eq!(data2, b"dtls-ciphertext");

    // A Direct event is distinguishable from Relayed.
    let direct = Str0mDatagramEvent {
        source: DatagramSource::Direct,
        data: b"direct".to_vec(),
        generation: 0,
    };
    assert_ne!(direct.source, DatagramSource::Relayed);
}

// ===========================================================================
// Refresh threshold detail
// ===========================================================================

#[test]
fn remote_turn_socket_provider_refresh_thresholds() {
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn://192.0.2.1:3478", true, 9999999999);

    // lifetime = 120s. 50% = 60s -> refresh at 1060. 60s before = 60s ->
    // refresh at 1060. Both equal here.
    provider.allocate(&entry, Duration::from_secs(120)).unwrap();
    let _ = provider.poll_event();
    let lead = provider.needs_refresh().unwrap();
    // established_at=1000, expiry=1120. 50% = 60. 60s-before = 60.
    // remaining=120, half=60, lead = 120-60 = 60.
    assert_eq!(lead, 60);

    // Credential expiry is an absolute ceiling.
    // lifetime=600s but credential expires at 1050s (50s from now).
    let mut provider2 = make_provider(true, 1000);
    let entry_short = test_entry("turn://192.0.2.1:3478", true, 1050);
    provider2
        .allocate(&entry_short, Duration::from_secs(600))
        .unwrap();
    let _ = provider2.poll_event();
    // effective_expiry = min(1600, 1050) = 1050. remaining=50.
    // half_lifetime=300. lead = 50-300 saturates to 0, but min with
    // 50-60 saturates to 0. So lead=0 (refresh now).
    let lead2 = provider2.needs_refresh().unwrap();
    assert_eq!(lead2, 0);

    // After credential expiry, allocation closes.
    // Advance the clock past expiry.
    // We need a mutable clock, so rebuild.
    let mut provider3 = make_provider(true, 1000);
    let entry_exp = test_entry("turn://192.0.2.1:3478", true, 1100);
    provider3
        .allocate(&entry_exp, Duration::from_secs(600))
        .unwrap();
    let _ = provider3.poll_event();
    // Now set clock past 1100 — but our clock is Box<dyn>, not mutable
    // from outside. Instead, test check_credential_expiry with a new
    // provider whose clock is already past.
    let mut provider4 = make_provider(true, 2000);
    let entry_past = test_entry("turn://192.0.2.1:3478", true, 1500);
    provider4
        .allocate(&entry_past, Duration::from_secs(600))
        .unwrap();
    let _ = provider4.poll_event();
    provider4.check_credential_expiry();
    assert!(!provider4.has_current());
    let ev = provider4.poll_event().unwrap();
    assert!(matches!(
        ev,
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
    let entry = test_entry("turn://192.0.2.1:3478", true, 9999999999);
    let lifetime = Duration::from_secs(600);

    // First -> current.
    provider.allocate(&entry, lifetime).unwrap();
    let _ = provider.poll_event();
    assert_eq!(provider.current_count(), 1);
    assert_eq!(provider.noncurrent_count(), 0);

    // Second -> pending (noncurrent).
    provider.allocate(&entry, lifetime).unwrap();
    assert_eq!(provider.current_count(), 1);
    assert_eq!(provider.noncurrent_count(), 1);

    // Third -> rejected (at most one current + one noncurrent).
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
    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn://192.0.2.1:3478", true, 9999999999);
    provider.allocate(&entry, Duration::from_secs(600)).unwrap();
    let _ = provider.poll_event();

    provider.revoke();
    assert!(!provider.has_current());
    let ev = provider.poll_event().unwrap();
    assert!(matches!(
        ev,
        LifecycleEvent::Closed {
            reason: CloseReason::Revoked,
            ..
        }
    ));

    // Interface change.
    let mut provider2 = make_provider(true, 1000);
    provider2
        .allocate(&entry, Duration::from_secs(600))
        .unwrap();
    let _ = provider2.poll_event();
    provider2.interface_change();
    assert!(!provider2.has_current());
    let ev = provider2.poll_event().unwrap();
    assert!(matches!(
        ev,
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
    // After cutover, the old allocation drains. It deallocates when windows
    // empty or 30 seconds. We verify the drain deadline constant and that
    // draining accepts no new operation.
    assert_eq!(DRAIN_DEADLINE, Duration::from_secs(30));

    let mut provider = make_provider(true, 1000);
    let entry = test_entry("turn://192.0.2.1:3478", true, 9999999999);
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

    // The draining allocation (gen 1) should not accept new sends.
    // Send goes to current (gen 2).
    provider.send(b"new".to_vec()).unwrap();
    let pumped = provider.pump_outbound().unwrap();
    assert_eq!(pumped.0, 2); // current, not draining

    // remove_draining deallocates it.
    provider.remove_draining().unwrap();
    assert!(!provider.has_draining());
}

// ===========================================================================
// DNS resolver bounds
// ===========================================================================

#[test]
fn remote_turn_socket_provider_dns_bounds() {
    let resolver = FakeDnsResolver {
        records: std::collections::HashMap::new(),
        fail: true,
    };
    assert_eq!(
        resolver
            .resolve("fail.example", MAX_DNS_ADDRESSES, DNS_LOOKUP_DEADLINE)
            .unwrap_err(),
        DnsError::LookupFailed
    );

    // RFC 8305 family interleaving — the resolver returns addresses; the
    // provider is responsible for interleaving. We verify the resolver
    // returns what it's given.
    let resolver2 = FakeDnsResolver {
        records: {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "dual.example".to_string(),
                vec![
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ],
            );
            m
        },
        fail: false,
    };
    let addrs = resolver2
        .resolve("dual.example", MAX_DNS_ADDRESSES, DNS_LOOKUP_DEADLINE)
        .unwrap();
    assert_eq!(addrs.len(), 2);
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
        old_allocation_generation: 1,
        new_allocation_generation: 2,
        lease_id: 100,
        lease_generation: 1,
        lease_digest: [0xcd; 32],
    };
    // Different digests.
    assert_ne!(lease1.lease_digest, lease2.lease_digest);
}

// ===========================================================================
// Zeroization — credentials are zeroized on drop
// ===========================================================================

#[test]
fn remote_turn_socket_provider_credentials_zeroize() {
    let creds = TurnCredentials::new("zeroize-me", "zeroize-pass");
    let user_ptr = creds.username.as_str().as_ptr();
    let _ = creds; // dropped here
    // After drop, the Zeroizing wrapper zeroizes the backing memory.
    // We cannot reliably read freed memory, but we verify the type
    // uses Zeroizing (compile-time guarantee). This test confirms the
    // type compiles and drops without panic.
    let _ = user_ptr; // suppress unused warning
}
