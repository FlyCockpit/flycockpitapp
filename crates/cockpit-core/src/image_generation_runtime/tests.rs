use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

struct Clock(AtomicU64);
impl RuntimeClock for Clock {
    fn now_millis(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Dns(IpAddr);
impl DnsResolver for Dns {
    fn resolve<'a>(
        &'a self,
        _: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, RuntimeError>> + Send + 'a>> {
        Box::pin(async move { Ok(vec![self.0]) })
    }
}
struct SequenceDns(Mutex<Vec<Vec<IpAddr>>>);
impl DnsResolver for SequenceDns {
    fn resolve<'a>(
        &'a self,
        _: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, RuntimeError>> + Send + 'a>> {
        Box::pin(async move { Ok(self.0.lock().unwrap().remove(0)) })
    }
}
struct Connector;
impl BoundConnector for Connector {
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        candidates: &'a [IpAddr],
        _required_location: AddressClass,
        _: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<ConnectionProof, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            Ok(ConnectionProof {
                authority: authority.into(),
                connected_ip: candidates[0],
                location: classify_address(candidates[0]),
                established_at: 0,
                hops: vec![ConnectionHop {
                    authority: authority.into(),
                    hostname: authority.split(':').next().unwrap().into(),
                    connected_ip: candidates[0],
                    location: classify_address(candidates[0]),
                }],
            })
        })
    }
}
struct ErrorConnector(RuntimeErrorCode);
impl BoundConnector for ErrorConnector {
    fn connect<'a>(
        &'a self,
        _: &'a str,
        _: &'a [IpAddr],
        _: AddressClass,
        _: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<ConnectionProof, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            Err(RuntimeError::new(
                self.0,
                health_state_for_error(self.0).remediation(),
            ))
        })
    }
}
struct MismatchedConnector;
impl BoundConnector for MismatchedConnector {
    fn connect<'a>(
        &'a self,
        authority: &'a str,
        _: &'a [IpAddr],
        _: AddressClass,
        _: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<ConnectionProof, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            Ok(ConnectionProof {
                authority: format!("wrong.{authority}"),
                connected_ip: "1.1.1.1".parse().unwrap(),
                location: AddressClass::PublicRemote,
                established_at: 0,
                hops: vec![],
            })
        })
    }
}
struct Adapter {
    kind: ImageAdapterKind,
    calls: AtomicUsize,
}
impl ImageRuntimeAdapter for Adapter {
    fn kind(&self) -> ImageAdapterKind {
        self.kind
    }
    fn probe<'a>(
        &'a self,
        r: ProbeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeResult, RuntimeError>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            r.limits,
            if r.kind == RefreshKind::Capabilities {
                ProbeLimits::discovery()
            } else {
                ProbeLimits::health()
            }
        );
        Box::pin(async move {
            Ok(ProbeResult {
                state: ImageHealthState::Healthy,
                capability: Some(CapabilitySnapshot {
                    target_id: "target".into(),
                    model_or_workflow_digest: "digest".into(),
                    retrieved_at: 0,
                    expires_at: CAPABILITY_DISPATCH_TTL.as_millis() as u64,
                    provenance: SnapshotProvenance::Live,
                    constraints: BTreeMap::new(),
                }),
                model_or_workflow_digest: Some("digest".into()),
                unavailable_reason: None,
            })
        })
    }
}
fn endpoint() -> ImageEndpoint {
    ImageEndpoint {
        id: "endpoint".into(),
        adapter: ImageAdapterKind::OpenaiImages,
        origin: "https://example.com".into(),
        path_prefix: None,
        credential_ref: Some("secret-ref".into()),
        headers: vec![],
        allow_insecure_transport: false,
        location: ImageLocationClass::PublicCloud,
        enabled: true,
        route_profile_version: 1,
    }
}
fn registry(clock: Arc<Clock>, adapter: Arc<Adapter>) -> ImageRuntimeRegistry {
    ImageRuntimeRegistry::new(
        clock,
        Arc::new(Dns(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))),
        Arc::new(Connector),
        vec![adapter],
    )
    .unwrap()
}

#[tokio::test]
async fn image_generation_runtime_registry() {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let adapter = Arc::new(Adapter {
        kind: ImageAdapterKind::OpenaiImages,
        calls: AtomicUsize::new(0),
    });
    let registry = registry(clock, adapter);
    assert!(
        matches!(registry.adapter(ImageAdapterKind::Comfyui),Err(error) if error.code==RuntimeErrorCode::AdapterMissing)
    );
    let duplicate = ImageRuntimeRegistry::new(
        Arc::new(Clock(AtomicU64::new(0))),
        Arc::new(Dns(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))),
        Arc::new(Connector),
        vec![
            Arc::new(Adapter {
                kind: ImageAdapterKind::OpenaiImages,
                calls: AtomicUsize::new(0),
            }),
            Arc::new(Adapter {
                kind: ImageAdapterKind::OpenaiImages,
                calls: AtomicUsize::new(0),
            }),
        ],
    );
    assert!(matches!(duplicate, Err(error) if error.code == RuntimeErrorCode::Incompatible));
}
#[test]
fn image_generation_runtime_health_states_and_ttls() {
    for state in [
        ImageHealthState::Checking,
        ImageHealthState::Healthy,
        ImageHealthState::Stale,
        ImageHealthState::Unreachable,
        ImageHealthState::DnsDenied,
        ImageHealthState::TlsFailed,
        ImageHealthState::AuthFailed,
        ImageHealthState::Incompatible,
        ImageHealthState::WorkflowInvalid,
        ImageHealthState::Busy,
        ImageHealthState::Disabled,
        ImageHealthState::Unknown,
    ] {
        assert!(!state.code().is_empty());
        assert!(!state.remediation().is_empty())
    }
    assert_eq!(SUCCESS_TTL, Duration::from_secs(30));
    assert_eq!(FAILURE_TTL, Duration::from_secs(5));
    assert_eq!(CAPABILITY_DISPATCH_TTL, Duration::from_secs(900));
    assert_eq!(DISPLAY_STALE_TTL, Duration::from_secs(86400));
}
#[test]
fn image_generation_runtime_limits_are_exact() {
    assert_eq!(
        ProbeLimits::health(),
        ProbeLimits {
            connect_timeout: Duration::from_secs(5),
            header_timeout: Duration::from_secs(15),
            body_limit: 256 * 1024,
            redirect_limit: 3
        }
    );
    assert_eq!(ProbeLimits::discovery().body_limit, 1024 * 1024);
    for (code, state) in [
        (
            RuntimeErrorCode::ConnectTimeout,
            ImageHealthState::Unreachable,
        ),
        (
            RuntimeErrorCode::HeaderTimeout,
            ImageHealthState::Unreachable,
        ),
        (RuntimeErrorCode::BodyLimit, ImageHealthState::Unreachable),
        (
            RuntimeErrorCode::RedirectLimit,
            ImageHealthState::Unreachable,
        ),
    ] {
        assert_eq!(health_state_for_error(code), state);
        assert!(!code.as_str().is_empty());
    }
}

#[tokio::test]
async fn image_generation_runtime_limit_failures_have_stable_results() {
    for code in [
        RuntimeErrorCode::ConnectTimeout,
        RuntimeErrorCode::HeaderTimeout,
        RuntimeErrorCode::BodyLimit,
        RuntimeErrorCode::RedirectLimit,
    ] {
        let registry = ImageRuntimeRegistry::new(
            Arc::new(Clock(AtomicU64::new(0))),
            Arc::new(Dns("8.8.8.8".parse().unwrap())),
            Arc::new(ErrorConnector(code)),
            vec![Arc::new(Adapter {
                kind: ImageAdapterKind::OpenaiImages,
                calls: AtomicUsize::new(0),
            })],
        )
        .unwrap();
        let endpoint = endpoint();
        registry.apply_endpoint(&endpoint, 1, 1);
        assert!(matches!(
            registry
                .refresh(endpoint.clone(), 1, 1, 1, RefreshKind::Health, "digest".into())
                .await,
            Err(error) if error.code == code
        ));
        let snapshot = registry.snapshot(&endpoint.id).unwrap();
        assert_eq!(snapshot.unavailable_reason, Some(code));
        assert_eq!(
            snapshot.expires_at - snapshot.retrieved_at,
            FAILURE_TTL.as_millis() as u64
        );
        let reused = registry
            .refresh(
                endpoint.clone(),
                1,
                1,
                2,
                RefreshKind::Health,
                "digest".into(),
            )
            .await
            .unwrap();
        assert_eq!(reused.request_id, 1);
    }
}

#[test]
fn image_generation_runtime_classifies_embedded_addresses_safely() {
    assert_eq!(
        classify_address(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        AddressClass::Loopback
    );
    assert_eq!(
        classify_address("64:ff9b::7f00:1".parse().unwrap()),
        AddressClass::Loopback
    );
    assert_eq!(
        classify_address("2002:7f00:0001::".parse().unwrap()),
        AddressClass::Loopback
    );
    assert_eq!(
        classify_address("::ffff:192.168.1.1".parse().unwrap()),
        AddressClass::PrivateLan
    );
    assert_eq!(
        classify_address("169.254.169.254".parse().unwrap()),
        AddressClass::Forbidden
    );
}
#[tokio::test]
async fn image_generation_runtime_coalesces_and_discards_stale() {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let adapter = Arc::new(Adapter {
        kind: ImageAdapterKind::OpenaiImages,
        calls: AtomicUsize::new(0),
    });
    let registry = registry(clock, adapter.clone());
    let endpoint = endpoint();
    registry.apply_endpoint(&endpoint, 1, 1);
    let (a, b) = tokio::join!(
        registry.refresh(
            endpoint.clone(),
            1,
            1,
            10,
            RefreshKind::Capabilities,
            "credential-digest".into()
        ),
        registry.refresh(
            endpoint.clone(),
            1,
            1,
            11,
            RefreshKind::Capabilities,
            "credential-digest".into()
        )
    );
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    registry.apply_endpoint(&endpoint, 2, 2);
    let immutable_identity = endpoint.immutable_identity();
    assert!(
        registry
            .commit(endpoint.id.clone(), a.unwrap(), 1, 1, &immutable_identity)
            .is_err()
    );
}
#[tokio::test]
async fn image_generation_runtime_dns_proof_and_dispatch_gate() {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let adapter = Arc::new(Adapter {
        kind: ImageAdapterKind::OpenaiImages,
        calls: AtomicUsize::new(0),
    });
    let registry = registry(clock.clone(), adapter);
    let endpoint = endpoint();
    registry.apply_endpoint(&endpoint, 1, 1);
    let snapshot = registry
        .refresh(
            endpoint.clone(),
            1,
            1,
            1,
            RefreshKind::Capabilities,
            "digest-only".into(),
        )
        .await
        .unwrap();
    assert_eq!(
        snapshot.connection.unwrap().connected_ip,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    );
    assert!(
        registry
            .revalidate_dispatch(&endpoint, "digest-only")
            .await
            .is_ok()
    );
    clock
        .0
        .store(CAPABILITY_DISPATCH_TTL.as_millis() as u64, Ordering::SeqCst);
    registry
        .refresh(
            endpoint.clone(),
            1,
            1,
            2,
            RefreshKind::Health,
            "digest-only".into(),
        )
        .await
        .unwrap();
    clock.0.store(
        CAPABILITY_DISPATCH_TTL.as_millis() as u64 + 1,
        Ordering::SeqCst,
    );
    assert!(
        registry
            .revalidate_dispatch(&endpoint, "digest-only")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn image_generation_runtime_ttls_are_clock_driven_and_stale_is_display_only() {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let adapter = Arc::new(Adapter {
        kind: ImageAdapterKind::OpenaiImages,
        calls: AtomicUsize::new(0),
    });
    let registry = registry(clock.clone(), adapter.clone());
    let endpoint = endpoint();
    registry.apply_endpoint(&endpoint, 1, 1);
    registry
        .refresh(
            endpoint.clone(),
            1,
            1,
            1,
            RefreshKind::Capabilities,
            "digest".into(),
        )
        .await
        .unwrap();
    clock.0.store(30_000, Ordering::SeqCst);
    registry
        .refresh(
            endpoint.clone(),
            1,
            1,
            2,
            RefreshKind::Health,
            "digest".into(),
        )
        .await
        .unwrap();
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    clock.0.store(30_001, Ordering::SeqCst);
    registry
        .refresh(
            endpoint.clone(),
            1,
            1,
            3,
            RefreshKind::Health,
            "digest".into(),
        )
        .await
        .unwrap();
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 2);

    let mut failure = registry.snapshot(&endpoint.id).unwrap();
    failure.state = ImageHealthState::AuthFailed;
    failure.retrieved_at = 0;
    failure.expires_at = FAILURE_TTL.as_millis() as u64;
    failure.unavailable_reason = Some(RuntimeErrorCode::Authentication);
    registry
        .inner
        .cache
        .lock()
        .unwrap()
        .insert(endpoint.id.clone(), failure);
    clock.0.store(5_001, Ordering::SeqCst);
    let stale = registry.snapshot(&endpoint.id).unwrap();
    assert_eq!(stale.state, ImageHealthState::Stale);
    assert_eq!(stale.provenance, SnapshotProvenance::Stale);
    assert!(!stale.dispatchable_at(clock.now_millis()));
    clock
        .0
        .store(DISPLAY_STALE_TTL.as_millis() as u64 + 1, Ordering::SeqCst);
    assert!(registry.snapshot(&endpoint.id).is_none());
}

#[tokio::test]
async fn image_generation_runtime_revalidates_every_redirect_hop() {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let adapter = Arc::new(Adapter {
        kind: ImageAdapterKind::OpenaiImages,
        calls: AtomicUsize::new(0),
    });
    let registry = registry(clock, adapter);
    let proof = ConnectionProof {
        authority: "example.com:443".into(),
        connected_ip: "8.8.8.8".parse().unwrap(),
        location: AddressClass::PublicRemote,
        established_at: 0,
        hops: vec![
            ConnectionHop {
                authority: "example.com:443".into(),
                hostname: "example.com".into(),
                connected_ip: "8.8.8.8".parse().unwrap(),
                location: AddressClass::PublicRemote,
            },
            ConnectionHop {
                authority: "redirect.example:443".into(),
                hostname: "redirect.example".into(),
                connected_ip: "127.0.0.1".parse().unwrap(),
                location: AddressClass::Loopback,
            },
        ],
    };
    assert!(matches!(
        registry
            .validate_connection_hops(
                &proof,
                AddressClass::PublicRemote,
                &["8.8.8.8".parse().unwrap()],
            )
            .await,
        Err(error) if error.code == RuntimeErrorCode::DnsDenied
    ));
    let mut too_many = proof.clone();
    too_many.hops = vec![too_many.hops[0].clone(); REDIRECT_LIMIT + 2];
    assert!(matches!(
        registry
            .validate_connection_hops(
                &too_many,
                AddressClass::PublicRemote,
                &["8.8.8.8".parse().unwrap()],
            )
            .await,
        Err(error) if error.code == RuntimeErrorCode::RedirectLimit
    ));
}

#[tokio::test]
async fn image_generation_runtime_blocks_rebinding_and_mismatched_socket_proofs() {
    let adapter = Arc::new(Adapter {
        kind: ImageAdapterKind::OpenaiImages,
        calls: AtomicUsize::new(0),
    });
    let endpoint = endpoint();
    let rebinding = ImageRuntimeRegistry::new(
        Arc::new(Clock(AtomicU64::new(0))),
        Arc::new(SequenceDns(Mutex::new(vec![
            vec!["8.8.8.8".parse().unwrap()],
            vec!["127.0.0.1".parse().unwrap()],
        ]))),
        Arc::new(Connector),
        vec![adapter.clone()],
    )
    .unwrap();
    rebinding.apply_endpoint(&endpoint, 1, 1);
    rebinding
        .refresh(
            endpoint.clone(),
            1,
            1,
            1,
            RefreshKind::Capabilities,
            "digest".into(),
        )
        .await
        .unwrap();
    assert!(matches!(
        rebinding.revalidate_dispatch(&endpoint, "digest").await,
        Err(error) if error.code == RuntimeErrorCode::DnsDenied
    ));
    assert!(rebinding.snapshot(&endpoint.id).is_none());

    let mismatch = ImageRuntimeRegistry::new(
        Arc::new(Clock(AtomicU64::new(0))),
        Arc::new(Dns("8.8.8.8".parse().unwrap())),
        Arc::new(MismatchedConnector),
        vec![adapter],
    )
    .unwrap();
    mismatch.apply_endpoint(&endpoint, 1, 1);
    assert!(matches!(
        mismatch
            .refresh(endpoint, 1, 1, 1, RefreshKind::Health, "digest".into())
            .await,
        Err(error) if error.code == RuntimeErrorCode::DnsDenied
    ));
}
