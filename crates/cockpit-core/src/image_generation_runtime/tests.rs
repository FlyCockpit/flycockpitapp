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
    fn execute<'a>(
        &'a self,
        request: ReadOnlyProbeRequest,
        candidates: &'a [IpAddr],
        _required_location: AddressClass,
        _: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<BoundProbeResponse, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            let origin = request.url;
            let hostname = origin.host_str().unwrap();
            let authority = origin_authority(&origin, hostname);
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
struct ErrorConnector(RuntimeErrorCode);
impl BoundConnector for ErrorConnector {
    fn execute<'a>(
        &'a self,
        _: ReadOnlyProbeRequest,
        _: &'a [IpAddr],
        _: AddressClass,
        _: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<BoundProbeResponse, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            Err(RuntimeError::new(
                self.0,
                health_state_for_error(self.0).remediation(),
            ))
        })
    }
}
struct PendingConnector;
impl BoundConnector for PendingConnector {
    fn execute<'a>(
        &'a self,
        _: ReadOnlyProbeRequest,
        _: &'a [IpAddr],
        _: AddressClass,
        _: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<BoundProbeResponse, RuntimeError>> + Send + 'a>> {
        Box::pin(std::future::pending())
    }
}
struct MismatchedConnector;
impl BoundConnector for MismatchedConnector {
    fn execute<'a>(
        &'a self,
        request: ReadOnlyProbeRequest,
        _: &'a [IpAddr],
        _: AddressClass,
        _: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<BoundProbeResponse, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            let authority = origin_authority(&request.url, request.url.host_str().unwrap());
            Ok(BoundProbeResponse {
                status: reqwest::StatusCode::OK,
                body: Vec::new(),
                connection: ConnectionProof {
                    authority: format!("wrong.{authority}"),
                    connected_ip: "1.1.1.1".parse().unwrap(),
                    location: AddressClass::PublicRemote,
                    established_at: 0,
                    hops: vec![],
                },
            })
        })
    }
}
struct ControlledConnector {
    calls: AtomicUsize,
    started: tokio::sync::mpsc::UnboundedSender<usize>,
    releases: Vec<Arc<Notify>>,
}
impl BoundConnector for ControlledConnector {
    fn execute<'a>(
        &'a self,
        request: ReadOnlyProbeRequest,
        candidates: &'a [IpAddr],
        _: AddressClass,
        _: ProbeLimits,
    ) -> Pin<Box<dyn Future<Output = Result<BoundProbeResponse, RuntimeError>> + Send + 'a>> {
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.started.send(index);
        Box::pin(async move {
            self.releases[index].notified().await;
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
struct Adapter {
    kind: ImageAdapterKind,
    calls: AtomicUsize,
}
impl adapter_sealed::Sealed for Adapter {}
impl ImageRuntimeAdapter for Adapter {
    fn kind(&self) -> ImageAdapterKind {
        self.kind
    }
    fn request(&self, r: &ProbeRequest) -> Result<ReadOnlyProbeRequest, RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            r.limits,
            if r.kind == RefreshKind::Capabilities {
                ProbeLimits::discovery()
            } else {
                ProbeLimits::health()
            }
        );
        let url = reqwest::Url::parse(&r.endpoint.origin).unwrap();
        Ok(r.read_only_request(url))
    }
    fn parse(
        &self,
        _request: &ProbeRequest,
        _response: &BoundProbeResponse,
    ) -> Result<ProbeResult, RuntimeError> {
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
    }
}
fn endpoint() -> ImageEndpoint {
    ImageEndpoint {
        id: "endpoint".into(),
        adapter: ImageAdapterKind::OpenaiImages,
        origin: "https://example.com".into(),
        path_prefix: None,
        credential_ref: None,
        headers: vec![],
        allow_insecure_transport: false,
        location: ImageLocationClass::PublicCloud,
        enabled: true,
        route_profile_version: 1,
        exclusive_server: false,
    }
}
fn credential_digest(seed: u8) -> CredentialIdentityDigest {
    CredentialIdentityDigest::from_sha256([seed; 32])
}
fn apply_endpoint_and_target(
    registry: &ImageRuntimeRegistry,
    endpoint: &ImageEndpoint,
    generation: u64,
    epoch: u64,
) {
    registry.apply_endpoint(endpoint, generation, epoch);
    registry.apply_test_target("target", &endpoint.id, generation, epoch, "digest");
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
fn image_generation_standard_registry_requires_every_exact_adapter_slot() {
    let adapter = |kind| {
        Arc::new(Adapter {
            kind,
            calls: AtomicUsize::new(0),
        }) as Arc<dyn ImageRuntimeAdapter>
    };
    let standard = StandardImageRuntimeAdapters {
        openai_images: adapter(ImageAdapterKind::OpenaiImages),
        openrouter_images: adapter(ImageAdapterKind::OpenrouterImages),
        gemini_images: adapter(ImageAdapterKind::GeminiImages),
        comfyui: adapter(ImageAdapterKind::Comfyui),
    };
    let registry = ImageRuntimeRegistry::standard(standard).unwrap();
    for kind in [
        ImageAdapterKind::OpenaiImages,
        ImageAdapterKind::OpenrouterImages,
        ImageAdapterKind::GeminiImages,
        ImageAdapterKind::Comfyui,
    ] {
        assert_eq!(registry.adapter(kind).unwrap().kind(), kind);
    }

    let wrong = StandardImageRuntimeAdapters {
        openai_images: adapter(ImageAdapterKind::Comfyui),
        openrouter_images: adapter(ImageAdapterKind::OpenrouterImages),
        gemini_images: adapter(ImageAdapterKind::GeminiImages),
        comfyui: adapter(ImageAdapterKind::OpenaiImages),
    };
    assert!(matches!(
        wrong.into_checked(),
        Err(error) if error.code == RuntimeErrorCode::Incompatible
    ));
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
            body_timeout: Duration::from_secs(15),
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
        apply_endpoint_and_target(&registry, &endpoint, 1, 1);
        assert!(matches!(
            registry
                .refresh(endpoint.clone(), "target".into(), ConfigRevision::new(1, 1), 1, RefreshKind::Health, credential_digest(1))
                .await,
            Err(error) if error.code == code
        ));
        let snapshot = registry.snapshot(&endpoint.id, "target").unwrap();
        assert_eq!(snapshot.unavailable_reason, Some(code));
        assert_eq!(
            snapshot.expires_at - snapshot.retrieved_at,
            FAILURE_TTL.as_millis() as u64
        );
        let reused = registry
            .refresh(
                endpoint.clone(),
                "target".into(),
                ConfigRevision::new(1, 1),
                2,
                RefreshKind::Health,
                credential_digest(1),
            )
            .await
            .unwrap();
        assert_eq!(reused.request_id, 2);
    }
}

#[tokio::test(start_paused = true)]
async fn image_generation_runtime_enforces_total_deadline_around_connector() {
    let registry = ImageRuntimeRegistry::new(
        Arc::new(Clock(AtomicU64::new(0))),
        Arc::new(Dns("8.8.8.8".parse().unwrap())),
        Arc::new(PendingConnector),
        vec![Arc::new(Adapter {
            kind: ImageAdapterKind::OpenaiImages,
            calls: AtomicUsize::new(0),
        })],
    )
    .unwrap();
    let endpoint = endpoint();
    apply_endpoint_and_target(&registry, &endpoint, 1, 1);
    let refresh = tokio::spawn(async move {
        registry
            .refresh(
                endpoint,
                "target".into(),
                ConfigRevision::new(1, 1),
                1,
                RefreshKind::Health,
                credential_digest(7),
            )
            .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(HEADER_TIMEOUT + BODY_TIMEOUT).await;
    assert!(matches!(
        refresh.await.unwrap(),
        Err(error) if error.code == RuntimeErrorCode::HeaderTimeout
    ));
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
    apply_endpoint_and_target(&registry, &endpoint, 1, 1);
    let (a, b) = tokio::join!(
        registry.refresh(
            endpoint.clone(),
            "target".into(),
            ConfigRevision::new(1, 1),
            10,
            RefreshKind::Capabilities,
            credential_digest(2)
        ),
        registry.refresh(
            endpoint.clone(),
            "target".into(),
            ConfigRevision::new(1, 1),
            11,
            RefreshKind::Capabilities,
            credential_digest(2)
        )
    );
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    apply_endpoint_and_target(&registry, &endpoint, 2, 2);
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
    apply_endpoint_and_target(&registry, &endpoint, 1, 1);
    let snapshot = registry
        .refresh(
            endpoint.clone(),
            "target".into(),
            ConfigRevision::new(1, 1),
            1,
            RefreshKind::Capabilities,
            credential_digest(3),
        )
        .await
        .unwrap();
    assert_eq!(
        snapshot.connection.unwrap().connected_ip,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    );
    assert!(
        registry
            .revalidate_dispatch(&endpoint, "target", &credential_digest(3))
            .await
            .is_ok()
    );
    clock
        .0
        .store(CAPABILITY_DISPATCH_TTL.as_millis() as u64, Ordering::SeqCst);
    registry
        .refresh(
            endpoint.clone(),
            "target".into(),
            ConfigRevision::new(1, 1),
            2,
            RefreshKind::Health,
            credential_digest(3),
        )
        .await
        .unwrap();
    clock.0.store(
        CAPABILITY_DISPATCH_TTL.as_millis() as u64 + 1,
        Ordering::SeqCst,
    );
    assert!(
        registry
            .revalidate_dispatch(&endpoint, "target", &credential_digest(3))
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
    apply_endpoint_and_target(&registry, &endpoint, 1, 1);
    registry
        .refresh(
            endpoint.clone(),
            "target".into(),
            ConfigRevision::new(1, 1),
            1,
            RefreshKind::Capabilities,
            credential_digest(4),
        )
        .await
        .unwrap();
    clock.0.store(30_000, Ordering::SeqCst);
    registry
        .refresh(
            endpoint.clone(),
            "target".into(),
            ConfigRevision::new(1, 1),
            2,
            RefreshKind::Health,
            credential_digest(4),
        )
        .await
        .unwrap();
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
    clock.0.store(30_001, Ordering::SeqCst);
    registry
        .refresh(
            endpoint.clone(),
            "target".into(),
            ConfigRevision::new(1, 1),
            3,
            RefreshKind::Health,
            credential_digest(4),
        )
        .await
        .unwrap();
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 2);

    let mut failure = registry.snapshot(&endpoint.id, "target").unwrap();
    failure.state = ImageHealthState::AuthFailed;
    failure.retrieved_at = 0;
    failure.expires_at = FAILURE_TTL.as_millis() as u64;
    failure.unavailable_reason = Some(RuntimeErrorCode::Authentication);
    registry.inner.cache.lock().unwrap().insert(
        CacheKey {
            endpoint: endpoint.id.clone(),
            target: "target".into(),
        },
        failure,
    );
    clock.0.store(5_001, Ordering::SeqCst);
    let stale = registry.snapshot(&endpoint.id, "target").unwrap();
    assert_eq!(stale.state, ImageHealthState::Stale);
    assert_eq!(stale.provenance, SnapshotProvenance::Stale);
    assert!(!stale.dispatchable_at(clock.now_millis()));
    clock
        .0
        .store(DISPLAY_STALE_TTL.as_millis() as u64 + 1, Ordering::SeqCst);
    assert!(registry.snapshot(&endpoint.id, "target").is_none());
}

#[tokio::test]
async fn image_generation_capability_cache_is_independent_and_waiters_keep_request_ids() {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let adapter = Arc::new(Adapter {
        kind: ImageAdapterKind::OpenaiImages,
        calls: AtomicUsize::new(0),
    });
    let registry = registry(clock.clone(), adapter.clone());
    let endpoint = endpoint();
    apply_endpoint_and_target(&registry, &endpoint, 1, 1);
    let first = registry
        .refresh(
            endpoint.clone(),
            "target".into(),
            ConfigRevision::new(1, 1),
            41,
            RefreshKind::Capabilities,
            credential_digest(6),
        )
        .await
        .unwrap();
    assert_eq!(first.request_id, 41);
    clock.0.store(14 * 60 * 1_000, Ordering::SeqCst);
    let cached = registry
        .refresh(
            endpoint,
            "target".into(),
            ConfigRevision::new(1, 1),
            42,
            RefreshKind::Capabilities,
            credential_digest(6),
        )
        .await
        .unwrap();
    assert_eq!(cached.request_id, 42);
    assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn image_generation_runtime_binds_capability_to_endpoint_and_target() {
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let adapter = Arc::new(Adapter {
        kind: ImageAdapterKind::OpenaiImages,
        calls: AtomicUsize::new(0),
    });
    let registry = registry(clock, adapter);
    let endpoint = endpoint();
    apply_endpoint_and_target(&registry, &endpoint, 1, 1);
    registry.apply_test_target("other-target", &endpoint.id, 1, 1, "digest");
    let accepted = registry
        .refresh(
            endpoint.clone(),
            "target".into(),
            ConfigRevision::new(1, 1),
            1,
            RefreshKind::Capabilities,
            credential_digest(9),
        )
        .await
        .unwrap();
    assert_eq!(accepted.target_id, "target");
    assert!(matches!(
        registry
            .refresh(
                endpoint.clone(),
                "other-target".into(),
                ConfigRevision::new(1, 1),
                2,
                RefreshKind::Capabilities,
                credential_digest(9),
            )
            .await,
        Err(error) if error.code == RuntimeErrorCode::Incompatible
    ));
    assert!(registry.snapshot(&endpoint.id, "target").is_some());
    assert!(registry.snapshot(&endpoint.id, "other-target").is_some());
}

#[test]
fn image_generation_credential_identity_is_typed_and_redacted() {
    let digest = credential_digest(0x5a);
    let rendered = format!("{digest:?}");
    assert_eq!(rendered, "CredentialIdentityDigest(<redacted>)");
    assert!(!rendered.contains("5a"));
}

#[test]
fn image_generation_adapter_boundary_is_sealed_and_parse_only() {
    let source = include_str!("../image_generation_runtime.rs");
    let trait_body = source
        .split("pub trait ImageRuntimeAdapter")
        .nth(1)
        .and_then(|tail| tail.split("/// Exhaustive production registration").next())
        .unwrap();
    assert!(trait_body.contains("adapter_sealed::Sealed"));
    assert!(trait_body.contains("fn request("));
    assert!(trait_body.contains("fn parse("));
    for forbidden in ["Future<", ".send()", "TcpStream", "lookup_host"] {
        assert!(
            !trait_body.contains(forbidden),
            "adapter authority contains {forbidden}"
        );
    }
}

#[test]
fn image_generation_runtime_revalidates_every_redirect_hop() {
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
        ImageRuntimeRegistry::validate_connection_hops(
            &proof,
            AddressClass::PublicRemote,
            &["8.8.8.8".parse().unwrap()],
        ),
        Err(error) if error.code == RuntimeErrorCode::DnsDenied
    ));
    let mut too_many = proof.clone();
    too_many.hops = vec![too_many.hops[0].clone(); REDIRECT_LIMIT + 2];
    assert!(matches!(
        ImageRuntimeRegistry::validate_connection_hops(
            &too_many,
            AddressClass::PublicRemote,
            &["8.8.8.8".parse().unwrap()],
        ),
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
    apply_endpoint_and_target(&rebinding, &endpoint, 1, 1);
    rebinding
        .refresh(
            endpoint.clone(),
            "target".into(),
            ConfigRevision::new(1, 1),
            1,
            RefreshKind::Capabilities,
            credential_digest(5),
        )
        .await
        .unwrap();
    assert!(matches!(
        rebinding
            .revalidate_dispatch(&endpoint, "target", &credential_digest(5))
            .await,
        Err(error) if error.code == RuntimeErrorCode::DnsDenied
    ));
    assert!(rebinding.snapshot(&endpoint.id, "target").is_none());

    let mismatch = ImageRuntimeRegistry::new(
        Arc::new(Clock(AtomicU64::new(0))),
        Arc::new(Dns("8.8.8.8".parse().unwrap())),
        Arc::new(MismatchedConnector),
        vec![adapter],
    )
    .unwrap();
    apply_endpoint_and_target(&mismatch, &endpoint, 1, 1);
    assert!(matches!(
        mismatch
            .refresh(endpoint, "target".into(), ConfigRevision::new(1, 1), 1, RefreshKind::Health, credential_digest(5))
            .await,
        Err(error) if error.code == RuntimeErrorCode::DnsDenied
    ));
}

#[tokio::test]
async fn image_generation_runtime_rejects_mixed_dns_location_classes() {
    let adapter = Arc::new(Adapter {
        kind: ImageAdapterKind::OpenaiImages,
        calls: AtomicUsize::new(0),
    });
    let registry = ImageRuntimeRegistry::new(
        Arc::new(Clock(AtomicU64::new(0))),
        Arc::new(SequenceDns(Mutex::new(vec![vec![
            "8.8.8.8".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
        ]]))),
        Arc::new(Connector),
        vec![adapter],
    )
    .unwrap();
    let endpoint = endpoint();
    apply_endpoint_and_target(&registry, &endpoint, 1, 1);
    assert!(matches!(
        registry
            .refresh(
                endpoint,
                "target".into(),
                ConfigRevision::new(1, 1),
                1,
                RefreshKind::Health,
                credential_digest(8),
            )
            .await,
        Err(error) if error.code == RuntimeErrorCode::DnsDenied
    ));
}

#[tokio::test]
async fn image_generation_pinned_connector_preserves_authority_and_revalidates_redirects() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for redirect in [true, false] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = vec![0; 4096];
            let read = socket.read(&mut bytes).await.unwrap();
            requests.push(String::from_utf8_lossy(&bytes[..read]).into_owned());
            let response = if redirect {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://redirect.test:{port}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            };
            socket.write_all(response.as_bytes()).await.unwrap();
        }
        requests
    });
    let dns: Arc<dyn DnsResolver> = Arc::new(Dns(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let connector = ReqwestPinnedConnector::new(dns);
    let origin = reqwest::Url::parse(&format!("http://origin.test:{port}/health")).unwrap();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_static("Bearer fixture-super-secret"),
    );
    let request = ReadOnlyProbeRequest::new(origin, headers);
    assert!(!format!("{request:?}").contains("fixture-super-secret"));
    let proof = connector
        .execute(
            request,
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            AddressClass::Loopback,
            ProbeLimits::health(),
        )
        .await
        .unwrap();
    let requests = server.await.unwrap();
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains(&format!("host: origin.test:{port}"))
    );
    assert!(requests[0].contains("Bearer fixture-super-secret"));
    assert!(
        requests[1]
            .to_ascii_lowercase()
            .contains(&format!("host: redirect.test:{port}"))
    );
    assert!(!requests[1].contains("fixture-super-secret"));
    assert_eq!(proof.connection.hops.len(), 2);
    assert_eq!(
        proof.connection.hops[0].connected_ip,
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
    assert_eq!(
        proof.connection.hops[1].connected_ip,
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
}

#[tokio::test]
async fn image_generation_pinned_connector_enforces_body_limit_while_reading() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0; 1024];
        let _ = socket.read(&mut request).await.unwrap();
        let body = vec![b'x'; HEALTH_BODY_LIMIT + 1];
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(head.as_bytes()).await.unwrap();
        let _ = socket.write_all(&body).await;
    });
    let dns: Arc<dyn DnsResolver> = Arc::new(Dns(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let connector = ReqwestPinnedConnector::new(dns);
    let origin = reqwest::Url::parse(&format!("http://body.test:{port}/health")).unwrap();
    assert!(matches!(
        connector
            .execute(
                ReadOnlyProbeRequest::new(origin, reqwest::header::HeaderMap::new()),
                &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
                AddressClass::Loopback,
                ProbeLimits::health(),
            )
            .await,
        Err(error) if error.code == RuntimeErrorCode::BodyLimit
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn image_generation_credential_rotation_prevents_old_flight_commit() {
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let releases = vec![Arc::new(Notify::new()), Arc::new(Notify::new())];
    let connector = Arc::new(ControlledConnector {
        calls: AtomicUsize::new(0),
        started: started_tx,
        releases: releases.clone(),
    });
    let adapter = Arc::new(Adapter {
        kind: ImageAdapterKind::OpenaiImages,
        calls: AtomicUsize::new(0),
    });
    let registry = ImageRuntimeRegistry::new(
        Arc::new(Clock(AtomicU64::new(0))),
        Arc::new(Dns("8.8.8.8".parse().unwrap())),
        connector,
        vec![adapter],
    )
    .unwrap();
    let endpoint = endpoint();
    apply_endpoint_and_target(&registry, &endpoint, 1, 1);
    let old_registry = registry.clone();
    let old_endpoint = endpoint.clone();
    let old = tokio::spawn(async move {
        old_registry
            .refresh(
                old_endpoint,
                "target".into(),
                ConfigRevision::new(1, 1),
                1,
                RefreshKind::Capabilities,
                credential_digest(10),
            )
            .await
    });
    assert_eq!(started_rx.recv().await.unwrap(), 0);
    let new_registry = registry.clone();
    let new_endpoint = endpoint.clone();
    let new = tokio::spawn(async move {
        new_registry
            .refresh(
                new_endpoint,
                "target".into(),
                ConfigRevision::new(1, 1),
                2,
                RefreshKind::Capabilities,
                credential_digest(11),
            )
            .await
    });
    assert_eq!(started_rx.recv().await.unwrap(), 1);
    releases[0].notify_one();
    assert!(matches!(old.await.unwrap(), Err(error) if error.code == RuntimeErrorCode::Obsolete));
    releases[1].notify_one();
    let current = new.await.unwrap().unwrap();
    assert_eq!(current.request_id, 2);
    assert_eq!(
        current.credential_identity_digest,
        Some(credential_digest(11))
    );
}

#[tokio::test]
async fn image_generation_refresh_waiter_drop_cancels_only_the_last_waiter() {
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(Notify::new());
    let connector = Arc::new(ControlledConnector {
        calls: AtomicUsize::new(0),
        started: started_tx,
        releases: vec![release.clone()],
    });
    let adapter = Arc::new(Adapter {
        kind: ImageAdapterKind::OpenaiImages,
        calls: AtomicUsize::new(0),
    });
    let registry = ImageRuntimeRegistry::new(
        Arc::new(Clock(AtomicU64::new(0))),
        Arc::new(Dns("8.8.8.8".parse().unwrap())),
        connector,
        vec![adapter],
    )
    .unwrap();
    let endpoint = endpoint();
    apply_endpoint_and_target(&registry, &endpoint, 1, 1);
    let first_registry = registry.clone();
    let first_endpoint = endpoint.clone();
    let first = tokio::spawn(async move {
        first_registry
            .refresh(
                first_endpoint,
                "target".into(),
                ConfigRevision::new(1, 1),
                20,
                RefreshKind::Capabilities,
                credential_digest(12),
            )
            .await
    });
    assert_eq!(started_rx.recv().await.unwrap(), 0);
    let second_registry = registry.clone();
    let second_endpoint = endpoint.clone();
    let second = tokio::spawn(async move {
        second_registry
            .refresh(
                second_endpoint,
                "target".into(),
                ConfigRevision::new(1, 1),
                21,
                RefreshKind::Capabilities,
                credential_digest(12),
            )
            .await
    });
    for _ in 0..16 {
        let has_two_waiters = registry
            .inner
            .inflight
            .lock()
            .unwrap()
            .values()
            .next()
            .is_some_and(|flight| flight.waiters.load(Ordering::Acquire) == 2);
        if has_two_waiters {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        registry
            .inner
            .inflight
            .lock()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .waiters
            .load(Ordering::Acquire),
        2
    );
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    release.notify_one();
    assert_eq!(second.await.unwrap().unwrap().request_id, 21);

    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let connector = Arc::new(ControlledConnector {
        calls: AtomicUsize::new(0),
        started: started_tx,
        releases: vec![Arc::new(Notify::new())],
    });
    let registry = ImageRuntimeRegistry::new(
        Arc::new(Clock(AtomicU64::new(0))),
        Arc::new(Dns("8.8.8.8".parse().unwrap())),
        connector,
        vec![Arc::new(Adapter {
            kind: ImageAdapterKind::OpenaiImages,
            calls: AtomicUsize::new(0),
        })],
    )
    .unwrap();
    apply_endpoint_and_target(&registry, &endpoint, 1, 1);
    let cancelled_registry = registry.clone();
    let cancelled_endpoint = endpoint.clone();
    let cancelled = tokio::spawn(async move {
        cancelled_registry
            .refresh(
                cancelled_endpoint,
                "target".into(),
                ConfigRevision::new(1, 1),
                30,
                RefreshKind::Capabilities,
                credential_digest(13),
            )
            .await
    });
    assert_eq!(started_rx.recv().await.unwrap(), 0);
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    for _ in 0..16 {
        if registry.inner.inflight.lock().unwrap().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(registry.snapshot(&endpoint.id, "target").is_none());
    assert!(registry.inner.inflight.lock().unwrap().is_empty());
}
