//! Health/capability probe tests for the ComfyUI runtime adapter.

use super::*;
use crate::image_generation_runtime::{
    AddressClass, BoundProbeResponse, ConnectionHop, ConnectionProof, CredentialIdentityDigest,
    ImageHealthState, ImageRuntimeAdapter, ProbeLimits, ProbeRequest, RefreshKind,
    RuntimeErrorCode,
};
use cockpit_config::config::image_generation::{
    ImageAdapterKind, ImageEndpoint, ImageLocationClass,
};
use std::net::{IpAddr, Ipv4Addr};

fn endpoint() -> ImageEndpoint {
    ImageEndpoint {
        id: "comfyui-endpoint".into(),
        adapter: ImageAdapterKind::Comfyui,
        origin: "http://127.0.0.1:8188".into(),
        path_prefix: None,
        credential_ref: None,
        headers: vec![],
        allow_insecure_transport: true,
        location: ImageLocationClass::Local,
        enabled: true,
        route_profile_version: 1,
        exclusive_server: false,
    }
}

fn probe(kind: RefreshKind) -> ProbeRequest {
    ProbeRequest {
        endpoint: endpoint(),
        target_id: "comfyui-target".into(),
        config_generation: 1,
        refresh_epoch: 1,
        request_id: 1,
        kind,
        credential_identity_digest: CredentialIdentityDigest::from_sha256([0u8; 32]),
        resolved_headers: reqwest::header::HeaderMap::new(),
        limits: ProbeLimits::health(),
    }
}

fn response(status: reqwest::StatusCode) -> BoundProbeResponse {
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    BoundProbeResponse {
        status,
        body: Vec::new(),
        connection: ConnectionProof {
            authority: "127.0.0.1:8188".into(),
            connected_ip: ip,
            location: AddressClass::Loopback,
            established_at: 0,
            hops: vec![ConnectionHop {
                authority: "127.0.0.1:8188".into(),
                hostname: "127.0.0.1".into(),
                connected_ip: ip,
                location: AddressClass::Loopback,
            }],
        },
    }
}

#[test]
fn comfyui_runtime_adapter_kind_is_comfyui() {
    let adapter = standard_adapter();
    assert_eq!(adapter.kind(), ImageAdapterKind::Comfyui);
}

#[test]
fn comfyui_runtime_adapter_request_uses_queue_route() {
    let adapter = ComfyuiRuntimeAdapter::new();
    let request = adapter.request(&probe(RefreshKind::Health)).unwrap();
    assert_eq!(request.url.as_str(), "http://127.0.0.1:8188/queue");
}

#[test]
fn comfyui_runtime_adapter_parse_success_is_healthy() {
    let adapter = ComfyuiRuntimeAdapter::new();
    let result = adapter
        .parse(
            &probe(RefreshKind::Health),
            &response(reqwest::StatusCode::OK),
        )
        .unwrap();
    assert_eq!(result.state, ImageHealthState::Healthy);
    assert!(result.capability.is_none());
}

#[test]
fn comfyui_runtime_adapter_parse_capability_probe_returns_snapshot() {
    let adapter = ComfyuiRuntimeAdapter::new();
    let result = adapter
        .parse(
            &probe(RefreshKind::Capabilities),
            &response(reqwest::StatusCode::OK),
        )
        .unwrap();
    let capability = result
        .capability
        .expect("capability probe returns snapshot");
    assert_eq!(capability.target_id, "comfyui-target");
}

#[test]
fn comfyui_runtime_adapter_parse_maps_status_codes() {
    let adapter = ComfyuiRuntimeAdapter::new();
    for (status, code) in [
        (
            reqwest::StatusCode::UNAUTHORIZED,
            RuntimeErrorCode::Authentication,
        ),
        (
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            RuntimeErrorCode::Busy,
        ),
        (
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            RuntimeErrorCode::MalformedResponse,
        ),
    ] {
        let err = adapter
            .parse(&probe(RefreshKind::Health), &response(status))
            .unwrap_err();
        assert_eq!(err.code, code, "status {status} maps to {code:?}");
    }
}
