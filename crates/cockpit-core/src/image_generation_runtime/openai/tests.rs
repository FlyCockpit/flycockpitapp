//! Health/capability probe tests for the OpenAI Images runtime adapter.

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
        id: "openai-endpoint".into(),
        adapter: ImageAdapterKind::OpenaiImages,
        origin: "https://api.openai.com".into(),
        path_prefix: None,
        credential_ref: Some("openai-api-key".into()),
        headers: vec![],
        allow_insecure_transport: false,
        location: ImageLocationClass::PublicCloud,
        enabled: true,
        route_profile_version: 1,
        exclusive_server: false,
    }
}

fn probe(kind: RefreshKind) -> ProbeRequest {
    ProbeRequest {
        endpoint: endpoint(),
        target_id: "openai-target".into(),
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
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    BoundProbeResponse {
        status,
        body: Vec::new(),
        connection: ConnectionProof {
            authority: "api.openai.com:443".into(),
            connected_ip: ip,
            location: AddressClass::PublicRemote,
            established_at: 0,
            hops: vec![ConnectionHop {
                authority: "api.openai.com:443".into(),
                hostname: "api.openai.com".into(),
                connected_ip: ip,
                location: AddressClass::PublicRemote,
            }],
        },
    }
}

#[test]
fn openai_runtime_adapter_kind_is_openai_images() {
    let adapter = standard_adapter();
    assert_eq!(adapter.kind(), ImageAdapterKind::OpenaiImages);
}

#[test]
fn openai_runtime_adapter_request_uses_images_route() {
    let adapter = OpenaiImagesRuntimeAdapter::new();
    let request = adapter.request(&probe(RefreshKind::Health)).unwrap();
    assert_eq!(
        request.url.as_str(),
        "https://api.openai.com/v1/images/generations"
    );
}

#[test]
fn openai_runtime_adapter_request_stays_within_configured_origin() {
    let adapter = OpenaiImagesRuntimeAdapter::new();
    let request = adapter.request(&probe(RefreshKind::Health)).unwrap();
    assert_eq!(
        request.url.origin(),
        endpoint().origin.parse::<reqwest::Url>().unwrap().origin()
    );
}

#[test]
fn openai_runtime_adapter_parse_success_is_healthy() {
    let adapter = OpenaiImagesRuntimeAdapter::new();
    let result = adapter
        .parse(
            &probe(RefreshKind::Health),
            &response(reqwest::StatusCode::OK),
        )
        .unwrap();
    assert_eq!(result.state, ImageHealthState::Healthy);
    // Health probes carry no capability snapshot.
    assert!(result.capability.is_none());
}

#[test]
fn openai_runtime_adapter_parse_capability_probe_returns_snapshot() {
    let adapter = OpenaiImagesRuntimeAdapter::new();
    let result = adapter
        .parse(
            &probe(RefreshKind::Capabilities),
            &response(reqwest::StatusCode::OK),
        )
        .unwrap();
    assert_eq!(result.state, ImageHealthState::Healthy);
    let capability = result
        .capability
        .expect("capability probe returns snapshot");
    assert_eq!(capability.target_id, "openai-target");
}

#[test]
fn openai_runtime_adapter_parse_maps_status_codes() {
    let adapter = OpenaiImagesRuntimeAdapter::new();
    for (status, code) in [
        (
            reqwest::StatusCode::UNAUTHORIZED,
            RuntimeErrorCode::Authentication,
        ),
        (
            reqwest::StatusCode::FORBIDDEN,
            RuntimeErrorCode::Authentication,
        ),
        (
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            RuntimeErrorCode::Busy,
        ),
        (
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            RuntimeErrorCode::MalformedResponse,
        ),
    ] {
        let err = adapter
            .parse(&probe(RefreshKind::Health), &response(status))
            .unwrap_err();
        assert_eq!(err.code, code, "status {status} maps to {code:?}");
    }
}
