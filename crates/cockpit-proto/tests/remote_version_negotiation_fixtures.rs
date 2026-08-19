//! Cross-language fixture tests for remote protocol version negotiation.
//!
//! Consumes `packages/cockpit-protocol/fixtures/remote/version-negotiation-v1.json`
//! and asserts nonzero positive and malformed cases before comparison.

use cockpit_proto::remote_version::{
    self, RemoteNegotiationTranscriptV1, RemoteVersionError, SelectionInputs, V1_TUPLE_ID,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fixture {
    #[allow(dead_code)]
    version: u8,
    // NOTE: the application version (`protocolVersion` / `v1Application`) is
    // deliberately absent from this fixture. It is not part of the
    // cross-language transcript byte corpus, and its single authority is the
    // PROTOCOL_VERSION constant. Embedding it here would be a second
    // hand-maintained authority that a constant bump would silently desync
    // (guarded by `remote_version_no_hardcoded_application_version`).
    registry: RegistryFixture,
    selection_cases: Vec<SelectionCase>,
    upgrade_cases: Vec<UpgradeCase>,
    transcript_vectors: Vec<TranscriptVector>,
    malformed_vectors: Vec<MalformedVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryFixture {
    v1_tuple_id: u16,
    v1_signaling: u16,
    v1_authorization: u16,
    v1_transport: u16,
    v1_security_rank: u16,
    v1_feature_count: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SelectionCase {
    name: String,
    client: Vec<u16>,
    daemon: Vec<u16>,
    server_allowed: Vec<u16>,
    revoked: Vec<u16>,
    expected_selected: Option<u16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpgradeCase {
    name: String,
    client: Vec<u16>,
    daemon: Vec<u16>,
    server_allowed: Vec<u16>,
    revoked: Vec<u16>,
    expected_upgrade_side: String,
    expected_recommended: Option<u16>,
    expected_client_supported: Vec<u16>,
    expected_daemon_supported: Vec<u16>,
    expected_server_allowed: Vec<u16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TranscriptVector {
    name: String,
    transcript_hex: String,
    expected_digest_hex: String,
    expected_len: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MalformedVector {
    name: String,
    transcript_hex: String,
    rejection: String,
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn remote_version_negotiation_cross_language_fixtures() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote/version-negotiation-v1.json"
    ))
    .expect("fixture parses");

    // Nonzero positive assertions.
    assert!(!fixture.selection_cases.is_empty());
    assert!(!fixture.upgrade_cases.is_empty());
    assert!(!fixture.transcript_vectors.is_empty());
    assert!(!fixture.malformed_vectors.is_empty());

    // Registry: V1 tuple.
    let reg = &fixture.registry;
    assert_eq!(reg.v1_tuple_id, V1_TUPLE_ID);
    assert_eq!(reg.v1_signaling, 1);
    assert_eq!(reg.v1_authorization, 1);
    assert_eq!(reg.v1_transport, 1);
    assert_eq!(reg.v1_security_rank, 100);
    assert_eq!(reg.v1_feature_count, 0);
    // The application version is intentionally not in the fixture; its sole
    // authority is PROTOCOL_VERSION, asserted against the live registry in the
    // `remote_version` unit tests.

    // Selection cases.
    for case in &fixture.selection_cases {
        let inputs = SelectionInputs {
            client: &case.client,
            daemon: &case.daemon,
            server_allowed: &case.server_allowed,
            revoked: &case.revoked,
        };
        let result = remote_version::select(&inputs).unwrap();
        assert_eq!(
            result.map(|s| s.tuple_id),
            case.expected_selected,
            "selection case: {}",
            case.name
        );
    }

    // Upgrade cases.
    for case in &fixture.upgrade_cases {
        let inputs = SelectionInputs {
            client: &case.client,
            daemon: &case.daemon,
            server_allowed: &case.server_allowed,
            revoked: &case.revoked,
        };
        let err = remote_version::upgrade_required(&inputs).unwrap();
        assert_eq!(
            err.upgrade_side.as_str(),
            case.expected_upgrade_side,
            "upgrade case: {}",
            case.name
        );
        assert_eq!(
            err.recommended_tuple_id, case.expected_recommended,
            "upgrade case recommended: {}",
            case.name
        );
        assert_eq!(
            err.client_supported, case.expected_client_supported,
            "upgrade case client_supported: {}",
            case.name
        );
        assert_eq!(
            err.daemon_supported, case.expected_daemon_supported,
            "upgrade case daemon_supported: {}",
            case.name
        );
        assert_eq!(
            err.server_allowed, case.expected_server_allowed,
            "upgrade case server_allowed: {}",
            case.name
        );
    }

    // Transcript vectors: byte identity and digest.
    for vector in &fixture.transcript_vectors {
        let bytes = decode_hex(&vector.transcript_hex);
        assert_eq!(
            bytes.len(),
            vector.expected_len,
            "transcript vector length: {}",
            vector.name
        );
        let decoded = RemoteNegotiationTranscriptV1::decode(&bytes)
            .unwrap_or_else(|e| panic!("transcript vector decode failed {}: {e:?}", vector.name));
        let reencoded = decoded.encode().unwrap();
        assert_eq!(
            encode_hex(&reencoded),
            vector.transcript_hex,
            "transcript vector round-trip: {}",
            vector.name
        );
        let digest = remote_version::transcript_digest(&bytes).unwrap();
        assert_eq!(
            encode_hex(&digest),
            vector.expected_digest_hex,
            "transcript vector digest: {}",
            vector.name
        );
    }

    // Malformed vectors: must reject.
    for vector in &fixture.malformed_vectors {
        let bytes = decode_hex(&vector.transcript_hex);
        let error =
            RemoteNegotiationTranscriptV1::decode(&bytes).expect_err("malformed vector must fail");
        let expected = match vector.rejection.as_str() {
            "length" => RemoteVersionError::Length,
            "preamble" => RemoteVersionError::Preamble,
            "discriminant" => RemoteVersionError::Discriminant,
            "combination" => RemoteVersionError::Combination,
            "invalid" => RemoteVersionError::Invalid,
            other => panic!("unknown rejection class {other}"),
        };
        assert_eq!(
            error, expected,
            "malformed vector {}: expected {:?}",
            vector.name, vector.rejection
        );
    }

    // Registry digest: computed at test time from the live registry, never
    // checked in. We verify it is a valid 32-byte SHA-256 and deterministic.
    let live_digest = remote_version::enabled_registry_digest();
    assert_eq!(live_digest.len(), 32);
    assert_eq!(live_digest, remote_version::enabled_registry_digest());

    // Wire magic: FCRN must be present in the global registry.
    let registry_json = include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote-wire-magic-registry-v1.json"
    );
    let registry = cockpit_proto::remote_wire_magic_registry::parse_registry(registry_json)
        .expect("wire magic registry parses");
    // FCRN maps to the real transcript codec, not the phantom relay-nonce type.
    cockpit_proto::remote_wire_magic_registry::assert_registered(
        &registry,
        &[("FCRN", "RemoteNegotiationTranscriptV1")],
    )
    .unwrap();
    // The phantom `RemoteRelayNonceV1` type (which has no codec anywhere) must
    // appear nowhere in the shared registry.
    assert!(
        !registry_json.contains("RemoteRelayNonceV1"),
        "phantom RemoteRelayNonceV1 must not be registered"
    );
}
