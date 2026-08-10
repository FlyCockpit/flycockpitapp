use cockpit_proto::remote_signaling_attempt_store::{
    RemoteSignalingCommitAckV1, RemoteSignalingEventRequestV1, SignalingCodecError,
    validate_fallback_noise, validate_fallback_pair, validate_fcab, validate_ready,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    transitions: Vec<serde_json::Value>,
    payloads: Payloads,
    requests: Vec<Request>,
    malformed_requests: Vec<Malformed>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payloads {
    fcab_hex: String,
    fallback_pair_hex: String,
    fallback_noise_hex: String,
    ready_hex: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    request_hex: String,
    event_digest_hex: String,
    ack_hex: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Malformed {
    request_hex: String,
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
fn remote_signaling_attempt_store_cross_language_fixtures() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote/signaling-attempt-store-v1.json"
    ))
    .expect("fixture parses");
    assert!(
        fixture
            .transitions
            .iter()
            .any(|row| row["transport"] == "common")
    );
    assert!(
        fixture
            .transitions
            .iter()
            .any(|row| row["transport"] == "webrtc")
    );
    assert!(
        fixture
            .transitions
            .iter()
            .any(|row| row["transport"] == "websocket_data")
    );
    assert!(fixture.transitions.iter().any(|row| {
        matches!(
            row["event"].as_str(),
            Some("attempt_rejected" | "attempt_cancelled" | "attempt_superseded")
        )
    }));
    assert!(!fixture.requests.is_empty());
    assert!(!fixture.malformed_requests.is_empty());
    assert_eq!(
        validate_fcab(&decode_hex(&fixture.payloads.fcab_hex)).unwrap(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    );
    validate_fallback_pair(&decode_hex(&fixture.payloads.fallback_pair_hex)).unwrap();
    validate_fallback_noise(&decode_hex(&fixture.payloads.fallback_noise_hex)).unwrap();
    validate_ready(&decode_hex(&fixture.payloads.ready_hex)).unwrap();
    for vector in fixture.requests {
        let bytes = decode_hex(&vector.request_hex);
        let request = RemoteSignalingEventRequestV1::decode(&bytes).unwrap();
        assert_eq!(request.encode().unwrap(), bytes);
        assert_eq!(
            encode_hex(&RemoteSignalingEventRequestV1::digest(&bytes).unwrap()),
            vector.event_digest_hex
        );
        let ack_bytes = decode_hex(&vector.ack_hex);
        let ack = RemoteSignalingCommitAckV1::decode(&ack_bytes).unwrap();
        assert_eq!(ack.encode().unwrap().as_slice(), ack_bytes);
    }
    for vector in fixture.malformed_requests {
        let error = RemoteSignalingEventRequestV1::decode(&decode_hex(&vector.request_hex))
            .expect_err("malformed vector must fail");
        match vector.rejection.as_str() {
            "length" => assert_eq!(error, SignalingCodecError::Length),
            "zero_id" => assert_eq!(error, SignalingCodecError::ZeroId),
            "preamble" => assert_eq!(error, SignalingCodecError::Preamble),
            "discriminant" => assert_eq!(error, SignalingCodecError::Discriminant),
            "combination" => assert_eq!(error, SignalingCodecError::Combination),
            other => panic!("unknown rejection class {other}"),
        }
    }
}
