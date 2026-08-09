use cockpit_proto::send_user_message_v2::CanonicalSendUserMessageV2;
use serde_json::Value;

fn hex(raw: &str) -> Vec<u8> {
    assert_eq!(raw.len() % 2, 0);
    raw.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

#[test]
fn send_user_message_v2_shared_bytes_and_digests() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/send-user-message-v2-canonical-vectors.json"
    ))
    .unwrap();
    let vector = &fixture["vectors"][0];
    let bytes = hex(vector["fcm2_hex"].as_str().unwrap());
    let decoded = CanonicalSendUserMessageV2::decode(&bytes).unwrap();
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert_eq!(
        decoded.message_request_digest().unwrap().as_slice(),
        hex(vector["message_request_digest_hex"].as_str().unwrap())
    );
    assert_eq!(
        decoded.attachment_set_digest().unwrap().as_slice(),
        hex(vector["attachment_set_digest_hex"].as_str().unwrap())
    );
}

#[test]
fn send_user_message_v2_shared_malformed_bytes_reject() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/send-user-message-v2-canonical-vectors.json"
    ))
    .unwrap();
    for case in fixture["malformed_fcm2"].as_array().unwrap() {
        let bytes = hex(case["fcm2_hex"].as_str().unwrap());
        assert!(
            CanonicalSendUserMessageV2::decode(&bytes).is_err(),
            "accepted {}",
            case["name"]
        );
    }
}
