use cockpit_proto::send_user_message_v2::{
    CanonicalSendUserMessageV2, MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES,
    MessageAttachmentIdentity, MessageAttachmentKind, MessageTagExpansion, SendUserMessageV2,
    validate_fcm2_length,
};
use serde_json::Value;
use uuid::Uuid;

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
fn send_user_message_v2_exact_maximum_and_preallocation_guard() {
    let four_byte_scalars = "😀".repeat(262_144);
    let tags = (0..64)
        .map(|_| MessageTagExpansion {
            tool: "t".repeat(128),
            path: "p".repeat(4_096),
            detail: "d".repeat(4_096),
            ok: true,
        })
        .collect();
    let attachments = (0..16)
        .map(|ordinal| MessageAttachmentIdentity {
            attachment_id: Uuid::from_u128(0x100 + ordinal),
            attachment_version: u64::MAX,
            checksum: [ordinal as u8; 32],
            kind: match ordinal % 3 {
                0 => MessageAttachmentKind::Image,
                1 => MessageAttachmentKind::Audio,
                _ => MessageAttachmentKind::Video,
            },
        })
        .collect();
    let value = CanonicalSendUserMessageV2 {
        session_id: Uuid::from_u128(1),
        canonical_project_digest: [1; 32],
        model_config_generation: u64::MAX,
        canonical_model_digest: [2; 32],
        request: SendUserMessageV2 {
            client_submission_id: Uuid::from_u128(2),
            text: four_byte_scalars.clone(),
            display_text: Some(four_byte_scalars),
            tag_expansions: tags,
            forced_skill: Some("s".repeat(128)),
            attachments,
        },
    };
    assert_eq!(
        value.encode().unwrap().len(),
        MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES
    );
    assert!(validate_fcm2_length(MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES + 1).is_err());
}

#[test]
fn send_user_message_v2_shared_bytes_and_digests() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/send-user-message-v2-canonical-vectors.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
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
