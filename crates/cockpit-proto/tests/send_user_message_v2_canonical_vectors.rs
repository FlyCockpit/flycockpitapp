use cockpit_proto::send_user_message_v2::{
    AuthenticatedRemoteOperationEnvelopeV2, CanonicalSendUserMessageV2,
    LocalOwnerDirectSendUserMessageV2, MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES,
    MAX_CURRENT_FCM2_ENCODING_BYTES, MAX_MESSAGE_TEXT_BYTES, MAX_MESSAGE_TEXT_SCALARS,
    MessageAttachmentIdentity, MessageAttachmentKind, MessageIngressProvenance,
    MessageTagExpansion, SendUserMessageV2, has_message_text, validate_fcm2_length,
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
fn send_user_message_v2_limits_match_shared_fixture() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/send-user-message-v2-canonical-vectors.json"
    ))
    .unwrap();
    let limits = fixture["limits"].as_object().unwrap();
    assert_eq!(
        limits["fcm2_max_bytes"].as_u64(),
        Some(MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES as u64)
    );
    assert_eq!(
        limits["fcm2_max_current_encoding_bytes"].as_u64(),
        Some(MAX_CURRENT_FCM2_ENCODING_BYTES as u64)
    );
    assert_eq!(
        limits["text_max_bytes"].as_u64(),
        Some(MAX_MESSAGE_TEXT_BYTES as u64)
    );
    assert_eq!(
        limits["text_max_scalars"].as_u64(),
        Some(MAX_MESSAGE_TEXT_SCALARS as u64)
    );
}

#[test]
fn send_user_message_v2_local_envelope_keeps_three_identities_distinct() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/send-user-message-v2-canonical-vectors.json"
    ))
    .unwrap();
    let mut command = CanonicalSendUserMessageV2::decode(&hex(fixture["vectors"][0]["fcm2_hex"]
        .as_str()
        .unwrap()))
    .unwrap()
    .request;
    let request_id = Uuid::parse_str("018f47a2-7b3c-7def-8123-000000000001").unwrap();
    let operation_id = Uuid::parse_str("018f47a2-7b3c-7def-8123-000000000002").unwrap();
    // Canonical FCM2 vectors may use placeholder v4 UUIDs; ingress identities
    // are RFC UUIDv7 and must stay pairwise distinct from request/operation.
    command.client_submission_id = Uuid::parse_str("018f47a2-7b3c-7def-8123-000000000003").unwrap();
    let validated = LocalOwnerDirectSendUserMessageV2 {
        operation_id,
        session_locator: "opaque-session".into(),
        expected_model_state_generation: None,
        expected_model: None,
        run_invocation_options: None,
        request: command,
    }
    .into_validated(request_id)
    .unwrap();
    assert_eq!(validated.request_id, request_id);
    assert_eq!(validated.operation_id, operation_id);
    assert_ne!(
        validated.operation_id,
        validated.command.client_submission_id
    );
    let error = LocalOwnerDirectSendUserMessageV2 {
        operation_id: request_id,
        session_locator: "opaque-session".into(),
        expected_model_state_generation: None,
        expected_model: None,
        run_invocation_options: None,
        request: validated.command.clone(),
    }
    .into_validated(request_id)
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "request, operation, and submission identities must be pairwise distinct"
    );
    let mut request_collision = validated.command.clone();
    request_collision.client_submission_id = request_id;
    assert!(
        LocalOwnerDirectSendUserMessageV2 {
            operation_id,
            session_locator: "opaque".into(),
            expected_model_state_generation: None,
            expected_model: None,
            run_invocation_options: None,
            request: request_collision
        }
        .into_validated(request_id)
        .is_err()
    );
    let mut operation_collision = validated.command.clone();
    operation_collision.client_submission_id = operation_id;
    assert!(
        LocalOwnerDirectSendUserMessageV2 {
            operation_id,
            session_locator: "opaque".into(),
            expected_model_state_generation: None,
            expected_model: None,
            run_invocation_options: None,
            request: operation_collision
        }
        .into_validated(request_id)
        .is_err()
    );
    let non_rfc_v7 = Uuid::parse_str("018f47a2-7b3c-7def-0123-000000000003").unwrap();
    assert_eq!(
        LocalOwnerDirectSendUserMessageV2 {
            operation_id,
            session_locator: "opaque".into(),
            expected_model_state_generation: None,
            expected_model: None,
            run_invocation_options: None,
            request: validated.command.clone()
        }
        .into_validated(non_rfc_v7)
        .unwrap_err()
        .to_string(),
        "request_id must be RFC UUIDv7"
    );
    let remote = AuthenticatedRemoteOperationEnvelopeV2 {
        session_locator: "opaque".into(),
        expected_model_state_generation: None,
        expected_model: None,
        request: validated.command,
    }
    .into_validated(request_id, operation_id, [42; 16], 9)
    .unwrap();
    assert_eq!(
        remote.provenance,
        MessageIngressProvenance::AuthenticatedRemote {
            actor_id: [42; 16],
            actor_generation: 9
        }
    );
}

fn compact_bytes(vector: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(segments) = vector["segments"].as_array() {
        for segment in segments {
            let bytes = hex(segment["hex"].as_str().unwrap());
            for _ in 0..segment["repeat"].as_u64().unwrap() {
                out.extend_from_slice(&bytes);
            }
        }
    } else {
        out.extend_from_slice(&hex(vector["prefix_hex"].as_str().unwrap()));
        for index in 1..=vector["generated_attachments"].as_u64().unwrap() {
            out.extend_from_slice(
                Uuid::parse_str(&format!("00000000-0000-4000-8000-{index:012x}"))
                    .unwrap()
                    .as_bytes(),
            );
            out.extend_from_slice(&index.to_be_bytes());
            out.extend_from_slice(&[index as u8; 32]);
            out.push(((index - 1) % 3 + 1) as u8);
        }
    }
    out
}

#[test]
fn send_user_message_v2_shared_scalar_predicate() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/send-user-message-v2-canonical-vectors.json"
    ))
    .unwrap();
    for vector in fixture["predicate_vectors"].as_array().unwrap() {
        assert_eq!(
            has_message_text(vector["text"].as_str().unwrap()),
            vector["has_message_text"].as_bool().unwrap(),
            "wrong predicate result for {:?}",
            vector["text"]
        );
    }
}

#[test]
fn send_user_message_v2_exact_maximum_and_preallocation_guard() {
    let ascii_max = "a".repeat(8_388_608);
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
            origin: cockpit_proto::UserMessageOrigin::ExternalRoot,
            text: ascii_max.clone(),
            display_text: Some(ascii_max),
            tag_expansions: tags,
            forced_skill: Some("s".repeat(128)),
            delivery_class_override: None,
            resolved_delivery_class: Some(cockpit_proto::QueueDeliveryClass::Held),
            resolved_queue_target: Some(cockpit_proto::QueueTarget {
                id: "i".repeat(4_096),
                agent: "a".repeat(1_024),
                depth: usize::MAX,
                task_call_id: Some("t".repeat(4_096)),
            }),
            attachments,
        },
    };
    assert_eq!(
        value.encode().unwrap().len(),
        MAX_CURRENT_FCM2_ENCODING_BYTES
    );
    assert!(validate_fcm2_length(MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES).is_ok());
    let oversized_wire = vec![0; MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES + 1];
    assert_eq!(
        CanonicalSendUserMessageV2::decode(&oversized_wire)
            .unwrap_err()
            .to_string(),
        "FCM2 exceeds maximum size"
    );
    let mut one_scalar_over = value.clone();
    one_scalar_over.request.text.push('a');
    assert_eq!(
        one_scalar_over.encode().unwrap_err().to_string(),
        "text exceeds byte limit"
    );
    let mut scalar_over = value.clone();
    // Four-byte scalars exhaust the byte budget before the independent scalar
    // ceiling; the byte check is deliberately first in both codecs.
    scalar_over.request.text = "😀".repeat(2_097_153);
    assert_eq!(
        scalar_over.encode().unwrap_err().to_string(),
        "text exceeds byte limit"
    );
    let mut display_over = value.clone();
    display_over
        .request
        .display_text
        .as_mut()
        .unwrap()
        .push('a');
    assert_eq!(
        display_over.encode().unwrap_err().to_string(),
        "display text exceeds byte limit"
    );
    let mut tags_over = value.clone();
    let repeated_tag = tags_over.request.tag_expansions[0].clone();
    tags_over.request.tag_expansions.push(repeated_tag);
    assert_eq!(tags_over.encode().unwrap_err().to_string(), "too many tags");
    let mut attachments_over = value.clone();
    let repeated_attachment = attachments_over.request.attachments[0].clone();
    attachments_over
        .request
        .attachments
        .push(repeated_attachment);
    assert_eq!(
        attachments_over.encode().unwrap_err().to_string(),
        "too many attachments"
    );
    let mut tool_over = value.clone();
    tool_over.request.tag_expansions[0].tool.push('t');
    assert_eq!(
        tool_over.encode().unwrap_err().to_string(),
        "fcm2_tag_tool_too_long"
    );
    let mut path_over = value.clone();
    path_over.request.tag_expansions[0].path.push('p');
    assert_eq!(
        path_over.encode().unwrap_err().to_string(),
        "fcm2_tag_path_too_long"
    );
    let mut skill_over = value;
    skill_over.request.forced_skill.as_mut().unwrap().push('s');
    assert_eq!(
        skill_over.encode().unwrap_err().to_string(),
        "fcm2_forced_skill_too_long"
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
        assert_eq!(
            decoded.request.origin,
            cockpit_proto::UserMessageOrigin::ExternalRoot
        );
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
    for vector in fixture["compact_positive_vectors"].as_array().unwrap() {
        let bytes = compact_bytes(vector);
        let decoded = CanonicalSendUserMessageV2::decode(&bytes).unwrap();
        assert_eq!(
            decoded.request.origin,
            cockpit_proto::UserMessageOrigin::ExternalRoot
        );
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
fn send_user_message_v2_rejects_client_claimed_internal_origin() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/send-user-message-v2-canonical-vectors.json"
    ))
    .unwrap();
    let external = CanonicalSendUserMessageV2::decode(&hex(fixture["vectors"][1]["fcm2_hex"]
        .as_str()
        .unwrap()))
    .unwrap();
    let mut internal = external.clone();
    internal.request.origin = cockpit_proto::UserMessageOrigin::AutoContinue;
    let error = internal.encode().unwrap_err().to_string();
    assert!(error.contains("origin must be external_root"), "{error}");
}

#[test]
fn send_user_message_v2_shared_semantic_errors() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/send-user-message-v2-canonical-vectors.json"
    ))
    .unwrap();
    let base = CanonicalSendUserMessageV2::decode(&hex(fixture["vectors"][1]["fcm2_hex"]
        .as_str()
        .unwrap()))
    .unwrap();
    for case in fixture["semantic_error_cases"].as_array().unwrap() {
        let mut value = base.clone();
        match case["mutation"].as_str().unwrap() {
            "empty_tool" => value.request.tag_expansions[0].tool.clear(),
            "detail_one_over" => value.request.tag_expansions[0].detail = "d".repeat(4097),
            "empty_skill" => value.request.forced_skill = Some(String::new()),
            "invalid_skill" => value.request.forced_skill = Some("bad/skill".into()),
            "multibyte_tool" => value.request.tag_expansions[0].tool = "é".repeat(65),
            other => panic!("unknown mutation {other}"),
        }
        let expected = case["error_code"].as_str().unwrap();
        assert_eq!(
            value.encode().unwrap_err().to_string(),
            expected,
            "{}",
            case["name"]
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
        let error = CanonicalSendUserMessageV2::decode(&bytes)
            .unwrap_err()
            .to_string();
        assert_eq!(error, case["error"], "wrong error for {}", case["name"]);
    }
    for case in fixture["mutation_cases"].as_array().unwrap() {
        let source = case["source"].as_u64().unwrap() as usize;
        let mut bytes = hex(fixture["vectors"][source]["fcm2_hex"].as_str().unwrap());
        if let Some(offset) = case["offset"].as_u64() {
            let replacement = hex(case["bytes_hex"].as_str().unwrap());
            let offset = offset as usize;
            bytes[offset..offset + replacement.len()].copy_from_slice(&replacement);
        }
        if let Some(length) = case["truncate"].as_u64() {
            bytes.truncate(length as usize);
        }
        let error = CanonicalSendUserMessageV2::decode(&bytes)
            .unwrap_err()
            .to_string();
        assert_eq!(error, case["error"], "wrong error for {}", case["name"]);
    }
}
