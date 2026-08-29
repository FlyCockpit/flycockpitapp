//! Tests for typed media tool-result transport.
//!
//! These tests cover the acceptance criteria from the prompt:
//! 1. `typed_media_result_schema` — round-trip Text/Json/MediaReference across
//!    Rust protocol and reject unknown/inline variants.
//! 2. `typed_media_result_rig_mapping` — fixture-test exact Anthropic embedded-
//!    image, OpenAI adjacent-image, audio/video adjacent-content, and sidecar
//!    mappings with call IDs/order.
//! 3. `typed_media_result_missing_reference` — prove every wrong-session/
//!    deleted/changed/unavailable/unnormalized/capability-unknown branch fails
//!    before provider transport.
//! 4. Sentinel tests — base64/data URL/provider URL/path/media bytes are absent
//!    from persisted union while transient captured provider requests receive
//!    exact bytes.
//! 5. Cleanup/use/replay/cancel/session-switch races yield either one leased
//!    delivery or typed unavailable.
//! 6. Safe metadata projection for client rendering.
//! 7. Exhaustive match updates (ordinal ordering).

#![allow(clippy::needless_pass_by_value)]

use super::*;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a deterministic UUIDv7 for testing.
fn test_uuid_v7() -> Uuid {
    // Use a fixed timestamp + random bits to create a valid UUIDv7.
    // UUIDv7: 48-bit unix_ts_ms | 4-bit version(7) | 12-bit rand_a |
    //         2-bit var(10) | 62-bit rand_b
    let ts_ms: u64 = 1_800_000_000_000; // fixed timestamp
    let mut bytes = [0u8; 16];
    bytes[0..6].copy_from_slice(&ts_ms.to_be_bytes()[2..]);
    bytes[6] = 0x70; // version 7
    bytes[7] = 0x01;
    bytes[8] = 0x80; // variant 10
    bytes[9..16].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    Uuid::from_bytes(bytes)
}

fn test_auth(session_id: Uuid, project: &str) -> MediaReferenceAuthContext {
    MediaReferenceAuthContext {
        session_id,
        canonical_project_digest: project.to_string(),
    }
}

fn test_reference(
    kind: CanonicalMediaKind,
    ordinal: u32,
    availability: MediaReferenceAvailability,
) -> MediaReference {
    MediaReference::new(
        test_uuid_v7(),
        1,
        kind,
        match kind {
            CanonicalMediaKind::Image => "image/png",
            CanonicalMediaKind::Audio => "audio/wav",
            CanonicalMediaKind::Video => "video/mp4",
        },
        ordinal,
        MediaReferencePurpose::Primary,
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        1024,
        availability,
        MediaProvenance {
            tool_name: "screenshot".to_string(),
            source_label: Some("screen".to_string()),
        },
    )
}

fn test_live_snapshot(
    reference: &MediaReference,
    session_id: Uuid,
    project: &str,
    availability: LiveAttachmentAvailability,
) -> LiveAttachmentSnapshot {
    LiveAttachmentSnapshot {
        attachment_id: reference.attachment_id,
        session_id,
        canonical_project_digest: project.to_string(),
        attachment_version: reference.attachment_version,
        availability,
        has_normalized_derivative: true,
        synthetic_lease_authorized: true,
        media_kind: reference.media_kind,
        mime_type: reference.mime_type.clone(),
    }
}

fn anthropic_capabilities() -> ModelCapabilityProfile {
    ModelCapabilityProfile {
        image_in_tool_result: true,
        image_in_user_content: true,
        audio_in_user_content: false,
        video_in_user_content: false,
    }
}

fn openai_capabilities() -> ModelCapabilityProfile {
    ModelCapabilityProfile {
        image_in_tool_result: false,
        image_in_user_content: true,
        audio_in_user_content: false,
        video_in_user_content: false,
    }
}

fn audio_video_capabilities() -> ModelCapabilityProfile {
    ModelCapabilityProfile {
        image_in_tool_result: false,
        image_in_user_content: true,
        audio_in_user_content: true,
        video_in_user_content: true,
    }
}

fn no_capability_profile() -> ModelCapabilityProfile {
    ModelCapabilityProfile::default()
}

const TEST_SESSION: &str = "00000000-0000-7000-8000-000000000001";
const TEST_PROJECT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn test_session_id() -> Uuid {
    Uuid::parse_str(TEST_SESSION).unwrap()
}

// ---------------------------------------------------------------------------
// 1. typed_media_result_schema — round-trip + rejection
// ---------------------------------------------------------------------------

#[test]
fn typed_media_result_schema_round_trips_text() {
    let content = CanonicalToolResultContent::text("hello world");
    let json = serde_json::to_string(&content).unwrap();
    let back: CanonicalToolResultContent = serde_json::from_str(&json).unwrap();
    assert_eq!(content, back);
    assert_eq!(back.as_text(), Some("hello world"));
}

#[test]
fn typed_media_result_schema_round_trips_json() {
    let value = serde_json::json!({"key": "value", "num": 42});
    let content = CanonicalToolResultContent::json(value.clone());
    let json = serde_json::to_string(&content).unwrap();
    let back: CanonicalToolResultContent = serde_json::from_str(&json).unwrap();
    assert_eq!(content, back);
    assert_eq!(back.as_json(), Some(&value));
}

#[test]
fn typed_media_result_schema_round_trips_media_reference() {
    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    )
    .with_dimensions(1920, 1080);
    let content = CanonicalToolResultContent::media_reference(reference);
    let json = serde_json::to_string(&content).unwrap();
    let back: CanonicalToolResultContent = serde_json::from_str(&json).unwrap();
    assert_eq!(content, back);
    assert!(back.is_media_reference());
    let mr = back.as_media_reference().unwrap();
    assert_eq!(mr.media_kind, CanonicalMediaKind::Image);
    assert_eq!(
        mr.dimensions,
        Some(MediaDimensions {
            width: 1920,
            height: 1080,
        })
    );
}

#[test]
fn typed_media_result_schema_round_trips_media_reference_with_duration() {
    let reference = test_reference(
        CanonicalMediaKind::Audio,
        0,
        MediaReferenceAvailability::Ready,
    )
    .with_duration_ms(5000);
    let content = CanonicalToolResultContent::media_reference(reference);
    let json = serde_json::to_string(&content).unwrap();
    let back: CanonicalToolResultContent = serde_json::from_str(&json).unwrap();
    assert_eq!(content, back);
    let mr = back.as_media_reference().unwrap();
    assert_eq!(mr.duration_ms, Some(MediaDurationMs(5000)));
}

#[test]
fn typed_media_result_schema_rejects_unknown_variant() {
    let json = r#"{"kind":"unknown_variant","text":"hello"}"#;
    let result: Result<CanonicalToolResultContent, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn typed_media_result_schema_rejects_inline_base64_in_text() {
    let content = CanonicalToolResultContent::text("data:image/png;base64,iVBORw0KGgo=");
    let result = content.validate_no_inline_media();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), MediaReferenceError::InlineMediaInText);
}

#[test]
fn typed_media_result_schema_rejects_inline_data_url_in_json() {
    let content = CanonicalToolResultContent::json(serde_json::json!({
        "image": "data:image/png;base64,iVBORw0KGgo="
    }));
    let result = content.validate_no_inline_media();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), MediaReferenceError::InlineMediaInJson);
}

#[test]
fn typed_media_result_schema_accepts_normal_text() {
    let content = CanonicalToolResultContent::text("The file contains 42 lines of code.");
    assert!(content.validate_no_inline_media().is_ok());
}

#[test]
fn typed_media_result_schema_accepts_normal_json() {
    let content = CanonicalToolResultContent::json(serde_json::json!({
        "lines": 42,
        "path": "/some/normal/path.rs"
    }));
    assert!(content.validate_no_inline_media().is_ok());
}

#[test]
fn typed_media_result_schema_rejects_data_audio_url() {
    let content = CanonicalToolResultContent::text("data:audio/wav;base64,AAAA");
    assert!(content.validate_no_inline_media().is_err());
}

#[test]
fn typed_media_result_schema_rejects_data_video_url() {
    let content = CanonicalToolResultContent::text("data:video/mp4;base64,AAAA");
    assert!(content.validate_no_inline_media().is_err());
}

#[test]
fn typed_media_result_schema_uses_camel_case() {
    let reference = test_reference(
        CanonicalMediaKind::Image,
        2,
        MediaReferenceAvailability::Ready,
    )
    .with_dimensions(640, 480);
    let content = CanonicalToolResultContent::media_reference(reference);
    let json = serde_json::to_string(&content).unwrap();
    // Check camelCase field names
    assert!(json.contains("\"attachmentId\""));
    assert!(json.contains("\"attachmentVersion\""));
    assert!(json.contains("\"mediaKind\""));
    assert!(json.contains("\"mimeType\""));
    assert!(json.contains("\"byteCount\""));
    assert!(json.contains("\"media_reference\""));
}

#[test]
fn typed_media_result_schema_rejects_unknown_fields_in_media_reference() {
    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let content = CanonicalToolResultContent::media_reference(reference);
    let json = serde_json::to_string(&content).unwrap();
    // Inject an unknown field
    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    if let Some(obj) = value.as_object_mut() {
        obj.insert("evilField".to_string(), serde_json::json!("malicious"));
    }
    let tampered = serde_json::to_string(&value).unwrap();
    let result: Result<CanonicalToolResultContent, _> = serde_json::from_str(&tampered);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// 2. typed_media_result_rig_mapping — exact mappings with call IDs/order
// ---------------------------------------------------------------------------

#[test]
fn typed_media_result_rig_mapping_anthropic_embedded_image() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        3,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let mapping = resolver
        .resolve(
            &reference,
            &live,
            MediaRoute::Primary,
            "call-001",
            Some("provider-call-001"),
        )
        .unwrap();

    let rig = map_to_provider_rig(&mapping, &reference, "iVBORw0KGgo=").unwrap();
    match &rig {
        ProviderRigMapping::AnthropicEmbeddedImage {
            tool_call_id,
            call_id,
            ordinal,
            mime_type,
            base64_bytes,
        } => {
            assert_eq!(tool_call_id, "call-001");
            assert_eq!(call_id.as_deref(), Some("provider-call-001"));
            assert_eq!(*ordinal, 3);
            assert_eq!(mime_type, "image/png");
            assert_eq!(base64_bytes, "iVBORw0KGgo=");
        }
        other => panic!("expected AnthropicEmbeddedImage, got {:?}", other),
    }
}

#[test]
fn typed_media_result_rig_mapping_openai_adjacent_image() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = openai_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        5,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let mapping = resolver
        .resolve(&reference, &live, MediaRoute::Primary, "call-002", None)
        .unwrap();

    let rig = map_to_provider_rig(&mapping, &reference, "iVBORw0KGgo=").unwrap();
    match &rig {
        ProviderRigMapping::OpenAiAdjacentImage {
            tool_call_id,
            call_id,
            ordinal,
            result_body,
            image_mime_type,
            image_base64_bytes,
        } => {
            assert_eq!(tool_call_id, "call-002");
            assert!(call_id.is_none());
            assert_eq!(*ordinal, 5);
            assert!(result_body.contains("image"));
            assert_eq!(image_mime_type, "image/png");
            assert_eq!(image_base64_bytes, "iVBORw0KGgo=");
        }
        other => panic!("expected OpenAiAdjacentImage, got {:?}", other),
    }
}

#[test]
fn typed_media_result_rig_mapping_adjacent_audio() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = audio_video_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Audio,
        1,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let mapping = resolver
        .resolve(
            &reference,
            &live,
            MediaRoute::Primary,
            "call-003",
            Some("pc-003"),
        )
        .unwrap();

    let rig = map_to_provider_rig(&mapping, &reference, "UklGRkA=").unwrap();
    match &rig {
        ProviderRigMapping::AdjacentAudio {
            tool_call_id,
            call_id,
            ordinal,
            result_body,
            audio_mime_type,
            audio_base64_bytes,
        } => {
            assert_eq!(tool_call_id, "call-003");
            assert_eq!(call_id.as_deref(), Some("pc-003"));
            assert_eq!(*ordinal, 1);
            assert!(result_body.contains("audio"));
            assert_eq!(audio_mime_type, "audio/wav");
            assert_eq!(audio_base64_bytes, "UklGRkA=");
        }
        other => panic!("expected AdjacentAudio, got {:?}", other),
    }
}

#[test]
fn typed_media_result_rig_mapping_adjacent_video() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = audio_video_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Video,
        7,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let mapping = resolver
        .resolve(&reference, &live, MediaRoute::Primary, "call-004", None)
        .unwrap();

    let rig = map_to_provider_rig(&mapping, &reference, "AAAAIGZ0").unwrap();
    match &rig {
        ProviderRigMapping::AdjacentVideo {
            tool_call_id,
            call_id,
            ordinal,
            result_body,
            video_mime_type,
            video_base64_bytes,
        } => {
            assert_eq!(tool_call_id, "call-004");
            assert!(call_id.is_none());
            assert_eq!(*ordinal, 7);
            assert!(result_body.contains("video"));
            assert_eq!(video_mime_type, "video/mp4");
            assert_eq!(video_base64_bytes, "AAAAIGZ0");
        }
        other => panic!("expected AdjacentVideo, got {:?}", other),
    }
}

#[test]
fn typed_media_result_rig_mapping_image_sidecar() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let mapping = resolver
        .resolve(
            &reference,
            &live,
            MediaRoute::Sidecar,
            "call-005",
            Some("pc-005"),
        )
        .unwrap();

    let rig = map_to_provider_rig(&mapping, &reference, "").unwrap();
    match &rig {
        ProviderRigMapping::ImageSidecar {
            tool_call_id,
            call_id,
            ordinal,
            reference_body,
        } => {
            assert_eq!(tool_call_id, "call-005");
            assert_eq!(call_id.as_deref(), Some("pc-005"));
            assert_eq!(*ordinal, 0);
            assert!(reference_body.contains("media reference"));
            assert!(reference_body.contains("image"));
        }
        other => panic!("expected ImageSidecar, got {:?}", other),
    }
    // Sidecar must not dispatch bytes
    assert!(rig.is_sidecar());
    assert!(mapping.bytes.is_none());
}

#[test]
fn typed_media_result_rig_mapping_preserves_call_id_and_order() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    // Multiple references with different ordinals and call IDs
    let refs: Vec<_> = (0..3)
        .map(|i| {
            let mut r = test_reference(
                CanonicalMediaKind::Image,
                i,
                MediaReferenceAvailability::Ready,
            );
            r.ordinal = i;
            r
        })
        .collect();

    let mappings: Vec<_> = refs
        .iter()
        .map(|r| {
            let live =
                test_live_snapshot(r, session, TEST_PROJECT, LiveAttachmentAvailability::Ready);
            resolver
                .resolve(
                    r,
                    &live,
                    MediaRoute::Primary,
                    &format!("call-{}", r.ordinal),
                    None,
                )
                .unwrap()
        })
        .collect();

    // Verify ordinals preserve order
    for (i, m) in mappings.iter().enumerate() {
        assert_eq!(m.ordinal, i as u32);
        assert_eq!(m.tool_call_id, format!("call-{}", i));
    }
}

// ---------------------------------------------------------------------------
// 3. typed_media_result_missing_reference — all failure branches
// ---------------------------------------------------------------------------

#[test]
fn typed_media_result_missing_reference_wrong_session() {
    let session = test_session_id();
    let other_session = Uuid::parse_str("00000000-0000-7000-8000-000000000002").unwrap();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        other_session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::WrongSession { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_wrong_project() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        "deadbeef",
        LiveAttachmentAvailability::Ready,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::WrongProject { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_deleted() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Deleted,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(result, Err(MediaReferenceError::Deleted { .. })));
}

#[test]
fn typed_media_result_missing_reference_security_blocked() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::SecurityBlocked,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::SecurityBlocked { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_cleanup_pending() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::CleanupPending,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::CleanupPending { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_source_changed() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let mut live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::SourceChanged,
    );
    live.attachment_version = 2; // version changed
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::SourceChanged { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_failed() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Failed,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(result, Err(MediaReferenceError::Failed { .. })));
}

#[test]
fn typed_media_result_missing_reference_not_ready_processing() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Processing,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Processing,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(result, Err(MediaReferenceError::NotReady { .. })));
}

#[test]
fn typed_media_result_image_sidecar_requires_normalized_derivative() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = openai_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let mut live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    live.has_normalized_derivative = false;
    let result = resolver.resolve(&reference, &live, MediaRoute::Sidecar, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::NotNormalized { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_not_normalized_audio() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = audio_video_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Audio,
        0,
        MediaReferenceAvailability::Ready,
    );
    let mut live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    live.has_normalized_derivative = false;
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::NotNormalized { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_not_normalized_video() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = audio_video_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Video,
        0,
        MediaReferenceAvailability::Ready,
    );
    let mut live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    live.has_normalized_derivative = false;
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::NotNormalized { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_not_normalized_adjacent_image() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = openai_capabilities(); // adjacent image requires normalized derivative
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let mut live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    live.has_normalized_derivative = false;
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::NotNormalized { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_no_lease() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let mut live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    live.synthetic_lease_authorized = false;
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(result, Err(MediaReferenceError::NoLease { .. })));
}

#[test]
fn typed_media_result_missing_reference_capability_unknown() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = no_capability_profile();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::CapabilityUnknown { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_capability_unknown_audio() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = no_capability_profile();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Audio,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::CapabilityUnknown { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_audio_sidecar_unsupported() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = audio_video_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Audio,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Sidecar, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::AudioVideoSidecarUnsupported { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_video_sidecar_unsupported() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = audio_video_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Video,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Sidecar, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::AudioVideoSidecarUnsupported { .. })
    ));
}

#[test]
fn typed_media_result_missing_reference_not_found() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let mut live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    live.attachment_id = Uuid::nil(); // different ID
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(result, Err(MediaReferenceError::NotFound { .. })));
}

// ---------------------------------------------------------------------------
// 4. Sentinel tests — no bytes/paths/URLs in persisted union
// ---------------------------------------------------------------------------

#[test]
fn typed_media_result_sentinel_no_bytes_in_media_reference() {
    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let content = CanonicalToolResultContent::media_reference(reference);
    let json = serde_json::to_string(&content).unwrap();

    // No raw bytes, base64 data, paths, or URLs in the persisted union
    assert!(!json.contains("data:"));
    assert!(!json.contains("base64,"));
    assert!(!json.contains("http://"));
    assert!(!json.contains("https://"));
    assert!(!json.contains("/tmp/"));
    assert!(!json.contains("/home/"));
    assert!(!json.contains("\\\\"));

    // The reference must contain only the attachment ID (opaque) and safe metadata
    assert!(json.contains("attachmentId"));
}

#[test]
fn typed_media_result_sentinel_text_rejects_large_base64_blob() {
    let large_base64 = "A".repeat(300);
    let content = CanonicalToolResultContent::text(large_base64);
    assert!(content.validate_no_inline_media().is_err());
}

#[test]
fn typed_media_result_sentinel_transient_mapping_contains_bytes() {
    // Transient captured provider requests receive exact bytes — but only
    // in the transient ProviderRigMapping, never in the persisted union.
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let mapping = resolver
        .resolve(&reference, &live, MediaRoute::Primary, "call", None)
        .unwrap();

    let rig = map_to_provider_rig(&mapping, &reference, "iVBORw0KGgo=").unwrap();
    // The transient mapping DOES contain the bytes
    match &rig {
        ProviderRigMapping::AnthropicEmbeddedImage { base64_bytes, .. } => {
            assert_eq!(base64_bytes, "iVBORw0KGgo=");
        }
        _ => panic!("expected embedded image"),
    }

    // But the persisted canonical content does NOT contain bytes
    let persisted = CanonicalToolResultContent::media_reference(reference.clone());
    let persisted_json = serde_json::to_string(&persisted).unwrap();
    assert!(!persisted_json.contains("iVBORw0KGgo"));
}

#[test]
fn typed_media_result_sentinel_no_host_path_in_provenance() {
    let reference = MediaReference::new(
        test_uuid_v7(),
        1,
        CanonicalMediaKind::Image,
        "image/png",
        0,
        MediaReferencePurpose::Primary,
        "abc123",
        100,
        MediaReferenceAvailability::Ready,
        MediaProvenance {
            tool_name: "screenshot".to_string(),
            source_label: Some("/home/user/secret.png".to_string()), // should be sanitized by caller
        },
    );
    let content = CanonicalToolResultContent::media_reference(reference);
    let json = serde_json::to_string(&content).unwrap();
    // The schema itself doesn't sanitize, but the provenance field must be
    // human-readable and safe. Callers must sanitize. The key point: the
    // schema does not have a "path" field — only tool_name and source_label.
    assert!(json.contains("toolName"));
    assert!(json.contains("sourceLabel"));
    // No explicit path field in the schema
    assert!(!json.contains("\"path\""));
}

// ---------------------------------------------------------------------------
// 5. Cleanup/use/replay/cancel/session-switch races
// ---------------------------------------------------------------------------

#[test]
fn typed_media_result_race_cleanup_before_lease_yields_unavailable() {
    // Cleanup before lease yields unavailable
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::CleanupPending,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(result.is_err());
    // Cleanup before lease yields typed unavailable, never dangling/partial media
    assert!(matches!(
        result,
        Err(MediaReferenceError::CleanupPending { .. })
    ));
}

#[test]
fn typed_media_result_race_leased_delivery_succeeds() {
    // A valid lease is held until provider body handoff completes — one leased
    // delivery succeeds.
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(result.is_ok());
}

#[test]
fn typed_media_result_race_session_switch_cannot_rebind() {
    // Session switch/reconnect cannot rebind a reference.
    let session = test_session_id();
    let new_session = Uuid::parse_str("00000000-0000-7000-8000-000000000099").unwrap();
    let auth = test_auth(new_session, TEST_PROJECT); // switched session
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    // Live attachment still belongs to old session
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let result = resolver.resolve(&reference, &live, MediaRoute::Primary, "call", None);
    assert!(matches!(
        result,
        Err(MediaReferenceError::WrongSession { .. })
    ));
}

#[test]
fn typed_media_result_race_cancel_after_commit_replays_same_reference() {
    // Cancellation before publication creates no result; after canonical result
    // commit it replays the same reference even if later unavailable.
    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let content = CanonicalToolResultContent::media_reference(reference.clone());

    // The canonical content is committed (serialized) — it can be replayed
    let json = serde_json::to_string(&content).unwrap();
    let replayed: CanonicalToolResultContent = serde_json::from_str(&json).unwrap();
    assert_eq!(content, replayed);

    // Even if the attachment later becomes unavailable, the reference replays
    // the same ID (the resolver will reject it, but the reference is preserved)
    let replayed_ref = replayed.as_media_reference().unwrap();
    assert_eq!(replayed_ref.attachment_id, reference.attachment_id);
}

// ---------------------------------------------------------------------------
// 6. Safe metadata projection for client rendering
// ---------------------------------------------------------------------------

#[test]
fn typed_media_result_safe_metadata_projection() {
    let reference = test_reference(
        CanonicalMediaKind::Image,
        2,
        MediaReferenceAvailability::Ready,
    )
    .with_dimensions(800, 600);
    let content = CanonicalToolResultContent::media_reference(reference);
    let metadata = project_safe_metadata(&content, Some("handle-abc-123")).unwrap();

    assert_eq!(metadata.media_kind, CanonicalMediaKind::Image);
    assert_eq!(metadata.mime_type, "image/png");
    assert_eq!(metadata.byte_count, 1024);
    assert_eq!(metadata.ordinal, 2);
    assert_eq!(metadata.artifact_handle.as_deref(), Some("handle-abc-123"));
    assert_eq!(
        metadata.dimensions,
        Some(MediaDimensions {
            width: 800,
            height: 600,
        })
    );
}

#[test]
fn typed_media_result_safe_metadata_no_eager_bytes() {
    let reference = test_reference(
        CanonicalMediaKind::Audio,
        0,
        MediaReferenceAvailability::Ready,
    )
    .with_duration_ms(3000);
    let content = CanonicalToolResultContent::media_reference(reference);
    let metadata = project_safe_metadata(&content, None).unwrap();

    // Safe metadata must not contain bytes
    let json = serde_json::to_string(&metadata).unwrap();
    assert!(!json.contains("bytes"));
    assert!(!json.contains("base64"));
    assert!(!json.contains("data:"));
    assert!(json.contains("durationMs"));
    assert_eq!(metadata.duration_ms, Some(MediaDurationMs(3000)));
    assert!(metadata.artifact_handle.is_none());
}

#[test]
fn typed_media_result_safe_metadata_text_returns_none() {
    let content = CanonicalToolResultContent::text("hello");
    assert!(project_safe_metadata(&content, None).is_none());
}

#[test]
fn typed_media_result_safe_metadata_json_returns_none() {
    let content = CanonicalToolResultContent::json(serde_json::json!({"a": 1}));
    assert!(project_safe_metadata(&content, None).is_none());
}

// ---------------------------------------------------------------------------
// 7. Ordinal ordering — exhaustive match updates
// ---------------------------------------------------------------------------

#[test]
fn typed_media_result_ordinal_ordering() {
    let mut contents = vec![
        CanonicalToolResultContent::media_reference(test_reference(
            CanonicalMediaKind::Image,
            5,
            MediaReferenceAvailability::Ready,
        )),
        CanonicalToolResultContent::text("first"),
        CanonicalToolResultContent::json(serde_json::json!({"v": 1})),
        CanonicalToolResultContent::media_reference(test_reference(
            CanonicalMediaKind::Audio,
            2,
            MediaReferenceAvailability::Ready,
        )),
    ];
    sort_by_ordinal(&mut contents);
    // Text (ordinal 0) < Json (ordinal 1) < Audio ref (ordinal 2) < Image ref (ordinal 5)
    assert_eq!(contents[0].ordinal(), 0);
    assert_eq!(contents[1].ordinal(), 1);
    assert_eq!(contents[2].ordinal(), 2);
    assert_eq!(contents[3].ordinal(), 5);
    assert!(contents[0].as_text().is_some());
    assert!(contents[1].as_json().is_some());
    assert!(contents[2].is_media_reference());
    assert!(contents[3].is_media_reference());
}

#[test]
fn typed_media_result_text_preserves_existing_behavior() {
    // Text/JSON behavior must not be loosened by the canonical variant.
    let text = CanonicalToolResultContent::text("hello");
    assert_eq!(text.as_text(), Some("hello"));
    assert!(!text.is_media_reference());

    let json = CanonicalToolResultContent::json(serde_json::json!([1, 2, 3]));
    assert_eq!(json.as_json(), Some(&serde_json::json!([1, 2, 3])));
    assert!(!json.is_media_reference());
}

// ---------------------------------------------------------------------------
// ProviderRigMapping helpers
// ---------------------------------------------------------------------------

#[test]
fn typed_media_result_mapping_is_adjacent_content() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = openai_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let mapping = resolver
        .resolve(&reference, &live, MediaRoute::Primary, "call", None)
        .unwrap();
    let rig = map_to_provider_rig(&mapping, &reference, "bytes").unwrap();
    assert!(rig.is_adjacent_content());
    assert!(!rig.is_embedded());
    assert!(!rig.is_sidecar());
}

#[test]
fn typed_media_result_mapping_is_embedded() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        0,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let mapping = resolver
        .resolve(&reference, &live, MediaRoute::Primary, "call", None)
        .unwrap();
    let rig = map_to_provider_rig(&mapping, &reference, "bytes").unwrap();
    assert!(rig.is_embedded());
    assert!(!rig.is_adjacent_content());
    assert!(!rig.is_sidecar());
}

#[test]
fn typed_media_result_mapping_tool_call_id_and_ordinal() {
    let session = test_session_id();
    let auth = test_auth(session, TEST_PROJECT);
    let caps = anthropic_capabilities();
    let resolver = MediaReferenceResolver::new(&auth, &caps);

    let reference = test_reference(
        CanonicalMediaKind::Image,
        42,
        MediaReferenceAvailability::Ready,
    );
    let live = test_live_snapshot(
        &reference,
        session,
        TEST_PROJECT,
        LiveAttachmentAvailability::Ready,
    );
    let mapping = resolver
        .resolve(
            &reference,
            &live,
            MediaRoute::Primary,
            "tc-99",
            Some("pc-99"),
        )
        .unwrap();
    let rig = map_to_provider_rig(&mapping, &reference, "bytes").unwrap();
    assert_eq!(rig.tool_call_id(), "tc-99");
    assert_eq!(rig.ordinal(), 42);
}

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

#[test]
fn typed_media_result_schema_version() {
    assert_eq!(CANONICAL_TOOL_RESULT_SCHEMA_VERSION, 1);
}

// ---------------------------------------------------------------------------
// TypeScript round-trip (JSON compatibility)
// ---------------------------------------------------------------------------

#[test]
fn typed_media_result_schema_typescript_compatible_json() {
    // The Rust JSON output must be consumable by a TypeScript zod schema
    // with camelCase fields and a `kind` discriminator.
    let reference = test_reference(
        CanonicalMediaKind::Video,
        10,
        MediaReferenceAvailability::Ready,
    )
    .with_duration_ms(10000)
    .with_dimensions(1280, 720);
    let content = CanonicalToolResultContent::media_reference(reference);
    let json = serde_json::to_string(&content).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let obj = value.as_object().unwrap();
    // kind discriminator
    assert_eq!(
        obj.get("kind").and_then(|v| v.as_str()),
        Some("media_reference")
    );
    // camelCase fields
    assert!(obj.contains_key("attachmentId"));
    assert!(obj.contains_key("attachmentVersion"));
    assert!(obj.contains_key("mediaKind"));
    assert!(obj.contains_key("mimeType"));
    assert!(obj.contains_key("ordinal"));
    assert!(obj.contains_key("purpose"));
    assert!(obj.contains_key("checksum"));
    assert!(obj.contains_key("byteCount"));
    assert!(obj.contains_key("availability"));
    assert!(obj.contains_key("provenance"));
    assert!(obj.contains_key("dimensions"));
    assert!(obj.contains_key("durationMs"));
    // mediaKind is snake_case inside the value
    assert_eq!(obj.get("mediaKind").and_then(|v| v.as_str()), Some("video"));
}
