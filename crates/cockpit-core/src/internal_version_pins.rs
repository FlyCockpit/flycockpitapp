//! One place to read every internal protocol / persisted-format version.
//!
//! Pre-launch, every Flycockpit-owned wire, persisted, and hash-domain format
//! version was reset to 1 and every compatibility window was deleted. This
//! module pins that invariant: a format change edits the format in place (and
//! regenerates its fixtures) instead of bumping a version and growing a
//! decoder for the old one. If you are here because you want to bump one of
//! these after launch, add a real migration path first and update this pin
//! deliberately.
//!
//! External standards are intentionally absent: JSON-RPC "2.0", the ACP
//! `protocolVersion`, MCP date versions, Noise suite names, WebRTC/JWS/
//! WebAuthn/UUID versions, the KCL manifest version, skill semver, and TUF
//! metadata counters are owned by other specifications.
//!
//! TypeScript mirrors (`RELAY_ENVELOPE_VERSION`, `FCM2_SCHEMA_VERSION`, ...)
//! are pinned against the same cross-language fixtures their Rust owners read.
//!
//! Versioned hash-domain and correlation labels are pinned here too, by the
//! named constant that owns each one (see [`hash_domain_labels_are_v1`]).
//! Changing a label changes every digest derived from it, which silently
//! orphans any durable hash computed under the old label; a new versioned
//! label belongs in a named constant at its definition site plus a pin here,
//! never an inline literal.
//!
//! Feature gating: [`remote_wire_protocol_versions_are_one`] compiles only
//! with `--features remote` and [`extended_wire_protocol_versions_are_one`]
//! only with `--features extended`. The default `--no-default-features`
//! gate skips them; CI executes them in the `remote-lockstep` job of
//! `.github/workflows/cli-ci.yml` (remote-only and extended-only nextest
//! matrices). Locally, pass `--features cockpit-core/remote` or
//! `cockpit-core/extended` to exercise them.

#[test]
fn daemon_wire_protocol_versions_are_one() {
    assert_eq!(cockpit_proto::PROTOCOL_VERSION, 1);
    assert_eq!(cockpit_proto::send_user_message::FCM2_SCHEMA_VERSION, 1);
    assert_eq!(cockpit_proto::acp::ACP_FORWARDED_MCP_VERSION_V1, 1);
    assert_eq!(
        cockpit_proto::agent_authoring::AGENT_AUTHORING_DTO_VERSION,
        1
    );
    assert_eq!(
        cockpit_proto::agent_installation::AGENT_INSTALLATION_DTO_VERSION,
        1
    );
    assert_eq!(cockpit_proto::session_setup::SESSION_SETUP_DTO_VERSION, 1);
    assert_eq!(
        cockpit_proto::session_override::AGENT_EFFECTIVE_SETTINGS_DTO_VERSION,
        1
    );
    assert_eq!(
        flycockpit_relay_protocol::envelopes::RELAY_ENVELOPE_VERSION,
        1
    );
    assert_eq!(crate::daemon::supervisor::ADMIN_PROTOCOL_VERSION, 1);
    assert_eq!(
        crate::daemon::leak_reveal_frame::LEAK_REVEAL_FRAME_VERSION,
        1
    );
    assert_eq!(cockpit_host::named_pipe::PIPE_IDENTITY_VERSION, 1);
}

/// Compiled only with `--features extended` (see the module docs).
#[cfg(feature = "extended")]
#[test]
fn extended_wire_protocol_versions_are_one() {
    assert_eq!(
        cockpit_proto::image_control::IMAGE_CONTROL_SCHEMA_VERSION,
        1
    );
}

/// Compiled only with `--features remote` (see the module docs).
#[cfg(feature = "remote")]
#[test]
fn remote_wire_protocol_versions_are_one() {
    use cockpit_proto::{
        remote_device_identity_enrollment, remote_ip_consent, remote_operation_fcor,
        remote_public_service_policy, remote_session_continuity, remote_tenant_authority_protocol,
        remote_transport, remote_turn_ice_policy, remote_version,
    };
    assert_eq!(remote_operation_fcor::FCOR_SCHEMA_VERSION, 1);
    assert_eq!(remote_version::TRANSCRIPT_VERSION, 1);
    assert_eq!(remote_transport::frame::REMOTE_TRANSPORT_FRAME_VERSION, 1);
    assert_eq!(
        remote_transport::fragment::REMOTE_CARRIER_FRAGMENT_VERSION,
        1
    );
    assert_eq!(remote_tenant_authority_protocol::FCTA_ENVELOPE_VERSION, 1);
    assert_eq!(
        remote_session_continuity::REMOTE_SESSION_CONTINUITY_SCHEMA_VERSION,
        1
    );
    assert_eq!(remote_session_continuity::REMOTE_CONTROL_EVENT_VERSION, 1);
    assert_eq!(remote_turn_ice_policy::ICE_POLICY_DIGEST_VERSION, 1);
    assert_eq!(remote_public_service_policy::POLICY_SCHEMA_VERSION, 1);
    assert_eq!(remote_ip_consent::RELATIONSHIP_VERSION, 1);
    assert_eq!(remote_ip_consent::RECEIPT_VERSION, 1);
    assert_eq!(remote_ip_consent::STATUS_VERSION, 1);
    assert_eq!(
        remote_device_identity_enrollment::ENROLLMENT_LINK_VERSION,
        1
    );
    assert_eq!(crate::daemon::remote_attempt::GRANT_SCHEMA_VERSION, 1);
}

#[test]
fn persisted_format_versions_are_one() {
    // Storage (cockpit-db).
    assert_eq!(crate::db::EXPECTED_SCHEMA_VERSION, 1);
    assert_eq!(crate::db::secret_vault::VAULT_WRAP_VERSION, 1);
    assert_eq!(
        crate::db::text_artifacts::USER_MESSAGE_MODEL_ENVELOPE_VERSION,
        1
    );
    assert_eq!(
        crate::db::agent_tree_decisions::RECURSIVE_LAUNCH_DESCRIPTOR_VERSION,
        1
    );
    assert_eq!(
        crate::db::agent_tree_decisions::NONINTERACTIVE_RECOVERY_SNAPSHOT_VERSION,
        1
    );

    // Runtime files (cockpit-host).
    assert_eq!(
        cockpit_host::daemon_lifecycle::DAEMON_PID_FILE_HEADER,
        "cockpit-daemon-pid-v1"
    );
    assert_eq!(
        cockpit_host::daemon_lifecycle::DAEMON_PID_RECEIPT_VERSION,
        1
    );

    // Application formats (cockpit-core).
    assert_eq!(
        crate::session::export::EXPORT_SCHEMA,
        "cockpit-session-export/1"
    );
    assert_eq!(crate::engine::driver::INTERACTIVE_TASK_SNAPSHOT_VERSION, 1);
    assert_eq!(crate::engine::driver::ROOT_CONTINUATION_SNAPSHOT_VERSION, 1);
    assert_eq!(crate::knowledge::SEALED_KNOWLEDGE_BASE_MARKER_VERSION, "v1");
    assert_eq!(crate::knowledge::INDEX_LOGIC_VERSION, 1);
    assert_eq!(crate::intel::INTEL_INDEX_LOGIC_VERSION, 1);
    assert_eq!(
        crate::audio_transcription::authorization::TRANSCRIPTION_REQUEST_DIGEST_VERSION,
        1
    );
    assert_eq!(
        crate::approval::classify::APPROVAL_KEY_VERSION_PREFIX,
        "v1:"
    );
    assert_eq!(crate::leaks::LEAK_CURSOR_VERSION, 1);
    assert_eq!(crate::policy::POLICY_BUNDLE_VERSION, 1);
    assert_eq!(crate::agents::SCHEMA_VERSION, 1);
    assert_eq!(crate::computer::audit::SEALED_HEAD_VERSION, 1);
    assert_eq!(crate::computer::guidance::SCHEMA_VERSION, 1);
    assert_eq!(crate::external_journal::capsule::CAPSULE_FORMAT_VERSION, 1);
    assert_eq!(
        crate::external_journal::projection::PROJECTION_SCHEMA_VERSION,
        1
    );
    assert_eq!(
        crate::external_runtime::ExternalRuntimeSchemaDocument::CURRENT_VERSION,
        1
    );
    assert_eq!(
        crate::external_runtime::DEPENDENCY_HEADLESS_SCHEMA_VERSION,
        1
    );
    assert_eq!(crate::tool_media_authority::seal::SEAL_VERSION, 1);
    assert_eq!(crate::tool_media_authority::receipt::RECEIPT_VERSION, 1);
    assert_eq!(
        crate::typed_media_result::CANONICAL_TOOL_RESULT_SCHEMA_VERSION,
        1
    );
    assert_eq!(crate::tools::read_image::READ_IMAGE_SCHEMA_VERSION, 1);
    assert_eq!(crate::tools::transcribe_audio::RESULT_SCHEMA_VERSION, 1);
    assert_eq!(crate::image_sidecar::DESTINATION_POLICY_DIGEST_VERSION, 1);
    assert_eq!(crate::image_sidecar::DOSSIER_INSTRUCTION_VERSION, 1);
    assert_eq!(crate::image_sidecar::ASK_IMAGE_INSTRUCTION_VERSION, 1);
    assert_eq!(crate::image_sidecar::dossier::DOSSIER_SCHEMA_VERSION, 1);
    assert_eq!(crate::image_sidecar::dossier::REPAIR_INSTRUCTION_VERSION, 1);

    // Configuration formats (cockpit-config).
    assert_eq!(
        crate::config::image_generation::IMAGE_GENERATION_ROUTE_PROFILE_VERSION,
        1
    );
    assert_eq!(
        crate::config::media_budget::MEDIA_RESOURCE_POLICY_VERSION,
        1
    );
}

#[test]
fn hash_domain_labels_are_v1() {
    // Wire / cross-crate labels (cockpit-proto).
    assert_eq!(
        cockpit_proto::send_user_message::MESSAGE_DIGEST_DOMAIN,
        b"flycockpit-send-user-message-v1\0"
    );
    assert_eq!(
        cockpit_proto::session_override::FOCUSED_MODEL_ROUTE_DIGEST_DOMAIN,
        b"flycockpit-focused-model-route-v1\0"
    );
    assert_eq!(
        cockpit_proto::session_override::FOCUSED_BINDING_CHOICE_ID_PREFIX,
        "focused-binding-v1-"
    );
    assert_eq!(
        cockpit_proto::agent_management::AGENT_MUTATION_SHAPE_DOMAIN,
        b"cockpit-agent-mutation-shape-v1\0"
    );
    assert_eq!(
        cockpit_proto::agent_management::ASSISTANT_MUTATION_SHAPE_DOMAIN,
        b"cockpit-assistant-mutation-shape-v1\0"
    );
    assert_eq!(
        cockpit_proto::COMPLETE_PROVIDER_OAUTH_RECEIPT_LABEL,
        "complete_provider_oauth_receipt_v1"
    );
    assert_eq!(
        cockpit_proto::COMPLETE_MCP_OAUTH_RECEIPT_LABEL,
        "complete_mcp_oauth_receipt_v1"
    );

    // Daemon labels (cockpit-core).
    assert_eq!(
        crate::daemon::server::FCM2_MODEL_DIGEST_DOMAIN,
        b"flycockpit-fcm2-model-digest-v1\0"
    );
    assert_eq!(crate::daemon::server::USER_MESSAGE_IDENTITY_TAG, b"user-v1");
    assert_eq!(
        crate::daemon::server::AGENT_MUTATION_UPDATE_REQUEST_DOMAIN,
        b"flycockpit.agent-mutation.update-request.v1"
    );
    assert_eq!(
        crate::daemon::server::ASSISTANT_MUTATION_REQUEST_DOMAIN,
        b"flycockpit.assistant-mutation.request.v1"
    );
    assert_eq!(
        crate::daemon::agent_management::AGENT_MUTATION_REQUEST_DOMAIN,
        b"flycockpit.agent-mutation.request.v1"
    );
    // Create and update agent mutations are separate request families and
    // must never share a keyed request-identity domain.
    assert_ne!(
        crate::daemon::agent_management::AGENT_MUTATION_REQUEST_DOMAIN,
        crate::daemon::server::AGENT_MUTATION_UPDATE_REQUEST_DOMAIN
    );
    assert_eq!(
        crate::daemon::agent_management::AGENT_EDITOR_COMPLETION_IDENTITY_DOMAIN,
        b"flycockpit.agent-editor.completion.v1"
    );
    assert_eq!(
        crate::daemon::agent_installation::RETAINED_DEFAULT_RECEIPT_AUTHORITY_DOMAIN,
        b"cockpit-retained-default-receipt-authority-v1\0"
    );

    // Application labels (cockpit-core).
    assert_eq!(
        crate::generated_svg::SANITIZER_POLICY_DIGEST_DOMAIN,
        b"generated-svg-v1\0canonical-v1\0verifier-v1\0"
    );
    assert_eq!(
        crate::onboarding_agent::AGENT_POLICY_SNAPSHOT_DIGEST_DOMAIN,
        b"cockpit-agent-policy-snapshot-v1\0"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        crate::computer::X11_HELD_KEYS_JOURNAL_DOMAIN,
        b"cockpit.x11.held-keys.v1"
    );
}
