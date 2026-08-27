use serde_json::json;

use super::AcpTransportCounters;
use super::adapter::AcpAdapter;
use super::classify::{InboundMessage, classify};
use super::codec::{
    ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1, ACP_JSON_FRAME_MAX_BYTES_V1, AcpFrameError,
    MemoryFrameSink,
};
use super::dispatch::{build_rpc_module, elicitation_is_rejected, registered_method_names};
use super::dto::{DtoError, decode_session_new};
use super::raw_json::{JsonRpcId, RawJsonErrorKind, parse_frame};
use super::registry::{
    ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1, ACP_OUTBOUND_PERMISSION_MAX_ENTRIES_V1,
    EdgeReason, OutboundPermissionRegistry, PermissionStateName, RecordingAck, RecordingResolve,
    RegistryError, permission_params,
};
use cockpit_proto::ResolveCodeRootInterruptResultV1;

fn peer() -> AcpAdapter<MemoryFrameSink, RecordingResolve, RecordingAck> {
    AcpAdapter::new(
        MemoryFrameSink::default(),
        RecordingResolve::default(),
        RecordingAck::default(),
    )
}

fn assert_jsonrpc_2_0(frame: &str) {
    assert!(
        frame.contains("\"jsonrpc\":\"2.0\""),
        "frame missing exact jsonrpc 2.0: {frame}"
    );
}

fn send(
    peer: &mut AcpAdapter<MemoryFrameSink, RecordingResolve, RecordingAck>,
    json: &str,
) -> Option<String> {
    let response = peer.handle_frame(json);
    if let Some(frame) = &response {
        assert_jsonrpc_2_0(frame);
        peer.write_protocol(frame).unwrap();
    }
    response
}

fn session_new_ok() -> String {
    r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/tmp/project","mcpServers":[{"name":"workspace-tools","command":"/bin/mcp","args":["--stdio"],"env":[]}]}}"#.to_string()
}

#[test]
fn acp_transport_initialize_capability_serialization() {
    let mut peer = peer();
    let response = send(
        &mut peer,
        r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":1}}"#,
    )
    .unwrap();
    assert_jsonrpc_2_0(&response);
    assert!(response.contains("\"protocolVersion\":1"));
    assert!(response.contains("\"loadSession\":true"));
    assert!(!response.contains("elicitation"));
    let _module = build_rpc_module();
    assert_eq!(
        registered_method_names(),
        [
            "initialize",
            "session/new",
            "session/load",
            "session/cancel",
            "session/prompt"
        ]
    );
}

#[test]
fn acp_transport_client_cancellation_and_agent_to_client() {
    let mut peer = peer();
    send(
        &mut peer,
        r#"{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s1"}}"#,
    );
    assert_eq!(peer.cancelled_sessions, ["s1"]);

    let id = peer
        .registry
        .issue_and_write(
            "att-1".into(),
            "delivery-1".into(),
            "attention-1".into(),
            vec!["allow-once".into()],
            permission_params("s1", &["allow-once"], "call-1"),
            &mut peer.sink,
            &mut peer.counters,
        )
        .unwrap();
    assert_eq!(id, "1");
    let outbound = peer.sink.frames.last().unwrap();
    assert_jsonrpc_2_0(outbound);
    assert!(outbound.contains("session/request_permission"));
    assert_eq!(
        peer.registry.state_of("1"),
        Some(PermissionStateName::Issued)
    );
}

#[test]
fn acp_transport_response_id_routing_and_malformed_errors() {
    let mut peer = peer();
    peer.registry
        .issue_and_write(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut peer.sink,
            &mut peer.counters,
        )
        .unwrap();
    send(
        &mut peer,
        r#"{"jsonrpc":"2.0","id":"1","result":{"outcome":{"outcome":"selected","optionId":"allow-once"}}}"#,
    );
    assert_eq!(peer.resolve.calls.len(), 1);
    assert_eq!(peer.ack.ids, ["d"]);
    assert_eq!(
        peer.registry.daemon_outcome_of("1"),
        Some(ResolveCodeRootInterruptResultV1::Accepted)
    );

    let mut peer = peer();
    let err = send(
        &mut peer,
        r#"{"jsonrpc":"1.0","id":9,"method":"initialize"}"#,
    )
    .unwrap();
    assert!(err.contains("\"code\":-32600"));
    let missing = send(&mut peer, r#"{"jsonrpc":"2.0","id":9,"method":"nope"}"#).unwrap();
    assert!(missing.contains("\"code\":-32601"));
    assert!(peer.counters.zero_side_effects() || peer.counters.frames_rejected >= 1);
}

#[test]
fn acp_transport_rejects_wrong_or_duplicate_jsonrpc_before_routing() {
    let mut peer = peer();
    assert!(send(&mut peer, r#"{"id":1,"method":"initialize"}"#).is_some());
    assert_eq!(peer.counters.dto_produced, 0);
    assert_eq!(peer.counters.bridge_conversions, 0);
    let dup = send(
        &mut peer,
        r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"initialize"}"#,
    );
    assert!(dup.unwrap().contains("-32600"));
    assert!(peer.counters.zero_side_effects() || peer.counters.bridge_conversions == 0);
}

fn duplicate_rejected(frame: &str, expected_name: &str) {
    let mut peer = peer();
    let response = send(&mut peer, frame);
    if let Some(frame) = response {
        assert!(frame.contains("-32600") || frame.contains("-32700"));
        assert_jsonrpc_2_0(&frame);
    }
    assert_eq!(peer.counters.daemon_mutations, 0);
    assert_eq!(peer.counters.bridge_conversions, 0);
    assert_eq!(peer.counters.catalog_mutations, 0);
    assert_eq!(peer.counters.dto_produced, 0);
    let err = parse_frame(frame).unwrap_err();
    match err.kind {
        RawJsonErrorKind::DuplicateMember { name, .. } => assert_eq!(name, expected_name),
        other => panic!("expected duplicate {expected_name}, got {other:?}"),
    }
}

#[test]
fn acp_transport_duplicate_members_at_every_admission_depth() {
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"session/new","params":{"cwd":"/a","mcpServers":[]}}"#,
        "id",
    );
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/a","cwd":"/b","mcpServers":[]}}"#,
        "cwd",
    );
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/a","mcpServers":[],"mcpServers":[]}}"#,
        "mcpServers",
    );
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/a","mcpServers":[{"name":"x","name":"y","command":"c","args":[],"env":[]}]}}"#,
        "name",
    );
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/a","mcpServers":[{"type":"stdio","type":"http","name":"x","command":"c","args":[],"env":[]}]}}"#,
        "type",
    );
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/a","mcpServers":[{"name":"x","command":"c","command":"d","args":[],"env":[]}]}}"#,
        "command",
    );
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/a","mcpServers":[{"name":"x","command":"c","args":[],"args":[],"env":[]}]}}"#,
        "args",
    );
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/a","mcpServers":[{"type":"http","name":"x","url":"http://a","url":"http://b","headers":[]}]}}"#,
        "url",
    );
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/a","mcpServers":[{"type":"http","name":"x","url":"http://a","headers":[{"name":"H","name":"H2","value":"v"}]}]}}"#,
        "name",
    );
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/a","mcpServers":[{"name":"x","command":"c","args":[],"env":[{"name":"E","name":"E2","value":"v"}]}]}}"#,
        "name",
    );
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"method":"session/load","params":{"cwd":"/a","sessionId":"s","sessionId":"t","mcpServers":[{"name":"x","command":"c","args":[],"env":[]}]}}"#,
        "sessionId",
    );
    duplicate_rejected(
        r#"{"jsonrpc":"2.0","id":1,"method":"session/new","method":"session/load","params":{"cwd":"/a","mcpServers":[]}}"#,
        "method",
    );
}

#[test]
fn acp_transport_raw_mcp_servers_before_schema_and_no_partial_dto() {
    let mut counters = AcpTransportCounters::default();
    let frame = r#"{"cwd":"/tmp","mcpServers":[{"name":"ok","command":"/bin/mcp","args":[],"env":[]},"bad"]}"#;
    let parsed = parse_frame(frame).unwrap();
    let err = decode_session_new(frame, &parsed.root, &mut counters).unwrap_err();
    assert!(matches!(
        err,
        DtoError::FieldType(_) | DtoError::MixedOrUnknownTransport
    ));
    assert_eq!(counters.dto_produced, 0);
    assert_eq!(counters.schema_decode_attempts, 0);

    let mut counters = AcpTransportCounters::default();
    let frame = r#"{"cwd":"/tmp","mcpServers":[{"name":"x","type":"nope","command":"c","args":[],"env":[]}]}"#;
    let parsed = parse_frame(frame).unwrap();
    let err = decode_session_new(frame, &parsed.root, &mut counters).unwrap_err();
    assert!(matches!(err, DtoError::MixedOrUnknownTransport));
    assert_eq!(counters.dto_produced, 0);
}

#[test]
fn acp_transport_session_new_bridge_only_converts_ingress() {
    let mut peer = peer();
    let response = send(&mut peer, &session_new_ok()).unwrap();
    assert_jsonrpc_2_0(&response);
    assert!(response.contains("sessionId"));
    assert_eq!(peer.counters.dto_produced, 1);
    assert_eq!(peer.counters.bridge_conversions, 1);
    assert_eq!(peer.counters.catalog_mutations, 0);
    assert_eq!(peer.counters.schema_decode_attempts, 1);
    assert!(!elicitation_is_rejected("session/new"));
    assert!(elicitation_is_rejected("elicitation/create"));
}

#[test]
fn acp_transport_nested_mcp_vector_cap_and_outer_overflow() {
    let nested_ok = mcp_servers_of_size(ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1);
    assert_eq!(nested_ok.len(), ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1);
    let mut counters = AcpTransportCounters::default();
    let params = format!(r#"{{"cwd":"/tmp","mcpServers":{nested_ok}}}"#);
    let parsed = parse_frame(&params).unwrap();
    decode_session_new(&params, &parsed.root, &mut counters).unwrap();

    let nested_over = mcp_servers_of_size(ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1 + 1);
    let params = format!(r#"{{"cwd":"/tmp","mcpServers":{nested_over}}}"#);
    let parsed = parse_frame(&params).unwrap();
    let mut counters = AcpTransportCounters::default();
    let err = decode_session_new(&params, &parsed.root, &mut counters).unwrap_err();
    assert!(matches!(err, DtoError::McpVectorOverLimit { .. }));
    assert_eq!(counters.dto_produced, 0);

    let outer = wrap_session_new_with_pad(ACP_JSON_FRAME_MAX_BYTES_V1 + 1, &nested_ok);
    assert!(outer.len() > ACP_JSON_FRAME_MAX_BYTES_V1);
    assert!(matches!(
        super::codec::reject_non_acp_object(&outer, &mut AcpTransportCounters::default()),
        Ok(())
    ));
    let err = super::codec::prepare_outbound_json(&outer).unwrap_err();
    assert!(matches!(err, AcpFrameError::OverLimit { .. }));
}

#[test]
fn acp_transport_registry_entry_and_byte_caps() {
    let registry = OutboundPermissionRegistry::new();
    let mut sink = MemoryFrameSink::default();
    let mut counters = AcpTransportCounters::default();
    for i in 0..ACP_OUTBOUND_PERMISSION_MAX_ENTRIES_V1 {
        registry
            .issue_and_write(
                format!("att-{i}"),
                format!("d-{i}"),
                format!("a-{i}"),
                vec!["allow-once".into()],
                permission_params("s", &["allow-once"], "c"),
                &mut sink,
                &mut counters,
            )
            .unwrap();
    }
    assert_eq!(
        registry.charged_entries(),
        ACP_OUTBOUND_PERMISSION_MAX_ENTRIES_V1
    );
    let err = registry
        .issue_and_write(
            "att-extra".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut sink,
            &mut counters,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        RegistryError::OutboundRequestCapacityExhausted
    ));
    assert!(sink.frames.len() == ACP_OUTBOUND_PERMISSION_MAX_ENTRIES_V1);

    let registry = OutboundPermissionRegistry::new();
    let mut sink = MemoryFrameSink::default();
    let mut counters = AcpTransportCounters::default();
    let params = padded_permission_params(ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1);
    let err = registry.reserve_permission(
        "att".into(),
        "d".into(),
        "a".into(),
        vec!["allow-once".into()],
        params,
        &mut counters,
    );
    match err {
        Ok(reserved) => {
            assert!(reserved.frame.len() <= ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1);
        }
        Err(RegistryError::OutboundRequestCapacityExhausted) => {}
        other => panic!("{other:?}"),
    }

    let too_big = padded_permission_params(ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1 + 1);
    let err = registry
        .reserve_permission(
            "att2".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            too_big,
            &mut counters,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        RegistryError::OutboundRequestCapacityExhausted | RegistryError::WriterOverflow
    ));
    assert_eq!(sink.frames.len(), 0);
}

#[test]
fn acp_transport_registry_unique_ids_one_live_per_attachment_and_release() {
    let mut peer = peer();
    let first = peer
        .registry
        .issue_and_write(
            "same".into(),
            "d1".into(),
            "a1".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut peer.sink,
            &mut peer.counters,
        )
        .unwrap();
    let second = peer.registry.issue_and_write(
        "same".into(),
        "d2".into(),
        "a2".into(),
        vec!["allow-once".into()],
        permission_params("s", &["allow-once"], "c"),
        &mut peer.sink,
        &mut peer.counters,
    );
    assert!(matches!(second, Err(RegistryError::AttachmentAlreadyLive)));
    peer.registry
        .on_local_cancel(&first, &mut peer.sink, &mut peer.counters);
    assert_eq!(
        peer.registry.state_of(&first),
        Some(PermissionStateName::Released)
    );
    assert!(
        peer.sink
            .frames
            .iter()
            .any(|frame| frame.contains("$/cancel_request"))
    );
    let reused_attachment = peer
        .registry
        .issue_and_write(
            "same".into(),
            "d3".into(),
            "a3".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut peer.sink,
            &mut peer.counters,
        )
        .unwrap();
    assert_ne!(reused_attachment, first);
}

#[test]
fn acp_transport_registry_state_edges_and_exact_once_charge() {
    use PermissionStateName::*;
    let legal = [
        (Reserved, Issued, EdgeReason::FullWrite),
        (Reserved, Released, EdgeReason::IncompleteOutput),
        (Issued, TerminalReserved, EdgeReason::SelectedResponse),
        (Issued, Cancelling, EdgeReason::DaemonTerminal),
        (Cancelling, Released, EdgeReason::DaemonTerminal),
        (Issued, Released, EdgeReason::Disconnect),
        (TerminalReserved, Released, EdgeReason::Disconnect),
        (Resolving, Released, EdgeReason::Disconnect),
        (TerminalReserved, Resolving, EdgeReason::ResolveStart),
        (Resolving, Terminal, EdgeReason::DaemonOutcome),
        (Terminal, Released, EdgeReason::AckOrClose),
        (Issued, Released, EdgeReason::AcpCancelled),
    ];
    for (from, to, reason) in legal {
        assert!(
            OutboundPermissionRegistry::legal_edge(from, to, reason),
            "{from:?} -> {to:?} via {reason:?}"
        );
    }
    assert!(!OutboundPermissionRegistry::legal_edge(
        Released,
        Issued,
        EdgeReason::FullWrite
    ));

    let mut peer = peer();
    let id = peer
        .registry
        .issue_and_write(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut peer.sink,
            &mut peer.counters,
        )
        .unwrap();
    assert_eq!(peer.registry.charged_entries(), 1);
    send(
        &mut peer,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"cancelled"}}}}}}"#
        ),
    );
    assert_eq!(peer.registry.charged_entries(), 0);
    assert_eq!(peer.registry.charge_releases(), 1);
    assert_eq!(peer.resolve.calls.len(), 0);
    assert!(peer.ack.ids.is_empty());
}

#[test]
fn acp_transport_registry_partial_write_late_wrong_and_races() {
    let registry = OutboundPermissionRegistry::new();
    let mut sink = MemoryFrameSink {
        partial_next: Some(4),
        ..MemoryFrameSink::default()
    };
    let mut counters = AcpTransportCounters::default();
    let err = registry
        .issue_and_write(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut sink,
            &mut counters,
        )
        .unwrap_err();
    assert!(matches!(err, RegistryError::ConnectionClosed));
    assert!(sink.frames.is_empty());
    assert_eq!(registry.charged_entries(), 0);
    assert_eq!(counters.resolve_calls, 0);

    let mut peer = peer();
    let id = peer
        .registry
        .issue_and_write(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut peer.sink,
            &mut peer.counters,
        )
        .unwrap();
    send(
        &mut peer,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"nope"}}}}}}"#
        ),
    );
    assert_eq!(peer.resolve.calls.len(), 0);
    send(
        &mut peer,
        r#"{"jsonrpc":"2.0","id":"999","result":{"outcome":{"outcome":"selected","optionId":"allow-once"}}}"#,
    );
    assert_eq!(peer.resolve.calls.len(), 0);

    send(
        &mut peer,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once"}}}}}}"#
        ),
    );
    assert_eq!(peer.resolve.calls.len(), 1);
    send(
        &mut peer,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once"}}}}}}"#
        ),
    );
    assert_eq!(peer.resolve.calls.len(), 1);

    let mut peer = peer();
    let id = peer
        .registry
        .issue_and_write(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut peer.sink,
            &mut peer.counters,
        )
        .unwrap();
    peer.registry
        .on_daemon_terminal(&mut peer.sink, &mut peer.counters);
    send(
        &mut peer,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once"}}}}}}"#
        ),
    );
    assert_eq!(peer.resolve.calls.len(), 0);
    assert!(
        peer.sink
            .frames
            .iter()
            .any(|frame| frame.contains("$/cancel_request"))
    );
}

#[test]
fn acp_transport_registry_disconnect_during_resolve_and_typed_outcomes() {
    for outcome in [
        ResolveCodeRootInterruptResultV1::Accepted,
        ResolveCodeRootInterruptResultV1::AlreadyResolvedSame,
        ResolveCodeRootInterruptResultV1::AlreadyResolvedOther,
        ResolveCodeRootInterruptResultV1::Cancelled,
        ResolveCodeRootInterruptResultV1::Expired,
    ] {
        let mut peer = AcpAdapter::new(
            MemoryFrameSink::default(),
            RecordingResolve {
                next: Some(outcome),
                ..RecordingResolve::default()
            },
            RecordingAck::default(),
        );
        let id = peer
            .registry
            .issue_and_write(
                "att".into(),
                "d".into(),
                "a".into(),
                vec!["allow-once".into()],
                permission_params("s", &["allow-once"], "c"),
                &mut peer.sink,
                &mut peer.counters,
            )
            .unwrap();
        send(
            &mut peer,
            &format!(
                r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once"}}}}}}"#
            ),
        );
        assert_eq!(peer.resolve.calls.len(), 1);
        assert_eq!(peer.registry.daemon_outcome_of(&id), Some(outcome));
        match outcome {
            ResolveCodeRootInterruptResultV1::Accepted
            | ResolveCodeRootInterruptResultV1::AlreadyResolvedSame => {
                assert_eq!(peer.ack.ids.len(), 1);
            }
            _ => assert!(peer.ack.ids.is_empty()),
        }
        assert_eq!(peer.counters.resolve_calls, 1);
    }

    let mut peer = peer();
    let _id = peer
        .registry
        .issue_and_write(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut peer.sink,
            &mut peer.counters,
        )
        .unwrap();
    peer.disconnect();
    send(
        &mut peer,
        r#"{"jsonrpc":"2.0","id":"1","result":{"outcome":{"outcome":"selected","optionId":"allow-once"}}}"#,
    );
    assert_eq!(peer.resolve.calls.len(), 0);
    assert!(peer.ack.ids.is_empty());
}

#[test]
fn acp_transport_classify_request_notification_response() {
    assert!(matches!(
        classify(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#).unwrap(),
        InboundMessage::Request(_)
    ));
    assert!(matches!(
        classify(r#"{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s"}}"#)
            .unwrap(),
        InboundMessage::Notification(_)
    ));
    assert!(matches!(
        classify(r#"{"jsonrpc":"2.0","id":"1","result":{"outcome":{"outcome":"cancelled"}}}"#)
            .unwrap(),
        InboundMessage::Response(_)
    ));
    assert_eq!(
        JsonRpcId::String("1".into()).to_json(),
        serde_json::to_string("1").unwrap()
    );
}

fn mcp_servers_of_size(size: usize) -> String {
    let prefix = r#"[{"name":"x","command":""#;
    let suffix = r#"","args":[],"env":[]}]"#;
    let fixed = prefix.len() + suffix.len();
    assert!(size >= fixed);
    let pad = "a".repeat(size - fixed);
    let mut out = String::with_capacity(size);
    out.push_str(prefix);
    out.push_str(&pad);
    out.push_str(suffix);
    debug_assert_eq!(out.len(), size);
    out
}

fn wrap_session_new_with_pad(size: usize, mcp_servers: &str) -> String {
    let prefix = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"session/new","params":{{"cwd":"/t","mcpServers":{mcp_servers},"pad":""#
    );
    let suffix = "\"}}";
    let fixed = prefix.len() + suffix.len();
    let pad = if size > fixed {
        "b".repeat(size - fixed)
    } else {
        String::new()
    };
    format!("{prefix}{pad}{suffix}")
}

fn padded_permission_params(target_frame_bytes: usize) -> serde_json::Value {
    let baseline = super::envelope::request(
        "1",
        "session/request_permission",
        permission_params("s", &["allow-once"], "c"),
    );
    let extra = target_frame_bytes.saturating_sub(baseline.len());
    json!({
        "sessionId": "s",
        "options": [{ "optionId": "allow-once", "name": "allow-once", "kind": "allow_once" }],
        "toolCall": {
            "toolCallId": "c",
            "title": "x".repeat(extra),
            "kind": "other",
            "status": "pending"
        }
    })
}
