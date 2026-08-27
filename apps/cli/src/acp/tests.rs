use serde_json::json;

use super::AcpTransportCounters;
use super::adapter::{AcpAdapter, run_stdio_peer};
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
    ApprovalAck, EdgeReason, OutboundPermissionRegistry, PermissionStateName, RecordingAck,
    RecordingResolve, RegistryError, ResolveCodeRootInterrupt, permission_params,
};
use cockpit_proto::ResolveCodeRootInterruptResultV1;
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};

fn peer() -> AcpAdapter<MemoryFrameSink, RecordingResolve, RecordingAck> {
    AcpAdapter::new(
        MemoryFrameSink::default(),
        RecordingResolve::default(),
        RecordingAck::default(),
    )
}

struct BlockingResolve {
    started: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
}

impl ResolveCodeRootInterrupt for BlockingResolve {
    fn resolve(
        &mut self,
        _request: cockpit_proto::ResolveCodeRootInterruptV1,
    ) -> ResolveCodeRootInterruptResultV1 {
        self.started.send(()).unwrap();
        self.resume.recv().unwrap();
        ResolveCodeRootInterruptResultV1::Accepted
    }
}

struct AtomicAck(Arc<AtomicUsize>);

impl ApprovalAck for AtomicAck {
    fn ack_approval_delivery(&mut self, _delivery_id: &str) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
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
fn acp_transport_stdio_transcript_keeps_diagnostics_off_stdout() {
    let input = concat!(
        "not-json\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":1}}\n"
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    run_stdio_peer(
        Cursor::new(input.as_bytes()),
        &mut stdout,
        &mut stderr,
        RecordingResolve::default(),
        RecordingAck::default(),
    )
    .unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    let stderr = String::from_utf8(stderr).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    assert_jsonrpc_2_0(stdout.trim_end_matches('\n'));
    assert!(stdout.ends_with('\n'));
    assert!(!stdout.contains("acp:"));
    assert!(stderr.contains("acp:"));
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

#[test]
fn acp_transport_rejects_response_with_result_and_error_before_resolve() {
    let mut peer = peer();
    peer.registry
        .issue_and_write(
            "att".into(),
            "delivery".into(),
            "attention".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut peer.sink,
            &mut peer.counters,
        )
        .unwrap();
    send(
        &mut peer,
        r#"{"jsonrpc":"2.0","id":"1","result":{"outcome":{"outcome":"selected","optionId":"allow-once"}},"error":{"code":-32603,"message":"no"}}"#,
    );
    assert!(peer.resolve.calls.is_empty());
    assert!(peer.ack.ids.is_empty());
}

#[test]
fn acp_transport_explicit_null_id_is_a_request_with_a_response() {
    let mut peer = peer();
    let response = send(
        &mut peer,
        r#"{"jsonrpc":"2.0","id":null,"method":"initialize","params":{"protocolVersion":1}}"#,
    )
    .unwrap();
    assert!(response.contains("\"id\":null"));
    assert!(response.contains("\"result\""));
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
fn acp_transport_rejects_mixed_transport_fields_losslessly() {
    for frame in [
        r#"{"cwd":"/tmp","mcpServers":[{"type":"http","name":"x","url":"https://x","command":"/bin/mcp","args":[],"env":[],"headers":[]}]}"#,
        r#"{"cwd":"/tmp","mcpServers":[{"type":"stdio","name":"x","command":"/bin/mcp","args":[],"env":[],"url":"https://x","headers":[]}]}"#,
        r#"{"cwd":"/tmp","mcpServers":[{"type":false,"name":"x","command":"/bin/mcp","args":[],"env":[]}]}"#,
    ] {
        let parsed = parse_frame(frame).unwrap();
        let mut counters = AcpTransportCounters::default();
        let err = decode_session_new(frame, &parsed.root, &mut counters).unwrap_err();
        assert!(matches!(err, DtoError::MixedOrUnknownTransport));
        assert_eq!(counters.dto_produced, 0);
        assert_eq!(counters.schema_decode_attempts, 0);
    }
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
    let mut counters = AcpTransportCounters::default();
    let params = padded_permission_params(ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1);
    let reserved = registry
        .reserve_permission(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            params,
            &mut counters,
        )
        .unwrap();
    assert_eq!(
        reserved.frame.len(),
        ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1
    );
    assert_eq!(
        registry.charged_bytes(),
        ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1
    );

    let registry = OutboundPermissionRegistry::new();
    let too_big = padded_permission_params(ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1 + 1);
    let err = registry
        .reserve_permission(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            too_big,
            &mut counters,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        RegistryError::OutboundRequestCapacityExhausted
    ));
    assert_eq!(registry.charged_entries(), 0);
    assert_eq!(registry.charged_bytes(), 0);
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
    assert!(matches!(
        second,
        Err(RegistryError::OutboundRequestCapacityExhausted)
    ));
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
fn acp_transport_registry_rejects_option_set_not_present_on_wire() {
    let registry = OutboundPermissionRegistry::new();
    let mut counters = AcpTransportCounters::default();
    let err = registry
        .reserve_permission(
            "att".into(),
            "delivery".into(),
            "attention".into(),
            vec!["not-sent".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut counters,
        )
        .unwrap_err();
    assert!(matches!(err, RegistryError::InvalidIssuedOptions));
    assert_eq!(registry.charged_entries(), 0);
}

#[test]
fn acp_transport_registry_cancel_output_failure_closes_and_releases() {
    let registry = OutboundPermissionRegistry::new();
    let mut sink = MemoryFrameSink::default();
    let mut counters = AcpTransportCounters::default();
    let id = registry
        .issue_and_write(
            "att".into(),
            "delivery".into(),
            "attention".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut sink,
            &mut counters,
        )
        .unwrap();
    sink.partial_next = Some(4);
    registry.on_local_cancel(&id, &mut sink, &mut counters);
    assert!(registry.connection_closed());
    assert_eq!(registry.state_of(&id), Some(PermissionStateName::Released));
    assert_eq!(registry.charged_entries(), 0);
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
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once","unexpected":true}}}}}}"#
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
fn acp_transport_registry_disconnect_while_resolve_blocks_suppresses_ack() {
    let registry = Arc::new(OutboundPermissionRegistry::new());
    let mut sink = MemoryFrameSink::default();
    let mut counters = AcpTransportCounters::default();
    let id = registry
        .issue_and_write(
            "att".into(),
            "delivery".into(),
            "attention".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut sink,
            &mut counters,
        )
        .unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let ack_count = Arc::new(AtomicUsize::new(0));
    let worker_registry = Arc::clone(&registry);
    let worker_ack_count = Arc::clone(&ack_count);
    let worker_id = id.clone();
    let worker = std::thread::spawn(move || {
        let response = format!(
            r#"{{"jsonrpc":"2.0","id":"{worker_id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once"}}}}}}"#
        );
        let parsed = match classify(&response).unwrap() {
            InboundMessage::Response(response) => response,
            other => panic!("expected response, got {other:?}"),
        };
        let mut resolve = BlockingResolve {
            started: started_tx,
            resume: resume_rx,
        };
        let mut ack = AtomicAck(worker_ack_count);
        let mut sink = MemoryFrameSink::default();
        let mut counters = AcpTransportCounters::default();
        worker_registry.on_inbound_response(
            &parsed.id,
            parsed.result.as_ref(),
            &parsed.raw,
            &mut resolve,
            &mut ack,
            &mut sink,
            &mut counters,
        )
    });
    started_rx.recv().unwrap();
    registry.on_disconnect(&mut AcpTransportCounters::default());
    resume_tx.send(()).unwrap();
    assert!(!worker.join().unwrap());
    assert_eq!(ack_count.load(Ordering::SeqCst), 0);
    assert_eq!(registry.state_of(&id), Some(PermissionStateName::Released));
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
    let empty_title = json!({
        "sessionId": "s",
        "options": [{ "optionId": "allow-once", "name": "allow-once", "kind": "allow_once" }],
        "toolCall": {
            "toolCallId": "c",
            "title": "",
            "kind": "other",
            "status": "pending"
        }
    });
    let baseline = super::envelope::request("1", "session/request_permission", empty_title).len();
    assert!(target_frame_bytes >= baseline);
    let extra = target_frame_bytes - baseline;
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
