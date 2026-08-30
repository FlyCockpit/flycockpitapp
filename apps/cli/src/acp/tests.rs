use serde_json::json;

use super::AcpTransportCounters;
use super::adapter::{AcpAdapter, AcpPeerExitError, run_stdio_peer, run_stdio_peer_with_adapter};
use super::bridge::{BridgeFacade, SessionAdmissionReceipt};
use super::classify::{InboundMessage, classify};
use super::codec::{
    ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1, ACP_JSON_FRAME_MAX_BYTES_V1, AcpFrameError,
    AcpLineReader, MemoryFrameSink,
};
use super::dispatch::{
    DispatchResult, SessionIngress, SessionIngressError, build_rpc_module, dispatch_notification,
    elicitation_is_rejected, is_request_only_session_method, registered_method_names,
};
use super::dto::{DtoError, SessionAdmissionDto, decode_session_new};
use super::raw_json::{JsonRpcId, RawJsonErrorKind, parse_frame};
use super::registry::{
    ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1, ACP_OUTBOUND_PERMISSION_MAX_ENTRIES_V1,
    ApprovalAck, CancelTurnError, EdgeReason, OutboundPermissionRegistry, PermissionStateName,
    RecordingAck, RecordingResolve, RegistryError, ResolveCodeRootInterrupt, permission_params,
};
use cockpit_proto::ResolveCodeRootInterruptResultV1;
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};

fn peer() -> AcpAdapter<MemoryFrameSink, RecordingResolve, RecordingAck> {
    AcpAdapter::new(
        MemoryFrameSink::default(),
        RecordingResolve::default(),
        RecordingAck::default(),
    )
}

#[derive(Debug, Default)]
struct RecordingSessionIngress {
    admissions: Vec<SessionAdmissionReceipt>,
    cancel_calls: usize,
    list_params: Vec<String>,
}

impl SessionIngress for RecordingSessionIngress {
    fn is_available(&self) -> bool {
        true
    }

    fn admit(
        &mut self,
        admission: SessionAdmissionDto,
        counters: &mut AcpTransportCounters,
    ) -> Result<serde_json::Value, SessionIngressError> {
        let receipt = BridgeFacade
            .admit(&admission, counters)
            .map_err(|_| SessionIngressError::InvalidAdmission)?;
        let session_id = format!("recorded-session-{}", self.admissions.len() + 1);
        self.admissions.push(receipt);
        Ok(json!({ "sessionId": session_id }))
    }

    fn list(
        &mut self,
        raw_params: &str,
        _counters: &mut AcpTransportCounters,
    ) -> Result<serde_json::Value, SessionIngressError> {
        self.list_params.push(raw_params.to_string());
        Ok(json!({ "sessions": [] }))
    }

    fn cancel(
        &mut self,
        _raw_params: &str,
        _counters: &mut AcpTransportCounters,
    ) -> Result<serde_json::Value, SessionIngressError> {
        self.cancel_calls += 1;
        Ok(serde_json::Value::Null)
    }

    fn prompt(
        &mut self,
        _raw_params: &str,
        _counters: &mut AcpTransportCounters,
    ) -> Result<serde_json::Value, SessionIngressError> {
        Ok(json!({ "stopReason": "end_turn" }))
    }
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

    fn cancel_turn(
        &mut self,
        _attachment_capability: cockpit_proto::CodeRootAttachmentCapabilityV1,
    ) -> Result<(), CancelTurnError> {
        Ok(())
    }
}

struct AtomicAck(Arc<AtomicUsize>);

impl ApprovalAck for AtomicAck {
    fn ack_approval_delivery(&mut self, _delivery_id: &str) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct BrokenReader;

impl Read for BrokenReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("simulated stdin failure"))
    }
}

fn assert_jsonrpc_2_0(frame: &str) {
    assert!(
        frame.contains("\"jsonrpc\":\"2.0\""),
        "frame missing exact jsonrpc 2.0: {frame}"
    );
}

fn assert_no_transport_mutation(counters: &AcpTransportCounters) {
    assert!(counters.zero_side_effects());
    assert_eq!(counters.daemon_mutations, 0);
    assert_eq!(counters.bridge_conversions, 0);
    assert_eq!(counters.catalog_mutations, 0);
    assert_eq!(counters.dto_produced, 0);
    assert_eq!(counters.schema_decode_attempts, 0);
    assert_eq!(counters.resolve_calls, 0);
    assert_eq!(counters.approval_acks, 0);
    assert_eq!(counters.cancel_notifications_queued, 0);
    assert_eq!(counters.stdout_non_protocol_writes, 0);
}

fn send<I: SessionIngress + 'static>(
    adapter: &mut AcpAdapter<MemoryFrameSink, RecordingResolve, RecordingAck, I>,
    json: &str,
) -> Option<String> {
    let response = adapter.handle_frame(json);
    if let Some(frame) = &response {
        assert_jsonrpc_2_0(frame);
        adapter.write_protocol(frame).unwrap();
    }
    response
}

fn session_new_ok() -> String {
    r#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":"/tmp/project","mcpServers":[{"name":"workspace-tools","command":"/bin/mcp","args":["--stdio"],"env":[]}]}}"#.to_string()
}

#[test]
fn acp_transport_initialize_capability_serialization() {
    let mut adapter = peer();
    let response = send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":1}}"#,
    )
    .unwrap();
    assert_jsonrpc_2_0(&response);
    assert!(response.contains("\"protocolVersion\":1"));
    assert!(response.contains("\"loadSession\":true"));
    assert!(response.contains("\"sessionCapabilities\""));
    let result = serde_json::from_str::<serde_json::Value>(&response)
        .unwrap()
        .get("result")
        .cloned()
        .unwrap();
    assert_eq!(
        result
            .get("agentCapabilities")
            .and_then(|capabilities| capabilities.get("sessionCapabilities"))
            .and_then(|capabilities| capabilities.get("list")),
        Some(&json!({}))
    );
    assert!(result.get("sessionCapabilities").is_none());
    assert!(!response.contains("promptCapabilities"));
    assert!(!response.contains("mcpCapabilities"));
    assert!(!response.contains("elicitation"));
    let _module = build_rpc_module();
    assert_eq!(
        registered_method_names(),
        [
            "initialize",
            "session/list",
            "session/new",
            "session/load",
            "session/cancel",
            "session/prompt"
        ]
    );
}

#[test]
fn acp_transport_initialize_requires_a_positive_protocol_version() {
    for params in [
        "{}",
        "[]",
        r#"{"protocolVersion":0}"#,
        r#"{"protocolVersion":"1"}"#,
    ] {
        let mut adapter = peer();
        let response = send(
            &mut adapter,
            &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{params}}}"#),
        )
        .expect("malformed initialization receives an error");
        assert!(response.contains("\"code\":-32602"));
        assert_no_transport_mutation(&adapter.counters);
    }
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
fn acp_transport_stdio_reader_io_is_terminal() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let err = run_stdio_peer(
        BrokenReader,
        &mut stdout,
        &mut stderr,
        RecordingResolve::default(),
        RecordingAck::default(),
    )
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("simulated stdin failure")
    );
}

#[test]
fn acp_transport_stdio_lsp_content_length_framing_is_terminal_without_body_response() {
    let input = concat!(
        "Content-Length: 65\r\n\r\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n"
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let err = run_stdio_peer(
        Cursor::new(input.as_bytes()),
        &mut stdout,
        &mut stderr,
        RecordingResolve::default(),
        RecordingAck::default(),
    )
    .unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("Content-Length/LSP framing")
    );
}

#[test]
fn acp_transport_stdio_closed_permission_refusal_is_a_typed_error() {
    for outcome in [
        ResolveCodeRootInterruptResultV1::AlreadyResolvedOther,
        ResolveCodeRootInterruptResultV1::Cancelled,
        ResolveCodeRootInterruptResultV1::Expired,
    ] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let ack_count = Arc::new(AtomicUsize::new(0));
        let mut adapter = AcpAdapter::new(
            super::codec::AcpLineWriter::new(&mut stdout),
            RecordingResolve {
                next: Some(outcome),
                ..RecordingResolve::default()
            },
            AtomicAck(Arc::clone(&ack_count)),
        );
        let request_id = adapter
            .registry
            .issue_and_write(
                "attachment".into(),
                "delivery".into(),
                "attention".into(),
                vec!["allow-once".into()],
                permission_params("session", &["allow-once"], "call"),
                &mut adapter.sink,
                &mut adapter.counters,
            )
            .unwrap();
        let transcript = format!(
            r#"{{"jsonrpc":"2.0","id":"{request_id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once"}}}}}}"#
        ) + "\n";

        let error =
            run_stdio_peer_with_adapter(Cursor::new(transcript.into_bytes()), &mut stderr, adapter)
                .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        let exit = error
            .into_inner()
            .and_then(|source| source.downcast::<AcpPeerExitError>().ok())
            .expect("closed refusal has its typed exit error");
        assert_eq!(*exit, AcpPeerExitError::ClosedPermissionRefusal(outcome));
        assert_eq!(ack_count.load(Ordering::SeqCst), 0);

        let stdout = String::from_utf8(stdout).unwrap();
        assert_eq!(stdout.lines().count(), 1);
        assert!(stdout.contains("session/request_permission"));
        assert!(!stdout.contains("\"result\""));
        assert!(stderr.is_empty());
    }
}

#[test]
fn acp_transport_stdio_cancelled_permission_without_daemon_settlement_is_a_typed_error() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut adapter = AcpAdapter::new(
        super::codec::AcpLineWriter::new(&mut stdout),
        RecordingResolve {
            cancel_next: Some(CancelTurnError::Unavailable),
            ..RecordingResolve::default()
        },
        RecordingAck::default(),
    );
    let request_id = adapter
        .registry
        .issue_and_write(
            "attachment".into(),
            "delivery".into(),
            "attention".into(),
            vec!["allow-once".into()],
            permission_params("session", &["allow-once"], "call"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    let transcript = format!(
        r#"{{"jsonrpc":"2.0","id":"{request_id}","result":{{"outcome":{{"outcome":"cancelled"}}}}}}"#
    ) + "\n";

    let error =
        run_stdio_peer_with_adapter(Cursor::new(transcript.into_bytes()), &mut stderr, adapter)
            .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    let exit = error
        .into_inner()
        .and_then(|source| source.downcast::<AcpPeerExitError>().ok())
        .expect("failed cancellation has its typed exit error");
    assert_eq!(*exit, AcpPeerExitError::PermissionCancellationFailed);
    assert!(stderr.is_empty());
}

#[test]
fn acp_transport_client_cancellation_and_agent_to_client() {
    let mut adapter = peer();
    send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s1"}}"#,
    );
    assert!(adapter.connection_closed);
    assert_no_transport_mutation(&adapter.counters);
    assert_eq!(adapter.counters.frames_rejected, 1);

    let mut adapter = peer();

    let id = adapter
        .registry
        .issue_and_write(
            "att-1".into(),
            "delivery-1".into(),
            "attention-1".into(),
            vec!["allow-once".into()],
            permission_params("s1", &["allow-once"], "call-1"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    assert_eq!(id, "1");
    let outbound = adapter.sink.frames.last().unwrap();
    assert_jsonrpc_2_0(outbound);
    assert!(outbound.contains("session/request_permission"));
    assert_eq!(
        adapter.registry.state_of("1"),
        Some(PermissionStateName::Issued)
    );
}

#[test]
fn acp_transport_session_methods_fail_closed_without_an_ingress_owner() {
    for frame in [
        session_new_ok(),
        r#"{"jsonrpc":"2.0","id":2,"method":"session/load","params":{"cwd":"/tmp/project","sessionId":"s1","mcpServers":[]}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":3,"method":"session/cancel","params":{"sessionId":"s1"}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":4,"method":"session/prompt","params":{"sessionId":"s1","prompt":[{"type":"text","text":"hello"}]}}"#.to_string(),
    ] {
        let mut adapter = peer();
        let response = send(&mut adapter, &frame).unwrap();
        assert!(response.contains("\"code\":-32601"));
        assert!(response.contains("ACP session adaptation is unavailable"));
        assert_no_transport_mutation(&adapter.counters);
    }
}

#[test]
fn acp_transport_session_list_preserves_an_absent_cwd_filter() {
    let mut adapter = AcpAdapter::new_with_session_ingress(
        MemoryFrameSink::default(),
        RecordingResolve::default(),
        RecordingAck::default(),
        RecordingSessionIngress::default(),
    );
    let response = send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","id":1,"method":"session/list","params":{}}"#,
    )
    .unwrap();
    assert!(response.contains("\"sessions\":[]"));
    assert_eq!(
        adapter
            .session_ingress
            .lock()
            .unwrap()
            .list_params
            .as_slice(),
        ["{}".to_string()]
    );
}

#[test]
fn acp_transport_rejects_scalar_or_null_params_before_routing() {
    for params in ["null", "true", "1", "\"scalar\""] {
        let mut adapter = peer();
        let response = send(
            &mut adapter,
            &format!(r#"{{"jsonrpc":"2.0","id":1,"method":"session/new","params":{params}}}"#),
        )
        .unwrap();
        assert!(response.contains("\"code\":-32600"));
        assert_no_transport_mutation(&adapter.counters);
        assert_eq!(adapter.counters.frames_rejected, 1);
    }

    assert!(matches!(
        classify(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":[]}"#),
        Ok(InboundMessage::Request(_))
    ));

    let mut adapter = peer();
    adapter
        .registry
        .issue_and_write(
            "att".into(),
            "delivery".into(),
            "attention".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","id":"1","result":{"outcome":{"outcome":"selected","optionId":"allow-once"}},"params":null}"#,
    );
    assert_eq!(adapter.resolve.calls.len(), 0);
    assert!(adapter.ack.ids.is_empty());
    assert_eq!(
        adapter.registry.state_of("1"),
        Some(PermissionStateName::Issued)
    );
}

#[test]
fn acp_transport_response_id_routing_and_malformed_errors() {
    let mut adapter = peer();
    adapter
        .registry
        .issue_and_write(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","id":"1","result":{"outcome":{"outcome":"selected","optionId":"allow-once"}}}"#,
    );
    assert_eq!(adapter.resolve.calls.len(), 1);
    assert_eq!(adapter.ack.ids, ["d"]);
    assert_eq!(
        adapter.registry.daemon_outcome_of("1"),
        Some(ResolveCodeRootInterruptResultV1::Accepted)
    );

    let mut adapter = peer();
    let err = send(
        &mut adapter,
        r#"{"jsonrpc":"1.0","id":9,"method":"initialize"}"#,
    )
    .unwrap();
    assert!(err.contains("\"code\":-32600"));
    let missing = send(&mut adapter, r#"{"jsonrpc":"2.0","id":9,"method":"nope"}"#).unwrap();
    assert!(missing.contains("\"code\":-32601"));
    assert_no_transport_mutation(&adapter.counters);
    assert_eq!(adapter.counters.frames_rejected, 1);
}

#[test]
fn acp_transport_rejects_wrong_or_duplicate_jsonrpc_before_routing() {
    let mut adapter = peer();
    assert!(send(&mut adapter, r#"{"id":1,"method":"initialize"}"#).is_some());
    assert_no_transport_mutation(&adapter.counters);
    let dup = send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"initialize"}"#,
    );
    assert!(dup.unwrap().contains("-32600"));
    assert_no_transport_mutation(&adapter.counters);
    assert_eq!(adapter.counters.frames_rejected, 2);
}

#[test]
fn acp_transport_duplicate_member_response_uses_only_a_later_unique_root_id() {
    let mut adapter = peer();
    let response = send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","method":"session/new","params":{"cwd":"/a","cwd":"/b","mcpServers":[]},"id":7}"#,
    )
    .expect("unique root id remains available after a nested duplicate");
    assert!(response.contains("\"code\":-32600"));
    assert!(response.contains("\"id\":7"));
    assert_no_transport_mutation(&adapter.counters);

    let response = send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","id":7,"method":"initialize","id":8}"#,
    );
    assert!(response.is_none(), "duplicate root id is ambiguous");
    assert_no_transport_mutation(&adapter.counters);
}

#[test]
fn acp_transport_rejects_response_with_result_and_error_before_resolve() {
    let mut adapter = peer();
    adapter
        .registry
        .issue_and_write(
            "att".into(),
            "delivery".into(),
            "attention".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","id":"1","result":{"outcome":{"outcome":"selected","optionId":"allow-once"}},"error":{"code":-32603,"message":"no"}}"#,
    );
    assert!(adapter.resolve.calls.is_empty());
    assert!(adapter.ack.ids.is_empty());
    assert_eq!(adapter.counters.resolve_calls, 0);
    assert_eq!(adapter.counters.approval_acks, 0);
}

#[test]
fn acp_transport_explicit_null_id_is_a_request_with_a_response() {
    let mut adapter = peer();
    let response = send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","id":null,"method":"initialize","params":{"protocolVersion":1}}"#,
    )
    .unwrap();
    assert!(response.contains("\"id\":null"));
    assert!(response.contains("\"result\""));
}

fn duplicate_rejected(frame: &str, expected_name: &str) {
    let mut adapter = peer();
    let response = send(&mut adapter, frame);
    if let Some(frame) = response {
        assert!(frame.contains("-32600"));
        assert_jsonrpc_2_0(&frame);
    }
    assert_no_transport_mutation(&adapter.counters);
    assert_eq!(adapter.counters.frames_rejected, 1);
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
fn acp_transport_session_new_bridge_conversion_requires_explicit_recording_ingress() {
    let mut adapter = AcpAdapter::new_with_session_ingress(
        MemoryFrameSink::default(),
        RecordingResolve::default(),
        RecordingAck::default(),
        RecordingSessionIngress::default(),
    );
    let response = send(&mut adapter, &session_new_ok()).unwrap();
    assert_jsonrpc_2_0(&response);
    assert!(response.contains("recorded-session-1"));
    assert_eq!(adapter.counters.dto_produced, 1);
    assert_eq!(adapter.counters.bridge_conversions, 1);
    assert_eq!(adapter.counters.catalog_mutations, 0);
    assert_eq!(adapter.counters.schema_decode_attempts, 1);
    let load_response = send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","id":2,"method":"session/load","params":{"cwd":"/tmp/project","sessionId":"s1","mcpServers":[]}}"#,
    )
    .unwrap();
    assert!(load_response.contains("recorded-session-2"));
    assert_eq!(adapter.counters.dto_produced, 2);
    assert_eq!(adapter.counters.bridge_conversions, 2);
    assert_eq!(adapter.counters.schema_decode_attempts, 2);
    let ingress = adapter.session_ingress.lock().unwrap();
    assert_eq!(ingress.admissions.len(), 2);
    assert_eq!(ingress.admissions[0].server_count, 1);
    assert_eq!(ingress.admissions[0].ingress.declarations.len(), 1);
    assert_eq!(ingress.admissions[1].server_count, 0);
    assert!(
        ingress.admissions[1]
            .ingress
            .client_provenance_id
            .as_str()
            .starts_with("load-")
    );
    assert!(!elicitation_is_rejected("session/new"));
    assert!(elicitation_is_rejected("elicitation/create"));
    assert!(is_request_only_session_method("session/new"));
    assert!(is_request_only_session_method("session/load"));
    assert!(is_request_only_session_method("session/prompt"));
    assert!(!is_request_only_session_method("session/cancel"));
}

#[test]
fn acp_transport_bridge_rejects_proto_invalid_dto_without_counting_or_admitting() {
    let servers = (0..33)
        .map(|index| {
            json!({
                "name": format!("server-{index}"),
                "command": "/bin/mcp",
                "args": [],
                "env": []
            })
        })
        .collect::<Vec<_>>();
    let frame = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "session/new",
        "params": { "cwd": "/tmp/project", "mcpServers": servers }
    }))
    .unwrap();
    let mut adapter = AcpAdapter::new_with_session_ingress(
        MemoryFrameSink::default(),
        RecordingResolve::default(),
        RecordingAck::default(),
        RecordingSessionIngress::default(),
    );

    let response = send(&mut adapter, &frame).expect("invalid admission receives an error");

    assert!(response.contains("ACP session admission is invalid"));
    assert_eq!(adapter.counters.dto_produced, 1);
    assert_eq!(adapter.counters.schema_decode_attempts, 1);
    assert_eq!(adapter.counters.bridge_conversions, 0);
    assert!(
        adapter
            .session_ingress
            .lock()
            .unwrap()
            .admissions
            .is_empty()
    );
}

#[test]
fn acp_transport_session_admission_rejects_notification_sibling() {
    for method in ["session/new", "session/load", "session/prompt"] {
        let mut adapter = AcpAdapter::new_with_session_ingress(
            MemoryFrameSink::default(),
            RecordingResolve::default(),
            RecordingAck::default(),
            RecordingSessionIngress::default(),
        );
        let params = if method == "session/load" {
            r#"{"cwd":"/tmp/project","sessionId":"s1","mcpServers":[]}"#
        } else if method == "session/prompt" {
            r#"{"sessionId":"s1","prompt":[{"type":"text","text":"hello"}]}"#
        } else {
            r#"{"cwd":"/tmp/project","mcpServers":[]}"#
        };
        let frame = format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":{params}}}"#);
        let response = send(&mut adapter, &frame);
        assert!(response.is_none(), "{method} notification must not reply");
        assert!(
            adapter
                .session_ingress
                .lock()
                .unwrap()
                .admissions
                .is_empty(),
            "{method} notification must not admit"
        );
        assert_eq!(adapter.session_ingress.lock().unwrap().cancel_calls, 0);
        assert_eq!(adapter.counters.dto_produced, 0);
        assert_eq!(adapter.counters.bridge_conversions, 0);
        assert_eq!(adapter.counters.schema_decode_attempts, 0);
        assert_eq!(adapter.counters.frames_rejected, 1);
        assert!(adapter.connection_closed);

        let ingress = Arc::new(Mutex::new(RecordingSessionIngress::default()));
        let mut counters = AcpTransportCounters::default();
        let result = dispatch_notification(method, &frame, Arc::clone(&ingress), &mut counters);
        assert!(matches!(result, DispatchResult::NoResponse));
        assert!(ingress.lock().unwrap().admissions.is_empty());
        assert_eq!(ingress.lock().unwrap().cancel_calls, 0);
        assert_eq!(counters.dto_produced, 0);
        assert_eq!(counters.bridge_conversions, 0);
        assert_eq!(counters.schema_decode_attempts, 0);
    }

    let mut adapter = AcpAdapter::new_with_session_ingress(
        MemoryFrameSink::default(),
        RecordingResolve::default(),
        RecordingAck::default(),
        RecordingSessionIngress::default(),
    );
    let response = send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s1"}}"#,
    );
    assert!(response.is_none());
    assert!(
        adapter
            .session_ingress
            .lock()
            .unwrap()
            .admissions
            .is_empty()
    );
    assert_eq!(adapter.session_ingress.lock().unwrap().cancel_calls, 1);
    assert!(!adapter.connection_closed);
}

#[test]
fn acp_transport_nested_mcp_vector_cap_and_outer_overflow() {
    let nested_ok = mcp_servers_of_size(ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1);
    assert_eq!(nested_ok.len(), ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1);
    let mut counters = AcpTransportCounters::default();
    let params = format!(r#"{{"cwd":"/tmp","mcpServers":{nested_ok}}}"#);
    let parsed = parse_frame(&params).unwrap();
    decode_session_new(&params, &parsed.root, &mut counters).unwrap();

    let outer_at_limit = wrap_session_new_with_pad(ACP_JSON_FRAME_MAX_BYTES_V1, &nested_ok);
    assert_eq!(outer_at_limit.len(), ACP_JSON_FRAME_MAX_BYTES_V1);
    let mut transcript = outer_at_limit.as_bytes().to_vec();
    transcript.push(b'\n');
    let mut reader = AcpLineReader::new(Cursor::new(transcript));
    let accepted = reader
        .read_frame(&mut AcpTransportCounters::default())
        .unwrap()
        .unwrap();
    assert_eq!(accepted.byte_len(), ACP_JSON_FRAME_MAX_BYTES_V1);

    let nested_over = mcp_servers_of_size(ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1 + 1);
    let params = format!(r#"{{"cwd":"/tmp","mcpServers":{nested_over}}}"#);
    let parsed = parse_frame(&params).unwrap();
    let mut counters = AcpTransportCounters::default();
    let err = decode_session_new(&params, &parsed.root, &mut counters).unwrap_err();
    assert!(matches!(err, DtoError::McpVectorOverLimit { .. }));
    assert_eq!(counters.dto_produced, 0);

    let outer = wrap_session_new_with_pad(ACP_JSON_FRAME_MAX_BYTES_V1 + 1, &nested_ok);
    assert_eq!(outer.len(), ACP_JSON_FRAME_MAX_BYTES_V1 + 1);
    let mut transcript = outer.as_bytes().to_vec();
    transcript.push(b'\n');
    let mut reader = AcpLineReader::new(Cursor::new(transcript));
    assert!(matches!(
        reader
            .read_frame(&mut AcpTransportCounters::default())
            .unwrap_err(),
        AcpFrameError::OverLimit { .. }
    ));
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
    let diagnostics = registry.diagnostics_of(&reserved.request_id).unwrap();
    assert_eq!(diagnostics.request_id, reserved.request_id);
    assert_eq!(diagnostics.attention_id, "a");
    assert_eq!(diagnostics.state, PermissionStateName::Reserved);
    assert_eq!(diagnostics.frame_bytes, reserved.frame.len());
    assert_eq!(diagnostics.charge, reserved.frame.len());

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
    let mut adapter = peer();
    let first = adapter
        .registry
        .issue_and_write(
            "same".into(),
            "d1".into(),
            "a1".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    let second = adapter.registry.issue_and_write(
        "same".into(),
        "d2".into(),
        "a2".into(),
        vec!["allow-once".into()],
        permission_params("s", &["allow-once"], "c"),
        &mut adapter.sink,
        &mut adapter.counters,
    );
    assert!(matches!(
        second,
        Err(RegistryError::OutboundRequestCapacityExhausted)
    ));
    adapter
        .registry
        .on_local_cancel(&first, &mut adapter.sink, &mut adapter.counters);
    assert_eq!(
        adapter.registry.state_of(&first),
        Some(PermissionStateName::Released)
    );
    assert!(
        adapter
            .sink
            .frames
            .iter()
            .any(|frame| frame.contains("$/cancel_request"))
    );
    let reused_attachment = adapter
        .registry
        .issue_and_write(
            "same".into(),
            "d3".into(),
            "a3".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
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
    let allowed = [
        (Reserved, Issued, EdgeReason::FullWrite),
        (Reserved, Released, EdgeReason::IncompleteOutput),
        (Issued, TerminalReserved, EdgeReason::SelectedResponse),
        (Issued, Cancelling, EdgeReason::DaemonTerminal),
        (Cancelling, Released, EdgeReason::DaemonTerminal),
        (Issued, Released, EdgeReason::DaemonTerminal),
        (Reserved, Released, EdgeReason::Disconnect),
        (Cancelling, Released, EdgeReason::Disconnect),
        (Issued, Released, EdgeReason::Disconnect),
        (TerminalReserved, Released, EdgeReason::Disconnect),
        (Resolving, Released, EdgeReason::Disconnect),
        (TerminalReserved, Resolving, EdgeReason::ResolveStart),
        (Resolving, Terminal, EdgeReason::DaemonOutcome),
        (Terminal, Released, EdgeReason::AckOrClose),
        (Issued, Cancelling, EdgeReason::AcpCancelled),
        (Cancelling, Released, EdgeReason::AcpCancelled),
    ];
    let states = [
        Reserved,
        Issued,
        TerminalReserved,
        Resolving,
        Terminal,
        Released,
        Cancelling,
    ];
    let reasons = [
        EdgeReason::FullWrite,
        EdgeReason::IncompleteOutput,
        EdgeReason::SelectedResponse,
        EdgeReason::DaemonTerminal,
        EdgeReason::Disconnect,
        EdgeReason::ResolveStart,
        EdgeReason::DaemonOutcome,
        EdgeReason::AckOrClose,
        EdgeReason::AcpCancelled,
    ];
    for from in states {
        for to in states {
            for reason in reasons {
                let expected = allowed.contains(&(from, to, reason));
                assert_eq!(
                    OutboundPermissionRegistry::legal_edge(from, to, reason),
                    expected,
                    "{from:?} -> {to:?} via {reason:?}"
                );
            }
        }
    }

    let mut adapter = peer();
    let id = adapter
        .registry
        .issue_and_write(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    assert_eq!(adapter.registry.state_of(&id), Some(Issued));
    assert_eq!(adapter.registry.charged_entries(), 1);
    assert!(
        !adapter
            .registry
            .try_apply_edge(&id, Terminal, EdgeReason::FullWrite)
    );
    assert!(
        !adapter
            .registry
            .try_apply_edge(&id, Released, EdgeReason::IncompleteOutput)
    );
    assert_eq!(adapter.registry.state_of(&id), Some(Issued));
    assert_eq!(adapter.registry.charged_entries(), 1);
    send(
        &mut adapter,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"cancelled"}}}}}}"#
        ),
    );
    assert_eq!(adapter.registry.state_of(&id), Some(Released));
    assert_eq!(adapter.registry.charged_entries(), 0);
    assert_eq!(adapter.registry.charge_releases(), 1);
    assert_eq!(adapter.resolve.calls.len(), 0);
    assert_eq!(
        adapter
            .resolve
            .cancelled_attachments
            .iter()
            .map(|attachment| attachment.expose_opaque())
            .collect::<Vec<_>>(),
        vec!["att"]
    );
    assert!(adapter.ack.ids.is_empty());
    send(
        &mut adapter,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"cancelled"}}}}}}"#
        ),
    );
    assert_eq!(adapter.resolve.cancelled_attachments.len(), 1);
    assert_eq!(adapter.registry.charge_releases(), 1);

    let mut adapter = peer();
    let id = adapter
        .registry
        .issue_and_write(
            "att-term".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    assert!(
        adapter
            .registry
            .try_apply_edge(&id, Released, EdgeReason::DaemonTerminal)
    );
    assert_eq!(adapter.registry.state_of(&id), Some(Released));
    assert_eq!(adapter.registry.charged_entries(), 0);
    assert_eq!(adapter.registry.charge_releases(), 1);
    assert_eq!(adapter.resolve.calls.len(), 0);

    let mut adapter = peer();
    let id = adapter
        .registry
        .issue_and_write(
            "att-disc".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    adapter.disconnect();
    assert_eq!(adapter.registry.state_of(&id), Some(Released));
    assert_eq!(adapter.registry.charged_entries(), 0);
    assert_eq!(adapter.resolve.calls.len(), 0);

    let mut adapter = peer();
    let id = adapter
        .registry
        .issue_and_write(
            "att-daemon".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    adapter
        .registry
        .on_daemon_terminal(&mut adapter.sink, &mut adapter.counters);
    assert_eq!(adapter.registry.state_of(&id), Some(Released));
    assert_eq!(adapter.registry.charged_entries(), 0);
    assert_eq!(adapter.counters.cancel_notifications_queued, 1);
    assert!(
        adapter
            .sink
            .frames
            .iter()
            .any(|frame| frame.contains("$/cancel_request"))
    );

    let mut adapter = peer();
    let ended = adapter
        .registry
        .issue_and_write(
            "att-ended".into(),
            "d-ended".into(),
            "a-ended".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    let live = adapter
        .registry
        .issue_and_write(
            "att-live".into(),
            "d-live".into(),
            "a-live".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    adapter.registry.on_daemon_terminal_for_attachment(
        Some("att-ended"),
        &mut adapter.sink,
        &mut adapter.counters,
    );
    assert_eq!(adapter.registry.state_of(&ended), Some(Released));
    assert_eq!(
        adapter.registry.state_of(&live),
        Some(PermissionStateName::Issued)
    );
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

    let mut adapter = peer();
    let id = adapter
        .registry
        .issue_and_write(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    send(
        &mut adapter,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"nope"}}}}}}"#
        ),
    );
    assert_eq!(adapter.resolve.calls.len(), 0);

    send(
        &mut adapter,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once","unexpected":true}}}}}}"#
        ),
    );
    assert_eq!(adapter.resolve.calls.len(), 0);
    send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","id":"999","result":{"outcome":{"outcome":"selected","optionId":"allow-once"}}}"#,
    );
    assert_eq!(adapter.resolve.calls.len(), 0);

    send(
        &mut adapter,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once"}}}}}}"#
        ),
    );
    assert_eq!(adapter.resolve.calls.len(), 1);
    send(
        &mut adapter,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once"}}}}}}"#
        ),
    );
    assert_eq!(adapter.resolve.calls.len(), 1);

    let mut adapter = peer();
    let id = adapter
        .registry
        .issue_and_write(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    adapter
        .registry
        .on_daemon_terminal(&mut adapter.sink, &mut adapter.counters);
    send(
        &mut adapter,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once"}}}}}}"#
        ),
    );
    assert_eq!(adapter.resolve.calls.len(), 0);
    assert!(
        adapter
            .sink
            .frames
            .iter()
            .any(|frame| frame.contains("$/cancel_request"))
    );
}

#[test]
fn acp_transport_cancelled_permission_fails_closed_when_daemon_cancel_is_unavailable() {
    let mut adapter = peer();
    let id = adapter
        .registry
        .issue_and_write(
            "att-cancel-fails".into(),
            "delivery-cancel-fails".into(),
            "attention-cancel-fails".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    adapter.resolve.cancel_next = Some(CancelTurnError::Unavailable);

    send(
        &mut adapter,
        &format!(
            r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"cancelled"}}}}}}"#
        ),
    );

    assert!(adapter.connection_closed);
    assert!(adapter.registry.connection_closed());
    assert_eq!(
        adapter.registry.state_of(&id),
        Some(PermissionStateName::Released)
    );
    assert_eq!(adapter.resolve.calls.len(), 0);
    assert_eq!(adapter.resolve.cancelled_attachments.len(), 1);
    assert!(adapter.ack.ids.is_empty());
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
        let mut adapter = AcpAdapter::new(
            MemoryFrameSink::default(),
            RecordingResolve {
                next: Some(outcome),
                ..RecordingResolve::default()
            },
            RecordingAck::default(),
        );
        let id = adapter
            .registry
            .issue_and_write(
                "att".into(),
                "d".into(),
                "a".into(),
                vec!["allow-once".into()],
                permission_params("s", &["allow-once"], "c"),
                &mut adapter.sink,
                &mut adapter.counters,
            )
            .unwrap();
        send(
            &mut adapter,
            &format!(
                r#"{{"jsonrpc":"2.0","id":"{id}","result":{{"outcome":{{"outcome":"selected","optionId":"allow-once"}}}}}}"#
            ),
        );
        assert_eq!(adapter.resolve.calls.len(), 1);
        assert_eq!(adapter.registry.daemon_outcome_of(&id), Some(outcome));
        match outcome {
            ResolveCodeRootInterruptResultV1::Accepted
            | ResolveCodeRootInterruptResultV1::AlreadyResolvedSame => {
                assert_eq!(adapter.ack.ids.len(), 1);
            }
            _ => assert!(adapter.ack.ids.is_empty()),
        }
        assert_eq!(adapter.counters.resolve_calls, 1);
    }

    let mut adapter = peer();
    let _id = adapter
        .registry
        .issue_and_write(
            "att".into(),
            "d".into(),
            "a".into(),
            vec!["allow-once".into()],
            permission_params("s", &["allow-once"], "c"),
            &mut adapter.sink,
            &mut adapter.counters,
        )
        .unwrap();
    adapter.disconnect();
    send(
        &mut adapter,
        r#"{"jsonrpc":"2.0","id":"1","result":{"outcome":{"outcome":"selected","optionId":"allow-once"}}}"#,
    );
    assert_eq!(adapter.resolve.calls.len(), 0);
    assert!(adapter.ack.ids.is_empty());
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
    assert_eq!(registry.state_of(&id), Some(PermissionStateName::Resolving));
    let diagnostics = registry.diagnostics_of(&id).unwrap();
    assert_eq!(diagnostics.selected_choice.as_deref(), Some("allow-once"));
    registry.on_disconnect(&mut AcpTransportCounters::default());
    resume_tx.send(()).unwrap();
    assert!(worker.join().unwrap().is_ok());
    assert_eq!(ack_count.load(Ordering::SeqCst), 0);
    assert_eq!(registry.state_of(&id), Some(PermissionStateName::Released));
    assert_eq!(
        registry
            .diagnostics_of(&id)
            .and_then(|diagnostics| diagnostics.selected_choice),
        Some("allow-once".into())
    );
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
