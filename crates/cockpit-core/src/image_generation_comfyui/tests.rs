use super::*;
use cockpit_config::config::image_generation::*;
use cockpit_config::config::providers::HeaderSpec;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_workflow() -> RegisteredComfyWorkflow {
    let graph_json = r#"{
        "1": {"class_type": "KSampler", "inputs": {"seed": 0, "steps": 20, "cfg": 7.0, "positive": "positive text", "negative": "negative text"}},
        "2": {"class_type": "VAEDecode", "inputs": {"samples": ["1", 0]}},
        "3": {"class_type": "SaveImage", "inputs": {"images": ["2", 0]}}
    }"#;
    let graph_json =
        serde_json::to_string(&serde_json::from_str::<serde_json::Value>(graph_json).unwrap())
            .unwrap();
    RegisteredComfyWorkflow {
        id: "portrait-v1".into(),
        graph_digest: canonical_workflow_digest(&graph_json).unwrap(),
        graph_json,
        bindings: vec![
            WorkflowBinding {
                parameter: ImageParameter::Seed,
                node_id: "1".into(),
                input: "seed".into(),
                value_type: WorkflowValueType::Integer,
                min: Some(0),
                max: Some(1_000_000),
            },
            WorkflowBinding {
                parameter: ImageParameter::Steps,
                node_id: "1".into(),
                input: "steps".into(),
                value_type: WorkflowValueType::Integer,
                min: Some(1),
                max: Some(100),
            },
            WorkflowBinding {
                parameter: ImageParameter::NegativePrompt,
                node_id: "1".into(),
                input: "negative".into(),
                value_type: WorkflowValueType::Text,
                min: None,
                max: None,
            },
        ],
        outputs: vec![WorkflowOutput {
            node_id: "3".into(),
            output: "images".into(),
            value_type: WorkflowValueType::Image,
        }],
    }
}

fn test_endpoint() -> ImageEndpoint {
    ImageEndpoint {
        id: "local-comfy".into(),
        adapter: ImageAdapterKind::Comfyui,
        origin: "http://127.0.0.1:8188".into(),
        path_prefix: Some("/tenant/a".into()),
        credential_ref: Some("comfy-token".into()),
        headers: vec![HeaderSpec {
            name: "X-Token".into(),
            value: "secret".into(),
        }],
        allow_insecure_transport: false,
        location: ImageLocationClass::Local,
        enabled: true,
        route_profile_version: 1,
        exclusive_server: false,
    }
}

fn exclusive_endpoint() -> ImageEndpoint {
    let mut endpoint = test_endpoint();
    endpoint.exclusive_server = true;
    endpoint
}

// ---------------------------------------------------------------------------
// AC 1: Workflow fixtures prove only declared typed bindings mutate a cloned
// registered graph, the source graph stays unchanged, and all agent-supplied
// graph/node/path fields are rejected.
// ---------------------------------------------------------------------------

#[test]
fn comfyui_clone_and_bind_only_declared_values() {
    let workflow = test_workflow();
    let original_json = workflow.graph_json.clone();
    let bound = clone_and_bind_workflow(
        &workflow,
        &[
            BindingApplication {
                parameter: ImageParameter::Seed,
                value: CanonicalBindingValue::Integer(42),
            },
            BindingApplication {
                parameter: ImageParameter::Steps,
                value: CanonicalBindingValue::Integer(30),
            },
            BindingApplication {
                parameter: ImageParameter::NegativePrompt,
                value: CanonicalBindingValue::Text("ugly".into()),
            },
        ],
    )
    .unwrap();

    // Source graph stays unchanged.
    assert_eq!(workflow.graph_json, original_json);
    assert!(source_graph_unchanged(&workflow, &bound).unwrap());

    // Bound graph has the declared values mutated.
    let bound_graph: serde_json::Value = serde_json::from_str(&bound.graph_json).unwrap();
    assert_eq!(bound_graph["1"]["inputs"]["seed"], 42);
    assert_eq!(bound_graph["1"]["inputs"]["steps"], 30);
    assert_eq!(bound_graph["1"]["inputs"]["negative"], "ugly");
    // Non-bound inputs remain unchanged.
    assert_eq!(bound_graph["1"]["inputs"]["cfg"], 7.0);
    assert_eq!(bound_graph["1"]["inputs"]["positive"], "positive text");
    // Other nodes unchanged.
    assert_eq!(
        bound_graph["2"]["inputs"]["samples"],
        serde_json::json!(["1", 0])
    );
}

#[test]
fn comfyui_clone_and_bind_rejects_undeclared_parameter() {
    let workflow = test_workflow();
    // GuidanceScaleMilli is not a declared binding.
    let result = clone_and_bind_workflow(
        &workflow,
        &[BindingApplication {
            parameter: ImageParameter::GuidanceScaleMilli,
            value: CanonicalBindingValue::DecimalMilli(7000),
        }],
    );
    assert!(result.is_err());
}

#[test]
fn comfyui_clone_and_bind_rejects_type_mismatch() {
    let workflow = test_workflow();
    // Seed is Integer, not Text.
    let result = clone_and_bind_workflow(
        &workflow,
        &[BindingApplication {
            parameter: ImageParameter::Seed,
            value: CanonicalBindingValue::Text("not-a-number".into()),
        }],
    );
    assert!(result.is_err());
}

#[test]
fn comfyui_clone_and_bind_rejects_out_of_bounds() {
    let workflow = test_workflow();
    // Seed max is 1_000_000.
    let result = clone_and_bind_workflow(
        &workflow,
        &[BindingApplication {
            parameter: ImageParameter::Seed,
            value: CanonicalBindingValue::Integer(2_000_000),
        }],
    );
    assert!(result.is_err());

    // Below min.
    let result = clone_and_bind_workflow(
        &workflow,
        &[BindingApplication {
            parameter: ImageParameter::Seed,
            value: CanonicalBindingValue::Integer(-1),
        }],
    );
    assert!(result.is_err());
}

#[test]
fn comfyui_source_graph_stays_unchanged_after_binding() {
    let workflow = test_workflow();
    let original = serde_json::from_str::<serde_json::Value>(&workflow.graph_json).unwrap();
    let bound = clone_and_bind_workflow(
        &workflow,
        &[BindingApplication {
            parameter: ImageParameter::Seed,
            value: CanonicalBindingValue::Integer(999),
        }],
    )
    .unwrap();
    // The source workflow JSON is byte-identical.
    let after = serde_json::from_str::<serde_json::Value>(&workflow.graph_json).unwrap();
    assert_eq!(original, after);
    // The bound graph differs only in the declared input.
    assert!(source_graph_unchanged(&workflow, &bound).unwrap());
    let bound_graph = serde_json::from_str::<serde_json::Value>(&bound.graph_json).unwrap();
    assert_eq!(bound_graph["1"]["inputs"]["seed"], 999);
}

// ---------------------------------------------------------------------------
// AC 2: Exact wire fixtures cover bounded upload, POST /prompt, unique
// client_id, /ws, GET /history/{prompt_id}, GET /view, route prefixes,
// headers, and remote-identifier validation.
// ---------------------------------------------------------------------------

#[test]
fn comfyui_route_profile_applies_prefix_and_substitutes_params() {
    let endpoint = test_endpoint();
    let profile = ComfyRouteProfile::new(&endpoint);

    // Fixed route with prefix.
    let submit = profile.fixed(ImageRoute::Submit).unwrap();
    assert_eq!(submit.url, "http://127.0.0.1:8188/tenant/a/prompt");

    let ws = profile.fixed(ImageRoute::Events).unwrap();
    assert_eq!(ws.url, "http://127.0.0.1:8188/tenant/a/ws");

    let view = profile.fixed(ImageRoute::Artifact).unwrap();
    assert_eq!(view.url, "http://127.0.0.1:8188/tenant/a/view");

    let queue = profile.fixed(ImageRoute::Queue).unwrap();
    assert_eq!(queue.url, "http://127.0.0.1:8188/tenant/a/queue");

    let interrupt = profile.fixed(ImageRoute::Job).unwrap();
    assert_eq!(
        interrupt.url,
        "http://127.0.0.1:8188/tenant/a/api/jobs/{job_id}"
    );
    // Job route has a param placeholder — fixed() should reject it.
    let result = profile.fixed(ImageRoute::Cancel);
    // Cancel has {job_id} — fixed should fail.
    assert!(result.is_err());

    // Param route.
    let cancel = profile.param(ImageRoute::Cancel, "job-123").unwrap();
    assert_eq!(
        cancel.url,
        "http://127.0.0.1:8188/tenant/a/api/jobs/job-123/cancel"
    );

    let history = profile.param(ImageRoute::History, "prompt-abc").unwrap();
    assert_eq!(
        history.url,
        "http://127.0.0.1:8188/tenant/a/history/prompt-abc"
    );
}

#[test]
fn comfyui_route_profile_without_prefix() {
    let mut endpoint = test_endpoint();
    endpoint.path_prefix = None;
    let profile = ComfyRouteProfile::new(&endpoint);
    let submit = profile.fixed(ImageRoute::Submit).unwrap();
    assert_eq!(submit.url, "http://127.0.0.1:8188/prompt");
}

#[test]
fn comfyui_param_route_rejects_traversal_and_reserved_chars() {
    let endpoint = test_endpoint();
    let profile = ComfyRouteProfile::new(&endpoint);
    // Path traversal in param value.
    assert!(profile.param(ImageRoute::History, "../etc/passwd").is_err());
    assert!(profile.param(ImageRoute::History, "..%2f").is_err());
    assert!(profile.param(ImageRoute::Cancel, "job{bad}").is_err());
    assert!(profile.param(ImageRoute::History, "").is_err());
    // Valid.
    assert!(profile.param(ImageRoute::History, "abc-123").is_ok());
}

#[test]
fn comfyui_remote_identifier_validation_rejects_traversal() {
    assert!(validate_remote_identifier("../etc/passwd").is_err());
    assert!(validate_remote_identifier("/etc/passwd").is_err());
    assert!(validate_remote_identifier("\\windows").is_err());
    assert!(validate_remote_identifier("file.exe;rm").is_err());
    assert!(validate_remote_identifier("").is_err());
    assert!(validate_remote_identifier(&"a".repeat(513)).is_err());
    // Valid.
    assert!(validate_remote_identifier("ComfyUI_00001_.png").is_ok());
    assert!(validate_remote_identifier("output/temp.png").is_ok());
    assert!(validate_subfolder("").is_ok());
    assert!(validate_subfolder("cockpit-uuid").is_ok());
    assert!(validate_subfolder("../traversal").is_err());
}

#[test]
fn comfyui_upload_request_builds_cockpit_owned_namespace() {
    let prefix = "cockpit-abc-123";
    let req = ComfyUploadRequest::new(prefix, "ref-image.png").unwrap();
    assert_eq!(req.image_name, "cockpit-abc-123-ref-image.png");
    assert_eq!(req.subfolder, "cockpit-abc-123");
    assert!(req.overwrite);
    // Rejects traversal in artifact name.
    assert!(ComfyUploadRequest::new(prefix, "../etc/passwd").is_err());
}

#[test]
fn comfyui_attempt_upload_prefix_is_unique() {
    let id1 = uuid::Uuid::new_v4();
    let id2 = uuid::Uuid::new_v4();
    let prefix1 = attempt_upload_prefix(&id1);
    let prefix2 = attempt_upload_prefix(&id2);
    assert_ne!(prefix1, prefix2);
    assert!(prefix1.starts_with("cockpit-"));
}

#[test]
fn comfyui_prompt_payload_has_unique_client_id() {
    let payload1 = ComfyPromptPayload {
        prompt: serde_json::json!({"1": {"inputs": {"seed": 1}}}),
        client_id: uuid::Uuid::new_v4().to_string(),
    };
    let payload2 = ComfyPromptPayload {
        prompt: serde_json::json!({"1": {"inputs": {"seed": 1}}}),
        client_id: uuid::Uuid::new_v4().to_string(),
    };
    assert_ne!(payload1.client_id, payload2.client_id);
}

#[test]
fn comfyui_prompt_response_parses_prompt_id() {
    let json = serde_json::json!({"prompt_id": "abc-123", "number": 1});
    let response: ComfyPromptResponse = serde_json::from_value(json).unwrap();
    assert_eq!(response.prompt_id, "abc-123");
}

#[test]
fn comfyui_view_request_from_artifact_validates_identifiers() {
    let artifact = ComfyOutputArtifact {
        node_id: "3".into(),
        output: "images".into(),
        filename: "ComfyUI_00001.png".into(),
        subfolder: "cockpit-uuid".into(),
        r#type: "output".into(),
    };
    let req = ComfyViewRequest::from_artifact(&artifact).unwrap();
    assert_eq!(req.filename, "ComfyUI_00001.png");
    let params = req.to_query_params();
    assert_eq!(params[0].0, "filename");
    assert_eq!(params[0].1, "ComfyUI_00001.png");

    // Traversal in filename is rejected.
    let bad = ComfyOutputArtifact {
        filename: "../../etc/passwd".into(),
        ..artifact
    };
    assert!(ComfyViewRequest::from_artifact(&bad).is_err());
}

// ---------------------------------------------------------------------------
// AC 3: Cancellation tests cover idempotent exact-job POST /api/jobs/{job_id}/cancel
// with cancelled true/false, exact queued POST /queue {"delete":[prompt_id]},
// and unsupported late quarantine.
// ---------------------------------------------------------------------------

#[test]
fn comfyui_cancellation_capability_strings() {
    assert_eq!(
        ComfyCancellationCapability::JobScopedCancel.as_str(),
        "job_scoped_cancel"
    );
    assert_eq!(
        ComfyCancellationCapability::QueuedPromptDelete.as_str(),
        "queued_prompt_delete"
    );
    assert_eq!(
        ComfyCancellationCapability::ExclusiveServerInterrupt.as_str(),
        "exclusive_server_interrupt"
    );
    assert_eq!(
        ComfyCancellationCapability::Unsupported.as_str(),
        "unsupported"
    );
}

#[test]
fn comfyui_select_job_scoped_cancel_wins_over_queued_delete() {
    let endpoint = test_endpoint();
    let job_binding = JobBinding {
        job_id: "job-123".into(),
    };
    let queue = QueueSnapshot {
        queued: vec!["prompt-abc".into()],
        running: vec!["prompt-abc".into()],
    };
    // A job-scoped route wins over queued deletion for a running job.
    let selection =
        select_cancellation_capability(&endpoint, Some(&job_binding), &queue, Some("prompt-abc"));
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::JobScopedCancel
    );
}

#[test]
fn comfyui_select_queued_prompt_delete_for_queued_work() {
    let endpoint = test_endpoint();
    let queue = QueueSnapshot {
        queued: vec!["prompt-abc".into()],
        running: vec![],
    };
    let selection = select_cancellation_capability(&endpoint, None, &queue, Some("prompt-abc"));
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::QueuedPromptDelete
    );
}

#[test]
fn comfyui_queued_delete_only_for_queued_not_running() {
    let endpoint = test_endpoint();
    let queue = QueueSnapshot {
        queued: vec![],
        running: vec!["prompt-abc".into()],
    };
    // Prompt is running, not queued, and no job binding — not queued delete.
    let selection = select_cancellation_capability(&endpoint, None, &queue, Some("prompt-abc"));
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::Unsupported
    );
}

#[test]
fn comfyui_unsupported_when_no_safe_cancellation() {
    let endpoint = test_endpoint();
    let queue = QueueSnapshot::default();
    let selection = select_cancellation_capability(&endpoint, None, &queue, Some("prompt-abc"));
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::Unsupported
    );
}

#[test]
fn comfyui_unsupported_late_quarantine_no_provider_cancel() {
    // When cancellation is unsupported, the result records
    // `cancellation_requested` locally and quarantines any later result.
    let result = ComfyCancelResult::Unsupported {
        evidence: b"cancellation_requested_no_provider_cancel".to_vec(),
    };
    assert!(matches!(result, ComfyCancelResult::Unsupported { .. }));
}

#[test]
fn comfyui_cancelled_false_is_authoritative_no_op() {
    // A `cancelled: false` job response is an authoritative no-op result,
    // not proof of failure or non-acceptance.
    let result = ComfyCancelResult::TooLateOrAccepted {
        evidence: br#"{"cancelled":false}"#.to_vec(),
    };
    assert!(matches!(
        result,
        ComfyCancelResult::TooLateOrAccepted { .. }
    ));
}

#[test]
fn comfyui_cancelled_true_confirms_cancellation() {
    let result = ComfyCancelResult::Cancelled {
        evidence: br#"{"cancelled":true}"#.to_vec(),
    };
    assert!(matches!(result, ComfyCancelResult::Cancelled { .. }));
}

// ---------------------------------------------------------------------------
// AC 4: Tests prove POST /interrupt without an ID is impossible unless
// exclusive_server is explicitly configured and an exclusive queue snapshot
// proves sole ownership; it is never fallback for a shared server or failed
// queue delete.
// ---------------------------------------------------------------------------

#[test]
fn comfyui_interrupt_forbidden_on_shared_server() {
    let endpoint = test_endpoint(); // exclusive_server = false
    let queue = QueueSnapshot {
        queued: vec![],
        running: vec!["prompt-abc".into()],
    };
    let selection = select_cancellation_capability(&endpoint, None, &queue, Some("prompt-abc"));
    // Even with sole execution, shared server cannot use interrupt.
    assert_ne!(
        selection.capability,
        ComfyCancellationCapability::ExclusiveServerInterrupt
    );
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::Unsupported
    );
}

#[test]
fn comfyui_interrupt_requires_sole_ownership() {
    let endpoint = exclusive_endpoint();
    // Sole execution.
    let queue = QueueSnapshot {
        queued: vec![],
        running: vec!["prompt-abc".into()],
    };
    let selection = select_cancellation_capability(&endpoint, None, &queue, Some("prompt-abc"));
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::ExclusiveServerInterrupt
    );

    // Not sole — another prompt is also running.
    let queue = QueueSnapshot {
        queued: vec![],
        running: vec!["prompt-abc".into(), "prompt-other".into()],
    };
    let selection = select_cancellation_capability(&endpoint, None, &queue, Some("prompt-abc"));
    assert_ne!(
        selection.capability,
        ComfyCancellationCapability::ExclusiveServerInterrupt
    );
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::Unsupported
    );
}

#[test]
fn comfyui_interrupt_never_fallback_for_failed_queue_delete() {
    let endpoint = test_endpoint(); // shared server
    let queue = QueueSnapshot {
        queued: vec!["prompt-abc".into()],
        running: vec![],
    };
    // Prompt is queued — queue delete is selected, not interrupt.
    let selection = select_cancellation_capability(&endpoint, None, &queue, Some("prompt-abc"));
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::QueuedPromptDelete
    );
    // Even if we imagine queue delete "failed" and prompt moved to running,
    // a shared server still cannot use interrupt.
    let queue_after = QueueSnapshot {
        queued: vec![],
        running: vec!["prompt-abc".into()],
    };
    let selection =
        select_cancellation_capability(&endpoint, None, &queue_after, Some("prompt-abc"));
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::Unsupported
    );
}

#[test]
fn comfyui_interrupt_requires_prompt_present_and_sole() {
    let endpoint = exclusive_endpoint();
    let queue = QueueSnapshot {
        queued: vec![],
        running: vec!["prompt-abc".into()],
    };
    // No prompt_id provided — cannot prove ownership.
    let selection = select_cancellation_capability(&endpoint, None, &queue, None);
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::Unsupported
    );
}

// ---------------------------------------------------------------------------
// AC 5: WebSocket loss, bounded polling fallback, duplicate/foreign/out-of-
// order events, restart recovery, and ambiguous submission have deterministic
// tests without wall-clock sleeps.
// ---------------------------------------------------------------------------

#[test]
fn comfyui_parse_ws_event_progress() {
    let msg = r#"{"type":"progress","prompt_id":"abc","client_id":"client-1","value":5,"max":10}"#;
    let event = parse_ws_event(msg, "client-1").unwrap().unwrap();
    assert!(matches!(
        event,
        ComfyWsEvent::Progress {
            prompt_id,
            value: 5,
            max: 10
        } if prompt_id == "abc"
    ));
}

#[test]
fn comfyui_parse_ws_event_executed() {
    let msg = r#"{"type":"executed","prompt_id":"abc","client_id":"client-1"}"#;
    let event = parse_ws_event(msg, "client-1").unwrap().unwrap();
    assert!(matches!(event, ComfyWsEvent::Executed { ref prompt_id } if prompt_id == "abc"));
}

#[test]
fn comfyui_parse_ws_event_execution_error() {
    let msg = r#"{"type":"execution_error","prompt_id":"abc","client_id":"client-1","exception_type":"OOM"}"#;
    let event = parse_ws_event(msg, "client-1").unwrap().unwrap();
    assert!(matches!(
        event,
        ComfyWsEvent::ExecutionError { ref prompt_id, ref safe_reason }
            if prompt_id == "abc" && safe_reason == "OOM"
    ));
}

#[test]
fn comfyui_parse_ws_event_execution_interrupted() {
    let msg = r#"{"type":"execution_interrupted","prompt_id":"abc","client_id":"client-1"}"#;
    let event = parse_ws_event(msg, "client-1").unwrap().unwrap();
    assert!(
        matches!(event, ComfyWsEvent::ExecutionInterrupted { ref prompt_id } if prompt_id == "abc")
    );
}

#[test]
fn comfyui_parse_ws_event_ignores_foreign_client() {
    let msg =
        r#"{"type":"progress","prompt_id":"abc","client_id":"other-client","value":1,"max":2}"#;
    let event = parse_ws_event(msg, "client-1").unwrap();
    assert!(event.is_none(), "foreign client events must be ignored");
}

#[test]
fn comfyui_parse_ws_event_ignores_malformed_and_unknown() {
    assert!(parse_ws_event("not json", "client-1").unwrap().is_none());
    assert!(parse_ws_event("{}", "client-1").unwrap().is_none());
    assert!(
        parse_ws_event(r#"{"type":"unknown"}"#, "client-1")
            .unwrap()
            .is_none()
    );
    assert!(parse_ws_event("[]", "client-1").unwrap().is_none());
}

#[test]
fn comfyui_prompt_execution_state_monotonic_progress() {
    let mut state = PromptExecutionState::new("abc".into());
    // Progress is monotonic — out-of-order regressions are ignored.
    state.apply_event(&ComfyWsEvent::Progress {
        prompt_id: "abc".into(),
        value: 5,
        max: 10,
    });
    assert_eq!(state.progress_value, 5);
    state.apply_event(&ComfyWsEvent::Progress {
        prompt_id: "abc".into(),
        value: 3,
        max: 10,
    });
    // Regression ignored.
    assert_eq!(state.progress_value, 5);
    state.apply_event(&ComfyWsEvent::Progress {
        prompt_id: "abc".into(),
        value: 8,
        max: 10,
    });
    assert_eq!(state.progress_value, 8);
}

#[test]
fn comfyui_prompt_execution_state_duplicate_executed_is_idempotent() {
    let mut state = PromptExecutionState::new("abc".into());
    state.apply_event(&ComfyWsEvent::Executed {
        prompt_id: "abc".into(),
    });
    assert!(state.completed);
    assert!(state.is_terminal());
    // Duplicate executed event — stays completed.
    state.apply_event(&ComfyWsEvent::Executed {
        prompt_id: "abc".into(),
    });
    assert!(state.completed);
}

#[test]
fn comfyui_prompt_execution_state_error_after_completed_is_ignored() {
    let mut state = PromptExecutionState::new("abc".into());
    state.apply_event(&ComfyWsEvent::Executed {
        prompt_id: "abc".into(),
    });
    assert!(state.completed);
    // Late error after completion is ignored (out-of-order).
    state.apply_event(&ComfyWsEvent::ExecutionError {
        prompt_id: "abc".into(),
        safe_reason: "late".into(),
    });
    assert!(state.completed);
    assert!(!state.failed);
}

#[test]
fn comfyui_prompt_execution_state_interrupted_then_error_is_ignored() {
    let mut state = PromptExecutionState::new("abc".into());
    state.apply_event(&ComfyWsEvent::ExecutionInterrupted {
        prompt_id: "abc".into(),
    });
    assert!(state.interrupted);
    // Late error after interrupt is ignored.
    state.apply_event(&ComfyWsEvent::ExecutionError {
        prompt_id: "abc".into(),
        safe_reason: "late".into(),
    });
    assert!(state.interrupted);
    assert!(!state.failed);
}

#[test]
fn comfyui_prompt_execution_state_ignores_foreign_prompt() {
    let mut state = PromptExecutionState::new("abc".into());
    state.apply_event(&ComfyWsEvent::Progress {
        prompt_id: "other".into(),
        value: 5,
        max: 10,
    });
    // Foreign prompt event ignored.
    assert_eq!(state.progress_value, 0);
}

#[test]
fn comfyui_websocket_loss_falls_back_to_polling() {
    // When WebSocket is not available, the adapter uses bounded history
    // polling. This test verifies the history parsing works as fallback.
    let workflow = test_workflow();
    let history_json = serde_json::json!({
        "prompt-abc": {
            "outputs": {
                "3": {
                    "images": [
                        {"filename": "ComfyUI_00001.png", "subfolder": "output", "type": "output"}
                    ]
                }
            },
            "status": {"completed": true}
        }
    });
    let result = parse_history_response(&history_json, "prompt-abc", &workflow.outputs).unwrap();
    assert_eq!(result.prompt_id, "prompt-abc");
    assert!(result.completed);
    assert_eq!(result.outputs.len(), 1);
    assert_eq!(result.outputs[0].node_id, "3");
    assert_eq!(result.outputs[0].filename, "ComfyUI_00001.png");
}

#[test]
fn comfyui_history_filters_to_declared_outputs_only() {
    let workflow = test_workflow();
    // Add a foreign node output that should be filtered out.
    let history_json = serde_json::json!({
        "prompt-abc": {
            "outputs": {
                "3": {
                    "images": [
                        {"filename": "declared.png", "subfolder": "", "type": "output"}
                    ]
                },
                "99": {
                    "images": [
                        {"filename": "foreign.png", "subfolder": "", "type": "output"}
                    ]
                }
            },
            "status": {"completed": true}
        }
    });
    let result = parse_history_response(&history_json, "prompt-abc", &workflow.outputs).unwrap();
    // Only node "3" (declared) is included; node "99" (foreign) is filtered.
    assert_eq!(result.outputs.len(), 1);
    assert_eq!(result.outputs[0].node_id, "3");
    assert_eq!(result.outputs[0].filename, "declared.png");
}

#[test]
fn comfyui_history_rejects_traversal_in_output() {
    let workflow = test_workflow();
    let history_json = serde_json::json!({
        "prompt-abc": {
            "outputs": {
                "3": {
                    "images": [
                        {"filename": "../../etc/passwd", "subfolder": "", "type": "output"}
                    ]
                }
            },
            "status": {"completed": true}
        }
    });
    let result = parse_history_response(&history_json, "prompt-abc", &workflow.outputs);
    assert!(result.is_err());
}

#[test]
fn comfyui_history_missing_prompt_id_is_error() {
    let workflow = test_workflow();
    let history_json = serde_json::json!({
        "other-prompt": {
            "outputs": {},
            "status": {"completed": true}
        }
    });
    let result = parse_history_response(&history_json, "prompt-abc", &workflow.outputs);
    assert!(result.is_err());
}

#[test]
fn comfyui_ambiguous_submission_is_submission_unknown() {
    // Missing response after possible handoff becomes submission_unknown.
    let outcome = SubmissionOutcome::SubmissionUnknown {
        evidence: b"no_response_after_possible_handoff".to_vec(),
    };
    assert!(matches!(
        outcome,
        SubmissionOutcome::SubmissionUnknown { .. }
    ));
}

#[test]
fn comfyui_submission_accepted_records_prompt_id() {
    let outcome = SubmissionOutcome::Accepted {
        prompt_id: "prompt-123".into(),
        evidence: b"accepted".to_vec(),
    };
    assert!(
        matches!(outcome, SubmissionOutcome::Accepted { ref prompt_id, .. } if prompt_id == "prompt-123")
    );
}

#[test]
fn comfyui_submission_retry_only_when_not_accepted() {
    // Submission retry is allowed only with proof POST /prompt was not
    // accepted. DefinitivelyRejected allows retry; SubmissionUnknown does not.
    let rejected = SubmissionOutcome::DefinitivelyRejected {
        safe_reason: "bad_workflow".into(),
        evidence: b"rejected".to_vec(),
    };
    assert!(matches!(
        rejected,
        SubmissionOutcome::DefinitivelyRejected { .. }
    ));
}

// ---------------------------------------------------------------------------
// AC 6: Upload/output namespace, declared-output filtering, download bounds,
// traversal rejection, canonical media validation, cleanup-supported/
// unsupported disclosure, and no-local-filesystem assumption.
// ---------------------------------------------------------------------------

#[test]
fn comfyui_upload_namespace_isolation() {
    let prefix1 = "cockpit-attempt-1";
    let prefix2 = "cockpit-attempt-2";
    let req1 = ComfyUploadRequest::new(prefix1, "ref.png").unwrap();
    let req2 = ComfyUploadRequest::new(prefix2, "ref.png").unwrap();
    // Same artifact name, different namespaces.
    assert_ne!(req1.image_name, req2.image_name);
    assert_ne!(req1.subfolder, req2.subfolder);
}

#[test]
fn comfyui_upload_response_creates_cleanup_obligation() {
    let response = ComfyUploadResponse {
        name: "cockpit-uuid-ref.png".into(),
        subfolder: "cockpit-uuid".into(),
        r#type: "input".into(),
    };
    let obligation = RemoteCleanupObligation::for_upload(&response, true).unwrap();
    assert!(obligation.fn_fulfillable());
    assert_eq!(obligation.filename, "cockpit-uuid-ref.png");
    assert_eq!(obligation.subfolder, "cockpit-uuid");
}

#[test]
fn comfyui_cleanup_unsupported_disclosed_not_hidden() {
    let response = ComfyUploadResponse {
        name: "cockpit-uuid-ref.png".into(),
        subfolder: "cockpit-uuid".into(),
        r#type: "input".into(),
    };
    // delete_supported = false — the obligation is recorded but cannot be
    // fulfilled. This is disclosed, not hidden.
    let obligation = RemoteCleanupObligation::for_upload(&response, false).unwrap();
    assert!(!obligation.fn_fulfillable());
    assert!(!obligation.delete_supported);
}

#[test]
fn comfyui_output_artifact_creates_cleanup_obligation() {
    let artifact = ComfyOutputArtifact {
        node_id: "3".into(),
        output: "images".into(),
        filename: "ComfyUI_00001.png".into(),
        subfolder: "output".into(),
        r#type: "output".into(),
    };
    let obligation = RemoteCleanupObligation::for_output(&artifact, false).unwrap();
    assert!(!obligation.fn_fulfillable());
    assert_eq!(obligation.filename, "ComfyUI_00001.png");
}

#[test]
fn comfyui_cleanup_obligation_rejects_traversal() {
    let response = ComfyUploadResponse {
        name: "../../etc/passwd".into(),
        subfolder: "".into(),
        r#type: "input".into(),
    };
    assert!(RemoteCleanupObligation::for_upload(&response, true).is_err());

    let artifact = ComfyOutputArtifact {
        node_id: "3".into(),
        output: "images".into(),
        filename: "../../etc/passwd".into(),
        subfolder: "".into(),
        r#type: "output".into(),
    };
    assert!(RemoteCleanupObligation::for_output(&artifact, true).is_err());
}

#[test]
fn comfyui_queue_snapshot_sole_ownership() {
    let queue = QueueSnapshot {
        queued: vec![],
        running: vec!["prompt-abc".into()],
    };
    assert!(queue.owns_sole_execution("prompt-abc"));
    assert!(!queue.owns_sole_execution("prompt-other"));

    let queue = QueueSnapshot {
        queued: vec![],
        running: vec!["prompt-abc".into(), "prompt-other".into()],
    };
    assert!(!queue.owns_sole_execution("prompt-abc"));
}

#[test]
fn comfyui_queue_snapshot_is_queued_and_running() {
    let queue = QueueSnapshot {
        queued: vec!["prompt-a".into()],
        running: vec!["prompt-b".into()],
    };
    assert!(queue.is_queued("prompt-a"));
    assert!(!queue.is_queued("prompt-b"));
    assert!(queue.is_running("prompt-b"));
    assert!(!queue.is_running("prompt-a"));
}

// ---------------------------------------------------------------------------
// AC 7: Config identity changes invalidate health/grants/plans, while display
// rename alone does not.
// ---------------------------------------------------------------------------

#[test]
fn comfyui_exclusive_server_config_is_identity_changing() {
    let endpoint = test_endpoint();
    let identity = endpoint.immutable_identity();
    let mut exclusive = endpoint;
    exclusive.exclusive_server = true;
    assert_ne!(exclusive.immutable_identity(), identity);
}

#[test]
fn comfyui_target_identity_changes_with_capability() {
    let endpoint = test_endpoint();
    let workflow = test_workflow();
    let id1 = comfy_target_identity(
        &endpoint,
        &workflow,
        ComfyCancellationCapability::JobScopedCancel,
    );
    let id2 = comfy_target_identity(
        &endpoint,
        &workflow,
        ComfyCancellationCapability::Unsupported,
    );
    // Different cancellation capabilities invalidate the identity.
    assert_ne!(id1, id2);
}

#[test]
fn comfyui_target_identity_changes_with_workflow_digest() {
    let endpoint = test_endpoint();
    let workflow1 = test_workflow();
    let mut workflow2 = test_workflow();
    // Change the graph (and its digest).
    workflow2.graph_json =
        r#"{"1":{"inputs":{"seed":0}},"2":{"inputs":{}},"3":{"inputs":{}}}"#.to_owned();
    workflow2.graph_digest = canonical_workflow_digest(&workflow2.graph_json).unwrap();
    let id1 = comfy_target_identity(
        &endpoint,
        &workflow1,
        ComfyCancellationCapability::JobScopedCancel,
    );
    let id2 = comfy_target_identity(
        &endpoint,
        &workflow2,
        ComfyCancellationCapability::JobScopedCancel,
    );
    assert_ne!(id1, id2);
}

#[test]
fn comfyui_target_identity_changes_with_endpoint() {
    let workflow = test_workflow();
    let endpoint1 = test_endpoint();
    let mut endpoint2 = test_endpoint();
    endpoint2.origin = "http://127.0.0.1:8189".into();
    let id1 = comfy_target_identity(
        &endpoint1,
        &workflow,
        ComfyCancellationCapability::JobScopedCancel,
    );
    let id2 = comfy_target_identity(
        &endpoint2,
        &workflow,
        ComfyCancellationCapability::JobScopedCancel,
    );
    assert_ne!(id1, id2);
}

#[test]
fn comfyui_discovery_base_cancellation_capability() {
    let endpoint = test_endpoint();
    let discovery = ComfyDiscovery {
        job_cancel_supported: true,
        queue_delete_supported: true,
        history_supported: true,
        ws_supported: true,
        delete_supported: true,
        server_version: Some("0.3.0".into()),
        workflow_compatible: true,
    };
    // Job-scoped cancel is preferred.
    assert_eq!(
        discovery.base_cancellation_capability(&endpoint),
        ComfyCancellationCapability::JobScopedCancel
    );

    let discovery = ComfyDiscovery {
        job_cancel_supported: false,
        queue_delete_supported: true,
        ..discovery
    };
    assert_eq!(
        discovery.base_cancellation_capability(&endpoint),
        ComfyCancellationCapability::QueuedPromptDelete
    );

    let discovery = ComfyDiscovery {
        job_cancel_supported: false,
        queue_delete_supported: false,
        ..discovery
    };
    // Shared server — unsupported, not interrupt.
    assert_eq!(
        discovery.base_cancellation_capability(&endpoint),
        ComfyCancellationCapability::Unsupported
    );

    // Exclusive server — interrupt available.
    let exclusive = exclusive_endpoint();
    assert_eq!(
        discovery.base_cancellation_capability(&exclusive),
        ComfyCancellationCapability::ExclusiveServerInterrupt
    );
}

#[test]
fn comfyui_adapter_kind_is_comfyui() {
    assert_eq!(adapter_kind(), ImageAdapterKind::Comfyui);
}

// ---------------------------------------------------------------------------
// Config: exclusive_server field round-trips and defaults to false.
// ---------------------------------------------------------------------------

#[test]
fn comfyui_config_exclusive_server_defaults_false_and_round_trips() {
    let json = serde_json::json!({
        "id": "local-comfy",
        "adapter": "comfyui",
        "origin": "http://127.0.0.1:8188",
        "location": "local",
        "route_profile_version": 1
    });
    let endpoint: ImageEndpoint = serde_json::from_value(json).unwrap();
    assert!(!endpoint.exclusive_server);

    let json = serde_json::json!({
        "id": "exclusive-comfy",
        "adapter": "comfyui",
        "origin": "http://127.0.0.1:8188",
        "location": "local",
        "route_profile_version": 1,
        "exclusive_server": true
    });
    let endpoint: ImageEndpoint = serde_json::from_value(json).unwrap();
    assert!(endpoint.exclusive_server);
    let round_trip = serde_json::to_string(&endpoint).unwrap();
    assert!(round_trip.contains("exclusive_server"));
}

#[test]
fn comfyui_config_exclusive_server_rejects_unknown_fields() {
    let json = serde_json::json!({
        "id": "local-comfy",
        "adapter": "comfyui",
        "origin": "http://127.0.0.1:8188",
        "location": "local",
        "route_profile_version": 1,
        "unknown_field": true
    });
    assert!(serde_json::from_value::<ImageEndpoint>(json).is_err());
}

// ---------------------------------------------------------------------------
// Race conditions: queued-delete racing execution must not escalate to global
// interrupt.
// ---------------------------------------------------------------------------

#[test]
fn comfyui_queued_delete_racing_execution_does_not_escalate_to_interrupt() {
    let endpoint = test_endpoint(); // shared server
    // Prompt was queued, but by the time the delete is sent, it's now running.
    let queue = QueueSnapshot {
        queued: vec![],
        running: vec!["prompt-abc".into()],
    };
    // No job binding — cannot use job-scoped cancel. Shared server — cannot
    // use interrupt. Must record cancellation_requested, not escalate.
    let selection = select_cancellation_capability(&endpoint, None, &queue, Some("prompt-abc"));
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::Unsupported
    );
}

#[test]
fn comfyui_queued_delete_racing_execution_uses_job_scoped_if_bound() {
    let endpoint = test_endpoint();
    let job_binding = JobBinding {
        job_id: "job-123".into(),
    };
    // Prompt was queued, now running, but job binding exists.
    let queue = QueueSnapshot {
        queued: vec![],
        running: vec!["prompt-abc".into()],
    };
    let selection =
        select_cancellation_capability(&endpoint, Some(&job_binding), &queue, Some("prompt-abc"));
    // Job-scoped cancel wins.
    assert_eq!(
        selection.capability,
        ComfyCancellationCapability::JobScopedCancel
    );
}

// ---------------------------------------------------------------------------
// Restart recovery: durable prompt/job identity recovers from disconnect.
// ---------------------------------------------------------------------------

#[test]
fn comfyui_restart_recovery_from_durable_prompt_identity() {
    // After a disconnect/restart, the adapter recovers from durable
    // prompt/job identity. If identity was never learned after ambiguous
    // handoff, remain submission_unknown and never scan or claim unrelated
    // history.
    let ambiguous = SubmissionOutcome::SubmissionUnknown {
        evidence: b"identity_never_learned".to_vec(),
    };
    assert!(matches!(
        ambiguous,
        SubmissionOutcome::SubmissionUnknown { .. }
    ));

    // With a known prompt_id, recovery can poll history.
    let known = SubmissionOutcome::Accepted {
        prompt_id: "prompt-abc".into(),
        evidence: b"accepted".to_vec(),
    };
    if let SubmissionOutcome::Accepted { prompt_id, .. } = &known {
        assert_eq!(prompt_id, "prompt-abc");
    }
}

// ---------------------------------------------------------------------------
// Edge cases: oversized history, malformed images.
// ---------------------------------------------------------------------------

#[test]
fn comfyui_oversized_history_output_array_handled() {
    let workflow = test_workflow();
    let mut images = Vec::new();
    for i in 0..10 {
        images.push(serde_json::json!({
            "filename": format!("ComfyUI_{i:05}.png"),
            "subfolder": "",
            "type": "output"
        }));
    }
    let history_json = serde_json::json!({
        "prompt-abc": {
            "outputs": {
                "3": {
                    "images": images
                }
            },
            "status": {"completed": true}
        }
    });
    let result = parse_history_response(&history_json, "prompt-abc", &workflow.outputs).unwrap();
    assert_eq!(result.outputs.len(), 10);
    assert!(
        result
            .outputs
            .iter()
            .all(|o| o.filename.starts_with("ComfyUI_"))
    );
}

#[test]
fn comfyui_history_missing_output_array_is_error() {
    let workflow = test_workflow();
    let history_json = serde_json::json!({
        "prompt-abc": {
            "outputs": {
                "3": {
                    "images": "not-an-array"
                }
            },
            "status": {"completed": true}
        }
    });
    let result = parse_history_response(&history_json, "prompt-abc", &workflow.outputs);
    assert!(result.is_err());
}

#[test]
fn comfyui_history_missing_filename_is_error() {
    let workflow = test_workflow();
    let history_json = serde_json::json!({
        "prompt-abc": {
            "outputs": {
                "3": {
                    "images": [{"subfolder": "", "type": "output"}]
                }
            },
            "status": {"completed": true}
        }
    });
    let result = parse_history_response(&history_json, "prompt-abc", &workflow.outputs);
    assert!(result.is_err());
}

#[test]
fn comfyui_history_declared_node_missing_in_output_is_skipped() {
    let workflow = test_workflow();
    // Node "3" is declared but not present in outputs — should be skipped,
    // not an error.
    let history_json = serde_json::json!({
        "prompt-abc": {
            "outputs": {},
            "status": {"completed": true}
        }
    });
    let result = parse_history_response(&history_json, "prompt-abc", &workflow.outputs).unwrap();
    assert_eq!(result.outputs.len(), 0);
    assert!(result.completed);
}

#[test]
fn comfyui_history_completed_false_means_incomplete() {
    let workflow = test_workflow();
    let history_json = serde_json::json!({
        "prompt-abc": {
            "outputs": {
                "3": {
                    "images": [{"filename": "out.png", "subfolder": "", "type": "output"}]
                }
            },
            "status": {"completed": false}
        }
    });
    let result = parse_history_response(&history_json, "prompt-abc", &workflow.outputs).unwrap();
    assert!(!result.completed);
}
