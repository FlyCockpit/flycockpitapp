use super::*;
use crate::db::session_log::SessionEventKind;
use crate::db::tool_calls::Recovery;
use crate::db::tool_calls::ToolCallEvent;
use crate::engine::tool::Tool;
use crate::session::{Session, ToolCallProviderIdentity, ToolCallRow};
use std::io::Read;

/// Read a named file out of a zip byte buffer.
fn read_zip_entry(bytes: &[u8], name: &str) -> Option<String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
    let mut f = archive.by_name(name).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    Some(s)
}

fn entry_names(bytes: &[u8]) -> Vec<String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
    (0..archive.len())
        .map(|i| archive.by_index(i).unwrap().name().to_string())
        .collect()
}

#[test]
fn export_redaction_helper_scrubs_by_default_and_preserves_with_opt_in() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = crate::config::extended::RedactConfig {
        denylist: vec!["exact-secret-value".to_string()],
        ..crate::config::extended::RedactConfig::default()
    };
    let redactor = RedactionTable::build_with_env(&cfg, tmp.path(), &Default::default())
        .expect("redaction table builds");

    let mut safe = json!({
        "request": {
            "prompt": "send exact-secret-value",
            "nested": ["exact-secret-value"],
        }
    });
    redact_value_for_export(&mut safe, &redactor, false);
    assert!(!safe.to_string().contains("exact-secret-value"));
    assert!(safe.to_string().contains("REDACTED"));

    let mut sensitive = json!({"prompt": "send exact-secret-value"});
    redact_value_for_export(&mut sensitive, &redactor, true);
    assert!(sensitive.to_string().contains("exact-secret-value"));
}

fn responses_session_with_intro() -> Session {
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db, PathBuf::from("/proj"), "Build").unwrap();
    session.set_active_model("codex-oauth", "gpt-5.4").unwrap();
    session
        .record_event(
            SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &json!({ "text": "investigate" }),
        )
        .unwrap();
    session
        .record_event(
            SessionEventKind::AssistantMessage,
            Some("Build"),
            Some("infer-1"),
            &json!({ "text": "delegating" }),
        )
        .unwrap();
    session
}

fn record_responses_task_pair(
    session: &Session,
    task_call_id: &str,
    provider_call_id: &str,
    label: &str,
    child_agent: &str,
    noninteractive: bool,
) {
    let identity = crate::engine::task_identity::TaskProviderIdentity::for_task_call(
        task_call_id,
        Some(provider_call_id),
    );
    session
        .record_event(
            SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some(task_call_id),
            &json!({
                "child_agent": child_agent,
                "task_call_id": task_call_id,
                "provider_call_id": identity.provider_call_id,
                "provider_call_id_source": identity.provider_call_id_source,
                "provider_identity": identity.event_identity_json(task_call_id),
                "label": label,
                "noninteractive": noninteractive,
                "prompt": format!("look around {label}"),
            }),
        )
        .unwrap();
    session
        .record_event(
            SessionEventKind::SubagentReport,
            Some(child_agent),
            Some(task_call_id),
            &json!({
                "child_agent": child_agent,
                "task_call_id": task_call_id,
                "provider_call_id": identity.provider_call_id,
                "provider_call_id_source": identity.provider_call_id_source,
                "provider_identity": identity.event_identity_json(task_call_id),
                "label": label,
                "report": format!("done {label}"),
            }),
        )
        .unwrap();
}

fn build_session_zip(session: &Session) -> Vec<u8> {
    let target = session.db.get_session(session.id).unwrap().unwrap();
    let bundle = collect_bundle(&session.db, session.id).unwrap();
    build_zip(&session.db, &target, &bundle).unwrap()
}

fn assert_manifest_has_no_resume_repair(zip: &[u8]) {
    let manifest: Value =
        serde_json::from_str(&read_zip_entry(zip, "manifest.json").unwrap()).unwrap();
    assert!(
        manifest.get("resume_repair_required").is_none(),
        "fresh Responses task export should not require resume repair: {manifest}"
    );
}

fn zip_events(zip: &[u8]) -> Vec<Value> {
    serde_json::from_str(&read_zip_entry(zip, "events.json").unwrap()).unwrap()
}

fn assert_task_event_identity(
    events: &[Value],
    event_type: &str,
    task_call_id: &str,
    label: &str,
    provider_call_id: &str,
) {
    let event = events
        .iter()
        .find(|event| {
            event["type"] == event_type
                && event["call_id"] == task_call_id
                && event["data"]["task_call_id"] == task_call_id
                && event["data"]["label"] == label
        })
        .unwrap_or_else(|| panic!("missing {event_type} event for {task_call_id}/{label}"));
    assert_eq!(event["data"]["provider_call_id"], provider_call_id);
    assert_eq!(event["data"]["provider_call_id_source"], "provider");
    assert_eq!(
        event["data"]["provider_identity"],
        json!({
            "cockpit_call_id": task_call_id,
            "provider_call_id": provider_call_id,
            "provider_call_id_source": "provider",
            "wire_api": "responses",
        })
    );
}

fn tool_def(name: &str, parameters: Value) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": name,
            "description": "",
            "parameters": parameters,
        }
    })
}

fn request_with_tools(tools: Vec<Value>) -> Value {
    json!({
        "model": "m",
        "provider": "openai",
        "system": "",
        "tools": tools,
        "params": {},
        "history": [],
        "prompt": {"role": "user", "content": "x"},
    })
}

fn validations(request: &Value, response: &Value) -> Vec<Value> {
    super::tandem_validation::validate_tandem_tool_calls(
        request,
        Some(response),
        Path::new("/proj"),
        None,
    )
    .as_array()
    .unwrap()
    .clone()
}

/// A session that delegates to a subagent (same session_id, distinct
/// agent) produces a zip with manifest + events + one inference_request
/// file per call across main AND subagent.
#[test]
fn export_bundles_main_and_subagent_requests() {
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join(".cockpit")).unwrap();
    std::fs::write(
            tmp.path().join(".cockpit/config.json"),
            r#"{"redact":{"scan_environment":false,"scan_dotenv":false,"denylist":["SECRET_STEER_TOKEN"]}}"#,
        )
        .unwrap();
    let db = Db::open_in_memory().unwrap();
    let s = db
        .create_session("p", tmp.path().to_string_lossy().as_ref(), "Build")
        .unwrap();
    let sid = s.session_id;

    // Main agent inference call + captured request.
    let call_main = Uuid::new_v4();
    db.insert_inference_request(
        &call_main.to_string(),
        sid,
        &json!({"model": "m", "system": "sys", "tools": [], "history": [{"role":"user"}]}),
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .unwrap();
    db.insert_session_event(
        sid,
        SessionEventKind::InferenceRequest,
        Some("Build"),
        Some(&call_main.to_string()),
        &json!({"usage": {"input_tokens": 10}}),
    )
    .unwrap();
    // A delegation to a subagent.
    db.insert_session_event(
        sid,
        SessionEventKind::SubagentSpawned,
        Some("Build"),
        Some("task-1"),
        &json!({"child_agent": "explore"}),
    )
    .unwrap();
    // Subagent inference call (shares session_id, distinct agent).
    let call_sub = Uuid::new_v4();
    db.insert_inference_request(
        &call_sub.to_string(),
        sid,
        &json!({"model": "m", "system": "explore-sys", "tools": [], "history": []}),
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .unwrap();
    db.insert_session_event(
        sid,
        SessionEventKind::InferenceRequest,
        Some("explore"),
        Some(&call_sub.to_string()),
        &json!({"usage": {"input_tokens": 5}}),
    )
    .unwrap();
    // A tool call with a recovery (the wire-vs-user split must survive).
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCall,
        Some("explore"),
        Some("tc-1"),
        &json!({
            "tool": "read",
            "original_input": {"path": "a.rs"},
            "wire_input": {"path": "/proj/a.rs"},
            "recovery_kind": "edit_cascade",
            "recovery_stage": "line_trim",
            "hard_fail": false,
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    let names = entry_names(&zip);
    assert!(names.contains(&"manifest.json".to_string()));
    assert!(names.contains(&"events.json".to_string()));
    // One request file per inference call across main AND subagent.
    let req_files: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("inference_requests/"))
        .collect();
    assert_eq!(req_files.len(), 2, "main + subagent requests");

    // events.json is one ordered timeline; each event tagged.
    let events_str = read_zip_entry(&zip, "events.json").unwrap();
    let events: Vec<Value> = serde_json::from_str(&events_str).unwrap();
    assert_eq!(events.len(), 4);
    let seqs: Vec<i64> = events.iter().map(|e| e["seq"].as_i64().unwrap()).collect();
    let mut sorted = seqs.clone();
    sorted.sort();
    assert_eq!(seqs, sorted, "events sorted by seq");
    for e in &events {
        assert!(e["session_id"].is_string());
        assert!(e["short_id"].is_string());
    }

    // Each inference_request event names a REAL file in the archive,
    // and that file holds the full request (system + tools + history).
    for e in &events {
        if e["type"] == "inference_request" {
            let file = e["file"].as_str().expect("inference_request has `file`");
            let body = read_zip_entry(&zip, file)
                .unwrap_or_else(|| panic!("file `{file}` referenced but missing"));
            let parsed: Value = serde_json::from_str(&body).unwrap();
            // The emitted file wraps the captured request body under
            // `request` and surfaces the dispatch-time `status`
            // (implementation note).
            assert!(parsed.get("status").is_some(), "{parsed}");
            let req = &parsed["request"];
            assert!(req.get("system").is_some());
            assert!(req.get("tools").is_some());
            assert!(req.get("history").is_some());
        }
    }

    // The tool_call event carries the recovery_* fields.
    let tool_call = events
        .iter()
        .find(|e| e["type"] == "tool_call")
        .expect("tool_call event present");
    assert_eq!(tool_call["data"]["recovery_kind"], "edit_cascade");
    assert_eq!(tool_call["data"]["recovery_stage"], "line_trim");
    assert_eq!(tool_call["data"]["original_input"]["path"], "a.rs");
    assert_eq!(tool_call["data"]["wire_input"]["path"], "/proj/a.rs");
}

#[test]
fn export_request_payloads_redacted_by_default_and_sensitive_opt_in_preserves() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.json"),
        r#"{"redact":{"denylist":["trusted-secret-value"]}}"#,
    )
    .unwrap();

    let db = Db::open_in_memory().unwrap();
    let s = db
        .create_session("p", tmp.path().to_str().unwrap(), "Build")
        .unwrap();
    let call = Uuid::new_v4();
    db.insert_inference_request(
        &call.to_string(),
        s.session_id,
        &json!({
            "model": "trusted-model",
            "system": "trusted-secret-value in system",
            "history": [{"role": "user", "content": "trusted-secret-value"}],
            "tools": [],
        }),
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .unwrap();
    db.insert_session_event(
        s.session_id,
        SessionEventKind::InferenceRequest,
        Some("Build"),
        Some(&call.to_string()),
        &json!({"routing": {"trust": "trusted", "note": "trusted-secret-value"}}),
    )
    .unwrap();

    let target = db.get_session(s.session_id).unwrap().unwrap();
    let bundle = collect_bundle(&db, s.session_id).unwrap();
    let safe = build_zip_with_options_and_env(
        &db,
        &target,
        &bundle,
        ExportBundleOptions::default(),
        &test_export_env(),
    )
    .unwrap();
    let safe_body = entry_names(&safe)
        .into_iter()
        .find(|name| name.starts_with("inference_requests/"))
        .and_then(|name| read_zip_entry(&safe, &name))
        .expect("request file exists");
    assert!(!safe_body.contains("trusted-secret-value"));
    assert!(
        !read_zip_entry(&safe, "events.json")
            .unwrap()
            .contains("trusted-secret-value")
    );

    let sensitive = build_zip_with_options_and_env(
        &db,
        &target,
        &bundle,
        ExportBundleOptions {
            include_sensitive: true,
            ..ExportBundleOptions::default()
        },
        &test_export_env(),
    )
    .unwrap();
    let sensitive_body = entry_names(&sensitive)
        .into_iter()
        .find(|name| name.starts_with("inference_requests/"))
        .and_then(|name| read_zip_entry(&sensitive, &name))
        .expect("request file exists");
    assert!(sensitive_body.contains("trusted-secret-value"));
    assert!(
        read_zip_entry(&sensitive, "events.json")
            .unwrap()
            .contains("trusted-secret-value")
    );
}

#[test]
fn export_tool_call_event_includes_provider_identity_provenance() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;

    db.insert_tool_call(&ToolCallEvent {
        event_id: Uuid::new_v4(),
        session_id: sid,
        call_id: "cockpit-call".into(),
        parent_call_id: None,
        parent_child_index: None,
        provider_item_id: Some("provider-item".into()),
        provider_call_id: Some("provider-call".into()),
        provider_call_id_source: Some("provider".into()),
        wire_api: Some("responses".into()),
        provider_family: Some("codex".into()),
        timestamp: 10,
        model: "gpt-5.4".into(),
        provider: "codex-oauth".into(),
        project_id: "p".into(),
        project_root: "/proj".into(),
        agent: "Build".into(),
        tool: "read".into(),
        mcp_server: None,
        path: Some("/proj/a.rs".into()),
        recovery: Recovery::Clean,
        hard_fail: false,
        exit_code: None,
        sandbox_enabled: false,
        sandboxed: false,
        sandbox_unavailable_reason: None,
        original_input_json: json!({"path": "a.rs"}),
        wire_input_json: json!({"path": "/proj/a.rs"}),
        output: "body".into(),
        truncated: false,
        duration_ms: 3,
        cockpit_version: Some(env!("CARGO_PKG_VERSION").into()),
        llm_mode: Some("defensive".into()),
        shape_fingerprint: None,
        hint: None,
    })
    .unwrap();
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCall,
        Some("Build"),
        Some("cockpit-call"),
        &json!({
            "tool": "read",
            "original_input": {"path": "a.rs"},
            "wire_input": {"path": "/proj/a.rs"},
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let tool_call = events
        .iter()
        .find(|e| e["type"] == "tool_call")
        .expect("tool_call event present");

    assert_eq!(
        tool_call["data"]["provider_identity"],
        json!({
            "cockpit_call_id": "cockpit-call",
            "provider_item_id": "provider-item",
            "provider_call_id": "provider-call",
            "provider_call_id_source": "provider",
            "wire_api": "responses",
            "provider_family": "codex",
        })
    );
}

#[test]
fn export_completions_wire_tool_call_event_includes_provider_identity() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    let providers = crate::config::providers::ProvidersConfig {
        providers: [(
            "openrouter".to_string(),
            crate::config::providers::ProviderEntry {
                template: Some("openrouter".to_string()),
                url: "https://openrouter.ai/api/v1".to_string(),
                wire_api: crate::config::providers::WireApi::Completions,
                ..crate::config::providers::ProviderEntry::default()
            },
        )]
        .into_iter()
        .collect(),
        ..crate::config::providers::ProvidersConfig::default()
    };
    let identity = ToolCallProviderIdentity::from_provider_call(
        Some("openrouter"),
        Some("anthropic/claude"),
        Some(&providers),
        Some(providers.resolve_wire_api("openrouter", "anthropic/claude")),
        "provider-chat-call".into(),
        None,
    );

    db.insert_tool_call(&ToolCallEvent {
        event_id: Uuid::new_v4(),
        session_id: sid,
        call_id: "cockpit-completions-call".into(),
        parent_call_id: None,
        parent_child_index: None,
        provider_item_id: identity.provider_item_id.clone(),
        provider_call_id: identity.provider_call_id.clone(),
        provider_call_id_source: identity.provider_call_id_source.clone(),
        wire_api: identity.wire_api.clone(),
        provider_family: identity.provider_family.clone(),
        timestamp: 10,
        model: "anthropic/claude".into(),
        provider: "openrouter".into(),
        project_id: "p".into(),
        project_root: "/proj".into(),
        agent: "Build".into(),
        tool: "read".into(),
        mcp_server: None,
        path: Some("/proj/a.rs".into()),
        recovery: Recovery::Clean,
        hard_fail: false,
        exit_code: None,
        sandbox_enabled: false,
        sandboxed: false,
        sandbox_unavailable_reason: None,
        original_input_json: json!({"path": "a.rs"}),
        wire_input_json: json!({"path": "/proj/a.rs"}),
        output: "body".into(),
        truncated: false,
        duration_ms: 3,
        cockpit_version: Some(env!("CARGO_PKG_VERSION").into()),
        llm_mode: Some("normal".into()),
        shape_fingerprint: None,
        hint: None,
    })
    .unwrap();
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCall,
        Some("Build"),
        Some("cockpit-completions-call"),
        &json!({
            "tool": "read",
            "original_input": {"path": "a.rs"},
            "wire_input": {"path": "/proj/a.rs"},
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let tool_call = events
        .iter()
        .find(|e| e["type"] == "tool_call")
        .expect("tool_call event present");

    assert_eq!(
        tool_call["data"]["provider_identity"],
        json!({
            "cockpit_call_id": "cockpit-completions-call",
            "provider_item_id": "provider-chat-call",
            "provider_call_id": "provider-chat-call",
            "provider_call_id_source": "completions_tool_call_id",
            "wire_api": "completions",
            "provider_family": "openrouter",
        })
    );
}

#[test]
fn export_synthetic_seed_tool_call_event_includes_provider_identity() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    let identity = ToolCallProviderIdentity::synthetic_cockpit_call(
        "seed-export",
        Some(crate::config::providers::WireApi::Responses),
    );

    db.insert_tool_call(&ToolCallEvent {
        event_id: Uuid::new_v4(),
        session_id: sid,
        call_id: "seed-export".into(),
        parent_call_id: None,
        parent_child_index: None,
        provider_item_id: identity.provider_item_id.clone(),
        provider_call_id: identity.provider_call_id.clone(),
        provider_call_id_source: identity.provider_call_id_source.clone(),
        wire_api: identity.wire_api.clone(),
        provider_family: identity.provider_family.clone(),
        timestamp: 10,
        model: "gpt-5.4".into(),
        provider: "codex-oauth".into(),
        project_id: "p".into(),
        project_root: "/proj".into(),
        agent: "Build".into(),
        tool: "read".into(),
        mcp_server: None,
        path: Some("/proj/seed.txt".into()),
        recovery: Recovery::Clean,
        hard_fail: false,
        exit_code: None,
        sandbox_enabled: false,
        sandboxed: false,
        sandbox_unavailable_reason: None,
        original_input_json: json!({"path": "seed.txt"}),
        wire_input_json: json!({"path": "seed.txt"}),
        output: "seed body".into(),
        truncated: false,
        duration_ms: 3,
        cockpit_version: Some(env!("CARGO_PKG_VERSION").into()),
        llm_mode: Some("normal".into()),
        shape_fingerprint: None,
        hint: None,
    })
    .unwrap();
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCall,
        Some("Build"),
        Some("seed-export"),
        &json!({
            "tool": "read",
            "original_input": {"path": "seed.txt"},
            "wire_input": {"path": "seed.txt"},
            "seed": true,
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events = zip_events(&zip);
    let seed = events
        .iter()
        .find(|event| event["type"] == "tool_call" && event["call_id"] == "seed-export")
        .expect("seed tool_call event present");

    assert_eq!(seed["data"]["seed"], true);
    assert_eq!(
        seed["data"]["provider_identity"],
        json!({
            "cockpit_call_id": "seed-export",
            "provider_item_id": "seed-export",
            "provider_call_id": "seed-export",
            "provider_call_id_source": "synthetic_from_cockpit_call_id",
            "wire_api": "responses",
            "provider_family": "cockpit",
        })
    );
}

#[test]
fn export_responses_single_task_has_provider_identity_without_resume_repair() {
    let session = responses_session_with_intro();
    record_responses_task_pair(
        &session,
        "task-single",
        "call-provider-single",
        "default",
        "explore",
        true,
    );

    let zip = build_session_zip(&session);
    assert_manifest_has_no_resume_repair(&zip);
    let events = zip_events(&zip);
    assert_task_event_identity(
        &events,
        "subagent_spawned",
        "task-single",
        "default",
        "call-provider-single",
    );
    assert_task_event_identity(
        &events,
        "subagent_report",
        "task-single",
        "default",
        "call-provider-single",
    );
}

#[test]
fn export_responses_batch_task_has_provider_identity_without_resume_repair() {
    let session = responses_session_with_intro();
    record_responses_task_pair(
        &session,
        "task-batch",
        "call-provider-batch",
        "alpha",
        "explore",
        true,
    );
    record_responses_task_pair(
        &session,
        "task-batch",
        "call-provider-batch",
        "beta",
        "docs",
        true,
    );

    let zip = build_session_zip(&session);
    assert_manifest_has_no_resume_repair(&zip);
    let events = zip_events(&zip);
    for label in ["alpha", "beta"] {
        assert_task_event_identity(
            &events,
            "subagent_spawned",
            "task-batch",
            label,
            "call-provider-batch",
        );
        assert_task_event_identity(
            &events,
            "subagent_report",
            "task-batch",
            label,
            "call-provider-batch",
        );
    }
}

#[test]
fn export_responses_interactive_subagent_has_provider_identity_without_resume_repair() {
    let session = responses_session_with_intro();
    record_responses_task_pair(
        &session,
        "task-interactive",
        "call-provider-interactive",
        "default",
        "explore",
        false,
    );

    let zip = build_session_zip(&session);
    assert_manifest_has_no_resume_repair(&zip);
    let events = zip_events(&zip);
    assert_task_event_identity(
        &events,
        "subagent_spawned",
        "task-interactive",
        "default",
        "call-provider-interactive",
    );
    assert_task_event_identity(
        &events,
        "subagent_report",
        "task-interactive",
        "default",
        "call-provider-interactive",
    );
    let spawn = events
        .iter()
        .find(|event| event["type"] == "subagent_spawned" && event["call_id"] == "task-interactive")
        .expect("interactive spawn event present");
    assert_eq!(spawn["data"]["noninteractive"], false);
}

#[test]
fn export_rejects_invalid_responses_provider_identity() {
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db, PathBuf::from("/proj"), "Build").unwrap();
    session.set_active_model("codex-oauth", "gpt-5.4").unwrap();
    session
        .record_event(
            SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &json!({ "text": "read the file" }),
        )
        .unwrap();
    session
        .record_event(
            SessionEventKind::AssistantMessage,
            Some("Build"),
            Some("infer-1"),
            &json!({ "text": "I'll inspect it." }),
        )
        .unwrap();
    session
        .record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: "call-without-provider-id".into(),
            parent_call_id: None,
            parent_child_index: None,
            identity: ToolCallProviderIdentity {
                wire_api: Some("responses".into()),
                provider_family: Some("codex".into()),
                ..ToolCallProviderIdentity::default()
            },
            tool: "read".into(),
            mcp_server: None,
            path: None,
            original_input_json: json!({"path": "a.rs"}),
            wire_input_json: json!({"path": "/proj/a.rs"}),
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: "body".into(),
            truncated: false,
            duration_ms: 1,
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        })
        .unwrap();
    session
        .record_event(
            SessionEventKind::ToolCall,
            Some("Build"),
            Some("call-without-provider-id"),
            &json!({
                "tool": "read",
                "original_input": {"path": "a.rs"},
                "wire_input": {"path": "/proj/a.rs"},
                "output": "body",
            }),
        )
        .unwrap();

    let target = session.db.get_session(session.id).unwrap().unwrap();
    let bundle = collect_bundle(&session.db, session.id).unwrap();
    let err = build_zip(&session.db, &target, &bundle).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid provider identity"), "{msg}");
    assert!(msg.contains("call-without-provider-id"), "{msg}");
}

#[test]
fn export_sanitizes_inference_request_call_id_filename_segment() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    let call_id = "call/../evil:id?";

    db.insert_inference_request(
        call_id,
        sid,
        &json!({"model": "m", "system": "sys", "tools": [], "history": []}),
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .unwrap();
    db.insert_session_event(
        sid,
        SessionEventKind::InferenceRequest,
        Some("Build"),
        Some(call_id),
        &json!({}),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let names = entry_names(&zip);
    let request_files: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("inference_requests/"))
        .collect();
    assert_eq!(request_files.len(), 1);
    assert!(
        request_files[0].ends_with("_call_.._evil_id_.json"),
        "call id filename segment is sanitized: {request_files:?}"
    );
    assert_eq!(request_files[0].matches('/').count(), 1);

    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let file = events[0]["file"].as_str().unwrap();
    assert_eq!(file, request_files[0]);
    assert_eq!(events[0]["call_id"], call_id);
    assert!(read_zip_entry(&zip, file).is_some());
}

/// A synthetic `context_pruned` event flows through the recorder API
/// and appears in an exported `events.json`, ordered immediately
/// before the next `inference_request`.
#[test]
fn export_includes_context_pruned_before_next_inference_request() {
    use crate::session::Session;
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), PathBuf::from("/proj"), "builder").unwrap();
    let sid = session.id;

    // Recorder API (Part C): synthetic prune, then a request — the
    // adjacency the export audit depends on.
    session
        .record_context_pruned(
            "builder",
            true,
            6,
            6,
            1200,
            400,
            &["c1".to_string(), "c2".to_string()],
            "exact-identity",
            800,
            Some(98_800),
            Some("cache_already_cold"),
        )
        .unwrap();
    let call = Uuid::new_v4();
    db.insert_inference_request(
        &call.to_string(),
        sid,
        &json!({"model": "m", "system": "s", "tools": [], "history": []}),
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .unwrap();
    session
        .record_event(
            SessionEventKind::InferenceRequest,
            Some("builder"),
            Some(&call.to_string()),
            &json!({"usage": null}),
        )
        .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    let events_str = read_zip_entry(&zip, "events.json").unwrap();
    let events: Vec<Value> = serde_json::from_str(&events_str).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["type"], "context_pruned");
    assert_eq!(events[1]["type"], "inference_request");
    // The context_pruned event carries the audit fields.
    let data = &events[0]["data"];
    assert_eq!(data["kind"], "prune");
    assert_eq!(data["trigger"], "auto");
    assert_eq!(data["tokens_before"], 1200);
    assert_eq!(data["tokens_after"], 400);
    assert_eq!(data["elided"], json!(["c1", "c2"]));
    // Effectiveness fields the analyzer classifies on (Part D).
    assert_eq!(data["tokens_saved"], 800);
    assert_eq!(data["remaining_budget"], 98_800);
    assert_eq!(data["reason"], "exact-identity");
    assert_eq!(data["trigger_reason"], "cache_already_cold");
}

#[test]
fn export_includes_goal_progress_diagnostic() {
    use crate::session::Session;
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), PathBuf::from("/proj"), "builder").unwrap();
    let sid = session.id;

    session
        .record_event(
            SessionEventKind::GoalProgressDiagnostic,
            Some("builder"),
            None,
            &json!({
                "kind": "goal_continue_no_progress",
                "anchor_seq": 42,
                "reason": "completed_inference_without_visible_progress",
            }),
        )
        .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "goal_progress_diagnostic");
    assert_eq!(events[0]["data"]["kind"], "goal_continue_no_progress");
    assert_eq!(events[0]["data"]["anchor_seq"], 42);
}

#[test]
fn export_includes_queued_user_fold_metadata() {
    use crate::session::Session;
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), PathBuf::from("/proj"), "builder").unwrap();
    let sid = session.id;
    let queue_id = uuid::Uuid::from_u128(7);

    session
        .record_event(
            SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &json!({
                "text": "queued while busy",
                "queued": true,
                "queue_item_ids": [queue_id],
                "queue_target": {
                    "id": "root",
                    "agent": "Build",
                    "depth": 0,
                },
                "preflight_cleaned": null,
            }),
        )
        .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["type"], "user_message");
    assert_eq!(events[0]["data"]["queued"], true);
    assert_eq!(events[0]["data"]["queue_item_ids"][0], queue_id.to_string());
    assert_eq!(events[0]["data"]["queue_target"]["agent"], "Build");
}

/// A hung/failed turn (`inference-timeout-and-failure-
/// observability.md`): the dispatch-time captured body is stored with a
/// non-`completed` status and an `inference_failure` event is recorded
/// (NO `inference_request` event). The export must (a) emit a file for the
/// failure call carrying the `timed_out` status + captured body, and
/// (b) include the failure event with provider/model/phase/class/elapsed.
#[test]
fn export_of_hung_turn_has_inference_record_and_failure_event() {
    use crate::session::Session;
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), PathBuf::from("/proj"), "builder").unwrap();
    let sid = session.id;
    let call = Uuid::new_v4();

    // Dispatch-time record settled to `timed_out` (what `turn()` writes on
    // a hang).
    db.insert_inference_request(
        &call.to_string(),
        sid,
        &json!({"model": "qwen3", "system": "s", "tools": [], "history": []}),
        crate::db::session_log::InferenceRequestStatus::TimedOut,
    )
    .unwrap();
    // The failure event (no `inference_request` event for this call).
    session
        .record_event(
            SessionEventKind::InferenceFailure,
            Some("builder"),
            Some(&call.to_string()),
            &json!({
                "provider": "openai-compatible",
                "model": "qwen3",
                "phase_reached": "dispatched",
                "error_class": "timeout_ttft",
                "elapsed_ms": 120_000,
            }),
        )
        .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    // The failure event is present with its diagnostics, and it names a
    // real file in the archive.
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let fail = events
        .iter()
        .find(|e| e["type"] == "inference_failure")
        .expect("failure event present");
    assert_eq!(fail["data"]["error_class"], "timeout_ttft");
    assert_eq!(fail["data"]["phase_reached"], "dispatched");
    let file = fail["file"].as_str().expect("failure event names a file");
    let body: Value =
        serde_json::from_str(&read_zip_entry(&zip, file).expect("file exists")).unwrap();
    // The emitted file carries the non-`completed` status + captured body.
    assert_eq!(body["status"], "timed_out");
    assert_eq!(body["request"]["model"], "qwen3");
}

/// A `/compact` successor session (a session boundary, not a fork) is
/// followed like the fork tree and lands in the same unified
/// `events.json`.
#[test]
fn export_follows_session_compacted_successor() {
    use crate::session::Session;
    let db = Db::open_in_memory().unwrap();
    let pred = Session::create(db.clone(), PathBuf::from("/proj"), "builder").unwrap();
    // The successor is a fresh session (NOT a fork — no parent link).
    let succ = Session::create(db.clone(), PathBuf::from("/proj"), "builder").unwrap();
    pred.record_session_compacted("builder", succ.id, &succ.short_id, 3, "handoff brief")
        .unwrap();
    // Each session has one inference call.
    for s in [&pred, &succ] {
        let call = Uuid::new_v4();
        db.insert_inference_request(
            &call.to_string(),
            s.id,
            &json!({"model": "m", "system": "s", "tools": [], "history": []}),
            crate::db::session_log::InferenceRequestStatus::Completed,
        )
        .unwrap();
        db.insert_session_event(
            s.id,
            SessionEventKind::InferenceRequest,
            Some("builder"),
            Some(&call.to_string()),
            &json!({}),
        )
        .unwrap();
    }

    let target = db.get_session(pred.id).unwrap().unwrap();
    let bundle = collect_bundle(&db, pred.id).unwrap();
    // Both predecessor and successor are in the bundle.
    assert_eq!(bundle.len(), 2);
    assert!(bundle.iter().any(|s| s.session_id == succ.id));

    let zip = build_zip(&db, &target, &bundle).unwrap();
    let names = entry_names(&zip);
    let req_files = names
        .iter()
        .filter(|n| n.starts_with("inference_requests/"))
        .count();
    assert_eq!(req_files, 2, "one request per session across the boundary");

    // events.json spans both sessions, tagged distinctly.
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let session_ids: HashSet<String> = events
        .iter()
        .map(|e| e["session_id"].as_str().unwrap().to_string())
        .collect();
    assert!(session_ids.contains(&pred.id.to_string()));
    assert!(session_ids.contains(&succ.id.to_string()));
}

/// A `permission_decision` event flows through the recorder API verbatim
/// (no exporter mapping needed — the export passes `data` through) and
/// lands in `events.json` with its `decision` / `source` / `target`
/// fields intact, linkable back to the tool it gated.
#[test]
fn export_includes_permission_decision_event() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "builder").unwrap();
    let sid = s.session_id;
    db.insert_session_event(
        sid,
        SessionEventKind::PermissionDecision,
        Some("builder"),
        None,
        &json!({
            "tool": "bash",
            "tool_call_id": null,
            "target": "rm -rf /",
            "offered_scopes": ["once", "session", "project", "global"],
            "decision": "deny",
            "scope": null,
            "source": "user_prompt",
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let pd = events
        .iter()
        .find(|e| e["type"] == "permission_decision")
        .expect("permission_decision event present in events.json");
    assert_eq!(pd["data"]["decision"], "deny");
    assert_eq!(pd["data"]["source"], "user_prompt");
    assert_eq!(pd["data"]["tool"], "bash");
    assert_eq!(pd["data"]["target"], "rm -rf /");
}

/// Durable approval grants explain why later tool calls may not prompt.
/// They are not event decisions, so the export includes an explicit
/// snapshot under `approvals/grants.json`.
#[test]
fn export_includes_persisted_approval_grants_snapshot() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "builder").unwrap();
    let sid = s.session_id;
    db.write_blocking(move |conn| {
        conn.execute(
            "INSERT INTO approval_grants \
                 (session_id, grant_kind, grant_key, granted_at) \
                 VALUES (?1, 'command', 'grep', ?2)",
            rusqlite::params![sid.to_string(), 1_700_000_000_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO approval_grants \
                 (session_id, grant_kind, grant_key, granted_at, access) \
                 VALUES (?1, 'path', '/tmp/example', ?2, 'read-write')",
            rusqlite::params![sid.to_string(), 1_700_000_001_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO loop_guard_rules \
                 (session_id, signature, rule_verdict, recorded_at) \
                 VALUES (?1, 'loop-hash', 'accept', ?2)",
            rusqlite::params![sid.to_string(), 1_700_000_002_i64],
        )
        .unwrap();
        Ok(())
    })
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    let approvals: Value =
        serde_json::from_str(&read_zip_entry(&zip, "approvals/grants.json").unwrap()).unwrap();
    assert_eq!(approvals["schema"], "cockpit-approval-grants/1");
    let session = &approvals["session"][0];
    assert_eq!(session["session_id"], sid.to_string());
    assert_eq!(session["grants"]["commands"], json!(["grep"]));
    assert_eq!(
        session["grants"]["paths"],
        json!([{ "key": "/tmp/example", "access": "read-write" }])
    );
    assert_eq!(session["grants"]["loop_accept"], json!(["loop-hash"]));
}

/// Export-audit fidelity (a): a `tool_rejected` event recorded through the
/// session recorder flows verbatim into `events.json` with its attempted
/// tool `name` and `reason`, so a hallucinated / unrepairable call is a
/// one-query check instead of prose inference. Both reason enum values
/// round-trip.
#[test]
fn export_includes_tool_rejected_event() {
    use crate::session::Session;
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), PathBuf::from("/proj"), "Build").unwrap();
    let sid = session.id;

    session
        .record_tool_rejected("Build", "tc-hallu", "handoff", "not_in_advertised_set")
        .unwrap();
    session
        .record_tool_rejected_with_correction(
            "Build",
            "tc-bad",
            "edit",
            "schema_invalid_unrepairable",
            Some(json!({
                "corrected_shape_hint_emitted": true,
                "correction_code": "test_shape",
                "corrected_shape_hint": "retry with {path,content}",
            })),
        )
        .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let rejected: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "tool_rejected")
        .collect();
    assert_eq!(rejected.len(), 2, "both rejections exported");
    // The hallucinated-tool rejection: name + reason both queryable, and the
    // model's per-tool-call id rides on `call_id`.
    let hallu = rejected
        .iter()
        .find(|e| e["data"]["reason"] == "not_in_advertised_set")
        .expect("not_in_advertised_set rejection present");
    assert_eq!(hallu["data"]["tool"], "handoff");
    assert_eq!(hallu["call_id"], "tc-hallu");
    // The unrepairable-schema rejection.
    let bad = rejected
        .iter()
        .find(|e| e["data"]["reason"] == "schema_invalid_unrepairable")
        .expect("schema_invalid_unrepairable rejection present");
    assert_eq!(bad["data"]["tool"], "edit");
    assert_eq!(
        bad["data"]["validation_correction"]["corrected_shape_hint_emitted"],
        true
    );
    assert_eq!(
        bad["data"]["validation_correction"]["corrected_shape_hint"],
        "retry with {path,content}"
    );
}

/// Export-audit fidelity (b): a `primary_swap` event records BOTH halves of
/// the wire-vs-user split (GOALS §14) — the user-facing `display` and the
/// model-facing wire `kickoff` — plus from/to/trigger. The `handoff` path
/// carries a kickoff; a `/plan`/`/build`/`/swarm` slash-command swap
/// injects none, so its `kickoff` is null (never fabricated).
#[test]
fn export_includes_primary_swap_event_both_halves() {
    use crate::session::Session;
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), PathBuf::from("/proj"), "Auto").unwrap();
    let sid = session.id;

    // Handoff swap: both display and kickoff present.
    session
        .record_primary_swap(
            "Auto",
            "Build",
            "handoff",
            Some("Handed off to `Build`."),
            Some("User's request:\nfix the bug\n\nBegin now."),
        )
        .unwrap();
    // Slash-command swap: no kickoff injected.
    session
        .record_primary_swap("Build", "Plan", "swap_command", None, None)
        .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let swaps: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "primary_swap")
        .collect();
    assert_eq!(swaps.len(), 2);

    let handoff = swaps
        .iter()
        .find(|e| e["data"]["trigger"] == "handoff")
        .expect("handoff swap present");
    assert_eq!(handoff["data"]["from"], "Auto");
    assert_eq!(handoff["data"]["to"], "Build");
    // BOTH the user-facing display AND the wire kickoff are recorded.
    assert_eq!(handoff["data"]["display"], "Handed off to `Build`.");
    assert!(
        handoff["data"]["kickoff"]
            .as_str()
            .unwrap()
            .contains("Begin now"),
        "wire kickoff text preserved"
    );

    let cmd = swaps
        .iter()
        .find(|e| e["data"]["trigger"] == "swap_command")
        .expect("slash-command swap present");
    assert_eq!(cmd["data"]["from"], "Build");
    assert_eq!(cmd["data"]["to"], "Plan");
    // No kickoff injected for a slash-command swap — null, not fabricated.
    assert!(cmd["data"]["kickoff"].is_null());
    assert!(cmd["data"]["display"].is_null());
}

fn build_model_switch_zip(
    trigger: crate::session::ModelSwitchTrigger,
    outcome: crate::session::ModelSwitchOutcome,
    error: Option<&str>,
) -> Vec<u8> {
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), PathBuf::from("/proj"), "Build").unwrap();
    session.set_active_model("provider-a", "model-a").unwrap();
    session
        .record_model_switch(crate::session::ModelSwitchAudit {
            from_provider: Some("provider-a"),
            from_model: Some("model-a"),
            to_provider: "provider-b",
            to_model: "model-b",
            trigger,
            outcome,
            error,
        })
        .unwrap();
    let target = db.get_session(session.id).unwrap().unwrap();
    let bundle = collect_bundle(&db, session.id).unwrap();
    build_zip(&db, &target, &bundle).unwrap()
}

fn only_model_switch_event(zip: &[u8]) -> Value {
    let events = zip_events(zip);
    events
        .into_iter()
        .find(|event| event["type"] == "model_switch")
        .expect("model_switch event exported")
}

#[test]
fn export_includes_model_switch_event_payload_shape() {
    let zip = build_model_switch_zip(
        crate::session::ModelSwitchTrigger::Picker,
        crate::session::ModelSwitchOutcome::Ok,
        None,
    );
    let event = only_model_switch_event(&zip);
    let data = event["data"].as_object().expect("model_switch data object");
    let mut keys = data.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "error",
            "from_model",
            "from_provider",
            "outcome",
            "to_model",
            "to_provider",
            "trigger",
        ]
    );
    assert_eq!(event["type"], "model_switch");
    assert_eq!(event["data"]["from_provider"], "provider-a");
    assert_eq!(event["data"]["from_model"], "model-a");
    assert_eq!(event["data"]["to_provider"], "provider-b");
    assert_eq!(event["data"]["to_model"], "model-b");
    assert_eq!(event["data"]["trigger"], "picker");
    assert_eq!(event["data"]["outcome"], "ok");
    assert!(event["data"]["error"].is_null());
}

#[test]
fn export_includes_model_switch_ok_event() {
    let zip = build_model_switch_zip(
        crate::session::ModelSwitchTrigger::Picker,
        crate::session::ModelSwitchOutcome::Ok,
        None,
    );
    let event = only_model_switch_event(&zip);
    assert_eq!(event["data"]["outcome"], "ok");
    assert!(event["data"]["error"].is_null());
}

#[test]
fn export_includes_model_switch_build_failed_event() {
    let zip = build_model_switch_zip(
        crate::session::ModelSwitchTrigger::Picker,
        crate::session::ModelSwitchOutcome::BuildFailed,
        Some("provider not configured"),
    );
    let event = only_model_switch_event(&zip);
    assert_eq!(event["data"]["outcome"], "build_failed");
    assert_eq!(event["data"]["error"], "provider not configured");
}

#[test]
fn export_includes_model_switch_send_failed_event() {
    let zip = build_model_switch_zip(
        crate::session::ModelSwitchTrigger::Picker,
        crate::session::ModelSwitchOutcome::SendFailed,
        Some("config write failed"),
    );
    let event = only_model_switch_event(&zip);
    assert_eq!(event["data"]["outcome"], "send_failed");
    assert_eq!(event["data"]["error"], "config write failed");
}

#[test]
fn export_includes_model_switch_noop_event() {
    let zip = build_model_switch_zip(
        crate::session::ModelSwitchTrigger::Picker,
        crate::session::ModelSwitchOutcome::Noop,
        None,
    );
    let event = only_model_switch_event(&zip);
    assert_eq!(event["data"]["outcome"], "noop");
    assert!(event["data"]["error"].is_null());
}

#[test]
fn export_model_switch_event_records_all_triggers() {
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), PathBuf::from("/proj"), "Build").unwrap();
    session.set_active_model("provider-a", "model-a").unwrap();
    for trigger in [
        crate::session::ModelSwitchTrigger::Picker,
        crate::session::ModelSwitchTrigger::Quick,
        crate::session::ModelSwitchTrigger::Cycle,
        crate::session::ModelSwitchTrigger::Daemon,
    ] {
        session
            .record_model_switch(crate::session::ModelSwitchAudit {
                from_provider: Some("provider-a"),
                from_model: Some("model-a"),
                to_provider: "provider-b",
                to_model: "model-b",
                trigger,
                outcome: crate::session::ModelSwitchOutcome::Ok,
                error: None,
            })
            .unwrap();
    }
    let target = db.get_session(session.id).unwrap().unwrap();
    let bundle = collect_bundle(&db, session.id).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let triggers = zip_events(&zip)
        .into_iter()
        .filter(|event| event["type"] == "model_switch")
        .map(|event| event["data"]["trigger"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(triggers, vec!["picker", "quick", "cycle", "daemon"]);
}

/// Export-audit fidelity (c): a `bash` `tool_call` event carries the
/// authoritative structured `exit_code` field, distinct from the
/// human-readable `exit: N` text kept in `output` for backward
/// compatibility. Resource scheduler metadata rides alongside it as
/// out-of-band event data.
#[test]
fn export_bash_tool_call_carries_exit_code_field() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    // A failing bash call: the event data the dispatcher writes today plus
    // the new authoritative `exit_code` field.
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCall,
        Some("Build"),
        Some("tc-bash"),
        &json!({
            "tool": "bash",
            "original_input": {"command": "false"},
            "wire_input": {"command": "false"},
            "recovery_kind": "clean",
            "recovery_stage": null,
            "hard_fail": false,
            "output": "exit: 1\n",
            "truncated": false,
            "duration_ms": 3,
            "exit_code": 1,
            "resource": {
                "declared": {"cpu": 1},
                "policy": {"memory": 1},
                "reviewer": {},
                "effective": {"cpu": 1, "memory": 1},
                "scheduler_request_id": "req-1",
                "scheduler_display_id": "R1",
                "lease_id": "req-1",
                "queue_position": 1,
                "queue_timeout_ms": 50,
                "queued_at_ms": 10,
                "acquired_at_ms": 15,
                "wait_ms": 5,
                "acquired": true,
                "released_on_drop": true
            },
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let bash = events
        .iter()
        .find(|e| e["type"] == "tool_call" && e["data"]["tool"] == "bash")
        .expect("bash tool_call present");
    // Authoritative structured field.
    assert_eq!(bash["data"]["exit_code"], 1);
    // Human-readable text still present for backward compatibility.
    assert!(
        bash["data"]["output"].as_str().unwrap().contains("exit: 1"),
        "human-readable exit line kept"
    );
    assert_eq!(bash["data"]["resource"]["effective"]["cpu"], 1);
    assert_eq!(bash["data"]["resource"]["scheduler_request_id"], "req-1");
    assert_eq!(bash["data"]["resource"]["wait_ms"], 5);
}

#[test]
fn export_tool_lifecycle_events_distinguish_start_and_completion() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCallStarted,
        Some("Build"),
        Some("tc-bash"),
        &json!({
            "tool": "bash",
            "original_input": {"command": "true"},
            "wire_input": {"command": "true"},
            "recovery_kind": "clean",
            "recovery_stage": null,
        }),
    )
    .unwrap();
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCallCompleted,
        Some("Build"),
        Some("tc-bash"),
        &json!({
            "tool": "bash",
            "status": "completed",
            "dispatched": true,
            "hard_fail": false,
            "output": "exit: 0\n",
            "truncated": false,
            "duration_ms": 4,
            "exit_code": 0,
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();

    let started = events
        .iter()
        .find(|e| e["type"] == "tool_call_started")
        .expect("started event present");
    assert_eq!(started["call_id"], "tc-bash");
    assert_eq!(started["data"]["original_input"]["command"], "true");
    assert!(started["data"].get("output").is_none());

    let completed = events
        .iter()
        .find(|e| e["type"] == "tool_call_completed")
        .expect("completed event present");
    assert_eq!(completed["data"]["status"], "completed");
    assert_eq!(completed["data"]["dispatched"], true);
    assert_eq!(completed["data"]["exit_code"], 0);
}

#[test]
fn export_includes_notice_events() {
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), PathBuf::from("/proj"), "Build").unwrap();
    session
        .record_event(
            SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &json!({ "text": "start" }),
        )
        .unwrap();
    session
        .record_notice(Some("Build"), "Model fallback applied.", "engine_turn")
        .unwrap();
    session
        .record_event(
            SessionEventKind::AssistantMessage,
            Some("Build"),
            None,
            &json!({ "text": "done" }),
        )
        .unwrap();

    let target = db.get_session(session.id).unwrap().unwrap();
    let bundle = collect_bundle(&db, session.id).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events = zip_events(&zip);
    let event_types: Vec<&str> = events
        .iter()
        .map(|event| event["type"].as_str().unwrap())
        .collect();
    assert_eq!(event_types, ["user_message", "notice", "assistant_message"]);
    let notice = events
        .iter()
        .find(|event| event["type"] == "notice")
        .expect("notice event present");
    assert_eq!(notice["data"]["text"], "Model fallback applied.");
    assert_eq!(notice["data"]["severity"], "info");
    assert_eq!(notice["data"]["source"], "engine_turn");
}

#[test]
fn export_labels_orphaned_tool_call_started() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCallStarted,
        Some("Build"),
        Some("tc-open"),
        &json!({
            "tool": "bash",
            "original_input": {"command": "sleep 10"},
            "wire_input": {"command": "sleep 10"},
            "recovery_kind": "clean",
            "recovery_stage": null,
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events = zip_events(&zip);
    let started = events
        .iter()
        .find(|event| event["type"] == "tool_call_started")
        .expect("started event present");
    assert_eq!(started["data"]["orphaned"], true);
}

#[test]
fn export_does_not_label_completed_tool_call_started() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCallStarted,
        Some("Build"),
        Some("tc-done"),
        &json!({
            "tool": "bash",
            "original_input": {"command": "true"},
            "wire_input": {"command": "true"},
            "recovery_kind": "clean",
            "recovery_stage": null,
        }),
    )
    .unwrap();
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCallCompleted,
        Some("Build"),
        Some("tc-done"),
        &json!({
            "tool": "bash",
            "status": "completed",
            "dispatched": true,
            "hard_fail": false,
            "output": "",
            "truncated": false,
            "duration_ms": 1,
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events = zip_events(&zip);
    let started = events
        .iter()
        .find(|event| event["type"] == "tool_call_started")
        .expect("started event present");
    assert!(started["data"].get("orphaned").is_none());
}

#[test]
fn export_orphan_detection_is_bundle_scoped() {
    let db = Db::open_in_memory().unwrap();
    let parent = db.create_session("p", "/proj", "Build").unwrap();
    let child = db.create_fork(parent.session_id, None).unwrap();
    db.insert_session_event(
        parent.session_id,
        SessionEventKind::ToolCallStarted,
        Some("Build"),
        Some("tc-cross"),
        &json!({
            "tool": "bash",
            "original_input": {"command": "true"},
            "wire_input": {"command": "true"},
            "recovery_kind": "clean",
            "recovery_stage": null,
        }),
    )
    .unwrap();
    db.insert_session_event(
        child.session_id,
        SessionEventKind::ToolCallCompleted,
        Some("Build"),
        Some("tc-cross"),
        &json!({
            "tool": "bash",
            "status": "completed",
            "dispatched": true,
            "hard_fail": false,
            "output": "",
            "truncated": false,
            "duration_ms": 1,
        }),
    )
    .unwrap();

    let target = db.get_session(parent.session_id).unwrap().unwrap();
    let bundle = collect_bundle(&db, parent.session_id).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events = zip_events(&zip);
    let started = events
        .iter()
        .find(|event| event["type"] == "tool_call_started")
        .expect("started event present");
    assert!(started["data"].get("orphaned").is_none());
}

#[test]
fn export_tool_lifecycle_blocked_completion_is_not_dispatched() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCallStarted,
        Some("Build"),
        Some("tc-blocked"),
        &json!({
            "tool": "bash",
            "original_input": {"command": "curl https://example.com"},
            "wire_input": {"command": "curl https://example.com"},
            "recovery_kind": "clean",
            "recovery_stage": null,
        }),
    )
    .unwrap();
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCallCompleted,
        Some("Build"),
        Some("tc-blocked"),
        &json!({
            "tool": "bash",
            "status": "blocked_safety_gate",
            "dispatched": false,
            "hard_fail": true,
            "output": "Error: blocked by safety gate",
            "truncated": false,
            "duration_ms": 0,
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();

    let completed = events
        .iter()
        .find(|e| e["type"] == "tool_call_completed")
        .expect("completed event present");
    assert_eq!(completed["data"]["status"], "blocked_safety_gate");
    assert_eq!(completed["data"]["dispatched"], false);
    assert!(completed["data"].get("exit_code").is_none());
}

#[test]
fn export_tool_output_sidecar_writes_file_and_keeps_event_bounded() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    let full_stdout = "line\n".repeat(3000);
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCall,
        Some("Build"),
        Some("tc-long"),
        &json!({
            "tool": "bash",
            "original_input": {"command": "cargo test"},
            "wire_input": {"command": "cargo test"},
            "recovery_kind": "clean",
            "recovery_stage": null,
            "hard_fail": false,
            "output": "... [truncated 12000 bytes] ...\nexit: 0\n",
            "truncated": true,
            "duration_ms": 5,
            "exit_code": 0,
            "output_sidecar": {
                "kind": "bash_output",
                "command": "cargo test",
                "cwd": "/proj",
                "exit_code": 0,
                "signaled": false,
                "success": true,
                "stdout": full_stdout,
                "stderr": "",
                "rendered_output": "stdout omitted from event",
                "display": {
                    "cap_bytes": 8192,
                    "truncated": true,
                    "rendered_bytes": 16000
                }
            }
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let event = events
        .iter()
        .find(|e| e["type"] == "tool_call")
        .expect("tool_call event present");
    let output_file = event["output_file"]
        .as_str()
        .expect("tool output sidecar file ref");
    assert!(output_file.starts_with("tool_outputs/"));
    assert!(event["data"].get("output_sidecar").is_none());
    assert!(
        event["data"]["output"]
            .as_str()
            .unwrap()
            .contains("truncated")
    );

    let sidecar: Value = serde_json::from_str(&read_zip_entry(&zip, output_file).unwrap()).unwrap();
    assert_eq!(sidecar["command"], "cargo test");
    assert_eq!(sidecar["stdout"].as_str().unwrap(), full_stdout);
    assert_eq!(sidecar["display"]["truncated"], true);
}

#[test]
fn export_compressed_tool_results_writes_index_and_payload() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    db.insert_compressed_tool_result(
        "0123456789abcdefabcdef12",
        crate::db::compressed_results::NewCompressedToolResult {
            session_id: sid,
            agent_id: "Build",
            tool: "bash",
            call_id: "tc-long",
            original_byte_len: 15,
            compressed_byte_len: Some(5),
            created_at: 123,
            kind: "truncated",
            content: "redacted output",
        },
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let names = entry_names(&zip);
    assert!(
        names
            .iter()
            .any(|n| n == "compressed_tool_results/index.json")
    );
    let index: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "compressed_tool_results/index.json").unwrap())
            .unwrap();
    assert_eq!(index[0]["hash"], "0123456789abcdefabcdef12");
    assert_eq!(index[0]["tool"], "bash");
    assert_eq!(index[0]["original_byte_len"], 15);
    assert_eq!(index[0]["compressed_byte_len"], 5);
    assert_ne!(
        index[0]["original_byte_len"],
        index[0]["compressed_byte_len"]
    );
    let file = index[0]["file"].as_str().unwrap();
    assert_eq!(read_zip_entry(&zip, file).unwrap(), "redacted output");
}

#[test]
fn export_truncate_only_result_omits_compressed_byte_len() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    db.insert_compressed_tool_result(
        "fedcba987654321001234567",
        crate::db::compressed_results::NewCompressedToolResult {
            session_id: sid,
            agent_id: "Build",
            tool: "tree",
            call_id: "tc-truncated",
            original_byte_len: 128,
            compressed_byte_len: None,
            created_at: 124,
            kind: "truncated",
            content: "retained pre-truncation body",
        },
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let index: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "compressed_tool_results/index.json").unwrap())
            .unwrap();

    assert_eq!(index[0]["kind"], "truncated");
    assert_eq!(index[0]["original_byte_len"], 128);
    assert!(index[0].get("compressed_byte_len").is_none());
    let file = index[0]["file"].as_str().unwrap();
    assert_eq!(
        read_zip_entry(&zip, file).unwrap(),
        "retained pre-truncation body"
    );
}

#[test]
fn export_task_delegation_payloads_writes_bounded_index_and_payload() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    db.upsert_task_delegation_job(
        sid,
        "task-long",
        Some("fn-long"),
        "Build",
        None,
        &[crate::db::task_delegations::DelegationChildInit {
            label: "alpha",
            child_agent: "explore",
            model: None,
            output_dir: None,
            requested_cwd: None,
            resolved_cwd: None,
            todo_ids_json: None,
        }],
    )
    .unwrap();
    let body = "x".repeat(800);
    db.insert_task_delegation_payload(
        crate::db::task_delegation_payloads::NewTaskDelegationPayload {
            task_call_id: "task-long",
            function_call_id: Some("fn-long"),
            parent_session_id: sid,
            parent_agent: "Build",
            label: "alpha",
            child_agent: "explore",
            prompt: &body,
        },
    )
    .unwrap();
    db.mark_task_delegation_payload_delivered("task-long", "alpha")
        .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let names = entry_names(&zip);
    assert!(names.iter().any(|n| n == "delegation_payloads/index.json"));
    let index: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "delegation_payloads/index.json").unwrap())
            .unwrap();
    assert_eq!(index[0]["task_call_id"], "task-long");
    assert_eq!(index[0]["label"], "alpha");
    assert_eq!(index[0]["prompt_byte_len"], body.len());
    assert_eq!(index[0]["delivered"], true);
    assert!(index[0]["payload_hash"].as_str().unwrap().len() == 64);
    assert_eq!(index[0]["excerpt"].as_str().unwrap().chars().count(), 512);
    let file = index[0]["file"].as_str().unwrap();
    assert_eq!(read_zip_entry(&zip, file).unwrap(), body);
}

#[test]
fn export_task_delegation_steers_includes_origin_and_redacted_body() {
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join(".cockpit")).unwrap();
    std::fs::write(
            tmp.path().join(".cockpit/config.json"),
            r#"{"redact":{"scan_environment":false,"scan_dotenv":false,"denylist":["SECRET_STEER_TOKEN"]}}"#,
        )
        .unwrap();
    let db = Db::open_in_memory().unwrap();
    let s = db
        .create_session("p", tmp.path().to_string_lossy().as_ref(), "Build")
        .unwrap();
    let sid = s.session_id;
    db.upsert_task_delegation_job(
        sid,
        "task-steer",
        Some("fn-steer"),
        "Build",
        None,
        &[crate::db::task_delegations::DelegationChildInit {
            label: "alpha",
            child_agent: "explore",
            model: None,
            output_dir: None,
            requested_cwd: None,
            resolved_cwd: None,
            todo_ids_json: None,
        }],
    )
    .unwrap();
    db.enqueue_task_delegation_steer(
        "task-steer",
        "alpha",
        "use SECRET_STEER_TOKEN",
        "local:tester",
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let names = entry_names(&zip);
    assert!(names.iter().any(|n| n == "delegation_steers/index.json"));
    let index: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "delegation_steers/index.json").unwrap())
            .unwrap();
    assert_eq!(index[0]["task_call_id"], "task-steer");
    assert_eq!(index[0]["label"], "alpha");
    assert_eq!(index[0]["origin_principal"], "local:tester");
    assert_eq!(index[0]["delivered"], false);
    let body = index[0]["body"].as_str().unwrap();
    assert!(!body.contains("SECRET_STEER_TOKEN"));
    assert!(body.contains("REDACTED"));
}

/// Additive backward compatibility: an OLDER export — events with none of
/// the new types/fields (no `tool_rejected`, no `primary_swap`, a `bash`
/// `tool_call` with no `exit_code`) — still parses unchanged, and a
/// consumer that filters for the new shapes simply finds nothing rather
/// than failing.
#[test]
fn export_older_events_without_new_fields_still_parse() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    // A pre-feature bash tool_call: no `exit_code` key at all.
    db.insert_session_event(
        sid,
        SessionEventKind::ToolCall,
        Some("Build"),
        Some("tc-old"),
        &json!({
            "tool": "bash",
            "original_input": {"command": "true"},
            "wire_input": {"command": "true"},
            "recovery_kind": "clean",
            "recovery_stage": null,
            "hard_fail": false,
            "output": "exit: 0\n",
            "truncated": false,
            "duration_ms": 1,
        }),
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    // Parses fine.
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    // None of the new event types appear.
    assert!(events.iter().all(|e| e["type"] != "tool_rejected"));
    assert!(events.iter().all(|e| e["type"] != "primary_swap"));
    assert!(events.iter().all(|e| e["type"] != "model_switch"));
    // The old bash event simply has no `exit_code` key (absent, not null).
    let bash = events
        .iter()
        .find(|e| e["type"] == "tool_call")
        .expect("tool_call present");
    assert!(
        bash["data"].get("exit_code").is_none(),
        "older export carries no exit_code key"
    );
    // Schema is still /1 — no version bump for the additive change.
    let manifest: Value =
        serde_json::from_str(&read_zip_entry(&zip, "manifest.json").unwrap()).unwrap();
    assert_eq!(manifest["schema"], "cockpit-session-export/1");
}

#[test]
fn resolve_unknown_short_id_is_usage_error() {
    let db = Db::open_in_memory().unwrap();
    let r = resolve_session(&db, "zzzzzz").unwrap();
    assert!(r.is_err(), "unknown short id must be a usage error");
}

#[test]
fn resolve_accepts_uuid_and_short_id() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/x", "builder").unwrap();
    let short = s.short_id.clone().unwrap();
    // By short id.
    assert_eq!(
        resolve_session(&db, &short).unwrap().unwrap().session_id,
        s.session_id
    );
    // By full UUID.
    assert_eq!(
        resolve_session(&db, &s.session_id.to_string())
            .unwrap()
            .unwrap()
            .session_id,
        s.session_id
    );
    // Unknown UUID is a usage error, not a crash.
    assert!(
        resolve_session(&db, &Uuid::new_v4().to_string())
            .unwrap()
            .is_err()
    );
}

/// End-to-end: the zip is written to disk under the default name, and
/// re-writing without `--force` refuses to clobber.
#[test]
fn build_zip_writes_to_disk_and_manifest_lists_sessions() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "builder").unwrap();
    let call = Uuid::new_v4();
    db.insert_inference_request(
        &call.to_string(),
        s.session_id,
        &json!({"model": "m", "system": "s", "tools": [], "history": []}),
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .unwrap();
    db.insert_session_event(
        s.session_id,
        SessionEventKind::InferenceRequest,
        Some("builder"),
        Some(&call.to_string()),
        &json!({}),
    )
    .unwrap();

    let target = db.get_session(s.session_id).unwrap().unwrap();
    let bundle = collect_bundle(&db, s.session_id).unwrap();
    let bytes = build_zip(&db, &target, &bundle).unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join(default_output_path(&target));
    std::fs::write(&out, &bytes).unwrap();
    assert!(out.exists());
    // Clobber guard: a second write without `--force` must be refused.
    assert!(out.exists(), "exists() drives the clobber guard");

    // Manifest round-trips and lists the session.
    let manifest: Value =
        serde_json::from_str(&read_zip_entry(&bytes, "manifest.json").unwrap()).unwrap();
    assert_eq!(manifest["schema"], "cockpit-session-export/1");
    assert_eq!(manifest["session_count"], 1);
    assert_eq!(
        manifest["target"]["short_id"],
        json!(target.short_id.clone().unwrap())
    );
}

/// The shared `write_bundle_zip` is the one implementation behind the
/// CLI and the TUI debug export. `overwrite = false` preserves the
/// CLI's no-clobber-without-`--force` guarantee; `overwrite = true`
/// (the TUI path, which has no force flag) replaces the prior file.
/// It also creates the export directory if missing.
#[test]
fn write_bundle_zip_overwrite_mode_vs_clobber_guard() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "builder").unwrap();
    let call = Uuid::new_v4();
    db.insert_inference_request(
        &call.to_string(),
        s.session_id,
        &json!({"model": "m", "system": "s", "tools": [], "history": []}),
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .unwrap();
    db.insert_session_event(
        s.session_id,
        SessionEventKind::InferenceRequest,
        Some("builder"),
        Some(&call.to_string()),
        &json!({}),
    )
    .unwrap();
    let target = db.get_session(s.session_id).unwrap().unwrap();

    let tmp = tempfile::tempdir().unwrap();
    // A nested dir that does not exist yet — the writer must create it.
    let out = tmp.path().join(".cockpit").join("exports").join("x.zip");
    assert!(!out.parent().unwrap().exists());

    // First write succeeds and creates the directory.
    let summary = write_bundle_zip(&db, &target, &out, false, false, false).unwrap();
    assert_eq!(summary.session_count, 1);
    assert!(summary.byte_len > 0);
    assert!(out.exists());

    // Clobber guard: a second write with `overwrite = false` is refused.
    let err = write_bundle_zip(&db, &target, &out, false, false, false).unwrap_err();
    assert!(err.to_string().contains("already exists"));

    // Overwrite mode replaces the file unconditionally (TUI path).
    let again = write_bundle_zip(&db, &target, &out, true, false, false).unwrap();
    assert_eq!(again.session_count, 1);
    assert!(out.exists());
}

/// Insert one captured inference call: an `inference_calls` row (carrying
/// the `is_utility` flag), the request payload, and the timeline event the
/// export iterates. Returns the call_id.
fn add_inference_call(db: &Db, sid: Uuid, agent: &str, is_utility: bool) -> Uuid {
    let call_id = Uuid::new_v4();
    db.insert_inference_call(&crate::db::inference_calls::InferenceCallRow {
        call_id,
        session_id: sid,
        project_id: "p".into(),
        project_root: "/proj".into(),
        model: "m".into(),
        provider: "anthropic".into(),
        timestamp: 1,
        input_tokens: 1,
        output_tokens: 1,
        cached_input_tokens: 0,
        cache_creation_input_tokens: 0,
        cost_usd_micros: None,
        is_utility,
    })
    .unwrap();
    db.insert_inference_request(
        &call_id.to_string(),
        sid,
        &json!({"model": "m", "system": "s", "tools": [], "history": []}),
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .unwrap();
    db.insert_session_event(
        sid,
        SessionEventKind::InferenceRequest,
        Some(agent),
        Some(&call_id.to_string()),
        &json!({}),
    )
    .unwrap();
    call_id
}

/// A utility-flagged inference call lands in `inference_requests_utility/`
/// while a regular one lands in `inference_requests/`, and each
/// `events.json` `file` reference points at the correct folder.
#[test]
fn export_splits_utility_and_regular_inference_requests() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;

    let regular = add_inference_call(&db, sid, "Build", false);
    let utility = add_inference_call(&db, sid, "Build", true);

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    let names = entry_names(&zip);
    let regular_files: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("inference_requests/"))
        .collect();
    let utility_files: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("inference_requests_utility/"))
        .collect();
    assert_eq!(regular_files.len(), 1, "one regular request");
    assert_eq!(utility_files.len(), 1, "one utility request");
    assert!(regular_files[0].contains(&regular.to_string()));
    assert!(utility_files[0].contains(&utility.to_string()));

    // events.json `file` refs point at the matching folder, and the file
    // each names really exists in the archive.
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    for e in &events {
        if e["type"] != "inference_request" {
            continue;
        }
        let call_id = e["call_id"].as_str().unwrap();
        let file = e["file"].as_str().expect("inference_request has `file`");
        if call_id == utility.to_string() {
            assert!(
                file.starts_with("inference_requests_utility/"),
                "utility event must reference the utility folder: {file}"
            );
        } else {
            assert!(
                file.starts_with("inference_requests/"),
                "regular event must reference the regular folder: {file}"
            );
        }
        assert!(
            read_zip_entry(&zip, file).is_some(),
            "referenced file `{file}` must exist in the archive"
        );
    }
}

/// Model-comparison tandem (shadow) records export to a sibling
/// `inference_requests_tandem/` directory, one file per (main call, tandem
/// model), each holding `{ provider, model, status, request, response,
/// usage }`; a `tandem_inference` event links each back to the main call.
/// An in-flight (`pending`) tandem record exports without blocking.
#[test]
fn export_includes_tandem_sibling_dir_and_events() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;

    // One main call, shadowed by two tandem models — one settled, one
    // still pending.
    let main = add_inference_call(&db, sid, "Build", false);
    db.upsert_tandem_inference(
        "tan-a",
        sid,
        &main.to_string(),
        None,
        Some("Build"),
        "openrouter",
        "z-ai/glm-4.6",
        &json!({ "model": "z-ai/glm-4.6", "messages": [] }),
        Some(&json!([{ "text": "shadow answer" }])),
        Some(&json!({ "input_tokens": 5, "output_tokens": 2 })),
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .unwrap();
    db.upsert_tandem_inference(
        "tan-b",
        sid,
        &main.to_string(),
        None,
        Some("Build"),
        "anthropic",
        "claude",
        &json!({ "model": "claude" }),
        None,
        None,
        crate::db::session_log::InferenceRequestStatus::Pending,
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    let names = entry_names(&zip);
    let tandem_files: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("inference_requests_tandem/"))
        .collect();
    assert_eq!(
        tandem_files.len(),
        2,
        "one file per (main call, tandem model)"
    );
    // The model id's `/` is sanitized for fs safety.
    assert!(
        tandem_files.iter().any(|n| n.contains("z-ai_glm-4.6")),
        "model id sanitized: {tandem_files:?}"
    );
    // Each tandem file links back to the main call id and holds the full
    // shape (provider/model/status/request/response/usage).
    for f in &tandem_files {
        assert!(f.contains(&main.to_string()), "links to main call: {f}");
        let body: Value = serde_json::from_str(&read_zip_entry(&zip, f).unwrap()).unwrap();
        assert!(body["provider"].is_string());
        assert!(body["model"].is_string());
        assert!(body["status"].is_string());
        assert!(body.get("request").is_some());
        // `response`/`usage` keys are always present (null when pending).
        assert!(body.as_object().unwrap().contains_key("response"));
        assert!(body.as_object().unwrap().contains_key("usage"));
    }

    // `tandem_inference` events exist, link to the main call, and name a
    // real file in the archive. One is `pending`.
    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let tandem_events: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "tandem_inference")
        .collect();
    assert_eq!(tandem_events.len(), 2);
    for e in &tandem_events {
        assert_eq!(e["call_id"], main.to_string(), "links to parent call");
        let file = e["file"].as_str().expect("tandem event has `file`");
        assert!(file.starts_with("inference_requests_tandem/"));
        assert!(read_zip_entry(&zip, file).is_some());
    }
    assert!(
        tandem_events
            .iter()
            .any(|e| e["data"]["status"] == "pending"),
        "in-flight tandem exports as pending"
    );
}

#[test]
fn export_sanitizes_tandem_parent_call_id_filename_segment() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    let parent_call_id = "main/../../call:id?";

    db.insert_session_event(
        sid,
        SessionEventKind::InferenceFailure,
        Some("Build"),
        Some(parent_call_id),
        &json!({}),
    )
    .unwrap();
    db.upsert_tandem_inference(
        "tan-unsafe-parent",
        sid,
        parent_call_id,
        None,
        Some("Build"),
        "provider/one",
        "model:two",
        &json!({ "model": "model:two", "messages": [] }),
        Some(&json!([{ "text": "shadow answer" }])),
        Some(&json!({ "input_tokens": 5, "output_tokens": 2 })),
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let names = entry_names(&zip);
    let tandem_files: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("inference_requests_tandem/"))
        .collect();
    assert_eq!(tandem_files.len(), 1);
    assert!(
        tandem_files[0].ends_with("_main_.._.._call_id___provider_one_model_two.json"),
        "parent call id/provider/model filename segments are sanitized: {tandem_files:?}"
    );
    assert_eq!(tandem_files[0].matches('/').count(), 1);

    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let tandem_event = events
        .iter()
        .find(|e| e["type"] == "tandem_inference")
        .unwrap();
    let file = tandem_event["file"].as_str().unwrap();
    assert_eq!(file, tandem_files[0]);
    assert_eq!(tandem_event["call_id"], parent_call_id);
    assert!(read_zip_entry(&zip, file).is_some());
}

#[test]
fn tandem_validation_marks_valid_read_tree_search_calls() {
    let request = request_with_tools(vec![
        tool_def("read", crate::tools::read::ReadTool.parameters()),
        tool_def("tree", crate::tools::intel::TreeTool.parameters()),
        tool_def("search", crate::tools::intel::SearchTool.parameters()),
    ]);
    let response = json!([
        {"type": "tool_use", "name": "read", "input": {"path": "src/main.rs"}},
        {"type": "tool_use", "name": "tree", "input": {"path": "src"}},
        {"type": "tool_use", "name": "search", "input": {"pattern": "tandem"}},
    ]);

    let rows = validations(&request, &response);
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r["status"] == "valid"));
    assert!(rows.iter().all(|r| r["schema_valid"] == true));
    assert!(rows.iter().all(|r| r["available"] == true));
}

#[test]
fn tandem_validation_distinguishes_unavailable_and_unknown_tools() {
    let request = request_with_tools(vec![tool_def(
        "read",
        crate::tools::read::ReadTool.parameters(),
    )]);
    let response = json!([
        {"type": "tool_use", "name": "bash", "input": {"command": "cargo test"}},
        {"type": "tool_use", "name": "teleport", "input": {}},
    ]);

    let rows = validations(&request, &response);
    assert_eq!(rows[0]["tool"], "bash");
    assert_eq!(rows[0]["status"], "unavailable_tool");
    assert_eq!(rows[0]["available"], false);
    assert_eq!(rows[1]["tool"], "teleport");
    assert_eq!(rows[1]["status"], "invalid_tool");
}

#[test]
fn tandem_validation_marks_invalid_schema() {
    let request = request_with_tools(vec![tool_def(
        "read",
        crate::tools::read::ReadTool.parameters(),
    )]);
    let response = json!([
        {"type": "tool_use", "name": "read", "input": {"limit": 10}},
    ]);

    let rows = validations(&request, &response);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["status"], "invalid_schema");
    assert_eq!(rows[0]["schema_valid"], false);
    assert!(rows[0]["reasons"][0].as_str().unwrap().contains("`path`"));
}

#[test]
fn tandem_validation_applies_bash_session_boundary_without_running() {
    let request = request_with_tools(vec![tool_def(
        "bash",
        crate::tools::bash::BashTool::new().parameters(),
    )]);
    let response = json!([
        {"type": "tool_use", "name": "bash", "input": {"command": "pwd", "cwd": "src"}},
        {"type": "tool_use", "name": "bash", "input": {"command": "pwd", "cwd": ".."}},
        {"type": "tool_use", "name": "bash", "input": {"command": "cd .. && pwd"}},
    ]);

    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("src")).unwrap();
    let rows = super::tandem_validation::validate_tandem_tool_calls(
        &request,
        Some(&response),
        root.path(),
        None,
    )
    .as_array()
    .unwrap()
    .clone();
    assert_eq!(rows[0]["status"], "valid");
    assert_eq!(rows[0]["schema_valid"], true);
    assert_eq!(rows[1]["status"], "would_require_approval");
    assert_eq!(rows[1]["schema_valid"], true);
    assert_eq!(rows[2]["status"], "would_require_approval");
}

#[test]
fn tandem_validation_classifies_write_and_lock_capable_tools() {
    let request = request_with_tools(vec![tool_def(
        "writeunlock",
        crate::tools::writeunlock::WriteunlockTool.parameters(),
    )]);
    let response = json!([
        {"type": "tool_use", "name": "writeunlock", "input": {"path": "src/lib.rs", "content": "x"}},
    ]);

    let rows = validations(&request, &response);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["status"], "write_or_lock_capable");
    assert_eq!(rows[0]["category"], "write_or_lock_capable");
    assert_eq!(rows[0]["schema_valid"], true);
}

#[test]
fn export_includes_tandem_tool_call_validation_in_file_and_event() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "Build").unwrap();
    let sid = s.session_id;
    let main = add_inference_call(&db, sid, "Build", false);

    db.upsert_tandem_inference(
        "tan-validated",
        sid,
        &main.to_string(),
        None,
        Some("Build"),
        "openrouter",
        "z-ai/glm-4.6",
        &request_with_tools(vec![tool_def(
            "read",
            crate::tools::read::ReadTool.parameters(),
        )]),
        Some(&json!([
            {"type": "tool_use", "name": "read", "input": {"path": "src/main.rs"}},
        ])),
        None,
        crate::db::session_log::InferenceRequestStatus::Completed,
    )
    .unwrap();

    let target = db.get_session(sid).unwrap().unwrap();
    let bundle = collect_bundle(&db, sid).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();
    let file = entry_names(&zip)
        .into_iter()
        .find(|n| n.starts_with("inference_requests_tandem/"))
        .expect("tandem file exists");
    let body: Value = serde_json::from_str(&read_zip_entry(&zip, &file).unwrap()).unwrap();
    assert_eq!(body["tool_call_validation"][0]["tool"], "read");
    assert_eq!(body["tool_call_validation"][0]["status"], "valid");

    let events: Vec<Value> =
        serde_json::from_str(&read_zip_entry(&zip, "events.json").unwrap()).unwrap();
    let event = events
        .iter()
        .find(|e| e["type"] == "tandem_inference")
        .expect("tandem event exists");
    assert_eq!(event["data"]["tool_call_validation"][0]["tool"], "read");
    assert_eq!(event["data"]["tool_call_validation"][0]["status"], "valid");
}

/// `manifest.json` carries the running cockpit version and the target
/// session's date as both an ISO-8601 string and the raw epoch value.
#[test]
fn manifest_has_version_and_session_date() {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/proj", "builder").unwrap();
    let target = db.get_session(s.session_id).unwrap().unwrap();
    let bundle = collect_bundle(&db, s.session_id).unwrap();
    let zip = build_zip(&db, &target, &bundle).unwrap();

    let manifest: Value =
        serde_json::from_str(&read_zip_entry(&zip, "manifest.json").unwrap()).unwrap();
    assert_eq!(manifest["cockpit_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest["excluded_generated_artifacts"], true);
    assert_eq!(manifest["include_generated_artifacts"], false);
    // Epoch matches the session row; ISO string is the RFC-3339 rendering
    // of that same epoch.
    assert_eq!(
        manifest["session_started_at"].as_i64().unwrap(),
        target.started_at
    );
    let iso = manifest["session_date"].as_str().unwrap();
    let expected = chrono::DateTime::<chrono::Utc>::from_timestamp(target.started_at, 0)
        .unwrap()
        .to_rfc3339();
    assert_eq!(iso, expected);

    let zip = build_zip_with_options_and_env(
        &db,
        &target,
        &bundle,
        ExportBundleOptions {
            include_generated_artifacts: true,
            include_sensitive: false,
        },
        &test_export_env(),
    )
    .unwrap();
    let manifest: Value =
        serde_json::from_str(&read_zip_entry(&zip, "manifest.json").unwrap()).unwrap();
    assert_eq!(manifest["excluded_generated_artifacts"], false);
    assert_eq!(manifest["include_generated_artifacts"], true);
}

fn write_manifest_active_model_config(root: &Path, provider: &str, model: &str) {
    let config_dir = root.join(".cockpit");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.json"),
        serde_json::to_string(&json!({
            "active_model": {
                "provider": provider,
                "model": model,
            },
        }))
        .unwrap(),
    )
    .unwrap();
}

fn build_zip_with_config_override(
    db: &Db,
    target: &SessionRow,
    bundle: &[SessionRow],
    config_path: &Path,
) -> Vec<u8> {
    let mut env = test_export_env();
    env.insert(
        crate::config::dirs::COCKPIT_CONFIG_ENV.to_string(),
        config_path.to_string_lossy().into_owned(),
    );
    build_zip_with_options_and_env(db, target, bundle, ExportBundleOptions::default(), &env)
        .unwrap()
}

#[test]
fn export_manifest_includes_session_and_config_active_model() {
    let tmp = tempfile::TempDir::new().unwrap();
    write_manifest_active_model_config(tmp.path(), "provider-a", "model-a");
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap();
    session.set_active_model("provider-a", "model-a").unwrap();

    let target = db.get_session(session.id).unwrap().unwrap();
    let bundle = collect_bundle(&db, session.id).unwrap();
    let zip = build_zip_with_config_override(
        &db,
        &target,
        &bundle,
        &tmp.path().join(".cockpit/config.json"),
    );
    let manifest: Value =
        serde_json::from_str(&read_zip_entry(&zip, "manifest.json").unwrap()).unwrap();

    assert_eq!(
        manifest["target"]["session_model"],
        json!({"provider": "provider-a", "model": "model-a"})
    );
    assert_eq!(
        manifest["target"]["config_active_model"],
        json!({"provider": "provider-a", "model": "model-a"})
    );
    assert_eq!(manifest["target"]["active_model_diverged"], false);
}

#[test]
fn export_manifest_flags_active_model_divergence() {
    let tmp = tempfile::TempDir::new().unwrap();
    write_manifest_active_model_config(tmp.path(), "provider-b", "model-b");
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap();
    session.set_active_model("provider-a", "model-a").unwrap();

    let target = db.get_session(session.id).unwrap().unwrap();
    let bundle = collect_bundle(&db, session.id).unwrap();
    let zip = build_zip_with_config_override(
        &db,
        &target,
        &bundle,
        &tmp.path().join(".cockpit/config.json"),
    );
    let manifest: Value =
        serde_json::from_str(&read_zip_entry(&zip, "manifest.json").unwrap()).unwrap();

    assert_eq!(
        manifest["target"]["session_model"],
        json!({"provider": "provider-a", "model": "model-a"})
    );
    assert_eq!(
        manifest["target"]["config_active_model"],
        json!({"provider": "provider-b", "model": "model-b"})
    );
    assert_eq!(manifest["target"]["active_model_diverged"], true);
}

#[test]
fn export_manifest_active_model_without_config_is_null() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open_in_memory().unwrap();
    let session = Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap();
    session.set_active_model("provider-a", "model-a").unwrap();

    let target = db.get_session(session.id).unwrap().unwrap();
    let bundle = collect_bundle(&db, session.id).unwrap();
    let zip = build_zip_with_config_override(
        &db,
        &target,
        &bundle,
        &tmp.path().join(".cockpit/missing-config.json"),
    );
    let manifest: Value =
        serde_json::from_str(&read_zip_entry(&zip, "manifest.json").unwrap()).unwrap();

    assert_eq!(
        manifest["target"]["session_model"],
        json!({"provider": "provider-a", "model": "model-a"})
    );
    assert!(manifest["target"]["config_active_model"].is_null());
    assert_eq!(manifest["target"]["active_model_diverged"], false);
}

/// The `config/` folder holds the deep-merged effective config plus raw
/// per-layer copies, with secrets scrubbed by the redaction table. The
/// closer (project) layer wins the deep merge.
#[test]
fn config_entries_deep_merge_raw_layers_and_redaction() {
    use crate::config::dirs::{ConfigDir, ConfigDirKind};

    let tmp = tempfile::tempdir().unwrap();
    // Home layer: a single `config.json` carrying the cockpit-only keys
    // (utility_model, predict_next_message) alongside a secret value.
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
            home.join("config.json"),
            r#"{"utility_model":"home:model","predict_next_message":"off","key":"SUPER_SECRET_VALUE","providers":{"legacy":{"url":"https://legacy","models":[{"id":"old"}]}}}"#,
        )
        .unwrap();
    let home_providers = home.join("providers");
    std::fs::create_dir_all(&home_providers).unwrap();
    std::fs::write(
        home_providers.join("openai.json"),
        r#"{"url":"https://api.openai.com/v1","models":[{"id":"gpt-5"}]}"#,
    )
    .unwrap();
    // Project layer: overrides utility_model (closer wins).
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("config.json"),
        r#"{"utility_model":"proj:model"}"#,
    )
    .unwrap();

    let layers = vec![
        ConfigDir {
            kind: ConfigDirKind::HomeXdg,
            path: home.clone(),
        },
        ConfigDir {
            kind: ConfigDirKind::Project,
            path: proj.clone(),
        },
    ];

    // A redaction table that scrubs the literal secret value.
    let cfg = crate::config::extended::RedactConfig {
        denylist: vec!["SUPER_SECRET_VALUE".to_string()],
        scan_ssh_keys: false,
        ..crate::config::extended::RedactConfig::default()
    };
    let redactor = RedactionTable::build_with_env(&cfg, tmp.path(), &test_export_env()).unwrap();

    let entries = config_entries_from_layers(&layers, &redactor, false);
    let map: BTreeMap<String, String> = entries.into_iter().collect();

    // Synthesized merge: project layer's utility_model wins; the home-only
    // key survives.
    let effective: Value = serde_json::from_str(&map["config/effective-config.json"]).unwrap();
    assert_eq!(effective["utility_model"], "proj:model");
    assert_eq!(effective["predict_next_message"], "off");
    assert!(
        effective.get("providers").is_none(),
        "global effective config must not imply inline providers"
    );
    let effective_providers: Value =
        serde_json::from_str(&map["config/effective-providers.json"]).unwrap();
    assert_eq!(
        effective_providers["providers"]["openai"]["models"][0]["id"],
        "gpt-5"
    );
    assert!(
        effective_providers["providers"].get("legacy").is_none(),
        "legacy inline providers are ignored"
    );

    // Raw per-layer copies present for both layers.
    assert!(map.contains_key("config/layers/home-xdg/config.json"));
    assert!(map.contains_key("config/layers/home-xdg/providers/openai.json"));
    assert!(map.contains_key("config/layers/project-0/config.json"));

    // Secret scrubbed in the raw config copy.
    let raw_config = &map["config/layers/home-xdg/config.json"];
    assert!(
        !raw_config.contains("SUPER_SECRET_VALUE"),
        "secret must be redacted in the exported config: {raw_config}"
    );
    assert!(raw_config.contains(&redactor.scrub("SUPER_SECRET_VALUE")));
}

#[test]
fn config_entries_exclude_generated_artifacts_by_default() {
    use crate::config::dirs::{ConfigDir, ConfigDirKind};

    let tmp = tempfile::tempdir().unwrap();
    let layer = tmp.path().join(".cockpit");
    std::fs::create_dir_all(layer.join("exports/old")).unwrap();
    std::fs::create_dir_all(layer.join("cache/models")).unwrap();
    std::fs::create_dir_all(layer.join("notes")).unwrap();
    std::fs::write(layer.join("config.json"), r#"{"utility_model":"u:m"}"#).unwrap();
    std::fs::write(layer.join("exports/old/events.json"), r#"{"old":true}"#).unwrap();
    std::fs::write(layer.join("cache/models/index.json"), r#"{"cached":true}"#).unwrap();
    std::fs::write(layer.join("old-debug.zip"), "zip-ish text").unwrap();
    std::fs::write(layer.join("notes/archive.zip"), "ordinary user config").unwrap();
    std::fs::write(layer.join("notes/user.md"), "keep SUPER_SECRET_VALUE\n").unwrap();

    let layers = vec![ConfigDir {
        kind: ConfigDirKind::Project,
        path: layer,
    }];
    let cfg = crate::config::extended::RedactConfig {
        denylist: vec!["SUPER_SECRET_VALUE".to_string()],
        scan_ssh_keys: false,
        ..crate::config::extended::RedactConfig::default()
    };
    let redactor = RedactionTable::build_with_env(&cfg, tmp.path(), &test_export_env()).unwrap();
    let entries = config_entries_from_layers(&layers, &redactor, false);
    let map: BTreeMap<String, String> = entries.into_iter().collect();

    assert!(map.contains_key("config/effective-config.json"));
    assert!(map.contains_key("config/layers/project-0/config.json"));
    assert!(map.contains_key("config/layers/project-0/notes/user.md"));
    assert!(map.contains_key("config/layers/project-0/notes/archive.zip"));
    assert!(!map.contains_key("config/layers/project-0/exports/old/events.json"));
    assert!(!map.contains_key("config/layers/project-0/cache/models/index.json"));
    assert!(!map.contains_key("config/layers/project-0/old-debug.zip"));
    let kept = &map["config/layers/project-0/notes/user.md"];
    assert!(!kept.contains("SUPER_SECRET_VALUE"));
    assert!(kept.contains(&redactor.scrub("SUPER_SECRET_VALUE")));
}

#[test]
fn config_entries_include_generated_artifacts_when_requested() {
    use crate::config::dirs::{ConfigDir, ConfigDirKind};

    let tmp = tempfile::tempdir().unwrap();
    let layer = tmp.path().join(".cockpit");
    std::fs::create_dir_all(layer.join("exports/old")).unwrap();
    std::fs::write(layer.join("config.json"), r#"{"utility_model":"u:m"}"#).unwrap();
    std::fs::write(layer.join("exports/old/events.json"), r#"{"old":true}"#).unwrap();

    let layers = vec![ConfigDir {
        kind: ConfigDirKind::Project,
        path: layer,
    }];
    let entries = config_entries_from_layers(&layers, &RedactionTable::empty(), true);
    let map: BTreeMap<String, String> = entries.into_iter().collect();

    assert!(map.contains_key("config/effective-config.json"));
    assert_eq!(
        map["config/layers/project-0/exports/old/events.json"],
        r#"{"old":true}"#
    );
}

#[test]
fn config_entries_structurally_redact_config_and_provider_secrets_without_redactor() {
    use crate::config::dirs::{ConfigDir, ConfigDirKind};

    let tmp = tempfile::tempdir().unwrap();
    let layer = tmp.path().join(".cockpit");
    std::fs::create_dir_all(layer.join("providers")).unwrap();
    std::fs::write(
        layer.join("config.json"),
        r#"{
              "utility_model": "openai:gpt-5",
              "redact": { "enabled": false },
              "auth": { "value": "config-auth-secret", "kind": "api-key" },
              "headers": { "Authorization": "Bearer config-secret" }
            }"#,
    )
    .unwrap();
    std::fs::write(
        layer.join("providers/openai.json"),
        r#"{
              "url": "https://api.openai.com/v1",
              "credential_ref": "provider-credential-ref",
              "headers": [{ "name": "Authorization", "value": "Bearer provider-secret" }],
              "models": [{ "id": "gpt-5" }]
            }"#,
    )
    .unwrap();

    let layers = vec![ConfigDir {
        kind: ConfigDirKind::Project,
        path: layer,
    }];
    let entries = config_entries_from_layers(&layers, &RedactionTable::empty(), false);
    let map: BTreeMap<String, String> = entries.into_iter().collect();

    for key in [
        "config/effective-config.json",
        "config/effective-providers.json",
        "config/layers/project-0/config.json",
        "config/layers/project-0/providers/openai.json",
    ] {
        let body = &map[key];
        assert!(!body.contains("config-auth-secret"), "{key}: {body}");
        assert!(!body.contains("config-secret"), "{key}: {body}");
        assert!(!body.contains("provider-secret"), "{key}: {body}");
        assert!(!body.contains("provider-credential-ref"), "{key}: {body}");
    }
    assert!(map["config/effective-config.json"].contains("openai:gpt-5"));
    assert!(map["config/effective-providers.json"].contains("gpt-5"));
    assert!(map["config/effective-providers.json"].contains("[REDACTED]"));
}

#[test]
fn config_entries_sanitize_mcp_config_structurally() {
    use crate::config::dirs::{ConfigDir, ConfigDirKind};

    let tmp = tempfile::tempdir().unwrap();
    let layer = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&layer).unwrap();
    std::fs::write(
        layer.join("mcp.json"),
        r#"{
              "servers": {
                "typefully": {
                  "transport": "streamable",
                  "endpoint": "https://api.typefully.com/mcp?api_key=tf-secret&keep=visible",
                  "env": { "RAW_BASE": "base-secret" },
                  "env_credential_refs": { "STORED_BASE": "mcp:typefully:base-env:STORED_BASE" },
                  "auth": {
                    "kind": "header",
                    "header": "Authorization",
                    "value": "Bearer raw-secret",
                    "credential_ref": "mcp:typefully:header"
                  }
                },
                "stdio": {
                  "transport": "stdio",
                  "command": "node",
                  "auth": {
                    "kind": "env",
                    "vars": { "TOKEN": "env-secret" },
                    "credential_refs": { "API_KEY": "mcp:stdio:auth-env:API_KEY" }
                  }
                }
              }
            }"#,
    )
    .unwrap();

    let layers = vec![ConfigDir {
        kind: ConfigDirKind::Project,
        path: layer,
    }];
    let entries = config_entries_from_layers(&layers, &RedactionTable::empty(), false);
    let map: BTreeMap<String, String> = entries.into_iter().collect();
    let raw = &map["config/layers/project-0/mcp.json"];
    let effective = &map["config/effective-mcp.json"];
    for body in [raw, effective] {
        assert!(!body.contains("tf-secret"), "{body}");
        assert!(!body.contains("base-secret"), "{body}");
        assert!(!body.contains("Bearer raw-secret"), "{body}");
        assert!(!body.contains("env-secret"), "{body}");
        assert!(!body.contains("mcp:typefully:header"), "{body}");
        assert!(body.contains("api_key=%5BREDACTED%5D"), "{body}");
        assert!(body.contains("keep=visible"), "{body}");
        assert!(body.contains("\"value\": \"[REDACTED]\""), "{body}");
        assert!(body.contains("\"TOKEN\": \"[REDACTED]\""), "{body}");
    }
}

/// No config layers anywhere → a marker entry, never an empty `config/`
/// nor a failure.
#[test]
fn config_entries_missing_config_writes_marker() {
    let entries = config_entries_from_layers(&[], &RedactionTable::empty(), false);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "config/NO-CONFIG-FOUND.txt");
    assert!(entries[0].1.contains("No cockpit config"));
}
