use super::*;
use cockpit_test_support::provider::{ScriptedProvider, Turn, Usage, WireDialect};

mod context;
mod delegation;
mod goals;
mod inbound;
mod learn;
mod llm_mode;
mod misc;
mod model_switch;
mod noninteractive;
mod primary_swap;
mod recursion;
mod reports;
mod schedule;
mod skills_preflight;

fn test_provider_base_url() -> String {
    static PROVIDER: std::sync::OnceLock<&'static ScriptedProvider> = std::sync::OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            // Leak the process-wide fixture provider so its listener outlives
            // every parallel driver test that reuses this cached base URL.
            Box::leak(Box::new(
                ScriptedProvider::builder()
                    .dialect(WireDialect::ChatCompletions)
                    .turn(Turn::Text("test compact brief".into()))
                    .with_usage(Usage {
                        prompt_tokens: 1,
                        completion_tokens: 3,
                        total_tokens: 4,
                        use_alias_names: false,
                    })
                    .repeat_last()
                    .start_blocking(),
            ))
        })
        .base_url()
}

/// Build a driver rooted on a keyless local fixture provider.
fn test_driver(max_schedules: usize) -> (Driver, tempfile::TempDir) {
    test_driver_with_url(max_schedules, test_provider_base_url())
}

fn test_driver_without_network(max_schedules: usize) -> (Driver, tempfile::TempDir) {
    test_driver_with_url(max_schedules, "http://127.0.0.1:1/v1".to_string())
}

fn test_driver_with_url(max_schedules: usize, provider_url: String) -> (Driver, tempfile::TempDir) {
    use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig, WireApi};
    use std::collections::BTreeMap;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let db = crate::db::Db::open_in_memory().unwrap();
    let session = Arc::new(Session::create(db.clone(), root.clone(), "Build").unwrap());
    let locks = Arc::new(crate::locks::LockManager::from_db(db).unwrap());
    let rcfg = crate::config::extended::RedactConfig::default();
    let redact = Arc::new(RedactionTable::build(&rcfg, &root).unwrap());

    let mut providers = BTreeMap::new();
    providers.insert(
        "lmstudio".to_string(),
        ProviderEntry {
            url: provider_url,
            headers: vec![],
            wire_api: WireApi::Completions,
            ..ProviderEntry::default()
        },
    );
    let pcfg = ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "lmstudio".into(),
            model: "local".into(),
            reasoning_effort: None,
            thinking_mode: None,
        }),
        ..ProvidersConfig::default()
    };
    let model = Arc::new(
        crate::engine::model::Model::from_config(
            &pcfg,
            std::sync::Arc::new(crate::redact::RedactionTable::empty()),
        )
        .unwrap(),
    );
    let agent = Arc::new(Agent {
        name: "Build".into(),
        system: String::new(),
        role_prompt: String::new(),
        tools: crate::engine::tool::ToolBox::new(),
        model,
        params: crate::engine::model::ModelParams::default(),
        scan_tool_results: true,
        llm_mode: crate::config::extended::LlmMode::default(),
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
    });
    let driver = Driver::with_max_schedules(session, locks, redact, root, agent, max_schedules);
    (driver, tmp)
}

#[tokio::test]
async fn command_capability_notice_emits_at_driver_startup_once() {
    let (mut driver, _tmp) = test_driver_without_network(1);
    let template = crate::config::extended::ToolCommandTemplate {
        enabled: true,
        command: "cockpit-definitely-missing-startup-tool {query}".to_string(),
        description: None,
    };
    let custom_tool = crate::tools::custom::CustomBashTool::from_template_with_provenance(
        "startup_search",
        &template,
        crate::tools::custom::ToolTemplateProvenance::Configured {
            source: "test".to_string(),
        },
    );
    let empty_path = _tmp.path().join("empty-path");
    std::fs::create_dir_all(&empty_path).unwrap();
    let frame = driver.stack.last_mut().expect("test driver has root frame");
    let agent = Arc::make_mut(&mut frame.agent);
    *agent.env_overlay.write().unwrap() =
        std::collections::HashMap::from([("PATH".to_string(), empty_path.display().to_string())]);
    agent.tools = crate::engine::tool::ToolBox::new().with(Arc::new(custom_tool));
    let (tx, mut rx) = mpsc::channel(4);

    driver.emit_command_capability_notice_if_new(&tx).await;
    driver.emit_command_capability_notice_if_new(&tx).await;

    let first = rx.recv().await.expect("startup capability notice");
    match first {
        TurnEvent::CommandCapabilityUnavailable { text, fix_command } => {
            assert!(text.contains("cockpit-definitely-missing-startup-tool"));
            assert!(text.contains("startup_search"));
            assert!(fix_command.is_none());
        }
        other => panic!("expected CommandCapabilityUnavailable, got {other:?}"),
    }
    assert!(rx.try_recv().is_err(), "same startup notice is deduped");
}

fn learn_tool_args(name: &str) -> serde_json::Value {
    serde_json::json!({
        "action": "create",
        "name": name,
        "params": {
            "description": "Repeat a verified setup workflow",
            "content": "## When to Use\n\nUse for the verified setup.\n\n## Procedure\n\n1. Run the verified command.\n\n## Pitfalls\n\nDo not invent flags.\n\n## Verification\n\nConfirm the expected output."
        }
    })
}

fn learn_driver(
    approval: bool,
    skill_name: &str,
    request_count: usize,
) -> (
    Driver,
    tempfile::TempDir,
    std::path::PathBuf,
    ScriptedProvider,
) {
    use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig, WireApi};
    use std::collections::BTreeMap;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("skills");
    let config_dir = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "skills": {
                "scan_dirs": [root.to_string_lossy()],
                "write_approval": approval
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let agents_dir = config_dir.join("agents");
    std::fs::create_dir_all(&agents_dir).unwrap();
    std::fs::write(
        agents_dir.join("Build.md"),
        "---\ndescription: Learn test primary\nmode: primary\ntools: [skill_manage, mcp]\ntoolTiers:\n  skill_manage: builtin\n---\n\nAuthor reusable skills from verified evidence.\n",
    )
    .unwrap();

    let mut provider_builder = ScriptedProvider::builder().turn(Turn::ToolCall {
        id: "learn-save".into(),
        name: "skill_manage".into(),
        arguments: learn_tool_args(skill_name),
    });
    if request_count > 1 {
        provider_builder = provider_builder.turn(Turn::Text("Saved the reusable skill.".into()));
    }
    let provider = provider_builder.start_blocking();
    let provider_url = provider.base_url();
    let mut providers = BTreeMap::new();
    providers.insert(
        "scripted".to_string(),
        ProviderEntry {
            url: provider_url,
            wire_api: WireApi::Completions,
            ..ProviderEntry::default()
        },
    );
    let provider_config = ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "scripted".into(),
            model: "local".into(),
            reasoning_effort: None,
            thinking_mode: None,
        }),
        ..ProvidersConfig::default()
    };
    let model = Arc::new(
        crate::engine::model::Model::from_config(
            &provider_config,
            Arc::new(crate::redact::RedactionTable::empty()),
        )
        .unwrap(),
    );
    let agent = Arc::new(Agent {
        name: "Build".into(),
        system: "Author reusable skills from verified evidence.".into(),
        role_prompt: "Author reusable skills from verified evidence.".into(),
        tools: crate::engine::tool::ToolBox::new()
            .with(Arc::new(crate::tools::skill_manage::SkillManageTool)),
        model,
        params: crate::engine::model::ModelParams::default(),
        scan_tool_results: false,
        llm_mode: crate::config::extended::LlmMode::default(),
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
    });
    let db = crate::db::Db::open_in_memory().unwrap();
    let session = Arc::new(Session::create(db.clone(), tmp.path().to_path_buf(), "Build").unwrap());
    let locks = Arc::new(crate::locks::LockManager::from_db(db).unwrap());
    let redact = Arc::new(RedactionTable::empty());
    let mut driver =
        Driver::with_max_schedules(session, locks, redact, tmp.path().to_path_buf(), agent, 1);
    driver.refresh_config_from_disk_for_tests();
    driver.stack[0].history.push(Message::user(
        "We verified the setup with cockpit verify --local.",
    ));
    driver.stack[0].history.push(Message::Assistant {
        id: Some("prior-assistant".into()),
        content: crate::engine::message::OneOrMany::one(
            crate::engine::message::AssistantContent::text(
                "The local verification completed successfully.",
            ),
        ),
    });
    (driver, tmp, root, provider)
}

fn set_active_delegated_recursion(
    driver: &mut Driver,
    ctx: crate::engine::builtin::DelegationRecursionContext,
) {
    let mut agent = (*driver.stack[0].agent).clone();
    agent.delegated = true;
    agent.delegation_recursion = ctx;
    driver.stack[0].agent = Arc::new(agent);
}

fn write_recursion_policy(root: &std::path::Path) {
    let cockpit = root.join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    std::fs::write(
        cockpit.join("config.json"),
        r#"{
          "delegation": {
            "recursionEnabled": true,
            "defaultRecursionDepth": 0,
            "recursion": {
              "Build": {
                "allowedTargets": ["Build"],
                "maxDepth": 6
              }
            }
          }
        }"#,
    )
    .unwrap();
}

fn record_goal_tool_event(driver: &Driver, tool: &str, wire_input: serde_json::Value) {
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some(&uuid::Uuid::new_v4().to_string()),
            &serde_json::json!({
                "tool": tool,
                "wire_input": wire_input,
                "original_input": wire_input,
            }),
        )
        .unwrap();
}

/// Build a driver rooted on the real `Plan` primary. The model is keyless
/// localhost and never called:
/// these tests drive [`Driver::apply_handoff`] (the engine side of a
/// model-issued `handoff` call) directly, so no inference round-trips.
fn plan_rooted_driver() -> (Driver, tempfile::TempDir) {
    let (mut driver, tmp) = test_driver(1);
    // Re-root on a genuine `Plan`, built through the same factory the
    // session worker uses, so its tool surface + name match production.
    let plan = crate::engine::builtin::load("Plan", &driver.spawn_args(true)).unwrap();
    driver.stack[0].agent = Arc::new(plan);
    driver.session.set_active_agent("Plan").unwrap();
    (driver, tmp)
}

/// An assistant turn carrying a single `writeunlock` tool call on `path`.
fn write_turn(call_id: &str, path: &str) -> Message {
    use crate::engine::message::AssistantContent;
    use rig::OneOrMany;
    use rig::message::{ToolCall, ToolFunction};
    Message::Assistant {
        id: None,
        content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
            id: call_id.to_string(),
            call_id: None,
            function: ToolFunction {
                name: "writeunlock".to_string(),
                arguments: serde_json::json!({ "path": path }),
            },
            signature: None,
            additional_params: None,
        })),
    }
}

fn read_turn(call_id: &str, path: &str) -> Message {
    use crate::engine::message::AssistantContent;
    use rig::OneOrMany;
    use rig::message::{ToolCall, ToolFunction};
    Message::Assistant {
        id: None,
        content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
            id: call_id.to_string(),
            call_id: None,
            function: ToolFunction {
                name: "read".to_string(),
                arguments: serde_json::json!({ "path": path }),
            },
            signature: None,
            additional_params: None,
        })),
    }
}

fn bash_turn(call_id: &str, command: &str) -> Message {
    use crate::engine::message::AssistantContent;
    use rig::OneOrMany;
    use rig::message::{ToolCall, ToolFunction};
    Message::Assistant {
        id: None,
        content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
            id: call_id.to_string(),
            call_id: None,
            function: ToolFunction {
                name: "bash".to_string(),
                arguments: serde_json::json!({ "command": command }),
            },
            signature: None,
            additional_params: None,
        })),
    }
}

/// The active-agent name persisted in the session row — what a resume
/// restarts on.
#[allow(deprecated)]
fn persisted_active_agent(driver: &Driver) -> String {
    let session_id = driver.session.id;
    driver
        .session
        .db
        .write_blocking(move |conn| crate::db::Db::get_session_conn(conn, session_id))
        .unwrap()
        .unwrap()
        .active_agent
}

/// The text of a `tool_result`-carrying `Message::User`. Empty for any other shape.
fn tool_result_text(msg: &Message) -> String {
    use rig::message::{ToolResultContent, UserContent};
    match msg {
        Message::User { content } => content
            .iter()
            .filter_map(|c| match c {
                UserContent::ToolResult(tr) => Some(
                    tr.content
                        .iter()
                        .filter_map(|c| match c {
                            ToolResultContent::Text(t) => Some(t.text.clone()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(""),
                ),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

fn push_user_turn(driver: &mut Driver, text: &str) {
    driver.stack[0].history.push(Message::user(text));
}

/// Plain `UserContent::Text` of a `Message::User` (the synthetic swap
/// marker is one such message). Empty for a tool-result-carrying user
/// message (the handoff kickoff) or any non-user shape.
fn plain_user_text(msg: &Message) -> String {
    match msg {
        Message::User { content } => crate::engine::message::extract_user_text(content),
        _ => String::new(),
    }
}

/// Count of injected agent-swap identity markers in the root history
/// (implementation note) — `Message::User` entries
/// whose plain text opens the `[Primary agent changed:` boundary.
fn swap_markers(driver: &Driver) -> Vec<String> {
    driver.stack[0]
        .history
        .iter()
        .map(plain_user_text)
        .filter(|t| t.starts_with("[Primary agent changed:"))
        .collect()
}

/// Re-root the driver on a real bundled primary built through the same
/// factory the session worker uses, so its tool surface + name match
/// production — the authority for "absent from the new agent"
/// (implementation note).
fn reroot_real(driver: &mut Driver, name: &str) {
    let agent = crate::engine::builtin::load(name, &driver.spawn_args(true)).unwrap();
    driver.stack[0].agent = Arc::new(agent);
    driver.session.set_active_agent(name).unwrap();
}

/// An assistant turn carrying one tool call: `tool` named `tool`, id
/// `call_id`. Used to seed cross-agent attribution history.
fn tool_call_turn(call_id: &str, tool: &str) -> Message {
    use crate::engine::message::{AssistantContent, OneOrMany};
    use rig::message::{ToolCall, ToolFunction};
    Message::Assistant {
        id: None,
        content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
            id: call_id.to_string(),
            call_id: None,
            function: ToolFunction {
                name: tool.to_string(),
                arguments: serde_json::json!({}),
            },
            signature: None,
            additional_params: None,
        })),
    }
}

/// The text of the `tool_result` answering `call_id` in the root history
/// (empty if none). Used to read back the wire-only attribution note.
fn tool_result_text_for(driver: &Driver, call_id: &str) -> String {
    use rig::message::{ToolResultContent, UserContent};
    for msg in &driver.stack[0].history {
        if let Message::User { content } = msg {
            for c in content.iter() {
                if let UserContent::ToolResult(tr) = c
                    && tr.id == call_id
                {
                    return tr
                        .content
                        .iter()
                        .filter_map(|p| match p {
                            ToolResultContent::Text(t) => Some(t.text.clone()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("");
                }
            }
        }
    }
    String::new()
}

fn history_text(history: &[Message]) -> String {
    use crate::engine::message::AssistantContent;
    use rig::message::{ToolResultContent, UserContent};

    let mut out = String::new();
    for msg in history {
        match msg {
            Message::User { content } => {
                for c in content.iter() {
                    match c {
                        UserContent::Text(text) => out.push_str(&text.text),
                        UserContent::ToolResult(tr) => {
                            for part in tr.content.iter() {
                                if let ToolResultContent::Text(text) = part {
                                    out.push_str(&text.text);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Message::Assistant { content, .. } => {
                for c in content.iter() {
                    match c {
                        AssistantContent::Text(text) => out.push_str(&text.text),
                        AssistantContent::ToolCall(tc) => out.push_str(&tc.id),
                        _ => {}
                    }
                }
            }
            Message::System { .. } => {}
        }
        out.push('\n');
    }
    out
}

fn record_skill_tool_row(driver: &Driver, call_id: &str, agent: &str, output: &str) {
    driver
        .session
        .record_tool_call(crate::session::ToolCallRow {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: agent.to_string(),
            call_id: call_id.to_string(),
            parent_call_id: None,
            parent_child_index: None,
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: "skill".to_string(),
            path: None,
            mcp_server: None,
            original_input_json: serde_json::json!({ "name": "x" }),
            wire_input_json: serde_json::json!({ "name": "x" }),
            recovery: crate::db::tool_calls::Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: output.to_string(),
            truncated: false,
            duration_ms: 1,
            llm_mode: crate::config::extended::LlmMode::Normal,
            shape_fingerprint: None,
            hint: None,
        })
        .unwrap();
}

/// Build a tiny history with two identical `read` snapshots (one
/// elidable). Mirrors the prune module's wire shape.
fn dup_read_history() -> Vec<Message> {
    dup_read_history_with_body("FULL SNAPSHOT BODY with enough tokens to matter here")
}

fn dup_read_history_zero_savings() -> Vec<Message> {
    dup_read_history_with_body("x")
}

fn dup_read_history_tiny_savings() -> Vec<Message> {
    dup_read_history_with_body("lorem ipsum dolor sit amet ".repeat(20))
}

fn dup_read_history_with_body(body: impl Into<String>) -> Vec<Message> {
    use rig::OneOrMany;
    use rig::message::{AssistantContent, ToolResult, ToolResultContent, UserContent};
    let body = body.into();
    let call = |id: &str| Message::Assistant {
        id: None,
        content: OneOrMany::one(AssistantContent::ToolCall(
            crate::engine::message::ToolCall {
                id: id.to_string(),
                call_id: None,
                function: rig::message::ToolFunction {
                    name: "read".into(),
                    arguments: serde_json::json!({ "path": "/abs/foo.rs" }),
                },
                signature: None,
                additional_params: None,
            },
        )),
    };
    let result = |id: &str| Message::User {
        content: OneOrMany::one(UserContent::ToolResult(ToolResult {
            id: id.to_string(),
            call_id: None,
            content: OneOrMany::one(ToolResultContent::text(body.clone())),
        })),
    };
    vec![call("c1"), result("c1"), call("c2"), result("c2")]
}

/// Like [`dup_read_history`] but with a large duplicated body so the
/// prune reclaims a substantial token count (used by the ctx%-threshold
/// auto-prune test, where the elision marker would otherwise dwarf a tiny
/// body and leave `tokens_saved` at 0).
fn dup_read_history_big() -> Vec<Message> {
    dup_read_history_with_body("lorem ipsum dolor sit amet ".repeat(400))
}

fn push_test_child(driver: &mut Driver, history: Vec<Message>) {
    let child = driver.stack[0].agent.clone();
    driver.stack.push(AgentSession {
        queue_target: crate::engine::message::QueueTarget::child(
            child.name.clone(),
            driver.stack.len(),
            "test",
            "default",
        ),
        agent: child,
        history,
        answering: None,
        deferred_log: crate::engine::deferred::DeferredLog::new(),
        fallback_decision: None,
    });
}

fn task_tool_call(call_id: &str, function_call_id: &str) -> Message {
    use rig::OneOrMany;
    use rig::message::AssistantContent;
    Message::Assistant {
        id: None,
        content: OneOrMany::one(AssistantContent::ToolCall(
            crate::engine::message::ToolCall {
                id: call_id.to_string(),
                call_id: Some(function_call_id.to_string()),
                function: rig::message::ToolFunction {
                    name: "task".into(),
                    arguments: serde_json::json!({
                        "agent": "builder",
                        "prompt": "do it"
                    }),
                },
                signature: None,
                additional_params: None,
            },
        )),
    }
}

fn tool_result_text_and_id(msg: &Message) -> Option<(String, String)> {
    use rig::message::{ToolResultContent, UserContent};
    match msg {
        Message::User { content } => content.iter().find_map(|part| match part {
            UserContent::ToolResult(result) => {
                let text = result
                    .content
                    .iter()
                    .filter_map(|part| match part {
                        ToolResultContent::Text(text) => Some(text.text.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("");
                Some((result.id.clone(), text))
            }
            _ => None,
        }),
        _ => None,
    }
}

fn push_answering_child(driver: &mut Driver, call_id: &str, function_call_id: &str) {
    let mut child = (*driver.stack[0].agent).clone();
    child.name = "builder".to_string();
    driver.stack.push(AgentSession {
        queue_target: crate::engine::message::QueueTarget::child(
            child.name.clone(),
            driver.stack.len(),
            call_id,
            "default",
        ),
        agent: Arc::new(child),
        history: vec![],
        answering: Some(PendingTaskCall {
            call_id: call_id.to_string(),
            function_call_id: Some(function_call_id.to_string()),
            repair_notes: Vec::new(),
        }),
        deferred_log: crate::engine::deferred::DeferredLog::new(),
        fallback_decision: None,
    });
}

async fn assert_unwind_reason(reason: StackUnwindReason, expected: &str) {
    let (mut driver, tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let call_id = "task-abort-1";
    let function_call_id = "fn-abort-1";
    let parent_lock = tmp.path().join("parent.txt");
    let child_lock = tmp.path().join("child.txt");
    std::fs::write(&parent_lock, "parent").unwrap();
    std::fs::write(&child_lock, "child").unwrap();

    driver.stack[0].history = vec![task_tool_call(call_id, function_call_id)];
    driver
        .locks
        .acquire(&parent_lock, "Build", driver.session.id)
        .unwrap();
    driver
        .locks
        .suspend_agent("Build", driver.session.id)
        .unwrap();
    push_answering_child(&mut driver, call_id, function_call_id);
    driver
        .locks
        .acquire(&child_lock, "builder", driver.session.id)
        .unwrap();

    let tracker = crate::engine::deleg_shrink::DelegationShrink::new(
        crate::config::providers::CacheConfig::default(),
        &crate::config::providers::ShrinkConfig::default(),
    );
    driver.deleg_shrinks.insert(
        0,
        PendingDelegationShrink {
            tracker,
            handle: None,
        },
    );

    driver.unwind_stack_to_root(reason, &tx).await;

    assert_eq!(driver.stack.len(), 1);
    assert!(
        !driver.deleg_shrinks.contains_key(&0),
        "parent-depth shrink entry must be cleared"
    );
    assert_eq!(
        driver
            .locks
            .holder(&parent_lock)
            .map(|(_, agent)| agent)
            .as_deref(),
        Some("Build"),
        "parent locks should be resumed"
    );
    assert!(
        driver.locks.holder(&child_lock).is_none(),
        "child locks should be suspended"
    );

    let (result_id, result_text) = tool_result_text_and_id(
        driver
            .stack
            .last()
            .unwrap()
            .history
            .last()
            .expect("abort tool result"),
    )
    .expect("tool result");
    assert_eq!(result_id, call_id);
    assert!(result_text.contains(expected), "{result_text}");
    assert!(!result_text.contains("## Accomplished"), "{result_text}");
    assert!(
        !result_text.contains("resume_handle"),
        "aborted child must not expose a follow-up handle: {result_text}"
    );

    let mut history = driver.stack[0].history.clone();
    let prompt = crate::engine::message::build_user_message(UserSubmission {
        kind: UserSubmissionKind::User,
        text: "next root message".into(),
        display_text: None,
        tag_expansions: Vec::new(),
        images: vec![],
        forced_skill: None,
        origin_principal: None,
        job_id: None,
        preflight_cleaned: None,
        queue_item_ids: Vec::new(),
        queue_target: None,
    });
    assert!(
        crate::engine::rehydrate::heal_live_history(&mut history, &prompt).is_empty(),
        "abort result should already pair the parent's task call"
    );

    let event = rx.try_recv().expect("subagent report event");
    match event {
        TurnEvent::SubagentReport {
            agent,
            task_call_id,
            report,
            ..
        } => {
            assert_eq!(agent, "builder");
            assert_eq!(task_call_id, call_id);
            assert!(report.contains(expected), "{report}");
        }
        other => panic!("expected subagent report, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "one child frame should emit one report"
    );

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    let event = events
        .iter()
        .find(|event| event.kind == "subagent_report" && event.call_id.as_deref() == Some(call_id))
        .expect("subagent_report session event should be recorded");
    assert_eq!(event.data["child_agent"], "builder");
    assert_eq!(event.data["task_call_id"], call_id);
    assert_eq!(event.data["label"], "default");
    let durable_report = event
        .data
        .get("report")
        .and_then(|v| v.as_str())
        .expect("subagent_report data.report");
    assert!(durable_report.contains(expected), "{durable_report}");
    assert_eq!(event.data["provider_call_id"], function_call_id);
    assert_eq!(event.data["provider_call_id_source"], "provider");
    assert_eq!(
        event.data["provider_identity"]["provider_call_id"],
        function_call_id
    );
}

/// Install a test providers override with the given context thresholds,
/// cache mode, and the active model's `context_length` so the
/// auto-prune/auto-compact triggers resolve deterministically.
fn install_test_providers(
    driver: &mut Driver,
    cache_mode: crate::config::providers::CacheMode,
    ctx: crate::config::providers::ContextConfig,
    context_length: u32,
) {
    use crate::config::providers::{
        ActiveModelRef, CacheConfig, ModelEntry, ProviderEntry, ProvidersConfig, WireApi,
    };
    let mut entry = ProviderEntry {
        url: "http://127.0.0.1:1/v1".to_string(),
        cache: CacheConfig {
            mode: cache_mode,
            ttl_secs: 300,
        },
        context: ctx,
        wire_api: WireApi::Completions,
        ..ProviderEntry::default()
    };
    entry.models.push(ModelEntry {
        id: "local".into(),
        name: None,
        thinking_modes: vec![],
        inputs: None,
        context_length: Some(context_length),
        favorite: false,
        manual: false,
        trust: None,
        location: None,
        quality_rank: None,
        cost_rank: None,
        subagent_invokable: None,
        can_delegate: None,
        computer_use: None,
        default_thinking_mode: None,
        embeddings: None,
        embedding_dimensions: None,
        availability: Default::default(),
        cache: None,
        shrink: None,
        context: None,
        auto_prune: None,
        timeout: None,
        backup: None,
        mode: None,
        inline_think: None,
        hint_tool_call_corrections: None,
        text_embedded_recovery: None,
        thinking_params: Default::default(),
        system_prompt: None,
        wire_api: WireApi::Completions,
        extra: Default::default(),
        capabilities: Default::default(),
        capability_overrides: Default::default(),
        provider_metadata: Default::default(),
    });
    let mut providers = std::collections::BTreeMap::new();
    providers.insert("lmstudio".to_string(), entry);
    let cfg = ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "lmstudio".into(),
            model: "local".into(),
            reasoning_effort: None,
            thinking_mode: None,
        }),
        ..ProvidersConfig::default()
    };
    driver.test_providers_override = Some((cfg, "lmstudio".into(), "local".into()));
}

fn record_test_context_tokens(driver: &Driver, input_tokens: u64) {
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .unwrap();
}

fn append_complete_test_turns(driver: &mut Driver, count: usize) {
    for index in 0..count {
        driver.stack[0]
            .history
            .push(Message::user(format!("shadow user {index}")));
        driver.stack[0]
            .history
            .push(Message::assistant(format!("shadow assistant {index}")));
    }
}

async fn wait_for_shadow_brief(driver: &mut Driver) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            driver.settle_shadow_brief().await;
            if matches!(driver.shadow_brief, Some(ShadowBriefState::Ready(_))) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fixture shadow brief should finish");
}

fn compact_inference_purposes(driver: &Driver) -> Vec<String> {
    driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap()
        .into_iter()
        .filter_map(|event| {
            (event.kind == "inference_request")
                .then(|| event.data["purpose"].as_str().map(str::to_string))
                .flatten()
        })
        .filter(|purpose| purpose.starts_with("compact_"))
        .collect()
}

// ---- re-queryable subagents + seeding (GOALS §3c) --------------------

use crate::db::seed_tools::SeedTool;

// ── write-capable follow-up (implementation note) ──

/// Build a driver whose root (caller) agent holds the `read` tool so
/// `inject_seeds` can re-execute a `read` seed in the caller's cwd.
fn driver_with_read_caller() -> (Driver, tempfile::TempDir) {
    let (mut driver, tmp) = test_driver(8);
    let old = driver.stack[0].agent.clone();
    let tools =
        crate::engine::tool::ToolBox::new().with(std::sync::Arc::new(crate::tools::read::ReadTool));
    driver.stack[0].agent = std::sync::Arc::new(Agent {
        name: old.name.clone(),
        system: old.system.clone(),
        role_prompt: old.role_prompt.clone(),
        tools,
        model: old.model.clone(),
        params: old.params.clone(),
        scan_tool_results: old.scan_tool_results,
        llm_mode: crate::config::extended::LlmMode::Normal,
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        env_overlay: old.env_overlay.clone(),
    });
    (driver, tmp)
}

/// A caller assistant turn that ends in a `task` tool call (the turn a
/// noninteractive delegation came from). `inject_seeds` folds seed calls
/// into this turn.
fn assistant_with_task_call(task_call_id: &str) -> Message {
    use crate::engine::message::{AssistantContent, OneOrMany, ToolCall};
    use rig::message::ToolFunction;
    Message::Assistant {
        id: None,
        content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
            id: task_call_id.to_string(),
            call_id: None,
            function: ToolFunction {
                name: "task".into(),
                arguments: serde_json::json!({ "agent": "explore", "prompt": "go" }),
            },
            signature: None,
            additional_params: None,
        })),
    }
}

fn tool_result_id(msg: &Message) -> String {
    use rig::message::UserContent;
    match msg {
        Message::User { content } => content
            .iter()
            .find_map(|part| match part {
                UserContent::ToolResult(result) => Some(result.id.clone()),
                _ => None,
            })
            .expect("tool_result id"),
        _ => panic!("expected a tool_result user message"),
    }
}

fn tool_result_provider_call_id(msg: &Message) -> Option<String> {
    use rig::message::UserContent;
    match msg {
        Message::User { content } => content.iter().find_map(|part| match part {
            UserContent::ToolResult(result) => result.call_id.clone(),
            _ => None,
        }),
        _ => panic!("expected a tool_result user message"),
    }
}

fn pending_test_shrink() -> PendingDelegationShrink {
    PendingDelegationShrink {
        tracker: crate::engine::deleg_shrink::DelegationShrink::new(
            crate::config::providers::CacheConfig::default(),
            &crate::config::providers::ShrinkConfig::default(),
        ),
        handle: None,
    }
}

fn single_noninteractive_completion(
    task_call_id: &str,
    report: &str,
) -> SingleNoninteractiveCompletion {
    SingleNoninteractiveCompletion {
        child_agent: "explore".to_string(),
        task_call_id: task_call_id.to_string(),
        task_function_call_id: Some(format!("fn-{task_call_id}")),
        report: report.to_string(),
        failed: false,
        failure: None,
        partial_progress: DelegationPartialProgress::default(),
        seeds: Vec::new(),
        new_handle: None,
        snapshot: NoninteractiveDelegationSnapshot::empty(),
        shrink: None,
        repair_notes: Vec::new(),
        child_routing: None,
    }
}

fn cold_ready_test_shrink(shrunk: Vec<Message>) -> PendingDelegationShrink {
    use crate::config::providers::{CacheConfig, CacheMode, ShrinkConfig};
    let mut tracker = crate::engine::deleg_shrink::DelegationShrink::new(
        CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 0,
        },
        &ShrinkConfig::default(),
    );
    tracker.set_shrunk(shrunk);
    PendingDelegationShrink {
        tracker,
        handle: None,
    }
}

fn seed_task_delegation(driver: &Driver, task_call_id: &str, label: &str) {
    driver
        .session
        .db
        .upsert_task_delegation_job(
            driver.session.id,
            task_call_id,
            Some("fc-test"),
            "Build",
            None,
            &[crate::db::task_delegations::DelegationChildInit {
                label,
                child_agent: "explore",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            }],
        )
        .unwrap();
}

fn seed_batch_task_delegation(driver: &Driver, task_call_id: &str, labels: &[&str]) {
    let children = labels
        .iter()
        .map(|label| crate::db::task_delegations::DelegationChildInit {
            label,
            child_agent: "explore",
            model: None,
            output_dir: None,
            requested_cwd: None,
            resolved_cwd: None,
            todo_ids_json: None,
        })
        .collect::<Vec<_>>();
    driver
        .session
        .db
        .upsert_task_delegation_job(
            driver.session.id,
            task_call_id,
            Some("fc-test"),
            "Build",
            None,
            &children,
        )
        .unwrap();
}

// ---- Caller→child read-only pre-seeding (`task.seed`) -----------------
// (implementation note). The parent→child mirror of
// `inject_seeds`: re-execute read-only seeds in the CHILD's cwd and
// prepend native tool-call/result pairs to the child's initial history.

/// A child agent holding `read` + `outline` (read-only) and `writeunlock`
/// (write) — enough to assert read-only seeds execute, a write seed is
/// never executed, and a failed read is surfaced (not aborted).
fn child_with_read_write_tools(agent: &Arc<Agent>) -> Agent {
    let tools = crate::engine::tool::ToolBox::new()
        .with(std::sync::Arc::new(crate::tools::read::ReadTool))
        .with(std::sync::Arc::new(crate::tools::intel::OutlineTool))
        .with(std::sync::Arc::new(
            crate::tools::writeunlock::WriteunlockTool,
        ));
    Agent {
        name: "explore".into(),
        system: agent.system.clone(),
        role_prompt: agent.role_prompt.clone(),
        tools,
        model: agent.model.clone(),
        params: agent.params.clone(),
        scan_tool_results: false,
        llm_mode: crate::config::extended::LlmMode::Normal,
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        env_overlay: agent.env_overlay.clone(),
    }
}

/// Build a driver whose root agent holds the `skill` tool, so
/// `seed_forced_skill` can synthesize a real `skill` tool call.
fn driver_with_skill_caller() -> (Driver, tempfile::TempDir) {
    let (mut driver, tmp) = test_driver(8);
    let old = driver.stack[0].agent.clone();
    let tools = crate::engine::tool::ToolBox::new()
        .with(std::sync::Arc::new(crate::tools::skill::SkillTool));
    driver.stack[0].agent = std::sync::Arc::new(Agent {
        name: old.name.clone(),
        system: old.system.clone(),
        role_prompt: old.role_prompt.clone(),
        tools,
        model: old.model.clone(),
        params: old.params.clone(),
        scan_tool_results: old.scan_tool_results,
        llm_mode: crate::config::extended::LlmMode::Normal,
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        env_overlay: old.env_overlay.clone(),
    });
    (driver, tmp)
}

// ---- auto-injected skill transcript visibility
// (implementation note) ----

// ---- request preflight (implementation note) ----

// ---- parent→child skill seeding ----

// --- Mid-session model switch (implementation note) ---

/// A providers config with two configured `(provider, model)` pairs (A and
/// B) — used to drive the live model-switch tests. `provider-c` is left
/// **unconfigured** so a switch to it exercises the fail-loud path.
fn two_model_providers_config() -> crate::config::providers::ProvidersConfig {
    use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig};
    use std::collections::BTreeMap;
    let mut providers = BTreeMap::new();
    providers.insert(
        "provider-a".to_string(),
        ProviderEntry {
            url: "http://localhost:1/v1".into(),
            headers: vec![],
            ..ProviderEntry::default()
        },
    );
    providers.insert(
        "provider-b".to_string(),
        ProviderEntry {
            url: "http://localhost:2/v1".into(),
            headers: vec![],
            ..ProviderEntry::default()
        },
    );
    ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "provider-a".into(),
            model: "model-a".into(),
            reasoning_effort: None,
            thinking_mode: None,
        }),
        ..ProvidersConfig::default()
    }
}

/// Re-root the driver on model A (`provider-a/model-a`) and install the
/// two-provider test config so the live switch resolves against it. Returns
/// the driver rooted on a real `Build` primary built through the same
/// factory production uses.
fn model_switch_driver() -> (Driver, tempfile::TempDir) {
    let (mut driver, tmp) = test_driver(1);
    let cfg = two_model_providers_config();
    // Build model A and root a genuine `Build` primary on it.
    let model_a = Arc::new(
        crate::engine::model::Model::for_provider(
            &cfg,
            "provider-a",
            "model-a",
            Arc::new(crate::redact::RedactionTable::empty()),
        )
        .unwrap(),
    );
    driver
        .session
        .set_active_model("provider-a", "model-a")
        .unwrap();
    driver.test_providers_override = Some((cfg, "provider-a".into(), "model-a".into()));
    let mut args = driver.spawn_args(true);
    args.model = model_a;
    driver.stack[0].agent = Arc::new(crate::engine::builtin::load("Build", &args).unwrap());
    (driver, tmp)
}
