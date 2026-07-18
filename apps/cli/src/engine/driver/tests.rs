use super::*;

#[tokio::test]
async fn noninteractive_event_forwarder_wraps_child_events() {
    let (child_tx, child_rx) = mpsc::channel(8);
    let (parent_tx, mut parent_rx) = mpsc::channel(8);
    let target = NoninteractiveSteerTarget::new("task-1", "default");
    let forwarder = spawn_noninteractive_event_forwarder(child_rx, Some(parent_tx), Some(target));

    child_tx
        .send(TurnEvent::AssistantTextDelta {
            agent: "Explore".into(),
            delta: "hel".into(),
        })
        .await
        .unwrap();
    child_tx
        .send(TurnEvent::AssistantTextDelta {
            agent: "Explore".into(),
            delta: "lo".into(),
        })
        .await
        .unwrap();
    child_tx
        .send(TurnEvent::ToolStart {
            agent: "Explore".into(),
            call_id: "call-1".into(),
            tool: "read".into(),
            args: serde_json::json!({"path":"README.md"}),
        })
        .await
        .unwrap();
    drop(child_tx);
    forwarder.await.unwrap();

    match parent_rx.recv().await.unwrap() {
        TurnEvent::NestedTurn {
            task_call_id,
            label,
            parent_task_call_id,
            inner,
        } => {
            assert_eq!(task_call_id, "task-1");
            assert_eq!(label, "default");
            assert_eq!(parent_task_call_id, None);
            assert!(matches!(
                inner.as_ref(),
                TurnEvent::AssistantTextDelta { agent, delta }
                    if agent == "Explore" && delta == "hello"
            ));
        }
        other => panic!("expected nested assistant delta, got {other:?}"),
    }
    match parent_rx.recv().await.unwrap() {
        TurnEvent::NestedTurn { inner, .. } => assert!(matches!(
            inner.as_ref(),
            TurnEvent::ToolStart { agent, call_id, tool, .. }
                if agent == "Explore" && call_id == "call-1" && tool == "read"
        )),
        other => panic!("expected nested tool start, got {other:?}"),
    }
    assert!(parent_rx.recv().await.is_none());
}

fn test_provider_base_url() -> String {
    static BASE_URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BASE_URL
        .get_or_init(|| {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else {
                        continue;
                    };
                    let mut request = Vec::new();
                    let mut buf = [0_u8; 512];
                    loop {
                        let Ok(n) = std::io::Read::read(&mut stream, &mut buf) else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..n]);
                        if request.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let header_end = request
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|idx| idx + 4)
                        .unwrap_or(request.len());
                    let header =
                        String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
                    let content_length = header
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let mut body_read = request.len().saturating_sub(header_end);
                    while body_read < content_length {
                        let Ok(n) = std::io::Read::read(&mut stream, &mut buf) else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        body_read += n;
                    }
                    let payload = if header.starts_with("post /v1/responses ") {
                        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"test compact brief\"}\n\n\
                         data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"created_at\":1,\"status\":\"completed\",\"error\":null,\"incomplete_details\":null,\"instructions\":null,\"max_output_tokens\":null,\"model\":\"local\",\"usage\":{\"input_tokens\":1,\"input_tokens_details\":{\"cached_tokens\":0},\"output_tokens\":3,\"output_tokens_details\":{\"reasoning_tokens\":0},\"total_tokens\":4},\"output\":[{\"type\":\"message\",\"id\":\"msg_1\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"annotations\":[],\"text\":\"test compact brief\"}]}],\"tools\":[]}}\n\n"
                    } else {
                        "data: {\"id\":\"c\",\"model\":\"local\",\"choices\":[{\"delta\":{\"content\":\"test compact brief\"},\"finish_reason\":null}],\"usage\":null}\n\n\
                         data: {\"id\":\"c\",\"model\":\"local\",\"choices\":[{\"delta\":{\"content\":\"\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":3,\"total_tokens\":4}}\n\n\
                         data: [DONE]\n\n"
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    let _ = std::io::Write::write_all(&mut stream, resp.as_bytes());
                    let _ = std::io::Write::flush(&mut stream);
                }
            });
            format!("http://{addr}/v1")
        })
        .clone()
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

fn learn_tool_args(name: &str) -> serde_json::Value {
    serde_json::json!({
        "action": "create",
        "name": name,
        "description": "Repeat a verified setup workflow",
        "content": "## When to Use\n\nUse for the verified setup.\n\n## Procedure\n\n1. Run the verified command.\n\n## Pitfalls\n\nDo not invent flags.\n\n## Verification\n\nConfirm the expected output."
    })
}

fn scripted_learn_provider(
    args: serde_json::Value,
    request_count: usize,
) -> (String, std::sync::mpsc::Receiver<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for request_index in 0..request_count {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let n = std::io::Read::read(&mut stream, &mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let header_end = header_end + 4;
                let header = String::from_utf8_lossy(&request[..header_end]);
                let content_length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + content_length {
                    break;
                }
            }
            let header_end = request
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|index| index + 4)
                .unwrap();
            request_tx
                .send(String::from_utf8_lossy(&request[header_end..]).to_string())
                .unwrap();

            let body = if request_index == 0 {
                let start = serde_json::json!({
                    "id": "learn-1",
                    "model": "local",
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "tool_calls": [{
                                "index": 0,
                                "id": "learn-save",
                                "type": "function",
                                "function": {
                                    "name": "skill_manage",
                                    "arguments": args.to_string()
                                }
                            }]
                        },
                        "finish_reason": null
                    }],
                    "usage": null
                });
                let finish = serde_json::json!({
                    "id": "learn-1",
                    "model": "local",
                    "choices": [{
                        "index": 0,
                        "delta": {"tool_calls": []},
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2
                    }
                });
                format!("data: {start}\n\ndata: {finish}\n\ndata: [DONE]\n\n")
            } else {
                let text = serde_json::json!({
                    "id": "learn-2",
                    "model": "local",
                    "choices": [{
                        "index": 0,
                        "delta": {"content": "Saved the reusable skill."},
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2
                    }
                });
                format!("data: {text}\n\ndata: [DONE]\n\n")
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            std::io::Write::write_all(&mut stream, response.as_bytes()).unwrap();
        }
    });
    (format!("http://{addr}/v1"), request_rx)
}

fn learn_driver(
    approval: bool,
    skill_name: &str,
    request_count: usize,
) -> (
    Driver,
    tempfile::TempDir,
    std::path::PathBuf,
    std::sync::mpsc::Receiver<String>,
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

    let (provider_url, requests) =
        scripted_learn_provider(learn_tool_args(skill_name), request_count);
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
    (driver, tmp, root, requests)
}

#[tokio::test]
async fn learn_saves_conformant_foreground_skill() {
    let (mut driver, tmp, root, requests) = learn_driver(false, "learned-workflow", 2);
    let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let (turn_tx, _turn_rx) = mpsc::channel(64);
    let prompt = crate::commands::learn::build_learn_prompt("");

    driver
        .run_user_input(UserSubmission::text(prompt.clone()), &queue, &turn_tx)
        .await
        .unwrap();

    let first_request = requests
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(first_request.contains("cockpit verify --local"));
    assert!(first_request.contains("local verification completed successfully"));
    assert!(first_request.contains("Create a reusable Agent Skill"));
    assert!(first_request.contains("skill_manage"));
    requests
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();

    let config = crate::config::extended::load_for_cwd(tmp.path());
    let skills = crate::skills::discover(tmp.path(), &config.skills).unwrap();
    let skill = crate::skills::find_by_name(&skills, "learned-workflow").unwrap();
    crate::skills::validate_conformant_package(skill).unwrap();
    let provenance: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("learned-workflow/.cockpit-provenance.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(provenance["created_origin"], "foreground");
}

#[tokio::test]
async fn learn_respects_write_gate() {
    let (mut driver, _tmp, root, requests) = learn_driver(true, "gated-learn", 1);
    let db = driver.session.db.clone();
    let session_id = driver.session.id;
    let (events, _event_rx) = tokio::sync::broadcast::channel(8);
    let hub = Arc::new(crate::engine::interrupt::InterruptHub::new(
        events,
        Arc::new(std::sync::RwLock::new(Arc::new(
            crate::redact::RedactionTable::empty(),
        ))),
        Arc::new(std::sync::atomic::AtomicUsize::new(1)),
        db.clone(),
        session_id,
    ));
    driver.set_interrupt_hub(hub.clone());
    let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let (turn_tx, _turn_rx) = mpsc::channel(64);
    let task = tokio::spawn(async move {
        driver
            .run_user_input(
                UserSubmission::text(crate::commands::learn::build_learn_prompt(
                    "our verified workflow",
                )),
                &queue,
                &turn_tx,
            )
            .await
    });

    loop {
        if !db.list_open_interrupts(session_id).unwrap().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(hub.park_all_registered(), 1);
    task.await.unwrap().unwrap();
    assert!(!root.join("gated-learn/SKILL.md").exists());
    let row = db.list_open_interrupts(session_id).unwrap().remove(0);
    let parked = row.parked.unwrap();
    assert_eq!(parked.tool, "skill_manage");
    assert_eq!(parked.call_id, "learn-save");
    assert_eq!(parked.args, learn_tool_args("gated-learn"));
    assert_eq!(
        parked.resume.call_origin,
        crate::db::needs_attention::InterruptCallOrigin::Foreground
    );
    let first_request = requests
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(first_request.contains("cockpit verify --local"));
    assert!(first_request.contains("our verified workflow"));
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

#[test]
fn task_recursion_rejects_delegated_child_without_budget() {
    let (mut driver, _tmp) = test_driver(1);
    set_active_delegated_recursion(
        &mut driver,
        crate::engine::builtin::DelegationRecursionContext::default(),
    );

    let err = driver
        .resolve_task_recursion("explore", Some(0), &None)
        .expect_err("no recursive budget");
    assert!(
        err.contains("not allowed") || err.contains("no remaining"),
        "{err}"
    );
}

#[test]
fn task_recursion_must_reduce_inherited_depth() {
    let (mut driver, _tmp) = test_driver(1);
    set_active_delegated_recursion(
        &mut driver,
        crate::engine::builtin::DelegationRecursionContext {
            enabled: true,
            remaining_depth: 1,
            allowed_targets: vec!["explore".to_string()],
            same_model_only: true,
        },
    );

    let err = driver
        .resolve_task_recursion("explore", Some(1), &None)
        .expect_err("child depth must be lower than parent depth");
    assert!(err.contains("exceeds"), "{err}");

    let child = driver
        .resolve_task_recursion("explore", Some(0), &None)
        .expect("leaf explore recursion allowed");
    assert_eq!(child.remaining_depth, 0);
    assert!(child.same_model_only);
    assert_eq!(child.allowed_targets, vec!["explore".to_string()]);
}

#[test]
fn task_recursion_rejects_model_selector_for_same_model_special_case() {
    let (mut driver, _tmp) = test_driver(1);
    set_active_delegated_recursion(
        &mut driver,
        crate::engine::builtin::DelegationRecursionContext {
            enabled: true,
            remaining_depth: 1,
            allowed_targets: vec!["explore".to_string()],
            same_model_only: true,
        },
    );
    let model =
        crate::engine::model_roles::DelegationModelSelector::from_value(Some(&serde_json::json!({
            "kind": "category",
            "category": "cheap_code"
        })))
        .unwrap();

    let err = driver
        .resolve_task_recursion("explore", Some(0), &model)
        .expect_err("same-model recursion rejects model selector");
    assert!(err.contains("must omit `model`"), "{err}");
}

#[test]
fn task_recursion_rejects_deepthink_depth() {
    let (driver, _tmp) = test_driver(1);
    let err = driver
        .resolve_task_recursion("deepthink", Some(1), &None)
        .expect_err("deepthink is always a leaf");
    assert!(err.contains("tool-free leaf"), "{err}");

    let leaf = driver
        .resolve_task_recursion("deepthink", Some(0), &None)
        .expect("leaf deepthink delegation is allowed");
    assert_eq!(leaf.remaining_depth, 0);
    assert!(leaf.allowed_targets.is_empty());
}

#[tokio::test]
async fn quick_recursion_override_off_rejects_root_recursive_depth() {
    let (mut driver, tmp) = test_driver(1);
    write_recursion_policy(tmp.path());
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .run_control(
            DriverControl::SetDelegationRecursion {
                enabled: false,
                default_depth: 0,
            },
            &tx,
        )
        .await;

    let err = driver
        .resolve_task_recursion("Build", Some(1), &None)
        .expect_err("quick off disables root recursion");
    assert!(err.contains("disabled"), "{err}");
}

#[tokio::test]
async fn quick_recursion_override_depths_apply_without_bypassing_policy() {
    for depth in 1..=6 {
        let (mut driver, tmp) = test_driver(1);
        write_recursion_policy(tmp.path());
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

        driver
            .run_control(
                DriverControl::SetDelegationRecursion {
                    enabled: true,
                    default_depth: depth,
                },
                &tx,
            )
            .await;

        let ctx = driver
            .resolve_task_recursion("Build", None, &None)
            .expect("default depth grants allowed recursive child");
        assert_eq!(ctx.remaining_depth, depth);
        assert!(ctx.enabled);

        let err = driver
            .resolve_task_recursion("Plan", None, &None)
            .expect_err("override must not bypass allowed-target policy");
        assert!(err.contains("may not grant"), "{err}");
    }
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

#[test]
fn goal_read_only_turns_count_as_no_progress_after_bound() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "ship without looping on reads",
            None,
            None,
        )
        .unwrap();
    driver.goal_progress_last_seq = driver.latest_session_event_seq();

    record_goal_tool_event(&driver, "read", serde_json::json!({"path": "src/lib.rs"}));
    let first = driver.observe_goal_progress_turn().unwrap();
    assert!(first.no_progress());
    assert_eq!(driver.goal_turns_since_mutating_action, 1);
    assert_eq!(driver.goal_turns_since_goal_context_delta, 1);

    record_goal_tool_event(
        &driver,
        "grep",
        serde_json::json!({"pattern": "TODO", "path": "src"}),
    );
    let second = driver.observe_goal_progress_turn().unwrap();

    assert!(second.no_progress());
    assert_eq!(
        driver.goal_turns_since_mutating_action,
        GOAL_NO_PROGRESS_NUDGE_BOUND
    );
    assert!(
        driver.goal_turns_since_goal_context_delta >= GOAL_NO_PROGRESS_NUDGE_BOUND,
        "read/search-only turns should cross the nudge bound"
    );
    assert_eq!(driver.goal_stall_prompt(), GOAL_IDLE_CONTINUATION);
}

#[test]
fn goal_mutating_action_and_context_delta_reset_progress_counters() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "reset counters on durable progress",
            None,
            None,
        )
        .unwrap();
    driver.goal_progress_last_seq = driver.latest_session_event_seq();
    driver.goal_turns_since_mutating_action = 4;
    driver.goal_turns_since_goal_context_delta = 4;

    record_goal_tool_event(
        &driver,
        "writeunlock",
        serde_json::json!({"path": "src/lib.rs", "content": "changed"}),
    );
    let mutating = driver.observe_goal_progress_turn().unwrap();
    assert!(mutating.mutating_action);
    assert_eq!(driver.goal_turns_since_mutating_action, 0);
    assert_eq!(driver.goal_turns_since_goal_context_delta, 5);

    record_goal_tool_event(
        &driver,
        "update_goal",
        serde_json::json!({"status": "active", "context_delta": "edited src/lib.rs"}),
    );
    let context = driver.observe_goal_progress_turn().unwrap();
    assert!(context.context_delta);
    assert_eq!(driver.goal_turns_since_goal_context_delta, 0);
    assert_eq!(driver.goal_turns_since_mutating_action, 1);
}

#[test]
fn goal_prose_without_tools_counts_as_no_progress_subset() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "catch prose-only stalls",
            None,
            None,
        )
        .unwrap();
    driver.goal_progress_last_seq = driver.latest_session_event_seq();
    driver
        .stack
        .first_mut()
        .unwrap()
        .history
        .push(Message::assistant("I will keep working."));

    let observation = driver.observe_goal_progress_turn().unwrap();

    assert!(observation.no_progress());
    assert_eq!(driver.goal_turns_since_mutating_action, 1);
    assert_eq!(driver.goal_turns_since_goal_context_delta, 1);
}

#[tokio::test]
async fn goal_no_progress_intervention_waits_for_budget_cap() {
    let (mut driver, tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "do not stop at three strikes",
            None,
            None,
        )
        .unwrap();
    driver.goal_no_tool_idle_count = 5;
    driver.goal_turns_since_mutating_action = GOAL_NO_PROGRESS_NUDGE_BOUND;
    driver.goal_turns_since_goal_context_delta = GOAL_NO_PROGRESS_NUDGE_BOUND;
    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();
    assert!(
        !driver.goal_continuation_budget_exhausted(&goal),
        "fixed strike count must not be the terminating condition"
    );
    assert_eq!(driver.goal_stall_prompt(), GOAL_IDLE_CONTINUATION_STRONGEST);
    assert!(!driver.goal_idle_intervention_pending);

    driver
        .session
        .db
        .insert_inference_call(&crate::db::inference_calls::InferenceCallRow {
            call_id: uuid::Uuid::new_v4(),
            session_id: driver.session.id,
            project_id: driver.session.project_id.clone(),
            project_root: tmp.path().display().to_string(),
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            input_tokens: GOAL_DEFAULT_CONTINUATION_TOKEN_CAP,
            output_tokens: 0,
            cached_input_tokens: 0,
            cache_creation_input_tokens: 0,
            cost_usd_micros: None,
            is_utility: false,
        })
        .unwrap();
    driver
        .session
        .db
        .refresh_session_goal_usage(driver.session.id)
        .unwrap();
    let capped = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .emit_goal_no_progress_budget_exhausted(&capped, &tx)
        .await;

    assert!(driver.goal_idle_intervention_pending);
    assert_eq!(
        driver.take_idle_reason(),
        crate::engine::IdleReason::NeedsIntervention {
            code: "agent_failed_to_progress_budget_exhausted".to_string()
        }
    );
    match rx
        .try_recv()
        .expect("budget intervention notice should emit")
    {
        TurnEvent::Notice { text } => {
            assert!(text.contains("agent_failed_to_progress_budget_exhausted"));
        }
        other => panic!("expected intervention Notice, got {other:?}"),
    }
}

#[tokio::test]
async fn goal_budget_autopause_idle_reason_is_budget_limited() {
    let (mut driver, tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "stay within budget",
            None,
            Some(1),
        )
        .unwrap();
    driver
        .session
        .db
        .insert_inference_call(&crate::db::inference_calls::InferenceCallRow {
            call_id: uuid::Uuid::new_v4(),
            session_id: driver.session.id,
            project_id: driver.session.project_id.clone(),
            project_root: tmp.path().display().to_string(),
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            input_tokens: 2,
            output_tokens: 0,
            cached_input_tokens: 0,
            cache_creation_input_tokens: 0,
            cost_usd_micros: None,
            is_utility: false,
        })
        .unwrap();
    driver
        .session
        .db
        .refresh_session_goal_usage(driver.session.id)
        .unwrap();
    let (queue_updates_tx, _queue_updates_rx) = mpsc::unbounded_channel();
    let input_queue = crate::engine::message::UserSubmissionQueue::new(queue_updates_tx);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .maybe_continue_active_goal(&input_queue, &tx)
        .await
        .unwrap();

    assert_eq!(
        driver.take_idle_reason(),
        crate::engine::IdleReason::BudgetLimited
    );
}

#[tokio::test]
async fn stalled_goal_token_budget_exhaustion_needs_intervention() {
    let (mut driver, tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "stop stalled work at explicit budget",
            None,
            Some(10),
        )
        .unwrap();
    driver.goal_turns_since_mutating_action = GOAL_NO_PROGRESS_NUDGE_BOUND;
    driver.goal_turns_since_goal_context_delta = GOAL_NO_PROGRESS_NUDGE_BOUND;
    driver
        .session
        .db
        .insert_inference_call(&crate::db::inference_calls::InferenceCallRow {
            call_id: uuid::Uuid::new_v4(),
            session_id: driver.session.id,
            project_id: driver.session.project_id.clone(),
            project_root: tmp.path().display().to_string(),
            model: "test-model".to_string(),
            provider: "test-provider".to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            input_tokens: 10,
            output_tokens: 0,
            cached_input_tokens: 0,
            cache_creation_input_tokens: 0,
            cost_usd_micros: None,
            is_utility: false,
        })
        .unwrap();
    driver
        .session
        .db
        .refresh_session_goal_usage(driver.session.id)
        .unwrap();
    let (queue_updates_tx, _queue_updates_rx) = mpsc::unbounded_channel();
    let input_queue = crate::engine::message::UserSubmissionQueue::new(queue_updates_tx);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .maybe_continue_active_goal(&input_queue, &tx)
        .await
        .unwrap();

    assert!(driver.goal_idle_intervention_pending);
    assert_eq!(
        driver.take_idle_reason(),
        crate::engine::IdleReason::NeedsIntervention {
            code: "agent_failed_to_progress_budget_exhausted".to_string()
        }
    );
}

#[tokio::test]
async fn goal_usage_limit_failure_pauses_goal_and_arms_backoff() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "keep going through provider throttling",
            None,
            None,
        )
        .unwrap();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let failure = crate::engine::model::InferenceFailure {
        provider: "test-provider".to_string(),
        model: "test-model".to_string(),
        phase: "stream".to_string(),
        class: "http_429".to_string(),
        elapsed_ms: 42,
        detail: "rate limited".to_string(),
    };

    assert!(driver.handle_goal_usage_limit_failure(&failure, &tx).await);

    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();
    assert_eq!(
        goal.status,
        crate::db::session_goals::GoalStatus::UsageLimited
    );
    assert_eq!(
        driver.take_idle_reason(),
        crate::engine::IdleReason::UsageLimited
    );
    let mut watchdog = None;
    driver.refresh_goal_watchdog(&mut watchdog);
    assert!(watchdog.is_some(), "usage_limited goal should arm backoff");
    match rx.try_recv().expect("usage-limit notice should emit") {
        TurnEvent::Notice { text } => {
            assert!(text.contains("auto-resuming after backoff"), "{text}");
        }
        other => panic!("expected usage-limit Notice, got {other:?}"),
    }
}

#[test]
fn goal_usage_limit_watchdog_auto_resumes_to_active() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "resume after throttling",
            None,
            None,
        )
        .unwrap();
    driver
        .session
        .db
        .update_session_goal(
            driver.session.id,
            crate::db::session_goals::GoalStatus::UsageLimited,
            None,
            None,
            Some("provider usage or rate limit reached"),
        )
        .unwrap();

    let action = driver.goal_usage_limit_watchdog_action().unwrap();

    assert_eq!(action, GoalUsageLimitWatchdogAction::AutoResume);
    assert_eq!(driver.goal_usage_limit_auto_resume_attempts, 1);
    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();
    assert_eq!(goal.status, crate::db::session_goals::GoalStatus::Active);
}

#[tokio::test]
async fn persistent_goal_usage_limit_requires_manual_resume_after_bound() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "stop retrying after bounded throttling",
            None,
            None,
        )
        .unwrap();
    driver.goal_usage_limit_auto_resume_attempts = GOAL_USAGE_LIMIT_MAX_AUTO_RESUME_ATTEMPTS;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let failure = crate::engine::model::InferenceFailure {
        provider: "test-provider".to_string(),
        model: "test-model".to_string(),
        phase: "dispatch".to_string(),
        class: "rate_limit_exceeded".to_string(),
        elapsed_ms: 7,
        detail: "quota exhausted".to_string(),
    };

    assert!(driver.handle_goal_usage_limit_failure(&failure, &tx).await);

    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();
    assert_eq!(
        goal.status,
        crate::db::session_goals::GoalStatus::UsageLimited
    );
    assert_eq!(
        driver.take_idle_reason(),
        crate::engine::IdleReason::NeedsIntervention {
            code: GOAL_USAGE_LIMIT_INTERVENTION_CODE.to_string()
        }
    );
    let mut watchdog = None;
    driver.refresh_goal_watchdog(&mut watchdog);
    assert!(
        watchdog.is_none(),
        "bounded usage-limit exhaustion should not re-arm auto-resume"
    );
    match rx.try_recv().expect("manual resume notice should emit") {
        TurnEvent::Notice { text } => {
            assert!(text.contains("run `/goal resume`"), "{text}");
        }
        other => panic!("expected manual resume Notice, got {other:?}"),
    }
}

#[test]
fn ordinary_non_goal_idle_reason_is_completed() {
    let (mut driver, _tmp) = test_driver(1);

    assert_eq!(
        driver.take_idle_reason(),
        crate::engine::IdleReason::Completed
    );
}

#[tokio::test]
async fn goal_idle_intervention_idle_reason_carries_code() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "ship goal flow",
            None,
            None,
        )
        .unwrap();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let goal = driver
        .session
        .db
        .current_session_goal(driver.session.id, false)
        .unwrap()
        .unwrap();

    driver
        .emit_goal_no_progress_budget_exhausted(&goal, &tx)
        .await;

    assert_eq!(
        driver.take_idle_reason(),
        crate::engine::IdleReason::NeedsIntervention {
            code: "agent_failed_to_progress_budget_exhausted".to_string()
        }
    );
}

#[tokio::test]
async fn goal_continue_only_maintenance_events_emits_diagnostic_and_keeps_latch() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "ship goal flow",
            None,
            None,
        )
        .unwrap();
    driver.goal_idle_intervention_pending = true;
    let anchor = driver.latest_session_event_seq();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "continue"}),
        )
        .unwrap();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::SkillAutoSelect,
            Some("Build"),
            None,
            &serde_json::json!({"rejections": []}),
        )
        .unwrap();
    driver
        .session
        .record_context_pruned(
            "Build",
            true,
            4,
            4,
            120,
            120,
            &[],
            "exact-identity",
            0,
            None,
            Some("cache_already_cold"),
        )
        .unwrap();
    let call_id = uuid::Uuid::new_v4().to_string();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::InferenceRequest,
            Some("Build"),
            Some(&call_id),
            &serde_json::json!({"usage": null}),
        )
        .unwrap();

    assert!(
        !driver.goal_continue_progress_since(anchor),
        "skill diagnostics, context_pruned, and inference_request are maintenance only"
    );

    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    driver.emit_goal_continue_no_progress(anchor, &tx).await;
    let notice = rx.try_recv().expect("diagnostic notice should emit");
    match notice {
        TurnEvent::Notice { text } => {
            assert!(text.contains("agent_failed_to_progress_after_continue"));
        }
        other => panic!("expected diagnostic Notice, got {other:?}"),
    }
    assert!(
        driver.goal_idle_intervention_pending,
        "no-progress continue keeps the intervention latch active"
    );
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    let diagnostic = events
        .iter()
        .find(|event| event.kind == "goal_progress_diagnostic")
        .expect("goal progress diagnostic is durable");
    assert_eq!(diagnostic.data["kind"], "goal_continue_no_progress");
    assert_eq!(diagnostic.data["anchor_seq"], serde_json::json!(anchor));
}

#[tokio::test]
async fn goal_continue_progress_accepts_goal_status_update() {
    let (driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "ship goal flow",
            None,
            None,
        )
        .unwrap();
    let anchor = driver.latest_session_event_seq();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({"text": "continue"}),
        )
        .unwrap();
    driver
        .session
        .db
        .current_session_goal(driver.session.id, true)
        .unwrap();
    driver
        .session
        .db
        .update_session_goal(
            driver.session.id,
            crate::db::session_goals::GoalStatus::Complete,
            Some("done"),
            None,
            None,
        )
        .unwrap();

    assert!(
        driver.goal_continue_progress_since(anchor),
        "terminal goal status is progress even if no further tool is needed"
    );
}

#[tokio::test]
async fn failed_turn_recovery_records_retry_context_and_progress() {
    let (mut driver, _tmp) = test_driver(1);
    driver
        .session
        .db
        .create_session_goal(
            driver.session.id,
            &driver.session.project_id,
            "ship the recovery path",
            None,
            None,
        )
        .unwrap();
    driver.stack[0]
        .history
        .push(write_turn("edit-1", "src/lib.rs"));
    driver.stack[0]
        .history
        .push(bash_turn("bash-1", "cargo test"));
    let agent = driver.stack[0].agent.clone();
    let attempted = Message::user("continue implementing the retry contract");
    let call_id = uuid::Uuid::new_v4();
    let failure = crate::engine::model::InferenceFailure {
        provider: "codex-oauth".into(),
        model: "gpt-5.5".into(),
        phase: "first_token".into(),
        class: "network".into(),
        elapsed_ms: 42_000,
        detail: "HTTP 503 Service Unavailable".into(),
    };
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .record_failed_turn_recovery(&agent, &attempted, call_id, &failure, &tx)
        .await;

    let notice = rx.try_recv().expect("retry notice emitted");
    match notice {
        TurnEvent::Notice { text } => {
            assert!(text.contains("continue"));
            assert!(text.contains("retry the same turn"));
        }
        other => panic!("expected Notice, got {other:?}"),
    }
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    let recovery = events
        .iter()
        .find(|event| event.kind == "failed_turn_recovery")
        .expect("failed_turn_recovery event recorded");
    let call_id_str = call_id.to_string();
    assert_eq!(recovery.call_id.as_deref(), Some(call_id_str.as_str()));
    assert_eq!(recovery.data["status"], "needs_retry");
    assert_eq!(
        recovery.data["active_prompt"]["text"],
        "continue implementing the retry contract"
    );
    assert_eq!(
        recovery.data["active_goal"]["objective"],
        "ship the recovery path"
    );
    assert_eq!(recovery.data["provider"], "codex-oauth");
    assert_eq!(recovery.data["model"], "gpt-5.5");
    assert_eq!(recovery.data["wire_api"], "completions");
    assert_eq!(recovery.data["phase_reached"], "first_token");
    assert_eq!(
        recovery.data["retry_final_decision"],
        "terminal_after_retry_layer"
    );
    assert_eq!(
        recovery.data["recommended_action"]["kind"],
        "retry_same_turn"
    );
    assert_eq!(recovery.data["last_action"], "bash `cargo test`");
    assert_eq!(recovery.data["files_edited"][0]["path"], "src/lib.rs");
    assert_eq!(recovery.data["commands"][0]["verification"], true);
    assert_eq!(
        recovery.data["worktree"]["dirty_files"][0],
        serde_json::json!("src/lib.rs")
    );
}

#[tokio::test]
async fn failed_turn_continue_reuses_and_consumes_recovery_record() {
    let (driver, _tmp) = test_driver(1);
    let recovery_id = uuid::Uuid::new_v4().to_string();
    driver
        .session
        .record_event(
            crate::db::session_log::SessionEventKind::FailedTurnRecovery,
            Some("Build"),
            Some(&recovery_id),
            &serde_json::json!({
                "status": "needs_retry",
                "recovery_id": recovery_id.clone(),
                "active_prompt": {
                    "text": "original failed prompt",
                    "truncated": false,
                    "has_non_text_parts": false
                }
            }),
        )
        .unwrap();

    let (id, prompt) = driver
        .failed_turn_retry_prompt_for("continue")
        .expect("continue should recover prompt");
    assert_eq!(id, recovery_id);
    assert_eq!(prompt, "original failed prompt");

    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    driver.record_failed_turn_retry_started(&id, &tx).await;
    assert!(matches!(
        rx.try_recv().unwrap(),
        TurnEvent::Notice { text } if text.contains("retrying failed turn")
    ));
    assert!(
        driver.failed_turn_retry_prompt_for("continue").is_none(),
        "retry_started should prevent stale repeated continue"
    );
}

/// Build a driver rooted on the real `Auto` front-door agent — the
/// handoff scenario. The model is keyless localhost and never called:
/// these tests drive [`Driver::apply_handoff`] (the engine side of a
/// model-issued `handoff` call) directly, so no inference round-trips.
fn auto_rooted_driver() -> (Driver, tempfile::TempDir) {
    let (mut driver, tmp) = test_driver(1);
    // Re-root on a genuine `Auto`, built through the same factory the
    // session worker uses, so its tool surface + name match production.
    let auto = crate::engine::builtin::load("Auto", &driver.spawn_args(true)).unwrap();
    driver.stack[0].agent = Arc::new(auto);
    driver.session.set_active_agent("Auto").unwrap();
    (driver, tmp)
}

#[tokio::test]
async fn turn_boundary_refresh_picks_up_new_dotenv_secret_for_driver_model_and_schedule() {
    let (mut driver, tmp) = test_driver(1);
    std::fs::write(tmp.path().join(".env"), "NEW_SECRET=turn-boundary-secret\n").unwrap();
    let (tx, _rx) = mpsc::channel(8);

    driver.refresh_redaction_table_for_turn(&tx).await;

    for scrubbed in [
        driver.redact.scrub("turn-boundary-secret"),
        driver.stack[0]
            .agent
            .model
            .redact_table()
            .scrub("turn-boundary-secret"),
        driver
            .schedule
            .redaction_table()
            .scrub("turn-boundary-secret"),
    ] {
        assert!(!scrubbed.contains("turn-boundary-secret"));
        assert!(scrubbed.contains("REDACTED"));
    }
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

/// A `builder` delegation that wrote a file returns a structured envelope with
/// `files_changed` derived deterministically from its edits — not prose.
#[test]
fn builder_report_is_structured_envelope_with_host_derived_files() {
    let (driver, _tmp) = test_driver(1);
    let builder = crate::engine::builtin::load("builder", &driver.spawn_args(true)).unwrap();
    let history = vec![
        write_turn("w1", "/src/a.rs"),
        Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
        Message::assistant("I changed the file."),
    ];
    let deferred = crate::engine::deferred::DeferredLog::new();
    // Via the structural `return` tool: the model fields plus the host
    // ledger render together.
    let fields = serde_json::json!({
        "accomplished": "added the flag",
        "decisions_made": "used a u32",
    });
    let report = assemble_subagent_report(&builder, &history, &deferred, Some(&fields));
    assert!(report.contains("## Accomplished"));
    assert!(report.contains("added the flag"));
    assert!(report.contains("## Decisions made"));
    assert!(report.contains("## Files changed"));
    assert!(report.contains("/src/a.rs"));
    assert!(report.contains("abc123"));
}

/// A read-only `explore` delegation returns the same envelope shape with an
/// empty `files_changed` (it issued no write/edit/unlock calls), and the
/// no-return-tool fallback wraps its final text as `accomplished`.
#[test]
fn explore_report_envelope_has_empty_files_and_fallback_wraps_final_text() {
    let (driver, _tmp) = test_driver(1);
    let explore = crate::engine::builtin::load("explore", &driver.spawn_args(false)).unwrap();
    let history = vec![Message::assistant("the bug is in foo.rs line 10")];
    let deferred = crate::engine::deferred::DeferredLog::new();
    // No `return` call (fallback): final text becomes `accomplished`; no
    // files section because nothing was written.
    let report = assemble_subagent_report(&explore, &history, &deferred, None);
    assert!(report.contains("## Accomplished"));
    assert!(report.contains("the bug is in foo.rs line 10"));
    assert!(
        !report.contains("## Files changed"),
        "read-only run must not list files: {report}"
    );
}

/// The `docs` pipeline is exempt: a `docs`-style agent holds no `return`
/// tool, so `assemble_subagent_report` returns its plain answer unchanged
/// (no envelope headers).
#[test]
fn docs_style_agent_without_return_tool_reports_plain_answer() {
    // A bare agent with an empty toolbox stands in for the `docs` answerer
    // (a pipeline stage, not an AgentDef) — it holds no `return` tool.
    let (driver, _tmp) = test_driver(1);
    let plain = Agent {
        name: "docs-answerer".into(),
        system: String::new(),
        role_prompt: String::new(),
        tools: crate::engine::tool::ToolBox::new(),
        model: driver.stack[0].agent.model.clone(),
        params: crate::engine::model::ModelParams::default(),
        scan_tool_results: false,
        llm_mode: crate::config::extended::LlmMode::default(),
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        env_overlay: driver.stack[0].agent.env_overlay.clone(),
    };
    let history = vec![Message::assistant("The answer is to call foo() with bar.")];
    let deferred = crate::engine::deferred::DeferredLog::new();
    let report = assemble_subagent_report(&plain, &history, &deferred, None);
    assert_eq!(report, "The answer is to call foo() with bar.");
    assert!(!report.contains("## Accomplished"));
}

#[test]
fn failed_subagent_progress_lists_partial_edits_and_incomplete_verification() {
    let history = vec![
        read_turn("r1", "/src/a.rs"),
        Message::tool_result_with_call_id("r1".to_string(), None, "[hash=old ok]"),
        write_turn("w1", "/src/a.rs"),
        Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
        bash_turn("b1", "cargo test -p cockpit-cli"),
    ];

    let progress = partial_progress_from_history(&history);
    assert_eq!(progress.files_read, vec!["/src/a.rs"]);
    assert_eq!(progress.files_edited[0].path, "/src/a.rs");
    assert_eq!(progress.files_edited[0].hash.as_deref(), Some("abc123"));
    assert_eq!(
        progress.verification_state.as_deref(),
        Some("not_completed")
    );
    assert_eq!(progress.review_state.as_deref(), Some("needs_review"));
    assert_eq!(progress.dirty_owned_changes, vec!["/src/a.rs"]);

    let report = render_failed_subagent_report(
        "Error: noninteractive agent `builder` exceeded 16 turns",
        &progress,
    );
    assert!(report.contains("Partial progress"));
    assert!(report.contains("`/src/a.rs`"));
    assert!(report.contains("Verification did not complete"));
    assert!(report.contains("needs_review"));
    assert!(!report.contains("before starting"));
    assert!(!report.contains("no code changes"));
}

#[test]
fn failed_subagent_before_first_tool_has_no_partial_progress() {
    let history = vec![Message::user("please edit a.rs")];
    let progress = partial_progress_from_history(&history);
    assert!(progress.is_empty());
    assert_eq!(
        render_failed_subagent_report("Error: model request failed", &progress),
        "Error: model request failed"
    );
}

#[test]
fn spawn_gate_clamps_to_ceiling_and_requires_output_dir() {
    // Depth ceiling (GOALS §24): at the ceiling the spawn is refused and
    // the branch does its own work (clamp, don't crash). Below it, the
    // child depth advances by one.
    assert_eq!(spawn_gate(0, 3, "/tmp/out"), Ok(1));
    assert_eq!(spawn_gate(2, 3, "/tmp/out"), Ok(3));
    let refused = spawn_gate(3, 3, "/tmp/out").unwrap_err();
    assert!(refused.contains("depth ceiling 3"), "{refused}");
    assert!(refused.contains("yourself"), "{refused}");
    // A ceiling of 0 refuses even the root's first spawn.
    assert!(spawn_gate(0, 0, "/tmp/out").is_err());
    // Missing `output_dir` is refused with the dedicated-folder nudge.
    let no_dir = spawn_gate(0, 3, "   ").unwrap_err();
    assert!(no_dir.contains("output_dir"), "{no_dir}");
    assert!(no_dir.contains("dedicated"), "{no_dir}");
}

#[tokio::test]
async fn set_swarm_config_threads_caps_to_authority() {
    let (mut driver, _tmp) = test_driver(8);
    driver.set_swarm_config(5, 0);
    assert_eq!(driver.swarm_max_depth, 5);
    assert_eq!(driver.swarm_max_concurrency, 0);
    // The authority received the (unlimited) cap: spawns never queue.
    for _ in 0..12 {
        assert!(
            driver
                .schedule
                .spawn_swarm(crate::engine::schedule::authority::SpawnSpec {
                    worker: crate::engine::schedule::authority::SpawnWorkerKind::Bee,
                    prompt: "s".into(),
                    output_dir: "/tmp/o".into(),
                    model: None,
                    depth: 1,
                    max_depth: 5,
                })
                .contains("scheduled")
        );
    }
    assert_eq!(driver.schedule.queued_swarm(), 0);
}

#[tokio::test]
async fn unbounded_loop_without_config_opt_in_is_rejected() {
    let (mut driver, _tmp) = test_driver(8);
    let err = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 60, "prompt": "poll", "limit": 0 }
        }))
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("allowUnboundedLoops"), "{msg}");
    assert!(!driver.schedule.has_loop());
}

#[tokio::test]
async fn unbounded_loop_headless_is_rejected_even_with_config_opt_in() {
    let (mut driver, _tmp) = test_driver(8);
    driver.set_allow_unbounded_schedule_loops(true);
    let err = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 60, "prompt": "poll", "limit": 0 }
        }))
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("headless"), "{msg}");
    assert!(!driver.schedule.has_loop());
}

#[tokio::test]
async fn primary_round_ceiling_zero_is_disabled() {
    let (driver, _tmp) = test_driver(1);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

    assert!(
        driver
            .primary_round_ceiling_allows_more(99, 0, &tx)
            .await
            .unwrap()
    );
    assert!(rx.try_recv().is_err(), "disabled ceiling emits no notice");
}

#[tokio::test]
async fn primary_round_ceiling_headless_stops_with_notice() {
    let (driver, _tmp) = test_driver(1);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

    assert!(
        !driver
            .primary_round_ceiling_allows_more(3, 3, &tx)
            .await
            .unwrap()
    );
    match rx.recv().await {
        Some(TurnEvent::Notice { text }) => {
            assert!(text.contains("configured limit of 3"), "{text}");
            assert!(text.contains("no interactive client"), "{text}");
        }
        other => panic!("expected notice, got {other:?}"),
    }
}

/// The active-agent name persisted in the session row — what a resume
/// restarts on.
fn persisted_active_agent(driver: &Driver) -> String {
    driver
        .session
        .db
        .get_session(driver.session.id)
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

#[tokio::test]
async fn auto_hands_off_to_build_on_clear_build_intent() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    assert_eq!(driver.active_agent(), "Auto", "starts on the front door");

    let next = driver
        .apply_handoff("Build", "call-1".to_string(), Some("fc-1".to_string()), &tx)
        .await;

    assert_eq!(driver.active_agent(), "Build", "primary swapped to `Build`");
    assert_eq!(driver.stack.len(), 1, "swap stays on the root frame");
    // Persisted so a resume restarts on the handed-off primary.
    assert_eq!(persisted_active_agent(&driver), "Build");
    // The confirmation tool_result is what drives `Build`'s next turn.
    assert!(
        matches!(&next, Message::User { .. }),
        "tool_result delivered"
    );
}

#[tokio::test]
async fn failed_handoff_does_not_persist_target_agent() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .apply_handoff(
            "DefinitelyNotAnAgent",
            "call-1".to_string(),
            Some("fc-1".to_string()),
            &tx,
        )
        .await;

    assert_eq!(driver.active_agent(), "Auto");
    assert_eq!(persisted_active_agent(&driver), "Auto");
}

/// Part 1 (implementation note): the swapped-in
/// primary's first turn is driven by an IMPERATIVE kickoff — the user's
/// originating request restated verbatim + a begin-now instruction — NOT
/// the bare `` "Handed off to `Build`." `` ack a weak model would merely
/// narrate.
#[tokio::test]
async fn handoff_kickoff_restates_user_request_and_commands_action() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    // The originating user request that triggered the handoff.
    let request = "Add a confirm-on-quit toggle to /settings";
    push_user_turn(&mut driver, request);

    let next = driver
        .apply_handoff("Build", "call-1".to_string(), Some("fc-1".to_string()), &tx)
        .await;

    let kickoff = tool_result_text(&next);
    assert!(
        kickoff.contains(request),
        "kickoff restates the user's request verbatim: {kickoff:?}"
    );
    assert!(
        kickoff.to_lowercase().contains("begin now")
            && kickoff.to_lowercase().contains("tool call"),
        "kickoff commands a begin-now tool call, not narration: {kickoff:?}"
    );
    assert!(
        !kickoff.contains("Handed off to"),
        "the bare ack is NOT the model-facing kickoff: {kickoff:?}"
    );
}

/// The kickoff restates the SALIENT (most recent) user turn when several
/// preceded the handoff — not the whole transcript.
#[tokio::test]
async fn handoff_kickoff_restates_only_the_salient_request() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_user_turn(&mut driver, "What does the config loader do?");
    // An intervening agent reply closes that turn so the next user message
    // opens a fresh, salient one.
    driver.stack[0]
        .history
        .push(Message::assistant("It walks up .cockpit/."));
    let salient = "Now rename `loadConfig` to `load_config` everywhere";
    push_user_turn(&mut driver, salient);

    let next = driver
        .apply_handoff("Build", "c".to_string(), Some("fc".to_string()), &tx)
        .await;

    let kickoff = tool_result_text(&next);
    assert!(
        kickoff.contains(salient),
        "salient request restated: {kickoff:?}"
    );
    assert!(
        !kickoff.contains("config loader"),
        "the earlier turn is not dragged in: {kickoff:?}"
    );
}

/// Companion to the above: a clear planning request routes to `Plan`.
#[tokio::test]
async fn auto_hands_off_to_plan_on_clear_plan_intent() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .apply_handoff("Plan", "call-2".to_string(), Some("fc-2".to_string()), &tx)
        .await;

    assert_eq!(driver.active_agent(), "Plan", "primary swapped to `Plan`");
    assert_eq!(persisted_active_agent(&driver), "Plan");
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

/// Regression (implementation note): start as agent A,
/// exchange a turn, swap to agent B via the `swap_command` path, then send
/// a message — the wire history carries exactly ONE swap marker naming
/// A→B, positioned at the swap boundary (immediately ahead of the user's
/// next message, after the prior turns).
#[tokio::test]
async fn swap_command_injects_one_marker_at_boundary_on_next_message() {
    let (mut driver, _t) = test_driver(1); // rooted on `Build`
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    // Exchange ≥1 turn under `Build` (A).
    push_user_turn(&mut driver, "What does the lock manager do?");
    driver.stack[0]
        .history
        .push(Message::assistant("It arbitrates writers."));
    assert_eq!(driver.active_agent(), "Build");

    // Swap to `Swarm` (B) via the slash-command path. No marker yet —
    // injection is deferred to the next message.
    driver.swap_primary("Swarm", &tx).await;
    assert_eq!(driver.active_agent(), "Swarm");
    assert!(
        swap_markers(&driver).is_empty(),
        "marker is deferred, not written at swap time"
    );

    // The user's next message: the marker is injected at send time, at the
    // boundary, then the user message follows.
    driver.inject_pending_swap_marker();
    driver.stack[0].history.push(Message::user("now build it"));

    let markers = swap_markers(&driver);
    assert_eq!(markers.len(), 1, "exactly one marker: {markers:?}");
    assert!(
        markers[0].contains("`Build` → `Swarm`") && markers[0].contains("You are now `Swarm`"),
        "marker names A→B and the new identity: {:?}",
        markers[0]
    );
    // Positioned at the boundary: the marker sits immediately before the
    // new user message and after the prior turns.
    let texts: Vec<String> = driver.stack[0]
        .history
        .iter()
        .map(plain_user_text)
        .collect();
    let marker_idx = texts
        .iter()
        .position(|t| t.starts_with("[Primary agent changed:"))
        .unwrap();
    assert_eq!(
        texts[marker_idx + 1],
        "now build it",
        "marker sits immediately ahead of the next user message"
    );
    // Pending state is consumed — a later message injects no second marker.
    driver.inject_pending_swap_marker();
    assert_eq!(swap_markers(&driver).len(), 1, "fires once per swap window");
}

/// Coalesce (implementation note): several swaps before
/// a message (`Build`→`Swarm`→`Plan`→`Build` … then `Plan`) emit exactly
/// ONE marker naming previously-effective → final. The intermediate hops
/// produce nothing; `from` stays the agent whose turns are in history.
#[tokio::test]
async fn multiple_swaps_before_message_coalesce_to_one_marker() {
    let (mut driver, _t) = test_driver(1); // rooted on `Build`
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_user_turn(&mut driver, "outline the change");
    driver.stack[0]
        .history
        .push(Message::assistant("here is an outline"));

    // Build → Swarm → Plan, all before a message.
    driver.swap_primary("Swarm", &tx).await;
    driver.swap_primary("Build", &tx).await;
    driver.swap_primary("Plan", &tx).await;
    assert_eq!(driver.active_agent(), "Plan");
    assert!(swap_markers(&driver).is_empty(), "no markers until send");

    driver.inject_pending_swap_marker();
    let markers = swap_markers(&driver);
    assert_eq!(markers.len(), 1, "intermediate hops coalesce: {markers:?}");
    assert!(
        markers[0].contains("`Build` → `Plan`"),
        "from = previously-effective (`Build`), to = final (`Plan`): {:?}",
        markers[0]
    );
}

/// Net no-op (implementation note): when the final
/// agent equals the previously-effective one (`Build`→`Swarm`→`Build`
/// while history was already `Build`), nothing is injected — and the
/// pending state is still cleared.
#[tokio::test]
async fn swap_back_to_original_agent_injects_no_marker() {
    let (mut driver, _t) = test_driver(1); // rooted on `Build`
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_user_turn(&mut driver, "think about it");
    driver.stack[0].history.push(Message::assistant("thinking"));

    driver.swap_primary("Swarm", &tx).await;
    driver.swap_primary("Build", &tx).await; // back to the original
    assert_eq!(driver.active_agent(), "Build");

    driver.inject_pending_swap_marker();
    assert!(
        swap_markers(&driver).is_empty(),
        "final == previously-effective → no marker"
    );
    assert!(
        driver.pending_swap_marker_from.is_none(),
        "pending state cleared even on the net no-op"
    );
}

/// The synthetic marker is wire-only (`agent-swap-identity-
/// marker.md`, wire-vs-user split GOALS §14): the swap path emits only the
/// terse `PrimarySwapped` chrome event for the user-facing timeline, never
/// a transcript row for the marker, and the marker is not recorded as a
/// session event. The user sees the switched-to row; the marker stays on
/// the wire.
#[tokio::test]
async fn swap_marker_does_not_leak_into_user_transcript() {
    let (mut driver, _t) = test_driver(1);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    push_user_turn(&mut driver, "do the thing");
    driver.stack[0].history.push(Message::assistant("ok"));

    driver.swap_primary("Swarm", &tx).await;
    driver.inject_pending_swap_marker();

    // The marker is on the wire.
    assert_eq!(swap_markers(&driver).len(), 1);
    // No user-message transcript row was recorded for the marker (the swap
    // records its own `primary_swap` event, but the marker is wire-only).
    let user_msg_rows = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "user_message")
        .count();
    assert_eq!(
        user_msg_rows, 0,
        "the marker is never recorded as a user-message transcript row"
    );
    // The only user-facing chrome signal from the swap is `PrimarySwapped`
    // (the terse switched-to row) — never a transcript entry carrying the
    // marker text.
    drop(tx);
    let mut saw_swapped = false;
    while let Ok(ev) = rx.try_recv() {
        if let TurnEvent::PrimarySwapped { name } = &ev {
            assert_eq!(name, "Swarm");
            saw_swapped = true;
        }
        // No event should ever carry the marker text.
        let dbg = format!("{ev:?}");
        assert!(
            !dbg.contains("[Primary agent changed:"),
            "marker text must not reach the client: {dbg}"
        );
    }
    assert!(saw_swapped, "the terse switched-to chrome event fired");
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
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: "skill".to_string(),
            path: None,
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

#[test]
fn stale_tool_owner_ledgers_drop_calls_absent_from_root_history() {
    let (mut driver, _t) = test_driver(1);
    driver.stack[0]
        .history
        .push(tool_call_turn("live", "editunlock"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "live".to_string(),
            None,
            "[elided body]",
        ));
    driver
        .tool_call_owner
        .insert("live".to_string(), "Build".to_string());
    driver
        .tool_call_owner
        .insert("stale".to_string(), "Build".to_string());

    driver.drop_stale_owner_ledgers();

    assert_eq!(
        driver.tool_call_owner.get("live").map(String::as_str),
        Some("Build"),
        "structural tool calls stay owned even when their result body is elided"
    );
    assert!(
        !driver.tool_call_owner.contains_key("stale"),
        "calls absent from root history are dropped"
    );
}

#[test]
fn stale_skill_pairs_drop_when_call_and_result_leave_root_history() {
    let (mut driver, _t) = test_driver(1);
    driver.stack[0]
        .history
        .push(tool_call_turn("skill-live", "skill"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "skill-live".to_string(),
            None,
            "skill body",
        ));
    driver.skill_pairs.push(SkillPair {
        call_id: "skill-live".to_string(),
        owner: "Auto".to_string(),
        intentional_steer: false,
    });
    driver.skill_pairs.push(SkillPair {
        call_id: "skill-stale".to_string(),
        owner: "Auto".to_string(),
        intentional_steer: false,
    });

    driver.drop_stale_owner_ledgers();

    assert_eq!(driver.skill_pairs.len(), 1);
    assert_eq!(driver.skill_pairs[0].call_id, "skill-live");
}

#[tokio::test]
async fn persisted_skill_pair_strips_after_resume_swap() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");
    driver.stack[0]
        .history
        .push(tool_call_turn("skillslash-resume", "skill"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "skillslash-resume".to_string(),
            None,
            "Skill `x`:\n\nresume-only instructions",
        ));
    driver
        .session
        .db
        .save_skill_pair(driver.session.id, "skillslash-resume", "Build", false)
        .unwrap();

    driver.restore_skill_pairs_after_rehydrate("Build");
    assert_eq!(driver.skill_pairs.len(), 1);
    assert_eq!(driver.skill_pairs[0].owner, "Build");

    driver.swap_primary("Plan", &tx).await;

    assert!(
        !history_text(&driver.stack[0].history).contains("resume-only instructions"),
        "resume-restored abandoned skill body stripped on swap"
    );
    assert!(
        driver
            .session
            .db
            .list_skill_pairs(driver.session.id)
            .unwrap()
            .is_empty(),
        "stripped pair is removed from durable ledger"
    );
}

#[test]
fn skill_pair_reconstructs_from_history_and_tool_log_when_db_empty() {
    let (mut driver, _t) = test_driver(1);
    driver.stack[0]
        .history
        .push(tool_call_turn("skillslash-rebuilt", "skill"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "skillslash-rebuilt".to_string(),
            None,
            "Skill `x`:\n\npre-migration instructions",
        ));
    record_skill_tool_row(
        &driver,
        "skillslash-rebuilt",
        "Build",
        "pre-migration instructions",
    );

    driver.restore_skill_pairs_after_rehydrate("Plan");

    assert_eq!(driver.skill_pairs.len(), 1);
    assert_eq!(driver.skill_pairs[0].call_id, "skillslash-rebuilt");
    assert_eq!(driver.skill_pairs[0].owner, "Build");
    assert!(
        !driver.skill_pairs[0].intentional_steer,
        "fallback reconstruction defaults to non-steering"
    );
    let rows = driver
        .session
        .db
        .list_skill_pairs(driver.session.id)
        .unwrap();
    assert_eq!(rows.len(), 1, "reconstructed row is persisted");
    assert_eq!(rows[0].owner, "Build");
}

#[test]
fn compact_brief_history_excludes_abandoned_skill_bodies() {
    let (mut driver, _t) = test_driver(1);
    driver.stack[0]
        .history
        .push(Message::user("please continue"));
    driver.stack[0]
        .history
        .push(tool_call_turn("skillslash-compact", "skill"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "skillslash-compact".to_string(),
            None,
            "Skill `x`:\n\nCOMPACT_SENTINEL_DO_NOT_SUMMARIZE",
        ));
    driver.skill_pairs.push(SkillPair {
        call_id: "skillslash-compact".to_string(),
        owner: "Build".to_string(),
        intentional_steer: false,
    });

    let filtered = driver.compact_brief_history(&driver.stack[0].history);

    let text = history_text(&filtered);
    assert!(text.contains("please continue"));
    assert!(
        !text.contains("COMPACT_SENTINEL_DO_NOT_SUMMARIZE"),
        "abandoned skill body is omitted from compact brief input"
    );
}

#[test]
fn stale_owner_cleanup_bounds_repeated_removed_calls() {
    let (mut driver, _t) = test_driver(1);
    driver.stack[0]
        .history
        .push(tool_call_turn("still-here", "read"));
    for i in 0..128 {
        driver
            .tool_call_owner
            .insert(format!("gone-{i}"), "Build".to_string());
        driver.skill_pairs.push(SkillPair {
            call_id: format!("skill-gone-{i}"),
            owner: "Auto".to_string(),
            intentional_steer: false,
        });
    }
    driver
        .tool_call_owner
        .insert("still-here".to_string(), "Build".to_string());

    driver.drop_stale_owner_ledgers();

    assert_eq!(driver.tool_call_owner.len(), 1);
    assert!(driver.tool_call_owner.contains_key("still-here"));
    assert!(
        driver.skill_pairs.is_empty(),
        "removed skill calls do not accumulate stale ledger rows"
    );
}

/// Regression (implementation note): agent A
/// (`Build`, has the write tool) calls a write tool and a `read`; swap to
/// agent B (`Plan`, read-only) and send a message — every historical
/// write-tool call carries a wire-only note naming A and the tool, while
/// the `read` call (a tool B still has) is left unannotated.
#[tokio::test]
async fn absent_tool_calls_annotated_naming_the_maker_present_tools_untouched() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");
    assert_eq!(driver.active_agent(), "Build");
    // `Build` is the authority for which tool A actually held.
    assert!(
        driver.stack[0].agent.tools.get("editunlock").is_some(),
        "Build holds the write tool"
    );
    assert!(driver.stack[0].agent.tools.get("read").is_some());

    // A (`Build`) makes a write call and a read call, each answered.
    push_user_turn(&mut driver, "edit the file then read it");
    driver.stack[0]
        .history
        .push(tool_call_turn("w1", "editunlock"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "w1".to_string(),
            None,
            "[hash=abc ok]",
        ));
    driver.stack[0].history.push(tool_call_turn("r1", "read"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "r1".to_string(),
            None,
            "file contents",
        ));

    // Swap to `Plan` (read-only — lacks `editunlock`). No annotation yet —
    // deferred to the next message.
    driver.swap_primary("Plan", &tx).await;
    assert_eq!(driver.active_agent(), "Plan");
    assert!(
        driver.stack[0].agent.tools.get("editunlock").is_none(),
        "Plan lacks the write tool"
    );
    assert!(
        !tool_result_text_for(&driver, "w1").contains("[Called by"),
        "annotation is deferred, not written at swap time"
    );

    // The user's next message: annotation fires at send time.
    driver.annotate_absent_tool_calls();

    // The write call carries the attribution note naming A (`Build`) and T.
    let w = tool_result_text_for(&driver, "w1");
    assert!(
        w.contains("[Called by `Build`, which had the `editunlock` tool. You (`Plan`) do not have this tool.]"),
        "absent-tool call annotated with maker + tool + new identity: {w:?}"
    );
    assert!(
        w.contains("[hash=abc ok]"),
        "the original tool output is preserved after the note: {w:?}"
    );
    // The `read` call (a tool `Plan` still has) is untouched.
    let r = tool_result_text_for(&driver, "r1");
    assert!(
        !r.contains("[Called by"),
        "a call for a tool the new agent still has is not annotated: {r:?}"
    );
    assert_eq!(r, "file contents");

    // Idempotent: a later message never double-stamps.
    driver.annotate_absent_tool_calls();
    let w2 = tool_result_text_for(&driver, "w1");
    assert_eq!(w2, w, "re-evaluation does not double-annotate");
}

/// Per-call ownership across several swaps
/// (implementation note): a write call made under
/// `Build`, then a swap to `Swarm` (also write-capable) that makes its own
/// write call, then a swap to `Plan` (read-only). On the next message each
/// write call is attributed to the agent that ACTUALLY made it — "the
/// previous agent" is not enough.
#[tokio::test]
async fn annotation_attributes_each_call_to_its_actual_maker() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");

    // A (`Build`) makes a write call.
    driver.stack[0]
        .history
        .push(tool_call_turn("b1", "editunlock"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "b1".to_string(),
            None,
            "build-write",
        ));

    // Swap to `Swarm` (still write-capable) which makes its own write call.
    driver.swap_primary("Swarm", &tx).await;
    driver.stack[0]
        .history
        .push(tool_call_turn("s1", "writeunlock"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "s1".to_string(),
            None,
            "swarm-write",
        ));

    // Swap to `Plan` (read-only) and annotate at the next message.
    driver.swap_primary("Plan", &tx).await;
    driver.annotate_absent_tool_calls();

    let b = tool_result_text_for(&driver, "b1");
    assert!(
        b.contains("[Called by `Build`, which had the `editunlock` tool."),
        "the first write call is attributed to `Build`: {b:?}"
    );
    let s = tool_result_text_for(&driver, "s1");
    assert!(
        s.contains("[Called by `Swarm`, which had the `writeunlock` tool."),
        "the second write call is attributed to `Swarm`, not `Build`: {s:?}"
    );
}

#[tokio::test]
async fn primary_swap_transfers_locks_between_write_capable_agents() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");
    let path = driver.cwd.join("swap-transfer.txt");
    std::fs::write(&path, "seed").unwrap();
    driver
        .locks
        .acquire(&path, "Build", driver.session.id)
        .unwrap();

    driver.swap_primary("Swarm", &tx).await;

    assert_eq!(driver.active_agent(), "Swarm");
    assert_eq!(
        driver.locks.holder(&path).map(|(_, a)| a).as_deref(),
        Some("Swarm")
    );
    driver
        .locks
        .check_write_permitted(&path, "Swarm", driver.session.id)
        .unwrap();
    assert!(!driver.locks.has_read(&path, "Build", driver.session.id));
}

#[tokio::test]
async fn primary_swap_releases_locks_when_incoming_is_read_only() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");
    let path = driver.cwd.join("swap-release.txt");
    std::fs::write(&path, "seed").unwrap();
    driver
        .locks
        .acquire(&path, "Build", driver.session.id)
        .unwrap();

    driver.swap_primary("Plan", &tx).await;

    assert_eq!(driver.active_agent(), "Plan");
    assert!(driver.locks.holder(&path).is_none());
}

/// A swapped-in read-only agent (`Plan`) does not re-issue a write tool
/// whose past calls are now annotated
/// (implementation note). The behavioral
/// guarantee is the annotation: the write call's outcome now reads as
/// "another agent made this; you lack this tool", and `Plan`'s own surface
/// holds no write tool, so a re-issue is impossible.
#[tokio::test]
async fn read_only_agent_cannot_reissue_annotated_write_tool() {
    let (mut driver, _t) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    reroot_real(&mut driver, "Build");
    driver.stack[0]
        .history
        .push(tool_call_turn("w1", "writeunlock"));
    driver.stack[0]
        .history
        .push(Message::tool_result_with_call_id(
            "w1".to_string(),
            None,
            "[hash=def ok]",
        ));

    driver.swap_primary("Plan", &tx).await;
    driver.annotate_absent_tool_calls();

    // Annotation present (the guarantee).
    assert!(tool_result_text_for(&driver, "w1").contains("You (`Plan`) do not have this tool."));
    // And `Plan`'s surface genuinely holds no write tool to re-issue.
    assert!(driver.stack[0].agent.tools.get("writeunlock").is_none());
    assert!(driver.stack[0].agent.tools.get("editunlock").is_none());
}

/// Part 2 (implementation note, the `myj42m`
/// shape): an abandoned skill pair injected under the outgoing primary
/// must not remain as authoritative instructions for the new primary after
/// a swap. After `Auto` seeds a user-invoked skill and then hands off, the
/// skill's call + result are stripped from the root history (both halves,
/// together) so `Build` follows its own role.
#[tokio::test]
async fn abandoned_skill_pair_is_stripped_on_handoff_swap() {
    use crate::engine::message::AssistantContent;
    use rig::message::UserContent;

    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    // The user invoked a skill then described a change. The skill
    // name need not exist on disk — the seam still folds a real pair into
    // history and records ownership (the leak we're closing).
    driver
        .seed_forced_skill("definitely-not-a-real-skill-xyz", &tx)
        .await;
    push_user_turn(&mut driver, "Add a confirm-on-quit toggle to /settings");

    // The pair is present and owned by the outgoing primary (`Auto`).
    let skill_call_present = |d: &Driver| {
        d.stack[0].history.iter().any(|m| {
            matches!(m,
            Message::Assistant { content, .. }
                if content.iter().any(|c| matches!(c,
                    AssistantContent::ToolCall(tc) if tc.function.name == "skill")))
        })
    };
    let skill_result_present = |d: &Driver| {
        d.stack[0].history.iter().any(|m| {
            matches!(m,
            Message::User { content }
                if content.iter().any(|c| matches!(c,
                    UserContent::ToolResult(tr) if tr.id.starts_with("skillslash-"))))
        })
    };
    assert!(
        skill_call_present(&driver),
        "skill call folded in before swap"
    );
    assert!(
        skill_result_present(&driver),
        "skill result folded in before swap"
    );
    assert_eq!(driver.skill_pairs.len(), 1, "ownership recorded");

    // Hand off to `Build`. The abandoned skill pair must be gone.
    driver
        .apply_handoff("Build", "call-1".to_string(), Some("fc-1".to_string()), &tx)
        .await;

    assert!(
        !skill_call_present(&driver),
        "abandoned skill call stripped on swap (does not govern `Build`)"
    );
    assert!(
        !skill_result_present(&driver),
        "abandoned skill result stripped on swap (no orphaned tool_result)"
    );
    assert!(
        driver.skill_pairs.is_empty(),
        "stripped pair dropped from the ledger"
    );
    // The kickoff still restated the user's own request (not the skill).
    // History stays well-formed: every tool_result has its call.
    assert_eq!(driver.active_agent(), "Build");
}

/// A steering pair (the future "intentional steer" opt-out) survives the
/// swap — the mechanism scopes narrowly to *abandoned* pairs and does not
/// hard-code "drop all skills on swap." (No production path sets the flag
/// today; this guards the seam.)
#[tokio::test]
async fn intentional_steer_skill_pair_survives_swap() {
    let (mut driver, _t) = auto_rooted_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    driver
        .seed_forced_skill("definitely-not-a-real-skill-xyz", &tx)
        .await;
    // Flip the recorded pair to steering, as a future intentional-steer
    // path would.
    driver.skill_pairs[0].intentional_steer = true;
    let before = driver.stack[0].history.len();

    driver
        .apply_handoff("Build", "c".to_string(), Some("fc".to_string()), &tx)
        .await;

    assert_eq!(
        driver.stack[0].history.len(),
        before,
        "a steering pair is retained across the swap"
    );
    assert_eq!(driver.skill_pairs.len(), 1, "steering ownership entry kept");
}

/// Part 3 (implementation note): the
/// `task`→subagent kickoff always carries an actionable brief and the
/// child begins its loop on the first turn. The brief is the caller's
/// (repair-required, non-empty) `task` prompt, delivered verbatim as the
/// child's first `Message::user`. This guards that the delegation path
/// never stalls on a non-actionable first turn.
#[test]
fn delegated_subagent_first_turn_is_the_actionable_brief() {
    // The interactive spawn path delivers `Message::user(scrub(&brief))`;
    // the noninteractive path delivers `compose_subagent_brief(&brief,&why)`.
    // Both carry the caller's brief verbatim — never an empty / passive
    // first turn. We assert the brief composition is faithful (the seam the
    // live loop uses), since the `task` prompt is required by the repair
    // layer and thus always non-empty.
    let brief = "Rename `loadConfig` to `load_config` in src/config/ and update callers.";
    // No `why`: the brief is delivered unchanged (actionable as written).
    assert_eq!(compose_subagent_brief(brief, ""), brief);
    // With a `why`: the brief is still present in full, prefixed with
    // motivation — the child still receives the actionable instruction.
    let with_why = compose_subagent_brief(brief, "the API changed");
    assert!(
        with_why.contains(brief),
        "brief carried verbatim: {with_why}"
    );
    assert!(with_why.contains("the API changed"), "motivation prefixed");
}

#[tokio::test]
async fn ambiguous_turn_keeps_auto_active() {
    let (driver, _t) = auto_rooted_driver();
    // No `apply_handoff` call (the model emitted no `handoff` tool call).
    assert_eq!(
        driver.active_agent(),
        "Auto",
        "ambiguous intent keeps the front door — no unsolicited swap"
    );
    assert_eq!(persisted_active_agent(&driver), "Auto");
}

/// Resume rehydration is automatic but applies ONLY when the root frame
/// has no live in-memory history. A driver whose root already has a live
/// context is left untouched — never rebuild over a live context
/// (implementation note).
#[test]
fn rehydrate_skips_a_live_history() {
    let (mut driver, _t) = test_driver(1);
    // Record a couple of turns to the DB transcript.
    let session = driver.session.clone();
    session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &serde_json::json!({ "text": "hi" }),
        )
        .unwrap();
    session
        .record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some("infer-1"),
            &serde_json::json!({ "text": "hello" }),
        )
        .unwrap();
    // Simulate a LIVE worker: the root frame already has in-memory
    // history. Rehydration must be a no-op.
    driver.stack[0].history = vec![Message::user("a live message")];
    let r = driver.rehydrate_root_if_empty("Build").unwrap();
    assert!(r.is_none(), "must not rebuild over a live context");
    assert_eq!(driver.stack[0].history.len(), 1, "live history untouched");
}

/// Persist-every-boundary + automatic rehydration: a transcript and a
/// prune ledger persisted to the DB (as the running driver would at each
/// inference boundary, surviving an UNCLEAN kill — no graceful exit
/// step) are rehydrated by a brand-new driver into the PRUNED form, with
/// the watermark restored and the context estimate seeded.
#[test]
fn fresh_driver_rehydrates_persisted_pruned_context() {
    use rig::OneOrMany;
    use rig::message::{AssistantContent, ToolResultContent, UserContent};

    let (driver, _t) = test_driver(1);
    let session = driver.session.clone();
    let db = session.db.clone();
    let sid = session.id;

    // Two identical reads → the older is prunable. Record the transcript
    // exactly as the engine does (events + tool_call rows).
    let rec_user = |text: &str| {
        session
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &serde_json::json!({ "text": text }),
            )
            .unwrap();
    };
    let rec_tool = |call_id: &str, body: &str| {
        session
            .record_tool_call(crate::session::ToolCallRow {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                agent: "Build".into(),
                call_id: call_id.into(),
                identity: crate::session::ToolCallProviderIdentity::default(),
                tool: "read".into(),
                path: Some("/f".into()),
                original_input_json: serde_json::json!({ "path": "/f" }),
                wire_input_json: serde_json::json!({ "path": "/f" }),
                recovery: crate::db::tool_calls::Recovery::Clean,
                hard_fail: false,
                exit_code: None,
                sandbox_enabled: false,
                sandboxed: false,
                sandbox_unavailable_reason: None,
                output: body.into(),
                truncated: false,
                duration_ms: 1,
                llm_mode: crate::config::extended::LlmMode::default(),
                shape_fingerprint: None,
                hint: None,
            })
            .unwrap();
        session
            .record_event(
                crate::db::session_log::SessionEventKind::ToolCall,
                Some("Build"),
                Some(call_id),
                &serde_json::json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": body }),
            )
            .unwrap();
    };
    rec_user("read it twice");
    session
        .record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some("infer-1"),
            &serde_json::json!({ "text": "" }),
        )
        .unwrap();
    rec_tool("tc-1", "BODY ONE padding padding padding");
    session
        .record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some("infer-2"),
            &serde_json::json!({ "text": "" }),
        )
        .unwrap();
    rec_tool("tc-2", "BODY TWO padding padding padding");

    // Persist the prune ledger as the boundary cadence would — the older
    // read (tc-1) elided.
    let ledger = prune::PruneLedger {
        elided: vec![prune::LedgerEntry {
            original_event_id: "tc-1".into(),
            reason: prune::REASON_SNAPSHOT_SUPERSEDED.into(),
            partial_body: None,
        }],
        watermark: 5,
    };
    db.save_prune_ledger(sid, &ledger).unwrap();
    drop(driver); // the daemon "died" — in-memory history is gone.

    // A brand-new driver for the SAME session (a fresh worker after an
    // unclean restart) rehydrates automatically.
    let s2 = Arc::new(Session::resume(db.clone(), sid).unwrap().unwrap());
    let locks = Arc::new(crate::locks::LockManager::from_db(db.clone()).unwrap());
    let rcfg = crate::config::extended::RedactConfig::default();
    let redact = Arc::new(RedactionTable::build(&rcfg, &s2.project_root).unwrap());
    let agent = Arc::new(Agent {
        name: "Build".into(),
        system: String::new(),
        role_prompt: String::new(),
        tools: crate::engine::tool::ToolBox::new(),
        model: Arc::new(
            crate::engine::model::Model::from_config(
                &{
                    use crate::config::providers::{
                        ActiveModelRef, ProviderEntry, ProvidersConfig,
                    };
                    let mut providers = std::collections::BTreeMap::new();
                    providers.insert(
                        "lmstudio".to_string(),
                        ProviderEntry {
                            url: "http://localhost:1/v1".into(),
                            ..ProviderEntry::default()
                        },
                    );
                    ProvidersConfig {
                        providers,
                        active_model: Some(ActiveModelRef {
                            provider: "lmstudio".into(),
                            model: "local".into(),
                            reasoning_effort: None,
                            thinking_mode: None,
                        }),
                        ..ProvidersConfig::default()
                    }
                },
                std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            )
            .unwrap(),
        ),
        params: crate::engine::model::ModelParams::default(),
        scan_tool_results: true,
        llm_mode: crate::config::extended::LlmMode::default(),
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
    });
    let mut driver2 =
        Driver::with_max_schedules(s2.clone(), locks, redact, s2.project_root.clone(), agent, 1);
    let r = driver2
        .rehydrate_root_if_empty("Build")
        .unwrap()
        .expect("a prior conversation was rebuilt");
    assert!(!r.ledger_fallback);
    // The pruned form is restored: tc-1's body is the elision marker.
    let body = |m: &Message| match m {
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
    };
    let h = &driver2.stack[0].history;
    // h: user, assistant(tc-1), result tc-1 (elided), assistant(tc-2), result tc-2.
    assert!(prune::Elision::is_marker(&body(&h[2])), "tc-1 body elided");
    assert_eq!(body(&h[4]), "BODY TWO padding padding padding");
    // Watermark restored so auto-prune's short-circuit stays consistent.
    assert_eq!(driver2.prune_watermark.get(&1).copied(), Some(5));
    // Context estimate seeded for the gauge (non-zero pruned history).
    assert!(s2.last_usage().is_some());
    // The assistant turn that issued tc-1 is unchanged (call shape kept).
    assert!(matches!(&h[1], Message::Assistant { content, .. }
        if content.iter().any(|c| matches!(c, AssistantContent::ToolCall(tc) if tc.id == "tc-1"))));
    let _ = OneOrMany::one(UserContent::text("")); // keep import used
}

#[test]
fn new_constructs_idle_driver() {
    // `Driver::new` is the public default-cap constructor; exercise it
    // so the default path stays alive + correct.
    let (driver, _t) = test_driver(crate::engine::schedule::DEFAULT_MAX_CONCURRENT_SCHEDULES);
    let agent = driver.stack[0].agent.clone();
    let d2 = Driver::new(
        driver.session.clone(),
        driver.locks.clone(),
        driver.redact.clone(),
        driver.cwd.clone(),
        agent,
    );
    assert_eq!(d2.active_agent(), "Build");
    assert!(!d2.schedule.has_loop());
    assert_eq!(
        d2.schedule.max_concurrent,
        crate::engine::schedule::DEFAULT_MAX_CONCURRENT_SCHEDULES
    );
}

#[test]
fn live_skill_inventory_publishes_exact_dynamic_toolbox() {
    let (driver, _tmp) = test_driver_without_network(1);
    let mut agent = (*driver.stack[0].agent).clone();
    agent.llm_mode = crate::config::extended::LlmMode::Normal;
    agent.tools = crate::engine::tool::ToolBox::new()
        .with(Arc::new(crate::tools::read::ReadTool))
        .with(Arc::new(crate::tools::web::WebSearchTool));
    let session = driver.session.clone();

    let _driver = Driver::new(
        session.clone(),
        driver.locks.clone(),
        driver.redact.clone(),
        driver.cwd.clone(),
        Arc::new(agent),
    );
    let names = session.active_tool_names();
    assert!(names.iter().any(|name| name == "read"));
    assert!(names.iter().any(|name| name == "websearch"));

    session.set_sandbox_escalation_enabled(false);
    assert!(
        !session
            .active_tool_names()
            .iter()
            .any(|name| name == "escalate")
    );
    session.set_sandbox_escalation_enabled(true);
    assert!(
        session
            .active_tool_names()
            .iter()
            .any(|name| name == "escalate")
    );
    session.set_sandbox_escalation_enabled(false);
    assert!(
        !session
            .active_tool_names()
            .iter()
            .any(|name| name == "escalate")
    );
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

#[test]
fn interactive_child_load_failure_returns_tool_error_without_pushing_child() {
    let (driver, tmp) = test_driver(8);
    let cockpit = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    std::fs::write(
        cockpit.join("config.json"),
        r#"{"tools":{"read":{"enabled":true,"command":"echo hi"}}}"#,
    )
    .unwrap();

    let message = match driver.load_interactive_child_or_tool_error(InteractiveChildLoadRequest {
        child_agent: "builder",
        granted_tools: Vec::new(),
        model: None,
        child_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        task_call_id: "task-load-fail",
        task_function_call_id: Some("fn-load-fail".to_string()),
        repair_notes: &[],
    }) {
        Ok(_) => panic!("invalid child config must return a tool error"),
        Err(message) => message,
    };

    assert_eq!(driver.stack.len(), 1, "parent session must remain alive");
    let (result_id, result_text) =
        tool_result_text_and_id(&message).expect("load failure returns tool_result");
    assert_eq!(result_id, "task-load-fail");
    assert!(
        result_text.contains("failed to load subagent `builder`"),
        "{result_text}"
    );
    assert!(result_text.contains("custom tool `read`"), "{result_text}");
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

#[tokio::test]
async fn unwind_stack_to_root_cancel_delivers_abort_result() {
    assert_unwind_reason(StackUnwindReason::Cancelled, "cancelled by user").await;
}

#[tokio::test]
async fn unwind_stack_to_root_gate_delivers_abort_result() {
    assert_unwind_reason(StackUnwindReason::Gated, "daemon draining").await;
}

#[tokio::test]
async fn unwind_stack_to_root_inference_failure_delivers_diagnostics() {
    assert_unwind_reason(
        StackUnwindReason::InferenceFailed {
            provider: "lmstudio".into(),
            model: "local".into(),
            class: "timeout_ttft".into(),
            phase: "ttft".into(),
        },
        "provider=lmstudio, model=local, class=timeout_ttft, phase=ttft",
    )
    .await;
}

#[tokio::test]
async fn root_only_unwind_emits_no_report() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .unwind_stack_to_root(StackUnwindReason::Cancelled, &tx)
        .await;

    assert_eq!(driver.stack.len(), 1);
    assert!(driver.stack[0].history.is_empty());
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn all_unwind_paths_drain_pending_input() {
    for reason in [
        StackUnwindReason::Cancelled,
        StackUnwindReason::Gated,
        StackUnwindReason::InferenceFailed {
            provider: "lmstudio".into(),
            model: "local".into(),
            class: "network".into(),
            phase: "dispatch".into(),
        },
    ] {
        let (mut driver, _tmp) = test_driver(8);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
        let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
        let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
        let target = driver.active_queue_target();
        for text in ["first", "second"] {
            queue
                .push(
                    UserSubmission {
                        kind: UserSubmissionKind::User,
                        text: text.to_string(),
                        display_text: None,
                        tag_expansions: Vec::new(),
                        images: vec![],
                        forced_skill: None,
                        origin_principal: None,
                        job_id: None,
                        preflight_cleaned: None,
                        queue_item_ids: Vec::new(),
                        queue_target: None,
                    },
                    target.clone(),
                )
                .await;
        }

        assert_eq!(
            driver
                .unwind_stack_to_root_and_discard_pending_input(reason, &queue, &tx)
                .await,
            2
        );
        let mut drained = Vec::new();
        queue
            .drain_into_for(&mut drained, MAX_FOLD, Some(&target.id))
            .await;
        assert!(drained.is_empty());
    }
}

#[tokio::test]
async fn queued_user_fold_records_and_emits_stable_ids() {
    let (driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let target = driver.active_queue_target();
    let (first_id, _) = queue
        .push(UserSubmission::text("first queued"), target.clone())
        .await;
    let (second_id, _) = queue
        .push(UserSubmission::text("second queued"), target.clone())
        .await;

    let mut drained = Vec::new();
    queue
        .drain_into_for(&mut drained, MAX_FOLD, Some(&target.id))
        .await;
    assert_eq!(drained.len(), 2);
    let first_seq = driver
        .record_queued_user_fold(&drained[0], &tx)
        .await
        .expect("first queued message should persist");
    let second_seq = driver
        .record_queued_user_fold(&drained[1], &tx)
        .await
        .expect("second queued message should persist");

    for (expected_text, expected_id, expected_seq) in [
        ("first queued", first_id, first_seq),
        ("second queued", second_id, second_seq),
    ] {
        let event = rx.try_recv().expect("queued turn event");
        match event {
            TurnEvent::QueuedUserMessagesFolded {
                text,
                queue_item_ids,
                target: event_target,
                seq: event_seq,
                preflight_cleaned,
                ..
            } => {
                assert_eq!(text, expected_text);
                assert_eq!(queue_item_ids, vec![expected_id]);
                assert_eq!(event_target.id, target.id);
                assert_eq!(event_seq, Some(expected_seq));
                assert!(preflight_cleaned.is_none());
            }
            other => panic!("expected queued turn event, got {other:?}"),
        }
    }

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    for (expected_text, expected_id, expected_seq) in [
        ("first queued", first_id, first_seq),
        ("second queued", second_id, second_seq),
    ] {
        let recorded = events
            .iter()
            .find(|event| event.seq == expected_seq)
            .expect("queued user_message event");
        assert_eq!(recorded.kind, "user_message");
        assert_eq!(recorded.data["text"], expected_text);
        assert_eq!(recorded.data["queued"], true);
        assert_eq!(recorded.data["queue_item_ids"][0], expected_id.to_string());
        assert_eq!(recorded.data["queue_target"]["id"], target.id);
    }
}

/// `/prune` (and auto-prune) target the **foreground** agent only —
/// the top of the interactive-agent stack. A suspended parent frame's
/// history is never touched (GOALS §3b scope).
#[tokio::test]
async fn prune_targets_foreground_subagent_only() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    // Parent (root) frame carries elidable duplicate reads.
    driver.stack[0].history = dup_read_history_big();

    // Push an interactive subagent frame with its OWN duplicate reads.
    let child = driver.stack[0].agent.clone();
    driver.stack.push(AgentSession {
        queue_target: crate::engine::message::QueueTarget::child(
            child.name.clone(),
            driver.stack.len(),
            "test",
            "default",
        ),
        agent: child,
        history: dup_read_history(),
        answering: None,
        deferred_log: crate::engine::deferred::DeferredLog::new(),
    });

    // Prune the foreground (the subagent on top).
    driver.do_prune(false, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}

    // Foreground (top) was pruned: older body became a marker.
    let top = driver.stack.last().unwrap();
    let plan_top = prune::dedup_plan(&top.history);
    assert!(plan_top.is_empty(), "foreground should be fully pruned");

    // Parent (suspended) is untouched: still has an elidable dup.
    let parent = &driver.stack[0];
    let plan_parent = prune::dedup_plan(&parent.history);
    assert!(
        !plan_parent.is_empty(),
        "suspended parent frame must NOT be pruned"
    );
}

/// The watermark short-circuits auto-prune: after a prune, with no
/// history growth, `maybe_auto_prune` is a no-op even when cold.
#[tokio::test]
async fn auto_prune_watermark_short_circuits() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.stack[0].history = dup_read_history_big();

    // Cache is cold (no send yet) and there's something prunable →
    // first auto-prune fires.
    assert!(driver.maybe_auto_prune(&tx).await, "first auto-prune fires");
    // History length unchanged since → watermark short-circuits.
    assert!(
        !driver.maybe_auto_prune(&tx).await,
        "watermark short-circuits with no growth"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

/// The auto-prune master switch: `auto_prune: off` on the provider
/// suppresses the automatic prune entirely — even with a cold/no-cache
/// provider and a material prunable plan, which would otherwise always
/// fire. Flipping it back on lets the same state prune.
#[tokio::test]
async fn auto_prune_master_switch_off_suppresses_auto_prune() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        100_000,
    );
    driver
        .test_providers_override
        .as_mut()
        .unwrap()
        .0
        .providers
        .get_mut("lmstudio")
        .unwrap()
        .auto_prune = Some(false);
    driver.stack[0].history = dup_read_history_big();
    let plan = prune::dedup_plan(&driver.stack[0].history);
    assert!(!plan.is_empty(), "test requires a prunable plan");
    let history_len = driver.stack[0].history.len();

    assert!(
        !driver.maybe_auto_prune(&tx).await,
        "auto-prune off must suppress the automatic prune"
    );
    assert!(rx.try_recv().is_err(), "no Pruned event is emitted");
    // The master-switch-off branch advances the watermark like the sibling
    // no-op branches, so the next boundary short-circuits the config load.
    assert_eq!(
        driver.prune_watermark.get(&1).copied(),
        Some(history_len),
        "switch-off must advance the watermark to history_len"
    );

    driver
        .test_providers_override
        .as_mut()
        .unwrap()
        .0
        .providers
        .get_mut("lmstudio")
        .unwrap()
        .auto_prune = Some(true);
    // Flipping back on with no growth stays short-circuited by the
    // watermark — matching sibling-branch semantics.
    assert!(
        !driver.maybe_auto_prune(&tx).await,
        "auto-prune on with no history growth stays watermark-short-circuited"
    );
    // Growing history past the watermark re-evaluates and fires.
    driver.stack[0].history.extend(dup_read_history_big());
    assert!(
        driver.maybe_auto_prune(&tx).await,
        "auto-prune on fires once history grows past the watermark"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn auto_prune_skips_zero_savings_plan_without_pruned_event() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(
        &mut driver,
        CacheMode::Ephemeral,
        ContextConfig::default(),
        100_000,
    );
    driver.stack[0].history = dup_read_history_zero_savings();
    let plan = prune::dedup_plan(&driver.stack[0].history);
    assert!(!plan.is_empty(), "test requires a non-empty plan");
    assert_eq!(plan.tokens_saved(), 0, "test requires zero savings");
    let history_len = driver.stack[0].history.len();

    assert!(!driver.maybe_auto_prune(&tx).await);
    assert_eq!(driver.prune_watermark.get(&1).copied(), Some(history_len));
    assert!(rx.try_recv().is_err(), "no visible Pruned event is emitted");

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    assert!(
        events.iter().all(|ev| ev.kind != "context_pruned"),
        "zero-savings auto-prune must not write context_pruned"
    );
    let diagnostic = events
        .iter()
        .find(|ev| ev.kind == "auto_prune_diagnostic")
        .expect("skip diagnostic is exported");
    assert_eq!(diagnostic.data["skip_reason"], "zero_savings");
    assert_eq!(diagnostic.data["trigger_reason"], "cache_already_cold");
    assert_eq!(diagnostic.data["tokens_saved"], serde_json::json!(0));
    assert_eq!(
        diagnostic.data["watermark_advanced"],
        serde_json::json!(true)
    );
}

#[tokio::test]
async fn auto_prune_skips_trivial_cache_cold_plan_with_diagnostic() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(
        &mut driver,
        CacheMode::Ephemeral,
        ContextConfig::default(),
        100_000,
    );
    driver.stack[0].history = dup_read_history_tiny_savings();
    let plan = prune::dedup_plan(&driver.stack[0].history);
    let projected = plan.tokens_saved();
    assert!(
        projected > 0 && projected < AUTO_PRUNE_MIN_COLD_SAVINGS_TOKENS,
        "test requires a tiny nonzero saving, got {projected}"
    );

    assert!(!driver.maybe_auto_prune(&tx).await);
    assert!(rx.try_recv().is_err(), "no visible Pruned event is emitted");

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    assert!(
        events.iter().all(|ev| ev.kind != "context_pruned"),
        "trivial cold-cache auto-prune must not write context_pruned"
    );
    let diagnostic = events
        .iter()
        .find(|ev| ev.kind == "auto_prune_diagnostic")
        .expect("skip diagnostic is exported");
    assert_eq!(diagnostic.data["skip_reason"], "below_min_cold_savings");
    assert_eq!(diagnostic.data["trigger_reason"], "cache_already_cold");
    assert_eq!(
        diagnostic.data["min_cold_savings_tokens"],
        serde_json::json!(AUTO_PRUNE_MIN_COLD_SAVINGS_TOKENS)
    );
    assert_eq!(
        diagnostic.data["tokens_saved"],
        serde_json::json!(projected)
    );
}

#[tokio::test]
async fn auto_prune_material_cache_cold_plan_records_trigger_reason() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(
        &mut driver,
        CacheMode::Ephemeral,
        ContextConfig::default(),
        100_000,
    );
    driver.stack[0].history = dup_read_history_big();
    let projected = prune::dedup_plan(&driver.stack[0].history).tokens_saved();
    assert!(projected >= AUTO_PRUNE_MIN_COLD_SAVINGS_TOKENS);

    assert!(driver.maybe_auto_prune(&tx).await);
    let mut saw_pruned = false;
    drop(tx);
    while let Some(ev) = rx.recv().await {
        if let TurnEvent::Pruned {
            cache_break,
            trigger_reason,
            tokens_saved,
            ..
        } = ev
        {
            saw_pruned = true;
            assert!(!cache_break);
            assert_eq!(trigger_reason.as_deref(), Some("cache_already_cold"));
            assert_eq!(tokens_saved, projected as u64);
        }
    }
    assert!(saw_pruned, "material cache-cold auto-prune emits Pruned");

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    let pruned = events
        .iter()
        .find(|ev| ev.kind == "context_pruned")
        .expect("applied auto-prune is exported");
    assert_eq!(pruned.data["trigger"], "auto");
    assert_eq!(pruned.data["trigger_reason"], "cache_already_cold");
    assert_eq!(
        pruned.data["tokens_saved"],
        serde_json::json!(projected as u64)
    );
}

#[tokio::test]
async fn prune_watermark_cleared_for_popped_child_depth() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.prune_watermark.insert(1, 99);
    push_test_child(&mut driver, dup_read_history_big());

    assert!(
        driver.maybe_auto_prune(&tx).await,
        "child auto-prune establishes depth-2 watermark"
    );
    assert!(driver.prune_watermark.get(&2).is_some());

    let _ = driver.pop_child_with_envelope(None, &tx).await;

    assert_eq!(
        driver.prune_watermark.get(&1).copied(),
        Some(99),
        "root watermark must not be cleared when the child pops"
    );
    assert!(
        driver.prune_watermark.get(&2).is_none(),
        "popped child depth watermark must be cleared"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn stale_child_watermark_does_not_suppress_sibling_auto_prune() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    push_test_child(&mut driver, dup_read_history_big());

    assert!(driver.maybe_auto_prune(&tx).await, "child A prunes");
    let stale_len = driver
        .prune_watermark
        .get(&2)
        .copied()
        .expect("child A depth-2 watermark");
    let _ = driver.pop_child_with_envelope(None, &tx).await;

    let sibling_history = dup_read_history_big();
    assert_eq!(
        sibling_history.len(),
        stale_len,
        "regression setup requires sibling history length to match stale watermark"
    );
    push_test_child(&mut driver, sibling_history);

    assert!(
        driver.maybe_auto_prune(&tx).await,
        "fresh sibling must evaluate and prune instead of matching stale depth watermark"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

/// Nothing prunable → auto-prune is a no-op and emits no Pruned event.
#[tokio::test]
async fn auto_prune_noop_when_nothing_prunable() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    // Empty foreground history: nothing to prune.
    assert!(!driver.maybe_auto_prune(&tx).await);
}

/// `context_metrics` (the ctx%/prunable% figure the auto-compact +
/// ctx%-threshold auto-prune triggers consume): computed from the last
/// request's prompt size against the model's context window, inert when
/// the window is unknown or no usage has been reported
/// (implementation note).
#[test]
fn context_metrics_compute_and_inert_cases() {
    // 60k of a 100k window → 60% ctx; 30k prunable → 30% prunable.
    let m = context_metrics(Some(100_000), Some(60_000), 30_000).unwrap();
    assert!((m.ctx_pct - 60.0).abs() < 1e-9);
    assert!((m.prunable_pct - 30.0).abs() < 1e-9);

    // No context_length known → None (ctx%-gated triggers inert): the
    // exact edge case the spec requires the ctx% paths to skip.
    assert!(context_metrics(None, Some(60_000), 30_000).is_none());
    // A zero/garbage window is treated as unknown.
    assert!(context_metrics(Some(0), Some(60_000), 30_000).is_none());
    // No usage reported yet → None (no last send).
    assert!(context_metrics(Some(100_000), None, 30_000).is_none());

    // Threshold composition mirrors `maybe_auto_prune`: above the prune
    // ctx% (50) AND above prunable% (30) fires.
    let warm = context_metrics(Some(100_000), Some(55_000), 31_000).unwrap();
    assert!(warm.ctx_pct > 50.0 && warm.prunable_pct > 30.0);
    // Below either gate → no threshold fire.
    let low_prunable = context_metrics(Some(100_000), Some(55_000), 10_000).unwrap();
    assert!(!(low_prunable.ctx_pct > 50.0 && low_prunable.prunable_pct > 30.0));

    // The auto-compact line (60%): at/above fires, below doesn't.
    let hot = context_metrics(Some(100_000), Some(65_000), 0).unwrap();
    assert!(hot.ctx_pct >= 60.0);
    let mid = context_metrics(Some(100_000), Some(55_000), 0).unwrap();
    assert!(mid.ctx_pct < 60.0);
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

#[test]
fn active_context_length_uses_probed_capability() {
    use crate::config::providers::{
        ActiveModelRef, CapabilitySource, ModelCapabilities, ModelEntry, ProviderEntry,
        ProvidersConfig, WireApi,
    };

    let (mut driver, _tmp) = test_driver(8);
    let mut entry = ProviderEntry {
        url: "http://127.0.0.1:1/v1".to_string(),
        wire_api: WireApi::Completions,
        ..ProviderEntry::default()
    };
    entry.models.push(ModelEntry {
        id: "local".into(),
        context_length: None,
        capabilities: ModelCapabilities {
            context_tokens: Some(128_000),
            context_tokens_source: Some(CapabilitySource::Probed),
            ..ModelCapabilities::default()
        },
        wire_api: WireApi::Completions,
        ..ModelEntry::default()
    });
    let mut providers = std::collections::BTreeMap::new();
    providers.insert("lmstudio".to_string(), entry);
    driver.test_providers_override = Some((
        ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".into(),
                model: "local".into(),
                reasoning_effort: None,
                thinking_mode: None,
            }),
            ..ProvidersConfig::default()
        },
        "lmstudio".into(),
        "local".into(),
    ));

    assert_eq!(driver.active_model_context_length(), Some(128_000));
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

#[tokio::test]
async fn shadow_brief_predrafts() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    append_complete_test_turns(&mut driver, 2);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    record_test_context_tokens(&driver, 5_500);

    assert!(driver.maybe_shadow_brief(&tx).await);
    assert!(matches!(
        driver.shadow_brief,
        Some(ShadowBriefState::InFlight(_))
    ));
    wait_for_shadow_brief(&mut driver).await;
    assert_eq!(
        compact_inference_purposes(&driver),
        ["compact_shadow_brief"]
    );
}

#[tokio::test]
async fn compact_uses_shadow_delta() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    append_complete_test_turns(&mut driver, 2);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    record_test_context_tokens(&driver, 5_500);
    assert!(driver.maybe_shadow_brief(&tx).await);
    wait_for_shadow_brief(&mut driver).await;
    append_complete_test_turns(&mut driver, 1);

    driver.do_compact(&tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}
    let purposes = compact_inference_purposes(&driver);
    assert_eq!(
        purposes
            .iter()
            .filter(|p| p.as_str() == "compact_shadow_brief")
            .count(),
        1,
        "the shadow/full draft runs exactly once"
    );
    assert_eq!(
        purposes
            .iter()
            .filter(|p| p.as_str() == "compact_brief_delta")
            .count(),
        1,
        "compaction performs one section-wise delta revision"
    );
    assert!(!purposes.iter().any(|p| p == "compact_brief"));
    let calls = crate::sync::lock_or_recover(
        driver
            .test_compact_brief_calls
            .as_ref()
            .expect("fake compact seam"),
    );
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].purpose, "compact_shadow_brief");
    assert_eq!(calls[1].purpose, "compact_brief_delta");
    assert!(calls[1].prompt.contains("<existing_shadow_brief>"));
    assert_eq!(
        crate::engine::compact::complete_exchange_count(&calls[1].history),
        3,
        "delta sees the shadow's omitted tail plus the new exchange"
    );
}

#[tokio::test]
async fn stale_shadow_discarded() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    append_complete_test_turns(&mut driver, 1);
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
    record_test_context_tokens(&driver, 55);
    assert!(driver.maybe_shadow_brief(&tx).await);
    wait_for_shadow_brief(&mut driver).await;
    append_complete_test_turns(&mut driver, 9);

    driver.do_compact(&tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}
    let purposes = compact_inference_purposes(&driver);
    assert!(purposes.iter().any(|p| p == "compact_shadow_brief"));
    assert!(purposes.iter().any(|p| p == "compact_brief"));
    assert!(!purposes.iter().any(|p| p == "compact_brief_delta"));
}

#[tokio::test]
async fn manual_compact_cancels_shadow() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
    let cancel = tokio_util::sync::CancellationToken::new();
    let observed_cancel = cancel.clone();
    driver.shadow_brief_generation = 1;
    driver.shadow_brief = Some(ShadowBriefState::InFlight(ShadowBriefInFlight {
        generation: 1,
        snapshot_history: Vec::new(),
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        cancel,
        handle: tokio::spawn(std::future::pending::<Option<String>>()),
    }));

    driver.do_compact(&tx).await;
    assert!(observed_cancel.is_cancelled());
    drop(tx);
    while rx.recv().await.is_some() {}
    assert_eq!(compact_inference_purposes(&driver), ["compact_brief"]);

    let (mut ending_driver, _tmp2) = test_driver_without_network(8);
    let ending_cancel = tokio_util::sync::CancellationToken::new();
    let ending_observer = ending_cancel.clone();
    ending_driver.shadow_brief = Some(ShadowBriefState::InFlight(ShadowBriefInFlight {
        generation: 1,
        snapshot_history: Vec::new(),
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        cancel: ending_cancel,
        handle: tokio::spawn(std::future::pending::<Option<String>>()),
    }));
    drop(ending_driver);
    assert!(
        ending_observer.is_cancelled(),
        "session teardown cancels shadow work"
    );
}

#[tokio::test]
async fn shadow_brief_foreground_preparation_preempts_before_preflight() {
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    let cancel = tokio_util::sync::CancellationToken::new();
    let observed_cancel = cancel.clone();
    driver.shadow_brief_generation = 1;
    driver.shadow_brief = Some(ShadowBriefState::InFlight(ShadowBriefInFlight {
        generation: 1,
        snapshot_history: Vec::new(),
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        cancel,
        handle: tokio::spawn(std::future::pending::<Option<String>>()),
    }));

    let prepared = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        driver.prepare_queued_user_submission(UserSubmission::text("hello"), &tx),
    )
    .await
    .expect("foreground preparation should not wait for the delayed shadow");
    assert!(prepared.is_some());
    assert!(
        observed_cancel.is_cancelled(),
        "the first preparation action cancels shadow utility work before preflight"
    );

    driver.shadow_brief_generation = 2;
    driver.shadow_brief = Some(ShadowBriefState::Ready(ShadowBriefReady {
        generation: 2,
        snapshot_history: Vec::new(),
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        brief: "ready".to_string(),
    }));
    let _ = driver
        .prepare_queued_user_submission(UserSubmission::text("hello again"), &tx)
        .await;
    assert!(
        matches!(
            &driver.shadow_brief,
            Some(ShadowBriefState::Ready(ready)) if ready.brief == "ready"
        ),
        "a shadow completed before dequeue remains available"
    );
}

#[tokio::test]
async fn shadow_gated_on_prune_effectiveness() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
    record_test_context_tokens(&driver, 50);
    assert!(
        !driver.maybe_shadow_brief(&tx).await,
        "effective pruning gates early band"
    );
    for ctx_pct in [35.0, 42.0, 50.0] {
        driver.note_prune_effectiveness(PruneEffectiveness {
            ctx_pct,
            saved_pct: 0.5,
        });
    }
    assert!(
        driver.maybe_shadow_brief(&tx).await,
        "ineffective pruning opens early band"
    );
    assert!(
        !driver.maybe_shadow_brief(&tx).await,
        "only one draft may be in flight"
    );
}

#[tokio::test]
async fn shadow_killswitch_restores_sync() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    let cfg = ContextConfig {
        compact_shadow: false,
        ..ContextConfig::default()
    };
    install_test_providers(&mut driver, CacheMode::None, cfg, 100);
    record_test_context_tokens(&driver, 55);
    assert!(!driver.maybe_shadow_brief(&tx).await);
    driver.do_compact(&tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}
    assert_eq!(compact_inference_purposes(&driver), ["compact_brief"]);
}

/// Threshold-branch auto-prune: a WARM cache (ephemeral, just sent) with
/// ctx% > the prune ctx% (50) AND prunable% > the prunable% (30) prunes
/// anyway, accepting the cache bust — and the `Pruned` event carries
/// `cache_break = true` so the client surfaces the warning.
#[tokio::test]
async fn auto_prune_threshold_branch_prunes_warm_cache_with_cache_break() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    // A big duplicated body so the prune actually reclaims many tokens
    // (the elision marker is small relative to the body).
    driver.stack[0].history = dup_read_history_big();
    let prunable = prune::dedup_plan(&driver.stack[0].history).tokens_saved();
    assert!(prunable > 0, "the big-body history must be prunable");
    // Pick a window so prunable% > 30 and ctx% > 50: window = prunable*2
    // makes prunable% = 50, and input = 60% of the window keeps ctx% > 50.
    let window = (prunable as u32) * 2;
    install_test_providers(
        &mut driver,
        CacheMode::Ephemeral,
        ContextConfig::default(),
        window,
    );
    // Warm cache: a send just happened.
    driver.session.note_send();
    let input = (f64::from(window) * 0.6) as u64; // ctx% = 60 (> 50)
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: input,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .unwrap();

    assert!(
        driver.maybe_auto_prune(&tx).await,
        "threshold branch prunes on a warm cache"
    );
    // The emitted Pruned event flags the cache break.
    let mut saw_cache_break = false;
    let mut saw_warm_threshold = false;
    drop(tx);
    while let Some(ev) = rx.recv().await {
        if let TurnEvent::Pruned {
            cache_break,
            trigger_reason,
            ..
        } = ev
        {
            saw_cache_break = saw_cache_break || cache_break;
            saw_warm_threshold =
                saw_warm_threshold || trigger_reason.as_deref() == Some("warm_threshold");
        }
    }
    assert!(
        saw_cache_break,
        "warm-cache threshold prune flags cache_break"
    );
    assert!(
        saw_warm_threshold,
        "warm-cache threshold prune records trigger reason"
    );
}

/// Auto-compact fires at/above the configured ctx% (default 60) and is a
/// one-shot (the second call no-ops because the session is being handed
/// off). Below the line it doesn't fire.
#[tokio::test]
async fn auto_compact_fires_at_threshold_once() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
    let fixture_model = driver.stack[0].agent.model.clone();
    let mut build = crate::engine::builtin::load("Build", &driver.spawn_args(true)).unwrap();
    build.model = fixture_model;
    driver.stack[0].agent = Arc::new(build);
    std::fs::write(driver.cwd.join("seed.txt"), "seed body").unwrap();
    driver
        .session
        .record_tool_call(crate::session::ToolCallRow {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: "seed-source".into(),
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: "read".into(),
            path: Some("seed.txt".into()),
            original_input_json: serde_json::json!({ "path": "seed.txt" }),
            wire_input_json: serde_json::json!({ "path": "seed.txt" }),
            recovery: crate::db::tool_calls::Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: "seed body".into(),
            truncated: false,
            duration_ms: 1,
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        })
        .unwrap();

    // 50% < 60 → no compact.
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: 50,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .unwrap();
    assert!(
        !driver.maybe_auto_compact(&tx).await,
        "below 60% no compact"
    );

    // 65% ≥ 60 → compact fires once.
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: 65,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .unwrap();
    assert!(driver.maybe_auto_compact(&tx).await, "at/over 60% compacts");
    // One-shot: a second call no-ops even while still hot.
    assert!(
        !driver.maybe_auto_compact(&tx).await,
        "auto-compact is one-shot per session"
    );
    drop(tx);
    let mut events = Vec::new();
    while let Some(ev) = rx.recv().await {
        events.push(ev);
    }
    let seed_start = events
        .iter()
        .position(|ev| matches!(ev, TurnEvent::ToolStart { tool, .. } if tool == "read"))
        .expect("seed read starts without a user follow-up");
    let seed_end = events
        .iter()
        .position(|ev| matches!(ev, TurnEvent::ToolEnd { tool, output, .. } if tool == "read" && output.contains("seed body")))
        .expect("seed read completes without a user follow-up");
    let compact_ready = events
        .iter()
        .position(
            |ev| matches!(ev, TurnEvent::CompactReady { brief, .. } if !brief.trim().is_empty()),
        )
        .expect("compact ready event emitted");
    assert!(
        seed_start < seed_end && seed_end < compact_ready,
        "seed tools should run before CompactReady: {events:?}"
    );
}

#[tokio::test]
async fn oversized_compact_handoff_leaves_history_unchanged() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.stack[0].history = vec![
        Message::user("retain this exact user turn"),
        Message::assistant("retain this exact assistant turn"),
    ];
    let before = serde_json::to_value(&driver.stack[0].history).unwrap();
    // The empty planning placeholder fits, while the assembled five-section
    // handoff plus deterministic appendix cannot land below 60% of this tiny
    // window. This exercises the driver's rollback after prune-first.
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 40);

    driver.do_compact(&tx).await;

    assert_eq!(
        serde_json::to_value(&driver.stack[0].history).unwrap(),
        before
    );
    assert!(
        driver
            .session
            .db
            .list_session_events(driver.session.id)
            .unwrap()
            .iter()
            .all(|event| event.kind != "session_compacted"),
        "a failed compaction must not record a successful boundary"
    );
    drop(tx);
    let mut saw_unchanged_notice = false;
    while let Some(event) = rx.recv().await {
        if matches!(event, TurnEvent::Notice { text } if text.contains("history was left unchanged"))
        {
            saw_unchanged_notice = true;
        }
    }
    assert!(
        saw_unchanged_notice,
        "the explicit failure should be surfaced"
    );
}

#[tokio::test]
async fn zero_window_compact_fails_explicitly_without_mutation() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(16);
    driver.stack[0].history = vec![Message::user("keep me"), Message::assistant("kept")];
    let before = serde_json::to_value(&driver.stack[0].history).unwrap();
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 0);

    driver.do_compact(&tx).await;

    assert_eq!(
        serde_json::to_value(&driver.stack[0].history).unwrap(),
        before
    );
    drop(tx);
    assert!(
        matches!(rx.recv().await, Some(TurnEvent::Notice { text }) if text.contains("history was left unchanged"))
    );
}

#[tokio::test]
async fn compact_private_prune_preserves_shell_condensation() {
    use crate::config::providers::{CacheMode, ContextConfig};
    use crate::engine::message::{AssistantContent, OneOrMany};
    use rig::message::{ToolCall, ToolFunction};

    let (mut driver, _tmp) = test_driver(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    let original = (0..700)
        .map(|index| format!("noise line {index}"))
        .collect::<Vec<_>>()
        .join("\n");
    driver.stack[0].history = vec![
        Message::user("run the suite"),
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                id: "bash-condense".into(),
                call_id: None,
                function: ToolFunction {
                    name: "bash".into(),
                    arguments: serde_json::json!({"command": "cargo test"}),
                },
                signature: None,
                additional_params: None,
            })),
        },
        Message::tool_result_with_call_id("bash-condense".to_string(), None, original.clone()),
        Message::assistant("suite complete"),
    ];
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        100_000,
    );

    driver.do_compact(&tx).await;

    let wire = serde_json::to_string(&driver.stack[0].history).unwrap();
    assert!(wire.contains("compressed tool result"), "{wire}");
    let stored = driver
        .session
        .db
        .list_compressed_tool_results(driver.session.id)
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].content, original);
}

#[test]
fn compact_tail_prompt_uses_durable_session_event_seqs() {
    let (mut driver, _tmp) = test_driver(8);
    let agent = driver.active_agent().to_string();
    let mut recorded = Vec::new();
    let mut excluded_skill_seq = None;
    for index in 0..2 {
        recorded.push(
            driver
                .session
                .record_event(
                    crate::db::session_log::SessionEventKind::UserMessage,
                    None,
                    None,
                    &serde_json::json!({"text": format!("user {index}")}),
                )
                .unwrap(),
        );
        if index == 1 {
            excluded_skill_seq = Some(
                driver
                    .session
                    .record_event(
                        crate::db::session_log::SessionEventKind::ToolCall,
                        Some(&agent),
                        Some("skill-nonsteering"),
                        &serde_json::json!({
                            "tool": "skill",
                            "wire_input": {"name": "reference"},
                            "output": "injected body",
                        }),
                    )
                    .unwrap(),
            );
            driver.skill_pairs.push(SkillPair {
                call_id: "skill-nonsteering".into(),
                owner: agent.clone(),
                intentional_steer: false,
            });
        }
        recorded.push(
            driver
                .session
                .record_event(
                    crate::db::session_log::SessionEventKind::AssistantMessage,
                    Some(&agent),
                    None,
                    &serde_json::json!({"text": format!("assistant {index}")}),
                )
                .unwrap(),
        );
    }

    assert_eq!(driver.compact_tail_message_seqs(1), recorded[2..]);
    assert!(
        !driver
            .compact_tail_message_seqs(1)
            .contains(&excluded_skill_seq.unwrap())
    );
}

#[tokio::test]
async fn request_compact_honored_at_safe_boundary() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    driver.auto_compacted = true;
    driver.session.request_agent_compact();

    assert!(
        driver.maybe_auto_compact(&tx).await,
        "agent-requested compaction bypasses the auto latch"
    );
    assert!(!driver.session.agent_compact_requested());
    assert!(
        matches!(driver.stack[0].history.first(), Some(Message::User { .. })),
        "post-compact history starts with the handoff; a configured tail may follow"
    );
    drop(tx);
    let mut saw_compact_ready = false;
    while let Some(ev) = rx.recv().await {
        if matches!(ev, TurnEvent::CompactReady { .. }) {
            saw_compact_ready = true;
        }
    }
    assert!(saw_compact_ready, "compaction emits CompactReady");
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    let compact_events: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "session_compacted")
        .collect();
    assert_eq!(compact_events.len(), 1);
    assert_eq!(compact_events[0].data["source"], "agent_requested");
}

#[tokio::test]
async fn request_compact_coalesces() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    driver.session.request_agent_compact();
    driver.session.request_agent_compact();

    assert!(driver.maybe_auto_compact(&tx).await);
    assert!(!driver.maybe_auto_compact(&tx).await);
    drop(tx);
    while rx.recv().await.is_some() {}
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    let compact_count = events
        .iter()
        .filter(|event| event.kind == "session_compacted")
        .count();
    assert_eq!(compact_count, 1);
}

/// `classify_prune_reason` reports the telemetry reason from a plan's
/// targets (Part D).
#[test]
fn classify_prune_reason_buckets() {
    use crate::engine::prune::{DedupPlan, Elision, ElisionTarget, OVERLAP_REASON};
    let mk = |reason: &'static str| ElisionTarget {
        history_index: 0,
        current_body: String::new(),
        elision: Elision {
            original_event_id: "x".into(),
            reason,
        },
        partial_body: None,
        tokens_saved: 0,
        target_call_id: "x".into(),
    };
    let exact = DedupPlan {
        targets: vec![mk("snapshot superseded")],
    };
    assert_eq!(classify_prune_reason(&exact), "exact-identity");
    let overlap = DedupPlan {
        targets: vec![mk(OVERLAP_REASON)],
    };
    assert_eq!(classify_prune_reason(&overlap), "overlap-merge");
    let mixed = DedupPlan {
        targets: vec![mk("snapshot superseded"), mk(OVERLAP_REASON)],
    };
    assert_eq!(classify_prune_reason(&mixed), "mixed");
}

/// The escalation predicate: N consecutive small-saving prunes while ctx%
/// climbs is ineffective; a single big save, a non-climbing run, or too
/// few prunes is not (implementation note Part B).
#[tokio::test]
async fn prune_ineffective_predicate() {
    let (mut driver, _tmp) = test_driver(8);
    // Fewer than the run length → not ineffective yet.
    driver.note_prune_effectiveness(PruneEffectiveness {
        ctx_pct: 50.0,
        saved_pct: 0.5,
    });
    driver.note_prune_effectiveness(PruneEffectiveness {
        ctx_pct: 55.0,
        saved_pct: 0.5,
    });
    assert!(!driver.prune_is_ineffective(), "two prunes is too few");

    // A third small-and-climbing prune trips it.
    driver.note_prune_effectiveness(PruneEffectiveness {
        ctx_pct: 60.0,
        saved_pct: 0.5,
    });
    assert!(
        driver.prune_is_ineffective(),
        "three small saves while ctx% climbs is ineffective"
    );

    // A large recent save breaks the run.
    driver.note_prune_effectiveness(PruneEffectiveness {
        ctx_pct: 65.0,
        saved_pct: 20.0,
    });
    assert!(
        !driver.prune_is_ineffective(),
        "a big save means pruning is working"
    );

    // Small saves but ctx% NOT climbing (flat/falling) → not ineffective
    // (pruning is holding the line).
    let mut d2 = test_driver(8).0;
    for ctx in [60.0, 55.0, 50.0] {
        d2.note_prune_effectiveness(PruneEffectiveness {
            ctx_pct: ctx,
            saved_pct: 0.5,
        });
    }
    assert!(
        !d2.prune_is_ineffective(),
        "ctx% not climbing → not an escalation case"
    );
}

/// End-to-end escalation: when auto-prunes keep saving little while ctx%
/// climbs (below the hard auto-compact line), the next idle boundary
/// escalates to `/compact` (implementation note Part B).
#[tokio::test]
async fn ineffective_prunes_escalate_to_compaction_below_compact_line() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    // ctx 55% is below the 60% auto-compact line, so only escalation can
    // trigger a compact here.
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: 55,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .unwrap();
    // No ineffective history yet → below the line, no compact.
    assert!(
        !driver.maybe_auto_compact(&tx).await,
        "below the compact line with no ineffective run → no compact"
    );
    // Seed an ineffective run (three small saves, climbing ctx%).
    for ctx in [35.0, 45.0, 55.0] {
        driver.note_prune_effectiveness(PruneEffectiveness {
            ctx_pct: ctx,
            saved_pct: 0.5,
        });
    }
    assert!(
        driver.maybe_auto_compact(&tx).await,
        "ineffective prunes escalate to compaction below the hard line"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

/// No `context_length` known → the ctx%-gated paths are inert: the
/// threshold auto-prune branch and auto-compact both skip, but the
/// cache-cold auto-prune branch still fires.
#[tokio::test]
async fn no_context_length_makes_ctx_gated_paths_inert() {
    use crate::config::providers::{
        ActiveModelRef, CacheConfig, CacheMode, ModelEntry, ProviderEntry, ProvidersConfig,
    };
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    // Provider config WITHOUT a context_length on the model, ephemeral
    // (so cache could be warm), warm send.
    let mut entry = ProviderEntry {
        url: "http://localhost:1/v1".into(),
        cache: CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 300,
        },
        ..ProviderEntry::default()
    };
    entry.models.push(ModelEntry {
        id: "local".into(),
        name: None,
        thinking_modes: vec![],
        inputs: None,
        context_length: None, // unknown window
        favorite: false,
        manual: false,
        trust: None,
        location: None,
        quality_rank: None,
        cost_rank: None,
        subagent_invokable: None,
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
        wire_api: Default::default(),
        extra: Default::default(),
        capabilities: Default::default(),
        capability_overrides: Default::default(),
        provider_metadata: Default::default(),
    });
    let mut providers = std::collections::BTreeMap::new();
    providers.insert("lmstudio".to_string(), entry);
    driver.test_providers_override = Some((
        ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".into(),
                model: "local".into(),
                reasoning_effort: None,
                thinking_mode: None,
            }),
            ..ProvidersConfig::default()
        },
        "lmstudio".into(),
        "local".into(),
    ));

    // Auto-compact inert (no ctx%).
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: 999_999,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .unwrap();
    assert!(
        !driver.maybe_auto_compact(&tx).await,
        "no context_length → auto-compact inert"
    );

    // Threshold auto-prune branch inert on a WARM cache (no ctx%), so the
    // only thing that could fire it is the cache-cold branch. Make it
    // cold (no send → cold) and confirm the cache-cold branch still works.
    driver.stack[0].history = dup_read_history_big();
    assert!(
        driver.maybe_auto_prune(&tx).await,
        "cache-cold auto-prune still fires without context_length"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn dispatch_loop_start_and_cancel() {
    let (mut driver, _tmp) = test_driver(8);
    let out = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 60, "prompt": "poll", "limit": 2 }
        }))
        .await
        .unwrap();
    assert!(out.starts_with("started loop"), "got {out}");
    assert!(driver.schedule.has_loop());
    // The capability hint for loop.cancel fires exactly once.
    let hints = driver.pending_capability_hints();
    assert_eq!(hints.len(), 1);
    assert!(hints[0].contains("loop.cancel"));
    assert!(
        driver.pending_capability_hints().is_empty(),
        "hint is one-shot"
    );

    let job_id = out
        .split('`')
        .nth(1)
        .expect("job id in backticks")
        .to_string();
    let cancel = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.cancel",
            "args": { "job_id": job_id }
        }))
        .await
        .unwrap();
    assert!(cancel.starts_with("cancelled"), "got {cancel}");
    assert!(!driver.schedule.has_loop());
}

/// End-to-end gate (implementation note): a
/// `loop.start` whose `interval` AND `limit` are JSON strings (the
/// observed weak-model failure, session `ezhcf7`) must SUCCEED — both
/// coerced/accepted, the loop scheduled — rather than erroring on a
/// value-vs-type confusion.
#[tokio::test]
async fn dispatch_loop_start_coerces_stringified_numerics_e2e() {
    let (mut driver, _tmp) = test_driver(8);
    let dispatch = driver
        .dispatch_schedule_action_repaired(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": "20000", "limit": "1", "prompt": "echo hello" }
        }))
        .await
        .expect("stringified numerics must be coerced, not rejected");
    // `limit=1` → a timer was scheduled.
    assert!(
        dispatch.output.starts_with("started timer"),
        "got {}",
        dispatch.output
    );
    assert!(driver.schedule.has_loop());

    // §14 wire-vs-user split: the row records the per-action repair as
    // its recovery, and the repaired `wire_args` show the coerced int.
    assert!(matches!(
        dispatch.recovery,
        crate::db::tool_calls::Recovery::ShapeRepair {
            stage: "parse_stringified_number",
            ..
        }
    ));
    assert_eq!(dispatch.wire_args["args"]["limit"], serde_json::json!(1));
    // The string interval (a schema-valid union member) survives as the
    // 20000-second value the parser read.
    assert_eq!(dispatch.wire_args["action"], "loop.start");
}

/// The §14 record is populated on the persisted `tool_call` row exactly
/// like a top-level tool repair: a stringified-numeric `schedule` call stores
/// `recovery_kind=shape_repair`/`recovery_stage=parse_stringified_number`,
/// `original_input` = what the model sent, `wire_input` = the repaired
/// `{action, args}`. Drives the production dispatch + record path.
#[tokio::test]
async fn schedule_subarg_repair_record_round_trips_recovery_and_wire() {
    let (mut driver, _tmp) = test_driver(8);
    let original = serde_json::json!({
        "action": "loop.start",
        "args": { "interval": 30, "limit": "1", "prompt": "p" }
    });
    let dispatch = driver
        .dispatch_schedule_action_repaired(&original)
        .await
        .expect("repairable call must dispatch");
    // Mirror the TurnOutcome::ScheduleAction recording (outer recovery is
    // Clean here, so the sub-arg repair is the recorded recovery).
    driver.record_schedule_tool_call(ScheduleToolCallRecord {
        agent: "builder".to_string(),
        llm_mode: crate::config::extended::LlmMode::default(),
        call_id: "call-jobs-repair".to_string(),
        original_input_json: original.clone(),
        wire_input_json: dispatch.wire_args.clone(),
        recovery: dispatch.recovery,
        hard_fail: false,
        output: dispatch.output,
        duration_ms: 1,
    });

    let rows = driver
        .session
        .db
        .list_tool_calls_for_session(driver.session.id)
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r.call_id == "call-jobs-repair")
        .unwrap();
    // original_input keeps the model's stringified `limit`.
    assert_eq!(
        row.original_input_json["args"]["limit"],
        serde_json::json!("1")
    );
    // wire_input carries the coerced integer.
    assert_eq!(row.wire_input_json["args"]["limit"], serde_json::json!(1));
    // recovery_kind/recovery_stage round-trip the shape repair.
    assert!(matches!(
        row.recovery,
        crate::db::tool_calls::Recovery::ShapeRepair {
            stage: "parse_stringified_number",
            ..
        }
    ));
}

#[tokio::test]
async fn dispatch_timer_is_loop_with_limit_one() {
    let (mut driver, _tmp) = test_driver(8);
    let out = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 5, "prompt": "fire", "limit": 1 }
        }))
        .await
        .unwrap();
    assert!(out.starts_with("started timer"), "got {out}");
}

#[tokio::test]
async fn dispatch_list_and_capacity_error() {
    let (mut driver, _tmp) = test_driver(1);
    let empty: serde_json::Value = serde_json::from_str(
        &driver
            .dispatch_schedule_action(&serde_json::json!({ "action": "list" }))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(empty["scheduled"].as_array().unwrap().len(), 0);
    assert_eq!(empty["swarm"]["running"], 0);
    assert_eq!(empty["swarm"]["queued"], 0);
    driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 60, "prompt": "p", "limit": 2 }
        }))
        .await
        .unwrap();
    let listed: serde_json::Value = serde_json::from_str(
        &driver
            .dispatch_schedule_action(&serde_json::json!({ "action": "list" }))
            .await
            .unwrap(),
    )
    .unwrap();
    let scheduled = listed["scheduled"].as_array().unwrap();
    assert_eq!(scheduled.len(), 1, "got {listed}");
    assert_eq!(scheduled[0]["kind"], "loop");
    assert_eq!(scheduled[0]["status"], "pending");
    assert_eq!(scheduled[0]["executions_completed"], 0);
    assert_eq!(scheduled[0]["execution_limit"], serde_json::json!(2));
    assert!(
        scheduled[0]["job_id"]
            .as_str()
            .unwrap()
            .starts_with("sched-")
    );
    assert_eq!(scheduled[0]["label"], "p");
    // Cap is 1 — a second start errors.
    let err = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 60, "prompt": "q", "limit": 2 }
        }))
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("max concurrent scheduled tasks"));
}

#[test]
fn schedule_tool_call_record_persists_wire_and_original() {
    let (driver, _tmp) = test_driver(8);
    let original = serde_json::json!({ "action": "list" });
    let wire = serde_json::json!({ "action": "list", "args": {} });
    driver.record_schedule_tool_call(ScheduleToolCallRecord {
        agent: "builder".to_string(),
        llm_mode: crate::config::extended::LlmMode::default(),
        call_id: "call-sched-1".to_string(),
        original_input_json: original.clone(),
        wire_input_json: wire.clone(),
        recovery: crate::db::tool_calls::Recovery::Clean,
        hard_fail: false,
        output: "{\"scheduled\":[],\"swarm\":{\"running\":0,\"queued\":0}}".to_string(),
        duration_ms: 3,
    });

    let rows = driver
        .session
        .db
        .list_tool_calls_for_session(driver.session.id)
        .unwrap();
    let row = rows.iter().find(|r| r.tool == "schedule").unwrap();
    assert_eq!(row.call_id, "call-sched-1");
    assert_eq!(row.original_input_json, original);
    assert_eq!(row.wire_input_json, wire);
    assert!(!row.hard_fail);
    assert_eq!(
        row.output,
        "{\"scheduled\":[],\"swarm\":{\"running\":0,\"queued\":0}}"
    );
}

/// §5 dispatch record (implementation note): a dispatched
/// `schedule` action also lands a `tool_call` row on the export timeline
/// (`session_events`), not just the `tool_call_events` stats table — so the
/// export reflects the successful native call, not only failed detours.
#[test]
fn schedule_dispatch_emits_tool_call_session_event() {
    let (driver, _tmp) = test_driver(8);
    driver.record_schedule_tool_call(ScheduleToolCallRecord {
        agent: "builder".to_string(),
        llm_mode: crate::config::extended::LlmMode::default(),
        call_id: "call-sched-evt".to_string(),
        original_input_json: serde_json::json!({ "action": "list" }),
        wire_input_json: serde_json::json!({ "action": "list", "args": {} }),
        recovery: crate::db::tool_calls::Recovery::Clean,
        hard_fail: false,
        output: "{\"scheduled\":[],\"swarm\":{\"running\":0,\"queued\":0}}".to_string(),
        duration_ms: 3,
    });

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    let tool_call = events
        .iter()
        .find(|e| e.kind == "tool_call" && e.call_id.as_deref() == Some("call-sched-evt"))
        .expect("schedule dispatch should emit a tool_call session event");
    assert_eq!(tool_call.data["tool"], "schedule");
    assert_eq!(tool_call.data["hard_fail"], false);
    assert_eq!(tool_call.data["original_input"]["action"], "list");
}

#[tokio::test]
async fn dispatch_background_tail_unknown_id() {
    let (mut driver, _tmp) = test_driver(8);
    let out = driver
        .dispatch_schedule_action(&serde_json::json!({
            "action": "background.tail",
            "args": { "job_id": "sched-nope" }
        }))
        .await
        .unwrap();
    assert!(out.contains("no live background"), "got {out}");
}

/// Config resolution: with no `config.json` on disk, the
/// delegation-shrink strategy defaults to `prune` (lowest quality
/// loss, priority #1) and a 30s margin.
#[test]
fn resolve_shrink_config_defaults_to_prune() {
    use crate::config::providers::ShrinkStrategy;
    let (driver, _tmp) = test_driver(8);
    let shrink = driver.resolve_shrink_config();
    assert_eq!(shrink.strategy, ShrinkStrategy::Prune);
    assert_eq!(shrink.margin_secs, 30);
}

/// `finish_delegation_shrink`: a COLD-at-return parent (no-cache
/// provider → always cold) with a computed prune-shrink resumes on the
/// SHRUNK context — the driver swaps the foreground frame's history.
#[tokio::test]
async fn finish_delegation_shrink_cold_swaps_parent_history() {
    use crate::config::providers::{CacheConfig, CacheMode, ShrinkConfig};
    use crate::engine::deleg_shrink::DelegationShrink;

    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    // Parent (foreground) frame carries elidable duplicate reads.
    driver.stack[0].history = dup_read_history();
    assert!(
        !prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "parent has something prunable"
    );

    // A tracker on a no-cache provider is always cold; pre-compute the
    // prune-shrink as the parallel task would have.
    let none = CacheConfig {
        mode: CacheMode::None,
        ttl_secs: 300,
    };
    let mut tracker = DelegationShrink::new(none, &ShrinkConfig::default());
    let shrunk = crate::engine::deleg_shrink::prune_shrink(&driver.stack[0].history);
    tracker.set_shrunk(shrunk);

    driver.finish_delegation_shrink(tracker, None, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}

    // Cold → resumed on the shrunk context: the foreground history is
    // now fully pruned (nothing left elidable).
    assert!(
        prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "cold parent resumed on the shrunk (pruned) context"
    );
}

/// `finish_delegation_shrink`: a HOT-at-return parent (cache-capable,
/// within TTL) keeps its FULL context even when a shrink was computed —
/// no quality loss, the cache is paid for.
#[tokio::test]
async fn finish_delegation_shrink_hot_keeps_full() {
    use crate::config::providers::{CacheConfig, CacheMode, ShrinkConfig};
    use crate::engine::deleg_shrink::DelegationShrink;

    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver.stack[0].history = dup_read_history();

    // Ephemeral cache, generous TTL, tracker started "now" → hot.
    let ephemeral = CacheConfig {
        mode: CacheMode::Ephemeral,
        ttl_secs: 3600,
    };
    let mut tracker = DelegationShrink::new(ephemeral, &ShrinkConfig::default());
    tracker.set_shrunk(vec![Message::user("shrunk")]);

    driver.finish_delegation_shrink(tracker, None, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}

    // Hot → full context retained: still has the elidable duplicate.
    assert!(
        !prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "hot parent kept its full (un-shrunk) context"
    );
}

/// `begin_delegation_shrink` on a no-cache provider spawns an EAGER
/// shrink task that finishes promptly (ZERO delay); the prune-shrink
/// result is adopted on `finish`. Exercises the full begin→finish path.
#[tokio::test]
async fn begin_delegation_shrink_eager_on_no_cache() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    // Default test driver uses provider `lmstudio` with no cache config
    // → CacheMode::None → eager.
    driver.stack[0].history = dup_read_history();
    let parent_full = driver.stack[0].history.clone();
    let (tracker, handle) = driver.begin_delegation_shrink(parent_full);
    assert!(handle.is_some(), "a shrink task was spawned");

    // Let the eager task run to completion.
    let handle = handle.unwrap();
    let shrunk = handle.await.unwrap();
    assert!(
        prune::dedup_plan(&shrunk).is_empty(),
        "eager prune-shrink produced a pruned history"
    );

    // Re-run begin to get a fresh tracker + handle to finish with the
    // already-computed result (the prior handle was consumed above).
    let (mut tracker2, h) = driver.begin_delegation_shrink(driver.stack[0].history.clone());
    if let Some(h) = h {
        h.abort();
    }
    tracker2.set_shrunk(shrunk);
    let _ = tracker; // first tracker not needed further
    driver.finish_delegation_shrink(tracker2, None, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}

    // No-cache provider is always cold → swapped to the shrunk context.
    assert!(prune::dedup_plan(&driver.stack[0].history).is_empty());
}

// ---- re-queryable subagents + seeding (GOALS §3c) --------------------

use crate::db::seed_tools::SeedTool;

/// Persist a transcript under a handle, then rehydrate it: the round trip
/// returns the same messages, so a follow-up resumes with prior context.
#[test]
fn rehydrate_handle_persist_round_trip() {
    let (driver, tmp) = test_driver(8);
    let history = vec![
        Message::user("earlier question"),
        Message::assistant("earlier answer"),
    ];
    let handle = driver
        .persist_subagent_handle("explore", &history, Some(tmp.path()), None)
        .expect("a handle is minted");
    // Enabled (normal-mode gate passed) + matching agent → rehydrated.
    let got = driver
        .rehydrate_handle(&handle, "explore", Some(tmp.path()), true)
        .expect("rehydrates");
    assert_eq!(got.len(), history.len());
}

/// An unknown handle is a clear tool error telling the caller to spawn
/// fresh — never a silent cold start.
#[test]
fn rehydrate_handle_unknown_is_stale_error() {
    let (driver, tmp) = test_driver(8);
    let err = driver
        .rehydrate_handle("sub-does-not-exist", "explore", Some(tmp.path()), true)
        .unwrap_err();
    assert!(err.contains("resume_handle"), "{err}");
    assert!(err.contains("fresh"), "{err}");
}

#[test]
fn resolve_child_cwd_accepts_relative_dot_and_absolute_inside_workspace() {
    let (driver, tmp) = test_driver(8);
    let child_dir = tmp.path().join("child");
    std::fs::create_dir(&child_dir).unwrap();

    let relative = driver.resolve_child_cwd(Some("child")).unwrap();
    assert_eq!(relative.requested.as_deref(), Some("child"));
    assert_eq!(relative.resolved, child_dir.canonicalize().unwrap());

    let dot = driver.resolve_child_cwd(Some(".")).unwrap();
    assert_eq!(dot.requested.as_deref(), Some("."));
    assert_eq!(dot.resolved, tmp.path().canonicalize().unwrap());

    let absolute = driver
        .resolve_child_cwd(Some(child_dir.to_str().unwrap()))
        .unwrap();
    assert_eq!(absolute.resolved, child_dir.canonicalize().unwrap());
}

#[test]
fn resolve_child_cwd_rejects_missing_files_and_outside_workspace() {
    let (driver, tmp) = test_driver(8);
    let file = tmp.path().join("not-a-dir.txt");
    std::fs::write(&file, "x").unwrap();

    let missing = driver.resolve_child_cwd(Some("missing")).unwrap_err();
    assert!(missing.contains("does not exist or is not a directory"));

    let file_err = driver
        .resolve_child_cwd(Some(file.to_str().unwrap()))
        .unwrap_err();
    assert!(file_err.contains("does not exist or is not a directory"));

    let outside = tempfile::tempdir().unwrap();
    let outside_err = driver
        .resolve_child_cwd(Some(outside.path().to_str().unwrap()))
        .unwrap_err();
    assert!(outside_err.contains("outside trusted workspace"));
}

/// In defensive mode the whole feature is disabled at the capability
/// level: even a valid handle is rejected (the only path is a fresh
/// spawn). Gates behavior, not just description text.
#[test]
fn rehydrate_handle_disabled_in_defensive() {
    let (driver, tmp) = test_driver(8);
    let history = vec![Message::user("q")];
    let handle = driver
        .persist_subagent_handle("explore", &history, Some(tmp.path()), None)
        .unwrap();
    // `followup_enabled = false` models the defensive gate
    // (`Capability::FollowupSeed.enabled(Defensive) == false`).
    let err = driver
        .rehydrate_handle(&handle, "explore", Some(tmp.path()), false)
        .unwrap_err();
    assert!(err.contains("fresh"), "{err}");
}

/// A handle that belongs to a different agent (and, by construction, any
/// `docs` follow-up — the pipeline never persists a handle) is stale.
#[test]
fn rehydrate_handle_wrong_agent_is_stale() {
    let (driver, tmp) = test_driver(8);
    let handle = driver
        .persist_subagent_handle("explore", &[Message::user("q")], Some(tmp.path()), None)
        .unwrap();
    // Re-querying as `docs` against an `explore` handle → stale (and docs
    // never mints one anyway, so this is the only outcome it can hit).
    let err = driver
        .rehydrate_handle(&handle, "docs", Some(tmp.path()), true)
        .unwrap_err();
    assert!(err.contains("fresh"), "{err}");
}

#[test]
fn rehydrate_handle_wrong_cwd_is_stale() {
    let (driver, tmp) = test_driver(8);
    let original = tmp.path().join("original");
    let other = tmp.path().join("other");
    std::fs::create_dir(&original).unwrap();
    std::fs::create_dir(&other).unwrap();
    let handle = driver
        .persist_subagent_handle("explore", &[Message::user("q")], Some(&original), None)
        .unwrap();

    let err = driver
        .rehydrate_handle(&handle, "explore", Some(&other), true)
        .unwrap_err();
    assert!(err.contains("fresh"), "{err}");
}

/// A follow-up persists under the SAME handle (passed as `existing`), so
/// the caller can keep re-querying with one stable handle.
#[test]
fn persist_reuses_existing_handle_on_followup() {
    let (driver, tmp) = test_driver(8);
    let h1 = driver
        .persist_subagent_handle("explore", &[Message::user("q1")], Some(tmp.path()), None)
        .unwrap();
    let h2 = driver
        .persist_subagent_handle(
            "explore",
            &[Message::user("q1"), Message::user("q2")],
            Some(tmp.path()),
            Some(&h1),
        )
        .unwrap();
    assert_eq!(h1, h2, "a follow-up keeps the same handle");
    // The transcript was refreshed (upsert) to the longer history.
    let got = driver
        .rehydrate_handle(&h2, "explore", Some(tmp.path()), true)
        .unwrap();
    assert_eq!(got.len(), 2);
}

// ── write-capable follow-up (implementation note) ──

/// A finished `builder` (write-capable, interactive by default) can be
/// persisted under a handle and re-queried via it — the round trip returns
/// the same transcript, so the follow-up resumes with prior context. The
/// re-query path is agent-name-agnostic: `builder` rehydrates exactly like
/// `explore`.
#[test]
fn builder_followup_persist_and_rehydrate_round_trip() {
    let (driver, tmp) = test_driver(8);
    let history = vec![
        Message::user("implement the flag"),
        write_turn("w1", "/src/a.rs"),
        Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
        Message::assistant("done"),
    ];
    let handle = driver
        .persist_subagent_handle("builder", &history, Some(tmp.path()), None)
        .expect("a builder handle is minted");
    // Stored under the `builder` agent name; re-querying as `builder` rehydrates.
    let got = driver
        .rehydrate_handle(&handle, "builder", Some(tmp.path()), true)
        .expect("builder rehydrates");
    assert_eq!(got.len(), history.len());
    // Re-querying that handle under a DIFFERENT agent name is stale (the
    // handle belongs to `builder`).
    assert!(
        driver
            .rehydrate_handle(&handle, "explore", Some(tmp.path()), true)
            .is_err()
    );
}

/// A `builder` follow-up persisting more work under the SAME handle upserts
/// the transcript (idempotent handle lifecycle), same as `explore`.
#[test]
fn builder_followup_refreshes_handle_idempotently() {
    let (driver, tmp) = test_driver(8);
    let h1 = driver
        .persist_subagent_handle(
            "builder",
            &[Message::user("step 1")],
            Some(tmp.path()),
            None,
        )
        .unwrap();
    let h2 = driver
        .persist_subagent_handle(
            "builder",
            &[Message::user("step 1"), Message::assistant("did step 1")],
            Some(tmp.path()),
            Some(&h1),
        )
        .unwrap();
    assert_eq!(h1, h2);
    assert_eq!(
        driver
            .rehydrate_handle(&h2, "builder", Some(tmp.path()), true)
            .unwrap()
            .len(),
        2
    );
}

/// The `docs` pipeline is excluded from follow-up: it never persists a
/// handle, so any `docs` resume is stale (told to spawn fresh).
#[test]
fn docs_is_excluded_from_followup() {
    assert!(!crate::engine::builtin::is_followup_eligible("docs"));
    assert!(!crate::engine::builtin::is_followup_eligible(
        "docs-resolver"
    ));
    assert!(!crate::engine::builtin::is_followup_eligible(
        "docs-answerer"
    ));
    // builder/explore/custom are all eligible.
    assert!(crate::engine::builtin::is_followup_eligible("builder"));
    assert!(crate::engine::builtin::is_followup_eligible("explore"));
    assert!(crate::engine::builtin::is_followup_eligible(
        "my-custom-subagent"
    ));
}

/// End-to-end lock composition for a write-capable follow-up: the finished
/// `builder`'s locks are snapshotted on suspend; a follow-up re-acquires them
/// HASH-MATCHED when the worktree is unchanged, and the §3c write guard
/// holds (the reawakened builder may write the still-matching file).
#[test]
fn write_capable_followup_reacquires_locks_hash_matched() {
    let (driver, tmp) = test_driver(8);
    let p = tmp.path().join("a.rs");
    std::fs::write(&p, "v1").unwrap();
    let sid = driver.session.id;
    // Original builder run: acquire + write, then finish (suspend snapshots).
    driver.locks.acquire(&p, "builder", sid).unwrap();
    driver
        .locks
        .check_write_permitted(&p, "builder", sid)
        .unwrap();
    driver.locks.suspend_agent("builder", sid).unwrap();
    assert!(
        driver.locks.holder(&p).is_none(),
        "finish releases the lock"
    );
    // Follow-up: worktree unchanged → resume reacquires hash-matched.
    let reacquired = driver.locks.resume_agent("builder", sid).unwrap();
    assert_eq!(reacquired.len(), 1);
    assert_eq!(
        driver.locks.holder(&p).map(|(_, a)| a).as_deref(),
        Some("builder")
    );
    // The reawakened builder may write the still-matching file (§3c holds).
    driver
        .locks
        .check_write_permitted(&p, "builder", sid)
        .unwrap();
}

/// No stale write when the worktree changed under a reawakened builder: a
/// drifted file is NOT reacquired and its §3c read record is dropped, so a
/// write is refused until the builder re-reads (`readlock`) it.
#[test]
fn write_capable_followup_forces_reread_on_drift() {
    let (driver, tmp) = test_driver(8);
    let p = tmp.path().join("a.rs");
    std::fs::write(&p, "v1").unwrap();
    let sid = driver.session.id;
    driver.locks.acquire(&p, "builder", sid).unwrap();
    driver.locks.suspend_agent("builder", sid).unwrap();
    // The user / another agent edits the file while the builder was finished.
    std::fs::write(&p, "v2-drift").unwrap();
    let reacquired = driver.locks.resume_agent("builder", sid).unwrap();
    assert!(reacquired.is_empty(), "drifted file must not reacquire");
    assert!(driver.locks.holder(&p).is_none());
    // Write is refused (the read record was invalidated) — no stale write.
    assert!(
        driver
            .locks
            .check_write_permitted(&p, "builder", sid)
            .is_err()
    );
    // After an explicit re-read the write is permitted again.
    driver.locks.note_read(&p, "builder", sid);
    driver
        .locks
        .check_write_permitted(&p, "builder", sid)
        .unwrap();
}

/// Lock re-acquire failure because another writer now holds the path is
/// surfaced (the builder simply doesn't hold it) and the follow-up does NOT
/// force-write — single-writer is preserved, the other writer keeps the
/// lock.
#[test]
fn write_capable_followup_defers_to_other_lock_holder() {
    let (driver, tmp) = test_driver(8);
    let p = tmp.path().join("a.rs");
    std::fs::write(&p, "v1").unwrap();
    let sid = driver.session.id;
    // A second session/agent grabs the path while the builder is finished.
    let other = driver
        .session
        .db
        .create_session("p", "/x", "builder")
        .unwrap();
    driver.locks.acquire(&p, "builder", sid).unwrap();
    driver.locks.suspend_agent("builder", sid).unwrap();
    driver
        .locks
        .acquire(&p, "builder", other.session_id)
        .unwrap();
    // Follow-up resume can't reacquire — the other holder wins.
    let reacquired = driver.locks.resume_agent("builder", sid).unwrap();
    assert!(reacquired.is_empty());
    assert_eq!(
        driver.locks.holder(&p).map(|(s, _)| s),
        Some(other.session_id)
    );
    // The reawakened builder cannot write the path (no force-write).
    assert!(
        driver
            .locks
            .check_write_permitted(&p, "builder", sid)
            .is_err()
    );
}

/// The cache-aware reuse decision is driven by the session's active cache
/// config + time-since-last-send. The test driver's provider declares no
/// cache, so a follow-up takes the no-cache-reuse path deterministically.
#[test]
fn followup_reuse_decision_no_cache_provider() {
    let (driver, _t) = test_driver(8);
    assert_eq!(
        driver.followup_reuse_decision(),
        crate::engine::prune::FollowupReuse::NoCacheReuse
    );
}

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
        partial_progress: DelegationPartialProgress::default(),
        seeds: Vec::new(),
        new_handle: None,
        snapshot: NoninteractiveDelegationSnapshot::empty(),
        shrink: None,
        repair_notes: Vec::new(),
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

#[tokio::test]
async fn pending_noninteractive_completion_routes_by_task_call_id() {
    let (mut driver, _tmp) = test_driver(8);
    let tx = driver.noninteractive_complete_tx.clone();
    tx.send(BackgroundNoninteractiveCompletion::Single {
        task_call_id: "task-a".to_string(),
        task_function_call_id: Some("fn-task-a".to_string()),
        result: Box::new(Ok(single_noninteractive_completion("task-a", "a done"))),
    })
    .await
    .unwrap();
    tx.send(BackgroundNoninteractiveCompletion::Single {
        task_call_id: "task-b".to_string(),
        task_function_call_id: Some("fn-task-b".to_string()),
        result: Box::new(Ok(single_noninteractive_completion("task-b", "b done"))),
    })
    .await
    .unwrap();

    let completion = driver
        .recv_noninteractive_completion_for("task-b")
        .await
        .expect("task-b completion");
    assert_eq!(completion.task_call_id(), "task-b");
    assert_eq!(driver.pending_noninteractive_completions.len(), 1);
    assert_eq!(
        driver.pending_noninteractive_completions[0].task_call_id(),
        "task-a"
    );

    let completion = driver
        .recv_noninteractive_completion_for("task-a")
        .await
        .expect("task-a completion");
    assert_eq!(completion.task_call_id(), "task-a");
    assert!(driver.pending_noninteractive_completions.is_empty());
}

#[tokio::test]
async fn delivered_finished_noninteractive_job_is_reaped() {
    let (mut driver, _tmp) = test_driver(8);
    driver.noninteractive_jobs.insert(
        "task-reap".to_string(),
        BackgroundNoninteractiveJob {
            delivered: true,
            handle: tokio::spawn(async {}),
        },
    );
    tokio::task::yield_now().await;

    driver.reap_finished_noninteractive_jobs();

    assert!(!driver.noninteractive_jobs.contains_key("task-reap"));
}

#[tokio::test]
async fn whole_job_cancel_releases_aborted_child_locks() {
    let (mut driver, tmp) = test_driver(8);
    let path = tmp.path().join("held.rs");
    std::fs::write(&path, "fn main() {}\n").unwrap();
    seed_task_delegation(&driver, "task-lock", "default");
    driver.noninteractive_delegations.register_running(
        "task-lock",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    driver
        .locks
        .acquire(&path, "explore", driver.session.id)
        .unwrap();
    driver.noninteractive_jobs.insert(
        "task-lock".to_string(),
        BackgroundNoninteractiveJob {
            delivered: false,
            handle: tokio::spawn(async {
                std::future::pending::<()>().await;
            }),
        },
    );

    let body = driver.dispatch_task_control(
        TaskControlAction::Cancel,
        Some("task-lock".to_string()),
        None,
        None,
    );

    assert!(body.contains("cancelled"), "{body}");
    assert!(driver.locks.holder(&path).is_none());
    assert!(!driver.noninteractive_jobs.contains_key("task-lock"));
}

#[tokio::test]
async fn inline_background_completion_error_keeps_original_task_pairing() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    let delivery = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Single {
                task_call_id: "task-inline".to_string(),
                task_function_call_id: Some("fn-inline".to_string()),
                result: Box::new(Err(anyhow::anyhow!("child crashed"))),
            }),
            &tx,
        )
        .await
        .unwrap();

    let NoninteractiveCompletionDelivery::Inline(message) = delivery else {
        panic!("inline error should satisfy the open task tool call");
    };
    assert_eq!(tool_result_id(&message), "task-inline");
    assert_eq!(
        tool_result_provider_call_id(&message).as_deref(),
        Some("fn-inline")
    );
    assert!(tool_result_text(&message).contains("child crashed"));
}

#[tokio::test]
async fn backgrounded_completion_error_becomes_async_failed_result_once() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-bg-error", "default");
    driver
        .session
        .db
        .background_task_delegation_child("task-bg-error", "default")
        .unwrap();
    driver.noninteractive_delegations.register_running(
        "task-bg-error",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    driver
        .noninteractive_delegations
        .background_on_user_input("task-bg-error", "default");
    driver.noninteractive_jobs.insert(
        "task-bg-error".to_string(),
        BackgroundNoninteractiveJob {
            delivered: false,
            handle: tokio::spawn(async {}),
        },
    );
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    let delivery = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Single {
                task_call_id: "task-bg-error".to_string(),
                task_function_call_id: Some("fn-bg-error".to_string()),
                result: Box::new(Err(anyhow::anyhow!("late child crashed"))),
            }),
            &tx,
        )
        .await
        .unwrap();

    let NoninteractiveCompletionDelivery::AsyncUser(text) = delivery else {
        panic!("backgrounded error should be delivered as async user input");
    };
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["type"], "task_delegation");
    assert_eq!(json["version"], 1);
    assert_eq!(json["state"], "failed");
    assert_eq!(json["task_call_id"], "task-bg-error");
    assert_eq!(json["children"][0]["label"], "default");
    assert_eq!(json["children"][0]["status"], "failed");
    assert_eq!(json["children"][0]["error"], "Error: late child crashed");

    let duplicate = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Single {
                task_call_id: "task-bg-error".to_string(),
                task_function_call_id: Some("fn-bg-error".to_string()),
                result: Box::new(Err(anyhow::anyhow!("late child crashed again"))),
            }),
            &tx,
        )
        .await
        .unwrap();
    assert!(matches!(duplicate, NoninteractiveCompletionDelivery::None));
}

#[tokio::test]
async fn backgrounded_batch_completion_delivers_one_mixed_status_payload() {
    let (mut driver, _tmp) = test_driver(8);
    seed_batch_task_delegation(&driver, "task-mixed", &["first", "second", "third"]);
    for label in ["first", "second", "third"] {
        driver
            .session
            .db
            .background_task_delegation_child("task-mixed", label)
            .unwrap();
        driver.noninteractive_delegations.register_running(
            "task-mixed",
            label,
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        driver
            .noninteractive_delegations
            .background_on_user_input("task-mixed", label);
    }
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    let delivery = driver
        .finalize_background_noninteractive_completion(
            Some(BackgroundNoninteractiveCompletion::Batch {
                task_call_id: "task-mixed".to_string(),
                task_function_call_id: Some("fn-mixed".to_string()),
                result: Box::new(Ok(BatchNoninteractiveCompletion {
                    task_call_id: "task-mixed".to_string(),
                    task_function_call_id: Some("fn-mixed".to_string()),
                    children: vec![
                        BatchChildCompletion {
                            idx: 0,
                            label: "first".to_string(),
                            child_agent: "explore".to_string(),
                            report: "first report".to_string(),
                            failed: false,
                            partial_progress: DelegationPartialProgress::default(),
                            snapshot: NoninteractiveDelegationSnapshot::empty(),
                        },
                        BatchChildCompletion {
                            idx: 1,
                            label: "second".to_string(),
                            child_agent: "explore".to_string(),
                            report: "second failed".to_string(),
                            failed: true,
                            partial_progress: DelegationPartialProgress::default(),
                            snapshot: NoninteractiveDelegationSnapshot::empty(),
                        },
                        BatchChildCompletion {
                            idx: 2,
                            label: "third".to_string(),
                            child_agent: "explore".to_string(),
                            report: "third report".to_string(),
                            failed: false,
                            partial_progress: DelegationPartialProgress::default(),
                            snapshot: NoninteractiveDelegationSnapshot::empty(),
                        },
                    ],
                    repair_notes: Vec::new(),
                })),
            }),
            &tx,
        )
        .await
        .unwrap();

    let NoninteractiveCompletionDelivery::AsyncUser(text) = delivery else {
        panic!("backgrounded batch should be delivered as one async user input");
    };
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["type"], "task_delegation");
    assert_eq!(json["version"], 1);
    assert_eq!(json["state"], "failed");
    assert_eq!(json["task_call_id"], "task-mixed");
    let children = json["children"].as_array().unwrap();
    assert_eq!(children.len(), 3);
    assert_eq!(children[0]["label"], "first");
    assert_eq!(children[0]["status"], "completed");
    assert_eq!(children[0]["report"], "first report");
    assert_eq!(children[1]["label"], "second");
    assert_eq!(children[1]["status"], "failed");
    assert_eq!(children[1]["error"], "second failed");
    assert_eq!(children[2]["label"], "third");
    assert_eq!(children[2]["status"], "completed");
    assert_eq!(children[2]["report"], "third report");
}

#[tokio::test]
async fn background_single_completion_does_not_apply_stale_shrink() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-single", "default");
    driver
        .noninteractive_delegations
        .background_on_user_input("task-single", "default");
    let foreground_history = vec![
        Message::user("start delegated task"),
        assistant_with_task_call("task-single"),
        Message::user("foreground remains"),
    ];
    driver.stack.last_mut().unwrap().history = foreground_history.clone();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    let result = driver
        .finalize_single_noninteractive_task(
            SingleNoninteractiveCompletion {
                shrink: Some(cold_ready_test_shrink(vec![Message::user("stale shrink")])),
                ..single_noninteractive_completion("task-single", "single report")
            },
            &tx,
            false,
        )
        .await
        .unwrap();
    drop(tx);
    while rx.recv().await.is_some() {}

    assert_eq!(tool_result_id(&result), "task-single");
    assert_eq!(tool_result_text(&result), "single report");
    assert_eq!(driver.stack.last().unwrap().history, foreground_history);
}

#[test]
fn subagent_report_event_data_preserves_body_for_all_writer_shapes() {
    for (child_agent, task_call_id, function_call_id, label, report, expected_source) in [
        (
            "explore",
            Some("task-single"),
            Some("fn-single"),
            "default",
            "single report",
            Some("provider"),
        ),
        (
            "reviewer",
            Some("task-batch"),
            Some("fn-batch"),
            "second",
            "batch report",
            Some("provider"),
        ),
        (
            "builder",
            Some("task-interactive"),
            Some("fn-interactive"),
            "default",
            "interactive report",
            Some("provider"),
        ),
        (
            "builder",
            Some("task-abort"),
            Some("fn-abort"),
            "default",
            "Error: cancelled by user",
            Some("provider"),
        ),
        (
            "builder",
            Some("task-synthetic"),
            None,
            "default",
            "Error: failed without provider identity",
            Some("synthetic_from_cockpit_call_id"),
        ),
        ("builder", None, None, "default", "detached report", None),
    ] {
        let data = subagent_report_event_data(
            child_agent,
            task_call_id,
            function_call_id,
            label,
            report,
            None,
        );
        assert_eq!(data["child_agent"], child_agent);
        assert_eq!(data["task_call_id"], serde_json::json!(task_call_id));
        assert_eq!(data["label"], label);
        assert_eq!(data["report"], report);
        match (task_call_id, function_call_id, expected_source) {
            (Some(task_call_id), Some(function_call_id), Some("provider")) => {
                assert_eq!(data["provider_call_id"], function_call_id);
                assert_eq!(data["provider_call_id_source"], "provider");
                assert_eq!(data["provider_identity"]["cockpit_call_id"], task_call_id);
                assert_eq!(
                    data["provider_identity"]["provider_call_id"],
                    function_call_id
                );
            }
            (Some(task_call_id), None, Some("synthetic_from_cockpit_call_id")) => {
                assert_eq!(data["provider_call_id"], task_call_id);
                assert_eq!(
                    data["provider_call_id_source"],
                    "synthetic_from_cockpit_call_id"
                );
                assert_eq!(data["provider_identity"]["provider_call_id"], task_call_id);
            }
            (None, None, None) => {
                assert!(data["provider_call_id"].is_null());
                assert!(data["provider_call_id_source"].is_null());
                assert!(data["provider_identity"].is_null());
            }
            other => panic!("uncovered test shape: {other:?}"),
        }
    }
}

#[test]
fn subagent_report_event_data_includes_partial_progress_when_present() {
    let progress = partial_progress_from_history(&[
        write_turn("w1", "/src/a.rs"),
        Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
    ]);
    let report = render_failed_subagent_report("Error: turn limit", &progress);

    let data = subagent_report_event_data(
        "builder",
        Some("task-single"),
        Some("fn-single"),
        "default",
        &report,
        Some(&progress),
    );

    assert_eq!(data["report"], report);
    assert_eq!(
        data["partial_progress"]["files_edited"][0]["path"],
        "/src/a.rs"
    );
    assert_eq!(
        data["partial_progress"]["verification_state"],
        "not_completed"
    );
    assert_eq!(data["partial_progress"]["review_state"], "needs_review");
    assert_eq!(
        data["partial_progress"]["dirty_owned_changes"][0],
        "/src/a.rs"
    );
}

#[tokio::test]
async fn noninteractive_single_inline_result_shape_is_unchanged() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_single_noninteractive_task(
            SingleNoninteractiveCompletion {
                child_agent: "explore".to_string(),
                task_call_id: "task-single".to_string(),
                task_function_call_id: Some("fn-single".to_string()),
                report: "single report".to_string(),
                failed: false,
                partial_progress: DelegationPartialProgress::default(),
                seeds: Vec::new(),
                new_handle: None,
                snapshot: NoninteractiveDelegationSnapshot::empty(),
                shrink: None,
                repair_notes: Vec::new(),
            },
            &tx,
            true,
        )
        .await
        .unwrap();
    drop(tx);
    while rx.recv().await.is_some() {}

    assert_eq!(tool_result_id(&result), "task-single");
    assert_eq!(tool_result_text(&result), "single report");
}

#[tokio::test]
async fn noninteractive_single_report_body_matches_live_event_db_event_row_and_result() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-single", "default");
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_single_noninteractive_task(
            SingleNoninteractiveCompletion {
                child_agent: "explore".to_string(),
                task_call_id: "task-single".to_string(),
                task_function_call_id: Some("fn-single".to_string()),
                report: "single report".to_string(),
                failed: false,
                partial_progress: DelegationPartialProgress::default(),
                seeds: Vec::new(),
                new_handle: None,
                snapshot: NoninteractiveDelegationSnapshot::empty(),
                shrink: Some(pending_test_shrink()),
                repair_notes: Vec::new(),
            },
            &tx,
            true,
        )
        .await
        .unwrap();
    drop(tx);

    let mut live_report = None;
    while let Some(event) = rx.recv().await {
        if let TurnEvent::SubagentReport {
            agent,
            task_call_id,
            label,
            report,
            ..
        } = event
        {
            live_report = Some((agent, task_call_id, label, report));
        }
    }
    let (agent, task_call_id, label, report) = live_report.expect("live subagent report event");
    assert_eq!(agent, "explore");
    assert_eq!(task_call_id, "task-single");
    assert_eq!(label, "default");
    assert_eq!(report, "single report");

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .unwrap();
    let event = events
        .iter()
        .find(|event| {
            event.kind == "subagent_report" && event.call_id.as_deref() == Some("task-single")
        })
        .expect("durable subagent_report event");
    assert_eq!(event.data["child_agent"], "explore");
    assert_eq!(event.data["task_call_id"], "task-single");
    assert_eq!(event.data["label"], "default");
    assert_eq!(event.data["report"], "single report");
    assert_eq!(event.data["provider_call_id"], "fn-single");
    assert_eq!(event.data["provider_call_id_source"], "provider");
    assert_eq!(
        event.data["provider_identity"]["provider_call_id"],
        "fn-single"
    );

    let row = driver
        .session
        .db
        .list_task_delegation_children(driver.session.id)
        .unwrap()
        .into_iter()
        .find(|row| row.task_call_id == "task-single" && row.label == "default")
        .expect("completed task delegation child row");
    assert_eq!(row.child_agent, "explore");
    assert_eq!(row.report.as_deref(), Some("single report"));

    assert_eq!(tool_result_id(&result), "task-single");
    assert_eq!(tool_result_text(&result), "single report");
}

#[tokio::test]
async fn noninteractive_single_result_includes_task_repair_notes() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_single_noninteractive_task(
            SingleNoninteractiveCompletion {
                child_agent: "explore".to_string(),
                task_call_id: "task-single".to_string(),
                task_function_call_id: Some("fn-single".to_string()),
                report: "single report".to_string(),
                failed: false,
                partial_progress: DelegationPartialProgress::default(),
                seeds: Vec::new(),
                new_handle: None,
                snapshot: NoninteractiveDelegationSnapshot::empty(),
                shrink: None,
                repair_notes: vec![
                    "dropped `action` (incompatible with fresh delegation) — treating as fresh spawn of `agent=explore`"
                        .to_string(),
                ],
            },
            &tx,
            true,
        )
        .await
        .unwrap();
    drop(tx);
    while rx.recv().await.is_some() {}

    let text = tool_result_text(&result);
    assert!(text.starts_with("dropped `action`"), "{text}");
    assert!(text.contains("\n\nsingle report"), "{text}");
}

#[tokio::test]
async fn noninteractive_batch_inline_result_shape_is_unchanged() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_batch_noninteractive_task(
            BatchNoninteractiveCompletion {
                task_call_id: "task-batch".to_string(),
                task_function_call_id: Some("fn-batch".to_string()),
                children: vec![
                    BatchChildCompletion {
                        idx: 1,
                        label: "second".to_string(),
                        child_agent: "reviewer".to_string(),
                        report: "second report".to_string(),
                        failed: false,
                        partial_progress: DelegationPartialProgress::default(),
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                    },
                    BatchChildCompletion {
                        idx: 0,
                        label: "first".to_string(),
                        child_agent: "explore".to_string(),
                        report: "Error: first issue was fixed".to_string(),
                        failed: false,
                        partial_progress: DelegationPartialProgress::default(),
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                    },
                ],
                repair_notes: Vec::new(),
            },
            &tx,
        )
        .await;
    drop(tx);
    while rx.recv().await.is_some() {}

    assert_eq!(tool_result_id(&result), "task-batch");
    let body: serde_json::Value = serde_json::from_str(&tool_result_text(&result)).unwrap();
    assert_eq!(body["status"], "completed");
    let children = body["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0]["label"], "first");
    assert_eq!(children[0]["agent"], "explore");
    assert_eq!(children[0]["failed"], false);
    assert_eq!(children[0]["report"], "Error: first issue was fixed");
    assert_eq!(children[1]["label"], "second");
    assert_eq!(children[1]["agent"], "reviewer");
    assert_eq!(children[1]["failed"], false);
    assert_eq!(children[1]["report"], "second report");
}

#[tokio::test]
async fn noninteractive_batch_result_includes_task_repair_notes() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let result = driver
        .finalize_batch_noninteractive_task(
            BatchNoninteractiveCompletion {
                task_call_id: "task-batch".to_string(),
                task_function_call_id: Some("fn-batch".to_string()),
                children: vec![BatchChildCompletion {
                    idx: 0,
                    label: "first".to_string(),
                    child_agent: "explore".to_string(),
                    report: "first report".to_string(),
                    failed: false,
                    partial_progress: DelegationPartialProgress::default(),
                    snapshot: NoninteractiveDelegationSnapshot::empty(),
                }],
                repair_notes: vec![
                    "dropped `action` (incompatible with fresh delegation) — treating as fresh spawn of `agent=explore`"
                        .to_string(),
                ],
            },
            &tx,
        )
        .await;
    drop(tx);
    while rx.recv().await.is_some() {}

    let body: serde_json::Value = serde_json::from_str(&tool_result_text(&result)).unwrap();
    assert_eq!(
        body["repair_notes"][0],
        "dropped `action` (incompatible with fresh delegation) — treating as fresh spawn of `agent=explore`"
    );
}

#[test]
fn queued_user_input_backgrounds_running_single_delegation() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    registry.register_running(
        "task-single",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::from_history(vec![Message::user("parent snapshot")]),
    );

    assert!(registry.background_on_user_input("task-single", "default"));
    assert_eq!(
        registry.status("task-single", "default"),
        Some(NoninteractiveDelegationStatus::Backgrounded)
    );
    assert_eq!(
        registry.child_agent("task-single", "default"),
        Some("explore")
    );
    assert_eq!(registry.snapshot_len("task-single", "default"), Some(1));
    assert!(
        !registry.background_on_user_input("task-single", "default"),
        "a backgrounded delegation is not backgrounded twice"
    );
}

#[test]
fn queued_user_input_backgrounds_running_batch_delegation() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    registry.register_running(
        "task-batch",
        "first",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::from_history(vec![Message::user("parent snapshot")]),
    );

    assert!(registry.background_on_user_input("task-batch", "first"));
    assert_eq!(
        registry.status("task-batch", "first"),
        Some(NoninteractiveDelegationStatus::Backgrounded)
    );
    assert_eq!(registry.child_agent("task-batch", "first"), Some("explore"));
}

#[test]
fn noninteractive_registry_is_live_only_for_running_and_backgrounded() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    assert!(!registry.is_live("task-1", "default"));
    registry.register_running(
        "task-1",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    assert!(registry.is_live("task-1", "default"));
    assert!(registry.background_on_user_input("task-1", "default"));
    assert!(registry.is_live("task-1", "default"));
    assert!(registry.cancel("task-1", "default"));
    assert!(!registry.is_live("task-1", "default"));

    registry.register_running(
        "task-2",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    assert!(registry.complete("task-2", "default", "done".to_string(), false, None));
    assert!(!registry.is_live("task-2", "default"));
}

#[test]
fn noninteractive_registry_completion_status_uses_host_flag() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    registry.register_running(
        "task-1",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );

    assert!(registry.complete(
        "task-1",
        "default",
        "Error: quoted issue was fixed".to_string(),
        false,
        None,
    ));
    assert_eq!(
        registry.status("task-1", "default"),
        Some(NoninteractiveDelegationStatus::Completed)
    );

    registry.register_running(
        "task-2",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    assert!(registry.complete(
        "task-2",
        "default",
        "ordinary report".to_string(),
        true,
        None
    ));
    assert_eq!(
        registry.status("task-2", "default"),
        Some(NoninteractiveDelegationStatus::Failed)
    );
}

#[test]
fn host_failure_sentinel_matches_only_host_error_shape() {
    assert!(is_host_failure_sentinel("Error: boom"));
    assert!(is_host_failure_sentinel("  Error: leading ws"));
    assert!(!is_host_failure_sentinel("Error:nospace"));
    assert!(!is_host_failure_sentinel("## Accomplished\nError: quoted"));
}

#[test]
fn task_control_orphan_list_status_cancel_and_refuse_live_actions() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-orphan", "default");

    let list = driver.dispatch_task_control(TaskControlAction::List, None, None, None);
    let list_json: serde_json::Value = serde_json::from_str(&list).unwrap();
    assert_eq!(list_json["type"], "task_delegation");
    assert_eq!(list_json["version"], 1);
    assert_eq!(list_json["state"], "list");
    assert_eq!(list_json["children"][0]["status"], "lost");
    assert_eq!(list_json["children"][0]["blocking"], false);
    assert_eq!(list_json["children"][0]["tool_call_closed"], false);
    assert_eq!(list_json["children"][0]["result_pending"], true);
    assert_eq!(list_json["children"][0]["report_available"], false);
    assert_eq!(list_json["children"][0]["report_delivered"], false);
    assert_eq!(list_json["children"][0]["pending_steers"], 0);
    assert_eq!(list_json["children"][0]["orphaned"], true);
    assert_eq!(list_json["children"][0]["actionable"], false);

    let status = driver.dispatch_task_control(
        TaskControlAction::Status,
        Some("task-orphan".to_string()),
        Some("default".to_string()),
        None,
    );
    let status_json: serde_json::Value = serde_json::from_str(&status).unwrap();
    assert_eq!(status_json["state"], "status");
    assert_eq!(status_json["children"][0]["status"], "lost");
    assert_eq!(status_json["children"][0]["orphaned"], true);

    let query = driver.dispatch_task_control(
        TaskControlAction::Query,
        Some("task-orphan".to_string()),
        Some("default".to_string()),
        None,
    );
    let query_json: serde_json::Value = serde_json::from_str(&query).unwrap();
    assert_eq!(query_json["state"], "refused");
    assert_eq!(query_json["actionable"], false);
    assert_eq!(
        query_json["reason"],
        "lost (daemon restarted; no live worker)"
    );
    assert_eq!(query_json["report_source"], "none");
    assert_eq!(query_json["children"][0]["status"], "lost");

    let steer = driver.dispatch_task_control(
        TaskControlAction::Steer,
        Some("task-orphan".to_string()),
        Some("default".to_string()),
        Some("please continue".to_string()),
    );
    let steer_json: serde_json::Value = serde_json::from_str(&steer).unwrap();
    assert_eq!(steer_json["state"], "refused");
    assert_eq!(steer_json["actionable"], false);
    assert_eq!(
        steer_json["reason"],
        "lost (daemon restarted; no live worker)"
    );
    assert_eq!(steer_json["children"][0]["status"], "lost");

    let cancel = driver.dispatch_task_control(
        TaskControlAction::Cancel,
        Some("task-orphan".to_string()),
        Some("default".to_string()),
        None,
    );
    let cancel_json: serde_json::Value = serde_json::from_str(&cancel).unwrap();
    assert_eq!(cancel_json["state"], "lost");
    assert_eq!(cancel_json["cancelled"].as_array().unwrap().len(), 0);
    assert_eq!(cancel_json["orphaned_lost"][0], "task-orphan:default");
    let rows = driver
        .session
        .db
        .list_task_delegation_children(driver.session.id)
        .unwrap();
    assert_eq!(
        rows[0].status,
        crate::db::task_delegations::DelegationStatus::Lost
    );
}

#[test]
fn task_control_live_registry_entry_keeps_happy_path() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-live", "default");
    driver.noninteractive_delegations.register_running(
        "task-live",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::from_history(vec![Message::user("live context")]),
    );

    let list = driver.dispatch_task_control(TaskControlAction::List, None, None, None);
    let list_json: serde_json::Value = serde_json::from_str(&list).unwrap();
    assert_eq!(list_json["state"], "list");
    assert_eq!(list_json["children"][0]["status"], "running");
    assert_eq!(list_json["children"][0]["blocking"], true);
    assert_eq!(list_json["children"][0]["tool_call_closed"], false);
    assert_eq!(list_json["children"][0]["result_pending"], false);
    assert_eq!(list_json["children"][0]["report_available"], false);
    assert_eq!(list_json["children"][0]["report_delivered"], false);
    assert_eq!(list_json["children"][0]["pending_steers"], 0);
    assert_eq!(list_json["children"][0]["orphaned"], false);
    assert_eq!(list_json["children"][0]["actionable"], true);

    let query = driver.dispatch_task_control(
        TaskControlAction::Query,
        Some("task-live".to_string()),
        Some("default".to_string()),
        None,
    );
    let query_json: serde_json::Value = serde_json::from_str(&query).unwrap();
    assert_eq!(query_json["state"], "query");
    assert_eq!(query_json["task_call_id"], "task-live");
    assert_eq!(query_json["read_only"], true);
    assert_eq!(query_json["child_state_unchanged"], true);
    assert_eq!(query_json["report_source"], "live_snapshot");
    assert!(
        query_json["report"]
            .as_str()
            .unwrap()
            .contains("live context"),
        "{query_json}"
    );
    assert_eq!(query_json["children"][0]["status"], "running");

    let steer = driver.dispatch_task_control(
        TaskControlAction::Steer,
        Some("task-live".to_string()),
        Some("default".to_string()),
        Some("keep going".to_string()),
    );
    let steer_json: serde_json::Value = serde_json::from_str(&steer).unwrap();
    assert_eq!(steer_json["state"], "steer_queued");
    assert_eq!(steer_json["applies_at"], "next_child_turn_boundary");
    assert_eq!(steer_json["applies_if"], "child_still_running_actionable");
    assert_eq!(steer_json["children"][0]["pending_steers"], 1);

    let cancel = driver.dispatch_task_control(
        TaskControlAction::Cancel,
        Some("task-live".to_string()),
        Some("default".to_string()),
        None,
    );
    let cancel_json: serde_json::Value = serde_json::from_str(&cancel).unwrap();
    assert_eq!(cancel_json["state"], "cancelled");
    assert_eq!(cancel_json["cancelled"][0], "task-live:default");
    let rows = driver
        .session
        .db
        .list_task_delegation_children(driver.session.id)
        .unwrap();
    assert_eq!(
        rows[0].status,
        crate::db::task_delegations::DelegationStatus::Cancelled
    );
}

#[test]
fn task_query_reports_db_and_none_sources() {
    let (mut driver, _tmp) = test_driver(8);
    seed_task_delegation(&driver, "task-db", "default");
    driver
        .session
        .db
        .write_blocking(move |conn| {
            conn.execute(
                "UPDATE task_delegation_children SET report = 'db report' WHERE task_call_id = 'task-db' AND label = 'default'",
                [],
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .unwrap();
    driver.noninteractive_delegations.register_running(
        "task-db",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::from_history(vec![Message::user("live fallback")]),
    );

    let db_query = driver.dispatch_task_control(
        TaskControlAction::Query,
        Some("task-db".to_string()),
        Some("default".to_string()),
        None,
    );
    let db_json: serde_json::Value = serde_json::from_str(&db_query).unwrap();
    assert_eq!(db_json["state"], "query");
    assert_eq!(db_json["report_source"], "db");
    assert_eq!(db_json["report"], "db report");
    assert_eq!(db_json["report_available"], true);

    seed_task_delegation(&driver, "task-none", "default");
    driver.noninteractive_delegations.register_running(
        "task-none",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    let none_query = driver.dispatch_task_control(
        TaskControlAction::Query,
        Some("task-none".to_string()),
        Some("default".to_string()),
        None,
    );
    let none_json: serde_json::Value = serde_json::from_str(&none_query).unwrap();
    assert_eq!(none_json["state"], "query");
    assert_eq!(none_json["report_source"], "none");
    assert_eq!(none_json["report_available"], false);
    assert!(
        none_json["report"]
            .as_str()
            .unwrap()
            .contains("No report yet")
    );
}

#[test]
fn late_noninteractive_completion_delivers_once() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    registry.register_running(
        "task-1",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );
    assert!(registry.background_on_user_input("task-1", "default"));

    let result = Message::tool_result_with_call_id("task-1".to_string(), None, "done".to_string());
    assert!(registry.complete("task-1", "default", "done".to_string(), false, Some(result)));
    assert!(
        !registry.complete(
            "task-1",
            "default",
            "duplicate".to_string(),
            false,
            Some(Message::tool_result_with_call_id(
                "task-1".to_string(),
                None,
                "duplicate".to_string(),
            ))
        ),
        "completion is accepted exactly once"
    );

    let delivered = registry
        .take_late_result("task-1", "default")
        .expect("first late result");
    assert_eq!(tool_result_text(&delivered), "done");
    assert!(
        registry.take_late_result("task-1", "default").is_none(),
        "late result is delivered exactly once"
    );
}

#[test]
fn background_ack_is_small_deterministic_and_omits_original_prompt() {
    let completed = vec![("first".to_string(), "first report".to_string())];
    let running = vec!["second".to_string()];
    let body = format_delegation_background_ack("task-batch", &completed, &running);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(json["type"], "task_delegation");
    assert_eq!(json["version"], 1);
    assert_eq!(json["state"], "backgrounded");
    assert_eq!(json["task_call_id"], "task-batch");
    assert_eq!(json["blocking"], false);
    assert_eq!(json["tool_call_closed"], true);
    assert_eq!(json["result_pending"], true);
    let children = json["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0]["task_call_id"], "task-batch");
    assert_eq!(children[0]["label"], "first");
    assert_eq!(children[0]["status"], "completed");
    assert_eq!(children[0]["newly_delivered"], true);
    assert_eq!(children[0]["report"], "first report");
    assert_eq!(children[1]["task_call_id"], "task-batch");
    assert_eq!(children[1]["label"], "second");
    assert_eq!(children[1]["status"], "backgrounded");
    assert_eq!(children[1]["result_pending"], true);
    assert!(!body.contains("original child prompt"));
}

#[test]
fn async_delegation_result_lists_only_new_children_with_status() {
    let completed = vec![
        AsyncDelegationChildResult {
            label: "second".to_string(),
            status: "completed".to_string(),
            report: Some("second report".to_string()),
        },
        AsyncDelegationChildResult {
            label: "third".to_string(),
            status: "failed".to_string(),
            report: Some("third failed".to_string()),
        },
    ];
    let running = Vec::new();
    let body = format_async_delegation_result("task-batch", &completed, &running);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert_eq!(json["type"], "task_delegation");
    assert_eq!(json["version"], 1);
    assert_eq!(json["state"], "failed");
    assert_eq!(json["task_call_id"], "task-batch");
    assert_eq!(json["result_pending"], false);
    let children = json["children"].as_array().unwrap();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0]["task_call_id"], "task-batch");
    assert_eq!(children[0]["label"], "second");
    assert_eq!(children[0]["status"], "completed");
    assert_eq!(children[0]["newly_delivered"], true);
    assert_eq!(children[0]["report"], "second report");
    assert_eq!(children[1]["task_call_id"], "task-batch");
    assert_eq!(children[1]["label"], "third");
    assert_eq!(children[1]["status"], "failed");
    assert_eq!(children[1]["error"], "third failed");
    assert!(!body.contains("first report"));
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

#[test]
fn steer_queue_drains_fifo_at_child_turn_boundary() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    registry.register_running(
        "task-1",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );

    registry.push_steer("task-1", "default", "first".to_string());
    registry.push_steer("task-1", "default", "second".to_string());
    registry.push_steer("task-1", "default", "third".to_string());
    let drained: Vec<_> = registry
        .drain_steer_queue("task-1", "default")
        .into_iter()
        .map(|steer| steer.body)
        .collect();
    assert_eq!(
        drained,
        vec![
            "first".to_string(),
            "second".to_string(),
            "third".to_string()
        ]
    );
    assert!(
        registry.drain_steer_queue("task-1", "default").is_empty(),
        "turn-boundary drain consumes queued steers"
    );
}

/// Seeds re-execute in the caller's cwd and land as native tool-call/
/// result pairs folded into the task turn; oversized seeds are dropped
/// under the budget and truncation is reported.
#[tokio::test]
async fn inject_seeds_caps_under_budget_and_injects_pairs() {
    let (mut driver, tmp) = driver_with_read_caller();
    // A small file (fits) followed by several sizeable ones. Each
    // sizeable file is ~1.5K tokens of distinct lines; the shared 2K-token
    // seed budget admits the small one, then trips before all the big ones
    // fit — so at least one whole seed is dropped, deterministically.
    let small = tmp.path().join("small.txt");
    std::fs::write(&small, "hello\n").unwrap();
    let mut big_paths = Vec::new();
    for i in 0..3 {
        let p = tmp.path().join(format!("big{i}.txt"));
        // ~600 short, distinct lines → comfortably above ~1K tokens each.
        let body: String = (0..600).map(|n| format!("file{i} line {n}\n")).collect();
        std::fs::write(&p, body).unwrap();
        big_paths.push(p);
    }

    // The caller's last turn is the `task` call the delegation came from.
    let task_call_id = "task-1";
    driver.stack[0].history = vec![
        Message::user("please investigate"),
        assistant_with_task_call(task_call_id),
    ];

    let mut seeds = vec![SeedTool {
        tool: "read".into(),
        args: serde_json::json!({ "path": small.to_string_lossy() }),
    }];
    for p in &big_paths {
        seeds.push(SeedTool {
            tool: "read".into(),
            args: serde_json::json!({ "path": p.to_string_lossy() }),
        });
    }

    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let truncated = driver.inject_seeds(&seeds, task_call_id, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}

    // The cumulative seed output blew the 2K budget → truncation reported,
    // at least one whole seed dropped.
    assert!(truncated, "oversized seeds should trip the budget");

    let history = &driver.stack[0].history;
    // The task turn now carries the original task call PLUS exactly one
    // seed tool call (the small read); the big one was dropped whole.
    let last_assistant = history
        .iter()
        .rev()
        .find_map(|m| match m {
            Message::Assistant { content, .. } => Some(content),
            _ => None,
        })
        .unwrap();
    use crate::engine::message::AssistantContent;
    let tool_calls: Vec<_> = last_assistant
        .iter()
        .filter_map(|c| match c {
            AssistantContent::ToolCall(tc) => Some(tc.function.name.clone()),
            _ => None,
        })
        .collect();
    assert!(
        tool_calls.iter().any(|n| n == "task"),
        "task call preserved"
    );
    let seed_calls = tool_calls.iter().filter(|n| *n == "read").count();
    // At least the small seed fit, and at least one big seed was dropped
    // (so fewer than the 4 requested were folded in).
    assert!(seed_calls >= 1, "in-budget seeds folded in");
    assert!(seed_calls < seeds.len(), "an over-budget seed was dropped");
    let seed_call_ids: Vec<_> = last_assistant
        .iter()
        .filter_map(|c| match c {
            AssistantContent::ToolCall(tc) if tc.function.name == "read" => {
                Some((tc.id.clone(), tc.call_id.clone()))
            }
            _ => None,
        })
        .collect();
    for (id, call_id) in &seed_call_ids {
        assert!(id.starts_with("seed-"), "seed call id is tagged");
        assert_eq!(
            call_id.as_deref(),
            Some(id.as_str()),
            "seed ToolCall.call_id uses the Cockpit synthetic provider id"
        );
    }

    // Each folded seed call has exactly one matching tool_result pair.
    use rig::message::UserContent;
    let seed_results: Vec<_> = history
        .iter()
        .filter_map(|m| match m {
            Message::User { content } => Some(content),
            _ => None,
        })
        .flat_map(|content| content.iter())
        .filter_map(|c| match c {
            UserContent::ToolResult(result) if result.id.starts_with("seed-") => {
                Some((result.id.clone(), result.call_id.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        seed_results.len(),
        seed_calls,
        "one result pair per folded seed"
    );
    for (id, call_id) in &seed_results {
        assert_eq!(
            call_id.as_deref(),
            Some(id.as_str()),
            "seed ToolResult.call_id matches the synthetic provider id"
        );
    }

    // Each folded seed is also persisted as a tool-call audit row (GOALS
    // §14) so it survives in a session export, not just the live stream.
    // A seed is emitted verbatim → `wire == original`, no recovery.
    let rows = driver
        .session
        .db
        .list_tool_calls_for_session(driver.session.id)
        .unwrap();
    let seed_rows: Vec<_> = rows.iter().filter(|r| r.tool == "read").collect();
    assert_eq!(
        seed_rows.len(),
        seed_calls,
        "each folded seed has a persisted tool-call row"
    );
    for r in seed_rows {
        assert!(r.call_id.starts_with("seed-"), "seed row tagged as a seed");
        assert_eq!(r.provider_item_id.as_deref(), Some(r.call_id.as_str()));
        assert_eq!(r.provider_call_id.as_deref(), Some(r.call_id.as_str()));
        assert_eq!(
            r.provider_call_id_source.as_deref(),
            Some("synthetic_from_cockpit_call_id")
        );
        assert_eq!(r.wire_api.as_deref(), Some("responses"));
        assert_eq!(r.provider_family.as_deref(), Some("cockpit"));
        assert_eq!(
            r.wire_input_json, r.original_input_json,
            "a seed is verbatim: wire == original (GOALS §14)"
        );
        assert_eq!(r.recovery, crate::db::tool_calls::Recovery::Clean);
    }
}

/// A seed naming a tool the caller doesn't hold (or a non-read-only tool)
/// is skipped — `inject_seeds` never dispatches a write/unknown path.
#[tokio::test]
async fn inject_seeds_skips_tools_the_caller_lacks() {
    let (mut driver, _t) = driver_with_read_caller();
    let task_call_id = "task-1";
    driver.stack[0].history = vec![assistant_with_task_call(task_call_id)];
    // `outline` is read-only but the caller (read-only `read` toolbox)
    // doesn't hold it → skipped; nothing is folded in.
    let seeds = vec![SeedTool {
        tool: "outline".into(),
        args: serde_json::json!({ "path": "/x.rs" }),
    }];
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let _ = driver.inject_seeds(&seeds, task_call_id, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}
    // History unchanged: only the original task turn remains.
    assert_eq!(driver.stack[0].history.len(), 1);
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

/// Read-only pre-seeds re-execute in the CHILD's cwd and become a native
/// assistant-tool-call + matching tool_result prefix for the child's
/// initial history — supporting any read-only tool, not just `read`.
#[tokio::test]
async fn prefill_child_seeds_injects_native_pairs_in_child_cwd() {
    let (driver, tmp) = test_driver(8);
    let child = child_with_read_write_tools(&driver.stack[0].agent.clone());

    let child_dir = tmp.path().join("child-cwd");
    std::fs::create_dir(&child_dir).unwrap();
    let f = child_dir.join("hello.txt");
    std::fs::write(&f, "hello from the child cwd\n").unwrap();

    let seeds = vec![SeedTool {
        tool: "read".into(),
        args: serde_json::json!({ "path": "hello.txt" }),
    }];
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let (prefix, truncated) = driver
        .prefill_child_seeds(&seeds, &child, &child_dir, Some(&tx))
        .await;
    drop(tx);
    while rx.recv().await.is_some() {}

    assert!(!truncated, "one small seed fits the budget");
    // One assistant turn carrying the read call, then one tool_result.
    assert_eq!(prefix.len(), 2, "assistant call turn + tool_result");
    use crate::engine::message::AssistantContent;
    let calls: Vec<_> = match &prefix[0] {
        Message::Assistant { content, .. } => content
            .iter()
            .filter_map(|c| match c {
                AssistantContent::ToolCall(tc) => {
                    Some((tc.function.name.clone(), tc.id.clone(), tc.call_id.clone()))
                }
                _ => None,
            })
            .collect(),
        _ => panic!("first prefix message is an assistant turn"),
    };
    assert_eq!(calls.len(), 1, "the read seed became one native call");
    assert_eq!(calls[0].0, "read");
    assert_eq!(
        calls[0].2.as_deref(),
        Some(calls[0].1.as_str()),
        "prefill seed ToolCall.call_id uses the synthetic provider id"
    );
    use rig::message::{ToolResultContent, UserContent};
    match &prefix[1] {
        Message::User { content } => {
            let result = content
                .iter()
                .find_map(|c| match c {
                    UserContent::ToolResult(tr) => Some(tr),
                    _ => None,
                })
                .expect("prefill seed tool_result");
            assert_eq!(result.id, calls[0].1);
            assert_eq!(
                result.call_id.as_deref(),
                Some(calls[0].1.as_str()),
                "prefill seed ToolResult.call_id matches the synthetic provider id"
            );
            let got = result.content.iter().any(|rc| {
                matches!(
                    rc,
                    ToolResultContent::Text(t) if t.text.contains("hello from the child cwd")
                )
            });
            assert!(
                got,
                "the result carries the file body read in the child cwd"
            );
        }
        _ => panic!("second prefix message is the tool_result"),
    }
    let rows = driver
        .session
        .db
        .list_tool_calls_for_session(driver.session.id)
        .unwrap();
    let row = rows
        .iter()
        .find(|row| row.call_id == calls[0].1)
        .expect("prefill seed audit row");
    assert_eq!(row.provider_call_id.as_deref(), Some(row.call_id.as_str()));
    assert_eq!(
        row.provider_call_id_source.as_deref(),
        Some("synthetic_from_cockpit_call_id")
    );
}

/// A write/lock seed is never executed — the execution-time read-only gate
/// (same rule as `seed.rs`) drops it, so nothing is injected.
#[tokio::test]
async fn prefill_child_seeds_never_executes_a_write_seed() {
    let (driver, tmp) = test_driver(8);
    let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
    let target = tmp.path().join("must_not_exist.txt");
    // A write seed (even though the child holds `writeunlock`): rejected at
    // the read-only gate, never dispatched.
    let seeds = vec![SeedTool {
        tool: "writeunlock".into(),
        args: serde_json::json!({ "path": target.to_string_lossy(), "content": "x" }),
    }];
    let (prefix, _truncated) = driver
        .prefill_child_seeds(&seeds, &child, tmp.path(), None)
        .await;
    assert!(prefix.is_empty(), "a write seed injects nothing");
    assert!(!target.exists(), "a write seed is never executed");
}

/// A seed that fails to execute in the child's cwd (missing path) is
/// surfaced as a failed seed — its `Error:` body is injected as the
/// tool_result — not a hard abort of the delegation.
#[tokio::test]
async fn prefill_child_seeds_surfaces_a_failed_seed_without_aborting() {
    let (driver, tmp) = test_driver(8);
    let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
    let good = tmp.path().join("ok.txt");
    std::fs::write(&good, "fine\n").unwrap();
    let missing = tmp.path().join("nope.txt");
    let seeds = vec![
        SeedTool {
            tool: "read".into(),
            args: serde_json::json!({ "path": missing.to_string_lossy() }),
        },
        SeedTool {
            tool: "read".into(),
            args: serde_json::json!({ "path": good.to_string_lossy() }),
        },
    ];
    let (prefix, _truncated) = driver
        .prefill_child_seeds(&seeds, &child, tmp.path(), None)
        .await;
    // Both seeds are injected: the failed one carries an `Error:` body, the
    // good one carries its content — the run is not aborted.
    use crate::engine::message::AssistantContent;
    let n_calls = match &prefix[0] {
        Message::Assistant { content, .. } => content
            .iter()
            .filter(|c| matches!(c, AssistantContent::ToolCall(_)))
            .count(),
        _ => panic!("assistant turn expected"),
    };
    assert_eq!(n_calls, 2, "both seeds injected (failed + ok)");
    let bodies: String = prefix
        .iter()
        .skip(1)
        .filter_map(|m| match m {
            Message::User { content } => Some(
                content
                    .iter()
                    .filter_map(|c| match c {
                        rig::message::UserContent::ToolResult(tr) => Some(
                            tr.content
                                .iter()
                                .filter_map(|rc| match rc {
                                    rig::message::ToolResultContent::Text(t) => {
                                        Some(t.text.clone())
                                    }
                                    _ => None,
                                })
                                .collect::<String>(),
                        ),
                        _ => None,
                    })
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect();
    assert!(
        bodies.contains("Error:"),
        "failed seed surfaced as an error"
    );
    assert!(bodies.contains("fine"), "the good seed still executed");
}

/// Oversized pre-seeds are dropped whole under the budget and the
/// truncation flag is set so the caller appends a model-visible note.
#[tokio::test]
async fn prefill_child_seeds_caps_under_budget_and_drops_whole_entries() {
    let (driver, tmp) = test_driver(8);
    let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
    let small = tmp.path().join("small.txt");
    std::fs::write(&small, "tiny\n").unwrap();
    let mut seeds = vec![SeedTool {
        tool: "read".into(),
        args: serde_json::json!({ "path": small.to_string_lossy() }),
    }];
    for i in 0..3 {
        let p = tmp.path().join(format!("big{i}.txt"));
        let body: String = (0..600).map(|n| format!("file{i} line {n}\n")).collect();
        std::fs::write(&p, body).unwrap();
        seeds.push(SeedTool {
            tool: "read".into(),
            args: serde_json::json!({ "path": p.to_string_lossy() }),
        });
    }
    let (prefix, truncated) = driver
        .prefill_child_seeds(&seeds, &child, tmp.path(), None)
        .await;
    assert!(truncated, "the cumulative seed output trips the budget");
    use crate::engine::message::AssistantContent;
    let n_calls = match &prefix[0] {
        Message::Assistant { content, .. } => content
            .iter()
            .filter(|c| matches!(c, AssistantContent::ToolCall(_)))
            .count(),
        _ => panic!("assistant turn expected"),
    };
    assert!(n_calls >= 1, "in-budget seeds injected");
    assert!(n_calls < seeds.len(), "at least one whole seed dropped");
}

/// Absent/empty pre-seeds behave exactly as today: nothing injected, no
/// truncation.
#[tokio::test]
async fn prefill_child_seeds_empty_is_a_noop() {
    let (driver, tmp) = test_driver(8);
    let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
    let (prefix, truncated) = driver
        .prefill_child_seeds(&[], &child, tmp.path(), None)
        .await;
    assert!(prefix.is_empty());
    assert!(!truncated);
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

/// A user-issued `/<skill>` seeds a real, recorded `skill` tool call —
/// folded into history as an assistant `skill` ToolCall + its tool_result
/// (not a model-initiated call) — with the wire-vs-user split preserved
/// (`wire == original`, `Recovery::Clean`). An unknown skill records the
/// invocation with the tool's error as the result (never a silent no-op).
#[tokio::test]
async fn seed_forced_skill_records_and_folds_a_real_skill_call() {
    use crate::engine::message::AssistantContent;
    use rig::message::UserContent;

    let (mut driver, _tmp) = driver_with_skill_caller();
    // A name almost certainly not on disk → the `skill` tool returns an
    // invalid-input error; the seam still records + folds the call. (Host
    // config can vary, so we assert the seam contract, not a body load —
    // body loading itself is covered by `tools::skill` tests.)
    let skill_name = "definitely-not-a-real-skill-xyz";

    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.seed_forced_skill(skill_name, &tx).await;
    drop(tx);
    // A ToolStart + ToolEnd pair was streamed for the synthesized call.
    let mut tool_starts = 0;
    let mut tool_ends = 0;
    while let Some(ev) = rx.recv().await {
        match ev {
            TurnEvent::ToolStart { tool, .. } if tool == "skill" => tool_starts += 1,
            TurnEvent::ToolEnd { tool, .. } if tool == "skill" => tool_ends += 1,
            _ => {}
        }
    }
    assert_eq!(tool_starts, 1, "exactly one synthesized skill ToolStart");
    assert_eq!(tool_ends, 1, "exactly one synthesized skill ToolEnd");

    // History gained an assistant `skill` ToolCall (harness-synthesized,
    // not model-initiated) followed by its tool_result.
    let history = &driver.stack[0].history;
    let assistant_skill_call = history
        .iter()
        .find_map(|m| match m {
            Message::Assistant { content, .. } => content.iter().find_map(|c| match c {
                AssistantContent::ToolCall(tc) if tc.function.name == "skill" => Some(tc.clone()),
                _ => None,
            }),
            _ => None,
        })
        .expect("a `skill` tool call was folded in");
    let tool_result = history
        .iter()
        .find_map(|m| match m {
            Message::User { content } => content.iter().find_map(|c| match c {
                UserContent::ToolResult(result) => Some(result.clone()),
                _ => None,
            }),
            _ => None,
        })
        .expect("the skill call's tool_result was folded in");
    assert_eq!(
        assistant_skill_call.call_id.as_deref(),
        Some(assistant_skill_call.id.as_str()),
        "synthetic Responses calls use the cockpit call id as provider call id"
    );
    assert_eq!(tool_result.id, assistant_skill_call.id);
    assert_eq!(
        tool_result.call_id.as_deref(),
        Some(assistant_skill_call.id.as_str()),
        "tool_result must carry the same synthetic provider call id"
    );

    // The call is persisted as a real tool-call audit row with the
    // wire-vs-user split intact (verbatim synth → wire == original, clean).
    let rows = driver
        .session
        .db
        .list_tool_calls_for_session(driver.session.id)
        .unwrap();
    let skill_rows: Vec<_> = rows.iter().filter(|r| r.tool == "skill").collect();
    assert_eq!(skill_rows.len(), 1, "one persisted skill tool-call row");
    let row = skill_rows[0];
    assert!(
        row.call_id.starts_with("skillslash-"),
        "row tagged as a skill-slash invocation"
    );
    assert_eq!(row.provider_item_id.as_deref(), Some(row.call_id.as_str()));
    assert_eq!(row.provider_call_id.as_deref(), Some(row.call_id.as_str()));
    assert_eq!(
        row.provider_call_id_source.as_deref(),
        Some("synthetic_from_cockpit_call_id")
    );
    assert_eq!(row.wire_api.as_deref(), Some("responses"));
    assert_eq!(row.provider_family.as_deref(), Some("cockpit"));
    assert_eq!(
        row.wire_input_json, row.original_input_json,
        "synthesized call is verbatim: wire == original (GOALS §14)"
    );
    assert_eq!(row.recovery, crate::db::tool_calls::Recovery::Clean);
    assert_eq!(
        row.original_input_json,
        serde_json::json!({ "name": skill_name }),
        "the recorded input is the synthesized `skill` args"
    );
}

// ---- auto-injected skill transcript visibility
// (implementation note) ----

/// The wire half of the split: every auto-injected body is folded ahead of
/// the user's message in relevance order, so the model still receives them
/// (the `SkillAutoInjected` transcript rows are the user-facing half).
#[test]
fn fold_injected_skills_folds_every_body_ahead_of_the_user_message() {
    use crate::skills::auto_select::InjectedSkill;

    let skills = vec![
        InjectedSkill {
            name: "firecrawl".to_string(),
            body: "FIRECRAWL BODY".to_string(),
            reason: Some("REASON SHOULD STAY OFF WIRE".to_string()),
        },
        InjectedSkill {
            name: "deploy".to_string(),
            body: "DEPLOY BODY".to_string(),
            reason: None,
        },
    ];
    let wire = Driver::fold_injected_skills(&skills, "scrape example.com please");

    // The model still receives each body (the wire is unchanged).
    assert!(
        wire.contains("FIRECRAWL BODY"),
        "firecrawl body on the wire"
    );
    assert!(wire.contains("DEPLOY BODY"), "deploy body on the wire");
    // The reason is display-only / off-wire (GOALS §14): it must never
    // leak into the folded body the model receives.
    assert!(
        !wire.contains("REASON SHOULD STAY OFF WIRE"),
        "the auto-injection reason must stay off the wire"
    );
    // In relevance/injection order, ahead of the user's message.
    let fc = wire.find("FIRECRAWL BODY").unwrap();
    let dp = wire.find("DEPLOY BODY").unwrap();
    let um = wire.find("scrape example.com please").unwrap();
    assert!(fc < dp, "first-ranked body precedes the second");
    assert!(dp < um, "bodies precede the user's message");
    assert!(
        wire.contains("Skill `firecrawl` (auto-selected):"),
        "each body keeps its auto-selected header"
    );
}

/// No injection (the empty-selection / `Selection::None` shape) leaves the
/// user's wire text untouched — and emits no rows.
#[test]
fn fold_injected_skills_empty_returns_user_text_unchanged() {
    let wire = Driver::fold_injected_skills(&[], "just a question");
    assert_eq!(wire, "just a question");
}

// ---- request preflight (implementation note) ----

#[test]
fn preflight_enabled_honors_session_override_over_config() {
    let (mut driver, _tmp) = test_driver(1);
    // No override → falls back to config (default off).
    assert!(!driver.preflight_enabled());
    // Session override wins, both directions.
    driver.preflight_override = Some(true);
    assert!(driver.preflight_enabled());
    driver.preflight_override = Some(false);
    assert!(!driver.preflight_enabled());
}

#[tokio::test]
async fn set_preflight_toggle_flips_and_broadcasts() {
    let (mut driver, _tmp) = test_driver(1);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    // Bare toggle from the default-off effective state → on.
    driver
        .run_control(DriverControl::SetPreflight { enabled: None }, &tx)
        .await;
    assert_eq!(driver.preflight_override, Some(true));
    match rx.try_recv() {
        Ok(TurnEvent::PreflightState { enabled }) => assert!(enabled),
        other => panic!("expected PreflightState(on), got {other:?}"),
    }
    // Explicit off.
    driver
        .run_control(
            DriverControl::SetPreflight {
                enabled: Some(false),
            },
            &tx,
        )
        .await;
    assert_eq!(driver.preflight_override, Some(false));
    match rx.try_recv() {
        Ok(TurnEvent::PreflightState { enabled }) => assert!(!enabled),
        other => panic!("expected PreflightState(off), got {other:?}"),
    }
}

#[test]
fn preflight_will_run_gates_the_in_progress_signal() {
    // Drives the submit-time `PreflightStarted` event
    // (implementation note): the animated
    // indicator is added ONLY when preflight is enabled AND will actually
    // run (not a `should_skip` no-op).
    let (mut driver, _tmp) = test_driver(1);

    // Disabled → never runs, regardless of the text.
    driver.preflight_override = Some(false);
    assert!(!driver.preflight_will_run("please refactor the parser module"));
    assert!(!driver.preflight_will_run("ok"));

    // Enabled → runs on a rewritable message, skips the `should_skip` set
    // (trivial / bare ack / leading `/`).
    driver.preflight_override = Some(true);
    assert!(driver.preflight_will_run("please refactor the parser module"));
    assert!(!driver.preflight_will_run("ok"), "bare ack skips");
    assert!(!driver.preflight_will_run("/plan"), "leading slash skips");
    assert!(!driver.preflight_will_run("hi"), "trivial-length skips");
}

#[tokio::test]
async fn resolve_preflight_outcome_rewritten_sets_display_and_skill() {
    use crate::engine::preflight::PreflightOutcome;
    let (mut driver, _tmp) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let outcome = PreflightOutcome::Rewritten {
        cleaned: "clean body".into(),
        skill: Some("verify".into()),
    };
    let (text, display, skill) = driver
        .resolve_preflight_outcome(outcome, "raw original", None, &tx)
        .await;
    assert_eq!(text, "clean body", "model gets the cleaned body");
    assert_eq!(
        display.as_deref(),
        Some("clean body"),
        "the cleaned body drives the chip display"
    );
    assert_eq!(skill.as_deref(), Some("verify"), "mid-text skill is loaded");
}

#[tokio::test]
async fn resolve_preflight_outcome_think_stripped_cleaned_flows_to_both() {
    // The strip-`<think>` `cleaned` (what the preflight path produces with
    // the toggle ON) is what `resolve_preflight_outcome` yields for BOTH
    // wire and display — one `<think>`-free string in both places.
    use crate::engine::preflight::PreflightOutcome;
    let (mut driver, _tmp) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let outcome = PreflightOutcome::Rewritten {
        cleaned: "Refactor the parser.".into(),
        skill: None,
    };
    let (text, display, _skill) = driver
        .resolve_preflight_outcome(outcome, "raw original", None, &tx)
        .await;
    assert_eq!(text, "Refactor the parser.");
    assert_eq!(display.as_deref(), Some("Refactor the parser."));
    assert_eq!(
        Some(text.as_str()),
        display.as_deref(),
        "wire and display are the same <think>-free string"
    );
}

#[tokio::test]
async fn resolve_preflight_outcome_leading_skill_wins_over_mid_text() {
    use crate::engine::preflight::PreflightOutcome;
    let (mut driver, _tmp) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let outcome = PreflightOutcome::Rewritten {
        cleaned: "body".into(),
        skill: Some("mid".into()),
    };
    let (_text, _display, skill) = driver
        .resolve_preflight_outcome(outcome, "raw", Some("leading".into()), &tx)
        .await;
    assert_eq!(
        skill.as_deref(),
        Some("leading"),
        "an existing leading forced_skill takes precedence"
    );
}

#[tokio::test]
async fn resolve_preflight_outcome_guard_trip_falls_back_with_notice() {
    use crate::engine::preflight::PreflightOutcome;
    let (mut driver, _tmp) = test_driver(1);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let outcome = PreflightOutcome::GuardTripped {
        original: "run /build now please".into(),
    };
    let (text, display, _skill) = driver
        .resolve_preflight_outcome(outcome, "run /build now please", None, &tx)
        .await;
    assert_eq!(
        text, "run /build now please",
        "the original is sent verbatim"
    );
    assert!(display.is_none(), "no chip on a guard-tripped fallback");
    // A one-time notice is surfaced.
    match rx.try_recv() {
        Ok(TurnEvent::Notice { text }) => assert!(text.contains("preflight")),
        other => panic!("expected a preflight-skipped Notice, got {other:?}"),
    }
    // Logged at most once per driver.
    assert!(driver.preflight_guard_logged);
    let outcome2 = PreflightOutcome::GuardTripped {
        original: "another /plan now".into(),
    };
    let _ = driver
        .resolve_preflight_outcome(outcome2, "another /plan now", None, &tx)
        .await;
    assert!(
        matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "the skipped notice fires at most once"
    );
}

#[tokio::test]
async fn resolve_preflight_outcome_skipped_is_byte_for_byte_original() {
    use crate::engine::preflight::PreflightOutcome;
    let (mut driver, _tmp) = test_driver(1);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
    let (text, display, skill) = driver
        .resolve_preflight_outcome(
            PreflightOutcome::Skipped,
            "untouched original text",
            Some("s".into()),
            &tx,
        )
        .await;
    assert_eq!(text, "untouched original text");
    assert!(display.is_none(), "no chip when preflight didn't run");
    assert_eq!(skill.as_deref(), Some("s"), "forced_skill passes through");
}

// ---- parent→child skill seeding ----

/// `record_active_skill` de-dups by name, latest body wins — a re-invoked
/// or re-injected skill refreshes its seedable body rather than duplicating.
#[test]
fn record_active_skill_dedups_latest_wins() {
    let (mut driver, _tmp) = test_driver(1);
    driver.record_active_skill("release-notes", "first body");
    driver.record_active_skill("other", "x");
    driver.record_active_skill("release-notes", "refreshed body");
    // One entry per name; the latest body is what survives.
    let dp: Vec<_> = driver
        .active_skills
        .iter()
        .filter(|(n, _)| n == "release-notes")
        .collect();
    assert_eq!(dp.len(), 1, "name de-duped");
    assert_eq!(dp[0].1, "refreshed body", "latest body wins");
    // A blank name records nothing.
    driver.record_active_skill("  ", "ignored");
    assert!(
        driver
            .active_skills
            .iter()
            .all(|(n, _)| !n.trim().is_empty())
    );
}

/// A parent resolving an active skill seeds it into
/// the child. An ACTIVE skill contributes its instructions PLUS the
/// delegation framing (we are resolving skill X; it takes precedence over
/// the child's baked-in default), so the child drafts instead of
/// implementing.
#[test]
fn seed_skills_block_seeds_active_skill_with_framing() {
    let (mut driver, _tmp) = test_driver(1);
    // The release-notes skill is active in the parent's context (e.g.
    // user-invoked `/release-notes`).
    driver.record_active_skill(
        "release-notes",
        "Turn the rough change summary into release notes. Do NOT implement it.",
    );
    let block = driver.seed_skills_block(&["release-notes".to_string()], "builder");
    // Carries the skill's instructions...
    assert!(
        block.contains("release notes"),
        "block carries the skill body: {block:?}"
    );
    // ...plus the framing that this delegation is resolving the skill and
    // takes precedence over the child's default behavior.
    assert!(
        block.contains("skill `release-notes`")
            && block.contains("part of")
            && block.contains("precedence"),
        "block carries the resolving-skill framing: {block:?}"
    );
    assert!(
        block.contains("builder"),
        "framing names the delegated child: {block:?}"
    );
    // No spurious strip note when everything requested was active.
    assert!(
        !block.contains("dropped because"),
        "no strip note for an active skill: {block:?}"
    );
}

/// Host-side validation (validate, don't trust the model): a parent that
/// names a skill NOT active in its context has that seed deterministically
/// stripped, surfaced as a model-visible note — never a body conjured from
/// thin air, never a hard error.
#[test]
fn seed_skills_block_strips_non_active_skill_with_note() {
    let (mut driver, _tmp) = test_driver(1);
    // Only `release-notes` is active; `made-up` is not.
    driver.record_active_skill("release-notes", "release body");
    let block = driver.seed_skills_block(
        &["release-notes".to_string(), "made-up".to_string()],
        "builder",
    );
    // The active one is still seeded...
    assert!(
        block.contains("release body"),
        "active skill still seeded: {block:?}"
    );
    // ...and the non-active one is stripped with a model-visible note that
    // names it and explains why.
    assert!(
        block.contains("`made-up`") && block.contains("dropped because"),
        "non-active skill stripped with a visible note: {block:?}"
    );
    // The non-active skill's instructions never appear (nothing conjured).
    assert!(
        !block.contains("made-up body"),
        "a non-active skill cannot inject any body: {block:?}"
    );
}

/// Seeding is opt-in: a delegation that requests no skill seed (or only
/// blank names) produces an empty block — neither a seed nor a note.
#[test]
fn seed_skills_block_empty_when_nothing_requested() {
    let (mut driver, _tmp) = test_driver(1);
    driver.record_active_skill("release-notes", "body");
    assert!(driver.seed_skills_block(&[], "builder").is_empty());
    assert!(
        driver
            .seed_skills_block(&["   ".to_string()], "builder")
            .is_empty(),
        "blank names contribute nothing"
    );
}

/// End-to-end: a user-invoked `/<skill>` whose body loads makes that skill
/// part of the seedable set, so a later `task.skill_seed` naming it passes
/// host validation. Writes a real skill under the cwd's seeded scan dir.
#[tokio::test(flavor = "current_thread")]
async fn user_invoked_skill_enters_the_seedable_set() {
    let (mut driver, tmp) = driver_with_skill_caller();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    // The seeded default scan dir `./.agents/skills` resolves against cwd
    // (= the driver's tmp root, with no config.json on disk).
    let skill_dir = tmp
        .path()
        .join(".agents")
        .join("skills")
        .join("release-notes");
    std::fs::create_dir_all(&skill_dir).unwrap();
    std::fs::write(
        skill_dir.join("SKILL.md"),
        "---\nname: release-notes\ndescription: draft release notes\n---\nRELEASE NOTES, do not implement.",
    )
    .unwrap();

    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    driver.seed_forced_skill("release-notes", &tx).await;

    // The stored seedable body is the rendered skill body itself — the
    // `Skill \`name\`:\n\n` wrapper the skill tool prepends is stripped, so
    // the seed carries instructions, not the tool-output wrapper line.
    let stored = driver
        .active_skills
        .iter()
        .find(|(n, _)| n == "release-notes")
        .map(|(_, b)| b.as_str());
    assert_eq!(
        stored,
        Some("RELEASE NOTES, do not implement."),
        "user-invoked skill body enters the seedable set, wrapper stripped"
    );

    // The skill is now active in the parent's context, so seeding it into a
    // child succeeds and carries the loaded body.
    let block = driver.seed_skills_block(&["release-notes".to_string()], "builder");
    assert!(
        block.contains("RELEASE NOTES, do not implement."),
        "user-invoked skill body is seedable: {block:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn failed_user_invoked_skill_does_not_enter_seedable_set() {
    let (mut driver, tmp) = driver_with_skill_caller();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());

    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    driver.seed_forced_skill("missing-skill", &tx).await;

    assert!(
        driver.active_skills.is_empty(),
        "failed skill invocation must not become seedable"
    );
    let block = driver.seed_skills_block(&["missing-skill".to_string()], "builder");
    assert!(
        block.contains("dropped because they are not active"),
        "inactive failed skill should be stripped with a note: {block:?}"
    );
    assert!(
        !block.contains("Skill `missing-skill`:"),
        "failed skill should not inject a seeded skill body: {block:?}"
    );
}

/// An async-result delivery header names both the job `kind` and the
/// originating `job_id` (implementation note), identically
/// across every job kind (`loop`/`timer`/`background`/`swarm`). Drives the
/// real `ScheduleKind::as_str` so a kind-vocabulary drift is caught.
#[test]
fn async_result_header_names_kind_and_job_id_for_every_kind() {
    use crate::engine::schedule::spec::ScheduleKind;
    let job_id = "sched-f36b81df";
    for kind in [
        ScheduleKind::Loop,
        ScheduleKind::Timer,
        ScheduleKind::Background,
        ScheduleKind::Swarm,
    ] {
        let header = async_result_header(kind.as_str(), job_id);
        assert_eq!(
            header,
            format!("[async result · {} · sched-f36b81df]", kind.as_str()),
        );
    }
}

/// The recorded delivery event carries `data.job_id` set to the
/// originating id, additively alongside `text`
/// (implementation note). Round-trips through the real DB
/// serialization so the exported `events.json` shape is what's asserted.
/// Ordinary input (no job) omits the key entirely.
#[test]
fn delivery_event_data_carries_job_id_round_trip() {
    let (driver, _t) = test_driver(1);
    let session = driver.session.clone();

    // Async-result delivery: `data.job_id` present.
    let delivery = user_message_event_data(
        "[async result · loop · sched-abc]\nok",
        None,
        &[],
        Some("sched-abc"),
        &[],
        None,
        None,
    );
    session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &delivery,
        )
        .unwrap();
    // Ordinary user input: no `job_id` key.
    let ordinary = user_message_event_data("hello", None, &[], None, &[], None, None);
    assert!(
        ordinary.get("job_id").is_none(),
        "ordinary input must omit data.job_id: {ordinary}"
    );
    session
        .record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &ordinary,
        )
        .unwrap();

    let events = session.db.list_session_events(session.id).unwrap();
    let delivery_row = events
        .iter()
        .find(|e| e.data.get("job_id").is_some())
        .expect("delivery event with data.job_id persisted");
    assert_eq!(
        delivery_row.data.get("job_id").and_then(|v| v.as_str()),
        Some("sched-abc"),
    );
    // The text field still rides alongside, unchanged.
    assert_eq!(
        delivery_row.data.get("text").and_then(|v| v.as_str()),
        Some("[async result · loop · sched-abc]\nok"),
    );
    // Exactly one event carries the key — the ordinary message has none.
    assert_eq!(
        events
            .iter()
            .filter(|e| e.data.get("job_id").is_some())
            .count(),
        1,
    );
}

#[test]
fn user_message_event_data_includes_display_fields() {
    let expansions = vec![crate::daemon::proto::TagExpansionMeta {
        tool: "read".into(),
        path: "src/lib.rs".into(),
        detail: "142 lines".into(),
        ok: true,
    }];
    let data = user_message_event_data(
        "<file path=\"src/lib.rs\">expanded</file>",
        Some("review @src/lib.rs"),
        &expansions,
        None,
        &[],
        None,
        None,
    );

    assert!(data["text"].as_str().unwrap().starts_with("<file"));
    assert_eq!(data["display_text"], "review @src/lib.rs");
    assert_eq!(data["tag_expansions"][0]["tool"], "read");
    assert_eq!(data["tag_expansions"][0]["path"], "src/lib.rs");
    assert_eq!(data["tag_expansions"][0]["ok"], true);
}

/// Regression (implementation note, candidate
/// "queued-message state"): on a ctrl+c cancel-unwind the driver must
/// discard *every* user message that was queued during the cancelled
/// span, so `run_main_loop` doesn't immediately pick the next one up and
/// start a fresh turn — which would make the cancel *appear* to leave the
/// primary running. `discard_pending_input` drains the whole buffered
/// queue (no `MAX_FOLD` cap) and reports the count; afterwards the channel
/// yields nothing until a new send.
#[tokio::test]
async fn discard_pending_input_drops_all_queued_messages() {
    let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let target = crate::engine::message::QueueTarget::root("Build");
    // Queue more than MAX_FOLD so we prove the discard has no fold cap —
    // a partial drain would let the leftovers auto-start the next turn.
    let queued = MAX_FOLD + 5;
    for i in 0..queued {
        queue
            .push(
                UserSubmission {
                    text: format!("queued message {i}"),
                    ..Default::default()
                },
                target.clone(),
            )
            .await;
    }

    let dropped = discard_pending_input(&queue).await;
    assert_eq!(
        dropped, queued,
        "every buffered queued message is discarded on cancel (no MAX_FOLD cap)"
    );
    // Nothing is left to auto-start a fresh turn after the cancel.
    let mut drained = Vec::new();
    queue
        .drain_into_for(&mut drained, MAX_FOLD, Some(&target.id))
        .await;
    assert!(
        drained.is_empty(),
        "the queue is empty after a cancel discard"
    );

    // A message sent *after* the cancel is a fresh turn and survives — the
    // discard only drops what was buffered at cancel time, it doesn't close
    // the channel.
    queue
        .push(
            UserSubmission {
                text: "post-cancel message".into(),
                ..Default::default()
            },
            target,
        )
        .await;
    assert_eq!(
        queue.recv().await.map(|s| s.text).as_deref(),
        Some("post-cancel message"),
        "a message sent after the cancel still drives the next turn"
    );

    // Idle discard (nothing queued) is a no-op reporting zero.
    assert_eq!(discard_pending_input(&queue).await, 0);
}

#[test]
fn fold_submission_commands_preserves_compact_order() {
    let folded = fold_submission_commands(vec![
        UserSubmission::text("before"),
        UserSubmission::compact_notice(),
        UserSubmission::text("after one"),
        UserSubmission::text("after two"),
    ]);
    assert_eq!(folded.len(), 4);
    match &folded[0] {
        FoldedSubmission::User(submission) => assert_eq!(submission.text, "before"),
        FoldedSubmission::Compact(_) => panic!("expected leading user turn"),
    }
    assert!(matches!(folded[1], FoldedSubmission::Compact(_)));
    match &folded[2] {
        FoldedSubmission::User(submission) => assert_eq!(submission.text, "after one"),
        FoldedSubmission::Compact(_) => panic!("expected first trailing user turn"),
    }
    match &folded[3] {
        FoldedSubmission::User(submission) => assert_eq!(submission.text, "after two"),
        FoldedSubmission::Compact(_) => panic!("expected second trailing user turn"),
    }
}

#[test]
fn fold_submission_commands_runs_lone_compact_without_dummy_user_turn() {
    let folded = fold_submission_commands(vec![UserSubmission::compact_notice()]);
    assert_eq!(folded.len(), 1);
    assert!(matches!(folded[0], FoldedSubmission::Compact(_)));
}

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

#[test]
fn reasoning_params_prefer_native_capability_over_legacy_thinking_mode() {
    use crate::config::providers::{
        ActiveModelRef, ActiveReasoningEffort, CapabilitySource, CapabilityValue, ModelEntry,
        ProviderEntry, ProvidersConfig, ReasoningEffortCapability, ReasoningEffortRequestMapping,
        ThinkingMode,
    };
    use std::collections::BTreeMap;

    let (mut driver, _tmp) = test_driver(1);
    let mut mapping = BTreeMap::new();
    mapping.insert("minimal".to_string(), serde_json::json!("minimal"));
    mapping.insert("xhigh".to_string(), serde_json::json!("xhigh"));
    let mut providers = BTreeMap::new();
    providers.insert(
        "provider-a".to_string(),
        ProviderEntry {
            url: "http://localhost:1/v1".into(),
            models: vec![ModelEntry {
                id: "model-a".into(),
                capabilities: crate::config::providers::ModelCapabilities {
                    reasoning_effort: Some(ReasoningEffortCapability {
                        values: vec![
                            CapabilityValue {
                                value: "minimal".into(),
                                label: None,
                                description: None,
                            },
                            CapabilityValue {
                                value: "xhigh".into(),
                                label: None,
                                description: None,
                            },
                        ],
                        default: Some("minimal".into()),
                        request_mapping: Some(ReasoningEffortRequestMapping::JsonField {
                            field: "reasoning_effort".into(),
                            values: mapping,
                        }),
                        source: Some(CapabilitySource::Live),
                    }),
                    ..crate::config::providers::ModelCapabilities::default()
                },
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    let cfg = ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "provider-a".into(),
            model: "model-a".into(),
            reasoning_effort: Some(ActiveReasoningEffort {
                value: "xhigh".into(),
            }),
            thinking_mode: Some(ThinkingMode::High),
        }),
        ..ProvidersConfig::default()
    };
    let model = crate::engine::model::Model::for_provider(
        &cfg,
        "provider-a",
        "model-a",
        Arc::new(crate::redact::RedactionTable::empty()),
    )
    .unwrap();
    driver.test_providers_override = Some((cfg, "provider-a".into(), "model-a".into()));

    assert_eq!(
        driver.resolve_thinking_params_for(&model),
        Some(serde_json::json!({ "reasoning_effort": "xhigh" }))
    );
}

/// Regression: a session driving on model A routes the next request to model
/// B after a mid-session `SetActiveModel`, with no restart — the root
/// primary's bound model is rebuilt to B's id + provider.
#[tokio::test]
async fn live_model_switch_routes_next_request_to_new_model() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);

    // The dispatched request's model == A's id before the switch.
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-b".into(),
                model: "model-b".into(),
            },
            &tx,
        )
        .await;

    // The next outbound request now routes to B's id + provider, same
    // session, same root history (no restart).
    assert_eq!(
        driver.stack[0].agent.model.model_id_ref(),
        "model-b",
        "next request's model is B after the switch"
    );
    assert_eq!(
        driver.stack[0].agent.model.provider_id(),
        "provider-b",
        "next request's provider is B after the switch"
    );
    // The primary identity is unchanged — only the bound model swapped.
    assert_eq!(driver.stack[0].agent.name, "Build");
    let names = driver.stack[0].agent.tools.names();
    for tool in [
        "create_goal",
        "get_goal",
        "update_goal",
        "todo",
        "todo_read",
        "session_read",
        "session_search",
    ] {
        assert!(
            names.contains(&tool),
            "rebuilt foreground Build must preserve interactive `{tool}` tool: {names:?}"
        );
    }
    // The session's persisted active-model row is committed to B.
    assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-b")
    );
}

/// Switching to an unconfigured model surfaces a loud `Notice` error and
/// leaves the prior model (and the persisted active-model row) active.
#[tokio::test]
async fn live_model_switch_to_unconfigured_keeps_current_model() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-c".into(), // never configured
                model: "model-c".into(),
            },
            &tx,
        )
        .await;

    // A loud notice surfaced (never a silent no-op).
    let notice = rx
        .try_recv()
        .expect("a Notice must surface on an unconfigured switch");
    match notice {
        TurnEvent::Notice { text } => {
            assert!(
                text.contains("provider-c") && text.contains("failed"),
                "the notice names the failed target: {text}"
            );
        }
        other => panic!("expected a Notice, got {other:?}"),
    }

    // The prior model A is still active — both the live routing and the
    // persisted row are untouched.
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert_eq!(driver.session.active_model().as_deref(), Some("model-a"));
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-a")
    );
}

/// Re-selecting the already-active model is a no-op — no rebuild, no
/// cache-busting churn, no error.
#[tokio::test]
async fn live_model_switch_same_model_is_noop() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let before = Arc::as_ptr(&driver.stack[0].agent);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-a".into(),
                model: "model-a".into(),
            },
            &tx,
        )
        .await;

    // Same Arc — the agent was not rebuilt.
    assert_eq!(
        Arc::as_ptr(&driver.stack[0].agent),
        before,
        "re-selecting the active model must not rebuild the primary"
    );
    // No notice, no projection event.
    assert!(
        rx.try_recv().is_err(),
        "a same-model re-select emits nothing"
    );
}
