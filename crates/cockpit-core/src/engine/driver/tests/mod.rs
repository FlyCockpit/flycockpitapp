use super::*;
use cockpit_test_support::provider::{ScriptedProvider, Turn, Usage, WireDialect};

mod context;
mod delegation;
mod goals;
mod inbound;
mod learn;
mod misc;
mod model_switch;
mod noninteractive;
mod primary_swap;
mod recursion;
mod reports;
mod schedule;
mod skills_preflight;
mod turn_loop;

/// `run_user_input` deliberately returns `Ok(())` after it has cleaned up a
/// cancellation or terminal inference failure.  The late-steer receipt is a
/// stricter boundary: neither a cancellation before the dispatch permit, a
/// cancellation after a provider stream started, nor a terminal model failure
/// may be converted into the durable `completed` transition.
#[tokio::test]
async fn late_steer_noncompletion_outcomes_never_complete_a_queued_receipt() {
    let (mut driver, _tmp) = test_driver_without_network(1);
    let cases = [
        (
            "cancelled before provider dispatch",
            LateUserSteerContinuationOutcome::Cancelled,
        ),
        (
            "cancelled during provider stream",
            LateUserSteerContinuationOutcome::Cancelled,
        ),
        (
            "terminal model failure",
            LateUserSteerContinuationOutcome::failed("provider unavailable"),
        ),
    ];

    for (case, outcome) in cases {
        let queue_item_id = uuid::Uuid::new_v4();
        let (respond_to, response) = tokio::sync::oneshot::channel();
        driver.pending_late_user_steer_acks.insert(
            queue_item_id,
            PendingLateUserSteerAck {
                agent_instance_id: uuid::Uuid::new_v4(),
                steer_id: uuid::Uuid::new_v4(),
                continuation_id: uuid::Uuid::new_v4(),
                recovery_epoch: uuid::Uuid::new_v4(),
                respond_to,
            },
        );

        driver
            .finish_late_steer_deliveries(&[queue_item_id], outcome.clone())
            .await;

        assert_eq!(
            response
                .await
                .expect("queued late steer must receive an outcome"),
            outcome,
            "{case} must retain the accepted checkpoint instead of completing it"
        );
    }
}

/// A recovery endpoint is deliberately publishable before the worker consumes
/// its durable claim, but its executor must remain inert through that crash
/// window.  This exercises the shared barrier used by root, foreground,
/// noninteractive, batch, and recursive recovery paths.
#[tokio::test]
async fn recovery_activation_gate_blocks_until_claim_and_abort_never_executes() {
    let gate = RecoveryActivationGate::new();
    let (executed_tx, mut executed_rx) = tokio::sync::oneshot::channel();
    let waiting_gate = gate.clone();
    tokio::spawn(async move {
        waiting_gate.wait().await.unwrap();
        let _ = executed_tx.send(());
    });

    // Let the executor register its wait.  Publishing an endpoint alone is
    // not a claim acknowledgement and therefore cannot start work.
    tokio::task::yield_now().await;
    assert!(matches!(
        executed_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    gate.release();
    executed_rx.await.unwrap();

    let aborted = RecoveryActivationGate::new();
    aborted.abort();
    aborted.release();
    assert!(aborted.wait().await.is_err());
}

/// A real interactive admission must atomically publish the seed declarations
/// and consume the explore receipt.  A new driver then takes the same
/// `DriverControl` recovery path used by the worker: it may attach the exact
/// child while its claim is pending, but it must not run until the claim is
/// consumed and the worker's deferred activation gate is released.
#[tokio::test]
async fn recovered_interactive_task_admission_replays_durable_seed_before_inference() {
    let (mut driver, tmp) = test_driver_without_network(8);
    std::fs::write(tmp.path().join("recovery-seed.txt"), "RECOVERED_SEED_BODY").unwrap();
    let seed_reads = vec![crate::engine::seed_reads::SeedRead {
        tool: "read".to_string(),
        args: serde_json::json!({"path": "recovery-seed.txt"}),
    }];
    let receipt = driver
        .session
        .issue_seed_read_receipt(&seed_reads)
        .expect("host issued explore receipt");
    let mut provider = ScriptedProvider::builder()
        .dialect(WireDialect::ChatCompletions)
        .turn(Turn::ToolCall {
            id: "task-recovery-seed".to_string(),
            name: "task".to_string(),
            arguments: serde_json::json!({
                "agent": "builder",
                "prompt": "durable interactive handoff",
                "mode": "subagent_interactive",
                "seed_reads": &seed_reads,
                "seed_reads_receipt": &receipt,
            }),
        })
        // The post-publication parent retry remains open while the test drops
        // the daemon. The child itself must not load: that is the fallible
        // post-publication boundary this recovery fixture exercises.
        .turn(Turn::Hang)
        .start()
        .await;

    let cockpit = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    std::fs::write(
        cockpit.join("config.json"),
        r#"{"tools":{"read":{"enabled":true,"command":"echo hi"}}}"#,
    )
    .unwrap();
    driver.refresh_config_from_disk_for_tests();

    {
        use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig, WireApi};

        let providers = std::collections::BTreeMap::from([(
            "lmstudio".to_string(),
            ProviderEntry {
                url: provider.base_url(),
                headers: vec![],
                wire_api: WireApi::Completions,
                ..ProviderEntry::default()
            },
        )]);
        let config = ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".into(),
                model: "local".into(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
            ..ProvidersConfig::default()
        };
        Arc::make_mut(&mut driver.stack[0].agent).model = Arc::new(
            crate::engine::model::Model::from_config(
                &config,
                Arc::new(crate::redact::RedactionTable::empty()),
            )
            .expect("scripted parent and child model"),
        );
    }

    let session = driver.session.clone();
    let locks = driver.locks.clone();
    let redact = driver.redact.clone();
    let cwd = driver.cwd.clone();
    let root = driver.stack[0].agent.clone();
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let input_queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let (turn_tx, _turn_rx) = mpsc::channel::<TurnEvent>(256);
    {
        let admission = driver.run_user_input(
            UserSubmission::text("admit an interactive builder with the explore seed"),
            &input_queue,
            &turn_tx,
        );
        tokio::pin!(admission);

        let parent_request = tokio::select! {
            request = provider.next_request() => request,
            result = &mut admission => panic!("admission ended before the parent request: {result:?}"),
        };
        assert!(
            parent_request.body.to_string().contains("task"),
            "the real parent turn must own the task admission"
        );
        let post_failure_parent_request = tokio::select! {
            request = provider.next_request() => request,
            result = &mut admission => panic!("admission ended before the post-publication child-load failure: {result:?}"),
        };
        assert!(
            post_failure_parent_request
                .body
                .to_string()
                .contains("failed to load subagent `builder`"),
            "the parent receives the post-publication child-load failure before retrying"
        );
    }
    drop(driver);
    std::fs::remove_file(cockpit.join("config.json"))
        .expect("recovery restores the valid child builtin configuration");

    let child = session
        .db
        .task_delegation_recovery_descriptors_for_job(session.id, "task-recovery-seed".to_string())
        .await
        .expect("real admission publishes a recovery descriptor")
        .pop()
        .expect("real admission publishes one interactive child");
    let snapshot: serde_json::Value =
        serde_json::from_str(&child.snapshot_json).expect("real admission writes JSON snapshot");
    let history: Vec<Message> = serde_json::from_value(
        snapshot
            .get("history")
            .cloned()
            .expect("real admission snapshot includes history"),
    )
    .expect("real admission snapshot history decodes");
    let declarations = crate::engine::seed_reads::pending_declared_seed_calls(&history);
    assert_eq!(
        declarations.len(),
        1,
        "snapshot retains one seed declaration"
    );
    assert_eq!(declarations[0].function.name, "read");
    assert_eq!(
        declarations[0].function.arguments,
        serde_json::json!({"path": "recovery-seed.txt"}),
        "the real admission snapshot retains the seed arguments"
    );
    assert!(
        session
            .claim_seed_read_receipt(Some(&receipt), &seed_reads)
            .is_err(),
        "the real admission commits the receipt only after publication"
    );

    let recovery_epoch = uuid::Uuid::new_v4();
    let tree_recovery = crate::agent_tree::AgentTreeLifecycle::new(session.db.clone())
        .recover_session(
            session.id,
            recovery_epoch,
            crate::agent_tree::system_now_unix_ms(),
        )
        .await
        .expect("worker recovery claims the published child");
    assert!(
        tree_recovery
            .claimed_agents
            .contains(&child.agent_instance_id),
        "the recovery worker owns the exact durable child claim before reattach"
    );
    let payload = session
        .db
        .load_task_delegation_payload(&child.task_call_id, &child.label)
        .await
        .expect("real admission payload remains available for recovery");

    let mut recovered_driver =
        Driver::with_max_schedules(session.clone(), locks, redact, cwd, root, 8);
    bind_test_session_root(&mut recovered_driver);
    let (recovery_updates_tx, _recovery_updates_rx) = tokio::sync::watch::channel(Vec::new());
    let recovery_queue = crate::engine::message::UserSubmissionQueue::new(recovery_updates_tx);
    let (recovery_turn_tx, _recovery_turn_rx) = mpsc::channel::<TurnEvent>(256);
    let (control_tx, control_rx) = mpsc::channel(8);
    let recovered_main = tokio::spawn(async move {
        recovered_driver
            .run_main_loop(recovery_queue, control_rx, &recovery_turn_tx)
            .await
    });
    let activation_gate = RecoveryActivationGate::new();
    let (respond_to, attached) = tokio::sync::oneshot::channel();
    control_tx
        .send(DriverControl::ReattachInteractiveTaskChild {
            recovery: RecoveredInteractiveTaskChild {
                agent_instance_id: child.agent_instance_id,
                parent_agent_instance_id: child.parent_agent_instance_id,
                task_call_id: child.task_call_id,
                label: child.label,
                child_agent: child.child_agent,
                original_args_json: child.original_args_json,
                snapshot_json: child.snapshot_json,
                payload: payload.body,
                accepted_late_steer: None,
                activation_gate: activation_gate.clone(),
            },
            respond_to,
        })
        .await
        .expect("worker control channel remains live");
    attached
        .await
        .expect("driver answers recovery control")
        .expect("driver attaches the exact recovered interactive child");
    assert_eq!(
        provider.request_count(),
        2,
        "reattach alone cannot consume its recovery marker or infer before the worker claim"
    );

    let claimed_child = session
        .db
        .agent_instance(session.id, child.agent_instance_id)
        .await
        .expect("read exact recovery claim revision")
        .expect("published child remains durable");
    assert!(
        session
            .db
            .consume_agent_resume_claims_atomically(
                session.id,
                vec![(child.agent_instance_id, claimed_child.revision)],
                recovery_epoch,
                crate::agent_tree::system_now_unix_ms(),
            )
            .await
            .expect("consume exact recovered child claim"),
        "the worker must acknowledge the claim before it releases execution"
    );
    activation_gate.release();
    let recovered_child_request = provider.next_request().await;
    assert!(
        recovered_child_request
            .body
            .to_string()
            .contains("RECOVERED_SEED_BODY"),
        "consuming the real recovery marker replays the durable tool declaration before inference"
    );
    recovered_main.abort();
}

/// An accepted interactive steer can park on a later QuestionTool after its
/// provider handoff. On restart the task snapshot still contains the pre-tool
/// prompt, so recovery must bind the exact accepted receipt to the frame and
/// let the parked replay supply the only post-question continuation. In
/// particular, `ResumeAccepted…` must not queue that stale prompt as a second
/// user turn.
#[tokio::test]
async fn recovered_parked_interactive_late_steer_restores_one_permit_without_queueing_stale_prompt()
{
    let (mut driver, _tmp) = test_driver_without_network(1);
    let owner = uuid::Uuid::new_v4();
    let steer_id = uuid::Uuid::new_v4();
    let continuation_id = uuid::Uuid::new_v4();
    let recovery_epoch = uuid::Uuid::new_v4();
    driver.set_root_agent_instance_id(owner);
    let permit = LateUserSteerPermitIdentity {
        agent_instance_id: owner,
        steer_id,
        continuation_id,
        recovery_epoch,
    };
    driver
        .recovered_interactive_late_steer_continuations
        .insert(
            owner,
            RecoveredInteractiveLateSteerContinuation {
                permit,
                continuation_id,
                next_prompt: Message::user("stale accepted user body"),
                has_parked_continuation: true,
                pending_response: None,
            },
        );
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let input_queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let (respond_to, mut response) = tokio::sync::oneshot::channel();
    let checkpoint = serde_json::json!({
        "version": 1,
        "steer_id": steer_id,
        "continuation_id": continuation_id,
        "agent_instance_id": owner,
    })
    .to_string();

    driver
        .resume_recovered_interactive_late_steer(
            owner,
            steer_id,
            continuation_id,
            recovery_epoch,
            &checkpoint,
            respond_to,
            &input_queue,
        )
        .await;
    assert!(
        driver.recovered_interactive_continuations.is_empty(),
        "the pre-question snapshot prompt must never be scheduled"
    );
    assert!(
        driver.pending_late_user_steer_acks.is_empty(),
        "the parked replay, not ResumeAccepted, owns the receipt handoff"
    );
    assert!(matches!(
        response.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));

    driver
        .restore_recovered_parked_late_steer(owner)
        .expect("parked replay restores the accepted permit");
    driver
        .restore_recovered_parked_late_steer(owner)
        .expect("a duplicate replay must not recreate a second receipt");
    assert!(
        driver
            .recovered_interactive_late_steer_continuations
            .is_empty(),
        "the parked phase has been consumed exactly once"
    );
    assert_eq!(driver.pending_late_user_steer_acks.len(), 1);
    let restored = driver
        .stack
        .last()
        .and_then(|frame| frame.late_user_steer_permit);
    assert_eq!(restored, Some(permit));
    let pending = driver
        .pending_late_user_steer_acks
        .values()
        .next()
        .expect("one recovered receipt");
    assert_eq!(pending.agent_instance_id, owner);
    assert_eq!(pending.steer_id, steer_id);
    assert_eq!(pending.continuation_id, continuation_id);
    assert_eq!(pending.recovery_epoch, recovery_epoch);
}

/// The root has no task-child snapshot to reattach. Its accepted late-steer
/// checkpoint must therefore restore the exact root frame first, remain parked
/// through the later decision, and create exactly the one continuation receipt
/// when that decision is replayed.
#[tokio::test]
async fn recovered_parked_root_late_steer_uses_its_durable_checkpoint_once() {
    let (mut driver, _tmp) = test_driver_without_network(1);
    let root = uuid::Uuid::new_v4();
    let steer_id = uuid::Uuid::new_v4();
    let continuation_id = uuid::Uuid::new_v4();
    let recovery_epoch = uuid::Uuid::new_v4();
    driver.set_root_agent_instance_id(root);
    let history = vec![Message::user("pre-accept root history")];
    let next_prompt = Message::user("pre-question root continuation");
    let snapshot = serde_json::json!({
        "version": 1,
        "agent_instance_id": root,
        "history": &history,
        "next_prompt": &next_prompt,
        "late_user_steer_continuation_id": continuation_id,
        "parked_interrupt_id": uuid::Uuid::new_v4(),
    })
    .to_string();
    let permit = RecoveredLateUserSteerPermit {
        steer_id,
        continuation_id,
        recovery_epoch,
    };
    driver
        .restore_root_late_user_steer_continuation(root, permit, &snapshot, true)
        .expect("root must restore only its exact accepted durable snapshot");
    assert_eq!(driver.stack.first().expect("root frame").history, history);

    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let input_queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let (respond_to, mut response) = tokio::sync::oneshot::channel();
    let checkpoint = serde_json::json!({
        "version": 1,
        "steer_id": steer_id,
        "continuation_id": continuation_id,
        "agent_instance_id": root,
    })
    .to_string();
    driver
        .resume_recovered_interactive_late_steer(
            root,
            steer_id,
            continuation_id,
            recovery_epoch,
            &checkpoint,
            respond_to,
            &input_queue,
        )
        .await;
    assert!(driver.recovered_interactive_continuations.is_empty());
    assert!(matches!(
        response.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));

    driver
        .restore_recovered_parked_late_steer(root)
        .expect("the resolved parked root decision restores one permit");
    driver
        .restore_recovered_parked_late_steer(root)
        .expect("a duplicate root replay cannot create another receipt");
    assert!(
        driver
            .recovered_interactive_late_steer_continuations
            .is_empty()
    );
    assert_eq!(driver.pending_late_user_steer_acks.len(), 1);
    assert_eq!(
        driver
            .stack
            .first()
            .expect("root frame")
            .late_user_steer_permit,
        Some(LateUserSteerPermitIdentity {
            agent_instance_id: root,
            steer_id,
            continuation_id,
            recovery_epoch,
        })
    );
}

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
///
/// The root "Build" primary carries NO vNext delegation grant (legacy path),
/// which is what the vast majority of driver tests exercise. Tests that need
/// the root to delegate to authored/cockpit vNext children must use the
/// `*_vnext` variants below, which attach a resolved [`test_vnext_build_grant`].
fn test_driver(max_schedules: usize) -> (Driver, tempfile::TempDir) {
    test_driver_with_url(max_schedules, test_provider_base_url())
}

fn test_driver_without_network(max_schedules: usize) -> (Driver, tempfile::TempDir) {
    test_driver_with_url(max_schedules, "http://127.0.0.1:1/v1".to_string())
}

/// vNext variant of [`test_driver`]: the root "Build" primary carries a
/// resolved vNext delegation grant so tests that delegate to authored/cockpit
/// vNext children clear the vNext delegation boundary check (the legacy `None`
/// path refuses such children).
fn test_driver_vnext(max_schedules: usize) -> (Driver, tempfile::TempDir) {
    test_driver_with_url_and_grant(max_schedules, test_provider_base_url(), true)
}

/// vNext variant of [`test_driver_with_url`] (see [`test_driver_vnext`]).
fn test_driver_with_url_vnext(
    max_schedules: usize,
    provider_url: String,
) -> (Driver, tempfile::TempDir) {
    test_driver_with_url_and_grant(max_schedules, provider_url, true)
}

/// Construct a vNext `EffectiveVnextGrant` for the test "Build" primary.
///
/// The grant carries a broad `allowed_children` list so tests that delegate
/// to workspace-authored vNext children (using `authored/` prefixed agent IDs)
/// and built-in children (using `cockpit/` prefixed agent IDs) both pass the
/// vNext/legacy delegation boundary check.  The test "Build" agent is created
/// directly (not via `agent_from_def`), so `vnext_reachable_subagents` is not
/// called and the broad list cannot cause a resolution bail.
fn test_vnext_build_grant(root: &std::path::Path) -> crate::agents::EffectiveVnextGrant {
    use crate::agents::{AllowedChild, DelegationTarget};
    let host = crate::agents::VnextHostPolicy::for_session_config(
        &crate::config::extended::load_for_cwd(root),
    );
    let children = [
        "cockpit/builder",
        "cockpit/explore",
        "cockpit/history",
        "cockpit/deepthink",
        "cockpit/scout",
    ];
    // Keep identity, roles, capabilities, and model slots exactly aligned
    // with the production Build definition. The test root is constructed
    // directly, but subsequent frame rebuilds use the production factory and
    // reject a grant projected from a different definition.
    let mut definition = crate::agents::embedded_default("Build")
        .and_then(|definition| definition.vnext)
        .expect("built-in Build must carry a vNext definition");
    definition.delegation.allowed_children = children
        .iter()
        .map(|child| AllowedChild::PortableRef {
            portable_agent_ref: child.to_string(),
        })
        .collect();
    definition.delegation.max_descendant_depth = Some(4);
    // Author exactly the host's concurrency ceiling so `resolve_grant`
    // always admits this test grant (it REJECTS, never clamps, an authored
    // value above the host ceiling — see vnext.rs). The batch delivery tests
    // fan out at most three children, well under this.
    definition.delegation.max_concurrent_children = Some(host.max_concurrent_children);
    definition.delegation.targets = vec![DelegationTarget::SameRoot];
    definition.delegation.default_child = None;
    definition
        .resolve_grant(&host)
        .expect("test vNext Build grant must resolve")
}

fn test_driver_with_url(max_schedules: usize, provider_url: String) -> (Driver, tempfile::TempDir) {
    test_driver_with_url_and_grant(max_schedules, provider_url, false)
}

fn test_driver_with_url_and_grant(
    max_schedules: usize,
    provider_url: String,
    with_vnext_grant: bool,
) -> (Driver, tempfile::TempDir) {
    use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig, WireApi};
    use std::collections::BTreeMap;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let db = crate::db::Db::open_in_memory().unwrap();
    let session = Arc::new(
        Session::create_for_test(
            db.clone(),
            root.clone(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    );
    session.install_test_external_journal();
    let locks = Arc::new(crate::locks::LockManager::in_memory(db));
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
            prompt_cache_retention: None,
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
        tool_steering: crate::agents::ToolSteering::Terse,
        posture: crate::agents::embedded_default("Build")
            .map(|def| crate::agents::PostureResolution::from_def(&def))
            .unwrap_or_else(crate::agents::PostureResolution::standard),
        context_policy: None,
        lock_identity: "Build".to_string(),
        write_scope: None,
        workspace_lease: None,
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        vnext_grant: with_vnext_grant.then(|| test_vnext_build_grant(&root)),
        env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        definition: None,
        assistant_identity_prefix: None,
        mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::empty(),
    });
    let mut driver = Driver::with_max_schedules(session, locks, redact, root, agent, max_schedules);
    // The root model above is built from this fixture configuration.  Keep the
    // driver's generation-pinned config handle on that same snapshot: turn
    // refreshes and delegated vNext children resolve through the handle, not
    // through the already-built root model.
    driver.set_config_handle(
        crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                pcfg,
                crate::config::extended::ExtendedConfig::default(),
            ),
        ),
    );
    bind_test_session_root(&mut driver);
    (driver, tmp)
}

/// Standalone driver tests do not go through the worker's deferred root
/// publication. Mint the reserved `session-root` so child START registration
/// and continuation snapshots have a durable parent. Tests that assert the
/// missing-parent refusal clear `agent_instance_id` afterwards.
fn bind_test_session_root(driver: &mut Driver) {
    let cwd = driver.cwd.clone();
    let db = driver.session.db.clone();
    let session_id = driver.session.id;
    let created = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("bind test session root runtime");
        runtime.block_on(async {
            let workspace_ref = crate::agent_tree::workspace_ref_for_host_path(&cwd)?;
            let created = db
                .ensure_session_root_agent(
                    session_id,
                    None,
                    workspace_ref,
                    crate::agent_tree::system_now_unix_ms(),
                )
                .await?;
            match db
                .transition_agent_instance(
                    session_id,
                    created.agent_instance_id,
                    created.revision,
                    crate::db::agent_tree_decisions::AgentInstanceState::Running,
                    r#"{"state":"running"}"#,
                    crate::agent_tree::system_now_unix_ms(),
                )
                .await?
            {
                crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(row) => {
                    Ok::<_, anyhow::Error>(row)
                }
                crate::db::agent_tree_decisions::AgentTransitionOutcome::AlreadyTerminal(_)
                | crate::db::agent_tree_decisions::AgentTransitionOutcome::RevisionConflict => {
                    Ok(created)
                }
            }
        })
    })
    .join()
    .expect("bind test session root thread")
    .expect("bind test session root");
    driver.set_root_agent_instance_id(created.agent_instance_id);
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

    // Create the scripted provider first so its URL can be written to a
    // per-provider file (the loader strips inline `providers` from
    // config.json and only reads `.cockpit/providers/<id>.json`).
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

    // config.json carries skills settings and the atomic active_model.
    // Provider definitions go in a separate file (see comment above).
    std::fs::write(
        config_dir.join("config.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "skills": {
                "scan_dirs": [root.to_string_lossy()],
                "write_approval": approval
            },
            "active_model": {
                "provider": "scripted",
                "model": "local"
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let providers_dir = config_dir.join("providers");
    std::fs::create_dir_all(&providers_dir).unwrap();
    std::fs::write(
        providers_dir.join("scripted.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "url": provider_url,
            "wire_api": "completions"
        }))
        .unwrap(),
    )
    .unwrap();

    let agents_dir = config_dir.join("agents");
    std::fs::create_dir_all(&agents_dir).unwrap();
    // Use a custom agent name "LearnBuild" instead of "Build" so that
    // `default_disabled_tools_for` (which disables `skill_manage` for Build
    // and other built-in primaries) does not remove the tool from the
    // rebuilt agent's surface during `refresh_active_tool_surface_for_turn`.
    // The launch-v1 format does not support `toolTiers` overrides, so the only way
    // to keep `skill_manage` enabled through the rebuild is to use a name
    // not in the disabled-by-default list.  The `cockpit` publisher prefix
    // is reserved for binary-owned definitions, so change the vNext agentId.
    let mut build_def = crate::agents::embedded_default("Build").expect("known built-in");
    if let Some(vnext) = &mut build_def.vnext {
        vnext.agent_id = "authored/learnbuild".to_string();
    }
    std::fs::write(
        agents_dir.join("LearnBuild.md"),
        build_def.to_markdown().expect("launch-v1 bundled override"),
    )
    .unwrap();
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
            prompt_cache_retention: None,
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
        name: "LearnBuild".into(),
        system: "Author reusable skills from verified evidence.".into(),
        role_prompt: "Author reusable skills from verified evidence.".into(),
        tools: crate::engine::tool::ToolBox::new()
            .with(Arc::new(crate::tools::skill_manage::SkillManageTool)),
        model,
        params: crate::engine::model::ModelParams::default(),
        scan_tool_results: false,
        tool_steering: crate::agents::ToolSteering::Terse,
        posture: crate::agents::PostureResolution::standard(),
        context_policy: None,
        lock_identity: "LearnBuild".to_string(),
        write_scope: None,
        workspace_lease: None,
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        vnext_grant: None,
        env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        definition: None,
        assistant_identity_prefix: None,
        mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::empty(),
    });
    let db = crate::db::Db::open_in_memory().unwrap();
    let session = Arc::new(
        Session::create_for_test(
            db.clone(),
            tmp.path().to_path_buf(),
            "LearnBuild",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    );
    session.install_test_external_journal();
    let locks = Arc::new(crate::locks::LockManager::in_memory(db));
    let redact = Arc::new(RedactionTable::empty());
    let mut driver =
        Driver::with_max_schedules(session, locks, redact, tmp.path().to_path_buf(), agent, 1);
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::with_workspace_trust_policy(policy, || {
        driver.refresh_config_from_disk_for_tests();
    });
    driver.stack[0].history.push(Message::user(
        "We verified the setup with cockpit verify --local.",
    ));
    driver.stack[0].history.push(Message::Assistant {
        id: Some("prior-assistant".into()),
        content: vec![crate::engine::message::AssistantContent::text(
            "The local verification completed successfully.",
        )],
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

async fn record_goal_tool_event(driver: &Driver, tool: &str, wire_input: serde_json::Value) {
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
        .await
        .unwrap();
}

/// Build a driver rooted on the real `Plan` primary. The model is keyless
/// localhost and never called: primary-swap tests drive
/// [`Driver::swap_primary`] directly, so no inference round-trips.
fn plan_rooted_driver() -> (Driver, tempfile::TempDir) {
    let (mut driver, tmp) = test_driver(1);
    // Re-root on a genuine `Plan`, built through the same factory the
    // session worker uses, so its tool surface + name match production.
    let plan = crate::engine::builtin::load("Plan", &driver.spawn_args(true)).unwrap();
    driver.stack[0].agent = Arc::new(plan);
    driver.session.set_active_agent("Plan").unwrap();
    (driver, tmp)
}

/// An assistant turn carrying a single `write` tool call on `path`.
fn write_turn(call_id: &str, path: &str) -> Message {
    use crate::engine::message::AssistantContent;
    use rig::message::{ToolCall, ToolFunction};
    Message::Assistant {
        id: None,
        content: vec![AssistantContent::ToolCall(ToolCall {
            id: rig::message::ToolCallId::new_or_mint(call_id.to_string()),
            provider: None,
            function: ToolFunction {
                name: "write".to_string(),
                arguments: serde_json::json!({ "path": path }),
            },
            signature: None,
            additional_params: None,
        })],
    }
}

fn read_turn(call_id: &str, path: &str) -> Message {
    use crate::engine::message::AssistantContent;
    use rig::message::{ToolCall, ToolFunction};
    Message::Assistant {
        id: None,
        content: vec![AssistantContent::ToolCall(ToolCall {
            id: rig::message::ToolCallId::new_or_mint(call_id.to_string()),
            provider: None,
            function: ToolFunction {
                name: "read".to_string(),
                arguments: serde_json::json!({ "path": path }),
            },
            signature: None,
            additional_params: None,
        })],
    }
}

fn bash_turn(call_id: &str, command: &str) -> Message {
    use crate::engine::message::AssistantContent;
    use rig::message::{ToolCall, ToolFunction};
    Message::Assistant {
        id: None,
        content: vec![AssistantContent::ToolCall(ToolCall {
            id: rig::message::ToolCallId::new_or_mint(call_id.to_string()),
            provider: None,
            function: ToolFunction {
                name: "bash".to_string(),
                arguments: serde_json::json!({ "command": command }),
            },
            signature: None,
            additional_params: None,
        })],
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
        .blocking_write_for_sync_maintenance(move |conn| {
            crate::db::Db::get_session_conn(conn, session_id)
        })
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
    use crate::engine::message::AssistantContent;
    use rig::message::{ToolCall, ToolFunction};
    Message::Assistant {
        id: None,
        content: vec![AssistantContent::ToolCall(ToolCall {
            id: rig::message::ToolCallId::new_or_mint(call_id.to_string()),
            provider: None,
            function: ToolFunction {
                name: tool.to_string(),
                arguments: serde_json::json!({}),
            },
            signature: None,
            additional_params: None,
        })],
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
                    && tr.call == call_id
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

async fn record_skill_tool_row(driver: &Driver, call_id: &str, agent: &str, output: &str) {
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
            shape_fingerprint: None,
            hint: None,
        })
        .await
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
    use rig::message::{AssistantContent, ToolResult, ToolResultContent, UserContent};
    let body = body.into();
    let call = |id: &str| Message::Assistant {
        id: None,
        content: vec![AssistantContent::ToolCall(
            crate::engine::message::ToolCall {
                id: rig::message::ToolCallId::new_or_mint(id.to_string()),
                provider: None,
                function: rig::message::ToolFunction {
                    name: "read".into(),
                    arguments: serde_json::json!({ "path": "/abs/foo.rs" }),
                },
                signature: None,
                additional_params: None,
            },
        )],
    };
    let result = |id: &str| Message::User {
        content: vec![UserContent::ToolResult(ToolResult {
            call: rig::message::ToolCallId::new_or_mint(id.to_string()),
            provider: None,
            name: "read".into(),
            content: vec![ToolResultContent::text(body.clone())],
        })],
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
        computer_coordinator: None,
        computer_contract: None,
        computer_coordinator_config: None,
        pending_computer_continuations: Vec::new(),
        agent_instance_id: None,
        endpoint_generation: None,
        history,
        answering: None,
        deferred_log: crate::engine::deferred::DeferredLog::new(),
        fallback_decision: None,
        recovery_activation: None,
        late_user_steer_permit: None,
        _vnext_child_admission: None,
        stop_gate: crate::engine::agent::hooks::StopGateState::default(),
    });
}

fn task_tool_call(call_id: &str, function_call_id: &str) -> Message {
    use rig::message::AssistantContent;
    Message::Assistant {
        id: None,
        content: vec![AssistantContent::ToolCall(
            crate::engine::message::ToolCall {
                id: rig::message::ToolCallId::new_or_mint(call_id.to_string()),
                provider: rig::message::ProviderCallId::new(function_call_id.to_string()),
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
        )],
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
                Some((result.call.to_string(), text))
            }
            _ => None,
        }),
        _ => None,
    }
}

fn enqueue_target_id(driver: &Driver) -> String {
    driver
        .enqueue_target
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .id
        .clone()
}

fn assert_enqueue_matches_drain(driver: &Driver) {
    assert_eq!(
        enqueue_target_id(driver),
        driver.active_queue_target_id(),
        "enqueue replica must match stack.last().queue_target"
    );
}

fn push_answering_child(driver: &mut Driver, call_id: &str, function_call_id: &str) {
    let mut child = (*driver.stack[0].agent).clone();
    child.name = "builder".to_string();
    let frame = AgentSession {
        queue_target: crate::engine::message::QueueTarget::child(
            child.name.clone(),
            driver.stack.len(),
            call_id,
            "default",
        ),
        agent: Arc::new(child),
        computer_coordinator: None,
        computer_contract: None,
        computer_coordinator_config: None,
        pending_computer_continuations: Vec::new(),
        agent_instance_id: None,
        endpoint_generation: None,
        history: vec![],
        answering: Some(PendingTaskCall {
            call_id: call_id.to_string(),
            provider_item_id: None,
            function_call_id: Some(function_call_id.to_string()),
            repair_notes: Vec::new(),
        }),
        deferred_log: crate::engine::deferred::DeferredLog::new(),
        fallback_decision: None,
        recovery_activation: None,
        late_user_steer_permit: None,
        _vnext_child_admission: None,
        stop_gate: crate::engine::agent::hooks::StopGateState::default(),
    };
    driver.mutate_live_stack(|stack| stack.push(frame));
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
        .await
        .unwrap();
    driver
        .locks
        .suspend_agent("Build", driver.session.id)
        .await
        .unwrap();
    push_answering_child(&mut driver, call_id, function_call_id);
    driver
        .locks
        .acquire(&child_lock, "builder", driver.session.id)
        .await
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

    driver.unwind_stack_to_root(reason, &tx).await.unwrap();

    assert_eq!(driver.stack.len(), 1);
    assert_eq!(
        enqueue_target_id(&driver),
        driver.active_queue_target_id(),
        "unwind must leave enqueue and drain on the same live frame"
    );
    assert_eq!(driver.active_queue_target_id(), "root");
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
        expected_model_state_generation: None,
        expected_model: None,
        kind: UserSubmissionKind::User,
        origin: Default::default(),
        text: "next root message".into(),
        display_text: None,
        tag_expansions: Vec::new(),
        images: vec![],
        media: vec![],
        forced_skill: None,
        origin_principal: None,
        job_id: None,
        preflight_cleaned: None,
        queue_item_ids: Vec::new(),
        client_submissions: Vec::new(),
        queue_target: None,
        pending_terminal_disposition: None,
        run_invocation_id: None,
        delivery_class_override: None,
        delivery_class: Default::default(),
    });
    assert!(
        crate::engine::rehydrate::heal_live_history(&mut history, &prompt).is_empty(),
        "abort result should already pair the parent's task call"
    );

    let mut turn_events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        turn_events.push(event);
    }
    assert!(
        turn_events.iter().any(|event| matches!(
            event,
            TurnEvent::ForegroundInputTarget { target } if target.id == "root"
                && target.agent == "Build"
                && target.depth == 0
        )),
        "unwind must emit FIT for the live root frame so enqueue follows drain: {turn_events:?}"
    );
    let report = turn_events
        .iter()
        .find(|event| matches!(event, TurnEvent::SubagentReport { .. }))
        .expect("subagent report event");
    match report {
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
    assert_eq!(
        turn_events
            .iter()
            .filter(|event| matches!(event, TurnEvent::SubagentReport { .. }))
            .count(),
        1,
        "one child frame should emit one report"
    );

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
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
async fn recovered_attach_then_agent_idle_keeps_enqueue_on_live_child() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(16);
    let shared = std::sync::Arc::new(std::sync::Mutex::new(
        crate::engine::message::QueueTarget::root("Build"),
    ));
    driver.bind_enqueue_target(shared.clone());
    push_answering_child(&mut driver, "task-1", "fn-1");
    driver.emit_foreground_input_target(&tx).await;

    assert_eq!(driver.active_queue_target_id(), "task:task-1:default");
    assert_enqueue_matches_drain(&driver);
    assert_eq!(
        shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .id,
        "task:task-1:default"
    );
    match rx.try_recv() {
        Ok(TurnEvent::ForegroundInputTarget { target }) => {
            assert_eq!(target.id, "task:task-1:default");
        }
        other => panic!("expected FIT for the attached child, got {other:?}"),
    }

    // The idle-loop select arm used to emit AgentIdle after reattach and
    // overwrite enqueue to root. Recovered attach does not settle a turn.
    driver.emit_turn_idle_if_settled(&tx).await;
    assert!(
        rx.try_recv().is_err(),
        "AgentIdle must not fire after attach without a settled turn"
    );
    assert_eq!(driver.active_queue_target_id(), "task:task-1:default");
    assert_enqueue_matches_drain(&driver);
}

#[tokio::test]
async fn unwind_and_cancel_leave_enqueue_and_drain_agreed() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    driver.bind_input_queue(queue.clone());
    push_answering_child(&mut driver, "task-1", "fn-1");
    driver.emit_foreground_input_target(&tx).await;
    let child = driver.active_queue_target();
    let _ = queue
        .push(UserSubmission::text("keep me dispatchable"), child)
        .await;

    driver
        .unwind_stack_to_root(StackUnwindReason::Cancelled, &tx)
        .await
        .unwrap();
    assert_eq!(driver.stack.len(), 1);
    assert_eq!(driver.active_queue_target_id(), "root");
    assert_enqueue_matches_drain(&driver);

    let (mut driver, _tmp) = test_driver(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    driver.bind_input_queue(queue.clone());
    push_answering_child(&mut driver, "task-1", "fn-1");
    driver.emit_foreground_input_target(&tx).await;
    let child = driver.active_queue_target();
    let _ = queue
        .push(UserSubmission::text("cancel me"), child.clone())
        .await;
    let dropped = driver
        .unwind_stack_to_root_and_discard_pending_input(StackUnwindReason::Cancelled, &queue, &tx)
        .await
        .expect("unwind must drain pending input");
    assert_eq!(dropped, 1);
    assert_eq!(driver.active_queue_target_id(), "root");
    assert_enqueue_matches_drain(&driver);
    let mut leftover = Vec::new();
    queue
        .drain_into_for(&mut leftover, 8, Some(&child.id))
        .await;
    assert!(leftover.is_empty());
}

#[tokio::test]
async fn unwind_cannot_strand_items_stamped_for_a_dead_child() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    driver.bind_input_queue(queue.clone());
    push_answering_child(&mut driver, "task-1", "fn-1");
    driver.emit_foreground_input_target(&tx).await;
    let child = driver.active_queue_target();
    let _ = queue
        .push(UserSubmission::text("do not strand"), child.clone())
        .await;

    driver
        .unwind_stack_to_root(
            StackUnwindReason::InferenceFailed {
                provider: String::new(),
                model: String::new(),
                class: crate::engine::model::InferenceErrorClass::Other("boom".into()),
                phase: "unknown".into(),
            },
            &tx,
        )
        .await
        .unwrap();

    assert_eq!(driver.active_queue_target_id(), "root");
    assert_enqueue_matches_drain(&driver);
    let got = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        queue.recv_group_order_for(Some("root")),
    )
    .await
    .expect("root wait must observe the adopted item")
    .expect("item remains dispatchable");
    assert_eq!(got.text, "do not strand");
    assert_eq!(
        got.queue_target.as_ref().map(|target| target.id.as_str()),
        Some("root")
    );
}

#[tokio::test]
async fn stack_last_mutation_commits_enqueue_replica_before_fit() {
    let (mut driver, _tmp) = test_driver(8);
    let shared = std::sync::Arc::new(std::sync::Mutex::new(
        crate::engine::message::QueueTarget::root("Build"),
    ));
    driver.bind_enqueue_target(shared.clone());
    push_answering_child(&mut driver, "task-1", "fn-1");
    assert_eq!(driver.active_queue_target_id(), "task:task-1:default");
    assert_enqueue_matches_drain(&driver);
    assert_eq!(
        shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .id,
        "task:task-1:default"
    );
}

#[tokio::test]
async fn live_enqueue_after_adopt_stamps_the_live_frame_not_a_stale_child() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    driver.bind_input_queue(queue.clone());
    let shared = std::sync::Arc::new(std::sync::Mutex::new(
        crate::engine::message::QueueTarget::root("Build"),
    ));
    driver.bind_enqueue_target(shared.clone());
    push_answering_child(&mut driver, "task-1", "fn-1");
    driver.emit_foreground_input_target(&tx).await;
    let stale_child = shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(stale_child.id, "task:task-1:default");

    driver
        .unwind_stack_to_root(
            StackUnwindReason::InferenceFailed {
                provider: String::new(),
                model: String::new(),
                class: crate::engine::model::InferenceErrorClass::Other("boom".into()),
                phase: "unknown".into(),
            },
            &tx,
        )
        .await
        .unwrap();
    assert_eq!(driver.active_queue_target_id(), "root");
    assert_enqueue_matches_drain(&driver);

    let mut submission = UserSubmission::text("do not strand");
    submission.queue_target = Some(stale_child);
    let id = uuid::Uuid::new_v4();
    let receipt = crate::engine::message::ClientSubmissionReceipt {
        id,
        fingerprint: submission.client_fingerprint(),
        wire_fingerprint: id.to_string(),
        origin_principal: None,
    };
    let (_, snapshot, outcome) = queue
        .push_idempotent_on_live_target(receipt, submission, &shared)
        .await;
    assert_eq!(outcome, crate::engine::message::IdempotentPush::Inserted);
    assert_eq!(
        snapshot
            .iter()
            .map(|item| item.target.id.as_str())
            .collect::<Vec<_>>(),
        vec!["root"]
    );
    let got = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        queue.recv_group_order_for(Some("root")),
    )
    .await
    .expect("root wait must observe the live-stamped item")
    .expect("item remains dispatchable");
    assert_eq!(got.text, "do not strand");
    assert_eq!(
        got.queue_target.as_ref().map(|target| target.id.as_str()),
        Some("root")
    );
}

#[tokio::test]
async fn emit_turn_idle_if_settled_emits_only_after_a_turn() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    driver.emit_turn_idle_if_settled(&tx).await;
    assert!(rx.try_recv().is_err());

    driver.current_lifecycle_turn_id = Some("turn-1".into());
    driver.emit_turn_idle_if_settled(&tx).await;
    match rx.try_recv() {
        Ok(TurnEvent::AgentIdle {
            turn_id: Some(turn_id),
            ..
        }) => assert_eq!(turn_id, "turn-1"),
        other => panic!("expected AgentIdle for the settled turn, got {other:?}"),
    }
    assert!(driver.current_lifecycle_turn_id.is_none());
}

/// #275: an idle published under a bound queue id may only carry a success
/// reason when the bound turn actually reached its terminal outcome. A
/// post-bind exit that never completed (durable-record retry, admission
/// refusal, run-invocation gate) must fail closed with a non-success reason
/// — the settlement layer maps `Completed`/`GoalComplete` to a successful
/// run, so a fabricated success would record a job that never ran.
#[tokio::test]
async fn post_bind_exit_never_idles_as_success() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

    // A bound turn that never reached a terminal outcome idles fail-closed.
    driver.current_lifecycle_turn_id = Some("turn-1".into());
    driver.emit_turn_idle_if_settled(&tx).await;
    match rx.try_recv() {
        Ok(TurnEvent::AgentIdle { reason, .. }) => assert!(
            !matches!(
                reason,
                crate::engine::IdleReason::Completed | crate::engine::IdleReason::GoalComplete
            ),
            "an uncompleted turn must not idle with a success reason, got {reason:?}"
        ),
        other => panic!("expected fail-closed AgentIdle, got {other:?}"),
    }
    assert!(driver.current_lifecycle_turn_id.is_none());

    // Only a turn marked as having reached its terminal outcome may take
    // the goal-aware success default.
    driver.current_lifecycle_turn_id = Some("turn-2".into());
    driver.current_lifecycle_turn_completed = true;
    driver.emit_turn_idle_if_settled(&tx).await;
    match rx.try_recv() {
        Ok(TurnEvent::AgentIdle {
            turn_id: Some(turn_id),
            reason,
        }) => {
            assert_eq!(turn_id, "turn-2");
            assert_eq!(reason, crate::engine::IdleReason::Completed);
        }
        other => panic!("expected completed AgentIdle, got {other:?}"),
    }
    assert!(driver.current_lifecycle_turn_id.is_none());
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
        allow_computer_guidance_proposals: None,
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
        inline_think: None,
        hint_tool_call_corrections: None,
        text_embedded_recovery: None,
        thinking_params: Default::default(),
        system_prompt: None,
        wire_api: WireApi::Completions,
        wire_api_provenance: Default::default(),
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
            prompt_cache_retention: None,
        }),
        ..ProvidersConfig::default()
    };
    driver.test_providers_override = Some((cfg, "lmstudio".into(), "local".into()));
}

async fn record_test_context_tokens(driver: &Driver, input_tokens: u64) {
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
        .await
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

// ---------------------------------------------------------------------------
// Shared lifecycle observe-hook boundary test helpers.
//
// A single observe hook whose command is deliberately unresolvable fails open
// (executable-not-found) WITHOUT spawning a real process, yet still records a
// `hook_run` row — the wiring signal every boundary test asserts on.
// ---------------------------------------------------------------------------

/// A registry with a single observe hook for `event` matched only on `matcher`.
fn observe_boundary_registry(
    event: crate::config::extended::hooks::HookEvent,
    matcher: &str,
) -> crate::config::extended::hooks::HookRegistry {
    use crate::config::extended::hooks::{HookOrigin, HookRegistry, ResolvedHook};
    HookRegistry {
        hooks: vec![ResolvedHook {
            event,
            matcher: Some([matcher.to_string()].into_iter().collect()),
            command: vec!["cockpit-observe-hook-does-not-exist".to_string()],
            timeout_secs: 5,
            env: std::collections::BTreeMap::new(),
            origin: HookOrigin::for_test("project:abcdef0123456789:0"),
            source_config_path: std::path::PathBuf::from("/tmp/test/config.json"),
            source_directory: std::path::PathBuf::from("/tmp/test"),
            execution: crate::config::extended::hooks::HookExecutionProvenance::Ambient,
        }],
        warnings: Vec::new(),
    }
}

/// Install a hook registry on the driver's turn-pinned config snapshot without
/// disturbing the test provider override compaction relies on.
fn inject_hooks(driver: &mut Driver, reg: crate::config::extended::hooks::HookRegistry) {
    driver.set_config_handle(
        crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::with_hooks(
                1,
                crate::config::providers::ProvidersConfig::default(),
                crate::config::extended::ExtendedConfig::default(),
                reg,
            ),
        ),
    );
}

/// The recorded `hook_run` statuses for `event`, in insertion order.
async fn observe_hook_events(driver: &Driver, event: &str) -> Vec<String> {
    driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "hook_run" && e.data["event"] == event)
        .map(|e| e.data["status"].as_str().unwrap_or_default().to_string())
        .collect()
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

async fn compact_inference_purposes(driver: &Driver) -> Vec<String> {
    driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|event| {
            (event.kind == "inference_request")
                .then(|| event.data["purpose"].as_str().map(str::to_string))
                .flatten()
        })
        .filter(|purpose| {
            purpose.starts_with("compact_") || purpose.starts_with("rolling_compaction_")
        })
        .collect()
}

// ── write-capable follow-up (implementation note) ──

/// A caller assistant turn that ends in a `task` tool call.
fn assistant_with_task_call(task_call_id: &str) -> Message {
    use crate::engine::message::{AssistantContent, ToolCall};
    use rig::message::ToolFunction;
    Message::Assistant {
        id: None,
        content: vec![AssistantContent::ToolCall(ToolCall {
            id: rig::message::ToolCallId::new_or_mint(task_call_id.to_string()),
            provider: None,
            function: ToolFunction {
                name: "task".into(),
                arguments: serde_json::json!({ "agent": "explore", "prompt": "go" }),
            },
            signature: None,
            additional_params: None,
        })],
    }
}

fn tool_result_id(msg: &Message) -> String {
    use rig::message::UserContent;
    match msg {
        Message::User { content } => content
            .iter()
            .find_map(|part| match part {
                UserContent::ToolResult(result) => Some(result.call.to_string()),
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
            UserContent::ToolResult(result) => result
                .provider
                .as_ref()
                .map(|provider| provider.call_id.clone()),
            _ => None,
        }),
        _ => panic!("expected a tool_result user message"),
    }
}

fn tool_result_provider_item_id(msg: &Message) -> Option<String> {
    use rig::message::UserContent;
    match msg {
        Message::User { content } => content.iter().find_map(|part| match part {
            UserContent::ToolResult(result) => result
                .provider
                .as_ref()
                .and_then(|provider| provider.item_id.clone()),
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
        task_provider_item_id: None,
        task_function_call_id: Some(format!("fn-{task_call_id}")),
        report: report.to_string(),
        failed: false,
        failure: None,
        partial_progress: DelegationPartialProgress::default(),
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

async fn seed_task_delegation(driver: &Driver, task_call_id: &str, label: &str) {
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
        .await
        .unwrap();
}

async fn seed_batch_task_delegation(driver: &Driver, task_call_id: &str, labels: &[&str]) {
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
        .await
        .unwrap();
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
        tool_steering: old.tool_steering,
        posture: old.posture.clone(),
        context_policy: None,
        lock_identity: "Build".to_string(),
        write_scope: None,
        workspace_lease: None,
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        vnext_grant: None,
        env_overlay: old.env_overlay.clone(),
        // This fixture installs a test-only single-tool surface, so no
        // definition may rebuild it into an unrelated role default during a
        // preflight boundary.
        definition: None,
        assistant_identity_prefix: None,
        mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::empty(),
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
            prompt_cache_retention: None,
        }),
        ..ProvidersConfig::default()
    }
}

/// Re-root the driver on model A (`provider-a/model-a`) and install the
/// two-provider test config so the live switch resolves against it. Returns
/// the driver rooted on a real `Build` primary built through the same
/// factory production uses.
fn model_switch_driver() -> (Driver, tempfile::TempDir) {
    let (mut driver, tmp) = test_driver_vnext(1);
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
    driver.test_providers_override = Some((cfg.clone(), "provider-a".into(), "model-a".into()));
    driver.set_config_handle(
        crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                cfg,
                crate::config::extended::ExtendedConfig::default(),
            ),
        ),
    );
    let mut args = driver.spawn_args(true);
    args.model = model_a;
    // Build the initial frame from the same grant snapshot that a turn-boundary
    // refresh preserves. This keeps the task schema stable until a test
    // deliberately admits a workspace-authored portable child.
    let grant = driver.stack[0].agent.vnext_grant.clone();
    args.vnext_grant = grant.clone();
    args.vnext_host_policy = grant
        .as_ref()
        .map(|g| std::sync::Arc::new(g.host_policy.clone()));
    let mut agent = crate::engine::builtin::load("Build", &args).unwrap();
    agent.vnext_grant = grant;
    driver.stack[0].agent = Arc::new(agent);
    (driver, tmp)
}

/// Admit a workspace-authored portable child into the active frames' vNext
/// grants after its on-disk definition exists (portable refs fail closed when
/// unresolved at Build construction).
fn admit_authored_child_to_test_grants(driver: &mut Driver, portable_agent_ref: &str) {
    use crate::agents::AllowedChild;
    for frame in &mut driver.stack {
        let agent = Arc::make_mut(&mut frame.agent);
        let Some(grant) = agent.vnext_grant.as_mut() else {
            continue;
        };
        let Some(delegation) = grant.delegation.as_mut() else {
            continue;
        };
        let already = delegation.allowed_children.iter().any(|child| {
            matches!(
                child,
                AllowedChild::PortableRef { portable_agent_ref: existing }
                    if existing == portable_agent_ref
            )
        });
        if !already {
            delegation.allowed_children.push(AllowedChild::PortableRef {
                portable_agent_ref: portable_agent_ref.to_string(),
            });
        }
    }
}
