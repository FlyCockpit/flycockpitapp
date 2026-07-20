use super::*;
use std::time::{Duration, Instant};

#[cfg(unix)]
fn wait_for_file(path: &std::path::Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {}", path.display());
}

#[test]
fn build_test_check_commands_get_output_sidecars() {
    let outcome = ShellOutcome {
        stdout: b"full stdout".to_vec(),
        stderr: b"full stderr".to_vec(),
        exit: 1,
        signaled: false,
        success: false,
    };
    let sidecar = bash_output_sidecar(
        "cargo test --workspace",
        Path::new("/repo"),
        &outcome,
        "stderr:\nshort\nexit: 1\n",
        false,
    )
    .expect("build/test command gets sidecar even when display is not truncated");
    assert_eq!(sidecar.payload["command"], "cargo test --workspace");
    assert_eq!(sidecar.payload["stdout"], "full stdout");
    assert_eq!(sidecar.payload["stderr"], "full stderr");
    assert_eq!(sidecar.payload["display"]["truncated"], false);
}

#[test]
fn bash_description_mentions_cap_and_tmpdir_redirection() {
    let tool = BashTool::new();
    assert!(tool.description().contains("capped at 8 KB"));
    assert!(tool.description().contains("declare resources"));
    assert!(tool.description().contains("$TMPDIR"));
    let defensive = tool.defensive_description().unwrap();
    assert!(defensive.contains("declare `resources`"));
    assert!(defensive.contains("Display output caps at 8 KB"));
    assert!(defensive.contains("$TMPDIR"));
    assert!(defensive.contains("persistent workspace artifact"));
    assert!(!tool.description().contains("jaq"));
    assert!(!tool.description().contains("diverg"));
    assert!(!defensive.contains("jaq"));
    assert!(!defensive.contains("diverg"));
}

#[test]
fn jq_shim_is_skipped_only_for_actual_container_runs() {
    use crate::tools::sandbox_mode::SandboxMode;

    assert!(!should_prepare_jq_shim(false, SandboxMode::Container));
    assert!(!should_prepare_jq_shim(
        false,
        SandboxMode::ContainerReadonly
    ));
    assert!(should_prepare_jq_shim(true, SandboxMode::Container));
    assert!(should_prepare_jq_shim(true, SandboxMode::ContainerReadonly));
    assert!(should_prepare_jq_shim(false, SandboxMode::Sandbox));
    assert!(should_prepare_jq_shim(false, SandboxMode::Off));
}

#[test]
fn resources_schema_is_closed_and_matches_scheduler_permits() {
    let expected: Vec<String> = crate::config::extended::ResourceSchedulerPoolsConfig::default()
        .as_map()
        .into_keys()
        .collect();
    let tool = BashTool::new();

    for schema in [tool.parameters(), tool.defensive_parameters().unwrap()] {
        let resources = &schema["properties"]["resources"];
        assert_eq!(resources["type"], "object");
        assert_eq!(resources["additionalProperties"], false);

        let properties = resources["properties"].as_object().unwrap();
        let actual: Vec<String> = properties.keys().cloned().collect();
        assert_eq!(actual, expected);

        for name in &expected {
            let permit = &properties[name];
            assert_eq!(permit["type"], "integer", "{name} permit type");
            assert_eq!(permit["minimum"], 0, "{name} permit minimum");
        }
    }
}

/// A turn-cancel (ctrl+c) terminates a long-running `bash` command
/// promptly — the tool returns the cancelled marker in well under the
/// command's natural runtime — and the killed command's *descendant*
/// (spawned in the same process group) dies too, so a runaway test
/// runner can't outlive its turn.
#[tokio::test]
async fn cancel_kills_process_group_promptly() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    let tool = BashTool::new();

    // A descendant subshell touches a heartbeat file every 100ms. If the
    // process group is killed, the heartbeat stops; if only the immediate
    // `sh -c` died, the descendant would keep updating it.
    let heartbeat = tmp.path().join("heartbeat");
    let hb = heartbeat.to_string_lossy().to_string();
    let command = format!("( while true; do touch '{hb}'; sleep 0.1; done ) & sleep 30",);

    let cancel = ctx.cancel.clone();
    // Fire the cancel shortly after the command starts.
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();
    });

    let start = Instant::now();
    let out = tool
        .call(serde_json::json!({ "command": command }), &ctx)
        .await
        .expect("bash call returns");
    let elapsed = start.elapsed();
    canceller.await.unwrap();

    // Returned promptly (well under the 30s sleep) with the cancel marker.
    assert!(
        elapsed < Duration::from_secs(5),
        "cancel should return promptly, took {elapsed:?}"
    );
    assert!(
        out.content.contains("cancelled by user"),
        "expected cancel marker, got: {}",
        out.content
    );

    // Give the SIGTERM→SIGKILL window time to land, then confirm the
    // descendant heartbeat has stopped (process group was killed).
    tokio::time::sleep(Duration::from_millis(600)).await;
    let mtime_after_kill = std::fs::metadata(&heartbeat)
        .ok()
        .and_then(|m| m.modified().ok());
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mtime_later = std::fs::metadata(&heartbeat)
        .ok()
        .and_then(|m| m.modified().ok());
    assert_eq!(
        mtime_after_kill, mtime_later,
        "descendant heartbeat kept updating — process group was not killed"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn kill_child_skips_grace_when_sigterm_reaps_child() {
    let tmp = tempfile::tempdir().unwrap();
    let ready = tmp.path().join("ready");
    let script = format!(
        "trap 'exit 0' TERM; touch '{}'; while true; do sleep 1; done",
        ready.display()
    );
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c")
        .arg(script)
        .current_dir(tmp.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = cmd.spawn().unwrap();
    let pid = child.id();
    wait_for_file(&ready);

    let start = Instant::now();
    kill_child(&mut child, pid).await;

    assert!(
        start.elapsed() < Duration::from_millis(150),
        "clean SIGTERM exit should not wait out the grace timer"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn kill_child_sends_sigkill_after_grace_when_sigterm_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let ready = tmp.path().join("ready");
    let script = format!(
        "trap '' TERM; touch '{}'; while true; do sleep 1; done",
        ready.display()
    );
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c")
        .arg(script)
        .current_dir(tmp.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .process_group(0);
    let mut child = cmd.spawn().unwrap();
    let pid = child.id();
    wait_for_file(&ready);

    let start = Instant::now();
    let mut killer = tokio::spawn(async move {
        kill_child(&mut child, pid).await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !killer.is_finished(),
        "SIGKILL should wait for the grace timer"
    );
    tokio::time::timeout(Duration::from_secs(2), &mut killer)
        .await
        .expect("SIGKILL fallback should reap the child")
        .unwrap();
    assert!(
        start.elapsed() >= Duration::from_millis(200),
        "SIGKILL fallback should honor the grace timer"
    );
}

// ---- shell compression setting (implementation note) -

/// With shell compression ENABLED (the default once seeded), noisy bash
/// output is compressed before it enters context — cargo-style progress
/// (`Compiling …`) is stripped — while the error/warning diagnostics and
/// the non-zero `exit:` line SURVIVE intact. The signal-preservation
/// guarantee (priority #1) is the load-bearing assertion here.
#[tokio::test]
async fn compression_enabled_strips_noise_keeps_signal_and_exit() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    ctx.session
        .set_shell_compression(crate::config::extended::ShellCompression::Enabled);
    let tool = BashTool::new();
    // Emit cargo-shaped output then exit non-zero. The command line starts
    // with `cargo` so the per-command (rust) strategy is recognized.
    let script = "printf '%s\\n' \
            '   Compiling foo v0.1.0' \
            '   Compiling bar v0.2.0' \
            'warning: unused variable: x' \
            'error[E0382]: borrow of moved value' \
            '   Finished dev in 2.3s'; exit 2";
    let out = tool
        .call(
            serde_json::json!({ "command": format!("cargo build; {script}") }),
            &ctx,
        )
        .await
        .expect("bash call returns");
    let compressed_output = out
        .content
        .split("cockpit_command_environment:")
        .next()
        .unwrap_or(&out.content);
    // Noise stripped from command output. The environment diagnostic below
    // still echoes the exact attempted command, which may contain the same
    // words as shell-script arguments.
    assert!(
        !compressed_output.contains("Compiling foo"),
        "progress noise should be stripped, got: {}",
        out.content
    );
    assert!(!compressed_output.contains("Finished dev"));
    // Signal preserved.
    assert!(
        out.content.contains("error[E0382]"),
        "error diagnostic must survive, got: {}",
        out.content
    );
    assert!(out.content.contains("warning: unused variable"));
    // Non-zero exit context preserved.
    assert!(out.content.contains("exit: 2"), "got: {}", out.content);
}

/// With shell compression DISABLED, bash output is byte-for-byte the raw
/// command output — no line is stripped, deduped, or collapsed.
#[tokio::test]
async fn compression_disabled_returns_verbatim() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    ctx.session
        .set_shell_compression(crate::config::extended::ShellCompression::Disabled);
    let tool = BashTool::new();
    let script = "printf '%s\\n' \
            '   Compiling foo v0.1.0' \
            '   Compiling bar v0.2.0' \
            'warning: unused variable: x' \
            'error[E0382]: borrow of moved value' \
            '   Finished dev in 2.3s'";
    let out = tool
        .call(
            serde_json::json!({ "command": format!("cargo build; {script}") }),
            &ctx,
        )
        .await
        .expect("bash call returns");
    // Verbatim: even the progress noise is present unchanged.
    assert!(out.content.contains("Compiling foo v0.1.0"));
    assert!(out.content.contains("Compiling bar v0.2.0"));
    assert!(out.content.contains("Finished dev in 2.3s"));
    assert!(out.content.contains("error[E0382]"));
}

/// The compression boundary is exactly the `shell_compression_enabled`
/// flag: the SAME command yields stripped output when enabled and
/// verbatim output when disabled. Guards the toggle wiring end-to-end.
#[tokio::test]
async fn compression_toggle_changes_output() {
    let tmp = tempfile::tempdir().unwrap();
    let cmd = "cargo build; printf '   Compiling foo v0.1.0\\ndone\\n'";

    let ctx_on = crate::tools::common::test_ctx(tmp.path());
    ctx_on
        .session
        .set_shell_compression(crate::config::extended::ShellCompression::Enabled);
    let on = BashTool::new()
        .call(serde_json::json!({ "command": cmd }), &ctx_on)
        .await
        .unwrap();

    let ctx_off = crate::tools::common::test_ctx(tmp.path());
    ctx_off
        .session
        .set_shell_compression(crate::config::extended::ShellCompression::Disabled);
    let off = BashTool::new()
        .call(serde_json::json!({ "command": cmd }), &ctx_off)
        .await
        .unwrap();

    assert!(
        !on.content.contains("Compiling foo"),
        "enabled strips noise"
    );
    assert!(
        off.content.contains("Compiling foo"),
        "disabled keeps noise"
    );
    // Both keep the real content.
    assert!(on.content.contains("done"));
    assert!(off.content.contains("done"));
}

/// A normal (uncancelled) command still runs to completion and returns
/// its output + exit line, AND the authoritative structured `exit_code`
/// field (export-audit fidelity) matching the `exit: N` text.
#[tokio::test]
async fn normal_command_completes() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    let tool = BashTool::new();
    let out = tool
        .call(serde_json::json!({ "command": "printf hello" }), &ctx)
        .await
        .expect("bash call returns");
    assert!(out.content.contains("hello"), "got: {}", out.content);
    assert!(out.content.contains("exit: 0"), "got: {}", out.content);
    // Structured exit code is the authoritative source, set to the same
    // value the human-readable line carries.
    assert_eq!(out.exit_code, Some(0));
}

/// A non-zero exit is reported on the structured `exit_code` field as well
/// as the `exit: N` text line (export-audit fidelity, part c).
#[tokio::test]
async fn nonzero_exit_sets_structured_exit_code() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    let tool = BashTool::new();
    let out = tool
        .call(serde_json::json!({ "command": "exit 3" }), &ctx)
        .await
        .expect("bash call returns");
    assert!(out.content.contains("exit: 3"), "got: {}", out.content);
    assert_eq!(out.exit_code, Some(3));
}

// ---- run-fail-escalate decision logic (sandboxing part 2) -------------

use std::sync::Arc;

use crate::approval::Approver;
use crate::approval::ID_APPROVE_SESSION;
use crate::approval::classify::SimpleCommandInfo;
use crate::approval::store::{GrantStore, Scope};
use crate::daemon::proto::ResolveResponse;

/// Build a sandbox-enabled ctx with an approver + grant store.
fn ctx_with_store(cwd: &std::path::Path) -> ToolCtx {
    let db = crate::db::Db::open_in_memory().unwrap();
    let session =
        crate::session::Session::create(db.clone(), cwd.to_path_buf(), "builder").unwrap();
    session.set_sandbox_enabled(true);
    let sid = session.id;
    let locks = Arc::new(crate::locks::LockManager::from_db(db.clone()).unwrap());
    let cfg = crate::config::extended::RedactConfig::default();
    let redact = Arc::new(crate::redact::RedactionTable::build(&cfg, cwd).unwrap());
    let hub = Arc::new(crate::engine::interrupt::InterruptHub::detached());
    let store = GrantStore::new(db.clone(), sid, cwd.to_path_buf());
    let approver = Arc::new(Approver::new(store, db, sid, "builder", hub.clone()));
    ToolCtx {
        agent_id: "builder".to_string(),
        current_tool_call_id: None,
        llm_mode: crate::config::extended::LlmMode::Normal,
        locks,
        session: Arc::new(session),
        cwd: cwd.to_path_buf(),
        redact,
        interrupts: hub,
        cancel: tokio_util::sync::CancellationToken::new(),
        shutdown_gate: crate::daemon::shutdown::ShutdownSignal::new(),
        approver: Some(approver),
        deferred_log: crate::engine::deferred::DeferredLog::new(),
        seeds: crate::engine::seed_collector::SeedCollector::new(),
        root_agent_frame: true,
        skill_write_origin: crate::skills::manage::SkillWriteOrigin::Foreground,
        review_cage: None,
        context_usage: None,
        available_tools: Arc::new(std::collections::HashSet::new()),
        has_tree: false,
        has_bash: false,
        events: None,
        lsp: None,
        resource_scheduler: None,
        env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
    }
}

fn scheduler(cpu: u32, memory: u32) -> Arc<crate::engine::resource_scheduler::ResourceScheduler> {
    let mut cfg = crate::config::extended::ResourceSchedulerConfig::default();
    cfg.pools.cpu.capacity = cpu;
    cfg.pools.memory.capacity = memory;
    Arc::new(crate::engine::resource_scheduler::ResourceScheduler::new(
        cfg,
    ))
}

#[test]
fn user_path_grants_merge_into_sandbox_and_container_mount_plan() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("repo");
    let read_dir = tmp.path().join("read-dir");
    let write_dir = tmp.path().join("write-dir");
    for dir in [&project, &read_dir, &write_dir] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let ctx = ctx_with_store(&project);
    let store = GrantStore::new(ctx.session.db.clone(), ctx.session.id, ctx.cwd.clone());
    store
        .record_path(
            &read_dir,
            Scope::Session,
            crate::tools::shell_sandbox::SandboxPathAccess::Read,
        )
        .unwrap();
    store
        .record_path(
            &write_dir,
            Scope::Session,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .unwrap();

    let plan = command_resource_plan_with_user_grants(
        crate::tools::command_resource_profiles::CommandResourcePlan::default(),
        &ctx,
    );
    assert!(plan.allow_paths.iter().any(|path| {
        path.kind == "user_grant"
            && path.path == read_dir
            && path.access == crate::tools::shell_sandbox::SandboxPathAccess::Read
    }));
    assert!(plan.allow_paths.iter().any(|path| {
        path.kind == "user_grant"
            && path.path == write_dir
            && path.access == crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite
    }));

    let map = crate::container::MountMap::unix(project);
    let mounts = crate::container::resource_profile_mounts(&plan, &map, false);
    assert!(
        mounts
            .iter()
            .any(|mount| mount.host == read_dir && mount.read_only)
    );
    assert!(
        mounts
            .iter()
            .any(|mount| mount.host == write_dir && !mount.read_only)
    );
}

fn ctx_with_scheduler(
    cwd: &std::path::Path,
    scheduler: Arc<crate::engine::resource_scheduler::ResourceScheduler>,
) -> ToolCtx {
    let mut ctx = crate::tools::common::test_ctx(cwd);
    ctx.resource_scheduler = Some(scheduler);
    ctx
}

#[test]
fn resource_policy_matches_and_merges_by_max() {
    let mut cfg = crate::config::extended::ResourceSchedulerConfig::default();
    cfg.rules
        .push(crate::config::extended::ResourceSchedulerRuleConfig {
            approval_key: Some("cargo test".to_string()),
            resources: BTreeMap::from([("cpu".to_string(), 2), ("memory".to_string(), 1)]),
            ..crate::config::extended::ResourceSchedulerRuleConfig::default()
        });
    cfg.rules
        .push(crate::config::extended::ResourceSchedulerRuleConfig {
            regex: Some("--locked".to_string()),
            resources: BTreeMap::from([("cpu".to_string(), 1), ("memory".to_string(), 3)]),
            ..crate::config::extended::ResourceSchedulerRuleConfig::default()
        });
    let classification = crate::approval::classify::classify("cargo test --locked");
    let plan = build_resource_plan(
        BTreeMap::from([("cpu".to_string(), 1)]),
        &cfg,
        "cargo test --locked",
        &classification,
        Some(50),
    );
    assert_eq!(plan.effective.get("cpu"), Some(&2));
    assert_eq!(plan.effective.get("memory"), Some(&3));
    assert_eq!(plan.queue_timeout_ms, Some(50));
}

#[test]
fn resource_policy_structured_fields_are_conjunctive() {
    let mut cfg = crate::config::extended::ResourceSchedulerConfig::default();
    cfg.rules
        .push(crate::config::extended::ResourceSchedulerRuleConfig {
            program: Some("cargo".to_string()),
            subcommand: Some("test".to_string()),
            resources: BTreeMap::from([("cpu".to_string(), 2)]),
            ..crate::config::extended::ResourceSchedulerRuleConfig::default()
        });
    cfg.rules
        .push(crate::config::extended::ResourceSchedulerRuleConfig {
            program: Some("npm".to_string()),
            subcommand: Some("build".to_string()),
            regex: Some("npm test".to_string()),
            resources: BTreeMap::from([("memory".to_string(), 1)]),
            ..crate::config::extended::ResourceSchedulerRuleConfig::default()
        });

    let cargo_test = crate::approval::classify::classify("cargo test --locked");
    assert_eq!(
        policy_resource_requirements(&cfg, "cargo test --locked", &cargo_test).get("cpu"),
        Some(&2)
    );

    let npm_test = crate::approval::classify::classify("npm test");
    let npm_policy = policy_resource_requirements(&cfg, "npm test", &npm_test);
    assert!(!npm_policy.contains_key("cpu"));
    assert_eq!(npm_policy.get("memory"), Some(&1));
}

#[tokio::test]
async fn bash_without_effective_resources_bypasses_scheduler() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    let out = BashTool::new()
        .call(serde_json::json!({ "command": "printf ok" }), &ctx)
        .await
        .unwrap();
    assert!(out.content.contains("ok"));
    assert!(out.resource.is_none());
}

#[tokio::test]
async fn bash_resource_over_capacity_returns_model_error() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_scheduler(tmp.path(), scheduler(1, 1));
    let out = BashTool::new()
        .call(
            serde_json::json!({
                "command": "printf nope",
                "resources": { "cpu": 2, "memory": 1 }
            }),
            &ctx,
        )
        .await
        .unwrap();
    assert!(
        out.content
            .contains("requested resources exceed scheduler capacity")
    );
    assert_eq!(out.resource.unwrap().effective.get("cpu"), Some(&2));
}

#[tokio::test]
async fn bash_queue_timeout_cancels_wait_without_spawning() {
    let tmp = tempfile::tempdir().unwrap();
    let scheduler = scheduler(1, 1);
    let hold = scheduler
        .acquire(
            crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                crate::engine::resource_scheduler::ResourceRequirements::new([
                    ("cpu", 1),
                    ("memory", 1),
                ]),
            ),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
    let ctx = ctx_with_scheduler(tmp.path(), scheduler.clone());
    let out = BashTool::new()
        .call(
            serde_json::json!({
                "command": "touch should-not-exist",
                "resources": { "cpu": 1, "memory": 1 },
                "queue_timeout_ms": 10
            }),
            &ctx,
        )
        .await
        .unwrap();
    assert!(out.content.contains("resource scheduler queue timeout"));
    assert!(!tmp.path().join("should-not-exist").exists());
    assert!(scheduler.snapshot().queued.is_empty());
    drop(hold);
}

#[tokio::test]
async fn bash_cancel_while_queued_removes_scheduler_request() {
    let tmp = tempfile::tempdir().unwrap();
    let scheduler = scheduler(1, 1);
    let _hold = scheduler
        .acquire(
            crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                crate::engine::resource_scheduler::ResourceRequirements::new([
                    ("cpu", 1),
                    ("memory", 1),
                ]),
            ),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
    let ctx = ctx_with_scheduler(tmp.path(), scheduler.clone());
    ctx.cancel.cancel();
    let out = BashTool::new()
        .call(
            serde_json::json!({
                "command": "printf nope",
                "resources": { "cpu": 1, "memory": 1 }
            }),
            &ctx,
        )
        .await
        .unwrap();
    assert!(out.content.contains("cancelled while waiting"));
    assert!(scheduler.snapshot().queued.is_empty());
}

#[tokio::test]
async fn bash_runtime_timeout_starts_after_resource_acquire() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_scheduler(tmp.path(), scheduler(1, 1));
    let out = BashTool::new()
        .call(
            serde_json::json!({
                "command": "sleep 1",
                "timeout_ms": 1,
                "queue_timeout_ms": 1000,
                "resources": { "cpu": 1, "memory": 1 }
            }),
            &ctx,
        )
        .await
        .unwrap();
    assert!(out.content.contains("timeout after 1 ms"));
    let meta = out.resource.unwrap();
    assert!(meta.acquired);
    assert!(meta.wait_ms.is_some());
}

async fn resolve_next_interrupt(
    db: crate::db::Db,
    sid: uuid::Uuid,
    hub: Arc<crate::engine::interrupt::InterruptHub>,
    selected_id: &'static str,
    exclude: Option<uuid::Uuid>,
) -> uuid::Uuid {
    let iid = loop {
        let open = db.list_open_interrupts(sid).unwrap();
        if let Some(row) = open.iter().find(|row| Some(row.interrupt_id) != exclude) {
            break row.interrupt_id;
        }
        tokio::task::yield_now().await;
    };
    assert!(hub.resolve(
        iid,
        ResolveResponse::Single {
            selected_id: selected_id.into(),
        }
    ));
    iid
}

async fn approve_next_path_prompt(ctx: &ToolCtx) {
    resolve_next_interrupt(
        ctx.session.db.clone(),
        ctx.session.id,
        ctx.interrupts.clone(),
        ID_APPROVE_SESSION,
        None,
    )
    .await;
}

async fn deny_next_path_prompt(ctx: &ToolCtx) {
    let iid = loop {
        let open = ctx.session.db.list_open_interrupts(ctx.session.id).unwrap();
        if let Some(row) = open.first() {
            break row.interrupt_id;
        }
        tokio::task::yield_now().await;
    };
    assert!(ctx.interrupts.resolve(iid, ResolveResponse::Cancel));
}

#[tokio::test]
async fn bash_child_receives_session_env_overlay() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    ctx.session.set_sandbox_enabled(false);
    ctx.env_overlay.write().unwrap().insert(
        "COCKPIT_REFRESH_TEST_VALUE".to_string(),
        "sk-session".to_string(),
    );
    let out = BashTool::new()
        .call(
            serde_json::json!({ "command": "printf '%s' \"$COCKPIT_REFRESH_TEST_VALUE\"" }),
            &ctx,
        )
        .await
        .expect("bash call returns");
    assert!(out.content.contains("sk-session"));
    assert!(out.content.contains("exit: 0"));
}

#[tokio::test]
async fn bash_child_does_not_receive_aws_access_key_from_parent_env() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    ctx.session.set_sandbox_enabled(false);
    let previous = std::env::var("AWS_ACCESS_KEY_ID").ok();
    unsafe {
        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIATESTSECRET");
    }
    let out = BashTool::new()
            .call(
                serde_json::json!({
                    "command": "if [ -z \"${AWS_ACCESS_KEY_ID+x}\" ]; then printf scrubbed; else printf '%s' \"$AWS_ACCESS_KEY_ID\"; fi"
                }),
                &ctx,
            )
            .await
            .expect("bash call returns");
    match previous {
        Some(value) => unsafe {
            std::env::set_var("AWS_ACCESS_KEY_ID", value);
        },
        None => unsafe {
            std::env::remove_var("AWS_ACCESS_KEY_ID");
        },
    }
    assert!(out.content.contains("scrubbed"), "{}", out.content);
    assert!(!out.content.contains("AKIATESTSECRET"), "{}", out.content);
}

#[test]
fn command_directory_escape_detects_literal_absolute_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    std::fs::create_dir_all(&root).unwrap();
    let inside = root.join("file");
    std::fs::write(&inside, "ok").unwrap();
    assert_eq!(
        command_directory_escape("cat /etc/passwd", &root, &root, None).as_deref(),
        Some(Path::new("/etc/passwd"))
    );
    assert!(
        command_directory_escape(&format!("cat {}", inside.display()), &root, &root, None)
            .is_none()
    );
}

#[test]
fn command_directory_escape_detects_relative_path_operands() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    let cwd = root.join("sub");
    std::fs::create_dir_all(&cwd).unwrap();
    let outside = tmp.path().join("outside");
    std::fs::write(&outside, "secret").unwrap();

    assert_eq!(
        command_directory_escape("cat ../../outside", &cwd, &root, None).as_deref(),
        Some(outside.as_path())
    );
}

#[test]
fn command_directory_escape_detects_quoted_relative_path_operands() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    let cwd = root.join("sub");
    std::fs::create_dir_all(&cwd).unwrap();
    let outside = tmp.path().join("outside secret");
    std::fs::write(&outside, "secret").unwrap();

    assert_eq!(
        command_directory_escape(r#"cat "../../outside secret""#, &cwd, &root, None).as_deref(),
        Some(outside.as_path())
    );
}

#[test]
fn command_directory_escape_detects_symlink_dotdot_operands() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("project");
    std::fs::create_dir_all(&root).unwrap();
    let outside_parent = tempfile::tempdir().unwrap();
    let outside_child = outside_parent.path().join("child");
    std::fs::create_dir(&outside_child).unwrap();
    let outside = outside_parent.path().join("secret.txt");
    std::fs::write(&outside, "secret").unwrap();
    let link = root.join("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside_child, &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&outside_child, &link).unwrap();

    assert_eq!(
        command_directory_escape("cat link/../secret.txt", &root, &root, None).as_deref(),
        Some(outside.as_path())
    );
}

#[test]
fn shell_write_targets_detect_redirection_heredoc_tee_and_multiple_files() {
    let root = Path::new("/workspace/project");
    assert_eq!(
        shell_write_targets("cat > scratch/staged/x.md <<EOF\nbody\nEOF", root),
        ShellWriteTargets::Concrete(vec![root.join("scratch/staged/x.md")])
    );
    assert_eq!(
        shell_write_targets("printf x > nested/x.txt", root),
        ShellWriteTargets::Concrete(vec![root.join("nested/x.txt")])
    );
    assert_eq!(
        shell_write_targets("tee scratch/staged/x.md", root),
        ShellWriteTargets::Concrete(vec![root.join("scratch/staged/x.md")])
    );
    assert_eq!(
        shell_write_targets("printf a > a.txt && printf b > b.txt", root),
        ShellWriteTargets::Concrete(vec![root.join("a.txt"), root.join("b.txt")])
    );
}

#[test]
fn shell_write_targets_ignore_redirect_like_heredoc_body_lines() {
    let root = Path::new("/workspace/project");
    assert_eq!(
        shell_write_targets("cat <<EOF\n> /etc/passwd\nEOF", root),
        ShellWriteTargets::None
    );
    assert_eq!(
        shell_write_targets(
            "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: /tmp/x\n> /\n*** End Patch\nPATCH",
            root,
        ),
        ShellWriteTargets::None
    );
    assert_eq!(
        shell_write_targets("cat <<EOF > /real/file\n> /etc/passwd\nEOF", root),
        ShellWriteTargets::Concrete(vec![PathBuf::from("/real/file")])
    );
}

#[test]
fn shell_write_tokens_handle_quoted_and_tab_stripped_heredocs() {
    assert_eq!(
        shell_write_content_preview_inner("cat <<'EOF' > out.txt\nbody > /\nEOF"),
        ShellWriteContentPreview::Literal("body > /\n".to_string())
    );
    assert_eq!(
        shell_write_content_preview_inner("cat <<-EOF > out.txt\n\tbody\n\tEOF"),
        ShellWriteContentPreview::Literal("body\n".to_string())
    );
    assert_eq!(
        shell_write_targets(
            "cat <<< hello > /real/path",
            Path::new("/workspace/project")
        ),
        ShellWriteTargets::Concrete(vec![PathBuf::from("/real/path")])
    );
}

#[test]
fn shell_write_targets_do_not_fabricate_dynamic_paths() {
    let root = Path::new("/workspace/project");
    assert_eq!(
        shell_write_targets(r#"cat > "$OUT""#, root),
        ShellWriteTargets::Dynamic
    );
    assert_eq!(
        shell_write_targets("printf x > logs/*.txt", root),
        ShellWriteTargets::Dynamic
    );
}

#[test]
fn shell_write_content_preview_preserves_literal_words() {
    assert_eq!(
        shell_write_content_preview_inner(r#"echo "a > b" > out.txt"#),
        ShellWriteContentPreview::Literal("a > b\n".to_string())
    );
    assert_eq!(
        shell_write_content_preview_inner(r#"echo "a   b" > out.txt"#),
        ShellWriteContentPreview::Literal("a   b\n".to_string())
    );
    assert_eq!(
        shell_write_content_preview_inner("echo -n hello > out.txt"),
        ShellWriteContentPreview::Literal("hello".to_string())
    );
    assert_eq!(
        shell_write_content_preview_inner("echo hello > out.txt"),
        ShellWriteContentPreview::Literal("hello\n".to_string())
    );
}

#[test]
fn shell_write_content_preview_keeps_printf_and_dynamic_fallback() {
    assert_eq!(
        shell_write_content_preview_inner("printf hello > out.txt"),
        ShellWriteContentPreview::Literal("hello".to_string())
    );
    assert_eq!(
        shell_write_content_preview("somecmd > out.txt"),
        crate::daemon::proto::WriteContentPreview {
            content: "(output of `somecmd`)".to_string(),
            dynamic: true,
        }
    );
}

// ---- bash cwd session-boundary gate ----------------------------------

#[tokio::test]
async fn default_cwd_runs_at_session_root() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    let out = BashTool::new()
        .call(serde_json::json!({ "command": "pwd" }), &ctx)
        .await
        .expect("bash call returns");
    assert!(out.content.contains(&tmp.path().display().to_string()));
    assert_eq!(out.exit_code, Some(0));
}

#[tokio::test]
async fn explicit_inside_cwd_runs() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("src")).unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    let out = BashTool::new()
        .call(serde_json::json!({ "command": "pwd", "cwd": "src" }), &ctx)
        .await
        .expect("bash call returns");
    assert!(
        out.content
            .contains(&tmp.path().join("src").display().to_string())
    );
    assert_eq!(out.exit_code, Some(0));
}

#[tokio::test]
async fn denied_outside_cwd_prevents_execution() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    ctx.session.set_sandbox_enabled(false);
    let marker = tmp.path().join("marker");
    let deny = {
        let ctx = ctx.clone();
        tokio::spawn(async move { deny_next_path_prompt(&ctx).await })
    };
    let out = BashTool::new()
        .call(
            serde_json::json!({
                "command": format!("touch '{}'", marker.display()),
                "cwd": "..",
            }),
            &ctx,
        )
        .await
        .expect_err("denied outside cwd returns an error");
    deny.await.unwrap();
    assert!(
        out.to_string()
            .contains("command working directory resolves outside")
    );
    assert!(
        !marker.exists(),
        "command must not run after denied cwd approval"
    );
}

#[tokio::test]
async fn approved_outside_cwd_executes() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    ctx.session.set_sandbox_enabled(false);
    let parent = tmp.path().parent().unwrap().to_path_buf();
    let approve = {
        let ctx = ctx.clone();
        tokio::spawn(async move { approve_next_path_prompt(&ctx).await })
    };
    let out = BashTool::new()
        .call(serde_json::json!({ "command": "pwd", "cwd": ".." }), &ctx)
        .await
        .expect("approved outside cwd runs");
    approve.await.unwrap();
    assert!(out.content.contains(&parent.display().to_string()));
    assert_eq!(out.exit_code, Some(0));
}

#[tokio::test]
async fn cd_inside_root_is_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("subdir")).unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    let out = BashTool::new()
        .call(serde_json::json!({ "command": "cd subdir && pwd" }), &ctx)
        .await
        .expect("bash call returns");
    assert!(
        out.content
            .contains(&tmp.path().join("subdir").display().to_string())
    );
}

#[tokio::test]
async fn cd_escape_triggers_approval_before_execution() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    ctx.session.set_sandbox_enabled(false);
    let marker = tmp.path().join("marker");
    let deny = {
        let ctx = ctx.clone();
        tokio::spawn(async move { deny_next_path_prompt(&ctx).await })
    };
    let out = BashTool::new()
        .call(
            serde_json::json!({ "command": format!("cd .. && touch '{}'", marker.display()) }),
            &ctx,
        )
        .await
        .expect_err("denied cd escape returns an error");
    deny.await.unwrap();
    assert!(
        out.to_string()
            .contains("command working directory resolves outside")
    );
    assert!(
        !marker.exists(),
        "command must not run after denied cd approval"
    );
}

#[tokio::test]
async fn pushd_escape_triggers_approval_before_execution() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    ctx.session.set_sandbox_enabled(false);
    let marker = tmp.path().join("marker");
    let deny = {
        let ctx = ctx.clone();
        tokio::spawn(async move { deny_next_path_prompt(&ctx).await })
    };
    let out = BashTool::new()
        .call(
            serde_json::json!({ "command": format!("pushd .. && touch '{}'", marker.display()) }),
            &ctx,
        )
        .await
        .expect_err("denied pushd escape returns an error");
    deny.await.unwrap();
    assert!(
        out.to_string()
            .contains("command working directory resolves outside")
    );
    assert!(
        !marker.exists(),
        "command must not run after denied pushd approval"
    );
}

#[tokio::test]
async fn dotdot_as_data_is_not_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    let out = BashTool::new()
        .call(
            serde_json::json!({ "command": "printf '%s\\n' '../data'" }),
            &ctx,
        )
        .await
        .expect("data-only dotdot does not require approval");
    assert!(out.content.contains("../data"));
    assert_eq!(out.exit_code, Some(0));
}

#[tokio::test]
async fn granted_broad_skips_the_box() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    let approver = ctx.approver.as_ref().unwrap();
    // Not yet granted → must run sandboxed.
    assert!(!command_granted_broad(&ctx, "cargo build --release").await);
    // Grant `cargo build` at Session scope.
    let info = SimpleCommandInfo {
        program: "cargo".into(),
        normalized_program: "cargo".into(),
        subcommand: Some("build".into()),
        key: crate::approval::classify::ApprovalKey {
            program: "cargo".into(),
            subcommand: Some("build".into()),
        },
        wrapper: false,
        risk: Default::default(),
        span: None,
    };
    approver
        .store()
        .record_command(&info, Scope::Session)
        .unwrap();
    // Now the same command is granted broad → skip the box.
    assert!(command_granted_broad(&ctx, "cargo build --release").await);
    // A different subcommand is still ungranted → run sandboxed.
    assert!(!command_granted_broad(&ctx, "cargo test").await);
}

#[tokio::test]
async fn risky_grant_above_policy_cap_does_not_skip_the_box() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    let approver = ctx.approver.as_ref().unwrap();
    let info = crate::approval::classify::classify("rm foo").simple_commands()[0].clone();
    approver
        .store()
        .record_command(&info, Scope::Session)
        .unwrap();

    assert!(
        approver.store().is_command_granted(&info.key),
        "the legacy broad grant exists"
    );
    assert!(
        !command_granted_broad(&ctx, "rm foo").await,
        "destructive commands are capped to once by policy"
    );
}

#[tokio::test]
async fn wrapper_never_skips_the_box() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    // A wrapper can't be persisted, so it can never be "granted
    // broad" -> always runs sandboxed (and re-prompts on failure).
    assert!(!command_granted_broad(&ctx, "bash -c 'echo hi'").await);
    assert!(
        !command_granted_broad(&ctx, r#"sh -c "printf permission""#).await,
        "quoted shell wrappers must not skip confinement"
    );
    assert!(
        !command_granted_broad(&ctx, r#"env FOO=bar bash -lc 'printf hi'"#).await,
        "dynamic env wrappers must not skip confinement"
    );
    assert!(!command_granted_broad(&ctx, "sudo rm x").await);
}

#[tokio::test]
async fn no_approver_never_skips_the_box() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    // No approver → can't know any grant → run sandboxed.
    assert!(!command_granted_broad(&ctx, "ls").await);
}

// ---- Part B: tool_call `sandbox` sub-object across the four states ----

/// Sandbox-OFF: `test_ctx` defaults sandboxing off, so a real command
/// runs unconfined and the sub-object records the off state with no
/// escalation. Model-facing body is the plain command output.
#[tokio::test]
async fn sandbox_meta_records_sandbox_off_state() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    let tool = BashTool::new();
    let out = tool
        .call(serde_json::json!({ "command": "printf hi" }), &ctx)
        .await
        .expect("bash call returns");
    let meta = out.sandbox.expect("bash always populates sandbox meta");
    assert!(!meta.enabled, "sandbox off → not enabled");
    assert!(!meta.confined);
    assert!(!meta.escalated);
    assert!(!meta.broad_grant_simple_commands);
    assert!(meta.approval_scope_recorded.is_none());
    // Model-facing body unchanged: only the command output, no note.
    assert!(out.content.contains("hi"));
    assert!(!out.content.to_lowercase().contains("sandbox"));
}

/// BROAD-GRANT-SKIP: sandboxing on, but every simple command is already
/// granted broad, so the box is skipped and the command runs unconfined
/// (no live confinement needed). The sub-object records
/// `broad_grant_simple_commands = true`, `confined = false`, and (on a
/// platform where the sandbox backend exists) `enabled = true`.
#[tokio::test]
async fn sandbox_meta_records_broad_grant_skip_state() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    let approver = ctx.approver.as_ref().unwrap();
    let command = "printf hi";
    // Pre-grant exactly the classified key for `command` so every simple
    // command is granted broad → `command_granted_broad` is true →
    // `confine` is false → the run is UNCONFINED (no live confined spawn,
    // which would re-exec the test binary as the zerobox helper). We
    // grant the parser's own key so the match is exact regardless of how
    // `printf hi` decomposes.
    let classification = crate::approval::classify::classify(command);
    for info in classification.simple_commands() {
        approver
            .store()
            .record_command(info, Scope::Session)
            .unwrap();
    }
    // Sanity: the grant makes the box skippable on a sandbox-supported
    // platform (so the live call below never confines).
    let supported = crate::tools::shell_sandbox::shell_sandbox_supported();
    if supported {
        assert!(
            command_granted_broad(&ctx, command).await,
            "granting the classified key makes the command broad-granted"
        );
    }

    let tool = BashTool::new();
    let out = tool
        .call(serde_json::json!({ "command": command }), &ctx)
        .await
        .expect("bash call returns");
    let meta = out.sandbox.expect("bash always populates sandbox meta");
    // `enabled` mirrors sandbox_on (session-on AND platform supports it).
    assert_eq!(meta.enabled, supported, "enabled mirrors sandbox_on");
    // On a sandbox-supported platform the broad grant skips the box.
    if supported {
        assert!(
            meta.broad_grant_simple_commands,
            "every simple command granted broad → box skipped"
        );
    }
    // Either way the run was not confined (off → never; broad-grant → skip).
    assert!(!meta.confined, "broad-grant skip never confines");
    assert!(!meta.escalated);
    assert!(meta.approval_scope_recorded.is_none());
    assert!(out.content.contains("hi"));
}

// NOTE: the two CONFINED states (confined-success and
// confined-fail→escalate) can't be exercised end-to-end through
// `bash::call`: a live confined spawn re-execs this test binary as the
// `zerobox-linux-sandbox` helper, which only works from a binary whose
// `main` ran `arg0::dispatch_linux_sandbox_helper` first (the test
// harness `main` does not). Per the existing convention we cover the
// confined-fail→escalate APPROVAL/dialog flow at the approver layer
// (`escalate_approve_*` / `escalate_deny_*` below) — the exact
// `approve_command_escalated` call `bash::call` makes — and the
// sub-object's `confined`/`escalated`/`approval_scope_recorded` mapping
// is asserted there + in the bash-side state tests above.

// ---- escalate→approve / escalate→deny dialog paths --------------------

use crate::daemon::proto::{InterruptQuestion, SandboxEscalation};

/// Pull the sandbox-escalation block off the open interrupt with `iid`.
fn open_escalation(
    db: &crate::db::Db,
    sid: uuid::Uuid,
    iid: uuid::Uuid,
) -> Option<SandboxEscalation> {
    let open = db.list_open_interrupts(sid).unwrap();
    let row = open.iter().find(|r| r.interrupt_id == iid)?;
    let set = row.questions.as_ref()?;
    match set.questions.first()? {
        InterruptQuestion::Single {
            sandbox_escalation, ..
        } => sandbox_escalation.clone(),
        _ => None,
    }
}

#[tokio::test]
async fn defensive_human_escalation_offer_is_run_once_or_deny_only() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = ctx_with_store(tmp.path());
    ctx.llm_mode = crate::config::extended::LlmMode::Defensive;
    ctx.session.set_sandbox_escalation_enabled(true);
    ctx.session
        .set_approval_mode(crate::config::extended::ApprovalMode::Manual);

    let db = ctx.session.db.clone();
    let sid = ctx.session.id;
    let hub = ctx.interrupts.clone();
    let cwd = tmp.path().display().to_string();
    let resolver = tokio::spawn(async move {
        let iid = loop {
            let open = db.list_open_interrupts(sid).unwrap();
            if let Some(row) = open.first() {
                break row.interrupt_id;
            }
            tokio::task::yield_now().await;
        };
        let open = db.list_open_interrupts(sid).unwrap();
        let row = open
            .iter()
            .find(|row| row.interrupt_id == iid)
            .expect("open interrupt row");
        let set = row.questions.as_ref().expect("questions present");
        let InterruptQuestion::Single {
            options,
            command_detail,
            sandbox_escalation,
            ..
        } = &set.questions[0]
        else {
            panic!("expected single escalation question");
        };
        let ids = options
            .iter()
            .map(|option| option.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                crate::approval::ID_ESCALATE_RUN_UNCONFINED_ONCE,
                crate::approval::ID_REJECT,
            ]
        );
        let detail = command_detail.as_ref().expect("command detail");
        assert_eq!(detail.full_command, "printf confined");
        assert_eq!(detail.cwd.as_deref(), Some(cwd.as_str()));
        assert_eq!(detail.offered_scopes, vec!["once"]);
        assert_eq!(detail.policy_cap.as_deref(), Some("once"));
        let esc = sandbox_escalation.as_ref().expect("escalation detail");
        assert_eq!(esc.confined_exit, 17);
        assert_eq!(esc.confined_stderr, "permission denied");
        assert!(esc.suggested_paths.is_empty());
        assert!(esc.suggested_access.is_none());
        assert!(hub.resolve(
            iid,
            crate::daemon::proto::ResolveResponse::Single {
                selected_id: crate::approval::ID_REJECT.into(),
            }
        ));
    });

    let decision = defensive_human_escalation_offer(
        serde_json::json!({ "command": "printf confined" }),
        "printf confined",
        tmp.path(),
        17,
        "permission denied".to_string(),
        &ctx,
    )
    .await
    .unwrap();
    resolver.await.unwrap();
    assert!(decision.is_none(), "deny leaves original failure in place");
}

#[tokio::test]
async fn defensive_human_escalation_offer_yolo_runs_unconfined_once() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = ctx_with_store(tmp.path());
    ctx.llm_mode = crate::config::extended::LlmMode::Defensive;
    ctx.session.set_sandbox_escalation_enabled(true);
    ctx.session
        .set_approval_mode(crate::config::extended::ApprovalMode::Yolo);
    ctx.approver = None;

    let out = defensive_human_escalation_offer(
        serde_json::json!({ "command": "printf yolo" }),
        "printf yolo",
        tmp.path(),
        1,
        "sandbox unavailable".to_string(),
        &ctx,
    )
    .await
    .unwrap()
    .expect("yolo reruns");
    assert!(out.content.contains("yolo"), "got: {}", out.content);
    let meta = out.sandbox.expect("sandbox meta");
    assert!(meta.enabled);
    assert!(!meta.confined);
    assert!(meta.escalated);
}

#[tokio::test]
async fn defensive_human_escalation_offer_auto_prompts_human() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = ctx_with_store(tmp.path());
    ctx.llm_mode = crate::config::extended::LlmMode::Defensive;
    ctx.session.set_sandbox_escalation_enabled(true);
    ctx.session
        .set_approval_mode(crate::config::extended::ApprovalMode::Auto);

    let db = ctx.session.db.clone();
    let sid = ctx.session.id;
    let hub = ctx.interrupts.clone();
    let resolver = tokio::spawn(async move {
        let iid = loop {
            let open = db.list_open_interrupts(sid).unwrap();
            if let Some(row) = open.first() {
                break row.interrupt_id;
            }
            tokio::task::yield_now().await;
        };
        assert!(hub.resolve(
            iid,
            crate::daemon::proto::ResolveResponse::Single {
                selected_id: crate::approval::ID_ESCALATE_RUN_UNCONFINED_ONCE.into(),
            }
        ));
    });

    let out = defensive_human_escalation_offer(
        serde_json::json!({ "command": "printf auto" }),
        "printf auto",
        tmp.path(),
        1,
        "sandbox unavailable".to_string(),
        &ctx,
    )
    .await
    .unwrap()
    .expect("auto prompts and approval reruns");
    resolver.await.unwrap();
    assert!(out.content.contains("auto"), "got: {}", out.content);
    assert!(out.sandbox.expect("sandbox meta").escalated);
}

/// escalate→APPROVE (session scope): the escalation prompt is the
/// distinct variant (carries the confined exit + stderr), the user
/// approves at session scope, and the decision returns that scope — the
/// value `bash::call` records as `approval_scope_recorded`. The grant is
/// persisted (the silent-skip cascade the dialog warns about).
#[tokio::test]
async fn escalate_approve_session_carries_confined_detail_and_records_scope() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    let approver = ctx.approver.as_ref().unwrap().clone();
    let db = ctx.session.db.clone();
    let sid = ctx.session.id;
    let hub = ctx.interrupts.clone();

    let resolver = tokio::spawn(async move {
        // The approval prompt carries the distinct escalation block and
        // resolves directly to a scoped action.
        let iid = loop {
            let open = db.list_open_interrupts(sid).unwrap();
            if let Some(row) = open.first() {
                break row.interrupt_id;
            }
            tokio::task::yield_now().await;
        };
        let esc = open_escalation(&db, sid, iid).expect("escalation block present");
        assert_eq!(esc.confined_exit, 13);
        assert!(esc.confined_stderr.contains("Permission denied"));
        assert!(hub.resolve(
            iid,
            crate::daemon::proto::ResolveResponse::Single {
                selected_id: crate::approval::ID_APPROVE_SESSION.into(),
            }
        ));
    });

    let decision = approver
        .approve_command_escalated("cat /etc/secret", 13, "cat: Permission denied".into())
        .await
        .unwrap();
    resolver.await.unwrap();
    assert_eq!(
        decision,
        crate::approval::Decision::Allow {
            scope: Scope::Session
        }
    );
    // The grant is now remembered → future runs skip the box silently.
    let key = crate::approval::classify::ApprovalKey {
        program: "cat".into(),
        subcommand: None,
    };
    assert!(approver.store().is_command_granted(&key));
}

/// escalate→DENY: the user rejects the unconfined re-run. The decision
/// is `Deny`, so `bash::call` keeps the original confined failure and
/// records `approval_scope_recorded = null` while still marking
/// `escalated = true` / `confined = true` (asserted via the bash-side
/// branch contract: a denied escalation never records a scope).
#[tokio::test]
async fn escalate_deny_keeps_confined_failure_and_records_no_scope() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = ctx_with_store(tmp.path());
    let approver = ctx.approver.as_ref().unwrap().clone();
    let db = ctx.session.db.clone();
    let sid = ctx.session.id;
    let hub = ctx.interrupts.clone();

    let resolver = tokio::spawn(async move {
        let iid = loop {
            let open = db.list_open_interrupts(sid).unwrap();
            if let Some(row) = open.first() {
                break row.interrupt_id;
            }
            tokio::task::yield_now().await;
        };
        assert!(hub.resolve(iid, crate::daemon::proto::ResolveResponse::Cancel));
    });

    let decision = approver
        .approve_command_escalated("cat /etc/secret", 13, "denied".into())
        .await
        .unwrap();
    resolver.await.unwrap();
    assert_eq!(decision, crate::approval::Decision::Deny);
    // Denied → nothing recorded; a later query still prompts.
    let key = crate::approval::classify::ApprovalKey {
        program: "cat".into(),
        subcommand: None,
    };
    assert!(!approver.store().is_command_granted(&key));
}

// NOTE: an end-to-end "runs confined and EPERMs an outside read" test
// is deliberately omitted. On Linux the zerobox path re-execs THIS
// test binary as the `zerobox-linux-sandbox` helper, which only works
// from a binary whose `main` ran `arg0::dispatch_linux_sandbox_helper`
// first — the test harness's `main` does not, so a confined spawn
// hangs/errors on helper re-entry. Per the build spec we therefore
// cover the Sandbox CONFIGURATION/command-building (see
// `shell_sandbox::tests::builds_confined_command`) and the
// run-fail-escalate DECISION logic (above) instead of live EPERM
// enforcement. The unconfined cancel/timeout/pgid path stays fully
// exercised by `cancel_kills_process_group_promptly` /
// `normal_command_completes` (test_ctx defaults sandbox OFF).

// ---- defensive routing nudge (defensive-tool-routing-behavioral-nudge) -

/// In `Defensive` mode a `cat` run appends the `read` routing tip after the
/// `exit:` line; the tip is model-facing body text, not a separate row.
#[tokio::test]
async fn defensive_cat_appends_read_tip() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = crate::tools::common::test_ctx(tmp.path());
    ctx.llm_mode = crate::config::extended::LlmMode::Defensive;
    let tool = BashTool::new();
    let out = tool
        .call(serde_json::json!({ "command": "cat foo.txt" }), &ctx)
        .await
        .expect("bash call returns");
    assert!(
        out.content.contains("tip: use `read <file>`"),
        "defensive cat must append the read tip, got: {}",
        out.content
    );
    // The tip sits after the `exit:` line (outside compression).
    let exit_pos = out.content.find("exit:").expect("exit line present");
    let tip_pos = out.content.find("tip:").expect("tip present");
    assert!(tip_pos > exit_pos, "tip must follow the exit line");
}

/// In `Normal` mode the SAME `cat` run appends nothing — the nudge is
/// defensive-mode-only (token economy §10).
#[tokio::test]
async fn normal_cat_appends_no_tip() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    // test_ctx defaults to Normal.
    assert!(matches!(
        ctx.llm_mode,
        crate::config::extended::LlmMode::Normal
    ));
    let tool = BashTool::new();
    let out = tool
        .call(serde_json::json!({ "command": "cat foo.txt" }), &ctx)
        .await
        .expect("bash call returns");
    assert!(
        !out.content.contains("tip:"),
        "normal mode must append no tip, got: {}",
        out.content
    );
}

#[tokio::test]
async fn durable_shell_write_appends_writeunlock_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    ctx.session.set_sandbox_enabled(false);
    let out = BashTool::new()
        .call(
            serde_json::json!({ "command": "printf hello > durable.txt" }),
            &ctx,
        )
        .await
        .expect("bash call returns");

    assert!(
        out.content.contains(SHELL_WRITE_NATIVE_TOOL_HINT),
        "{}",
        out.content
    );
}

/// Self-suppression: once the model has successfully used `read` this
/// session, a later defensive `cat` appends NO tip.
#[tokio::test]
async fn defensive_cat_tip_suppressed_after_read() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = crate::tools::common::test_ctx(tmp.path());
    ctx.llm_mode = crate::config::extended::LlmMode::Defensive;
    // The model already adopted `read` this session (recorded at the
    // dispatch site on a successful read call).
    ctx.session.record_tip_tool_used("read");
    let tool = BashTool::new();
    let out = tool
        .call(serde_json::json!({ "command": "cat foo.txt" }), &ctx)
        .await
        .expect("bash call returns");
    assert!(
        !out.content.contains("tip:"),
        "the read tip must be suppressed after a successful read, got: {}",
        out.content
    );
}

// ---- empty-output annotation (implementation note) -

/// exit 0 with both streams empty: the bare `exit: 0` line is preserved
/// AND the complete-result annotation is appended.
#[test]
fn empty_exit_zero_is_annotated_complete() {
    let out = format_combined("", "", 0, false);
    assert!(out.contains("exit: 0"), "exit line preserved, got: {out}");
    assert!(
        out.contains("no output") && out.contains("complete result"),
        "expected complete-result annotation, got: {out}"
    );
}

/// Nonzero with both streams empty: annotated, but NEUTRAL — never
/// labelled "failed"/"error" (grep/diff exit 1 = a valid answer).
#[test]
fn empty_nonzero_is_annotated_neutral() {
    let out = format_combined("", "", 1, false);
    assert!(out.contains("exit: 1"), "exit line preserved, got: {out}");
    assert!(out.contains("no output"), "expected annotation, got: {out}");
    let lower = out.to_lowercase();
    assert!(
        !lower.contains("fail") && !lower.contains("error"),
        "nonzero annotation must stay neutral, got: {out}"
    );
}

/// Any stdout means it is not the void case — no annotation.
#[test]
fn stdout_present_is_not_annotated() {
    let out = format_combined("hi\n", "", 0, false);
    assert!(out.contains("stdout:"), "stdout rendered, got: {out}");
    assert!(
        !out.contains("no output"),
        "stdout-present must not be annotated, got: {out}"
    );
}

/// Any stderr means it is not the void case — no annotation.
#[test]
fn stderr_present_is_not_annotated() {
    let out = format_combined("", "oops\n", 1, false);
    assert!(out.contains("stderr:"), "stderr rendered, got: {out}");
    assert!(
        !out.contains("no output"),
        "stderr-present must not be annotated, got: {out}"
    );
}

/// The signaled branch keeps its current rendering — never annotated.
#[test]
fn signaled_empty_is_not_annotated() {
    let out = format_combined("", "", 0, true);
    assert!(
        out.contains("exit: signaled"),
        "signaled rendering preserved, got: {out}"
    );
    assert!(
        !out.contains("no output"),
        "signaled must not be annotated, got: {out}"
    );
}

#[test]
fn missing_binary_diagnostic_names_cockpit_environment() {
    let outcome = ShellOutcome {
        stdout: Vec::new(),
        stderr: b"sh: 1: npm: not found\n".to_vec(),
        exit: 127,
        signaled: false,
        success: false,
    };
    let body = render_output(
        &outcome,
        None,
        false,
        "npm run build",
        Path::new("/repo"),
        None,
        None,
    );
    assert!(body.contains("stderr:\nsh: 1: npm: not found\n"));
    assert!(body.contains("exit: 127\n"));
    assert!(body.contains("cockpit_command_environment:"));
    assert!(body.contains("attempted_command: npm run build"));
    assert!(body.contains("cwd: /repo"));
    assert!(body.contains("exit_code: 127"));
    assert!(body.contains("missing_binary: npm"));
    assert!(body.contains("not found in cockpit's command environment"));
    assert!(body.contains("does not establish that it is absent from the host system"));
}

#[test]
fn missing_binary_diagnostic_adds_remedy_for_declared_binary_only() {
    let declared = cockpit_command_environment_block_with_requirements(
        "jq . package.json",
        Path::new("/repo"),
        Some("127"),
        None,
        Some("jq"),
        vec![crate::capabilities::BinaryRequirement::required(
            "jq",
            crate::capabilities::common_remedy("jq"),
        )],
    );
    assert!(declared.contains("missing_binary: jq"));
    assert!(declared.contains("remedy:"));
    assert!(declared.contains("cockpit jq"));

    let undeclared = cockpit_command_environment_block_with_requirements(
        "mystery",
        Path::new("/repo"),
        Some("127"),
        None,
        Some("mystery"),
        Vec::new(),
    );
    assert!(undeclared.contains("missing_binary: mystery"));
    assert!(!undeclared.contains("remedy:"));
}

#[test]
fn nonzero_command_diagnostic_includes_attempted_command_and_cwd() {
    let outcome = ShellOutcome {
        stdout: Vec::new(),
        stderr: b"tests failed\n".to_vec(),
        exit: 2,
        signaled: false,
        success: false,
    };
    let body = render_output(
        &outcome,
        None,
        false,
        "cargo test",
        Path::new("/repo"),
        None,
        None,
    );
    assert!(body.contains("exit: 2\n"));
    assert!(body.contains("cockpit_command_environment:"));
    assert!(body.contains("attempted_command: cargo test"));
    assert!(body.contains("cwd: /repo"));
    assert!(body.contains("exit_code: 2"));
    assert!(!body.contains("missing_binary:"));
    assert!(body.contains("failure occurred while running in cockpit's command environment"));
}

#[test]
fn spawn_error_diagnostic_includes_command_cwd_and_error() {
    let error = std::io::Error::new(std::io::ErrorKind::NotFound, "No such file or directory");
    let body = render_spawn_error("cargo test", Path::new("/repo"), &error);
    assert!(body.contains("Error: could not start cockpit shell"));
    assert!(body.contains("cockpit_command_environment:"));
    assert!(body.contains("attempted_command: cargo test"));
    assert!(body.contains("cwd: /repo"));
    assert!(body.contains("spawn_error: No such file or directory"));
    assert!(body.contains("missing_binary: sh"));
    assert!(body.contains("not found in cockpit's command environment"));
}
