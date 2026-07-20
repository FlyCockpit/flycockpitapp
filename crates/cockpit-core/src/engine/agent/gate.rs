use super::*;

#[cfg(test)]
use super::recheck::{RecheckAction, result_recheck_action};

/// What the command-safety gate decided for one call.
#[derive(Clone)]
pub(super) enum GateOutcome {
    /// Proceed to dispatch. `recheck` is whether the call's result must be
    /// injection-re-checked afterward.
    Run { recheck: bool },
    /// Skip dispatch; the string is the model-readable tool result
    /// (`invalid_input`) explaining why the call was withheld.
    Block(String),
}

#[cfg(test)]
thread_local! {
    static SAFETY_GATE_TEST_OVERRIDE: std::cell::RefCell<Option<GateOutcome>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) struct SafetyGateTestOverrideGuard;

#[cfg(test)]
pub(super) fn set_safety_gate_test_override(outcome: GateOutcome) -> SafetyGateTestOverrideGuard {
    SAFETY_GATE_TEST_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(outcome));
    SafetyGateTestOverrideGuard
}

#[cfg(test)]
impl Drop for SafetyGateTestOverrideGuard {
    fn drop(&mut self) {
        SAFETY_GATE_TEST_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
    }
}

/// Decide a single gated call under the session's approval mode
/// (implementation note). Non-gated tools, and the
/// `manual`/`yolo` modes, never reach the utility-model gate:
///
/// - `manual` → the user approves everything elsewhere; the gate is not
///   this mode's engine. Run (no per-call gate here).
/// - `yolo` → run everything unprompted.
/// - `auto` → judge the single call (no history) via the utility model:
///   `safe` runs; `unsafe` escalates to the user; utility-model unavailable
///   fails CLOSED (escalates). A user denial blocks dispatch.
///
/// The evaluator also reports whether the result needs an injection
/// re-check; that flag is threaded back on [`GateOutcome::Run`].
pub(super) async fn safety_gate_decision(
    tool: &str,
    args: &Value,
    ctx: &ToolCtx,
    tx: &mpsc::Sender<TurnEvent>,
) -> GateOutcome {
    #[cfg(test)]
    if let Some(outcome) = SAFETY_GATE_TEST_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return outcome;
    }
    let (extended, providers) = ctx.config.configs();
    safety_gate_decision_with_configs(tool, args, ctx, tx, extended.guard_model_ref(), &providers)
        .await
}

pub(super) async fn safety_gate_decision_with_configs(
    tool: &str,
    args: &Value,
    ctx: &ToolCtx,
    tx: &mpsc::Sender<TurnEvent>,
    model_ref: Option<&str>,
    providers: &crate::config::providers::ProvidersConfig,
) -> GateOutcome {
    use crate::config::extended::ApprovalMode;
    use crate::engine::safety_gate::{SafetyOutcome, evaluate};

    if !is_gated_tool(tool, &ctx.config) {
        return GateOutcome::Run { recheck: false };
    }
    match ctx.session.approval_mode() {
        // `manual`: the gate is not invoked (the user is the gate elsewhere).
        // `yolo`: everything runs, gate bypassed. Either way, run ungated.
        ApprovalMode::Manual | ApprovalMode::Yolo => return GateOutcome::Run { recheck: false },
        ApprovalMode::Auto => {}
    }

    // `auto` mode. The utility model judges this single call with no
    // conversation history. The guard's own model override falls back to the
    // utility model (same chain the injection guard uses).
    tracing::debug!(
        mode = crate::config::extended::ApprovalMode::Auto.as_str(),
        tool,
        "safety gate: evaluating gated call"
    );
    let payload = gate_payload(tool, args);
    let outcome = evaluate(
        model_ref,
        providers,
        ctx.redact.clone(),
        ctx.session.trusted_only_flag(),
        Some(ctx.shutdown_gate.clone()),
        tool,
        &payload,
    )
    .await;

    match outcome {
        SafetyOutcome::Rated(verdict) if verdict.safe => {
            // Safe → run without prompting.
            GateOutcome::Run {
                recheck: verdict.recheck_result,
            }
        }
        SafetyOutcome::Rated(verdict) => {
            // Unsafe → escalate to the user. A denial blocks dispatch.
            // If the user approves, still honor the result re-check flag.
            match escalate_gated_call(tool, args, ctx, false, tx).await {
                GateApproval::Allow => GateOutcome::Run {
                    recheck: verdict.recheck_result,
                },
                GateApproval::Deny => GateOutcome::Block(gate_block_message(tool, false)),
                GateApproval::NoninteractiveDeny => {
                    GateOutcome::Block(crate::approval::NONINTERACTIVE_RUN_DENIAL.to_string())
                }
            }
        }
        SafetyOutcome::Unavailable => {
            // Fail CLOSED: the gate couldn't vet the call, so treat it as
            // requiring user approval rather than silently running it.
            match escalate_gated_call(tool, args, ctx, true, tx).await {
                // Approved → run, and (conservatively) re-check the result:
                // the eval that would have set the flag never completed, so a
                // call the user only let through under an unavailable gate
                // still gets its result vetted if it's a network tool.
                GateApproval::Allow => GateOutcome::Run {
                    recheck: tool != "bash",
                },
                GateApproval::Deny => GateOutcome::Block(gate_block_message(tool, true)),
                GateApproval::NoninteractiveDeny => {
                    GateOutcome::Block(crate::approval::NONINTERACTIVE_RUN_DENIAL.to_string())
                }
            }
        }
    }
}

/// The single command/call text the safety evaluator judges. For `bash`
/// it's the raw command line; for the network tools it's the call's
/// arguments serialized compactly (the URL / server+tool+args).
pub(super) fn gate_payload(tool: &str, args: &Value) -> String {
    if tool == "bash" {
        return args
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
    }
    serde_json::to_string(args).unwrap_or_else(|_| args.to_string())
}

/// Escalate a gated call to the user through the existing approval prompt.
/// `bash` reuses [`Approver::approve_command`] (classify + command-detail
/// UX); the network tools use the once-only [`Approver::approve_tool_call`].
/// `unavailable` tailors the surfaced reason (gate down vs. rated unsafe).
/// With no approver wired (seed re-exec, tests) there is no client to ask —
/// fail closed by treating it as denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateApproval {
    Allow,
    Deny,
    NoninteractiveDeny,
}

async fn escalate_gated_call(
    tool: &str,
    args: &Value,
    ctx: &ToolCtx,
    unavailable: bool,
    tx: &mpsc::Sender<TurnEvent>,
) -> GateApproval {
    let Some(approver) = ctx.approver.as_ref() else {
        // No human to ask → fail closed (do not silently run).
        return GateApproval::Deny;
    };

    // Surface why we're asking (the safety gate, not an ordinary approval).
    let reason = if unavailable {
        format!(
            "safety gate unavailable (utility model unset or unreachable) — asking before running `{tool}`"
        )
    } else {
        format!("safety gate flagged this `{tool}` call as unsafe — asking before running it")
    };
    let _ = tx.send(TurnEvent::Notice { text: reason }).await;

    let decision = if tool == "bash" {
        let command = args.get("command").and_then(Value::as_str).unwrap_or("");
        approver.approve_command(command).await
    } else {
        let label = format!("{tool} {}", gate_payload(tool, args));
        approver.approve_tool_call(&label).await
    };
    match decision {
        Ok(crate::approval::Decision::Allow { .. }) => GateApproval::Allow,
        Ok(crate::approval::Decision::NoninteractiveDeny) => GateApproval::NoninteractiveDeny,
        Ok(crate::approval::Decision::Deny) | Err(_) => GateApproval::Deny,
    }
}

/// The model-readable tool result when a gated call is withheld (denied at
/// the safety-gate escalation). Reads as an invocation error so the model
/// changes course rather than treating it as a hard abort.
pub(super) fn gate_block_message(tool: &str, unavailable: bool) -> String {
    if unavailable {
        format!(
            "`{tool}` was not run: the command-safety gate could not reach the utility model and \
             the user declined to run it unverified. Try a different approach or ask the user."
        )
    } else {
        format!(
            "`{tool}` was not run: the command-safety gate flagged it as unsafe and the user \
             declined. Do not retry the same call — choose a safer approach."
        )
    }
}

#[cfg(test)]
mod safety_gate_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::approval::Approver;
    use crate::approval::store::GrantStore;
    use crate::config::extended::ApprovalMode;
    use crate::engine::injection_check::CheckOutcome;
    use crate::engine::tool::{Tool, ToolCtx};
    use async_trait::async_trait;

    /// Build a ToolCtx for the gate tests: a real session (so we can set the
    /// approval mode) plus an `Approver` wired to a detached interrupt hub.
    /// The hub is detached → not interactive, so an escalation prompt would
    /// never resolve; the tests only exercise paths that don't actually wait
    /// (no approver, or modes that skip the gate).
    fn gate_ctx(root: &std::path::Path, mode: ApprovalMode, with_approver: bool) -> ToolCtx {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session =
            crate::session::Session::create(db.clone(), root.to_path_buf(), "builder").unwrap();
        session.set_sandbox_enabled(false);
        session.set_approval_mode(mode);
        let sid = session.id;
        let locks = Arc::new(crate::locks::LockManager::from_db(db.clone()).unwrap());
        let cfg = crate::config::extended::RedactConfig::default();
        let redact = Arc::new(crate::redact::RedactionTable::build(&cfg, root).unwrap());
        let hub = Arc::new(crate::engine::interrupt::InterruptHub::detached());
        let approver = if with_approver {
            let store = GrantStore::new(
                db.clone(),
                sid,
                root.to_path_buf(),
                crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(root),
            );
            Some(Arc::new(Approver::new(
                store,
                db,
                sid,
                "builder",
                hub.clone(),
            )))
        } else {
            None
        };
        ToolCtx {
            agent_id: "builder".to_string(),
            current_tool_call_id: None,
            llm_mode: crate::config::extended::LlmMode::Normal,
            locks,
            session: Arc::new(session),
            cwd: root.to_path_buf(),
            redact,
            interrupts: hub,
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: crate::daemon::shutdown::ShutdownSignal::new(),
            approver,
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
            root_agent_frame: true,
            skill_write_origin: crate::skills::manage::SkillWriteOrigin::Foreground,
            review_cage: None,
            context_usage: None,
            available_tools: Arc::new(std::collections::HashSet::new()),
            mcp_builtin_registry: Arc::new(crate::mcp::builtin::BuiltinRegistry::default_with(
                Vec::new(),
            )),
            has_tree: false,
            has_bash: false,
            events: None,
            lsp: None,
            resource_scheduler: None,
            config: crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(root),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    #[test]
    fn gate_scope_covers_shell_mcp_fetch_and_custom_websearch() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        let default_config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(cwd);
        assert!(is_gated_tool("bash", &default_config));
        assert!(is_gated_tool("webfetch", &default_config));
        assert!(is_gated_tool("mcp", &default_config));
        assert!(!is_gated_tool("websearch", &default_config));
        assert!(!is_gated_tool("read", &default_config));
        assert!(!is_gated_tool("editunlock", &default_config));
        assert!(!is_gated_tool("search", &default_config));
        assert!(!is_gated_tool("task", &default_config));

        std::fs::create_dir_all(cwd.join(".cockpit")).unwrap();
        std::fs::write(
            cwd.join(".cockpit/config.json"),
            r#"{"web":{"provider":"custom"}}"#,
        )
        .unwrap();
        let custom_config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(cwd);
        assert!(is_gated_tool("websearch", &custom_config));
    }

    #[tokio::test]
    async fn manual_mode_runs_without_gating() {
        // `manual`: the per-call utility gate is not this mode's engine — the
        // gate decision is `Run` immediately, with no model call and no
        // result re-check requested.
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gate_ctx(tmp.path(), ApprovalMode::Manual, true);
        let (tx, _rx) = mpsc::channel(8);
        let args = serde_json::json!({ "command": "rm -rf /" });
        let outcome = safety_gate_decision("bash", &args, &ctx, &tx).await;
        assert!(matches!(outcome, GateOutcome::Run { recheck: false }));
    }

    #[tokio::test]
    async fn yolo_mode_bypasses_the_gate() {
        // `yolo`: everything runs unprompted; the gate is bypassed even for a
        // destructive command, with no model call.
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gate_ctx(tmp.path(), ApprovalMode::Yolo, true);
        let (tx, _rx) = mpsc::channel(8);
        let args = serde_json::json!({ "command": "rm -rf /" });
        let outcome = safety_gate_decision("bash", &args, &ctx, &tx).await;
        assert!(matches!(outcome, GateOutcome::Run { recheck: false }));
    }

    #[tokio::test]
    async fn non_gated_tool_is_never_gated_even_in_auto() {
        // A non-scoped tool runs ungated in `auto` mode — no model call.
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gate_ctx(tmp.path(), ApprovalMode::Auto, true);
        let (tx, _rx) = mpsc::channel(8);
        let args = serde_json::json!({ "path": "src/main.rs" });
        let outcome = safety_gate_decision("read", &args, &ctx, &tx).await;
        assert!(matches!(outcome, GateOutcome::Run { recheck: false }));
    }

    struct SleepTool;

    #[async_trait]
    impl Tool for SleepTool {
        fn name(&self) -> &str {
            "sleepy"
        }

        fn description(&self) -> &str {
            "Sleep briefly."
        }

        fn parameters(&self) -> Value {
            serde_json::json!({})
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(ToolOutput {
                content: "done".to_string(),
                repeat_guard: None,
                truncated: false,
                truncated_retention: None,
                recovery: None,
                canonical_args: None,
                sandbox: None,
                resource: None,
                exit_code: None,
                output_sidecar: None,
            })
        }
    }

    #[tokio::test]
    async fn dispatch_duration_excludes_pre_call_approval_wait() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gate_ctx(tmp.path(), ApprovalMode::Manual, false);
        let tools = ToolBox::new().with(Arc::new(SleepTool));

        tokio::time::sleep(Duration::from_millis(200)).await;
        let (result, duration_ms) =
            dispatch_one_timed(&tools, "sleepy", serde_json::json!({}), &ctx, None).await;

        result.expect("tool runs");
        assert!(
            duration_ms >= 30,
            "duration should include the tool call runtime, got {duration_ms}ms"
        );
        assert!(
            duration_ms < 150,
            "duration must exclude the simulated approval/gating wait, got {duration_ms}ms"
        );
    }

    #[tokio::test]
    async fn auto_mode_fails_closed_when_utility_model_unset_and_no_client() {
        // `auto` + no utility model configured → safety eval is Unavailable →
        // fail CLOSED: escalate to the user. With no approver/interactive
        // client to ask, the call is BLOCKED (not silently run) — the
        // opposite of the inbound scan's fail-open.
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gate_ctx(tmp.path(), ApprovalMode::Auto, false);
        let (tx, _rx) = mpsc::channel(8);
        let args = serde_json::json!({ "command": "ls" });
        let providers = crate::config::providers::ProvidersConfig::default();
        let outcome =
            safety_gate_decision_with_configs("bash", &args, &ctx, &tx, None, &providers).await;
        match outcome {
            GateOutcome::Block(msg) => {
                assert!(msg.contains("safety gate"), "got: {msg}");
            }
            GateOutcome::Run { .. } => {
                panic!("auto mode must NOT silently run when the gate is unavailable")
            }
        }
    }

    #[test]
    fn gate_payload_uses_command_for_bash_and_args_for_network() {
        let bash = serde_json::json!({ "command": "curl https://x", "cwd": "/tmp" });
        assert_eq!(gate_payload("bash", &bash), "curl https://x");
        let fetch = serde_json::json!({ "url": "https://x.com/foo" });
        let p = gate_payload("webfetch", &fetch);
        assert!(p.contains("https://x.com/foo"), "got: {p}");
    }

    #[test]
    fn result_recheck_routing_maps_rating_to_action() {
        use crate::config::extended::{InjectionResultAction, InjectionThreshold};
        // Only a flagged result is ever re-checked; given the outcome and
        // threshold, ratings at/above threshold follow resultAction.
        assert_eq!(
            result_recheck_action(
                CheckOutcome::Rated(InjectionThreshold::High),
                InjectionThreshold::Medium,
                InjectionResultAction::Block,
            ),
            RecheckAction::Block
        );
        assert_eq!(
            result_recheck_action(
                CheckOutcome::Rated(InjectionThreshold::Medium),
                InjectionThreshold::Medium,
                InjectionResultAction::Ask,
            ),
            RecheckAction::Ask
        );
        assert_eq!(
            result_recheck_action(
                CheckOutcome::Rated(InjectionThreshold::Medium),
                InjectionThreshold::High,
                InjectionResultAction::Block,
            ),
            RecheckAction::Warn
        );
        assert_eq!(
            result_recheck_action(
                CheckOutcome::Rated(InjectionThreshold::Low),
                InjectionThreshold::Medium,
                InjectionResultAction::Block,
            ),
            RecheckAction::Pass
        );
        assert_eq!(
            result_recheck_action(
                CheckOutcome::Unavailable,
                InjectionThreshold::Medium,
                InjectionResultAction::Block,
            ),
            RecheckAction::Unavailable
        );
    }
}
