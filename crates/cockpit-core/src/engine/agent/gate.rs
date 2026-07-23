use super::*;

#[cfg(test)]
use super::recheck::{RecheckAction, result_recheck_action};

/// What the command-safety gate decided for one call.
#[derive(Clone)]
pub(super) enum GateOutcome {
    /// Proceed to dispatch. `recheck` is whether the call's result must be
    /// injection-re-checked afterward.
    Run { recheck: bool },
    /// The human escalation prompt parked. Dispatch must stop without
    /// fabricating a denial result.
    Parked,
    /// Skip dispatch; the string is the model-readable tool result
    /// (`invalid_input`) explaining why the call was withheld.
    Block(GateBlock),
}

#[derive(Clone)]
pub(super) struct GateBlock {
    pub message: String,
    pub status: &'static str,
}

#[cfg(test)]
thread_local! {
    static SAFETY_GATE_TEST_OVERRIDE: std::cell::RefCell<Option<GateOutcome>> =
        const { std::cell::RefCell::new(None) };
    static SAFETY_GATE_EVALUATE_CALLS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
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

#[cfg(test)]
fn reset_safety_gate_evaluate_calls() {
    SAFETY_GATE_EVALUATE_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
fn safety_gate_evaluate_calls() -> usize {
    SAFETY_GATE_EVALUATE_CALLS.with(std::cell::Cell::get)
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

    if !is_gated_tool(tool) {
        return GateOutcome::Run { recheck: false };
    }
    match ctx.session.approval_mode() {
        // `manual`: the utility-model gate is not invoked because the human
        // is the gate. Bash asks in its grant-or-ask paths when a command
        // would run unconfined; `escalate` prompts through its Manual route.
        ApprovalMode::Manual => return GateOutcome::Run { recheck: false },
        // `yolo`: everything runs unprompted and unverified.
        ApprovalMode::Yolo => return GateOutcome::Run { recheck: false },
        ApprovalMode::Auto => {}
    }
    if let Some(block) = standing_reject_gate_block(tool, args, ctx) {
        return GateOutcome::Block(block);
    }
    if let Some(payload) = crate::engine::interrupt::current_interrupt_park_payload()
        && payload.tool == tool
        && payload.args == *args
        && let Some(gate) = payload.gate
    {
        return GateOutcome::Run {
            recheck: gate.recheck_result,
        };
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
    #[cfg(test)]
    SAFETY_GATE_EVALUATE_CALLS.with(|calls| calls.set(calls.get() + 1));
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
                GateApproval::Parked => GateOutcome::Parked,
                GateApproval::Deny => GateOutcome::Block(gate_block(tool, false)),
                GateApproval::NoninteractiveDeny => GateOutcome::Block(GateBlock {
                    message: crate::approval::NONINTERACTIVE_RUN_DENIAL.to_string(),
                    status: "blocked_safety_gate",
                }),
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
                GateApproval::Parked => GateOutcome::Parked,
                GateApproval::Deny => GateOutcome::Block(gate_block(tool, true)),
                GateApproval::NoninteractiveDeny => GateOutcome::Block(GateBlock {
                    message: crate::approval::NONINTERACTIVE_RUN_DENIAL.to_string(),
                    status: "blocked_safety_gate",
                }),
            }
        }
    }
}

fn standing_reject_gate_block(tool: &str, args: &Value, ctx: &ToolCtx) -> Option<GateBlock> {
    let approver = ctx.approver.as_ref()?;
    match tool {
        "bash" => {
            let command = args.get("command").and_then(Value::as_str).unwrap_or("");
            let scope = approver.command_standing_reject_scope(command)?;
            approver.record_standing_reject_decision("bash", command, scope);
            Some(standing_reject_block("bash", scope))
        }
        "mcp" => {
            let script = args.get("script").and_then(Value::as_str)?;
            for invocation in static_mcp_invocations(script) {
                if let Some(scope) = approver
                    .store()
                    .mcp_tool_reject_scope(&invocation.server, &invocation.tool)
                {
                    let target =
                        crate::approval::store::mcp_tool_key(&invocation.server, &invocation.tool);
                    approver.record_standing_reject_decision("mcp_tool", &target, scope);
                    return Some(standing_reject_block("mcp", scope));
                }
            }
            None
        }
        _ => None,
    }
}

struct StaticMcpInvocation {
    server: String,
    tool: String,
}

fn static_mcp_invocations(script: &str) -> Vec<StaticMcpInvocation> {
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(script, None) else {
        return Vec::new();
    };
    let mut invocations = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "call"
            && let Some(invocation) = static_mcp_invocation_from_call(node, script.as_bytes())
        {
            invocations.push(invocation);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    invocations
}

fn static_mcp_invocation_from_call(
    node: tree_sitter::Node<'_>,
    source: &[u8],
) -> Option<StaticMcpInvocation> {
    let function = node.child_by_field_name("function")?;
    if function.utf8_text(source).ok()? != "mcp.invoke" {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let mut static_args = Vec::new();
    let mut cursor = arguments.walk();
    for child in arguments.named_children(&mut cursor) {
        if child.kind() == "string" {
            static_args.push(decode_python_string_literal(child.utf8_text(source).ok()?)?);
        } else if static_args.len() < 2 {
            return None;
        }
        if static_args.len() == 2 {
            return Some(StaticMcpInvocation {
                server: static_args.remove(0),
                tool: static_args.remove(0),
            });
        }
    }
    None
}

fn decode_python_string_literal(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let start = raw.find(['"', '\''])?;
    if raw[..start]
        .chars()
        .any(|ch| matches!(ch, 'f' | 'F' | 'b' | 'B'))
    {
        return None;
    }
    let quote = raw.as_bytes()[start] as char;
    let triple = raw[start..].starts_with(&format!("{quote}{quote}{quote}"));
    let body_start = start + if triple { 3 } else { 1 };
    let terminator = if triple {
        format!("{quote}{quote}{quote}")
    } else {
        quote.to_string()
    };
    let body_end = raw[body_start..].rfind(&terminator)? + body_start;
    let body = &raw[body_start..body_end];
    if raw[..start].chars().any(|ch| matches!(ch, 'r' | 'R')) {
        return Some(body.to_string());
    }
    let mut decoded = String::new();
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => decoded.push('\n'),
            Some('r') => decoded.push('\r'),
            Some('t') => decoded.push('\t'),
            Some('\\') => decoded.push('\\'),
            Some('\'') => decoded.push('\''),
            Some('"') => decoded.push('"'),
            Some(other) => decoded.push(other),
            None => return None,
        }
    }
    Some(decoded)
}

fn standing_reject_block(tool: &str, scope: crate::approval::store::Scope) -> GateBlock {
    GateBlock {
        message: crate::approval::standing_reject_refusal(tool, scope),
        status: "blocked_standing_reject",
    }
}

/// The single command/call text the safety evaluator judges. For `bash`
/// it's the raw command line; for other gated tools it's the call's
/// arguments serialized compactly.
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
/// UX); non-bash gated tools use the once-only [`Approver::approve_tool_call`].
/// `unavailable` tailors the surfaced reason (gate down vs. rated unsafe).
/// With no approver wired (seed re-exec, tests) there is no client to ask —
/// fail closed by treating it as denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateApproval {
    Allow,
    Parked,
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
        Ok(crate::approval::Decision::StandingReject { .. }) => GateApproval::Deny,
        Err(error) if crate::engine::interrupt::is_parked(&error) => GateApproval::Parked,
        Ok(crate::approval::Decision::Deny) | Err(_) => GateApproval::Deny,
    }
}

/// The model-readable tool result when a gated call is withheld (denied at
/// the safety-gate escalation). Reads as an invocation error so the model
/// changes course rather than treating it as a hard abort.
#[cfg(test)]
pub(super) fn gate_block_message(tool: &str, unavailable: bool) -> String {
    gate_block(tool, unavailable).message
}

fn gate_block(tool: &str, unavailable: bool) -> GateBlock {
    let message = if unavailable {
        format!(
            "`{tool}` was not run: the command-safety gate could not reach the utility model and \
             the user declined to run it unverified. Try a different approach or ask the user."
        )
    } else {
        format!(
            "`{tool}` was not run: the command-safety gate flagged it as unsafe and the user \
             declined. Do not retry the same call — choose a safer approach."
        )
    };
    GateBlock {
        message,
        status: "blocked_safety_gate",
    }
}

#[cfg(test)]
mod safety_gate_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::approval::Approver;
    use crate::approval::classify::classify;
    use crate::approval::store::GrantStore;
    use crate::approval::store::Scope;
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

    fn init_git_repo(path: &std::path::Path) {
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(path)
            .status()
            .unwrap();
        assert!(status.success());
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    fn attach_approver_with_hub(
        ctx: &mut ToolCtx,
        hub: Arc<crate::engine::interrupt::InterruptHub>,
    ) {
        let store = GrantStore::new(
            ctx.session.db.clone(),
            ctx.session.id,
            ctx.cwd.clone(),
            ctx.config.clone(),
        );
        ctx.interrupts = hub.clone();
        ctx.approver = Some(Arc::new(Approver::new(
            store,
            ctx.session.db.clone(),
            ctx.session.id,
            &ctx.agent_id,
            hub,
        )));
    }

    fn attached_interrupt_hub(ctx: &ToolCtx) -> Arc<crate::engine::interrupt::InterruptHub> {
        let (events, _receiver) = tokio::sync::broadcast::channel(16);
        let redaction = Arc::new(std::sync::RwLock::new(Arc::new(
            crate::redact::RedactionTable::empty(),
        )));
        Arc::new(crate::engine::interrupt::InterruptHub::new(
            events,
            redaction,
            Arc::new(std::sync::atomic::AtomicUsize::new(1)),
            ctx.session.db.clone(),
            ctx.session.id,
        ))
    }

    async fn wait_for_open_interrupt(ctx: &ToolCtx) -> uuid::Uuid {
        for _ in 0..1000 {
            if let Some(row) = ctx
                .session
                .db
                .list_open_interrupts(ctx.session.id)
                .unwrap()
                .first()
            {
                return row.interrupt_id;
            }
            tokio::task::yield_now().await;
        }
        panic!("timed out waiting for gate interrupt");
    }

    fn replay_question_from_row(
        ctx: &ToolCtx,
        interrupt_id: uuid::Uuid,
    ) -> crate::engine::interrupt::PreResolvedInterruptQuestion {
        let row = ctx
            .session
            .db
            .get_interrupt(interrupt_id)
            .unwrap()
            .expect("parked gate row");
        crate::engine::interrupt::PreResolvedInterruptQuestion {
            agent: row.agent_id,
            description: row.description,
            questions: row.questions.expect("gate question set"),
            occurrence: 1,
        }
    }

    #[test]
    fn gate_scope_covers_shell_and_mcp_only() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path();
        assert!(is_gated_tool("bash"));
        assert!(is_gated_tool("mcp"));
        assert!(!is_gated_tool("webfetch"));
        assert!(!is_gated_tool("websearch"));
        assert!(!is_gated_tool("read"));
        assert!(!is_gated_tool("editunlock"));
        assert!(!is_gated_tool("search"));
        assert!(!is_gated_tool("task"));

        std::fs::create_dir_all(cwd.join(".cockpit")).unwrap();
        std::fs::write(
            cwd.join(".cockpit/config.json"),
            r#"{"web":{"provider":"custom"}}"#,
        )
        .unwrap();
        let _custom_config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(cwd);
        assert!(!is_gated_tool("webfetch"));
        assert!(!is_gated_tool("websearch"));
    }

    #[tokio::test]
    async fn web_tools_are_never_gated_in_any_approval_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".cockpit")).unwrap();
        std::fs::write(
            root.join(".cockpit/config.json"),
            r#"{"web":{"provider":"custom"}}"#,
        )
        .unwrap();
        let providers = crate::config::providers::ProvidersConfig::default();
        let (tx, _rx) = mpsc::channel(8);

        for mode in [ApprovalMode::Manual, ApprovalMode::Auto, ApprovalMode::Yolo] {
            let ctx = gate_ctx(root, mode, true);
            for (tool, args) in [
                (
                    "webfetch",
                    serde_json::json!({ "url": "https://example.com" }),
                ),
                ("websearch", serde_json::json!({ "query": "example" })),
            ] {
                let outcome =
                    safety_gate_decision_with_configs(tool, &args, &ctx, &tx, None, &providers)
                        .await;
                assert!(
                    matches!(outcome, GateOutcome::Run { recheck: false }),
                    "{tool} should run ungated in {mode:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn manual_mode_skips_utility_gate_but_bash_still_asks() {
        // `manual`: the per-call utility gate is not this mode's engine. The
        // gate decision is `Run` immediately, with no model call and no
        // result re-check requested. This is not unconditional command
        // approval: unconfined `bash` runs still ask in
        // `sandbox_off_ungranted_command_prompts_and_deny_blocks_run`, and
        // the `escalate` tool prompts through its Manual route.
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

    #[tokio::test]
    async fn standing_reject_gate_blocks_before_model() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gate_ctx(tmp.path(), ApprovalMode::Auto, true);
        let approver = ctx.approver.as_ref().unwrap();
        let classification = classify("gh pr create");
        let info = classification.simple_commands().iter().next().unwrap();
        approver
            .store()
            .record_command_reject(info, Scope::Session)
            .unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let args = serde_json::json!({ "command": "gh pr create" });
        let providers = crate::config::providers::ProvidersConfig::default();

        reset_safety_gate_evaluate_calls();
        let outcome =
            safety_gate_decision_with_configs("bash", &args, &ctx, &tx, None, &providers).await;

        match outcome {
            GateOutcome::Block(block) => {
                assert_eq!(block.status, "blocked_standing_reject");
                assert!(
                    block.message.contains("rejected at session scope"),
                    "{}",
                    block.message
                );
            }
            GateOutcome::Run { .. } => panic!("standing reject must block before dispatch"),
            GateOutcome::Parked => panic!("standing reject must not park"),
        }
        assert_eq!(safety_gate_evaluate_calls(), 0);
    }

    #[tokio::test]
    async fn standing_reject_gate_passthrough_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gate_ctx(tmp.path(), ApprovalMode::Auto, false);
        let (tx, _rx) = mpsc::channel(8);
        let args = serde_json::json!({ "command": "gh pr create" });
        let providers = crate::config::providers::ProvidersConfig::default();

        reset_safety_gate_evaluate_calls();
        let outcome =
            safety_gate_decision_with_configs("bash", &args, &ctx, &tx, None, &providers).await;

        match outcome {
            GateOutcome::Block(block) => assert_eq!(block.status, "blocked_safety_gate"),
            GateOutcome::Run { .. } | GateOutcome::Parked => {
                panic!("unconfigured utility model with no client should fail closed")
            }
        }
        assert_eq!(safety_gate_evaluate_calls(), 1);
    }

    #[tokio::test]
    async fn standing_reject_allow_flip_unblocks_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gate_ctx(tmp.path(), ApprovalMode::Auto, true);
        let approver = ctx.approver.as_ref().unwrap();
        let classification = classify("gh pr create");
        let info = classification.simple_commands().iter().next().unwrap();
        approver
            .store()
            .record_command_reject(info, Scope::Session)
            .unwrap();
        approver
            .store()
            .record_command(info, info.risk.tier, Scope::Session)
            .unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let args = serde_json::json!({ "command": "gh pr create" });
        let providers = crate::config::providers::ProvidersConfig::default();

        reset_safety_gate_evaluate_calls();
        let outcome =
            safety_gate_decision_with_configs("bash", &args, &ctx, &tx, None, &providers).await;

        match outcome {
            GateOutcome::Run { recheck: false } => {}
            GateOutcome::Run { recheck: true } => {
                panic!("bash gate allow must not request recheck")
            }
            GateOutcome::Block(block) => {
                panic!("allow flip must unblock gate, got {}", block.status)
            }
            GateOutcome::Parked => panic!("allow flip must not park"),
        }
        assert_eq!(safety_gate_evaluate_calls(), 1);
    }

    #[tokio::test]
    async fn standing_reject_gate_covers_mcp() {
        let env = tempfile::tempdir().unwrap();
        let _home =
            cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at_async(env.path()).await;
        let project = tempfile::tempdir_in(env.path()).unwrap();
        init_git_repo(project.path());
        let ctx = gate_ctx(project.path(), ApprovalMode::Auto, true);
        let approver = ctx.approver.as_ref().unwrap();
        approver
            .store()
            .record_mcp_tool_reject("example", "mutate", Scope::Project)
            .unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let args =
            serde_json::json!({ "script": "result = mcp.invoke('example', 'mutate', {'x': 1})" });
        let providers = crate::config::providers::ProvidersConfig::default();

        reset_safety_gate_evaluate_calls();
        let outcome =
            safety_gate_decision_with_configs("mcp", &args, &ctx, &tx, None, &providers).await;

        match outcome {
            GateOutcome::Block(block) => {
                assert_eq!(block.status, "blocked_standing_reject");
                assert!(
                    block.message.contains("rejected at project scope"),
                    "{}",
                    block.message
                );
            }
            GateOutcome::Run { .. } => panic!("MCP standing reject must block before dispatch"),
            GateOutcome::Parked => panic!("MCP standing reject must not park"),
        }
        assert_eq!(safety_gate_evaluate_calls(), 0);
    }

    #[tokio::test]
    async fn standing_reject_precedes_replay_gate_memo() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gate_ctx(tmp.path(), ApprovalMode::Auto, true);
        let approver = ctx.approver.as_ref().unwrap();
        let classification = classify("gh pr create");
        let info = classification.simple_commands().iter().next().unwrap();
        approver
            .store()
            .record_command_reject(info, Scope::Session)
            .unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let args = serde_json::json!({ "command": "gh pr create" });
        let providers = crate::config::providers::ProvidersConfig::default();
        let payload = crate::db::needs_attention::InterruptParkPayload {
            tool: "bash".to_string(),
            args: args.clone(),
            call_id: "call-1".to_string(),
            resume: crate::db::needs_attention::InterruptResumeAnchor {
                agent_id: "builder".to_string(),
                call_id: "call-1".to_string(),
                provider_call_id: None,
                assistant_seq: None,
                call_origin: crate::db::needs_attention::InterruptCallOrigin::Foreground,
            },
            gate: Some(crate::db::needs_attention::InterruptGateMemo {
                recheck_result: true,
            }),
        };

        reset_safety_gate_evaluate_calls();
        let outcome = crate::engine::interrupt::with_interrupt_park_payload(payload, async {
            safety_gate_decision_with_configs("bash", &args, &ctx, &tx, None, &providers).await
        })
        .await;

        match outcome {
            GateOutcome::Block(block) => assert_eq!(block.status, "blocked_standing_reject"),
            GateOutcome::Run { .. } => panic!("standing reject must override replay gate memo"),
            GateOutcome::Parked => panic!("standing reject must not park"),
        }
        assert_eq!(safety_gate_evaluate_calls(), 0);
    }

    #[tokio::test]
    async fn standing_reject_yolo_bypass_pinned() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gate_ctx(tmp.path(), ApprovalMode::Yolo, true);
        let approver = ctx.approver.as_ref().unwrap();
        let classification = classify("gh pr create");
        let info = classification.simple_commands().iter().next().unwrap();
        approver
            .store()
            .record_command_reject(info, Scope::Session)
            .unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let args = serde_json::json!({ "command": "gh pr create" });

        reset_safety_gate_evaluate_calls();
        let outcome = safety_gate_decision("bash", &args, &ctx, &tx).await;

        assert!(matches!(outcome, GateOutcome::Run { recheck: false }));
        assert_eq!(safety_gate_evaluate_calls(), 0);
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

        tokio::time::sleep(Duration::from_millis(60)).await;
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
            GateOutcome::Block(block) => {
                assert!(
                    block.message.contains("safety gate"),
                    "got: {}",
                    block.message
                );
                assert_eq!(block.status, "blocked_safety_gate");
            }
            GateOutcome::Run { .. } => {
                panic!("auto mode must NOT silently run when the gate is unavailable")
            }
            GateOutcome::Parked => panic!("no-client gate escalation must block, not park"),
        }
    }

    #[tokio::test]
    async fn interrupt_replay_reuses_memoized_gate_decision() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = gate_ctx(tmp.path(), ApprovalMode::Auto, false);
        let (tx, _rx) = mpsc::channel(8);
        let args = serde_json::json!({ "command": "ls" });
        let providers = crate::config::providers::ProvidersConfig::default();
        let payload = crate::db::needs_attention::InterruptParkPayload {
            tool: "bash".to_string(),
            args: args.clone(),
            call_id: "call-1".to_string(),
            resume: crate::db::needs_attention::InterruptResumeAnchor {
                agent_id: "builder".to_string(),
                call_id: "call-1".to_string(),
                provider_call_id: None,
                assistant_seq: None,
                call_origin: crate::db::needs_attention::InterruptCallOrigin::Foreground,
            },
            gate: Some(crate::db::needs_attention::InterruptGateMemo {
                recheck_result: true,
            }),
        };

        let outcome = crate::engine::interrupt::with_interrupt_park_payload(payload, async {
            safety_gate_decision_with_configs("bash", &args, &ctx, &tx, None, &providers).await
        })
        .await;

        assert!(matches!(outcome, GateOutcome::Run { recheck: true }));
    }

    #[tokio::test]
    async fn interrupt_replay_gate_escalation_parks_and_replays() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = gate_ctx(tmp.path(), ApprovalMode::Auto, false);
        let hub = attached_interrupt_hub(&ctx);
        attach_approver_with_hub(&mut ctx, hub.clone());
        let ctx = Arc::new(ctx);
        let (tx, _rx) = mpsc::channel(8);
        let args = serde_json::json!({ "server": "example", "tool": "mutate" });
        let payload = crate::db::needs_attention::InterruptParkPayload {
            tool: "mcp".to_string(),
            args: args.clone(),
            call_id: "call-1".to_string(),
            resume: crate::db::needs_attention::InterruptResumeAnchor {
                agent_id: "builder".to_string(),
                call_id: "call-1".to_string(),
                provider_call_id: None,
                assistant_seq: None,
                call_origin: crate::db::needs_attention::InterruptCallOrigin::Foreground,
            },
            gate: None,
        };
        let first_ctx = ctx.clone();
        let first_tx = tx.clone();
        let first_args = args.clone();
        let first_payload = payload.clone();
        let first = tokio::spawn(async move {
            crate::engine::interrupt::with_interrupt_park_payload(first_payload, async {
                escalate_gated_call("mcp", &first_args, &first_ctx, true, &first_tx).await
            })
            .await
        });

        let interrupt_id = wait_for_open_interrupt(&ctx).await;
        let row = ctx
            .session
            .db
            .get_interrupt(interrupt_id)
            .unwrap()
            .expect("parked gate row");
        assert!(
            row.parked.is_some(),
            "gate interrupt must carry replay payload"
        );
        assert_eq!(hub.park_all_registered(), 1);
        assert_eq!(first.await.unwrap(), GateApproval::Parked);

        let response = crate::daemon::proto::ResolveResponse::Single {
            selected_id: crate::approval::ID_APPROVE.to_string(),
        };
        assert!(
            ctx.session
                .db
                .begin_parked_interrupt_execution(interrupt_id, &response)
                .unwrap()
        );
        let question = replay_question_from_row(&ctx, interrupt_id);
        let replayed = crate::engine::interrupt::with_pre_resolved_interrupt_question(
            interrupt_id,
            response,
            question,
            async {
                crate::engine::interrupt::with_interrupt_park_payload(payload, async {
                    escalate_gated_call("mcp", &args, &ctx, true, &tx).await
                })
                .await
            },
        )
        .await;
        assert_eq!(replayed, GateApproval::Allow);
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
