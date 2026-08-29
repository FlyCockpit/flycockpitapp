use std::collections::{BTreeMap, BTreeSet};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::FutureExt;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolBox, ToolCtx, ToolOutput};

const GLOBAL_TOOL_TIMEOUT: Duration = Duration::from_secs(120);
const TOOL_ABANDON_HOOK_TIMEOUT: Duration = Duration::from_secs(5);
const AV_TOOL_TIMEOUT: Duration = Duration::from_secs(135);
const AV_TOOL_CANCEL_GRACE: Duration = Duration::from_secs(30);

/// Checked-in tool timeout and abandon-safety inventory for production tools.
///
/// Cancel-aware native tools: `bash`, A/V tools, and the native `webfetch` /
/// `websearch` implementations override `Tool::honors_dispatch_cancel`; after
/// cancellation the dispatcher gives only those concrete tool objects a
/// bounded grace window to run their own cleanup before abandoning them. A/V
/// cleanup has a larger bounded window for process-tree and durable artifact
/// compensation. Custom command tools with the reserved web names stay
/// abandon-safe but do not receive that grace.
/// Mixed MCP tool: `mcp` reaches external servers over owned per-call clients
/// and can also invoke cockpit-native tools; nested native invokes route through
/// this dispatcher helper again once reached, so they get their own independent
/// timeout while the outer `mcp` wrapper still caps the whole sandbox run.
/// Human-blocking unbounded tools: `escalate`, `question`.
/// Every other listed tool is abandon-safe under the dispatcher-level drop
/// contract and uses the global timeout unless an override is added. Dynamic
/// custom command tools are also covered by the total default lookup; their
/// runtime names are user-authored, so the static inventory covers only native
/// production registrations.
const TOOL_TIMEOUT_SAFETY: &[ToolTimeoutSafety] = &[
    ToolTimeoutSafety::abandon_safe("add-package"),
    ToolTimeoutSafety::honors_cancel("bash"),
    ToolTimeoutSafety::abandon_safe("cancel_image_generation_job"),
    ToolTimeoutSafety::abandon_safe("change_impact"),
    ToolTimeoutSafety::abandon_safe("code"),
    ToolTimeoutSafety::abandon_safe("context_pack"),
    ToolTimeoutSafety::abandon_safe("defer_to_orchestrator"),
    ToolTimeoutSafety::abandon_safe("delegation_payload_retrieve"),
    ToolTimeoutSafety::abandon_safe("edit"),
    ToolTimeoutSafety::human_blocking("escalate"),
    // A/V tools own subprocess and durable reservation/attachment cleanup.
    // They observe dispatcher cancellation and must not be dropped under the
    // abandon-safe contract while that cleanup is in flight.
    ToolTimeoutSafety::honors_cancel("extract_audio"),
    ToolTimeoutSafety::honors_cancel("extract_video_clip"),
    ToolTimeoutSafety::abandon_safe("generate_image"),
    ToolTimeoutSafety::abandon_safe("get_image_generation_job"),
    ToolTimeoutSafety::abandon_safe("glob"),
    ToolTimeoutSafety::abandon_safe("goal"),
    ToolTimeoutSafety::abandon_safe("grep"),
    ToolTimeoutSafety::abandon_safe("harness_invoke"),
    ToolTimeoutSafety::abandon_safe("harness_list"),
    ToolTimeoutSafety::abandon_safe("graph"),
    ToolTimeoutSafety::honors_cancel("inspect_audio"),
    ToolTimeoutSafety::honors_cancel("inspect_video"),
    ToolTimeoutSafety::abandon_safe("list-packages"),
    ToolTimeoutSafety::abandon_safe("list_image_generation_targets"),
    ToolTimeoutSafety::abandon_safe("lsp"),
    ToolTimeoutSafety::nested_dispatch_or_owned_transport("mcp"),
    ToolTimeoutSafety::abandon_safe("memory_search"),
    ToolTimeoutSafety::abandon_safe("note"),
    ToolTimeoutSafety::abandon_safe("plan_edit"),
    ToolTimeoutSafety::abandon_safe("plan_read"),
    ToolTimeoutSafety::abandon_safe("plan_write"),
    ToolTimeoutSafety::human_blocking("question"),
    ToolTimeoutSafety::abandon_safe("read"),
    ToolTimeoutSafety::abandon_safe("read_image"),
    ToolTimeoutSafety::abandon_safe("ask_image"),
    ToolTimeoutSafety::abandon_safe("return"),
    ToolTimeoutSafety::abandon_safe("schedule"),
    ToolTimeoutSafety::abandon_safe("search"),
    ToolTimeoutSafety::abandon_safe("seed"),
    ToolTimeoutSafety::abandon_safe("session_lineage_search"),
    ToolTimeoutSafety::abandon_safe("session_read"),
    ToolTimeoutSafety::abandon_safe("session_search"),
    ToolTimeoutSafety::abandon_safe("skill"),
    ToolTimeoutSafety::abandon_safe("skill_manage"),
    ToolTimeoutSafety::abandon_safe("spawn"),
    ToolTimeoutSafety::abandon_safe("start_build"),
    ToolTimeoutSafety::abandon_safe("task"),
    ToolTimeoutSafety::abandon_safe("todo"),
    // Journaled provider POST. Dispatcher drop does not cancel `ctx.cancel`
    // (that token is the turn). The tool clones a child token and cancels it
    // on drop so a detached send records `completed_after_cancel` instead of
    // `succeeded` with an undeliverable body.
    ToolTimeoutSafety::honors_cancel("transcribe_audio"),
    ToolTimeoutSafety::abandon_safe("artifact_read"),
    ToolTimeoutSafety::abandon_safe("artifact_search"),
    ToolTimeoutSafety::abandon_safe("unlock"),
    // `use_sealed_value` dispatches an Owner-compiled adapter outbound to a
    // fixed destination. Abandoning it mid-flight cannot be assumed safe: the
    // external effect may already have landed, and the caller is never told
    // either way (the completion is a fixed constant).
    ToolTimeoutSafety::nested_dispatch_or_owned_transport("use_sealed_value"),
    ToolTimeoutSafety::web_backend_dependent("webfetch"),
    ToolTimeoutSafety::web_backend_dependent("websearch"),
    // Candidate validation mutates the primary tree under exclusive path
    // locks, then restores on Drop of the `validate_*` future (wrapper
    // process-group SIGKILL-and-wait, overlay snapshot, reverse-patch
    // guard, exclusive-hold guard). Dispatcher timeout and cancel
    // `drop(call)` and are therefore abandon-safe.
    ToolTimeoutSafety::abandon_safe("worktree_orchestrate"),
    ToolTimeoutSafety::abandon_safe("write"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolAbandonSafety {
    HonorsCancel,
    NestedDispatchOrOwnedTransport,
    HumanBlocking,
    AbandonSafe,
    WebBackendDependent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ToolTimeoutSafety {
    name: &'static str,
    safety: ToolAbandonSafety,
}

impl ToolTimeoutSafety {
    const fn honors_cancel(name: &'static str) -> Self {
        Self {
            name,
            safety: ToolAbandonSafety::HonorsCancel,
        }
    }

    const fn human_blocking(name: &'static str) -> Self {
        Self {
            name,
            safety: ToolAbandonSafety::HumanBlocking,
        }
    }

    const fn nested_dispatch_or_owned_transport(name: &'static str) -> Self {
        Self {
            name,
            safety: ToolAbandonSafety::NestedDispatchOrOwnedTransport,
        }
    }

    const fn abandon_safe(name: &'static str) -> Self {
        Self {
            name,
            safety: ToolAbandonSafety::AbandonSafe,
        }
    }

    const fn web_backend_dependent(name: &'static str) -> Self {
        Self {
            name,
            safety: ToolAbandonSafety::WebBackendDependent,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ToolTimeoutPolicy {
    default: Duration,
    overrides: BTreeMap<&'static str, Option<Duration>>,
}

impl Default for ToolTimeoutPolicy {
    fn default() -> Self {
        let overrides = BTreeMap::from([
            // Preserve bash's existing per-call maximum; its own shorter
            // timeout/cancel path kills the process group.
            ("bash", Some(Duration::from_secs(600))),
            // The longest individual FFmpeg runner deadline is 120s. Preserve
            // a bounded cleanup window beyond it; if a multi-run storyboard
            // reaches this outer cap, the dispatcher cancels its child token
            // and waits for cancel-aware cleanup before returning.
            ("extract_audio", Some(AV_TOOL_TIMEOUT)),
            ("extract_video_clip", Some(AV_TOOL_TIMEOUT)),
            ("inspect_audio", Some(AV_TOOL_TIMEOUT)),
            ("inspect_video", Some(AV_TOOL_TIMEOUT)),
            // `mcp` wraps up to 60s of sandbox execution around host calls; keep
            // the outer wrapper above the default so one nested native dispatch
            // can reach its own 120s timeout.
            ("mcp", Some(Duration::from_secs(240))),
            // `question` waits for an interrupt answer from a human.
            ("question", None),
            // `escalate` waits for a human approval decision.
            ("escalate", None),
        ]);
        let documented_unbounded = TOOL_TIMEOUT_SAFETY
            .iter()
            .filter_map(|entry| {
                matches!(entry.safety, ToolAbandonSafety::HumanBlocking).then_some(entry.name)
            })
            .collect::<BTreeSet<_>>();
        debug_assert_eq!(
            overrides
                .iter()
                .filter_map(|(name, timeout)| timeout.is_none().then_some(*name))
                .collect::<BTreeSet<_>>(),
            documented_unbounded
        );
        Self {
            default: GLOBAL_TOOL_TIMEOUT,
            overrides,
        }
    }
}

impl ToolTimeoutPolicy {
    #[cfg(test)]
    fn new(default: Duration, overrides: BTreeMap<&'static str, Option<Duration>>) -> Self {
        Self { default, overrides }
    }

    pub(crate) fn lookup(&self, name: &str) -> Option<Duration> {
        self.overrides
            .get(name)
            .copied()
            .unwrap_or(Some(self.default))
    }

    #[cfg(test)]
    fn covers(&self, name: &str) -> bool {
        self.overrides.contains_key(name) || self.lookup(name).is_some()
    }

    #[cfg(test)]
    fn unbounded_names(&self) -> BTreeSet<&'static str> {
        self.overrides
            .iter()
            .filter_map(|(name, timeout)| timeout.is_none().then_some(*name))
            .collect()
    }

    fn cancel_grace(&self, tool: &dyn Tool) -> Option<Duration> {
        tool.honors_dispatch_cancel().then(|| {
            if matches!(
                tool.name(),
                "inspect_audio" | "inspect_video" | "extract_audio" | "extract_video_clip"
            ) {
                AV_TOOL_CANCEL_GRACE
            } else {
                TOOL_ABANDON_HOOK_TIMEOUT
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolTimedOut {
    pub tool: String,
    pub timeout_ms: u64,
}

impl ToolTimedOut {
    fn output(&self) -> ToolOutput {
        ToolOutput::text(format!(
            "tool `{}` did not return within {}s and was abandoned",
            self.tool,
            self.timeout_ms / 1000
        ))
        .with_unknown_host_effect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolCancelled {
    pub tool: String,
}

impl ToolCancelled {
    fn output(&self) -> ToolOutput {
        ToolOutput::text(format!(
            "tool `{}` was cancelled by the user and abandoned",
            self.tool
        ))
        .with_unknown_host_effect()
    }
}

pub(super) async fn dispatch_with_default_timeout(
    tools: &ToolBox,
    name: &str,
    args: Value,
    ctx: &ToolCtx,
    current_tool_call_id: Option<&str>,
) -> Result<ToolOutput> {
    let policy = ToolTimeoutPolicy::default();
    dispatch_with_policy(tools, name, args, ctx, current_tool_call_id, &policy).await
}

pub(crate) async fn dispatch_arc_with_default_timeout(
    tool: Arc<dyn Tool>,
    args: Value,
    ctx: &ToolCtx,
    current_tool_call_id: Option<&str>,
) -> Result<ToolOutput> {
    let policy = ToolTimeoutPolicy::default();
    let name = tool.name().to_string();
    dispatch_tool_with_policy(tool, &name, args, ctx, current_tool_call_id, &policy).await
}

async fn dispatch_with_policy(
    tools: &ToolBox,
    name: &str,
    args: Value,
    ctx: &ToolCtx,
    current_tool_call_id: Option<&str>,
    policy: &ToolTimeoutPolicy,
) -> Result<ToolOutput> {
    let tool = tools
        .get_cloned(name)
        .with_context(|| format!("unknown tool `{name}`"))?;
    dispatch_tool_with_policy(tool, name, args, ctx, current_tool_call_id, policy).await
}

async fn dispatch_tool_with_policy(
    tool: Arc<dyn Tool>,
    name: &str,
    args: Value,
    ctx: &ToolCtx,
    current_tool_call_id: Option<&str>,
    policy: &ToolTimeoutPolicy,
) -> Result<ToolOutput> {
    crate::engine::interrupt::with_host_approval_effect_scope(
        "tool_dispatch",
        ctx.cancel.clone(),
        dispatch_tool_with_policy_unscoped(tool, name, args, ctx, current_tool_call_id, policy),
        // A shell's non-zero exit is a definitive rejected operation, not an
        // ambiguous handoff. Other tool output shapes have no process-exit
        // field and therefore report their successful return as completion.
        |output: &ToolOutput| Some(output.exit_code.is_none_or(|code| code == 0)),
    )
    .await
}

/// The timeout/cancellation machinery runs inside the host-approval effect
/// handoff scope above.  Keeping the body separate makes every exit path
/// (normal return, timeout, cancellation grace expiry, or error) pass through
/// the one definitive completion/submission-unknown boundary.
async fn dispatch_tool_with_policy_unscoped(
    tool: Arc<dyn Tool>,
    name: &str,
    args: Value,
    ctx: &ToolCtx,
    current_tool_call_id: Option<&str>,
    policy: &ToolTimeoutPolicy,
) -> Result<ToolOutput> {
    let args = crate::engine::model::wire_schema::strip_wire_nulls(&tool.parameters(), args);
    let mut ctx = ctx.clone_for_dispatch();
    // Isolate dispatcher deadlines from the caller's session token while still
    // propagating parent cancellation. A timeout can now request cleanup for
    // this call without cancelling sibling work that shares the parent token.
    ctx.cancel = ctx.cancel.child_token();
    ctx.current_tool_call_id = current_tool_call_id.map(str::to_string);
    // Monty and other timeout-dispatcher enter paths skip `dispatch_one`.
    // Keep the durable lease fence here so a ToolCtx snapshot cannot
    // authorize work after another actor expires or revokes the row.
    ctx.revalidate_workspace_lease_effect_boundary()
        .await
        .map_err(|error| {
            crate::engine::tool::invalid_input(format!(
                "workspace lease is unavailable at this tool boundary: {error:#}"
            ))
        })?;
    // This dispatcher deliberately does *not* claim host-approval
    // capabilities from a generic `(tool, wire_input)` projection. A selected
    // command/MCP/harness/filesystem/package/computer candidate carries facts
    // that only its lower concrete boundary can reconstruct. Claiming here
    // would either reject valid rich candidates before they reach that
    // boundary, or make a generic wrapper the irreversible submission point.
    // Concrete effect implementations claim the ready capability immediately
    // before their real spawn/request/mutation instead.
    let timeout = policy.lookup(name);
    let mut call = Box::pin(tool.call(args, &ctx));
    if ctx.cancel.is_cancelled() {
        drop(call);
        run_abandon_hook(tool, &ctx, name).await;
        return Ok(ToolCancelled {
            tool: name.to_string(),
        }
        .output());
    }

    match timeout {
        Some(timeout) => {
            let deadline = tokio::time::sleep(timeout);
            tokio::pin!(deadline);
            tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => {
                    if let Some(grace) = policy.cancel_grace(tool.as_ref()) {
                        let cancel_grace = tokio::time::sleep(grace);
                        tokio::pin!(cancel_grace);
                        tokio::select! {
                            biased;
                            result = &mut call => cancelled_error_as_output(result, &ctx, name),
                            _ = &mut cancel_grace => {
                                drop(call);
                                run_abandon_hook(tool, &ctx, name).await;
                                Ok(ToolCancelled { tool: name.to_string() }.output())
                            }
                        }
                    } else {
                        drop(call);
                        run_abandon_hook(tool, &ctx, name).await;
                        Ok(ToolCancelled { tool: name.to_string() }.output())
                    }
                }
                result = &mut call => result,
                _ = &mut deadline => {
                    if let Some(grace) = policy.cancel_grace(tool.as_ref()) {
                        ctx.cancel.cancel();
                        let cleanup_grace = tokio::time::sleep(grace);
                        tokio::pin!(cleanup_grace);
                        tokio::select! {
                            biased;
                            _ = &mut call => Ok(ToolTimedOut {
                                tool: name.to_string(),
                                timeout_ms: timeout.as_millis() as u64,
                            }.output()),
                            _ = &mut cleanup_grace => {
                                drop(call);
                                run_abandon_hook(tool, &ctx, name).await;
                                Ok(ToolTimedOut {
                                    tool: name.to_string(),
                                    timeout_ms: timeout.as_millis() as u64,
                                }.output())
                            }
                        }
                    } else {
                        drop(call);
                        run_abandon_hook(tool, &ctx, name).await;
                        Ok(ToolTimedOut {
                            tool: name.to_string(),
                            timeout_ms: timeout.as_millis() as u64,
                        }.output())
                    }
                }
            }
        }
        None => {
            tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => {
                    if let Some(grace) = policy.cancel_grace(tool.as_ref()) {
                        let cancel_grace = tokio::time::sleep(grace);
                        tokio::pin!(cancel_grace);
                        tokio::select! {
                            biased;
                            result = &mut call => cancelled_error_as_output(result, &ctx, name),
                            _ = &mut cancel_grace => {
                                drop(call);
                                run_abandon_hook(tool, &ctx, name).await;
                                Ok(ToolCancelled { tool: name.to_string() }.output())
                            }
                        }
                    } else {
                        drop(call);
                        run_abandon_hook(tool, &ctx, name).await;
                        Ok(ToolCancelled { tool: name.to_string() }.output())
                    }
                }
                result = &mut call => result,
            }
        }
    }
}

fn cancelled_error_as_output(
    result: Result<ToolOutput>,
    ctx: &ToolCtx,
    name: &str,
) -> Result<ToolOutput> {
    if ctx.cancel.is_cancelled() && result.is_err() {
        return Ok(ToolCancelled {
            tool: name.to_string(),
        }
        .output());
    }
    result
}

async fn run_abandon_hook(tool: Arc<dyn crate::engine::tool::Tool>, ctx: &ToolCtx, name: &str) {
    let hook = AssertUnwindSafe(tool.on_abandon(ctx)).catch_unwind();
    tokio::pin!(hook);
    let timeout = tokio::time::sleep(TOOL_ABANDON_HOOK_TIMEOUT);
    tokio::pin!(timeout);
    tokio::select! {
        biased;
        result = &mut hook => {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(tool = name, error = ?error, "tool abandon hook failed");
                }
                Err(_panic) => {
                    tracing::warn!(tool = name, "tool abandon hook panicked");
                }
            }
        }
        _ = &mut timeout => {
            tracing::warn!(
                tool = name,
                timeout_ms = TOOL_ABANDON_HOOK_TIMEOUT.as_millis() as u64,
                "tool abandon hook timed out"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use serde_json::json;

    use crate::engine::tool::Tool;

    struct TimedTestTool {
        name: &'static str,
        sleep: Option<Duration>,
        call_count: Arc<AtomicUsize>,
        abandon_count: Arc<AtomicUsize>,
        abandon_mode: AbandonMode,
        honors_cancel: bool,
        fail_after_sleep: bool,
    }

    #[derive(Clone, Copy)]
    enum AbandonMode {
        Ok,
        Err,
        Panic,
        Pending,
    }

    impl TimedTestTool {
        fn new(
            name: &'static str,
            sleep: Option<Duration>,
            abandon_count: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                name,
                sleep,
                call_count: Arc::new(AtomicUsize::new(0)),
                abandon_count,
                abandon_mode: AbandonMode::Ok,
                honors_cancel: false,
                fail_after_sleep: false,
            }
        }

        fn with_call_count(mut self, call_count: Arc<AtomicUsize>) -> Self {
            self.call_count = call_count;
            self
        }

        fn with_abandon_mode(mut self, abandon_mode: AbandonMode) -> Self {
            self.abandon_mode = abandon_mode;
            self
        }

        fn with_honors_cancel(mut self) -> Self {
            self.honors_cancel = true;
            self
        }

        fn with_error_result(mut self) -> Self {
            self.fail_after_sleep = true;
            self
        }
    }

    #[async_trait]
    impl Tool for TimedTestTool {
        fn name(&self) -> &str {
            self.name
        }

        fn description(&self) -> &str {
            "test tool"
        }

        fn parameters(&self) -> Value {
            json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            match self.sleep {
                Some(duration) => tokio::time::sleep(duration).await,
                None => std::future::pending::<()>().await,
            }
            if self.fail_after_sleep {
                anyhow::bail!("tool observed cancellation");
            }
            Ok(ToolOutput::text("finished"))
        }

        fn honors_dispatch_cancel(&self) -> bool {
            self.honors_cancel
        }

        async fn on_abandon(&self, _ctx: &ToolCtx) -> Result<()> {
            self.abandon_count.fetch_add(1, Ordering::SeqCst);
            match self.abandon_mode {
                AbandonMode::Ok => Ok(()),
                AbandonMode::Err => anyhow::bail!("teardown failed"),
                AbandonMode::Panic => panic!("teardown panic"),
                AbandonMode::Pending => std::future::pending::<Result<()>>().await,
            }
        }
    }

    struct DeadlineCleanupTool {
        cleanup_finished: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Tool for DeadlineCleanupTool {
        fn name(&self) -> &str {
            "deadline-cleanup"
        }

        fn description(&self) -> &str {
            "deadline cleanup test tool"
        }

        fn parameters(&self) -> Value {
            json!({"type": "object", "properties": {}})
        }

        fn honors_dispatch_cancel(&self) -> bool {
            true
        }

        async fn call(&self, _args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
            ctx.cancel.cancelled().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            self.cleanup_finished.store(true, Ordering::SeqCst);
            anyhow::bail!("deadline cleanup completed")
        }
    }

    fn test_ctx() -> (tempfile::TempDir, ToolCtx) {
        let dir = tempfile::tempdir().expect("tempdir");
        let ctx = crate::tools::common::test_ctx(dir.path());
        (dir, ctx)
    }

    fn policy_with_default(timeout: Duration) -> ToolTimeoutPolicy {
        ToolTimeoutPolicy::new(timeout, BTreeMap::new())
    }

    async fn run_test_tool(
        tool: TimedTestTool,
        ctx: &ToolCtx,
        policy: &ToolTimeoutPolicy,
    ) -> Result<ToolOutput> {
        let name = tool.name;
        let tools = ToolBox::new().with(Arc::new(tool));
        dispatch_with_policy(&tools, name, json!({}), ctx, Some("call-1"), policy).await
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_returns_typed_timed_out_tool_result() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = policy_with_default(Duration::from_secs(120));
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move { run_test_tool(TimedTestTool::new("slow", None, count), &ctx, &policy).await }
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(
            output.content,
            "tool `slow` did not return within 120s and was abandoned"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_cancels_cancel_aware_call_and_waits_for_cleanup() {
        let (_dir, ctx) = test_ctx();
        let cleanup_finished = Arc::new(AtomicBool::new(false));
        let policy = policy_with_default(Duration::from_secs(120));
        let tools = ToolBox::new().with(Arc::new(DeadlineCleanupTool {
            cleanup_finished: cleanup_finished.clone(),
        }));
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            async move {
                dispatch_with_policy(
                    &tools,
                    "deadline-cleanup",
                    json!({}),
                    &ctx,
                    Some("call-1"),
                    &policy,
                )
                .await
            }
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert!(
            !dispatch.is_finished(),
            "dispatcher must retain the cleanup future"
        );
        assert!(!cleanup_finished.load(Ordering::SeqCst));
        tokio::time::advance(Duration::from_secs(1)).await;
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert!(cleanup_finished.load(Ordering::SeqCst));
        assert_eq!(
            output.content,
            "tool `deadline-cleanup` did not return within 120s and was abandoned"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_invokes_teardown_hook_exactly_once_on_abandon() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = policy_with_default(Duration::from_secs(120));
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move { run_test_tool(TimedTestTool::new("slow", None, count), &ctx, &policy).await }
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        let _ = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_no_teardown_on_normal_completion() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = policy_with_default(Duration::from_secs(120));
        let output = run_test_tool(
            TimedTestTool::new("fast", Some(Duration::from_secs(1)), count.clone()),
            &ctx,
            &policy,
        )
        .await
        .expect("tool result");

        assert_eq!(output.content, "finished");
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_unbounded_opt_out_tool_never_times_out() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = ToolTimeoutPolicy::default();
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move {
                run_test_tool(
                    TimedTestTool::new("question", Some(Duration::from_secs(121)), count),
                    &ctx,
                    &policy,
                )
                .await
            }
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert!(!dispatch.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(output.content, "finished");
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_cancel_aborts_dispatch_before_deadline() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let count = count.clone();
            async move {
                super::super::dispatch_one_timed(
                    &ToolBox::new().with(Arc::new(TimedTestTool::new("slow", None, count))),
                    "slow",
                    json!({}),
                    &ctx,
                    Some("call-1"),
                )
                .await
            }
        });

        tokio::task::yield_now().await;
        ctx.cancel.cancel();
        let (result, elapsed_ms) = dispatch.await.expect("dispatch join");
        let output = result.expect("tool result");

        assert_eq!(
            output.content,
            "tool `slow` was cancelled by the user and abandoned"
        );
        assert!(elapsed_ms < 120_000, "elapsed_ms={elapsed_ms}");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_prefired_cancel_wins_over_ready_completion() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = policy_with_default(Duration::from_secs(120));
        ctx.cancel.cancel();

        let output = run_test_tool(
            TimedTestTool::new("fast", Some(Duration::ZERO), count.clone()),
            &ctx,
            &policy,
        )
        .await
        .expect("tool result");

        assert_eq!(
            output.content,
            "tool `fast` was cancelled by the user and abandoned"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_cancel_aware_tool_gets_grace_to_finish() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = ToolTimeoutPolicy::default();
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move {
                run_test_tool(
                    TimedTestTool::new("bash", Some(Duration::from_secs(1)), count)
                        .with_honors_cancel(),
                    &ctx,
                    &policy,
                )
                .await
            }
        });

        tokio::task::yield_now().await;
        ctx.cancel.cancel();
        tokio::time::advance(Duration::from_secs(1)).await;
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(output.content, "finished");
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_cancel_aware_error_during_grace_is_cancelled_output() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = ToolTimeoutPolicy::default();
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move {
                run_test_tool(
                    TimedTestTool::new("code", Some(Duration::from_secs(1)), count)
                        .with_honors_cancel()
                        .with_error_result(),
                    &ctx,
                    &policy,
                )
                .await
            }
        });

        tokio::task::yield_now().await;
        ctx.cancel.cancel();
        tokio::time::advance(Duration::from_secs(1)).await;
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(
            output.content,
            "tool `code` was cancelled by the user and abandoned"
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_prefired_cancel_aware_tool_does_not_start() {
        let (_dir, ctx) = test_ctx();
        let abandon_count = Arc::new(AtomicUsize::new(0));
        let call_count = Arc::new(AtomicUsize::new(0));
        let policy = ToolTimeoutPolicy::default();
        ctx.cancel.cancel();

        let output = run_test_tool(
            TimedTestTool::new("bash", Some(Duration::from_secs(1)), abandon_count.clone())
                .with_call_count(call_count.clone())
                .with_honors_cancel(),
            &ctx,
            &policy,
        )
        .await
        .expect("tool result");

        assert_eq!(
            output.content,
            "tool `bash` was cancelled by the user and abandoned"
        );
        assert_eq!(call_count.load(Ordering::SeqCst), 0);
        assert_eq!(abandon_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_web_name_without_cancel_capability_gets_no_grace() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = ToolTimeoutPolicy::default();
        ctx.cancel.cancel();
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move {
                run_test_tool(
                    TimedTestTool::new("webfetch", Some(Duration::from_secs(1)), count),
                    &ctx,
                    &policy,
                )
                .await
            }
        });

        tokio::task::yield_now().await;
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(
            output.content,
            "tool `webfetch` was cancelled by the user and abandoned"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_cancel_wins_over_deadline_when_both_ready() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = policy_with_default(Duration::from_secs(120));
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move { run_test_tool(TimedTestTool::new("slow", None, count), &ctx, &policy).await }
        });

        tokio::task::yield_now().await;
        ctx.cancel.cancel();
        tokio::time::advance(Duration::from_secs(120)).await;
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(
            output.content,
            "tool `slow` was cancelled by the user and abandoned"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_completion_wins_over_deadline_race() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = policy_with_default(Duration::from_secs(120));
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move {
                run_test_tool(
                    TimedTestTool::new("edge", Some(Duration::from_secs(120)), count),
                    &ctx,
                    &policy,
                )
                .await
            }
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(output.content, "finished");
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_unbounded_tool_still_honors_cancel() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = ToolTimeoutPolicy::default();
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move {
                run_test_tool(TimedTestTool::new("question", None, count), &ctx, &policy).await
            }
        });

        tokio::task::yield_now().await;
        ctx.cancel.cancel();
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(
            output.content,
            "tool `question` was cancelled by the user and abandoned"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_panicking_teardown_hook_still_returns_timeout_result() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = policy_with_default(Duration::from_secs(120));
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move {
                run_test_tool(
                    TimedTestTool::new("slow", None, count).with_abandon_mode(AbandonMode::Panic),
                    &ctx,
                    &policy,
                )
                .await
            }
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(
            output.content,
            "tool `slow` did not return within 120s and was abandoned"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_pending_teardown_hook_still_returns_timeout_result() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = policy_with_default(Duration::from_secs(120));
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move {
                run_test_tool(
                    TimedTestTool::new("slow", None, count).with_abandon_mode(AbandonMode::Pending),
                    &ctx,
                    &policy,
                )
                .await
            }
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        tokio::task::yield_now().await;
        assert!(
            !dispatch.is_finished(),
            "pending teardown should be bounded but not skipped"
        );
        tokio::time::advance(TOOL_ABANDON_HOOK_TIMEOUT).await;
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(
            output.content,
            "tool `slow` did not return within 120s and was abandoned"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_failing_teardown_hook_still_returns_timeout_result() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let policy = policy_with_default(Duration::from_secs(120));
        let dispatch = tokio::spawn({
            let ctx = ctx.clone_for_dispatch();
            let policy = policy.clone();
            let count = count.clone();
            async move {
                run_test_tool(
                    TimedTestTool::new("slow", None, count).with_abandon_mode(AbandonMode::Err),
                    &ctx,
                    &policy,
                )
                .await
            }
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        let output = dispatch.await.expect("dispatch join").expect("tool result");

        assert_eq!(
            output.content,
            "tool `slow` did not return within 120s and was abandoned"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tool_timeout_timed_dispatch_reports_elapsed_bound() {
        let (_dir, ctx) = test_ctx();
        let count = Arc::new(AtomicUsize::new(0));
        let tools = ToolBox::new().with(Arc::new(TimedTestTool::new("slow", None, count)));
        let dispatch = tokio::spawn(async move {
            super::super::dispatch_one_timed(&tools, "slow", json!({}), &ctx, Some("call-1")).await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        let (result, elapsed_ms) = dispatch.await.expect("dispatch join");

        assert!(result.expect("tool result").content.contains("120s"));
        assert!(elapsed_ms >= 120_000, "elapsed_ms={elapsed_ms}");
    }

    #[test]
    fn tool_timeout_policy_covers_every_registered_tool() {
        let policy = ToolTimeoutPolicy::default();
        let missing = crate::engine::builtin::invariant_builtin_tools()
            .into_iter()
            .map(|tool| tool.name().to_string())
            .filter(|name| !policy.covers(name))
            .collect::<Vec<_>>();

        assert!(
            missing.is_empty(),
            "tools missing timeout policy: {missing:?}"
        );
    }

    #[test]
    fn tool_timeout_policy_opt_out_set_matches_documentation() {
        let policy = ToolTimeoutPolicy::default();
        let documented = TOOL_TIMEOUT_SAFETY
            .iter()
            .filter_map(|entry| {
                matches!(entry.safety, ToolAbandonSafety::HumanBlocking).then_some(entry.name)
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(policy.unbounded_names(), documented);
    }

    #[test]
    fn tool_timeout_policy_preserves_bash_max_timeout() {
        let policy = ToolTimeoutPolicy::default();

        assert_eq!(policy.lookup("bash"), Some(Duration::from_secs(600)));
    }

    #[test]
    fn tool_timeout_policy_gives_mcp_wrapper_room_for_nested_default() {
        let policy = ToolTimeoutPolicy::default();

        assert!(policy.lookup("mcp") > policy.lookup("read"));
    }

    #[test]
    fn tool_timeout_policy_gives_av_runner_bounded_cleanup_room() {
        let policy = ToolTimeoutPolicy::default();
        let media_names = [
            "inspect_audio",
            "inspect_video",
            "extract_audio",
            "extract_video_clip",
        ];

        for name in media_names {
            assert_eq!(policy.lookup(name), Some(AV_TOOL_TIMEOUT), "{name}");
            let safety = TOOL_TIMEOUT_SAFETY
                .iter()
                .find(|entry| entry.name == name)
                .map(|entry| entry.safety);
            assert_eq!(safety, Some(ToolAbandonSafety::HonorsCancel), "{name}");
        }
        assert!(AV_TOOL_TIMEOUT > Duration::from_secs(120));
        assert!(AV_TOOL_CANCEL_GRACE > Duration::from_secs(4));
        let tools: [Box<dyn Tool>; 4] = [
            Box::new(crate::tools::audio_video::InspectAudioTool::new()),
            Box::new(crate::tools::audio_video::InspectVideoTool::new()),
            Box::new(crate::tools::audio_video::ExtractAudioTool::new()),
            Box::new(crate::tools::audio_video::ExtractVideoClipTool::new()),
        ];
        for tool in tools {
            assert_eq!(
                policy.cancel_grace(tool.as_ref()),
                Some(AV_TOOL_CANCEL_GRACE)
            );
        }
        let ordinary =
            TimedTestTool::new("bash", None, Arc::new(AtomicUsize::new(0))).with_honors_cancel();
        assert_eq!(
            policy.cancel_grace(&ordinary),
            Some(TOOL_ABANDON_HOOK_TIMEOUT)
        );
    }

    #[test]
    fn tool_timeout_documentation_covers_registered_tools() {
        let documented = TOOL_TIMEOUT_SAFETY
            .iter()
            .map(|entry| entry.name)
            .collect::<BTreeSet<_>>();
        let missing = crate::engine::builtin::invariant_builtin_tools()
            .into_iter()
            .map(|tool| tool.name().to_string())
            .filter(|name| !documented.contains(name.as_str()))
            .collect::<Vec<_>>();

        assert!(missing.is_empty(), "tools missing safety docs: {missing:?}");
    }

    #[test]
    fn tool_timeout_documentation_covers_runtime_attached_tools() {
        let documented = TOOL_TIMEOUT_SAFETY
            .iter()
            .map(|entry| entry.name)
            .collect::<BTreeSet<_>>();
        let runtime_attached_tools = crate::knowledge::runtime_attached_tool_names()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();

        assert!(
            runtime_attached_tools.is_subset(&documented),
            "runtime-attached tools missing safety docs: {:?}",
            runtime_attached_tools
                .difference(&documented)
                .collect::<Vec<_>>()
        );
    }
}
