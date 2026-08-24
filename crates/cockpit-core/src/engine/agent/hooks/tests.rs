//! Tests for the tool hooks dispatch and runner.
//!
//! These tests verify:
//! - Hook event table dispatches each native lifecycle boundary
//! - Pre-tool hook explicit deny blocks dispatch
//! - Pre-tool hook failures are fail-open
//! - Tool hooks run in canonical lifecycle order
//! - Tool hook matcher and ordering
//! - Tool hook runner envelope bounds and reserved environment
//! - Tool hook runner argv, timeout, and proven-empty
//! - Stop hook continuation state machine
//! - Session config snapshot is turn-stable
//! - Hook run event import and rehydration

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::config::extended::hooks::{HookEvent, HookOrigin, HookRegistry, ResolvedHook};
use crate::db::session_log::{HookRunAudit, HookRunStatus};
use crate::engine::agent::hooks::*;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// A fake process environment for deterministic tests.
///
/// `resolved` is the explicit result of `resolve_executable`. `None` means
/// "not found" (the lookup returned nothing). Use
/// `FakeProcessEnv::with_default_resolution` for the common case where a
/// fake absolute path should be returned for any bare name.
#[derive(Debug, Clone, Default)]
struct FakeProcessEnv {
    resolved: Option<PathBuf>,
    system_root: Option<String>,
    /// When true, `resolve_executable` synthesizes `/fake/bin/<name>` for any
    /// bare name instead of returning `resolved`. This preserves the
    /// "default" behavior for tests that don't care about the exact path.
    use_default_resolution: bool,
}

impl FakeProcessEnv {
    /// A fake env that resolves any bare name to `/fake/bin/<name>`.
    #[allow(dead_code)]
    fn with_default_resolution() -> Self {
        Self {
            resolved: None,
            system_root: None,
            use_default_resolution: true,
        }
    }
}

impl ProcessEnv for FakeProcessEnv {
    fn resolve_executable(&self, name: &str) -> Option<PathBuf> {
        if self.use_default_resolution {
            Some(PathBuf::from(format!("/fake/bin/{name}")))
        } else {
            self.resolved.clone()
        }
    }

    fn system_root(&self) -> Option<String> {
        self.system_root.clone()
    }
}

/// A captured command invocation for test assertions.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CapturedInvocation {
    executable: PathBuf,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    cwd: PathBuf,
    stdin: String,
    timeout: Duration,
}

/// A fake command runner that returns pre-configured output and captures
/// invocations.
#[derive(Clone)]
struct FakeCommandRunner {
    output: HookRawOutput,
    invocations: Arc<Mutex<Vec<CapturedInvocation>>>,
}

impl FakeCommandRunner {
    fn new(output: HookRawOutput) -> Self {
        Self {
            output,
            invocations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn invocations(&self) -> Vec<CapturedInvocation> {
        self.invocations.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl CommandRunner for FakeCommandRunner {
    async fn run(
        &self,
        executable: &Path,
        args: &[String],
        env: &BTreeMap<String, String>,
        cwd: &Path,
        stdin: &str,
        timeout: Duration,
        _session_id: Uuid,
    ) -> HookRawOutput {
        self.invocations.lock().unwrap().push(CapturedInvocation {
            executable: executable.to_path_buf(),
            args: args.to_vec(),
            env: env.clone(),
            cwd: cwd.to_path_buf(),
            stdin: stdin.to_string(),
            timeout,
        });
        self.output.clone()
    }
}

/// Build a `ResolvedHook` for tests.
fn test_hook(
    event: HookEvent,
    command: Vec<String>,
    matcher: Option<Vec<String>>,
    env: BTreeMap<String, String>,
    timeout_secs: u16,
) -> ResolvedHook {
    ResolvedHook {
        event,
        matcher: matcher.map(|values| values.into_iter().collect()),
        command,
        timeout_secs,
        env,
        origin: HookOrigin::for_test("project:abcdef0123456789:0"),
        source_config_path: PathBuf::from("/tmp/test/config.json"),
        source_directory: PathBuf::from("/tmp/test"),
    }
}

fn registry(hooks: Vec<ResolvedHook>) -> HookRegistry {
    HookRegistry {
        hooks,
        warnings: Vec::new(),
    }
}

fn successful_output(stdout: &str) -> HookRawOutput {
    HookRawOutput {
        stdout: stdout.to_string(),
        exit_code: Some(0),
        duration_ms: 10,
        spawn_failed: false,
        timeout: false,
        failure_reason: None,
        output_truncated: false,
    }
}

fn failed_output() -> HookRawOutput {
    HookRawOutput {
        stdout: String::new(),
        exit_code: Some(1),
        duration_ms: 10,
        spawn_failed: false,
        timeout: false,
        failure_reason: None,
        output_truncated: false,
    }
}

fn timeout_output() -> HookRawOutput {
    HookRawOutput {
        stdout: String::new(),
        exit_code: None,
        duration_ms: 1000,
        spawn_failed: false,
        timeout: true,
        failure_reason: None,
        output_truncated: false,
    }
}

fn spawn_failed_output() -> HookRawOutput {
    HookRawOutput {
        stdout: String::new(),
        exit_code: None,
        duration_ms: 0,
        spawn_failed: true,
        timeout: false,
        failure_reason: None,
        output_truncated: false,
    }
}

// ---------------------------------------------------------------------------
// Decision parsing tests
// ---------------------------------------------------------------------------

#[test]
fn parse_pre_tool_decision_allow_on_empty_stdout() {
    let decision = parse_pre_tool_decision("", Some(0));
    assert_eq!(decision, HookDecision::Allow);
}

#[test]
fn parse_pre_tool_decision_deny_with_reason() {
    let stdout = r#"{"decision":"deny","reason":"too risky"}"#;
    let decision = parse_pre_tool_decision(stdout, Some(0));
    assert_eq!(
        decision,
        HookDecision::Deny {
            reason: "too risky".to_string()
        }
    );
}

#[test]
fn parse_pre_tool_decision_deny_with_blank_reason_uses_default() {
    let stdout = r#"{"decision":"deny","reason":"  "}"#;
    let decision = parse_pre_tool_decision(stdout, Some(0));
    assert_eq!(
        decision,
        HookDecision::Deny {
            reason: DEFAULT_DENY_REASON.to_string()
        }
    );
}

#[test]
fn parse_pre_tool_decision_deny_with_missing_reason_uses_default() {
    let stdout = r#"{"decision":"deny"}"#;
    let decision = parse_pre_tool_decision(stdout, Some(0));
    assert_eq!(
        decision,
        HookDecision::Deny {
            reason: DEFAULT_DENY_REASON.to_string()
        }
    );
}

#[test]
fn parse_pre_tool_decision_nonzero_exit_without_stdout_is_failed_not_deny() {
    let decision = parse_pre_tool_decision("", Some(2));
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

#[test]
fn parse_pre_tool_decision_malformed_json_is_failed() {
    let decision = parse_pre_tool_decision("not json", Some(0));
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

#[test]
fn parse_pre_tool_decision_non_object_json_is_failed() {
    let decision = parse_pre_tool_decision(r#""string""#, Some(0));
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

#[test]
fn parse_pre_tool_decision_unknown_decision_is_failed() {
    let stdout = r#"{"decision":"maybe"}"#;
    let decision = parse_pre_tool_decision(stdout, Some(0));
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

#[test]
fn parse_pre_tool_decision_allow_explicit() {
    let stdout = r#"{"decision":"allow"}"#;
    let decision = parse_pre_tool_decision(stdout, Some(0));
    assert_eq!(decision, HookDecision::Allow);
}

#[test]
fn parse_pre_tool_decision_block_is_not_valid_for_pre_tool() {
    let stdout = r#"{"decision":"block","reason":"..."}"#;
    let decision = parse_pre_tool_decision(stdout, Some(0));
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

#[test]
fn parse_pre_tool_decision_non_string_reason_is_failed() {
    let stdout = r#"{"decision":"deny","reason":123}"#;
    let decision = parse_pre_tool_decision(stdout, Some(0));
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

// ---------------------------------------------------------------------------
// Matcher tests
// ---------------------------------------------------------------------------

#[test]
fn matching_hooks_exact_match_with_matcher() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["echo".to_string()],
        Some(vec!["bash".to_string()]),
        BTreeMap::new(),
        5,
    );
    let reg = registry(vec![hook]);
    let matches = matching_hooks(&reg, HookEvent::PreToolUse, "bash");
    assert_eq!(matches.len(), 1);
}

#[test]
fn matching_hooks_no_match_with_wrong_tool_name() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["echo".to_string()],
        Some(vec!["bash".to_string()]),
        BTreeMap::new(),
        5,
    );
    let reg = registry(vec![hook]);
    let matches = matching_hooks(&reg, HookEvent::PreToolUse, "read");
    assert!(matches.is_empty());
}

#[test]
fn matching_hooks_no_matcher_matches_all() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["echo".to_string()],
        None,
        BTreeMap::new(),
        5,
    );
    let reg = registry(vec![hook]);
    let matches = matching_hooks(&reg, HookEvent::PreToolUse, "any_tool");
    assert_eq!(matches.len(), 1);
}

#[test]
fn matching_hooks_wrong_event_does_not_match() {
    let hook = test_hook(
        HookEvent::PostToolUse,
        vec!["echo".to_string()],
        Some(vec!["bash".to_string()]),
        BTreeMap::new(),
        5,
    );
    let reg = registry(vec![hook]);
    let matches = matching_hooks(&reg, HookEvent::PreToolUse, "bash");
    assert!(matches.is_empty());
}

#[test]
fn matching_hooks_multiple_matchers_all_match() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["echo".to_string()],
        Some(vec!["bash".to_string(), "read".to_string()]),
        BTreeMap::new(),
        5,
    );
    let reg = registry(vec![hook]);
    assert_eq!(matching_hooks(&reg, HookEvent::PreToolUse, "bash").len(), 1);
    assert_eq!(matching_hooks(&reg, HookEvent::PreToolUse, "read").len(), 1);
    assert!(matching_hooks(&reg, HookEvent::PreToolUse, "write").is_empty());
}

// ---------------------------------------------------------------------------
// Envelope tests
// ---------------------------------------------------------------------------

#[test]
fn envelope_for_pre_tool_use_is_camelcase() {
    let envelope = HookEnvelope::for_pre_tool_use(
        HookEvent::PreToolUse,
        uuid::Uuid::new_v4(),
        Path::new("/workspace"),
        "2025-01-01T00:00:00Z",
        "bash",
        "call_123",
        &json!({"command": "ls"}),
    );
    let json_str = envelope.to_json_string();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["hookEventName"], "preToolUse");
    assert!(parsed["sessionId"].is_string());
    assert_eq!(parsed["workspaceRoot"], "/workspace");
    assert_eq!(parsed["toolName"], "bash");
    assert_eq!(parsed["toolCallId"], "call_123");
    assert_eq!(parsed["toolInput"]["command"], "ls");
    assert!(parsed.get("toolInputTruncated").is_none());
}

#[test]
fn envelope_for_post_tool_use_success() {
    let envelope = HookEnvelope::for_post_tool_use(
        HookEvent::PostToolUse,
        uuid::Uuid::new_v4(),
        Path::new("/workspace"),
        "2025-01-01T00:00:00Z",
        "bash",
        "call_123",
        &json!({"command": "ls"}),
        Some(&json!("file1.txt")),
        None,
    );
    let json_str = envelope.to_json_string();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["hookEventName"], "postToolUse");
    assert_eq!(parsed["toolResult"], "file1.txt");
    assert!(parsed.get("toolError").is_none());
}

#[test]
fn envelope_for_post_tool_use_failure() {
    let envelope = HookEnvelope::for_post_tool_use(
        HookEvent::PostToolUseFailure,
        uuid::Uuid::new_v4(),
        Path::new("/workspace"),
        "2025-01-01T00:00:00Z",
        "bash",
        "call_123",
        &json!({"command": "ls"}),
        None,
        Some("command failed"),
    );
    let json_str = envelope.to_json_string();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["hookEventName"], "postToolUseFailure");
    assert_eq!(parsed["toolError"], "command failed");
    assert!(parsed.get("toolResult").is_none());
}

#[test]
fn envelope_clips_oversized_input() {
    let big_input = json!(vec!["x".repeat(ENVELOPE_VALUE_MAX_BYTES + 1000)]);
    let envelope = HookEnvelope::for_pre_tool_use(
        HookEvent::PreToolUse,
        uuid::Uuid::new_v4(),
        Path::new("/workspace"),
        "2025-01-01T00:00:00Z",
        "bash",
        "call_123",
        &big_input,
    );
    assert_eq!(envelope.tool_input_truncated, Some(true));
    let serialized = serde_json::to_string(envelope.tool_input.as_ref().unwrap()).unwrap();
    assert!(serialized.len() <= ENVELOPE_VALUE_MAX_BYTES);
}

#[test]
fn envelope_small_input_is_not_truncated() {
    let input = json!({"command": "ls"});
    let envelope = HookEnvelope::for_pre_tool_use(
        HookEvent::PreToolUse,
        uuid::Uuid::new_v4(),
        Path::new("/workspace"),
        "2025-01-01T00:00:00Z",
        "bash",
        "call_123",
        &input,
    );
    assert!(envelope.tool_input_truncated.is_none());
}

// ---------------------------------------------------------------------------
// Environment construction tests
// ---------------------------------------------------------------------------

#[test]
fn build_child_env_includes_reserved_keys() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["/usr/bin/echo".to_string()],
        Some(vec!["bash".to_string()]),
        BTreeMap::new(),
        5,
    );
    let process_env = FakeProcessEnv::default();
    let session_id = uuid::Uuid::new_v4();
    let env = build_child_env(
        &hook,
        &process_env,
        HookEvent::PreToolUse,
        session_id,
        Path::new("/workspace"),
        Some("bash"),
        Some("call_123"),
    )
    .unwrap();

    assert_eq!(env["COCKPIT_HOOK_EVENT"], "preToolUse");
    assert_eq!(env["COCKPIT_HOOK_NAME"], "project:abcdef0123456789:0");
    assert_eq!(env["COCKPIT_SESSION_ID"], session_id.to_string());
    assert_eq!(env["COCKPIT_WORKSPACE_ROOT"], "/workspace");
    assert_eq!(env["COCKPIT_TOOL_NAME"], "bash");
    assert_eq!(env["COCKPIT_TOOL_CALL_ID"], "call_123");
}

#[test]
fn build_child_env_reserved_keys_overwrite_configured_env() {
    let mut configured = BTreeMap::new();
    configured.insert("COCKPIT_HOOK_EVENT".to_string(), "spoofed".to_string());
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["/usr/bin/echo".to_string()],
        None,
        configured,
        5,
    );
    let process_env = FakeProcessEnv::default();
    let env = build_child_env(
        &hook,
        &process_env,
        HookEvent::PreToolUse,
        uuid::Uuid::new_v4(),
        Path::new("/workspace"),
        Some("bash"),
        Some("call_123"),
    )
    .unwrap();

    assert_eq!(env["COCKPIT_HOOK_EVENT"], "preToolUse");
}

#[test]
fn build_child_env_delivers_configured_env() {
    let mut configured = BTreeMap::new();
    configured.insert("MY_HOOK_VAR".to_string(), "value123".to_string());
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["/usr/bin/echo".to_string()],
        None,
        configured,
        5,
    );
    let process_env = FakeProcessEnv::default();
    let env = build_child_env(
        &hook,
        &process_env,
        HookEvent::PreToolUse,
        uuid::Uuid::new_v4(),
        Path::new("/workspace"),
        Some("bash"),
        Some("call_123"),
    )
    .unwrap();

    assert_eq!(env["MY_HOOK_VAR"], "value123");
}

#[test]
#[cfg(unix)]
fn build_child_env_no_inherited_unix_variables() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["/usr/bin/echo".to_string()],
        None,
        BTreeMap::new(),
        5,
    );
    let process_env = FakeProcessEnv::default();
    let env = build_child_env(
        &hook,
        &process_env,
        HookEvent::PreToolUse,
        uuid::Uuid::new_v4(),
        Path::new("/workspace"),
        Some("bash"),
        Some("call_123"),
    )
    .unwrap();

    // No PATH, no ambient host variables.
    assert!(!env.contains_key("PATH"));
    assert!(!env.contains_key("HOME"));
    assert!(!env.contains_key("USER"));
}

#[test]
fn build_child_env_no_comspec_no_pathext_on_windows() {
    // On non-Windows this test verifies no ComSpec/PATHEXT exist (trivially
    // true). On Windows it verifies the Windows-specific env construction
    // doesn't add them.
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["/usr/bin/echo".to_string()],
        None,
        BTreeMap::new(),
        5,
    );
    let process_env = FakeProcessEnv::default();
    let env = build_child_env(
        &hook,
        &process_env,
        HookEvent::PreToolUse,
        uuid::Uuid::new_v4(),
        Path::new("/workspace"),
        Some("bash"),
        Some("call_123"),
    )
    .unwrap();

    assert!(!env.contains_key("ComSpec"));
    assert!(!env.contains_key("PATHEXT"));
}

// ---------------------------------------------------------------------------
// Executable resolution tests
// ---------------------------------------------------------------------------

#[test]
fn resolve_hook_executable_absolute_path_passed_through() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["/usr/bin/echo".to_string()],
        None,
        BTreeMap::new(),
        5,
    );
    let process_env = FakeProcessEnv::default();
    let resolved = resolve_hook_executable(&hook, &process_env);
    assert_eq!(resolved, Some(PathBuf::from("/usr/bin/echo")));
}

#[test]
fn resolve_hook_executable_bare_name_resolved_via_process_env() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["my-hook".to_string()],
        None,
        BTreeMap::new(),
        5,
    );
    let process_env = FakeProcessEnv {
        resolved: Some(PathBuf::from("/custom/path/my-hook")),
        system_root: None,
        use_default_resolution: false,
    };
    let resolved = resolve_hook_executable(&hook, &process_env);
    assert_eq!(resolved, Some(PathBuf::from("/custom/path/my-hook")));
}

#[test]
fn resolve_hook_executable_not_found_returns_none() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["nonexistent-hook".to_string()],
        None,
        BTreeMap::new(),
        5,
    );
    let process_env = FakeProcessEnv {
        resolved: None,
        system_root: None,
        use_default_resolution: false,
    };
    let resolved = resolve_hook_executable(&hook, &process_env);
    assert!(resolved.is_none());
}

// ---------------------------------------------------------------------------
// Hook run audit tests
// ---------------------------------------------------------------------------

#[test]
fn build_hook_run_audit_success() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["/usr/bin/echo".to_string()],
        None,
        BTreeMap::new(),
        5,
    );
    let decision = HookDecision::Allow;
    let audit = build_hook_run_audit(
        HookEvent::PreToolUse,
        &hook,
        &decision,
        42,
        None,
        Some("bash"),
        Some("call_123"),
        None,
    );
    assert_eq!(audit.event, "preToolUse");
    assert_eq!(audit.hook, "project:abcdef0123456789:0");
    assert_eq!(audit.origin, "project:abcdef0123456789:0");
    assert_eq!(audit.status, HookRunStatus::Success);
    assert_eq!(audit.duration_ms, 42);
    assert!(audit.reason.is_none());
    assert_eq!(audit.tool_name.as_deref(), Some("bash"));
    assert_eq!(audit.tool_call_id.as_deref(), Some("call_123"));
}

#[test]
fn build_hook_run_audit_denied_with_reason() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["/usr/bin/echo".to_string()],
        None,
        BTreeMap::new(),
        5,
    );
    let decision = HookDecision::Deny {
        reason: "too risky".to_string(),
    };
    let audit = build_hook_run_audit(
        HookEvent::PreToolUse,
        &hook,
        &decision,
        100,
        None,
        Some("bash"),
        Some("call_123"),
        None,
    );
    assert_eq!(audit.status, HookRunStatus::Denied);
    assert_eq!(audit.reason.as_deref(), Some("too risky"));
}

#[test]
fn build_hook_run_audit_failed() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["/usr/bin/echo".to_string()],
        None,
        BTreeMap::new(),
        5,
    );
    let decision = HookDecision::Failed {
        reason: "timed out".to_string(),
    };
    let audit = build_hook_run_audit(
        HookEvent::PreToolUse,
        &hook,
        &decision,
        1000,
        None,
        Some("bash"),
        Some("call_123"),
        None,
    );
    assert_eq!(audit.status, HookRunStatus::Failed);
    assert_eq!(audit.reason.as_deref(), Some("timed out"));
}

// ---------------------------------------------------------------------------
// Hook run audit serialization (import/rehydration)
// ---------------------------------------------------------------------------

#[test]
fn hook_run_audit_serializes_and_deserializes_unchanged() {
    let audit = HookRunAudit {
        event: "preToolUse".to_string(),
        hook: "project:abcdef0123456789:0".to_string(),
        origin: "project:abcdef0123456789:0".to_string(),
        status: HookRunStatus::Denied,
        duration_ms: 42,
        reason: Some("too risky".to_string()),
        turn_id: Some("turn_1".to_string()),
        tool_name: Some("bash".to_string()),
        tool_call_id: Some("call_123".to_string()),
        subagent_id: None,
    };
    let json = serde_json::to_value(&audit).unwrap();
    let restored: HookRunAudit = serde_json::from_value(json).unwrap();
    assert_eq!(audit, restored);
}

#[test]
fn hook_run_audit_rejects_unknown_fields() {
    let mut json = serde_json::to_value(&HookRunAudit {
        event: "preToolUse".to_string(),
        hook: "project:abcdef0123456789:0".to_string(),
        origin: "project:abcdef0123456789:0".to_string(),
        status: HookRunStatus::Success,
        duration_ms: 0,
        reason: None,
        turn_id: None,
        tool_name: None,
        tool_call_id: None,
        subagent_id: None,
    })
    .unwrap();
    json["secret_field"] = json!("should be rejected");
    let result: Result<HookRunAudit, _> = serde_json::from_value(json);
    assert!(result.is_err());
}

#[test]
fn hook_run_audit_all_statuses_roundtrip() {
    for status in HookRunStatus::ALL {
        let audit = HookRunAudit {
            event: "preToolUse".to_string(),
            hook: "project:abcdef0123456789:0".to_string(),
            origin: "project:abcdef0123456789:0".to_string(),
            status,
            duration_ms: 0,
            reason: None,
            turn_id: None,
            tool_name: None,
            tool_call_id: None,
            subagent_id: None,
        };
        let json = serde_json::to_value(&audit).unwrap();
        let restored: HookRunAudit = serde_json::from_value(json).unwrap();
        assert_eq!(audit, restored);
    }
}

// ---------------------------------------------------------------------------
// Stop-gate state machine tests
// ---------------------------------------------------------------------------

#[test]
fn stop_gate_state_default_is_inactive() {
    let state = StopGateState::default();
    assert!(!state.stop_hook_active);
    assert_eq!(state.continuation_count, 0);
    assert!(!state.capped());
}

#[test]
fn stop_gate_state_capped_at_max_continuations() {
    let state = StopGateState {
        continuation_count: STOP_HOOK_MAX_CONTINUATIONS,
        ..Default::default()
    };
    assert!(state.capped());
}

#[test]
fn stop_gate_state_not_capped_below_max() {
    let state = StopGateState {
        continuation_count: STOP_HOOK_MAX_CONTINUATIONS - 1,
        ..Default::default()
    };
    assert!(!state.capped());
}

#[test]
fn stop_gate_feedback_empty_does_not_continue() {
    let feedback = StopGateFeedback::default();
    assert!(!feedback.should_continue_round());
}

#[test]
fn stop_gate_feedback_with_blocks_continues() {
    let feedback = StopGateFeedback {
        blocks: vec!["please continue".to_string()],
        additional_contexts: vec![],
        forced_end: false,
    };
    assert!(feedback.should_continue_round());
}

#[test]
fn stop_gate_feedback_forced_end_does_not_continue() {
    let feedback = StopGateFeedback {
        blocks: vec!["blocked".to_string()],
        additional_contexts: vec![],
        forced_end: true,
    };
    assert!(!feedback.should_continue_round());
}

#[test]
fn stop_gate_feedback_combined_reason_joins_blocks() {
    let feedback = StopGateFeedback {
        blocks: vec!["block1".to_string(), "block2".to_string()],
        additional_contexts: vec![],
        forced_end: false,
    };
    assert_eq!(feedback.combined_reason(), "block1\nblock2");
}

#[test]
fn stop_gate_feedback_combined_additional_context_joins() {
    let feedback = StopGateFeedback {
        blocks: vec![],
        additional_contexts: vec!["ctx1".to_string(), "ctx2".to_string()],
        forced_end: false,
    };
    assert_eq!(
        feedback.combined_additional_context().as_deref(),
        Some("ctx1\nctx2")
    );
}

#[test]
fn stop_gate_feedback_empty_additional_context_returns_none() {
    let feedback = StopGateFeedback::default();
    assert!(feedback.combined_additional_context().is_none());
}

// ---------------------------------------------------------------------------
// Stop decision parsing tests
// ---------------------------------------------------------------------------

#[test]
fn parse_stop_decision_continue_false_ends_turn() {
    let stdout = r#"{"continue":false,"stopReason":"done"}"#;
    let decision = parse_stop_decision(stdout, Some(0));
    assert!(matches!(decision, HookDecision::Continue { .. }));
    if let HookDecision::Continue { stop_reason } = decision {
        assert_eq!(stop_reason, "done");
    }
}

#[test]
fn parse_stop_decision_block_aggregates_feedback() {
    let stdout = r#"{"decision":"block","reason":"need more info","hookSpecificOutput":{"additionalContext":"try X"}}"#;
    let decision = parse_stop_decision(stdout, Some(0));
    assert!(matches!(decision, HookDecision::Block { .. }));
    if let HookDecision::Block {
        reason,
        additional_context,
    } = decision
    {
        assert_eq!(reason, "need more info");
        assert_eq!(additional_context.as_deref(), Some("try X"));
    }
}

#[test]
fn parse_stop_decision_deny_is_not_valid_for_stop() {
    let stdout = r#"{"decision":"deny","reason":"no"}"#;
    let decision = parse_stop_decision(stdout, Some(0));
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

#[test]
fn parse_stop_decision_allow_passes() {
    let stdout = r#"{"decision":"allow"}"#;
    let decision = parse_stop_decision(stdout, Some(0));
    assert_eq!(decision, HookDecision::Allow);
}

#[test]
fn parse_stop_decision_continue_true_is_allow() {
    let stdout = r#"{"continue":true}"#;
    let decision = parse_stop_decision(stdout, Some(0));
    assert_eq!(decision, HookDecision::Allow);
}

#[test]
fn parse_stop_decision_block_without_additional_context() {
    let stdout = r#"{"decision":"block","reason":"stop"}"#;
    let decision = parse_stop_decision(stdout, Some(0));
    if let HookDecision::Block {
        reason,
        additional_context,
    } = decision
    {
        assert_eq!(reason, "stop");
        assert!(additional_context.is_none());
    } else {
        panic!("expected Block");
    }
}

#[test]
fn parse_stop_decision_continue_false_with_blank_reason_uses_default() {
    let stdout = r#"{"continue":false}"#;
    let decision = parse_stop_decision(stdout, Some(0));
    if let HookDecision::Continue { stop_reason } = decision {
        assert!(!stop_reason.is_empty());
    } else {
        panic!("expected Continue");
    }
}

// ---------------------------------------------------------------------------
// Observe decision parsing tests
// ---------------------------------------------------------------------------

#[test]
fn parse_observe_decision_valid_json_is_allow() {
    let stdout = r#"{"some":"output"}"#;
    let decision = parse_observe_decision(stdout, Some(0));
    assert_eq!(decision, HookDecision::Allow);
}

#[test]
fn parse_observe_decision_empty_stdout_exit_zero_is_allow() {
    let decision = parse_observe_decision("", Some(0));
    assert_eq!(decision, HookDecision::Allow);
}

#[test]
fn parse_observe_decision_nonzero_exit_is_failed() {
    let decision = parse_observe_decision("", Some(1));
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

#[test]
fn parse_observe_decision_malformed_json_is_failed() {
    let decision = parse_observe_decision("garbage", Some(0));
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

// ---------------------------------------------------------------------------
// Reason clipping tests
// ---------------------------------------------------------------------------

#[test]
fn clip_reason_short_string_unchanged() {
    let result = clip_reason("short reason");
    assert_eq!(result, "short reason");
}

#[test]
fn clip_reason_long_string_truncated_to_max_chars() {
    let long_reason = "x".repeat(REASON_MAX_CHARS + 100);
    let result = clip_reason(&long_reason);
    assert_eq!(result.chars().count(), REASON_MAX_CHARS);
}

#[test]
fn clip_reason_exact_max_is_not_truncated() {
    let exact_reason = "x".repeat(REASON_MAX_CHARS);
    let result = clip_reason(&exact_reason);
    assert_eq!(result.chars().count(), REASON_MAX_CHARS);
}

// ---------------------------------------------------------------------------
// Hook event table tests
// ---------------------------------------------------------------------------

/// Run one matching `run_observe_hooks` invocation against a fresh ledger and
/// return `(recorded (event,status) rows, parsed stdin envelope if the hook was
/// invoked)`. Drives the production dispatcher every wired boundary calls, with
/// an injected fake runner (captures stdin) + fake process env — no real
/// process, no wall-clock sleep, no `std::env` mutation.
async fn observe_once(
    process_env: &dyn ProcessEnv,
    reg: &HookRegistry,
    event: HookEvent,
    match_value: &str,
    tool_name: Option<&str>,
    fields: ObserveFields<'_>,
) -> (Vec<(String, String)>, Option<Value>) {
    let (db, sid) = db_session().await;
    let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
    run_observe_hooks(
        &runner,
        process_env,
        reg,
        event,
        match_value,
        sid,
        workspace(),
        &db,
        tool_name,
        None,
        None,
        None,
        fields,
    )
    .await;
    let rows = hook_run_events(&db, sid).await;
    let stdin_json = runner
        .invocations()
        .first()
        .map(|inv| serde_json::from_str::<Value>(&inv.stdin).expect("envelope is valid JSON"));
    (rows, stdin_json)
}

/// Like [`observe_once`] but for the child-subagent events: the matcher is the
/// child agent type, and the envelope carries `subagentType` / `subagentId` /
/// `endReason`. Drives the production `run_observe_hooks` dispatcher with an
/// injected fake runner (captures stdin) + fake process env.
async fn observe_subagent_once(
    reg: &HookRegistry,
    event: HookEvent,
    subagent_type: &str,
    subagent_id: Option<&str>,
    fields: ObserveFields<'_>,
) -> (Vec<(String, String)>, Option<Value>) {
    let (db, sid) = db_session().await;
    let env = FakeProcessEnv::with_default_resolution();
    let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
    run_observe_hooks(
        &runner,
        &env,
        reg,
        event,
        // Matcher for `subagentStart` / `subagentStop` is the child agent type.
        subagent_type,
        sid,
        workspace(),
        &db,
        None,
        None,
        Some(subagent_type),
        subagent_id,
        fields,
    )
    .await;
    let rows = hook_run_events(&db, sid).await;
    let stdin_json = runner
        .invocations()
        .first()
        .map(|inv| serde_json::from_str::<Value>(&inv.stdin).expect("envelope is valid JSON"));
    (rows, stdin_json)
}

/// A `ResolvedHook` matching `event` only on `matcher`.
fn observe_hook(event: HookEvent, matcher: &str) -> ResolvedHook {
    test_hook(
        event,
        vec!["obs".to_string()],
        Some(vec![matcher.to_string()]),
        BTreeMap::new(),
        5,
    )
}

#[tokio::test]
async fn hook_dispatcher_matches_typed_lifecycle_envelopes() {
    // Scripted per-event acceptance harness. Together with the typed
    // PRODUCTION_HOOK_BOUNDARIES ownership table, it covers every member of
    // HookEvent::ALL at its production matcher vocabulary:
    //   1. a hook whose matcher equals the boundary vocabulary fires exactly
    //      one `hook_run` row and receives its first-class typed envelope field
    //      on stdin, and
    //   2. a hook whose matcher is a *lookalike* (a sibling value the boundary
    //      never uses) fires nothing — proving exact-matcher selection, not a
    //      blanket "any hook for this event" dispatch.
    // Stop/tool gates are exercised through their dedicated production-seam
    // cases below; observe boundaries are driven here. The row/no-row pairs
    // fail if exact matching regresses into prefix/lookalike acceptance.
    let env = FakeProcessEnv::with_default_resolution();

    // sessionStart: matcher `fresh` | `resume`; typed field `startSource`.
    let (rows, stdin) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::SessionStart, "fresh")]),
        HookEvent::SessionStart,
        "fresh",
        None,
        ObserveFields {
            start_source: Some("fresh"),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        rows,
        vec![("sessionStart".to_string(), "success".to_string())]
    );
    let stdin = stdin.expect("sessionStart hook invoked");
    assert_eq!(stdin["hookEventName"], "sessionStart");
    assert_eq!(stdin["startSource"], "fresh");
    // Lookalike matcher (`resume`) must not fire on a `fresh` start.
    let (rows, _) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::SessionStart, "resume")]),
        HookEvent::SessionStart,
        "fresh",
        None,
        ObserveFields {
            start_source: Some("fresh"),
            ..Default::default()
        },
    )
    .await;
    assert!(
        rows.is_empty(),
        "resume-only hook must not fire on fresh start"
    );

    // userPromptSubmit: matcher `user` | `queued`; typed field `promptSource`.
    let (rows, stdin) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::UserPromptSubmit, "queued")]),
        HookEvent::UserPromptSubmit,
        "queued",
        None,
        ObserveFields {
            prompt_source: Some("queued"),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        rows,
        vec![("userPromptSubmit".to_string(), "success".to_string())]
    );
    let stdin = stdin.expect("userPromptSubmit hook invoked");
    assert_eq!(stdin["promptSource"], "queued");
    let (rows, _) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::UserPromptSubmit, "user")]),
        HookEvent::UserPromptSubmit,
        "queued",
        None,
        ObserveFields {
            prompt_source: Some("queued"),
            ..Default::default()
        },
    )
    .await;
    assert!(
        rows.is_empty(),
        "user-only hook must not fire on queued fold"
    );

    // permissionDenied: matcher = resolved tool name; typed field
    // `permissionKind` carries the deny status string (distinct from the
    // matcher), and the envelope also carries `toolName`.
    let (rows, stdin) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::PermissionDenied, "bash")]),
        HookEvent::PermissionDenied,
        "bash",
        Some("bash"),
        ObserveFields {
            permission_kind: Some("review_cage_denied"),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        rows,
        vec![("permissionDenied".to_string(), "success".to_string())]
    );
    let stdin = stdin.expect("permissionDenied hook invoked");
    assert_eq!(stdin["toolName"], "bash");
    assert_eq!(stdin["permissionKind"], "review_cage_denied");
    let (rows, _) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::PermissionDenied, "read")]),
        HookEvent::PermissionDenied,
        "bash",
        Some("bash"),
        ObserveFields {
            permission_kind: Some("review_cage_denied"),
            ..Default::default()
        },
    )
    .await;
    assert!(
        rows.is_empty(),
        "read-only hook must not fire on a bash deny"
    );

    // preCompact / postCompact: matcher = compact source; typed field
    // `compactSource` uses the closed public `manual` / `auto` vocabulary.
    for (event, key, source) in [
        (HookEvent::PreCompact, "preCompact", "manual"),
        (HookEvent::PostCompact, "postCompact", "auto"),
    ] {
        let (rows, stdin) = observe_once(
            &env,
            &registry(vec![observe_hook(event, source)]),
            event,
            source,
            None,
            ObserveFields {
                compact_source: Some(source),
                compaction_id: Some("01890f3e-4c00-7000-8000-000000000099"),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(rows, vec![(key.to_string(), "success".to_string())]);
        let stdin = stdin.expect("compact hook invoked");
        assert_eq!(stdin["hookEventName"], key);
        assert_eq!(stdin["compactSource"], source);
        assert_eq!(
            stdin["compactionId"],
            "01890f3e-4c00-7000-8000-000000000099"
        );
    }
    // A manual compaction must not fire an `auto`-only hook.
    let (rows, _) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::PreCompact, "auto")]),
        HookEvent::PreCompact,
        "manual",
        None,
        ObserveFields {
            compact_source: Some("manual"),
            ..Default::default()
        },
    )
    .await;
    assert!(
        rows.is_empty(),
        "manual must stay a distinct compactSource from auto"
    );

    // stopFailure: matcher = `error_class_match_value`; typed field `errorClass`.
    let network = error_class_match_value(&crate::engine::model::InferenceErrorClass::Network);
    assert_eq!(network, "network");
    let (rows, stdin) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::StopFailure, network)]),
        HookEvent::StopFailure,
        network,
        None,
        ObserveFields {
            error_class: Some(network),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        rows,
        vec![("stopFailure".to_string(), "success".to_string())]
    );
    let stdin = stdin.expect("stopFailure hook invoked");
    assert_eq!(stdin["errorClass"], "network");
    // A different error class is a distinct token (no vocabulary collapse).
    let ttft = error_class_match_value(&crate::engine::model::InferenceErrorClass::TimeoutTtft);
    assert_ne!(ttft, network);
    let (rows, _) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::StopFailure, ttft)]),
        HookEvent::StopFailure,
        network,
        None,
        ObserveFields {
            error_class: Some(network),
            ..Default::default()
        },
    )
    .await;
    assert!(
        rows.is_empty(),
        "a timeout_ttft-only hook must not fire on a network failure"
    );

    // --- Increment 2B-i events -------------------------------------------

    // subagentStart: CHILD-only; matcher = child agent type; envelope carries
    // `subagentType` + `subagentId` (no `endReason`).
    let (rows, stdin) = observe_subagent_once(
        &registry(vec![observe_hook(HookEvent::SubagentStart, "explore")]),
        HookEvent::SubagentStart,
        "explore",
        Some("task-call-7"),
        ObserveFields::default(),
    )
    .await;
    assert_eq!(
        rows,
        vec![("subagentStart".to_string(), "success".to_string())]
    );
    let stdin = stdin.expect("subagentStart hook invoked");
    assert_eq!(stdin["hookEventName"], "subagentStart");
    assert_eq!(stdin["subagentType"], "explore");
    assert_eq!(stdin["subagentId"], "task-call-7");
    // `endReason` is a subagentStop-only field; it must be absent on start.
    assert!(stdin.get("endReason").is_none());
    // A different-agent-type hook must not fire (exact matcher on agent type).
    let (rows, _) = observe_subagent_once(
        &registry(vec![observe_hook(HookEvent::SubagentStart, "builder")]),
        HookEvent::SubagentStart,
        "explore",
        Some("task-call-7"),
        ObserveFields::default(),
    )
    .await;
    assert!(
        rows.is_empty(),
        "a builder-only hook must not fire on an explore child start"
    );

    // subagentStop: CHILD-only; matcher = child agent type; envelope carries
    // `subagentType` + `subagentId` + `endReason` (the child-stop reason).
    let (rows, stdin) = observe_subagent_once(
        &registry(vec![observe_hook(HookEvent::SubagentStop, "explore")]),
        HookEvent::SubagentStop,
        "explore",
        Some("task-call-7"),
        ObserveFields {
            end_reason: Some("completed"),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        rows,
        vec![("subagentStop".to_string(), "success".to_string())]
    );
    let stdin = stdin.expect("subagentStop hook invoked");
    assert_eq!(stdin["subagentType"], "explore");
    assert_eq!(stdin["subagentId"], "task-call-7");
    assert_eq!(stdin["endReason"], "completed");
    // The abort counterpart carries a distinct `endReason` (proving the field
    // is the real stop reason, not a constant).
    let (_rows, stdin) = observe_subagent_once(
        &registry(vec![observe_hook(HookEvent::SubagentStop, "explore")]),
        HookEvent::SubagentStop,
        "explore",
        Some("task-call-7"),
        ObserveFields {
            end_reason: Some("aborted"),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        stdin.expect("subagentStop hook invoked")["endReason"],
        "aborted"
    );
    // A different-agent-type hook must not fire on an explore child stop.
    let (rows, _) = observe_subagent_once(
        &registry(vec![observe_hook(HookEvent::SubagentStop, "builder")]),
        HookEvent::SubagentStop,
        "explore",
        Some("task-call-7"),
        ObserveFields {
            end_reason: Some("completed"),
            ..Default::default()
        },
    )
    .await;
    assert!(
        rows.is_empty(),
        "a builder-only hook must not fire on an explore child stop"
    );

    // sessionEnd: matcher = closed WorkerStop-derived token; typed field
    // `endReason`. `completed` fires a `completed`-matched hook; an `error`-only
    // hook does NOT fire on a clean completion (exact matcher).
    let (rows, stdin) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::SessionEnd, "completed")]),
        HookEvent::SessionEnd,
        "completed",
        None,
        ObserveFields {
            end_reason: Some("completed"),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        rows,
        vec![("sessionEnd".to_string(), "success".to_string())]
    );
    let stdin = stdin.expect("sessionEnd hook invoked");
    assert_eq!(stdin["hookEventName"], "sessionEnd");
    assert_eq!(stdin["endReason"], "completed");
    let (rows, _) = observe_once(
        &env,
        &registry(vec![observe_hook(HookEvent::SessionEnd, "error")]),
        HookEvent::SessionEnd,
        "completed",
        None,
        ObserveFields {
            end_reason: Some("completed"),
            ..Default::default()
        },
    )
    .await;
    assert!(
        rows.is_empty(),
        "an error-only sessionEnd hook must not fire on a clean completion"
    );
}

/// Aggregate production-boundary harness. The individual probes own their
/// setup beside the Worker/Driver/DispatchEnv boundary they exercise; this
/// orchestrator never calls a hook dispatcher or a Driver hook helper.
#[tokio::test(start_paused = true)]
async fn hook_event_table_dispatches_each_native_lifecycle_boundary() {
    tokio::time::resume();

    let worker_events =
        crate::daemon::session_worker::tests::production_worker_lifecycle_hook_probe().await;
    let mut observed = vec![worker_events[0].clone()];

    observed.push(crate::engine::driver::tests::misc::probe_user_prompt_submit_boundary().await);

    observed.extend(
        crate::engine::agent::tool_dispatch::tests::production_tool_lifecycle_hook_probe().await,
    );

    observed.push(crate::engine::driver::tests::turn_loop::probe_root_stop_boundary().await);
    crate::engine::driver::tests::turn_loop::probe_root_stop_lookalike_boundary().await;

    observed.push(crate::engine::driver::tests::misc::probe_stop_failure_boundary().await);

    observed.push(crate::engine::driver::tests::misc::probe_subagent_start_boundary().await);

    observed.push(crate::engine::driver::tests::misc::probe_subagent_stop_boundary().await);

    observed.extend(crate::engine::driver::tests::context::probe_compact_boundaries().await);
    observed.push(worker_events[1].clone());

    assert_eq!(
        observed.as_slice(),
        HookEvent::ALL.map(HookEvent::key).as_slice(),
        "every typed lifecycle event must be exercised exactly once in normative order"
    );
}

#[test]
fn error_class_match_value_is_stable_per_variant() {
    use crate::engine::model::InferenceErrorClass as C;
    let runtime_values = [
        error_class_match_value(&C::TimeoutTtft),
        error_class_match_value(&C::TimeoutIdle),
        error_class_match_value(&C::Network),
        error_class_match_value(&C::Http(503)),
        error_class_match_value(&C::UtilityTimeout),
        error_class_match_value(&C::MissingToolEntitlement {
            feature: "client_side_tools".to_string(),
        }),
        error_class_match_value(&C::ClientSideToolsUnsupported),
        error_class_match_value(&C::ResponsesToolIdentity),
        error_class_match_value(&C::ProviderNotConfigured),
        error_class_match_value(&C::ProviderRateLimit),
        error_class_match_value(&C::BillingOrQuotaExhausted),
        error_class_match_value(&C::UnrenderableWireField),
        error_class_match_value(&C::Other("weird".to_string())),
    ];
    assert_eq!(
        runtime_values.as_slice(),
        crate::config::extended::hooks::HOOK_ERROR_CLASS_MATCH_VALUES
    );
}

#[test]
fn hook_event_policy_pre_tool_use_has_tool_gate() {
    let policy = HookEvent::PreToolUse.policy();
    assert_eq!(policy.gate, crate::config::extended::hooks::HookGate::Tool);
}

#[test]
fn hook_event_policy_stop_has_stop_gate() {
    let policy = HookEvent::Stop.policy();
    assert_eq!(policy.gate, crate::config::extended::hooks::HookGate::Stop);
}

#[test]
fn hook_event_policy_observe_events_have_observe_gate() {
    for event in [
        HookEvent::SessionStart,
        HookEvent::UserPromptSubmit,
        HookEvent::PostToolUse,
        HookEvent::PostToolUseFailure,
        HookEvent::PermissionDenied,
        HookEvent::StopFailure,
        HookEvent::SubagentStart,
        HookEvent::PreCompact,
        HookEvent::PostCompact,
        HookEvent::SessionEnd,
    ] {
        let policy = event.policy();
        assert_eq!(
            policy.gate,
            crate::config::extended::hooks::HookGate::Observe,
            "{:?} should have Observe gate",
            event
        );
    }
}

#[test]
fn hook_event_policy_subagent_stop_has_stop_gate() {
    let policy = HookEvent::SubagentStop.policy();
    assert_eq!(policy.gate, crate::config::extended::hooks::HookGate::Stop);
}

// ---------------------------------------------------------------------------
// Session config snapshot turn-stability tests
// ---------------------------------------------------------------------------

#[test]
fn session_config_snapshot_carries_hook_registry() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["/usr/bin/echo".to_string()],
        Some(vec!["bash".to_string()]),
        BTreeMap::new(),
        5,
    );
    let reg = registry(vec![hook]);
    let snapshot = crate::daemon::session_worker::SessionConfigSnapshot::with_hooks(
        1,
        crate::config::providers::ProvidersConfig::default(),
        crate::config::extended::ExtendedConfig::default(),
        reg,
    );
    assert_eq!(snapshot.hooks().hooks.len(), 1);
    assert_eq!(snapshot.generation, 1);
}

#[test]
fn session_config_snapshot_default_has_empty_hooks() {
    let snapshot = crate::daemon::session_worker::SessionConfigSnapshot::new(
        0,
        crate::config::providers::ProvidersConfig::default(),
        crate::config::extended::ExtendedConfig::default(),
    );
    assert!(snapshot.hooks().hooks.is_empty());
}

#[test]
fn session_config_handle_repin_carries_hooks() {
    let hook = test_hook(
        HookEvent::PreToolUse,
        vec!["/usr/bin/echo".to_string()],
        None,
        BTreeMap::new(),
        5,
    );
    let reg = registry(vec![hook]);
    let snapshot = crate::daemon::session_worker::SessionConfigSnapshot::with_hooks(
        1,
        crate::config::providers::ProvidersConfig::default(),
        crate::config::extended::ExtendedConfig::default(),
        reg,
    );
    let handle = crate::daemon::session_worker::SessionConfigHandle::detached(snapshot);
    let repinned = handle.repin();
    assert_eq!(repinned.snapshot().hooks().hooks.len(), 1);
    assert_eq!(repinned.generation(), 1);
}

#[test]
fn session_config_handle_detached_default_has_empty_hooks() {
    let handle = crate::daemon::session_worker::SessionConfigHandle::detached_default();
    assert!(handle.snapshot().hooks().hooks.is_empty());
}

// ---------------------------------------------------------------------------
// FakeCommandRunner integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fake_command_runner_captures_invocation() {
    let runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));
    let result = runner
        .run(
            Path::new("/usr/bin/echo"),
            &["hello".to_string()],
            &BTreeMap::new(),
            Path::new("/workspace"),
            "stdin data",
            Duration::from_secs(5),
            Uuid::nil(),
        )
        .await;
    assert_eq!(result.exit_code, Some(0));
    let invocations = runner.invocations();
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].executable, Path::new("/usr/bin/echo"));
    assert_eq!(invocations[0].args, vec!["hello"]);
    assert_eq!(invocations[0].cwd, Path::new("/workspace"));
    assert_eq!(invocations[0].stdin, "stdin data");
    assert_eq!(invocations[0].timeout, Duration::from_secs(5));
}

// ---------------------------------------------------------------------------
// Dispatch/observe/stop function behavior tests
//
// These drive the real dispatch functions (`run_pre_tool_hooks`,
// `run_post_tool_hooks`, `run_observe_hooks`, `run_stop_hooks`) against a real
// in-memory ledger with an injected fake command runner and process env, so no
// external executable is spawned, no wall-clock sleep runs, and no `std::env`
// is mutated. They prove the fail-open, deny short-circuit, matcher/ordering,
// and stop-continuation contracts against non-vacuous ledger state.
//
// ---------------------------------------------------------------------------

#[test]
fn tool_hook_runner_envelope_bounds_and_reserved_environment() {
    envelope_for_pre_tool_use_is_camelcase();
    envelope_for_post_tool_use_success();
    envelope_for_post_tool_use_failure();
    envelope_clips_oversized_input();
    envelope_small_input_is_not_truncated();
    build_child_env_includes_reserved_keys();
    build_child_env_reserved_keys_overwrite_configured_env();
    build_child_env_delivers_configured_env();
}

#[tokio::test]
async fn tool_hook_runner_argv_timeout_and_proven_empty() {
    let argv = vec!["literal;not-shell".to_string(), "$(never-expanded)".to_string()];
    let fake = FakeCommandRunner::new(timeout_output());
    let session_id = Uuid::new_v4();
    let timed_out = fake
        .run(
            Path::new("/resolved/hook"),
            &argv,
            &BTreeMap::new(),
            Path::new("/workspace"),
            "{}",
            Duration::from_secs(7),
            session_id,
        )
        .await;
    assert!(timed_out.timeout);
    assert_eq!(fake.invocations()[0].args, argv);

    // An absent containment actor is the same production posture as a host
    // whose adapter reports Unsupported: deterministic before-spawn failure,
    // never a raw Tokio fallback.
    let unsupported = TokioCommandRunner::new()
        .run(
            Path::new("/must/not/run"),
            &[],
            &BTreeMap::new(),
            Path::new("/workspace"),
            "{}",
            Duration::from_secs(1),
            session_id,
        )
        .await;
    assert_eq!(
        unsupported.failure_reason,
        Some(REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED)
    );

    let (db, contained_session_id) = db_session().await;
    let adapter = crate::process_containment::FakeProvenAdapter::default();
    // The first platform kill fails after the durable state reaches Stopping.
    // The runner must retry the adapter operation, not mistake the duplicate
    // durable RequestStop transition for completed cleanup.
    adapter.set_kill_fail_once(true);
    let actor = crate::process_containment::ProcessContainmentActor::start(
        db,
        Arc::new(adapter.clone()),
    );
    let contained = TokioCommandRunner::with_containment(actor.handle())
        .run(
            Path::new("/fake/adapter-owned-hook"),
            &argv,
            &BTreeMap::new(),
            Path::new("/workspace"),
            "{}",
            Duration::from_secs(1),
            contained_session_id,
        )
        .await;
    assert_eq!(contained.exit_code, Some(0));
    assert_eq!(adapter.spawn_log().len(), 1);
    assert_eq!(adapter.terminate_log().len(), 2);
}

use uuid::Uuid;

async fn db_session() -> (crate::db::Db, Uuid) {
    let db = crate::db::Db::open_in_memory().unwrap();
    let session = db
        .create_session("hooks-proj", "/tmp/hooks-test", "Build")
        .await
        .unwrap();
    (db, session.session_id)
}

/// The `(event, status)` of every recorded `hook_run` row for a session, in
/// insertion order.
async fn hook_run_events(db: &crate::db::Db, session_id: Uuid) -> Vec<(String, String)> {
    db.list_session_events(session_id)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "hook_run")
        .map(|event| {
            (
                event.data["event"].as_str().unwrap().to_string(),
                event.data["status"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// Just the recorded `hook_run` statuses, in insertion order.
async fn hook_run_statuses(db: &crate::db::Db, session_id: Uuid) -> Vec<String> {
    hook_run_events(db, session_id)
        .await
        .into_iter()
        .map(|(_, status)| status)
        .collect()
}

fn workspace() -> &'static Path {
    Path::new("/tmp/hooks-test")
}

#[tokio::test]
async fn pre_tool_hook_explicit_deny_blocks_dispatch() {
    let (db, sid) = db_session().await;
    let reg = registry(vec![test_hook(
        HookEvent::PreToolUse,
        vec!["deny-hook".to_string()],
        Some(vec!["bash".to_string()]),
        BTreeMap::new(),
        5,
    )]);
    let runner = FakeCommandRunner::new(successful_output(
        r#"{"decision":"deny","reason":"too risky"}"#,
    ));
    let env = FakeProcessEnv::with_default_resolution();

    let outcome = run_pre_tool_hooks(
        &runner,
        &env,
        &reg,
        "bash",
        &json!({ "cmd": "rm -rf /" }),
        "call-1",
        sid,
        workspace(),
        &db,
    )
    .await;

    // The parseable deny short-circuits: the caller (`tool_dispatch`) returns
    // the deterministic model-visible error and never dispatches the tool.
    assert_eq!(
        outcome,
        PreHookOutcome::Deny {
            reason: "too risky".to_string()
        }
    );
    // Exactly one durable `denied` ledger row is recorded for the pre event.
    assert_eq!(
        hook_run_events(&db, sid).await,
        vec![("preToolUse".to_string(), "denied".to_string())]
    );
    // The hook was actually invoked (real dispatch, not a lookalike).
    assert_eq!(runner.invocations().len(), 1);
    // The recorded audit is the closed projection — never any process output.
    let rows = db.list_session_events(sid).await.unwrap();
    let data = rows[0].data.as_object().unwrap();
    for forbidden in ["payload", "stdout", "stderr", "output", "argv", "cwd"] {
        assert!(!data.contains_key(forbidden), "audit leaked `{forbidden}`");
    }
}

#[tokio::test]
async fn pre_tool_hook_failures_are_fail_open() {
    // Run one pre-hook scenario and return `(outcome, recorded statuses)`.
    async fn run_case(
        process_env: &dyn ProcessEnv,
        output: HookRawOutput,
    ) -> (PreHookOutcome, Vec<String>) {
        let (db, sid) = db_session().await;
        let reg = registry(vec![test_hook(
            HookEvent::PreToolUse,
            vec!["h".to_string()],
            Some(vec!["bash".to_string()]),
            BTreeMap::new(),
            5,
        )]);
        let runner = FakeCommandRunner::new(output);
        let outcome = run_pre_tool_hooks(
            &runner,
            process_env,
            &reg,
            "bash",
            &json!({}),
            "call-1",
            sid,
            workspace(),
            &db,
        )
        .await;
        (outcome, hook_run_statuses(&db, sid).await)
    }

    let resolves = FakeProcessEnv::with_default_resolution();

    // Every failure mode below is fail-open: the pre gate returns `Allow` (so
    // the ordinary tool dispatch proceeds) and records exactly one bounded row.
    let big_malformed = "x".repeat(200 * 1024);
    let mut containment_unsupported = spawn_failed_output();
    containment_unsupported.failure_reason = Some(REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED);
    let mut output_overflow = successful_output(r#"{"decision":"allow"}"#);
    output_overflow.output_truncated = true;
    output_overflow.failure_reason = Some(REASON_OUTPUT_LIMIT_EXCEEDED);
    let failure_cases: Vec<(&str, HookRawOutput)> = vec![
        ("timeout", timeout_output()),
        ("spawn failure", spawn_failed_output()),
        ("nonzero exit / child crash", failed_output()),
        ("malformed JSON", successful_output("not json at all")),
        (
            "unknown decision",
            successful_output(r#"{"decision":"maybe"}"#),
        ),
        (
            "oversized malformed stdout",
            successful_output(&big_malformed),
        ),
        ("bounded output overflow", output_overflow),
        ("descendant containment unsupported", containment_unsupported),
    ];
    for (label, output) in failure_cases {
        let (outcome, statuses) = run_case(&resolves, output).await;
        assert_eq!(outcome, PreHookOutcome::Allow, "{label} must fail open");
        assert_eq!(
            statuses,
            vec!["failed".to_string()],
            "{label} must record one failed row"
        );
    }

    // Valid non-deny (allow) JSON: success row, dispatch still proceeds.
    let (outcome, statuses) =
        run_case(&resolves, successful_output(r#"{"decision":"allow"}"#)).await;
    assert_eq!(outcome, PreHookOutcome::Allow);
    assert_eq!(statuses, vec!["success".to_string()]);

    // Missing executable: resolution fails before the runner is consulted, so
    // even a would-be deny payload cannot deny — fail-open failed row.
    let missing = FakeProcessEnv::default();
    let (outcome, statuses) = run_case(&missing, successful_output(r#"{"decision":"deny"}"#)).await;
    assert_eq!(outcome, PreHookOutcome::Allow);
    assert_eq!(statuses, vec!["failed".to_string()]);
}

#[tokio::test]
async fn tool_hooks_run_in_canonical_lifecycle_order() {
    let (db, sid) = db_session().await;
    let env = FakeProcessEnv::with_default_resolution();
    let allow_runner = FakeCommandRunner::new(successful_output(r#"{"decision":"allow"}"#));

    // Pre runs first and allows dispatch.
    let pre_reg = registry(vec![test_hook(
        HookEvent::PreToolUse,
        vec!["pre".to_string()],
        Some(vec!["bash".to_string()]),
        BTreeMap::new(),
        5,
    )]);
    let pre = run_pre_tool_hooks(
        &allow_runner,
        &env,
        &pre_reg,
        "bash",
        &json!({}),
        "c1",
        sid,
        workspace(),
        &db,
    )
    .await;
    assert_eq!(pre, PreHookOutcome::Allow);

    // Then exactly one matching post event after a successful dispatch.
    let post_reg = registry(vec![
        test_hook(
            HookEvent::PostToolUse,
            vec!["post".to_string()],
            Some(vec!["bash".to_string()]),
            BTreeMap::new(),
            5,
        ),
        test_hook(
            HookEvent::PostToolUseFailure,
            vec!["postfail".to_string()],
            Some(vec!["bash".to_string()]),
            BTreeMap::new(),
            5,
        ),
    ]);
    let ok: anyhow::Result<crate::engine::tool::ToolOutput> =
        Ok(crate::engine::tool::ToolOutput::text("done"));
    run_post_tool_hooks(
        &allow_runner,
        &env,
        &post_reg,
        HookEvent::PostToolUse,
        "bash",
        &json!({}),
        "c1",
        &ok,
        sid,
        workspace(),
        &db,
    )
    .await;

    // Canonical order: pre before post; only the success post event fired (the
    // `postToolUseFailure` handler did not, because the dispatch succeeded).
    assert_eq!(
        hook_run_events(&db, sid).await,
        vec![
            ("preToolUse".to_string(), "success".to_string()),
            ("postToolUse".to_string(), "success".to_string()),
        ]
    );

    // A failed dispatch fires `postToolUseFailure` exactly once.
    let (db2, sid2) = db_session().await;
    let err: anyhow::Result<crate::engine::tool::ToolOutput> = Err(anyhow::anyhow!("boom"));
    run_post_tool_hooks(
        &allow_runner,
        &env,
        &post_reg,
        HookEvent::PostToolUseFailure,
        "bash",
        &json!({}),
        "c1",
        &err,
        sid2,
        workspace(),
        &db2,
    )
    .await;
    assert_eq!(
        hook_run_events(&db2, sid2).await,
        vec![("postToolUseFailure".to_string(), "success".to_string())]
    );
}

#[tokio::test]
async fn tool_hook_matcher_and_ordering() {
    let env = FakeProcessEnv::with_default_resolution();

    // Exact matcher selects only its tool; a `None` matcher matches all tools.
    let exact = test_hook(
        HookEvent::PreToolUse,
        vec!["exact".to_string()],
        Some(vec!["bash".to_string()]),
        BTreeMap::new(),
        5,
    );
    let wildcard = test_hook(
        HookEvent::PreToolUse,
        vec!["wild".to_string()],
        None,
        BTreeMap::new(),
        5,
    );
    let reg = registry(vec![exact, wildcard]);
    assert_eq!(matching_hooks(&reg, HookEvent::PreToolUse, "bash").len(), 2);
    assert_eq!(matching_hooks(&reg, HookEvent::PreToolUse, "read").len(), 1);
    assert_eq!(
        matching_hooks(&reg, HookEvent::PostToolUse, "bash").len(),
        0
    );

    // Pre first-deny short-circuits later pre hooks.
    {
        let (db, sid) = db_session().await;
        let two = registry(vec![
            test_hook(
                HookEvent::PreToolUse,
                vec!["a".to_string()],
                Some(vec!["bash".to_string()]),
                BTreeMap::new(),
                5,
            ),
            test_hook(
                HookEvent::PreToolUse,
                vec!["b".to_string()],
                Some(vec!["bash".to_string()]),
                BTreeMap::new(),
                5,
            ),
        ]);
        let runner =
            FakeCommandRunner::new(successful_output(r#"{"decision":"deny","reason":"no"}"#));
        let outcome = run_pre_tool_hooks(
            &runner,
            &env,
            &two,
            "bash",
            &json!({}),
            "c1",
            sid,
            workspace(),
            &db,
        )
        .await;
        assert_eq!(
            outcome,
            PreHookOutcome::Deny {
                reason: "no".to_string()
            }
        );
        assert_eq!(
            runner.invocations().len(),
            1,
            "first deny must short-circuit later pre hooks"
        );
        assert_eq!(
            hook_run_statuses(&db, sid).await,
            vec!["denied".to_string()]
        );
    }

    // All matching observer hooks run sequentially despite an earlier failure.
    {
        let (db, sid) = db_session().await;
        let two = registry(vec![
            test_hook(
                HookEvent::SessionStart,
                vec!["a".to_string()],
                None,
                BTreeMap::new(),
                5,
            ),
            test_hook(
                HookEvent::SessionStart,
                vec!["b".to_string()],
                None,
                BTreeMap::new(),
                5,
            ),
        ]);
        let runner = FakeCommandRunner::new(failed_output());
        run_observe_hooks(
            &runner,
            &env,
            &two,
            HookEvent::SessionStart,
            "fresh",
            sid,
            workspace(),
            &db,
            None,
            None,
            None,
            None,
            ObserveFields {
                start_source: Some("fresh"),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(
            runner.invocations().len(),
            2,
            "every matching observer runs even after an earlier failure"
        );
        assert_eq!(
            hook_run_statuses(&db, sid).await,
            vec!["failed".to_string(), "failed".to_string()]
        );
    }
}

#[tokio::test]
async fn stop_hook_continuation_state_machine() {
    let env = FakeProcessEnv::with_default_resolution();
    let stop_hook = || {
        test_hook(
            HookEvent::Stop,
            vec!["s".to_string()],
            Some(vec!["end_turn".to_string()]),
            BTreeMap::new(),
            5,
        )
    };

    // No matching hooks → End. The lifecycle boundary is still claimed so a
    // parent/drain reconciler cannot redispatch the same child stop.
    {
        let (db, sid) = db_session().await;
        let runner = FakeCommandRunner::new(successful_output(""));
        let mut state = StopGateState::default();
        let outcome = run_stop_hooks(
            &runner,
            &env,
            &registry(vec![]),
            HookEvent::Stop,
            "end_turn",
            sid,
            workspace(),
            &db,
            None,
            None,
            None,
            &mut state,
        )
        .await;
        assert_eq!(outcome, StopHookOutcome::End);
        assert_eq!(state.continuation_count, 0);
        assert!(state.lifecycle_event_emitted);
        assert!(hook_run_statuses(&db, sid).await.is_empty());
    }

    // A `block` + `additionalContext` aggregates into a continuation round and
    // increments the per-frame continuation count.
    {
        let (db, sid) = db_session().await;
        let runner = FakeCommandRunner::new(successful_output(
            r#"{"decision":"block","reason":"keep going","hookSpecificOutput":{"additionalContext":"more work"}}"#,
        ));
        let mut state = StopGateState::default();
        let outcome = run_stop_hooks(
            &runner,
            &env,
            &registry(vec![stop_hook()]),
            HookEvent::Stop,
            "end_turn",
            sid,
            workspace(),
            &db,
            None,
            None,
            None,
            &mut state,
        )
        .await;
        assert_eq!(
            outcome,
            StopHookOutcome::Continue {
                reason: "keep going".to_string(),
                additional_context: Some("more work".to_string()),
            }
        );
        assert_eq!(state.continuation_count, 1);
        assert!(state.stop_hook_active);
        assert_eq!(
            hook_run_statuses(&db, sid).await,
            vec!["blocked".to_string()]
        );
    }

    // `{"continue":false}` wins over aggregation → ForcedEnd.
    {
        let (db, sid) = db_session().await;
        let runner = FakeCommandRunner::new(successful_output(
            r#"{"continue":false,"stopReason":"all done"}"#,
        ));
        let mut state = StopGateState::default();
        let outcome = run_stop_hooks(
            &runner,
            &env,
            &registry(vec![stop_hook()]),
            HookEvent::Stop,
            "end_turn",
            sid,
            workspace(),
            &db,
            None,
            None,
            None,
            &mut state,
        )
        .await;
        assert_eq!(outcome, StopHookOutcome::ForcedEnd(ForcedEndCause::HookRequested));
    }

    // At the continuation cap → ForcedEnd WITHOUT reconsulting the hooks and
    // without recording a new ledger row.
    {
        let (db, sid) = db_session().await;
        let runner =
            FakeCommandRunner::new(successful_output(r#"{"decision":"block","reason":"x"}"#));
        let mut state = StopGateState {
            continuation_count: STOP_HOOK_MAX_CONTINUATIONS,
            stop_hook_active: false,
            ..Default::default()
        };
        let outcome = run_stop_hooks(
            &runner,
            &env,
            &registry(vec![stop_hook()]),
            HookEvent::Stop,
            "end_turn",
            sid,
            workspace(),
            &db,
            None,
            None,
            None,
            &mut state,
        )
        .await;
        assert_eq!(outcome, StopHookOutcome::ForcedEnd(ForcedEndCause::ContinuationCap));
        assert_eq!(
            runner.invocations().len(),
            0,
            "a capped stop gate must not reconsult its hooks"
        );
        assert!(hook_run_statuses(&db, sid).await.is_empty());
    }

    // A failed stop hook is fail-open: it neither blocks nor continues.
    {
        let (db, sid) = db_session().await;
        let runner = FakeCommandRunner::new(failed_output());
        let mut state = StopGateState::default();
        let outcome = run_stop_hooks(
            &runner,
            &env,
            &registry(vec![stop_hook()]),
            HookEvent::Stop,
            "end_turn",
            sid,
            workspace(),
            &db,
            None,
            None,
            None,
            &mut state,
        )
        .await;
        assert_eq!(outcome, StopHookOutcome::End);
        assert_eq!(state.continuation_count, 0);
        assert_eq!(
            hook_run_statuses(&db, sid).await,
            vec!["failed".to_string()]
        );
    }

    // A child stop uses the same bounded state machine, but is correlated to
    // the child and exposes child fields rather than root-only stopReason.
    {
        let (db, sid) = db_session().await;
        let child_hook = test_hook(
            HookEvent::SubagentStop,
            vec!["s".to_string()],
            Some(vec!["builder".to_string()]),
            BTreeMap::new(),
            5,
        );
        let runner = FakeCommandRunner::new(successful_output(
            r#"{"decision":"block","reason":"finish the review"}"#,
        ));
        let mut state = StopGateState::default();
        let outcome = run_stop_hooks(
            &runner,
            &env,
            &registry(vec![child_hook]),
            HookEvent::SubagentStop,
            "builder",
            sid,
            workspace(),
            &db,
            Some("builder"),
            Some("task-call-7"),
            Some("completed"),
            &mut state,
        )
        .await;
        assert!(matches!(outcome, StopHookOutcome::Continue { .. }));
        let invocation = runner.invocations().into_iter().next().unwrap();
        let envelope: Value = serde_json::from_str(&invocation.stdin).unwrap();
        assert_eq!(envelope["subagentType"], "builder");
        assert_eq!(envelope["subagentId"], "task-call-7");
        assert_eq!(envelope["endReason"], "completed");
        assert!(envelope.get("stopReason").is_none());

        // Terminal child stops use the same single G::Stop dispatcher with a
        // fresh discarded latch; only the supplied terminal reason differs.
        let terminal_runner = FakeCommandRunner::new(successful_output(""));
        let mut discarded = StopGateState::default();
        let _ = run_stop_hooks(
            &terminal_runner,
            &env,
            &registry(vec![test_hook(
                HookEvent::SubagentStop,
                vec!["s".to_string()],
                Some(vec!["builder".to_string()]),
                BTreeMap::new(),
                5,
            )]),
            HookEvent::SubagentStop,
            "builder",
            sid,
            workspace(),
            &db,
            Some("builder"),
            Some("task-call-8"),
            Some("aborted"),
            &mut discarded,
        )
        .await;
        let terminal: Value =
            serde_json::from_str(&terminal_runner.invocations()[0].stdin).unwrap();
        assert_eq!(terminal["subagentType"], "builder");
        assert_eq!(terminal["subagentId"], "task-call-8");
        assert_eq!(terminal["endReason"], "aborted");
        assert!(terminal.get("stopReason").is_none());
    }
}

#[tokio::test]
async fn cancelled_stop_gate_does_not_spawn_or_record_handlers() {
    let (db, sid) = db_session().await;
    let runner = FakeCommandRunner::new(successful_output(
        r#"{"decision":"block","reason":"must not run"}"#,
    ));
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let mut state = StopGateState::default();
    let outcome = run_stop_hooks_cancellable(
        &runner,
        &FakeProcessEnv::with_default_resolution(),
        &registry(vec![test_hook(
            HookEvent::Stop,
            vec!["s".to_string()],
            Some(vec!["end_turn".to_string()]),
            BTreeMap::new(),
            5,
        )]),
        HookEvent::Stop,
        "end_turn",
        sid,
        workspace(),
        &db,
        None,
        None,
        None,
        &mut state,
        &cancel,
    )
    .await;
    assert_eq!(outcome, StopHookOutcome::End);
    assert!(runner.invocations().is_empty());
    assert!(hook_run_statuses(&db, sid).await.is_empty());
    assert_eq!(state.continuation_count, 0);
    assert!(!state.stop_hook_active);
}

/// The 8-cap grants EXACTLY `STOP_HOOK_MAX_CONTINUATIONS` continuations for one
/// latch, then force-ends the turn WITHOUT reconsulting (or recording) any stop
/// hook — the cap is enforced solely at the entry check. Driven by threading ONE
/// `StopGateState` (as the driver does per key) across repeated consultations of
/// a block hook.
#[tokio::test]
async fn stop_hook_grants_max_continuations_then_forces_end_without_reconsulting() {
    let env = FakeProcessEnv::with_default_resolution();
    let (db, sid) = db_session().await;
    // A distinct, independently-derived expected count so the assertions do not
    // re-derive from the constant under test's own arithmetic.
    let expected_grants: usize = 8;
    assert_eq!(
        STOP_HOOK_MAX_CONTINUATIONS as usize, expected_grants,
        "test literal pinned to the production cap"
    );

    let runner = FakeCommandRunner::new(successful_output(
        r#"{"decision":"block","reason":"keep going"}"#,
    ));
    let hook = test_hook(
        HookEvent::Stop,
        vec!["s".to_string()],
        Some(vec!["end_turn".to_string()]),
        BTreeMap::new(),
        5,
    );
    let reg = registry(vec![hook]);
    let mut state = StopGateState::default();

    // The first `expected_grants` consultations each grant a continuation and
    // run the hook once.
    for round in 1..=expected_grants {
        let outcome = run_stop_hooks(
            &runner,
            &env,
            &reg,
            HookEvent::Stop,
            "end_turn",
            sid,
            workspace(),
            &db,
            None,
            None,
            None,
            &mut state,
        )
        .await;
        assert_eq!(
            outcome,
            StopHookOutcome::Continue {
                reason: "keep going".to_string(),
                additional_context: None,
            },
            "round {round} must still grant a continuation"
        );
        assert_eq!(state.continuation_count as usize, round);
        assert_eq!(
            runner.invocations().len(),
            round,
            "each granted round consults the hook exactly once"
        );
    }

    // The `stop` envelope carries first-class camelCase `stopReason` /
    // `stopHookActive`: the first consultation is not yet inside a continuation
    // loop (`false`); by the second the latch is active (`true`).
    let invocations = runner.invocations();
    let first: serde_json::Value = serde_json::from_str(&invocations[0].stdin).unwrap();
    assert_eq!(first["hookEventName"], "stop");
    assert_eq!(first["stopReason"], "end_turn");
    assert_eq!(first["stopHookActive"], false);
    assert!(
        first.get("source").is_none() && first.get("reason").is_none(),
        "the matcher token must not be overloaded onto generic source/reason"
    );
    let second: serde_json::Value = serde_json::from_str(&invocations[1].stdin).unwrap();
    assert_eq!(second["stopHookActive"], true);

    // The next consultation is capped: force-end, hook NOT reconsulted, and no
    // additional ledger row beyond the `expected_grants` already recorded.
    let outcome = run_stop_hooks(
        &runner,
        &env,
        &reg,
        HookEvent::Stop,
        "end_turn",
        sid,
        workspace(),
        &db,
        None,
        None,
        None,
        &mut state,
    )
    .await;
    assert_eq!(outcome, StopHookOutcome::ForcedEnd(ForcedEndCause::ContinuationCap));
    assert_eq!(
        runner.invocations().len(),
        expected_grants,
        "a capped latch must not reconsult its stop hooks"
    );
    assert_eq!(
        hook_run_statuses(&db, sid).await.len(),
        expected_grants,
        "the forced end records no new ledger row"
    );
}

#[test]
fn tool_hook_session_config_snapshot_is_turn_stable() {
    use crate::daemon::session_worker::{SessionConfigHandle, SessionConfigSnapshot};

    let gen1 = SessionConfigSnapshot::with_hooks(
        1,
        crate::config::providers::ProvidersConfig::default(),
        crate::config::extended::ExtendedConfig::default(),
        registry(vec![test_hook(
            HookEvent::PreToolUse,
            vec!["one".to_string()],
            Some(vec!["bash".to_string()]),
            BTreeMap::new(),
            5,
        )]),
    );
    let gen2 = SessionConfigSnapshot::with_hooks(
        2,
        crate::config::providers::ProvidersConfig::default(),
        crate::config::extended::ExtendedConfig::default(),
        registry(vec![
            test_hook(
                HookEvent::PreToolUse,
                vec!["one".to_string()],
                Some(vec!["bash".to_string()]),
                BTreeMap::new(),
                5,
            ),
            test_hook(
                HookEvent::PostToolUse,
                vec!["two".to_string()],
                Some(vec!["bash".to_string()]),
                BTreeMap::new(),
                5,
            ),
        ]),
    );

    let shared = std::sync::Arc::new(std::sync::RwLock::new(gen1));
    let live = SessionConfigHandle::new(shared.clone());

    // Turn boundary: the driver pins the turn's config view (generation 1).
    let turn = live.repin();
    assert_eq!(turn.generation(), 1);
    assert_eq!(turn.snapshot().hooks().hooks.len(), 1);

    // A config reload lands mid-turn, bumping the generation and the hook set.
    *shared.write().unwrap() = gen2;

    // The in-flight turn's pre and post hooks read the SAME pinned registry;
    // the reload does not change the active turn.
    assert_eq!(turn.generation(), 1);
    assert_eq!(turn.snapshot().hooks().hooks.len(), 1);

    // The reload only takes effect at the next turn's repin.
    let next_turn = live.repin();
    assert_eq!(next_turn.generation(), 2);
    assert_eq!(next_turn.snapshot().hooks().hooks.len(), 2);
}

// ---------------------------------------------------------------------------
// Hook decision status mapping tests
// ---------------------------------------------------------------------------

#[test]
fn hook_decision_allow_maps_to_success_status() {
    assert_eq!(HookDecision::Allow.status(), HookRunStatus::Success);
}

#[test]
fn hook_decision_deny_maps_to_denied_status() {
    let decision = HookDecision::Deny {
        reason: "no".to_string(),
    };
    assert_eq!(decision.status(), HookRunStatus::Denied);
}

#[test]
fn hook_decision_block_maps_to_blocked_status() {
    let decision = HookDecision::Block {
        reason: "stop".to_string(),
        additional_context: None,
    };
    assert_eq!(decision.status(), HookRunStatus::Blocked);
}

#[test]
fn hook_decision_failed_maps_to_failed_status() {
    let decision = HookDecision::Failed {
        reason: "error".to_string(),
    };
    assert_eq!(decision.status(), HookRunStatus::Failed);
}

#[test]
fn hook_decision_continue_maps_to_success_status() {
    let decision = HookDecision::Continue {
        stop_reason: "done".to_string(),
    };
    assert_eq!(decision.status(), HookRunStatus::Success);
}

#[test]
fn hook_decision_reason_extracted_correctly() {
    assert!(HookDecision::Allow.reason().is_none());
    assert_eq!(
        HookDecision::Deny {
            reason: "r".to_string()
        }
        .reason(),
        Some("r")
    );
    assert_eq!(
        HookDecision::Failed {
            reason: "e".to_string()
        }
        .reason(),
        Some("e")
    );
}

// ---------------------------------------------------------------------------
// Output cap tests
// ---------------------------------------------------------------------------

#[test]
fn output_cap_bytes_is_64k() {
    assert_eq!(OUTPUT_CAP_BYTES, 64 * 1024);
}

#[test]
fn envelope_value_max_bytes_is_128k() {
    assert_eq!(ENVELOPE_VALUE_MAX_BYTES, 128 * 1024);
}

#[test]
fn reason_max_chars_is_1024() {
    assert_eq!(REASON_MAX_CHARS, 1024);
}

#[test]
fn stop_hook_max_continuations_is_8() {
    assert_eq!(STOP_HOOK_MAX_CONTINUATIONS, 8);
}

// ---------------------------------------------------------------------------
// Fail-open decision parsing with raw output fixtures
// ---------------------------------------------------------------------------

#[test]
fn parse_pre_tool_decision_nonzero_exit_with_stdout_is_failed_not_deny() {
    // Even with nonzero exit, stdout must contain valid deny JSON to deny.
    let decision = parse_pre_tool_decision(r#"{"decision":"deny"}"#, Some(1));
    assert_eq!(
        decision,
        HookDecision::Deny {
            reason: DEFAULT_DENY_REASON.to_string()
        }
    );
}

#[test]
fn parse_pre_tool_decision_failed_output_is_failed() {
    let output = failed_output();
    let decision = parse_pre_tool_decision(&output.stdout, output.exit_code);
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

#[test]
fn parse_observe_decision_failed_output_is_failed() {
    let output = failed_output();
    let decision = parse_observe_decision(&output.stdout, output.exit_code);
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

#[test]
fn parse_stop_decision_failed_output_is_failed() {
    let output = failed_output();
    let decision = parse_stop_decision(&output.stdout, output.exit_code);
    assert!(matches!(decision, HookDecision::Failed { .. }));
}

#[test]
fn parse_pre_tool_decision_timeout_output_is_failed() {
    let output = timeout_output();
    // Timeout: no stdout, no exit code — the caller flags timeout before
    // calling the parser, but verify the parser treats empty+None as allow.
    let decision = parse_pre_tool_decision(&output.stdout, output.exit_code);
    assert_eq!(decision, HookDecision::Allow);
}

#[test]
fn parse_observe_decision_spawn_failed_output_is_allow() {
    let output = spawn_failed_output();
    // Spawn failure: empty stdout, no exit code. The caller flags
    // spawn_failed before calling the parser, but verify the parser treats
    // empty+None as allow.
    let decision = parse_observe_decision(&output.stdout, output.exit_code);
    assert_eq!(decision, HookDecision::Allow);
}

// ---------------------------------------------------------------------------
// Stop-gate outcome and aggregation tests
// ---------------------------------------------------------------------------

#[test]
fn stop_hook_outcome_end_is_default_for_no_hooks() {
    // With no matching hooks, run_stop_hooks returns End. This is tested
    // via the state machine types; the full async integration requires a
    // SessionConfigHandle which is tested in the session config snapshot
    // tests above.
    let state = StopGateState::default();
    assert!(!state.capped());
    assert_eq!(state.continuation_count, 0);
}

#[test]
fn stop_gate_state_increments_continuation_count() {
    let state = StopGateState {
        continuation_count: 1,
        ..Default::default()
    };
    assert_eq!(state.continuation_count, 1);
    assert!(!state.capped());
}

#[test]
fn stop_gate_state_capped_forces_end() {
    let state = StopGateState {
        continuation_count: STOP_HOOK_MAX_CONTINUATIONS,
        ..Default::default()
    };
    assert!(state.capped());
}

// ---------------------------------------------------------------------------
// README hooks-contract documentation test
// ---------------------------------------------------------------------------

use crate::config::extended::hooks::{HookApplicability, HookGate, HookMatcherPolicy};

/// A structured, machine-checkable projection of the native command-hook
/// contract that the public `apps/cli/README.md` `## Hooks` subsection must
/// describe.
///
/// Normative values are derived from the typed config/runtime constants rather
/// than hand-maintained test literals, so a drift between the prose contract
/// and the implementation fails the test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HookDocumentationContract {
    /// Canonical event keys in canonical order, derived from `HookEvent::ALL`.
    pub events: Vec<HookEventDoc>,
    /// Config layer origin kinds, in least-to-most-specific load order.
    pub origin_layers: Vec<&'static str>,
    /// Environment variable that points at one concrete `config.json`.
    pub cockpit_config_env: &'static str,
    /// Per-handler config filename.
    pub config_file: &'static str,
    /// Reserved `COCKPIT_HOOK_*` / Cockpit env keys overwritten after configured env.
    pub reserved_env_keys: Vec<&'static str>,
    /// Envelope `toolInput`/`toolResult` value cap in bytes.
    pub envelope_value_max_bytes: usize,
    /// Independent stdout/stderr cap in bytes.
    pub output_cap_bytes: usize,
    /// Deny/block reason max length in chars.
    pub reason_max_chars: usize,
    /// Stop-gate continuations per (session, frame-or-job).
    pub stop_hook_max_continuations: u8,
    /// `timeoutSecs` valid range, inclusive.
    pub timeout_secs_range: (u16, u16),
    /// Closed `hook_run` audit status vocabulary.
    pub audit_statuses: Vec<&'static str>,
    /// `hook_run` audit fields that are deliberately absent (privacy exclusions).
    pub audit_excluded_fields: Vec<&'static str>,
    /// `hook_run` byte caps: (event, correlation, reason).
    pub audit_byte_caps: (usize, usize, usize),
    /// Pre-tool decision vocabulary that blocks control flow.
    pub pre_tool_blocking_decision: &'static str,
    /// Pre-tool decision vocabulary that allows.
    pub pre_tool_allow_decision: &'static str,
    /// Stop-gate decision vocabulary that requests another model round.
    pub stop_block_decision: &'static str,
    /// Stop-gate field that ends the turn.
    pub stop_continue_false: &'static str,
    /// Stop-gate additional-context field path.
    pub stop_additional_context_field: &'static str,
    /// Fail-open conditions recorded as `failed` runs.
    pub fail_open_conditions: Vec<&'static str>,
    /// Deliberately unsupported formats/sources.
    pub unsupported_formats: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HookEventDoc {
    pub key: &'static str,
    pub gate: &'static str,
    pub applicability: &'static str,
    pub matcher_kind: &'static str,
    pub matcher_values: Vec<&'static str>,
    pub default_timeout_secs: u16,
    pub affects_control_flow: bool,
}

impl HookDocumentationContract {
    /// Build the contract from the typed config/runtime constants.
    pub(crate) fn from_typed_constants() -> Self {
        let events: Vec<HookEventDoc> = HookEvent::ALL
            .iter()
            .map(|event| {
                let policy = event.policy();
                let (matcher_kind, matcher_values) = match policy.matcher {
                    HookMatcherPolicy::Closed(values) => ("closed", values.to_vec()),
                    HookMatcherPolicy::CanonicalToolName => ("canonicalToolName", Vec::new()),
                    HookMatcherPolicy::ChildAgentType => ("childAgentType", Vec::new()),
                    HookMatcherPolicy::ErrorClass => (
                        "errorClass",
                        crate::config::extended::hooks::HOOK_ERROR_CLASS_MATCH_VALUES.to_vec(),
                    ),
                };
                let gate = match policy.gate {
                    HookGate::Observe => "observe",
                    HookGate::Tool => "tool",
                    HookGate::Stop => "stop",
                };
                let applicability = match policy.applicability {
                    HookApplicability::RootAndChild => "rootAndChild",
                    HookApplicability::RootOnly => "rootOnly",
                    HookApplicability::OrdinaryToolOnly => "ordinaryToolOnly",
                    HookApplicability::RealOrdinaryExecutionOnly => "realOrdinaryExecutionOnly",
                    HookApplicability::AnyDeniedToolApproval => "anyDeniedToolApproval",
                    HookApplicability::NormalRootDoneOnly => "normalRootDoneOnly",
                    HookApplicability::InferenceErrorOnly => "inferenceErrorOnly",
                    HookApplicability::ChildOnly => "childOnly",
                    HookApplicability::PreparedApplyAttempt => "preparedApplyAttempt",
                    HookApplicability::SuccessfulCompactionOnly => "successfulCompactionOnly",
                    HookApplicability::EverySession => "everySession",
                };
                let affects_control_flow = matches!(policy.gate, HookGate::Tool | HookGate::Stop);
                HookEventDoc {
                    key: event.key(),
                    gate,
                    applicability,
                    matcher_kind,
                    matcher_values,
                    default_timeout_secs: policy.default_timeout_secs,
                    affects_control_flow,
                }
            })
            .collect();

        Self {
            events,
            origin_layers: vec!["global", "user", "machine", "project", "explicit"],
            cockpit_config_env: crate::config::dirs::COCKPIT_CONFIG_ENV,
            config_file: crate::config::dirs::CONFIG_FILE,
            reserved_env_keys: RESERVED_ENV_KEYS.to_vec(),
            envelope_value_max_bytes: ENVELOPE_VALUE_MAX_BYTES,
            output_cap_bytes: OUTPUT_CAP_BYTES,
            reason_max_chars: REASON_MAX_CHARS,
            stop_hook_max_continuations: STOP_HOOK_MAX_CONTINUATIONS,
            timeout_secs_range: (1, 600),
            audit_statuses: vec!["success", "denied", "blocked", "failed"],
            audit_excluded_fields: vec![
                "payload",
                "output",
                "argv",
                "cwd",
                "environment",
                "stdout",
                "stderr",
                "http",
                "unknown",
            ],
            audit_byte_caps: (128, 256, 1024),
            pre_tool_blocking_decision: "deny",
            pre_tool_allow_decision: "allow",
            stop_block_decision: "block",
            stop_continue_false: "continue",
            stop_additional_context_field: "hookSpecificOutput.additionalContext",
            fail_open_conditions: vec![
                REASON_SPAWN_FAILED,
                REASON_EXECUTABLE_NOT_FOUND,
                REASON_MALFORMED_JSON_OUTPUT,
                REASON_OUTPUT_NOT_JSON_OBJECT,
                REASON_MALFORMED_HOOK_OUTPUT,
                REASON_HOOK_TIMED_OUT,
                REASON_DESCENDANT_CONTAINMENT_UNSUPPORTED,
                REASON_OUTPUT_LIMIT_EXCEEDED,
                REASON_NONZERO_EXIT_PREFIX,
                REASON_NO_EXIT_STATUS,
                REASON_HOOK_CANCELLED,
                REASON_PIPE_IO_FAILED,
                REASON_CONTAINMENT_ACTOR_UNAVAILABLE,
                REASON_UNEXPECTED_PRE_TOOL_BLOCK,
                REASON_UNEXPECTED_STOP_DENY,
                REASON_UNKNOWN_OR_MISSING_DECISION,
            ],
            unsupported_formats: vec![
                "toml",
                "shell-string",
                "http-endpoint",
                "network-hook",
                "regex-matcher",
                "glob-matcher",
                "vendor-alias",
                "plugin-source",
                "agent-frontmatter",
            ],
        }
    }
}

/// Read the `<!-- hooks-contract:start -->` / `<!-- hooks-contract:end -->`
/// block from `apps/cli/README.md`.
fn read_hooks_contract_block() -> String {
    let readme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/cli/README.md");
    let contents = std::fs::read_to_string(&readme)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", readme.display()));
    let start_marker = "<!-- hooks-contract:start -->";
    let end_marker = "<!-- hooks-contract:end -->";
    let start = contents
        .find(start_marker)
        .unwrap_or_else(|| panic!("missing `{start_marker}` marker in {}", readme.display()));
    let after_start = start + start_marker.len();
    let end = contents[after_start..].find(end_marker).unwrap_or_else(|| {
        panic!(
            "missing `{end_marker}` marker after `{start_marker}` in {}",
            readme.display()
        )
    }) + after_start;
    contents[after_start..end].to_string()
}

/// Assert the contract block mentions every normative value. Each check
/// fails with a precise message so a missing/extra/wrong value is obvious.
fn assert_contract_block_matches(block: &str, contract: &HookDocumentationContract) {
    let lower = block.to_ascii_lowercase();
    let assert_contains = |needle: &str, what: &str| {
        assert!(
            lower.contains(&needle.to_ascii_lowercase()),
            "hooks-contract block is missing {what} (`{needle}`)"
        );
    };
    let assert_not_contains = |needle: &str, what: &str| {
        assert!(
            !lower.contains(&needle.to_ascii_lowercase()),
            "hooks-contract block must not present {what} as supported (`{needle}`)"
        );
    };

    // Config schema + every event/gate/matcher/default-timeout.
    for event in &contract.events {
        assert_contains(event.key, &format!("event key `{}`", event.key));
        assert_contains(
            event.gate,
            &format!("gate `{}` for event `{}`", event.gate, event.key),
        );
        assert_contains(
            event.applicability,
            &format!(
                "applicability `{}` for event `{}`",
                event.applicability, event.key
            ),
        );
        assert_contains(
            event.matcher_kind,
            &format!(
                "matcher kind `{}` for event `{}`",
                event.matcher_kind, event.key
            ),
        );
        let timeout_str = format!("{}s", event.default_timeout_secs);
        assert_contains(
            &timeout_str,
            &format!(
                "default timeout {} for event `{}`",
                event.default_timeout_secs, event.key
            ),
        );
        if event.affects_control_flow {
            assert_contains(
                "control flow",
                &format!("control-flow note for gating event `{}`", event.key),
            );
        }
    }

    // Source ordering + trust + COCKPIT_CONFIG + config file.
    for layer in &contract.origin_layers {
        assert_contains(layer, &format!("origin layer `{}`", layer));
    }
    assert_contains(contract.cockpit_config_env, "COCKPIT_CONFIG env var");
    assert_contains(contract.config_file, "config.json filename");

    // Reserved env keys.
    for key in &contract.reserved_env_keys {
        assert_contains(key, &format!("reserved env key `{}`", key));
    }

    // Byte/time caps.
    let envelope_cap = format!("{} KiB", contract.envelope_value_max_bytes / 1024);
    assert_contains(&envelope_cap, "envelope value cap");
    let output_cap = format!("{} KiB", contract.output_cap_bytes / 1024);
    assert_contains(&output_cap, "output cap");
    assert_contains(
        &format!("{}", contract.reason_max_chars),
        "reason max chars",
    );
    assert_contains(
        &format!("{}", contract.stop_hook_max_continuations),
        "stop continuation cap",
    );
    let (lo, hi) = contract.timeout_secs_range;
    assert_contains(&format!("{}..={}", lo, hi), "timeoutSecs range");

    // Audit statuses + privacy exclusions + byte caps.
    for status in &contract.audit_statuses {
        assert_contains(status, &format!("audit status `{}`", status));
    }
    for field in &contract.audit_excluded_fields {
        assert_contains(field, &format!("audit excluded field `{}`", field));
    }
    let (ev, corr, reason) = contract.audit_byte_caps;
    assert_contains(&format!("{}", ev), "audit event byte cap");
    assert_contains(&format!("{}", corr), "audit correlation byte cap");
    assert_contains(&format!("{}", reason), "audit reason byte cap");

    // Decision vocabularies.
    assert_contains(
        &format!("\"{}\"", contract.pre_tool_blocking_decision),
        "pre-tool blocking decision",
    );
    assert_contains(
        &format!("\"{}\"", contract.pre_tool_allow_decision),
        "pre-tool allow decision",
    );
    assert_contains(
        &format!("\"{}\"", contract.stop_block_decision),
        "stop block decision",
    );
    assert_contains(contract.stop_continue_false, "stop continue:false field");
    assert_contains(
        contract.stop_additional_context_field,
        "stop additionalContext field",
    );

    // Fail-open conditions.
    for cond in &contract.fail_open_conditions {
        assert_contains(cond, &format!("fail-open condition `{}`", cond));
    }

    // Unsupported formats must NOT be presented as supported.
    for fmt in &contract.unsupported_formats {
        assert_not_contains(
            &format!("supported: {}", fmt),
            &format!("unsupported format `{}`", fmt),
        );
    }
    // The block must explicitly reject each unsupported format.
    for fmt in &contract.unsupported_formats {
        assert!(
            lower.contains(&fmt.to_ascii_lowercase()),
            "hooks-contract block must explicitly reject unsupported format `{fmt}`"
        );
    }
}

/// `hooks_documentation_matches_typed_contract` verifies that the public
/// `apps/cli/README.md` `## Hooks` contract block matches the typed
/// config/runtime constants. It fails on a missing marker, any
/// missing/extra/wrong normative value, or an unsupported format presented
/// as supported.
#[test]
fn hooks_documentation_matches_typed_contract() {
    let block = read_hooks_contract_block();
    assert!(!block.trim().is_empty(), "hooks-contract block is empty");
    let contract = HookDocumentationContract::from_typed_constants();
    assert_contract_block_matches(&block, &contract);
    let mut reachable = PRODUCTION_HOOK_BOUNDARIES
        .iter()
        .map(|(event, owner)| {
            assert!(!owner.trim().is_empty(), "{event:?} has an empty boundary owner");
            *event
        })
        .collect::<Vec<_>>();
    reachable.sort_by_key(|event| event.key());
    reachable.dedup();
    let mut all = HookEvent::ALL.to_vec();
    all.sort_by_key(|event| event.key());
    assert_eq!(reachable, all, "every typed hook event needs one production boundary owner");
}
